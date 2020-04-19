import os
import sys
import signal
import shutil
import tempfile
import contextlib
import time
import logging.config
from driller import Driller
from driller.prioritization_techniques import UniqueSearch, HardestSearch, SyMLSearch
import argparse
import subprocess
import multiprocessing

from glob import glob

l = logging.getLogger("local_callback")
logging.getLogger("cle.backends.elf.elf").setLevel("ERROR")

def _run_drill(drill, fuzz, _path_to_input_to_drill, length_extension=None):
    _fuzzer_out_dir = fuzz.work_dir
    _binary_path = fuzz.target
    _fuzzer_cmdline = os.path.join(_fuzzer_out_dir, 'fuzzer-master', "cmdline")
    _bitmap_path = os.path.join(_fuzzer_out_dir, 'fuzzer-master', "fuzz_bitmap")
    _timeout = drill._worker_timeout
    
    l.warning("starting drilling of %s, %s", os.path.basename(_binary_path), os.path.basename(_path_to_input_to_drill))
    args = (
        "timeout", "-k", str(_timeout+10), str(_timeout),
        sys.executable, os.path.abspath(__file__),
        _fuzzer_cmdline, _fuzzer_out_dir, _bitmap_path, _path_to_input_to_drill
    )
    if length_extension:
        args += ('--length-extension', str(length_extension))

    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    p.communicate()


class LocalCallback(object):
    def __init__(self, num_workers=1, worker_timeout=10*60, length_extension=None, technique=UniqueSearch):
        self._already_drilled_inputs = set()

        self._num_workers = num_workers
        self._running_workers = []
        self._worker_timeout = worker_timeout
        self._length_extension = length_extension

        self.t = technique
        self.suspend = False
        
        self.seen = list()
        
    @staticmethod
    def new_seeds(fuzz):
        all_seeds = glob(f"{fuzz.work_dir}/fuzzer-*/queue/*id:*")
        seen_seeds = os.listdir(fuzz.queue_all_dir)

        for seed in all_seeds:
            id = seed.split("/")[-1]
            fuzzer = seed.split("/queue")[0].split("/")[-1]
            if f"{{{fuzzer}}}{id}" not in seen_seeds:
                return True
        return False
    
    def _queue_files(self, fuzz, fuzzer='fuzzer-master'):
        '''
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        '''
        
        # don't call cmin during update
        if self.t.updating: raise RuntimeError("Called afl-cmin during update")

        # don't call cmin if we're up-to-date
        try: 
            if not self.new_seeds(fuzz):
                l.debug("Already up-to-date")
                raise RuntimeError("Already up-to-date")
        except OSError: pass
        
        # queue file after cmin
        l.debug("[*] Calling afl-cmin...")
        fuzz.cmin().wait()
        
        queue_files = glob(f"{fuzz.queue_min_dir}/*id:*")
        return queue_files

    def driller_callback(self, fuzz):
        if self.suspend: return
        
        l.debug("Driller callback triggered!")
        if self.t.__class__.__name__ == 'ABCMeta': self.t = self.t(fuzz=fuzz)
        # remove any workers that aren't running
        self._running_workers = [x for x in self._running_workers if x.is_alive()]

        # get the files in queue
        try: queue = self._queue_files(fuzz)
        except (RuntimeError, OSError) as e: return
        
        #for i in range(1, fuzz.fuzz_id):
        #    fname = "fuzzer-%d" % i
        #    queue.extend(self.queue_files(fname))

        # start drilling
        not_drilled = set(queue) - self._already_drilled_inputs
        self.t.update(list(not_drilled))

        if len(self._running_workers) < self._num_workers and len(not_drilled) == 0:
            l.warning("no inputs left to drill")

        while len(self._running_workers) < self._num_workers and len(not_drilled) > 0:
            to_drill_path = self.t.pop_best(not_drilled=not_drilled)
            if not to_drill_path: return
            not_drilled.remove(to_drill_path)
            self._already_drilled_inputs.add(to_drill_path)

            proc = multiprocessing.Process(target=_run_drill, args=(self, fuzz, to_drill_path),
                    kwargs={'length_extension': self._length_extension})
            proc.start()
            self._running_workers.append(proc)
    __call__ = driller_callback

    def kill(self):
        for p in self._running_workers:
            try:
                p.terminate()
                os.kill(p.pid, signal.SIGKILL)
            except OSError:
                pass


# this is for running with bash timeout
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Driller local callback")
    parser.add_argument('fuzzer_cmdline')
    parser.add_argument('fuzzer_out_dir')
    parser.add_argument('bitmap_path')
    parser.add_argument('path_to_input_to_drill')
    parser.add_argument('--length-extension', help="Try extending inputs to driller by this many bytes", type=int)
    args = parser.parse_args()
    logcfg_file = os.path.join(os.getcwd(), '.driller.ini')
    if os.path.isfile(logcfg_file):
        logging.config.fileConfig(logcfg_file)

    fuzzer_bitmap = open(args.bitmap_path, "rb").read()
    fuzzer_cmdline = open(args.fuzzer_cmdline, "r").read().split()

    # create a folder
    driller_dir = os.path.join(args.fuzzer_out_dir, "driller")
    driller_queue_dir = os.path.join(driller_dir, "queue")
    try: os.mkdir(driller_dir)
    except OSError: pass
    try: os.mkdir(driller_queue_dir)
    except OSError: pass

    l.debug('drilling %s', args.path_to_input_to_drill)
    # get the input
    input_to_drill = open(args.path_to_input_to_drill, "rb").read()
    input_file_to_drill = args.path_to_input_to_drill
    #if args.length_extension:
    #    inputs_to_drill.append(inputs_to_drill[0] + b'\0' * args.length_extension)

    #for input_to_drill in inputs_to_drill:
    d = Driller(args=fuzzer_cmdline, input_str=input_to_drill, input_file=input_file_to_drill, seed_glob=f"{args.fuzzer_out_dir}/*/queue/id:*")  #fuzz_bitmap=fuzzer_bitmap)
    count = 0
    for new_input in d.drill_generator():
        id_num = len(os.listdir(driller_queue_dir))
        fuzzer_from = args.path_to_input_to_drill.split("/")[-1].split("}")[0][1:] + ":" + args.path_to_input_to_drill.split("id:")[1].split(",")[0]
        filepath = "id:" + ("%d" % id_num).rjust(6, "0") + ",from:" + fuzzer_from
        filepath = os.path.join(driller_queue_dir, filepath)
        with open(filepath, "wb") as f:
            f.write(new_input[1])
        count += 1
    l.warning("found %d new inputs", count)
