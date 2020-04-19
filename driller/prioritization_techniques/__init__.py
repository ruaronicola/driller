from abc import ABC, abstractmethod

import archr
import logging
import threading

l = logging.getLogger('archr.arsenal.pin')

def threaded(fn):
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper

class PrioritizationTechnique(ABC):
    def __init__(self, fuzz):
        self.binary = fuzz.target
        self.traces = dict()
        self.blacklist = list()
        self.target_os = fuzz.target_os
        self.target_arch = fuzz.target_arch
        self.work_dir = fuzz.work_dir
        
        self.target = archr.targets.LocalTarget([self.binary], target_os=self.target_os, target_arch=self.target_arch)
        self.tracer_bow = archr.arsenal.PINTracerBow(self.target)
        
        self.updating = False

    def trace(self, seed, calls=False, syscalls=False):
        if seed in self.traces: 
            return self.traces[seed]
        elif seed in self.blacklist:
            raise Exception(f"PIN failed to trace {seed}")

        try:
            with open(seed, 'rb') as testcase:
                r = self.tracer_bow.fire(testcase=testcase.read(), main_object_only=True, branches_only=True, basic_blocks=True, calls=calls, syscalls=syscalls, timeout=30)
                trace = [int(line) for line in r.split('\n') if line]
                self.traces[seed] = trace
                return trace
        except Exception as e:
            self.blacklist.append(seed)
            l.exception(f"PIN failed when tracing {seed}")
            raise Exception(f"PIN failed to trace {seed}")

    def update(self, seeds):
    	# clean up traces
    	self.traces = {k:v for k,v in self.traces.items() if k in seeds}

    @abstractmethod
    def pop_best(self, not_drilled):
        """
            Abstract method for pop_best, which should retrieve the best path and pop it from the dict
        """


from .unique import UniqueSearch
from .hardest import HardestSearch
from .syml import SyMLSearch
