import os
import time
import signal
import hashlib
import resource
import pickle
import logging
import binascii

import angr
import archr
from trraces.replay_interfaces.angr.technique import Trracer

from driller import config
from .drrillerr_core import DrrillerrCore

logger = logging.getLogger("driller.driller")

logging.getLogger('driller.drrillerr_core').setLevel('ERROR')
logging.getLogger('angr.state_plugins.preconstrainer').setLevel('ERROR')
logging.getLogger('trraces.syscall_replay').setLevel('ERROR')
logging.getLogger('trraces.replay_interfaces.angr.setup_state').setLevel('ERROR')
logging.getLogger('angr.storage.paged_memory').setLevel('ERROR')


class Drrillerr(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, binary, input_str, fuzz_bitmap=None, tag=None, redis=None):
        """
        :param input_str  : Input string to feed to the binary.
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
        :param redis      : redis.Redis instance for coordinating multiple Driller instances.
        """

        # Redis channel identifier.
        self.binary = binary
        self.identifier = os.path.basename(binary)
        self.input = input_str
        self.fuzz_bitmap = fuzz_bitmap
        self.tag = tag
        self.redis = redis

        self.base = os.path.join(os.path.dirname(__file__), "..")

        # The driller core, which is now an exploration technique in angr.
        self._core = None

        # Start time, set by drill method.
        self.start_time = time.time()

        # Set of all the generated inputs.
        self._generated = set()

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        logger.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))

    # DRILLING

    def drill(self):
        """
        Perform the drilling, finding more code coverage based off our existing input base.
        """

        # Don't re-trace the same input.
        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):
            return -1

        # Write out debug info if desired.
        if logger.level == logging.DEBUG and config.DEBUG_DIR:
            self._write_debug_info()
        elif logger.level == logging.DEBUG and not config.DEBUG_DIR:
            logger.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # Update traced.
        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input)

        list(self._drill_input())

        if self.redis:
            return len(self._generated)
        else:
            return self._generated

    def drill_generator(self):
        """
        A generator interface to the actual drilling.
        """

        # Set up alarm for timeouts.
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        for i in self._drill_input():
            yield i

    def setup_angr(self):
        # retrace
        p = angr.Project(self.binary)
        # assert p.loader.main_object.os == 'UNIX - System V'
        with archr.targets.LocalTarget([self.binary], target_cwd=os.path.dirname(self.binary), target_os=p.loader.main_object.os, target_arch=p.arch.linux_name) as target:
            tracer_bow = archr.arsenal.RRTracerBow(target)
            r = tracer_bow.fire(testcase=self.input, empty_reads=True)
            self.rr_trace_dir = r.trace_dir.name

        # setup trracer
        new_options = {angr.options.STRICT_PAGE_ACCESS, angr.options.REPLACEMENT_SOLVER} | angr.options.unicorn
        s = p.factory.blank_state(mode='tracing', stdin=angr.SimFileStream, add_options=new_options)

        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=True)

        t = Trracer(trace_dir=self.rr_trace_dir, keep_predecessors=2)

        self._core = DrrillerrCore()

        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)
        return simgr

    def _drill_input(self):
        """
        Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        """

        simgr = self.setup_angr()
        self._set_concretizations(simgr.one_active)
        logger.debug("Drilling into %r.", self.input)
        logger.debug("Input is %r.", self.input)

        while simgr.active:
            try: simgr.step()
            except: return

            # Check here to see if a crash has been found.
            if self.redis and self.redis.sismember(self.identifier + '-finished', True):
                return

            if 'diverted' not in simgr.stashes:
                continue

            while simgr.diverted:
                state = simgr.diverted.pop(0)
                logger.debug("Found a diverted state, exploring to some extent.")
                w = self._writeout(state.history.bbl_addrs[-1], state)
                if w is not None:
                    yield w
                for i in self._symbolic_explorer_stub(state):
                    yield i

    # EXPLORER

    def _symbolic_explorer_stub(self, state):
        # Create a new simulation manager and step it forward up to 1024
        # accumulated active states or steps.
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()
        state.inspect._breakpoints['dirty'] = []
        state.inspect._breakpoints['simprocedure'] = []
        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass
        simgr = p.factory.simulation_manager(state, hierarchy=False)
        simgr.use_technique(angr.exploration_techniques.Oppologist())

        logger.debug("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

        while len(simgr.active) and accumulated < 1024:
            try: simgr.step()
            except: break
            
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))

        logger.debug("[%s] stopped symbolic exploration at %s.", self.identifier, time.ctime())

        # DO NOT think this is the same as using only the deadended stashes. this merges deadended and active
        simgr.stash(from_stash='deadended', to_stash='active')
        for dumpable in simgr.active:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w

            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass

    # UTILS

    @staticmethod
    def _set_concretizations(state):
        if state.project.loader.main_object.os == 'cgc':
            flag_vars = set()
            for b in state.cgc.flag_bytes:
                flag_vars.update(b.variables)

            state.unicorn.always_concretize.update(flag_vars)

        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def _in_catalogue(self, length, prev_addr, next_addr):
        """
        Check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length   : Length of the input.
        :param prev_addr: The source address in the state transition.
        :param next_addr: The destination address in the state transition.

        :return: boolean describing whether or not the input generated is redundant.
        """

        key = '%x,%x,%x\n' % (length, prev_addr, next_addr)

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key)

        # No redis means no coordination, so no catalogue.
        else:
            return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)
        # No redis = no catalogue.

    def _writeout(self, prev_addr, state):
        generated = state.posix.stdin.load(0, state.posix.stdin.pos)
        generated = state.solver.eval(generated, cast_to=bytes)

        key = (len(generated), prev_addr, state.addr)

        # Checks here to see if the generation is worth writing to disk.
        # If we generate too many inputs which are not really different we'll seriously slow down AFL.
        if self._in_catalogue(*key):
            self._core.encounters.remove((prev_addr, state.addr))
            return None

        else:
            self._add_to_catalogue(*key)

        logger.debug("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self._generated.add((key, generated))

        if self.redis:
            # Publish it out in real-time so that inputs get there immediately.
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag}))

        else:
            logger.debug("Generated: %s", binascii.hexlify(generated))

        return key, generated

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR, self.identifier + '_' + m.hexdigest() + '.py')

        with open(f_name, 'w+') as f:
            logger.debug("Debug log written to %s.", f_name)
            f.write("rr_trace_dir = %r\n" % self.rr_trace_dir
                    + "started = '%s'\n" % time.ctime(self.start_time)
                    + "input = %r\n" % self.input
                    + "fuzz_bitmap = %r" % self.fuzz_bitmap)
