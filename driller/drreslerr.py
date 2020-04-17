import functools
import logging
import angr
import archr
import sys
import os
import glob

import archinfo
import claripy
import trraces
import argparse
from claripy.utils import OrderedSet
from trraces.replay_interfaces.angr import setup_state
from trraces.replay_interfaces.angr. explore_with_state_stop_points import StateStopPoints
from trraces.rr_constants import RR_ARCH_X86, RR_ARCH_X8664
from trraces.trrace import RRTrace

logger = logging.getLogger("driller.drreslerr")

logging.getLogger('angr.state_plugins.preconstrainer').setLevel('ERROR')
logging.getLogger('trraces.syscall_replay').setLevel('ERROR')
logging.getLogger('trraces.replay_interfaces.angr.setup_state').setLevel('ERROR')
logging.getLogger('angr.storage.paged_memory').setLevel('ERROR')


class Drreslerr(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """

    def __init__(self, args, input_str, input_file, seed_glob="", fuzz_bitmap=None, tag=None, redis=None, hooks=None, argv=None):
        """
        :param binary     : The binary to be traced.
        :param input_str  : Input string to feed to the binary.
        :param work_dir   : The working directory used by the fuzzer
        """

        self.args = args
        self.binary = self.args[0]
        self.input_str = input_str
        self.input_file = input_file
        self.seed_glob = seed_glob
        
    def drill_generator(self):
        """
        A generator interface to the actual drilling.
        """
        p = angr.Project(self.binary)
        
        # deal with input files
        if "@@" in self.args:
            assert self.args.count('@@') == 1
            self.args[self.args.index('@@')] = self.input_file
        
        with archr.targets.LocalTarget(self.args, target_cwd=os.path.dirname(self.binary), 
                                       target_os=p.loader.main_object.os, target_arch=p.arch.linux_name) as target:
                tracer_bow = archr.arsenal.RRTracerBow(target)
                r = tracer_bow.fire(testcase=self.input_str, empty_reads=True)

                inputs_seen = []
                for seed_name in glob.iglob(self.seed_glob):
                    with open(seed_name, 'rb') as f:
                        inputs_seen.append(f.read())

                new_inputs = Drreslerr.drill_explore(r.trace_dir.name, p, None, None, inputs_seen=inputs_seen)
                for i in enumerate(new_inputs):
                    yield i

    @staticmethod
    def contains_model_for_solver(solver, var, seen):
        for inp in seen:
            if len(inp)  != len(var): # can't be uninteresting because of this input, they have different lengths!
                continue

            if solver.solution(var, inp):
                # this input does the same thing, ignore
                return True

        return False

    @staticmethod
    def produce_partial_constraint_inputs(var, constraints, inputs_seen=()):
        solver = claripy.Solver(track=True)

        seen = {claripy.BVV(inp) for inp in inputs_seen}
        found = set()

        possible_inputs = OrderedSet()
        for c in constraints:
            if not solver.satisfiable(extra_constraints=(claripy.Not(c),)):
                continue

            alternatives = []

            if c.op == '__eq__':
                alternatives.append(solver.branch())
                slt = claripy.SLT(c.args[0], c.args[1])
                sgt = claripy.SGT(c.args[0], c.args[1])
                ult = claripy.ULT(c.args[0], c.args[1])
                ugt = claripy.UGT(c.args[0], c.args[1])

                all_cs = [slt, sgt, ult, ugt]
                for c in all_cs:
                    option_solver = solver.branch()
                    option_solver.add(c)
                    alternatives.append(option_solver)

            general_negated_solver = solver.branch()
            general_negated_solver.add(claripy.Not(c))

            for alternate_solver in alternatives:
                if not alternate_solver.satisfiable() or Drreslerr.contains_model_for_solver(alternate_solver, var, seen | found):
                    continue

                found.update(alternate_solver.eval_to_ast(var, 1))

            solver.add(c)

        return found


    @staticmethod
    def get_new_inputs(traced_state: angr.SimState, inputs_seen=()):
        s = traced_state

        input_var = claripy.Concat(*(buf for buf, sz in s.posix.stdin.content))

        # s.preconstrainer.remove_preconstraints()

        all_inps = OrderedSet()
        # all_inps |= produce_partial_constraint_inputs(input_var, [a.constraint.ast for a in s.history.actions if a.type == 'constraint'], inputs_seen=inputs_seen)
        # all_inps |= produce_partial_constraint_inputs(input_var, [h.jump_guard for h in s.history.parents if h.jump_guard is not None and not h.jump_guard.is_true()], inputs_seen=inputs_seen)
        all_inps |= Drreslerr.produce_partial_constraint_inputs(input_var, s.solver.constraints, inputs_seen=inputs_seen)
        # all_inps |= produce_partial_constraint_inputs(input_var, list(reversed(s.solver.constraints)))
        return [s.solver.eval_one(inp, cast_to=bytes) for inp in all_inps]

    @staticmethod
    def drill_explore(trace_path, proj, *_, inputs_seen=()):
        opts = {angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                angr.options.STRICT_PAGE_ACCESS,
                angr.options.REPLACEMENT_SOLVER,
                } | angr.options.unicorn

        state = proj.factory.blank_state(add_options=opts, remove_options=angr.options.simplification | {angr.options.SIMPLIFY_CONSTRAINTS})
        state = setup_state.setup_symbolic_input_tracing_state(trace_path, state)

        sm = proj.factory.simulation_manager(state)
        sm.use_technique(StateStopPoints())
        sm.use_technique(angr.exploration_techniques.Oppologist())
        sm.run()

        final_states = sm.active + sm.deadended
        assert len(final_states) == 1

        s: angr.SimState = final_states[0]
        return Drreslerr.get_new_inputs(s, inputs_seen=inputs_seen)
                


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('-b', '--binary', help='The target binary. Only x86 and x86_64 binaries are supported')
    p.add_argument('-i', '--input-seed', help='The input seed to drill')
    p.add_argument('-s', '--seed-glob', help='Glob that can find all previously discovered seeds so they don\'t get rediscovered', default="") 
    #p.add_argument('-t', '--rr-trace-path', help='Path to rr latest-trace directory (or any directory containing the rr trace data)')
    args = p.parse_args()

    input_str = open(args.input_seed, 'rb').read()
    d = Drreslerr(binary=args.binary, input_str=input_str, seed_glob=args.seed_glob)

    inputs = d.drill_generator()
    print('$' * 30 + " Explored the following new inputs: " + '$' * 30)
    for i, inp in enumerate(inputs):
        print(i, repr(inp))
