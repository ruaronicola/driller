from abc import ABC, abstractmethod

import archr


class PrioritizationTechnique(ABC):
    def __init__(self, binary, target_os, target_arch):
        self.binary = binary
        self.traces = dict()
        self.target_os = target_os
        self.target_arch = target_arch

    def trace(self, seed):
        if seed in self.traces:
            return self.traces[seed]
        with archr.targets.LocalTarget([self.binary], target_os=self.target_os, target_arch=self.target_arch) as target, open(seed, 'rb') as testcase:
            tracer_bow = archr.arsenal.PINTracerBow(target)
            r = tracer_bow.fire(testcase=testcase.read(), main_object_only=True, syscalls=False, timeout=10)
            trace = [int(line) for line in r.split('\n') if line]
            self.traces[seed] = trace
            return trace

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
