from . import PrioritizationTechnique, threaded

from statistics import mean

import logging
l = logging.getLogger("driller.prioritization_techniques.hardest")

class HardestSearch(PrioritizationTechnique):
    def __init__(self, binary, target_os, target_arch, work_dir):
        super(HardestSearch, self).__init__(binary=binary, target_os=target_os, target_arch=target_arch, work_dir=work_dir)

        self.visits = dict()
        self.hardness = dict()
        
        self.updating = False

    def get_tuples(self, trace):
        return set(zip(trace[:-1], trace[1:]))

    @threaded
    def update(self, seeds):
        super(HardestSearch, self).update(seeds=seeds)
        
        new_seeds = [s for s in seeds if s not in self.hardness]
        if self.updating or not new_seeds: return
        
        self.updating = True
        l.debug(f"Updating... [{len(new_seeds)}]")

        # update visits from new seeds
        for s in new_seeds:
            try:
                trace = self.trace(s)
                for a, b in self.get_tuples(trace):
                    self.visits[a] = self.visits.get(a, dict())
                    self.visits[a][b] = self.visits[a].get(b, 0) + 1
            except: pass

        # update hardness
        for s in seeds:
            try:
                trace = self.trace(s)
                total = {node: sum(self.visits[node].values()) for node in self.visits}
                scores = [self.visits[a][b]/total[a] for a, b in self.get_tuples(trace)]  # if self.visits[a][b]!=total[a]]
                self.hardness[s] = 1 - mean(scores)
            except: self.hardness[s] = 1.0
        
        # clean up
        self.hardness = {k:self.hardness[k] for k in seeds}
        
        self.updating = False

    def pop_best(self, not_drilled):
        candidates = {k:v for k,v in self.hardness.items() if k in not_drilled}
        return max(candidates, key=self.hardness.get) if candidates else None
