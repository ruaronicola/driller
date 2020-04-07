from . import PrioritizationTechnique

from statistics import mean

class HardestSearch(PrioritizationTechnique):
    def __init__(self, binary, target_os, target_arch):
        super(HardestSearch, self).__init__(binary=binary, target_os=target_os, target_arch=target_arch)

        self.visits = dict()
        self.hardness = dict()

    def get_tuples(self, trace):
        return set(zip(trace[:-1], trace[1:]))

    def update(self, seeds):
        super(HardestSearch, self).update(seeds=seeds)

        seeds = [s for s in seeds if 'driller' not in s]
        new_seeds = [s for s in seeds if s not in self.hardness]
        if len(new_seeds) == 0: return

        # update visits from new seeds
        for s in new_seeds:
            trace = self.trace(s)
            for a, b in self.get_tuples(trace):
                self.visits[a] = self.visits.get(a, dict())
                self.visits[a][b] = self.visits[a].get(b, 0) + 1

        # clean up
        self.hardness = {k:0. for k in seeds}

        # update hardness
        for s in seeds:
            trace = self.trace(s)
            total = {node: sum(self.visits[node].values()) for node in self.visits}
            scores = [self.visits[a][b]/total[a] for a, b in self.get_tuples(trace)]  # if self.visits[a][b]!=total[a]]
            self.hardness[s] = 1 - mean(scores)

    def pop_best(self, not_drilled):
        best = max({k:v for k,v in self.hardness.items() if k in not_drilled}, key=self.hardness.get)
        self.hardness.pop(best)
        return best
