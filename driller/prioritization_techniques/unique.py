from . import PrioritizationTechnique, threaded

from collections import Counter

import logging
l = logging.getLogger("driller.prioritization_techniques.unique")

class UniqueSearch(PrioritizationTechnique):
    def __init__(self, fuzz, similarity_func=None):
        super(UniqueSearch, self).__init__(fuzz)
        
        self.uniqueness = dict()
        self.similarity = dict()
        self.similarity_func = similarity_func or self.l2_similarity

    @threaded
    def update(self, seeds):
        super(UniqueSearch, self).update(seeds=seeds)
        
        new_seeds = [s for s in seeds if s not in self.uniqueness]
        if self.updating or not new_seeds: return

        self.updating = True
        l.debug(f"Updating... [{len(new_seeds)}]")

        # clean up
        _uniqueness = {k:(0,0) for k in seeds}
        self.similarity = {(a,b):v for (a,b),v in self.similarity.items() if a in seeds and b in seeds}


        def update_average(seed, new):
            prev, size = _uniqueness[seed]
            new_average = float(prev * size + new) / (size + 1)
            _uniqueness[seed] = new_average, size + 1

        for a in seeds:
            for b in seeds:
                similarity = self.similarity.get((a, b), None) or self.similarity_func(a, b)
                self.similarity[(a, b)] = self.similarity[(b, a)] = similarity
                update_average(a, similarity)
                update_average(b, similarity)

        self.uniqueness = {k:v for k,(v,_) in _uniqueness.items()}
        
        self.updating = False

    def pop_best(self, not_drilled):
        candidates = {k:v for k,v in self.uniqueness.items() if k in not_drilled}
        return max(candidates, key=self.uniqueness.get) if candidates else None

    def l2_similarity(self, seed_a, seed_b):
        """
        The (L2) distance between the counts of the state addresses in the history of the path.
        :param seed_a: The first seed to compare
        :param seed_b: The second seed to compare
        """
        if seed_a == seed_b: return 1.0
        try:
            count_a = Counter(self.trace(seed_a))
            count_b = Counter(self.trace(seed_b))
            normal_distance = sum((count_a.get(addr, 0) - count_b.get(addr, 0)) ** 2
                                  for addr in set(list(count_a.keys()) + list(count_b.keys()))) ** 0.5
            return 1.0 / (1 + normal_distance)
        except: return 0.0
