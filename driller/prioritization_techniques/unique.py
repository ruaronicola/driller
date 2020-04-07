from . import PrioritizationTechnique

from collections import Counter

class UniqueSearch(PrioritizationTechnique):
    def __init__(self, binary, target_os, target_arch, similarity_func=None):
        super(UniqueSearch, self).__init__(binary=binary, target_os=target_os, target_arch=target_arch)
        
        self.uniqueness = dict()
        self.similarity = dict()
        self.similarity_func = similarity_func or self.l2_similarity

    def update(self, seeds):
        super(UniqueSearch, self).update(seeds=seeds)

        seeds = [s for s in seeds if 'driller' not in s]
        if all([s in self.uniqueness for s in seeds]): return

        # clean up
        self.uniqueness = {k:(0,0) for k in seeds}
        self.similarity = {(a,b):v for (a,b),v in self.similarity.items() if a in seeds and b in seeds}


        def update_average(seed, new):
            prev, size = self.uniqueness[seed]
            new_average = float(prev * size + new) / (size + 1)
            self.uniqueness[seed] = new_average, size + 1

        for a in seeds:
            for b in seeds:
                similarity = self.similarity.get((a, b), None) or self.similarity_func(a, b)
                self.similarity[(a, b)] = self.similarity[(b, a)] = similarity
                update_average(a, similarity)
                update_average(b, similarity)

        self.uniqueness = {k:v for k,(v,_) in self.uniqueness.items()}

    def pop_best(self, not_drilled):
        best = max({k:v for k,v in self.uniqueness.items() if k in not_drilled}, key=self.uniqueness.get)
        self.uniqueness.pop(best)
        return best


    def l2_similarity(self, seed_a, seed_b):
        """
        The (L2) distance between the counts of the state addresses in the history of the path.
        :param seed_a: The first seed to compare
        :param seed_b: The second seed to compare
        """
        if seed_a == seed_b: return 1.0
        count_a = Counter(self.trace(seed_a))
        count_b = Counter(self.trace(seed_b))
        normal_distance = sum((count_a.get(addr, 0) - count_b.get(addr, 0)) ** 2
                              for addr in set(list(count_a.keys()) + list(count_b.keys()))) ** 0.5
        return 1.0 / (1 + normal_distance)
