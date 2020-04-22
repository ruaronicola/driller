from . import PrioritizationTechnique, threaded

from statistics import mean

import angr

import logging
l = logging.getLogger("driller.prioritization_techniques.hardest")

class HardestSearch(PrioritizationTechnique):
    def __init__(self, fuzz):
        super(HardestSearch, self).__init__(fuzz)

        self.visits = dict()
        self.hardness = dict()

        project = angr.Project(self.binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast(fail_fast=True, normalize=True, objects=[project.loader.main_object]).model
        self.successors = {n.addr:{s.addr for s in n.successors} for n in cfg.nodes()}

    def flatten(l):
        return [item for sublist in l for item in sublist]

    def get_tuples(self, trace):
        return set(zip(trace[:-1], trace[1:]))

    def addr_hash(addr):
        bitmap_size = len(self.fuzz_bitmap)
        assert bitmap_size == 1 << (bitmap_size.bit_length() - 1)
        return ((addr >> 4) ^ (addr << 8)) & (bitmap_size - 1)

    def get_hits(a, b):
        prev_loc = addr_hash(a, self.fuzz_bitmap) >> 1
        cur_loc = addr_hash(b, self.fuzz_bitmap)
        idx = prev_loc ^ cur_loc
        return self.fuzz_bitmap[idx]

    @threaded
    def update(self, seeds):
        super(HardestSearch, self).update(seeds=seeds)
        
        new_seeds = [s for s in seeds if s not in self.hardness]
        if self.updating or not new_seeds: return
        
        self.updating = True
        l.debug(f"Updating... [{len(new_seeds)}]")

        # read current bitmap
        self.fuzz_bitmap = open(self.bitmap_path, "rb").read()
        self.fuzz_bitmap = bytes([ b ^ 0xff for b in self.fuzz_bitmap ])

        # update hardness
        for s in seeds:
            try:
                trace = self.trace(s)
                self.hardness[s] = 1.0
                path_hardness = 1.0
                for a,b in self.get_tuples(trace):
                    missed_hits = []
                    taken_hits = self.get_hits(a, b)
                    if taken_hits == 0: continue
                    for s in self.successors.get(a, {b})-{b}:
                        missed_hits += [self.get_hits(a, s)]
                    total_hits = sum(missed_hits)+taken_hits

                for m in missed_hits:
                    if m != 0:
                        self.hardness[s] = min(self.hardness[s], path_hardness*m/total_hits)
                    elif total_hits > 30:
                        self.hardness[s] = min(self.hardness[s], path_hardness*3/total_hits)
                path_hardness *= taken_hits/total_hits

            except: self.hardness[s] = mean(self.hardness.values() or [0.5])
        
        # clean up
        self.hardness = {k:self.hardness[k] for k in seeds}
        
        self.updating = False

    def pop_best(self, not_drilled):
        candidates = {k:v for k,v in self.hardness.items() if k in not_drilled}
        return min(candidates, key=self.hardness.get) if candidates else None
