from . import PrioritizationTechnique, threaded

import os
import networkx as nx
import numpy as np
import angr
import pickle

import logging
l = logging.getLogger("driller.prioritization_techniques.syml")

class SyMLSearch(PrioritizationTechnique):
    def __init__(self, fuzz):
        super(SyMLSearch, self).__init__(fuzz)
        
        # static analysis
        self.cfg = self.cfg or self.proj.analyses.CFG(fail_fast=True, normalize=True, 
                                                      objects=[self.proj.loader.main_object], 
                                                      resolve_indirect_jumps=True, collect_data_references=True)
        self.cfg = self.cfg.model
        self.centr = {n.addr: np.around(centr, 3) for n, centr in nx.betweenness_centrality(self.cfg.graph, min(len(self.cfg.graph.nodes), 400)).items()}
        self.conn = {n.addr: conn for n, conn in self.cfg.graph.degree}
        
        funcs = self.proj.kb.functions
        self.func_addrs = {n.addr: n.function_address for n in self.cfg.nodes()}
        self.func_size = {f: funcs[f].size for f in funcs}
        self.func_cpx = dict()
        for f in funcs:
            edges = len(funcs[f].graph.edges())
            nodes = len(funcs[f].graph.nodes())
            parts = nx.components.number_strongly_connected_components(funcs[f].graph)
            self.func_cpx[f] = edges - nodes + 2 * parts
        
        self.scores = dict()
        
        with open(f"{self.work_dir}/driller/classifier.pkl", 'rb') as f:
            self.classifier = pickle.load(f)

    @threaded
    def update(self, seeds):
        super(SyMLSearch, self).update(seeds=seeds)

        new_seeds = [s for s in seeds if s not in self.scores]
        if self.updating or not new_seeds: return
        
        self.updating = True
        l.debug(f"Updating... [{len(new_seeds)}]")

        for s in new_seeds:
            # trace
            try:
                trace = self.trace(s, calls=True, syscalls=True)
                # extract features
                x = self.get_features(trace)
                # update scores
                self.scores[s] = self.classifier.predict_proba(x)[0, 1]
            except: self.scores[s] = 0.5
                
        # clean up
        self.scores = {s:self.scores[s] for s in seeds}
        self.traces = {}
        
        self.updating = False

    def pop_best(self, not_drilled):
        candidates = {k:v for k,v in self.scores.items() if k in not_drilled}
        return max(candidates, key=self.scores.get) if candidates else None

    def get_features(self, trace):
        datapoints = []
        syscalls = {'S_FS': 0, 'S_IPC': 0, 'S_KERNEL': 0, 'S_MM': 0, 'S_NET': 0, 'S_SECURITY': 0}
        num_calls = 0
        last_branch = None
        for t in trace:
            if not t.startswith('SYSCALL') and not t.startswith('CALL'):
                try:
                    if last_branch is not None and self.func_addrs[int(t)] == self.func_addrs[last_branch]:
                        continue
                except: continue
                if last_branch is not None:
                    f_addr = self.func_addrs[last_branch]
                    datapoints += [{'centr': self.centr[last_branch], 'conn': self.conn[last_branch],
                                  'f_size': self.func_size[f_addr], 'f_cpx': self.func_cpx[f_addr],
                                  'num_calls': num_calls, **syscalls}]
                last_branch = int(t)
                num_calls = 0
                syscalls = {'S_FS': 0, 'S_IPC': 0, 'S_KERNEL': 0, 'S_MM': 0, 'S_NET': 0, 'S_SECURITY': 0}
            elif t.startswith('CALL'):
                num_calls += 1
            elif t.startswith('SYSCALL') and t != 'SYSCALL KERNEL::exit_group':
                syscalls['S_'+t.split("::")[0][8:]] += 1

        f_addr = self.func_addrs[last_branch]
        datapoints += [{'centr': self.centr[last_branch], 'conn': self.conn[last_branch],
                      'f_size': self.func_size[f_addr], 'f_cpx': self.func_cpx[f_addr],
                      'num_calls': num_calls, **syscalls}]

        # compress datapoints into one-dimensional features
        x0 = sum([d['f_cpx'] for d in data])/len(data)
        x1 = sum([d['centr'] for d in data])/len(data)

        x2 = sum([1 for d in data if d['f_cpx'] > 30])/len(data)
        x3 = sum([1 for d in data if d['f_cpx']/d['f_size'] > 0.1])/len(data)
        x4 = sum([1 for d in data if d['centr'] > 0.1])/len(data)
        
        x5 = sum([d['S_FS'] for d in data])/len(data)
        x6 = sum([d['S_IPC'] for d in data])/len(data)
        x7 = sum([d['S_KERNEL'] for d in data])/len(data)
        x8 = sum([d['S_MM'] for d in data])/len(data)
        x9 = sum([d['S_NET'] for d in data])/len(data)
        x10 = sum([d['S_SECURITY'] for d in data])/len(data)
        
        return np.array([x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10])

