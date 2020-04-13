from . import PrioritizationTechnique, threaded

import os
import networkx as nx
import numpy as np
import angr
import pickle

import logging
l = logging.getLogger("driller.prioritization_techniques.syml")

class SyMLSearch(PrioritizationTechnique):
    def __init__(self, binary, target_os, target_arch):
        super(SyMLSearch, self).__init__(binary=binary, target_os=target_os, target_arch=target_arch)
        
        # static analysis
        #dscout_bow = archr.arsenal.DataScoutBow(self.target)
        #proj_bow = archr.arsenal.angrProjectBow(self.target, dscout_bow)
        #project = proj_bow.fire(auto_load_libs=False)
        project = angr.Project(binary, auto_load_libs=False)
        cfg = project.analyses.CFGFast(fail_fast=True, normalize=True, objects=[project.loader.main_object]).model
        self.centr = {n.addr: np.around(centr, 3) for n, centr in nx.betweenness_centrality(cfg.graph, min(len(cfg.graph.nodes), 400)).items()}
        self.conn = {n.addr: conn for n, conn in cfg.graph.degree}
        
        funcs = cfg.project.kb.functions
        self.func_addrs = {n.addr: n.function_address for n in cfg.nodes()}
        self.func_size = {f: funcs[f].size for f in funcs}
        self.func_cpx = dict()
        for f in funcs:
            edges = len(funcs[f].graph.edges())
            nodes = len(funcs[f].graph.nodes())
            parts = nx.components.number_strongly_connected_components(funcs[f].graph)
            self.func_cpx[f] = edges - nodes + 2 * parts
        
        self.scores = dict()
        
        classifier_path = f"{os.path.dirname(os.path.realpath(binary))}/classifiers/xgb.{os.path.basename(binary)}.pkl"
        with open(classifier_path, 'rb') as f:
            self.classifier = pickle.load(f)
            
        self.updating = False

    @threaded
    def update(self, seeds):
        super(SyMLSearch, self).update(seeds=seeds)

        new_seeds = [s for s in seeds if s not in self.scores]
        if self.updating or not new_seeds: return
        
        self.updating = True
        l.debug(f"Updating... [{len(new_seeds)}]")

        for s in seeds:
            # trace
            try:
                trace = self.trace(s, calls=True, syscalls=True)
                # extract features
                x = self.get_features(trace)
                # update scores
                self.scores[s] = self.classifier.predict_proba(x)[0, 1]
            except: self.scores[seed] = 0.0
                
        # clean up
        self.scores = {s:self.scores[s] for s in seeds}
        
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
        x0 = sum([d['num_calls'] for d in datapoints])/len(datapoints)
        x1 = sum([1 for d in datapoints if d['f_cpx'] > 15])/len(datapoints)
        x2 = sum([1 for d in datapoints if d['f_cpx'] > 30])/len(datapoints)
        x3 = sum([1 for d in datapoints if d['f_cpx']/d['f_size'] > 0.1])/len(datapoints)
        x4 = sum([1 for d in datapoints if d['centr'] > 0.1])/len(datapoints)
        x5 = sum([d['S_FS'] for d in datapoints if d['f_cpx']/d['f_size'] > 0.1])/(1+sum([d['S_FS'] for d in datapoints]))
        x6 = sum([d['S_IPC'] for d in datapoints if d['f_cpx']/d['f_size'] > 0.1])/(1+sum([d['S_IPC'] for d in datapoints]))
        x7 = sum([d['S_KERNEL'] for d in datapoints if d['f_cpx']/d['f_size'] > 0.1])/(1+sum([d['S_KERNEL'] for d in datapoints]))
        x8 = sum([d['S_MM'] for d in datapoints if d['f_cpx']/d['f_size'] > 0.1])/(1+sum([d['S_MM'] for d in datapoints]))
        x9 = sum([d['S_NET'] for d in datapoints if d['f_cpx']/d['f_size'] > 0.1])/(1+sum([d['S_NET'] for d in datapoints]))
        x10 = sum([d['S_SECURITY'] for d in datapoints if d['f_cpx']/d['f_size'] > 0.1])/(1+sum([d['S_SECURITY'] for d in datapoints]))
        
        return np.array([x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10])

