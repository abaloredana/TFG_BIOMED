import numpy as np
from chipwhisperer.analyzer.attacks.algorithmsbase import AlgorithmsBase

class CPAProgressiveOneSubkey:
    """Welford‐based progressive CPA for one subkey byte."""
    def __init__(self, model):
        self.model = model
        self.totalTraces = 0
        self.modelstate = {'knownkey': None}

        # Welford for traces
        self.n_welford      = 0
        self.mean_welford   = None   # will become a vector
        self.M2_welford     = None   # Σ(t−t̄)²

        # Per-key accumulators (initialized once we know trace length)
        self.sum_cross_welford   = [None] * self.model.getPermPerSubkey()
        self.sum_centered_hyp_sq = None

        # Store final correlation curves
        self.welford_diffs         = [None] * self.model.getPermPerSubkey()
        #keep variance snapshots
        self.stored_welford_variances = []

    def oneSubkey(self, bnum, pointRange, traces_all, numtraces,
                  plaintexts, ciphertexts, knownkeys,
                  progressBar, state, pbcnt, accumulate_variances):
        diffs = [0] * self.model.getPermPerSubkey()
        self.totalTraces += numtraces

        # 1) Crop if requested
        if pointRange is None:
            traces = traces_all
        else:
            traces = traces_all[:, pointRange[0]:pointRange[1]]

        # 2) Update Welford on the new batch of traces
        for tr in traces:
            self.n_welford += 1
            if self.mean_welford is None:
                self.mean_welford = np.zeros_like(tr, dtype=np.double)
                self.M2_welford   = np.zeros_like(tr, dtype=np.double)
            delta = tr - self.mean_welford
            self.mean_welford += delta / self.n_welford
            delta2 = tr - self.mean_welford
            self.M2_welford += delta * delta2
        #AQUI IBA EL IF ACCUMULATE_VARIANCES AND SELF.N_WELFORD > 1
        if accumulate_variances and self.n_welford > 1:
            var = self.M2_welford / (self.n_welford - 1)
            
        
        num_keys = self.model.getPermPerSubkey()

        # 3) Init per-key hyp-variance arrays once
        if self.sum_centered_hyp_sq is None:
            self.sum_centered_hyp_sq = [
                np.zeros_like(self.mean_welford, dtype=np.double)
                for _ in range(num_keys)
            ]

        # 4) For each candidate key, accumulate cross‐products & hyp‐variance
        for key in range(num_keys):
            # build hypothesized leakage for this batch
            hyp = np.zeros(numtraces, dtype=np.double)
            for i in range(numtraces):
                pt = plaintexts[i]
                ct = ciphertexts[i]
                nk = knownkeys[i] if knownkeys else None
                state['knownkey'] = nk

                if self.model._has_prev:
                    hyp[i] = self.model.leakage(pt, ct, pt, ct, key, bnum, state)
                else:
                    hyp[i] = self.model.leakage(pt, ct, key, bnum, state)

            # init cross‐product accumulator
            if self.sum_cross_welford[key] is None:
                self.sum_cross_welford[key] = np.zeros_like(self.mean_welford, dtype=np.double)

            hyp_mean = hyp.mean()
            centered_hyp = hyp - hyp_mean

            for i, tr in enumerate(traces):
                centered_tr = tr - self.mean_welford
                self.sum_cross_welford[key]   += centered_hyp[i] * centered_tr
                self.sum_centered_hyp_sq[key] += centered_hyp[i] ** 2

            # 5) Compute Pearson-style r (Mangard Eq.6.2) once we have ≥2 traces
            if self.n_welford > 1:
                hyp_ssq   = self.sum_centered_hyp_sq[key]  # Σ(h−h̄)²
                hyp_ssq_normalized = hyp_ssq / (self.n_welford - 1)
                trace_ssq = self.M2_welford               # Σ(t−t̄)²
                if accumulate_variances:
                    self.stored_welford_variances.append((np.copy(hyp_ssq_normalized[0]), bnum, key, np.copy(var)))

                denom     = np.sqrt(hyp_ssq * trace_ssq)
                denom[denom == 0] = 1e-12
                
                corr      = self.sum_cross_welford[key] / denom
                self.welford_diffs[key] = corr
                diffs[key]             = corr

            # progress callback
            if progressBar:
                progressBar.updateStatus(pbcnt,
                  (self.totalTraces - numtraces,
                   self.totalTraces - 1,
                   bnum))
            pbcnt += 1

        return diffs, pbcnt


class CPAProgressiveCustom(AlgorithmsBase):
    """Wraps CPAProgressiveOneSubkey to progressively add traces."""
    _name = "Progressive Custom"

    def __init__(self):
        super().__init__()
        self.subkey_instances = []
        self.getParams().addChildren([
            {'name': 'Iteration Mode', 'key': 'itmode',
             'type': 'list',
             'values': {'Depth-First':'df','Breadth-First':'bf'},
             'value':'bf','action':self.updateScript},
            {'name': 'Skip when PGE=0', 'key':'checkpge',
             'type':'bool','value':False,'action':self.updateScript},
        ])
        self.updateScript()

    def addTraces(self, traceSource, tracerange, progressBar=None, pointRange=None):
        # numtraces = tracerange[1] - tracerange[0] + 1
        numtraces = tracerange[1] - tracerange[0]
        pbcnt = 0

        # one CPAProgressiveOneSubkey per byte
        cpa = [None] * (max(self.brange) + 1)
        for bnum in self.brange:
            cpa_instance = CPAProgressiveOneSubkey(self.model)
            cpa[bnum] = cpa_instance
            self.subkey_instances.append(cpa_instance)

        # breadth-first over batches
        for bnum in self.brange:
            tstart = 0
            tend   = self._reportingInterval

            while tstart < numtraces:
                if tend > numtraces:
                    tend = numtraces

                data, textins, textouts, knownkeys = [], [], [], []
                for i in range(tstart, tend):
                    tnum = i + tracerange[0]
                    data.append(traceSource.get_trace(tnum))
                    textins.append( traceSource.get_textin(tnum) )
                    textouts.append(traceSource.get_textout(tnum))
                    knownkeys.append(traceSource.get_known_key(tnum))

                traces   = np.array(data)
                textins     = np.array(textins)
                textouts   = np.array(textouts)

                accumulate_variances = (tstart >= 0 and tend <= 5000)

                diffs, pbcnt = cpa[bnum].oneSubkey(
                    bnum, pointRange,traces, tend - tstart,textins, textouts, knownkeys,progressBar, cpa[bnum].modelstate,
                    pbcnt, accumulate_variances)

                self.stats.update_subkey(bnum, diffs, tnum=tend)
                
                tend   += self._reportingInterval
                tstart += self._reportingInterval
                if self.sr: self.sr()

    def get_welford_variances(self):
        vals = []
        for inst in self.subkey_instances:
            vals.extend(inst.stored_welford_variances)
        return vals
