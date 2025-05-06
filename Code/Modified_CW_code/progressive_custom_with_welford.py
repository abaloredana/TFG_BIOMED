import numpy as np
import math
from chipwhisperer.analyzer.attacks.algorithmsbase import AlgorithmsBase
import IPython as ip

class CPAProgressiveOneSubkey:
    """This class is the WELFORD BASED CUSTOMIZED basic progressive CPA attack, capable of adding traces onto a variable with previous data"""
    def __init__(self, model):
        self.model = model
        self.totalTraces = 0
        self.modelstate = {'knownkey': None}

        # Initialize Welford's Variables 
        self.n_welford = 0
        self.mean_welford = None  # Will be initialized based on trace shape
        self.M2_welford = None
        self.sum_cross_welford = [None] * self.model.getPermPerSubkey()
        self.stored_welford_variances = []  # for storing wellford variance
        self.welford_diffs = [None] * self.model.getPermPerSubkey()

    def oneSubkey(self, bnum, pointRange, traces_all, numtraces, plaintexts, ciphertexts, knownkeys, progressBar, state, pbcnt, accumulate_variances):
        diffs = [0] * self.model.getPermPerSubkey()
        self.totalTraces += numtraces

        if pointRange is None:
            traces = traces_all
        else:
            traces = traces_all[:, pointRange[0]:pointRange[1]]

        # Update Welford
        for trace in traces:
            self.n_welford += 1
            if self.mean_welford is None:
                self.mean_welford = np.zeros_like(trace, dtype=np.longdouble)
                self.M2_welford = np.zeros_like(trace, dtype=np.longdouble)
            delta = trace - self.mean_welford #difference between the new trace and old mean
            self.mean_welford += delta / self.n_welford
            delta2 = trace - self.mean_welford #difference between the new trace and the new mean (after update)
            self.M2_welford += delta * delta2 # building sum of squared diffs
            
            # if accumulate_variances and self.n_welford > 1:
            #     current_variance = self.M2_welford / (self.n_welford - 1)
            #     self.stored_welford_variances.append((np.copy(current_variance), bnum, self.n_welford))

        #For each 0..0xFF possible value of the key byte
        for key in range(0, self.model.getPermPerSubkey()):
            #Initialize arrays & variables to zero
            hyp = [0] * numtraces

            #Formula for CPA & description found in "Power Analysis Attacks"
            # by Mangard et al, page 124, formula 6.2.
            #
            # This has been modified to reduce computational requirements such that adding a new waveform
            # doesn't require you to recalculate everything
            prev_cts = np.insert(ciphertexts[:-1], 0, 0, axis=0)
            prev_pts = np.insert(plaintexts[:-1], 0, 0, axis=0)

            #Generate hypotheticals
            for tnum in range(numtraces):
                if len(plaintexts) > 0:
                    pt = plaintexts[tnum]

                if len(ciphertexts) > 0:
                    ct = ciphertexts[tnum]

                if len(prev_cts) > 0:
                    prev_ct = prev_cts[tnum]

                if len(prev_pts) > 0:
                    prev_pt = prev_pts[tnum]

                if knownkeys and len(knownkeys) > 0:
                    nk = knownkeys[tnum]
                else:
                    nk = None

                state['knownkey'] = nk

                if self.model._has_prev:
                    hypint = self.model.leakage(pt, ct, prev_pt, prev_ct, key, bnum, state)
                else:
                    hypint = self.model.leakage(pt, ct, key, bnum, state)

                hyp[tnum] = hypint

            hyp = np.array(hyp)

            if self.sum_cross_welford[key] is None:
                self.sum_cross_welford[key] = np.zeros_like(self.mean_welford, dtype=np.longdouble)

            centered_hyp = hyp - np.mean(hyp)
            for i in range(len(traces)):
                centered_trace = traces[i] - self.mean_welford
                self.sum_cross_welford[key] += centered_hyp[i] * centered_trace

            #Store Welford variances
            if accumulate_variances and self.n_welford >1:
                current_variance = self.M2_welford / (self.n_welford - 1)
                self.stored_welford_variances.append((np.copy(current_variance), bnum, self.n_welford))

            #THIS GUESSES CORRECTLY THE KEY BUT GIVES CORRELATIONS > 1!!!
            # if self.n_welford > 1:
            #     hyp_var = np.sum(centered_hyp ** 2)
            #     denom = np.sqrt(hyp_var * self.M2_welford)
            #     welford_corr = self.sum_cross_welford[key] / denom
            #     self.welford_diffs[key] = welford_corr
            #     diffs[key] = welford_corr

        
            #OTHER APPROACH, STILL CORR >1
        
            if self.n_welford > 1:
                n = self.n_welford

                hyp_sum = np.sum(centered_hyp, dtype=np.longdouble)
                hyp_sqsum = np.sum(centered_hyp ** 2, dtype=np.longdouble)

                # sumden1 = (hyp_sum ** 2 - n * hyp_sqsum)
                sumden1 = hyp_sqsum * n - hyp_sum ** 2

                trace_variance = self.M2_welford / (self.n_welford - 1)

                denom = np.sqrt(sumden1 * trace_variance)
                denom[denom == 0] = 1e-12  # prevent division by zero

                corr = self.sum_cross_welford[key] / denom

                self.welford_diffs[key] = corr
                diffs[key] = corr

            if progressBar:
                progressBar.updateStatus(pbcnt, (self.totalTraces - numtraces, self.totalTraces - 1, bnum))
            pbcnt += 1

        return (diffs, pbcnt)

   
class CPAProgressiveCustom(AlgorithmsBase):
    """CPA Attack done as a loop, using an algorithm which can progressively add traces & give output stats"""
    _name = "Progressive Custom"

    def __init__(self):
        AlgorithmsBase.__init__(self)
        super().__init__()
        self.subkey_instances = []  # Added to store CPAProgressiveOneSubkey instances

        self.getParams().addChildren([
            {'name': 'Iteration Mode', 'key': 'itmode', 'type': 'list', 'values': {'Depth-First': 'df', 'Breadth-First': 'bf'}, 'value': 'bf', 'action': self.updateScript},
            {'name': 'Skip when PGE=0', 'key': 'checkpge', 'type': 'bool', 'value': False, 'action': self.updateScript},
        ])
        self.updateScript()

    def addTraces(self, traceSource, tracerange, progressBar=None, pointRange=None):
        numtraces = tracerange[1] - tracerange[0] + 1
        pbcnt = 0
        cpa = [None] * (max(self.brange) + 1)
        for bnum in self.brange:
            cpa_instance = CPAProgressiveOneSubkey(self.model)
            cpa[bnum] = cpa_instance
            self.subkey_instances.append(cpa_instance)  # Track the instance
        for bnum_df in [0]:
            tstart = 0
            tend = self._reportingInterval

            while tstart < numtraces:
                if tend > numtraces:
                    tend = numtraces

                data = []
                textins = []
                textouts = []
                knownkeys = []
                for i in range(tstart, tend):
                    tnum = i + tracerange[0]
                    try:
                        data.append(traceSource.get_trace(tnum))
                        textins.append(traceSource.get_textin(tnum))
                        textouts.append(traceSource.get_textout(tnum))
                        knownkeys.append(traceSource.get_known_key(tnum))
                    except Exception as e:
                        if progressBar:
                            progressBar.abort(e.message)
                        return

                traces = np.array(data)
                textins = np.array(textins)
                textouts = np.array(textouts)

                for bnum_bf in self.brange:
                    #Chnage values according to the interval of traces that we want to study
                    # accumulate_variances = True
                    if tstart >= 0 and tend <= 1001:   # Error interval for ECG data is [18500, 46975]
                        accumulate_variances = True
                    (data, pbcnt) = cpa[bnum_bf].oneSubkey(
                        bnum_bf, pointRange, traces, tend - tstart, textins, textouts, knownkeys, progressBar, cpa[bnum_bf].modelstate, pbcnt, accumulate_variances
                    )
                    self.stats.update_subkey(bnum_bf, data, tnum=tend)

                tend += self._reportingInterval
                tstart += self._reportingInterval
                if self.sr:
                    self.sr()

    def get_welford_variances(self):
        all_vars = []
        for subkey_instance in self.subkey_instances:
            all_vars.extend(subkey_instance.stored_welford_variances)
        return all_vars
