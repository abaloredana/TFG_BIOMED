import numpy as np
import math
from chipwhisperer.analyzer.attacks.algorithmsbase import AlgorithmsBase
import IPython as ip

#THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/cpa_algorithms/
#This file may be simply added to the previously mentioned directory without need for substituting any of the preexisting files

class CPAProgressiveOneSubkey:
    """This class is the CUSTOMIZED basic progressive CPA attack, capable of adding traces onto a variable with previous data"""
    def __init__(self, model):
        self.model = model
        self.sumhq = [0] * self.model.getPermPerSubkey()
        self.sumtq = [0]
        self.sumt = [0]
        self.sumh = [0] * self.model.getPermPerSubkey()
        self.sumht = [0] * self.model.getPermPerSubkey()
        self.totalTraces = 0
        self.modelstate = {'knownkey': None}

     # Store sumden1 and sumden2 for the current subkey (bnum)
        self.stored_sumden1 = []
        self.stored_sumden2 = []

        
    # List to store tuples of (sumden1, sumden2) for each bnum iteration
        self.stored_sumden_pairs = []  

    def oneSubkey(self, bnum, pointRange, traces_all, numtraces, plaintexts, ciphertexts, knownkeys, progressBar, state, pbcnt):
        diffs = [0] * self.model.getPermPerSubkey()
        self.totalTraces += numtraces

        if pointRange is None:
            traces = traces_all
        else:
            traces = traces_all[:, pointRange[0]:pointRange[1]]

        self.sumtq += np.sum(np.square(traces), axis=0, dtype=np.longdouble)
        self.sumt += np.sum(traces, axis=0, dtype=np.longdouble)
        sumden2 = np.square(self.sumt) - self.totalTraces * self.sumtq

        # Ensure the list is long enough to hold the current index
        # while len(self.stored_sumden2) <= bnum:
        # self.stored_sumden2.append("AYUDA")
        # Assign the value to the correct index
        # self.stored_sumden2[bnum] = sumden2


        for key in range(0, self.model.getPermPerSubkey()):
            sumnum = np.zeros(len(traces[0, :]))
            hyp = [0] * numtraces

            prev_cts = np.insert(ciphertexts[:-1], 0, 0, axis=0)
            prev_pts = np.insert(plaintexts[:-1], 0, 0, axis=0)

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

            self.sumh[key] += np.sum(hyp, axis=0, dtype=np.longdouble)
            self.sumht[key] += np.sum(np.multiply(np.transpose(traces), hyp), axis=1, dtype=np.longdouble)

            sumnum = self.totalTraces * self.sumht[key] - self.sumh[key] * self.sumt

            self.sumhq[key] += np.sum(np.square(hyp), axis=0, dtype=np.longdouble)

            sumden1 = (np.square(self.sumh[key]) - self.totalTraces * self.sumhq[key])

            # Store tuple (sumden1, sumden2) in list
            self.stored_sumden_pairs.append((sumden1, bnum, sumden2))

            sumden = sumden1 * sumden2

            diffs[key] = sumnum / np.sqrt(sumden)

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
                    (data, pbcnt) = cpa[bnum_bf].oneSubkey(
                        bnum_bf, pointRange, traces, tend - tstart, textins, textouts, knownkeys, progressBar, cpa[bnum_bf].modelstate, pbcnt
                    )
                    self.stats.update_subkey(bnum_bf, data, tnum=tend)

                tend += self._reportingInterval
                tstart += self._reportingInterval

                if self.sr:
                    self.sr()
    def get_sumden_pairs(self):
        """Method to collect and return stored sumden1 and sumden2 pairs from all subkey instances."""
        sumden_pairs = []
        for subkey_instance in self.subkey_instances:
            sumden_pairs.extend(subkey_instance.stored_sumden_pairs)
        return sumden_pairs
