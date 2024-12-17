#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013-2014, NewAE Technology Inc
# All rights reserved.
#
# Authors: Colin O'Flynn
#
# Find this and more at newae.com - this file is part of the chipwhisperer
# project, http://www.assembla.com/spaces/chipwhisperer
#
#    This file is part of chipwhisperer.
#
#    chipwhisperer is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    chipwhisperer is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with chipwhisperer.  If not, see <http://www.gnu.org/licenses/>.
#=================================================

import sys
#from chipwhisperer.analyzer.attacks.cpa_algorithms.progressive import CPAProgressive
from chipwhisperer.analyzer.attacks.cpa_algorithms.progressive_custom import CPAProgressiveCustom
from ._base import AttackBaseClass

#THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/
#This code must substitute the existing cpa.py within said directory 

class CPA(AttackBaseClass):
    """Correlation Power Analysis Attack

    Before running attack, set a leak model (set_leak_model()). By default
    attacks all keys using all traces.
    Basic usage:

    .. code:: python
        >>> import chipwhisperer as cw
        >>> import chipwhisperer.analyzer as cwa
        >>> project = cw.open_project("project.cwp")
        >>> attack = cwa.cpa(project.trace_manager())
        >>> leak_model = cwa.AES128(cw.aes128leakage.SBox_output)
        >>> attack.set_leak_model(leak_model)
        >>> attack.process_traces()
    """
    _name = "CPA"

    def __init__(self):
        # self._analysisAlgorithm = CPAProgressive()
        self._analysisAlgorithm = CPAProgressiveCustom()
        AttackBaseClass.__init__(self)
        self.updateScript()

    def updateScript(self, _=None):
        AttackBaseClass.updateScript(self)

        analysAlgoStr = sys.modules[self._analysisAlgorithm.__class__.__module__].__name__ + '.' + self._analysisAlgorithm.__class__.__name__
        model_path = None
        cryptoalg = None
        hwmodel = None


    def process_known_key(self, inpkey):
        if inpkey is None:
            return None

        if hasattr(self.attack, 'process_known_key'):
            return self.attack.process_known_key(inpkey)
        else:
            return inpkey

    def getStatistics(self):
        return self.attack.getStatistics()

    def get_variance_terms(self):
        """Method to retrieve variance terms from the analysis algorithm."""
        if hasattr(self._analysisAlgorithm, 'get_variance_terms'):
            return self._analysisAlgorithm.get_variance_terms()
        else:
            return {'sumden1': [], 'sumden2': []}  # Return empty if not available

