""" CPA Algorithms

Algorithms:
* Progressive - Online calculation allowing feedback during attack. You probably want this.
* SimpleLoop - Simple attack loop. No feedback before end of attack
* ProgressiveCAccel - Progressive with ctypes to increase speed. Experimental/untested.
* CPAProgressiveCustom - Progressive with graphication and extraction of intermediate statistical values of the attack
"""
#THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/cpa_algorithms/
#This code must substitute the existing __init__.py within said directory AND remove the "2" from this file's name

#from .progressive import CPAProgressive as Progressive
from .simpleloop import CPASimpleLoop as SimpleLoop
from .progressive_caccel import CPAProgressive_CAccel as ProgressiveCAccel
from .progressive_custom import CPAProgressiveCustom  
