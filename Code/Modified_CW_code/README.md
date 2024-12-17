# Modifications to the Chipwhisperer (CW) software files in order to visualize intermediate values of the variance-correlation computations.

Each of the files within this folder must be added to the existing CW directories as follows:

- __init__.py : THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/ 
                This code must substitute the existing __init__.py within said directory

- __init__2.py : THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/cpa_algorithms/
                This code must substitute the existing __init__.py within said directory 
                Remember to remove the "2" from this file's name when adding it to CW 

- _stats.py : THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/
                This code must substitute the existing _stats.py within said directory 

- cpa.py : THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/
                This code must substitute the existing cpa.py within said directory 

- cpa_new.py : THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/
                This code must substitute the existing cpa_new.py within said directory 

- progressive_custom.py : THIS FILE GOES INSIDE chiswhisperer/software/chipwhisperer/analyzer/attacks/cpa_algorithms/
                This file may be simply added to the previously mentioned directory without need for substituting any of the preexisting files.


