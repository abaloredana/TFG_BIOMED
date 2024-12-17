import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np

# Load the project file
project_file = "/Users/loredana/Desktop/TFG/randattackarduino_prueba/randattackarduino_prueba"
project = cw.open_project(project_file)

# Set up the CPA attack
leak_model = cwa.leakage_models.sbox_output
attack = cwa.cpa(project, leak_model)

# Run the attack
print("Type of attack.algorithm:", type(attack.algorithm))
print(dir(attack))

results = attack.run(None, 100)
print("\nAttack Results:")
print(results)

# Retrieve and print stored sumden pairs for verification
try:
    sumden_pairs = attack.algorithm.get_sumden_pairs()
    print("\nStored sumden pairs (sumden1, sumden2):")
    for i, (sumden1, bnum, sumden2) in enumerate(sumden_pairs):
        print(f"Pair {i}: sumden1 = {sumden1}, bnum= {bnum}, sumden2 = {sumden2}")
except AttributeError:
    print("\nError: The method 'get_sumden_pairs()' does not exist in the current attack instance.")

if __name__ == "__main__":
    import sys
    sys.exit(0)
