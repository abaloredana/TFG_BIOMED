import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np
import matplotlib.pyplot as plt
import os

#project_file = "/Users/loredana/Desktop/TFG/attackarduino_Abraham_ECG_Malo_16_bits/attackarduino_Abraham_ECG_Malo_16_bits"
project_file = "/Users/loredana/Desktop/TFG/randattackarduino_prueba/randattackarduino_prueba"
print(f"Project file: {project_file}")
project_name = os.path.basename(project_file)

# Open the ChipWhisperer project
project = cw.open_project(project_file)

# Set up the CPA attack (must be using your Welford‐based algorithm)
leak_model = cwa.leakage_models.sbox_output
attack = cwa.cpa(project, leak_model)
print("CPA algorithm in use:", type(attack.algorithm))
print("Defined in file:", attack.algorithm.__class__.__module__)

# --- Run the attack ---
# This 'update_interval' must match the second argument below.
update_interval = 100
attack_run_output = attack.run(None, update_interval)
print("\nAttack Results (Welford-based):")
print(attack_run_output)

# Retrieve the standard Results object
results_obj = attack.get_statistics()

# --- Grab the Welford data ---
try:
    welford_data = attack.algorithm.get_welford_variances()
    print("\nSample of Welford variances (hyp_ssq_normalized, bnum, hyp, var):")
    for i, entry in enumerate(welford_data[:5]):
        print(f"  Entry {i}: {entry}")
except AttributeError:
    print("\nNo 'get_welford_variances()' method found on this attack instance.")
    welford_data = []

# --- Prepare output directory ---
# Manually set total traces (must match your experiment)
numTraces = 5000
# 3) X‐axis: batches of traces
n_batches = numTraces // update_interval
start_trace_subset = 0
end_trace_subset = 5000
subTraces = end_trace_subset - start_trace_subset
subset_batches = subTraces // update_interval

output_dir = os.path.join(os.getcwd(), "graphs", "Welford", project_name, f"{numTraces}_traces")
os.makedirs(output_dir, exist_ok=True)

def plot_hyp_variance_normalized_best_guess(wdata, results, upd_int, nTraces, out_dir):
    """
    Plot hyp_var_normalized vs. number of traces, for each byte's best guess.
    """
    # 1) Find best hypothesis for each subkey
    max_info = results.find_maximums()
    best_hyps = { bnum: max_info[bnum][0][0]
                  for bnum in range(results.numSubkeys) }

    # 2) Organize into dict[(bnum, hyp)] → [hyp_ssq_normalized, ...]
    by_pair = {}
    for (hyp_ssq_norm, bnum, hyp, var) in wdata:
        by_pair.setdefault((bnum, hyp), []).append(hyp_ssq_norm)

    # 3) X‐axis: batches of traces
    n_batches = nTraces // upd_int
    x = [(i+1)*upd_int for i in range(n_batches)]

    # 4) Plot one figure per subkey
    for bnum, hyp in best_hyps.items():
        y = by_pair.get((bnum, hyp), [])
        if len(y) != n_batches:
            print(f"Warning: expected {n_batches} points for bnum={bnum}, hyp=0x{hyp:02x}, got {len(y)}")
        plt.figure(figsize=(8,4))
        plt.plot(x, y, marker='.')
        plt.title(f"Hypothesis variance: hyp_ssq_normalized (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel(f"Traces processed: [{start_trace_subset}, {end_trace_subset}]")
        plt.ylabel("hyp_ssq_normalized")
        plt.grid(True)
        plt.savefig(os.path.join(out_dir, f"hyp_ssq_normalized_best_bnum{bnum}_{n_batches}batches.png"), dpi=300)
        plt.close()

def plot_trace_variance_normalized_best_guess(wdata, results, upd_int, nTraces, out_dir):
    """
    Plot trace variance vs. number of traces, for each byte's best guess, at the sample point of max correlation.
    """
    # 1) Find best hypothesis for each subkey
    max_info = results.find_maximums()
    # max_info[bnum][0] == (best_hyp, max_idx, best_corr)
    best_hyps = { bnum: (max_info[bnum][0][0], max_info[bnum][0][1])
             for bnum in range(results_obj.numSubkeys) } #trully best_info
             
    # 2) Organize into dict[(bnum, hyp)] → [var, ...]
    by_pair = {}
    for (hyp_ssq_norm, bnum, hyp, var) in wdata:
        by_pair.setdefault((bnum, hyp), []).append(var)


    

    # 4) Plot one figure per subkey, the trace variance at its max_idx for its best hypothesis
    for bnum, (hyp, max_idx) in best_hyps.items():
        x = [(i+1)*upd_int for i in range(n_batches)] #For numTraces attack
        vectors = by_pair.get((bnum, hyp), [])
        # extract the single sample-point from each batch
        y = [ vec[max_idx] for vec in vectors ]
        
        if len(vectors) != n_batches:
            if len(vectors) == subset_batches:
                x = [(i+1)*update_interval for i in range(subset_batches)] #For subTraces attack
            elif len(vectors) != subset_batches:
                print(f"Warning: expected {n_batches} points for bnum={bnum}, hyp=0x{hyp:02x}, got {len(y)}")
        plt.figure(figsize=(8,4))
        plt.plot(x, y, marker='|')
        plt.title(f"Trace variance: var (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel(f"Traces processed: [{start_trace_subset}, {end_trace_subset}]")
        plt.ylabel(f"trace_var_normalized @ point {max_idx}")
        plt.grid(True)
        plt.savefig(os.path.join(out_dir, f"variance_best_bnum{bnum}_{n_batches}batches.png"), dpi=300)
        plt.close()

if __name__ == "__main__":
    if len(welford_data) > 0:
        plot_hyp_variance_normalized_best_guess(welford_data, results_obj,
                                           update_interval, numTraces, output_dir)
        plot_trace_variance_normalized_best_guess(welford_data, results_obj,
                                 update_interval, numTraces, output_dir)
        print("Done plotting Welford data.")
    else:
        print("No Welford data available for plotting.")
