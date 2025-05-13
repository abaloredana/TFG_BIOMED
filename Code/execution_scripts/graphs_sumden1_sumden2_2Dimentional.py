import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np
import matplotlib.pyplot as plt
import os

# --- Adjust this path to your desired project file ---
project_file = "/Users/loredana/Desktop/TFG/randattackarduino_prueba/randattackarduino_prueba"
print(f"Project file: {project_file}")
project_name = os.path.basename(project_file)

# Open the project
project = cw.open_project(project_file)

# Set up the CPA attack
leak_model = cwa.leakage_models.sbox_output
attack = cwa.cpa(project, leak_model)
print("CPA algorithm in use:", type(attack.algorithm))
print("Defined in file:", attack.algorithm.__class__.__module__)

# Run the attack
attack_run_output = attack.run(None, 100)
print("\nAttack Results (Mangard):")
print(attack_run_output)

# Retrieve the ChipWhisperer Results object that has find_maximums()
results_obj = attack.get_statistics()  # This returns a standard 'Results' instance

try:
    sumden_pairs = attack.algorithm.get_sumden_pairs()
    print("\nCustom sumden_pairs (sumden1, sumden2) retrieved from get_sumden_pairs():")
    # Print just the first 5 for brevity
    for i, sp in enumerate(sumden_pairs[:5]):
        print(f"  Pair {i}: {sp}")
except AttributeError:
    print("\nNo 'get_sumden_pairs()' method on this attack instance.")
    sumden_pairs = []

max_info =results_obj.find_maximums()
numSubkeys = results_obj.numSubkeys

# Directory for saving graphs
output_dir = os.path.join(os.getcwd(), "graphs/Mangard")
os.makedirs(output_dir, exist_ok=True)

# If the .cfg says numTraces=1000, 5000, or 10000, set it here:

numTraces = 50000

# Check/Save metadata to avoid overwriting
def check_existing_graph(file_path, project_file, numTraces):
    metadata_file = file_path + ".meta"
    if os.path.exists(file_path) and os.path.exists(metadata_file):
        with open(metadata_file, "r") as f:
            stored_project, stored_numTraces = f.read().strip().split(",")
        if stored_project == project_file and int(stored_numTraces) == numTraces:
            return True
    return False

def save_metadata(file_path, project_file, numTraces):
    metadata_file = file_path + ".meta"
    with open(metadata_file, "w") as f:
        f.write(f"{project_file},{numTraces}")

            
def plot_sumden1_best_guess(sumden_pairs, results_obj,
                            update_interval, numTraces, output_dir):

    # 1) Find the best‐guess key for each subkey byte at the *end* of the attack
    max_info = results_obj.find_maximums()
    best_hyps = { bnum: max_info[bnum][0][0]
                  for bnum in range(results_obj.numSubkeys) }

    
    # 2) Organize the stored pairs into a dict[(bnum, hyp)] → [sumden1, ...]
    
    by_pair = {}
    for (sumden1, bnum, hyp, sumden2) in sumden_pairs:
        
        by_pair.setdefault((bnum, hyp), []).append(sumden1)
        
    # 2.5)Conditions for x-axis adjustment
    n_batches = numTraces // update_interval
    start_trace_subset = 18000   #must match the value for tstart in accumulate_sumdens conditional within progressive class
    end_trace_subset = 48000    #must match the value for tend in accumulate_sumdens conditional within progressive class
    subTraces = end_trace_subset - start_trace_subset
    subset_batches = subTraces // update_interval

    # 3) Plot, for each subkey byte, only the best‐guess curve
    for bnum, hyp in best_hyps.items():
        y = by_pair.get((bnum, hyp), [])
        
        x = [(i+1)*update_interval for i in range(n_batches)] #For numTraces attack
        
        if len(y) != n_batches:
            if len(y) == subset_batches:
                x = [(i+1)*update_interval for i in range(subset_batches)] #For subTraces attack
            elif len(y) != subset_batches:
                print(f"Warning: x and y axis out of expected ranges")
        
    

        plt.figure(figsize=(8,4))
        plt.plot(x, y, marker='.')
        plt.title(f"Sumden1 (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel(f"Traces processed: [{start_trace_subset}, {end_trace_subset}]")
        plt.ylabel("Sumden1")
        plt.grid(True)
        plt.savefig(f"{output_dir}/sumden1_best_bnum{bnum}_{subset_batches}batches.png", dpi=300)
        plt.close()
        
def plot_sumden2_at_maxidx(sumden_pairs, results_obj,
                           update_interval, numTraces, output_dir):

    # 1) Find, for each subkey, its max_idx (sample-point) & best hypothesis
    max_info = results_obj.find_maximums()
    # max_info[bnum][0] == (best_hyp, max_idx, best_corr)
    info = { bnum: (max_info[bnum][0][0], max_info[bnum][0][1])
             for bnum in range(results_obj.numSubkeys) }

    # 2) Organize the stored sumden2 into dict[(bnum,hyp)] → [ sumden2_vector, ... ]
    by_pair = {}
    for (sumden1, bnum, hyp, sumden2) in sumden_pairs:
            
        by_pair.setdefault((bnum, hyp), []).append(sumden2)
    
     # 2.5)Conditions for x-axis adjustment
    n_batches = numTraces // update_interval
    start_trace_subset = 18000   #must match the value for tstart in accumulate_sumdens conditional within progressive class
    end_trace_subset = 48000    #must match the value for tend in accumulate_sumdens conditional within progressive class
    subTraces = end_trace_subset - start_trace_subset
    subset_batches = subTraces // update_interval

  

    # 3) Plot, for each subkey, the sumden2 at its max_idx for its best hypothesis
    for bnum, (hyp, max_idx) in info.items():
        vectors = by_pair.get((bnum, hyp), [])
        # extract the single sample-point from each batch
        y = [ vec[max_idx] for vec in vectors ]
        
        x = [(i+1)*update_interval for i in range(n_batches)] #For numTraces attack
        if len(vectors) != n_batches:
            if len(vectors) == subset_batches:
                x = [(i+1)*update_interval for i in range(subset_batches)] #For subTraces attack
            elif len(vectors) != subset_batches:
                print(f"Warning: x and y axis out of expected ranges")
     

        plt.figure(figsize=(8,4))
        plt.plot(x, y, marker='|')
        plt.title(f"Sumden2[@{max_idx}] (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel(f"Traces processed: [{start_trace_subset}, {end_trace_subset}]")
        plt.ylabel(f"Sumden2 @ point {max_idx}")
        plt.grid(True)
        plt.savefig(f"{output_dir}/sumden2_best_bnum{bnum}_{subset_batches}batches.png", dpi=300)
        plt.close()


if __name__ == "__main__":

    update_interval = 100       # the second arg to attack.run(...)
    output_dir = os.path.join(os.getcwd(), "graphs", "Mangard", project_name, f"{numTraces}_traces")
    os.makedirs(output_dir, exist_ok=True)
    
    if len(sumden_pairs) > 0:
        
        # bnum_sumden2 = visualize_sumden_by_bnum(sumden_pairs, numTraces, project_file)
        #visualize_sumden_at_point_clean(sumden_pairs, numTraces=1000, project_file=project_file, target_idx=12, term="sumden2")
        #plot_sumden1_and_sumden2_vs_traces(sumden_pairs, results_obj, numTraces, project_file)
        by_pair1 = plot_sumden1_best_guess(sumden_pairs,
                                results_obj,
                                update_interval,
                                numTraces,
                                output_dir)

        # Plot sumden2 @ each byte’s max_idx (BEST guess):
        by_pair2 = plot_sumden2_at_maxidx(sumden_pairs,
                               results_obj,
                               update_interval,
                               numTraces,
                               output_dir)

        print("Done plotting sumden1 & sumden2.")
    else:
        print("No sumden_pairs data available for custom sumden1/sumden2 plotting.\n")

   
