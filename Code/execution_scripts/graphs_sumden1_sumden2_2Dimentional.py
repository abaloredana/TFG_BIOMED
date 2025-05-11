import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np
import matplotlib.pyplot as plt
import os

# --- Adjust this path to your desired project file ---
project_file = "/Users/loredana/Desktop/TFG/attackarduino_Abraham_ECG_Malo_16_bits/attackarduino_Abraham_ECG_Malo_16_bits"
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

numTraces = 7000

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

import matplotlib.pyplot as plt
import numpy as np
import os

def visualize_sumden_by_bnum(sumden_pairs, numTraces, project_file):
    """
  
    """
    if not sumden_pairs:
        print("No sumden_pairs data to visualize for sumden1/sumden2.")
        return

    # Extract sumden1, sumden2, and bnum values
    sumden1 = [pair[0] for pair in sumden_pairs]
    bnums   = [pair[1] for pair in sumden_pairs]
    sumden2 = np.array([pair[2] for pair in sumden_pairs])

    unique_bnums = sorted(set(bnums))
    colors = plt.cm.tab20(np.linspace(0, 1, len(unique_bnums)))

    # Just a sample plot for sumden1 overlapping
    overlapping_file = os.path.join(output_dir, f"sumden1_overlapping_{numTraces}.png")
    if not check_existing_graph(overlapping_file, project_file, numTraces):
        plt.figure(figsize=(12, 6))
        for i, bnum in enumerate(unique_bnums):
            bnum_indices = [idx for idx, pair in enumerate(sumden_pairs) if pair[1] == bnum]
            x_axis = range(len(bnum_indices))
            plt.plot(x_axis, [sumden1[idx] for idx in bnum_indices],
                     label=f"bnum {bnum}", color=colors[i], alpha=0.7)
        plt.title(f"Sumden1 Overlapping - {numTraces} Traces")
        plt.xlabel("Index (local to each bnum subset)")
        plt.ylabel("Sumden1")
        plt.legend()
        plt.grid(True)
        plt.savefig(overlapping_file, dpi=300)
        save_metadata(overlapping_file, project_file, numTraces)
        plt.show()

    # Plot for sumden2
    max_info = results_obj.find_maximums()  # => list of length numSubkeys
    numSubkeys = results_obj.numSubkeys
    all_max_idxs = []

    # 'results_obj.diffs[bnum]' => correlation array of shape (256, #points), OJO que results_obj "equivale" a attacks.algorithm
    for bnum in range(numSubkeys):
        if results_obj.diffs[bnum] is None:
            continue

        # best guess is the first entry: (hyp, point, correlation)
        best_guess_tuple = max_info[bnum][0]
        best_hyp = best_guess_tuple[0]
        max_idx = best_guess_tuple[1]
        best_corr = best_guess_tuple[2]
        all_max_idxs.append(max_idx)
    
    print(f"Maximum correlation points:\n{all_max_idxs}")

    for bnum in unique_bnums:
        sumden2_file = os.path.join(output_dir, f"hybrid_lineplot_bnum_{bnum}_{numTraces}.png")
        if not check_existing_graph(sumden2_file, project_file, numTraces):
            bnum_indices = [idx for idx, pair in enumerate(sumden_pairs) if pair[1] == bnum]
            bnum_sumden2 = sumden2[bnum_indices]
            #return bnum_sumden2
            if bnum_sumden2.size == 0:
                continue
            plt.figure(figsize=(12, 6))
            print(bnum_sumden2.shape)
            bnum_sumden2_max = bnum_sumden2[:,max_idx]
            # plt.imshow(bnum_sumden2, aspect="auto", cmap="viridis")
            plt.plot(bnum_sumden2_max)
            plt.title(f"Sumden2 Lineplot bnum={bnum}, {numTraces} Traces")
            plt.xlabel("Points")
            plt.ylabel("Sumden2 Variance at Max Correlation Index")
            plt.savefig(sumden2_file, dpi=300)
            save_metadata(sumden2_file, project_file, numTraces)
            plt.close()
            print(f"Saved lineplot for bnum={bnum} => {sumden2_file}")
            
def plot_sumden1_best_guess(sumden_pairs, results_obj,
                            update_interval, numTraces, output_dir):

    # 1) Find the best‐guess key for each subkey byte at the *end* of the attack
    max_info = results_obj.find_maximums()
    best_hyps = { bnum: max_info[bnum][0][0]
                  for bnum in range(results_obj.numSubkeys) }

    # 2) Organize the stored pairs into a dict[(bnum, hyp)] → [sumden1, ...]
    #    (we assume you modify your CPA to store the hypothesis index too)
    by_pair = {}
    for (sumden1, bnum, hyp, sumden2) in sumden_pairs:
        by_pair.setdefault((bnum, hyp), []).append(sumden1)

    n_batches = numTraces // update_interval
    x = [(i+1)*update_interval for i in range(n_batches)]

    # 3) Plot, for each subkey byte, only the best‐guess curve
    for bnum, hyp in best_hyps.items():
        y = by_pair.get((bnum, hyp), [])
        if len(y) != n_batches:
            print(f"Warning: bnum={bnum}, hyp={hyp} has {len(y)} points, expected {n_batches}")
            continue

        plt.figure(figsize=(8,4))
        plt.plot(x, y, marker='o')
        plt.title(f"Sumden1 (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel("Traces processed")
        plt.ylabel("Sumden1")
        plt.grid(True)
        plt.savefig(f"{output_dir}/sumden1_best_bnum{bnum}.png", dpi=300)
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

    n_batches = numTraces // update_interval
    x = [(i+1)*update_interval for i in range(n_batches)]

    # 3) Plot, for each subkey, the sumden2 at its max_idx for its best hypothesis
    for bnum, (hyp, max_idx) in info.items():
        vectors = by_pair.get((bnum, hyp), [])
        if len(vectors) != n_batches:
            print(f"Warning: bnum={bnum}, hyp={hyp} has {len(vectors)} batches, expected {n_batches}")
            continue

        # extract the single sample-point from each batch
        y = [ vec[max_idx] for vec in vectors ]

        plt.figure(figsize=(8,4))
        plt.plot(x, y, marker='x')
        plt.title(f"Sumden2[@{max_idx}] (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel("Traces processed")
        plt.ylabel(f"Sumden2 @ point {max_idx}")
        plt.grid(True)
        plt.savefig(f"{output_dir}/sumden2_best_bnum{bnum}.png", dpi=300)
        plt.close()


if __name__ == "__main__":

    update_interval = 100       # the second arg to attack.run(...)
    output_dir = os.path.join(os.getcwd(), "graphs", "Mangard", project_name, "{numTraces}_traces")
    os.makedirs(output_dir, exist_ok=True)
    
    if len(sumden_pairs) > 0:
        # Optional: visualize sumden1 & sumden2 from sumden_pairs if your script uses them
        # bnum_sumden2 = visualize_sumden_by_bnum(sumden_pairs, numTraces, project_file)
        #visualize_sumden_at_point_clean(sumden_pairs, numTraces=1000, project_file=project_file, target_idx=12, term="sumden2")
        #plot_sumden1_and_sumden2_vs_traces(sumden_pairs, results_obj, numTraces, project_file)
        plot_sumden1_best_guess(sumden_pairs,
                                results_obj,
                                update_interval,
                                numTraces,
                                output_dir)

        # Plot sumden2 @ each byte’s max_idx (BEST guess):
        plot_sumden2_at_maxidx(sumden_pairs,
                               results_obj,
                               update_interval,
                               numTraces,
                               output_dir)

        print("Done plotting sumden1 & sumden2.")
    else:
        print("No sumden_pairs data available for custom sumden1/sumden2 plotting.\n")

   
