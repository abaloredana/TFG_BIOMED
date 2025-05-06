import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np
import matplotlib.pyplot as plt
import os

# --- Adjust this path to your desired project file ---
project_file = "/Users/loredana/Desktop/TFG/randattackarduino_prueba/randattackarduino_prueba"
print(f"Project file: {project_file}")

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
print("\nResults Object:", results_obj)

# Some scripts store "sumden_pairs" for custom usage. If you have a custom method, try:
try:
    sumden_pairs = attack.algorithm.get_sumden_pairs()
    print("\nCustom sumden_pairs (sumden1, sumden2) retrieved from get_sumden_pairs():")
    # Print just the first 5 for brevity
    for i, sp in enumerate(sumden_pairs[:5]):
        print(f"  Pair {i}: {sp}")
except AttributeError:
    print("\nNo 'get_sumden_pairs()' method on this attack instance.")
    sumden_pairs = []

# Directory for saving graphs
output_dir = os.path.join(os.getcwd(), "graphs/Mangard")
os.makedirs(output_dir, exist_ok=True)

# If your .cfg says numTraces=1000, 5000, or 10000, set it here:
numTraces = 1000

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

############################################
# Example sumden1/sumden2 visualization code
############################################
def visualize_sumden_by_bnum(sumden_pairs, numTraces, project_file):
    """
    Example code to visualize sumden1 vs. Traces and sumden2 heatmaps per bnum
    if sumden_pairs is available. Adjust as needed.
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


###############################################
# MAIN EXECUTION
###############################################
if __name__ == "__main__":
    if len(sumden_pairs) > 0:
        # Optional: visualize sumden1 & sumden2 from sumden_pairs if your script uses them
        bnum_sumden2 = visualize_sumden_by_bnum(sumden_pairs, numTraces, project_file)
        # print(bnum_sumden2)
    else:
        print("No sumden_pairs data available for custom sumden1/sumden2 plotting.\n")

    # Now we get the standard Results object from the CPA
    # results_obj = attack.get_statistics()  # => built-in 'Results' with find_maximums, numSubkeys
    # if results_obj is not None:
    #     # Plot sumden2 line graphs from find_maximums
    #     plot_sumden2_line(attack, results_obj, project_file, numTraces)
    # else:
    #     print("Error: Could not retrieve standard Results object from 'attack.get_statistics()'.")
