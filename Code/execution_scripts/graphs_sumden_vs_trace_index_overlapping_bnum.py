import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np
import matplotlib.pyplot as plt
import os

# Load the project file
project_file = "/Users/loredana/Desktop/TFG/randattackarduino_prueba/randattackarduino_prueba"
#project_file = "/Users/loredana/Desktop/TFG/attackarduino_Abraham_ECG_Malo_16_bits/attackarduino_Abraham_ECG_Malo_16_bits"
print(project_file)
project = cw.open_project(project_file)

# Set up the CPA attack
leak_model = cwa.leakage_models.sbox_output
attack = cwa.cpa(project, leak_model)

# Run the attack
results = attack.run(None, 100)
print("\nAttack Results:")
print(results)

# Retrieve stored sumden pairs for verification
try:
    sumden_pairs = attack.algorithm.get_sumden_pairs()
    print("\nStored sumden pairs (sumden1, sumden2):")
except AttributeError:
    print("\nError: The method 'get_sumden_pairs()' does not exist in the current attack instance.")
    sumden_pairs = []

# Directory to save the graphs
output_dir = os.path.join(os.getcwd(), "graphs")
os.makedirs(output_dir, exist_ok=True)

# Ensure numTraces aligns with the actual traces
numTraces = 5000  # Replace this with the value from the .cfg file

# Function to check if the graph should be rewritten
def check_existing_graph(file_path, project_file, numTraces):
    metadata_file = file_path + ".meta"
    if os.path.exists(file_path) and os.path.exists(metadata_file):
        with open(metadata_file, "r") as f:
            stored_project, stored_numTraces = f.read().strip().split(",")
        if stored_project == project_file and int(stored_numTraces) == numTraces:
            return True
    return False

# Save metadata for the graph
def save_metadata(file_path, project_file, numTraces):
    metadata_file = file_path + ".meta"
    with open(metadata_file, "w") as f:
        f.write(f"{project_file},{numTraces}")

def visualize_sumden_by_bnum(sumden_pairs, numTraces, project_file):
    """
    Visualize Sumden1 vs. Traces and Sumden2 heatmaps per bnum with real trace indices.

    Parameters:
    - sumden_pairs: List of tuples containing (sumden1, bnum, sumden2).
    - numTraces: Total number of traces from the .cfg file.
    - project_file: The project file path.
    """
    # Extract sumden1, sumden2, and bnum values
    sumden1 = [pair[0] for pair in sumden_pairs]
    sumden2 = np.array([pair[2] for pair in sumden_pairs])
    bnums = [pair[1] for pair in sumden_pairs]

    # Unique bnums
    unique_bnums = sorted(set(bnums))
    colors = plt.cm.tab20(np.linspace(0, 1, len(unique_bnums)))

    # Divide traces evenly across bnums
    traces_per_bnum = numTraces // len(unique_bnums)

    # Overlapping Sumden1 vs. Traces Plot
    overlapping_file = os.path.join(output_dir, f"sumden1_vs_traces_overlapping_{numTraces}.png")
    if not check_existing_graph(overlapping_file, project_file, numTraces):
        plt.figure(figsize=(12, 6))
        for i, bnum in enumerate(unique_bnums):
            bnum_indices = [idx for idx, pair in enumerate(sumden_pairs) if pair[1] == bnum]
            # real_trace_indices = [traces_per_bnum * bnum + j for j in range(len(bnum_indices))]
            real_trace_indices = range(len(bnum_indices))
            plt.plot(real_trace_indices, [sumden1[idx] for idx in bnum_indices], label=f"bnum {bnum}", color=colors[i], alpha=0.7)
        plt.title(f"Sumden1 vs. Traces (Overlapping bnums) - {numTraces} Traces")
        plt.xlabel("Trace Index")
        plt.ylabel("Sumden1")
        plt.legend()
        plt.grid(True)
        plt.savefig(overlapping_file, dpi=300)
        save_metadata(overlapping_file, project_file, numTraces)
        plt.show()

    # Sumden1 vs. Traces Plot per bnum
    for i, bnum in enumerate(unique_bnums):
        bnum_file = os.path.join(output_dir, f"sumden1_vs_traces_bnum_{bnum}_{numTraces}.png")
        if not check_existing_graph(bnum_file, project_file, numTraces):
            plt.figure(figsize=(12, 6))
            bnum_indices = [idx for idx, pair in enumerate(sumden_pairs) if pair[1] == bnum]
            real_trace_indices = [traces_per_bnum * bnum + j for j in range(len(bnum_indices))]
            plt.plot(real_trace_indices, [sumden1[idx] for idx in bnum_indices], label=f"bnum {bnum}", color=colors[i])
            plt.title(f"Sumden1 vs. Traces (bnum {bnum}) - {numTraces} Traces")
            plt.xlabel("Trace Index")
            plt.ylabel("Sumden1")
            plt.legend()
            plt.grid(True)
            plt.savefig(bnum_file, dpi=300)
            save_metadata(bnum_file, project_file, numTraces)
            plt.show()

    # Heatmaps for Sumden2 per bnum
    for i, bnum in enumerate(unique_bnums):
        heatmap_file = os.path.join(output_dir, f"heatmap_sumden2_bnum_{bnum}_{numTraces}.png")
        if not check_existing_graph(heatmap_file, project_file, numTraces):
            bnum_indices = [idx for idx, pair in enumerate(sumden_pairs) if pair[1] == bnum]
            bnum_sumden2 = sumden2[bnum_indices]
            plt.figure(figsize=(12, 6))
            plt.imshow(bnum_sumden2, aspect="auto", cmap="viridis")
            plt.colorbar(label="Value")
            plt.title(f"Heatmap for Sumden2 (bnum {bnum}) - {numTraces} Traces")
            plt.xlabel("Points")
            plt.ylabel("Trace Index")
            plt.savefig(heatmap_file, dpi=300)
            save_metadata(heatmap_file, project_file, numTraces)
            plt.show()


if __name__ == "__main__":
    # Ensure sumden_pairs is valid
    if len(sumden_pairs) > 0:
        visualize_sumden_by_bnum(sumden_pairs, numTraces, project_file)
    else:
        print("No sumden data available for visualization.")
