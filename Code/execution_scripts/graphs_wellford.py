import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np
import matplotlib.pyplot as plt
import os


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
print("\nAttack Results (Welford):")
print(attack_run_output)

# Retrieve the ChipWhisperer Results object that has find_maximums()
results_obj = attack.get_statistics()
max_info = results_obj.find_maximums()
numSubkeys = results_obj.numSubkeys
all_max_idxs = []
for bnum in range(numSubkeys):
    if results_obj.diffs[bnum] is None:
        continue
    max_idx = max_info[bnum][0][1]
    all_max_idxs.append(max_idx)
    
print(f"Maximum correlation points:\n{all_max_idxs}")

# Try to get Welford variances
try:
    welford_data = attack.algorithm.get_welford_variances()
except AttributeError:
    print("\nNo 'get_welford_variances()' method on this attack instance.")
    welford_data = []

# Directory for saving graphs
output_dir = os.path.join(os.getcwd(), "graphs/welford")
os.makedirs(output_dir, exist_ok=True)

# Change according to the .cfg  numTraces value
numTraces = 1000

def save_metadata(file_path, project_file, numTraces):
    metadata_file = file_path + ".meta"
    with open(metadata_file, "w") as f:
        f.write(f"{project_file},{numTraces}")
        
def visualize_welford_variance_at_point(welford_data, numTraces, project_file, target_idx):
    if not welford_data:
        print("No Welford variance data to visualize.")
        return

    # Aggregate variance at the target index only
    x_axis = [n for (_, _, n) in welford_data]  # number of traces seen
    y_axis = [var[target_idx] for (var, _, _) in welford_data]  # variance at the specific trace point

    # Sort the data by trace count
    sorted_data = sorted(zip(x_axis, y_axis), key=lambda x: x[0])
    x_axis, y_axis = zip(*sorted_data)

    plt.figure(figsize=(10, 5))
    plt.plot(x_axis, y_axis, marker='o', label=f"Welford Variance at Point {target_idx}")
    plt.xlabel("Number of Traces")
    plt.ylabel(f"Variance at Point {target_idx}")
    plt.title(f"Welford Variance @ Point {target_idx} vs. Traces")
    plt.grid(True)
    plt.legend()

    file_path = os.path.join(output_dir, f"welford_variance_point_{target_idx}_{numTraces}.png")
    plt.savefig(file_path, dpi=300)
    save_metadata(file_path, project_file, numTraces)
    print(f"Saved Welford variance plot at point {target_idx}: {file_path}")

#Varianza media para quitar la segunda dimension de welford
def visualize_welford_variance_global(welford_data, numTraces, project_file):
    if not welford_data:
        print("No Welford variance data to visualize.")
        return

    # Aggregate all entries regardless of bnum
    x_axis = [n for (_, _, n) in welford_data]
    y_axis = [np.mean(var) for (var, _, _) in welford_data]

    # Sort the data by trace count to avoid line artifact
    sorted_data = sorted(zip(x_axis, y_axis), key=lambda x: x[0])
    x_axis, y_axis = zip(*sorted_data)

    plt.figure(figsize=(10, 5))
    plt.plot(x_axis, y_axis, marker='o', label="Global Welford Variance Mean")
    plt.xlabel("Number of Traces")
    plt.ylabel("Mean Variance")
    plt.title("Welford Variance (Global Mean across all points) vs. Traces")
    plt.grid(True)
    plt.legend()

    file_path = os.path.join(output_dir, f"welford_variance_GLOBAL_{numTraces}.png")
    plt.savefig(file_path, dpi=300)
    save_metadata(file_path, project_file, numTraces)
    print(f"Saved global Welford variance plot: {file_path}")

if __name__ == "__main__":
    output_dir = os.path.join(os.getcwd(), "graphs", "Welford", project_name, f"{numTraces}_traces")
    os.makedirs(output_dir, exist_ok=True)
    
    print("\nWelford Variance Snapshots (first 5):")
    for i, (var, bnum, n) in enumerate(welford_data[:5]):
        print(f"  [bnum={bnum}] n={n}, variance shape={var.shape}")

    print("\nWelford Variance Snapshots (last 5):")
    for i, (var, bnum, n) in enumerate(welford_data[-5:]):
        print(f"  [bnum={bnum}] n={n}, variance shape={var.shape}")

    if welford_data:
        #visualize_welford_variance_global(welford_data, numTraces, project_file)
        visualize_welford_variance_at_point(welford_data, numTraces, project_file, target_idx=1)
    else:
        print("No Welford data available for plotting.")
