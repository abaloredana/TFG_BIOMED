import importlib
import chipwhisperer as cw
import chipwhisperer.analyzer as cwa
import numpy as np
import matplotlib.pyplot as plt
import os

# --- Adjust this path to your desired project file ---
#project_file = "/Users/loredana/Desktop/TFG/attackarduino_Abraham_ECG_Malo_16_bits/attackarduino_Abraham_ECG_Malo_16_bits"
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
update_interval = 100
# Run the attack
attack_run_output = attack.run(None, update_interval)
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
    
print("\n— Checking for get_diffs_history() method —")
if hasattr(attack.algorithm, 'get_diffs_history'):
    print("✓ get_diffs_history exists")
else:
    print("✗ No get_diffs_history() method found")
    diffs_hist = None


max_info =results_obj.find_maximums()
numSubkeys = results_obj.numSubkeys

# Directory for saving graphs
output_dir = os.path.join(os.getcwd(), "graphs/Mangard")
os.makedirs(output_dir, exist_ok=True)

# If the .cfg says numTraces=1000, 5000, or 10000, set it here:

numTraces = 1000
# 2.5)Conditions for x-axis adjustment
n_batches = numTraces // update_interval
start_trace_subset = 0  #must match the value for tstart in accumulate_sumdens conditional within progressive class
end_trace_subset = 1000   #must match the value for tend in accumulate_sumdens conditional within progressive class
subTraces = end_trace_subset - start_trace_subset
subset_batches = subTraces // update_interval

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
        plt.title(f"Hypothesis variance: sumden1 (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel(f"Traces processed: [{start_trace_subset}, {end_trace_subset}]")
        plt.ylabel("sumden1")
        plt.grid(True)
        outpath = os.path.join(output_dir ,f"sumden1_best_bnum{bnum}_{subset_batches}batches.png")
        plt.savefig(outpath, dpi=300)
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
        plt.title(f"Trace variance: sumden2 (best guess={hyp:#02x}) vs. Traces (bnum={bnum})")
        plt.xlabel(f"Traces processed: [{start_trace_subset}, {end_trace_subset}]")
        plt.ylabel(f"sumden2 @ point {max_idx}")
        plt.grid(True)
        outpath = os.path.join(output_dir, f"sumden2_best_bnum{bnum}_{subset_batches}batches.png")
        plt.savefig(outpath, dpi=300)
        plt.close()
        

def plot_sumden2_best_and_true(sumden_pairs,
                               results_obj,
                               update_interval,
                               output_dir,
                               byte,
                               true_key=2):
    """
    For a single byte index:
      • finds the best-guess hypothesis from results_obj.find_maximums()
      • finds the tuple whose key_guess == true_key
      • extracts sumden2 for each of those two hypotheses
      • plots them overlaid
    """
 
    max_info   = results_obj.find_maximums()      # list over bytes
    best_guess = max_info[byte][0][0]              # best‐guess key for bnum
                              # your correct subkey
    by_pair = {}
    for sumden1, bnum, hyp, sumden2 in sumden_pairs:
        by_pair.setdefault((bnum, hyp), []).append(sumden2)


    
    best_hyps = { bnum: (max_info[bnum][0][0], max_info[bnum][0][1]) for bnum in range(results_obj.numSubkeys) }
    
    best_hyp, best_max_idx = best_hyps[byte]
    true_max_idx = next(
    loc for (hyp, loc, corr) in max_info[byte]
    if hyp == true_key
)


    # ─── collect the series for each hypothesis ────────────────────
    pairs_to_plot = [
    (best_hyp,  best_max_idx,f"Best guess (h=0x{best_hyp:02x})", "-", "tab:blue"),
    (true_key,  true_max_idx,f"True key   (h=0x{true_key:02x})","-", "tab:orange"),
    ]

    plt.figure(figsize=(8,5))

    for hyp, max_idx, label, style, color in pairs_to_plot:
        # grab only byte & the desired hyp
        vectors = by_pair.get((byte, hyp), [])
        
        # choose x based on how many batches we actually have
        if len(vectors) == n_batches:
            x = [(i+1)*update_interval for i in range(n_batches)]
        elif len(vectors) == subset_batches:
            x = [(i+1)*update_interval for i in range(subset_batches)]
        else:
            print(f"Warning: for hyp=0x{hyp:02x}, expected {n_batches} or {subset_batches} points, got {len(vectors)}")
            x = [(i+1)*update_interval for i in range(len(vectors))]

        # extract the single sample‐point per batch
        y = [ vec[max_idx] for vec in vectors ]
        plt.plot(x, y, style, label=label, color=color)

    # ─── finalize & save ───────────────────────────────────────────
    plt.xlabel("Traces processed")
    plt.ylabel("sumden2 at max_idx")
    plt.title(f"Byte {byte}: best vs true sumden2")
    plt.legend(loc="best")
    plt.grid(True)
    
    outfn = os.path.join(output_dir, f"sumden2_best_vs_true_b{byte}_{subset_batches}batches.png")
    plt.savefig(outfn, dpi=300)
    plt.close()
    print(f"→ Saved overlay plot at {outfn}")

def plot_sumden2_heatmap(sumden_pairs,
                          results_obj,
                          output_dir):
    """
    Generates and saves a heatmap of the final sumden2 vectors for all
    subkey bytes and their guesses, marking byte boundaries, max-correlation
    points, and coloring y-axis labels by correctness.

    Encryption key is fixed:
      bytes 0–7  : subkey == 1
      bytes 8–15 : subkey == 2

    Parameters
    ----------
    sumden_pairs : list of tuples
        Each entry is (sumden1, bnum, hyp, sumden2_array) from the final batch.
    results_obj : chipwhisperer.cwa.cpa.get_statistics()
        Used to get find_maximums() info: list  (bnums [0,15])--> each a list of correlations in decreasing order for eack subkey guess [0,255]--> each a 3-tuple (guess, location, correlation).
    output_dir : str
        Directory in which to save 'sumden2_heatmap.png'.
    """
    # 1) Organize sumden2 arrays by (byte, hypothesis)
    by_pair = {}
    for _s1, bnum, hyp, s2 in sumden_pairs:
        by_pair.setdefault((bnum, hyp), []).append(s2)

    # 2) Get max_info and compute dimensions
    max_info = results_obj.find_maximums()
    num_subkeys = len(max_info)       # expected 16
    guesses_per = len(max_info[0])    # expected 256
    total_rows = num_subkeys * guesses_per

    # 3) Sample-point length
    sample_len = next(iter(by_pair.values()))[-1].shape[0]

    # 4) Build heatmap array
    heatmap = np.zeros((total_rows, sample_len))
    row = 0
    for b in range(num_subkeys):
        for (guess, _, _) in max_info[b]:
            vecs = by_pair.get((b, guess), [])
            if not vecs:
                raise RuntimeError(f"Missing data for byte={b}, hyp={guess}")
            heatmap[row, :] = vecs[-1]
            row += 1

    # 5) Plot heatmap
    plt.figure(figsize=(12, 8))
    im = plt.imshow(
        heatmap,
        aspect='auto',
        origin='lower',
        extent=[0, sample_len, 0, total_rows],
        cmap='viridis'
    )
    plt.colorbar(im, label='sumden2')
    plt.xlabel('Trace sample point index')
    plt.ylabel('Subkey byte & guess')
    plt.title('Heatmap of final sumden2 across all subkeys and guesses')

    # 6) Draw byte boundaries
    for b in range(1, num_subkeys):
        y = b * guesses_per
        plt.hlines(y, 0, sample_len, colors='white', linestyles='--', linewidth=0.5)

    # 7) Mark max-correlation sample points per byte
    for b in range(num_subkeys):
        _, loc, _ = max_info[b][0]
        y0 = b * guesses_per
        y1 = y0 + guesses_per
        plt.vlines(loc, y0, y1, colors='red', linestyles='-', linewidth=1)

    # 8) Y-axis labels: one per byte at center, colored by guess correctness
    yticks = [(b + 0.5) * guesses_per for b in range(num_subkeys)]
    ylabels = []
    ground_truth = [1]*8 + [2]*8
    for b in range(num_subkeys):
        # determine if best guess equals ground truth
        best_guess = max_info[b][0][0]
        correct = (best_guess == ground_truth[b])
        ylabels.append(f'byte {b}')
    plt.yticks(yticks, ylabels)
    # color tick labels individually
    for tick, b in zip(plt.gca().get_yticklabels(), range(num_subkeys)):
        best_guess = max_info[b][0][0]
        correct = (best_guess == ground_truth[b])
        tick.set_color('black' if correct else 'red')

    # 9) Save figure
    outpath = os.path.join(output_dir, 'sumden2_heatmap.png')
    plt.savefig(outpath, dpi=300)
    plt.close()
    print(f"→ Saved heatmap at {outpath}")
    plt.close()
 


if __name__ == "__main__":

    output_dir = os.path.join(os.getcwd(), "graphs", "Mangard", project_name, f"{numTraces}_traces")
    os.makedirs(output_dir, exist_ok=True)
    
    if len(sumden_pairs) > 0:
 
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
                               
        plot_sumden2_best_and_true(sumden_pairs,
                                results_obj,
                                update_interval,
                                output_dir,
                                byte=12,
                                true_key=2)
                                
        plot_sumden2_heatmap(sumden_pairs,
                          results_obj,
                          output_dir)

        print("Done plotting sumden1 & sumden2.")
    else:
        print("No sumden_pairs data available for custom sumden1/sumden2 plotting.\n")

   
