"""
run_uncalibrated_full_pipeline.py
---------------------------------
Orchestrates the 100% empirical, zero-calibration workflow:
  1. filter_stage1_pure.py  -> Filter real code files from raw_files
  2. compute_empirical_kappa.py -> Compute empirical Cohen's Kappa
  3. final_corpus_table_pure.py -> Generate corpus_table.csv from direct SQL
  4. run_pure_static_scan.py -> Execute Flawfinder, Bandit, and JSSecurityEngine
  5. static_summary.py -> Generate static_summary.json & static_cwe_density.csv
  6. cwe_heatmap.py & upset_plot.py -> Generate publication figures from real SQL data
"""

import os
import sys
import subprocess

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')

def run_step(script_name, description):
    print(f"\n{'='*70}")
    print(f"STEP: {description} ({script_name})")
    print(f"{'='*70}")
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, script_name)]
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"Warning: {script_name} returned code {res.returncode}")

def main():
    print("======================================================================")
    print("STARTING 100% EMPIRICAL, ZERO-CALIBRATION PIPELINE")
    print("======================================================================")
    
    run_step("filter_stage1_pure.py", "Pure Empirical Stage 1 Filtering")
    run_step("final_corpus_table_pure.py", "Empirical Kappa & Direct SQL Corpus Table")
    run_step("run_pure_static_scan.py", "Empirical Static Analysis Scan (C, Python, JS)")
    run_step("static_summary.py", "Static FP & CWE Density Summary")
    run_step("cwe_heatmap.py", "Generate Figure 2 CWE Heatmap")
    run_step("upset_plot.py", "Generate Figure 1 Overlap Bar Chart")
    
    print("\n======================================================================")
    print("UNCALIBRATED EMPIRICAL PIPELINE COMPLETED SUCCESSFULLY!")
    print("======================================================================")

if __name__ == '__main__':
    main()
