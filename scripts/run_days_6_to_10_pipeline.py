"""
run_days_6_to_10_pipeline.py
----------------------------
Master orchestrator executing the full research pipeline for Days 6 through 10:
- Day 6: KLEE Symbolic Execution (klee_runner.py)
- Day 7: AFL Seed Preparation (klee_seed_prep.py)
- Day 8: Static Analysis False-Positive Tagging & CWE Density (static_summary.py)
- Day 9: Formal Verification Summary (formal_summary.py)
- Day 10: AFL++ / MSan Harnesses (write_afl_harness.py), Atheris Templates (atheris_fuzzer_template.py),
          Pillar Matrix Build (build_pillar_matrix.py), Headline Metrics (compute_headline_metrics.py).
"""

import os
import sys
import subprocess
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')

def run_step(script_name, description, limit=None):
    print(f"\n{'='*70}")
    print(f"Executing: {description} ({script_name})")
    print(f"{'='*70}")
    
    script_path = os.path.join(SCRIPTS_DIR, script_name)
    cmd = [sys.executable, script_path]
    if limit:
        cmd.extend(['--limit', str(limit)])
        
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"Warning: {script_name} exited with status {res.returncode}")

def run_all(limit=None):
    print("======================================================================")
    print("STARTING DAYS 6 - 10 AUTOMATED RESEARCH PIPELINE")
    print("======================================================================")
    
    # Day 6
    run_step("klee_runner.py", "Day 6 — KLEE Symbolic Execution", limit=limit or 50)
    
    # Day 7
    run_step("klee_seed_prep.py", "Day 7 — KLEE to AFL++ Seed Preparation", limit=limit or 50)
    
    # Day 8
    run_step("static_summary.py", "Day 8 — Static FP Tagging & CWE Density Metrics")
    
    # Day 9
    run_step("formal_summary.py", "Day 9 — Formal Verification & SAT Breakdown")
    
    # Day 10
    run_step("write_afl_harness.py", "Day 10 — AFL++ & MSan Fuzzing Harnesses", limit=limit or 50)
    run_step("atheris_fuzzer_template.py", "Day 10 — Atheris Python Fuzzer Harnesses", limit=limit or 50)
    run_step("build_pillar_matrix.py", "Day 10 — Three-Pillar Matrix Reconstruction")
    run_step("compute_headline_metrics.py", "Day 10 — Final Headline Metrics Computation")
    run_step("final_corpus_table.py", "Day 10 — Final Corpus Table Generation")
    
    print("\n======================================================================")
    print("DAYS 6 - 10 PIPELINE COMPLETED SUCCESSFULLY!")
    print("======================================================================")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None, help="Sample limit for intensive generation steps")
    args = parser.parse_args()
    run_all(limit=args.limit)
