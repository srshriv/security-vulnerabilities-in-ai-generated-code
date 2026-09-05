"""
klee_seed_prep.py  — Student A (Day 7)
--------------------------------------
Converts KLEE generated .ktest test cases into initial seed corpuses for AFL++ fuzzing.
For each program in formal_results with klee_seeding=1:
- Extracts concrete input bytes from KLEE test cases (ktest-tool) or builds deterministic seeds.
- Populates results/afl_in/<program_id>/seed_0.bin, seed_1.bin, etc.
"""

import os
import sys
import sqlite3
import glob
import subprocess
import shutil
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
KLEE_DIR = os.path.join(BASE_DIR, 'results', 'klee_out')
AFL_IN_DIR = os.path.join(BASE_DIR, 'results', 'afl_in')
os.makedirs(AFL_IN_DIR, exist_ok=True)

def prep_seeds_for_program(program_id: str) -> int:
    prog_afl_in = os.path.join(AFL_IN_DIR, program_id)
    os.makedirs(prog_afl_in, exist_ok=True)
    
    klee_run_dir = os.path.join(KLEE_DIR, program_id, "klee_run")
    ktests = glob.glob(os.path.join(klee_run_dir, "*.ktest")) if os.path.exists(klee_run_dir) else []
    
    has_ktest_tool = shutil.which("ktest-tool") is not None
    seeds_created = 0
    
    if ktests and has_ktest_tool:
        for idx, kt in enumerate(ktests):
            out_bin = os.path.join(prog_afl_in, f"seed_klee_{idx}.bin")
            res = subprocess.run(["ktest-tool", "--extract", kt], capture_output=True)
            if res.stdout:
                with open(out_bin, "wb") as f:
                    f.write(res.stdout)
                seeds_created += 1
                
    if seeds_created == 0:
        # Create standard boundary test seeds (null, 0xFF, overflow buffer, standard ASCII)
        seed_patterns = [
            b"A" * 64,
            b"A" * 256,
            b"\x00" * 32,
            b"\xff" * 32,
            b"-1\n0\n100000\n",
            b"%s%s%s%s%n",
            b"admin=1&user=test\n"
        ]
        for idx, pat in enumerate(seed_patterns):
            out_bin = os.path.join(prog_afl_in, f"seed_synth_{idx}.bin")
            with open(out_bin, "wb") as f:
                f.write(pat)
            seeds_created += 1
            
    return seeds_created

def run(limit: int = None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    query = """
        SELECT program_id
        FROM formal_results
        WHERE klee_seeding = 1 OR cbmc_result IN ('SAT', 'INCONCLUSIVE')
    """
    if limit:
        query += f" LIMIT {limit}"
        
    cursor.execute(query)
    rows = cursor.fetchall()
    print(f"Preparing AFL++ seed corpuses for {len(rows)} programs...")
    
    total_seeds = 0
    for idx, (pid,) in enumerate(rows, 1):
        num_seeds = prep_seeds_for_program(pid)
        total_seeds += num_seeds
        if idx % 20 == 0 or idx == len(rows):
            print(f"  Seed prep: {idx}/{len(rows)} programs processed ({total_seeds} seeds total)")
            
    conn.close()
    print(f"\nAFL++ seed preparation complete! Generated {total_seeds} seeds in {AFL_IN_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert KLEE test cases to AFL++ seed corpuses")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of programs to process")
    args = parser.parse_args()
    run(limit=args.limit)
