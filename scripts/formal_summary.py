"""
formal_summary.py  — Student A (Day 9)
--------------------------------------
Aggregates and reports all formal verification (CBMC + KLEE) findings:
1. CBMC SAT, UNSAT, and Inconclusive rates.
2. Violated property distribution (array bounds, signed overflow, pointer checks, div-by-zero).
3. KLEE symbolic execution metrics (paths explored, test cases generated, direct crashes).
4. ASAN harness generation status.
5. Saves results to results/formal_summary.json.
"""

import os
import sys
import sqlite3
import json
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def compute_formal_summary():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    total_formal = cursor.execute("SELECT COUNT(*) FROM formal_results").fetchone()[0]
    print(f"=== Formal Verification Summary (Total: {total_formal}) ===")
    
    # CBMC Verdict Breakdown
    cbmc_counts = dict(cursor.execute("""
        SELECT cbmc_result, COUNT(*) FROM formal_results
        GROUP BY cbmc_result ORDER BY COUNT(*) DESC
    """).fetchall())
    print("\n1. CBMC Verdict Breakdown:")
    for v, c in cbmc_counts.items():
        pct = (c / max(total_formal, 1)) * 100
        print(f"  {v:<15}: {c:>5} ({pct:.1f}%)")
        
    # Violated Properties
    prop_counts = dict(cursor.execute("""
        SELECT property_type, COUNT(*) FROM formal_results
        WHERE property_type IS NOT NULL AND property_type != ''
        GROUP BY property_type ORDER BY COUNT(*) DESC LIMIT 10
    """).fetchall())
    print("\n2. Violated Formal Properties:")
    for p, c in prop_counts.items():
        print(f"  {p:<30}: {c}")
        
    # KLEE Metrics
    klee_stats = cursor.execute("""
        SELECT 
            SUM(COALESCE(klee_paths_explored, 0)),
            SUM(COALESCE(klee_test_cases, 0)),
            SUM(COALESCE(klee_direct_crash, 0)),
            SUM(COALESCE(klee_seeding, 0))
        FROM formal_results
    """).fetchone()
    
    klee_summary = {
        "total_paths_explored": klee_stats[0] or 0,
        "total_ktest_cases": klee_stats[1] or 0,
        "total_direct_crashes": klee_stats[2] or 0,
        "seeded_programs": klee_stats[3] or 0
    }
    print("\n3. KLEE Symbolic Execution Metrics:")
    print(f"  Paths Explored   : {klee_summary['total_paths_explored']}")
    print(f"  Test Cases (.ktest): {klee_summary['total_ktest_cases']}")
    print(f"  Direct Crashes   : {klee_summary['total_direct_crashes']}")
    print(f"  Seeded Programs  : {klee_summary['seeded_programs']}")
    
    # ASAN Harness count
    harnesses_generated = cursor.execute("""
        SELECT COUNT(*) FROM formal_results WHERE cbmc_result = 'SAT'
    """).fetchone()[0]
    
    summary = {
        "total_programs_analyzed": total_formal,
        "cbmc_verdicts": cbmc_counts,
        "violated_properties": prop_counts,
        "klee_symbolic_execution": klee_summary,
        "sat_counterexamples_count": cbmc_counts.get("SAT", 0),
        "asan_harnesses_ready": harnesses_generated
    }
    
    json_path = os.path.join(RESULTS_DIR, 'formal_summary.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=4)
        
    conn.close()
    print(f"\nFormal summary saved to: {json_path}")

if __name__ == "__main__":
    compute_formal_summary()
