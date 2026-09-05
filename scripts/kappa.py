import sqlite3
import sys
from collections import defaultdict

def compute_kappa(rater_a_decisions, rater_b_decisions):
    """
    Given two dicts of {file_id: decision}, compute Cohen's Kappa.
    Only files rated by BOTH raters are included.
    """
    # Find files rated by both
    common_files = set(rater_a_decisions.keys()) & set(rater_b_decisions.keys())

    if len(common_files) < 2:
        return None, 0, "Not enough files rated by both raters"

    categories = ['Y', 'N', 'U']
    n = len(common_files)

    # Build confusion matrix
    matrix = defaultdict(int)
    for fid in common_files:
        a = rater_a_decisions[fid]
        b = rater_b_decisions[fid]
        matrix[(a, b)] += 1

    # Observed agreement (Po)
    observed_agreement = sum(matrix[(cat, cat)] for cat in categories) / n

    # Expected agreement (Pe)
    expected_agreement = 0
    for cat in categories:
        count_a = sum(matrix[(cat, b)] for b in categories)
        count_b = sum(matrix[(a, cat)] for a in categories)
        expected_agreement += (count_a / n) * (count_b / n)

    # Kappa
    if expected_agreement == 1.0:
        kappa = 1.0
    else:
        kappa = (observed_agreement - expected_agreement) / (1 - expected_agreement)

    return kappa, n, "OK"

def get_decisions(conn, rater_id):
    """Returns {file_id: decision} for a given rater."""
    rows = conn.execute(
        'SELECT file_id, decision FROM rater_decisions WHERE rater_id = ?',
        (rater_id,)
    ).fetchall()
    return {row[0]: row[1] for row in rows}

import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

def run_kappa():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    decisions_a = get_decisions(conn, 'rater_A')
    decisions_b = get_decisions(conn, 'rater_B')

    print("=" * 60)
    print("COHEN'S KAPPA REPORT")
    print("=" * 60)
    print(f"rater_A rated : {len(decisions_a)} files")
    print(f"rater_B rated : {len(decisions_b)} files")

    common = set(decisions_a.keys()) & set(decisions_b.keys())
    print(f"Both rated    : {len(common)} files")

    if len(common) == 0:
        print("\nNo files have been rated by both raters yet.")
        print("Student A needs to rate files before Kappa can be computed.")
        conn.close()
        return

    # Overall Kappa
    kappa, n, status = compute_kappa(decisions_a, decisions_b)

    if kappa is None:
        print(f"\nCannot compute Kappa: {status}")
        conn.close()
        return

    print(f"\n--- OVERALL KAPPA ---")
    print(f"Kappa : {kappa:.4f}  (n={n})")

    if kappa >= 0.80:
        print(f"Result: PASS (>= 0.80 threshold)")
    elif kappa >= 0.60:
        print(f"Result: WARNING (0.60-0.79, below threshold)")
        print(f"Action: Review disagreements and re-rate before proceeding")
    else:
        print(f"Result: FAIL (< 0.60)")
        print(f"Action: Calibration required - see disagreements below")

    # Per AI tool breakdown
    print(f"\n--- PER AI TOOL BREAKDOWN ---")
    tools = c.execute(
        'SELECT DISTINCT ai_tool FROM raw_files'
    ).fetchall()

    for (tool,) in tools:
        tool_files = c.execute(
            'SELECT id FROM raw_files WHERE ai_tool = ?', (tool,)
        ).fetchall()
        tool_ids = {row[0] for row in tool_files}

        a_tool = {k: v for k, v in decisions_a.items() if k in tool_ids}
        b_tool = {k: v for k, v in decisions_b.items() if k in tool_ids}

        k, n_tool, status = compute_kappa(a_tool, b_tool)
        if k is not None:
            flag = "OK" if k >= 0.80 else "BELOW THRESHOLD"
            print(f"  {tool:<12} : kappa={k:.4f}  n={n_tool}  [{flag}]")
        else:
            print(f"  {tool:<12} : {status}")

    # Show disagreements
    print(f"\n--- DISAGREEMENTS ---")
    disagreements = [
        fid for fid in common
        if decisions_a[fid] != decisions_b[fid]
    ]
    print(f"Total disagreements: {len(disagreements)} of {len(common)} files")

    if disagreements:
        print("\nFiles where raters disagree:")
        for fid in disagreements[:20]:  # Show first 20
            row = c.execute(
                'SELECT repo_name, file_path, ai_tool FROM raw_files WHERE id = ?',
                (fid,)
            ).fetchone()
            if row:
                print(f"  ID={fid} | {row[2]:<10} | {row[0]}/{row[1]}")
                print(f"    rater_A={decisions_a[fid]}  rater_B={decisions_b[fid]}")
        if len(disagreements) > 20:
            print(f"  ... and {len(disagreements) - 20} more")

    # Assert threshold
    print(f"\n--- THRESHOLD CHECK ---")
    try:
        assert kappa >= 0.80, \
            f"Kappa {kappa:.4f} is below the required 0.80 threshold. Calibration needed."
        print(f"PASSED: Kappa {kappa:.4f} >= 0.80")
    except AssertionError as e:
        print(f"FAILED: {e}")

    conn.close()

if __name__ == '__main__':
    run_kappa()
