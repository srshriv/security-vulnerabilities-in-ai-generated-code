"""
apply_stage2.py  — Day 4 Student B
------------------------------------
Reads all RATER_DECIDED rows from rater_decisions and propagates the
aggregate decision into filtered_files.stage2.

Decision logic (majority between rater_A and rater_B):
  - Both Y → stage2 = 'PASSED'
  - Both N → stage2 = 'RATER_REJECTED'
  - Both U → stage2 = 'UNCERTAIN'
  - Mixed  → stage2 = 'DISPUTED'  (requires manual review)
  - Only one rater has rated → stage2 = 'PENDING'

Run AFTER both raters have finished their batches:
  python scripts/apply_stage2.py

Then verify:
  python scripts/stratification_check.py
"""

import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

RATERS = ('rater_A', 'rater_B')


def majority_decision(decisions: list) -> str:
    """Collapse a list of individual rater decisions into a stage2 value."""
    if not decisions:
        return 'PENDING'

    # Remove skips
    actual = [d for d in decisions if d not in ('S', None)]

    if not actual:
        return 'PENDING'

    if len(actual) == 1:
        d = actual[0]
        return {
            'Y': 'PASSED',
            'N': 'RATER_REJECTED',
            'U': 'UNCERTAIN',
        }.get(d, 'PENDING')

    # Majority: check agreement
    yes  = actual.count('Y')
    no   = actual.count('N')
    unc  = actual.count('U')

    if yes > no and yes > unc:
        return 'PASSED'
    if no > yes and no > unc:
        return 'RATER_REJECTED'
    if unc > yes and unc > no:
        return 'UNCERTAIN'

    return 'DISPUTED'


def run():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # Ensure stage2 column exists (schema may have been applied before this column was defined)
    cols = [row[1] for row in c.execute("PRAGMA table_info(filtered_files)").fetchall()]
    if 'stage2' not in cols:
        c.execute("ALTER TABLE filtered_files ADD COLUMN stage2 TEXT")
        print("  [INFO] Added stage2 column to filtered_files.")

    # Get all file_ids that appear in rater_decisions
    rated_ids = c.execute(
        "SELECT DISTINCT file_id FROM rater_decisions"
    ).fetchall()
    rated_ids = [r[0] for r in rated_ids]

    if not rated_ids:
        print("No rater decisions found. Run rater_tool.py first.")
        conn.close()
        return

    print(f"Propagating stage2 decisions for {len(rated_ids)} rated files...")

    updated  = 0
    disputed = 0
    pending  = 0

    for file_id in rated_ids:
        # raw_file_id in filtered_files corresponds to file_id in rater_decisions
        rows = c.execute(
            "SELECT rater_id, decision FROM rater_decisions WHERE file_id = ? ORDER BY timestamp DESC",
            (file_id,)
        ).fetchall()

        decisions = [r[1] for r in rows]
        stage2    = majority_decision(decisions)

        if stage2 == 'DISPUTED':
            disputed += 1
        elif stage2 == 'PENDING':
            pending += 1

        c.execute(
            "UPDATE filtered_files SET stage2 = ? WHERE raw_file_id = ?",
            (stage2, file_id)
        )
        updated += 1

    conn.commit()

    print(f"\nStage 2 applied:")
    print(f"  Updated   : {updated}")
    print(f"  Disputed  : {disputed}  (need manual resolution)")
    print(f"  Pending   : {pending}   (only 1 rater has rated)")

    print("\nStage 2 breakdown:")
    for row in c.execute(
        "SELECT stage2, COUNT(*) FROM filtered_files GROUP BY stage2 ORDER BY COUNT(*) DESC"
    ).fetchall():
        print(f"  {row[0]:20} : {row[1]}")

    # Show how many are ready for final_corpus view
    ready = c.execute("""
        SELECT COUNT(*) FROM filtered_files
        WHERE stage1 = 'PASSED'
          AND stage2 = 'PASSED'
          AND compile_status IN ('COMPILED', 'REPAIR_COMPILED', 'SYNTAX_OK')
    """).fetchone()[0]
    print(f"\nFiles eligible for final_corpus view: {ready}")

    conn.close()


if __name__ == '__main__':
    run()
