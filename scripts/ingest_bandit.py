"""
ingest_bandit.py  — Day 5 Student B (fixed)
---------------------------------------------
Parses Bandit JSON output and inserts findings into static_results.

Fixes vs original:
  - Absolute DB_PATH derived from __file__ (was '../corpus.db')
  - Resolves real program_id from filtered_files instead of hardcoded 1
  - Applies bandit_cwe_corrections.json (full 73-rule table)
  - Dedup key (file_path, line_number, rule_id, cwe): increments tool_count
    rather than inserting a duplicate if the same triplet already exists

Usage:
  # Ingest a single Bandit JSON file
  python scripts/ingest_bandit.py --input results/static_raw/bandit_prog_000001.json

  # Batch-ingest all bandit_*.json in results/static_raw/
  python scripts/ingest_bandit.py --batch
"""

import json
import os
import sqlite3
import glob
import argparse
import re

BASE_DIR         = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH          = os.path.join(BASE_DIR, 'corpus.db')
STATIC_DIR       = os.path.join(BASE_DIR, 'results', 'static_raw')
CORRECTIONS_FILE = os.path.join(BASE_DIR, 'scripts', 'bandit_cwe_corrections.json')

# ---------------------------------------------------------------------------
# Load CWE corrections
# ---------------------------------------------------------------------------

def load_corrections() -> dict:
    """Return {rule_id: correct_cwe} for all entries where corrected=True,
    plus the verified CWE for all other entries."""
    if not os.path.exists(CORRECTIONS_FILE):
        print(f"  [WARN] corrections file not found: {CORRECTIONS_FILE}")
        return {}
    with open(CORRECTIONS_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)

    mapping = {}
    for rule_id, data in raw.items():
        if rule_id == "_note":
            continue
        mapping[rule_id] = data.get("correct_cwe", "UNCATEGORIZED")
    return mapping


def resolve_program_id(cursor, file_path: str, fallback_path: str = None):
    """Look up program_id in filtered_files by regex prog_XXXXXX, then exact path, then basename."""
    for p in [file_path, fallback_path]:
        if not p:
            continue
        m = re.search(r'prog_\d+', p)
        if m:
            row = cursor.execute(
                "SELECT program_id FROM filtered_files WHERE program_id = ? AND stage1 = 'PASSED' LIMIT 1",
                (m.group(0),)
            ).fetchone()
            if row:
                return row[0]

    row = cursor.execute(
        "SELECT program_id FROM filtered_files WHERE file_path = ? AND stage1 = 'PASSED' LIMIT 1",
        (file_path,)
    ).fetchone()
    if row:
        return row[0]

    basename = os.path.basename(file_path)
    row = cursor.execute(
        "SELECT program_id FROM filtered_files "
        "WHERE file_path LIKE ? AND stage1 = 'PASSED' LIMIT 1",
        (f"%{basename}",)
    ).fetchone()
    return row[0] if row else None


def ensure_tool_count_column(cursor):
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(static_results)").fetchall()]
    if "tool_count" not in cols:
        cursor.execute("ALTER TABLE static_results ADD COLUMN tool_count INTEGER DEFAULT 1")
        print("  [INFO] Added tool_count column to static_results.")


def ingest_bandit_file(json_path: str, cursor, corrections: dict) -> tuple[int, int, int]:
    """Ingest one Bandit JSON file. Returns (inserted, skipped, corrected_count)."""
    if not os.path.exists(json_path):
        print(f"  [SKIP] Not found: {json_path}")
        return 0, 0, 0

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    inserted  = 0
    skipped   = 0
    corrected = 0

    for result in data.get("results", []):
        rule_id   = result.get("test_id", "UNKNOWN")
        file_path = result.get("filename", "unknown")
        line_num  = result.get("line_number", 0)
        severity  = result.get("issue_severity", "MEDIUM").upper()

        # Apply CWE correction
        cwe = corrections.get(rule_id, "UNCATEGORIZED")
        cwe_corrected = 1 if rule_id in corrections else 0
        if cwe_corrected:
            corrected += 1

        program_id = resolve_program_id(cursor, file_path, fallback_path=json_path)
        if not program_id:
            skipped += 1
            continue

        # Dedup check
        existing = cursor.execute("""
            SELECT id, tool_count FROM static_results
            WHERE program_id = ? AND file_path = ?
              AND line_number = ? AND rule_id = ? AND cwe = ?
            LIMIT 1
        """, (program_id, file_path, line_num, rule_id, cwe)).fetchone()

        if existing:
            cursor.execute(
                "UPDATE static_results SET tool_count = tool_count + 1 WHERE id = ?",
                (existing[0],)
            )
        else:
            cursor.execute("""
                INSERT INTO static_results
                    (program_id, file_path, line_number, rule_id,
                     cwe, severity, tool, cwe_corrected, tool_count)
                VALUES (?, ?, ?, ?, ?, ?, 'Bandit', ?, 1)
            """, (program_id, file_path, line_num, rule_id, cwe, severity, cwe_corrected))
            inserted += 1

    return inserted, skipped, corrected


def run(input_path: str = None, batch: bool = False):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    ensure_tool_count_column(c)
    corrections = load_corrections()
    print(f"Loaded {len(corrections)} CWE correction mappings from bandit_cwe_corrections.json")

    if batch:
        paths = sorted(glob.glob(os.path.join(STATIC_DIR, "bandit_*.json")))
        if not paths:
            print(f"No bandit_*.json files found in {STATIC_DIR}")
            conn.close()
            return
    elif input_path:
        paths = [input_path]
    else:
        # Default test file
        default = os.path.join(BASE_DIR, "results", "test_bandit.json")
        paths   = [default]

    total_ins = total_skp = total_corr = 0
    for p in paths:
        print(f"Ingesting: {os.path.basename(p)} ...", end=" ")
        ins, skp, corr = ingest_bandit_file(p, c, corrections)
        conn.commit()
        print(f"{ins} inserted, {skp} unmatched, {corr} CWE corrections applied")
        total_ins  += ins
        total_skp  += skp
        total_corr += corr

    print(f"\nTotal inserted        : {total_ins}")
    print(f"Total unmatched       : {total_skp}")
    print(f"Total CWE corrections : {total_corr}")
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest Bandit JSON findings into static_results")
    parser.add_argument("--input", type=str, default=None, help="Path to Bandit JSON file")
    parser.add_argument("--batch", action="store_true",
                        help="Ingest all bandit_*.json files in results/static_raw/")
    args = parser.parse_args()
    run(input_path=args.input, batch=args.batch)
