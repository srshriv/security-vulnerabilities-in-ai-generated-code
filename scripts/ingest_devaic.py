"""
ingest_devaic.py  — Day 5 (fixed)
-----------------------------------
Parses DeVAIC CSV output and inserts findings into static_results.

Fixes vs original:
  - Absolute DB_PATH derived from __file__
  - Resolves real program_id from filtered_files
  - Dedup key (file_path, line_number, rule_id, cwe): increments tool_count
  - Batch mode for processing all devaic_*.csv files

Usage:
  python scripts/ingest_devaic.py --input results/static_raw/devaic_prog_000001.csv
  python scripts/ingest_devaic.py --batch
"""

import csv
import os
import sqlite3
import glob
import argparse

BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH    = os.path.join(BASE_DIR, 'corpus.db')
STATIC_DIR = os.path.join(BASE_DIR, 'results', 'static_raw')

# DeVAIC rule → CWE mapping (based on DeVAIC rule table, 2024)
DEVAIC_CWE_MAP = {
    "buffer_overflow":          "CWE-120",
    "stack_buffer_overflow":    "CWE-121",
    "heap_buffer_overflow":     "CWE-122",
    "oob_read":                 "CWE-125",
    "oob_write":                "CWE-787",
    "integer_overflow":         "CWE-190",
    "integer_underflow":        "CWE-191",
    "null_dereference":         "CWE-476",
    "divide_by_zero":           "CWE-369",
    "use_after_free":           "CWE-416",
    "memory_leak":              "CWE-401",
    "double_free":              "CWE-415",
    "format_string":            "CWE-134",
    "command_injection":        "CWE-78",
    "sql_injection":            "CWE-89",
    "path_traversal":           "CWE-22",
    "hardcoded_credentials":    "CWE-798",
    "weak_crypto":              "CWE-327",
}


def rule_to_cwe(rule_id: str) -> str:
    return DEVAIC_CWE_MAP.get(rule_id.lower().replace("-", "_"), "UNCATEGORIZED")


def resolve_program_id(cursor, file_path: str):
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


def ingest_devaic_file(csv_path: str, cursor) -> tuple[int, int]:
    if not os.path.exists(csv_path):
        print(f"  [SKIP] Not found: {csv_path}")
        return 0, 0

    inserted = 0
    skipped  = 0

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            file_path = row.get("file", row.get("filename", "unknown"))
            line_num  = int(row.get("line", row.get("line_number", 0)) or 0)
            rule_id   = row.get("rule", row.get("rule_id", "UNKNOWN"))
            severity  = row.get("severity", "MEDIUM").upper()
            cwe       = row.get("cwe") or rule_to_cwe(rule_id)

            program_id = resolve_program_id(cursor, file_path)
            if not program_id:
                skipped += 1
                continue

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
                         cwe, severity, tool, tool_count)
                    VALUES (?, ?, ?, ?, ?, ?, 'DeVAIC', 1)
                """, (program_id, file_path, line_num, rule_id, cwe, severity))
                inserted += 1

    return inserted, skipped


def run(input_path: str = None, batch: bool = False):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    ensure_tool_count_column(c)

    if batch:
        paths = sorted(glob.glob(os.path.join(STATIC_DIR, "devaic_*.csv")))
        if not paths:
            print(f"No devaic_*.csv files found in {STATIC_DIR}")
            conn.close()
            return
    elif input_path:
        paths = [input_path]
    else:
        default = os.path.join(BASE_DIR, "results", "test_devaic.csv")
        paths   = [default]

    total_ins = total_skp = 0
    for p in paths:
        print(f"Ingesting: {os.path.basename(p)} ...", end=" ")
        ins, skp = ingest_devaic_file(p, c)
        conn.commit()
        print(f"{ins} inserted, {skp} unmatched")
        total_ins += ins
        total_skp += skp

    print(f"\nTotal inserted : {total_ins}")
    print(f"Total unmatched: {total_skp}")
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest DeVAIC CSV findings into static_results")
    parser.add_argument("--input", type=str, default=None)
    parser.add_argument("--batch", action="store_true")
    args = parser.parse_args()
    run(input_path=args.input, batch=args.batch)
