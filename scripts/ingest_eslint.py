"""
ingest_eslint.py  — Student B, Day 5
--------------------------------------
Parses ESLint JSON output and inserts findings into static_results.

ESLint must be invoked with:
    eslint --format json --output-file results/static_raw/eslint_<program_id>.json <file.js>

Or for batch runs:
    eslint --format json <dir>/*.js > results/static_raw/eslint_batch.json

Dedup key (file_path, line_number, rule_id, cwe):
  If two tools flag the same triplet, increment tool_count rather than
  inserting a duplicate row (matches ingest_sarif.py strategy).

CWE mapping for common ESLint security rules is built-in.
"""

import json
import os
import re
import sqlite3
import sys
import glob
import argparse
from datetime import datetime

BASE_DIR    = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH     = os.path.join(BASE_DIR, 'corpus.db')
STATIC_DIR  = os.path.join(BASE_DIR, 'results', 'static_raw')

# ---------------------------------------------------------------------------
# ESLint rule → CWE mapping
# Common security-relevant ESLint rules + popular security plugins
# ---------------------------------------------------------------------------
ESLINT_CWE_MAP = {
    # no-eval family
    "no-eval":                         "CWE-95",
    "no-implied-eval":                 "CWE-95",
    "security/detect-eval-with-expression": "CWE-95",
    # injection
    "security/detect-child-process":   "CWE-78",
    "security/detect-non-literal-regexp": "CWE-625",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-non-literal-require": "CWE-22",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-338",
    "security/detect-unsafe-regex":    "CWE-400",
    "security/detect-new-buffer":      "CWE-119",
    "security/detect-buffer-noassert": "CWE-119",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-object-injection": "CWE-73",
    # prototype pollution
    "no-prototype-builtins":           "CWE-1321",
    # path traversal
    "security/detect-non-literal-fs-filename": "CWE-22",
    # sql
    "security/detect-sql-literal-injection": "CWE-89",
    # xss
    "no-unsanitized/property":         "CWE-79",
    "no-unsanitized/method":           "CWE-79",
    # misc
    "no-new-func":                     "CWE-95",
    "no-script-url":                   "CWE-95",
}

def rule_to_cwe(rule_id: str) -> str:
    """Return a CWE string for a given ESLint rule ID."""
    return ESLINT_CWE_MAP.get(rule_id, "UNCATEGORIZED")

def severity_from_int(sev: int) -> str:
    """ESLint severity: 0=off, 1=warn, 2=error → HIGH/MEDIUM/LOW"""
    return {2: "HIGH", 1: "MEDIUM", 0: "LOW"}.get(sev, "MEDIUM")


def resolve_program_id(cursor, file_path: str, fallback_path: str = None) -> str | None:
    """Look up the program_id from filtered_files by regex prog_XXXXXX, then exact path, then basename."""
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

    # Also try matching on the basename alone (ESLint paths may be absolute)
    basename = os.path.basename(file_path)
    row = cursor.execute(
        "SELECT program_id FROM filtered_files "
        "WHERE file_path LIKE ? AND stage1 = 'PASSED' LIMIT 1",
        (f"%{basename}",)
    ).fetchone()
    return row[0] if row else None


def ingest_eslint_file(eslint_json_path: str, cursor, tool_name: str = "eslint") -> tuple[int, int]:
    """Ingest a single ESLint JSON output file.

    Returns (inserted, skipped_unmatched) counts.
    """
    if not os.path.exists(eslint_json_path):
        print(f"  [SKIP] File not found: {eslint_json_path}")
        return 0, 0

    with open(eslint_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    inserted = 0
    skipped  = 0

    # ESLint --format json produces a list of file result objects
    for file_result in data:
        source_path = file_result.get("filePath", "")
        messages    = file_result.get("messages", [])

        program_id = resolve_program_id(cursor, source_path, fallback_path=eslint_json_path)
        if not program_id:
            skipped += 1
            continue

        for msg in messages:
            rule_id  = msg.get("ruleId") or "UNKNOWN"
            line_num = msg.get("line", 0)
            severity = severity_from_int(msg.get("severity", 1))
            cwe      = rule_to_cwe(rule_id)

            # Check for existing row with same dedup key
            existing = cursor.execute("""
                SELECT id, tool_count FROM static_results
                WHERE program_id = ? AND file_path = ?
                  AND line_number = ? AND rule_id = ? AND cwe = ?
                LIMIT 1
            """, (program_id, source_path, line_num, rule_id, cwe)).fetchone()

            if existing:
                # Increment tool_count instead of inserting duplicate
                cursor.execute(
                    "UPDATE static_results SET tool_count = tool_count + 1 WHERE id = ?",
                    (existing[0],)
                )
            else:
                cursor.execute("""
                    INSERT INTO static_results
                        (program_id, file_path, line_number, rule_id, cwe,
                         severity, tool, tool_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                """, (program_id, source_path, line_num, rule_id, cwe, severity, tool_name))
                inserted += 1

    return inserted, skipped


def run(input_path: str = None, tool_name: str = "eslint"):
    """Entry point: ingest one file or all eslint_*.json in STATIC_DIR."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # Ensure tool_count column exists (added in newer schema versions)
    cols = [row[1] for row in c.execute("PRAGMA table_info(static_results)").fetchall()]
    if "tool_count" not in cols:
        c.execute("ALTER TABLE static_results ADD COLUMN tool_count INTEGER DEFAULT 1")
        print("  [INFO] Added tool_count column to static_results.")

    if input_path:
        paths = [input_path]
    else:
        paths = sorted(glob.glob(os.path.join(STATIC_DIR, "eslint_*.json")))
        if not paths:
            # Also try a single batch file
            batch = os.path.join(STATIC_DIR, "eslint_batch.json")
            if os.path.exists(batch):
                paths = [batch]

    if not paths:
        print(f"No ESLint JSON files found in {STATIC_DIR}")
        print("Expected pattern: eslint_<program_id>.json  or  eslint_batch.json")
        conn.close()
        return

    total_inserted = 0
    total_skipped  = 0

    for p in paths:
        print(f"Ingesting: {os.path.basename(p)} ...", end=" ")
        ins, skp = ingest_eslint_file(p, c, tool_name=tool_name)
        conn.commit()
        print(f"{ins} inserted, {skp} unmatched files")
        total_inserted += ins
        total_skipped  += skp

    print(f"\nTotal inserted : {total_inserted}")
    print(f"Total unmatched: {total_skipped}")

    # Summary from DB
    count = c.execute(
        "SELECT COUNT(*) FROM static_results WHERE tool = ?", (tool_name,)
    ).fetchone()[0]
    print(f"ESLint rows in static_results: {count}")
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Ingest ESLint JSON findings into static_results"
    )
    parser.add_argument("--input", type=str, default=None,
                        help="Path to ESLint JSON file (default: scan results/static_raw/eslint_*.json)")
    parser.add_argument("--tool", type=str, default="eslint",
                        help="Tool name to record in static_results (default: eslint)")
    args = parser.parse_args()
    run(input_path=args.input, tool_name=args.tool)
