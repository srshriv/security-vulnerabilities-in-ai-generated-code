"""
ingest_sarif.py  — Day 5 Student B (fixed)
-------------------------------------------
Parses CodeQL + Semgrep SARIF output and inserts findings into static_results.

Fixes vs original:
  - Absolute DB_PATH derived from __file__ (was '../corpus.db')
  - Resolves real program_id from filtered_files instead of hardcoded 1
  - Dedup key (file_path, line_number, rule_id, cwe): increments tool_count
    rather than inserting a duplicate if the same triplet already exists
  - CWE extraction from SARIF tags / properties / rule metadata

Usage:
  # Ingest a single SARIF file
  python scripts/ingest_sarif.py --input results/static_raw/codeql_out.sarif --tool CodeQL

  # Batch-ingest all *.sarif files in results/static_raw/
  python scripts/ingest_sarif.py --batch
"""

import json
import os
import sqlite3
import glob
import argparse
import re

BASE_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH    = os.path.join(BASE_DIR, 'corpus.db')
STATIC_DIR = os.path.join(BASE_DIR, 'results', 'static_raw')

# Severity normalisation
_LEVEL_MAP = {
    "error":   "HIGH",
    "warning": "MEDIUM",
    "note":    "LOW",
    "none":    "LOW",
}


def extract_cwe(rule: dict) -> str:
    """Extract a CWE identifier from a SARIF rule object.

    Checks (in order):
      1. rule.properties.tags  (e.g. ["CWE-89"])
      2. rule.relationships    (SARIF 2.1 taxa)
      3. rule.id               (if it starts with 'CWE')
    """
    props = rule.get("properties", {})
    tags  = props.get("tags", [])
    for tag in tags:
        if re.match(r"CWE-\d+", tag, re.IGNORECASE):
            return tag.upper()

    for rel in rule.get("relationships", []):
        target = rel.get("target", {})
        tid    = target.get("id", "")
        if re.match(r"CWE-\d+", tid, re.IGNORECASE):
            return tid.upper()

    rule_id = rule.get("id", "")
    if re.match(r"CWE-\d+", rule_id, re.IGNORECASE):
        return rule_id.upper()

    return "UNCATEGORIZED"


def resolve_program_id(cursor, file_path: str):
    """Look up program_id in filtered_files by exact path, then by basename."""
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


def ingest_sarif(file_path: str, tool_name: str, cursor) -> tuple[int, int]:
    """Ingest one SARIF file. Returns (inserted, skipped_unmatched)."""
    if not os.path.exists(file_path):
        print(f"  [SKIP] Not found: {file_path}")
        return 0, 0

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    inserted = 0
    skipped  = 0

    for run in data.get("runs", []):
        # Build rule → CWE lookup from this run's tool rules
        rules_by_id = {}
        tool_rules = (
            run.get("tool", {})
               .get("driver", {})
               .get("rules", [])
        )
        for rule in tool_rules:
            rid = rule.get("id", "")
            if rid:
                rules_by_id[rid] = rule

        for result in run.get("results", []):
            rule_id   = result.get("ruleId", "UNKNOWN")
            level     = result.get("level", "warning")
            severity  = _LEVEL_MAP.get(level, "MEDIUM")

            # CWE: try the result's rule first, then the result object itself
            rule_obj  = rules_by_id.get(rule_id, {})
            cwe       = extract_cwe(rule_obj)
            if cwe == "UNCATEGORIZED":
                cwe = extract_cwe(result)

            for loc in result.get("locations", []):
                phys    = loc.get("physicalLocation", {})
                uri     = phys.get("artifactLocation", {}).get("uri", "unknown")
                line_no = phys.get("region", {}).get("startLine", 0)

                program_id = resolve_program_id(cursor, uri)
                if not program_id:
                    skipped += 1
                    continue

                # Dedup check
                existing = cursor.execute("""
                    SELECT id, tool_count FROM static_results
                    WHERE program_id = ? AND file_path = ?
                      AND line_number = ? AND rule_id = ? AND cwe = ?
                    LIMIT 1
                """, (program_id, uri, line_no, rule_id, cwe)).fetchone()

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
                        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                    """, (program_id, uri, line_no, rule_id, cwe, severity, tool_name))
                    inserted += 1

    return inserted, skipped


def run(input_path: str = None, tool_name: str = "CodeQL", batch: bool = False):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    ensure_tool_count_column(c)

    if batch:
        paths = sorted(glob.glob(os.path.join(STATIC_DIR, "*.sarif")))
        if not paths:
            print(f"No *.sarif files found in {STATIC_DIR}")
            conn.close()
            return
    elif input_path:
        paths = [input_path]
    else:
        # Default test file
        paths = [os.path.join(BASE_DIR, "results", "test_sample.sarif")]

    total_ins = total_skp = 0
    for p in paths:
        print(f"Ingesting: {os.path.basename(p)} ...", end=" ")
        ins, skp = ingest_sarif(p, tool_name, c)
        conn.commit()
        print(f"{ins} inserted, {skp} unmatched")
        total_ins += ins
        total_skp += skp

    print(f"\nTotal inserted : {total_ins}")
    print(f"Total unmatched: {total_skp}")
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest SARIF findings into static_results")
    parser.add_argument("--input", type=str, default=None, help="Path to SARIF file")
    parser.add_argument("--tool",  type=str, default="CodeQL", help="Tool label (default: CodeQL)")
    parser.add_argument("--batch", action="store_true",
                        help="Ingest all *.sarif files in results/static_raw/")
    args = parser.parse_args()
    run(input_path=args.input, tool_name=args.tool, batch=args.batch)