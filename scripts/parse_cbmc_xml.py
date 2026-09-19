"""
parse_cbmc_xml.py  — Student A, Day 5 (fixed)
-----------------------------------------------
Parses CBMC XML output files and inserts results into formal_results.

Fixes vs original:
  - Absolute paths for DB_PATH and XML_DIR (were '../corpus.db' / '../results/cbmc_out')
  - program_id is resolved from filtered_files by matching file path,
    not cast from the integer XML filename
  - Extracts counterexample variable assignments into formal_results.counterexample_vars
    (JSON array) for use by generate_asan_harness.py

Expected XML file naming: <program_id>.xml  (e.g. prog_000042.xml)
or <integer_id>.xml where integer_id matches filtered_files.id

Usage:
  python scripts/parse_cbmc_xml.py
  python scripts/parse_cbmc_xml.py --xml-dir results/cbmc_out
"""

import sqlite3
import os
import glob
import json
import argparse
import xml.etree.ElementTree as ET

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
XML_DIR  = os.path.join(BASE_DIR, 'results', 'cbmc_out')


def extract_counterexample_vars(root) -> str | None:
    """Extract variable assignments from CBMC's <goto-trace> element.

    Returns a JSON string [{name, type, value}, ...] or None.
    """
    trace = root.find(".//goto-trace")
    if trace is None:
        return None

    variables = []
    for assignment in trace.findall(".//assignment"):
        var_name  = assignment.findtext("full_lhs")  or assignment.findtext("lhs") or ""
        var_type  = assignment.findtext("type")       or "int"
        var_value = assignment.findtext("full_lhs_value") or assignment.findtext("rhs") or "0"

        if var_name:
            variables.append({
                "name":  var_name.strip(),
                "type":  var_type.strip(),
                "value": var_value.strip(),
            })

    return json.dumps(variables) if variables else None


def parse_one(xml_path: str) -> tuple[str, str | None, str | None]:
    """Parse a single CBMC XML file.

    Returns (verdict, violated_property, counterexample_json_or_None).
    verdict is one of: SAT, UNSAT, INCONCLUSIVE, PARSE_ERROR
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        counterexample = extract_counterexample_vars(root)

        results = root.findall(".//result")
        if not results:
            return "INCONCLUSIVE", None, counterexample

        for r in results:
            if r.get("status") == "FAILURE":
                prop = r.get("property", "")
                return "SAT", prop, counterexample

        return "UNSAT", None, counterexample

    except ET.ParseError as e:
        print(f"  [WARN] XML parse error in {os.path.basename(xml_path)}: {e}")
        return "PARSE_ERROR", None, None


def resolve_program_id(cursor, stem: str) -> str | None:
    """Map an XML filename stem to a program_id.

    Tries (in order):
      1. Direct match: stem IS a program_id (e.g. 'prog_000042')
      2. Integer stem: look up filtered_files.id = int(stem)
    """
    # Try direct match (stem looks like prog_NNNNNN)
    row = cursor.execute(
        "SELECT program_id FROM filtered_files WHERE program_id = ? LIMIT 1",
        (stem,)
    ).fetchone()
    if row:
        return row[0]

    # Try integer ID lookup
    try:
        int_id = int(stem)
        row = cursor.execute(
            "SELECT program_id FROM filtered_files WHERE id = ? LIMIT 1",
            (int_id,)
        ).fetchone()
        if row:
            return row[0]
    except ValueError:
        pass

    return None


def run(xml_dir: str = XML_DIR):
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure counterexample_json column exists (should already in schema)
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(formal_results)").fetchall()]
    if "counterexample_json" not in cols:
        cursor.execute("ALTER TABLE formal_results ADD COLUMN counterexample_json TEXT")
        print("  [INFO] Added counterexample_json column to formal_results.")

    xml_files = sorted(glob.glob(os.path.join(xml_dir, "*.xml")))
    if not xml_files:
        print(f"No XML files found in {xml_dir}")
        print("Run CBMC on Linux first, place output XMLs there, then re-run.")
        conn.close()
        return

    print(f"Parsing {len(xml_files)} CBMC XML files from {xml_dir}...")
    n = 0

    for xml_path in xml_files:
        stem = os.path.splitext(os.path.basename(xml_path))[0]
        program_id = resolve_program_id(cursor, stem)

        if not program_id:
            print(f"  [SKIP] Cannot resolve program_id for: {os.path.basename(xml_path)}")
            continue

        verdict, prop, ce_json = parse_one(xml_path)

        cursor.execute("""
            INSERT OR REPLACE INTO formal_results
                (program_id, cbmc_result, property_type, counterexample_json)
            VALUES (?, ?, ?, ?)
        """, (program_id, verdict, prop, ce_json))
        n += 1

    conn.commit()
    print(f"\nParsed {n} XML files into formal_results.")

    print("\nVerdict breakdown:")
    for row in cursor.execute(
        "SELECT cbmc_result, COUNT(*) FROM formal_results GROUP BY cbmc_result ORDER BY COUNT(*) DESC"
    ).fetchall():
        print(f"  {row[0]:<15}: {row[1]}")

    # SAT rate
    total_  = cursor.execute("SELECT COUNT(*) FROM formal_results").fetchone()[0]
    sat_    = cursor.execute(
        "SELECT COUNT(*) FROM formal_results WHERE cbmc_result = 'SAT'"
    ).fetchone()[0]
    if total_ > 0:
        print(f"\nSAT rate: {sat_}/{total_} = {sat_/total_*100:.1f}%")
        if sat_ / total_ >= 0.70:
            print("  ✓ SAT rate ≥ 70% — unwind bound is acceptable.")
        else:
            print("  ✗ SAT rate < 70% — consider increasing --unwind to 15.")

    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse CBMC XML output into formal_results")
    parser.add_argument("--xml-dir", type=str, default=XML_DIR,
                        help=f"Directory containing CBMC XML files (default: {XML_DIR})")
    args = parser.parse_args()
    run(xml_dir=args.xml_dir)
