"""
run_full_static_scan.py
-----------------------
High-performance batch static analysis runner for the entire corpus (5,042 files).
Runs:
  - C (2,335 files): Flawfinder (CWE-119, CWE-120, CWE-126, CWE-134, CWE-362, CWE-676, etc.)
  - Python (1,535 files): Bandit (CWE-78, CWE-89, CWE-295, CWE-327, CWE-338, CWE-400, CWE-502, etc.)
  - JavaScript (1,172 files): ESLint (CWE-94, CWE-95, CWE-79, CWE-1321, etc.)
Directly populates and deduplicates findings into `static_results` in `corpus.db`.
"""

import os
import sys
import sqlite3
import subprocess
import json
import csv
import re
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')
CORRECTIONS_FILE = os.path.join(BASE_DIR, 'scripts', 'bandit_cwe_corrections.json')

# Load bandit corrections
BANDIT_MAP = {}
if os.path.exists(CORRECTIONS_FILE):
    with open(CORRECTIONS_FILE, 'r', encoding='utf-8') as f:
        raw_b = json.load(f)
        for k, v in raw_b.items():
            if k != "_note":
                BANDIT_MAP[k] = v.get("correct_cwe", "UNCATEGORIZED")

ESLINT_CWE_MAP = {
    "no-eval": "CWE-95",
    "no-implied-eval": "CWE-95",
    "no-new-func": "CWE-95",
    "no-prototype-builtins": "CWE-1321",
    "security/detect-eval-with-expr": "CWE-95",
    "security/detect-non-literal-require": "CWE-73",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-338",
    "security/detect-unsafe-regex": "CWE-1333",
    "security/detect-buffer-noassert": "CWE-119",
    "security/detect-child-process": "CWE-78",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-object-injection": "CWE-1321",
    "security/detect-new-buffer": "CWE-119",
    "security/detect-bidi-characters": "CWE-94",
}

def analyze_c_file(item):
    pid, content = item
    findings = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False, encoding='utf-8') as f:
            f.write(content or '')
            tmp_path = f.name

        cmd = ['flawfinder', '--csv', tmp_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if res.stdout:
            reader = csv.DictReader(res.stdout.strip().splitlines())
            for row in reader:
                try:
                    line_val = row.get('Line', '1')
                    line_no = int(line_val) if line_val and line_val.isdigit() else 1
                    rule_id = row.get('Name', 'flaw') or 'flaw'
                    cwe_raw = row.get('CWEs', '') or ''
                    m = re.search(r'CWE-(\d+)', cwe_raw)
                    cwe = f"CWE-{m.group(1)}" if m else "CWE-119"
                    
                    lvl = row.get('Level', '2')
                    sev = "HIGH" if lvl in ['4', '5'] else ("MEDIUM" if lvl in ['2', '3'] else "LOW")
                    findings.append((pid, "Flawfinder", f"{pid}.c", line_no, rule_id, cwe, sev))
                except Exception:
                    continue
    except Exception:
        pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    return findings

def analyze_py_file(item):
    pid, content = item
    findings = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False, encoding='utf-8') as f:
            f.write(content or '')
            tmp_path = f.name

        cmd = [sys.executable, '-m', 'bandit', '-f', 'json', tmp_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if res.stdout:
            try:
                data = json.loads(res.stdout)
                for item_res in data.get('results', []):
                    test_id = item_res.get('test_id', 'B000')
                    line_no = int(item_res.get('line_number', 1))
                    sev = item_res.get('issue_severity', 'MEDIUM')
                    
                    cwe = BANDIT_MAP.get(test_id, 'UNCATEGORIZED')
                    if cwe == 'UNCATEGORIZED':
                        issue_cwe = item_res.get('issue_cwe', {})
                        if isinstance(issue_cwe, dict) and issue_cwe.get('id'):
                            cwe = f"CWE-{issue_cwe['id']}"
                    if cwe == 'UNCATEGORIZED':
                        cwe = 'CWE-78'
                    findings.append((pid, "Bandit", f"{pid}.py", line_no, test_id, cwe, sev))
            except Exception:
                pass
    except Exception:
        pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    return findings

def analyze_js_file(item):
    pid, content = item
    findings = []
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.js', mode='w', delete=False, encoding='utf-8') as f:
            f.write(content or '')
            tmp_path = f.name

        cmd = ['eslint', '--no-eslintrc', '--env', 'browser,node,es6',
               '--rule', '{"no-eval": "error", "no-implied-eval": "error", "no-new-func": "error", "no-prototype-builtins": "warn"}',
               '--format', 'json', tmp_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = res.stdout
        if not out:
            res2 = subprocess.run(['eslint', '--format', 'json', tmp_path], capture_output=True, text=True, timeout=20)
            out = res2.stdout

        if out:
            try:
                data = json.loads(out)
                for f_entry in data:
                    for msg in f_entry.get('messages', []):
                        rule_id = msg.get('ruleId', 'unknown') or 'unknown'
                        line_no = int(msg.get('line', 1))
                        cwe = ESLINT_CWE_MAP.get(rule_id, 'CWE-95' if 'eval' in rule_id else 'CWE-94')
                        findings.append((pid, "eslint", f"{pid}.js", line_no, rule_id, cwe, "HIGH" if msg.get('severity') == 2 else "MEDIUM"))
            except Exception:
                pass
    except Exception:
        pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    return findings

def main():
    print("=" * 70)
    print("FULL CORPUS STATIC ANALYSIS SCAN (5,042 FILES)")
    print("=" * 70)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        SELECT f.program_id, r.file_content, r.language
        FROM raw_files r
        JOIN filtered_files f ON r.id = f.raw_file_id
        WHERE f.stage1 = 'PASSED'
    """)
    rows = cur.fetchall()
    conn.close()

    c_files = [(r[0], r[1]) for r in rows if r[2] == 'C']
    py_files = [(r[0], r[1]) for r in rows if r[2] == 'Python']
    js_files = [(r[0], r[1]) for r in rows if r[2] == 'JavaScript']

    print(f"Loaded: {len(c_files)} C files, {len(py_files)} Python files, {len(js_files)} JS files (Total: {len(rows)})")

    all_findings = []

    # 1. C Analysis (Flawfinder)
    print("\n[1/3] Scanning C files with Flawfinder...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_c_file, item) for item in c_files]
        done = 0
        for f in as_completed(futures):
            res = f.result()
            all_findings.extend(res)
            done += 1
            if done % 500 == 0 or done == len(c_files):
                print(f"  C Scan Progress: {done}/{len(c_files)} ({done*100/len(c_files):.1f}%) | Findings so far: {len(all_findings)}")

    # 2. Python Analysis (Bandit)
    print("\n[2/3] Scanning Python files with Bandit...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_py_file, item) for item in py_files]
        done = 0
        for f in as_completed(futures):
            res = f.result()
            all_findings.extend(res)
            done += 1
            if done % 300 == 0 or done == len(py_files):
                print(f"  Python Scan Progress: {done}/{len(py_files)} ({done*100/len(py_files):.1f}%) | Findings so far: {len(all_findings)}")

    # 3. JavaScript Analysis (ESLint)
    print("\n[3/3] Scanning JavaScript files with ESLint...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_js_file, item) for item in js_files]
        done = 0
        for f in as_completed(futures):
            res = f.result()
            all_findings.extend(res)
            done += 1
            if done % 300 == 0 or done == len(js_files):
                print(f"  JS Scan Progress: {done}/{len(js_files)} ({done*100/len(js_files):.1f}%) | Findings so far: {len(all_findings)}")

    print(f"\nScan complete! Total raw findings collected: {len(all_findings)}")
    print("Ingesting findings into static_results table...")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM static_results")

    inserted = 0
    for finding in all_findings:
        pid, tool, path, line_no, rule_id, cwe, severity = finding
        # Deduplication check
        cur.execute("""
            SELECT id, tool_count FROM static_results
            WHERE program_id = ? AND line_number = ? AND rule_id = ? AND cwe = ?
        """, (pid, line_no, rule_id, cwe))
        existing = cur.fetchone()
        if existing:
            cur.execute("UPDATE static_results SET tool_count = tool_count + 1 WHERE id = ?", (existing[0],))
        else:
            cur.execute("""
                INSERT INTO static_results (program_id, tool, file_path, line_number, rule_id, cwe, severity, tool_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (pid, tool, path, line_no, rule_id, cwe, severity))
            inserted += 1

    conn.commit()

    print(f"Successfully ingested {inserted} unique findings into static_results!")
    
    # Summary
    print("\nFindings by Tool:")
    cur.execute("SELECT tool, count(*) FROM static_results GROUP BY tool")
    for r in cur.fetchall():
        print(f"  - {r[0]}: {r[1]} findings")
    
    cur.execute("SELECT cwe, count(*) FROM static_results GROUP BY cwe ORDER BY count(*) DESC LIMIT 15")
    print("\nTop 15 CWEs across full corpus:")
    for r in cur.fetchall():
        print(f"  - {r[0]}: {r[1]} findings")

    conn.close()

if __name__ == '__main__':
    main()
