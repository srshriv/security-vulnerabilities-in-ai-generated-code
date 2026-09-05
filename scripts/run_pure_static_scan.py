"""
run_pure_static_scan.py
-----------------------
100% Empirical Static Analysis Engine across all passed files in corpus.db.
Tools:
  - C: Flawfinder (CWE-119, CWE-120, CWE-126, CWE-134, CWE-362, CWE-676, etc.)
  - Python: Bandit (CWE-78, CWE-89, CWE-295, CWE-327, CWE-338, CWE-400, CWE-502, etc.)
  - JavaScript: Multi-pattern Security Engine (CWE-95 Eval/Code Injection, CWE-78 Child Process,
                CWE-1321 Prototype Pollution, CWE-79 XSS / DOM Injection, CWE-338 Insecure Randomness, CWE-327 Weak Crypto)
"""

import os
import sys
import sqlite3
import subprocess
import json
import csv
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')
CORRECTIONS_FILE = os.path.join(BASE_DIR, 'scripts', 'bandit_cwe_corrections.json')

BANDIT_MAP = {}
if os.path.exists(CORRECTIONS_FILE):
    with open(CORRECTIONS_FILE, 'r', encoding='utf-8') as f:
        raw_b = json.load(f)
        for k, v in raw_b.items():
            if k != "_note":
                BANDIT_MAP[k] = v.get("correct_cwe", "UNCATEGORIZED")

# JavaScript Security Rules
JS_SECURITY_RULES = [
    (r'\beval\s*\(', "CWE-95", "eval_used", "HIGH"),
    (r'\bFunction\s*\([^)]*\)\s*\(', "CWE-95", "function_constructor_eval", "HIGH"),
    (r'\bsetTimeout\s*\(\s*["\']', "CWE-95", "string_setTimeout_eval", "MEDIUM"),
    (r'\bsetInterval\s*\(\s*["\']', "CWE-95", "string_setInterval_eval", "MEDIUM"),
    (r'\bexec\s*\([^)]*shell\s*:\s*true', "CWE-78", "child_process_shell_true", "HIGH"),
    (r'\bchild_process\.(?:exec|execSync)\s*\(', "CWE-78", "child_process_exec", "HIGH"),
    (r'\b(?:spawn|spawnSync)\s*\([^,]+,\s*\{[^}]*shell\s*:\s*true', "CWE-78", "spawn_shell_true", "HIGH"),
    (r'\.innerHTML\s*=', "CWE-79", "dom_xss_innerhtml", "MEDIUM"),
    (r'\.outerHTML\s*=', "CWE-79", "dom_xss_outerhtml", "MEDIUM"),
    (r'document\.write\s*\(', "CWE-79", "document_write_xss", "MEDIUM"),
    (r'Math\.random\s*\(', "CWE-338", "weak_prng_math_random", "LOW"),
    (r'crypto\.createCipher\s*\(\s*["\'](?:des|rc4|md5)', "CWE-327", "weak_crypto_cipher", "HIGH"),
    (r'crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']', "CWE-327", "weak_hash_md5_sha1", "LOW"),
    (r'__proto__\s*\[', "CWE-1321", "prototype_pollution_proto", "HIGH"),
    (r'Object\.assign\s*\([^,]+,\s*JSON\.parse', "CWE-1321", "prototype_pollution_assign", "MEDIUM"),
    (r'vm\.(?:runInContext|runInThisContext|runInNewContext)\s*\(', "CWE-94", "vm_code_execution", "HIGH")
]

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
    if not content:
        return findings
    
    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        for pattern, cwe, rule_id, sev in JS_SECURITY_RULES:
            if re.search(pattern, line):
                findings.append((pid, "JSSecurityEngine", f"{pid}.js", idx, rule_id, cwe, sev))
    return findings

def run_pure_static_scan():
    print("=" * 70)
    print("100% EMPIRICAL FULL CORPUS STATIC ANALYSIS SCAN")
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

    print(f"Loaded: {len(c_files)} C, {len(py_files)} Python, {len(js_files)} JS (Total: {len(rows)})")

    all_findings = []

    # 1. C Analysis (Flawfinder)
    print("\n[1/3] Scanning C files with Flawfinder...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_c_file, item) for item in c_files]
        done = 0
        for f in as_completed(futures):
            all_findings.extend(f.result())
            done += 1
            if done % 500 == 0 or done == len(c_files):
                print(f"  C Progress: {done}/{len(c_files)} ({done*100/len(c_files):.1f}%) | Findings: {len(all_findings)}")

    # 2. Python Analysis (Bandit)
    print("\n[2/3] Scanning Python files with Bandit...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_py_file, item) for item in py_files]
        done = 0
        for f in as_completed(futures):
            all_findings.extend(f.result())
            done += 1
            if done % 500 == 0 or done == len(py_files):
                print(f"  Python Progress: {done}/{len(py_files)} ({done*100/len(py_files):.1f}%) | Findings: {len(all_findings)}")

    # 3. JavaScript Analysis (JSSecurityEngine)
    print("\n[3/3] Scanning JavaScript files with JS Security Engine...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_js_file, item) for item in js_files]
        done = 0
        for f in as_completed(futures):
            all_findings.extend(f.result())
            done += 1
            if done % 500 == 0 or done == len(js_files):
                print(f"  JS Progress: {done}/{len(js_files)} ({done*100/len(js_files):.1f}%) | Findings: {len(all_findings)}")

    print(f"\nScan complete! Total raw findings collected: {len(all_findings)}")
    print("Ingesting findings into static_results table...")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM static_results")

    inserted = 0
    for finding in all_findings:
        pid, tool, path, line_no, rule_id, cwe, severity = finding
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
    
    print("\nFindings by Tool:")
    for r in cur.execute("SELECT tool, count(*) FROM static_results GROUP BY tool").fetchall():
        print(f"  - {r[0]}: {r[1]} findings")
    
    print("\nTop 15 CWEs across full corpus:")
    for r in cur.execute("SELECT cwe, count(*) FROM static_results GROUP BY cwe ORDER BY count(*) DESC LIMIT 15").fetchall():
        print(f"  - {r[0]}: {r[1]} findings")

    conn.close()

if __name__ == '__main__':
    run_pure_static_scan()
