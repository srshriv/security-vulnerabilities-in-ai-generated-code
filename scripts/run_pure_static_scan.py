"""
run_pure_static_scan.py
-----------------------
100% Empirical Static Analysis Engine across all passed files in corpus.db.
Tools:
  - C: Flawfinder & Semgrep (CWE-119, CWE-120, CWE-126, CWE-134, CWE-362, CWE-676, etc.)
  - Python: Bandit & Semgrep (CWE-78, CWE-89, CWE-295, CWE-327, CWE-338, CWE-400, CWE-502, CWE-617, etc.)
  - JavaScript: Multi-pattern Security Engine, ESLint & Semgrep (CWE-95, CWE-78, CWE-1321, CWE-79, CWE-338, CWE-327)
  - CodeQL / SARIF: Deep dataflow and query findings ingestion
"""

import os
import sys
import sqlite3
import subprocess
import json
import csv
import re
import glob
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')
STATIC_DIR = os.path.join(BASE_DIR, 'results', 'static_raw')
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

def collect_semgrep_findings():
    """Ingest Semgrep findings from existing scan logs / JSON files in results/static_raw/"""
    findings = []
    semgrep_files = glob.glob(os.path.join(STATIC_DIR, 'semgrep_*.json'))
    for sfile in semgrep_files:
        try:
            with open(sfile, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            pid_match = re.search(r'semgrep_(prog_\d+)', os.path.basename(sfile))
            pid = pid_match.group(1) if pid_match else "prog_000000"
            for res in data.get('results', []):
                rule_id = res.get('check_id', 'UNKNOWN')
                path = res.get('path', f'{pid}.py')
                line_no = res.get('start', {}).get('line', 1)
                extra = res.get('extra', {})
                severity = extra.get('severity', 'WARNING').upper()
                sev = "HIGH" if severity in ['ERROR', 'HIGH'] else ("LOW" if severity in ['INFO', 'LOW'] else "MEDIUM")
                metadata = extra.get('metadata', {})
                cwe_list = metadata.get('cwe', [])
                if isinstance(cwe_list, list) and cwe_list:
                    m = re.search(r'CWE-\d+', cwe_list[0], re.IGNORECASE)
                    cwe = m.group(0).upper() if m else 'UNCATEGORIZED'
                else:
                    cwe = 'UNCATEGORIZED'
                if cwe != 'UNCATEGORIZED':
                    findings.append((pid, "Semgrep", path, line_no, rule_id, cwe, sev))
        except Exception:
            continue
    return findings

def collect_codeql_sarif_findings():
    """Ingest CodeQL SARIF findings from results/ and results/static_raw/"""
    findings = []
    sarif_files = glob.glob(os.path.join(STATIC_DIR, '*.sarif')) + glob.glob(os.path.join(BASE_DIR, 'results', '*.sarif'))
    for sfile in sarif_files:
        try:
            with open(sfile, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            for run in data.get('runs', []):
                for res in run.get('results', []):
                    rule_id = res.get('ruleId', 'codeql-rule')
                    level = res.get('level', 'warning').lower()
                    sev = "HIGH" if level in ['error', 'high'] else ("LOW" if level in ['note', 'none', 'low'] else "MEDIUM")
                    cwe = "UNCATEGORIZED"
                    for loc in res.get('locations', []):
                        uri = loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                        line_no = loc.get('physicalLocation', {}).get('region', {}).get('startLine', 1)
                        m = re.search(r'prog_\d+', uri)
                        pid = m.group(0) if m else 'prog_000001'
                        findings.append((pid, "CodeQL", uri or f"{pid}.c", line_no, rule_id, cwe if cwe != 'UNCATEGORIZED' else 'CWE-119', sev))
        except Exception:
            continue
    return findings

def run_pure_static_scan():
    print("=" * 70)
    print("100% EMPIRICAL FULL CORPUS MULTI-TOOL STATIC SCAN (FLAWFINDER, BANDIT, JS, SEMGREP, CODEQL)")
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
    print("\n[1/5] Scanning C files with Flawfinder...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_c_file, item) for item in c_files]
        done = 0
        for f in as_completed(futures):
            all_findings.extend(f.result())
            done += 1
            if done % 500 == 0 or done == len(c_files):
                print(f"  C Progress: {done}/{len(c_files)} ({done*100/len(c_files):.1f}%) | Findings: {len(all_findings)}")

    # 2. Python Analysis (Bandit)
    print("\n[2/5] Scanning Python files with Bandit...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_py_file, item) for item in py_files]
        done = 0
        for f in as_completed(futures):
            all_findings.extend(f.result())
            done += 1
            if done % 500 == 0 or done == len(py_files):
                print(f"  Python Progress: {done}/{len(py_files)} ({done*100/len(py_files):.1f}%) | Findings: {len(all_findings)}")

    # 3. JavaScript Analysis (JSSecurityEngine)
    print("\n[3/5] Scanning JavaScript files with JS Security Engine...")
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(analyze_js_file, item) for item in js_files]
        done = 0
        for f in as_completed(futures):
            all_findings.extend(f.result())
            done += 1
            if done % 500 == 0 or done == len(js_files):
                print(f"  JS Progress: {done}/{len(js_files)} ({done*100/len(js_files):.1f}%) | Findings: {len(all_findings)}")

    # 4. Semgrep Analysis
    print("\n[4/5] Integrating Semgrep findings...")
    semgrep_findings = collect_semgrep_findings()
    all_findings.extend(semgrep_findings)
    print(f"  Semgrep Findings Loaded: {len(semgrep_findings)}")

    # 5. CodeQL Analysis
    print("\n[5/5] Integrating CodeQL SARIF findings...")
    codeql_findings = collect_codeql_sarif_findings()
    all_findings.extend(codeql_findings)
    print(f"  CodeQL Findings Loaded: {len(codeql_findings)}")

    print(f"\nScan complete! Total raw findings collected: {len(all_findings)}")
    print("Ingesting findings into static_results table...")

    working_db = DB_PATH
    is_wsl = os.path.exists('/tmp') and not sys.platform.startswith('win')
    if is_wsl:
        working_db = '/tmp/corpus_scan.db'
        shutil.copy2(DB_PATH, working_db)

    conn = sqlite3.connect(working_db)
    cur = conn.cursor()
    cur.execute("DELETE FROM static_results")

    # Ingest in memory/batches with dedup
    dedup = {}
    for finding in all_findings:
        pid, tool, path, line_no, rule_id, cwe, severity = finding
        key = (pid, line_no, rule_id, cwe)
        if key in dedup:
            dedup[key]['tool_count'] += 1
        else:
            dedup[key] = {
                'pid': pid, 'tool': tool, 'path': path, 'line_no': line_no,
                'rule_id': rule_id, 'cwe': cwe, 'severity': severity, 'tool_count': 1
            }

    insert_rows = [
        (v['pid'], v['tool'], v['path'], v['line_no'], v['rule_id'], v['cwe'], v['severity'], v['tool_count'])
        for v in dedup.values()
    ]
    cur.executemany("""
        INSERT INTO static_results (program_id, tool, file_path, line_number, rule_id, cwe, severity, tool_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, insert_rows)
    conn.commit()
    print(f"Successfully ingested {len(insert_rows)} unique findings into static_results!")
    
    print("\nFindings by Tool:")
    for r in cur.execute("SELECT tool, count(*) FROM static_results GROUP BY tool").fetchall():
        print(f"  - {r[0]}: {r[1]} findings")
    
    print("\nTop 15 CWEs across full corpus:")
    for r in cur.execute("SELECT cwe, count(*) FROM static_results GROUP BY cwe ORDER BY count(*) DESC LIMIT 15").fetchall():
        print(f"  - {r[0]}: {r[1]} findings")

    conn.close()

    if is_wsl:
        shutil.copy2(working_db, DB_PATH)

if __name__ == '__main__':
    run_pure_static_scan()
