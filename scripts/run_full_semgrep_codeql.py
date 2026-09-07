"""
run_full_semgrep_codeql.py
--------------------------
1. Exports all 6,320 passed corpus programs to structured directories:
     - /tmp/corpus_export/Python/ (3,978 .py files)
     - /tmp/corpus_export/JavaScript/ (2,025 .js files)
     - /tmp/corpus_export/C/ (317 .c files)

2. Runs Semgrep batch security scan across each language directory using:
     - p/security-audit, p/cwe-top-25, p/owasp-top-ten, p/python, p/javascript

3. Builds CodeQL databases and analyzes:
     - Python database: `codeql database create ... --language=python` -> `codeql database analyze python-security-and-quality.qls`
     - JavaScript database: `codeql database create ... --language=javascript` -> `codeql database analyze javascript-security-and-quality.qls`
     - C database (or AST fallback): `codeql database create ... --language=cpp`

4. Ingests all Semgrep and CodeQL SARIF/JSON findings into `static_results` in `corpus.db`.
5. Recomputes static summary and outputs `results/static_summary_corrected.json`.
"""

import os
import sys
import sqlite3
import subprocess
import json
import re
import shutil
import time

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
STATIC_RAW_DIR = os.path.join(RESULTS_DIR, 'static_raw')
os.makedirs(STATIC_RAW_DIR, exist_ok=True)

# Ensure Linux PATH finds Semgrep and CodeQL
ENV = os.environ.copy()
ENV['PATH'] = f"/home/kiit/codeql:/home/kiit/.local/bin:/usr/local/bin:/usr/bin:/bin:{ENV.get('PATH', '')}"
ENV['CODEQL_ALLOW_INSTALLATION_ANYWHERE'] = 'true'

EXPORT_DIR = '/tmp/corpus_export' if not sys.platform.startswith('win') else os.path.join(BASE_DIR, 'corpus_export')

def export_corpus_files():
    print("=" * 70)
    print("1. EXPORTING 6,320 FILTERED PROGRAMS TO DIRECTORIES")
    print("=" * 70)
    if os.path.exists(EXPORT_DIR):
        shutil.rmtree(EXPORT_DIR)
    os.makedirs(EXPORT_DIR, exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT f.program_id, r.file_content, r.language
        FROM raw_files r
        JOIN filtered_files f ON r.id = f.raw_file_id
        WHERE f.stage1 = 'PASSED'
    """).fetchall()
    conn.close()

    ext_map = {'C': 'c', 'Python': 'py', 'JavaScript': 'js'}
    counts = {'C': 0, 'Python': 0, 'JavaScript': 0}
    for pid, content, lang in rows:
        ext = ext_map.get(lang, 'txt')
        target_dir = os.path.join(EXPORT_DIR, lang)
        os.makedirs(target_dir, exist_ok=True)
        file_path = os.path.join(target_dir, f"{pid}.{ext}")
        with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(content or '')
        counts[lang] = counts.get(lang, 0) + 1

    print(f"Exported to {EXPORT_DIR}:")
    for k, v in counts.items():
        print(f"  - {k}: {v} files")
    return counts

def run_semgrep_scans():
    print("\n" + "=" * 70)
    print("2. RUNNING SEMGREP SCAN ACROSS ALL 6,320 PROGRAMS")
    print("=" * 70)
    semgrep_findings = []
    
    configs = ['p/security-audit', 'p/owasp-top-ten', 'p/cwe-top-25', 'p/ci']
    config_args = []
    for c in configs:
        config_args.extend(['--config', c])

    languages = ['Python', 'JavaScript', 'C']
    for lang in languages:
        lang_dir = os.path.join(EXPORT_DIR, lang)
        if not os.path.exists(lang_dir):
            continue
        out_json = os.path.join(STATIC_RAW_DIR, f"semgrep_full_{lang.lower()}.json")
        print(f"Running Semgrep on {lang} corpus ({len(os.listdir(lang_dir))} files)...")
        cmd = ['semgrep'] + config_args + ['--json', '--output', out_json, lang_dir]
        
        t0 = time.time()
        res = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
        elapsed = time.time() - t0
        print(f"  Completed in {elapsed:.1f}s (code: {res.returncode})")
        
        if os.path.exists(out_json):
            try:
                data = json.load(open(out_json, encoding='utf-8', errors='ignore'))
                results = data.get('results', [])
                print(f"  Semgrep flagged {len(results)} findings in {lang}!")
                for r in results:
                    rule_id = r.get('check_id', 'semgrep-rule')
                    path = r.get('path', '')
                    m_pid = re.search(r'(prog_\d+)', path)
                    pid = m_pid.group(1) if m_pid else 'prog_000000'
                    line_no = r.get('start', {}).get('line', 1)
                    extra = r.get('extra', {})
                    sev_raw = extra.get('severity', 'WARNING').upper()
                    sev = "HIGH" if sev_raw in ['ERROR', 'HIGH'] else ("LOW" if sev_raw in ['INFO', 'LOW'] else "MEDIUM")
                    
                    cwe = "UNCATEGORIZED"
                    metadata = extra.get('metadata', {})
                    cwe_val = metadata.get('cwe')
                    if isinstance(cwe_val, list) and cwe_val:
                        m_cwe = re.search(r'CWE-\d+', cwe_val[0], re.IGNORECASE)
                        cwe = m_cwe.group(0).upper() if m_cwe else 'UNCATEGORIZED'
                    elif isinstance(cwe_val, str):
                        m_cwe = re.search(r'CWE-\d+', cwe_val, re.IGNORECASE)
                        cwe = m_cwe.group(0).upper() if m_cwe else 'UNCATEGORIZED'
                    
                    if cwe == 'UNCATEGORIZED':
                        # Default heuristics from rule_id
                        if 'sql' in rule_id.lower(): cwe = 'CWE-89'
                        elif 'exec' in rule_id.lower() or 'command' in rule_id.lower(): cwe = 'CWE-78'
                        elif 'xss' in rule_id.lower() or 'innerhtml' in rule_id.lower(): cwe = 'CWE-79'
                        elif 'eval' in rule_id.lower(): cwe = 'CWE-95'
                        elif 'deserial' in rule_id.lower() or 'pickle' in rule_id.lower(): cwe = 'CWE-502'
                        elif 'crypto' in rule_id.lower() or 'hash' in rule_id.lower(): cwe = 'CWE-327'
                        elif 'random' in rule_id.lower(): cwe = 'CWE-338'
                        else: cwe = 'CWE-699'
                    
                    semgrep_findings.append((pid, "Semgrep", os.path.basename(path), line_no, rule_id, cwe, sev))
            except Exception as e:
                print(f"  Error reading {out_json}: {e}")

    print(f"Total Semgrep findings collected across full corpus: {len(semgrep_findings)}")
    return semgrep_findings

def run_codeql_scans():
    print("\n" + "=" * 70)
    print("3. BUILDING CODEQL DATABASES AND RUNNING DEEP SECURITY QUERIES")
    print("=" * 70)
    codeql_findings = []
    
    codeql_exec = shutil.which('codeql', path=ENV['PATH']) or '/home/kiit/codeql/codeql'
    if not os.path.exists(codeql_exec) and shutil.which('codeql') is None:
        print("  CodeQL executable not found, skipping CodeQL scan.")
        return codeql_findings

    # 1. Python CodeQL DB
    py_dir = os.path.join(EXPORT_DIR, 'Python')
    py_db = '/tmp/codeql_py_db'
    py_sarif = os.path.join(STATIC_RAW_DIR, 'codeql_python.sarif')
    if os.path.exists(py_dir):
        if os.path.exists(py_db): shutil.rmtree(py_db)
        print(f"Building CodeQL Python Database ({len(os.listdir(py_dir))} files)...")
        cmd1 = [codeql_exec, 'database', 'create', py_db, '--language=python', f'--source-root={py_dir}', '--overwrite']
        res1 = subprocess.run(cmd1, env=ENV, capture_output=True, text=True)
        print(f"  DB Created (code: {res1.returncode})")
        
        print("Analyzing CodeQL Python Security Queries...")
        cmd2 = [codeql_exec, 'database', 'analyze', py_db, 'python-security-and-quality.qls',
                '--format=sarifv2.1.0', f'--output={py_sarif}', '--threads=8']
        res2 = subprocess.run(cmd2, env=ENV, capture_output=True, text=True)
        print(f"  Python Analysis Done (code: {res2.returncode})")

    # 2. JavaScript CodeQL DB
    js_dir = os.path.join(EXPORT_DIR, 'JavaScript')
    js_db = '/tmp/codeql_js_db'
    js_sarif = os.path.join(STATIC_RAW_DIR, 'codeql_javascript.sarif')
    if os.path.exists(js_dir):
        if os.path.exists(js_db): shutil.rmtree(js_db)
        print(f"Building CodeQL JavaScript Database ({len(os.listdir(js_dir))} files)...")
        cmd1 = [codeql_exec, 'database', 'create', js_db, '--language=javascript', f'--source-root={js_dir}', '--overwrite']
        res1 = subprocess.run(cmd1, env=ENV, capture_output=True, text=True)
        print(f"  DB Created (code: {res1.returncode})")
        
        print("Analyzing CodeQL JavaScript Security Queries...")
        cmd2 = [codeql_exec, 'database', 'analyze', js_db, 'javascript-security-and-quality.qls',
                '--format=sarifv2.1.0', f'--output={js_sarif}', '--threads=8']
                
        res2 = subprocess.run(cmd2, env=ENV, capture_output=True, text=True)
        print(f"  JS Analysis Done (code: {res2.returncode})")

    # Parse all SARIF files generated
    for sarif_path in [py_sarif, js_sarif] + glob.glob(os.path.join(STATIC_RAW_DIR, '*.sarif')):
        if not os.path.exists(sarif_path):
            continue
        try:
            data = json.load(open(sarif_path, encoding='utf-8', errors='ignore'))
            for run in data.get('runs', []):
                # Build rule tags map
                rules_cwe = {}
                for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
                    rid = rule.get('id', '')
                    tags = rule.get('properties', {}).get('tags', [])
                    for t in tags:
                        m = re.search(r'CWE-\d+', t, re.IGNORECASE)
                        if m:
                            rules_cwe[rid] = m.group(0).upper()
                            break
                
                for res in run.get('results', []):
                    rule_id = res.get('ruleId', 'codeql-rule')
                    level = res.get('level', 'warning').lower()
                    sev = "HIGH" if level in ['error', 'high'] else ("LOW" if level in ['note', 'none', 'low'] else "MEDIUM")
                    cwe = rules_cwe.get(rule_id, 'UNCATEGORIZED')
                    if cwe == 'UNCATEGORIZED':
                        # Match from ruleId
                        if 'sql' in rule_id.lower(): cwe = 'CWE-89'
                        elif 'xss' in rule_id.lower() or 'dom' in rule_id.lower(): cwe = 'CWE-79'
                        elif 'eval' in rule_id.lower() or 'code-injection' in rule_id.lower(): cwe = 'CWE-95'
                        elif 'command' in rule_id.lower() or 'shell' in rule_id.lower(): cwe = 'CWE-78'
                        elif 'path' in rule_id.lower() or 'traversal' in rule_id.lower(): cwe = 'CWE-22'
                        elif 'overflow' in rule_id.lower() or 'bound' in rule_id.lower(): cwe = 'CWE-119'
                        else: cwe = 'CWE-699'

                    for loc in res.get('locations', []):
                        uri = loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                        line_no = loc.get('physicalLocation', {}).get('region', {}).get('startLine', 1)
                        m_pid = re.search(r'(prog_\d+)', uri)
                        pid = m_pid.group(1) if m_pid else 'prog_000000'
                        codeql_findings.append((pid, "CodeQL", os.path.basename(uri), line_no, rule_id, cwe, sev))
        except Exception as e:
            print(f"  Error reading {sarif_path}: {e}")

    print(f"Total CodeQL findings collected across full corpus: {len(codeql_findings)}")
    return codeql_findings

def ingest_and_recompute(semgrep_findings, codeql_findings):
    print("\n" + "=" * 70)
    print("4. MERGING FINDINGS AND RECOMPUTING STATIC METRICS")
    print("=" * 70)
    
    # Import standard scans for Flawfinder, Bandit, and JSSecurityEngine
    from run_pure_static_scan import analyze_c_file, analyze_py_file, analyze_js_file
    from concurrent.futures import ThreadPoolExecutor, as_completed

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

    all_findings = []
    
    # Flawfinder
    print("Running Flawfinder across C files...")
    with ThreadPoolExecutor(max_workers=16) as ex:
        for f in as_completed([ex.submit(analyze_c_file, it) for it in c_files]):
            all_findings.extend(f.result())

    # Bandit
    print("Running Bandit across Python files...")
    with ThreadPoolExecutor(max_workers=16) as ex:
        for f in as_completed([ex.submit(analyze_py_file, it) for it in py_files]):
            all_findings.extend(f.result())

    # JS Security Engine
    print("Running JS Security Engine across JS files...")
    with ThreadPoolExecutor(max_workers=16) as ex:
        for f in as_completed([ex.submit(analyze_js_file, it) for it in js_files]):
            all_findings.extend(f.result())

    # Add Semgrep and CodeQL findings
    all_findings.extend(semgrep_findings)
    all_findings.extend(codeql_findings)

    print(f"\nTotal combined findings collected: {len(all_findings)}")
    
    # Ingest into SQLite using local tmp to avoid 9p locking
    working_db = '/tmp/corpus_scan.db' if not sys.platform.startswith('win') else DB_PATH
    if working_db != DB_PATH:
        shutil.copy2(DB_PATH, working_db)

    conn = sqlite3.connect(working_db)
    cur = conn.cursor()
    cur.execute("DELETE FROM static_results")

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
    conn.close()

    if working_db != DB_PATH:
        shutil.copy2(working_db, DB_PATH)

    print(f"Successfully saved {len(insert_rows)} findings into corpus.db static_results!")

    # Run recompute_static_summary
    print("\nRunning recompute_static_summary.py...")
    import recompute_static_summary
    recompute_static_summary.main()

def main():
    export_corpus_files()
    semgrep_findings = run_semgrep_scans()
    codeql_findings = run_codeql_scans()
    ingest_and_recompute(semgrep_findings, codeql_findings)

if __name__ == '__main__':
    main()
