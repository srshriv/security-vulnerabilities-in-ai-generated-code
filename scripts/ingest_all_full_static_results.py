"""
ingest_all_full_static_results.py
---------------------------------
Ingests full-corpus static findings across all 5 engines:
  1. CodeQL (from codeql_python.sarif and codeql_javascript.sarif)
  2. Semgrep (from semgrep_full_python.json, semgrep_full_javascript.json, semgrep_full_c.json)
  3. Bandit (Python full corpus)
  4. Flawfinder (C full corpus)
  5. JSSecurityEngine (JavaScript full corpus)

Populates `static_results` in `corpus.db` and runs `recompute_static_summary.py`.
"""

import os
import sys
import sqlite3
import json
import re
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')
STATIC_RAW_DIR = os.path.join(BASE_DIR, 'results', 'static_raw')

def parse_semgrep_files():
    print("\n--- Parsing Full Semgrep JSON Exports ---")
    findings = []
    semgrep_files = glob.glob(os.path.join(STATIC_RAW_DIR, "semgrep_full_*.json"))
    for sfile in semgrep_files:
        try:
            with open(sfile, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            results = data.get('results', [])
            print(f"  {os.path.basename(sfile)}: {len(results)} findings")
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
                    if 'sql' in rule_id.lower(): cwe = 'CWE-89'
                    elif 'exec' in rule_id.lower() or 'command' in rule_id.lower(): cwe = 'CWE-78'
                    elif 'xss' in rule_id.lower() or 'innerhtml' in rule_id.lower(): cwe = 'CWE-79'
                    elif 'eval' in rule_id.lower(): cwe = 'CWE-95'
                    elif 'deserial' in rule_id.lower() or 'pickle' in rule_id.lower(): cwe = 'CWE-502'
                    elif 'crypto' in rule_id.lower() or 'hash' in rule_id.lower(): cwe = 'CWE-327'
                    elif 'random' in rule_id.lower(): cwe = 'CWE-338'
                    elif 'xml' in rule_id.lower() or 'xxe' in rule_id.lower(): cwe = 'CWE-611'
                    else: cwe = 'CWE-699'
                
                findings.append((pid, "Semgrep", os.path.basename(path), line_no, rule_id, cwe, sev))
        except Exception as e:
            print(f"  Error reading {sfile}: {e}")
    print(f"Total Semgrep findings: {len(findings)}")
    return findings

def parse_codeql_sarif_files():
    print("\n--- Parsing Full CodeQL SARIF Exports ---")
    findings = []
    sarif_files = glob.glob(os.path.join(STATIC_RAW_DIR, "codeql_*.sarif"))
    for sfile in sarif_files:
        try:
            with open(sfile, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            file_findings = 0
            for run in data.get('runs', []):
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
                        if 'sql' in rule_id.lower(): cwe = 'CWE-89'
                        elif 'xss' in rule_id.lower() or 'dom' in rule_id.lower(): cwe = 'CWE-79'
                        elif 'eval' in rule_id.lower() or 'code-injection' in rule_id.lower(): cwe = 'CWE-95'
                        elif 'command' in rule_id.lower() or 'shell' in rule_id.lower(): cwe = 'CWE-78'
                        elif 'path' in rule_id.lower() or 'traversal' in rule_id.lower(): cwe = 'CWE-22'
                        elif 'overflow' in rule_id.lower() or 'bound' in rule_id.lower(): cwe = 'CWE-119'
                        elif 'random' in rule_id.lower(): cwe = 'CWE-338'
                        elif 'crypto' in rule_id.lower(): cwe = 'CWE-327'
                        else: cwe = 'CWE-699'

                    for loc in res.get('locations', []):
                        uri = loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                        line_no = loc.get('physicalLocation', {}).get('region', {}).get('startLine', 1)
                        m_pid = re.search(r'(prog_\d+)', uri)
                        pid = m_pid.group(1) if m_pid else 'prog_000000'
                        findings.append((pid, "CodeQL", os.path.basename(uri), line_no, rule_id, cwe, sev))
                        file_findings += 1
            print(f"  {os.path.basename(sfile)}: {file_findings} findings")
        except Exception as e:
            print(f"  Error reading {sfile}: {e}")
    print(f"Total CodeQL findings: {len(findings)}")
    return findings

def main():
    print("=" * 70)
    print("INGESTING ALL MULTI-TOOL CORPUS STATIC RESULTS")
    print("=" * 70)

    # 1. Semgrep & CodeQL
    semgrep_findings = parse_semgrep_files()
    codeql_findings = parse_codeql_sarif_files()

    # 2. Bandit, Flawfinder, JS Security Engine
    from run_pure_static_scan import analyze_c_file, analyze_py_file, analyze_js_file

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
    
    print("\n--- Running Flawfinder across C files ---")
    with ThreadPoolExecutor(max_workers=16) as ex:
        for f in as_completed([ex.submit(analyze_c_file, it) for it in c_files]):
            all_findings.extend(f.result())

    print("\n--- Running Bandit across Python files ---")
    with ThreadPoolExecutor(max_workers=16) as ex:
        for f in as_completed([ex.submit(analyze_py_file, it) for it in py_files]):
            all_findings.extend(f.result())

    print("\n--- Running JS Security Engine across JS files ---")
    with ThreadPoolExecutor(max_workers=16) as ex:
        for f in as_completed([ex.submit(analyze_js_file, it) for it in js_files]):
            all_findings.extend(f.result())

    # Add Semgrep and CodeQL findings
    all_findings.extend(semgrep_findings)
    all_findings.extend(codeql_findings)

    print(f"\nTotal raw multi-tool findings collected: {len(all_findings)}")
    
    # Ingest into SQLite database
    conn = sqlite3.connect(DB_PATH)
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

    print(f"Successfully saved {len(insert_rows)} unique findings into static_results table!")

    # Run recompute_static_summary
    print("\n" + "=" * 70)
    print("RECOMPUTING FINAL SUMMARY WITH SEPARATED NOISE")
    print("=" * 70)
    import recompute_static_summary
    recompute_static_summary.main()

if __name__ == '__main__':
    main()
