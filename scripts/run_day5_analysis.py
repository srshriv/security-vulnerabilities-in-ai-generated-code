"""
run_day5_analysis.py  — Day 5 Unified Static & Formal Analysis Pipeline
-----------------------------------------------------------------------
Executes Student A (Formal / CBMC) and Student B (Static Tools: Bandit,
Flawfinder, ESLint, Semgrep) analysis on stage1 'PASSED' files, then
ingests all findings into `static_results` and `formal_results` in `corpus.db`.
"""

import os
import sys
import sqlite3
import subprocess
import shutil
import json
import csv
import glob
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')
STATIC_DIR = os.path.join(BASE_DIR, 'results', 'static_raw')
CBMC_DIR = os.path.join(BASE_DIR, 'results', 'cbmc_out')
HARNESS_DIR = os.path.join(BASE_DIR, 'results', 'asan_harnesses')
CORRECTIONS_FILE = os.path.join(BASE_DIR, 'scripts', 'bandit_cwe_corrections.json')

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(CBMC_DIR, exist_ok=True)
os.makedirs(HARNESS_DIR, exist_ok=True)

# Ensure local bin is on PATH for Linux/WSL
home_local_bin = os.path.expanduser('~/.local/bin')
if home_local_bin not in os.environ.get('PATH', ''):
    os.environ['PATH'] = f"{home_local_bin}:{os.environ.get('PATH', '')}"

def run_cmd(cmd_list, timeout=45):
    """Run tool command."""
    try:
        res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout, res.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return 1, "", str(e)

# ---------------------------------------------------------------------------
# Student B: Static Analysis Runners
# ---------------------------------------------------------------------------

def scan_bandit(pid: str, src_path: str) -> str:
    out_json = os.path.join(STATIC_DIR, f'bandit_{pid}.json')
    cmd = ['bandit', '-f', 'json', src_path] if shutil.which('bandit') else [sys.executable, '-m', 'bandit', '-f', 'json', src_path]
    ret, out, err = run_cmd(cmd, timeout=30)
    if out:
        with open(out_json, 'w', encoding='utf-8') as f:
            f.write(out)
        return out_json
    return None

def scan_flawfinder(pid: str, src_path: str) -> str:
    out_csv = os.path.join(STATIC_DIR, f'flawfinder_{pid}.csv')
    ret, out, err = run_cmd(['flawfinder', '--csv', src_path], timeout=30)
    if out:
        with open(out_csv, 'w', encoding='utf-8') as f:
            f.write(out)
        return out_csv
    return None

def scan_eslint(pid: str, src_path: str) -> str:
    out_json = os.path.join(STATIC_DIR, f'eslint_{pid}.json')
    # Run ESLint (default config if none in dir)
    ret, out, err = run_cmd(['eslint', '--no-eslintrc', '--env', 'browser,node,es6',
                            '--rule', '{"no-eval": "error", "no-implied-eval": "error", "no-new-func": "error", "no-prototype-builtins": "warn"}',
                            '--format', 'json', src_path], timeout=30)
    if not out and shutil.which('eslint'):
        ret, out, err = run_cmd(['eslint', '--format', 'json', src_path], timeout=30)
    if out:
        with open(out_json, 'w', encoding='utf-8') as f:
            f.write(out)
        return out_json
    return None

def scan_semgrep(pid: str, src_path: str) -> str:
    out_json = os.path.join(STATIC_DIR, f'semgrep_{pid}.json')
    ret, out, err = run_cmd(['semgrep', '--config=p/security-audit', '--json', src_path], timeout=40)
    if out:
        with open(out_json, 'w', encoding='utf-8') as f:
            f.write(out)
        return out_json
    return None

# ---------------------------------------------------------------------------
# Student A: Formal Verification (CBMC) Runner
# ---------------------------------------------------------------------------

def scan_cbmc(pid: str, src_path: str, unwind: int = 10) -> str:
    out_xml = os.path.join(CBMC_DIR, f'{pid}.xml')
    cmd = ['cbmc', src_path, '--unwind', str(unwind),
           '--xml-ui', '--bounds-check', '--signed-overflow-check',
           '--pointer-check', '--div-by-zero-check', '--trace']
    ret, out, err = run_cmd(cmd, timeout=35)
    content = out or err or ""
    if content:
        with open(out_xml, 'w', encoding='utf-8') as f:
            f.write(content)
        return out_xml
    return None

# ---------------------------------------------------------------------------
# Ingestion Functions
# ---------------------------------------------------------------------------

def ingest_all_static():
    """Run ingestion scripts to populate static_results in corpus.db."""
    print("\n--- Ingesting Static Analysis Findings into corpus.db ---")
    sys.path.insert(0, os.path.join(BASE_DIR, 'scripts'))
    
    # 1. Ingest Bandit
    print("\n1. Ingesting Bandit findings...")
    try:
        import ingest_bandit
        ingest_bandit.run(batch=True)
    except Exception as e:
        print(f"Error ingesting Bandit: {e}")

    # 2. Ingest ESLint
    print("\n2. Ingesting ESLint findings...")
    try:
        import ingest_eslint
        ingest_eslint.run()
    except Exception as e:
        print(f"Error ingesting ESLint: {e}")

    # 3. Ingest Semgrep JSON
    print("\n3. Ingesting Semgrep findings...")
    try:
        ingest_semgrep_custom()
    except Exception as e:
        print(f"Error ingesting Semgrep: {e}")

    # 4. Ingest Flawfinder
    print("\n4. Ingesting Flawfinder findings...")
    try:
        ingest_flawfinder_csvs()
    except Exception as e:
        print(f"Error ingesting Flawfinder: {e}")

def ingest_flawfinder_csvs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    csv_files = glob.glob(os.path.join(STATIC_DIR, 'flawfinder_*.csv'))
    
    inserted = 0
    for csv_file in csv_files:
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    file_path = row.get('File', '')
                    line_no = int(row.get('Line', 0) or 0)
                    rule_id = row.get('Category', '') or row.get('Name', 'flawfinder')
                    severity = row.get('Level', 'MEDIUM')
                    cwe_raw = row.get('CWEs', '')
                    
                    cwe_match = re.search(r'CWE-\d+', cwe_raw, re.IGNORECASE)
                    cwe = cwe_match.group(0).upper() if cwe_match else 'UNCATEGORIZED'
                    
                    pid_match = re.search(r'flawfinder_(prog_\d+)', os.path.basename(csv_file))
                    if pid_match:
                        program_id = pid_match.group(1)
                    else:
                        r = c.execute("SELECT program_id FROM filtered_files WHERE file_path LIKE ? LIMIT 1", (f"%{os.path.basename(file_path)}",)).fetchone()
                        program_id = r[0] if r else None
                        
                    if not program_id:
                        continue
                        
                    existing = c.execute("""
                        SELECT id, tool_count FROM static_results
                        WHERE program_id = ? AND file_path = ? AND line_number = ? AND rule_id = ? AND cwe = ?
                    """, (program_id, file_path, line_no, rule_id, cwe)).fetchone()
                    
                    if existing:
                        c.execute("UPDATE static_results SET tool_count = tool_count + 1 WHERE id = ?", (existing[0],))
                    else:
                        c.execute("""
                            INSERT INTO static_results (program_id, file_path, line_number, rule_id, cwe, severity, tool, tool_count)
                            VALUES (?, ?, ?, ?, ?, ?, 'Flawfinder', 1)
                        """, (program_id, file_path, line_no, rule_id, cwe, severity))
                        inserted += 1
        except Exception:
            continue
            
    conn.commit()
    conn.close()
    print(f"Flawfinder: {inserted} findings inserted.")

def ingest_semgrep_custom():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    semgrep_files = glob.glob(os.path.join(STATIC_DIR, 'semgrep_*.json'))
    
    inserted = 0
    for sfile in semgrep_files:
        try:
            with open(sfile, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                
            pid_match = re.search(r'semgrep_(prog_\d+)', os.path.basename(sfile))
            default_pid = pid_match.group(1) if pid_match else None
            
            for res in data.get('results', []):
                rule_id = res.get('check_id', 'UNKNOWN')
                path = res.get('path', '')
                line_no = res.get('start', {}).get('line', 0)
                extra = res.get('extra', {})
                severity = extra.get('severity', 'WARNING').upper()
                
                metadata = extra.get('metadata', {})
                cwe_list = metadata.get('cwe', [])
                if isinstance(cwe_list, list) and cwe_list:
                    cwe = cwe_list[0]
                    m = re.search(r'CWE-\d+', cwe, re.IGNORECASE)
                    cwe = m.group(0).upper() if m else 'UNCATEGORIZED'
                elif isinstance(cwe_list, str):
                    m = re.search(r'CWE-\d+', cwe_list, re.IGNORECASE)
                    cwe = m.group(0).upper() if m else 'UNCATEGORIZED'
                else:
                    cwe = 'UNCATEGORIZED'
                    
                program_id = default_pid
                if not program_id:
                    r = c.execute("SELECT program_id FROM filtered_files WHERE file_path LIKE ? LIMIT 1", (f"%{os.path.basename(path)}",)).fetchone()
                    program_id = r[0] if r else None
                if not program_id:
                    continue
                    
                existing = c.execute("""
                    SELECT id, tool_count FROM static_results
                    WHERE program_id = ? AND file_path = ? AND line_number = ? AND rule_id = ? AND cwe = ?
                """, (program_id, path, line_no, rule_id, cwe)).fetchone()
                
                if existing:
                    c.execute("UPDATE static_results SET tool_count = tool_count + 1 WHERE id = ?", (existing[0],))
                else:
                    c.execute("""
                        INSERT INTO static_results (program_id, file_path, line_number, rule_id, cwe, severity, tool, tool_count)
                        VALUES (?, ?, ?, ?, ?, ?, 'Semgrep', 1)
                    """, (program_id, path, line_no, rule_id, cwe, severity))
                    inserted += 1
        except Exception:
            continue
            
    conn.commit()
    conn.close()
    print(f"Semgrep: {inserted} findings inserted.")

def ingest_formal_and_harnesses():
    """Parse CBMC XMLs and generate ASAN harnesses."""
    print("\n--- Student A: Parsing CBMC XML & Generating ASAN Harnesses ---")
    sys.path.insert(0, os.path.join(BASE_DIR, 'scripts'))
    try:
        import parse_cbmc_xml
        parse_cbmc_xml.run(xml_dir=CBMC_DIR)
    except Exception as e:
        print(f"Error in parse_cbmc_xml: {e}")

    try:
        import generate_asan_harness
        generate_asan_harness.run()
    except Exception as e:
        print(f"Error in generate_asan_harness: {e}")

# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

def process_file(file_info):
    pid, content, lang = file_info
    ext = '.py' if lang.lower() == 'python' else ('.js' if lang.lower() == 'javascript' else '.c')
    
    tmp_path = os.path.join(STATIC_DIR, f'temp_{pid}{ext}')
    with open(tmp_path, 'w', encoding='utf-8') as f:
        f.write(content or '')
        
    results = {}
    try:
        if lang.lower() == 'python':
            results['bandit'] = scan_bandit(pid, tmp_path)
            results['semgrep'] = scan_semgrep(pid, tmp_path)
        elif lang.lower() == 'javascript':
            results['eslint'] = scan_eslint(pid, tmp_path)
            results['semgrep'] = scan_semgrep(pid, tmp_path)
        elif lang.lower() == 'c':
            results['flawfinder'] = scan_flawfinder(pid, tmp_path)
            results['cbmc'] = scan_cbmc(pid, tmp_path, unwind=10)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    return pid, results

def run_pipeline(limit=None, workers=6):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if limit:
        # Balanced sample across languages
        per_lang = max(1, limit // 3)
        files = []
        for lang in ['C', 'JavaScript', 'Python']:
            q = """
                SELECT f.program_id, r.file_content, r.language
                FROM raw_files r
                JOIN filtered_files f ON r.id = f.raw_file_id
                WHERE f.stage1 = 'PASSED' AND r.language = ?
                LIMIT ?
            """
            cursor.execute(q, (lang, per_lang))
            files.extend(cursor.fetchall())
    else:
        query = """
            SELECT f.program_id, r.file_content, r.language
            FROM raw_files r
            JOIN filtered_files f ON r.id = f.raw_file_id
            WHERE f.stage1 = 'PASSED'
        """
        cursor.execute(query)
        files = cursor.fetchall()
        
    conn.close()
    
    print(f"============================================================")
    print(f"Starting Day 5 Static & Formal Analysis Pipeline")
    print(f"Target files: {len(files)}")
    print(f"Workers: {workers}")
    print(f"============================================================")
    
    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(process_file, f): f[0] for f in files}
        for future in as_completed(futures):
            pid = futures[future]
            completed += 1
            if completed % 10 == 0 or completed == len(files):
                print(f"  Progress: {completed}/{len(files)} files processed ({(completed/len(files))*100:.1f}%)")
                
    print("\nScan phase complete! Now ingesting all results...")
    ingest_all_static()
    ingest_formal_and_harnesses()
    
    # Summary of DB
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    print("\n============================================================")
    print("DAY 5 ANALYSIS SUMMARY IN CORPUS.DB")
    print("============================================================")
    print("static_results count:", c.execute("SELECT count(*) FROM static_results").fetchone()[0])
    for row in c.execute("SELECT tool, count(*) FROM static_results GROUP BY tool").fetchall():
        print(f"  - {row[0]}: {row[1]} findings")
    print("\nformal_results count:", c.execute("SELECT count(*) FROM formal_results").fetchone()[0])
    for row in c.execute("SELECT cbmc_result, count(*) FROM formal_results GROUP BY cbmc_result").fetchall():
        print(f"  - {row[0]}: {row[1]} results")
    conn.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--limit', type=int, default=None, help='Limit number of files to scan')
    parser.add_argument('--workers', type=int, default=6, help='Number of worker threads')
    args = parser.parse_args()
    run_pipeline(limit=args.limit, workers=args.workers)
