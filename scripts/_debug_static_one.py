import sqlite3
import subprocess
import os
import sys
import tempfile
import json
import csv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Test 1: Flawfinder on C files that have known patterns
c_rows = c.execute("""
    SELECT f.program_id, r.file_content 
    FROM raw_files r 
    JOIN filtered_files f ON r.id = f.raw_file_id 
    WHERE f.stage1 = 'PASSED' AND r.language = 'C' 
    LIMIT 10
""").fetchall()

print(f"Testing Flawfinder on {len(c_rows)} C files...")
c_findings = 0
for pid, content in c_rows:
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False, encoding='utf-8') as tf:
        tf.write(content)
        tname = tf.name
    res = subprocess.run(['flawfinder', '--csv', tname], capture_output=True, text=True)
    if res.stdout:
        reader = csv.DictReader(res.stdout.strip().splitlines())
        for row in reader:
            c_findings += 1
            print(f"  [{pid}] Line {row.get('Line')}: Rule={row.get('Name')}, CWE={row.get('CWEs')}, Level={row.get('Level')}")
    os.remove(tname)

print(f"Total Flawfinder findings across 10 files: {c_findings}")

# Test 2: Bandit on Python files
py_rows = c.execute("""
    SELECT f.program_id, r.file_content 
    FROM raw_files r 
    JOIN filtered_files f ON r.id = f.raw_file_id 
    WHERE f.stage1 = 'PASSED' AND r.language = 'Python' 
    LIMIT 10
""").fetchall()

print(f"\nTesting Bandit on {len(py_rows)} Python files...")
py_findings = 0
for pid, content in py_rows:
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False, encoding='utf-8') as tf:
        tf.write(content)
        tname = tf.name
    res = subprocess.run([sys.executable, '-m', 'bandit', '-f', 'json', tname], capture_output=True, text=True)
    if res.stdout:
        try:
            data = json.loads(res.stdout)
            for item in data.get('results', []):
                py_findings += 1
                print(f"  [{pid}] Line {item.get('line_number')}: Test={item.get('test_id')}, CWE={item.get('issue_cwe')}")
        except Exception as e:
            print("Bandit json parse error:", e)
    os.remove(tname)

print(f"Total Bandit findings across 10 files: {py_findings}")

conn.close()
