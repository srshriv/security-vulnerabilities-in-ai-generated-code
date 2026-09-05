"""
filter_stage1_pure.py
---------------------
100% Empirical, zero-calibration Stage 1 filter for corpus.db.
Applies pure data cleaning:
  - Discards non-code extensions (.md, .json, .txt, .html, .csv, etc.)
  - Discards files < 100 bytes or HTML wrappers
  - Discards exact SHA-256 duplicate code files
  - Populates filtered_files strictly from real database rows.
"""

import os
import sys
import sqlite3
import hashlib

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

NON_CODE_EXTENSIONS = {
    '.md', '.txt', '.rst', '.json', '.yaml', '.yml',
    '.toml', '.cfg', '.ini', '.csv', '.html', '.xml', '.svg'
}

def content_hash(content):
    if not content:
        return None
    return hashlib.sha256(content.strip().encode('utf-8')).hexdigest()

def run_pure_stage1():
    print("=" * 70)
    print("RUNNING 100% EMPIRICAL STAGE 1 FILTER")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Clear previous filtered_files to build clean empirical set
    cur.execute("DELETE FROM filtered_files")
    conn.commit()

    cur.execute("""
        SELECT id, file_path, language, file_content, ai_tool, repo_name, search_keyword
        FROM raw_files
        ORDER BY id ASC
    """)
    rows = cur.fetchall()
    print(f"Total raw files to evaluate: {len(rows)}")

    seen_hashes = set()
    passed = 0
    rejected = 0
    prog_counter = 0

    model_alias = {
        'copilot': 'copilot',
        'chatgpt': 'chatgpt',
        'gpt4': 'gpt4',
        'gpt-4': 'gpt4',
        'gemini': 'gemini',
        'gemini-2.5-pro': 'gemini',
        'gemini-flash': 'gemini-flash',
        'deepseek': 'deepseek',
        'deepseek-coder': 'deepseek-coder',
        'claude': 'claude',
        'tabnine': 'tabnine',
        'codeium': 'codeium'
    }

    for row_id, file_path, language, content, ai_tool, repo_name, search_kw in rows:
        _, ext = os.path.splitext(file_path.lower()) if file_path else ('', '')
        
        stage1 = 'PASSED'
        reason = None

        if ext in NON_CODE_EXTENSIONS:
            stage1 = 'REJECTED'
            reason = 'NON_CODE_EXTENSION'
        elif not content or len(content.strip().encode('utf-8')) < 100:
            stage1 = 'REJECTED'
            reason = 'TOO_SMALL'
        elif content.strip()[:100].lower().startswith(('<!doctype', '<html')):
            stage1 = 'REJECTED'
            reason = 'HTML_PAGE'
        else:
            h = content_hash(content)
            if h in seen_hashes:
                stage1 = 'REJECTED'
                reason = 'EXACT_DUPLICATE'
            else:
                seen_hashes.add(h)

        if stage1 == 'PASSED':
            prog_counter += 1
            program_id = f"prog_{prog_counter:06d}"
            passed += 1
        else:
            program_id = f"rej_{row_id:07d}"
            rejected += 1

        model = model_alias.get(ai_tool.lower() if ai_tool else '', ai_tool or 'unknown')
        source = 'SYNTHETIC' if (repo_name and repo_name.startswith('SYNTHETIC')) else 'GITHUB'
        cwe_target = search_kw if source == 'SYNTHETIC' else None

        cur.execute("""
            INSERT INTO filtered_files
            (raw_file_id, program_id, file_path, language, model, source, cwe_target, stage1, stage1_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (row_id, program_id, file_path, language, model, source, cwe_target, stage1, reason))

    conn.commit()
    print(f"\nStage 1 Filtering Complete:")
    print(f"  PASSED (Unique Code Files): {passed}")
    print(f"  REJECTED (Duplicates / Non-code): {rejected}")
    
    print("\nPassed programs by language:")
    for r in cur.execute("SELECT language, count(*) FROM filtered_files WHERE stage1='PASSED' GROUP BY language").fetchall():
        print(f"  - {r[0]}: {r[1]} files")
        
    print("\nPassed programs by model:")
    for r in cur.execute("SELECT model, count(*) FROM filtered_files WHERE stage1='PASSED' GROUP BY model").fetchall():
        print(f"  - {r[0]}: {r[1]} files")

    conn.close()

if __name__ == '__main__':
    run_pure_stage1()
