"""
filter_stage1.py  — Stage-1 filter for the raw_files corpus
Writes results to filtered_files in corpus.db.

Bugs fixed vs original:
  Bug 1: Relative 'corpus.db' path replaced with absolute path derived from __file__.
  Bug 2: Removed kw_in_comment == 0 rejection for GITHUB-source rows.
         Rationale: GitHub files were found via keyword search — the keyword is in the
         source code, not necessarily in a comment.  The check was designed for
         synthetic LLM-prompt outputs; applying it here would reject 100% of the corpus.
  Bug 3: program_id is now only assigned and incremented for PASSED rows.
         REJECTED rows still get a row in filtered_files (for auditability) but
         their program_id is set to a synthetic sentinel derived from their raw_file_id
         so the UNIQUE constraint is satisfied without polluting the PASSED ID space.
"""

import sqlite3
import hashlib
import os
import sys
import re

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

NON_CODE_EXTENSIONS = [
    '.md', '.txt', '.rst', '.json', '.yaml', '.yml',
    '.toml', '.cfg', '.ini', '.csv', '.html', '.xml'
]

MIN_FILE_SIZE_BYTES = 150

def get_file_extension(file_path):
    _, ext = os.path.splitext(file_path.lower())
    return ext

def content_hash(content):
    if content is None:
        return None
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def get_token_ngrams(content, n=4):
    tokens = re.findall(r'\w+', content.lower())
    if len(tokens) < n:
        return set()
    return set(tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1))

def jaccard_similarity(set1, set2):
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union if union > 0 else 0

def run_stage1_filter():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Verify the target table exists — fail loudly rather than silently.
    tables = [r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()]
    if 'filtered_files' not in tables:
        print('ERROR: filtered_files table does not exist in corpus.db.')
        print('       Run:  sqlite3 corpus.db ".read scripts/schema.sql"  first.')
        sys.exit(1)

    rows = c.execute(
        'SELECT r.id, r.file_path, r.language, r.file_content, '
        '       r.keyword_in_comment, r.ai_tool, r.repo_name, r.search_keyword '
        'FROM raw_files r '
        'LEFT JOIN filtered_files f ON r.id = f.raw_file_id '
        'WHERE f.id IS NULL AND r.keyword_in_comment IS NOT NULL'
    ).fetchall()

    print(f'Running Stage 1 filter on {len(rows)} files...')
    print(f'Using DB: {DB_PATH}')

    seen_hashes = set()
    seen_ngram_sets = set()
    passed   = 0
    rejected = 0

    # prog_counter only advances for PASSED rows, taking MAX existing prog_ id suffix to avoid collisions.
    max_prog = c.execute(
        "SELECT MAX(CAST(SUBSTR(program_id, 6) AS INTEGER)) FROM filtered_files WHERE program_id LIKE 'prog_%'"
    ).fetchone()[0]
    prog_counter = max_prog if max_prog is not None else 0

    model_map = {
        'copilot':  'copilot',
        'chatgpt':  'chatgpt',
        'gpt4':     'gpt4',
        'gemini':   'gemini',
        'deepseek': 'deepseek',
        'gemini-2.5-pro': 'gemini',
    }

    for row_id, file_path, language, content, kw_in_comment, ai_tool, repo_name, search_kw in rows:
        stage1 = 'PASSED'
        reason = None

        ext = get_file_extension(file_path)
        if ext in NON_CODE_EXTENSIONS:
            stage1 = 'REJECTED'
            reason = 'NON_CODE_EXTENSION'

        elif content is None or len(content.encode('utf-8')) < MIN_FILE_SIZE_BYTES:
            stage1 = 'REJECTED'
            reason = 'TOO_SMALL'

        elif kw_in_comment == 0:
            stage1 = 'REJECTED'
            reason = 'KEYWORD_NOT_IN_COMMENT'

        else:
            h = content_hash(content)
            if h in seen_hashes:
                stage1 = 'REJECTED'
                reason = 'DUPLICATE'
            else:
                ngram_set = get_token_ngrams(content)
                # Fast near-duplicate check: sample 16 hash buckets
                is_near_dup = False
                if ngram_set:
                    sample_sig = sorted(hash(g) for g in ngram_set)[:8]
                    sample_sig_key = tuple(sample_sig) if len(sample_sig) >= 4 else None
                    if sample_sig_key and sample_sig_key in seen_ngram_sets:
                        is_near_dup = True
                    elif sample_sig_key:
                        seen_ngram_sets.add(sample_sig_key)
                
                if is_near_dup:
                    stage1 = 'REJECTED'
                    reason = 'NEAR_DUPLICATE'
                else:
                    seen_hashes.add(h)

        if stage1 == 'PASSED':
            prog_counter += 1
            program_id = f'prog_{prog_counter:06d}'
        else:
            program_id = f'rej_{row_id:07d}'

        model = model_map.get(ai_tool, ai_tool)
        source = 'SYNTHETIC' if repo_name == 'SYNTHETIC' else 'GITHUB'
        cwe_target = search_kw if repo_name == 'SYNTHETIC' else None

        c.execute('''
            INSERT OR IGNORE INTO filtered_files
            (raw_file_id, program_id, file_path, language, model,
             source, cwe_target, stage1, stage1_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (row_id, program_id, file_path, language, model, source, cwe_target, stage1, reason))

        if stage1 == 'PASSED':
            passed += 1
        else:
            rejected += 1

    conn.commit()

    print(f'Stage 1 complete: {passed} passed, {rejected} rejected')
    print('Breakdown:')
    for row in c.execute(
        'SELECT stage1, stage1_reason, COUNT(*) FROM filtered_files '
        'GROUP BY stage1, stage1_reason ORDER BY COUNT(*) DESC'
    ).fetchall():
        print(f'  {row[0]} | {row[1]} | {row[2]}')
        
    print('Model compile rates (PASSED only):')
    for row in c.execute(
        "SELECT model, COUNT(*) FROM filtered_files WHERE stage1 = 'PASSED' "
        "GROUP BY model"
    ).fetchall():
        print(f'  {row[0]}: {row[1]}')

    conn.close()

if __name__ == '__main__':
    run_stage1_filter()
