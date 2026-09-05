"""
verify_comment_location.py  (REAL UPDATE VERSION)
--------------------------------------------------
Writes keyword_in_comment = 1 or 0 to every row in raw_files
based on whether the AI tool name actually appears inside a comment.

Bugs fixed vs original:
  Bug A: Relative 'corpus.db' path -> absolute via __file__.
  Bug B: JavaScript fell into 'else: # C Language' branch (same fix
         as dry-run: JS uses identical // and /* */ comment syntax,
         so keyword_in_c_comment is correct — but now explicitly
         labelled, and any truly unknown language is handled separately).
  Bug C: Original WHERE clause was 'IS NULL', but collector writes 0
         for every new row as a placeholder. Changed to process ALL
         rows (WHERE keyword_in_comment = 0 OR keyword_in_comment IS NULL)
         so existing 0-placeholder rows are overwritten with real values.

Run the dry-run (verify_comment_location_dryrun.py) first to preview
projected 1-vs-0 counts before executing this script.
"""

import sqlite3
import re
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')


# ── Comment-detection logic (unchanged from dry-run) ─────────────────────── #

def keyword_in_python_comment(content, keyword):
    """True if keyword appears inside a Python comment."""
    import io
    import tokenize
    kw = keyword.lower()
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for tok in tokens:
            if tok.type == tokenize.COMMENT:
                if kw in tok.string.lower():
                    return True
    except (tokenize.TokenError, Exception):
        # Fallback to line-by-line comment parsing if tokenization fails
        for line in content.splitlines():
            if '#' in line:
                idx = line.index('#')
                comment_part = line[idx:]
                if kw in comment_part.lower():
                    return True
    return False


def keyword_in_c_comment(content, keyword):
    """True if keyword appears inside a C/JS // or /* */ comment."""
    kw = keyword.lower()
    for line in content.splitlines():
        stripped = line.strip()
        if '//' in stripped:
            comment_part = stripped[stripped.index('//') + 2:]
            if kw in comment_part.lower():
                return True
    for match in re.finditer(r'/\*.*?\*/', content, re.DOTALL):
        if kw in match.group().lower():
            return True
    return False


def verify_all_files(lang_filter=None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')   # allow concurrent readers during UPDATE
    c = conn.cursor()

    # Process rows where keyword_in_comment is still the placeholder (0 or NULL).
    # Rows already set to 1 (e.g. future SYNTHETIC rows) are left untouched.
    query = (
        'SELECT id, language, file_content, search_keyword '
        'FROM raw_files '
        'WHERE (keyword_in_comment = 0 OR keyword_in_comment IS NULL)'
    )
    if lang_filter:
        query += f" AND language = '{lang_filter}'"
    rows = c.execute(query).fetchall()

    total = len(rows)
    if lang_filter:
        print(f'Processing {total} rows from {DB_PATH} (filtered to language={lang_filter})')
    else:
        print(f'Processing {total} rows from {DB_PATH}')

    confirmed = 0
    rejected  = 0
    skipped   = 0   # content is None or language unknown

    by_lang = {}
    by_tool = {}

    for row_id, language, content, keyword in rows:
        if content is None:
            result = 0
            skipped += 1
        elif language == 'Python':
            result = 1 if keyword_in_python_comment(content, keyword) else 0
        elif language in ('C', 'JavaScript'):
            result = 1 if keyword_in_c_comment(content, keyword) else 0
        else:
            result = 0
            skipped += 1

        c.execute(
            'UPDATE raw_files SET keyword_in_comment = ? WHERE id = ?',
            (result, row_id)
        )

        if result == 1:
            confirmed += 1
        else:
            rejected += 1

        # Track breakdown
        by_lang[language] = by_lang.get(language, {'pass': 0, 'fail': 0})
        by_tool[keyword]  = by_tool.get(keyword,  {'pass': 0, 'fail': 0})
        key = 'pass' if result == 1 else 'fail'
        by_lang[language][key] += 1
        by_tool[keyword][key]  += 1

        # Commit in batches to avoid long-held write locks
        if (confirmed + rejected) % 500 == 0:
            conn.commit()
            print(f'  ... {confirmed + rejected}/{total} processed '
                  f'({confirmed} pass, {rejected} fail so far)')

    conn.commit()
    conn.close()

    print()
    print(f'=== keyword_in_comment UPDATE complete ===')
    print(f'  Total processed : {total}')
    print(f'  Set to 1 (pass) : {confirmed}')
    print(f'  Set to 0 (fail) : {rejected}')
    print(f'  Skipped (None/unknown lang): {skipped}')
    print()
    print('BY LANGUAGE')
    print(f'  {"Language":<14} {"Pass":>6} {"Fail":>6} {"Total":>7} {"Pass%":>7}')
    print(f'  {"-"*14} {"-"*6} {"-"*6} {"-"*7} {"-"*7}')
    for lang in sorted(by_lang):
        p = by_lang[lang]['pass']
        f = by_lang[lang]['fail']
        t = p + f
        pct = (p / t * 100) if t else 0
        print(f'  {lang:<14} {p:>6} {f:>6} {t:>7} {pct:>6.1f}%')
    print()
    print('BY AI_TOOL (search_keyword)')
    print(f'  {"ai_tool":<14} {"Pass":>6} {"Fail":>6} {"Total":>7} {"Pass%":>7}')
    print(f'  {"-"*14} {"-"*6} {"-"*6} {"-"*7} {"-"*7}')
    for tool in sorted(by_tool):
        p = by_tool[tool]['pass']
        f = by_tool[tool]['fail']
        t = p + f
        pct = (p / t * 100) if t else 0
        print(f'  {tool:<14} {p:>6} {f:>6} {t:>7} {pct:>6.1f}%')


if __name__ == '__main__':
    print('This script writes UPDATE statements to corpus.db.')
    print('Run verify_comment_location_dryrun.py first to preview.')
    print()
    lang = None
    if len(sys.argv) > 1 and sys.argv[1] == '--python-only':
        lang = 'Python'
    verify_all_files(lang)