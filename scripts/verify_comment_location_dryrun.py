"""
verify_comment_location_dryrun.py
----------------------------------
DRY-RUN ONLY — SELECT and COUNT, zero writes to the DB.

Simulates what verify_comment_location.py would do if run for real,
showing the projected keyword_in_comment = 1 vs 0 breakdown by
language and by ai_tool.

Bugs fixed vs original verify_comment_location.py:
  Bug A: Relative 'corpus.db' path -> absolute path via __file__.
  Bug B: JavaScript fell into 'else: # C Language' branch.
         JavaScript uses the same comment syntax as C (// and /* */),
         so keyword_in_c_comment() is functionally correct for JS —
         but it was unlabelled. Added explicit elif for JavaScript
         so the intent is clear and any future language added won't
         silently misroute.
  Bug C (new): Original WHERE clause was 'IS NULL', but the collector
         writes 0 for every row at insert time, so IS NULL matches
         nothing. Dry-run processes all rows unconditionally so you
         can see the true pass rate.
"""

import sqlite3
import re
import os
from collections import defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')


# ── Comment-detection logic (unchanged from original) ────────────────────── #

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
    """True if keyword appears inside a C // or /* */ comment."""
    kw = keyword.lower()

    # Single-line // comments
    for line in content.splitlines():
        stripped = line.strip()
        if '//' in stripped:
            comment_part = stripped[stripped.index('//') + 2:]
            if kw in comment_part.lower():
                return True

    # Multi-line /* ... */ comments
    for match in re.finditer(r'/\*.*?\*/', content, re.DOTALL):
        if kw in match.group().lower():
            return True

    return False


def would_be_confirmed(language, content, keyword):
    """
    Returns True (would set keyword_in_comment=1) or False (would set 0).
    Mirrors the logic verify_comment_location.py would apply.
    """
    if content is None:
        return False
    if language == 'Python':
        return keyword_in_python_comment(content, keyword)
    elif language in ('C', 'JavaScript'):
        # JS uses identical comment syntax to C (// and /* */)
        return keyword_in_c_comment(content, keyword)
    else:
        # Unknown language — conservative: treat as not confirmed
        return False


# ── Main dry-run ─────────────────────────────────────────────────────────── #

def run_dryrun():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # Process ALL rows — not just IS NULL — because the collector writes 0
    # as a placeholder for every row at insert time (no row is ever NULL).
    rows = c.execute(
        'SELECT id, language, file_content, search_keyword, ai_tool '
        'FROM raw_files'
    ).fetchall()

    print(f'DRY-RUN: verify_comment_location.py against {len(rows)} rows')
    print(f'DB: {DB_PATH}')
    print('(No writes will be made)')
    print()

    # Accumulators
    # by_lang[language]  = {'would_be_1': N, 'would_be_0': N}
    # by_tool[ai_tool]   = {'would_be_1': N, 'would_be_0': N}
    by_lang = defaultdict(lambda: {'would_be_1': 0, 'would_be_0': 0})
    by_tool = defaultdict(lambda: {'would_be_1': 0, 'would_be_0': 0})
    by_lang_tool = defaultdict(lambda: {'would_be_1': 0, 'would_be_0': 0})
    unknown_langs = defaultdict(int)

    total_1 = 0
    total_0 = 0

    for row_id, language, content, keyword, ai_tool in rows:
        if language not in ('C', 'Python', 'JavaScript'):
            unknown_langs[language] += 1

        result = would_be_confirmed(language, content, keyword)
        key = 'would_be_1' if result else 'would_be_0'

        by_lang[language][key]               += 1
        by_tool[ai_tool or 'NULL'][key]      += 1
        by_lang_tool[f'{language}|{ai_tool or "NULL"}'][key] += 1

        if result:
            total_1 += 1
        else:
            total_0 += 1

    conn.close()

    total = total_1 + total_0

    # ── Results ───────────────────────────────────────────────────────────── #

    print('=' * 60)
    print('PROJECTED PASS RATE (keyword_in_comment = 1)')
    print('=' * 60)
    pct = (total_1 / total * 100) if total else 0
    print(f'  Would be 1 (pass) : {total_1:>5}  ({pct:.1f}%)')
    print(f'  Would be 0 (fail) : {total_0:>5}  ({100-pct:.1f}%)')
    print(f'  Total processed   : {total:>5}')

    print()
    print('BY LANGUAGE')
    print('-' * 55)
    print(f'  {"Language":<14} {"Would=1":>8} {"Would=0":>8} {"Total":>7} {"Pass%":>7}')
    print(f'  {"-"*14} {"-"*8} {"-"*8} {"-"*7} {"-"*7}')
    for lang in sorted(by_lang):
        w1 = by_lang[lang]['would_be_1']
        w0 = by_lang[lang]['would_be_0']
        t  = w1 + w0
        p  = (w1 / t * 100) if t else 0
        print(f'  {lang:<14} {w1:>8} {w0:>8} {t:>7} {p:>6.1f}%')

    print()
    print('BY AI_TOOL (search_keyword used during collection)')
    print('-' * 55)
    print(f'  {"ai_tool":<14} {"Would=1":>8} {"Would=0":>8} {"Total":>7} {"Pass%":>7}')
    print(f'  {"-"*14} {"-"*8} {"-"*8} {"-"*7} {"-"*7}')
    for tool in sorted(by_tool):
        w1 = by_tool[tool]['would_be_1']
        w0 = by_tool[tool]['would_be_0']
        t  = w1 + w0
        p  = (w1 / t * 100) if t else 0
        print(f'  {tool:<14} {w1:>8} {w0:>8} {t:>7} {p:>6.1f}%')

    print()
    print('CROSS-TAB: LANGUAGE x AI_TOOL  (would_be_1 / total)')
    langs = sorted(by_lang.keys())
    tools = sorted(by_tool.keys())
    col_w = 18
    # header row
    hdr = f'  {"language":<14}' + ''.join(f'{t:<{col_w}}' for t in tools)
    print(hdr)
    print('  ' + '-' * (14 + col_w * len(tools)))
    for lang in langs:
        row_str = f'  {lang:<14}'
        for tool in tools:
            k = f'{lang}|{tool}'
            if k in by_lang_tool:
                w1 = by_lang_tool[k]['would_be_1']
                tot = w1 + by_lang_tool[k]['would_be_0']
                pct = (w1 / tot * 100) if tot else 0
                cell = f'{w1}/{tot} ({pct:.0f}%)'
            else:
                cell = '---'
            row_str += f'{cell:<{col_w}}'
        print(row_str)

    if unknown_langs:
        print()
        print('WARNING: Unknown language(s) found (treated as would_be_0):')
        for lang, cnt in unknown_langs.items():
            print(f'  {lang}: {cnt} rows')

    print()
    print('NOTE: These are projected values only.')
    print('Run verify_comment_location.py (real version) to write them to the DB.')


if __name__ == '__main__':
    run_dryrun()
