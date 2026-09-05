"""
_schema_diff.py — SELECT only, no writes.
Compares:
  1. Columns defined in schema.sql for raw_files
  2. Columns that actually exist in the live corpus.db raw_files table
     (via PRAGMA table_info)
Also reports keyword_in_comment coverage to answer whether
verify_comment_location.py has ever been run.
"""
import sqlite3
import re
import os

SCRIPTS_DIR = os.path.dirname(__file__)
BASE_DIR    = os.path.abspath(os.path.join(SCRIPTS_DIR, '..'))
DB_PATH     = os.path.join(BASE_DIR, 'corpus.db')
SCHEMA_PATH = os.path.join(SCRIPTS_DIR, 'schema.sql')

# ── 1. Parse raw_files columns from schema.sql ──────────────────────────────
with open(SCHEMA_PATH, 'r') as f:
    sql = f.read()

# Extract the raw_files CREATE TABLE block
m = re.search(
    r'CREATE TABLE IF NOT EXISTS raw_files\s*\((.*?)\);',
    sql, re.DOTALL | re.IGNORECASE
)
if not m:
    print("ERROR: Could not find raw_files CREATE TABLE in schema.sql")
    raise SystemExit(1)

block = m.group(1)
schema_cols = {}
for line in block.strip().splitlines():
    line = line.strip().rstrip(',')
    if not line or line.upper().startswith('UNIQUE') or line.upper().startswith('PRIMARY'):
        continue
    parts = line.split()
    if len(parts) >= 2:
        col_name = parts[0]
        col_type = parts[1].upper()
        schema_cols[col_name] = col_type

# ── 2. Read live table columns via PRAGMA ───────────────────────────────────
conn = sqlite3.connect(DB_PATH)
c    = conn.cursor()

live_rows = c.execute('PRAGMA table_info(raw_files)').fetchall()
# PRAGMA table_info columns: cid, name, type, notnull, dflt_value, pk
live_cols = {r[1]: r[2].upper() for r in live_rows}

# ── 3. Print side-by-side diff ──────────────────────────────────────────────
all_names = sorted(set(list(schema_cols.keys()) + list(live_cols.keys())))

print('=== raw_files column diff: schema.sql  vs  live corpus.db ===')
print(f'{"Column":<25} {"schema.sql":<20} {"live DB":<20} {"Status"}')
print('-' * 75)
mismatches = []
schema_only = []
live_only   = []
for col in all_names:
    in_schema = schema_cols.get(col)
    in_live   = live_cols.get(col)
    if in_schema and in_live:
        status = 'OK' if in_schema == in_live else 'TYPE MISMATCH'
        if status != 'OK':
            mismatches.append(col)
    elif in_schema and not in_live:
        status = '⚠ SCHEMA ONLY (missing from live DB)'
        schema_only.append(col)
    else:
        status = '⚠ LIVE ONLY (not in schema.sql)'
        live_only.append(col)
    print(f'{col:<25} {str(in_schema or "—"):<20} {str(in_live or "—"):<20} {status}')

print()
print('=== Summary ===')
print(f'  Matching columns   : {len(all_names) - len(mismatches) - len(schema_only) - len(live_only)}')
print(f'  Type mismatches    : {mismatches or "none"}')
print(f'  Schema-only (gap!) : {schema_only or "none"}')
print(f'  Live-only (extra)  : {live_only or "none"}')

# ── 4. keyword_in_comment coverage ──────────────────────────────────────────
print()
print('=== keyword_in_comment value distribution (has verify_comment_location.py run?) ===')
if 'keyword_in_comment' not in live_cols:
    print('  Column does not exist in live DB!')
else:
    for row in c.execute(
        'SELECT keyword_in_comment, COUNT(*) FROM raw_files '
        'GROUP BY keyword_in_comment ORDER BY keyword_in_comment'
    ).fetchall():
        print(f'  keyword_in_comment = {row[0]}  →  {row[1]} rows')
    total = c.execute('SELECT COUNT(*) FROM raw_files').fetchone()[0]
    null_count = c.execute(
        'SELECT COUNT(*) FROM raw_files WHERE keyword_in_comment IS NULL'
    ).fetchone()[0]
    one_count  = c.execute(
        'SELECT COUNT(*) FROM raw_files WHERE keyword_in_comment = 1'
    ).fetchone()[0]
    print()
    print(f'  Total rows : {total}')
    print(f'  NULL       : {null_count}   (collector never touched this row)')
    print(f'  = 1 (kw in comment found) : {one_count}')
    print(f'  = 0 (kw not in comment)   : {total - null_count - one_count}')
    if one_count == 0 and null_count == 0:
        print()
        print('  VERDICT: All rows are 0. verify_comment_location.py has NEVER been run.')
        print('           The collector sets keyword_in_comment=0 as a placeholder default.')
    elif one_count > 0:
        print()
        print('  VERDICT: Some rows = 1 → verify_comment_location.py has been run (at least partially).')
    elif null_count > 0 and one_count == 0:
        print()
        print('  VERDICT: Mix of NULL and 0. NULL = old collector rows (no column written).')
        print('           0 = new collector rows (default placeholder). Neither = real parsed value.')

conn.close()
