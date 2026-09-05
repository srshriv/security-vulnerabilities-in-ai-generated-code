"""Dry-run audit — SELECT only, no writes."""
import sqlite3, os

db = os.path.join(os.path.dirname(__file__), '..', 'corpus.db')
conn = sqlite3.connect(db)
c = conn.cursor()

print('=== Tables in corpus.db ===')
for row in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
    print(f'  {row[0]}')

print()
print('=== raw_files counts by language ===')
for row in c.execute('SELECT language, COUNT(*) FROM raw_files GROUP BY language ORDER BY language').fetchall():
    print(f'  {row[0]}: {row[1]}')

print()
print('=== raw_files: ai_tool distinct values ===')
for row in c.execute('SELECT ai_tool, COUNT(*) FROM raw_files GROUP BY ai_tool ORDER BY ai_tool').fetchall():
    print(f'  ai_tool={repr(row[0])}: {row[1]}')

print()
print('=== raw_files: keyword_in_comment distribution ===')
for row in c.execute('SELECT keyword_in_comment, COUNT(*) FROM raw_files GROUP BY keyword_in_comment').fetchall():
    print(f'  kw_in_comment={row[0]}: {row[1]}')

print()
# Check if filtered_files exists
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
if 'filtered_files' in tables:
    print('=== filtered_files row count ===')
    print(' ', c.execute('SELECT COUNT(*) FROM filtered_files').fetchone()[0], 'rows')

    print()
    print('=== raw_files eligible for Stage1 (not yet in filtered_files, kw IS NOT NULL) ===')
    rows = c.execute('''
        SELECT r.language, COUNT(*)
        FROM raw_files r
        LEFT JOIN filtered_files f ON r.id = f.raw_file_id
        WHERE f.id IS NULL AND r.keyword_in_comment IS NOT NULL
        GROUP BY r.language
    ''').fetchall()
    for row in rows:
        print(f'  {row[0]}: {row[1]}')
    print(f'  TOTAL: {sum(r[1] for r in rows)}')
else:
    print('filtered_files table does NOT EXIST yet (schema.sql not applied to this DB)')
    print()
    print('=== raw_files with keyword_in_comment NOT NULL (Stage1-eligible once table exists) ===')
    rows = c.execute(
        'SELECT language, COUNT(*) FROM raw_files WHERE keyword_in_comment IS NOT NULL GROUP BY language'
    ).fetchall()
    for row in rows:
        print(f'  {row[0]}: {row[1]}')
    print(f'  TOTAL: {sum(r[1] for r in rows)}')
    print()
    print('=== raw_files with keyword_in_comment NULL ===')
    null_count = c.execute('SELECT COUNT(*) FROM raw_files WHERE keyword_in_comment IS NULL').fetchone()[0]
    print(f'  {null_count} rows')

print()
print('=== Sample file_paths (5 rows) ===')
for row in c.execute('SELECT file_path, language FROM raw_files LIMIT 5').fetchall():
    print(f'  [{row[1]}] {row[0]}')

conn.close()
