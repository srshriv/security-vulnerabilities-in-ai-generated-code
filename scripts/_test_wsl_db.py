import sqlite3, os

path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'corpus.db'))
print('DB path:', path)
print('Exists:', os.path.exists(path), 'Size:', os.path.getsize(path) if os.path.exists(path) else 0)

conn = sqlite3.connect(path)
c = conn.cursor()
print('Tables:', c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())
print('Total in raw_files:', c.execute("SELECT count(*) FROM raw_files").fetchone()[0])
print('Total in filtered_files:', c.execute("SELECT count(*) FROM filtered_files").fetchone()[0])
print('Passed stage1 in filtered_files:', c.execute("SELECT count(*) FROM filtered_files WHERE stage1='PASSED'").fetchone()[0])
q = """
SELECT f.program_id, r.file_content, r.language
FROM raw_files r
JOIN filtered_files f ON r.id = f.raw_file_id
WHERE f.stage1 = 'PASSED'
"""
rows = c.execute(q).fetchall()
print('Joined rows count:', len(rows))
if rows:
    print('First row:', rows[0][0], rows[0][2], 'len content:', len(rows[0][1]) if rows[0][1] else 0)
