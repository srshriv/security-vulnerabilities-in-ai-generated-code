import sqlite3, os
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
c = sqlite3.connect(os.path.join(BASE_DIR, 'corpus.db'))
r = c.execute("SELECT COUNT(*) FROM raw_files WHERE repo_name='SYNTHETIC'").fetchone()[0]
print(f'SYNTHETIC rows in raw_files: {r}')
c.close()
