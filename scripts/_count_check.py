"""SELECT-only DB count check."""
import sqlite3, os
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
print('=== raw_files counts by language ===')
for row in c.execute('SELECT language, COUNT(*) FROM raw_files GROUP BY language ORDER BY language').fetchall():
    print(f'  {row[0]}: {row[1]}')
total = c.execute('SELECT COUNT(*) FROM raw_files').fetchone()[0]
print(f'  TOTAL: {total}')
print()
print('Targets: C=2500, Python=4600, JavaScript=4600')
targets = {'C': 2500, 'Python': 4600, 'JavaScript': 4600}
counts  = dict(c.execute('SELECT language, COUNT(*) FROM raw_files GROUP BY language').fetchall())
for lang, tgt in targets.items():
    cur = counts.get(lang, 0)
    pct = cur / tgt * 100
    remaining = max(0, tgt - cur)
    print(f'  {lang:<12}: {cur:>5}/{tgt}  ({pct:.1f}%)  still need {remaining}')
conn.close()

# Also show keyword_in_comment pass/fail for the rows we have
import sqlite3, os
conn2 = sqlite3.connect(os.path.join(os.path.dirname(__file__), '..', 'corpus.db'))
rows2 = conn2.execute('SELECT language, keyword_in_comment, COUNT(*) FROM raw_files GROUP BY language, keyword_in_comment ORDER BY language, keyword_in_comment').fetchall()
if rows2:
    print()
    print('keyword_in_comment breakdown (1=pass, 0=fail):')
    print(f'  {"Language":<14} {"Pass":>6} {"Fail":>6} {"Unverified":>10} {"Pass%":>7}')
    langs = {}
    for lang, kic, cnt in rows2:
        langs.setdefault(lang, {0: 0, 1: 0})[kic] = cnt
    for lang in sorted(langs):
        p = langs[lang].get(1, 0)
        f = langs[lang].get(0, 0)
        pct = (p / (p+f) * 100) if (p+f) else 0
        print(f'  {lang:<14} {p:>6} {f:>6} {"":>10} {pct:>6.1f}%')
conn2.close()
