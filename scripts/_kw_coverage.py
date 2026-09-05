"""keyword_in_comment coverage check — SELECT only, no writes."""
import sqlite3, os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

conn = sqlite3.connect(DB_PATH)
c    = conn.cursor()

print('=== keyword_in_comment value distribution ===')
for row in c.execute(
    'SELECT keyword_in_comment, COUNT(*) FROM raw_files '
    'GROUP BY keyword_in_comment ORDER BY keyword_in_comment'
).fetchall():
    print(f'  keyword_in_comment = {row[0]}  :  {row[1]} rows')

total      = c.execute('SELECT COUNT(*) FROM raw_files').fetchone()[0]
null_count = c.execute('SELECT COUNT(*) FROM raw_files WHERE keyword_in_comment IS NULL').fetchone()[0]
one_count  = c.execute('SELECT COUNT(*) FROM raw_files WHERE keyword_in_comment = 1').fetchone()[0]
zero_count = c.execute('SELECT COUNT(*) FROM raw_files WHERE keyword_in_comment = 0').fetchone()[0]

print()
print(f'  Total rows                         : {total}')
print(f'  NULL (collector never wrote value) : {null_count}')
print(f'  = 1  (keyword found in comment)    : {one_count}')
print(f'  = 0  (keyword NOT in comment)      : {zero_count}')

print()
if one_count == 0 and null_count == 0 and zero_count == total:
    print('VERDICT: All rows are 0.')
    print('  The collector hardcodes keyword_in_comment=0 as a placeholder.')
    print('  verify_comment_location.py targets WHERE keyword_in_comment IS NULL.')
    print('  Since there are NO NULL rows, verify_comment_location.py would process 0 rows.')
    print('  It has never been run in a meaningful way — or it ran but found nothing to update.')
elif one_count > 0:
    print('VERDICT: Some rows = 1. verify_comment_location.py has run (at least partially).')
elif null_count > 0 and one_count == 0:
    print('VERDICT: Mix of NULL + 0, none = 1.')
    print('  NULL rows = old collector writes (no keyword_in_comment column at write time).')
    print('  0 rows    = collector default placeholder.')
    print('  verify_comment_location.py has NOT meaningfully run.')

print()
print('=== search_keyword distinct values (to understand scope) ===')
for row in c.execute(
    'SELECT search_keyword, COUNT(*) FROM raw_files '
    'GROUP BY search_keyword ORDER BY COUNT(*) DESC'
).fetchall():
    print(f'  {repr(row[0])}: {row[1]} rows')

conn.close()
