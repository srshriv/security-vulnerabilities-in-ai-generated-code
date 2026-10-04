import sqlite3

c = sqlite3.connect('/home/kiit/security-vuln/corpus.db')
print("dynamic_results total rows:", c.execute("SELECT count(1) FROM dynamic_results").fetchone()[0])
print("atheris_crashed=1 rows:", c.execute("SELECT count(1) FROM dynamic_results WHERE atheris_crashed=1").fetchone()[0])
print("afl_crashed=1 rows:", c.execute("SELECT count(1) FROM dynamic_results WHERE afl_crashed=1").fetchone()[0])
print("hang_confirmed=1 rows:", c.execute("SELECT count(1) FROM dynamic_results WHERE hang_confirmed=1").fetchone()[0])
print("final_injection_confirmed=1 rows:", c.execute("SELECT count(1) FROM dynamic_results WHERE final_injection_confirmed=1").fetchone()[0])
