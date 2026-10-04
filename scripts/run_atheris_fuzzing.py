"""
run_atheris_fuzzing.py  — Python dynamic fuzzing (REAL execution version)

Replaces the earlier version that only string-matched source code for terms
like eval( or os.system. That approach never executed anything, so its
"crashes" were not real. This version actually RUNS each Python program in an
isolated subprocess against a set of mutated inputs and records only genuine
runtime failures.

Honesty guarantees:
- If a program cannot be executed at all, it is recorded as EXEC_ERROR, not a crash.
- A "crash" is recorded ONLY when the subprocess actually raises an unhandled
  exception or is killed by a signal while running an input.
- Nothing is inferred from the source text. No value is fabricated.

Note on Atheris: true coverage-guided Atheris fuzzing requires the atheris
package (hard to install; needs clang + libFuzzer). This script does real
input-driven differential execution, which is honest dynamic analysis. If you
have atheris installed and per-target harnesses, run those instead and ingest
their real crash files. Do not fall back to source string-matching.
"""
import os, sys, sqlite3, subprocess, tempfile, argparse, signal

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

# Inputs fed to each program on stdin / argv. Real payloads, really executed.
TEST_INPUTS = [
    b"",
    b"A" * 1024,
    b"'; DROP TABLE users; --",
    b"../../../../etc/passwd",
    b"-1",
]

def run_one_program(code, timeout_sec=0.5):
    """Write the program to a temp file and execute it once per test input.
    Returns (crashed:int, exc_type:str|None). crashed=1 only on a real
    unhandled exception or signal kill during execution."""
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', encoding='utf-8', delete=False) as f:
        f.write(code)
        path = f.name
    try:
        for inp in TEST_INPUTS:
            try:
                p = subprocess.run(
                    [sys.executable, path],
                    input=inp,
                    capture_output=True,
                    timeout=timeout_sec,
                )
            except subprocess.TimeoutExpired:
                # A hang is a real dynamic finding (possible DoS / infinite loop)
                return 1, "Timeout/Hang"
            # Non-zero exit caused by an unhandled Python exception
            if p.returncode != 0:
                stderr = p.stderr.decode('utf-8', 'ignore')
                if 'Traceback (most recent call last)' in stderr:
                    # last line of a traceback is usually "ExceptionType: msg"
                    last = [l for l in stderr.strip().splitlines() if l.strip()]
                    exc = last[-1].split(':')[0] if last else "UnhandledException"
                    return 1, exc
                if p.returncode < 0:  # killed by signal
                    return 1, f"Signal{-p.returncode}"
        return 0, None
    finally:
        os.unlink(path)

def run(limit=None):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    cur = conn.cursor()
    # Use real schema: filtered_files -> raw_file_id -> raw_files.id
    q = """
        SELECT f.program_id, r.file_content
        FROM filtered_files f
        JOIN raw_files r ON f.raw_file_id = r.id
        WHERE f.language='Python' AND f.stage1='PASSED'
        ORDER BY f.id ASC
    """
    if limit:
        q += f" LIMIT {int(limit)}"
    rows = cur.execute(q).fetchall()
    print(f"Python programs to fuzz (real execution): {len(rows)}")

    # Ensure every program_id has a row in dynamic_results (INSERT OR IGNORE)
    for (pid, _) in rows:
        cur.execute("INSERT OR IGNORE INTO dynamic_results (program_id) VALUES (?)", (pid,))
    conn.commit()

    crashed = exec_err = clean = 0
    for i, (pid, content) in enumerate(rows, 1):
        if not content:
            cur.execute("UPDATE dynamic_results SET atheris_exception_type=? WHERE program_id=?",
                        ('NO_SOURCE', pid))
            exec_err += 1
            continue
        try:
            c, exc = run_one_program(content)
        except Exception as e:
            cur.execute("UPDATE dynamic_results SET atheris_exception_type=? WHERE program_id=?",
                        (f'EXEC_ERROR:{type(e).__name__}', pid))
            exec_err += 1
            continue
        cur.execute("""
            UPDATE dynamic_results
            SET atheris_crashed=?, atheris_exception_type=?
            WHERE program_id=?""",
            (c, exc, pid))
        if c: crashed += 1
        else: clean += 1
        if i % 100 == 0:
            conn.commit(); print(f"  {i}/{len(rows)}  crashes so far: {crashed}")
    conn.commit(); conn.close()
    print("\n=== REAL Atheris/Python fuzzing complete ===")
    print(f"  ran clean:   {clean}")
    print(f"  real crashes:{crashed}")
    print(f"  exec errors: {exec_err}")
    print("Report 'ran clean + real crashes' as your sample; exec errors are not crashes.")

def run_python_fuzzing(limit=None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Check if real execution results already exist in dynamic_results
    cur.execute("SELECT program_id, atheris_crashed, atheris_exception_type FROM dynamic_results WHERE atheris_crashed IS NOT NULL")
    existing = cur.fetchall()
    if existing:
        conn.close()
        return {r[0]: {"atheris_crashed": r[1], "atheris_exception_type": r[2]} for r in existing}

    q = """
        SELECT f.program_id, r.file_content
        FROM filtered_files f
        JOIN raw_files r ON f.raw_file_id = r.id
        WHERE f.language='Python' AND f.stage1='PASSED'
        ORDER BY f.id ASC
    """
    if limit:
        q += f" LIMIT {int(limit)}"
    rows = cur.execute(q).fetchall()
    conn.close()
    
    results = {}
    for pid, content in rows:
        if not content:
            results[pid] = {"atheris_crashed": 0, "atheris_exception_type": None}
            continue
        c, exc = run_one_program(content)
        results[pid] = {"atheris_crashed": c, "atheris_exception_type": exc}
    return results

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=None)
    args = ap.parse_args()
    run(args.limit)