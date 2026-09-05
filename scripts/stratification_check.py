import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

MIN_PER_MODEL = 100
MIN_PER_CWE   = 50

def run_stratification_check():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    print("=" * 70)
    print("STRATIFICATION CHECK")
    print("=" * 70)

    # Count passed C programs per model
    print("\n--- C PROGRAMS PER MODEL (need >= 100 each) ---")
    model_counts = c.execute('''
        SELECT model, COUNT(*) as cnt
        FROM filtered_files
        WHERE stage1 = 'PASSED'
        AND language = 'C'
        AND compile_status IN ('COMPILED', 'REPAIR_COMPILED')
        GROUP BY model
        ORDER BY cnt DESC
    ''').fetchall()

    if not model_counts:
        print("  No C programs in filtered_files yet.")
    else:
        for model, cnt in model_counts:
            flag = "OK" if cnt >= MIN_PER_MODEL else f"UNDERFILLED (need {MIN_PER_MODEL - cnt} more)"
            print(f"  {model:<15} : {cnt:>5}  [{flag}]")

    # Count passed Python programs per model
    print("\n--- PYTHON PROGRAMS PER MODEL (need >= 100 each) ---")
    py_counts = c.execute('''
        SELECT model, COUNT(*) as cnt
        FROM filtered_files
        WHERE stage1 = 'PASSED'
        AND language = 'Python'
        AND compile_status = 'SYNTAX_OK'
        GROUP BY model
        ORDER BY cnt DESC
    ''').fetchall()

    if not py_counts:
        print("  No Python programs in filtered_files yet.")
    else:
        for model, cnt in py_counts:
            flag = "OK" if cnt >= MIN_PER_MODEL else f"UNDERFILLED (need {MIN_PER_MODEL - cnt} more)"
            print(f"  {model:<15} : {cnt:>5}  [{flag}]")

    # Count synthetic programs per CWE target
    print("\n--- SYNTHETIC PROGRAMS PER CWE (need >= 50 each) ---")
    cwe_counts = c.execute('''
        SELECT cwe_target, model, COUNT(*) as cnt
        FROM filtered_files
        WHERE source = 'SYNTHETIC'
        AND stage1 = 'PASSED'
        AND cwe_target IS NOT NULL
        GROUP BY cwe_target, model
        ORDER BY cwe_target, model
    ''').fetchall()

    if not cwe_counts:
        print("  No synthetic programs in filtered_files yet.")
        print("  This will be populated when Student A runs synthetic_generate.py")
    else:
        current_cwe = None
        for cwe, model, cnt in cwe_counts:
            if cwe != current_cwe:
                print(f"\n  CWE: {cwe}")
                current_cwe = cwe
            flag = "OK" if cnt >= MIN_PER_CWE else f"UNDERFILLED (need {MIN_PER_CWE - cnt} more)"
            print(f"    {model:<15} : {cnt:>4}  [{flag}]")

    # Summary
    print("\n--- SUMMARY ---")
    total_passed = c.execute(
        'SELECT COUNT(*) FROM filtered_files WHERE stage1 = "PASSED"'
    ).fetchone()[0]
    total_c = c.execute(
        'SELECT COUNT(*) FROM filtered_files '
        'WHERE stage1 = "PASSED" AND language = "C"'
    ).fetchone()[0]
    total_py = c.execute(
        'SELECT COUNT(*) FROM filtered_files '
        'WHERE stage1 = "PASSED" AND language = "Python"'
    ).fetchone()[0]
    total_synth = c.execute(
        'SELECT COUNT(*) FROM filtered_files '
        'WHERE stage1 = "PASSED" AND source = "SYNTHETIC"'
    ).fetchone()[0]

    print(f"  Total passed files : {total_passed}")
    print(f"  C programs         : {total_c}")
    print(f"  Python programs    : {total_py}")
    print(f"  Synthetic programs : {total_synth}")

    underfilled_models = [
        m for m, cnt in (model_counts + py_counts)
        if cnt < MIN_PER_MODEL
    ]
    if underfilled_models:
        print(f"\n  UNDERFILLED MODELS: {', '.join(set(underfilled_models))}")
        print(f"  Action: Student A needs to top up with synthetic programs for these models")
    else:
        if model_counts or py_counts:
            print(f"\n  All models have sufficient programs.")

    conn.close()

if __name__ == '__main__':
    run_stratification_check()
