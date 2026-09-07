"""
recompute_static_summary.py
---------------------------
Re-computes the static-analysis summary with two corrections that make the
numbers meaningful for the paper:

  1. CWE-617 (Bandit B101 'assert used') is SEPARATED OUT of the main
     vulnerability count. Asserts are a low-severity code-quality issue that
     AI code triggers thousands of times; leaving them in the headline count
     makes ~46% of "vulnerabilities" just "this file uses assert".

  2. Findings are broken down by SEVERITY and by TOOL, and a "core
     vulnerabilities" figure (excluding the assert noise and LOW severity)
     is reported separately from the raw total.

Run it from the folder that contains corpus.db (the real one with data).
It writes results/static_summary_corrected.json and prints a readable report.
"""
import sqlite3, json, os, sys

DB = 'corpus.db'
OUT = os.path.join('results', 'static_summary_corrected.json')

# CWEs we treat as low-value "noise" rules that inflate counts.
# CWE-617 = asserts (Bandit B101). Add others here if you decide to.
NOISE_CWES = {'CWE-617'}

def main():
    if not os.path.exists(DB):
        print(f"ERROR: {DB} not found in this folder.")
        print("Run this from the folder that has the real corpus.db (the one with static_results filled in).")
        sys.exit(1)

    c = sqlite3.connect(DB)
    total = c.execute("SELECT COUNT(*) FROM static_results").fetchone()[0]
    if total == 0:
        print("static_results is empty in this database. Use the one that has the real scan results.")
        sys.exit(1)

    # --- headline counts ---
    noise = c.execute(
        f"SELECT COUNT(*) FROM static_results WHERE cwe IN ({','.join('?'*len(NOISE_CWES))})",
        tuple(NOISE_CWES)
    ).fetchone()[0]
    core = total - noise

    # --- severity breakdown (excluding noise) ---
    sev = dict(c.execute(
        f"SELECT severity, COUNT(*) FROM static_results "
        f"WHERE cwe NOT IN ({','.join('?'*len(NOISE_CWES))}) "
        f"GROUP BY severity", tuple(NOISE_CWES)
    ).fetchall())

    # --- tool breakdown (excluding noise) ---
    tools = dict(c.execute(
        f"SELECT tool, COUNT(*) FROM static_results "
        f"WHERE cwe NOT IN ({','.join('?'*len(NOISE_CWES))}) "
        f"GROUP BY tool", tuple(NOISE_CWES)
    ).fetchall())

    # --- top CWEs EXCLUDING noise ---
    top = c.execute(
        f"SELECT cwe, COUNT(*) FROM static_results "
        f"WHERE cwe NOT IN ({','.join('?'*len(NOISE_CWES))}) "
        f"GROUP BY cwe ORDER BY COUNT(*) DESC LIMIT 10", tuple(NOISE_CWES)
    ).fetchall()

    # --- MEDIUM+HIGH only, excluding noise = the real vulnerability signal ---
    core_medhigh = c.execute(
        f"SELECT COUNT(*) FROM static_results "
        f"WHERE cwe NOT IN ({','.join('?'*len(NOISE_CWES))}) "
        f"AND severity IN ('HIGH','MEDIUM')", tuple(NOISE_CWES)
    ).fetchone()[0]

    # --- programs flagged with a CORE (non-noise) finding ---
    progs_core = c.execute(
        f"SELECT COUNT(DISTINCT program_id) FROM static_results "
        f"WHERE cwe NOT IN ({','.join('?'*len(NOISE_CWES))})", tuple(NOISE_CWES)
    ).fetchone()[0]

    # --- per-model density EXCLUDING noise (fair comparison) ---
    per_model = c.execute(f"""
        SELECT ff.model, ff.language,
               COUNT(DISTINCT ff.program_id) AS programs,
               COUNT(sr.id) AS findings
        FROM filtered_files ff
        LEFT JOIN static_results sr
               ON sr.program_id = ff.program_id
              AND sr.cwe NOT IN ({','.join('?'*len(NOISE_CWES))})
        WHERE ff.stage1='PASSED'
        GROUP BY ff.model, ff.language
        ORDER BY findings DESC
    """, tuple(NOISE_CWES)).fetchall()

    result = {
        "raw_total_findings": total,
        "assert_noise_CWE617_excluded": noise,
        "assert_noise_pct_of_raw": round(100.0*noise/total, 1),
        "core_findings_excluding_asserts": core,
        "core_findings_MEDIUM_HIGH_only": core_medhigh,
        "programs_with_a_core_finding": progs_core,
        "core_severity_breakdown": sev,
        "core_tool_breakdown": tools,
        "top_10_cwes_excluding_asserts": {k: v for k, v in top},
        "per_model_density_excluding_asserts": [
            {"model": m, "language": l, "programs": p, "findings": f,
             "findings_per_program": round(f/p, 2) if p else 0}
            for (m, l, p, f) in per_model
        ],
        "note": "CWE-617 (assert-used, Bandit B101) separated out as low-value noise. "
                "Core = all findings except asserts. Report core numbers as the headline; "
                "report asserts separately as a code-quality observation."
    }

    os.makedirs('results', exist_ok=True)
    json.dump(result, open(OUT, 'w'), indent=2)

    # readable report
    print("="*60)
    print("CORRECTED STATIC SUMMARY")
    print("="*60)
    print(f"Raw total findings:                 {total:,}")
    print(f"  of which asserts (CWE-617):       {noise:,}  ({result['assert_noise_pct_of_raw']}% of raw)")
    print(f"Core findings (no asserts):         {core:,}")
    print(f"Core MEDIUM+HIGH only:              {core_medhigh:,}   <-- the real vulnerability signal")
    print(f"Programs with a core finding:       {progs_core:,}")
    print()
    print("Core severity breakdown:", sev)
    print("Core tool breakdown:    ", tools)
    print()
    print("Top CWEs EXCLUDING asserts:")
    for cwe, n in top:
        print(f"   {cwe:12s} {n:,}")
    print()
    print(f"Written: {OUT}")

if __name__ == '__main__':
    main()
