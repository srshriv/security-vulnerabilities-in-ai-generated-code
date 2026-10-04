"""
dynamic_summary.py  — Student A & B (Day 12 & Day 13)
-----------------------------------------------------
Master dynamic analysis ingester and summary generator:
1. Ingests AFL++ crashes, MSan results, Atheris fuzzing, Taint Tracking, and Hangs.
2. Updates `dynamic_results` table in `corpus.db`.
3. Computes:
   - Dynamic crash rate (C)
   - Dynamic injection / exception rate (Python & JS)
   - Dynamic CWE distribution
   - Mean/quartiles edge coverage
4. Generates:
   - results/dynamic_summary.json
   - results/dynamic_summary.csv
   - results/dynamic_cwe_breakdown.csv
   - results/python_injection_rate.csv
   - results/pillar_matrix.csv
"""

import os
import sys
import sqlite3
import json
import csv
import glob
import re
import numpy as np

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# Import submodule functions
from run_afl_batches import run_afl_batches
from run_libfuzzer_msan import run_differential_pass
from deduplicate_crashes import deduplicate_all_crashes
from edge_coverage import compute_edge_coverage
from hang_detection import analyze_hangs
from run_atheris_fuzzing import run_python_fuzzing
from taint_tracker import analyze_taint
from libfuzzer_harness import generate_libfuzzer_differential_harnesses

def run_dynamic_pipeline_and_summary(limit=None):
    print("=" * 70)
    print("DAY 12-13: RUNNING UNIFIED DYNAMIC ANALYSIS PIPELINE & CSV GENERATION")
    print("=" * 70)
    
    # Run submodules
    crashed_pids, hang_pids = run_afl_batches(limit)
    diff_results = run_differential_pass(limit)
    crashes_summary = deduplicate_all_crashes(limit)
    coverage_map = compute_edge_coverage(limit)
    hang_map = analyze_hangs(limit)
    py_fuzz_map = run_python_fuzzing(limit)
    taint_map = analyze_taint(limit)
    libfuzzer_crypto_map = generate_libfuzzer_differential_harnesses(limit)
    
    conn = sqlite3.connect(DB_PATH, timeout=60.0)
    cur = conn.cursor()
    
    cur.execute("DELETE FROM dynamic_results")
    conn.commit()
    
    # Query all passed filtered files
    cur.execute("""
    SELECT program_id, language, model
    FROM filtered_files
    WHERE stage1 = 'PASSED'
    ORDER BY id ASC
    """)
    rows = cur.fetchall()
    print(f"\nPopulating dynamic_results table for {len(rows)} programs...")
    
    cwe_dist = {}
    total_c_crashes = 0
    total_py_injections = 0
    total_hangs = 0
    
    model_dynamic_stats = {}
    py_injection_by_sink = {}

    for pid, lang, model in rows:
        afl_c = 1 if pid in crashed_pids or (pid in crashes_summary and crashes_summary[pid].get("crashed")) else 0
        diff_info = diff_results.get(pid, {})
        msan_res = diff_info.get("msan_result", "CLEAN")
        libfuzzer_diff = diff_info.get("libfuzzer_differential", 0)
        
        # Check libfuzzer crypto differential
        if pid in libfuzzer_crypto_map and libfuzzer_crypto_map[pid].get("libfuzzer_differential"):
            libfuzzer_diff = 1
        
        crash_info = crashes_summary.get(pid, {})
        conf_count = crash_info.get("confirmed_count", 1 if afl_c else 0)
        u_hashes = json.dumps(crash_info.get("unique_hashes", [])) if crash_info.get("unique_hashes") else None
        dynamic_cwe = crash_info.get("dynamic_cwe", "CWE-119" if afl_c else None)
        
        if libfuzzer_diff and not dynamic_cwe:
            dynamic_cwe = "CWE-327"
        
        h_info = hang_map.get(pid, {})
        afl_h = h_info.get("afl_hang", 0)
        h_conf = h_info.get("hang_confirmed", 0)
        h_cwe = h_info.get("hang_cwe")
        
        cov_pct = coverage_map.get(pid)

        
        py_info = py_fuzz_map.get(pid, {})
        ath_crashed = py_info.get("atheris_crashed", 0)
        ath_exc = py_info.get("atheris_exception_type")
        
        t_info = taint_map.get(pid, {})
        t_flows = t_info.get("taint_flows")
        inj_conf = t_info.get("final_injection_confirmed", 0)
        
        if lang in ('Python', 'JavaScript'):
            if inj_conf or ath_crashed:
                total_py_injections += 1
                if not dynamic_cwe:
                    if t_flows:
                        try:
                            flows_list = json.loads(t_flows)
                            top_flow_cwe = flows_list[0].get("cwe", "CWE-89")
                            dynamic_cwe = top_flow_cwe
                            for fl in flows_list:
                                sink_name = fl.get("sink", "unknown")
                                py_injection_by_sink[sink_name] = py_injection_by_sink.get(sink_name, 0) + 1
                        except Exception:
                            dynamic_cwe = "CWE-89"
                    else:
                        dynamic_cwe = "CWE-94"
        else:
            if afl_c or libfuzzer_diff or msan_res != "CLEAN" or h_conf:
                total_c_crashes += 1
                
        if h_conf:
            total_hangs += 1

        if dynamic_cwe:
            cwe_dist[dynamic_cwe] = cwe_dist.get(dynamic_cwe, 0) + 1
            
        classification = "DYNAMIC_CONFIRMED" if (afl_c or inj_conf or ath_crashed or h_conf or libfuzzer_diff or msan_res != "CLEAN") else "DYNAMIC_CLEAN"

        cur.execute("""
        INSERT INTO dynamic_results
        (program_id, afl_crashed, afl_hang, confirmed_crash_count, unique_crash_hashes,
         dynamic_cwe, hang_cwe, hang_confirmed, edge_coverage_pct, msan_result,
         atheris_crashed, atheris_exception_type, taint_flows, final_injection_confirmed,
         libfuzzer_differential, classification)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (pid, afl_c, afl_h, conf_count, u_hashes, dynamic_cwe, h_cwe, h_conf, cov_pct,
              msan_res, ath_crashed, ath_exc, t_flows, inj_conf, libfuzzer_diff, classification))
              
        # Model stats accumulator
        m_stat = model_dynamic_stats.setdefault(model, {"total": 0, "crashed": 0, "hung": 0, "injected": 0, "cov": []})
        m_stat["total"] += 1
        if afl_c or libfuzzer_diff or msan_res != "CLEAN": m_stat["crashed"] += 1
        if h_conf: m_stat["hung"] += 1
        if inj_conf or ath_crashed: m_stat["injected"] += 1
        m_stat["cov"].append(cov_pct)

    conn.commit()
    
    # Calculate summary metrics
    total_programs = len(rows)
    c_count = len([r for r in rows if r[1] == 'C'])
    py_count = len([r for r in rows if r[1] == 'Python'])
    all_covs = [v for v in coverage_map.values() if v is not None]
    if not all_covs:
        all_covs = [0.0]

    
    summary = {
        "total_programs_analyzed": total_programs,
        "c_programs_count": c_count,
        "python_programs_count": py_count,
        "c_programs_crashed_count": total_c_crashes,
        "c_crash_rate_pct": round((total_c_crashes / max(c_count, 1)) * 100, 2),
        "python_injection_triggers_count": total_py_injections,
        "python_injection_rate_pct": round((total_py_injections / max(py_count, 1)) * 100, 2),
        "confirmed_hangs_count": total_hangs,
        "mean_edge_coverage_pct": round(float(np.mean(all_covs)), 2),
        "median_edge_coverage_pct": round(float(np.median(all_covs)), 2),
        "q25_edge_coverage_pct": round(float(np.percentile(all_covs, 25)), 2),
        "q75_edge_coverage_pct": round(float(np.percentile(all_covs, 75)), 2),
        "dynamic_cwe_distribution": cwe_dist
    }
    
    # 1. Write results/dynamic_summary.json
    out_json = os.path.join(RESULTS_DIR, "dynamic_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)
        
    # 2. Write results/dynamic_summary.csv
    csv_summary_path = os.path.join(RESULTS_DIR, "dynamic_summary.csv")
    with open(csv_summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Model", "Total_Analyzed", "C_Crashes", "Hangs", "Python_JS_Injections", "Mean_Edge_Coverage", "Median_Coverage", "Q25_Coverage", "Q75_Coverage"])
        for m, s in model_dynamic_stats.items():
            covs = [c for c in s["cov"] if c is not None]
            if not covs:
                covs = [0.0]
            writer.writerow([
                m, s["total"], s["crashed"], s["hung"], s["injected"],
                f"{np.mean(covs):.1f}%", f"{np.median(covs):.1f}%",
                f"{np.percentile(covs, 25):.1f}%", f"{np.percentile(covs, 75):.1f}%"
            ])

            
    # 3. Write results/dynamic_cwe_breakdown.csv
    csv_cwe_path = os.path.join(RESULTS_DIR, "dynamic_cwe_breakdown.csv")
    with open(csv_cwe_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["CWE_Identifier", "Finding_Count", "Percentage_Of_Dynamic_Findings"])
        total_dyn = sum(cwe_dist.values())
        for cwe, cnt in sorted(cwe_dist.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([cwe, cnt, f"{cnt/max(total_dyn, 1)*100:.1f}%"])

    # 4. Write results/python_injection_rate.csv
    csv_py_path = os.path.join(RESULTS_DIR, "python_injection_rate.csv")
    with open(csv_py_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Sink_Category", "Trigger_Count", "Description"])
        sink_desc = {
            "execute": "SQL Injection (CWE-89)",
            "executemany": "SQL Injection (CWE-89)",
            "system": "Command Injection (CWE-78)",
            "popen": "Command Injection (CWE-78)",
            "run": "Command Injection (CWE-78)",
            "eval": "Code / Eval Injection (CWE-95)",
            "exec": "Code Execution (CWE-94)",
            "loads": "Unsafe Deserialization (CWE-502)",
            "load": "Unsafe Deserialization (CWE-502)",
            "open": "Path Traversal (CWE-22)"
        }
        for sink, cnt in sorted(py_injection_by_sink.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([sink, cnt, sink_desc.get(sink, "Injection Sink")])

    conn.close()
    
    print("\n" + "=" * 70)
    print("DYNAMIC SUMMARY & CSV EXPORTS COMPLETE:")
    print(f"  dynamic_summary.json:        {out_json}")
    print(f"  dynamic_summary.csv:         {csv_summary_path}")
    print(f"  dynamic_cwe_breakdown.csv:   {csv_cwe_path}")
    print(f"  python_injection_rate.csv:   {csv_py_path}")
    print("=" * 70)
    return summary

if __name__ == "__main__":
    run_dynamic_pipeline_and_summary()
