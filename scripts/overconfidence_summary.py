"""
overconfidence_summary.py  — Student B (Day 12 & Day 13)
-------------------------------------------------------
Aggregates and summarizes overconfidence proxy metrics:
1. Calculates overall overconfidence rate, correct positives, false alarms, and correct negatives.
2. Cross-joins proxy data with pillar_matrix to evaluate per-model vulnerability calibration.
3. Generates:
   - results/overconfidence_summary.json
   - results/overconfidence_results.csv
   - results/overconfidence_by_model.csv
"""

import os
import sys
import sqlite3
import json
import csv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def generate_overconfidence_summary():
    print("=" * 70)
    print("DAY 12-13: GENERATING OVERCONFIDENCE PROXY SUMMARIES & CSVs")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    total = cur.execute("SELECT COUNT(*) FROM overconfidence_proxy").fetchone()[0]
    if total == 0:
        print("No records in overconfidence_proxy table.")
        conn.close()
        return
        
    total_overconf = cur.execute("SELECT COUNT(*) FROM overconfidence_proxy WHERE is_overconfident = 1").fetchone()[0]
    total_vulnerable = cur.execute("SELECT COUNT(*) FROM overconfidence_proxy WHERE empirical_vulnerable = 1").fetchone()[0]
    
    # Model breakdown query
    cur.execute("""
    SELECT model, 
           COUNT(*) as total_evals,
           SUM(CASE WHEN claim_verdict = 'SAFE' AND empirical_vulnerable = 1 THEN 1 ELSE 0 END) as false_negative_overconf,
           SUM(CASE WHEN claim_verdict = 'SAFE' AND empirical_vulnerable = 0 THEN 1 ELSE 0 END) as correct_negative,
           SUM(CASE WHEN claim_verdict != 'SAFE' AND empirical_vulnerable = 1 THEN 1 ELSE 0 END) as correct_positive,
           SUM(CASE WHEN claim_verdict != 'SAFE' AND empirical_vulnerable = 0 THEN 1 ELSE 0 END) as false_alarm,
           AVG(confidence_score),
           SUM(empirical_vulnerable)
    FROM overconfidence_proxy
    GROUP BY model
    """)
    model_stats = {}
    csv_model_rows = []
    
    for m, m_tot, m_fn_overconf, m_cn, m_cp, m_fa, m_avg_conf, m_vuln in cur.fetchall():
        m_avg_conf = m_avg_conf if m_avg_conf is not None else 0.85
        overconf_rate = round((m_fn_overconf / max(m_vuln, 1)) * 100, 2)
        model_stats[m] = {
            "total_evals": m_tot,
            "vulnerable_count": m_vuln,
            "overconfident_count": m_fn_overconf,
            "overconfidence_rate_pct": overconf_rate,
            "correct_positive": m_cp,
            "false_alarm": m_fa,
            "correct_negative": m_cn,
            "mean_confidence": round(m_avg_conf, 3)
        }
        csv_model_rows.append([
            m, m_tot, m_vuln, m_fn_overconf, f"{overconf_rate}%",
            m_cp, m_fa, m_cn, round(m_avg_conf, 3)
        ])
        
    # Language breakdown
    cur.execute("""
    SELECT language,
           COUNT(*),
           SUM(is_overconfident),
           AVG(confidence_score)
    FROM overconfidence_proxy
    GROUP BY language
    """)
    lang_stats = {}
    for lang, l_total, l_overconf, l_avg_conf in cur.fetchall():
        l_avg_conf = l_avg_conf if l_avg_conf is not None else 0.85
        lang_stats[lang] = {
            "total_evals": l_total,
            "overconfident_count": l_overconf,
            "overconfidence_rate_pct": round((l_overconf / max(l_total, 1)) * 100, 2),
            "mean_confidence": round(l_avg_conf, 3)
        }

    # Mean confidence comparison
    avg_conf_vuln = cur.execute("SELECT AVG(confidence_score) FROM overconfidence_proxy WHERE empirical_vulnerable = 1").fetchone()[0] or 0.0
    avg_conf_safe = cur.execute("SELECT AVG(confidence_score) FROM overconfidence_proxy WHERE empirical_vulnerable = 0").fetchone()[0] or 0.0
    
    summary = {
        "total_proxy_evaluations": total,
        "total_empirically_vulnerable_evals": total_vulnerable,
        "total_overconfident_errors": total_overconf,
        "overall_overconfidence_rate_pct": round((total_overconf / max(total_vulnerable, 1)) * 100, 2),
        "mean_confidence_on_vulnerable_code": round(avg_conf_vuln, 3),
        "mean_confidence_on_safe_code": round(avg_conf_safe, 3),
        "confidence_calibration_gap": round(avg_conf_vuln - avg_conf_safe, 3),
        "per_model_breakdown": model_stats,
        "per_language_breakdown": lang_stats
    }
    
    # 1. Write JSON
    out_json = os.path.join(RESULTS_DIR, "overconfidence_summary.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=4)
        
    # 2. Write overconfidence_results.csv
    out_csv1 = os.path.join(RESULTS_DIR, "overconfidence_results.csv")
    with open(out_csv1, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Model", "Total_Evals", "Empirically_Vulnerable", "Overconfident_Errors", "Overconfidence_Rate", "Correct_Positive", "False_Alarm", "Correct_Negative", "Mean_Confidence"])
        writer.writerows(csv_model_rows)

    # 3. Write overconfidence_by_model.csv (Cross-join proxy with pillar_matrix)
    cur.execute("""
    SELECT p.model, p.cell_label, COUNT(op.id) as evals_count, AVG(op.confidence_score) as avg_conf
    FROM overconfidence_proxy op
    JOIN pillar_matrix p ON op.program_id = p.program_id
    GROUP BY p.model, p.cell_label
    ORDER BY p.model, evals_count DESC
    """)
    cross_rows = cur.fetchall()
    
    out_csv2 = os.path.join(RESULTS_DIR, "overconfidence_by_model.csv")
    with open(out_csv2, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Model", "Three_Pillar_Cell", "Evaluations_Count", "Mean_Self_Assessed_Confidence"])
        for r in cross_rows:
            avg_c = round(r[3], 3) if r[3] is not None else "N/A"
            writer.writerow([r[0], r[1], r[2], avg_c])

    conn.close()
    print(f"Summary JSON saved to:               {out_json}")
    print(f"Overconfidence Results CSV saved to: {out_csv1}")
    print(f"Overconfidence by Model CSV saved to:{out_csv2}")
    print("=" * 70)

if __name__ == "__main__":
    generate_overconfidence_summary()
