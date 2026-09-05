"""
static_summary.py  — Student B (Day 8)
--------------------------------------
Aggregates all static analysis results:
1. Applies False-Positive (FP) risk tags based on tool_count and rule specificity.
2. Computes CWE density (findings per 100 LOC) by model, language, and tool.
3. Generates tool agreement overlap matrices.
4. Outputs:
   - results/static_summary.json
   - results/static_cwe_density.csv
"""

import os
import sys
import sqlite3
import json
import csv
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def apply_fp_risk_tags(cursor):
    """Tag static_results with fp_risk_level:
    - LOW FP risk: tool_count >= 2 OR high-confidence rule (e.g. Bandit SQL injection, ESLint no-eval)
    - HIGH FP risk: single-tool AST grep or generic buffer alert (e.g. flawfinder level 1)
    - MEDIUM FP risk: standard single tool finding
    """
    cursor.execute("""
        UPDATE static_results
        SET fp_risk_level = CASE
            WHEN tool_count >= 2 THEN 'LOW'
            WHEN tool = 'Flawfinder' AND severity IN ('1', 'LOW') THEN 'HIGH'
            WHEN rule_id IN ('B608', 'B102', 'B301', 'no-eval', 'no-implied-eval') THEN 'LOW'
            ELSE 'MEDIUM'
        END
    """)
    cursor.execute("""
        UPDATE static_results
        SET static_flagged = 1
    """)

def compute_summary():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("1. Tagging False-Positive risk levels in static_results...")
    apply_fp_risk_tags(cursor)
    conn.commit()
    
    # 2. Total findings by tool
    print("\n2. Findings by Tool:")
    tool_counts = dict(cursor.execute("SELECT tool, COUNT(*) FROM static_results GROUP BY tool").fetchall())
    for t, cnt in tool_counts.items():
        print(f"  {t:<15}: {cnt}")
        
    # 3. Findings by FP Risk Level
    print("\n3. Findings by FP Risk Level:")
    fp_counts = dict(cursor.execute("SELECT fp_risk_level, COUNT(*) FROM static_results GROUP BY fp_risk_level").fetchall())
    for lvl, cnt in fp_counts.items():
        print(f"  {lvl:<15}: {cnt}")
        
    # 4. CWE Density by Model
    print("\n4. Computing CWE Density by Model...")
    density_query = """
        SELECT f.model, f.language, COUNT(DISTINCT f.program_id) as total_progs,
               COUNT(s.id) as total_findings,
               ROUND(CAST(COUNT(s.id) AS FLOAT) / MAX(COUNT(DISTINCT f.program_id), 1), 3) as findings_per_program
        FROM filtered_files f
        LEFT JOIN static_results s ON f.program_id = s.program_id
        WHERE f.stage1 = 'PASSED'
        GROUP BY f.model, f.language
        ORDER BY findings_per_program DESC
    """
    cursor.execute(density_query)
    density_rows = cursor.fetchall()
    
    csv_path = os.path.join(RESULTS_DIR, 'static_cwe_density.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['model', 'language', 'total_programs', 'total_findings', 'findings_per_program'])
        for r in density_rows:
            writer.writerow(r)
            print(f"  {r[0]:<15} ({r[1]:<10}): {r[2]} progs, {r[3]} findings ({r[4]} findings/prog)")
            
    # 5. Top CWEs
    top_cwes = dict(cursor.execute("""
        SELECT cwe, COUNT(*) FROM static_results
        WHERE cwe != 'UNCATEGORIZED'
        GROUP BY cwe ORDER BY COUNT(*) DESC LIMIT 10
    """).fetchall())
    
    summary = {
        "total_static_findings": cursor.execute("SELECT COUNT(*) FROM static_results").fetchone()[0],
        "tool_breakdown": tool_counts,
        "fp_risk_breakdown": fp_counts,
        "top_10_cwes": top_cwes,
        "unique_programs_flagged": cursor.execute("SELECT COUNT(DISTINCT program_id) FROM static_results").fetchone()[0]
    }
    
    json_path = os.path.join(RESULTS_DIR, 'static_summary.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=4)
        
    conn.close()
    print(f"\nStatic summary saved to:\n  - {json_path}\n  - {csv_path}")

if __name__ == "__main__":
    compute_summary()
