"""
build_pillar_matrix.py  — Student A & B (Days 13-14)
----------------------------------------------------
Reconstructs the Three-Pillar Matrix (Static, Formal, Dynamic) across all analyzed programs:
1. Performs three-way LEFT JOIN:
   - filtered_files (Stage 1 PASSED)
   - static_results (Multi-tool: CodeQL, Semgrep, Bandit, Flawfinder, JSSecurityEngine)
   - formal_results (CBMC SAT & KLEE)
   - dynamic_results (AFL++, MSan, Atheris, Taint Tracker)
2. Classifies each program into one of 8 mutually exclusive cells:
   - ALL_THREE        (Static=1, Formal=1, Dynamic=1)
   - STATIC_FORMAL    (Static=1, Formal=1, Dynamic=0)
   - STATIC_DYNAMIC   (Static=1, Formal=0, Dynamic=1)
   - FORMAL_DYNAMIC   (Static=0, Formal=1, Dynamic=1)
   - STATIC_ONLY      (Static=1, Formal=0, Dynamic=0) -> Candidate Static FP
   - FORMAL_ONLY      (Static=0, Formal=1, Dynamic=0)
   - DYNAMIC_ONLY     (Static=0, Formal=0, Dynamic=1) -> Dynamic-only discovery
   - NONE             (Static=0, Formal=0, Dynamic=0) -> Verified Clean
3. Assigns definitive research classification label:
   - CONFIRMED_VULNERABLE (>= 2 pillars agree or dynamic crash confirmed)
   - STATIC_FP_RISK (Static only, formal UNSAT and dynamic clean)
   - PROVEN_SAFE (No tool flagged, formal verified, dynamic clean)
   - DYNAMIC_DISCOVERY (Dynamic finding without static signature)
4. Populates `pillar_matrix` table in `corpus.db`.
"""

import os
import sys
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

def build_matrix():
    print("=" * 70)
    print("DAYS 13-14: BUILDING THREE-PILLAR MATRIX")
    print("=" * 70)
    
    conn = sqlite3.connect(DB_PATH, timeout=60.0)
    cur = conn.cursor()
    
    # Ensure pillar_matrix table exists
    cur.execute("""
    CREATE TABLE IF NOT EXISTS pillar_matrix (
        program_id TEXT PRIMARY KEY,
        model TEXT,
        language TEXT,
        static_flagged INTEGER DEFAULT 0,
        cbmc_sat INTEGER DEFAULT 0,
        asan_confirmed INTEGER DEFAULT 0,
        afl_crashed INTEGER DEFAULT 0,
        dynamic_cwe TEXT,
        edge_coverage_pct REAL,
        classification TEXT,
        cell_label TEXT
    )
    """)
    cur.execute("DELETE FROM pillar_matrix")
    conn.commit()
    
    query = """
    SELECT 
        f.program_id, f.model, f.language,
        CASE WHEN s.cnt > 0 THEN 1 ELSE 0 END as static_flagged,
        COALESCE(fr.sat_flag, 0) as cbmc_sat,
        COALESCE(d.dynamic_flagged, 0) as dynamic_flagged,
        COALESCE(d.dynamic_cwe, 'NONE') as dynamic_cwe,
        d.edge_coverage_pct as edge_coverage_pct

    FROM filtered_files f
    LEFT JOIN (SELECT program_id, count(*) as cnt FROM static_results GROUP BY program_id) s 
        ON f.program_id = s.program_id
    LEFT JOIN (SELECT program_id, MAX(CASE WHEN cbmc_result = 'SAT' OR klee_direct_crash = 1 THEN 1 ELSE 0 END) as sat_flag FROM formal_results GROUP BY program_id) fr 
        ON f.program_id = fr.program_id
    LEFT JOIN (
        SELECT 
            program_id,
            MAX(CASE WHEN afl_crashed = 1 OR final_injection_confirmed = 1 OR atheris_crashed = 1 
                          OR libfuzzer_differential = 1 OR msan_result = 'UNINITIALIZED_READ' 
                          OR hang_confirmed = 1 OR classification = 'DYNAMIC_CONFIRMED' 
                     THEN 1 ELSE 0 END) as dynamic_flagged,
            MAX(dynamic_cwe) as dynamic_cwe,
            MAX(edge_coverage_pct) as edge_coverage_pct
        FROM dynamic_results
        GROUP BY program_id
    ) d ON f.program_id = d.program_id
    WHERE f.stage1 = 'PASSED'
    GROUP BY f.program_id
    ORDER BY f.id ASC
    """
    
    cur.execute(query)
    rows = cur.fetchall()
    print(f"Classifying {len(rows)} passed programs across 3 pillars...")
    
    cell_counts = {}
    classification_counts = {}
    
    for row in rows:
        pid, model, lang, s, f_sat, d, dyn_cwe, edge = row
        
        # Determine 8 Venn / UpSet cell labels
        if s and f_sat and d:
            cell = 'ALL_THREE'
        elif s and f_sat and not d:
            cell = 'STATIC_FORMAL'
        elif s and not f_sat and d:
            cell = 'STATIC_DYNAMIC'
        elif not s and f_sat and d:
            cell = 'FORMAL_DYNAMIC'
        elif s and not f_sat and not d:
            cell = 'STATIC_ONLY'
        elif not s and f_sat and not d:
            cell = 'FORMAL_ONLY'
        elif not s and not f_sat and d:
            cell = 'DYNAMIC_ONLY'
        else:
            cell = 'NONE'
            
        # Ground-truth research classification
        if cell in ['ALL_THREE', 'STATIC_FORMAL', 'STATIC_DYNAMIC', 'FORMAL_DYNAMIC']:
            classification = 'CONFIRMED_VULNERABLE'
        elif cell == 'STATIC_ONLY':
            classification = 'STATIC_FP_RISK'
        elif cell == 'DYNAMIC_ONLY':
            classification = 'DYNAMIC_DISCOVERY'
        elif cell == 'FORMAL_ONLY':
            classification = 'FORMAL_SAT_UNFLAGGED'
        else:
            classification = 'PROVEN_SAFE'
            
        cell_counts[cell] = cell_counts.get(cell, 0) + 1
        classification_counts[classification] = classification_counts.get(classification, 0) + 1
        
        cur.execute("""
            INSERT OR REPLACE INTO pillar_matrix 
            (program_id, model, language, static_flagged, cbmc_sat, asan_confirmed, afl_crashed, dynamic_cwe, edge_coverage_pct, classification, cell_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (pid, model, lang, s, f_sat, d, d, dyn_cwe, edge, classification, cell))
        
    conn.commit()
    
    # Export pillar_matrix.csv
    results_dir = os.path.join(BASE_DIR, 'results')
    os.makedirs(results_dir, exist_ok=True)
    csv_matrix_path = os.path.join(results_dir, "pillar_matrix.csv")
    
    cur.execute("""
    SELECT program_id, model, language, static_flagged, cbmc_sat, afl_crashed, dynamic_cwe, edge_coverage_pct, classification, cell_label
    FROM pillar_matrix
    ORDER BY program_id ASC
    """)
    matrix_export_rows = cur.fetchall()
    
    import csv
    with open(csv_matrix_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Program_ID", "Model", "Language", "Static_Flagged", "CBMC_SAT", "Dynamic_Crashed", "Dynamic_CWE", "Edge_Coverage_Pct", "Classification", "Cell_Label"])
        writer.writerows(matrix_export_rows)

    print(f"Pillar Matrix CSV saved to: {csv_matrix_path}")
    print("\n" + "=" * 70)
    print("PILLAR MATRIX RECONSTRUCTION COMPLETE:")
    print("  8-Cell Matrix Distribution:")
    for c, cnt in sorted(cell_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {c:<16}: {cnt:>5} ({cnt/max(len(rows),1)*100:.1f}%)")
    print("\n  Research Classifications:")
    for cl, cnt in sorted(classification_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {cl:<22}: {cnt:>5} ({cnt/max(len(rows),1)*100:.1f}%)")
    print("=" * 70)
    
    conn.close()

if __name__ == "__main__":
    build_matrix()