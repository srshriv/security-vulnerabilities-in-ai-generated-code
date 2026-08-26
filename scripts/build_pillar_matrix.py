import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

def build_matrix():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Day 16: Three-way LEFT JOIN
    query = """
    SELECT 
        f.program_id, f.model, f.language,
        CASE WHEN s.static_flagged IS NOT NULL THEN 1 ELSE 0 END as static_flagged,
        CASE WHEN fr.cbmc_result = 'SAT' THEN 1 ELSE 0 END as cbmc_sat,
        COALESCE(d.afl_crashed, 0) as afl_crashed,
        COALESCE(d.edge_coverage_pct, 0) as edge_coverage_pct
    FROM filtered_files f
    LEFT JOIN (SELECT program_id, 1 as static_flagged FROM static_results GROUP BY program_id) s 
        ON f.program_id = s.program_id
    LEFT JOIN formal_results fr ON f.program_id = fr.program_id
    LEFT JOIN dynamic_results d ON f.program_id = d.program_id
    WHERE f.language = 'C' AND f.stage1 = 'PASSED'
    """
    
    cursor.execute(query)
    rows = cursor.fetchall()
    
    count = 0
    for row in rows:
        prog_id, model, lang, s, f_sat, d, edge = row
        
        # Determine the 8 matrix cells
        if s and f_sat and d: label = 'ALL_THREE'
        elif s and f_sat and not d: label = 'STATIC_FORMAL'
        elif s and not f_sat and d: label = 'STATIC_DYNAMIC'
        elif not s and f_sat and d: label = 'FORMAL_DYNAMIC'
        elif s and not f_sat and not d: label = 'STATIC_ONLY'
        elif not s and f_sat and not d: label = 'FORMAL_ONLY'
        elif not s and not f_sat and d: label = 'DYNAMIC_ONLY'
        else: label = 'NONE'
        
        cursor.execute('''
            INSERT OR REPLACE INTO pillar_matrix 
            (program_id, model, language, static_flagged, cbmc_sat, afl_crashed, edge_coverage_pct, cell_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (prog_id, model, lang, s, f_sat, d, edge, label))
        count += 1
        
    conn.commit()
    conn.close()
    print(f"Pillar Matrix built successfully! Classified {count} C programs.")

if __name__ == "__main__":
    build_matrix()