import sqlite3
import json

DB_PATH = '../corpus.db'

def compute_metrics():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Aggregate counts by cell label
    cursor.execute("SELECT cell_label, COUNT(*) FROM pillar_matrix GROUP BY cell_label")
    matrix_counts = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Calculate Novel Static FP Rate (Flagged, but CBMC UNSAT and AFL didn't crash)
    cursor.execute("""
        SELECT COUNT(*) FROM pillar_matrix 
        WHERE static_flagged = 1 AND cbmc_sat = 0 AND afl_crashed = 0
    """)
    static_fps = cursor.fetchone()[0]
    
    metrics = {
        "1_total_c_programs_analyzed": sum(matrix_counts.values()),
        "2_all_three_agreement_count": matrix_counts.get("ALL_THREE", 0),
        "3_static_only_count": matrix_counts.get("STATIC_ONLY", 0),
        "4_dynamic_only_count": matrix_counts.get("DYNAMIC_ONLY", 0),
        "5_static_false_positives": static_fps,
        "note": "Metrics successfully computed from local database."
    }
    
    with open('../results/headline_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=4)
        
    print("Headline metrics computed and saved to results/headline_metrics.json")
    conn.close()

if __name__ == "__main__":
    compute_metrics()