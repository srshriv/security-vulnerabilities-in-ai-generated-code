"""
final_corpus_table_pure.py
--------------------------
Generates results/corpus_table.csv directly from pure database queries
and the empirically computed Kappa score.
"""

import os
import sqlite3
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

def generate_pure_corpus_table(kappa_score=0.85):
    conn = sqlite3.connect(DB_PATH)
    
    query = """
    SELECT 
        source,
        model, 
        language, 
        COUNT(*) as total_programs,
        COUNT(*) as final_analyzed
    FROM filtered_files
    WHERE stage1 = 'PASSED'
    GROUP BY source, model, language
    ORDER BY language ASC, total_programs DESC
    """
    df = pd.read_sql_query(query, conn)
    df['stage2_kappa_score'] = kappa_score
    
    output_path = os.path.join(BASE_DIR, 'results', 'corpus_table.csv')
    df.to_csv(output_path, index=False)
    print(f"Empirical corpus table saved to {output_path}")
    print(f"Total Unique Programs Analyzed: {df['final_analyzed'].sum()}")
    conn.close()

if __name__ == '__main__':
    from compute_empirical_kappa import compute_empirical_kappa
    k = compute_empirical_kappa()
    generate_pure_corpus_table(kappa_score=k)
