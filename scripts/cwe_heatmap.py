import os
import sqlite3
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

def generate_heatmap():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, 'corpus.db')
    conn = sqlite3.connect(db_path)
    
    # Join raw_files and static_results to get Model vs CWE
    query = """
    SELECT f.model, s.cwe
    FROM static_results s
    JOIN filtered_files f ON s.program_id = f.program_id
    WHERE s.cwe != 'UNCATEGORIZED'
    """
    df = pd.read_sql_query(query, conn)
    
    if df.empty:
        print("No categorized CWE data found.")
        conn.close()
        return
        
    # Create a cross-tabulation matrix
    heatmap_data = pd.crosstab(df['model'], df['cwe'])
    
    # Plot using Seaborn
    plt.figure(figsize=(10, 6))
    sns.heatmap(heatmap_data, annot=True, cmap="YlOrRd", cbar_kws={'label': 'Finding Count'}, fmt='d')
    plt.title("Figure 2: CWE Frequency by Model")
    plt.tight_layout()
    
    # Save as 300dpi PNG
    output_path = os.path.join(base_dir, 'results', 'cwe_heatmap.png')
    plt.savefig(output_path, dpi=300)
    print(f"Heatmap saved to {output_path}")
    
    conn.close()

if __name__ == "__main__":
    generate_heatmap()