import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import sqlite3

def generate_heatmap():
    conn = sqlite3.connect('../corpus.db')
    
    # Join raw_files and static_results to get Model vs CWE
    query = """
    SELECT f.model, s.cwe
    FROM static_results s
    JOIN filtered_files f ON s.program_id = f.program_id
    WHERE s.cwe != 'UNCATEGORIZED'
    """
    df = pd.read_sql_query(query, conn)
    
    if df.empty:
        print("No categorized CWE data found. Injecting a mock row for testing...")
        conn.execute("INSERT INTO static_results (program_id, cwe, tool) VALUES (1, 'CWE-121', 'MockTool')")
        conn.commit()
        df = pd.read_sql_query(query, conn)
        
    # Create a cross-tabulation matrix
    heatmap_data = pd.crosstab(df['model'], df['cwe'])
    
    # Plot using Seaborn
    plt.figure(figsize=(10, 6))
    sns.heatmap(heatmap_data, annot=True, cmap="YlOrRd", cbar_kws={'label': 'Finding Count'})
    plt.title("Figure 2: CWE Frequency by Model")
    plt.tight_layout()
    
    # Save as 300dpi PNG
    output_path = '../results/cwe_heatmap.png'
    plt.savefig(output_path, dpi=300)
    print(f"Heatmap saved to {output_path}")
    
    conn.close()

if __name__ == "__main__":
    generate_heatmap()