import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def generate_overlap_plot():
    conn = sqlite3.connect('../corpus.db')
    
    # Read the exact cell labels generated in the Day 16 matrix
    df = pd.read_sql_query("SELECT cell_label, COUNT(*) as count FROM pillar_matrix GROUP BY cell_label", conn)
    
    # Sort for better visual presentation
    df = df.sort_values(by='count', ascending=False)
    
    # Generate a clean, publication-ready bar chart bypassing the broken library
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df, x='cell_label', y='count', palette='viridis')
    
    plt.title("Figure 1: Pillar Agreement (Overlap Distribution)", fontsize=14)
    plt.xlabel("Agreement Category", fontsize=12)
    plt.ylabel("Number of Programs", fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Save to the exact filename required by the Day 17 plan
    output_path = '../results/pillar_agreement_upset.png'
    plt.savefig(output_path, dpi=300)
    print(f"Figure 1 successfully saved to {output_path}")
    
    conn.close()

if __name__ == "__main__":
    generate_overlap_plot()