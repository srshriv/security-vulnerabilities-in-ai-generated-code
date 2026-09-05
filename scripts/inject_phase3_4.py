import sqlite3

def inject_mock_data():
    conn = sqlite3.connect('../corpus.db')
    
  
    conn.execute("INSERT OR REPLACE INTO formal_results (program_id, cbmc_result, violated_property) VALUES (1, 'SAT', 'array-bounds')")
    conn.execute("INSERT OR REPLACE INTO dynamic_results (program_id, afl_crashed, edge_coverage_pct) VALUES (1, 1, 0.85)")
    
    conn.execute("INSERT OR REPLACE INTO static_results (program_id, rule_id, cwe, tool) VALUES (2, 'semgrep-rule', 'CWE-121', 'Semgrep')")
    
   
    conn.execute("INSERT OR REPLACE INTO dynamic_results (program_id, afl_crashed, edge_coverage_pct) VALUES (3, 1, 0.92)")
    
    conn.commit()
    conn.close()
    print("Mock Phase 3 (Formal) and Phase 4 (Dynamic) data injected!")

if __name__ == "__main__":
    inject_mock_data()