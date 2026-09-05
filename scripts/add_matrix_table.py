import sqlite3

def fix_db():
    conn = sqlite3.connect('../corpus.db')
    
    # Adding the missing Day 16 table
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS pillar_matrix (
        program_id INTEGER PRIMARY KEY,
        model TEXT,
        language TEXT,
        static_flagged INTEGER DEFAULT 0,
        cbmc_sat INTEGER DEFAULT 0,
        asan_confirmed INTEGER DEFAULT 0,
        afl_crashed INTEGER DEFAULT 0,
        dynamic_cwe TEXT,
        edge_coverage_pct REAL,
        classification TEXT,
        cell_label TEXT,
        FOREIGN KEY(program_id) REFERENCES raw_files(program_id)
    );
    """)
    
    conn.commit()
    conn.close()
    print("Table 'pillar_matrix' added successfully!")

if __name__ == "__main__":
    fix_db()