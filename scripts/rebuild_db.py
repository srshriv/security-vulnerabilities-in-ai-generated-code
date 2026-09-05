import sqlite3
import os

DB_PATH = '../corpus.db'

def rebuild():
   
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print("Old database removed.")
        
    conn = sqlite3.connect(DB_PATH)
    
   
    conn.executescript("""
    CREATE TABLE raw_files (
        program_id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo TEXT, path TEXT, commit_sha TEXT, star_count INTEGER,
        language TEXT, raw_url TEXT, search_keyword TEXT, ai_tool TEXT,
        content TEXT,
        source TEXT DEFAULT 'GITHUB', 
        model TEXT, prompt_id TEXT, cwe_target TEXT
    );

    CREATE TABLE filtered_files (
        program_id INTEGER PRIMARY KEY,
        stage1 TEXT, stage1_reason TEXT, stage2 TEXT, compile_status TEXT,
        FOREIGN KEY(program_id) REFERENCES raw_files(program_id)
    );

    CREATE TABLE static_results (
        finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER, file_path TEXT, line_number INTEGER,
        rule_id TEXT, cwe TEXT, severity TEXT, tool TEXT,
        cwe_corrected INTEGER DEFAULT 0, fp_risk_level TEXT,
        FOREIGN KEY(program_id) REFERENCES raw_files(program_id)
    );

    CREATE TABLE formal_results (
        program_id INTEGER PRIMARY KEY,
        cbmc_result TEXT, violated_property TEXT, not_confirmed_reason TEXT,
        klee_seeding TEXT, klee_direct_crash INTEGER DEFAULT 0,
        FOREIGN KEY(program_id) REFERENCES raw_files(program_id)
    );

    CREATE TABLE dynamic_results (
        program_id INTEGER PRIMARY KEY,
        afl_crashed INTEGER DEFAULT 0, afl_hang INTEGER DEFAULT 0,
        hang_confirmed INTEGER DEFAULT 0, hang_cwe TEXT,
        confirmed_crash_count INTEGER DEFAULT 0, edge_coverage_pct REAL,
        dynamic_cwe TEXT, classification TEXT,
        FOREIGN KEY(program_id) REFERENCES raw_files(program_id)
    );
    """)
    conn.commit()
    conn.close()
    print("Database successfully rebuilt with ALL required columns!")

if __name__ == "__main__":
    rebuild()