import sqlite3
conn = sqlite3.connect('corpus.db')
c = conn.cursor()
c.execute('''
CREATE TABLE IF NOT EXISTS raw_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT, repo_name TEXT NOT NULL, file_path TEXT NOT NULL, 
    commit_sha TEXT, star_count INTEGER, language TEXT, raw_url TEXT, 
    search_keyword TEXT, ai_tool TEXT, file_content TEXT, collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repo_name, file_path, commit_sha)
) ''')
conn.commit()
conn.close()
print('raw_files table created successfully')