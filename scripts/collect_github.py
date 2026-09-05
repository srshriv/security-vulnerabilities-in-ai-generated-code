import os
import sys
import time
import sqlite3
import requests

# -------------------------------------------------------------------
# Configuration & Absolute Path Setup
# -------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH = os.path.join(BASE_DIR, 'corpus.db')

# Target collection metrics totaling 10,000 files
TARGET_COUNTS = {
    
    
    'JavaScript': 4600
}

# Keywords to identify AI-generated or AI-assisted code commits/comments
AI_KEYWORDS = [
    'copilot', 'chatgpt', 'gpt4', 'gpt-4', 'claude', 
    'gemini', 'deepseek', 'codeium', 'tabnine'
]

def init_db(conn):
    """Creates the raw_files table with exact pipeline schema if missing."""
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS raw_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT,
            file_path TEXT,
            language TEXT,
            search_keyword TEXT,
            ai_tool TEXT,
            file_content TEXT,
            keyword_in_comment INTEGER DEFAULT 0,
            UNIQUE(repo_name, file_path)
        )
    ''')
    conn.commit()

def get_existing_counts(conn):
    """Queries existing row counts per language to allow safe resumption."""
    cursor = conn.cursor()
    cursor.execute("SELECT language, COUNT(*) FROM raw_files GROUP BY language")
    return dict(cursor.fetchall())

def handle_rate_limit(response):
    """Detects rate limits and pauses execution until token resets."""
    if response.status_code in (403, 429):
        reset_time = int(response.headers.get('X-RateLimit-Reset', time.time() + 60))
        sleep_duration = max(reset_time - int(time.time()) + 5, 10)
        print(f"\n[Rate Limit Triggered] Sleeping for {sleep_duration} seconds...")
        time.sleep(sleep_duration)
        return True
    return False

def collect_github_data():
    token = os.getenv('GITHUB_PAT') or os.getenv('GITHUB_TOKEN')
    if not token:
        print("ERROR: Neither GITHUB_PAT nor GITHUB_TOKEN environment variable is set.")
        print("Set your token using: export GITHUB_PAT='your_token_here'")
        sys.exit(1)

    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'Security-Vulnerability-Research-Harvester'
    }

    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    counts = get_existing_counts(conn)
    print("=" * 60)
    print("Starting GitHub Corpus Collection (Target: 10,000 files)")
    print(f"Current database counts: {counts}")
    print("=" * 60)

    for lang, target in TARGET_COUNTS.items():
        current_count = counts.get(lang, 0)
        if current_count >= target:
            print(f"\n[{lang}] Target of {target} already reached ({current_count} files). Skipping...")
            continue

        print(f"\n--- Collecting {lang} Files (Target: {target} | Current: {current_count}) ---")

        for keyword in AI_KEYWORDS:
            if current_count >= target:
                break

            page = 1
            # GitHub Search API limits search pagination to 10 pages (1000 items per query)
            while current_count < target and page <= 10:
                query = f"{keyword} language:{lang}"
                url = f"https://api.github.com/search/code?q={query}&per_page=100&page={page}"

                try:
                    resp = requests.get(url, headers=headers)

                    if handle_rate_limit(resp):
                        continue

                    if resp.status_code != 200:
                        print(f"API Error ({resp.status_code}): {resp.json().get('message', '')}")
                        break

                    data = resp.json()
                    items = data.get('items', [])
                    if not items:
                        break

                    for item in items:
                        if current_count >= target:
                            break

                        repo_name = item['repository']['full_name']
                        file_path = item['path']
                        raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')

                        # Fetch raw file content
                        content_resp = requests.get(raw_url, headers=headers)
                        if handle_rate_limit(content_resp):
                            content_resp = requests.get(raw_url, headers=headers)

                        if content_resp.status_code == 200:
                            file_content = content_resp.text

                            cursor = conn.cursor()
                            try:
                                cursor.execute('''
                                    INSERT INTO raw_files (
                                        repo_name, file_path, language, search_keyword, ai_tool, file_content, keyword_in_comment
                                    ) VALUES (?, ?, ?, ?, ?, ?, 0)
                                ''', (repo_name, file_path, lang, keyword, keyword, file_content))
                                conn.commit()
                                current_count += 1
                                print(f"[{lang} {current_count}/{target}] Stored: {repo_name}/{file_path}")
                            except sqlite3.IntegrityError:
                                # Skip duplicate repo + path combinations
                                pass

                        time.sleep(0.5)  # Politeness interval between file downloads

                    page += 1
                    time.sleep(2)  # Delay between API search requests

                except Exception as e:
                    print(f"Unexpected error occurred: {e}")
                    time.sleep(5)

    conn.close()
    print("\nCollection job finished successfully!")

if __name__ == "__main__":
    collect_github_data()
