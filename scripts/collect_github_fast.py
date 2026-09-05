import os
import sys
import time
import sqlite3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env'))


class _Tee:
    def __init__(self, log_path):
        self._stdout = sys.__stdout__
        self._stderr = sys.__stderr__
        self._log = open(log_path, 'a', encoding='utf-8', buffering=1)

    def write(self, data):
        self._stdout.write(data)
        self._stdout.flush()
        self._log.write(data)
        self._log.flush()

    def flush(self):
        self._stdout.flush()
        self._log.flush()

    def close(self):
        self._log.close()


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

TARGET_COUNTS = {'C': 2500, 'Python': 4600, 'JavaScript': 4600}

AI_KEYWORDS = [
    'copilot', 'chatgpt', 'gpt4', 'gpt-4', 'claude',
    'gemini', 'deepseek', 'codeium', 'tabnine'
]

SEARCH_MIN_INTERVAL = 7.5
CONTENT_WORKERS = 16
last_search_call = [0.0]

# Global session with connection pooling
session = requests.Session()
adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=Retry(total=2, backoff_factor=0.5))
session.mount('https://', adapter)
session.mount('http://', adapter)


def init_db(conn):
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS raw_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_name TEXT, file_path TEXT, language TEXT,
            search_keyword TEXT, ai_tool TEXT, file_content TEXT,
            keyword_in_comment INTEGER DEFAULT 0,
            UNIQUE(repo_name, file_path)
        )
    ''')
    conn.commit()


def get_existing_counts(conn):
    return dict(conn.execute("SELECT language, COUNT(*) FROM raw_files GROUP BY language").fetchall())


def paced_search_get(url, headers):
    elapsed = time.time() - last_search_call[0]
    if elapsed < SEARCH_MIN_INTERVAL:
        time.sleep(SEARCH_MIN_INTERVAL - elapsed)
    resp = session.get(url, headers=headers, timeout=20)
    last_search_call[0] = time.time()
    return resp


def handle_rate_limit(resp):
    if resp.status_code in (403, 429):
        retry_after = resp.headers.get('Retry-After')
        if retry_after:
            wait = int(retry_after) + 2
        else:
            reset_time = int(resp.headers.get('X-RateLimit-Reset', time.time() + 60))
            wait = max(reset_time - int(time.time()) + 5, 10)
        print(f"[rate limit] sleeping {wait}s")
        time.sleep(wait)
        return True
    return False


def fetch_file_content(item, lang, keyword, headers):
    """Network worker with pooled session and fast timeout."""
    try:
        repo_name = item.get('repository', {}).get('full_name', '')
        file_path = item.get('path', '')
        html_url  = item.get('html_url', '')
        if not repo_name or not file_path or not html_url:
            return None

        raw_url = (html_url
                   .replace('github.com', 'raw.githubusercontent.com')
                   .replace('/blob/', '/'))

        try:
            resp = session.get(raw_url, headers=headers, timeout=6)
            if resp.status_code != 200:
                return None
            content = resp.text
        except Exception:
            return None

        if not content:
            return None
        stripped = content.strip()
        if len(stripped.encode('utf-8')) < 150:
            return None
        low = stripped[:120].lower()
        if low.startswith('<!doctype') or low.startswith('<html'):
            return None

        return (repo_name, file_path, lang, keyword, content)
    except Exception:
        return None


def collect():
    log_path = os.path.join(BASE_DIR, 'scripts', 'collection_fast.log')
    tee = _Tee(log_path)
    sys.stdout = tee
    sys.stderr = tee

    try:
        print(f"\n{'='*60}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] fast-collector started pid={os.getpid()}")
        token = os.getenv('GITHUB_PAT') or os.getenv('GITHUB_TOKEN') or ""
        print(f"PAT length={len(token)}")

        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Security-Vulnerability-Research-Harvester'
        }

        conn = sqlite3.connect(DB_PATH)
        init_db(conn)
        counts = get_existing_counts(conn)
        print(f"Current counts: {counts}")
        print(f"Targets:        {TARGET_COUNTS}")
        print("=" * 60)

        for lang, target in TARGET_COUNTS.items():
            current = counts.get(lang, 0)
            if current >= target:
                print(f"[{lang}] at target ({current}/{target}), skipping")
                continue
            print(f"[{lang}] need {target - current} more")

            for keyword in AI_KEYWORDS:
                if current >= target:
                    break
                page = 1
                while current < target and page <= 10:
                    query = f"{keyword} language:{lang}"
                    url = f"https://api.github.com/search/code?q={query}&per_page=100&page={page}"
                    print(f"[{lang}/{keyword}] p{page} searching...")
                    resp = paced_search_get(url, headers)

                    if handle_rate_limit(resp):
                        continue
                    if resp.status_code != 200:
                        print(f"[{lang}/{keyword}] HTTP {resp.status_code}: {resp.text[:200]}")
                        break

                    data = resp.json()
                    items = data.get('items', [])
                    print(f"[{lang}/{keyword}] p{page} got {len(items)} (total={data.get('total_count','?')})")
                    if not items:
                        break

                    stored = 0
                    with ThreadPoolExecutor(max_workers=CONTENT_WORKERS) as ex:
                        futures = [ex.submit(fetch_file_content, it, lang, keyword, headers) for it in items]
                        for f in as_completed(futures):
                            try:
                                res = f.result()
                                if res:
                                    repo_name, file_path, l, kw, content = res
                                    try:
                                        conn.execute(
                                            'INSERT INTO raw_files (repo_name, file_path, language, search_keyword, ai_tool, file_content, keyword_in_comment) VALUES (?, ?, ?, ?, ?, ?, 0)',
                                            (repo_name, file_path, l, kw, kw, content)
                                        )
                                        conn.commit()
                                        current += 1
                                        stored += 1
                                        if current % 10 == 0:
                                            print(f"[{lang}] {current}/{target}")
                                    except sqlite3.IntegrityError:
                                        pass
                            except Exception as ex_err:
                                print(f"worker error: {ex_err}")

                            if current >= target:
                                break

                    print(f"[{lang}/{keyword}] p{page} stored {stored}/{len(items)} | total {current}/{target}")
                    page += 1

            print(f"[{lang}] done: {current}/{target}")

        conn.close()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Done.")
    except Exception as main_err:
        print(f"Fatal error in collect(): {main_err}")
        traceback.print_exc(file=sys.stdout)
    finally:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        tee.close()


if __name__ == "__main__":
    collect()
