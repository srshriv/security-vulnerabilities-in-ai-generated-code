"""
_api_probe.py -- one-shot GitHub code search probe, SELECT only, no DB writes.
Hits one search query for each language and prints the response status,
item count, and any error messages. Diagnoses why the collector may be exiting.
"""
import os, sys, time, requests

token = os.getenv('GITHUB_PAT') or os.getenv('GITHUB_TOKEN')
if not token:
    print("ERROR: GITHUB_PAT not set")
    sys.exit(1)

print(f"PAT present, length={len(token)}")

headers = {
    'Authorization': f'token {token}',
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'Security-Vulnerability-Research-Probe'
}

# Check rate limit first
rl = requests.get('https://api.github.com/rate_limit', headers=headers, timeout=10)
if rl.status_code == 200:
    d = rl.json()
    core  = d['resources']['core']
    search = d['resources']['search']
    print(f"Rate limit - core:   {core['remaining']}/{core['limit']}  resets in {max(0, core['reset'] - int(time.time()))}s")
    print(f"Rate limit - search: {search['remaining']}/{search['limit']}  resets in {max(0, search['reset'] - int(time.time()))}s")
else:
    print(f"rate_limit endpoint: HTTP {rl.status_code}")

print()

# One probe query per language
probes = [
    ('C',          'copilot language:C'),
    ('Python',     'copilot language:Python'),
    ('JavaScript', 'copilot language:JavaScript'),
]

for lang, query in probes:
    url = f'https://api.github.com/search/code?q={query}&per_page=5&page=1'
    print(f"Probing [{lang}]: {query}")
    resp = requests.get(url, headers=headers, timeout=30)
    print(f"  HTTP {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        total = data.get('total_count', '?')
        items = len(data.get('items', []))
        incomplete = data.get('incomplete_results', False)
        print(f"  total_count={total}  items_returned={items}  incomplete={incomplete}")
        if items > 0:
            print(f"  sample: {data['items'][0]['repository']['full_name']} / {data['items'][0]['path']}")
    else:
        print(f"  body: {resp.text[:300]}")
    print(f"  X-RateLimit-Remaining: {resp.headers.get('X-RateLimit-Remaining', 'n/a')}")
    print()
    time.sleep(8)   # stay under 10/min code_search cap
