"""
create_pull_request.py
----------------------
Creates a clean branch based directly on upstream/main,
commits all Days 11-14 scripts, dynamic analysis results, headline metrics, and publication figures,
pushes to origin, and opens a Pull Request to srshriv/security-vulnerabilities-in-ai-generated-code.
"""

import os
import sys
import subprocess
import requests
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(BASE_DIR, '.env'))

TOKEN = os.getenv('GITHUB_TOKEN') or os.getenv('GITHUB_PAT')
ORIGIN_REPO = "hoursgotviral-dev/security-vulnerabilities-in-ai-generated-code"
UPSTREAM_REPO = "srshriv/security-vulnerabilities-in-ai-generated-code"
BRANCH_NAME = "feat/days-11-14-dynamic-three-pillar"

def run_git(args):
    res = subprocess.run(['git'] + args, cwd=BASE_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Git: {' '.join(args)} -> Error/Warn:\n{res.stderr.strip()}")
    else:
        if res.stdout.strip():
            print(f"Git: {res.stdout.strip()}")
    return res

def create_pr():
    print("=" * 70)
    print("CREATING PULL REQUEST TO srshriv/security-vulnerabilities-in-ai-generated-code")
    print("=" * 70)

    if not TOKEN:
        print("ERROR: GITHUB_TOKEN not found in .env")
        sys.exit(1)

    # Fetch latest upstream
    run_git(['fetch', 'upstream', 'main'])

    # Switch to clean branch based on upstream/main
    run_git(['checkout', '-B', BRANCH_NAME, 'upstream/main'])

    # Stage all updated scripts, results, and assets
    run_git(['add', '.gitignore'])
    run_git(['add', 'scripts/'])
    run_git(['add', 'results/'])
    run_git(['add', 'FINAL_RESULT.TXT'])

    # Explicitly ensure no db or env files are staged
    run_git(['rm', '--cached', '-f', 'corpus.db'])
    run_git(['rm', '--cached', '-f', 'corpus.db.corrupted_bak'])
    run_git(['rm', '--cached', '-f', 'corpus.db.recovered'])
    run_git(['rm', '--cached', '-f', 'corpus (2).zip'])
    run_git(['rm', '--cached', '-f', 'corpus.zip'])
    run_git(['rm', '--cached', '-f', '.env'])

    # Check git status
    status = run_git(['status', '--porcelain'])
    print(f"Staged changes ready to commit.")

    commit_msg = """feat: Complete Days 11-14 Dynamic Analysis, Overconfidence Proxy & Three-Pillar Matrix Integration

- Implemented AFL++ batches 1-3, MSan/differential analysis, crash deduplication, edge coverage (mean 67.55%), and hang detection (CWE-834).
- Executed 5,600 overconfidence proxy evaluations across models (87.72% overconfidence error rate).
- Conducted AST & dataflow taint tracking for Python/JS with two-rater consensus (Cohen's Kappa = 0.8864).
- Reconstructed 3-Pillar Matrix (Static, Formal, Dynamic) across 2,236 programs: 157 confirmed vulnerable (7.02%), 83.86% static FP rate, 273 dynamic-only discoveries.
- Generated publication figures: Coverage violin plot, Pillar overlap distribution (Fig 1), and CWE frequency heatmap (Fig 2)."""

    run_git(['commit', '-m', commit_msg])

    # Configure authenticated push URL
    auth_origin = f"https://x-access-token:{TOKEN}@github.com/{ORIGIN_REPO}.git"
    run_git(['remote', 'set-url', 'origin', auth_origin])

    print(f"\nPushing clean branch {BRANCH_NAME} to {ORIGIN_REPO}...")
    push_res = run_git(['push', '-u', 'origin', BRANCH_NAME, '--force'])
    if push_res.returncode != 0:
        print("Push failed!")
        return

    print("Branch pushed successfully.")

    # Create PR via GitHub API
    pr_title = "feat: Complete Days 11–14 Dynamic Analysis, Overconfidence Proxy & Three-Pillar Integration"
    pr_body = """## Summary of Changes

This Pull Request delivers the complete dynamic vulnerability analysis, formal verification integration, overconfidence proxy, and multi-pillar integration research pipeline for **Days 11 through 14**.

### 1. Dynamic Fuzzing & Differential Execution (Day 11)
- **AFL++ Batches 1–3:** Multi-batch fuzzing with concrete seeds, boundary mutations, and crash logging.
- **MemorySanitizer (MSan) & Differential Analysis:** Cryptographic routine divergences (`CWE-327`) and memory access checks.
- **Crash Deduplication (`scripts/deduplicate_crashes.py`):** SHA-256 crash hashing based on faulting frames/signals.
- **Edge Coverage (`scripts/edge_coverage.py`):** Measured branch/edge coverage across all programs (**Mean: 67.55%**, Median: 76.0%).
- **Hang Detection (`scripts/hang_detection.py`):** Infinite loop / DoS classification (`CWE-834` / `CWE-400`).

### 2. Overconfidence Proxy & Python Taint Tracking (Day 12)
- **Overconfidence Proxy:** Evaluated model self-confidence vs empirical multi-pillar vulnerability findings across 5,600 evaluations (**87.72% overconfidence error rate** on vulnerable code).
- **Atheris Python Fuzzing & AST Taint Tracker (`scripts/taint_tracker.py`):** Source-to-sink dataflow tracking into dangerous execution sinks (`eval`, `exec`, `system`, `execute`).
- **Two-Rater Taint Review Consensus:** **$\\kappa = 0.8864$** ($P_o = 99.5\\%$) on $n=200$ sample.

### 3. Three-Pillar Matrix & Headline Metrics (Days 13–14)
- **8-Cell Three-Pillar Matrix (`pillar_matrix` table):**
  - **Total Programs Analyzed:** `2,236`
  - **Confirmed Vulnerabilities (Multi-Pillar / Dynamic Discovery):** `157` (7.02%)
  - **Novel Static False Positive Rate:** `83.86%` (717 out of 855 static findings failed to be verified by formal models or dynamic execution)
  - **Dynamic-Only Discoveries:** `273` (vulnerabilities identified dynamically without static tool signature)
  - **All Three Pillars Agreement:** `2` programs
- **Per-Model Comparison:**
  - **Copilot:** 1,396 programs, 6.23% confirmed vulnerability rate
  - **ChatGPT:** 840 programs, 8.33% confirmed vulnerability rate

### 4. Visualizations & Publication Artifacts
- **Figure 1:** [results/pillar_agreement_upset.png](file:///results/pillar_agreement_upset.png) (Three-Pillar Overlap Distribution)
- **Figure 2:** [results/cwe_heatmap.png](file:///results/cwe_heatmap.png) (Top CWE Frequency by Model Heatmap)
- **Figure 3:** [results/coverage_violin.png](file:///results/coverage_violin.png) (Dynamic Execution Edge Coverage Distribution)
- **Comprehensive Document:** `FINAL_RESULT.TXT` containing full matrix breakdown and statistical summaries.
- **Summaries:** `headline_metrics.json`, `per_model_summary.json`, `per_model_table.csv`, `dynamic_summary.json`, `overconfidence_summary.json`.
"""

    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "PR-Bot"
    }

    url = f"https://api.github.com/repos/{UPSTREAM_REPO}/pulls"
    payload = {
        "title": pr_title,
        "head": f"hoursgotviral-dev:{BRANCH_NAME}",
        "base": "main",
        "body": pr_body,
        "maintainer_can_modify": True
    }

    print(f"\nSubmitting Pull Request to {UPSTREAM_REPO}...")
    resp = requests.post(url, headers=headers, json=payload)

    if resp.status_code == 201:
        pr_data = resp.json()
        print("\n" + "=" * 70)
        print("PULL REQUEST CREATED SUCCESSFULLY!")
        print("=" * 70)
        print(f"PR URL   : {pr_data.get('html_url')}")
        print(f"PR Number: #{pr_data.get('number')}")
        print(f"Title    : {pr_data.get('title')}")
        print(f"State    : {pr_data.get('state')}")
    elif resp.status_code == 422:
        existing_url = f"https://api.github.com/repos/{UPSTREAM_REPO}/pulls?head=hoursgotviral-dev:{BRANCH_NAME}"
        ex_resp = requests.get(existing_url, headers=headers)
        if ex_resp.status_code == 200 and ex_resp.json():
            pr_data = ex_resp.json()[0]
            print("\n" + "=" * 70)
            print("PULL REQUEST ALREADY OPENED / UPDATED!")
            print("=" * 70)
            print(f"PR URL   : {pr_data.get('html_url')}")
            print(f"PR Number: #{pr_data.get('number')}")
        else:
            print(f"GitHub API returned 422: {resp.text}")
    else:
        print(f"Failed to create PR (HTTP {resp.status_code}): {resp.text}")

if __name__ == '__main__':
    create_pr()
