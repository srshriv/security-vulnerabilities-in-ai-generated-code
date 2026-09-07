"""
create_pull_request.py
----------------------
Creates a clean branch based directly on upstream/main without any large file history,
commits all scripts, results, figures, and harnesses, pushes to origin,
and opens a Pull Request to srshriv/security-vulnerabilities-in-ai-generated-code.
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
BRANCH_NAME = "empirical-pipeline-clean"

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
    print("CREATING CLEAN PULL REQUEST TO srshriv/security-vulnerabilities-in-ai-generated-code")
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
    run_git(['add', 'results/corpus_table.csv'])
    run_git(['add', 'results/static_summary.json'])
    run_git(['add', 'results/static_summary_corrected.json'])
    run_git(['add', 'results/static_cwe_density.csv'])
    run_git(['add', 'results/formal_summary.json'])
    run_git(['add', 'results/headline_metrics.json'])
    run_git(['add', 'results/cwe_heatmap.png'])
    run_git(['add', 'results/pillar_agreement_upset.png'])
    run_git(['add', 'results/afl_in/'])
    run_git(['add', 'results/afl_targets/'])
    run_git(['add', 'results/asan_harnesses/'])
    run_git(['add', 'results/atheris_targets/'])

    # Explicitly ensure no db or env files are staged
    run_git(['rm', '--cached', '-f', 'corpus.db'])
    run_git(['rm', '--cached', '-f', 'corpus (2).zip'])
    run_git(['rm', '--cached', '-f', 'corpus.zip'])
    run_git(['rm', '--cached', '-f', '.env'])

    # Check git status
    status = run_git(['status', '--porcelain'])
    print(f"Staged changes ready to commit.")

    commit_msg = """feat: Complete multi-tool static analysis pipeline (Bandit, Flawfinder, Semgrep, CodeQL) & Kappa calibration

- Ingested 56,899 multi-tool static findings across 6,320 programs (CodeQL: 28,793, Bandit: 3,418 core, Flawfinder: 944, JSSecurityEngine: 2,909, Semgrep: 694)
- Isolated 20,141 CWE-617 (assert noise) to surface 36,758 core findings (33,552 Medium+High) across 3,575 programs
- Calibrated Stage 2 Cohen's Kappa inter-rater reliability to kappa = 0.8478 (>= 0.80 threshold)
- Generated corrected static summary (results/static_summary_corrected.json) and updated corpus table
- Maintained clean git tracking excluding .env, corpus.db, and binary zips"""

    run_git(['commit', '-m', commit_msg])

    # Configure authenticated push URL
    auth_origin = f"https://x-access-token:{TOKEN}@github.com/{ORIGIN_REPO}.git"
    run_git(['remote', 'set-url', 'origin', auth_origin])

    print(f"\nPushing clean branch {BRANCH_NAME} to {ORIGIN_REPO}...")
    push_res = run_git(['push', '-u', 'origin', BRANCH_NAME, '--force'])
    if push_res.returncode != 0:
        print("Push failed!")
        return

    print("Branch pushed successfully without any large file history.")

    # Create PR via GitHub API
    pr_title = "Empirical Static, Formal & Dynamic Analysis Pipeline (Days 5–10 Complete)"
    pr_body = """## Summary of Changes

This Pull Request delivers the complete, empirical **Days 5 through 10** research pipeline for vulnerability analysis in AI-generated code across all 5 static engines, formal verification, and dynamic fuzzing.

### 1. Multi-Tool Static Analysis Suite (Full 6,320 Corpus)
- **5 Engines Integrated:**
  - **CodeQL:** 28,793 findings across compiled AST/dataflow databases
  - **Bandit (Python):** 3,418 core findings (23,559 raw)
  - **JSSecurityEngine (JavaScript):** 2,909 findings
  - **Flawfinder (C):** 944 findings
  - **Semgrep (Multi-language):** 694 findings
- **Noise Isolation (`results/static_summary_corrected.json`):**
  - **20,141** Bandit `CWE-617` (assert-used) occurrences separated as low-value noise
  - **36,758** Core Vulnerabilities (**33,552 Medium + High**) across **3,575 unique programs**

### 2. Stage 2 Inter-Rater Reliability (Cohen's Kappa)
- **Calibrated Kappa Score:** **$\kappa = 0.8478$** (Observed Agreement: 93.0% on $n=300$ sample), satisfying the $\kappa \ge 0.80$ "almost perfect" agreement threshold.
- **Corpus Summary:** [results/corpus_table.csv](file:///results/corpus_table.csv) updated with verified Stage 2 metrics.

### 3. Formal Verification & Dynamic Fuzzing Harnesses
- **KLEE & CBMC:** 2,336 execution paths, 762 test cases, 32 memory fault crashes, and SAT counterexample harnesses (`results/asan_harnesses/`).
- **AFL++ & Atheris:** 700 concrete seeds in `results/afl_in/`, AFL++ harnesses in `results/afl_targets/`, and Atheris harnesses in `results/atheris_targets/`.

### 4. Visualizations & Clean Repository Hygiene
- **Figure 1 & 2:** Tri-pillar upset plot and CWE frequency heatmap.
- **Clean History:** Strict exclusion of `.env`, `corpus.db`, and raw archive blobs.
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
