# Environment Setup Guide

## Overview

The pipeline has two environments:
- **Windows** (this machine): corpus collection, filtering, DB management, script development
- **Linux** (`linux_env/` virtual env or WSL/remote): CBMC, AFL++, ASAN, CodeQL, Semgrep, Bandit, Flawfinder

---

## 1. Python Environment

### Windows
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Linux
```bash
source linux_env/bin/activate
pip install -r requirements.txt
# Additional Linux tools:
pip install bandit semgrep flawfinder
```

---

## 2. Static Analysis Tools

| Tool | Version | Status | Install |
|------|---------|--------|---------|
| Python | 3.12.3 | ✅ | — |
| clang | 18.1.3 | ✅ Linux | `apt install clang` |
| gcc | 13.3.0 | ✅ Linux | `apt install gcc` |
| ESLint | 6.4.0 | ✅ | `npm install -g eslint eslint-plugin-security` |
| CodeQL | 2.26.1 | ✅ Linux | `/home/kiit/codeql/codeql` |
| cbmc | 5.95.1 | ✅ Linux | `apt install cbmc` |
| afl-clang-fast | 17.0.6 | ✅ Linux | `apt install afl++` |
| bandit | — | ⚠️ Missing | `pip install bandit` |
| semgrep | — | ⚠️ Missing | `pip install semgrep` |
| flawfinder | — | ⚠️ Missing | `pip install flawfinder` |
| klee | — | ⚠️ Missing | Build from source |

---

## 3. CBMC Usage (Student A — Day 5)

```bash
# Calibration run (unwind 10, timeout 30s)
cbmc calibration_set/CWE-121_example.c \
    --unwind 10 --timeout 30 --xml-ui \
    --bounds-check --signed-overflow-check \
    --pointer-check --div-by-zero-check --nil-pointer-check \
    > results/cbmc_out/prog_000001.xml 2>&1

# Parse results
python scripts/parse_cbmc_xml.py

# Generate ASAN harnesses from SAT counterexamples
python scripts/generate_asan_harness.py

# Compile and run harness
gcc -fsanitize=address,undefined -g -O0 \
    -o results/asan_harnesses/prog_000001/harness \
    results/asan_harnesses/prog_000001/harness.c \
    <source_file.c>
./results/asan_harnesses/prog_000001/harness
```

---

## 4. AFL++ Usage (Student B — Day 5)

```bash
# Pick 5 C programs from calibration_set
# Write a trivial harness (read from stdin, call vulnerable function)
# Compile with AFL++:
afl-clang-fast -g -O1 -o fuzz_target harness.c target.c

# Run AFL++ for 30 seconds:
AFL_SKIP_CPUFREQ=1 timeout 30 \
    afl-fuzz -i corpus_in/ -o corpus_out/ -- ./fuzz_target @@

# Check for crashes:
ls corpus_out/crashes/

# Get stack frame from crash:
addr2line -e fuzz_target -f <address>
afl-tmin -i corpus_out/crashes/id:000000 -o minimised -- ./fuzz_target @@
```

---

## 5. CodeQL Usage (Student B — Day 5)

```bash
# Create CodeQL database for a C program
/home/kiit/codeql/codeql database create results/codeql_db/ \
    --language=cpp --command="gcc -c target.c" --overwrite

# Run security queries
/home/kiit/codeql/codeql database analyze results/codeql_db/ \
    --format=sarif-latest \
    --output=results/static_raw/codeql_prog_000001.sarif \
    codeql/cpp-queries:CplusPlus/Security/...

# Ingest
python scripts/ingest_sarif.py --input results/static_raw/codeql_prog_000001.sarif --tool CodeQL
```

---

## 6. Bandit Usage (Student B — Day 5)

```bash
# Run Bandit on Python file
bandit -f json -o results/static_raw/bandit_prog_000001.json <file.py>

# Batch run
for f in $(sqlite3 corpus.db "SELECT file_path FROM filtered_files WHERE language='Python' AND stage1='PASSED' LIMIT 20"); do
    pid=$(sqlite3 corpus.db "SELECT program_id FROM filtered_files WHERE file_path='$f'")
    bandit -f json -o results/static_raw/bandit_${pid}.json "$f"
done

# Ingest
python scripts/ingest_bandit.py --batch
```

---

## 7. Database Path

All scripts use:
```python
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')
```

The database is at: `security-vulnerabilities-in-ai-generated-code/corpus.db`

---

## 8. Phase 1 Completion Checklist

- [x] Schema applied (`schema.sql`)
- [x] Raw collection (11,768 files: C=2568, JS=4600, Py=4600)
- [x] Stage 1 filter (3,578 passed; near-dup detection active)
- [x] `securityeval_extended.json` (80 prompts, 10 CWEs)
- [x] `cwe_to_property.json` + `asan_to_cwe.json`
- [x] `bandit_cwe_corrections.json` (73 rules)
- [x] `final_corpus` view in DB (2,459 rows)
- [x] `ingest_sarif.py`, `ingest_bandit.py`, `ingest_devaic.py`, `ingest_eslint.py` (fixed)
- [x] `parse_cbmc_xml.py` (fixed)
- [x] `generate_asan_harness.py` (Jinja2, --dry-run)
- [x] `apply_stage2.py` (majority-vote stage2 propagation)
- [x] `rater_tool.py` (--rater flag, cross-rater agreement table)
- [ ] CBMC calibration on 50 Big-Vul files (Linux)
- [ ] AFL++ smoke test on 5 calibration SATs (Linux)
- [ ] Static tool smoke test on 20-program sample (Linux)
- [ ] `synthetic_generate.py` API run (needs LLM API keys)
- [ ] Stage 2 rating sessions (rater_A + rater_B)
