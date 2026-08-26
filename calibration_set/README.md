# calibration_set/

This directory holds the **50 Big-Vul pre-fix C files** used for CBMC calibration (Day 5 — Student A task).

## Purpose

These files are pulled from the Big-Vul dataset (Fan et al., 2020) and represent
real-world C programs with **known, exploitable vulnerabilities** covering the
10 target CWEs of this study.  They serve as a ground-truth calibration set for:

1. **CBMC SAT-rate calibration** — target ≥ 70% SAT on these known-vulnerable files.
2. **ASAN trigger verification** — generated harnesses must trigger ASAN/UBSan on all 5 calibration SATs.
3. **Unwind bound selection** — the `--unwind N` value that achieves ≥ 70% SAT is documented as the corpus bound.

## File Naming Convention

```
<cwe_id>_<bigvul_id>_vuln.c      # vulnerable (pre-fix) version
```

Example: `CWE-121_CVE-2019-9903_vuln.c`

## How to populate

On Linux, run:

```bash
python scripts/collect_bigvul_sample.py --cwe CWE-121 CWE-122 CWE-125 CWE-787 \
    CWE-190 CWE-191 CWE-476 CWE-369 CWE-416 CWE-401 --n 5 --out calibration_set/
```

Or manually copy 5 pre-fix C files per CWE from the Big-Vul dataset into this directory.

## CBMC Calibration Commands

```bash
# For each file in calibration_set/:
cbmc file.c --unwind 10 --timeout 30 --xml-ui \
    --bounds-check --signed-overflow-check \
    --pointer-check --div-by-zero-check --nil-pointer-check \
    > results/cbmc_out/<stem>.xml 2>&1

# Parse results
python scripts/parse_cbmc_xml.py --xml-dir results/cbmc_out/

# If SAT rate < 70%, retry:
cbmc file.c --unwind 15 ...
```

## Current Status

- [ ] Files not yet downloaded (requires Linux environment with Big-Vul dataset access)
- [ ] CBMC calibration run: pending
- [ ] Unwind bound: TBD

## References

- Fan, J. et al. (2020). A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries.
  MSR 2020. https://dl.acm.org/doi/10.1145/3379597.3387501
- Big-Vul GitHub: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
