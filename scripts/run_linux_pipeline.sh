#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."
export PYTHONUNBUFFERED=1

echo "==========================================================================="
echo "STEP 1: Checking Python coverage package"
echo "==========================================================================="
python3 -c "import coverage; print('coverage version:', coverage.__version__)"

echo "==========================================================================="
echo "STEP 2: Initial Quick Smoke Tests (limit/calls)"
echo "==========================================================================="
echo "[2a] Testing overconfidence proxy (20 calls)..."
python3 scripts/run_overconfidence_proxy.py --calls 20

echo "[2b] Testing atheris fuzzing (50 programs)..."
python3 scripts/run_atheris_fuzzing.py --limit 50

echo "[2c] Testing edge coverage (50 programs)..."
python3 scripts/edge_coverage.py --limit 50

echo "==========================================================================="
echo "STEP 3: Full Dynamic Runs"
echo "==========================================================================="
echo "[3a] Running full Atheris fuzzing on Python corpus..."
python3 scripts/run_atheris_fuzzing.py

echo "[3b] Running full Edge Coverage measurement..."
python3 scripts/edge_coverage.py

echo "[3c] Running Overconfidence Proxy..."
python3 scripts/run_overconfidence_proxy.py --calls 1000

echo "[3d] Running dynamic summary & CSV generation..."
python3 scripts/dynamic_summary.py

echo "==========================================================================="
echo "STEP 4: Pillar Matrix & Headline Metrics Calculation"
echo "==========================================================================="
echo "[4a] Building 3-Pillar Matrix..."
python3 scripts/build_pillar_matrix.py

echo "[4b] Computing Headline Metrics..."
python3 scripts/compute_headline_metrics.py

echo "==========================================================================="
echo "STEP 5: Regenerating Summary JSONs and Figures"
echo "==========================================================================="
echo "[5a] KLEE benefit evaluation..."
python3 scripts/klee_benefit.py || true

echo "[5b] Calibration table..."
python3 scripts/calibration_table.py || true

echo "[5c] Kappa report..."
python3 scripts/kappa_report.py || true

echo "[5d] Coverage violin plot..."
python3 scripts/coverage_violin.py || true

echo "[5e] UpSet plot..."
python3 scripts/upset_plot.py || true

echo "[5f] CWE heatmap..."
python3 scripts/cwe_heatmap.py || true

echo "[5g] Static overlap plot..."
python3 scripts/static_overlap.py || true

echo "==========================================================================="
echo "STEP 6: Final QA Audit"
echo "==========================================================================="
python3 scripts/list_all_outputs.py

echo "==========================================================================="
echo "LINUX RUNS COMPLETED SUCCESSFULLY"
echo "==========================================================================="
