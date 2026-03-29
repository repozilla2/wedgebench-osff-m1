#!/usr/bin/env bash
# run_m1.sh — One-command Sentinel OSFF M1 runner
#
# Usage: ./run_m1.sh
# Requirements: Python 3.10+, GCC
#
# On success: exits 0 and prints evidence artifact path
# On failure: exits nonzero with diagnostic

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo "═══════════════════════════════════════════════════"
echo "  Sentinel OSFF M1 — One-Command Runner"
echo "═══════════════════════════════════════════════════"

# Check dependencies
echo ""
echo "── Checking dependencies ──"
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }
command -v gcc     >/dev/null 2>&1 || { echo "ERROR: gcc not found"; exit 1; }
echo "  python3: $(python3 --version)"
echo "  gcc:     $(gcc --version | head -1)"

# Step 1: Generate corpus
echo ""
echo "── Step 1/3: Generating corpus ──"
python3 tools/generate_corpus.py

# Step 2: Run fuzz harness
echo ""
echo "── Step 2/3: Running fuzz harness ──"
EVIDENCE_PATH=$(python3 tools/fuzz_runner.py)

# Step 3: Validate evidence artifact
echo ""
echo "── Step 3/3: Validating evidence artifact ──"
python3 tools/validate_evidence.py "$EVIDENCE_PATH"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  M1 COMPLETE"
echo "  Evidence: $EVIDENCE_PATH"
echo "═══════════════════════════════════════════════════"
