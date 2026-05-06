#!/usr/bin/env bash
set -euo pipefail

echo "Running WedgeBench M2 go-tcg-storage reference integration..."
python3 tools/run_m2_tcg.py
