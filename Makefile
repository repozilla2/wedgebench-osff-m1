.PHONY: reproduce osff-verify m2-tcg test validate clean corpus local clean-all

# One-command Docker reproduce for M1.
reproduce:
	docker compose run --rm sentinel-m1

# Reviewer-facing OSFF verification path.
osff-verify:
	@echo "== OSFF reviewer verification =="
	@echo ""
	@echo "== M1 Docker reproducibility =="
	docker compose run --rm sentinel-m1
	@echo ""
	@echo "== M2 TCG adapter draft generation =="
	python3 tools/run_m2_tcg.py
	@echo ""
	@echo "== Pytest contract suite =="
	pytest -q
	@echo ""
	@echo "== OSFF verification complete =="

# Generate the M2 draft TCG adapter artifact.
m2-tcg:
	python3 tools/run_m2_tcg.py

# Run tests.
test:
	pytest -q

# Run locally without Docker.
local:
	./run_m1.sh

# Generate corpus only.
corpus:
	python3 tools/generate_corpus.py

# Validate an existing evidence artifact.
# Usage: make validate FILE=evidence/EP-20260330-m1.json
validate:
	python3 tools/validate_evidence.py $(FILE)

# Clean generated artifacts.
clean:
	rm -rf build/
	rm -f evidence/EP-*-m1.json
	rm -rf evidence/m2/

# Full clean including corpus.
clean-all: clean
	rm -rf corpus/
