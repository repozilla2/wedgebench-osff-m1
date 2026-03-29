.PHONY: reproduce validate clean corpus

# One-command Docker reproduce (OSFF verification target)
reproduce:
	docker compose run sentinel-m1

# Run locally without Docker (requires gcc + python3)
local:
	./run_m1.sh

# Generate corpus only
corpus:
	python3 tools/generate_corpus.py

# Validate an existing evidence artifact
# Usage: make validate FILE=evidence/EP-20260302-m1.json
validate:
	python3 tools/validate_evidence.py $(FILE)

# Clean generated artifacts (keeps corpus)
clean:
	rm -rf build/ evidence/

# Full clean including corpus
clean-all: clean
	rm -rf corpus/
