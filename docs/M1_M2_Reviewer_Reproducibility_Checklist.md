# M1/M2 Reviewer Reproducibility Checklist

This checklist provides the shortest reviewer path for reproducing the public WedgeBench M1/M2 workflow.

## Purpose

This checklist is for the completed public M1 and M2 reviewer path.

It verifies:

1. M1 Docker reproducibility
2. M2 go-tcg-storage adapter/evidence generation
3. M2 evidence validation
4. Python contract tests

This checklist does not represent OSFF Milestone 3. M3 verification logging remains future scope until publicly released.

## Prerequisites

- Docker Desktop or Docker Engine
- Docker Compose
- Python 3.10+
- pytest

## One-command reviewer verification

From the repository root:

    make osff-verify

## M2-specific verification

For the M2 go-tcg-storage reference integration and evidence validator path:

    make m2-verify

## Expected success signs

M1 should show:

    Corpus generation complete.
    Total cases: 39
    Parser 'safe': ✓ PASS
    Parser 'vuln': ✓ PASS
    Result: PASS
    M1 COMPLETE

M2 should show:

    Wrote .../evidence/m2/EP-M2-go-tcg-storage-draft.json
    M2 evidence: PASS
    trial_count=39

Tests should show:

    45 passed

## Generated artifacts

Reviewer runs may generate local evidence files:

    evidence/EP-*-m1.json
    evidence/m2/EP-M2-go-tcg-storage-draft.json

These are local reproducibility outputs and are intentionally ignored unless promoted deliberately as canonical evidence.

## Claim boundaries

This public M1/M2 verification path demonstrates:

- deterministic corpus generation
- M1 Docker-based reproducibility
- schema-valid M1 evidence generation
- M2 go-tcg-storage reference integration path
- M2 semantic outcome classification
- M2 artifact validation through `tools/validate_m2_evidence.py`
- contract-test coverage for the adapter and validator path

It does not claim:

- exhaustive fuzz coverage
- physical-device timing
- exploit discovery
- formal safety proof
- production firmware validation
- real TCG storage device validation
- OSFF Milestone 3 completion

## Troubleshooting

If Docker cannot connect to the Docker API, start Docker Desktop and retry:

    docker info
    make osff-verify

If tests fail with import errors, run tests from the repository root:

    pytest -q

A clean reviewer run should not require committing generated files.
