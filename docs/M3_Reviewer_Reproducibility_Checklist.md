# M3 Reviewer Reproducibility Checklist

M3 provides the shortest reviewer path for reproducing the OSFF workflow.

## Purpose

M3 does not introduce new parser behavior, new vulnerability claims, or new hardware timing claims.

It verifies:

1. M1 Docker reproducibility
2. M2 semantic adapter generation
3. Python contract tests

## Prerequisites

- Docker Desktop or Docker Engine
- Docker Compose
- Python 3.10+
- pytest

## One-command verification

From the repository root:

    make osff-verify

## Expected success signs

M1 should show:

    Corpus generation complete.
    Total cases: 39
    Parser safe: PASS
    Parser vuln: PASS
    Result: PASS
    M1 COMPLETE

M2 should show:

    Wrote .../evidence/m2/EP-M2-go-tcg-storage-draft.json
    trial_count=39

Tests should show:

    6 passed

## Generated artifacts

Reviewer runs may generate local evidence files:

    evidence/EP-*-m1.json
    evidence/m2/EP-M2-go-tcg-storage-draft.json

These are local reproducibility outputs and are intentionally ignored unless promoted deliberately as canonical evidence.

## Claim boundaries

This verification path demonstrates:

- deterministic corpus generation
- M1 Docker-based reproducibility
- schema-valid M1 evidence generation
- M2 semantic outcome classification
- draft TCG adapter mapping
- contract-test coverage for the adapter path

It does not claim:

- exhaustive fuzz coverage
- physical-device timing
- exploit discovery
- formal safety proof
- production firmware validation
- real TCG storage device integration

## Troubleshooting

If Docker cannot connect to the Docker API, start Docker Desktop and retry:

    docker info
    make osff-verify

If tests fail with import errors, run from the repository root:

    pytest -q

A clean reviewer run should not require committing generated files.
