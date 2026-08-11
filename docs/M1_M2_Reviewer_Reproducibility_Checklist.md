# M1/M2 Reviewer Reproducibility Checklist

This checklist provides the shortest reviewer path for reproducing the public WedgeBench M1/M2 workflow.

## Purpose

This checklist is for the completed public M1 and M2 reviewer path.

It verifies:

1. M1 Docker reproducibility
2. M2 go-tcg-storage adapter/evidence generation
3. M2 evidence validation
4. Python contract tests

This checklist remains specifically for M1/M2. M3 is now complete and public
through the separate `make m3-verify` path. M3 is not part of
`make osff-verify`.

## Prerequisites

- Git
- Docker Desktop or Docker Engine with Docker Compose support for
  `make osff-verify`
- Python 3.10 or later
- GCC or Clang
- Go 1.24 or later
- `pytest`
- Network access on the first required Go module or toolchain dependency run

The M2 Go module uses a local replace directive. Place the upstream checkout as a
sibling of this WedgeBench repository:

```text
workspace/
├── go-tcg-storage/
└── wedgebench-osff-m1/
```

The sibling `go-tcg-storage` checkout must be a Git repository at:

    f99905c99780c82856226b20b59fb4863d83ae0d

It must be clean: no staged changes, unstaged changes, or untracked files. The
preflight reports dirty status paths but does not modify or clean the upstream
checkout.

The upstream repository for that checkout is:

    https://github.com/open-source-firmware/go-tcg-storage

After the required Go modules and toolchain have been cached, the Go-dependent
reviewer paths can be rerun with Go proxy and checksum-database access disabled:

    GOPROXY=off GOSUMDB=off make m2-verify
    GOPROXY=off GOSUMDB=off make m3-verify

These cached reruns are not a claim of hermetic or fully air-gapped execution.

## One-command reviewer verification

From the repository root:

    make osff-verify

## M2-specific verification

For the M2 go-tcg-storage reference integration and evidence validator path:

    make m2-verify

## Separate M3 verification

M3 is public through its separate verification path:

    make m3-verify

This command is not invoked by `make osff-verify` and remains outside this
checklist's M1/M2 verification scope.

## Expected success signs

M1 should show:

    Corpus generation complete.
    Total cases: 39
    Parser 'safe': ✓ PASS
    Parser 'vuln': ✓ PASS
    Result: PASS
    M1 COMPLETE

M2 should show:

    M2 environment preflight: PASS
    Wrote .../evidence/m2/EP-M2-go-tcg-storage-draft.json
    M2 evidence: PASS
    trial_count=39

Tests should show:

    at least 45 passed

## Generated artifacts

Reviewer runs may generate local evidence files:

    evidence/EP-*-m1.json
    evidence/m2/EP-M2-go-tcg-storage-draft.json

These are local reproducibility outputs and are intentionally ignored unless promoted deliberately as canonical evidence.

Newly generated M2 draft artifacts include the recovered upstream provenance:

    "upstream_repository": "https://github.com/open-source-firmware/go-tcg-storage"
    "upstream_commit": "f99905c99780c82856226b20b59fb4863d83ae0d"

Already submitted canonical evidence artifacts are not rewritten by this reviewer
path.

## Claim boundaries

This public M1/M2 verification path demonstrates:

- deterministic corpus generation
- M1 Docker-based reproducibility
- schema-valid M1 evidence generation
- M2 go-tcg-storage reference integration path
- M2 semantic outcome classification
- M2 artifact validation through `tools/validate_m2_evidence.py`
- contract-test coverage for the adapter and validator path

This M1/M2 checklist and `make osff-verify` do not perform M3 verification.

It does not claim:

- exhaustive fuzz coverage
- physical-device timing
- exploit discovery
- formal safety proof
- production firmware validation
- real TCG storage device validation

## Troubleshooting

If Docker cannot connect to the Docker API, start Docker Desktop and retry:

    docker info
    make osff-verify

If tests fail with import errors, run tests from the repository root:

    pytest -q

If `make m2-verify` reports a missing, mismatched, or dirty sibling checkout,
verify the layout above and run:

    cd ../go-tcg-storage
    git rev-parse HEAD
    git status --short --untracked-files=all

A clean reviewer run should not require committing generated files.
