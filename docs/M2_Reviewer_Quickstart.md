# WedgeBench M2 Reviewer Quickstart

## Purpose

This document explains how to run the current M2 `go-tcg-storage` reference integration.

M2 demonstrates that WedgeBench can connect to a real firmware-adjacent parser boundary while preserving:

- deterministic replay
- adapter-based integration
- machine-checkable draft artifacts
- parser outcome classification
- wedge field compatibility

## Current Target

`open-source-firmware/go-tcg-storage`

Boundary:

`plainCom.Receive(ses *Session)`

## Run Tests

```bash
make m2-verify
```

`make m2-verify` runs the M2 environment preflight, builds the Go probe,
generates the draft M2 evidence artifact, validates it, and runs the Python test
suite.

## Required Local Layout

The WedgeBench checkout and upstream checkout must be siblings:

```text
<parent>/
  wedgebench-osff-m1/
  go-tcg-storage/
```

The sibling `go-tcg-storage` path must be a Git repository at:

```text
f99905c99780c82856226b20b59fb4863d83ae0d
```

The sibling checkout must be clean: no staged changes, unstaged changes, or
untracked files. The preflight reports dirty status paths but does not modify or
clean the upstream checkout.

The upstream repository is:

```text
https://github.com/open-source-firmware/go-tcg-storage
```

Required local tools:

- Python 3.10+
- GCC or Clang
- Go
- pytest
- Docker for the Docker M1 path

## Generated Evidence Provenance

Newly generated M2 artifacts include:

```json
{
  "upstream_repository": "https://github.com/open-source-firmware/go-tcg-storage",
  "upstream_commit": "f99905c99780c82856226b20b59fb4863d83ae0d"
}
```

Already submitted canonical evidence artifacts are not rewritten by this
quickstart.
