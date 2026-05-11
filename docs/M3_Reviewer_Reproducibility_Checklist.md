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

```bash
make osff-verify
