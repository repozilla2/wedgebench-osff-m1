#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


UPSTREAM_REPOSITORY = "https://github.com/open-source-firmware/go-tcg-storage"
UPSTREAM_COMMIT = "f99905c99780c82856226b20b59fb4863d83ae0d"

GitRunner = Callable[[Path, list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class M2Provenance:
    upstream_repository: str
    upstream_commit: str


@dataclass(frozen=True)
class M2EnvironmentInspection:
    errors: list[str]
    provenance: M2Provenance | None = None


def _run_git(repo: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _canonical_repo_url(url: str) -> str:
    url = url.strip()
    if url.endswith(".git"):
        return url[:-4]
    return url


def inspect_environment(
    repo_root: Path,
    *,
    go_path: str | None = None,
    git_runner: GitRunner = _run_git,
) -> M2EnvironmentInspection:
    errors: list[str] = []

    if go_path is None:
        go_path = shutil.which("go")
    if not go_path:
        errors.append("Go executable not found on PATH")

    upstream_checkout = repo_root.parent / "go-tcg-storage"
    if not upstream_checkout.exists():
        errors.append(f"Missing sibling checkout: {upstream_checkout}")
        return M2EnvironmentInspection(errors)

    git_check = git_runner(upstream_checkout, ["rev-parse", "--is-inside-work-tree"])
    if git_check.returncode != 0 or git_check.stdout.strip() != "true":
        errors.append(f"Sibling checkout is not a Git repository: {upstream_checkout}")
        return M2EnvironmentInspection(errors)

    remote = git_runner(upstream_checkout, ["remote", "get-url", "origin"])
    actual_repository = (
        _canonical_repo_url(remote.stdout) if remote.returncode == 0 else "<unavailable>"
    )
    if actual_repository != UPSTREAM_REPOSITORY:
        errors.append(
            "Wrong go-tcg-storage origin\n"
            f"Expected upstream repository: {UPSTREAM_REPOSITORY}\n"
            f"Actual upstream repository:   {actual_repository}"
        )

    head = git_runner(upstream_checkout, ["rev-parse", "HEAD"])
    actual_commit = head.stdout.strip() if head.returncode == 0 else "<unavailable>"
    if actual_commit != UPSTREAM_COMMIT:
        errors.append(
            "Wrong go-tcg-storage HEAD\n"
            f"Expected upstream commit: {UPSTREAM_COMMIT}\n"
            f"Actual upstream commit:   {actual_commit}"
        )

    status = git_runner(
        upstream_checkout,
        ["status", "--porcelain=v1", "--untracked-files=all"],
    )
    if status.returncode != 0:
        errors.append("Could not inspect go-tcg-storage working tree status")
    elif status.stdout.strip():
        dirty_paths = "\n".join(
            f"  {line}" for line in status.stdout.splitlines() if line.strip()
        )
        errors.append(
            "Dirty go-tcg-storage checkout; commit, stash, or remove local changes "
            "before generating M2 evidence\n"
            f"{dirty_paths}"
        )

    if errors:
        return M2EnvironmentInspection(errors)

    return M2EnvironmentInspection(
        errors=[],
        provenance=M2Provenance(
            upstream_repository=actual_repository,
            upstream_commit=actual_commit,
        ),
    )


def validate_environment(
    repo_root: Path,
    *,
    go_path: str | None = None,
    git_runner: GitRunner = _run_git,
) -> list[str]:
    return inspect_environment(
        repo_root,
        go_path=go_path,
        git_runner=git_runner,
    ).errors


def print_errors(errors: list[str]) -> None:
    print("M2 environment preflight: FAIL", file=sys.stderr)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    inspection = inspect_environment(repo_root)
    if inspection.errors:
        print_errors(inspection.errors)
        return 1

    assert inspection.provenance is not None
    print("M2 environment preflight: PASS")
    print(f"upstream_repository={inspection.provenance.upstream_repository}")
    print(f"upstream_commit={inspection.provenance.upstream_commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
