from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from tools import run_m2_tcg
from tools.check_m2_environment import (
    UPSTREAM_COMMIT,
    UPSTREAM_REPOSITORY,
    M2EnvironmentInspection,
    M2Provenance,
    inspect_environment,
    validate_environment,
)


def _git_runner(
    *,
    inside_work_tree: bool = True,
    head: str = UPSTREAM_COMMIT,
    remote: str = f"{UPSTREAM_REPOSITORY}.git",
    status: str = "",
):
    def run_git(_repo: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
        if args == ["rev-parse", "--is-inside-work-tree"]:
            stdout = "true\n" if inside_work_tree else "false\n"
            return subprocess.CompletedProcess(args, 0, stdout, "")
        if args == ["remote", "get-url", "origin"]:
            return subprocess.CompletedProcess(args, 0, f"{remote}\n", "")
        if args == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(args, 0, f"{head}\n", "")
        if args == ["status", "--porcelain=v1", "--untracked-files=all"]:
            return subprocess.CompletedProcess(args, 0, status, "")
        raise AssertionError(f"unexpected git args: {args}")

    return run_git


def test_preflight_fails_when_go_is_missing(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    errors = validate_environment(
        tmp_path / "wedgebench",
        go_path="",
        git_runner=_git_runner(),
    )
    assert errors == ["Go executable not found on PATH"]


def test_preflight_fails_when_sibling_checkout_is_missing(tmp_path):
    errors = validate_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(),
    )
    assert errors == [f"Missing sibling checkout: {tmp_path / 'go-tcg-storage'}"]


def test_preflight_fails_when_sibling_checkout_is_not_git(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    errors = validate_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(inside_work_tree=False),
    )
    assert errors == [f"Sibling checkout is not a Git repository: {tmp_path / 'go-tcg-storage'}"]


def test_preflight_fails_with_expected_and_actual_sha_on_mismatch(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    actual = "1" * 40
    errors = validate_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(head=actual),
    )
    assert errors == [
        "Wrong go-tcg-storage HEAD\n"
        f"Expected upstream commit: {UPSTREAM_COMMIT}\n"
        f"Actual upstream commit:   {actual}"
    ]


def test_preflight_passes_at_recovered_upstream_sha(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    assert validate_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(head=UPSTREAM_COMMIT),
    ) == []


def test_clean_checkout_at_expected_commit_returns_inspected_provenance(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    inspection = inspect_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(head=UPSTREAM_COMMIT, status=""),
    )

    assert inspection.errors == []
    assert inspection.provenance == M2Provenance(
        upstream_repository=UPSTREAM_REPOSITORY,
        upstream_commit=UPSTREAM_COMMIT,
    )


def test_preflight_fails_on_unstaged_tracked_change(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    errors = validate_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(status=" M pkg/core/communication.go\n"),
    )

    assert len(errors) == 1
    assert "Dirty go-tcg-storage checkout" in errors[0]
    assert " M pkg/core/communication.go" in errors[0]


def test_preflight_fails_on_staged_change(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    errors = validate_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(status="M  pkg/core/communication.go\n"),
    )

    assert len(errors) == 1
    assert "Dirty go-tcg-storage checkout" in errors[0]
    assert "M  pkg/core/communication.go" in errors[0]


def test_preflight_fails_on_untracked_file(tmp_path):
    (tmp_path / "go-tcg-storage").mkdir()
    errors = validate_environment(
        tmp_path / "wedgebench",
        go_path="/usr/bin/go",
        git_runner=_git_runner(status="?? scratch.bin\n"),
    )

    assert len(errors) == 1
    assert "Dirty go-tcg-storage checkout" in errors[0]
    assert "?? scratch.bin" in errors[0]


def test_run_m2_tcg_invalid_environment_creates_no_artifact_or_adapter(tmp_path, capsys):
    repo_root = tmp_path / "wedgebench"
    repo_root.mkdir()

    def fail_if_constructed():
        raise AssertionError("TCGAdapter must not be constructed")

    rc = run_m2_tcg.main(
        repo_root=repo_root,
        adapter_factory=fail_if_constructed,
        environment_inspector=lambda _repo_root: M2EnvironmentInspection(
            errors=["Missing sibling checkout: ../go-tcg-storage"]
        ),
    )

    assert rc == 1
    assert "M2 environment preflight: FAIL" in capsys.readouterr().err
    assert not (repo_root / "evidence" / "m2" / "EP-M2-go-tcg-storage-draft.json").exists()


def test_run_m2_tcg_records_inspected_exact_provenance(tmp_path):
    repo_root = tmp_path / "wedgebench"
    corpus_dir = repo_root / "corpus"
    corpus_dir.mkdir(parents=True)
    (corpus_dir / "case.bin").write_bytes(b"\x00")
    inspected_repo = "https://github.com/open-source-firmware/go-tcg-storage"
    inspected_sha = "f99905c99780c82856226b20b59fb4863d83ae0d"

    class FakeAdapter:
        def reset(self):
            pass

        def feed(self, _data: bytes):
            return SimpleNamespace(
                ok=True,
                error=None,
                response_len=1,
                frames_accepted=1,
                output_bytes=1,
                progress=1,
                latency_us=1.0,
                parser_outcome="accepted",
            )

        def inject_heartbeat(self):
            return True

    rc = run_m2_tcg.main(
        repo_root=repo_root,
        adapter_factory=FakeAdapter,
        environment_inspector=lambda _repo_root: M2EnvironmentInspection(
            errors=[],
            provenance=M2Provenance(
                upstream_repository=inspected_repo,
                upstream_commit=inspected_sha,
            ),
        ),
    )

    artifact_path = repo_root / "evidence" / "m2" / "EP-M2-go-tcg-storage-draft.json"
    artifact = json.loads(artifact_path.read_text())
    assert rc == 0
    assert artifact["upstream_repository"] == inspected_repo
    assert artifact["upstream_commit"] == inspected_sha
    assert artifact["trial_count"] == 1


def test_make_m2_tcg_depends_on_preflight():
    makefile = Path(__file__).resolve().parents[1] / "Makefile"
    assert "m2-tcg: m2-preflight\n" in makefile.read_text()
