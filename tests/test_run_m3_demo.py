"""
Tests for tools/run_m3_demo.py — M3 demo runner.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.event_log import load_events
import tools.run_m3_demo as run_m3_demo
from tools.verify_event_log import verify

REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_EVENT_TYPES = {
    "run_started",
    "m2_evidence_generated",
    "m2_evidence_validated",
    "tests_skipped",
    "run_completed",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_demo(tmp_path: Path) -> tuple[int, Path]:
    log = tmp_path / "WBLOG-M3-demo.jsonl"
    rc = run_m3_demo.run(log)
    return rc, log


# ── Basic execution ───────────────────────────────────────────────────────────

def test_runner_exits_0(tmp_path):
    rc, _ = _run_demo(tmp_path)
    assert rc == 0


def test_log_file_created(tmp_path):
    _, log = _run_demo(tmp_path)
    assert log.exists()


def test_log_is_nonempty(tmp_path):
    _, log = _run_demo(tmp_path)
    assert log.stat().st_size > 0


# ── Required event types ──────────────────────────────────────────────────────

def test_all_required_event_types_present(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    found = {ev["event_type"] for ev in events}
    assert REQUIRED_EVENT_TYPES.issubset(found), (
        f"Missing event types: {REQUIRED_EVENT_TYPES - found}"
    )


def test_event_order_is_correct(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    types = [ev["event_type"] for ev in events]
    assert types == [
        "run_started",
        "m2_evidence_generated",
        "m2_evidence_validated",
        "tests_skipped",
        "run_completed",
    ]


def test_tests_skipped_payload(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    ev = next(e for e in events if e["event_type"] == "tests_skipped")
    assert ev["payload"]["reason"]
    assert ev["payload"]["acceptance_command"] == "pytest -q"


# ── Artifact hash in events ───────────────────────────────────────────────────

def test_m2_evidence_generated_has_artifact_path(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    ev = next(e for e in events if e["event_type"] == "m2_evidence_generated")
    assert "artifact_path" in ev["payload"]
    assert ev["payload"]["artifact_path"]


def test_m2_evidence_generated_has_artifact_sha256(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    ev = next(e for e in events if e["event_type"] == "m2_evidence_generated")
    sha = ev["payload"].get("artifact_sha256")
    assert sha is not None
    assert len(sha) == 64
    int(sha, 16)  # must be valid hex


def test_m2_evidence_validated_has_artifact_path(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    ev = next(e for e in events if e["event_type"] == "m2_evidence_validated")
    assert "artifact_path" in ev["payload"]


def test_m2_evidence_validated_has_artifact_sha256(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    ev = next(e for e in events if e["event_type"] == "m2_evidence_validated")
    sha = ev["payload"].get("artifact_sha256")
    assert sha is not None
    assert len(sha) == 64


def test_artifact_sha256_matches_actual_file(tmp_path):
    import hashlib

    _, log = _run_demo(tmp_path)
    events = load_events(log)
    ev = next(e for e in events if e["event_type"] == "m2_evidence_generated")
    artifact_path = Path(ev["payload"]["artifact_path"])
    stored_sha = ev["payload"]["artifact_sha256"]
    actual_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    assert stored_sha == actual_sha


# ── Hash chain and log integrity ──────────────────────────────────────────────

def test_generated_log_passes_verifier(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    result = verify(events)
    assert result.passed, result.report()


def test_sequence_is_contiguous(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    seqs = [ev["sequence"] for ev in events]
    assert seqs == list(range(len(seqs)))


def test_all_events_share_run_id(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    run_ids = {ev["run_id"] for ev in events}
    assert len(run_ids) == 1


def test_each_line_is_valid_json(tmp_path):
    _, log = _run_demo(tmp_path)
    for line in log.read_text().splitlines():
        if line.strip():
            obj = json.loads(line)
            assert "event_hash" in obj


# ── run_completed payload ─────────────────────────────────────────────────────

def test_run_completed_reports_success(tmp_path):
    _, log = _run_demo(tmp_path)
    events = load_events(log)
    ev = next(e for e in events if e["event_type"] == "run_completed")
    assert ev["payload"]["success"] is True


# ── Second run overwrites log (idempotent) ────────────────────────────────────

def test_second_run_replaces_log(tmp_path):
    _, log = _run_demo(tmp_path)
    first_hash = log.read_bytes()

    run_m3_demo.run(log)  # run again
    second_events = load_events(log)
    # New run_id means the log is fresh, not appended
    run_ids = {ev["run_id"] for ev in second_events}
    assert len(run_ids) == 1
    seqs = [ev["sequence"] for ev in second_events]
    assert seqs[0] == 0  # starts from 0, not a continuation


# ── Current-run M2 artifact requirement ──────────────────────────────────────

def test_failed_m2_generation_cannot_reuse_stale_artifact(tmp_path, monkeypatch):
    monkeypatch.setattr(run_m3_demo, "_REPO_ROOT", tmp_path)
    artifact = (
        tmp_path / "evidence" / "m2" / "EP-M2-go-tcg-storage-draft.json"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"stale": true}\n')

    def fail_generation():
        assert not artifact.exists()
        return 1

    monkeypatch.setattr(
        run_m3_demo, "_load_m2_generator_main", lambda: fail_generation
    )

    log = tmp_path / "failure.jsonl"
    assert run_m3_demo.run(log) == 1
    assert not artifact.exists()


def test_generator_exception_removes_partial_artifact_and_reraises(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(run_m3_demo, "_REPO_ROOT", tmp_path)
    evidence_dir = tmp_path / "evidence" / "m2"
    evidence_dir.mkdir(parents=True)
    artifact = evidence_dir / "EP-M2-go-tcg-storage-draft.json"

    def raise_after_partial_write():
        artifact.write_text('{"partial": true}\n')
        raise RuntimeError("generator failed after partial write")

    monkeypatch.setattr(
        run_m3_demo,
        "_load_m2_generator_main",
        lambda: raise_after_partial_write,
    )

    with pytest.raises(RuntimeError, match="generator failed after partial write"):
        run_m3_demo._run_m2(evidence_dir)
    assert not artifact.exists()


def test_failed_m2_generation_produces_failure_log(tmp_path, monkeypatch):
    monkeypatch.setattr(run_m3_demo, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        run_m3_demo, "_load_m2_generator_main", lambda: (lambda: 1)
    )

    log = tmp_path / "failure.jsonl"
    assert run_m3_demo.run(log) == 1
    events = load_events(log)
    generated = next(e for e in events if e["event_type"] == "m2_evidence_generated")
    validated = next(e for e in events if e["event_type"] == "m2_evidence_validated")
    completed = next(e for e in events if e["event_type"] == "run_completed")

    assert generated["payload"]["ok"] is False
    assert "artifact_sha256" not in generated["payload"]
    assert "status 1" in generated["payload"]["error"]
    assert validated["payload"]["ok"] is False
    assert "generated failed" in validated["payload"]["error"]
    assert completed["payload"]["success"] is False
    assert verify(events).passed


def test_successful_current_m2_generation_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(run_m3_demo, "_REPO_ROOT", tmp_path)
    artifact = (
        tmp_path / "evidence" / "m2" / "EP-M2-go-tcg-storage-draft.json"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"stale": true}\n')

    def generate_current_artifact():
        assert not artifact.exists()
        artifact.write_text('{"current": true}\n')
        return 0

    monkeypatch.setattr(
        run_m3_demo, "_load_m2_generator_main", lambda: generate_current_artifact
    )
    monkeypatch.setattr(run_m3_demo, "_validate_m2", lambda path: path == artifact)

    log = tmp_path / "success.jsonl"
    assert run_m3_demo.run(log) == 0
    events = load_events(log)
    generated = next(e for e in events if e["event_type"] == "m2_evidence_generated")
    completed = next(e for e in events if e["event_type"] == "run_completed")

    assert json.loads(artifact.read_text()) == {"current": True}
    assert generated["payload"]["ok"] is True
    assert completed["payload"]["success"] is True
    assert verify(events).passed


# ── CLI integration ───────────────────────────────────────────────────────────

def test_cli_exits_0_and_produces_log(tmp_path):
    log = tmp_path / "cli_test.jsonl"
    result = subprocess.run(
        [sys.executable, "tools/run_m3_demo.py", "--log-path", str(log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "M3 demo log: PASS" in result.stdout
    assert log.exists()


def test_cli_log_passes_verifier_subprocess(tmp_path):
    log = tmp_path / "cli_verify.jsonl"
    subprocess.run(
        [sys.executable, "tools/run_m3_demo.py", "--log-path", str(log)],
        cwd=REPO_ROOT,
        check=True,
    )
    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "M3 event log: PASS" in result.stdout


def test_default_log_path_after_direct_invocation():
    """Running the demo with default path writes to evidence/m3/WBLOG-M3-demo.jsonl."""
    result = subprocess.run(
        [sys.executable, "tools/run_m3_demo.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    default_log = REPO_ROOT / "evidence" / "m3" / "WBLOG-M3-demo.jsonl"
    assert default_log.exists()
    verify_result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(default_log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert verify_result.returncode == 0
