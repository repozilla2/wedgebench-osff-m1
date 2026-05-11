"""
Tests for tools/run_m3_demo.py — M3 internal demo runner.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.event_log import load_events
from tools.run_m3_demo import run
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
    rc = run(log)
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

    run(log)  # run again
    second_events = load_events(log)
    # New run_id means the log is fresh, not appended
    run_ids = {ev["run_id"] for ev in second_events}
    assert len(run_ids) == 1
    seqs = [ev["sequence"] for ev in second_events]
    assert seqs[0] == 0  # starts from 0, not a continuation


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
