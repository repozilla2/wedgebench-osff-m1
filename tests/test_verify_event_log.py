"""
Tests for tools/verify_event_log.py — M3 JSONL event log verifier.
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.event_log import (
    SCHEMA_VERSION,
    append_event,
    create_event,
    hash_event,
)
from tools import verify_event_log as verifier
from tools.verify_event_log import verify

REPO_ROOT = Path(__file__).resolve().parents[1]


# ── Helpers ───────────────────────────────────────────────────────────────────

_TS = [
    "2026-05-11T00:00:00.000000Z",
    "2026-05-11T00:00:01.000000Z",
    "2026-05-11T00:00:02.000000Z",
    "2026-05-11T00:00:03.000000Z",
]


def _chain(n: int = 3, run_id: str = "test-run") -> list[dict]:
    """Return a valid hash-chained event list of length n."""
    events = []
    prev_hash = None
    for i in range(n):
        ev = create_event(
            run_id=run_id,
            sequence=i,
            event_type="test_event",
            payload={"index": i},
            previous_event_hash=prev_hash,
            timestamp_utc=_TS[i] if i < len(_TS) else f"2026-05-11T00:00:0{i}.000000Z",
        )
        events.append(ev)
        prev_hash = ev["event_hash"]
    return events


def _write_log(path: Path, events: list[dict]) -> None:
    for ev in events:
        append_event(path, ev)


def _artifact_event(path: str | Path, digest: str) -> dict:
    return create_event(
        run_id="artifact-test",
        sequence=0,
        event_type="artifact",
        payload={"artifact_path": str(path), "artifact_sha256": digest},
        previous_event_hash=None,
        timestamp_utc=_TS[0],
    )


# ── Valid log ─────────────────────────────────────────────────────────────────

def test_valid_chain_passes():
    assert verify(_chain(3)).passed


def test_single_event_passes():
    assert verify(_chain(1)).passed


def test_empty_log_fails():
    r = verify([])
    assert not r.passed
    assert any("empty" in e.lower() for e in r.errors)


# ── Per-event hash integrity ──────────────────────────────────────────────────

def test_edited_payload_fails():
    events = _chain(3)
    events[1] = {**events[1], "payload": {"tampered": True}}
    # Fix event_hash to match the tampered payload so chain still looks linked —
    # but the stored event_hash should mismatch the recomputed one.
    r = verify(events)
    assert not r.passed
    assert any("event_hash mismatch" in e for e in r.errors)


def test_changed_event_hash_fails():
    events = _chain(3)
    events[0] = {**events[0], "event_hash": "a" * 64}
    r = verify(events)
    assert not r.passed
    assert any("event_hash mismatch" in e for e in r.errors)


# ── Hash chain linkage ────────────────────────────────────────────────────────

def test_broken_previous_event_hash_fails():
    events = _chain(3)
    events[2] = {**events[2], "previous_event_hash": "b" * 64}
    # Re-seal event_hash so per-event hash check passes, chain check fails
    body = {k: v for k, v in events[2].items() if k != "event_hash"}
    events[2] = {**events[2], "event_hash": hash_event(body)}
    r = verify(events)
    assert not r.passed
    assert any("previous_event_hash" in e for e in r.errors)


def test_first_event_must_have_null_previous_hash():
    events = _chain(2)
    # Give the first event a non-null previous_event_hash and re-seal it
    events[0] = {**events[0], "previous_event_hash": "c" * 64}
    body = {k: v for k, v in events[0].items() if k != "event_hash"}
    events[0] = {**events[0], "event_hash": hash_event(body)}
    # Also fix event[1].previous_event_hash to match the new event[0].event_hash
    events[1] = {**events[1], "previous_event_hash": events[0]["event_hash"]}
    body1 = {k: v for k, v in events[1].items() if k != "event_hash"}
    events[1] = {**events[1], "event_hash": hash_event(body1)}
    r = verify(events)
    assert not r.passed
    assert any("previous_event_hash=null" in e for e in r.errors)


def test_deleted_middle_event_fails():
    events = _chain(4)
    # Drop event[1]; event[2].previous_event_hash no longer matches event[0]
    trimmed = [events[0], events[2], events[3]]
    r = verify(trimmed)
    assert not r.passed
    # Either chain linkage or sequence gap should be reported
    assert any("previous_event_hash" in e or "sequence" in e for e in r.errors)


def test_reordered_events_fail():
    events = _chain(3)
    reordered = [events[1], events[0], events[2]]
    r = verify(reordered)
    assert not r.passed


# ── Sequence checks ───────────────────────────────────────────────────────────

def test_bad_sequence_fails():
    events = _chain(3)
    # Duplicate sequence number 0, re-seal
    events[1] = {**events[1], "sequence": 0}
    body = {k: v for k, v in events[1].items() if k != "event_hash"}
    events[1] = {**events[1], "event_hash": hash_event(body)}
    # Also fix chain link for event[2]
    events[2] = {**events[2], "previous_event_hash": events[1]["event_hash"]}
    body2 = {k: v for k, v in events[2].items() if k != "event_hash"}
    events[2] = {**events[2], "event_hash": hash_event(body2)}
    r = verify(events)
    assert not r.passed
    assert any("sequence" in e for e in r.errors)


def test_sequence_gap_fails():
    events = _chain(3)
    # Jump from 0 to 2, re-seal
    events[1] = {**events[1], "sequence": 2}
    body = {k: v for k, v in events[1].items() if k != "event_hash"}
    events[1] = {**events[1], "event_hash": hash_event(body)}
    events[2] = {**events[2], "previous_event_hash": events[1]["event_hash"]}
    body2 = {k: v for k, v in events[2].items() if k != "event_hash"}
    events[2] = {**events[2], "event_hash": hash_event(body2)}
    r = verify(events)
    assert not r.passed
    assert any("sequence" in e for e in r.errors)


def test_sequence_starting_at_1_passes():
    """Sequences starting at 1 (rather than 0) are explicitly allowed."""
    events = []
    prev_hash = None
    for i in range(3):
        ev = create_event(
            run_id="r",
            sequence=i + 1,
            event_type="t",
            payload={},
            previous_event_hash=prev_hash,
            timestamp_utc=_TS[i],
        )
        events.append(ev)
        prev_hash = ev["event_hash"]
    assert verify(events).passed


def test_sequence_starting_at_2_fails():
    events = []
    prev_hash = None
    for i in range(3):
        ev = create_event(
            run_id="r",
            sequence=i + 2,
            event_type="t",
            payload={},
            previous_event_hash=prev_hash,
            timestamp_utc=_TS[i],
        )
        events.append(ev)
        prev_hash = ev["event_hash"]
    r = verify(events)
    assert not r.passed
    assert any("sequence" in e for e in r.errors)


# ── run_id consistency ────────────────────────────────────────────────────────

def test_inconsistent_run_id_fails():
    events = _chain(3)
    # Change run_id on event[2] and re-seal the whole suffix
    ev2 = {**events[2], "run_id": "different-run"}
    body2 = {k: v for k, v in ev2.items() if k != "event_hash"}
    ev2 = {**ev2, "event_hash": hash_event(body2)}
    # Fix chain link
    ev2 = {**ev2, "previous_event_hash": events[1]["event_hash"]}
    body2 = {k: v for k, v in ev2.items() if k != "event_hash"}
    ev2 = {**ev2, "event_hash": hash_event(body2)}
    events[2] = ev2
    r = verify(events)
    assert not r.passed
    assert any("run_id" in e for e in r.errors)


# ── Missing required fields ───────────────────────────────────────────────────

@pytest.mark.parametrize("field", [
    "schema_version", "run_id", "sequence", "timestamp_utc",
    "event_type", "payload", "previous_event_hash", "event_hash",
])
def test_missing_required_field_fails(field):
    events = _chain(2)
    del events[0][field]
    r = verify(events)
    assert not r.passed
    assert any(field in e for e in r.errors)


# ── Field type and format validation ─────────────────────────────────────────

def test_event_must_be_an_object():
    r = verify([["not", "an", "object"]])
    assert not r.passed
    assert any("event must be an object" in e for e in r.errors)


@pytest.mark.parametrize(("field", "value"), [
    ("schema_version", 3),
    ("run_id", ["run"]),
    ("sequence", True),
    ("timestamp_utc", 0),
    ("event_type", None),
    ("payload", []),
    ("previous_event_hash", 7),
    ("event_hash", 9),
])
def test_malformed_required_field_type_fails_cleanly(field, value):
    event = _chain(1)[0]
    event[field] = value

    r = verify([event])

    assert not r.passed
    assert any(field in error for error in r.errors)


def test_event_hash_must_be_64_character_hexadecimal_string():
    event = _chain(1)[0]
    event["event_hash"] = "z" * 64

    r = verify([event])

    assert not r.passed
    assert any("event_hash" in error and "hexadecimal" in error for error in r.errors)


@pytest.mark.parametrize(("field", "value"), [
    ("artifact_path", 123),
    ("artifact_sha256", None),
])
def test_malformed_artifact_field_type_fails_cleanly(field, value):
    event = _chain(1)[0]
    event["payload"][field] = value

    r = verify([event])

    assert not r.passed
    assert any(field in error for error in r.errors)


def test_artifact_sha256_must_be_64_character_hexadecimal_string():
    event = _chain(1)[0]
    event["payload"]["artifact_sha256"] = "not-a-sha256"

    r = verify([event])

    assert not r.passed
    assert any(
        "artifact_sha256" in error and "hexadecimal" in error
        for error in r.errors
    )


# ── Schema version ────────────────────────────────────────────────────────────

def test_accepted_schema_version_m3_log_v1_passes():
    events = _chain(1)
    events[0] = {**events[0], "schema_version": "m3-log-v1"}
    body = {k: v for k, v in events[0].items() if k != "event_hash"}
    events[0] = {**events[0], "event_hash": hash_event(body)}
    assert verify(events).passed


def test_draft_schema_version_fails():
    events = _chain(1)
    events[0] = {**events[0], "schema_version": "m3-draft"}
    body = {k: v for k, v in events[0].items() if k != "event_hash"}
    events[0] = {**events[0], "event_hash": hash_event(body)}
    r = verify(events)
    assert not r.passed
    assert any("schema_version" in e for e in r.errors)


def test_unknown_schema_version_fails():
    events = _chain(1)
    events[0] = {**events[0], "schema_version": "unknown-version"}
    body = {k: v for k, v in events[0].items() if k != "event_hash"}
    events[0] = {**events[0], "event_hash": hash_event(body)}
    r = verify(events)
    assert not r.passed
    assert any("schema_version" in e for e in r.errors)


# ── Artifact hash checks ──────────────────────────────────────────────────────

def test_correct_artifact_hash_passes(tmp_path):
    artifact = tmp_path / "out.bin"
    artifact.write_bytes(b"hello world")
    sha = hashlib.sha256(b"hello world").hexdigest()

    ev = create_event(
        run_id="r",
        sequence=0,
        event_type="artifact",
        payload={"artifact_path": str(artifact), "artifact_sha256": sha},
        previous_event_hash=None,
        timestamp_utc=_TS[0],
    )
    assert verify([ev]).passed


def test_bad_artifact_hash_fails(tmp_path):
    artifact = tmp_path / "out.bin"
    artifact.write_bytes(b"real content")

    ev = create_event(
        run_id="r",
        sequence=0,
        event_type="artifact",
        payload={"artifact_path": str(artifact), "artifact_sha256": "deadbeef" * 8},
        previous_event_hash=None,
        timestamp_utc=_TS[0],
    )
    r = verify([ev])
    assert not r.passed
    assert any("artifact_sha256 mismatch" in e for e in r.errors)


def test_missing_artifact_file_does_not_fail(tmp_path):
    missing = tmp_path / "nonexistent.bin"

    ev = create_event(
        run_id="r",
        sequence=0,
        event_type="artifact",
        payload={"artifact_path": str(missing), "artifact_sha256": "aa" * 32},
        previous_event_hash=None,
        timestamp_utc=_TS[0],
    )
    r = verify([ev])
    assert r.passed  # missing file is a warning, not an error


def test_missing_artifact_file_produces_warning(tmp_path):
    missing = tmp_path / "nonexistent.bin"

    ev = create_event(
        run_id="r",
        sequence=0,
        event_type="artifact",
        payload={"artifact_path": str(missing), "artifact_sha256": "aa" * 32},
        previous_event_hash=None,
        timestamp_utc=_TS[0],
    )
    r = verify([ev])
    assert any("not found" in w or "skipped" in w for w in r.warnings)


def test_relative_regular_artifact_below_limit_passes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    artifact = Path("relative.bin")
    content = b"relative artifact"
    artifact.write_bytes(content)

    r = verify([_artifact_event(artifact, hashlib.sha256(content).hexdigest())])

    assert r.passed, r.report()


def test_absolute_regular_artifact_below_limit_passes(tmp_path):
    artifact = (tmp_path / "absolute.bin").absolute()
    content = b"absolute artifact"
    artifact.write_bytes(content)

    r = verify([_artifact_event(artifact, hashlib.sha256(content).hexdigest())])

    assert artifact.is_absolute()
    assert r.passed, r.report()


def test_directory_artifact_fails_cleanly(tmp_path):
    artifact = tmp_path / "artifact-directory"
    artifact.mkdir()

    r = verify([_artifact_event(artifact, "aa" * 32)])

    assert not r.passed
    assert "not a regular file" in r.report()
    assert "Traceback" not in r.report()


def test_final_symlink_fails_without_reading_target(tmp_path, monkeypatch):
    target = tmp_path / "target.bin"
    content = b"must not be read"
    target.write_bytes(content)
    target_digest = hashlib.sha256(content).hexdigest()
    artifact = tmp_path / "artifact-link"
    try:
        artifact.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")

    def unexpected_open(*args, **kwargs):
        raise AssertionError("symlink target must not be opened")

    monkeypatch.setattr(verifier.os, "open", unexpected_open)
    r = verify([_artifact_event(artifact, target_digest)])

    assert not r.passed
    assert "symlink" in r.report()
    assert "Traceback" not in r.report()


def test_broken_final_symlink_is_rejected_not_treated_as_missing(tmp_path):
    artifact = tmp_path / "broken-link"
    try:
        artifact.symlink_to(tmp_path / "missing-target.bin")
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")

    r = verify([_artifact_event(artifact, "aa" * 32)])

    assert not r.passed
    assert "symlink" in r.report()
    assert not r.warnings


def test_oversized_sparse_regular_artifact_fails(tmp_path):
    artifact = tmp_path / "oversized.bin"
    with artifact.open("wb") as fh:
        fh.truncate(verifier.MAX_ARTIFACT_SIZE_BYTES + 1)

    r = verify([_artifact_event(artifact, "aa" * 32)])

    assert not r.passed
    assert "exceeds inclusive" in r.report()


def test_exact_limit_regular_artifact_passes_with_reduced_limit(
    tmp_path, monkeypatch
):
    limit = 8
    content = b"12345678"
    artifact = tmp_path / "exact-limit.bin"
    artifact.write_bytes(content)
    monkeypatch.setattr(verifier, "MAX_ARTIFACT_SIZE_BYTES", limit)
    monkeypatch.setattr(verifier, "ARTIFACT_HASH_CHUNK_SIZE_BYTES", 3)

    r = verify([_artifact_event(artifact, hashlib.sha256(content).hexdigest())])

    assert r.passed, r.report()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO support unavailable")
def test_fifo_artifact_fails_without_blocking(tmp_path):
    artifact = tmp_path / "artifact.fifo"
    os.mkfifo(artifact)
    log = tmp_path / "fifo.jsonl"
    _write_log(log, [_artifact_event(artifact, "aa" * 32)])

    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 1
    assert "M3 event log: FAIL" in result.stdout
    assert "not a regular file" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_artifact_growth_beyond_limit_during_streaming_fails(
    tmp_path, monkeypatch
):
    artifact = tmp_path / "growing.bin"
    initial_content = b"1234"
    artifact.write_bytes(initial_content)
    monkeypatch.setattr(verifier, "MAX_ARTIFACT_SIZE_BYTES", 8)
    monkeypatch.setattr(verifier, "ARTIFACT_HASH_CHUNK_SIZE_BYTES", 4)
    real_read = os.read
    read_count = 0
    observed_bytes = 0

    def read_then_grow(fd, size):
        nonlocal read_count, observed_bytes
        chunk = real_read(fd, size)
        read_count += 1
        observed_bytes += len(chunk)
        if read_count == 1:
            with artifact.open("ab") as fh:
                fh.write(b"56789ABC")
        return chunk

    monkeypatch.setattr(verifier.os, "read", read_then_grow)
    r = verify(
        [_artifact_event(artifact, hashlib.sha256(initial_content).hexdigest())]
    )

    assert not r.passed
    assert "exceeds inclusive" in r.report()
    assert observed_bytes == verifier.MAX_ARTIFACT_SIZE_BYTES + 1


def test_artifact_filesystem_error_fails_without_traceback(tmp_path, monkeypatch):
    artifact = tmp_path / "unreadable.bin"
    content = b"content"
    artifact.write_bytes(content)

    def denied_open(*args, **kwargs):
        raise PermissionError("simulated filesystem denial")

    monkeypatch.setattr(verifier.os, "open", denied_open)
    r = verify([_artifact_event(artifact, hashlib.sha256(content).hexdigest())])

    assert not r.passed
    assert "simulated filesystem denial" in r.report()
    assert "Traceback" not in r.report()


def test_artifact_mismatch_does_not_expose_recomputed_digest(tmp_path):
    artifact = tmp_path / "external.bin"
    content = b"external file content"
    artifact.write_bytes(content)
    recomputed = hashlib.sha256(content).hexdigest()

    r = verify([_artifact_event(artifact, "de" * 32)])

    assert not r.passed
    assert "artifact_sha256 mismatch" in r.report()
    assert recomputed not in r.report()


def test_correct_uppercase_artifact_sha256_passes(tmp_path):
    artifact = tmp_path / "uppercase.bin"
    content = b"uppercase artifact digest"
    artifact.write_bytes(content)
    uppercase = hashlib.sha256(content).hexdigest().upper()

    r = verify([_artifact_event(artifact, uppercase)])

    assert r.passed, r.report()


def test_correct_uppercase_event_hash_passes():
    event = _chain(1)[0]
    event["event_hash"] = event["event_hash"].upper()

    assert verify([event]).passed


def test_mixed_case_previous_event_hash_linkage_passes_after_resealing():
    events = _chain(2)
    parent_hash = events[0]["event_hash"]
    mixed_case = parent_hash[:32].upper() + parent_hash[32:].lower()
    assert mixed_case != mixed_case.lower()
    assert mixed_case != mixed_case.upper()
    events[1] = {**events[1], "previous_event_hash": mixed_case}
    body = {k: v for k, v in events[1].items() if k != "event_hash"}
    events[1] = {**events[1], "event_hash": hash_event(body)}

    assert verify(events).passed


# ── JSONL roundtrip via CLI ───────────────────────────────────────────────────

def test_cli_passes_on_valid_log(tmp_path):
    log = tmp_path / "valid.jsonl"
    _write_log(log, _chain(3))
    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "M3 event log: PASS" in result.stdout
    assert "events_verified=3" in result.stdout


def test_cli_fails_on_tampered_log(tmp_path):
    log = tmp_path / "tampered.jsonl"
    events = _chain(3)
    events[1] = {**events[1], "payload": {"tampered": True}}
    _write_log(log, events)
    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "M3 event log: FAIL" in result.stdout


def test_cli_exits_1_without_traceback_on_malformed_log(tmp_path):
    log = tmp_path / "malformed.jsonl"
    event = _chain(1)[0]
    event["sequence"] = True
    log.write_text(json.dumps(event) + "\n")

    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "M3 event log: FAIL" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_cli_exits_1_on_invalid_json_syntax(tmp_path):
    log = tmp_path / "invalid-json.jsonl"
    log.write_text('{"schema_version":\n')

    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(log)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "M3 event log: FAIL" in result.stdout
    assert "invalid JSON" in result.stdout
    assert "line" in result.stdout and "column" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_cli_exits_2_on_missing_file():
    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", "no_such_file.jsonl"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
