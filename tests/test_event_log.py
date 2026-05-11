"""
Tests for tools/event_log.py — M3 tamper-evident JSONL hash-chain core.
"""
import hashlib
import json
from pathlib import Path

import pytest

from tools.event_log import (
    SCHEMA_VERSION,
    append_event,
    canonical_json,
    create_event,
    hash_event,
    load_events,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event(**kw) -> dict:
    defaults = dict(
        run_id="test-run",
        sequence=0,
        event_type="test_event",
        payload={"key": "value"},
        previous_event_hash=None,
        timestamp_utc="2026-05-11T00:00:00.000000Z",
    )
    defaults.update(kw)
    return create_event(**defaults)


# ── canonical_json ────────────────────────────────────────────────────────────

def test_canonical_json_returns_bytes():
    result = canonical_json({"b": 2, "a": 1})
    assert isinstance(result, bytes)


def test_canonical_json_sorts_keys():
    result = canonical_json({"z": 3, "a": 1, "m": 2})
    parsed = json.loads(result)
    assert list(parsed.keys()) == ["a", "m", "z"]


def test_canonical_json_compact_no_spaces():
    result = canonical_json({"a": 1, "b": 2})
    assert b" " not in result


def test_canonical_json_is_deterministic():
    obj = {"c": [1, 2, 3], "a": {"nested": True}, "b": None}
    assert canonical_json(obj) == canonical_json(obj)


def test_canonical_json_equal_for_same_content_different_insertion_order():
    d1 = {"a": 1, "b": 2}
    d2 = {"b": 2, "a": 1}
    assert canonical_json(d1) == canonical_json(d2)


# ── hash_event ────────────────────────────────────────────────────────────────

def test_hash_event_returns_hex_string():
    body = {"schema_version": "m3-draft", "sequence": 0, "payload": {}}
    result = hash_event(body)
    assert isinstance(result, str)
    assert len(result) == 64
    int(result, 16)  # must be valid hex


def test_hash_event_is_deterministic():
    body = {"a": 1, "b": "hello"}
    assert hash_event(body) == hash_event(body)


def test_hash_event_matches_manual_sha256():
    body = {"event_type": "run_start", "sequence": 0}
    expected = hashlib.sha256(canonical_json(body)).hexdigest()
    assert hash_event(body) == expected


def test_hash_event_changes_when_payload_changes():
    body1 = {"payload": {"x": 1}}
    body2 = {"payload": {"x": 2}}
    assert hash_event(body1) != hash_event(body2)


def test_hash_event_changes_when_any_field_changes():
    base = {"sequence": 0, "event_type": "a", "payload": {}}
    modified = {**base, "event_type": "b"}
    assert hash_event(base) != hash_event(modified)


# ── create_event ──────────────────────────────────────────────────────────────

def test_create_event_contains_all_required_fields():
    ev = _event()
    required = {
        "schema_version", "run_id", "sequence", "timestamp_utc",
        "event_type", "payload", "previous_event_hash", "event_hash",
    }
    assert required.issubset(ev.keys())


def test_create_event_schema_version_is_m3_draft():
    ev = _event()
    assert ev["schema_version"] == SCHEMA_VERSION


def test_create_event_first_event_has_null_previous_hash():
    ev = _event(sequence=0, previous_event_hash=None)
    assert ev["previous_event_hash"] is None


def test_create_event_event_hash_is_correct():
    ev = _event()
    body_without_hash = {k: v for k, v in ev.items() if k != "event_hash"}
    expected = hash_event(body_without_hash)
    assert ev["event_hash"] == expected


def test_create_event_event_hash_not_in_hashed_body():
    """event_hash must be excluded from the pre-image."""
    ev = _event()
    # Re-hash with event_hash included — must differ from the stored hash
    full_body_hash = hash_event(ev)
    assert ev["event_hash"] != full_body_hash


def test_create_event_payload_is_preserved():
    payload = {"trial": 7, "outcome": "accepted", "nested": {"ok": True}}
    ev = _event(payload=payload)
    assert ev["payload"] == payload


def test_create_event_sequence_is_preserved():
    ev = _event(sequence=42)
    assert ev["sequence"] == 42


def test_create_event_timestamp_defaults_to_now_when_omitted():
    ev = create_event(
        run_id="r",
        sequence=0,
        event_type="t",
        payload={},
        previous_event_hash=None,
    )
    assert isinstance(ev["timestamp_utc"], str)
    assert len(ev["timestamp_utc"]) > 0


def test_create_event_accepts_explicit_timestamp():
    ts = "2026-01-01T00:00:00.000000Z"
    ev = _event(timestamp_utc=ts)
    assert ev["timestamp_utc"] == ts


# ── Chain linking ─────────────────────────────────────────────────────────────

def test_second_event_links_to_first_event_hash():
    ev0 = _event(sequence=0, previous_event_hash=None)
    ev1 = create_event(
        run_id="test-run",
        sequence=1,
        event_type="next",
        payload={},
        previous_event_hash=ev0["event_hash"],
        timestamp_utc="2026-05-11T00:00:01.000000Z",
    )
    assert ev1["previous_event_hash"] == ev0["event_hash"]


def test_sequence_increments_across_chain():
    ev0 = _event(sequence=0, previous_event_hash=None)
    ev1 = create_event(
        run_id="test-run",
        sequence=1,
        event_type="t",
        payload={},
        previous_event_hash=ev0["event_hash"],
        timestamp_utc="2026-05-11T00:00:01.000000Z",
    )
    assert ev0["sequence"] == 0
    assert ev1["sequence"] == 1


def test_changing_payload_breaks_chain():
    ev0 = _event(sequence=0, previous_event_hash=None)
    ev1 = create_event(
        run_id="test-run",
        sequence=1,
        event_type="t",
        payload={"original": True},
        previous_event_hash=ev0["event_hash"],
        timestamp_utc="2026-05-11T00:00:01.000000Z",
    )
    # Tamper with ev0's payload — ev1's previous_event_hash no longer matches
    tampered_ev0 = {**ev0, "payload": {"tampered": True}}
    tampered_ev0_body = {k: v for k, v in tampered_ev0.items() if k != "event_hash"}
    recomputed_hash = hash_event(tampered_ev0_body)
    assert recomputed_hash != ev1["previous_event_hash"]


# ── JSONL roundtrip ───────────────────────────────────────────────────────────

def test_append_and_load_single_event(tmp_path):
    log = tmp_path / "test.jsonl"
    ev = _event()
    append_event(log, ev)
    loaded = load_events(log)
    assert len(loaded) == 1
    assert loaded[0] == ev


def test_append_and_load_multiple_events(tmp_path):
    log = tmp_path / "chain.jsonl"
    ev0 = _event(sequence=0, previous_event_hash=None)
    ev1 = create_event(
        run_id="test-run",
        sequence=1,
        event_type="second",
        payload={"n": 1},
        previous_event_hash=ev0["event_hash"],
        timestamp_utc="2026-05-11T00:00:01.000000Z",
    )
    ev2 = create_event(
        run_id="test-run",
        sequence=2,
        event_type="third",
        payload={"n": 2},
        previous_event_hash=ev1["event_hash"],
        timestamp_utc="2026-05-11T00:00:02.000000Z",
    )
    for ev in (ev0, ev1, ev2):
        append_event(log, ev)

    loaded = load_events(log)
    assert len(loaded) == 3
    assert loaded[0] == ev0
    assert loaded[1] == ev1
    assert loaded[2] == ev2


def test_load_preserves_event_hash(tmp_path):
    log = tmp_path / "ev.jsonl"
    ev = _event()
    append_event(log, ev)
    loaded = load_events(log)[0]
    assert loaded["event_hash"] == ev["event_hash"]


def test_each_line_is_valid_json(tmp_path):
    log = tmp_path / "lines.jsonl"
    ev0 = _event(sequence=0, previous_event_hash=None)
    ev1 = create_event(
        run_id="test-run",
        sequence=1,
        event_type="t",
        payload={},
        previous_event_hash=ev0["event_hash"],
        timestamp_utc="2026-05-11T00:00:01.000000Z",
    )
    append_event(log, ev0)
    append_event(log, ev1)

    lines = [l for l in log.read_text().splitlines() if l.strip()]
    assert len(lines) == 2
    for line in lines:
        parsed = json.loads(line)
        assert "event_hash" in parsed


def test_append_creates_file_if_not_exists(tmp_path):
    log = tmp_path / "new.jsonl"
    assert not log.exists()
    append_event(log, _event())
    assert log.exists()


def test_load_events_skips_blank_lines(tmp_path):
    log = tmp_path / "blank.jsonl"
    ev = _event()
    line = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    log.write_text(f"\n{line}\n\n")
    loaded = load_events(log)
    assert len(loaded) == 1


def test_hash_is_stable_across_calls():
    """Same inputs must produce the same hash on every call."""
    ev_a = _event(payload={"x": 1})
    ev_b = _event(payload={"x": 1})
    assert ev_a["event_hash"] == ev_b["event_hash"]
