"""
event_log.py — WedgeBench M3 tamper-evident JSONL event log core.

Each event in the log is a JSON object on a single line (JSONL).  Events are
linked in a hash chain: every event records the SHA-256 hash of its
predecessor, and its own hash covers all fields (including that link).

Public API
----------
canonical_json(obj)          -> bytes   deterministic JSON bytes for hashing
hash_event(event_without_hash) -> str   hex SHA-256 of canonical_json(event)
create_event(...)            -> dict    build a complete, hashed event dict
append_event(path, event)    -> None    append one event to a JSONL file
load_events(path)            -> list    read all events from a JSONL file

Schema
------
{
    "schema_version":      str,    # "m3-log-v1"
    "run_id":              str,    # caller-supplied run identifier
    "sequence":            int,    # 0-based, monotonically increasing
    "timestamp_utc":       str,    # ISO 8601, UTC
    "event_type":          str,    # e.g. "run_start", "case_result"
    "payload":             dict,   # arbitrary event data
    "previous_event_hash": str|None,  # null for first event
    "event_hash":          str     # sha256(canonical_json(event sans event_hash))
}
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "m3-log-v1"


# ── Canonical JSON ────────────────────────────────────────────────────────────

def canonical_json(obj: Any) -> bytes:
    """Return deterministic, compact JSON bytes with sorted keys."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_event(event_without_hash: dict) -> str:
    """Return hex SHA-256 of the canonical JSON of an event dict that does
    not yet contain the 'event_hash' field."""
    return hashlib.sha256(canonical_json(event_without_hash)).hexdigest()


# ── Event construction ────────────────────────────────────────────────────────

def create_event(
    *,
    run_id: str,
    sequence: int,
    event_type: str,
    payload: dict,
    previous_event_hash: str | None,
    timestamp_utc: str | None = None,
    schema_version: str = SCHEMA_VERSION,
) -> dict:
    """Build a complete, self-hashed event dict.

    Parameters
    ----------
    run_id:               Caller-supplied identifier for this run.
    sequence:             0-based position of this event in the chain.
    event_type:           String label for the event kind.
    payload:              Arbitrary dict of event-specific data.
    previous_event_hash:  Hash of the preceding event, or None for the first.
    timestamp_utc:        ISO 8601 UTC string; defaults to now if omitted.
    schema_version:       Schema label; defaults to SCHEMA_VERSION.
    """
    if timestamp_utc is None:
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    body: dict = {
        "schema_version": schema_version,
        "run_id": run_id,
        "sequence": sequence,
        "timestamp_utc": timestamp_utc,
        "event_type": event_type,
        "payload": payload,
        "previous_event_hash": previous_event_hash,
    }
    body["event_hash"] = hash_event(body)
    return body


# ── Persistence ───────────────────────────────────────────────────────────────

def append_event(path: str | Path, event: dict) -> None:
    """Append one event as a single JSON line to the JSONL file at *path*.

    The file is created if it does not exist.  Each call writes exactly one
    line followed by a newline, so the file remains valid JSONL after
    concurrent appends are not expected (single-writer model).
    """
    line = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def load_events(path: str | Path) -> list[dict]:
    """Read all events from a JSONL file.  Returns a list in file order.

    Blank lines are skipped.  Raises json.JSONDecodeError on malformed lines.
    """
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
