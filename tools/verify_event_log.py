#!/usr/bin/env python3
"""
verify_event_log.py — WedgeBench M3 JSONL event log verifier.

Verifies a JSONL event log produced by tools/event_log.py:

  1. All required fields present on every event.
  2. schema_version is an accepted value.
  3. event_hash recomputes correctly for every event.
  4. Hash chain is intact (previous_event_hash links).
  5. First event has previous_event_hash == null.
  6. sequence starts at 0 or 1 and increments by 1 with no gaps.
  7. run_id is consistent across all events.
  8. If a payload contains artifact_path + artifact_sha256 and the file
     exists, the SHA-256 is recomputed and compared.  Missing files are
     reported as warnings, not errors.

Usage:
    python3 tools/verify_event_log.py <log.jsonl>

Exit codes:
    0 — PASS
    1 — FAIL (integrity errors found)
    2 — Usage / file error
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# Ensure the repo root is importable when the script is run directly.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.event_log import SCHEMA_VERSION, hash_event, load_events

ACCEPTED_SCHEMA_VERSIONS = {SCHEMA_VERSION, "m3-log-v1"}

REQUIRED_FIELDS = (
    "schema_version",
    "run_id",
    "sequence",
    "timestamp_utc",
    "event_type",
    "payload",
    "previous_event_hash",
    "event_hash",
)


# ── Result accumulator ────────────────────────────────────────────────────────

class _Result:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(f"  ERROR: {msg}")

    def warn(self, msg: str) -> None:
        self.warnings.append(f"  WARN:  {msg}")

    @property
    def passed(self) -> bool:
        return not self.errors

    def report(self) -> str:
        lines = self.errors + self.warnings
        return "\n".join(lines)


# ── Core verifier ─────────────────────────────────────────────────────────────

def verify(events: list[dict]) -> _Result:
    """Verify a list of event dicts loaded from a JSONL log.

    Returns a _Result whose .passed reflects whether all integrity checks
    passed.  Warnings are informational and do not affect .passed.
    """
    r = _Result()

    if not events:
        r.error("Log is empty — no events to verify")
        return r

    # ── Per-event checks ──────────────────────────────────────────────────
    for i, ev in enumerate(events):
        label = f"event[{i}]"

        # Required fields
        for field in REQUIRED_FIELDS:
            if field not in ev:
                r.error(f"{label}: missing required field '{field}'")

        # Bail on this event if structure is too broken to continue
        missing = [f for f in REQUIRED_FIELDS if f not in ev]
        if missing:
            continue

        # schema_version
        if ev["schema_version"] not in ACCEPTED_SCHEMA_VERSIONS:
            r.error(
                f"{label}: unrecognised schema_version {ev['schema_version']!r}; "
                f"accepted: {sorted(ACCEPTED_SCHEMA_VERSIONS)}"
            )

        # event_hash recomputation
        body = {k: v for k, v in ev.items() if k != "event_hash"}
        expected_hash = hash_event(body)
        if ev["event_hash"] != expected_hash:
            r.error(
                f"{label}: event_hash mismatch — stored {ev['event_hash']!r}, "
                f"recomputed {expected_hash!r}"
            )

        # Artifact hash (optional, only when payload carries both keys)
        payload = ev.get("payload") or {}
        if isinstance(payload, dict):
            artifact_path = payload.get("artifact_path")
            artifact_sha256 = payload.get("artifact_sha256")
            if artifact_path is not None and artifact_sha256 is not None:
                p = Path(artifact_path)
                if p.exists():
                    actual = hashlib.sha256(p.read_bytes()).hexdigest()
                    if actual != artifact_sha256:
                        r.error(
                            f"{label}: artifact_sha256 mismatch for {artifact_path!r} — "
                            f"stored {artifact_sha256!r}, recomputed {actual!r}"
                        )
                else:
                    r.warn(
                        f"{label}: artifact_path {artifact_path!r} not found; "
                        "artifact hash check skipped"
                    )

    # Stop cross-event checks if per-event errors make them unreliable
    if not r.passed:
        return r

    # ── Cross-event chain checks ──────────────────────────────────────────

    # First event: previous_event_hash must be null
    first = events[0]
    if first["previous_event_hash"] is not None:
        r.error(
            f"event[0]: first event must have previous_event_hash=null, "
            f"got {first['previous_event_hash']!r}"
        )

    # Sequence: must start at 0 or 1 and increment by 1
    start_seq = first["sequence"]
    if start_seq not in (0, 1):
        r.error(
            f"event[0]: sequence must start at 0 or 1, got {start_seq}"
        )

    for i in range(1, len(events)):
        prev = events[i - 1]
        curr = events[i]

        # Hash chain linkage
        if curr["previous_event_hash"] != prev["event_hash"]:
            r.error(
                f"event[{i}]: previous_event_hash {curr['previous_event_hash']!r} "
                f"does not match event[{i - 1}].event_hash {prev['event_hash']!r}"
            )

        # Sequence increment
        expected_seq = prev["sequence"] + 1
        if curr["sequence"] != expected_seq:
            r.error(
                f"event[{i}]: sequence {curr['sequence']} is not "
                f"prev sequence {prev['sequence']} + 1 (expected {expected_seq})"
            )

    # run_id consistency
    run_ids = {ev["run_id"] for ev in events}
    if len(run_ids) > 1:
        r.error(f"run_id is not consistent across events: found {sorted(run_ids)}")

    return r


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: python3 tools/verify_event_log.py <log.jsonl>",
            file=sys.stderr,
        )
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    try:
        events = load_events(path)
    except Exception as exc:
        print(f"ERROR: could not load log: {exc}", file=sys.stderr)
        return 2

    result = verify(events)

    if result.passed:
        print("M3 event log: PASS")
        print(f"events_verified={len(events)}")
        if result.warnings:
            print(result.report())
        return 0
    else:
        print("M3 event log: FAIL")
        print(result.report())
        return 1


if __name__ == "__main__":
    sys.exit(main())
