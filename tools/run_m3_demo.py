#!/usr/bin/env python3
"""
run_m3_demo.py — WedgeBench M3 demo runner.

Wraps the M2 evidence workflow in a tamper-evident JSONL event log:

  run_started
  m2_evidence_generated   (payload includes artifact_path, artifact_sha256)
  m2_evidence_validated
  tests_skipped
  run_completed

The resulting log is written to evidence/m3/WBLOG-M3-demo.jsonl by default
and is verified by tools/verify_event_log.py on completion.

Usage:
    python3 tools/run_m3_demo.py [--log-path PATH]

Exit codes:
    0 — all steps passed, log verified
    1 — one or more steps failed
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Ensure repo root is importable when invoked as python3 tools/run_m3_demo.py
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.event_log import SCHEMA_VERSION, append_event, create_event
from tools.verify_event_log import verify


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_m2_generator_main():
    """Load and return the M2 generator entry point."""
    # Import here to keep the path-bootstrap side-effect contained.
    # run_m2_tcg imports tcg_adapter which lives in tools/; we need the
    # tools/ directory importable for that relative import to work.
    tools_dir = _REPO_ROOT / "tools"
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "run_m2_tcg", _REPO_ROOT / "tools" / "run_m2_tcg.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main


def _run_m2(evidence_dir: Path) -> Path:
    """Run M2 and return only a fresh artifact from a successful invocation."""
    artifact_path = evidence_dir / "EP-M2-go-tcg-storage-draft.json"
    if artifact_path.exists():
        artifact_path.unlink()

    try:
        return_code = _load_m2_generator_main()()
    except Exception:
        if artifact_path.exists():
            artifact_path.unlink()
        raise
    if return_code != 0:
        if artifact_path.exists():
            artifact_path.unlink()
        raise RuntimeError(f"M2 evidence generator exited with status {return_code}")

    if not artifact_path.is_file():
        raise FileNotFoundError(
            f"M2 evidence generator did not produce expected artifact: {artifact_path}"
        )

    return artifact_path


def _validate_m2(artifact_path: Path) -> bool:
    """Return True if the M2 artifact passes validation."""
    from tools.validate_m2_evidence import validate

    data = json.loads(artifact_path.read_text())
    result = validate(data)
    return result.passed


def run(log_path: Path) -> int:
    """Execute the M3 demo workflow and write a verified JSONL log.

    Returns 0 on full success, 1 on any failure.
    """
    run_id = str(uuid.uuid4())
    m2_evidence_dir = _REPO_ROOT / "evidence" / "m2"
    m2_artifact_path = m2_evidence_dir / "EP-M2-go-tcg-storage-draft.json"

    log_path.parent.mkdir(parents=True, exist_ok=True)
    # Start fresh for this run
    if log_path.exists():
        log_path.unlink()

    events: list[dict] = []
    failed = False

    def _emit(event_type: str, payload: dict) -> None:
        seq = len(events)
        prev_hash = events[-1]["event_hash"] if events else None
        ev = create_event(
            run_id=run_id,
            sequence=seq,
            event_type=event_type,
            payload=payload,
            previous_event_hash=prev_hash,
            timestamp_utc=_now(),
        )
        events.append(ev)
        append_event(log_path, ev)

    # ── run_started ───────────────────────────────────────────────────────
    _emit("run_started", {
        "log_path": str(log_path),
        "m2_artifact_path": str(m2_artifact_path),
    })

    # ── m2_evidence_generated ─────────────────────────────────────────────
    try:
        generated_path = _run_m2(m2_evidence_dir)
        sha256 = _sha256_file(generated_path)
        _emit("m2_evidence_generated", {
            "artifact_path": str(m2_artifact_path),
            "artifact_sha256": sha256,
            "ok": True,
            "error": None,
        })
    except Exception as exc:
        failed = True
        _emit("m2_evidence_generated", {
            "artifact_path": str(m2_artifact_path),
            "ok": False,
            "error": str(exc),
        })

    # ── m2_evidence_validated ─────────────────────────────────────────────
    if not failed:
        try:
            passed = _validate_m2(m2_artifact_path)
            if not passed:
                failed = True
            _emit("m2_evidence_validated", {
                "artifact_path": str(m2_artifact_path),
                "artifact_sha256": _sha256_file(m2_artifact_path),
                "validation_passed": passed,
                "ok": passed,
                "error": None if passed else "M2 artifact failed validation",
            })
        except Exception as exc:
            failed = True
            _emit("m2_evidence_validated", {
                "artifact_path": str(m2_artifact_path),
                "validation_passed": False,
                "ok": False,
                "error": str(exc),
            })
    else:
        _emit("m2_evidence_validated", {
            "artifact_path": str(m2_artifact_path),
            "validation_passed": False,
            "ok": False,
            "error": "skipped — m2_evidence_generated failed",
        })

    # ── tests_skipped ─────────────────────────────────────────────────────
    _emit("tests_skipped", {
        "reason": (
            "run_m3_demo.py verifies evidence/log plumbing only; "
            "pytest remains part of make-based acceptance"
        ),
        "acceptance_command": "pytest -q",
    })

    # ── run_completed ─────────────────────────────────────────────────────
    _emit("run_completed", {
        "success": not failed,
        "events_emitted": len(events) + 1,  # +1 for this event
    })

    # ── verify the log itself ─────────────────────────────────────────────
    from tools.event_log import load_events

    loaded = load_events(log_path)
    result = verify(loaded)
    if not result.passed:
        print("ERROR: generated log failed self-verification:", file=sys.stderr)
        print(result.report(), file=sys.stderr)
        return 1

    print(f"M3 demo log: {'PASS' if not failed else 'FAIL (workflow errors)'}")
    print(f"log_path={log_path}")
    print(f"events_emitted={len(events)}")
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="WedgeBench M3 demo runner"
    )
    ap.add_argument(
        "--log-path",
        default=str(_REPO_ROOT / "evidence" / "m3" / "WBLOG-M3-demo.jsonl"),
        help="Path for the output JSONL event log",
    )
    args = ap.parse_args()
    return run(Path(args.log_path))


if __name__ == "__main__":
    sys.exit(main())
