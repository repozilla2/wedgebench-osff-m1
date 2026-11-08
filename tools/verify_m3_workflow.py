#!/usr/bin/env python3
"""Check the versioned M3 demo workflow profile after generic integrity checks.

The result separates integrity, profile completeness, recorded workflow outcome
and skipped tests. It checks record consistency, without attesting execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.event_log import SCHEMA_VERSION, load_events
from tools.verify_event_log import REQUIRED_FIELDS, verify

PROFILE_ID = "m3-demo-workflow-v1"
PROFILE_PATH = _REPO_ROOT / "profiles" / f"{PROFILE_ID}.json"
_EVENT_TYPES = [
    "run_started",
    "m2_evidence_generated",
    "m2_evidence_validated",
    "tests_skipped",
    "run_completed",
]
_FIELD_TYPES = {
    "string": (str,),
    "boolean": (bool,),
    "integer": (int,),
    "nullable_string": (str, type(None)),
}


def load_profile(
    *,
    expected_profile_id: str = PROFILE_ID,
    expected_profile_sha256: str | None = None,
) -> tuple[dict, str]:
    """Load the bundled, supported policy and optionally check a retained digest."""
    if expected_profile_id != PROFILE_ID:
        raise ValueError(f"unsupported workflow profile {expected_profile_id!r}")

    raw = PROFILE_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_profile_sha256 is not None and digest != expected_profile_sha256.lower():
        raise ValueError("workflow profile SHA-256 does not match the expected digest")

    profile = json.loads(raw)
    if (
        not isinstance(profile, dict)
        or profile.get("schema_version") != "m3-workflow-profile-v1"
        or profile.get("profile_id") != PROFILE_ID
        or profile.get("event_schema_version") != SCHEMA_VERSION
        or type(profile.get("sequence_start")) is not int
        or profile["sequence_start"] != 0
        or profile.get("required_event_types") != _EVENT_TYPES
    ):
        raise ValueError("bundled workflow profile has an unsupported definition")
    return profile, digest


def _payload_errors(event: dict, rule: dict) -> list[str]:
    payload = event["payload"]
    label = event["event_type"]
    required = rule["required"]
    allowed = {**required, **rule["optional"]}
    errors = []

    for field in sorted(required.keys() - payload.keys()):
        errors.append(f"{label}.payload.{field} is required")
    for field in sorted(payload.keys() - allowed.keys()):
        errors.append(f"{label}.payload.{field} is outside this profile")
    for field, kind in allowed.items():
        if field not in payload:
            continue
        value = payload[field]
        if type(value) not in _FIELD_TYPES[kind]:
            errors.append(f"{label}.payload.{field} must be {kind}")
        elif kind == "string" and not value.strip():
            errors.append(f"{label}.payload.{field} must be nonempty")
    return errors


def verify_workflow(
    events: list[object],
    *,
    expected_profile_id: str = PROFILE_ID,
    expected_profile_sha256: str | None = None,
) -> dict:
    """Evaluate records against the bundled profile without running the workflow."""
    profile, digest = load_profile(
        expected_profile_id=expected_profile_id,
        expected_profile_sha256=expected_profile_sha256,
    )
    integrity = verify(events)
    result = {
        "schema_version": "m3-workflow-result-v1",
        "profile_id": profile["profile_id"],
        "profile_sha256": digest,
        "integrity": {
            "status": "pass" if integrity.passed else "fail",
            "errors": integrity.errors,
            "warnings": integrity.warnings,
        },
        "profile_completeness": "unverified",
        "recorded_workflow_outcome": "indeterminate",
        "test_execution": "unverified",
        "profile_errors": [],
    }
    if not integrity.passed:
        return result

    expected = profile["required_event_types"]
    observed = [event["event_type"] for event in events]
    errors = result["profile_errors"]
    if observed != expected:
        result["profile_completeness"] = (
            "incomplete" if observed == expected[:len(observed)] else "invalid"
        )
        errors.append(f"required event sequence {expected!r}, observed {observed!r}")
        return result

    for event in events:
        extra_fields = event.keys() - set(REQUIRED_FIELDS)
        if extra_fields:
            errors.append(
                f"{event['event_type']} has fields outside this profile: "
                f"{sorted(extra_fields)!r}"
            )
        errors.extend(_payload_errors(event, profile["payload_fields"][event["event_type"]]))
    if errors:
        result["profile_completeness"] = "invalid"
        return result

    started, generated, validated, _, completed = [
        event["payload"] for event in events
    ]
    if events[0]["sequence"] != profile["sequence_start"]:
        errors.append("workflow sequence must start at zero")
    if not events[0]["run_id"].strip():
        errors.append("workflow run_id must be nonempty")
    if started.get("example_status", "illustrative") != "illustrative":
        errors.append("supplied example_status must be 'illustrative'")

    for name, stage in (("generation", generated), ("validation", validated)):
        if stage["artifact_path"] != started["m2_artifact_path"]:
            errors.append(f"{name} artifact_path differs from the run's declared artifact")
        if stage["ok"] and stage["error"] is not None:
            errors.append(f"successful {name} must have error=null")
        if not stage["ok"] and (
            stage["error"] is None or not stage["error"].strip()
        ):
            errors.append(f"failed {name} must record a nonempty error string")
        if stage["ok"] and "artifact_sha256" not in stage:
            errors.append(f"successful {name} requires artifact_sha256")

    if generated.get("artifact_sha256") and validated.get("artifact_sha256"):
        if generated["artifact_sha256"].lower() != validated["artifact_sha256"].lower():
            errors.append("generation and validation refer to different artifact digests")
    if validated["ok"] != validated["validation_passed"]:
        errors.append("validation ok and validation_passed disagree")
    if validated["ok"] and not generated["ok"]:
        errors.append("validation cannot succeed after failed generation")
    if completed["events_emitted"] != len(expected):
        errors.append("run_completed.events_emitted differs from the required event count")
    expected_success = generated["ok"] and validated["ok"]
    if completed["success"] != expected_success:
        errors.append("run_completed.success disagrees with the recorded stage outcomes")

    if errors:
        result["profile_completeness"] = "invalid"
        return result
    if integrity.warnings:
        result["profile_completeness"] = "incomplete"
        errors.append("required artifact verification was skipped")
        return result

    result["profile_completeness"] = "complete"
    result["recorded_workflow_outcome"] = "succeeded" if expected_success else "failed"
    result["test_execution"] = "skipped"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_path", type=Path)
    parser.add_argument("--profile-id", default=PROFILE_ID)
    parser.add_argument("--expected-profile-sha256")
    args = parser.parse_args()

    try:
        events = load_events(args.log_path)
    except (json.JSONDecodeError, UnicodeError) as exc:
        print(f"Invalid event log: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not read event log: {exc}", file=sys.stderr)
        return 2

    try:
        result = verify_workflow(
            events,
            expected_profile_id=args.profile_id,
            expected_profile_sha256=args.expected_profile_sha256,
        )
    except (OSError, ValueError) as exc:
        print(f"Could not load workflow profile: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if (
        result["profile_completeness"] == "complete"
        and result["recorded_workflow_outcome"] == "succeeded"
    ) else 1


if __name__ == "__main__":
    sys.exit(main())
