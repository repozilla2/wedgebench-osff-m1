#!/usr/bin/env python3
"""Run deterministic illustrative controls for the M3 workflow profile."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.event_log import hash_event, load_events
from tools.verify_m3_workflow import verify_workflow


def main() -> int:
    intact = load_events(_REPO_ROOT / "examples/m3/WBLOG-M3-example.jsonl")
    failed = copy.deepcopy(intact)
    for index in (1, 2):
        payload = failed[index]["payload"]
        payload.pop("artifact_sha256")
        payload["ok"] = False
    failed[1]["payload"]["error"] = "Illustrative generation failure"
    failed[2]["payload"]["error"] = "Validation skipped after generation failure"
    failed[2]["payload"]["validation_passed"] = False
    failed[4]["payload"]["success"] = False
    for index, event in enumerate(failed):
        event["previous_event_hash"] = failed[index - 1]["event_hash"] if index else None
        event["event_hash"] = hash_event({
            key: value for key, value in event.items() if key != "event_hash"
        })

    tampered = copy.deepcopy(intact)
    tampered[4]["payload"]["success"] = False
    controls = [
        ("intact", intact, ("pass", "complete", "succeeded", "skipped")),
        ("truncated", intact[:-1], ("pass", "incomplete", "indeterminate", "unverified")),
        ("complete_failed", failed, ("pass", "complete", "failed", "skipped")),
        ("tampered", tampered, ("fail", "unverified", "indeterminate", "unverified")),
    ]
    results = []
    for name, events, expected in controls:
        result = verify_workflow(events)
        observed = (
            result["integrity"]["status"],
            result["profile_completeness"],
            result["recorded_workflow_outcome"],
            result["test_execution"],
        )
        results.append({"control": name, "expectation_met": observed == expected, **result})

    report = {"example_status": "illustrative", "controls": results}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if all(result["expectation_met"] for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
