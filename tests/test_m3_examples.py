"""Checks for the committed illustrative M3 example artifacts."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from tools.event_log import load_events
from tools.validate_m2_evidence import validate
from tools.verify_event_log import verify

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_DIR = REPO_ROOT / "examples" / "m3"
EXAMPLE_ARTIFACT = EXAMPLE_DIR / "EP-M2-example.json"
EXAMPLE_LOG = EXAMPLE_DIR / "WBLOG-M3-example.jsonl"


def test_committed_m2_example_passes_actual_validator():
    result = validate(json.loads(EXAMPLE_ARTIFACT.read_text()))
    assert result.passed, result.report()


def test_committed_example_verifies_via_cli():
    result = subprocess.run(
        [sys.executable, "tools/verify_event_log.py", str(EXAMPLE_LOG)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "M3 event log: PASS" in result.stdout
    assert "events_verified=5" in result.stdout


def test_committed_example_uses_canonical_schema_and_sequence():
    events = load_events(EXAMPLE_LOG)
    assert verify(events).passed
    assert {event["schema_version"] for event in events} == {"m3-log-v1"}
    assert [event["event_type"] for event in events] == [
        "run_started",
        "m2_evidence_generated",
        "m2_evidence_validated",
        "tests_skipped",
        "run_completed",
    ]


def test_committed_example_artifact_hash_matches():
    expected = hashlib.sha256(EXAMPLE_ARTIFACT.read_bytes()).hexdigest()
    artifact_events = [
        event
        for event in load_events(EXAMPLE_LOG)
        if event["event_type"] in {"m2_evidence_generated", "m2_evidence_validated"}
    ]
    assert artifact_events
    for event in artifact_events:
        assert event["payload"]["artifact_path"] == "examples/m3/EP-M2-example.json"
        assert event["payload"]["artifact_sha256"] == expected


def test_committed_examples_have_no_absolute_personal_paths():
    for path in EXAMPLE_DIR.iterdir():
        if path.is_file():
            content = path.read_text()
            assert "/Users/" not in content
            assert "m3/event-log-release-candidate" not in content

    for event in load_events(EXAMPLE_LOG):
        for key in ("artifact_path", "log_path", "m2_artifact_path"):
            value = event["payload"].get(key)
            if value is not None:
                assert not Path(value).is_absolute()
