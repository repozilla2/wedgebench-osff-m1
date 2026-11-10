"""Adversarial controls for the separate M3 workflow-completeness profile."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.event_log import hash_event, load_events
from tools.verify_event_log import verify
from tools.verify_m3_workflow import PROFILE_ID, PROFILE_PATH, load_profile, verify_workflow

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_LOG = REPO_ROOT / "examples/m3/WBLOG-M3-example.jsonl"
EXAMPLE_ARTIFACT = REPO_ROOT / "examples/m3/EP-M2-example.json"


@pytest.fixture
def events():
    return load_events(EXAMPLE_LOG)


def reseal(events):
    """Keep malicious controls integrity-valid so the profile must reject them."""
    for index, event in enumerate(events):
        event["sequence"] = index
        event["previous_event_hash"] = events[index - 1]["event_hash"] if index else None
        event["event_hash"] = hash_event({
            key: value for key, value in event.items() if key != "event_hash"
        })
    return events


def fail_generation(events):
    for index in (1, 2):
        events[index]["payload"].pop("artifact_sha256")
        events[index]["payload"]["ok"] = False
    events[1]["payload"]["error"] = "Illustrative generation failure"
    events[2]["payload"]["error"] = "Validation skipped after generation failure"
    events[2]["payload"]["validation_passed"] = False
    events[4]["payload"]["success"] = False
    return reseal(events)


def run_cli(tmp_path, events, *arguments):
    path = tmp_path / "workflow.jsonl"
    path.write_text("".join(json.dumps(event) + "\n" for event in events))
    return subprocess.run(
        [sys.executable, "tools/verify_m3_workflow.py", str(path), *arguments],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )


def assert_invalid_profile(events):
    assert verify(events).passed, "control must pass the generic integrity verifier"
    result = verify_workflow(events)
    assert result["profile_completeness"] == "invalid"
    assert result["recorded_workflow_outcome"] == "indeterminate"
    assert result["test_execution"] == "unverified"
    assert result["profile_errors"]


def test_intact_fixture_is_complete_recorded_success_with_tests_skipped(events):
    result = verify_workflow(events)
    assert result["integrity"] == {"status": "pass", "errors": [], "warnings": []}
    assert result["profile_completeness"] == "complete"
    assert result["recorded_workflow_outcome"] == "succeeded"
    assert result["test_execution"] == "skipped"
    assert result["profile_errors"] == []
    assert result["profile_id"] == PROFILE_ID
    assert result["profile_sha256"] == hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest()


@pytest.mark.parametrize("retained_events", [1, 2, 3, 4])
def test_valid_prefix_still_passes_integrity_but_is_incomplete(events, retained_events):
    prefix = events[:retained_events]
    assert verify(prefix).passed
    result = verify_workflow(prefix)
    assert result["profile_completeness"] == "incomplete"
    assert result["recorded_workflow_outcome"] == "indeterminate"
    assert result["test_execution"] == "unverified"


def test_complete_generation_failure_is_a_complete_failed_record(events):
    result = verify_workflow(fail_generation(events))
    assert result["integrity"]["status"] == "pass"
    assert result["profile_completeness"] == "complete"
    assert result["recorded_workflow_outcome"] == "failed"
    assert result["test_execution"] == "skipped"
    assert result["profile_errors"] == []


def test_complete_validation_failure_is_a_complete_failed_record(events):
    events[2]["payload"].update(
        ok=False, validation_passed=False, error="Illustrative validation exception"
    )
    events[4]["payload"]["success"] = False
    result = verify_workflow(reseal(events))
    assert result["integrity"]["status"] == "pass"
    assert result["profile_completeness"] == "complete"
    assert result["recorded_workflow_outcome"] == "failed"


def test_current_runner_failed_generation_record_conforms(tmp_path, monkeypatch):
    from tools import run_m3_demo

    def generation_failure(_directory):
        raise RuntimeError("controlled generation failure")

    monkeypatch.setattr(run_m3_demo, "_run_m2", generation_failure)
    path = tmp_path / "runner-failure.jsonl"
    assert run_m3_demo.run(path) == 1
    result = verify_workflow(load_events(path))
    assert result["profile_completeness"] == "complete"
    assert result["recorded_workflow_outcome"] == "failed"
    assert result["test_execution"] == "skipped"


def test_complete_failure_cli_exits_one_and_reports_complete(tmp_path, events):
    completed = run_cli(tmp_path, fail_generation(events))
    assert completed.returncode == 1
    result = json.loads(completed.stdout)
    assert result["profile_completeness"] == "complete"
    assert result["recorded_workflow_outcome"] == "failed"


def test_unrecomputed_tamper_is_an_integrity_failure(events):
    events[4]["payload"]["success"] = False
    result = verify_workflow(events)
    assert result["integrity"]["status"] == "fail"
    assert result["profile_completeness"] == "unverified"
    assert result["recorded_workflow_outcome"] == "indeterminate"


@pytest.mark.parametrize("event", [None, [], 1, "event"])
def test_malformed_event_fails_without_profile_interpretation(event):
    result = verify_workflow([event])
    assert result["integrity"]["status"] == "fail"
    assert result["profile_completeness"] == "unverified"


def test_empty_log_is_an_integrity_failure():
    result = verify_workflow([])
    assert result["integrity"]["status"] == "fail"
    assert result["profile_completeness"] == "unverified"


@pytest.mark.parametrize("value", ["true", 1, 0, None, []])
@pytest.mark.parametrize("index,field", [(1, "ok"), (2, "validation_passed"), (4, "success")])
def test_boolean_claims_require_actual_booleans(events, index, field, value):
    events[index]["payload"][field] = value
    assert_invalid_profile(reseal(events))


@pytest.mark.parametrize("value", [True, 5.0, "5", None])
def test_emitted_count_requires_an_integer(events, value):
    events[4]["payload"]["events_emitted"] = value
    assert_invalid_profile(reseal(events))


@pytest.mark.parametrize("index,field", [
    (0, "log_path"), (0, "m2_artifact_path"), (1, "ok"), (1, "error"),
    (2, "validation_passed"), (3, "reason"), (3, "acceptance_command"),
    (4, "success"), (4, "events_emitted"),
])
def test_required_payload_field_omission_fails(events, index, field):
    del events[index]["payload"][field]
    assert_invalid_profile(reseal(events))


@pytest.mark.parametrize("index,field", [(0, "log_path"), (3, "reason"), (3, "acceptance_command")])
def test_required_text_cannot_be_blank(events, index, field):
    events[index]["payload"][field] = "  "
    assert_invalid_profile(reseal(events))


@pytest.mark.parametrize("index", [1, 2])
def test_successful_stage_requires_a_digest(events, index):
    del events[index]["payload"]["artifact_sha256"]
    assert_invalid_profile(reseal(events))


@pytest.mark.parametrize("index", [1, 2])
def test_successful_stage_cannot_also_record_an_error(events, index):
    events[index]["payload"]["error"] = "stage failed"
    assert_invalid_profile(reseal(events))


def test_failed_stage_requires_error_text(events):
    events = fail_generation(events)
    events[1]["payload"]["error"] = None
    assert_invalid_profile(reseal(events))


@pytest.mark.parametrize("index", [1, 2])
@pytest.mark.parametrize("error", ["", "  ", "\t\n"])
def test_failed_stage_rejects_blank_error_text(events, index, error):
    events = fail_generation(events)
    events[index]["payload"]["error"] = error
    assert_invalid_profile(reseal(events))


def test_validation_flags_must_agree(events):
    events[2]["payload"]["validation_passed"] = False
    assert_invalid_profile(reseal(events))


def test_validation_success_after_failed_generation_is_rejected(events):
    events[1]["payload"].update(ok=False, error="generation failed")
    events[4]["payload"]["success"] = False
    assert_invalid_profile(reseal(events))


@pytest.mark.parametrize("failed_stages", [False, True])
def test_completion_outcome_must_match_stage_outcomes(events, failed_stages):
    if failed_stages:
        events = fail_generation(events)
    events[4]["payload"]["success"] = failed_stages
    assert_invalid_profile(reseal(events))


def test_emitted_count_must_match_the_required_profile(events):
    events[4]["payload"]["events_emitted"] = 4
    assert_invalid_profile(reseal(events))


def test_deleting_a_required_step_and_reducing_count_cannot_hide_omission(events):
    del events[2]
    events[-1]["payload"]["events_emitted"] = len(events)
    assert_invalid_profile(reseal(events))


def test_duplicate_event_cannot_satisfy_the_profile(events):
    events.insert(2, copy.deepcopy(events[1]))
    events[-1]["payload"]["events_emitted"] = len(events)
    assert_invalid_profile(reseal(events))


def test_reordered_rehashed_events_fail_the_profile(events):
    events[1], events[2] = events[2], events[1]
    assert_invalid_profile(reseal(events))


def test_test_execution_cannot_be_relabelled_as_passed(events):
    events[3]["event_type"] = "tests_passed"
    assert_invalid_profile(reseal(events))


def test_skipped_tests_cannot_carry_a_passing_tests_claim(events):
    events[3]["payload"]["tests_passed"] = True
    assert_invalid_profile(reseal(events))


def test_unrecognised_lifecycle_claim_is_rejected(events):
    events[4]["payload"]["recovered_in_same_instance"] = True
    assert_invalid_profile(reseal(events))


def test_top_level_physical_validation_claim_is_rejected(events):
    events[0]["physical_device_validated"] = True
    assert_invalid_profile(reseal(events))


def test_unsupported_example_status_is_rejected(events):
    events[0]["payload"]["example_status"] = "physical_execution"
    assert_invalid_profile(reseal(events))


def test_generic_one_based_sequence_remains_valid_but_fails_this_profile(events):
    for event in events:
        event["sequence"] += 1
    for index, event in enumerate(events):
        event["previous_event_hash"] = events[index - 1]["event_hash"] if index else None
        event["event_hash"] = hash_event({key: value for key, value in event.items() if key != "event_hash"})
    assert_invalid_profile(events)


def test_empty_run_identity_is_rejected(events):
    for event in events:
        event["run_id"] = ""
    assert_invalid_profile(reseal(events))


def test_stage_artifact_cannot_differ_from_declared_artifact(tmp_path, events):
    duplicate = tmp_path / "same-content.json"
    duplicate.write_bytes(EXAMPLE_ARTIFACT.read_bytes())
    events[2]["payload"]["artifact_path"] = str(duplicate)
    assert_invalid_profile(reseal(events))


def test_missing_artifact_is_incomplete_despite_generic_integrity_pass(tmp_path, events):
    path = str(tmp_path / "missing.json")
    events[0]["payload"]["m2_artifact_path"] = path
    events[1]["payload"]["artifact_path"] = path
    events[2]["payload"]["artifact_path"] = path
    events = reseal(events)
    assert verify(events).passed
    result = verify_workflow(events)
    assert result["integrity"]["warnings"]
    assert result["profile_completeness"] == "incomplete"
    assert result["recorded_workflow_outcome"] == "indeterminate"


def test_missing_artifacts_do_not_hide_different_recorded_digests(tmp_path, events):
    path = str(tmp_path / "missing.json")
    events[0]["payload"]["m2_artifact_path"] = path
    events[1]["payload"]["artifact_path"] = path
    events[2]["payload"]["artifact_path"] = path
    events[2]["payload"]["artifact_sha256"] = "f" * 64
    assert_invalid_profile(reseal(events))


def test_artifact_mutation_fails_integrity(tmp_path, events):
    path = tmp_path / "changed.json"
    path.write_text("changed content\n")
    events[0]["payload"]["m2_artifact_path"] = str(path)
    events[1]["payload"]["artifact_path"] = str(path)
    events[2]["payload"]["artifact_path"] = str(path)
    result = verify_workflow(reseal(events))
    assert result["integrity"]["status"] == "fail"
    assert result["profile_completeness"] == "unverified"


def test_profile_id_mismatch_fails_closed(events):
    with pytest.raises(ValueError, match="unsupported workflow profile"):
        verify_workflow(events, expected_profile_id="orbital-recovery-v1")


def test_retained_profile_digest_mismatch_fails_closed(events):
    with pytest.raises(ValueError, match="SHA-256 does not match"):
        verify_workflow(events, expected_profile_sha256="0" * 64)


def test_retained_profile_digest_and_cli_positive_control(tmp_path, events):
    _, digest = load_profile()
    completed = run_cli(tmp_path, events, "--expected-profile-sha256", digest.upper())
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["profile_sha256"] == digest
    assert result["test_execution"] == "skipped"


@pytest.mark.parametrize("arguments", [
    ["--profile-id", "other-profile"],
    ["--expected-profile-sha256", "0" * 64],
])
def test_cli_profile_mismatch_has_no_success_result(tmp_path, events, arguments):
    completed = run_cli(tmp_path, events, *arguments)
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "Traceback" not in completed.stderr


def test_cli_malformed_json_is_clean_failure(tmp_path):
    path = tmp_path / "malformed.jsonl"
    path.write_text("{invalid JSON}\n")
    completed = subprocess.run(
        [sys.executable, "tools/verify_m3_workflow.py", str(path)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 1
    assert "Invalid event log" in completed.stderr
    assert "Traceback" not in completed.stderr


def test_cli_missing_log_is_clean_input_error(tmp_path):
    completed = subprocess.run(
        [sys.executable, "tools/verify_m3_workflow.py", str(tmp_path / "missing.jsonl")],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 2
    assert "Traceback" not in completed.stderr


def test_demo_is_deterministic_and_all_controls_match():
    command = [sys.executable, "tools/demo_m3_workflow.py"]
    first = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, timeout=10)
    second = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, timeout=10)
    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout
    data = json.loads(first.stdout)
    assert data["example_status"] == "illustrative"
    assert [item["control"] for item in data["controls"]] == [
        "intact", "truncated", "complete_failed", "tampered"
    ]
    assert all(item["expectation_met"] for item in data["controls"])
