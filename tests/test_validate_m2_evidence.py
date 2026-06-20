"""
Tests for tools/validate_m2_evidence.py
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.check_m2_environment import UPSTREAM_COMMIT, UPSTREAM_REPOSITORY
from tools.validate_m2_evidence import validate, ALLOWED_PARSER_OUTCOMES

# ── Helpers ───────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parents[1]


def _make_case(**overrides) -> dict:
    base = {
        "case": "valid_frame",
        "ok": True,
        "error": None,
        "response_len": 61,
        "frames_accepted": 1,
        "output_bytes": 5,
        "progress": 1,
        "latency_us": 100.0,
        "parser_outcome": "accepted",
        "heartbeat_ok": True,
        "wedge": False,
        "wedge_type": None,
    }
    base.update(overrides)
    return base


def _make_artifact(n: int = 1, **top_overrides) -> dict:
    artifact = {
        "schema_version": "m2-draft",
        "milestone": "M2",
        "artifact_type": "tcg_storage_adapter_draft",
        "target": "go-tcg-storage",
        "upstream_repository": UPSTREAM_REPOSITORY,
        "upstream_commit": UPSTREAM_COMMIT,
        "adapter": "tcg_adapter",
        "parser_under_test": "semantic_adapter",
        "trial_count": n,
        "source_evidence": "evidence/EP-20260511-m1-docker-local.json",
        "claim_scope": "Semantic outcome taxonomy only.",
        "latency_note": "latency_us is host adapter runtime.",
        "results": [_make_case(case=f"case_{i}") for i in range(n)],
    }
    artifact.update(top_overrides)
    return artifact


# ── Top-level metadata ────────────────────────────────────────────────────────

def test_valid_artifact_passes():
    assert validate(_make_artifact(n=3)).passed


def test_missing_required_field_fails():
    for field in [
        "schema_version", "milestone", "artifact_type", "target",
        "upstream_repository", "upstream_commit", "adapter", "parser_under_test",
        "trial_count", "source_evidence", "claim_scope", "latency_note", "results",
    ]:
        d = _make_artifact()
        del d[field]
        r = validate(d)
        assert not r.passed, f"expected FAIL when '{field}' is missing"
        assert any(field in e for e in r.errors)


def test_wrong_type_on_top_level_string_field_fails():
    r = validate(_make_artifact(schema_version=123))
    assert not r.passed
    assert any("schema_version" in e for e in r.errors)


def test_wrong_type_trial_count_fails():
    r = validate(_make_artifact(trial_count="39"))
    assert not r.passed


def test_bool_trial_count_fails():
    r = validate(_make_artifact(n=1, trial_count=True))
    assert not r.passed
    assert any("'trial_count'" in e and "expected int, got bool" in e for e in r.errors)


def test_bad_schema_version_fails():
    r = validate(_make_artifact(schema_version="1.0.0"))
    assert not r.passed
    assert any("schema_version" in e for e in r.errors)


def test_bad_milestone_fails():
    r = validate(_make_artifact(milestone="M1"))
    assert not r.passed


def test_bad_artifact_type_fails():
    r = validate(_make_artifact(artifact_type="m1_fuzz_run"))
    assert not r.passed


def test_bad_target_fails():
    r = validate(_make_artifact(target="not-a-target"))
    assert not r.passed


def test_missing_upstream_repository_fails():
    d = _make_artifact()
    del d["upstream_repository"]
    r = validate(d)
    assert not r.passed
    assert any("upstream_repository" in e for e in r.errors)


def test_wrong_upstream_repository_fails():
    r = validate(_make_artifact(upstream_repository="https://example.invalid/repo"))
    assert not r.passed
    assert any("upstream_repository" in e for e in r.errors)


def test_missing_upstream_commit_fails():
    d = _make_artifact()
    del d["upstream_commit"]
    r = validate(d)
    assert not r.passed
    assert any("upstream_commit" in e for e in r.errors)


def test_wrong_upstream_commit_fails():
    r = validate(_make_artifact(upstream_commit="0" * 40))
    assert not r.passed
    assert any("upstream_commit" in e for e in r.errors)


def test_bad_adapter_fails():
    r = validate(_make_artifact(adapter="wrong_adapter"))
    assert not r.passed


# ── trial_count consistency ───────────────────────────────────────────────────

def test_trial_count_mismatch_fails():
    d = _make_artifact(n=2)
    d["trial_count"] = 5
    r = validate(d)
    assert not r.passed
    assert any("trial_count" in e for e in r.errors)


def test_trial_count_zero_with_empty_results_passes():
    assert validate(_make_artifact(n=0)).passed


def test_negative_trial_count_fails():
    d = _make_artifact(n=0, trial_count=-1)
    assert not validate(d).passed


# ── Per-case fields ───────────────────────────────────────────────────────────

_REQUIRED_CASE_FIELDS = [
    "case", "ok", "error", "response_len", "frames_accepted",
    "output_bytes", "progress", "latency_us", "parser_outcome",
    "heartbeat_ok", "wedge", "wedge_type",
]


def test_missing_case_field_fails():
    for field in _REQUIRED_CASE_FIELDS:
        d = _make_artifact(n=1)
        del d["results"][0][field]
        r = validate(d)
        assert not r.passed, f"expected FAIL when case field '{field}' is missing"
        assert any(field in e for e in r.errors)


def test_case_ok_wrong_type_fails():
    d = _make_artifact(n=1)
    d["results"][0]["ok"] = "true"
    assert not validate(d).passed


def test_case_heartbeat_ok_wrong_type_fails():
    d = _make_artifact(n=1)
    d["results"][0]["heartbeat_ok"] = 1
    assert not validate(d).passed


def test_case_wedge_wrong_type_fails():
    d = _make_artifact(n=1)
    d["results"][0]["wedge"] = "false"
    assert not validate(d).passed


def test_case_error_none_passes():
    d = _make_artifact(n=1)
    d["results"][0]["error"] = None
    assert validate(d).passed


def test_case_error_string_passes():
    d = _make_artifact(n=1)
    d["results"][0]["error"] = "some error message"
    assert validate(d).passed


def test_case_error_int_fails():
    d = _make_artifact(n=1)
    d["results"][0]["error"] = 42
    assert not validate(d).passed


# ── parser_outcome values ─────────────────────────────────────────────────────

@pytest.mark.parametrize("outcome", sorted(ALLOWED_PARSER_OUTCOMES))
def test_allowed_parser_outcome_passes(outcome):
    d = _make_artifact(n=1)
    d["results"][0]["parser_outcome"] = outcome
    # accepted requires frames_accepted=1 and output_bytes>0; adjust for others
    if outcome != "accepted":
        d["results"][0]["frames_accepted"] = 0
        d["results"][0]["output_bytes"] = 0
    assert validate(d).passed


def test_bad_parser_outcome_fails():
    d = _make_artifact(n=1)
    d["results"][0]["parser_outcome"] = "unknown_outcome"
    assert not validate(d).passed


# ── Non-negative counters ─────────────────────────────────────────────────────

@pytest.mark.parametrize("field", ["response_len", "frames_accepted", "output_bytes", "progress"])
def test_negative_case_counter_fails(field):
    d = _make_artifact(n=1)
    d["results"][0][field] = -1
    assert not validate(d).passed


@pytest.mark.parametrize("field", ["response_len", "frames_accepted", "output_bytes", "progress"])
def test_bool_case_counter_fails(field):
    d = _make_artifact(n=1)
    d["results"][0][field] = True
    r = validate(d)
    assert not r.passed
    assert any(field in e and "expected int, got bool" in e for e in r.errors)


def test_negative_latency_fails():
    d = _make_artifact(n=1)
    d["results"][0]["latency_us"] = -5.0
    assert not validate(d).passed


def test_zero_latency_passes():
    d = _make_artifact(n=1)
    d["results"][0]["latency_us"] = 0.0
    assert validate(d).passed


# ── Wedge consistency ─────────────────────────────────────────────────────────

def test_wedge_true_with_wedge_type_passes():
    d = _make_artifact(n=1)
    d["results"][0]["wedge"] = True
    d["results"][0]["wedge_type"] = "wedge_timeout"
    assert validate(d).passed


def test_wedge_true_without_wedge_type_fails():
    d = _make_artifact(n=1)
    d["results"][0]["wedge"] = True
    d["results"][0]["wedge_type"] = None
    assert not validate(d).passed


def test_wedge_false_with_wedge_type_fails():
    d = _make_artifact(n=1)
    d["results"][0]["wedge"] = False
    d["results"][0]["wedge_type"] = "wedge_timeout"
    assert not validate(d).passed


def test_bad_wedge_type_string_fails():
    d = _make_artifact(n=1)
    d["results"][0]["wedge"] = True
    d["results"][0]["wedge_type"] = "not_a_wedge_type"
    assert not validate(d).passed


# ── Non-dict inputs ───────────────────────────────────────────────────────────

def test_non_dict_top_level_fails():
    assert not validate([1, 2, 3]).passed


def test_non_dict_case_fails():
    d = _make_artifact(n=1)
    d["results"][0] = "not a dict"
    assert not validate(d).passed


# ── CLI integration against real generated artifact ───────────────────────────

def test_cli_passes_on_generated_artifact():
    """Generate a fresh artifact and run the CLI validator against it."""
    subprocess.run(
        [sys.executable, "tools/run_m2_tcg.py"],
        cwd=REPO_ROOT,
        check=True,
    )
    result = subprocess.run(
        [sys.executable, "tools/validate_m2_evidence.py",
         "evidence/m2/EP-M2-go-tcg-storage-draft.json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"CLI failed:\n{result.stdout}\n{result.stderr}"
    assert "M2 evidence: PASS" in result.stdout
    assert "trial_count=39" in result.stdout
    artifact = json.loads((REPO_ROOT / "evidence/m2/EP-M2-go-tcg-storage-draft.json").read_text())
    assert artifact["upstream_repository"] == UPSTREAM_REPOSITORY
    assert artifact["upstream_commit"] == UPSTREAM_COMMIT


def test_cli_fails_on_bad_artifact(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "wrong"}))
    result = subprocess.run(
        [sys.executable, "tools/validate_m2_evidence.py", str(bad)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "M2 evidence: FAIL" in result.stdout


def test_cli_exits_2_on_missing_file():
    result = subprocess.run(
        [sys.executable, "tools/validate_m2_evidence.py", "does_not_exist.json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
