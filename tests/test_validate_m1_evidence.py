from __future__ import annotations

from tools.validate_evidence import validate_single


def _valid_m1_artifact() -> dict:
    return {
        "schema_version": "1.0.0",
        "firmware_build_id": "sentinel-osff-m1",
        "config_hash": "abc123",
        "input_corpus_hash": "def456",
        "corpus_random_seed": 3735928559,
        "cases_count": 1,
        "trial_count": 1,
        "wedge_count": 0,
        "latency_scope": "harness_roundtrip",
        "latency_unit": "us",
        "latency_distribution": {
            "p50": 1.0,
            "p95": 1.0,
            "p99": 1.0,
            "n": 1,
            "min": 1,
            "max": 1,
        },
        "wedge_timeout_ms": 1000,
        "progress_window_ms": 200,
        "harness_version": "test",
        "parser_under_test": "safe",
        "enforcement_count": 0,
        "crash_count": 0,
        "wedge_categories": {
            "wedge_timeout": 0,
            "wedge_no_progress": 0,
            "wedge_no_heartbeat": 0,
            "wedge_spin": 0,
        },
        "max_parse_time_mult": 100,
    }


def test_valid_m1_artifact_still_passes():
    assert validate_single(_valid_m1_artifact()).passed


def test_m1_required_integer_rejects_bool():
    artifact = _valid_m1_artifact()
    artifact["trial_count"] = True
    result = validate_single(artifact)
    assert not result.passed
    assert "Field 'trial_count': expected int, got bool (True)" in result.report()


def test_m1_optional_integer_rejects_bool():
    artifact = _valid_m1_artifact()
    artifact["enforcement_count"] = False
    result = validate_single(artifact)
    assert not result.passed
    assert "Optional field 'enforcement_count': expected int, got bool" in result.report()


def test_m1_latency_distribution_integer_rejects_bool():
    artifact = _valid_m1_artifact()
    artifact["latency_distribution"]["n"] = True
    result = validate_single(artifact)
    assert not result.passed
    assert "latency_distribution.n: expected int, got bool" in result.report()


def test_m1_wedge_category_integer_rejects_bool():
    artifact = _valid_m1_artifact()
    artifact["wedge_categories"]["wedge_timeout"] = True
    result = validate_single(artifact)
    assert not result.passed
    assert "wedge_categories.wedge_timeout must be int >= 0" in result.report()
