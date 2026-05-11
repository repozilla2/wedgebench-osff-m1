from tools.tcg_adapter import AdapterResult, TCGAdapter


def test_tcg_adapter_returns_adapter_result():
    adapter = TCGAdapter()
    result = adapter.feed(bytes.fromhex("aa010203"))

    assert isinstance(result, AdapterResult)
    assert isinstance(result.ok, bool)
    assert isinstance(result.response_len, int)
    assert isinstance(result.frames_accepted, int)
    assert isinstance(result.output_bytes, int)
    assert isinstance(result.progress, int)
    assert isinstance(result.latency_us, float)
    assert isinstance(result.parser_outcome, str)
    assert result.parser_outcome in {"accepted", "empty_parse", "rejected", "probe_error"}


def test_tcg_adapter_handles_empty_input():
    adapter = TCGAdapter()
    result = adapter.feed(b"")

    assert isinstance(result, AdapterResult)
    assert result.response_len == 0
    assert result.progress >= 0


def test_tcg_adapter_heartbeat_returns_bool():
    adapter = TCGAdapter()

    assert isinstance(adapter.inject_heartbeat(), bool)

def test_tcg_adapter_classifies_short_input_as_empty_parse():
    adapter = TCGAdapter()
    result = adapter.feed(bytes.fromhex("deadbeef"))

    assert isinstance(result, AdapterResult)
    assert result.parser_outcome == "empty_parse"
    assert result.frames_accepted == 0
    assert result.output_bytes == 0


def test_tcg_adapter_rejects_invalid_hex_probe_input():
    adapter = TCGAdapter()
    result = adapter.feed(b"not-hex-at-probe-level")

    assert isinstance(result, AdapterResult)
    assert result.parser_outcome in {"empty_parse", "rejected"}
    assert result.frames_accepted == 0



def test_m2_tcg_generated_artifact_has_reviewer_metadata(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]

    subprocess.run(
        [sys.executable, "tools/run_m2_tcg.py"],
        cwd=repo_root,
        check=True,
    )

    path = repo_root / "evidence" / "m2" / "EP-M2-go-tcg-storage-draft.json"
    data = json.loads(path.read_text())

    assert data["schema_version"] == "m2-draft"
    assert data["milestone"] == "M2"
    assert data["artifact_type"] == "tcg_storage_adapter_draft"
    assert data["target"] == "go-tcg-storage"
    assert data["adapter"] == "tcg_adapter"
    assert data["parser_under_test"] == "semantic_adapter"
    assert data["trial_count"] == 39
    assert data["source_evidence"] == "evidence/EP-20260511-m1-docker-local.json"
    assert "Semantic outcome taxonomy" in data["claim_scope"]
    assert "latency_us" in data["latency_note"]
