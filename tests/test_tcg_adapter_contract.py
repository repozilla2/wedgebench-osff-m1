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


def test_tcg_adapter_handles_empty_input():
    adapter = TCGAdapter()
    result = adapter.feed(b"")

    assert isinstance(result, AdapterResult)
    assert result.response_len == 0
    assert result.progress >= 0


def test_tcg_adapter_heartbeat_returns_bool():
    adapter = TCGAdapter()

    assert isinstance(adapter.inject_heartbeat(), bool)
