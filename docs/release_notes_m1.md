# OSFF Milestone 1 — Release Notes
**Tag:** `osff-m1.3`
**Date:** March 2026

---

## What This Delivers

A reproducible fuzz harness that verifies embedded serial parser recovery behavior
under malformed input, with schema-locked evidence artifacts and a strict validator.

## Deliverables

| Component | File |
|---|---|
| Fuzz harness | `tools/fuzz_runner.py` |
| Schema validator | `tools/validate_evidence.py` |
| Corpus generator | `tools/generate_corpus.py` |
| Reference parser (safe + vuln) | `tools/parser_target.c` |
| Evidence artifact | `evidence/EP-YYYYMMDD-m1.json` (generated from tagged commit `osff-m1.3`; `firmware_build_id` equals the tag name (e.g. `osff-m1.3`)) |
| Reproducible environment | `Dockerfile`, `docker-compose.yml` |

## Verification

```bash
docker compose run sentinel-m1
```

Expected output:
```
Parser 'safe': ✓ PASS
Parser 'vuln': ✓ PASS
Result: PASS
```

Fallback (no Compose): `docker build -t sentinel-m1 . && docker run --rm -v "$(pwd)/evidence:/sentinel/evidence" sentinel-m1`
Native (no Docker): `./run_m1.sh` (requires Python 3.10+, GCC)

Typical runtime: ~1 second on a laptop (39 trials).

## What the Evidence Proves

- **`wedge_count = 0` (safe parser):** The safe parser correctly returns to a functional
  IDLE state after every malformed input, verified by post-reset heartbeat acceptance.
  This is not a null result — a parser with corrupted post-fuzz state fails the heartbeat
  even after reset.

- **Defect detection demonstrated:** The vuln parser accepts a zero-length frame on
  `zero_length_valid_chk` (`frames_accepted = 1`) that the safe parser correctly rejects
  (`frames_accepted = 0`). This confirms the harness detects real semantic defects,
  not just timing anomalies.

- **Latency figures** are labeled `harness_roundtrip` and include Python/ctypes/OS
  overhead. They are provided for reproducibility and distribution analysis only,
  not as device execution timing.

## Corpus

39 deterministic seed cases, generated from `CORPUS_RANDOM_SEED = 3735928559` (`0xDEADBEEF`).
Corpus binaries committed to `corpus/`. Hash bound to evidence artifact via
`input_corpus_hash` field.

## Locked Constants

| Constant | Value |
|---|---|
| `WEDGE_TIMEOUT_MS` | 1000 |
| `PROGRESS_WINDOW_MS` | 200 |
| `MAX_PARSE_TIME_MULT` | 100 |
| `CORPUS_RANDOM_SEED` | 3735928559 |
| `SCHEMA_VERSION` | `1.0.0` |

## What This Milestone Does Not Claim

- Device-native execution timing
- Hardware or embedded platform testing
- Protocol stack coverage beyond UART framing
- Parser security certification of any kind

## M2 Preview

M2 will deliver a hardened parser module with a defined acceptance test matrix
(T01–T09), CI regression runner, and expanded corpus stress testing.
