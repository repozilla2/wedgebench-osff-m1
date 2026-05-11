# M3 Event Log Verification Guide

**Status:** Internal draft — M3 go-tcg-storage tamper-evident logging
**Scope:** Internal use only. Do not publish, submit, or tag.

---

## Purpose

M3 adds a tamper-evident event log layer around the M2 evidence workflow.
Each run of the evidence pipeline emits a JSONL hash-chain log that records
what happened, in what order, and with what artifact hashes.

The goal is not cryptographic signing or attestation. The goal is to make
post-hoc tampering with the evidence workflow detectable.

---

## What the Event Log Proves

The hash-chain log provides the following observable guarantees:

| Claim | Mechanism |
|---|---|
| **Event sequence** | `sequence` field increments by 1; any gap or reorder breaks verification |
| **Artifact hash continuity** | `artifact_sha256` in `m2_evidence_generated` and `m2_evidence_validated` payloads is a SHA-256 of the artifact at the time of emission; recomputable |
| **Hash-chain integrity** | Each event's `event_hash` covers all fields including `previous_event_hash`; editing any event breaks all subsequent hashes |
| **Evidence steps occurred in order** | Required event types appear in a fixed sequence: `run_started` → `m2_evidence_generated` → `m2_evidence_validated` → `tests_skipped` → `run_completed` |
| **Single run_id per log** | All events in a log share one `run_id`; cross-run splicing is detectable |

A log that passes `verify_event_log.py` means: at the time the log was
written, these steps ran in this order and produced an artifact with this
hash. Any subsequent modification of the log or artifact is detectable by
re-running verification.

---

## What the Event Log Does Not Prove

M3 is a hash-chain tamper-evidence layer, not a signature or attestation
system. The following claims are explicitly out of scope:

- **Tamper-proof storage.** The log file itself is not encrypted or write-protected. An adversary with filesystem access can delete and replace it. The chain detects tampering only if the original log is available for comparison.
- **Cryptographic signing.** Events are not signed by a key. There is no key management, certificate infrastructure, or public-key verification.
- **External timestamping.** `timestamp_utc` is the local system clock at time of emission. It is not anchored to a trusted time authority and may not be accurate.
- **Physical-device timing.** `latency_us` fields in M2 artifact events are host adapter wall-clock time, not hardware timing. No firmware timing claims are made.
- **Exploit discovery.** The log records whether the M2 adapter accepted, rejected, or wedged on corpus inputs. It does not identify or demonstrate security vulnerabilities.
- **Formal safety proof.** Log verification is not a formal proof of correctness, soundness, or completeness for any parser or firmware target.
- **Production firmware validation.** The pipeline runs against a fake hardware stub. No physical device is involved.

---

## Event Schema

Each line of the JSONL log is a JSON object with these fields:

```json
{
    "schema_version":      "m3-draft",
    "run_id":              "<uuid>",
    "sequence":            0,
    "timestamp_utc":       "2026-05-11T00:00:00.000000Z",
    "event_type":          "run_started",
    "payload":             {},
    "previous_event_hash": null,
    "event_hash":          "<sha256-hex>"
}
```

`event_hash` is `sha256(canonical_json(event_without_event_hash))` where
canonical JSON uses sorted keys and no extra whitespace.

---

## Required Event Sequence

Every demo log must contain these five event types in this order:

```
run_started
m2_evidence_generated    ← payload includes artifact_path, artifact_sha256
m2_evidence_validated    ← payload includes artifact_path, artifact_sha256
tests_skipped            ← payload includes reason, acceptance_command
run_completed            ← payload includes success, events_emitted
```

---

## How to Generate a Demo Log

```bash
python3 tools/run_m3_demo.py
```

This will:
1. Regenerate the M2 evidence artifact via `tools/run_m2_tcg.py`
2. Validate the artifact via `tools/validate_m2_evidence.py`
3. Emit five hash-chained events to `evidence/m3/WBLOG-M3-demo.jsonl`
4. Self-verify the log before exiting

Expected output:
```
M3 demo log: PASS
log_path=evidence/m3/WBLOG-M3-demo.jsonl
events_emitted=5
```

To write the log to a custom path:
```bash
python3 tools/run_m3_demo.py --log-path /path/to/custom.jsonl
```

---

## How to Verify a Log

```bash
python3 tools/verify_event_log.py evidence/m3/WBLOG-M3-demo.jsonl
```

The verifier checks:

- All required fields present on every event
- `schema_version` is an accepted value (`m3-draft` or `m3-log-v1`)
- `event_hash` recomputes correctly for every event
- Hash chain is intact across all events
- First event has `previous_event_hash = null`
- `sequence` starts at 0 or 1 and increments by 1 with no gaps
- `run_id` is consistent across all events
- If a payload contains `artifact_path` + `artifact_sha256` and the file
  exists, the SHA-256 is recomputed and compared (missing files produce a
  warning, not an error)

Expected output on a clean log:
```
M3 event log: PASS
events_verified=5
```

Exit codes: `0` = PASS, `1` = FAIL, `2` = usage/file error.

---

## Internal Verification Command

```bash
make m3-verify
```

This runs all three steps in sequence:

```
== M3 demo event log generation ==
== M3 event log verification ==
== M3 test suite ==
== M3 verification complete ==
```

The test suite (`pytest -q tests/test_event_log.py tests/test_verify_event_log.py tests/test_run_m3_demo.py`) covers hash determinism, chain integrity, all tamper scenarios, artifact hash checks, and CLI exit codes.

---

## Claim Boundary

M3 is a hash-chain tamper-evidence layer, not a signature or attestation system.

It answers: *"Was this log modified after it was written?"*

It does not answer: *"Was this log written by a trusted party?"* or *"Was this log written at the claimed time?"*

Those claims require cryptographic signing and external timestamping, which are out of scope for the current M3 draft.

---

## File Locations

| File | Role |
|---|---|
| `tools/event_log.py` | Hash-chain primitives: `create_event`, `append_event`, `load_events` |
| `tools/verify_event_log.py` | Log verifier CLI and `verify()` function |
| `tools/run_m3_demo.py` | Demo runner: wraps M2 workflow in a tamper-evident log |
| `evidence/m3/WBLOG-M3-demo.jsonl` | Generated log (gitignored; not committed) |
| `tests/test_event_log.py` | Unit tests for hash-chain primitives |
| `tests/test_verify_event_log.py` | Unit tests for the verifier |
| `tests/test_run_m3_demo.py` | Integration tests for the demo runner |
