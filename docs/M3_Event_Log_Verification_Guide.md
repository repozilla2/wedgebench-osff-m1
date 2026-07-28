# M3 Event Log Verification Guide

## Purpose

M3 adds a tamper-evident JSONL event log around the M2 evidence workflow. This
guide is for reviewers who want to generate a log, inspect its claim boundary,
and run the public verifier.

The canonical public event schema is `m3-log-v1`.

## What M3 Proves

A log that passes `tools/verify_event_log.py` is internally consistent at the
time it is checked:

- every event has the required fields and uses `m3-log-v1`;
- each `event_hash` matches the canonical JSON content of that event;
- each `previous_event_hash` links to the preceding event;
- sequence numbers are contiguous and the `run_id` is consistent; and
- when a referenced artifact is present, its current SHA-256 matches the
  `artifact_sha256` recorded in the event.

For logs produced by `tools/run_m3_demo.py`, the recorded workflow also shows
whether the current M2 generation and validation steps succeeded. The runner
removes the expected M2 output before generation, requires the M2 generator to
return zero, and requires that invocation to produce the expected artifact
before it emits a successful generation event.

These are bounded integrity checks. A passing log is not proof that an
unobserved real-world action occurred or that the event producer is trusted.

## What M3 Does Not Prove

M3 does not provide:

- cryptographic signing or signer identity;
- source, operator, machine, or artifact provenance attestation;
- a trusted timestamp or external time authority;
- tamper-proof or write-protected storage;
- certification or a formal proof of correctness;
- exploit discovery, production firmware validation, or physical-device
  validation; or
- device-native timing. M2 `latency_us` values remain host adapter timing.

No event is signed, and no key, certificate, identity, or provenance chain is
associated with a log.

## Hash Behavior

Each event contains an `event_hash` computed as:

```text
sha256(canonical_json(event_without_event_hash))
```

Canonical JSON sorts object keys, uses compact separators, and encodes as
UTF-8. The hash therefore covers the schema, run ID, sequence, timestamp,
event type, payload, and `previous_event_hash`.

The first event has `previous_event_hash: null`. Every later event records the
preceding event's `event_hash`. Editing an event without recomputing its hash is
detected. Reordering, deleting, or inserting events without rebuilding the
affected chain is also detected.

This design is tamper-evident, not tamper-proof. A party able to replace the
whole log can recompute an unsigned chain, and a log can be deleted. M3 has no
external signed anchor against which to distinguish such a replacement. Keep
independent copies or digests when stronger change detection is needed.

## Artifact Hash Checking

The `m2_evidence_generated` and `m2_evidence_validated` payloads include an
`artifact_path` and `artifact_sha256`. When the referenced artifact is present,
the verifier recomputes its SHA-256 and fails on a mismatch. If the artifact is
absent, the verifier reports a warning and skips that artifact comparison.

Accordingly, artifact modification is checked only when the referenced
artifact is present at verification time. The event chain still verifies the
recorded digest as event content, but it cannot compare that digest with a
missing file.

## Time Behavior

`timestamp_utc` is read from the machine's local system clock and formatted as
UTC. It is not synchronized or anchored by M3 to a trusted timestamp service.
Hashing protects the timestamp text from unrecomputed edits inside the chain;
it does not establish that the clock was accurate or that the event occurred
at the stated time.

## Event Schema

Each JSONL line is one event:

```json
{
  "schema_version": "m3-log-v1",
  "run_id": "<run-identifier>",
  "sequence": 0,
  "timestamp_utc": "2026-05-11T00:00:00.000000Z",
  "event_type": "run_started",
  "payload": {},
  "previous_event_hash": null,
  "event_hash": "<sha256-hex>"
}
```

The public verifier accepts `m3-log-v1`. Unknown schema versions, including
the former generator label, fail verification.

## Demo Event Sequence

`tools/run_m3_demo.py` emits exactly five events in this order:

```text
run_started
m2_evidence_generated
m2_evidence_validated
tests_skipped
run_completed
```

`tests_skipped` is explicit because the demo runner covers M2 artifact
generation, M2 artifact validation, and event-log plumbing; it does not run the
Python test suite inside the event chain. This keeps test execution from being
misrepresented as a chained workflow event.

`make m3-verify` runs tests separately, after demo generation and standalone
log verification. Those tests are acceptance checks outside the five-event
chain.

## Generate and Verify

From the repository root:

```bash
python3 tools/run_m3_demo.py
python3 tools/verify_event_log.py evidence/m3/WBLOG-M3-demo.jsonl
```

The default output is `evidence/m3/WBLOG-M3-demo.jsonl`. To choose another
repository-relative output path:

```bash
python3 tools/run_m3_demo.py --log-path evidence/m3/reviewer-run.jsonl
```

The runner exits `0` only when current-run M2 generation succeeds, the expected
artifact is produced and validates, and the resulting log self-verifies. It
exits `1` for workflow or integrity failure.

The standalone verifier exits `0` for PASS, `1` for integrity errors, and `2`
for usage or file errors.

“M3 event log: PASS” means log integrity passed, not necessarily that the
recorded workflow succeeded. Review `run_completed.payload.success` and the
runner exit code to determine the workflow outcome.

## Reviewer Verification

Run the complete M3 acceptance path with:

```bash
make m3-verify
```

The target performs:

1. M3 demo generation, including current-run M2 generation and validation.
2. Standalone verification of the generated event log.
3. The M3-focused Python tests, separately from the generated event chain.

M3 remains a separate target. `make osff-verify` retains its M1/M2 scope and
continues to invoke `make m2-verify`.

## Committed Example

The repository includes a small fixed example pair:

- `examples/m3/EP-M2-example.json`
- `examples/m3/WBLOG-M3-example.jsonl`

Both files are illustrative reviewer fixtures, not canonical execution
evidence. They use a fixed `run_id`, fixed timestamps, and repository-relative
paths so their hashes are stable and portable.

Verify the committed example from the repository root:

```bash
python3 tools/verify_event_log.py examples/m3/WBLOG-M3-example.jsonl
```

Expected output:

```text
M3 event log: PASS
events_verified=5
```

The verifier also recomputes the SHA-256 of
`examples/m3/EP-M2-example.json` because that referenced artifact is present.

## Implementation Map

| Path | Role |
|---|---|
| `tools/event_log.py` | Canonical serialization, event hashing, and JSONL I/O |
| `tools/verify_event_log.py` | Public event-log verifier |
| `tools/run_m3_demo.py` | Five-event M2 workflow runner |
| `tests/test_event_log.py` | Event construction and hash-chain tests |
| `tests/test_verify_event_log.py` | Verifier and tamper-detection tests |
| `tests/test_run_m3_demo.py` | Runner and stale-artifact regression tests |
| `tests/test_m3_examples.py` | Committed example and path-hygiene tests |
