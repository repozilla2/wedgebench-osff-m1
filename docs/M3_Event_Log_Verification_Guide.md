# M3 Event Log Verification Guide

## Purpose

M3 adds a tamper-evident JSONL event log around the M2 evidence workflow. This
guide is for reviewers who want to generate a log, inspect its claim boundary,
and run the public verifier.

The canonical public event schema is `m3-log-v1`.

M3 is complete and publicly released for its bounded event-log scope. Its
release lineage is:

- `osff-m3-event-log-v1` — existing initial M3 implementation release
- `osff-m3-event-log-v1.1` — designated reviewer-clarification release

The `osff-m3-event-log-v1.1` tag is created only after this documentation
change is merged and validated. This documentation change itself does not
create or move tags.

## What M3 Proves

A log that passes `tools/verify_event_log.py` is internally consistent at the
time it is checked:

- every event is an object with the required fields and required field types;
- every event uses the accepted schema version, `m3-log-v1`;
- `event_hash` and supplied `artifact_sha256` values use the required SHA-256
  hexadecimal format;
- each `event_hash` matches the canonical JSON content of that event;
- each `previous_event_hash` links to the preceding event;
- sequence values are contiguous and the `run_id` is consistent; and
- when `artifact_path` and `artifact_sha256` are both supplied and the
  referenced artifact is present, its current SHA-256 matches the recorded
  `artifact_sha256`.

For logs produced by `tools/run_m3_demo.py`, the recorded workflow also shows
whether the current M2 generation and validation steps succeeded. The runner
removes the expected M2 output before generation, requires the M2 generator to
return zero, and requires that invocation to produce the expected artifact
before it emits a successful generation event.

These are bounded integrity checks. A passing log is not proof that an
unobserved real-world action occurred or that the event producer is trusted.

## What the Generic Verifier Does Not Enforce

The current generic verifier does not fully enforce:

- timestamp syntax or trusted time;
- an event-type vocabulary;
- the exact five-event semantic profile produced by the demo runner;
- payload-specific schemas;
- mandatory `run_completed` termination;
- `artifact_path` and `artifact_sha256` pairing; or
- workflow success.

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
detected. Inserting, reordering, or deleting an interior event without
recomputing the affected downstream hashes and sequence values is also
detected. A party able to rewrite and recompute the chain can produce a new
internally consistent log. Suffix truncation can leave a valid prefix that
passes generic integrity verification. Detecting wholesale replacement or
valid-prefix truncation requires an external retained digest, signed anchor,
expected terminal profile, or equivalent independent expectation. The current
verifier does not enforce a terminal anchor.

## Artifact Hash Checking

The `m2_evidence_generated` and `m2_evidence_validated` payloads include an
`artifact_path` and `artifact_sha256`. When the referenced artifact is present,
the verifier recomputes its SHA-256 and fails on a mismatch. If the artifact is
absent, the verifier reports a warning and skips that artifact comparison.

The generic verifier performs this artifact comparison only when both
`artifact_path` and `artifact_sha256` are supplied. It does not require the two
fields to be paired.

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

This exact five-event order is the demo runner's profile. It is not a semantic
profile enforced by the generic verifier.

`make m3-verify` runs tests separately, after demo generation and standalone
log verification. Those tests are acceptance checks outside the five-event
chain.

## Reviewer Prerequisites

Use this exact sibling-checkout layout:

```text
workspace/
├── go-tcg-storage/
└── wedgebench-osff-m1/
```

The reviewer environment requires:

- Git;
- Python 3.10 or later;
- `pytest`;
- Go 1.24 or later;
- Docker with Compose support for `make osff-verify`;
- network access on the first required Go module or toolchain dependency run;
  and
- a clean sibling `go-tcg-storage` Git checkout whose origin is
  `https://github.com/open-source-firmware/go-tcg-storage` and whose HEAD is
  `f99905c99780c82856226b20b59fb4863d83ae0d`.

After the required Go modules and toolchain have been cached, the M3 workflow
can be rerun with Go proxy and checksum-database access disabled:

```bash
GOPROXY=off GOSUMDB=off make m3-verify
```

This cached rerun is not a claim of hermetic or fully air-gapped execution.

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

“M3 event log: PASS” means integrity checks passed. Workflow outcome is
determined by `run_completed.payload.success` and the runner exit code.

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
