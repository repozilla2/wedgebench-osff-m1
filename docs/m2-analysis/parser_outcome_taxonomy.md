# Parser Outcome Taxonomy

## Purpose

Define the initial semantic outcome categories used by WedgeBench M2 to classify parser behavior under deterministic malformed-input replay.

This taxonomy is intentionally bounded. It does not claim full correctness, certification, or exhaustive safety analysis.

## Current Implemented Outcomes

### accepted

The parser returned a meaningful non-empty payload.

Criteria:
- `ok=true`
- `output_bytes > 0`
- `frames_accepted=1`

### empty_parse

The parser returned successfully but produced no meaningful payload.

Criteria:
- `ok=true`
- `output_bytes=0`
- `frames_accepted=0`

Interpretation:
- not a frame acceptance
- may indicate structurally empty input, zero-filled header interpretation, or benign empty parser result
- requires context-specific analysis

### rejected

The parser returned an error for the supplied input.

Criteria:
- `ok=false`
- parser/probe returned a target error
- `frames_accepted=0`

Interpretation:
- malformed input was rejected or failed structural parsing

### probe_error

The integration probe failed before a meaningful parser result could be produced.

Criteria:
- no valid probe stdout
- invalid JSON
- toolchain/module failure
- subprocess execution failure

Interpretation:
- integration-layer failure, not parser behavior

## Future Candidate Outcomes

### structural_error

Malformed framing or packet structure detected by target parser.

### transport_error

Mock transport or hardware abstraction failure.

### timeout

Parser execution exceeded bounded execution threshold.

### no_progress

Parser returned or continued without observable progress signal.

### heartbeat_failure

Parser cannot recover to a functional post-input state.

### spin

Explicit spin/livelock detection, reserved for future use.

## Design Principle

Outcomes should separate:

1. parser behavior
2. adapter behavior
3. probe/toolchain failures
4. WedgeBench-level acceptance semantics

This prevents `ok=true` from being incorrectly interpreted as `accepted`.

## M2 Rule

A parser outcome is not equivalent to a verification claim.

Verification claims are produced only after:
- deterministic replay
- artifact generation
- validation
- consistency checks
