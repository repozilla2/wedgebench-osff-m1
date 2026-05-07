# Zero-Length Parse Behavior

## Context

During M2 baseline replay, short or malformed corpus inputs can return `ok=true` with `output_bytes=0`.

This occurs because the fake drive copies corpus bytes into the receive buffer and zero-fills the remainder. For very short inputs, `plainCom.Receive(ses *Session)` may read zero-filled packet headers as structurally valid with zero-length payload.

## Current Classification

Current adapter behavior maps this case to:

- `ok=true`
- `output_bytes=0`
- `frames_accepted=0`
- `heartbeat_ok=true`

This avoids counting the case as accepted, but the semantic meaning is still under-specified.

## Interpretation

This should not be treated as a successful frame acceptance.

It is better classified as:

`empty_parse`

or:

`structural_empty`

depending on final M2 taxonomy.

## Risk

If left undocumented, reviewers may interpret `ok=true` as parser acceptance even when the adapter correctly reports `frames_accepted=0`.

## Next Refinement

Add explicit parser outcome classification:

- `accepted`
- `rejected`
- `structural_error`
- `empty_parse`

The M2 artifact should distinguish library-level parse success from WedgeBench-level frame acceptance.
