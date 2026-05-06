# go-tcg-storage Boundary Notes

## Purpose

Document the parser boundary selected for the M2 reference integration.

## Target

`go-tcg-storage`

## Candidate Boundary

`plainCom.Receive(ses *Session)`

## Selection Rationale

This boundary is selected because it is:

- bounded
- parser-adjacent
- below workflow/session logic
- above raw hardware transport
- callable through a fake/stubbed device interface
- suitable for deterministic malformed-input replay

## Rejected Alternatives

### `Discovery0(...)`

Rejected because it is too high-level and mixes parser behavior with workflow semantics.

### `MethodCall.Execute(...)`

Rejected because it introduces session and token semantics beyond the parser boundary.

### `HandleComIDRequest(...)`

Rejected as narrower and less representative of the receive/decode path.

## Integration Assumption

The M2 integration should prove that WedgeBench can connect to a real firmware-adjacent parser target through a thin adapter while preserving:

- deterministic execution
- machine-checkable evidence artifacts
- validator compatibility
- independent rerun capability

## Open Questions

- Confirm exact package import path for `plainCom.Receive(ses *Session)`
- Confirm minimal fake `DriveIntf` implementation
- Confirm Go version required for reproducible Docker build
- Confirm whether the first probe should use `go run` or compiled binary
