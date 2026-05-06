cat > docs/m2-notes/m2_status_checkpoint.md <<'EOF'
# M2 Status Checkpoint

## Status

M2 reference integration skeleton established against:

`open-source-firmware/go-tcg-storage`

Branch merged:
`m2/go-tcg-storage-reference-integration`

---

## Working Components

### Deterministic replay chain

Working end-to-end:

Corpus
→ Adapter
→ Probe
→ `plainCom.Receive(ses *Session)`
→ AdapterResult
→ Draft artifact

---

### Real boundary invocation

Confirmed:
- real invocation of `plainCom.Receive`
- fake `DriveIntf` substitutes hardware layer
- parser executes against corpus-derived bytes

---

### Adapter model

Established:
- subprocess adapter architecture
- frozen `AdapterResult` contract
- isolated integration module
- reusable integration pattern

---

## Current Constraints

Current implementation remains intentionally bounded.

Not yet implemented:
- final M2 validator-compatible schema
- refined wedge classification semantics
- Dockerized reproducible M2 execution
- full malformed-input semantic analysis
- additional firmware targets

---

## Known Limitations

### Zero-length parse edge case

Short or malformed buffers may parse as valid zero-length packets because:
- receive buffer is zero-filled
- parser interprets zeroed headers as structurally valid

Current behavior:
- `frames_accepted=0`
- no false positive acceptance currently emitted

Further refinement required before final M2 artifact generation.

---

## Current Architecture

```text
Corpus bytes
    ↓
Adapter
    ↓
Probe
    ↓
go-tcg-storage parser boundary
    ↓
AdapterResult
    ↓
Draft evidence artifact
