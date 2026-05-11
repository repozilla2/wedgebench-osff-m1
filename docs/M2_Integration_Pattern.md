# WedgeBench M2 Integration Pattern

**Status:** Reference document — applies to all M2+ integrations  
**Version:** 1.0 (established during go-tcg-storage reference integration)

---

This document defines the portable integration pattern established during the M2 reference integration effort.

## Purpose

The objective is portability of verification methodology, not project-specific instrumentation.

Define the repeatable pattern used to connect WedgeBench to a real
firmware-adjacent parser target. The `go-tcg-storage` integration is the
reference implementation of this pattern — not a one-off. Every design
decision made during that integration is documented here so the pattern
can transfer to future targets without redesign.

---

## Target Selection Criteria

A viable integration target must satisfy all critical criteria:

| Criterion | Requirement | go-tcg-storage |
|---|---|---|
| Bounded parser surface | Single receive/decode function, not a full workflow | ✅ `plainCom.Receive()` |
| Deterministic execution | Same input → same output, no hidden state | ✅ stateless per call |
| Hardware independence | Exercisable with a stub/fake device interface | ✅ `DriveIntf` is stubbable |
| Observable behavior | Accept/reject/error surfaced as return values | ✅ structured error returns |
| Clean build environment | Builds in Docker without hardware or kernel deps | ✅ external dep isolated in `nvme_nix.go` |
| Language bridge feasibility | Callable from Python without cgo | ✅ subprocess adapter viable |

**Reject a target immediately if any critical criterion fails.** Do not
attempt to work around hardware dependencies or non-deterministic
execution — those indicate the wrong boundary, not an engineering problem.

---

## Parser Boundary Selection

The correct boundary is the **lowest-level receive/decode function** that:

1. Takes a raw byte buffer as input
2. Returns a structured result or error
3. Is below workflow/session logic
4. Is above raw transport (hardware I/O)

### go-tcg-storage boundary

```
core.NewPlainCommunication(fakeDevice, hostProps, tperProps).Receive(ses)
```

**Why this boundary and not higher-level helpers:**

- `Discovery0(d)` — too high; mixes parsing with workflow semantics
- `MethodCall.Execute(...)` — too high; adds session/token semantics
- `HandleComIDRequest(...)` — narrower; less representative of the full receive path
- `plainCom.Receive(...)` — correct; pure packet framing parser, hardware-decoupled

**How to find the equivalent boundary in a new target:**

```bash
grep -rn "Receive\|Decode\|Unmarshal\|ParsePacket" <target>/
```

Look for: `func([]byte) -> (result, error)` or equivalent. If the function
signature requires a live connection, session, or device handle that cannot
be stubbed, the boundary is too high.

---

## Adapter Architecture

**Decision: subprocess adapter, not cgo.**

This decision was made once and applies to all Go targets. Rationale:

| Approach | Complexity | Docker | Reset isolation | Decision |
|---|---|---|---|---|
| cgo shared library | High | Fragile | Poor | ❌ Rejected |
| Subprocess stdin/stdout | Low | Clean | Perfect | ✅ Selected |

The subprocess model means:
- WedgeBench Python harness remains unchanged
- Each trial is a fresh process invocation
- No parser state leaks between trials
- Docker image builds simply (just needs Go runtime)

For non-Go targets: the same subprocess pattern applies. The Go probe
is replaced by a language-appropriate probe binary. The Python adapter
contract (`AdapterResult`) does not change.

---

## Adapter Responsibilities

The adapter must and must not do the following:

**Must:**
- Translate corpus input bytes into target parser input format
- Invoke the parser boundary deterministically
- Capture: accept/reject outcome, output bytes, progress signals
- Normalize results into `AdapterResult` (language-neutral dataclass)
- Support clean per-trial reset (subprocess model: free)
- Support heartbeat injection (separate call after reset)

**Must not:**
- Modify the target parser code
- Add retry or recovery logic
- Mask parser errors or failures
- Depend on external services or hardware
- Grow complex enough to require its own tests

> Rule: if the adapter requires target-specific heuristics to produce
> basic fields, the parser boundary is wrong.

---

## Adapter Interface Contract

```python
class ParserAdapter:
    def reset(self) -> None: ...
    def feed(self, data: bytes) -> AdapterResult: ...
    def inject_heartbeat(self) -> bool: ...
    def teardown(self) -> None: ...

@dataclass
class AdapterResult:
    ok: bool
    error: str | None
    response_len: int
    frames_accepted: int   # 1 = successful parse, 0 = rejected/failed
    output_bytes: int      # length of parsed output payload
    progress: int          # observable progress signal (recv calls, etc.)
    latency_us: float
```

This interface is frozen. New targets implement this interface. The
harness and validator do not change.

---

## Evidence Schema Mapping

| WedgeBench field | Source |
|---|---|
| `case` | Corpus filename stem (harness-provided) |
| `latency_us` | `AdapterResult.latency_us` (wall clock, harness roundtrip) |
| `frames_accepted` | `1` if `result.ok and result.output_bytes > 0`, else `0` |
| `output_bytes` | `AdapterResult.output_bytes` |
| `heartbeat_ok` | Separate `inject_heartbeat()` call after reset |
| `wedge` | Derived: `wedge_type is not None` |
| `wedge_type` | See wedge classification rules below |
| `crash` | Subprocess exit abnormally or unhandled panic |

**Wedge classification rules:**

```
timeout              → wedge_timeout
no heartbeat         → wedge_no_heartbeat
no progress (stall)  → wedge_no_progress
spin (explicit only) → wedge_spin (reserved, M2 unused)
```

A parser that quickly and cleanly rejects malformed input is **not**
wedged. Only classify `wedge_no_progress` when the subprocess returns
but produced no observable progress signals.

---

## go-tcg-storage Reference Integration

### Boundary

`pkg/core/communication.go` → `plainCom.Receive(ses)`  
Called via `core.NewPlainCommunication(fakeDevice, hostProps, tperProps)`

### Fake device

`DriveIntf` in `pkg/drive/drive.go` defines a two-method interface:

```go
type DriveIntf interface {
    IFSend(proto SecurityProtocol, sps uint16, data []byte) error
    IFRecv(proto SecurityProtocol, sps uint16, data *[]byte) error
    // + Close()
}
```

`IFRecv` is implemented to return deterministic test bytes. No hardware
required. The NVMe hardware driver (`nvme_nix.go`) imports the only
external dependency (`dswarbrick/smart`) and is not needed for the probe.

### Probe architecture

```
Python harness
  → subprocess: go run ./cmd/wb_tcg_probe
  → stdin: JSON {response_hex, proto, sps, com_id}
  → stdout: JSON {ok, error, response_len, parsed_hex, if_recv_calls, ...}
```

### Build requirements

- Go 1.24+
- No hardware
- No kernel modules
- Docker: Ubuntu 24.04 + golang package

---

## Portability Notes

To apply this pattern to a new target, change only:

1. **The Go probe** (`cmd/wb_<target>_probe/main.go`) — new fake device, new boundary call
2. **The Python adapter** (`tools/<target>_adapter.py`) — maps target-specific output to `AdapterResult`
3. **The Docker target** (`docker-compose.yml`) — new service or new image

Do not change:
- Corpus generator
- Wedge definition
- Evidence schema
- Validator
- Harness core loop

**Time estimate for a new target:** 1–3 days to boundary identification
and probe compile; 1 week to full adapter and evidence generation.

---

## Transfer Candidates (Post-M2)

Targets that would apply this pattern cleanly:

| Target | Boundary candidate | Language bridge |
|---|---|---|
| Dynamixel SDK | `rxPacket2()` in `protocol2_packet_handler.cpp` | C shared lib via ctypes (no subprocess needed) |
| barebox | Serial console parser, pre-specified function | C shared lib via ctypes |
| Feetech STS Arduino | Packet receive in STS servo driver | C shared lib via ctypes |

For C targets, the subprocess adapter is not required — ctypes works
directly (as in M1). The `AdapterResult` contract and evidence mapping
remain identical.

---

## Non-Goals

This integration pattern is not intended to:
- standardize firmware interfaces
- replace existing validation frameworks
- provide certification
- eliminate target-specific parser logic

The goal is bounded, reproducible behavioral verification across heterogeneous targets.

---

## Bottom Line

The integration pattern has three fixed layers:

```
Corpus bytes
    ↓
Adapter (target-specific, thin)
    ↓
AdapterResult (language-neutral, frozen)
    ↓
Evidence artifact (schema-stable, validator-checked)
```

Only the adapter layer is target-specific. The verification workflow, artifact schema, and validator remain unchanged.
