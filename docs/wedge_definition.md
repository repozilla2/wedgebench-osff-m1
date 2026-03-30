# Wedge Definition — Sentinel OSFF Firmware Slice

## Overview

A **wedge** is a failure mode in which an embedded serial parser enters a state from which it
cannot recover without external intervention (reset/restart), or in which it consumes
computational resources without making measurable progress toward frame resolution.

Parser wedge under malformed traffic is itself a safety failure in safety-adjacent embedded
systems: a wedged parser cannot process legitimate control traffic, degrading or halting
system function.

---

## Formal Wedge Definition

A **wedge event** is declared by the harness when **either** of the following conditions is met:

### Condition 1 — Timeout Wedge

```
elapsed_ms(trial) > WEDGE_TIMEOUT_MS
```

The trial did not complete (return from parse call or reach idle state) within the
wall-clock timeout window.

### Condition 2 — No-Progress Wedge

```
bytes_consumed_delta == 0
  over any window of length PROGRESS_WINDOW_MS
  while elapsed_ms(trial) < WEDGE_TIMEOUT_MS
```

The parser is running but has not advanced its consumed-byte counter within the progress
sampling window. This catches tight busy-loops that do not trip the wall-clock timeout.

---

## Wedge Categories

The harness distinguishes and reports four wedge subtypes:

| Category | Code | Description |
|---|---|---|
| Timeout | `wedge_timeout` | Wall-clock timeout exceeded, progress state unknown |
| No-progress | `wedge_no_progress` | Progress counter stalled within timeout window |
| No-heartbeat | `wedge_no_heartbeat` | Heartbeat frame not accepted after parser reset |
| Spin | `wedge_spin` | Reserved — not implemented in M1; always 0 |

All four are summed into `wedge_count` in the evidence artifact. Category breakdown is
recorded in `wedge_categories`.

---

## Constants

All wedge detection constants are declared here and used verbatim in harness code.
Changing these constants changes the wedge definition; do so only with documentation update.

| Constant | Value | Meaning |
|---|---|---|
| `WEDGE_TIMEOUT_MS` | 1000 | Max wall-clock time per trial before timeout wedge |
| `PROGRESS_WINDOW_MS` | 200 | Sampling window for no-progress detection |
| `MAX_PARSE_TIME_MULT` | 100 | Max allowed ms per input byte (anti-slow-drain) |
| `PROGRESS_POLL_INTERVAL_MS` | 10 | How often harness polls bytes-consumed counter |

### Anti-Slow-Drain Rule

A trial that technically makes byte-level progress but at a rate slower than:

```
MAX_PARSE_TIME_MULT × input_length_bytes ms
```

is flagged as a `wedge_timeout` regardless of bytes-consumed counter. This prevents a parser
from gaming the no-progress check by advancing one byte per (PROGRESS_WINDOW_MS − 1) ms.

---

## What Is NOT a Wedge

- A parser that **rejects** malformed input cleanly and returns to IDLE state: **not a wedge**
- A parser that **crashes** (segfault, assertion): **not a wedge** — recorded separately as `crash_count`
- A parser that **returns an error code** within the timeout: **not a wedge**

Rejection and error returns are correct behavior. Only hang/lock-up/no-progress qualifies.

---

## Heartbeat Verification Policy (M1)

For M1, heartbeat verification is performed **after a parser reset** to test
recovery-to-IDLE rather than mid-frame resynchronization.

Harness sequence per trial:
1. `init/reset` parser
2. Feed fuzz input bytes
3. `init/reset` parser (explicit reset before heartbeat)
4. Feed heartbeat frame (`0xAA 0x04 P I N G <xor_checksum>`)
5. Heartbeat must be accepted (frames_accepted > 0) → **pass**; otherwise → `wedge_no_heartbeat`

This means partial frames that leave the parser mid-stream are **not** declared wedges
from the fuzz phase itself — only the post-reset heartbeat acceptance test gates pass/fail.
"Stream resync without reset" is explicitly deferred to a post-M1 enhancement.


## Progress Instrumentation

Progress is measured as **bytes consumed** by the parser (`g_parser_bytes_consumed`), not
output bytes. The reference parser (`tools/parser_target.c`) exposes:

```c
extern volatile size_t g_parser_bytes_consumed;
```

The harness monitor thread reads this counter every `PROGRESS_POLL_INTERVAL_MS` (10ms).
If the counter does not advance within `PROGRESS_WINDOW_MS` (200ms), a `wedge_no_progress`
is declared. Heartbeat acceptance is a separate post-reset gate — see Heartbeat Verification
Policy above.

Third-party parsers under test must expose an equivalent counter, or the harness falls back
to timeout-only wedge detection (logged in run output).

---

## Reproducibility Note

Wedge detection is deterministic for a given input corpus and constant set. Two runs against
the same tagged release with the same corpus hash must produce identical `wedge_count`.
Non-determinism is a harness bug.
