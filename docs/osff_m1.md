# Sentinel OSFF M1 — Finalized Specification
**Status: LOCKED — Council Approved**
**Date: 2026-03-02**

---

## 1. Done Condition

M1 is complete when OSFF can:

1. Check out tagged release `osff-m1.3`
2. Run `docker compose run sentinel-m1` (one command)
3. Receive a schema-valid evidence JSON
4. Observe `wedge_count`, `latency_distribution`, declared `latency_unit` and `latency_scope`

The validator script (`tools/validate_evidence.py`) is the machine-readable acceptance gate.
Exit code `0` = PASS. No other acceptance criteria.

---

## 2. Locked Constants

These are frozen. Changing any value requires a new doc revision and schema version bump.

| Constant | Value | Defined In |
|---|---|---|
| `WEDGE_TIMEOUT_MS` | `1000` | `docs/wedge_definition.md`, `tools/fuzz_runner.py` |
| `PROGRESS_WINDOW_MS` | `200` | `docs/wedge_definition.md`, `tools/fuzz_runner.py` |
| `PROGRESS_POLL_INTERVAL_MS` | `10` | `tools/fuzz_runner.py` |
| `MAX_PARSE_TIME_MULTIPLIER` | `100` | `docs/wedge_definition.md`, `tools/fuzz_runner.py` |
| `CORPUS_RANDOM_SEED` | `3735928559` (`0xDEADBEEF`) | `tools/generate_corpus.py` |
| `SCHEMA_VERSION` | `"1.0.0"` | evidence JSON, `tools/validate_evidence.py` |

---

## 3. Wedge Definition (Locked)

A **wedge event** is declared when **either** condition is met:

**Condition 1 — Timeout Wedge**
```
elapsed_ms(trial) > WEDGE_TIMEOUT_MS (1000ms)
```

**Condition 2 — No-Progress Wedge**
```
bytes_consumed_delta == 0
  over any window of length PROGRESS_WINDOW_MS (200ms)
  while elapsed_ms(trial) < WEDGE_TIMEOUT_MS
```

**Progress definition (Decision A — locked):**
Progress is measured as **bytes consumed** by the parser (`g_parser_bytes_consumed` counter),
not output bytes. After the fuzz input, the parser is reset and a heartbeat valid frame is
injected. A trial where the heartbeat is not accepted post-reset is declared `wedge_no_heartbeat`.
This tests recovery-to-IDLE, not just survival during the fuzz phase.

**Anti-slow-drain rule:**
Any trial where:
```
elapsed_ms > MAX_PARSE_TIME_MULTIPLIER × input_length_bytes
```
is declared `wedge_timeout` regardless of bytes-consumed delta.

**Wedge categories (reported separately in evidence JSON):**

| Category | Code | Trigger |
|---|---|---|
| Timeout | `wedge_timeout` | Wall-clock exceeded or anti-slow-drain |
| No-progress | `wedge_no_progress` | Output stalled within timeout window |
| No-heartbeat | `wedge_no_heartbeat` | Heartbeat frame not accepted after malformed burst |

All three sum to `wedge_count`. What is NOT a wedge: clean rejection, error return, crash
(crashes are tracked separately in `crash_count`).

---

## 4. Target Under Test (Decision B — locked)

**In-process simulator via ctypes.**

The reference C parser (`tools/parser_target.c`) is compiled to a shared library and loaded
via Python ctypes. No subprocess, no IPC, no timing noise from OS scheduling between
processes. Deterministic. Reproducible on any machine with gcc + Python 3.10+.

Two variants ship:
- `parser_safe_*` — hardened reference, expected `wedge_count: 0` across all corpus cases
- `parser_vuln_*` — intentional defects demonstrable via behavioral divergence in `per_case_results`. The `zero_length_valid_chk` case produces the clearest divergence: vuln accepts a zero-length frame (`frames_accepted=1`) that safe correctly rejects (`frames_accepted=0`). This is a real semantic defect — vuln lacks the zero-length rejection guard present in safe. Timing-based wedge detection of the unbounded SOF loop requires input sizes not practical in M1; that is explicitly M2 scope. The safe parser's `wedge_count: 0` and correct frame rejection are the primary M1 correctness claims.

Persistent subprocess target is explicitly deferred to M2.

---

## 5. Reproducibility Strategy (Decision C — locked)

**Docker + `make reproduce`.**

```bash
# One-command reproduce from any machine with Docker installed
docker compose run sentinel-m1

# Equivalent make target
make reproduce
```

`Dockerfile` pins:
- Ubuntu 24.04 LTS base
- Python 3.12 (current in Ubuntu 24.04 LTS; package version floats with apt)
- gcc (current in Ubuntu 24.04 apt; no strict version pin)
- No pip dependencies (stdlib only for harness)

`docker compose run sentinel-m1` runs `./run_m1.sh` inside the container, which:
1. Generates corpus (fixed seed `3735928559` (`0xDEADBEEF`))
2. Compiles `parser_target.c`
3. Runs fuzz harness
4. Validates evidence artifact
5. Exits `0` on PASS, `1` on FAIL

Evidence artifact is written to `/evidence/` volume-mounted to host.

---

## 6. Evidence JSON Schema (Locked — v1.0.0)

**Complete field specification:**

```json
{
  "schema_version":         "string — required, must be '1.0.0'",
  "harness_version":        "string — required, e.g. 'osff-m1.3'",
  "run_timestamp_utc":      "string — ISO 8601, e.g. '2026-03-02T14:00:00Z'",
  "parser_under_test":      "string — enum: 'safe' | 'vuln'",
  "firmware_build_id":      "string — git SHA (40 hex chars) from 'git rev-parse HEAD', or 'untracked-YYYYMMDDHHMMSS' if run outside a git repo. Submitted artifact is always regenerated post-tag so this field contains the tag SHA.",
  "config_hash":            "string — SHA-256 of JSON-serialized locked constants dict with keys in sorted order: {HARNESS_VERSION, MAX_PARSE_TIME_MULT, PROGRESS_POLL_INTERVAL, PROGRESS_WINDOW_MS, SCHEMA_VERSION, WEDGE_TIMEOUT_MS}. Independently reproducible from constants in docs/wedge_definition.md.",
  "input_corpus_hash":      "string — SHA-256 of all corpus file content in sorted order",
  "corpus_random_seed":     "integer — must be 3735928559 (0xDEADBEEF)",
  "cases_count":            "integer >= 0 — number of corpus cases",
  "trial_count":            "integer >= 0 — must equal cases_count for M1",
  "enforcement_count":      "integer >= 0 — must equal wedge_count + crash_count",
  "wedge_count":            "integer >= 0",
  "crash_count":            "integer >= 0",
  "wedge_categories": {
    "wedge_timeout":        "integer >= 0",
    "wedge_no_progress":    "integer >= 0",
    "wedge_no_heartbeat":   "integer >= 0",
    "wedge_spin":           "integer >= 0"
  },
  "latency_scope":          "string — must be 'harness_roundtrip' for M1",
  "latency_unit":           "string — must be 'us' for M1",
  "harness_overhead_note":  "string — human-readable, e.g. 'includes Python ctypes + OS scheduling'",
  "latency_distribution": {
    "p50":  "number >= 0 | null",
    "p95":  "number >= 0 | null",
    "p99":  "number >= 0 | null",
    "min":  "number >= 0 | null",
    "max":  "number >= 0 | null",
    "n":    "integer >= 0"
  },
  "wedge_timeout_ms":       "integer > 0 — must equal 1000",
  "progress_window_ms":     "integer > 0 — must equal 200",
  "max_parse_time_mult":    "integer > 0 — must equal 100",
  "per_case_results": [
    {
      "case":             "string — corpus filename stem",
      "wedge":            "boolean",
      "wedge_type":       "string | null — 'wedge_timeout' | 'wedge_no_progress' | 'wedge_no_heartbeat' | null",
      "crash":            "boolean",
      "heartbeat_ok":     "boolean — did heartbeat frame parse after this case?",
      "latency_us":       "number >= 0 | null",
      "frames_accepted":  "integer >= 0",
      "output_bytes":     "integer >= 0"
    }
  ]
}
```

**Invariants enforced by validator:**
- `p50 <= p95 <= p99` (ordering check)
- `latency_distribution.n <= trial_count`
- `enforcement_count == wedge_count + crash_count`
- `sum(wedge_categories.values()) == wedge_count`
- `len(per_case_results) == trial_count`
- `sum(r.wedge for r in per_case_results) == wedge_count`
- `sum(r.crash for r in per_case_results) == crash_count`
- `corpus_random_seed == 3735928559` (0xDEADBEEF)
- `wedge_timeout_ms == 1000`
- `progress_window_ms == 200`
- `latency_scope == 'harness_roundtrip'`
- `latency_unit == 'us'`

### config_hash Definition

`config_hash` is the SHA-256 of the canonical JSON serialization (UTF-8, sorted keys) of the locked constants dictionary exactly as serialized by `tools/fuzz_runner.py`:

```json
{
  "HARNESS_VERSION": "osff-m1",
  "MAX_PARSE_TIME_MULT": 100,
  "PROGRESS_POLL_INTERVAL": 0.01,
  "PROGRESS_WINDOW_MS": 200,
  "SCHEMA_VERSION": "1.0.0",
  "WEDGE_TIMEOUT_MS": 1000
}
```

Notes:
- `PROGRESS_POLL_INTERVAL` is in seconds (`0.01` = 10ms).
- `CORPUS_RANDOM_SEED` (`3735928559`, i.e. `0xDEADBEEF`) is captured in the evidence artifact as `corpus_random_seed` but is not part of `config_hash` in the current implementation.

To independently verify: serialize this dict with `json.dumps(config, sort_keys=True).encode()` and compute SHA-256.

---

## 7. Corpus Categories (Locked)

39 seed cases generated deterministically from `CORPUS_RANDOM_SEED = 3735928559` (`0xDEADBEEF`).

| # | Category | Cases | Description |
|---|---|---|---|
| 1 | Valid frames | 4 | Baseline — safe parser must accept, zero wedges |
| 2 | Partial frames | 7 | Truncated at offsets 1, 2, 3, 5, 10, SOF-only, SOF+LEN |
| 3 | Overlong length | 3 | LEN > MAX_PAYLOAD_SIZE |
| 4 | Bad checksum | 2 | Correct structure, wrong XOR |
| 5 | Garbage/burst noise | 6 | Random, all-zeros, all-0xFF, all-SOF, no-SOF, 512B burst |
| 6 | Zero-length payload | 2 | LEN=0 valid/invalid checksum |
| 7 | Valid structure, garbage payload | 1 | Passes framing, fails content |
| 8 | SOF mid-frame | 2 | Resync stress |
| 9 | Interlaced valid/invalid | 1 | Mixed stream |
| 10 | Bit flips | 6 | Single-bit at positions 0,7,8,15,16,23 |
| 11 | Empty input | 1 | Zero bytes |
| 12 | Single bytes | 4 | SOF, null, 0xFF, 0x55 |

Each malformed case (categories 2–12) is followed by a heartbeat valid frame injection
by the harness.

**Note:** `partial_frame_cut1`, `partial_frame_sof_only`, and `single_single_sof` are byte-identical (all `0xAA` — the SOF byte). This is a protocol constraint: any 1-byte truncation of a valid frame is the SOF byte. The three cases are counted separately for categorical coverage (partial frames vs. single bytes) and their filenames contribute distinctly to `input_corpus_hash`. `heartbeat_ok` in per-case results records whether it was accepted.

---

## 8. Deliverable Checklist

M1 tag `osff-m1.3` must contain:

- [x] `docs/wedge_definition.md` — formal spec matching this document
- [x] `docs/osff_m1.md` — this file
- [x] `tools/parser_target.c` — safe + vuln variants, progress instrumented
- [x] `tools/fuzz_runner.py` — harness with heartbeat injection, output-byte progress
- [x] `tools/validate_evidence.py` — all invariants above enforced
- [x] `tools/generate_corpus.py` — seed=3735928559 (0xDEADBEEF), deterministic
- [x] `Dockerfile` + `docker-compose.yml` — reproducible Ubuntu 24.04 environment (no version pinning; ARM/x86 portable)
- [x] `Makefile` — `make reproduce` target
- [x] `run_m1.sh` — called inside Docker
- [x] `corpus/*.bin` — 39 cases committed
- [x] `evidence/EP-YYYYMMDD-m1.json` — example artifact from a clean run
- [x] `README.md` — one-command instructions, schema description

---

## 9. What Is Explicitly Out of Scope for M1

- Persistent subprocess parser target (M2)
- CI/CD pipeline integration (M2)
- Hardened parser module (M2)
- Hash-chained event log (M3)
- Any hardware, device, or robot claims
- AFL++, libFuzzer, or mutation engine integration (post-M1 enhancement)
- Certification claims of any kind
