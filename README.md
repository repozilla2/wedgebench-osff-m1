# Sentinel — OSFF Firmware Slice / M1

**Anti-wedge fuzzing + tamper-evident event logging for embedded serial parsers.**

This repository demonstrates a reproducible fuzz harness for detecting parser wedge conditions and validating recovery behavior after malformed input. It is the open-source deliverable for OSFF Milestone 1: Fuzzing harness with wedge detection.

---

## One-Command Run

**Recommended (Docker — fully reproducible):**
```bash
docker compose run sentinel-m1
```

If `docker compose` is not available (older Docker or Compose not installed):
```bash
docker build -t sentinel-m1 .
docker run --rm -v "$(pwd)/evidence:/sentinel/evidence" sentinel-m1
```

**Native fallback** (no Docker — requires Python 3.10+ and GCC):
```bash
./run_m1.sh
```

All three paths produce the same schema-valid artifact structure and verification outcome.

---

## Verification Notes for Reviewers

**Firmware Build ID** — `firmware_build_id` is populated from `git rev-parse HEAD` (or `SENTINEL_GIT_SHA` Docker build arg). The submitted artifact is regenerated after tagging `osff-m1.2` so this field contains the tag commit SHA. Artifacts generated between tags show an intermediate commit SHA — this is expected and not an error.

**Why vuln divergence is measured by correctness, not wedge count** — The vuln variant
demonstrates real semantic defects visible in `per_case_results`: `zero_length_valid_chk`
shows vuln accepting a frame safe correctly rejects (safe `frames_accepted`=0, vuln=1).
Timing-based wedge detection of the unbounded SOF loop requires impractically large inputs;
that is M2 scope. Behavioral divergence via frame acceptance counts is the M1 demonstration.

**What wedge_count=0 proves** — A `wedge_count` of 0 means the safe parser correctly returns to a functional IDLE state after every malformed input, verified via post-reset heartbeat acceptance. It is not a trivial result: a parser with corrupted internal state after malformed input will fail the heartbeat even after reset. The harness's ability to detect incorrect behavior is demonstrated by the vuln parser's `frames_accepted=1` on `zero_length_valid_chk` — a case safe correctly rejects.

**Latency scope** — All latency values carry `latency_scope = "harness_roundtrip"` and
`latency_unit = "us"`. These reflect host-observed harness timing (Python + ctypes + OS
scheduling), not device-native execution timing.

---

## What M1 Delivers

| Deliverable | Location |
|---|---|
| Formal wedge definition | `docs/wedge_definition.md` |
| Fuzz harness | `tools/fuzz_runner.py` |
| Schema validator | `tools/validate_evidence.py` |
| Corpus seed generator | `tools/generate_corpus.py` |
| Reference parser (safe + vuln) | `src/parser_target.c` |
| Example evidence artifact | `evidence/EP-*-m1.json` |

---

## Repository Structure

```
sentinel-osff/
├── docs/
│   └── wedge_definition.md     # Formal wedge spec + constants
├── src/
│   └── parser_target.c         # Reference parser (safe + vulnerable variants)
├── tools/
│   ├── fuzz_runner.py          # Main fuzz harness
│   ├── validate_evidence.py    # Schema + logic validator
│   └── generate_corpus.py      # Corpus seed generator
├── corpus/                     # Binary fuzz seeds (generated)
├── evidence/                   # Output evidence JSON artifacts
├── build/                      # Compiled shared library (generated)
└── run_m1.sh                   # One-command runner
```

---

## Wedge Definition Summary

A **wedge** is declared when either:
1. **Timeout**: parser does not complete within `WEDGE_TIMEOUT_MS` (1000ms)
2. **No-progress**: parser's `bytes_consumed` counter stalls for `PROGRESS_WINDOW_MS` (200ms)

See `docs/wedge_definition.md` for the full formal specification including constants,
gaming resistance, and category definitions.

---

## Corpus Categories

The corpus covers all required malformed traffic patterns:

| Category | Cases | Description |
|---|---|---|
| Valid frames | 4 | Baseline — should never wedge |
| Partial frames | 7 | Truncated at various byte offsets |
| Overlong length | 3 | LEN field > MAX_PAYLOAD_SIZE |
| Bad checksum | 2 | Correct structure, wrong XOR |
| Garbage / burst noise | 6 | Random bytes, all-zeros, all-0xFF, SOF floods |
| Zero-length payload | 2 | LEN=0 with valid/invalid checksum |
| Valid structure, garbage payload | 1 | Passes framing, fails content |
| SOF mid-frame | 2 | Resync stress |
| Interlaced valid/invalid | 1 | Mixed stream |
| Bit flips | 6 | Single-bit errors at various positions |
| Empty input | 1 | Zero-byte input |
| Single bytes | 4 | SOF, null, 0xFF, 0x55 |

**Total: 39 cases**

---

## Evidence Artifact Format

The harness emits a JSON evidence artifact at `evidence/EP-YYYYMMDD-m1.json`.

Key fields:

```json
{
  "schema_version": "1.0.0",
  "firmware_build_id": "<git-sha>",
  "config_hash": "<sha256-of-constants>",
  "input_corpus_hash": "<sha256-of-corpus>",
  "trial_count": 39,
  "wedge_count": 0,
  "crash_count": 0,
  "enforcement_count": 0,
  "wedge_categories": {
    "wedge_timeout": 0,
    "wedge_no_progress": 0,
    "wedge_no_heartbeat": 0,
    "wedge_spin": 0
  },
  "latency_scope": "harness_roundtrip",
  "latency_unit": "us",
  "latency_distribution": {
    "p50": 6.51,
    "p95": 12.96,
    "p99": 13.65,
    "min": 0.22,
    "max": 13.65,
    "n": 39
  }
}
```

**Note on `firmware_build_id`:** Populated from `git rev-parse HEAD` at run time. Pre-tag runs show `untracked-<timestamp>`. The submitted evidence artifact is regenerated after tagging `osff-m1.2`. The `firmware_build_id` in the committed artifact reflects the commit at build time; the final submission artifact is generated from the tagged commit so both will match.

**Note on `config_hash`:** SHA-256 of the JSON-serialized locked constants `{"HARNESS_VERSION":..., "MAX_PARSE_TIME_MULT":..., "PROGRESS_POLL_INTERVAL":..., "PROGRESS_WINDOW_MS":..., "SCHEMA_VERSION":..., "WEDGE_TIMEOUT_MS":...}` with keys in sorted order. Independently reproducible from the constants listed in `docs/wedge_definition.md`. means these measurements include
Python ctypes overhead and OS scheduling. They are **not** device execution times.
This is intentional and honest. The scope field makes this explicit and machine-readable.

---

## Verifying an Evidence Artifact

```bash
python3 tools/validate_evidence.py evidence/EP-20260302-m1.json
```

The validator checks:
- All required fields present with correct types
- Non-negative integer constraints
- Percentile ordering: p50 ≤ p95 ≤ p99
- Latency `n` ≤ `trial_count`
- `enforcement_count` == `wedge_count` + `crash_count`
- `wedge_categories` sum == `wedge_count`
- Per-case result counts match top-level counters

Exit code `0` = PASS, `1` = FAIL.

---

## M1 Done Condition

Milestone 1 is complete when an independent reviewer can:

1. Check out the tagged release `osff-m1.2`
2. Run `./run_m1.sh`
3. Receive a schema-valid evidence JSON including `wedge_count`, `latency_distribution`,
   and `latency_unit`

The validator script (`validate_evidence.py`) is the machine-readable acceptance check.

---

## Parser Variants

`src/parser_target.c` contains two parser implementations:

**`parser_safe_*`** — Hardened reference implementation:
- Bounded loops with `PARSER_MAX_ITERS = 512` guard
- Enforces `MAX_PAYLOAD_SIZE = 253` on LEN field
- Clean rejection + IDLE reset on all malformed inputs
- Progress counter incremented on every byte

**`parser_vuln_*`** — Intentionally defective implementation:
- Unbounded SOF search loop (wedge-able with non-SOF garbage bursts)
- No LEN upper-bound check (out-of-bounds write on LEN=255)
- Demonstrates the failure modes the safe parser prevents

The M1 corpus produces observable behavioral divergence between safe and vuln. The clearest case: `zero_length_valid_chk` — vuln accepts a zero-length frame (`frames_accepted=1`) that safe correctly rejects (`frames_accepted=0`). This is a real semantic defect visible in the evidence artifact without any synthetic injection. Timing-based wedge detection of the unbounded SOF loop requires input sizes impractical for a serial parser corpus; exhaustive vuln stress testing is M2 scope. The safe parser reports `wedge_count: 0` across all cases; this is the primary M1 claim.

---

## Milestone Roadmap

| Milestone | Due | Description |
|---|---|---|
| **M1** (this) | Mar 23, 2026 | Fuzz harness + wedge detection + evidence schema |
| M2 | Apr 13, 2026 | Hardened parser module + test suite + CI runner |
| M3 | Apr 27, 2026 | Hash-chained event log + verifier tooling |
