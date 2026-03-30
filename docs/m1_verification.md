# Sentinel M1 — Verification Steps

## Requirements

- Docker (any recent version)
- Git

No other dependencies required.

---

## One Command

```bash
git clone <repo-url>
cd wedgebench-osff-m1
docker compose run sentinel-m1
```

## Expected Output

```
Parser 'safe': ✓ PASS
Parser 'vuln': ✓ PASS
Result: PASS
```

Typical runtime: ~1 second. Evidence artifact written to `evidence/EP-<date>-m1.json`.

---

## If docker compose Is Not Available

```bash
docker build -t sentinel-m1 .
docker run --rm -v "$(pwd)/evidence:/sentinel/evidence" sentinel-m1
```

## Native (No Docker)

```bash
./run_m1.sh   # requires Python 3.10+ and GCC
```

---

## Validating an Existing Artifact

```bash
python3 tools/validate_evidence.py evidence/EP-<date>-m1.json --strict
```

Expected: `Result: PASS` for both `safe` and `vuln` parsers.

---

## What to Check in the Artifact

Open `evidence/EP-<date>-m1.json` and confirm:

| Field | Expected value |
|---|---|
| `schema_version` | `"1.0.0"` |
| `corpus_random_seed` | `3735928559` |
| `cases_count` | `39` |
| `trial_count` | `39` |
| `wedge_count` (safe) | `0` |
| `wedge_timeout_ms` | `1000` |
| `progress_window_ms` | `200` |
| `latency_scope` | `"harness_roundtrip"` |
| `firmware_build_id` | `osff-m1.3` (exact tag name) |
