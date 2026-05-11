#!/usr/bin/env python3
"""
validate_m2_evidence.py — WedgeBench M2 Evidence Artifact Validator

Validates an M2 go-tcg-storage evidence JSON artifact against the m2-draft schema.

Checks:
  - Required top-level metadata fields with correct types
  - Allowed literal values for key string fields
  - trial_count consistency with results array length
  - Required per-case fields with correct types
  - Allowed parser_outcome values
  - Non-negative numeric counters
  - Boolean wedge / heartbeat fields

Usage:
    python3 tools/validate_m2_evidence.py evidence/m2/EP-M2-go-tcg-storage-draft.json

Exit codes:
    0 — PASS
    1 — FAIL (validation errors found)
    2 — Usage / file error
"""

import json
import sys
from pathlib import Path

# ── Schema constants ──────────────────────────────────────────────────────────

SUPPORTED_SCHEMA_VERSIONS = {"m2-draft"}

REQUIRED_TOP_LEVEL: dict[str, type | tuple] = {
    "schema_version":   str,
    "milestone":        str,
    "artifact_type":    str,
    "target":           str,
    "adapter":          str,
    "parser_under_test": str,
    "trial_count":      int,
    "source_evidence":  str,
    "claim_scope":      str,
    "latency_note":     str,
    "results":          list,
}

ALLOWED_LITERALS: dict[str, set] = {
    "schema_version": SUPPORTED_SCHEMA_VERSIONS,
    "milestone":      {"M2"},
    "artifact_type":  {"tcg_storage_adapter_draft"},
    "target":         {"go-tcg-storage"},
    "adapter":        {"tcg_adapter"},
}

REQUIRED_CASE_FIELDS: dict[str, type | tuple] = {
    "case":           str,
    "ok":             bool,
    "error":          (str, type(None)),
    "response_len":   int,
    "frames_accepted": int,
    "output_bytes":   int,
    "progress":       int,
    "latency_us":     (float, int),
    "parser_outcome": str,
    "heartbeat_ok":   bool,
    "wedge":          bool,
    "wedge_type":     (str, type(None)),
}

NONNEG_CASE_INT_FIELDS = ("response_len", "frames_accepted", "output_bytes", "progress")

ALLOWED_PARSER_OUTCOMES = {"accepted", "empty_parse", "rejected", "probe_error"}

ALLOWED_WEDGE_TYPES = {"wedge_timeout", "wedge_no_progress", "wedge_no_heartbeat", "wedge_spin", None}


# ── Validator ─────────────────────────────────────────────────────────────────

class _Result:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, msg: str) -> None:
        self.errors.append(f"  ERROR: {msg}")

    @property
    def passed(self) -> bool:
        return not self.errors

    def report(self) -> str:
        return "\n".join(self.errors)


def _check_type(r: _Result, label: str, val: object, expected: type | tuple) -> bool:
    """Return True if val matches expected type(s), else record error and return False."""
    types = expected if isinstance(expected, tuple) else (expected,)
    if not isinstance(val, types):
        type_names = " | ".join(t.__name__ for t in types)
        r.error(f"{label}: expected {type_names}, got {type(val).__name__} ({val!r})")
        return False
    return True


def validate(data: object) -> _Result:
    r = _Result()

    if not isinstance(data, dict):
        r.error("Top-level JSON must be an object")
        return r

    # ── Required top-level fields ─────────────────────────────────────────
    for field, expected in REQUIRED_TOP_LEVEL.items():
        if field not in data:
            r.error(f"Missing required field: '{field}'")
        else:
            _check_type(r, f"'{field}'", data[field], expected)

    if not r.passed:
        return r  # structure too broken to continue

    # ── Allowed literal values ────────────────────────────────────────────
    for field, allowed in ALLOWED_LITERALS.items():
        val = data[field]
        if val not in allowed:
            r.error(f"'{field}' must be one of {sorted(allowed)}, got {val!r}")

    # ── trial_count consistency ───────────────────────────────────────────
    trial_count: int = data["trial_count"]
    results: list = data["results"]

    if trial_count < 0:
        r.error(f"'trial_count' must be >= 0, got {trial_count}")

    if len(results) != trial_count:
        r.error(
            f"'trial_count' ({trial_count}) does not match "
            f"len(results) ({len(results)})"
        )

    # ── Per-case validation ───────────────────────────────────────────────
    for i, case in enumerate(results):
        prefix = f"results[{i}]"

        if not isinstance(case, dict):
            r.error(f"{prefix}: must be an object, got {type(case).__name__}")
            continue

        case_name = case.get("case", f"<index {i}>")
        label_prefix = f"{prefix} ({case_name!r})"

        # Required fields and types
        for field, expected in REQUIRED_CASE_FIELDS.items():
            if field not in case:
                r.error(f"{label_prefix}: missing required field '{field}'")
            else:
                _check_type(r, f"{label_prefix} '{field}'", case[field], expected)

        # Non-negative counters
        for field in NONNEG_CASE_INT_FIELDS:
            if field in case and isinstance(case[field], int) and case[field] < 0:
                r.error(f"{label_prefix} '{field}' must be >= 0, got {case[field]}")

        # latency_us >= 0
        if "latency_us" in case and isinstance(case["latency_us"], (float, int)):
            if case["latency_us"] < 0:
                r.error(f"{label_prefix} 'latency_us' must be >= 0, got {case['latency_us']}")

        # parser_outcome allowed values
        if "parser_outcome" in case and isinstance(case["parser_outcome"], str):
            if case["parser_outcome"] not in ALLOWED_PARSER_OUTCOMES:
                r.error(
                    f"{label_prefix} 'parser_outcome' must be one of "
                    f"{sorted(ALLOWED_PARSER_OUTCOMES)}, got {case['parser_outcome']!r}"
                )

        # wedge_type: allowed values (None or known string)
        if "wedge_type" in case:
            wt = case["wedge_type"]
            if wt not in ALLOWED_WEDGE_TYPES:
                r.error(
                    f"{label_prefix} 'wedge_type' must be one of "
                    f"{sorted(str(v) for v in ALLOWED_WEDGE_TYPES)}, got {wt!r}"
                )

        # wedge consistency: if wedge=True, wedge_type must be non-None
        if case.get("wedge") is True and case.get("wedge_type") is None:
            r.error(f"{label_prefix} 'wedge' is True but 'wedge_type' is None")

        # wedge consistency: if wedge=False, wedge_type must be None
        if case.get("wedge") is False and case.get("wedge_type") is not None:
            r.error(
                f"{label_prefix} 'wedge' is False but 'wedge_type' is "
                f"{case['wedge_type']!r}"
            )

    return r


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    if len(sys.argv) != 2:
        print(
            "Usage: python3 tools/validate_m2_evidence.py <artifact.json>",
            file=sys.stderr,
        )
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        return 1

    result = validate(data)

    if result.passed:
        trial_count = data.get("trial_count", "?")
        print("M2 evidence: PASS")
        print(f"trial_count={trial_count}")
        return 0
    else:
        print("M2 evidence: FAIL")
        print(result.report())
        return 1


if __name__ == "__main__":
    sys.exit(main())
