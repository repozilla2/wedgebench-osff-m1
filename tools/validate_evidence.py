#!/usr/bin/env python3
"""
validate_evidence.py — Sentinel OSFF M1 Evidence Artifact Validator

Validates a fuzz run evidence JSON against the M1 schema:
  - All required fields present with correct types
  - Non-negative integer constraints
  - Percentile ordering: p50 <= p95 <= p99
  - Latency sample count consistency
  - Wedge category sum == wedge_count
  - Schema version check

Usage:
    python3 tools/validate_evidence.py evidence/EP-20260330-m1.json
    python3 tools/validate_evidence.py evidence/EP-20260330-m1.json --strict

Exit codes:
    0 — PASS
    1 — FAIL (validation errors found)
    2 — Usage error
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Any


# ─── Schema definition ────────────────────────────────────────────────────────

SUPPORTED_SCHEMA_VERSIONS = {"1.0.0"}

# M1 REQUIRED fields — artifact fails validation without these
REQUIRED_TOP_LEVEL = {
    "schema_version":         str,
    "firmware_build_id":      str,
    "config_hash":            str,
    "input_corpus_hash":      str,
    "corpus_random_seed":     int,
    "cases_count":            int,
    "trial_count":            int,
    "wedge_count":            int,
    "latency_scope":          str,
    "latency_unit":           str,
    "latency_distribution":   dict,
    "wedge_timeout_ms":       int,
    "progress_window_ms":     int,
    "harness_version":        str,
}

# OPTIONAL fields — validated if present, warned if absent
OPTIONAL_TOP_LEVEL = {
    "run_timestamp_utc":      str,
    "parser_under_test":      str,
    "enforcement_count":      int,
    "crash_count":            int,
    "wedge_categories":       dict,
    "harness_overhead_note":  str,
    "max_parse_time_mult":    int,
    "per_case_results":       list,   # optional debug output
}

NON_NEGATIVE_INT_FIELDS = [
    "trial_count", "wedge_count", "cases_count",
    "enforcement_count", "crash_count",
    "wedge_timeout_ms", "progress_window_ms", "max_parse_time_mult",
]

WEDGE_CATEGORY_FIELDS = ["wedge_timeout", "wedge_no_progress", "wedge_no_heartbeat", "wedge_spin"]

LATENCY_DIST_FIELDS = {
    "p50": (float, type(None)),
    "p95": (float, type(None)),
    "p99": (float, type(None)),
    "n":   int,
    "min": (float, int),
    "max": (float, int),
}

# Locked constants — deviations are hard validation errors
LOCKED_CONSTANTS = {
    "corpus_random_seed": 3735928559,
    "wedge_timeout_ms":   1000,
    "progress_window_ms": 200,
    "latency_scope":      "harness_roundtrip",
    "latency_unit":       "us",
    "max_parse_time_mult": 100,
}

VALID_LATENCY_UNITS  = {"us", "ms", "ns"}
VALID_LATENCY_SCOPES = {"harness_roundtrip", "parser_execution", "transport_only"}
VALID_PARSERS        = {"safe", "vuln"}


# ══════════════════════════════════════════════════════════════════════════════
# Validator
# ══════════════════════════════════════════════════════════════════════════════

class ValidationResult:
    def __init__(self):
        self.errors:   list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str):
        self.errors.append(f"  ERROR: {msg}")

    def warn(self, msg: str):
        self.warnings.append(f"  WARN:  {msg}")

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def report(self) -> str:
        lines = []
        lines.extend(self.errors)
        lines.extend(self.warnings)
        return "\n".join(lines)


def validate_single(ev: dict, name: str = "") -> ValidationResult:
    r = ValidationResult()
    label = f"[{name}] " if name else ""

    # ── Required fields and types ─────────────────────────────────────────
    for field, expected_type in REQUIRED_TOP_LEVEL.items():
        if field not in ev:
            r.error(f"{label}Missing required field: '{field}'")
            continue
        val = ev[field]
        if not isinstance(val, expected_type):
            r.error(f"{label}Field '{field}': expected {expected_type.__name__}, "
                    f"got {type(val).__name__} ({val!r})")

    if r.errors:
        # Skip deeper checks if structure is broken
        return r

    # ── Schema version ────────────────────────────────────────────────────
    sv = ev.get("schema_version", "")
    if sv and sv not in SUPPORTED_SCHEMA_VERSIONS:
        r.error(f"{label}Unsupported schema_version: '{sv}'. "
                f"Supported: {SUPPORTED_SCHEMA_VERSIONS}")

    # ── Locked constants (deviations are hard errors) ─────────────────────
    for field, expected_val in LOCKED_CONSTANTS.items():
        if field in ev and ev[field] != expected_val:
            r.error(f"{label}Locked constant '{field}' must be {expected_val!r}, "
                    f"got {ev[field]!r}. Changing locked constants requires a schema version bump.")

    # ── cases_count consistency ───────────────────────────────────────────
    if "cases_count" in ev and "trial_count" in ev:
        if ev["cases_count"] != ev["trial_count"]:
            r.error(f"{label}cases_count ({ev['cases_count']}) != "
                    f"trial_count ({ev['trial_count']}): must be equal for M1.")

    # ── Optional fields: type-check if present ────────────────────────────
    for field, expected_type in OPTIONAL_TOP_LEVEL.items():
        if field in ev and not isinstance(ev[field], expected_type):
            r.error(f"{label}Optional field '{field}': expected {expected_type.__name__}, "
                    f"got {type(ev[field]).__name__}")

    # ── Non-negative integers ─────────────────────────────────────────────
    for field in NON_NEGATIVE_INT_FIELDS:
        if field in ev and isinstance(ev[field], int):
            if ev[field] < 0:
                r.error(f"{label}Field '{field}' must be >= 0, got {ev[field]}")

    # ── Parser type (warn only) ───────────────────────────────────────────
    if "parser_under_test" in ev and ev["parser_under_test"] not in VALID_PARSERS:
        r.warn(f"{label}Unexpected parser_under_test: '{ev['parser_under_test']}'. "
               f"Expected one of {VALID_PARSERS}")

    # ── Latency unit and scope ────────────────────────────────────────────
    if ev.get("latency_unit") not in VALID_LATENCY_UNITS:
        r.error(f"{label}Invalid latency_unit: '{ev.get('latency_unit')}'. "
                f"Must be one of {VALID_LATENCY_UNITS}")

    if ev.get("latency_scope") not in VALID_LATENCY_SCOPES:
        r.error(f"{label}Invalid latency_scope: '{ev.get('latency_scope')}'. "
                f"Must be one of {VALID_LATENCY_SCOPES}")

    # ── Latency distribution ──────────────────────────────────────────────
    ld = ev.get("latency_distribution", {})
    for field, expected in LATENCY_DIST_FIELDS.items():
        if field not in ld:
            r.error(f"{label}latency_distribution missing '{field}'")
            continue
        val = ld[field]
        if isinstance(expected, tuple):
            if not isinstance(val, expected):
                r.error(f"{label}latency_distribution.{field}: expected "
                        f"{[t.__name__ for t in expected]}, got {type(val).__name__}")
        else:
            if not isinstance(val, expected):
                r.error(f"{label}latency_distribution.{field}: expected "
                        f"{expected.__name__}, got {type(val).__name__}")

    # Percentile ordering: p50 <= p95 <= p99
    p50 = ld.get("p50")
    p95 = ld.get("p95")
    p99 = ld.get("p99")
    if all(v is not None for v in [p50, p95, p99]):
        if not (p50 <= p95):
            r.error(f"{label}Percentile ordering violated: p50={p50} > p95={p95}")
        if not (p95 <= p99):
            r.error(f"{label}Percentile ordering violated: p95={p95} > p99={p99}")
        if any(v < 0 for v in [p50, p95, p99]):
            r.error(f"{label}Negative latency value in distribution")

    # n <= trial_count
    n           = ld.get("n", 0)
    trial_count = ev.get("trial_count", 0)
    wedge_count = ev.get("wedge_count", 0)
    crash_count = ev.get("crash_count", 0)
    if isinstance(n, int) and isinstance(trial_count, int) and n > trial_count:
        r.error(f"{label}latency_distribution.n ({n}) > trial_count ({trial_count})")

    # ── Wedge categories (optional — only validated if present) ───────────
    wc = ev.get("wedge_categories")
    if wc is not None:
        for field in WEDGE_CATEGORY_FIELDS:
            if field not in wc:
                r.warn(f"{label}wedge_categories missing '{field}'")
            elif not isinstance(wc[field], int) or wc[field] < 0:
                r.error(f"{label}wedge_categories.{field} must be int >= 0")
        cat_sum = sum(wc.get(f, 0) for f in WEDGE_CATEGORY_FIELDS)
        if cat_sum != wedge_count:
            r.error(f"{label}wedge_categories sum ({cat_sum}) != wedge_count ({wedge_count})")

    # ── enforcement_count (optional — only validated if present) ──────────
    if "enforcement_count" in ev and "crash_count" in ev:
        expected_enforcement = wedge_count + crash_count
        if ev["enforcement_count"] != expected_enforcement:
            r.error(f"{label}enforcement_count ({ev['enforcement_count']}) != "
                    f"wedge_count + crash_count ({expected_enforcement})")

    # ── per_case_results (optional — only validated if present) ───────────
    pcr = ev.get("per_case_results")
    if pcr is not None:
        if not isinstance(pcr, list):
            r.error(f"{label}per_case_results must be a list")
        else:
            actual_wedges  = sum(1 for c in pcr if c.get("wedge"))
            actual_crashes = sum(1 for c in pcr if c.get("crash"))
            if actual_wedges != wedge_count:
                r.error(f"{label}wedge_count ({wedge_count}) != "
                        f"per_case wedge sum ({actual_wedges})")
            if "crash_count" in ev and actual_crashes != crash_count:
                r.error(f"{label}crash_count ({crash_count}) != "
                        f"per_case crash sum ({actual_crashes})")
            if len(pcr) != trial_count:
                r.error(f"{label}per_case_results length ({len(pcr)}) != "
                        f"trial_count ({trial_count})")

    return r


def validate_artifact(data: Any, strict: bool = False) -> tuple[bool, str]:
    """
    Validate an evidence artifact. Handles both single-parser and both-parser formats.
    Returns (passed: bool, report: str).
    """
    lines    = []
    all_pass = True

    # Detect format: both-parser wraps in {"safe": {...}, "vuln": {...}}
    if isinstance(data, dict) and set(data.keys()).issubset({"safe", "vuln"}):
        for parser_name, ev in data.items():
            r = validate_single(ev, name=parser_name)
            status = "✓ PASS" if r.passed else "✗ FAIL"
            lines.append(f"Parser '{parser_name}': {status}")
            if not r.passed:
                all_pass = False
            report = r.report()
            if report:
                lines.append(report)
            if strict and r.warnings:
                all_pass = False
    elif isinstance(data, dict):
        r = validate_single(data)
        status = "✓ PASS" if r.passed else "✗ FAIL"
        lines.append(f"Artifact: {status}")
        if not r.passed:
            all_pass = False
        report = r.report()
        if report:
            lines.append(report)
        if strict and r.warnings:
            all_pass = False
    else:
        lines.append("✗ FAIL: Top-level JSON must be an object")
        all_pass = False

    return all_pass, "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Sentinel OSFF M1 — Evidence artifact validator"
    )
    ap.add_argument("artifact", help="Path to evidence JSON artifact")
    ap.add_argument("--strict", action="store_true",
                    help="Treat warnings as errors")
    args = ap.parse_args()

    path = Path(args.artifact)
    if not path.exists():
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(2)

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    passed, report = validate_artifact(data, strict=args.strict)

    print(f"\nValidating: {path}")
    print(report)
    print()
    print("Result:", "PASS" if passed else "FAIL")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
