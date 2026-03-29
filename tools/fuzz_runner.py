#!/usr/bin/env python3
"""
fuzz_runner.py — Sentinel OSFF M1 Fuzz Harness

Injects corpus inputs into the C parser via ctypes, detects wedge events,
and emits a schema-valid evidence JSON artifact.

Usage:
    python3 tools/fuzz_runner.py [--corpus CORPUS_DIR] [--output OUTPUT_FILE]
                                  [--parser {safe,vuln,both}] [--trials N]

One-command run (from repo root):
    python3 tools/fuzz_runner.py

Constants (LOCKED — must match docs/wedge_definition.md and docs/osff_m1.md):
    WEDGE_TIMEOUT_MS        1000
    PROGRESS_WINDOW_MS      200
    MAX_PARSE_TIME_MULT     100
    CORPUS_RANDOM_SEED      1234
    PROGRESS_POLL_INTERVAL  0.010  (10ms)
"""

import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
import datetime
from pathlib import Path
from typing import Optional

# ─── Wedge detection constants (must match wedge_definition.md) ──────────────
# LOCKED: do not change without bumping SCHEMA_VERSION and updating docs/osff_m1.md
WEDGE_TIMEOUT_MS        = 1000
PROGRESS_WINDOW_MS      = 200
MAX_PARSE_TIME_MULT     = 100      # max ms per input byte
PROGRESS_POLL_INTERVAL  = 0.010   # 10ms

# ─── Corpus constants ─────────────────────────────────────────────────────────
CORPUS_RANDOM_SEED      = 1234    # LOCKED: determinism anchor

# ─── Paths ───────────────────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).parent.parent
SRC_DIR      = REPO_ROOT / "src"
CORPUS_DIR   = REPO_ROOT / "corpus"
EVIDENCE_DIR = REPO_ROOT / "evidence"
LIB_PATH     = REPO_ROOT / "build" / "libparser.so"

# ─── Schema version (increment on schema changes) ────────────────────────────
SCHEMA_VERSION  = "1.0.0"
HARNESS_VERSION = "osff-m1"


# ══════════════════════════════════════════════════════════════════════════════
# Parser library loader
# ══════════════════════════════════════════════════════════════════════════════

def build_parser_lib() -> Path:
    """Compile parser_target.c to a shared library if not already built."""
    build_dir = REPO_ROOT / "build"
    build_dir.mkdir(exist_ok=True)

    lib = build_dir / "libparser.so"
    src = SRC_DIR / "parser_target.c"

    if lib.exists() and lib.stat().st_mtime > src.stat().st_mtime:
        return lib  # already up to date

    print("[harness] Compiling parser_target.c ...", file=sys.stderr)
    result = subprocess.run(
        ["gcc", "-O0", "-g", "-shared", "-fPIC",
         "-o", str(lib), str(src)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("[harness] Compile error:\n" + result.stderr, file=sys.stderr)
        sys.exit(1)
    print("[harness] Compiled OK →", lib, file=sys.stderr)
    return lib


def load_parser(lib_path: Path) -> ctypes.CDLL:
    lib = ctypes.CDLL(str(lib_path))

    # ParserCtx is ~290 bytes; allocate as opaque buffer
    # sizeof(ParserCtx): state(4) + exp_len(1) + payload(253) + idx(1) + xor(1) + pad + accepted(8) + rejected(8)
    # Use 512 bytes to be safe with alignment
    lib._ctx_size = 512

    # void parser_safe_init(ParserCtx*)
    lib.parser_safe_init.argtypes  = [ctypes.c_void_p]
    lib.parser_safe_init.restype   = None

    # int parser_safe_feed_buffer(ParserCtx*, const uint8_t*, size_t)
    lib.parser_safe_feed_buffer.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
    ]
    lib.parser_safe_feed_buffer.restype = ctypes.c_int

    # void parser_vuln_init(ParserCtx*)
    lib.parser_vuln_init.argtypes  = [ctypes.c_void_p]
    lib.parser_vuln_init.restype   = None

    # int parser_vuln_feed_buffer(ParserCtx*, const uint8_t*, size_t)
    lib.parser_vuln_feed_buffer.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t
    ]
    lib.parser_vuln_feed_buffer.restype = ctypes.c_int

    # volatile size_t g_parser_bytes_consumed
    lib.g_bytes_ref = ctypes.c_size_t.in_dll(lib, "g_parser_bytes_consumed")

    return lib


# ══════════════════════════════════════════════════════════════════════════════
# Corpus loader
# ══════════════════════════════════════════════════════════════════════════════

def load_corpus(corpus_dir: Path) -> list[tuple[str, bytes]]:
    """Load all .bin corpus files. Returns list of (name, data) tuples."""
    cases = []
    for f in sorted(corpus_dir.glob("*.bin")):
        cases.append((f.stem, f.read_bytes()))
    if not cases:
        print(f"[harness] WARNING: No corpus files found in {corpus_dir}", file=sys.stderr)
    return cases


def corpus_hash(cases: list[tuple[str, bytes]]) -> str:
    """SHA-256 of all corpus content in sorted order."""
    h = hashlib.sha256()
    for name, data in sorted(cases):
        h.update(name.encode())
        h.update(data)
    return h.hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# Wedge detection
# ══════════════════════════════════════════════════════════════════════════════

class WedgeMonitor:
    """
    Runs in a background thread while the parser processes input.
    Signals wedge if:
      - wall-clock exceeds WEDGE_TIMEOUT_MS, or
      - bytes_consumed_delta == 0 over PROGRESS_WINDOW_MS window.
    """

    def __init__(self, lib: ctypes.CDLL, input_len: int):
        self.lib          = lib
        self.input_len    = input_len
        self.wedge_type   = None   # set to category string if wedge detected
        self.stop_event   = threading.Event()
        self._last_count  = 0
        self._last_progress_time = time.monotonic()
        self._start_time  = time.monotonic()
        self._max_allowed_ms = MAX_PARSE_TIME_MULT * max(input_len, 1)

    def start(self):
        self._thread = threading.Thread(target=self._monitor, daemon=True)
        self._start_time = time.monotonic()
        self._last_progress_time = self._start_time
        self._thread.start()

    def stop(self):
        self.stop_event.set()
        self._thread.join(timeout=1.0)

    def _monitor(self):
        while not self.stop_event.is_set():
            time.sleep(PROGRESS_POLL_INTERVAL)
            now     = time.monotonic()
            elapsed_ms = (now - self._start_time) * 1000.0

            current_count = self.lib.g_bytes_ref.value

            # Anti-slow-drain check
            if elapsed_ms > self._max_allowed_ms:
                self.wedge_type = "wedge_timeout"
                self.stop_event.set()
                return

            # Wall-clock timeout
            if elapsed_ms > WEDGE_TIMEOUT_MS:
                self.wedge_type = "wedge_timeout"
                self.stop_event.set()
                return

            # Progress check
            if current_count != self._last_count:
                self._last_count = current_count
                self._last_progress_time = now
            else:
                stall_ms = (now - self._last_progress_time) * 1000.0
                if stall_ms > PROGRESS_WINDOW_MS:
                    self.wedge_type = "wedge_no_progress"
                    self.stop_event.set()
                    return


# ══════════════════════════════════════════════════════════════════════════════
# Single trial runner
# ══════════════════════════════════════════════════════════════════════════════

# ─── Heartbeat frame (valid frame the parser must accept after recovery) ──────
# SOF=0xAA, LEN=0x04, PAYLOAD=b"PING", CHK=XOR(0xAA,0x04,0x50,0x49,0x4E,0x47)
_HEARTBEAT_PAYLOAD = b"PING"
_HEARTBEAT_HEADER  = bytes([0xAA, len(_HEARTBEAT_PAYLOAD)])
_HEARTBEAT_CHK     = 0
for _b in _HEARTBEAT_HEADER + _HEARTBEAT_PAYLOAD:
    _HEARTBEAT_CHK ^= _b
HEARTBEAT_FRAME = _HEARTBEAT_HEADER + _HEARTBEAT_PAYLOAD + bytes([_HEARTBEAT_CHK])


def run_trial(lib: ctypes.CDLL, data: bytes, parser_type: str) -> dict:
    """
    Run one fuzz trial. Returns result dict with timing, wedge, and heartbeat info.

    Progress is measured as output bytes (frames_accepted count).
    After the fuzz input, a heartbeat valid frame is injected to test recovery.
    """
    # Allocate opaque context buffer
    ctx_buf = (ctypes.c_uint8 * lib._ctx_size)()
    ctx_ptr = ctypes.cast(ctx_buf, ctypes.c_void_p)

    # Convert inputs to ctypes arrays
    input_arr     = (ctypes.c_uint8 * len(data))(*data) if data else (ctypes.c_uint8 * 1)(0)
    input_len     = len(data)
    heartbeat_arr = (ctypes.c_uint8 * len(HEARTBEAT_FRAME))(*HEARTBEAT_FRAME)

    # Reset progress counter
    lib.g_bytes_ref.value = 0

    # Initialize parser
    if parser_type == "safe":
        lib.parser_safe_init(ctx_ptr)
        feed_fn = lib.parser_safe_feed_buffer
    else:
        lib.parser_vuln_init(ctx_ptr)
        feed_fn = lib.parser_vuln_feed_buffer

    # Set up wedge monitor
    monitor = WedgeMonitor(lib, input_len)
    monitor.start()

    result = {
        "wedge":         False,
        "wedge_type":    None,
        "crash":         False,
        "latency_us":    None,
        "frames_accepted": 0,
        "output_bytes":  0,
        "heartbeat_ok":  False,
    }

    try:
        t0 = time.perf_counter()

        # Phase 1: feed fuzz input
        if not monitor.stop_event.is_set() and input_len > 0:
            frames = feed_fn(ctx_ptr, input_arr, input_len)
            result["frames_accepted"] = frames
            result["output_bytes"]    = frames  # 1 output unit per accepted frame

        t1 = time.perf_counter()
        result["latency_us"] = (t1 - t0) * 1_000_000.0

        # Phase 2: Option A — reset before heartbeat
        # Tests recovery-to-IDLE, not mid-frame resync.
        # See docs/wedge_definition.md for rationale.
        if parser_type == "safe":
            lib.parser_safe_init(ctx_ptr)
        else:
            lib.parser_vuln_init(ctx_ptr)

        if not monitor.stop_event.is_set():
            hb_frames = feed_fn(ctx_ptr, heartbeat_arr, len(HEARTBEAT_FRAME))
            result["heartbeat_ok"] = (hb_frames > 0)
            if not result["heartbeat_ok"] and not monitor.stop_event.is_set():
                result["wedge"]      = True
                result["wedge_type"] = "wedge_no_heartbeat"

    except Exception as e:
        result["crash"]     = True
        result["crash_msg"] = str(e)
    finally:
        monitor.stop()

    if monitor.wedge_type and not result["wedge"]:
        result["wedge"]      = True
        result["wedge_type"] = monitor.wedge_type

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Evidence artifact builder
# ══════════════════════════════════════════════════════════════════════════════

def compute_build_id() -> str:
    """Git SHA of HEAD, or 'untracked' if not in a git repo."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=REPO_ROOT
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    return "untracked-" + datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y%m%d%H%M%S")


def compute_config_hash() -> str:
    """SHA-256 of the wedge definition constants used in this run."""
    config = {
        "WEDGE_TIMEOUT_MS":       WEDGE_TIMEOUT_MS,
        "PROGRESS_WINDOW_MS":     PROGRESS_WINDOW_MS,
        "MAX_PARSE_TIME_MULT":    MAX_PARSE_TIME_MULT,
        "PROGRESS_POLL_INTERVAL": PROGRESS_POLL_INTERVAL,
        "SCHEMA_VERSION":         SCHEMA_VERSION,
        "HARNESS_VERSION":        HARNESS_VERSION,
    }
    return hashlib.sha256(
        json.dumps(config, sort_keys=True).encode()
    ).hexdigest()


def build_evidence(
    results:        list[dict],
    parser_type:    str,
    corpus_cases:   list[tuple[str, bytes]],
    build_id:       str,
    config_hash:    str,
) -> dict:
    """Assemble the evidence artifact from raw trial results."""

    trial_count      = len(results)
    wedge_count      = sum(1 for r in results if r["wedge"])
    crash_count      = sum(1 for r in results if r["crash"])
    enforcement_count = wedge_count + crash_count

    wedge_cats = {
        "wedge_timeout":      sum(1 for r in results if r.get("wedge_type") == "wedge_timeout"),
        "wedge_no_progress":  sum(1 for r in results if r.get("wedge_type") == "wedge_no_progress"),
        "wedge_no_heartbeat": sum(1 for r in results if r.get("wedge_type") == "wedge_no_heartbeat"),
        "wedge_spin":         sum(1 for r in results if r.get("wedge_type") == "wedge_spin"),
    }

    # Latency distribution (harness roundtrip only — not device execution time)
    latencies = sorted(
        r["latency_us"] for r in results
        if r["latency_us"] is not None and not r["wedge"]
    )

    def percentile(data: list[float], p: float) -> Optional[float]:
        if not data:
            return None
        # Nearest-rank method, 1-indexed, clamped to valid range
        rank = max(1, int(len(data) * p / 100.0 + 0.5))
        idx  = min(rank, len(data)) - 1
        return round(data[idx], 3)

    n = len(latencies)
    lat_dist = {
        "p50": percentile(latencies, 50),
        "p95": percentile(latencies, 95),
        "p99": percentile(latencies, 99),
        "min": round(min(latencies), 3) if latencies else None,
        "max": round(max(latencies), 3) if latencies else None,
        "n":   n
    }

    per_case = []
    for i, (name, _) in enumerate(corpus_cases):
        if i < len(results):
            r = results[i]
            per_case.append({
                "case":            name,
                "wedge":           r["wedge"],
                "wedge_type":      r.get("wedge_type"),
                "crash":           r["crash"],
                "heartbeat_ok":    r.get("heartbeat_ok", False),
                "latency_us":      round(r["latency_us"], 3) if r["latency_us"] else None,
                "frames_accepted": r["frames_accepted"],
                "output_bytes":    r.get("output_bytes", 0),
            })

    return {
        "schema_version":         SCHEMA_VERSION,
        "harness_version":        HARNESS_VERSION,
        "run_timestamp_utc":      datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "parser_under_test":      parser_type,
        "firmware_build_id":      build_id,
        "config_hash":            config_hash,
        "input_corpus_hash":      corpus_hash(corpus_cases),
        "corpus_random_seed":     CORPUS_RANDOM_SEED,
        "cases_count":            len(corpus_cases),
        "trial_count":            trial_count,
        "enforcement_count":      enforcement_count,
        "wedge_count":            wedge_count,
        "crash_count":            crash_count,
        "wedge_categories":       wedge_cats,
        "latency_scope":          "harness_roundtrip",
        "latency_unit":           "us",
        "harness_overhead_note":  "Latency includes Python ctypes dispatch and OS scheduling. Not device execution time.",
        "latency_distribution":   lat_dist,
        "wedge_timeout_ms":       WEDGE_TIMEOUT_MS,
        "progress_window_ms":     PROGRESS_WINDOW_MS,
        "max_parse_time_mult":    MAX_PARSE_TIME_MULT,
        "per_case_results":       per_case,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Sentinel OSFF M1 Fuzz Harness")
    parser.add_argument("--corpus",  default=str(CORPUS_DIR),
                        help="Corpus directory (default: corpus/)")
    parser.add_argument("--output",  default=None,
                        help="Output JSON path (default: evidence/EP-YYYYMMDD-m1.json)")
    parser.add_argument("--parser",  choices=["safe", "vuln", "both"], default="both",
                        help="Which parser variant to run (default: both)")
    parser.add_argument("--trials",  type=int, default=0,
                        help="Limit number of trials (0 = all corpus cases)")
    args = parser.parse_args()

    # Build shared library
    lib_path = build_parser_lib()
    lib      = load_parser(lib_path)

    # Load corpus
    corpus_path = Path(args.corpus)
    cases = load_corpus(corpus_path)
    if not cases:
        print("[harness] ERROR: Empty corpus. Generate seeds first.", file=sys.stderr)
        sys.exit(1)

    if args.trials > 0:
        cases = cases[:args.trials]

    build_id    = compute_build_id()
    config_hash = compute_config_hash()

    print(f"[harness] Build ID:     {build_id[:16]}...", file=sys.stderr)
    print(f"[harness] Config hash:  {config_hash[:16]}...", file=sys.stderr)
    print(f"[harness] Corpus cases: {len(cases)}", file=sys.stderr)
    print(f"[harness] Parser:       {args.parser}", file=sys.stderr)

    # Run trials
    parser_types = ["safe", "vuln"] if args.parser == "both" else [args.parser]
    all_evidence = {}

    for ptype in parser_types:
        print(f"\n[harness] ── Running {ptype} parser ──", file=sys.stderr)
        results = []
        for i, (name, data) in enumerate(cases):
            sys.stderr.write(f"\r[harness]   Trial {i+1}/{len(cases)}: {name:<40}")
            sys.stderr.flush()
            r = run_trial(lib, data, ptype)
            results.append(r)
            if r["wedge"]:
                sys.stderr.write(f" ⚠ WEDGE ({r['wedge_type']})")
            elif r["crash"]:
                sys.stderr.write(f" ✗ CRASH")
        sys.stderr.write("\n")

        ev = build_evidence(results, ptype, cases, build_id, config_hash)
        all_evidence[ptype] = ev

        print(f"[harness]   Trials:  {ev['trial_count']}", file=sys.stderr)
        print(f"[harness]   Wedges:  {ev['wedge_count']}", file=sys.stderr)
        print(f"[harness]   Crashes: {ev['crash_count']}", file=sys.stderr)
        if ev['latency_distribution']['n'] > 0:
            ld = ev['latency_distribution']
            print(f"[harness]   Latency (harness roundtrip): "
                  f"p50={ld['p50']}µs p95={ld['p95']}µs p99={ld['p99']}µs",
                  file=sys.stderr)

    # Write output
    date_str = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y%m%d")
    if args.output:
        out_path = Path(args.output)
    elif args.parser == "both":
        out_path = EVIDENCE_DIR / f"EP-{date_str}-m1.json"
    else:
        out_path = EVIDENCE_DIR / f"EP-{date_str}-m1-{args.parser}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)

    output = all_evidence if args.parser == "both" else all_evidence[args.parser]
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n[harness] Evidence written → {out_path}", file=sys.stderr)
    print(str(out_path))   # stdout: machine-readable path


if __name__ == "__main__":
    main()
