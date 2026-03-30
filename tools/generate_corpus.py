#!/usr/bin/env python3
"""
generate_corpus.py — Sentinel OSFF M1 Corpus Seed Generator

Generates binary corpus files covering all malformed UART-style frame categories.
Run once to populate corpus/ before running fuzz_runner.py.

Usage:
    python3 tools/generate_corpus.py [--output CORPUS_DIR]

Frame format:
    [SOF: 0xAA] [LEN: 1 byte] [PAYLOAD: LEN bytes] [CHECKSUM: XOR of all prior bytes]
"""

import os
import struct
import random
import argparse
from pathlib import Path

REPO_ROOT  = Path(__file__).parent.parent
CORPUS_DIR = REPO_ROOT / "corpus"

SOF = 0xAA
MAX_PAYLOAD = 253  # MAX_FRAME_SIZE(256) - SOF(1) - LEN(1) - CHK(1)


def xor_checksum(data: bytes) -> int:
    result = 0
    for b in data:
        result ^= b
    return result


def valid_frame(payload: bytes) -> bytes:
    """Build a valid frame."""
    header = bytes([SOF, len(payload)])
    chk    = xor_checksum(header + payload)
    return header + payload + bytes([chk])


def write_case(corpus_dir: Path, name: str, data: bytes):
    path = corpus_dir / f"{name}.bin"
    path.write_bytes(data)
    print(f"  wrote {name}.bin ({len(data)} bytes)")


def generate_corpus(corpus_dir: Path):
    corpus_dir.mkdir(parents=True, exist_ok=True)
    print(f"Generating corpus → {corpus_dir}\n")

    # ── Category 1: Valid frames (baseline — should never wedge) ─────────
    write_case(corpus_dir, "valid_short",
               valid_frame(b"Hello"))
    write_case(corpus_dir, "valid_max",
               valid_frame(bytes(range(MAX_PAYLOAD % 256)) * (MAX_PAYLOAD // 256 + 1))[:MAX_PAYLOAD + 3])
    write_case(corpus_dir, "valid_single_byte",
               valid_frame(b"\x42"))
    write_case(corpus_dir, "valid_sequence",
               valid_frame(b"ABCD") + valid_frame(b"EFGH") + valid_frame(b"IJKL"))

    # ── Category 2: Partial frames (truncated at various offsets) ─────────
    frame = valid_frame(b"SENTINEL")
    for cut in [1, 2, 3, 5, len(frame) - 1]:
        write_case(corpus_dir, f"partial_frame_cut{cut}", frame[:cut])
    write_case(corpus_dir, "partial_frame_sof_only", bytes([SOF]))
    write_case(corpus_dir, "partial_frame_sof_len_only", bytes([SOF, 0x05]))

    # ── Category 3: Overlong length field ─────────────────────────────────
    # LEN claims more bytes than frame actually contains
    write_case(corpus_dir, "overlong_len_255",
               bytes([SOF, 0xFF]) + bytes(10))   # LEN=255, only 10 payload bytes
    write_case(corpus_dir, "overlong_len_max_payload_plus1",
               bytes([SOF, MAX_PAYLOAD + 1]) + bytes(MAX_PAYLOAD))
    write_case(corpus_dir, "overlong_len_254_short",
               bytes([SOF, 0xFE]) + bytes(5) + bytes([0x00]))  # checksum won't match

    # ── Category 4: Bad checksum ──────────────────────────────────────────
    frame = bytearray(valid_frame(b"PAYLOAD"))
    frame[-1] ^= 0xFF   # flip all bits in checksum
    write_case(corpus_dir, "bad_checksum", bytes(frame))

    frame2 = bytearray(valid_frame(b"TESTDATA"))
    frame2[-1] = (frame2[-1] + 1) & 0xFF   # off-by-one
    write_case(corpus_dir, "bad_checksum_offbyone", bytes(frame2))

    # ── Category 5: Garbage / burst noise ────────────────────────────────
    random.seed(0xDEADBEEF)   # deterministic
    write_case(corpus_dir, "garbage_burst_256",
               bytes([random.randint(0, 255) for _ in range(256)]))
    write_case(corpus_dir, "garbage_burst_512",
               bytes([random.randint(0, 255) for _ in range(512)]))
    write_case(corpus_dir, "garbage_no_sof",
               bytes([b for b in range(256) if b != SOF]))  # 255 bytes, no SOF
    write_case(corpus_dir, "garbage_all_zeros",
               bytes(256))
    write_case(corpus_dir, "garbage_all_ff",
               bytes([0xFF] * 256))
    write_case(corpus_dir, "garbage_all_sof",
               bytes([SOF] * 128))   # stream of SOF bytes — resync stress

    # ── Category 6: Zero-length payload ──────────────────────────────────
    write_case(corpus_dir, "zero_length_valid_chk",
               bytes([SOF, 0x00, SOF ^ 0x00]))   # LEN=0, checksum of SOF+LEN
    write_case(corpus_dir, "zero_length_bad_chk",
               bytes([SOF, 0x00, 0xFF]))

    # ── Category 7: Valid-looking frame with garbage payload ──────────────
    garbage_payload = bytes([random.randint(0x20, 0x7E) for _ in range(16)])
    header          = bytes([SOF, len(garbage_payload)])
    bad_chk         = random.randint(0, 255)
    write_case(corpus_dir, "valid_framing_bad_checksum",
               header + garbage_payload + bytes([bad_chk]))

    # ── Category 8: Repeated SOF mid-frame ───────────────────────────────
    # SOF appears in middle of a frame payload — tests resync behavior
    payload_with_sof = bytes([0x01, 0x02, SOF, 0x03, 0x04])
    write_case(corpus_dir, "sof_mid_payload",
               valid_frame(payload_with_sof))   # valid frame where SOF is in payload

    # Raw stream where SOF appears mid-frame (malformed framing)
    write_case(corpus_dir, "sof_mid_frame_stream",
               bytes([SOF, 0x05, 0x01, 0x02, SOF, 0x03, 0x04, 0x05, 0xFF]))

    # ── Category 9: Interlaced valid and invalid frames ───────────────────
    mixed = (
        valid_frame(b"GOOD1") +
        bytes([SOF, 0xFF] + [0x00] * 5) +   # invalid overlong
        valid_frame(b"GOOD2") +
        bytes([0xDE, 0xAD, 0xBE, 0xEF]) +   # garbage
        valid_frame(b"GOOD3")
    )
    write_case(corpus_dir, "interlaced_valid_invalid", mixed)

    # ── Category 10: Timing / bit-flip simulation ─────────────────────────
    # Single bit flips at various positions in a valid frame
    frame = bytearray(valid_frame(b"BITFLIP"))
    for bit_pos in [0, 7, 8, 15, 16, 23]:
        flipped = bytearray(frame)
        byte_idx = bit_pos // 8
        bit_idx  = bit_pos % 8
        if byte_idx < len(flipped):
            flipped[byte_idx] ^= (1 << bit_idx)
        write_case(corpus_dir, f"bitflip_pos{bit_pos}", bytes(flipped))

    # ── Category 11: Empty input ──────────────────────────────────────────
    write_case(corpus_dir, "empty_input", b"")

    # ── Category 12: Single bytes ─────────────────────────────────────────
    # Note: vuln defect demonstration does not require a synthetic trigger case.
    # The zero_length_valid_chk case (category 6) already produces observable
    # divergence: vuln accepts a zero-length frame (frames_accepted=1) that safe
    # correctly rejects (frames_accepted=0). This is documented in osff_m1.md.
    for byte_val, name in [(SOF, "single_sof"), (0x00, "single_null"),
                            (0xFF, "single_ff"), (0x55, "single_55")]:
        write_case(corpus_dir, f"single_{name}", bytes([byte_val]))

    print(f"\nCorpus generation complete.")
    print(f"Total cases: {len(list(corpus_dir.glob('*.bin')))}")


def main():
    ap = argparse.ArgumentParser(description="Generate OSFF M1 fuzz corpus")
    ap.add_argument("--output", default=str(CORPUS_DIR),
                    help=f"Output directory (default: {CORPUS_DIR})")
    args = ap.parse_args()
    generate_corpus(Path(args.output))


if __name__ == "__main__":
    main()
