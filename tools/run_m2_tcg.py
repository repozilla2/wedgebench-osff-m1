from __future__ import annotations

import json
from pathlib import Path

from tcg_adapter import TCGAdapter


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    corpus_dir = repo_root / "corpus"
    evidence_dir = repo_root / "evidence" / "m2"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    adapter = TCGAdapter()
    cases = sorted(corpus_dir.glob("*.bin"))

    results = []
    for case_path in cases:
        data = case_path.read_bytes()
        adapter.reset()
        result = adapter.feed(data)
        heartbeat_ok = adapter.inject_heartbeat()

        results.append({
            "case": case_path.stem,
            "ok": result.ok,
            "error": result.error,
            "response_len": result.response_len,
            "frames_accepted": result.frames_accepted,
            "output_bytes": result.output_bytes,
            "progress": result.progress,
            "latency_us": result.latency_us,
            "parser_outcome": result.parser_outcome,
            "heartbeat_ok": heartbeat_ok,
        })

    artifact = {
        "schema_version": "m2-draft",
        "target": "go-tcg-storage",
        "adapter": "tcg_adapter",
        "trial_count": len(results),
        "results": results,
    }

    out_path = evidence_dir / "EP-M2-go-tcg-storage-draft.json"
    out_path.write_text(json.dumps(artifact, indent=2) + "\n")

    print(f"Wrote {out_path}")
    print(f"trial_count={len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
