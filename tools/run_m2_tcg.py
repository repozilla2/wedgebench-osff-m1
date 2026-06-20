from __future__ import annotations

import json
from pathlib import Path

try:
    from .check_m2_environment import inspect_environment, print_errors
    from .tcg_adapter import TCGAdapter
except ImportError:
    from check_m2_environment import inspect_environment, print_errors
    from tcg_adapter import TCGAdapter


def main(
    *,
    repo_root: Path | None = None,
    adapter_factory=TCGAdapter,
    environment_inspector=inspect_environment,
) -> int:
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]

    inspection = environment_inspector(repo_root)
    if inspection.errors:
        print_errors(inspection.errors)
        return 1
    assert inspection.provenance is not None

    corpus_dir = repo_root / "corpus"
    evidence_dir = repo_root / "evidence" / "m2"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    adapter = adapter_factory()
    cases = sorted(corpus_dir.glob("*.bin"))

    results = []
    for case_path in cases:
        data = case_path.read_bytes()
        adapter.reset()
        result = adapter.feed(data)
        heartbeat_ok = adapter.inject_heartbeat()

        wedge_type = None
        if not heartbeat_ok:
            wedge_type = "wedge_no_heartbeat"

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
            "wedge": wedge_type is not None,
            "wedge_type": wedge_type,
        })

    artifact = {
        "schema_version": "m2-draft",
        "milestone": "M2",
        "artifact_type": "tcg_storage_adapter_draft",
        "target": "go-tcg-storage",
        "upstream_repository": inspection.provenance.upstream_repository,
        "upstream_commit": inspection.provenance.upstream_commit,
        "adapter": "tcg_adapter",
        "parser_under_test": "semantic_adapter",
        "trial_count": len(results),
        "source_evidence": "evidence/EP-20260511-m1-docker-local.json",
        "claim_scope": (
            "Semantic outcome taxonomy and draft TCG adapter mapping only; "
            "not physical-device timing, exploit discovery, formal safety proof, "
            "or production firmware validation."
        ),
        "latency_note": (
            "Per-case latency_us is host adapter runtime and may vary between runs; "
            "it is not used as a deterministic M2 evidence claim."
        ),
        "results": results,
    }

    out_path = evidence_dir / "EP-M2-go-tcg-storage-draft.json"
    out_path.write_text(json.dumps(artifact, indent=2) + "\n")

    print(f"Wrote {out_path}")
    print(f"trial_count={len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
