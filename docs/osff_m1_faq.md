# Sentinel OSFF M1 — Reviewer FAQ

Anticipated reviewer questions and prepared answers for the M1 submission.
Use these verbatim or as drafts for email replies.

---

## Q1: If wedge_count = 0 for the safe parser, what exactly does the harness prove?

`wedge_count = 0` means the reference parser successfully recovers to a functional
IDLE state after every malformed input in the corpus. The harness injects a valid
heartbeat frame after each fuzz case — after a parser reset — and the parser must
accept that heartbeat to pass the trial. If malformed input corrupts the parser state
machine or leaves it partially wedged, the heartbeat will fail even after reset and
the harness records a wedge event. Therefore a zero wedge count demonstrates
successful recovery from malformed traffic, not merely that the parser avoided crashing.

---

## Q2: The latency metrics come from Python — how meaningful are they?

The reported latency values are explicitly labeled `harness_roundtrip` latency and
represent the round-trip timing observed by the fuzz harness, not device-level
execution latency. They include Python dispatch and OS scheduling overhead and are
provided only as distributional stability metrics (p50/p95/p99) for the harness
itself. The validator enforces ordering and non-negative constraints on these values
but they are not used to claim real-time performance of the parser. Device-level
timing analysis is intentionally out of scope for Milestone 1 and will be addressed
in later milestones.

---

## Q3: Why is this open source?

Open-source publication is the contribution mechanism OSFF funds. Beyond grant
compliance, publishing the harness, corpus generator, and schema validator means
the safety tooling can be adopted, audited, and improved by other embedded systems
developers facing the same class of parser wedge problems. The correctness properties
the harness enforces — bounded recovery, heartbeat acceptance after reset — are
general enough to apply to any UART-framed protocol parser, not just this one.
Publishing the methodology rather than just the result ensures the firmware ecosystem gains a reusable testing framework for parser robustness, not just a one-off implementation.

---

## Supporting Evidence Locations

| Question | Evidence location |
|---|---|
| wedge_count=0 interpretation | README "Verification Notes" → "What wedge_count=0 proves" |
| Defect detection demonstration | `evidence/EP-*-m1.json` → `per_case_results.zero_length_valid_chk` |
| Latency scope disclaimer | Evidence JSON `latency_scope: "harness_roundtrip"` |
| Reproducibility | `docker compose run sentinel-m1` → same artifact every run |
| Locked constants | `docs/wedge_definition.md` + validator hard errors on deviation |
