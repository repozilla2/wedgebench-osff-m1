# Applying WedgeBench's verification method to Tabula Rasa through v2.10

*Updated 10 November 2026 — internal method-transfer case study*

WedgeBench's testing method helped Kaimera turn malformed-input and parser findings into explicit failure policies, fixed synthetic inputs, expected outcomes and preserved observations. The work progressed from row-identity repairs in v2.3 to context-preserving parsing, a human-assisted review gate, stricter grading, and durable acceptance protections through v2.10. **It did not establish that the parser understands arbitrary prose or that a language model extracts more accurately. The extraction experiment has not run.**

This was a new Python implementation inspired by WedgeBench's verification approach. It did not import WedgeBench's C parser, firmware harness, event-log tools or evidence validators. The method transfer resembles the [SpecGuard case study](specguard-saas-boundary-conformance.md): specify a boundary, mutate inputs, preserve the original, and compare observed behavior with an explicit oracle.

The original [v2.3 evidence](tabula-rasa-v2.3-boundary-evidence.json) remains available. The new [through-v2.10 evidence supplement](tabula-rasa-v2.10-method-transfer-evidence.json) contains versioned repair ledgers, development receipts and test IDs, complete synthetic replay observations, and the later mechanical qualification results. These are publisher-produced records, not independent semantic certification or a complete executable distribution.

## 1. Malformed inputs: repair identity and preserve every error

In v2.2, row identity was counted after row-shape validation. A malformed row could disappear from duplicate detection. Errors keyed only by target ID could overwrite earlier errors, and an anonymous extra row did not reliably make the notice unprocessable. Conversely, a malformed row with one recognizable ID could be mistaken for a missing target and reject an otherwise processable notice.

The v2.3 repair counts string target IDs before validating the rest of each row, accumulates errors and retains an audit entry for each original row index. Missing, duplicate, unknown or unidentified targets cause notice rejection before target lookup. A uniquely identified malformed row can be rejected locally without erasing the other rows.

| Recorded synthetic input | v2.2 behavior | v2.3 repair |
| --- | --- | --- |
| Malformed row, then valid-looking duplicate ID | Notice remained processable | Notice rejected |
| Valid-looking row, then malformed duplicate ID | Duplicate not rejected at notice level | Notice rejected |
| Valid row plus anonymous extra | Notice remained processable | Notice rejected |
| One malformed row with a unique known ID | Whole notice rejected | Notice processable; malformed row rejected locally |

“Processable” never meant semantically correct. Later versions made the distinction more explicit: a local schema error can still exclude the whole raw notice from the primary semantic endpoint even when another row remains mechanically processable.

The v2.3 receipt recorded 48 test methods passing. Its four-case replay checked only the top-level processability Boolean; the 42 field-type mutation subtests established determinism and non-mutation without a verdict oracle for every mutation. **v2.4 strengthened this evidence** with explicit mutation verdicts and complete boundary-record replay, rather than presenting those earlier checks as exhaustive validation.

## 2. Parser repairs: a useful progression, not a solved semantics problem

### v2.4: narrow the supported grammar and clarify scoring

The parser introduced a narrow present-action grammar, applied proposal framing across recognized modes, and required original-frame coverage. Supported issuer requests were distinguished from outside-party statements; unsupported historical, passive or ambiguous forms could abstain. Tests exercised proposal modes, wrapped actions, lists, clipped qualifiers, genuine but irrelevant citations, scope and issuer distinctions.

The same revision separated envelope identity, typed schema, contract and evidence errors. It made the structural-validation output explicit, gave rejected records a null status rather than disguising them as abstention, and preserved indexed anonymous-row audits. Label-set membership remained only one scoring dimension: scope, authority and evidence still required separate assessment. Typed citation defects were not allowed to conceal otherwise scoreable unsupported raw claims.

### v2.5: keep governing context across paragraphs

Review identified dropped quotations and conditions outside the immediate action paragraph. The repair checked every substantive notice block against a closed grammar. Unknown context before or after an action, intervening prose, colon-free qualifications and dangling list headers caused abstention; unknown material remained in the evidence.

That was conservative but impractical: harmless background and undeclared list items could also force abstention. Passing rejection tests did not demonstrate useful coverage. This tradeoff motivated v2.6 rather than being reported as a complete parser fix.

### v2.6: section-aware parsing and a concrete list-binding repair

Document-wide unknown-prose rejection was replaced with explicit field/section recognition and retained-context screening. The supported forms included adjacent headers, wrapped action text, neutral administrative/background fields and exact summary actions. Structured commitments required complete-document evidence.

A shared document analysis also fixed a reproduced alias/scope collision: text naming another target in an item's scope no longer disabled list inheritance. In the synthetic Section 1 / Part 2 example, the item received the withdrawal while Part 2 remained an abstention. This repaired a false abstention without incorrectly withdrawing the parent.

The revision improved practicality, but whole-document quotation did not prove that every governing statement had been understood. Context screening was still heuristic. The evidence supplement retains the structured-context and related replay records; these remain development examples, not measurements of real-notice coverage.

### v2.7: retain the known parser error and gate its promotion

A synthetic notice explicitly described an operative-looking paragraph as a litigant's demand. The v2.6-style parser could still propose that paragraph as an issuer withdrawal. Adding more warning words would not establish general authority interpretation.

The response was an architectural change, **not a claim that the unsafe parse had been corrected**. The lexical parser became `D0`, a diagnostic candidate generator. Public comparison became `D_R`, a human-context-review-assisted reference. It withholds a commitment unless exactly two authenticated independent context-review records support authority, operative force, exact scope, governing context and operative corroboration on the bound source/candidate.

Missing, uncertain, contradictory, stale, forged, duplicate or otherwise invalid reviews withhold the commitment. Summary-only support is insufficient: operative corroboration must cover a matching non-summary action. The safeguard `G` requires agreement with this assisted reference and coverage of its reviewed premises. Its verdict is `context_attested`, not “verified truth.”

This contains an unsafe candidate at the public commitment boundary under the tested conditions. It does not make D0 semantically sound, recover actions D0 never proposes, or protect against two authenticated reviewers making the same substantive mistake. Registry groups represent independence only if the organizer verifies real identities and conflicts. Synthetic signatures are not human evidence.

## 3. Transport, presentation and grading: avoid misleading results

The later work addressed failures around the parser as well as within it:

| Issue | Recorded repair through v2.10 | Limit |
| --- | --- | --- |
| Wrong-notice or invalid responses shown as ordinary answers | Integrity-checked prepared records; transport/envelope failures suppress answers while preserving diagnostics | Does not establish source truth |
| A top-level empty audit conceals a failure | Organizer records retain transport, structural, filter and eligibility details | Organizer records are not grader payloads |
| Different or modified raw responses feed different arms | A/G derive from the same saved S; altered diagnostics and mismatched source/completion states reject | Raw S remains the unchanged primary endpoint |
| Duplicate JSON keys and non-JSON constants | Saved-text decoder rejects them and respects incomplete transport | Live wire-byte collection/completion attestation remains unimplemented |
| Lone Unicode surrogates cause encoding errors | Saved text is retained; surrogate-aware hashing is deterministic; literal/decoded lone surrogates produce explicit transport failure | Saved-text digest is not a wire-byte digest |
| Rejection confused with model abstention | Schema/filter rejects display no answer; genuine abstentions remain abstentions; internal causes remain distinct | Coverage losses must still be reported |
| Date and label rules drift | Dates excluded from semantic endpoint; null/string schema, non-null strings are contract defects, other types schema failures; label membership separated from outcome categories | Prospective policy changes, not retroactive improvement claims |
| Arm identity/multiplicity reveals answer origin | Identical answers deduplicated per notice/target, shuffled per grader, arm/count metadata omitted; private propagation retains original denominators | Actual blinding effectiveness is unmeasured |
| Incomplete grades or altered propagation maps accepted | Whole-bundle binding and upstream invariants; separate complete status-appropriate judgments and required notes | Hashes cannot authenticate fabricated original construction |

Some review allegations were not reproduced. The v2.5 ledger does not claim that hypothetical quote-splicing or helper slash/colon matching was a proven full-parser failure. Likewise, v2.8's stricter nonfinite metadata handling is hardening, not confirmation of an alleged universal NaN bypass. A finding, a reproduced defect and a proposed risk are different evidence categories.

## 4. Approval and durable storage: extending the mutation method

These were integrity fixes around the evaluation workflow, not parser accuracy improvements.

**v2.8** bound contextual review to exact release bytes and bound grading to the full predispatch bundle, including source, answers, mappings, eligibility and reviewer assignment. Incomplete substantive grades and inconsistent D_R/G review records were rejected. Subsequent review showed that a documented external pin and a successful validation result were not sufficient implementation guarantees.

**v2.9** added explicit approval-pin enforcement and durable grade acceptance. No default local digest silently creates approval. Pure validation reports `primary_locked=False`; durable acceptance uses an organizer-owned SQLite ledger, one registered batch/manifest and a transactional acceptance record. The receipt binds the release, manifest, exact grade set and validated result. Replay fails; a lost response is recovered by reading the original receipt. Separate processes and competing submissions are covered by the tested store behavior.

**v2.10** closed a concrete ordinary-SQL replacement bypass. With recursive triggers off, `INSERT OR REPLACE` could overwrite protected records despite delete-trigger protections. New BEFORE INSERT guards reject existing identities and manifest conflicts before conflict resolution. WITHOUT ROWID tables remove implicit rowid aliases; non-null keys, update/delete guards and format-210 checks complete the stated protection. Multirow rejection rolls back that statement, not unrelated earlier successful statements in the transaction.

These protections assume intact schema and enforcement. They do not withstand privileged trigger removal, database-file replacement or rollback, or authenticate newly fabricated nonconflicting direct-SQL rows. Production permissions, external receipts, approved deployment and actual reviewer roles remain necessary.

## 5. Evidence and what the counts mean

| Evidence layer | Recorded result | What it supports |
| --- | --- | --- |
| v2.3 author development | 48 test methods passed; four boundary before/after observations | Specific row-handling repairs, with the original oracle limitations |
| v2.10 author development | 141 test methods passed; zero failures/errors/skips; 38 serialized synthetic replay controls | Regression behavior under fixed development inputs |
| v2.10 scoped mechanical qualification | 125 checks passed on Python 3.15.2 / SQLite 3.54.1 and 125 on Python 3.9.6 / SQLite 3.54.0 | Replacement, approval and acceptance mechanics on two runtimes on the same Mac |
| Independent semantic development qualification | Not performed | No semantic coverage or automated-baseline adequacy claim |

The counts overlap across versions and include subcases; they are not independent real-world notices. Of the 38 v2.10 replay controls, 32 exercise inherited candidate/boundary/context/presentation behavior and six exercise the context gate and G. Historical lexical tests were explicitly routed to candidate diagnostics after the architecture changed; they must not be advertised as tests of the new assisted G. Fixture authentication bindings were renewed for the release, with the synthetic judgments still public test data.

The scoped qualification plan was designed in separate OpenAI, Claude and Gemini sessions from the contract/interfaces, without implementation or author-test results. The plan and new harness were frozen before execution. **The original implementation assistant implemented and ran that harness**: test-design separation was achieved, but independent human/operator qualification was not.

Its checks included competing processes, restart recovery, interruption before and after commit, invalid-grade rollback, unsupported-format refusal and unchanged receipts after replacement attempts. A temporary negative control deliberately removed a guard and detected replacement. Another documented the excluded ability to insert a new fabricated raw record. Process termination is not a power-loss or filesystem-corruption test. The two runtime runs are 250 check executions, not 250 distinct tests or semantic cases.

The tested release fingerprint is `d7e5655ca61edb4eb13455cc7e539d1035731597bb9c405f5ff885fa119b97fb`. Source and harness hashes identify the evidence; they do not prove correctness. The supplement preserves all 38 full replay observations and complete mechanical check results, but is not a runnable distribution. No tests were rerun to prepare this publication.

## 6. Current limits and next step

The v2.10 Council review supported advancing to scoped mechanical qualification with conditions. That review did not certify semantic parsing, production deployment or experiment readiness. The subsequent mechanical passes do not close those broader gates.

The next preparation package defines at least 20 answerable and 20 adversarial development controls, retaining the proposed >=80% supported coverage/retention and zero-false-commitment conditions. Its 40 slots are empty: independent qualified participants still need to author, annotate, lock and evaluate the controls. The metric definitions require independent pre-execution acceptance. Those are preparation criteria, not achieved results.

D0 is not a qualified automated semantic baseline. D_R/G are assisted secondary analyses, and raw S is judged against separate human gold. A successful assisted workflow cannot silently clear the automated-baseline requirement. That question requires independent evidence or an explicitly reviewed narrower study design.

Remaining gates include human qualification and role separation, full source sufficiency, prospective fresh case selection, exact model/context and protocol freeze, live transport collection, masking, production key/storage/approval controls, verified experiment funding and separate owner execution approval. No model-extraction improvement, learned-memory evidence, financial saving, production reliability rate or exhaustive fuzzing result has been measured.

**Confirmation cases remained sealed and were not opened, hashed, copied or published. No extraction experiment ran.** The contribution documented here is a traceable testing method—and the discipline to distinguish a repaired boundary, a still-unsafe parser candidate, an assisted safeguard and an unproven scientific claim.
