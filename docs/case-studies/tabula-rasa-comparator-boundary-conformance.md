# Applying WedgeBench's verification method to Tabula Rasa's comparator

*10 November 2026 — internal method-transfer case study*

Kaimera adapted WedgeBench's deterministic verification method to repair malformed-output handling in Tabula Rasa, a proposed study of language-model extraction and scope binding. Four synthetic before/after cases showed the revised comparator following its intended rejection policy. A local development receipt recorded 48 test methods passing. A subsequent three-model design review supported the boundary repair and its description as method transfer, while identifying unresolved semantic and measurement issues. **The extraction experiment has not run.**

This was a new Python test implementation inspired by WedgeBench. It did not integrate WedgeBench's C parser, firmware harness, evidence validators or event-log tooling. It follows the same kind of internal method reuse described in the [SpecGuard case study](specguard-saas-boundary-conformance.md).

## The problem being repaired

The proposed study compares a model's raw extraction with a deterministic reference parser and two processing steps: structural validation, called A, and a parser-based filter, called G. The task asks what a dated notice does to an exact named object. Correctly interpreting the notice is a separate problem from correctly handling malformed model output.

Council review of version 2.2 found that row identity was counted **after** row-shape validation. A malformed row could therefore disappear from the duplicate check. Error storage was keyed by target ID and replaced earlier errors, so a later valid-looking duplicate could overwrite a malformed row's error. An anonymous extra row could leave an error that did not cause the whole notice to be rejected. Conversely, a single malformed row with a recognizable target ID could be treated as a missing target, rejecting the whole notice rather than isolating that row.

These were review findings first. WedgeBench's contribution was a way to turn the repair requirements into repeatable verification evidence, not a claim that its existing firmware tools discovered or automatically repaired the defects.

## What carried over from WedgeBench

The [WedgeBench workflow](../../README.md) uses fixed malformed inputs, explicit expected behavior and structured observations. Tabula Rasa adapted that pattern to structured extraction output:

| WedgeBench method | Tabula Rasa adaptation |
| --- | --- |
| Fixed malformed-input corpus | Synthetic missing-field, duplicate-ID, anonymous-row and wrong-type mutations |
| Explicit failure conditions | Notice rejection for ambiguous identity; local rejection for one uniquely identified malformed row |
| Observable behavior | Notice processability, row dispositions, retained errors and original-input preservation |
| Repeatable verification | Python unit tests and a four-case replay record |
| Evidence artifacts | Test IDs, observed outcomes and hashes identifying the reviewed files |

The implementation now counts string target IDs before validating the rest of each row, accumulates errors instead of overwriting them, and retains an audit entry for each original row index. The filter rejects notices with missing, duplicate, unknown or unidentified targets before building its target lookup. A uniquely identified malformed row can be rejected locally while other rows remain processable.

The distinction matters: a processable notice does **not** mean that every row was accepted or that any answer is semantically correct.

## Recorded results

The [supporting evidence](tabula-rasa-v2.3-boundary-evidence.json) contains the synthetic inputs, recorded before/after outcomes, development receipt, source hashes and comparator diff.

| Synthetic case | Recorded v2.2 behavior | Recorded v2.3 behavior |
| --- | --- | --- |
| Malformed row followed by a valid-looking row with the same ID | Notice processed despite duplicate identity | Notice rejected |
| Valid-looking row followed by a malformed duplicate | Notice processed rather than rejected as a duplicate | Notice rejected |
| Valid row plus an anonymous extra row | Notice processed despite unidentified content | Notice rejected |
| One malformed row with a unique known ID | Whole notice rejected | Notice processable; malformed row locally rejected |

The fourth change is deliberately more selective rejection. It aligns implementation with the intended local-error policy; it does not turn the malformed row into a valid answer.

The local receipt reports **48 test methods passed, zero failures, zero errors and zero skips**: 38 existing comparator tests and 10 boundary-test methods. Several methods contain multiple mutations. These are regression and development checks, not 48 independent real-world evaluation cases.

The evidence has specific limits. The four-case replay script checks the top-level processability boolean. Separate boundary tests check selected row errors, original preservation, isolation of an unaffected target and successful processing after a bad call. The 42 field-type mutation subtests check determinism and non-mutation but do not specify an expected acceptance or rejection verdict for every mutation. A stronger next version should add those verdict oracles and replay the complete audit/output record.

## What the follow-up Council review changed

OpenAI, Claude and Gemini reviewed v2.3. Router context limits required separate engineering and protocol passes. Claude's first engineering API response hit its output limit; its missing review was recovered in a fresh included chat, using a different displayed model revision and no peer verdicts. The completed reviews were collected before the combined assessment. This was internal, model-assisted static review—not independent human qualification or a uniform model benchmark.

The reviewers supported the row-handling repair and the bounded WedgeBench framing. They did not unanimously approve the broader design. OpenAI and the recovered Claude review recommended **revise before experiment**; Gemini supported proceeding to admission checks with conditions. The protocol router also retained disagreement: Claude and Gemini supported conditional admission work, while OpenAI wanted clarifications completed first.

The combined disposition remains **revise before experiment**. The outstanding work includes:

- **Semantic binding:** static code traces indicate that a proposal frame does not govern all passive sentences, historical wording can be treated as a current action, and a request word elsewhere in a sentence can change the inferred disposition. These patterns were identified by inspection, not measured on evaluation notices.
- **Measurement rules:** explicitly distinguish whole-notice processability from structural validity, decide which citation and schema errors exclude an answer from the primary endpoint, and define the structural-validation arm's scored output.
- **Audit and masking:** preserve the distinction between structural rejection and abstention, and specify how model explanations and malformed but readable claims receive a provider-blinded audit.
- **Qualification and selection:** complete independent controls, human annotation, model/context checks and prospective selection. Retire previously exposed examples and disclose table/image exclusions as limitations of the study's scope.

These concerns do not erase the four demonstrated boundary improvements. They prevent those improvements from being presented as validation of the entire comparator or extraction study.

## What this case establishes—and what it does not

This case documents an internal transfer of a verification method from firmware-related work to an AI evaluation tool. The useful result is a traceable connection between a failure policy, specific malformed inputs, a small code repair and recorded behavior.

The public evidence is publisher-produced. It is not signed attestation, third-party replay, a WedgeBench-schema validation result or a complete executable distribution of the comparator. Hashes identify files; they do not prove correctness. The published synthetic records make the reported observations inspectable, while independent execution still requires the corresponding implementation and test artifacts.

No exhaustive fuzzing, resource-safety proof, improvement in model extraction accuracy, production reliability rate or financial saving was measured. The sealed confirmation cases were not opened or published. Development verification used synthetic fixtures; the later paid Council review assessed the design and did not execute the extraction experiment.
