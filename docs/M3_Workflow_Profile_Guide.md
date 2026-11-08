# M3 workflow profile

The candidate `m3-demo-workflow-v1` profile checks the completeness and
consistency of the five stages recorded by `tools/run_m3_demo.py`. Its policy
is versioned in `profiles/m3-demo-workflow-v1.json`. The checker reuses
`tools.verify_event_log.verify` for event integrity and referenced-artifact
hash verification.

## Run the illustrative demonstration

From the repository root, with Python 3.10 or later, run

```bash
python3 tools/demo_m3_workflow.py
```

The demonstration loads the existing fixed M3 example and constructs
additional controls in memory. It produces deterministic JSON. The complete
failure control is resealed with the existing event-hashing function, so it
exercises workflow interpretation with a valid hash chain.

| Control | Integrity | Profile completeness | Recorded outcome | Test execution |
| --- | --- | --- | --- | --- |
| Intact illustrative fixture | pass | complete | succeeded | skipped |
| Fixture with its terminal event removed | pass | incomplete | indeterminate | unverified |
| Complete record of generation failure and subsequent validation skip | pass | complete | failed | skipped |
| Edited completion flag with its original hash | fail | unverified | indeterminate | unverified |

The demonstration exits `0` when every control produces its expected result.
Each control remains illustrative fixture data. The demonstration's successful
exit means that its expected distinctions were reproduced.

## Check a selected log

```bash
python3 tools/verify_m3_workflow.py examples/m3/WBLOG-M3-example.jsonl
```

The JSON result includes the profile ID and the SHA-256 of the exact manifest
bytes used. A reviewer can supply a previously retained profile digest

```bash
python3 tools/verify_m3_workflow.py examples/m3/WBLOG-M3-example.jsonl \
  --profile-id m3-demo-workflow-v1 \
  --expected-profile-sha256 <retained-profile-sha256>
```

The manifest is a bundled trusted policy. Its digest identifies the policy
used. An independently retained digest and source revision provide the
reference against which a later copy can be checked.

## Required records

The profile requires these events exactly once, in this order, starting with
sequence zero and a nonempty run ID

1. `run_started`
2. `m2_evidence_generated`
3. `m2_evidence_validated`
4. `tests_skipped`
5. `run_completed`

Payload fields and their types are declared in the manifest. Boolean claims
require actual booleans, and the emitted-event count requires an integer.
Additional payload or top-level claim fields fall outside this profile.

Generation and validation must refer to the artifact declared at run start.
A successful stage requires a digest and a null error. A failed stage requires
a nonempty error string. Supplied generation and validation digests must agree.
Validation success requires generation success, its two success flags must
agree, and the terminal outcome must match both stage outcomes. The terminal
event count must match the required profile.

A valid prefix is incomplete. Missing, duplicated, reordered or substituted
stages cannot satisfy the complete profile. A referenced artifact that is
unavailable produces an incomplete result even when generic integrity
verification reports only a warning. A complete and consistent failure record
has completeness `complete` and recorded outcome `failed`.

## Result and exit interpretation

| Result | Meaning |
| --- | --- |
| `integrity.status` | Outcome of the existing generic verifier, with its errors and warnings |
| `profile_completeness` | `complete`, `incomplete`, `invalid` or `unverified` for the selected recorded-stage contract |
| `recorded_workflow_outcome` | Consistent recorded success or failure, or `indeterminate` when the required evidence checks cannot be completed |
| `test_execution` | `skipped` for a conforming record, otherwise `unverified` |

The individual-log checker exits `0` for complete, consistent recorded success.
It exits `1` for recorded workflow failure, incomplete or invalid records,
integrity failure or malformed log JSON. It exits `2` for usage, file-access or
profile-selection errors. A complete failed workflow therefore retains its
`complete` classification while the individual-log command exits `1`.

## Evidence scope

This profile evaluates the supplied records and available referenced-file
hashes. Its completeness claim covers the five recorded workflow stages.
Required corpus-case accounting and M2 artifact semantic validation require
their own checks. The `tests_skipped` stage reports the test suite as skipped
within this workflow. The profile's own regression tests run separately.

Execution authenticity, producer identity, trusted time, hardware behavior and
physical recovery require additional evidence. A producer able to rewrite and
rehash records can construct a new consistent complete log. File handling,
artifact-size limits and relative-path interpretation follow the existing M3
verifier. Relative artifact paths are interpreted from the working directory.

## Regression checks

```bash
python3 -m pytest -q tests/test_verify_m3_workflow.py
```

These controls run with the committed fixtures and Python. The complete
repository suite also exercises live M2/M3 generation and requires the Go
toolchain and pinned sibling checkout documented in the M3 event-log guide.

[M3 Event Log Verification Guide](M3_Event_Log_Verification_Guide.md)
