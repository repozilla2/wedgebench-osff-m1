# Phase 3 conformance requirements

Candidate requirements dated 5 November 2026. These acceptance criteria guide the next authorized contract-extraction work. For each criterion, record applicability to the selected profile and declared claims, the rationale, implementation status and execution evidence against a selected revision.

## Objective and inputs

Extract the smallest versioned contract demonstrated by already working integrations selected for review. The contract describes the target, adapter, required test manifest, observations, evidence validation and replay procedure. The firmware reference profiles provide the implementation evidence. The SpecGuard internal method-transfer case supplies candidate requirements for an applicable software profile.

If a software profile is selected for a future integration, its qualification and authorized scope should include an assessment of how the project-specific runtime drivers and checks can use the shared WedgeBench runner, evidence format and verifier. That assessment records reused components, required changes and delivery effort.

## Acceptance backlog

| ID | Required behavior | Demonstration |
| --- | --- | --- |
| C01 | For profiles declaring semantic equivalence, compare the promised result | For findings-equivalence claims, compare normalized finding identities and content. Use a negative fixture with equal counts and different findings. Document permitted variation. |
| C02 | For profiles declaring transformation preservation, check every claimed implementation path | Inspect the actual transformed output returned by each claimed runtime and access path. Verify every protected field and the permitted changes. The shared-anchor environment case in the SpecGuard study is a candidate example for an applicable software profile. |
| C03 | Exercise valid acceptance and invalid rejection | Assert the expected accepted output for a valid control before applying deletion or corruption mutations. A deliberately always-rejecting implementation must fail conformance. |
| C04 | Bind execution accounting to a versioned manifest | Identify required cases and expectation references in a digest-bound manifest. Delete a required result and reduce its reported count. The checker must report incomplete execution against the manifest. |
| C05 | Bound execution and fixture resources | Specify subprocess, request and fixture-lifetime limits. Test termination and cleanup. Record whether all planned observations were collected and evaluate each timeout under the declared claim policy. |
| C06 | Challenge the candidate with independently selected cases | A named reviewer selects cases after the candidate behavior is documented. Record the initial outcome and revision. Retain accepted counterexamples as regression fixtures and record the outcome after correction. |
| C07 | Make unsupported or mismatched claims detectable | Exercise missing observations, malformed output, mismatched target profiles and mislabeled lifecycle behavior. Each claim must identify its required observations and expectation version. |

## Evidence interpretation

The candidate profile records the five dimensions defined in the roadmap.

- Artifact validation reports structural and internal-consistency checks.
- Execution completeness accounts for required manifest cases.
- Behavioral expectations report met, unmet, inconclusive or unexecuted claims.
- Independent replay records reproduced, contradicted or blocked attempts and the assistance received.
- Provenance records the available references, verification policy and outcome.

A release decision identifies its policy, evaluated claims and unevaluated dimensions. Lifecycle claims identify clean-start acceptance, operation after an explicit reset, or recovery in the same running instance. The adapter must collect the observations required by the selected lifecycle claim.

## Review and handoff

Complete contract extraction against the selected acceptance criteria, with external-review costs explicitly scoped. Record the candidate profile, execution evidence, completed criteria, open requirements and the remaining work at each review. Progress to the next decision when its evidence and review requirements are met.

The handoff exercise requires an engineer outside the implementation effort to make a meaningful integration change using the published contract and tests. Record the selected revision, task, documentation used, time, assistance and result. Address material handoff failures before promoting the candidate to a stable contract.

## Source case

The case study pins its initial observations to SpecGuard revision `296db2a1fe194b845abddb0826f7290521eeb029` and adds a dated PR #63 follow-up at `4fe668cb20e5d165043a100d1e5f153861cb4648`. Each observation retains its source-review and execution scope.

[Applying WedgeBench's firmware verification method to SpecGuard](case-studies/specguard-saas-boundary-conformance.md)
