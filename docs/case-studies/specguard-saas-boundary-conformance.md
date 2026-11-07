# Applying WedgeBench's firmware verification method to SpecGuard

Repeated review of Kaimera's SpecGuard tool uncovered related defects. A Docker Compose image update could change text that only looked like an image declaration. Missing fields in a simulated payment response raised a different question about when to unlock paid output. After eight pull requests, Kaimera adapted the verification method it had developed for the OSFF-supported WedgeBench project. SpecGuard implements its own test harness.

The initial case below describes SpecGuard revision `296db2a1fe194b845abddb0826f7290521eeb029`. Kaimera conducted the source review and follow-up local checks. The dated PR #63 section records the later revision separately.

## What the tests measure

At SpecGuard commit `296db2a`, two test functions exercise 38 hand-selected cases.

| Case set | Check |
| --- | --- |
| 20 Compose inputs | Compare the Python and Node implementations' original and remediated risk scores, grade, and number of findings. For inputs Python accepts, use PyYAML to compare the values of existing service fields other than `image` before and after Python remediation. |
| 18 mutations of a simulated Stripe payment flow | Remove or alter selected evidence in an otherwise working payment fixture. Check that the Python verifier rejects the key, the Node claim handler denies or defers the claim, and the Node audit handler keeps paid output locked. |

Kaimera reported 68 tests passing in 5.50 seconds in its local full-suite run, with zero Netlify deployment credits used during that run. Kaimera's 5 November review record describes a subsequent local rerun of the two conformance functions and a separate check in which the unmodified payment fixture unlocked access on the expected paths. The GitHub Actions quality run for that revision stopped at the workflow lint step because the runner lacked `actionlint`.

## What a follow-up check found

A valid Compose input used a YAML anchor to share a mapping with a service's environment. One environment variable happened to be named `image`. At the reviewed revision, the Node audit handler rewrote that variable's value. Python preserved the original input and classified the proposed change as invalid. The original 20 inputs omitted this pattern. Comparing the returned manifests on the additional input exposed it.

A stronger regression check would include that input, compare the complete findings and the returned YAML from both runtimes, and verify that only the intended service image changes. An independent reviewer could then replay the original failure and the corrected behavior against pinned revisions.

## Follow-up on 6 November 2026 — PR #63

SpecGuard PR #63 merged as revision `4fe668cb20e5d165043a100d1e5f153861cb4648`. Source review and the successful main-branch GitHub Actions run establish the following coverage at that revision. The shared-anchor environment case and a plain-scalar apostrophe case are now included in the Compose corpus. [PR #63](https://github.com/kaimera-group/autonomous-revenue-engine/pull/63)

| Case set | Check at `4fe668c` |
| --- | --- |
| 22 Compose inputs | Require authenticated Node access, compare Python and Node risk scores, grade, findings count and exact returned YAML. For inputs Python accepts, use PyYAML to compare existing non-`image` service values against both Python and paid Node output. |
| 21 mutations of a simulated Stripe payment flow | Apply specified field deletions and value changes to a fixed payment fixture. Check rejection by the Python verifier, denial or deferral by the Node claim handler, and locked output from the Node audit handler. |

These 43 fixture cases run inside two conformance test functions. Separate Compose regressions assert the expected preserved environment-anchor output and the intended service-image update in the apostrophe example. The findings comparison in the conformance test still checks counts. Complete finding-content equivalence remains a candidate requirement. [Conformance tests](https://github.com/kaimera-group/autonomous-revenue-engine/blob/4fe668cb20e5d165043a100d1e5f153861cb4648/tests/test_wedgebench_conformance.py) · [Compose regressions](https://github.com/kaimera-group/autonomous-revenue-engine/blob/4fe668cb20e5d165043a100d1e5f153861cb4648/tests/test_compose_remediator.py)

The main-branch Quality Gate recorded **69 tests passed in 10.86 seconds** with Python 3.12.16 and Node.js 22.23.4. Workflow lint, formatting and strict type checks also passed. The 6.05-second local timing is attributed to the development update supplied by Kaimera. PR #63 reports zero Netlify CLI or build invocations for its implementation session. [Verified CI run](https://github.com/kaimera-group/autonomous-revenue-engine/actions/runs/42275592886)

The Compose corpus is batched into one Node child process. The separate Netlify-function tests assign per-process `TMPDIR` values and exercise valid payment controls, malformed objects and a refunded charge on a second invoice-payment page. The 21-mutation conformance fixture uses an inline payment list and object-ID dispatch. The tests communicate with loopback HTTP mocks, and the CI setup downloads tools and dependencies. [Netlify-function tests](https://github.com/kaimera-group/autonomous-revenue-engine/blob/4fe668cb20e5d165043a100d1e5f153861cb4648/tests/test_netlify_functions.py) · [CI workflow](https://github.com/kaimera-group/autonomous-revenue-engine/blob/4fe668cb20e5d165043a100d1e5f153861cb4648/.github/workflows/quality.yml)

These observations support a broader internal method-transfer case and a concrete regression response. Independent replay, broader target portability, required-case accounting and bounded execution remain subjects for the Phase 3 requirements. The SpecGuard source and CI links require access to its private repository.

## What carried over from firmware

The same team used a fixed set of inputs, specified the behavior each should preserve, and made the observations repeatable in another project. SpecGuard supplied its own fixtures, payment simulator and runtime drivers. This case documents internal reuse of the method. Further validation requires an independently reproduced integration, a documented handoff and repeated external use.

The public firmware workflow and its replay instructions are available in the [WedgeBench repository](../../README.md).

The resulting implementation backlog is recorded in [Phase 3 conformance requirements](../Phase_3_Conformance_Requirements.md).
