# Case Study: Breaking the Multi-LLM Red-Team Loop with WedgeBench

**Project:** Kaimera SpecGuard (`kaimera-group/autonomous-revenue-engine`, commit `296db2a`)  
**Domain:** Cloud-Native B2B SaaS — Multi-Runtime YAML 1.2 AST Remediation & Stateless Payment Entitlement Verification  
**Methodology:** WedgeBench Differential Parser Conformance & Negative-Space Boundary Fuzzing  

---

## 1. Executive Summary

While hardening **Kaimera SpecGuard**—a deterministic B2B Docker Compose supply-chain auditor and stateless entitlement engine—an iterative red-team audit across multiple frontier LLMs (ChatGPT and Claude) spanned eight sequential pull requests (PRs #54–#61). Each time a patch closed a reported vulnerability, the external auditor synthesized a new YAML 1.2 grammar corner case or a truncated upstream Stripe API fixture (`2025-03-31.basil`) that bypassed the point fix.

Applying the **WedgeBench** parser-boundary conformance methodology in PR #62 (`296db2a`) terminated this reactive cycle. By replacing ad-hoc regression tests with a **three-way differential AST oracle (`PyYAML` ↔ Python ↔ Node.js)** and a **systematic negative-space API graph fuzzer**, WedgeBench verified 38 adversarial sub-vectors locally in 5.50 seconds while reducing iterative cloud deployment credit consumption to **0 credits**.

---

## 2. The Problem: Why Traditional Unit Tests Failed Against an Adversarial Reviewer

Standard unit test suites validate *intended inputs* and *known regression fixtures*. An adversarial reviewer, by contrast, searches the **negative space** between a specification and its implementation. Across PRs #54–#61, two structural gaps repeatedly produced new findings:

### A. Cross-Runtime Line-Scanner Drift (The YAML 1.2 Grammar Wedge)
SpecGuard evaluates Docker Compose manifests in both Python (`src/compose_remediator.py`, backing the CLI and Model Context Protocol server) and Node.js (`netlify/functions/audit.js`, backing the serverless web API). Because both implementations initially relied on line-by-line regular expressions and flat boolean state flags rather than a quote-aware tree model, fixing one YAML construct left adjacent grammar rules exposed:

* **Block Scalar Indicators:** Patching basic block scalars (`command: |`) missed indentation and chomping indicators (`command: |2`, `|-`).
* **Doubled Single-Quote Escapes:** Patching quoted multiline strings missed YAML 1.2 doubled single-quote escapes (`'it''s\n image: postgres:latest\n done'`). The quote detector treated the first apostrophe in `''` as a closing quote, causing the remediator to rewrite `postgres:latest` to `postgres:16` inside a shell command.
* **Premature Comment Stripping:** Stripping `#` comments before quote tokenization caused `command: "echo # literal"` to truncate the current line and skip subsequent unhardened services in the same file.
* **YAML Merge Key (`<<: *base`) Override Precedence:** Copying boolean control flags from an anchor failed when a service inherited controls via `<<: *base` and then explicitly overrode them with `restart: 'no'` or replaced `deploy:` with `{ replicas: 1 }`.

### B. Permissive Deserialization at the Payment Trust Boundary (The `2025-03-31.basil` API Wedge)
SpecGuard's stateless HMAC-SHA256 license verifier queries Stripe (`2025-03-31.basil`) to confirm that an entitlement's underlying subscription, invoice, payment intent, and charge remain active and unrefunded. Because the verifier used defensive fallback defaults (`status || "succeeded"`, `currency || "usd"`, optional `if (price)` checks, and a branch that authorized `PaymentIntent` objects lacking a charge reference), the external reviewer was able to craft stripped mock responses (`{"id": "pi_good"}`, `{"id": "ch_good"}`, or a `SubscriptionItem` with its `price` object deleted) that failed open and unlocked paid output.

---

## 3. How WedgeBench Solved the Problem

Originally developed to expose parser-boundary differentials in embedded firmware (presented at OSFC 2026), **WedgeBench** enforces a strict engineering invariant: *never trust a hand-rolled parser or trust-boundary validator unless it is continuously fuzz-tested against a canonical AST oracle and systematic field-deletion mutations.*

In PR #62 (`296db2a`), we embedded a WedgeBench conformance harness (`tests/test_wedgebench_conformance.py`) directly into SpecGuard's deterministic quality gate (`make quality`):

### 1. Three-Way Differential AST Oracle (`PyYAML` ↔ Python Engine ↔ Node.js Engine)
* **Cross-Runtime Equivalence:** WedgeBench feeds a 20-vector corpus of adversarial YAML 1.2 constructs (doubled `''` escapes, `#` inside double quotes, `|2-` chomped block scalars, `<<: *base` merges with negative overrides, `${VAR:-default}` interpolations, unquoted `: ` plain scalar continuations, flow `{}` mappings, and nested duplicate keys) into both the Python engine and an isolated Node.js subprocess, asserting 100% parity on `original_risk_score`, `remediated_risk_score`, `grade`, and `findings`.
* **Non-Target Semantic Invariance:** For every accepted manifest, WedgeBench parses both the original YAML and the remediated YAML through a canonical YAML 1.2 parser (`yaml.safe_load`) and enforces the invariant:

    For every service S and every key K != "image":
        AST_remediated[S][K] == AST_original[S][K]

  If a line editor ever mutates a `command:`, `entrypoint:`, or `environment:` value that happens to contain `image: postgres:latest`, the AST diff detects the semantic drift immediately and fails closed.

### 2. Systematic Field-Deletion & Negative-Space Boundary Fuzzing
* Instead of testing only well-formed Stripe mocks, WedgeBench starts from a valid 5-node `2025-03-31.basil` entitlement graph (`CheckoutSession` -> `Subscription` -> `SubscriptionItem.price` -> `Invoice` -> paginated `InvoicePayment` -> `PaymentIntent` -> `Charge`) and executes 18 targeted field deletions and type corruptions:
  * `missing_price_obj`, `missing_price_id`, `missing_price_currency`, `non_usd_price`, `missing_unit_amount`, `low_unit_amount`, `missing_recurring`, `yearly_interval`
  * `missing_latest_invoice`, `unpaid_invoice`, `partial_invoice_refund`
  * `bare_pi_id_only` (`{"id": "pi_wb_1"}`), `pi_without_charge_ref`
  * `bare_charge_id_only` (`{"id": "ch_wb_1"}`), `charge_missing_paid_bool`, `charge_missing_status`, `charge_missing_refunded_bool`, `charge_partial_refund`
* Across every mutation, WedgeBench asserts that Python (`verify_signed_license_key`), Node.js `claim.js`, and Node.js `audit.js` all fail closed (`False`, `HTTP 402`, or retryable `HTTP 503`).

---

## 4. Adaptations Made to WedgeBench for Cloud-Native SaaS

To extend WedgeBench from embedded firmware parsers to a multi-runtime Python + Node.js cloud application, we introduced three adaptations:

1. **Subprocess Batching for Sub-Second Multi-Runtime Fuzzing:** Spawning a fresh Node.js VM per YAML vector adds seconds of process startup overhead. We adapted the WedgeBench runner to serialize the entire 20-vector YAML corpus into a single batched `Promise.all(...)` call inside an isolated `TMPDIR` Node.js child process, completing all 20 cross-runtime differential comparisons in ~0.4 seconds.
2. **Runtime Self-Check Shim Inside the Production Engine:** Rather than keeping WedgeBench purely in the test suite, we promoted its AST semantic invariant check into `src/compose_remediator.py` (`remediate_compose_manifest`). Every production remediation in Python validates its own generated YAML against `yaml.safe_load` before returning, guaranteeing that no non-`image` property can ever be altered in production.
3. **Relational DAG Mutation for REST API Boundaries:** Traditional fuzzers mutate flat byte streams or single JSON payloads. Because Stripe's `2025-03-31.basil` API distributes entitlement state across five linked REST resources (including paginated `/v1/invoice_payments`), we extended WedgeBench's mutator to operate on an in-memory relational state graph (`active_state`) served over an ephemeral loopback HTTP server (`127.0.0.1`), enabling deterministic injection of multi-page refund states and stripped JSON objects.

---

## 5. Quantifiable Impact

| Metric | Pre-WedgeBench (PRs #54–#61) | With WedgeBench (PR #62, `296db2a`) |
| :--- | :--- | :--- |
| **Verification Mode** | Reactive point-fix unit tests after external LLM review | Proactive differential AST & negative-space boundary fuzzing |
| **Adversarial Vectors Verified per Run** | 7 static regression fixtures | **38 differential YAML & API mutation vectors** (68 total tests) |
| **Full Suite Execution Time** | 3.51s | **5.50s** (batched subprocess execution) |
| **Cloud Deploy Credits Used in Iteration** | High (repeated preview/prod deploys) | **0 credits** (100% local loopback & subprocess isolation) |
| **Non-Image YAML Mutation Risk** | Vulnerable to `''` and `#`-in-quotes edge cases | **0%** (guarded by canonical AST equivalence check) |
