# Implementation Plan: Current Plan Eligibility

**Branch**: `master` (feature directory `002-plan-eligibility`) | **Date**: 2026-07-10 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/002-plan-eligibility/spec.md`

## Summary

Add an independent `helix-plan-eligibility` Rust crate that promotes a previously
verified `AuthenticPlanEnvelopeV1` only when explicit, trusted current-state facts still
match every signed binding. Evaluation is deterministic and read-only through time,
boot, epochs, signer, workload, lease, authorization, policy, catalogue and capability
checks. It then calls a caller-owned atomic replay claimant exactly once and last. A
successful claim yields an opaque, non-serializable `EligiblePlanV1`; every other path
returns the authentic plan with one closed, redacted denial code.

The feature adds a borrowing `PlanEligibilityClaimsV1` projection to
`helix-contracts`, but does not change the v1 wire schema, canonical bytes, plan ID,
signature profile, fixtures or legacy runtime. The new marker is a point-in-time
prerequisite only: it is not approval, preparation authority, an `ExecutionGrant`, or an
adapter input.

## Technical Context

**Language/Version**: Rust edition 2021 with exact toolchain `1.96.1`, components
`rustfmt` and `clippy`, pinned in `kernel/rust-toolchain.toml`. CI uses that same
toolchain on Windows x64, Linux x86_64 and macOS arm64; an MSRV is declared only after a
dedicated lower-toolchain gate.

**Primary Dependencies**: Runtime dependency only on the workspace path crate
`helix-contracts`. Reuse its portable identifiers, digests, nonces and authenticated
plan marker. Test-only dependencies may reuse the workspace's exact-pinned
`proptest 1.11.0`, `serde 1.0.228`, `serde_json 1.0.150`,
`serde_json_canonicalizer 0.3.2`, and `ed25519-dalek 2.2.0`; no async runtime,
database, clock, filesystem, network or platform abstraction dependency is introduced.

**Storage**: No production storage implementation. `ReplayClaimantV1` is a synchronous
atomic contract; a deterministic thread-safe in-memory implementation exists only for
tests and examples. Versioned conformance cases and benchmark evidence are repository
files. Production durable uniqueness and recovery remain a later coordinator feature.

**Testing**: `cargo test --locked`; table-driven single-fault fixtures; exact boundary
tests; replay call-order probes; barrier-synchronised contention; property tests; an
ignored 100,000-context release soak; a release p50/p95/p99 benchmark; source-level
portability and redaction tests; unchanged corpus on the three CI operating systems.

**Target Platform**: Portable common library for macOS arm64 (primary deployment:
Mac mini M4), Linux arm64/x86_64 and Windows x64. Current local implementation evidence
is Windows x64; macOS arm64 remains an immutable CI and target-device evidence gate.

**Project Type**: Leaf library plus a small non-wire claims projection, language-neutral
conformance manifest, ADR, release evidence and CI matrix.

**Performance Goals**: Complete current-state evaluation plus deterministic local
atomic claim p95 <= 1 ms over at least 10,000 release iterations on recorded hardware;
1,000 contention rounds yield exactly one success; 100,000 generated contexts produce
no panic, overflow, platform drift or false acceptance.

**Constraints**: `#![forbid(unsafe_code)]`; no serialization on eligibility markers; no
native path, handle, clock, RNG, filesystem, network, process-global state, OS-specific
`cfg`, provider error string or implicit authority. All arithmetic is checked, all
collections are bounded and canonical before entry, all unavailable/ambiguous inputs
fail closed, and all read-only gates precede the replay claim.

**Scale/Scope**: One authentic plan version, one deterministic eligibility transition,
one closed denial taxonomy, one replay-claim interface, one test claimant, one positive
fixture plus a single-fault case for every bound fact and provider failure. Preparation,
budget consumption, durable operation state, recovery receipts, grants, adapters and
host effects are explicitly excluded.

## Constitution Check

*GATE: Passed before Phase 0 research; re-checked after Phase 1 design.*

- **Boundary - PASS**: The evaluator accepts only `AuthenticPlanEnvelopeV1` and
  core-supplied facts. It has no host/share/egress API and cannot dispatch. Agent fields
  cannot satisfy current-state checks.
- **Authority - PASS**: Exact task, workload, boot, epochs, key-trust generation, lease,
  exact verification-key fingerprint, authorization, immutable policy/catalogue
  identity, capability context and replay bindings are required. Ahead, stale, unknown
  and unavailable values deny. The result is explicitly not an execution authority.
- **Effects - PASS (no effect in scope)**: The only mutation is the final abstract
  one-shot replay claim. Its contract requires atomic durable uniqueness, but the
  production store, budget transaction, `PREPARING`, recovery, `ExecutionGrant`,
  dispatch and effect verification remain later mandatory gates.
- **Data - PASS**: Inputs contain identifiers, digests, bounded capability names,
  scalar deadlines and generations, but no secret bytes. Public errors and `Debug`
  expose only type/count/stable-code metadata; fixtures use public synthetic values.
- **Portability - PASS**: UTC and boot-monotonic milliseconds are passed as scalar facts;
  the crate never obtains native time. No path, handle or OS branch enters the API. The
  same manifest and outcome digest run unchanged on Windows, Linux and macOS arm64.
- **Performance - PASS**: SC-003 through SC-005 define iterations, concurrency,
  percentile and evidence metadata. Inputs are bounded; required capabilities use a
  linear merge over sorted slices; dependency failure is immediate and closed.
- **Evidence - PASS**: `PLAN-002`, single-fault codes, claim-call probes, contention,
  soak, benchmark samples, fixture drift, strict lint, portability CI, ADR and removal
  instructions are named below.

Post-design re-check: PASS. The design preserves the final atomic claim after all
read-only gates and does not mistake a pre-observed or pre-reserved nonce for eligibility.
No constitutional deviation or complexity waiver is needed.

## Phase 0: Research Decisions

Research in [research.md](research.md) resolves the following decisions before code:

1. A new leaf crate owns current-state evaluation; `helix-contracts` stays a pure
   canonical wire/cryptography boundary.
2. `AuthenticPlanEnvelopeV1 + EligibilityContextV1 + atomic claim` is the only positive
   transition. Authenticity and a prior `unused` observation are insufficient.
3. All mutable facts are borrowed, explicit and generation/digest bound. No provider or
   ambient I/O runs inside validation except the single final replay method.
4. UTC half-open validity is combined with a same-boot, suspend-aware monotonic
   half-open deadline; checked arithmetic handles all boundary and overflow cases.
5. The closed denial order is stable and redacted. Replay unavailable, conflict or
   ambiguous outcomes deny and never fall back to process-local memory.
6. The positive marker owns the authentic plan, is not cloneable or serializable, and
   exposes only the minimum decision metadata needed by the future coordinator.
7. The authentic marker retains a non-wire SHA-256 fingerprint of the exact Ed25519
   public key used for verification. Eligibility matches it to the current signer view
   and trust generation, preventing key-identifier reuse after rotation without changing
   protected bytes or signatures.
8. Replay uniqueness is `(instance_epoch, nonce)` in a stable issuer namespace; key
   identity/fingerprint are compared binding fields. A successful receipt must carry the
   exact domain-separated binding digest, which the evaluator verifies.

## Phase 1: Design and Contracts

- [data-model.md](data-model.md) defines the claims view, trusted context entities,
  replay request/outcomes, denial taxonomy, marker and state transitions.
- [contracts/plan-eligibility-v1.md](contracts/plan-eligibility-v1.md) defines the Rust
  API contract, validation order, exact boundaries, provider obligations, diagnostics
  and compatibility rules. It is an in-process contract, not a new wire schema.
- [quickstart.md](quickstart.md) defines local, extended and immutable multi-OS evidence
  commands, including the Mac mini M4 benchmark target and Graphify refresh.
- `docs/adr/0006-current-plan-eligibility.md` records the trust transition and why the
  replay claim must occur last.

## Project Structure

### Documentation (this feature)

```text
specs/002-plan-eligibility/
|-- spec.md
|-- plan.md
|-- research.md
|-- data-model.md
|-- quickstart.md
|-- contracts/
|   `-- plan-eligibility-v1.md
|-- checklists/
|   `-- requirements.md
|-- evidence/
|   `-- benchmark-<platform>-<date>.json
`-- tasks.md
```

### Source Code (repository root)

```text
contracts/fixtures/plan-eligibility-v1/
|-- cases.json
`-- expected-outcomes.json

conformance/catalog.yaml
docs/adr/0006-current-plan-eligibility.md

kernel/
|-- Cargo.toml
|-- Cargo.lock
|-- rust-toolchain.toml
|-- helix-contracts/
|   |-- src/crypto.rs
|   |-- src/lib.rs
|   |-- src/plan.rs
|   |-- src/validation.rs
|   `-- tests/eligibility_claims.rs
`-- helix-plan-eligibility/
    |-- Cargo.toml
    |-- src/
    |   |-- lib.rs
    |   |-- context.rs
    |   |-- denial.rs
    |   |-- evaluator.rs
    |   |-- marker.rs
    |   `-- replay.rs
    |-- examples/eligibility_benchmark.rs
    |-- test-support/
    |   `-- replay_claimant.rs
    `-- tests/
        |-- common/mod.rs
        |-- authority.rs
        |-- conformance.rs
        |-- contract.rs
        |-- contention.rs
        |-- eligibility.rs
        |-- policy_and_capabilities.rs
        |-- portability.rs
        |-- property.rs
        |-- redaction.rs
        |-- replay.rs
        |-- soak.rs
        `-- time_and_epochs.rs

.github/workflows/plan-eligibility.yml
```

**Structure Decision**: `helix-plan-eligibility` is a leaf beside
`helix-contracts`, not inside the Windows-first legacy runtime. The contract crate gains
one borrowing projection because its protected fields must remain encapsulated and must
not be recovered through serialization. The evaluator crate depends inward only on the
portable contract layer. A separate workflow can prove the two portable crates on all
three operating systems without claiming that the still-unmigrated legacy runtime is
already Tier 1 on macOS.

## Public Boundary and Evaluation Sequence

The intended surface is structurally equivalent to:

```rust
pub fn evaluate_and_claim_plan_v1<C: ReplayClaimantV1 + ?Sized>(
    plan: AuthenticPlanEnvelopeV1,
    context: EligibilityContextV1<'_>,
    claimant: &C,
) -> Result<EligiblePlanV1, EligibilityFailureV1>;
```

`EligibilityFailureV1` owns the authentic plan and exposes only
`denial()`/`into_authentic()`, allowing a trusted coordinator to decide whether to
re-resolve transient facts without repeating cryptographic verification. The evaluator
performs, in order:

1. context structure, snapshot revision, torn-generation checks, supervisor consistency
   and admission state;
2. clock health and UTC validity;
3. exact boot equality, same-boot monotonic validity, instance epoch and fencing epoch;
4. signer key identifier, exact verified-key fingerprint, current trust generation and
   authenticated workload validity;
5. exact active lease/source/scope/budget and authorization bindings;
6. immutable policy and catalogue bindings and current affirmative decisions;
7. capability report context, digest, observation, freshness and required set;
8. one atomic `(instance_epoch, nonce)` replay claim whose compared binding includes key
   fingerprint, plan, operation, task, workload, lease, trust generation and fencing;
9. receipt-binding-digest verification and construction of `EligiblePlanV1` from the
   owned authentic plan and matching receipt.

No failed step 1-7 calls the claimant. No successful claim is released for reuse.
Claim ambiguity is a denial requiring reconciliation or a new plan. A future coordinator
must compare every carried generation again in its durable prepare transaction.

## Implementation Strategy

1. Add claims-view tests first, then expose `PlanEligibilityClaimsV1<'_>` without
   changing serialization or golden fixtures.
2. Scaffold the leaf crate with forbidden-API and marker-surface tests.
3. Implement the closed denial/replay contracts and borrowed trusted context.
4. Add one failing test for each gate and boundary, asserting zero claimant calls, then
   implement gates in the specified order using checked arithmetic.
5. Add replay conflict/unavailable/ambiguous and 1,000-round barrier contention tests,
   then construct the opaque marker only from a successful receipt.
6. Add the portable corpus, drift test, redaction sentinels, 100,000 soak and benchmark.
7. Extend strict CI and run crate plus workspace regression. Record local evidence but
   leave macOS arm64/Tier 1 claims pending until immutable remote or target-device proof.

## Removal and Migration

Removal deletes the workspace member, its fixture/CI/ADR/spec artefacts and the single
claims projection. It does not alter plan-envelope wire bytes, signatures, feature-001
fixtures or the MVP-0 runtime. Later migration must make a durable coordinator consume
`EligiblePlanV1`; it must never convert the legacy `Plan` into eligibility or let an
adapter accept `AuthenticPlanEnvelopeV1`/`EligiblePlanV1` directly.

## Complexity Tracking

No Constitution Check violation requires justification. The extra crate and replay
trait are the minimum boundary that separates authenticity, current eligibility and
future durable execution authority.
