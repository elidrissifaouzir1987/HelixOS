# Tasks: Current Plan Eligibility

**Input**: Design documents from `specs/002-plan-eligibility/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`,
`contracts/plan-eligibility-v1.md`, `quickstart.md`

**Tests**: Contract, single-fault, boundary, call-order, replay contention, property,
redaction, portability, soak, performance and regression tests are mandatory under
FR-001 through FR-025, SC-001 through SC-008 and the Constitution Check.

**Organization**: Tasks are grouped by independently testable user story. Test tasks
precede the implementation they specify. A checked task requires local evidence; remote
CI evidence remains unchecked until an immutable run exists.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the removable leaf crate and its documented trust boundary.

- [x] T001 Pin Rust `1.96.1` with rustfmt/clippy in `kernel/rust-toolchain.toml`, add `helix-plan-eligibility` to `kernel/Cargo.toml`, and create the exact-pinned leaf manifest plus module/test skeleton in `kernel/helix-plan-eligibility/Cargo.toml`, `kernel/helix-plan-eligibility/src/lib.rs`, and `kernel/helix-plan-eligibility/tests/common/mod.rs`
- [x] T002 [P] Record authenticity-versus-eligibility, last-only replay claim, non-authority marker and removal decisions in `docs/adr/0006-current-plan-eligibility.md`
- [x] T003 [P] Create the versioned eligibility corpus root and public format description in `contracts/fixtures/plan-eligibility-v1/README.md`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Expose authenticated claims safely and define closed portable eligibility
types before implementing any positive story.

**Critical**: No evaluator gate begins until the feature-001 projection and feature-002
closed types pass their tests.

- [x] T004 Write failing fingerprint, immutable-never-reused key-ID/rotation, claims-completeness, claims-redaction and feature-001 golden-regression tests in `kernel/helix-contracts/tests/eligibility_claims.rs`
- [x] T005 Implement the non-wire verified-key fingerprint, fixed nonce-byte accessor and borrowed `PlanEligibilityClaimsV1` projection without changing canonical bytes in `kernel/helix-contracts/src/crypto.rs`, `kernel/helix-contracts/src/validation.rs`, `kernel/helix-contracts/src/plan.rs`, and `kernel/helix-contracts/src/lib.rs`
- [x] T006 [P] Write failing stable denial/build-code, terminal-versus-ready context, compile-fail non-Clone marker and non-Serde marker/claims, receipt-binding, diagnostic-redaction and initial forbidden-production-API tests in `kernel/helix-plan-eligibility/tests/contract.rs`, `kernel/helix-plan-eligibility/tests/redaction.rs`, and `kernel/helix-plan-eligibility/tests/portability.rs`
- [x] T007 Implement the bounded sum-type context and closed build errors, exhaustive denial/status mapping, replay binding/receipt contracts, result ownership and redacted public surfaces in `kernel/helix-plan-eligibility/src/context.rs`, `kernel/helix-plan-eligibility/src/denial.rs`, `kernel/helix-plan-eligibility/src/replay.rs`, `kernel/helix-plan-eligibility/src/marker.rs`, and `kernel/helix-plan-eligibility/src/lib.rs`
- [x] T008 Review `kernel/Cargo.lock` after resolution and prove that the production crate added no runtime dependency beyond `helix-contracts`, with test-only pins documented in `kernel/helix-plan-eligibility/Cargo.toml`

**Checkpoint**: An authentic plan exposes every required claim and the new crate exposes
only bounded, OS-neutral, non-serializable types; no eligibility success exists yet.

---

## Phase 3: User Story 1 - Admit Only a Current Coherent Plan (Priority: P1) MVP

**Goal**: Promote one authentic plan only when every current binding is coherent, then
call replay exactly once and last.

**Independent Test**: The complete context returns one opaque eligible marker; changing
any single trusted fact returns the declared first denial with zero claimant calls.

### Tests for User Story 1

- [x] T009 [P] [US1] Write the failing coherent-context success, exact evaluation-order and claimant-last probe tests in `kernel/helix-plan-eligibility/tests/eligibility.rs`
- [x] T010 [P] [US1] Write failing context health, admission, UTC issuance/expiry, clock rollback, reboot, monotonic deadline and epoch-minus/equal/plus boundary tests in `kernel/helix-plan-eligibility/tests/time_and_epochs.rs`
- [x] T011 [P] [US1] Write failing signer fingerprint/generation, workload validity, unique lease/source/scope/budget and authorization single-fault tests in `kernel/helix-plan-eligibility/tests/authority.rs`
- [x] T012 [P] [US1] Write failing immutable policy/catalogue, explicit decision-plan/current-generation, capability missing/digest/context/observation/freshness and required/mandatory-set tests, including the feature-001 proof that future protected observations are unreachable, in `kernel/helix-plan-eligibility/tests/policy_and_capabilities.rs`
- [x] T013 [P] [US1] Write the generated one-binding-at-a-time mutation oracle with checked-arithmetic extremes in `kernel/helix-plan-eligibility/tests/property.rs`

### Implementation for User Story 1

- [x] T014 [US1] Implement context/admission, UTC, same-boot monotonic and exact epoch gates in normative first-failure order in `kernel/helix-plan-eligibility/src/evaluator.rs`
- [x] T015 [US1] Implement exact signer, workload, lease/source/scope/budget and plan-bound authorization gates in `kernel/helix-plan-eligibility/src/evaluator.rs`
- [x] T016 [US1] Implement immutable policy/catalogue and linear sorted capability/freshness gates with checked arithmetic in `kernel/helix-plan-eligibility/src/evaluator.rs`
- [x] T017 [US1] Construct the `(instance_epoch, nonce)` uniqueness binding, invoke `ReplayClaimantV1::claim_once` as the final/only impure step, verify the domain-separated receipt binding digest and create `EligiblePlanV1` only from a matching new receipt in `kernel/helix-plan-eligibility/src/evaluator.rs` and `kernel/helix-plan-eligibility/src/marker.rs`

**Checkpoint**: US1 is green with every pre-claim denial proving zero replay calls. The
marker remains unusable for preparation, dispatch or adapters.

---

## Phase 4: User Story 2 - Claim Admission Exactly Once (Priority: P1)

**Goal**: Prove the replay interface has one linearization point and never turns a prior
observation, ambiguity or same-binding replay into a second eligible instance.

**Independent Test**: Sequential and concurrent identical evaluations yield exactly one
new claim; conflicts and dependency failures return closed denials without retry/release.

### Tests and implementation for User Story 2

- [x] T018 [P] [US2] Write failing sequential replay, cross-key-rotation same-nonce, same-nonce/different-operation, same-operation/different-plan, invalid receipt digest, unavailable, ambiguous, bounded-completion and no-retry tests in `kernel/helix-plan-eligibility/tests/replay.rs`
- [x] T019 [P] [US2] Implement a deterministic thread-safe two-index claimant shared only by tests and examples in `kernel/helix-plan-eligibility/test-support/replay_claimant.rs`
- [x] T020 [US2] Make the replay conflict and failure test matrix green while proving no release/reset/idempotent-success API exists in `kernel/helix-plan-eligibility/src/replay.rs` and `kernel/helix-plan-eligibility/src/evaluator.rs`
- [x] T021 [US2] Add and pass at least 1,000 ignored release-mode barrier-synchronised contention rounds with exactly one winner per round in `kernel/helix-plan-eligibility/tests/contention.rs`

**Checkpoint**: US2 proves deterministic process-level linearizability. Production
crash/restart durability remains explicitly unimplemented and blocks dispatch.

---

## Phase 5: User Story 3 - Reproduce and Audit Eligibility Decisions (Priority: P2)

**Goal**: Run one unchanged redacted corpus and evidence format on Windows, Linux and
macOS arm64.

**Independent Test**: The committed manifest produces byte-identical public outcome
summaries, and source gates find no native path/clock/network/OS-dependent semantics.

### Tests and implementation for User Story 3

- [x] T022 [P] [US3] Commit the versioned positive, context-build-error and every-runtime-single-fault manifest plus exact RFC 8785 redacted summaries in `contracts/fixtures/plan-eligibility-v1/cases.json` and `contracts/fixtures/plan-eligibility-v1/expected-outcomes.json`
- [x] T023 [US3] Implement the unchanged manifest runner, declared first-code checks, claimant-reached flag and fixture-drift assertion in `kernel/helix-plan-eligibility/tests/conformance.rs`
- [x] T024 [P] [US3] Expand sentinel tests across denial/failure/marker/claims/replay `Debug` and `Display` surfaces in `kernel/helix-plan-eligibility/tests/redaction.rs`
- [x] T025 [P] [US3] Extend and rerun the foundational source/dependency gate to forbid unsafe, native paths/clocks/handles, production filesystem/network, target OS branches, ambient state, floats, unbounded maps and reverse workspace dependencies in `kernel/helix-plan-eligibility/tests/portability.rs`
- [x] T026 [P] [US3] Add the ignored deterministic 100,000-context acceptance-oracle soak with seed and summary output in `kernel/helix-plan-eligibility/tests/soak.rs`
- [x] T027 [P] [US3] Add a release benchmark that records schema, corpus/version/digest, public case ID, hardware, parallelism, platform, exact toolchain, build profile, workload, iteration/concurrency counts, raw sorted samples and p50/p95/p99/max without runtime plan IDs in `kernel/helix-plan-eligibility/examples/eligibility_benchmark.rs`
- [x] T028 [P] [US3] Register `PLAN-002`, corpus, platforms, local/immutable evidence and deferred durable gates in `conformance/catalog.yaml`
- [x] T029 [P] [US3] Add exact-Rust-1.96.1 format, strict lint, targeted crate tests, corpus drift, contention and soak jobs for Linux x86_64, macOS arm64 and Windows x64 in `.github/workflows/plan-eligibility.yml`, and replace the floating Rust install in `.github/workflows/contracts.yml`

**Checkpoint**: Local US3 evidence is reproducible. Cross-platform acceptance remains
pending until the unchanged remote matrix succeeds for one immutable commit.

---

## Phase 6: Polish and Cross-Cutting Evidence

**Purpose**: Verify regression, performance, removal and project memory without
overstating system authority or portability.

- [x] T030 [P] Reconcile public rustdoc and the explicit removal path with `specs/002-plan-eligibility/contracts/plan-eligibility-v1.md`, `specs/002-plan-eligibility/quickstart.md`, and `docs/adr/0006-current-plan-eligibility.md`
- [x] T031 Run package-scoped format checks, strict workspace Clippy, `helix-contracts` tests and all `helix-plan-eligibility` targets from `specs/002-plan-eligibility/quickstart.md`
- [x] T032 Run the locked whole-workspace regression plus inverse-dependency and `--exclude helix-plan-eligibility` removal-isolation drill on the local supported host, and record the existing legacy macOS hazard without presenting targeted crate success as whole-system Tier 1 in `specs/002-plan-eligibility/quickstart.md`
- [x] T033 Run the ignored contention/soak and release benchmark, preserve complete raw metadata/samples under `specs/002-plan-eligibility/evidence/`, report p95 against SC-005, and label a real Mac mini M4 run only when executed on that hardware
- [x] T034 Refresh Graphify; save concise redacted records for the claim-last/non-authority design decision, corrected replay namespace and verified implementation outcome (plus a dead end only if one occurred); regenerate lessons and confirm nodes in `graphify-out/graph.json`, `graphify-out/memory/`, and `graphify-out/reflections/LESSONS.md`
- [ ] T035 Capture a successful unchanged Linux/macOS-arm64/Windows `PLAN-002` matrix and record exact commit, run URL, artifact SHA-256/attestation and preserved retention location in `conformance/catalog.yaml`

---

## Acceptance Traceability

| Requirement / criterion | Primary tasks |
|---|---|
| FR-001 | T004-T005, T009, T017 |
| FR-002-FR-003 | T006-T007, T009, T014-T017, T023 |
| FR-004-FR-007 | T010, T014, T022-T023 |
| FR-008 | T004-T005, T011, T015, T018 |
| FR-009-FR-011 | T011, T015, T022-T023 |
| FR-012-FR-013 | T012, T016, T022-T023 |
| FR-014 | T011, T015, T030 |
| FR-015 | T012-T013, T016, T022-T023 |
| FR-016 | T009, T014-T017, T023 |
| FR-017-FR-018 | T007, T009, T017-T021, T023 |
| FR-019-FR-020 | T006-T007, T017-T018, T030, T032 |
| FR-021-FR-022 | T006-T007, T010-T012, T018, T020, T022-T024 |
| FR-023-FR-024 | T002, T006-T008, T017, T024-T025, T030 |
| FR-025 | T003, T006-T007, T022-T023, T029, T035 |
| SC-001-SC-002 | T009-T013, T022-T023 |
| SC-003 | T019-T021, T029, T033 |
| SC-004 | T013, T026, T029, T033 |
| SC-005 | T027, T033 |
| SC-006 | T022-T023, T028-T029, T035 |
| SC-007 | T004, T006-T007, T024, T027 |
| SC-008 | T004-T005, T025, T030-T032 |

---

## Dependencies and Execution Order

### Phase dependencies

- Phase 1 has no dependencies.
- Phase 2 depends on T001 and blocks all user stories.
- US1 depends on the authenticated claims projection and foundational closed types.
- US2 depends on the US1 final-claim call site but is independently testable through
  sequential/conflict/contention cases.
- US3 depends on stable US1/US2 codes and outcomes.
- Phase 6 local validation depends on implemented US1-US3 files; T035 additionally
  requires external CI execution and cannot be checked from local evidence.

### Parallel opportunities

- T002 and T003 can run in parallel with the crate skeleton.
- T004 and T006 touch different crates and can run in parallel.
- T009-T013 are separate failing test files once foundational types compile.
- T018-T019 can run in parallel; T021 follows the deterministic claimant.
- T022 and T024-T029 touch separate fixtures/tests/catalogue/workflow files after stable
  denial names are frozen.
- Tasks sharing `evaluator.rs`, `plan.rs`, `Cargo.lock` or the same fixture run
  sequentially.

## Implementation Strategy

### MVP first

1. Complete Setup and Foundational tasks.
2. Complete US1 and prove every invalid context stops before replay.
3. Complete US2 and prove exactly one replay claim without claiming durability.
4. Complete US3 locally and preserve raw evidence.
5. Leave T035 open until immutable remote evidence exists.

### Removal and later migration

- Removing feature 002 deletes one leaf workspace member, its fixtures/workflow/ADR,
  and the non-wire claims/fingerprint accessors. Feature-001 canonical/signature behavior
  and MVP-0 runtime behavior remain unchanged.
- A later durable coordinator may consume `EligiblePlanV1` only after atomically
  comparing its generations and reserving budgets/recovery. It may not adapt the legacy
  `Plan` into eligibility or let an adapter consume authenticity/eligibility directly.

## Task Summary

- Total tasks: 35
- Setup/foundational: 8
- US1: 9
- US2: 4
- US3: 8
- Polish/evidence: 6
- Suggested local implementation scope: T001-T034
- External immutable evidence: T035
- Every task row follows the required checkbox, ID, optional `[P]`, story label and exact
  path format.
