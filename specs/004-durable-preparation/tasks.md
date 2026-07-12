---
description: "Dependency-ordered implementation tasks for PLAN-004 durable preparation"
---

# Tasks: Durable Preparation Before Dispatch

**Input**: Design documents from `specs/004-durable-preparation/`

**Prerequisites**: `spec.md`, `plan.md`, `research.md`, `data-model.md`, `contracts/`,
`quickstart.md`

**Tests**: Required. The feature specification mandates contract, negative, contention,
fault-injection, crash, restore, portability, redaction and performance evidence. Write
the test tasks in each story first and observe the intended failures before implementing
that story.

**Organization**: Tasks are grouped by user story. US1 is the only minimum slice that
may construct `PreparedOperationV1`; US2 and US3 use non-authoritative fixtures for
independent testing, and US4 cannot begin until both are integrated. The 42-item
requirements-writing gate in `checklists/durability.md` passed during planning and is
revalidated against implementation evidence in Phase 7.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: May run in parallel after its phase prerequisites because it touches distinct
  files and does not depend on another incomplete task in the same group.
- **[Story]**: Maps implementation work to US1, US2, US3 or US4.
- Every task names exact repository paths and acceptance coverage.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the two new crates, byte-stable artifacts and a recorded frozen
baseline without changing PLAN-001/002/003 semantics.

- [X] T001 Capture the locked PLAN-001/002/003 test, metadata and dependency baseline before Feature 004 changes in `specs/004-durable-preparation/evidence/baseline.md`
- [X] T002 Create minimal compilable crate manifests and library roots with pinned dependencies, empty-default features plus private non-default `test-fault-injection`, and `#![forbid(unsafe_code)]`; atomically extend the reviewed eligibility-consumer allowlist for the new portable crate while keeping `helix-plan-preparation -> contracts + eligibility`, `helix-coordinator-sqlite -> preparation + contracts`, and replay SQLite only as dev/integration wiring in `kernel/helix-plan-preparation/Cargo.toml`, `kernel/helix-plan-preparation/src/lib.rs`, `kernel/helix-coordinator-sqlite/Cargo.toml`, `kernel/helix-coordinator-sqlite/src/lib.rs`, and `kernel/helix-plan-eligibility/tests/portability.rs`
- [X] T003 Add `helix-plan-preparation` and `helix-coordinator-sqlite` to the workspace and resolve only the reviewed pinned dependency set in `kernel/Cargo.toml` and `kernel/Cargo.lock`
- [X] T004 [P] Create the portable module skeleton, including private non-default fault plumbing, in `kernel/helix-plan-preparation/src/attempt.rs`, `context.rs`, `guard.rs`, `commit_gate.rs`, `compare.rs`, `budget.rs`, `recovery.rs`, `store.rs`, `outcome.rs`, `coordinator.rs`, and `test_fault.rs`
- [X] T005 [P] Create the coordinator module skeleton in `kernel/helix-coordinator-sqlite/src/clock.rs`, `config.rs`, `error.rs`, `connection.rs`, `schema.rs`, `root_safety.rs`, `budget.rs`, `preflight.rs`, `prepare.rs`, `readback.rs`, `transition.rs`, `failure.rs`, `outbox.rs`, `quarantine.rs`, `retirement.rs`, `maintenance.rs`, `manifest.rs`, and `test_fault.rs`
- [X] T006 [P] Create separate upstream-portable and downstream cross-process test harness roots without a reverse crate dependency in `kernel/helix-plan-preparation/tests/common/mod.rs`, `kernel/helix-coordinator-sqlite/tests/common/mod.rs`, and `kernel/helix-coordinator-sqlite/tests/common/process_probe.rs`
- [X] T007 [P] Pin LF normalization for Feature 004 SQL, JCS-sensitive JSON, fixtures and evidence and include the policy in future CI path filters in `.gitattributes`

**Checkpoint**: Both new crates resolve under the locked workspace, while the recorded
prerequisite baseline remains unchanged.

---

## Phase 2: Foundational Contracts and Storage (Blocking)

**Purpose**: Build the non-wire projections, exact replay seam, closed portable types and
strict empty-to-v1 coordinator foundation required by every story.

**Critical**: No user-story implementation begins until this phase passes.

- [X] T008 [P] Write failing non-wire projection, canonical-custody, redaction and PLAN-001 byte/signature regression tests in `kernel/helix-contracts/tests/preparation_claims.rs`
- [X] T009 Implement borrowed `PlanPreparationClaimsV1` and authentic canonical-envelope custody without changing plan-v1 identity in `kernel/helix-contracts/src/plan.rs` and `kernel/helix-contracts/src/lib.rs`
- [X] T010 [P] Write failing opaque replay-view and five-classification contract tests without exposing `ReplayBindingV1` in `kernel/helix-plan-eligibility/tests/replay_verification.rs`
- [X] T011 [P] Write failing read-only exact-row verification tests, including advanced global generation and zero `claim_once` mutation, in `kernel/helix-replay-sqlite/tests/preparation_verification.rs`
- [X] T012 Implement `ReplayClaimVerificationViewV1`, `ReplayClaimVerifierV1`, closed outcomes and the `EligiblePlanV1::replay_verification_view()` factory in `kernel/helix-plan-eligibility/src/replay.rs`, `kernel/helix-plan-eligibility/src/marker.rs`, and `kernel/helix-plan-eligibility/src/lib.rs`
- [X] T013 Implement a genuine query-only exact replay verifier by reusing one strict row decoder and the three permanent indexes in `kernel/helix-replay-sqlite/src/verification.rs`, `kernel/helix-replay-sqlite/src/connection.rs`, `kernel/helix-replay-sqlite/src/claim.rs`, and `kernel/helix-replay-sqlite/src/lib.rs`
- [X] T014 Preserve the one-method `ReplayClaimantV1` contract and extend the reviewed replay source-file gate for the query-only verifier without widening legacy/MCP/adapter access in `kernel/helix-plan-eligibility/tests/portability.rs` and `kernel/helix-replay-sqlite/tests/portability.rs`
- [X] T015 [P] Write failing type-construction, non-Serde/non-Clone, closed context/outcome class, exclusive stable-code, provider-wiring and adapter-prohibition tests in `kernel/helix-plan-preparation/tests/contract.rs`
- [X] T016 [P] Write failing application-ID, schema/profile, root-lifecycle, JSON-contract and redacted-error tests in `kernel/helix-coordinator-sqlite/tests/contract.rs`
- [X] T017 [P] Implement safe attempt identities, complete preliminary/final contexts and injected time abstractions in `kernel/helix-plan-preparation/src/attempt.rs` and `kernel/helix-plan-preparation/src/context.rs`
- [X] T018 [P] Define opaque authority/permit contracts, the 250 ms permit ceiling and ephemeral `NoDispatchAuthorityGuardV1` for an externally injected supervisor; keep production deadman threads, ambient clocks and fencing storage outside the portable crate in `kernel/helix-plan-preparation/src/guard.rs` and `kernel/helix-plan-preparation/src/commit_gate.rs`
- [X] T019 Implement portable budget, recovery, store/preflight/readback input and receipt traits with closed versions after the T017/T018 context and authority types exist in `kernel/helix-plan-preparation/src/budget.rs`, `kernel/helix-plan-preparation/src/recovery.rs`, and `kernel/helix-plan-preparation/src/store.rs`
- [X] T020 Implement closed prepared/denied/failed/ambiguous outcomes, redacted projections and crate exports in `kernel/helix-plan-preparation/src/outcome.rs` and `kernel/helix-plan-preparation/src/lib.rs`
- [X] T021 [P] Write failing empty-to-v1, wrong-profile, root identity, irreversible `RESTORE_PENDING`, lifecycle-trigger and `OR REPLACE` regression tests in `kernel/helix-coordinator-sqlite/tests/schema_corruption.rs`
- [X] T022 [P] Implement the injected monotonic clock and payload-free internal error mapping used by root safety and storage configuration in `kernel/helix-coordinator-sqlite/src/clock.rs` and `kernel/helix-coordinator-sqlite/src/error.rs`
- [X] T023 Implement provisioner-attested empty/existing root roles, opaque root identities, lock discipline and unknown-member refusal after T022 establishes the clock/error types in `kernel/helix-coordinator-sqlite/src/root_safety.rs`
- [X] T024 Implement trusted configuration after T023 root-role types, connection profile establishment/readback, parameterized metadata initialization, embedded SQL drift checks, lifecycle triggers, injected historical PLAN-001 key resolution for canonical-plan revalidation and full invariant open in `kernel/helix-coordinator-sqlite/src/config.rs`, `kernel/helix-coordinator-sqlite/src/connection.rs`, `kernel/helix-coordinator-sqlite/src/schema.rs`, and `kernel/helix-coordinator-sqlite/src/lib.rs`
- [X] T025 Implement duplicate-key-rejecting closed decoders and embedded digests for all four JSON schemas, exact no-BOM/no-newline RFC 8785 handling, fixed-zero pending-retirement cross-validation and pinned Ed25519 provenance verification in `kernel/helix-coordinator-sqlite/src/manifest.rs`
- [X] T026 Build portable deterministic public-synthetic plans, clocks, authorities, externally injected supervisor guards/test-only deadman and provider contracts upstream; add only SQLite roots, cross-process recovery, budget and provenance signer/verifier fixtures downstream in `kernel/helix-plan-preparation/tests/common/mod.rs` and `kernel/helix-coordinator-sqlite/tests/common/mod.rs`
- [X] T027 Define private no-op-by-default hook plumbing for every independent point in Durable Preparation Contract section 14 as one closed frozen taxonomy shared by exact IDs across `kernel/helix-plan-preparation/src/test_fault.rs` and `kernel/helix-coordinator-sqlite/src/test_fault.rs`

**Checkpoint**: The portable authority surface and strict coordinator store compile and
their negative contract tests fail only because no story orchestration exists yet.

---

## Phase 3: User Story 1 — Prepare Only a Fresh Eligible Plan (Priority: P1) MVP

**Goal**: Consume one current `EligiblePlanV1` and create exactly one coherent,
non-dispatchable `PREPARING` operation only while every authority fact remains fresh.

**Coverage**: FR-001–FR-014, FR-028–FR-034; SC-001–SC-002, permit portion of SC-010.

**Independent Test**: Vary every authority/replay/time field singly. The coherent case
alone creates one complete operation/transition/reservation/recovery/event set; every
denial has its frozen first code and zero mutation.

### Tests for User Story 1

- [X] T028 [P] [US1] Write preliminary/final single-leaf and adjacent dual-fault cases for every normative section 6.1 mapping row, exact replay positive control, exclusive-time and zero-mutation/provider-call expectations in `kernel/helix-plan-preparation/tests/freshness.rs`
- [X] T029 [P] [US1] Write PAUSE/HALT ordering, caller-deadline-first, 250 ms-ceiling-first, equality, confirmed-rollback, explicit-uncertainty, missing-classification and deadman tests in `kernel/helix-plan-preparation/tests/revocation.rs`
- [X] T030 [P] [US1] Write all-eight-or-none atomic commit/rollback/reopen tests for metadata, operation, transition, comparison/replay, scope delta, reservation, recovery/irreversibility and event plus conflict and acknowledged/uncertain readback cases in `kernel/helix-coordinator-sqlite/tests/preparation.rs`

### Implementation for User Story 1

- [X] T031 [P] [US1] Implement field-by-field preliminary/final comparisons, checked freshness and the normative first-denial order in `kernel/helix-plan-preparation/src/context.rs` and `kernel/helix-plan-preparation/src/compare.rs`
- [X] T032 [P] [US1] Consume the injected external supervisor guard to implement fixed acquisition/reverse release, linearizable permit entry and one-shot commit custody while calling every section-14 guard/permit/deadman hook; prove deadman behavior only through the deterministic harness, with no production supervisor thread or fencing store in `kernel/helix-plan-preparation/src/guard.rs` and `kernel/helix-plan-preparation/src/commit_gate.rs`
- [X] T033 [US1] Implement read-only operation-identity then budget-authority preflight with no reservation or recovery call in `kernel/helix-coordinator-sqlite/src/preflight.rs`
- [X] T034 [US1] Implement and instrument every staging boundary of the canonical eight-member transaction—metadata generations, operation, transition, comparison/replay, scope delta, reservation, recovery/irreversibility and event—while holding the true permit across COMMIT in `kernel/helix-coordinator-sqlite/src/prepare.rs` and `kernel/helix-coordinator-sqlite/src/outbox.rs`
- [X] T035 [US1] Implement and instrument full-store exact same-attempt/prior/conflict/definite-absence/ambiguous acknowledgement/readback plus base quarantine custody in `kernel/helix-coordinator-sqlite/src/readback.rs` and `kernel/helix-coordinator-sqlite/src/quarantine.rs`
- [X] T036 [US1] Implement ordered Phase A–E orchestration with every section-14 preliminary/final capture, replay, operation/budget preflight, recovery revalidation, time sample and result/guard-release hook, retaining the recovery guard and never retrying after mutation in `kernel/helix-plan-preparation/src/coordinator.rs`
- [X] T037 [US1] Wire the public `prepare_plan_v1` entry, private one-shot `PreparedOperationV1` construction and exact-store adapter implementation in `kernel/helix-plan-preparation/src/lib.rs` and `kernel/helix-coordinator-sqlite/src/lib.rs`
- [X] T038 [US1] Enforce marker custody, stable redaction and zero dispatch/grant/legacy/MCP adapter reachability in `kernel/helix-plan-preparation/src/outcome.rs`, `kernel/helix-plan-preparation/tests/contract.rs`, and `kernel/helix-coordinator-sqlite/tests/contract.rs`

**Checkpoint**: US1 independently proves a fresh, one-shot, complete `PREPARING` slice;
no partial story or durable lookup can manufacture its positive marker.

---

## Phase 4: User Story 2 — Reserve Every Declared Budget Once (Priority: P1)

**Goal**: Reserve exact signed cost/action/egress/recovery capacity atomically with
`PREPARING`, serialize shared allowance and release once only under live no-dispatch
custody.

**Coverage**: FR-015–FR-021; SC-003–SC-004 and held-writer portion of SC-010.

**Independent Test**: Fixed non-authoritative authority/recovery fixtures exercise every
limit, identifier conflict, shared-scope contender and guarded failure release without
constructing `PreparedOperationV1`.

### Tests for User Story 2

- [X] T039 [P] [US2] Write create-only scope, exact/minus-one/plus-one, currency/price/generation and permanent binding tests in `kernel/helix-coordinator-sqlite/tests/budget.rs`
- [X] T040 [P] [US2] Write at least 100,000 checked-oracle vectors covering zero, safe maximum, underflow, overflow and all four aggregate dimensions in `kernel/helix-coordinator-sqlite/tests/budget_property.rs`
- [X] T041 [P] [US2] Write idempotent `PREPARING -> FAILED`, exact stored release and absent/mismatched/expired/revoked no-dispatch guard tests in `kernel/helix-coordinator-sqlite/tests/cancellation.rs`
- [X] T042 [P] [US2] Write 64-thread, 8-process, same-operation and distinct-operation shared-allowance contention cases in `kernel/helix-coordinator-sqlite/tests/contention.rs`
- [X] T043 [P] [US2] Write held-writer absolute-deadline, 50 ms tolerance, 250 ms observation and no-late-mutation cases in `kernel/helix-coordinator-sqlite/tests/deadline.rs`

### Implementation for User Story 2

- [X] T044 [P] [US2] Implement exact four-dimensional vectors, create-only trusted scope provisioning and checked sum/subtract helpers in `kernel/helix-plan-preparation/src/budget.rs` and `kernel/helix-coordinator-sqlite/src/budget.rs`
- [X] T045 [US2] Implement operation-first budget preflight and repeat all binding/arithmetic/capacity predicates after `BEGIN IMMEDIATE` in `kernel/helix-coordinator-sqlite/src/preflight.rs` and `kernel/helix-coordinator-sqlite/src/prepare.rs`
- [X] T046 [US2] Implement permanent reservation/operation/attempt conflicts and exact aggregate readback without overwrite, merge or retry in `kernel/helix-coordinator-sqlite/src/readback.rs`
- [X] T047 [US2] Implement and instrument every section-14 known-failure staging boundary for append-only `PREPARING -> FAILED`, `HELD -> RELEASED`, exact held-total subtraction and one failure event after T044 establishes coordinator budget helpers in `kernel/helix-coordinator-sqlite/src/transition.rs`, `kernel/helix-coordinator-sqlite/src/failure.rs`, and `kernel/helix-coordinator-sqlite/src/outbox.rs`
- [X] T048 [US2] Validate and retain the live ephemeral no-dispatch guard through the failure COMMIT, instrument its acquisition/final revalidation/revocation/release boundaries and persist no reusable guard evidence in `kernel/helix-plan-preparation/src/store.rs` and `kernel/helix-coordinator-sqlite/src/failure.rs`
- [X] T049 [US2] Implement bounded busy handling, child-process probes and budget/failure fault points for release contention evidence in `kernel/helix-coordinator-sqlite/src/connection.rs`, `kernel/helix-coordinator-sqlite/tests/common/process_probe.rs`, and `kernel/helix-coordinator-sqlite/src/test_fault.rs`

**Checkpoint**: US2 proves exact reservation and guarded one-time reconciliation under
thread/process contention without broadening the signed v1 budget.

---

## Phase 5: User Story 3 — Prepare Honest Recovery Evidence (Priority: P2)

**Goal**: Publish and revalidate exact recovery material for compensation, record honest
L2 irreversibility, and reconcile both operation-bound and true-orphan retirement paths.

**Coverage**: FR-022–FR-027, FR-039–FR-040; SC-005–SC-006 and recovery parts of SC-011.

**Independent Test**: Fixed non-authoritative authority/store fixtures accept exact
public synthetic material only, deny every single fault, perform zero material calls for
L2, and never fabricate an operation while reconciling an orphan.

### Tests for User Story 3

- [X] T050 [P] [US3] Write manifest-last provider, exact binding/capacity, L2 no-material and recovery first-failure tests in `kernel/helix-plan-preparation/tests/recovery.rs`
- [X] T051 [P] [US3] Write publication/cleanup contention, evidence persistence, corruption, orphan quarantine and two retirement-path integration tests in `kernel/helix-coordinator-sqlite/tests/recovery_integration.rs`
- [X] T052 [P] [US3] Write no-pruning, permanent failure/release/quarantine tombstone and orphan reverse/replace rejection tests in `kernel/helix-coordinator-sqlite/tests/retention.rs`

### Implementation for User Story 3

- [X] T053 [P] [US3] Implement approved provider profiles, publication/cleanup guards, immutable receipts, exact verification, L2 irreversibility and maintenance traits in `kernel/helix-plan-preparation/src/recovery.rs`
- [X] T054 [US3] Implement the manifest-last public-synthetic conformance provider and operation-scoped cross-process guard fixture after T053 defines its interfaces, calling every section-14 recovery staging/write/sync/verify/publish/reopen hook in `kernel/helix-coordinator-sqlite/tests/common/mod.rs`
- [X] T055 [US3] Validate and persist exact compensation/irreversibility evidence and cross-bind reserved capacity in `kernel/helix-coordinator-sqlite/src/prepare.rs` and `kernel/helix-coordinator-sqlite/src/schema.rs`
- [X] T056 [US3] Implement and instrument active orphan discovery, quarantine insertion, definitive no-reference proof and permanent resolved-quarantine `RETIREMENT_PENDING` authorization without operation creation in `kernel/helix-coordinator-sqlite/src/quarantine.rs`
- [X] T057 [US3] Implement and instrument operation-bound and true-orphan provider retirement invocation/byte/tombstone/final-`RETIRED_TOMBSTONE` boundaries idempotently in `kernel/helix-coordinator-sqlite/src/retirement.rs`
- [X] T058 [US3] Implement and instrument guarded provider enumeration, invariant reconciliation and backup-blocking pending-state maintenance operations in `kernel/helix-coordinator-sqlite/src/maintenance.rs`
- [X] T059 [US3] Complete the closed recovery/quarantine/retirement hook definitions and exact-ID source audit after T054–T058 place every call site behind the non-default feature in `kernel/helix-coordinator-sqlite/src/test_fault.rs`
- [X] T060 [US3] Integrate compensable and irreversible recovery branches, retained publication custody and closed failure classification into Phase B/C orchestration in `kernel/helix-plan-preparation/src/coordinator.rs`

**Checkpoint**: US3 proves honest recovery evidence and irreversible orphan/retirement
history, while synthetic evidence remains explicitly non-production.

---

## Phase 6: User Story 4 — Recover and Restore Preparation Safely (Priority: P3)

**Goal**: Reopen, reconcile, back up and restore preparation state without dispatch,
with authenticated provenance and independently durable pending root states.

**Coverage**: FR-028–FR-044; SC-006–SC-012.

**Independent Test**: Kill every frozen boundary, reopen or clean-root restore, and
observe only absence, one coherent operation, one atomic failed operation or explicit
quarantine. Coherent package substitution and root-state disagreement always deny.

### Tests for User Story 4

- [X] T061 [US4] Create the normative domain encodings, both package-binding known-answer vectors, every section 6.1 leaf/ordering case, every independent slash-action boundary ID/count from section 14, and stable outcome/generation/provider-call expectations consumed by US4 conformance in `contracts/fixtures/durable-preparation-v1/README.md`, `contracts/fixtures/durable-preparation-v1/cases.json`, and `contracts/fixtures/durable-preparation-v1/expected-outcomes.json`
- [X] T062 [P] [US4] Write the ignored release process-kill matrix for every frozen context/recovery/permit/transaction/failure/quarantine/retirement/backup/restore boundary in `kernel/helix-coordinator-sqlite/tests/process_crash.rs`
- [X] T063 [P] [US4] Extend corruption coverage for exact SQL/triggers, recursive-trigger profile, canonical plan, cross-record links, lifecycle reversals and every `OR REPLACE` key in `kernel/helix-coordinator-sqlite/tests/schema_corruption.rs`
- [X] T064 [P] [US4] Write quiescent online-backup, both fixed-zero pending-retirement counts, complete multi-provider inventory, byte-exact JCS/detached-attestation, coherent-substitution and dual-root pending restore tests in `kernel/helix-coordinator-sqlite/tests/backup_restore.rs`
- [X] T065 [P] [US4] Write portable stable-case/digest conformance tests against the T061 frozen Feature 004 corpus in `kernel/helix-plan-preparation/tests/conformance.rs` and `kernel/helix-coordinator-sqlite/tests/conformance.rs`
- [X] T066 [P] [US4] Write single-threaded private fault-corpus execution and exact boundary-count tests against T061 in `kernel/helix-coordinator-sqlite/tests/conformance_execution.rs`
- [X] T067 [P] [US4] Write seeded private-path/identifier/digest/content/budget/provider/key diagnostic redaction tests in `kernel/helix-plan-preparation/tests/redaction.rs` and `kernel/helix-coordinator-sqlite/tests/redaction.rs`
- [X] T068 [P] [US4] Write OS-neutral source, dependency, schema-byte, provider-order and no-weaker-fallback tests in `kernel/helix-coordinator-sqlite/tests/portability.rs`

### Implementation for User Story 4

- [X] T069 [P] [US4] Implement PAUSE plus provider/coordinator maintenance guards, stable generation cuts, generation rechecks, full invariant verification and every corresponding section-14 backup hook in `kernel/helix-coordinator-sqlite/src/maintenance.rs`
- [X] T070 [P] [US4] Implement and instrument exact u16/u64/digest/optional package binding, both known-answer vectors, sorted/unique inventory/JCS finalization, custody classes, fixed-zero pending counts and four closed schema codecs in `kernel/helix-coordinator-sqlite/src/manifest.rs`
- [X] T071 [US4] Implement and instrument create-only SQLite backup/export/package boundaries, authoritative pending-count reconciliation, exact canonical top-level manifest digest and detached Ed25519 attestation publication/reopen/verification through typed provisioner-owned signing custody in `kernel/helix-coordinator-sqlite/src/maintenance.rs` and `kernel/helix-coordinator-sqlite/src/manifest.rs`
- [X] T072 [US4] Implement and instrument package/provenance acceptance, clean empty-root reservation/import, profile establishment and matching independently durable coordinator/recovery `RESTORE_PENDING` publication/reopen/agreement with pinned trust/revocation in `kernel/helix-coordinator-sqlite/src/maintenance.rs`, `kernel/helix-coordinator-sqlite/src/schema.rs`, and `kernel/helix-coordinator-sqlite/src/root_safety.rs`
- [X] T073 [US4] Implement old-authority reconciliation to guarded `FAILED` or quarantine with rotated epochs and no activation transition in `kernel/helix-coordinator-sqlite/src/failure.rs` and `kernel/helix-coordinator-sqlite/src/quarantine.rs`
- [X] T074 [US4] Complete process probes and audit that every closed section-14 hook ID is called exactly at its portable/coordinator boundary, including attestation and each independent pending-root publication/reopen point, in `kernel/helix-coordinator-sqlite/tests/common/process_probe.rs`, `kernel/helix-plan-preparation/src/test_fault.rs`, and `kernel/helix-coordinator-sqlite/src/test_fault.rs`
- [X] T075 [US4] Export only the non-constructible bounded payload-free redacted `VerifiedPreparationRestoreV1` and `RestoredPreparationMaintenanceEvidenceV1` projections with no public producer; keep restore acceptance/validation, old-authority reconciliation, quarantine, limits/errors/inputs and every PAUSE/fencing/recovery/trust/no-dispatch type, constructor and operation crate-internal, and prove the negative external surface in `kernel/helix-coordinator-sqlite/src/lib.rs`, `kernel/helix-coordinator-sqlite/src/maintenance.rs`, and `kernel/helix-coordinator-sqlite/tests/restore_maintenance_api.rs`

**Checkpoint**: All four stories are independently testable, and their integrated state
remains non-dispatchable after crash and authenticated clean-root restore. The default
public surface exposes only two non-constructible redacted read-only evidence
projections with no producer; authority-bearing restore maintenance remains internal
and the sovereign host/activation gate is deferred.

---

## Phase 7: Polish and Cross-Cutting Release Evidence

**Purpose**: Execute and retain portable corpus evidence, CI, supply-chain/removal
evidence, performance evidence and project memory without promoting synthetic results.

- [X] T076 Implement the portable corpus runner and stable summary/digest output in `kernel/helix-coordinator-sqlite/examples/durable_preparation_corpus.rs`
- [X] T077 Implement the refusing-clean-root physical-M4 benchmark with separate coordinator and recovery-transfer artifacts in `kernel/helix-coordinator-sqlite/examples/durable_preparation_benchmark.rs`
- [X] T078 Add pinned three-platform conformance, fault, contention, provenance, artifact-attestation and path-filter jobs including `.gitattributes` in `.github/workflows/durable-preparation.yml`
- [X] T079 Register `PLAN-004` fields without changing PLAN-001/002/003 claim status in `conformance/catalog.yaml`
- [X] T080 Complete cross-crate dependency/source/removal gates so only reviewed consumers see Feature 004 contracts in `kernel/helix-plan-eligibility/tests/portability.rs`, `kernel/helix-replay-sqlite/tests/portability.rs`, and `kernel/helix-coordinator-sqlite/tests/portability.rs`
- [X] T081 Document pinned licenses, advisories, bundled SQLite source, SBOM/provenance expectations, clean-root boundary and pending external evidence in `specs/004-durable-preparation/evidence/README.md`
- [X] T082 Execute every command and interpretation gate in `specs/004-durable-preparation/quickstart.md` and retain exact local results/digests without private values in `specs/004-durable-preparation/evidence/local-validation.md`
- [X] T083 Revalidate the planning-passed 42-item authority/durability requirements-writing gate against completed implementation and evidence before release acceptance in `specs/004-durable-preparation/checklists/durability.md`
- [X] T084 Refresh secret-free Graphify code graph, useful outcome memory and reflections after all code/evidence changes in `graphify-out/graph.json`, `graphify-out/memory/`, and `graphify-out/reflections/LESSONS.md`

---

## Dependencies and Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: T001 precedes repository changes; T002 must create compilable
  manifests/library roots before T003 adds workspace members. T004–T007 then proceed in
  parallel where marked.
- **Foundational (Phase 2)**: Depends on Phase 1 and blocks all stories. Projection,
  replay and coordinator-foundation streams may proceed in parallel, then converge at
  T024–T027.
- **US1 (Phase 3)**: Depends on all foundational tasks and establishes the only positive
  marker path.
- **US2 (Phase 4)** and **US3 (Phase 5)**: Their tests/module-local work may be prepared
  independently after Phase 2, but production integration into `prepare.rs`,
  `readback.rs` and `coordinator.rs` follows US1 and must be serialized.
- **US4 (Phase 6)**: Depends on completed US2 failure/release and US3
  quarantine/retirement semantics; T061 freezes its normative corpus before T062–T068
  consume it.
- **Polish (Phase 7)**: Depends on all desired stories; physical M4/catalog evidence is
  recorded only when actually produced.

### User Story Dependencies

```text
Foundation
  -> US1 fresh complete PREPARING (MVP)
       -> US2 exact budgets ---------+
       -> US3 honest recovery -------+-> US4 crash/backup/restore
                                        -> release evidence
```

- **US1 (P1)**: No dependency on another story after foundation, but its transaction
  already contains one valid fixed budget hold and recovery/irreversibility record.
- **US2 (P1)**: Deepens budget authority independently with non-authoritative fixtures;
  it does not create a marker outside the US1 orchestrator.
- **US3 (P2)**: Deepens recovery independently with non-authoritative fixtures; it does
  not construct `PreparedOperationV1`.
- **US4 (P3)**: Requires US2 atomic release and US3 quarantine/retirement/inventory.

### Hot-File Serialization

- Serialize changes to `kernel/helix-coordinator-sqlite/src/prepare.rs`, `preflight.rs`,
  `readback.rs`, `maintenance.rs`, `tests/common/mod.rs`, and
  `kernel/helix-plan-preparation/src/coordinator.rs`.
- The permit must wrap the actual SQLite COMMIT; a copied pre-commit token check is not
  an acceptable parallel shortcut.
- Recovery publication/cleanup custody is acquired before the SQLite writer for
  preparation, cleanup and backup.

## Parallel Execution Examples

### User Story 1

```text
Parallel tests: T028 freshness | T029 revocation | T030 durable preparation
Parallel modules after tests: T031 compare/context | T032 guard/commit gate
Serialize integration: T033 -> T034 -> T035 -> T036 -> T037 -> T038
```

### User Story 2

```text
Parallel tests: T039 budget | T040 property | T041 cancellation | T042 contention | T043 deadline
Budget prerequisite: T044
Parallel after T044: T045 preflight/prepare | T047 failure transition
Serialize and converge: T045 -> T046; T046 + T047 -> T048 -> T049
```

### User Story 3

```text
Parallel tests: T050 portable recovery | T051 integration | T052 retention
Parallel module after tests: T053 provider contracts
Provider fixture dependency: T053 -> T054
Serialize lifecycle integration: T055 -> T056 -> T057 -> T058 -> T059 -> T060
```

### User Story 4

```text
Corpus prerequisite: T061
Parallel tests: T062 process crash | T063 corruption | T064 backup/restore | T065-T068 conformance/redaction/portability
Parallel modules after tests: T069 maintenance guards | T070 manifest codecs
Serialize package/restore integration: T071 -> T072 -> T073 -> T074 -> T075
```

## Implementation Strategy

### MVP First

1. Complete Setup and Foundational phases.
2. Complete US1 with one preprovisioned exact budget scope and fixed valid
   recovery/irreversibility fixture in the real atomic transaction.
3. Stop and run the US1 independent tests; this is the smallest slice allowed to return
   `PreparedOperationV1`.
4. Do not describe the MVP as production compensable recovery, dispatch or Tier 1.

### Incremental Delivery

1. Add US2 exact budget authority and guarded failure reconciliation.
2. Add US3 provider publication, honest L2, quarantine and both retirement paths.
3. Add US4 crash, authenticated backup and dual-root pending restore.
4. Execute and retain final corpus/CI/evidence only after all selected story semantics
   stabilize.

### Completion Discipline

- Write and observe each story's failing tests before implementation.
- Mark a task complete only after its named evidence passes under `--locked`.
- Preserve unrelated user changes and never weaken a constitutional MUST to make a test
  pass.
- Refresh Graphify only with public structural facts, decisions and verified outcomes;
  never include plan/recovery content, credentials or private reasoning.

## Phase 8: Convergence

- [X] T085 Record Option B: Feature 004 exposes only two bounded non-constructible redacted read-only evidence projections with no public producer, keeps all authority-bearing restore maintenance crate-internal, and defers the sovereign host and activation facade to a later feature; align `specs/004-durable-preparation/spec.md`, `specs/004-durable-preparation/research.md`, `specs/004-durable-preparation/plan.md`, `specs/004-durable-preparation/contracts/durable-preparation-v1.md`, and `specs/004-durable-preparation/tasks.md` without renumbering completed work

## Phase 9: Convergence

- [X] T086 Partition the release-only process-kill executor by the existing production platform contract: retain the frozen 123-boundary/167-case registry; on Windows prove the exact pre-capture `RESTORE_PLATFORM_UNSUPPORTED` refusal, exclude exactly the 17 unreachable restore cases, and execute the remaining 150 cases; on non-Windows execute all 167 cases; retain the hosted remediation evidence in `kernel/helix-coordinator-sqlite/tests/process_crash.rs`, `kernel/helix-coordinator-sqlite/tests/production_restore_conformance.rs`, `specs/004-durable-preparation/quickstart.md`, and `specs/004-durable-preparation/evidence/ci-remediation-local.md` per FR-036, SC-006, and Constitution VI (partial)

## Phase 10: Convergence

- [X] T087 Generate and fail-closed verify the exact-commit PLAN-004 supply-chain and provenance bundle, including an all-required-target CycloneDX/SPDX SBOM, license inventory and source/license texts, complete pinned RustSec output with scanner/database identity, runner/toolchain/workflow/Cargo.lock/bundled-SQLite provenance, reviewed digests, and explicitly local-only physical-M4 artifacts in `.github/workflows/durable-preparation.yml` and `specs/004-durable-preparation/evidence/` per FR-043, FR-044, plan: PLAN-004-SUPPLY, and Constitution IX (partial)
- [X] T088 Execute a non-destructive removal drill in an isolated clean copy that removes the Feature 004 crates, workspace members, catalog entry, workflow and fixtures, then proves unchanged PLAN-001 bytes/signatures, PLAN-002 outcomes, PLAN-003 rows/tests and legacy MVP-0 behavior while retaining commands, results and digests in `specs/004-durable-preparation/evidence/` per FR-044, SC-012, and Constitution X (partial)
- [X] T089 Dispatch the finalized PLAN-004 workflow for one exact commit, require successful unchanged Linux x64, macOS arm64 and Windows x64 artifacts with upload digests, attestations and preservation URLs, retain the immutable evidence record, populate the corresponding `conformance/catalog.yaml` fields without promoting the overall `pending-evidence` claim, and regenerate the roadmap per FR-043, SC-008, and plan: PLAN-004-SUPPLY (partial)
