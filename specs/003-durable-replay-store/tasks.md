# Tasks: Durable Replay Claim Store

**Input**: Design documents from `specs/003-durable-replay-store/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`,
`quickstart.md`

**Tests**: Required. Contract, persistence and security tests are written first and must
fail for the intended reason before implementation. Tests use synthetic data only.

**Organization**: Tasks are grouped by prioritized user story. Every task has an exact
path and a verifiable completion condition.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel after its phase prerequisites because it owns different
  files and does not depend on another incomplete task in the same group.
- **[Story]**: Maps to the user stories in `spec.md`.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the isolated storage crate and deterministic test scaffolding.

- [x] T001 Add `helix-replay-sqlite` to `kernel/Cargo.toml` and create `kernel/helix-replay-sqlite/Cargo.toml` with exact path/runtime/dev dependencies, empty default features, and the non-default `test-fault-injection` feature from `plan.md`
- [x] T002 [P] Create the `#![forbid(unsafe_code)]` module/export skeleton in `kernel/helix-replay-sqlite/src/lib.rs`, `kernel/helix-replay-sqlite/src/clock.rs`, `kernel/helix-replay-sqlite/src/config.rs`, `kernel/helix-replay-sqlite/src/error.rs`, `kernel/helix-replay-sqlite/src/connection.rs`, `kernel/helix-replay-sqlite/src/schema.rs`, `kernel/helix-replay-sqlite/src/claim.rs`, `kernel/helix-replay-sqlite/src/maintenance.rs`, and `kernel/helix-replay-sqlite/src/manifest.rs`
- [x] T003 [P] Create reusable synthetic temp-root, injected-clock and feature-002 fixture helpers in `kernel/helix-replay-sqlite/tests/common/mod.rs` without exposing paths or provider errors in assertion output
- [x] T004 [P] Create placeholder integration-test targets with documented ownership in `kernel/helix-replay-sqlite/tests/contract.rs`, `kernel/helix-replay-sqlite/tests/claim.rs`, `kernel/helix-replay-sqlite/tests/eligibility_integration.rs`, `kernel/helix-replay-sqlite/tests/contention.rs`, `kernel/helix-replay-sqlite/tests/process_crash.rs`, `kernel/helix-replay-sqlite/tests/deadline.rs`, `kernel/helix-replay-sqlite/tests/schema_corruption.rs`, `kernel/helix-replay-sqlite/tests/backup_restore.rs`, `kernel/helix-replay-sqlite/tests/conformance.rs`, `kernel/helix-replay-sqlite/tests/redaction.rs`, and `kernel/helix-replay-sqlite/tests/portability.rs`
- [x] T005 Resolve and inspect `kernel/Cargo.lock`, prove `rusqlite 0.40.1` resolves bundled `libsqlite3-sys 0.38.1`/SQLite 3.53.2 plus `getrandom 0.4.3`, and make `cargo check --locked -p helix-replay-sqlite --all-targets` pass without implementing a claim

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Freeze redacted types, clock/config bounds, schema identity, safe open and
storage invariants used by every story.

**Critical**: No user-story implementation begins until this phase passes.

- [x] T006 Write failing checked-construction, stable-code, `Debug`/`Display`/`Error::source`, provisioned-root and configuration-bound tests in `kernel/helix-replay-sqlite/tests/contract.rs`
- [x] T007 Implement `ReplayMonotonicClockV1`, clock/location/config error enums, `TrustedLocalStoreRootV1`, and `ReplayStoreConfigV1` with redacted diagnostics in `kernel/helix-replay-sqlite/src/clock.rs`, `kernel/helix-replay-sqlite/src/config.rs`, and `kernel/helix-replay-sqlite/src/error.rs`
- [x] T008 Write failing empty-to-v1, concurrent-initializer, wrong-application-ID, unknown/newer-version, altered-schema, non-dedicated-root and durability-profile tests in `kernel/helix-replay-sqlite/tests/schema_corruption.rs`
- [x] T009 Embed and drift-check `specs/003-durable-replay-store/contracts/replay-store-schema-v1.sql` plus `specs/003-durable-replay-store/contracts/backup-manifest-v1.schema.json`, freeze application/schema constants and define strict row decoders in `kernel/helix-replay-sqlite/src/schema.rs` and `kernel/helix-replay-sqlite/src/manifest.rs`
- [x] T010 Implement foreign-file read-before-mutate checks, WAL/FULL/trusted-schema/cell-check/autocheckpoint connection setup, transactional concurrent empty-to-v1 initialization, exact schema verification and `SqliteReplayClaimantV1::open_or_create` in `kernel/helix-replay-sqlite/src/connection.rs`, `kernel/helix-replay-sqlite/src/schema.rs`, and `kernel/helix-replay-sqlite/src/lib.rs`
- [x] T011 Clarify the implementable deadline semantics without changing v1 types/outcomes in `kernel/helix-plan-eligibility/src/replay.rs`, `specs/002-plan-eligibility/contracts/plan-eligibility-v1.md`, `specs/002-plan-eligibility/data-model.md`, and `specs/002-plan-eligibility/quickstart.md`
- [x] T012 Implement the internal owned binding projection, fresh OS-random/domain-hashed attempt identity, checked phase enum and deterministic test identity seam in `kernel/helix-replay-sqlite/src/claim.rs`
- [x] T013 Implement local unhealthy-state latching plus full metadata/count/min/max/contiguity and strict row invariant verification in `kernel/helix-replay-sqlite/src/schema.rs` and `kernel/helix-replay-sqlite/src/maintenance.rs`
- [x] T014 Run `cargo fmt --all -- --check`, `cargo clippy --locked -p helix-replay-sqlite --all-targets -- -D warnings`, and the Phase 2 tests; record any contract correction in `specs/003-durable-replay-store/research.md` before proceeding

**Checkpoint**: A dedicated local root can be initialized/reopened or rejected with one
closed redacted code; no replay claim exists yet.

---

## Phase 3: User Story 1 - Permanently claim one eligible plan (Priority: P1) MVP

**Goal**: Implement the production atomic claim, restart, exact-repeat and conflict
semantics without adding effect authority.

**Independent Test**: A fresh coherent evaluator call returns one eligible marker; after
closing/reopening, the exact call denies as already claimed and either-key variants deny
as conflicts with one intact row/generation.

### Tests for User Story 1

- [x] T015 [US1] Extend `kernel/helix-replay-sqlite/tests/contract.rs` with a compile-time `ReplayClaimantV1 + Send + Sync` assertion, receipt-binding checks, non-serialization expectations and closed five-outcome mapping, and confirm the new tests fail before claim implementation
- [x] T016 [P] [US1] Write fresh, reopen, exact repeat, nonce-only conflict, operation-only conflict, independent keys, generation exhaustion, claim-ID collision rollback and all-or-none row tests in `kernel/helix-replay-sqlite/tests/claim.rs`
- [x] T017 [P] [US1] Write end-to-end feature-002 coherent/repeat/conflict evaluation tests using the shared authentic-plan fixture in `kernel/helix-replay-sqlite/tests/eligibility_integration.rs`

### Implementation for User Story 1

- [x] T018 [US1] Implement strict lookup decoding and the two-index comparison table for exact prior, incompatible occupation and unhealthy persisted data in `kernel/helix-replay-sqlite/src/claim.rs`
- [x] T019 [US1] Implement `BEGIN IMMEDIATE`, checked singleton-generation allocation, receipt construction, one-row insertion and confirmed rollback behavior in `kernel/helix-replay-sqlite/src/claim.rs` using the reviewed v1 schema
- [x] T020 [US1] Implement phase-based commit handling and fresh-view candidate-claim-ID readback with no mutation retry in `kernel/helix-replay-sqlite/src/claim.rs` and closed internal provider mapping in `kernel/helix-replay-sqlite/src/error.rs`
- [x] T021 [US1] Implement `ReplayClaimantV1 for SqliteReplayClaimantV1<C>` and export only the intended non-authority surface from `kernel/helix-replay-sqlite/src/lib.rs`
- [x] T022 [US1] Make all US1 tests pass after a real process reopen, run the feature-001/002 regression suites, and align any observed command/outcome correction in `specs/003-durable-replay-store/quickstart.md`

**Checkpoint**: The P1 store is a usable durable replay claimant and nothing downstream
can prepare or dispatch an effect.

---

## Phase 4: User Story 2 - Resolve concurrent claims within a deadline (Priority: P2)

**Goal**: Prove one winner across threads/processes and bounded writer-lock behavior with
no detached work.

**Independent Test**: Synchronized same/conflicting-key contenders yield one durable
winner; a held writer makes a second claimant return by the controlled deadline and no
claim appears after return.

### Tests for User Story 2

- [x] T023 [P] [US2] Write expired-clock, unavailable-clock, deadline-after-writer-lock, held-writer timeout, post-commit-late and no-row-after-return tests in `kernel/helix-replay-sqlite/tests/deadline.rs`
- [x] T024 [P] [US2] Write normal and ignored 100-round x 64-thread barrier tests for exact, nonce-only, operation-only and independent bindings in `kernel/helix-replay-sqlite/tests/contention.rs`
- [x] T025 [P] [US2] Write the 8-process `READY`/`GO` probe cases and watchdog/reap assertions in `kernel/helix-replay-sqlite/tests/common/process_probe.rs` and `kernel/helix-replay-sqlite/tests/contention.rs`

### Implementation for User Story 2

- [x] T026 [US2] Calculate and override each connection busy timeout from injected clock, configured cap and binding deadline; recheck after writer acquisition/before/after commit and prohibit late positive results in `kernel/helix-replay-sqlite/src/connection.rs` and `kernel/helix-replay-sqlite/src/claim.rs`
- [x] T027 [US2] Implement the shell-free child-process readiness protocol, bounded watchdog and unconditional child kill/wait cleanup in `kernel/helix-replay-sqlite/tests/common/process_probe.rs`
- [x] T028 [US2] Pass normal plus ignored thread/process contention and controlled busy-deadline suites in release mode, preserving only aggregate redacted output under `specs/003-durable-replay-store/evidence/`

**Checkpoint**: Contention is linearizable on the local host and all controlled waits
close before/at their defined tolerance without background mutation.

---

## Phase 5: User Story 3 - Recover honestly from crashes and uncertain commits (Priority: P3)

**Goal**: Prove all-or-none crash recovery and conservative commit/readback outcome
classification without claiming power-loss evidence.

**Independent Test**: Kill a child at every frozen transaction boundary, reopen from a
fresh process, and observe either no row before commit or one complete row after commit;
synthetic commit/readback faults never turn a possible commit into unavailable.

### Tests for User Story 3

- [x] T029 [P] [US3] Write deterministic internal pre-write, confirmed-rollback, commit-started, exact-readback, conflicting-readback, healthy-absence, failed-readback and late-readback classification tests in `kernel/helix-replay-sqlite/src/claim/tests.rs`
- [x] T030 [P] [US3] Write compile-out/default-feature and frozen fault-point contract tests for `opened`, `begin_acquired`, `generation_updated`, `row_inserted`, `before_commit`, `commit_returned`, and `before_result_ack` in `kernel/helix-replay-sqlite/src/test_fault.rs`
- [x] T031 [P] [US3] Write the ignored parent/child kill, fresh-process reopen, full-integrity and all-or-none matrix in `kernel/helix-replay-sqlite/tests/process_crash.rs`

### Implementation for User Story 3

- [x] T032 [US3] Implement the private commit-result/readback seam and non-default blocking fault hook without an environment-controlled default-build surface in `kernel/helix-replay-sqlite/src/claim.rs`, `kernel/helix-replay-sqlite/src/test_fault.rs`, and `kernel/helix-replay-sqlite/src/lib.rs`
- [x] T033 [US3] Wire frozen phase notifications into initialization and claim boundaries, ensure every child flushes readiness before blocking, and guarantee parent cleanup in `kernel/helix-replay-sqlite/src/schema.rs`, `kernel/helix-replay-sqlite/src/claim.rs`, and `kernel/helix-replay-sqlite/tests/common/process_probe.rs`
- [x] T034 [US3] Pass the complete release process-kill and synthetic ambiguity matrix, archive a redacted `process-kill` summary in `specs/003-durable-replay-store/evidence/`, and explicitly state that no result is power-loss evidence

**Checkpoint**: Process crash and commit uncertainty are honest and reconciliable; no
test or output claims universal exactly-once or sector-loss survival.

---

## Phase 6: User Story 4 - Back up, restore and operate portably (Priority: P4)

**Goal**: Provide verified maintenance, a consistent online backup, safe clean restore
and unchanged three-platform behavior.

**Independent Test**: Back up a live writer in multiple steps, restore to an empty root,
verify digest/schema/integrity/invariants and reproduce all claim outcomes through the
manifest generation; every corrupt/incomplete/foreign fixture fails closed.

### Tests for User Story 4

- [x] T035 [P] [US4] Write strict backup-manifest round-trip, unknown/missing/invalid field, source-ID bound, database-digest and redacted-debug tests in `kernel/helix-replay-sqlite/tests/backup_restore.rs`
- [x] T036 [P] [US4] Write full-integrity writer-lock, passive checkpoint and explicitly quiescent truncate tests in `kernel/helix-replay-sqlite/tests/schema_corruption.rs`
- [x] T037 [P] [US4] Write positive live multi-step backup with concurrent claim plus clean-directory restore and claim-outcome reproduction tests in `kernel/helix-replay-sqlite/tests/backup_restore.rs`
- [x] T038 [P] [US4] Complete negative truncated/bit-flipped DB, bad app/schema, removed index/table, invalid row/meta, incomplete staging, missing/bad manifest, unknown file, source=destination and non-empty destination cases in `kernel/helix-replay-sqlite/tests/schema_corruption.rs` and `kernel/helix-replay-sqlite/tests/backup_restore.rs`

### Implementation for User Story 4

- [x] T039 [US4] Implement deadline-bounded full verification under the writer lock and explicit passive/quiescent-truncate checkpoint evidence in `kernel/helix-replay-sqlite/src/maintenance.rs`
- [x] T040 [US4] Implement strict `BackupManifestV1` encoding/decoding, closed database streaming SHA-256 and manifest/database cross-checks in `kernel/helix-replay-sqlite/src/manifest.rs`
- [x] T041 [US4] Implement incremental online backup into staging, deadline/page-step handling, quiescent destination verification/sync and manifest-last publication in `kernel/helix-replay-sqlite/src/maintenance.rs`
- [x] T042 [US4] Implement strict source-package verification and SQLite-API restore into a different empty root with WAL/FULL re-establishment and `VerifiedRestoreEvidenceV1` in `kernel/helix-replay-sqlite/src/maintenance.rs`
- [x] T043 [P] [US4] Create the bounded synthetic corpus and instructions in `contracts/fixtures/durable-replay-store-v1/cases.json`, `contracts/fixtures/durable-replay-store-v1/expected-outcomes.json`, and `contracts/fixtures/durable-replay-store-v1/README.md`
- [x] T044 [US4] Implement exact case-ID/outcome loading and a stable redacted summary/digest in `kernel/helix-replay-sqlite/tests/conformance.rs`
- [x] T045 [P] [US4] Implement path/nonce/identifier/digest/provider sentinels and no-OS-semantic-branch/no-legacy-runtime source checks in `kernel/helix-replay-sqlite/tests/redaction.rs` and `kernel/helix-replay-sqlite/tests/portability.rs`
- [x] T046 [US4] Pass backup/restore, corruption, conformance, redaction and portability suites locally and update exact runnable/expected behavior in `specs/003-durable-replay-store/quickstart.md`

**Checkpoint**: A consistent backup can be verified/restored, but the returned evidence
still requires external paused activation and epoch rotation.

---

## Phase 7: Polish, Evidence and Cross-Cutting Gates

**Purpose**: Converge the workspace, prove budgets/supply chain/removal and preserve
portable evidence without overstating remote or M4 status.

- [x] T047 [P] Implement the create-new-root release probe with raw samples, p50/p95/p99/max and exact redacted environment/profile metadata in `kernel/helix-replay-sqlite/examples/durable_replay_benchmark.rs`
- [x] T048 Run 500 warmups plus 10,000 sequential FULL/WAL claims, the ignored release contention/process-kill workloads and the full release backup/restore suite on the controlled local host, preserve raw immutable local artifacts in `specs/003-durable-replay-store/evidence/`, and report SC-004/SC-007 against the actual hardware only
- [x] T049 [P] Add locked fmt/clippy/test, unchanged corpus, fault-feature, artifact digest and three-host Windows/Linux/macOS-arm64 jobs in `.github/workflows/durable-replay-store.yml`
- [x] T050 Register `PLAN-003`, schema/corpus/toolchain/platforms, evidence requirements and pending immutable fields without weakening PLAN-001/002 in `conformance/catalog.yaml`
- [x] T051 Verify exact direct/native dependency tree, bundled SQLite version/source ID, licenses, vulnerability result and build provenance; record the commands/results without secrets in `specs/003-durable-replay-store/evidence/supply-chain-local.md`
- [x] T052 Run the locked whole-workspace fmt/clippy/test suite plus an inverse-dependency/removal-isolation drill excluding `helix-replay-sqlite`, and document that fallback to the in-memory claimant is test-only in `specs/003-durable-replay-store/evidence/validation-local.md`
- [x] T053 Refresh Graphify with `graphify update .`, save concise redacted `useful` records for the bounded replay-only decision, random attempt-ID correction and verified outcomes, refresh reflections, and confirm the records in `graphify-out/memory/` and `graphify-out/reflections/LESSONS.md`
- [ ] T054 Capture one successful unchanged Linux x64/macOS arm64/Windows x64 `PLAN-003` workflow for the same immutable commit and record run URLs, runner/rustc hosts, corpus/schema/artifact SHA-256, attestations and preserved locations in `conformance/catalog.yaml`
- [ ] T055 Run the controlled release probe on the actual Mac mini M4, archive its hardware/filesystem/profile/raw samples in `specs/003-durable-replay-store/evidence/`, and keep the separate `F_FULLFSYNC`/power-cut spike explicitly pending unless it is genuinely executed

---

## Phase 8: Convergence Hardening (append-only review findings)

**Purpose**: Preserve the post-implementation adversarial-review corrections as
explicit, independently replayable tasks without weakening the original plan.

- [x] T056 Implement and prove the synchronized closed root roles `LIVE_READY`, `LIVE_QUARANTINED`, `BACKUP_PACKAGE` and `RESTORE_PENDING`, a distinct recoverable live-initialization intent that cannot promote interrupted backup/restore reservations, and post-`BEGIN IMMEDIATE` waiting-writer revalidation in `kernel/helix-replay-sqlite/src/root_safety.rs`, `kernel/helix-replay-sqlite/src/config.rs`, and `kernel/helix-replay-sqlite/tests/root_safety_process.rs`
- [x] T057 Make backup/restore destinations exclusive and no-clobber across processes, freeze the three-member backup package, expose full package verification, keep restored data non-claimable, and establish/close/reopen/reverify WAL/FULL before returning restore evidence in `kernel/helix-replay-sqlite/src/maintenance.rs`, `kernel/helix-replay-sqlite/tests/backup_restore.rs`, and the feature-003 contract/model/quickstart
- [x] T058 Execute all 68 frozen corpus cases through real runtime paths under the non-default fault feature with zero blocked cases, while proving the default build has no selectable fault behavior, in `kernel/helix-replay-sqlite/src/claim.rs`, `kernel/helix-replay-sqlite/src/connection.rs`, `kernel/helix-replay-sqlite/tests/conformance_execution.rs`, and `kernel/helix-replay-sqlite/tests/portability.rs`
- [x] T059 Extend deterministic process-kill coverage to initialization, claim, checkpoint, backup and restore mutation/publication/profile boundaries, and prove a real concurrent online backup plus exact/conflict reproduction without labeling either process-kill or local tests as power-loss evidence in `kernel/helix-replay-sqlite/src/test_fault.rs`, `kernel/helix-replay-sqlite/tests/process_crash.rs`, and `kernel/helix-replay-sqlite/tests/backup_restore.rs`
- [x] T060 Replace feature 002's obsolete zero-consumer source gate with exactly one reviewed non-authority replay provider, rerun the whole-workspace and removal-isolation gates, and preserve the baseline-only formatting limitation plus local hashes/results in `kernel/helix-plan-eligibility/tests/portability.rs`, `specs/002-plan-eligibility/`, and `specs/003-durable-replay-store/evidence/validation-local.md`

---

## Phase 9: First Immutable CI Remediation (append-only findings)

**Purpose**: Preserve the first real three-host CI findings and their bounded fixes
without rewriting the implementation history or claiming T054 before a green rerun.

- [x] T061 Fix the live-root create-new/lock interposition by accepting an exact waiter-published role under lock, repairing only the exact empty live reservation, preserving unknown role bytes, and adding deterministic regressions in `kernel/helix-replay-sqlite/src/root_safety.rs` and `kernel/helix-replay-sqlite/src/root_safety/tests.rs`
- [x] T062 Make multiline source guards CRLF/LF-independent and make historical Windows filesystem tests compile and exercise equivalent Unix symlink behavior without changing production semantics in `kernel/helix-replay-sqlite/tests/initialization_faults.rs`, `kernel/helix-replay-sqlite/tests/portability.rs`, and `kernel/helixos-kernel/src/`
- [x] T063 Separate the hosted-runner contention correctness window from SC-004 latency, rerun the exact workspace/release gates, and preserve the failed-run diagnosis without labeling it successful immutable evidence in `kernel/helix-replay-sqlite/tests/contention.rs` and `specs/003-durable-replay-store/evidence/ci-remediation-local.md`

---

## Phase 10: First Remediation Rerun (append-only findings)

**Purpose**: Preserve the additional interleavings and hosted-runner limit exposed by
the first remediation rerun without closing the unchanged three-host evidence gate.

- [x] T064 Eliminate both pre-lock intent/role TOCTOU variants by inspecting intent state before a final monotonic role-path sample, preserving the original error when no role exists, and adding deterministic false/error regressions in `kernel/helix-replay-sqlite/src/root_safety.rs` and `kernel/helix-replay-sqlite/src/root_safety/tests.rs`
- [x] T065 Give the concurrent-schema correctness fixture a hosted-runner budget distinct from SC-004 and preserve the payload-free public error code in future failures without changing production limits in `kernel/helix-replay-sqlite/tests/schema_corruption.rs`
- [x] T066 Inspect every job of the immutable `6e3940d40b5661ece7b4ed53ce9e7c8f598e4ff2` rerun, record its partial macOS/Linux successes and exact remaining failures, rerun the bounded local gates, and retain T054 as pending in `specs/003-durable-replay-store/evidence/ci-remediation-local.md` and `conformance/catalog.yaml`

---

## Acceptance Traceability

| Requirement / criterion | Primary tasks |
|---|---|
| FR-001 | T001-T005, T015, T021-T022 |
| FR-002-FR-006 | T008-T010, T016, T018-T021, T029-T034 |
| FR-007-FR-010 | T012, T016, T019-T020, T029-T034 |
| FR-011-FR-012 | T011-T012, T023, T026, T028-T029 |
| FR-013-FR-017 | T008-T010, T013-T014, T031, T036, T039, T056-T057, T061, T064 |
| FR-018-FR-022 | T035-T042, T046, T054-T055, T057, T059 |
| FR-023-FR-026 | T006-T007, T009, T015, T045, T051-T053 |
| FR-027-FR-029 | T024-T025, T031-T034, T043-T046, T049, T054, T058-T066 |
| FR-030-FR-031 | T015, T021-T022, T045, T050-T053, T060 |
| SC-001 | T016-T022, T043-T046, T058 |
| SC-002 | T024-T025, T027-T028, T048, T054, T056, T059, T061, T063-T066 |
| SC-003 | T029-T034, T048, T054, T059, T061, T064 |
| SC-004 | T023, T026, T028, T048, T055 |
| SC-005 | T035-T042, T046, T048, T054, T057, T059 |
| SC-006 | T043-T046, T049-T050, T054, T058, T060-T066 |
| SC-007 | T047-T048, T055 |
| SC-008 | T006-T007, T015, T045, T052, T054, T060 |
| SC-009 | T005, T009-T010, T035-T042, T049-T052, T054, T056-T057, T060 |

## Dependencies and Execution Order

### Phase dependencies

- Phase 1 has no dependencies.
- Phase 2 depends on T001-T005 and blocks all user stories.
- US1 depends on Phase 2 and is the MVP production claimant.
- US2, US3 and US4 depend on the US1 claim core but remain independently testable
  through their own contention, crash and restore journeys.
- US3 reuses the US2 child-process protocol after T027; its private classification tests
  T029 can start as soon as US1 exists.
- US4 maintenance can be developed in parallel with US2/US3 once US1 is stable.
- Phase 7 local convergence depends on selected user stories. T054 requires remote CI;
  T055 requires the user's physical M4 and neither can be checked from Windows evidence.

### Parallel opportunities

- T002-T004 own separate setup files after T001.
- T006 and T008 are different failing test targets; T009 can prepare reviewed constants.
- T016 and T017 are independent US1 test files.
- T023-T025 are independent US2 test workloads.
- T029-T031 cover separate unit/fault/process layers.
- T035-T038 and later T043/T045 own separate US4 files.
- T047 and T049 can run alongside documentation/catalog preparation after APIs freeze.
- Tasks touching `kernel/Cargo.lock`, `claim.rs`, `maintenance.rs`,
  `conformance/catalog.yaml` or the same evidence file run sequentially.

## Parallel Examples

### User Story 1

```text
T016: persistence/repeat/conflict tests in tests/claim.rs
T017: evaluator integration in tests/eligibility_integration.rs
```

### User Story 2

```text
T023: controlled deadline tests
T024: thread contention tests
T025: process contention protocol/tests
```

### User Story 3

```text
T029: private outcome-classification unit tests
T030: test-feature/fault-point contract tests
T031: parent/child process-kill integration matrix
```

### User Story 4

```text
T035: manifest tests
T036: integrity/checkpoint tests
T037: positive backup/restore tests
T038: negative corruption/package tests
```

## Implementation Strategy

### MVP first

1. Complete T001-T014.
2. Write T015-T017 and verify they fail for missing claim behavior.
3. Implement T018-T021.
4. Complete T022 and stop to validate the durable P1 transition independently.

### Incremental delivery

1. MVP: durable fresh/repeat/conflict claim and restart.
2. Add bounded thread/process contention and deadline proof.
3. Add deterministic process-crash and ambiguity proof.
4. Add integrity/checkpoint, online backup, clean restore and portable corpus.
5. Converge performance, supply chain, removal, CI and Graphify evidence.

### Removal and later transition

- Removal deletes one leaf workspace member, its fixture/workflow/spec artifacts and
  production registration only after affected epochs are retired. Feature 001/002 wire
  and evaluator semantics remain.
- No task adapts the legacy JSONL/in-memory runtime as production replay storage.
- Feature 004 must separately specify fresh comparison, budget/recovery reservation and
  durable `PREPARING`; no adapter may consume this store receipt directly.

## Task Summary

- Total tasks: 66
- Setup: 5
- Foundational: 9
- US1: 8
- US2: 6
- US3: 6
- US4: 12
- Polish/evidence: 9
- Convergence hardening: 5
- First immutable CI remediation: 3
- First remediation rerun: 3
- Suggested MVP scope: T001-T022
- Suggested locally actionable scope before external evidence: T001-T053 and T056-T066
- External unchanged CI: T054
- Physical Mac mini M4 evidence: T055
- Every task row follows the required checkbox, sequential ID, optional `[P]`, story
  label and exact path format.
