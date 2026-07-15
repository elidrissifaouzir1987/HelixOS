# Tasks: Durable One-Shot Dispatch

**Input**: Design documents from `specs/005-durable-dispatch/`

**Prerequisites**: [spec.md](spec.md), [plan.md](plan.md),
[research.md](research.md), [data-model.md](data-model.md),
[contracts/](contracts/), [quickstart.md](quickstart.md)

**Tests**: Required by the specification and Constitution. Story tests are written first
and must demonstrate the intended failure before authority-bearing implementation lands.

**Organization**: Tasks are grouped by user story. PLAN-005 stops after durable
adapter consumption and effective `EXECUTING`; no real host effect or execution-token API
is permitted.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can proceed in parallel in different files after named prerequisites.
- **[Story]**: Maps the task to one independently testable user story.
- Unrelated local modifications under `helixos-kernel`, `helixos-mcp-shim` and
  `helixos-provision` are user-owned and excluded from every PLAN-005 task/commit.

## Phase 1: Setup and Frozen Baseline

**Purpose**: Establish exact ownership, dependencies and generated project tracking
without changing PLAN-001 through PLAN-004 authority or evidence.

- [x] T001 Record Graphify reflection, merged PLAN-004 source/removal baseline `6f8dfdd5194792e8592cd10ebaaf8828833effbe`, exact protected-file inventory and the 27 excluded user Rust paths in `specs/005-durable-dispatch/evidence/README.md`
- [x] T002 Add `helix-dispatch-contracts`, `helix-plan-dispatch` and `helix-dispatch-inbox-sqlite` as edition-2021 `unsafe`-forbidden workspace members with exact dependency pins in `kernel/Cargo.toml`, `kernel/Cargo.lock`, `kernel/helix-dispatch-contracts/Cargo.toml`, `kernel/helix-plan-dispatch/Cargo.toml` and `kernel/helix-dispatch-inbox-sqlite/Cargo.toml`
- [x] T003 [P] Create minimal crate roots with redacted public surfaces and no token/legacy dependency in `kernel/helix-dispatch-contracts/src/lib.rs`, `kernel/helix-plan-dispatch/src/lib.rs` and `kernel/helix-dispatch-inbox-sqlite/src/lib.rs`
- [x] T004 [P] Create exhaustive grant/receipt JSON schemas plus the versioned fixture inventory and expected outcomes in `specs/005-durable-dispatch/contracts/execution-grant-v1.schema.json`, `specs/005-durable-dispatch/contracts/execution-receipt-v1.schema.json`, `contracts/fixtures/durable-dispatch-v1/README.md`, `contracts/fixtures/durable-dispatch-v1/cases.json` and `contracts/fixtures/durable-dispatch-v1/expected-outcomes.json`
- [x] T005 Pin all PLAN-005 JSON/SQL/fixture files to LF and exclude only generated evidence outputs in `.gitattributes` and `.gitignore`
- [x] T006 Run the locked baseline and record exact prerequisite/test/toolchain/schema/fault-registry digests without altering frozen inputs in `specs/005-durable-dispatch/evidence/baseline.md`

---

## Phase 2: Foundational Contracts, Types and Store Versions (Blocking)

**Purpose**: Close wire, type, migration and trust boundaries before any user story can
create dispatch authority.

**⚠️ CRITICAL**: No story implementation begins until T007–T020 pass.

- [x] T007 [P] Write failing exhaustive-schema plus grant canonicalization/signature/domain/key-purpose/version/size/tamper tests from the frozen corpus in `kernel/helix-dispatch-contracts/tests/grant_contract.rs`
- [x] T008 [P] Write failing exhaustive-schema plus receipt decision/signature/domain/key-purpose/cross-grant/cross-adapter tests, including the exact post-`RECEIVED` `REFUSED_DEFINITE` reason set and proof that all four pre-`RECEIVED` refusals cannot serialize as receipts, in `kernel/helix-dispatch-contracts/tests/receipt_contract.rs`
- [x] T009 [P] Write failing redacted-Debug/error/public-surface and no-private-path/secret tests in `kernel/helix-dispatch-contracts/tests/redaction.rs`
- [x] T010 Implement bounded identifiers, safe integers, canonical JSON, digest/error helpers and distinct signer/resolver trust-purpose traits in `kernel/helix-dispatch-contracts/src/validation.rs`, `kernel/helix-dispatch-contracts/src/canonical.rs`, `kernel/helix-dispatch-contracts/src/digest.rs`, `kernel/helix-dispatch-contracts/src/crypto.rs` and `kernel/helix-dispatch-contracts/src/error.rs`
- [x] T011 Implement strict protected/signed/authentic `ExecutionGrantV1` with exact 5,000 ms lifetime and complete binding validation in `kernel/helix-dispatch-contracts/src/grant.rs`
- [x] T012 Implement protected/signed/authentic `ExecutionReceiptV1` with closed `CONSUMED` and post-`RECEIVED` `REFUSED_DEFINITE` reasons exactly `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` and `ADAPTER_PAUSED`, plus historical public-key verification that treats a retained post-expiry receipt only as evidence of its prior decision, in `kernel/helix-dispatch-contracts/src/receipt.rs`
- [x] T013 Make T007–T012 pass against byte-exact fixtures and export only reviewed contract types/functions in `kernel/helix-dispatch-contracts/src/lib.rs`
- [x] T014 [P] Write compile/source contract failures proving no Serde/Clone/public constructor for positive dispatch candidates/permits and no execution-token API in `kernel/helix-plan-dispatch/tests/contract.rs`
- [x] T015 [P] Write closed outcome/reason/version and redaction tests in `kernel/helix-plan-dispatch/tests/outcome.rs` and `kernel/helix-plan-dispatch/tests/redaction.rs`
- [x] T016 Define untrusted lookup input, private ready context, attempt identity, authority-view/provider traits and fixed guard classes in `kernel/helix-plan-dispatch/src/request.rs`, `kernel/helix-plan-dispatch/src/authority.rs`, `kernel/helix-plan-dispatch/src/attempt.rs` and `kernel/helix-plan-dispatch/src/guard.rs`
- [x] T017 Define coordinator-store, transport/handoff, inbox/readback, clock/entropy/signer and PAUSE/control traits without SQLite, OS, network or legacy dependencies in `kernel/helix-plan-dispatch/src/store.rs`, `kernel/helix-plan-dispatch/src/transport.rs`, `kernel/helix-plan-dispatch/src/inbox.rs` and `kernel/helix-plan-dispatch/src/control.rs`
- [x] T018 Define closed request/delivery/reconciliation outcomes and typed payload-free reason codes in `kernel/helix-plan-dispatch/src/outcome.rs`
- [x] T019 [P] Write failing strict V1/V2/open/migration/old-binary/no-auto-upgrade contract tests in `kernel/helix-coordinator-sqlite/tests/dispatch_migration.rs`
- [x] T020 Preserve `SqliteCoordinatorStoreV1` and PLAN-004 DDL/digest/allowlists byte-semantically, add the additive reviewed overlay digest, composite graph invariants, append-only guards, RESTORE_PENDING authority blocks and a private explicit V2 type seam in `kernel/helix-coordinator-sqlite/src/dispatch_schema.rs`, `kernel/helix-coordinator-sqlite/src/schema.rs` and `kernel/helix-coordinator-sqlite/src/lib.rs`

**Checkpoint**: Canonical wire contracts, portable traits, closed outcomes and strict
store-version boundaries compile and pass independently; no dispatch transition exists.

---

## Phase 3: User Story 1 — Dispatch One Prepared Operation Once (Priority: P1) 🎯 MVP

**Goal**: Reload one authoritative current PLAN-004 record, retain ordered guards and a
fresh permit, then atomically store exact signed bytes with one effective
`PREPARING -> DISPATCHING` overlay transition/outbox before delivery.

**Independent Test**: Concurrent/thread/process requests using only the lookup input
produce one exact grant/operation/nonce and one dispatch transition; stale/restored/
legacy/mismatched authority creates no deliverable grant.

### Tests for User Story 1

- [x] T021 [P] [US1] Write failing lookup-only input and durable reload tests covering missing/torn/restored/failed/quarantined/already-overlaid records in `kernel/helix-coordinator-sqlite/tests/dispatch.rs`
- [x] T022 [P] [US1] Write failing single-field authority-generation/digest/epoch/deadline/destination/signing-profile mutation tests in `kernel/helix-plan-dispatch/tests/authority.rs`
- [x] T023 [P] [US1] Write failing exact-capacity, over-by-one, deadline-equality and 5,000 ms ceiling tests in `kernel/helix-plan-dispatch/tests/bounds.rs`
- [x] T024 [P] [US1] Write failing ordered-guard/PAUSE/HALT/revocation/owner-loss/permit-deadline tests in `kernel/helix-plan-dispatch/tests/guard.rs`
- [x] T025 [P] [US1] Write failing 10,000 duplicate, 100 x 64-thread and 20 x 8-process contention tests proving one grant/operation/nonce in `kernel/helix-coordinator-sqlite/tests/dispatch_contention.rs`
- [x] T026 [P] [US1] Write failing partial-member/uncertain-commit/exact-attempt-readback tests for the canonical dispatch transaction in `kernel/helix-coordinator-sqlite/tests/dispatch_commit.rs`

### Implementation for User Story 1

- [x] T027 [US1] Implement explicit paused/quiescent V1-to-V2 migration, migration receipt, exact uncertain readback, V1 rejection of V2 and downgrade refusal in `kernel/helix-coordinator-sqlite/src/dispatch_schema.rs` and `kernel/helix-coordinator-sqlite/src/maintenance.rs`
- [x] T028 [US1] Implement full V2 durable reload and invariant classification from lookup key/expected bindings without accepting PLAN-004 markers or direct rows in `kernel/helix-coordinator-sqlite/src/dispatch_preflight.rs`
- [x] T029 [US1] Implement injected trusted authority captures, preliminary/final context digesting and exact comparison in `kernel/helix-plan-dispatch/src/authority.rs` and `kernel/helix-plan-dispatch/src/compare.rs`
- [x] T030 [US1] Implement the PLAN-004-compatible global guard order and non-cloneable linearizable dispatch permit with PAUSE/HALT/deadman behavior in `kernel/helix-plan-dispatch/src/guard.rs` and `kernel/helix-plan-dispatch/src/commit_gate.rs`
- [x] T031 [US1] Implement coordinator-owned attempt/grant/nonce creation, effect-descriptor projection and exact grant signing under the dedicated purpose/domain in `kernel/helix-plan-dispatch/src/coordinator.rs`
- [x] T032 [US1] Implement V2 overlay tables/invariants for comparison, exact grant bytes, current records, transitions, outbox and events in `kernel/helix-coordinator-sqlite/src/dispatch_schema.rs` and `kernel/helix-coordinator-sqlite/src/dispatch.rs`
- [x] T033 [US1] Implement the canonical all-or-none `PREPARING -> DISPATCHING` transaction under the retained permit with no transport call in `kernel/helix-coordinator-sqlite/src/dispatch.rs` and `kernel/helix-coordinator-sqlite/src/dispatch_outbox.rs`
- [x] T034 [US1] Implement confirmed-rollback versus uncertain-commit custody and exact attempt readback without resign/retry in `kernel/helix-coordinator-sqlite/src/dispatch_readback.rs`
- [x] T035 [US1] Block PLAN-004 known-failure release after any dispatch overlay and retain held reservation/recovery custody in `kernel/helix-coordinator-sqlite/src/failure.rs` and `kernel/helix-coordinator-sqlite/src/dispatch.rs`
- [x] T036 [US1] Implement permanent redacted dispatch event projections and bounded metrics with no canonical/internal value leakage in `kernel/helix-coordinator-sqlite/src/dispatch_events.rs`
- [x] T037 [US1] Integrate the portable dispatch coordinator with `SqliteCoordinatorStoreV2` while keeping V1/public restore authority unchanged in `kernel/helix-coordinator-sqlite/src/lib.rs` and `kernel/helix-plan-dispatch/src/lib.rs`
- [x] T038 [US1] Make T021–T037 and all PLAN-001 through PLAN-004 prerequisite tests pass, then record the MVP boundary/evidence/nonclaims in `specs/005-durable-dispatch/evidence/us1-dispatch.md`

**Checkpoint**: User Story 1 independently produces one durable non-delivered grant and
one `DISPATCHING` outbox member; the adapter and real effect remain absent.

---

## Phase 4: User Story 2 — Consume a Grant Once and Recover Its Receipt (Priority: P1)

**Goal**: In a separate adapter trust domain, durably receive, independently fence,
consume once and sign one receipt; the coordinator accepts only exact `CONSUMED`
evidence to enter effective `EXECUTING` with no effect/token API.

**Independent Test**: Exact duplicate delivery before/after restart returns one retained
receipt, conflicting grant/operation/nonce authorizes zero consumption, stale epoch
denies, and one exact receipt alone advances the coordinator.

### Tests for User Story 2

- [x] T039 [P] [US2] Write failing adapter application/schema/root/PRAGMA/invariant and unsupported-version tests in `kernel/helix-dispatch-inbox-sqlite/tests/contract.rs`
- [x] T040 [P] [US2] Write failing receive-before-acknowledge and consume/post-`RECEIVED` definite-refusal-plus-receipt atomicity tests, including the exact three signed refusal reasons and durable no-receipt behavior for the four pre-`RECEIVED` refusals, in `kernel/helix-dispatch-inbox-sqlite/tests/consume_once.rs`
- [x] T041 [P] [US2] Write failing exact duplicate and grant/operation/nonce/digest/key-rotation conflict tests, then drive exactly the SC-001 matrix of 10,000 repeated requests, 100 x 64-thread rounds and 20 x 8-process rounds through the adapter boundary to prove one consumption and zero duplicate consumptions, in `kernel/helix-dispatch-inbox-sqlite/tests/contention.rs`
- [x] T042 [P] [US2] Write failing independent epoch observer unavailable/stale/mismatch/change-before-consume tests in `kernel/helix-dispatch-inbox-sqlite/tests/stale_epoch.rs`
- [x] T043 [P] [US2] Write failing receipt signer purpose/domain/revocation/history and cross-binding tests in `kernel/helix-dispatch-inbox-sqlite/tests/receipt.rs`
- [x] T044 [P] [US2] Write failing coordinator receipt verification, exact timely `DISPATCHING -> EXECUTING`, late-receipt reconciliation custody and no-effect/no-success tests in `kernel/helix-coordinator-sqlite/tests/dispatch_receipt.rs`

### Implementation for User Story 2

- [x] T045 [US2] Implement provisioner-bound inbox config, root identity, strict connection profile and exact schema verifier in `kernel/helix-dispatch-inbox-sqlite/src/config.rs`, `kernel/helix-dispatch-inbox-sqlite/src/root_safety.rs`, `kernel/helix-dispatch-inbox-sqlite/src/connection.rs` and `kernel/helix-dispatch-inbox-sqlite/src/schema.rs`
- [x] T046 [US2] Implement injected independent supervisor epoch observer and bounded clock/deadline handling in `kernel/helix-dispatch-inbox-sqlite/src/epoch.rs` and `kernel/helix-dispatch-inbox-sqlite/src/clock.rs`
- [x] T047 [US2] Implement strict canonical grant decode/trust/destination/protocol/capability/capacity validation and first `ABSENT -> RECEIVED` transaction before acknowledgement; `DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`, `CAPABILITY_MISMATCH` and `INBOX_CAPACITY_EXHAUSTED` must stop before `RECEIVED`, retain durable redacted diagnostics/quarantine and produce no receipt or release proof, in `kernel/helix-dispatch-inbox-sqlite/src/inbox.rs`
- [x] T048 [US2] Implement create-only grant/operation/nonce uniqueness, exact duplicate readback and permanent conflict/quarantine evidence in `kernel/helix-dispatch-inbox-sqlite/src/inbox.rs` and `kernel/helix-dispatch-inbox-sqlite/src/quarantine.rs`
- [x] T049 [US2] Implement second epoch/deadline/pause revalidation and atomic `RECEIVED -> CONSUMED`/`REFUSED` plus closed signed receipt/event, limiting `REFUSED_DEFINITE` exactly to `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` and `ADAPTER_PAUSED`, in `kernel/helix-dispatch-inbox-sqlite/src/receipt.rs` and `kernel/helix-dispatch-inbox-sqlite/src/events.rs`
- [x] T050 [US2] Implement exact retained inbox/receipt readback after restart with no re-consumption/resigning in `kernel/helix-dispatch-inbox-sqlite/src/readback.rs`
- [x] T051 [US2] Prove and enforce absence of public/Serde/Clone execution-token or effect-handoff surfaces in `kernel/helix-dispatch-inbox-sqlite/src/lib.rs` and `kernel/helix-dispatch-inbox-sqlite/tests/contract.rs`
- [x] T052 [US2] Implement coordinator strict receipt verification, permanent receipt row and all-or-none timely `DISPATCHING -> EXECUTING` transition/event while routing any post-unknown receipt only to reconciliation custody in `kernel/helix-coordinator-sqlite/src/dispatch_receipt.rs`
- [x] T053 [US2] Integrate the deterministic no-effect inbox adapter through portable traits without sharing coordinator storage or signing authority in `kernel/helix-plan-dispatch/src/inbox.rs` and `kernel/helix-plan-dispatch/src/coordinator.rs`
- [x] T054 [US2] Add seeded redaction/public-event/metrics tests for both domains in `kernel/helix-dispatch-inbox-sqlite/tests/redaction.rs` and `kernel/helix-coordinator-sqlite/tests/dispatch_redaction.rs`
- [x] T055 [US2] Make T039–T054 pass across restarts, run the same complete SC-001 matrix end to end from coordinator dispatch through exactly one adapter consumption in `kernel/helix-coordinator-sqlite/tests/dispatch_end_to_end_contention.rs`, and record exact one-shot/no-effect counts and evidence in `specs/005-durable-dispatch/evidence/us2-inbox-receipt.md`

**Checkpoint**: User Stories 1 and 2 independently prove one grant, one adapter
consumption and one retained receipt. `EXECUTING` does not mean an effect or success.

---

## Phase 5: User Story 3 — Fail Closed Across Crashes and Ambiguous Transport (Priority: P2)

**Goal**: Classify confirmed no-send, exact consumption, definite refusal and possible
handoff without blind grant replacement; unresolved delivery becomes
`OUTCOME_UNKNOWN` and remains reconcilable.

**Independent Test**: One closed fault inventory plus lost-ack/process-kill cases yields
no duplicate consumption, false absence/success, late mutation or replacement grant;
control-lane requests remain bounded under saturation.

### Tests for User Story 3

- [x] T056 [P] [US3] Consume the closed ordered PLAN-005 registry of exactly 90 boundaries and 180 declared in-process/process-kill cases from `specs/005-durable-dispatch/contracts/fault-boundaries-v1.json` and write failing cardinality/order/reachability/one-fault expectations without changing PLAN-004's registry in `kernel/helix-plan-dispatch/src/test_fault.rs` and `contracts/fixtures/durable-dispatch-v1/fault-boundaries.json`
- [x] T057 [P] [US3] Write failing lost receive/consume acknowledgement, exact redelivery, post-expiry verification of a previously retained receipt without authority renewal, and retained receipt recovery tests in `kernel/helix-plan-dispatch/tests/ambiguity.rs`
- [x] T058 [P] [US3] Write failing confirmed-no-send versus possible-handoff and empty-inbox-not-absence tests; prove exactly one automatic sequence per possible-handoff attempt, at most four observations after 0/25/75/175 ms backoffs (offsets 0/25/100/275 ms), a hard 500 ms budget from the first observation truncated by earlier caller/grant deadlines, and exhaustion/unavailability custody without absence or an automatic loop, in `kernel/helix-coordinator-sqlite/tests/dispatch_readback.rs`
- [x] T059 [P] [US3] Write failing fenced/quiesced transport, matching root/epoch/generation and deadline-closure definite-absence tests in `kernel/helix-plan-dispatch/tests/reconciliation.rs`
- [x] T060 [P] [US3] Write failing transaction/process-kill cases for coordinator, handoff, adapter receive/consume/receipt and coordinator readback in `kernel/helix-coordinator-sqlite/tests/dispatch_faults.rs` and `kernel/helix-dispatch-inbox-sqlite/tests/process_crash.rs`
- [x] T061 [P] [US3] Write failing cancellation/PAUSE/audit-before-versus-after-handoff tests in `kernel/helix-plan-dispatch/tests/control.rs`
- [x] T062 [P] [US3] Write failing 1,024 ordinary/32 control capacity, 10,000 duplicate flood, 50 ms backpressure and 100 ms control p99 tests in `kernel/helix-dispatch-inbox-sqlite/tests/queue_control.rs` and `kernel/helix-coordinator-sqlite/tests/dispatch_queue_control.rs`

### Implementation for User Story 3

- [x] T063 [US3] Implement the closed fault enum/registry, private non-default probes and one identical in-process/process-driver selection path in `kernel/helix-plan-dispatch/src/test_fault.rs`, `kernel/helix-coordinator-sqlite/src/dispatch_fault.rs` and `kernel/helix-dispatch-inbox-sqlite/src/test_fault.rs`
- [x] T064 [US3] Implement exact outbox loading, pause/deadline precheck and linearizable per-grant handoff/attempt evidence in `kernel/helix-plan-dispatch/src/transport.rs` and `kernel/helix-coordinator-sqlite/src/dispatch_outbox.rs`
- [x] T065 [US3] Implement byte-identical bounded redelivery and exact adapter inbox/receipt readback without renewal/resigning/re-consumption: exactly one automatic sequence per possible-handoff attempt, at most four observations after 0/25/75/175 ms backoffs (offsets 0/25/100/275 ms), hard-stopped at 500 ms from the first observation or an earlier caller/grant deadline, with retained post-expiry receipts accepted only as evidence of their prior decision and exhaustion/unavailability routed once to unknown/reconciliation custody in `kernel/helix-plan-dispatch/src/coordinator.rs`
- [x] T066 [US3] Implement fenced definite-absence classification and no-consumption tombstone custody for signed permanent post-`RECEIVED` `REFUSED_DEFINITE` receipts limited exactly to `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` and `ADAPTER_PAUSED`, while pre-`RECEIVED` destination/protocol/capability/capacity refusals remain no-receipt diagnostics that cannot release the hold, in `kernel/helix-plan-dispatch/src/reconciliation.rs` and `kernel/helix-dispatch-inbox-sqlite/src/receipt.rs`
- [x] T067 [US3] Implement `DISPATCHING -> OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED`, keep late consumed evidence in reconciliation custody, and for exact no-consumption only append final overlay/base `FAILED`, release the exact reservation once and retain receipt/reconciliation/both event chains atomically in `kernel/helix-coordinator-sqlite/src/dispatch_reconciliation.rs`
- [x] T068 [US3] Implement cancellation/PAUSE/HALT/audit-pending behavior before and after possible handoff with no deletion or false pre-dispatch failure in `kernel/helix-plan-dispatch/src/control.rs` and `kernel/helix-coordinator-sqlite/src/dispatch.rs`
- [x] T069 [US3] Implement bounded ordinary and reserved control-lane accounting/backpressure/payload-free metrics and the exact 100-trial measurement surface in `kernel/helix-plan-dispatch/src/queue.rs`, `kernel/helix-coordinator-sqlite/src/dispatch_queue.rs` and `kernel/helix-dispatch-inbox-sqlite/src/queue.rs`
- [x] T070 [US3] Run the complete closed 90-boundary/180-declared-case fault/lost-ack/flood matrix, prove every ID and case is reached and record process-kill versus power-loss limits in `specs/005-durable-dispatch/evidence/us3-fault-ambiguity.md`

**Checkpoint**: User Stories 1–3 cover normal, duplicate, refusal, lost-response,
process-kill, overload and unknown/reconciliation behavior without a real effect.

---

## Phase 6: User Story 4 — Restore and Remove Dispatch Safely (Priority: P3)

**Goal**: Preserve one-shot history across upgrade/backup/clean restore and prove PLAN-005
can be removed without reviving authority or changing prerequisite behavior.

**Independent Test**: Every lifecycle backup restores into new paused roots with zero
old redelivery, detects all seeded orphans/conflicts, retains public verifier history and
passes isolated removal against baseline `6f8dfdd`.

### Tests for User Story 4

- [x] T071 [P] [US4] Write failing strict coordinator-v2/adapter-v1 manifest constants, detailed generations/counts/backup order, unique required key purposes, signature-domain, substitution/private-key-exclusion and sequential-cut tests in `kernel/helix-coordinator-sqlite/tests/dispatch_restore.rs` and `kernel/helix-dispatch-inbox-sqlite/tests/backup_restore.rs`
- [x] T072 [P] [US4] Write failing new-root/new-epoch/RESTORE_PENDING/PAUSED/zero-redelivery and possible-consumption-quarantine tests in `kernel/helix-coordinator-sqlite/tests/dispatch_restore.rs`
- [x] T073 [P] [US4] Write failing orphan grant/inbox/receipt, rollback/truncation, generation reuse and cross-store disagreement tests in `kernel/helix-coordinator-sqlite/tests/dispatch_corruption.rs` and `kernel/helix-dispatch-inbox-sqlite/tests/corruption.rs`
- [x] T074 [P] [US4] Write failing compatible-open/public-key-history, old-binary refusal, no-in-place-downgrade and no-pruning tests in `kernel/helix-coordinator-sqlite/tests/dispatch_migration.rs` and `kernel/helix-dispatch-inbox-sqlite/tests/retention.rs`

### Implementation for User Story 4

- [x] T075 [US4] Implement coordinator V2 and adapter inbox canonical manifests/inventories plus public-key trust/revocation history codecs in `kernel/helix-coordinator-sqlite/src/dispatch_manifest.rs` and `kernel/helix-dispatch-inbox-sqlite/src/manifest.rs`
- [x] T076 [US4] Implement PAUSE/quiescence fencing and independent online backups with signed manifest-last cross-store index and no private-key custody in `kernel/helix-coordinator-sqlite/src/maintenance.rs` and `kernel/helix-dispatch-inbox-sqlite/src/maintenance.rs`
- [x] T077 [US4] Implement empty-root restore verification, new identities/epochs, RESTORE_PENDING/PAUSED and zero-redelivery/quarantine behavior in `kernel/helix-coordinator-sqlite/src/maintenance.rs` and `kernel/helix-dispatch-inbox-sqlite/src/maintenance.rs`
- [x] T078 [US4] Implement cross-store orphan/conflict/rollback/truncation/generation-reuse detection with no activation authority in `kernel/helix-coordinator-sqlite/src/dispatch_quarantine.rs` and `kernel/helix-dispatch-inbox-sqlite/src/quarantine.rs`
- [x] T079 [US4] Enforce permanent v1 retention/no-delete/no-reuse and explicit at-rest/secure-erasure nonclaims in `kernel/helix-coordinator-sqlite/src/dispatch_schema.rs` and `kernel/helix-dispatch-inbox-sqlite/src/schema.rs`
- [x] T080 [US4] Add one unchanged end-to-end no-effect conformance corpus covering migration, dispatch, consume, lost-ack, unknown and clean restore in `kernel/helix-plan-dispatch/tests/conformance.rs` and `kernel/helix-coordinator-sqlite/examples/durable_dispatch_corpus.rs`
- [x] T081 [US4] Implement the isolated PLAN-005 removal driver and protected baseline manifest in `tools/plan005_removal_drill.py` and `specs/005-durable-dispatch/evidence/removal-protected-files.json`
- [x] T082 [US4] Run restore/corruption/retention/removal evidence, prove all PLAN-001 through PLAN-004 protected bytes/tests remain intact and document subsystem-only limits in `specs/005-durable-dispatch/evidence/us4-restore-removal.md`

**Checkpoint**: All four stories are independently testable; old authority never revives
and no full-machine/Tier 1 claim is made.

---

## Phase 7: Polish, Performance, Supply Chain and Immutable Evidence

**Purpose**: Close cross-cutting acceptance, CI, roadmap and exact-commit evidence while
preserving honest `pending-evidence` status.

- [x] T083 [P] Run at least 100,000 generated grant/receipt mutation cases and retain the deterministic seed/summary in `kernel/helix-dispatch-contracts/tests/property.rs` and `specs/005-durable-dispatch/evidence/property-summary.md`
- [x] T084 [P] Add the controlled 500-warmup/10,000-sample guard-to-consumed-receipt benchmark with exact profile metadata and raw JSON output in `kernel/helix-coordinator-sqlite/examples/durable_dispatch_benchmark.rs`
- [x] T085 [P] Add source/dependency/egress/secret/private-path/frozen-registry/removal-allowlist contract tests in `kernel/helix-plan-dispatch/tests/portability.rs`, `kernel/helix-dispatch-inbox-sqlite/tests/portability.rs` and `tools/tests/test_plan005_evidence.py`
- [x] T086 Add PLAN-005 acceptance IDs, owners, fixtures, thresholds, external physical gates and `claim_status: pending-evidence` to `conformance/catalog.yaml`
- [x] T087 Generate the roadmap from `tasks.md` and the catalogue, verify PLAN-005 counts/phase/status and never hand-edit generated data in `docs/roadmap/roadmap-data.js` via `tools/update_roadmap.py`
- [x] T088 Implement the PLAN-005 supply-chain builder/verifier with union closure/full adjacency, exact lock/bundled SQLite source/features, licenses, pinned RustSec/SPDX, SBOM/provenance, semantic tamper and secret/path scans in `tools/plan005_supply_chain.py` and `tools/tests/test_plan005_evidence.py`
- [x] T089 Create the unchanged Linux x86_64/macOS arm64/Windows x64 workflow with exact host checks, prerequisite chain, contract/fault/migration/restore/overload gates, release bundle and four attestations in `.github/workflows/durable-dispatch.yml`
- [x] T090 Run format, locked check/Clippy/workspace tests, all PLAN-005 focused suites, JSON/SQL/actionlint/roadmap/tool tests and `git diff --check`, then retain exact command/result/nonclaim evidence in `specs/005-durable-dispatch/evidence/local-validation.md`
- [x] T091 Run the physical Mac mini M4 benchmark only when exact hardware/OS/store metadata is available; otherwise retain a clearly diagnostic result and keep `PERF-002` pending in `specs/005-durable-dispatch/evidence/m4-benchmark.md`
- [x] T092 Run SpecKit Converge and Analyze, require 100% FR/SC-to-task coverage and zero critical/high consistency findings, then append any new build-scope tasks to `specs/005-durable-dispatch/tasks.md`
- [x] T093 Refresh Graphify after code changes, save secret-free design/test/removal results and regenerate reflections in `graphify-out/graph.json`, `graphify-out/memory/` and `graphify-out/reflections/LESSONS.md`
- [x] T094 Commit only PLAN-005-owned files, push `codex/plan-005-durable-dispatch`, dispatch one exact successful immutable workflow run, verify all artifact digests/attestations/release bundle/removal semantics, catalog the evidence without promoting physical claims, update the roadmap and open a ready-for-review PR while recording exact links/digests in `specs/005-durable-dispatch/evidence/README.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies; T001 protects baseline/user changes before edits.
- **Foundational (Phase 2)**: Depends on Setup and blocks every user story.
- **US1 (Phase 3)**: Depends on all foundational contract/type/V2 seams and creates the
  first durable grant/outbox only.
- **US2 (Phase 4)**: Depends on canonical contracts and US1's exact grant/outbox; its
  adapter store remains independently testable with fixtures.
- **US3 (Phase 5)**: Depends on US1 outbox and US2 inbox/receipt readback; fault-registry
  definitions/tests can start after Phase 2.
- **US4 (Phase 6)**: Depends on the lifecycle rows from US1–US3; manifest/schema negative
  tests can start earlier against fixtures.
- **Polish (Phase 7)**: Depends on all desired story checkpoints. T091 may remain external
  evidence pending without falsifying implementation completion; T094 requires all
  software/build-scope tasks and hosted release gates.

### User Story Dependencies

```text
Foundational
  -> US1 durable dispatch MVP
      -> US2 one-shot inbox/receipt
          -> US3 ambiguity/reconciliation
              -> US4 restore/removal
                  -> release evidence
```

US2's standalone inbox contract/tests can run from fixtures after Phase 2, but
coordinator `EXECUTING` integration depends on US1. US3/US4 negative fixtures and schema
reviews may proceed in parallel; their positive end-to-end checkpoints follow the graph.

### Within Each Story

- Write and observe failing contract/negative/fault tests before authority-bearing code.
- Models/contracts and schema invariants precede transactions/orchestration.
- Durable commit precedes delivery; receive precedes consume; receipt precedes state
  advance; PAUSE/quiescence precedes backup.
- Story evidence is retained only after focused and prerequisite gates pass.

### Parallel Opportunities

- T003–T005 are separate setup files.
- T007–T009, T014–T015 and T019 are independent failing contract/type/version tests.
- US1 tests T021–T026 can be authored in parallel.
- US2 tests T039–T044 and early store scaffolding can proceed in parallel after Phase 2.
- US3 tests T056–T062 span distinct protocol/store/control surfaces.
- US4 tests T071–T074 span manifests, restore, corruption and retention.
- T083–T085 cover independent property, benchmark and portability evidence.

## Parallel Example: User Story 1

```text
Task T021: coordinator durable lookup/reload negative tests
Task T022: portable authority single-field mutation tests
Task T023: deadline/capacity boundary tests
Task T024: ordered guard and permit tests
Task T025: thread/process contention tests
Task T026: transaction uncertainty/readback tests
```

## Parallel Example: User Story 2

```text
Task T039: adapter schema/root contract tests
Task T040: receive/consume atomicity tests
Task T041: duplicate/conflict contention tests
Task T042: independent epoch tests
Task T043: receipt signer/history tests
Task T044: coordinator receipt-state tests
```

## Implementation Strategy

### MVP First — User Story 1

1. Complete Setup and Foundational phases.
2. Implement US1 only through exact signed grant/outbox and `DISPATCHING`.
3. Stop and run the independent US1 checkpoint.
4. Do not build a transport/inbox/effect until this authority boundary is green.

### Incremental Delivery

1. US1: durable grant and dispatch transition.
2. US2: independent receive/consume/receipt and `EXECUTING` marker, still no effect.
3. US3: handoff ambiguity, unknown/reconciliation and overload.
4. US4: migration/backup/restore/removal.
5. Polish: multi-platform, physical performance when available, supply and immutable CI.

## Notes

- Every task uses an exact file path and the required checkbox/ID/story format.
- `[P]` means separate files and no dependency on an incomplete same-file task.
- The existing 27 user formatting changes are never part of PLAN-005 staging.
- `EXECUTING` means consumed adapter authority only; no task may add an effect or token.
- Hosted CI/process-kill remains synthetic no-effect evidence. Power-loss, production
  supervisor/provider, full-machine activation and Tier 1 remain external gates.

## Phase 8: Convergence

- [x] T095 Profile and remediate the physical Mac mini M4 final-guard-to-consumed-receipt p95 regression without weakening fixed guard order, WAL/FULL durability, independent coordinator/adapter stores, signed receipt verification, or no-effect boundaries; add deterministic performance characterization, retain the original failed artifacts unchanged, rerun the exact 500-warmup/10,000-sample profile into new create-only evidence, and keep `PERF-002` pending unless p95 is at most 50 ms and p99 at most 100 ms in `kernel/helix-coordinator-sqlite/examples/durable_dispatch_benchmark.rs`, the measured production paths, `specs/005-durable-dispatch/evidence/m4-benchmark-remediation.md`, `specs/005-durable-dispatch/evidence/m4-remediation-raw.json` and `conformance/catalog.yaml` per SC-005
- [x] T096 Exercise the production backup and clean-restore path dynamically for prepared, dispatching, adapter-received, consumed and ambiguous lifecycle fixtures, proving fresh roots/epochs, `RESTORE_PENDING`, `PAUSED`, zero old redelivery or consumption, and exact quarantine/reconciliation custody in `kernel/helix-coordinator-sqlite/tests/dispatch_restore.rs`, `kernel/helix-dispatch-inbox-sqlite/tests/backup_restore.rs`, the corresponding `maintenance.rs` implementations and `specs/005-durable-dispatch/evidence/us4-restore-removal.md` per FR-031, SC-007 and US4/AC1
- [x] T097 Inject and reopen every remaining coordinator/adapter corruption class through the real stores, including conflicting histories, cross-store or digest disagreement, rollback, truncation and generation reuse, and prove fail-closed post-audit ordinary open/handoff/receive/consume plus permanent redacted custody in `kernel/helix-coordinator-sqlite/tests/dispatch_corruption.rs`, `kernel/helix-dispatch-inbox-sqlite/tests/corruption.rs`, `kernel/helix-coordinator-sqlite/src/dispatch_quarantine.rs`, `kernel/helix-dispatch-inbox-sqlite/src/quarantine.rs` and `specs/005-durable-dispatch/evidence/us4-restore-removal.md` per FR-032 and SC-007
