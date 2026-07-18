# Tasks: Durable Signed Task Authority

**Input**: Design documents from
`specs/006-durable-signed-task-authority/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`,
`quickstart.md`, `.specify/memory/constitution.md`, and every file under
`specs/006-durable-signed-task-authority/contracts/`

**Tests**: Tests are mandatory because the specification explicitly requires contract,
negative, tamper, property, concurrency, fault, migration, restore, portability,
redaction, overload, performance, supply-chain and removal evidence. Within each story,
test tasks are written first and must fail for the intended reason before implementation.

**Organization**: Tasks are grouped into setup, blocking foundation, the six user
stories in specification order, and final cross-cutting validation. Every positive
authority slice remains independently testable at its checkpoint.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: May run in parallel only after its phase prerequisites are complete, because
  it uses different files and does not depend on another incomplete `[P]` task.
- **[Story]**: Required only in user-story phases and maps directly to US1 through US6.
- Every task names the exact file or files it creates, changes or records evidence in.
- Tests precede the implementation they constrain.

## Immutable implementation boundary

The merged PLAN-005 removal baseline is commit
`c324f528dc76007a599005e5cc054dcbe1370b1a`, tree
`c70a3f2157498dd880822f97ef74d3d4757347d7`. The following 27 user-owned Rust paths are
excluded from every PLAN-006 edit, format, stage, commit, generated rewrite and removal
operation; their sorted newline-terminated inventory has SHA-256
`cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530`:

```text
kernel/helixos-kernel/src/approval/card.rs
kernel/helixos-kernel/src/approval/mod.rs
kernel/helixos-kernel/src/approval/server.rs
kernel/helixos-kernel/src/audit.rs
kernel/helixos-kernel/src/driver/files.rs
kernel/helixos-kernel/src/driver/mod.rs
kernel/helixos-kernel/src/driver/search.rs
kernel/helixos-kernel/src/intention.rs
kernel/helixos-kernel/src/lib.rs
kernel/helixos-kernel/src/main.rs
kernel/helixos-kernel/src/mtls.rs
kernel/helixos-kernel/src/pipeline.rs
kernel/helixos-kernel/src/plan.rs
kernel/helixos-kernel/src/policy.rs
kernel/helixos-kernel/src/runtime.rs
kernel/helixos-kernel/src/scope.rs
kernel/helixos-kernel/tests/approval_it.rs
kernel/helixos-kernel/tests/bootstrap_it.rs
kernel/helixos-kernel/tests/mtls_it.rs
kernel/helixos-kernel/tests/restart_it.rs
kernel/helixos-mcp-shim/src/config.rs
kernel/helixos-mcp-shim/src/kernel_client.rs
kernel/helixos-mcp-shim/src/lib.rs
kernel/helixos-mcp-shim/src/main.rs
kernel/helixos-mcp-shim/src/mcp.rs
kernel/helixos-mcp-shim/tests/shim_kernel_e2e.rs
kernel/helixos-provision/src/main.rs
```

PLAN-001 through PLAN-005 production Rust sources and wire contracts also remain
unchanged. Four dependency-policy tests may recognize the new reviewed PLAN-006 leaf
consumer and one workspace-removal test may recognize the four PLAN-006 packages as
downstream members. PLAN-005 removal/supply policy tests and retained policy/evidence
artifacts may classify only the PLAN-006 crate, fixture, Graphify and lock extension,
repinning only exact artifacts that bind the full lockfile while preserving the
selected production package, edge, external dependency, license and SBOM oracles; no
other allowlist or frozen set may be weakened. New dependencies flow from PLAN-006
toward existing public seams; no existing crate gains a PLAN-006 dependency.
`docs/roadmap/roadmap-data.js` is generated and is never edited by hand.

---

## Phase 1: Setup and Frozen Baseline

**Purpose**: Establish exact ownership, package boundaries, fixtures and baseline
evidence before implementing authority.

- [X] T001 Record the PLAN-005 commit/tree baseline, full protected-object inventory, exact 27-path exclusion list/hash, existing package set and clean-scope reproduction commands in `specs/006-durable-signed-task-authority/evidence/baseline.md`
- [X] T002 Add the four edition-2021 `unsafe`-forbidden workspace members with exact dependency pins, bundled SQLite features, non-default `test-fault-injection`/`controlled-benchmark` features and one-way dependency direction in `kernel/Cargo.toml`, `kernel/Cargo.lock`, `kernel/helix-task-authority-contracts/Cargo.toml`, `kernel/helix-task-authority/Cargo.toml`, `kernel/helix-task-authority-sqlite/Cargo.toml` and `kernel/helix-task-authority-projections/Cargo.toml`; update only the frozen consumer allowlists to recognize the reviewed projection leaf in `kernel/helix-plan-eligibility/tests/portability.rs`, `kernel/helix-plan-preparation/tests/contract.rs`, `kernel/helix-coordinator-sqlite/tests/portability.rs` and `kernel/helix-plan-dispatch/tests/portability.rs`, the exact downstream workspace set in `tools/tests/test_plan004_evidence.py`, the PLAN-005 inbox removal allowlist in `kernel/helix-dispatch-inbox-sqlite/tests/portability.rs`, and the PLAN-005 downstream removal/supply projection in `specs/005-durable-dispatch/evidence/removal-protected-files.json`, `specs/005-durable-dispatch/evidence/us4-restore-removal.md`, `tools/plan005_removal_drill.py`, `tools/plan005_supply_chain.py` and `tools/tests/test_plan005_evidence.py`
- [X] T003 [P] Create the closed contract-crate module skeleton and redacted public surface in `kernel/helix-task-authority-contracts/src/lib.rs`
- [X] T004 [P] Create the portable authority-core module skeleton and redacted public surface in `kernel/helix-task-authority/src/lib.rs`
- [X] T005 [P] Create the SQLite implementation module skeleton with fault hooks absent from default builds in `kernel/helix-task-authority-sqlite/src/lib.rs`
- [X] T006 [P] Create the leaf projection-adapter module skeleton without coordinator, inbox or legacy dependencies in `kernel/helix-task-authority-projections/src/lib.rs`
- [X] T007 [P] Create the versioned fixture inventory/golden-directory skeleton, pin PLAN-006 JSON/SQL/fixture/workflow/tool files to LF and ignore only generated evidence outputs in `contracts/fixtures/durable-signed-task-authority-v1/README.md`, `contracts/fixtures/durable-signed-task-authority-v1/golden/README.md`, `contracts/fixtures/durable-signed-task-authority-v1/cases.json`, `contracts/fixtures/durable-signed-task-authority-v1/chain-cases.json`, `contracts/fixtures/durable-signed-task-authority-v1/expected-outcomes.json`, `contracts/fixtures/durable-signed-task-authority-v1/public-keys.json`, `.gitattributes` and `.gitignore`
- [X] T008 Run the locked PLAN-001 through PLAN-005 and protected-package baseline tests without formatting or staging excluded paths, then record exact Rust/Cargo/SQLite/source/lock/schema results in `specs/006-durable-signed-task-authority/evidence/baseline.md`

**Checkpoint**: The PLAN-006-owned surface is isolated, dependency direction is
reviewable, and all prior behavior is captured before feature implementation.

---

## Phase 2: Foundational Contracts, Store and Control Boundaries

**Purpose**: Build shared canonical, cryptographic, durable-store, outcome, deadline and
fault seams that block every story until complete.

**⚠️ CRITICAL**: No user-story implementation begins before this phase passes.

### Tests for the foundation

- [X] T009 [P] Write failing cross-contract primitive, duplicate-member, canonical-byte, digest/base64url, unknown-version and generated leaf-coverage tests in `kernel/helix-task-authority-contracts/tests/cross_contract.rs` and `kernel/helix-task-authority-contracts/tests/property.rs`
- [X] T010 [P] Write failing source/dependency, OS-neutral primitive, non-Serde/non-Clone authority-marker and seeded public-redaction tests in `kernel/helix-task-authority-contracts/tests/portability.rs` and `kernel/helix-task-authority-contracts/tests/redaction.rs`

### Shared implementation

- [X] T011 Implement bounded duplicate-aware RFC 8785 input handling, exact byte equality, SHA-256 protected digests and canonical envelope helpers in `kernel/helix-task-authority-contracts/src/canonical.rs` and `kernel/helix-task-authority-contracts/src/digest.rs`
- [X] T012 [P] Implement strict canonical base64url Ed25519 signature verification, purpose-separated signer/resolver traits and immutable key-fingerprint evidence in `kernel/helix-task-authority-contracts/src/crypto.rs`
- [X] T013 [P] Implement safe integers, identifiers, NFC/resource components, closed enums, checked time/bound validation and payload-free public error codes in `kernel/helix-task-authority-contracts/src/validation.rs` and `kernel/helix-task-authority-contracts/src/error.rs`
- [X] T014 Expose only closed signed/authentic marker APIs with redacted `Debug`, no defaulted fields and no caller-constructible current authority in `kernel/helix-task-authority-contracts/src/lib.rs`
- [X] T015 Define the nine exact idempotency domains, closed stable preimages excluding candidate-generated values, immutable attempt/namespace/input/outcome bindings, closed mutation/readback outcomes and abstract atomic store operations shared by every story in `kernel/helix-task-authority/src/outcome.rs` and `kernel/helix-task-authority/src/store.rs`
- [X] T016 Define trusted clock/deadline capture, 1,024 ordinary plus 32 reserved-control capacity, unified non-cloneable authority guard custody and nonconstructible projection-provider traits in `kernel/helix-task-authority/src/control.rs`, `kernel/helix-task-authority/src/guard.rs` and `kernel/helix-task-authority/src/projection.rs`
- [X] T017 [P] Embed and digest the exact strict HLXA v1 normalized SQL contract, required tables/triggers/indexes and application/schema constants in `kernel/helix-task-authority-sqlite/src/schema.rs` from `specs/006-durable-signed-task-authority/contracts/task-authority-store-schema-v1.sql`
- [X] T018 [P] Implement provisioned local-root configuration, filesystem identity checks and injected trusted UTC/monotonic/boot observations without native paths in portable outputs in `kernel/helix-task-authority-sqlite/src/config.rs`, `kernel/helix-task-authority-sqlite/src/root_safety.rs` and `kernel/helix-task-authority-sqlite/src/clock.rs`
- [X] T019 Implement exclusive root initialization/publication and strict ordinary open with HLXA application ID, schema v1, WAL/FULL, foreign keys, recursive triggers, `trusted_schema=OFF`, `cell_size_check=ON`, disabled auto-checkpoint and bounded busy waits in `kernel/helix-task-authority-sqlite/src/connection.rs`
- [X] T020 Implement non-mutating exact schema/root/durability/integrity/cross-record admission verification with no repair, downgrade or implicit migration in `kernel/helix-task-authority-sqlite/src/schema.rs`
- [X] T021 Implement append-only public-key history, immutable purpose/key identity, current trust status, generation-increasing revocation and redacted transition/conflict events in `kernel/helix-task-authority-sqlite/src/revocation.rs` and `kernel/helix-task-authority-sqlite/src/event.rs`
- [X] T022 [P] Implement one-fresh-connection uncertainty readback types and complete-graph/healthy-absence/conflict/ambiguity classification without retry authority in `kernel/helix-task-authority-sqlite/src/readback.rs`
- [X] T023 [P] Implement bounded ordinary admission, duplicate coalescing and reserved revocation/status control lanes with injected deadlines in `kernel/helix-task-authority-sqlite/src/queue.rs`
- [X] T024 Wire the closed non-default fault-selection seam, prove default production builds cannot read environment/process fault selectors, and make the foundation tests pass in `kernel/helix-task-authority/src/test_fault.rs`, `kernel/helix-task-authority-sqlite/src/test_fault.rs` and `kernel/helix-task-authority-sqlite/tests/contract.rs`

**Checkpoint**: Canonical verification, trusted time/control, strict HLXA open, generic
atomic outcomes and immutable trust/revocation evidence are ready. All stories may now
write their tests, but implementation follows the dependency order below.

---

## Phase 3: User Story 1 - Accept an Authentic Human Request Once (Priority: P1) 🎯 MVP

**Goal**: Verify one exact current HumanRequestGrant, atomically consume its issuer-
scoped identity and retain one signed root TaskLease; exact retries recover identical
bytes and every forged/conflicting/current-trust failure produces no lease.

**Independent Test**: Submit one authentic grant and all negative variants to an empty
HLXA root. Exactly one root chain is retained; 10,000 sequential retries, 100 rounds x
64 threads and 20 rounds x eight processes return the same bytes, while conflicting or
stale inputs make zero positive mutation.

### Tests for User Story 1

- [X] T025 [P] [US1] Write failing HumanRequestGrant canonical/domain/purpose/context/expiry/current-trust contract tests and every protected-leaf mutation case in `kernel/helix-task-authority-contracts/tests/human_request_grant_contract.rs`
- [X] T026 [P] [US1] Write failing root TaskLease shape, source-grant, scope-intersection, exact-digest and exclusive deadline contract tests in `kernel/helix-task-authority-contracts/tests/task_lease_contract.rs`
- [X] T027 [P] [US1] Write failing core tests for forged/replayed/wrong-context grants, key rotation/revocation, signing failure before claim, exact retry/conflict outcomes and current-versus-historical authority after source/ancestor/decision revocation in `kernel/helix-task-authority/tests/request.rs` and `kernel/helix-task-authority/tests/revocation.rs`
- [X] T028 [P] [US1] Write failing 10,000 sequential, 100 x 64-thread and 20 x eight-process one-shot root issuance tests with exact retained bytes and invariant reopen in `kernel/helix-task-authority-sqlite/tests/contention.rs`
- [X] T029 [P] [US1] Write failing SQLite atomic-graph and readback tests proving grant record, one claim, one root lease, initial usage, generations and event are all visible or all absent in `kernel/helix-task-authority-sqlite/tests/contract.rs`

### Implementation for User Story 1

- [X] T030 [US1] Implement the closed HumanRequestGrant protected/envelope/authentic types and fixed verification order for `helixos.human-request-grant/1` in `kernel/helix-task-authority-contracts/src/human_request_grant.rs` from `specs/006-durable-signed-task-authority/contracts/human-request-grant-v1.schema.json`
- [X] T031 [US1] Implement the root TaskLease protected/envelope/authentic types, explicit null parent branch, source digest and purpose-separated signing needed by root issuance in `kernel/helix-task-authority-contracts/src/task_lease.rs` from `specs/006-durable-signed-task-authority/contracts/task-lease-v1.schema.json`
- [X] T032 [US1] Implement current grant-context resolution, scope/policy/catalogue intersection, sign-before-writer root candidate construction and closed request outcomes in `kernel/helix-task-authority/src/request.rs` and `kernel/helix-task-authority/src/lease.rs`
- [X] T033 [US1] Implement create-only exact grant retention, issuer-scoped claim uniqueness, current trust/scope/time recheck and conflict tombstones in `kernel/helix-task-authority-sqlite/src/grant.rs`
- [X] T034 [US1] Implement the single `BEGIN IMMEDIATE` root graph that commits grant, claim, signed root lease, initial usage, generations and redacted event atomically in `kernel/helix-task-authority-sqlite/src/lease.rs`
- [X] T035 [US1] Implement exact retry retrieval and one-readback handling for lost acknowledgement without re-signing or reissuing in `kernel/helix-task-authority-sqlite/src/grant.rs` and `kernel/helix-task-authority-sqlite/src/readback.rs`
- [X] T036 [US1] Enforce immutable key IDs, new-ID rotation, current-versus-historical trust and signer/grant revocation before consumption in `kernel/helix-task-authority/src/revocation.rs` and `kernel/helix-task-authority-sqlite/src/revocation.rs`
- [X] T037 [US1] Freeze public synthetic grant/root-lease canonical bytes, signatures, context/replay/expiry mutations and exact outcomes in `contracts/fixtures/durable-signed-task-authority-v1/golden/human-request-grant.protected.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/human-request-grant.envelope.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/root-task-lease.protected.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/root-task-lease.envelope.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/cases.json` and `contracts/fixtures/durable-signed-task-authority-v1/expected-outcomes.json`
- [X] T038 [US1] Run and record `PLAN006-REQUEST`, FR-007–FR-011, FR-031–FR-032, FR-035–FR-036, SC-002–SC-003 and SC-007 with exact mutation/generation deltas and zero authority from bare messages or notifications in `specs/006-durable-signed-task-authority/evidence/us1-request.md`

**Checkpoint**: US1 is independently functional and is the MVP: one authentic human
grant yields one durable root chain; no approval, projection or host effect exists.

---

## Phase 4: User Story 2 - Issue and Restrict Task Leases (Priority: P1)

**Goal**: Delegate only equal-or-smaller authority, atomically account sibling
allocations and monotonic counters, and make source/ancestor expiry, exhaustion or
revocation invalidate descendants without rewriting signed bytes.

**Independent Test**: Starting from the US1 root chain, accept exact-limit child leases
and reject every one-axis widening, union, overflow, underflow and sibling
oversubscription across generated, thread and process cases without an approval or
dispatch dependency.

### Tests for User Story 2

- [ ] T039 [P] [US2] Extend failing TaskLease contract tests to child shape, depth, resource/catalogue subsets, every budget/counter/trust/time one-unit widening and exact-limit acceptance in `kernel/helix-task-authority-contracts/tests/task_lease_contract.rs`
- [ ] T040 [P] [US2] Write failing core delegation tests for non-delegable parents, cross-task/workload/source use, unions, renewals, ancestor gaps/cycles and monotonic counter rules in `kernel/helix-task-authority/tests/delegation.rs`
- [ ] T041 [P] [US2] Write a failing independent checked oracle for at least 100,000 generated restrictive-delegation/allocation cases in `kernel/helix-task-authority/tests/delegation_property.rs`
- [ ] T042 [P] [US2] Extend failing SQLite contention tests for exact aggregate limits, oversubscribing sibling threads/processes, unique allocation IDs and complete invariant reopen in `kernel/helix-task-authority-sqlite/tests/contention.rs`

### Implementation for User Story 2

- [ ] T043 [US2] Complete TaskLease child decoding and semantic validation for canonical resources, intentions, budgets, counters, trust/catalogue bounds, depth and same-boot deadlines in `kernel/helix-task-authority-contracts/src/task_lease.rs`
- [ ] T044 [US2] Implement field-by-field restrictive delegation, checked subset/prefix arithmetic and exact parent/ancestor validation in `kernel/helix-task-authority/src/delegation.rs`
- [ ] T045 [US2] Implement monotonic direct counter-consumption semantics with no decrement, release, reset, renewal or widening API in `kernel/helix-task-authority/src/lease.rs`
- [ ] T046 [US2] Implement the atomic parent allocation, child signed lease, child usage, parent summary, generations and event transaction in `kernel/helix-task-authority-sqlite/src/delegation.rs`
- [ ] T047 [US2] Implement append-only counter-consumption tombstones and reproducible checked usage summaries in `kernel/helix-task-authority-sqlite/src/lease.rs`
- [ ] T048 [US2] Implement complete acyclic ancestor resolution and descendant non-current derivation for source/ancestor expiry, exhaustion, reboot, instance mismatch and revocation in `kernel/helix-task-authority/src/projection.rs` and `kernel/helix-task-authority-sqlite/src/projection.rs`
- [ ] T049 [US2] Implement exact allocation/counter retries, conflicting namespace tombstones and complete-graph uncertainty readback in `kernel/helix-task-authority-sqlite/src/delegation.rs` and `kernel/helix-task-authority-sqlite/src/readback.rs`
- [ ] T050 [US2] Freeze canonical child-lease bytes plus exact-limit, one-unit widening, ancestry, exhaustion, revocation and sibling-allocation cases in `contracts/fixtures/durable-signed-task-authority-v1/golden/child-task-lease.protected.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/child-task-lease.envelope.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/chain-cases.json` and `contracts/fixtures/durable-signed-task-authority-v1/expected-outcomes.json`
- [ ] T051 [US2] Run the release 100,000-case oracle and retain seed, case counts, exact/minus-one/plus-one results and zero-widening summary in `specs/006-durable-signed-task-authority/evidence/us2-property.md`
- [ ] T052 [US2] Run and record `PLAN006-LEASE`, FR-012–FR-021, FR-031, FR-033, FR-036, SC-004 and SC-007 across normal/thread/process contention with zero partial allocation or counter reset in `specs/006-durable-signed-task-authority/evidence/us2-lease.md`

**Checkpoint**: US1 and US2 work independently: root issuance and restrictive
delegation are durable without requiring any decision or downstream plan seam.

---

## Phase 5: User Story 3 - Bind One Terminal Decision to One Exact Plan (Priority: P1)

**Goal**: Retain exactly one signed `APPROVED` or `DENIED` decision bound to the exact
PLAN-001 envelope and current grant/lease chain; only current qualifying approval may
produce positive authorization evidence.

**Independent Test**: Race approval and denial for one exact target, mutate each plan,
grant, lease, identity, evidence, policy, catalogue, epoch and time binding, and prove
that only the retained current approval can become positive.

### Tests for User Story 3

- [ ] T053 [P] [US3] Write failing ApprovalDecision canonical/domain/purpose/terminal/plan-chain/deadline tests and every protected-leaf mutation case in `kernel/helix-task-authority-contracts/tests/approval_decision_contract.rs`
- [ ] T054 [P] [US3] Write failing core tests for exact PLAN-001 envelope binding, approve/deny immutability, weak L2 evidence, synthetic non-production evidence and current-chain mutation in `kernel/helix-task-authority/tests/decision.rs`
- [ ] T055 [P] [US3] Extend failing thread/process contention tests so concurrent approve/deny retains one terminal wire/event and cannot flip on retry in `kernel/helix-task-authority-sqlite/tests/contention.rs`
- [ ] T056 [P] [US3] Write failing seeded redaction tests for raw messages, authentication assertions, bearer/private-key/native-path/identifier/digest/provider sentinels in `kernel/helix-task-authority/tests/redaction.rs`

### Implementation for User Story 3

- [ ] T057 [US3] Implement the closed ApprovalDecision protected/envelope/authentic types, exact canonical plan-envelope digest and purpose-separated signature profile in `kernel/helix-task-authority-contracts/src/approval_decision.rs` from `specs/006-durable-signed-task-authority/contracts/approval-decision-v1.schema.json`
- [ ] T058 [US3] Implement exact authentic PLAN-001 target verification, current grant/lease/ancestor resolution, evidence-profile/risk policy and sign-before-writer terminal candidate construction in `kernel/helix-task-authority/src/decision.rs`
- [ ] T059 [US3] Implement the single atomic plan binding, terminal decision, uniqueness, generation and redacted event transaction in `kernel/helix-task-authority-sqlite/src/decision.rs`
- [ ] T060 [US3] Implement exact decision retry, conflicting terminal tombstone and one-fresh-readback classification without decision flipping in `kernel/helix-task-authority-sqlite/src/decision.rs` and `kernel/helix-task-authority-sqlite/src/readback.rs`
- [ ] T061 [US3] Derive current approved, current denied, expired, revoked, chain-non-current, boot/instance/fencing mismatch, weak-evidence and historical-only states without editing signed bytes in `kernel/helix-task-authority/src/revocation.rs` and `kernel/helix-task-authority/src/projection.rs`
- [ ] T062 [US3] Freeze canonical approved/denied wires, terminal races, every exact-binding mutation and labelled synthetic evidence cases in `contracts/fixtures/durable-signed-task-authority-v1/golden/approval-approved.protected.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/approval-approved.envelope.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/approval-denied.protected.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/approval-denied.envelope.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/chain-cases.json` and `contracts/fixtures/durable-signed-task-authority-v1/expected-outcomes.json`
- [ ] T063 [US3] Complete the three-wire fixture/outcome bijection, schema-leaf coverage and cross-contract source/plan/lease/decision tests in `kernel/helix-task-authority-contracts/tests/cross_contract.rs` against `specs/006-durable-signed-task-authority/contracts/signed-task-authority-v1.md`
- [ ] T064 [US3] Run and record `PLAN006-CONTRACT` and `PLAN006-DECISION`, FR-001–FR-006, FR-022–FR-031, FR-034–FR-036, SC-001, SC-005, SC-007 and SC-011 with zero positive authority from `DENIED` or synthetic evidence in `specs/006-durable-signed-task-authority/evidence/us3-decision.md`

**Checkpoint**: The complete signed HumanRequestGrant → TaskLease → ApprovalDecision
chain exists and is independently testable, but it still performs no preparation,
dispatch or host effect.

---

## Phase 6: User Story 4 - Replace Synthetic and Legacy Authority Views (Priority: P2)

**Goal**: Produce only nonconstructible current PLAN-006 projections and feed their
exact digests, generations, ancestry, revocation and deadline values through the
unchanged PLAN-002/004/005 public seams under one retained HLXA guard.

**Independent Test**: Resolve one coherent signed chain, pass it through all three
existing seams, mutate every carried leaf independently, race revocation against final
commit, and prove deterministic denial plus zero downstream mutation for legacy,
synthetic or mismatched inputs.

### Tests for User Story 4

- [ ] T065 [P] [US4] Write failing core projection tests for the complete signed graph, every closed ancestor-vector/plan-bound-lease/revocation preimage leaf and order, current-vs-historical status and earliest exclusive deadlines in `kernel/helix-task-authority/tests/projection.rs`, freezing exact bytes and lowercase digests in `contracts/fixtures/durable-signed-task-authority-v1/golden/ancestor-vector.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/ancestor-vector.sha256`, `contracts/fixtures/durable-signed-task-authority-v1/golden/plan-bound-lease-projection.jcs`, `contracts/fixtures/durable-signed-task-authority-v1/golden/plan-bound-lease-projection.sha256`, `contracts/fixtures/durable-signed-task-authority-v1/golden/revocation-vector.jcs` and `contracts/fixtures/durable-signed-task-authority-v1/golden/revocation-vector.sha256`
- [ ] T066 [P] [US4] Write failing PLAN-002 mapping tests proving signed lease/authorization views, authority-before-claim denial and exact TaskLease/HumanRequestGrant/ApprovalDecision bindings in `kernel/helix-task-authority-projections/tests/plan002.rs`
- [ ] T067 [P] [US4] Write failing PLAN-004 preliminary/final comparison tests proving the unified authority guard survives through `prepare_plan_v1` commit and every changed leaf causes zero preparation mutation in `kernel/helix-task-authority-projections/tests/plan004.rs`
- [ ] T068 [P] [US4] Write failing PLAN-005 preliminary/FinalGuarded tests proving exact view mapping, retained guard custody through `dispatch_prepared_once_v1` and zero dispatch mutation on mismatch in `kernel/helix-task-authority-projections/tests/plan005.rs`
- [ ] T069 [P] [US4] Write failing fixed-order, reverse-release, commit-classification/custody-transfer, absolute-deadline, cross-process revocation/usage TOCTOU and mutation-provider-reentry tests proving no Clock/Signer/Workload/Policy/Catalogue acquisition occurs under HLXA in `kernel/helix-task-authority-projections/tests/guard_order.rs`
- [ ] T070 [P] [US4] Write failing dependency/source/legacy/caller-positive-view and redaction tests proving existing crates and all protected paths cannot produce or import PLAN-006 authority in `kernel/helix-task-authority-projections/tests/portability.rs` and `kernel/helix-task-authority-projections/tests/redaction.rs`

### Implementation for User Story 4

- [ ] T071 [US4] Implement nonconstructible current authority, lease and authorization projections from exact signed records, trust, ancestry, usage, revocation, epochs and checked deadlines in `kernel/helix-task-authority/src/projection.rs` from `specs/006-durable-signed-task-authority/contracts/task-authority-projections-v1.md`
- [ ] T072 [US4] Implement strict complete-graph projection loading and canonical ancestor/revocation/plan-bound lease digest derivation from one verified SQLite snapshot in `kernel/helix-task-authority-sqlite/src/projection.rs`
- [ ] T073 [US4] Implement one deadline-bounded HLXA `BEGIN IMMEDIATE` guard acquired at Lease, Authorization validation in the same transaction, reverse release and authority-before-replay/coordinator lock order in `kernel/helix-task-authority-sqlite/src/guard.rs`
- [ ] T074 [US4] Implement `evaluate_and_claim_signed_authority_plan_v1` so non-authority inputs cannot carry lease/authorization views and the guard remains held through the unchanged PLAN-002 claim in `kernel/helix-task-authority-projections/src/eligibility.rs`
- [ ] T075 [US4] Implement `SignedPreparationAuthoritySourceV1` with exact PLAN-006 field replacement at existing Lease/Authorization slots and no change to PLAN-004 source in `kernel/helix-task-authority-projections/src/preparation.rs`
- [ ] T076 [US4] Implement `SignedDispatchAuthorityProviderV1` and `SignedDispatchGuardProviderV1` with exact preliminary/final mapping and no change or dependency addition to PLAN-005 in `kernel/helix-task-authority-projections/src/dispatch.rs` and `kernel/helix-task-authority-projections/src/guards.rs`
- [ ] T077 [US4] Run and record `PLAN006-PROJECTION`, FR-014, FR-020, FR-024–FR-029, FR-041–FR-045 and SC-006 for every digest/generation/ancestor/revocation/deadline mutation, legacy refusal and authority-write-before/after-commit linearization in `specs/006-durable-signed-task-authority/evidence/us4-projections.md`

**Checkpoint**: US4 replaces synthetic production authority only through new leaf
adapters; PLAN-001–PLAN-005 source and wire bytes remain unchanged.

---

## Phase 7: User Story 5 - Recover Authority Safely (Priority: P2)

**Goal**: Preserve exact authority through restart and declared fault boundaries,
bootstrap one empty HLXA root explicitly, back up one coherent paused multi-store cut
and restore historical evidence into `RESTORE_PENDING` with zero live authority.

**Independent Test**: Kill/restart at every declared transition, corrupt each invariant
and backup member, resume the supported bootstrap, refuse unknown/newer/downgrade state,
and restore only to approved empty roots under rotated epochs without reactivation.

### Tests for User Story 5

- [ ] T078 [P] [US5] Write failing schema/root/PRAGMA/indexed-wire/cross-record corruption and no-admission-repair cases in `kernel/helix-task-authority-sqlite/tests/corruption.rs`
- [ ] T079 [P] [US5] Write the failing in-process and applicable child-process kill matrix for every root/delegation/counter/decision/revocation/readback transition in `kernel/helix-task-authority-sqlite/tests/process_crash.rs`
- [ ] T080 [P] [US5] Write failing explicit paused bootstrap, same-identity restart, wrong-source/version/downgrade/partial publication and zero-import tests in `kernel/helix-task-authority-sqlite/tests/bootstrap_migration.rs`
- [ ] T081 [P] [US5] Write failing quiescent checkpoint, manifest-last, substitution/extra/missing member, exact `backup-provisioner-signing` purpose/domain, complete public key history with no private keys, clean-root restore, epoch rotation and zero-reactivation cases in `kernel/helix-task-authority-sqlite/tests/backup_restore.rs`
- [ ] T082 [P] [US5] Write failing permanent-retention, no-prune/no-delete and restricted/public redaction cases for wires, keys, tombstones, manifests and restore evidence in `kernel/helix-task-authority-sqlite/tests/retention.rs` and `kernel/helix-task-authority-sqlite/tests/redaction.rs`

### Implementation for User Story 5

- [ ] T083 [US5] Implement the exact HLXA v1 strict schema contract with its metadata/receipt/key/grant/claim/lease/usage/allocation/consumption/plan/decision/revocation/attempt/event/conflict tables, attempt foreign-key graph, immutable-record and strict monotonic-generation triggers, final `user_version=1` publication and normalized schema-digest verification in `kernel/helix-task-authority-sqlite/src/schema.rs` from `specs/006-durable-signed-task-authority/contracts/task-authority-store-schema-v1.sql`
- [ ] T084 [US5] Complete operation-specific exact-graph readback for every atomic transition, abandoning the original connection and allowing at most one automatic fresh observation in `kernel/helix-task-authority-sqlite/src/readback.rs`
- [ ] T085 [US5] Derive stable boundary instances for phases P00–P10 after transaction/publication operations stabilize, prove registry/driver bijection for each applicable in-process or process-kill model, and implement only the closed non-default probes in `specs/006-durable-signed-task-authority/contracts/fault-boundaries-v1.json` and `kernel/helix-task-authority-sqlite/src/test_fault.rs`
- [ ] T086 [US5] Implement explicit PAUSED bootstrap from exact coordinator V2 source backup to a new empty staged HLXA root, zero imported authority, receipt binding, publish-last and same-identity restart/readback in `kernel/helix-task-authority-sqlite/src/maintenance.rs`
- [ ] T087 [US5] Implement the closed RFC 8785/Ed25519 published-last backup manifest codec with exact Task Authority→Coordinator→Plan Replay→Dispatch Inbox order, bounded portable member aliases, complete four-purpose public-key history without private keys, provenance and exact `backup-provisioner-signing` purpose/domain verification through an externally provisioned trust resolver; require every embedded backup key/history entry to byte-match that resolver and never trust the self-contained copy in `kernel/helix-task-authority-sqlite/src/manifest.rs` from `specs/006-durable-signed-task-authority/contracts/task-authority-backup-manifest-v1.schema.json`
- [ ] T088 [US5] Implement PAUSE/quiescence custody, fixed root order, independent online checkpoints, generation recheck, staged members and atomic package publication in `kernel/helix-task-authority-sqlite/src/maintenance.rs`
- [ ] T089 [US5] Implement full pre-publication package verification, approved empty destinations, root/boot/instance/fencing/restore epoch rotation and `RESTORE_PENDING` publication with zero projection/reissue/redelivery in `kernel/helix-task-authority-sqlite/src/maintenance.rs`
- [ ] T090 [US5] Implement admission/readback/backup/restore invariant verification, permanent v1 tombstone/key history retention and fail-closed quarantine of corrupt or ambiguous state in `kernel/helix-task-authority-sqlite/src/maintenance.rs` and `kernel/helix-task-authority-sqlite/src/schema.rs`
- [ ] T091 [US5] Run the complete normal/fault/process-kill/bootstrap/backup/restore matrices and record exact boundary counts, absence/retained/ambiguous classifications, package mutations and zero reactivation in `specs/006-durable-signed-task-authority/evidence/us5-recovery.md`
- [ ] T092 [US5] Build and self-verify `PLAN006-DURABILITY` for FR-009–FR-010, FR-018–FR-021, FR-028–FR-039 and SC-003–SC-009 plus `PLAN006-RESTORE` for FR-037–FR-040 and SC-008–SC-009, with shared support references explicit while labelling process-kill as non-power-loss and restore as non-full-machine in `specs/006-durable-signed-task-authority/evidence/us5-gates.json`

**Checkpoint**: Restart, uncertainty, bootstrap, backup and clean restore are reusable
and fail closed; no restored nonterminal lease or approval is current.

---

## Phase 8: User Story 6 - Produce Reusable Release Evidence (Priority: P3)

**Goal**: Produce portable deterministic corpus, overload, performance, exact-commit
supply/removal and three-OS workflow evidence while keeping all catalogue claims
pending until their own immutable or physical gates pass.

**Independent Test**: Run one unchanged corpus on macOS arm64, Linux x64 and Windows
x64; verify byte-identical common outcomes, bounded duplicate floods, exact provenance
and removal back to the frozen PLAN-005 tree with no protected-path change.

### Tests for User Story 6

- [ ] T093 [P] [US6] Write failing evidence-tool tests for exact commit/tree, workflow provenance, dependency/license/advisory inputs, manifest tampering, nonclaims and protected-path exclusion in `tools/tests/test_plan006_evidence.py`
- [ ] T094 [P] [US6] Write failing three-OS common-semantics, exact fixture/outcome summary, SQLite capability-refusal and no platform-conditioned contract tests in `kernel/helix-task-authority-sqlite/tests/portability.rs`
- [ ] T095 [P] [US6] Write the failing 100-trial x 10,000-duplicate overload test proving ordinary work is bounded/refused within 50 ms and reserved revocation/status lookup remains p99 <= 100 ms in `kernel/helix-task-authority-sqlite/tests/queue_control.rs`

### Implementation for User Story 6

- [ ] T096 [US6] Implement deterministic materialization of the unchanged positive/negative/single-fault/concurrency/generated corpus and byte-identical machine summary in `kernel/helix-task-authority-sqlite/examples/durable_task_authority_corpus.rs`
- [ ] T097 [US6] Implement controlled raw-sample capture for 500 warmups plus 10,000 three-contract/projection, root issue, delegation and decision measurements with declared metadata and independent percentiles in `kernel/helix-task-authority-sqlite/examples/durable_task_authority_benchmark.rs`
- [ ] T098 [US6] Implement exact-commit dependency closure, bundled SQLite/toolchain/schema/source/lock digests, licenses, advisories, SBOM/provenance, secret/path scans and independent bundle verification in `tools/plan006_supply_chain.py`
- [ ] T099 [US6] Implement the detached exact-removal drill that deletes PLAN-006 executable surfaces, restores every baseline blob/mode plus the eleven PLAN-006-owned existing test/policy/evidence edits, proves the frozen tree/package set and original consumer/downstream/removal/supply oracles, runs locked/offline prior tests and never touches the 27 excluded paths in `tools/plan006_removal_drill.py`
- [ ] T100 [US6] Add policy, Linux/macOS/Windows conformance, release-evidence and exact-attestation jobs with hosted diagnostic/non-effect/non-power-loss claims only in `.github/workflows/durable-signed-task-authority.yml`
- [ ] T101 [US6] Update only the existing PLAN-006 `REQUEST-001`, `SEC-002` and `SEC-003` catalogue mappings with exact implementation/evidence paths while preserving `pending-evidence`, run the roadmap generator to refresh `docs/roadmap/roadmap-data.js` without hand editing it, and verify the static shell remains unchanged in `conformance/catalog.yaml` and `docs/roadmap/index.html`
- [ ] T102 [US6] Run the unchanged three-platform corpus, overload profile and hosted diagnostic benchmark, compare exact summaries and retain machine-readable artifacts/nonclaims in `specs/006-durable-signed-task-authority/evidence/us6-portability-performance.md`
- [ ] T103 [US6] Build and self-verify `PLAN006-PORTABILITY` for FR-001–FR-006, FR-046, SC-001 and SC-010–SC-011; `PLAN006-PERFORMANCE` for FR-036, FR-048 and SC-012–SC-013; and `PLAN006-SUPPLY` for FR-044, FR-046–FR-048, SC-009–SC-011 and SC-014 from one exact commit, while leaving physical-M4/Tier-1 claims pending in `specs/006-durable-signed-task-authority/evidence/us6-release.md`

**Checkpoint**: All ten PLAN-006 gates have reusable evidence surfaces; catalogue
claims remain pending until exact external/physical requirements are independently met.

---

## Phase 9: Polish and Cross-Cutting Validation

**Purpose**: Close traceability, quality, boundary, documentation, Graphify and roadmap
checks without broadening scope or manufacturing acceptance evidence.

- [ ] T104 [P] Create a complete FR-001–FR-048, SC-001–SC-014, user-story, contract, test, gate and evidence traceability matrix with no uncovered item and one explicit primary owner plus labelled supporting owners for every shared acceptance item in `specs/006-durable-signed-task-authority/evidence/traceability.md`
- [ ] T105 [P] Reconcile implemented names/commands/nonclaims across design artifacts and verify every local link/schema/fixture/fault reference without weakening normative requirements in `specs/006-durable-signed-task-authority/quickstart.md` and `specs/006-durable-signed-task-authority/contracts/`
- [ ] T106 Run `cargo fmt --package` with `-- --check` for only `helix-task-authority-contracts`, `helix-task-authority`, `helix-task-authority-sqlite` and `helix-task-authority-projections`, then run locked workspace check, strict Clippy, default/non-default feature checks and full tests without formatting any existing or protected crate, and retain exact results in `specs/006-durable-signed-task-authority/evidence/quality.md`
- [ ] T107 Execute every applicable quickstart contract, request, lease, decision, projection, TOCTOU, migration, durability, restore, portability, overload, supply and removal command and record pass/fail/non-applicable evidence honestly in `specs/006-durable-signed-task-authority/evidence/quickstart-validation.md`
- [ ] T108 Run source/dependency/reverse-reachability, forbidden host/effect/egress/secret, legacy-positive-authority and exact 27-path hash/status gates, then record zero protected-path mutation in `specs/006-durable-signed-task-authority/evidence/boundary.md`
- [ ] T109 Refresh the derived knowledge graph after code changes, persist concise evidence-based results/reflections without secrets, regenerate the roadmap only when authoritative status changed and verify current output in `graphify-out/reflections/LESSONS.md` and `docs/roadmap/index.html`
- [ ] T110 From one pushed immutable exact commit, run and verify the release workflow/attestation, all ten PLAN006 gate manifests and exact-removal evidence; confirm catalogue attestations remain `pending-evidence` with no promotion, then run Spec Kit analyze/converge, `git diff --check` and the final acceptance/nonclaim review in `specs/006-durable-signed-task-authority/evidence/final.md`

**Checkpoint**: PLAN-006 is implementation-complete only when every selected task and
its evidence passes. A completed task ratio is not a Tier-1, physical-M4, power-loss,
production-ingress, WebAuthn, host-effect, secure-erasure or full-machine claim.

---

## Dependencies and Execution Order

### Phase dependencies

```text
Phase 1 Setup
    -> Phase 2 Foundation
        -> US1 Authentic Request (MVP)
            -> US2 Restrictive Leases
                -> US3 Terminal Decision
                    -> US4 Signed Projections -----+
                    -> US5 Recovery ---------------+-> US6 Release Evidence
                                                        -> Phase 9 Polish
```

- **Phase 1** has no prerequisite and freezes ownership/baseline first.
- **Phase 2** depends on Phase 1 and blocks every user story.
- **US1** depends only on the foundation and delivers the independently testable MVP.
- **US2** depends on US1's retained root chain.
- **US3** depends on US1 and US2 because a decision binds the exact current grant/lease
  chain.
- **US4** and **US5** both depend on US1–US3 and may then proceed in parallel: US4 owns
  downstream projection adapters; US5 owns lifecycle/recovery.
- **US6** depends on both US4 and US5 so release evidence covers the complete slice.
- **Phase 9** depends on every story selected for release.

### Within each story

1. Write the listed tests and confirm they fail for the intended missing behavior.
2. Implement portable contract/core semantics before native storage.
3. Implement atomic SQLite behavior before exact retry/readback integration.
4. Add canonical fixtures only from reviewed deterministic public material.
5. Run the independent story gate and retain machine-readable evidence.
6. Do not check off the checkpoint until negative cases prove zero forbidden mutation.

### Gate ownership

| Gate | Primary completion task |
|---|---:|
| `PLAN006-CONTRACT` | T064 |
| `PLAN006-REQUEST` | T038 |
| `PLAN006-LEASE` | T052 |
| `PLAN006-DECISION` | T064 |
| `PLAN006-PROJECTION` | T077 |
| `PLAN006-DURABILITY` | T092 |
| `PLAN006-RESTORE` | T092 |
| `PLAN006-PORTABILITY` | T103 |
| `PLAN006-PERFORMANCE` | T103 |
| `PLAN006-SUPPLY` | T103 |

### Requirement and success-criteria coverage

| Requirement range | Primary phases/tasks |
|---|---|
| FR-001–FR-006 | Foundation, US1–US3; T009–T014, T025–T026, T053, T063–T064 |
| FR-007–FR-011 | US1; T025, T027–T030, T032–T038 |
| FR-012–FR-021 | US1/US2; T026, T031–T034, T039–T052 |
| FR-022–FR-030 | US3; T053–T064 |
| FR-031–FR-036 | Foundation and US1–US5; T015–T024, T029, T034–T035, T046–T049, T059–T060, T078–T092 |
| FR-037–FR-040 | US5; T078–T092 |
| FR-041–FR-045 | US4; T065–T077 |
| FR-046–FR-048 | US6; T093–T103 |
| SC-001 | T025–T026, T053, T063–T064 |
| SC-002–SC-003 | T027–T029, T033–T038 |
| SC-004 | T039–T052 |
| SC-005 | T053–T064 |
| SC-006 | T065–T077 |
| SC-007–SC-009 | T078–T092, T099 |
| SC-010 | T094, T096, T100, T102–T103 |
| SC-011 | T010, T056, T064, T082, T108 |
| SC-012–SC-013 | T095, T097, T102–T103 |
| SC-014 | T093, T098–T103, T110 |

---

## Parallel Execution Examples

Parallel examples assume every preceding phase and any named prerequisite is complete.

### Setup

```text
T003 contract-crate root
T004 authority-core root
T005 SQLite root
T006 projection-adapter root
T007 fixture/LF policy skeleton
```

### User Story 1

```text
T025 HumanRequestGrant contract tests
T026 root TaskLease contract tests
T027 core request tests
T028 thread/process contention tests
T029 atomic graph/readback tests
```

### User Story 2

```text
T039 child TaskLease contract tests
T040 delegation semantic tests
T041 generated independent oracle
T042 SQLite sibling contention tests
```

### User Story 3

```text
T053 ApprovalDecision contract tests
T054 core decision tests
T055 terminal race tests
T056 redaction tests
```

### User Story 4

```text
T065 core projection tests
T066 PLAN-002 mapping tests
T067 PLAN-004 guarded tests
T068 PLAN-005 guarded tests
T069 fixed-order/TOCTOU tests
T070 portability/legacy/refusal tests
```

### User Story 5

```text
T078 corruption tests
T079 process-crash tests
T080 bootstrap tests
T081 backup/restore tests
T082 retention/redaction tests
```

### User Story 6

```text
T093 evidence-tool tests
T094 portability tests
T095 overload/control-lane tests
```

---

## Implementation Strategy

### MVP first

1. Complete Phase 1 and preserve the baseline/protected paths.
2. Complete the blocking Phase 2 foundation.
3. Complete US1 through T038.
4. Stop and independently validate one authentic grant → one retained root chain,
   including all negative and thread/process retry cases.
5. Do not describe this MVP as approval, preparation, dispatch or execution authority.

### Incremental delivery

1. **MVP**: Setup + Foundation + US1 — authentic one-shot request/root issuance.
2. Add **US2** — restrictive delegation, aggregate allocation and counters.
3. Add **US3** — immutable exact plan-bound terminal decision.
4. Run **US4** and **US5** in parallel after US3 — downstream signed projections and
   durable lifecycle/recovery.
5. Add **US6** — portable/performance/supply/removal evidence.
6. Finish Phase 9 — traceability, quickstart, boundary, Graphify and roadmap checks.

### Parallel team strategy

After Phase 2, one team owns the current dependency-front story while other teams may
prepare only the `[P]` tests for later isolated files. After US3, one team implements
US4 projections while another implements US5 lifecycle. They merge only through the
new PLAN-006 traits and fixtures; neither edits existing plan or protected legacy Rust
sources.

## Notes

- `[P]` never permits simultaneous edits to the same file or work before prerequisites.
- Exact retries return retained bytes; they never re-sign or renew authority.
- Only explicit uncertain commits receive one fresh readback; blind retries are banned.
- HLXA authority custody is acquired before replay/coordinator custody and never in the
  reverse order; no distributed transaction is claimed.
- Every public output is closed and redacted; raw messages, assertions, bearer values,
  private keys and native paths are prohibited.
- Hosted CI/process-kill evidence remains synthetic and no-effect. Physical M4,
  power-loss, production ingress/WebAuthn, host effects, full-machine restore, secure
  erasure, R2 and Tier-1 remain external or future gates.
