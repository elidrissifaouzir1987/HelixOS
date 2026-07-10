# Tasks: Portable Signed Contracts

**Input**: Design documents from `specs/001-portable-signed-contracts/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`,
`contracts/plan-envelope-v1.md`, `quickstart.md`

**Tests**: Contract, negative, tamper, property, portability, soak, and performance tests
are required by FR-013, FR-014, SC-001 through SC-005, and the HelixOS constitution.

**Organization**: Tasks are grouped by independently testable user story. Test tasks
precede the implementation they specify.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the isolated crate and language-neutral contract locations.

- [x] T001 Add `helix-contracts` as a workspace member in `kernel/Cargo.toml`
- [x] T002 Create the exact-pinned crate manifest and module skeleton in `kernel/helix-contracts/Cargo.toml` and `kernel/helix-contracts/src/lib.rs`
- [x] T003 [P] Record the canonicalization/signature decision and removal path in `docs/adr/0005-canonical-signed-contracts.md`
- [x] T004 [P] Create contract, fixture, and conformance roots in `contracts/schemas/`, `contracts/fixtures/plan-envelope-v1/`, and `conformance/catalog.yaml`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Create closed errors and primitive validation used by every story.

**Critical**: No story implementation begins until these value-object invariants pass.

- [x] T005 Write failing tests for typed errors, SHA-256 hex parsing, safe integers, bounded identifiers, nonce parsing, and no-secret diagnostics in `kernel/helix-contracts/tests/canonical.rs`
- [x] T006 Implement typed errors and bounded primitives in `kernel/helix-contracts/src/error.rs`, `kernel/helix-contracts/src/digest.rs`, and `kernel/helix-contracts/src/validation.rs`
- [x] T007 Update and review dependency resolution in `kernel/Cargo.lock`, confirming no runtime network, filesystem resolver, RNG, or schema engine entered `helix-contracts`

**Checkpoint**: Closed primitive types and errors are independently green.

---

## Phase 3: User Story 1 — Stable Plan Identity (Priority: P1) MVP

**Goal**: Produce identical protected JCS and plan identifiers for the same logical plan
on every supported OS.

**Independent Test**: The positive fixture produces byte-identical protected JCS and
SHA-256 plan ID, while every effect-bearing mutation changes the ID.

### Tests for User Story 1

- [x] T008 [P] [US1] Add RFC 8785 ordering, Unicode, escaping, safe-number, idempotence, and noncanonical-input tests in `kernel/helix-contracts/tests/canonical.rs`
- [x] T009 [P] [US1] Add traversal, separator, NFC, control/bidi, ADS, reserved-device, size, and portability-profile tests in `kernel/helix-contracts/tests/resource.rs`
- [x] T010 [P] [US1] Add protected-plan golden and every-protected-leaf digest mutation tests in `kernel/helix-contracts/tests/conformance.rs`

### Implementation for User Story 1

- [x] T011 [US1] Implement bounded `root_id + components` validation and canonical `helixfs://` rendering in `kernel/helix-contracts/src/resource.rs`
- [x] T012 [US1] Implement the private RFC 8785 wrapper and JCS input guards in `kernel/helix-contracts/src/canonical.rs`
- [x] T013 [US1] Implement closed `PlanInputV1`, `PlanProtectedV1`, file-patch effect, budget, request source, recovery, and verification types in `kernel/helix-contracts/src/plan.rs`
- [x] T014 [US1] Commit the reviewed JSON Schema and positive golden fixture files in `contracts/schemas/plan-envelope-v1.schema.json` and `contracts/fixtures/plan-envelope-v1/`

**Checkpoint**: User Story 1 passes without any signature or legacy-runtime dependency.

---

## Phase 4: User Story 2 — Verify Before Trust (Priority: P2)

**Goal**: Sign protected plans and reject all unsupported, noncanonical, untrusted, or
tampered wire data before consumers can use it.

**Independent Test**: The trusted fixture verifies; wrong schema/algorithm/key/digest/
signature, duplicate/unknown fields, and byte-level tampering produce typed denial.

### Tests for User Story 2

- [x] T015 [P] [US2] Add RFC 8032, deterministic signature, wrong-key, domain, key-ID, truncation, and bit-flip tests in `kernel/helix-contracts/tests/crypto.rs`
- [x] T016 [P] [US2] Add canonical-wire, duplicate/unknown/missing field, unsupported schema/algorithm/intent, size-limit, and tamper-table tests in `kernel/helix-contracts/tests/conformance.rs`

### Implementation for User Story 2

- [x] T017 [US2] Implement signer/key-resolver traits, domain-separated Ed25519 signing, strict verification, and base64url encoding in `kernel/helix-contracts/src/crypto.rs`
- [x] T018 [US2] Implement `SignedPlanEnvelopeV1`, canonical wire serialization, size-bounded strict decoding, plan-ID recomputation, key resolution, and `AuthenticPlanEnvelopeV1` in `kernel/helix-contracts/src/plan.rs`
- [x] T019 [US2] Finalize signature/public-key/envelope golden files and verify them byte-for-byte in `contracts/fixtures/plan-envelope-v1/` and `kernel/helix-contracts/tests/conformance.rs`

**Checkpoint**: User Stories 1 and 2 work independently of host effects and the MVP-0
pipeline.

---

## Phase 5: User Story 3 — Reusable Conformance Evidence (Priority: P3)

**Goal**: Make the same acceptance evidence runnable on Windows, Linux, and macOS arm64.

**Independent Test**: A platform-neutral test suite consumes the committed fixtures with
no target-specific branches and reports the same outcomes.

### Tests and implementation for User Story 3

- [x] T020 [P] [US3] Add generated round-trip, canonical-idempotence, mutation, and no-panic properties in `kernel/helix-contracts/tests/property.rs`
- [x] T021 [P] [US3] Add a static portability gate forbidding native paths, floats, unsafe, target cfg, clocks, RNG, and process-local wire types in `kernel/helix-contracts/tests/portability.rs`
- [x] T022 [P] [US3] Add the ignored 100,000-envelope deterministic soak and release percentile runner in `kernel/helix-contracts/tests/soak.rs` and `kernel/helix-contracts/examples/plan_benchmark.rs`
- [x] T023 [P] [US3] Register `PLAN-001`, fixture paths, platforms, and evidence requirements in `conformance/catalog.yaml`
- [x] T024 [P] [US3] Add stable-toolchain format, clippy, contract, and workspace test jobs for Ubuntu, macOS arm64, and Windows in `.github/workflows/contracts.yml`

**Checkpoint**: Local conformance passes; the Tier 1 portability claim remains pending
until the remote matrix produces evidence.

---

## Phase 6: Polish & Cross-Cutting Evidence

**Purpose**: Validate the slice, update memory, and state remaining external proof honestly.

- [x] T025 Run `cargo fmt --check`, strict clippy, `cargo test -p helix-contracts`, and `cargo test --workspace`; update `specs/001-portable-signed-contracts/quickstart.md` only if commands differ
- [x] T026 Run the ignored soak and release benchmark, record local Windows evidence without claiming Mac Tier 1 in `specs/001-portable-signed-contracts/quickstart.md`
- [x] T027 Refresh Graphify, save the verified implementation/test outcome, and regenerate lessons in `graphify-out/memory/` and `graphify-out/reflections/LESSONS.md`
- [ ] T028 Capture a successful unchanged Linux/macOS-arm64/Windows CI matrix and link its immutable run artifact from `conformance/catalog.yaml`

---

## Dependencies & Execution Order

### Phase Dependencies

- Phase 1 has no dependencies.
- Phase 2 depends on Phase 1 and blocks all user stories.
- US1 depends on Phase 2.
- US2 depends on the US1 protected-plan representation but remains independently
  testable as a verify-only consumer.
- US3 depends on stable US1/US2 fixtures.
- Phase 6 local validation depends on implemented US1–US3 files; T028 additionally
  requires external CI execution.

### Parallel Opportunities

- T003 and T004 can run in parallel after repository paths are agreed.
- Test files T008–T010 and T015–T016 are independent and can be authored in parallel.
- T020–T024 touch separate files and can run in parallel after fixtures stabilize.
- Tasks touching `plan.rs`, `canonical.rs`, or the same golden fixture run sequentially.

## Implementation Strategy

### MVP First

1. Complete Setup and Foundational tasks.
2. Complete US1 and prove stable plan identity before adding signatures.
3. Complete US2 and prove strict verification before adding portability automation.
4. Complete US3 locally; do not claim cross-platform proof before T028.

### Removal and migration

- Removing this feature deletes one leaf workspace member plus `contracts/` and
  conformance artifacts; MVP-0 behavior remains unchanged.
- A later Spec Kit feature adds an explicit legacy-to-v1 adapter. It may not mutate the
  v1 schema or bypass verification to ease migration.

## Task Summary

- Total tasks: 28
- Setup/foundational: 7
- US1: 7
- US2: 5
- US3: 5
- Polish/evidence: 4
- Suggested first implementation scope: T001–T019, followed by local T025 validation
- All task rows follow the required checkbox, ID, optional `[P]`, story-label, and exact
  path format.
