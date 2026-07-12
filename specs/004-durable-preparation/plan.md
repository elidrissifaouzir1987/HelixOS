# Implementation Plan: Durable Preparation Before Dispatch

**Branch**: `master` (Spec Kit feature `004-durable-preparation`) | **Date**:
2026-07-12 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/004-durable-preparation/spec.md`

## Summary

Add a portable `helix-plan-preparation` orchestration crate and a replaceable
`helix-coordinator-sqlite` storage crate. One call consumes `EligiblePlanV1`, performs a
complete preliminary comparison, verifies an eligibility-built exact replay view, then
runs read-only operation/budget preflight before publishing verified recovery evidence.
It acquires a fixed-order final guard set, repeats replay and preflight verification, and
passes a linearizable supervisor commit permit into the store. One SQLite transaction
commits the canonical eight-member positive coordinator set: metadata generations,
`PREPARING` operation, permanent transition, comparison/replay evidence, exact scope
delta, held reservation, recovery/irreversibility evidence and redacted event. A fresh attempt identity and full
readback distinguish committed, absent, conflicting and ambiguous outcomes without
retry or double release. An independent supervisor deadman resolves killed, hung or
expired permit owners to ambiguous PAUSE by the earlier caller deadline or fixed 250 ms
v1 permit ceiling. Any exact readback after that resolution is later reconciliation and
cannot recreate the original marker. Known failure holds a sovereign no-dispatch guard
across its atomic release transaction.

The coordinator database is separate from the replay, supervisor and recovery domains.
Those domains are joined only by immutable receipts, short-lived guards, exact readback
and reconciliation; no implicit distributed transaction is claimed. The feature ends
before `DISPATCHING`, grants, adapters and host effects. Synthetic recovery proves the
portable protocol only, and restored old preparation never reactivates.
The default public restore surface contains only two non-constructible, payload-free
redacted evidence projections and no producer. Restore validation, reconciliation,
quarantine, maintenance limits/errors and every sovereign authority operation remain
crate-internal; a later feature owns the host and activation facade.

## Technical Context

**Language/Version**: Rust edition 2021 with exact Rust/Cargo `1.96.1`, minimal profile,
`rustfmt` and `clippy`, pinned by `kernel/rust-toolchain.toml`. No lower MSRV is claimed.
New crates use `#![forbid(unsafe_code)]`.

**Primary Dependencies**: Existing workspace `helix-contracts` and
`helix-plan-eligibility`; exact `getrandom 0.4.3`; exact `rusqlite 0.40.1` with
`default-features=false`, `bundled`, `backup` (`libsqlite3-sys 0.38.1`, bundled SQLite
3.53.2); exact `serde 1.0.228`, `serde_json 1.0.150`,
`serde_json_canonicalizer 0.3.2`, `sha2 0.10.9`, `base64 0.22.1` and existing pinned
`ed25519-dalek 2.2.0` for detached backup provenance verification. Development uses
exact `proptest 1.11.0` and `helix-replay-sqlite` integration. No Tokio, network client,
UUID/ambient-time API, system SQLite, dynamic extension or legacy `helixos-kernel`
production dependency.

**Storage**: One new provisioner-attested local coordinator SQLite root/database,
separate from PLAN-003. It uses application ID `0x484c5843` (`HLXC`), schema v1, strict
tables, WAL, `synchronous=FULL`, `wal_autocheckpoint=0`, foreign keys,
`trusted_schema=OFF`, `cell_size_check=ON`, short deadline-bounded `BEGIN IMMEDIATE`
transactions, `recursive_triggers=ON` and controlled checkpoints. One transaction owns
the complete canonical eight-member positive coordinator set; replay, supervisor and
external recovery bytes remain separate receipt/guard domains. Quiescent backup uses SQLite online backup, an exact recovery
inventory and a top-level manifest; clean restore remains `RESTORE_PENDING` and PAUSED.
Both operation-bound and orphan pending-retirement counts are fixed zero at the cut.
Inventory and top-level digests use the byte-exact RFC 8785 encodings frozen by the
recovery-provider contract.
The top-level manifest is followed by a detached
provisioner-signed provenance attestation as the final package publication point. Both
coordinator and recovery roots persist the same restore identity and independent
`RESTORE_PENDING` lifecycle metadata.

**Testing**: `cargo fmt`, `cargo check --locked`, strict Clippy, full locked workspace
tests, compile-fail type contracts, deterministic first-failure cases, exact replay
verification, at least 100,000 generated budget vectors, 100 x 64-thread and
20 x 8-process contention, controlled held-writer deadlines, process-kill/fault
injection, schema/cross-record corruption, recovery publication/cleanup races,
quiescent backup/restore, no-pruning, redaction, source portability, removal and release
benchmark. Negative cases include confirmed rollback versus uncertain commit, the
250 ms permit deadman, no-dispatch-guard revocation, true-orphan resolution, coherent
backup substitution and mismatched root lifecycle metadata. Fault hooks exist only
behind a non-default `test-fault-injection` feature.

**Target Platform**: macOS arm64 is primary and the physical Mac mini M4 is the
controlled performance target. Required unchanged conformance hosts are macOS arm64,
Linux x64 and Windows x64. Common logic has no target-OS-conditioned semantics.

**Project Type**: Two Rust libraries (portable coordinator protocol plus host SQLite
storage adapter), reviewed Markdown/SQL/JSON contracts, one versioned fixture corpus,
CI matrix, validation/benchmark examples and retained evidence. No CLI, server, effect
adapter or legacy runtime migration.

**Performance Goals**: On the physical M4, 500 warmups plus at least 10,000 sequential
final-compare/coordinator-commit samples achieve p95 <= 25 ms and p99 <= 100 ms.
Recovery transfer is measured separately. At least 1,000 held-writer calls return by the
absolute monotonic deadline plus at most 50 ms scheduler tolerance, followed by at least
250 ms observation and reopen proving no detached mutation. Every commit permit has the
earlier caller deadline or 250 ms after entry and is deadman-resolved within the same
50 ms controlled scheduler tolerance.

**Constraints**: Consume only `EligiblePlanV1`; no second replay claim; no dispatch or
effect authority; no floating point, native path or provider handle in common values;
no implicit transaction across independent stores; no blind mutation retry after
possible commit; no positive result after deadline/revocation; no public plan/recovery
content, private identifier/digest, user budget value or provider diagnostic; no
production recovery claim from the synthetic provider. Production data roots require
an approved encrypted-at-rest provisioning profile. V1 has no automatic pruning or
physical secure-erasure claim. Operation-bound recovery retires only after `FAILED`;
true orphans require definitive no-reference proof and a permanent resolution tombstone.
Backup provenance requires a pinned provisioner verifier and never exposes signing keys.
The default public crate surface contains no restore-maintenance producer, input, error,
authority constructor, factory or operation; only the two redacted evidence projections
cross that boundary. Hidden non-default conformance entrypoints are not production APIs.

**Scale/Scope**: Single-user v1; operation states limited to `PREPARING` and known
pre-dispatch `FAILED`; budget dimensions limited to cost/action/egress/recovery bytes;
one coordinator database namespace; at least 100,000 property vectors, 100 x 64-thread
and 20 x 8-process contention rounds, and a 10,000-sample target benchmark. No full
coordinator lifecycle, production platform recovery provider, sovereign host-maintenance
facade or restored-system activation.

## Constitution Check

*GATE: Passed before Phase 0 research; re-checked after Phase 1 design.*

- **Boundary - PASS**: Agent/model, MCP, recovery fixtures and legacy runtime are
  untrusted/non-sovereign. They cannot create contexts, guards, scopes, receipts or the
  prepared marker. The only new authority is a core-owned held budget plus durable,
  non-dispatchable `PREPARING`. No host share, shell, direct egress, raw secret or
  sovereign-target mutation is introduced. Stale facts, forged/torn receipts,
  reservation reuse and attempted adapter consumption are mandatory negative cases.
- **Authority - PASS**: Contracts are typed, closed and versioned. Positive input is a
  consumed `EligiblePlanV1`; unknown values deny. The plan projection is non-wire and
  preserves PLAN-001 bytes/signatures. The exact replay verifier is read-only and does
  not compare the global latest generation. `PreparedOperationV1` is non-Clone,
  non-Serde and not grant/adapter authority.
  Restore evidence has no public producer; limits, errors, validation, reconciliation,
  quarantine and sovereign custody remain behind the private crate boundary.
- **Effects - PASS**: Recovery publication precedes the sole coordinator linearization
  point. A supervisor-owned commit permit total-orders PAUSE/HALT activation against the
  actual SQLite commit without becoming an operation transition. The complete canonical
  eight-member positive coordinator set commits together. Possible commit uses exact
  readback without retry/release; only an explicitly uncertain result enters readback.
  Owner loss/permit expiry at the earlier caller deadline or 250 ms ceiling activates
  PAUSE independently of the worker and unresolved state is quarantined. Known
  pre-dispatch failure atomically releases the stored hold once while an exact sovereign
  no-dispatch guard remains held through commit. Independent stores remain
  receipt/guard domains. No target effect exists, so effect verification/compensation
  execution is N/A; honest recovery preparation is in scope.
- **Data - PASS**: Canonical plan/recovery data is source-classified restricted data,
  excluded from agent/model, Graphify, public diagnostics/events, fixtures and egress.
  No raw credential is used. Production roots require an approved encrypted-at-rest
  profile. V1 retention is explicit: no pruning; active/ambiguous state and canonical
  plan retained indefinitely; failed/released/delivered/quarantine rows are permanent
  tombstones. Operation-bound recovery retirement needs durable failure, exact
  reconciliation and `RETIREMENT_PENDING -> RETIRED_TOMBSTONE`; a true orphan instead
  needs definitive no-reference proof plus a permanent orphan-resolution tombstone.
  Both use the exclusive cleanup guard. No secure-erasure claim is made.
- **Portability - PASS**: Common values are bounded identifiers, safe integers, fixed
  digests and explicit times only. Unsupported guard/storage/recovery semantics deny.
  One unchanged corpus and schemas run on macOS arm64, Linux x64 and Windows x64.
  Synthetic recovery is protocol evidence only.
- **Performance - PASS**: Cost/action/egress/recovery holds use checked exact arithmetic.
  File/concurrency/duration budgets are a justified N/A because plan-v1 does not sign
  them and this feature cannot dispatch. SC-003/004/009/010 define contention,
  generated vectors, physical-M4 percentiles and bounded writer waits/no-late-write
  evidence. PAUSE/HALT uses a revocable control-lane guard.
- **Evidence - PASS**: `PLAN-004` names contract/schema/corpus/toolchain/platform,
  process-crash, backup/restore, supply-chain, performance and removal evidence. The
  event outbox is redacted and transactional; future hash-chained/off-host delivery is
  not claimed. Detached provisioner provenance prevents coherent package substitution;
  no raw signing key enters the feature. Both roots persist `RESTORE_PENDING`, stay
  paused with rotated epochs and cannot reactivate old preparation. Synthetic, hosted
  and process-kill evidence cannot be promoted to
  production, physical-M4, power-loss or Tier 1 proof. This clean-root coordinator/
  recovery restore is subsystem evidence only; it does not satisfy the full
  clean-machine restore/activation gate.

Post-design re-check: PASS, 7/7, with no constitutional deviation or waiver. The
contracts freeze the guard order, read-only replay seam, budget transaction, recovery
publication/cleanup exclusion, coordinator schema/readback, quarantine separation,
cross-domain restore and v1 retention policy.

## Phase 0: Research Decisions

[research.md](research.md) resolves all design questions:

1. Stop PLAN-004 at durable non-dispatchable preparation.
2. Split portable preparation orchestration from SQLite coordinator storage.
3. Add only a borrowed non-wire plan preparation projection/canonical custody method.
4. Verify replay, perform preliminary operation/budget preflight, then recovery and a
   guarded final comparison that repeats replay/preflight verification under one global
   guard/commit-permit order.
5. Add an eligibility-created opaque replay view for exact read-only row verification
   without reclaim/global-generation rules.
6. Use injected UTC/boot-monotonic providers and exclusive deadline checks.
7. Provision trusted create-only budget scopes and reserve only signed v1 dimensions.
8. Publish recovery material create-only and manifest-last under a retained guard.
9. Make one WAL/FULL SQLite transaction the sole `PREPARING` linearization point.
10. Bind every possible commit to a random attempt, cap the supervisor permit at the
    earlier caller deadline or 250 ms and reserve readback for explicit uncertainty.
11. Keep quarantine/restore uncertainty separate from operation state.
12. Reconcile known pre-dispatch failure and exact budget release atomically under a
    sovereign no-dispatch guard; use separate persisted retirement paths for failed
    operations and definitively absent true orphans.
13. Use a PAUSED, quiescent cross-domain backup cut with a canonical sorted
    multi-provider inventory, detached signed provenance and matching independently
    persisted `RESTORE_PENDING` root identities.
14. Require approved at-rest profiles and freeze an explicit no-pruning retention rule.
15. Run one unchanged positive/single-fault/fault-injection corpus on three OS families.
16. Separate M4 coordinator latency from recovery transfer and pin release evidence.
17. Export only two redacted pending-restore evidence projections; retain all
    authority-bearing restore maintenance inside the crate and defer the sovereign host.

No `NEEDS CLARIFICATION` remains.

## Phase 1: Design and Contracts

- [data-model.md](data-model.md) defines portable contexts/guards/outcomes, budget and
  recovery evidence, coordinator rows, state transitions, invariants, backup/restore,
  classification and retention.
- [contracts/durable-preparation-v1.md](contracts/durable-preparation-v1.md) defines the
  coordinator API boundary, ownership, ordered algorithm, closed outcomes/readback,
  failure, quarantine, exact public evidence-only restore surface and adapter
  prohibitions.
- [contracts/authority-compare-v1.md](contracts/authority-compare-v1.md) freezes the two
  captures, complete comparison vector, guard acquisition/revocation order, time and
  exact replay-verifier semantics.
- [contracts/budget-reservation-v1.md](contracts/budget-reservation-v1.md) freezes scope
  provisioning, checked aggregate reservation, conflict and idempotent release rules.
- [contracts/recovery-provider-v1.md](contracts/recovery-provider-v1.md) defines provider
  profiles, manifest-last publication, receipts, irreversibility, quarantine, guarded
  retirement, backup membership and synthetic-evidence limits.
- [contracts/preparation-store-schema-v1.sql](contracts/preparation-store-schema-v1.sql)
  defines the reviewed coordinator application/schema identity and strict tables.
- [contracts/preparation-backup-manifest-v1.schema.json](contracts/preparation-backup-manifest-v1.schema.json)
  defines the top-level quiescent backup/restore evidence.
- [contracts/preparation-backup-provenance-attestation-v1.schema.json](contracts/preparation-backup-provenance-attestation-v1.schema.json)
  defines the detached provisioner-signed provenance envelope published after the
  manifest and verified before restore.
- [contracts/recovery-root-metadata-v1.schema.json](contracts/recovery-root-metadata-v1.schema.json)
  defines the independently durable recovery-root `ACTIVE`/`RESTORE_PENDING` metadata.
- [contracts/recovery-snapshot-manifest-v1.schema.json](contracts/recovery-snapshot-manifest-v1.schema.json)
  defines the exact sorted/unique restricted inventory of material-present and retired-
  tombstone recovery entries.
- [quickstart.md](quickstart.md) defines repeatable baseline, contract, freshness, budget,
  recovery, contention, deadline, crash, corruption, retention, restore, portability,
  redaction and physical-M4 evidence commands and expected outcomes.

The repository's Spec Kit distribution does not contain
`.specify/scripts/bash/update-agent-context.sh`, so the prescribed generated agent
context update cannot run. `AGENTS.md` already contains durable project/Graphify
instructions and is not modified with feature-local dependency details. This absence is
reported rather than replacing the helper with an invented write path.

## Project Structure

### Documentation (this feature)

```text
specs/004-durable-preparation/
|-- spec.md
|-- plan.md
|-- research.md
|-- data-model.md
|-- quickstart.md
|-- contracts/
|   |-- durable-preparation-v1.md
|   |-- authority-compare-v1.md
|   |-- budget-reservation-v1.md
|   |-- recovery-provider-v1.md
|   |-- preparation-store-schema-v1.sql
|   |-- preparation-backup-manifest-v1.schema.json
|   |-- preparation-backup-provenance-attestation-v1.schema.json
|   |-- recovery-root-metadata-v1.schema.json
|   `-- recovery-snapshot-manifest-v1.schema.json
|-- checklists/
|   |-- requirements.md
|   `-- durability.md
|-- evidence/
`-- tasks.md                         # created later by speckit-tasks
```

### Source Code (repository root)

```text
kernel/
|-- Cargo.toml                         # add both new workspace members
|-- Cargo.lock
|-- helix-contracts/
|   |-- src/lib.rs                     # export the new non-wire projection
|   |-- src/plan.rs                  # non-wire preparation projection/canonical custody
|   `-- tests/preparation_claims.rs
|-- helix-plan-eligibility/
|   |-- src/lib.rs                     # export verifier/view contract types
|   |-- src/replay.rs                # read-only ReplayClaimVerifierV1 contract
|   |-- src/marker.rs                # eligibility-built verification view factory
|   `-- tests/replay_verification.rs
|-- helix-replay-sqlite/
|   |-- src/lib.rs                     # declare/export verification module/surface
|   |-- src/verification.rs          # exact permanent row verifier implementation
|   `-- tests/preparation_verification.rs
|-- helix-plan-preparation/
|   |-- Cargo.toml
|   |-- src/
|   |   |-- lib.rs
|   |   |-- attempt.rs
|   |   |-- context.rs
|   |   |-- guard.rs
|   |   |-- commit_gate.rs
|   |   |-- compare.rs
|   |   |-- budget.rs
|   |   |-- recovery.rs
|   |   |-- store.rs
|   |   |-- outcome.rs
|   |   |-- coordinator.rs
|   |   `-- test_fault.rs             # non-default test feature only
|   `-- tests/
|       |-- common/mod.rs
|       |-- contract.rs
|       |-- freshness.rs
|       |-- revocation.rs
|       |-- recovery.rs
|       |-- conformance.rs
|       `-- redaction.rs
`-- helix-coordinator-sqlite/
    |-- Cargo.toml
    |-- src/
    |   |-- lib.rs
    |   |-- clock.rs
    |   |-- config.rs
    |   |-- error.rs
    |   |-- connection.rs
    |   |-- schema.rs
    |   |-- root_safety.rs
    |   |-- budget.rs
    |   |-- preflight.rs
    |   |-- prepare.rs
    |   |-- readback.rs
    |   |-- transition.rs
    |   |-- failure.rs
    |   |-- outbox.rs
    |   |-- quarantine.rs
    |   |-- retirement.rs
    |   |-- maintenance.rs
    |   |-- manifest.rs
    |   `-- test_fault.rs            # non-default test feature only
    |-- tests/
    |   |-- common/mod.rs
    |   |-- common/process_probe.rs
    |   |-- contract.rs
    |   |-- budget.rs
    |   |-- budget_property.rs
    |   |-- recovery_integration.rs
    |   |-- preparation.rs
    |   |-- cancellation.rs
    |   |-- contention.rs
    |   |-- deadline.rs
    |   |-- process_crash.rs
    |   |-- schema_corruption.rs
    |   |-- retention.rs
    |   |-- backup_restore.rs
    |   |-- conformance.rs
    |   |-- conformance_execution.rs
    |   |-- redaction.rs
    |   `-- portability.rs
    `-- examples/
        |-- durable_preparation_corpus.rs
        `-- durable_preparation_benchmark.rs

contracts/fixtures/durable-preparation-v1/
|-- README.md
|-- cases.json
`-- expected-outcomes.json

conformance/catalog.yaml
.github/workflows/durable-preparation.yml
.gitattributes                         # LF-pin digest/JCS/SQL-sensitive artifacts
```

**Structure Decision**: One portable orchestration crate is the smallest place for
OS-neutral comparison/guard/provider/outcome contracts. One separate SQLite leaf is the
smallest authoritative store that can atomically own the canonical eight-member set
without broadening the frozen replay database. The replay verifier is added beside the
existing receipt trait and implemented read-only by PLAN-003. No legacy runtime or
effect adapter enters the dependency path.

## Acceptance Traceability

| Evidence gate | Specification coverage | Planned proof |
|---|---|---|
| `PLAN-004-AUTHORITY` | FR-001..FR-014; SC-001..SC-002 | Non-wire/opaque compile contracts, two captures, eligibility-built replay view, linearizable 250 ms-capped commit permit, exact field comparison and zero-mutation single-fault corpus |
| `PLAN-004-BUDGET` | FR-015..FR-021; SC-003..SC-004 | Read-only preflight before recovery, create-only scopes, exact/minus/plus-one, 100,000-vector oracle, shared-scope contention and no-dispatch-guarded idempotent release |
| `PLAN-004-RECOVERY` | FR-022..FR-027; SC-005..SC-006 | Manifest-last provider, profile/binding/capacity corruption corpus, L2 irreversibility, publication-cleanup races, failed-operation and true-orphan retirement paths and process-kill matrix |
| `PLAN-004-DURABILITY` | FR-028..FR-036; SC-001, SC-006 | Strict schema/profile/invariants, canonical eight-member transaction, permanent transition ledger, exact attempt readback, closed fault-boundary inventory, cancellation, corruption and no-dispatch source tests |
| `PLAN-004-RESTORE` | FR-037..FR-038; SC-007, SC-011 | PAUSED quiescent cut, SQLite online backup, exact recovery inventory, detached signed provenance/substitution corpus, matching dual-root `RESTORE_PENDING`, empty-root restore, non-reactivation proof and negative public-surface test proving only two non-constructible redacted evidence projections are exported while all producers/authorities remain internal |
| `PLAN-004-DATA` | FR-039..FR-040; SC-011 | Classification/at-rest provisioning, seeded redaction, no-egress/dependency scan, explicit no-pruning and guarded-retirement tests |
| `PLAN-004-PORTABILITY` | FR-003, FR-006, FR-041; SC-008 | One unchanged corpus/outcomes and SQL/JSON schema digests on macOS arm64, Linux x64 and Windows x64 |
| `PLAN-004-PERFORMANCE` | FR-042; SC-003, SC-009..SC-010 | Physical-M4 raw 500+10,000 latency samples, separate recovery workload, controlled held-writer and 250 ms permit-deadman deadline/no-late-write evidence |
| `PLAN-004-SUPPLY` | FR-043..FR-044; SC-007, SC-012 | Catalog entry, exact lock/native SQLite source, license/advisory/SBOM/provenance, immutable CI, rollback refusal, clean restore and removal drill |

## Complexity Tracking

No constitutional violation requires a waiver. The two-crate split is an authority
boundary, not an additional runtime/service: portable contracts must not own SQLite or
native providers, and the storage adapter must atomically own the complete positive
operation, transition, comparison, budget, recovery-reference, event and metadata set.
Both remain synchronous in-process libraries with one coordinator database.
