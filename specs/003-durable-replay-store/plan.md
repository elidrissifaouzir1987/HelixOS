# Implementation Plan: Durable Replay Claim Store

**Branch**: `master` (feature directory `003-durable-replay-store`) | **Date**:
2026-07-10 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/003-durable-replay-store/spec.md`

## Summary

Add a replaceable `helix-replay-sqlite` Rust leaf crate that implements feature 002's
unchanged `ReplayClaimantV1`. A fresh attempt receives a random opaque identity, opens a
short configured SQLite connection, enters `BEGIN IMMEDIATE`, compares both replay
indexes, and commits the checked claimant generation, receipt and one strict claim row
atomically. Exact repeats and conflicts are closed denials; possible commits use
readback by exact attempt identity and remain `Ambiguous` when proof is unavailable or
late.

The store pins one bundled SQLite version and verifies WAL plus `synchronous=FULL` on a
trusted local filesystem. It adds closed/redacted initialization, integrity, controlled
checkpoint, online backup and clean-directory restore operations. Process-kill,
contention, deadline, corruption, backup/restore, conformance and release probes run
with unchanged semantics on Windows x64, Linux x64 and macOS arm64. The result is still
only replay admission evidence: compare-before-`PREPARING`, budgets, recovery material,
grants, adapters and effects remain feature 004+.

## Technical Context

**Language/Version**: Rust edition 2021 with exact toolchain `1.96.1`, `rustfmt` and
`clippy`, pinned by `kernel/rust-toolchain.toml`. No lower MSRV is claimed; exact
toolchain builds are required because rusqlite does not declare one in package metadata.

**Primary Dependencies**: Workspace `helix-plan-eligibility` and `helix-contracts`;
exact `rusqlite 0.40.1` with `default-features=false`, `bundled`, and `backup`
(`libsqlite3-sys 0.38.1`, SQLite 3.53.2); exact `getrandom 0.4.3`; exact existing
`sha2 0.10.9`, `serde 1.0.228`, and `serde_json 1.0.150`. No async runtime, pool,
network client, SQLCipher, extension loading, build-time bindgen or host SQLite.

**Storage**: One fixed SQLite database below a provisioner-attested local root. WAL,
`synchronous=FULL`, `trusted_schema=OFF`, `cell_size_check=ON`, disabled automatic
checkpoint and bounded per-call busy timeout are established and read back. Schema v1
uses an application ID, `user_version=1`, strict metadata and claim tables, one
composite nonce primary key, unique operation/claim/generation indexes, and full
application invariant checks. Live backup uses SQLite's incremental online backup API
and a closed SHA-256 manifest. A synchronized root-role file provides cross-process
reservation and closed `LIVE_READY`, `LIVE_QUARANTINED`, `BACKUP_PACKAGE` and
`RESTORE_PENDING` states. A complete backup is exactly role file + closed database +
manifest; restore targets an empty directory and remains non-claimable pending future
supervisor activation. A separate create-new live-initialization intent makes an
interrupted empty-root reservation restartable without promoting a zero/torn backup or
restore role.

Connection initialization/profile setup uses a deadline-bounded process-local gate per
canonical database path, released before every claim transaction. It prevents redundant
same-process WAL/PRAGMA negotiation without pooling connections or replacing SQLite's
cross-process `BEGIN IMMEDIATE` arbitration. Candidate identity is read in one
consistent transaction before the first persistent profile mutation.

**Testing**: `cargo test --locked`; contract/evaluator integration; table-driven
conformance; exact repeat/conflict tests; 100 x 64-thread and 20 x 8-process contention;
barrier-driven child-process kill points; private commit/readback fault seam; held-writer
deadline tests; schema/application/invariant corruption; initialization race; live
backup and clean restore; redaction/source portability scans; ignored release
benchmark/soak. Fault hooks compile only with the non-default `test-fault-injection`
feature.

**Target Platform**: macOS arm64 is primary (user target: Mac mini M4); Linux x64 and
Windows x64 are required unchanged conformance drivers. Controlled local evidence now
covers Windows x64 and physical Mac mini M4 process commits. Hosted macOS arm64 process
tests and the controlled M4 latency probe do not replace target M4 power-loss and
`F_FULLFSYNC` evidence.

**Project Type**: One storage-adapter library, versioned fixture corpus, conformance
catalog entry, CI matrix, validation example and immutable evidence directory.

**Performance Goals**: On each controlled local-SSD target, 500 warmups plus 10,000
fresh FULL/WAL commits including connection open/close achieve p95 <= 25 ms and
p99 <= 100 ms. Controlled busy-lock calls return by their boot-monotonic deadline plus
50 ms scheduler tolerance. Contention produces one durable winner per key.

**Constraints**: `#![forbid(unsafe_code)]`; no hard cancellation claim for an in-flight
VFS flush; no positive result after deadline; no mutation retry after possible commit;
no detached work; no raw plan, signature, resource path, secret or egress; no native
path/provider error in public diagnostics; no runtime `cfg(target_os)` semantics; no
network/cloud/removable filesystem fallback; no deletion/pruning; no host effect or
adapter authority. Provisioning must attest same-volume regular files with working
cross-process exclusive locks, exclusive creation, hard links and `sync_all`; this
feature does not infer those properties from a path.

**Scale/Scope**: Schema v1, one store namespace, permanent claims up to JavaScript-safe
u64 generation, 10,000-claim baseline corpus and bounded maintenance operations. This
feature proves application crash/reopen and online backup/restore. It does not prove
power-loss behavior, full coordinator state, restored-system activation, budget or
adapter lifecycle.

## Constitution Check

*GATE: Passed before Phase 0 research; re-checked after Phase 1 design.*

- **Boundary - PASS**: The agent and plan never receive a store path or SQLite API.
  Only the trusted host core constructs a provisioner-attested local root and injected
  clock. The crate has no network, host-effect, secret, share or raw SQL surface.
- **Authority - PASS**: The only new authority is the permanent replay linearization
  point already typed by `ReplayClaimantV1`. Both nonce and operation keys, exact
  binding digest, generation and attempt receipt commit together. Unknown, malformed,
  conflicting, expired or unavailable state denies. A receipt remains non-serializable
  eligibility evidence, never preparation or adapter authority.
- **Effects - PASS**: The sole mutation is sovereign replay state. Pre-write failures
  are unavailable; possible commit is read back without mutation retry and otherwise
  ambiguous. Process-kill tests prove all-or-none recovery. There is no target effect,
  so verification/compensation is N/A; feature 004 must still compare fresh bindings,
  reserve budgets and durably prepare recovery before dispatch.
- **Data - PASS**: Restricted operational state contains only the two uniqueness keys,
  binding/claim digests, safe generation and storage metadata. No secret, raw plan,
  signature, task/workload/resource content or egress exists. Public errors, debug,
  metrics, fixtures and evidence are redacted. Rows are permanent while their authority
  history can be accepted.
- **Portability - PASS**: SQLite is bundled at one version; common logic, schema and
  expected outcomes are identical on macOS arm64, Linux x64 and Windows x64. Native
  paths stop at the adapter boundary. Locality is a trusted provisioning assertion;
  unsupported filesystem semantics are refused, never emulated.
- **Performance - PASS**: SC-002, SC-004 and SC-007 declare contention, scheduler
  tolerance, samples and percentiles. Lock waits use the remaining monotonic deadline;
  storage/RNG/busy/generation failures close admission. Kernel I/O stalls are not
  falsely described as hard-cancellable.
- **Evidence - PASS**: `PLAN-003` covers exact/repeat/conflict, crash phase, ambiguity,
  deadline, corruption, migration refusal, backup/restore, redaction, supply chain,
  conformance and performance. Process-kill and power-loss claims are separate.
  Restore evidence requires paused external activation and new supervisor epochs.

Post-design re-check: PASS. The data model keeps both uniqueness constraints in one row,
the API cannot dispatch, backup uses the engine API, and restore does not claim absence
of post-backup work. No constitutional deviation or complexity waiver is needed.

## Phase 0: Research Decisions

[research.md](research.md) records the resolved decisions:

1. Close production replay durability before the separately specified cross-store
   compare-and-prepare transition.
2. Isolate SQLite in `helix-replay-sqlite`; preserve feature 001/002 contracts.
3. Pin bundled rusqlite/SQLite, online-backup and attempt-token dependencies exactly.
4. Represent both replay indexes with one strict row and minimal retained evidence.
5. Use `BEGIN IMMEDIATE`, checked generation and a fresh random attempt identity.
6. Inject the same boot-monotonic clock domain; bound lock waiting and forbid late
   positive results without claiming VFS hard cancellation.
7. Classify outcomes by mutation phase and exact fresh-view readback, never error text.
8. Verify WAL/FULL and local-filesystem assurance; control checkpoints outside claims.
9. Validate application/schema identity and full storage/application invariants.
10. Use online backup in both backup and restore paths with a closed manifest.
11. Use barrier-driven child-process kills plus a private fault seam and honest labels.
12. Run one semantic corpus across Windows, Linux and hosted macOS arm64.
13. Benchmark acknowledged durable commits on recorded controlled hardware.
14. Keep diagnostics closed/redacted and omit a replay-pruning path.

## Phase 1: Design and Contracts

- [data-model.md](data-model.md) defines configuration, attempt, metadata, claim row,
  receipt, manifest, maintenance evidence, invariants and state transitions.
- [contracts/durable-replay-store-v1.md](contracts/durable-replay-store-v1.md) defines the
  Rust library boundary, claim algorithm, closed open/maintenance codes, deadline and
  ambiguity semantics, schema identity and lifecycle methods.
- [contracts/replay-store-schema-v1.sql](contracts/replay-store-schema-v1.sql) is the
  reviewed normative schema/migration input embedded by the crate and checked for drift.
- [contracts/backup-manifest-v1.schema.json](contracts/backup-manifest-v1.schema.json)
  defines the non-secret backup evidence format.
- [quickstart.md](quickstart.md) defines repeatable local validation, fault, contention,
  backup/restore, benchmark and evidence commands plus expected outcomes.

The SpecKit distribution in this repository has no
`.specify/scripts/bash/update-agent-context.sh`; the prescribed generated context update
cannot run. `AGENTS.md` already contains the project-specific Graphify workflow and is
not altered with transient dependency details. This missing helper is documented rather
than silently fabricated.

## Project Structure

### Documentation (this feature)

```text
specs/003-durable-replay-store/
|-- spec.md
|-- plan.md
|-- research.md
|-- data-model.md
|-- quickstart.md
|-- contracts/
|   |-- durable-replay-store-v1.md
|   |-- replay-store-schema-v1.sql
|   `-- backup-manifest-v1.schema.json
|-- checklists/requirements.md
|-- evidence/
`-- tasks.md
```

### Source Code (repository root)

```text
kernel/
|-- Cargo.toml
|-- Cargo.lock
`-- helix-replay-sqlite/
    |-- Cargo.toml
    |-- src/
    |   |-- lib.rs
    |   |-- claim.rs
    |   |-- clock.rs
    |   |-- config.rs
    |   |-- connection.rs
    |   |-- error.rs
    |   |-- maintenance.rs
    |   |-- manifest.rs
    |   |-- schema.rs
    |   `-- test_fault.rs       # non-default test-fault-injection feature only
    |-- tests/
    |   |-- common/mod.rs
    |   |-- contract.rs
    |   |-- eligibility_integration.rs
    |   |-- contention.rs
    |   |-- process_crash.rs
    |   |-- deadline.rs
    |   |-- schema_corruption.rs
    |   |-- backup_restore.rs
    |   |-- conformance.rs
    |   |-- redaction.rs
    |   `-- portability.rs
    `-- examples/
        `-- durable_replay_benchmark.rs

contracts/fixtures/durable-replay-store-v1/
|-- README.md
|-- cases.json
`-- expected-outcomes.json

conformance/catalog.yaml
.github/workflows/durable-replay-store.yml
```

**Structure Decision**: One SQLite leaf crate is the smallest replaceable production
adapter for the existing replay trait. Storage-neutral eligibility remains unchanged;
schema/manifest contracts and the corpus stay language-readable outside the crate.
Fault injection is compiled out of default builds. No legacy MVP-0 source is modified
or used as durability evidence.

## Acceptance Traceability

| Evidence gate | Specification coverage | Planned proof |
|---|---|---|
| `PLAN-003-CLAIM` | FR-001..FR-010, SC-001 | Contract, exact-repeat, conflict, generation and evaluator integration tests |
| `PLAN-003-DEADLINE` | FR-011..FR-012, SC-004 | Injected clock and held-writer busy-deadline tests |
| `PLAN-003-DURABILITY` | FR-013..FR-017, FR-029, SC-003 | WAL/FULL verification, schema/integrity and process-kill/fault matrix |
| `PLAN-003-RESTORE` | FR-018..FR-022, SC-005 | Live online backup, manifest negative corpus and clean-directory restore |
| `PLAN-003-DATA` | FR-023..FR-026, FR-030..FR-031, SC-008 | Persistence allowlist, redaction sentinels, no-egress/dependency and removal checks |
| `PLAN-003-PORTABILITY` | FR-027..FR-029, SC-006 | Unchanged fixture summary and source scan on the three-host CI matrix |
| `PLAN-003-PERFORMANCE` | SC-002, SC-004, SC-007 | Thread/process contention, controlled deadline probe and raw release samples |
| `PLAN-003-SUPPLY` | SC-009 | Exact lockfile, SQLite source/version, license/vulnerability and restore drill evidence |

## Complexity Tracking

No constitutional violation requires a waiver. SQLite and the non-default fault seam are
necessary implementation boundaries for the architecture-selected durable store and
its crash proof; neither broadens runtime authority.
