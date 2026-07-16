# Implementation Plan: Durable Signed Task Authority

**Branch**: `codex/plan-006-durable-signed-task-authority` (Spec Kit feature
`006-durable-signed-task-authority`) | **Date**: 2026-07-15 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from
`specs/006-durable-signed-task-authority/spec.md`

## Summary

Close the remaining R1 signed-authority gap without changing PLAN-001 through
PLAN-005 wire bytes or entering host effects. A trusted request-surface signer
produces one canonical `HumanRequestGrantV1`. The core verifies and atomically
consumes that grant while retaining one signed root `TaskLeaseV1`; exact retries
recover the same bytes and conflicts issue nothing. Delegation only reduces every
governed axis and atomically accounts aggregate sibling allocation. The core then
binds one terminal signed `ApprovalDecisionV1` to the exact current PLAN-001 plan,
grant and lease chain. Current projections derived from verified durable state
replace synthetic lease and authorization inputs at the existing PLAN-002,
PLAN-004 and PLAN-005 comparison seams.

The implementation adds an isolated portable contract crate, portable authority
orchestration, a separate strict SQLite authority store, and a downstream
projection adapter. A single authority `BEGIN IMMEDIATE` guard captures both
lease and approval from one snapshot and remains held through the final existing
coordinator commit, closing interprocess revocation/generation TOCTOU without a
cross-store transaction or coordinator V3 migration. PLAN-006 bootstraps a new
empty authority root under PAUSE and never backfills legacy/synthetic views. It
adds canonical fixtures, fault/readback, backup/clean-restore, portability,
performance, supply-chain and exact-removal evidence. Real ingress, WebAuthn,
IPC, host effects, R2, physical power-loss and Tier 1 claims remain out of scope.

## Technical Context

**Language/Version**: Rust edition 2021 with exact Rust/Cargo `1.96.1`, minimal
profile, `rustfmt` and strict Clippy, pinned by `kernel/rust-toolchain.toml`.
Reviewed Markdown, JSON Schema draft 2020-12, canonical JSON fixtures, SQLite SQL
and Python 3 evidence tools accompany the Rust implementation.

**Primary Dependencies**: Exact locked `base64 0.22.1`, `ed25519-dalek 2.2.0`,
`serde 1.0.228`, `serde_json 1.0.150`, `serde_json_canonicalizer 0.3.2`,
`sha2 0.10.9`, `unicode-normalization 0.1.25`, `getrandom 0.4.3`, and
`rusqlite 0.40.1` with bundled SQLite `3.53.2`, backup and serialize support;
exact `proptest 1.11.0` for development. The projection crate depends on the
existing `helix-contracts`, `helix-plan-eligibility`, `helix-plan-preparation`
and `helix-plan-dispatch` public seams. Existing crates do not depend on
PLAN-006. No Tokio, network client, system SQLite, UUID/ambient-time API, dynamic
SQLite extension, raw-secret dependency or protected legacy runtime dependency.

**Storage**: A distinct provisioned local SQLite root owned by
`helix-task-authority-sqlite`, with `application_id=1212962881` (`HLXA`,
`0x484c5841`) and `user_version=1`. It stores exact signed grant/lease/decision
bytes and protected digests; one-shot claims; parent/child links; allocation and
counter tombstones; terminal plan bindings; append-only revocations and trust
history; canonical mutation-attempt bindings; monotonic generations;
transition/conflict events; bootstrap receipts; and root lifecycle metadata.
Tables are strict and create-only facts cannot be
updated or deleted. The profile is WAL, `synchronous=FULL`, foreign keys and
recursive triggers on, `trusted_schema=OFF`, `cell_size_check=ON`, controlled
checkpoints and trusted-deadline-bounded short writer transactions.

Ordinary open validates the exact application/schema/root/durability identity
and all cross-record invariants without repair or migration. The supported
migration is an explicit restartable PAUSED bootstrap from the exact PLAN-005
coordinator V2 baseline into a new empty PLAN-006 root. It retains a migration
receipt but imports zero unsigned, legacy or synthetic authority rows. One
unified authority writer guard supplies a stable current snapshot across an
existing downstream coordinator commit; no transaction spans databases. Backup
uses independently coherent online snapshots bound by one published-last paused
manifest signed by the separate `backup-provisioner-signing` maintenance purpose
and verified only through an externally provisioned purpose-specific trust
resolver; manifest-embedded public keys are evidence copies, never trust anchors.
That signature is recovery evidence, never task authority. Clean restore rotates
identities/epochs, enters `RESTORE_PENDING`, and reactivates no restored lease or
approval.

**Testing**: Locked format/check/Clippy/workspace tests; exact canonical positive
and negative wires; duplicate/unknown/noncanonical/domain/purpose/key mutation;
at least 100,000 generated lease/delegation cases; 10,000 sequential retries,
100 rounds x 64 threads and 20 rounds x eight processes for root issuance; the
same concurrency classes for sibling allocation and terminal approve/deny races;
expiry/reboot/trust/revocation and ancestor invalidation; exact PLAN-002/004/005
projection comparison and ordered-guard tests; fault injection plus applicable
process-kill at every declared durable boundary; one-readback ambiguity; bootstrap
migration/restart/rollback refusal; corruption and substitution; paused backup,
empty-root restore and zero reactivation; permanent retention/redaction; bounded
queue/control lane; multi-platform portability; source/dependency policy;
supply-chain and isolated-removal evidence; controlled release benchmark. Fault
hooks remain behind a non-default feature.

**Target Platform**: Common contracts and behavior are unchanged on macOS arm64,
Linux x86_64 and Windows x64. macOS arm64 is the reference platform; only a
separately controlled physical Mac mini M4 run may satisfy a physical performance
gate. Hosted CI proves compilation, wire/protocol semantics, process-kill and
synthetic no-effect durability only. It does not prove power-loss durability,
production request identity, WebAuthn, physical isolation, full-machine recovery
or Tier 1.

**Project Type**: Four portable/native Rust library crates plus one independent
SQLite authority domain, reviewed Markdown/SQL/JSON contracts, a versioned
fixture corpus, CI workflow, evidence tools and deterministic validation examples.
No CLI, server, real ingress, authentication UI, network transport, supervisor,
OS adapter or host-effect implementation.

**Performance Goals**: On the declared reference profile, after 500 warmups and
10,000 measurements, strict verification of the three-contract chain plus current
projection has p95 <= 2 ms. Root issuance, delegation and terminal-decision
transactions have p95 <= 25 ms and p99 <= 100 ms. Across 100 duplicate-flood
trials of 10,000 requests, new ordinary work is bounded or refused within 50 ms,
while current status/revocation remains p99 <= 100 ms through a separately
reserved control lane. Raw sample series, hardware, OS, toolchain, corpus,
concurrency and percentiles are retained. Hosted values remain diagnostic.

**Constraints**: Every positive value derives from exact signed bytes and a
current verified durable chain. Unknowns deny. Key IDs, grant/lease/decision IDs,
claims, allocations, terminal results and revocations are create-only. UTC expiry
is half-open; live authority also requires the exact same boot and an exclusive
monotonic deadline. Retry cannot renew authority. One authority guard transaction
must cover both lease and authorization and remain held through final downstream
commit; lock order is authority before coordinator and never reversed. No
cross-store atomicity claim, blind re-sign/reissue, legacy backfill, raw message,
authentication assertion, bearer token, private-key persistence/backup, native
path, floating point, ambient process authority, host effect, pruning or secure-
erasure claim. V1 signed bytes and one-shot tombstones are permanently retained.

**Scale/Scope**: Single-user v1; three distinct signer purposes and resolver/key
namespaces for request grants, task leases and approval decisions, each with
immutable rotating key IDs; one root lease per
human grant; bounded delegation depth and closed resource/intention/budget axes;
one terminal decision per exact plan target; ordinary queue capacity 1,024 plus
reserved control capacity 32; exactly the repetition/concurrency/fault/performance
corpora stated above. Catalogue mappings are limited to `REQUEST-001`, `SEC-002`
and `SEC-003` and remain pending evidence. Complete `IntentRequest`,
`PolicySnapshot`, `CapabilityReport`, real WebAuthn/edge, registered triggers,
effects, R2 and production activation are excluded.

## Constitution Check

*GATE: Passed before Phase 0 research; re-checked after Phase 1 design.*

- **Boundary — PASS**: Agent, caller, transport, raw message, authentication
  assertion, legacy runtime, synthetic booleans and caller rows are untrusted.
  Only the three exact purpose-separated signed contracts and current durable
  chain can create a projection. No host/share/egress access or real effect is
  introduced.
- **Authority — PASS**: Contracts are typed, closed, versioned, task/workload/
  plan-bound and canonical; unknown schema, algorithm, purpose, field or enum
  denies. Root issuance is core-only, delegation is monotonically restrictive,
  terminal decisions cannot flip, and historical signature validity is not
  current authority.
- **Effects — PASS**: Root issuance, delegation/allocation, counter consumption,
  decision and revocation have explicit durable atomic graphs and one-shot
  readback rules before any positive projection. PLAN-006 performs no host
  effect, so effect verification, compensation and settlement are explicitly
  deferred rather than falsely satisfied.
- **Data — PASS**: Signed authority contains bounded identifiers, digests, scope,
  counters and redacted evidence references only. Raw messages, assertions,
  bearer values, private keys and native paths are excluded. Restricted exact
  wires/tombstones are retained; public outputs use closed redacted codes; no
  egress occurs.
- **Portability — PASS**: Common contracts contain safe bounded integers, opaque
  portable resource components and explicit UTC/epoch values only. One unchanged
  corpus runs across macOS arm64, Linux x64 and Windows x64; unsupported storage
  or durability capability is refused.
- **Performance — PASS**: Verification, durable transitions, duplicate-flood
  admission and control-lane response have explicit workload, warmup,
  repetition, percentile and raw-sample requirements. Hosted results cannot
  satisfy the separate physical M4 gate.
- **Evidence — PASS**: Negative mutation, replay, expiry, revocation, concurrency,
  fault/readback, migration, backup/restore, redaction, portability, supply-chain
  and exact-removal gates bind an exact commit. Catalogue claims remain pending
  until their own immutable evidence passes.

Post-design re-check: **PASS, 7/7**, with no constitutional deviation or waiver.
The separate store plus retained unified guard supplies the required stable
authority cut without claiming a cross-store transaction.

## Phase 0: Research Decisions

[research.md](research.md) resolves all design questions:

1. Stop after durable signed request/lease/decision authority and exact current
   projections, before ingress, WebAuthn, IPC, effects or R2.
2. Use four one-way crates for wires, portable authority, SQLite and downstream
   projection.
3. Freeze three distinct canonical Ed25519 profiles with strict duplicate-aware
   RFC 8785 verification.
4. Use a separate `HLXA` schema-v1 SQLite domain and one retained unified writer
   guard, not a coordinator V3 overlay or a cross-store transaction.
5. Bootstrap an empty authority root explicitly under PAUSE and never backfill
   legacy/synthetic authority.
6. Consume an issuer-scoped human grant once and recover one identical retained
   root chain on exact retry.
7. Make delegation monotonically restrictive and atomically aggregate-bounded.
8. Retain exactly one immutable terminal plan-bound approval or denial.
9. Use create-only transactions, domain-separated attempt IDs and at most one
   fresh uncertainty readback.
10. Combine half-open UTC validity, exact same-boot monotonic deadlines and
    monotonic generations.
11. Separate historical cryptographic verification from current trust and
    append-only revocation.
12. Project only through existing PLAN-002/004/005 seams while retaining the
    authority guard through final commit.
13. Bind independently coherent paused backups in one published-last manifest;
    clean restore reactivates no authority.
14. Permanently retain v1 restricted evidence/tombstones and expose only closed
    redacted public outcomes.
15. Use one unchanged cross-platform corpus, a separate derived fault registry,
    pending catalogue claims, and exact baseline removal evidence.

No `NEEDS CLARIFICATION` remains.

## Phase 1: Design and Contracts

- [data-model.md](data-model.md) defines canonical authorities, durable rows,
  atomic graphs, generations, current projections, guard custody, migration,
  backup/restore, retention and closed outcomes.
- [contracts/signed-task-authority-v1.md](contracts/signed-task-authority-v1.md)
  freezes ownership, canonical verification, signer purposes, semantic and
  cross-contract invariants, version handling and fixture rules.
- [contracts/human-request-grant-v1.schema.json](contracts/human-request-grant-v1.schema.json),
  [contracts/task-lease-v1.schema.json](contracts/task-lease-v1.schema.json) and
  [contracts/approval-decision-v1.schema.json](contracts/approval-decision-v1.schema.json)
  freeze exhaustive wire member names, nesting, encodings and bounds.
- [contracts/task-authority-projections-v1.md](contracts/task-authority-projections-v1.md)
  freezes the exact PLAN-001/002/004/005 mappings, unified guard ownership, lock
  order, deadline behavior and legacy refusal.
- [contracts/task-authority-store-schema-v1.sql](contracts/task-authority-store-schema-v1.sql)
  defines the independent strict authority database, create-only facts and
  cross-record invariants.
- [contracts/task-authority-backup-manifest-v1.schema.json](contracts/task-authority-backup-manifest-v1.schema.json)
  defines the paused multi-component backup inventory, checkpoints, public-key
  bindings, bootstrap receipt and provenance.
- [contracts/fault-boundaries-v1.json](contracts/fault-boundaries-v1.json) defines
  the separate ordered PLAN-006 fault phases and required coverage classes; exact
  boundary instances/cardinality are frozen after implementation operations
  stabilize.
- [quickstart.md](quickstart.md) defines repeatable contract, one-shot,
  delegation, decision, projection/guard, migration, fault, overload, restore,
  portability, supply/removal and controlled benchmark validation.

The repository does not contain the Spec Kit helper
`.specify/scripts/bash/update-agent-context.sh`; therefore no generated agent
context command can run. `AGENTS.md` remains authoritative for the Constitution
and Graphify workflow, and no feature dependency summary is inserted manually.

## Acceptance and Evidence Mapping

| Gate | Requirements / criteria | Required evidence |
|---|---|---|
| `PLAN006-CONTRACT` | FR-001..FR-006; SC-001, SC-011 | Closed schemas; duplicate-aware RFC 8785 decoding; purpose/domain/key separation; complete leaf mutation; canonical golden bytes; redaction |
| `PLAN006-REQUEST` | FR-007..FR-011, FR-031..FR-032, FR-035..FR-036; SC-002..SC-003, SC-007 | Exact human context; current trust/scope; atomic one-shot root issue; identical retry; 10,000 sequential, 100 x 64-thread and 20 x eight-process cases; uncertainty readback |
| `PLAN006-LEASE` | FR-012..FR-021, FR-031, FR-033, FR-036; SC-004, SC-007 | Core-only issue; every one-axis restriction; checked aggregate sibling allocation; counter tombstones; ancestor expiry/revocation; 100,000 generated cases |
| `PLAN006-DECISION` | FR-022..FR-030, FR-031, FR-034..FR-036; SC-005, SC-007, SC-011 | Exact plan/chain/evidence binding; approve/deny contention; terminal immutability; L2 user-verification rule; current/historical distinction; redaction |
| `PLAN006-PROJECTION` | FR-014, FR-020, FR-024..FR-029, FR-041..FR-045; SC-006 | Exact PLAN-001/002/004/005 mappings; unified HLXA custody; generation/digest/ancestor/revocation/deadline mutation; zero downstream mutation; legacy/source exclusion |
| `PLAN006-DURABILITY` | FR-009..FR-010, FR-018..FR-021, FR-028..FR-039; SC-003..SC-009 | Strict HLXA schema; atomic graphs; contention; fault/process-kill boundaries; one fresh readback; corruption/orphan/rollback refusal; permanent history |
| `PLAN006-RESTORE` | FR-037..FR-040; SC-008..SC-009 | Explicit paused empty-root bootstrap; no legacy backfill; independently coherent published-last backup; clean restore under new epochs; zero reactivation |
| `PLAN006-PORTABILITY` | FR-001..FR-006, FR-046; SC-001, SC-010..SC-011 | One unchanged schema/fixture/outcome corpus and byte-identical common summaries on macOS arm64, Linux x64 and Windows x64 |
| `PLAN006-PERFORMANCE` | FR-036, FR-048; SC-012..SC-013 | Declared reference profile; 500 warmups/10,000 raw samples; p95/p99 gates; 100 x 10,000 duplicate floods; reserved status/revocation control lane |
| `PLAN006-SUPPLY` | FR-044, FR-046..FR-048; SC-009..SC-011, SC-014 | Exact locked dependency/license/advisory/SBOM/provenance bundle; immutable artifacts; baseline-tree removal; prior-plan regressions; honest pending claims |

`conformance/catalog.yaml` registers PLAN-006 only after `tasks.md` exists so the
roadmap never shows an untracked or catalogue-only plan. Its only mappings are:

| Catalogue claim | PLAN-006 owner/gate | Initial state |
|---|---|---|
| `REQUEST-001` | `helix-task-authority`; `PLAN006-REQUEST` plus `PLAN006-CONTRACT` | `pending-evidence` |
| `SEC-002` | `helix-task-authority-projections`; `PLAN006-PROJECTION` plus `PLAN006-DURABILITY` | `pending-evidence` |
| `SEC-003` | `helix-task-authority`; `PLAN006-LEASE` plus `PLAN006-PROJECTION` | `pending-evidence` |

Aggregate and mapped claims remain `pending-evidence`; local evidence is `pending`,
immutable evidence is `pending-workflow-evidence`, and promotion requires one exact
successful immutable commit. No hosted or local result promotes physical M4,
power-loss, production ingress/WebAuthn, effects, R2 or Tier-1 claims.

## Project Structure

### Documentation (this feature)

```text
specs/006-durable-signed-task-authority/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── signed-task-authority-v1.md
│   ├── task-authority-projections-v1.md
│   ├── human-request-grant-v1.schema.json
│   ├── task-lease-v1.schema.json
│   ├── approval-decision-v1.schema.json
│   ├── task-authority-store-schema-v1.sql
│   ├── task-authority-backup-manifest-v1.schema.json
│   └── fault-boundaries-v1.json
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
kernel/
├── Cargo.toml
├── Cargo.lock
├── helix-task-authority-contracts/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── canonical.rs
│   │   ├── crypto.rs
│   │   ├── digest.rs
│   │   ├── error.rs
│   │   ├── validation.rs
│   │   ├── human_request_grant.rs
│   │   ├── task_lease.rs
│   │   └── approval_decision.rs
│   └── tests/
│       ├── human_request_grant_contract.rs
│       ├── task_lease_contract.rs
│       ├── approval_decision_contract.rs
│       ├── cross_contract.rs
│       ├── property.rs
│       ├── portability.rs
│       └── redaction.rs
├── helix-task-authority/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── request.rs
│   │   ├── lease.rs
│   │   ├── delegation.rs
│   │   ├── decision.rs
│   │   ├── revocation.rs
│   │   ├── projection.rs
│   │   ├── guard.rs
│   │   ├── store.rs
│   │   ├── outcome.rs
│   │   ├── control.rs
│   │   └── test_fault.rs
│   └── tests/
│       ├── request.rs
│       ├── delegation.rs
│       ├── delegation_property.rs
│       ├── decision.rs
│       ├── revocation.rs
│       ├── projection.rs
│       ├── property.rs
│       └── redaction.rs
├── helix-task-authority-sqlite/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── config.rs
│   │   ├── clock.rs
│   │   ├── connection.rs
│   │   ├── root_safety.rs
│   │   ├── schema.rs
│   │   ├── grant.rs
│   │   ├── lease.rs
│   │   ├── delegation.rs
│   │   ├── decision.rs
│   │   ├── revocation.rs
│   │   ├── projection.rs
│   │   ├── guard.rs
│   │   ├── readback.rs
│   │   ├── event.rs
│   │   ├── queue.rs
│   │   ├── maintenance.rs
│   │   ├── manifest.rs
│   │   └── test_fault.rs
│   ├── tests/
│   │   ├── contract.rs
│   │   ├── contention.rs
│   │   ├── process_crash.rs
│   │   ├── bootstrap_migration.rs
│   │   ├── backup_restore.rs
│   │   ├── corruption.rs
│   │   ├── retention.rs
│   │   ├── redaction.rs
│   │   ├── portability.rs
│   │   └── queue_control.rs
│   └── examples/
│       ├── durable_task_authority_corpus.rs
│       └── durable_task_authority_benchmark.rs
└── helix-task-authority-projections/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs
    │   ├── eligibility.rs
    │   ├── preparation.rs
    │   ├── dispatch.rs
    │   └── guards.rs
    └── tests/
        ├── plan002.rs
        ├── plan004.rs
        ├── plan005.rs
        ├── guard_order.rs
        ├── portability.rs
        └── redaction.rs

contracts/fixtures/durable-signed-task-authority-v1/
├── README.md
├── cases.json
├── chain-cases.json
├── expected-outcomes.json
├── public-keys.json
└── golden/
    ├── README.md
    ├── human-request-grant.protected.jcs
    ├── human-request-grant.envelope.jcs
    ├── root-task-lease.protected.jcs
    ├── root-task-lease.envelope.jcs
    ├── child-task-lease.protected.jcs
    ├── child-task-lease.envelope.jcs
    ├── approval-approved.protected.jcs
    ├── approval-approved.envelope.jcs
    ├── approval-denied.protected.jcs
    ├── approval-denied.envelope.jcs
    ├── ancestor-vector.jcs
    ├── ancestor-vector.sha256
    ├── plan-bound-lease-projection.jcs
    ├── plan-bound-lease-projection.sha256
    ├── revocation-vector.jcs
    └── revocation-vector.sha256

.github/workflows/durable-signed-task-authority.yml
tools/plan006_supply_chain.py
tools/plan006_removal_drill.py
tools/tests/test_plan006_evidence.py
```

**Structure Decision**: Four PLAN-006 crates preserve a one-way dependency graph:
wire contracts are leaf-portable; the authority core owns semantics and abstract
store/guard interfaces; SQLite implements those interfaces in the independent
`HLXA` root; and the projection adapter alone imports existing PLAN-002/004/005
types. Existing production crates, wire contracts and protected legacy runtime
sources remain unchanged. Four existing dependency-policy tests may add only the
reviewed `helix-task-authority-projections` direct consumer, while one PLAN-004
workspace-removal test may recognize the four new PLAN-006 packages as downstream
members. PLAN-005's retained removal/supply guards may classify the new crate,
fixture and Graphify prefixes while proving its frozen production closure is otherwise
unchanged. These seven test edits and four retained PLAN-005 policy/evidence artifacts
are part of the PLAN-006 integration and exact-removal footprint and must be restored
to the clean source versions when PLAN-006 is removed. Fixtures, workflow and evidence
tools are PLAN-006-owned and disappear in the isolated-removal drill.

## Complexity Tracking

No constitutional violation, exception or waiver is required. The four-crate
split is a boundary decomposition, not four independently deployed services; the
feature remains one local core responsibility with one new SQLite authority root.
