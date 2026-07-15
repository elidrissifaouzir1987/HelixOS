# Implementation Plan: Durable One-Shot Dispatch

**Branch**: `codex/plan-005-durable-dispatch` (Spec Kit feature
`005-durable-dispatch`) | **Date**: 2026-07-12 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/005-durable-dispatch/spec.md`

## Summary

Extend the R1 durable coordinator from the non-dispatchable PLAN-004 boundary to the
next normative lifecycle slice. One current invariant-valid `PREPARING` record is
revalidated under the existing globally ordered authority guards and a fresh dispatch
permit. The coordinator canonicalizes and signs one short `ExecutionGrantV1`, then one
schema-v2 transaction stores the exact signed bytes and performs
`PREPARING -> DISPATCHING` with its permanent transition and redacted outbox event before
delivery can begin.

A separate adapter trust domain receives only the signed grant. Its independent inbox
verifies the contract and an independently observed supervisor epoch, enforces
create-only uniqueness for grant, operation and nonce, consumes the authority once, and
stores one signed `ExecutionReceiptV1`. PLAN-005 exposes no execution-token API. The
coordinator accepts only the exact retained receipt to perform
`DISPATCHING -> EXECUTING`. `EXECUTING` in this feature proves consumed adapter authority,
not a host mutation. Lost acknowledgement reuses the same grant and receipt; transient
inbox absence never proves non-delivery. Each possible-handoff attempt receives exactly
one automatic readback sequence of at most four observations at offsets 0/25/100/275 ms
within 500 ms of the first observation, truncated by any earlier caller/grant deadline.
A receipt retained before expiry remains verifiable afterward as evidence of that prior
decision without renewing authority. Exhaustion or unavailability never loops and
becomes `OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED` rather than a new grant. Exact signed
`REFUSED_DEFINITE` plus fenced no-inflight proof closes through the normative
reconciliation path to `FAILED`, atomically closes the PLAN-004 base operation and
releases its held reservation once. Such receipts exist only after `RECEIVED`, with the
closed reasons `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` or `ADAPTER_PAUSED`;
destination/protocol/capability/capacity failures occur before `RECEIVED`, retain
diagnostic/quarantine evidence and never produce a receipt.

The implementation adds portable wire values to a new `helix-dispatch-contracts` crate,
portable orchestration to `helix-plan-dispatch`, a new strict
`SqliteCoordinatorStoreV2` beside the unchanged v1 API, and a separate
`helix-dispatch-inbox-sqlite` no-effect adapter store. There is deliberately no
cross-store transaction, real IPC, host effect, legacy-kernel authority, production
supervisor, or R2 platform driver. Migration, fault injection, quiescent cross-store
backup/restore, redaction, performance, supply-chain, removal, multi-platform CI and
immutable evidence are in scope; physical power-loss and Tier 1 claims remain pending.

## Technical Context

**Language/Version**: Rust edition 2021 with exact Rust/Cargo `1.96.1`, minimal profile,
`rustfmt` and strict Clippy, pinned by `kernel/rust-toolchain.toml`. New crates use
`#![forbid(unsafe_code)]` and deny missing debug implementations.

**Primary Dependencies**: Existing workspace `helix-contracts`,
`helix-plan-preparation` and `helix-coordinator-sqlite`; new leaf crates depend only on
their narrower dispatch contracts/traits; exact `ed25519-dalek 2.2.0`, `base64 0.22.1`,
`serde 1.0.228`, `serde_json 1.0.150`, `serde_json_canonicalizer 0.3.2`,
`sha2 0.10.9`, `unicode-normalization 0.1.25`, `getrandom 0.4.3`, `rusqlite 0.40.1`
with bundled SQLite 3.53.2 and backup support, plus exact `proptest 1.11.0` for
development. No Tokio, network client,
system SQLite, UUID/ambient-time API, dynamic extension, raw secret dependency or
legacy `helixos-kernel` production dependency.

**Storage**: `SqliteCoordinatorStoreV1` and the reviewed PLAN-004 schema remain strict
and unchanged. An explicit paused maintenance operation verifies and backs up v1, then
adds a schema-v2 dispatch overlay and publishes `SqliteCoordinatorStoreV2`. The overlay
retains all PLAN-004 rows unchanged and adds exact signed grants, dispatch attempts,
effective `DISPATCHING`/`EXECUTING`/`OUTCOME_UNKNOWN`/
`RECONCILIATION_REQUIRED`/`FAILED` transitions,
delivery/readback metadata and redacted events. Migration is never automatic during
ordinary open; v1 rejects v2, v2 rejects incomplete upgrades, and in-place downgrade is
forbidden after dispatch history exists. Base preparation remains `PREPARING` with its
reservation held for every live/unknown state; only exact final no-consumption
reconciliation may append the existing base `PREPARING -> FAILED`, release the hold and
finalize the overlay `FAILED` state in one transaction.

The dispatch inbox is a separate provisioner-bound local SQLite root with a distinct
application ID and schema v1. It stores canonical grant bytes, validation/consumption
generations, exact receipt bytes, conflict/quarantine evidence and root lifecycle
metadata. Both stores use strict tables, WAL, `synchronous=FULL`, controlled checkpoints,
foreign keys, `trusted_schema=OFF`, `cell_size_check=ON`, recursive triggers and
deadline-bounded short write transactions. No transaction spans the stores. A paused,
quiescent top-level manifest binds two independently coherent online backups and public
verification keys; private signing keys are excluded.

**Testing**: Locked format/check/Clippy/workspace tests; canonical positive and negative
grant/receipt fixtures; at least 100,000 generated contract mutations; exactly 10,000
repeated end-to-end dispatch/consume requests, 100 end-to-end rounds x 64 threads and 20
end-to-end rounds x 8 processes, all through one adapter consumption boundary;
exact/minus/plus-one authority and capacity boundaries; stale lease/approval/capability/
epoch/deadline cases; signer/key rotation; operation/nonce/digest collisions; bounded
queues and duplicate flood; process and transaction fault injection at every dispatch/
inbox/receipt/readback boundary; lost-acknowledgement recovery with one four-observation/
500 ms maximum readback sequence; post-expiry verification of already-retained receipts
without authority renewal; closed post-`RECEIVED` signed-refusal reasons and
pre-`RECEIVED` no-receipt diagnostics; transport fencing/definite absence; schema v1-to-v2
migration and rollback refusal; corruption/orphan/conflict detection; quiescent backup,
clean paused restore and no-reactivation; retention/redaction; source portability;
isolated removal; supply-chain verification and controlled release benchmark. Test-only
fault hooks remain behind a non-default feature.

**Target Platform**: macOS arm64 is the reference platform and the physical Mac mini M4
is the only target for release performance evidence. The unchanged hosted conformance
matrix is macOS arm64, Linux x86_64 and Windows x64. Hosted jobs prove compilation,
protocol behavior, process-kill and synthetic no-effect durability only, not power loss,
filesystem durability, physical isolation or Tier 1.

**Project Type**: Portable Rust contract/orchestration libraries plus two independent
SQLite authority domains, reviewed Markdown/SQL/JSON contracts, a versioned fixture
corpus, CI workflow, evidence tools and benchmark/validation examples. No CLI, server,
real transport, OS adapter, host effect or legacy pipeline migration.

**Performance Goals**: A v1 grant expires no later than the earliest authority deadline
or 5,000 ms after trusted issue time. On the physical reference M4, after 500 warmups and
at least 10,000 sequential complete dispatch/inbox/receipt cycles, p95 is at most 50 ms
and p99 at most 100 ms. The benchmark records hardware, OS, toolchain, store profile,
queue depth, corpus, repetitions and raw samples. At configured queue capacity, new
dispatch work refuses or backpressures within 50 ms while the reserved control lane
answers PAUSE/status/reconciliation at p99 at or below 100 ms. Hosted values are
diagnostic and cannot satisfy the physical claim.

Automatic readback is independently bounded: one sequence per possible-handoff attempt,
at most four observations after backoffs of 0/25/75/175 ms (offsets 0/25/100/275 ms),
and a hard end at 500 ms from the first observation, always truncated by an earlier
caller or grant deadline.

**Constraints**: Input is derived only by the coordinator from one current PLAN-004
record; `PreparedOperationV1`, direct rows and legacy lease/approval objects are not
authority. Exact signed grant bytes commit with the dispatch transition before delivery.
The 5-second maximum is never renewed. The adapter independently observes the current
supervisor epoch and exposes no execution-token API. An already-retained signed receipt
remains historically verifiable after expiry but cannot renew authority. Signed
`REFUSED_DEFINITE` receipts are limited to the post-`RECEIVED` reasons
`GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` and `ADAPTER_PAUSED`; pre-`RECEIVED`
`DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`, `CAPABILITY_MISMATCH` and
`INBOX_CAPACITY_EXHAUSTED` produce durable diagnostics/quarantine only, no receipt and
no standalone release proof. Exact capacity is accepted; over-by-one denies. No
cross-store atomicity, blind grant replacement, transient-absence proof, real effect,
private-key backup, native path,
floating point, unrestricted payload, raw secret, direct egress, pruning or secure-
erasure claim. Retained v1 grants, receipts, transitions and conflict tombstones are
permanent until a future retention feature proves safe retirement.

**Scale/Scope**: Single-user v1; one coordinator, one destination adapter identity per
grant, maximum 1,024 ordinary pending inbox/dispatch entries plus a separate capacity-32
control lane, one grant and nonce per operation, one consumption receipt, 5-second grant
lifetime, exactly 10,000 repeated end-to-end requests, 100 end-to-end rounds x 64
threads, 20 end-to-end rounds x 8 processes, each driven through the adapter boundary,
100 overload/control trials and 100,000 generated contract cases. The
feature stops before effect execution, verification, compensation, budget settlement,
final success, production supervisor/IPC and R2 Mac integration.

## Constitution Check

*GATE: Passed before Phase 0 research; re-checked after Phase 1 design.*

- **Boundary — PASS**: Agent, caller, transport, payload and legacy runtime are
  untrusted. They cannot construct the coordinator-only dispatch candidate/permit or a
  future sealed adapter effect handoff. The new authority is one signed short grant no broader than
  the current prepared operation. No host share, raw secret, external egress or target
  mutation is introduced. Fake-adapter acceptance is not a production effect claim.
- **Authority — PASS**: `ExecutionGrantV1` and `ExecutionReceiptV1` are canonical,
  versioned, signed, task/workload/operation/destination/epoch bound and deny unknown
  values. PLAN-005 consumes injected current lease/authorization views matching retained
  PLAN-004 digests and generations; it never elevates legacy kernel objects. Signed
  `TaskLease`/`ApprovalDecision` migration remains a separate blocking R1 feature before
  production/R2 claims.
- **Effects — PASS**: The exact grant and `PREPARING -> DISPATCHING` commit together
  under the ordered guards before delivery. Inbox receipt precedes acceptance;
  consumption and signed receipt precede any future sealed effect handoff. A verified receipt
  alone permits `DISPATCHING -> EXECUTING`; possible delivery without proof becomes
  `OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED`. A definite no-consumption receipt closes
  only through the normative reconciliation path to `FAILED` and atomically releases
  the PLAN-004 hold. A consumed receipt discovered after `OUTCOME_UNKNOWN` is retained
  in reconciliation custody and cannot jump back to execution. No host effect exists,
  so verification/compensation/settlement are explicitly deferred rather than falsely
  satisfied.
- **Data — PASS**: Canonical grant/receipt bytes and correlation metadata are restricted
  security data retained in sovereign stores. Logs/events expose redacted bounded
  identifiers only. Private signing keys stay in provisioned signing authorities and
  never enter backups, manifests, fixtures, Graphify or evidence. No network/connector
  data or secret use is introduced.
- **Portability — PASS**: Common contracts contain bounded identifiers, safe integers,
  fixed digests and explicit time/epoch fields only. Store and protocol semantics are
  OS-neutral; platform differences are declared capability refusals. One unchanged
  corpus runs on macOS arm64, Linux x64 and Windows x64.
- **Performance — PASS**: The original held budget and deadlines remain authoritative;
  retry cannot renew either. Grant lifetime, M4 p95/p99, queue capacity, ordinary-lane
  backpressure and control-lane response are bounded and measured. Overload authorizes
  no additional grant or effect.
- **Evidence — PASS**: PLAN-005 requires tamper/replay/stale-epoch, fault-boundary,
  lost-ack, migration/rollback, backup/clean-restore, redaction, removal, supply-chain,
  multi-platform and exact-commit immutable evidence. Hosted/process-kill evidence stays
  labeled synthetic; physical fullfsync/power-loss, production supervisor/provider and
  Tier 1 remain pending.

Post-design re-check: PASS, 7/7, with no constitutional deviation or waiver. The design
keeps the coordinator and adapter stores independent, preserves PLAN-004 authority, and
does not claim universal exactly-once behavior.

## Phase 0: Research Decisions

[research.md](research.md) resolves all design questions:

1. End PLAN-005 after durable adapter consumption and the normative `EXECUTING` marker,
   before any real host effect.
2. Put canonical grant/receipt wire contracts in isolated `helix-dispatch-contracts`
   and portable orchestration in `helix-plan-dispatch`, so adapters do not inherit the
   PLAN-001 plan API.
3. Preserve strict `SqliteCoordinatorStoreV1`; add a reviewed additive v2 overlay and an
   explicit `SqliteCoordinatorStoreV2` upgrade rather than create a second coordinator
   database or rebuild v1 tables.
4. Put the adapter inbox in a separate trust-domain store and never claim a distributed
   transaction.
5. Derive the dispatch candidate only inside the coordinator while retaining PLAN-004's
   global guard order and a new linearizable dispatch permit.
6. Freeze a 5,000 ms maximum grant lifetime and preserve exact PLAN authority/capacity
   semantics.
7. Sign and persist exact grant bytes inside the dispatch transaction with create-only
   grant/operation/nonce uniqueness.
8. Independently verify supervisor epoch and all grant bindings before durable inbox
   acceptance. Destination, protocol, capability or capacity failures before
   `RECEIVED` retain diagnostics/quarantine but never create a receipt or release proof.
9. Persist one-shot consumption and a signed receipt; expose no execution-token API;
   exact timely `CONSUMED` receipt evidence, not transport acknowledgement, advances
   `DISPATCHING -> EXECUTING`. Post-`RECEIVED` `REFUSED_DEFINITE` is closed to exactly
   `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` and `ADAPTER_PAUSED`.
10. Retry only the retained grant. For each possible-handoff attempt, run exactly one
    automatic readback sequence with at most four observations after 0/25/75/175 ms
    backoffs (offsets 0/25/100/275 ms), bounded to 500 ms from the first and truncated
    by earlier caller/grant deadlines. A previously retained receipt stays verifiable
    after expiry without authority renewal. Require fenced/quiesced transport for
    definite absence, use `OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED` after readback
    exhaustion/unavailability without an automatic loop, and close an exact
    no-consumption refusal through normative `FAILED` with one base hold release.
11. Use bounded ordinary and reserved control lanes with deterministic overload
    behavior.
12. Use explicit public-key history, permanent v1 retention and redacted permanent
    transition/conflict evidence.
13. Bind two independently coherent backups in a paused quiescent manifest; clean
    restore rotates epochs, expires grants and quarantines possible acceptance.
14. Use one unchanged contract corpus plus the closed ordered registry of exactly 90
    PLAN-005 boundaries and 180 declared in-process/process-kill cases, with
    physical-only release performance claims across the three hosted OS targets.
15. Build PLAN-005-specific supply-chain and isolated-removal evidence from the merged
    PLAN-004 baseline `6f8dfdd5194792e8592cd10ebaaf8828833effbe`.

No `NEEDS CLARIFICATION` remains.

## Phase 1: Design and Contracts

- [data-model.md](data-model.md) defines signed contracts, coordinator v2 rows, adapter
  inbox rows, lifecycle transitions, cross-store invariants, backup/restore, retention
  and closed outcomes.
- [contracts/durable-dispatch-v1.md](contracts/durable-dispatch-v1.md) freezes ownership,
  ordered guards, grant creation, delivery/readback and closed state transitions.
- [contracts/execution-grant-receipt-v1.md](contracts/execution-grant-receipt-v1.md)
  freezes canonical fields, domains, limits, signatures, version/key handling and
  no-token boundary and future sealed-effect-handoff restriction.
- [contracts/execution-grant-v1.schema.json](contracts/execution-grant-v1.schema.json)
  and [contracts/execution-receipt-v1.schema.json](contracts/execution-receipt-v1.schema.json)
  freeze exhaustive wire member names, nesting, encodings and limits.
- [contracts/coordinator-dispatch-schema-v2.sql](contracts/coordinator-dispatch-schema-v2.sql)
  defines the migrated coordinator schema and cross-record invariants.
- [contracts/adapter-inbox-schema-v1.sql](contracts/adapter-inbox-schema-v1.sql) defines
  the independent create-only inbox, receipt, quarantine and lifecycle tables.
- [contracts/dispatch-backup-manifest-v1.schema.json](contracts/dispatch-backup-manifest-v1.schema.json)
  defines the paused cross-store backup inventory and public-key bindings.
- [contracts/fault-boundaries-v1.json](contracts/fault-boundaries-v1.json) defines the
  closed ordered PLAN-005 boundary IDs, owners, phases and in-process/process-kill
  coverage without changing PLAN-004's registry.
- [quickstart.md](quickstart.md) defines repeatable contract, guard, migration, inbox,
  replay, ambiguity, fault, overload, restore, portability, supply/removal and physical
  benchmark validation.

The repository's Spec Kit distribution does not contain
`.specify/scripts/bash/update-agent-context.sh`, so the prescribed generated agent
context update cannot run. `AGENTS.md` already carries the project Constitution and
Graphify workflow; no feature-local dependency data is inserted manually.

## Project Structure

### Documentation (this feature)

```text
specs/005-durable-dispatch/
|-- spec.md
|-- plan.md
|-- research.md
|-- data-model.md
|-- quickstart.md
|-- contracts/
|   |-- durable-dispatch-v1.md
|   |-- execution-grant-receipt-v1.md
|   |-- execution-grant-v1.schema.json
|   |-- execution-receipt-v1.schema.json
|   |-- coordinator-dispatch-schema-v2.sql
|   |-- adapter-inbox-schema-v1.sql
|   |-- dispatch-backup-manifest-v1.schema.json
|   `-- fault-boundaries-v1.json
|-- checklists/
|   |-- requirements.md
|   `-- durability.md
|-- evidence/
`-- tasks.md                         # created later by speckit-tasks
```

### Source Code (repository root)

```text
kernel/
|-- Cargo.toml                       # add three workspace members
|-- Cargo.lock
|-- helix-dispatch-contracts/
|   |-- Cargo.toml
|   |-- src/lib.rs
|   |-- src/grant.rs
|   |-- src/receipt.rs
|   |-- src/crypto.rs
|   `-- tests/
|       |-- grant_contract.rs
|       |-- receipt_contract.rs
|       |-- redaction.rs
|       `-- property.rs
|-- helix-plan-dispatch/
|   |-- Cargo.toml
|   |-- src/
|   |   |-- lib.rs
|   |   |-- attempt.rs
|   |   |-- authority.rs
|   |   |-- guard.rs
|   |   |-- store.rs
|   |   |-- adapter.rs
|   |   |-- outcome.rs
|   |   |-- coordinator.rs
|   |   `-- test_fault.rs
|   `-- tests/
|       |-- common/mod.rs
|       |-- contract.rs
|       |-- authority.rs
|       |-- bounds.rs
|       |-- guard.rs
|       |-- outcome.rs
|       |-- replay.rs
|       |-- ambiguity.rs
|       |-- reconciliation.rs
|       |-- control.rs
|       |-- conformance.rs
|       |-- portability.rs
|       `-- redaction.rs
|-- helix-coordinator-sqlite/
|   |-- Cargo.toml
|   |-- src/
|   |   |-- schema.rs                # unchanged strict v1 verification
|   |   |-- dispatch_schema.rs       # additive v2 overlay + explicit migration
|   |   |-- dispatch.rs
|   |   |-- dispatch_readback.rs
|   |   |-- dispatch_outbox.rs
|   |   |-- dispatch_quarantine.rs
|   |   |-- maintenance.rs
|   |   |-- manifest.rs
|   |   `-- test_fault.rs
|   |-- tests/
|   |   |-- dispatch.rs
|   |   |-- dispatch_contention.rs
|   |   |-- dispatch_commit.rs
|   |   |-- dispatch_receipt.rs
|   |   |-- dispatch_readback.rs
|   |   |-- dispatch_faults.rs
|   |   |-- dispatch_migration.rs
|   |   |-- dispatch_restore.rs
|   |   |-- dispatch_corruption.rs
|   |   |-- dispatch_queue_control.rs
|   |   |-- dispatch_redaction.rs
|   |   `-- dispatch_end_to_end_contention.rs
|   `-- examples/
|       |-- durable_dispatch_corpus.rs
|       `-- durable_dispatch_benchmark.rs
`-- helix-dispatch-inbox-sqlite/
    |-- Cargo.toml
    |-- src/
    |   |-- lib.rs
    |   |-- config.rs
    |   |-- clock.rs
    |   |-- epoch.rs
    |   |-- schema.rs
    |   |-- inbox.rs
    |   |-- receipt.rs
    |   |-- quarantine.rs
    |   |-- maintenance.rs
    |   |-- manifest.rs
    |   `-- test_fault.rs
    `-- tests/
        |-- contract.rs
        |-- consume_once.rs
        |-- contention.rs
        |-- receipt.rs
        |-- process_crash.rs
        |-- stale_epoch.rs
        |-- queue_control.rs
        |-- backup_restore.rs
        |-- corruption.rs
        |-- retention.rs
        |-- portability.rs
        `-- redaction.rs

contracts/fixtures/durable-dispatch-v1/
|-- README.md
|-- cases.json
`-- expected-outcomes.json

conformance/catalog.yaml
.github/workflows/durable-dispatch.yml
.gitattributes
tools/plan005_supply_chain.py
tools/plan005_removal_drill.py
tools/tests/test_plan005_evidence.py
docs/roadmap/roadmap-data.js          # generated by tools/update_roadmap.py only
```

**Structure Decision**: `helix-dispatch-contracts` owns only canonical dispatch wire
values and signature verification, without exposing the complete plan API to adapters.
`helix-plan-dispatch` owns portable orchestration/authority traits but no storage or
platform I/O. The existing coordinator root must own the atomic
`PREPARING -> DISPATCHING` transaction, so a strict V2 type adds an overlay while the V1
API and tables remain unchanged. The adapter inbox
must remain a separate trust and crash domain, so it receives its own leaf crate and
database. This is the smallest split that proves one-shot protocol behavior without a
false distributed transaction or a real effect. The wire crate owns the separate
`grant_contract` and `receipt_contract` test targets; the unchanged end-to-end corpus
driver belongs to `helix-coordinator-sqlite` at
`kernel/helix-coordinator-sqlite/examples/durable_dispatch_corpus.rs` because it
orchestrates both independent stores.

## Acceptance Traceability

| Evidence gate | Specification coverage | Planned proof |
|---|---|---|
| `PLAN-005-CONTRACT` | FR-003..FR-005, FR-017..FR-019, FR-041..FR-043; SC-003, SC-008 | Exhaustive canonical signed grant/receipt schemas, golden/tamper corpus, version/key rotation, 5-second limit and unchanged three-platform output |
| `PLAN-005-AUTHORITY` | FR-001..FR-011, FR-039..FR-040, FR-049; SC-001, SC-003 | Coordinator-only durable reload, ordered guards/permit, exact PLAN-004 bindings, atomic signed bytes/outbox, exact-capacity cases and fixed concurrency |
| `PLAN-005-INBOX` | FR-012..FR-020, FR-042..FR-045; SC-001, SC-004 | Independent epoch observer, create-only grant/operation/nonce, durable receive/consume/receipt, append-only evidence and proof that no execution-token API exists |
| `PLAN-005-AMBIGUITY` | FR-021..FR-029, FR-043..FR-047; SC-002, SC-004 | Lost acknowledgements, exact redelivery, fenced absence, normative unknown/reconciliation/refusal path, cancellation, audit-pending and exact closed fault inventory |
| `PLAN-005-RESTORE` | FR-030..FR-032, FR-036, FR-044..FR-046; SC-007 | Explicit v1->v2 migration, old-binary refusal, paused quiescent cross-store backup, public-key history, clean restore, orphan/conflict detection and no reactivation |
| `PLAN-005-PORTABILITY` | FR-033, FR-038, FR-046, FR-048; SC-008 | One unchanged protocol/schema/fault corpus on macOS arm64, Linux x64 and Windows x64 with explicit capability refusals and honest claim labels |
| `PLAN-005-PERFORMANCE` | FR-034..FR-035, FR-041; SC-005..SC-006 | Physical-M4 500+10,000 samples, queue 1,024/control 32, duplicate flood and bounded control lane |
| `PLAN-005-SUPPLY` | FR-036..FR-038, FR-045..FR-048; SC-009..SC-010 | Exact-lock SBOM/advisory/license/provenance bundle, retained evidence/nonclaims, immutable artifact attestations and isolated removal from baseline `6f8dfdd` |

## Complexity Tracking

No constitutional violation requires a waiver. Three new crates are authority
boundaries, not new production services: wire contracts remain isolated, portable
orchestration cannot own SQLite or keys, while the
adapter inbox must not share the coordinator database. Extending the existing
coordinator schema is required to keep signed grant bytes and the dispatch transition
atomic; a second coordinator store was rejected because it would create an unprovable
distributed commit.
