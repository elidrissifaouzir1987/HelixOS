# Research: Durable One-Shot Dispatch

**Feature**: `005-durable-dispatch`

**Date**: 2026-07-12
**Authoritative inputs**: `ARCHITECTURE.md` §6–7, `ROADMAP-SPECS.md` R1,
`constitution.md`, PLAN-001 through PLAN-004 specifications/contracts and the current
Rust workspace at merge baseline `6f8dfdd5194792e8592cd10ebaaf8828833effbe`.

## Decision 1 - Stop after consumed dispatch authority, before a host effect

**Decision**: PLAN-005 implements `PREPARING -> DISPATCHING`, one-shot adapter
consumption and exact receipt verification. An exact `CONSUMED` receipt advances the
effective coordinator lifecycle from current `DISPATCHING` to normative `EXECUTING`,
but this state means only that adapter authority is durably consumed. A receipt recovered
after `OUTCOME_UNKNOWN` enters `RECONCILIATION_REQUIRED` custody and cannot jump back to
execution. PLAN-005 exposes no execution-token API and performs no filesystem, process,
secret, network or other host mutation.

**Rationale**: `ARCHITECTURE.md` orders durable dispatch, inbox consumption and receipt
before effect handling. Naming the state `EXECUTING` preserves that normative lifecycle;
stating its no-effect meaning prevents synthetic acceptance from being reported as an
effect. A later feature must separately specify a sealed adapter-internal effect handoff,
verification, compensation and settlement.

**Alternatives considered**:

- Stop forever in `DISPATCHING`: rejected because a verified consumed receipt has a
  normative state transition and leaving it unnamed creates ambiguous recovery.
- Add `GRANT_CONSUMED` or `READY_FOR_EFFECT`: rejected because those states do not exist
  in the architecture and would silently fork the lifecycle.
- Expose an execution token: rejected because it broadens this no-effect slice into
  transferable effect authority.

## Decision 2 - Isolate wire contracts and portable orchestration

**Decision**: Add three leaf crates:

1. `helix-dispatch-contracts` for canonical signed grant/receipt wire values and crypto;
2. `helix-plan-dispatch` for synchronous portable orchestration, authority/store/
   transport/inbox traits and closed outcomes;
3. `helix-dispatch-inbox-sqlite` for the independent no-effect adapter inbox.

Extend `helix-coordinator-sqlite` with a separate strict `SqliteCoordinatorStoreV2`.

The wire crate also depends directly on the already workspace-locked
`unicode-normalization 0.1.25` so resource components enforce the contract's full
Unicode NFC rule instead of approximating it with an incomplete local table.

**Rationale**: Adapters need grant/receipt verification but must not gain the entire
PLAN-001 plan API or depend on preparation/coordinator internals. Portable orchestration
must not own SQLite, keys, OS primitives or transport. The adapter inbox is a separate
trust/crash domain from the coordinator. This split also makes isolated removal and
dependency closure review exact.

**Alternatives considered**:

- Add dispatch values to `helix-contracts`: compatible, but rejected because every
  adapter dependency would expose the broader plan API and blur PLAN-001 ownership.
- Put orchestration in the coordinator crate: rejected because it would make protocol
  behavior storage-specific.
- Combine coordinator and inbox storage: rejected because it erases the independent
  adapter boundary and creates a false same-store guarantee.

## Decision 3 - Reload durable state from an untrusted lookup request

**Decision**: Dispatch input is a bounded untrusted request containing operation ID plus
expected plan, preparation-attempt and preparation-transition identities. Coordinator
V2 reloads the complete PLAN-004 durable record and verifies schema/root state,
operation invariants, comparison/replay evidence, held reservation, published recovery,
prepared event, current authority generations, deadlines and epochs. Neither
`PreparedOperationV1`, a preparation receipt, a caller projection nor a legacy kernel
object is accepted as authority.

**Rationale**: PLAN-004 deliberately makes its marker opaque, non-cloneable and
non-serializable. It cannot be a post-restart or concurrent idempotent input. Durable
reload also prevents a stale in-memory marker from bypassing current store state.

**Alternatives considered**:

- Consume `PreparedOperationV1`: rejected because it cannot safely cross restart or
  concurrency boundaries and was explicitly not dispatch authority.
- Accept direct rows or a serialized positive projection: rejected because callers
  could replay or synthesize authority.
- Reuse `helixos-kernel` lease/approval objects: rejected as legacy, in-memory and not
  cryptographically bound to the R1 durable context.

## Decision 4 - Preserve PLAN-004 V1 and add an explicit additive V2 overlay

**Decision**: Keep `SqliteCoordinatorStoreV1`, its DDL, exact-schema verifier and
`PREPARING`/`FAILED` tables unchanged. Add a reviewed schema-v2 overlay containing
dispatch metadata, comparisons, grants, records, transitions, outbox, delivery attempts,
receipts, reconciliations, events and migration receipts. Effective PLAN-005 lifecycle
comes from this overlay. The authoritative PLAN-004 base row remains `PREPARING` with
its reservation held through every live, executing, unknown and reconciliation state.
Only final exact no-consumption reconciliation may append the existing base
`PREPARING -> FAILED`, release the exact hold and append the overlay `FAILED` state in
one V2 transaction; the V1 schema and prior history remain unchanged.

Upgrade is an explicit paused maintenance operation: verify exact V1 and a fresh backup,
acquire quiescence, begin one immediate transaction, add all overlay objects, insert a
migration receipt binding source/target schema digests and backup digest, set
`user_version=2` last, then commit. Ordinary open never migrates. V1 rejects V2; V2
rejects partial/unknown schemas. New roots construct V1 privately, apply V2, then publish
only V2. There is no in-place downgrade after any dispatch history.

**Rationale**: PLAN-004's cyclic tables, schema digest and frozen invariants are already
immutable evidence. Rebuilding them would rewrite authoritative history and invalidate
the no-dispatch contract. An additive overlay lets one coordinator transaction still
bind the existing preparation row to the signed grant.

**Alternatives considered**:

- Modify V1 tables/checks in place: rejected because V1 explicitly forbids dispatch
  states and exact-schema verification would become ambiguous.
- Separate coordinator dispatch database: rejected because signed bytes and
  `PREPARING -> DISPATCHING` could not commit atomically.
- Automatic open-time migration or rerun after uncertain commit: rejected because
  authority migration must be explicit and exact-readback classified.

## Decision 5 - Freeze the canonical grant contract and lifetime

**Decision**: `ExecutionGrantV1` uses strict RFC 8785 protected bytes, SHA-256 digest,
Ed25519 and signature domain `HELIXOS\0EXECUTION-GRANT\0V1\0`. It uses a dedicated
coordinator dispatch-signing key purpose. It binds grant and dispatch-attempt IDs,
one-shot nonce, operation/current-state/preparation generations, plan/task/workload,
typed effect descriptor, target/precondition/content metadata, lease/authorization/
policy/catalog/capability generations and digests, reservation/recovery bindings,
destination adapter/protocol, boot/instance/supervisor epochs, trusted UTC and monotonic
samples, and the exclusive deadline.

The effect descriptor carries bounded digests, lengths, media type and portable resource
reference, not replacement bytes, secrets or native paths. The deadline is the minimum
of all authority/caller deadlines and trusted issue time plus 5,000 ms. Equality with the
exclusive deadline denies; exact reserved capacity is accepted and over-by-one denies.

**Rationale**: Exact bindings prevent a grant from becoming a bearer version of broader
plan authority. The five-second ceiling is long enough for bounded local delivery and
readback while remaining short compared with task authority. It is independent of
PLAN-004's 250 ms commit-permit ceiling.

**Alternatives considered**:

- Reuse the signed plan as a grant: rejected because plans are not destination-bound,
  short one-shot adapter authority.
- Sign only a digest and reconstruct bytes later: rejected because exact retry and
  cross-platform evidence require the original canonical wire.
- Renew lifetime on retry: rejected because retry must never expand authority.

## Decision 6 - Use a distinct closed receipt contract and signer purpose

**Decision**: `ExecutionReceiptV1` uses canonical protected bytes, SHA-256, Ed25519,
domain `HELIXOS\0EXECUTION-RECEIPT\0V1\0` and an independently trusted adapter
receipt-signing key purpose. It binds receipt/grant/digest/operation/destination,
inbox/consumption generations, observed supervisor epoch, boot-bound time samples,
closed decision/refusal code and bounded opaque trace identity.

Receipt decisions are only `CONSUMED` and `REFUSED_DEFINITE`. `CONSUMED` is the only
positive authority evidence. `REFUSED_DEFINITE` requires a permanent no-consumption
tombstone plus guarded proof that no delivery remains in flight. Its signed
post-`RECEIVED` code is exactly `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` or
`ADAPTER_PAUSED`. `DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`,
`CAPABILITY_MISMATCH` and `INBOX_CAPACITY_EXHAUSTED` reject before `RECEIVED`; they
produce durable diagnostic/quarantine evidence, never a signed receipt or sufficient
no-consumption/reservation-release proof. The coordinator retains
that signed receipt and closes only through normative
`DISPATCHING -> OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED -> FAILED`, atomically
closing the PLAN-004 base operation and releasing its held reservation once. Malformed,
forged, unsupported or conflicting inputs receive local redacted diagnostic/quarantine
evidence, not an authoritative positive receipt. Grant and receipt trust profiles cannot
verify each other's signature domain. Historical public keys and revocation/trust
metadata are retained; private signing keys remain outside backups and evidence.

**Rationale**: Separate signer purposes prevent a compromised coordinator key from
forging adapter acceptance and vice versa. Closed decisions keep transport errors from
becoming execution evidence.

**Alternatives considered**:

- One shared plan/grant/receipt signer/domain: rejected for cross-protocol substitution
  and excessive blast radius.
- Unsigned adapter acknowledgement: rejected because it cannot support durable
  cross-store readback or restore.
- Sign diagnostics for malformed bytes as receipts: rejected because untrusted input
  must not create evidence that resembles accepted authority.

## Decision 7 - Retain PLAN-004 guard order through the dispatch transaction

**Decision**: Coordinator V2 uses the same globally ordered guard classes as PLAN-004
and a fresh non-cloneable linearizable `DispatchCommitPermitV1`. It reloads preliminary
state, builds/signs candidate bytes, acquires guards in fixed order, repeats the full
authoritative capture/comparison, then holds the permit across the complete SQLite V2
compare-and-transition. PAUSE/HALT revokes admission; owner loss or deadline expiry
activates PAUSE and produces bounded unknown custody.

The transaction atomically commits final comparison evidence, exact signed grant,
current dispatch record, `PREPARING -> DISPATCHING` overlay transition, deliverable
outbox member, redacted event and all generations. Transport is invoked only after the
writer transaction closes.

**Rationale**: A merely recent pre-check leaves a TOCTOU window. Reusing the guard order
prevents a new dispatch/preparation deadlock cycle. Committing outbox before transport
prevents unpersisted authority while avoiding a writer lock over untrusted delivery.

**Alternatives considered**:

- Revalidate just before commit without guards: rejected because mutable authority can
  change between comparison and transition.
- Deliver inside the transaction: rejected for writer starvation, deadlock and
  unclassifiable transport ambiguity.
- Create a second grant after uncertain commit: rejected by one-shot authority.

## Decision 8 - Use an independent create-only adapter inbox

**Decision**: `helix-dispatch-inbox-sqlite` owns a distinct root identity/application ID
and tables for store metadata, inbox grants, transitions, receipts, conflicts,
quarantines and events. Grant ID, operation ID and nonce are independently create-only
unique, in addition to the full-wire digest.

Acceptance uses two bounded transactions. First, canonical decode/signature/trust,
destination/protocol/capability and an independently observed supervisor epoch are
validated before `ABSENT -> RECEIVED` commits. Second, the entry is reloaded, deadline
and epoch are revalidated, then `RECEIVED -> CONSUMED` or `RECEIVED -> REFUSED` and the
signed receipt/event commit together. Exact duplicate returns retained state/receipt;
any conflicting key/binding adds permanent conflict evidence and authorizes nothing.

**Rationale**: Separate transactions make first durable receipt and final consumption
observable fault boundaries without pretending receipt equals effect. Create-only
operation/nonce indexes prevent a malicious second grant ID or key rotation from
reopening the namespace.

**Alternatives considered**:

- SELECT then insert without unique constraints: rejected as race-prone.
- Trust supervisor epoch carried only by the grant: rejected because fencing must come
  from an independent supervisor-owned source.
- Store inbox in coordinator DB: rejected because adapter compromise/crash would share
  the authority domain.

## Decision 9 - Treat delivery absence as a fenced protocol result

**Decision**: Every delivery uses the exact retained outbox bytes and dispatch attempt.
The transport exposes a linearizable handoff guard and attempt evidence. Confirmed
no-send is possible only before handoff. After possible handoff, coordinator readback
may classify definite absence only after delivery is quiesced/fenced, the exact adapter
root/epoch is healthy and authoritative, the grant deadline has closed late acceptance,
and the readback generation proves no later delivery can arrive. A simple missing inbox
row is never enough.

Exact duplicates may be redelivered only while original authority remains valid. A
retained signed receipt is recovered idempotently and remains authoritative evidence
after deadline expiry without renewing, extending, replacing or resigning its grant.
Each possible-handoff attempt permits one automatic readback sequence only: at most four
observations within 500 ms total, using backoffs `0/25/75/175 ms` (offsets
`0/25/100/275 ms`), with an earlier cut-off at the original exclusive grant deadline.
If neither exact consumption nor fenced definite absence is proved within that bound,
including when the sequence is exhausted, coordinator records
`DISPATCHING -> OUTCOME_UNKNOWN`, then explicit
`OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED` custody; reconciliation never mints a
replacement grant, and exhaustion is never evidence of absence. A late `CONSUMED`
receipt remains in reconciliation custody for a
future effect-aware feature. A definite no-consumption proof alone permits the normative
final `FAILED` transition.

**Rationale**: Transport acknowledgement and adapter durability are different failure
domains. This rule prevents a lost handoff from being misreported as safe failure and
replayed with new authority.

**Alternatives considered**:

- Empty inbox means absent: rejected while a message/process/queue can still arrive.
- Retry with a new grant/nonce: rejected because the old one may already be accepted.
- Leave the operation indefinitely `DISPATCHING`: rejected because bounded unknown
  classification is required for incident response and restore.

## Decision 10 - Freeze closed coordinator outcomes and budget custody

**Decision**: Public orchestration outcomes are closed typed variants for dispatched,
consumed, definitely refused, conflict, denied-before-transition, failed-before-
transition, unknown and reconciliation-required. Only an exact timely receipt drives
`DISPATCHING -> EXECUTING`. Guarded permanent no-consumption evidence follows
`DISPATCHING -> OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED -> FAILED`; its one V2
closure transaction also appends base `PREPARING -> FAILED`, releases the exact held
reservation once and retains both event chains. PLAN-004 reservations and recovery
material remain held/published through `DISPATCHING`, `EXECUTING`, `OUTCOME_UNKNOWN` and
`RECONCILIATION_REQUIRED`. Effect-aware settlement/retirement remain later features.

**Rationale**: Releasing budget/recovery after possible consumption would allow a second
operation to spend reserved capacity while the first may execute. Closed outcomes avoid
string/error-code ambiguity.

**Alternatives considered**:

- Release on transport error or inbox absence: rejected without no-in-flight proof.
- Reuse PLAN-004's known pre-dispatch failure after a dispatch overlay exists: rejected
  because its no-dispatch premise is false.
- Mark consumed receipt as success: rejected because no effect was performed or verified.

## Decision 11 - Bound ordinary and control lanes

**Decision**: V1 supports at most 1,024 ordinary pending dispatch/inbox entries and a
separate capacity-32 control lane for PAUSE, status and reconciliation. Saturated
ordinary work refuses or backpressures within 50 ms. On the declared reference profile,
control requests remain at p99 <= 100 ms under a 10,000-request duplicate flood. Queue
counts and duplicate/conflict/refusal/unknown metrics are bounded and payload-free. The
gate executes 100 controlled saturation trials.

**Rationale**: Availability of emergency controls under overload is constitutional.
Exact capacities make SC-006 reproducible and prevent an implementation from claiming
an unbounded in-memory queue.

**Alternatives considered**:

- One shared unbounded queue: rejected because duplicate floods could starve PAUSE.
- Drop duplicates silently: rejected because retained receipt/conflict evidence is
  required.
- Platform-specific queue semantics: rejected; capacity and outcomes are portable.

## Decision 12 - Retain authoritative evidence and redact public surfaces

**Decision**: Canonical grant/receipt wires contain only required bounded internal
identities/digests and no raw secrets/native paths/unbounded content. Public logs,
`Debug`, metrics and outward audit projections redact all non-public values before
serialization. V1 grant bytes, dispatch/inbox transitions, receipts, conflicts,
quarantines and reconciliations are authoritative permanent evidence with no automatic
pruning, row/key reuse or secure-erasure claim. Production roots require an approved
encrypted-at-rest profile.

**Rationale**: Historical one-shot and restore verification need retained bytes and
public-key history; deleting them could reopen authority. Public observability does not
need the sensitive binding values.

**Alternatives considered**:

- Treat inbox/receipt as derived cache: rejected because they determine whether
  authority was consumed.
- Log complete canonical contracts: rejected as sensitive and unnecessary.
- Claim physical deletion from logical row removal: rejected without storage-specific
  secure-erasure evidence.

## Decision 13 - Bind separate backups under PAUSE without claiming atomicity

**Decision**: PLAN-005 adds coordinator-v2 and adapter-inbox manifests plus a signed
`dispatch-backup-index/1` that binds both database/manifest/root/generation digests,
historical public-key profiles, supervisor epoch and a complete cross-store grant/
receipt inventory. Under a live PAUSE/quiescence guard, create independently coherent
online backups sequentially, publish manifests, then publish the signed index last.

Clean restore verifies the complete package into empty independent roots with new root,
instance and supervisor identities, persists `RESTORE_PENDING`, starts PAUSED, expires
all old grants, quarantines possible accepted/consumed state and performs zero automatic
redelivery. It is coordinator/adapter subsystem evidence only; sovereign activation and
full-machine restore remain deferred.

**Rationale**: PAUSE can make sequential cuts coherent without pretending SQLite
provides a cross-database transaction. New epochs prevent backup copies from reviving
bearer authority.

**Alternatives considered**:

- Extend the PLAN-004 manifest in place: rejected because its frozen v1 inventory omits
  dispatch/inbox semantics.
- Copy two live databases best-effort: rejected because generations can tear.
- Restore old epochs to simplify readback: rejected because old grants could execute.

## Decision 14 - Use a separate exhaustive fault corpus and physical-only performance

**Decision**: PLAN-005 owns the closed ordered registry in
`contracts/fault-boundaries-v1.json`, with stable IDs, owner, phase, ordinal and explicit
in-process/process-kill applicability spanning coordinator lookup/signing/guards/commit,
delivery handoff, adapter receive/consume/receipt, coordinator receipt/reconciliation,
migration, backup and restore. It includes faults after begin, every durable member,
immediately before/after commit and after possible handoff. The file's declared
cardinality is exactly 90 boundaries / 180 declared cases, and its digest is the only
accepted inventory; PLAN-004's frozen
123-boundary/167-case registry remains byte-unchanged.

Contract/fault outcomes run unchanged on hosted macOS arm64, Linux x86_64 and Windows
x64. At least 100,000 generated contract cases, 10,000 repeated requests, 100 x
64-thread contention rounds and 20 x 8-process rounds run before release. The physical
M4 benchmark measures from entry into the retained
final guard through exact consumed-receipt verification, with 500 warmups and 10,000
samples; p95 <= 50 ms and p99 <= 100 ms. Hosted timing is diagnostic only.

**Rationale**: A closed registry proves coverage instead of allowing implementation-
defined omissions. Process kill does not prove power-loss durability, and hosted VMs do
not prove M4 performance.

**Alternatives considered**:

- Extend PLAN-004's registry: rejected because its immutable evidence would change.
- Test only transaction boundaries: rejected because transport/inbox/receipt ambiguity
  is the primary risk.
- Promote hosted timing: rejected because hardware/runtime claims require the named
  physical profile.

## Decision 15 - Produce PLAN-005-specific supply, removal and roadmap evidence

**Decision**: Add a dedicated CI workflow and PLAN-005 evidence tools. The supply tool
verifies the union dependency closure and full adjacency for the three new crates plus
coordinator V2, exact lock/native bundled SQLite sources and features, licenses, pinned
RustSec/SPDX inputs, semantic tamper cases and secret/path scans. Immutable release
artifacts are resolved only from one successful exact-commit workflow run and attested
for Linux, macOS, Windows and the release bundle.

The isolated removal drill uses merged PLAN-004 commit
`6f8dfdd5194792e8592cd10ebaaf8828833effbe` as the pre-feature baseline, removes only
PLAN-005 surfaces, restores the pre-feature lock/schema integration and byte-verifies all
protected PLAN-001 through PLAN-004 and legacy files/tests. `conformance/catalog.yaml`
adds `PLAN-005` with aggregate `pending-evidence`; `tools/update_roadmap.py` generates the
roadmap after `tasks.md` exists.

**Rationale**: PLAN-004 tools and evidence are immutable and must not be repurposed.
Feature-specific removal proves the new authority boundary is not a hidden migration.

**Alternatives considered**:

- Modify PLAN-004 evidence tools: rejected because it would invalidate exact-commit
  proof and removal baseline.
- Hand-edit `docs/roadmap/roadmap-data.js`: rejected because it is generated state.
- Mark PLAN-005 accepted after hosted CI: rejected because physical M4, power-loss,
  production supervisor/provider and full-machine gates remain external.

## Decision 16 - Audit one exact retained checkpoint and require PAUSE at production boundaries

**Decision**: The default-compiled adapter audit compares separately retained strict
coordinator and adapter checkpoints with observed roots only while one caller-owned PAUSE
binding remains live. The production `SqliteCoordinatorStoreV2` caller captures that
binding before its leases, delegates the same proof to the adapter cut, and rechecks it
after the bound files and complete schemas are validated again. The audit classifies the
closed FR-032 relationship and generation corruption families before interpreting
checkpoint equality.

The feature-gated coordinator real-store matrix separately proves the same exact-
checkpoint classification over closed strict roots under dual `BEGIN IMMEDIATE` cuts and
file-identity rechecks. It does not expose or claim a production coordinator PAUSE
surface. Any later production wiring of the coordinator classifier must require the same
caller-owned PAUSE custody; the matrix alone cannot substitute for that integration.

An observed pair that is fully strict but differs from the retained checkpoint returns a
payload-free `CHECKPOINT_MISMATCH` and writes neither a source fence nor external custody.
An exact clean checkpoint returns clean with the same zero-mutation rule. A classified
corruption commits one permanent redacted fence in the observed source before attempting
the identical record in a distinct custody root; ordinary subsystem open, handoff,
receive and consume paths then remain refused after reopen. A coherent old or forked root
is detectable only relative to the separately retained exact checkpoint; this is not a
full-machine or sovereign activation claim.

**Rationale**: Coordinator and adapter histories contain legitimate mutable projections.
A byte-identical moving-prefix rule can therefore misclassify valid progress, while a
positional prefix can accept a different keyed history. Exact checkpoint binding plus
writer and file-identity fencing removes the local race; live PAUSE is additionally
mandatory at every production boundary so normal progress is neither misclassified nor
allowed to race the cut.

**Alternatives considered**:

- Accept any keyed history prefix as clean: rejected because valid in-place progression
  changes retained row bytes and malformed extra rows can masquerade as an append.
- Quarantine every strict but newer root: rejected because normal progress is not
  corruption and must not create permanent evidence.
- Compare snapshots without PAUSE custody and file-identity rechecks: rejected because a
  writer or path substitution could change the state between projection and fencing.
- Treat a different strict checkpoint as clean: rejected because the comparison would no
  longer prove the retained checkpoint requested by the caller.

## Research Closure

All technical and scope questions identified by the specification and independent
review are resolved. No `NEEDS CLARIFICATION` marker remains. These decisions do not
authorize production dispatch, a real effect, use of legacy authority, private-key
backup, full-machine activation or any Tier 1 claim.
