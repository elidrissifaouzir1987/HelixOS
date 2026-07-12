# Research: Durable Preparation Before Dispatch

This research resolves the Phase 0 decisions for feature 004. The canonical inputs are
`constitution.md`, `ARCHITECTURE.md`, `ROADMAP-SPECS.md`, features 001 through 003,
the Graphify boundary analysis, and `specs/004-durable-preparation/spec.md`. No
`NEEDS CLARIFICATION` remains.

## Decision 1 - Keep PLAN-004 at the preparation boundary

**Decision**: Consume one `EligiblePlanV1`, perform a complete preliminary comparison,
verify its exact replay row, and run the read-only operation/budget preflight before
preparing recovery evidence. Then perform one guarded final comparison that repeats
replay/preflight verification, reserve the signed v1 budget vector, and atomically
publish the canonical eight-member positive coordinator set. End before
`DISPATCHING`, grant creation, adapter input, target resolution or host effects.

The trust progression remains:

```text
PLAN-001: wire plan -> AuthenticPlanEnvelopeV1
PLAN-002: authentic plan + current facts + abstract replay claim -> EligiblePlanV1
PLAN-003: abstract replay claim -> durable permanent replay row
PLAN-004: eligible plan + fresh guards + budget + recovery -> durable PREPARING
```

**Rationale**: Preparation is the last boundary before future dispatch authority. It
must prove that point-in-time eligibility is still current without mixing in the later
execution protocol. The Graphify analysis confirms that signed budget and recovery
claims exist, while durable reservation, recovery evidence, operation state and a
transactional event are still absent.

**Alternatives considered**:

- Create `DISPATCHING` or an `ExecutionGrant`: rejected because that adds effect
  authority and a new crash boundary.
- Fold preparation into PLAN-003: rejected because replay admission is already a
  frozen, permanent and independently testable store boundary.
- Migrate the legacy in-memory/JSONL pipeline: rejected because it is outside this
  feature and cannot provide transactional preparation evidence.

## Decision 2 - Split portable orchestration from coordinator storage

**Decision**: Add two Rust libraries:

- `kernel/helix-plan-preparation`: portable non-wire contracts, comparison ordering,
  external guard/provider traits, closed outcomes and the opaque prepared marker;
- `kernel/helix-coordinator-sqlite`: the first SQLite-backed coordinator database slice,
  limited in v1 to operation preparation, budget reservation, quarantine evidence,
  event outbox, maintenance, backup and restore.

`helix-plan-preparation` depends on `helix-contracts` and
`helix-plan-eligibility`. `helix-coordinator-sqlite` depends on the portable crate and
the same exact SQLite/storage dependencies already pinned by PLAN-003. The portable
crate has no native path, SQLite, async runtime, network, ambient clock or legacy
`helixos-kernel` dependency.

The coordinator crate does not attach or mutate the replay database. A real integration
wires a replay verifier through a portable trait; `helix-replay-sqlite` is needed only
as that implementation and in integration tests, not as a production dependency of the
coordinator store.

**Rationale**: The authority and provider contracts must remain replaceable and
OS-neutral, while SQLite paths, connections and maintenance remain inside a host storage
adapter. The split also lets the first-failure order and non-authority type properties be
tested without a database.

**Alternatives considered**:

- Put every type in a SQLite crate: rejected because it couples future coordinator
  transitions and recovery providers to one storage implementation.
- Add rows to `helix-replay-sqlite`: rejected because replay rows are permanent minimal
  evidence and cannot make the earlier claim atomic with later preparation.
- Extend legacy `helixos-kernel`: rejected because its JSONL/in-memory path is not the
  authoritative R1 coordinator design.

## Decision 3 - Add non-wire plan preparation projections only

**Decision**: Add a borrowed, read-only `PlanPreparationClaimsV1<'plan>` projection to
`helix-contracts`. It exposes the authenticated target, precondition, replacement
digest/length/media type, recovery class/atomicity/preimage digest/reserved bytes,
verification predicate and existing budget projection. It is `Copy` only as a borrowed
view, has redacted `Debug`, and implements neither Serde direction nor a wire decoder.

Add a borrowed canonical serialization method on `AuthenticPlanEnvelopeV1` or an
equivalent deliberate custody method so the trusted coordinator can persist the exact
already-authenticated signed envelope without changing its bytes. `EligiblePlanV1`
continues to be consumed by value and remains non-`Clone` and non-Serde.

**Rationale**: The current signed fields are private, and parsing canonical JSON inside
the coordinator would create a second contract implementation. A non-wire projection
reuses the authenticated model while preserving PLAN-001 identity, signatures and
fixtures.

**Alternatives considered**:

- Add fields to plan-v1: rejected because it changes canonical bytes and signatures.
- Deserialize the signed envelope again in the coordinator: rejected because it
  duplicates validation and risks accepting a different interpretation.
- Expose mutable or owned plan internals: rejected because callers need observation,
  not authority to rewrite the authenticated plan.

## Decision 4 - Use two comparisons and one global guard order

**Decision**: Preparation uses these phases:

1. Consume `EligiblePlanV1`, generate a fresh opaque preparation-attempt ID and perform
   a complete preliminary comparison without coordinator mutation.
2. Verify the exact permanent replay row through the eligibility-built read-only view.
   Any replay denial returns before store preflight or recovery work; final comparison
   repeats the check under guards.
3. Run a healthy read-only coordinator preflight in normative order: operation/attempt
   identity, then exact budget scope/binding/arithmetic/current capacity. It returns no
   reservation and final transaction checks still repeat; any failure occurs before a
   recovery-provider call.
4. Prepare and publish recovery material. Long material transfer happens before
   mutable authority guards are held.
5. Acquire the following deadline-bounded guards in one global order:

   | Order | Domain |
   |---:|---|
   | 1 | recovery publication versus cleanup |
   | 2 | clock health and plan deadline, when externally owned |
   | 3 | supervisor admission, boot, instance and fencing epochs |
   | 4 | signer trust |
   | 5 | workload identity |
   | 6 | task lease |
   | 7 | authorization |
   | 8 | policy |
   | 9 | catalogue |
   | 10 | capabilities |
   | 11 | coordinator SQLite `BEGIN IMMEDIATE` writer slot |

6. After acquiring the external guards, capture a new complete context, compare every
   PLAN-002 field, verify the exact replay row, repeat read-only operation/budget
   preflight, then verify recovery publication and sample UTC/boot-monotonic time. The
   writer transaction repeats operation/budget checks after serialization.
7. Inside the SQLite transaction publish the canonical eight-member set: metadata
   generations, `PREPARING`, its permanent transition, comparison/replay evidence,
   exact scope delta, held reservation, recovery/irreversibility evidence and event.
   Then the store calls a borrowed `FinalCommitGateV1`; it atomically revalidates all
   guards and obtains a supervisor-owned commit permit held across the actual SQLite
   commit.
8. Resolve acknowledged commit or confirmed rollback immediately. Only an explicitly
   uncertain store result remains `COMMIT_IN_FLIGHT` for one fresh readback. The permit
   deadline is the earlier caller deadline or exactly 250 ms after entry; exact proof or
   the independent deadman resolves it. Recheck caller deadline/guards before any marker,
   then release guards in reverse order.

Coordinator-resident generations are compared transactionally at their logical place
and need no external handle. Guard handles are opaque ephemeral custody, separate from
portable snapshots, and are never serialized or persisted.

PAUSE/HALT persists through the independent control lane. The supervisor gate
linearizably chooses `REVOKED` or `COMMIT_PERMITTED`: revocation first forces rollback;
permit first orders activation after the tightly bounded permit resolves. The permit
does not create an operation, so SQLite commit remains the sole `PREPARING`
linearization point. Ambiguous permit resolution activates PAUSE and returns no marker.
An independent supervisor deadman owns the permit deadline/owner token: process loss,
missing commit classification or equality with the earlier caller/250 ms deadline
resolves it ambiguous, activates PAUSE, blocks new permits and forces exact readback
without relying on `Drop`. Confirmed rollback never enters uncertain readback. No copied
last-token check or retroactive cancellation is claimed.

**Rationale**: The order closes the preparation TOCTOU window, avoids a cleanup/commit
deadlock by acquiring the recovery guard before SQLite, keeps long recovery I/O out of
authority locks and gives control revocation a deterministic ordering.

**Alternatives considered**:

- Check providers and then write without guards: rejected as a check-then-write race.
- Hold all guards during recovery transfer: rejected because it can starve PAUSE and
  consume the caller deadline.
- Acquire SQLite before recovery or external guards: rejected because it creates a
  long writer hold and reverses maintenance lock order.
- Use a process mutex: rejected because it does not serialize other processes or
  provider state.

## Decision 5 - Verify the exact replay row without reclaiming

**Decision**: Add a portable, read-only `ReplayClaimVerifierV1` contract beside the
existing replay receipt types and implement it in `helix-replay-sqlite` without changing
`claim_once`:

```text
verify_exact_claim(eligible.replay_verification_view(), deadline)
  -> Exact | Missing | Conflict | Unavailable | Unhealthy
```

The opaque borrowed view is constructed only by `EligiblePlanV1`; no public
`ReplayBindingV1` constructor is added. Verification compares the permanent row's nonce
namespace, operation, binding digest, claim ID and claimant generation against the exact
eligible plan and carried receipt. It does
not mutate, reissue a receipt, release a claim or require equality with the store's
latest global claimant generation. Unknown/corrupt state is unhealthy and closes
preparation.

**Rationale**: PLAN-003 already stores the required row but exposes exact lookup only to
its internal commit-readback path. Reusing `claim_once` would always deny a consumed
plan and would confuse verification with a new admission attempt.

**Alternatives considered**:

- Call `claim_once` again: rejected because replay claims are one-shot and permanent.
- Compare only the in-memory receipt: rejected because FR-009 requires the durable row
  to remain coherent.
- Compare the latest claimant generation: rejected because unrelated valid claims may
  advance it.

## Decision 6 - Use explicit clock and deadline semantics

**Decision**: Inject trusted UTC and suspend-aware boot-monotonic providers. No ambient
`SystemTime`, process-start clock or wall-clock timeout is read inside common types.
Every wait uses the caller's absolute monotonic deadline and a bounded configured wait.
The commit permit is additionally capped at exactly 250 ms from permit entry and can
only be shortened by the caller deadline.

Both comparisons and the pre-commit gate require:

```text
now_utc_ms < effective_expires_at_utc_ms
now_monotonic_ms < effective_deadline_monotonic_ms
capability age remains strictly within its bound
```

Equality denies. A commit proven after the deadline remains durable but returns no
positive marker. A possible commit whose timely readback cannot be proven is ambiguous.
The synchronous API does not claim hard cancellation of a VFS flush already in flight,
but it creates no detached retry or later mutation after returning.

**Rationale**: This preserves PLAN-002's exclusive bounds and PLAN-003's honest deadline
model while separating an acknowledged durable row from permission to proceed.

**Alternatives considered**:

- Use relative timeouts: rejected because provider waits would use inconsistent clock
  samples.
- Return a positive result solely because commit succeeded: rejected when authority
  expired before acknowledgement.
- Spawn cancellable background writes: rejected because detached mutation violates the
  closed return contract.

## Decision 7 - Provision budget scopes explicitly and reserve inside the operation transaction

**Decision**: The coordinator database is the authoritative v1 budget store. Before
preparation, a trusted non-agent, create-only provisioning path installs a
`BudgetScopeV1` derived from authenticated lease authority. It binds task-lease digest,
allowance-binding digest, generation, currency, price-table identity and total cost,
action, egress and recovery-byte limits. Preparation cannot create, widen or update a
scope; missing or mismatched scope denies.

Version 1 reserves exactly the authority present today:

- maximum cost in integer micro-units;
- action count;
- egress bytes;
- recovery bytes.

File count, concurrency and duration are explicitly unclaimed because plan-v1 does not
sign them and this feature cannot dispatch. A later signed contract must add them before
a relevant effect.

Inside the same `BEGIN IMMEDIATE` transaction as `PREPARING`, checked arithmetic accepts
only `requested <= total - held` for every dimension, updates shared held totals and
inserts one immutable reservation. The reservation ID and operation ID are each unique
and permanently bind the plan, lease, scope generation, price identity, vector and
preparation-attempt ID. No identifier is recycled.

`PREPARING -> FAILED` atomically changes `HELD -> RELEASED`, subtracts the exact stored
vector once and inserts a failure event. An ambiguous attempt never releases
automatically.

Before recovery publication, a read-only store preflight classifies operation identity
and proves the current scope binding/arithmetic/capacity in that order. It is deliberately
non-authoritative and final transaction checks repeat, but it preserves FR-014 ordering
and avoids sensitive recovery work when budget authority is already unavailable or
exhausted.

**Rationale**: Signed budget fields are requested upper bounds, not proof of available
capacity. One database transaction is the only way to serialize shared aggregate
allowance with the operation decision.

**Alternatives considered**:

- Treat the signed reservation ID as capacity proof: rejected because concurrent plans
  could spend the same allowance.
- Accept caller-supplied totals during prepare: rejected because prepare must not widen
  authority.
- Use a separate budget service: rejected for v1 because operation and reservation
  would lose one atomic boundary.
- Release on ambiguous commit: rejected because it may over-credit a committed hold.

## Decision 8 - Publish recovery evidence manifest-last

**Decision**: Recovery remains a separate provider domain. A compensable plan uses an
approved `RecoveryProviderProfileV1` and an operation-scoped cross-process publication
guard. The provider protocol is:

1. derive a domain-separated material identity from the exact plan, operation, target,
   precondition, provider generation and recovery binding;
2. create a fresh publication-attempt ID;
3. write create-only staging material, synchronize it, reopen it and verify exact digest
   and length;
4. publish material without overwrite inside the attested local provider root;
5. write, synchronize and publish a canonical manifest last;
6. reopen the published pair, verify capacity and all bindings, and return an immutable
   receipt;
7. keep the publication guard until coordinator commit/readback is classified.

The receipt binds closed receipt/provider-profile versions, profile/provider identities,
evidence class, at-rest/capability binding, plan, operation/attempt,
target/precondition identity/digest/length, recovery class and atomicity, actual material
digest/length, reserved capacity, publication state, boot/instance/fencing epochs and
manifest digest. A synthetic provider is conformance-only and cannot establish a
production compensability claim.

An already valid irreversible L2 plan records explicit `NO_RECOVERY_MATERIAL` evidence
and never calls the provider or receives a synthetic receipt.

**Rationale**: A signed digest and byte reservation are not recovery material.
Manifest-last publication makes incomplete staging non-authoritative and the guard
prevents cleanup from racing the coordinator commit.

**Alternatives considered**:

- Put pre-image bytes in the coordinator database: rejected because recovery providers
  are independent sensitive durability domains.
- Write directly to a final object: rejected because a crash can leave torn material
  that appears published.
- Downgrade failed compensation to irreversible: rejected because a new L2 plan is
  required.
- Claim directory-fsync or power-loss durability portably: rejected; v1 evidence is
  process-crash plus provider-profile evidence only.

## Decision 9 - Make the coordinator transaction the only PREPARING linearization point

**Decision**: Use a dedicated provisioner-attested coordinator SQLite root and a
distinct application ID/schema version. Reuse the exact locked PLAN-003 supply chain:

- Rust `1.96.1`;
- `rusqlite 0.40.1` with `default-features=false`, `bundled`, `backup`, `serialize`;
- `libsqlite3-sys 0.38.1`, bundled SQLite `3.53.2`;
- `getrandom 0.4.3`, `sha2 0.10.9`, `serde 1.0.228`, `serde_json 1.0.150`,
  `serde_json_canonicalizer 0.3.2`, `base64 0.22.1` and `ed25519-dalek 2.2.0`.

Every writable connection establishes and reads back WAL, `synchronous=FULL`, disabled
automatic checkpoint, foreign keys, `trusted_schema=OFF`, `cell_size_check=ON` and a
deadline-bounded busy timeout. Every connection also establishes and reads back
`recursive_triggers=ON`; explicit conflict guards plus recursive delete triggers prevent
`OR REPLACE` from erasing permanent root/quarantine history. Schema v1 uses strict tables and exact schema/index,
application-ID, version, integrity and cross-record invariant checks.

One short `BEGIN IMMEDIATE` transaction atomically:

- allocates a preparation generation;
- inserts the exact attempt-bearing `PREPARING` operation and canonical plan;
- appends one permanent globally unique operation-transition generation;
- inserts the complete comparison/replay evidence;
- updates the budget scope and inserts the held reservation;
- stores the immutable recovery reference or explicit irreversibility evidence;
- inserts one redacted preparation event/outbox row;
- advances metadata generations.

The independently durable replay row, supervisor store and recovery material are
verified/guarded inputs. They are not attached databases and no distributed transaction
or global atomicity is claimed. SQLite's transaction, WAL and synchronous semantics are
documented by the [official transaction](https://www.sqlite.org/lang_transaction.html),
[WAL](https://www.sqlite.org/wal.html) and
[synchronous pragma](https://www.sqlite.org/pragma.html#pragma_synchronous) references.

**Rationale**: Every member of the positive coordinator set shares one authority and
must never be partially visible. Independent domains need receipts, guards and
reconciliation instead of fictional cross-store atomicity.

**Alternatives considered**:

- Attach the replay database: rejected because attached WAL databases do not form the
  required cross-domain transaction and the replay schema must stay frozen.
- Use `BEGIN DEFERRED`: rejected because read-to-write upgrade races complicate bounded
  contention.
- Use system SQLite or `synchronous=NORMAL`: rejected as supply-chain/profile drift.
- Allow automatic checkpoints during admission: rejected because it introduces
  unbounded surprise work into the short commit gate.

## Decision 10 - Bind every possible commit to a fresh attempt and exact readback

**Decision**: Generate one OS-random, domain-separated preparation-attempt ID before
recovery publication. Bind it into the recovery receipt, operation, reservation,
comparison evidence and event.

Classify outcomes by mutation phase and trusted store classification, never native error
text:

- a definite pre-transition authority/binding refusal is `Denied`; a definitive
  provider/store operational result after recovery/store entry is `Failed`;
- confirmed rollback is `Failed(PREPARATION_STORE_COMMIT_ABORTED)` and never opens
  readback;
- once mutation begins or commit is attempted: never retry the transaction;
- only an explicit `UNCERTAIN` classification (including lost acknowledgement) opens one
  fresh readback view while retaining the recovery guard and supervisor permit. A result
  with lost acknowledgement is explicitly `UNCERTAIN`. Verify the full store first;
  missing/untrusted classification performs zero worker readback and, like late or
  owner-loss paths, resolves ambiguous through the independent deadman at the earlier
  caller deadline or 250 ms permit ceiling.

Readback is closed:

- exact same attempt and all cross-record bindings: committed; return `Prepared` only
  if the deadline and guards still hold;
- a coherent prior attempt: `AlreadyPrepared`, never a second positive marker;
- any key bound differently: conflict;
- all operation/attempt/reservation/transition/event keys absent in one healthy
  definitive view: `Failed(PREPARATION_STORE_DEFINITE_ABSENCE)` with no retry;
- failed, late, unhealthy, contradictory or incomplete proof: ambiguous.

Only the original call's exact attempt readback may recover a positive in-process
marker. Public lookup after return or restart yields read-only status/evidence, not a
recreated marker. A future dispatch feature must perform its own fresh transition from
durable state.

**Rationale**: Attempt identity distinguishes the original possible commit from a
later contender and prevents double reservation or false absence. It reuses PLAN-003's
proven conservative pattern.

**Alternatives considered**:

- Retry after a commit error: rejected because it can double-reserve.
- Treat every commit error as failure: rejected because the row may be durable.
- Return an existing record as a second positive marker: rejected because positive
  custody is one-shot.

## Decision 11 - Keep quarantine separate from operation state

**Decision**: The only operation states introduced remain `PREPARING` and `FAILED`.
Ambiguity, orphan material, corrupt roots and restored old authority use a separate
`PreparationQuarantineV1` maintenance record/root disposition. Quarantine is never an
operation transition, positive marker, dispatch input or proof that an operation exists.

An ambiguous call returns an opaque redacted handle for trusted reconciliation. Once
the store is healthy, maintenance performs exact readback:

- exact `PREPARING`: retain it and withhold authority until future fresh transition;
- definite absence plus published material: record an orphan quarantine;
- conflicting or incomplete evidence: retain quarantine and fail closed.

Recovery cleanup acquires the mutually exclusive cleanup guard first, then the
coordinator maintenance/write gate, verifies full invariants and proves no operation,
attempt, reservation, event or ambiguity record can reference the material. One
temporary absence read is never enough.

**Rationale**: FR-034 freezes the operation machine while FR-027/033/038 require
uncertainty to remain visible. A separate maintenance disposition satisfies both without
inventing dispatchable states.

**Alternatives considered**:

- Add `OUTCOME_UNKNOWN` to the operation machine now: rejected because no host effect
  exists and the spec limits this slice to pre-dispatch states.
- Delete orphans after a timeout: rejected because a commit may still be in flight or
  unobservable.
- Infer an operation from recovery material: rejected because material is explicitly
  non-authoritative.

## Decision 12 - Reconcile known pre-dispatch failures atomically

**Decision**: A privileged coordinator method may perform exactly one
`PREPARING -> FAILED` transition only while holding an opaque sovereign
`NoDispatchAuthorityGuardV1`. The guard binds operation, attempt, current state
generation, boot/instance/fencing epochs and revocation generation and remains live
through commit. Missing, stale or revoked custody leaves operation and reservation
unchanged; row absence or an operator assertion is never proof. The same transaction
releases the exact held reservation once, preserves its permanent tombstone and inserts
one failure event. The guard itself and
its binding are entirely ephemeral; only the `FAILED` result, transition and event are
durable and cannot recreate authority. It cannot release replay
state, reuse a reservation ID, delete the canonical plan or silently retire recovery
material.

After commit, recovery retirement remains a separate guarded provider operation. A
failed retirement leaves the operation `FAILED` and material quarantined; it never
reopens the budget or preparation transition. Under the cleanup guard, coordinator
recovery evidence first moves `PUBLISHED -> RETIREMENT_PENDING`, the provider publishes
an immutable retirement tombstone, then coordinator evidence moves to
`RETIRED_TOMBSTONE` with the exact tombstone digest. Pending state is reconcilable and
blocks backup; `PREPARING` can never enter it.

A true pre-commit orphan uses a separate path and never fabricates an operation. Under
the same exclusive cleanup guard, a healthy definitive view proves absence of every
operation, attempt, reservation, event, in-flight permit and active ambiguity reference.
The coordinator then appends a permanent orphan-resolution record in
`RETIREMENT_AUTHORIZED` before provider retirement. Provider retirement publishes its
immutable tombstone; a final coordinator transition records `RETIRED_TOMBSTONE` and the
exact provider tombstone digest. Either crash boundary remains quarantined,
reconcilable, permanent and backup-blocking while pending.

**Rationale**: Budget reconciliation belongs to authoritative coordinator state, while
external material cleanup has separate crash semantics. Splitting them avoids claiming
one transaction without weakening the failure record.

**Alternatives considered**:

- Release budgets without a held no-dispatch guard: rejected because absence can race a
  future dispatch authority.
- Release budgets before the failure state: rejected because a crash could over-credit.
- Delete failed operations: rejected because replay, budget and audit history must stay
  explainable.
- Fabricate `FAILED` for an orphan: rejected because material alone is not operation
  authority.
- Release the permanent replay claim: rejected because a fresh signed plan is required.

## Decision 13 - Use a quiescent cross-domain backup manifest

**Decision**: Backup is a coordinated quiescent cut, not an atomic distributed
snapshot:

1. persist PAUSE through the supervisor control lane;
2. acquire provider-wide recovery maintenance and coordinator maintenance guards;
3. verify paused supervisor epochs and no in-flight preparation;
4. record stable coordinator and recovery generations;
5. use SQLite's online backup API into a create-only destination;
6. emit a canonical recovery inventory grouped by provider profile/identity/generation;
   groups are strictly sorted/unique by that tuple and each group's entries are strictly
   sorted/unique by binding digest. Export material-present packages and retired
   tombstones, reject any retirement-pending state and support permanently retained rows
   across provider rotation. The complete set covers operation references, active
   quarantine and every provider-enumerated package; unrecorded extras first become
   durable quarantine. Coordinator operation-bound and orphan pending-retirement counts
   both equal zero and agree with provider enumeration and inventory
   `no_retirement_pending=true`;
7. close, integrity-check and hash the coordinator database;
8. recheck both source generations;
9. publish one canonical top-level manifest whose digest is lowercase SHA-256 of the
   complete object's exact RFC 8785 UTF-8 bytes without BOM or trailing newline;
10. publish a detached, versioned provisioner-signed provenance attestation as the
    final package publication point.

The manifest binds application/schema/profile versions, coordinator digest and
generations/counts, canonical multi-provider inventory digest/group and entry counts, and
fixed requirements for PAUSED restore, new boot/instance/fencing epochs, non-reactivation
of nonterminal preparations and possible omission of work after the cut. The detached
attestation uses the already pinned Ed25519 profile to sign a domain-separated RFC 8785
canonical payload binding the exact manifest
digest, opaque coordinator/recovery root identities, source instance, coordinator and
recovery generations, at-rest profile and approved signing profile/key identity. No raw
key enters this feature. The
[SQLite online backup API](https://www.sqlite.org/c3ref/backup_finish.html) is the
positive database path; raw live DB/WAL copying is not.

Restore requires new empty coordinator and recovery roots, verifies every member before
publication, verifies the detached signature and pinned key/profile/revocation state
before either destination root is published, restores through SQLite, establishes
WAL/FULL, closes/reopens and rechecks all cross-record references. Coordinator and
recovery metadata independently persist the same restore identity and
`RESTORE_PENDING`; mismatch quarantines and ordinary open, prepare and retirement deny.
Old `PREPARING` rows are historical evidence and must become `FAILED` or remain
quarantined under rotated authority. Feature 004 does not activate either restored root.

**Rationale**: Quiescence is the smallest honest v1 protocol across independent stores.
It retains a coherent reference set without pretending recovery and SQLite share a
transaction.

**Alternatives considered**:

- Fully live cross-domain backup: deferred because it needs versioned pin leases and a
  distributed cut protocol.
- Back up only SQLite: rejected because compensability references would be incomplete.
- Trust digests or encrypted storage without signed provenance: rejected because a
  coherent package replacement would remain internally consistent.
- Restore over a live root or reactivate old `PREPARING`: rejected as authority reuse.

## Decision 14 - Make data protection and retention explicit

**Decision**: Canonical plans and recovery material are restricted operational data,
at least as sensitive as their source. Agent/model workloads, Graphify, fixtures, logs,
metrics, public diagnostics and egress never receive them. V1 uses no raw credential or
network egress.

SQLite is not presented as application-encrypted. A production coordinator/recovery
root must be provisioner-attested to an approved encrypted-at-rest local storage
profile. Backup staging must remain in an equally approved root, and exported backups
require encrypted transport/storage handled outside this feature. Synthetic roots prove
protocol conformance only. No key bytes enter these APIs.

V1 retention is closed and testable:

- no automatic pruning or online deletion API exists;
- `PREPARING`, ambiguous/quarantined evidence and canonical plan bytes are retained
  indefinitely;
- `FAILED` operations, released reservation rows and delivered outbox events remain
  permanent tombstones/evidence;
- recovery bytes remain while state is `PREPARING`, ambiguous or quarantined;
- operation-bound bytes retire only after durable `FAILED` plus exact reservation
  reconciliation under the exclusive guard;
- true orphan bytes retire only after guarded definitive no-reference proof and a
  permanent orphan-resolution tombstone, without fabricating an operation;
- both paths retain immutable provider/coordinator retirement tombstones;
- physical secure erasure is not claimed;
- any shorter lifecycle requires a later versioned policy and, where guarantees change,
  a constitution/spec amendment.

Public errors and events use bounded stable codes/counts only. Restricted database
foreign keys may link internal rows, but serialized preparation events expose no plan
content, native path, identifier, nonce, digest, user-bound amount or provider error.

**Rationale**: This closes Constitution Gate 4 without inventing a deletion guarantee
or leaving retention to an unspecified deployment default.

**Alternatives considered**:

- Add SQLCipher now: rejected because it adds a new native crypto/key-management supply
  chain; an approved encrypted storage profile is the bounded v1 dependency.
- Retain data for an unspecified configurable period: rejected because that is not a
  testable policy.
- Delete all recovery material on `FAILED`: rejected because ambiguous references and
  cleanup races must be excluded first.

## Decision 15 - Use one unchanged portable conformance and fault corpus

**Decision**: Add one versioned corpus under
`contracts/fixtures/durable-preparation-v1` with positive and single-fault cases for
comparison, exact replay verification, budget limits/contention, recovery publication,
guard revocation, commit ambiguity, cancellation, quarantine, backup/restore and
redaction. Expected case IDs, outcome codes and schema/corpus digests are unchanged on
macOS arm64, Linux x64 and Windows x64.

The Rust tests include contract/compile-fail boundaries, deterministic first-failure
order, at least 100,000 generated budget vectors, 100 x 64-thread and 20 x 8-process
contention, controlled held writers, process-kill/fault points, schema/invariant
corruption, backup/restore, redaction and source portability scans. Fault hooks compile
only under an empty-default `test-fault-injection` feature.

The corpus additionally freezes no-dispatch guard mismatch/revocation, confirmed
rollback versus explicit uncertainty, the earlier caller/250 ms permit boundary,
true-orphan tombstone crash points, coherent package substitution, provenance
key/profile/revocation failures and disagreement between independently pending roots.

Evidence says `process-kill` or injected fault, never power-loss. Synthetic recovery is
explicitly conformance-only. No `cfg(target_os)` branch may change common outcomes.

**Rationale**: Portability is semantic equality, not compilation alone. The corpus
freezes first-denial ordering and prevents platform-specific fallback.

**Alternatives considered**:

- Per-platform expected files: rejected because they hide semantic drift.
- Test only the SQLite happy path: rejected because authority races and corrupt evidence
  are the primary risk.
- Compile fault hooks in production: rejected because they expand the sovereign surface.

## Decision 16 - Separate commit latency from recovery transfer and pin release evidence

**Decision**: On the physical Mac mini M4, collect 500 warmups and at least 10,000
sequential final-compare plus coordinator-commit samples. Require p95 <= 25 ms and
p99 <= 100 ms. Record raw samples, hardware, OS/build/architecture, exact Rust/SQLite
source and durability profile, corpus/schema digests, concurrency, source commit,
artifact path and SHA-256.

Measure recovery transfer separately by size/profile and never relabel it as the
coordinator threshold. Run at least 1,000 controlled held-writer calls; each returns by
the caller's monotonic deadline plus at most 50 ms scheduler tolerance. Release the
blocker, observe for at least 250 ms, reopen, and prove zero detached mutation.
Run the permit/deadman matrix against both caller-deadline-first and 250 ms-ceiling-first
cases, including equality; every unresolved permit resolves within the same 50 ms
controlled scheduler tolerance with PAUSE active and no reusable permit.

PLAN-004 release evidence also pins the lockfile, bundled SQLite source ID, licenses,
advisories, SBOM/provenance where applicable, immutable CI artifacts, clean restore,
rollback refusal and removal. Removal must preserve PLAN-001 bytes/signatures,
PLAN-002 outcomes, PLAN-003 rows and legacy tests.

**Rationale**: Recovery I/O and the short authority commit have different performance
profiles. Separating them keeps the acceptance claim measurable and prevents a fast
synthetic provider from masking coordinator regressions.

**Alternatives considered**:

- Report averages only: rejected because tail latency controls deadlines.
- Count hosted macOS as physical M4 evidence: rejected because runner hardware/storage
  are not the declared target.
- Upgrade dependencies while implementing: rejected because it mixes feature behavior
  with supply-chain drift.

## Decision 17 - Keep sovereign restore maintenance behind the crate boundary

**Decision**: Feature 004 publicly exports only the non-constructible,
payload-free `VerifiedPreparationRestoreV1` and
`RestoredPreparationMaintenanceEvidenceV1` projections. It provides no public producer
for either projection. Restore package acceptance, pending-root validation,
old-authority reconciliation, quarantine, maintenance limits/errors and every PAUSE,
fencing, recovery, trust/revocation or no-dispatch authority remain crate-internal.
Non-default hidden conformance entrypoints may return only static payload-free test
results and never become production maintenance APIs.

**Rationale**: No implemented Feature 004 host owns the complete sovereign authority set
needed to expose a safe production maintenance facade. Keeping the authority-bearing
operations internal preserves the constitutional typed-host boundary while allowing a
later host feature to return the already redacted evidence after it specifies and proves
PAUSE, fencing, recovery, trust, quarantine, no-dispatch and activation ownership.

**Alternatives considered**:

- Expose the crate-internal restore/reconciliation functions directly: rejected because
  callers could not supply the required sovereign custody honestly.
- Export test-only synthetic factories as production wiring: rejected because
  conformance fixtures are not authority or release evidence.
- Implement the complete sovereign host in Feature 004: rejected because supervisor,
  fencing-store, leadership and restored-system activation are explicitly out of scope.
