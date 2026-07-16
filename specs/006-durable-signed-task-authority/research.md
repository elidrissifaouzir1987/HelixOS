# Research: Durable Signed Task Authority

**Feature**: `006-durable-signed-task-authority`

**Date**: 2026-07-15
**Authoritative inputs**: `ARCHITECTURE.md` sections 4 and 6,
`ROADMAP-SPECS.md` R1, Constitution 2.0, PLAN-001 through PLAN-005
specifications/contracts, the Rust workspace at merged baseline
`c324f528dc76007a599005e5cc054dcbe1370b1a` (tree
`c70a3f2157498dd880822f97ef74d3d4757347d7`), and Graphify queries over the
current project graph.

## Decision 1 - Stop at durable signed authority and verified projections

**Decision**: PLAN-006 implements the complete version-1 chain
`HumanRequestGrantV1 -> TaskLeaseV1 -> ApprovalDecisionV1`, its durable
one-shot state, revocation, and current projections into the already-reviewed
PLAN-002, PLAN-004 and PLAN-005 comparison seams. It performs no request-edge
transport, WebAuthn ceremony, IPC, host effect, effect verification, settlement,
or R2 platform activation.

`EXECUTING` from PLAN-005 continues to mean consumed adapter authority only.
PLAN-006 does not reinterpret that state or manufacture a production approval
from deterministic test evidence.

**Rationale**: The R1 gap named by PLAN-005 is signed request, lease and approval
authority. Extending the slice into ingress or effects would combine distinct
trust boundaries and make acceptance claims ambiguous.

**Alternatives rejected**:

- Add real WebAuthn or `helix-edge`: separate sovereign ingress feature.
- Add host drivers or execution settlement: R2 and later lifecycle work.
- Treat existing synthetic views as migrated authority: violates the
  specification and preserves the exact gap PLAN-006 closes.

## Decision 2 - Use four one-way PLAN-006 crates

**Decision**: Add these crates:

1. `helix-task-authority-contracts`: canonical signed wire values, strict
   decoding, protected digests, purpose-specific signer/resolver traits, and no
   storage or prior-plan dependency.
2. `helix-task-authority`: portable issuance, delegation, decision, revocation,
   outcome, projection and store/guard traits.
3. `helix-task-authority-sqlite`: the strict local authority store and its
   maintenance, backup, restore, readback and fault-injection implementation.
4. `helix-task-authority-projections`: the only adapter from verified PLAN-006
   projections to PLAN-002/004/005 interfaces.

Dependencies flow from PLAN-006 toward existing PLAN-001/002/004/005 APIs.
No existing signed wire or production source changes and no protected legacy runtime
source is modified. The exact direct-consumer guards in
`kernel/helix-plan-eligibility/tests/portability.rs`,
`kernel/helix-plan-preparation/tests/contract.rs`,
`kernel/helix-coordinator-sqlite/tests/portability.rs` and
`kernel/helix-plan-dispatch/tests/portability.rs` may recognize only the new reviewed
projection leaf. The semantic workspace-removal guard in
`tools/tests/test_plan004_evidence.py` may recognize all four PLAN-006 crates as
downstream members while retaining the exact prior sets. PLAN-005's removal manifest,
removal driver, supply verifier, evidence test and retained removal record may classify
the PLAN-006 crate/fixture/Graphify prefixes and current lock extension, including
repinning only the exact full-lock-bound RustSec report and production-graph artifact
digests while preserving the selected package, edge, external dependency, license and
SBOM oracles. The PLAN-005 inbox portability guard may recognize the same reviewed
removal-prefix set. These seven test edits and four retained PLAN-005 policy/evidence
artifacts belong to the PLAN-006 integration and removal footprint. All new production
crates use `#![forbid(unsafe_code)]`.

**Rationale**: Contract, authority semantics, native persistence and downstream
projection have different portability and dependency surfaces. The split lets
the contracts run everywhere, keeps SQLite out of core semantics, prevents
PLAN-002/004/005 types from contaminating the authority model, and makes removal
mechanical.

**Alternatives rejected**:

- Put new wires in `helix-contracts` or `helix-dispatch-contracts`: widens
  frozen PLAN-001/005 ownership and removal surfaces.
- One crate per wire: duplicates canonicalization and cryptographic machinery.
- Put projections in the core crate: forces prior-plan dependencies into the
  portable authority boundary.
- Add PLAN-006 dependencies to existing plan crates: reverses the intended
  integration direction and weakens isolated removal.

## Decision 3 - Freeze three closed canonical signature profiles

**Decision**: All envelopes contain exactly `protected`, the contract-specific
protected digest, and `signature`. Verification performs, in order: bounded raw
input, duplicate-aware parse, exact RFC 8785 byte comparison, closed-field
preflight, typed semantic validation, SHA-256 protected-digest recomputation,
canonical base64url-no-pad signature decoding, purpose-specific key resolution,
and strict Ed25519 verification. The signed message is
`domain || JCS(protected)`.

| Contract | Protected schema | Outer digest | Key purpose | Signature domain |
|---|---|---|---|---|
| `HumanRequestGrantV1` | `helixos.human-request-grant/1` | `grant_digest` | `request-surface-grant-signing` | `HELIXOS\0HUMAN-REQUEST-GRANT\0V1\0` |
| `TaskLeaseV1` | `helixos.task-lease/1` | `lease_digest` | `core-task-lease-signing` | `HELIXOS\0TASK-LEASE\0V1\0` |
| `ApprovalDecisionV1` | `helixos.approval-decision/1` | `decision_digest` | `core-approval-decision-signing` | `HELIXOS\0APPROVAL-DECISION\0V1\0` |

Each protected object requires its schema, `sha-256`, `ed25519`, exact key
purpose and immutable key ID. Unknown fields, versions, algorithms, purposes and
enum values deny. A future V2 receives a new schema, domain, decoder and fixtures;
V1 never silently upgrades it.

**Rationale**: This applies the PLAN-001 cryptographic profile with PLAN-005's
stronger duplicate denial, closed preflight and current-versus-historical key
separation.

**Alternatives rejected**:

- Accept noncanonical JSON and normalize it: permits multiple accepted wires.
- Sign the digest or outer envelope: changes the reviewed protocol and creates
  avoidable substitution or hash-then-sign ambiguity.
- Use one generic signer purpose: makes cross-protocol misuse easier.
- Runtime JSON Schema as the authority verifier: cannot prove duplicate denial,
  canonical bytes, NFC or relational invariants.

## Decision 4 - Keep authority in a separate guarded SQLite domain

**Decision**: `helix-task-authority-sqlite` owns a separate local SQLite root
with:

```text
application_id = 1212962881
hex            = 0x484c5841
ASCII          = HLXA
user_version   = 1
```

The authority store uses WAL, `synchronous=FULL`, foreign keys, recursive
triggers, `trusted_schema=OFF`, `cell_size_check=ON`, disabled automatic
checkpoints and deadline-bounded busy waits. Ordinary open verifies the exact
application/schema identity, root metadata, durability profile and all
cross-record invariants without repair or migration.

One unified authority guard starts `BEGIN IMMEDIATE`, resolves the lease and
approval chain from one snapshot, and remains held from the existing Lease guard
slot through the final PLAN-004 or PLAN-005 coordinator commit. Authority writes
therefore linearize entirely before or after the downstream commit. The
downstream coordinator transaction starts only after the authority guard, and no
authority path takes locks in the reverse order.

**Rationale**: PLAN-004/005 read but do not mutate PLAN-006 authority. A retained
writer guard closes the interprocess TOCTOU without a distributed transaction,
preserves the proven coordinator V2 database unchanged, avoids self-deadlock
between a guard transaction and a coordinator transaction on one database, and
keeps removal exact.

**Alternatives rejected**:

- Add a coordinator V3 overlay: would require an invasive redesign so the
  current guard capture and coordinator commit share one SQLite transaction;
  otherwise a V3 writer guard self-blocks. It also couples contention, migration,
  backup and rollback to PLAN-004/005 state.
- Use separate lease and approval transactions: the second writer transaction
  would block behind the first and could observe a different generation.
- Read then commit without a retained guard: permits revocation or generation
  change between capture and commit.
- Claim cross-store atomicity: no transaction spans the authority and
  coordinator databases.

## Decision 5 - Bootstrap a new authority root without migrating authority by assertion

**Decision**: PLAN-006 has no valid predecessor authority schema. Its supported
migration is an explicit paused bootstrap from the exact PLAN-005 coordinator V2
baseline to a new, empty `HLXA` schema-v1 root. Maintenance verifies the source
root/schema and a fresh backup, stages the complete authority database, writes a
migration receipt binding the source summary and PLAN-006 schema digest, and
publishes the root last. Restart either resumes the same staging identity or
classifies the already-published exact root; it never creates a second root.

No unsigned legacy lease, approval enum, caller row, boolean or synthetic
projection is inserted into the grant, lease or decision tables. Those values can
remain historical PLAN-001/005 evidence only. Ordinary open never bootstraps.
Wrong, newer, corrupt, partial or downgrade states fail closed.

**Rationale**: This gives FR-038 and SC-009 a real restartable lifecycle while
truthfully acknowledging that there is no prior signed-authority database to
upgrade.

**Alternatives rejected**:

- Pretend the coordinator V2 store is authority schema v0: changes its meaning.
- Backfill signed records from legacy values: creates authority without a valid
  signer or human request.
- Treat first ordinary open as migration: makes admission mutating and
  non-auditable.

## Decision 6 - Consume one human grant and retain one root chain

**Decision**: Grant identity uniqueness is issuer-scoped and independent of key
ID and PLAN-003 replay. Root issuance atomically retains exact grant bytes,
verification/trust evidence, one create-only claim, one signed root lease, initial
usage, generation changes and a redacted transition event. The candidate lease is
signed before the short writer transaction. Every external clock, signer-trust,
scope, policy, catalogue and workload guard required for the mutation is acquired
in the global prefix order before HLXA; immutable observation tokens are then
carried into the writer. Under HLXA the mutation compares those tokens with the
candidate and current HLXA rows, but never calls a provider or acquires a guard
that precedes HLXA. This is the mutation/maintenance meaning of "rechecked under
the writer."

Before signing, the operation also freezes the canonical idempotency preimage and
its domain-separated `input_graph_digest`. The preimage excludes the random attempt
ID and generated candidate lease ID, issue-time fields and signature bytes. An
exact retry compares that stable digest and returns the identical retained
root-lease bytes, even when its losing candidate bytes differ. Reuse with any
different input digest is a permanent conflict and produces no second lease.

**Rationale**: Database uniqueness, not a preflight `SELECT`, must arbitrate the
64-thread/eight-process race and survive signer rotation.

**Alternatives rejected**:

- Key grant uniqueness by signer key: rotation reopens the one-shot identity.
- Re-sign an exact retry: changes evidence bytes and makes lost acknowledgement
  unsafe.
- Use PLAN-003 nonce claims: conflates request issuance with plan execution replay.

## Decision 7 - Model delegation as atomic monotone allocation

**Decision**: Every lease binds task, workload, source grant, parent/ancestor
chain, allowed intentions, portable resources, budgets, counters, trust/catalogue
bounds, audience, boot/instance state and exclusive deadlines. Root scope is the
intersection of the human grant and current trusted scope/policy/catalogue limits.

Delegation atomically rechecks the parent and ancestors, computes checked
aggregate sibling allocation, inserts one create-only allocation, child lease,
child usage and event, and increments generations. Every governed child axis is
equal or narrower. Exact limits pass; a one-unit widening, union, renewal,
overflow, underflow or oversubscription denies without mutation.

**Rationale**: Comparing a child only to its parent is insufficient when siblings
share finite budgets. Parent allocation and child issuance must have one writer
linearization point.

**Alternatives rejected**:

- Track allocations in memory: loses limits on restart and across processes.
- Release or reset counters: recreates authority that the parent already spent.
- Merge multiple leases: can form a wider union than any signed parent.

## Decision 8 - Retain one terminal plan-bound decision

**Decision**: Approval evaluation requires the exact authentic PLAN-001 envelope,
current grant/lease chain, plan ID and canonical envelope digest, operation,
nonce, risk, principal/session, evidence profile, policy/catalogue, boot/instance
and exclusive deadline. The core signs and atomically retains either `APPROVED`
or `DENIED`, never an intermediate value. One exact target has one terminal
decision; approve/deny races linearize to the retained result and cannot flip.

Only a current approved decision with the required user-verification-capable
profile can yield a positive authorization projection. Synthetic evidence is
labelled conformance-only and never production authority.

**Rationale**: The core is the only signer able to bind authentication evidence to
the exact current plan and authority generations at durable commit.

**Alternatives rejected**:

- Let the request surface sign the final plan decision: it does not own the
  current plan/lease/store snapshot.
- Store a mutable pending/approved row: permits terminal decision flipping.
- Bind only `plan_id`: misses canonical plan-envelope substitution.

## Decision 9 - Use create-only transitions and one fresh uncertainty readback

**Decision**: Root issuance, delegation/allocation, counter consumption, terminal
decision, trust change and revocation each use one short `BEGIN IMMEDIATE`
transaction with an independent domain-separated attempt ID. Signed bytes are
immutable; mutable current summaries are derived from append-only facts and
monotonic generations.

Failure before mutation or confirmed rollback is definite. Once mutation may
have begun, the operation is never blindly retried. Only explicit uncertainty
opens one fresh readback after abandoning the original connection. The readback
validates the complete schema and classifies exact complete graph, conflict,
healthy absence, or ambiguity. Expired/revoked retained bytes are historical
evidence, not renewed authority.

**Rationale**: This preserves one-shot semantics across lost acknowledgements and
process death without overstating exactly-once infrastructure.

**Alternatives rejected**:

- Retry on any database error: can duplicate signed authority after a lost commit
  acknowledgement.
- Return success from a partial row: treats corruption as authority.
- Continue work in a detached thread after timeout: permits mutation after a
  terminal caller result.

## Decision 10 - Combine UTC validity, same-boot monotonic time and generations

**Decision**: Signed wires carry bounded UTC validity; durable projections also
carry the earliest exclusive monotonic deadline and exact boot/instance identity.
Equality at any expiry denies. Reboot makes every nonterminal lease and approval
non-current. Wall-clock rollback, monotonic rollback, boot mismatch, suspend and
unexpected long sleep fail closed. A downstream commit must finish before its
captured earliest deadline while the unified authority guard remains held.

**Rationale**: UTC is portable evidence; same-boot monotonic time resists local
clock rollback for live authority. Neither alone is sufficient.

**Alternatives rejected**:

- Refresh deadlines on retry: renews authority.
- Use ambient system time inside contracts: is neither injected nor portable.
- Treat rebooted monotonic values as continuous: can revive expired authority.

## Decision 11 - Separate current trust from historical verification

**Decision**: Each key ID is immutable and purpose-bound. Rotation creates a new
ID. The store retains public verification history, current trust status and
append-only status/revocation events with monotonic generations. A historical key
may verify retained bytes through a distinct evidence API but cannot create a
current marker or projection. Source or ancestor revocation invalidates all
descendants without rewriting their signed bytes.

**Rationale**: Cryptographic authenticity at a past instant is not equivalent to
current authorization.

**Alternatives rejected**:

- Delete old public keys: makes retained evidence unverifiable.
- Re-sign historical objects during rotation: changes immutable authority
  identity.
- Put current status only in memory: loses revocation on restart.

## Decision 12 - Project exact authority through existing seams only

**Decision**: PLAN-006 produces a nonconstructible current projection carrying at
least grant digest/generation, leaf lease digest/generation, ancestor-vector
digest, plan-bound lease projection digest, approval decision digest/generation,
revocation digest/generation, earliest deadline, and boot/instance/task/workload
bindings.

- PLAN-001 already binds the protected TaskLease digest and HumanRequestGrant
  source digest; its wire is unchanged.
- PLAN-002 inputs receive the same lease protected digest and a separate
  plan-specific lease decision digest; authorization evidence receives the
  ApprovalDecision protected digest.
- PLAN-004's `PreparationAuthoritySourceV1` acquires and retains the PLAN-006
  guard at the existing Lease/Authorization slots.
- PLAN-005's `DispatchAuthorityProviderV1` and `DispatchGuardProviderV1` reload
  the exact signed projection while that guard remains held.

Caller-provided positive PLAN-002 views, rows, legacy leases, approval enums and
booleans never become PLAN-006 markers.

**Rationale**: The existing seams already compare the right values under ordered
guards. An external adapter closes the signed-authority gap without changing
prior wire types or weakening their removal gates.

**Alternatives rejected**:

- Expose a public positive-view constructor from arbitrary fields: makes a
  projection forgeable.
- Modify PLAN-001 bytes: unnecessary; the digest seams already exist.
- Let downstream stores reconstruct signed wires: creates multiple authorities
  for canonical identity.

## Decision 13 - Back up one coherent paused multi-store cut and restore no live authority

**Decision**: A top-level PLAN-006 manifest is published last under PAUSE and a
fixed custody order. It binds independently coherent online backups for the new
authority root and all prior components required to interpret its plan
projections, exact application/schema/root identities, checkpoint/generation
summaries, public key history, member digests, migration receipt and provenance.
The manifest is maintenance evidence, not task authority: a distinct backup
provisioner signs `HELIXOS\0TASK-AUTHORITY-BACKUP\0V1\0 || JCS(protected)` with
purpose `backup-provisioner-signing`. Verification resolves `key_id` through an
externally provisioned purpose-specific trust anchor and current/historical status
history. Public keys copied into the manifest are checked against that resolver and
serve only as portable evidence; they cannot authenticate the document containing
them. All private keys are excluded.

Restore validates the complete package into approved empty destinations, rotates
root/boot/instance/fencing identities, publishes `RESTORE_PENDING`, and remains
PAUSED. Restored signed bytes remain historically verifiable, but every restored
nonterminal lease and approval is non-current. No redelivery, reissue or automatic
activation occurs.

**Rationale**: There is no cross-store transaction. Quiescent custody plus a
published-last manifest proves a coherent cut without claiming distributed
atomicity or full-machine recovery.

**Alternatives rejected**:

- Copy live database files without checkpoints: permits a torn logical package.
- Restore into existing roots: permits substitution and identity collisions.
- Preserve live epochs: can reactivate pre-restore authority.
- Back up signing keys: expands secret custody beyond this feature.

## Decision 14 - Retain restricted authority evidence permanently in V1

**Decision**: V1 retains signed wires, claims, allocations, counter consumptions,
terminal decisions, revocations, key history, transition events, migration
receipts and conflict tombstones without pruning. Raw messages, authentication
assertions, bearer values, private keys and native paths never enter the wires,
store, logs, fixtures or evidence. Public errors, metrics and events use closed
payload-free reason codes; debug output redacts identifiers and digests.

**Rationale**: Safe retirement and cryptographic erasure require a later policy.
Deleting one-shot tombstones now could recreate authority.

**Alternatives rejected**:

- Time-based deletion: may reopen grant, decision or allocation namespaces.
- Store raw authentication material for audit: violates data minimization and
  enlarges breach impact.
- Claim secure erasure from SQLite deletion: not established by this feature.

## Decision 15 - Use one portable corpus and evidence that stays pending

**Decision**: Freeze synthetic public-key golden fixtures plus generated mutation
and relational cases for grant, root/child lease and approved/denied decision.
The same corpus runs on macOS arm64, Linux x64 and Windows x64. A separate closed
fault registry covers in-process and applicable process-kill boundaries only
after schema operations stabilize; cardinality is derived, not guessed.

Release gates cover contracts, request one-shot behavior, restrictive delegation,
terminal decisions, projections, durability/readback, migration, backup/restore,
redaction, portability, controlled performance/overload, supply chain and exact
removal. The removal baseline is commit
`c324f528dc76007a599005e5cc054dcbe1370b1a`, tree
`c70a3f2157498dd880822f97ef74d3d4757347d7`.
Exact removal also restores the four existing dependency-policy test blobs changed
only to recognize `helix-task-authority-projections` plus the PLAN-004 workspace-
removal test changed to recognize all four PLAN-006 crates, the two PLAN-005 policy
tests that validate the inbox removal allowlist and downstream removal/lock projection,
and the four retained PLAN-005 policy/evidence artifacts synchronized by Phase 1. The
baseline package set, original expected-consumer/downstream lists and original PLAN-005
manifest/oracles must pass after every PLAN-006 crate is deleted.

The catalogue maps only `REQUEST-001`, `SEC-002` and `SEC-003` and remains
`pending-evidence` until exact-commit workflow artifacts satisfy their own gates.
Hosted timings are diagnostic. Physical M4, power-loss, production ingress/
WebAuthn, effects, full-machine restore and Tier 1 remain unclaimed.

**Rationale**: Portable deterministic evidence is reusable, while immutable and
physical claims require separately controlled environments.

**Alternatives rejected**:

- Platform-conditioned common semantics: hides portability failures.
- Promote claims from local tests or a PR head: lacks immutable exact-commit
  evidence.
- Reuse PLAN-004/005 fault registries: changes frozen evidence surfaces.

No `NEEDS CLARIFICATION` remains.
