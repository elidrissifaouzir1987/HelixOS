# Feature Specification: Durable Preparation Before Dispatch

**Feature Branch**: `master`

**Created**: 2026-07-11

**Status**: Implementation and local validation in progress

**Input**: Continue the HelixOS delivery sequence by consuming one current
`EligiblePlanV1`, comparing its complete authority vector again, reserving its declared
budgets and recovery capacity, and committing one recoverable `PREPARING` operation
without creating dispatch or effect authority.

## Clarifications

### Session 2026-07-11

- Q: How may published recovery material be retired when definitive readback proves
  that no `PREPARING` operation was ever committed? → A: Use two guarded paths:
  operation-bound material retires only after durable `FAILED` plus exact budget
  reconciliation; a true orphan retires only after definitive no-reference proof and a
  permanent orphan-resolution tombstone, without fabricating an operation.
- Q: Where is `RESTORE_PENDING` authoritatively retained after restore? → A: Persist it
  independently in both coordinator-root and recovery-root metadata; ordinary open and
  preparation paths deny until a later feature performs activation.
- Q: How is backup provenance authenticated against coherent replacement of the
  database, recovery inventory and their digests? → A: Require a detached, versioned
  provisioner-signed attestation binding the exact top-level manifest digest, opaque
  source identity, generations and protection profile; publish it last and verify it
  before restore.
- Q: What proves that releasing a held budget cannot race dispatch authority? → A:
  Require an opaque sovereign no-dispatch guard bound to the operation, attempt, current
  state generation and epochs, and hold it through the complete
  `PREPARING -> FAILED` transaction.
- Q: What is the v1 upper bound for a supervisor commit permit? → A: Its absolute
  monotonic deadline is the earlier of the caller deadline and 250 ms after permit
  entry; confirmed rollback resolves immediately, and only an explicitly uncertain
  commit may use bounded exact readback.

### Session 2026-07-12

- Q: Should Feature 004 implement a new sovereign host-maintenance facade, or restrict
  T075 to redacted evidence and internal maintenance operations? → A: Expose at most a
  bounded, payload-free, redacted read-only evidence type surface with no public
  producer; keep every authority-bearing restore-validation and reconciliation
  operation crate-internal, and defer the sovereign host and activation facade to a
  later feature.

## User Scenarios & Testing *(mandatory)*

User Story 1 is the minimum authority-bearing vertical slice. User Stories 2 through 4
remain independently testable with fixed non-authoritative fixtures for their other
dependencies, but no partial story may emit a production prepared marker by itself.

### User Story 1 - Prepare Only a Fresh Eligible Plan (Priority: P1)

As the sovereign coordinator, I can convert one point-in-time eligible plan into durable
preparation only while every authority fact, deadline and replay binding still matches,
so a stale plan cannot cross the last boundary before dispatch.

**Why this priority**: Eligibility proves that the plan was current at one earlier
instant. Policy, authorization, leases, capabilities, clocks and epochs may change while
recovery material is being prepared. Entering durable preparation from a stale result
would turn expired or widened authority into a future host effect.

**Independent Test**: Start with one eligible plan and a complete trusted preparation
context, then change each compared fact independently before the final transition. The
coherent case alone creates one durable `PREPARING` operation; every stale, expired,
torn or unavailable case returns its declared denial and creates no operation or budget
reservation.

**Acceptance Scenarios**:

1. **Given** an eligible plan, durable verified recovery evidence and an exact fresh
   authority comparison, **When** the coordinator prepares it, **Then** exactly one
   `PREPARING` operation is committed with the matching budget and recovery receipts.
2. **Given** any changed generation, digest, boot, epoch, deadline or authority
   decision, **When** final comparison occurs, **Then** preparation is denied before a
   new operation or budget mutation becomes visible.
3. **Given** the UTC expiry or boot-monotonic deadline is reached during recovery
   preparation, **When** the final comparison occurs, **Then** no positive prepared
   result is returned.
4. **Given** a trusted source that cannot participate in the required serialized final
   comparison, **When** preparation is requested, **Then** the request fails closed
   instead of using a check-then-write approximation.
5. **Given** a failed fresh comparison after the replay claim was already committed,
   **When** the caller considers retry, **Then** the replay claim remains permanent and
   a newly signed plan is required; the old claim is never released or revived.
6. **Given** a commit permit, **When** its caller deadline or fixed 250 ms v1 ceiling is
   reached first, **Then** the independent supervisor deadman resolves any unresolved
   permit as ambiguous, activates PAUSE and prevents a resumed worker from committing
   with that permit.

---

### User Story 2 - Reserve Every Declared Budget Once (Priority: P1)

As the budget authority owner, I can reserve the exact signed cost, action, egress and
recovery bounds for one operation at the same durable decision point as `PREPARING`, so
concurrency, crashes or reused reservation identifiers cannot overspend or double-count
capacity.

**Why this priority**: A budget inside a signed plan is a limit declaration, not proof
that capacity exists. Dispatching from an unreserved declaration would bypass lease
quotas and permit concurrent operations to spend the same allowance.

**Independent Test**: With fixed current-context and recovery fixtures that cannot emit
a production prepared marker, exercise exact-limit, one-below and one-above cases for
every supported budget dimension. Then run synchronized contenders with the same and
conflicting reservation identifiers and with distinct operations drawing from one
shared allowance. No failure can over-credit, double-reserve or silently change
currency or pricing.

**Acceptance Scenarios**:

1. **Given** sufficient current allowance and matching currency and price-table
   identity, **When** preparation commits, **Then** the exact upper bounds are held for
   that operation and the remaining allowance is reduced once.
2. **Given** any bound exceeds the remaining allowance by one unit, **When** preparation
   is attempted, **Then** it is denied with no partial reservation.
3. **Given** a reservation identifier already bound to another plan, operation, lease
   or budget vector, **When** it is reused, **Then** preparation returns a binding
   conflict and neither reservation changes.
4. **Given** concurrent local processes prepare the same operation, **When** they reach
   the durable decision point, **Then** exactly one coherent reservation and
   `PREPARING` record exist.
5. **Given** a possible commit whose acknowledgement is lost, **When** the caller
   recovers, **Then** exact readback determines whether the reservation exists; no blind
   retry or compensating double-release occurs.
6. **Given** two distinct operations with distinct reservation identifiers that each fit
   alone but exceed a shared allowance together, **When** they contend, **Then** only a
   subset within the aggregate limit commits and the total never exceeds any dimension.
7. **Given** a known pre-dispatch failure, **When** the coordinator attempts to release
   its held reservation, **Then** it may commit `PREPARING -> FAILED` only while holding
   an exact sovereign no-dispatch guard through the transaction; a missing, mismatched,
   expired or revoked guard leaves the operation and reservation unchanged.

---

### User Story 3 - Prepare Honest Recovery Evidence (Priority: P2)

As an operator responsible for recovery, I can require verified recovery material
before a compensable operation becomes prepared, so the system never promises rollback
from a digest declaration, an undersized reservation or an incomplete pre-image.

**Why this priority**: The signed plan already declares compensation or
irreversibility, but no recovery bytes are prepared today. A false compensation claim
is more dangerous than an explicit refusal or an honestly irreversible L2 operation.

**Independent Test**: With fixed current-context and budget fixtures that cannot emit a
production prepared marker, prepare synthetic compensable and irreversible plans
through the conformance recovery provider. Exact create-only material succeeds within
that test profile; missing, truncated, substituted, corrupted, stale, undersized or
unpublished material is denied. An irreversible L2 plan records that no compensation
exists and never receives a synthetic recovery receipt.

**Acceptance Scenarios**:

1. **Given** a compensable plan, a matching target precondition and a recovery provider
   whose evidence class is approved for the active environment, **When** recovery is
   prepared, **Then** the material is durable, hash-verified, sufficiently reserved and
   bound to the exact plan, operation, target and epoch before `PREPARING` commits.
2. **Given** a recovery receipt with a different digest, length, target, operation,
   provider generation or publication state, **When** it is checked, **Then**
   preparation is denied and compensation is not claimed.
3. **Given** recovery storage becomes unavailable or full, **When** compensation is
   required, **Then** the operation fails closed; an L1 plan is never silently
   reclassified as irreversible.
4. **Given** a valid irreversible plan already classified L2, **When** it is prepared,
   **Then** the durable record explicitly states that no pre-image exists and does not
   advertise compensation.
5. **Given** a crash after create-only recovery material is published but before the
   coordinator commits, **When** maintenance reconciles the orphan, **Then** it remains
   quarantined until an exclusive cleanup guard proves there is no committed, in-flight
   or ambiguous operation; a read showing temporary absence is never enough to retire
   it. After definitive no-reference proof, maintenance records a permanent orphan-
   resolution tombstone before provider retirement and never fabricates a `FAILED`
   operation.

---

### User Story 4 - Recover and Restore Preparation Safely (Priority: P3)

As a recovery maintainer, I can restart, back up, restore and inspect preparation state
without dispatching anything, so every interrupted attempt resolves to no operation,
one coherent prepared operation, or explicit quarantine requiring reconciliation.

**Why this priority**: This feature introduces the first durable operation and budget
state after replay admission. Its crash and restore semantics must be proven before a
future feature is allowed to create an execution grant.

**Independent Test**: Kill the process at every declared comparison, recovery,
reservation, transaction, publication and acknowledgement boundary. Reopen and restore
the state on a clean root. Every result is invariant-valid and non-dispatchable; no
budget, recovery receipt or audit event is duplicated or lost silently.

**Acceptance Scenarios**:

1. **Given** a process kill at any preparation boundary, **When** state is reopened,
   **Then** it contains either no committed operation, exactly one coherent
   `PREPARING` operation, or a quarantined ambiguous record with no positive marker.
2. **Given** an exact committed operation after restart, **When** it is read back,
   **Then** the canonical plan, comparison vector, budget receipt, recovery receipt and
   preparation event still agree.
3. **Given** a clean backup restored into a new system instance, **When** validation
   completes with an exact valid provisioner-signed provenance attestation, **Then**
   both the coordinator and recovery roots persist `RESTORE_PENDING`, the restored
   system remains paused, epochs are rotated and every old nonterminal preparation is
   permanently non-dispatchable. Ordinary open and preparation paths deny;
   reconciliation may release or retain resources but cannot activate either root or
   the old preparation. A new authorized signed plan is required after a later
   activation feature establishes new authority.
4. **Given** the same versioned corpus on macOS arm64, Linux x64 and Windows x64, **When**
   it is evaluated, **Then** every case produces the same stable outcome summary and
   digests without platform-conditioned preparation semantics.
5. **Given** an external caller inspecting the Feature 004 surface, **When** it examines
   restore and maintenance exports, **Then** it finds at most bounded redacted read-only
   evidence types with no public producer and cannot invoke restore validation,
   old-authority reconciliation, quarantine, activation or any
   PAUSE/fencing/trust/no-dispatch authority operation.

### Edge Cases

- The final trusted time sample equals the exclusive UTC expiry or boot-monotonic
  deadline exactly.
- A generation changes after preliminary comparison but before recovery publication,
  or after publication but before the durable transition.
- The supervisor fencing epoch changes while recovery material is being prepared or
  while the operation transaction is committing.
- A commit returns confirmed rollback, explicit uncertainty or no trusted
  classification as the earlier of the caller deadline and the 250 ms permit ceiling
  is reached.
- A no-dispatch guard is valid when failure reconciliation begins but is revoked or its
  bound state generation changes before the failure transaction commits.
- An unrelated replay claim advances the store's global generation while the exact
  replay receipt for this plan remains valid.
- The same operation identifier is paired with another plan, replay receipt, budget
  vector or recovery receipt.
- Two operations attempt to reuse one budget reservation identifier concurrently.
- Distinct operations with distinct identifiers each fit alone but exceed the same
  remaining task allowance in aggregate.
- A budget is exactly exhausted, exceeds one dimension by one, or would overflow a
  bounded integer during aggregate reservation.
- Currency remains the same but the price-table identity or authoritative generation
  changes.
- Recovery capacity is declared sufficient but actual material is short, corrupted,
  unpublished, substituted, duplicated or bound to a stale target precondition.
- Recovery publication succeeds but coordinator commit definitely fails; coordinator
  commit may have succeeded but acknowledgement is lost.
- Orphan cleanup observes no operation while a final commit is in flight or its outcome
  is still ambiguous.
- A true orphan is proved absent, but the process crashes before or after the permanent
  orphan-resolution tombstone and before provider retirement completes.
- The durable operation exists but its budget, recovery or preparation-event record is
  missing, duplicated, inconsistent or from an unknown schema version.
- A store is busy, read-only, full, corrupt, rolled back to an older generation or
  located on an unsupported filesystem.
- A backup observes recovery publication and operation commit at different instants.
- An attacker replaces the coordinator database, recovery inventory and all internal
  digests coherently but cannot produce the approved detached provenance attestation.
- A restored record carries the old boot, instance or fencing epoch.
- One restored root reports `RESTORE_PENDING` while the other is absent, active,
  unknown-version or otherwise disagrees about restore identity.
- A caller tries to serialize, clone, transfer or submit a prepared marker to an
  adapter.
- A debug string, metric, fixture or evidence artifact is seeded with plan content,
  native paths, identifiers, digests, pre-image bytes or provider diagnostics.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The feature MUST accept only a deliberately consumed `EligiblePlanV1` as
  its positive input. An authentic envelope, replay receipt, plan identifier, prior
  status row or caller-supplied boolean MUST NOT substitute for that marker.
- **FR-002**: The feature MUST define a versioned, read-only preparation projection for
  the authenticated target precondition, recovery profile, verification predicate and
  budget fields needed by the coordinator. This addition MUST NOT change plan-v1 wire
  bytes, canonical identity, signatures or existing fixtures.
- **FR-003**: Preparation inputs, contexts, receipts, outcomes and persisted records MUST
  use closed version rules. Unknown or incompatible versions, fields, enum values or
  contract combinations MUST deny before preparation authority is created.
- **FR-004**: A positive prepared result MUST be opaque, non-transferable and
  non-serializable, with no public constructor. It MUST NOT be approval evidence, an
  execution grant, an adapter input or permission to produce an effect.
- **FR-005**: No effect adapter may depend on or accept the preparation marker, budget
  receipt, recovery receipt, preparation event or durable `PREPARING` record.
- **FR-006**: All common preparation values MUST be platform-neutral and explicit. They
  MUST NOT contain native absolute paths, platform handles, floating-point amounts,
  ambient clocks, callbacks, process-global providers or agent-constructed trusted
  facts.
- **FR-007**: `PreparationContextV1` MUST be a closed five-state result: `Ready`,
  `Unavailable`, `Incomplete`, `Torn` or `Unsupported`. Negative states MUST carry no
  dummy trusted record or provider diagnostic and MUST map exactly to
  `PREPARATION_CONTEXT_UNAVAILABLE`, `PREPARATION_CONTEXT_INCOMPLETE`,
  `PREPARATION_CONTEXT_TORN` or `PREPARATION_CONTEXT_UNSUPPORTED`, respectively.
  `PREPARATION_VERSION_UNSUPPORTED` is distinct and applies only when an API, contract,
  value or persisted version is not v1. A ready context bound to the exact plan and
  operation MUST contain the closed context/identity, capture/time, supervisor, signer,
  workload, lease, authorization, policy, catalogue, capability/freshness, replay,
  budget and recovery-provider-or-irreversibility groups. A missing group is
  `Incomplete`, contradictory samples are `Torn`, and recognized v1 wiring unable to
  provide the required comparison/guard semantics is `Unsupported`.
- **FR-008**: Final comparison MUST cover every carried eligibility binding: capture,
  clock and plan-deadline generations; admission state; boot, instance and fencing
  epochs; signer trust and key fingerprint; workload, lease, authorization, policy,
  catalogue and capability generations/digests; and the exact replay claim identifier,
  generation and binding digest.
- **FR-009**: Replay comparison MUST verify the exact permanent claim row and receipt
  for this plan. It MUST NOT require equality with a global latest-claim generation that
  unrelated operations may legitimately advance.
- **FR-010**: Final comparison MUST recheck `now < effective UTC expiry`,
  `now_monotonic < effective boot deadline` and capability freshness immediately before
  the durable transition. Equality with an exclusive bound MUST deny.
- **FR-011**: Recovery-material work MUST begin only after a complete preliminary
  comparison succeeds and MUST be followed by a complete new final comparison. The
  preliminary result MUST NOT be reused as proof that the plan remains current.
- **FR-012**: The final authority comparison and creation of `PREPARING` MUST form one
  serialized compare-and-transition boundary. Every mutable signer, workload, lease,
  authorization, policy, catalogue, capability and supervisor source MUST either be
  compared inside the coordinator transaction by authoritative generation or supply a
  short-lived, non-transferable compare guard that prevents a conflicting change until
  commit. Guards MUST be acquired in a fixed order, expire within the caller deadline
  and be revocable by PAUSE or HALT so a control action forces denial rather than waiting
  behind preparation. Immutable plan, replay and recovery receipts are checked by exact
  binding instead of guarded. If any source cannot provide one of these semantics,
  preparation MUST deny rather than approximate atomicity. The supervisor commit
  permit's absolute monotonic deadline MUST be the earlier of the caller deadline and
  exactly 250 ms after permit entry. Confirmed rollback MUST resolve the permit
  immediately without uncertain readback. Only a commit result explicitly classified
  as uncertain may remain in-flight for one fresh exact readback within that same
  deadline; missing classification, owner loss, process loss or deadline equality MUST
  resolve ambiguous, activate PAUSE and block permit reuse.
- **FR-013**: A changed, expired, paused, unavailable or non-comparable binding MUST
  create no new operation or budget reservation. The existing replay claim remains
  permanent, and reuse of the old signed plan MUST NOT become eligible again.
- **FR-014**: Nonpositive outcomes MUST follow one documented first-failure order:
  context health; time, boot and supervisor state; remaining eligibility bindings;
  operation identity; budget authority; recovery evidence; then durable-store outcome.
  The exact field/fault-to-code table in the authority comparison contract is
  normative, and concurrent timing MUST NOT change the code for a fixed captured case.
  Every call MUST select exactly one top-level class: `Denied` is a definite
  pre-transition authority, version, binding, identity, capacity or evidence refusal;
  `Failed` is a definite nonpositive operational result after recovery work or store
  entry begins; and `Ambiguous` means recovery publication or coordinator commit cannot
  be classified definitely. A stable public code belongs to exactly one class. No
  class returns a marker; ambiguity permits no automatic retry, release or retirement;
  and raw provider, SQLite, OS or transport errors never select or cross classes.
- **FR-015**: Signed budget fields MUST be treated as requested upper bounds, not as
  reservation evidence. A trusted budget authority MUST produce the only positive
  reservation receipt.
- **FR-016**: Version 1 MUST reserve the signed maximum cost in integer micro-units,
  action count and egress-byte limit, plus the plan's recovery-byte capacity. It MUST
  NOT claim to reserve file-count, concurrency, duration or other dimensions absent
  from the current signed authority.
- **FR-017**: Reservation MUST verify the exact reservation identifier, operation, plan,
  task lease, currency, price-table identity and authoritative budget generation. A
  mismatch, missing price table or unavailable authority MUST deny.
- **FR-018**: Budget arithmetic MUST be checked and exact: an aggregate exactly at every
  limit MUST be accepted when all other conditions match; one unit beyond any limit,
  underflow, overflow or negative-style alternate encoding MUST deny without a partial
  reservation.
- **FR-019**: One reservation identifier MUST bind permanently to one exact operation,
  plan and budget vector for its lifecycle. Concurrent or later conflicting reuse MUST
  return a binding conflict and MUST NOT mutate either reservation. Reservations for
  distinct operations MUST also serialize against their shared authoritative allowance
  so their committed aggregate never exceeds any dimension.
- **FR-020**: The budget reservation and `PREPARING` operation MUST commit together.
  Definite pre-commit failure leaves both absent; possible commit requires exact
  readback and MUST NOT trigger blind reservation retry or double release.
- **FR-021**: A known pre-dispatch failure or operator cancellation MUST reconcile a held
  reservation through one durable, idempotent `PREPARING -> FAILED` transition while
  holding an opaque sovereign no-dispatch guard through commit. The guard MUST be issued
  by trusted supervisor/dispatch-authority wiring, bind the exact operation,
  preparation attempt, current state generation, boot/instance/fencing epochs and
  revocation generation, and prove that no grant, dispatch transition or in-flight
  dispatch authority exists. A caller assertion, copied boolean or observed row absence
  MUST NOT substitute. Missing, mismatched, expired, unavailable or revoked proof MUST
  leave both operation and reservation unchanged. A successful transition releases no
  more than the exact stored held amount once; replay state remains claimed.
- **FR-022**: A compensable plan MUST have create-only recovery material that is durable,
  published, hash-verified and backed by at least the signed reserved byte count before
  a positive prepared result exists. The active recovery provider's evidence class and
  capability binding MUST be approved for the deployment profile. A deterministic or
  synthetic provider may establish protocol conformance only and MUST NOT establish a
  production compensable-preparation claim.
- **FR-023**: A recovery receipt MUST bind its version, provider and generation, plan and
  operation identities, target reference, precondition identity/digest/length,
  recovery class and atomicity, actual material digest/length, reserved capacity,
  publication state, and applicable boot/instance/fencing epochs.
- **FR-024**: Recovery receipts and material identifiers MUST be immutable and
  content-bound. Missing, temporary, extra, stale, truncated, corrupted, substituted
  or differently bound material MUST deny preparation.
- **FR-025**: An irreversible plan MUST already carry the required L2 classification,
  MUST explicitly record that no compensation material exists, and MUST NOT receive a
  fabricated pre-image or recovery receipt that implies rollback.
- **FR-026**: Recovery failure MUST NOT silently downgrade compensation to
  irreversibility, reduce reserved capacity, change the target or bypass the final
  comparison. A profile/version/binding/irreversibility mismatch MUST be a recovery
  `Denied` code. A provider result definitively proving create, durability or
  publication failure MUST be `Failed(PREPARATION_RECOVERY_UNAVAILABLE)`. A missing,
  untrusted or unclassifiable provider result MUST be
  `Ambiguous(PREPARATION_AMBIGUOUS)` and quarantine possible material. Every result
  requires a new plan or operator action and permits no immediate retirement.
- **FR-027**: Recovery preparation and retirement MUST be idempotent by exact operation,
  plan and material identity. Final commit MUST hold a recovery-publication guard and
  MUST revalidate present, published and non-retired material while holding it;
  retirement MUST hold a mutually exclusive cleanup guard. Operation-bound material
  may retire only after the matching operation is durably `FAILED` and its budget is
  exactly reconciled. For a true pre-commit orphan, one healthy definitive readback
  under the cleanup guard MUST prove that no committed, in-flight or ambiguous
  operation, attempt, reservation, event or active quarantine can reference the
  material; maintenance MUST then commit a permanent orphan-resolution tombstone before
  provider retirement and MUST NOT fabricate an operation. Temporary absence or any
  ambiguity MUST retain quarantine, and material alone MUST never imply an operation.
- **FR-028**: The durable operation record MUST bind the exact canonical signed plan,
  operation/task/workload identities, state and state generation, boot/instance/fencing
  epochs, effective deadlines, complete comparison vector, replay receipt, budget
  receipt, recovery receipt or explicit irreversibility evidence, and preparation-event
  identity.
- **FR-029**: The exact canonical signed plan and its content MUST remain available from
  restricted durable operation state after restart and clean restore. An external
  reference is acceptable only if its immutable bytes and availability are verified as
  part of the same recovery and backup contract.
- **FR-030**: The canonical positive coordinator commit set MUST consist exactly of
  eight logical members in one SQLite commit: advance the enclosing store/operation/
  budget/event generations; insert the `PREPARING` operation; append the permanent
  `ABSENT -> PREPARING` transition; insert exact comparison/replay evidence; apply the
  exact budget-scope held-vector delta; insert the `HELD` reservation; insert either the
  immutable recovery reference or exact irreversibility evidence; and insert one
  `PREPARED/PENDING` event. All eight MUST become visible or none may become visible.
  External recovery bytes, replay-store state and supervisor state are not members of
  this coordinator transaction.
- **FR-031**: External recovery storage, the supervisor fencing store and coordinator
  state MUST be treated as separate durability domains. The feature MUST define receipt,
  guard, readback and reconciliation rules and MUST NOT claim one implicit transaction
  across them. Compare guards protect freshness or cleanup exclusion only; they MUST NOT
  be described as making independent stores transactionally atomic.
- **FR-032**: Exactly one contender may create the first `PREPARING` record for an
  operation. Exact readback returns the existing coherent record; any different plan,
  replay, budget or recovery binding returns conflict without overwrite.
- **FR-033**: Coordinator commit observation MUST be closed and non-overlapping:
  acknowledged commit, confirmed rollback, explicit `UNCERTAIN`, or missing/untrusted
  classification. Acknowledged commit may produce `Prepared` only after final
  guard/deadline validation. Confirmed rollback MUST resolve the permit aborted
  immediately, perform zero readback and return
  `Failed(PREPARATION_STORE_COMMIT_ABORTED)`. Only explicit `UNCERTAIN`, including lost
  acknowledgement, may keep the permit `COMMIT_IN_FLIGHT` for exactly one fresh bounded
  readback. Missing/untrusted classification MUST immediately return
  `Ambiguous(PREPARATION_AMBIGUOUS)`, activate PAUSE and perform zero worker readback.
  Readback after explicit `UNCERTAIN` maps exactly: `THIS_ATTEMPT -> Prepared` only
  while still valid; `PRIOR_EXACT_ATTEMPT ->
  Denied(PREPARATION_ALREADY_PREPARED)`; a healthy coherent conflicting occupant ->
  `Denied(PREPARATION_OPERATION_CONFLICT)`; `DEFINITE_ABSENCE ->
  Failed(PREPARATION_STORE_DEFINITE_ABSENCE)`; and unavailable, partial, inconsistent,
  late or revoked proof -> `Ambiguous(PREPARATION_AMBIGUOUS)`. Definite absence never
  revives or retries the consumed plan and never authorizes immediate recovery
  retirement; published material still follows the permanent true-orphan protocol.
- **FR-034**: Operation state MUST be monotonic and append-evidenced. The only operation
  transitions introduced by this feature MUST be creation in `PREPARING` and
  `PREPARING -> FAILED` before dispatch. It MUST NOT create `DISPATCHING`, an execution
  grant, a dispatch outbox item, an adapter receipt, an effect result, settlement or
  compensation execution.
- **FR-035**: Opening or maintaining preparation state MUST verify the reviewed
  application/schema identity, durability profile and cross-record invariants. Unknown,
  newer, rolled-back, altered, corrupt, read-only or weaker state MUST fail closed
  without repair during admission.
- **FR-036**: Controlled fault and crash testing MUST cover every comparison, recovery
  creation/durability/publication, budget reservation, coordinator commit, event
  publication, readback, cancellation and cleanup boundary. Reopen MUST prove no state,
  one coherent state or explicit quarantine, never a false positive. The closed,
  exhaustive v1 boundary inventory in Durable Preparation Contract section 14 is
  normative; a new boundary requires a contract and frozen-corpus change.
- **FR-037**: Backup and clean restore MUST preserve a coherent manifest of operation,
  budget, recovery and preparation-event generations without claiming a simultaneous
  snapshot of independent stores. Both authoritative pending-retirement counts—
  operation-bound and true-orphan—MUST equal zero, agree with provider enumeration and
  the recovery inventory's `no_retirement_pending=true`, and be encoded as zero in the
  top-level manifest. Its digest MUST be lowercase SHA-256 of the exact RFC 8785 UTF-8
  bytes of the complete top-level object, with no BOM, prefix or trailing newline.
  After publishing the top-level manifest, backup MUST
  publish as the package's final publication point one detached, closed-version
  provenance attestation signed through an approved provisioner-owned profile. The
  attestation MUST bind the exact canonical top-level manifest digest, opaque source
  root/instance identity, coordinator and recovery generations, at-rest protection
  profile and attestation profile/key identity without exposing signing key material.
  Restore MUST verify this attestation against pinned trusted configuration before
  publishing either destination root, then persist a closed restore identity and
  `RESTORE_PENDING` independently in both coordinator-root and recovery-root metadata.
  Missing, unknown, revoked or mismatched attestation, member, lifecycle state or
  restore identity MUST quarantine the restore; internally consistent digests alone
  MUST NOT establish provenance.
- **FR-038**: Both restored roots MUST remain `RESTORE_PENDING` while the supervisor is
  paused and new boot, instance and fencing epochs are established. Ordinary open,
  prepare and recovery-retirement paths MUST deny on either pending root; only bounded
  restore-validation and old-authority reconciliation operations may inspect or mutate
  them. Restored `PREPARING` operations and reservations remain non-dispatchable and
  MUST NOT be rebound or activated under the new authority. Reconciliation MUST move
  each old preparation to a terminal failed/quarantined disposition and reconcile its
  resources, but this feature MUST NOT transition either root to active. A later
  activation feature and a newly authorized signed plan plus replay claim are required.
  The Feature 004 public surface MUST expose at most bounded, payload-free, redacted
  read-only verification evidence types, with no public producer. Restore validation,
  old-authority reconciliation, quarantine and every operation requiring PAUSE/fencing,
  recovery, trust/revocation or no-dispatch authority MUST remain crate-internal, with
  no public authority constructor or factory. A later host feature MUST specify, own
  and test those sovereign authorities before it may expose a maintenance or activation
  facade.
- **FR-039**: Public errors, debug output, metrics, fixtures, audit events and evidence
  MUST use bounded stable codes and counts and MUST NOT expose canonical plan content,
  replacement or pre-image bytes, native paths, identifiers, nonces, digests, budget
  values tied to a user, or raw provider diagnostics.
- **FR-040**: Recovery material and canonical plan content MUST be classified at least as
  restrictively as the source data, retained only under an explicit lifecycle policy,
  unavailable to agent/model workloads and excluded from Graphify memory and egress.
- **FR-041**: One versioned positive and single-fault conformance corpus MUST exercise
  fresh comparison, budget, recovery, contention, ambiguity, cancellation, backup,
  restore and redaction without modification across required platforms.
- **FR-042**: Controlled performance evidence MUST separate final comparison and
  coordinator commit latency from external recovery-material transfer time, record raw
  samples and environment, and bound all lock waits by caller-owned monotonic deadlines.
- **FR-043**: The feature MUST register `PLAN-004` with contract, corpus, toolchain,
  platform, restore, supply-chain, performance and pending external-evidence fields. It
  MUST NOT change the claim status of PLAN-001, PLAN-002 or PLAN-003.
- **FR-044**: Dependencies, schemas and native artifacts MUST be pinned and reviewed;
  rollback/refusal, removal and clean-restore procedures MUST be documented. Removing
  this feature MUST leave PLAN-001 wire bytes, PLAN-002 eligibility semantics, PLAN-003
  replay rows and the legacy MVP-0 pipeline unchanged.

### Key Entities

- **Preparation Context**: One complete trusted, plan-bound snapshot and short-lived
  final comparison guard covering every authority fact required before `PREPARING`.
- **Plan Preparation Claims**: A read-only projection of exact authenticated
  precondition, recovery, verification and budget facts without changing plan wire
  identity.
- **Budget Reservation Record**: The authoritative held upper bounds for one operation,
  including binding, lifecycle, generation and exact release accounting.
- **Budget Reservation Receipt**: Opaque positive evidence that the exact declared bounds
  were reserved once; it is not spend or dispatch authority.
- **Recovery Material Record**: Sensitive create-only material or explicit
  irreversibility evidence retained by a trusted provider and bound to one plan and
  operation.
- **Recovery Material Receipt**: Opaque immutable evidence of verified, durable and
  sufficiently reserved recovery material; it is not compensation authority.
- **Prepared Operation Record**: Authoritative durable operation state in `PREPARING`,
  bound to the canonical plan, comparison vector, replay, budget, recovery and event
  evidence.
- **Prepared Operation Marker**: Opaque in-process custody of one coherent prepared
  operation for a future coordinator transition; never transferable to an adapter.
- **Preparation Event**: Transactionally recorded, redacted evidence that a preparation
  transition or pre-dispatch failure occurred; future audit delivery cannot authorize an
  effect.
- **Preparation Outcome**: Closed prepared, denied, failed or ambiguous result whose
  public surface contains no trusted values.
- **Restore Root State**: Closed durable metadata held independently by the coordinator
  and recovery roots, binding one restore identity and lifecycle state. Feature 004 can
  create and validate `RESTORE_PENDING` but cannot activate it.
- **Restore Verification Evidence**: Bounded, payload-free and redacted read-only facts
  about a verified pending restore. It carries no PAUSE, fencing, recovery,
  trust/revocation, quarantine, no-dispatch, reconciliation or activation authority.
- **No-Dispatch Authority Guard**: Opaque, non-transferable sovereign custody bound to
  one preparation attempt, current operation generation and authority epochs. It is
  retained across known-failure commit and cannot be reconstructed from database
  absence or an operator assertion.
- **Backup Provenance Attestation**: Detached, closed-version signature evidence
  produced by an approved provisioner-owned signing profile over the exact canonical
  top-level backup manifest digest and its source/generation/protection bindings. It is
  the final package publication point and carries no raw key material.

### In Scope

- A non-wire preparation projection over the existing signed plan.
- Fresh comparison of every PLAN-002 binding without a second replay claim.
- Exact reservation of plan-v1 cost, action, egress and recovery-byte bounds.
- Portable recovery-provider and supervisor-guard contracts with deterministic test
  implementations.
- Durable operation state through coherent `PREPARING` and known pre-dispatch failure.
- A transactional preparation event for future audit delivery.
- A bounded, payload-free public read-only evidence type surface for verified pending
  restore state, with no public producer; all authority-bearing restore maintenance
  remains crate-internal.
- Crash, ambiguity, contention, redaction, backup, restore, performance and removal
  evidence.

### Out of Scope

- Broader file-count, concurrency or duration quotas not present in current signed
  authority; adding them requires a later lease or plan contract version.
- `DISPATCHING`, execution-grant creation/signing, dispatch transport, adapter inbox or
  receipt, target effects and idempotency at an effect provider.
- Real macOS/Linux/Windows target resolution, file precondition re-probe or patch
  execution; this feature uses a portable recovery-provider contract only.
- Production compensable preparation until a real platform recovery provider has
  retained durability, corruption, backup and clean-restore evidence for its declared
  profile. The synthetic provider proves protocol behavior only.
- Post-effect verification, settlement, actual cost reconciliation, compensation
  execution and effect reconciliation.
- WebAuthn, approval UI and authorization-provider implementation.
- A public sovereign host-maintenance or activation facade, supervisor/fencing-store
  implementation and leadership election; the feature consumes trusted authorities,
  keeps restore paused and exposes no constructor or factory for those authorities.
- Egress/provider pricing calls, secret use, knowledge projection or agent memory.
- Migration of the legacy in-memory/JSONL MVP-0 pipeline.
- APFS snapshots, `F_FULLFSYNC`, sector-loss or power-cut/power-loss claims.
- Full clean-machine restore or activation of replay, supervisor, policy, catalogue,
  audit-checkpoint, key or broader runtime state. Feature 004 proves only a clean-root
  coordinator/recovery subsystem restore and leaves the constitutional clean-machine
  gate pending.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of coherent positive corpus cases produce exactly one durable
  `PREPARING` operation whose plan, comparison, replay, budget, recovery and event
  evidence all match after complete process restart, with zero dispatch calls.
- **SC-002**: Changing each bound generation, digest, deadline, boot, epoch or authority
  decision independently produces its declared first denial in 100% of cases and
  creates zero operation, budget or preparation-event mutation.
- **SC-003**: Across at least 100 rounds with 64 synchronized threads and 20 rounds with
  8 synchronized processes, each contested operation produces exactly one coherent
  `PREPARING` record, one budget reservation and one preparation event.
- **SC-004**: Exact-limit, minus-one and plus-one tests plus at least 100,000 generated
  budget vectors complete without overflow, partial reservation, double reservation,
  double release or aggregate use above any supported limit. This includes concurrent
  distinct operations whose individual requests fit but whose sum does not. Every
  failure-release case lacking an exact live no-dispatch guard leaves the held vector
  and operation state unchanged.
- **SC-005**: 100% of missing, undersized, truncated, corrupt, unpublished, substituted,
  stale and differently bound recovery cases are denied; every compensable positive
  case verifies exact material hash, length and capacity within its declared provider
  profile, and every irreversible positive case remains explicitly L2 with no
  compensation claim. Synthetic results are labeled conformance-only and never
  production recovery evidence.
- **SC-006**: Process termination at every declared preparation boundary always reopens
  to no committed operation, one invariant-valid operation or explicit quarantine. No
  ambiguous case returns a positive marker or definite-absence result.
- **SC-007**: A clean backup with an exact valid detached provenance attestation and
  restore reproduces 100% of committed operation, budget, recovery-manifest and
  preparation-event evidence, uses externally supplied trusted PAUSE and rotated-epoch
  custody to start both roots in `RESTORE_PENDING`, and makes zero restored operation
  dispatchable. Every missing, altered, unknown-key/profile, revoked or coherently
  substituted attestation case is rejected before either root is published.
- **SC-008**: The unchanged corpus produces byte-identical case IDs, stable outcome
  summaries and fixture/schema digests on macOS arm64, Linux x64 and Windows x64.
- **SC-009**: On the physical Mac mini M4 controlled target, after 500 warmups at least
  10,000 sequential final-compare plus durable-preparation samples have p95 at or below
  25 ms and p99 at or below 100 ms. The retained `PLAN-004` artifact records exact
  hardware, OS/build/architecture, toolchain/runtime, storage assurance, durability
  profile, corpus and digest, concurrency, raw samples, source commit, artifact path and
  SHA-256. Recovery-material transfer latency is reported separately and is not hidden
  inside or relabeled as this coordinator threshold.
- **SC-010**: At least 1,000 controlled held-writer attempts return by their caller-owned
  monotonic deadline plus at most 50 ms scheduler tolerance. After each return, the
  blocker is released, the store is observed for at least 250 ms and reopened; zero
  detached later preparation, reservation or event may appear. Permit tests also prove
  that every unresolved permit is supervisor-resolved by the earlier caller deadline or
  250 ms v1 ceiling plus at most the same 50 ms controlled scheduler tolerance, with
  PAUSE active, new permits blocked and no expired permit reusable.
- **SC-011**: Public diagnostics, fixtures and retained evidence expose zero seeded
  private native paths, identifiers, nonces, digests, canonical/replacement/pre-image
  content, user-bound budget values or provider diagnostics; reviewed public synthetic
  fixture values remain allowed. External callers obtain zero authority-bearing
  restore-maintenance operation or constructor from the Feature 004 public surface.
- **SC-012**: The feature can be removed without changing PLAN-001 canonical bytes or
  signatures, PLAN-002 outcomes, PLAN-003 replay behavior or legacy MVP-0 runtime tests.

## Assumptions

- PLAN-001 signed plan-v1, PLAN-002 eligibility and PLAN-003 durable replay semantics are
  frozen dependencies. Feature 004 adds a non-wire preparation projection rather than
  changing their existing identities or fixtures.
- The trusted coordinator owns the operation and budget authority. A complete final
  comparison token covers sources stored in the coordinator transaction. Every other
  mutable authority source supplies a fixed-order, short-lived non-transferable guard
  across the commit boundary; PAUSE or HALT can revoke it and force denial.
- The supervisor persists and resolves commit-permit owner tokens independently of the
  preparation process. The fixed v1 permit ceiling is 250 ms and is shortened, never
  extended, by the caller's absolute monotonic deadline.
- Known-failure reconciliation obtains a separate sovereign no-dispatch guard from
  trusted supervisor/dispatch-authority wiring and holds it through the failure commit.
  Feature 004's deterministic provider may prove the structural absence of any dispatch
  implementation for conformance, but no caller or database-absence observation may
  create this proof.
- Version 1 reserves only signed plan-v1 cost, action and egress limits plus recovery
  bytes. Other constitutional budget dimensions remain mandatory before relevant
  future effects but cannot be claimed without new signed authority.
- The portable R1 slice uses a deterministic recovery provider and synthetic material
  for protocol conformance only. Real host pre-image capture and effect precondition
  checks belong to a later platform slice, and no production compensable-preparation
  claim is made until that provider has its own durability and clean-restore evidence.
- External recovery material is fully published and verified before the coordinator
  transaction. The coordinator stores its immutable receipt; no global transaction
  across recovery storage, supervisor storage and operation state is claimed.
- A crash after replay claim but before an exact `PREPARING` record requires orphan
  reconciliation and a new signed plan. Cleanup and final commit use mutually exclusive
  recovery guards; ambiguous material is quarantined rather than deleted. Definitively
  absent material can retire only after a permanent orphan-resolution tombstone, while
  operation-bound material requires durable `FAILED` plus exact budget reconciliation.
  A coherent existing `PREPARING` record is recovered by operation identity, never by
  replaying eligibility.
- Restored nonterminal preparation is historical evidence only. It is terminally failed
  or quarantined under the old authority and can never be rebound to rotated epochs.
  Both restored roots persist the same restore identity in independent
  `RESTORE_PENDING` metadata; disagreement quarantines the restore, and activation is a
  later feature.
- Restricted operation state retains the exact canonical signed plan needed after
  restart. Fixtures contain only public synthetic content; production retention and
  protection follow the source data classification.
- Backup signing is a typed use of a provisioner-owned signing profile. Raw private key
  material never enters the feature API, package or restored roots; restore receives a
  pinned trust configuration rather than an agent-selected verifier.
- The initial profile is single-user and has no network egress or secret use in this
  feature.
- Process-crash evidence is not power-loss evidence. Tier 1 and host-effect claims remain
  blocked until the separate durability, dispatch, adapter, restore and hardware gates
  pass.
- The feature's clean-root restore artifact covers only coordinator and recovery roots;
  it is necessary subsystem evidence but does not satisfy the full clean-machine restore
  requirement or activate a system.

## Constitution Constraints *(mandatory)*

- **Boundary and authority**: The untrusted agent may propose a plan but cannot create a
  preparation context, budget receipt, recovery receipt, compare guard or prepared
  marker. The only new authority is core-owned reservation and durable preparation for
  a later transition. Stale-generation races, forged/torn receipts, reservation-ID
  reuse and attempted adapter consumption are mandatory negative cases.
- **Durability and recovery**: Recovery material, supervisor fencing and coordinator
  state are separate durability domains joined by immutable receipts, a final compare
  guard, exact readback and reconciliation. Possible commit is ambiguous, never retried
  blindly. No host effect exists, and restore remains paused and non-dispatchable.
- **Data and secrets**: Canonical plan and recovery material are restricted operational
  data classified at least as strongly as the source. They never reach agent/model
  workloads, egress, fixtures, logs or Graphify memory. No credential or raw secret use
  is introduced.
- **Portability**: Contracts use opaque resource references, bounded identifiers,
  fixed digests, safe integers and explicit time values only. Unsupported compare,
  recovery or durability semantics deny; one unchanged corpus is required across
  macOS, Linux and Windows.
- **Performance and budgets**: Cost, action, egress and recovery-byte reservations are
  exact and checked. SC-003, SC-004, SC-009 and SC-010 define contention, robustness,
  target latency and deadline evidence with recovery transfer reported separately.
- **Audit and lifecycle**: Every preparation transition has one transactional redacted
  event, versioned schemas, pinned inputs and retained evidence. Supply-chain review,
  rollback refusal, feature-local clean-root backup/restore, pre-dispatch failure and
  removal are required before Feature 004 completion. Full clean-machine restore and
  activation remain later system/Tier 1 gates and are not claimed here.
