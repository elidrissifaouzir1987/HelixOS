# Feature Specification: Durable One-Shot Dispatch

**Feature Branch**: `codex/plan-005-durable-dispatch`

**Created**: 2026-07-12

**Status**: Implementation and immutable software evidence complete; physical and
external evidence pending

**Input**: User description: "Continue after PLAN-004 by implementing the next bounded architecture slice: move one current prepared operation to durable dispatch with a short signed ExecutionGrant, a durable one-shot adapter inbox, and a recoverable signed receipt, without performing a real host effect."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Dispatch One Prepared Operation Once (Priority: P1)

As the operator of HelixOS, I want an already prepared and authorized operation to
produce exactly one bounded dispatch authority so that no adapter can act from an
unpersisted, stale, broadened, or duplicated instruction.

**Why this priority**: Dispatch is the first point where prepared authority can leave
the coordinator. If this boundary is not durable and one-shot, later effect handling
cannot make an honest replay or recovery claim.

**Independent Test**: Start with one coherent current prepared operation and request
dispatch repeatedly and concurrently. The system produces one dispatch record and one
grant identity, delivers only the exact retained grant, and never authorizes a second
operation or a broader action.

**Acceptance Scenarios**:

1. **Given** one current prepared operation with matching authority, held budget,
   recovery evidence, epochs, and destination, **When** dispatch is requested, **Then**
   one short signed grant is bound to the exact operation and the durable operation
   enters dispatching before any delivery is attempted.
2. **Given** the same prepared operation is requested concurrently by many callers,
   **When** the requests race, **Then** all successful observations identify the same
   grant and only one dispatch transition exists.
3. **Given** a prepared operation whose lease, policy, capability, destination,
   supervisor epoch, deadline, or recovery binding changed, **When** dispatch is
   requested, **Then** no grant is created or delivered and the refusal identifies the
   stale authority class without exposing sensitive values.

---

### User Story 2 - Consume a Grant Once and Recover Its Receipt (Priority: P1)

As the operator, I want the trusted adapter boundary to durably accept and consume a
valid grant once, returning the same signed receipt after retries, so that a lost
response or process restart cannot cause duplicate execution authority.

**Why this priority**: A durable coordinator transition alone cannot prevent replay at
the adapter. The inbox and receipt are the independent second half of the one-shot
protocol required before any future host effect.

**Independent Test**: Deliver the same valid grant before and after adapter restarts,
drop acknowledgements at every protocol boundary, and verify that one inbox item, one
consumption result, and one recoverable receipt exist with no second consumption.

**Acceptance Scenarios**:

1. **Given** a valid current grant and a matching independently observed supervisor
   epoch, **When** the adapter accepts it, **Then** the adapter durably records the grant,
   consumes it once, and retains a signed receipt before exposing acceptance.
2. **Given** the same grant and digest arrive again, **When** the adapter has already
   accepted or consumed it, **Then** the adapter returns the retained result and never
   consumes the authority a second time.
3. **Given** the same grant identity arrives with different bytes or a different digest,
   **When** the adapter compares it with its retained inbox entry, **Then** it refuses the
   conflict, preserves evidence, and authorizes no execution.
4. **Given** the response is lost after durable consumption, **When** the coordinator
   retries or performs readback, **Then** it recovers the original receipt and advances
   only from evidence bound to the exact dispatch record.
5. **Given** the adapter returns a signed definite refusal and transport is proven
   fenced with no consumption in flight, **When** the coordinator reconciles the
   dispatch, **Then** it follows the normative unknown/reconciliation path to durable
   failure, releases the exact held reservation once, and never retries the grant.
6. **Given** the same prepared operation is requested exactly 10,000 times, then in 100
   rounds of 64 concurrent threads and 20 rounds of 8 concurrent processes, **When**
   each retained grant is delivered through the adapter boundary, **Then** the complete
   dispatch-to-inbox matrix observes exactly one adapter consumption and zero duplicate
   consumptions.
7. **Given** validation fails before the adapter has durably entered `RECEIVED`, **When**
   the reason is `DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`,
   `CAPABILITY_MISMATCH` or `INBOX_CAPACITY_EXHAUSTED`, **Then** the adapter retains a
   redacted diagnostic or quarantine record, emits no receipt, and that record alone
   cannot prove safe reservation release.

---

### User Story 3 - Fail Closed Across Crashes and Ambiguous Transport (Priority: P2)

As an incident responder, I want every crash and transport ambiguity to produce a
deterministic recoverable state so that HelixOS never reports a mutation as blocked or
blindly generates a replacement grant when acceptance may have occurred.

**Why this priority**: Honest ambiguity handling prevents duplicate authority and false
success during the most operationally dangerous boundary in the lifecycle.

**Independent Test**: Inject a crash before and after every durable transition, send,
inbox write, consumption step, receipt write, and readback. Recovery yields either
definite pre-dispatch failure, the one retained grant and receipt, or an explicit
unknown/reconciliation-required outcome; it never creates a new grant silently.

**Acceptance Scenarios**:

1. **Given** the coordinator fails before the dispatch transition commits, **When** it
   restarts, **Then** no grant is deliverable and the operation remains prepared or is
   closed by the existing proved no-dispatch failure path.
2. **Given** the dispatch transition committed but delivery status is unknown, **When**
   recovery runs, **Then** only the exact retained grant may be queried or redelivered;
   no replacement identity or broader authority is created.
3. **Given** the system cannot prove adapter acceptance or definite absence before the
   bounded deadline, **When** recovery concludes, **Then** the operation becomes
   explicitly unknown and requires reconciliation rather than automatic execution.
4. **Given** a receipt is missing, malformed, unsigned, late, or bound to another grant,
   **When** it is evaluated, **Then** it cannot advance the operation and the incident is
   retained as bounded redacted evidence.
5. **Given** one delivery attempt may have handed off, **When** automatic readback
   starts, **Then** exactly one sequence makes at most four observations at offsets 0,
   25, 100 and 275 ms, ends no later than 500 ms after its first observation or an
   earlier caller/grant deadline, and never starts an automatic replacement sequence.
6. **Given** the adapter retained a signed receipt before grant expiry, **When** that
   receipt is recovered after expiry, **Then** it remains verifiable as evidence of the
   earlier decision without renewing or recreating authority.

---

### User Story 4 - Restore and Remove Dispatch Safely (Priority: P3)

As the maintainer, I want backup, clean restore, upgrade, and removal behavior for the
dispatch protocol to preserve one-shot authority so that old grants cannot become live
again and the feature can be retired without damaging earlier PLAN guarantees.

**Why this priority**: Grant replay after restore or partial removal would bypass the
same fencing and recovery guarantees that the feature is intended to add.

**Independent Test**: Back up coordinator and adapter state at every dispatch phase,
restore into a clean paused instance with rotated epochs, and remove the feature from an
isolated copy. No old grant becomes dispatchable, ambiguous items remain quarantined,
and PLAN-001 through PLAN-004 behavior remains intact.

**Acceptance Scenarios**:

1. **Given** a backup containing prepared, dispatching, accepted, consumed, or ambiguous
   records, **When** it is restored into a clean instance, **Then** the instance starts
   paused, old grants remain non-executable, and each possible effect requires explicit
   reconciliation.
2. **Given** a compatible upgrade, **When** retained grants and receipts are read, **Then**
   their signatures, versions, identities, and history remain verifiable without
   reissuing authority.
3. **Given** the feature is removed from an isolated source and state copy, **When** the
   removal drill completes, **Then** earlier plans, contracts, preparation records, and
   protected files remain valid and no dispatch artifact is mistaken for executable
   authority.

### Edge Cases

- The grant expires between durable creation and first delivery.
- The supervisor epoch changes between coordinator validation and adapter consumption.
- The adapter receives a validly signed grant for an unknown protocol, verb,
  destination, workload, schema version, key, or algorithm.
- The coordinator and adapter disagree about the grant digest, operation generation,
  reservation, recovery evidence, or capability snapshot.
- The adapter store is busy, full, unavailable, corrupt, or only partially restored.
- A receipt is durable but its acknowledgement is lost indefinitely.
- A malicious caller floods duplicate grants or colliding grant identifiers.
- A restored adapter contains an inbox entry that the restored coordinator cannot bind
  to one authoritative dispatch transition.
- Wall time moves backward, the monotonic boot identity changes, or the deadline is
  reached exactly at an exclusive boundary.
- Dispatch cancellation races with grant delivery or receipt readback.
- Audit delivery is unavailable before dispatch or becomes unavailable after possible
  adapter acceptance.
- A preparation created by an older instance or restored root appears structurally
  valid but is not authorized under the current epoch.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST accept dispatch input only from one authoritative current
  prepared operation whose plan, replay claim, reservation, recovery evidence,
  preparation event, authority versions, deadlines, and epochs remain mutually bound.
- **FR-002**: The system MUST refuse every restored, quarantined, failed, already
  dispatching, stale-instance, or otherwise non-current prepared operation. A restored
  `PREPARING` record is historical and MUST never be rebound, resumed, or dispatched.
  Recovery MAY reconcile an already-retained dispatch record but MUST NOT revive
  preparation authority.
- **FR-003**: The system MUST define a versioned `ExecutionGrant` contract with canonical
  bytes, a collision-resistant digest, a signature domain, key and algorithm identity,
  strict unknown-field/version handling, and cross-platform golden fixtures.
- **FR-004**: Each grant MUST bind the grant and dispatch-attempt identities, operation
  identity and current state generation, preparation attempt and transition generation,
  plan, intent, typed arguments, task, lease, workload, destination adapter, protocol,
  capability and policy snapshots, reservation, recovery reference, boot identity,
  instance and supervisor epochs, issue time, exclusive deadline, and one-shot nonce.
- **FR-005**: A grant MUST be monotonically no broader than the prepared plan and lease;
  dispatch MUST fail closed if any bound cannot be compared exactly.
- **FR-006**: Exactly one grant identity and digest MAY be associated with an operation.
  A repeated or concurrent request MUST return the same retained identity or a stable
  closed outcome.
- **FR-007**: The exact canonical signed grant bytes, grant identity and digest, the
  transition from prepared to dispatching, the permanent transition record, the exact
  deliverable outbox member, and the pending redacted event MUST become visible
  atomically or not at all.
- **FR-008**: No grant bytes MAY be delivered, exposed as deliverable, or accepted as
  authority before the matching dispatch transition is durable.
- **FR-009**: Signing failure, unavailable key authority, unsupported algorithm, or
  unverifiable canonical bytes MUST create no dispatchable grant.
- **FR-010**: Dispatch MUST acquire the same globally ordered current-authority guard
  classes established by PLAN-004, revalidate deadlines, boot identity, supervisor
  epoch, revocation generations, signer, workload, lease, approval, policy, catalog,
  capability, reservation, recovery, destination, and protocol, and retain a fresh
  linearizable dispatch permit across the complete signed-grant compare-and-transition
  transaction. A sample taken merely before that serialized boundary is insufficient.
- **FR-011**: Equality with an exclusive time deadline MUST refuse dispatch. An exact
  remaining capacity match MUST be accepted, while exceeding any held capacity by one
  unit MUST deny; no retry MAY extend the original time or budget authority.
- **FR-012**: The adapter MUST maintain a durable inbox keyed by grant identity and
  digest, separate from untrusted callers and from transient transport state.
- **FR-013**: Before acceptance, the adapter MUST verify the complete canonical grant,
  trusted signature, supported schema and algorithm, destination and protocol,
  operation binding, deadline, workload, capability predicates, and current supervisor
  epoch from an independent trusted source.
- **FR-014**: An unavailable, unreadable, stale, or mismatching supervisor epoch MUST
  permit zero new grant consumptions.
- **FR-015**: The adapter MUST durably insert the exact valid grant in state `RECEIVED`
  before acknowledging reception and MUST persist one-shot consumption plus its signed
  receipt before exposing an effect-authority handoff. This feature MUST expose no
  execution-token API. A later effect feature must separately specify a sealed
  adapter-internal handoff without transferring authority to the coordinator, agent,
  transport, or caller.
- **FR-016**: Re-delivery of identical grant bytes MUST return the retained state or
  receipt without repeating consumption. Grant identity, operation identity and
  one-shot nonce MUST each be create-only unique adapter keys; reuse of any one with
  conflicting bytes, digest or binding MUST fail closed and preserve conflict evidence.
- **FR-017**: The adapter MUST retain a signed, versioned `ExecutionReceipt` bound to the
  exact grant digest, adapter identity, inbox generation, consumption generation,
  observed supervisor epoch, decision, timestamp, and opaque trace identity.
- **FR-018**: Canonical grant and receipt wires MAY contain only the bounded internal
  identities and digests required by their contracts; they MUST contain no raw secret,
  native host path, unrestricted content, credential, or unbounded adapter output.
  Public logs, `Debug`, metrics and outward audit projections MUST redact all non-public
  identities and digests before serialization.
- **FR-019**: The coordinator MUST verify a receipt independently before it can advance
  dispatch state, including signature, version, grant digest, operation, destination,
  epochs, decision, and monotonic ordering.
- **FR-020**: Only a verified accepted-and-consumed receipt recovered while the exact
  operation is still `DISPATCHING` MAY advance it to `EXECUTING`. This feature MUST NOT
  perform or report a real host mutation, and `EXECUTING` therefore means only that the
  one-shot adapter authority was durably consumed for a later effect feature. Once the
  operation has entered `OUTCOME_UNKNOWN`, any later receipt is retained only through
  explicit `RECONCILIATION_REQUIRED`; PLAN-005 MUST NOT automatically return it to
  `EXECUTING`.
- **FR-021**: A definite adapter refusal before consumption MUST remain distinguishable
  from possible acceptance, and any budget release or prepared-operation failure MUST
  require proof that no consumption or in-flight authority exists.
- **FR-022**: After a committed dispatch transition, retry MUST use only the exact
  retained grant identity and bytes. The system MUST NOT mint a replacement grant,
  broaden authority, or restart from preparation silently.
- **FR-023**: When delivery or response is ambiguous, the system MUST perform bounded
  inbox/receipt readback. Each delivery attempt classified possible-handoff MUST start
  exactly one automatic readback sequence with at most four observations. The backoff
  before those observations MUST be exactly 0, 25, 75 and 175 ms, producing observation
  offsets 0, 25, 100 and 275 ms, with a hard budget ending no later than 500 ms after
  the first observation. Any earlier caller deadline or grant deadline truncates the
  sequence. A receipt already retained before expiry MUST remain verifiable after
  expiry solely as proof of that earlier decision and MUST NOT renew authority. Inbox
  absence, readback exhaustion, or readback unavailability alone MUST NOT prove
  definite absence while a send, queue item, process, or transport attempt may still be
  in flight, and MUST NOT start another automatic sequence. Definite absence requires
  fenced/quiesced transport plus exact attempt evidence; otherwise the operation MUST
  transition from `DISPATCHING` to `OUTCOME_UNKNOWN` and then require explicit
  `OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED` custody, with no automatic loop. A later
  exact no-consumption proof MUST close only through
  `RECONCILIATION_REQUIRED -> FAILED`; possible or consumed effects remain
  reconciliation-required for a later effect-aware feature.
- **FR-024**: The system MUST never report a possible post-delivery effect as denied,
  failed before dispatch, or safely retryable without evidence of definite absence.
- **FR-025**: Cancellation, pause, or shutdown MUST prevent new delivery when absence is
  still provable; after possible delivery it MUST preserve the grant and require
  readback or reconciliation rather than delete authority evidence.
- **FR-026**: Every durable coordinator and adapter transition MUST have one permanent,
  ordered, redacted event with task, lease, workload, plan, operation, grant, versions,
  decision, latency, and trace identifiers.
- **FR-027**: Audit or receipt persistence unavailable before possible adapter acceptance
  MUST fail closed. Failure after possible acceptance MUST retain an audit-pending or
  unknown state without claiming absence.
- **FR-028**: Crash injection MUST cover every boundary from pre-signing through durable
  dispatch, delivery, inbox insert, epoch validation, consumption, receipt retention,
  acknowledgement, coordinator readback, and state advancement.
- **FR-029**: Recovery MUST be deterministic for every injected crash: no grant existed,
  the one retained grant is pending, the one retained receipt is recoverable, definite
  refusal is proved, or the operation is explicitly unknown.
- **FR-030**: Backup MUST capture or cryptographically bind all coordinator grant state,
  adapter inbox state, receipts, public keys and key identifiers needed for historical
  verification, and their cross-store relationship without treating a best-effort
  simultaneous copy as atomic. Private signing keys MUST NOT enter the backup package,
  manifest, logs, fixtures, or evidence.
- **FR-031**: Clean restore MUST start paused under a new instance and supervisor epoch,
  expire all old grant authority, quarantine possible accepted or consumed operations,
  and require reconciliation before any later effect.
- **FR-032**: The system MUST detect orphan coordinator grants, orphan inbox entries,
  orphan receipts, conflicting histories, rollback, truncation, and generation reuse;
  none may authorize execution.
- **FR-033**: Contract behavior and conformance fixtures MUST be independent of operating
  system paths and primitives. Unsupported platform capabilities MUST be refused
  explicitly rather than weakened or silently skipped.
- **FR-034**: The feature MUST provide bounded queues, duplicate-flood protection,
  backpressure, and a control lane for pause, status, and reconciliation under load.
- **FR-035**: The feature MUST publish measurable dispatch, inbox, receipt, duplicate,
  refusal, ambiguity, queue, and recovery counters without sensitive payloads.
- **FR-036**: Upgrade MUST preserve verification of retained grant and receipt versions;
  incompatible versions MUST remain non-executable and fail closed.
- **FR-037**: Removal MUST delete only PLAN-005-owned executable surfaces and derived
  state while preserving PLAN-001 through PLAN-004 contracts, preparation evidence,
  protected files, and historical audit verification.
- **FR-038**: Release evidence MUST include unchanged multi-platform contract tests,
  deterministic fault-boundary results, tamper/replay cases, clean restore, removal,
  supply-chain provenance, and exact artifact digests without promoting hardware claims
  that were not measured.
- **FR-039**: For this no-effect R1 slice, lease and human-authorization authority MUST
  be supplied as current trusted versioned views whose exact digests and generations
  match the retained preparation context. The feature MUST NOT treat legacy in-memory
  kernel lease, approval, or scope objects as dispatch authority. Introducing complete
  signed `TaskLease`, `HumanRequestGrant`, or `ApprovalDecision` envelopes requires a
  separately specified migration before any production or R2 claim.
- **FR-040**: PLAN-005 MUST NOT accept `PreparedOperationV1`, a caller-constructed
  equivalent, or direct preparation-table rows as dispatch authority. Only the
  coordinator may derive a non-cloneable fresh dispatch candidate and serialized permit
  from one invariant-valid current `PREPARING` record while holding the required guards.
- **FR-041**: A v1 grant's exclusive deadline MUST be the earliest authority deadline
  and MUST NOT exceed 5,000 ms after its trusted issue-time sample. Delivery, duplicate
  recovery, readback, and reconciliation observation MUST NOT renew that lifetime.
- **FR-042**: Grants and receipts MUST use distinct signature domains and independently
  trusted signer purposes. V1 grants use coordinator dispatch-signing authority and the
  domain `HELIXOS\0EXECUTION-GRANT\0V1\0`; v1 receipts use destination-adapter
  receipt-signing authority and `HELIXOS\0EXECUTION-RECEIPT\0V1\0`. Key rotation,
  revocation, trust profiles and historical public verification MUST never allow one
  purpose or domain to verify the other.
- **FR-043**: Receipt decisions MUST be closed. `CONSUMED` is the only positive receipt
  and the only receipt allowed to advance to `EXECUTING`. `REFUSED_DEFINITE` requires a
  permanent post-`RECEIVED` no-consumption tombstone, MUST carry exactly one of the
  closed reasons `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` or `ADAPTER_PAUSED`, and
  MAY close only the exact dispatch attempt under the guarded no-in-flight proof.
  `DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`, `CAPABILITY_MISMATCH` and
  `INBOX_CAPACITY_EXHAUSTED` are pre-`RECEIVED` refusals: they MUST retain a redacted
  durable diagnostic or quarantine record, MUST NOT produce a receipt, and MUST NOT by
  themselves prove safe reservation release. A valid definite-refusal coordinator
  transaction MUST retain the signed receipt and append the normative
  `DISPATCHING -> OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED -> FAILED` history, update
  the PLAN-004 base operation `PREPARING -> FAILED`, release the exact held reservation
  once, and append both base and overlay events atomically. Conflict, malformed input,
  unsupported versions and unverifiable signatures produce redacted durable diagnostics
  or quarantine but never positive authority evidence.
- **FR-044**: Coordinator, adapter inbox, supervisor epoch and signing authorities MUST
  remain separate durability and trust domains. The system MUST NOT claim one atomic
  transaction across them; cross-domain correctness is established only by signed
  immutable bindings, ordered handoff, exact readback, fencing and reconciliation.
- **FR-045**: V1 grant bytes, dispatch transitions, inbox entries, receipts, conflicts,
  quarantines and reconciliation decisions are authoritative retained evidence. V1 MUST
  perform no automatic pruning or reuse, MUST preserve permanent tombstones, and MUST
  make no physical secure-erasure claim. Production roots still require an approved
  encrypted-at-rest profile.
- **FR-046**: The clean restore required by this feature MUST be labelled coordinator /
  adapter clean-root subsystem evidence only. It MUST NOT satisfy or imply the
  constitutional full-machine restore, activation, power-loss or Tier 1 gate.
- **FR-047**: PLAN-005 MUST define its own closed, versioned, exhaustive fault-boundary
  inventory covering coordinator transaction, delivery handoff, inbox, epoch check,
  consumption, receipt, acknowledgement, readback, migration and restore. The same
  immutable inventory MUST contain exactly 90 ordered boundaries and drive exactly 180
  declared in-process/process-kill cases; PLAN-004's frozen boundary registry MUST remain
  unchanged.
- **FR-048**: Acceptance evidence MUST map this feature explicitly to `GRANT-001`,
  `DUR-001`, `DUR-002`, `OPS-002`, `OPS-003`, `SUPPLY-001` and `PERF-002`, while keeping
  every aggregate claim `pending-evidence` until its external and physical gates pass.
- **FR-049**: Dispatch entry MUST accept only a bounded untrusted operation lookup key
  plus expected plan, preparation-attempt and transition bindings. The coordinator MUST
  reload and verify the full authoritative durable record and current generations; no
  caller-provided positive projection, receipt or stored row may substitute for that
  reload.

### Key Entities

- **Execution Grant**: Short signed one-shot authority derived from one exact prepared
  operation; it cannot broaden or outlive the plan, lease, deadline, or epochs.
- **Dispatch Record**: Authoritative durable coordinator record that binds one operation
  to one grant identity and proves dispatch authority existed before delivery.
- **Adapter Inbox Entry**: Durable destination-side record of the exact received grant,
  its validation outcome, and whether its one-shot authority was consumed.
- **Execution Receipt**: Signed durable adapter evidence identifying the exact grant,
  inbox and consumption generations, epoch observation, and acceptance or refusal.
- **Dispatch Transition**: Permanent ordered `PREPARING -> DISPATCHING` state change and,
  when exact accepted-and-consumed receipt evidence exists, `DISPATCHING -> EXECUTING`;
  unresolved possible delivery becomes `DISPATCHING -> OUTCOME_UNKNOWN ->
  RECONCILIATION_REQUIRED`. Definite no-consumption closes through `FAILED`; no later
  receipt may jump directly from unknown/reconciliation back to execution.
- **Dispatch Reconciliation Record**: Evidence and decision for ambiguous delivery,
  orphan state, restore, or receipt disagreement; it never mints authority.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Across exactly 10,000 repeated end-to-end requests, 100 end-to-end rounds
  with 64 concurrent threads and 20 end-to-end rounds with 8 concurrent processes for
  the same prepared operation, with every retained grant driven through the adapter
  boundary, exactly one grant identity, one dispatch transition, and one adapter
  consumption are observed, with zero duplicate consumptions.
- **SC-002**: All 90 enumerated crash boundaries and 180 declared
  in-process/process-kill cases produce one of the specified recoverable outcomes with
  zero blind grant replacement, zero false pre-dispatch failure, and zero unauthorized
  state advancement.
- **SC-003**: All tampered, replayed, expired, cross-operation, cross-workload,
  cross-destination, stale-epoch, unsupported-version, and conflicting-digest fixtures
  are refused before the grant is consumed.
- **SC-004**: For 100% of lost-acknowledgement cases where the adapter retained a valid
  receipt, the single bounded readback sequence uses no more than the four specified
  observations, finishes within 500 ms or the earlier caller/grant deadline, returns
  the original receipt even when recovered after expiry as evidence of its prior
  decision, renews no authority, and never consumes the grant a second time.
- **SC-005**: On the declared physical Mac mini M4 reference profile, after 500 warmups
  and at least 10,000 samples measured from entry into the retained final authority
  guard through verification of the exact consumed receipt, p95 is at most 50 ms and
  p99 at most 100 ms; evidence names hardware, operating system, store profile, load,
  repetitions and artifact digest.
- **SC-006**: With at most 1,024 ordinary pending entries and a separate capacity-32
  control lane, queue saturation and a 10,000-request duplicate flood refuse or
  backpressure new ordinary work within 50 ms while pause, status, and reconciliation
  requests remain at or below 100 ms p99 in all 100 controlled trials.
- **SC-007**: A clean restore from every lifecycle phase starts paused, revives zero old
  grant authority, detects every seeded orphan or conflict, and preserves all retained
  records required for reconciliation.
- **SC-008**: The unchanged contract and protocol conformance suite passes on macOS
  arm64, Linux x86_64, and Windows x64, with platform capability refusals declared in
  fixtures rather than hidden by test branches.
- **SC-009**: Independent release verification validates every artifact digest,
  signature, provenance record, dependency manifest, backup/restore result, and removal
  result for one exact source commit.
- **SC-010**: Removing PLAN-005 from an isolated copy leaves all protected PLAN-001
  through PLAN-004 files and behaviors unchanged and leaves no path that interprets a
  retained dispatch artifact as live authority.

## Assumptions

- PLAN-001 canonical signed contracts, PLAN-002 eligibility, PLAN-003 replay claiming,
  and PLAN-004 durable preparation are authoritative prerequisites and are not
  redefined by this feature.
- PLAN-005 consumes the lease and authorization digests/generations already frozen by
  PLAN-004 and revalidates them through injected trusted authority views. This is a
  deliberate test boundary, not a claim that the legacy kernel authority model is
  production-ready.
- The initial profile is single-user and uses one logical coordinator writer and one
  destination adapter identity per grant.
- The supervisor exposes an independently trustworthy current fencing epoch to the
  adapter; implementing the production supervisor itself is outside this feature.
- The coordinator, not portable callers, owns construction of the fresh dispatch
  candidate and permit from the current PLAN-004 record. No public or legacy operation
  projection is accepted as equivalent authority.
- Dispatch begins from an untrusted bounded lookup key and expected digests only; all
  positive state and authority are reloaded from the coordinator store.
- The transport is local, authenticated, bounded, and replaceable. Network egress and
  remote provider dispatch are outside this feature.
- This feature stops at durable one-shot adapter acceptance and the next pre-effect
  state. Host filesystem, process, secret, network, and other real effects belong to
  later adapter/execution features.
- Performance targets are provisional until ratified or amended by evidence on the
  declared Mac mini M4 reference profile.

## Scope

### In Scope

- `ExecutionGrant` and `ExecutionReceipt` v1 contracts and fixtures.
- The guarded prepared-to-dispatching transition and exact grant retention.
- Durable destination inbox, one-shot consumption, signed receipt, duplicate recovery,
  and conflicting replay refusal.
- Bounded delivery/readback, ambiguity classification, audit evidence, backup/restore,
  upgrade compatibility, removal, fault injection, and multi-platform conformance.
- A deterministic no-effect adapter proving the protocol without host mutation.

### Out of Scope

- Real filesystem, process, package, secret, model, network, notification, or other host
  effects.
- Effect verification, compensation, budget settlement, success reporting, and final
  audit delivery after an effect.
- Production VM, vsock, macOS service packaging, WebAuthn UI, egress gateway, and remote
  adapters.
- Definition or migration of complete signed `TaskLease`, `HumanRequestGrant`, and
  `ApprovalDecision` envelopes, and direct use of legacy kernel lease/approval objects.
- General exactly-once claims across coordinator, adapter, operating system, or external
  provider boundaries.
- Promotion of PLAN-005 or any hardware profile to Tier 1 without external physical
  evidence.

## Constitution Constraints *(mandatory)*

- **Boundary and authority**: The agent, caller, transport, grant submitter, and adapter
  payload are untrusted. The only new authority is a short signed one-shot grant derived
  from one current prepared operation. Forged, replayed, broadened, cross-destination,
  and stale-epoch grants must be refused before consumption.
- **Durability and recovery**: The signed grant and dispatch transition commit together
  under the retained ordered guards before delivery; the inbox precedes acceptance;
  consumption and receipt precede any future sealed effect handoff. Possible acceptance is never
  rewritten as definite absence, and transient inbox absence is not proof. Retry uses
  the same grant, ambiguity becomes `OUTCOME_UNKNOWN`, and restore starts paused with
  old grants expired.
- **Data and secrets**: Grant, receipt, trace, and audit metadata are internal security
  data. No raw secrets, unrestricted payloads, native paths, or external egress are
  introduced. Retention follows the operation/audit lifecycle and redaction occurs
  before serialization.
- **Portability**: Canonical contracts and protocol outcomes are OS-neutral. Platform
  differences appear only as declared capability fixtures; unsupported behavior is
  refused. One unchanged suite must run across the three build targets.
- **Performance and budgets**: Dispatch consumes no authority beyond the exact held
  reservation, never extends a deadline, and uses bounded queues and readback. Reference
  p95/p99, load, repetitions, refusal behavior, and control-lane responsiveness are
  recorded without implying unmeasured hardware guarantees.
- **Audit and lifecycle**: Every transition and decision is permanently correlated but
  redacted. Dependencies and artifacts are pinned with provenance; compatible upgrades
  preserve historical verification; clean restore and isolated removal are mandatory
  subsystem evidence. The PLAN-005 fault inventory is separate from PLAN-004, and no
  full-machine, physical durability, secure-erasure or Tier 1 claim is implied.
