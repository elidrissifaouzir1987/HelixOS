# Feature Specification: Current Plan Eligibility

**Feature Branch**: `master`

**Created**: 2026-07-10

**Status**: Ready for planning

**Input**: Continue the recommended HelixOS build sequence by converting a
cryptographically authentic plan plus trusted current-state evidence into a one-shot,
point-in-time eligibility result before preparation.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Admit Only a Current Coherent Plan (Priority: P1)

As the trusted core admission evaluator, I can determine whether an authentic plan is
still coherent with current time, boot, epochs, identity, lease, authorization, policy,
catalogue and capabilities, so stale or widened authority never reaches preparation.

**Why this priority**: A valid signature proves provenance, not that the signer remains
trusted, the lease remains active, the approval remains current, or the host state still
matches the plan. Every later durable transition depends on this distinction.

**Independent Test**: Starting with one authentic plan and a complete trusted current
snapshot, change each bound fact independently. The coherent snapshot is eligible;
every single mismatch returns its declared denial before any replay claim or preparation
probe is reached.

**Acceptance Scenarios**:

1. **Given** an authentic plan and matching healthy current facts, **When** eligibility
   is evaluated, **Then** it can proceed to the one-shot replay claim stage.
2. **Given** a plan before issuance or at/after expiry, **When** it is evaluated, **Then**
   it is denied under the half-open validity interval `issued_at <= now < expires_at`.
3. **Given** a different boot, task, workload, lease digest, request source, version,
   epoch, key-trust generation or capability binding, **When** evaluation occurs,
   **Then** it is denied deterministically and no downstream state is consumed.
4. **Given** an ahead epoch, rollback-suspect clock, paused supervisor or unavailable
   authority source, **When** evaluation occurs, **Then** it fails closed and never
   advances local state from the plan's claim.

---

### User Story 2 - Claim Admission Exactly Once (Priority: P1)

As the coordinator, I can atomically claim the plan nonce only after all read-only gates
pass, so concurrent or repeated admission cannot create two eligible instances.

**Why this priority**: A prior `nonce unused` observation is inherently racy. The final
admission step must be a one-shot compare-and-claim operation bound to this plan and
operation.

**Independent Test**: Repeated and barrier-synchronized evaluations of the same valid
plan use one shared replay claimant. Exactly one claim succeeds; all others receive the
same replay denial and no invalid pre-claim case consumes a nonce.

**Acceptance Scenarios**:

1. **Given** multiple simultaneous evaluations of the same valid plan, **When** they
   attempt the final atomic claim, **Then** exactly one returns an eligible result.
2. **Given** the nonce is already bound to another plan or operation, **When** admission
   is attempted, **Then** it is denied without fallback to process-local memory.
3. **Given** the replay authority is unavailable or reports an ambiguous outcome,
   **When** claim is attempted, **Then** admission fails closed and requires replan or
   reconciliation rather than retrying as a new claim.
4. **Given** any read-only gate fails, **When** evaluation ends, **Then** the replay
   claimant was not called.

---

### User Story 3 - Reproduce and Audit Eligibility Decisions (Priority: P2)

As a conformance or release maintainer, I can run one unchanged eligibility corpus on
macOS arm64, Linux and Windows and receive the same redacted codes and decision facts,
so portability and denial behavior are measured rather than asserted.

**Why this priority**: Eligibility is a security boundary shared by the core and future
platform work. Platform-specific clocks or identifiers must not silently change its
meaning.

**Independent Test**: The same fixture plan, trusted snapshots and replay outcomes
produce byte-for-byte identical decision summaries and denial codes on every registered
platform, without native path, clock or handle values.

**Acceptance Scenarios**:

1. **Given** a declared single-fault fixture, **When** conformance runs, **Then** it
   produces the declared stable denial code and zero preparation/dispatch probes.
2. **Given** diagnostics for any denial, **When** they are rendered, **Then** they omit
   plan content, identifiers, nonces, paths, signatures and raw provider errors.
3. **Given** an eligible result, **When** it is inspected, **Then** it is visibly a
   point-in-time prerequisite and cannot be serialized or used as adapter authority.

### Edge Cases

- Current wall time is one millisecond before issuance, exactly at issuance, one
  millisecond before expiry, exactly at expiry, or beyond the safe integer range.
- The monotonic source is missing, from another boot, at its deadline, moves backward,
  or disagrees with a durable clock high-water mark.
- Instance or fencing epoch is current minus one, exactly current, current plus one, or
  unavailable; an ahead value never updates authoritative state.
- The system is paused, aborting, halted, restored or between supervisor generations.
- Signer trust, workload identity or approval is revoked after signature verification.
- A signer registry attempts to reuse an existing key identifier after rotation, or a
  marker verified with the old public key remains in memory after trust changes.
- Lease resolution finds none or more than one matching lease, or finds an expired,
  revoked, exhausted, cross-task, cross-workload, source-mismatched, scope-widening or
  budget-widening lease.
- A policy/catalogue identifier is reused with different immutable content, is unknown,
  or changes immediately after evaluation.
- A context supplies an observation timestamp different from the protected report
  (including a future timestamp), or the exact report is stale by one millisecond, from
  another boot/instance/host/driver context, has a changed digest, or lacks one
  mandatory capability. Feature 001 already prevents an authentic plan from protecting
  an observation later than its own issuance.
- The same nonce is used with another operation; the same operation is bound to another
  plan; a replay claim times out or returns an ambiguous result.
- A bound generation, deadline or supervisor epoch changes after eligibility but before
  `PREPARING`; the result must be compared again or discarded.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The evaluator MUST accept only a previously authenticated plan marker;
  raw or merely signed wire data MUST NOT enter this transition.
- **FR-002**: All current facts MUST come from explicitly trusted providers controlled
  by the core; agent-supplied fields MUST NOT satisfy eligibility.
- **FR-003**: Validation MUST follow the deterministic order: context health and plan
  binding; time/boot/epochs; signer/workload/lease/authorization; policy/catalogue;
  capabilities; final atomic replay claim.
- **FR-004**: Wall-clock validity MUST use `issued_at <= now < expires_at`, with
  `issued_at` serving as v1 not-before time.
- **FR-005**: Eligibility MUST require a healthy suspend-aware monotonic deadline bound
  to the same plan and boot. A reboot, missing clock, rollback suspicion or reached
  deadline MUST deny.
- **FR-006**: Plan, lease and current core state MUST match exact boot ID, task ID,
  workload ID and instance epoch.
- **FR-007**: The plan fencing epoch MUST equal the current supervisor-owned epoch and
  the supervisor MUST be open for admission. Stale, ahead or unavailable values MUST
  deny and MUST NOT mutate the supervisor.
- **FR-008**: The current signer-trust view MUST match the plan key ID and the non-wire
  fingerprint of the exact public key used during signature verification, remain
  trusted, and bind an explicit trust generation and minimum accepted issuance time so
  rotation or later revocation invalidates a held authentic plan. Key identifiers MUST
  be immutable and never reassigned to different key bytes; rotation MUST issue a new
  identifier.
- **FR-009**: The authenticated workload identity MUST match the plan and active lease,
  remain trusted and remain within both its UTC and monotonic validity windows.
- **FR-010**: Exactly one active unrevoked lease MUST resolve from the signed digest and
  match task, workload and request-source kind/digest.
- **FR-011**: The lease decision MUST affirm that intent, resource root/subtree,
  action/byte/cost limits, price table and reservation are no wider than the lease. An
  assertion for another plan MUST deny.
- **FR-012**: The active policy identity and immutable content digest MUST match the
  plan binding and an affirmative current policy decision. Missing or changed policy
  MUST require replan, never approval fallback.
- **FR-013**: The active catalogue identity and immutable content digest MUST match the
  plan binding and affirm that the schema and intent semantics remain supported.
- **FR-014**: Current plan-bound authorization evidence MUST remain valid for the plan,
  operation, risk level, nonce and effective deadlines. This feature consumes trusted
  evidence but does not implement WebAuthn or approval UI.
- **FR-015**: The current capability view MUST match the plan report digest and
  observation time, current boot/instance and host-driver context, contain every
  required and intent-mandatory capability, and be no older than the active policy's
  maximum age. The exact maximum age is valid; one millisecond older MUST deny.
- **FR-016**: All read-only checks MUST complete before the replay authority is called.
- **FR-017**: The final replay action MUST atomically claim `(instance_epoch, nonce)` in
  a stable issuer namespace and bind it to the exact key ID/fingerprint, plan,
  operation, task, workload, lease, trust generation and fencing epoch. Key rotation
  MUST NOT reopen a nonce. A plain `unused` observation is insufficient.
- **FR-018**: Failed pre-claim checks MUST NOT consume replay state. A successful claim
  MUST never be released for reuse; an interrupted admission requires replan or
  reconciliation.
- **FR-019**: An eligible result MUST bind the plan ID, effective UTC and monotonic
  deadlines, all mutable state generations/digests, the replay claim identifier and a
  domain-separated digest of the exact replay binding. A claimant receipt with another
  binding digest MUST deny.
- **FR-020**: The marker MUST expose the complete comparison vector needed by a future
  coordinator. Before `PREPARING`, that coordinator MUST atomically compare every bound
  generation/deadline or repeat eligibility. This feature specifies and tests the
  comparison material but does not implement the durable transition.
- **FR-021**: Eligibility MUST return closed stable denial codes without expected/actual
  values, sensitive plan content, nonce, path, signature or raw provider diagnostics.
- **FR-022**: Missing, ambiguous or unavailable trust, time, replay, lease, policy,
  catalogue, identity, authorization or capability state MUST fail closed.
- **FR-023**: Eligibility facts and decisions MUST use platform-independent values and
  MUST NOT contain native clocks, paths, handles, conditional OS semantics or ambient
  process state.
- **FR-024**: The eligible result MUST be an opaque in-process prerequisite. It MUST NOT
  be serializable, transferable, approval evidence, an `ExecutionGrant`, or accepted by
  an adapter.
- **FR-025**: A versioned positive and single-fault negative conformance corpus MUST
  cover every bound fact, exact time/freshness boundary, replay outcome and dependency
  failure without modification across supported platforms. Malformed context inputs
  rejected by checked construction MUST use a separate closed redacted build-error
  taxonomy and corpus outcome.

### Key Entities

- **Eligibility Context**: Trusted point-in-time clock, supervisor, identity, lease,
  authorization, policy, catalogue and capability facts plus their generations.
- **Active Lease View**: Verified lease identity and expiry plus a plan-bound decision
  that scope and budgets do not widen authority.
- **Current Capability View**: Resolved capability report, context, freshness limit and
  available/mandatory capability sets.
- **Replay Claim**: Atomic durable one-shot binding between nonce, plan, operation,
  task, lease, key and instance epoch.
- **Eligible Plan**: Opaque point-in-time result binding the authentic plan to effective
  deadlines, evidence generations and replay claim. It is necessary but not sufficient
  for preparation or dispatch.
- **Eligibility Denial**: Closed redacted reason code indicating the first failed gate.

## Scope

### In Scope

- Deterministic current-state evaluation over explicit trusted facts.
- Contract for an atomic one-shot replay claimant and a deterministic concurrent test
  implementation.
- Opaque eligible marker, stable denial taxonomy and portable conformance corpus.
- Read-only projection of the protected plan facts required for evaluation.

### Out of Scope

- Human approval UI, WebAuthn verification and approval persistence.
- Production replay database, durable coordinator or operation-state implementation.
- Budget/counter reservation transaction, recovery pre-image preparation and receipt.
- `PREPARING`, `DISPATCHING`, `ExecutionGrant`, adapter inbox or host effects.
- Target precondition and capability re-probe immediately before effect.
- Migration of the MVP-0 pipeline or any platform adapter.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of declared single-fault fixtures deny with the expected code before
  replay claim or preparation, while the complete coherent fixture reaches one claim.
- **SC-002**: Boundary tests pass at issuance, expiry, lease/identity/authorization
  deadline, monotonic deadline and capability maximum age, including boundary plus or
  minus one millisecond.
- **SC-003**: In at least 1,000 contention rounds, exactly one concurrent evaluation of
  an identical plan obtains the replay claim; all others deny and no round produces two
  eligible results.
- **SC-004**: At least 100,000 generated contexts complete without panic, arithmetic
  overflow, platform drift or false acceptance.
- **SC-005**: On the reference development machine, complete evaluation with a
  deterministic local replay claimant has p95 at or below 1 ms over at least 10,000
  iterations, with hardware, platform, corpus and raw samples recorded.
- **SC-006**: The unchanged corpus produces identical eligibility outcomes on Windows,
  Linux and macOS arm64; no portability claim is made before immutable CI evidence.
- **SC-007**: Public diagnostics and debug output contain none of the sentinel plan
  content, identifiers, nonce, resource components, signature or raw provider error in
  100% of denial cases.
- **SC-008**: Existing feature-001 and legacy workspace tests remain green, and removing
  this feature leaves canonical/signature behavior and MVP-0 runtime behavior unchanged.

## Assumptions

- Feature 001 locally supplies the authentic plan marker and stable portable plan ID;
  its remote multi-OS evidence may remain pending while this leaf is developed.
- Trusted provider implementations resolve immutable policy/catalogue content and
  cannot replace content under an existing identity.
- Signing-key identifiers are globally immutable within the plan-v1 trust domain and
  are retained for historical verification; rotation never reuses an identifier.
- The production replay store and compare-before-prepare transaction are delivered by a
  later durable-coordinator feature; absence of that implementation blocks Tier 1 and
  all host effects.
- The active authorization verifier exists conceptually outside this feature and
  supplies plan-bound evidence; this feature does not decide human approval validity
  from raw WebAuthn data.
- Eligible results are consumed promptly. Time or generation change requires
  re-evaluation; no grace period is assumed.

## Constitution Constraints *(mandatory)*

- **Boundary and authority**: The agent and authentic plan remain insufficiently
  trusted. Only core-controlled current facts participate. Replay, cross-task,
  cross-workload, widened lease and stale-generation abuse cases must deny.
- **Durability and recovery**: This feature performs no host effect. The replay claimant
  contract requires atomic durable semantics, but its production store, recovery
  material and durable operation transitions are deferred and therefore block dispatch.
- **Data and secrets**: No secret bytes or full plan content are needed. Diagnostics,
  tests and Graphify memory must remain redacted.
- **Portability**: Common facts are scalar identifiers, digests, sets, UTC milliseconds
  and boot-scoped monotonic milliseconds. Native clock/path/handle objects are forbidden;
  the unchanged corpus is required on macOS arm64 and another driver.
- **Performance and budgets**: SC-003 through SC-005 define contention, robustness and
  latency gates. Dependency unavailability fails closed; no unbounded queue or retry is
  introduced.
- **Audit and lifecycle**: Evidence includes decision codes, bound generations,
  contention results, performance artifact and removal path. The eligible marker is not
  persisted as authority and can be removed without changing feature 001 or MVP-0.
