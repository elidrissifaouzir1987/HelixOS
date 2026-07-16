# Feature Specification: Durable Signed Task Authority

**Feature Branch**: `codex/plan-006-durable-signed-task-authority`

**Created**: 2026-07-15

**Status**: Draft

**Input**: User description: "Continue the remaining project after PLAN-005 with the separately specified R1 migration for complete signed HumanRequestGrant, TaskLease, and ApprovalDecision authority, while preserving all prior contracts and stopping before host effects or R2."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Accept an authentic human request once (Priority: P1)

A human can authorize a bounded task request once, while forged, replayed, expired,
or context-mismatched requests create no task authority.

**Why this priority**: Every later lease and approval depends on proving that a real,
current human request entered through the trusted request boundary. Without this
foundation, no other authority in the feature is meaningful.

**Independent Test**: Submit a valid signed request grant and its negative variants to
an otherwise empty authority system. The valid grant can produce one retained root
lease, while every invalid or conflicting variant produces no lease mutation.

**Acceptance Scenarios**:

1. **Given** a current trusted request signer and an unused grant identity bound to the
   exact principal, message digest, channel, session, audience, scope template and
   expiry, **When** the core consumes the grant, **Then** it retains exactly one root
   lease chain and an exact retry returns the identical retained lease.
2. **Given** a forged, replayed, expired, wrong-message, wrong-session, wrong-purpose or
   unsupported-version grant, **When** issuance is requested, **Then** the request is
   denied before any lease or positive authority projection exists.
3. **Given** 64 concurrent threads or eight concurrent processes presenting the same
   unused grant, **When** issuance completes, **Then** exactly one issuance chain exists,
   exact duplicates observe its retained bytes and conflicting reuse is denied.
4. **Given** a signer rotation or revocation that becomes current before consumption,
   **When** the previously signed grant is presented, **Then** current trust denies it
   without mutation.

---

### User Story 2 - Issue and restrict task leases (Priority: P1)

The trusted core can issue a durable root task lease from the consumed human request
and delegate only authority that is smaller on every governed axis.

**Why this priority**: The task lease is the typed boundary that prevents an agent,
sub-agent or alternate channel from acquiring broader resources, budgets, time or
intentions than the human request allowed.

**Independent Test**: Issue one root lease from a valid consumed grant, then evaluate
exact-limit delegations, every single-axis widening, concurrent sibling allocations,
expiry and revocation without requiring approval or dispatch.

**Acceptance Scenarios**:

1. **Given** an atomically consumed current human grant, **When** the core issues a root
   lease, **Then** the lease binds the exact grant, task, workload, allowed intentions,
   resources, budgets, counters, deadlines and trust limits.
2. **Given** a proposed child lease within all parent bounds, **When** delegation is
   requested, **Then** the child and parent allocation are retained atomically.
3. **Given** a proposed child that widens any one intention, resource, budget, counter,
   duration, audience, catalogue or trust bound by one unit, **When** delegation is
   requested, **Then** it is denied without partial allocation.
4. **Given** concurrent sibling allocations, **When** their aggregate reaches the exact
   parent limit, **Then** the exact limit is allowed and every oversubscribing request is
   denied.
5. **Given** expiry, reboot, source revocation or ancestor revocation, **When** current
   lease authority is resolved, **Then** the affected lease and all descendants are
   non-current.

---

### User Story 3 - Bind one terminal decision to one exact plan (Priority: P1)

A human approval or denial is bound to one exact current plan and authority chain, and
cannot be replayed against another plan or changed afterward.

**Why this priority**: A valid lease does not itself authorize a risky plan. The system
must prove that the terminal human decision covers the exact plan, request and lease
that downstream guards will later compare.

**Independent Test**: Create one valid terminal decision for an exact plan, race
approve and deny attempts, and mutate each bound plan or authority field. Only the one
retained terminal result can yield a current positive projection.

**Acceptance Scenarios**:

1. **Given** an authentic current plan and its exact current grant and lease chain,
   **When** a valid `APPROVED` decision is retained, **Then** a plan-bound current
   authorization projection is available.
2. **Given** a decision whose plan digest, operation, nonce, request, lease, session,
   risk, evidence profile or deadline differs, **When** it is evaluated, **Then** it is
   denied before a positive projection.
3. **Given** concurrent approve and deny attempts for the same decision identity,
   **When** they complete, **Then** exactly one terminal result is retained and it can
   never flip.
4. **Given** an L2 decision without user-verification-capable evidence, **When** positive
   authority is requested, **Then** it is denied; deterministic synthetic evidence is
   accepted only as labelled conformance input and never as production evidence.
5. **Given** a current approval whose signer, grant, lease or decision is later revoked,
   **When** downstream authority is resolved, **Then** every affected positive
   projection becomes non-current.

---

### User Story 4 - Replace synthetic and legacy authority views (Priority: P2)

Eligibility, durable preparation and one-shot dispatch consume authority projections
derived only from verified PLAN-006 records, never legacy objects or caller assertions.

**Why this priority**: PLAN-002 through PLAN-005 deliberately use trusted synthetic
views. Replacing those views closes the signed-authority gap without broadening this
feature into host execution.

**Independent Test**: Resolve exact lease and authorization projections from a coherent
signed chain, feed them through the existing eligibility, preparation and dispatch
comparison seams, and prove that every legacy or mismatched substitute is refused.

**Acceptance Scenarios**:

1. **Given** a coherent verified authority chain, **When** current authority is
   projected, **Then** the exact lease and authorization digests, generations,
   deadlines, ancestors and revocation bindings are produced.
2. **Given** those projections, **When** PLAN-004 performs its final comparison and
   PLAN-005 performs its dispatch comparison, **Then** both revalidate the exact values
   under their existing ordered guards.
3. **Given** a legacy scope lease, approval enum, synthetic boolean, caller-provided row
   or caller-constructed positive view, **When** it is offered as authority, **Then** it
   cannot satisfy any PLAN-006 projection.
4. **Given** historical state without the exact signed chain, **When** current authority
   is requested, **Then** the state remains non-current and a new grant, lease, plan and
   decision chain is required.

---

### User Story 5 - Recover authority safely (Priority: P2)

Signed task authority remains coherent through restart, interrupted writes, migration,
backup and clean-root restore without reviving old authority.

**Why this priority**: Authority that can duplicate, disappear ambiguously or reactivate
after restore would invalidate the one-shot and revocation guarantees of the first four
stories.

**Independent Test**: Restart after every declared transition boundary, run supported
and unsupported migrations, corrupt or substitute backup members, and restore into an
empty root under new epochs. Observe only absent, coherently retained or explicitly
ambiguous results, with zero restored live authority.

**Acceptance Scenarios**:

1. **Given** retained grants, leases, decisions, allocations and revocations, **When**
   the authority subsystem restarts, **Then** exact signed bytes, digests, replay claims,
   counters, generations and public verification-key history remain coherent.
2. **Given** interruption at any declared durable boundary, **When** the subsystem
   reopens, **Then** the transition is fully absent, coherently committed or explicitly
   ambiguous, and no blind reissuance occurs.
3. **Given** supported prior state, **When** migration is interrupted and resumed,
   **Then** it converges exactly once; unknown, newer, corrupt or downgrade state fails
   closed.
4. **Given** a complete valid backup restored into an approved empty root, **When**
   restore completes under new epochs, **Then** historical verification remains
   possible but every restored nonterminal lease and approval is non-current and the
   subsystem starts paused.

---

### User Story 6 - Produce reusable release evidence (Priority: P3)

Maintainers can validate and later remove the feature with portable, deterministic,
exact-commit evidence without overstating production readiness.

**Why this priority**: The feature cannot advance conformance claims without reusable
evidence, but evidence follows the independently useful authority slices above.

**Independent Test**: Run the unchanged positive, negative, concurrency, fault,
migration, restore, performance, redaction, supply-chain and removal gates on all target
platforms and verify that catalogue claims remain pending until their own gates pass.

**Acceptance Scenarios**:

1. **Given** one unchanged fixture corpus, **When** it runs on macOS arm64, Linux x64
   and Windows x64, **Then** each platform produces byte-identical machine-readable
   outcomes for common semantics.
2. **Given** release evidence from one exact commit, **When** provenance, redaction,
   migration, removal and supply-chain validation run, **Then** every artifact is bound
   to that commit and no unrelated hardware or production claim is promoted.
3. **Given** completed implementation tasks but incomplete immutable or external gates,
   **When** the conformance catalogue is generated, **Then** PLAN-006 and its mappings
   remain `pending-evidence`.

### Edge Cases

- Duplicate members, unknown fields or versions, noncanonical Unicode or numbers,
  wrong field order, wrong signature domain or purpose, unsupported algorithm and any
  protected-field mutation.
- Reusing the same grant or decision identity under another key, reassigning a key ID,
  or rotating or revoking trust between verification and durable commit.
- Exact UTC or monotonic expiry, wall-clock rollback, monotonic rollback, reboot, boot
  mismatch, suspend/resume and an unexpectedly long sleep.
- Wrong principal, message, channel, session, audience or scope-template generation.
- Missing, ambiguous, exhausted, revoked, cross-task or cross-workload lease authority.
- Missing or revoked ancestor, maximum delegation depth, every single-axis one-unit
  widening, authority unions, sibling oversubscription and counter overflow/underflow.
- Concurrent approve/deny, exact approval deadline, weak L2 evidence, plan mutation
  after approval and revocation after approval.
- Durable commit with lost acknowledgement, signing failure before commit, torn or
  corrupt rows, missing public verification-key history and detached late mutation.
- Migration or restore from unsigned, synthetic or legacy-only authority state.
- Backup generation changes during export, incomplete members, substituted provenance
  and coherent-looking replacement stores.
- Seeded raw message, authentication assertion, identifier, digest, native path,
  provider error and secret sentinels reaching public errors, logs or evidence.
- A platform or durability capability being unsupported and therefore refused instead
  of silently downgraded.

## Requirements *(mandatory)*

### Functional Requirements

#### Common signed contracts

- **FR-001**: The feature MUST define closed, versioned signed contracts for a human
  request grant, task lease and approval decision.
- **FR-002**: Version 1 protected content MUST have one canonical UTF-8 representation,
  a SHA-256 protected digest, Ed25519 signatures and a distinct signature domain and
  signer purpose for each contract.
- **FR-003**: Verification MUST reject duplicate members, noncanonical values, unknown
  versions, unsupported algorithms, wrong domains or purposes, untrusted keys and any
  tampering before treating content as authority.
- **FR-004**: Authority values MUST be platform-independent, use bounded integers and
  opaque resource components, and exclude native paths, floating-point authority
  values, handles and ambient process state.
- **FR-005**: Every authority-bearing leaf MUST affect the protected digest and
  signature; mutation of any such leaf MUST invalidate the original signature.
- **FR-006**: Public errors, logs, metrics and retained evidence MUST expose only closed,
  redacted reason codes and MUST NOT echo untrusted or secret values.

#### Human request grant

- **FR-007**: A human request grant MUST bind issuer, audience, principal, exact message
  digest, channel and session, immutable scope-template identity/digest/generation,
  issue time, exclusive expiry and a one-shot grant identity.
- **FR-008**: Only the configured request-surface signer purpose may create a valid
  grant; chat text, notifications, bearer links and transport identity alone MUST NOT
  substitute for it.
- **FR-009**: The core MUST atomically consume an issuer-scoped grant identity exactly
  once while issuing exactly one root lease chain.
- **FR-010**: An exact grant retry MUST recover the same retained lease bytes;
  conflicting reuse MUST NOT issue another lease.
- **FR-011**: Grant consumption MUST use current key trust, revocation,
  scope-template generation and expiry. Key identifiers MUST be immutable and rotation
  MUST use a new identifier.

#### Task lease

- **FR-012**: The trusted core MUST be the sole version 1 root-lease issuer, and root
  issuance MUST require the exact atomically consumed human grant.
- **FR-013**: A task lease MUST bind its lease and task identities, workload identity,
  allowed intentions, resource scope, budgets, counters, trust and catalogue bounds,
  audience, validity, delegation state, boot/instance state and source-grant digest.
- **FR-014**: The plan MUST bind the exact lease protected digest and exact source-grant
  digest and MUST identify the request source as the human request grant.
- **FR-015**: Lease validity MUST use half-open UTC validity and an exclusive same-boot
  monotonic deadline; reboot MUST invalidate nonterminal leases.
- **FR-016**: Root authority MUST be no wider than the trusted scope template, current
  policy/catalogue constraints and source human grant.
- **FR-017**: Delegation MUST only reduce authority and MUST NOT add resources or
  intentions, union prior leases, extend time, renew authority, increase budgets or
  counters, or change the request source.
- **FR-018**: Parent allocation and child issuance MUST be atomic and aggregate-bounded
  under concurrency. Exact limits MUST be permitted; one-unit widening, underflow,
  overflow and sibling oversubscription MUST be denied.
- **FR-019**: Lease, grant and parent-child identities MUST be create-only. Exact
  duplicates MUST return retained evidence and conflicting reuse MUST be denied.
- **FR-020**: Source or ancestor revocation, expiry or exhaustion MUST invalidate
  descendants and current projections without rewriting retained signed bytes.
- **FR-021**: Counter and delegation consumption MUST be durable and monotonic. Agents
  MUST NOT reset, release, renew or widen them.

#### Approval decision

- **FR-022**: A decision may be created only after authenticating the exact current plan
  and its current request-grant and lease chain.
- **FR-023**: A decision MUST bind the plan digest and ID, terminal decision, operation,
  task, workload, plan nonce, grant and lease digests, risk, principal/session,
  authentication profile and evidence digest, policy/catalogue state,
  boot/instance/fencing state, issue time, exclusive expiry and one-shot identity.
- **FR-024**: Decisions MUST be terminal `APPROVED` or `DENIED`; only a current
  `APPROVED` decision may produce positive authorization authority.
- **FR-025**: Decisions MUST use their distinct signer purpose and signature domain and
  MUST be checked against current trust and revocation state.
- **FR-026**: Decision validity MUST end no later than the plan, lease and source grant;
  equality at any exclusive expiry boundary MUST deny.
- **FR-027**: Positive L2 authorization MUST require a user-verification-capable
  evidence profile. Deterministic synthetic profiles MUST be labelled conformance-only
  and MUST NOT qualify a production claim.
- **FR-028**: Concurrent approve/deny attempts MUST commit one terminal result. Exact
  retry MUST return retained bytes; conflicting reuse or decision flipping MUST deny.
- **FR-029**: Revocation MUST be append-only and generation-increasing, MUST invalidate
  current projections and MUST NOT claim to undo an already possible downstream effect.
- **FR-030**: Raw messages, authentication assertions, bearer tokens and private keys
  MUST NOT appear in signed authority wires, authority storage, logs or evidence.

#### Durability and lifecycle

- **FR-031**: Durable authority state MUST retain exact signed wires and digests, grant
  claims, derivation links, counters, allocations, revocations, generations, public
  verification-key history and transition events before publishing positive
  projections.
- **FR-032**: Grant consumption, root-lease issuance, generation change and their event
  publication MUST become visible atomically.
- **FR-033**: Parent allocation, counter consumption, child issuance, generation change
  and their event MUST become visible atomically.
- **FR-034**: A terminal decision, generation change and its event MUST become visible
  atomically.
- **FR-035**: Outcomes MUST distinguish definite pre-mutation or rolled-back failure
  from uncertain commit. At most one fresh exact readback may classify uncertainty;
  authority MUST NOT be blindly re-signed or reissued.
- **FR-036**: Waits and deadlines MUST be bounded by trusted monotonic time, and no
  detached mutation may continue after the caller receives a terminal result.
- **FR-037**: Open and migration MUST validate application identity, schema version,
  declared durability profile, invariants and rollback state. Unsupported or corrupt
  state MUST fail closed without admission-time repair.
- **FR-038**: Migration MUST be explicit, restartable and compatible with unchanged
  PLAN-001 wire bytes. Unsigned, legacy or synthetic state MUST NOT be backfilled as
  signed authority.
- **FR-039**: Backup MUST be consistent or explicitly checkpoint-bound, publish its
  manifest last, verify the maintenance signature through an externally provisioned
  purpose-specific trust anchor rather than an embedded key, retain public verification
  history, counters, generations and tombstones, and exclude private keys.
- **FR-040**: Restore MUST target an approved empty root, validate the complete package,
  enter paused/restore-pending state under new epochs and make all restored nonterminal
  leases and approvals non-current.

#### Projection and integration

- **FR-041**: Current projections MUST derive only from exact verified durable state and
  carry their digest, generation, status, deadline, source, ancestor and revocation
  bindings.
- **FR-042**: PLAN-002 lease and authorization views MUST derive only from those
  projections and MUST validate exact plan, request and lease bindings.
- **FR-043**: PLAN-004 and PLAN-005 MUST carry and recheck the exact authority
  generations and digests under their existing ordered guards; change or unavailability
  MUST deny before preparation or dispatch.
- **FR-044**: Dependency, source and removal checks MUST prove that legacy leases,
  legacy approvals, booleans and caller-provided rows cannot satisfy authority.
- **FR-045**: PLAN-006 MUST NOT create plan-wire changes, PLAN-003 replay claims,
  preparation or dispatch claims, execution grants, adapter handoffs, host effects,
  effect verification or settlement.

#### Evidence

- **FR-046**: One unchanged positive, negative, single-fault, concurrency and generated
  corpus MUST cover signatures, domains, versions, one-shot reuse, expiry, revocation,
  delegation, replay, migration, restore and redaction on macOS arm64, Linux x64 and
  Windows x64.
- **FR-047**: The release catalogue MUST register PLAN-006 and map only `REQUEST-001`,
  `SEC-002` and `SEC-003`; all mapped claims MUST remain pending until their required
  gates are satisfied.
- **FR-048**: Performance and overload evidence MUST identify hardware, OS/runtime,
  workload, concurrency, repetitions, percentiles and raw samples, while proving that
  current revocation and status controls remain available during duplicate floods.

### Key Entities

- **HumanRequestGrantV1**: The signed, bounded, expiring, one-shot proof that a trusted
  request surface authenticated a human request and its exact context.
- **Human Request Claim**: The durable create-only record that prevents a grant identity
  from issuing more than one root lease chain.
- **TaskLeaseV1**: Core-issued task authority over exact intentions, resources, budgets,
  counters, validity and delegation bounds.
- **Lease Allocation**: A durable parent-child allocation that proves aggregate sibling
  delegations remain within the parent.
- **ApprovalDecisionV1**: A signed terminal approval or denial bound to one exact plan
  and current authority chain.
- **Authority Chain**: The exact grant, root/ancestor leases, plan and terminal decision
  relationships required for a positive projection.
- **Revocation Record**: An append-only generation-increasing invalidation of a signer,
  grant, lease, ancestor or decision.
- **Key Trust History**: Current trust plus retained public verification material needed
  to verify historical signed bytes without reviving authority.
- **Current Lease Projection**: The closed current lease digest/generation/deadline view
  consumed by PLAN-002, PLAN-004 and PLAN-005.
- **Current Authorization Projection**: The closed current plan-bound decision view
  consumed by PLAN-002, PLAN-004 and PLAN-005.
- **Authority Transition Event**: The retained redacted evidence that an atomic authority
  transition became visible.
- **Migration Receipt**: Evidence that supported prior authority storage converged to
  the current schema without manufacturing authority.
- **Backup Manifest and Restore Evidence**: Checkpoint-bound provenance and validation
  needed to restore historical state into paused rotated authority.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All positive fixtures produce byte-identical canonical protected bytes,
  outer bytes, digests and signature results on all three target platforms, and every
  authority-bearing leaf mutation invalidates the original signature.
- **SC-002**: 100% of forged, replayed, expired, wrong-message, wrong-session,
  wrong-audience, wrong-schema and wrong-purpose grants are denied before root issuance,
  with zero authority produced from bare messages or notifications.
- **SC-003**: Across 10,000 sequential retries, 100 rounds with 64 threads and 20 rounds
  with eight processes, one grant identity creates exactly one root chain and every
  exact retry recovers identical retained bytes.
- **SC-004**: 100,000 generated lease/delegation cases produce zero widening, overflow,
  aggregate oversubscription or cross-task/workload acceptance.
- **SC-005**: Every terminal-decision race retains exactly one result, and 100% of plan,
  operation, nonce, request, lease, risk, profile, session and expiry mutations are
  denied.
- **SC-006**: A coherent chain produces the exact PLAN-002/004/005 authority values;
  changing any bound digest, generation, ancestor or revocation state causes the
  expected denial and zero downstream mutation.
- **SC-007**: Fault injection at every declared durable boundary reopens as absent, one
  coherent retained transition or explicit ambiguity, with zero duplicate lease or
  decision.
- **SC-008**: Backup/restore reproduces 100% of records through its declared checkpoint,
  rejects every corrupted or substituted package and reactivates zero restored lease or
  approval.
- **SC-009**: Supported migrations are restartable, 100% of legacy/synthetic-only
  records remain non-current, and feature removal leaves PLAN-001 through PLAN-005
  behavior unchanged.
- **SC-010**: The unchanged three-platform corpus produces byte-identical
  machine-readable summaries with no platform-conditioned common semantics.
- **SC-011**: Seeded redaction tests expose zero raw messages, authentication assertions,
  private keys, native paths, identifiers, protected digests or provider details in
  public outputs.
- **SC-012**: On the declared reference profile, after 500 warmups and 10,000 measured
  samples, verification of the three-contract chain plus projection has p95 at or below
  2 ms; durable issue, delegation and decision transitions have p95 at or below 25 ms
  and p99 at or below 100 ms.
- **SC-013**: In 100 duplicate-flood trials of 10,000 requests, new work is bounded or
  refused within 50 ms and current revocation/status lookup remains p99 at or below
  100 ms.
- **SC-014**: One exact-commit release bundle validates contracts, corpus, durability,
  migration, restore, dependency inventory, licenses, advisories, provenance and
  removal, while catalogue claims remain pending until their own evidence gates pass.

## Assumptions

- The initial deployment remains single-user.
- A human request grant is one-shot for root-lease issuance.
- A task lease may authorize multiple plans within its durable counters and bounds;
  each plan remains independently one-shot under PLAN-002 and PLAN-003.
- An approval decision is terminal and scoped to one exact plan.
- The three signed objects use distinct signer purposes and domains. Key IDs are
  immutable, rotations receive new IDs and historical public keys remain available.
- Grant and decision identity uniqueness is independent of key identity and independent
  of PLAN-003's plan replay namespace.
- Real WebAuthn and request-edge identity are outside scope; deterministic evidence
  profiles never qualify production claims.
- PLAN-001 through PLAN-005 contracts remain authoritative and byte-compatible.
- Existing unsigned, synthetic or legacy records are not backfilled; a new signed chain
  is required.
- Version 1 retains authority records, revocations, replay tombstones and public key
  history without pruning.
- Restore is subsystem recovery, not full-machine recovery, and does not prove secure
  erasure or physical power-loss durability.

## Scope

### In Scope

- Closed version 1 signed contracts for the human request grant, task lease and
  approval decision.
- Canonical representation, protected digests, signature domains, verification order,
  replay identities, expiry, trust rotation and revocation.
- One-shot human-grant consumption, core issuance of root leases, restrictive
  delegation, durable counters/budgets and aggregate sibling contention.
- Plan-bound terminal decisions and exact current authority projections into PLAN-002,
  PLAN-004 and PLAN-005.
- Durable authority state, explicit migration, restart recovery, backup, clean-root
  restore, redaction, portability, performance, supply-chain and removal evidence.
- Catalogue mappings for `REQUEST-001`, `SEC-002` and `SEC-003`.

### Out of Scope

- Complete `IntentRequest`, `PolicySnapshot` or `CapabilityReport` contracts.
- Registered-trigger issuance, autonomous scheduling and R7 behavior.
- Real request-edge/chat/PWA transport, TLS session establishment or notification
  delivery.
- Real WebAuthn/passkey enrollment, origin validation, recovery or assertion processing.
- Production workload PKI, IPC, supervisor, PAUSE provider, OS driver, adapter
  execution, host effect, verification, compensation or settlement.
- Changes to PLAN-001 wire bytes, PLAN-003 replay semantics or protected legacy runtime
  files.
- Legacy authority migration by assertion, caller-provided positive state or synthetic
  booleans as authority.
- R2/full-machine activation, secure erasure, physical power-loss durability or Tier-1
  production claims.

## Dependencies

- The HelixOS Constitution 2.0 authority, durability, privacy, portability, lifecycle
  and evidence rules.
- PLAN-001 canonical signed plans and immutable plan bindings.
- PLAN-002 eligibility and closed lease/authorization view interfaces.
- PLAN-003 durable plan replay as a separate replay domain.
- PLAN-004 ordered guards and final authority comparison.
- PLAN-005 one-shot dispatch and its explicit requirement for this separately specified
  signed-authority migration.
- Trusted clock/epoch, signer trust, policy/catalogue, workload and supervisor-state
  providers. Deterministic stand-ins are permitted only for conformance evidence.

## Constitution Constraints *(mandatory)*

- **Boundary and authority**: The agent, caller, transport, legacy runtime state,
  synthetic booleans and caller-provided rows are untrusted. The feature introduces only
  the exact signed grant, core-issued restrictive lease and plan-bound terminal decision
  authority. Forgery, replay, cross-context use and one-axis widening must deny before a
  positive projection or durable downstream mutation.
- **Durability and recovery**: Grant consumption/root issuance, delegation/allocation
  and terminal decision retention become durable atomically before positive projection.
  Uncertain commit permits one exact readback and never blind retry. Backup is
  checkpoint-bound; clean-root restore starts paused under new epochs and revives no
  nonterminal authority. No host effect is performed by this feature.
- **Data and secrets**: Signed authority contains identifiers, digests, limits and
  redacted authentication-evidence references, never raw messages, authentication
  assertions, bearer tokens, private keys or native paths. Public errors and evidence
  use closed codes; version 1 retains authority history without pruning and performs no
  egress.
- **Portability**: Common contracts and outcomes are platform-independent and unchanged
  across macOS arm64, Linux x64 and Windows x64. Unsupported schema, trust, storage or
  durability capability is refused rather than replaced by a weaker fallback.
- **Performance and budgets**: The declared reference profile measures warmups,
  repetitions, percentiles and raw samples. Authority verification and durable
  transitions have explicit p95/p99 limits; duplicate floods are bounded while the
  revocation/status control lane remains available. Lease budgets and counters are
  allocated before delegation and cannot be reset by an agent.
- **Audit and lifecycle**: Atomic transitions retain redacted events and exact signed
  bytes. Release evidence pins the exact commit, toolchain, dependency inventory,
  licenses, advisories, provenance, migration, restore and removal results. Removal
  preserves PLAN-001 through PLAN-005 and historical verification, and no catalogue
  claim becomes accepted before its own evidence gate passes.
