# Feature Specification: Durable Replay Claim Store

**Feature Branch**: `003-durable-replay-store`

**Created**: 2026-07-10

**Status**: Draft

**Input**: User description: "Continue building the robust, performant, cross-platform
agentic OS, using Graphify for project memory and SpecKit for specification, tasks and
implementation."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Permanently claim one eligible plan (Priority: P1)

As the plan-eligibility evaluator, I can use a production replay claimant whose positive
receipt proves that both replay keys were durably committed for the exact eligibility
binding, so a process restart cannot make the same plan eligible a second time.

**Why this priority**: Feature 002 deliberately exposes only a test claimant. Until a
durable implementation exists, eligibility cannot safely feed a coordinator.

**Independent Test**: Claim a fresh binding, close and reopen the store, then submit the
same binding and bindings that reuse either uniqueness key. The first call alone returns
`Claimed`; the exact repeat returns `AlreadyClaimed`; either conflicting reuse returns
`BindingConflict`.

**Acceptance Scenarios**:

1. **Given** a healthy empty store and an unexpired binding, **When** it is claimed,
   **Then** both `(instance_epoch, nonce)` and `operation_id` become durable in one
   linearization point and the returned receipt matches the exact binding digest.
2. **Given** that claim and a completely restarted process, **When** the exact binding is
   submitted again, **Then** the result is `AlreadyClaimed` and no new receipt or
   generation is created.
3. **Given** either uniqueness key is already bound to different compared evidence,
   **When** a contender submits the conflicting binding, **Then** the result is
   `BindingConflict` and neither index changes.
4. **Given** a definite failure before a transaction can mutate replay state, **When** a
   claim is attempted, **Then** the result is `Unavailable` and the binding remains
   unclaimed.

---

### User Story 2 - Resolve concurrent claims within a deadline (Priority: P2)

As the coordinator owner, I can allow multiple threads or local processes to contend for
replay state without a split-brain winner, an unbounded queue, or a retry that silently
outlives the caller-owned monotonic deadline.

**Why this priority**: The replay store is a sovereign admission boundary. Contention or
temporary storage locks must not create two eligible instances or stall control work
indefinitely.

**Independent Test**: Start synchronized contenders from independent connections and
processes against identical, conflicting and independent bindings with bounded
deadlines, then verify the closed outcomes, durable rows and elapsed-time bounds.

**Acceptance Scenarios**:

1. **Given** 64 simultaneous contenders for the same fresh binding, **When** they start
   together, **Then** exactly one returns `Claimed`, every other definitive result is
   `AlreadyClaimed`, and one durable claim exists after reopen.
2. **Given** contenders sharing only a nonce key or only an operation key, **When** they
   race, **Then** at most one returns `Claimed`, all incompatible winners return
   `BindingConflict`, and the two indexes remain mutually consistent.
3. **Given** storage remains busy until the monotonic claim deadline, **When** the call
   cannot begin a mutation, **Then** it returns `Unavailable` within the configured
   tolerance and does not retry in the background.
4. **Given** independent bindings and available capacity, **When** they contend, **Then**
   each may commit exactly once without changing the semantics of any other binding.

---

### User Story 3 - Recover honestly from crashes and uncertain commits (Priority: P3)

As an operator, I can distinguish a definitely uncommitted claim from a possibly
committed claim, reopen the store after a crash, and reconcile uncertainty without
blindly replaying sovereign admission.

**Why this priority**: A crash around commit is the dangerous boundary. Reporting a
possibly committed attempt as merely unavailable could authorize a duplicate effect
later.

**Independent Test**: Run a child process with deterministic fault points before the
first write, after each write, immediately before commit, immediately after commit and
after acknowledgement; terminate it at each point, reopen from another process, and
compare caller outcome with durable state.

**Acceptance Scenarios**:

1. **Given** a crash before any mutation or after a confirmed rollback, **When** the
   store is reopened, **Then** no partial index or receipt exists and a later fresh claim
   may proceed.
2. **Given** an error or deadline after commit may have started, **When** a definitive
   readback cannot prove the result, **Then** the caller receives `Ambiguous` and no
   automatic retry occurs.
3. **Given** a post-commit transport or acknowledgement fault, **When** a fresh storage
   view proves the exact attempt receipt was committed while the monotonic deadline is
   still valid, **Then** the implementation may return `Claimed`; if proof is unavailable
   or the deadline has been reached it returns `Ambiguous`, never `Unavailable`.
4. **Given** any crash point, **When** integrity is checked after reopen, **Then** the
   store contains either both uniqueness bindings plus their receipt or none of them.

---

### User Story 4 - Back up, restore and operate portably (Priority: P4)

As an operator preparing HelixOS for macOS Apple Silicon while retaining Linux and
Windows compatibility, I can create a consistent online backup, restore it into an empty
directory, validate it before activation, and run the same behavior suite on every
supported host.

**Why this priority**: Durability is incomplete without a supported restore path, and a
Windows-only success cannot establish the Mac mini M4 target.

**Independent Test**: Back up a live store while claims continue, restore into a clean
directory, run integrity and schema checks, reopen it, and replay the same conformance
corpus unchanged on Windows x64, Linux x64 and macOS arm64.

**Acceptance Scenarios**:

1. **Given** a live store with committed claims, **When** an online backup completes,
   **Then** the backup has a verifiable manifest and contains a transactionally
   consistent generation without copying an active journal as an ad hoc file set.
2. **Given** a valid backup and an empty destination, **When** restore verification
   completes, **Then** every claim up to the declared backup generation retains the same
   conflict behavior and the result explicitly requires paused activation plus external
   instance/fencing-epoch rotation.
3. **Given** an unsupported newer schema, a corrupt store, an incomplete backup or a
   non-empty restore destination, **When** open or restore is requested, **Then** it
   fails closed without accepting claims or overwriting evidence.
4. **Given** the same fixtures and test commands on all three supported operating-system
   families, **When** conformance runs, **Then** outcomes and durable invariants are
   identical without platform-specific policy branches.

### Edge Cases

- The monotonic deadline is already reached, is reached while waiting for a writer, is
  reached after the first write, or cannot be read from the trusted clock.
- The claimant generation is at its maximum safe value and cannot be incremented.
- Only the nonce index, only the operation index, the receipt, or store metadata appears
  present because of corruption or unsupported manual modification.
- The same binding digest appears under a different operation ID or nonce tuple.
- Two independent processes initialize the same empty store concurrently.
- A process is terminated during schema initialization, migration, backup, checkpoint,
  restore verification, or claim commit.
- The disk becomes full, read-only, disconnected or reports an I/O error before a write,
  during journal synchronization, during commit, or during checkpoint.
- A backup is older than claims that existed before host loss; restoring it must not be
  mistaken for proof that those later claims never happened.
- The database is placed on a network share, cloud-synchronized directory, removable
  filesystem with unknown guarantees, or another unvalidated location.
- A path contains valid non-ASCII host characters; paths remain confined to this native
  storage boundary and never enter portable plan contracts or logs.
- A caller opens the store with incompatible durability, deadline, namespace or schema
  expectations.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The feature MUST provide a production implementation of the existing
  `ReplayClaimantV1` contract without changing the contract's five closed outcomes or
  broadening what an `EligiblePlanV1` authorizes.
- **FR-002**: A new claim MUST atomically create one permanent record binding both
  `(instance_epoch, nonce)` and `operation_id` to the exact replay binding digest and one
  receipt. No observer may see only one uniqueness binding.
- **FR-003**: Exactly one fresh attempt MAY return `Claimed` for either uniqueness key.
  A committed claim MUST never be released, overwritten or recycled during normal
  operation.
- **FR-004**: An exact prior match across both keys and binding evidence MUST return
  `AlreadyClaimed`, MUST NOT return the original receipt as positive admission, and MUST
  NOT advance the claimant generation.
- **FR-005**: Any prior occupation of either key by different binding evidence MUST
  return `BindingConflict`; the attempt MUST NOT change either existing binding or
  create the missing counterpart.
- **FR-006**: A partial, contradictory or structurally invalid persisted binding MUST be
  treated as unhealthy storage and fail closed; it MUST NOT be repaired automatically
  by a claim attempt.
- **FR-007**: Each attempt MUST receive a fresh collision-resistant internal identity.
  Each new receipt MUST contain the corresponding opaque claim ID, the exact binding
  digest and a non-zero safe claimant generation that increases strictly for every
  newly committed claim and survives reopen, backup and restore.
- **FR-008**: Generation allocation, receipt creation and both uniqueness constraints
  MUST share the same atomic commit boundary. Generation exhaustion MUST be detected
  before mutation and fail closed.
- **FR-009**: Failure classification MUST be based on the mutation phase, not on
  provider-specific error text: a provably pre-mutation or confirmed-rollback failure
  maps to `Unavailable`; a failure after commit may have started maps to `Ambiguous`
  unless a new definitive storage view proves the exact result.
- **FR-010**: A definitive post-fault readback MAY convert uncertainty only when it can
  prove the exact attempt receipt, an exact prior claim, a binding conflict, or the
  complete absence of both the attempt and either occupied key after confirmed recovery.
  Failed, stale or inconsistent readback MUST remain `Ambiguous`. The implementation
  MUST NOT blindly repeat the write transaction.
- **FR-011**: Claim execution MUST consume a trusted suspend-aware boot-monotonic clock,
  honor `claim_deadline_monotonic_ms`, and perform no mutation when the deadline is
  already reached or the clock is unavailable. It MUST recheck immediately before and
  after commit and MUST NOT return a positive claim after the deadline.
- **FR-012**: Lock waits and internal retries MUST be bounded by the remaining monotonic
  deadline. A return MUST cancel or finish all work for that call; no detached retry may
  later consume replay state. Because a synchronous storage flush cannot be portably
  cancelled inside the operating-system call, the hard elapsed-time acceptance bound
  applies to controlled lock contention; a flush that returns after the deadline MUST
  fail closed as `Ambiguous` and be reported as a late storage operation.
- **FR-013**: The store MUST use a crash-durable commit profile on a caller-validated
  local filesystem, with short transactions and controlled journal checkpoints. It MUST
  refuse startup when required durability settings cannot be established or verified.
- **FR-014**: A local-filesystem assurance is a trusted deployment precondition. An
  unknown, network, cloud-synchronized or otherwise unsupported location MUST be
  rejected by provisioning or opening rather than silently downgraded. The assurance
  MUST include cross-process exclusive file locks, exclusive file creation, same-volume
  hard links and regular-file `sync_all`; lack of any required primitive fails closed.
- **FR-015**: Opening a store MUST validate application identity, schema version,
  durability configuration and mandatory invariants before enabling claims. An unknown
  application ID or newer/incompatible schema MUST fail closed.
- **FR-016**: Schema creation and supported forward migration MUST be transactional,
  restartable and versioned. This initial feature MUST define empty-to-v1 creation and
  explicit refusal of unsupported downgrade or rollback.
- **FR-017**: Maintenance MUST expose a full integrity verification that cannot run
  concurrently with an unsafe mutation. A failed integrity result disables new claims
  across cooperating processes until operator recovery. A fixed, synchronized root-role
  file MUST distinguish `LIVE_READY`, `LIVE_QUARANTINED`, `BACKUP_PACKAGE` and
  `RESTORE_PENDING`; unknown or torn persistent role state fails closed. A distinct
  exclusively-created live-initialization intent MAY recover an interrupted role write
  only while no database or other root member exists; backup/restore reservations MUST
  never be inferred as live intent.
- **FR-018**: Live backup MUST use a storage-consistent online backup/checkpoint
  protocol. Raw copying of an active database and journal pair MUST NOT be presented as
  a supported backup.
- **FR-019**: A backup manifest MUST bind format version, application/schema identity,
  backup generation, integrity result and database digest. It MUST contain no secret or
  raw plan content. A complete v1 package contains exactly the fixed
  `BACKUP_PACKAGE` role file, the closed database and the manifest published last.
- **FR-020**: Restore MUST target a new empty directory, verify the manifest, digest,
  schema and integrity before open, and preserve every claim through the manifest's
  declared generation. It MUST NOT overwrite a live store. The destination remains
  durably `RESTORE_PENDING` with an activation-required marker after WAL/FULL is
  established and reverified; generic open/claim paths MUST reject it.
- **FR-021**: Restored replay data MUST be reported as requiring system `PAUSED` state,
  trigger quarantine and rotation of supervisor-owned instance/fencing epochs before
  later coordinator activation. This feature records and tests that requirement but
  does not implement supervisor authority.
- **FR-022**: A backup cannot prove absence of claims committed after its generation.
  Restore documentation and evidence MUST state this limit and forbid reuse of the old
  active instance epoch.
- **FR-023**: Persisted claim data MUST be limited to bounded identifiers, fixed digests,
  nonces, safe integers, receipt evidence and storage metadata needed for comparison and
  recovery. Signatures, canonical plan bytes, resource paths, user content, credentials
  and raw provider errors MUST NOT be stored.
- **FR-024**: Debug output, errors, metrics and evidence MUST be redacted before
  serialization and MUST NOT expose nonce values, operation/task/workload IDs, binding
  or plan digests, native paths or provider diagnostics.
- **FR-025**: The feature MUST perform no network egress and MUST require no secret. Its
  database, journal, backup and manifest are operational security state with restricted
  host access and operator-defined retention at least as long as the corresponding
  instance/operation evidence can be accepted.
- **FR-026**: Successful claims MUST be retained permanently for the active authority
  history. Offline pruning is out of scope and MUST NOT be enabled without a later spec
  proving that the affected epochs and operations can never be accepted again.
- **FR-027**: Platform-independent behavior, persisted value semantics and conformance
  outcomes MUST be identical on macOS arm64, Linux x64 and Windows x64. Common logic MUST
  NOT contain operating-system-conditioned security or conflict semantics.
- **FR-028**: The same versioned positive, conflict, contention, deadline, corruption,
  crash, migration, backup and restore corpus MUST run unchanged on all supported
  platforms. Platform launch wrappers MAY differ but expected records MUST NOT.
- **FR-029**: Deterministic fault injection MUST cover every mutation and commit boundary
  in a child process. Evidence MUST distinguish process-kill survival from real
  power-loss durability; the former MUST NOT be reported as the latter.
- **FR-030**: The feature MUST publish bounded health and maintenance outcomes suitable
  for a future audit ledger, but MUST NOT claim that logs or Graphify memory are the
  authoritative replay database.
- **FR-031**: A receipt from this store remains only an eligibility prerequisite. It
  MUST NOT be serializable adapter authority, an approval, a budget reservation, a
  `PreparedOperation`, an `ExecutionGrant` or permission to produce a host effect.

### Key Entities

- **Replay Claim Record**: Permanent atomic association of the two replay uniqueness
  keys, the compared binding digest, opaque claim ID and claimant generation.
- **Claim Attempt**: One deadline-bounded invocation with an internal attempt identity
  used only to distinguish a definitively committed attempt from an uncertain commit.
- **Replay Store Metadata**: Application/schema identity, durability profile, current
  claimant generation, migration state and health needed to open fail-closed.
- **Backup Manifest**: Non-secret evidence binding a consistent backup to its schema,
  generation, integrity result and digest, plus the paused-restore activation warning.
- **Maintenance Outcome**: Closed redacted result for initialize, migrate, verify,
  checkpoint, backup or restore operations; it is not a replay claim outcome.

## Scope

### In Scope

- Production durable implementation of `ReplayClaimantV1`.
- Atomic nonce and operation uniqueness, receipt and generation persistence.
- Bounded contention, monotonic deadlines and honest commit ambiguity.
- Initial schema, transactional initialization, integrity checking and controlled
  checkpointing.
- Consistent online backup, clean-directory restore verification and restore evidence.
- Cross-platform conformance, fault injection, redaction and performance evidence.

### Out of Scope

- Atomic comparison of the full `EligiblePlanV1` bindings before `PREPARING`.
- Operation state, budget/counter reservation, recovery pre-images or audit outbox.
- `PREPARING`, `DISPATCHING`, `ExecutionGrant`, adapter inbox/receipt or host effects.
- Supervisor/fencing store implementation, leadership election and restored-system
  activation; this feature only exposes their required restore precondition.
- WebAuthn, approval UI, policy/lease providers and capability re-probe.
- Post-effect verification, settlement, compensation or reconciliation.
- Real power-cut guarantees and the macOS `F_FULLFSYNC` decision, which require a later
  Mac mini M4 hardware spike.
- Network filesystems, cloud-synchronized directories, raw live-file backup and online
  pruning of committed claims.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Across 10,000 fresh sequential claims plus reopen, 100% produce one
  matching durable receipt, exact repeats produce `AlreadyClaimed`, and single-key
  mutations produce `BindingConflict`, with zero partial records.
- **SC-002**: In each of 100 runs with 64 synchronized thread contenders and each of 20
  runs with 8 synchronized process contenders, exactly one fresh contender returns
  `Claimed` and durable verification finds one claim.
- **SC-003**: Every declared pre-write, post-write, pre-commit, post-commit and
  post-acknowledgement process-kill fixture reopens to a valid all-or-none store; no case
  maps a possibly committed write to `Unavailable` or performs an automatic replay.
- **SC-004**: Busy-store tests return every call no later than its caller deadline plus
  50 ms scheduler tolerance, and no claim appears after its call has returned.
- **SC-005**: A live backup restored into a clean directory passes manifest, digest,
  schema and full-integrity verification and reproduces 100% of claim outcomes through
  its declared generation; all corrupt/incomplete/non-empty-destination fixtures fail
  closed.
- **SC-006**: The unchanged conformance suite passes on macOS arm64, Linux x64 and
  Windows x64. Local evidence alone is labeled by its actual OS/hardware and does not
  satisfy the missing platforms.
- **SC-007**: On each measured local-SSD target, 10,000 sequential durable claims after
  500 warmups complete at p95 no slower than 25 ms and p99 no slower than 100 ms, with
  hardware, OS, runtime, durability settings, repetitions and raw evidence recorded.
- **SC-008**: Automated scans and negative tests find zero secret, raw plan, nonce,
  identifier, digest or native-path disclosure in public debug/error/metric outputs and
  zero OS-conditioned semantic branches in common store logic.
- **SC-009**: Dependency, license, vulnerability and provenance checks identify every
  direct/native storage component at an exact reviewed version; restore and rollback
  instructions are exercised before this feature is called production-ready.

## Assumptions

- Feature 001 authentic plan contracts and Feature 002 eligibility/replay contracts are
  immutable prerequisites; the new crate consumes their public API rather than copying
  or weakening it.
- The architecture-selected reference implementation uses SQLite WAL on a supported
  local filesystem with full synchronous durability; the implementation plan must pin
  and justify the exact library/native version.
- The caller supplies a healthy boot-scoped monotonic clock and a deployment-validated
  local store location. Portable filesystem-locality detection is not inferred from an
  agent-provided string.
- One logical replay writer may be backed by multiple local connections/processes, but
  the storage engine serializes the atomic claim transaction and all waits remain
  deadline-bounded.
- Restoring any point-in-time backup may omit later claims. Safe system activation is
  therefore paused, rotates external instance/fencing epochs, quarantines triggers and
  reconciles possible work in a later coordinator feature.
- The p95/p99 objectives are initial engineering budgets, not Tier 1 claims. Real Mac
  mini M4 power-loss/full-flush behavior remains unproven until hardware evidence exists.

## Constitution Constraints *(mandatory)*

- **Boundary and authority**: The agent, plan and identifiers remain untrusted. The only
  new authority is a core-owned permanent replay linearization point; conflicting,
  malformed and unavailable state fails closed. The mandatory abuse test races forged
  variants sharing each uniqueness key and proves one winner without execution power.
- **Durability and recovery**: Both indexes, generation and receipt commit atomically.
  Pre-mutation failure is unavailable; possible commit is ambiguous unless definitive
  readback proves it. Claims are never released, backup is storage-consistent, restore
  is verified and activation remains paused with epoch rotation.
- **Data and secrets**: Replay state is restricted operational security data. No secret,
  raw plan, user content, signature, resource path or egress is needed. Retention covers
  the complete acceptability lifetime and every outward representation is redacted.
- **Portability**: Contract semantics and fixtures are unchanged on macOS arm64, Linux
  x64 and Windows x64. Native paths exist only inside the storage adapter boundary;
  unsupported filesystem guarantees are refused, never weakened.
- **Performance and budgets**: Claim calls are deadline-bounded with no detached retry;
  sequential p95/p99 and contention workloads have explicit thresholds. Saturation,
  busy storage, disk-full and generation exhaustion fail closed.
- **Audit and lifecycle**: Version/schema identity, migration, integrity, checkpoint,
  backup, restore, dependency and benchmark evidence are archived. Rollback refuses
  incompatible schemas; removal requires permanent retirement of affected authority
  epochs and cannot silently prune replay history.
