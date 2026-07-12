# Contract: Durable Preparation v1

**Contract ID**: `helixos.durable-preparation/1`
**Acceptance ID**: `PLAN-004`
**Status**: implementation and local validation in progress

## 1. Scope

This contract consumes exactly one `EligiblePlanV1` and may create exactly one durable,
non-dispatchable `PREPARING` operation. It coordinates:

- complete preliminary and guarded final authority comparison;
- exact read-only verification of the permanent replay claim;
- one existing authoritative budget scope and one atomic reservation;
- verified recovery material or explicit authenticated irreversibility;
- one coordinator SQLite transition and preparation event.

It does not create `DISPATCHING`, an `ExecutionGrant`, adapter input, target mutation,
effect receipt, settlement or compensation execution.

## 2. Crate boundary

### `helix-plan-preparation`

Portable synchronous orchestration and contract types. It owns:

- `PreparationAuthoritySourceV1` and guard traits;
- `ReplayClaimVerifierV1` use;
- `RecoveryProviderV1` use;
- `PreparationStoreV1` use;
- deterministic first-failure ordering;
- `PreparationOutcomeV1` and opaque `PreparedOperationV1`.

It contains no native path, SQLite connection, network, async runtime, ambient clock or
provider implementation.

### `helix-coordinator-sqlite`

Host storage adapter implementing `PreparationStoreV1`, v1 budget provisioning,
quarantine/maintenance, online backup and clean restore. It owns native paths and
SQLite details but never exposes them through portable values or errors.

Its default public restore surface is exactly the non-constructible, payload-free
`VerifiedPreparationRestoreV1` and `RestoredPreparationMaintenanceEvidenceV1`
projections, with no public producer. Restore acceptance/validation, old-authority
reconciliation, quarantine, maintenance limits/errors and every PAUSE, fencing,
recovery, trust/revocation or no-dispatch authority type, constructor and operation
remain crate-internal. Hidden non-default conformance entrypoints are test evidence only
and return no root, binding, path, guard or activation authority.

## 3. Required interfaces

The signatures below are semantic Rust sketches, not implementation source.

```rust
pub trait PreparationAuthoritySourceV1: Send + Sync {
    fn capture_preliminary(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> PreparationContextV1;

    fn acquire_final_guards(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardAcquisitionV1;
}

pub trait PreparationStoreV1: Send + Sync {
    fn preflight_operation_and_budget(
        &self,
        input: &PreparationPreflightInputV1<'_>,
    ) -> PreparationPreflightOutcomeV1;

    fn commit_preparing<G: FinalCommitGateV1>(
        &self,
        input: &PreparationCommitInputV1<'_>,
        final_gate: &mut G,
    ) -> PreparationCommitOutcomeV1;

    fn readback_attempt(
        &self,
        input: &PreparationReadbackInputV1<'_>,
    ) -> PreparationReadbackOutcomeV1;

    fn fail_before_dispatch<G: NoDispatchAuthorityGuardV1>(
        &self,
        input: &PreparationFailureInputV1<'_>,
        no_dispatch_guard: &mut G,
    ) -> PreparationFailureOutcomeV1;
}
```

The replay and recovery interfaces are defined in
[`authority-compare-v1.md`](authority-compare-v1.md) and
[`recovery-provider-v1.md`](recovery-provider-v1.md). Budget semantics are defined in
[`budget-reservation-v1.md`](budget-reservation-v1.md).

## 4. Ownership and construction rules

1. `prepare_plan_v1` accepts `EligiblePlanV1` by value. No borrowed plan, envelope,
   receipt, status row or boolean substitutes for it.
2. The attempt ID is generated inside trusted orchestration before recovery publication.
3. Contexts, guards, replay verification, budget receipts, recovery receipts and the
   prepared marker have no agent-callable public constructors.
4. Provider/store traits are trusted host wiring. They are never implemented, selected
   or parameterized by an agent request.
5. `PreparedOperationV1` is non-Clone, non-Serde and has no adapter conversion. Its
   public `Debug` is exactly redacted. It owns the deliberately consumed
   `EligiblePlanV1` plus opaque exact commit custody.
6. A durable row obtained after restart is status/evidence only. This contract does not
   recreate a positive marker from arbitrary lookup.

## 5. Preparation algorithm

The coordinator performs the following ordered algorithm.

### Phase A - Preliminary comparison

1. Validate the API/contract versions and generate one fresh attempt ID.
2. Capture one complete preliminary context.
   Match `PreparationContextV1` exhaustively before reading any ready field:
   `Unavailable`, `Incomplete`, `Torn` and `Unsupported` return their distinct context
   denials, while an unknown contract/value version returns
   `PREPARATION_VERSION_UNSUPPORTED`. No negative state reaches replay, preflight or
   recovery.
3. Apply the first-failure order through all authority fields.
4. Verify exclusive UTC/monotonic bounds and capability freshness.
5. Verify the exact permanent replay row through the eligibility-built read-only view.
   Missing, conflicting, unavailable or unhealthy replay state returns before any store
   preflight or recovery-provider call.
6. Run the store's read-only operation/budget preflight. Check operation/attempt identity
   first, then prove the existing scope binding, generation, currency, price table,
   checked arithmetic and current capacity. Return only a non-authoritative preflight
   receipt; do not reserve or mutate.
7. If any step fails, return `Denied` with zero coordinator mutation and do not call the
   recovery provider.

### Phase B - Recovery publication

1. For compensation, acquire the operation-scoped recovery publication guard and run
   the manifest-last protocol. Verify exact receipt binding and retain the guard.
2. For authenticated L2 irreversibility, construct fixed no-material evidence and do
   not call the provider.
3. Classify provider outcomes exactly once. A profile, version, binding or authenticated-
   irreversibility mismatch is `Denied` with the corresponding recovery code. A result
   definitively proving create, durability or publication failure is
   `Failed(PREPARATION_RECOVERY_UNAVAILABLE)`. A missing, untrusted or unclassifiable
   publication result is `Ambiguous(PREPARATION_AMBIGUOUS)`. Possible material is
   quarantined in the latter two cases; no case fabricates an operation, permits
   immediate retirement or treats published material as operation authority.

### Phase C - Guarded final comparison

1. Acquire all mutable authority guards in the order frozen by
   `authority-compare-v1.md`; each wait uses the caller's absolute monotonic deadline.
2. Capture a new final context after all external guards are held.
3. Compare every carried eligibility binding and effective bound field-by-field.
4. Repeat exact PLAN-003 replay-row verification while the final guard set is held.
5. Repeat the read-only operation/budget preflight in the same first-failure order.
   This is still non-authoritative; the writer transaction repeats it after serialization.
6. Reopen/revalidate the recovery receipt while holding the publication guard.
7. Sample UTC and monotonic time again; equality with an exclusive bound denies.
8. On mismatch/revocation/unavailability, release guards in reverse order. The permanent
   replay claim remains consumed and published recovery stays quarantined until guarded
   reconciliation.

### Phase D - Coordinator transaction

1. Acquire the coordinator writer last using a deadline-bounded `BEGIN IMMEDIATE`.
2. Verify exact application/schema/durability identity, provisioner-attested root
   identity, `ACTIVE` root lifecycle and lightweight invariants.
3. Check operation ID and attempt uniqueness.
4. Load the existing budget scope and compare lease, binding, generation, currency and
   price-table identity.
5. Perform checked aggregate capacity predicates for cost/action/egress/recovery bytes.
6. Publish exactly the canonical positive coordinator commit set in one transaction:

   1. advance the enclosing coordinator store/operation/budget/event generations;
   2. insert `prepared_operations(state = PREPARING)`;
   3. insert the permanent `ABSENT -> PREPARING` `operation_transitions` row;
   4. insert the exact `preparation_comparisons` row, including replay evidence;
   5. apply the exact `budget_scopes` held-vector delta;
   6. insert `budget_reservations(state = HELD)`;
   7. insert `preparation_recovery_evidence` containing either the immutable recovery
      reference or exact irreversibility evidence;
   8. insert `preparation_events(kind = PREPARED, delivery = PENDING)`.

   All eight logical members become visible in one SQLite commit or none becomes
   visible. External recovery bytes, replay-store state and supervisor state are not
   members of this transaction.
7. After all writes are staged, call `final_gate.enter_commit_permit(...)`. It
   revalidates every guard/time bound and obtains one short supervisor-owned permit that
   total-orders PAUSE/HALT activation against the actual SQLite commit. The independent
   supervisor deadman owns its lease, whose absolute deadline is
   `min(caller_deadline, permit_entry_monotonic + 250 ms)`, and resolves owner loss,
   process loss or equality with that deadline to ambiguous PAUSE.
8. Commit once through the permit's one-shot method. Acknowledged commit or confirmed
   rollback resolves the permit immediately; confirmed rollback never enters readback.
   Only an explicitly `UNCERTAIN` return stays
   `COMMIT_IN_FLIGHT` only for the bounded exact-readback window; the coordinator or
   independent deadman must then resolve it. Lost acknowledgement is explicitly
   `UNCERTAIN`; a missing/untrusted classification resolves ambiguous immediately with
   zero worker readback and is never definite absence. Process `Drop` is not a durability
   mechanism. No mutation retry is permitted after mutation begins.

| Store observation | Permit action | Readback | Outcome |
|---|---|---:|---|
| acknowledged commit | resolve committed | no uncertain readback | final checks, then `Prepared` or `Ambiguous` |
| confirmed rollback | resolve aborted immediately | none | `Failed(PREPARATION_STORE_COMMIT_ABORTED)` |
| explicit `UNCERTAIN` | remain `COMMIT_IN_FLIGHT` within bound | exactly one | section 8 classification |
| missing/untrusted classification | resolve ambiguous; activate PAUSE | none | `Ambiguous(PREPARATION_AMBIGUOUS)` |

Store open, writer or profile failures that definitely occur after store entry and
before commit map to the corresponding `Failed(PREPARATION_STORE_*)`; preliminary
operation/budget snapshot failures remain authority-specific `Denied` codes.

### Phase E - Acknowledgement/readback

1. After acknowledged commit and `RESOLVED_COMMITTED`, recheck deadline and guard state.
   If still valid, construct one `PreparedOperationV1`.
2. On a store result explicitly classified `UNCERTAIN` (including lost acknowledgement), close
   the uncertain connection and run one exact fresh readback while the permit remains
   `COMMIT_IN_FLIGHT` and the recovery guard is retained. Exact timely proof resolves
   committed or aborted; failed/late proof or the independent deadman resolves ambiguous
   and activates PAUSE.
3. Return a positive marker only for the same attempt when all rows are exact and the
   final deadline/guards remain valid.
4. Any unclassifiable result is `Ambiguous`; no budget release or material retirement
   occurs.
5. Release every guard in reverse order.

## 6. Normative first-failure order

For one fixed captured case, the first matching class wins:

1. context health and contract version;
2. UTC/monotonic time, boot, admission, supervisor and revocation;
3. signer trust, workload, lease, authorization, policy, catalogue and capabilities;
4. exact replay row;
5. operation/attempt identity;
6. budget scope/binding/arithmetic/capacity;
7. recovery profile/receipt/publication;
8. coordinator store open/schema/durability/commit/readback.

The authoritative leaf order and exact field/fault-to-code mapping are in
[`authority-compare-v1.md` section 6.1](authority-compare-v1.md#61-normative-leaf-fault-to-code-mapping).
Native provider timing or error strings never select a public code.

## 7. Closed outcomes

### `PreparationOutcomeV1`

```text
Prepared(PreparedOperationV1)
Denied(PreparationDenialV1)
Failed(PreparationFailureV1)
Ambiguous(AmbiguousPreparationV1)
```

- `Prepared`: exact same-attempt commit/readback plus still-current guards/deadline.
- `Denied`: a closed pre-transition authority/version/binding/identity/capacity/evidence
  refusal.
- `Failed`: one closed definite operational failure after recovery work or store entry
  begins, with no positive marker. It may retain published orphan maintenance custody
  without exposing its identity publicly.
- `Ambiguous`: possible commit or inconsistent/unavailable readback. It is never
  definite absence and never triggers automatic retry/release.

`PreparationDenialV1` owns only context/version, time/supervisor/guard, eligibility-
binding, replay, operation-authority, budget and recovery-binding/unverified/profile
refusals. `PreparationFailureV1` is closed as follows:

| Variant | Stable code |
|---|---|
| `RecoveryProviderFailed` | `PREPARATION_RECOVERY_UNAVAILABLE` |
| `StoreUnavailable` | `PREPARATION_STORE_UNAVAILABLE` |
| `StoreBusy` | `PREPARATION_STORE_BUSY` |
| `StoreUnhealthy` | `PREPARATION_STORE_UNHEALTHY` |
| `StoreConflict` | `PREPARATION_STORE_CONFLICT` |
| `CommitAborted` | `PREPARATION_STORE_COMMIT_ABORTED` |
| `DefiniteAbsence` | `PREPARATION_STORE_DEFINITE_ABSENCE` |

`AmbiguousPreparationV1` has the closed internal reasons
`RecoveryPublicationUnclassified`, `CommitClassificationMissing`,
`PermitOwnerOrProcessLost`, `PermitDeadlineReached`, `ReadbackUnavailable`,
`ReadbackInconsistent` and `ReadbackLateOrRevoked`; every reason exposes only
`PREPARATION_AMBIGUOUS` and opaque quarantine custody publicly.

### Stable public codes

The minimum v1 code set is:

```text
PREPARATION_CONTEXT_UNAVAILABLE
PREPARATION_CONTEXT_INCOMPLETE
PREPARATION_CONTEXT_TORN
PREPARATION_CONTEXT_UNSUPPORTED
PREPARATION_CONTEXT_MISMATCH
PREPARATION_VERSION_UNSUPPORTED
PREPARATION_CLOCK_MISMATCH
PREPARATION_TIME_EXPIRED
PREPARATION_DEADLINE_MISMATCH
PREPARATION_DEADLINE_REACHED
PREPARATION_BOOT_MISMATCH
PREPARATION_SUPERVISOR_MISMATCH
PREPARATION_SUPERVISOR_DENIED
PREPARATION_GUARD_REVOKED
PREPARATION_TRUST_MISMATCH
PREPARATION_WORKLOAD_MISMATCH
PREPARATION_LEASE_MISMATCH
PREPARATION_AUTHORIZATION_MISMATCH
PREPARATION_POLICY_MISMATCH
PREPARATION_CATALOGUE_MISMATCH
PREPARATION_CAPABILITY_MISMATCH
PREPARATION_REPLAY_MISSING
PREPARATION_REPLAY_CONFLICT
PREPARATION_REPLAY_UNAVAILABLE
PREPARATION_REPLAY_UNHEALTHY
PREPARATION_OPERATION_CONFLICT
PREPARATION_ALREADY_PREPARED
PREPARATION_OPERATION_AUTHORITY_UNAVAILABLE
PREPARATION_BUDGET_SCOPE_MISSING
PREPARATION_BUDGET_AUTHORITY_UNAVAILABLE
PREPARATION_BUDGET_BINDING_CONFLICT
PREPARATION_BUDGET_EXHAUSTED
PREPARATION_BUDGET_ARITHMETIC_INVALID
PREPARATION_RECOVERY_UNAVAILABLE
PREPARATION_RECOVERY_BINDING_CONFLICT
PREPARATION_RECOVERY_UNVERIFIED
PREPARATION_RECOVERY_PROFILE_UNAPPROVED
PREPARATION_STORE_UNAVAILABLE
PREPARATION_STORE_BUSY
PREPARATION_STORE_UNHEALTHY
PREPARATION_STORE_CONFLICT
PREPARATION_STORE_COMMIT_ABORTED
PREPARATION_STORE_DEFINITE_ABSENCE
PREPARATION_AMBIGUOUS
```

`Debug`, `Display` and optional `Error::source` expose only the stable code/variant.

`PREPARATION_RECOVERY_UNAVAILABLE` and all `PREPARATION_STORE_*` codes belong only to
`PreparationFailureV1`. `PREPARATION_AMBIGUOUS` belongs only to
`AmbiguousPreparationV1`. Every other listed code belongs only to
`PreparationDenialV1`; raw error strings cannot move a result between classes.

`PREPARATION_OPERATION_AUTHORITY_UNAVAILABLE` is the preliminary operation-class denial
when the read-only snapshot cannot first prove operation identity. After identity is
proved, `PREPARATION_BUDGET_AUTHORITY_UNAVAILABLE` means that snapshot cannot prove the
existing scope. Store codes in the final class refer to the later writer/schema/commit/
readback phase; this preserves operation -> budget -> recovery -> durable-store ordering
without doing sensitive recovery work for already unprovable authority.

## 8. Exact readback

Readback uses operation ID, attempt ID, permanent transition generation, reservation ID
and event ID in one healthy consistent snapshot and classifies:

| Classification | Required proof | Public result |
|---|---|---|
| `THIS_ATTEMPT` | all rows exact and invariant-valid | `Prepared` only if final guards/deadline remain valid; otherwise `Ambiguous(PREPARATION_AMBIGUOUS)` |
| `PRIOR_EXACT_ATTEMPT` | one coherent prior attempt occupies the operation | `Denied(PREPARATION_ALREADY_PREPARED)` |
| `CONFLICT` | a full healthy snapshot proves one coherent incompatible occupant and excludes this attempt | `Denied(PREPARATION_OPERATION_CONFLICT)` |
| `DEFINITE_ABSENCE` | all attempt/operation/reservation/transition/event keys absent after full healthy verification and no in-flight same-operation publisher | `Failed(PREPARATION_STORE_DEFINITE_ABSENCE)` |
| `AMBIGUOUS` | unavailable, unhealthy, partial, contradictory, late or revoked proof | `Ambiguous(PREPARATION_AMBIGUOUS)` |

Readback never manufactures an eligibility marker, replay receipt, budget receipt or
recovery receipt. `DEFINITE_ABSENCE` exists only after an explicit `UNCERTAIN` result;
confirmed rollback does not enter this table. Neither result revives the consumed
replay claim, retries the plan, releases a reservation or retires recovery material
automatically.

## 9. Known pre-dispatch failure contract

`fail_before_dispatch` is privileged and accepts only a verified coherent
`PREPARING` record plus a mutable borrow of `NoDispatchAuthorityGuardV1`. Trusted
supervisor/dispatch-authority wiring creates the opaque guard; it binds the operation,
attempt, current state generation, boot/instance/fencing epochs, revocation generation
and deadline and proves no grant, dispatch transition or in-flight dispatch authority.
It remains live through one transaction:

```text
PREPARING -> FAILED
append permanent PREPARING -> FAILED transition generation
HELD -> RELEASED
scope held totals -= exact stored vector once
append PREPARATION_FAILED/PENDING event
```

Exact repeated calls read the terminal tombstones and do not subtract/append twice.
Caller assertions, booleans, row absence and missing/mismatched/expired/revoked guards
mutate nothing. Replay remains claimed. The guard is not persisted or reconstructible
from the resulting transition/event. External recovery retirement is a later guarded
provider action and cannot roll the operation back to `PREPARING`.

## 10. Quarantine and restore

- Quarantine is separate maintenance evidence, not an operation state.
- Ambiguous commit, orphan material, invariant conflict and restored old authority may
  create/retain quarantine evidence; none can return a marker.
- A true orphan may retire only after guarded definitive proof excludes every operation,
  attempt, reservation, event, in-flight permit and active ambiguity reference. The
  coordinator records a permanent `ORPHAN_RETIREMENT_AUTHORIZED` tombstone before
  provider retirement and never fabricates an operation. Pending retirement blocks
  backup and later records the exact provider tombstone digest.
- Restore verifies the detached provisioner-signed provenance attestation against pinned
  trust before publishing either destination root. Coordinator and recovery metadata
  independently persist the same restore ID/attestation digest and `RESTORE_PENDING`;
  disagreement quarantines.
- Ordinary open, prepare and recovery-retirement deny on either pending root. Restore
  requires PAUSE plus new boot, instance and fencing epochs, and Feature 004 cannot
  activate either root.
- Restored `PREPARING` is historical. It can become `FAILED` under maintenance or remain
  quarantined; it cannot be rebound, resumed or dispatched by this contract.
- The default public crate surface exposes only the two redacted evidence projections
  named in section 2 and no producer. Package acceptance, validation, reconciliation,
  quarantine, maintenance limits/errors and sovereign custody remain crate-internal.
- A later operation needs a new signed plan and new replay claim.

## 11. Data and retention

- Canonical plan and recovery data are restricted and never enter agent/model memory,
  Graphify, logs, fixtures, public events or egress.
- Production roots require an approved encrypted-at-rest provisioning profile; this
  contract carries no encryption key or raw credential.
- V1 has no pruning API. Operation/canonical plan, failed rows, released reservations,
  delivered events, quarantine and retirement tombstones are retained indefinitely.
- Operation-bound recovery bytes retire only after durable `FAILED`, exact budget
  reconciliation, exclusive cleanup guard and definite non-reference proof. True-orphan
  bytes use the separate permanent-resolution path above.
- Physical secure erasure is not claimed. Shorter retention requires a later versioned
  policy/amendment.

## 12. Adapter/source prohibition

Production source and dependency tests must prove that no effect adapter, legacy driver,
MCP shim or dispatch module depends on:

- `PreparedOperationV1`;
- budget or recovery receipts;
- coordinator preparation rows/events;
- quarantine or restore evidence.

No API in this contract accepts an adapter, signs a grant, resolves a native target or
produces an effect.

## 13. Versioning

- Contract ID and all value versions are exactly v1.
- Unknown fields/variants/combinations deny.
- Schema migration is empty-to-v1 only. Newer stores fail closed; incompatible downgrade
  is refused.
- Changes to signed plan bytes require a new PLAN-001 wire version and are not a v1
  migration.
- Adding `DISPATCHING`, broader budgets or production platform recovery requires a later
  feature/contract version.

## 14. Closed v1 fault-boundary inventory

The following inventory is closed and exhaustive for v1. Fault injection occurs
immediately after every listed boundary and immediately before every call that may
publish into another durability domain. Each slash-separated action is an independent
boundary. A new comparison, mutation, publication or acknowledgement boundary must be
added here and to the frozen corpus before implementation may rely on it.

```text
PRELIMINARY
attempt identity generated
preliminary context returned
each preliminary first-failure group classified
preliminary replay snapshot opened / classified
preliminary preflight snapshot opened
preliminary operation identity classified
preliminary budget binding / arithmetic / capacity classified

RECOVERY
publication guard acquired
staging created / written / synchronized / closed / reopened
material digest-length-capacity verified
material published
manifest staged / synchronized / published / reopened
recovery receipt returned

FINAL COMPARISON
each final guard acquired
final context returned
each final first-failure group classified
final replay snapshot opened / classified
final preflight snapshot opened
final operation identity classified
final budget binding / arithmetic / capacity classified
recovery receipt reopened / revalidated
final UTC sample returned / final monotonic sample returned

POSITIVE COORDINATOR COMMIT
coordinator root/profile/invariants accepted
BEGIN IMMEDIATE acquired
operation-attempt identity classified
budget scope loaded / final arithmetic-capacity classified
each member of the canonical positive coordinator commit set staged
enter_commit_permit returned
permit moved to COMMIT_IN_FLIGHT
SQLite commit invoked / returned with trusted classification
permit resolved committed / aborted / ambiguous

ACKNOWLEDGEMENT AND READBACK
uncertain connection closed
readback snapshot opened
readback classified THIS_ATTEMPT / PRIOR_EXACT_ATTEMPT / CONFLICT /
  DEFINITE_ABSENCE / AMBIGUOUS
post-commit time classified / post-commit guards classified
positive marker constructed / result returned
all final guards released

KNOWN FAILURE
no-dispatch guard acquired / finally revalidated
failure BEGIN IMMEDIATE acquired
operation FAILED staged
failure transition staged
scope held subtraction staged
reservation RELEASED staged
failure event staged / failure metadata staged
failure commit returned / classified
no-dispatch guard released

QUARANTINE AND RETIREMENT
quarantine inserted / resolved
operation-bound RETIREMENT_PENDING committed
true-orphan definitive proof returned
orphan-resolution RETIREMENT_PENDING tombstone committed
provider retirement invoked / bytes retired
retirement manifest published
operation-bound RETIRED_TOMBSTONE committed / orphan RETIRED_TOMBSTONE committed

BACKUP
PAUSE persisted
provider maintenance guard acquired
coordinator maintenance guard acquired
source profiles/invariants verified
source generations captured
SQLite online backup completed / closed / integrity-checked / hashed
provider enumeration reconciled
each material-present package exported
each retirement tombstone exported
inventory JCS finalized
source generations rechecked
top-level manifest staged / published
attestation protected JCS finalized / signed / staged / published / reopened / verified

RESTORE
package and pinned provenance accepted
empty coordinator root reserved
empty recovery root reserved
coordinator database imported / WAL-FULL profile established
each recovery package imported
coordinator database RESTORE_PENDING SQLite committed
coordinator root EXISTING marker published
recovery RESTORE_PENDING metadata published
both roots closed / reopened / agreement classified
VerifiedPreparationRestoreV1 returned / quarantine persisted
```
