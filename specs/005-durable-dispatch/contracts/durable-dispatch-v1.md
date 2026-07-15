# Durable Dispatch Protocol v1

## 1. Status and scope

This contract defines PLAN-005's synchronous no-effect transition from one authoritative
PLAN-004 preparation to one durable adapter consumption receipt. It owns:

- coordinator reload and final guarded comparison;
- creation/retention of one signed execution grant;
- effective `PREPARING -> DISPATCHING` overlay transition and outbox;
- exact delivery/redelivery/readback;
- adapter durable receive/consume/refuse and signed receipt;
- coordinator `DISPATCHING -> EXECUTING` or the normative
  `OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED -> FAILED` custody;
- migration, backup/restore and reconciliation evidence.

It does **not** own a real host effect, an execution-token API, verification,
compensation, budget settlement, final success, production IPC/supervisor, legacy kernel
migration, sovereign activation or Tier 1 evidence.

## 2. Trust and storage domains

The following domains are independent:

1. coordinator V2 store and dispatch signer;
2. adapter inbox store and receipt signer;
3. supervisor-owned current epoch observer;
4. transport/handoff implementation;
5. backup provisioner/verifier.

No transaction spans these domains. Correctness uses immutable signed bindings, ordered
guards, exact retained bytes, unique indexes, handoff fencing, readback and
reconciliation. Agent, caller, transport payload and legacy runtime are untrusted.

## 3. Public inputs and positive authority

The public dispatch request contains only:

- contract version;
- bounded operation ID;
- expected plan digest;
- expected preparation attempt digest;
- expected preparation transition generation;
- exclusive caller monotonic deadline.

The request is never positive authority. The coordinator reloads exact durable PLAN-004
state. It rejects restored, quarantined, failed, stale-instance, mismatched or already
overlaid preparation. `PreparedOperationV1`, preparation receipts, caller-created rows,
and legacy kernel scopes/approvals are prohibited inputs.

For this synthetic R1 slice, current lease and human-authorization state is supplied by
trusted versioned views whose generations/digests must equal the PLAN-004 retained
context. Signed `TaskLease`/`HumanRequestGrant`/`ApprovalDecision` migration remains a
separate production/R2 prerequisite.

## 4. Ordered dispatch algorithm

### Phase A - Preliminary reload

1. Validate request syntax/version/deadline without trusting positive fields.
2. Open exact active coordinator V2 root and verify V1 base plus V2 overlay invariants.
3. Load the complete base operation, plan, comparison/replay, reservation, recovery and
   prepared event.
4. Refuse any restored source, non-`PREPARING` base state, existing conflicting overlay,
   missing/partial/torn evidence or expected-binding mismatch.
5. Capture current supervisor, trust, workload, lease, authorization, policy, catalog,
   capability, destination/protocol and dispatch signer views.
6. Generate one dispatch-attempt ID, grant ID and one-shot nonce from coordinator-owned
   entropy. They carry no authority before commit.
7. Build and sign candidate grant bytes with deadline
   `min(all authority bounds, caller bound, issue + 5000 ms)`.

### Phase B - Ordered final guard and comparison

1. Acquire the PLAN-004 global authority guard classes in the same fixed order.
2. Acquire a fresh linearizable dispatch commit permit from the supervisor lane.
3. Repeat the full durable reload and current authority capture.
4. Compare every group, generation, digest, deadline, epoch, destination, signing profile
   and signed grant field against the preliminary candidate.
5. Any mismatch releases guards and creates no dispatch transition or deliverable grant.

### Phase C - Coordinator transaction

While guards and permit remain valid, one short immediate transaction:

1. verifies exact schema/root/generation and absence of a conflicting overlay;
2. appends final comparison evidence;
3. inserts exact canonical signed grant bytes and unique grant/operation/nonce bindings;
4. inserts current `DISPATCHING` overlay record;
5. appends permanent `PREPARING -> DISPATCHING` overlay transition;
6. inserts the exact deliverable outbox row;
7. appends one redacted pending dispatch event;
8. advances all dispatch generations.

Every member commits or none commits. `user_version`, V1 base rows, held reservation and
published recovery material are not rewritten by this initial dispatch transaction.
Transport starts only after commit and writer closure.

Confirmed rollback produces a closed pre-delivery failure. Uncertain commit transfers
the exact attempt to readback; no signing/commit retry occurs. Exact readback returns
absent, this attempt committed, prior exact dispatch, conflict or ambiguous corruption.

### Phase D - Delivery and adapter receive

1. Load the exact retained outbox bytes; never reconstruct or resign.
2. Recheck PAUSE, deadline and handoff fencing.
3. Acquire a linearizable per-grant handoff guard and record the delivery attempt.
4. Deliver exact bytes to the bounded adapter protocol.
5. Adapter strictly decodes/verifies canonical grant, grant signer purpose/trust,
   destination/protocol/capability and independent supervisor epoch.
6. Adapter transaction A inserts create-only grant/operation/nonce and
   `ABSENT -> RECEIVED` plus event before acknowledging durable receive.

`DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`, `CAPABILITY_MISMATCH` and
`INBOX_CAPACITY_EXHAUSTED` reject before `RECEIVED`. Each produces durable local
diagnostic or quarantine evidence, never a signed receipt, and is insufficient to prove
no consumption or authorize reservation release.

Identical duplicate returns the retained state. Reuse of grant, operation or nonce with
any conflicting bytes/binding creates permanent conflict evidence and authorizes zero
consumption.

### Phase E - Adapter consumption and receipt

1. Reload the exact `RECEIVED` row.
2. Revalidate exclusive deadline and independently observed supervisor epoch.
3. Construct the closed `CONSUMED` or `REFUSED_DEFINITE` receipt.
4. Adapter transaction B appends transition, exact canonical signed receipt and event,
   then advances generations.
5. Only after commit may the retained receipt be returned.

`CONSUMED` means one-shot authority was spent. PLAN-005 exposes no execution token or
effect handoff. `REFUSED_DEFINITE` requires a permanent no-consumption tombstone and
proof that no concurrent/in-flight consumption is possible. Its closed post-`RECEIVED`
code is exactly one of `GRANT_EXPIRED`, `SUPERVISOR_EPOCH_MISMATCH` or
`ADAPTER_PAUSED`.

### Phase F - Coordinator receipt and state advance

The coordinator strictly verifies receipt canonical bytes, domain/key purpose/trust,
grant/operation/destination, adapter root, generations, observed epoch, decision and
ordering. One transaction retains exact receipt bytes and:

- for `CONSUMED`, appends `DISPATCHING -> EXECUTING`, acknowledges outbox and appends
  event, but only while the current state is exactly `DISPATCHING`;
- for `REFUSED_DEFINITE` plus fenced no-inflight proof, appends
  `DISPATCHING -> OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED -> FAILED`, retains the
  receipt/tombstone/reconciliation, appends base `PREPARING -> FAILED`, releases the
  exact held reservation once and appends both event chains atomically;
- for mismatch/conflict, leaves authority held and quarantines evidence.

`EXECUTING` is not success and proves no real effect in this feature.
A `CONSUMED` receipt recovered after `OUTCOME_UNKNOWN` is retained only after
`OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED`; it cannot jump back to `EXECUTING` and
requires a later effect-aware feature.

## 5. Retry, absence and unknown outcomes

- Before handoff, confirmed no-send may leave exact retained outbox pending while the
  original deadline remains valid.
- After possible handoff, retry may redeliver only the exact same grant bytes/identity
  and only within the original deadline.
- A retained exact adapter receipt is idempotently recoverable.
- Each possible-handoff attempt permits exactly one automatic readback sequence, with
  at most four observations and a total budget of 500 ms. Observation backoffs are
  `0/25/75/175 ms`, giving offsets `0/25/100/275 ms` from sequence start; the sequence
  cuts off sooner at the original exclusive grant deadline.
- A retained exact signed receipt remains authoritative evidence after deadline expiry;
  readback never renews, extends, replaces or resigns its grant.
- A missing inbox row alone is never definite absence.
- Definite absence requires quiesced/fenced transport, matching healthy adapter
  root/epoch, closure of late delivery by the exclusive deadline, and a readback
  generation proving no later receive can arrive.
- If exact consumption or definite absence cannot be proved by the bound, the
  coordinator commits `DISPATCHING -> OUTCOME_UNKNOWN`, retains reservation/recovery and
  later enters explicit `RECONCILIATION_REQUIRED` custody. Exhausting the automatic
  readback sequence is therefore never classified as absence.
- Reconciliation can consume exact signed evidence or a permanent no-consumption proof;
  only the latter may close `RECONCILIATION_REQUIRED -> FAILED` and release the exact
  base hold. It cannot mint/renew/replace a grant, jump back to `EXECUTING` after unknown
  custody or reactivate restored preparation.

## 6. Closed outcomes

### Request/commit

- `Dispatched`
- `AlreadyDispatched`
- `Denied(code)` — definite before transition
- `Failed(code)` — proved no dispatch commit
- `Ambiguous(code)` — possible commit or corrupted readback, PAUSE

### Delivery/adapter

- `Consumed(receipt)`
- `DefinitelyRefused(receipt)`
- `Pending(exact_grant)`
- `Conflict(redacted_incident)`
- `OutcomeUnknown(redacted_custody)`
- `ReconciliationRequired(redacted_custody)`

Codes are closed uppercase ASCII values. Unknown code/schema/version denies.

## 7. Deadlines, queues and control lane

- Grant lifetime is at most 5,000 ms from trusted issue sample and never renews.
- Equality with an exclusive deadline denies.
- Exact held capacity is accepted; any over-by-one dimension denies.
- Ordinary pending capacity is 1,024 per v1 profile.
- Control-lane capacity is independently reserved at 32 for PAUSE, status and
  reconciliation.
- Ordinary saturation refuses/backpressures within 50 ms; control p99 target is 100 ms
  on the declared reference profile.

## 8. Migration and compatibility

- Coordinator V1 remains exact and rejects V2.
- V2 is unchanged V1 plus the reviewed additive overlay.
- Ordinary open never migrates.
- Explicit migration requires PAUSE/quiescence, exact V1 verification and a verified
  fresh V1 backup.
- One migration transaction creates all overlay objects and receipt, then writes
  `user_version=2` last.
- Uncertain migration is exact-readback classified; it is never blindly rerun.
- No in-place downgrade exists after dispatch history. A pre-upgrade V1 backup may be
  restored only into a new paused root when no authority/evidence would be discarded.

## 9. Backup and clean restore

Under PAUSE/quiescence, coordinator V2 and adapter inbox are independently backed up and
verified. A top-level signed index published last binds both roots/manifests/database
digests, all generations, cross-store inventory and public verification-key profiles.
This is coherent sequential evidence, not an atomic cross-database snapshot.

Clean restore uses empty roots, new root/instance/supervisor identities,
`RESTORE_PENDING` and PAUSED state. All old grant authority is expired; possible
accepted/consumed items are quarantined; automatic redelivery is zero. Activation is not
exported. This proves subsystem restore only, not a full-machine/Tier 1 gate.

## 10. Retention, redaction and removal

Grant/receipt wires, transitions, conflicts, quarantines and reconciliation tombstones
are permanent authoritative v1 evidence. No pruning, reuse or secure-erasure claim
exists. Production roots require an approved at-rest profile. Private signing keys never
enter stores, backups, fixtures, logs, Graphify or evidence; only public verification
history is retained.

Public logs, `Debug`, metrics and outward events redact internal IDs/digests and never
include raw secrets, native paths, replacement content or unbounded diagnostics.
Removal disables PLAN-005 executable surfaces in an isolated copy while preserving
historical evidence and all PLAN-001 through PLAN-004 protected behavior.

## 11. Required evidence

PLAN-005 maps to `GRANT-001`, `DUR-001`, `DUR-002`, `OPS-002`, `OPS-003`,
`SUPPLY-001` and `PERF-002`. Required proof includes canonical/tamper corpus,
thread/process contention, separate exhaustive PLAN-005 fault registry, lost-ack and
fenced-absence cases, migration/rollback, backup/restore, redaction, overload/control
lane, physical-M4 benchmark, unchanged three-platform conformance, supply-chain bundle,
isolated removal and exact-commit immutable attestations.

Hosted/process-kill evidence remains synthetic no-effect evidence and cannot promote
power-loss, production supervisor/provider, physical isolation, full-machine restore or
Tier 1 claims. Aggregate catalog status remains `pending-evidence`.
