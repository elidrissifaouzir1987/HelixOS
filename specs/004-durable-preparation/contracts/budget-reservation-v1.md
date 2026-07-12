# Contract: Preparation Budget Reservation v1

**Contract ID**: `helixos.preparation-budget/1`
**Status**: design contract; implementation pending

## 1. Authority boundary

The signed plan budget is a requested upper bound. It is not a reservation or proof of
remaining capacity. Only a trusted, pre-existing coordinator `BudgetScopeV1` and one
successful coordinator transaction can create a held reservation.

The agent cannot provision a scope, select its generation, change totals, choose a price
table or construct a positive receipt.

## 2. V1 vector

V1 reserves exactly:

```text
max_cost_micro_units : safe u64
action_limit         : safe u64
egress_bytes_limit   : safe u64
recovery_bytes       : safe u64
```

The first three values come from authenticated plan-v1 budget claims. Recovery bytes
come from the authenticated recovery profile. Values are upper bounds and are reserved
without estimation or reduction.

File count, concurrency and duration are not claimed in v1 because current signed
authority does not carry them. They remain mandatory before a future relevant effect.

## 3. Scope provisioning

A trusted create-only maintenance operation provisions one scope before any preparation:

```text
scope_id
task_lease_digest
allowance_binding_digest
budget_generation
currency_code
price_table_id
total vector
held vector = zero
provisioning_profile = TRUSTED_LEASE_V1
```

Rules:

- the scope key/binding is derived from authenticated decoded lease authority outside
  the agent path;
- v1 rejects an existing scope with any different field;
- prepare cannot create or modify totals/generation/price identity;
- a missing, unknown or mismatched scope is a closed denial; v1 scopes have no inactive
  state, and adding deactivation requires a later contract version;
- scope provisioning is not a claim that TaskLease issuance is implemented by this
  feature; deterministic trusted fixtures supply it for conformance.

## 4. Read-only preflight before recovery

Before any recovery-provider call, `PreparationStoreV1::preflight_operation_and_budget`
opens one healthy read-only coordinator snapshot and applies this order:

1. operation/attempt/plan identity is absent, an exact prior preparation, or conflict;
2. the named budget scope exists and its lease/binding/generation/currency/price table
   match final authority expectations;
3. all request arithmetic is valid;
4. every current remaining dimension is sufficient.

Failure to obtain the healthy snapshot before operation identity is proved is
`PREPARATION_OPERATION_AUTHORITY_UNAVAILABLE`. Success returns an opaque,
non-authoritative `BudgetPreflightV1` containing the observed
scope generation and budget vector snapshot. It reserves nothing and cannot substitute
for the final transaction. Failure returns the operation or budget code before sensitive
recovery work. Inability to prove the scope is
`PREPARATION_BUDGET_AUTHORITY_UNAVAILABLE`, not a positive assumption.

The final `BEGIN IMMEDIATE` transaction repeats every binding, arithmetic and capacity
check against the then-current rows. Concurrent reservations may therefore turn a
successful preflight into a later closed budget denial.

## 5. Reservation preconditions

Before mutation, all fields must agree:

- reservation ID, operation ID, plan ID and attempt ID are unused;
- plan task-lease digest equals scope lease digest;
- final context allowance-binding digest/generation equal the stored scope;
- plan/context/scope currency and price-table identity are exact;
- requested recovery bytes equal the authenticated recovery reservation;
- no supported integer is out of the safe range.

For every dimension `d`, acceptance uses checked arithmetic equivalent to:

```text
request[d] <= total[d] - held[d]
```

Subtraction underflow, addition overflow, alternative negative encoding or any failed
dimension denies before a partial update.

## 6. Atomic reservation

Budget mutation is one part of, and MUST NOT narrow, the canonical positive coordinator
commit set defined by Durable Preparation Contract section 5 Phase D. In one
`BEGIN IMMEDIATE` commit the coordinator performs exactly these eight logical members:

```text
advance enclosing store/operation/budget/event generations
insert operation(state = PREPARING)
insert permanent ABSENT -> PREPARING transition
insert exact comparison/replay evidence
scope.held += exact request
insert reservation(state = HELD)
insert recovery reference or exact irreversibility evidence
insert event(kind = PREPARED, delivery = PENDING)
```

All eight commit or roll back together. Unique indexes cover reservation ID, operation
ID and attempt ID. Distinct reservations for one shared scope serialize against the
same held totals. Replay-store, recovery-provider and supervisor state remain separate
receipt/guard domains outside this transaction.

The positive `BudgetReservationReceiptV1` is constructed only after exact same-attempt
commit/readback and is retained inside preparation custody. It is not serializable,
spend authority, a grant or adapter input.

## 7. Conflict semantics

| Existing state | Incoming binding | Result |
|---|---|---|
| no reservation | exact and sufficient | create `HELD` atomically |
| same ID, same operation/plan/vector, same attempt | exact readback only; no second marker |
| same ID, any different binding | `PREPARATION_BUDGET_BINDING_CONFLICT` |
| same operation, different reservation/plan/attempt | `PREPARATION_OPERATION_CONFLICT` |
| distinct IDs, shared scope insufficient in any dimension | `PREPARATION_BUDGET_EXHAUSTED` |
| arithmetic invalid/overflow | `PREPARATION_BUDGET_ARITHMETIC_INVALID` |

Conflicts never overwrite, merge, resize or release either reservation.

## 8. Known pre-dispatch release

Release is allowed only with a verified `PREPARING` operation while holding an opaque
`NoDispatchAuthorityGuardV1` issued by trusted supervisor/dispatch-authority wiring.
The guard binds operation, attempt, current state generation, boot/instance/fencing
epochs, revocation generation and deadline, proves no grant/dispatch/in-flight authority
and remains held through commit. Caller assertions, copied booleans and observed row
absence are invalid. One coordinator transaction performs:

```text
operation PREPARING -> FAILED
reservation HELD -> RELEASED
scope.held -= reservation's exact stored vector
append PREPARATION_FAILED event
```

Rules:

- subtract from the stored reservation, never caller-supplied amounts;
- missing, mismatched, expired, unavailable or revoked no-dispatch custody rolls back and
  leaves the operation/reservation unchanged;
- release each dimension exactly once;
- preserve the reservation row permanently with `released_generation`;
- exact repeated release returns the existing terminal result without another event or
  subtraction;
- never reuse the reservation ID;
- never release automatically after ambiguous commit/readback;
- never release or reset replay state.

## 9. Invariants

For every healthy open, transaction and backup/restore verification:

1. `0 <= held[d] <= total[d]` for every scope/dimension.
2. Scope held totals equal the checked sum of all `HELD` reservation vectors.
3. Every `HELD` reservation has exactly one `PREPARING` operation.
4. Every `RELEASED` reservation has exactly one `FAILED` operation.
5. Operation, plan, attempt, lease, generation, currency, price table and vector agree
   across operation/reservation/scope rows.
6. No identifier is reused; no reservation returns from `RELEASED` to `HELD`.
7. Unknown state/generation/schema fails closed without admission-time repair.

## 10. Required evidence

- exact-limit, minus-one and plus-one cases for every dimension;
- zero and maximum safe values where contract-valid;
- at least 100,000 generated vectors with an independent checked oracle;
- same-ID and same-operation conflicts;
- 100 x 64-thread and 20 x 8-process contested preparation rounds;
- distinct operations that each fit alone but exceed one shared scope together;
- commit acknowledgement loss and exact readback;
- repeated `PREPARING -> FAILED` idempotency and no double release;
- corruption/invariant cases for held totals and row bindings;
- redaction proving no public event/error exposes IDs, amounts or digests.
- operation/budget preflight failure proves zero recovery-provider calls, while a
  concurrent post-preflight reservation is still caught by the final transaction.
- no-dispatch guard negatives cover caller boolean/row absence, wrong operation/attempt/
  state generation/epoch and expiry/revocation, with zero mutation and no release.

## 11. Retention

Scopes, held/released reservations and their binding evidence are not pruned in v1.
Released reservations remain permanent tombstones. Any future compaction requires a
new versioned retention policy that preserves aggregate and conflict history.
