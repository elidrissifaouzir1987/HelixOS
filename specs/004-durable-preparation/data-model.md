# Data Model: Durable Preparation Before Dispatch

This model defines feature 004's portable in-process values and the first coordinator
SQLite persistence model. Wire plan-v1, PLAN-002 eligibility and PLAN-003 replay rows
remain unchanged.

## Type conventions

- All counters, generations, epochs, lengths, deadlines and amounts are checked safe
  unsigned integers in `0..=9_007_199_254_740_991` unless a smaller bound is stated.
- Digests are fixed 32-byte SHA-256 values with domain separation where derived.
- Identifiers are bounded portable ASCII/Unicode-normalized contract values; common
  values never contain native paths.
- UTC values are Unix milliseconds. Deadline values are absolute milliseconds in the
  same trusted suspend-aware boot-monotonic domain used by PLAN-002.
- Public `Debug`, `Display`, error and evidence projections are redacted. Restricted
  persistence fields below are not automatically eligible for logs or audit payloads.
- Every enum and persisted record uses a closed version. Unknown values fail closed.

## Portable input and authority entities

### `PlanPreparationClaimsV1<'plan>`

A borrowed, read-only, non-wire projection over `AuthenticPlanEnvelopeV1`.

| Field | Rule |
|---|---|
| `plan_id` | Exact PLAN-001 digest |
| `operation_id`, `task_id`, `workload_id` | Existing authenticated bounded identifiers |
| `task_lease_digest` | Exact signed lease binding |
| `target` | Borrowed `ResourceRefV1`; no native path |
| `precondition_volume_id`, `precondition_file_id` | Existing authenticated opaque identifiers |
| `precondition_content_sha256` | Exact pre-image digest |
| `precondition_byte_length` | Safe integer |
| `replacement_sha256`, `replacement_byte_length` | Exact signed replacement identity |
| `replacement_media_type` | Existing bounded media type |
| `recovery_class`, `atomicity` | Existing closed PLAN-001 enums |
| `preimage_sha256` | Present exactly for compensation; absent for irreversibility |
| `recovery_reserved_bytes` | At least precondition length for compensation |
| `verification_sha256`, `verification_byte_length` | Exact replacement predicate |
| `budget` | Existing `PlanEligibilityBudgetClaimsV1` projection |

Validation and authority rules:

- the projection has no public constructor independent of an authentic plan;
- it is not serializable/deserializable and cannot change canonical bytes;
- replacement content bytes remain reachable only through restricted authentic plan
  custody, never through diagnostics or provider metadata;
- compile-fail tests prove that this projection is not a wire/persistence type.

### `PreparationAttemptIdV1`

Fresh 32-byte domain-separated identity generated from OS randomness before recovery
publication.

- unique in the coordinator store;
- bound into recovery, operation, reservation and event records;
- not a credential, idempotency permission or public diagnostic value;
- distinguishes exact readback of this attempt from any prior contender.

### `PreparationContextV1`

Closed result of one trusted context build:

```text
Ready(ReadyPreparationContextV1)
Unavailable
Incomplete
Torn
Unsupported
```

| State | Exact meaning | Public result |
|---|---|---|
| `Ready` | Every required group is present, coherent and supported | continue |
| `Unavailable` | A required trusted snapshot cannot be obtained | `Denied(PREPARATION_CONTEXT_UNAVAILABLE)` |
| `Incomplete` | One or more mandatory groups or fields are absent | `Denied(PREPARATION_CONTEXT_INCOMPLETE)` |
| `Torn` | Groups were sampled inconsistently or contradict one another | `Denied(PREPARATION_CONTEXT_TORN)` |
| `Unsupported` | Recognized v1 wiring cannot supply required comparison/guard semantics | `Denied(PREPARATION_CONTEXT_UNSUPPORTED)` |

Unknown API, value or persistence version is not `Unsupported`; it maps separately to
`Denied(PREPARATION_VERSION_UNSUPPORTED)`. Negative variants are payload-free and
contain no dummy records or provider diagnostics.

### `ReadyPreparationContextV1`

One internally coherent snapshot bound to the exact eligible plan and attempt.

| Group | Fields |
|---|---|
| identity | context version, plan ID, operation/task/workload binding, attempt ID |
| capture/time | capture generation, clock generation, deadline generation, sampled UTC, sampled monotonic time |
| supervisor | admission state, supervisor generation, boot ID, instance epoch, fencing epoch |
| signer | trust generation, verified key fingerprint |
| workload | workload generation, workload evidence digest |
| lease | lease generation, lease digest, lease-decision digest |
| authorization | authorization generation and evidence digest |
| policy | policy/content and decision generations/digests |
| catalogue | catalogue/content and decision generations/digests |
| capabilities | report generation/digest, host-driver context digest, observed UTC and max age |
| replay | exact claim ID, claimant generation and binding digest expected from PLAN-003 |
| budget | scope binding digest, scope generation, currency, price-table identity and exact requested vector |
| recovery provider | compensation only: profile ID, evidence class, provider generation and capability binding digest; absent for authenticated irreversibility |

Rules:

- preliminary and final contexts are separate values; preliminary context cannot be
  reused as final proof;
- every field corresponding to `EligibilityBindingsV1` and
  `EffectiveEligibilityBoundsV1` compares exactly;
- `now < expiry` and `now_monotonic < deadline`; equality denies;
- capability age uses checked subtraction and the signed maximum age;
- context values contain no callbacks, locks, paths or provider handles.

### `AuthorityGuardV1` and `AuthorityGuardSetV1`

Opaque, non-Clone, non-Serde ephemeral custody held by the trusted coordinator. A guard
binds one provider, expected generation/digest, acquisition deadline and revocation
state. The set records acquisition success in the normative order:

```text
recovery publication
-> external clock/deadline
-> supervisor
-> signer trust
-> workload
-> lease
-> authorization
-> policy
-> catalogue
-> capabilities
```

The SQLite writer slot follows these guards and is not a portable value. Guards release
in reverse order. PAUSE/HALT revocation makes validation fail and never waits behind an
unbounded preparation queue.

### `FinalCommitGateV1` and `FinalCommitPermitV1`

`FinalCommitGateV1` borrows the complete live guard set and is passed by mutable borrow
to the SQLite store. After staging writes, `enter_commit_permit` atomically compares the
supervisor revocation generation and all guards, then either denies or returns one
opaque permit held across the actual SQLite commit.

The supervisor-owned gate total-orders `REVOKED` versus `COMMIT_PERMITTED`. A control
request that wins first forces rollback/no row. A permit that wins first creates no
operation itself; SQLite commit remains the sole `PREPARING` linearization point, while
control activation for that attempt is ordered after permit resolution. Definite abort,
commit and ambiguous commit resolve the permit explicitly. A copied last-minute token
check without a held permit is non-conforming.

Each permit has a supervisor-owned opaque owner token and absolute lease deadline equal
to the earlier caller deadline or exactly 250 ms after permit entry. Its one-shot commit
method moves active custody to `COMMIT_IN_FLIGHT` before calling SQLite. Acknowledged
commit and confirmed rollback resolve immediately; only an explicit uncertain store
classification may use one fresh readback before the same deadline. The independent
supervisor—not process `Drop`—resolves missing classification, owner loss, process kill
or deadline equality to
`RESOLVED_AMBIGUOUS`, activates PAUSE, blocks new permits and requires exact readback.
A resumed worker cannot use a resolved permit; an already-started flush may complete but
remains ambiguous/nonpositive.

### `NoDispatchAuthorityGuardV1`

Opaque non-Clone, non-Serde sovereign custody issued only by trusted supervisor/
dispatch-authority wiring for known-failure reconciliation. It binds:

- operation and preparation-attempt identities;
- current `PREPARING` state generation;
- boot ID, instance epoch and fencing epoch;
- provider/revocation generation and absolute monotonic deadline;
- a closed proof that no grant, dispatch transition or in-flight dispatch authority
  exists.

It remains live through the complete `PREPARING -> FAILED` coordinator transaction.
Missing, mismatched, expired, unavailable or revoked custody leaves the operation and
reservation unchanged. A caller boolean, operator assertion or observed database
absence cannot construct it. It is never persisted; the permanent transition and event
prove only the committed outcome and cannot recreate the authority.

### `ReplayClaimVerificationViewV1<'eligible>`

Opaque borrowed view created only by `EligiblePlanV1`. It binds authenticated instance
epoch, nonce and operation ID to the exact carried replay claim ID, claimant generation
and binding digest. It has no public independent constructor and avoids exposing the
crate-private `ReplayBindingV1` builder.

### `ReplayClaimVerificationV1`

Closed read-only classification from `ReplayClaimVerifierV1`:

```text
Exact
Missing
Conflict
Unavailable
Unhealthy
```

`Exact` requires the same permanent row to match nonce namespace, operation, binding
digest, claim ID and claimant generation. The latest global generation is not compared.
No variant creates or releases a claim.

## Budget entities

### `BudgetVectorV1`

| Field | Meaning |
|---|---|
| `max_cost_micro_units` | Signed maximum cost in integer micro-units |
| `action_limit` | Signed maximum action count |
| `egress_bytes_limit` | Signed maximum egress bytes |
| `recovery_bytes` | Signed recovery capacity |

All aggregate arithmetic is checked. File count, concurrency and duration are not
represented in v1 because current signed authority does not carry them.

### `BudgetScopeV1`

Trusted create-only allowance installed before preparation.

| Field | Rule |
|---|---|
| `scope_id` | Domain-separated digest of the authority namespace |
| `task_lease_digest` | Exact authenticated lease binding |
| `allowance_binding_digest` | Digest of the trusted decoded allowance |
| `budget_generation` | Positive, immutable v1 generation |
| `currency_code` | Same three uppercase ASCII characters as plan |
| `price_table_id` | Exact current price-table identity |
| `total` | Total `BudgetVectorV1` |
| `held` | Sum of all `HELD` reservations, initially zero |
| `provisioning_profile` | Closed trusted profile; never agent-selected |

Rules:

- prepare cannot create, widen or rewrite a scope;
- v1 provisioning is create-only and rejects conflicting identity/generation;
- `held <= total` for every dimension;
- `held` exactly equals the checked sum of `HELD` reservation rows for the scope.

### `BudgetReservationRecordV1`

Authoritative permanent record.

| Field | Rule |
|---|---|
| `reservation_id` | Exact signed ID; unique forever |
| `operation_id` | Unique one-to-one operation binding |
| `plan_id`, `attempt_id` | Exact preparation binding |
| `scope_id`, `task_lease_digest` | Existing authoritative scope |
| `budget_generation` | Must equal scope generation at commit |
| `currency_code`, `price_table_id` | Must match both scope and plan |
| `reserved` | Exact requested `BudgetVectorV1` |
| `state` | `HELD` or `RELEASED` |
| `created_generation` | Same coordinator transition as `PREPARING` |
| `released_generation` | Null for `HELD`; positive exactly for `RELEASED` |

State transition:

```text
ABSENT -> HELD -> RELEASED
```

- `ABSENT -> HELD` is atomic with `PREPARING` and the prepared event;
- `HELD -> RELEASED` is atomic with `PREPARING -> FAILED` and the failure event;
- repeat exact release is an idempotent read of the tombstone;
- a conflicting reservation ID never mutates either binding;
- no transition returns to `HELD` and no row is deleted/reused.

### `BudgetPreflightV1`

Opaque read-only evidence captured from one healthy coordinator snapshot before the
recovery provider is invoked:

- operation/attempt identity was absent (or classified exact/conflicting first);
- scope lease/binding/generation/currency/price table matched;
- observed total and held vectors were valid and the requested vector fit;
- checked arithmetic succeeded;
- store/schema/profile were healthy enough to prove those facts.

It causes no mutation, is non-Serde and is not reservation evidence. The final writer
transaction must repeat every check because concurrent holds may change capacity after
preflight. Failure to prove budget authority denies before recovery work.

### `BudgetReservationReceiptV1`

Opaque positive in-process evidence constructed only after exact coordinator commit.
It exposes bounded status/generation getters needed by the coordinator but no raw ID,
digest, native path or amount through `Debug`. It is not spend, grant or adapter
authority and is not serialized.

## Recovery entities

### `RecoveryProviderProfileV1`

Trusted deployment configuration:

| Field | Rule |
|---|---|
| `profile_id` | Bounded approved profile identity |
| `profile_version` | Exactly v1 |
| `provider_id`, `provider_generation` | Bounded identity and positive generation |
| `evidence_class` | `SYNTHETIC_CONFORMANCE` or approved production class |
| `capability_binding_digest` | Exact current provider capabilities |
| `at_rest_profile_id` | Approved opaque protection profile; no key/path |
| `supports_create_only`, `supports_sync`, `supports_no_clobber_publication` | All true for a positive compensable result |

Synthetic evidence never satisfies a production compensability gate.

### `RecoveryMaterialReceiptV1`

Immutable receipt over a manifest-last published recovery object.

| Group | Fields |
|---|---|
| version/provider | receipt version, profile ID/version, provider ID/generation, evidence class, at-rest profile and capability binding |
| authority | plan ID, operation ID, preparation attempt ID |
| target | target reference digest, precondition identity/digest/length |
| recovery | class, atomicity, actual material digest/length, reserved capacity |
| publication | material ID, publication-attempt ID, manifest digest, state `PUBLISHED` |
| epochs | boot binding, instance epoch, fencing epoch |

Rules:

- compensable receipt requires actual length equal to the authenticated precondition
  length, exact digest equality and reserved capacity at least the signed bound;
- every provider/profile/generation/capability field matches final context;
- the manifest and material reopen successfully while the publication guard is held;
- no receipt contains a native path or material bytes;
- irreversible plans use explicit irreversibility evidence instead of this entity.

### `IrreversibilityEvidenceV1`

| Field | Rule |
|---|---|
| `version` | Exactly v1 |
| `risk_level` | Exactly L2 |
| `recovery_class` | Exactly `IRREVERSIBLE` |
| `atomicity` | Exact authenticated plan enum |
| `no_material` | Fixed true |

It cannot be synthesized for a compensable plan.

### `RecoveryMaterialLifecycleV1`

Provider-side lifecycle:

```text
STAGING -> PUBLISHED
          \-> QUARANTINED
PUBLISHED --operation durable FAILED + exact reconciliation--> RETIREMENT_PENDING
RETIREMENT_PENDING -> RETIRED_TOMBSTONE

QUARANTINED true orphan
  --definitive no-reference proof + permanent orphan resolution-->
  ORPHAN_RETIREMENT_AUTHORIZED -> RETIRED_TOMBSTONE
```

`ORPHAN_RETIREMENT_AUTHORIZED` is persisted as an `ORPHAN_MATERIAL`
`RESOLVED_TOMBSTONE` whose internal `orphan_retirement_state` is
`RETIREMENT_PENDING`; it is not an operation state.

- staging and incomplete publication are non-authoritative;
- `PUBLISHED` is positive recovery evidence only when exact coordinator readback proves
  the matching `PREPARING` row; otherwise it remains non-authoritative/quarantined;
- ambiguity remains `QUARANTINED` and is never retired by time alone;
- retirement first commits `RETIREMENT_PENDING` in coordinator recovery evidence while
  holding the cleanup guard, then publishes the provider tombstone, then commits
  `RETIRED_TOMBSTONE` with its exact manifest digest;
- a true orphan never creates an operation: under the cleanup guard a healthy definitive
  view excludes every operation, attempt, reservation, event, in-flight permit and
  active ambiguity reference, then commits a permanent orphan-resolution record in
  `ORPHAN_RETIREMENT_AUTHORIZED` before provider retirement;
- a crash in `RETIREMENT_PENDING` remains quarantined/reconcilable and blocks backup;
- a crash after orphan authorization or provider retirement remains quarantined and
  blocks backup until the permanent record reaches `RETIRED_TOMBSTONE`;
- `PREPARING` requires `PUBLISHED`; `FAILED` may retain `PUBLISHED`,
  `RETIREMENT_PENDING` or `RETIRED_TOMBSTONE` recovery evidence;
- both retirement paths hold the cleanup guard and prove definite non-reference;
- the retirement tombstone is permanent; physical secure erasure is not claimed.

## Coordinator persistence entities

### `CoordinatorStoreMetadataV1`

Exactly one strict row plus fixed database header/profile:

| Field | Rule |
|---|---|
| `singleton` | Exactly `1` |
| `format_version` | Exactly `1` |
| `store_generation` | Global sequence advanced once by every committed mutating transaction |
| `operation_generation` | Global sequence advanced by operation creation/failure transitions |
| `budget_generation` | Global sequence advanced by scope/reservation/release transitions |
| `event_generation` | Global sequence advanced by every outbox insert; delivery records the enclosing store generation separately |
| `quarantine_generation` | Global sequence advanced by quarantine creation/resolution transitions |
| `root_id` | Fresh restricted 32-byte opaque root identity; never a native path |
| `root_lifecycle` | `ACTIVE` for a native provisioned root or `RESTORE_PENDING` for a restored root |
| `restore_id` | Null for `ACTIVE`; exact 32-byte restore identity for `RESTORE_PENDING` |
| `restore_attestation_digest` | Null for `ACTIVE`; exact detached-attestation SHA-256 for `RESTORE_PENDING` |
| `restore_state_generation` | Zero for `ACTIVE`; positive enclosing store generation for `RESTORE_PENDING` |

Header/profile invariants include the reviewed application ID, `user_version=1`, exact
schema/index SQL, WAL, `synchronous=FULL`, disabled automatic checkpoint, foreign keys,
`trusted_schema=OFF` and `cell_size_check=ON`.
Every connection also requires `recursive_triggers=ON`; reviewed conflict/transition/
no-delete triggers reject direct and `OR REPLACE` rollback of permanent lifecycle rows.

Healthy open also requires `root_id` to match the provisioner-attested expected identity
for that native root. Moving/copying an `ACTIVE` database to another root does not
preserve authority and denies; restore is the only path that installs a fresh destination
root identity and `RESTORE_PENDING` metadata.

`RecoveryRootMetadataV1` is independently durable in the provider root under the closed
schema `helixos.recovery-root-metadata/1`. It carries its own opaque root ID, lifecycle,
state generation, restore ID, provenance-attestation digest and source-inventory digest.
All restore fields are absent for `ACTIVE` and exact for `RESTORE_PENDING`. Restore
verifies provenance before publishing either root, writes `RESTORE_PENDING`
independently to both, then requires restore-ID/attestation agreement after close/reopen.
Generic open, prepare and retirement reject either pending root. Feature 004 has no
`RESTORE_PENDING -> ACTIVE` transition.

### `PreparedOperationRecordV1`

Authoritative operation state.

| Group | Fields |
|---|---|
| identity | operation ID primary key, unique attempt ID, plan ID, task ID, workload ID |
| plan custody | exact canonical signed envelope BLOB and its checked length |
| lifecycle | state `PREPARING` or `FAILED`, state generation, created generation, optional failed generation/reason |
| authority bounds | boot ID, instance/fencing epochs, UTC expiry, monotonic deadline |
| evidence links | comparison row, replay row projection, reservation ID, recovery reference or irreversibility row, current event ID |
| restore | source backup generation when restored; null for native live creation |

Rules:

- canonical bytes reparse under the reviewed PLAN-001 decoder and reproduce `plan_id`;
- one operation has exactly one attempt, reservation, comparison row and initial event;
- exactly one of recovery receipt and irreversibility evidence exists;
- `PREPARING` is not dispatchable and has no grant/adapter fields;
- `FAILED` has a released reservation and a failure event;
- restored old `PREPARING` can only become `FAILED` or remain quarantined, never rebound.

### `OperationTransitionV1`

Permanent append-evidence for each operation state transition:

| Field | Rule |
|---|---|
| `state_generation` | Globally unique transition generation; never reusable |
| `operation_id` | Existing operation foreign key |
| `previous_state` | Null only for initial creation; otherwise `PREPARING` |
| `new_state` | `PREPARING` or `FAILED` |
| `event_id` | Unique exact outbox event for this transition |

Allowed rows are only `ABSENT -> PREPARING` and `PREPARING -> FAILED`. The current
operation row points to its latest retained transition, while earlier transition rows
remain permanently. One event exists for each `(operation_id, state_generation)`;
`event_kind` cannot create a second event for the same transition. Deferrable composite
foreign keys bind `(operation_id, state_generation, event_id, operation_state)` across
the current operation, transition and event, so no operation can adopt another
operation's retained historical transition/event.

### `PreparationComparisonRecordV1`

One-to-one restricted record containing the exact final comparison vector:

- capture, clock, deadline and supervisor generations plus exact `OPEN` admission state;
- boot, instance and fencing epochs;
- trust generation and key fingerprint;
- workload generation/evidence digest;
- lease generation, lease and decision digests;
- authorization generation/evidence digest;
- policy/content and decision generations/digests;
- catalogue/content and decision generations/digests;
- capability generation/report and driver-context digests;
- original eligibility-evaluation UTC/monotonic samples, sampled final UTC/monotonic
  time and effective bounds;
- replay claim ID/generation/binding digest;
- budget scope/generation and recovery profile/provider/generation bindings;
- domain-separated whole-record digest covering the comparison row plus the exact joined
  operation, scope/reservation and recovery/irreversibility fields required by FR-028.

The record compares field-by-field before its summary digest is accepted. It never uses
the replay store's latest global generation.

### `PreparationEventOutboxV1`

One transactional redacted event per operation transition.

| Field | Rule |
|---|---|
| `event_id` | Internal unique 32-byte ID |
| `event_generation` | Strictly increasing |
| `operation_row_key` | Restricted internal foreign key; not serialized outward |
| `event_kind` | `PREPARED` or `PREPARATION_FAILED` |
| `operation_state_generation` | Exact resulting generation |
| `reason_code` | Null for prepared; bounded closed code for failed |
| `delivery_state` | `PENDING` or `DELIVERED` |
| `delivered_generation` | Null until delivery, then the permanent enclosing store generation |

The future delivery projection exposes stable kind/reason/count/version fields only. It
contains no content, path, identifier, nonce, digest, user-bound amount or provider
diagnostic. Delivery cannot authorize an effect. `DELIVERED` rows remain permanent.

### `PreparationQuarantineV1`

Separate maintenance evidence, not an operation state.

| Field | Rule |
|---|---|
| `quarantine_id` | Unique restricted ID |
| `attempt_id` | Exact ambiguous/recovery attempt when known |
| `operation_binding_digest` | Restricted binding; no public rendering |
| `reason` | Closed `AMBIGUOUS_COMMIT`, `ORPHAN_MATERIAL`, `RESTORED_OLD_AUTHORITY`, `INVARIANT_CONFLICT` or `STORE_UNHEALTHY` |
| `status` | `ACTIVE` or `RESOLVED_TOMBSTONE` |
| `created_generation`, `resolved_generation` | Monotonic metadata bindings |
| `recovery_manifest_digest` | Optional restricted reference |
| `no_reference_digest`, `retirement_id` | Required only after definitive true-orphan proof; bind the permanent authorization before provider retirement |
| `orphan_retirement_state` | Null while active; `RETIREMENT_PENDING` or `RETIRED_TOMBSTONE` on an orphan resolution |
| `retirement_manifest_digest` | Required only for a resolved retired-orphan tombstone |

Quarantine never creates a prepared marker or infers an operation. Resolution requires
full healthy readback and remains as a permanent tombstone. Only
`reason=ORPHAN_MATERIAL` may become a `RESOLVED_TOMBSTONE` whose internal retirement
state is initially `RETIREMENT_PENDING`; that transaction binds the exact
material/attempt identity, definitive no-reference digest and fresh retirement ID before
provider retirement. It then advances the same permanent row to
`RETIRED_TOMBSTONE` only with the exact provider retirement-manifest digest. All pending
states block backup.

## Closed coordinator outcomes

### `PreparationDenialV1`

`Denied` owns only the following definite pre-transition refusals. The authoritative
leaf order and exact code mapping are in Authority Comparison Contract section 6.1:

1. `CONTEXT_UNAVAILABLE`, `CONTEXT_INCOMPLETE`, `CONTEXT_TORN`,
   `CONTEXT_UNSUPPORTED`, `CONTEXT_MISMATCH`, `VERSION_UNSUPPORTED`;
2. `CLOCK_MISMATCH`, `TIME_EXPIRED`, `DEADLINE_MISMATCH`, `DEADLINE_REACHED`,
   `BOOT_MISMATCH`, `SUPERVISOR_MISMATCH`, `SUPERVISOR_DENIED`, `GUARD_REVOKED`;
3. signer/workload/lease/authorization/policy/catalogue/capability mismatch codes;
4. `REPLAY_MISSING`, `REPLAY_CONFLICT`, `REPLAY_UNAVAILABLE`, `REPLAY_UNHEALTHY`;
5. `OPERATION_CONFLICT`, `ALREADY_PREPARED`, `OPERATION_AUTHORITY_UNAVAILABLE`;
6. `BUDGET_SCOPE_MISSING`, `BUDGET_AUTHORITY_UNAVAILABLE`,
   `BUDGET_BINDING_CONFLICT`, `BUDGET_EXHAUSTED`, `BUDGET_ARITHMETIC_INVALID`;
7. `RECOVERY_BINDING_CONFLICT`, `RECOVERY_UNVERIFIED`,
   `RECOVERY_PROFILE_UNAPPROVED`.

`RECOVERY_UNAVAILABLE` and every `STORE_*` code are excluded from this enum.

### `PreparationFailureV1`

Closed definite operational failures:

| Variant | Stable code |
|---|---|
| `RecoveryProviderFailed` | `PREPARATION_RECOVERY_UNAVAILABLE` |
| `StoreUnavailable` | `PREPARATION_STORE_UNAVAILABLE` |
| `StoreBusy` | `PREPARATION_STORE_BUSY` |
| `StoreUnhealthy` | `PREPARATION_STORE_UNHEALTHY` |
| `StoreConflict` | `PREPARATION_STORE_CONFLICT` |
| `CommitAborted` | `PREPARATION_STORE_COMMIT_ABORTED` |
| `DefiniteAbsence` | `PREPARATION_STORE_DEFINITE_ABSENCE` |

A failure may retain redacted orphan-maintenance custody but never a positive marker.
Neither `CommitAborted` nor `DefiniteAbsence` performs automatic retry, budget release
or recovery retirement.

### `AmbiguousPreparationV1`

Closed internal reasons are:

```text
RecoveryPublicationUnclassified
CommitClassificationMissing
PermitOwnerOrProcessLost
PermitDeadlineReached
ReadbackUnavailable
ReadbackInconsistent
ReadbackLateOrRevoked
```

Every reason exposes only `PREPARATION_AMBIGUOUS` publicly and retains opaque
quarantine custody. It never means definite absence. Raw provider, SQLite and OS errors
remain internal and cannot select or move a result between public classes.

### `PreparedOperationV1`

Opaque non-Clone, non-Serde, non-transferable positive marker produced only by
`helix-plan-preparation` after exact same-attempt commit/readback and final guard/deadline
validation. It has no public constructor, wire encoding or adapter trait. It is not
approval, execution grant or effect authority. It owns the deliberately consumed
`EligiblePlanV1` plus opaque exact commit custody; no caller can reconstruct it from a
plan ID or durable status row.

### `PreparationOutcomeV1`

```text
Prepared(PreparedOperationV1)
Denied(PreparationDenialV1)
Failed(PreparationFailureV1)
Ambiguous(AmbiguousPreparationV1)
```

- `Failed` is one of the closed definite operational failures above and has no positive
  marker;
- `Ambiguous` is redacted reconciliation custody and never means definite absence;
- exact coherent prior preparation maps to the closed nonpositive
  `ALREADY_PREPARED` result;
- after return/restart, lookup exposes read-only status rather than recreating a marker.

## State transitions and atomicity

### Positive transition

```text
eligible plan + final guards + exact replay + verified recovery
  + existing sufficient budget scope
  -> one SQLite transaction
       enclosing store/operation/budget/event generations advance
       operation ABSENT -> PREPARING
       transition append ABSENT -> PREPARING
       comparison/replay evidence inserted
       scope held vector updated by exact request
       reservation ABSENT -> HELD
       recovery reference or irreversibility evidence inserted
       event ABSENT -> PREPARED/PENDING
```

These are the canonical eight logical members of the positive coordinator commit set;
all eight are visible or none is. External recovery bytes were already published and
are referenced by immutable receipt; replay-store and supervisor state also remain
outside this transaction. The recovery guard prevents concurrent retirement.

### Known pre-dispatch failure

```text
live NoDispatchAuthorityGuardV1
  + exact PREPARING operation/state generation/epochs
  -> one coordinator transaction
operation PREPARING -> FAILED
transition append PREPARING -> FAILED
reservation HELD -> RELEASED
scope held totals subtract exact stored vector once
event append PREPARATION_FAILED/PENDING
```

This is one transaction and the guard remains live through commit. Replay remains
claimed. A missing/revoked/mismatched guard mutates nothing. Recovery retirement is a
later guarded provider transition.

### Commit observation and uncertainty

```text
acknowledged commit
  -> final guard/deadline valid -> Prepared
  -> late/revoked               -> Ambiguous + quarantine

confirmed rollback
  -> Failed(PREPARATION_STORE_COMMIT_ABORTED)
  -> zero readback

missing/untrusted commit classification
  -> Ambiguous(PREPARATION_AMBIGUOUS)
  -> PAUSE, zero worker readback

explicit UNCERTAIN
  -> exactly one fresh healthy readback
       THIS_ATTEMPT and still valid       -> Prepared
       PRIOR_EXACT_ATTEMPT                -> Denied(PREPARATION_ALREADY_PREPARED)
       healthy coherent conflict          -> Denied(PREPARATION_OPERATION_CONFLICT)
       DEFINITE_ABSENCE                   -> Failed(PREPARATION_STORE_DEFINITE_ABSENCE)
       unavailable/partial/inconsistent/
       late/revoked                       -> Ambiguous(PREPARATION_AMBIGUOUS) + quarantine
```

No ambiguous or definite-absence path releases budget, deletes material, retries the
consumed plan or returns a marker. Confirmed rollback resolves immediately and does not
enter readback.

## Cross-record invariants

1. Metadata generations are safe and monotonic. Each is zero iff its domain has no
   transition, otherwise it equals the greatest retained transition generation; event,
   reservation and quarantine history proves the permitted sequence even when an
   operation row has advanced from its earlier generation.
2. Every operation has exactly one comparison record, one reservation, one current
   transition and at least one event; every such row points back to the same
   operation/plan/attempt.
3. Every `PREPARING` operation has a `HELD` reservation and a `PREPARED` event.
4. Every `FAILED` operation has a `RELEASED` reservation and exactly one terminal
   failure event; it cannot transition again. The live no-dispatch guard is not
   reconstructible from those durable rows.
5. Scope held totals equal the checked sum of `HELD` rows and never exceed totals.
6. Reservation, operation and attempt IDs are never rebound or reused.
7. Every state generation is permanently unique in the transition ledger and has
   exactly one matching event; prior generations remain after the current row advances.
8. Exactly one recovery receipt or irreversibility record exists per operation and
   matches its plan, precondition identity/digest/length, signed recovery-byte bound,
   budget reservation, profile/provider/capability/at-rest binding and epochs.
9. Compensable `PREPARING` requires `PUBLISHED` material. Compensable `FAILED` may retain
   `PUBLISHED`, `RETIREMENT_PENDING` or `RETIRED_TOMBSTONE`; pending blocks backup and a
   retired tombstone preserves the original receipt/digest/length without requiring the
   retired bytes. Irreversible operations are L2 and reference no material.
10. Canonical signed bytes decode exactly and reproduce the stored plan ID and projected
   fields.
11. No `DISPATCHING`, grant, adapter receipt, effect, settlement or compensation result
    column/table exists in schema v1.
12. Quarantine records cannot satisfy operation foreign keys or positive lookups.
13. Unknown schema, enum, table/index definition, extra file/member or weaker durability
    profile closes open/prepare without repair.
14. Coordinator and recovery roots are both `ACTIVE` with no restore ID, or both are
    independently `RESTORE_PENDING` with the same restore ID. Any mixed/unknown state
    denies ordinary open. The only coordinator lifecycle transition is irreversible
    `ACTIVE -> RESTORE_PENDING`; Feature 004 cannot activate either root.
15. An orphan quarantine becomes a permanent resolved tombstone with internal
    `RETIREMENT_PENDING` only after definitive no-reference proof and retains its
    resolution fields before provider retirement; pending authorization blocks backup
    and can never create an operation. Its immutable generations satisfy
    `created < resolved < retired` once fully retired, and it cannot transition backward.

## Backup and restore entities

### `PreparationBackupManifestV1`

Canonical top-level package consistency evidence, published before its detached
provenance attestation:

- schema/application/store versions and exact durability profile;
- opaque source coordinator/recovery root and instance identity digests and fixed
  `ACTIVE` source lifecycle;
- closed coordinator database SHA-256 and schema digest;
- store/operation-transition/budget/event/quarantine generations and counts;
- fixed-zero `operation_retirement_pending` and `orphan_retirement_pending` counts,
  cross-validated against both authoritative domains and inventory
  `no_retirement_pending=true`;
- canonical multi-provider inventory digest, provider-set count and entry count;
- required detached provenance schema/profile declaration; the manifest does not contain
  the attestation digest and therefore has no self-reference cycle;
- at-rest protection profile ID;
- `requires_paused_restore = true`;
- `requires_boot_epoch_rotation = true`;
- `requires_instance_epoch_rotation = true`;
- `requires_fencing_epoch_rotation = true`;
- `nonterminal_preparations_not_reactivatable = true`;
- `may_omit_work_after_generation = true`;
- no native path, plan/recovery content or private row identity.

Its nested recovery value has the distinct schema
`helixos.recovery-snapshot-summary/1` and binds the exact digest of the standalone
inventory, never a second incompatible object called `helixos.recovery-snapshot/1`.

The manifest is not provenance by itself. Its exact canonical digest is lowercase
SHA-256 of the complete object's RFC 8785 UTF-8 bytes with no BOM, prefix, suffix,
whitespace or trailing newline; the digest is not a member of that object. It is the
primary binding of `BackupProvenanceAttestationV1`, which is published afterward as the
final package publication point. Recovery Provider Contract sections 10.1–10.2 are the
single normative byte-encoding definitions.

### `RecoverySnapshotManifestV1`

Restricted canonical inventory with schema `helixos.recovery-snapshot/1`. Permanently
retained rows are grouped by provider-profile ID/version, provider ID/generation,
evidence class and at-rest profile. Groups are strictly sorted/unique by
`(provider_profile_id, provider_id, provider_generation)`. Within each group, entries
are strictly sorted by lowercase package-binding SHA-256 and have unique bindings.
`manifest_sha256` is also unique across the complete inventory because it is the
immutable coordinator/quarantine recovery-reference key; distinct package bindings
cannot reuse the same manifest digest. The closed decoder verifies each group count,
the checked sum against total `entry_count`
and exact RFC 8785 bytes before hashing. `inventory_sha256` is lowercase SHA-256 of the
complete standalone object's canonical bytes and is carried only by the top-level
summary, avoiding self-reference.

- `MATERIAL_PRESENT` entries require the original manifest and material bytes;
- `RETIRED_TOMBSTONE` entries retain original digest/length/capacity plus the immutable
  retirement-manifest digest and do not require retired bytes;
- every entry declares closed custody `OPERATION_BOUND`, `QUARANTINED_ORPHAN` or
  `ORPHAN_RESOLUTION_TOMBSTONE`; the complete set covers coordinator references, active
  quarantine and provider-enumerated packages under the quiescent guard;
- every entry requires `reserved_capacity >= material_length`;
- `RETIREMENT_PENDING` has no inventory representation and blocks backup.

### `BackupProvenanceAttestationV1`

Detached closed JSON envelope published after the top-level manifest. Its protected JCS
payload binds:

- contract/profile version and approved provisioner signing-profile/key identity;
- exact canonical top-level manifest SHA-256;
- opaque source coordinator/recovery root and instance identity digests;
- coordinator generations, recovery inventory SHA-256, provider generations and
  provider-set/entry counts;
- at-rest protection profile.

The Ed25519 signature covers
`HELIXOS\0PREPARATION-BACKUP-ATTESTATION\0V1\0 || JCS(protected)` and carries no raw key.
The protected manifest digest is computed exactly as Recovery Provider Contract section
10.2 defines; neither the attestation envelope nor signature enters that digest.
Restore uses pinned sovereign trust/revocation configuration; missing, altered, unknown
or revoked evidence denies before either destination root is published. Internally
consistent package digests without this proof are not provenance.

### `VerifiedPreparationRestoreV1`

Redacted non-authoritative evidence returned only after clean empty-root restore,
provenance verification, database/recovery digest verification, cross-record checks,
WAL/FULL establishment, and close/reopen verification of the same independently durable
restore ID plus `RESTORE_PENDING` in both roots. It exposes bounded counts/generations
and all fixed activation requirements, never activation authority. Ordinary open,
prepare and retirement deny on either pending root, and Feature 004 has no activation
transition. Its fields and constructors are private, and Feature 004 exposes no public
producer; an external host may receive or return this projection only after a later
feature supplies the complete sovereign authority boundary.

### `RestoredPreparationMaintenanceEvidenceV1`

Redacted non-authoritative evidence from one bounded crate-internal old-authority
reconciliation pass. It contains only the pending-root verification projection and safe
counts for inspected, failed, already-failed and retained-quarantine records. It carries
no root, identifier, digest, provider diagnostic, limit input, error payload, guard,
constructor, producer or activation capability. The maintenance limits, errors and all
operations that can produce it remain crate-internal in Feature 004.

## Data classification and retention

| Data | Class | Retention |
|---|---|---|
| canonical signed plan and comparison rows | source classification, at least confidential | indefinite in v1 |
| recovery material and manifests | source classification | while PREPARING/ambiguous/quarantined; guarded retirement after FAILED reconciliation or permanent true-orphan resolution |
| operation/failed records | restricted operational | indefinite; no pruning |
| reservation/release rows | restricted financial/operational | permanent tombstones |
| event outbox rows | restricted audit | permanent after delivery |
| quarantine/retirement rows | restricted recovery evidence | permanent tombstones |
| synthetic fixture corpus | reviewed public synthetic | repository lifecycle |

Production roots require an approved encrypted-at-rest provisioning profile. Backups
remain in approved encrypted storage/transport. There is no automatic pruning, public
deletion API or physical secure-erasure claim in v1; shorter retention requires a later
versioned policy/amendment.
