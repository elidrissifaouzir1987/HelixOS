# Data Model: Current Plan Eligibility

## Boundary and ownership

Feature 002 adds one removable leaf crate, `kernel/helix-plan-eligibility`. Its
positive transition is:

```text
AuthenticPlanEnvelopeV1
  + EligibilityContextV1<'_> captured by the sovereign core
  + ReplayClaimantV1
    -> EligiblePlanV1 | EligibilityFailureV1
```

`AuthenticPlanEnvelopeV1` proves canonical cryptographic authenticity only. It is not
evidence that any mutable authority remains current. `EligiblePlanV1` owns that
authentic envelope after all read-only gates and one new atomic replay claim succeed,
but is still only a point-in-time prerequisite. It is not approval, preparation
authority, an `ExecutionGrant`, or an adapter input.

The eligibility crate has no runtime dependency other than `helix-contracts`. Its
production model contains no Serde traits, native clock/path/handle types, filesystem or
network client, async runtime, process-global provider, or OS-conditional behavior.

## Feature-001 projection

### `AuthenticPlanEnvelopeV1` verification evidence

Feature 001 retains one additional non-wire value after strict signature verification:

- `verified_key_fingerprint`: `Sha256Digest` of the exact 32 Ed25519 public-key bytes
  used by `decode_and_verify_plan`.

The fingerprint is computed only after trusted key resolution and is stored beside the
authentic marker. It is not added to `PlanProtectedV1`, canonical JSON, `plan_id`, the
signature message, or any feature-001 fixture. Cloning an authentic marker copies the
fingerprint; converting it back to a signed envelope intentionally discards this
non-wire verification evidence.

### `PlanEligibilityClaimsV1<'plan>`

An authentic envelope exposes one borrowed, read-only projection. It has no public
constructor, no deserialization, and a redacted `Debug`. It does not copy replacement
content or create authority.

The projection contains:

- envelope evidence: `plan_id`, signed `key_id`, and `verified_key_fingerprint`;
- operation binding: `operation_id`, `task_id`, `workload_id`, `boot_id`,
  `instance_epoch`, and `fencing_epoch`;
- lease/source binding: `task_lease_digest`, request-source kind, and request-source
  digest;
- semantic binding: schema, intent kind, risk level, policy version, catalogue
  version, target root/subtree, and budget reservation fields;
- capability binding: report digest, exact observation time, and the sorted required
  capability slice;
- validity/replay binding: issuance, exclusive UTC expiry, and nonce.

All strings and slices borrow from the authenticated protected plan. Digests, nonce,
epochs, limits, and timestamps are copied fixed-size portable values. The projection is
safe to inspect but remains cryptographic evidence only.

## Trusted eligibility context

### `EligibilityContextV1<'ctx>`

The sovereign coordinator captures one fixed context before calling the evaluator. The
context borrows immutable provider snapshots and contains no callback. Its public shape
is a sum type: terminal `Unavailable`, `Incomplete`, and `Torn` variants carry no dummy
provider values; `Ready(ReadyEligibilityContextV1<'ctx>)` carries the complete checked
record below. Provider resolutions use the same terminal-variant-plus-record pattern.
Private record fields and checked constructors preserve bounds, sorted/unique
collections, and scalar time semantics; the type name alone is not a trust proof.
Agent-facing RPC code must never expose a constructor for it.

`ReadyEligibilityContextV1` fields:

- `bound_plan_id`: the exact plan for which facts and decisions were resolved;
- `capture_generation`: coordinator-owned generation for this captured set;
- `time`: wall and monotonic observations plus clock-health generation;
- `plan_deadline`: trusted plan-store monotonic record;
- `supervisor`: admission state, boot and epochs;
- `signer`: current key-trust resolution;
- `workload`: current authenticated workload identity;
- `lease`: unique lease resolution and plan-bound authority decision;
- `authorization`: current plan-bound authorization evidence;
- `policy`: immutable policy resolution and current decision;
- `catalogue`: immutable catalogue resolution and schema/intent support;
- `capabilities`: current report, host/driver context and available set.

Unavailable, inconsistent and ambiguous provider results are represented by closed
status variants, never by missing dummy values or arbitrary error strings. In
particular, the context contains neither `nonce_unused`, a pre-reserved nonce, a claim
token, nor a prior replay receipt.

Checked construction failures use the separate payload-free
`EligibilityContextBuildErrorV1` taxonomy: `CONTEXT_BUILD_INTEGER_OUT_OF_RANGE`,
`CONTEXT_BUILD_INVALID_INTERVAL`, `CONTEXT_BUILD_INVALID_IDENTIFIER`,
`CONTEXT_BUILD_INVALID_CAPABILITY_SET`, and `CONTEXT_BUILD_LIMIT_EXCEEDED`. These are
fixture outcomes but never runtime `EligibilityDenialV1` values. V1 bounds every
identifier and capability name to 128 UTF-8 bytes, available capabilities to 128,
policy-mandatory capabilities to 64, catalogue-mandatory capabilities to 64, and every
generation/time scalar to `SafeU64`.

### Clock and plan-deadline views

`TimeViewV1<'ctx>` contains:

- `now_utc_unix_ms` as a bounded non-negative integer;
- `now_monotonic_ms` as a bounded boot-local suspend-aware tick;
- the monotonic sample's `boot_id`;
- `clock_generation`;
- wall status: `Healthy`, `Unavailable`, or `RollbackSuspected`;
- monotonic status: `Healthy`, `Unavailable`, `Regressed`, or `NotSuspendAware`.

`PlanDeadlineRecordV1<'ctx>` is resolved by `(plan_id, boot_id)` from the trusted plan
store and contains:

- `plan_id` and `boot_id`;
- exclusive `deadline_monotonic_ms`;
- `deadline_generation`;
- status `Current`, `Missing`, `Unavailable`, or `Inconsistent`.

No UTC value is converted into ticks during evaluation. A deadline is created alongside
plan issuance and is never rebased after reboot.

### `SupervisorViewV1<'ctx>`

Fields:

- resolution: `Unavailable`, `Inconsistent`, or `Current`;
- current admission state: `Open`, `Paused`, `Aborting`, `Halted`, or `Restoring`;
- current `boot_id`, `instance_epoch`, and `fencing_epoch`;
- `supervisor_generation`.

Only `Open` admits a plan. Both stale and ahead plan epochs deny; plan data never
advances supervisor state.

### `SignerTrustViewV1<'ctx>`

Fields:

- current `key_id` and exact `public_key_fingerprint`;
- status: `Trusted`, `Revoked`, `Unknown`, `Unavailable`, or `Inconsistent`;
- `trust_generation`;
- `minimum_accepted_issued_at_unix_ms` for that generation.

The signed key identifier, verification fingerprint and current trust fingerprint must
all match. The minimum issuance value prevents a revoked or replaced generation from
silently reviving an older authentic plan. Key identifiers are immutable and never
reassigned to different bytes; rotation issues a new identifier and retains the old
public entry for historical verification. A registry that reports reuse is
`Inconsistent`.

### `WorkloadIdentityViewV1<'ctx>`

Fields:

- `workload_id`, identity-evidence digest and `identity_generation`;
- status: `Trusted`, `Revoked`, `Unknown`, `Unavailable`, or `Inconsistent`;
- `boot_id` and `instance_epoch`;
- inclusive UTC not-before and exclusive UTC expiry;
- same-boot exclusive monotonic deadline.

The identity grants no scope by itself. Its task authority is supplied only by the
active lease.

### `LeaseResolutionV1<'ctx>` and `ActiveLeaseViewV1<'ctx>`

Resolution is closed: `ExactlyOne`, `NotFound`, `Multiple`, `Unavailable`, or
`Inconsistent`. `ExactlyOne` borrows an active lease view with:

- exact canonical `lease_digest` and `lease_generation`;
- state `Active`, `Revoked`, or `Exhausted`; time expiry is computed from the explicit
  deadlines so its denial remains reachable and unambiguous;
- `task_id`, `workload_id`, `boot_id`, and `instance_epoch`;
- request-source kind and digest;
- inclusive UTC not-before, exclusive UTC expiry, and exclusive same-boot monotonic
  deadline;
- `LeaseAuthorityDecisionV1` and its digest.

The plan-bound lease decision is one of:

- `Allows { plan_id, decision_digest }`;
- `PlanMismatch`;
- `IntentDenied`;
- `ScopeWidened`;
- `BudgetWidened`;
- `PriceTableMismatch`;
- `ReservationMismatch`;
- `Unavailable` or `Inconsistent`.

`Allows` means that the intent, target root/subtree, action/byte/cost/egress limits,
currency, price table and reservation are no wider than this exact lease. The evaluator
does not trust a free-standing boolean from the agent.

### `AuthorizationViewV1<'ctx>`

Fields:

- resolution: `Unavailable`, `Inconsistent`, or `Current`;
- current status: `Granted`, `Denied`, or `Revoked`; time expiry is computed from the
  explicit deadlines;
- `plan_id`, `operation_id`, risk level and nonce;
- authorization-evidence digest and `authorization_generation`;
- `boot_id`;
- inclusive UTC not-before, exclusive UTC expiry, and exclusive same-boot monotonic
  deadline.

The view is the output of a trusted authorization verifier. Raw WebAuthn assertions,
human-facing summaries and approval UI behavior are outside this feature.

### `PolicyViewV1<'ctx>`

Fields:

- signed version identity from the plan;
- immutable registry-resolved content digest and active content digest;
- current `policy_generation`, the policy generation used by the decision, and decision
  generation;
- status `Current`, `Unknown`, `Unavailable`, `IdentifierReused`, or `Inconsistent`;
- a plan-bound `Allow { plan_id, decision_digest }` or
  `Deny { plan_id, decision_digest }` decision;
- maximum capability age in milliseconds;
- bounded sorted unique mandatory capability slice for the declared intent.

Because plan v1 signs a policy identifier rather than its content digest, the trusted
registry must enforce an immutable one-to-one identifier-to-digest mapping. A changed
digest under an existing identity is an inconsistency, never an approval fallback.

### `CatalogueViewV1<'ctx>`

Fields:

- signed version identity from the plan;
- immutable registry-resolved content digest and active content digest;
- current `catalogue_generation`, the catalogue generation used by the decision, and
  decision generation;
- status `Current`, `Unknown`, `Unavailable`, `IdentifierReused`, or `Inconsistent`;
- explicit decision `plan_id` and plan-bound decision digest;
- explicit closed results for plan schema support and intent support;
- bounded sorted unique catalogue-mandatory capabilities.

The same immutable identity rule used for policy applies to the catalogue.

### `CapabilityViewV1<'ctx>`

Fields:

- report digest and exact `observed_at_unix_ms`;
- report `boot_id`, `instance_epoch`, and `report_generation`;
- report and current opaque host/driver-context digests;
- status `Current`, `Unknown`, `Unavailable`, or `Inconsistent`;
- bounded sorted unique available capability slice.

The report digest and observation time must equal the protected plan. Its boot,
instance, and host/driver context must be current. Available capabilities must contain
both the plan-required set and the current policy/catalogue-mandatory union. A changed
report requires replan even if it appears to add capabilities.

## Time bounds

Wall validity uses exactly:

```text
issued_at_unix_ms <= now_utc_unix_ms < expires_at_unix_ms
```

Every boot-monotonic validity uses:

```text
now_monotonic_ms < deadline_monotonic_ms
```

Feature 001 already validates `observed_at <= issued_at`; eligibility first validates
`issued_at <= now` and exact equality between the protected and current observation.
Consequently `observed_at > now` is unreachable for an authentic plan, while a
context-only future value fails as an observation mismatch. Freshness nevertheless uses
checked subtraction and accepts exactly:

```text
now_utc_unix_ms - observed_at_unix_ms <= max_capability_age_ms
```

All subtraction, addition, minimum and range validation is checked. Overflow denies.

The owned `EffectiveEligibilityBoundsV1` retains:

- the earliest exclusive UTC expiry among plan, workload, lease and authorization;
- the capability freshness limit and its inclusive boundary;
- the earliest exclusive monotonic deadline among plan record, workload, lease and
  authorization;
- the shared boot ID, evaluation UTC value and evaluation monotonic value.

Keeping the inclusive freshness boundary explicit avoids an overflow-prone conversion
to an artificial `fresh_through + 1` exclusive deadline.

## Internal read-only state

### `ValidatedEligibilityV1<'plan, 'ctx>` (crate-private)

This non-public typestate is constructed only after all read-only gates succeed. It
borrows the authentic plan claims and contains owned effective bounds, generation and
digest bindings, plus the exact replay request. It has no public constructor, is never
returned to a caller, and cannot be stored or treated as authority.

Its existence proves only that the claimant may now be invoked. The evaluator performs
no other call, allocation-dependent lookup, clock read or provider operation between
constructing this value and calling `ReplayClaimantV1::claim_once`.

## Replay model

### `ReplayBindingV1<'plan>`

The read-only request uses uniqueness key `(instance_epoch, nonce)` in the stable
plan-v1 issuer namespace and binds:

- `key_id` and `verified_key_fingerprint` as compared binding evidence rather than as
  part of the uniqueness key;
- `plan_id` and `operation_id`;
- `task_id`, `workload_id`, and `task_lease_digest`;
- current signer trust generation;
- `instance_epoch`, `fencing_epoch`, and the caller-owned exclusive absolute deadline
  for the claim call in the same trusted suspend-aware boot-monotonic clock domain.

It has private fields, narrow accessors, no serialization and a redacted `Debug`.

The deadline bounds implementable claimant behavior rather than promising cancellation
of arbitrary synchronous kernel I/O. A production claimant performs no mutation when the
deadline is already reached, bounds intentional lock waiting by the remaining budget,
rechecks after writer acquisition and immediately before/after commit or readback,
returns no positive outcome at or after the deadline, and leaves no detached mutation
after return. A definitely pre-mutation failure or confirmed rollback is `Unavailable`;
a possibly committed write that is late or cannot be proved by timely readback is
`Ambiguous`. The five `ReplayClaimOutcomeV1` variants and all v1 field types remain
unchanged.

### `ReplayClaimOutcomeV1`

Closed outcomes:

- `Claimed(ReplayClaimReceiptV1)`;
- `AlreadyClaimed`;
- `BindingConflict`;
- `Unavailable`;
- `Ambiguous`.

Only `Claimed` is positive. An identical prior binding is still `AlreadyClaimed`, not
idempotent success, because one replay claim may produce only one eligible instance.

### `ReplayClaimReceiptV1`

Owned fields:

- opaque bounded `claim_id`;
- claimant/store generation;
- domain-separated binding digest of the exact request.

The receipt is created through a checked public constructor so an external claimant can
implement the trait. It is not an execution receipt, does not implement Serde and has
redacted `Debug`. The evaluator recomputes and compares the binding digest before marker
construction; a mismatch maps to `REPLAY_RECEIPT_BINDING_MISMATCH`. A production
claimant must durably create it in the same atomic transaction as both nonce and
operation indexes. The test claimant proves linearizable contention only, not crash
durability.

## Positive and negative results

### `EligibilityFailureV1`

Owns:

- the original `AuthenticPlanEnvelopeV1`;
- one payload-free `EligibilityDenialV1`.

It is not cloneable or serializable. `denial()` and `into_authentic()` are the only
recovery-oriented accessors. Returning the plan preserves sovereign custody and allows
safe pre-claim facts to be resolved again; it does not authorize automatic retry after
`REPLAY_AMBIGUOUS`, successful prior claim, or binding conflict.

### `EligiblePlanV1`

Owns:

- the original authentic plan;
- `EffectiveEligibilityBoundsV1`;
- `EligibilityBindingsV1`;
- the new `ReplayClaimReceiptV1`.

`EligibilityBindingsV1` records every mutable fact used by the decision:

- capture, clock, plan-deadline and supervisor generations;
- exact boot, instance epoch and fencing epoch;
- signer trust generation and verification-key fingerprint;
- workload identity generation and evidence digest;
- lease generation, lease digest and lease-decision digest;
- authorization generation and evidence digest;
- policy generation, immutable content digest and decision digest;
- catalogue generation, immutable content digest and decision digest;
- capability report generation, report digest and host/driver-context digest;
- replay claim identifier/generation and binding proof.

The marker has private fields, no public constructor, `Clone`, `Copy`, Serde or wire
encoding. Its `Debug` omits every identifier, digest, nonce, resource, signature and
provider value. A future durable coordinator must atomically compare the carried
generations and deadlines again before `PREPARING`; any change discards the marker and
requires a new evaluation.

## Stable denial taxonomy

`EligibilityDenialV1` is a closed payload-free enum. The normative ordered codes and
their gates are defined in `contracts/plan-eligibility-v1.md`. `code()` returns only a
stable SCREAMING_SNAKE_CASE string. `Display`, `Debug` and `Error::source()` never expose
expected/actual values or wrapped provider errors.

## State transitions and invariants

```text
strict canonical decode + exact-key signature verification
  -> AuthenticPlanEnvelopeV1(key fingerprint retained)

Authentic + fixed trusted context
  -> first read-only denial
       -> EligibilityFailureV1(authentic, denial); replay untouched
  -> crate-private ValidatedEligibilityV1
       -> replay AlreadyClaimed/Conflict/Unavailable/Ambiguous
            -> EligibilityFailureV1(authentic, replay denial); never release
       -> new atomic Claim
            -> EligiblePlanV1(authentic, bounds, bindings, receipt)

EligiblePlanV1
  -> bound fact/deadline changed before PREPARING: discard and re-evaluate
  -> future atomic compare + durable PREPARING: out of scope
```

Replay-state invariants:

- unclaimed may transition to one permanently claimed exact binding;
- both `(instance_epoch, nonce)` and `operation_id` uniqueness change at one
  linearization point;
- claimed never transitions back to unclaimed;
- an ambiguous caller outcome is treated as possibly claimed and requires
  reconciliation or replan, never blind retry;
- no failed read-only gate consumes replay state;
- exactly one contender may receive `Claimed` for one replay authority domain.

Authority invariants:

- authentic is not current, eligible is not approved-for-effect, and neither is an
  `ExecutionGrant`;
- no host-effect adapter may depend on `helix-plan-eligibility` or accept its markers;
  the reviewed non-authority `helix-replay-sqlite` leaf may depend on it only to
  implement `ReplayClaimantV1` and consume replay binding/outcome types;
- no plan claim, including an ahead epoch, mutates a trusted provider;
- no public positive boolean or storable read-only candidate exists;
- current facts are provider-owned, not reconstructed from the plan or agent input.

## Portability, compatibility and removal

All common values are bounded strings, fixed digests/nonces, sorted slices, integer UTC
milliseconds, or boot-scoped monotonic milliseconds. The same
`contracts/fixtures/plan-eligibility-v1/` corpus and stable outcome summary run unchanged
on Windows, Linux and macOS arm64.

Feature 002 adds no wire version or persisted eligible state. Removal first removes any
reviewed `ReplayClaimantV1` provider such as feature 003, then removes the leaf workspace
member and its source, fixtures, CI and spec artefacts, plus the non-wire claims
projection and verification fingerprint if they have no remaining consumer.
Feature-001 canonical bytes, `plan_id`, signatures, fixtures and legacy runtime behavior
remain unchanged.
