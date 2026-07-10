# Plan Eligibility v1 In-Process Contract

## Purpose and authority

This contract promotes one cryptographically authentic plan only when a fixed set of
core-controlled current facts still matches it and one new atomic replay claim succeeds.
It is an in-process Rust contract, not a wire format.

```text
AuthenticPlanEnvelopeV1 + EligibilityContextV1 + ReplayClaimantV1
  -> EligiblePlanV1 | EligibilityFailureV1
```

Authenticity proves canonical provenance only. Eligibility is a point-in-time necessary
condition only. Neither type is approval, durable preparation authority, an
`ExecutionGrant`, or an adapter input. No adapter may depend on this crate.

## Public surface

The sole public positive transition is structurally equivalent to:

```rust
pub fn evaluate_and_claim_plan_v1<C: ReplayClaimantV1 + ?Sized>(
    plan: AuthenticPlanEnvelopeV1,
    context: EligibilityContextV1<'_>,
    claimant: &C,
) -> Result<EligiblePlanV1, EligibilityFailureV1>;
```

There is no public `assess`, `validate`, `reserve`, `release`, `reset`, or
`nonce_unused` API. The read-only positive candidate is crate-private and cannot be
stored or used by a caller.

`EligibilityContextV1` borrows one fixed, core-captured set of trusted provider facts.
It is a sum type whose `Unavailable`, `Incomplete`, and `Torn` variants require no dummy
facts and whose `Ready` variant contains one complete record. Provider resolutions use
terminal variants plus checked resolved records. Construction must be controlled by the
sovereign core; the type name is not itself a trust proof and constructors must not be
exposed through agent-facing RPC.

Checked construction has a separate closed redacted error contract:

```text
CONTEXT_BUILD_INTEGER_OUT_OF_RANGE
CONTEXT_BUILD_INVALID_INTERVAL
CONTEXT_BUILD_INVALID_IDENTIFIER
CONTEXT_BUILD_INVALID_CAPABILITY_SET
CONTEXT_BUILD_LIMIT_EXCEEDED
```

These codes are conformance outcomes but never eligibility denials. V1 freezes
identifier and capability-name length at 128 UTF-8 bytes, available capabilities at
128, policy-mandatory capabilities at 64, catalogue-mandatory capabilities at 64, and
all generations/time values to `SafeU64`. Constructors validate shape only; the
sovereign integration is responsible for provider trust.

On success, `EligiblePlanV1` owns the authentic plan, effective time bounds, all
generations/digests used by the decision, and the new replay receipt. On failure,
`EligibilityFailureV1` owns the authentic plan and one payload-free denial. The failure
exposes only `denial()` and `into_authentic()`. Returning the plan does not permit an
automatic retry after an ambiguous or previously committed replay claim.

Neither result type has a public constructor, `Clone`, `Copy`, Serde implementation, or
wire encoding. Both have redacted `Debug` implementations.

## Feature-001 claims projection

`helix-contracts` adds this read-only projection without changing signed bytes:

```rust
impl AuthenticPlanEnvelopeV1 {
    pub fn eligibility_claims(&self) -> PlanEligibilityClaimsV1<'_>;
}
```

`PlanEligibilityClaimsV1<'_>` exposes only the protected bindings enumerated in
`../data-model.md`, plus `SHA-256` of the exact Ed25519 public-key bytes that verified
the signature. The fingerprint is non-wire verification evidence retained by
`decode_and_verify_plan`; it is not part of `PlanProtectedV1`, canonical JSON,
`plan_id`, or the signature message. The claims view has no public constructor,
`Serialize`/`Deserialize` implementation, or unredacted diagnostic representation.

Signing-key identifiers are immutable in the v1 trust domain. Rotation issues a new
identifier and retains historical public keys. The non-wire fingerprint detects a held
marker whose trust entry changed; it cannot make a reused identifier safe during a new
decode, so registry reuse is an inconsistency and MUST deny.

## Exact evaluation order

The evaluator returns the first failure in the following total order. It MUST NOT run
checks in parallel, aggregate failures, or reorder them for performance. Steps 1-5 are
read-only. `ReplayClaimantV1::claim_once` is the only external effect and is called
exactly once and last, only after every preceding check passes.

### 1. Context and admission

1. Context health is `Ready`, complete and coherent.
2. `context.bound_plan_id == claims.plan_id`.
3. Supervisor facts are available and internally consistent.
4. Supervisor admission state is exactly `Open`.

### 2. Time, boot and epochs

1. Wall clock is available and not rollback-suspect.
2. `claims.issued_at <= now_utc < claims.expires_at`.
3. Context, monotonic sample, supervisor and plan use the exact same boot ID.
4. The suspend-aware monotonic sample is available and non-regressing.
5. The trusted plan-deadline record resolves the exact plan and boot.
6. `now_monotonic < plan_deadline`.
7. Plan instance epoch equals current instance epoch exactly.
8. Plan fencing epoch equals current supervisor epoch exactly.

At issuance the plan is valid; at UTC expiry it is invalid. At the monotonic deadline
it is invalid. Stale and ahead epochs both deny and never mutate trusted state.

### 3. Signer, workload, lease and authorization

1. Current signer trust resolves the signed key ID.
2. Its public-key fingerprint equals the exact verification fingerprint retained by the
   authentic marker.
3. The key is currently trusted and the plan issuance is accepted by the current trust
   generation.
4. Workload identity, boot and instance match; the identity is trusted and inside both
   its UTC and same-boot monotonic windows.
5. Exactly one lease resolves from the signed digest. It is active, unrevoked and
   unexhausted; task, workload, boot, instance and request source match; both time
   windows are current.
6. The plan-bound lease decision affirms intent, resource subtree, action/byte/cost and
   egress limits, currency, price table and reservation without widening.
7. Authorization is currently granted and binds the exact plan, operation, risk,
   nonce, boot and effective UTC/monotonic windows.

This check attests only that the trusted authorization view was current at evaluation.
The eligible marker contains no raw WebAuthn assertion and is not itself approval
evidence, durable authorization consumption, or effect authority.

### 4. Policy and catalogue

1. The signed policy identity resolves through an immutable registry.
2. Resolved and active policy content digests match; the decision's policy generation
   equals the current policy generation; the exact decision `plan_id` matches and its
   result is affirmative.
3. The signed catalogue identity resolves through an immutable registry.
4. Resolved and active catalogue content digests match; the decision's catalogue
   generation equals the current catalogue generation; its exact decision `plan_id`
   matches and the schema/intent remain supported.

For plan v1, policy/catalogue identifiers are signed but their content digests are not.
The trusted registries MUST therefore enforce an immutable one-to-one mapping from each
identifier to one content digest. Identifier reuse with other bytes is inconsistency and
denies; human approval is never a fallback.

### 5. Capabilities

1. The exact report digest and observation time match the plan.
2. Report boot, instance and opaque host/driver context match current facts.
3. Feature 001 has already proved `observed_at <= issued_at`, this evaluator proves
   `issued_at <= now`, and the current observation must equal the protected value.
   Therefore a future observation is not a reachable authentic-plan state; a
   context-only future value denies earlier as `CAPABILITY_OBSERVATION_MISMATCH`.
4. Freshness still uses checked integer arithmetic and accepts exactly
   `now_utc - observed_at <= max_age`; one millisecond older denies.
5. The bounded sorted available set contains every plan-required capability and every
   currently policy/catalogue-mandatory capability.

No capability is inferred from an OS or architecture name. Immediate adapter re-probe
before effect remains outside this feature.

### 6. Atomic replay claim

After steps 1-5 pass, the evaluator constructs the exact replay binding and invokes the
claimant. A successful new receipt constructs `EligiblePlanV1`; every other outcome
constructs `EligibilityFailureV1` with the matching replay denial.

## Stable denial taxonomy

`EligibilityDenialV1` is a closed payload-free enum. `code()` returns the exact string
below. Codes are listed in first-failure order within their gate; implementations and
fixtures MUST preserve this order.

| Gate | Ordered stable codes |
|---|---|
| Context | `CONTEXT_UNAVAILABLE`, `CONTEXT_INCOMPLETE`, `CONTEXT_TORN`, `CONTEXT_PLAN_MISMATCH`, `SUPERVISOR_UNAVAILABLE`, `SUPERVISOR_INCONSISTENT`, `SUPERVISOR_NOT_OPEN` |
| Time / boot / epochs | `WALL_CLOCK_UNAVAILABLE`, `WALL_CLOCK_ROLLBACK_SUSPECTED`, `PLAN_NOT_YET_VALID`, `PLAN_EXPIRED`, `BOOT_MISMATCH`, `MONOTONIC_CLOCK_UNAVAILABLE`, `MONOTONIC_CLOCK_UNSUITABLE`, `MONOTONIC_CLOCK_REGRESSED`, `PLAN_DEADLINE_UNAVAILABLE`, `PLAN_DEADLINE_INCONSISTENT`, `PLAN_DEADLINE_MISMATCH`, `MONOTONIC_DEADLINE_REACHED`, `INSTANCE_EPOCH_MISMATCH`, `FENCING_EPOCH_MISMATCH` |
| Signer | `SIGNER_TRUST_UNAVAILABLE`, `SIGNER_TRUST_INCONSISTENT`, `SIGNER_KEY_MISMATCH`, `SIGNER_FINGERPRINT_MISMATCH`, `SIGNER_NOT_TRUSTED`, `SIGNER_GENERATION_REJECTS_PLAN` |
| Workload | `WORKLOAD_UNAVAILABLE`, `WORKLOAD_INCONSISTENT`, `WORKLOAD_ID_MISMATCH`, `WORKLOAD_NOT_TRUSTED`, `WORKLOAD_BOOT_MISMATCH`, `WORKLOAD_INSTANCE_EPOCH_MISMATCH`, `WORKLOAD_NOT_YET_VALID`, `WORKLOAD_EXPIRED`, `WORKLOAD_MONOTONIC_EXPIRED` |
| Lease | `LEASE_UNAVAILABLE`, `LEASE_INCONSISTENT`, `LEASE_NOT_FOUND`, `LEASE_AMBIGUOUS`, `LEASE_DIGEST_MISMATCH`, `LEASE_NOT_ACTIVE`, `LEASE_TASK_MISMATCH`, `LEASE_WORKLOAD_MISMATCH`, `LEASE_BOOT_MISMATCH`, `LEASE_INSTANCE_EPOCH_MISMATCH`, `LEASE_SOURCE_MISMATCH`, `LEASE_NOT_YET_VALID`, `LEASE_EXPIRED`, `LEASE_MONOTONIC_EXPIRED`, `LEASE_DECISION_UNAVAILABLE`, `LEASE_DECISION_INCONSISTENT`, `LEASE_DECISION_PLAN_MISMATCH`, `LEASE_INTENT_DENIED`, `LEASE_SCOPE_WIDENED`, `LEASE_BUDGET_WIDENED`, `LEASE_PRICE_TABLE_MISMATCH`, `LEASE_RESERVATION_MISMATCH` |
| Authorization | `AUTHORIZATION_UNAVAILABLE`, `AUTHORIZATION_INCONSISTENT`, `AUTHORIZATION_NOT_GRANTED`, `AUTHORIZATION_PLAN_MISMATCH`, `AUTHORIZATION_OPERATION_MISMATCH`, `AUTHORIZATION_RISK_MISMATCH`, `AUTHORIZATION_NONCE_MISMATCH`, `AUTHORIZATION_BOOT_MISMATCH`, `AUTHORIZATION_NOT_YET_VALID`, `AUTHORIZATION_EXPIRED`, `AUTHORIZATION_MONOTONIC_EXPIRED` |
| Policy | `POLICY_UNAVAILABLE`, `POLICY_INCONSISTENT`, `POLICY_IDENTITY_MISMATCH`, `POLICY_CONTENT_MISMATCH`, `POLICY_GENERATION_MISMATCH`, `POLICY_DECISION_PLAN_MISMATCH`, `POLICY_DENIED` |
| Catalogue | `CATALOGUE_UNAVAILABLE`, `CATALOGUE_INCONSISTENT`, `CATALOGUE_IDENTITY_MISMATCH`, `CATALOGUE_CONTENT_MISMATCH`, `CATALOGUE_GENERATION_MISMATCH`, `CATALOGUE_DECISION_PLAN_MISMATCH`, `CATALOGUE_SCHEMA_UNSUPPORTED`, `CATALOGUE_INTENT_UNSUPPORTED` |
| Capabilities | `CAPABILITY_UNAVAILABLE`, `CAPABILITY_INCONSISTENT`, `CAPABILITY_NOT_FOUND`, `CAPABILITY_DIGEST_MISMATCH`, `CAPABILITY_OBSERVATION_MISMATCH`, `CAPABILITY_BOOT_MISMATCH`, `CAPABILITY_INSTANCE_EPOCH_MISMATCH`, `CAPABILITY_CONTEXT_MISMATCH`, `CAPABILITY_STALE`, `REQUIRED_CAPABILITY_MISSING`, `MANDATORY_CAPABILITY_MISSING` |
| Replay | `REPLAY_ALREADY_CLAIMED`, `REPLAY_BINDING_CONFLICT`, `REPLAY_UNAVAILABLE`, `REPLAY_AMBIGUOUS`, `REPLAY_RECEIPT_BINDING_MISMATCH` |

Checked context constructors may reject malformed bounds, unsorted/duplicate sets, or
impossible intervals before evaluation; they never construct a partially valid context.
Runtime provider absence, ambiguity and inconsistency remain representable and map to
the stable codes above.

### Exhaustive status mapping

Terminal/status variants map before field comparison as follows; no variant may fall
through to a generic code:

| View status | Required denial |
|---|---|
| context `Unavailable` / `Incomplete` / `Torn` | `CONTEXT_UNAVAILABLE` / `CONTEXT_INCOMPLETE` / `CONTEXT_TORN` |
| supervisor `Unavailable` / `Inconsistent` / non-`Open` | `SUPERVISOR_UNAVAILABLE` / `SUPERVISOR_INCONSISTENT` / `SUPERVISOR_NOT_OPEN` |
| plan deadline `Missing` or `Unavailable` / `Inconsistent` | `PLAN_DEADLINE_UNAVAILABLE` / `PLAN_DEADLINE_INCONSISTENT` |
| signer `Unavailable` / `Inconsistent` / `Unknown` or `Revoked` | `SIGNER_TRUST_UNAVAILABLE` / `SIGNER_TRUST_INCONSISTENT` / `SIGNER_NOT_TRUSTED` |
| workload `Unavailable` / `Inconsistent` / `Unknown` or `Revoked` | `WORKLOAD_UNAVAILABLE` / `WORKLOAD_INCONSISTENT` / `WORKLOAD_NOT_TRUSTED` |
| lease `Unavailable` / `Inconsistent` / `NotFound` / `Multiple` | `LEASE_UNAVAILABLE` / `LEASE_INCONSISTENT` / `LEASE_NOT_FOUND` / `LEASE_AMBIGUOUS` |
| resolved lease `Revoked` or `Exhausted` | `LEASE_NOT_ACTIVE` |
| lease decision `Unavailable` / `Inconsistent` / `PlanMismatch` / `IntentDenied` / `ScopeWidened` / `BudgetWidened` / `PriceTableMismatch` / `ReservationMismatch` | the correspondingly named `LEASE_DECISION_*` or `LEASE_*` code in the table above |
| authorization `Unavailable` / `Inconsistent` / `Denied` or `Revoked` | `AUTHORIZATION_UNAVAILABLE` / `AUTHORIZATION_INCONSISTENT` / `AUTHORIZATION_NOT_GRANTED` |
| policy `Unavailable` / `Inconsistent` / `Unknown` / `IdentifierReused` | `POLICY_UNAVAILABLE` / `POLICY_INCONSISTENT` / `POLICY_IDENTITY_MISMATCH` / `POLICY_CONTENT_MISMATCH` |
| policy `Deny` | `POLICY_DENIED` after decision-plan/generation checks |
| catalogue `Unavailable` / `Inconsistent` / `Unknown` / `IdentifierReused` | `CATALOGUE_UNAVAILABLE` / `CATALOGUE_INCONSISTENT` / `CATALOGUE_IDENTITY_MISMATCH` / `CATALOGUE_CONTENT_MISMATCH` |
| capability `Unavailable` / `Inconsistent` / `Unknown` | `CAPABILITY_UNAVAILABLE` / `CAPABILITY_INCONSISTENT` / `CAPABILITY_NOT_FOUND` |

Lease and authorization records have no `Expired` status variant: their explicit UTC
and monotonic fields exclusively select the corresponding expiry denial. Policy and
catalogue resolved records carry both current generation and the generation used by the
plan-bound decision, making `*_GENERATION_MISMATCH` reachable and deterministic.

## Replay claimant contract

```rust
pub trait ReplayClaimantV1: Send + Sync {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1;
}

pub enum ReplayClaimOutcomeV1 {
    Claimed(ReplayClaimReceiptV1),
    AlreadyClaimed,
    BindingConflict,
    Unavailable,
    Ambiguous,
}
```

`ReplayBindingV1` uses `(instance_epoch, nonce)` as the nonce uniqueness key in the
stable plan-v1 issuer namespace. It binds:

- key ID and verified-key fingerprint as compared evidence, not as a rotating
  uniqueness namespace;
- `plan_id`, `operation_id`, `task_id`, `workload_id`, and `task_lease_digest`;
- current signer-trust generation;
- instance and fencing epochs;
- the caller-owned monotonic completion deadline for the claim call.

The binding exposes redacted narrow accessors required by an external claimant,
including the nonce uniqueness key, operation ID and `binding_digest()`. The digest is:

```text
SHA-256(
  UTF8("HELIXOS\0PLAN-ELIGIBILITY-REPLAY-BINDING\0V1\0") ||
  u64be(instance_epoch) || nonce16 ||
  u16be(len(key_id)) || UTF8(key_id) || verified_key_fingerprint32 ||
  plan_id32 ||
  u16be(len(operation_id)) || UTF8(operation_id) ||
  u16be(len(task_id)) || UTF8(task_id) ||
  u16be(len(workload_id)) || UTF8(workload_id) ||
  task_lease_digest32 || u64be(trust_generation) ||
  u64be(fencing_epoch) || u64be(claim_deadline_monotonic_ms)
)
```

All strings have already passed the 128-byte bound, so the two-byte lengths are
unambiguous. Integers are unsigned big-endian. No serialization framework or native
value participates.

`ReplayClaimReceiptV1` has a checked public constructor accepting an opaque fixed
SHA-256 claim ID, claimant generation and exact binding digest, plus redacted getters.
This lets an external trusted claimant implement the trait without exposing marker
construction. After `Claimed`, the evaluator MUST compare the receipt digest to
`binding.binding_digest()` and return `REPLAY_RECEIPT_BINDING_MISMATCH` on mismatch.

A conforming production claimant MUST:

- be linearizable and durably compare/insert both replay-key and operation indexes in
  one transaction;
- return `Claimed` to exactly one new exact binding;
- return `AlreadyClaimed` for an identical prior binding, never the old receipt as a
  second success;
- return `BindingConflict` if either uniqueness index belongs to another binding;
- never fall back to process-local memory, check-then-insert, or a caller-provided
  `unused` observation;
- make a successful claim permanent, with no release or reuse path;
- return `Ambiguous` when the caller cannot know whether commit occurred, and preserve
  enough durable state for later reconciliation;
- never panic and never expose storage/provider error text through the outcome.

The claimant implementation is caller-owned and MUST have bounded completion no later
than the binding's monotonic claim deadline. A timeout after a possibly committed write
maps to `Ambiguous`; a definite pre-write outage maps to `Unavailable`. The synchronous
trait itself cannot pre-empt a broken implementation, so production integration remains
blocked until the sovereign coordinator enforces that deadline and integrates the claim
with durable operation/reconciliation state. The local 1 ms benchmark measures only the
deterministic in-memory model and is not a production-store latency claim.

`Unavailable` and `Ambiguous` fail closed. The evaluator MUST NOT retry the trait call.
An ambiguous outcome is treated as possibly committed and requires reconciliation or a
new plan. The deterministic in-memory claimant used by tests proves the linearization
and contention contract only; it is not a production durability implementation.

## Eligible binding and later comparison

The successful marker binds the authentic plan, replay receipt, evaluated UTC and
monotonic values, effective UTC/monotonic bounds, and every generation/digest named in
`../data-model.md`. A future durable coordinator MUST atomically compare all mutable
generations and deadlines again before entering `PREPARING`. Any change discards the
marker and repeats eligibility. A replay claim is never released merely because that
later comparison fails.

Production replay storage, budget/counter reservation, operation state, recovery
material, `PREPARING`, `DISPATCHING`, `ExecutionGrant`, adapter inbox/receipt, target
re-probe and host effects are out of scope and remain mandatory before dispatch.

## Diagnostics and conformance

- `EligibilityDenialV1::Display` is one generic redacted sentence; `Error::source()` is
  always `None`.
- Denial/failure/marker/claims/replay `Debug` output contains no plan, operation, task,
  workload, key or lease identifier; nonce; digest; resource component; signature;
  protected content; expected/actual value; or raw provider error.
- Public conformance summaries contain only public case ID, positive/negative outcome,
  stable code, and whether the claimant was reached.
- Every read-only negative fixture asserts zero claimant calls. Exact issuance, expiry,
  monotonic and freshness boundaries are fixtures.
- In at least 1,000 barrier-synchronised rounds, exactly one contender receives
  `Claimed`; all others deny.
- At least 100,000 generated contexts produce no panic, overflow or false acceptance.

The unchanged corpus is `contracts/fixtures/plan-eligibility-v1/` and runs on Windows,
Linux and macOS arm64. Platform-specific fixture selection or expectation rewriting is
forbidden.

The byte-identity artifact is UTF-8 RFC 8785 JCS with no BOM or trailing newline:

```json
{"cases":[{"case_id":"public-ascii-token","claimant_reached":false,"code":"PLAN_EXPIRED","outcome":"denied"}],"schema":"helixos.plan-eligibility-summary/1"}
```

Cases are sorted uniquely by `case_id`; `outcome` is `eligible`, `denied`, or
`context_build_denied`; eligible rows use `code: "NONE"`. All four values are closed,
public fields. CI compares the exact bytes and SHA-256 digest of
`expected-outcomes.json` on every platform.

## Portability, compatibility and removal

The production crate depends only on the Rust standard library and the workspace path
crate `helix-contracts`. It contains no native clocks, paths, handles, filesystem,
network, async runtime, random hash iteration, `usize` contract value, floating point,
or `cfg(target_os)` semantic branch. Time is supplied as bounded integer UTC and
same-boot suspend-aware monotonic milliseconds.

Feature 002 changes no v1 protected field, schema, canonical byte, plan ID, signature
domain, signature input, or golden feature-001 fixture. The verification-key
fingerprint and eligibility claims view are non-wire additions only.

Removal deletes `helix-plan-eligibility`, its workspace entry, fixtures, CI/spec
artefacts and unused non-wire claims/fingerprint accessors. No database or serialized
eligible authority is migrated, and feature-001 wire/signature behavior plus the legacy
runtime remain unchanged.
