# ADR 0006: Current plan eligibility before durable preparation

- **Status:** Accepted for feature `002-plan-eligibility`; durable coordinator rollout pending
- **Date:** 2026-07-10
- **Owners:** HelixOS core, contract, and coordinator maintainers
- **Acceptance contract:** `PLAN-002`

## Context

Feature 001 establishes that a `PlanEnvelope` is canonical, content-addressed, signed,
and cryptographically authentic. Authenticity is necessary but is not current
authority. Between signature verification and preparation, the signer can be rotated or
revoked, a workload identity or lease can expire, policy or catalogue content can
change, capabilities can become stale, the supervisor can pause, the host can reboot,
and the same nonce can be presented concurrently.

Treating an authentic plan as executable would collapse provenance, current admission,
durable preparation, and adapter authority into one type. It would also let a racy
`nonce unused` observation or a process-local cache stand in for a one-shot claim. The
architecture instead requires a separate, fail-closed transition before `PREPARING`.

## Decision

Feature `002-plan-eligibility` introduces a removable, platform-neutral in-process
boundary:

```text
AuthenticPlanEnvelopeV1
  + EligibilityContextV1 captured by the sovereign core
  + ReplayClaimantV1
    -> EligiblePlanV1 | EligibilityFailureV1
```

The following rules are normative.

### 1. Authenticity and eligibility remain distinct

`evaluate_and_claim_plan_v1` accepts only `AuthenticPlanEnvelopeV1`, never raw JSON or a
merely signed envelope. Feature 001 adds a borrowed, non-wire
`PlanEligibilityClaimsV1<'_>` projection so the evaluator can inspect protected
bindings without reconstructing them through serialization.

An authentic marker proves canonical cryptographic provenance only. An eligible marker
proves only that all declared current checks and one new replay claim succeeded at a
particular UTC and boot-monotonic observation. Neither is approval, durable preparation
authority, an `ExecutionGrant`, or an adapter input.

### 2. Key identifiers are immutable and exact verified key bytes remain bound

Key identifiers are immutable in the plan-v1 trust domain. Rotation creates a new key
identifier and retains historical public keys for the required verification period.
Reusing an identifier for different public-key bytes is a trust-registry inconsistency
and denies.

After strict Ed25519 verification, `AuthenticPlanEnvelopeV1` retains a non-wire
`SHA-256` fingerprint of the exact 32 public-key bytes that verified the signature.
Eligibility compares the signed key identifier, retained verification fingerprint,
current trust-entry fingerprint, trust status, trust generation, and minimum accepted
issuance time. This detects a held marker whose trust entry changed without modifying
the feature-001 protected bytes, `plan_id`, signature message, or fixtures.

### 3. Current facts are explicit and core-controlled

The sovereign coordinator captures one fixed `EligibilityContextV1`. It contains closed
views for context health, wall and monotonic time, the plan deadline, supervisor,
signer trust, authenticated workload identity, lease and scope/budget decision,
authorization, policy, catalogue, and capabilities. Mutable views carry their exact
generations and immutable content digests.

The evaluator performs no clock read, environment lookup, filesystem or network I/O,
provider callback, global-state lookup, or OS-specific operation. Agent-supplied fields
cannot construct trusted current facts. Context constructors validate bounded shape;
the sovereign integration controls their use and must not expose them through an
agent-facing RPC boundary.

### 4. Time uses UTC and a same-boot suspend-aware monotonic deadline

Wall validity is the half-open interval:

```text
issued_at_unix_ms <= now_utc_unix_ms < expires_at_unix_ms
```

Every monotonic validity is also half-open:

```text
now_monotonic_ms < deadline_monotonic_ms
```

The trusted plan store supplies a monotonic deadline record keyed by the exact
`plan_id` and `boot_id`; feature 001's signed wire remains unchanged. Workload, lease,
and authorization views carry their own UTC and same-boot monotonic bounds. Eligibility
keeps the earliest applicable bounds. A reboot, rollback suspicion, missing or
regressing clock, unsuitable suspend behavior, or reached deadline denies. UTC
remaining time is never re-based into a new boot's ticks.

### 5. Replay has a stable namespace independent of key rotation

The nonce uniqueness key is `(instance_epoch, nonce)` inside the stable plan-v1 issuer
namespace. `key_id` is deliberately not part of that namespace: rotating a key must not
make a previously consumed nonce available again.

The exact replay binding additionally contains the key ID and verified-key fingerprint,
`plan_id`, `operation_id`, `task_id`, `workload_id`, `task_lease_digest`, signer-trust
generation, fencing epoch, and caller-owned monotonic completion deadline. The replay
authority atomically maintains both the nonce-namespace index and the operation index.
An existing uniqueness key or operation attached to different evidence is a binding
conflict, not a new claim.

### 6. The atomic claim is exactly once and last

All context, time, boot, epoch, signer, workload, lease, authorization, policy,
catalogue, and capability checks are read-only and follow the frozen first-failure
order. Only after every gate passes may the evaluator call
`ReplayClaimantV1::claim_once`, exactly once and as its final external operation.

There is no public positive `assess`, `nonce_unused`, reserve, release, reset, or retry
API. A pre-observed unused flag is racy. A pre-reserved claim would let an invalid plan
consume replay state or would require an unsafe release path. Failed pre-claim checks
leave replay untouched. A successful claim is permanent. `Unavailable` and `Ambiguous`
deny without retry; ambiguity is treated as possibly committed and requires a new plan
or reconciliation.

### 7. The claimant receipt is cryptographically tied to the request

`ReplayBindingV1::binding_digest()` is SHA-256 over the domain-separated, length-delimited
portable binding defined by the feature contract:

```text
HELIXOS\0PLAN-ELIGIBILITY-REPLAY-BINDING\0V1\0
```

followed by the instance epoch, nonce, key ID, verification fingerprint, plan ID,
operation ID, task ID, workload ID, lease digest, trust generation, fencing epoch, and
claim deadline in the contract's fixed big-endian encoding.

`ReplayClaimReceiptV1` carries an opaque SHA-256 claim ID, claimant generation, and the
exact binding digest. The evaluator recomputes and compares the digest before creating
the positive marker. A mismatched receipt denies with
`REPLAY_RECEIPT_BINDING_MISMATCH`; it is never accepted merely because the claimant
returned `Claimed`.

### 8. The eligible marker is opaque and carries no effect authority

`EligiblePlanV1` owns the authentic plan, effective UTC and monotonic bounds, every
generation/digest used in the decision, and the checked replay receipt. It has private
fields, no public constructor, no `Clone`, `Copy`, Serde implementation, or wire
encoding, and a redacted `Debug`.

The marker is a point-in-time prerequisite. Before `PREPARING`, a future durable
coordinator must atomically compare the carried generations and deadlines or repeat
eligibility. A failed later comparison never releases the replay claim. No adapter may
depend on the eligibility crate or accept this marker.

### 9. Durable execution authority remains deferred

The feature defines the production claimant obligations but ships only a deterministic
thread-safe claimant for tests and examples. That model proves call order,
linearizability, conflicts, and contention; it does not prove crash/restart durability.

Production replay storage, atomic compare-before-prepare, budget/counter reservation,
durable operation state, recovery material, `PREPARING`, `DISPATCHING`, a signed
one-shot `ExecutionGrant`, adapter inbox/receipt, target re-probe, effects, and
reconciliation are later mandatory features. Their absence blocks Tier 1 and all host
effects.

### 10. Portability is semantic, not inferred from the OS name

The common crate uses bounded identifiers, fixed digests/nonces, sorted unique slices,
safe integer UTC milliseconds, and boot-scoped monotonic milliseconds. It contains no
native path, handle, clock object, floating point, ambient state, filesystem/network
client, or `cfg(target_os)` semantic branch.

macOS arm64 on the Mac mini M4 is the primary deployment target, but the same corpus and
outcome bytes must run unchanged on macOS arm64, Linux, and Windows. Capabilities come
from an observed report and are never inferred from `os` or `arch`.

## Consequences

### Positive

- Provenance, current eligibility, durable preparation, and adapter authority have
  separate types and trust transitions.
- Key rotation cannot reopen a nonce or substitute different key bytes behind a familiar
  identifier.
- Read-only denials are reproducible and cannot consume replay state.
- The exact receipt binding catches a buggy or confused claimant before marker creation.
- A portable, redacted corpus can prove identical first-failure behavior on all target
  platforms.
- The new crate remains a leaf and can be removed before coordinator adoption.

### Costs and limitations

- The sovereign core must capture coherent trusted facts and retain plan-bound monotonic
  deadline records.
- Strict first-failure ordering prevents parallelizing independent checks.
- Eligibility can become stale immediately; the future coordinator must compare its
  carried bindings before preparation.
- The synchronous claimant contract cannot pre-empt a broken implementation. Production
  integration must enforce the monotonic claim deadline outside the leaf.
- The test claimant and the local p95 benchmark make no durability or production-store
  latency claim.

## Alternatives considered

- **Treat a valid signature as current authority:** rejected because revocation,
  expiry, policy, capability, epoch, and replay state remain mutable.
- **Use `(key_id, nonce)` as the replay namespace:** rejected because key rotation would
  reopen nonce space. The stable namespace uses `(instance_epoch, nonce)`.
- **Observe `nonce_unused` and insert later:** rejected because observation and insertion
  race.
- **Reserve before read-only validation:** rejected because invalid plans could burn
  replay state and a release operation would reintroduce reuse.
- **Expose a public read-only positive assessment:** rejected because callers could
  mistake it for authority or omit the final claim.
- **Serialize or clone `EligiblePlanV1`:** rejected because a transferable marker would
  invite stale or replayed use.
- **Let an adapter accept authentic or eligible plans:** rejected because adapters may
  accept only a later short signed `ExecutionGrant`.
- **Integrate the legacy runtime now:** rejected because native paths, mutable state, and
  effect code would contaminate the portable proof and broaden the feature scope.

## Evidence and rollout

`PLAN-002` requires the versioned positive and every-single-fault corpus, exact boundary
tests, claimant-last probes, key-rotation/fingerprint tests, receipt-digest mismatch
tests, at least 1,000 contention rounds, the deterministic 100,000-context soak, raw
release benchmark samples, redaction sentinels, strict lint, and byte-identical corpus
outcomes on Linux, macOS arm64, and Windows.

Local success proves only the leaf implementation and test claimant. Cross-platform
acceptance remains pending until one immutable CI commit/run/artifact set is linked from
`conformance/catalog.yaml`. Production eligibility remains non-operational until the
durable coordinator gates listed above are delivered.

## Removal and migration

Before coordinator adoption, removal deletes `kernel/helix-plan-eligibility`, its
workspace entry, feature-002 fixtures/workflow/spec artifacts, and this ADR, then removes
the unused non-wire claims/fingerprint additions from `helix-contracts`. No database or
serialized eligible authority requires migration. Feature-001 canonical bytes,
`plan_id`, signatures, fixtures, and MVP-0 runtime behavior remain unchanged.

A later coordinator may consume `EligiblePlanV1` only through a separately specified
atomic compare-before-prepare transition. It may not adapt the legacy `Plan` into
eligibility or allow an adapter to consume authenticity/eligibility directly.
