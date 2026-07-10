# Research: Current Plan Eligibility

This research resolves the Phase 0 design questions for feature 002. The canonical
constraints are `constitution.md`, `ARCHITECTURE.md`, and
`specs/002-plan-eligibility/spec.md`. Feature 001's signed wire contract, schema,
canonical bytes, signatures, and fixtures remain unchanged. All Phase 0 technical
questions are resolved below.

## Decision 1 - Trust transition and crate boundary

**Decision**: Add an independent Rust leaf crate at
`kernel/helix-plan-eligibility`. Its only accepted plan input is
`AuthenticPlanEnvelopeV1`, produced by feature 001 after strict canonical decoding,
plan-ID verification, key resolution, and signature verification. The public transition
is conceptually:

```text
AuthenticPlanEnvelopeV1
  + EligibilityContextV1 from the sovereign core
  + ReplayClaimantV1
    -> EligiblePlanV1 | EligibilityDenialV1
```

`AuthenticPlanEnvelopeV1` proves canonical cryptographic provenance only. It does not
prove that the signer, workload, lease, authorization, policy, catalogue, capability
report, time window, boot, or epochs are current. `EligiblePlanV1` proves only that the
declared current checks and the final replay claim succeeded at one point in time. It is
not approval, durable preparation, an `ExecutionGrant`, or effect authority.

Feature 001 receives one non-wire, read-only projection,
`PlanEligibilityClaimsV1<'_>`, obtainable from an authentic envelope. It exposes the
already protected fields needed by the evaluator without exposing private wire structs
or adding serialization. During `decode_and_verify_plan`, the authentic marker also
records `SHA-256(verified_ed25519_public_key)` as a non-wire verification fingerprint.
The projection exposes that fingerprint beside the signed `key_id`, so eligibility can
prove that current trust still names the exact key bytes that verified the signature.
No existing protected field, schema, canonicalization rule, fixture, or signature input
changes.

**Rationale**: A separate leaf makes the trust transition explicit and removable. It
prevents the legacy Windows-first runtime, native paths, ambient clocks, and effect code
from entering a portable admission boundary. Requiring the authentic marker at the type
boundary prevents raw JSON, an unverified signed envelope, or an agent assertion from
being treated as eligible.

**Alternatives considered**:

- Extend `decode_and_verify_plan` to return "valid now": rejected because signature
  verification and current authorization have different inputs, lifetimes, and failure
  modes.
- Put eligibility in `helixos-kernel`: rejected because that crate already contains
  legacy runtime and platform concepts and would make removal and cross-platform
  conformance harder.
- Modify the v1 signed envelope: rejected because feature 002 must not invalidate the
  feature-001 golden corpus or signature behavior.

## Decision 2 - Pure assessment followed by one atomic replay call

**Decision**: The evaluator performs a deterministic, read-only assessment over the
authentic plan projection and one immutable `EligibilityContextV1`. The intermediate
positive assessment remains crate-private and cannot be used by a caller. Only after
every read-only gate passes does the evaluator construct a `ReplayBindingV1` and
call `ReplayClaimantV1::claim_once` exactly once. Only a new successful claim constructs
`EligiblePlanV1`.

The replay uniqueness key is `(instance_epoch, nonce)` inside a stable plan-v1 issuer
namespace. The exact binding additionally contains `key_id`, the verified-key
fingerprint, `plan_id`, `operation_id`, `task_id`, `workload_id`,
`task_lease_digest`, current trust generation, and fencing epoch. Key rotation therefore
cannot reopen a nonce; a changed key or fingerprint conflicts with the existing
binding. The trait has no observe, reserve, release, reset, or retry method. Its closed
outcomes are new claim, already claimed, conflicting binding, unavailable, and
ambiguous. Already-claimed and conflicting requests never return the existing claim as
another success. Unavailable or ambiguous outcomes fail closed; an ambiguous outcome
may already have committed and therefore requires replan or reconciliation, never an
automatic second claim.

A positive claimant receipt carries a domain-separated digest of the complete binding.
The evaluator recomputes and compares it before marker construction; a mismatched
receipt denies. This catches cross-request/provider bugs without treating the receipt as
execution authority.

Two shortcuts are explicitly forbidden:

- A pre-observed `nonce_unused: bool` (or equivalent lookup result) MUST NOT appear in
  the snapshot. Observation and insertion can race, so it cannot prove one-shot use.
- A pre-reserved nonce, reservation token, or claim receipt MUST NOT appear in the
  snapshot. Reserving before the declared gates lets invalid plans burn replay state;
  making a reservation releasable reintroduces reuse; and passing a pre-made receipt
  separates it from the exact plan/operation binding checked by this transition.

All pre-claim denials leave replay state untouched. A successful claim is permanent and
has no release path.

**Rationale**: This is the smallest API that preserves the spec's validation order and
gives the concurrent success condition a linearization point. Keeping the pure positive
type private avoids creating a second, weaker authority object.

**Alternatives considered**:

- Public `assess()` followed by caller-managed replay: rejected because callers could
  mistake the assessment for authority or reorder/omit the claim.
- Check-then-insert through two claimant methods: rejected as racy.
- Claim first and validate afterward: rejected because malformed, expired, revoked, or
  mismatched plans could consume a nonce.
- Return an existing same-binding receipt as idempotent success: rejected because it
  would create more than one eligible instance from one one-shot admission claim.

## Decision 3 - Explicit trusted snapshot, not ambient providers

**Decision**: The leaf evaluator does not read clocks, files, environment variables,
network services, OS APIs, global state, or policy stores. The sovereign coordinator
captures one typed `EligibilityContextV1` from trusted providers and passes it by value.
The snapshot contains a single UTC observation, a single boot-scoped monotonic
observation, provider health, exact plan binding, and fixed subviews for supervisor,
signer trust, workload identity, lease, authorization, policy, catalogue, and
capabilities.

Snapshot and subview fields are closed Rust types with private fields and checked
constructors. They do not implement `Deserialize`; the core must not expose their
constructors over an agent-facing RPC boundary. Provider-specific errors are converted
to closed availability/consistency states before evaluation. The type name is not a
security proof by itself: trusted construction is an integration invariant enforced by
the sovereign core and its tests.

The public construction shape is a sum type: top-level unavailable, incomplete and torn
states carry no dummy provider values, while `Ready` owns one fully checked record.
Provider resolutions likewise use terminal variants plus a resolved record. Checked
shape failures use a separate payload-free `EligibilityContextBuildErrorV1` contract;
they are never confused with a runtime eligibility denial. V1 freezes 128-byte
identifiers/capability names, 128 available capabilities, 64 policy-mandatory and 64
catalogue-mandatory capabilities, and RFC 8785/I-JSON safe-range scalar generations and
milliseconds.

The snapshot binds each mutable source generation. It is not claimed to be an atomic
cross-service database snapshot. `EligiblePlanV1` carries those exact generations and
deadlines so the later durable coordinator can compare them atomically before
`PREPARING` or discard the result and repeat eligibility.

**Rationale**: Calling providers during validation would make the first-failure code
depend on timing and could combine facts from different generations. A fixed snapshot
makes decisions reproducible and lets tests prove that claimant invocation is last.

**Alternatives considered**:

- Provider traits for every eligibility fact inside the evaluator: rejected because
  interleaved I/O produces incoherent, non-reproducible decisions and complicates the
  portable leaf.
- Ambient `SystemTime`/`Instant`: rejected because tests cannot reproduce them and
  native monotonic values cannot cross a boot or process boundary safely.
- Treat snapshot construction as complete authorization: rejected because generations
  can change after capture and must still be compared before durable preparation.

## Decision 4 - Opaque ownership and explicit non-authority

**Decision**: `evaluate_and_claim` consumes the authentic envelope by value and a
successful `EligiblePlanV1` owns it. The eligible marker has private fields, no public
constructor, no `Clone`/`Copy`, no Serde implementation, no canonical/wire encoding, no
conversion to approval or `ExecutionGrant`, and a fully redacted `Debug`. It is marked
`#[must_use]` and exposes only narrow read access needed by the future sovereign
coordinator.

The marker binds the authentic plan, effective UTC and monotonic deadlines, all current
generations/digests used by the decision, and the new replay claim identifier. Consuming
the authentic value is an ownership cue, not the one-shot security mechanism: feature
001's marker is cloneable, so the atomic claimant remains authoritative for uniqueness.

Adapters will never depend on this crate and must continue to accept only a future short
signed `ExecutionGrant`. Holding an eligible marker cannot enter `PREPARING` without a
generation comparison and cannot enter `DISPATCHING` without the later durable
coordinator, recovery preparation, budget transaction, outbox, and execution grant.

**Rationale**: Rust ownership prevents common accidental reuse while the private,
non-serializable marker communicates that eligibility is local and ephemeral. The lack
of adapter integration preserves the architecture's authority gradient.

**Alternatives considered**:

- A serializable eligibility receipt: rejected because it could be replayed or mistaken
  for transferable authority.
- A cloneable/copyable boolean or enum success: rejected because it loses the exact
  bindings and encourages use after state changes.
- Make the marker an `ExecutionGrant`: rejected because preparation, recovery,
  durability, fencing at dispatch, and adapter receipts are outside this feature.

## Decision 5 - Fixed fail-closed validation order

**Decision**: The evaluator returns the first failure in the following total order. It
does not reorder checks for convenience or performance:

1. Snapshot version, completeness, provider health, exact `plan_id` binding, and
   supervisor admission state (`OPEN` only).
2. Clock health and rollback status; wall interval; boot binding; suspend-aware
   monotonic health and deadline; exact instance epoch; exact fencing epoch.
3. Signer key/trust; workload identity; unique active lease plus source/scope/budget
   decision; current plan-bound authorization.
4. Policy identity, immutable content resolution, generation, and decision; then
   catalogue identity, immutable content resolution, generation, schema, and intent.
5. Capability report identity/context, observation time, freshness, and required plus
   currently mandatory capability membership.
6. Final atomic replay claim.

Within each step, fields are checked in documented contract order. Missing, unknown,
multiple, revoked, exhausted, inconsistent, or unavailable evidence maps to a closed
denial. Stale and ahead epochs both deny; an ahead value never advances supervisor or
local state. No read-only denial can invoke the claimant.

**Rationale**: A total order makes fixtures and incident diagnostics deterministic and
prevents an attacker from probing later state through variable evaluation paths. It also
gives SC-001 a precise "claim not reached" assertion.

**Alternatives considered**:

- Parallel or cheapest-first validation: rejected because the selected error would
  become timing-dependent.
- Aggregate all failures: rejected because it leaks more current-state information and
  increases diagnostic exposure.
- Trust a plan's ahead epoch and update local state: rejected because untrusted signed
  claims do not own current authority.

## Decision 6 - UTC plus boot-scoped suspend-aware monotonic time

**Decision**: Common time values are bounded integer milliseconds represented by
purpose-specific newtypes, not `SystemTime`, `Instant`, floating-point seconds, or native
clock handles. Wall validity is exactly `issued_at <= now_utc < expires_at`; issuance is
valid and expiry is not. Checked arithmetic is mandatory.

Feature 001's wire contains UTC issuance/expiry and `boot_id`, but no monotonic deadline.
To preserve its canonical bytes, the trusted plan store supplies a
`PlanDeadlineRecordV1` keyed by `plan_id` and `boot_id`, created alongside plan issuance.
It contains the plan's suspend-aware monotonic deadline and record generation. Lease,
workload identity, and authorization views likewise provide UTC and monotonic deadlines
bound to the same boot. The evaluator uses the minimum applicable UTC deadline and the
minimum applicable monotonic deadline as the effective bounds carried by the eligible
marker.

The time view must declare the wall-clock high-water/rollback check healthy and the
monotonic sample healthy, non-regressing, suspend-aware, and from the plan's current
boot. A reboot, missing sample, reached monotonic deadline, rollback suspicion, or
provider ambiguity denies. No UTC-to-tick conversion occurs after reboot, and no stale
deadline is re-based onto a new boot.

Capability freshness is calculated only after feature 001 has proved
`observed_at <= issued_at`, eligibility has proved `issued_at <= now`, and the current
observation equals the protected value. A future protected observation is therefore
unreachable; a context-only future value is an observation mismatch. The evaluator
still uses checked subtraction and accepts `age <= max_age`; exactly the maximum is
valid and one millisecond older is denied. Platform-specific providers on macOS,
Linux, and Windows are responsible for producing and sleep/wake-testing the same scalar
suspend-aware semantics; those OS APIs never enter this crate.

**Rationale**: UTC binds signed civil time and audit, while monotonic time resists wall
clock changes and correctly scopes a deadline to one boot. A trusted plan-deadline
record supplies the missing v1 monotonic fact without changing the signed contract.

**Alternatives considered**:

- UTC only: rejected because rollback or manual clock changes can extend authority.
- Monotonic only: rejected because ticks are boot-local and cannot represent the signed
  validity interval or audit time.
- Add a monotonic tick to the signed v1 envelope: rejected because ticks are local and
  doing so would break the feature-001 wire corpus.
- Recompute remaining time from UTC after reboot: rejected because it silently revives
  authority in a different clock domain.

## Decision 7 - Immutable identities, content digests, and generations

**Decision**: A version-like identifier is never accepted as sufficient evidence that
mutable content stayed the same. Eligibility uses and carries these bindings:

- Supervisor: admission state, `boot_id`, `instance_epoch`, `fencing_epoch`, and
  supervisor generation.
- Signer: exact signed `key_id`, the authentic marker's non-wire SHA-256 fingerprint of
  the Ed25519 public key that actually verified the signature, the current trust entry's
  matching key fingerprint, trusted status, active trust generation, and the
  generation's minimum accepted issuance time. Key identifiers are immutable and never
  reassigned; rotation issues a new identifier and retains historical verification
  entries. Revocation or later re-enrolment cannot silently substitute key bytes or
  revive a plan from an older trust generation.
- Workload: exact workload identity, identity/registry generation, trusted status, and
  UTC plus boot-monotonic validity.
- Lease: exact signed lease digest, unique active record, lease-store generation,
  task/workload/source bindings, UTC plus monotonic validity, revocation/exhaustion
  status, and a plan-bound scope/budget decision digest.
- Authorization: evidence digest and generation bound to plan, operation, risk, nonce,
  and effective deadlines, with current validity/revocation state.
- Policy: signed policy version identifier, immutable registry resolution to a content
  digest, active content digest, policy generation, and affirmative plan-bound decision
  digest.
- Catalogue: signed catalogue version identifier, immutable registry resolution to a
  content digest, active content digest, catalogue generation, and explicit support for
  the schema and intent.
- Capabilities: report digest, exact observation time, report generation, boot and
  instance, opaque host/driver-context digest, available set, mandatory set, and the
  current policy freshness bound.
- Time/deadline records: clock-health generation, plan-deadline generation, effective
  UTC deadline, and effective boot-monotonic deadline.
- Replay: the claimant's new opaque claim identifier, claimant generation, and the
  domain-separated digest of the complete claim binding.

Feature 001 signs policy/catalogue version identifiers rather than content digests. For
v1, the trusted registry therefore enforces an immutable one-to-one mapping from each
signed identifier to a content digest. Eligibility requires both the immutable resolved
digest and active digest to match. Reusing an identifier for different bytes is a
provider inconsistency and denies. A future plan schema may sign both directly, but v1
is not changed here.

All capability identifiers and other collections are bounded, sorted, and unique.
Membership uses deterministic linear/two-pointer comparison rather than randomized hash
iteration or arbitrary maps.

**Rationale**: Generations detect revocation and replacement between evaluation and
preparation; content digests prevent semantic replacement under a familiar name. The
eligible marker retains enough exact evidence for a later atomic compare.

**Alternatives considered**:

- Compare policy/catalogue names only: rejected because an identifier could be reused
  with different semantics.
- Trust agent-provided digests or decisions: rejected because the agent is compromised
  by assumption.
- Copy complete policy, lease, or capability documents into the marker: rejected
  because it expands sensitive retention and makes diagnostics harder to redact.
- Compare only `key_id`: rejected because rotation or registry corruption could reuse a
  familiar identifier for different public-key bytes. The verification fingerprint and
  current trust fingerprint must match even though neither changes the signed wire.

## Decision 8 - Capability coherence and freshness

**Decision**: The current capability view must resolve the exact plan-bound report
digest and exact signed observation timestamp. It must also match current boot,
instance, and opaque host/driver context. A changed report digest requires replan even
if the new report appears to be a superset.

The report's available set must contain both the plan's sorted required capabilities
and the current policy/catalogue mandatory capabilities for the declared intent. A
missing mandatory value denies. Feature 001 prevents a future protected observation;
a different future context observation denies as a mismatch before age calculation.
An age equal to policy `max_age_ms` is accepted and `max_age_ms + 1` is denied. Missing
or unavailable context denies rather than inferring a capability from `os` or `arch`.

The adapter's immediate pre-effect capability and target re-probe remains outside this
feature. Passing eligibility does not promise that a capability will still exist at
dispatch.

**Rationale**: A digest alone does not prove that a report belongs to the current host
context or remains fresh. Requiring both planned and newly mandatory capabilities lets
current policy tighten safely without treating human approval as a fallback.

**Alternatives considered**:

- Infer capabilities from the operating-system name: rejected by the portability
  constitution.
- Accept any current superset with a different digest: rejected because recovery and
  effect semantics may have changed even when named capabilities increased.
- Let the eligibility check replace the adapter re-probe: rejected because target and
  native conditions can change immediately before effect.

## Decision 9 - Closed, redacted denial contract

**Decision**: `EligibilityDenialV1` is a closed payload-free enum with one stable
SCREAMING_SNAKE_CASE `code()` per declared gate. `Display` is a generic redacted
sentence; `Debug` prints only the type and variant; `Error::source()` exposes nothing.
It never includes expected/actual values, plan or operation IDs, key/workload/task/lease
identifiers, nonce, path/resource components, signatures, plan content, or raw provider
errors.

Replay failures map to distinct closed denials for already claimed, conflicting
binding, unavailable authority, and ambiguous outcome. Provider absence and provider
inconsistency remain distinguishable stable codes where operational action differs, but
neither carries the provider's message. The portable conformance summary contains only
a public fixture case ID, outcome kind, stable code, and whether the claimant probe was
reached; it does not print runtime bindings. `EligiblePlanV1::Debug` is equally
redacted.

**Rationale**: Stable codes support unchanged cross-platform fixtures and operational
routing without turning diagnostics into an oracle for current authority or sensitive
plan data.

**Alternatives considered**:

- Errors with expected and actual identifiers/generations: rejected because they leak
  trusted state.
- Wrap arbitrary provider errors as sources: rejected because their display/debug
  implementations may contain secrets, paths, nonces, or platform details.
- One undifferentiated denial: rejected because replay ambiguity, dependency outage,
  and ordinary mismatch require different sovereign remediation.

## Decision 10 - Concurrency contract and proof boundary

**Decision**: `ReplayClaimantV1` is a synchronous `Send + Sync` trait whose single
`claim_once(&self, request)` operation is required to be linearizable. A production
implementation must durably compare and insert the nonce and operation indexes in one
transaction and must never fall back to process-local memory. This feature defines the
contract but does not ship that production store.

The conformance implementation is a deterministic test-only claimant shared through
`Arc`, with one mutex protecting both `(instance_epoch, nonce)` and operation bindings.
Key identity and fingerprint remain part of the compared binding, not the uniqueness
namespace. Each of
at least 1,000 rounds creates a fresh claimant, starts a fixed number of contenders
behind a barrier, and asserts exactly one new claim and no second eligible result. It
also proves:

- sequential replay denies;
- same nonce with another plan/operation denies as a conflict;
- same operation with another plan/nonce denies as a conflict;
- every single pre-claim fault records zero claimant calls and a later coherent attempt
  can still claim;
- unavailable and ambiguous outcomes are not retried; and
- no API can release or reuse a successful claim.

The claim is "exactly one successful eligibility claim in one replay-authority domain",
not universal exactly-once host effects. Dispatch and effect ambiguity remain governed
by later inbox/receipt/reconciliation features.

**Rationale**: A mutex-backed model gives a clear linearization point for portable
threaded tests, while the trait documents the stronger durable semantics required from
the future coordinator. It avoids making an unproved durability claim about a test
double.

**Alternatives considered**:

- Atomics for the nonce alone: rejected because all plan/operation/task/lease bindings
  must commit consistently, not just a boolean bit.
- Process-local claimant in production: rejected because restart or multiple core
  processes would permit replay.
- Async trait and runtime dependency: rejected for this leaf; there is one bounded
  call, and the future coordinator can schedule its durable implementation without
  imposing an executor on the contract crate.

## Decision 11 - Portability, dependencies, testing, and performance

**Decision**: The new crate uses Rust edition 2021 on exact toolchain `1.96.1` pinned by
`kernel/rust-toolchain.toml`, `#![forbid(unsafe_code)]`, and only
the Rust standard library plus the path dependency on `helix-contracts` at runtime. It
does not depend on Serde, a crypto library, an async runtime, a database, or OS bindings.
The payload-free error enum implements `Display`/`Error` directly, so `thiserror` is not
needed. Test-only `proptest = 1.11.0`, `serde = 1.0.228`, `serde_json = 1.0.150`,
`serde_json_canonicalizer = 0.3.2`, and `ed25519-dalek = 2.2.0` may be exact-pinned
consistently with feature 001 for generated contexts, public fixture parsing, canonical
summary output and deterministic signing; barriers, threads, timing, and the claimant
model use `std`.

The public model contains no native path, handle, clock object, `usize` contract value,
floating point, `cfg(target_os)`, environment lookup, filesystem access, network call,
or OS-dependent branch. Bounded sorted vectors make pure checks deterministic and
linear. Apart from constructing the final owned marker and claimant receipt, the hot
read-only path should avoid allocation; replay latency is measured separately because
it dominates a future durable implementation.

Evidence consists of:

- table-driven positive and one-fault negative cases for every gate and exact boundary;
- at least 1,000 barrier-synchronized contention rounds;
- at least 100,000 generated contexts with an independent acceptance oracle, checked
  arithmetic, no panic, and no false acceptance;
- a release benchmark of at least 10,000 complete evaluations with the deterministic
  local claimant, p50/p95/p99 and raw samples, with p95 at or below 1 ms; and
- one unchanged corpus and decision-summary format on Windows, Linux, and macOS arm64.

Each performance artifact records hardware, OS/architecture, Rust version, build
profile, corpus version, contender count where applicable, sample count, and raw
durations. Local Windows evidence is developmental. The unchanged macOS-arm64 CI corpus
and another driver are required for feature portability; a real Mac mini M4 result is a
separate reference-performance gate before claiming the user's target hardware profile,
not a substitute for portability or whole-system Tier 1 evidence.

**Rationale**: A standard-library leaf minimizes supply-chain and platform variance,
while the exact path dependency reuses the already reviewed authentic marker and
portable scalar/digest types. The evidence directly matches SC-001 through SC-006.

**Alternatives considered**:

- Tokio/async-trait/database dependencies: rejected because production storage is out
  of scope and those dependencies would not strengthen the pure contract.
- Criterion or a large benchmark framework: rejected for this slice; a small
  project-owned runner can preserve raw samples and required metadata.
- Per-OS fixture code: rejected because it would test different semantics rather than
  portability.

## Decision 12 - Deferred authority and removal path

**Decision**: Feature 002 stops at the opaque point-in-time marker and replay-claim
contract. Production durable replay storage, atomic generation/budget comparison,
operation state, recovery material, `PREPARING`, `DISPATCHING`, `ExecutionGrant`,
adapter inbox/receipt, target re-probe, and host effects are deferred. Until those
features exist and pass their own gates, this marker cannot authorize Tier 1 or any host
effect.

Removal requires only:

1. remove `helix-plan-eligibility` from `kernel/Cargo.toml`;
2. delete `kernel/helix-plan-eligibility/` and its feature-002 conformance artifacts;
3. remove the non-wire eligibility projection/accessor from `helix-contracts`; and
4. remove future call sites, if any.

There is no database migration or persisted eligible authority to convert. The
feature-001 schema, fixtures, canonical bytes, signature behavior, and current MVP-0
runtime remain unchanged before, during, and after removal.

**Rationale**: The removal path proves the feature is a bounded trust layer rather than
a hidden runtime migration. Explicit deferrals prevent an eligibility success from
being presented as durable execution safety.

**Alternatives considered**:

- Integrate the legacy runtime in the same feature: rejected because it would broaden
  scope into effects and contaminate the portable proof.
- Persist or serialize eligible markers for later use: rejected because stale
  generations and deadlines must be re-evaluated, not restored as authority.
- Ship a process-local production claimant temporarily: rejected because it would
  appear functional while violating replay durability and restart safety.
