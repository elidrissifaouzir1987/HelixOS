# Contract: Preparation Authority Comparison v1

**Contract ID**: `helixos.preparation-authority-compare/1`
**Status**: design contract; implementation pending

## 1. Purpose

This contract defines how a point-in-time `EligiblePlanV1` is compared again before
`PREPARING`. It does not issue approval, replay admission, a budget reservation, a
prepared marker or adapter authority.

## 2. Snapshot and guard separation

`ReadyPreparationContextV1` is an OS-neutral value snapshot. It contains explicit
generations, digests, epochs and time samples only.

`AuthorityGuardV1` is opaque in-process custody held by the trusted coordinator. It may
wrap provider-native synchronization internally but exposes no handle, callback, path
or serialization. A snapshot without its required live guard cannot satisfy the final
comparison.

`FinalCommitGateV1` borrows the complete live guard set. After SQLite has staged every
write, the store calls `enter_commit_permit`. A successful call returns an opaque,
non-Serde `FinalCommitPermitV1` held across the actual `COMMIT`. The permit keeps every
external authority guard stable and total-orders supervisor PAUSE/HALT activation with
that commit. A store API that receives only copied context values is non-conforming.

Provider wiring is sovereign configuration. The agent cannot select providers, create
guards or supply a context field.

## 3. Two-capture rule

1. The preliminary capture occurs before recovery work and is used only to reject an
   already stale/incomplete request.
2. Preliminary success includes exact replay verification followed by read-only
   operation/budget preflight; recovery publication may proceed only afterward.
3. The final capture occurs after all required external guards are acquired.
4. No preliminary record, boolean or digest may substitute for final capture.
5. Any provider unable to supply a complete final snapshot plus transaction/guard
   semantics returns a closed unavailable/unsupported result.

## 4. Global acquisition order

Every path, including cleanup and backup, uses the same order:

| Order | Guard/domain | Required behavior |
|---:|---|---|
| 1 | recovery publication/cleanup | mutually exclusive for one operation/material identity |
| 2 | clock/deadline, if external | healthy source/generation; no time freeze claim |
| 3 | supervisor/admission/epochs | PAUSE/HALT revocable; exact boot/instance/fencing binding |
| 4 | signer trust | protects expected trust generation/fingerprint |
| 5 | workload identity | protects expected workload generation/evidence |
| 6 | task lease | protects lease generation/digests and non-revocation |
| 7 | authorization | protects decision generation/evidence |
| 8 | policy | protects content/decision generations/digests |
| 9 | catalogue | protects content/decision generations/digests |
| 10 | capabilities | protects report generation/digest and driver context |
| 11 | coordinator SQLite writer | acquired with `BEGIN IMMEDIATE` after all external guards |

Coordinator-resident facts are compared inside the SQLite transaction at their logical
position and do not add an external lock. Guards release in reverse order.

A call that cannot acquire the next guard before the absolute monotonic deadline releases
all prior guards and denies. It does not skip, reorder or retain them for retry.

## 5. Linearizable commit permit and PAUSE/HALT

The supervisor provider owns a deadline-bounded per-attempt gate with this closed state
machine:

```text
OPEN -> REVOKED
OPEN -> COMMIT_PERMITTED -> COMMIT_IN_FLIGHT -> RESOLVED_COMMITTED
                                              -> RESOLVED_ABORTED
                                              -> RESOLVED_AMBIGUOUS
COMMIT_PERMITTED --owner loss/deadline--> RESOLVED_AMBIGUOUS
COMMIT_IN_FLIGHT --owner loss/deadline--> RESOLVED_AMBIGUOUS
```

`enter_commit_permit` is the sole linearizable transition out of `OPEN`. It atomically
compares the captured admission/revocation generation and every live guard:

- if a PAUSE/HALT request won first, the gate becomes `REVOKED`, SQLite rolls back and
  no operation/reservation/event commits;
- if the permit won first, the coordinator holds it across exactly one SQLite commit;
  later PAUSE/HALT is durably accepted immediately for the control lane and blocks every
  new permit, but activation for this already-permitted attempt is ordered after permit
  resolution;
- acknowledged commit resolves `RESOLVED_COMMITTED`; confirmed rollback resolves
  `RESOLVED_ABORTED` immediately and never enters readback; only an explicit
  `UNCERTAIN` store result remains `COMMIT_IN_FLIGHT` for one fresh exact readback.
  Missing classification, owner/process loss or permit-deadline equality resolves
  `RESOLVED_AMBIGUOUS`, activates PAUSE and returns no marker.

The permit stores a supervisor-owned opaque owner token and an absolute monotonic lease
deadline computed with checked arithmetic as
`min(caller_deadline, permit_entry_monotonic + 250 ms)`. Equality is expired. Its
one-shot `commit_once` method atomically verifies that the permit is still active and
moves to `COMMIT_IN_FLIGHT` before invoking SQLite commit. A resumed worker cannot
commit from an expired/resolved permit.

The independent supervisor, not Rust `Drop` or the preparation process, owns the
deadman. Owner loss, process kill or permit-deadline expiry atomically resolves either
permit state to `RESOLVED_AMBIGUOUS`, activates PAUSE, blocks all new permits and
requires exact coordinator readback. A storage flush already started while the permit
was valid may still become durable; it remains the earlier permitted but ambiguous
attempt and can never yield a marker without reconciliation.

If `commit_once` returns uncertain while the owner is healthy, the permit may remain
`COMMIT_IN_FLIGHT` only for a fresh, non-mutating exact-readback attempt within the same
lease deadline. Exact timely proof resolves committed/aborted; otherwise the owner or
deadman resolves ambiguous. No transaction retry occurs in this window.

The permit transition is not the `PREPARING` linearization point and creates no
operation. SQLite commit remains the sole operation-state linearization point. The
permit only establishes whether PAUSE/HALT activation is ordered before or after that
commit. Control persistence never waits for the normal worker pool; only the already
entered, tightly bounded commit permit may resolve before its activation applies to the
attempt.

Every other external source remains protected by its live guard until permit resolution.
If any provider cannot implement these total-order semantics, final preparation denies;
a last-token-read followed by an unguarded commit is forbidden.

## 6. Exact final comparison vector

The comparison is field-by-field in this order:

1. context version/health/completeness;
2. `capture_generation`;
3. `clock_generation`, UTC expiry and monotonic deadline;
4. `plan_deadline_generation` and capability freshness arithmetic;
5. admission state, `supervisor_generation`, boot ID, instance/fencing epochs;
6. trust generation and verified key fingerprint;
7. workload generation and evidence digest;
8. lease generation, lease digest and lease-decision digest;
9. authorization generation/evidence digest;
10. policy generation, decision generation, content and decision digests;
11. catalogue generation, decision generation, content and decision digests;
12. capability report generation/digest and host-driver context digest;
13. exact replay claim ID, claimant generation and binding digest;
14. operation/plan/task/workload identity;
15. budget scope binding/generation/currency/price table;
16. recovery provider profile/evidence class/generation/capability binding.

The expected first 13 groups come from `EligiblePlanV1` and authenticated plan claims;
later groups bind the new preparation authority. A summary digest may be stored only
after every field has compared exactly.

### 6.1 Normative leaf fault-to-code mapping

This table is the authoritative v1 evaluation order. Rows are evaluated from top to
bottom, and every comma-separated leaf is varied independently in the frozen corpus. If
multiple rows fail in one captured case, the lowest row number wins. Native timing,
provider diagnostics and iteration order never alter this result.

| Order | Independent field or fault | First public outcome/code |
|---:|---|---|
| 1 | API, context, input, receipt or irreversibility contract version/enum is not v1 | `Denied(PREPARATION_VERSION_UNSUPPORTED)` |
| 2 | `PreparationContextV1::Unavailable` | `Denied(PREPARATION_CONTEXT_UNAVAILABLE)` |
| 3 | required context field/provider group absent | `Denied(PREPARATION_CONTEXT_INCOMPLETE)` |
| 4 | recognized v1 context provider cannot supply required compare/guard semantics | `Denied(PREPARATION_CONTEXT_UNSUPPORTED)` |
| 5 | internally mixed capture identities/generations or contradictory plan/operation/task/workload/attempt binding | `Denied(PREPARATION_CONTEXT_TORN)` |
| 6 | `capture_generation` differs | `Denied(PREPARATION_CONTEXT_MISMATCH)` |
| 7 | `clock_generation` differs or the UTC source is uncomparable | `Denied(PREPARATION_CLOCK_MISMATCH)` |
| 8 | checked UTC arithmetic fails or `sampled_utc_ms >= effective_expires_at_utc_ms` | `Denied(PREPARATION_TIME_EXPIRED)` |
| 9 | `plan_deadline_generation` differs | `Denied(PREPARATION_DEADLINE_MISMATCH)` |
| 10 | `sampled_monotonic_ms >= effective plan deadline` or caller deadline reached before `enter_commit_permit` | `Denied(PREPARATION_DEADLINE_REACHED)` |
| 11 | boot ID differs | `Denied(PREPARATION_BOOT_MISMATCH)` |
| 12 | admission state is not open | `Denied(PREPARATION_SUPERVISOR_DENIED)` |
| 13 | `supervisor_generation`, instance epoch or fencing epoch differs | `Denied(PREPARATION_SUPERVISOR_MISMATCH)` |
| 14 | required guard absent/revoked or its guarded binding changes while held | `Denied(PREPARATION_GUARD_REVOKED)` |
| 15 | trust generation or verified key fingerprint differs/unavailable | `Denied(PREPARATION_TRUST_MISMATCH)` |
| 16 | workload generation or evidence digest differs/unavailable | `Denied(PREPARATION_WORKLOAD_MISMATCH)` |
| 17 | lease generation, lease digest or lease-decision digest differs/unavailable | `Denied(PREPARATION_LEASE_MISMATCH)` |
| 18 | authorization generation or evidence digest differs/unavailable | `Denied(PREPARATION_AUTHORIZATION_MISMATCH)` |
| 19 | policy generation, decision generation, content digest or decision digest differs/unavailable | `Denied(PREPARATION_POLICY_MISMATCH)` |
| 20 | catalogue generation, decision generation, content digest or decision digest differs/unavailable | `Denied(PREPARATION_CATALOGUE_MISMATCH)` |
| 21 | capability report generation/digest, driver-context digest, observed UTC or max age differs, is stale or overflows | `Denied(PREPARATION_CAPABILITY_MISMATCH)` |
| 22 | exact replay row absent | `Denied(PREPARATION_REPLAY_MISSING)` |
| 23 | replay nonce namespace, operation, binding digest, claim ID or claimant generation differs | `Denied(PREPARATION_REPLAY_CONFLICT)` |
| 24 | replay store cannot provide a definitive view | `Denied(PREPARATION_REPLAY_UNAVAILABLE)` |
| 25 | replay schema, row or invariant is corrupt/unknown | `Denied(PREPARATION_REPLAY_UNHEALTHY)` |
| 26 | coordinator snapshot unavailable before operation identity is proved | `Denied(PREPARATION_OPERATION_AUTHORITY_UNAVAILABLE)` |
| 27 | operation/attempt/plan/task/workload or unique-key binding conflicts with an existing record | `Denied(PREPARATION_OPERATION_CONFLICT)` |
| 28 | one fully coherent prior preparation attempt already occupies the operation | `Denied(PREPARATION_ALREADY_PREPARED)` |
| 29 | exact budget scope absent | `Denied(PREPARATION_BUDGET_SCOPE_MISSING)` |
| 30 | scope cannot be proved after operation identity is proved | `Denied(PREPARATION_BUDGET_AUTHORITY_UNAVAILABLE)` |
| 31 | scope lease, allowance digest, generation, currency, price table, reservation ID or recovery-byte binding differs | `Denied(PREPARATION_BUDGET_BINDING_CONFLICT)` |
| 32 | out-of-range value, subtraction underflow, addition overflow or negative-style alternate encoding | `Denied(PREPARATION_BUDGET_ARITHMETIC_INVALID)` |
| 33 | cost, action, egress or recovery request exceeds checked remaining capacity | `Denied(PREPARATION_BUDGET_EXHAUSTED)` |
| 34 | provider profile version/class/at-rest profile or required create/sync/no-clobber capability is unapproved | `Denied(PREPARATION_RECOVERY_PROFILE_UNAPPROVED)` |
| 35 | publication provider/guard is definitely unavailable or creation/durability/publication definitely fails | `Failed(PREPARATION_RECOVERY_UNAVAILABLE)` |
| 36 | receipt plan, operation, attempt, target, precondition, recovery, provider/capability or epoch binding differs | `Denied(PREPARATION_RECOVERY_BINDING_CONFLICT)` |
| 37 | material is absent, temporary, short, extra, corrupt, substituted, undersized, unpublished, retired or not reopen-verifiable | `Denied(PREPARATION_RECOVERY_UNVERIFIED)` |
| 38 | recovery publication result is missing, untrusted or unclassifiable | `Ambiguous(PREPARATION_AMBIGUOUS)` |
| 39 | coordinator root/connection is unavailable, read-only/full or otherwise definitely cannot enter commit | `Failed(PREPARATION_STORE_UNAVAILABLE)` |
| 40 | bounded writer acquisition loses before the caller deadline | `Failed(PREPARATION_STORE_BUSY)` |
| 41 | application/schema/root/lifecycle/durability/integrity/cross-record verification fails | `Failed(PREPARATION_STORE_UNHEALTHY)` |
| 42 | post-serialization constraint/binding conflict not already classified as operation/budget conflict | `Failed(PREPARATION_STORE_CONFLICT)` |
| 43 | commit returns trusted confirmed rollback | `Failed(PREPARATION_STORE_COMMIT_ABORTED)` |
| 44 | explicit `UNCERTAIN` then healthy exact readback proves `DEFINITE_ABSENCE` | `Failed(PREPARATION_STORE_DEFINITE_ABSENCE)` |
| 45 | classification is missing/untrusted, permit owner/deadman expires, or readback is unavailable/partial/inconsistent/late/revoked | `Ambiguous(PREPARATION_AMBIGUOUS)` |

Row 10 applies only before a permit exists. Once the gate is `COMMIT_PERMITTED` or
`COMMIT_IN_FLIGHT`, equality with the permit lease deadline is exclusively row 45:
`Ambiguous(PREPARATION_AMBIGUOUS)`, PAUSE active and new permits blocked. Expiry of a
`NoDispatchAuthorityGuardV1` belongs to the separate `fail_before_dispatch` API; it
returns that API's closed no-mutation deadline refusal and is not a
`PreparationOutcomeV1` row.

For every leaf participating in both captures, the corpus contains a preliminary
single-fault case, a final single-fault case introduced after recovery publication and
an ordering case combining it with a later-row fault. Every expected outcome records
the outcome variant/code, operation/reservation/event generation deltas, recovery-
provider call count, whether recovery may remain quarantined and proof that replay was
not released. Preliminary operation/budget denials additionally prove zero provider
calls. Final denials may retain non-authoritative quarantined material.

An unrelated advance of the replay store's global claimant generation is a required
positive control: if the carried permanent row remains exact, verification proceeds.
Budget order is binding, checked arithmetic, then capacity. Recovery order is profile
approval, availability, receipt binding, then publication verification.

## 7. Time semantics

For preliminary capture, final capture, immediately before commit and before returning a
positive result:

```text
sampled_utc_ms < effective_expires_at_utc_ms
sampled_monotonic_ms < effective_deadline_monotonic_ms
sampled_utc_ms - capability_observed_at_utc_ms <= capability_max_age_ms
```

All arithmetic is checked. Equality with either exclusive plan bound denies. A negative
clock movement, unavailable sample, generation change or overflow is a closed context/
time failure. Time is sampled; no provider claims to lock wall time.

## 8. Replay verification

`EligiblePlanV1::replay_verification_view()` returns an opaque borrowed
`ReplayClaimVerificationViewV1<'_>` constructed only inside
`helix-plan-eligibility`. The view binds the authentic instance/nonce/operation keys to
the exact receipt claim ID/generation/digest without exposing or making public the
crate-private replay-binding constructor.

`ReplayClaimVerifierV1` is read-only:

```rust
pub trait ReplayClaimVerifierV1: Send + Sync {
    fn verify_exact_claim(
        &self,
        view: &ReplayClaimVerificationViewV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> ReplayClaimVerificationV1;
}
```

`Exact` requires one healthy permanent row matching:

- `(instance_epoch, nonce)`;
- operation ID;
- binding digest;
- claim ID;
- claimant generation.

The store's current global generation may be greater and is not an error. Verification
does not call `claim_once`, update metadata, issue a receipt or release anything.

Closed classifications:

```text
EXACT
MISSING
CONFLICT
UNAVAILABLE
UNHEALTHY
```

Only `EXACT` proceeds.

## 9. Guard conformance requirements

The deterministic conformance provider must prove:

- exact fixed acquisition/release order;
- one-at-a-time single-fault change for every vector field;
- changes before preliminary, during recovery and before commit;
- acquisition deadline and already-expired behavior;
- PAUSE/HALT before permit, permit-before-PAUSE, acknowledged abort/commit and ambiguous
  permit resolution at every boundary;
- caller-deadline-first, 250 ms-ceiling-first and exact-equality cases; confirmed
  rollback performs zero readback, while an unclassified result resolves ambiguous;
- owner process kill/hang and permit-deadline expiry before and during `commit_once`,
  proving independent deadman resolution, immediate PAUSE activation, no resumed late
  commit from an expired permit and exact readback for an in-flight commit;
- proof that the trusted coordinator SQLite store implementation calls
  `enter_commit_permit` after staging and holds the returned permit across the actual
  commit;
- no guard retained after any return;
- no coordinator mutation for pre-transaction denial;
- no positive marker when a post-commit check is late/revoked;
- source-independent stable first-denial code.

## 10. Prohibitions

- No check-then-write approximation for a mutable source.
- No process-local mutex claimed as cross-process/provider serialization.
- No guard held across unbounded recovery transfer.
- No guard value serialized, cloned, logged, persisted or submitted to an effect,
  native-operation or agent-facing adapter. The only allowed boundary crossing is the
  borrowed `FinalCommitGateV1` passed in-process to the trusted coordinator store for
  the scoped commit protocol defined above.
- No global transaction claim across supervisor, replay, recovery and coordinator stores.
- No release/revival of the existing replay claim after denial.
