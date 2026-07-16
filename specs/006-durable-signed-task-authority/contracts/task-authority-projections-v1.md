# Contract: Durable Task Authority Projections v1

**Contract ID**: `helixos.task-authority-projections/1`

**Status**: design contract; implementation pending

## 1. Purpose

This contract defines the only production integration from exact, verified PLAN-006
authority into the existing PLAN-002 eligibility, PLAN-004 preparation and PLAN-005
dispatch seams. It does not define a fourth signed wire. A projection is an opaque,
in-process current-state result derived from retained `HumanRequestGrantV1`,
`TaskLeaseV1`, `ApprovalDecisionV1`, their durable relationships, current trust and
current revocation state.

The projection cannot issue a plan, create a PLAN-003 replay claim, prepare or dispatch
an operation, mint an execution grant, call an adapter, perform a host effect or revive
historical authority. Existing PLAN-001 through PLAN-005 wires and portable contracts
remain byte-for-byte unchanged.

## 2. Ownership and dependency direction

PLAN-006 is split into four crates:

| Crate | Ownership |
|---|---|
| `helix-task-authority-contracts` | Closed canonical signed wires and strict verification |
| `helix-task-authority` | Portable issuance, delegation, decision, projection, guard and store traits |
| `helix-task-authority-sqlite` | Separate durable HLXA authority root and maintenance implementation |
| `helix-task-authority-projections` | Leaf adapters into PLAN-002, PLAN-004 and PLAN-005 |

Dependencies point from `helix-task-authority-projections` toward
`helix-contracts`, `helix-plan-eligibility`, `helix-plan-preparation` and
`helix-plan-dispatch`. None of those existing crates gains a PLAN-006 dependency.
`helix-plan-dispatch` therefore retains its closed normal dependency set. The
projection crate does not depend on `helix-coordinator-sqlite`,
`helix-dispatch-inbox-sqlite`, `helixos-kernel`, `helixos-mcp-shim` or
`helixos-provision`.

SQLite is confined to `helix-task-authority-sqlite`. The portable contracts, core
authority model and existing plan crates neither open nor identify an HLXA root.

## 3. Current projection boundary

`CurrentAuthorityProjectionV1` is non-Serde, non-wire and has no public positive
constructor. Only `CurrentAuthorityProjectionProviderV1` may return it after verifying
one complete durable graph. Production APIs accept an authenticated PLAN-001 envelope
or an existing nonconstructible plan marker plus an opaque projection provider; they do
not accept caller-populated projection fields.

A positive projection binds at least:

| Projection fact | Authoritative derivation |
|---|---|
| request source | exact retained `HumanRequestGrantV1` and its protected `grant_digest` |
| grant generation | current create-only grant-claim generation |
| leaf lease | exact retained `TaskLeaseV1` and its protected `lease_digest` |
| lease generation | current durable lease-projection generation |
| ancestry | ordered root-to-leaf lease IDs/digests/generations plus a domain-separated ancestor-vector digest |
| lease allowance | domain-separated plan-bound lease projection digest after exact intention, resource, budget, counter, trust and catalogue comparison |
| authorization | exact retained terminal `ApprovalDecisionV1` and its protected `decision_digest` |
| authorization generation | current durable decision/projection generation |
| revocation | current revocation generation and digest covering signer, grant, every ancestor, leaf lease and decision |
| identity | exact plan, operation, nonce, task, workload, boot, instance and fencing bindings required by the target seam |
| status | closed current, denied, expired, exhausted, revoked, unavailable, inconsistent or unsupported result |
| time | earliest exclusive UTC expiry and earliest exclusive same-boot monotonic deadline |

The three projection digests below are derived evidence, not new signatures. Each is
`lowercase_hex(SHA-256(domain || JCS(closed_map)))`, where `domain` is the exact byte
string in the table, `JCS` is RFC 8785 UTF-8, every listed member is required and no
other member exists. Object member order is RFC 8785 lexical order. Arrays use the
explicit semantic order below, contain no duplicates and are never treated as sets
unless an ascending-byte-order rule is stated.

| Digest | Exact domain bytes | Closed map schema |
|---|---|---|
| ancestor vector | `HELIXOS\0TASK-AUTHORITY-ANCESTOR-VECTOR\0V1\0` | `helixos.task-authority-ancestor-vector/1` |
| plan-bound lease | `HELIXOS\0TASK-AUTHORITY-PLAN-BOUND-LEASE\0V1\0` | `helixos.task-authority-plan-bound-lease/1` |
| revocation vector | `HELIXOS\0TASK-AUTHORITY-REVOCATION-VECTOR\0V1\0` | `helixos.task-authority-revocation-vector/1` |

### 3.1 Ancestor-vector preimage

The closed ancestor-vector map contains exactly:

- `schema`;
- `source_grant_issuer_id`, `source_grant_id`, `source_grant_digest` and
  `grant_claim_generation`;
- `leases`, an array ordered strictly from root to leaf; and
- `leaf_lease_issuer_id`, `leaf_lease_id` and `leaf_lease_digest`, which MUST equal
  the final array entry.

Every closed `leases` entry contains exactly `lease_issuer_id`, `lease_id`,
`lease_digest`, `delegation_depth`, `parent_allocation_id`,
`lease_projection_generation`, `allocation_generation` and `counter_generation`.
Depth is exactly the zero-based array index. `parent_allocation_id` is explicit
`null` only at depth zero and a digest otherwise. Every digest is the protected
digest of the exact retained wire or allocation record named by the member. No
historical, skipped, duplicated or caller-supplied entry is accepted.

### 3.2 Plan-bound lease preimage

The closed plan-bound lease map contains exactly:

- `schema`, `plan_id`, `plan_envelope_digest`, `operation_id`, `plan_nonce`,
  `task_id` and `workload_id`;
- `human_request_grant_digest`, `ancestor_vector_digest`, `leaf_lease_digest` and
  `lease_projection_generation`;
- `allowed_intentions`, the exact ascending UTF-8 byte-ordered identifiers;
- `resource_roots`, the exact canonical TaskLease resource-root array;
- `remaining_budget`, containing exactly `read_bytes`, `distinct_files`, `actions`,
  `egress_bytes`, `cost_micro_units`, `currency_code` and `price_table_id`;
- `remaining_counters`, containing exactly `plans`, `approvals`, `child_leases`,
  `delegation_depth` and `max_delegation_depth`;
- `trust_bound`, byte-for-byte the closed TaskLease trust-bound object;
- `catalogue_bound`, byte-for-byte the closed TaskLease catalogue-bound object;
- `policy_decision_digest` and `catalogue_decision_digest` for the exact plan;
- `workload_identity_digest`, `workload_generation` and closed `workload_status`;
- `revocation_vector_digest`, `clock_generation`, `boot_id`, `instance_epoch` and
  `fencing_epoch`; and
- `earliest_expires_at_utc_ms` and `earliest_deadline_monotonic_ms`.

All remaining amounts are checked safe integers computed from signed limits minus
the complete durable allocation/consumption graph. `workload_status` is exactly
`CURRENT` for a positive projection. The two earliest deadlines are the minimum
exclusive bounds across plan, grant, every lease, decision and current clock
custody. Any underflow, missing price/currency identity, changed policy/catalogue,
non-current workload or unequal plan binding yields no digest and a non-positive
projection.

### 3.3 Revocation-vector preimage

The closed revocation-vector map contains exactly `schema`,
`revocation_generation`, `signers`, `source_grant`, `leases`, `decision`,
`scope_template`, `boot`, `instance_epoch` and `fencing_epoch`.

- `signers` is ascending by `(key_purpose, key_id)` and each closed entry contains
  exactly `key_purpose`, `key_id`, `public_key_fingerprint`, `trust_generation`,
  `status` and `applicable_revocation_ids`.
- `source_grant` contains exactly `issuer_id`, `grant_id`, `grant_digest`,
  `grant_claim_generation`, `status` and `applicable_revocation_ids`.
- `leases` is the same root-to-leaf identity order as the ancestor vector; each
  entry contains exactly `lease_issuer_id`, `lease_id`, `lease_digest`,
  `lease_projection_generation`, `status` and `applicable_revocation_ids`.
- `decision` contains exactly `issuer_id`, `decision_id`, `decision_digest`,
  `decision_projection_generation`, `status` and `applicable_revocation_ids`.
- `scope_template` contains exactly `scope_template_id`,
  `scope_template_digest`, `scope_template_generation`, `status` and
  `applicable_revocation_ids`.
- `boot`, `instance_epoch` and `fencing_epoch` each contain exactly `value`,
  `status` and `applicable_revocation_ids`.

Every `applicable_revocation_ids` array is ascending lowercase digest order and may
be empty. Status is the closed `CURRENT`, `RETIRED`, `REVOKED` or `REPLACED` value
appropriate to the subject. A positive projection requires `CURRENT` everywhere
and empty applicable arrays; the digest still covers the explicit absence. The
generation is the exact HLXA revocation generation from the same snapshot.

The contract corpus MUST freeze the exact JCS preimage bytes and lowercase digest
for all three maps in `golden/ancestor-vector.jcs`,
`golden/plan-bound-lease-projection.jcs`, `golden/revocation-vector.jcs` and their
adjacent `.sha256` files. Mutation coverage changes every listed leaf, array order,
status and explicit root `null`; no implementation may choose or extend these
preimages from fixture data.

The `ApprovalDecisionV1.decision_digest`, not its inner authentication-evidence
digest, is the downstream authorization evidence digest because it binds the
complete signed terminal decision.

A current result requires exactly one coherent grant claim, one exact leaf path, one
terminal decision, current purpose-specific signer trust, no applicable revocation,
unexhausted counters, exact generations and all current time/epoch bindings. Missing,
multiple, torn, unsupported or historical-only graphs return a closed non-positive
outcome.

## 4. PLAN-002 eligibility seam

The exact existing seam is:

- `ActiveLeaseInputV1`, `LeaseResolutionV1`, `AuthorizationInputV1` and
  `AuthorizationViewV1` in `kernel/helix-plan-eligibility/src/context.rs`;
- `evaluate_and_claim_plan_v1` in
  `kernel/helix-plan-eligibility/src/evaluator.rs`.

The projection crate exposes one production orchestration function equivalent to:

```rust
evaluate_and_claim_signed_authority_plan_v1(
    authentic_plan,
    non_authority_inputs,
    projection_provider,
    replay_claimant,
)
```

It first resolves the current signed chain. Only then may it construct the lease and
authorization portions of `EligibilityContextV1` and call the unchanged
`evaluate_and_claim_plan_v1`. Authority resolution failure occurs before the PLAN-003
claimant is invoked. The returned `EligiblePlanV1` remains the existing
non-authoritative, one-shot eligibility marker; PLAN-004 must still revalidate current
authority under guards.

`non_authority_inputs` contains only the clock, supervisor, workload, policy, catalogue,
capability, replay and plan-deadline inputs. It cannot carry a lease or authorization
view that the orchestration might accidentally prefer over PLAN-006.

The mapping is exact:

| PLAN-002 field | PLAN-006 value |
|---|---|
| `lease_digest` | protected TaskLease `lease_digest` already bound by PLAN-001 |
| `lease_generation` | current lease-projection generation |
| `state` | `Active` only for one current, unexhausted and unrevoked chain |
| task/workload/boot/instance | exact signed lease and plan bindings |
| `request_source_kind` | `HumanRequestGrant` only |
| `request_source_digest` | protected HumanRequestGrant `grant_digest` already bound by PLAN-001 |
| lease UTC/monotonic bounds | effective earliest grant/ancestor/leaf bounds |
| `LeaseAllowanceV1.plan_id` | exact authenticated PLAN-001 plan ID |
| `LeaseAllowanceV1.decision_digest` | plan-bound lease projection digest |
| authorization `status` | `Granted` only for a current signed `APPROVED` decision |
| authorization plan/operation/risk/nonce/boot | exact ApprovalDecision and plan values |
| `evidence_digest` | protected ApprovalDecision `decision_digest` |
| `authorization_generation` | current authorization-projection generation |
| authorization UTC/monotonic bounds | effective earliest decision and authority-chain bounds |

Public PLAN-002 record constructors remain available to that crate's isolated tests,
but no production PLAN-006 API accepts an `ActiveLeaseRecordV1`,
`AuthorizationRecordV1`, `LeaseResolutionV1` or `AuthorizationViewV1` as proof of
signed authority.

## 5. PLAN-004 preparation seam

The exact existing seam is `PreparationAuthoritySourceV1` in
`kernel/helix-plan-preparation/src/guard.rs`, consumed by `prepare_plan_v1` in
`kernel/helix-plan-preparation/src/coordinator.rs`. The adapter is
`SignedPreparationAuthoritySourceV1` and implements the existing trait without changing
`helix-plan-preparation`.

Preliminary capture may read a current projection for early rejection only. It does not
authorize recovery publication or commit. During ordered final acquisition the adapter:

1. delegates the non-PLAN-006 clock, supervisor, signer, workload, policy, catalogue and
   capability facts to sovereign configured providers;
2. opens the unified HLXA guard at the existing `Lease` slot;
3. verifies the authorization inside the same HLXA snapshot at the existing
   `Authorization` slot;
4. builds the final `ReadyPreparationContextInputV1` while that custody remains live;
5. preserves the existing `prepare_plan_v1` comparison, commit gate and coordinator
   store transaction unchanged.

The following final context fields are replaced from PLAN-006, never copied from a
caller or an unguarded base context:

```text
lease_generation
lease_digest
lease_decision_digest
authorization_generation
authorization_evidence_digest
effective_expires_at_utc_ms
effective_deadline_monotonic_ms
boot_id / instance_epoch / fencing_epoch where the signed binding applies
```

`lease_decision_digest` is the same plan-bound lease projection digest used by
PLAN-002. `authorization_evidence_digest` is the protected ApprovalDecision digest.
Any preliminary/final change in either digest, either generation, the ancestor vector,
revocation state, status or deadline denies before a prepared marker is returned.

## 6. PLAN-005 dispatch seam

The exact existing seams are:

- `DispatchAuthorityProviderV1` and `DispatchAuthorityViewInputV1` in
  `kernel/helix-plan-dispatch/src/authority.rs`;
- `DispatchGuardProviderV1` in `kernel/helix-plan-dispatch/src/guard.rs`;
- `dispatch_prepared_once_v1` in
  `kernel/helix-plan-dispatch/src/coordinator.rs`.

`SignedDispatchAuthorityProviderV1` supplies preliminary and `FinalGuarded` views.
`SignedDispatchGuardProviderV1` owns the full fixed-order acquisition and the unified
HLXA custody. The final provider reload occurs inside that held snapshot. These
existing `DispatchAuthorityViewInputV1` fields receive PLAN-006 values:

```text
lease_generation
lease_digest
lease_decision_digest
authorization_generation
authorization_evidence_digest
earliest_authority_deadline_monotonic_ms
task_id / workload_id / instance_epoch where the signed binding applies
```

The adapter must not accept a ready `DispatchAuthorityViewV1` from its caller and must
not reconstruct authority from coordinator rows. A mismatch between preliminary and
final guarded values follows the existing dispatch denial path and produces no new
execution grant, dispatch graph or adapter handoff.

## 7. Fixed guard order and unified HLXA custody

PLAN-004 and PLAN-005 retain the same frozen order:

| Order | Existing guard class | PLAN-006 behavior |
|---:|---|---|
| 1 | Recovery publication | existing sovereign custody |
| 2 | External clock/deadline | existing trusted clock custody |
| 3 | Supervisor | existing admission/epoch custody |
| 4 | Signer trust | existing current-trust custody |
| 5 | Workload | existing workload custody |
| 6 | Lease | open one deadline-bounded HLXA `BEGIN IMMEDIATE`; verify grant, ancestry, leaf lease, counters, trust and revocations |
| 7 | Authorization | verify the terminal decision and plan binding in the same HLXA transaction; do not open a second writer transaction |
| 8 | Policy | existing policy custody |
| 9 | Catalogue | existing catalogue custody |
| 10 | Capabilities | existing capability custody |
| 11 | Existing coordinator writer | acquired by the unchanged PLAN-004/005 store after every external guard |

The adapter reports each existing class exactly once at its required acquisition
boundary. Lease and Authorization remain two logical guard classes even though they
share one physical HLXA writer transaction. The guard set is non-Clone, non-Serde and
owns that transaction until release.

On failure to acquire or validate any class before the absolute monotonic deadline, all
already-held guards are released in reverse order and the HLXA transaction is rolled
back. On success the unified HLXA guard remains held across final capture, candidate
construction, the existing one-shot commit permit and the actual coordinator commit
call. It is released only after the existing commit API returns its committed,
confirmed-rollback, prior-exact or uncertain/ambiguous classification and establishes
any required readback custody.

No authority mutation is part of a PLAN-004 or PLAN-005 commit. Consequently the two
SQLite databases do not require, and do not claim, a distributed atomic transaction.
The retained HLXA writer exclusion linearizes every authority write either before the
downstream refusal or after the downstream commit attempt. No PLAN-006 operation may
take the coordinator writer and then attempt to acquire HLXA.

## 8. TOCTOU and revocation semantics

A read-then-commit sequence without retained custody is non-conforming. The unified
guard must block cross-thread and cross-process authority writers, including signer
status changes, grant/lease/ancestor/decision revocations, counter consumption and
generation changes.

If such a change commits before the HLXA guard is acquired, final projection resolution
denies. If the downstream commit permit wins while the guard is held, the downstream
commit is ordered before the later authority change. A later revocation does not claim
to undo an already committed preparation or dispatch; it prevents subsequent positive
projections. Process exit releases SQLite custody, but correctness must not depend on
Rust `Drop` alone and no detached worker may continue mutation after a terminal return.

PLAN-002 does not make an end-to-end currency claim: its signed projection is current at
resolution, its marker is non-authoritative, and PLAN-004/005 perform the guarded final
rechecks. PLAN-003 replay state remains a separate namespace and is neither created nor
released by projection resolution itself.

## 9. Time and deadline rules

All boundaries are exclusive and all arithmetic is checked:

```text
sampled_utc_ms < earliest_expires_at_utc_ms
sampled_monotonic_ms < earliest_deadline_monotonic_ms
```

`earliest_expires_at_utc_ms` is the minimum applicable plan, HumanRequestGrant,
root/ancestor/leaf TaskLease, ApprovalDecision and sovereign-provider UTC bound.
`earliest_deadline_monotonic_ms` is the minimum applicable caller, plan,
root/ancestor/leaf TaskLease, ApprovalDecision, commit-permit and sovereign-provider
same-boot bound. The signed TaskLease and ApprovalDecision clock generation, boot ID and
instance epoch must match the current trusted clock domain.

Equality is expired. Unavailable time, rollback suspicion, generation change, reboot,
boot/instance mismatch, overflow, suspend/resume inconsistency or an unexpectedly long
sleep denies. Deadlines are never refreshed on retry, and wall time is sampled rather
than claimed to be locked by the HLXA guard.

## 10. Legacy and synthetic refusal

None of the following can satisfy this contract:

- a protected legacy runtime lease or approval object;
- an approval enum, boolean, notification or chat message;
- a caller-provided database row, digest, generation or current-status assertion;
- a caller-constructed positive PLAN-002, PLAN-004 or PLAN-005 view;
- deterministic synthetic authentication evidence outside labelled conformance tests;
- restored, unsigned or historical state lacking the complete exact signed chain.

There is no backfill or compatibility constructor. Historical PLAN-001/005 evidence may
remain readable but is non-current. A new HumanRequestGrant, root/child TaskLease, plan
and terminal ApprovalDecision chain is required for new authority. Source and dependency
tests must prove that no protected legacy crate can reach a PLAN-006 positive projection
and that removing PLAN-006 leaves prior package behavior unchanged.

## 11. HLXA bootstrap, backup and restore

The authority store is a separate local SQLite root with exact identity:

```text
application_id = 1212962881
hex            = 0x484c5841
ASCII          = HLXA
user_version   = 1
```

Ordinary open is non-mutating and accepts only the exact published schema, durability
profile, root identity and cross-record invariants. PLAN-006 has no predecessor
authority schema. Its sole initial supported migration is an explicit, restartable,
paused bootstrap from the exact PLAN-005 coordinator-V2 baseline and a fresh verified
backup into a new empty HLXA root. The complete schema, root metadata and migration
receipt are staged before root publication. An interruption resumes the same bootstrap
identity or classifies the exact published result; it never repairs admission state,
creates a second root or imports legacy authority.

Backup runs under PAUSE and fixed custody order. The PLAN-006 published-last manifest
binds an independently coherent authority checkpoint plus the independently coherent
prior component backups required to interpret its plan projections. It includes exact
application/schema/root identities, schema digest, checkpoint and generation summaries,
public verification-key history, signed wires, counters, allocations, revocations,
tombstones, migration receipt, member digests and provenance. Private signing keys, raw
messages, authentication assertions, bearer values and native paths are excluded.

Restore accepts only a complete verified package and approved empty destinations. It
rotates root, boot, instance, fencing and restore epochs, publishes
`RESTORE_PENDING`, and remains PAUSED. Restored signed bytes remain historically
verifiable, but every restored nonterminal lease and approval is non-current. Restore
does not redeliver, reissue or automatically activate authority. The top-level manifest
proves a quiescent coherent cut, not cross-store transactional atomicity.

## 12. Conformance gates

The release evidence uses these closed gate identifiers:

| Gate | Required proof |
|---|---|
| `PLAN006-CONTRACT` | strict canonical wires, domains, signatures, leaf mutations and redaction |
| `PLAN006-REQUEST` | one-shot grant consumption/root issuance and exact retry |
| `PLAN006-LEASE` | restrictive delegation, counters, aggregate sibling limits and revocation |
| `PLAN006-DECISION` | exact terminal decision, approve/deny races and L2 evidence rules |
| `PLAN006-PROJECTION` | exact PLAN-002/004/005 mappings, guarded recheck and zero downstream mutation on mismatch |
| `PLAN006-DURABILITY` | atomic transitions, crash boundaries, uncertainty and exact readback |
| `PLAN006-RESTORE` | bootstrap, migration, backup, clean-root restore and zero reactivation |
| `PLAN006-PORTABILITY` | unchanged corpus on macOS arm64, Linux x64 and Windows x64 |
| `PLAN006-PERFORMANCE` | declared raw samples, percentiles, overload and control-lane availability |
| `PLAN006-SUPPLY` | exact-commit dependencies, licenses, advisories, provenance and removal |

Projection conformance independently mutates every mapped digest, generation, ancestor,
revocation, identity and deadline. Each case must produce the expected closed denial and
prove zero new PLAN-003 claim when authority fails before eligibility, zero preparation
mutation, and zero dispatch mutation at the relevant seam. The prior PLAN-001 through
PLAN-005 tests remain unchanged regression gates.

## 13. Performance and overload

On the declared physical reference profile, after 500 warmups and 10,000 measured raw
samples:

- verification of all three signed contracts plus current projection has p95 at or
  below 2 ms;
- each durable root issue, delegation and terminal-decision transition has p95 at or
  below 25 ms and p99 at or below 100 ms.

One hundred trials of 10,000 duplicate requests must bound or refuse new work within
50 ms while current revocation and status lookup remain p99 at or below 100 ms. The
ordinary queue and reserved control capacity are measured independently; duplicates
coalesce by immutable identity and never trigger re-signing or blind reissuance.

Evidence records hardware, OS/architecture, Rust and SQLite source identity, filesystem,
durability profile, schema/source/lock digests, corpus, concurrency, warmups, raw sample
order and percentile method. Hosted CI timing is diagnostic only.

## 14. Removal and nonclaims

The exact removal baseline is commit
`c324f528dc76007a599005e5cc054dcbe1370b1a`, tree
`c70a3f2157498dd880822f97ef74d3d4757347d7`. Removal deletes the four PLAN-006 crates,
fixtures, executable examples and workflow, restores every baseline-modified manifest,
lock, catalogue and generated input byte-for-byte, and requires the resulting indexed
tree and baseline package set to match that frozen baseline. Because all runtime edges
point from new crates to old crates and HLXA is separate, no existing plan source needs
authority-removal edits and the coordinator V2 root remains usable.

This contract does not claim production request ingress, WebAuthn/passkey processing,
production key custody, host effects, adapter delivery, effect verification, physical
power-loss durability, secure erasure, full-machine recovery, cross-store atomic commit,
cross-store atomic live backup, physical-M4 evidence from hosted runners, R2 activation
or Tier-1 readiness.
