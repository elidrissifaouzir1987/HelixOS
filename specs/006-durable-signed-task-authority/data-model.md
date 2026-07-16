# Data Model: Durable Signed Task Authority

**Feature**: `006-durable-signed-task-authority`

**Date**: 2026-07-15

## 1. Model rules

1. Signed bytes are immutable evidence. Current authority is a derived property
   of those bytes plus current trust, generations, revocations, ancestors, usage,
   boot/instance state and time.
2. Wire identity, one-shot identity and database attempt identity are distinct.
   Key rotation never reopens a grant, lease, allocation or decision namespace.
3. Unknown values deny. Version 1 has no optional extension map and no implicit
   default. A conditionally absent value is represented only by the exact
   explicit shape frozen in the schema.
4. Every authority-bearing wire leaf contributes to
   `SHA-256(JCS(protected))` and to the purpose-separated Ed25519 signature.
5. Immutable facts are create-only. Mutable summaries exist only where required
   for bounded contention and are reproducible from append-only facts.
6. A positive projection is non-serializable, nonconstructible from caller
   fields, and available only while its durable authority guard is alive.
7. `HLXA` is a separate SQLite domain. Stable cross-store observation is proven
   by guard custody and ordered commits, never described as a distributed
   transaction.

## 2. Signed wire values

### 2.1 Common envelope

Each version-1 wire has exactly:

| Field | Type | Rule |
|---|---|---|
| `protected` | closed object | Contract-specific authority content. |
| contract digest | 64 lowercase hex characters | SHA-256 of exact RFC 8785 canonical `protected` bytes. |
| `signature` | canonical base64url without padding | Strict Ed25519 signature over `domain || JCS(protected)`. |

The outer digest member is `grant_digest`, `lease_digest` or
`decision_digest`. The entire envelope is exact RFC 8785 JSON. Duplicate members,
unknown members, a noncanonical order/number/string, invalid NFC, a wrong digest,
wrong key purpose, wrong domain or invalid signature deny before any authentic
marker exists.

### 2.2 `HumanRequestGrantProtectedV1`

Purpose: prove that one trusted request surface authenticated one bounded human
request context.

Required semantic groups:

| Group | Required bindings |
|---|---|
| Contract | schema `helixos.human-request-grant/1`, `sha-256`, `ed25519`, purpose `request-surface-grant-signing`, immutable key ID |
| Identity | issuer ID, grant ID, audience and one-shot namespace |
| Human context | principal ID, exact message digest, channel ID, session ID |
| Scope | immutable scope-template ID, protected digest and generation |
| Time | trusted issue UTC and exclusive expiry UTC |

The contract never includes raw message text, transport credentials, a bearer
link, cookie, notification body, authentication assertion or native path.

### 2.3 `SignedHumanRequestGrantV1`

The exact envelope containing `HumanRequestGrantProtectedV1`, `grant_digest` and
the request-surface signature. Its protected digest becomes both the lease source
binding and the PLAN-001 request-source digest.

### 2.4 `AuthenticHumanRequestGrantV1`

Non-wire verifier result containing the typed protected value, exact canonical
bytes, protected digest, resolved immutable public-key fingerprint and a marker
for either current trust or historical evidence. Only the current variant can be
consumed for root issuance.

### 2.5 `TaskLeaseProtectedV1`

Purpose: represent core-issued task authority over an exact bounded scope.

Required semantic groups:

| Group | Required bindings |
|---|---|
| Contract | schema `helixos.task-lease/1`, `sha-256`, `ed25519`, purpose `core-task-lease-signing`, immutable key ID |
| Identity | issuer ID, lease ID, task ID, workload ID, audience |
| Derivation | source grant protected digest; root/child kind; explicit parent lease digest and delegation depth for a child |
| Intentions/resources | sorted unique closed intention IDs and portable opaque resource components/roots |
| Budgets/counters | safe bounded read-byte, distinct-file, action and feature-specific limits; no float or negative value |
| Trust bounds | direct policy and catalogue bounds; workload identity is signed directly, scope-template identity is transitively bound by the exact source-grant digest, and current workload/signer/scope generations remain verified projection metadata |
| Lifecycle | boot ID, instance epoch, issue UTC, inclusive not-before UTC, exclusive expiry UTC, exclusive same-boot monotonic deadline |

A root lease has the explicit root shape and is no wider than the exact source
grant plus current scope/policy/catalogue constraints. A child has the explicit
child shape and binds one parent/ancestor chain. Omission never substitutes for a
root/child discriminator.

### 2.6 `SignedTaskLeaseV1`

The exact envelope containing `TaskLeaseProtectedV1`, `lease_digest` and the core
lease signature. The protected digest is the PLAN-001 `task_lease_digest` and the
PLAN-002 lease digest. Store generations are deliberately not signed fields;
they are current durable projection metadata rechecked at each commit.

### 2.7 `AuthenticTaskLeaseV1`

Non-wire verifier result parallel to the grant authentic type. Authenticity proves
the bytes and signer. Current authority additionally requires the exact current
source grant, all ancestors, remaining allocation/counters, trust/catalogue,
revocation generation, boot/instance and time.

### 2.8 `ApprovalDecisionProtectedV1`

Purpose: bind one immutable terminal human decision to one exact current plan and
authority chain.

Required semantic groups:

| Group | Required bindings |
|---|---|
| Contract | schema `helixos.approval-decision/1`, `sha-256`, `ed25519`, purpose `core-approval-decision-signing`, immutable key ID |
| Identity | issuer ID, decision ID and terminal `APPROVED` or `DENIED` |
| Plan target | PLAN-001 `plan_id`, `plan_envelope_digest`, operation ID, task/workload IDs and plan nonce |
| Authority chain | human grant protected digest and leaf lease protected digest; the complete ancestor vector is transitively bound by recursive parent digests and recomputed as current derived projection evidence |
| Decision context | risk level, principal/session, authentication profile, redacted evidence digest |
| Current state | policy/catalogue/trust, boot/instance/fencing identities and generations |
| Time | trusted issue UTC and exclusive expiry UTC no later than plan, grant or lease |

`plan_envelope_digest` means SHA-256 of the exact canonical signed PLAN-001
envelope bytes. It is distinct from `plan_id`; no generic ambiguous `plan_digest`
alias is used in the implementation contracts.

### 2.9 `SignedApprovalDecisionV1`

The exact envelope containing `ApprovalDecisionProtectedV1`, `decision_digest`
and the core decision signature. Only an authentic, current `APPROVED` value with
the required evidence profile may contribute a positive authorization projection.
A valid `DENIED` value is terminal evidence but never positive authority.

### 2.10 `AuthenticApprovalDecisionV1`

Non-wire verifier result parallel to the other authentic types. The historical
variant can prove retained decision bytes. The current variant additionally
requires the exact target plan, source grant, leaf/ancestor leases, signer trust,
revocation state, boot/instance and exclusive deadline.

## 3. Independent authority root

### 3.1 `AuthorityStoreMetadataV1`

Singleton root metadata:

- application ID `1212962881` (`HLXA`) and schema version `1`;
- immutable opaque root identity and schema/normalized-SQL digest;
- durability profile and queue/control capacities;
- lifecycle `ACTIVE` or `RESTORE_PENDING`;
- current boot ID, instance and fencing epochs;
- monotonic store, trust, grant, lease, allocation, counter, decision,
  revocation, event, migration and restore generations;
- optional exact bootstrap receipt, backup checkpoint and restore-package
  bindings.

Every generation starts at a positive safe integer, increases only inside the
atomic graph it describes, is never reused, and is no greater than the global
store generation. Generation overflow denies before mutation.

### 3.2 `VerificationKeyRecordV1`

Immutable public verification material:

- key ID and exact signer purpose;
- public-key bytes/fingerprint and algorithm;
- issuer identity;
- introduction generation and provenance digest.

Private keys never enter the authority store. Key ID plus purpose is create-only;
the same ID cannot be reassigned to different bytes or another purpose.

### 3.3 `KeyStatusEventV1`

Append-only current-trust history:

- event ID, key ID/purpose and trust generation;
- closed status `TRUSTED`, `RETIRED` or `REVOKED`;
- exclusive effective time and closed reason code;
- redacted event/provenance binding.

The latest valid event derives current trust. `RETIRED`/`REVOKED` keys remain
usable only for historical verification according to the closed evidence API.

## 4. Durable request entities

### 4.1 `HumanRequestGrantRecordV1`

Create-only retained record keyed by `(grant_issuer_id, grant_id)`:

- exact canonical signed envelope bytes and grant protected digest;
- immutable request key ID/purpose/fingerprint and verification generation;
- principal, channel, session, audience and scope-template bindings needed for
  indexed strict readback;
- issue/expiry and retention generation;
- current-at-consumption trust/scope observations.

Indexed copies are redundant validation aids only. Open/readback recomputes the
wire and checks every indexed binding; the row can never override signed bytes.

### 4.2 `HumanGrantClaimV1`

Create-only one-shot claim keyed by the exact grant namespace:

- claim/attempt ID;
- grant record and digest;
- exactly one root lease ID/digest and exact root signed bytes reference;
- claim generation and transition event;
- closed result `ROOT_ISSUED`.

An exact retry matches every stored binding and returns the retained root lease.
Any differing reuse is a conflict tombstone and yields no new lease.

## 5. Durable lease entities

### 5.1 `TaskLeaseRecordV1`

Create-only row keyed by `(lease_issuer_id, lease_id)` and unique signed digest:

- exact canonical signed envelope bytes and protected lease digest;
- source grant identity/digest;
- task/workload/audience;
- root/child discriminator, parent identity/digest and delegation depth;
- signed validity and trust/scope/catalogue bindings;
- creation attempt/generation and event.

The root lease has exactly one `HumanGrantClaimV1`. A child has exactly one
allocation and one existing parent. Cycles, missing ancestors, cross-task,
cross-workload, cross-source and excessive depth fail invariant validation.

### 5.2 `TaskLeaseUsageV1`

Current monotonic summary for one lease:

- allocated child totals per governed budget/counter axis;
- consumed direct totals per governed counter axis;
- current usage and last allocation/counter generations;
- derived exhaustion flags.

Only reviewed transactions may increase a total. Decrease, reset, delete,
release, negative arithmetic and overflow are prohibited. Open/readback verifies
the summary against append-only allocation and consumption facts.

### 5.3 `TaskLeaseAllocationV1`

Create-only parent-child allocation:

- allocation identity and attempt ID;
- parent and child lease IDs/digests;
- exact allocated intentions/resources/budget/counter vector digest and bounded
  indexed totals;
- parent generation before/after and event.

The allocation and child lease become visible atomically. Sum of all child
allocations is checked with safe arithmetic and cannot exceed the signed parent
limit or any current remaining constraint.

### 5.4 `TaskLeaseCounterConsumptionV1`

Create-only consumption tombstone:

- consumption identity and attempt ID;
- lease ID/digest, task/workload and closed counter kind;
- positive bounded amount and exact context digest;
- usage generation before/after and event.

Exact retry returns the retained result. Conflicting identity reuse denies.
There is no decrement or refund operation in V1.

## 6. Durable decision entities

### 6.1 `ApprovalPlanBindingV1`

Create-only exact target evidence:

- `plan_id` and canonical `plan_envelope_digest`;
- exact retained canonical signed PLAN-001 envelope bytes or immutable retained
  reference plus verified digest;
- operation ID, nonce, task/workload, risk and plan deadline;
- source grant, leaf lease and ancestor-vector digests;
- verification generation and current-state summary.

It is not authority by itself. It is the exact evidence against which a terminal
decision is verified and re-read.

### 6.2 `ApprovalDecisionRecordV1`

Create-only terminal row keyed by `(decision_issuer_id, decision_id)` and unique
exact plan target:

- exact canonical signed decision bytes and protected decision digest;
- exact `ApprovalPlanBindingV1`;
- terminal value `APPROVED` or `DENIED`;
- signer purpose/key/fingerprint;
- authentication profile and redacted evidence digest;
- issue/expiry, decision attempt/generation and event.

There is no update from denied to approved, approved to denied, or pending to
terminal. A concurrent exact retry returns the retained bytes; any other terminal
candidate for the same identity/target is a conflict.

## 7. Revocation and events

### 7.1 `AuthorityRevocationV1`

Append-only create-only record:

- revocation ID and attempt ID;
- closed subject kind `SIGNER`, `GRANT`, `LEASE`, `DECISION`, `BOOT`, `INSTANCE`
  or `SCOPE_TEMPLATE`;
- exact subject identity/digest and optional parent generation;
- effective UTC/monotonic observation and revocation generation;
- closed reason and event ID.

Revoking a grant or lease derives non-current status for every descendant. No
signed row is edited. A revocation cannot claim to undo an already possible
downstream effect.

### 7.2 `AuthorityTransitionEventV1`

Permanent append-only redacted evidence:

- event ID, event generation and closed event kind;
- subject kind and bounded pseudonymous reference;
- before/after generation summaries;
- attempt ID and closed result/reason;
- trusted UTC/monotonic/boot observations;
- previous-event digest and current event digest when chain sealing is enabled.

Events never contain exact signed wires, identifiers, protected digests, raw
messages, assertions, paths, keys or provider error text in their public form.
Restricted internal row references may link to exact records without becoming
public output.

### 7.3 `AuthorityConflictTombstoneV1`

Create-only proof that one one-shot namespace was reused with a different
binding. It carries only stable namespace hashes, expected/observed binding
digests in restricted storage, closed reason, attempt/generation and event.
Public errors expose only the closed reason.

## 8. Attempts and readback

### 8.1 `AuthorityAttemptV1`

Every mutating request has a random domain-separated attempt ID unrelated to
the signed object ID. `input_graph_digest` is
`lowercase_hex(SHA-256(operation_domain || JCS(closed_idempotency_preimage)))`.
The closed preimage is frozen before signing and excludes the attempt ID, generated
object IDs, generated issue times/nonces, signatures and all other candidate-only
values. Its exact leaves are:

| Operation | Closed stable idempotency leaves |
|---|---|
| root issue | exact request-grant wire digest; task/workload/audience; requested authority bounds; scope/policy/catalogue/workload/trust observation digests and generations; caller deadline |
| child delegation | exact parent/source digests; task/workload/audience; requested restrictive authority; current ancestor/allocation/counter/trust observation digests and generations; caller deadline |
| counter consumption | exact lease/ancestor projection digest; counter kind; amount; context digest; current counter generation; caller deadline |
| terminal decision | exact plan-envelope digest; grant/ancestor/lease projection digests; requested terminal value; authentication profile/evidence digest; current policy/catalogue/trust observations; caller deadline |
| key status or revocation | exact subject/purpose/current-generation binding; requested status/reason/effective-time binding; caller deadline |
| bootstrap, backup or restore | exact source/root/schema/package/configuration digests; requested lifecycle/epoch transition; caller deadline |

The exact `operation_domain` bytes are respectively
`HELIXOS\0TASK-AUTHORITY-ROOT-ISSUE\0V1\0`,
`HELIXOS\0TASK-AUTHORITY-CHILD-DELEGATION\0V1\0`,
`HELIXOS\0TASK-AUTHORITY-COUNTER-CONSUMPTION\0V1\0`,
`HELIXOS\0TASK-AUTHORITY-TERMINAL-DECISION\0V1\0`,
`HELIXOS\0TASK-AUTHORITY-KEY-STATUS\0V1\0`,
`HELIXOS\0TASK-AUTHORITY-REVOCATION\0V1\0`,
`HELIXOS\0TASK-AUTHORITY-BOOTSTRAP\0V1\0`,
`HELIXOS\0TASK-AUTHORITY-BACKUP\0V1\0` and
`HELIXOS\0TASK-AUTHORITY-RESTORE\0V1\0`; operation-kind mismatch changes the
digest and cannot alias another namespace.

The retained `AuthorityAttemptV1` row binds the operation kind, canonical one-shot
`namespace_digest`, `input_graph_digest`, caller deadline, outcome binding digest,
outcome code and creation generation to the same atomic event graph. A retry
recomputes the stable
preimage before any new signature. Equal namespace plus equal input digest returns
the already-retained graph without inserting a new attempt; it deliberately ignores
the losing candidate's generated fields. Equal namespace plus a different digest
retains one conflict attempt/tombstone. An attempt never authorizes a retry.

### 8.2 `AuthorityMutationOutcomeV1`

Closed outcome families:

- `COMMITTED_RETAINED`: complete exact graph exists; return retained evidence.
- `DENIED_DEFINITE`: validation failed before mutation or rollback is confirmed.
- `CONFLICT_RETAINED`: namespace exists with a different exact binding.
- `UNCERTAIN_READBACK_REQUIRED`: commit acknowledgement is uncertain; no retry.
- `AMBIGUOUS_RECONCILIATION_REQUIRED`: fresh readback cannot prove complete
  graph, conflict or healthy absence.
- `UNAVAILABLE`: store/control/deadline unavailable before mutation.

No public outcome embeds a native database/path/provider error.

### 8.3 `AuthorityReadbackV1`

At most one fresh readback is automatic after explicit uncertainty. It abandons
the original connection, opens/verifies a new exact schema/root view, and checks
the attempt plus every member of its atomic graph.

| Observation | Classification |
|---|---|
| Complete graph, exact bindings, valid invariants | `COMMITTED_RETAINED` |
| Same namespace, different retained binding | `CONFLICT_RETAINED` |
| Healthy schema and absence of all graph keys | `DENIED_DEFINITE` / definite absence |
| Partial graph, corrupt invariant, deadline or read failure | `AMBIGUOUS_RECONCILIATION_REQUIRED` |

Later explicit status lookup is a new observation, not another automatic attempt.

## 9. Current projections

### 9.1 `CurrentAuthorityProjectionV1`

Non-wire value available only from a verified store snapshot:

- source grant protected digest and current generation;
- leaf lease protected digest and current generation;
- ordered ancestor digest vector and its aggregate digest;
- plan-bound lease projection/decision digest;
- approval protected decision digest and authorization generation;
- trust and revocation digests/generations;
- task, workload, plan, operation, nonce and request-source bindings;
- policy/catalogue/scope generations;
- boot/instance/fencing bindings;
- earliest exclusive UTC and monotonic deadlines;
- current/exhaustion/terminal flags represented by closed internal enums.

Construction verifies exact signed bytes, current keys, source/ancestor
relationships, allocation/counter state, terminal decision, plan target,
revocation and time. It is not `Serialize`, not `Clone` across custody, and its
`Debug` output is redacted.

### 9.2 `CurrentLeaseProjectionV1`

Closed subview used for PLAN-002/004/005:

- `lease_digest` = SHA-256 of canonical `TaskLeaseV1.protected`;
- `lease_generation` = current authority-store lease generation;
- `request_source_kind` = `human_request_grant`;
- `request_source_digest` = SHA-256 of canonical
  `HumanRequestGrantV1.protected`;
- plan-specific `lease_decision_digest`, separate from the protected lease
  digest;
- exact task/workload/plan/deadline/boot/ancestor/revocation bindings.

### 9.3 `CurrentAuthorizationProjectionV1`

Closed subview used for PLAN-002/004/005:

- positive status only for exact current `APPROVED`;
- `evidence_digest` = SHA-256 of canonical
  `ApprovalDecisionV1.protected`;
- current authorization generation;
- exact plan ID/envelope digest, operation, nonce, task/workload, grant/lease,
  risk/evidence-profile, deadline and revocation bindings.

### 9.4 `AuthorityProjectionGuardV1`

Non-cloneable RAII custody over one authority-store `BEGIN IMMEDIATE`
transaction and one verified projection snapshot. It is acquired once at the
existing Lease guard slot; Authorization validation is performed inside the same
transaction at the next logical slot. It remains held through final PLAN-002
claim, PLAN-004 preparation commit or PLAN-005 dispatch commit. It is released only
after the existing commit API classifies the attempt as committed, prior-exact,
confirmed rollback or uncertain and, for uncertainty, transfers a non-authority
readback-custody token. PLAN-004/005 may then perform their existing readback before
forming the user-visible terminal result; readback does not retain or reacquire the
HLXA guard.

Global lock rules:

1. Existing supervisor/trust/workload guards that precede Lease retain their
   current order.
2. Acquire the unified PLAN-006 authority guard at Lease.
3. Validate authorization inside it at Authorization; do not start another
   SQLite writer transaction.
4. Acquire later existing guards in their reviewed order.
5. Start and finish the existing replay/coordinator transaction only after the
   authority guard.
6. No PLAN-006 mutation/maintenance path may take coordinator/replay custody and
   then request the authority writer.
7. Mutation and maintenance paths acquire every required external clock,
   supervisor, signer-trust, workload, scope, policy and catalogue guard in this
   same prefix order before HLXA, then pass immutable observations inward. No code
   holding HLXA may call a provider or acquire a guard from an earlier slot.
8. Release in reverse order after commit classification/custody transfer and before
   returning a user-visible terminal result.

Revocation/trust/usage writers either commit before guard acquisition and are
observed, or wait until the downstream commit is terminal. Time can still pass,
so the downstream permit and transaction must stop strictly before the captured
earliest deadline.

## 10. Atomic durable graphs

### 10.1 Root issuance

One `BEGIN IMMEDIATE` makes visible together:

1. exact verified grant record;
2. one issuer-scoped grant claim;
3. exact signed root lease record;
4. initial lease usage;
5. attempt and generation changes;
6. redacted transition event.

All current trust, scope template, policy/catalogue, time and uniqueness facts are
rechecked after acquiring the writer. Any signing failure occurs before the
writer and creates no claim.

### 10.2 Delegation

One transaction makes visible together:

1. current source grant, parent and complete ancestor recheck;
2. exact aggregate sibling arithmetic;
3. parent-child allocation;
4. exact signed child lease;
5. child usage and increased parent summary;
6. attempt, generation changes and event.

There is no allocation without child and no child without allocation.

### 10.3 Counter consumption

One transaction makes visible together the unique consumption tombstone, checked
monotonic usage increase, generation changes and event. Exact capacity is valid;
zero, overflow, over-limit and conflicting identity deny.

### 10.4 Terminal decision

One transaction makes visible together:

1. exact verified PLAN-001 binding;
2. current grant/lease/ancestor/trust/revocation/time recheck;
3. one terminal signed decision;
4. target uniqueness and decision generation;
5. attempt and event.

There is no durable unsigned positive approval state.

### 10.5 Trust or revocation

One transaction appends the status/revocation fact, advances the exact subject
and global generations, and appends its event. Descendant projections become
non-current by resolution; signed rows remain unchanged.

## 11. State derivation

### 11.1 Authority root lifecycle

```text
ABSENT
  -> STAGED                 # explicit PAUSED bootstrap/restore only
  -> ACTIVE                 # new empty bootstrap, publish last

ABSENT
  -> STAGED_RESTORE
  -> RESTORE_PENDING        # validated clean-root restore, PAUSED

RESTORE_PENDING
  -> ACTIVE                 # future explicit reconciliation feature only
```

PLAN-006 defines no automatic `RESTORE_PENDING -> ACTIVE` transition.

### 11.2 Grant lifecycle

```text
VERIFIED_CURRENT -> CLAIMED_ROOT_ISSUED
VERIFIED_CURRENT -> DENIED_NO_MUTATION
CLAIMED_ROOT_ISSUED -> HISTORICAL_NON_CURRENT  # expiry/revocation/reboot
```

The store does not retain a reusable unclaimed authority pool. A grant is
verified and claimed in the root-issuance graph.

### 11.3 Lease current state

`CURRENT`, `EXHAUSTED`, `EXPIRED`, `REVOKED`, `ANCESTOR_NON_CURRENT`,
`BOOT_MISMATCH`, `INSTANCE_MISMATCH`, `CONFLICT` and `HISTORICAL_ONLY` are derived
closed results, not mutable signed status fields. A lease can only move from
current to non-current; V1 has no renew/reactivate transition.

### 11.4 Decision current state

The signed terminal value is immutable `APPROVED` or `DENIED`. Projection state
is derived as `CURRENT_APPROVED`, `CURRENT_DENIED`, `EXPIRED`, `REVOKED`,
`CHAIN_NON_CURRENT`, `BOOT_MISMATCH`, `WEAK_EVIDENCE` or `HISTORICAL_ONLY`.
Only `CURRENT_APPROVED` is positive.

## 12. Bootstrap migration

### 12.1 `AuthorityBootstrapReceiptV1`

Permanent receipt in the new authority root:

- bootstrap attempt/staging identity;
- exact source commit/tree, coordinator `HLXC` application ID, V2 schema/root
  identity and verified source backup digest/summary;
- target `HLXA` root identity, schema digest and durability profile;
- explicit imported-authority counts, each exactly zero;
- tool/version/provenance digest, trusted time and migration generation;
- publication result and manifest binding.

### 12.2 Procedure

1. Enter PAUSE and prove source quiescence.
2. Verify the exact coordinator V2 root and produce a fresh verified backup.
3. Reserve an approved empty destination and unique staging identity.
4. Create all strict `HLXA` V1 objects and metadata in staging.
5. Insert the bootstrap receipt with zero migrated grants, leases and decisions.
6. Validate schema, root, durability and cross-record invariants from a fresh
   connection.
7. Publish the complete authority root last.
8. If acknowledgement is uncertain, classify the same staging/publication
   identity by one fresh readback; never create a second root.

Ordinary open never performs these steps. A partial, wrong-source, corrupt,
newer, downgrade or already-owned destination fails closed. Legacy/synthetic
PLAN-002/004/005 rows remain outside the authority database and non-current.

## 13. Backup and clean restore

### 13.1 `TaskAuthorityBackupManifestV1`

Published-last canonical maintenance-evidence envelope. Its protected object is
signed by the distinct `backup-provisioner-signing` purpose over
`HELIXOS\0TASK-AUTHORITY-BACKUP\0V1\0 || JCS(protected)`; this signature can
authenticate a recovery package but cannot create task authority. The manifest
contains:

- schema/version, package ID and exact source commit/tree;
- PAUSE/quiescence proof and custody order;
- authority database application/schema/root/checkpoint/generation/count digest;
- exact coordinator/replay/dispatch components required to interpret bound plans,
  each with its own application/schema/root/checkpoint digest;
- public verification-key inventory and current/historical status digest;
- bootstrap receipt and migration generation;
- member path aliases, byte sizes and SHA-256 digests using portable relative
  names only;
- restore policy, required new epochs and zero-reactivation assertion;
- provenance/attestation reference and manifest digest.

Verification MUST resolve the manifest `key_id` through an externally provisioned
`backup-provisioner-signing` trust anchor and current/historical status resolver.
The backup provisioner's public verification history retained in the package MUST
byte-match that external resolver and is only an evidence copy; it is never accepted
as its own trust source. No private key, native absolute path or secret enters the
package/manifest.

### 13.2 Backup cut

PAUSE acquires custody in one fixed order, verifies no in-flight PLAN-006 writer,
captures independent coherent online backups, rechecks every generation/root
after backup, writes members into staging, writes the canonical manifest last,
and atomically publishes the package. A changed source generation makes the cut
invalid; there is no partial-success manifest.

### 13.3 Restore

Restore accepts only a complete manifest-bound package and approved empty roots.
It validates every member before publication, rotates root/boot/instance/fencing
identities, records restore evidence, and publishes the authority root as
`RESTORE_PENDING` while the system remains PAUSED. Exact signed bytes and public
keys remain historical evidence. All restored nonterminal leases and approvals
are non-current, counters/tombstones remain retained, and there is no automatic
reissue, redelivery, decision, projection or dispatch.

## 14. Validation invariants

Open, readback, backup and restore verify at least:

- exact application ID, schema version/digest and normalized SQL;
- required WAL/durability PRAGMAs and root identity;
- immutable signed bytes recanonicalize, redigest and reverify against retained
  public keys;
- indexed row bindings exactly equal signed content;
- grant claim has exactly one source grant and root lease;
- every root has one claim; every child has one parent allocation;
- parent graphs are acyclic, depth-bounded and source/task/workload coherent;
- allocations and counter summaries equal append-only facts with checked
  arithmetic and never exceed signed limits;
- each terminal target has exactly one immutable decision;
- every revocation/status event has monotonic unique generations;
- every current projection references complete current trust/ancestor/decision
  evidence and exact deadlines;
- every attempt graph is complete or classified ambiguous, never partially
  authoritative;
- event, conflict, migration and restore references are complete;
- no delete/reuse/reset/downgrade path exists;
- root lifecycle permits no admission while `RESTORE_PENDING`.

Any failure is a closed admission error with no repair and no positive projection.

## 15. Data classification, retention and redaction

| Data | Classification | V1 retention | Public exposure |
|---|---|---|---|
| Exact signed grant/lease/decision/plan evidence | Restricted security data | Permanent | Never; closed result only |
| Protected digests, IDs, roots, generations | Restricted correlation data | Permanent | Redacted/pseudonymous bounded reference only |
| Public verification keys and fingerprints | Security metadata | Permanent | Evidence inventory may expose synthetic/release-approved public values only |
| Claims, allocations, counters, decisions, revocations, conflicts | Restricted authority history | Permanent | Closed event/reason only |
| Raw message/assertion/bearer/private key/native path | Prohibited | Never stored | Never |
| Fixtures | Synthetic public conformance data | Versioned | Allowed after secret/path scans |

Version 1 has no pruning, compaction that drops authority facts, secure-erasure or
cryptographic-erasure claim. Backups exclude private keys and use portable member
aliases. Debug implementations redact values; public errors and metrics are
closed, bounded and payload-free.

## 16. Portability and compatibility

- Contract values use UTF-8 NFC strings with explicit byte/code-point limits,
  safe bounded integers, fixed lowercase-hex digests and canonical base64url.
- No native path, file handle, socket, float, ambient clock or platform enum is a
  signed authority value.
- V1 rejects V2 fields/schema/domain. A future implementation may retain an
  explicit N-1 verifier, but it never rewrites/re-signs/reinterprets old bytes.
- PLAN-001 through PLAN-005 signed bytes and semantics remain unchanged.
- The exact same PLAN-006 fixtures and expected outcomes run on all three target
  OS families. Platform incapability is a closed refusal, not a semantic fallback.
