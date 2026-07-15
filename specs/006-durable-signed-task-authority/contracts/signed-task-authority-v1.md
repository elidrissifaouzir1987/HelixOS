# Durable Signed Task Authority Wire Contracts v1

This document freezes the complete PLAN-006 version 1 wire and compatibility profile
for `HumanRequestGrantV1`, `TaskLeaseV1` and `ApprovalDecisionV1`. The normative
structural schemas are:

- [`human-request-grant-v1.schema.json`](human-request-grant-v1.schema.json)
- [`task-lease-v1.schema.json`](task-lease-v1.schema.json)
- [`approval-decision-v1.schema.json`](approval-decision-v1.schema.json)

A field not listed in the corresponding schema does not exist in v1. The schemas are
necessary interoperability artifacts; the strict typed decoder, semantic validation,
current trust resolution and durable authority store remain authoritative for rules
that JSON Schema cannot express.

## 1. Common wire profile

### 1.1 Encoding and primitive domains

- Each wire is exactly one RFC 8785 canonical JSON value encoded as UTF-8, with no BOM,
  leading or trailing whitespace, trailing newline or trailing bytes.
- Duplicate member names, unknown member names, non-canonical encodings, unsupported
  profiles and missing required members deny before any positive authority exists.
- `HumanRequestGrantV1` and `ApprovalDecisionV1` wires are at most 65,536 bytes.
  `TaskLeaseV1` is at most 1,048,576 bytes because it may carry bounded resource and
  catalogue arrays.
- A `safeInteger` is a JSON integer in `0..=9,007,199,254,740,991`. A `generation` is a
  `safeInteger` in `1..=9,007,199,254,740,991`. Fractional, exponent and negative forms
  are not alternate encodings of authority integers.
- A `digest` is exactly 32 bytes encoded as 64 lowercase hexadecimal characters.
  Every grant, lease, allocation and decision identity defined as a digest uses this
  representation. Uppercase, prefix and shortened forms deny.
- `plan_nonce` is the exact PLAN-001 16-byte nonce encoded as 32 lowercase hexadecimal
  characters.
- An `identifier` is 1–128 ASCII bytes from `[-A-Za-z0-9._:]`. It is an opaque
  correlation value, never user text, a credential, bearer link, authentication
  assertion, secret or native path.
- An Ed25519 signature is exactly 64 bytes encoded as canonical unpadded base64url:
  exactly 86 characters and a final character in `A`, `Q`, `g` or `w`. Padding,
  standard-base64 characters, whitespace and non-canonical trailing bits deny.
- A resource root uses a 1–64 byte lowercase ASCII `root_id` followed by zero to 128
  decoded NFC relative components. Each component is 1–255 UTF-8 bytes; combined
  component bytes per root are at most 4,096. Empty component arrays mean the approved
  opaque root. Components deny dot/traversal, separators, NUL/control/default-ignorable
  characters, colon/ADS, trailing dot/space and Windows device basenames. They are
  never OS-native paths.
- Arrays whose semantic meaning is a set have no alternate ordering: catalogue entry
  identifiers use ascending ASCII-byte order; intentions use their frozen schema order;
  resource roots use ascending byte order of each element's canonical JCS bytes.
  Duplicate members deny.
- Raw request messages, authentication assertions, bearer tokens, private keys, native
  paths and unrestricted payloads are absent from all three wires.

### 1.2 Protected digest, envelope and signature

Every protected object contains the exact constants `schema`, `digest_algorithm`,
`signature_algorithm`, `key_purpose` and `key_id`. There are no implicit defaults.

For each contract:

```text
protected_jcs  = JCS(protected)
object_digest = lowercase_hex(SHA-256(protected_jcs))
signature     = Ed25519.sign(purpose_key(key_id), domain || protected_jcs)
```

This is pure Ed25519, not Ed25519ph. The signature covers the domain and canonical
protected bytes directly, not the digest text and not the outer envelope.

| Rust value | Protected `schema` | Outer digest member | Exact key purpose | Exact signature-domain bytes |
|---|---|---|---|---|
| `HumanRequestGrantV1` | `helixos.human-request-grant/1` | `grant_digest` | `request-surface-grant-signing` | `HELIXOS\0HUMAN-REQUEST-GRANT\0V1\0` |
| `TaskLeaseV1` | `helixos.task-lease/1` | `lease_digest` | `core-task-lease-signing` | `HELIXOS\0TASK-LEASE\0V1\0` |
| `ApprovalDecisionV1` | `helixos.approval-decision/1` | `decision_digest` | `core-approval-decision-signing` | `HELIXOS\0APPROVAL-DECISION\0V1\0` |

Each outer envelope contains exactly three required, non-null members:

```json
{
  "protected": {},
  "<object>_digest": "<64 lowercase hexadecimal characters>",
  "signature": "<canonical Ed25519 base64url without padding>"
}
```

The explanatory member order above is not a wire-order exception; the complete outer
object must already be RFC 8785 canonical JSON.

### 1.3 Verification order and typed trust transitions

Verification uses this fixed order:

1. Enforce the contract-specific raw byte limit and reject a BOM or trailing bytes.
2. Parse one JSON value while detecting duplicate members.
3. Re-canonicalize and require byte equality with the supplied wire.
4. Require the exact closed outer and protected member inventories.
5. Reject unsupported schema, digest algorithm, signature algorithm, key purpose and
   closed enum values.
6. Decode closed typed values and validate bounds and all contract-local relations.
7. Recompute protected JCS and the outer digest; require exact equality.
8. Validate the signature encoding before calling a key resolver.
9. Resolve `key_id` through the contract-specific purpose resolver and apply trust and
   revocation policy.
10. Perform strict Ed25519 verification over the exact domain and protected JCS.

Cryptographic authenticity alone is not current authority. A distinct non-constructible
type represents authentic retained evidence. Only a second current-resolution step may
produce current grant, lease or positive authorization authority after checking durable
one-shot state, current trust/revocation, time, source, ancestor, policy, catalogue,
clock and epoch state. Public errors and `Debug` output expose only closed payload-free
codes.

## 2. Human request grant

Media type: `application/vnd.helixos.human-request-grant+json;version=1`.

### 2.1 Complete protected payload

All fields are required and non-null.

| Group | Field | Domain and meaning |
|---|---|---|
| profile | `schema` | exact `helixos.human-request-grant/1` |
| profile | `digest_algorithm` | exact `sha-256` |
| profile | `signature_algorithm` | exact `ed25519` |
| profile | `key_purpose` | exact `request-surface-grant-signing` |
| profile | `key_id` | identifier; request-surface grant-key lookup only |
| one-shot | `grant_id` | 32-byte create-only identity, independent of key identity |
| origin | `issuer_id` | configured request-surface issuer identifier |
| origin | `audience` | exact intended core/audience identifier |
| origin | `principal_id` | authenticated human principal identifier |
| request | `message_digest` | SHA-256 of the exact authenticated request message |
| request | `channel_id` | exact authenticated ingress channel identifier |
| request | `session_id` | exact authenticated session identifier |
| scope | `scope_template_id` | immutable trusted scope-template identifier |
| scope | `scope_template_digest` | exact current template-content digest |
| scope | `scope_template_generation` | exact current template generation |
| time | `issued_at_utc_ms` | trusted issuance UTC sample |
| time | `expires_at_utc_ms` | exclusive UTC expiry |

### 2.2 Grant invariants

- `issued_at_utc_ms < expires_at_utc_ms`; equality with the expiry is expired.
- The issuer, audience, principal, message, channel, session and scope-template triple
  must equal independently authenticated current context. Transport identity, chat
  text, a notification and a bearer link never substitute for these checks.
- The resolver accepts only the configured request-surface grant purpose. A lease,
  approval, plan, dispatch or receipt key cannot verify this profile.
- Current consumption requires the exact current immutable key ID, trust and
  revocation state and the exact current scope-template generation/digest. Rotation
  receives a new key ID; key IDs are never reassigned.
- The durable uniqueness namespace is `(issuer_id, grant_id)`, independent of `key_id`
  and independent of PLAN-003's plan replay namespace.
- Grant consumption and root-lease issuance commit atomically. The first valid use
  retains one exact root lease wire. An exact retry returns that retained wire;
  conflicting reuse authorizes nothing.
- Historical key verification may prove retained bytes were signed, but never makes an
  unconsumed or no-longer-current grant consumable.

## 3. Task lease

Media type: `application/vnd.helixos.task-lease+json;version=1`.

### 3.1 Complete protected payload

Every field is required. The three parent fields are explicitly `null` for a root
lease and non-null digests for a delegated child; omission is never equivalent to
`null`.

| Group | Field | Domain and meaning |
|---|---|---|
| profile | `schema` | exact `helixos.task-lease/1` |
| profile | `digest_algorithm` | exact `sha-256` |
| profile | `signature_algorithm` | exact `ed25519` |
| profile | `key_purpose` | exact `core-task-lease-signing` |
| profile | `key_id` | identifier; core lease-key lookup only |
| identity | `lease_id` | 32-byte create-only lease identity |
| identity | `issuer_id` | configured core lease issuer; durable namespace with `lease_id` |
| subject | `task_id` | exact task identifier |
| subject | `workload_id` | exact workload identity receiving this lease |
| subject | `audience` | exact lease audience |
| source | `source_kind` | exact `HUMAN_REQUEST_GRANT` in v1 |
| source | `source_grant_id` | exact source `HumanRequestGrantV1.grant_id` |
| source | `source_grant_digest` | exact SHA-256 of source grant protected JCS |
| source | `source_principal_id` | exact source human principal identifier |
| authority | `allowed_intentions` | canonical set; v1 contains exactly `host.file.patch` |
| authority | `resource_roots` | 1–128 canonical opaque root/prefix bounds |
| authority | `budget` | complete bounded budget object below |
| authority | `counter_limits` | complete durable counter-limit object below |
| authority | `trust_bound` | complete risk/authentication/policy bound below |
| authority | `catalogue_bound` | complete catalogue bound below |
| delegation | `delegation_mode` | closed `DELEGABLE` or `NON_DELEGABLE` |
| delegation | `parent_lease_id` | root: `null`; child: exact parent lease ID |
| delegation | `parent_lease_digest` | root: `null`; child: exact parent protected digest |
| delegation | `parent_allocation_id` | root: `null`; child: exact atomic allocation ID |
| delegation | `delegation_depth` | root: `0`; child: `1..=32` |
| time/fence | `clock_generation` | generation shared by trusted UTC/monotonic capture |
| time/fence | `boot_id` | exact monotonic-clock boot domain |
| time/fence | `instance_epoch` | safe integer for the issuing core instance |
| time/fence | `issued_at_utc_ms` | trusted issuance UTC sample |
| time/fence | `not_before_utc_ms` | inclusive UTC lower bound |
| time/fence | `expires_at_utc_ms` | exclusive UTC upper bound |
| time/fence | `issued_at_monotonic_ms` | trusted same-boot issuance sample |
| time/fence | `deadline_monotonic_ms` | exclusive same-boot deadline |

The closed `budget` object contains exactly:

| Field | Domain |
|---|---|
| `read_bytes_limit` | safe integer |
| `distinct_files_limit` | safe integer |
| `action_limit` | safe integer |
| `egress_bytes_limit` | safe integer |
| `currency_code` | exactly three uppercase ASCII letters |
| `max_cost_micro_units` | safe integer |
| `price_table_id` | identifier |

The closed `counter_limits` object contains exactly:

| Field | Domain |
|---|---|
| `plan_limit` | safe integer |
| `approval_limit` | safe integer |
| `child_lease_limit` | safe integer |
| `max_delegation_depth` | integer `0..=32` |

The closed `trust_bound` object contains exactly:

| Field | Domain |
|---|---|
| `maximum_risk_level` | closed `L0`, `L1` or `L2` |
| `minimum_authentication_profile` | `SESSION_AUTHENTICATED_V1` or `USER_VERIFICATION_V1` |
| `policy_id` | identifier |
| `policy_content_digest` | digest |
| `policy_generation` | generation |

The closed `catalogue_bound` object contains exactly:

| Field | Domain |
|---|---|
| `catalogue_id` | identifier |
| `catalogue_content_digest` | digest |
| `catalogue_generation` | generation |
| `allowed_catalogue_entries` | 1–256 unique canonical identifiers |

### 3.2 Root and delegation invariants

- Only the core lease signer may issue a v1 lease. A root lease requires the exact
  atomically consumed current human grant. Unsigned, synthetic, legacy or caller-built
  state cannot satisfy the source.
- For a root lease, `parent_lease_id`, `parent_lease_digest` and
  `parent_allocation_id` are all explicit `null`, and `delegation_depth` is exactly `0`.
  For a child, all three are non-null and depth is exactly parent depth plus one.
- `issued_at_utc_ms <= not_before_utc_ms < expires_at_utc_ms` and
  `issued_at_monotonic_ms < deadline_monotonic_ms`. Equality with either exclusive
  boundary denies. A lease is current only in its exact `boot_id` and `instance_epoch`.
- Root authority is no wider than the exact source scope template and current
  policy/catalogue constraints. Its expiry is no later than the source grant expiry.
- A child retains the exact task and source grant chain. Its intentions and catalogue
  entries are subsets; every resource root is equal to or below a parent prefix; every
  numeric budget and counter limit is at most the parent allocation; currency and price
  table remain exact; maximum risk does not increase; minimum authentication cannot
  weaken; policy and catalogue identity/content/generation remain exact; expiry and
  monotonic deadline do not increase.
- A child requires `DELEGABLE` parent authority and depth no greater than both the
  parent's and child's `max_delegation_depth`. `NON_DELEGABLE` or a zero maximum depth
  cannot produce a child.
- Parent allocation, all changed counters, child signed bytes, authority generation and
  event commit atomically. Across siblings, aggregate allocations on every governed
  axis are at most the parent's remaining limit. An exact limit is accepted; one unit
  over, underflow and overflow deny with no partial allocation.
- A child workload must independently resolve as current and trusted under the exact
  parent trust/policy/catalogue constraints. A new workload identity is not evidence of
  broader authority.
- Lease IDs and parent allocation IDs are create-only and independent of signing keys.
  Exact retry returns retained bytes. Conflicting reuse, renewal, release, widening,
  union of prior leases and counter reset are unavailable in v1.
- Grant, ancestor or signer revocation, expiry, exhaustion, boot change, instance
  change or corrupt/ambiguous ancestry makes the lease non-current without rewriting
  retained signed bytes.

### 3.3 Existing PLAN-001 binding

PLAN-001 bytes remain unchanged. For a plan sourced from this authority chain:

```text
PlanProtectedV1.task_lease_digest
  = SHA-256(JCS(TaskLeaseV1.protected))

PlanProtectedV1.request_source.kind
  = "human_request_grant"

PlanProtectedV1.request_source.digest_sha256
  = SHA-256(JCS(HumanRequestGrantV1.protected))
```

No full signed envelope, native lease type or legacy kernel object substitutes for
these exact protected digests.

## 4. Approval decision

Media type: `application/vnd.helixos.approval-decision+json;version=1`.

### 4.1 Complete protected payload

All fields are required and non-null for both decisions. `APPROVED` and `DENIED` use
one identical shape; there is no omitted or default branch data.

| Group | Field | Domain and meaning |
|---|---|---|
| profile | `schema` | exact `helixos.approval-decision/1` |
| profile | `digest_algorithm` | exact `sha-256` |
| profile | `signature_algorithm` | exact `ed25519` |
| profile | `key_purpose` | exact `core-approval-decision-signing` |
| profile | `key_id` | identifier; core approval-decision key lookup only |
| terminal | `decision_id` | 32-byte create-only terminal identity |
| terminal | `issuer_id` | configured core decision issuer; durable namespace with `decision_id` |
| terminal | `decision` | closed `APPROVED` or `DENIED` |
| plan | `plan_id` | exact PLAN-001 protected-plan SHA-256 ID |
| plan | `plan_envelope_digest` | SHA-256 of exact canonical signed PLAN-001 envelope |
| plan | `operation_id` | exact PLAN-001 operation identifier |
| plan | `plan_nonce` | exact PLAN-001 16-byte nonce |
| subject | `task_id` | exact task identifier |
| subject | `workload_id` | exact workload identifier |
| request | `human_request_grant_id` | exact request grant ID |
| request | `human_request_grant_digest` | exact request protected digest |
| request | `grant_claim_generation` | exact durable consumed-grant generation |
| lease | `task_lease_id` | exact task lease ID |
| lease | `task_lease_digest` | exact task lease protected digest |
| lease | `lease_projection_generation` | exact current lease projection generation |
| risk | `risk_level` | closed `L0`, `L1` or `L2` |
| human | `principal_id` | exact request principal identifier |
| human | `session_id` | exact authenticated approval session identifier |
| evidence | `authentication_profile` | closed profile below |
| evidence | `authentication_evidence_digest` | digest of bounded evidence metadata |
| evidence | `authentication_evidence_generation` | exact evidence generation |
| policy | `policy_generation` | exact current generation |
| policy | `policy_content_digest` | exact current policy content digest |
| policy | `policy_decision_digest` | exact plan-bound policy decision digest |
| catalogue | `catalogue_generation` | exact current generation |
| catalogue | `catalogue_content_digest` | exact current catalogue content digest |
| catalogue | `catalogue_decision_digest` | exact plan-bound catalogue decision digest |
| time/fence | `clock_generation` | generation shared by trusted time samples |
| time/fence | `boot_id` | exact same-boot monotonic domain |
| time/fence | `instance_epoch` | exact core instance epoch |
| time/fence | `fencing_epoch` | exact current fencing epoch |
| time/fence | `issued_at_utc_ms` | trusted decision issue time |
| time/fence | `expires_at_utc_ms` | exclusive UTC expiry |
| time/fence | `issued_at_monotonic_ms` | trusted same-boot issue sample |
| time/fence | `deadline_monotonic_ms` | exclusive same-boot deadline |

The closed authentication profiles are:

- `SESSION_AUTHENTICATED_V1`: authenticated session evidence, eligible only where the
  exact current policy allows that profile.
- `USER_VERIFICATION_V1`: user-verification-capable evidence required for positive L2
  authority.
- `SYNTHETIC_CONFORMANCE_V1`: deterministic labelled test evidence. It can exercise
  canonical/signature/chain logic but never produces production positive authority.

`authentication_evidence_digest` covers bounded evidence metadata only. Raw WebAuthn
assertions, bearer material, cookies, challenges and credentials never enter the wire,
authority store, logs or release evidence.

### 4.2 Decision invariants

- The core signs only after independently authenticating the exact canonical PLAN-001
  envelope and resolving one exact current request-grant and lease chain. The approval
  surface supplies authenticated evidence; it does not receive core lease-signing or
  decision-signing authority.
- `plan_envelope_digest` is SHA-256 of the exact canonical signed PLAN-001 envelope.
  It supplements the stable protected `plan_id` without changing PLAN-001 bytes.
- Plan ID/envelope, operation, nonce, task, workload, grant ID/digest/generation, lease
  ID/digest/generation, principal/session, risk, evidence, policy/catalogue and epochs
  must equal the independently reloaded current chain.
- `issued_at_utc_ms < expires_at_utc_ms` and
  `issued_at_monotonic_ms < deadline_monotonic_ms`. UTC expiry is no later than the
  exact plan, lease and source-grant UTC bounds; the monotonic deadline is no later than
  the plan and lease same-boot bounds. Equality with any exclusive boundary denies, and
  current UTC validation independently enforces source-grant expiry.
- `DENIED` is retained terminal evidence and never yields positive authorization.
  Only a current `APPROVED` record may produce a positive projection.
- A positive `APPROVED` L2 decision requires `USER_VERIFICATION_V1`.
  `SYNTHETIC_CONFORMANCE_V1` never satisfies a production projection at any risk level.
- The durable uniqueness namespace is `decision_id`, independent of `key_id` and
  independent of PLAN-003 replay. Approve/deny races commit one exact terminal signed
  wire, generation and event. Exact retry returns those retained bytes; a different
  terminal value or any changed binding is a conflict and cannot flip the result.
- Current positive authority requires current signer trust, non-revoked grant/lease/
  ancestors/decision, current policy/catalogue/evidence state and matching boot,
  instance and fencing epochs. Revocation invalidates the current projection without
  rewriting signed bytes and does not claim to undo an already possible downstream
  effect.
- The positive PLAN-002 authorization evidence digest is the exact
  `decision_digest = SHA-256(JCS(ApprovalDecisionV1.protected))`. Its current generation
  and revocation bindings come only from verified durable state, never from caller rows
  or booleans.

## 5. Key lifecycle, retention and redaction

- The three private signing authorities are distinct. Private keys never enter signed
  wires, SQLite rows, backups, manifests, fixtures, diagnostics, Graphify memory or
  release evidence.
- A key ID is immutable. Rotation creates a new ID. The durable store retains exact
  purpose, algorithm, public-key fingerprint and public verification material needed
  for historical verification.
- Purpose-specific signer and resolver traits prevent a request, lease or decision key
  from being selected through another contract's API. Distinct signature domains still
  prevent cross-contract substitution if key bytes are accidentally duplicated.
- Retained signed bytes are never resigned. Historical verification proves only the
  original cryptographic record. It does not revive a grant, lease or approval.
- Grant, lease, decision, allocation, claim, revocation, generation and public-key
  history are retained in v1. No prune, compact, delete-history, secure-erasure or
  private-key-backup surface exists.
- Canonical wires and internal identifiers/digests are restricted sovereign data.
  Public errors, logs, events, metrics and evidence expose only closed reason/status,
  bounded counts and latency classes. They never echo protected bytes, identifiers,
  digests, resource roots, evidence metadata, key material or provider diagnostics.

## 6. Compatibility

- V1 consumers accept exactly the three schema strings, `sha-256`, `ed25519`, exact
  purposes and closed values defined here. Unknown versions, fields, algorithms,
  purposes, intentions and enum variants deny rather than being ignored or downgraded.
- No v1 field is optional through a default. Explicit `null` exists only for the three
  root-lease parent fields. Adding, removing, renaming, defaulting or changing the
  semantics of a protected field is a new contract version.
- A future V2 uses a new protected schema, schema file, signature domain, fixtures and
  explicit decoder. A V1 consumer rejects V2. An N implementation may retain an
  isolated N-1 historical verifier, but never silently upgrades, rewrites or re-signs
  N-1 bytes and never treats historical validity alone as current authority.
- Existing PLAN-001 through PLAN-005 wire bytes and schemas remain authoritative and
  byte-compatible. PLAN-006 adds only exact digest/projection bindings through their
  existing seams; it does not mutate plan wire, PLAN-003 replay, preparation or dispatch
  contracts.
- Existing unsigned, synthetic or legacy authority is not backfilled as signed v1
  authority. A new human grant, root/child lease as applicable, exact plan and terminal
  decision chain is required.
- JSON Schema references remain local. Runtime schema resolution, remote `$ref`, schema
  inference and generated defaults are outside v1. The Rust decoder and frozen
  language-neutral corpus must reproduce identical canonical protected/outer bytes,
  digests, signatures and closed outcomes on macOS arm64, Linux x86_64 and Windows x64.

## 7. Minimum conformance corpus

One unchanged language-neutral corpus must include at least these authentic signed
bases: one human grant, one root lease, one delegated child lease, one approved
decision and one denied decision. It must retain only synthetic public keys and fixed
signatures, never private signing material.

The closed case inventory covers:

- every protected leaf removal and mutation, every outer member and all null branches;
- duplicate, missing, unknown, non-canonical, malformed and oversized wire;
- digest, signature, signature-domain, key-purpose, key rotation, revocation and
  current-versus-historical behavior;
- grant context mismatch, issuer-scoped one-shot exact retry and conflicting reuse;
- root/child shapes, every single-axis one-unit widening, resource/catalogue subset,
  counter/budget overflow and concurrent sibling oversubscription;
- exact UTC/monotonic boundaries, clock/boot/instance/fencing changes and reboot;
- approved/denied terminal races, every plan/grant/lease/session/risk/evidence/policy/
  catalogue mutation and L2 evidence profiles;
- labelled synthetic evidence that remains non-production;
- raw message, authentication assertion, credential, secret-like identifier, digest
  and native-path sentinels proving public redaction; and
- N/N-1 historical verification rules without authority revival.

Every stable case ID maps exactly once to a closed result, stage, reason and authority
class. Tests assert complete schema-leaf coverage, fixture/outcome bijection and exact
canonical bytes rather than parsed semantic equality.
