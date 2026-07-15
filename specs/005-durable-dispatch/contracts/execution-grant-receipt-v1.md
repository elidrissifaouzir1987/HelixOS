# Execution Grant and Receipt Wire Contracts v1

This document freezes the complete v1 wire vocabulary. The normative structural
schemas are
[`execution-grant-v1.schema.json`](execution-grant-v1.schema.json) and
[`execution-receipt-v1.schema.json`](execution-receipt-v1.schema.json). A field not
listed in those schemas does not exist in v1.

## 1. Encoding, primitive domains and limits

- The wire is one RFC 8785 canonical JSON value encoded as UTF-8, with no BOM,
  leading/trailing whitespace or trailing bytes. Duplicate object names, unknown
  names and non-canonical encodings deny.
- Before parsing, the decoder rejects a grant longer than 1,048,576 bytes and a
  receipt longer than 65,536 bytes.
- `safeInteger` is a JSON integer in `0..=9007199254740991`. A generation is a
  `safeInteger` in `1..=9007199254740991`. Negative, fractional and exponent
  alternatives deny.
- Every field ending in `_digest`, every plan/attempt/grant/receipt identity and the
  one-shot nonce is exactly 32 bytes encoded as 64 lowercase hexadecimal characters.
  Uppercase hexadecimal and prefixed forms deny.
- `identifier` is 1–128 UTF-8 bytes and contains only ASCII
  `[-A-Za-z0-9._:]`. `key_id` and `trace_id` use this same domain. Identifiers carry
  no user content, secret or native path.
- An Ed25519 signature is exactly 64 bytes encoded as canonical, unpadded base64url:
  86 characters, with the last character in `A`, `Q`, `g` or `w`. Padding, standard
  base64 `+`/`/`, whitespace and non-canonical final bits deny.
- `target` has the exact PLAN-001 `ResourceRefV1` shape. `root_id` is 1–64 lowercase
  ASCII characters, starts with `[a-z0-9]` and thereafter uses `[a-z0-9._-]`.
  `components` has 1–128 NFC strings; each is 1–255 UTF-8 bytes and their combined
  UTF-8 byte length is at most 4,096. Empty, `.`, `..`, separators, controls,
  default-ignorables, trailing space/dot, alternate data stream syntax and Windows
  device basenames deny. JSON Schema covers the portable structure; the decoder also
  enforces the UTF-8 aggregate, NFC, default-ignorable and device-name rules that JSON
  Schema cannot express.
- `content_media_type` is 3–127 ASCII bytes: one 1–63-character type, `/`, and one
  1–63-character subtype, each using `[A-Za-z0-9!#$&^_.+-]`. Parameters are forbidden.
- Schema validity is necessary but not sufficient. The relational/time/signature
  invariants below are mandatory decoder/verifier checks.

## 2. Execution grant

### 2.1 Cryptographic profile

| Property | Exact v1 value |
|---|---|
| protected `schema` | `helixos.execution-grant/1` |
| `digest_algorithm` | `sha-256` |
| `signature_algorithm` | `ed25519` |
| `key_purpose` | `coordinator-dispatch-signing` |
| signature domain bytes | `HELIXOS\0EXECUTION-GRANT\0V1\0` |
| maximum lifetime | 5,000 monotonic milliseconds, exclusive |

The signature input is the exact signature-domain bytes followed by the RFC 8785
canonical bytes of `protected`. `grant_digest` is SHA-256 of those canonical protected
bytes. Neither the digest text nor the outer envelope is part of the signature input.
The complete outer envelope is canonicalized separately and retained byte-for-byte.

### 2.2 Complete protected payload

All fields in this table are required. The protected object rejects additional
properties.

| Group | Exact field | Type/domain |
|---|---|---|
| profile | `schema` | exact profile constant above |
| profile | `digest_algorithm` | exact `sha-256` |
| profile | `signature_algorithm` | exact `ed25519` |
| profile | `key_purpose` | exact `coordinator-dispatch-signing` |
| profile | `key_id` | identifier; dispatch-signing public-key lookup only |
| one-shot | `grant_id` | 32-byte domain-separated random identity, lowercase hex |
| one-shot | `dispatch_attempt_id` | distinct 32-byte domain-separated random identity, lowercase hex |
| one-shot | `one_shot_nonce` | distinct 32-byte domain-separated random nonce, lowercase hex |
| operation | `operation_id` | identifier |
| operation | `operation_state_generation` | generation |
| operation | `preparation_attempt_id` | exact PLAN-004 32-byte attempt identity |
| operation | `preparation_transition_generation` | generation |
| operation | `plan_id` | exact PLAN-001 32-byte plan digest |
| subject | `task_id` | identifier |
| subject | `workload_id` | identifier |
| effect | `intent` | exact `host.file.patch` |
| effect | `target` | closed PLAN-001 `ResourceRefV1` object |
| effect | `precondition_digest` | 32-byte digest of the exact prepared precondition |
| effect | `content_digest` | 32-byte digest of the prepared replacement content |
| effect | `content_byte_length` | safeInteger |
| effect | `content_media_type` | bounded media type defined above |
| signer trust | `trust_generation` | generation |
| signer trust | `verified_key_fingerprint` | 32-byte digest of the authenticated plan key |
| workload | `workload_generation` | generation |
| workload | `workload_evidence_digest` | 32-byte digest |
| lease | `lease_generation` | generation |
| lease | `lease_digest` | 32-byte exact lease-content digest |
| lease | `lease_decision_digest` | 32-byte current lease-decision digest |
| authorization | `authorization_generation` | generation |
| authorization | `authorization_evidence_digest` | 32-byte digest |
| policy | `policy_generation` | generation |
| policy | `policy_decision_generation` | generation |
| policy | `policy_content_digest` | 32-byte digest |
| policy | `policy_decision_digest` | 32-byte digest |
| catalogue | `catalogue_generation` | generation |
| catalogue | `catalogue_decision_generation` | generation |
| catalogue | `catalogue_content_digest` | 32-byte digest |
| catalogue | `catalogue_decision_digest` | 32-byte digest |
| capability | `capability_report_generation` | generation |
| capability | `capability_report_digest` | 32-byte digest |
| capability | `host_driver_context_digest` | 32-byte digest |
| capability | `capability_observed_at_utc_ms` | safeInteger trusted UTC observation |
| capability | `capability_max_age_ms` | safeInteger maximum accepted age |
| capability | `adapter_capability_digest` | 32-byte destination capability digest |
| replay | `replay_claim_id` | exact 32-byte PLAN-003 claim identity |
| replay | `replay_claimant_generation` | generation |
| replay | `replay_binding_digest` | 32-byte digest |
| budget | `budget_scope_id` | identifier |
| budget | `budget_scope_generation` | generation |
| budget | `budget_scope_binding_digest` | 32-byte digest |
| budget | `reservation_id` | identifier |
| budget | `reservation_generation` | generation |
| budget | `reservation_binding_digest` | 32-byte digest |
| budget | `reservation_vector_digest` | 32-byte digest of the exact reserved vector |
| recovery | `recovery_reference_digest` | 32-byte digest of the exact retained recovery reference |
| recovery | `recovery_mode` | closed `COMPENSATION` or `IRREVERSIBLE` |
| recovery | `recovery_profile_digest` | 32-byte digest |
| recovery | `recovery_binding_digest` | 32-byte digest |
| recovery | `recovery_receipt_digest` | 32-byte digest of the retained PLAN-004 recovery/preparation receipt |
| destination | `destination_adapter_id` | identifier |
| destination | `protocol_version` | exact integer `1` |
| fencing | `boot_id` | identifier for the monotonic-clock boot domain |
| fencing | `instance_epoch` | safeInteger |
| fencing | `supervisor_epoch` | safeInteger |
| fencing | `supervisor_generation` | generation |
| time | `clock_generation` | generation |
| time | `issued_at_utc_ms` | safeInteger trusted UTC sample |
| time | `issued_at_monotonic_ms` | safeInteger trusted monotonic sample |
| time | `deadline_monotonic_ms` | generation-shaped positive safeInteger; exclusive |

No raw content bytes, raw secret, credential, unrestricted argument, native path or
adapter output is a grant field.

### 2.3 Closed outer envelope

The envelope has exactly three required properties and rejects all others:

| Field | Type/domain |
|---|---|
| `protected` | the complete closed payload in §2.2 |
| `grant_digest` | 64 lowercase hexadecimal characters; SHA-256 of canonical `protected` |
| `signature` | canonical unpadded 64-byte Ed25519 base64url signature |

Verification performs raw-size and canonical-form checks, recomputes protected bytes
and digest, resolves exactly `key_id` under purpose
`coordinator-dispatch-signing`, applies current/historical trust and revocation policy,
then verifies the domain-separated signature. A plan-signing or receipt-signing key
cannot satisfy this lookup.

### 2.4 Cross-field authority rules

- `grant_id`, `dispatch_attempt_id` and `one_shot_nonce` are independently generated
  with disjoint domain separators; equality between any pair denies.
- Grant ID, dispatch-attempt ID, operation ID, nonce and grant digest are create-only
  unique in the coordinator. Grant ID, operation ID, nonce and grant digest are
  create-only unique in the adapter.
- Every protected authority, effect, replay, budget, recovery, destination and fencing
  field equals the retained final comparison and current guarded view.
- `issued_at_monotonic_ms < deadline_monotonic_ms`, and their difference is at most
  5,000. The deadline equals the minimum of the plan, lease, authorization, caller and
  permit bounds and `issued_at_monotonic_ms + 5000`. Equality with the deadline denies.
- UTC/monotonic samples have the same retained `clock_generation`; monotonic checks are
  valid only under the exact `boot_id`. Instance/supervisor mismatch denies.
- Retry reuses the exact retained envelope bytes. It changes no field, signature,
  identity, nonce or deadline.

## 3. Execution receipt

### 3.1 Cryptographic profile

| Property | Exact v1 value |
|---|---|
| protected `schema` | `helixos.execution-receipt/1` |
| `digest_algorithm` | `sha-256` |
| `signature_algorithm` | `ed25519` |
| `key_purpose` | `adapter-receipt-signing` |
| signature domain bytes | `HELIXOS\0EXECUTION-RECEIPT\0V1\0` |

The receipt signature/digest construction mirrors §2.1 using the receipt domain and
`receipt_digest`. Receipt keys are independently provisioned and cannot verify a plan
or grant.

### 3.2 Complete protected payload

Every property below is required, including nullable decision-specific properties; the
object rejects all additional properties. Requiring explicit `null` for the inapplicable
branch gives both decisions one unambiguous canonical shape.

| Group | Exact field | Type/domain |
|---|---|---|
| profile | `schema` | exact receipt profile constant |
| profile | `digest_algorithm` | exact `sha-256` |
| profile | `signature_algorithm` | exact `ed25519` |
| profile | `key_purpose` | exact `adapter-receipt-signing` |
| profile | `key_id` | identifier; adapter receipt-signing public-key lookup only |
| identity | `receipt_id` | 32-byte domain-separated random identity, lowercase hex |
| identity | `grant_id` | exact retained 32-byte grant identity |
| identity | `grant_digest` | exact retained 32-byte protected grant digest |
| identity | `operation_id` | exact retained identifier |
| identity | `destination_adapter_id` | exact retained identifier |
| identity | `protocol_version` | exact integer `1` |
| inbox | `adapter_root_id` | exact 32-byte adapter-root identity, lowercase hex |
| inbox | `inbox_generation` | generation of first durable receipt |
| inbox | `consumption_generation` | generation for `CONSUMED`; otherwise `null` |
| inbox | `refusal_generation` | generation for `REFUSED_DEFINITE`; otherwise `null` |
| inbox | `receipt_generation` | generation of the signed receipt row |
| fencing | `observed_boot_id` | identifier from the independent epoch observer |
| fencing | `observed_supervisor_epoch` | safeInteger |
| fencing | `epoch_observer_generation` | generation |
| decision | `decision` | closed `CONSUMED` or `REFUSED_DEFINITE` |
| decision | `refusal_code` | closed refusal code for `REFUSED_DEFINITE`; otherwise `null` |
| decision | `no_consumption_tombstone_digest` | 32-byte digest for `REFUSED_DEFINITE`; otherwise `null` |
| time/trace | `decided_at_utc_ms` | safeInteger trusted UTC sample |
| time/trace | `decided_at_monotonic_ms` | safeInteger in the observed boot domain |
| time/trace | `trace_id` | opaque identifier; no user content |

The receipt decisions and their exact shapes are:

| Decision | `consumption_generation` | `refusal_generation` | `refusal_code` | `no_consumption_tombstone_digest` |
|---|---|---|---|---|
| `CONSUMED` | generation | `null` | `null` | `null` |
| `REFUSED_DEFINITE` | `null` | generation | one code below | 32-byte digest |

The closed v1 refusal-code domain is:

```text
GRANT_EXPIRED
SUPERVISOR_EPOCH_MISMATCH
ADAPTER_PAUSED
```

These are the only signed refusal codes after a grant has durably reached `RECEIVED`.
`DESTINATION_MISMATCH`, `PROTOCOL_UNSUPPORTED`, `CAPABILITY_MISMATCH` and
`INBOX_CAPACITY_EXHAUSTED` are pre-`RECEIVED` rejections. They create durable local
diagnostic or quarantine evidence, never a signed receipt, and never sufficient
no-consumption or reservation-release proof.

Malformed wire/signature/version/purpose, identity collisions and conflicting retained
bindings are local diagnostic or quarantine outcomes. They do not produce a signed
receipt.

### 3.3 Closed outer envelope and verification

The envelope has exactly `protected`, `receipt_digest` and `signature`; all three are
required and no fourth property is accepted. `receipt_digest` is the lowercase-hex
SHA-256 of canonical protected bytes, and `signature` is the canonical unpadded
base64url Ed25519 signature described in §1.

Verification requires exact canonical bytes, recomputed digest, key purpose
`adapter-receipt-signing`, historical/current trust and revocation policy, the receipt
signature domain, and exact retained grant, operation, destination, root, protocol,
boot, epoch and generation bindings. `decided_at_monotonic_ms` is compared only within
`observed_boot_id` and must order after the durable inbox generation evidence and no
later than the exclusive retained grant deadline for `CONSUMED`.

Only authentic `CONSUMED` advances the exact coordinator record to `EXECUTING`.
`REFUSED_DEFINITE` closes only the exact dispatch attempt and only after separate
guarded, fenced/quiescent no-in-flight proof matches its permanent tombstone. The
receipt alone never proves transport quiescence.

## 4. Key lifecycle and redaction

- Grant and receipt private keys stay in distinct provisioned signing authorities and
  never enter store rows, backups, fixtures, diagnostics or evidence.
- Stores retain key IDs, exact purposes, algorithms, public-key fingerprints and
  trust/revocation metadata needed for historical verification.
- Rotation changes neither the create-only grant/operation/nonce namespace nor retained
  bytes. Retained contracts are never resigned.
- Revocation may stop new signatures while an explicit historical policy verifies old
  evidence. It never turns an invalid current signature into authority.
- Wire values are restricted sovereign data. Public `Debug`, errors, logs, metrics and
  audit projections expose only closed decision/reason and bounded count/latency
  classes—never canonical bytes, identifiers, digests, targets, media types, trace IDs,
  key material or native paths.

## 5. Conformance corpus

One unchanged corpus on macOS arm64, Linux x86_64 and Windows x64 covers:

- RFC 8785 ordering, Unicode/NFC, integer, primitive and raw-wire size boundaries;
- every single protected grant and receipt field mutation;
- digest, signature, signature-domain, key-purpose, rotation and revocation failures;
- grant/attempt/operation/nonce/digest collisions and exact duplicates;
- exact deadline, one millisecond before/after and the 5,000 ms ceiling;
- both receipt shapes and every closed refusal code;
- cross-grant, cross-operation, cross-adapter, cross-protocol, cross-epoch and cross-root
  receipts;
- missing, unknown, duplicate, non-canonical and oversized input; and
- seeded identifiers resembling secrets and private paths to prove redaction.

Expected canonical bytes, protected digests, signatures and closed outcomes are
byte-identical on all three platforms.
