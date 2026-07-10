# Data Model: Portable Signed Contracts

## Wire aggregate

### `SignedPlanEnvelopeV1`

The canonical wire object contains exactly:

- `protected`: one `PlanProtectedV1`;
- `plan_id`: lowercase 32-byte SHA-256 hexadecimal digest of JCS(`protected`);
- `signature`: base64url without padding, exactly 64 Ed25519 bytes.

Unknown, absent, duplicate, or defaulted fields are invalid. The complete wire object
must itself already be RFC 8785 canonical JSON.

The raw wire representation is private to the trust-boundary decoder. The public
`SignedPlanEnvelopeV1` is not directly deserializable, and only successful identity,
key-trust, and signature verification yields `AuthenticPlanEnvelopeV1`. Public debug
summaries omit identifiers, resource components, replacement bytes, signatures, and
untrusted JSON text. Denials expose stable `ContractError::code()` values.

## Protected entities

### `PlanProtectedV1`

Fields:

- fixed `schema = helixos.plan-envelope/1`;
- fixed `digest_algorithm = sha-256` and `signature_algorithm = ed25519`;
- validated `key_id`;
- `operation_id`, `task_id`, `workload_id`, `boot_id`;
- `task_lease_digest` and `request_source`;
- `catalog_version`, `policy_version`;
- `risk_level`; the intent's recovery object carries the single recovery class;
- one `FilePatchIntentV1`;
- `capability_report_digest`, observation timestamp, sorted required capabilities;
- one `BudgetReservationV1`;
- issued/expiry Unix milliseconds, 128-bit lowercase nonce, instance and fencing epochs.

Validation rules:

- all identifiers are nonempty, bounded ASCII tokens;
- all signed integers are within 0..=2^53-1;
- issue time is strictly before expiry;
- capabilities are bounded, sorted, unique tokens;
- all enum values are closed; no implicit default exists.

### `RequestSourceV1`

- `kind`: `human_request_grant` or `registered_trigger`;
- `digest_sha256`: digest of the verified grant/trigger definition.

### `BudgetReservationV1`

- reservation identifier;
- three-letter uppercase currency code;
- price-table identifier binding the cost calculation basis;
- maximum cost in integer micro-units;
- action limit and egress-byte limit.

Zero limits are explicit and valid; values above the JCS/I-JSON safe integer bound are
invalid.

## Effect entities

### `FilePatchIntentV1`

- fixed `kind = host.file.patch`;
- `target`: `ResourceRefV1`;
- `precondition`: `FilePreconditionV1`;
- `replacement`: `ReplacementContentV1`;
- `recovery`: `RecoveryProfileV1`;
- `verification`: `FileVerificationV1`.

The replacement and verification length/digest must agree. Compensation requires the
exact pre-image digest and at least the declared pre-image byte length in reserved
space; irreversible recovery forbids a pre-image digest.

### `ResourceRefV1`

- `root_id`: lowercase ASCII token, max 64 characters;
- `components`: 1..128 NFC components, each max 255 UTF-8 bytes, total max 4096 bytes.

Components reject traversal, separators, NUL/control/bidi, colon/ADS, Windows forbidden
characters/device names (including console aliases and superscript COM/LPT digits),
trailing dot/space, non-NFC spellings, and the v1 fixed set of Unicode
default-ignorable format characters. This deliberately conservative profile prevents
approval-UI path spoofing and must change only through a new reviewed contract profile.

### `FilePreconditionV1`

- opaque `volume_id` and `file_id`;
- current content SHA-256;
- current byte length.

### `ReplacementContentV1`

- exact bytes as base64url without padding;
- declared byte length and SHA-256;
- bounded media type.

The constructor decodes once and verifies length/digest before the plan can be signed.

### `RecoveryProfileV1`

- class: `compensation` or `irreversible`;
- optional pre-image digest;
- reserved byte count;
- observed atomicity: `atomic_replace` or `non_atomic`.

### `FileVerificationV1`

- expected post-effect SHA-256;
- expected byte length.

## Value objects

- `Sha256Digest`: exactly 64 lowercase hexadecimal characters / 32 bytes.
- `Nonce128`: exactly 32 lowercase hexadecimal characters / 16 bytes.
- `SafeU64`: wire integer restricted to 0..=9,007,199,254,740,991.
- `Identifier`: bounded ASCII `[A-Za-z0-9._:-]` token; field-specific limits apply.
- Closed enums for schema, algorithms, risk, request source, recovery, atomicity, and
  intent kind.

## Trust transition

```text
untrusted canonical wire
  -> strict decode and invariant validation
  -> recompute protected JCS and plan_id
  -> resolve trusted public key by protected key_id
  -> strict Ed25519 verification over domain || protected JCS
  -> AuthenticPlanEnvelopeV1
```

`AuthenticPlanEnvelopeV1` means cryptographically authentic only. It does not imply that
the lease is current, the policy authorizes dispatch, the target precondition still
holds, or the plan has not already been consumed.
