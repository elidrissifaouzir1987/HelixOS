# Plan Envelope v1 Wire Contract

## Media and canonical form

- Media type for fixtures: `application/vnd.helixos.plan-envelope+json;version=1`.
- Encoding: UTF-8 RFC 8785 JCS with no BOM or trailing newline.
- Maximum accepted wire size: 1,048,576 bytes.
- The decoder rejects any byte sequence that is valid JSON but not the exact JCS form of
  its typed value.

## Top-level shape

```json
{
  "plan_id": "<64 lowercase SHA-256 hex>",
  "protected": {
    "schema": "helixos.plan-envelope/1",
    "digest_algorithm": "sha-256",
    "signature_algorithm": "ed25519",
    "key_id": "<bounded key identifier>",
    "...": "all effect and authority fields"
  },
  "signature": "<64 Ed25519 bytes, base64url without padding>"
}
```

The example is explanatory, not canonical fixture data. The normative field set is the
committed JSON Schema and Rust closed types.

## Cryptographic construction

```text
protected_jcs = JCS(protected)
plan_id       = lowercase_hex(SHA-256(protected_jcs))
message       = UTF8("HELIXOS\0PLAN-ENVELOPE\0V1\0") || protected_jcs
signature     = Ed25519.sign(signing_key(key_id), message)
```

Verification performs strict typed decode and validation, exact canonical-wire
comparison, plan-ID comparison, signature-encoding validation, trusted key resolution,
and strict Ed25519 verification in that order. Malformed signatures never reach a
keychain/HSM resolver. No parsed field becomes execution authority merely because the
signature is valid.

## Compatibility

- Consumers in this feature accept exactly `helixos.plan-envelope/1`, `sha-256`,
  `ed25519`, and `host.file.patch`.
- Unknown schema, algorithm, field, or intent is a typed deny result.
- No v1 field is optional through a default. Compatibility changes require a new schema,
  fixtures, and explicit consumer policy.

## External evidence

The language-neutral schema and fixtures are located under `contracts/`. CI verifies
that the Rust implementation reproduces them byte for byte on Windows, Linux, and macOS.
