# Research: Portable Signed Contracts

## Decision 1 — Canonical JSON

**Decision**: Use RFC 8785 JCS through the private wrapper
`serde_json_canonicalizer = 0.3.2`. Public APIs expose only closed typed structures.

**Rationale**: RFC 8785 defines invariant UTF-8 JSON, deterministic property sorting by
UTF-16 code units, and I-JSON constraints for cryptographic operations. The selected
crate is active and explicitly targets RFC 8785; it is covered by project-owned official
vectors and golden cross-platform fixtures.

**Alternatives considered**:

- `serde_jcs`: rejected because its maintenance and RFC divergence history are weaker.
- `BTreeMap` plus `serde_json::to_vec`: rejected because Rust ordering is not RFC 8785
  UTF-16 property ordering and ordinary JSON serialization is not canonical.
- CBOR/COSE: viable future contract family, but rejected for v1 because the architecture
  already specifies inspectable JCS and multi-language JSON fixtures.

**Risk controls**: Exact pin, private wrapper, official vectors, no arbitrary
`serde_json::Value`, no floats, safe-integer validation, and fixture drift CI.

## Decision 2 — Digest and signature

**Decision**: Compute `plan_id = SHA-256(JCS(protected))`. Sign with pure Ed25519 over
`"HELIXOS\0PLAN-ENVELOPE\0V1\0" || JCS(protected)`. The protected object includes the
schema, digest/signature algorithms, and signer key ID. The wire envelope adds only the
plan ID and base64url-no-pad signature.

**Rationale**: The digest provides the stable approval/audit identifier. Signing the
domain-separated canonical content directly avoids confusing Ed25519 with Ed25519ph and
binds all protected metadata without circular serialization. Verification uses strict
Ed25519 verification after recomputing the JCS and plan ID.

**Alternatives considered**:

- Sign only the SHA-256 digest: secure under the digest assumption but adds an avoidable
  hash-then-sign layer and is easier to mislabel as Ed25519ph.
- `ed25519-dalek 3.0.0`/`sha2 0.11`: current majors but released only days before this
  decision; deferred until soak and dependency review.
- P-256/Secure Enclave: device-bound and not the portable plan-signing profile. It may
  sign hardware checkpoints under a different declared algorithm later.

**Selected versions**: mature `ed25519-dalek 2.2.0` with `verify_strict` and matching
`sha2 0.10.9`, both exact-pinned. No RNG or private-key persistence exists in this crate.

## Decision 3 — Strict wire boundary

**Decision**: The trust-boundary decoder accepts at most 1 MiB, parses into
`#[serde(deny_unknown_fields)]` closed types, validates every invariant, reserializes the
entire signed object as JCS, and rejects the input unless its bytes already equal that
canonical representation.

**Rationale**: This denies whitespace/order variants, unknown fields, duplicate struct
fields, float/exponent/negative-zero forms, implicit defaults, and ambiguous wire
representations before verified data reaches a consumer.

**Alternatives considered**:

- Accept noncanonical JSON and verify its canonical form: cryptographically workable,
  but allows multiple wire encodings and weakens fixture/protocol diagnostics.
- JSON Schema as the only validator: rejected; schema validation complements but cannot
  replace typed validation, canonical byte comparison, and signature verification.

## Decision 4 — Closed v1 semantic scope

**Decision**: v1 supports only `host.file.patch`. It binds an opaque root plus validated
relative components, file/volume identity and pre-hash, exact replacement bytes/length/
hash/media type, observed recovery profile, verification result, capability digest,
request/lease/policy/catalog bindings, budget, timestamps, boot ID, nonce, and epochs.

**Rationale**: One complete effect is safer and more falsifiable than a generic map that
could hide floats, unknown semantics, or unbounded content. Future intents require a new
declared compatible schema and fixtures.

**Alternatives considered**:

- Generic arbitrary JSON arguments/effects: rejected for v1 because unknown semantics
  cannot be safely approved or executed.
- Reuse the legacy `Plan`: rejected because it contains `PathBuf`, mutable execution
  state, custom field concatenation, and an incomplete hash surface.

## Decision 5 — Resource representation

**Decision**: The signed contract stores `root_id` plus decoded NFC relative components.
It never stores an OS-native or absolute path. Components are bounded and reject empty,
dot/traversal, separators, NUL/control/bidi, colon/ADS, trailing dot/space, Windows
forbidden characters/device basenames, non-NFC text, and oversized input.

**Rationale**: This representation has one JSON spelling and can later be rendered as
`helixfs://` without making URI parsing or a platform filesystem part of the v1 trust
boundary. Handle-relative resolution, links, reparse points, mount crossing, and
case-collision checks remain adapter responsibilities under `PATH-001`.

## Decision 6 — Schema, fixtures, and dependency surface

**Decision**: Commit a hand-reviewed JSON Schema 2020-12 document and a golden corpus.
Do not add runtime schema resolution in this slice. Keep `$ref` local if introduced
later. Exact dependency pins plus `Cargo.lock` are the supply-chain baseline.

**Rationale**: The Rust decoder remains authoritative while the schema and fixtures give
future non-Rust adapters a stable interoperability target. Avoiding `jsonschema` and
schema-generation dependencies keeps network/file resolvers and newly released code out
of the sovereign crate until needed.

**Alternatives considered**:

- `schemars` + `jsonschema`: capable, but they add substantial and very recent
  dependencies; deferred until a second-language consumer demonstrates the need.
- Rust-only fixtures: rejected because portability must be demonstrable outside Rust.

## Primary references

- RFC 8785, JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785.html
- Verified RFC 8785 errata, including negative zero:
  https://www.rfc-editor.org/errata/rfc8785
- RFC 8032, Edwards-Curve Digital Signature Algorithm:
  https://www.rfc-editor.org/rfc/rfc8032.html
- JSON Schema 2020-12: https://json-schema.org/draft/2020-12
- Canonicalizer crate: https://crates.io/crates/serde_json_canonicalizer/0.3.2
- Ed25519 implementation: https://crates.io/crates/ed25519-dalek/2.2.0

All decisions are removable: the canonicalizer is behind one private module; algorithms
are explicit enums; the crate is not yet wired into the legacy runtime.
