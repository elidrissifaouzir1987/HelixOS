# ADR 0005: Canonical, content-addressed, signed plan contracts

- **Status:** Accepted for feature `001-portable-signed-contracts`; rollout evidence pending
- **Date:** 2026-07-10
- **Owners:** HelixOS core and contract maintainers
- **Acceptance contract:** `PLAN-001`

## Context

The MVP-0 plan type is an in-process Windows-first structure. It contains native path
state, mutable execution state, and an incomplete custom hash surface. It therefore
cannot be the durable identity shared by approvals, leases, adapters, receipts, audit,
and recovery on macOS, Linux, and Windows.

Approval safety requires one logical protected plan to have exactly one byte
representation and one identifier on every supported architecture. A consumer must
also be able to reject an unsupported, altered, or untrusted plan before treating any
field as execution authority.

## Decision

Feature `001-portable-signed-contracts` introduces an independent, closed v1 contract
with these rules:

1. The protected plan is a typed JSON object with no native paths, floats, platform
   handles, process-local values, arbitrary maps, implicit defaults, or unknown fields.
2. Its canonical representation is RFC 8785 JCS over UTF-8. All integer fields are in
   the I-JSON exact range `0..=9,007,199,254,740,991`.
3. `plan_id` is lowercase hexadecimal `SHA-256(JCS(protected))`.
4. The signature profile is pure Ed25519 over the domain-separated message:

   ```text
   UTF8("HELIXOS\0PLAN-ENVELOPE\0V1\0") || JCS(protected)
   ```

   This is Ed25519, not Ed25519ph. The protected object binds the schema, digest and
   signature algorithms, and signer key identifier.
5. The wire envelope contains exactly `protected`, `plan_id`, and `signature`. It must
   already be canonical JCS and must not exceed 1,048,576 bytes.
6. Verification is ordered: size and canonical-wire checks; closed typed decode and
   invariant checks; protected-JCS and plan-ID recomputation; bounded signature-encoding
   validation; trusted-key resolution; then strict Ed25519 verification. Malformed
   signatures never reach a keychain/HSM resolver. Failure at any step is a typed denial
   and cannot dispatch an effect.
7. v1 accepts exactly `helixos.plan-envelope/1`, `sha-256`, `ed25519`, and
   `host.file.patch`. Compatibility is explicit; unknown versions, algorithms, fields,
   and intents are denied rather than ignored or downgraded.
8. File targets use an opaque `root_id` and validated NFC relative components. Native
   path rendering and handle-relative resolution remain adapter responsibilities.
9. Raw wire decoding uses a private representation. The public signed-envelope type is
   serializable but not directly deserializable; only strict verification produces the
   public `AuthenticPlanEnvelopeV1` marker. Public `Debug` output and JSON parse errors
   are redacted, and every denial exposes a stable non-secret error code for the shared
   negative corpus.

The initial Rust implementation exact-pins `serde_json_canonicalizer 0.3.2` behind a
private wrapper, `sha2 0.10.9`, and `ed25519-dalek 2.2.0` with strict verification.
These libraries are implementation choices, not wire identifiers; a dependency change
must reproduce the frozen corpus before it can merge.

The normative language-neutral shape is
`contracts/schemas/plan-envelope-v1.schema.json`. The Rust closed types and invariant
checks remain authoritative for constraints JSON Schema cannot express, including JCS
byte equality, duplicate-key rejection, Unicode NFC and byte-size limits, sorted
capabilities, cross-field digest/length agreement, time ordering, and recovery-class
rules.

## Consequences

### Positive

- Approvals, audit entries, retries, and receipts can refer to a stable portable plan
  identity.
- Every effect-bearing or authority-bearing protected field is covered by the digest
  and signature.
- A single language-neutral corpus can detect canonicalization or validation drift on
  macOS arm64, Linux, and Windows.
- The contract library remains pure: it performs no host effect, clock, RNG, network,
  or filesystem access.

### Costs and limitations

- Strict canonical-wire acceptance rejects otherwise equivalent noncanonical JSON.
- Conditional and cross-field invariants require typed validation in addition to JSON
  Schema.
- Ed25519 test fixtures prove interoperability only; production key custody, rotation,
  trust policy, workload identity, WebAuthn grants, and dispatch are later features.
- A valid signature proves authenticity of this envelope. It does not prove that a
  lease is current, policy authorizes dispatch, a precondition still holds, or the plan
  has not already been consumed.

## Alternatives considered

- **`BTreeMap` plus ordinary JSON serialization:** rejected because Rust string order is
  not RFC 8785 UTF-16 property order and ordinary JSON has multiple encodings.
- **Canonical CBOR/COSE:** viable as a future contract family, but v1 uses inspectable
  JSON and JCS for simpler cross-language fixtures.
- **Sign only `plan_id`:** rejected to avoid an unnecessary hash-then-sign profile and
  confusion with Ed25519ph. The signature covers the domain plus protected JCS directly.
- **P-256/Secure Enclave as the portable profile:** rejected because it would make the
  v1 interoperability contract device-bound. Hardware checkpoint signing may use a
  separate declared profile later.
- **Reuse the MVP-0 `Plan`:** rejected because native `PathBuf`, mutable state, and its
  partial hash surface violate the portable trust boundary.
- **Schema-only validation:** rejected because JSON Schema cannot establish canonical
  bytes, reject every parser-level ambiguity, or enforce all semantic relationships.

## Evidence and rollout

`PLAN-001` is not satisfied merely by merging this ADR or the schema. Release evidence
must include the reviewed positive and negative fixtures, RFC vectors, exhaustive
protected-field mutation tests, property tests, the deterministic 100,000-envelope
soak, and byte-identical results from the unchanged conformance suite on the registered
platform matrix. Until an immutable successful CI run is linked from
`conformance/catalog.yaml`, the cross-platform claim remains pending.

The negative corpus is a closed manifest plus exact raw wire files. Its typed outcomes
are consumed locally and reproduced unchanged in CI, rather than being re-authored in
platform-specific tests.

## Removal and migration

This feature is deliberately a leaf. Before the legacy runtime adopts it, rollback is
the deletion of `kernel/helix-contracts`, its workspace membership, `contracts/`, this
ADR, the conformance entry, and its workflow; MVP-0 behavior remains unchanged.

Migration of the existing plan pipeline requires a later Spec Kit feature with an
explicit legacy-to-v1 adapter. That migration may not weaken v1 validation, mutate this
schema in place, or bypass signature verification. A breaking semantic change creates
a new schema, media/profile declaration, fixtures, catalogue entry, and consumer policy.
