# Plan envelope v1 fixture corpus

This directory is the versioned, language-neutral golden corpus for
`helixos.plan-envelope/1`. Fixture bytes are security-relevant contract data. They must
be generated from the reviewed `helix-contracts` implementation and independently
verified; hashes, signatures, keys, or canonical output must never be guessed or copied
from an unverified example.

The positive corpus is generated from the reviewed Rust constructor and the synthetic
test-only signing key in `kernel/helix-contracts/examples/plan_benchmark.rs`. Local tests
recompute every value and compare exact bytes. `PLAN-001` nevertheless remains pending
until the unchanged files are reproduced byte-for-byte by the required CI matrix.

## Required positive fixture set

| File | Required content |
|---|---|
| `valid-plan.json` | Reviewed logical constructor input for the positive plan; it is not accepted directly at a trust boundary. |
| `valid-plan.protected.jcs` | Exact UTF-8 RFC 8785 bytes of the protected object. |
| `valid-plan.envelope.jcs` | Exact canonical signed wire envelope accepted by the v1 decoder. |
| `valid-plan.plan-id` | The 64 lowercase hexadecimal SHA-256 identifier derived from `valid-plan.protected.jcs`. |
| `valid-plan.public-key` | Base64url-without-padding encoding of exactly 32 Ed25519 public-key bytes (43 ASCII characters). Never a production key. |
| `valid-plan.signature` | Base64url-without-padding encoding of the exact 64-byte Ed25519 signature. |

Canonical `.jcs` files have no BOM and no trailing newline. Scalar text fixture files
also have no surrounding whitespace or trailing newline. `valid-plan.envelope.jcs` is
limited to 1,048,576 bytes.

## Generation and review procedure

1. Finalize the closed Rust types, bounds, and invariant tests before generating data.
2. Construct the positive plan through validated public constructors. Use only a
   deterministic test-only signing key whose public half is clearly marked as fixture
   material. Do not use or serialize a production private key.
3. Generate protected JCS, `plan_id`, signature, and complete envelope through the same
   public contract operations exercised by consumers. A repository script or example
   may write these artifacts; manual editing of derived files is forbidden.
4. Independently recompute SHA-256 over the exact protected bytes, decode the signature
   to exactly 64 bytes, and verify it over
   `UTF8("HELIXOS\0PLAN-ENVELOPE\0V1\0") || protected_jcs`.
5. Run schema validation plus the Rust conformance test. The test must compare file
   bytes, not parsed semantic equality, and must fail at the first drift.
6. Review the corpus for secrets and sensitive real-world content. Commit only synthetic
   identifiers, paths, and content.
7. Run the unchanged corpus on every platform registered in
   `conformance/catalog.yaml`; link immutable successful CI evidence there before
   claiming `PLAN-001`.

The repository generator is deterministic and overwrites only this fixture set:

```sh
cd kernel
cargo run -p helix-contracts --example plan_benchmark -- \
  --write-fixtures ../contracts/fixtures/plan-envelope-v1
```

## Negative and mutation corpus

`negative-cases.json` is the machine-readable negative corpus. It references exact raw
wire files under `negative/` plus one bounded generated size case, declares the resolver
profile and stable `ContractError::code()`, and records `dispatch_reached: false` for
every case. Its closed schema is
`contracts/schemas/negative-contract-corpus-v1.schema.json`.

The corpus covers member order and Unicode edges, safe-integer boundaries, invalid
resource components, duplicate and unknown fields, unsupported versions and algorithms,
noncanonical wire encodings, payload tampering, wrong and untrusted keys, malformed
signatures, and every protected leaf mutation. The Rust conformance runner consumes the
same manifest later adapters will use and fails on the first error-code drift.

Negative signed artifacts must be derived mechanically from the reviewed positive
fixture or generated explicitly by tests. Do not hand-author plausible hashes or
signatures merely to fill the corpus.

## Authority

The schema describes the portable shape. The feature specification, ADR 0005, and
closed Rust decoder define the trust transition and semantic validation. A fixture is
evidence, not authority, and a cryptographically valid fixture conveys no permission to
perform a host effect.
