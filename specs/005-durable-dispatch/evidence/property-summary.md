# PLAN-005 T083 Deterministic Contract Property Summary

**Date**: 2026-07-13

**Status**: PASS (local implementation evidence)

**Target**: `helix-dispatch-contracts` production grant/receipt decoders and verifiers

**Platform**: macOS 26.5.2, arm64

**Toolchain**: `rustc 1.96.1 (31fca3adb 2026-06-26)`,
`cargo 1.96.1 (356927216 2026-06-26)`

## Reproduction profile

- Fixed public seed: `0x504c414e30303583`.
- Generator schema: `plan005-contract-property/1`.
- Total generated mutations executed: **100,000**.
- Grant mutations: **50,000**.
- Receipt mutations: **50,000**.
- Families: **26**, with 22 fast families x 4,540 cases and four bounded raw
  size/UTF-8 families x 30 cases.
- Every case calls either `decode_and_verify_execution_grant_v1` or
  `decode_and_verify_execution_receipt_v1`. No case is counted from a local parser or
  oracle alone.
- Every production result is compared with one exact `ContractError` member, then the
  complete observed error histogram is compared with a frozen closed histogram.
- Generated values are derived as SHA-256 of the public seed, family name, ordinal and
  public attempt counter. Wrong-key cases generate only public Ed25519 verification-key
  candidates and require `VerifyingKey::from_bytes` to accept them. No signing key,
  private seed, credential or regeneration authority is present.

The ignored release gate keeps the ordinary crate suite fast. The permanent non-ignored
test still proves the seed, family names, exact 100,000 total, 50,000/50,000 split,
closed histogram cardinality and all five valid signed goldens on every ordinary run.

## Exact mutation distribution

| Contract | Family | Cases | Primary closed oracle |
|---|---|---:|---|
| grant | RFC 8785 canonical framing/order/BOM/whitespace | 4,540 | `NON_CANONICAL_WIRE` |
| grant | duplicate JSON member | 4,540 | `DUPLICATE_MEMBER` |
| grant | unknown outer/protected field | 4,540 | `UNKNOWN_FIELD` |
| grant | signature mutation | 4,540 | `SIGNATURE_INVALID` |
| grant | receipt-signature/cross-domain substitution | 4,540 | `SIGNATURE_INVALID` |
| grant | wrong valid public verification key | 4,540 | `SIGNATURE_INVALID` |
| grant | protocol version | 4,540 | `UNSUPPORTED_PROTOCOL` |
| grant | protected digest | 4,540 | `DIGEST_MISMATCH` |
| grant | grant/attempt/one-shot nonce collision | 4,540 | `INVALID_FIELD` |
| grant | grant/attempt/preparation/plan/replay identity | 4,540 | `DIGEST_MISMATCH` |
| grant | unknown dispatch key ID | 4,540 | `UNKNOWN_KEY` |
| grant | invalid UTF-8 | 30 | `MALFORMED_JSON` |
| grant | wire over 1,048,576 bytes | 30 | `WIRE_TOO_LARGE` |
| **grant subtotal** |  | **50,000** |  |
| receipt | RFC 8785 canonical framing/order/BOM/whitespace | 4,540 | `NON_CANONICAL_WIRE` |
| receipt | duplicate JSON member | 4,540 | `DUPLICATE_MEMBER` |
| receipt | unknown outer/protected field | 4,540 | `UNKNOWN_FIELD` |
| receipt | signature mutation | 4,540 | `SIGNATURE_INVALID` |
| receipt | grant-signature/cross-domain substitution | 4,540 | `SIGNATURE_INVALID` |
| receipt | wrong valid public verification key | 4,540 | `SIGNATURE_INVALID` |
| receipt | protocol version | 4,540 | `UNSUPPORTED_PROTOCOL` |
| receipt | protected digest | 4,540 | `DIGEST_MISMATCH` |
| receipt | receipt identity | 4,540 | `DIGEST_MISMATCH` |
| receipt | grant ID/digest, operation and destination bindings | 4,540 | exact binding member |
| receipt | adapter root, boot and supervisor-epoch bindings | 4,540 | exact binding member |
| receipt | invalid UTF-8 | 30 | `MALFORMED_JSON` |
| receipt | wire over 65,536 bytes | 30 | `WIRE_TOO_LARGE` |
| **receipt subtotal** |  | **50,000** |  |
| **total** |  | **100,000** |  |

The two composite receipt families are exactly partitioned by ordinal:

- grant ID/digest: 2,270 `GRANT_BINDING_MISMATCH`;
- operation: 1,135 `OPERATION_BINDING_MISMATCH`;
- destination: 1,135 `DESTINATION_BINDING_MISMATCH`;
- adapter root: 1,514 `ADAPTER_ROOT_BINDING_MISMATCH`;
- boot/supervisor epoch: 3,026 `SUPERVISOR_EPOCH_BINDING_MISMATCH`.

## Exact observed closed outcomes

| `ContractError` code | Observed |
|---|---:|
| `ADAPTER_ROOT_BINDING_MISMATCH` | 1,514 |
| `DESTINATION_BINDING_MISMATCH` | 1,135 |
| `DIGEST_MISMATCH` | 18,160 |
| `DUPLICATE_MEMBER` | 9,080 |
| `GRANT_BINDING_MISMATCH` | 2,270 |
| `INVALID_FIELD` | 4,540 |
| `MALFORMED_JSON` | 60 |
| `NON_CANONICAL_WIRE` | 9,080 |
| `OPERATION_BINDING_MISMATCH` | 1,135 |
| `SIGNATURE_INVALID` | 27,240 |
| `SUPERVISOR_EPOCH_BINDING_MISMATCH` | 3,026 |
| `UNKNOWN_FIELD` | 9,080 |
| `UNKNOWN_KEY` | 4,540 |
| `UNSUPPORTED_PROTOCOL` | 9,080 |
| `WIRE_TOO_LARGE` | 60 |
| **total refused** | **100,000** |

Result: **100,000/100,000 generated mutations were refused with the exact expected
closed classification; zero authenticated.**

## Unchanged valid goldens

The permanent and release tests authenticate every reviewed base before and after the
generated run, reserialize it byte-identically, and freeze the SHA-256 of its canonical
outer envelope:

| Golden | Canonical-envelope SHA-256 |
|---|---|
| `grant.valid` | `a3b3a5e6af6c6aca1fc0d440d90f5f25071bd9d61af538080563a444cac67052` |
| `receipt.consumed.valid` | `5b6e7466898957f97a876dade64fa95fc3cdbda3321dbeee2221c731bc72872e` |
| `receipt.refused.adapter-paused.valid` | `9e205753336494357469e17bf2edc15c30631fbefe0bbf7d97ec524d1db289d0` |
| `receipt.refused.grant-expired.valid` | `be63549cec431287d00c5e6892488e6d1d4d111509bd7dd680c7aebce69f586b` |
| `receipt.refused.supervisor-epoch-mismatch.valid` | `234a6658ee424fb2c8260de5b08b813033f6893d125d3aef32ca49ad8e914440` |

No file under `contracts/fixtures/durable-dispatch-v1/` was changed for T083.

## Commands and exact local results

Run from `kernel/`:

```text
cargo test --locked -p helix-dispatch-contracts
```

PASS: 26 passed, 0 failed, one release test ignored as designed.

```text
cargo test --locked -p helix-dispatch-contracts --all-features
```

PASS: 26 passed, 0 failed, one release test ignored as designed.

```text
/usr/bin/time -p cargo test --locked -p helix-dispatch-contracts --test property release_100_000_generated_mutations_follow_closed_oracle -- --ignored --exact --nocapture
```

Final PASS on the post-Clippy source:

```text
seed=0x504c414e30303583
total=100000 grant=50000 receipt=50000 families=26
fast_family_cases=4540 bounded_raw_family_cases=30
elapsed_ms=61540 status=pass
test result: 1 passed; 0 failed
real 61.65
user 61.53
sys 0.08
```

```text
cargo clippy --locked -p helix-dispatch-contracts --all-targets --no-deps -- -D warnings
cargo clippy --locked -p helix-dispatch-contracts --all-targets --all-features --no-deps -- -D warnings
```

PASS: both targeted strict-Clippy gates completed with zero warnings.

## Nonclaims

- This is deterministic generated contract evidence, not a proof over every possible
  byte string and not an unbounded fuzzing or memory-safety claim.
- The 61.540-second harness duration is diagnostic test timing, not the PLAN-005 M4
  dispatch latency benchmark and not a product performance claim.
- The gate proves strict grant/receipt wire rejection and unchanged synthetic signed
  goldens only. It does not prove coordinator/adapter store atomicity, transport,
  process-kill, power-loss, filesystem durability, host mutation or exactly-once effect.
- This local arm64 result is not multi-platform CI or immutable exact-commit evidence.
  Linux x86_64, Windows x64, hosted attestations and release-bundle evidence remain
  separate PLAN-005 gates.
- No private signing key is available or needed. The fixture remains synthetic
  no-effect evidence and authorizes no execution token, effect handoff or host change.
