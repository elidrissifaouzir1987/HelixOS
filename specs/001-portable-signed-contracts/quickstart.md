# Quickstart: Validate Portable Signed Contracts

## Prerequisites

- Rust stable with Cargo.
- Repository root is the current directory.
- No API key, network service, credential store, or platform VM is required after Cargo
  dependencies are available.

## Contract tests

```sh
cd kernel
cargo test --locked -p helix-contracts --all-targets --all-features
```

Expected result: all canonicalization, resource, digest, signature, tamper, fixture, and
property tests pass.

## Whole-workspace regression

```sh
cd kernel
cargo test --locked --workspace --all-targets --all-features
```

Expected result: the legacy MVP-0 tests and new contract tests all pass. The runtime
behavior is unchanged because no legacy crate depends on `helix-contracts` yet.

## Extended deterministic soak

```sh
cd kernel
cargo test --locked --release -p helix-contracts --test soak -- --ignored --nocapture
```

Expected result: 100,000 generated valid envelopes canonicalize, sign, and verify without
panic, invalid acceptance, or identifier drift.

## Reference performance evidence

```sh
cd kernel
HELIX_BENCH_HARDWARE="Mac mini M4, 16 GB" \
  cargo run --locked --release -p helix-contracts --example plan_benchmark -- \
  --evidence ../specs/001-portable-signed-contracts/evidence/benchmark-macos-arm64.json
```

Record the printed hardware/OS/toolchain/build profile, iterations, p50, p95, p99, and
maximum in the release evidence. The provisional gate is p95 <= 1 ms for protected JCS
plus plan-ID creation over at least 10,000 iterations.

## Graphify refresh

```sh
graphify update . --force
graphify reflect --if-stale --graph graphify-out/graph.json
```

Persist only a concise result/correction/dead-end record. Specs, fixtures, tests, and code
remain the authoritative evidence.

## Local evidence (not a Tier 1 portability claim)

Recorded 2026-07-10 on `windows-x86_64`, `AMD64 Family 26 Model 68 Stepping 0,
AuthenticAMD`, 32 available logical CPUs, with `rustc 1.96.1 (31fca3adb
2026-06-26)`, host `x86_64-pc-windows-msvc`:

- Release benchmark, 10,000 protected-JCS plus plan-ID iterations: p50 26.5 us,
  p95 27.0 us, p99 29.7 us, maximum 138.3 us. The provisional p95 gate of
  1 ms passed.
- Raw sorted samples, corpus/plan ID, toolchain, hardware label, and summary are stored
  in `evidence/benchmark-windows-x86_64-2026-07-10.json`.
- Release soak: 100,000 deterministic sign-and-verify envelopes passed in 17.07 s.
- Exact-pinned Draft 2020-12 metaschema validation of both schemas, the committed
  golden envelope, and the 23-case negative manifest passed with
  `check-jsonschema 0.37.4`.

This remains reproducible local evidence only. T028's separate unchanged hosted Linux
x86_64, macOS arm64 and Windows x64 matrix, retained artifacts and attestations are
recorded in
[`evidence/ci-immutable-b3132586245acea415104381b337d3fea3303444.md`](evidence/ci-immutable-b3132586245acea415104381b337d3fea3303444.md).
That closes only the hosted matrix task. Linux arm64, physical Mac mini M4, CI execution
of the ignored 100,000-envelope soak, Tier 1 and production readiness remain unproven;
`PLAN-001` remains `pending-evidence`.

## Mandatory next trust transition

`AuthenticPlanEnvelopeV1` proves canonical identity and signature only. It is not
dispatch eligibility. The next Spec Kit feature must produce a distinct eligible/current
type from explicit inputs for current time, boot ID, instance and fencing epochs, live
lease/policy/catalog state, nonce replay state, and capability-report freshness. No
adapter may accept `AuthenticPlanEnvelopeV1` directly.

Likewise, declared compensation and sufficient byte reservation are not proof that a
durable, flushed, hash-verified pre-image exists. A later prepare/dispatch transition
must bind and resolve a durable recovery-preparation receipt before compensation can
justify L1 execution.
