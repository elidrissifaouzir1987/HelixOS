# PLAN-002 local Windows x64 evidence — 2026-07-10

This is local, uncommitted-workspace evidence only. It is not immutable CI evidence,
not a macOS or Mac mini M4 run, not production replay durability, and not HelixOS Tier 1
evidence.

## Environment

- Base commit: `dcc38a1a2a31837a2c38a4cb1cda9e95e71b6e9c`
- Branch: `master`
- Worktree dirty during run: `true`
- OS: Microsoft Windows 11 Professionnel `10.0.26200`, x64
- CPU: AMD Ryzen 9 9950X3D, 16 cores / 32 logical processors
- Rust: `rustc 1.96.1 (31fca3adb 2026-06-26)`
- Rust commit: `31fca3adb283cc9dfd56b49cdee9a96eb9c96ffd`
- Rust host: `x86_64-pc-windows-msvc`
- Build profile: `release`

## Reviewed corpus

- Cases: 106 = 1 coherent + 5 checked-construction failures + 100 reachable runtime denials
- `cases.json`: 26,412 bytes; SHA-256
  `eefc1403e8b267afc3dde30b29d4064fa2d3c16cdeaeb1a5154377289a253b7a`
- `expected-outcomes.json`: 12,838 bytes; SHA-256
  `258fcd002c335a1f25070e593ae97eb7472b2fe55342134058e2e4e470af7bbb`
- Both artifacts were regenerated with `--check-fixtures`, parsed through the closed
  schema, compared as exact RFC 8785 JCS, and verified to have no BOM or trailing newline.

## Replay contention

Command:

```text
cargo test --locked --release -p helix-plan-eligibility --test contention -- --ignored --nocapture --test-threads=1
```

Raw summary:

```text
PLAN-002 contention: rounds=1000 contenders=8 winners_per_round=1
test result: ok. 1 passed; 0 failed; finished in 0.67s
```

Every round used one shared deterministic claimant and produced exactly one new claim.

## Deterministic context soak

Command:

```text
cargo test --locked --release -p helix-plan-eligibility --test soak -- --ignored --nocapture --test-threads=1
```

Raw summary:

```text
plan-eligibility-soak schema=1 corpus=helixos.plan-eligibility-cases/1 seed=0x48454c49584f5302 iterations=100000 eligible=12429 denied=[12531, 12403, 12418, 12403, 12867, 12490, 12459] elapsed_ms=136 status=pass
test result: ok. 1 passed; 0 failed; finished in 0.14s
```

## Release benchmark

Artifact: `benchmark-windows-x64-2026-07-10.json`

- Artifact bytes: 111,521
- Artifact SHA-256:
  `9527f82d04fa2b46b8381871f046fcf0102d298198169cb98b3d3f82e161c6cb`
- Public case: `eligible-coherent`
- Warmups: 1,000
- Measured evaluator-plus-deterministic-claimant calls: 10,000
- Claimant concurrency: 1
- Winners / denials: 10,000 / 0
- p50 / p95 / p99 / max: 600 / 600 / 600 / 6,800 ns
- SC-005 provisional p95 gate: 600 ns = 0.0006 ms <= 1 ms — **PASS**

The JSON artifact contains all 10,000 raw sorted integer nanosecond samples plus corpus,
hardware, platform, toolchain, profile, workload, counts, percentiles, limit, and explicit
authority/durability limitations. It contains no runtime plan, operation, task, workload,
key, lease, nonce, signature, resource, path, hostname, or username value.

## Evidence boundary

The benchmark measures the pure in-process evaluator call and the process-local
deterministic claimant after the caller has assembled a coherent context. It does not
measure provider acquisition, signature verification, a durable database transaction,
fsync, multi-process coordination, recovery, preparation, dispatch, or host effects.
A real Mac mini M4 benchmark and the unchanged Linux/macOS-arm64/Windows CI matrix remain
separate required evidence.
