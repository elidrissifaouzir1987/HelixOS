# PLAN-004 Frozen Prerequisite Baseline

**Captured**: 2026-07-11, before Feature 004 source/workspace changes

**Source commit**: `01a9181ef83539c0516139f8285551a9dfabc3b5`

**Branch**: `master`

This is the locked PLAN-001/002/003 prerequisite baseline for T001. At capture time,
`git status --short kernel` was empty and neither `helix-plan-preparation` nor
`helix-coordinator-sqlite` existed. Planning and secret-free Graphify artifacts outside
`kernel/` were intentionally uncommitted and are not part of this source baseline.

## Toolchain

```text
rustc 1.96.1 (31fca3adb 2026-06-26)
cargo 1.96.1 (356927216 2026-06-26)
host: aarch64-apple-darwin
LLVM: 22.1.2
```

Commands:

```sh
cd kernel
rustc --version --verbose
cargo --version --verbose
cargo metadata --locked --no-deps --format-version 1
```

The locked metadata contained exactly six workspace packages:
`helix-contracts`, `helix-plan-eligibility`, `helix-replay-sqlite`,
`helixos-kernel`, `helixos-mcp-shim`, and `helixos-provision`.

## Byte-stable dependency evidence

| Artifact | SHA-256 |
|---|---|
| `kernel/Cargo.lock` | `f3b6c0cb07f9e9ddec2f6b64cb3b00f7df99fd93066315e92f1a5dfa4b3498f8` |
| locked no-dependency metadata JSON | `135bb19288138489b539054b4954594336c4210599cb2527f5c42881009b4126` |
| locked dependency tree for PLAN-001/002/003 crates | `6e53432a9e884f97604af7ebfa548f3e0a4b7a727737c60ab430f2f53220ef6a` |

Digest commands:

```sh
shasum -a 256 kernel/Cargo.lock
cd kernel
cargo metadata --locked --no-deps --format-version 1 | shasum -a 256
cargo tree --locked \
  -p helix-contracts \
  -p helix-plan-eligibility \
  -p helix-replay-sqlite | shasum -a 256
```

## Locked test baseline

Commands:

```sh
cd kernel
cargo test --locked -p helix-contracts
cargo test --locked -p helix-plan-eligibility
cargo test --locked -p helix-replay-sqlite
```

| Prerequisite | Passed | Failed | Intentionally ignored |
|---|---:|---:|---:|
| PLAN-001 `helix-contracts` | 48 | 0 | 1 |
| PLAN-002 `helix-plan-eligibility` | 51 | 0 | 2 |
| PLAN-003 `helix-replay-sqlite` | 95 | 0 | 9 |
| **Total** | **194** | **0** | **12** |

The ignored cases are explicitly labeled release contention, soak, process-kill or
fault-entry evidence and were not silently skipped as ordinary tests. No ignored soak
or release workload was executed for this prerequisite snapshot.

## Interpretation gate

- PLAN-001 canonical/signature fixtures remain green.
- PLAN-002 eligibility, first-failure, redaction and one-shot replay semantics remain
  green.
- PLAN-003 claim/conflict, deadlines, corruption, backup/restore and ordinary
  contention behavior remain green.
- This artifact proves the pre-Feature-004 software baseline only. It is not physical
  M4, power-loss, production recovery or Tier 1 evidence.
