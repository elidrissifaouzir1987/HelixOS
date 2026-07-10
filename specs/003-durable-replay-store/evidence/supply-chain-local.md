# PLAN-003 local supply-chain evidence

**Recorded**: 2026-07-10
**Scope**: local Windows x64 pre-commit validation of Feature 003
**Status**: useful local evidence, not immutable three-platform release evidence

This record identifies the exact reviewed storage components and the state of the
workspace lockfile. The Feature 003 worktree was not yet committed when the commands
ran, so `T054` must repeat and attest the checks for one immutable commit on all three
required runners.

## Toolchain and native provider

- `rustc 1.96.1 (31fca3adb 2026-06-26)`
- host: `x86_64-pc-windows-msvc`
- LLVM: `22.1.2`
- `cargo 1.96.1 (356927216 2026-06-26)`
- `rusqlite = 0.40.1`, features `backup` and `bundled`
- `libsqlite3-sys = 0.38.1`, features `bundled`, `bundled_bindings`, and `cc`
- bundled SQLite: `3.53.2`
- bundled SQLite source ID:
  `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`
- OS randomness provider crate: `getrandom = 0.4.3`

`cargo tree --locked -p helix-replay-sqlite -e features` confirmed that this build
selects the bundled SQLite source and not SQLCipher or a host SQLite. The source ID was
cross-checked against the bundled `sqlite3.c` and is also verified by the PLAN-003 CI
runtime probe.

## Licenses

The direct/native storage components report:

| Component | Version | Declared license |
|---|---:|---|
| `rusqlite` | 0.40.1 | MIT |
| `libsqlite3-sys` | 0.38.1 | MIT |
| bundled SQLite amalgamation | 3.53.2 | public domain notice in the reviewed source |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 |

A `cargo metadata --locked --format-version 1` reachability scan from
`helix-replay-sqlite`, including target-specific and development dependencies, found
94 packages: 3 private workspace packages and 91 external packages. Every external
package had non-empty SPDX-compatible Cargo license metadata. This is inventory
evidence, not a substitute for the project's legal approval policy.

## Vulnerability audit

Command:

```text
cargo audit --file Cargo.lock --json
```

Tool and advisory snapshot:

- `cargo-audit 0.22.2`
- RustSec advisory database commit:
  `1090288da789aaf84278006fad35a36bfcfcbd67`
- database update time: `2026-07-09T08:36:22+02:00`
- audited workspace lockfile dependencies: 200
- vulnerabilities found: 0

The audit also emitted one informational `unmaintained` warning for
`rustls-pemfile 2.2.0` (`RUSTSEC-2025-0134`). `cargo tree --locked -i
rustls-pemfile` places it only below the legacy `helixos-kernel` /
`helixos-mcp-shim` packages; it is absent from the Feature 003 dependency tree. The
warning is not silently described as a clean whole-workspace audit.

## Reviewed hashes

| Artifact | SHA-256 |
|---|---|
| `kernel/Cargo.lock` | `f3b6c0cb07f9e9ddec2f6b64cb3b00f7df99fd93066315e92f1a5dfa4b3498f8` |
| replay schema v1 SQL | `7749bd426803f589c6a4dd0643d0b19d76aa38bc0645bc74db205f24e687d53d` |
| backup manifest v1 JSON Schema | `ecd2a0ddfbd0fc3e64f9a9bd2ea7659adef04bfd551c7c49bf3fceb51f3255b6` |
| frozen case corpus | `7db71958d28d135d1880daaaf57788b4476950a7835a4c85d633e8d921a3a5ff` |
| frozen expected outcomes | `687c562f05fe7e449f3df2b09505057a26420407e7df9c91b109a1d3950f25ac` |

## Reproduction commands

```text
cargo tree --locked -p helix-replay-sqlite -e normal
cargo tree --locked -p helix-replay-sqlite -e features
cargo metadata --locked --format-version 1
cargo audit --file Cargo.lock --json
rustc --version --verbose
cargo --version --verbose
```

Pending before production-ready status: immutable CI artifact digests and attestations
for Linux x64, macOS arm64 and Windows x64; preserved evidence beyond hosted artifact
retention; the controlled Mac mini M4 benchmark; and the separately scoped
`F_FULLFSYNC`/power-cut investigation.
