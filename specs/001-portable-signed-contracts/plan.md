# Implementation Plan: Portable Signed Contracts

**Branch**: `master` (feature directory `001-portable-signed-contracts`) | **Date**: 2026-07-10 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from
`specs/001-portable-signed-contracts/spec.md`

## Summary

Add an independent `helix-contracts` Rust crate that defines the first closed,
platform-neutral `PlanEnvelope` contract. It canonicalizes the protected plan with
RFC 8785, derives a SHA-256 plan identifier, signs a domain-separated message with
Ed25519, decodes canonical wire bytes strictly, and validates a portable
`host.file.patch` resource/effect. The current MVP-0 `Plan` and runtime remain unchanged;
migration requires a later adapter feature.

## Technical Context

**Language/Version**: Rust edition 2021; developed with rustc 1.96.1. CI uses the
stable toolchain and the crate declares an MSRV only after a clean lower-toolchain gate.

**Primary Dependencies**: Exact pins: `serde 1.0.228`, `serde_json 1.0.150`,
`serde_json_canonicalizer 0.3.2`, `sha2 0.10.9`, `ed25519-dalek 2.2.0`,
`base64 0.22.1`, `unicode-normalization 0.1.25`, `thiserror 2.0.18`; test-only
`proptest 1.11.0`.

**Storage**: No runtime storage. Versioned schemas, golden fixtures, public test keys,
and conformance metadata are repository files.

**Testing**: `cargo test --workspace`; RFC 8785/RFC 8032 vectors; golden fixtures;
table-driven negative/tamper cases; property tests; an ignored 100,000-envelope soak;
release-mode p50/p95/p99 benchmark; GitHub Actions matrix for Linux, macOS, and Windows.

**Target Platform**: Common library for macOS arm64, Linux arm64/x86_64, and Windows
x64. Hosted CI evidence covers Linux x86_64, macOS arm64 and Windows x64. Linux arm64
and physical Mac mini M4/Tier 1 proof remain pending.

**Project Type**: Library plus language-neutral schemas/fixtures and conformance
catalogue entry.

**Performance Goals**: Representative protected-plan canonicalization plus plan-ID
creation p95 <= 1 ms over 10,000 release iterations on recorded hardware; no hidden
network, filesystem, RNG, clock, or model calls.

**Constraints**: `#![forbid(unsafe_code)]`; no `std::path`, OS conditionals, floats,
`usize` on the wire, arbitrary JSON maps, defaulted security fields, or unbounded input.
All signed integers fit the RFC 8785/I-JSON safe range. Canonical wire is required at the
trust boundary; unknown schema/intent/algorithm/field is denied.

**Scale/Scope**: One schema (`helixos.plan-envelope/1`), one signature profile
(`ed25519`), one digest profile (`sha-256`), one intent (`host.file.patch`), payload <=
1 MiB, bounded identifiers/components/capability lists, and one stable fixture corpus.

## Constitution Check

*GATE: Passed before Phase 0 research; re-checked after Phase 1 design.*

- **Boundary — PASS**: The crate performs pure validation/cryptography and exposes no
  host effect. `decode_and_verify_plan` cannot dispatch.
- **Authority — PASS**: Schema, algorithms, key ID, task/lease/request bindings, target,
  budget, time, nonce, and epochs are protected. Unknown values deny.
- **Effects — PASS**: The sole file-patch effect carries exact replacement bytes, length,
  digest, precondition, recovery profile, and verification predicate. Runtime execution
  is explicitly OUT.
- **Data — PASS**: No production private key, secret store, egress, or sensitive fixture
  is introduced. Diagnostic errors never echo full input.
- **Portability — PASS**: Public contract types contain no native paths, clock/RNG, OS
  types, floats, or target cfg. One fixture corpus feeds all CI operating systems.
- **Performance — PASS**: Input limits, soak test, and release benchmark are specified;
  the benchmark records hardware/OS/profile/corpus/raw percentiles.
- **Evidence — PASS**: `PLAN-001`, negative tests, RFC vectors, dependency pins, ADR,
  schema, fixtures, CI matrix, and removal path are named below.

Post-design re-check: PASS. No constitutional deviation or complexity waiver is needed.

## Project Structure

### Documentation (this feature)

```text
specs/001-portable-signed-contracts/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── plan-envelope-v1.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
contracts/
├── schemas/
│   └── plan-envelope-v1.schema.json
└── fixtures/plan-envelope-v1/
    ├── valid-plan.json
    ├── valid-plan.protected.jcs
    ├── valid-plan.envelope.jcs
    ├── valid-plan.plan-id
    ├── valid-plan.public-key
    └── valid-plan.signature

conformance/
└── catalog.yaml

docs/adr/
└── 0005-canonical-signed-contracts.md

kernel/
├── Cargo.toml
└── helix-contracts/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs
    │   ├── canonical.rs
    │   ├── crypto.rs
    │   ├── digest.rs
    │   ├── error.rs
    │   ├── plan.rs
    │   ├── resource.rs
    │   └── validation.rs
    ├── examples/
    │   └── plan_benchmark.rs
    └── tests/
        ├── canonical.rs
        ├── conformance.rs
        ├── crypto.rs
        ├── portability.rs
        ├── property.rs
        ├── resource.rs
        └── soak.rs

.github/workflows/contracts.yml
```

**Structure Decision**: A leaf workspace crate prevents a big-bang migration and keeps
platform-neutral contracts out of the Windows-first legacy crate. Language-neutral
schemas and fixtures live at repository root so future adapters can consume them without
depending on Rust internals.

## Complexity Tracking

No Constitution Check violation requires justification. The extra crate is the smallest
boundary that prevents legacy `PathBuf`, mutable execution state, and custom
canonicalization from contaminating the stable wire contract.
