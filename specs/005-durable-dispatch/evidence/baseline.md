# PLAN-005 Locked Phase 1 Baseline

**Captured**: 2026-07-13

**Branch**: `codex/plan-005-durable-dispatch`

**Source/removal baseline and current HEAD**:
`6f8dfdd5194792e8592cd10ebaaf8828833effbe`

**Claim status**: `pending-evidence`

This is a local synthetic no-effect baseline. It proves that the frozen PLAN-001 through
PLAN-004 inputs still build and that the PLAN-005 setup artifacts are byte-identified.
It is not immutable CI, physical power-loss, production supervisor/provider, physical
M4 performance, full-machine restore, secure-erasure, host-effect, or Tier 1 evidence.
The 27 user-owned Rust changes listed in [README.md](README.md) remained unstaged and
were neither rewritten nor included as PLAN-005 evidence.

## Toolchain and workspace

```text
rustc 1.96.1 (31fca3adb 2026-06-26)
cargo 1.96.1 (356927216 2026-06-26)
host: aarch64-apple-darwin
LLVM: 22.1.2
OS observed locally: macOS 26.5.2, arm64
workspace packages: 11
listed default test entries: 848
listed benchmarks: 0
```

The 11 locked workspace packages are:

```text
helix-contracts
helix-coordinator-sqlite
helix-dispatch-contracts
helix-dispatch-inbox-sqlite
helix-plan-dispatch
helix-plan-eligibility
helix-plan-preparation
helix-replay-sqlite
helixos-kernel
helixos-mcp-shim
helixos-provision
```

The new portable orchestration crate depends directly only on `getrandom` and
`helix-dispatch-contracts`. It does not add a consumer edge to
`helix-plan-preparation`, and the independent inbox reaches no preparation crate
transitively. The three new dependency trees contain no `helixos-kernel`, Tokio,
network client, UUID/ambient-time crate, system SQLite, or dynamic SQLite extension.

## Locked validation results

The following final commands passed without changing source files or frozen inputs:

```sh
cd kernel
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked -p helix-coordinator-sqlite --test portability
cargo check --locked -p helix-dispatch-contracts -p helix-plan-dispatch \
  -p helix-dispatch-inbox-sqlite --all-features
cargo clippy --locked -p helix-dispatch-contracts -p helix-plan-dispatch \
  -p helix-dispatch-inbox-sqlite --all-features -- -D warnings
```

The complete default workspace test run passed. Tests already declared ignored for
release contention, soak, process-kill, fault-entry, or physical evidence remained
ignored; this baseline does not relabel them as executed evidence. The protected
PLAN-004 portability target passed 8/8 tests.

An initial internal setup attempt gave `helix-plan-dispatch` a direct
`helix-plan-preparation` dependency. The protected PLAN-004 portability test correctly
rejected the additional consumer. That edge was removed rather than weakening the
allowlist; the final commands above then passed. The empty non-default
`controlled-benchmark` and `test-fault-injection` feature names remain reserved without
forwarding PLAN-004 features.

## Frozen prerequisite custody

The following roots were compared directly with the baseline commit and produced no
changed path: the five PLAN-001 through PLAN-004 Rust crates, their four fixture roots,
and the PLAN-003/PLAN-004 contract directories. Their current byte inventory contains
197 files. A length-delimited SHA-256 over each sorted repository-relative path and its
exact bytes is:

```text
2a4f61f5f243335107d227d34ef09e989e13a6f07b6dbcdadf2125a792e44f73
```

The full 495-blob committed baseline tree and its canonical inventory digests are
recorded separately in [README.md](README.md). Workspace membership, the lockfile, new
PLAN-005 paths, catalogue/roadmap state, and the explicit LF rules are intended Phase 1
changes and are not falsely included in the unchanged prerequisite digest above.

## Workspace and manifest digests

| Artifact | SHA-256 |
|---|---|
| `kernel/Cargo.toml` | `e5cf270c1d0554de0536bc9f456e8cbab32a5b7bf5b69e75fddf306fd7dd58a5` |
| `kernel/Cargo.lock` | `b2a236776bb127c36ec884aa73b9d4a1d2aa85fbad39ea8865a54277af213075` |
| `kernel/helix-dispatch-contracts/Cargo.toml` | `35130191f851e5d5c65cd8f9c5f070efa53f14e7a699c82a96fec8e7e660db48` |
| `kernel/helix-plan-dispatch/Cargo.toml` | `0da4ac4fc1d8abb4ea6335666cc3950b64957a3427b65080b4b2cc659ae8b377` |
| `kernel/helix-dispatch-inbox-sqlite/Cargo.toml` | `845fa762aeae6dd727910290d44e42772b8c536182ae3daa24a2cc4e26f7b82b` |

`Cargo.lock` adds only the three internal PLAN-005 package records and their reviewed
edges. The Phase 2 contract correction adds `unicode-normalization = 0.1.25` as a direct
dispatch-contract edge; that exact external version was already locked transitively, so
no previously locked external package version changed.

## Contract, schema, registry, and fixture digests

| Artifact | SHA-256 |
|---|---|
| `contracts/adapter-inbox-schema-v1.sql` | `f6d4917175038ff726ec6d27a1c59de7210f58a1079cf428586130862c050724` |
| `contracts/coordinator-dispatch-schema-v2.sql` | `ee05a9e4db7934ae6ba2be9536595c0b100fec7bc3d8991d884674aa1ceb2440` |
| `contracts/dispatch-backup-manifest-v1.schema.json` | `ae7d12714aa995dc8779aaba29da268259ba1783dfa2e16a9385f7eed03daa67` |
| `contracts/execution-grant-v1.schema.json` | `f326cacda2a4fca49dc3278e758ed56ef178fef63cad9ff37eb0f506db6f021a` |
| `contracts/execution-receipt-v1.schema.json` | `d112c63c236df12004f9ef85fc4dd1e69443cc68044f42640dcaa6dba4f901e3` |
| `contracts/fault-boundaries-v1.json` | `afef6e0b580a8ea62906227e25c59e7b067c7aa5dc55d5458d9ccf92f0b1ff26` |
| `fixtures/durable-dispatch-v1/README.md` | `094b3cc4fdd7dcc0eab792e9273e86fd1225b61ec6eba00920ddad664ebc20d5` |
| `fixtures/durable-dispatch-v1/cases.json` | `70d91b274d70c974ecd198dc1d70698346fbaa8c9785cd824f0aa2a84427601a` |
| `fixtures/durable-dispatch-v1/expected-outcomes.json` | `8a34adce4a2d4c20cdc033eb1586d37c7d1281cde3c7645f82b4cc4e401198a4` |

Paths in the table are relative to `specs/005-durable-dispatch/` for contracts and to
`contracts/` for fixtures.

All six JSON artifacts parse. The grant and receipt protected schemas remain closed at
69/69 and 25/25 required properties. The parametric corpus contains 143 unique cases
and 143 exact outcomes, removes every protected field once, retains five authentic
signed bases, covers the four forbidden pre-`RECEIVED` receipt codes, and verifies all
five base digests/signatures against the two retained public keys. No private key or
seed is retained.

### Phase 2 fixture correction

Decoder implementation exposed two semantically inconsistent values in the original
otherwise authentic receipt bases. The `GRANT_EXPIRED` base decided before the grant's
exclusive deadline, and the `SUPERVISOR_EPOCH_MISMATCH` base repeated the grant epoch.
The corrected bases decide at the deadline and observe a distinct next supervisor epoch
and observer generation respectively. A fresh ephemeral receipt key was generated only
for this correction, all four receipt bases were resigned under the unchanged receipt
purpose/domain, and the private key was discarded without being printed or retained.
The public receipt key and the two affected receipt digests changed; the grant key/base,
143-case cardinality, case IDs, mutation inventory and 143 expected outcomes did not.
The digest table above supersedes the earlier Phase 1 `cases.json` digest.

The fault registry contains exactly 90 ordered boundaries and 180 declared
in-process/process-kill cases. Loading the coordinator overlay after the PLAN-004 V1
DDL with foreign keys enabled yields application ID `1212962883`, user version `2`, an
empty foreign-key check, and `integrity_check=ok`. Loading the adapter schema alone
yields application ID `1212962889`, user version `1`, the same two checks passing.

## Reproduction commands

```sh
python3 -m json.tool specs/005-durable-dispatch/contracts/execution-grant-v1.schema.json >/dev/null
python3 -m json.tool specs/005-durable-dispatch/contracts/execution-receipt-v1.schema.json >/dev/null
python3 -m json.tool specs/005-durable-dispatch/contracts/dispatch-backup-manifest-v1.schema.json >/dev/null
python3 -m json.tool specs/005-durable-dispatch/contracts/fault-boundaries-v1.json >/dev/null
python3 -m json.tool contracts/fixtures/durable-dispatch-v1/cases.json >/dev/null
python3 -m json.tool contracts/fixtures/durable-dispatch-v1/expected-outcomes.json >/dev/null
python3 tools/update_roadmap.py --check
git diff --check
```

These local results authorize implementation of the next task phase only. They do not
promote the aggregate PLAN-005 catalogue claim beyond `pending-evidence`.
