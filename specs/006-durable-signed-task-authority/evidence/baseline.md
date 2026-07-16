# PLAN-006 Phase 1 Frozen Baseline

Recorded on 2026-07-16 for tasks T001 through T008. This evidence separates the
merged PLAN-005 removal anchor from the later clean source commit on which PLAN-006
setup started.

## Evidence boundary and nonclaims

- This file proves repository ownership, package direction, locked historical test
  results, schema smoke results and byte identities for the Phase 1 setup surface.
- It does not claim that signed authority, canonical verification, durable HLXA
  storage, projection admission, release gates or any PLAN-006 user story exists.
- The Phase 1 fixture arrays are intentionally empty and are not conformance evidence.
- Explicitly ignored Rust tests remain ignored; they are reported, not counted as
  passing.
- Specs, contracts, source and retained test outputs remain authoritative over this
  summary.

## Frozen anchors

| Meaning | Commit | Tree |
|---|---|---|
| Merged PLAN-005 removal baseline | `c324f528dc76007a599005e5cc054dcbe1370b1a` | `c70a3f2157498dd880822f97ef74d3d4757347d7` |
| Clean PLAN-006 Phase 1 source | `551421cca045e192655b69cccdfd9e0c9dd2f6ce` | `e25eab4ed41fcc8e514557a49062d86c4fecfa70` |

The 27-path difference between these anchors consists of the merged PLAN-006 design
and registration artifacts plus eight retained PLAN-005 evidence/test/tool
corrections. `kernel/Cargo.toml` and `kernel/Cargo.lock` are byte-identical at both
anchors. The removal anchor remains the protected-object reference; the later commit
is the clean implementation starting point.

## Full protected-object inventory

The complete NUL-delimited recursive tree stream at the PLAN-005 removal anchor has:

| Measurement | Result |
|---|---:|
| Blob entries | 703 |
| Mode `100644` | 698 |
| Mode `100755` | 5 |
| SHA-256 of full `git ls-tree -r -z --full-tree` stream | `d5de7d3aff3d062616b0b8ba5f7e8f874f545f40da4842ffe521bd32ca5a1913` |
| SHA-256 of NUL-delimited path stream | `6540b97939b5ec9437d62875c1781d68013e0670576a5653ba887695f060a3f1` |

Reproduction:

```sh
REMOVAL_BASE=c324f528dc76007a599005e5cc054dcbe1370b1a

git rev-parse "$REMOVAL_BASE^{tree}"
git ls-tree -r -z --full-tree "$REMOVAL_BASE" |
  tr -cd '\0' |
  wc -c
git ls-tree -r -z --full-tree "$REMOVAL_BASE" |
  shasum -a 256
git ls-tree -r -z --full-tree --name-only "$REMOVAL_BASE" |
  shasum -a 256
git ls-tree -r "$REMOVAL_BASE" |
  awk '{count[$1]++} END {for (mode in count) print mode, count[mode]}' |
  LC_ALL=C sort
```

## Excluded user-owned Rust paths

The exact sorted newline-terminated inventory has SHA-256
`cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530`:

```text
kernel/helixos-kernel/src/approval/card.rs
kernel/helixos-kernel/src/approval/mod.rs
kernel/helixos-kernel/src/approval/server.rs
kernel/helixos-kernel/src/audit.rs
kernel/helixos-kernel/src/driver/files.rs
kernel/helixos-kernel/src/driver/mod.rs
kernel/helixos-kernel/src/driver/search.rs
kernel/helixos-kernel/src/intention.rs
kernel/helixos-kernel/src/lib.rs
kernel/helixos-kernel/src/main.rs
kernel/helixos-kernel/src/mtls.rs
kernel/helixos-kernel/src/pipeline.rs
kernel/helixos-kernel/src/plan.rs
kernel/helixos-kernel/src/policy.rs
kernel/helixos-kernel/src/runtime.rs
kernel/helixos-kernel/src/scope.rs
kernel/helixos-kernel/tests/approval_it.rs
kernel/helixos-kernel/tests/bootstrap_it.rs
kernel/helixos-kernel/tests/mtls_it.rs
kernel/helixos-kernel/tests/restart_it.rs
kernel/helixos-mcp-shim/src/config.rs
kernel/helixos-mcp-shim/src/kernel_client.rs
kernel/helixos-mcp-shim/src/lib.rs
kernel/helixos-mcp-shim/src/main.rs
kernel/helixos-mcp-shim/src/mcp.rs
kernel/helixos-mcp-shim/tests/shim_kernel_e2e.rs
kernel/helixos-provision/src/main.rs
```

The implementation was performed in a separate clean worktree. The primary checkout
retained exactly these 27 unstaged paths, with zero staged protected paths, throughout
Phase 1.

Portable clean-scope reproduction:

```sh
SOURCE_BASE=551421cca045e192655b69cccdfd9e0c9dd2f6ce
PRIMARY_CHECKOUT=${PRIMARY_CHECKOUT:?set the user-owned checkout}
CLEAN_SCOPE=${CLEAN_SCOPE:?set an unused worktree directory}

git worktree add --detach "$CLEAN_SCOPE" "$SOURCE_BASE"
test -z "$(git -C "$CLEAN_SCOPE" status --porcelain)"

git -C "$PRIMARY_CHECKOUT" diff --name-only -- ':(glob)kernel/**/*.rs' |
  LC_ALL=C sort |
  tee /tmp/plan006-excluded-rust-paths.txt
test "$(wc -l < /tmp/plan006-excluded-rust-paths.txt | tr -d ' ')" = 27
test "$(shasum -a 256 /tmp/plan006-excluded-rust-paths.txt | awk '{print $1}')" = \
  cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530
test -z "$(git -C "$PRIMARY_CHECKOUT" diff --cached --name-only \
  -- ':(glob)kernel/**/*.rs')"

while IFS= read -r protected_path; do
  git -C "$CLEAN_SCOPE" diff --quiet "$SOURCE_BASE" -- "$protected_path"
done < /tmp/plan006-excluded-rust-paths.txt
```

## Existing package and lock baseline

The frozen workspace contains these 11 packages:

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

| State | Workspace packages | External locked packages | Total lock package records |
|---|---:|---:|---:|
| Frozen PLAN-005 baseline | 11 | 209 | 220 |
| PLAN-006 Phase 1 setup | 15 | 209 | 224 |

The only new lock records are the four local PLAN-006 packages. No new external
package was introduced.

Normal dependency direction is:

```text
helix-task-authority-contracts
  -> pinned canonical/crypto/serialization primitives

helix-task-authority
  -> helix-task-authority-contracts
  -> helix-contracts

helix-task-authority-sqlite
  -> helix-task-authority
  -> helix-task-authority-contracts
  -> pinned bundled SQLite and supporting primitives

helix-task-authority-projections
  -> helix-task-authority
  -> reviewed PLAN-002, PLAN-004 and PLAN-005 public seams
```

There are zero normal dependency edges from an existing package into a PLAN-006
package. The projection package has no coordinator, dispatch-inbox or legacy-runtime
dependency.

The first focused dependency-policy run correctly went red because four existing tests
freeze the exact set of direct consumers. Only those expected-consumer lists were
extended with `helix-task-authority-projections`; no other allowlist was weakened and
no existing production source or wire contract changed. The corrected focused results
were:

| Guard | Result |
|---|---:|
| `helix-plan-eligibility --test portability` | 6 passed |
| `helix-plan-preparation --test contract` | 10 passed |
| `helix-coordinator-sqlite --test portability` | 8 passed |
| `helix-plan-dispatch --test portability` | 7 passed |

The first pull-request policy run then exposed one separate PLAN-004 removal guard
whose exact downstream workspace set predated PLAN-006. Its expected set was extended
with the four new PLAN-006 packages in `tools/tests/test_plan004_evidence.py`. This is
a fifth test-only PLAN-006 integration edit, is included in the exact-removal
footprint, and does not change PLAN-004 tooling or production behavior.

The same run exposed the next PLAN-005 downstream gates. Its removal manifest now
deletes the four PLAN-006 crate prefixes, fixture prefix and PLAN-006 Graphify memory,
and restores the two earlier-plan baseline test paths not already covered by its
policy. The inbox portability guard now recognizes that same exact ten-prefix removal
set. The first exact hosted supply-chain build then proved that the four local lock
records also change the two full-lock-bound PLAN-005 artifacts even though the selected
production closure is unchanged. The evidence test now compares the live graph
directly, its exact digest is
`b52d4bfbe69c74f66c420279dd81abfa16bdd64b05d4fdc8d371cf72bae8ef48`,
and the pinned RustSec report digest is
`f3cc655afe7d84a1a14d8dc67753c224a68270bfe9151b13e4d5688d5dc30bb7`
for 224 locked records, zero vulnerabilities and the same retained
`RUSTSEC-2025-0134` informational warning. Package, edge, external dependency,
license-inventory and SBOM oracles remain unchanged. These are the sixth and seventh
test-only integration edits, making eleven existing test/policy/evidence edits in the
exact PLAN-006 removal footprint. The corrected focused results are 8/8 inbox
portability tests and 38/38 PLAN-005 evidence tests. The synchronized manifest SHA-256
is `6c9422f47fd65ba7866750666a3f0e4c4c1e35944b8a1506c4a6ffa34ab2edf2`.

## Toolchain identity

| Component | Exact identity |
|---|---|
| Rust | `rustc 1.96.1 (31fca3adb 2026-06-26)` |
| Cargo | `cargo 1.96.1 (356927216 2026-06-26)` |
| Rust host / LLVM | `aarch64-apple-darwin` / `22.1.2` |
| Host | `macOS 26.5.2 (25F84)`, `arm64` |
| Python | `3.9.6` |
| System SQLite CLI | `3.51.0` |
| Bundled Rust SQLite | `rusqlite 0.40.1`, `libsqlite3-sys 0.38.1`, SQLite `3.53.2` |
| Bundled SQLite source ID | `2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24` |

## Locked historical and post-setup Rust results

The frozen-source column was executed from a separate detached worktree at exact
commit `551421cca045e192655b69cccdfd9e0c9dd2f6ce`, tree
`e25eab4ed41fcc8e514557a49062d86c4fecfa70`. The worktree was clean before and after
the run. An external Cargo target cache was reused only for build artifacts; Cargo
compiled the workspace packages from the detached source paths.

The Phase 1 column was then executed in the implementation worktree after adding the
four local packages, the four exact expected-consumer updates and the synchronized
downstream policy guards. This separates the unchanged source baseline from the
post-setup regression result.

```sh
SOURCE_BASE=551421cca045e192655b69cccdfd9e0c9dd2f6ce
BASELINE_WORKTREE=${BASELINE_WORKTREE:?set an unused worktree directory}

git worktree add --detach "$BASELINE_WORKTREE" "$SOURCE_BASE"
test -z "$(git -C "$BASELINE_WORKTREE" status --porcelain)"
(
  cd "$BASELINE_WORKTREE/kernel"
  cargo test --locked -p PACKAGE
)
test -z "$(git -C "$BASELINE_WORKTREE" status --porcelain)"

# Repeat in the Phase 1 implementation worktree.
cd kernel
cargo test --locked -p PACKAGE
```

| Package | Frozen passed | Frozen failed | Frozen ignored | Phase 1 passed | Phase 1 failed | Phase 1 ignored |
|---|---:|---:|---:|---:|---:|---:|
| `helix-contracts` | 56 | 0 | 1 | 56 | 0 | 1 |
| `helix-plan-eligibility` | 55 | 0 | 2 | 55 | 0 | 2 |
| `helix-replay-sqlite` | 105 | 0 | 9 | 105 | 0 | 9 |
| `helix-plan-preparation` | 103 | 0 | 0 | 103 | 0 | 0 |
| `helix-coordinator-sqlite` | 537 | 0 | 12 | 537 | 0 | 12 |
| `helix-dispatch-contracts` | 26 | 0 | 1 | 26 | 0 | 1 |
| `helix-plan-dispatch` | 89 | 0 | 0 | 89 | 0 | 0 |
| `helix-dispatch-inbox-sqlite` | 104 | 0 | 5 | 104 | 0 | 5 |
| `helixos-kernel` | 67 | 0 | 0 | 67 | 0 | 0 |
| `helixos-mcp-shim` | 27 | 0 | 0 | 27 | 0 | 0 |
| `helixos-provision` | 13 | 0 | 0 | 13 | 0 | 0 |
| **Total** | **1,182** | **0** | **30** | **1,182** | **0** | **30** |

No excluded path was formatted or staged by either run.

## Frozen SQLite schema smoke

Each source SQL file was applied to a new temporary database with the system SQLite
CLI. The coordinator V2 overlay was applied after Preparation V1, as required.

| Schema | Source SHA-256 | App ID | User version | Objects | FK violations | Integrity |
|---|---|---:|---:|---:|---:|---|
| Replay V1 | `7749bd426803f589c6a4dd0643d0b19d76aa38bc0645bc74db205f24e687d53d` | 1212962898 | 1 | 5 | 0 | `ok` |
| Preparation V1 | `e7b7c6c70f356afe4e45b3e2c7210b38c4ccc0f69a012cbdaddd103a8827880e` | 1212962883 | 1 | 49 | 0 | `ok` |
| Coordinator V2 overlay | `87799d20f2cba3cd9d84e8c7d06d21c9becf06fc1a33f2a0e61832879948d41f` | 1212962883 | 2 | 136 | 0 | `ok` |
| Adapter inbox V1 | `f6d4917175038ff726ec6d27a1c59de7210f58a1079cf428586130862c050724` | 1212962889 | 1 | 47 | 0 | `ok` |

Smoke-query shape:

```sh
sqlite3 "$DB" < "$SCHEMA"
sqlite3 "$DB" 'PRAGMA application_id;'
sqlite3 "$DB" 'PRAGMA user_version;'
sqlite3 "$DB" \
  "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%';"
sqlite3 "$DB" 'PRAGMA foreign_key_check;'
sqlite3 "$DB" 'PRAGMA integrity_check;'
```

## Source, lock, manifest, schema and fixture digests

### Workspace and package manifests

| File/state | SHA-256 |
|---|---|
| Frozen `kernel/Cargo.toml` | `e5cf270c1d0554de0536bc9f456e8cbab32a5b7bf5b69e75fddf306fd7dd58a5` |
| Frozen `kernel/Cargo.lock` | `f18941ac90749f8eb9adffc2e4e9b91e1d9705da8c0cad0c9fe53b451759ff4d` |
| Phase 1 `kernel/Cargo.toml` | `7c5c76a5a619fb8b3757b98a8ca1ec5d35a8a5402f21186d733a6f00cd3722d5` |
| Phase 1 `kernel/Cargo.lock` | `1ee27ea28ed2c51167acb180f79bf5f3722ca26a1c775013c6f7ce3082d87d3c` |
| `helix-task-authority-contracts/Cargo.toml` | `60e27b51d7752ccea78055ba90b15c888b2dddbdfd73cc23c46153931b8c9784` |
| `helix-task-authority/Cargo.toml` | `71816b857b5839b4999c1c4537e22e47f01720002532ec93f133d08eb5e52f5c` |
| `helix-task-authority-sqlite/Cargo.toml` | `9c08c743095524e9d58400329dacc2f10df24e1f63d01e2e9f4db52faaf9f389` |
| `helix-task-authority-projections/Cargo.toml` | `b0adc5e142c718dead9c0a66d1785fdf47a6588fccf0b8f13ae4061317a3897c` |

### PLAN-006 normative contracts

| File | SHA-256 |
|---|---|
| `approval-decision-v1.schema.json` | `a0b8358f0e839e489c682cc9e4247fda769ff5ad43a8f7a45bddc5aaabb34868` |
| `fault-boundaries-v1.json` | `26a8f7cf9a517bf141ee8e723a1c5fe14fef28849faa755bca2a81ac492b5c2b` |
| `human-request-grant-v1.schema.json` | `59f16ea3b07d9048d8162ad0064e273e83f95ec940887c7123cc2865d36dcfc9` |
| `signed-task-authority-v1.md` | `adad71c048c0f36203150a7e6f06c289448a326037a7ad102bd283044657f1c1` |
| `task-authority-backup-manifest-v1.schema.json` | `bae6b77d744b3fb2b8ce7e0b91bede48de7a521a353da90f3e3aca2a9fb12174` |
| `task-authority-projections-v1.md` | `60599c3aa602a626b7ea3d8fea27b978b44032a1c818ed6e4e7b83aa58b78cdf` |
| `task-authority-store-schema-v1.sql` | `f2a1124440c68d50da60e678c16dabccfe0588048ecc63d3cd7d3074bd92c5b8` |
| `task-lease-v1.schema.json` | `2188dc4c988513b834cab4461cc88e0fd67bb0d6f9504d40871936430da972fa` |

### Phase 1 fixture skeleton

| File | SHA-256 |
|---|---|
| `README.md` | `3653dca26b1dbb110f5fce4b23802eba853a894d0c057672f24f90b7a9d5016a` |
| `golden/README.md` | `d84d08218305782d007c63cfce8a21bc9d88839f5d02e88733cfe935f0e0214d` |
| `cases.json` | `374edc611935d2112132fb7834ae5f5004cb115dbe57bb29349c2d9d1e1bde80` |
| `chain-cases.json` | `12ad5cfb21c67751755f5d54513f446f862d8a261384cab664e6c93229271e83` |
| `expected-outcomes.json` | `c7b6ff017e5e4457c94be2e8978cd4a60c69cd998b0d94b90079ec51e3fceadc` |
| `public-keys.json` | `3e8cec62e75121769b767bcf8406ba543c63e96f81a832ecc18ac0e38869bfaf` |

## Phase 1 setup validation

| Command or check | Result |
|---|---|
| `cargo test --locked` for each of the four PLAN-006 packages | PASS; setup surfaces contain 0 tests by design |
| `cargo check --locked --workspace --all-targets` | PASS |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | PASS |
| Package-scoped `cargo fmt -- --check` for the four new packages | PASS |
| SQLite package with `test-fault-injection` | PASS; feature is non-default |
| SQLite package with `controlled-benchmark` | PASS; feature is non-default |
| PLAN-004 evidence/removal unit suite | PASS; 24 tests |
| PLAN-005 evidence policy suite that reuses the PLAN-004 guard | PASS; 38 tests |
| Four fixture JSON files parsed as JSON | PASS |
| Tracked non-authority `golden/` placeholder survives commit and clone | PASS |
| Recursive PLAN-006 LF attributes, including future `golden/` files | PASS |
| Generated PLAN-006 evidence/output ignore rules | PASS |

## Phase 1 interpretation gate

The historical baseline is green, the four new packages add no external lock
dependency, dependency direction remains toward existing public seams, and the
user-owned Rust paths remain excluded. This permits Phase 2 test-first work; it does
not satisfy any later authority, story, conformance or release gate.
