# PLAN-005 Evidence Baseline

**Captured**: 2026-07-13

**Updated**: 2026-07-15

**Branch**: `codex/plan-005-durable-dispatch`

**Source and removal baseline**: `6f8dfdd5194792e8592cd10ebaaf8828833effbe`

**Status**: `pending-evidence`

This record establishes the clean tracked source boundary before PLAN-005 executable
changes. The baseline is both the source anchor for implementation and the comparison
target for the later isolated removal drill. At capture time, the branch `HEAD` exactly
equalled the baseline commit. PLAN-005 software implementation and immutable hosted
software evidence are complete at exact source commit
`bf6f178ff605b0541b5b5dabe9c4609af0218da9`. The aggregate release claim remains
pending because the physical and external gates listed below are still open.

## Evidence and nonclaims

This file began as baseline bookkeeping and also records the bounded release-evidence
transition. It does not prove a real host effect, physical
power-loss durability, production supervisor or IPC integration, production recovery,
full-machine restore, secure erasure, performance on the declared physical profile, or
Tier 1 readiness. It grants no execution or restoration authority. Binding immutable
software artifacts in `conformance/catalog.yaml` does not close those gates, so the
aggregate PLAN-005 claim remains `pending-evidence`.

No credential material, sensitive canonical payload, or machine-local checkout path is
recorded here.

## Immutable software evidence

GitHub Actions [run `29387761127`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127)
completed successfully from a `push`, attempt 1, with all nine policy, platform,
supply-chain/removal and attestation jobs passing. The exact evidence record is
[ci-immutable-bf6f178ff605b0541b5b5dabe9c4609af0218da9.md](ci-immutable-bf6f178ff605b0541b5b5dabe9c4609af0218da9.md),
SHA-256 `a2a0e26a12822e0711f933ff98ef36a50f2f4e371fc4688bf30d1b71fd3cc5c1`.

| Subject | Preserved artifact | ZIP SHA-256 | Attestation |
|---|---|---|---|
| Linux x86_64 | [artifact `8332458950`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332458950) | `58ac45f2f2e4b3fdd90c62e52b2fa621d4ca9e3ac37d5383ae7ff7425479d747` | [`35386312`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386312) |
| macOS arm64 | [artifact `8332319700`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332319700) | `487d33e301a267b79fe5369c6361f915428d51f75f1c0ab912591525ee9a2bf4` | [`35386322`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386322) |
| Windows x64 | [artifact `8332641362`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332641362) | `899c2e5b8f487e16baa60e69fcf079fa25266164843032fa3f355d08e65868c1` | [`35386319`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386319) |
| Release bundle | [artifact `8332754639`](https://github.com/elidrissifaouzir1987/HelixOS/actions/runs/29387761127/artifacts/8332754639) | `10802a33838c2edc53db8c9db64fed9d37c4ad10b1afb125fc6adf89a4e96025` | [`35386320`](https://github.com/elidrissifaouzir1987/HelixOS/attestations/35386320) |

All four artifacts were current and unexpired when catalogued and expire at
`2026-10-13T03:57:01Z`. The full exact verifier passed in the immutable Ubuntu release
job before upload and attestation. The evidence record separately documents the
post-download macOS digest, attestation and host-independent semantic audit, including
the deliberately host-bound live-toolchain comparison that prevents claiming a second
full local verifier pass.

## Graphify reflection snapshot

The current secret-free Graphify reflection contains 180 retained memories: 129 marked
`useful`, 2 marked `dead_end`, and 49 marked `corrected`. It is a derived retrieval and
work-memory summary, not an authority source. Specifications, ADRs, source code, tests,
Git history, evidence, and the conformance catalogue remain authoritative whenever a
derived graph edge, memory, or reflection differs from them.

## Exact protected baseline inventory

The protected inventory is defined as every recursively tracked leaf blob in the Git
tree of the baseline commit, including its path, file mode, object type, and blob object
ID. Untracked working-tree files, subdirectories as containers, and working-tree bytes
outside that committed tree are not members. This definition deliberately protects all
PLAN-001 through PLAN-004 and legacy tracked bytes; the removal drill must restore any
baseline file changed by PLAN-005 before comparing the inventory.

The canonical inventory is the NUL-terminated byte stream produced by:

```sh
BASE=6f8dfdd5194792e8592cd10ebaaf8828833effbe
git ls-tree -r -z --full-tree "$BASE"
```

Its compact, deterministic identity is:

| Property | Value |
|---|---|
| Baseline commit | `6f8dfdd5194792e8592cd10ebaaf8828833effbe` |
| Baseline tree object | `d1f51cc3ba5d0e42ade27fb9aefda01750093971` |
| Tracked leaf blobs | 495 |
| Regular modes | 490 at `100644`; 5 at `100755` |
| Full NUL inventory SHA-256 | `3495ead55ab40e469940c5a6a585064d75137eaba9af9b5adeaf51b553fba7b9` |
| NUL path inventory SHA-256 | `0a7a3e4cda89f78a7ccda8184c9c78f7bc52073b92003d7db669e4817ac0ec11` |

Reproduce the cardinality and both SHA-256 values without locale-sensitive parsing:

```sh
BASE=6f8dfdd5194792e8592cd10ebaaf8828833effbe
git ls-tree -r -z --full-tree "$BASE" | tr -cd '\0' | wc -c
git ls-tree -r -z --full-tree "$BASE" | shasum -a 256
git ls-tree -r -z --full-tree --name-only "$BASE" | shasum -a 256
```

The commit and tree object make the complete 495-path set directly recoverable, while
the full-stream digest binds every path, mode, type, and blob ID. The path-only digest
independently binds the exact ordered path set.

## Excluded user-owned Rust changes

The following 27 tracked Rust paths were locally modified at capture and are excluded
from every PLAN-005 edit, stage, commit, format, or bulk rewrite:

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

The sorted newline-terminated list above has SHA-256
`cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530`.
At capture, `git status --short` reported exactly these 27 paths in the three excluded
packages, each as an unstaged tracked modification, and reported no other modified Rust
path. Reproduce the set and digest with:

```sh
git diff --name-only -- \
  kernel/helixos-kernel \
  kernel/helixos-mcp-shim \
  kernel/helixos-provision | LC_ALL=C sort
```

The exclusion records ownership only. These working-tree bytes are not evidence, are
not part of the committed baseline inventory, and must remain untouched by PLAN-005.
