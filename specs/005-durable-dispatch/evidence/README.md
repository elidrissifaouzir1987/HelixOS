# PLAN-005 Evidence Baseline

**Captured**: 2026-07-13

**Updated**: 2026-07-15

**Branch**: `codex/plan-005-durable-dispatch`

**Source and removal baseline**: `6f8dfdd5194792e8592cd10ebaaf8828833effbe`

**Status**: `pending-evidence`

This record establishes the clean tracked source boundary before PLAN-005 executable
changes. The baseline is both the source anchor for implementation and the comparison
target for the later isolated removal drill. At capture time, the branch `HEAD` exactly
equalled the baseline commit. PLAN-005 software implementation and bounded local
subsystem evidence are now complete; T094 exact-commit publication, immutable workflow
verification and evidence cataloguing are in progress. The aggregate release claim
remains pending.

## Evidence and nonclaims

This file began as baseline bookkeeping and also records the bounded release-evidence
transition. It does not prove a real host effect, physical
power-loss durability, production supervisor or IPC integration, production recovery,
full-machine restore, secure erasure, performance on the declared physical profile, or
Tier 1 readiness. It grants no execution or restoration authority. Until immutable
artifacts are bound in `conformance/catalog.yaml`, the aggregate PLAN-005 claim remains
`pending-evidence`.

No credential material, sensitive canonical payload, or machine-local checkout path is
recorded here.

## Graphify reflection snapshot

The current secret-free Graphify reflection contains 171 retained memories: 128 marked
`useful`, 2 marked `dead_end`, and 41 marked `corrected`. It is a derived retrieval and
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
