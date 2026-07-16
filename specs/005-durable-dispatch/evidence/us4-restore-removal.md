# PLAN-005 User Story 4 — Restore, Retention and Isolated Removal

**Captured**: 2026-07-13

**Updated**: 2026-07-15 after T094 immutable software evidence completed and the
post-evidence historical-workflow scoping plus T098 removal-workspace remediations
passed local validation

**Branch**: `codex/plan-005-durable-dispatch`

**Claim status**: `immutable software evidence passing at bf6f178; current post-evidence CI scoping and removal-workspace remediations locally validated; aggregate claim pending physical and external evidence`

This record closes the local evidence requested by T082 and T097. It combines focused
current PLAN-005 restore/corruption/retention suites with the historical complete
diagnostic removal run in a detached, no-checkout worktree. The source driver demonstrates
that the PLAN-005 executable surface can be removed while every frozen PLAN-001 through
PLAN-004 and legacy blob is restored byte-for-byte and its ordinary prerequisite tests
remain green. The state suites provide the production-path T096 restore matrix for
prepared, dispatching, adapter-received, consumed and ambiguous cuts plus two sovereign
T097 real-store matrices that inject, classify, fence, reopen and retain all 11
coordinator and all 11 adapter corruption classes. For the declared local subsystem
fixtures, the lifecycle and seeded-corruption clauses of SC-007 are now dynamic.

The filtered working-tree removal report documented below is the historical T070 local
diagnostic. At that time it correctly set both exact-commit eligibility flags to
`false` and did not satisfy SC-009 or the immutable part of SC-010. T094 later ran the
committed driver for exact source `bf6f178ff605b0541b5b5dabe9c4609af0218da9` in
immutable run `29387761127`; that closure is recorded separately in
`ci-immutable-bf6f178ff605b0541b5b5dabe9c4609af0218da9.md` and remains the
authoritative immutable software record.

## Current restore, corruption and retention suites

The following unchanged commands passed against the current PLAN-005 implementation:

```sh
cd kernel

cargo test --locked --all-features -p helix-coordinator-sqlite \
  --lib --test dispatch_restore --test dispatch_corruption --test dispatch_migration \
  -- --test-threads=1

cargo test --locked --all-features -p helix-dispatch-inbox-sqlite \
  --lib --test backup_restore --test corruption --test retention \
  --test production_receipt_readback \
  -- --test-threads=1
```

| Domain | Target | Result | Measured local time |
|---|---|---:|---:|
| Coordinator | library | 173/173 passed | 2.19 s |
| Coordinator | `dispatch_corruption` | 16/16 passed | 30.64 s |
| Coordinator | `dispatch_migration` | 12/12 passed | 1.44 s |
| Coordinator | `dispatch_restore` | 13/13 passed | 14.02 s |
| Adapter | library | 41/41 passed | 1.34 s |
| Adapter | `backup_restore` | 6/6 passed | 0.82 s |
| Adapter | `corruption` | 14/14 passed | 3.60 s |
| Adapter | `production_receipt_readback` | 8/8 passed | 1.61 s |
| Adapter | `retention` | 5/5 passed | 0.09 s |
| **Total** | libraries plus seven focused targets | **288/288 passed** | 0 failed |

The final exact T096 coordinator matrix completed 1/1 in 8.87 seconds; the exact adapter
matrix completed 1/1 in 0.71 seconds. Compilation and Cargo-lock waits are excluded
from all per-target measurements above.

### T096 production lifecycle restore matrix

The two exact commands were:

```sh
cd kernel

cargo test --locked --all-features -p helix-coordinator-sqlite \
  --test dispatch_restore \
  production_t096_restore_matrix_covers_every_declared_lifecycle_phase \
  -- --exact --nocapture --test-threads=1

cargo test --locked --all-features -p helix-dispatch-inbox-sqlite \
  --test backup_restore \
  production_adapter_backup_restore_matrix_is_fresh_pending_paused_and_idempotent \
  -- --exact --nocapture --test-threads=1
```

The coordinator command drives ordinary production stores into each declared cut,
backs up the live mutated roots under retained pause custody, verifies the signed
cross-store inventory, and restores the package into create-only coordinator and
adapter roots. `adapter-received` is the durable adapter `RECEIVED` state corresponding
to the user-story term `accepted`. The exact custody inventory is:

| Lifecycle cut | Coordinator grants | Adapter grants | Coordinator receipts | Adapter receipts | Expired grants | Possible handoffs | Adapter quarantines | Coordinator reconciliations | Reconciliation union |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Prepared | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Dispatching | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| Adapter-received | 1 | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 1 |
| Consumed | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 |
| Ambiguous | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 1 |

Every case proves fresh destination roots, exact `source + 1` instance, supervisor and
adapter epoch-observer generations, coordinator and adapter `RESTORE_PENDING`, control
state `PAUSED`, an unchanged append-only old-grant inventory, and zero automatic old
redelivery. The paired adapter matrix exercises empty, durable `RECEIVED` and durable
`CONSUMED` cuts from their live mutated stores; it proves zero automatic consumption,
zero automatic redelivery, refusal of new receive/re-consumption authority while
pending, exact retained readback evidence, no probe mutation, and an idempotent retry.
The coordinator retry likewise returns identical custody counts/digests and does not
append a second quarantine or generation.

The restore overlay permits only the exact `NULL -> source_generation` preparation
stamp after the dispatch metadata has entered `RESTORE_PENDING`. Its four positive,
negative, all-column mutation and atomic-rollback guards passed 4/4 in 0.02 seconds.
`cargo fmt --all -- --check` passed, and targeted all-target/all-feature Clippy passed
with `-D warnings` and no diagnostic.

### T097 exact-checkpoint corruption matrices

The coordinator `dispatch_corruption` target contains one exhaustive 11/11 real-store
matrix and five clean T096 lifecycle controls inside its 16/16 result. The adapter
`corruption` target contains its own exhaustive 11/11 matrix, three strict-valid
checkpoint-mismatch controls and the production-boundary checks inside its 14/14 result.
The corresponding classifier units passed 7/7 coordinator and 5/5 adapter. An independent
run of the three `production_coordinator_caller*` tests passed 3/3 in 9.67 seconds.

The closed coordinator taxonomy is orphan grant, orphan receipt, grant-digest conflict,
receipt-digest conflict, cross-generation conflict, store rollback, root rollback,
generation rollback, history truncation, generation reuse and cross-store disagreement.
The adapter taxonomy replaces the first two and rollback names with its sovereign inbox,
receipt and adapter-history equivalents. Every case is injected into SQLite state; none
is accepted from a caller-provided expected label.

The exact-checkpoint contract established by these tests is:

- the default-compiled `SqliteCoordinatorStoreV2` adapter caller captures one opaque PAUSE
  proof before its two coordinator leases, delegates that exact proof to the public hidden
  adapter audit, and rechecks PAUSE and both complete V2 graphs before return;
- an exact strict checkpoint and all five clean lifecycle shapes return clean with zero
  mutation; a different fully strict keyed, lifecycle or mutable checkpoint returns the
  payload-free `CHECKPOINT_MISMATCH` error with zero source fence and zero custody;
- a synthetic coordinator migration projection proves the same strict-schema-valid
  mismatch behavior, but does not claim a runtime production migration transition;
- the feature-gated coordinator classifier uses closed strict roots, two held
  `BEGIN IMMEDIATE` cuts and file-identity rechecks. It is real-store core evidence, not
  a claim that a production coordinator PAUSE surface is already wired;
- classified corruption commits the redacted source fence before external custody. Exact
  retry, custody failure, uncertain commit readback, alias/hardlink refusal and writer-race
  controls preserve that order; ordinary open, handoff, receive and consume paths remain
  refused after the fence, including the exercised pre-opened handles;
- outputs expose only bounded reason/generation state. Paths, canonical wires, root IDs,
  digests, PAUSE evidence and seeded canaries remain absent from public results/debug and
  retained external evidence.

### State conclusions and evidence classes

- The coordinator V2 and adapter V1 manifests are closed and canonical. Their generation
  counts, inventories, cross-store orphan declarations, backup order and three distinct
  verifier purposes/signature domains are exhaustive; no private signing key is a
  manifest member and no backup step or signer profile is substitutable.
- The dynamic T076 production backup path is coordinator first, adapter second and
  signed index last. Its success/fault/substitution cases fail closed instead of
  publishing a partial top-level package.
- The dynamic T096 matrix restores five separate paired coordinator/adapter lifecycle
  packages into fresh roots. It rotates identities/epochs, enters `RESTORE_PENDING` and
  `PAUSED`, redelivers and automatically consumes zero old grants, and binds every
  possible effect to the exact adapter quarantine or retained coordinator
  reconciliation union shown above.
- The two T097 matrices dynamically inject every declared orphan, digest conflict,
  cross-generation conflict, rollback, truncation, generation-reuse and cross-store-
  disagreement class. Each incident creates one permanent local source fence before the
  independent custody copy; both roots remain refused after close/reopen and exact retry
  reuses the original incident.
- V1 opens do not auto-upgrade. V2 preserves public historical grant/receipt
  verification, while an old V1 binary refuses V2 without repair, downgrade or raw
  version relabelling.
- Coordinator and adapter authoritative history reject delete, replace, whole-history
  prune, generation reuse and tombstone reversal without mutation. Production exposes
  no prune/compact/delete/reuse/downgrade authority surface.

These are bounded subsystem roots and injected corruption cases. FR-030, FR-031, FR-032
and the exercised SC-007/migration/retention boundaries have passing local coverage for
their declared fixtures. They do not establish a production-machine restore or a wired
production coordinator corruption-audit PAUSE surface.

## Frozen protected baseline manifest

`specs/005-durable-dispatch/evidence/removal-protected-files.json` binds every recursively
tracked leaf blob in baseline commit
`6f8dfdd5194792e8592cd10ebaaf8828833effbe`:

| Property | Exact value |
|---|---|
| Baseline tree | `d1f51cc3ba5d0e42ade27fb9aefda01750093971` |
| Protected leaves | 495 |
| Modes | 490 × `100644`; 5 × `100755` |
| Full NUL inventory SHA-256 | `3495ead55ab40e469940c5a6a585064d75137eaba9af9b5adeaf51b553fba7b9` |
| NUL path inventory SHA-256 | `0a7a3e4cda89f78a7ccda8184c9c78f7bc52073b92003d7db669e4817ac0ec11` |
| Manifest file SHA-256 | `6c9422f47fd65ba7866750666a3f0e4c4c1e35944b8a1506c4a6ffa34ab2edf2` |
| Driver SHA-256 | `be5f28c0f544280c4af2124a57853e988c3d58ec9e6152df7717ffe39cf6a79e` |

Each entry contains path, Git mode, object type, blob OID and content SHA-256. The driver
reconstructs both canonical NUL streams, resolves all 495 Git blobs and recomputes their
content digests before creating any evidence output. The manifest remains outside its
own baseline inventory and is itself pinned by the driver. PLAN-005 evidence, workflow
and tool paths are forced to LF by `.gitattributes` so exact bytes remain portable on
Windows checkouts. The repinned removal class contains both the
`dispatch_maintenance_faults.rs` target and the coordinator base-quarantine integration
explicitly. It retains the PLAN-006 specification tree as audit history, removes the
classified PLAN-006 Phase 1 fixture/crate/Graphify executable surface, and restores the
two earlier-plan baseline test paths that Phase 1 changes. The full PLAN-005 evidence
module passes 38/38 after this synchronization; the prerequisite PLAN-004 evidence
module passes 24/24, for 62/62 evidence-tool tests.

The 27 user-owned dirty Rust paths remain protected through their committed baseline
blobs but their local bytes are never copied into the removal source, edited, formatted,
staged or treated as evidence. Their exact sorted path-list digest remains
`cd755b4089997ff229a31980b81473eba48504de241903fccef0e908fdbea530`.

## Historical isolated removal procedure and result (T070)

T097 did not rerun or rewrite the protected T070 removal artifacts. Their most recent
local command was:

```sh
python3 tools/plan005_removal_drill.py \
  --repository . \
  --baseline 6f8dfdd5194792e8592cd10ebaaf8828833effbe \
  --output plan-005-release-evidence/removal/t070-refresh-20260714
```

The output is ignored local evidence. The driver created an owned detached worktree with
`--no-checkout`, loaded the source index explicitly, materialized raw Git blobs without
smudge filters or EOL conversion, overlaid only classified working-tree deltas and then:

| Removal observation | Result |
|---|---:|
| Baseline paths differing before removal | 21 |
| Baseline blobs already exact before removal | 474/495 |
| Allowlisted baseline paths restored from Git objects | 21 |
| PLAN-005 executable/derived added files removed one-by-one | 131 |
| Constrained specification/evidence/verification files retained | 26 |
| Baseline blobs exact after removal and after all tests | 495/495 |
| Post-removal files | 521 = 495 baseline + 26 retained audit files |
| Post-removal Git index tree | `d1f51cc3ba5d0e42ade27fb9aefda01750093971` |
| Excluded user-owned working-tree paths observed and ignored | 27/27 |
| Source delta SHA-256 | `cab1ff43789cce3f7312d065741d8347837716648d9b82aa18b187c26226ed04` |

Those counts and digests remain historical T070 observations. The current post-evidence
policy names 30 possible baseline restoration paths: 23 cover the T097 coordinator
base-quarantine integration, three restore the PLAN-001/PLAN-004 workflow scoping
remediation and its PLAN-004 policy test, and four restore the T098 PLAN-004
workspace-manifest integration in both tools and their two living documentation files.
The implementation and policy bytes pass the filtered-source classifier and 62 evidence
tests. The 24 PLAN-004 tests include a real Cargo workspace whose multiline-string fake
`[workspace]` block and quoted real `"members"` key previously bypassed textual parsing;
semantic Cargo metadata now exposes the hidden downstream member and rejects the legacy
empty-downstream binding; a decoy manifest path is rejected as well. A complete
diagnostic isolated removal run, executed
immediately before this result was saved to Graphify, restored 30 baseline paths,
removed 172 added paths, retained 36 non-executable audit paths, recovered all 495
protected files and the exact eight-package PLAN-001-through-PLAN-004 workspace, and
returned six zero exit codes with `tests_skipped=false`; its source-delta SHA-256 was
`06bd0acd859dbc62d3492eccd2f511b4262f015783da4b34122d12d0f30702c7`.
These bytes postdate source `bf6f178ff605b0541b5b5dabe9c4609af0218da9`.
They therefore do not replace the immutable T094 record or change the catalogued
historical counts; binding these newer bytes would require a separate exact-commit
immutable run, which is not claimed here.

The removal policy classifies every delta exactly once. Baseline changes outside the
closed restoration list, additions outside the closed removal/retained classes,
symlinks, traversal, unexpected modes/types and unrelated Graphify memory names all fail
closed. Added Graphify files are removed individually; the broad prefix is never passed
to `rmtree`, so its 116 protected baseline blobs cannot be deleted. Retained
`specs/005-durable-dispatch/` entries must be non-executable `.md`, `.json` or `.sql`
files. Cargo uses a fresh absent target outside the repository, worktree and evidence
output. The exact index, complete file inventory, protected bytes/modes and absence of
every removed file are revalidated after all Cargo commands.

## Prerequisite behavior after removal

Post-removal `cargo metadata --locked --offline --no-deps` returned exactly these eight
baseline packages and no PLAN-005 package:

```text
helix-contracts
helix-coordinator-sqlite
helix-plan-eligibility
helix-plan-preparation
helix-replay-sqlite
helixos-kernel
helixos-mcp-shim
helixos-provision
```

The driver then ran five locked, offline, all-target/all-feature command groups in a
clean environment. Across their ordinary targets, 1,169 tests passed, zero failed and
37 remained explicitly ignored exactly as selected by the unchanged baseline suites.
Ignored release/slow gates are not counted as passing evidence.

| Group | Passed | Failed | Ignored | Log SHA-256 |
|---|---:|---:|---:|---|
| PLAN-001 contracts | 51 | 0 | 1 | `094d88ea4ec7d6e91af8394afa1f249b46351a6d80ed6d0e95c9062309e2dc12` |
| PLAN-002 eligibility | 55 | 0 | 2 | `4457bd70c8e9bcf12ea888475c9a57c36c737fcd78912cbd65d49bd3225c3014` |
| PLAN-003 replay | 109 | 0 | 11 | `b04f36b2b1241ac26a0fa26d69ac08d58f89bdd1f56ec6db367ab4630b2d5f73` |
| PLAN-004 preparation/coordinator | 847 | 0 | 23 | `7053b2e02a5cfe4a7ca2deef6e4fdda8352921ebe41aedd313145b6b8f942332` |
| Legacy MVP0 packages | 107 | 0 | 0 | `d6685040f4fb953517954d6f46071150350d9dadf895bf4ea4866f1d12e3e0c0` |

No test or build command recreated a removed source file, changed the baseline index,
or changed any protected byte/mode. The original checkout's porcelain status shape was
unchanged; the report deliberately does not claim content-hash equality for the dirty
working tree.

## Historical local raw evidence identities (T070)

| Local output | SHA-256 |
|---|---|
| `report.json` | `47b2184631fec001fb2cec9787c2aaebd559f6f22b60b3b4fe44175aae79201a` |
| `removal-inventory.json` | `b3e1e017f18c6840254546803ac8e69ed37f4241a5dbed60ee9dd74525a506f2` |
| `metadata-after-removal.json` | `5eb333cc9b6f612ca02dda385430407766eccfa291b1d539df968bf6c4c0a2fd` |
| `protected-files-before.json` | `af85a19401c89c17f25201dcd811191d4b28531e7c2b67d440c9e563897acd92` |
| `protected-files-after.json` | `1059662aed9ca18a531647d67fb946a8e81a98c43dfe0f3edf500618d0b004a9` |

Secret, credential, authorization-header, home-directory and private temporary-path
scans of the output returned no matches. Logs redact the repository, removal root,
evidence output, Cargo target, home and path-valued toolchain environment variables.

## SC-007/SC-010 interpretation and limits

The combined local evidence establishes the following bounded subsystem boundary:

1. five distinct production-path lifecycle restores cannot revive, redeliver or
   automatically consume old authority, and every possible effect remains in an exact
   adapter quarantine or coordinator reconciliation union;
2. both 11-class real-store matrices fence and retain every seeded orphan, conflict,
   rollback, truncation, generation-reuse and cross-store disagreement without execution
   authority; strict-valid different checkpoints instead return zero-mutation mismatch;
3. after source removal, every executable package and baseline runtime file is exactly
   the PLAN-001 through PLAN-004/legacy baseline, so retained PLAN-005 specifications
   and verification tools have no Cargo/runtime path that can interpret an artifact as
   live dispatch authority.

For the declared local subsystem fixtures, SC-007's lifecycle and seeded-corruption
clauses are dynamically covered. This does not prove a full-machine restore, sovereign
activation or production coordinator PAUSE wiring. The source driver also does not feed
a retained PLAN-005 artifact to a post-removal baseline binary; absence of such a live
interpretation path is established structurally by the exact baseline source/package
inventory.

The source driver does not delete or decommission a production state root, and its own
report explicitly says retained-state authority is not assessed without the paired state
evidence above. This is software/subsystem evidence only: not secure erasure, not private
key destruction, not a full-machine backup or restore, not physical power-loss testing,
not a production supervisor/provider or host effect, not the physical M4 benchmark and
not Tier 1 readiness. The project and catalogue remain `pending-evidence`.

No file was staged, committed or pushed by this local evidence run.
