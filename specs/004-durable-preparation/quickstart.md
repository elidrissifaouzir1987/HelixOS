# Quickstart: Validate Durable Preparation Before Dispatch

This guide validates feature 004 after implementation. It is a synthetic test/runbook,
not a preparation, approval, dispatch or recovery authority path. Never point these
commands at production coordinator, replay or recovery roots.

## 1. Preconditions

- Rust `1.96.1`, `rustfmt` and `clippy` are installed through
  `kernel/rust-toolchain.toml`.
- Build resolution uses the committed `kernel/Cargo.lock`.
- Test roots are new dedicated directories on a provisioner-validated local filesystem;
  do not use NFS/SMB, cloud-synced folders, removable media or a production root.
- Synthetic recovery input contains reviewed public sentinel bytes only.
- Backup/restore tests use a reviewed public synthetic provisioner key fixture; production
  restore uses pinned sovereign trust/revocation configuration and never test keys.
- At least 2 GiB of free local space is available for builds, crash fixtures, backup
  packages and the 10,000-sample benchmark.
- The supervisor/authority/recovery implementations used here are deterministic
  conformance fakes and do not establish a production recovery or Tier 1 claim.

Confirm the pinned environment from the repository root:

```sh
cd kernel
rustc --version --verbose
cargo --version --verbose
cargo metadata --locked --no-deps --format-version 1
```

Expected:

- Rust/Cargo report `1.96.1`;
- metadata lists `helix-plan-preparation` and `helix-coordinator-sqlite` after
  implementation;
- no dependency is resolved outside the lockfile.

## 2. Frozen prerequisite baseline

Run the complete existing trust chain before feature-specific tests:

```sh
cargo test --locked -p helix-contracts
cargo test --locked -p helix-plan-eligibility
cargo test --locked -p helix-replay-sqlite
```

Expected:

- PLAN-001 canonical bytes, plan IDs, signatures and fixtures remain unchanged;
- PLAN-002 eligibility outcomes and one-shot marker semantics remain unchanged;
- PLAN-003 claim/conflict, crash, deadline and backup/restore behavior remains green;
- the new read-only replay verifier does not issue/release a claim or change global
  claimant-generation semantics.

## 3. Fast quality gate

```sh
cargo fmt \
  --package helix-contracts \
  --package helix-plan-eligibility \
  --package helix-replay-sqlite \
  --package helix-plan-preparation \
  --package helix-coordinator-sqlite \
  -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Then verify the non-default fault surface separately:

```sh
cargo check --locked -p helix-coordinator-sqlite \
  --features test-fault-injection --all-targets
cargo clippy --locked -p helix-coordinator-sqlite \
  --features test-fault-injection --all-targets -- -D warnings
```

Expected: no formatting drift, lint warning, unsafe code, default-build fault hook,
network/async dependency or adapter dependency.

## 4. Contract and type boundary

```sh
cargo test --locked -p helix-contracts --test preparation_claims
cargo test --locked -p helix-plan-preparation --test contract
cargo test --locked -p helix-coordinator-sqlite --test contract
```

Expected:

- `PlanPreparationClaimsV1` exposes exact authenticated preparation facts without
  changing plan-v1 wire bytes;
- compile-fail cases prove contexts/guards/receipts/markers are not Serde values;
- `EligiblePlanV1` and `PreparedOperationV1` cannot be cloned or publicly constructed;
- no effect adapter accepts any feature-004 type;
- all `Debug`, `Display` and error-source projections are redacted stable codes.

## 5. Fresh comparison and replay verification

```sh
cargo test --locked -p helix-plan-preparation --test freshness -- --nocapture
cargo test --locked -p helix-replay-sqlite --test preparation_verification -- --nocapture
```

Expected:

- one coherent eligible plan reaches the store once;
- preliminary replay denial proves zero operation/budget-preflight and zero
  recovery-provider calls; final guarded replay verification is repeated;
- operation/budget preflight denial occurs before and proves zero recovery-provider
  calls; a concurrent reservation after successful preflight is caught transactionally;
- changing every generation, digest, decision, boot, epoch or bound independently
  returns its frozen first-denial code and causes zero operation/budget/event mutation;
- equality with UTC expiry or monotonic deadline denies;
- a change during recovery is caught by the new final context;
- guard acquisition/release follows the exact global order;
- PAUSE/HALT-before-permit rolls back/denies, permit-before-PAUSE is total-ordered and
  bounded, and ambiguous permit resolution returns no marker;
- permit deadline is exactly the earlier caller deadline or 250 ms after entry;
  confirmed rollback performs zero readback, only explicit uncertainty reads back, and
  an unclassified result resolves ambiguous;
- killing/hanging the permit owner or reaching its supervisor deadline independently
  activates PAUSE, blocks new permits and requires exact readback without relying on
  process cleanup; a resumed worker cannot commit with an expired permit;
- exact replay row verifies even after unrelated claims advance the global generation;
- missing/conflicting/unhealthy replay state denies without calling `claim_once` again.

## 6. Budget exactness and reconciliation

```sh
cargo test --locked -p helix-coordinator-sqlite --test budget -- --nocapture
cargo test --locked -p helix-coordinator-sqlite --test budget_property -- --nocapture
cargo test --locked -p helix-coordinator-sqlite --test cancellation -- --nocapture
```

Expected:

- exact, minus-one and plus-one cases pass for cost, action, egress and recovery bytes;
- at least 100,000 generated vectors match an independent checked oracle with no
  overflow, partial hold or aggregate overspend;
- a scope must already exist and match lease/binding/generation/currency/price table;
- same reservation or operation IDs cannot be rebound;
- `PREPARING -> FAILED` releases the exact stored vector and appends one failure event;
- exact repeated cancellation never double-releases or appends twice;
- cancellation/failure holds an exact live sovereign no-dispatch guard through commit;
  caller booleans, row absence, wrong operation/attempt/state/epoch and expired/revoked
  guards leave both operation and reservation unchanged;
- ambiguous preparation never releases automatically;
- file/concurrency/duration capacity is not falsely reported as reserved.

## 7. Recovery provider protocol

```sh
cargo test --locked -p helix-plan-preparation --test recovery -- --nocapture
cargo test --locked -p helix-coordinator-sqlite --test recovery_integration -- --nocapture
```

Expected:

- exact synthetic compensable material publishes manifest-last and is labeled
  conformance-only;
- missing, short, extra, corrupt, substituted, stale, unpublished, retired or
  differently bound material denies;
- capacity exact/minus-one/plus-one cases are enforced;
- an authenticated L2 irreversible plan records no-material evidence and makes zero
  provider calls;
- failed compensation is never reclassified irreversible;
- publication/cleanup use mutually exclusive guards and the fixed recovery-before-DB
  lock order;
- ambiguous/orphan material remains quarantined; one absent read never deletes it;
- retirement persists `RETIREMENT_PENDING`, publishes an immutable tombstone, then
  persists `RETIRED_TOMBSTONE`; crashes at either boundary reconcile without requiring
  retired bytes or losing original digest/length evidence.
- a true orphan uses definitive no-reference proof plus a permanent
  `ORPHAN_RETIREMENT_AUTHORIZED` quarantine tombstone before provider retirement, never
  fabricates `FAILED`, and reconciles both crash boundaries idempotently.

## 8. Thread and process contention

Run normal semantic coverage:

```sh
cargo test --locked -p helix-coordinator-sqlite --test contention -- --nocapture
```

Run the controlled release evidence workload:

```sh
cargo test --locked --release -p helix-coordinator-sqlite \
  --test contention -- --ignored --nocapture
```

Expected release workload:

- 100 rounds x 64 synchronized threads;
- 20 rounds x 8 synchronized child processes;
- one coherent `PREPARING` operation, held reservation and prepared event per contested
  operation;
- only the original exact attempt can receive a positive marker;
- distinct operations sharing insufficient allowance commit only within all aggregate
  limits;
- reopen passes every cross-record and budget-sum invariant.

## 9. Deadline, revocation and no detached work

```sh
cargo test --locked -p helix-coordinator-sqlite --test deadline -- --nocapture
cargo test --locked -p helix-plan-preparation --test revocation -- --nocapture
```

The held-writer test keeps `BEGIN IMMEDIATE` while preparation waits. Expected:

- already expired/unavailable clocks deny without mutation;
- at least 1,000 controlled attempts return by the caller monotonic deadline plus at
  most 50 ms scheduler tolerance on the controlled target;
- after return, release the blocker, observe at least 250 ms and reopen; no late
  operation/reservation/event appears;
- acknowledged commit followed by expiry/revocation remains durable but returns no
  positive marker;
- caller-deadline-first, 250 ms-ceiling-first and equality cases resolve within the
  controlled 50 ms scheduler tolerance, activate PAUSE and leave no reusable permit;
- no test claims hard cancellation of an in-flight filesystem flush.

## 10. Deterministic crash and ambiguity matrix

Fault hooks must be absent from default builds. Enable them only in the dedicated test:

```sh
cargo test --locked -p helix-coordinator-sqlite \
  --features test-fault-injection \
  --test production_restore_conformance -- --nocapture
cargo test --locked -p helix-coordinator-sqlite \
  --test restore_maintenance_api -- --nocapture
cargo test --locked --release -p helix-coordinator-sqlite \
  --features test-fault-injection \
  --test process_crash -- --ignored --nocapture
```

The release matrix MUST match the closed exhaustive inventory in
[Durable Preparation Contract section 14](contracts/durable-preparation-v1.md#14-closed-v1-fault-boundary-inventory)
exactly. Every slash-separated action is an independent fault point, including both
operation/budget preflights, final recovery revalidation, separate final UTC/monotonic
samples and the backup generation recheck. The frozen registry and derived matrix remain
exactly 123 boundaries and 167 controlled cases on every host; no registry subset
satisfies this gate.

Execution is then partitioned only by the reviewed production platform contract:

- macOS and Linux execute all 167 process-kill cases;
- Windows v1 first proves the exact public `RESTORE_PLATFORM_UNSUPPORTED` refusal before
  package capture, PAUSE or destination mutation, then executes the remaining 150
  production-reachable cases; and
- the Windows exclusion is exactly the 14 frozen `restore` boundary IDs, expanding to
  17 controlled cases because `restore_recovery_package_imported` has four occurrences.

Excluding any non-restore case, changing the frozen 123/167 inventory, accepting a
weaker Windows restore fallback or omitting the separate refusal oracle fails the gate.

Expected: reopen proves no coordinator operation, one complete invariant-valid
`PREPARING`, one atomic `FAILED` transition, or explicit quarantine. No boundary yields
`DISPATCHING`, a grant, adapter call, false absence or blind retry. Evidence is labeled
process-kill/fault-injection, not power-loss.

## 11. Schema, corruption and no-pruning checks

```sh
cargo test --locked -p helix-coordinator-sqlite --test schema_corruption -- --nocapture
cargo test --locked -p helix-coordinator-sqlite --test retention -- --nocapture
```

Expected fail-closed cases include wrong application ID, unknown/newer version, altered
table/index, invalid canonical plan, broken operation/reservation/event/recovery link,
bad held totals, duplicate generation, partial quarantine, mismatched provisioner root
identity, unavailable WAL/FULL/recursive-trigger profile, read-only/full store and unknown root members.
Lifecycle negatives also prove `RESTORE_PENDING` cannot return to `ACTIVE`, root identity
cannot be rewritten outside the one restore transition, and orphan
`RETIRED_TOMBSTONE` cannot regress or use non-monotonic generations.

Retention tests prove no automatic prune/delete API; canonical plans, failed rows,
released reservations, delivered events and quarantine/retirement tombstones remain.
Operation-bound recovery retirement requires durable `FAILED`, exact budget
reconciliation, exclusive cleanup guard and full definite non-reference proof. A true
orphan instead requires the guarded definitive proof and permanent orphan-resolution
tombstone; no operation is created.

## 12. Quiescent backup and clean restore

```sh
cargo test --locked -p helix-coordinator-sqlite --test backup_restore -- --nocapture
```

Expected:

- PAUSE and provider/coordinator maintenance guards establish one quiescent cut;
- SQLite online backup is used; raw live DB/WAL copying is not;
- recovery inventory entries are strictly sorted/unique, count equals length, capacity
  covers material length, and duplicate/reordered/count-mismatched cases deny;
- both byte-exact package-binding known-answer vectors pass, and recovery-inventory and
  top-level files are exact RFC 8785 bytes with no duplicate keys, BOM or trailing
  newline before their lowercase SHA-256 digests are checked;
- `complete_reference_set` covers every operation reference, active quarantine and
  provider-enumerated package; unrecorded extras are quarantined before the cut and any
  pending operation/orphan retirement blocks backup;
- top-level `operation_retirement_pending` and `orphan_retirement_pending` both equal
  zero and match coordinator evidence, quarantine, provider enumeration and recovery
  inventory `no_retirement_pending=true`;
- provider groups are sorted/unique by profile/provider/generation and a single backup
  covers permanently retained rows from multiple provider generations;
- material-present entries carry bytes; retired-tombstone entries carry the immutable
  retirement manifest without requiring retired bytes; pending retirement blocks backup;
- top-level manifest publishes, then a detached provisioner-signed provenance
  attestation publishes last and binds its exact digest, source root/instance identity,
  generations, inventory, protection profile and signing profile/key;
- coherent package substitution, missing/early/bad attestation and unknown/revoked
  signing profile/key deny before either root is published;
- missing, extra, corrupt, unknown or mismatched members quarantine the package;
- restore targets new empty coordinator/recovery roots, establishes WAL/FULL, closes,
  reopens and passes full invariants;
- coordinator and recovery metadata independently persist the same restore identity,
  attestation digest and `RESTORE_PENDING`; one-root-only or mismatched states quarantine;
- pending roots require new boot/instance/fencing epochs and deny ordinary open,
  prepare, retirement and dispatch; Feature 004 cannot activate them;
- old `PREPARING` can only become `FAILED` under maintenance or stay quarantined.

## 13. Versioned conformance and portability

```sh
cargo test --locked -p helix-plan-preparation --test conformance -- --nocapture
cargo test --locked -p helix-coordinator-sqlite --test conformance -- --nocapture
cargo test --locked -p helix-coordinator-sqlite \
  --features test-fault-injection \
  --test conformance_execution -- --test-threads=1 --nocapture
cargo run --locked -p helix-coordinator-sqlite \
  --example durable_preparation_corpus
```

Load only:

- `contracts/fixtures/durable-preparation-v1/cases.json`;
- `contracts/fixtures/durable-preparation-v1/expected-outcomes.json`.

Expected: identical case IDs, stable outcome summary, expected-outcomes digest, SQL
schema digest and JSON-schema digests on macOS arm64, Linux x64 and Windows x64. No
target-OS branch changes common comparison, budget, recovery or preparation semantics.
The runner's canonical redacted summary digest is
`e0dac29c01276a7f6168a83bff51accefc86a129f1046065ebea5f136bbddd87`.

## 14. Redaction, dependency and removal proof

```sh
cargo test --locked -p helix-plan-preparation --test redaction
cargo test --locked -p helix-coordinator-sqlite --test redaction
cargo test --locked -p helix-coordinator-sqlite --test restore_maintenance_api
cargo test --locked -p helix-coordinator-sqlite --test portability
cargo tree --locked -p helix-plan-preparation
cargo tree --locked -p helix-coordinator-sqlite
```

Seed sentinels for native paths, identifiers, nonces, digests, canonical/replacement/
preimage content, user budget values and raw provider/SQLite errors. Expected: none
appear in public errors, `Debug`, metrics, events, fixtures or release summaries.

Source/dependency checks prove:

- the default restore surface exports only the two non-constructible redacted evidence
  projections and no public producer, maintenance limit/error, authority or operation;
- no adapter, legacy driver or MCP shim depends on feature-004 marker/receipts;
- no network, async runtime, system SQLite, dynamic extension or ambient clock enters
  the new trust path;
- removing the new crates/catalog/workflow leaves PLAN-001/002/003 and legacy baseline
  behavior unchanged.

## 15. Physical M4 release benchmark

Choose new dedicated local coordinator and synthetic recovery roots. The benchmark must
refuse non-empty roots and never print them.

```sh
export HELIX_BENCH_HARDWARE='public-mac-mini-m4-cpu-memory-storage-label'
export HELIX_BENCH_FILESYSTEM_ASSURANCE='validated-local-apfs-lock-create-sync-label'
export HELIX_BENCH_AT_REST_PROFILE='approved-local-encrypted-volume-label'
cargo run --locked --release -p helix-coordinator-sqlite \
  --features controlled-benchmark \
  --example durable_preparation_benchmark -- \
  --coordinator-root /dedicated/local/test-root \
  --recovery-root /dedicated/local/recovery-root \
  --warmups 500 \
  --samples 10000 \
  --output ../specs/004-durable-preparation/evidence/benchmark-mac-mini-m4.json
```

Expected coordinator gate:

- p95 <= 25 ms;
- p99 <= 100 ms;
- raw sorted samples and exact hardware, OS/build/architecture, toolchain, SQLite source,
  durability/at-rest profile, corpus/schema digests, concurrency, commit and artifact
  SHA-256 are retained;
- exact clean source commit is required before release evidence is accepted.

Run recovery transfer as a separate workload/artifact by declared material size. Do not
include it in or relabel it as the coordinator latency threshold.

## 16. Supply-chain bundle and isolated removal drill

The evidence tooling itself is standard-library Python and is exercised before the
release jobs:

```sh
python3 -m unittest discover -s tools/tests -p 'test_plan004_evidence.py' -v
```

The hosted `release-evidence` job pins the RustSec and SPDX repositories and invokes
`tools/plan004_supply_chain.py`; do not replace those exact revisions with an ambient
scanner database for an immutable run. To exercise removal locally from a commit whose
full history is available:

```sh
python3 tools/plan004_removal_drill.py \
  --repository . \
  --output /dedicated/redacted/removal-evidence \
  --source-commit "$(git rev-parse HEAD)" \
  --cargo-target-dir /dedicated/temporary/cargo-target
```

Expected: the drill uses a detached clean worktree, restores the exact pre-Feature-004
`Cargo.lock`, exposes exactly the six baseline packages, proves protected bytes
unchanged, and passes PLAN-001, PLAN-002 semantics, PLAN-003 and legacy MVP-0. It must
record the sole structural PLAN-002 skip by exact test name; it must not patch or
silently filter any other test. Generated reports contain placeholders such as
`<removal-root>`, `<repo>` and `<home>`, never machine paths or credentials.

The final immutable workflow-dispatch must publish four non-empty current-run
artifacts: Linux x64, macOS arm64, Windows x64 and the release bundle. A separate job
resolves each artifact through the GitHub API, verifies its run and commit provenance,
and attests the exact `upload-artifact` digest. Until those URLs and digests are entered
in the catalogue, the overall claim remains `pending-evidence`.

## 17. Release interpretation

A passing local or hosted suite proves only the named contract/profile. It does not by
itself prove:

- production compensable recovery from the synthetic provider;
- power-loss, sector-loss, directory-fsync or secure-erasure behavior;
- restored-system activation;
- dispatch, adapter or target-effect safety;
- Mac mini M4 evidence when run on hosted/unknown hardware;
- Tier 1 readiness while external evidence/catalog fields remain pending.
