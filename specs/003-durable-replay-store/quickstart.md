# Quickstart: Validate the Durable Replay Claim Store

This guide validates feature 003 after implementation. It is a runbook, not an
authorization path. All commands run from the repository checkout and create only
synthetic replay data below an explicitly selected local test directory.

## 1. Preconditions

- Rust `1.96.1` from `kernel/rust-toolchain.toml` is installed with `rustfmt` and
  `clippy`.
- The test/benchmark root is a dedicated directory on a known local filesystem. Do not
  use NFS/SMB, iCloud Drive, OneDrive, Dropbox, a network home, or a removable volume
  whose flush/locking behavior has not been validated.
- Provisioning also attests working cross-process exclusive file locks, exclusive file
  creation, same-volume hard links and regular-file `sync_all` (normally APFS on the
  target Mac mini, NTFS on Windows and a validated local Linux filesystem).
- At least 1 GiB of free space is available for build, WAL, crash and backup fixtures.
- No command is run against a production operation database.

Confirm the pinned environment:

```powershell
Set-Location C:\path\to\HelixOS\kernel
rustc --version --verbose
cargo --version --verbose
cargo metadata --locked --no-deps --format-version 1
```

Expected: Rust reports `1.96.1`; metadata lists `helix-replay-sqlite`; dependency
resolution is locked.

## 2. Fast quality gate

```powershell
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Expected:

- no format or lint warning;
- feature 001 and 002 suites remain green;
- the new crate compiles with `#![forbid(unsafe_code)]`;
- no default build contains the test fault hook.

## 3. Contract and evaluator integration

```powershell
cargo test --locked -p helix-replay-sqlite --test contract
cargo test --locked -p helix-replay-sqlite --test eligibility_integration
```

The integration scenario evaluates a coherent feature-002 fixture through the
production claimant, closes the process view, reopens the store, and evaluates it again.

Expected:

```text
first coherent evaluation  -> EligiblePlanV1 from Claimed(receipt)
exact evaluation after open -> REPLAY_ALREADY_CLAIMED
same nonce/different binding -> REPLAY_BINDING_CONFLICT
same operation/different binding -> REPLAY_BINDING_CONFLICT
```

No repeat returns an old receipt as positive admission.

## 4. Versioned conformance corpus

```powershell
cargo test --locked -p helix-replay-sqlite --test conformance -- --nocapture
cargo test --locked -p helix-replay-sqlite --all-features --test conformance_execution -- --test-threads=1
```

The loader reads only:

- `contracts/fixtures/durable-replay-store-v1/cases.json`;
- `contracts/fixtures/durable-replay-store-v1/expected-outcomes.json`.

Expected: every declared case ID occurs exactly once; the summary and expected-outcomes
digest match on Windows x64, Linux x64 and macOS arm64. The corpus contains synthetic
public identifiers only. The all-feature executable projection runs all 68 setup/action/
fault/state cases through real runtime paths with zero blocked cases. The default build
runs 47 public cases and explicitly reports the 21 crash/fault scenarios that are
compiled only under `test-fault-injection`; no fault selector exists in production.

## 5. Thread and process contention

Run the normal-size semantic tests:

```powershell
cargo test --locked -p helix-replay-sqlite --test contention -- --nocapture
```

Run the release evidence workload:

```powershell
cargo test --locked --release -p helix-replay-sqlite --test contention -- --ignored --nocapture
```

Expected release workload:

- 100 rounds x 64 synchronized threads;
- 20 rounds x 8 synchronized child processes;
- exactly one `Claimed` for each contested fresh key;
- exact losers are `AlreadyClaimed`;
- incompatible losers are `BindingConflict`;
- after reopen, claimant generation/count and all indexes are consistent.

The worker protocol uses stdin/stdout readiness barriers and `std::process::Child`, not
shell commands or timing sleeps.

## 6. Deadline and no-detached-work proof

```powershell
cargo test --locked -p helix-replay-sqlite --test deadline -- --nocapture
```

The test process holds `BEGIN IMMEDIATE` while the claimant attempts a bounded call.
After the method returns, the holder releases the lock and the store is checked again.

Expected:

- already-expired and unavailable clock: `Unavailable`, zero mutation;
- held writer until deadline: `Unavailable` by deadline plus the declared scheduler
  tolerance on controlled hardware;
- no row appears after the call returns;
- acknowledged commit followed by a reached/unavailable clock: `Ambiguous`, permanent
  row retained;
- no test claims hard cancellation of an in-flight VFS flush.

Shared CI records elapsed values but is not authoritative for the 50 ms scheduler tail.

## 7. Deterministic process-crash matrix

Fault hooks are absent from default builds. Enable them only for this test executable:

```powershell
cargo test --locked --release -p helix-replay-sqlite --features test-fault-injection --test process_crash -- --ignored --nocapture
```

The parent kills a child after each of the 18 frozen boundaries:

```text
initialization: initialization_schema_staged, initialization_committed
claim: opened, begin_acquired, generation_updated, row_inserted, before_commit,
       commit_returned, before_result_ack
checkpoint: checkpoint_before_mutation, checkpoint_returned
backup: backup_database_complete, backup_manifest_staged, backup_published
restore: restore_reserved, restore_database_staged, restore_published,
         restore_profile_verified
```

Expected:

- claim boundaries through `before_commit`: reopen finds no claim and unchanged
  generation;
- claim boundaries after `commit_returned`: reopen finds one complete row, both indexes
  and receipt;
- initialization, checkpoint, backup and restore boundaries reopen or verify as a
  complete pre-state or complete post-state; a pending restore is never claimable;
- every reopen passes full integrity and application invariants;
- private commit/readback fault cases never map a possible commit to `Unavailable` and
  never retry the mutation.

Evidence must say `process-kill`. It is not Mac power-cut or sector-loss evidence.

## 8. Schema, corruption and initialization race

```powershell
cargo test --locked -p helix-replay-sqlite --test schema_corruption -- --nocapture
```

Expected fail-closed cases include:

- concurrent initialization produces one complete v1 store;
- a killed concurrent initializer converges through the distinct live-init intent,
  while a zero/torn role without that intent is never promoted;
- wrong application ID;
- newer/unknown `user_version`;
- deleted/changed table or index;
- invalid nonce/digest/generation row;
- inconsistent metadata count/max generation;
- truncated or bit-flipped database;
- unavailable WAL/FULL profile;
- read-only/unavailable store.

No claim attempt repairs these cases. Public output contains only frozen error codes.

## 9. Live backup and clean restore

```powershell
cargo test --locked -p helix-replay-sqlite --test backup_restore -- --nocapture
```

The positive test creates enough claims for a multi-step online backup, commits another
synthetic claim after backup progress begins, closes and hashes the backup, publishes the
manifest last, then restores through SQLite into a different empty root.

Expected:

- backup generation/count describe one consistent snapshot;
- a complete backup contains exactly the canonical `BACKUP_PACKAGE` role file, closed
  database and manifest; incomplete or unknown members fail closed;
- closed backup database passes schema, integrity and application invariants;
- restored claims reproduce exact `AlreadyClaimed`/`BindingConflict` behavior through
  the manifest generation;
- evidence always says `PAUSED`, `instance epoch rotation required`, `fencing epoch
  rotation required`, and `may omit later claims`;
- the restored root stays `RESTORE_PENDING` and generic open refuses it even after
  WAL/FULL establishment and re-verification; only the explicit test supervisor
  simulation transitions it to `LIVE_READY`;
- missing/temporary manifest, bad digest, wrong schema/application ID, corrupt database,
  unknown files and non-empty destination all fail closed;
- raw copying of live `replay.sqlite3`, `-wal` or `-shm` is never used as the positive
  path.

The restored database must not be handed to a coordinator until feature 004+ implements
paused activation, epoch rotation and reconciliation.

## 10. Redaction and portability

```powershell
cargo test --locked -p helix-replay-sqlite --test redaction
cargo test --locked -p helix-replay-sqlite --test portability
```

Sentinels assert that `Debug`, `Display`, `Error::source`, metrics and maintenance
summaries contain none of the synthetic path, nonce, operation/task/workload ID,
binding/plan digest or provider-error values. Source checks reject platform-conditioned
claim/conflict/deadline semantics and direct dependencies on the legacy runtime.

## 11. Release latency probe

Choose a new dedicated local directory. The example refuses a non-empty root and never
prints it. Then run:

```powershell
$env:HELIX_BENCH_HARDWARE = 'public-machine-cpu-memory-storage-label'
$env:HELIX_BENCH_FILESYSTEM_ASSURANCE = 'validated-local-filesystem-lock-create-hardlink-sync-label'
cargo run --locked --release -p helix-replay-sqlite --example durable_replay_benchmark -- --root C:\dedicated\helix-replay-bench --warmups 500 --samples 10000 --output ..\specs\003-durable-replay-store\evidence\benchmark-local.json
```

Both labels are required, public, trimmed, bounded to 160 characters and contain no
native path separator. The program also requires an exact clean commit at startup and
creates both the root and output without overwrite.

Capture the complementary controlled-host workloads with `--nocapture` so the bounded
deadline, contention and process-kill summaries remain reviewable:

```powershell
cargo test --locked --release -p helix-replay-sqlite --test deadline -- --nocapture --test-threads=1
cargo test --locked --release -p helix-replay-sqlite --test contention release_thread_then_process_contention_suite -- --ignored --nocapture --test-threads=1
cargo test --locked --release -p helix-replay-sqlite --features test-fault-injection --test process_crash -- --ignored --nocapture --test-threads=1
cargo test --locked --release -p helix-replay-sqlite --features test-fault-injection --test backup_restore -- --nocapture --test-threads=1
```

On macOS/Linux, pass an absolute dedicated local path appropriate to that host. Expected
artifact fields include:

- acceptance ID and immutable commit;
- CPU/hardware, OS/architecture and filesystem assurance label;
- Rust, rusqlite and SQLite version/source ID;
- WAL/FULL/checkpoint profile;
- warmups, samples, concurrency and raw sorted nanoseconds;
- p50/p95/p99/max and corpus/schema digests.

Controlled-target gates are p95 <= 25 ms and p99 <= 100 ms. A shared hosted runner may
publish samples but cannot establish this performance claim. The actual Mac mini M4 run
must remain separate from hosted M1 evidence and from the later fullfsync/power-loss
spike.

## 12. CI and immutable evidence

`.github/workflows/durable-replay-store.yml` runs the unchanged semantic suite on:

- Ubuntu x64;
- macOS arm64;
- Windows x64.

Before changing `PLAN-003` from `pending-evidence`, record in
`conformance/catalog.yaml`:

- immutable commit and run URL;
- exact runner image and `rustc -vV` host;
- fixture/schema/expected-outcome digests;
- per-platform artifact digest and attestation;
- retained preservation location;
- local controlled-hardware performance evidence.

Hosted process-crash success does not satisfy Mac mini M4 power-loss/fullfsync evidence.

## 13. Graphify memory and completion

After code and tests converge from the repository root:

```powershell
graphify update .
graphify save-result "Feature 003 durable replay store decisions and verified outcomes" --status useful
graphify reflect --graph graphify-out/graph.json
```

Store only concise decisions and evidence references. Do not store native paths,
identifiers, nonces, database contents, credentials or private reasoning in Graphify.

## Deferred mandatory work

Even after every local feature-003 command passes, the following remain blocked:

- immutable unchanged three-platform CI evidence if no remote run exists;
- actual Mac mini M4 latency and power-loss/fullfsync spike;
- atomic fresh comparison, budgets and durable `PREPARING`;
- recovery material, audit/outbox and restored-system activation;
- `DISPATCHING`, `ExecutionGrant`, adapter inbox/receipt and host effects;
- reconciliation, verification, settlement and compensation.

Feature 003 therefore closes durable replay admission only; it does not complete R1 or
establish Tier 1 readiness.
