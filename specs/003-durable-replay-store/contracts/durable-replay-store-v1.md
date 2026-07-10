# Durable Replay Store v1 Contract

**Status**: Phase 1 design contract for feature 003
**Crate**: `helix-replay-sqlite`
**Consumes**: `helix_plan_eligibility::ReplayClaimantV1`
**Acceptance ID**: `PLAN-003`

This is a host storage-adapter contract, not a wire protocol. Native paths are accepted
only at trusted provisioning boundaries and never enter plans, fixtures, diagnostics or
adapter grants.

## Authority statement

```text
ReplayBindingV1 + healthy durable local store + unexpired boot clock
  -> Claimed(ReplayClaimReceiptV1)
   | AlreadyClaimed
   | BindingConflict
   | Unavailable
   | Ambiguous
```

Only `Claimed` is positive. It creates an `EligiblePlanV1` prerequisite through feature
002; it is not human authorization, budget/recovery preparation, an `ExecutionGrant`,
adapter input or effect permission.

## Public Rust surface

The intended public surface is shown below. Exact module paths may be organized during
implementation, but semantic types/outcomes and redaction rules are normative.

```rust
pub trait ReplayMonotonicClockV1: Send + Sync {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1>;
}

pub struct TrustedLocalStoreRootV1 { /* native path, private */ }

impl TrustedLocalStoreRootV1 {
    /// Security precondition: `root` was approved as a dedicated local filesystem
    /// directory by sovereign host provisioning, not by an agent or path heuristic.
    pub fn try_from_provisioned(
        root: std::path::PathBuf,
    ) -> Result<Self, ReplayStoreLocationErrorV1>;
}

pub struct ReplayStoreConfigV1 { /* checked, path-redacted */ }

impl ReplayStoreConfigV1 {
    pub fn try_new(
        root: TrustedLocalStoreRootV1,
        maximum_busy_wait_ms: u64,
        backup_step_pages: u32,
        backup_retry_wait_ms: u64,
    ) -> Result<Self, ReplayStoreConfigErrorV1>;
}

pub struct SqliteReplayClaimantV1<C> { /* path-redacted */ }

impl<C: ReplayMonotonicClockV1> SqliteReplayClaimantV1<C> {
    pub fn open_or_create(
        config: ReplayStoreConfigV1,
        clock: C,
        deadline_monotonic_ms: u64,
    ) -> Result<Self, ReplayStoreOpenErrorV1>;

    pub fn verify_integrity_v1(
        &self,
        deadline_monotonic_ms: u64,
    ) -> Result<ReplayStoreVerificationV1, ReplayStoreMaintenanceErrorV1>;

    pub fn checkpoint_v1(
        &self,
        mode: ReplayCheckpointModeV1,
        deadline_monotonic_ms: u64,
    ) -> Result<ReplayCheckpointEvidenceV1, ReplayStoreMaintenanceErrorV1>;

    pub fn backup_v1(
        &self,
        empty_destination: TrustedLocalStoreRootV1,
        deadline_monotonic_ms: u64,
    ) -> Result<ReplayBackupEvidenceV1, ReplayStoreMaintenanceErrorV1>;
}

impl<C: ReplayMonotonicClockV1> ReplayClaimantV1 for SqliteReplayClaimantV1<C> {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1;
}

pub fn verify_replay_backup_v1<C: ReplayMonotonicClockV1>(
    backup_root: TrustedLocalStoreRootV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<ReplayBackupEvidenceV1, ReplayStoreMaintenanceErrorV1>;

pub fn restore_replay_store_v1<C: ReplayMonotonicClockV1>(
    backup_root: TrustedLocalStoreRootV1,
    empty_destination_config: ReplayStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<VerifiedRestoreEvidenceV1, ReplayStoreMaintenanceErrorV1>;
```

All path-bearing types implement redacted `Debug`. No type exposes the native database,
WAL, SHM, temporary or manifest filenames. The root constructor validates absolute,
existing directory syntax and allowed contents, but its name and documentation make the
critical limitation explicit: portable code cannot infer trustworthy filesystem
locality from a path. The caller is responsible for provisioning assurance.

## Checked configuration

| Field | Accepted values | Failure |
|---|---|---|
| `maximum_busy_wait_ms` | `1..=MAX_SAFE_U64` | `INVALID_BUSY_BOUND` |
| `backup_step_pages` | `1..=4096` | `INVALID_BACKUP_STEP` |
| `backup_retry_wait_ms` | `0..=1000` | `INVALID_BACKUP_WAIT` |
| live root | dedicated provisioned local directory | location error |

Callers cannot configure application ID, schema version, database filename, journal
mode, synchronous level, schema checks or automatic checkpoint behavior.

Every provisioned root uses one fixed synchronized role file. Generic open/claim accepts
only canonical `LIVE_READY`. Persistent integrity/invariant failure transitions it to
`LIVE_QUARANTINED` before releasing the SQLite writer. Backup packages use
`BACKUP_PACKAGE`; restored destinations use `RESTORE_PENDING` plus a fixed
activation-required marker. Missing, unknown or torn state fails closed. These are
cooperating-process locks, not a sandbox against a hostile host.

Live empty-root initialization uses a different create-new empty intent file. Only the
exact intent + root-role pair, before any database exists, can recover an interrupted
role write to `LIVE_READY`; the intent is removed after the role is synchronized. The
same zero/torn root-role bytes without live intent are never recoverable, so an
interrupted backup/restore reservation cannot become a live store.

## Live database identity and profile

Normative constants:

| Item | Value |
|---|---|
| SQLite application ID | `0x484c5852` / `1212962898` (`HLXR`) |
| application schema version | `1` |
| database filename | crate-fixed, private |
| journal mode | `WAL` |
| synchronous | `FULL` (`2`) |
| trusted schema | `OFF` |
| cell-size check | `ON` |
| automatic checkpoint | disabled (`0`) |
| temporary store content | never authoritative |

An existing non-zero foreign application ID is rejected before changing its journal or
schema. An application ID of zero is initializable only when `user_version=0` and no
application schema object exists in the dedicated root. Concurrent initializers acquire
the SQLite writer lock, re-read identity inside the transaction, and either create all
v1 objects or verify the winner. A crash exposes only an empty/recoverable database or a
complete v1 schema.

Opening an existing store verifies application ID, user version, exact required schema,
header/schema generation, singleton metadata, full integrity and application invariants
before constructing the claimant. Per-claim connections re-establish connection-local
pragmas and verify application ID, user version, journal mode and the cached schema
generation. Any mismatch marks that claimant object unhealthy and returns only closed
failures.

The reviewed SQL is [replay-store-schema-v1.sql](replay-store-schema-v1.sql). Runtime
creation embeds those exact bytes or a build-time checked equivalent; a drift test hashes
the embedded migration and this contract file.

## Claim algorithm

### 1. Pre-write preparation

1. If the claimant object is unhealthy, return `Unavailable`.
2. Read the injected boot-monotonic clock. Missing, unsafe or
   `now >= binding.claim_deadline_monotonic_ms()` returns `Unavailable`.
3. Fill 32 bytes from the supported OS random source and domain-hash them with
   `HELIXOS\0REPLAY-CLAIM-ATTEMPT\0V1\0` into a candidate claim ID. Failure returns
   `Unavailable`.
4. Copy only instance epoch, nonce, operation ID, binding digest and deadline into the
   internal owned attempt.
5. Open a fresh non-creating connection. Set its busy timeout to:

```text
min(deadline - now, config.maximum_busy_wait_ms, i32::MAX milliseconds)
```

6. Establish and verify connection-local profile and start `BEGIN IMMEDIATE`. Busy or
   provider failure here is definitely pre-mutation and returns `Unavailable`.
7. Re-read the clock. Expiry/unavailability causes an explicit rollback; return
   `Unavailable` only if rollback is confirmed, otherwise `Ambiguous`.

### 2. Compare under the writer lock

Read by composite nonce key and operation key inside the same transaction.

| Nonce lookup | Operation lookup | Required outcome |
|---|---|---|
| absent | absent | continue with fresh insertion |
| same row, exact keys/digest | same row, exact keys/digest | `AlreadyClaimed` |
| occupied incompatibly | any | `BindingConflict` |
| any | occupied incompatibly | `BindingConflict` |
| malformed/contradictory storage | malformed/contradictory storage | unhealthy + closed failure |

The exact-repeat transaction performs no generation update and rolls back/ends before
return. It never reconstructs or returns the old receipt as positive admission.

### 3. Fresh insert and commit

1. Checked-increment the singleton generation with a conditional update and `RETURNING`.
2. Build `ReplayClaimReceiptV1(candidate_claim_id, generation, binding_digest)` before
   commit; construction failure confirms rollback and returns `Unavailable`.
3. Insert one strict row containing both uniqueness keys, digest, claim ID and
   generation.
4. Invoke private fault point `row_inserted` only in a non-default test build.
5. Re-read clock immediately before commit. If expired/unavailable, explicitly roll
   back. Confirmed rollback is `Unavailable`; uncertain rollback is `Ambiguous`.
6. Mark phase `CommitStarted` before invoking `COMMIT`. Never invoke a second mutation
   transaction for this attempt.
7. After acknowledged commit, re-read the clock. Only `now < deadline` returns the
   already-built `Claimed(receipt)`. Reached/unavailable clock returns `Ambiguous`; the
   committed row remains permanent.

### 4. Commit-error readback

After any error once commit has started, dispose of the original transaction/connection
and, only while the clock is still valid, open a fresh read-only view. Readback never
mutates.

| Definitive fresh view | Outcome |
|---|---|
| exact keys/digest/claim ID/generation of this attempt | `Claimed(receipt)` |
| exact keys/digest with another claim ID | `AlreadyClaimed` |
| either key occupied incompatibly | `BindingConflict` |
| healthy recovery proves both keys and candidate claim ID absent | `Unavailable` |
| cannot open/read, invalid store, contradictory view, clock reached/unavailable | `Ambiguous` |

The fresh random claim ID is mandatory. A deterministic `(binding, generation)` token
could be reused by a later exact contender after the original transaction rolled back,
causing a false positive during readback.

## Deadline semantics

The absolute scalar belongs to the caller's suspend-aware boot clock. The contract
requires:

- no mutation when already expired;
- busy/lock waiting limited to the calculated remaining budget;
- recheck after writer acquisition, immediately before commit and immediately after
  commit/readback;
- no positive outcome once the deadline is reached;
- no detached worker or background retry after return.

It does not claim that a synchronous VFS `fsync` already executing in the operating
system can be hard-cancelled. A stalled call may return late; a successful or uncertain
commit observed after the deadline maps to `Ambiguous`. Controlled held-lock tests must
meet deadline plus scheduler tolerance. Feature 002 documentation is clarified from
“hard completion” to this implementable meaning without changing the v1 type or outcomes.

## Error phase mapping

| Phase | Examples | Replay outcome |
|---|---|---|
| before mutation | clock, RNG, open, profile, `BEGIN IMMEDIATE`, read | `Unavailable` |
| mutation + confirmed rollback | generation/insert/receipt/pre-commit deadline | `Unavailable` |
| mutation + uncertain rollback | rollback/provider failure | `Ambiguous` |
| commit started | any error | fresh readback table above; default `Ambiguous` |
| commit success but late | post-commit deadline/clock unavailable | `Ambiguous` |

SQLite error codes/text do not determine sovereignty. They may guide internal health
metrics but never escape public output or override the phase table.

## Maintenance contracts

### Full verification

`verify_integrity_v1` acquires `BEGIN IMMEDIATE` within the maintenance deadline so no
claim mutation overlaps its view. It verifies:

- application/user version and exact schema;
- required live pragmas;
- `PRAGMA integrity_check` returns exactly one `ok` row;
- singleton metadata is well formed;
- every row passes type/length/safe-bound checks;
- claim count/generation/min/max/uniqueness and contiguity invariants.

It never repairs. Failure marks the local claimant unhealthy.

### Checkpoint

`ReplayCheckpointModeV1` is closed:

- `Passive`: ordinary bounded maintenance; never waits for readers beyond SQLite's
  passive semantics;
- `QuiescentTruncate`: caller asserts the coordinator is quiescent; failure to obtain a
  complete checkpoint is a closed maintenance error and does not weaken mode.

Claims have `wal_autocheckpoint=0` and never checkpoint implicitly. The future
coordinator must schedule maintenance; this feature's quickstart and soak exercise it.

### Online backup

1. Recheck destination is empty and distinct from source; exclusively create, sync and
   hold its fixed `BACKUP_PACKAGE` role file for the complete operation.
2. Create every staging/final name only inside that reserved destination and never
   replace an existing name.
3. Use `rusqlite::backup::Backup::step` in configured page batches, checking the
   maintenance deadline between steps; never use raw live-file copy.
4. On completion, close/quiesce the destination database, verify schema, full integrity
   and application invariants, and `sync_all` the closed database file.
5. Stream SHA-256 of the closed database.
6. Serialize [backup-manifest-v1.schema.json](backup-manifest-v1.schema.json), sync the
   temporary manifest and publish the final manifest last.
7. Any crash/incomplete state lacks a valid final manifest or fails digest/integrity and
   is not restorable. No directory-fsync or power-loss property is claimed portably.

A complete v1 package contains exactly three regular files: the canonical
`BACKUP_PACKAGE` role file, final closed database and final manifest. The manifest binds
the database; the role file has fixed exact bytes and is verified independently.
`verify_replay_backup_v1` performs that full role/member/manifest/digest/runtime/schema/
integrity/invariant verification without restoring or activating the package and returns
only redacted generation/count evidence.

Continuous writes may cause the SQLite backup to restart/starve; reaching its maintenance
deadline returns `MAINTENANCE_DEADLINE_REACHED` and leaves only rejected staging data.

### Clean restore

1. Lock and verify the backup source as `BACKUP_PACKAGE`; recheck the destination is
   empty and distinct.
2. Require exactly the v1 role file, final database and manifest; reject
   staging/unknown files.
3. Strictly decode the manifest with unknown fields denied.
4. Hash the closed backup database and compare the manifest.
5. Open the backup read-only; cross-check application/schema/generation/count and run
   full integrity/application verification.
6. Exclusively reserve the destination as `RESTORE_PENDING`, publish its fixed
   activation-required marker, then use the SQLite backup API into a no-clobber file.
7. Establish WAL/FULL internally while the root remains non-claimable, close/sync,
   reopen and repeat full profile/schema/integrity/application verification.
8. Return `VerifiedRestoreEvidenceV1`; generic open still rejects `RESTORE_PENDING` and
   this feature does not activate a coordinator or supervisor.

A valid backup proves inclusion only through its recorded generation. The result always
requires external system `PAUSED`, trigger quarantine, strictly new instance/fencing
epochs and later reconciliation. No old epoch may resume from this leaf API.

## Backup manifest

The normative JSON Schema is
[backup-manifest-v1.schema.json](backup-manifest-v1.schema.json). Serialization is strict
UTF-8 JSON with all required fields and no extension keys. It is not signed authority.
The database digest and cross-checks detect incomplete/mismatched packaging, not a host
attacker able to replace both database and manifest.

## Closed maintenance codes

Public configuration, location, clock, open and maintenance errors are payload-free
enums. `code()`, `Display` and `Debug` expose only the stable code. At minimum the
following externally testable codes are frozen for v1:

```text
INVALID_BUSY_BOUND
INVALID_BACKUP_STEP
INVALID_BACKUP_WAIT
CLOCK_UNAVAILABLE
DEADLINE_REACHED
LOCATION_INVALID
LOCATION_NOT_DEDICATED
STORE_UNAVAILABLE
STORE_BUSY
APPLICATION_ID_MISMATCH
SCHEMA_UNSUPPORTED
SCHEMA_INVALID
DURABILITY_PROFILE_UNAVAILABLE
INTEGRITY_FAILED
INVARIANT_FAILED
DESTINATION_NOT_EMPTY
SOURCE_DESTINATION_CONFLICT
MANIFEST_MISSING
MANIFEST_INVALID
DATABASE_DIGEST_MISMATCH
BACKUP_INCOMPLETE
RESTORE_INCOMPLETE
MAINTENANCE_DEADLINE_REACHED
```

No code includes a path, identifier, nonce, digest or provider detail.

## Test-only fault contract

The non-default Cargo feature `test-fault-injection` exposes a doc-hidden hook only to
the repository test worker. Default/release builds contain no hook or environment-driven
kill behavior. Frozen points (18 total):

```text
initialization: initialization_schema_staged, initialization_committed
claim: opened, begin_acquired, generation_updated, row_inserted, before_commit,
       commit_returned, before_result_ack
checkpoint: checkpoint_before_mutation, checkpoint_returned
backup: backup_database_complete, backup_manifest_staged, backup_published
restore: restore_reserved, restore_database_staged, restore_published,
         restore_profile_verified
```

The process worker emits a bounded readiness token, flushes stdout and blocks on stdin.
The parent kills and reaps it with `std::process::Child`; every reopen runs integrity and
all-or-none checks. A private executor seam separately injects commit/readback failures.
These are process-crash tests, not power-loss evidence.

## Compatibility and removal

- v1 adds no wire or feature-002 outcome version.
- Unknown/newer database or manifest versions fail closed; no downgrade occurs.
- Empty-to-v1 initialization is the only migration in this feature. The first schema
  change must add an actual N-to-N+1 and allowed/refused rollback fixture.
- The bundled SQLite version and compile source are evidence inputs and exact lockfile
  changes require review.
- Removing this crate leaves feature 001/002 source semantics intact, but production
  use cannot fall back to the in-memory test claimant. Every affected authority epoch
  must be retired and required replay/audit evidence preserved before database removal.
