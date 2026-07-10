# Data Model: Durable Replay Claim Store

This model is the Phase 1 design for feature 003. It implements the replay entities
already defined by feature 002 without changing their public outcome or marker types.
Native storage values exist only inside `helix-replay-sqlite`.

## Relationship overview

```text
TrustedLocalStoreRootV1
  + ReplayStoreConfigV1
  + ReplayMonotonicClockV1
       |
       v
SqliteReplayClaimantV1
  + one ReplayStoreMetadataV1
  + zero..n ReplayClaimRowV1
       |
       +-- claim_once(ReplayBindingV1)
       |      -> ReplayClaimOutcomeV1
       |
       +-- verify/checkpoint
       +-- online backup -> BackupManifestV1 + closed database snapshot
                               |
                               +-- restore -> VerifiedRestoreEvidenceV1
```

## Boundary entities

### `TrustedLocalStoreRootV1`

Host-native, non-serializable input constructed only from trusted provisioning.

Fields:

- canonical absolute root path, private and redacted;
- locality assurance kind fixed to `provisioned_local_filesystem_v1`;
- fixed database filename supplied by the crate, never by a plan or agent.

Validation:

- root exists and is a directory;
- root is dedicated to replay storage and contains only the allowed live database,
  `-wal`, `-shm`, fixed root-role and closed marker names, or is empty for
  initialization;
- relative paths, NUL-containing paths and paths not approved by provisioning are
  rejected;
- the type does not attempt to infer network/cloud/removable locality from path syntax.

`Debug` prints only `TrustedLocalStoreRootV1 { .. }`. The path never enters fixtures,
logs, errors, metrics or a portable contract.

### `TrustedEmptyLocalRootV1`

Host-native, non-serializable destination for backup or restore.

Validation:

- all `TrustedLocalStoreRootV1` provisioning conditions apply;
- the directory is empty at construction and rechecked immediately before use;
- it must differ from the live/source root;
- backup/restore never deletes, empties or overwrites a destination.

### `RootStateV1`

Fixed synchronized operational state stored in `.helix-replay-root-v1.lock` and held
under a cross-process exclusive file lease:

- `LIVE_READY`: the only state accepted by generic open and claim paths;
- `LIVE_QUARANTINED`: a persistent integrity/invariant failure blocks every cooperating
  process until operator recovery;
- `BACKUP_PACKAGE`: reserves a backup destination and remains the third required member
  of a complete v1 package;
- `RESTORE_PENDING`: reserves a restore destination and remains non-claimable after
  verification until a future paused supervisor rotates epochs and activates it.

Unknown, missing where required, truncated or otherwise non-canonical role contents
fail closed. A separate fixed activation marker is required with `RESTORE_PENDING`; a
quarantine marker is redundant evidence for `LIVE_QUARANTINED`. File sync is performed,
but no portable directory-fsync or power-loss atomicity claim is made.

Live empty-root creation first exclusively creates the distinct empty
`.helix-replay-live-initializing-v1` intent. Only the exact `{intent, root-role}` state
with no database or other member may rewrite an interrupted root-role write to
`LIVE_READY`; the intent is removed under the live lease after the role is synchronized.
A zero/torn role without that intent, including interrupted `BACKUP_PACKAGE` or
`RESTORE_PENDING` reservation, is never promoted and fails closed. The fixed SQLite
rollback-journal filename is allowed only as transient live SQLite state alongside the
database and role.

### `ReplayStoreConfigV1`

Owned checked configuration:

- `root: TrustedLocalStoreRootV1`;
- `maximum_busy_wait_ms: 1..=MAX_SAFE_U64`;
- `backup_step_pages: 1..=4096`;
- `backup_retry_wait_ms: 0..=1000`;
- fixed application ID `0x484c5852` (`HLXR`);
- fixed schema version `1`;
- fixed filenames and durability profile, not caller-selectable.

The caller may reduce busy/maintenance bounds but cannot select weaker journal or sync
semantics. `Debug` omits root and scalar values.

### `ReplayMonotonicClockV1`

Injected `Send + Sync` provider:

```text
now_monotonic_ms() -> safe u64 | ClockUnavailableV1
```

The provider uses the same suspend-aware boot clock domain that feature 002 used to
construct `claim_deadline_monotonic_ms`. This crate offers no process-start or UTC
fallback.

## Persistent entities

### `ReplayStoreMetadataV1`

Exactly one strict row:

| Field | Type | Rule |
|---|---|---|
| `singleton` | integer | exactly `1`, primary key |
| `format_version` | integer | exactly `1` |
| `claimant_generation` | integer | `0..=9_007_199_254_740_991` |

Database-header identity is also mandatory:

- `application_id = 0x484c5852`;
- `user_version = 1`;
- exact schema objects and normalized SQL match the reviewed v1 schema;
- journal mode is `wal` for a live store;
- every writable connection reports synchronous level `2` (`FULL`).

Application invariants:

- generation `0` iff the claim table is empty;
- otherwise generation equals claim count and maximum claim generation;
- claim generations are unique and contiguous from `1` through metadata generation;
- metadata generation never decreases in a live history.

### `ReplayClaimRowV1`

One permanent strict row represents both replay indexes and the receipt:

| Field | Type | Rule |
|---|---|---|
| `instance_epoch` | integer | safe u64 range |
| `nonce` | blob | exactly 16 bytes |
| `operation_id` | text, binary collation | 1..128 portable ASCII bytes |
| `binding_digest` | blob | exactly 32 bytes |
| `claim_id` | blob | exactly 32 bytes, unique |
| `claimant_generation` | integer | 1..MAX_SAFE_U64, unique |

Keys:

- primary key `(instance_epoch, nonce)`;
- unique key `operation_id`;
- unique keys `claim_id` and `claimant_generation` for exact readback/invariants.

The row contains no raw plan, signature, public key, task/workload ID, lease, resource,
path, secret, content, UTC timestamp or provider error. `operation_id` and nonce are
retained only because they are the normative uniqueness keys; all other compared
evidence is represented by `binding_digest`.

### `ClaimAttemptV1`

Ephemeral owned projection created inside `claim_once`:

- instance epoch;
- nonce;
- operation ID;
- binding digest;
- absolute boot-monotonic deadline;
- fresh 32-byte OS-random token, domain-hashed into candidate `claim_id`;
- candidate generation only after the write transaction allocates it;
- mutation phase: `PreWrite`, `Mutating`, `CommitStarted`, `CommitReturned`.

The random identity distinguishes this attempt from a later exact contender that may
reuse a rolled-back generation. It is opaque identity, not a credential or bearer
authority.

## Output entities

### `ReplayClaimReceiptV1` (existing)

Constructed before commit and returned only when a still-timely committed attempt is
proven:

- `claim_id` equals the persisted attempt claim ID;
- `claimant_generation` equals the persisted generation;
- `binding_digest` equals the exact feature-002 binding digest.

It remains non-serializable and redacted. A persisted receipt does not imply approval,
budget reservation, preparation, grant, dispatch or effect.

### `ReplayStoreVerificationV1`

Owned, non-serializable, redacted maintenance evidence:

- application and schema versions;
- claimant generation and claim count;
- journal/synchronous profile verified;
- full SQLite integrity result verified;
- all application invariants verified.

It exposes bounded scalar getters needed to build an external evidence artifact, not a
path or database/provider diagnostic.

### `CheckpointEvidenceV1`

- mode: `Passive` or `QuiescentTruncate`;
- log-frame count and checkpointed-frame count as safe integers;
- whether all frames were checkpointed;
- claimant generation observed before and after;
- closed status.

`QuiescentTruncate` is an explicit operator/coordinator maintenance action. Claim calls
never trigger a checkpoint.

### `BackupManifestV1`

Versioned JSON evidence stored beside one quiescent backup database and the fixed
`BACKUP_PACKAGE` role file:

- schema ID `helixos.replay-store-backup/1`;
- application ID `1212962898`;
- store schema version `1`;
- claimant generation;
- claim count;
- lowercase SHA-256 of the closed backup database;
- bundled SQLite version and source ID;
- `integrity_check = "ok"`;
- `requires_paused_activation = true`;
- `requires_instance_epoch_rotation = true`;
- `requires_fencing_epoch_rotation = true`;
- `may_omit_claims_after_generation = true`.

No native path, runtime identifier, plan/binding digest, nonce, operation ID, timestamp
or secret appears. Restore cross-checks every scalar with the database; the manifest is
consistency evidence, not a signature or proof against a host attacker who can replace
all package members.

### `VerifiedRestoreEvidenceV1`

Returned only after a clean-directory restore passes database digest, manifest, schema,
full integrity and application invariants, establishes WAL/FULL, closes/syncs and
reopens/reverifies the destination while its role remains `RESTORE_PENDING`:

- restored claimant generation and claim count;
- source manifest schema/store version;
- all three activation requirements fixed to `true`;
- redacted verification status.

It deliberately does not activate or open the store for claims. The future supervisor
and coordinator must remain paused, rotate external epochs and reconcile possible work.

## Closed errors

### `ReplayStoreOpenErrorV1`

Payload-free codes:

- `CLOCK_UNAVAILABLE`
- `DEADLINE_REACHED`
- `LOCATION_INVALID`
- `LOCATION_NOT_DEDICATED`
- `STORE_UNAVAILABLE`
- `STORE_BUSY`
- `APPLICATION_ID_MISMATCH`
- `SCHEMA_UNSUPPORTED`
- `SCHEMA_INVALID`
- `DURABILITY_PROFILE_UNAVAILABLE`
- `INTEGRITY_FAILED`
- `INVARIANT_FAILED`

### `ReplayStoreMaintenanceErrorV1`

Payload-free codes:

- all relevant open errors above;
- `DESTINATION_NOT_EMPTY`
- `SOURCE_DESTINATION_CONFLICT`
- `MANIFEST_MISSING`
- `MANIFEST_INVALID`
- `DATABASE_DIGEST_MISMATCH`
- `BACKUP_INCOMPLETE`
- `RESTORE_INCOMPLETE`
- `MAINTENANCE_DEADLINE_REACHED`

`Debug`, `Display` and optional `Error` output only the stable code. Raw SQLite, OS,
path, RNG and serialization errors remain internal and are not chained through
`source()`.

## Claim state transition

```text
binding + healthy clock
  -> PRE_WRITE
       clock/RNG/open/config/begin failure -> Unavailable; no mutation
       exact existing row                 -> AlreadyClaimed
       either key occupied incompatibly   -> BindingConflict
       fresh keys
          -> MUTATING
               allocate generation + insert one row
               pre-commit expiry + confirmed rollback -> Unavailable
               rollback uncertain                    -> Ambiguous
          -> COMMIT_STARTED
               success + timely post-check -> Claimed(receipt)
               success + late/unavailable clock -> Ambiguous; row retained
               error -> fresh readback only
                    exact attempt + timely -> Claimed(receipt)
                    exact prior            -> AlreadyClaimed
                    incompatible occupant  -> BindingConflict
                    healthy total absence  -> Unavailable
                    otherwise              -> Ambiguous
```

No branch repeats the mutation transaction. A successful row never transitions back to
fresh. `Ambiguous` is treated operationally as possibly claimed even if later maintenance
can reconcile it.

## Store lifecycle

```text
ABSENT dedicated root
  -> INITIALIZING (WAL/FULL + transactional schema)
       crash -> empty/partial SQLite recovery -> retry initialization or fail closed
  -> READY
       open/claim/verify
       detected wrong identity/schema/invariant/corruption -> UNHEALTHY
  -> UNHEALTHY
       claims denied; no automatic repair
       operator backup/restore/replacement workflow only

READY --online backup--> STAGED BACKUP --verify + manifest-last--> VALID BACKUP
VALID BACKUP --restore to empty root--> VERIFIED RESTORE (not activated)
```

## Concurrency invariants

- SQLite permits one active writer; `BEGIN IMMEDIATE` is the claim linearization gate.
- Multiple claimant objects and local processes may contend, but exactly one fresh
  attempt can commit either uniqueness key.
- An exact losing contender returns `AlreadyClaimed`; an incompatible one returns
  `BindingConflict`.
- Busy waiting never exceeds the calculated configured lock-wait budget intentionally;
  no work remains after the synchronous method returns.
- Full integrity verification acquires the writer slot first so mutations cannot run
  concurrently with the checked view.
- Online backup is the only maintenance read allowed to overlap claims; it uses bounded
  steps and may restart when the source changes.

## Restore and removal invariants

- A backup generation proves what it includes, never the absence of later claims.
- Restore never overwrites a live/non-empty destination.
- A restored store is evidence only until the external system is paused and rotates
  instance and fencing epochs; feature 003 cannot perform that sovereign transition.
- No online claim deletion or pruning API exists.
- Removing the feature requires retiring every epoch/operation whose replay history
  could otherwise be accepted and preserving required audit/restore evidence.
