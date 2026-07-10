# Research: Durable Replay Claim Store

This research resolves the Phase 0 decisions for feature 003. The canonical constraints
are `constitution.md`, `ARCHITECTURE.md`, `ROADMAP-SPECS.md`, feature 002's replay
contract, and `specs/003-durable-replay-store/spec.md`. All questions needed for Phase 1
design are resolved below; no `NEEDS CLARIFICATION` remains.

## Decision 1 - Keep feature 003 at the durable replay boundary

**Decision**: Implement the production `ReplayClaimantV1` and its lifecycle evidence as
an independent slice. Do not yet consume `EligiblePlanV1` into `PREPARING`, reserve
budgets, write recovery material, create grants, or call an adapter.

The resulting trust progression remains explicit:

```text
feature 001: wire plan -> AuthenticPlanEnvelopeV1
feature 002: authentic plan + current facts + abstract atomic claim -> EligiblePlanV1
feature 003: abstract atomic claim -> production durable replay linearization point
feature 004: eligible plan + fresh comparison + budgets/recovery -> durable PREPARING
```

**Rationale**: Feature 002 explicitly leaves production replay storage unresolved. A
larger compare-and-prepare slice would also need an honest protocol across the SQLite
operation database, the independently fsynced supervisor fencing store and external
recovery material. Those stores cannot be presented as one implicit atomic transaction.
Closing the already-specified replay contract first is independently testable and does
not invent effect authority.

**Alternatives considered**:

- Build compare, budgets and `PREPARING` in this feature: deferred because its
  cross-store compare/CAS and multi-phase recovery semantics need a separate spec.
- Complete the full R1 coordinator and fake adapter: rejected as too broad for one
  security proof and would mix claim, preparation, dispatch and ambiguity boundaries.
- Start the real Mac filesystem slice: rejected because R1's portable durable core must
  precede R2.

## Decision 2 - Add one SQLite-specific leaf crate

**Decision**: Add `kernel/helix-replay-sqlite`, a leaf Rust library that depends on
`helix-plan-eligibility` and implements its unchanged `ReplayClaimantV1` trait. It owns
native store paths, connection configuration, schema, claim transactions, integrity,
checkpoint, backup and restore. It does not modify the feature-001 wire schema or the
feature-002 marker/outcome taxonomy.

The public production type is `SqliteReplayClaimantV1<C>`, generic over an injected
`ReplayMonotonicClockV1`. It stores only a trusted local root, bounded configuration and
the clock. Each claim opens a short-lived connection; no `rusqlite::Connection`, native
handle or SQLite error escapes the crate.

**Rationale**: A dedicated leaf makes SQLite a replaceable storage adapter and keeps
native paths out of portable contracts. Per-call connections make the claimant
`Send + Sync` without wrapping a non-thread-safe connection in a process mutex, and let
SQLite coordinate independent local processes at the actual persistence boundary.

One narrower process-local mechanism is justified for connection setup only: a weak,
per-canonical-database-path gate bounds concurrent empty-to-v1/WAL negotiation and
per-connection PRAGMA establishment. Acquisition uses `try_lock`, the injected
deadline during initialization and a configured bounded attempt count; the guard is
dropped before `BEGIN IMMEDIATE`. It neither shares a SQLite connection nor serializes
claim transactions, and it is not a cross-process correctness primitive. SQLite remains
the only transaction coordinator. The gate was added after repeated Windows contention
showed that simultaneous journal/profile setup could fail every contender before any
writer reached the database.

Initialization reads application ID, schema version and `sqlite_schema` in one deferred
snapshot before changing journal mode. This prevents a concurrent schema commit from
being misclassified from mixed header/schema observations. SQLite `SQLITE_SCHEMA` and
locking-protocol races are treated as bounded transient setup failures; decoded
persisted invariant violations remain permanently unhealthy.

**Alternatives considered**:

- Put SQLite in `helix-plan-eligibility`: rejected because eligibility remains a pure,
  storage-neutral contract and decision boundary.
- Put the store in legacy `helixos-kernel`: rejected because that crate contains native
  effect code and Windows-first behavior unrelated to replay admission.
- Add a pool or async runtime: rejected because claims are synchronous, short and
  single-writer; a pool adds queue and cancellation semantics without value here.
- Keep one connection or the claim transaction behind `Mutex`: rejected because it
  cannot serialize other processes and would introduce an authority-relevant queue.
  The bounded setup-only gate above does not own a connection and ends before claim
  arbitration.

## Decision 3 - Pin the SQLite supply chain and minimal features

**Decision**: Pin Rust `1.96.1` as already declared by the workspace and add:

```toml
rusqlite = { version = "=0.40.1", default-features = false, features = ["bundled", "backup"] }
getrandom = { version = "=0.4.3", default-features = false }
serde = { version = "=1.0.228", features = ["derive"] }
serde_json = "=1.0.150"
sha2 = { version = "=0.10.9", default-features = false }
```

`rusqlite 0.40.1`'s `bundled` feature pins `libsqlite3-sys 0.38.1` and SQLite 3.53.2;
`backup` exposes the online backup API. Default features are disabled because the store
does not need statement-cache or WASM support. The upstream documentation recommends
`bundled` for applications that control their own database because it avoids dependence
on a missing or older system SQLite. See the current
[rusqlite package documentation](https://docs.rs/crate/rusqlite/0.40.1) and its
[feature manifest](https://docs.rs/crate/rusqlite/0.40.1/source/Cargo.toml.orig).
`getrandom 0.4.3` supplies the cross-platform per-attempt token and declares Rust 1.85
as its MSRV; see its [package documentation](https://docs.rs/crate/getrandom/0.4.3).

**Rationale**: The exact native SQLite source then stays identical across Windows,
Linux and macOS, which materially improves reproducibility and avoids accidental
behavior changes from host packages.

**Alternatives considered**:

- Link the host SQLite: rejected because available versions and compile options differ
  across the three target families.
- Enable rusqlite defaults or `bundled-full`: rejected because unused cache/WASM/date,
  extension and virtual-table surfaces increase build and review scope.
- Derive the attempt token from process/time state: rejected because it can collide or
  become predictable across restore and does not improve availability over the OS RNG.
- Use SQLCipher now: deferred; the replay rows contain no content or secret, while
  backup encryption and platform credential integration belong to later operational
  hardening.

## Decision 4 - Use one strict claim row for both uniqueness indexes

**Decision**: Schema v1 uses a singleton metadata row and one strict claim table:

```text
replay_store_meta
  singleton = 1
  format_version = 1
  claimant_generation: 0..MAX_SAFE_U64

replay_claims (STRICT, WITHOUT ROWID)
  instance_epoch
  nonce BLOB(16)
  operation_id TEXT (binary comparison)
  binding_digest BLOB(32)
  claim_id BLOB(32) UNIQUE
  claimant_generation UNIQUE
  PRIMARY KEY(instance_epoch, nonce)
  UNIQUE(operation_id)
```

All lengths and safe-integer bounds are database checks. `STRICT` tables, the SQLite
application ID, `user_version=1`, exact table/index inspection and integrity checks make
wrong-file, wrong-schema and malformed-row failures closed. The store does not persist
canonical plans, signatures, key bytes, task/workload IDs, resource paths, provider
diagnostics or user content.

The operation ID and nonce must be stored because they are the two uniqueness keys. The
binding digest proves all other compared evidence without duplicating sensitive plan
fields. A single row is preferable to two application-maintained index tables: SQLite's
two unique constraints become one atomic row insertion and partial counterparts are not
representable through the supported API.

**Rationale**: This is the minimum data that implements feature 002's exact contract.
It is easier to verify after a crash than a pair of mutable mapping tables.

**Alternatives considered**:

- Store every replay-binding field: rejected as unnecessary duplication and broader
  retention; the domain-separated digest already binds every compared value.
- Hash operation ID before indexing: rejected because equality could be preserved, but
  it adds another domain/version contract without reducing the need to protect the DB.
- Separate nonce and operation tables: rejected because they add a partial-state
  invariant with no benefit.

## Decision 5 - Allocate generation and receipt inside `BEGIN IMMEDIATE`

**Decision**: A claim performs this sequence on a configured connection:

1. Read the injected monotonic clock; deny pre-write if unavailable or expired.
2. Fill a fresh 32-byte OS-random attempt token and domain-hash it into `claim_id`; RNG
   failure is a definite pre-write `Unavailable` result.
3. Set the connection busy timeout to the bounded remaining duration.
4. Start `BEGIN IMMEDIATE`, acquiring the only writer slot before any read/upgrade race.
5. Re-read the clock; roll back as `Unavailable` if the deadline is reached.
6. Query both uniqueness keys in the transaction.
7. Return `AlreadyClaimed` only when both resolve to the same row and exact digest;
   return `BindingConflict` for every occupied incompatible combination.
8. For a fresh pair, increment the singleton generation with a checked update, insert
   the token-bearing strict row, recheck the deadline, construct the receipt and commit.
9. Re-read the clock after commit. A reached or unavailable clock yields `Ambiguous`,
   not a late positive marker, even though the durable claim is retained.

SQLite documents that `BEGIN IMMEDIATE` starts a write transaction immediately and can
return `SQLITE_BUSY` when another writer exists; it avoids a deferred read transaction
that later fails while upgrading. See [SQLite transaction control](https://www.sqlite.org/lang_transaction.html)
and rusqlite's
[`TransactionBehavior::Immediate`](https://docs.rs/rusqlite/0.40.1/rusqlite/enum.TransactionBehavior.html).

**Rationale**: Generation allocation, claim ID, both uniqueness constraints and the
receipt then share the same transaction. The random claim ID is not bearer authority;
it is an attempt discriminator. If an uncertain transaction actually rolled back and a
later exact contender reused the same generation, a deterministic
`hash(binding, generation)` would falsely make readback identify the later contender as
the original attempt.

**Alternatives considered**:

- Check outside the write transaction then insert: rejected as racy.
- Return an existing receipt for an exact repeat: rejected by the v1 contract; it would
  create a second positive eligibility instance.
- Deterministic `hash(binding, generation)` claim IDs: rejected because a rolled-back
  generation can be reused by a later exact contender before the original readback.
- `BEGIN DEFERRED`: rejected because read-to-write upgrade behavior complicates bounded
  contention.

## Decision 6 - Inject the caller's boot-monotonic clock

**Decision**: Define a small `ReplayMonotonicClockV1: Send + Sync` trait returning a
safe millisecond value or one closed unavailable outcome. The production claimant has no
wall clock and no default `Instant` implementation because a process-start `Instant`
would not necessarily share the core's boot-scoped epoch used to create the binding.

Each connection overrides rusqlite's changeable default busy timeout with the remaining
binding duration, capped to an implementation maximum and rechecked before mutation.
The current rusqlite implementation notes that new connections default to 5000 ms, but
also says that value may change, so relying on it would make semantics version-dependent;
see [`Connection::busy_timeout`](https://docs.rs/rusqlite/0.40.1/rusqlite/struct.Connection.html#method.busy_timeout).

**Rationale**: The exact same trusted monotonic domain then governs eligibility and the
store call. There is no ambient time lookup or unbounded process mutex. SQLite owns the
lock sleep; the method creates no detached retry.

The deadline is not a universal hard cancellation guarantee for an in-flight VFS sync:
safe synchronous SQLite calls cannot be interrupted portably. The contract therefore
means no mutation when already expired, bounded lock waiting, checks immediately before
and after commit, no positive result after the deadline, and no detached work. A stalled
filesystem may return late and must be recorded as an operational storage failure; the
busy-lock acceptance fixture, not arbitrary kernel I/O, is bounded by deadline plus
tolerance. Feature 002's trait documentation is clarified accordingly without changing
its type or outcomes.

**Alternatives considered**:

- Use UTC: rejected because wall-clock correction can move backward or forward.
- Construct a clock from `std::time::Instant` inside the crate: rejected because its
  origin would not match the binding's boot-monotonic scalar.
- Custom rusqlite busy handler: rejected because the public callback is a plain function
  pointer and cannot safely capture the per-call clock/deadline; a calculated timeout
  plus pre-write recheck is simpler.

## Decision 7 - Classify uncertainty by transaction phase and readback proof

**Decision**: Never infer sovereign outcome from a SQLite error string. Track whether a
mutation has begun and whether commit was attempted.

- Open/configure/clock/`BEGIN IMMEDIATE`/pre-write failures: `Unavailable`.
- Confirmed rollback with no committed row: `Unavailable`.
- Any error after mutation or once commit starts: open a fresh connection for readback
  only if time and health permit.
- Exact row with this attempt's claim ID and a still-valid clock: `Claimed(receipt)`.
- Exact prior row with another claim ID: `AlreadyClaimed`.
- Occupied incompatible key: `BindingConflict`.
- Definitive healthy absence of both keys and attempt: `Unavailable`.
- Failed, stale, contradictory, late or deadline-precluded readback: `Ambiguous`.

The mutation transaction is never repeated. `Ambiguous` consumes the caller's eligible
marker operationally and requires later reconciliation/replan. Public errors and debug
output carry only closed codes, not paths, identifiers, nonces, digests or SQLite text.

**Rationale**: This is conservative without turning every acknowledged durable commit
into an unnecessary unknown. It also handles the case where another writer wins after a
confirmed rollback but before readback.

**Alternatives considered**:

- Map every commit error to `Unavailable`: rejected because the row may be durable.
- Map every commit error to `Ambiguous` without readback: safe but needlessly loses a
  result that can sometimes be proven from a fresh connection.
- Automatically retry commit/transaction: rejected because a potentially committed
  one-shot action cannot be repeated blindly.

## Decision 8 - Establish and verify a fixed durability profile

**Decision**: Every writable connection establishes and verifies:

```text
journal_mode = WAL
synchronous = FULL
foreign_keys = ON
trusted_schema = OFF
cell_size_check = ON
wal_autocheckpoint = 0
busy_timeout = per call, never an ambient default
```

The store uses short transactions and a maintenance checkpoint API; the configured
disabled autocheckpoint prevents an admission commit from unexpectedly running a
checkpoint after it has consumed most of its deadline. The future coordinator/operator
must schedule bounded `PASSIVE` checkpoints and use `FULL`/`RESTART`/`TRUNCATE` only for
explicit quiescent maintenance; feature validation exercises that path. Startup fails if
the returned journal or synchronous modes differ. The store accepts only a
caller-trusted local root and a fixed database filename; network/cloud/removable
locality is a provisioning denial, not an agent-controlled option.

SQLite states that WAL requires all processes to be on the same host, does not work on a
network filesystem, and has only one writer at a time. It also states that the WAL file
is part of persistent database state and must not be separated from the database. See
[SQLite WAL](https://www.sqlite.org/wal.html). In WAL mode, `synchronous=FULL` adds a WAL
sync after each transaction and is the documented ACID setting; see
[SQLite `synchronous`](https://www.sqlite.org/pragma.html#pragma_synchronous).

**Rationale**: These are the architecture's portable baseline settings. Unknown or
broken filesystem locking cannot be made safe by a weaker fallback.

**Alternatives considered**:

- `synchronous=NORMAL`: rejected because SQLite documents that power-loss durability
  may be lost in WAL mode.
- Network filesystem plus application lock: rejected because WAL requires shared memory
  and trustworthy filesystem locking.
- Enable `fullfsync` on every platform: deferred. SQLite documents that
  `F_FULLFSYNC` is macOS-only; its cost and actual Mac mini M4 behavior require the
  planned hardware/power-loss spike. This feature must not add an OS semantic branch or
  claim that process-kill tests prove power-loss durability.

## Decision 9 - Fail closed on identity, schema and corruption

**Decision**: Use a fixed non-zero SQLite application ID for Helix replay storage,
`user_version=1`, a singleton format version, exact expected tables/indexes/checks and
`PRAGMA integrity_check`. Initialization is transactional after the durability profile
is established. Two concurrent initializers serialize; the loser reopens and verifies
the winner's complete schema. Unknown application IDs, newer versions, missing objects,
altered SQL, failed checks or unsafe downgrade disable claims.

Feature 003 implements empty-to-v1 creation. There is no fabricated v0 production
schema, so the only rollback gate is explicit refusal to open newer/unknown versions.
The migration runner and manifest are versioned now so an actual N-to-N+1 fixture can be
added with the first schema change.

**Rationale**: `user_version` alone is mutable metadata, not sufficient wrong-file or
tamper detection. The application ID is the SQLite-supported file identity mechanism,
while exact schema and integrity verification catch accidental/manual modification.

**Alternatives considered**:

- Silently recreate missing indexes: rejected because it can hide corruption and alter
  conflict semantics.
- Auto-downgrade a newer store: rejected because older code cannot know newer invariants.
- Run only `quick_check`: retained for optional health sampling, but production open and
  backup/restore evidence use the full integrity check.

## Decision 10 - Use the online backup API and a quiescent backup artifact

**Decision**: `backup_v1` accepts a new empty destination root and a maintenance
deadline. It uses rusqlite's `backup` feature with distinct source/destination
connections and bounded page steps. After completion it makes the destination a
quiescent single-file artifact, runs full integrity/schema checks, closes it, streams a
SHA-256 digest and writes a versioned JSON manifest containing application/schema
identity, claimant generation, claim count, database digest and
`requires_paused_activation=true`.

`restore_v1` accepts a valid backup root and a different empty destination. It verifies
the manifest and source digest first, then uses the SQLite backup API into the new live
database, re-establishes WAL/FULL, runs full schema/integrity checks and returns redacted
restore evidence. It never overwrites a live store. The evidence explicitly cannot prove
absence of claims newer than the backup generation and therefore requires external
paused activation plus new instance/fencing epochs.

The final design adds one permanent fixed root-role file. Backup holds an exclusive
`BACKUP_PACKAGE` lease and publishes exactly role file + database + manifest. Restore
locks that package, reserves a new destination as `RESTORE_PENDING`, and leaves a fixed
activation-required marker after WAL/FULL close/reopen verification. Generic open only
accepts `LIVE_READY`; persistent invariant/integrity failure synchronously transitions
the held lease to `LIVE_QUARANTINED`. Publication uses exclusive creation and
same-volume no-clobber hard links. Those primitives are part of the provisioner-attested
local-filesystem precondition; no directory-fsync or power-loss atomicity is inferred.

The root-role pathname alone cannot identify the creator's intended role if a process
dies between `create_new` and writing bytes. Live initialization therefore first creates
a distinct empty live-intent filename. An exact intent + role-only directory may recover
the interrupted role write; zero/torn role state without that intent remains rejected.
Backup and restore never create live intent, preventing their interrupted reservations
from being promoted to a fresh live authority history.

SQLite's [online backup API](https://www.sqlite.org/backup.html) creates a consistent
snapshot of a live source while allowing bounded concurrent access. SQLite's corruption
guidance warns that copying an active database without its hot journal/WAL can lose
transactions or corrupt the copy, and names the backup API as a safe live method; see
[How To Corrupt An SQLite Database](https://www.sqlite.org/howtocorrupt.html).

**Rationale**: The produced database can be hashed and transported as one closed file,
while source claims can continue. Restore uses SQLite semantics in both directions
rather than guessing which live files are needed.

**Alternatives considered**:

- Copy the active database/WAL/SHM files: rejected as race-prone and explicitly
  unsupported.
- `VACUUM INTO`: valid, but the online backup API exposes bounded page progress and is
  already required by the architecture.
- Treat restore as proof no later claim existed: rejected; any point-in-time backup can
  be stale.

## Decision 11 - Separate deterministic crash tests from power-loss claims

**Decision**: Add a dedicated Rust fault-worker test executable and a parent integration
harness. They communicate readiness through inherited stdin/stdout lines and explicit
barriers, never timing sleeps or shell scripts. The parent uses `std::process::Child::kill`
and `wait` at these 18 private test-only fault points:

```text
initialization: initialization_schema_staged -> initialization_committed
claim:          opened -> begin_acquired -> generation_updated -> row_inserted
                -> before_commit -> commit_returned -> before_result_ack
checkpoint:     checkpoint_before_mutation -> checkpoint_returned
backup:         backup_database_complete -> backup_manifest_staged -> backup_published
restore:        restore_reserved -> restore_database_staged -> restore_published
                -> restore_profile_verified
```

Each kill is followed by a completely fresh process that runs integrity, reads both keys
and checks the all-or-none invariant. A private storage-executor seam separately injects
definite pre-write, confirmed rollback, commit-started and readback failures so every
public outcome classification is deterministic. The entire fault module is compiled out
of default production builds and accepts no environment-controlled production action.

**Rationale**: Safe rusqlite cannot portably inject an actual kernel I/O failure in the
middle of `fsync`. Process termination proves application crash recovery, while the
classification seam proves conservative logic. Evidence labels them honestly; later M4
power-cut tests remain separate.

**Alternatives considered**:

- Sleep then kill: rejected as flaky and scheduler-dependent.
- Run platform shell commands: rejected because Windows/Linux/macOS process semantics
  would diverge.
- Call `abort` from production code via an environment variable: rejected as an
  unnecessary production kill surface.

## Decision 12 - Use one semantic corpus across three CI hosts

**Decision**: Add `contracts/fixtures/durable-replay-store-v1/` with bounded JSON cases
for fresh/exact/conflicting bindings, deadline phases, corrupt metadata/schema, crash
points, backup and restore outcomes. A Rust loader verifies exact case IDs and expected
closed codes. The CI workflow runs the same commands on the reviewed labels
`windows-2022` x64, `ubuntu-24.04` x64 and `macos-26` arm64, then records the exact
`ImageOS`/`ImageVersion`, OS description, runner architecture and Rust host rather than
treating a mutable label as immutable evidence. See the
[GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Local Windows results are archived separately from CI. CI proves portable semantics and
process-crash behavior, not Mac mini M4 power-loss/fullfsync behavior. Source scans deny
`cfg(target_os)` in common store code and prohibit native path/error disclosure.

**Rationale**: One corpus detects semantic drift while allowing only launch/evidence
metadata to differ. The Mac runner is the closest available continuous architecture
check; the user's M4 remains the real reference hardware gate.

**Alternatives considered**:

- Cross-compile only: rejected because filesystem locks, WAL, process kill and backup
  must execute on each host.
- Different expected fixtures by OS: rejected because unsupported security semantics
  must be denied, not weakened per platform.
- Call hosted macOS evidence “M4 validated”: rejected because the documented runner is
  different hardware and does not simulate power loss.

## Decision 13 - Benchmark acknowledged durable commits, not cached inserts

**Decision**: A release probe records host CPU, OS/architecture, Rust and SQLite
versions, filesystem root classification, WAL/FULL pragmas, warmups, sample count and
raw nanoseconds. It measures 500 warmups and 10,000 sequential fresh claim calls,
including connection, `BEGIN IMMEDIATE`, WAL sync and close, then reports p50/p95/p99/max.
The initial budget is p95 <= 25 ms and p99 <= 100 ms on each recorded local-SSD target.

Contention evidence is separate: 100 thread rounds with 64 contenders and 20 process
rounds with 8 contenders. Busy-deadline fixtures use a held writer lock and require
return by deadline plus 50 ms scheduler tolerance. CI may record measurements, but noisy
hosted-runner results are not release performance claims.

**Rationale**: Measuring in-memory logic would hide the cost that protects replay
durability. Separating latency, contention and CI prevents a flattering but meaningless
number.

**Alternatives considered**:

- Reuse feature 002's 1 ms budget: rejected because that test claimant performs no disk
  synchronization.
- Make CI timing a hard release gate: rejected because shared hosted hardware has
  uncontrolled storage noise; target-hardware evidence remains authoritative.
- Batch claims: rejected because one claim is one admission linearization point and
  batching changes acknowledgement and ambiguity semantics.

## Decision 14 - Make redaction and maintenance outcomes closed contracts

**Decision**: Public open/maintenance errors expose only stable enum codes and redacted
`Debug`/`Display`; `source()` is absent or redacted. `SqliteReplayClaimantV1` and all
path-bearing request types have non-path debug output. Backup manifests contain only
format/application/schema, counts/generation, a database digest and activation flags;
logs, metrics, Graphify records and evidence never contain native paths, nonce,
operation ID, binding/plan digest or raw SQLite errors.

The database and backup are restricted operational security state. No network, secret,
model, connector or agent API is introduced. Committed rows are never deleted by this
feature. Removal requires external retirement of every affected epoch and operation;
there is no online prune endpoint.

**Rationale**: Native provider diagnostics commonly include SQL and paths. Closed codes
preserve operability without turning logs or project memory into a replay-data copy.

**Alternatives considered**:

- Wrap `rusqlite::Error` as `source`: rejected because callers/loggers could serialize
  paths, SQL or provider detail.
- Put operation IDs in metrics labels: rejected because labels are high-cardinality and
  disclose identifiers.
- Add retention pruning now: rejected because proving an old authority can never be
  accepted depends on supervisor/coordinator lifecycle not present in this feature.
