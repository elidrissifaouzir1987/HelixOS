mod common;

#[path = "../src/budget.rs"]
mod budget;
#[path = "../src/clock.rs"]
mod clock;
#[path = "../src/comparison_digest.rs"]
mod comparison_digest;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/failure.rs"]
mod failure;
#[path = "../src/outbox.rs"]
mod outbox;
#[path = "../src/prepare.rs"]
mod prepare;
#[path = "../src/readback.rs"]
mod readback;
#[path = "../src/root_safety.rs"]
mod root_safety;
#[cfg(feature = "test-fault-injection")]
#[path = "../src/test_fault.rs"]
mod test_fault;
#[path = "../src/transition.rs"]
mod transition;

use clock::CoordinatorMonotonicClockV1;
use common::{
    SyntheticCoordinatorClockV1, SyntheticCoordinatorRootV1, SyntheticHistoricalPlanKeyResolverV1,
};
use error::{CoordinatorClockUnavailableV1, InternalCoordinatorError};
use failure::{
    fail_synthetic_before_dispatch_v1, SyntheticKnownFailureCaseV1, SyntheticNoDispatchGuardCaseV1,
};
use helix_contracts::{ContractError, Ed25519KeyResolver};
use helix_coordinator_sqlite::{
    embedded_schema_v1_sha256, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
    CoordinatorStoreOpenErrorV1, SqliteCoordinatorStoreV1, COORDINATOR_STORE_APPLICATION_ID_V1,
    COORDINATOR_STORE_SCHEMA_VERSION_V1,
};
use helix_plan_preparation::{PreparationCommitOutcomeV1, PreparationFailureOutcomeV1};
use prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use root_safety::{
    acquire_existing_root_lease, acquire_initialization_root_lease, reserve_empty_root,
    CoordinatorRootIdentityV1, CoordinatorRootRoleV1, ProvisionedEmptyCoordinatorRootV1,
    ProvisionedExistingCoordinatorRootV1, COORDINATOR_DATABASE_FILENAME, ROOT_LOCK_FILENAME,
};
use rusqlite::{params, Connection};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const DEADLINE_MS: u64 = 10_000;
const STORE_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);
const CONNECTION_SOURCE: &str = include_str!("../src/connection.rs");

#[derive(Clone, Copy)]
struct InjectedClock(u64);

impl CoordinatorMonotonicClockV1 for InjectedClock {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        Ok(self.0)
    }
}

impl helix_coordinator_sqlite::CoordinatorMonotonicClockV1 for InjectedClock {
    fn now_monotonic_ms(
        &self,
    ) -> Result<u64, helix_coordinator_sqlite::CoordinatorClockUnavailableV1> {
        Ok(self.0)
    }
}

struct ExpiringInitializationClock {
    calls: AtomicU64,
    expire_on_call: u64,
}

impl helix_coordinator_sqlite::CoordinatorMonotonicClockV1 for ExpiringInitializationClock {
    fn now_monotonic_ms(
        &self,
    ) -> Result<u64, helix_coordinator_sqlite::CoordinatorClockUnavailableV1> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(if call >= self.expire_on_call {
            DEADLINE_MS
        } else {
            1_000
        })
    }
}

struct HistoricalPlanKeys;

impl Ed25519KeyResolver for HistoricalPlanKeys {
    fn resolve_ed25519(&self, _: &str) -> helix_contracts::Result<[u8; 32]> {
        Err(ContractError::UnknownKey)
    }
}

struct MetadataSnapshot {
    singleton: i64,
    format_version: i64,
    root_identity: Vec<u8>,
    lifecycle: String,
    restore_identity: Option<Vec<u8>>,
    restore_attestation: Option<Vec<u8>>,
    restore_generation: i64,
}

struct SyntheticRoot {
    path: PathBuf,
}

impl SyntheticRoot {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-coordinator-foundation-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("synthetic root creates");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SyntheticRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn initialize_store(root: &SyntheticRoot) -> CoordinatorRootIdentityEvidenceV1 {
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 25)
        .expect("empty trusted config validates");
    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        InjectedClock(1_000),
        HistoricalPlanKeys,
        DEADLINE_MS,
    )
    .expect("empty root initializes exactly once");
    assert_eq!(store.operation_count(), 0);
    store.root_identity_evidence()
}

fn reopen_store(
    root: &SyntheticRoot,
    identity: CoordinatorRootIdentityEvidenceV1,
) -> Result<SqliteCoordinatorStoreV1<InjectedClock, HistoricalPlanKeys>, CoordinatorStoreOpenErrorV1>
{
    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        25,
    )
    .expect("existing trusted config validates");
    SqliteCoordinatorStoreV1::open_or_create(
        config,
        InjectedClock(1_000),
        HistoricalPlanKeys,
        DEADLINE_MS,
    )
}

struct PreparedCorruptionRootV1 {
    root: SyntheticCoordinatorRootV1,
    identity: CoordinatorRootIdentityEvidenceV1,
    database: PathBuf,
}

impl PreparedCorruptionRootV1 {
    fn new() -> Self {
        let root = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root creates");
        let store = root
            .open_empty_v1(
                SyntheticCoordinatorClockV1::new(1_000),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                DEADLINE_MS,
            )
            .expect("synthetic coordinator initializes");
        let identity = store.root_identity_evidence();
        drop(store);

        let database = fs::canonicalize(root.path())
            .expect("synthetic coordinator root canonicalizes")
            .join(COORDINATOR_DATABASE_FILENAME);
        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
        provision_synthetic_budget_scope_v1(&database, &case)
            .expect("synthetic budget scope provisions");
        let outcome =
            commit_synthetic_preparation_v1(&database, &case, SyntheticCommitModeV1::Acknowledged);
        assert!(
            matches!(outcome, PreparationCommitOutcomeV1::Committed(_)),
            "corruption baseline must be one coherent preparation: {outcome:?}",
        );
        Self {
            root,
            identity,
            database,
        }
    }

    fn assert_full_reopen_rejected(&self, label: &str) {
        let result = self.root.open_existing_v1(
            self.identity,
            SyntheticCoordinatorClockV1::new(1_001),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            DEADLINE_MS,
        );
        assert!(result.is_err(), "{label} survived full invariant reopen");
    }
}

fn schema_objects(connection: &Connection) -> Vec<(String, String, String, String)> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
        )
        .expect("schema inventory statement prepares");
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("schema inventory queries")
        .collect::<Result<Vec<_>, _>>()
        .expect("schema inventory decodes")
}

fn reviewed_schema_objects() -> Vec<(String, String, String, String)> {
    let connection = Connection::open_in_memory().expect("reviewed schema database opens");
    connection
        .execute_batch(STORE_SCHEMA)
        .expect("reviewed schema installs in memory");
    schema_objects(&connection)
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn unique_key_inventory(connection: &Connection) -> Vec<String> {
    let tables = [
        "coordinator_store_meta",
        "budget_scopes",
        "prepared_operations",
        "operation_transitions",
        "preparation_comparisons",
        "budget_reservations",
        "preparation_recovery_evidence",
        "preparation_events",
        "preparation_quarantines",
    ];
    let mut keys = Vec::new();
    for table in tables {
        let mut indexes = connection
            .prepare(&format!("PRAGMA index_list({})", quote_identifier(table)))
            .expect("index inventory prepares");
        let indexes = indexes
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .expect("index inventory queries")
            .collect::<Result<Vec<_>, _>>()
            .expect("index inventory decodes");
        for (index, unique, origin, partial) in indexes {
            if unique != 1 {
                continue;
            }
            let mut columns = connection
                .prepare(&format!("PRAGMA index_info({})", quote_identifier(&index)))
                .expect("index columns prepare");
            let columns = columns
                .query_map([], |row| row.get::<_, String>(2))
                .expect("index columns query")
                .collect::<Result<Vec<_>, _>>()
                .expect("index columns decode")
                .join(",");
            keys.push(format!("{table}|{index}|{origin}|{partial}|{columns}"));
        }
    }
    keys.sort();
    keys
}

#[test]
fn empty_attested_root_refuses_every_unknown_member_without_disclosure() {
    const PRIVATE_MEMBER: &str = "DO-NOT-DISCLOSE-private-member";
    let root = SyntheticRoot::new("unknown-member");
    File::create(root.path().join(PRIVATE_MEMBER)).expect("foreign fixture creates");

    let error = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect_err("foreign member must deny empty role");
    assert_eq!(error, InternalCoordinatorError::UnknownRootMember);
    assert_eq!(format!("{error:?}"), "UNKNOWN_ROOT_MEMBER");
    assert!(!format!("{error:?}").contains(PRIVATE_MEMBER));
}

#[test]
fn held_empty_lease_revalidates_members_and_refuses_late_unknown_content() {
    const PRIVATE_MEMBER: &str = "DO-NOT-DISCLOSE-late-member";
    let root = SyntheticRoot::new("late-unknown-member");
    let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("empty provisioned root validates");
    let clock = InjectedClock(1_000);
    let mut lease =
        reserve_empty_root(&empty, &clock, DEADLINE_MS).expect("empty root reservation succeeds");

    File::create(root.path().join(PRIVATE_MEMBER)).expect("late foreign fixture creates");
    let error = lease
        .verify_role(CoordinatorRootRoleV1::Empty)
        .expect_err("held lease must revalidate unknown members");
    assert_eq!(error, InternalCoordinatorError::UnknownRootMember);
    assert!(!format!("{error:?}").contains(PRIVATE_MEMBER));
}

#[test]
fn empty_and_existing_roles_hold_one_exclusive_redacted_root_lease() {
    const PATH_SENTINEL: &str = "DO-NOT-DISCLOSE-root";
    let root = SyntheticRoot::new(PATH_SENTINEL);
    let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("empty provisioned root validates");
    assert_eq!(
        format!("{empty:?}"),
        "ProvisionedEmptyCoordinatorRootV1 { .. }"
    );
    assert!(!format!("{empty:?}").contains(PATH_SENTINEL));

    let clock = InjectedClock(1_000);
    let identity = CoordinatorRootIdentityV1::from_bytes([0xA5; 32]);
    let mut initialization =
        reserve_empty_root(&empty, &clock, DEADLINE_MS).expect("empty root reservation succeeds");
    initialization
        .verify_role(CoordinatorRootRoleV1::Empty)
        .expect("empty role marker verifies");
    initialization
        .begin_initialization(identity)
        .expect("initializing identity publishes before database creation");
    assert_eq!(initialization.initializing_identity(), Some(identity));
    assert!(!initialization
        .database_present()
        .expect("database absence reads"));
    assert_eq!(
        fs::read_to_string(root.path().join(ROOT_LOCK_FILENAME))
            .expect("initializing marker reads"),
        format!(
            "HELIXOS_COORDINATOR_ROOT_LOCK_V1\nROOT_IDENTITY={}\nSTATE=INITIALIZING\n",
            "a5".repeat(32)
        )
    );
    File::create(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("placeholder database creates");
    initialization
        .finalize_committed_initialization(identity)
        .expect("initialized role promotes exactly once");
    drop(initialization);
    assert_eq!(
        fs::read_to_string(root.path().join(ROOT_LOCK_FILENAME)).expect("existing marker reads"),
        format!(
            "HELIXOS_COORDINATOR_ROOT_LOCK_V1\nROOT_IDENTITY={}\nSTATE=EXISTING\n",
            "a5".repeat(32)
        )
    );

    assert_eq!(format!("{identity:?}"), "CoordinatorRootIdentityV1 { .. }");
    let existing = ProvisionedExistingCoordinatorRootV1::try_from_attested(
        root.path().to_path_buf(),
        identity,
    )
    .expect("existing provisioned root validates");
    assert!(existing.expected_identity().matches(&[0xA5; 32]));
    assert_eq!(
        format!("{existing:?}"),
        "ProvisionedExistingCoordinatorRootV1 { .. }"
    );

    let first = acquire_existing_root_lease(&existing, 1, &clock, DEADLINE_MS)
        .expect("first existing lease succeeds");
    let second = acquire_existing_root_lease(&existing, 1, &clock, DEADLINE_MS)
        .expect_err("second lease must not overlap");
    assert_eq!(second, InternalCoordinatorError::RootBusy);
    drop(first);
    acquire_existing_root_lease(&existing, 1, &clock, DEADLINE_MS)
        .expect("lease becomes available after drop");
}

#[test]
fn committed_initialization_recovers_an_interrupted_role_marker_rewrite() {
    let root = SyntheticRoot::new("partial-role-marker");
    let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("empty provisioned root validates");
    let clock = InjectedClock(1_000);
    let mut lease = reserve_empty_root(&empty, &clock, DEADLINE_MS).expect("empty lease reserves");
    let identity = CoordinatorRootIdentityV1::from_bytes([0x7A; 32]);
    lease
        .begin_initialization(identity)
        .expect("initializing identity publishes first");
    File::create(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("committed database fixture creates");
    let marker_path = root.path().join(ROOT_LOCK_FILENAME);
    let marker = fs::read(&marker_path).expect("initializing marker reads");
    let state_offset = marker
        .windows(b"STATE=".len())
        .position(|window| window == b"STATE=")
        .expect("state field exists");
    fs::write(&marker_path, &marker[..state_offset + b"STATE=EX".len()])
        .expect("interrupted marker fixture writes");

    lease
        .finalize_committed_initialization(identity)
        .expect("held empty authority repairs only committed role publication");
    drop(lease);
    let existing = ProvisionedExistingCoordinatorRootV1::try_from_attested(
        root.path().to_path_buf(),
        identity,
    )
    .expect("recovered existing role validates");
    acquire_existing_root_lease(&existing, 1, &clock, DEADLINE_MS)
        .expect("recovered exact marker acquires");
}

#[cfg(unix)]
#[test]
fn attested_directory_replacement_is_rejected_by_filesystem_identity() {
    let root = SyntheticRoot::new("directory-replacement");
    let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("empty provisioned root validates");
    let displaced = root.path().with_extension("attested-displaced");
    fs::rename(root.path(), &displaced).expect("attested directory moves aside");
    fs::create_dir(root.path()).expect("replacement directory creates at same path");

    let result = acquire_initialization_root_lease(&empty, 1, &InjectedClock(1_000), DEADLINE_MS);

    fs::remove_dir(root.path()).expect("replacement directory removes");
    fs::rename(&displaced, root.path()).expect("attested directory restores for cleanup");
    assert_eq!(
        result.expect_err("directory replacement must not inherit attestation"),
        InternalCoordinatorError::RootRoleMismatch
    );
}

#[cfg(unix)]
#[test]
fn held_lease_rejects_lock_path_replacement_even_when_marker_bytes_match() {
    let root = SyntheticRoot::new("lock-replacement");
    let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("empty provisioned root validates");
    let mut lease = reserve_empty_root(&empty, &InjectedClock(1_000), DEADLINE_MS)
        .expect("empty root reservation succeeds");
    let lock_path = root.path().join(ROOT_LOCK_FILENAME);
    let displaced = root.path().join("displaced-root-lock");
    fs::rename(&lock_path, &displaced).expect("held lock path moves aside");
    fs::write(&lock_path, fs::read(&displaced).expect("held marker reads"))
        .expect("byte-identical replacement lock creates");

    let result = lease.database_present();
    drop(lease);
    fs::remove_file(lock_path).expect("replacement lock removes");
    fs::remove_file(displaced).expect("held lock removes");
    assert_eq!(
        result.expect_err("replacement inode must not inherit the held lease"),
        InternalCoordinatorError::RootRoleMismatch
    );
}

#[cfg(unix)]
#[test]
fn attested_lock_replacement_is_rejected_before_lease_acquisition() {
    let root = SyntheticRoot::new("attested-lock-replacement");
    let first_attestation =
        ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
            .expect("empty root first attestation validates");
    drop(
        reserve_empty_root(&first_attestation, &InjectedClock(1_000), DEADLINE_MS)
            .expect("exact empty marker publishes"),
    );
    let attested = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("existing empty marker is attested by filesystem identity");
    let lock_path = root.path().join(ROOT_LOCK_FILENAME);
    let displaced = root.path().with_extension("attested-displaced-lock");
    fs::rename(&lock_path, &displaced).expect("attested lock moves aside");
    fs::write(
        &lock_path,
        fs::read(&displaced).expect("attested marker reads"),
    )
    .expect("byte-identical replacement lock creates");

    let result =
        acquire_initialization_root_lease(&attested, 1, &InjectedClock(1_000), DEADLINE_MS);

    fs::remove_file(lock_path).expect("replacement lock removes");
    fs::rename(displaced, root.path().join(ROOT_LOCK_FILENAME))
        .expect("attested lock restores for cleanup");
    assert_eq!(
        result.expect_err("replacement inode must not inherit attestation"),
        InternalCoordinatorError::RootRoleMismatch
    );
}

#[test]
fn restart_recovers_partial_state_suffix_without_losing_initializing_identity() {
    let root = SyntheticRoot::new("partial-marker-restart");
    let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("empty provisioned root validates");
    let clock = InjectedClock(1_000);
    let identity = CoordinatorRootIdentityV1::from_bytes([0x3C; 32]);
    let mut first = acquire_initialization_root_lease(&empty, 1, &clock, DEADLINE_MS)
        .expect("initialization lease acquires");
    first
        .begin_initialization(identity)
        .expect("initializing marker publishes");
    File::create(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("committed database fixture creates");
    drop(first);

    let marker_path = root.path().join(ROOT_LOCK_FILENAME);
    let marker = fs::read(&marker_path).expect("initializing marker reads");
    let state_offset = marker
        .windows(b"STATE=".len())
        .position(|window| window == b"STATE=")
        .expect("state field exists");
    fs::write(&marker_path, &marker[..state_offset + b"STATE=EXI".len()])
        .expect("crash-partial state suffix writes");

    let recovered_empty =
        ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
            .expect("restart re-attests the interrupted initialization root");
    let mut recovered = acquire_initialization_root_lease(&recovered_empty, 1, &clock, DEADLINE_MS)
        .expect("partial state suffix recovers under the exclusive lease");
    assert_eq!(recovered.initializing_identity(), Some(identity));
    assert!(recovered
        .database_present()
        .expect("database presence reads"));
    recovered
        .finalize_committed_initialization(identity)
        .expect("verified committed initialization finalizes");
    drop(recovered);

    let existing = ProvisionedExistingCoordinatorRootV1::try_from_attested(
        root.path().to_path_buf(),
        identity,
    )
    .expect("existing root attestation validates");
    acquire_existing_root_lease(&existing, 1, &clock, DEADLINE_MS)
        .expect("exact existing marker with matching identity acquires");
}

#[test]
fn restart_recovers_exact_existing_identity_from_the_attested_lock_marker() {
    let root = SyntheticRoot::new("existing-marker-restart");
    let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
        .expect("empty provisioned root validates");
    let clock = InjectedClock(1_000);
    let identity = CoordinatorRootIdentityV1::from_bytes([0x6D; 32]);
    let mut first = acquire_initialization_root_lease(&empty, 1, &clock, DEADLINE_MS)
        .expect("initialization lease acquires");
    first
        .begin_initialization(identity)
        .expect("initializing marker publishes");
    File::create(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("committed database fixture creates");
    first
        .finalize_committed_initialization(identity)
        .expect("existing marker publishes");
    drop(first);

    let recovery_root =
        ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
            .expect("provisioner re-attests the dedicated recovery root and lock inode");
    let mut recovered = acquire_initialization_root_lease(&recovery_root, 1, &clock, DEADLINE_MS)
        .expect("exact existing marker is recoverable after restart");
    assert_eq!(recovered.recovery_role(), CoordinatorRootRoleV1::Existing);
    assert_eq!(recovered.recovery_identity(), Some(identity));
    assert_eq!(recovered.initializing_identity(), None);
    assert!(recovered
        .database_present()
        .expect("database presence reads"));
    recovered
        .finalize_committed_initialization(identity)
        .expect("existing finalization is idempotent for the same identity");
    drop(recovered);

    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 25)
        .expect("provisioner-attested publication recovery config validates");
    let error = SqliteCoordinatorStoreV1::open_or_create(
        config,
        InjectedClock(1_000),
        HistoricalPlanKeys,
        DEADLINE_MS,
    )
    .expect_err("EXISTING marker must never authorize an exact-empty database");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::SchemaInvalid);
}

#[test]
fn lifecycle_and_or_replace_guards_are_present_in_reviewed_sql() {
    for trigger in [
        "coordinator_store_meta_initial_insert_guard",
        "coordinator_store_meta_single_row_guard",
        "coordinator_store_meta_no_delete",
        "coordinator_store_meta_root_transition_guard",
    ] {
        assert!(STORE_SCHEMA.contains(trigger));
    }
    assert!(STORE_SCHEMA.contains("OLD.root_lifecycle_state = 'ACTIVE'"));
    assert!(STORE_SCHEMA.contains("NEW.root_lifecycle_state = 'RESTORE_PENDING'"));
    assert!(!STORE_SCHEMA.contains("OLD.root_lifecycle_state = 'RESTORE_PENDING'\n     AND NEW.root_lifecycle_state = 'ACTIVE'"));
}

#[test]
fn late_database_collision_after_empty_attestation_is_never_adopted() {
    let root = SyntheticRoot::new("late-database-collision");
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 25)
        .expect("empty trusted config validates before collision");
    let database_path = root.path().join(COORDINATOR_DATABASE_FILENAME);
    let sentinel = b"DO-NOT-ADOPT-CONCURRENT-DATABASE";
    fs::write(&database_path, sentinel).expect("late colliding file publishes");

    let error = SqliteCoordinatorStoreV1::open_or_create(
        config,
        InjectedClock(1_000),
        HistoricalPlanKeys,
        DEADLINE_MS,
    )
    .expect_err("late database collision must fail closed");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::RootRoleMismatch);
    assert_eq!(fs::read(database_path).expect("sentinel reads"), sentinel);
}

#[test]
fn initialization_deadline_is_rechecked_inside_the_transaction_before_commit() {
    let root = SyntheticRoot::new("deadline-before-initialization-commit");
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 25)
        .expect("empty trusted config validates");
    let error = SqliteCoordinatorStoreV1::open_or_create(
        config,
        ExpiringInitializationClock {
            calls: AtomicU64::new(0),
            expire_on_call: 4,
        },
        HistoricalPlanKeys,
        DEADLINE_MS,
    )
    .expect_err("deadline reached at the pre-commit check must roll back schema v1");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::DeadlineReached);

    let database_path = root.path().join(COORDINATOR_DATABASE_FILENAME);
    let connection = Connection::open(database_path).expect("rolled-back database opens raw");
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .expect("application id reads");
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user version reads");
    let object_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .expect("schema objects count");
    assert_eq!((application_id, user_version, object_count), (0, 0, 0));
    let marker = fs::read(root.path().join(ROOT_LOCK_FILENAME)).expect("role marker reads");
    assert!(
        marker.starts_with(b"HELIXOS_COORDINATOR_ROOT_LOCK_V1\nROOT_IDENTITY="),
        "database creation may begin only after durable initialization identity"
    );
    assert!(
        marker.ends_with(b"\nSTATE=INITIALIZING\n"),
        "rolled-back database remains recoverable under its assigned identity"
    );
}

#[test]
fn empty_root_initializes_exact_v1_and_wrong_profiles_fail_without_repair() {
    const EXPECTED_SCHEMA_SHA256: [u8; 32] = [
        0xe7, 0xb7, 0xc6, 0xc7, 0x0f, 0x35, 0x6a, 0xfe, 0x4e, 0x45, 0xb3, 0xe2, 0xc7, 0x21, 0x0b,
        0x38, 0xc4, 0xcc, 0xc0, 0xf6, 0x9a, 0x01, 0x2c, 0xbd, 0xad, 0xdd, 0x10, 0x3a, 0x88, 0x27,
        0x88, 0x0e,
    ];
    let root = SyntheticRoot::new("empty-to-v1");
    let identity = initialize_store(&root);
    assert_eq!(
        format!("{identity:?}"),
        "CoordinatorRootIdentityEvidenceV1 { .. }"
    );
    assert_eq!(embedded_schema_v1_sha256(), EXPECTED_SCHEMA_SHA256);

    let connection = Connection::open(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("initialized database opens");
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .expect("application identity reads");
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("schema version reads");
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("journal mode reads");
    let metadata = connection
        .query_row(
            "SELECT singleton, format_version, root_identity, root_lifecycle_state, \
             restore_identity_digest, restore_attestation_digest, restore_state_generation \
             FROM coordinator_store_meta",
            [],
            |row| {
                Ok(MetadataSnapshot {
                    singleton: row.get(0)?,
                    format_version: row.get(1)?,
                    root_identity: row.get(2)?,
                    lifecycle: row.get(3)?,
                    restore_identity: row.get(4)?,
                    restore_attestation: row.get(5)?,
                    restore_generation: row.get(6)?,
                })
            },
        )
        .expect("metadata reads");
    assert_eq!(application_id, COORDINATOR_STORE_APPLICATION_ID_V1);
    assert_eq!(user_version, COORDINATOR_STORE_SCHEMA_VERSION_V1);
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(metadata.singleton, 1);
    assert_eq!(metadata.format_version, 1);
    assert_eq!(metadata.root_identity, identity.to_attested_bytes());
    assert_eq!(metadata.lifecycle, "ACTIVE");
    assert_eq!(
        (
            metadata.restore_identity,
            metadata.restore_attestation,
            metadata.restore_generation,
        ),
        (None, None, 0)
    );

    drop(connection);
    let reopened = reopen_store(&root, identity).expect("healthy initialized store reopens");
    assert_eq!(reopened.operation_count(), 0);
    drop(reopened);
    let connection = Connection::open(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("initialized database reopens for corruption");

    let mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .expect("persistent profile weakens");
    assert_eq!(mode.to_ascii_lowercase(), "delete");
    drop(connection);
    let error = reopen_store(&root, identity).expect_err("weaker persistent profile denies");
    assert_eq!(
        error,
        CoordinatorStoreOpenErrorV1::DurabilityProfileUnavailable
    );
    let connection = Connection::open(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("database opens after denial");
    let mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("journal mode reads after denial");
    assert_eq!(mode.to_ascii_lowercase(), "delete");
}

#[test]
fn copied_identity_and_restore_pending_never_reopen_as_active() {
    let source = SyntheticRoot::new("copy-source");
    let source_identity = initialize_store(&source);
    let destination = SyntheticRoot::new("copy-destination");
    let destination_identity = initialize_store(&destination);

    let source_database = source.path().join(COORDINATOR_DATABASE_FILENAME);
    let destination_database = destination.path().join(COORDINATOR_DATABASE_FILENAME);
    let source_connection = Connection::open(&source_database).expect("source opens");
    let checkpoint: (i64, i64, i64) = source_connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .expect("source checkpoints");
    assert_eq!(checkpoint.0, 0, "checkpoint must not be busy");
    drop(source_connection);
    let _ = fs::remove_file(destination.path().join("coordinator.sqlite3-wal"));
    let _ = fs::remove_file(destination.path().join("coordinator.sqlite3-shm"));
    fs::copy(&source_database, &destination_database).expect("active database copies");

    let publication_recovery =
        CoordinatorStoreConfigV1::try_new_empty_attested(destination.path().to_path_buf(), 25)
            .expect("existing publication layout is provisioner-attested for recovery");
    let recovery_error = SqliteCoordinatorStoreV1::open_or_create(
        publication_recovery,
        InjectedClock(1_000),
        HistoricalPlanKeys,
        DEADLINE_MS,
    )
    .expect_err("publication recovery must bind marker identity to database metadata");
    assert_eq!(
        recovery_error,
        CoordinatorStoreOpenErrorV1::RootIdentityMismatch
    );

    let error = reopen_store(&destination, destination_identity)
        .expect_err("copied active identity must not gain destination authority");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::RootIdentityMismatch);
    assert_eq!(format!("{error:?}"), "ROOT_IDENTITY_MISMATCH");
    assert!(!format!("{error:?}").contains("copy-source"));

    let connection = Connection::open(&source_database).expect("source opens for restore marker");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers establish");
    connection
        .execute(
            "UPDATE coordinator_store_meta SET \
                 store_generation = 1, \
                 root_identity = ?1, \
                 root_lifecycle_state = 'RESTORE_PENDING', \
                 restore_identity_digest = ?2, \
                 restore_attestation_digest = ?3, \
                 restore_state_generation = 1 \
             WHERE singleton = 1",
            params![&[0xA1_u8; 32][..], &[0xB2_u8; 32][..], &[0xC3_u8; 32][..]],
        )
        .expect("one-way restore-pending transition succeeds");
    drop(connection);
    let error = reopen_store(&source, source_identity)
        .expect_err("generic open must deny restore-pending state");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::RestorePending);
    assert_eq!(format!("{error:?}"), "RESTORE_PENDING");
}

#[test]
fn lifecycle_delete_reverse_and_or_replace_mutations_are_rejected() {
    let root = SyntheticRoot::new("lifecycle-triggers");
    let identity = initialize_store(&root);
    let connection = Connection::open(root.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("initialized database opens");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers establish");

    assert!(connection
        .execute("DELETE FROM coordinator_store_meta", [])
        .is_err());
    assert!(connection
        .execute(
            "INSERT OR REPLACE INTO coordinator_store_meta \
             SELECT * FROM coordinator_store_meta WHERE singleton = 1",
            [],
        )
        .is_err());
    connection
        .execute(
            "INSERT INTO preparation_quarantines (\
                 quarantine_id, attempt_id, operation_binding_digest, quarantine_reason, \
                 quarantine_status, created_generation, resolved_generation, \
                 recovery_manifest_digest, orphan_resolution_evidence_digest, \
                 orphan_retirement_id, orphan_retirement_state, orphan_retired_generation, \
                 orphan_retirement_manifest_digest\
             ) VALUES (?1, ?2, ?3, 'AMBIGUOUS_COMMIT', 'ACTIVE', 1, NULL, NULL, NULL, \
                       NULL, NULL, NULL, NULL)",
            params![&[0x11_u8; 32][..], &[0x22_u8; 32][..], &[0x33_u8; 32][..]],
        )
        .expect("active quarantine inserts");
    assert!(connection
        .execute(
            "INSERT OR REPLACE INTO preparation_quarantines \
             SELECT * FROM preparation_quarantines WHERE quarantine_id = ?1",
            params![&[0x11_u8; 32][..]],
        )
        .is_err());
    let quarantine_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
            row.get(0)
        })
        .expect("quarantine count reads");
    assert_eq!(quarantine_count, 1);

    connection
        .execute(
            "UPDATE coordinator_store_meta SET \
                 store_generation = 1, \
                 root_identity = ?1, \
                 root_lifecycle_state = 'RESTORE_PENDING', \
                 restore_identity_digest = ?2, \
                 restore_attestation_digest = ?3, \
                 restore_state_generation = 1 \
             WHERE singleton = 1",
            params![&[0xD4_u8; 32][..], &[0xE5_u8; 32][..], &[0xF6_u8; 32][..]],
        )
        .expect("allowed active-to-pending transition succeeds");
    let reverse = connection.execute(
        "UPDATE coordinator_store_meta SET \
             store_generation = 2, \
             root_identity = ?1, \
             root_lifecycle_state = 'ACTIVE', \
             restore_identity_digest = NULL, \
             restore_attestation_digest = NULL, \
             restore_state_generation = 0 \
         WHERE singleton = 1",
        params![&identity.to_attested_bytes()[..]],
    );
    assert!(
        reverse.is_err(),
        "pending-to-active must be unrepresentable"
    );

    let lifecycle: String = connection
        .query_row(
            "SELECT root_lifecycle_state FROM coordinator_store_meta",
            [],
            |row| row.get(0),
        )
        .expect("lifecycle reads");
    assert_eq!(lifecycle, "RESTORE_PENDING");
    let trigger_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema \
             WHERE type = 'trigger' AND tbl_name = 'coordinator_store_meta'",
            [],
            |row| row.get(0),
        )
        .expect("lifecycle triggers count");
    assert_eq!(trigger_count, 4);
}

#[test]
fn reviewed_schema_inventory_is_byte_exact_and_every_object_drift_fails_closed() {
    let expected = reviewed_schema_objects();
    assert_eq!(
        expected.len(),
        49,
        "reviewed v1 schema object count drifted"
    );
    assert_eq!(
        expected
            .iter()
            .filter(|(kind, _, _, _)| kind == "table")
            .count(),
        9,
    );
    assert_eq!(
        expected
            .iter()
            .filter(|(kind, _, _, _)| kind == "index")
            .count(),
        23,
    );
    assert_eq!(
        expected
            .iter()
            .filter(|(kind, _, _, _)| kind == "trigger")
            .count(),
        17,
    );

    let exact = SyntheticRoot::new("exact-schema-inventory");
    let exact_identity = initialize_store(&exact);
    let connection = Connection::open(exact.path().join(COORDINATOR_DATABASE_FILENAME))
        .expect("initialized schema opens raw");
    assert_eq!(schema_objects(&connection), expected);
    drop(connection);
    reopen_store(&exact, exact_identity).expect("byte-exact reviewed schema reopens");

    for (kind, name, _, _) in &expected {
        let root = SyntheticRoot::new(&format!("missing-{kind}-{name}"));
        let identity = initialize_store(&root);
        let connection = Connection::open(root.path().join(COORDINATOR_DATABASE_FILENAME))
            .expect("schema-corruption database opens raw");
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("foreign keys disable for out-of-band corruption");
        let quoted = quote_identifier(name);
        let statement = match kind.as_str() {
            "table" => format!(
                "ALTER TABLE {quoted} RENAME TO {}",
                quote_identifier(&format!("{name}__corrupt"))
            ),
            "index" => format!("DROP INDEX {quoted}"),
            "trigger" => format!("DROP TRIGGER {quoted}"),
            other => panic!("unexpected reviewed schema object kind {other}"),
        };
        connection
            .execute_batch(&statement)
            .unwrap_or_else(|error| panic!("{kind} {name} corruption applies: {error}"));
        drop(connection);
        assert_eq!(
            reopen_store(&root, identity).unwrap_err(),
            CoordinatorStoreOpenErrorV1::SchemaInvalid,
            "missing or renamed {kind} {name} was not rejected",
        );
    }
}

#[test]
fn altered_table_index_and_trigger_sql_each_fail_exact_schema_reopen() {
    for (label, mutation) in [
        (
            "table-sql",
            "ALTER TABLE budget_scopes ADD COLUMN injected_schema_drift INTEGER",
        ),
        (
            "index-sql",
            "DROP INDEX budget_scopes_generation_uq; \
             CREATE UNIQUE INDEX budget_scopes_generation_uq \
             ON budget_scopes (currency_code, scope_generation)",
        ),
        (
            "trigger-sql",
            "DROP TRIGGER budget_scopes_no_delete; \
             CREATE TRIGGER budget_scopes_no_delete BEFORE DELETE ON budget_scopes \
             BEGIN SELECT RAISE(ABORT, 'different reviewed SQL'); END",
        ),
    ] {
        let root = SyntheticRoot::new(label);
        let identity = initialize_store(&root);
        let connection = Connection::open(root.path().join(COORDINATOR_DATABASE_FILENAME))
            .expect("schema-drift database opens raw");
        connection
            .execute_batch(mutation)
            .expect("out-of-band schema drift applies");
        drop(connection);
        assert_eq!(
            reopen_store(&root, identity).unwrap_err(),
            CoordinatorStoreOpenErrorV1::SchemaInvalid,
            "altered {label} survived exact schema verification",
        );
    }
}

#[test]
fn recursive_trigger_profile_and_every_unique_replace_key_are_closed() {
    for required in [
        ".pragma_update(None, \"recursive_triggers\", \"ON\")",
        "profile_pragma_i64(connection, \"recursive_triggers\")? != 1",
    ] {
        assert!(
            CONNECTION_SOURCE.contains(required),
            "every coordinator connection must establish and read back recursive triggers",
        );
    }

    let fixture = PreparedCorruptionRootV1::new();
    let connection = Connection::open(&fixture.database).expect("prepared database opens raw");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("out-of-band weak control disables foreign keys");
    connection
        .pragma_update(None, "recursive_triggers", "OFF")
        .expect("weak test connection disables recursive delete triggers");
    assert_eq!(
        connection
            .pragma_query_value(None, "recursive_triggers", |row| row.get::<_, i64>(0))
            .expect("weak recursive-trigger value reads"),
        0,
    );
    connection
        .execute(
            "INSERT OR REPLACE INTO budget_scopes SELECT * FROM budget_scopes LIMIT 1",
            [],
        )
        .expect("control proves OR REPLACE bypasses delete triggers when profile is weak");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive delete triggers establish");
    assert_eq!(
        connection
            .pragma_query_value(None, "recursive_triggers", |row| row.get::<_, i64>(0))
            .expect("strong recursive-trigger value reads"),
        1,
    );
    let expected_keys = [
        "budget_reservations|budget_reservations_attempt_uq|c|0|attempt_id",
        "budget_reservations|budget_reservations_operation_uq|c|0|operation_id",
        "budget_reservations|sqlite_autoindex_budget_reservations_1|pk|0|reservation_id",
        "budget_scopes|budget_scopes_binding_uq|c|0|task_lease_digest,allowance_binding_digest,scope_generation,currency_code,price_table_id",
        "budget_scopes|budget_scopes_generation_uq|c|0|scope_generation",
        "budget_scopes|sqlite_autoindex_budget_scopes_1|pk|0|scope_id",
        "coordinator_store_meta|sqlite_autoindex_coordinator_store_meta_1|pk|0|singleton",
        "operation_transitions|operation_transitions_complete_identity_uq|c|0|operation_id,state_generation,event_id,new_state",
        "operation_transitions|operation_transitions_event_uq|c|0|event_id",
        "operation_transitions|operation_transitions_operation_state_uq|c|0|operation_id,new_state",
        "operation_transitions|sqlite_autoindex_operation_transitions_1|pk|0|state_generation",
        "preparation_comparisons|preparation_comparisons_digest_uq|c|0|comparison_digest",
        "preparation_comparisons|sqlite_autoindex_preparation_comparisons_1|pk|0|operation_id",
        "preparation_events|preparation_events_generation_uq|c|0|event_generation",
        "preparation_events|preparation_events_transition_uq|c|0|operation_id,operation_state_generation",
        "preparation_events|sqlite_autoindex_preparation_events_1|pk|0|event_id",
        "preparation_quarantines|preparation_quarantines_attempt_active_uq|c|1|attempt_id",
        "preparation_quarantines|preparation_quarantines_generation_uq|c|0|created_generation",
        "preparation_quarantines|preparation_quarantines_orphan_manifest_uq|c|1|recovery_manifest_digest",
        "preparation_quarantines|preparation_quarantines_orphan_retirement_manifest_uq|c|1|orphan_retirement_manifest_digest",
        "preparation_quarantines|preparation_quarantines_orphan_retirement_uq|c|1|orphan_retirement_id",
        "preparation_quarantines|sqlite_autoindex_preparation_quarantines_1|pk|0|quarantine_id",
        "preparation_recovery_evidence|preparation_recovery_manifest_uq|c|1|manifest_digest",
        "preparation_recovery_evidence|preparation_recovery_material_uq|c|1|material_id",
        "preparation_recovery_evidence|preparation_recovery_retirement_manifest_uq|c|1|retirement_manifest_digest",
        "preparation_recovery_evidence|preparation_recovery_retirement_uq|c|1|retirement_id",
        "preparation_recovery_evidence|sqlite_autoindex_preparation_recovery_evidence_1|pk|0|operation_id",
        "prepared_operations|prepared_operations_attempt_id_uq|c|0|attempt_id",
        "prepared_operations|prepared_operations_plan_id_uq|c|0|plan_id",
        "prepared_operations|prepared_operations_reservation_id_uq|c|0|reservation_id",
        "prepared_operations|prepared_operations_state_generation_uq|c|0|state_generation",
        "prepared_operations|sqlite_autoindex_prepared_operations_1|pk|0|operation_id",
    ];
    assert_eq!(unique_key_inventory(&connection), expected_keys);

    connection
        .execute(
            "INSERT INTO preparation_quarantines (\
                 quarantine_id, attempt_id, operation_binding_digest, quarantine_reason, \
                 quarantine_status, created_generation, resolved_generation, \
                 recovery_manifest_digest, orphan_resolution_evidence_digest, \
                 orphan_retirement_id, orphan_retirement_state, orphan_retired_generation, \
                 orphan_retirement_manifest_digest\
             ) VALUES (?1, ?2, ?3, 'ORPHAN_MATERIAL', 'ACTIVE', 100, NULL, ?4, \
                       NULL, NULL, NULL, NULL, NULL)",
            params![
                &[0x71_u8; 32][..],
                &[0x72_u8; 32][..],
                &[0x73_u8; 32][..],
                &[0x74_u8; 32][..],
            ],
        )
        .expect("orphan row inserts active");
    connection
        .execute(
            "UPDATE preparation_quarantines SET quarantine_status = 'RESOLVED_TOMBSTONE', \
                 resolved_generation = 101, orphan_resolution_evidence_digest = ?1, \
                 orphan_retirement_id = ?2, orphan_retirement_state = 'RETIREMENT_PENDING' \
             WHERE quarantine_id = ?3",
            params![&[0x75_u8; 32][..], &[0x76_u8; 32][..], &[0x71_u8; 32][..],],
        )
        .expect("orphan row advances pending");
    connection
        .execute(
            "UPDATE preparation_quarantines SET orphan_retirement_state = 'RETIRED_TOMBSTONE', \
                 orphan_retired_generation = 102, orphan_retirement_manifest_digest = ?1 \
             WHERE quarantine_id = ?2",
            params![&[0x77_u8; 32][..], &[0x71_u8; 32][..]],
        )
        .expect("orphan row advances retired");
    for reverse in [
        "UPDATE preparation_quarantines SET orphan_retirement_state = 'RETIREMENT_PENDING', \
             orphan_retired_generation = NULL, orphan_retirement_manifest_digest = NULL \
         WHERE quarantine_id = x'7171717171717171717171717171717171717171717171717171717171717171'",
        "UPDATE preparation_quarantines SET quarantine_status = 'ACTIVE', \
             resolved_generation = NULL, orphan_resolution_evidence_digest = NULL, \
             orphan_retirement_id = NULL, orphan_retirement_state = NULL, \
             orphan_retired_generation = NULL, orphan_retirement_manifest_digest = NULL \
         WHERE quarantine_id = x'7171717171717171717171717171717171717171717171717171717171717171'",
    ] {
        assert!(
            connection.execute_batch(reverse).is_err(),
            "terminal orphan lifecycle reversal must be rejected by reviewed SQL",
        );
    }
    connection
        .execute(
            "UPDATE preparation_recovery_evidence SET material_state = 'RETIREMENT_PENDING', \
                 retirement_id = ?1, retirement_generation = 103",
            params![&[0x78_u8; 32][..]],
        )
        .expect("operation recovery advances pending");
    connection
        .execute(
            "UPDATE preparation_recovery_evidence SET material_state = 'RETIRED_TOMBSTONE', \
                 retirement_manifest_digest = ?1",
            params![&[0x79_u8; 32][..]],
        )
        .expect("operation recovery advances retired");

    for table in [
        "coordinator_store_meta",
        "budget_scopes",
        "prepared_operations",
        "operation_transitions",
        "preparation_comparisons",
        "budget_reservations",
        "preparation_recovery_evidence",
        "preparation_events",
        "preparation_quarantines",
    ] {
        let trigger = format!("{table}_no_delete");
        let trigger_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'trigger' \
                 AND tbl_name = ?1 AND name = ?2 AND sql LIKE '%BEFORE DELETE%'",
                params![table, trigger],
                |row| row.get(0),
            )
            .expect("permanence trigger inventory reads");
        assert_eq!(trigger_count, 1, "missing no-delete guard for {table}");
        let count_before: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("historical row count reads");
        assert!(count_before > 0, "OR REPLACE fixture missing for {table}");
        assert!(
            connection
                .execute(
                    &format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table} LIMIT 1"),
                    [],
                )
                .is_err(),
            "recursive delete guard allowed OR REPLACE on {table}",
        );
        let count_after: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("historical row count rereads");
        assert_eq!(count_after, count_before, "OR REPLACE changed {table}");
    }
}

#[test]
fn canonical_plan_and_every_cross_record_link_corruption_fail_full_reopen() {
    for (label, mutation) in [
        (
            "canonical-plan",
            "UPDATE prepared_operations SET canonical_plan = \
             CAST(canonical_plan || x'00' AS BLOB), \
             canonical_plan_length = canonical_plan_length + 1",
        ),
        (
            "operation-reservation-attempt",
            "UPDATE budget_reservations SET attempt_id = zeroblob(32)",
        ),
        (
            "operation-comparison-link",
            "UPDATE preparation_comparisons SET operation_id = 'operation:corrupt-comparison'",
        ),
        (
            "operation-event-link",
            "UPDATE preparation_events SET operation_id = 'operation:corrupt-event'",
        ),
        (
            "operation-recovery-link",
            "UPDATE preparation_recovery_evidence \
             SET operation_id = 'operation:corrupt-recovery'",
        ),
        (
            "scope-held-sum",
            "UPDATE budget_scopes SET held_recovery_bytes = held_recovery_bytes - 1",
        ),
    ] {
        let fixture = PreparedCorruptionRootV1::new();
        let connection = Connection::open(&fixture.database).expect("prepared database opens raw");
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("foreign keys disable for corruption injection");
        connection
            .execute_batch(mutation)
            .unwrap_or_else(|error| panic!("{label} corruption applies: {error}"));
        drop(connection);
        fixture.assert_full_reopen_rejected(label);
    }
}

#[test]
fn terminal_operation_lifecycle_reversal_is_rejected_by_full_reopen() {
    let fixture = PreparedCorruptionRootV1::new();
    let operation_id: String = Connection::open(&fixture.database)
        .expect("prepared database opens for operation identity")
        .query_row("SELECT operation_id FROM prepared_operations", [], |row| {
            row.get(0)
        })
        .expect("prepared operation identity reads");
    let known = SyntheticKnownFailureCaseV1::load_preparing_v1(
        &fixture.database,
        &operation_id,
        17,
        DEADLINE_MS,
    )
    .expect("known pre-dispatch failure binding loads");
    assert!(matches!(
        fail_synthetic_before_dispatch_v1(
            &fixture.database,
            &known,
            SyntheticNoDispatchGuardCaseV1::Exact,
            1_000,
        ),
        PreparationFailureOutcomeV1::Failed
    ));

    let connection = Connection::open(&fixture.database).expect("failed database opens raw");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("foreign keys disable for lifecycle corruption");
    let (preparing_generation, preparing_event): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT state_generation, event_id FROM operation_transitions \
             WHERE operation_id = ?1 AND previous_state IS NULL AND new_state = 'PREPARING'",
            [&operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("initial transition identity reads");
    connection
        .execute(
            "UPDATE prepared_operations SET operation_state = 'PREPARING', \
                 state_generation = ?1, failed_generation = NULL, failed_reason_code = NULL, \
                 current_event_id = ?2 WHERE operation_id = ?3",
            params![preparing_generation, preparing_event, operation_id],
        )
        .expect("out-of-band terminal-to-preparing corruption applies");
    drop(connection);
    fixture.assert_full_reopen_rejected("FAILED-to-PREPARING lifecycle reversal");
}
