//! PLAN-005 T019 version-boundary contracts for the additive coordinator dispatch store.
//!
//! These tests deliberately keep using the public PLAN-004 V1 opener as the old-binary
//! oracle.  The PLAN-005 V2 seam remains private until the explicit paused migration
//! workflow owns all of its preconditions.

use helix_contracts::{ContractError, Ed25519KeyResolver};
use helix_coordinator_sqlite::{
    embedded_schema_v1_sha256, CoordinatorMonotonicClockV1, CoordinatorRootIdentityEvidenceV1,
    CoordinatorStoreConfigV1, CoordinatorStoreOpenErrorV1, SqliteCoordinatorStoreV1,
    SqliteCoordinatorStoreV2, COORDINATOR_STORE_APPLICATION_ID_V1,
    COORDINATOR_STORE_SCHEMA_VERSION_V1,
};
use helix_dispatch_contracts::{
    decode_and_verify_execution_receipt_v1, decode_and_verify_retained_execution_grant_v1,
    ContractError as DispatchContractError, GrantKeyResolver, GrantVerificationKeyV1,
    ReceiptKeyResolver, ReceiptVerificationBindingsV1, ReceiptVerificationKeyV1,
    Result as DispatchContractResult, Sha256Digest, VerificationKeyStatusV1,
};
#[cfg(feature = "test-fault-injection")]
use helix_plan_dispatch::FaultInjectionModeV1;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "test-fault-injection")]
use std::sync::Arc;

const V1_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);
const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);
const V2_SCHEMA_VERSION: i64 = 2;
const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const FIXTURE_GRANT_KEY: [u8; 32] = [
    167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246, 103,
    165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
];
const FIXTURE_RECEIPT_KEY: [u8; 32] = [
    73, 138, 246, 228, 225, 240, 240, 39, 22, 120, 165, 254, 244, 181, 164, 82, 26, 243, 72, 154,
    220, 213, 40, 89, 255, 132, 157, 231, 154, 245, 149, 120,
];

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl CoordinatorMonotonicClockV1 for FixedClock {
    fn now_monotonic_ms(
        &self,
    ) -> Result<u64, helix_coordinator_sqlite::CoordinatorClockUnavailableV1> {
        Ok(self.0)
    }
}

struct HistoricalPlanKeys;

impl Ed25519KeyResolver for HistoricalPlanKeys {
    fn resolve_ed25519(&self, _: &str) -> helix_contracts::Result<[u8; 32]> {
        Err(ContractError::UnknownKey)
    }
}

struct HistoricalGrantKeys;

impl GrantKeyResolver for HistoricalGrantKeys {
    fn resolve_grant_key(&self, key_id: &str) -> DispatchContractResult<GrantVerificationKeyV1> {
        if key_id == "fixture-grant-key-v1" {
            Ok(GrantVerificationKeyV1::historical(FIXTURE_GRANT_KEY))
        } else {
            Err(DispatchContractError::UnknownKey)
        }
    }
}

struct HistoricalReceiptKeys;

impl ReceiptKeyResolver for HistoricalReceiptKeys {
    fn resolve_receipt_key(
        &self,
        key_id: &str,
    ) -> DispatchContractResult<ReceiptVerificationKeyV1> {
        if key_id == "fixture-receipt-key-v1" {
            Ok(ReceiptVerificationKeyV1::historical(FIXTURE_RECEIPT_KEY))
        } else {
            Err(DispatchContractError::UnknownKey)
        }
    }
}

struct MigrationRoot {
    path: PathBuf,
}

impl MigrationRoot {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-dispatch-migration-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("migration root creates");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn database(&self) -> PathBuf {
        self.path.join("coordinator.sqlite3")
    }
}

impl Drop for MigrationRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn initialize_v1(root: &MigrationRoot) -> CoordinatorRootIdentityEvidenceV1 {
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 25)
        .expect("empty attested coordinator config validates");
    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        FixedClock(1_000),
        HistoricalPlanKeys,
        10_000,
    )
    .expect("exact V1 coordinator initializes");
    let identity = store.root_identity_evidence();
    drop(store);
    identity
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn t070_real_migration_workflow_reaches_fb072_through_fb076_and_reopens_exactly() {
    for boundary_id in [
        "PLAN005-FB-072",
        "PLAN005-FB-073",
        "PLAN005-FB-074",
        "PLAN005-FB-075",
        "PLAN005-FB-076",
    ] {
        let root = MigrationRoot::new(boundary_id);
        let ready_calls = Arc::new(AtomicU64::new(0));
        let unexpected_process_barrier_calls = Arc::new(AtomicU64::new(0));
        let ready_observation = Arc::clone(&ready_calls);
        let barrier_observation = Arc::clone(&unexpected_process_barrier_calls);

        helix_coordinator_sqlite::run_t070_migration_fault_probe_for_test_v1(
            boundary_id,
            1,
            FaultInjectionModeV1::InProcess,
            root.path().to_path_buf(),
            move || {
                ready_observation.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move || {
                barrier_observation.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap_or_else(|error| panic!("{boundary_id} real migration fault failed: {error}"));

        assert_eq!(ready_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            unexpected_process_barrier_calls.load(Ordering::SeqCst),
            0,
            "in-process selection must not invoke the process callback"
        );
        helix_coordinator_sqlite::verify_t070_migration_fault_readback_for_test_v1(
            boundary_id,
            root.path().to_path_buf(),
        )
        .unwrap_or_else(|error| panic!("{boundary_id} independent reopen failed: {error}"));
    }
}

fn reopen_v1(
    root: &MigrationRoot,
    identity: CoordinatorRootIdentityEvidenceV1,
) -> Result<SqliteCoordinatorStoreV1<FixedClock, HistoricalPlanKeys>, CoordinatorStoreOpenErrorV1> {
    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        25,
    )
    .expect("existing attested coordinator config validates");
    SqliteCoordinatorStoreV1::open_or_create(config, FixedClock(1_001), HistoricalPlanKeys, 10_000)
}

fn install_exact_empty_v2(root: &MigrationRoot) {
    let connection = Connection::open(root.database()).expect("V1 database opens for migration");
    let root_identity: Vec<u8> = connection
        .query_row(
            "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("root identity reads");
    connection
        .execute_batch(V2_OVERLAY)
        .expect("reviewed V2 overlay installs");
    connection
        .execute(
            "INSERT INTO dispatch_store_meta (
                singleton, extension_format_version, dispatch_store_generation,
                dispatch_generation, delivery_generation, receipt_generation,
                reconciliation_generation, event_generation, migration_generation,
                ordinary_queue_capacity, control_queue_capacity, root_lifecycle_state,
                restore_index_digest, restore_state_generation
             ) VALUES (1, 1, 1, 0, 0, 0, 0, 0, 1, 1024, 32, 'ACTIVE', NULL, 0)",
            [],
        )
        .expect("dispatch metadata installs");
    connection
        .execute(
            "INSERT INTO coordinator_v2_migrations (
                migration_attempt_id, source_schema_digest, source_root_identity,
                source_summary_digest, verified_backup_digest, overlay_schema_digest,
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms,
                tool_identity
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1000, 1000, 'helixos-test-v1')",
            rusqlite::params![
                [0x42_u8; 32].as_slice(),
                embedded_schema_v1_sha256().as_slice(),
                root_identity,
                [0x43_u8; 32].as_slice(),
                [0x44_u8; 32].as_slice(),
                <[u8; 32]>::from(Sha256::digest(V2_OVERLAY.as_bytes())).as_slice(),
            ],
        )
        .expect("migration receipt installs");
}

fn pragma_i64(connection: &Connection, name: &str) -> i64 {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .unwrap_or_else(|_| panic!("PRAGMA {name} reads"))
}

fn schema_objects(connection: &Connection) -> Vec<(String, String, String, String)> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
        )
        .expect("schema inventory prepares");
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("schema inventory queries")
        .collect::<Result<Vec<_>, _>>()
        .expect("schema inventory decodes")
}

fn coordinator_rust_sources() -> Vec<(PathBuf, String)> {
    fn visit(directory: &Path, sources: &mut Vec<(PathBuf, String)>) {
        let mut entries = fs::read_dir(directory)
            .expect("coordinator source directory reads")
            .map(|entry| entry.expect("coordinator source entry reads").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(&path, sources);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let source = fs::read_to_string(&path).expect("coordinator Rust source is UTF-8");
                sources.push((path, source));
            }
        }
    }

    let mut sources = Vec::new();
    visit(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources
}

fn source_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    let mut block_depth = 0_u64;
    while cursor < bytes.len() {
        if block_depth > 0 {
            if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                block_depth += 1;
                cursor += 2;
            } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
                block_depth -= 1;
                cursor += 2;
            } else {
                if bytes[cursor] == b'\n' {
                    output.push('\n');
                }
                cursor += 1;
            }
        } else if bytes.get(cursor..cursor + 2) == Some(b"//") {
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
        } else if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            block_depth = 1;
            cursor += 2;
        } else {
            output.push(char::from(bytes[cursor]));
            cursor += 1;
        }
    }
    assert_eq!(block_depth, 0, "production source comments are balanced");
    output
}

fn production_source_without_comments(source: &str) -> String {
    let source = source_without_comments(source);
    let test_start = ["#[cfg(test)]", "#[cfg(all(test"]
        .into_iter()
        .filter_map(|marker| source.find(marker))
        .min()
        .unwrap_or(source.len());
    source[..test_start].to_owned()
}

fn canonical_fixture(name: &str) -> Vec<u8> {
    let corpus: serde_json::Value =
        serde_json::from_str(CASES).expect("reviewed PLAN-005 fixture decodes");
    serde_json_canonicalizer::to_vec(&corpus["base_envelopes"][name])
        .expect("reviewed PLAN-005 fixture canonicalizes")
}

#[derive(Debug, PartialEq, Eq)]
struct HistoricalVerificationObservationV1 {
    grant_digest: Sha256Digest,
    grant_wire: Vec<u8>,
    receipt_digest: Sha256Digest,
    receipt_wire: Vec<u8>,
}

fn verify_historical_grant_and_receipt_v1() -> HistoricalVerificationObservationV1 {
    let grant_wire = canonical_fixture("grant.valid");
    let grant = decode_and_verify_retained_execution_grant_v1(&grant_wire, &HistoricalGrantKeys)
        .expect("retained grant verifies through historical public-key trust");
    assert_eq!(
        grant.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    let adapter_root =
        Sha256Digest::parse_hex("cb4857fc9951f4cb964eaee4ce85bbb664d626a0c757ca01cce79b49e062b24b")
            .expect("fixture adapter root parses");
    let bindings =
        ReceiptVerificationBindingsV1::from_retained_grant_evidence(&grant, adapter_root);
    let receipt_wire = canonical_fixture("receipt.consumed.valid");
    let receipt =
        decode_and_verify_execution_receipt_v1(&receipt_wire, &HistoricalReceiptKeys, &bindings)
            .expect("retained receipt verifies through historical public-key trust");
    assert_eq!(
        receipt.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );

    HistoricalVerificationObservationV1 {
        grant_digest: grant.grant_digest(),
        grant_wire: grant
            .canonical_signed_envelope_bytes()
            .expect("retained grant re-encodes canonically"),
        receipt_digest: receipt.receipt_digest(),
        receipt_wire: receipt
            .canonical_signed_envelope_bytes()
            .expect("retained receipt re-encodes canonically"),
    }
}

#[test]
fn ordinary_v1_open_stays_exact_v1_and_creates_no_dispatch_overlay() {
    let root = MigrationRoot::new("ordinary-v1");
    let identity = initialize_v1(&root);
    let connection = Connection::open(root.database()).expect("V1 database opens directly");

    assert_eq!(
        pragma_i64(&connection, "application_id"),
        COORDINATOR_STORE_APPLICATION_ID_V1
    );
    assert_eq!(
        pragma_i64(&connection, "user_version"),
        COORDINATOR_STORE_SCHEMA_VERSION_V1
    );
    let dispatch_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema \
             WHERE name = 'coordinator_v2_migrations' OR name LIKE 'dispatch_%'",
            [],
            |row| row.get(0),
        )
        .expect("dispatch object count reads");
    assert_eq!(dispatch_objects, 0, "ordinary V1 open must not upgrade");
    assert_eq!(
        embedded_schema_v1_sha256(),
        <[u8; 32]>::from(Sha256::digest(V1_SCHEMA.as_bytes())),
        "the old binary must retain the byte-exact PLAN-004 DDL digest"
    );

    drop(connection);
    let reopened = reopen_v1(&root, identity).expect("exact V1 remains reopenable by V1");
    assert_eq!(reopened.operation_count(), 0);
}

#[test]
fn explicit_v2_open_restarts_without_auto_migration_and_v1_still_refuses() {
    let root = MigrationRoot::new("public-v2-open");
    let identity = initialize_v1(&root);

    let v1_config = CoordinatorStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        25,
    )
    .expect("existing V1 config validates");
    let error = SqliteCoordinatorStoreV2::open_existing(
        v1_config,
        FixedClock(1_001),
        HistoricalPlanKeys,
        10_000,
    )
    .expect_err("ordinary V2 open never migrates V1");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::SchemaUnsupported);

    install_exact_empty_v2(&root);
    let v2_config = CoordinatorStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        25,
    )
    .expect("existing V2 config validates");
    let v2 = SqliteCoordinatorStoreV2::open_existing(
        v2_config,
        FixedClock(1_002),
        HistoricalPlanKeys,
        10_000,
    )
    .expect("exact V2 reopens after restart");
    assert_eq!(v2.operation_count(), 0);
    assert_eq!(v2.root_identity_evidence(), identity);
    drop(v2);

    let v1_error = reopen_v1(&root, identity).expect_err("old V1 binary still refuses V2");
    assert_eq!(v1_error, CoordinatorStoreOpenErrorV1::SchemaUnsupported);
}

#[test]
fn compatible_v2_open_preserves_historical_grant_and_receipt_verification() {
    let before = verify_historical_grant_and_receipt_v1();
    let root = MigrationRoot::new("historical-public-keys");
    let identity = initialize_v1(&root);
    install_exact_empty_v2(&root);

    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        25,
    )
    .expect("compatible V2 root remains provisioner-attested");
    let v2 = SqliteCoordinatorStoreV2::open_existing(
        config,
        FixedClock(1_002),
        HistoricalPlanKeys,
        10_000,
    )
    .expect("compatible V2 root opens without reissuing authority");
    assert_eq!(v2.root_identity_evidence(), identity);

    let after = verify_historical_grant_and_receipt_v1();
    assert_eq!(
        after, before,
        "compatible open must preserve exact retained v1 wires and historical signatures"
    );
}

#[test]
fn reviewed_v2_sql_is_additive_and_publishes_version_two_last() {
    let connection = Connection::open_in_memory().expect("oracle database opens");
    connection
        .execute_batch(V1_SCHEMA)
        .expect("reviewed PLAN-004 V1 DDL installs");
    let v1_objects = schema_objects(&connection);
    assert!(!v1_objects.is_empty());

    let last_statement = V2_OVERLAY
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty() && !line.starts_with("--"));
    assert_eq!(
        last_statement,
        Some("PRAGMA user_version = 2;"),
        "schema version must be the final overlay statement before caller COMMIT"
    );
    for required in [
        "PRAGMA application_id = 1212962883;",
        "CREATE TABLE dispatch_store_meta (",
        "CREATE TABLE coordinator_v2_migrations (",
        "source_schema_digest BLOB NOT NULL",
        "verified_backup_digest BLOB NOT NULL",
        "overlay_schema_digest BLOB NOT NULL",
        "CREATE TRIGGER coordinator_v2_migrations_no_update",
        "CREATE TRIGGER coordinator_v2_migrations_no_delete",
        "RESTORE_PENDING denies new dispatch authority",
    ] {
        assert!(
            V2_OVERLAY.contains(required),
            "missing V2 contract {required}"
        );
    }

    connection
        .execute_batch(V2_OVERLAY)
        .expect("reviewed additive V2 overlay installs over exact V1");
    assert_eq!(
        pragma_i64(&connection, "application_id"),
        COORDINATOR_STORE_APPLICATION_ID_V1,
        "V2 must keep the coordinator application identity"
    );
    assert_eq!(pragma_i64(&connection, "user_version"), V2_SCHEMA_VERSION);

    let v2_objects = schema_objects(&connection);
    for object in &v1_objects {
        assert!(
            v2_objects.contains(object),
            "V2 rewrote or removed an authoritative V1 object: {} {}",
            object.0,
            object.1
        );
    }
    assert!(v2_objects.len() > v1_objects.len());
}

#[test]
fn old_v1_binary_rejects_v2_without_repair_or_downgrade() {
    let root = MigrationRoot::new("old-binary");
    let identity = initialize_v1(&root);

    let connection = Connection::open(root.database()).expect("V1 database opens directly");
    connection
        .execute_batch(V2_OVERLAY)
        .expect("reviewed V2 overlay installs over exact V1");
    let v2_inventory = schema_objects(&connection);
    drop(connection);

    let error = reopen_v1(&root, identity).expect_err("V1 binary must refuse a V2 root");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::SchemaUnsupported);

    let connection = Connection::open(root.database()).expect("refused V2 database reopens raw");
    assert_eq!(
        pragma_i64(&connection, "user_version"),
        V2_SCHEMA_VERSION,
        "old-binary admission must not roll V2 back"
    );
    assert_eq!(
        schema_objects(&connection),
        v2_inventory,
        "old-binary admission must not repair, migrate, or rewrite V2"
    );
}

#[test]
fn raw_version_relabel_cannot_turn_published_v2_history_back_into_v1() {
    let root = MigrationRoot::new("raw-downgrade-relabel");
    let identity = initialize_v1(&root);
    install_exact_empty_v2(&root);

    let connection = Connection::open(root.database()).expect("published V2 database opens raw");
    let v2_inventory = schema_objects(&connection);
    let migration_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM coordinator_v2_migrations",
            [],
            |row| row.get(0),
        )
        .expect("published migration history reads");
    assert_eq!(migration_count, 1);
    connection
        .pragma_update(None, "user_version", COORDINATOR_STORE_SCHEMA_VERSION_V1)
        .expect("out-of-band downgrade tamper relabels only the version pragma");
    drop(connection);

    assert_eq!(
        reopen_v1(&root, identity).unwrap_err(),
        CoordinatorStoreOpenErrorV1::SchemaInvalid,
        "V2 objects and migration history must prevent a relabelled root becoming V1 authority"
    );
    let connection = Connection::open(root.database()).expect("tampered root reopens raw");
    assert_eq!(schema_objects(&connection), v2_inventory);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM coordinator_v2_migrations",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .expect("migration history remains readable"),
        migration_count,
        "failed old-binary admission must not delete migration evidence"
    );
}

#[test]
fn coordinator_v2_history_rejects_delete_replace_and_prune_shortcuts() {
    let root = MigrationRoot::new("migration-retention");
    initialize_v1(&root);
    install_exact_empty_v2(&root);
    let connection = Connection::open(root.database()).expect("published V2 database opens raw");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("replacement delete triggers enable");

    for statement in [
        "DELETE FROM coordinator_v2_migrations",
        "INSERT OR REPLACE INTO coordinator_v2_migrations SELECT * FROM coordinator_v2_migrations",
    ] {
        assert!(
            connection.execute_batch(statement).is_err(),
            "permanent migration history must reject `{statement}`"
        );
    }
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM coordinator_v2_migrations",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .expect("migration count reads after rejected mutations"),
        1
    );
}

#[test]
fn every_ordinary_open_path_is_free_of_automatic_v2_upgrade_authority() {
    for (path, source) in coordinator_rust_sources() {
        let source = source_without_comments(&source);
        for forbidden_auto_upgrade in [
            "auto_migrate",
            "auto_upgrade",
            "upgrade_on_open",
            "migrate_during_open",
        ] {
            assert!(
                !source.contains(forbidden_auto_upgrade),
                "{} contains forbidden automatic upgrade surface {forbidden_auto_upgrade}",
                path.display()
            );
        }

        if path.file_name().and_then(|value| value.to_str()) != Some("dispatch_schema.rs") {
            for explicit_migration_only in [
                "coordinator-dispatch-schema-v2.sql",
                "PRAGMA user_version = 2",
            ] {
                assert!(
                    !source.contains(explicit_migration_only),
                    "{} can reach V2 migration material outside dispatch_schema.rs: {explicit_migration_only}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn production_exposes_no_dispatch_prune_compact_reuse_or_downgrade_surface() {
    let forbidden_identifiers = [
        "pub fn prune_dispatch",
        "pub(crate) fn prune_dispatch",
        "pub fn compact_dispatch",
        "pub(crate) fn compact_dispatch",
        "pub fn delete_dispatch_history",
        "pub(crate) fn delete_dispatch_history",
        "pub fn reuse_dispatch_generation",
        "pub(crate) fn reuse_dispatch_generation",
        "pub fn downgrade_dispatch_v2",
        "pub(crate) fn downgrade_dispatch_v2",
        "pub fn revert_dispatch_to_v1",
        "pub(crate) fn revert_dispatch_to_v1",
    ];
    let forbidden_sql = [
        "DELETE FROM coordinator_v2_migrations",
        "DELETE FROM dispatch_comparisons",
        "DELETE FROM dispatch_grants",
        "DELETE FROM dispatch_records",
        "DELETE FROM dispatch_transitions",
        "DELETE FROM dispatch_outbox",
        "DELETE FROM dispatch_delivery_attempts",
        "DELETE FROM dispatch_receipts",
        "DELETE FROM dispatch_reconciliations",
        "DELETE FROM dispatch_events",
        "INSERT OR REPLACE INTO dispatch_",
    ];
    for (path, source) in coordinator_rust_sources() {
        let source = production_source_without_comments(&source);
        for forbidden in forbidden_identifiers.into_iter().chain(forbidden_sql) {
            assert!(
                !source.contains(forbidden),
                "{} contains forbidden dispatch history mutation `{forbidden}`",
                path.display()
            );
        }
    }
}

#[test]
fn production_t079_coordinator_retention_contract_is_explicit_and_closed() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dispatch_schema.rs");
    let source = source_without_comments(
        &fs::read_to_string(&path).expect("coordinator dispatch schema source reads"),
    );
    let required = [
        "CoordinatorDispatchRetentionPolicyV1",
        "coordinator_dispatch_retention_policy_v1",
        "verify_permanent_dispatch_history_v1",
        "requires_approved_encrypted_at_rest_profile",
        "automatic_pruning_enabled",
        "physical_secure_erasure_claimed",
    ];
    let missing = required
        .iter()
        .copied()
        .filter(|member| !source.contains(member))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "T074 RED: future T079 coordinator retention contract is absent or incomplete; missing={missing:?}"
    );
}

#[test]
fn dispatch_v2_seam_is_explicit_and_exposes_no_migration_authority() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dispatch_schema_path = crate_root.join("src/dispatch_schema.rs");
    let dispatch_schema = source_without_comments(
        &fs::read_to_string(&dispatch_schema_path).unwrap_or_else(|_| {
            panic!(
                "T019 RED: {} is required before the private strict V2 seam exists",
                dispatch_schema_path.display()
            )
        }),
    );
    let lib_source = source_without_comments(
        &fs::read_to_string(crate_root.join("src/lib.rs"))
            .expect("coordinator library source reads"),
    );

    for required in [
        "coordinator-dispatch-schema-v2.sql",
        "pub struct SqliteCoordinatorStoreV2",
        "pub fn open_existing",
        "DispatchCoordinatorStoreV1",
    ] {
        assert!(
            dispatch_schema.contains(required),
            "explicit V2 seam is missing {required}"
        );
    }
    for forbidden_public_surface in [
        "pub struct DispatchMigrationRequestV2",
        "pub struct DispatchMigrationReceiptV2",
        "pub fn stage_dispatch_migration_v2",
        "pub fn classify_dispatch_migration_readback_v2",
    ] {
        assert!(
            !lib_source.contains(forbidden_public_surface)
                && !dispatch_schema.contains(forbidden_public_surface),
            "V2 migration authority escaped through {forbidden_public_surface}"
        );
    }
    assert!(
        !lib_source.contains("coordinator-dispatch-schema-v2.sql"),
        "ordinary public open must not embed or execute the migration overlay"
    );

    let has_version_two_constant = dispatch_schema
        .lines()
        .any(|line| line.contains("const ") && line.contains("V2") && line.contains("2"));
    assert!(
        has_version_two_constant,
        "the private seam needs an explicit schema-V2 version constant"
    );

    let has_overlay_digest_candidate = dispatch_schema.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("fn ")
            && line.contains("v2")
            && (line.contains("digest") || line.contains("sha256"))
    });
    assert!(
        has_overlay_digest_candidate,
        "the private seam needs a callable V2 overlay-digest candidate"
    );

    let has_strict_v2_candidate = dispatch_schema.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("fn ")
            && line.contains("v2")
            && (line.contains("verify") || line.contains("classif") || line.contains("open"))
    });
    assert!(
        has_strict_v2_candidate,
        "the private seam needs a strict V2 verification/open candidate"
    );
}
