#[path = "../src/clock.rs"]
mod clock;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/manifest.rs"]
mod manifest;

use clock::{read_safe_now, remaining_monotonic_ms, CoordinatorMonotonicClockV1};
use error::{CoordinatorClockUnavailableV1, InternalCoordinatorError};
use helix_contracts::{ContractError, Ed25519KeyResolver, MAX_SAFE_U64};
use helix_coordinator_sqlite::{
    CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1, CoordinatorStoreOpenErrorV1,
    SqliteCoordinatorStoreV1,
};
use rusqlite::Connection;
use serde_json::Value;
use std::error::Error as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const STORE_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);
const BACKUP_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-backup-manifest-v1.schema.json"
);
const ATTESTATION_SCHEMA: &str = include_str!("../../../specs/004-durable-preparation/contracts/preparation-backup-provenance-attestation-v1.schema.json");
const RECOVERY_ROOT_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/recovery-root-metadata-v1.schema.json"
);
const RECOVERY_SNAPSHOT_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/recovery-snapshot-manifest-v1.schema.json"
);
const CLOCK_SOURCE: &str = include_str!("../src/clock.rs");
const PACKAGE_MANIFEST: &str = include_str!("../Cargo.toml");

#[derive(Clone, Copy)]
struct FixedClock {
    now: Option<u64>,
}

impl FixedClock {
    const fn available(now: u64) -> Self {
        Self { now: Some(now) }
    }

    const fn unavailable() -> Self {
        Self { now: None }
    }
}

impl CoordinatorMonotonicClockV1 for FixedClock {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        self.now.ok_or_else(CoordinatorClockUnavailableV1::new)
    }
}

impl helix_coordinator_sqlite::CoordinatorMonotonicClockV1 for FixedClock {
    fn now_monotonic_ms(
        &self,
    ) -> Result<u64, helix_coordinator_sqlite::CoordinatorClockUnavailableV1> {
        self.now
            .ok_or_else(helix_coordinator_sqlite::CoordinatorClockUnavailableV1::new)
    }
}

struct HistoricalPlanKeys;

impl Ed25519KeyResolver for HistoricalPlanKeys {
    fn resolve_ed25519(&self, _: &str) -> helix_contracts::Result<[u8; 32]> {
        Err(ContractError::UnknownKey)
    }
}

struct ContractRoot {
    path: PathBuf,
}

impl ContractRoot {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-coordinator-contract-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("contract root creates");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn database_path(&self) -> PathBuf {
        self.path.join("coordinator.sqlite3")
    }
}

impl Drop for ContractRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn injected_clock_is_safe_exclusive_and_has_no_ambient_fallback() {
    assert_eq!(read_safe_now(&FixedClock::available(41)).unwrap(), 41);
    assert_eq!(
        remaining_monotonic_ms(&FixedClock::available(41), 42).unwrap(),
        1
    );
    assert_eq!(
        remaining_monotonic_ms(&FixedClock::available(42), 42),
        Err(InternalCoordinatorError::DeadlineReached)
    );
    assert_eq!(
        read_safe_now(&FixedClock::available(MAX_SAFE_U64 + 1)),
        Err(InternalCoordinatorError::ClockUnavailable)
    );
    assert_eq!(
        read_safe_now(&FixedClock::unavailable()),
        Err(InternalCoordinatorError::ClockUnavailable)
    );
    assert!(!CLOCK_SOURCE.contains("SystemTime"));
    assert!(!CLOCK_SOURCE.contains("Instant::now"));
}

#[test]
fn internal_errors_are_closed_payload_free_and_redacted() {
    let cases = [
        (
            InternalCoordinatorError::ClockUnavailable,
            "CLOCK_UNAVAILABLE",
        ),
        (
            InternalCoordinatorError::DeadlineReached,
            "DEADLINE_REACHED",
        ),
        (InternalCoordinatorError::RootInvalid, "ROOT_INVALID"),
        (
            InternalCoordinatorError::RootNotDedicated,
            "ROOT_NOT_DEDICATED",
        ),
        (
            InternalCoordinatorError::RootRoleMismatch,
            "ROOT_ROLE_MISMATCH",
        ),
        (
            InternalCoordinatorError::RootIdentityMismatch,
            "ROOT_IDENTITY_MISMATCH",
        ),
        (InternalCoordinatorError::RootBusy, "ROOT_BUSY"),
        (
            InternalCoordinatorError::RootUnavailable,
            "ROOT_UNAVAILABLE",
        ),
        (
            InternalCoordinatorError::UnknownRootMember,
            "UNKNOWN_ROOT_MEMBER",
        ),
        (
            InternalCoordinatorError::ApplicationIdMismatch,
            "APPLICATION_ID_MISMATCH",
        ),
        (
            InternalCoordinatorError::SchemaUnsupported,
            "SCHEMA_UNSUPPORTED",
        ),
        (InternalCoordinatorError::SchemaInvalid, "SCHEMA_INVALID"),
        (
            InternalCoordinatorError::DurabilityProfileUnavailable,
            "DURABILITY_PROFILE_UNAVAILABLE",
        ),
        (
            InternalCoordinatorError::IntegrityFailed,
            "INTEGRITY_FAILED",
        ),
        (
            InternalCoordinatorError::InvariantFailed,
            "INVARIANT_FAILED",
        ),
        (
            InternalCoordinatorError::JsonContractInvalid,
            "JSON_CONTRACT_INVALID",
        ),
        (
            InternalCoordinatorError::ProvenanceInvalid,
            "PROVENANCE_INVALID",
        ),
        (InternalCoordinatorError::RestorePending, "RESTORE_PENDING"),
    ];

    for (error, code) in cases {
        assert_eq!(error.code(), code);
        assert_eq!(format!("{error:?}"), code);
        assert_eq!(error.to_string(), code);
        assert!(error.source().is_none());
    }
    assert_eq!(std::mem::size_of::<InternalCoordinatorError>(), 1);
}

#[test]
fn reviewed_sql_identity_profile_and_root_lifecycle_are_exact() {
    for required in [
        "PRAGMA application_id = 1212962883;",
        "PRAGMA user_version = 1;",
        "PRAGMA recursive_triggers = ON;",
        "root_lifecycle_state = 'ACTIVE'",
        "root_lifecycle_state = 'RESTORE_PENDING'",
        "coordinator_store_meta_root_transition_guard",
        "coordinator_store_meta_no_delete",
    ] {
        assert!(
            STORE_SCHEMA.contains(required),
            "missing SQL contract {required}"
        );
    }
}

#[test]
fn all_four_json_contracts_are_closed_v1_objects() {
    for source in [
        BACKUP_SCHEMA,
        ATTESTATION_SCHEMA,
        RECOVERY_ROOT_SCHEMA,
        RECOVERY_SNAPSHOT_SCHEMA,
    ] {
        let schema: Value = serde_json::from_str(source).expect("reviewed schema parses");
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert!(schema["required"]
            .as_array()
            .is_some_and(|items| !items.is_empty()));
    }
}

#[test]
fn preparation_storage_has_no_dispatch_grant_legacy_or_mcp_reachability() {
    for forbidden_dependency in ["helixos-kernel", "helixos-mcp-shim", "helixos-provision"] {
        assert!(
            !PACKAGE_MANIFEST.contains(forbidden_dependency),
            "coordinator gained forbidden dependency {forbidden_dependency}"
        );
    }

    let production = coordinator_source_tree();
    for forbidden_authority in [
        "ExecutionGrant",
        "EffectAdapter",
        "AdapterReceipt",
        "DispatchOutbox",
        "DISPATCHING",
    ] {
        assert!(
            !production.contains(forbidden_authority),
            "preparation storage exposes forbidden authority {forbidden_authority}"
        );
    }
}

fn coordinator_source_tree() -> String {
    fn visit(directory: &Path, sources: &mut Vec<String>) {
        let mut entries = fs::read_dir(directory)
            .expect("coordinator source directory is readable")
            .map(|entry| entry.expect("coordinator source entry is readable").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(&path, sources);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                sources.push(fs::read_to_string(path).expect("coordinator Rust source is UTF-8"));
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    visit(&root, &mut sources);
    sources.join("\n")
}

#[test]
fn sqlite_open_rejects_wrong_application_schema_and_profile_without_repair() {
    fn initialize(label: &str) -> (ContractRoot, CoordinatorRootIdentityEvidenceV1) {
        let root = ContractRoot::new(label);
        let config =
            CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 25)
                .expect("empty trusted config validates");
        let store = SqliteCoordinatorStoreV1::open_or_create(
            config,
            FixedClock::available(100),
            HistoricalPlanKeys,
            1_000,
        )
        .expect("empty coordinator initializes");
        assert_eq!(store.operation_count(), 0);
        let identity = store.root_identity_evidence();
        drop(store);
        (root, identity)
    }

    fn reopen(
        root: &ContractRoot,
        identity: CoordinatorRootIdentityEvidenceV1,
    ) -> Result<SqliteCoordinatorStoreV1<FixedClock, HistoricalPlanKeys>, CoordinatorStoreOpenErrorV1>
    {
        let config = CoordinatorStoreConfigV1::try_new_existing_attested(
            root.path().to_path_buf(),
            identity,
            25,
        )
        .expect("existing trusted config validates");
        SqliteCoordinatorStoreV1::open_or_create(
            config,
            FixedClock::available(100),
            HistoricalPlanKeys,
            1_000,
        )
    }

    let (application_root, application_identity) = initialize("application-id");
    let connection = Connection::open(application_root.database_path()).expect("store opens");
    connection
        .pragma_update(None, "application_id", 7_i64)
        .expect("application id corrupts");
    drop(connection);
    let error = reopen(&application_root, application_identity)
        .expect_err("wrong application identity denies");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::ApplicationIdMismatch);
    let connection = Connection::open(application_root.database_path()).expect("store reopens raw");
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .expect("application id reads");
    assert_eq!(application_id, 7, "admission must not repair identity");

    let (schema_root, schema_identity) = initialize("schema-version");
    let connection = Connection::open(schema_root.database_path()).expect("store opens");
    connection
        .pragma_update(None, "user_version", 2_i64)
        .expect("schema version corrupts");
    drop(connection);
    let error = reopen(&schema_root, schema_identity).expect_err("newer schema denies");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::SchemaUnsupported);
    let connection = Connection::open(schema_root.database_path()).expect("store reopens raw");
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("schema version reads");
    assert_eq!(user_version, 2, "admission must not roll schema back");

    let (shape_root, shape_identity) = initialize("schema-shape");
    let connection = Connection::open(shape_root.database_path()).expect("store opens");
    connection
        .execute_batch("DROP INDEX budget_scopes_binding_uq")
        .expect("reviewed schema shape corrupts");
    drop(connection);
    let error = reopen(&shape_root, shape_identity).expect_err("altered schema denies");
    assert_eq!(error, CoordinatorStoreOpenErrorV1::SchemaInvalid);
    let connection = Connection::open(shape_root.database_path()).expect("store reopens raw");
    let index_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'budget_scopes_binding_uq'",
            [],
            |row| row.get(0),
        )
        .expect("schema shape reads");
    assert_eq!(index_count, 0, "admission must not recreate schema objects");

    let (profile_root, profile_identity) = initialize("durability-profile");
    let connection = Connection::open(profile_root.database_path()).expect("store opens");
    let mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .expect("journal profile corrupts");
    assert_eq!(mode.to_ascii_lowercase(), "delete");
    drop(connection);
    let error = reopen(&profile_root, profile_identity).expect_err("weaker profile denies");
    assert_eq!(
        error,
        CoordinatorStoreOpenErrorV1::DurabilityProfileUnavailable
    );
    let connection = Connection::open(profile_root.database_path()).expect("store reopens raw");
    let mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("journal mode reads");
    assert_eq!(
        mode.to_ascii_lowercase(),
        "delete",
        "admission must not repair a weaker persistent profile"
    );
}

#[test]
fn json_decoders_reject_unknown_duplicate_and_noncanonical_input() {
    const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let canonical = format!(
        "{{\"at_rest_profile_id\":\"synthetic-conformance\",\"root_identity_sha256\":\"{ZERO_SHA256}\",\"root_lifecycle_state\":\"ACTIVE\",\"schema\":\"helixos.recovery-root-metadata/1\",\"state_generation\":0}}"
    );
    manifest::decode_recovery_root_metadata_v1(canonical.as_bytes())
        .expect("exact canonical closed recovery-root metadata decodes");

    let noncanonical = format!(" {canonical}");
    assert!(manifest::decode_recovery_root_metadata_v1(noncanonical.as_bytes()).is_err());

    let duplicate = canonical.replacen(
        "\"schema\":\"helixos.recovery-root-metadata/1\"",
        "\"schema\":\"helixos.recovery-root-metadata/1\",\"schema\":\"helixos.recovery-root-metadata/1\"",
        1,
    );
    assert!(manifest::decode_recovery_root_metadata_v1(duplicate.as_bytes()).is_err());

    let unknown = canonical.replacen(
        "\"state_generation\":0",
        "\"state_generation\":0,\"unknown\":0",
        1,
    );
    assert!(manifest::decode_recovery_root_metadata_v1(unknown.as_bytes()).is_err());

    for malformed in [b"{}".as_slice(), b"{ }".as_slice()] {
        assert!(manifest::decode_preparation_backup_manifest_v1(malformed).is_err());
        assert!(manifest::decode_backup_provenance_attestation_v1(malformed).is_err());
        assert!(manifest::decode_recovery_snapshot_manifest_v1(malformed).is_err());
    }

    let digests = [
        manifest::embedded_preparation_backup_manifest_schema_v1_sha256(),
        manifest::embedded_backup_provenance_attestation_schema_v1_sha256(),
        manifest::embedded_recovery_root_metadata_schema_v1_sha256(),
        manifest::embedded_recovery_snapshot_manifest_schema_v1_sha256(),
    ];
    assert!(digests.iter().all(|digest| *digest != [0_u8; 32]));
    for left in 0..digests.len() {
        for right in (left + 1)..digests.len() {
            assert_ne!(digests[left], digests[right]);
        }
    }
}
