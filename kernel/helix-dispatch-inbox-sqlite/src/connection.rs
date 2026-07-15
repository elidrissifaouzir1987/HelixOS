//! Strict SQLite connection/profile boundary for the independent adapter inbox.

#![allow(dead_code)]

use crate::config::{AdapterInboxInitializationV1, AdapterInboxStoreConfigV1};
use crate::root_safety::{
    ensure_initializing_marker, initialization_database_present, publish_existing_marker,
    reserve_database_file, sync_root_directory, AdapterRootSafetyErrorV1,
};
use crate::schema::{self, AdapterInboxStoreSummaryV1};
use rusqlite::{Connection, Error as SqliteError, ErrorCode, OpenFlags};
use std::error::Error;
use std::fmt;
use std::fs;
use std::time::Duration;

/// Closed, payload-free adapter-store admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterInboxStoreOpenErrorV1 {
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    RootBusy,
    RootUnavailable,
    UnknownRootMember,
    ApplicationIdMismatch,
    SchemaUnsupported,
    SchemaInvalid,
    DurabilityProfileUnavailable,
    IntegrityFailed,
    InvariantFailed,
}

impl AdapterInboxStoreOpenErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::RootInvalid => "ROOT_INVALID",
            Self::RootNotDedicated => "ROOT_NOT_DEDICATED",
            Self::RootRoleMismatch => "ROOT_ROLE_MISMATCH",
            Self::RootIdentityMismatch => "ROOT_IDENTITY_MISMATCH",
            Self::RootBusy => "ROOT_BUSY",
            Self::RootUnavailable => "ROOT_UNAVAILABLE",
            Self::UnknownRootMember => "UNKNOWN_ROOT_MEMBER",
            Self::ApplicationIdMismatch => "APPLICATION_ID_MISMATCH",
            Self::SchemaUnsupported => "SCHEMA_UNSUPPORTED",
            Self::SchemaInvalid => "SCHEMA_INVALID",
            Self::DurabilityProfileUnavailable => "DURABILITY_PROFILE_UNAVAILABLE",
            Self::IntegrityFailed => "INTEGRITY_FAILED",
            Self::InvariantFailed => "INVARIANT_FAILED",
        }
    }

    const fn from_root(error: AdapterRootSafetyErrorV1) -> Self {
        match error {
            AdapterRootSafetyErrorV1::RootInvalid => Self::RootInvalid,
            AdapterRootSafetyErrorV1::RootNotDedicated => Self::RootNotDedicated,
            AdapterRootSafetyErrorV1::RootRoleMismatch => Self::RootRoleMismatch,
            AdapterRootSafetyErrorV1::RootIdentityMismatch => Self::RootIdentityMismatch,
            AdapterRootSafetyErrorV1::UnknownRootMember => Self::UnknownRootMember,
            AdapterRootSafetyErrorV1::RootUnavailable => Self::RootUnavailable,
        }
    }
}

impl fmt::Debug for AdapterInboxStoreOpenErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AdapterInboxStoreOpenErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterInboxStoreOpenErrorV1 {}

/// Fully verified connection retained behind provisioner-bound root custody.
pub(crate) struct OpenedAdapterInboxStoreV1 {
    config: AdapterInboxStoreConfigV1,
    connection: Connection,
    summary: AdapterInboxStoreSummaryV1,
}

/// Identity-bound connection for corruption classification before schema admission.
///
/// Unlike `OpenedAdapterInboxStoreV1`, this type does not claim that the observed schema is
/// valid. It retains the provisioner-attested root binding and revalidates the directory, marker,
/// and database-file identities around the diagnostic cut.
pub(crate) struct BoundAdapterCorruptionAuditConnectionV1 {
    config: AdapterInboxStoreConfigV1,
    connection: Connection,
}

impl BoundAdapterCorruptionAuditConnectionV1 {
    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) fn revalidate(&self) -> Result<(), AdapterInboxStoreOpenErrorV1> {
        self.config
            .existing_root()
            .ok_or(AdapterInboxStoreOpenErrorV1::RootRoleMismatch)?
            .revalidate()
            .map_err(AdapterInboxStoreOpenErrorV1::from_root)
    }

    pub(crate) fn expected_root_identity(
        &self,
    ) -> Result<crate::root_safety::AdapterRootIdentityV1, AdapterInboxStoreOpenErrorV1> {
        self.config
            .existing_root()
            .map(|root| root.expected_identity())
            .ok_or(AdapterInboxStoreOpenErrorV1::RootRoleMismatch)
    }
}

impl fmt::Debug for BoundAdapterCorruptionAuditConnectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundAdapterCorruptionAuditConnectionV1")
            .finish_non_exhaustive()
    }
}

impl OpenedAdapterInboxStoreV1 {
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) fn config(&self) -> &AdapterInboxStoreConfigV1 {
        &self.config
    }

    pub(crate) const fn summary(&self) -> AdapterInboxStoreSummaryV1 {
        self.summary
    }
}

impl fmt::Debug for OpenedAdapterInboxStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedAdapterInboxStoreV1")
            .finish_non_exhaustive()
    }
}

/// Explicitly initializes only a provisioner-attested empty/recovering root.
pub(crate) fn initialize_empty(
    config: AdapterInboxStoreConfigV1,
    initial: AdapterInboxInitializationV1,
) -> Result<OpenedAdapterInboxStoreV1, AdapterInboxStoreOpenErrorV1> {
    let empty_root = config
        .empty_root()
        .ok_or(AdapterInboxStoreOpenErrorV1::RootRoleMismatch)?;
    ensure_initializing_marker(empty_root).map_err(AdapterInboxStoreOpenErrorV1::from_root)?;

    let database_present = initialization_database_present(empty_root)
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    let mut connection = if database_present {
        preflight_database_file(&config)?;
        let connection = open_read_write_database(&config)?;
        configure_existing_connection(&connection, config.maximum_busy_wait_ms())?;
        connection
    } else {
        let reservation =
            reserve_database_file(empty_root).map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
        reservation
            .sync_all()
            .map_err(|_| AdapterInboxStoreOpenErrorV1::RootUnavailable)?;
        drop(reservation);
        sync_root_directory(config.root_path()).map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
        let connection = open_read_write_database(&config)?;
        configure_initialization_connection(&connection, config.maximum_busy_wait_ms())?;
        connection
    };

    let root_identity = empty_root.provisioned_identity();
    let summary = if database_present {
        schema::verify_full(&connection, root_identity)?
    } else {
        verify_exact_empty_candidate(&connection)?;
        schema::initialize_empty_schema(&mut connection, root_identity, initial)?
    };
    verify_profile(&connection, config.maximum_busy_wait_ms())?;
    empty_root
        .revalidate()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    publish_existing_marker(empty_root).map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    let config = config
        .into_existing()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    config
        .existing_root()
        .ok_or(AdapterInboxStoreOpenErrorV1::RootRoleMismatch)?
        .revalidate()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    Ok(OpenedAdapterInboxStoreV1 {
        config,
        connection,
        summary,
    })
}

/// Opens only an already-published store. This path has no create, migration or repair
/// authority and refuses every non-exact or unknown schema before returning a connection.
pub(crate) fn open_existing(
    config: AdapterInboxStoreConfigV1,
) -> Result<OpenedAdapterInboxStoreV1, AdapterInboxStoreOpenErrorV1> {
    open_existing_strict_and_verify(config)
}

/// Opens an attested existing adapter root without admitting its schema.
///
/// This is restricted to the corruption classifier: an observed root whose generation index or
/// append-only guard was removed must still be readable long enough to receive a local permanent
/// fence. No ordinary store handle is constructed from this path.
pub(crate) fn open_existing_for_corruption_audit_v1(
    config: AdapterInboxStoreConfigV1,
) -> Result<BoundAdapterCorruptionAuditConnectionV1, AdapterInboxStoreOpenErrorV1> {
    let existing_root = config
        .existing_root()
        .ok_or(AdapterInboxStoreOpenErrorV1::RootRoleMismatch)?;
    existing_root
        .revalidate()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    preflight_database_file(&config)?;
    let connection = Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| map_sqlite_error(&error, AdapterInboxStoreOpenErrorV1::RootUnavailable))?;
    configure_existing_connection(&connection, config.maximum_busy_wait_ms())?;
    existing_root
        .revalidate()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    Ok(BoundAdapterCorruptionAuditConnectionV1 { config, connection })
}

fn open_existing_strict_and_verify(
    config: AdapterInboxStoreConfigV1,
) -> Result<OpenedAdapterInboxStoreV1, AdapterInboxStoreOpenErrorV1> {
    let existing_root = config
        .existing_root()
        .ok_or(AdapterInboxStoreOpenErrorV1::RootRoleMismatch)?;
    existing_root
        .revalidate()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    preflight_database_file(&config)?;
    let connection = Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| map_sqlite_error(&error, AdapterInboxStoreOpenErrorV1::RootUnavailable))?;
    configure_existing_connection(&connection, config.maximum_busy_wait_ms())?;
    existing_root
        .revalidate()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    let summary = schema::verify_full(&connection, existing_root.expected_identity())?;
    verify_profile(&connection, config.maximum_busy_wait_ms())?;
    existing_root
        .revalidate()
        .map_err(AdapterInboxStoreOpenErrorV1::from_root)?;
    Ok(OpenedAdapterInboxStoreV1 {
        config,
        connection,
        summary,
    })
}

fn open_read_write_database(
    config: &AdapterInboxStoreConfigV1,
) -> Result<Connection, AdapterInboxStoreOpenErrorV1> {
    Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| map_sqlite_error(&error, AdapterInboxStoreOpenErrorV1::RootUnavailable))
}

fn configure_initialization_connection(
    connection: &Connection,
    busy_timeout_ms: u64,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    configure_busy_timeout(connection, busy_timeout_ms)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable);
    }
    configure_connection_local_profile(connection)?;
    verify_profile(connection, busy_timeout_ms)
}

fn configure_existing_connection(
    connection: &Connection,
    busy_timeout_ms: u64,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    configure_busy_timeout(connection, busy_timeout_ms)?;
    configure_connection_local_profile(connection)?;
    verify_profile(connection, busy_timeout_ms)
}

fn configure_connection_local_profile(
    connection: &Connection,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    connection
        .execute_batch(
            "PRAGMA synchronous = FULL; \
             PRAGMA foreign_keys = ON; \
             PRAGMA trusted_schema = OFF; \
             PRAGMA cell_size_check = ON; \
             PRAGMA recursive_triggers = ON; \
             PRAGMA wal_autocheckpoint = 0;",
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable)
}

fn configure_busy_timeout(
    connection: &Connection,
    busy_timeout_ms: u64,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    connection
        .busy_timeout(Duration::from_millis(busy_timeout_ms))
        .map_err(|_| AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable)
}

fn verify_profile(
    connection: &Connection,
    busy_timeout_ms: u64,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    let expected_busy_timeout = i64::try_from(busy_timeout_ms)
        .map_err(|_| AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable)?;
    let profile: (String, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT \
                 (SELECT journal_mode FROM temp.pragma_journal_mode()), \
                 (SELECT synchronous FROM temp.pragma_synchronous()), \
                 (SELECT foreign_keys FROM temp.pragma_foreign_keys()), \
                 (SELECT trusted_schema FROM temp.pragma_trusted_schema()), \
                 (SELECT cell_size_check FROM temp.pragma_cell_size_check()), \
                 (SELECT recursive_triggers FROM temp.pragma_recursive_triggers()), \
                 (SELECT timeout FROM temp.pragma_busy_timeout())",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable)?;
    if !profile.0.eq_ignore_ascii_case("wal")
        || profile.1 != 2
        || profile.2 != 1
        || profile.3 != 0
        || profile.4 != 1
        || profile.5 != 1
        || profile_pragma_i64(connection, "wal_autocheckpoint")? != 0
        || profile.6 != expected_busy_timeout
    {
        return Err(AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable);
    }
    Ok(())
}

fn profile_pragma_i64(
    connection: &Connection,
    pragma: &str,
) -> Result<i64, AdapterInboxStoreOpenErrorV1> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|_| AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable)
}

fn verify_exact_empty_candidate(
    connection: &Connection,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    let application_id = profile_pragma_i64(connection, "application_id")?;
    let user_version = profile_pragma_i64(connection, "user_version")?;
    let object_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)?;
    if application_id != 0 || user_version != 0 || object_count != 0 {
        return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
    }
    Ok(())
}

fn preflight_database_file(
    config: &AdapterInboxStoreConfigV1,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    let metadata = fs::symlink_metadata(config.database_path())
        .map_err(|_| AdapterInboxStoreOpenErrorV1::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdapterInboxStoreOpenErrorV1::RootNotDedicated);
    }
    Ok(())
}

fn map_sqlite_error(
    error: &SqliteError,
    fallback: AdapterInboxStoreOpenErrorV1,
) -> AdapterInboxStoreOpenErrorV1 {
    match error {
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
            ) =>
        {
            AdapterInboxStoreOpenErrorV1::IntegrityFailed
        }
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy
                    | ErrorCode::DatabaseLocked
                    | ErrorCode::SchemaChanged
                    | ErrorCode::FileLockingProtocolFailed
            ) =>
        {
            AdapterInboxStoreOpenErrorV1::RootBusy
        }
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AdapterInboxRootIdentityEvidenceV1;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TemporaryRoot(PathBuf);

    impl TemporaryRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock follows epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "helix-dispatch-inbox-connection-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("temporary root creates");
            Self(path)
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn explicit_initialize_then_strict_reopen_is_exact() {
        let root = TemporaryRoot::new();
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x31; 32]);
        let config =
            AdapterInboxStoreConfigV1::try_new_empty_attested(root.0.clone(), identity, 25)
                .expect("empty config validates");
        let opened = initialize_empty(
            config,
            AdapterInboxInitializationV1::try_new(9, 1, [0x42; 32])
                .expect("initial observation validates"),
        )
        .expect("store initializes");
        assert_eq!(opened.summary().store_generation, 0);
        drop(opened);

        let config =
            AdapterInboxStoreConfigV1::try_new_existing_attested(root.0.clone(), identity, 25)
                .expect("existing config validates");
        let reopened = open_existing(config).expect("exact store reopens");
        assert_eq!(reopened.summary().root_identity, identity);
    }

    #[test]
    fn existing_configuration_refuses_wrong_provisioned_identity() {
        let root = TemporaryRoot::new();
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x51; 32]);
        let config =
            AdapterInboxStoreConfigV1::try_new_empty_attested(root.0.clone(), identity, 10)
                .expect("empty config validates");
        drop(
            initialize_empty(
                config,
                AdapterInboxInitializationV1::try_new(1, 1, [0x62; 32])
                    .expect("initial metadata validates"),
            )
            .expect("store initializes"),
        );
        assert!(AdapterInboxStoreConfigV1::try_new_existing_attested(
            root.0.clone(),
            AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x52; 32]),
            10,
        )
        .is_err());
    }

    #[test]
    fn persistent_pragma_virtual_table_shadow_cannot_authorize_a_non_wal_store() {
        let root = TemporaryRoot::new();
        let database = root.0.join("profile-shadow.sqlite3");
        let connection = Connection::open(&database).expect("connection opens");
        connection
            .execute_batch(
                "CREATE VIRTUAL TABLE pragma_journal_mode USING fts5(journal_mode); \
                 INSERT INTO pragma_journal_mode(journal_mode) VALUES ('wal');",
            )
            .expect("persistent virtual-table shadow installs");

        let real_journal: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("real journal mode reads");
        assert_eq!(real_journal.to_ascii_lowercase(), "delete");
        let shadowed_journal: String = connection
            .query_row(
                "SELECT journal_mode FROM pragma_journal_mode()",
                [],
                |row| row.get(0),
            )
            .expect("unqualified table-valued PRAGMA is demonstrably shadowed");
        assert_eq!(shadowed_journal, "wal");

        assert_eq!(
            configure_existing_connection(&connection, 10),
            Err(AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable)
        );
        let journal_after_refusal: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("refusal leaves the persistent journal mode readable");
        assert_eq!(journal_after_refusal.to_ascii_lowercase(), "delete");
    }
}
