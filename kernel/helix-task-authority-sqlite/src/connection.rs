//! Exclusive HLXA initialization and strict ordinary-open boundary.
//!
//! Initialization is explicit: it accepts only a provisioner-attested empty root,
//! stages the exact schema and caller-supplied bootstrap graph in one exclusive
//! transaction, verifies the committed result, and publishes the root marker last.
//! Ordinary open never creates, migrates, repairs, or backfills a store.

#![allow(dead_code)] // Foundation consumed by the story-specific atomic writers and readback.

use crate::config::AuthorityStoreConfigV1;
use crate::root_safety::{
    ensure_initializing_marker, initialization_database_present, publish_existing_marker,
    reserve_database_file, AuthorityRootIdentityV1, AuthorityRootSafetyErrorV1,
};
use crate::schema::{
    self, TaskAuthoritySchemaAdmissionErrorV1, TASK_AUTHORITY_STORE_APPLICATION_ID_V1,
    TASK_AUTHORITY_STORE_SCHEMA_V1_SQL, TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1,
};
use helix_task_authority::{AuthorityClockProviderV1, AuthorityControlErrorV1};
use helix_task_authority_contracts::SafeU64;
use rusqlite::{
    Connection, Error as SqliteError, ErrorCode, OpenFlags, Transaction, TransactionBehavior,
};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::time::Duration;

/// Closed, payload-free failure from initialization or strict ordinary open.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityStoreOpenErrorV1 {
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    RootUnavailable,
    UnknownRootMember,
    ClockUnavailable,
    DeadlineReached,
    StoreBusy,
    ApplicationIdMismatch,
    SchemaUnsupported,
    SchemaInvalid,
    LifecycleUnavailable,
    DurabilityProfileUnavailable,
    IntegrityFailed,
    InvariantFailed,
    InitializationRejected,
}

impl AuthorityStoreOpenErrorV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::RootInvalid => "AUTHORITY_ROOT_INVALID",
            Self::RootNotDedicated => "AUTHORITY_ROOT_NOT_DEDICATED",
            Self::RootRoleMismatch => "AUTHORITY_ROOT_ROLE_MISMATCH",
            Self::RootIdentityMismatch => "AUTHORITY_ROOT_IDENTITY_MISMATCH",
            Self::RootUnavailable => "AUTHORITY_ROOT_UNAVAILABLE",
            Self::UnknownRootMember => "AUTHORITY_UNKNOWN_ROOT_MEMBER",
            Self::ClockUnavailable => "AUTHORITY_CLOCK_UNAVAILABLE",
            Self::DeadlineReached => "AUTHORITY_DEADLINE_REACHED",
            Self::StoreBusy => "AUTHORITY_STORE_BUSY",
            Self::ApplicationIdMismatch => "AUTHORITY_APPLICATION_ID_MISMATCH",
            Self::SchemaUnsupported => "AUTHORITY_SCHEMA_UNSUPPORTED",
            Self::SchemaInvalid => "AUTHORITY_SCHEMA_INVALID",
            Self::LifecycleUnavailable => "AUTHORITY_LIFECYCLE_UNAVAILABLE",
            Self::DurabilityProfileUnavailable => "AUTHORITY_DURABILITY_PROFILE_UNAVAILABLE",
            Self::IntegrityFailed => "AUTHORITY_INTEGRITY_FAILED",
            Self::InvariantFailed => "AUTHORITY_INVARIANT_FAILED",
            Self::InitializationRejected => "AUTHORITY_INITIALIZATION_REJECTED",
        }
    }
}

impl fmt::Debug for AuthorityStoreOpenErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityStoreOpenErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl Error for AuthorityStoreOpenErrorV1 {}

/// One verified connection retained together with its provisioner-bound root.
pub(crate) struct OpenedAuthorityStoreV1 {
    config: AuthorityStoreConfigV1,
    connection: Connection,
    _database_binding: BoundDatabaseFileV1,
    root_id: Box<str>,
}

impl OpenedAuthorityStoreV1 {
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) fn config(&self) -> &AuthorityStoreConfigV1 {
        &self.config
    }

    pub(crate) fn root_id_v1(&self) -> &str {
        &self.root_id
    }
}

impl fmt::Debug for OpenedAuthorityStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedAuthorityStoreV1")
            .finish_non_exhaustive()
    }
}

/// Initializes and publishes one exact root, or resumes the same committed staging root.
///
/// `stage_bootstrap` runs only for a byte-empty SQLite database and must insert the
/// complete metadata/bootstrap/event graph required by strict admission. If the
/// transaction had already committed before a crash, it is not invoked again.
pub(crate) fn initialize_empty_with_v1<P, F>(
    config: AuthorityStoreConfigV1,
    clock: &P,
    absolute_deadline_monotonic_ms: SafeU64,
    expected_root_id: &str,
    stage_bootstrap: F,
) -> Result<OpenedAuthorityStoreV1, AuthorityStoreOpenErrorV1>
where
    P: AuthorityClockProviderV1 + ?Sized,
    F: FnOnce(&Transaction<'_>, &str) -> Result<(), AuthorityStoreOpenErrorV1>,
{
    validate_expected_root_id_v1(expected_root_id)?;
    let empty_root = config
        .empty_root()
        .ok_or(AuthorityStoreOpenErrorV1::RootRoleMismatch)?;
    validate_expected_root_identity_v1(expected_root_id, empty_root.provisioned_identity())?;
    let initial_busy_ms = remaining_busy_ms_v1(
        clock,
        absolute_deadline_monotonic_ms,
        config.maximum_busy_wait_ms(),
    )?;

    empty_root.revalidate().map_err(map_root_error_v1)?;
    ensure_initializing_marker(empty_root).map_err(map_root_error_v1)?;
    let database_binding =
        if initialization_database_present(empty_root).map_err(map_root_error_v1)? {
            bind_database_file_v1(&config.database_path())?
        } else {
            let database = reserve_database_file(empty_root).map_err(map_root_error_v1)?;
            database
                .sync_all()
                .map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
            sync_root_directory_v1(config.root_path())?;
            bind_reserved_database_file_v1(&config.database_path(), database)?
        };
    empty_root.revalidate().map_err(map_root_error_v1)?;

    let mut connection = open_reserved_database_v1(&config, initial_busy_ms)?;
    verify_database_file_binding_v1(&config.database_path(), &database_binding)?;
    let database_state = classify_initialization_database_v1(&connection)?;

    if database_state == InitializationDatabaseStateV1::Empty {
        configure_initializing_connection_v1(&connection, initial_busy_ms)?;
        let busy_ms = remaining_busy_ms_v1(
            clock,
            absolute_deadline_monotonic_ms,
            config.maximum_busy_wait_ms(),
        )?;
        arm_busy_timeout_v1(&connection, busy_ms)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(map_sqlite_busy_v1)?;
        transaction
            .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
            .map_err(|_| AuthorityStoreOpenErrorV1::SchemaInvalid)?;
        stage_bootstrap(&transaction, expected_root_id)?;
        transaction.commit().map_err(map_sqlite_busy_v1)?;
        verify_database_file_binding_v1(&config.database_path(), &database_binding)?;
    } else {
        configure_ordinary_connection_v1(&connection, initial_busy_ms)?;
    }

    let checkpoint_busy_ms = remaining_busy_ms_v1(
        clock,
        absolute_deadline_monotonic_ms,
        config.maximum_busy_wait_ms(),
    )?;
    arm_busy_timeout_v1(&connection, checkpoint_busy_ms)?;
    checkpoint_initialization_v1(&connection)?;
    schema::verify_admission_v1(&connection, expected_root_id).map_err(map_schema_error_v1)?;
    database_binding
        .file
        .sync_all()
        .map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
    sync_root_directory_v1(config.root_path())?;
    verify_database_file_binding_v1(&config.database_path(), &database_binding)?;
    empty_root.revalidate().map_err(map_root_error_v1)?;
    remaining_busy_ms_v1(
        clock,
        absolute_deadline_monotonic_ms,
        config.maximum_busy_wait_ms(),
    )?;
    publish_existing_marker(empty_root).map_err(map_root_error_v1)?;

    let config = config.into_existing().map_err(map_root_error_v1)?;
    config
        .existing_root()
        .ok_or(AuthorityStoreOpenErrorV1::RootRoleMismatch)?
        .revalidate()
        .map_err(map_root_error_v1)?;

    Ok(OpenedAuthorityStoreV1 {
        config,
        connection,
        _database_binding: database_binding,
        root_id: expected_root_id.into(),
    })
}

/// Strictly opens one already-published root without any create, schema, repair, or migration.
pub(crate) fn open_existing_v1<P: AuthorityClockProviderV1 + ?Sized>(
    config: AuthorityStoreConfigV1,
    clock: &P,
    absolute_deadline_monotonic_ms: SafeU64,
    expected_root_id: &str,
) -> Result<OpenedAuthorityStoreV1, AuthorityStoreOpenErrorV1> {
    validate_expected_root_id_v1(expected_root_id)?;
    let existing_root = config
        .existing_root()
        .ok_or(AuthorityStoreOpenErrorV1::RootRoleMismatch)?;
    validate_expected_root_identity_v1(expected_root_id, existing_root.expected_identity())?;
    let busy_ms = remaining_busy_ms_v1(
        clock,
        absolute_deadline_monotonic_ms,
        config.maximum_busy_wait_ms(),
    )?;
    existing_root.revalidate().map_err(map_root_error_v1)?;
    let database_binding = bind_database_file_v1(&config.database_path())?;

    let connection = Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(map_sqlite_busy_v1)?;
    configure_ordinary_connection_v1(&connection, busy_ms)?;
    schema::verify_admission_v1(&connection, expected_root_id).map_err(map_schema_error_v1)?;
    verify_database_file_binding_v1(&config.database_path(), &database_binding)?;
    existing_root.revalidate().map_err(map_root_error_v1)?;
    remaining_busy_ms_v1(
        clock,
        absolute_deadline_monotonic_ms,
        config.maximum_busy_wait_ms(),
    )?;

    Ok(OpenedAuthorityStoreV1 {
        config,
        connection,
        _database_binding: database_binding,
        root_id: expected_root_id.into(),
    })
}

struct BoundDatabaseFileV1 {
    file: File,
    identity: DatabaseFileIdentityV1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DatabaseFileIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(windows)]
    file_id: u128,
}

fn bind_database_file_v1(path: &Path) -> Result<BoundDatabaseFileV1, AuthorityStoreOpenErrorV1> {
    validate_database_member_v1(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
    bind_reserved_database_file_v1(path, file)
}

fn bind_reserved_database_file_v1(
    path: &Path,
    file: File,
) -> Result<BoundDatabaseFileV1, AuthorityStoreOpenErrorV1> {
    validate_database_member_v1(path)?;
    let identity = database_file_identity_v1(&file)?;
    let path_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
    if database_file_identity_v1(&path_file)? != identity {
        return Err(AuthorityStoreOpenErrorV1::RootRoleMismatch);
    }
    validate_database_member_v1(path)?;
    Ok(BoundDatabaseFileV1 { file, identity })
}

fn verify_database_file_binding_v1(
    path: &Path,
    binding: &BoundDatabaseFileV1,
) -> Result<(), AuthorityStoreOpenErrorV1> {
    validate_database_member_v1(path)?;
    let path_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
    if database_file_identity_v1(&binding.file)? != binding.identity
        || database_file_identity_v1(&path_file)? != binding.identity
    {
        return Err(AuthorityStoreOpenErrorV1::RootRoleMismatch);
    }
    validate_database_member_v1(path)
}

fn validate_database_member_v1(path: &Path) -> Result<(), AuthorityStoreOpenErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AuthorityStoreOpenErrorV1::RootNotDedicated);
    }
    Ok(())
}

#[cfg(unix)]
fn database_file_identity_v1(
    file: &File,
) -> Result<DatabaseFileIdentityV1, AuthorityStoreOpenErrorV1> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
    Ok(DatabaseFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn database_file_identity_v1(
    file: &File,
) -> Result<DatabaseFileIdentityV1, AuthorityStoreOpenErrorV1> {
    let identity =
        fs_id::FileID::new(file).map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)?;
    Ok(DatabaseFileIdentityV1 {
        volume_serial_number: identity.storage_id(),
        file_id: identity.internal_file_id(),
    })
}

#[cfg(unix)]
fn sync_root_directory_v1(root: &Path) -> Result<(), AuthorityStoreOpenErrorV1> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AuthorityStoreOpenErrorV1::RootUnavailable)
}

#[cfg(windows)]
fn sync_root_directory_v1(_root: &Path) -> Result<(), AuthorityStoreOpenErrorV1> {
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitializationDatabaseStateV1 {
    Empty,
    CommittedV1,
}

fn open_reserved_database_v1(
    config: &AuthorityStoreConfigV1,
    busy_ms: u64,
) -> Result<Connection, AuthorityStoreOpenErrorV1> {
    let connection = Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(map_sqlite_busy_v1)?;
    arm_busy_timeout_v1(&connection, busy_ms)?;
    Ok(connection)
}

fn classify_initialization_database_v1(
    connection: &Connection,
) -> Result<InitializationDatabaseStateV1, AuthorityStoreOpenErrorV1> {
    let application_id = pragma_i64_v1(connection, "application_id")?;
    let user_version = pragma_i64_v1(connection, "user_version")?;
    let object_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| AuthorityStoreOpenErrorV1::SchemaInvalid)?;
    match (application_id, user_version, object_count) {
        (0, 0, 0) => Ok(InitializationDatabaseStateV1::Empty),
        (TASK_AUTHORITY_STORE_APPLICATION_ID_V1, TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1, count)
            if count > 0 =>
        {
            Ok(InitializationDatabaseStateV1::CommittedV1)
        }
        (TASK_AUTHORITY_STORE_APPLICATION_ID_V1, version, _)
            if version > TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1 =>
        {
            Err(AuthorityStoreOpenErrorV1::SchemaUnsupported)
        }
        (TASK_AUTHORITY_STORE_APPLICATION_ID_V1, _, _) => {
            Err(AuthorityStoreOpenErrorV1::SchemaInvalid)
        }
        (0, 0, _) => Err(AuthorityStoreOpenErrorV1::SchemaInvalid),
        _ => Err(AuthorityStoreOpenErrorV1::ApplicationIdMismatch),
    }
}

fn configure_initializing_connection_v1(
    connection: &Connection,
    busy_ms: u64,
) -> Result<(), AuthorityStoreOpenErrorV1> {
    arm_busy_timeout_v1(connection, busy_ms)?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable)?;
    configure_fixed_connection_pragmas_v1(connection)?;
    verify_journal_mode_v1(connection)
}

fn configure_ordinary_connection_v1(
    connection: &Connection,
    busy_ms: u64,
) -> Result<(), AuthorityStoreOpenErrorV1> {
    arm_busy_timeout_v1(connection, busy_ms)?;
    configure_fixed_connection_pragmas_v1(connection)?;
    verify_journal_mode_v1(connection)
}

fn configure_fixed_connection_pragmas_v1(
    connection: &Connection,
) -> Result<(), AuthorityStoreOpenErrorV1> {
    connection
        .pragma_update(None, "synchronous", "FULL")
        .and_then(|()| connection.pragma_update(None, "foreign_keys", true))
        .and_then(|()| connection.pragma_update(None, "recursive_triggers", true))
        .and_then(|()| connection.pragma_update(None, "trusted_schema", false))
        .and_then(|()| connection.pragma_update(None, "cell_size_check", true))
        .and_then(|()| connection.pragma_update(None, "wal_autocheckpoint", 0_i64))
        .map_err(|_| AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable)
}

fn verify_journal_mode_v1(connection: &Connection) -> Result<(), AuthorityStoreOpenErrorV1> {
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable)?;
    if journal_mode.eq_ignore_ascii_case("wal") {
        Ok(())
    } else {
        Err(AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable)
    }
}

fn checkpoint_initialization_v1(connection: &Connection) -> Result<(), AuthorityStoreOpenErrorV1> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
        .query_row("PRAGMA main.wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(map_sqlite_busy_v1)?;
    if busy == 0 && log_frames == checkpointed_frames {
        Ok(())
    } else {
        Err(AuthorityStoreOpenErrorV1::StoreBusy)
    }
}

fn arm_busy_timeout_v1(
    connection: &Connection,
    busy_ms: u64,
) -> Result<(), AuthorityStoreOpenErrorV1> {
    if busy_ms == 0 || busy_ms > i32::MAX as u64 {
        return Err(AuthorityStoreOpenErrorV1::DeadlineReached);
    }
    connection
        .busy_timeout(Duration::from_millis(busy_ms))
        .map_err(|_| AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable)
}

fn remaining_busy_ms_v1<P: AuthorityClockProviderV1 + ?Sized>(
    clock: &P,
    absolute_deadline_monotonic_ms: SafeU64,
    configured_maximum_ms: u64,
) -> Result<u64, AuthorityStoreOpenErrorV1> {
    if absolute_deadline_monotonic_ms.get() == 0 {
        return Err(AuthorityStoreOpenErrorV1::DeadlineReached);
    }
    let observation = clock
        .capture_v1(absolute_deadline_monotonic_ms)
        .map_err(map_clock_error_v1)?;
    absolute_deadline_monotonic_ms
        .get()
        .checked_sub(observation.sampled_monotonic_ms_v1().get())
        .filter(|remaining| *remaining > 0)
        .map(|remaining| remaining.min(configured_maximum_ms).min(i32::MAX as u64))
        .ok_or(AuthorityStoreOpenErrorV1::DeadlineReached)
}

fn validate_expected_root_id_v1(root_id: &str) -> Result<(), AuthorityStoreOpenErrorV1> {
    if root_id.len() != 64
        || !root_id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        Err(AuthorityStoreOpenErrorV1::RootIdentityMismatch)
    } else {
        Ok(())
    }
}

fn validate_expected_root_identity_v1(
    root_id: &str,
    provisioned_identity: AuthorityRootIdentityV1,
) -> Result<(), AuthorityStoreOpenErrorV1> {
    validate_expected_root_id_v1(root_id)?;
    for (encoded, expected) in root_id
        .as_bytes()
        .chunks_exact(2)
        .zip(provisioned_identity.as_bytes())
    {
        let decoded =
            (decode_lower_hex_nibble_v1(encoded[0]) << 4) | decode_lower_hex_nibble_v1(encoded[1]);
        if decoded != *expected {
            return Err(AuthorityStoreOpenErrorV1::RootIdentityMismatch);
        }
    }
    Ok(())
}

const fn decode_lower_hex_nibble_v1(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0xff,
    }
}

fn pragma_i64_v1(connection: &Connection, pragma: &str) -> Result<i64, AuthorityStoreOpenErrorV1> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|_| AuthorityStoreOpenErrorV1::SchemaInvalid)
}

fn map_clock_error_v1(error: AuthorityControlErrorV1) -> AuthorityStoreOpenErrorV1 {
    match error {
        AuthorityControlErrorV1::DeadlineReached
        | AuthorityControlErrorV1::InvalidAbsoluteDeadline => {
            AuthorityStoreOpenErrorV1::DeadlineReached
        }
        _ => AuthorityStoreOpenErrorV1::ClockUnavailable,
    }
}

fn map_root_error_v1(error: AuthorityRootSafetyErrorV1) -> AuthorityStoreOpenErrorV1 {
    match error {
        AuthorityRootSafetyErrorV1::RootInvalid => AuthorityStoreOpenErrorV1::RootInvalid,
        AuthorityRootSafetyErrorV1::RootNotDedicated => AuthorityStoreOpenErrorV1::RootNotDedicated,
        AuthorityRootSafetyErrorV1::RootRoleMismatch => AuthorityStoreOpenErrorV1::RootRoleMismatch,
        AuthorityRootSafetyErrorV1::RootIdentityMismatch => {
            AuthorityStoreOpenErrorV1::RootIdentityMismatch
        }
        AuthorityRootSafetyErrorV1::UnknownRootMember => {
            AuthorityStoreOpenErrorV1::UnknownRootMember
        }
        AuthorityRootSafetyErrorV1::RootUnavailable => AuthorityStoreOpenErrorV1::RootUnavailable,
    }
}

fn map_schema_error_v1(error: TaskAuthoritySchemaAdmissionErrorV1) -> AuthorityStoreOpenErrorV1 {
    match error {
        TaskAuthoritySchemaAdmissionErrorV1::ApplicationIdMismatch => {
            AuthorityStoreOpenErrorV1::ApplicationIdMismatch
        }
        TaskAuthoritySchemaAdmissionErrorV1::SchemaUnsupported => {
            AuthorityStoreOpenErrorV1::SchemaUnsupported
        }
        TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid => {
            AuthorityStoreOpenErrorV1::SchemaInvalid
        }
        TaskAuthoritySchemaAdmissionErrorV1::RootIdentityMismatch => {
            AuthorityStoreOpenErrorV1::RootIdentityMismatch
        }
        TaskAuthoritySchemaAdmissionErrorV1::LifecycleUnavailable => {
            AuthorityStoreOpenErrorV1::LifecycleUnavailable
        }
        TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable => {
            AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable
        }
        TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed => {
            AuthorityStoreOpenErrorV1::IntegrityFailed
        }
        TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed => {
            AuthorityStoreOpenErrorV1::InvariantFailed
        }
    }
}

fn map_sqlite_busy_v1(error: SqliteError) -> AuthorityStoreOpenErrorV1 {
    match error {
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            AuthorityStoreOpenErrorV1::StoreBusy
        }
        _ => AuthorityStoreOpenErrorV1::RootUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthorityRootIdentityEvidenceV1, AuthorityStoreConfigV1};
    use crate::root_safety::{
        AUTHORITY_DATABASE_FILENAME, AUTHORITY_ROOT_MARKER_FILENAME, AUTHORITY_WAL_FILENAME,
    };
    use crate::schema::{
        TASK_AUTHORITY_STORE_DURABILITY_PROFILE_V1, TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
    };
    use helix_task_authority::{AuthorityClockObservationV1, AuthorityControlErrorV1};
    use helix_task_authority_contracts::{Generation, Identifier};
    use rusqlite::params;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TemporaryRoot(PathBuf);

    impl TemporaryRoot {
        fn new() -> Self {
            loop {
                let nonce = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "helixos-task-authority-connection-{}-{nonce}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary authority root creates: {error}"),
                }
            }
        }

        fn database_path(&self) -> PathBuf {
            self.0.join(AUTHORITY_DATABASE_FILENAME)
        }

        fn marker_path(&self) -> PathBuf {
            self.0.join(AUTHORITY_ROOT_MARKER_FILENAME)
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FixedClock(u64);

    impl AuthorityClockProviderV1 for FixedClock {
        fn capture_v1(
            &self,
            _absolute_deadline_monotonic_ms: SafeU64,
        ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1> {
            Ok(clock_observation(self.0))
        }
    }

    struct ScriptedClock(Mutex<VecDeque<u64>>);

    impl ScriptedClock {
        fn new(samples: impl IntoIterator<Item = u64>) -> Self {
            Self(Mutex::new(samples.into_iter().collect()))
        }
    }

    impl AuthorityClockProviderV1 for ScriptedClock {
        fn capture_v1(
            &self,
            _absolute_deadline_monotonic_ms: SafeU64,
        ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1> {
            let sample = self
                .0
                .lock()
                .expect("scripted clock mutex remains available")
                .pop_front()
                .expect("scripted clock has a sample for every boundary");
            Ok(clock_observation(sample))
        }
    }

    #[test]
    fn explicit_initialization_publishes_last_and_ordinary_reopen_is_non_mutating() {
        let root = TemporaryRoot::new();
        let identity = evidence(0x11);
        let root_id = digest_hex(0x11);
        let config = empty_config(&root, identity);
        let marker_path = root.marker_path();
        let mut callback_observed_initializing = false;

        let opened =
            initialize_empty_with_v1(config, &FixedClock(1), safe(100), &root_id, |tx, id| {
                let marker =
                    fs::read_to_string(&marker_path).expect("initializing marker is readable");
                assert!(marker.ends_with("STATE=INITIALIZING\n"));
                callback_observed_initializing = true;
                stage_exact_bootstrap(tx, id);
                Ok(())
            })
            .expect("exact empty root initializes");

        assert!(callback_observed_initializing);
        assert_eq!(opened.root_id_v1(), root_id);
        assert!(fs::read_to_string(&marker_path)
            .expect("published marker reads")
            .ends_with("STATE=EXISTING\n"));
        let wal_path = root.0.join(AUTHORITY_WAL_FILENAME);
        assert!(
            !wal_path.exists() || fs::metadata(&wal_path).expect("WAL metadata reads").len() == 0,
            "publication requires a completed truncating checkpoint"
        );
        let database_before = fs::read(root.database_path()).expect("database snapshot reads");
        let marker_before = fs::read(&marker_path).expect("marker snapshot reads");
        drop(opened);

        let reopened = open_existing_v1(
            existing_config(&root, identity),
            &FixedClock(2),
            safe(100),
            &root_id,
        )
        .expect("exact published root reopens");
        assert_eq!(reopened.connection().total_changes(), 0);
        assert_eq!(reopened.root_id_v1(), root_id);
        assert_eq!(
            fs::read(root.database_path()).expect("reopened database snapshot reads"),
            database_before
        );
        assert_eq!(
            fs::read(&marker_path).expect("reopened marker snapshot reads"),
            marker_before
        );
    }

    #[test]
    fn callback_failure_rolls_back_and_never_publishes() {
        let root = TemporaryRoot::new();
        let identity = evidence(0x21);
        let root_id = digest_hex(0x21);

        assert_eq!(
            initialize_empty_with_v1(
                empty_config(&root, identity),
                &FixedClock(1),
                safe(100),
                &root_id,
                |_tx, _| Err(AuthorityStoreOpenErrorV1::InitializationRejected),
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::InitializationRejected
        );
        assert!(fs::read_to_string(root.marker_path())
            .expect("failed bootstrap retains marker")
            .ends_with("STATE=INITIALIZING\n"));
        assert!(
            AuthorityStoreConfigV1::try_new_existing_attested(root.0.clone(), identity, 25,)
                .is_err()
        );

        let connection = Connection::open(root.database_path()).expect("staging database opens");
        let application_id: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .expect("staging application id reads");
        let object_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .expect("staging object count reads");
        assert_eq!((application_id, object_count), (0, 0));
    }

    #[test]
    fn committed_initialization_resumes_without_reinvoking_bootstrap() {
        let root = TemporaryRoot::new();
        let identity = evidence(0x31);
        let root_id = digest_hex(0x31);
        let expiring = ScriptedClock::new([1, 2, 3, 100]);

        assert_eq!(
            initialize_empty_with_v1(
                empty_config(&root, identity),
                &expiring,
                safe(100),
                &root_id,
                |tx, id| {
                    stage_exact_bootstrap(tx, id);
                    Ok(())
                },
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::DeadlineReached
        );
        assert!(fs::read_to_string(root.marker_path())
            .expect("interrupted marker reads")
            .ends_with("STATE=INITIALIZING\n"));

        let mut callback_reinvoked = false;
        let recovered = initialize_empty_with_v1(
            empty_config(&root, identity),
            &FixedClock(4),
            safe(100),
            &root_id,
            |_tx, _| {
                callback_reinvoked = true;
                Err(AuthorityStoreOpenErrorV1::InitializationRejected)
            },
        )
        .expect("committed staging root resumes and publishes");
        assert!(!callback_reinvoked);
        assert!(fs::read_to_string(root.marker_path())
            .expect("recovered marker reads")
            .ends_with("STATE=EXISTING\n"));
        assert_eq!(recovered.root_id_v1(), root_id);
    }

    #[test]
    fn wrong_role_and_reached_deadline_refuse_before_mutation() {
        let empty = TemporaryRoot::new();
        let identity = evidence(0x41);
        let root_id = digest_hex(0x41);
        assert_eq!(
            open_existing_v1(
                empty_config(&empty, identity),
                &FixedClock(1),
                safe(100),
                &root_id,
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::RootRoleMismatch
        );
        assert_eq!(
            initialize_empty_with_v1(
                empty_config(&empty, identity),
                &FixedClock(100),
                safe(100),
                &root_id,
                |_tx, _| -> Result<(), AuthorityStoreOpenErrorV1> {
                    panic!("expired initialization must not invoke bootstrap")
                },
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::DeadlineReached
        );
        assert_eq!(fs::read_dir(&empty.0).expect("empty root reads").count(), 0);

        let published = TemporaryRoot::new();
        let published_id = digest_hex(0x42);
        let opened = initialize_exact(&published, 0x42);
        let existing = opened.config().clone();
        drop(opened);
        assert_eq!(
            initialize_empty_with_v1(
                existing,
                &FixedClock(1),
                safe(100),
                &published_id,
                |_tx, _| Ok(()),
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::RootRoleMismatch
        );
    }

    #[test]
    fn malformed_or_marker_mismatched_root_identity_refuses_without_mutation() {
        for invalid in [
            "ff".to_owned(),
            "f".repeat(63),
            "f".repeat(65),
            "FF".repeat(32),
            "fg".repeat(32),
            digest_hex(0x11),
        ] {
            let root = TemporaryRoot::new();
            assert_eq!(
                initialize_empty_with_v1(
                    empty_config(&root, evidence(0xff)),
                    &FixedClock(1),
                    safe(100),
                    &invalid,
                    |_tx, _| -> Result<(), AuthorityStoreOpenErrorV1> {
                        panic!("invalid identity must fail before bootstrap")
                    },
                )
                .unwrap_err(),
                AuthorityStoreOpenErrorV1::RootIdentityMismatch,
                "identity unexpectedly admitted: {invalid}"
            );
            assert_eq!(
                fs::read_dir(&root.0)
                    .expect("unmodified root reads")
                    .count(),
                0
            );
        }

        let root = TemporaryRoot::new();
        let opened = initialize_exact(&root, 0x51);
        let database_before = fs::read(root.database_path()).expect("database snapshot reads");
        let existing = opened.config().clone();
        drop(opened);
        assert_eq!(
            open_existing_v1(existing, &FixedClock(1), safe(100), &digest_hex(0x52),).unwrap_err(),
            AuthorityStoreOpenErrorV1::RootIdentityMismatch
        );
        assert_eq!(
            fs::read(root.database_path()).expect("refused database snapshot reads"),
            database_before
        );
    }

    #[test]
    fn committed_resume_refuses_a_wrong_persistent_profile_without_repair() {
        let root = TemporaryRoot::new();
        let identity = evidence(0x59);
        let root_id = digest_hex(0x59);
        let expiring = ScriptedClock::new([1, 2, 3, 100]);
        assert_eq!(
            initialize_empty_with_v1(
                empty_config(&root, identity),
                &expiring,
                safe(100),
                &root_id,
                |tx, id| {
                    stage_exact_bootstrap(tx, id);
                    Ok(())
                },
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::DeadlineReached
        );

        let connection = Connection::open(root.database_path())
            .expect("committed staging mutation connection opens");
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .expect("committed staging profile mutates");
        drop(connection);
        assert_eq!(
            initialize_empty_with_v1(
                empty_config(&root, identity),
                &FixedClock(1),
                safe(100),
                &root_id,
                |_tx, _| -> Result<(), AuthorityStoreOpenErrorV1> {
                    panic!("committed staging must never rerun bootstrap")
                },
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable
        );
        assert!(fs::read_to_string(root.marker_path())
            .expect("refused committed marker reads")
            .ends_with("STATE=INITIALIZING\n"));
        let connection = Connection::open(root.database_path())
            .expect("committed staging profile readback opens");
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("committed staging profile reads");
        assert_eq!(journal_mode.to_ascii_lowercase(), "delete");
    }

    #[test]
    fn future_schema_and_wrong_persistent_profile_refuse_without_repair() {
        let future_root = TemporaryRoot::new();
        let future_identity = evidence(0x61);
        let future_id = digest_hex(0x61);
        drop(initialize_exact(&future_root, 0x61));
        let future_connection = Connection::open(future_root.database_path())
            .expect("future schema mutation connection opens");
        future_connection
            .pragma_update(None, "user_version", 2_i64)
            .expect("future version installs");
        drop(future_connection);
        assert_eq!(
            open_existing_v1(
                existing_config(&future_root, future_identity),
                &FixedClock(1),
                safe(100),
                &future_id,
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::SchemaUnsupported
        );
        let future_connection =
            Connection::open(future_root.database_path()).expect("future schema readback opens");
        assert_eq!(
            future_connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .expect("future version reads"),
            2
        );

        let profile_root = TemporaryRoot::new();
        let profile_identity = evidence(0x62);
        let profile_id = digest_hex(0x62);
        drop(initialize_exact(&profile_root, 0x62));
        let profile_connection = Connection::open(profile_root.database_path())
            .expect("profile mutation connection opens");
        let journal_mode: String = profile_connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("initial journal mode reads");
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        profile_connection
            .pragma_update(None, "journal_mode", "DELETE")
            .expect("persistent profile mutates");
        drop(profile_connection);
        assert_eq!(
            open_existing_v1(
                existing_config(&profile_root, profile_identity),
                &FixedClock(1),
                safe(100),
                &profile_id,
            )
            .unwrap_err(),
            AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable
        );
        let profile_connection = Connection::open(profile_root.database_path())
            .expect("profile readback connection opens");
        let journal_mode: String = profile_connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("profile readback reads");
        assert_eq!(journal_mode.to_ascii_lowercase(), "delete");
    }

    #[test]
    fn replacing_the_database_member_breaks_the_retained_binding() {
        let root = TemporaryRoot::new();
        let path = root.database_path();
        fs::write(&path, b"original").expect("original database member writes");
        let binding = bind_database_file_v1(&path).expect("database member binds");
        let moved = root.0.join("moved-outside-root");
        fs::rename(&path, &moved).expect("bound database member moves");
        fs::write(&path, b"replacement").expect("replacement database member writes");
        assert_eq!(
            verify_database_file_binding_v1(&path, &binding),
            Err(AuthorityStoreOpenErrorV1::RootRoleMismatch)
        );
        fs::remove_file(&moved).expect("moved test member removes");
    }

    fn initialize_exact(root: &TemporaryRoot, identity_byte: u8) -> OpenedAuthorityStoreV1 {
        let root_id = digest_hex(identity_byte);
        initialize_empty_with_v1(
            empty_config(root, evidence(identity_byte)),
            &FixedClock(1),
            safe(100),
            &root_id,
            |tx, id| {
                stage_exact_bootstrap(tx, id);
                Ok(())
            },
        )
        .expect("exact test store initializes")
    }

    fn empty_config(
        root: &TemporaryRoot,
        identity: AuthorityRootIdentityEvidenceV1,
    ) -> AuthorityStoreConfigV1 {
        AuthorityStoreConfigV1::try_new_empty_attested(root.0.clone(), identity, 25)
            .expect("empty authority configuration validates")
    }

    fn existing_config(
        root: &TemporaryRoot,
        identity: AuthorityRootIdentityEvidenceV1,
    ) -> AuthorityStoreConfigV1 {
        AuthorityStoreConfigV1::try_new_existing_attested(root.0.clone(), identity, 25)
            .expect("existing authority configuration validates")
    }

    fn evidence(byte: u8) -> AuthorityRootIdentityEvidenceV1 {
        AuthorityRootIdentityEvidenceV1::from_attested_bytes([byte; 32])
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("test safe integer validates")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("test generation validates")
    }

    fn clock_observation(monotonic_ms: u64) -> AuthorityClockObservationV1 {
        AuthorityClockObservationV1::from_trusted_provider_parts_v1(
            Identifier::new("boot-a").expect("test boot id validates"),
            generation(1),
            generation(1),
            safe(1),
            safe(monotonic_ms),
        )
    }

    fn stage_exact_bootstrap(transaction: &Transaction<'_>, root_id: &str) {
        let attempt_id = digest_hex(0x01);
        let event_id = digest_hex(0x02);
        let receipt_id = digest_hex(0x03);
        transaction
            .execute(
                "INSERT INTO authority_attempts (
                     attempt_id, operation_kind, namespace_digest, input_graph_digest,
                     caller_deadline_monotonic_ms, outcome_code, outcome_binding_digest,
                     attempt_generation, event_id
                 ) VALUES (?1, 'BOOTSTRAP', ?2, ?3, 1000, 'COMMITTED_RETAINED', ?4, 1, ?5)",
                params![
                    attempt_id,
                    digest_hex(0x04),
                    digest_hex(0x05),
                    digest_hex(0x06),
                    event_id,
                ],
            )
            .expect("bootstrap attempt inserts");
        transaction
            .execute(
                "INSERT INTO authority_events (
                     event_id, event_kind, subject_kind, subject_reference_digest,
                     attempt_id, result_code, reason_code, event_generation,
                     observed_at_utc_ms, observed_at_monotonic_ms, boot_id,
                     previous_event_digest, event_digest
                 ) VALUES (
                     ?1, 'BOOTSTRAP_COMPLETED', 'ROOT', ?2, ?3, 'COMMITTED_RETAINED',
                     'BOOTSTRAP_COMPLETED', 1, 1, 1, 'boot-a', NULL, ?4
                 )",
                params![event_id, digest_hex(0x07), attempt_id, digest_hex(0x08)],
            )
            .expect("bootstrap event inserts");
        transaction
            .execute(
                "INSERT INTO authority_bootstrap_receipts (
                     bootstrap_receipt_id, bootstrap_attempt_id, source_commit, source_tree,
                     source_application_id, source_user_version, source_root_id,
                     source_schema_digest, source_backup_digest, source_summary_digest,
                     target_root_id, target_schema_digest, imported_grant_count,
                     imported_lease_count, imported_decision_count, migration_generation,
                     created_at_utc_ms, tool_identity, tool_digest
                 ) VALUES (
                     ?1, ?2, ?3, ?4, 1212962883, 2, 'coordinator-root', ?5, ?6, ?7,
                     ?8, ?9, 0, 0, 0, 1, 1, 'helixos-provision', ?10
                 )",
                params![
                    receipt_id,
                    attempt_id,
                    "aa".repeat(20),
                    "bb".repeat(20),
                    digest_hex(0x09),
                    digest_hex(0x0a),
                    digest_hex(0x0b),
                    root_id,
                    TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                    digest_hex(0x0c),
                ],
            )
            .expect("bootstrap receipt inserts");
        transaction
            .execute(
                "INSERT INTO authority_store_metadata (
                     singleton_id, application_id, schema_version, schema_digest, root_id,
                     lifecycle, durability_profile, boot_id, instance_epoch, fencing_epoch,
                     restore_epoch, ordinary_capacity, control_capacity, store_generation,
                     trust_generation, grant_generation, lease_generation,
                     allocation_generation, counter_generation, decision_generation,
                     revocation_generation, event_generation, migration_generation,
                     backup_generation, restore_generation, created_at_utc_ms,
                     bootstrap_receipt_id, restore_receipt_id
                 ) VALUES (
                     1, ?1, 1, ?2, ?3, 'ACTIVE', ?4, 'boot-a', 1, 1, 0, 1024, 32,
                     1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, ?5, NULL
                 )",
                params![
                    TASK_AUTHORITY_STORE_APPLICATION_ID_V1,
                    TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                    root_id,
                    TASK_AUTHORITY_STORE_DURABILITY_PROFILE_V1,
                    receipt_id,
                ],
            )
            .expect("authority metadata inserts");
    }

    fn digest_hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }
}
