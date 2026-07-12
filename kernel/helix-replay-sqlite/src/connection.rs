use crate::clock::remaining_monotonic_ms;
use crate::config::{revalidate_live_root, ReplayStoreConfigV1};
use crate::error::InternalStoreError;
use crate::root_safety::{
    acquire_checked_live_root_lease, quarantine_unopenable_live_root,
    quarantine_with_held_live_lease,
};
use crate::schema::{self, StoreSummary};
use crate::ReplayMonotonicClockV1;
use rusqlite::{Connection, Error as SqliteError, ErrorCode, OpenFlags};
use std::collections::HashMap;
#[cfg(feature = "test-fault-injection")]
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError, Weak};
use std::time::Duration;

const MAX_SQLITE_BUSY_TIMEOUT_MS: u64 = i32::MAX as u64;
const MAX_CONNECTION_ATTEMPTS: u64 = 8;
const MAX_SETUP_GATE_ATTEMPTS: u64 = 5_000;

#[cfg(feature = "test-fault-injection")]
const INITIALIZATION_FAULT_ENV: &str = "HELIX_REPLAY_TEST_INITIALIZATION_FAULT";

#[cfg(feature = "test-fault-injection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitializationFaultBoundary {
    ProviderOpen,
    WritableProfile,
}

#[cfg(feature = "test-fault-injection")]
impl InitializationFaultBoundary {
    const fn scenario(self) -> &'static str {
        match self {
            Self::ProviderOpen => "provider_open_unavailable",
            Self::WritableProfile => "writable_profile_unavailable",
        }
    }

    const fn error(self) -> InternalStoreError {
        match self {
            Self::ProviderOpen => InternalStoreError::StoreUnavailable,
            Self::WritableProfile => InternalStoreError::DurabilityProfileUnavailable,
        }
    }
}

static CONNECTION_SETUP_GATES: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

pub(crate) fn initialize_or_verify_store<C: ReplayMonotonicClockV1>(
    config: &ReplayStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<StoreSummary, InternalStoreError> {
    let initial_remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    #[cfg(feature = "test-fault-injection")]
    fail_initialization_at(InitializationFaultBoundary::ProviderOpen)?;
    let gate = connection_setup_gate(config.database_path());
    let gate_attempts =
        bounded_busy_ms(config, initial_remaining_ms).clamp(1, MAX_SETUP_GATE_ATTEMPTS);
    let _guard = acquire_setup_gate_with_clock(&gate, gate_attempts, clock, deadline_monotonic_ms)?;
    let root_lease = acquire_checked_live_root_lease(
        config.root(),
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    revalidate_live_root(config.root()).map_err(|error| match error {
        crate::ReplayStoreLocationErrorV1::LocationInvalid => InternalStoreError::LocationInvalid,
        crate::ReplayStoreLocationErrorV1::LocationNotDedicated => {
            InternalStoreError::LocationNotDedicated
        }
    })?;
    preflight_database_file(config, true)?;
    drop(root_lease);
    let remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;

    let total_busy_ms = bounded_busy_ms(config, remaining_ms);
    let attempts = total_busy_ms.clamp(1, MAX_CONNECTION_ATTEMPTS);
    let attempt_busy_ms = total_busy_ms.div_ceil(attempts);
    for attempt in 0..attempts {
        let current_remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        let current_busy_ms = attempt_busy_ms
            .min(current_remaining_ms)
            .min(config.maximum_busy_wait_ms());
        match initialize_or_verify_store_attempt(
            config,
            clock,
            deadline_monotonic_ms,
            current_busy_ms,
        ) {
            Ok(summary) => {
                remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
                return Ok(summary);
            }
            Err(error) => {
                if !error.is_retryable_connection() || attempt + 1 == attempts {
                    return Err(error);
                }
                remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    Err(InternalStoreError::StoreUnavailable)
}

fn connection_setup_gate(database_path: PathBuf) -> Arc<Mutex<()>> {
    let registry = CONNECTION_SETUP_GATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut gates = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    gates.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = gates.get(&database_path).and_then(Weak::upgrade) {
        return gate;
    }
    let gate = Arc::new(Mutex::new(()));
    gates.insert(database_path, Arc::downgrade(&gate));
    gate
}

fn acquire_setup_gate_with_clock<'gate, C: ReplayMonotonicClockV1>(
    gate: &'gate Mutex<()>,
    maximum_attempts: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<MutexGuard<'gate, ()>, InternalStoreError> {
    for attempt in 0..maximum_attempts {
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        match gate.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) if attempt + 1 < maximum_attempts => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => return Err(InternalStoreError::StoreBusy),
        }
    }
    Err(InternalStoreError::StoreBusy)
}

fn initialize_or_verify_store_attempt<C: ReplayMonotonicClockV1>(
    config: &ReplayStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
    busy_timeout_ms: u64,
) -> Result<StoreSummary, InternalStoreError> {
    let path = config.database_path();
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    connection
        .busy_timeout(Duration::from_millis(busy_timeout_ms))
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;
    if let Err(error) = verify_initialization_candidate(&mut connection) {
        if error.requires_durable_quarantine() {
            quarantine_unopenable_live_root(
                config.root(),
                config.maximum_busy_wait_ms(),
                clock,
                deadline_monotonic_ms,
            )?;
        }
        return Err(error);
    }
    #[cfg(feature = "test-fault-injection")]
    fail_initialization_at(InitializationFaultBoundary::WritableProfile)?;
    configure_writable_connection(&connection, busy_timeout_ms, true)?;
    schema::initialize_empty_to_v1_or_verify(
        &mut connection,
        config,
        clock,
        deadline_monotonic_ms,
    )?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    let mut root_lease = acquire_checked_live_root_lease(
        config.root(),
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    let result = schema::verify_full(&transaction);
    if let Err(error) = result {
        if error.requires_durable_quarantine() {
            quarantine_with_held_live_lease(&mut root_lease, config.root())?;
        }
        return Err(error);
    }
    let summary = result?;
    transaction
        .rollback()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    Ok(summary)
}

#[cfg(feature = "test-fault-injection")]
fn fail_initialization_at(boundary: InitializationFaultBoundary) -> Result<(), InternalStoreError> {
    let requested = env::var(INITIALIZATION_FAULT_ENV).ok();
    if requested.as_deref() == Some(boundary.scenario()) {
        Err(boundary.error())
    } else {
        Ok(())
    }
}

pub(crate) fn open_existing_for_claim<C: ReplayMonotonicClockV1>(
    config: &ReplayStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<Connection, InternalStoreError> {
    let initial_remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    let gate = connection_setup_gate(config.database_path());
    let gate_attempts =
        bounded_busy_ms(config, initial_remaining_ms).clamp(1, MAX_SETUP_GATE_ATTEMPTS);
    let _guard = acquire_setup_gate_with_clock(&gate, gate_attempts, clock, deadline_monotonic_ms)?;
    let root_lease = acquire_checked_live_root_lease(
        config.root(),
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    revalidate_live_root(config.root()).map_err(|error| match error {
        crate::ReplayStoreLocationErrorV1::LocationInvalid => InternalStoreError::LocationInvalid,
        crate::ReplayStoreLocationErrorV1::LocationNotDedicated => {
            InternalStoreError::LocationNotDedicated
        }
    })?;
    preflight_database_file(config, false)?;
    drop(root_lease);
    let remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    let total_busy_ms = bounded_busy_ms(config, remaining_ms);
    let attempts = total_busy_ms.clamp(1, MAX_CONNECTION_ATTEMPTS);
    let attempt_busy_ms = total_busy_ms.div_ceil(attempts);
    for attempt in 0..attempts {
        let current_remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        let current_busy_ms = attempt_busy_ms
            .min(current_remaining_ms)
            .min(config.maximum_busy_wait_ms());
        let result = open_existing_for_claim_attempt(config, current_busy_ms);
        match result {
            Ok(connection) => {
                remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
                return Ok(connection);
            }
            Err(error) => {
                if !error.is_retryable_connection() || attempt + 1 == attempts {
                    return Err(error);
                }
                remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    Err(InternalStoreError::StoreUnavailable)
}

/// Opens an existing replay store through SQLite's read-only and query-only gates.
///
/// This path never creates the database, establishes WAL, or invokes the writable
/// connection profile used by replay admission.
pub(crate) fn open_existing_query_only<C: ReplayMonotonicClockV1>(
    config: &ReplayStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<Connection, InternalStoreError> {
    let initial_remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    let gate = connection_setup_gate(config.database_path());
    let gate_attempts =
        bounded_busy_ms(config, initial_remaining_ms).clamp(1, MAX_SETUP_GATE_ATTEMPTS);
    let _guard = acquire_setup_gate_with_clock(&gate, gate_attempts, clock, deadline_monotonic_ms)?;
    let root_lease = acquire_checked_live_root_lease(
        config.root(),
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    revalidate_live_root(config.root()).map_err(|error| match error {
        crate::ReplayStoreLocationErrorV1::LocationInvalid => InternalStoreError::LocationInvalid,
        crate::ReplayStoreLocationErrorV1::LocationNotDedicated => {
            InternalStoreError::LocationNotDedicated
        }
    })?;
    preflight_database_file(config, false)?;
    drop(root_lease);

    let remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    let total_busy_ms = bounded_busy_ms(config, remaining_ms);
    let attempts = total_busy_ms.clamp(1, MAX_CONNECTION_ATTEMPTS);
    let attempt_busy_ms = total_busy_ms.div_ceil(attempts);
    for attempt in 0..attempts {
        let current_remaining_ms = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        let current_busy_ms = attempt_busy_ms
            .min(current_remaining_ms)
            .min(config.maximum_busy_wait_ms());
        match open_existing_query_only_attempt(config, current_busy_ms) {
            Ok(connection) => {
                remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
                return Ok(connection);
            }
            Err(error) => {
                if !error.is_retryable_connection() || attempt + 1 == attempts {
                    return Err(error);
                }
                remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    Err(InternalStoreError::StoreUnavailable)
}

fn open_existing_for_claim_attempt(
    config: &ReplayStoreConfigV1,
    busy_timeout_ms: u64,
) -> Result<Connection, InternalStoreError> {
    let connection = Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    configure_writable_connection(&connection, busy_timeout_ms, false)?;
    Ok(connection)
}

fn open_existing_query_only_attempt(
    config: &ReplayStoreConfigV1,
    busy_timeout_ms: u64,
) -> Result<Connection, InternalStoreError> {
    let connection = Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    configure_query_only_connection(&connection, busy_timeout_ms)?;
    Ok(connection)
}

fn preflight_database_file(
    config: &ReplayStoreConfigV1,
    absent_is_initializable: bool,
) -> Result<(), InternalStoreError> {
    let metadata = match fs::symlink_metadata(config.database_path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && absent_is_initializable => {
            return Ok(())
        }
        Err(_) => return Err(InternalStoreError::StoreUnavailable),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InternalStoreError::SchemaInvalid);
    }
    if metadata.len() == 0 && !absent_is_initializable {
        return Err(InternalStoreError::SchemaInvalid);
    }
    Ok(())
}

pub(crate) fn map_sqlite_error(
    error: &SqliteError,
    fallback: InternalStoreError,
) -> InternalStoreError {
    match error {
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
            ) =>
        {
            InternalStoreError::IntegrityFailed
        }
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            InternalStoreError::StoreBusy
        }
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::SchemaChanged | ErrorCode::FileLockingProtocolFailed
            ) =>
        {
            InternalStoreError::StoreBusy
        }
        _ => fallback,
    }
}

fn bounded_busy_ms(config: &ReplayStoreConfigV1, remaining_ms: u64) -> u64 {
    remaining_ms
        .min(config.maximum_busy_wait_ms())
        .min(MAX_SQLITE_BUSY_TIMEOUT_MS)
}

pub(crate) fn configure_writable_connection(
    connection: &Connection,
    busy_timeout_ms: u64,
    establish_journal_mode: bool,
) -> Result<(), InternalStoreError> {
    connection
        .busy_timeout(Duration::from_millis(busy_timeout_ms))
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;

    let journal_mode: String = if establish_journal_mode {
        connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|error| {
                map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
            })?
    } else {
        connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|error| {
                map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
            })?
    };
    if pragma_i64(connection, "synchronous")? != 2 {
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| {
                map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
            })?;
    }
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|()| connection.pragma_update(None, "cell_size_check", "ON"))
        .and_then(|()| connection.pragma_update(None, "wal_autocheckpoint", 0_i64))
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;

    let synchronous = pragma_i64(connection, "synchronous")?;
    let foreign_keys = pragma_i64(connection, "foreign_keys")?;
    let trusted_schema = pragma_i64(connection, "trusted_schema")?;
    let cell_size_check = pragma_i64(connection, "cell_size_check")?;
    let wal_autocheckpoint = pragma_i64(connection, "wal_autocheckpoint")?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || trusted_schema != 0
        || cell_size_check != 1
        || wal_autocheckpoint != 0
    {
        return Err(InternalStoreError::DurabilityProfileUnavailable);
    }
    Ok(())
}

fn configure_query_only_connection(
    connection: &Connection,
    busy_timeout_ms: u64,
) -> Result<(), InternalStoreError> {
    connection
        .busy_timeout(Duration::from_millis(busy_timeout_ms))
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;

    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;
    if pragma_i64(connection, "synchronous")? != 2 {
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|error| {
                map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
            })?;
    }
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|()| connection.pragma_update(None, "cell_size_check", "ON"))
        .and_then(|()| connection.pragma_update(None, "wal_autocheckpoint", 0_i64))
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;

    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;
    if pragma_i64(connection, "query_only")? != 1
        || !journal_mode.eq_ignore_ascii_case("wal")
        || pragma_i64(connection, "synchronous")? != 2
        || pragma_i64(connection, "foreign_keys")? != 1
        || pragma_i64(connection, "trusted_schema")? != 0
        || pragma_i64(connection, "cell_size_check")? != 1
        || pragma_i64(connection, "wal_autocheckpoint")? != 0
    {
        return Err(InternalStoreError::DurabilityProfileUnavailable);
    }
    Ok(())
}

fn verify_initialization_candidate(connection: &mut Connection) -> Result<(), InternalStoreError> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    let application_id = pragma_i64_with_fallback(
        &transaction,
        "application_id",
        InternalStoreError::SchemaInvalid,
    )?;
    let user_version = pragma_i64_with_fallback(
        &transaction,
        "user_version",
        InternalStoreError::SchemaInvalid,
    )?;
    let object_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))?;

    let result = match (application_id, user_version, object_count) {
        (0, 0, 0) => Ok(()),
        (schema::REPLAY_STORE_APPLICATION_ID_V1, schema::REPLAY_STORE_SCHEMA_VERSION_V1, _) => {
            Ok(())
        }
        (schema::REPLAY_STORE_APPLICATION_ID_V1, version, _)
            if version > schema::REPLAY_STORE_SCHEMA_VERSION_V1 =>
        {
            Err(InternalStoreError::SchemaUnsupported)
        }
        (schema::REPLAY_STORE_APPLICATION_ID_V1, _, _) => Err(InternalStoreError::SchemaInvalid),
        (0, _, _) => Err(InternalStoreError::SchemaInvalid),
        (_, _, _) => Err(InternalStoreError::ApplicationIdMismatch),
    };
    transaction
        .rollback()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    result
}

fn pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, InternalStoreError> {
    pragma_i64_with_fallback(
        connection,
        pragma,
        InternalStoreError::DurabilityProfileUnavailable,
    )
}

fn pragma_i64_with_fallback(
    connection: &Connection,
    pragma: &str,
    fallback: InternalStoreError,
) -> Result<i64, InternalStoreError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error, fallback))
}
