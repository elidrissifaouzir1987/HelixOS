use crate::config::ReplayStoreConfigV1;
use crate::connection::map_sqlite_error;
use crate::error::InternalStoreError;
use crate::root_safety::acquire_checked_live_root_lease;
use crate::ReplayMonotonicClockV1;
use helix_contracts::MAX_SAFE_U64;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};

pub const REPLAY_STORE_APPLICATION_ID_V1: i64 = 1_212_962_898;
pub const REPLAY_STORE_SCHEMA_VERSION_V1: i64 = 1;
pub const REPLAY_STORE_FORMAT_VERSION_V1: i64 = 1;
pub const REPLAY_STORE_SCHEMA_V1_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/003-durable-replay-store/contracts/replay-store-schema-v1.sql"
));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoreSummary {
    pub(crate) claimant_generation: u64,
    pub(crate) claim_count: u64,
    pub(crate) schema_cookie: i64,
}

#[derive(Clone, PartialEq, Eq)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Clone, Copy)]
pub(crate) struct ReplayStoreMetadataRow {
    pub(crate) claimant_generation: u64,
}

pub(crate) struct ReplayClaimRow {
    pub(crate) claimant_generation: u64,
}

pub fn embedded_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(REPLAY_STORE_SCHEMA_V1_SQL.as_bytes()).into()
}

pub(crate) fn initialize_empty_to_v1_or_verify<C: ReplayMonotonicClockV1>(
    connection: &mut Connection,
    config: &ReplayStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<(), InternalStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    let root_lease = acquire_checked_live_root_lease(
        config.root(),
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    drop(root_lease);

    let application_id = pragma_i64(&transaction, "application_id")?;
    let user_version = pragma_i64(&transaction, "user_version")?;
    let object_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))?;

    let _initialized_empty_store = match (application_id, user_version, object_count) {
        (0, 0, 0) => {
            transaction
                .execute_batch(REPLAY_STORE_SCHEMA_V1_SQL)
                .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))?;
            #[cfg(feature = "test-fault-injection")]
            crate::test_fault::reach(
                crate::test_fault::ReplayFaultPointV1::InitializationSchemaStaged,
            );
            true
        }
        (REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1, _) => false,
        (0, 0, _) => return Err(InternalStoreError::SchemaInvalid),
        (REPLAY_STORE_APPLICATION_ID_V1, version, _)
            if version > REPLAY_STORE_SCHEMA_VERSION_V1 =>
        {
            return Err(InternalStoreError::SchemaUnsupported);
        }
        (REPLAY_STORE_APPLICATION_ID_V1, _, _) => {
            return Err(InternalStoreError::SchemaInvalid);
        }
        (_, _, _) => return Err(InternalStoreError::ApplicationIdMismatch),
    };

    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    #[cfg(feature = "test-fault-injection")]
    if _initialized_empty_store {
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::InitializationCommitted);
    }
    verify_exact_schema(connection)
}

pub(crate) fn verify_lightweight(
    connection: &Connection,
    expected_schema_cookie: i64,
) -> Result<(), InternalStoreError> {
    verify_identity(connection)?;

    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| {
            map_sqlite_error(&error, InternalStoreError::DurabilityProfileUnavailable)
        })?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || pragma_i64(connection, "synchronous")? != 2
        || pragma_i64(connection, "foreign_keys")? != 1
        || pragma_i64(connection, "trusted_schema")? != 0
        || pragma_i64(connection, "cell_size_check")? != 1
        || pragma_i64(connection, "wal_autocheckpoint")? != 0
    {
        return Err(InternalStoreError::DurabilityProfileUnavailable);
    }

    if schema_cookie(connection)? != expected_schema_cookie {
        return Err(InternalStoreError::SchemaInvalid);
    }
    Ok(())
}

pub(crate) fn verify_exact_schema(connection: &Connection) -> Result<(), InternalStoreError> {
    verify_identity(connection)?;
    let actual = read_schema_objects(connection)?;
    let expected_connection = Connection::open_in_memory()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))?;
    expected_connection
        .execute_batch(REPLAY_STORE_SCHEMA_V1_SQL)
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))?;
    let expected = read_schema_objects(&expected_connection)?;
    if actual != expected {
        return Err(InternalStoreError::SchemaInvalid);
    }
    Ok(())
}

pub(crate) fn verify_full(connection: &Connection) -> Result<StoreSummary, InternalStoreError> {
    verify_exact_schema(connection)?;
    verify_integrity_check(connection)?;

    let metadata = decode_single_metadata_row(connection)?;
    let mut statement = connection
        .prepare(
            "SELECT instance_epoch, nonce, operation_id, binding_digest, claim_id, \
             claimant_generation FROM replay_claims ORDER BY claimant_generation",
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::InvariantFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::InvariantFailed))?;
    let mut count = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::InvariantFailed))?
    {
        let decoded = decode_claim_row(row)?;
        count = count
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(InternalStoreError::InvariantFailed)?;
        if decoded.claimant_generation != count {
            return Err(InternalStoreError::InvariantFailed);
        }
    }

    if metadata.claimant_generation != count {
        return Err(InternalStoreError::InvariantFailed);
    }

    Ok(StoreSummary {
        claimant_generation: metadata.claimant_generation,
        claim_count: count,
        schema_cookie: schema_cookie(connection)?,
    })
}

pub(crate) fn schema_cookie(connection: &Connection) -> Result<i64, InternalStoreError> {
    pragma_i64(connection, "schema_version").map_err(|_| InternalStoreError::SchemaInvalid)
}

pub(crate) fn latch_unhealthy(healthy: &AtomicBool) {
    healthy.store(false, Ordering::Release);
}

fn verify_identity(connection: &Connection) -> Result<(), InternalStoreError> {
    let application_id = pragma_i64(connection, "application_id")?;
    if application_id != REPLAY_STORE_APPLICATION_ID_V1 {
        return Err(InternalStoreError::ApplicationIdMismatch);
    }
    let user_version = pragma_i64(connection, "user_version")?;
    if user_version > REPLAY_STORE_SCHEMA_VERSION_V1 {
        return Err(InternalStoreError::SchemaUnsupported);
    }
    if user_version != REPLAY_STORE_SCHEMA_VERSION_V1 {
        return Err(InternalStoreError::SchemaInvalid);
    }
    Ok(())
}

fn verify_integrity_check(connection: &Connection) -> Result<(), InternalStoreError> {
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::IntegrityFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::IntegrityFailed))?;
    let first = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::IntegrityFailed))?
        .ok_or(InternalStoreError::IntegrityFailed)?;
    let result: String = first
        .get(0)
        .map_err(|_| InternalStoreError::IntegrityFailed)?;
    if result != "ok"
        || rows
            .next()
            .map_err(|error| map_sqlite_error(&error, InternalStoreError::IntegrityFailed))?
            .is_some()
    {
        return Err(InternalStoreError::IntegrityFailed);
    }
    Ok(())
}

fn decode_single_metadata_row(
    connection: &Connection,
) -> Result<ReplayStoreMetadataRow, InternalStoreError> {
    let mut statement = connection
        .prepare("SELECT singleton, format_version, claimant_generation FROM replay_store_meta")
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::InvariantFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::InvariantFailed))?;
    let row = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::InvariantFailed))?
        .ok_or(InternalStoreError::InvariantFailed)?;
    let singleton = strict_safe_integer(
        row.get_ref(0)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
    )?;
    let format_version = strict_safe_integer(
        row.get_ref(1)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
    )?;
    let claimant_generation = strict_safe_integer(
        row.get_ref(2)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
    )?;
    if singleton != 1
        || format_version != REPLAY_STORE_FORMAT_VERSION_V1 as u64
        || rows
            .next()
            .map_err(|error| map_sqlite_error(&error, InternalStoreError::InvariantFailed))?
            .is_some()
    {
        return Err(InternalStoreError::InvariantFailed);
    }
    Ok(ReplayStoreMetadataRow {
        claimant_generation,
    })
}

fn decode_claim_row(row: &rusqlite::Row<'_>) -> Result<ReplayClaimRow, InternalStoreError> {
    let _instance_epoch = strict_safe_integer(
        row.get_ref(0)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
    )?;
    let nonce = strict_blob(
        row.get_ref(1)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
        16,
    )?;
    let operation_id = strict_text(
        row.get_ref(2)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
    )?;
    let binding_digest = strict_blob(
        row.get_ref(3)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
        32,
    )?;
    let claim_id = strict_blob(
        row.get_ref(4)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
        32,
    )?;
    let claimant_generation = strict_safe_integer(
        row.get_ref(5)
            .map_err(|_| InternalStoreError::InvariantFailed)?,
    )?;

    if nonce.len() != 16
        || binding_digest.len() != 32
        || claim_id.len() != 32
        || operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:".contains(byte))
        || claimant_generation == 0
    {
        return Err(InternalStoreError::InvariantFailed);
    }
    Ok(ReplayClaimRow {
        claimant_generation,
    })
}

fn strict_safe_integer(value: ValueRef<'_>) -> Result<u64, InternalStoreError> {
    match value {
        ValueRef::Integer(value) if value >= 0 && value as u64 <= MAX_SAFE_U64 => Ok(value as u64),
        _ => Err(InternalStoreError::InvariantFailed),
    }
}

fn strict_blob(value: ValueRef<'_>, length: usize) -> Result<&[u8], InternalStoreError> {
    match value {
        ValueRef::Blob(value) if value.len() == length => Ok(value),
        _ => Err(InternalStoreError::InvariantFailed),
    }
}

fn strict_text(value: ValueRef<'_>) -> Result<&[u8], InternalStoreError> {
    match value {
        ValueRef::Text(value) => Ok(value),
        _ => Err(InternalStoreError::InvariantFailed),
    }
}

fn read_schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, InternalStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))?;
    let rows = statement
        .query_map([], |row| {
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))
}

fn pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, InternalStoreError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::SchemaInvalid))
}
