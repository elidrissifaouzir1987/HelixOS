//! Frozen PLAN-006 HLXA schema identity and reviewed object inventory.
//!
//! Initialization and admission verification are implemented by later PLAN-006
//! tasks. This module keeps their source of truth byte-exact: the reviewed SQL file
//! is embedded directly, its SHA-256 is pinned, and every named schema object is
//! inventoried for exact verification.

#![allow(dead_code)] // Foundation consumed by ordinary admission and story-specific writers.

use rusqlite::types::ValueRef;
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};
use std::fmt;

/// SQLite application identity `0x484c5841` (`HLXA`).
pub const TASK_AUTHORITY_STORE_APPLICATION_ID_V1: i64 = 1_212_962_881;
/// Published SQLite `user_version` for the first HLXA schema.
pub const TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1: i64 = 1;
/// Durable authority-store format version carried by typed metadata.
pub const TASK_AUTHORITY_STORE_FORMAT_VERSION_V1: i64 = 1;

/// Exact reviewed PLAN-006 authority-store SQL contract.
pub const TASK_AUTHORITY_STORE_SCHEMA_V1_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/006-durable-signed-task-authority/contracts/task-authority-store-schema-v1.sql"
));

/// SHA-256 of the exact embedded SQL bytes, including comments and final newline.
pub const TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256: [u8; 32] = [
    0xf2, 0xa1, 0x12, 0x44, 0x40, 0xc6, 0x8d, 0x50, 0xda, 0x60, 0xe6, 0x78, 0xc1, 0x6d, 0xab, 0xcc,
    0xfe, 0x05, 0x88, 0x04, 0x8e, 0xcc, 0x63, 0xd3, 0xcd, 0x7d, 0x30, 0x74, 0xbd, 0x92, 0xc5, 0xb8,
];
/// Lowercase hexadecimal form persisted in `authority_store_metadata`.
pub const TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX: &str =
    "f2a1124440c68d50da60e678c16dabccfe0588048ecc63d3cd7d3074bd92c5b8";

pub(crate) const TASK_AUTHORITY_STORE_DURABILITY_PROFILE_V1: &str =
    "WAL_FULL_CONTROLLED_CHECKPOINT_V1";
const MAX_SAFE_INTEGER_V1: u64 = 9_007_199_254_740_991;

/// Recomputes the embedded SQL digest so callers can detect source drift.
pub fn embedded_task_authority_store_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL.as_bytes()).into()
}

#[allow(dead_code)] // Consumed by the exact T020/T083 schema verifier.
pub(crate) const REQUIRED_TASK_AUTHORITY_TABLES_V1: &[&str] = &[
    "approval_decisions",
    "approval_plan_bindings",
    "authority_attempts",
    "authority_bootstrap_receipts",
    "authority_conflict_tombstones",
    "authority_events",
    "authority_key_status_events",
    "authority_restore_receipts",
    "authority_revocations",
    "authority_store_metadata",
    "authority_verification_keys",
    "human_grant_claims",
    "human_request_grants",
    "task_lease_allocations",
    "task_lease_counter_consumptions",
    "task_lease_usage",
    "task_leases",
];

#[allow(dead_code)] // Consumed by the exact T020/T083 schema verifier.
pub(crate) const REQUIRED_TASK_AUTHORITY_INDEXES_V1: &[(&str, &str)] = &[
    (
        "authority_key_status_by_key_generation",
        "authority_key_status_events",
    ),
    ("authority_revocations_by_subject", "authority_revocations"),
    ("task_leases_by_parent", "task_leases"),
    ("task_leases_by_source", "task_leases"),
];

#[allow(dead_code)] // Consumed by the exact T020/T083 schema verifier.
pub(crate) const REQUIRED_TASK_AUTHORITY_TRIGGERS_V1: &[(&str, &str)] = &[
    ("allocations_no_delete", "task_lease_allocations"),
    ("allocations_no_update", "task_lease_allocations"),
    ("attempts_no_delete", "authority_attempts"),
    ("attempts_no_update", "authority_attempts"),
    (
        "authority_metadata_monotonic_update",
        "authority_store_metadata",
    ),
    ("authority_metadata_no_delete", "authority_store_metadata"),
    (
        "bootstrap_receipts_no_delete",
        "authority_bootstrap_receipts",
    ),
    (
        "bootstrap_receipts_no_update",
        "authority_bootstrap_receipts",
    ),
    ("claims_no_delete", "human_grant_claims"),
    ("claims_no_update", "human_grant_claims"),
    ("conflicts_no_delete", "authority_conflict_tombstones"),
    ("conflicts_no_update", "authority_conflict_tombstones"),
    ("consumptions_no_delete", "task_lease_counter_consumptions"),
    ("consumptions_no_update", "task_lease_counter_consumptions"),
    ("decisions_no_delete", "approval_decisions"),
    ("decisions_no_update", "approval_decisions"),
    ("events_no_delete", "authority_events"),
    ("events_no_update", "authority_events"),
    ("grants_no_delete", "human_request_grants"),
    ("grants_no_update", "human_request_grants"),
    ("key_status_no_delete", "authority_key_status_events"),
    ("key_status_no_update", "authority_key_status_events"),
    ("leases_no_delete", "task_leases"),
    ("leases_no_update", "task_leases"),
    ("plans_no_delete", "approval_plan_bindings"),
    ("plans_no_update", "approval_plan_bindings"),
    ("restores_no_delete", "authority_restore_receipts"),
    ("restores_no_update", "authority_restore_receipts"),
    ("revocations_no_delete", "authority_revocations"),
    ("revocations_no_update", "authority_revocations"),
    ("task_lease_usage_monotonic_update", "task_lease_usage"),
    ("task_lease_usage_no_delete", "task_lease_usage"),
    ("verification_keys_no_delete", "authority_verification_keys"),
    ("verification_keys_no_update", "authority_verification_keys"),
];

#[allow(dead_code)] // Consumed by the exact T020/T083 schema verifier.
pub(crate) const TASK_AUTHORITY_STORE_REQUIRED_OBJECT_COUNT_V1: usize =
    REQUIRED_TASK_AUTHORITY_TABLES_V1.len()
        + REQUIRED_TASK_AUTHORITY_INDEXES_V1.len()
        + REQUIRED_TASK_AUTHORITY_TRIGGERS_V1.len();

/// Closed, payload-free failure from non-mutating HLXA admission verification.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TaskAuthoritySchemaAdmissionErrorV1 {
    ApplicationIdMismatch,
    SchemaUnsupported,
    SchemaInvalid,
    RootIdentityMismatch,
    LifecycleUnavailable,
    DurabilityProfileUnavailable,
    IntegrityFailed,
    InvariantFailed,
}

impl TaskAuthoritySchemaAdmissionErrorV1 {
    pub(crate) const fn code_v1(self) -> &'static str {
        match self {
            Self::ApplicationIdMismatch => "TASK_AUTHORITY_APPLICATION_ID_MISMATCH",
            Self::SchemaUnsupported => "TASK_AUTHORITY_SCHEMA_UNSUPPORTED",
            Self::SchemaInvalid => "TASK_AUTHORITY_SCHEMA_INVALID",
            Self::RootIdentityMismatch => "TASK_AUTHORITY_ROOT_IDENTITY_MISMATCH",
            Self::LifecycleUnavailable => "TASK_AUTHORITY_LIFECYCLE_UNAVAILABLE",
            Self::DurabilityProfileUnavailable => "TASK_AUTHORITY_DURABILITY_PROFILE_UNAVAILABLE",
            Self::IntegrityFailed => "TASK_AUTHORITY_INTEGRITY_FAILED",
            Self::InvariantFailed => "TASK_AUTHORITY_INVARIANT_FAILED",
        }
    }
}

impl fmt::Debug for TaskAuthoritySchemaAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for TaskAuthoritySchemaAdmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl std::error::Error for TaskAuthoritySchemaAdmissionErrorV1 {}

#[derive(Clone, PartialEq, Eq)]
struct SchemaObjectV1 {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Clone, Copy)]
struct AuthorityStoreMetadataV1 {
    store_generation: u64,
    trust_generation: u64,
    grant_generation: u64,
    lease_generation: u64,
    allocation_generation: u64,
    counter_generation: u64,
    decision_generation: u64,
    revocation_generation: u64,
    event_generation: u64,
    migration_generation: u64,
    backup_generation: u64,
    restore_generation: u64,
}

/// Performs strict, read-only admission of one already-published HLXA v1 root.
///
/// The caller supplies the provisioner-bound opaque root identity. This function
/// never initializes, repairs, migrates, downgrades, updates, or backfills the target
/// connection. `RESTORE_PENDING` is intentionally not ordinary-open authority.
pub(crate) fn verify_admission_v1(
    connection: &Connection,
    expected_root_id: &str,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    if expected_root_id.is_empty() || expected_root_id.len() > 128 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::RootIdentityMismatch);
    }

    verify_embedded_schema_digest_v1()?;
    verify_application_and_version_v1(connection)?;
    verify_exact_schema_v1(connection)?;
    verify_durability_pragmas_v1(connection)?;
    let metadata = decode_metadata_v1(connection, expected_root_id)?;
    verify_integrity_check_v1(connection)?;
    verify_foreign_key_check_v1(connection)?;
    verify_generation_high_water_v1(connection, metadata)?;
    verify_cross_record_invariants_v1(connection)?;
    Ok(())
}

fn verify_embedded_schema_digest_v1() -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    if embedded_task_authority_store_schema_v1_sha256() != TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid);
    }
    Ok(())
}

fn verify_application_and_version_v1(
    connection: &Connection,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    let application_id = pragma_i64_v1(connection, "application_id")?;
    if application_id != TASK_AUTHORITY_STORE_APPLICATION_ID_V1 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::ApplicationIdMismatch);
    }
    let user_version = pragma_i64_v1(connection, "user_version")?;
    if user_version > TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaUnsupported);
    }
    if user_version != TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid);
    }
    Ok(())
}

fn verify_exact_schema_v1(
    connection: &Connection,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    let actual = read_schema_objects_v1(connection)?;
    let expected_connection = Connection::open_in_memory()
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)?;
    expected_connection
        .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)?;
    let expected = read_schema_objects_v1(&expected_connection)?;
    if actual != expected || actual.len() != TASK_AUTHORITY_STORE_REQUIRED_OBJECT_COUNT_V1 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid);
    }
    Ok(())
}

fn verify_durability_pragmas_v1(
    connection: &Connection,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable)?;
    let pragma = |name| {
        connection
            .pragma_query_value(None, name, |row| row.get::<_, i64>(0))
            .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable)
    };
    if !journal_mode.eq_ignore_ascii_case("wal")
        || pragma("synchronous")? != 2
        || pragma("foreign_keys")? != 1
        || pragma("recursive_triggers")? != 1
        || pragma("trusted_schema")? != 0
        || pragma("cell_size_check")? != 1
        || pragma("wal_autocheckpoint")? != 0
    {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable);
    }
    Ok(())
}

fn decode_metadata_v1(
    connection: &Connection,
    expected_root_id: &str,
) -> Result<AuthorityStoreMetadataV1, TaskAuthoritySchemaAdmissionErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT singleton_id, application_id, schema_version, schema_digest, root_id, \
                    lifecycle, durability_profile, boot_id, instance_epoch, fencing_epoch, \
                    restore_epoch, ordinary_capacity, control_capacity, store_generation, \
                    trust_generation, grant_generation, lease_generation, \
                    allocation_generation, counter_generation, decision_generation, \
                    revocation_generation, event_generation, migration_generation, \
                    backup_generation, restore_generation, created_at_utc_ms, \
                    bootstrap_receipt_id, restore_receipt_id \
             FROM main.authority_store_metadata",
        )
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?;
    let row = rows
        .next()
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?
        .ok_or(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?;

    let singleton_id = strict_safe_integer_v1(row.get_ref(0).map_err(invariant_v1)?)?;
    let application_id = strict_safe_integer_v1(row.get_ref(1).map_err(invariant_v1)?)?;
    let schema_version = strict_safe_integer_v1(row.get_ref(2).map_err(invariant_v1)?)?;
    let schema_digest = strict_text_v1(row.get_ref(3).map_err(invariant_v1)?)?.to_owned();
    let root_id = strict_text_v1(row.get_ref(4).map_err(invariant_v1)?)?.to_owned();
    let lifecycle = strict_text_v1(row.get_ref(5).map_err(invariant_v1)?)?.to_owned();
    let durability_profile = strict_text_v1(row.get_ref(6).map_err(invariant_v1)?)?.to_owned();
    let boot_id = strict_text_v1(row.get_ref(7).map_err(invariant_v1)?)?.to_owned();
    let instance_epoch = strict_safe_integer_v1(row.get_ref(8).map_err(invariant_v1)?)?;
    let fencing_epoch = strict_safe_integer_v1(row.get_ref(9).map_err(invariant_v1)?)?;
    let restore_epoch = strict_safe_integer_v1(row.get_ref(10).map_err(invariant_v1)?)?;
    let ordinary_capacity = strict_safe_integer_v1(row.get_ref(11).map_err(invariant_v1)?)?;
    let control_capacity = strict_safe_integer_v1(row.get_ref(12).map_err(invariant_v1)?)?;
    let store_generation = strict_safe_integer_v1(row.get_ref(13).map_err(invariant_v1)?)?;
    let trust_generation = strict_safe_integer_v1(row.get_ref(14).map_err(invariant_v1)?)?;
    let grant_generation = strict_safe_integer_v1(row.get_ref(15).map_err(invariant_v1)?)?;
    let lease_generation = strict_safe_integer_v1(row.get_ref(16).map_err(invariant_v1)?)?;
    let allocation_generation = strict_safe_integer_v1(row.get_ref(17).map_err(invariant_v1)?)?;
    let counter_generation = strict_safe_integer_v1(row.get_ref(18).map_err(invariant_v1)?)?;
    let decision_generation = strict_safe_integer_v1(row.get_ref(19).map_err(invariant_v1)?)?;
    let revocation_generation = strict_safe_integer_v1(row.get_ref(20).map_err(invariant_v1)?)?;
    let event_generation = strict_safe_integer_v1(row.get_ref(21).map_err(invariant_v1)?)?;
    let migration_generation = strict_safe_integer_v1(row.get_ref(22).map_err(invariant_v1)?)?;
    let backup_generation = strict_safe_integer_v1(row.get_ref(23).map_err(invariant_v1)?)?;
    let restore_generation = strict_safe_integer_v1(row.get_ref(24).map_err(invariant_v1)?)?;
    let _created_at_utc_ms = strict_safe_integer_v1(row.get_ref(25).map_err(invariant_v1)?)?;
    let bootstrap_receipt_id = strict_text_v1(row.get_ref(26).map_err(invariant_v1)?)?.to_owned();
    let restore_receipt_id =
        optional_strict_text_v1(row.get_ref(27).map_err(invariant_v1)?)?.map(str::to_owned);

    if rows
        .next()
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?
        .is_some()
        || singleton_id != 1
        || root_id.is_empty()
        || root_id.len() > 128
        || boot_id.is_empty()
        || boot_id.len() > 128
        || bootstrap_receipt_id.len() != 64
        || store_generation == 0
        || instance_epoch == 0
        || fencing_epoch == 0
    {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed);
    }
    if application_id != TASK_AUTHORITY_STORE_APPLICATION_ID_V1 as u64 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::ApplicationIdMismatch);
    }
    if schema_version != TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1 as u64
        || schema_digest != TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX
    {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid);
    }
    if root_id != expected_root_id {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::RootIdentityMismatch);
    }
    if durability_profile != TASK_AUTHORITY_STORE_DURABILITY_PROFILE_V1 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable);
    }
    if ordinary_capacity != 1_024 || control_capacity != 32 {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed);
    }
    let positive_generations = [
        trust_generation,
        grant_generation,
        lease_generation,
        allocation_generation,
        counter_generation,
        decision_generation,
        revocation_generation,
        event_generation,
        migration_generation,
    ];
    if positive_generations
        .iter()
        .any(|generation| *generation == 0 || *generation > store_generation)
        || backup_generation > store_generation
        || restore_generation > store_generation
        || restore_epoch > store_generation
    {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed);
    }
    match lifecycle.as_str() {
        "ACTIVE"
            if restore_epoch == 0 && restore_generation == 0 && restore_receipt_id.is_none() => {}
        "RESTORE_PENDING" => return Err(TaskAuthoritySchemaAdmissionErrorV1::LifecycleUnavailable),
        _ => return Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed),
    }

    Ok(AuthorityStoreMetadataV1 {
        store_generation,
        trust_generation,
        grant_generation,
        lease_generation,
        allocation_generation,
        counter_generation,
        decision_generation,
        revocation_generation,
        event_generation,
        migration_generation,
        backup_generation,
        restore_generation,
    })
}

fn verify_integrity_check_v1(
    connection: &Connection,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    let mut statement = connection
        .prepare("PRAGMA main.integrity_check")
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed)?;
    let first = rows
        .next()
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed)?
        .ok_or(TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed)?;
    let result: String = first
        .get(0)
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed)?;
    if result != "ok"
        || rows
            .next()
            .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed)?
            .is_some()
    {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed);
    }
    Ok(())
}

fn verify_foreign_key_check_v1(
    connection: &Connection,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    let mut statement = connection
        .prepare("PRAGMA main.foreign_key_check")
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?;
    if statement
        .query([])
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?
        .next()
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?
        .is_some()
    {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed);
    }
    Ok(())
}

fn verify_generation_high_water_v1(
    connection: &Connection,
    metadata: AuthorityStoreMetadataV1,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    let trust = [
        maximum_generation_v1(
            connection,
            "authority_verification_keys",
            "introduced_generation",
            1,
        )?,
        maximum_generation_v1(
            connection,
            "authority_key_status_events",
            "trust_generation",
            1,
        )?,
    ];
    let grant = [
        maximum_generation_v1(connection, "human_request_grants", "retained_generation", 1)?,
        maximum_generation_v1(connection, "human_grant_claims", "claim_generation", 1)?,
    ];
    let allocation = [
        maximum_generation_v1(
            connection,
            "task_lease_allocations",
            "created_generation",
            1,
        )?,
        maximum_generation_v1(connection, "task_lease_usage", "allocation_generation", 1)?,
    ];
    let counter = [
        maximum_generation_v1(
            connection,
            "task_lease_counter_consumptions",
            "created_generation",
            1,
        )?,
        maximum_generation_v1(connection, "task_lease_usage", "counter_generation", 1)?,
    ];
    let exact = [
        (
            metadata.store_generation,
            maximum_generation_v1(connection, "authority_attempts", "attempt_generation", 1)?,
        ),
        (metadata.trust_generation, maximum_v1(&trust)),
        (metadata.grant_generation, maximum_v1(&grant)),
        (
            metadata.lease_generation,
            maximum_generation_v1(connection, "task_leases", "created_generation", 1)?,
        ),
        (metadata.allocation_generation, maximum_v1(&allocation)),
        (metadata.counter_generation, maximum_v1(&counter)),
        (
            metadata.decision_generation,
            maximum_generation_v1(connection, "approval_decisions", "created_generation", 1)?,
        ),
        (
            metadata.revocation_generation,
            maximum_generation_v1(connection, "authority_revocations", "created_generation", 1)?,
        ),
        (
            metadata.event_generation,
            maximum_generation_v1(connection, "authority_events", "event_generation", 1)?,
        ),
        (
            metadata.migration_generation,
            maximum_generation_v1(
                connection,
                "authority_bootstrap_receipts",
                "migration_generation",
                1,
            )?,
        ),
    ];
    if exact
        .iter()
        .any(|(retained, observed)| retained != observed)
        || metadata.backup_generation > metadata.store_generation
        || metadata.restore_generation > metadata.store_generation
    {
        return Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed);
    }
    Ok(())
}

fn verify_cross_record_invariants_v1(
    connection: &Connection,
) -> Result<(), TaskAuthoritySchemaAdmissionErrorV1> {
    for query in CROSS_RECORD_ANOMALY_QUERIES_V1 {
        let anomaly_count: i64 = connection
            .query_row(query, [], |row| row.get(0))
            .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?;
        if anomaly_count != 0 {
            return Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed);
        }
    }
    Ok(())
}

const CROSS_RECORD_ANOMALY_QUERIES_V1: &[&str] = &[
    r#"SELECT COUNT(*)
       FROM main.authority_attempts AS attempt
       LEFT JOIN main.authority_events AS event
         ON event.event_id = attempt.event_id
        AND event.attempt_id = attempt.attempt_id
       WHERE event.event_id IS NULL
          OR event.event_generation <> attempt.attempt_generation
          OR event.result_code <> attempt.outcome_code
          OR CASE
               WHEN attempt.outcome_code = 'CONFLICT_RETAINED'
                 THEN event.event_kind <> 'CONFLICT_RETAINED'
               WHEN attempt.operation_kind = 'BOOTSTRAP'
                 THEN event.event_kind <> 'BOOTSTRAP_COMPLETED'
               WHEN attempt.operation_kind = 'KEY_STATUS_CHANGE'
                 THEN event.event_kind <> 'KEY_STATUS_CHANGED'
               WHEN attempt.operation_kind = 'ROOT_LEASE_ISSUE'
                 THEN event.event_kind <> 'ROOT_LEASE_ISSUED'
               WHEN attempt.operation_kind = 'CHILD_LEASE_ISSUE'
                 THEN event.event_kind <> 'CHILD_LEASE_ISSUED'
               WHEN attempt.operation_kind = 'COUNTER_CONSUME'
                 THEN event.event_kind <> 'COUNTER_CONSUMED'
               WHEN attempt.operation_kind = 'DECISION_RETAIN'
                 THEN event.event_kind <> 'DECISION_RETAINED'
               WHEN attempt.operation_kind = 'AUTHORITY_REVOKE'
                 THEN event.event_kind <> 'AUTHORITY_REVOKED'
               WHEN attempt.operation_kind = 'BACKUP_PUBLISH'
                 THEN event.event_kind <> 'BACKUP_PUBLISHED'
               WHEN attempt.operation_kind = 'RESTORE_PUBLISH'
                 THEN event.event_kind <> 'RESTORE_PUBLISHED'
               ELSE 1
             END"#,
    r#"SELECT COUNT(*)
       FROM main.authority_events AS event
       WHERE NOT EXISTS (
           SELECT 1 FROM main.authority_attempts AS attempt
           WHERE attempt.attempt_id = event.attempt_id
             AND attempt.event_id = event.event_id
             AND attempt.attempt_generation = event.event_generation
       )"#,
    r#"SELECT COUNT(*)
       FROM main.authority_attempts AS attempt
       WHERE (attempt.outcome_code = 'CONFLICT_RETAINED' AND NOT EXISTS (
                 SELECT 1 FROM main.authority_conflict_tombstones AS conflict
                 WHERE conflict.attempt_id = attempt.attempt_id
                   AND conflict.event_id = attempt.event_id
             ))
          OR (attempt.outcome_code = 'COMMITTED_RETAINED' AND CASE attempt.operation_kind
                 WHEN 'BOOTSTRAP' THEN NOT EXISTS (
                     SELECT 1 FROM main.authority_bootstrap_receipts AS receipt
                     WHERE receipt.bootstrap_attempt_id = attempt.attempt_id)
                 WHEN 'KEY_STATUS_CHANGE' THEN NOT EXISTS (
                     SELECT 1 FROM main.authority_key_status_events AS status
                     WHERE status.attempt_id = attempt.attempt_id
                       AND status.event_id = attempt.event_id)
                 WHEN 'ROOT_LEASE_ISSUE' THEN NOT EXISTS (
                     SELECT 1 FROM main.task_leases AS lease
                     JOIN main.human_grant_claims AS claim
                       ON claim.claim_attempt_id = attempt.attempt_id
                      AND claim.root_lease_issuer_id = lease.lease_issuer_id
                      AND claim.root_lease_id = lease.lease_id
                     WHERE lease.creation_attempt_id = attempt.attempt_id
                       AND lease.delegation_depth = 0)
                 WHEN 'CHILD_LEASE_ISSUE' THEN NOT EXISTS (
                     SELECT 1 FROM main.task_lease_allocations AS allocation
                     JOIN main.task_leases AS lease
                       ON lease.creation_attempt_id = attempt.attempt_id
                      AND lease.parent_allocation_id = allocation.allocation_id
                     WHERE allocation.allocation_attempt_id = attempt.attempt_id
                       AND allocation.event_id = attempt.event_id)
                 WHEN 'COUNTER_CONSUME' THEN NOT EXISTS (
                     SELECT 1 FROM main.task_lease_counter_consumptions AS consumption
                     WHERE consumption.consumption_attempt_id = attempt.attempt_id
                       AND consumption.event_id = attempt.event_id)
                 WHEN 'DECISION_RETAIN' THEN NOT EXISTS (
                     SELECT 1 FROM main.approval_decisions AS decision
                     WHERE decision.creation_attempt_id = attempt.attempt_id
                       AND decision.event_id = attempt.event_id)
                 WHEN 'AUTHORITY_REVOKE' THEN NOT EXISTS (
                     SELECT 1 FROM main.authority_revocations AS revocation
                     WHERE revocation.revocation_attempt_id = attempt.attempt_id
                       AND revocation.event_id = attempt.event_id)
                 WHEN 'BACKUP_PUBLISH' THEN 0
                 WHEN 'RESTORE_PUBLISH' THEN NOT EXISTS (
                     SELECT 1 FROM main.authority_restore_receipts AS restore
                     WHERE restore.restore_attempt_id = attempt.attempt_id
                       AND restore.event_id = attempt.event_id)
                 ELSE 1
              END)
          OR (attempt.outcome_code = 'RESTORE_PENDING' AND NOT EXISTS (
                 SELECT 1 FROM main.authority_restore_receipts AS restore
                 WHERE restore.restore_attempt_id = attempt.attempt_id
                   AND restore.event_id = attempt.event_id
             ))"#,
    r#"SELECT COUNT(*)
       FROM main.authority_store_metadata AS metadata
       WHERE NOT EXISTS (
           SELECT 1
           FROM main.authority_bootstrap_receipts AS receipt
           JOIN main.authority_attempts AS attempt
             ON attempt.attempt_id = receipt.bootstrap_attempt_id
           JOIN main.authority_events AS event
             ON event.event_id = attempt.event_id
            AND event.attempt_id = attempt.attempt_id
           WHERE receipt.bootstrap_receipt_id = metadata.bootstrap_receipt_id
             AND receipt.target_root_id = metadata.root_id
             AND receipt.target_schema_digest = metadata.schema_digest
             AND receipt.source_application_id = 1212962883
             AND receipt.source_user_version = 2
             AND receipt.imported_grant_count = 0
             AND receipt.imported_lease_count = 0
             AND receipt.imported_decision_count = 0
             AND receipt.migration_generation = metadata.migration_generation
             AND attempt.operation_kind = 'BOOTSTRAP'
             AND attempt.attempt_generation = receipt.migration_generation
             AND event.event_kind = 'BOOTSTRAP_COMPLETED'
             AND event.event_generation = receipt.migration_generation
       )
          OR metadata.restore_receipt_id IS NOT NULL
          OR EXISTS (SELECT 1 FROM main.authority_restore_receipts)"#,
    r#"SELECT COUNT(*) FROM (
           SELECT key.key_id
           FROM main.authority_verification_keys AS key
           WHERE NOT EXISTS (
               SELECT 1 FROM main.authority_key_status_events AS status
               WHERE status.key_purpose = key.key_purpose
                 AND status.key_id = key.key_id
           )
           UNION ALL
           SELECT status.key_status_event_id
           FROM main.authority_key_status_events AS status
           JOIN main.authority_attempts AS attempt ON attempt.attempt_id = status.attempt_id
           WHERE attempt.operation_kind <> 'KEY_STATUS_CHANGE'
              OR attempt.event_id <> status.event_id
           UNION ALL
           SELECT grant.grant_id
           FROM main.human_request_grants AS grant
           JOIN main.authority_verification_keys AS key
             ON key.key_purpose = grant.key_purpose AND key.key_id = grant.key_id
           WHERE grant.key_fingerprint <> key.public_key_fingerprint
              OR NOT EXISTS (
                  SELECT 1 FROM main.human_grant_claims AS claim
                  WHERE claim.grant_issuer_id = grant.grant_issuer_id
                    AND claim.grant_id = grant.grant_id
              )
           UNION ALL
           SELECT claim.grant_id
           FROM main.human_grant_claims AS claim
           JOIN main.human_request_grants AS grant
             ON grant.grant_issuer_id = claim.grant_issuer_id AND grant.grant_id = claim.grant_id
           JOIN main.task_leases AS lease
             ON lease.lease_issuer_id = claim.root_lease_issuer_id
            AND lease.lease_id = claim.root_lease_id
           JOIN main.authority_attempts AS attempt ON attempt.attempt_id = claim.claim_attempt_id
           WHERE claim.grant_digest <> grant.grant_digest
              OR claim.root_lease_digest <> lease.lease_digest
              OR lease.delegation_depth <> 0
              OR lease.source_grant_issuer_id <> grant.grant_issuer_id
              OR lease.source_grant_id <> grant.grant_id
              OR lease.source_grant_digest <> grant.grant_digest
              OR lease.creation_attempt_id <> claim.claim_attempt_id
              OR attempt.operation_kind <> 'ROOT_LEASE_ISSUE'
              OR attempt.event_id <> claim.event_id
       )"#,
    r#"SELECT COUNT(*) FROM (
           SELECT lease.lease_id
           FROM main.task_leases AS lease
           JOIN main.authority_verification_keys AS key
             ON key.key_purpose = lease.key_purpose AND key.key_id = lease.key_id
           JOIN main.human_request_grants AS grant
             ON grant.grant_issuer_id = lease.source_grant_issuer_id
            AND grant.grant_id = lease.source_grant_id
           WHERE lease.key_fingerprint <> key.public_key_fingerprint
              OR lease.source_grant_digest <> grant.grant_digest
              OR NOT EXISTS (
                  SELECT 1 FROM main.task_lease_usage AS usage
                  WHERE usage.lease_issuer_id = lease.lease_issuer_id
                    AND usage.lease_id = lease.lease_id
              )
              OR (lease.delegation_depth = 0 AND NOT EXISTS (
                  SELECT 1 FROM main.human_grant_claims AS claim
                  WHERE claim.root_lease_issuer_id = lease.lease_issuer_id
                    AND claim.root_lease_id = lease.lease_id
              ))
              OR (lease.delegation_depth > 0 AND NOT EXISTS (
                  SELECT 1
                  FROM main.task_leases AS parent
                  JOIN main.task_lease_allocations AS allocation
                    ON allocation.allocation_id = lease.parent_allocation_id
                   AND allocation.parent_lease_issuer_id = parent.lease_issuer_id
                   AND allocation.parent_lease_id = parent.lease_id
                   AND allocation.child_lease_issuer_id = lease.lease_issuer_id
                   AND allocation.child_lease_id = lease.lease_id
                  WHERE parent.lease_issuer_id = lease.parent_lease_issuer_id
                    AND parent.lease_id = lease.parent_lease_id
                    AND parent.lease_digest = lease.parent_lease_digest
                    AND parent.delegation_depth + 1 = lease.delegation_depth
                    AND parent.source_grant_issuer_id = lease.source_grant_issuer_id
                    AND parent.source_grant_id = lease.source_grant_id
                    AND parent.task_id = lease.task_id
                    AND parent.workload_id = lease.workload_id
              ))
           UNION ALL
           SELECT allocation.allocation_id
           FROM main.task_lease_allocations AS allocation
           JOIN main.task_leases AS parent
             ON parent.lease_issuer_id = allocation.parent_lease_issuer_id
            AND parent.lease_id = allocation.parent_lease_id
           JOIN main.task_leases AS child
             ON child.lease_issuer_id = allocation.child_lease_issuer_id
            AND child.lease_id = allocation.child_lease_id
           JOIN main.authority_attempts AS attempt
             ON attempt.attempt_id = allocation.allocation_attempt_id
           WHERE allocation.parent_lease_digest <> parent.lease_digest
              OR allocation.child_lease_digest <> child.lease_digest
              OR child.parent_allocation_id <> allocation.allocation_id
              OR child.creation_attempt_id <> allocation.allocation_attempt_id
              OR attempt.operation_kind <> 'CHILD_LEASE_ISSUE'
              OR attempt.event_id <> allocation.event_id
           UNION ALL
           SELECT consumption.consumption_id
           FROM main.task_lease_counter_consumptions AS consumption
           JOIN main.task_leases AS lease
             ON lease.lease_issuer_id = consumption.lease_issuer_id
            AND lease.lease_id = consumption.lease_id
           JOIN main.authority_attempts AS attempt
             ON attempt.attempt_id = consumption.consumption_attempt_id
           WHERE consumption.lease_digest <> lease.lease_digest
              OR attempt.operation_kind <> 'COUNTER_CONSUME'
              OR attempt.event_id <> consumption.event_id
       )"#,
    r#"SELECT COUNT(*)
       FROM main.task_lease_usage AS usage
       WHERE usage.allocated_read_bytes <> COALESCE((
                 SELECT SUM(allocation.allocated_read_bytes)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.allocated_distinct_files <> COALESCE((
                 SELECT SUM(allocation.allocated_distinct_files)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.allocated_actions <> COALESCE((
                 SELECT SUM(allocation.allocated_actions)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.allocated_egress_bytes <> COALESCE((
                 SELECT SUM(allocation.allocated_egress_bytes)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.allocated_cost_micro_units <> COALESCE((
                 SELECT SUM(allocation.allocated_cost_micro_units)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.allocated_plans <> COALESCE((
                 SELECT SUM(allocation.allocated_plans)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.allocated_approvals <> COALESCE((
                 SELECT SUM(allocation.allocated_approvals)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.allocated_child_leases <> COALESCE((
                 SELECT SUM(allocation.allocated_child_leases)
                 FROM main.task_lease_allocations AS allocation
                 WHERE allocation.parent_lease_issuer_id = usage.lease_issuer_id
                   AND allocation.parent_lease_id = usage.lease_id), 0)
          OR usage.consumed_read_bytes <> COALESCE((
                 SELECT SUM(consumption.amount)
                 FROM main.task_lease_counter_consumptions AS consumption
                 WHERE consumption.lease_issuer_id = usage.lease_issuer_id
                   AND consumption.lease_id = usage.lease_id
                   AND consumption.counter_kind = 'READ_BYTES'), 0)
          OR usage.consumed_distinct_files <> COALESCE((
                 SELECT SUM(consumption.amount)
                 FROM main.task_lease_counter_consumptions AS consumption
                 WHERE consumption.lease_issuer_id = usage.lease_issuer_id
                   AND consumption.lease_id = usage.lease_id
                   AND consumption.counter_kind = 'DISTINCT_FILES'), 0)
          OR usage.consumed_actions <> COALESCE((
                 SELECT SUM(consumption.amount)
                 FROM main.task_lease_counter_consumptions AS consumption
                 WHERE consumption.lease_issuer_id = usage.lease_issuer_id
                   AND consumption.lease_id = usage.lease_id
                   AND consumption.counter_kind = 'ACTIONS'), 0)
          OR usage.consumed_plans <> COALESCE((
                 SELECT SUM(consumption.amount)
                 FROM main.task_lease_counter_consumptions AS consumption
                 WHERE consumption.lease_issuer_id = usage.lease_issuer_id
                   AND consumption.lease_id = usage.lease_id
                   AND consumption.counter_kind = 'PLANS'), 0)
          OR usage.consumed_approvals <> COALESCE((
                 SELECT SUM(consumption.amount)
                 FROM main.task_lease_counter_consumptions AS consumption
                 WHERE consumption.lease_issuer_id = usage.lease_issuer_id
                   AND consumption.lease_id = usage.lease_id
                   AND consumption.counter_kind = 'APPROVALS'), 0)"#,
    r#"SELECT COUNT(*) FROM (
           SELECT plan.plan_id
           FROM main.approval_plan_bindings AS plan
           JOIN main.human_request_grants AS grant
             ON grant.grant_issuer_id = plan.grant_issuer_id AND grant.grant_id = plan.grant_id
           JOIN main.task_leases AS lease
             ON lease.lease_issuer_id = plan.leaf_lease_issuer_id
            AND lease.lease_id = plan.leaf_lease_id
           WHERE plan.grant_digest <> grant.grant_digest
              OR plan.leaf_lease_digest <> lease.lease_digest
              OR plan.grant_issuer_id <> lease.source_grant_issuer_id
              OR plan.grant_id <> lease.source_grant_id
              OR plan.task_id <> lease.task_id
              OR plan.workload_id <> lease.workload_id
              OR NOT EXISTS (
                  SELECT 1 FROM main.approval_decisions AS decision
                  WHERE decision.plan_id = plan.plan_id
              )
           UNION ALL
           SELECT decision.decision_id
           FROM main.approval_decisions AS decision
           JOIN main.approval_plan_bindings AS plan ON plan.plan_id = decision.plan_id
           JOIN main.authority_verification_keys AS key
             ON key.key_purpose = decision.key_purpose AND key.key_id = decision.key_id
           JOIN main.authority_attempts AS attempt
             ON attempt.attempt_id = decision.creation_attempt_id
           WHERE decision.plan_envelope_digest <> plan.plan_envelope_digest
              OR decision.key_fingerprint <> key.public_key_fingerprint
              OR attempt.operation_kind <> 'DECISION_RETAIN'
              OR attempt.event_id <> decision.event_id
       )"#,
    r#"SELECT COUNT(*) FROM (
           SELECT revocation.revocation_id
           FROM main.authority_revocations AS revocation
           JOIN main.authority_attempts AS attempt
             ON attempt.attempt_id = revocation.revocation_attempt_id
           WHERE attempt.operation_kind <> 'AUTHORITY_REVOKE'
              OR attempt.event_id <> revocation.event_id
           UNION ALL
           SELECT conflict.conflict_id
           FROM main.authority_conflict_tombstones AS conflict
           JOIN main.authority_attempts AS attempt ON attempt.attempt_id = conflict.attempt_id
           WHERE attempt.outcome_code <> 'CONFLICT_RETAINED'
              OR attempt.event_id <> conflict.event_id
           UNION ALL
           SELECT restore.restore_receipt_id
           FROM main.authority_restore_receipts AS restore
           JOIN main.authority_attempts AS attempt
             ON attempt.attempt_id = restore.restore_attempt_id
           WHERE attempt.operation_kind <> 'RESTORE_PUBLISH'
              OR attempt.event_id <> restore.event_id
       )"#,
    r#"SELECT COUNT(*)
       FROM main.authority_events AS event
       WHERE (event.event_generation = (
                  SELECT MIN(first_event.event_generation) FROM main.authority_events AS first_event
              ) AND event.previous_event_digest IS NOT NULL)
          OR (event.event_generation > (
                  SELECT MIN(first_event.event_generation) FROM main.authority_events AS first_event
              ) AND event.previous_event_digest IS NOT (
                  SELECT previous.event_digest
                  FROM main.authority_events AS previous
                  WHERE previous.event_generation < event.event_generation
                  ORDER BY previous.event_generation DESC LIMIT 1
              ))"#,
];

fn read_schema_objects_v1(
    connection: &Connection,
) -> Result<Vec<SchemaObjectV1>, TaskAuthoritySchemaAdmissionErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM main.sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
        )
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)?;
    let objects = statement
        .query_map([], |row| {
            Ok(SchemaObjectV1 {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)?;
    Ok(objects)
}

fn pragma_i64_v1(
    connection: &Connection,
    pragma: &str,
) -> Result<i64, TaskAuthoritySchemaAdmissionErrorV1> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)
}

fn maximum_generation_v1(
    connection: &Connection,
    table: &str,
    column: &str,
    empty_value: u64,
) -> Result<u64, TaskAuthoritySchemaAdmissionErrorV1> {
    let query = format!("SELECT COALESCE(MAX({column}), ?1) FROM main.{table}");
    let empty_value = i64::try_from(empty_value)
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?;
    let value: i64 = connection
        .query_row(&query, [empty_value], |row| row.get(0))
        .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)?;
    safe_i64_v1(value)
}

fn maximum_v1(values: &[u64]) -> u64 {
    values.iter().copied().max().unwrap_or(0)
}

fn strict_safe_integer_v1(value: ValueRef<'_>) -> Result<u64, TaskAuthoritySchemaAdmissionErrorV1> {
    match value {
        ValueRef::Integer(value) => safe_i64_v1(value),
        _ => Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed),
    }
}

fn safe_i64_v1(value: i64) -> Result<u64, TaskAuthoritySchemaAdmissionErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_INTEGER_V1)
        .ok_or(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)
}

fn strict_text_v1(value: ValueRef<'_>) -> Result<&str, TaskAuthoritySchemaAdmissionErrorV1> {
    match value {
        ValueRef::Text(value) => std::str::from_utf8(value)
            .map_err(|_| TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed),
        _ => Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed),
    }
}

fn optional_strict_text_v1(
    value: ValueRef<'_>,
) -> Result<Option<&str>, TaskAuthoritySchemaAdmissionErrorV1> {
    match value {
        ValueRef::Null => Ok(None),
        _ => strict_text_v1(value).map(Some),
    }
}

fn invariant_v1(_: rusqlite::Error) -> TaskAuthoritySchemaAdmissionErrorV1 {
    TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const FIXTURE_ROOT_ID: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Copy)]
    struct FixtureOptions<'a> {
        metadata_schema_digest: &'a str,
        receipt_target_schema_digest: &'a str,
        lifecycle: &'a str,
        durability_profile: &'a str,
        ordinary_capacity: i64,
        control_capacity: i64,
        attempt_event_generation: i64,
        insert_metadata: bool,
    }

    impl Default for FixtureOptions<'_> {
        fn default() -> Self {
            Self {
                metadata_schema_digest: TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                receipt_target_schema_digest: TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                lifecycle: "ACTIVE",
                durability_profile: TASK_AUTHORITY_STORE_DURABILITY_PROFILE_V1,
                ordinary_capacity: 1_024,
                control_capacity: 32,
                attempt_event_generation: 1,
                insert_metadata: true,
            }
        }
    }

    struct TestStore {
        connection: Option<Connection>,
        path: PathBuf,
    }

    impl TestStore {
        fn connection(&self) -> &Connection {
            self.connection
                .as_ref()
                .expect("fixture connection present")
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            drop(self.connection.take());
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
        }
    }

    #[test]
    fn embedded_contract_has_exact_pinned_identity_and_digest() {
        assert_eq!(TASK_AUTHORITY_STORE_APPLICATION_ID_V1, 0x484c_5841);
        assert_eq!(TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1, 1);
        assert_eq!(TASK_AUTHORITY_STORE_FORMAT_VERSION_V1, 1);
        assert_eq!(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL.len(), 39_437);
        assert!(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL.ends_with('\n'));
        assert_eq!(
            embedded_task_authority_store_schema_v1_sha256(),
            TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256
        );
    }

    #[test]
    fn reviewed_contract_executes_with_exact_identity_and_object_inventory() {
        let connection = Connection::open_in_memory().expect("in-memory SQLite opens");
        connection
            .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
            .expect("reviewed HLXA schema executes");

        let application_id: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .expect("application_id reads");
        let user_version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("user_version reads");
        assert_eq!(application_id, TASK_AUTHORITY_STORE_APPLICATION_ID_V1);
        assert_eq!(user_version, TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1);

        assert_eq!(
            named_schema_tables(&connection),
            REQUIRED_TASK_AUTHORITY_TABLES_V1
        );
        assert_eq!(
            named_schema_objects(&connection, "index"),
            owned_schema_objects(REQUIRED_TASK_AUTHORITY_INDEXES_V1)
        );
        assert_eq!(
            named_schema_objects(&connection, "trigger"),
            owned_schema_objects(REQUIRED_TASK_AUTHORITY_TRIGGERS_V1)
        );
        assert_eq!(
            REQUIRED_TASK_AUTHORITY_TABLES_V1.len(),
            17,
            "required table inventory drifted"
        );
        assert_eq!(
            REQUIRED_TASK_AUTHORITY_INDEXES_V1.len(),
            4,
            "required named-index inventory drifted"
        );
        assert_eq!(
            REQUIRED_TASK_AUTHORITY_TRIGGERS_V1.len(),
            34,
            "required trigger inventory drifted"
        );
        assert_eq!(TASK_AUTHORITY_STORE_REQUIRED_OBJECT_COUNT_V1, 55);
    }

    #[test]
    fn every_reviewed_authority_table_is_strict() {
        let connection = Connection::open_in_memory().expect("in-memory SQLite opens");
        connection
            .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
            .expect("reviewed HLXA schema executes");
        let mut statement = connection
            .prepare(
                "SELECT name, sql FROM sqlite_schema \
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("table inventory prepares");
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("table inventory queries");
        let tables = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("table inventory decodes");

        assert_eq!(tables.len(), REQUIRED_TASK_AUTHORITY_TABLES_V1.len());
        for (name, sql) in tables {
            assert!(
                sql.ends_with("STRICT") || sql.ends_with("STRICT, WITHOUT ROWID"),
                "{name} is not a STRICT table"
            );
        }
    }

    #[test]
    fn exact_published_store_admits_without_mutating_the_target() {
        let store = exact_store(FixtureOptions::default());
        let before_changes = store.connection().total_changes();
        verify_admission_v1(store.connection(), FIXTURE_ROOT_ID)
            .expect("coherent published HLXA root admits");
        assert_eq!(store.connection().total_changes(), before_changes);
    }

    #[test]
    fn identity_version_and_object_drift_refuse_without_repair() {
        let wrong_application = exact_store(FixtureOptions::default());
        wrong_application
            .connection()
            .pragma_update(
                None,
                "application_id",
                TASK_AUTHORITY_STORE_APPLICATION_ID_V1 + 1,
            )
            .expect("test application id mutates");
        assert_eq!(
            verify_admission_v1(wrong_application.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::ApplicationIdMismatch)
        );

        let future = exact_store(FixtureOptions::default());
        future
            .connection()
            .pragma_update(None, "user_version", 2_i64)
            .expect("test user version mutates");
        assert_eq!(
            verify_admission_v1(future.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaUnsupported)
        );

        let downgrade = exact_store(FixtureOptions::default());
        downgrade
            .connection()
            .pragma_update(None, "user_version", 0_i64)
            .expect("test user version mutates");
        assert_eq!(
            verify_admission_v1(downgrade.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)
        );

        let injected_object = exact_store(FixtureOptions::default());
        injected_object
            .connection()
            .execute_batch("CREATE TABLE injected_schema_drift (id INTEGER PRIMARY KEY) STRICT;")
            .expect("test schema object creates");
        assert_eq!(
            verify_admission_v1(injected_object.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)
        );
    }

    #[test]
    fn every_required_connection_pragma_is_admission_critical() {
        for mutation in [
            "PRAGMA journal_mode=DELETE;",
            "PRAGMA synchronous=NORMAL;",
            "PRAGMA foreign_keys=OFF;",
            "PRAGMA recursive_triggers=OFF;",
            "PRAGMA trusted_schema=ON;",
            "PRAGMA cell_size_check=OFF;",
            "PRAGMA wal_autocheckpoint=1000;",
        ] {
            let store = exact_store(FixtureOptions::default());
            store
                .connection()
                .execute_batch(mutation)
                .expect("test durability pragma mutates");
            assert_eq!(
                verify_admission_v1(store.connection(), FIXTURE_ROOT_ID),
                Err(TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable),
                "pragma mutation admitted: {mutation}"
            );
        }
    }

    #[test]
    fn metadata_digest_root_lifecycle_profile_capacity_and_singleton_are_closed() {
        let exact = exact_store(FixtureOptions::default());
        assert_eq!(
            verify_admission_v1(exact.connection(), "different-root"),
            Err(TaskAuthoritySchemaAdmissionErrorV1::RootIdentityMismatch)
        );

        let bad_digest = digest_hex(0x91);
        let store = exact_store(FixtureOptions {
            metadata_schema_digest: &bad_digest,
            receipt_target_schema_digest: &bad_digest,
            ..FixtureOptions::default()
        });
        assert_eq!(
            verify_admission_v1(store.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid)
        );

        let store = exact_store(FixtureOptions {
            durability_profile: "UNREVIEWED_PROFILE",
            ..FixtureOptions::default()
        });
        assert_eq!(
            verify_admission_v1(store.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable)
        );

        let store = exact_store(FixtureOptions {
            ordinary_capacity: 1_025,
            ..FixtureOptions::default()
        });
        assert_eq!(
            verify_admission_v1(store.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)
        );

        let store = exact_store(FixtureOptions {
            lifecycle: "RESTORE_PENDING",
            ..FixtureOptions::default()
        });
        assert_eq!(
            verify_admission_v1(store.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::LifecycleUnavailable)
        );

        let store = exact_store(FixtureOptions {
            insert_metadata: false,
            ..FixtureOptions::default()
        });
        assert_eq!(
            verify_admission_v1(store.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)
        );
    }

    #[test]
    fn foreign_key_high_water_and_cross_record_corruption_fail_closed() {
        let dangling = exact_store(FixtureOptions::default());
        dangling
            .connection()
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .expect("foreign keys disable for corruption fixture");
        dangling
            .connection()
            .execute(
                "INSERT INTO human_request_grants (
                     grant_issuer_id, grant_id, grant_digest, signed_wire,
                     signed_wire_sha256, key_purpose, key_id, key_fingerprint,
                     principal_id, channel_id, session_id, audience, scope_template_id,
                     scope_template_digest, scope_template_generation, issued_at_utc_ms,
                     expires_at_utc_ms, verification_generation, retained_generation
                 ) VALUES (
                     'issuer', ?1, ?2, X'01', ?3, 'request-surface-grant-signing',
                     'missing-key', ?4, 'principal', 'channel', 'session', 'audience',
                     'scope', ?5, 1, 1, 2, 1, 1
                 )",
                params![
                    digest_hex(0x71),
                    digest_hex(0x72),
                    digest_hex(0x73),
                    digest_hex(0x74),
                    digest_hex(0x75),
                ],
            )
            .expect("dangling grant inserts with foreign keys disabled");
        dangling
            .connection()
            .execute_batch("PRAGMA foreign_keys=ON;")
            .expect("foreign keys re-enable");
        assert_eq!(
            verify_admission_v1(dangling.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)
        );

        let high_water = exact_store(FixtureOptions {
            attempt_event_generation: 2,
            ..FixtureOptions::default()
        });
        assert_eq!(
            verify_admission_v1(high_water.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)
        );

        let wrong_target_digest = digest_hex(0x81);
        let cross_record = exact_store(FixtureOptions {
            receipt_target_schema_digest: &wrong_target_digest,
            ..FixtureOptions::default()
        });
        assert_eq!(
            verify_admission_v1(cross_record.connection(), FIXTURE_ROOT_ID),
            Err(TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed)
        );
    }

    #[test]
    fn every_admission_error_is_stable_and_payload_free() {
        for error in [
            TaskAuthoritySchemaAdmissionErrorV1::ApplicationIdMismatch,
            TaskAuthoritySchemaAdmissionErrorV1::SchemaUnsupported,
            TaskAuthoritySchemaAdmissionErrorV1::SchemaInvalid,
            TaskAuthoritySchemaAdmissionErrorV1::RootIdentityMismatch,
            TaskAuthoritySchemaAdmissionErrorV1::LifecycleUnavailable,
            TaskAuthoritySchemaAdmissionErrorV1::DurabilityProfileUnavailable,
            TaskAuthoritySchemaAdmissionErrorV1::IntegrityFailed,
            TaskAuthoritySchemaAdmissionErrorV1::InvariantFailed,
        ] {
            assert_eq!(format!("{error:?}"), error.code_v1());
            assert_eq!(error.to_string(), error.code_v1());
        }
    }

    fn exact_store(options: FixtureOptions<'_>) -> TestStore {
        let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-task-authority-schema-{}-{fixture_id}.sqlite3",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut connection = Connection::open(&path).expect("fixture SQLite opens");
        connection
            .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
            .expect("reviewed schema initializes fixture");
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA recursive_triggers=ON;
                 PRAGMA trusted_schema=OFF;
                 PRAGMA cell_size_check=ON;
                 PRAGMA wal_autocheckpoint=0;
                 PRAGMA ignore_check_constraints=ON;",
            )
            .expect("reviewed durability profile configures");

        let attempt_id = digest_hex(0x01);
        let event_id = digest_hex(0x02);
        let receipt_id = digest_hex(0x03);
        let transaction = connection
            .transaction()
            .expect("fixture transaction begins");
        transaction
            .execute(
                "INSERT INTO authority_attempts (
                     attempt_id, operation_kind, namespace_digest, input_graph_digest,
                     caller_deadline_monotonic_ms, outcome_code, outcome_binding_digest,
                     attempt_generation, event_id
                 ) VALUES (?1, 'BOOTSTRAP', ?2, ?3, 1000, 'COMMITTED_RETAINED', ?4, ?5, ?6)",
                params![
                    attempt_id,
                    digest_hex(0x04),
                    digest_hex(0x05),
                    digest_hex(0x06),
                    options.attempt_event_generation,
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
                     'BOOTSTRAP_COMPLETED', ?4, 1, 1, 'boot-a', NULL, ?5
                 )",
                params![
                    event_id,
                    digest_hex(0x07),
                    attempt_id,
                    options.attempt_event_generation,
                    digest_hex(0x08),
                ],
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
                    FIXTURE_ROOT_ID,
                    options.receipt_target_schema_digest,
                    digest_hex(0x0c),
                ],
            )
            .expect("bootstrap receipt inserts");
        if options.insert_metadata {
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
                         1, ?1, 1, ?2, ?3, ?4, ?5, 'boot-a', 1, 1, 0, ?6, ?7,
                         1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, ?8, NULL
                     )",
                    params![
                        TASK_AUTHORITY_STORE_APPLICATION_ID_V1,
                        options.metadata_schema_digest,
                        FIXTURE_ROOT_ID,
                        options.lifecycle,
                        options.durability_profile,
                        options.ordinary_capacity,
                        options.control_capacity,
                        receipt_id,
                    ],
                )
                .expect("authority metadata inserts");
        }
        transaction.commit().expect("fixture transaction commits");
        connection
            .execute_batch("PRAGMA ignore_check_constraints=OFF;")
            .expect("check constraints restore");
        TestStore {
            connection: Some(connection),
            path,
        }
    }

    fn digest_hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn named_schema_tables(connection: &Connection) -> Vec<String> {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema \
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("table inventory prepares");
        statement
            .query_map([], |row| row.get(0))
            .expect("table inventory queries")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("table inventory decodes")
    }

    fn named_schema_objects(connection: &Connection, object_type: &str) -> Vec<(String, String)> {
        let mut statement = connection
            .prepare(
                "SELECT name, tbl_name FROM sqlite_schema \
                 WHERE type = ?1 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("schema-object inventory prepares");
        statement
            .query_map([object_type], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("schema-object inventory queries")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("schema-object inventory decodes")
    }

    fn owned_schema_objects(objects: &[(&str, &str)]) -> Vec<(String, String)> {
        objects
            .iter()
            .map(|(name, table)| ((*name).to_owned(), (*table).to_owned()))
            .collect()
    }
}
