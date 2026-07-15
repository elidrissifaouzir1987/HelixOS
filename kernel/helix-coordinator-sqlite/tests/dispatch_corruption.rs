//! PLAN-005 T073 RED contracts for coordinator/cross-store corruption custody.
//!
//! The strict V2 reopen checks below reuse the schema-corruption pattern: seed an exact
//! published store, inject out-of-band structural corruption with foreign keys disabled,
//! and prove ordinary open returns no store handle. The final production-source gate is a
//! compile-safe runtime RED until T078 adds the cross-store verifier and quarantine writer.

use ed25519_dalek::SigningKey;
use helix_contracts::{ContractError, Ed25519KeyResolver};
#[cfg(feature = "test-fault-injection")]
use helix_coordinator_sqlite::CoordinatorDispatchHandoffOutcomeV1;
#[cfg(feature = "test-fault-injection")]
use helix_coordinator_sqlite::{
    classify_and_retain_t097_coordinator_history_for_test_v1,
    clear_t097_after_projection_barrier_for_test_v1,
    install_t097_after_projection_barrier_for_test_v1,
    materialize_t097_production_lifecycle_for_test_v1, T097CoordinatorLifecycleForTestV1,
};
use helix_coordinator_sqlite::{
    embedded_schema_v1_sha256, CoordinatorMonotonicClockV1, CoordinatorRootIdentityEvidenceV1,
    CoordinatorStoreConfigV1, CoordinatorStoreOpenErrorV1, SqliteCoordinatorStoreV1,
    SqliteCoordinatorStoreV2,
};
#[cfg(feature = "test-fault-injection")]
use helix_dispatch_contracts::Sha256Digest as DispatchSha256Digest;
use helix_dispatch_inbox_sqlite::{
    AdapterCorruptionAuditErrorV1, AdapterCorruptionAuditPauseEvidenceV1,
    AdapterCorruptionAuditPauseV1,
};
#[cfg(feature = "test-fault-injection")]
use helix_dispatch_inbox_sqlite::{
    AdapterCorruptionAuditLifecycleV1, AdapterCorruptionAuditOutcomeV1,
    AdapterCorruptionAuditSelectionV1, AdapterInboxProfileV1, AdapterInboxRootIdentityEvidenceV1,
    AdapterInboxStoreConfigV1, AdapterInboxStoreOpenErrorV1, SqliteDispatchInboxStoreV1,
};
#[cfg(feature = "test-fault-injection")]
use helix_plan_dispatch::{
    DispatchHandoffGuardV1, DispatchHandoffOutcomeV1, DispatchHandoffValidationV1,
    DispatchTransportV1,
};
#[cfg(feature = "controlled-benchmark")]
use helix_plan_preparation::CONTROLLED_BENCHMARK_KEY_ID_V1;
#[cfg(feature = "test-fault-injection")]
use rusqlite::ErrorCode;
use rusqlite::{params, Connection};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "test-fault-injection")]
use std::sync::{Arc, Barrier};
#[cfg(feature = "test-fault-injection")]
use std::time::Duration;

const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);
const DEADLINE_MONOTONIC_MS: u64 = 10_000;
#[cfg(not(feature = "controlled-benchmark"))]
const CONTROLLED_BENCHMARK_KEY_ID_V1: &str = "core-signing-key:controlled-benchmark-v1";
#[cfg(feature = "test-fault-injection")]
const ADAPTER_DATABASE_FILENAME: &str = "dispatch-inbox.sqlite3";

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
    fn resolve_ed25519(&self, key_id: &str) -> helix_contracts::Result<[u8; 32]> {
        if key_id == CONTROLLED_BENCHMARK_KEY_ID_V1 {
            Ok(SigningKey::from_bytes(&[0x42; 32])
                .verifying_key()
                .to_bytes())
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

struct CompileOnlyAdapterCorruptionPauseV1;

impl AdapterCorruptionAuditPauseV1 for CompileOnlyAdapterCorruptionPauseV1 {
    fn capture_adapter_corruption_audit_pause_v1(
        &mut self,
    ) -> Result<AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditErrorV1> {
        Err(AdapterCorruptionAuditErrorV1::Unavailable)
    }

    fn recheck_adapter_corruption_audit_pause_v1(
        &mut self,
        _expected: &AdapterCorruptionAuditPauseEvidenceV1,
    ) -> Result<(), AdapterCorruptionAuditErrorV1> {
        Err(AdapterCorruptionAuditErrorV1::Unavailable)
    }
}

#[test]
fn production_adapter_corruption_caller_is_present_in_the_default_build() {
    fn typecheck<P: AdapterCorruptionAuditPauseV1>() {
        let _ = SqliteCoordinatorStoreV2::<FixedClock, HistoricalPlanKeys>::
            audit_and_retain_adapter_corruption_under_pause_v1::<P>;
    }

    typecheck::<CompileOnlyAdapterCorruptionPauseV1>();
}

struct StrictCoordinatorV2Root {
    path: PathBuf,
    identity: CoordinatorRootIdentityEvidenceV1,
}

impl StrictCoordinatorV2Root {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-t073-coordinator-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("T073 coordinator root creates");
        let config = CoordinatorStoreConfigV1::try_new_empty_attested(path.clone(), 25)
            .expect("T073 empty coordinator root is provisioner-attested");
        let v1 = SqliteCoordinatorStoreV1::open_or_create(
            config,
            FixedClock(1_000),
            HistoricalPlanKeys,
            DEADLINE_MONOTONIC_MS,
        )
        .expect("T073 exact coordinator V1 initializes");
        let identity = v1.root_identity_evidence();
        drop(v1);

        install_exact_empty_v2(&path.join("coordinator.sqlite3"));
        let fixture = Self { path, identity };
        drop(
            fixture
                .reopen()
                .expect("T073 exact empty coordinator V2 passes strict open"),
        );
        fixture
    }

    fn database(&self) -> PathBuf {
        self.path.join("coordinator.sqlite3")
    }

    fn reopen(
        &self,
    ) -> Result<SqliteCoordinatorStoreV2<FixedClock, HistoricalPlanKeys>, CoordinatorStoreOpenErrorV1>
    {
        let config = CoordinatorStoreConfigV1::try_new_existing_attested(
            self.path.clone(),
            self.identity,
            25,
        )
        .expect("T073 existing coordinator root remains provisioner-attested");
        SqliteCoordinatorStoreV2::open_existing(
            config,
            FixedClock(1_001),
            HistoricalPlanKeys,
            DEADLINE_MONOTONIC_MS,
        )
    }

    #[cfg(feature = "test-fault-injection")]
    fn fork(&self, label: &str) -> Self {
        checkpoint_sqlite(&self.database());
        let path = unique_test_root("coordinator-fork", label);
        copy_directory(&self.path, &path);
        let fork = Self {
            path,
            identity: self.identity,
        };
        drop(
            fork.reopen()
                .expect("T097 unmodified coordinator fork passes strict open"),
        );
        fork
    }

    #[cfg(feature = "test-fault-injection")]
    fn from_materialized(path: PathBuf) -> Self {
        let root_identity: Vec<u8> = Connection::open(path.join("coordinator.sqlite3"))
            .expect("T097 materialized coordinator opens")
            .query_row(
                "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("T097 materialized coordinator identity reads");
        let identity = CoordinatorRootIdentityEvidenceV1::from_attested_bytes(
            root_identity
                .try_into()
                .expect("T097 coordinator identity remains exact"),
        );
        let fixture = Self { path, identity };
        drop(
            fixture
                .reopen()
                .expect("T097 materialized coordinator strictly reopens"),
        );
        fixture
    }
}

impl Drop for StrictCoordinatorV2Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(feature = "test-fault-injection")]
struct StrictAdapterRootV1 {
    path: PathBuf,
    identity: AdapterInboxRootIdentityEvidenceV1,
}

#[cfg(feature = "test-fault-injection")]
impl StrictAdapterRootV1 {
    fn database(&self) -> PathBuf {
        self.path.join(ADAPTER_DATABASE_FILENAME)
    }

    fn reopen(&self) -> Result<SqliteDispatchInboxStoreV1, AdapterInboxStoreOpenErrorV1> {
        let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
            self.path.clone(),
            self.identity,
            25,
        )
        .expect("T097 existing adapter root remains provisioner-attested");
        SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile())
    }

    fn fork(&self, label: &str) -> Self {
        checkpoint_sqlite(&self.database());
        let path = unique_test_root("adapter-fork", label);
        copy_directory(&self.path, &path);
        let fork = Self {
            path,
            identity: self.identity,
        };
        drop(
            fork.reopen()
                .expect("T097 unmodified adapter fork passes strict open"),
        );
        fork
    }

    fn from_materialized(path: PathBuf) -> Self {
        let root_identity: Vec<u8> = Connection::open(path.join(ADAPTER_DATABASE_FILENAME))
            .expect("T097 materialized adapter opens")
            .query_row(
                "SELECT root_identity FROM adapter_store_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("T097 materialized adapter identity reads");
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(
            root_identity
                .try_into()
                .expect("T097 adapter identity remains exact"),
        );
        let fixture = Self { path, identity };
        drop(
            fixture
                .reopen()
                .expect("T097 materialized adapter strictly reopens"),
        );
        fixture
    }
}

#[cfg(feature = "test-fault-injection")]
impl Drop for StrictAdapterRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(feature = "test-fault-injection")]
fn adapter_profile() -> AdapterInboxProfileV1 {
    AdapterInboxProfileV1::try_new(
        "adapter-t097-v1",
        1,
        DispatchSha256Digest::from_bytes([0x53; 32]),
    )
    .expect("T097 adapter profile is exact")
}

#[cfg(feature = "test-fault-injection")]
fn unique_test_root(domain: &str, label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(10_000);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "helixos-t097-{domain}-{}-{sequence}-{label}",
        std::process::id()
    ))
}

#[cfg(feature = "test-fault-injection")]
fn materialize_lifecycle_roots(
    label: &str,
    lifecycle: T097CoordinatorLifecycleForTestV1,
) -> (StrictCoordinatorV2Root, StrictAdapterRootV1) {
    let coordinator_path = unique_test_root("coordinator-production", label);
    let adapter_path = unique_test_root("adapter-production", label);
    materialize_t097_production_lifecycle_for_test_v1(lifecycle, &coordinator_path, &adapter_path)
        .expect("T097 production lifecycle materializes and strict-reopens destinations");
    (
        StrictCoordinatorV2Root::from_materialized(coordinator_path),
        StrictAdapterRootV1::from_materialized(adapter_path),
    )
}

#[cfg(feature = "test-fault-injection")]
fn checkpoint_sqlite(database: &Path) {
    let connection = Connection::open(database).expect("T097 database opens for checkpoint");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("T097 WAL checkpoints before filesystem fork");
}

#[cfg(feature = "test-fault-injection")]
fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("T097 fork destination creates");
    for entry in fs::read_dir(source).expect("T097 source root enumerates") {
        let entry = entry.expect("T097 source entry reads");
        let destination_entry = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("T097 source entry type reads");
        if file_type.is_dir() {
            copy_directory(&entry.path(), &destination_entry);
        } else if file_type.is_file() {
            fs::copy(entry.path(), destination_entry).expect("T097 source file copies");
        }
    }
}

fn install_exact_empty_v2(database: &Path) {
    let connection = Connection::open(database).expect("T073 V1 database opens for V2 overlay");
    let root_identity: Vec<u8> = connection
        .query_row(
            "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("T073 coordinator root identity reads");
    connection
        .execute_batch(V2_OVERLAY)
        .expect("T073 reviewed V2 overlay installs");
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
        .expect("T073 dispatch metadata installs");
    connection
        .execute(
            "INSERT INTO coordinator_v2_migrations (
                migration_attempt_id, source_schema_digest, source_root_identity,
                source_summary_digest, verified_backup_digest, overlay_schema_digest,
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms,
                tool_identity
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1000, 1000, 'helixos-t073-v1')",
            params![
                [0x41_u8; 32].as_slice(),
                embedded_schema_v1_sha256().as_slice(),
                root_identity,
                [0x42_u8; 32].as_slice(),
                [0x43_u8; 32].as_slice(),
                <[u8; 32]>::from(Sha256::digest(V2_OVERLAY.as_bytes())).as_slice(),
            ],
        )
        .expect("T073 exact migration receipt installs");
}

fn inject_orphan_coordinator_grant(database: &Path) {
    let connection = Connection::open(database).expect("T073 coordinator database opens raw");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T073 out-of-band fixture disables foreign keys");
    connection
        .execute(
            "UPDATE dispatch_store_meta
             SET dispatch_store_generation = 2, dispatch_generation = 2
             WHERE singleton = 1",
            [],
        )
        .expect("T073 orphan grant high-water projection seeds");
    connection
        .execute(
            "INSERT INTO dispatch_grants (
                grant_id, dispatch_attempt_id, operation_id, preparation_attempt_id,
                preparation_transition_generation, plan_id, task_id, workload_id,
                task_lease_digest, reservation_id, one_shot_nonce, grant_digest,
                canonical_grant, canonical_grant_length, signer_key_id,
                signer_key_fingerprint, destination_adapter_id, protocol_version,
                issued_at_monotonic_ms, deadline_monotonic_ms, created_generation
             ) VALUES (
                ?1, ?2, 'operation:t073-orphan-grant', ?3, 1, ?4,
                'task:t073', 'workload:t073', ?5, 'reservation:t073', ?6, ?7,
                ?8, 1, 'grant-key:t073', ?9, 'adapter:t073', 1, 1000, 2000, 2
             )",
            params![
                [0x51_u8; 32].as_slice(),
                [0x52_u8; 32].as_slice(),
                [0x53_u8; 32].as_slice(),
                [0x54_u8; 32].as_slice(),
                [0x55_u8; 32].as_slice(),
                [0x56_u8; 32].as_slice(),
                [0x57_u8; 32].as_slice(),
                [0x58_u8].as_slice(),
                [0x59_u8; 32].as_slice(),
            ],
        )
        .expect("T073 structurally orphan coordinator grant injects");
}

fn inject_orphan_coordinator_receipt(database: &Path) {
    let connection = Connection::open(database).expect("T073 coordinator database opens raw");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T073 out-of-band fixture disables foreign keys");
    connection
        .execute(
            "UPDATE dispatch_store_meta
             SET dispatch_store_generation = 2, receipt_generation = 2
             WHERE singleton = 1",
            [],
        )
        .expect("T073 orphan receipt high-water projection seeds");
    connection
        .execute(
            "INSERT INTO dispatch_receipts (
                receipt_id, grant_id, operation_id, dispatch_attempt_id,
                receipt_digest, canonical_receipt, canonical_receipt_length,
                adapter_key_fingerprint, decision, refusal_code,
                no_consumption_tombstone_digest, receipt_generation
             ) VALUES (
                ?1, ?2, 'operation:t073-orphan-receipt', ?3,
                ?4, ?5, 1, ?6, 'CONSUMED', NULL, NULL, 2
             )",
            params![
                [0x61_u8; 32].as_slice(),
                [0x62_u8; 32].as_slice(),
                [0x63_u8; 32].as_slice(),
                [0x64_u8; 32].as_slice(),
                [0x65_u8].as_slice(),
                [0x66_u8; 32].as_slice(),
            ],
        )
        .expect("T073 structurally orphan coordinator receipt injects");
}

#[cfg(feature = "test-fault-injection")]
const T097_OPERATION_ID: &str = "operation:t097-paired";

#[cfg(feature = "test-fault-injection")]
const T097_SECOND_GRANT_ID: [u8; 32] = [0xff; 32];
#[cfg(feature = "test-fault-injection")]
const T097_SECOND_DISPATCH_ATTEMPT_ID: [u8; 32] = [0xfe; 32];
#[cfg(feature = "test-fault-injection")]
const T097_SECOND_GRANT_DIGEST: [u8; 32] = [0xfd; 32];

#[cfg(feature = "test-fault-injection")]
fn append_observed_coordinator_grant(database: &Path) {
    let connection = Connection::open(database).expect("T097 coordinator multi-grant DB opens");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T097 coordinator multi-grant injection disables foreign keys");
    let (store_generation, dispatch_generation): (i64, i64) = connection
        .query_row(
            "SELECT dispatch_store_generation, dispatch_generation
             FROM dispatch_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("T097 coordinator generations read");
    let next_generation = store_generation.max(dispatch_generation) + 1;
    connection
        .execute(
            "UPDATE dispatch_store_meta
             SET dispatch_store_generation = ?1, dispatch_generation = ?1
             WHERE singleton = 1",
            [next_generation],
        )
        .expect("T097 coordinator multi-grant high-water advances");
    connection
        .execute(
            "INSERT INTO dispatch_grants (
                grant_id, dispatch_attempt_id, operation_id, preparation_attempt_id,
                preparation_transition_generation, plan_id, task_id, workload_id,
                task_lease_digest, reservation_id, one_shot_nonce, grant_digest,
                canonical_grant, canonical_grant_length, signer_key_id,
                signer_key_fingerprint, destination_adapter_id, protocol_version,
                issued_at_monotonic_ms, deadline_monotonic_ms, created_generation
             ) VALUES (
                ?1, ?2, ?3, ?4, 1, ?5, 'task:t097-second', 'workload:t097-second', ?6,
                'reservation:t097-second', ?7, ?8, ?9, 1, 'grant-key:t097-second', ?10,
                'adapter:t080:no-effect-v1', 1, 1000, 2000, ?11
             )",
            params![
                T097_SECOND_GRANT_ID.as_slice(),
                T097_SECOND_DISPATCH_ATTEMPT_ID.as_slice(),
                "operation:t097-multi-second",
                [0x84_u8; 32].as_slice(),
                [0x85_u8; 32].as_slice(),
                [0x86_u8; 32].as_slice(),
                [0x87_u8; 32].as_slice(),
                T097_SECOND_GRANT_DIGEST.as_slice(),
                [0x88_u8].as_slice(),
                [0x89_u8; 32].as_slice(),
                next_generation,
            ],
        )
        .expect("T097 second coordinator grant appends out of band");
}

#[cfg(feature = "test-fault-injection")]
fn append_observed_adapter_grant(database: &Path, digest: [u8; 32]) {
    let connection = Connection::open(database).expect("T097 adapter multi-grant DB opens");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T097 adapter multi-grant injection disables foreign keys");
    let (store_generation, inbox_generation, supervisor_epoch, epoch_generation): (
        i64,
        i64,
        i64,
        i64,
    ) = connection
        .query_row(
            "SELECT store_generation, inbox_generation, supervisor_epoch,
                    epoch_observer_generation
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("T097 adapter generations read");
    let next_generation = store_generation.max(inbox_generation) + 1;
    connection
        .execute(
            "UPDATE adapter_store_meta
             SET store_generation = ?1, inbox_generation = ?1
             WHERE singleton = 1",
            [next_generation],
        )
        .expect("T097 adapter multi-grant high-water advances");
    connection
        .execute(
            "INSERT INTO grant_inbox (
                grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                canonical_grant, canonical_grant_length, coordinator_key_fingerprint,
                destination_adapter_id, protocol_version, observed_supervisor_epoch,
                epoch_observer_generation, inbox_state, received_generation,
                current_generation, receipt_id, receipt_decision, current_event_id
             ) VALUES (
                ?1, ?2, ?3, ?4, 'task:t097-second', 'workload:t097-second', ?5, ?6, ?7,
                ?8, 1, ?9, 'adapter:t080:no-effect-v1', 1, ?10, ?11,
                'RECEIVED', ?12, ?12, NULL, NULL, ?13
             )",
            params![
                T097_SECOND_GRANT_ID.as_slice(),
                "operation:t097-multi-second",
                T097_SECOND_DISPATCH_ATTEMPT_ID.as_slice(),
                [0x85_u8; 32].as_slice(),
                [0x86_u8; 32].as_slice(),
                [0x87_u8; 32].as_slice(),
                digest.as_slice(),
                [0x88_u8].as_slice(),
                [0x89_u8; 32].as_slice(),
                supervisor_epoch,
                epoch_generation,
                next_generation,
                [0x8a_u8; 32].as_slice(),
            ],
        )
        .expect("T097 second adapter grant appends out of band");
}

#[cfg(feature = "test-fault-injection")]
fn delete_adapter_receipt(database: &Path) {
    let connection = Connection::open(database).expect("T097 adapter DB opens for receipt loss");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T097 receipt loss disables foreign keys out of band");
    connection
        .execute_batch("DROP TRIGGER execution_receipts_no_delete; DELETE FROM execution_receipts;")
        .expect("T097 adapter receipt is removed out of band");
}

#[cfg(feature = "test-fault-injection")]
fn delete_adapter_grant(database: &Path) {
    let connection = Connection::open(database).expect("T097 adapter DB opens for grant loss");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T097 grant loss disables foreign keys out of band");
    connection
        .execute_batch("DROP TRIGGER grant_inbox_no_delete; DELETE FROM grant_inbox;")
        .expect("T097 adapter grant is removed out of band");
}

#[cfg(feature = "test-fault-injection")]
fn mutate_adapter_grant_digest(database: &Path) {
    let connection = Connection::open(database).expect("T097 adapter DB opens for grant conflict");
    connection
        .execute_batch("DROP TRIGGER grant_inbox_update_guard;")
        .expect("T097 adapter grant guard drops out of band");
    connection
        .execute(
            "UPDATE grant_inbox SET grant_digest = ?1",
            [[0xa1_u8; 32].as_slice()],
        )
        .expect("T097 adapter grant digest diverges");
}

#[cfg(feature = "test-fault-injection")]
fn mutate_adapter_receipt_digest(database: &Path) {
    let connection =
        Connection::open(database).expect("T097 adapter DB opens for receipt conflict");
    connection
        .execute_batch("DROP TRIGGER execution_receipts_no_update;")
        .expect("T097 adapter receipt guard drops out of band");
    connection
        .execute(
            "UPDATE execution_receipts SET receipt_digest = ?1",
            [[0xa2_u8; 32].as_slice()],
        )
        .expect("T097 adapter receipt digest diverges");
}

#[cfg(feature = "test-fault-injection")]
fn mutate_adapter_actual_relation_generation(database: &Path) {
    let connection =
        Connection::open(database).expect("T097 adapter DB opens for generation conflict");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T097 generation conflict disables foreign keys out of band");
    connection
        .execute_batch("DROP TRIGGER grant_inbox_update_guard;")
        .expect("T097 adapter grant guard drops out of band");
    connection
        .execute(
            "UPDATE grant_inbox SET current_generation = current_generation + 1",
            [],
        )
        .expect("T097 retained per-record generation diverges");
}

#[cfg(feature = "test-fault-injection")]
fn advance_migration_history(database: &Path) {
    let connection = Connection::open(database).expect("T097 coordinator DB opens for advance");
    let trigger = exact_trigger_sql(&connection, "coordinator_v2_migrations_no_update");
    connection
        .execute_batch(
            "DROP TRIGGER coordinator_v2_migrations_no_update;
             UPDATE coordinator_v2_migrations SET migration_generation = 2;
             UPDATE dispatch_store_meta
             SET dispatch_store_generation = 2, migration_generation = 2
             WHERE singleton = 1;",
        )
        .expect("T097 coordinator migration history advances to generation two");
    connection
        .execute_batch(&trigger)
        .expect("T097 exact migration update guard restores");
}

#[cfg(feature = "test-fault-injection")]
fn append_invalid_second_migration_history(database: &Path) {
    let connection = Connection::open(database).expect("T097 coordinator DB opens for append");
    let trusted_key: Vec<u8> = connection
        .query_row(
            "SELECT migration_attempt_id FROM coordinator_v2_migrations",
            [],
            |row| row.get(0),
        )
        .expect("T097 trusted migration key reads before append");
    let appended_key = [0_u8; 32];
    assert_ne!(
        appended_key.as_slice(),
        trusted_key.as_slice(),
        "T097 invalid second migration key must remain distinct"
    );
    let transaction = connection
        .unchecked_transaction()
        .expect("T097 invalid second-migration transaction begins");
    transaction
        .execute(
            "INSERT INTO coordinator_v2_migrations (
                migration_attempt_id, source_schema_digest, source_root_identity,
                source_summary_digest, verified_backup_digest, overlay_schema_digest,
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms,
                tool_identity
             )
             SELECT ?1, source_schema_digest, source_root_identity,
                    source_summary_digest, verified_backup_digest, overlay_schema_digest,
                    2, migrated_at_utc_ms + 1, migrated_at_monotonic_ms + 1,
                    tool_identity
             FROM coordinator_v2_migrations",
            [appended_key.as_slice()],
        )
        .expect("T097 invalid second migration row appends");
    transaction
        .execute(
            "UPDATE dispatch_store_meta
             SET dispatch_store_generation = 2, migration_generation = 2
             WHERE singleton = 1",
            [],
        )
        .expect("T097 invalid second-migration high-water advances");
    transaction
        .commit()
        .expect("T097 invalid second-migration transaction commits");
}

#[cfg(feature = "test-fault-injection")]
fn advance_store_without_history_axis(database: &Path) {
    let connection = Connection::open(database).expect("T097 coordinator DB opens for rollback");
    connection
        .execute(
            "UPDATE dispatch_store_meta SET dispatch_store_generation = 2 WHERE singleton = 1",
            [],
        )
        .expect("T097 coordinator store advances without its migration axis");
}

#[cfg(feature = "test-fault-injection")]
fn truncate_migration_history(database: &Path) {
    let connection = Connection::open(database).expect("T097 coordinator DB opens for truncation");
    let trigger = exact_trigger_sql(&connection, "coordinator_v2_migrations_no_delete");
    connection
        .execute_batch(
            "DROP TRIGGER coordinator_v2_migrations_no_delete;
             DELETE FROM coordinator_v2_migrations;",
        )
        .expect("T097 coordinator history truncates out of band");
    connection
        .execute_batch(&trigger)
        .expect("T097 exact migration delete guard restores");
}

#[cfg(feature = "test-fault-injection")]
fn fork_migration_history_at_same_generation(database: &Path) {
    let connection = Connection::open(database).expect("T097 coordinator DB opens for fork");
    let trigger = exact_trigger_sql(&connection, "coordinator_v2_migrations_no_update");
    connection
        .execute_batch("DROP TRIGGER coordinator_v2_migrations_no_update;")
        .expect("T097 migration update guard drops out of band");
    connection
        .execute(
            "UPDATE coordinator_v2_migrations SET verified_backup_digest = ?1",
            [[0xb1_u8; 32].as_slice()],
        )
        .expect("T097 distinct valid generation-one branch writes");
    connection
        .execute_batch(&trigger)
        .expect("T097 exact migration update guard restores");
}

#[cfg(feature = "test-fault-injection")]
fn exact_trigger_sql(connection: &Connection, name: &str) -> String {
    connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .expect("T097 exact trigger SQL reads before fault injection")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinatorCorruptionSeedV1 {
    OrphanCoordinatorGrant,
    OrphanCoordinatorReceipt,
    GrantDigestConflict,
    ReceiptDigestConflict,
    CrossGenerationConflict,
    StoreRollback,
    RootRollback,
    GenerationRollback,
    HistoryTruncation,
    GenerationReuse,
    CrossStoreDisagreement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CustodyOracleV1 {
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionOracleV1 {
    Refused,
}

fn coordinator_oracle(
    seed: CoordinatorCorruptionSeedV1,
) -> (&'static str, CustodyOracleV1, ExecutionOracleV1) {
    use CoordinatorCorruptionSeedV1::*;
    let reason = match seed {
        OrphanCoordinatorGrant => "ORPHAN_COORDINATOR_GRANT",
        OrphanCoordinatorReceipt => "ORPHAN_COORDINATOR_RECEIPT",
        GrantDigestConflict => "GRANT_DIGEST_CONFLICT",
        ReceiptDigestConflict => "RECEIPT_DIGEST_CONFLICT",
        CrossGenerationConflict => "CROSS_GENERATION_CONFLICT",
        StoreRollback => "COORDINATOR_STORE_ROLLBACK",
        RootRollback => "COORDINATOR_ROOT_ROLLBACK",
        GenerationRollback => "COORDINATOR_GENERATION_ROLLBACK",
        HistoryTruncation => "COORDINATOR_HISTORY_TRUNCATED",
        GenerationReuse => "COORDINATOR_GENERATION_REUSED",
        CrossStoreDisagreement => "CROSS_STORE_DISAGREEMENT",
    };
    (
        reason,
        CustodyOracleV1::Quarantined,
        ExecutionOracleV1::Refused,
    )
}

#[test]
fn strict_v2_open_returns_no_store_for_structural_orphan_grant_or_receipt() {
    let grant = StrictCoordinatorV2Root::new("orphan-grant");
    inject_orphan_coordinator_grant(&grant.database());
    assert_eq!(
        grant.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed,
        "a structurally orphan coordinator grant must fail before any store handle exists"
    );

    let receipt = StrictCoordinatorV2Root::new("orphan-receipt");
    inject_orphan_coordinator_receipt(&receipt.database());
    assert_eq!(
        receipt.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed,
        "a structurally orphan coordinator receipt must fail before any store handle exists"
    );
}

#[test]
fn coordinator_corruption_oracles_are_closed_quarantine_plus_refusal() {
    use CoordinatorCorruptionSeedV1::*;
    let seeds = [
        OrphanCoordinatorGrant,
        OrphanCoordinatorReceipt,
        GrantDigestConflict,
        ReceiptDigestConflict,
        CrossGenerationConflict,
        StoreRollback,
        RootRollback,
        GenerationRollback,
        HistoryTruncation,
        GenerationReuse,
        CrossStoreDisagreement,
    ];
    let expected_reasons = [
        "ORPHAN_COORDINATOR_GRANT",
        "ORPHAN_COORDINATOR_RECEIPT",
        "GRANT_DIGEST_CONFLICT",
        "RECEIPT_DIGEST_CONFLICT",
        "CROSS_GENERATION_CONFLICT",
        "COORDINATOR_STORE_ROLLBACK",
        "COORDINATOR_ROOT_ROLLBACK",
        "COORDINATOR_GENERATION_ROLLBACK",
        "COORDINATOR_HISTORY_TRUNCATED",
        "COORDINATOR_GENERATION_REUSED",
        "CROSS_STORE_DISAGREEMENT",
    ];
    for (seed, expected_reason) in seeds.into_iter().zip(expected_reasons) {
        assert_eq!(
            coordinator_oracle(seed),
            (
                expected_reason,
                CustodyOracleV1::Quarantined,
                ExecutionOracleV1::Refused,
            ),
            "T073 corruption oracles must never contain an activation outcome"
        );
    }
}

#[cfg(feature = "test-fault-injection")]
fn observe_t097(
    trusted_coordinator: &StrictCoordinatorV2Root,
    trusted_adapter: &StrictAdapterRootV1,
    observed_coordinator: &StrictCoordinatorV2Root,
    observed_adapter: &StrictAdapterRootV1,
    custody: &StrictCoordinatorV2Root,
    lifecycle: T097CoordinatorLifecycleForTestV1,
) -> helix_coordinator_sqlite::T097CoordinatorObservationEvidenceV1 {
    classify_and_retain_t097_coordinator_history_for_test_v1(
        &trusted_coordinator.database(),
        &trusted_adapter.database(),
        &observed_coordinator.database(),
        &observed_adapter.database(),
        &custody.database(),
        lifecycle,
    )
    .expect("T097 production filesystem observer classifies")
}

#[cfg(feature = "test-fault-injection")]
fn resolve_t097_custody_out_of_band(database: &Path) {
    let connection = Connection::open(database).expect("T097 custody opens for status transition");
    let created_generation: i64 = connection
        .query_row(
            "SELECT created_generation FROM preparation_quarantines
             WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
            [],
            |row| row.get(0),
        )
        .expect("T097 retained generation reads before tombstone transition");
    let resolved_generation = created_generation
        .checked_add(1)
        .expect("T097 tombstone generation remains representable");
    let transaction = connection
        .unchecked_transaction()
        .expect("T097 custody status transaction begins");
    transaction
        .execute(
            "UPDATE preparation_quarantines
             SET quarantine_status = 'RESOLVED_TOMBSTONE', resolved_generation = ?1
             WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
            [resolved_generation],
        )
        .expect("T097 custody transitions to tombstone");
    transaction
        .execute(
            "UPDATE coordinator_store_meta
             SET store_generation = ?1, quarantine_generation = ?1
             WHERE singleton = 1",
            [resolved_generation],
        )
        .expect("T097 custody metadata advances");
    transaction
        .commit()
        .expect("T097 custody status transition commits");
}

#[cfg(feature = "test-fault-injection")]
#[derive(Debug, PartialEq, Eq)]
struct T097RetainedBaseRowV1 {
    attempt_id: Vec<u8>,
    operation_binding_digest: Vec<u8>,
    reason: String,
    status: String,
    created_generation: i64,
}

#[cfg(feature = "test-fault-injection")]
fn retained_t097_base_row(database: &Path) -> T097RetainedBaseRowV1 {
    let connection = Connection::open(database).expect("T097 retained root opens read-only");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM preparation_quarantines
             WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
            [],
            |row| row.get(0),
        )
        .expect("T097 retained row count reads");
    assert_eq!(count, 1, "T097 must retain exactly one permanent base row");
    connection
        .query_row(
            "SELECT attempt_id, operation_binding_digest, quarantine_reason,
                    quarantine_status, created_generation
             FROM preparation_quarantines
             WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
            [],
            |row| {
                Ok(T097RetainedBaseRowV1 {
                    attempt_id: row.get(0)?,
                    operation_binding_digest: row.get(1)?,
                    reason: row.get(2)?,
                    status: row.get(3)?,
                    created_generation: row.get(4)?,
                })
            },
        )
        .expect("T097 exact retained base row reads")
}

#[cfg(feature = "test-fault-injection")]
struct NeverCalledT097HandoffGuardV1;

#[cfg(feature = "test-fault-injection")]
impl DispatchHandoffGuardV1 for NeverCalledT097HandoffGuardV1 {
    fn evidence_binding_v1(&self) -> [u8; 32] {
        [0; 32]
    }

    fn validate_at_v1(&mut self, _now_monotonic_ms: u64) -> DispatchHandoffValidationV1 {
        DispatchHandoffValidationV1::Revoked
    }

    fn release_v1(self) {}
}

#[cfg(feature = "test-fault-injection")]
struct CountingT097TransportV1<'counter> {
    calls: &'counter AtomicU64,
}

#[cfg(feature = "test-fault-injection")]
impl DispatchTransportV1 for CountingT097TransportV1<'_> {
    type Guard = NeverCalledT097HandoffGuardV1;
    type Response = ();

    fn acquire_handoff_guard_v1(
        &self,
        _grant_binding: &[u8; 32],
        _deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(DispatchHandoffValidationV1::Revoked)
    }

    fn deliver_exact_v1(
        &self,
        _guard: &mut Self::Guard,
        _exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        DispatchHandoffOutcomeV1::ConfirmedNoSend
    }
}

#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)]
fn assert_t097_corruption_case(
    trusted_coordinator: &StrictCoordinatorV2Root,
    trusted_adapter: &StrictAdapterRootV1,
    observed_coordinator: &StrictCoordinatorV2Root,
    observed_adapter: &StrictAdapterRootV1,
    custody: &StrictCoordinatorV2Root,
    lifecycle: T097CoordinatorLifecycleForTestV1,
    expected_reason: &str,
    expected_base_reason: &str,
) {
    let first = observe_t097(
        trusted_coordinator,
        trusted_adapter,
        observed_coordinator,
        observed_adapter,
        custody,
        lifecycle,
    );
    let retry = observe_t097(
        trusted_coordinator,
        trusted_adapter,
        observed_coordinator,
        observed_adapter,
        custody,
        lifecycle,
    );
    assert_eq!(first.corruption_reason_code(), Some(expected_reason));
    assert_eq!(first.base_reason_code(), Some(expected_base_reason));
    assert_eq!(first.created_generation(), Some(1));
    assert_eq!(first.retained_row_count(), 1);
    assert!(first.execution_refused());
    assert_eq!(retry, first, "exact retry must read one original custody");
    assert_eq!(
        observed_coordinator.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed,
        "every corrupt observed coordinator branch must be locally fenced"
    );
    assert_eq!(
        custody.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed,
        "retained corruption must return no ordinary V2 handle"
    );
    let local_row = retained_t097_base_row(&observed_coordinator.database());
    let external_row = retained_t097_base_row(&custody.database());
    assert_eq!(local_row.reason, expected_base_reason);
    assert_eq!(external_row.reason, expected_base_reason);
    assert_eq!(local_row.status, "ACTIVE");
    assert_eq!(external_row.status, "ACTIVE");
    assert_eq!(local_row.attempt_id, external_row.attempt_id);
    assert_eq!(
        local_row.operation_binding_digest, external_row.operation_binding_digest,
        "local and external custody must bind the exact same redacted disposition"
    );

    let debug = format!("{first:?}");
    for forbidden in [
        T097_OPERATION_ID,
        trusted_coordinator.path.to_string_lossy().as_ref(),
        observed_coordinator.path.to_string_lossy().as_ref(),
        custody.path.to_string_lossy().as_ref(),
        "canonical_grant",
        "canonical_receipt",
    ] {
        assert!(
            !debug.contains(forbidden),
            "T097 evidence Debug leaked `{forbidden}`"
        );
    }
    for database in [observed_coordinator.database(), custody.database()] {
        let persisted: String = Connection::open(database)
            .expect("T097 custody raw reopen succeeds")
            .query_row(
                "SELECT quote(quarantine_id) || quote(attempt_id) ||
                        quote(operation_binding_digest) || quarantine_reason
                 FROM preparation_quarantines",
                [],
                |row| row.get(0),
            )
            .expect("T097 redacted custody reads");
        assert!(!persisted.contains(T097_OPERATION_ID));
        assert!(!persisted.contains("canonical_grant"));
        assert!(!persisted.contains("canonical_receipt"));
    }

    resolve_t097_custody_out_of_band(&observed_coordinator.database());
    resolve_t097_custody_out_of_band(&custody.database());
    assert_eq!(
        observed_coordinator.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed,
        "resolved/tampered local status must never lift the source fence"
    );
    assert_eq!(
        custody.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed,
        "resolved/tampered status must never lift the permanent T097 fence"
    );
    let resolved_retry = observe_t097(
        trusted_coordinator,
        trusted_adapter,
        observed_coordinator,
        observed_adapter,
        custody,
        lifecycle,
    );
    assert_eq!(resolved_retry.created_generation(), Some(1));
    assert_eq!(resolved_retry.retained_row_count(), 1);
    let local_resolved = retained_t097_base_row(&observed_coordinator.database());
    let external_resolved = retained_t097_base_row(&custody.database());
    assert_eq!(local_resolved.status, "RESOLVED_TOMBSTONE");
    assert_eq!(external_resolved.status, "RESOLVED_TOMBSTONE");
    assert_eq!(
        local_resolved.created_generation,
        local_row.created_generation
    );
    assert_eq!(
        external_resolved.created_generation,
        external_row.created_generation
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_filesystem_matrix_classifies_and_permanently_fences_all_eleven_classes() {
    // Every trusted cut is materialized by the ordinary T096 production pipeline and
    // strictly reopened after its destination copy. Only observed forks are fault-injected.

    // 1. The observed adapter loses a retained grant from an exact received cut.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-orphan-grant-trusted",
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-orphan-grant-observed");
        let observed_adapter = trusted_adapter.fork("t097-orphan-grant-observed");
        delete_adapter_grant(&observed_adapter.database());
        let custody = StrictCoordinatorV2Root::new("t097-orphan-grant-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
            "ORPHAN_COORDINATOR_GRANT",
            "INVARIANT_CONFLICT",
        );
    }

    // 2. Orphan coordinator receipt.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-orphan-receipt-trusted",
            T097CoordinatorLifecycleForTestV1::Consumed,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-orphan-receipt-observed");
        let observed_adapter = trusted_adapter.fork("t097-orphan-receipt-observed");
        delete_adapter_receipt(&observed_adapter.database());
        let custody = StrictCoordinatorV2Root::new("t097-orphan-receipt-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Consumed,
            "ORPHAN_COORDINATOR_RECEIPT",
            "INVARIANT_CONFLICT",
        );
    }

    // 3. Same grant identity, conflicting canonical digest.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-grant-digest-trusted",
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-grant-digest-observed");
        let observed_adapter = trusted_adapter.fork("t097-grant-digest-observed");
        mutate_adapter_grant_digest(&observed_adapter.database());
        let custody = StrictCoordinatorV2Root::new("t097-grant-digest-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
            "GRANT_DIGEST_CONFLICT",
            "INVARIANT_CONFLICT",
        );
    }

    // 4. Same receipt identity, conflicting canonical digest.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-receipt-digest-trusted",
            T097CoordinatorLifecycleForTestV1::Consumed,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-receipt-digest-observed");
        let observed_adapter = trusted_adapter.fork("t097-receipt-digest-observed");
        mutate_adapter_receipt_digest(&observed_adapter.database());
        let custody = StrictCoordinatorV2Root::new("t097-receipt-digest-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Consumed,
            "RECEIPT_DIGEST_CONFLICT",
            "INVARIANT_CONFLICT",
        );
    }

    // 5. Same immutable grant/digest, but its actual retained adapter generation changes.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-cross-generation-trusted",
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-cross-generation-observed");
        let observed_adapter = trusted_adapter.fork("t097-cross-generation-observed");
        mutate_adapter_actual_relation_generation(&observed_adapter.database());
        let custody = StrictCoordinatorV2Root::new("t097-cross-generation-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
            "CROSS_GENERATION_CONFLICT",
            "INVARIANT_CONFLICT",
        );
    }

    // 6. A valid old same-root copy is below a valid advanced trusted generation.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-store-rollback-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-store-rollback-observed");
        let observed_adapter = trusted_adapter.fork("t097-store-rollback-observed");
        advance_migration_history(&trusted_coordinator.database());
        drop(
            trusted_coordinator
                .reopen()
                .expect("T097 generation-two trusted branch is locally valid"),
        );
        drop(
            observed_coordinator
                .reopen()
                .expect("T097 old generation-one branch is locally valid"),
        );
        let custody = StrictCoordinatorV2Root::new("t097-store-rollback-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "COORDINATOR_STORE_ROLLBACK",
            "STORE_UNHEALTHY",
        );
    }

    // 7. A different valid root can be internally coherent but still conflicts with the
    // trusted root lineage.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-root-rollback-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let (observed_coordinator, observed_adapter) = materialize_lifecycle_roots(
            "t097-root-rollback-observed",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let custody = StrictCoordinatorV2Root::new("t097-root-rollback-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "COORDINATOR_ROOT_ROLLBACK",
            "STORE_UNHEALTHY",
        );
    }

    // 8. Store generation did not regress, but one retained domain axis did.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-generation-rollback-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-generation-rollback-observed");
        let observed_adapter = trusted_adapter.fork("t097-generation-rollback-observed");
        advance_migration_history(&trusted_coordinator.database());
        advance_store_without_history_axis(&observed_coordinator.database());
        let custody = StrictCoordinatorV2Root::new("t097-generation-rollback-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "COORDINATOR_GENERATION_ROLLBACK",
            "STORE_UNHEALTHY",
        );
    }

    // 9. One immutable migration row was physically removed while its high-water remains.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-history-truncated-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-history-truncated-observed");
        let observed_adapter = trusted_adapter.fork("t097-history-truncated-observed");
        truncate_migration_history(&observed_coordinator.database());
        let custody = StrictCoordinatorV2Root::new("t097-history-truncated-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "COORDINATOR_HISTORY_TRUNCATED",
            "STORE_UNHEALTHY",
        );
    }

    // 10. Valid A/B branches reuse generation one with a different immutable receipt.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-generation-reuse-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-generation-reuse-observed");
        let observed_adapter = trusted_adapter.fork("t097-generation-reuse-observed");
        fork_migration_history_at_same_generation(&observed_coordinator.database());
        drop(
            trusted_coordinator
                .reopen()
                .expect("T097 trusted generation-one branch stays locally valid"),
        );
        drop(
            observed_coordinator
                .reopen()
                .expect("T097 conflicting generation-one branch stays locally valid"),
        );
        let custody = StrictCoordinatorV2Root::new("t097-generation-reuse-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "COORDINATOR_GENERATION_REUSED",
            "STORE_UNHEALTHY",
        );
    }

    // 11. Both stores are locally valid and empty, but the adapter root in the paired cut
    // is not the trusted adapter root.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-cross-store-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-cross-store-observed");
        let (_other_coordinator, observed_adapter) = materialize_lifecycle_roots(
            "t097-cross-store-observed-adapter",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let custody = StrictCoordinatorV2Root::new("t097-cross-store-custody");
        drop(
            trusted_coordinator
                .reopen()
                .expect("T097 coordinator is locally coherent before paired audit"),
        );
        drop(
            observed_adapter
                .reopen()
                .expect("T097 observed adapter is locally coherent before paired audit"),
        );
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "CROSS_STORE_DISAGREEMENT",
            "INVARIANT_CONFLICT",
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_local_fence_survives_external_custody_failure_and_retry_repairs_it() {
    let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
        "t097-custody-pending-trusted",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let observed_coordinator = trusted_coordinator.fork("t097-custody-pending-observed");
    let (_other_coordinator, observed_adapter) = materialize_lifecycle_roots(
        "t097-custody-pending-other-adapter",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let custody = StrictCoordinatorV2Root::new("t097-custody-pending-custody");
    let custody_writer =
        Connection::open(custody.database()).expect("T097 custody contention handle opens");
    custody_writer
        .execute_batch("BEGIN IMMEDIATE")
        .expect("T097 custody writer slot is held before the audit");

    let failure = classify_and_retain_t097_coordinator_history_for_test_v1(
        &trusted_coordinator.database(),
        &trusted_adapter.database(),
        &observed_coordinator.database(),
        &observed_adapter.database(),
        &custody.database(),
        T097CoordinatorLifecycleForTestV1::Prepared,
    )
    .unwrap_err();
    assert_eq!(failure, "t097-locally-fenced-custody-pending");
    assert_eq!(
        observed_coordinator.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed,
        "external custody failure cannot leave the observed source authoritative"
    );
    let local = retained_t097_base_row(&observed_coordinator.database());
    assert_eq!(local.reason, "INVARIANT_CONFLICT");
    let external_count: i64 = custody_writer
        .query_row(
            "SELECT COUNT(*) FROM preparation_quarantines
             WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
            [],
            |row| row.get(0),
        )
        .expect("T097 locked external custody remains readable");
    assert_eq!(external_count, 0);
    custody_writer
        .execute_batch("ROLLBACK")
        .expect("T097 custody writer slot releases before repair");

    let repaired = observe_t097(
        &trusted_coordinator,
        &trusted_adapter,
        &observed_coordinator,
        &observed_adapter,
        &custody,
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    assert_eq!(
        repaired.corruption_reason_code(),
        Some("CROSS_STORE_DISAGREEMENT")
    );
    assert_eq!(repaired.base_reason_code(), Some("INVARIANT_CONFLICT"));
    assert_eq!(repaired.retained_row_count(), 1);
    let external = retained_t097_base_row(&custody.database());
    assert_eq!(local.attempt_id, external.attempt_id);
    assert_eq!(
        local.operation_binding_digest,
        external.operation_binding_digest
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_adapter_writer_cannot_commit_between_projection_and_local_fence() {
    let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
        "t097-adapter-writer-trusted",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let observed_coordinator = trusted_coordinator.fork("t097-adapter-writer-observed");
    let (_other_coordinator, observed_adapter) = materialize_lifecycle_roots(
        "t097-adapter-writer-other",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let custody = StrictCoordinatorV2Root::new("t097-adapter-writer-custody");
    let before_generation: i64 = Connection::open(observed_adapter.database())
        .expect("T097 observed adapter reads before concurrent audit")
        .query_row(
            "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("T097 observed adapter generation reads");

    let reached = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    install_t097_after_projection_barrier_for_test_v1(Arc::clone(&reached), Arc::clone(&release))
        .expect("T097 deterministic projection barrier installs");
    let paths = (
        trusted_coordinator.database(),
        trusted_adapter.database(),
        observed_coordinator.database(),
        observed_adapter.database(),
        custody.database(),
    );
    let scanner = std::thread::spawn(move || {
        classify_and_retain_t097_coordinator_history_for_test_v1(
            &paths.0,
            &paths.1,
            &paths.2,
            &paths.3,
            &paths.4,
            T097CoordinatorLifecycleForTestV1::Prepared,
        )
    });

    reached.wait();
    let writer = Connection::open(observed_adapter.database())
        .expect("T097 concurrent adapter writer opens while audit is paused");
    writer
        .busy_timeout(Duration::ZERO)
        .expect("T097 concurrent adapter writer is fail-fast");
    let writer_error = writer
        .execute_batch(
            "BEGIN IMMEDIATE;
             UPDATE adapter_store_meta
             SET store_generation = store_generation + 1
             WHERE singleton = 1;
             COMMIT;",
        )
        .expect_err("T097 adapter writer must be excluded until source fence commit");
    assert!(matches!(
        writer_error,
        rusqlite::Error::SqliteFailure(ref failure, _)
            if matches!(failure.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    ));
    release.wait();
    let retained = scanner
        .join()
        .expect("T097 deterministic scanner thread joins")
        .expect("T097 deterministic scanner retains the exact verdict");
    clear_t097_after_projection_barrier_for_test_v1()
        .expect("T097 deterministic projection barrier clears");

    assert_eq!(
        retained.corruption_reason_code(),
        Some("CROSS_STORE_DISAGREEMENT")
    );
    assert_eq!(retained.base_reason_code(), Some("INVARIANT_CONFLICT"));
    assert_eq!(retained.retained_row_count(), 1);
    let after_generation: i64 = Connection::open(observed_adapter.database())
        .expect("T097 observed adapter reads after concurrent audit")
        .query_row(
            "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("T097 observed adapter generation rereads");
    assert_eq!(after_generation, before_generation);
    assert_eq!(
        observed_coordinator.reopen().unwrap_err(),
        CoordinatorStoreOpenErrorV1::InvariantFailed
    );
    let local = retained_t097_base_row(&observed_coordinator.database());
    let external = retained_t097_base_row(&custody.database());
    assert_eq!(local.reason, "INVARIANT_CONFLICT");
    assert_eq!(local.attempt_id, external.attempt_id);
    assert_eq!(
        local.operation_binding_digest,
        external.operation_binding_digest
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_preopened_handle_refuses_handoff_before_transport_after_source_fence() {
    let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
        "t097-live-handle-trusted",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let observed_coordinator = trusted_coordinator.fork("t097-live-handle-observed");
    let live_handle = observed_coordinator
        .reopen()
        .expect("T097 observed source is healthy before the cross-store audit");
    let (_other_coordinator, observed_adapter) = materialize_lifecycle_roots(
        "t097-live-handle-other-adapter",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let custody = StrictCoordinatorV2Root::new("t097-live-handle-custody");

    let retained = observe_t097(
        &trusted_coordinator,
        &trusted_adapter,
        &observed_coordinator,
        &observed_adapter,
        &custody,
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    assert_eq!(
        retained.corruption_reason_code(),
        Some("CROSS_STORE_DISAGREEMENT")
    );
    let calls = AtomicU64::new(0);
    let transport = CountingT097TransportV1 { calls: &calls };
    assert!(matches!(
        live_handle.handoff_pending_dispatch_v1([0; 32], DEADLINE_MONOTONIC_MS, &transport),
        CoordinatorDispatchHandoffOutcomeV1::Unhealthy
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the permanent local fence must fail before any transport method is called"
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_scans_every_real_relationship_not_only_the_first_match() {
    // A is the strict production relationship. B sorts after it and exists only in the
    // observed coordinator, so the exhaustive scanner must report the later orphan.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-multi-orphan-trusted",
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-multi-orphan-observed");
        let observed_adapter = trusted_adapter.fork("t097-multi-orphan-observed");
        append_observed_coordinator_grant(&observed_coordinator.database());
        let custody = StrictCoordinatorV2Root::new("t097-multi-orphan-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
            "ORPHAN_COORDINATOR_GRANT",
            "INVARIANT_CONFLICT",
        );
    }

    // A still matches first. B exists on both sides but its later adapter digest differs,
    // so the exact digest class must win over a generic inventory disagreement.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-multi-digest-trusted",
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-multi-digest-observed");
        let observed_adapter = trusted_adapter.fork("t097-multi-digest-observed");
        append_observed_coordinator_grant(&observed_coordinator.database());
        append_observed_adapter_grant(&observed_adapter.database(), [0xfc; 32]);
        let custody = StrictCoordinatorV2Root::new("t097-multi-digest-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
            "GRANT_DIGEST_CONFLICT",
            "INVARIANT_CONFLICT",
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn t097_exact_checkpoint_refuses_strict_valid_newer_or_invalid_branches_without_false_custody() {
    // A synthetic but complete strict-schema-valid migration projection represents a distinct
    // checkpoint. It is neither clean at the retained checkpoint nor corruption, and creates
    // no local or external custody. This fixture does not claim a runtime migration transition.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-checkpoint-advance-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-checkpoint-advance-observed");
        let observed_adapter = trusted_adapter.fork("t097-checkpoint-advance-observed");
        advance_migration_history(&observed_coordinator.database());
        drop(
            observed_coordinator
                .reopen()
                .expect("T097 newer observed checkpoint remains strict V2"),
        );
        let custody = StrictCoordinatorV2Root::new("t097-checkpoint-advance-custody");

        assert_eq!(
            classify_and_retain_t097_coordinator_history_for_test_v1(
                &trusted_coordinator.database(),
                &trusted_adapter.database(),
                &observed_coordinator.database(),
                &observed_adapter.database(),
                &custody.database(),
                T097CoordinatorLifecycleForTestV1::Prepared,
            )
            .unwrap_err(),
            "CHECKPOINT_MISMATCH"
        );
        for database in [observed_coordinator.database(), custody.database()] {
            let retained: i64 = Connection::open(database)
                .expect("T097 checkpoint-mismatch root opens for custody count")
                .query_row(
                    "SELECT COUNT(*) FROM preparation_quarantines
                     WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
                    [],
                    |row| row.get(0),
                )
                .expect("T097 checkpoint-mismatch custody count reads");
            assert_eq!(
                retained, 0,
                "a newer strict checkpoint must create no corruption custody"
            );
        }
        drop(
            observed_coordinator
                .reopen()
                .expect("T097 mismatch leaves the observed coordinator authoritative"),
        );
        drop(
            custody
                .reopen()
                .expect("T097 mismatch leaves independent custody empty and strict"),
        );
    }

    // A second migration row is not a strict V2 checkpoint. The verifier running on the
    // locked observation refuses it before any false clean result or fence.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-checkpoint-invalid-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-checkpoint-invalid-observed");
        let observed_adapter = trusted_adapter.fork("t097-checkpoint-invalid-observed");
        append_invalid_second_migration_history(&observed_coordinator.database());
        assert_eq!(
            observed_coordinator.reopen().unwrap_err(),
            CoordinatorStoreOpenErrorV1::InvariantFailed,
            "T097 extra migration row is not a strict-valid progression"
        );
        let custody = StrictCoordinatorV2Root::new("t097-checkpoint-invalid-custody");

        assert_eq!(
            classify_and_retain_t097_coordinator_history_for_test_v1(
                &trusted_coordinator.database(),
                &trusted_adapter.database(),
                &observed_coordinator.database(),
                &observed_adapter.database(),
                &custody.database(),
                T097CoordinatorLifecycleForTestV1::Prepared,
            )
            .unwrap_err(),
            "t097-observation-invalid"
        );
        for database in [observed_coordinator.database(), custody.database()] {
            let retained: i64 = Connection::open(database)
                .expect("T097 invalid-checkpoint root opens for custody count")
                .query_row(
                    "SELECT COUNT(*) FROM preparation_quarantines
                     WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
                    [],
                    |row| row.get(0),
                )
                .expect("T097 invalid-checkpoint custody count reads");
            assert_eq!(retained, 0, "an invalid checkpoint must create no custody");
        }
    }

    // Removing a trusted keyed row remains truncation.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-keyed-missing-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-keyed-missing-observed");
        let observed_adapter = trusted_adapter.fork("t097-keyed-missing-observed");
        truncate_migration_history(&observed_coordinator.database());
        let custody = StrictCoordinatorV2Root::new("t097-keyed-missing-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "COORDINATOR_HISTORY_TRUNCATED",
            "STORE_UNHEALTHY",
        );
    }

    // Rebinding the exact trusted key at the same generation remains generation reuse.
    {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            "t097-keyed-changed-trusted",
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let observed_coordinator = trusted_coordinator.fork("t097-keyed-changed-observed");
        let observed_adapter = trusted_adapter.fork("t097-keyed-changed-observed");
        fork_migration_history_at_same_generation(&observed_coordinator.database());
        let custody = StrictCoordinatorV2Root::new("t097-keyed-changed-custody");
        assert_t097_corruption_case(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            T097CoordinatorLifecycleForTestV1::Prepared,
            "COORDINATOR_GENERATION_REUSED",
            "STORE_UNHEALTHY",
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_refuses_every_path_alias_before_observation_or_custody() {
    let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
        "t097-alias-trusted",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let observed_coordinator = trusted_coordinator.fork("t097-alias-observed");
    let observed_adapter = trusted_adapter.fork("t097-alias-observed");
    let custody = StrictCoordinatorV2Root::new("t097-alias-custody");
    let hard_link_alias = observed_coordinator.path.join("coordinator-alias.sqlite3");
    fs::hard_link(observed_coordinator.database(), &hard_link_alias)
        .expect("T097 hard-link alias creates inside disposable observed root");

    for paths in [
        (
            trusted_coordinator.database(),
            trusted_adapter.database(),
            trusted_coordinator.database(),
            observed_adapter.database(),
            custody.database(),
        ),
        (
            trusted_coordinator.database(),
            trusted_adapter.database(),
            observed_coordinator.database(),
            observed_adapter.database(),
            observed_coordinator.database(),
        ),
        (
            trusted_coordinator.database(),
            trusted_adapter.database(),
            observed_coordinator.database(),
            observed_adapter.database(),
            hard_link_alias,
        ),
    ] {
        assert_eq!(
            classify_and_retain_t097_coordinator_history_for_test_v1(
                &paths.0,
                &paths.1,
                &paths.2,
                &paths.3,
                &paths.4,
                T097CoordinatorLifecycleForTestV1::Prepared,
            )
            .unwrap_err(),
            "t097-database-alias-refused"
        );
    }
    drop(
        custody
            .reopen()
            .expect("alias refusal cannot poison the healthy custody root"),
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_refuses_unverified_trusted_checkpoints_before_comparison() {
    let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
        "t097-invalid-trusted",
        T097CoordinatorLifecycleForTestV1::AdapterReceived,
    );
    let observed_coordinator = trusted_coordinator.fork("t097-invalid-observed");
    let observed_adapter = trusted_adapter.fork("t097-invalid-observed");
    let custody = StrictCoordinatorV2Root::new("t097-invalid-custody");
    Connection::open(trusted_coordinator.database())
        .expect("T097 trusted coordinator opens for guard loss")
        .execute_batch("DROP TRIGGER dispatch_grants_no_delete;")
        .expect("T097 trusted coordinator guard is removed out of band");
    assert_eq!(
        classify_and_retain_t097_coordinator_history_for_test_v1(
            &trusted_coordinator.database(),
            &trusted_adapter.database(),
            &observed_coordinator.database(),
            &observed_adapter.database(),
            &custody.database(),
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
        )
        .unwrap_err(),
        "t097-trusted-coordinator-invalid"
    );

    let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
        "t097-invalid-adapter-trusted",
        T097CoordinatorLifecycleForTestV1::AdapterReceived,
    );
    let observed_coordinator = trusted_coordinator.fork("t097-invalid-adapter-observed");
    let observed_adapter = trusted_adapter.fork("t097-invalid-adapter-observed");
    Connection::open(trusted_adapter.database())
        .expect("T097 trusted adapter opens for guard loss")
        .execute_batch("DROP TRIGGER grant_inbox_no_delete;")
        .expect("T097 trusted adapter guard is removed out of band");
    assert_eq!(
        classify_and_retain_t097_coordinator_history_for_test_v1(
            &trusted_coordinator.database(),
            &trusted_adapter.database(),
            &observed_coordinator.database(),
            &observed_adapter.database(),
            &custody.database(),
            T097CoordinatorLifecycleForTestV1::AdapterReceived,
        )
        .unwrap_err(),
        "t097-trusted-adapter-invalid"
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t097_observer_accepts_all_five_legitimate_t096_lifecycle_shapes() {
    let cases = [
        T097CoordinatorLifecycleForTestV1::Prepared,
        T097CoordinatorLifecycleForTestV1::Dispatching,
        T097CoordinatorLifecycleForTestV1::AdapterReceived,
        T097CoordinatorLifecycleForTestV1::Consumed,
        T097CoordinatorLifecycleForTestV1::Ambiguous,
    ];
    for (ordinal, lifecycle) in cases.into_iter().enumerate() {
        let (coordinator, adapter) =
            materialize_lifecycle_roots(&format!("t097-clean-{ordinal}"), lifecycle);
        let observed_coordinator = coordinator.fork(&format!("t097-clean-observed-{ordinal}"));
        let observed_adapter = adapter.fork(&format!("t097-clean-observed-{ordinal}"));
        let custody = StrictCoordinatorV2Root::new(&format!("t097-clean-custody-{ordinal}"));
        let observed = observe_t097(
            &coordinator,
            &adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody,
            lifecycle,
        );
        assert_eq!(observed.corruption_reason_code(), None);
        assert_eq!(observed.base_reason_code(), None);
        assert_eq!(observed.created_generation(), None);
        assert_eq!(observed.retained_row_count(), 0);
        assert!(observed.execution_refused());
        drop(
            custody
                .reopen()
                .expect("clean lifecycle must not append a corruption fence"),
        );
    }
}

#[cfg(feature = "test-fault-injection")]
fn existing_coordinator_config_v1(root: &StrictCoordinatorV2Root) -> CoordinatorStoreConfigV1 {
    CoordinatorStoreConfigV1::try_new_existing_attested(root.path.clone(), root.identity, 25)
        .expect("T097 production caller coordinator root remains provisioner-attested")
}

#[cfg(feature = "test-fault-injection")]
fn existing_adapter_config_v1(root: &StrictAdapterRootV1) -> AdapterInboxStoreConfigV1 {
    AdapterInboxStoreConfigV1::try_new_existing_attested(root.path.clone(), root.identity, 25)
        .expect("T097 production caller adapter root remains provisioner-attested")
}

#[cfg(feature = "test-fault-injection")]
fn adapter_audit_lifecycle_v1(
    lifecycle: T097CoordinatorLifecycleForTestV1,
) -> AdapterCorruptionAuditLifecycleV1 {
    match lifecycle {
        T097CoordinatorLifecycleForTestV1::Prepared => AdapterCorruptionAuditLifecycleV1::Prepared,
        T097CoordinatorLifecycleForTestV1::Dispatching => {
            AdapterCorruptionAuditLifecycleV1::Dispatching
        }
        T097CoordinatorLifecycleForTestV1::AdapterReceived => {
            AdapterCorruptionAuditLifecycleV1::AdapterReceived
        }
        T097CoordinatorLifecycleForTestV1::Consumed => AdapterCorruptionAuditLifecycleV1::Consumed,
        T097CoordinatorLifecycleForTestV1::Ambiguous => {
            AdapterCorruptionAuditLifecycleV1::Ambiguous
        }
    }
}

#[cfg(feature = "test-fault-injection")]
fn adapter_audit_selection_v1(
    coordinator: &StrictCoordinatorV2Root,
    lifecycle: T097CoordinatorLifecycleForTestV1,
) -> AdapterCorruptionAuditSelectionV1 {
    if matches!(lifecycle, T097CoordinatorLifecycleForTestV1::Prepared) {
        return AdapterCorruptionAuditSelectionV1::try_new(
            [0xd1; 32],
            "operation:t097-prepared",
            [0xd2; 32],
            None,
        )
        .expect("T097 prepared selection is bounded and deliberately absent");
    }

    let connection = Connection::open(coordinator.database())
        .expect("T097 strict coordinator opens for exact relationship selection");
    let (grant_id, operation_id, dispatch_attempt_id): (Vec<u8>, String, Vec<u8>) = connection
        .query_row(
            "SELECT grant_id, operation_id, dispatch_attempt_id
             FROM dispatch_grants ORDER BY grant_id LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("T097 non-prepared lifecycle retains one coordinator grant");
    let receipt_id = if matches!(lifecycle, T097CoordinatorLifecycleForTestV1::Consumed) {
        Some(
            connection
                .query_row(
                    "SELECT receipt_id FROM dispatch_receipts
                     WHERE grant_id = ?1 ORDER BY receipt_id LIMIT 1",
                    [grant_id.as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .expect("T097 consumed lifecycle retains one coordinator receipt")
                .try_into()
                .expect("T097 production receipt identity remains exact"),
        )
    } else {
        None
    };
    AdapterCorruptionAuditSelectionV1::try_new(
        grant_id
            .try_into()
            .expect("T097 production grant identity remains exact"),
        operation_id,
        dispatch_attempt_id
            .try_into()
            .expect("T097 production dispatch-attempt identity remains exact"),
        receipt_id,
    )
    .expect("T097 production relationship selection is bounded")
}

#[cfg(feature = "test-fault-injection")]
struct ExactAdapterCorruptionPauseV1 {
    evidence: AdapterCorruptionAuditPauseEvidenceV1,
    capture_count: u64,
    recheck_count: u64,
    fail_recheck: Option<u64>,
}

#[cfg(feature = "test-fault-injection")]
impl ExactAdapterCorruptionPauseV1 {
    fn new(binding_tag: u8, fail_recheck: Option<u64>) -> Self {
        Self {
            evidence: AdapterCorruptionAuditPauseEvidenceV1::try_new(1, [binding_tag; 32])
                .expect("T097 synthetic PAUSE evidence is bounded and non-zero"),
            capture_count: 0,
            recheck_count: 0,
            fail_recheck,
        }
    }
}

#[cfg(feature = "test-fault-injection")]
impl AdapterCorruptionAuditPauseV1 for ExactAdapterCorruptionPauseV1 {
    fn capture_adapter_corruption_audit_pause_v1(
        &mut self,
    ) -> Result<AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditErrorV1> {
        self.capture_count += 1;
        Ok(self.evidence)
    }

    fn recheck_adapter_corruption_audit_pause_v1(
        &mut self,
        expected: &AdapterCorruptionAuditPauseEvidenceV1,
    ) -> Result<(), AdapterCorruptionAuditErrorV1> {
        self.recheck_count += 1;
        if expected != &self.evidence || self.fail_recheck == Some(self.recheck_count) {
            return Err(AdapterCorruptionAuditErrorV1::Unavailable);
        }
        Ok(())
    }
}

#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)]
fn audit_adapter_through_production_coordinator_v1(
    trusted_coordinator: &StrictCoordinatorV2Root,
    trusted_adapter: &StrictAdapterRootV1,
    observed_coordinator: &StrictCoordinatorV2Root,
    observed_adapter: &StrictAdapterRootV1,
    custody_adapter: &StrictAdapterRootV1,
    lifecycle: T097CoordinatorLifecycleForTestV1,
    pause: &mut ExactAdapterCorruptionPauseV1,
) -> Result<AdapterCorruptionAuditOutcomeV1, AdapterCorruptionAuditErrorV1> {
    let trusted_store = trusted_coordinator
        .reopen()
        .expect("T097 production caller trusted coordinator strictly opens");
    let trusted_adapter_store = trusted_adapter
        .reopen()
        .expect("T097 production caller trusted adapter strictly opens");
    let selection = adapter_audit_selection_v1(trusted_coordinator, lifecycle);
    trusted_store.audit_and_retain_adapter_corruption_under_pause_v1(
        pause,
        existing_coordinator_config_v1(observed_coordinator),
        &trusted_adapter_store,
        existing_adapter_config_v1(observed_adapter),
        existing_adapter_config_v1(custody_adapter),
        &selection,
        adapter_audit_lifecycle_v1(lifecycle),
        DEADLINE_MONOTONIC_MS,
    )
}

#[cfg(feature = "test-fault-injection")]
fn retained_global_adapter_custody_v1(
    root: &StrictAdapterRootV1,
) -> (Vec<u8>, Vec<u8>, String, i64, Option<i64>) {
    let connection = Connection::open(root.database())
        .expect("T097 adapter custody opens for exact redacted readback");
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM inbox_quarantines WHERE grant_id IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("T097 global adapter custody count reads");
    assert_eq!(count, 1, "T097 retains exactly one global adapter incident");
    connection
        .query_row(
            "SELECT quarantine_id, evidence_digest, public_reason_code,
                    quarantine_generation, resolved_generation
             FROM inbox_quarantines WHERE grant_id IS NULL",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .expect("T097 exact global adapter custody reads")
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_coordinator_caller_accepts_all_five_real_t096_lifecycles() {
    let lifecycles = [
        T097CoordinatorLifecycleForTestV1::Prepared,
        T097CoordinatorLifecycleForTestV1::Dispatching,
        T097CoordinatorLifecycleForTestV1::AdapterReceived,
        T097CoordinatorLifecycleForTestV1::Consumed,
        T097CoordinatorLifecycleForTestV1::Ambiguous,
    ];
    for (ordinal, lifecycle) in lifecycles.into_iter().enumerate() {
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            &format!("t097-production-caller-clean-trusted-{ordinal}"),
            lifecycle,
        );
        let observed_coordinator =
            trusted_coordinator.fork(&format!("t097-production-caller-clean-coord-{ordinal}"));
        let observed_adapter =
            trusted_adapter.fork(&format!("t097-production-caller-clean-adapter-{ordinal}"));
        let (_custody_coordinator, custody_adapter) = materialize_lifecycle_roots(
            &format!("t097-production-caller-clean-custody-{ordinal}"),
            T097CoordinatorLifecycleForTestV1::Prepared,
        );
        let mut pause = ExactAdapterCorruptionPauseV1::new(
            0x70_u8.saturating_add(u8::try_from(ordinal).expect("ordinal fits")),
            None,
        );

        let outcome = audit_adapter_through_production_coordinator_v1(
            &trusted_coordinator,
            &trusted_adapter,
            &observed_coordinator,
            &observed_adapter,
            &custody_adapter,
            lifecycle,
            &mut pause,
        )
        .expect("T097 production coordinator caller accepts exact clean lifecycle");
        assert!(matches!(
            outcome,
            AdapterCorruptionAuditOutcomeV1::NoCorruptionObserved
        ));
        assert_eq!(pause.capture_count, 1);
        assert_eq!(pause.recheck_count, 3);
        drop(
            observed_coordinator
                .reopen()
                .expect("T097 clean observed coordinator remains strict V2"),
        );
        drop(
            observed_adapter
                .reopen()
                .expect("T097 clean observed adapter remains strict"),
        );
        drop(
            custody_adapter
                .reopen()
                .expect("T097 clean custody adapter remains empty and strict"),
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_coordinator_caller_fences_cross_store_adapter_only_and_retains_exact_custody() {
    let lifecycle = T097CoordinatorLifecycleForTestV1::AdapterReceived;
    let (trusted_coordinator, trusted_adapter) =
        materialize_lifecycle_roots("t097-production-caller-conflict-trusted", lifecycle);
    let observed_coordinator =
        trusted_coordinator.fork("t097-production-caller-conflict-coordinator");
    let (_other_coordinator, observed_adapter) =
        materialize_lifecycle_roots("t097-production-caller-conflict-adapter", lifecycle);
    let (_custody_coordinator, custody_adapter) = materialize_lifecycle_roots(
        "t097-production-caller-conflict-custody",
        T097CoordinatorLifecycleForTestV1::Prepared,
    );
    let mut pause = ExactAdapterCorruptionPauseV1::new(0x91, None);

    let outcome = audit_adapter_through_production_coordinator_v1(
        &trusted_coordinator,
        &trusted_adapter,
        &observed_coordinator,
        &observed_adapter,
        &custody_adapter,
        lifecycle,
        &mut pause,
    )
    .expect("T097 production caller retains the cross-store adapter conflict");
    let AdapterCorruptionAuditOutcomeV1::Quarantined(retained) = outcome else {
        panic!("T097 cross-store adapter conflict must retain permanent custody");
    };
    assert_eq!(retained.reason_code(), "ADAPTER_ROOT_ROLLBACK");
    assert_eq!(retained.quarantine_generation(), 1);
    assert_eq!(pause.capture_count, 1);
    assert_eq!(pause.recheck_count, 3);
    let local_custody = retained_global_adapter_custody_v1(&observed_adapter);
    let external_custody = retained_global_adapter_custody_v1(&custody_adapter);
    assert_eq!(local_custody.0, external_custody.0);
    assert_eq!(local_custody.1, external_custody.1);
    assert_eq!(local_custody.2, external_custody.2);
    assert_eq!(local_custody.4, external_custody.4);
    assert_eq!(
        retained.quarantine_generation(),
        u64::try_from(external_custody.3).expect("T097 custody generation remains bounded"),
        "T097 returned generation belongs to the exact independent custody row"
    );
    assert_eq!(
        observed_adapter.reopen().unwrap_err(),
        AdapterInboxStoreOpenErrorV1::InvariantFailed,
        "T097 observed adapter source is permanently fenced"
    );
    assert_eq!(
        custody_adapter.reopen().unwrap_err(),
        AdapterInboxStoreOpenErrorV1::InvariantFailed,
        "T097 independent adapter custody is permanently fenced"
    );
    drop(
        observed_coordinator
            .reopen()
            .expect("T097 projection-only audit leaves the complete coordinator V2 strict"),
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_coordinator_caller_fails_closed_on_each_pause_recheck() {
    for fail_recheck in [1_u64, 2_u64] {
        let lifecycle = T097CoordinatorLifecycleForTestV1::Prepared;
        let (trusted_coordinator, trusted_adapter) = materialize_lifecycle_roots(
            &format!("t097-production-caller-pause-trusted-{fail_recheck}"),
            lifecycle,
        );
        let observed_coordinator = trusted_coordinator.fork(&format!(
            "t097-production-caller-pause-coordinator-{fail_recheck}"
        ));
        let observed_adapter = trusted_adapter.fork(&format!(
            "t097-production-caller-pause-adapter-{fail_recheck}"
        ));
        let (_custody_coordinator, custody_adapter) = materialize_lifecycle_roots(
            &format!("t097-production-caller-pause-custody-{fail_recheck}"),
            lifecycle,
        );
        let mut pause = ExactAdapterCorruptionPauseV1::new(
            0xa0_u8.saturating_add(u8::try_from(fail_recheck).expect("recheck fits")),
            Some(fail_recheck),
        );

        assert_eq!(
            audit_adapter_through_production_coordinator_v1(
                &trusted_coordinator,
                &trusted_adapter,
                &observed_coordinator,
                &observed_adapter,
                &custody_adapter,
                lifecycle,
                &mut pause,
            )
            .unwrap_err(),
            AdapterCorruptionAuditErrorV1::Unavailable
        );
        assert_eq!(pause.capture_count, 1);
        assert_eq!(pause.recheck_count, fail_recheck + 1);
        drop(
            observed_coordinator
                .reopen()
                .expect("T097 PAUSE failure leaves no coordinator mutation"),
        );
        drop(
            observed_adapter
                .reopen()
                .expect("T097 PAUSE failure returns no adapter activation or fence"),
        );
        drop(
            custody_adapter
                .reopen()
                .expect("T097 PAUSE failure leaves independent custody empty"),
        );
    }
}

#[test]
fn production_coordinator_cross_store_verifier_must_be_non_authoritative() {
    let quarantine = required_production_source(
        "dispatch_quarantine.rs",
        "T078 coordinator cross-store verifier and quarantine custody",
    );
    let crate_root = required_production_source("lib.rs", "T078 coordinator module wiring");
    assert!(
        crate_root.contains("mod dispatch_quarantine;"),
        "T073 RED: coordinator crate root must compile src/dispatch_quarantine.rs"
    );
    for required in [
        "DispatchCorruptionKindV1",
        "DispatchCorruptionDispositionV1",
        "verify_cross_store_dispatch_history_v1",
        "retain_dispatch_corruption_quarantine_v1",
        "Quarantined",
        "Refused",
        "ORPHAN_COORDINATOR_GRANT",
        "ORPHAN_COORDINATOR_RECEIPT",
        "GRANT_DIGEST_CONFLICT",
        "RECEIPT_DIGEST_CONFLICT",
        "CROSS_GENERATION_CONFLICT",
        "COORDINATOR_STORE_ROLLBACK",
        "COORDINATOR_ROOT_ROLLBACK",
        "COORDINATOR_GENERATION_ROLLBACK",
        "COORDINATOR_HISTORY_TRUNCATED",
        "COORDINATOR_GENERATION_REUSED",
        "CROSS_STORE_DISAGREEMENT",
    ] {
        assert!(
            quarantine.contains(required),
            "T073 RED: coordinator corruption custody omits `{required}`"
        );
    }
    for forbidden in [
        "ReadyDispatchContextV1",
        "VerifiedDispatchAuthorityV1",
        "DispatchGrantPermitV1",
        "ExecutionPermit",
        "activate_v1",
        "redeliver_v1",
    ] {
        assert!(
            !quarantine.contains(forbidden),
            "T073: corruption/quarantine code must not expose activation authority `{forbidden}`"
        );
    }
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T073 RED: missing future production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0_usize;
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
    assert_eq!(block_depth, 0, "T073 production comments are balanced");
    output
}
