//! T052 red tests for the closed v1 retention policy.
//!
//! The fixture uses the real preparation/failure transaction seams and the reviewed
//! schema. US3 contributes only the crate-private true-orphan insertion seam; the
//! provider and retirement protocol remain covered by `recovery_integration.rs`.

#[path = "../src/budget.rs"]
mod budget;
#[path = "../src/comparison_digest.rs"]
mod comparison_digest;
#[path = "../src/failure.rs"]
mod failure;
#[path = "../src/outbox.rs"]
mod outbox;
#[path = "../src/prepare.rs"]
mod prepare;
#[path = "../src/quarantine.rs"]
mod quarantine;
#[path = "../src/readback.rs"]
mod readback;
#[cfg(feature = "test-fault-injection")]
#[path = "../src/test_fault.rs"]
mod test_fault;
#[path = "../src/transition.rs"]
mod transition;

use failure::{
    fail_synthetic_before_dispatch_v1, SyntheticKnownFailureCaseV1, SyntheticNoDispatchGuardCaseV1,
};
use helix_contracts::Sha256Digest;
use helix_plan_preparation::{PreparationCommitOutcomeV1, PreparationFailureOutcomeV1};
use prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use quarantine::{retain_synthetic_orphan_v1, SyntheticOrphanInputV1};
use rusqlite::{params, Connection, TransactionBehavior};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const NOW_MONOTONIC_MS: u64 = 1_000;
const GUARD_DEADLINE_MONOTONIC_MS: u64 = 10_000;
const REVOCATION_GENERATION: u64 = 17;
const STORE_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

struct SyntheticDatabaseV1 {
    directory: PathBuf,
    database: PathBuf,
}

impl SyntheticDatabaseV1 {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "helixos-t052-retention-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("retention fixture directory creates");
        let directory = fs::canonicalize(directory)
            .expect("retention fixture canonicalizes before SQLite open");
        let database = directory.join("coordinator.sqlite3");
        let connection = Connection::open(&database).expect("retention database creates");
        connection
            .execute_batch(STORE_SCHEMA)
            .expect("reviewed coordinator schema installs");
        connection
            .execute(
                "INSERT INTO coordinator_store_meta (\
                     singleton, format_version, store_generation, operation_generation, \
                     budget_generation, event_generation, quarantine_generation, root_identity, \
                     root_lifecycle_state, restore_identity_digest, restore_attestation_digest, \
                     restore_state_generation\
                 ) VALUES (1, 1, 0, 0, 0, 0, 0, ?1, 'ACTIVE', NULL, NULL, 0)",
                params![[0x52_u8; 32].as_slice()],
            )
            .expect("active root metadata initializes");
        drop(connection);
        Self {
            directory,
            database,
        }
    }

    fn database(&self) -> &Path {
        &self.database
    }
}

impl Drop for SyntheticDatabaseV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct FailedPreparationV1 {
    store: SyntheticDatabaseV1,
    operation_id: String,
}

impl FailedPreparationV1 {
    fn new() -> Self {
        let store = SyntheticDatabaseV1::new("failed");
        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
        provision_synthetic_budget_scope_v1(store.database(), &case)
            .expect("trusted synthetic scope provisions");
        assert!(matches!(
            commit_synthetic_preparation_v1(
                store.database(),
                &case,
                SyntheticCommitModeV1::Acknowledged,
            ),
            PreparationCommitOutcomeV1::Committed(_)
        ));

        let operation_id: String = Connection::open(store.database())
            .expect("prepared database reopens")
            .query_row("SELECT operation_id FROM prepared_operations", [], |row| {
                row.get(0)
            })
            .expect("prepared operation identity reads");
        let known = SyntheticKnownFailureCaseV1::load_preparing_v1(
            store.database(),
            &operation_id,
            REVOCATION_GENERATION,
            GUARD_DEADLINE_MONOTONIC_MS,
        )
        .expect("coherent preparation yields failure custody");
        assert!(matches!(
            fail_synthetic_before_dispatch_v1(
                store.database(),
                &known,
                SyntheticNoDispatchGuardCaseV1::Exact,
                NOW_MONOTONIC_MS,
            ),
            PreparationFailureOutcomeV1::Failed
        ));
        Self {
            store,
            operation_id,
        }
    }

    fn database(&self) -> &Path {
        self.store.database()
    }

    fn observation(&self) -> FailedRetentionObservationV1 {
        FailedRetentionObservationV1::read(self.database(), &self.operation_id)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FailedRetentionObservationV1 {
    operation_state: String,
    canonical_plan_length: i64,
    reservation_state: String,
    released_generation: Option<i64>,
    transition_count: i64,
    comparison_count: i64,
    recovery_count: i64,
    event_count: i64,
}

impl FailedRetentionObservationV1 {
    fn read(database: &Path, operation_id: &str) -> Self {
        let connection = Connection::open(database).expect("retention database reopens");
        let (operation_state, canonical_plan_length) = connection
            .query_row(
                "SELECT operation_state, canonical_plan_length \
                 FROM prepared_operations WHERE operation_id = ?1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("failed operation tombstone reads");
        let (reservation_state, released_generation) = connection
            .query_row(
                "SELECT reservation_state, released_generation \
                 FROM budget_reservations WHERE operation_id = ?1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("released reservation tombstone reads");
        Self {
            operation_state,
            canonical_plan_length,
            reservation_state,
            released_generation,
            transition_count: count_for_operation(
                &connection,
                "operation_transitions",
                operation_id,
            ),
            comparison_count: count_for_operation(
                &connection,
                "preparation_comparisons",
                operation_id,
            ),
            recovery_count: count_for_operation(
                &connection,
                "preparation_recovery_evidence",
                operation_id,
            ),
            event_count: count_for_operation(&connection, "preparation_events", operation_id),
        }
    }
}

fn count_for_operation(connection: &Connection, table: &str, operation_id: &str) -> i64 {
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE operation_id = ?1"),
            [operation_id],
            |row| row.get(0),
        )
        .expect("retained operation member count reads")
}

fn attempt_operation_statement_rolled_back(
    database: &Path,
    operation_id: &str,
    statement: &str,
) -> rusqlite::Result<usize> {
    let mut connection = Connection::open(database)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "recursive_triggers", "ON")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = transaction.execute(statement, [operation_id]);
    transaction.rollback()?;
    outcome
}

#[test]
fn v1_exposes_no_prune_compact_or_history_deletion_surface() {
    let production_surfaces = [
        include_str!("../src/lib.rs"),
        include_str!("../src/maintenance.rs"),
        include_str!("../src/retirement.rs"),
    ];
    for forbidden in [
        "pub fn prune",
        "pub(crate) fn prune",
        "pub fn compact_history",
        "pub(crate) fn compact_history",
        "pub fn delete_preparation",
        "pub(crate) fn delete_preparation",
    ] {
        assert!(
            production_surfaces
                .iter()
                .all(|source| !source.contains(forbidden)),
            "v1 must not expose an automatic pruning or online history-deletion surface",
        );
    }
}

#[test]
fn failed_operation_and_released_reservation_are_permanent_tombstones() {
    let fixture = FailedPreparationV1::new();
    let before = fixture.observation();
    assert_eq!(before.operation_state, "FAILED");
    assert!(before.canonical_plan_length > 0);
    assert_eq!(before.reservation_state, "RELEASED");
    assert!(before.released_generation.is_some());
    assert_eq!(before.transition_count, 2);
    assert_eq!(before.comparison_count, 1);
    assert_eq!(before.recovery_count, 1);
    assert_eq!(before.event_count, 2);

    for (tombstone, statement) in [
        (
            "FAILED_OPERATION",
            "DELETE FROM prepared_operations WHERE operation_id = ?1",
        ),
        (
            "RELEASED_RESERVATION",
            "DELETE FROM budget_reservations WHERE operation_id = ?1",
        ),
    ] {
        assert!(
            attempt_operation_statement_rolled_back(
                fixture.database(),
                &fixture.operation_id,
                statement,
            )
            .is_err(),
            "{tombstone} history must reject deletion",
        );
        assert_eq!(fixture.observation(), before);
    }
}

#[test]
fn a_complete_operation_graph_cannot_be_pruned_even_with_deferred_foreign_keys() {
    let fixture = FailedPreparationV1::new();
    let before = fixture.observation();
    let mut connection = Connection::open(fixture.database()).expect("retention database reopens");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys enable");
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .expect("recursive triggers enable");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("prune attempt transaction begins");
    transaction
        .pragma_update(None, "defer_foreign_keys", "ON")
        .expect("foreign keys defer for whole-graph prune attempt");
    let result = match transaction.execute_batch(
        "DELETE FROM preparation_events;\
         DELETE FROM operation_transitions;\
         DELETE FROM preparation_comparisons;\
         DELETE FROM preparation_recovery_evidence;\
         DELETE FROM budget_reservations;\
         DELETE FROM prepared_operations;",
    ) {
        Ok(()) => transaction.commit(),
        Err(error) => {
            transaction
                .rollback()
                .expect("rejected prune transaction rolls back");
            Err(error)
        }
    };
    assert!(
        result.is_err(),
        "v1 history must reject whole-graph pruning"
    );
    assert_eq!(fixture.observation(), before);
}

#[derive(Debug, PartialEq, Eq)]
struct OrphanTombstoneObservationV1 {
    quarantine_status: String,
    created_generation: i64,
    resolved_generation: Option<i64>,
    retirement_state: Option<String>,
    retired_generation: Option<i64>,
    retirement_manifest_digest: Option<Vec<u8>>,
    operation_count: i64,
}

fn orphan_observation(
    database: &Path,
    quarantine_id: Sha256Digest,
) -> OrphanTombstoneObservationV1 {
    let connection = Connection::open(database).expect("orphan database reopens");
    let mut observation = connection
        .query_row(
            "SELECT quarantine_status, created_generation, resolved_generation, \
                    orphan_retirement_state, orphan_retired_generation, \
                    orphan_retirement_manifest_digest \
             FROM preparation_quarantines WHERE quarantine_id = ?1",
            [quarantine_id.as_bytes().as_slice()],
            |row| {
                Ok(OrphanTombstoneObservationV1 {
                    quarantine_status: row.get(0)?,
                    created_generation: row.get(1)?,
                    resolved_generation: row.get(2)?,
                    retirement_state: row.get(3)?,
                    retired_generation: row.get(4)?,
                    retirement_manifest_digest: row.get(5)?,
                    operation_count: 0,
                })
            },
        )
        .expect("orphan quarantine tombstone reads");
    observation.operation_count = connection
        .query_row("SELECT COUNT(*) FROM prepared_operations", [], |row| {
            row.get(0)
        })
        .expect("operation absence reads");
    observation
}

fn attempt_quarantine_statement_rolled_back(
    database: &Path,
    quarantine_id: Sha256Digest,
    statement: &str,
) -> rusqlite::Result<usize> {
    let mut connection = Connection::open(database)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "recursive_triggers", "ON")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let outcome = transaction.execute(statement, [quarantine_id.as_bytes().as_slice()]);
    transaction.rollback()?;
    outcome
}

#[test]
fn retired_orphan_quarantine_is_permanent_and_rejects_reverse_or_replace() {
    let store = SyntheticDatabaseV1::new("orphan");
    let mut connection = Connection::open(store.database()).expect("orphan database reopens");
    let custody = retain_synthetic_orphan_v1(
        &mut connection,
        &SyntheticOrphanInputV1 {
            attempt_id: digest(0x61),
            operation_binding_digest: digest(0x62),
            recovery_manifest_digest: digest(0x63),
        },
    )
    .expect("true-orphan quarantine inserts through the US3 seam");
    let quarantine_id = custody.quarantine_id();
    let created_generation = custody.created_generation();
    let resolved_generation = created_generation + 1;
    let retired_generation = resolved_generation + 1;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("orphan lifecycle fixture transaction begins");
    transaction
        .execute(
            "UPDATE preparation_quarantines SET \
                 quarantine_status = 'RESOLVED_TOMBSTONE', resolved_generation = ?1, \
                 orphan_resolution_evidence_digest = ?2, orphan_retirement_id = ?3, \
                 orphan_retirement_state = 'RETIREMENT_PENDING' \
             WHERE quarantine_id = ?4",
            params![
                resolved_generation as i64,
                digest(0x64).as_bytes().as_slice(),
                digest(0x65).as_bytes().as_slice(),
                quarantine_id.as_bytes().as_slice(),
            ],
        )
        .expect("synthetic definitive proof records permanent pending authorization");
    transaction
        .execute(
            "UPDATE preparation_quarantines SET \
                 orphan_retirement_state = 'RETIRED_TOMBSTONE', \
                 orphan_retired_generation = ?1, orphan_retirement_manifest_digest = ?2 \
             WHERE quarantine_id = ?3",
            params![
                retired_generation as i64,
                digest(0x66).as_bytes().as_slice(),
                quarantine_id.as_bytes().as_slice(),
            ],
        )
        .expect("synthetic provider tombstone records exact terminal state");
    transaction
        .execute(
            "UPDATE coordinator_store_meta SET \
                 store_generation = ?1, quarantine_generation = ?1 \
             WHERE singleton = 1",
            [retired_generation as i64],
        )
        .expect("synthetic quarantine metadata advances");
    transaction
        .commit()
        .expect("synthetic retired-orphan fixture commits");
    drop(connection);

    let terminal = orphan_observation(store.database(), quarantine_id);
    assert_eq!(terminal.quarantine_status, "RESOLVED_TOMBSTONE");
    assert_eq!(terminal.created_generation, created_generation as i64);
    assert_eq!(
        terminal.resolved_generation,
        Some(resolved_generation as i64)
    );
    assert_eq!(
        terminal.retirement_state.as_deref(),
        Some("RETIRED_TOMBSTONE")
    );
    assert_eq!(terminal.retired_generation, Some(retired_generation as i64));
    assert!(terminal.retirement_manifest_digest.is_some());
    assert_eq!(
        terminal.operation_count, 0,
        "an orphan never fabricates FAILED"
    );

    for statement in [
        "DELETE FROM preparation_quarantines WHERE quarantine_id = ?1",
        "UPDATE preparation_quarantines SET \
             orphan_retirement_state = 'RETIREMENT_PENDING', \
             orphan_retired_generation = NULL, orphan_retirement_manifest_digest = NULL \
         WHERE quarantine_id = ?1",
        "UPDATE preparation_quarantines SET \
             quarantine_status = 'ACTIVE', resolved_generation = NULL, \
             orphan_resolution_evidence_digest = NULL, orphan_retirement_id = NULL, \
             orphan_retirement_state = NULL, orphan_retired_generation = NULL, \
             orphan_retirement_manifest_digest = NULL \
         WHERE quarantine_id = ?1",
        "INSERT OR REPLACE INTO preparation_quarantines \
         SELECT * FROM preparation_quarantines WHERE quarantine_id = ?1",
    ] {
        assert!(
            attempt_quarantine_statement_rolled_back(store.database(), quarantine_id, statement)
                .is_err(),
            "permanent orphan history must reject delete, reverse, and replacement",
        );
        assert_eq!(
            orphan_observation(store.database(), quarantine_id),
            terminal
        );
    }
}
