//! Ownership: T008 initialization/schema checks and T036/T038 maintenance/corruption tests.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    SyntheticTempRoot, MAINTENANCE_DEADLINE_MONOTONIC_MS, OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_replay_sqlite::{
    ReplayCheckpointModeV1, ReplayStoreConfigV1, SqliteReplayClaimantV1, TrustedLocalStoreRootV1,
    REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1,
};
use rusqlite::Connection;
use std::fs::{self, OpenOptions};
use std::sync::{Arc, Barrier};
use std::thread;

fn assert_open_error(root: &SyntheticTempRoot, expected: &str) {
    let error = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("invalid replay store was accepted"));
    assert_eq!(error.code(), expected);
    assert_eq!(error.to_string(), expected);
    assert!(std::error::Error::source(&error).is_none());
}

fn assert_durable_quarantine_blocks_reopen(root: &SyntheticTempRoot) {
    let error = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("durably quarantined replay store reopened"));
    assert!(matches!(
        error.code(),
        "LOCATION_NOT_DEDICATED" | "STORE_UNAVAILABLE"
    ));
}

fn mutate_closed_database(root: &SyntheticTempRoot, statements: &str) {
    let connection = Connection::open(root.closed_database_path())
        .unwrap_or_else(|_| panic!("corruption fixture open failed"));
    connection
        .execute_batch(statements)
        .unwrap_or_else(|_| panic!("corruption fixture mutation failed"));
}

fn quiesce_database(root: &SyntheticTempRoot) {
    let claimant = open_store(root, InjectedClock::coherent());
    let evidence = claimant
        .checkpoint_v1(
            ReplayCheckpointModeV1::QuiescentTruncate,
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("synthetic database quiescence failed"));
    assert!(evidence.is_complete());
    assert_eq!(evidence.log_frames(), 0);
    assert_eq!(evidence.checkpointed_frames(), 0);
}

#[test]
fn empty_root_initializes_one_exact_v1_store_and_reopens_cleanly() {
    let root = SyntheticTempRoot::new("empty-to-v1");
    let claimant = open_store(&root, InjectedClock::coherent());
    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("new v1 store verification failed"));
    assert_eq!(
        verification.application_id(),
        REPLAY_STORE_APPLICATION_ID_V1
    );
    assert_eq!(
        verification.store_schema_version(),
        REPLAY_STORE_SCHEMA_VERSION_V1
    );
    assert_eq!(verification.claim_count(), 0);
    assert_eq!(verification.claimant_generation(), 0);
    drop(claimant);

    let reopened = open_store(&root, InjectedClock::coherent());
    reopened
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("reopened v1 store verification failed"));
}

#[test]
fn concurrent_empty_root_initializers_converge_on_one_complete_schema() {
    const INITIALIZERS: usize = 8;
    // This is an initialization-convergence correctness fixture, not SC-004 latency
    // evidence. Give hosted providers five seconds while the production setup gate
    // retains its independent cap of 1,000 one-millisecond attempts.
    const INITIALIZATION_CORRECTNESS_BUSY_WAIT_MS: u64 = 5_000;
    let root = SyntheticTempRoot::new("concurrent-init");
    let path = Arc::new(root.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(INITIALIZERS));
    let mut handles = Vec::with_capacity(INITIALIZERS);

    for _ in 0..INITIALIZERS {
        let path = Arc::clone(&path);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let trusted = TrustedLocalStoreRootV1::try_from_provisioned((*path).clone())
                .unwrap_or_else(|_| panic!("concurrent provisioned root was rejected"));
            let config = ReplayStoreConfigV1::try_new(
                trusted,
                INITIALIZATION_CORRECTNESS_BUSY_WAIT_MS,
                16,
                1,
            )
            .unwrap_or_else(|_| panic!("concurrent configuration was rejected"));
            barrier.wait();
            SqliteReplayClaimantV1::open_or_create(
                config,
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .map(|claimant| {
                claimant
                    .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
                    .map(|_| ())
            })
        }));
    }

    for handle in handles {
        let opened = handle
            .join()
            .unwrap_or_else(|_| panic!("concurrent initializer panicked"));
        let verified = opened
            .unwrap_or_else(|error| panic!("concurrent initializer failed: {}", error.code()));
        verified.unwrap_or_else(|_| panic!("concurrent initialized store was unhealthy"));
    }

    open_store(&root, InjectedClock::coherent())
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("concurrently initialized store did not reopen"));
}

#[test]
fn wrong_application_id_fails_closed() {
    let root = SyntheticTempRoot::new("wrong-app-id");
    drop(open_store(&root, InjectedClock::coherent()));
    let connection = Connection::open(root.closed_database_path())
        .unwrap_or_else(|_| panic!("application-id fixture open failed"));
    connection
        .pragma_update(None, "application_id", REPLAY_STORE_APPLICATION_ID_V1 + 1)
        .unwrap_or_else(|_| panic!("application-id fixture mutation failed"));
    drop(connection);
    assert_open_error(&root, "APPLICATION_ID_MISMATCH");
}

#[test]
fn newer_or_reset_schema_version_fails_closed() {
    for (label, version, expected) in [
        (
            "newer-schema",
            REPLAY_STORE_SCHEMA_VERSION_V1 + 1,
            "SCHEMA_UNSUPPORTED",
        ),
        ("reset-schema", 0, "SCHEMA_INVALID"),
    ] {
        let root = SyntheticTempRoot::new(label);
        drop(open_store(&root, InjectedClock::coherent()));
        let connection = Connection::open(root.closed_database_path())
            .unwrap_or_else(|_| panic!("schema-version fixture open failed"));
        connection
            .pragma_update(None, "user_version", version)
            .unwrap_or_else(|_| panic!("schema-version fixture mutation failed"));
        drop(connection);
        assert_open_error(&root, expected);
    }
}

#[test]
fn altered_exact_schema_fails_closed_without_repair() {
    let root = SyntheticTempRoot::new("altered-schema");
    drop(open_store(&root, InjectedClock::coherent()));
    let connection = Connection::open(root.closed_database_path())
        .unwrap_or_else(|_| panic!("altered-schema fixture open failed"));
    connection
        .execute_batch("DROP INDEX replay_claims_operation_id_uq;")
        .unwrap_or_else(|_| panic!("altered-schema fixture mutation failed"));
    drop(connection);
    assert_open_error(&root, "SCHEMA_INVALID");
    assert_open_error(&root, "SCHEMA_INVALID");
}

#[test]
fn foreign_content_is_rejected_before_database_mutation() {
    let root = SyntheticTempRoot::new("foreign-content");
    root.create_foreign_file();
    let error = TrustedLocalStoreRootV1::try_from_provisioned(root.path().to_path_buf())
        .err()
        .unwrap_or_else(|| panic!("foreign replay root was accepted"));
    assert_eq!(error.code(), "LOCATION_NOT_DEDICATED");
    assert!(root.closed_database_path_if_present().is_none());
}

#[test]
fn fixed_wal_full_profile_is_reestablished_and_verified_on_reopen() {
    let root = SyntheticTempRoot::new("durability-profile");
    drop(open_store(&root, InjectedClock::coherent()));
    let connection = Connection::open(root.closed_database_path())
        .unwrap_or_else(|_| panic!("durability fixture open failed"));
    let mode: String = connection
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .unwrap_or_else(|_| panic!("durability fixture mutation failed"));
    assert!(mode.eq_ignore_ascii_case("delete"));
    drop(connection);

    let claimant = open_store(&root, InjectedClock::coherent());
    claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("fixed durability profile was not reestablished"));
}

#[test]
fn full_integrity_verification_refuses_to_overlap_a_held_writer_and_recovers() {
    let root = SyntheticTempRoot::new("integrity-writer-lock");
    let claimant = open_store(&root, InjectedClock::coherent());
    let writer = Connection::open(root.closed_database_path())
        .unwrap_or_else(|_| panic!("writer-lock fixture open failed"));
    writer
        .execute_batch("BEGIN IMMEDIATE;")
        .unwrap_or_else(|_| panic!("writer-lock fixture acquisition failed"));

    let error = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .err()
        .unwrap_or_else(|| panic!("full verification overlapped a held writer"));
    assert_eq!(error.code(), "STORE_BUSY");
    assert_eq!(error.to_string(), "STORE_BUSY");
    assert!(std::error::Error::source(&error).is_none());

    writer
        .execute_batch("ROLLBACK;")
        .unwrap_or_else(|_| panic!("writer-lock fixture release failed"));
    claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("verification did not recover after writer release"));
}

#[test]
fn passive_checkpoint_reports_reader_blockage_then_quiescent_truncate_completes() {
    let root = SyntheticTempRoot::new("checkpoint-evidence");
    let claimant = open_store(&root, InjectedClock::coherent());
    let (first, _) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert!(first.is_ok());

    let baseline = claimant
        .checkpoint_v1(
            ReplayCheckpointModeV1::QuiescentTruncate,
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("checkpoint baseline failed"));
    assert!(baseline.is_complete());

    let reader = Connection::open(root.closed_database_path())
        .unwrap_or_else(|_| panic!("checkpoint reader fixture open failed"));
    reader
        .execute_batch("BEGIN;")
        .unwrap_or_else(|_| panic!("checkpoint reader transaction failed"));
    let mut statement = reader
        .prepare("SELECT claimant_generation FROM replay_store_meta WHERE singleton = 1")
        .unwrap_or_else(|_| panic!("checkpoint reader statement failed"));
    let mut rows = statement
        .query([])
        .unwrap_or_else(|_| panic!("checkpoint reader query failed"));
    let generation: i64 = rows
        .next()
        .unwrap_or_else(|_| panic!("checkpoint reader step failed"))
        .unwrap_or_else(|| panic!("checkpoint reader observed no metadata"))
        .get(0)
        .unwrap_or_else(|_| panic!("checkpoint reader decode failed"));
    assert_eq!(generation, 1);

    let (second, _) = evaluate_with_observation(
        feature002_fixture(Feature002Variant::Independent),
        &claimant,
    );
    assert!(second.is_ok());

    let passive = claimant
        .checkpoint_v1(
            ReplayCheckpointModeV1::Passive,
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("passive checkpoint failed"));
    assert_eq!(passive.mode(), ReplayCheckpointModeV1::Passive);
    assert!(!passive.is_complete());
    assert!(passive.log_frames() > 0);
    assert!(passive.checkpointed_frames() < passive.log_frames());
    assert_eq!(passive.claimant_generation_before(), 2);
    assert_eq!(passive.claimant_generation_after(), 2);

    drop(rows);
    drop(statement);
    reader
        .execute_batch("ROLLBACK;")
        .unwrap_or_else(|_| panic!("checkpoint reader release failed"));
    drop(reader);

    let truncate = claimant
        .checkpoint_v1(
            ReplayCheckpointModeV1::QuiescentTruncate,
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("quiescent truncate checkpoint failed"));
    assert_eq!(truncate.mode(), ReplayCheckpointModeV1::QuiescentTruncate);
    assert!(truncate.is_complete());
    assert_eq!(truncate.log_frames(), 0);
    assert_eq!(truncate.checkpointed_frames(), 0);
    assert_eq!(truncate.claimant_generation_before(), 2);
    assert_eq!(truncate.claimant_generation_after(), 2);
}

#[test]
fn truncated_database_is_rejected_without_reinitialization() {
    let root = SyntheticTempRoot::new("truncated-database");
    quiesce_database(&root);
    let database = root.closed_database_path();
    let file = OpenOptions::new()
        .write(true)
        .open(database)
        .unwrap_or_else(|_| panic!("truncation fixture open failed"));
    assert!(
        file.metadata()
            .unwrap_or_else(|_| panic!("truncation fixture metadata failed"))
            .len()
            > 512
    );
    file.set_len(512)
        .and_then(|()| file.sync_all())
        .unwrap_or_else(|_| panic!("truncation fixture mutation failed"));
    drop(file);

    assert_open_error(&root, "INTEGRITY_FAILED");
    assert_durable_quarantine_blocks_reopen(&root);
}

#[test]
fn bit_flipped_btree_header_is_rejected_without_repair() {
    const FIRST_BTREE_PAGE_HEADER_OFFSET: usize = 100;

    let root = SyntheticTempRoot::new("bit-flipped-database");
    quiesce_database(&root);
    let database = root.closed_database_path();
    let mut bytes = fs::read(&database).unwrap_or_else(|_| panic!("bit-flip fixture read failed"));
    let byte = bytes
        .get_mut(FIRST_BTREE_PAGE_HEADER_OFFSET)
        .unwrap_or_else(|| panic!("bit-flip fixture was unexpectedly short"));
    *byte ^= 0xff;
    fs::write(database, bytes).unwrap_or_else(|_| panic!("bit-flip fixture mutation failed"));

    assert_open_error(&root, "INTEGRITY_FAILED");
    assert_durable_quarantine_blocks_reopen(&root);
}

#[test]
fn removed_required_table_fails_exact_schema_verification() {
    let root = SyntheticTempRoot::new("removed-table");
    drop(open_store(&root, InjectedClock::coherent()));
    mutate_closed_database(&root, "DROP TABLE replay_claims;");

    assert_open_error(&root, "SCHEMA_INVALID");
    assert_open_error(&root, "SCHEMA_INVALID");
}

#[test]
fn missing_singleton_metadata_row_fails_application_invariants() {
    let root = SyntheticTempRoot::new("missing-metadata");
    drop(open_store(&root, InjectedClock::coherent()));
    mutate_closed_database(&root, "DELETE FROM replay_store_meta;");

    assert_open_error(&root, "INVARIANT_FAILED");
    assert_durable_quarantine_blocks_reopen(&root);
}

#[test]
fn malformed_claim_row_fails_full_sqlite_integrity() {
    let root = SyntheticTempRoot::new("malformed-claim-row");
    drop(open_store(&root, InjectedClock::coherent()));
    mutate_closed_database(
        &root,
        "PRAGMA ignore_check_constraints = ON;
         BEGIN IMMEDIATE;
         UPDATE replay_store_meta SET claimant_generation = 1 WHERE singleton = 1;
         INSERT INTO replay_claims (
             instance_epoch, nonce, operation_id, binding_digest, claim_id,
             claimant_generation
         ) VALUES (
             1,
             X'111111111111111111111111111111',
             'operation:malformed-claim-row',
             X'2222222222222222222222222222222222222222222222222222222222222222',
             X'3333333333333333333333333333333333333333333333333333333333333333',
             1
         );
         COMMIT;
         PRAGMA ignore_check_constraints = OFF;",
    );

    assert_open_error(&root, "INTEGRITY_FAILED");
    assert_durable_quarantine_blocks_reopen(&root);
}

#[test]
fn noncontiguous_claim_generation_fails_application_invariants() {
    let root = SyntheticTempRoot::new("noncontiguous-generation");
    drop(open_store(&root, InjectedClock::coherent()));
    mutate_closed_database(
        &root,
        "BEGIN IMMEDIATE;
         UPDATE replay_store_meta SET claimant_generation = 2 WHERE singleton = 1;
         INSERT INTO replay_claims (
             instance_epoch, nonce, operation_id, binding_digest, claim_id,
             claimant_generation
         ) VALUES (
             1,
             X'44444444444444444444444444444444',
             'operation:noncontiguous-generation',
             X'5555555555555555555555555555555555555555555555555555555555555555',
             X'6666666666666666666666666666666666666666666666666666666666666666',
             2
         );
         COMMIT;",
    );

    assert_open_error(&root, "INVARIANT_FAILED");
    assert_durable_quarantine_blocks_reopen(&root);
}
