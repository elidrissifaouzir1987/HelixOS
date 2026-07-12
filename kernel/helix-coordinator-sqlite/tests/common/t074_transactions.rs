//! Explicit T074 terminal-commit, readback and known-failure process workflows.

use crate::common::{SyntheticCoordinatorClockV1, SyntheticHistoricalPlanKeyResolverV1};
use crate::failure::{
    fail_synthetic_before_dispatch_with_fault_probes_v1, SyntheticKnownFailureCaseV1,
    SyntheticNoDispatchGuardCaseV1,
};
use crate::prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticConflictV1, SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use crate::readback::{
    readback_synthetic_attempt_with_fault_probe_v1, synthetic_uncertain_v1, SyntheticReadbackModeV1,
};
use helix_coordinator_sqlite::{
    CoordinatorFaultProbeV1, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
    SqliteCoordinatorStoreV1,
};
use helix_plan_preparation::{
    run_t074_terminal_commit_classification_for_test_v1, FaultProbeV1, PreparationCommitOutcomeV1,
    PreparationFailureOutcomeV1, PreparationReadbackOutcomeV1,
};
use rusqlite::{Connection, OpenFlags};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const COORDINATOR_ROOT_DIRECTORY: &str = "coordinator-root-v1";
const COORDINATOR_IDENTITY_FILE: &str = "coordinator-root-identity-v1";
const COORDINATOR_DATABASE_FILE: &str = "coordinator.sqlite3";
const OPEN_NOW_MS: u64 = 1_000;
const OPEN_DEADLINE_MS: u64 = 10_000;
const FAILURE_REVOCATION_GENERATION: u64 = 17;
const FAILURE_GUARD_DEADLINE_MS: u64 = 10_000;

const TERMINAL_COMMIT_BOUNDARY_IDS_V1: [&str; 2] = [
    "positive_coordinator_commit_permit_resolved_aborted",
    "positive_coordinator_commit_permit_resolved_ambiguous",
];

const PORTABLE_FAILURE_BOUNDARY_IDS_V1: [&str; 3] = [
    "known_failure_no_dispatch_guard_acquired",
    "known_failure_no_dispatch_guard_finally_revalidated",
    "known_failure_no_dispatch_guard_released",
];

const COORDINATOR_FAILURE_BOUNDARY_IDS_V1: [&str; 9] = [
    "known_failure_begin_immediate_acquired",
    "known_failure_operation_failed_staged",
    "known_failure_transition_staged",
    "known_failure_scope_held_subtraction_staged",
    "known_failure_reservation_released_staged",
    "known_failure_event_staged",
    "known_failure_metadata_staged",
    "known_failure_commit_returned",
    "known_failure_commit_classified",
];

/// The exact 21 closed IDs owned by this workflow, in frozen corpus order.
pub(crate) const SUPPORTED_BOUNDARY_IDS_V1: [&str; 21] = [
    "positive_coordinator_commit_permit_resolved_aborted",
    "positive_coordinator_commit_permit_resolved_ambiguous",
    "acknowledgement_uncertain_connection_closed",
    "acknowledgement_readback_snapshot_opened",
    "acknowledgement_readback_classified_this_attempt",
    "acknowledgement_readback_classified_prior_exact_attempt",
    "acknowledgement_readback_classified_conflict",
    "acknowledgement_readback_classified_definite_absence",
    "acknowledgement_readback_classified_ambiguous",
    "known_failure_no_dispatch_guard_acquired",
    "known_failure_no_dispatch_guard_finally_revalidated",
    "known_failure_begin_immediate_acquired",
    "known_failure_operation_failed_staged",
    "known_failure_transition_staged",
    "known_failure_scope_held_subtraction_staged",
    "known_failure_reservation_released_staged",
    "known_failure_event_staged",
    "known_failure_metadata_staged",
    "known_failure_commit_returned",
    "known_failure_commit_classified",
    "known_failure_no_dispatch_guard_released",
];

pub(crate) type ProcessBarrierV1 = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadbackFixtureV1 {
    ThisAttempt,
    PriorExactAttempt,
    Conflict,
    DefiniteAbsence,
    Ambiguous,
}

pub(crate) fn supports_boundary_v1(boundary_id: &str) -> bool {
    SUPPORTED_BOUNDARY_IDS_V1.contains(&boundary_id)
}

/// Initializes the caller-owned coordinator root and seeds the exact durable fixture
/// required by one selected terminal, readback or known-failure boundary.
pub(crate) fn prepare_fixture_v1(
    protocol_root: &Path,
    boundary_id: &str,
) -> Result<(), &'static str> {
    if !supports_boundary_v1(boundary_id) {
        return Err("transaction-boundary-unsupported");
    }
    let protocol_root = canonical_protocol_root_v1(protocol_root)?;
    let coordinator_root = protocol_root.join(COORDINATOR_ROOT_DIRECTORY);
    create_exact_directory_v1(&coordinator_root)?;
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(coordinator_root.clone(), 50)
        .map_err(|_| "coordinator-config-invalid")?;
    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
        SyntheticHistoricalPlanKeyResolverV1::default(),
        OPEN_DEADLINE_MS,
    )
    .map_err(|_| "coordinator-initialize-failed")?;
    let identity = store.root_identity_evidence().to_attested_bytes();
    drop(store);

    let database = coordinator_root.join(COORDINATOR_DATABASE_FILE);
    if let Some(readback_fixture) = readback_fixture_v1(boundary_id) {
        prepare_readback_fixture_v1(&database, readback_fixture)?;
    } else if PORTABLE_FAILURE_BOUNDARY_IDS_V1.contains(&boundary_id)
        || COORDINATOR_FAILURE_BOUNDARY_IDS_V1.contains(&boundary_id)
    {
        prepare_known_failure_fixture_v1(&database)?;
    } else if !TERMINAL_COMMIT_BOUNDARY_IDS_V1.contains(&boundary_id) {
        return Err("transaction-boundary-unsupported");
    }

    write_create_new_synced_v1(&protocol_root.join(COORDINATOR_IDENTITY_FILE), &identity)
}

/// Runs one real terminal classification, live readback, or known-failure transaction
/// with callback custody supplied solely by the caller.
pub(crate) fn run_boundary_v1(
    protocol_root: &Path,
    boundary_id: &str,
    occurrence: u64,
    process_barrier: ProcessBarrierV1,
) -> Result<(), &'static str> {
    if !supports_boundary_v1(boundary_id) {
        return Err("transaction-boundary-unsupported");
    }
    if occurrence != 1 {
        return Err("transaction-occurrence-unsupported");
    }
    let protocol_root = canonical_protocol_root_v1(protocol_root)?;
    if TERMINAL_COMMIT_BOUNDARY_IDS_V1.contains(&boundary_id) {
        return run_t074_terminal_commit_classification_for_test_v1(
            boundary_id,
            occurrence,
            move || process_barrier(),
        );
    }
    let database = protocol_root
        .join(COORDINATOR_ROOT_DIRECTORY)
        .join(COORDINATOR_DATABASE_FILE);
    if let Some(readback_fixture) = readback_fixture_v1(boundary_id) {
        return run_readback_boundary_v1(
            &database,
            boundary_id,
            occurrence,
            readback_fixture,
            process_barrier,
        );
    }
    run_known_failure_boundary_v1(&database, boundary_id, occurrence, process_barrier)
}

/// Reopens through the production verifier and returns only the closed process-harness
/// state token for this workflow's coordinator root.
#[allow(dead_code)] // Wired by the parent process driver after this isolated workflow lands.
pub(crate) fn reopen_state_v1(protocol_root: &Path) -> Result<&'static [u8], &'static str> {
    let protocol_root = canonical_protocol_root_v1(protocol_root)?;
    let identity_path = protocol_root.join(COORDINATOR_IDENTITY_FILE);
    let metadata = fs::symlink_metadata(&identity_path).map_err(|_| "identity-file-invalid")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 32 {
        return Err("identity-file-invalid");
    }
    let identity: [u8; 32] = fs::read(identity_path)
        .map_err(|_| "identity-file-invalid")?
        .try_into()
        .map_err(|_| "identity-file-invalid")?;
    let coordinator_root = protocol_root.join(COORDINATOR_ROOT_DIRECTORY);
    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        coordinator_root.clone(),
        CoordinatorRootIdentityEvidenceV1::from_attested_bytes(identity),
        50,
    )
    .map_err(|_| "coordinator-config-invalid")?;
    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
        SyntheticHistoricalPlanKeyResolverV1::default(),
        OPEN_DEADLINE_MS,
    )
    .map_err(|_| "coordinator-reopen-failed")?;
    let verified_operation_count = store.operation_count();
    drop(store);

    let database = coordinator_root.join(COORDINATOR_DATABASE_FILE);
    let connection = open_read_connection_v1(&database)?;
    let (total, preparing, failed): (i64, i64, i64) = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN operation_state='PREPARING' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN operation_state='FAILED' THEN 1 ELSE 0 END), 0)
               FROM prepared_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "coordinator-reopen-classification-failed")?;
    let verified_operation_count = i64::try_from(verified_operation_count)
        .map_err(|_| "coordinator-reopen-classification-failed")?;
    if total != verified_operation_count {
        return Err("coordinator-reopen-classification-failed");
    }
    match (total, preparing, failed) {
        (0, 0, 0) => Ok(b"absent"),
        (total, preparing, 0) if total > 0 && total == preparing => Ok(b"preparing"),
        (total, 0, failed) if total > 0 && total == failed => Ok(b"failed"),
        _ => Err("coordinator-reopen-state-invalid"),
    }
}

fn prepare_readback_fixture_v1(
    database: &Path,
    fixture: ReadbackFixtureV1,
) -> Result<(), &'static str> {
    let case = readback_base_case_v1(fixture);
    provision_synthetic_budget_scope_v1(database, &case)
        .map_err(|_| "readback-budget-scope-failed")?;
    let mode = match fixture {
        ReadbackFixtureV1::ThisAttempt => SyntheticCommitModeV1::UncertainCommitted,
        ReadbackFixtureV1::DefiniteAbsence => SyntheticCommitModeV1::UncertainRolledBack,
        ReadbackFixtureV1::PriorExactAttempt
        | ReadbackFixtureV1::Conflict
        | ReadbackFixtureV1::Ambiguous => SyntheticCommitModeV1::Acknowledged,
    };
    let outcome = commit_synthetic_preparation_v1(database, &case, mode);
    let committed = match fixture {
        ReadbackFixtureV1::ThisAttempt | ReadbackFixtureV1::DefiniteAbsence => {
            matches!(outcome, PreparationCommitOutcomeV1::Uncertain { .. })
        }
        ReadbackFixtureV1::PriorExactAttempt
        | ReadbackFixtureV1::Conflict
        | ReadbackFixtureV1::Ambiguous => {
            matches!(outcome, PreparationCommitOutcomeV1::Committed(_))
        }
    };
    if !committed {
        return Err("readback-fixture-commit-failed");
    }
    let expected = if fixture == ReadbackFixtureV1::DefiniteAbsence {
        (0, 0, 0)
    } else {
        (1, 1, 0)
    };
    require_operation_counts_v1(database, expected)
}

fn prepare_known_failure_fixture_v1(database: &Path) -> Result<(), &'static str> {
    let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
    provision_synthetic_budget_scope_v1(database, &case)
        .map_err(|_| "known-failure-budget-scope-failed")?;
    if !matches!(
        commit_synthetic_preparation_v1(database, &case, SyntheticCommitModeV1::Acknowledged),
        PreparationCommitOutcomeV1::Committed(_)
    ) {
        return Err("known-failure-preparing-commit-failed");
    }
    require_operation_counts_v1(database, (1, 1, 0))
}

fn run_readback_boundary_v1(
    database: &Path,
    boundary_id: &str,
    occurrence: u64,
    fixture: ReadbackFixtureV1,
    process_barrier: ProcessBarrierV1,
) -> Result<(), &'static str> {
    let fault_probe = CoordinatorFaultProbeV1::selected_process_barrier_for_test_v1(
        boundary_id,
        occurrence,
        move || process_barrier(),
    )?;
    let outcome = execute_readback_v1(database, fixture, &fault_probe);
    if readback_outcome_matches_v1(fixture, &outcome) {
        Ok(())
    } else {
        Err("readback-classification-invalid")
    }
}

fn execute_readback_v1(
    database: &Path,
    fixture: ReadbackFixtureV1,
    fault_probe: &CoordinatorFaultProbeV1,
) -> PreparationReadbackOutcomeV1 {
    let base = readback_base_case_v1(fixture);
    let candidate = match fixture {
        ReadbackFixtureV1::PriorExactAttempt => base.next_exact_attempt_v1(),
        ReadbackFixtureV1::Conflict => base.conflicting_v1(SyntheticConflictV1::Plan),
        ReadbackFixtureV1::ThisAttempt
        | ReadbackFixtureV1::DefiniteAbsence
        | ReadbackFixtureV1::Ambiguous => base,
    };
    let uncertain = synthetic_uncertain_v1(&candidate);
    let mode = if fixture == ReadbackFixtureV1::Ambiguous {
        SyntheticReadbackModeV1::ContradictorySnapshot
    } else {
        SyntheticReadbackModeV1::Healthy
    };
    readback_synthetic_attempt_with_fault_probe_v1(
        database,
        &candidate,
        &uncertain,
        mode,
        fault_probe,
    )
}

fn run_known_failure_boundary_v1(
    database: &Path,
    boundary_id: &str,
    occurrence: u64,
    process_barrier: ProcessBarrierV1,
) -> Result<(), &'static str> {
    let coordinator_fault_probe = if COORDINATOR_FAILURE_BOUNDARY_IDS_V1.contains(&boundary_id) {
        let callback = Arc::clone(&process_barrier);
        CoordinatorFaultProbeV1::selected_process_barrier_for_test_v1(
            boundary_id,
            occurrence,
            move || callback(),
        )?
    } else {
        CoordinatorFaultProbeV1::disabled_v1()
    };
    let portable_fault_probe = if PORTABLE_FAILURE_BOUNDARY_IDS_V1.contains(&boundary_id) {
        FaultProbeV1::selected_process_barrier_v1(boundary_id, occurrence, move || {
            process_barrier()
        })
        .map_err(|_| "portable-failure-probe-invalid")?
    } else {
        FaultProbeV1::default()
    };
    let outcome =
        execute_known_failure_v1(database, &coordinator_fault_probe, &portable_fault_probe)?;
    if matches!(outcome, PreparationFailureOutcomeV1::Failed) {
        Ok(())
    } else {
        Err("known-failure-transaction-invalid")
    }
}

fn execute_known_failure_v1(
    database: &Path,
    coordinator_fault_probe: &CoordinatorFaultProbeV1,
    portable_fault_probe: &FaultProbeV1,
) -> Result<PreparationFailureOutcomeV1, &'static str> {
    let operation_id = only_preparing_operation_id_v1(database)?;
    let known = SyntheticKnownFailureCaseV1::load_preparing_v1(
        database,
        &operation_id,
        FAILURE_REVOCATION_GENERATION,
        FAILURE_GUARD_DEADLINE_MS,
    )
    .map_err(|_| "known-failure-binding-invalid")?;
    Ok(fail_synthetic_before_dispatch_with_fault_probes_v1(
        database,
        &known,
        SyntheticNoDispatchGuardCaseV1::Exact,
        OPEN_NOW_MS,
        coordinator_fault_probe,
        portable_fault_probe,
    ))
}

fn readback_fixture_v1(boundary_id: &str) -> Option<ReadbackFixtureV1> {
    match boundary_id {
        "acknowledgement_uncertain_connection_closed"
        | "acknowledgement_readback_snapshot_opened"
        | "acknowledgement_readback_classified_this_attempt" => {
            Some(ReadbackFixtureV1::ThisAttempt)
        }
        "acknowledgement_readback_classified_prior_exact_attempt" => {
            Some(ReadbackFixtureV1::PriorExactAttempt)
        }
        "acknowledgement_readback_classified_conflict" => Some(ReadbackFixtureV1::Conflict),
        "acknowledgement_readback_classified_definite_absence" => {
            Some(ReadbackFixtureV1::DefiniteAbsence)
        }
        "acknowledgement_readback_classified_ambiguous" => Some(ReadbackFixtureV1::Ambiguous),
        _ => None,
    }
}

fn readback_base_case_v1(fixture: ReadbackFixtureV1) -> SyntheticPreparationCaseV1 {
    let recovery = match fixture {
        ReadbackFixtureV1::ThisAttempt | ReadbackFixtureV1::DefiniteAbsence => {
            SyntheticRecoveryModeV1::Irreversible
        }
        ReadbackFixtureV1::PriorExactAttempt
        | ReadbackFixtureV1::Conflict
        | ReadbackFixtureV1::Ambiguous => SyntheticRecoveryModeV1::Compensation,
    };
    SyntheticPreparationCaseV1::coherent_v1(recovery)
}

fn readback_outcome_matches_v1(
    fixture: ReadbackFixtureV1,
    outcome: &PreparationReadbackOutcomeV1,
) -> bool {
    matches!(
        (fixture, outcome),
        (
            ReadbackFixtureV1::ThisAttempt,
            PreparationReadbackOutcomeV1::ThisAttempt(_)
        ) | (
            ReadbackFixtureV1::PriorExactAttempt,
            PreparationReadbackOutcomeV1::PriorExactAttempt
        ) | (
            ReadbackFixtureV1::Conflict,
            PreparationReadbackOutcomeV1::Conflict
        ) | (
            ReadbackFixtureV1::DefiniteAbsence,
            PreparationReadbackOutcomeV1::DefiniteAbsence
        ) | (
            ReadbackFixtureV1::Ambiguous,
            PreparationReadbackOutcomeV1::Ambiguous
        )
    )
}

fn require_operation_counts_v1(
    database: &Path,
    expected: (i64, i64, i64),
) -> Result<(), &'static str> {
    let connection = open_read_connection_v1(database)?;
    let actual = connection
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN operation_state='PREPARING' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN operation_state='FAILED' THEN 1 ELSE 0 END), 0)
               FROM prepared_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "operation-count-read-failed")?;
    if actual == expected {
        Ok(())
    } else {
        Err("operation-count-invalid")
    }
}

fn only_preparing_operation_id_v1(database: &Path) -> Result<String, &'static str> {
    require_operation_counts_v1(database, (1, 1, 0))?;
    open_read_connection_v1(database)?
        .query_row(
            "SELECT operation_id FROM prepared_operations WHERE operation_state='PREPARING'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "preparing-operation-read-failed")
}

fn open_read_connection_v1(database: &Path) -> Result<Connection, &'static str> {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "coordinator-database-open-failed")
}

fn canonical_protocol_root_v1(path: &Path) -> Result<PathBuf, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "protocol-root-invalid")?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("protocol-root-invalid");
    }
    fs::canonicalize(path).map_err(|_| "protocol-root-invalid")
}

fn create_exact_directory_v1(path: &Path) -> Result<(), &'static str> {
    fs::create_dir(path).map_err(|_| "fixture-directory-create-failed")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "fixture-directory-invalid")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("fixture-directory-invalid");
    }
    Ok(())
}

fn write_create_new_synced_v1(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "fixture-identity-create-failed")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "fixture-identity-publish-failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const CASES_BYTES: &[u8] =
        include_bytes!("../../../../contracts/fixtures/durable-preparation-v1/cases.json");
    static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestRootV1(PathBuf);

    impl TestRootV1 {
        fn new_v1() -> Self {
            for _ in 0..64 {
                let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
                let path = std::env::temp_dir().join(format!(
                    "helixos-t074-transactions-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        let path =
                            fs::canonicalize(path).expect("T074 transaction root canonicalizes");
                        return Self(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => panic!("T074 transaction root creation failed"),
                }
            }
            panic!("T074 transaction root allocation exhausted")
        }

        fn path_v1(&self) -> &Path {
            &self.0
        }

        fn database_v1(&self) -> PathBuf {
            self.0
                .join(COORDINATOR_ROOT_DIRECTORY)
                .join(COORDINATOR_DATABASE_FILE)
        }
    }

    impl Drop for TestRootV1 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn frozen_supported_partition_matches_the_21_corpus_rows() {
        let corpus: Value = serde_json::from_slice(CASES_BYTES).expect("cases corpus decodes");
        let rows = corpus["fault_boundaries"]
            .as_array()
            .expect("fault boundary rows exist");
        let actual = rows
            .iter()
            .filter(|row| {
                let id = row["boundary_id"].as_str().expect("boundary ID exists");
                let phase = row["phase"].as_str().expect("phase exists");
                let owner = row["owner"].as_str().expect("owner exists");
                TERMINAL_COMMIT_BOUNDARY_IDS_V1.contains(&id)
                    || (phase == "acknowledgement-and-readback" && owner == "coordinator")
                    || phase == "known-failure"
            })
            .map(|row| row["boundary_id"].as_str().expect("boundary ID exists"))
            .collect::<Vec<_>>();
        assert_eq!(actual, SUPPORTED_BOUNDARY_IDS_V1);
        assert!(SUPPORTED_BOUNDARY_IDS_V1
            .iter()
            .all(|boundary| supports_boundary_v1(boundary)));
        assert!(!supports_boundary_v1("acknowledgement_result_returned"));
    }

    #[test]
    fn five_readback_classes_use_live_transaction_fixtures() {
        for (boundary_id, fixture) in [
            (
                "acknowledgement_readback_classified_this_attempt",
                ReadbackFixtureV1::ThisAttempt,
            ),
            (
                "acknowledgement_readback_classified_prior_exact_attempt",
                ReadbackFixtureV1::PriorExactAttempt,
            ),
            (
                "acknowledgement_readback_classified_conflict",
                ReadbackFixtureV1::Conflict,
            ),
            (
                "acknowledgement_readback_classified_definite_absence",
                ReadbackFixtureV1::DefiniteAbsence,
            ),
            (
                "acknowledgement_readback_classified_ambiguous",
                ReadbackFixtureV1::Ambiguous,
            ),
        ] {
            let root = TestRootV1::new_v1();
            prepare_fixture_v1(root.path_v1(), boundary_id).expect("readback fixture prepares");
            let outcome = execute_readback_v1(
                &root.database_v1(),
                fixture,
                &CoordinatorFaultProbeV1::disabled_v1(),
            );
            assert!(
                readback_outcome_matches_v1(fixture, &outcome),
                "wrong readback class for {boundary_id}: {outcome:?}"
            );
            let expected_state: &[u8] = if fixture == ReadbackFixtureV1::DefiniteAbsence {
                b"absent"
            } else {
                b"preparing"
            };
            assert_eq!(
                reopen_state_v1(root.path_v1()).expect("readback root reopens"),
                expected_state
            );
        }
    }

    #[test]
    fn selected_coordinator_readback_reaches_the_caller_owned_arc() {
        let root = TestRootV1::new_v1();
        let boundary_id = "acknowledgement_readback_classified_this_attempt";
        prepare_fixture_v1(root.path_v1(), boundary_id).expect("readback fixture prepares");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_barrier = Arc::clone(&calls);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_boundary_v1(
                root.path_v1(),
                boundary_id,
                1,
                Arc::new(move || {
                    calls_for_barrier.fetch_add(1, Ordering::SeqCst);
                }),
            )
        }));
        assert!(
            result.is_err(),
            "a returning coordinator barrier fails closed"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn known_failure_starts_preparing_and_releases_the_caller_owned_guard() {
        let root = TestRootV1::new_v1();
        let boundary_id = "known_failure_no_dispatch_guard_released";
        prepare_fixture_v1(root.path_v1(), boundary_id).expect("failure fixture prepares");
        require_operation_counts_v1(&root.database_v1(), (1, 1, 0))
            .expect("failure fixture is PREPARING");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_barrier = Arc::clone(&calls);
        run_boundary_v1(
            root.path_v1(),
            boundary_id,
            1,
            Arc::new(move || {
                calls_for_barrier.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .expect("known failure runs");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        require_operation_counts_v1(&root.database_v1(), (1, 0, 1))
            .expect("known failure commits FAILED");
        assert_eq!(
            reopen_state_v1(root.path_v1()).expect("failed root reopens"),
            b"failed"
        );
    }

    #[test]
    fn aborted_and_ambiguous_use_real_fault_probed_terminal_classification() {
        for boundary_id in TERMINAL_COMMIT_BOUNDARY_IDS_V1 {
            let root = TestRootV1::new_v1();
            prepare_fixture_v1(root.path_v1(), boundary_id)
                .expect("terminal classification fixture prepares");
            let calls = Arc::new(AtomicUsize::new(0));
            let calls_for_barrier = Arc::clone(&calls);
            run_boundary_v1(
                root.path_v1(),
                boundary_id,
                1,
                Arc::new(move || {
                    calls_for_barrier.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .expect("terminal classification runs");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            require_operation_counts_v1(&root.database_v1(), (0, 0, 0))
                .expect("terminal refusal does not seed an operation");
            assert_eq!(
                reopen_state_v1(root.path_v1()).expect("terminal root reopens"),
                b"absent"
            );
        }
    }
}
