//! T041 red tests for guarded, idempotent known pre-dispatch failure.
//!
//! The fixture is deliberately local and builds one real v1 SQLite preparation. The
//! only API expected from production is a crate-private synthetic seam in `failure.rs`;
//! it must delegate staging to the transaction-only helpers in `transition.rs` and
//! `outbox.rs`. No public attempt constructor or caller-supplied budget vector is added.

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
use helix_plan_preparation::{PreparationCommitOutcomeV1, PreparationFailureOutcomeV1};
#[allow(unused_imports)] // Compile-time contract for the transaction-only T047 seam.
use outbox::{stage_failed_event_v1, FailedEventRowV1};
use prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[allow(unused_imports)] // Compile-time contract for the append-only T047 seam.
use transition::{stage_failed_transition_v1, FailedTransitionRowV1};

const NOW_MONOTONIC_MS: u64 = 1_000;
const GUARD_DEADLINE_MONOTONIC_MS: u64 = 10_000;
const REVOCATION_GENERATION: u64 = 17;
const STORE_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);

#[derive(Debug, PartialEq, Eq)]
struct OperationObservation {
    state: String,
    state_generation: i64,
    failed_generation: Option<i64>,
    failed_reason_code: Option<String>,
    attempt_id: Vec<u8>,
    boot_id: String,
    instance_epoch: i64,
    fencing_epoch: i64,
    current_event_id: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct ReservationObservation {
    state: String,
    released_generation: Option<i64>,
    reserved: [i64; 4],
}

#[derive(Debug, PartialEq, Eq)]
struct ReplayObservation {
    claim_id: Vec<u8>,
    claimant_generation: i64,
    binding_digest: Vec<u8>,
    comparison_digest: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveryObservation {
    recovery_mode: String,
    target_reference_digest: Vec<u8>,
    precondition_identity_digest: Vec<u8>,
    precondition_digest: Vec<u8>,
    boot_binding_digest: Vec<u8>,
    instance_epoch: i64,
    fencing_epoch: i64,
}

#[derive(Debug, PartialEq, Eq)]
struct TransitionObservation {
    state_generation: i64,
    previous_state: Option<String>,
    new_state: String,
    event_id: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct EventObservation {
    event_generation: i64,
    operation_state_generation: i64,
    operation_state: String,
    event_kind: String,
    reason_code: Option<String>,
    event_id: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct DurableObservation {
    metadata: [i64; 4],
    operation: OperationObservation,
    scope_held: [i64; 4],
    reservation: ReservationObservation,
    replay: ReplayObservation,
    recovery: RecoveryObservation,
    transitions: Vec<TransitionObservation>,
    events: Vec<EventObservation>,
}

impl DurableObservation {
    fn read(database: &Path, operation_id: &str) -> Self {
        let connection = Connection::open(database).expect("coordinator database opens");
        let metadata = connection
            .query_row(
                "SELECT store_generation, operation_generation, budget_generation, \
                        event_generation \
                 FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
            )
            .expect("metadata generations read");
        let operation = connection
            .query_row(
                "SELECT operation_state, state_generation, failed_generation, \
                        failed_reason_code, attempt_id, boot_id, instance_epoch, \
                        fencing_epoch, current_event_id \
                 FROM prepared_operations WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    Ok(OperationObservation {
                        state: row.get(0)?,
                        state_generation: row.get(1)?,
                        failed_generation: row.get(2)?,
                        failed_reason_code: row.get(3)?,
                        attempt_id: row.get(4)?,
                        boot_id: row.get(5)?,
                        instance_epoch: row.get(6)?,
                        fencing_epoch: row.get(7)?,
                        current_event_id: row.get(8)?,
                    })
                },
            )
            .expect("operation reads");
        let scope_held = connection
            .query_row(
                "SELECT held_cost_micro_units, held_action_count, held_egress_bytes, \
                        held_recovery_bytes \
                 FROM budget_scopes",
                [],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
            )
            .expect("scope held vector reads");
        let reservation = connection
            .query_row(
                "SELECT reservation_state, released_generation, reserved_cost_micro_units, \
                        reserved_action_count, reserved_egress_bytes, reserved_recovery_bytes \
                 FROM budget_reservations WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    Ok(ReservationObservation {
                        state: row.get(0)?,
                        released_generation: row.get(1)?,
                        reserved: [row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?],
                    })
                },
            )
            .expect("reservation reads");
        let replay = connection
            .query_row(
                "SELECT replay_claim_id, replay_claimant_generation, replay_binding_digest, \
                        comparison_digest \
                 FROM preparation_comparisons WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    Ok(ReplayObservation {
                        claim_id: row.get(0)?,
                        claimant_generation: row.get(1)?,
                        binding_digest: row.get(2)?,
                        comparison_digest: row.get(3)?,
                    })
                },
            )
            .expect("permanent replay evidence reads");
        let recovery = connection
            .query_row(
                "SELECT recovery_mode, target_reference_digest, \
                        precondition_identity_digest, precondition_digest, \
                        boot_binding_digest, instance_epoch, fencing_epoch \
                 FROM preparation_recovery_evidence WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    Ok(RecoveryObservation {
                        recovery_mode: row.get(0)?,
                        target_reference_digest: row.get(1)?,
                        precondition_identity_digest: row.get(2)?,
                        precondition_digest: row.get(3)?,
                        boot_binding_digest: row.get(4)?,
                        instance_epoch: row.get(5)?,
                        fencing_epoch: row.get(6)?,
                    })
                },
            )
            .expect("recovery evidence reads");

        let transitions = {
            let mut statement = connection
                .prepare(
                    "SELECT state_generation, previous_state, new_state, event_id \
                     FROM operation_transitions WHERE operation_id = ?1 \
                     ORDER BY state_generation",
                )
                .expect("transition query prepares");
            statement
                .query_map([operation_id], |row| {
                    Ok(TransitionObservation {
                        state_generation: row.get(0)?,
                        previous_state: row.get(1)?,
                        new_state: row.get(2)?,
                        event_id: row.get(3)?,
                    })
                })
                .expect("transitions query")
                .map(|row| row.expect("transition row reads"))
                .collect()
        };
        let events = {
            let mut statement = connection
                .prepare(
                    "SELECT event_generation, operation_state_generation, operation_state, \
                            event_kind, reason_code, event_id \
                     FROM preparation_events WHERE operation_id = ?1 \
                     ORDER BY event_generation",
                )
                .expect("event query prepares");
            statement
                .query_map([operation_id], |row| {
                    Ok(EventObservation {
                        event_generation: row.get(0)?,
                        operation_state_generation: row.get(1)?,
                        operation_state: row.get(2)?,
                        event_kind: row.get(3)?,
                        reason_code: row.get(4)?,
                        event_id: row.get(5)?,
                    })
                })
                .expect("events query")
                .map(|row| row.expect("event row reads"))
                .collect()
        };

        Self {
            metadata,
            operation,
            scope_held,
            reservation,
            replay,
            recovery,
            transitions,
            events,
        }
    }
}

struct PreparedFixture {
    directory: PathBuf,
    database: PathBuf,
    operation_id: String,
}

impl PreparedFixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "helixos-t041-cancellation-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("fixture directory creates");
        let directory = fs::canonicalize(directory)
            .expect("fixture root canonicalizes before SQLITE_OPEN_NOFOLLOW");
        let database = directory.join("coordinator.sqlite3");
        let connection = Connection::open(&database).expect("fixture database creates");
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
                params![[0x41_u8; 32].as_slice()],
            )
            .expect("root metadata initializes");
        drop(connection);

        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
        provision_synthetic_budget_scope_v1(&database, &case)
            .expect("trusted scope fixture provisions");
        assert!(matches!(
            commit_synthetic_preparation_v1(&database, &case, SyntheticCommitModeV1::Acknowledged,),
            PreparationCommitOutcomeV1::Committed(_)
        ));
        let operation_id = Connection::open(&database)
            .expect("fixture database reopens")
            .query_row("SELECT operation_id FROM prepared_operations", [], |row| {
                row.get(0)
            })
            .expect("prepared operation id reads");
        Self {
            directory,
            database,
            operation_id,
        }
    }

    fn known_failure(&self) -> SyntheticKnownFailureCaseV1 {
        SyntheticKnownFailureCaseV1::load_preparing_v1(
            &self.database,
            &self.operation_id,
            REVOCATION_GENERATION,
            GUARD_DEADLINE_MONOTONIC_MS,
        )
        .expect("coherent PREPARING fixture yields exact synthetic failure custody")
    }

    fn observe(&self) -> DurableObservation {
        DurableObservation::read(&self.database, &self.operation_id)
    }
}

impl Drop for PreparedFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn exact_live_guard_commits_one_failed_tombstone_and_releases_the_stored_vector_once() {
    let fixture = PreparedFixture::new();
    let known_failure = fixture.known_failure();
    let before = fixture.observe();
    assert_eq!(before.operation.state, "PREPARING");
    assert_eq!(before.reservation.state, "HELD");
    assert_eq!(before.scope_held, before.reservation.reserved);
    assert!(before.scope_held.iter().any(|value| *value != 0));

    let first = fail_synthetic_before_dispatch_v1(
        &fixture.database,
        &known_failure,
        SyntheticNoDispatchGuardCaseV1::Exact,
        NOW_MONOTONIC_MS,
    );
    assert!(matches!(first, PreparationFailureOutcomeV1::Failed));

    let failed = fixture.observe();
    assert_eq!(
        failed.metadata,
        [
            before.metadata[0] + 1,
            before.metadata[1] + 1,
            before.metadata[2] + 1,
            before.metadata[3] + 1,
        ]
    );
    assert_eq!(failed.operation.state, "FAILED");
    assert_eq!(
        failed.operation.state_generation,
        before.operation.state_generation + 1
    );
    assert_eq!(failed.operation.failed_generation, Some(failed.metadata[0]));
    assert_eq!(failed.reservation.state, "RELEASED");
    assert_eq!(
        failed.reservation.released_generation,
        failed.operation.failed_generation
    );
    assert_eq!(failed.reservation.reserved, before.reservation.reserved);
    assert_eq!(failed.scope_held, [0; 4]);
    assert_eq!(failed.transitions.len(), before.transitions.len() + 1);
    assert_eq!(failed.events.len(), before.events.len() + 1);
    assert_eq!(
        failed
            .transitions
            .iter()
            .filter(|transition| transition.new_state == "FAILED")
            .count(),
        1,
    );
    assert_eq!(
        failed
            .events
            .iter()
            .filter(|event| event.event_kind == "PREPARATION_FAILED")
            .count(),
        1,
    );

    let failure_transition = failed
        .transitions
        .last()
        .expect("failure transition exists");
    let failure_event = failed.events.last().expect("failure event exists");
    assert_eq!(
        failure_transition.previous_state.as_deref(),
        Some("PREPARING")
    );
    assert_eq!(failure_transition.new_state, "FAILED");
    assert_eq!(failure_event.operation_state, "FAILED");
    assert_eq!(failure_event.event_kind, "PREPARATION_FAILED");
    assert!(failure_event.reason_code.is_some());
    assert_eq!(
        failure_event.reason_code, failed.operation.failed_reason_code,
        "the one failure event and terminal operation share one closed reason",
    );
    assert_eq!(failure_transition.event_id, failure_event.event_id);
    assert_eq!(failed.operation.current_event_id, failure_event.event_id);
    assert_eq!(failed.replay, before.replay, "replay remains claimed");
    assert_eq!(failed.recovery, before.recovery, "recovery is not retired");

    let repeated = fail_synthetic_before_dispatch_v1(
        &fixture.database,
        &known_failure,
        SyntheticNoDispatchGuardCaseV1::Exact,
        NOW_MONOTONIC_MS,
    );
    assert!(matches!(
        repeated,
        PreparationFailureOutcomeV1::AlreadyFailed
    ));
    assert_eq!(
        fixture.observe(),
        failed,
        "terminal readback cannot subtract, append, or advance generations twice",
    );
}

#[test]
fn every_missing_or_inexact_no_dispatch_guard_leaves_all_durable_state_unchanged() {
    let cases = [
        (
            SyntheticNoDispatchGuardCaseV1::Absent,
            PreparationFailureOutcomeV1::Unavailable,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::WrongOperation,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::WrongAttempt,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::WrongStateGeneration,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::WrongBootId,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::WrongInstanceEpoch,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::WrongFencingEpoch,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::WrongRevocationGeneration,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::Expired,
            PreparationFailureOutcomeV1::DeadlineReached,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::RevokedBeforeCommit,
            PreparationFailureOutcomeV1::Mismatch,
        ),
        (
            SyntheticNoDispatchGuardCaseV1::Unavailable,
            PreparationFailureOutcomeV1::Unavailable,
        ),
    ];

    for (guard_case, expected) in cases {
        let fixture = PreparedFixture::new();
        let known_failure = fixture.known_failure();
        let before = fixture.observe();
        let guard_case_label = format!("{guard_case:?}");
        let actual = fail_synthetic_before_dispatch_v1(
            &fixture.database,
            &known_failure,
            guard_case,
            NOW_MONOTONIC_MS,
        );
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
        assert_eq!(
            fixture.observe(),
            before,
            "{guard_case_label} changed operation, hold, ledger, event, replay, or recovery",
        );
    }
}
