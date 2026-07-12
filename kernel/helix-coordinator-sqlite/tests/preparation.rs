//! T030 red tests for the canonical durable-preparation transaction.
//!
//! These tests intentionally precede T034/T035/T037. The source-included modules must
//! provide crate-private synthetic transaction/readback seams; production APIs stay
//! closed and this integration test never constructs an eligibility marker or attempt.

mod common;

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

use common::{
    SyntheticCoordinatorClockV1, SyntheticCoordinatorRootV1, SyntheticHistoricalPlanKeyResolverV1,
    SYNTHETIC_BUDGET_ACTION_LIMIT, SYNTHETIC_BUDGET_EGRESS_BYTES_LIMIT,
    SYNTHETIC_BUDGET_MAX_COST_MICRO_UNITS, SYNTHETIC_BUDGET_RECOVERY_BYTES,
};
use comparison_digest::{
    immutable_comparison_digest_for_operation_v1, verify_persisted_comparison_digests_v1,
};
use failure::{
    fail_synthetic_before_dispatch_v1, SyntheticKnownFailureCaseV1, SyntheticNoDispatchGuardCaseV1,
};
use helix_contracts::decode_and_verify_plan;
use helix_plan_preparation::{
    recovery_boot_binding_digest_v1, recovery_precondition_identity_digest_v1,
    recovery_target_reference_digest_v1, PreparationCommitOutcomeV1, PreparationFailureOutcomeV1,
    PreparationReadbackOutcomeV1,
};
use prepare::production::CoordinatorUncertainCommitCustodyV1;
use prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticConflictV1, SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
    CANONICAL_POSITIVE_MEMBER_COUNT_V1,
};
use readback::{
    readback_synthetic_attempt_v1, readback_with_live_snapshot_v1, synthetic_uncertain_v1,
    SyntheticReadbackCaseV1, SyntheticReadbackModeV1,
};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

const OPEN_NOW_MS: u64 = 100;
const OPEN_DEADLINE_MS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct EightMemberObservation {
    metadata: [i64; 4],
    operation: i64,
    transition: i64,
    comparison_and_replay: i64,
    scope_held: [i64; 4],
    reservation: i64,
    recovery_or_irreversibility: i64,
    event: i64,
}

struct ExactCustodyObservation {
    event_id: Vec<u8>,
    scope_id: Vec<u8>,
    comparison_digest: Vec<u8>,
    target_reference_digest: Vec<u8>,
    precondition_identity_digest: Vec<u8>,
    boot_binding_digest: Vec<u8>,
    reservation_created_generation: i64,
    supervisor_generation: i64,
    instance_epoch: i64,
    fencing_epoch: i64,
}

struct StoredRecoveryEvidenceV1 {
    canonical_plan: Vec<u8>,
    recovery_mode: String,
    recovery_class: String,
    target_reference_digest: Vec<u8>,
    precondition_identity_digest: Vec<u8>,
    precondition_digest: Vec<u8>,
    precondition_length: i64,
    reserved_capacity: i64,
    reserved_recovery_bytes: i64,
    provider_profile_id: Option<String>,
    provider_profile_version: Option<i64>,
    provider_id: Option<String>,
    provider_generation: Option<i64>,
    evidence_class: Option<String>,
    at_rest_profile_id: Option<String>,
    capability_binding_digest: Option<Vec<u8>>,
    material_id: Option<Vec<u8>>,
    publication_attempt_id: Option<Vec<u8>>,
    manifest_digest: Option<Vec<u8>>,
    material_digest: Option<Vec<u8>>,
    material_length: Option<i64>,
    material_state: Option<String>,
    boot_binding_digest: Vec<u8>,
    instance_epoch: i64,
    fencing_epoch: i64,
}

impl EightMemberObservation {
    fn read(database: &Path) -> Self {
        let connection = Connection::open(database).expect("synthetic coordinator database opens");
        let metadata = connection
            .query_row(
                "SELECT store_generation, operation_generation, budget_generation, \
                        event_generation \
                 FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
            )
            .expect("metadata generations read");
        let scope_held = connection
            .query_row(
                "SELECT held_cost_micro_units, held_action_count, held_egress_bytes, \
                        held_recovery_bytes \
                 FROM budget_scopes",
                [],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
            )
            .expect("one provisioned synthetic budget scope reads");

        Self {
            metadata,
            operation: count_where(
                &connection,
                "prepared_operations",
                "operation_state = 'PREPARING'",
            ),
            transition: count_where(
                &connection,
                "operation_transitions",
                "previous_state IS NULL AND new_state = 'PREPARING'",
            ),
            comparison_and_replay: count_where(
                &connection,
                "preparation_comparisons",
                "comparison_version = 1 AND replay_claim_id IS NOT NULL \
                 AND replay_binding_digest IS NOT NULL",
            ),
            scope_held,
            reservation: count_where(
                &connection,
                "budget_reservations",
                "reservation_state = 'HELD' AND released_generation IS NULL",
            ),
            recovery_or_irreversibility: count_where(
                &connection,
                "preparation_recovery_evidence",
                "evidence_version = 1 AND recovery_mode IN ('COMPENSATION', 'IRREVERSIBLE')",
            ),
            event: count_where(
                &connection,
                "preparation_events",
                "event_kind = 'PREPARED' AND operation_state = 'PREPARING' \
                 AND delivery_state = 'PENDING'",
            ),
        }
    }

    fn assert_complete_commit_from(&self, baseline: &Self) {
        assert_eq!(
            self.metadata,
            [
                baseline.metadata[0] + 1,
                baseline.metadata[1] + 1,
                baseline.metadata[2] + 1,
                baseline.metadata[3] + 1,
            ],
            "one enclosing commit advances every positive metadata generation once",
        );
        assert_eq!(self.operation, 1, "operation member");
        assert_eq!(self.transition, 1, "transition member");
        assert_eq!(self.comparison_and_replay, 1, "comparison/replay member");
        assert_eq!(
            self.scope_held,
            [
                SYNTHETIC_BUDGET_MAX_COST_MICRO_UNITS as i64,
                SYNTHETIC_BUDGET_ACTION_LIMIT as i64,
                SYNTHETIC_BUDGET_EGRESS_BYTES_LIMIT as i64,
                SYNTHETIC_BUDGET_RECOVERY_BYTES as i64,
            ],
            "scope held-vector delta member",
        );
        assert_eq!(self.reservation, 1, "reservation member");
        assert_eq!(
            self.recovery_or_irreversibility, 1,
            "recovery/irreversibility member",
        );
        assert_eq!(self.event, 1, "event member");
    }
}

fn count_where(connection: &Connection, table: &str, predicate: &str) -> i64 {
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
            [],
            |row| row.get(0),
        )
        .expect("synthetic member count reads")
}

struct PreparedTestRoot {
    root: SyntheticCoordinatorRootV1,
    identity: helix_coordinator_sqlite::CoordinatorRootIdentityEvidenceV1,
    database: PathBuf,
    baseline: EightMemberObservation,
}

impl PreparedTestRoot {
    fn new(case: &SyntheticPreparationCaseV1) -> Self {
        let root = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root");
        let store = root
            .open_empty_v1(
                SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                OPEN_DEADLINE_MS,
            )
            .expect("empty coordinator initializes");
        let identity = store.root_identity_evidence();
        drop(store);

        let database = std::fs::canonicalize(root.path())
            .expect("synthetic coordinator root canonicalizes")
            .join("coordinator.sqlite3");
        provision_synthetic_budget_scope_v1(&database, case)
            .expect("trusted synthetic scope provisions exactly once");
        let baseline = EightMemberObservation::read(&database);
        assert_eq!(baseline.operation, 0);
        assert_eq!(baseline.transition, 0);
        assert_eq!(baseline.comparison_and_replay, 0);
        assert_eq!(baseline.scope_held, [0; 4]);
        assert_eq!(baseline.reservation, 0);
        assert_eq!(baseline.recovery_or_irreversibility, 0);
        assert_eq!(baseline.event, 0);

        Self {
            root,
            identity,
            database,
            baseline,
        }
    }

    fn reopen_and_verify(&self, expected_operations: u64) {
        let reopened = self
            .root
            .open_existing_v1(
                self.identity,
                SyntheticCoordinatorClockV1::new(OPEN_NOW_MS + 1),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                OPEN_DEADLINE_MS,
            )
            .expect("full invariant reopen succeeds");
        assert_eq!(reopened.operation_count(), expected_operations);
    }

    fn assert_reopen_rejected(&self) {
        let result = self.root.open_existing_v1(
            self.identity,
            SyntheticCoordinatorClockV1::new(OPEN_NOW_MS + 1),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            OPEN_DEADLINE_MS,
        );
        assert!(result.is_err(), "immutable corruption survived full reopen");
    }
}

#[test]
fn acknowledged_commit_publishes_all_eight_members_and_both_modes_survive_reopen() {
    for recovery_mode in [
        SyntheticRecoveryModeV1::Compensation,
        SyntheticRecoveryModeV1::Irreversible,
    ] {
        let case = SyntheticPreparationCaseV1::coherent_v1(recovery_mode);
        let fixture = PreparedTestRoot::new(&case);
        let outcome = commit_synthetic_preparation_v1(
            &fixture.database,
            &case,
            SyntheticCommitModeV1::Acknowledged,
        );
        assert!(
            matches!(&outcome, PreparationCommitOutcomeV1::Committed(_)),
            "acknowledged commit must not enter uncertain readback: {outcome:?}",
        );

        let committed = EightMemberObservation::read(&fixture.database);
        committed.assert_complete_commit_from(&fixture.baseline);
        fixture.reopen_and_verify(1);
        assert_eq!(EightMemberObservation::read(&fixture.database), committed);
    }
}

#[test]
fn persisted_recovery_evidence_rejoins_canonical_plan_and_exact_reserved_capacity() {
    for mode in [
        SyntheticRecoveryModeV1::Compensation,
        SyntheticRecoveryModeV1::Irreversible,
    ] {
        let case = SyntheticPreparationCaseV1::coherent_v1(mode);
        let fixture = PreparedTestRoot::new(&case);
        let outcome = commit_synthetic_preparation_v1(
            &fixture.database,
            &case,
            SyntheticCommitModeV1::Acknowledged,
        );
        assert!(matches!(outcome, PreparationCommitOutcomeV1::Committed(_)));

        let operation_id = case.coordinator_readback_input_v1().operation_id;
        let connection = Connection::open(&fixture.database).expect("committed store opens");
        let stored = connection
            .query_row(
                "SELECT operation.canonical_plan, recovery.recovery_mode, \
                        recovery.recovery_class, recovery.target_reference_digest, \
                        recovery.precondition_identity_digest, recovery.precondition_digest, \
                        recovery.precondition_length, recovery.reserved_capacity, \
                        reservation.reserved_recovery_bytes, recovery.provider_profile_id, \
                        recovery.provider_profile_version, recovery.provider_id, \
                        recovery.provider_generation, recovery.evidence_class, \
                        recovery.at_rest_profile_id, recovery.capability_binding_digest, \
                        recovery.material_id, recovery.publication_attempt_id, \
                        recovery.manifest_digest, recovery.material_digest, \
                        recovery.material_length, recovery.material_state, \
                        recovery.boot_binding_digest, recovery.instance_epoch, \
                        recovery.fencing_epoch \
                 FROM prepared_operations AS operation \
                 JOIN budget_reservations AS reservation \
                   ON reservation.operation_id = operation.operation_id \
                 JOIN preparation_recovery_evidence AS recovery \
                   ON recovery.operation_id = operation.operation_id \
                 WHERE operation.operation_id = ?1",
                [operation_id],
                |row| {
                    Ok(StoredRecoveryEvidenceV1 {
                        canonical_plan: row.get(0)?,
                        recovery_mode: row.get(1)?,
                        recovery_class: row.get(2)?,
                        target_reference_digest: row.get(3)?,
                        precondition_identity_digest: row.get(4)?,
                        precondition_digest: row.get(5)?,
                        precondition_length: row.get(6)?,
                        reserved_capacity: row.get(7)?,
                        reserved_recovery_bytes: row.get(8)?,
                        provider_profile_id: row.get(9)?,
                        provider_profile_version: row.get(10)?,
                        provider_id: row.get(11)?,
                        provider_generation: row.get(12)?,
                        evidence_class: row.get(13)?,
                        at_rest_profile_id: row.get(14)?,
                        capability_binding_digest: row.get(15)?,
                        material_id: row.get(16)?,
                        publication_attempt_id: row.get(17)?,
                        manifest_digest: row.get(18)?,
                        material_digest: row.get(19)?,
                        material_length: row.get(20)?,
                        material_state: row.get(21)?,
                        boot_binding_digest: row.get(22)?,
                        instance_epoch: row.get(23)?,
                        fencing_epoch: row.get(24)?,
                    })
                },
            )
            .expect("exact persisted recovery evidence reads");
        let authentic = decode_and_verify_plan(
            &stored.canonical_plan,
            &SyntheticHistoricalPlanKeyResolverV1::default(),
        )
        .expect("retained canonical plan authenticates");
        let claims = authentic.preparation_claims();
        let eligibility = authentic.eligibility_claims();
        assert_eq!(
            stored.target_reference_digest,
            recovery_target_reference_digest_v1(claims.target())
                .expect("target digest derives")
                .as_bytes()
        );
        assert_eq!(
            stored.precondition_identity_digest,
            recovery_precondition_identity_digest_v1(
                claims.precondition_volume_id(),
                claims.precondition_file_id(),
            )
            .expect("precondition identity digest derives")
            .as_bytes()
        );
        assert_eq!(
            stored.boot_binding_digest,
            recovery_boot_binding_digest_v1(
                eligibility.boot_id(),
                eligibility.instance_epoch(),
                eligibility.fencing_epoch(),
            )
            .expect("boot binding digest derives")
            .as_bytes()
        );
        assert_eq!(
            stored.precondition_digest,
            claims.precondition_content_sha256().as_bytes()
        );
        assert_eq!(
            stored.precondition_length,
            claims.precondition_byte_length() as i64
        );
        assert_eq!(
            stored.reserved_capacity,
            claims.recovery_reserved_bytes() as i64
        );
        assert_eq!(stored.reserved_recovery_bytes, stored.reserved_capacity);
        assert_eq!(stored.instance_epoch, eligibility.instance_epoch() as i64);
        assert_eq!(stored.fencing_epoch, eligibility.fencing_epoch() as i64);

        match mode {
            SyntheticRecoveryModeV1::Compensation => {
                assert_eq!(stored.recovery_mode, "COMPENSATION");
                assert_eq!(stored.recovery_class, "COMPENSATION");
                assert!(stored.provider_profile_id.is_some());
                assert_eq!(stored.provider_profile_version, Some(1));
                assert!(stored.provider_id.is_some());
                assert_eq!(stored.provider_generation, Some(1));
                assert_eq!(
                    stored.evidence_class.as_deref(),
                    Some("SYNTHETIC_CONFORMANCE")
                );
                assert!(stored.at_rest_profile_id.is_some());
                assert!(stored.capability_binding_digest.is_some());
                assert!(stored.material_id.is_some());
                assert!(stored.publication_attempt_id.is_some());
                assert!(stored.manifest_digest.is_some());
                assert_eq!(stored.material_digest, Some(stored.precondition_digest));
                assert_eq!(stored.material_length, Some(stored.precondition_length));
                assert_eq!(stored.material_state.as_deref(), Some("PUBLISHED"));
            }
            SyntheticRecoveryModeV1::Irreversible => {
                assert_eq!(stored.recovery_mode, "IRREVERSIBLE");
                assert_eq!(stored.recovery_class, "IRREVERSIBLE");
                assert!(stored.provider_profile_id.is_none());
                assert!(stored.provider_profile_version.is_none());
                assert!(stored.provider_id.is_none());
                assert!(stored.provider_generation.is_none());
                assert!(stored.evidence_class.is_none());
                assert!(stored.at_rest_profile_id.is_none());
                assert!(stored.capability_binding_digest.is_none());
                assert!(stored.material_id.is_none());
                assert!(stored.publication_attempt_id.is_none());
                assert!(stored.manifest_digest.is_none());
                assert!(stored.material_digest.is_none());
                assert!(stored.material_length.is_none());
                assert!(stored.material_state.is_none());
            }
        }
        drop(connection);
        fixture.reopen_and_verify(1);
    }
}

#[test]
fn comparison_digest_survives_lifecycle_mutation_but_rejects_immutable_corruption() {
    let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
    let fixture = PreparedTestRoot::new(&case);
    let outcome = commit_synthetic_preparation_v1(
        &fixture.database,
        &case,
        SyntheticCommitModeV1::Acknowledged,
    );
    assert!(matches!(outcome, PreparationCommitOutcomeV1::Committed(_)));

    let operation_id = case.coordinator_readback_input_v1().operation_id;
    let connection = Connection::open(&fixture.database).expect("committed store opens");
    let original = immutable_comparison_digest_for_operation_v1(&connection, operation_id)
        .expect("immutable comparison projection recomputes");
    verify_persisted_comparison_digests_v1(&connection)
        .expect("writer and verifier use the same immutable projection");

    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("isolated lifecycle test disables graph checks");
    connection
        .execute(
            "UPDATE budget_scopes SET held_cost_micro_units = 0, held_action_count = 0, \
             held_egress_bytes = 0, held_recovery_bytes = 0",
            [],
        )
        .expect("scope hold snapshot advances");
    connection
        .execute(
            "UPDATE prepared_operations SET operation_state = 'FAILED', \
             state_generation = state_generation + 100, failed_generation = 100, \
             failed_reason_code = 'PREPARATION_STORE_UNAVAILABLE' \
             WHERE operation_id = ?1",
            [operation_id],
        )
        .expect("operation lifecycle advances");
    connection
        .execute(
            "UPDATE budget_reservations SET reservation_state = 'RELEASED', \
             released_generation = 100 WHERE operation_id = ?1",
            [operation_id],
        )
        .expect("reservation lifecycle advances");
    connection
        .execute(
            "UPDATE preparation_recovery_evidence SET material_state = 'RETIRED_TOMBSTONE', \
             retirement_id = ?1, retirement_manifest_digest = ?2, \
             retirement_generation = 100 WHERE operation_id = ?3",
            rusqlite::params![
                [0x91_u8; 32].as_slice(),
                [0x92_u8; 32].as_slice(),
                operation_id
            ],
        )
        .expect("recovery lifecycle advances");

    assert_eq!(
        immutable_comparison_digest_for_operation_v1(&connection, operation_id)
            .expect("mutated lifecycle projection recomputes"),
        original,
        "mutable hold/state/retirement fields cannot invalidate historical comparison proof",
    );
    verify_persisted_comparison_digests_v1(&connection)
        .expect("persisted digest remains exact after lifecycle mutation");

    connection
        .execute(
            "UPDATE preparation_comparisons SET capture_generation = capture_generation + 1 \
             WHERE operation_id = ?1",
            [operation_id],
        )
        .expect("immutable comparison binding corrupts");
    assert!(
        verify_persisted_comparison_digests_v1(&connection).is_err(),
        "immutable comparison corruption must fail closed",
    );
}

#[test]
fn canonical_recovery_bindings_reject_corruption_even_after_digest_recalculation() {
    for column in [
        "target_reference_digest",
        "precondition_identity_digest",
        "boot_binding_digest",
        "reserved_capacity",
    ] {
        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
        let fixture = PreparedTestRoot::new(&case);
        let outcome = commit_synthetic_preparation_v1(
            &fixture.database,
            &case,
            SyntheticCommitModeV1::Acknowledged,
        );
        assert!(matches!(outcome, PreparationCommitOutcomeV1::Committed(_)));
        let operation_id = case.coordinator_readback_input_v1().operation_id;
        let connection = Connection::open(&fixture.database).expect("committed store opens");
        match column {
            "reserved_capacity" => {
                connection
                    .execute(
                        "UPDATE preparation_recovery_evidence \
                         SET reserved_capacity = reserved_capacity + 1 \
                         WHERE operation_id = ?1",
                        [operation_id],
                    )
                    .expect("signed reserved capacity corrupts");
            }
            digest_column => {
                let sql = format!(
                    "UPDATE preparation_recovery_evidence SET {digest_column} = ?1 \
                     WHERE operation_id = ?2"
                );
                connection
                    .execute(
                        &sql,
                        rusqlite::params![[0xee_u8; 32].as_slice(), operation_id],
                    )
                    .expect("canonical recovery digest corrupts");
            }
        }
        let recomputed = immutable_comparison_digest_for_operation_v1(&connection, operation_id)
            .expect("attacker-visible digest projection recomputes");
        connection
            .execute(
                "UPDATE preparation_comparisons SET comparison_digest = ?1 \
                 WHERE operation_id = ?2",
                rusqlite::params![recomputed.as_slice(), operation_id],
            )
            .expect("persisted comparison digest is substituted coherently");
        verify_persisted_comparison_digests_v1(&connection)
            .expect("generic immutable digest alone now appears exact");
        drop(connection);
        fixture.assert_reopen_rejected();
    }
}

#[test]
fn full_reopen_accepts_closed_recovery_lifecycle_without_weakening_immutable_digest() {
    let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
    let fixture = PreparedTestRoot::new(&case);
    let outcome = commit_synthetic_preparation_v1(
        &fixture.database,
        &case,
        SyntheticCommitModeV1::Acknowledged,
    );
    assert!(matches!(outcome, PreparationCommitOutcomeV1::Committed(_)));
    let operation_id = case.coordinator_readback_input_v1().operation_id;
    let known =
        SyntheticKnownFailureCaseV1::load_preparing_v1(&fixture.database, operation_id, 17, 10_000)
            .expect("committed preparation loads for guarded failure");
    assert!(matches!(
        fail_synthetic_before_dispatch_v1(
            &fixture.database,
            &known,
            SyntheticNoDispatchGuardCaseV1::Exact,
            1_000,
        ),
        PreparationFailureOutcomeV1::Failed
    ));
    fixture.reopen_and_verify(1);

    let original_digest = {
        let connection = Connection::open(&fixture.database).expect("failed store opens");
        immutable_comparison_digest_for_operation_v1(&connection, operation_id)
            .expect("immutable digest reads after failure")
    };
    {
        let mut connection = Connection::open(&fixture.database).expect("failed store opens");
        let transaction = connection.transaction().expect("retirement writer begins");
        let store_generation: i64 = transaction
            .query_row(
                "SELECT store_generation FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("store generation reads");
        let retirement_generation = store_generation + 1;
        transaction
            .execute(
                "UPDATE preparation_recovery_evidence \
                 SET material_state = 'RETIREMENT_PENDING', retirement_id = ?1, \
                     retirement_generation = ?2 \
                 WHERE operation_id = ?3 AND material_state = 'PUBLISHED'",
                rusqlite::params![
                    [0x71_u8; 32].as_slice(),
                    retirement_generation,
                    operation_id,
                ],
            )
            .expect("retirement pending stages");
        transaction
            .execute(
                "UPDATE coordinator_store_meta SET store_generation = ?1 \
                 WHERE singleton = 1 AND store_generation = ?2",
                rusqlite::params![retirement_generation, store_generation],
            )
            .expect("retirement high-water advances");
        transaction.commit().expect("retirement pending commits");
    }
    fixture.reopen_and_verify(1);
    {
        let connection = Connection::open(&fixture.database).expect("pending store opens");
        assert_eq!(
            immutable_comparison_digest_for_operation_v1(&connection, operation_id)
                .expect("pending lifecycle digest recomputes"),
            original_digest
        );
        verify_persisted_comparison_digests_v1(&connection)
            .expect("pending lifecycle preserves persisted digest");
        connection
            .execute(
                "UPDATE preparation_recovery_evidence \
                 SET material_state = 'RETIRED_TOMBSTONE', \
                     retirement_manifest_digest = ?1 \
                 WHERE operation_id = ?2 AND material_state = 'RETIREMENT_PENDING'",
                rusqlite::params![[0x72_u8; 32].as_slice(), operation_id],
            )
            .expect("retired tombstone publishes");
    }
    fixture.reopen_and_verify(1);
    let connection = Connection::open(&fixture.database).expect("retired store opens");
    assert_eq!(
        immutable_comparison_digest_for_operation_v1(&connection, operation_id)
            .expect("retired lifecycle digest recomputes"),
        original_digest
    );
    verify_persisted_comparison_digests_v1(&connection)
        .expect("retired lifecycle preserves persisted digest");
}

#[test]
fn rollback_after_each_staged_member_leaves_all_eight_members_absent_after_reopen() {
    assert_eq!(CANONICAL_POSITIVE_MEMBER_COUNT_V1, 8);
    for staged_member in 1..=CANONICAL_POSITIVE_MEMBER_COUNT_V1 {
        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
        let fixture = PreparedTestRoot::new(&case);
        let outcome = commit_synthetic_preparation_v1(
            &fixture.database,
            &case,
            SyntheticCommitModeV1::ConfirmedRollbackAfterMember(staged_member),
        );
        assert!(
            matches!(&outcome, PreparationCommitOutcomeV1::ConfirmedRollback),
            "member {staged_member} rollback was not definitive: {outcome:?}",
        );
        assert_eq!(
            EightMemberObservation::read(&fixture.database),
            fixture.baseline,
            "member {staged_member} leaked a partial coordinator commit",
        );
        fixture.reopen_and_verify(0);
        assert_eq!(
            EightMemberObservation::read(&fixture.database),
            fixture.baseline
        );
    }
}

#[test]
fn every_incompatible_occupant_conflicts_without_overwrite_or_second_hold() {
    for conflict in [
        SyntheticConflictV1::Plan,
        SyntheticConflictV1::Replay,
        SyntheticConflictV1::Budget,
        SyntheticConflictV1::Recovery,
    ] {
        let original =
            SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
        let fixture = PreparedTestRoot::new(&original);
        let first = commit_synthetic_preparation_v1(
            &fixture.database,
            &original,
            SyntheticCommitModeV1::Acknowledged,
        );
        assert!(matches!(first, PreparationCommitOutcomeV1::Committed(_)));
        let committed = EightMemberObservation::read(&fixture.database);

        let contender = original.conflicting_v1(conflict);
        let second = commit_synthetic_preparation_v1(
            &fixture.database,
            &contender,
            SyntheticCommitModeV1::Acknowledged,
        );
        assert!(
            matches!(&second, PreparationCommitOutcomeV1::Conflict),
            "incompatible occupant was not a closed conflict: {second:?}",
        );
        assert_eq!(EightMemberObservation::read(&fixture.database), committed);
        fixture.reopen_and_verify(1);
    }
}

#[test]
fn explicit_uncertainty_reads_back_this_attempt_or_definite_absence_without_retry() {
    let committed_case =
        SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
    let committed_root = PreparedTestRoot::new(&committed_case);
    let uncertain_outcome = commit_synthetic_preparation_v1(
        &committed_root.database,
        &committed_case,
        SyntheticCommitModeV1::UncertainCommitted,
    );
    let uncertain = match uncertain_outcome {
        PreparationCommitOutcomeV1::Uncertain { token, .. } => token,
        other => panic!("lost acknowledgement must be explicitly uncertain: {other:?}"),
    };
    let readback = readback_synthetic_attempt_v1(
        &committed_root.database,
        &committed_case,
        &uncertain,
        SyntheticReadbackModeV1::Healthy,
    );
    assert!(
        matches!(&readback, PreparationReadbackOutcomeV1::ThisAttempt(_)),
        "durable uncertain commit must classify THIS_ATTEMPT: {readback:?}",
    );
    EightMemberObservation::read(&committed_root.database)
        .assert_complete_commit_from(&committed_root.baseline);
    committed_root.reopen_and_verify(1);

    let absent_case =
        SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
    let absent_root = PreparedTestRoot::new(&absent_case);
    let uncertain_outcome = commit_synthetic_preparation_v1(
        &absent_root.database,
        &absent_case,
        SyntheticCommitModeV1::UncertainRolledBack,
    );
    let uncertain = match uncertain_outcome {
        PreparationCommitOutcomeV1::Uncertain { token, .. } => token,
        other => panic!("lost rollback acknowledgement must be uncertain: {other:?}"),
    };
    let readback = readback_synthetic_attempt_v1(
        &absent_root.database,
        &absent_case,
        &uncertain,
        SyntheticReadbackModeV1::Healthy,
    );
    assert!(
        matches!(&readback, PreparationReadbackOutcomeV1::DefiniteAbsence),
        "healthy all-key absence must be definite: {readback:?}",
    );
    assert_eq!(
        EightMemberObservation::read(&absent_root.database),
        absent_root.baseline
    );
    absent_root.reopen_and_verify(0);
}

#[test]
fn exact_readback_distinguishes_prior_conflict_and_ambiguous_snapshots() {
    let original = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
    let fixture = PreparedTestRoot::new(&original);
    let first = commit_synthetic_preparation_v1(
        &fixture.database,
        &original,
        SyntheticCommitModeV1::Acknowledged,
    );
    assert!(matches!(first, PreparationCommitOutcomeV1::Committed(_)));
    let committed = EightMemberObservation::read(&fixture.database);

    let prior = original.next_exact_attempt_v1();
    let prior_uncertain = synthetic_uncertain_v1(&prior);
    let prior_result = readback_synthetic_attempt_v1(
        &fixture.database,
        &prior,
        &prior_uncertain,
        SyntheticReadbackModeV1::Healthy,
    );
    assert!(
        matches!(
            &prior_result,
            PreparationReadbackOutcomeV1::PriorExactAttempt
        ),
        "coherent prior occupant must not return a second marker: {prior_result:?}",
    );

    let conflicting = original.conflicting_v1(SyntheticConflictV1::Plan);
    let conflict_uncertain = synthetic_uncertain_v1(&conflicting);
    let conflict_result = readback_synthetic_attempt_v1(
        &fixture.database,
        &conflicting,
        &conflict_uncertain,
        SyntheticReadbackModeV1::Healthy,
    );
    assert!(
        matches!(&conflict_result, PreparationReadbackOutcomeV1::Conflict),
        "incompatible coherent occupant must be conflict: {conflict_result:?}",
    );

    let ambiguous = synthetic_uncertain_v1(&original);
    let ambiguous_result = readback_synthetic_attempt_v1(
        &fixture.database,
        &original,
        &ambiguous,
        SyntheticReadbackModeV1::ContradictorySnapshot,
    );
    assert!(
        matches!(&ambiguous_result, PreparationReadbackOutcomeV1::Ambiguous),
        "partial/contradictory proof must stay ambiguous: {ambiguous_result:?}",
    );

    assert_eq!(EightMemberObservation::read(&fixture.database), committed);
    fixture.reopen_and_verify(1);
}

#[test]
fn production_exact_custody_rejoins_every_attempt_owned_binding() {
    let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
    let fixture = PreparedTestRoot::new(&case);
    let outcome = commit_synthetic_preparation_v1(
        &fixture.database,
        &case,
        SyntheticCommitModeV1::Acknowledged,
    );
    assert!(matches!(outcome, PreparationCommitOutcomeV1::Committed(_)));

    let base = case.coordinator_readback_input_v1();
    let connection = Connection::open(&fixture.database).expect("committed store opens");
    let (store_generation, operation_generation, event_generation): (i64, i64, i64) = connection
        .query_row(
            "SELECT store_generation, operation_generation, event_generation \
             FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("metadata generations read");
    let exact_rows = connection
        .query_row(
            "SELECT event.event_id, reservation.scope_id, comparison.comparison_digest, \
                        recovery.target_reference_digest, \
                        recovery.precondition_identity_digest, recovery.boot_binding_digest, \
                        reservation.created_generation, comparison.supervisor_generation, \
                        comparison.instance_epoch, comparison.fencing_epoch \
                 FROM prepared_operations AS operation \
                 JOIN preparation_events AS event \
                   ON event.event_id = operation.current_event_id \
                 JOIN budget_reservations AS reservation \
                   ON reservation.operation_id = operation.operation_id \
                 JOIN preparation_comparisons AS comparison \
                   ON comparison.operation_id = operation.operation_id \
                 JOIN preparation_recovery_evidence AS recovery \
                   ON recovery.operation_id = operation.operation_id \
                 WHERE operation.operation_id = ?1",
            [base.operation_id],
            |row| {
                Ok(ExactCustodyObservation {
                    event_id: row.get(0)?,
                    scope_id: row.get(1)?,
                    comparison_digest: row.get(2)?,
                    target_reference_digest: row.get(3)?,
                    precondition_identity_digest: row.get(4)?,
                    boot_binding_digest: row.get(5)?,
                    reservation_created_generation: row.get(6)?,
                    supervisor_generation: row.get(7)?,
                    instance_epoch: row.get(8)?,
                    fencing_epoch: row.get(9)?,
                })
            },
        )
        .expect("exact joined custody reads");
    drop(connection);

    fn exact_digest(bytes: Vec<u8>) -> helix_contracts::Sha256Digest {
        helix_contracts::Sha256Digest::from_bytes(
            bytes.try_into().expect("stored exact digest has 32 bytes"),
        )
    }

    let mut custody = CoordinatorUncertainCommitCustodyV1 {
        operation_id: base.operation_id.to_owned(),
        attempt_id: base.attempt_id,
        plan_id: base.plan_id,
        reservation_id: base.reservation_id.to_owned(),
        event_id: exact_digest(exact_rows.event_id),
        scope_id: exact_digest(exact_rows.scope_id),
        budget_scope_binding_digest: base.allowance_binding_digest,
        comparison_digest: exact_digest(exact_rows.comparison_digest),
        replay_claim_id: base.replay_claim_id,
        replay_claimant_generation: base.replay_claimant_generation,
        replay_binding_digest: base.replay_binding_digest,
        target_reference_digest: exact_digest(exact_rows.target_reference_digest),
        precondition_identity_digest: exact_digest(exact_rows.precondition_identity_digest),
        boot_binding_digest: exact_digest(exact_rows.boot_binding_digest),
        budget_scope_generation: base.scope_generation,
        store_generation: u64::try_from(store_generation).expect("safe store generation"),
        operation_generation: u64::try_from(operation_generation)
            .expect("safe operation generation"),
        event_generation: u64::try_from(event_generation).expect("safe event generation"),
        reservation_created_generation: u64::try_from(exact_rows.reservation_created_generation)
            .expect("safe reservation generation"),
        supervisor_generation: u64::try_from(exact_rows.supervisor_generation)
            .expect("safe supervisor generation"),
        instance_epoch: u64::try_from(exact_rows.instance_epoch).expect("safe instance epoch"),
        fencing_epoch: u64::try_from(exact_rows.fencing_epoch).expect("safe fencing epoch"),
    };
    {
        let mut exact = case.coordinator_readback_input_v1();
        exact.exact_custody = Some(&custody);
        let mut fresh = Connection::open(&fixture.database).expect("fresh readback opens");
        let exact_result = readback_with_live_snapshot_v1(&mut fresh, &exact, |_| true);
        assert!(
            matches!(exact_result, PreparationReadbackOutcomeV1::ThisAttempt(_)),
            "exact production custody did not rejoin the committed package: {exact_result:?}",
        );
    }

    custody.comparison_digest = helix_contracts::Sha256Digest::from_bytes([0xee; 32]);
    let mut mismatched = case.coordinator_readback_input_v1();
    mismatched.exact_custody = Some(&custody);
    let mut fresh = Connection::open(&fixture.database).expect("second fresh readback opens");
    let mismatch = readback_with_live_snapshot_v1(&mut fresh, &mismatched, |_| true);
    assert!(
        matches!(mismatch, PreparationReadbackOutcomeV1::Ambiguous),
        "same-attempt comparison custody mismatch must stay ambiguous: {mismatch:?}",
    );
}
