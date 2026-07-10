//! Ownership: T016 permanent-claim, conflict, generation and atomic-row behavior.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, MAINTENANCE_DEADLINE_MONOTONIC_MS,
    OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_contracts::MAX_SAFE_U64;
use helix_plan_eligibility::EligibilityDenialV1;
use helix_replay_sqlite::SqliteReplayClaimantV1;
use rusqlite::{params, Connection};
use std::error::Error as _;

fn assert_denial(
    result: Result<
        helix_plan_eligibility::EligiblePlanV1,
        helix_plan_eligibility::EligibilityFailureV1,
    >,
    expected: EligibilityDenialV1,
) {
    let failure = result
        .err()
        .unwrap_or_else(|| panic!("replay-denied fixture was accepted"));
    assert_eq!(failure.denial(), expected);
}

#[test]
fn fresh_claim_survives_reopen_and_both_uniqueness_indexes_remain_atomic() {
    let root = SyntheticTempRoot::new("claim-lifecycle");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&root, clock.clone());

    let (fresh, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    let fresh = fresh.unwrap_or_else(|_| panic!("fresh coherent claim was denied"));
    assert_eq!(fresh.replay_claim().claimant_generation(), 1);
    assert_eq!(
        observed,
        ObservedReplayOutcome::Claimed {
            claimant_generation: 1,
            receipt_matches_binding: true,
            claim_id_is_nonzero: true,
        }
    );
    drop(claimant);

    let claimant = open_store(&root, clock);
    let (repeat, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert_denial(repeat, EligibilityDenialV1::ReplayAlreadyClaimed);
    assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);

    let (nonce_conflict, observed) = evaluate_with_observation(
        feature002_fixture(Feature002Variant::SameNonceDifferentOperation),
        &claimant,
    );
    assert_denial(nonce_conflict, EligibilityDenialV1::ReplayBindingConflict);
    assert_eq!(observed, ObservedReplayOutcome::BindingConflict);

    let (operation_conflict, observed) = evaluate_with_observation(
        feature002_fixture(Feature002Variant::SameOperationDifferentNonce),
        &claimant,
    );
    assert_denial(
        operation_conflict,
        EligibilityDenialV1::ReplayBindingConflict,
    );
    assert_eq!(observed, ObservedReplayOutcome::BindingConflict);

    let (independent, observed) = evaluate_with_observation(
        feature002_fixture(Feature002Variant::Independent),
        &claimant,
    );
    let independent = independent.unwrap_or_else(|_| panic!("independent replay keys were denied"));
    assert_eq!(independent.replay_claim().claimant_generation(), 2);
    assert_eq!(
        observed,
        ObservedReplayOutcome::Claimed {
            claimant_generation: 2,
            receipt_matches_binding: true,
            claim_id_is_nonzero: true,
        }
    );

    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("healthy replay store verification failed"));
    assert_eq!(verification.claim_count(), 2);
    assert_eq!(verification.claimant_generation(), 2);
}

#[test]
fn unique_claim_id_collision_rolls_back_generation_and_candidate_row() {
    let root = SyntheticTempRoot::new("claim-id-collision");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&root, clock.clone());
    let (fresh, _) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert!(fresh.is_ok());
    drop(claimant);

    let database = root.closed_database_path();
    let mut connection =
        Connection::open(database).unwrap_or_else(|_| panic!("collision fixture open failed"));
    let existing_claim_id: Vec<u8> = connection
        .query_row("SELECT claim_id FROM replay_claims LIMIT 1", [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|_| panic!("collision fixture read failed"));
    let transaction = connection
        .transaction()
        .unwrap_or_else(|_| panic!("collision fixture transaction failed"));
    transaction
        .execute(
            "UPDATE replay_store_meta SET claimant_generation = 2 WHERE singleton = 1",
            [],
        )
        .unwrap_or_else(|_| panic!("collision fixture generation update failed"));
    let collision = transaction.execute(
        "INSERT INTO replay_claims (
            instance_epoch, nonce, operation_id, binding_digest, claim_id,
            claimant_generation
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            77_i64,
            &[0x77_u8; 16][..],
            "operation:collision-fixture",
            &[0x88_u8; 32][..],
            existing_claim_id,
            2_i64,
        ],
    );
    assert!(collision.is_err());
    drop(transaction);
    drop(connection);

    let claimant =
        SqliteReplayClaimantV1::open_or_create(root.config(), clock, OPEN_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("collision rollback store reopen failed"));
    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("collision rollback verification failed"));
    assert_eq!(verification.claim_count(), 1);
    assert_eq!(verification.claimant_generation(), 1);
}

#[test]
fn impossible_exhausted_generation_fixture_fails_closed_before_claiming() {
    let root = SyntheticTempRoot::new("generation-exhaustion");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&root, clock.clone());
    drop(claimant);

    let database = root.closed_database_path();
    let connection =
        Connection::open(database).unwrap_or_else(|_| panic!("exhaustion fixture open failed"));
    connection
        .execute(
            "UPDATE replay_store_meta SET claimant_generation = ?1 WHERE singleton = 1",
            [MAX_SAFE_U64 as i64],
        )
        .unwrap_or_else(|_| panic!("exhaustion fixture mutation failed"));
    drop(connection);

    let error =
        SqliteReplayClaimantV1::open_or_create(root.config(), clock, OPEN_DEADLINE_MONOTONIC_MS)
            .err()
            .unwrap_or_else(|| panic!("inconsistent exhausted generation was accepted"));
    assert_eq!(error.code(), "INVARIANT_FAILED");
    assert_eq!(error.to_string(), "INVARIANT_FAILED");
    assert!(error.source().is_none());
}
