//! Exact, query-only replay verification for durable preparation.

mod common;

use common::{
    feature002_fixture, open_store, Feature002Variant, InjectedClock, SyntheticTempRoot,
    MAINTENANCE_DEADLINE_MONOTONIC_MS,
};
use helix_plan_eligibility::{EligiblePlanV1, ReplayClaimVerificationV1, ReplayClaimVerifierV1};
use helix_replay_sqlite::SqliteReplayClaimantV1;
use rusqlite::{Connection, OpenFlags};
use std::ffi::OsString;
use std::fs;

type StoredClaimSnapshot = (i64, Vec<u8>, String, Vec<u8>, Vec<u8>, i64);

#[derive(Debug, PartialEq, Eq)]
struct StoreSnapshot {
    claimant_generation: i64,
    claim_count: i64,
    claims: Vec<StoredClaimSnapshot>,
}

fn claim(
    claimant: &SqliteReplayClaimantV1<InjectedClock>,
    variant: Feature002Variant,
) -> EligiblePlanV1 {
    feature002_fixture(variant)
        .evaluate(claimant)
        .unwrap_or_else(|_| panic!("synthetic replay claim was denied"))
}

fn snapshot(root: &SyntheticTempRoot) -> StoreSnapshot {
    let connection = Connection::open_with_flags(
        root.closed_database_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap_or_else(|_| panic!("synthetic replay snapshot open failed"));
    let claimant_generation = connection
        .query_row(
            "SELECT claimant_generation FROM replay_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| panic!("synthetic replay metadata read failed"));
    let claim_count = connection
        .query_row("SELECT COUNT(*) FROM replay_claims", [], |row| row.get(0))
        .unwrap_or_else(|_| panic!("synthetic replay count read failed"));
    let mut statement = connection
        .prepare(
            "SELECT instance_epoch, nonce, operation_id, binding_digest, claim_id, \
                    claimant_generation
             FROM replay_claims ORDER BY claimant_generation",
        )
        .unwrap_or_else(|_| panic!("synthetic replay snapshot query failed"));
    let claims = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .unwrap_or_else(|_| panic!("synthetic replay snapshot iteration failed"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| panic!("synthetic replay snapshot decoding failed"));
    StoreSnapshot {
        claimant_generation,
        claim_count,
        claims,
    }
}

fn root_inventory(root: &SyntheticTempRoot) -> Vec<(OsString, u64)> {
    let mut members = fs::read_dir(root.path())
        .unwrap_or_else(|_| panic!("synthetic replay root inventory failed"))
        .map(|entry| {
            let entry = entry.unwrap_or_else(|_| panic!("synthetic replay root member failed"));
            let length = entry
                .metadata()
                .unwrap_or_else(|_| panic!("synthetic replay root metadata failed"))
                .len();
            (entry.file_name(), length)
        })
        .collect::<Vec<_>>();
    members.sort_by(|left, right| left.0.cmp(&right.0));
    members
}

#[test]
fn exact_row_remains_exact_after_global_generation_advances_without_mutation() {
    let root = SyntheticTempRoot::new("preparation-exact");
    let claimant = open_store(&root, InjectedClock::coherent());
    let first = claim(&claimant, Feature002Variant::Coherent);

    let before = snapshot(&root);
    let root_before = root_inventory(&root);
    assert_eq!(before.claimant_generation, 1);
    assert_eq!(
        claimant.verify_exact_claim(
            &first.replay_verification_view(),
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        ),
        ReplayClaimVerificationV1::Exact
    );
    assert_eq!(snapshot(&root), before);
    assert_eq!(root_inventory(&root), root_before);

    let independent = claim(&claimant, Feature002Variant::Independent);
    assert_eq!(independent.replay_claim().claimant_generation(), 2);
    let advanced = snapshot(&root);
    assert_eq!(advanced.claimant_generation, 2);
    assert_eq!(advanced.claim_count, 2);

    assert_eq!(
        claimant.verify_exact_claim(
            &first.replay_verification_view(),
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        ),
        ReplayClaimVerificationV1::Exact,
        "the row generation, not the latest global generation, is authoritative"
    );
    assert_eq!(snapshot(&root), advanced);
}

#[test]
fn missing_view_does_not_call_claim_once_or_change_empty_store() {
    let source_root = SyntheticTempRoot::new("preparation-missing-source");
    let source = open_store(&source_root, InjectedClock::coherent());
    let eligible = claim(&source, Feature002Variant::Coherent);

    let empty_root = SyntheticTempRoot::new("preparation-missing-empty");
    let empty = open_store(&empty_root, InjectedClock::coherent());
    let before = snapshot(&empty_root);
    let root_before = root_inventory(&empty_root);
    assert_eq!(before.claimant_generation, 0);
    assert_eq!(before.claim_count, 0);

    assert_eq!(
        empty.verify_exact_claim(
            &eligible.replay_verification_view(),
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        ),
        ReplayClaimVerificationV1::Missing
    );
    assert_eq!(snapshot(&empty_root), before);
    assert_eq!(root_inventory(&empty_root), root_before);
}

#[test]
fn different_permanent_occupants_are_conflicts_and_never_mutate() {
    let source_root = SyntheticTempRoot::new("preparation-conflict-source");
    let source = open_store(&source_root, InjectedClock::coherent());
    let eligible = claim(&source, Feature002Variant::Coherent);
    let view = eligible.replay_verification_view();

    for (label, variant) in [
        ("preparation-conflict-receipt", Feature002Variant::Coherent),
        (
            "preparation-conflict-nonce",
            Feature002Variant::SameNonceDifferentOperation,
        ),
        (
            "preparation-conflict-operation",
            Feature002Variant::SameOperationDifferentNonce,
        ),
    ] {
        let root = SyntheticTempRoot::new(label);
        let claimant = open_store(&root, InjectedClock::coherent());
        let _occupant = claim(&claimant, variant);
        let before = snapshot(&root);
        assert_eq!(
            claimant.verify_exact_claim(&view, MAINTENANCE_DEADLINE_MONOTONIC_MS),
            ReplayClaimVerificationV1::Conflict
        );
        assert_eq!(snapshot(&root), before);
    }
}

#[test]
fn reached_deadline_is_unavailable_without_mutation() {
    let root = SyntheticTempRoot::new("preparation-deadline");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&root, clock.clone());
    let eligible = claim(&claimant, Feature002Variant::Coherent);
    let before = snapshot(&root);
    clock.set(MAINTENANCE_DEADLINE_MONOTONIC_MS);

    assert_eq!(
        claimant.verify_exact_claim(
            &eligible.replay_verification_view(),
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        ),
        ReplayClaimVerificationV1::Unavailable
    );
    assert_eq!(snapshot(&root), before);
}

#[test]
fn changed_schema_is_unhealthy_without_claim_mutation() {
    let root = SyntheticTempRoot::new("preparation-unhealthy");
    let claimant = open_store(&root, InjectedClock::coherent());
    let eligible = claim(&claimant, Feature002Variant::Coherent);
    let before = snapshot(&root);

    Connection::open(root.closed_database_path())
        .and_then(|connection| connection.execute_batch("DROP INDEX replay_claims_claim_id_uq"))
        .unwrap_or_else(|_| panic!("synthetic schema corruption failed"));

    assert_eq!(
        claimant.verify_exact_claim(
            &eligible.replay_verification_view(),
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        ),
        ReplayClaimVerificationV1::Unhealthy
    );
    let after = snapshot(&root);
    assert_eq!(after.claimant_generation, before.claimant_generation);
    assert_eq!(after.claim_count, before.claim_count);
    assert_eq!(after.claims, before.claims);
}

#[test]
fn malformed_target_row_is_unhealthy_and_strictly_decoded_without_mutation() {
    let root = SyntheticTempRoot::new("preparation-malformed-row");
    let claimant = open_store(&root, InjectedClock::coherent());
    let eligible = claim(&claimant, Feature002Variant::Coherent);

    Connection::open(root.closed_database_path())
        .and_then(|connection| {
            connection.execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE replay_claims SET binding_digest = X'00'",
            )
        })
        .unwrap_or_else(|_| panic!("synthetic row corruption failed"));
    let before = snapshot(&root);

    assert_eq!(
        claimant.verify_exact_claim(
            &eligible.replay_verification_view(),
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        ),
        ReplayClaimVerificationV1::Unhealthy
    );
    assert_eq!(snapshot(&root), before);
}
