//! Ownership: T017 end-to-end Feature-002 evaluator integration.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot,
};
use helix_plan_eligibility::EligibilityDenialV1;

fn assert_denial(
    result: Result<
        helix_plan_eligibility::EligiblePlanV1,
        helix_plan_eligibility::EligibilityFailureV1,
    >,
    expected: EligibilityDenialV1,
) {
    let failure = result
        .err()
        .unwrap_or_else(|| panic!("replay-denied evaluator fixture was accepted"));
    assert_eq!(failure.denial(), expected);
}

#[test]
fn coherent_evaluation_is_eligible_once_and_exact_repeat_is_denied_after_reopen() {
    let root = SyntheticTempRoot::new("eligibility-reopen");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&root, clock.clone());
    let (first, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    let first = first.unwrap_or_else(|_| panic!("fresh coherent evaluation was denied"));
    assert_eq!(
        observed,
        ObservedReplayOutcome::Claimed {
            claimant_generation: 1,
            receipt_matches_binding: true,
            claim_id_is_nonzero: true,
        }
    );
    assert_eq!(first.replay_claim().claimant_generation(), 1);
    drop(claimant);

    let claimant = open_store(&root, clock);
    let (repeat, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert_denial(repeat, EligibilityDenialV1::ReplayAlreadyClaimed);
    assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);
}

#[test]
fn evaluator_maps_either_unique_key_conflict_to_the_frozen_denial() {
    let root = SyntheticTempRoot::new("eligibility-conflicts");
    let claimant = open_store(&root, InjectedClock::coherent());
    let (first, _) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert!(first.is_ok());

    for variant in [
        Feature002Variant::SameNonceDifferentOperation,
        Feature002Variant::SameOperationDifferentNonce,
    ] {
        let (conflict, observed) =
            evaluate_with_observation(feature002_fixture(variant), &claimant);
        assert_denial(conflict, EligibilityDenialV1::ReplayBindingConflict);
        assert_eq!(observed, ObservedReplayOutcome::BindingConflict);
    }
}

#[test]
fn independent_keys_remain_independently_eligible() {
    let root = SyntheticTempRoot::new("eligibility-independent");
    let claimant = open_store(&root, InjectedClock::coherent());

    for (variant, expected_generation) in [
        (Feature002Variant::Coherent, 1),
        (Feature002Variant::Independent, 2),
    ] {
        let (result, observed) = evaluate_with_observation(feature002_fixture(variant), &claimant);
        let eligible = result.unwrap_or_else(|_| panic!("independent coherent fixture was denied"));
        assert_eq!(
            eligible.replay_claim().claimant_generation(),
            expected_generation
        );
        assert_eq!(
            observed,
            ObservedReplayOutcome::Claimed {
                claimant_generation: expected_generation,
                receipt_matches_binding: true,
                claim_id_is_nonzero: true,
            }
        );
    }
}
