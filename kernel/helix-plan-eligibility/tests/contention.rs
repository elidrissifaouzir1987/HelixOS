mod common;

#[path = "../test-support/replay_claimant.rs"]
mod replay_claimant;

use common::coherent_fixture;
use helix_plan_eligibility::EligibilityDenialV1;
use replay_claimant::DeterministicReplayClaimant;
use std::sync::{Arc, Barrier};
use std::thread;

const ROUNDS: usize = 1_000;
const CONTENDERS: usize = 8;

#[test]
#[ignore = "release-mode PLAN-002 contention gate"]
fn one_thousand_barrier_rounds_have_exactly_one_winner() {
    for round in 0..ROUNDS {
        let claimant = Arc::new(DeterministicReplayClaimant::new());
        let barrier = Arc::new(Barrier::new(CONTENDERS));
        let mut handles = Vec::with_capacity(CONTENDERS);

        for _ in 0..CONTENDERS {
            let claimant = Arc::clone(&claimant);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let fixture = coherent_fixture();
                barrier.wait();
                match fixture.evaluate(claimant.as_ref()) {
                    Ok(_) => true,
                    Err(failure) => {
                        assert_eq!(failure.denial(), EligibilityDenialV1::ReplayAlreadyClaimed);
                        false
                    }
                }
            }));
        }

        let winners = handles
            .into_iter()
            .map(|handle| handle.join().expect("contender must not panic"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1, "round {round} did not have one winner");
        assert_eq!(claimant.call_count(), CONTENDERS as u64);
        assert_eq!(claimant.successful_claim_count(), 1);
        assert_eq!(claimant.claimant_generation(), 1);
    }

    println!("PLAN-002 contention: rounds={ROUNDS} contenders={CONTENDERS} winners_per_round=1");
}
