//! Ownership: T024-T025 synchronized thread/process linearizability evidence.

mod common;
#[path = "common/process_probe.rs"]
mod process_probe;

use common::{
    evaluate_with_observation, feature002_fixture, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, DEFAULT_BACKUP_RETRY_WAIT_MS,
    DEFAULT_BACKUP_STEP_PAGES, MAINTENANCE_DEADLINE_MONOTONIC_MS, OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_replay_sqlite::{ReplayStoreConfigV1, SqliteReplayClaimantV1};
use process_probe::{run_process_round, ProcessOutcome};
use std::sync::{Arc, Barrier};
use std::thread;

const THREAD_CONTENDERS: usize = 64;
const PROCESS_CONTENDERS: usize = 8;
// This is a correctness/linearizability fixture, not the SC-004 latency fixture. Hosted
// Windows runners can serialize 64 FULL-sync contenders for more than five seconds;
// keep enough budget for every call to observe the durable winner instead of honestly
// timing out as `Unavailable` under runner load.
const CONTENTION_BUSY_WAIT_MS: u64 = 30_000;
const RELEASE_THREAD_ROUNDS_PER_SCENARIO: usize = 100;
const RELEASE_PROCESS_ROUNDS: usize = 20;

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Exact,
    NonceConflict,
    OperationConflict,
    Independent,
}

impl Scenario {
    const ALL: [Self; 4] = [
        Self::Exact,
        Self::NonceConflict,
        Self::OperationConflict,
        Self::Independent,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::NonceConflict => "nonce-conflict",
            Self::OperationConflict => "operation-conflict",
            Self::Independent => "independent",
        }
    }

    fn variant(self, contender: usize) -> Feature002Variant {
        match self {
            Self::Exact => Feature002Variant::Coherent,
            Self::NonceConflict if contender.is_multiple_of(2) => Feature002Variant::Coherent,
            Self::NonceConflict => Feature002Variant::SameNonceDifferentOperation,
            Self::OperationConflict if contender.is_multiple_of(2) => Feature002Variant::Coherent,
            Self::OperationConflict => Feature002Variant::SameOperationDifferentNonce,
            Self::Independent if contender.is_multiple_of(2) => Feature002Variant::Coherent,
            Self::Independent => Feature002Variant::Independent,
        }
    }

    fn expected(self, contenders: usize) -> OutcomeCounts {
        match self {
            Self::Exact => OutcomeCounts {
                claimed: 1,
                already_claimed: contenders - 1,
                binding_conflict: 0,
                unavailable: 0,
                ambiguous: 0,
            },
            Self::NonceConflict | Self::OperationConflict => OutcomeCounts {
                claimed: 1,
                already_claimed: contenders / 2 - 1,
                binding_conflict: contenders / 2,
                unavailable: 0,
                ambiguous: 0,
            },
            Self::Independent => OutcomeCounts {
                claimed: 2,
                already_claimed: contenders - 2,
                binding_conflict: 0,
                unavailable: 0,
                ambiguous: 0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OutcomeCounts {
    claimed: usize,
    already_claimed: usize,
    binding_conflict: usize,
    unavailable: usize,
    ambiguous: usize,
}

impl OutcomeCounts {
    fn observe_thread(&mut self, outcome: ObservedReplayOutcome) {
        match outcome {
            ObservedReplayOutcome::Claimed {
                receipt_matches_binding: true,
                claim_id_is_nonzero: true,
                ..
            } => self.claimed += 1,
            ObservedReplayOutcome::Claimed { .. } => {
                panic!("contended claim returned an invalid receipt")
            }
            ObservedReplayOutcome::AlreadyClaimed => self.already_claimed += 1,
            ObservedReplayOutcome::BindingConflict => self.binding_conflict += 1,
            ObservedReplayOutcome::Unavailable => self.unavailable += 1,
            ObservedReplayOutcome::Ambiguous => self.ambiguous += 1,
        }
    }

    fn observe_process(&mut self, outcome: ProcessOutcome) {
        match outcome {
            ProcessOutcome::Claimed => self.claimed += 1,
            ProcessOutcome::AlreadyClaimed => self.already_claimed += 1,
            ProcessOutcome::BindingConflict => self.binding_conflict += 1,
            ProcessOutcome::Unavailable => self.unavailable += 1,
            ProcessOutcome::Ambiguous => self.ambiguous += 1,
        }
    }
}

fn contention_store(root: &SyntheticTempRoot) -> SqliteReplayClaimantV1<InjectedClock> {
    let config = ReplayStoreConfigV1::try_new(
        root.trusted_root(),
        CONTENTION_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("contention configuration was rejected"));
    SqliteReplayClaimantV1::open_or_create(
        config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("contention store open failed"))
}

fn run_thread_round(scenario: Scenario, round: usize) {
    let label = format!("thread-{}-{round}", scenario.label());
    let root = SyntheticTempRoot::new(&label);
    let claimant = Arc::new(contention_store(&root));
    let barrier = Arc::new(Barrier::new(THREAD_CONTENDERS));
    let mut handles = Vec::with_capacity(THREAD_CONTENDERS);

    for contender in 0..THREAD_CONTENDERS {
        let fixture = feature002_fixture(scenario.variant(contender));
        let claimant = Arc::clone(&claimant);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let (result, observed) = evaluate_with_observation(fixture, claimant.as_ref());
            match observed {
                ObservedReplayOutcome::Claimed { .. } => assert!(result.is_ok()),
                _ => assert!(result.is_err()),
            }
            observed
        }));
    }

    let mut counts = OutcomeCounts::default();
    for handle in handles {
        counts.observe_thread(
            handle
                .join()
                .unwrap_or_else(|_| panic!("thread contender panicked")),
        );
    }
    assert_eq!(
        counts,
        scenario.expected(THREAD_CONTENDERS),
        "thread scenario failed: {} round {round}",
        scenario.label()
    );
    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("thread contention verification failed"));
    assert_eq!(verification.claim_count() as usize, counts.claimed);
    assert_eq!(verification.claimant_generation() as usize, counts.claimed);
}

fn run_one_process_round(scenario: Scenario, round: usize) {
    let label = format!("process-{}-{round}", scenario.label());
    let root = SyntheticTempRoot::new(&label);
    drop(contention_store(&root));
    let variants = (0..PROCESS_CONTENDERS)
        .map(|contender| scenario.variant(contender))
        .collect::<Vec<_>>();
    let outcomes = run_process_round(root.path(), &variants);
    let mut counts = OutcomeCounts::default();
    for outcome in outcomes {
        counts.observe_process(outcome);
    }
    assert_eq!(
        counts,
        scenario.expected(PROCESS_CONTENDERS),
        "process scenario failed: {} round {round}",
        scenario.label()
    );

    let claimant = contention_store(&root);
    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("process contention verification failed"));
    assert_eq!(verification.claim_count() as usize, counts.claimed);
    assert_eq!(verification.claimant_generation() as usize, counts.claimed);
}

#[test]
fn normal_thread_then_process_contention_suite() {
    // Keep the two intentionally heavy workloads in one test so libtest cannot
    // oversubscribe the host by starting 64 threads and 32 child processes together.
    for scenario in Scenario::ALL {
        run_thread_round(scenario, 0);
    }
    for scenario in Scenario::ALL {
        run_one_process_round(scenario, 0);
    }
}

#[test]
#[ignore = "release PLAN-003 gate: 4 scenarios x 100 x 64 threads plus 20 x 8 READY/GO processes"]
fn release_thread_then_process_contention_suite() {
    for scenario in Scenario::ALL {
        for round in 0..RELEASE_THREAD_ROUNDS_PER_SCENARIO {
            run_thread_round(scenario, round);
        }
    }
    println!(
        "PLAN-003 thread contention scenarios={} rounds_per_scenario={} contenders={} status=pass",
        Scenario::ALL.len(),
        RELEASE_THREAD_ROUNDS_PER_SCENARIO,
        THREAD_CONTENDERS
    );
    for round in 0..RELEASE_PROCESS_ROUNDS {
        run_one_process_round(Scenario::Exact, round);
    }
    println!(
        "PLAN-003 process contention rounds={} contenders={} winners_per_round=1 status=pass",
        RELEASE_PROCESS_ROUNDS, PROCESS_CONTENDERS
    );
}

#[test]
fn process_probe_worker() {
    let _worker_ran = process_probe::run_worker_if_requested();
}
