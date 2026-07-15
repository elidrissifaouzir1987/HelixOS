//! PLAN-005 T062 RED contract for coordinator dispatch/control-lane saturation.

use helix_coordinator_sqlite::measure_coordinator_dispatch_queue_profile_v1;
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::Path;

const ORDINARY_CAPACITY: usize = 1_024;
const CONTROL_CAPACITY: usize = 32;
const DUPLICATE_FLOOD: usize = 10_000;
const CONTROLLED_TRIALS: usize = 100;
const MAX_BACKPRESSURE_MS: u64 = 50;
const MAX_CONTROL_P99_MS: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlKindV1 {
    Pause,
    Status,
    Reconciliation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrdinaryAdmissionV1 {
    Accepted,
    ExactDuplicate,
    Backpressured { latency_ms: u64 },
}

#[derive(Debug)]
struct CoordinatorQueueOracleV1 {
    ordinary: BTreeSet<u64>,
    control: VecDeque<ControlKindV1>,
}

impl CoordinatorQueueOracleV1 {
    fn saturated() -> Self {
        Self {
            ordinary: (0..u64::try_from(ORDINARY_CAPACITY).expect("capacity fits u64")).collect(),
            control: VecDeque::with_capacity(CONTROL_CAPACITY),
        }
    }

    fn admit_ordinary_v1(&mut self, binding: u64) -> OrdinaryAdmissionV1 {
        if self.ordinary.contains(&binding) {
            return OrdinaryAdmissionV1::ExactDuplicate;
        }
        if self.ordinary.len() == ORDINARY_CAPACITY {
            return OrdinaryAdmissionV1::Backpressured {
                latency_ms: MAX_BACKPRESSURE_MS,
            };
        }
        assert!(self.ordinary.insert(binding));
        OrdinaryAdmissionV1::Accepted
    }

    fn admit_control_v1(&mut self, kind: ControlKindV1) -> Result<(), u64> {
        if self.control.len() == CONTROL_CAPACITY {
            return Err(MAX_CONTROL_P99_MS);
        }
        self.control.push_back(kind);
        Ok(())
    }
}

fn p99_nearest_rank_v1(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    let rank = (samples.len() * 99).div_ceil(100);
    samples[rank.saturating_sub(1)]
}

#[test]
fn ordinary_saturation_never_borrows_reserved_control_capacity() {
    let mut queue = CoordinatorQueueOracleV1::saturated();
    assert_eq!(queue.ordinary.len(), ORDINARY_CAPACITY);
    assert_eq!(
        queue.admit_ordinary_v1(10_000),
        OrdinaryAdmissionV1::Backpressured {
            latency_ms: MAX_BACKPRESSURE_MS
        }
    );
    for ordinal in 0..CONTROL_CAPACITY {
        let kind = match ordinal % 3 {
            0 => ControlKindV1::Pause,
            1 => ControlKindV1::Status,
            _ => ControlKindV1::Reconciliation,
        };
        assert_eq!(queue.admit_control_v1(kind), Ok(()));
    }
    assert_eq!(queue.control.len(), CONTROL_CAPACITY);
    assert_eq!(
        queue.admit_control_v1(ControlKindV1::Pause),
        Err(MAX_CONTROL_P99_MS)
    );
}

#[test]
fn duplicate_flood_does_not_create_more_dispatch_work_or_starve_control() {
    let mut queue = CoordinatorQueueOracleV1::saturated();
    let retained_binding = 7_u64;
    let mut duplicate_observations = 0_usize;
    for candidate in std::iter::repeat_n(retained_binding, DUPLICATE_FLOOD) {
        assert_eq!(
            queue.admit_ordinary_v1(candidate),
            OrdinaryAdmissionV1::ExactDuplicate
        );
        duplicate_observations += 1;
    }
    assert_eq!(duplicate_observations, DUPLICATE_FLOOD);
    assert_eq!(queue.ordinary.len(), ORDINARY_CAPACITY);
    assert_eq!(queue.admit_control_v1(ControlKindV1::Pause), Ok(()));
    assert_eq!(queue.control.front(), Some(&ControlKindV1::Pause));
}

#[test]
fn deterministic_p99_oracle_freezes_the_release_threshold_math() {
    let mut control_samples = Vec::with_capacity(CONTROLLED_TRIALS);
    for trial in 0..CONTROLLED_TRIALS {
        let ordinary_backpressure_ms = 25 + u64::try_from(trial % 11).expect("trial fits");
        let control_ms = 30 + u64::try_from(trial % 13).expect("trial fits");
        assert!(ordinary_backpressure_ms <= MAX_BACKPRESSURE_MS);
        assert!(control_ms <= MAX_CONTROL_P99_MS);
        control_samples.push(control_ms);
    }
    assert!(p99_nearest_rank_v1(&mut control_samples) <= MAX_CONTROL_P99_MS);
}

#[test]
fn production_coordinator_queue_is_portable_bounded_and_separate_from_adapter_storage() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let coordinator_path = manifest.join("src/dispatch_queue.rs");
    let portable_path = manifest.join("../helix-plan-dispatch/src/queue.rs");
    let coordinator = fs::read_to_string(&coordinator_path).unwrap_or_else(|error| {
        panic!(
            "T062 RED: T069 must add coordinator queue accounting at {}: {error}",
            coordinator_path.display()
        )
    });
    let portable = fs::read_to_string(&portable_path).unwrap_or_else(|error| {
        panic!(
            "T062 RED: T069 must add portable queue contracts at {}: {error}",
            portable_path.display()
        )
    });
    let coordinator = source_without_comments_v1(&coordinator);
    let portable = source_without_comments_v1(&portable);
    let combined = format!("{coordinator}\n{portable}").to_ascii_lowercase();

    for required in [
        "1024",
        "32",
        "ordinary",
        "control",
        "pause",
        "status",
        "reconciliation",
        "backpressure",
        "duplicate",
        "dispatchqueuemetricssnapshotv1",
        "ordinary_pending",
        "control_pending",
        "duplicate_count",
        "backpressure_count",
        "control_latency_sample_count",
        "50",
        "100",
    ] {
        assert!(
            combined.contains(required),
            "T062 RED: coordinator queue seam omits {required}"
        );
    }
    assert!(
        !portable.contains("rusqlite") && !portable.contains("std::path"),
        "T062 portable queue contract must not own storage or native paths"
    );
    assert!(
        !coordinator.contains("helix_dispatch_inbox_sqlite"),
        "T062 coordinator queue must not share adapter storage"
    );
}

#[test]
#[ignore = "release SC-006 gate: real 100-trial queue/control latency evidence"]
fn release_coordinator_queue_control_profile_cardinalities() {
    assert_eq!(ORDINARY_CAPACITY, 1_024);
    assert_eq!(CONTROL_CAPACITY, 32);
    assert_eq!(DUPLICATE_FLOOD, 10_000);
    assert_eq!(CONTROLLED_TRIALS, 100);
    let profile = measure_coordinator_dispatch_queue_profile_v1()
        .expect("T069 production coordinator profile preserves all queue invariants");

    assert_eq!(profile.trial_count_v1(), CONTROLLED_TRIALS);
    assert_eq!(profile.duplicate_flood_per_trial_v1(), DUPLICATE_FLOOD);
    assert!(
        profile.ordinary_backpressure_max_ms_v1() <= MAX_BACKPRESSURE_MS,
        "coordinator ordinary backpressure exceeds SC-006: {profile:?}"
    );
    assert!(
        profile.pause_p99_ms_v1() <= MAX_CONTROL_P99_MS,
        "coordinator PAUSE p99 exceeds SC-006: {profile:?}"
    );
    assert!(
        profile.status_p99_ms_v1() <= MAX_CONTROL_P99_MS,
        "coordinator status p99 exceeds SC-006: {profile:?}"
    );
    assert!(
        profile.reconciliation_p99_ms_v1() <= MAX_CONTROL_P99_MS,
        "coordinator reconciliation p99 exceeds SC-006: {profile:?}"
    );
    assert!(profile.meets_contract_v1(), "{profile:?}");
}

fn source_without_comments_v1(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut block_depth = 0_u64;
    for line in source.lines() {
        let mut remaining = line;
        loop {
            if block_depth > 0 {
                let Some(end) = remaining.find("*/") else {
                    break;
                };
                block_depth -= 1;
                remaining = &remaining[end + 2..];
                continue;
            }
            let line_comment = remaining.find("//");
            let block_comment = remaining.find("/*");
            match (line_comment, block_comment) {
                (Some(line_start), Some(block_start)) if block_start < line_start => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (Some(line_start), _) => {
                    output.push_str(&remaining[..line_start]);
                    break;
                }
                (None, Some(block_start)) => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (None, None) => {
                    output.push_str(remaining);
                    break;
                }
            }
        }
        output.push('\n');
    }
    assert_eq!(block_depth, 0, "T062 source comments are balanced");
    output
}
