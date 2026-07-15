//! PLAN-005 T062 RED contract for bounded adapter ordinary/control lanes.

use helix_dispatch_inbox_sqlite::measure_adapter_dispatch_queue_profile_v1;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const ORDINARY_CAPACITY: usize = 1_024;
const CONTROL_CAPACITY: usize = 32;
const DUPLICATE_FLOOD: usize = 10_000;
const CONTROLLED_TRIALS: usize = 100;
const MAX_BACKPRESSURE_MS: u64 = 50;
const MAX_CONTROL_P99_MS: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionV1 {
    Accepted,
    ExactDuplicate,
    Backpressured { latency_ms: u64 },
}

#[derive(Debug)]
struct AdapterQueueOracleV1 {
    ordinary: BTreeSet<u64>,
    control_pending: usize,
}

impl AdapterQueueOracleV1 {
    fn new() -> Self {
        Self {
            ordinary: BTreeSet::new(),
            control_pending: 0,
        }
    }

    fn admit_ordinary_v1(&mut self, binding: u64) -> AdmissionV1 {
        if self.ordinary.contains(&binding) {
            return AdmissionV1::ExactDuplicate;
        }
        if self.ordinary.len() == ORDINARY_CAPACITY {
            return AdmissionV1::Backpressured {
                latency_ms: MAX_BACKPRESSURE_MS,
            };
        }
        assert!(self.ordinary.insert(binding));
        AdmissionV1::Accepted
    }

    fn admit_control_v1(&mut self) -> AdmissionV1 {
        if self.control_pending == CONTROL_CAPACITY {
            return AdmissionV1::Backpressured {
                latency_ms: MAX_CONTROL_P99_MS,
            };
        }
        self.control_pending += 1;
        AdmissionV1::Accepted
    }
}

fn p99_nearest_rank_v1(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    let rank = (samples.len() * 99).div_ceil(100);
    samples[rank.saturating_sub(1)]
}

#[test]
fn exact_ordinary_and_control_capacity_boundaries_are_independent() {
    let mut queue = AdapterQueueOracleV1::new();
    for binding in 0..ORDINARY_CAPACITY as u64 {
        assert_eq!(queue.admit_ordinary_v1(binding), AdmissionV1::Accepted);
    }
    assert_eq!(queue.ordinary.len(), ORDINARY_CAPACITY);
    assert_eq!(
        queue.admit_ordinary_v1(ORDINARY_CAPACITY as u64),
        AdmissionV1::Backpressured {
            latency_ms: MAX_BACKPRESSURE_MS
        }
    );

    for _ in 0..CONTROL_CAPACITY {
        assert_eq!(queue.admit_control_v1(), AdmissionV1::Accepted);
    }
    assert_eq!(queue.control_pending, CONTROL_CAPACITY);
    assert_eq!(
        queue.admit_control_v1(),
        AdmissionV1::Backpressured {
            latency_ms: MAX_CONTROL_P99_MS
        }
    );
}

#[test]
fn ten_thousand_exact_duplicates_do_not_consume_new_capacity() {
    let mut queue = AdapterQueueOracleV1::new();
    assert_eq!(queue.admit_ordinary_v1(7), AdmissionV1::Accepted);
    for _ in 1..DUPLICATE_FLOOD {
        assert_eq!(queue.admit_ordinary_v1(7), AdmissionV1::ExactDuplicate);
    }
    assert_eq!(queue.ordinary.len(), 1);
    assert_eq!(queue.control_pending, 0);
}

#[test]
fn deterministic_p99_oracle_freezes_the_release_threshold_math() {
    let mut samples = (0..CONTROLLED_TRIALS)
        .map(|trial| 20 + u64::try_from(trial % 17).expect("trial fits u64"))
        .collect::<Vec<_>>();
    assert_eq!(samples.len(), CONTROLLED_TRIALS);
    assert!(p99_nearest_rank_v1(&mut samples) <= MAX_CONTROL_P99_MS);
}

#[test]
fn production_adapter_queue_owns_bounded_separate_lanes_and_payload_free_metrics() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let queue_path = manifest.join("src/queue.rs");
    let queue = fs::read_to_string(&queue_path).unwrap_or_else(|error| {
        panic!(
            "T062 RED: T069 must add the adapter queue at {}: {error}",
            queue_path.display()
        )
    });
    let lib = fs::read_to_string(manifest.join("src/lib.rs"))
        .expect("T062 adapter crate root remains readable");
    let queue = source_without_comments_v1(&queue);
    let lib = source_without_comments_v1(&lib);
    let combined = format!("{queue}\n{lib}");

    for required in [
        "1024",
        "32",
        "ordinary",
        "control",
        "pause",
        "status",
        "reconciliation",
        "duplicate",
        "backpressure",
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
            combined.to_ascii_lowercase().contains(required),
            "T062 RED: adapter queue seam omits {required}"
        );
    }
    for forbidden in ["canonical_grant", "canonical_receipt", "target.components"] {
        assert!(
            !queue.contains(forbidden),
            "T062 queue metric surface leaks payload through {forbidden}"
        );
    }
}

#[test]
#[ignore = "release SC-006 gate: 100 real saturation trials with a 10,000-request duplicate flood"]
fn release_adapter_saturation_and_control_latency_profile() {
    assert_eq!(ORDINARY_CAPACITY, 1_024);
    assert_eq!(CONTROL_CAPACITY, 32);
    assert_eq!(DUPLICATE_FLOOD, 10_000);
    assert_eq!(CONTROLLED_TRIALS, 100);
    let profile = measure_adapter_dispatch_queue_profile_v1()
        .expect("T069 production adapter profile preserves all queue invariants");

    assert_eq!(profile.trial_count_v1(), CONTROLLED_TRIALS);
    assert_eq!(profile.duplicate_flood_per_trial_v1(), DUPLICATE_FLOOD);
    assert!(
        profile.ordinary_backpressure_max_ms_v1() <= MAX_BACKPRESSURE_MS,
        "adapter ordinary backpressure exceeds SC-006: {profile:?}"
    );
    assert!(
        profile.pause_p99_ms_v1() <= MAX_CONTROL_P99_MS,
        "adapter PAUSE p99 exceeds SC-006: {profile:?}"
    );
    assert!(
        profile.status_p99_ms_v1() <= MAX_CONTROL_P99_MS,
        "adapter status p99 exceeds SC-006: {profile:?}"
    );
    assert!(
        profile.reconciliation_p99_ms_v1() <= MAX_CONTROL_P99_MS,
        "adapter reconciliation p99 exceeds SC-006: {profile:?}"
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
