//! Portable bounded dispatch queue accounting and controlled latency profiles.

#![allow(dead_code)]

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

pub const DISPATCH_QUEUE_ORDINARY_CAPACITY_V1: usize = 1_024;
pub const DISPATCH_QUEUE_CONTROL_CAPACITY_V1: usize = 32;
pub const DISPATCH_QUEUE_ORDINARY_BACKPRESSURE_LIMIT_MS_V1: u64 = 50;
pub const DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1: u64 = 100;
pub const DISPATCH_QUEUE_CONTROLLED_TRIALS_V1: usize = 100;
pub const DISPATCH_QUEUE_DUPLICATE_FLOOD_V1: usize = 10_000;

const DISPATCH_QUEUE_MAX_SAFE_INTEGER_V1: u64 = 9_007_199_254_740_991;

/// Opaque identity used only to suppress duplicate pending queue work.
///
/// The value is deliberately absent from `Debug` and from metric snapshots. It carries
/// no execution authority and queue ownership does not make the referenced work valid.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DispatchQueueBindingV1([u8; 32]);

impl DispatchQueueBindingV1 {
    pub const fn new_v1(value: [u8; 32]) -> Self {
        Self(value)
    }

    pub const fn as_bytes_v1(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DispatchQueueBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchQueueBindingV1")
            .finish_non_exhaustive()
    }
}

/// The only work classes admitted to the capacity reserved for control traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DispatchControlKindV1 {
    Pause,
    Status,
    Reconciliation,
}

/// One opaque control request dequeued from the reserved lane.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DispatchControlRequestV1 {
    kind: DispatchControlKindV1,
    binding: DispatchQueueBindingV1,
}

impl DispatchControlRequestV1 {
    pub const fn kind_v1(&self) -> DispatchControlKindV1 {
        self.kind
    }

    pub const fn binding_v1(&self) -> DispatchQueueBindingV1 {
        self.binding
    }
}

impl fmt::Debug for DispatchControlRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchControlRequestV1")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Immediate, closed admission result for either bounded lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchQueueAdmissionV1 {
    Accepted,
    ExactDuplicate,
    Backpressured { within_ms: u64 },
}

impl DispatchQueueAdmissionV1 {
    pub const fn accepted_v1(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub const fn duplicate_v1(self) -> bool {
        matches!(self, Self::ExactDuplicate)
    }

    pub const fn backpressure_limit_ms_v1(self) -> Option<u64> {
        match self {
            Self::Backpressured { within_ms } => Some(within_ms),
            Self::Accepted | Self::ExactDuplicate => None,
        }
    }
}

/// Bounded, payload-free queue and lifecycle counters.
///
/// Pending counts cannot exceed the two compile-time lane capacities. Every lifetime
/// counter saturates at the portable safe-integer ceiling. The control percentile is
/// calculated from a fixed rolling window of at most 100 latency samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchQueueMetricsSnapshotV1 {
    ordinary_pending: usize,
    control_pending: usize,
    ordinary_accepted_count: u64,
    control_accepted_count: u64,
    duplicate_count: u64,
    backpressure_count: u64,
    control_latency_sample_count: u64,
    control_latency_p99_ms: Option<u64>,
    dispatch_count: u64,
    inbox_count: u64,
    receipt_count: u64,
    refusal_count: u64,
    ambiguity_count: u64,
    conflict_count: u64,
    recovery_count: u64,
}

impl DispatchQueueMetricsSnapshotV1 {
    pub const fn ordinary_pending_v1(self) -> usize {
        self.ordinary_pending
    }

    pub const fn control_pending_v1(self) -> usize {
        self.control_pending
    }

    pub const fn ordinary_accepted_count_v1(self) -> u64 {
        self.ordinary_accepted_count
    }

    pub const fn control_accepted_count_v1(self) -> u64 {
        self.control_accepted_count
    }

    pub const fn duplicate_count_v1(self) -> u64 {
        self.duplicate_count
    }

    pub const fn backpressure_count_v1(self) -> u64 {
        self.backpressure_count
    }

    pub const fn control_latency_sample_count_v1(self) -> u64 {
        self.control_latency_sample_count
    }

    pub const fn control_latency_p99_ms_v1(self) -> Option<u64> {
        self.control_latency_p99_ms
    }

    pub const fn dispatch_count_v1(self) -> u64 {
        self.dispatch_count
    }

    pub const fn inbox_count_v1(self) -> u64 {
        self.inbox_count
    }

    pub const fn receipt_count_v1(self) -> u64 {
        self.receipt_count
    }

    pub const fn refusal_count_v1(self) -> u64 {
        self.refusal_count
    }

    pub const fn ambiguity_count_v1(self) -> u64 {
        self.ambiguity_count
    }

    pub const fn conflict_count_v1(self) -> u64 {
        self.conflict_count
    }

    pub const fn recovery_count_v1(self) -> u64 {
        self.recovery_count
    }
}

struct DispatchControlLatencyWindowV1 {
    samples_ms: [u64; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1],
    populated: usize,
    cursor: usize,
    total_sample_count: u64,
}

impl Default for DispatchControlLatencyWindowV1 {
    fn default() -> Self {
        Self {
            samples_ms: [0; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1],
            populated: 0,
            cursor: 0,
            total_sample_count: 0,
        }
    }
}

impl DispatchControlLatencyWindowV1 {
    fn observe_v1(&mut self, latency_ms: u64) {
        self.samples_ms[self.cursor] = bounded_counter_v1(latency_ms);
        self.cursor = (self.cursor + 1) % DISPATCH_QUEUE_CONTROLLED_TRIALS_V1;
        self.populated = self
            .populated
            .saturating_add(1)
            .min(DISPATCH_QUEUE_CONTROLLED_TRIALS_V1);
        increment_bounded_v1(&mut self.total_sample_count);
    }

    fn p99_ms_v1(&self) -> Option<u64> {
        if self.populated == 0 {
            return None;
        }
        let mut samples = self.samples_ms;
        samples[..self.populated].sort_unstable();
        Some(samples[nearest_rank_index_v1(self.populated, 99)])
    }
}

impl fmt::Debug for DispatchControlLatencyWindowV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchControlLatencyWindowV1")
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct DispatchQueueMetricsV1 {
    ordinary_accepted_count: u64,
    control_accepted_count: u64,
    duplicate_count: u64,
    backpressure_count: u64,
    control_latency: DispatchControlLatencyWindowV1,
    dispatch_count: u64,
    inbox_count: u64,
    receipt_count: u64,
    refusal_count: u64,
    ambiguity_count: u64,
    conflict_count: u64,
    recovery_count: u64,
}

impl fmt::Debug for DispatchQueueMetricsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchQueueMetricsV1")
            .finish_non_exhaustive()
    }
}

/// Two independent in-memory lanes with exact pending-work deduplication.
///
/// The ordinary lane can never consume the 32 control slots. Admission performs only
/// bounded local work and returns an immediate backpressure decision when a lane is
/// full; it never sleeps or waits for the other lane.
pub struct DispatchQueueV1 {
    ordinary: VecDeque<DispatchQueueBindingV1>,
    ordinary_bindings: BTreeSet<DispatchQueueBindingV1>,
    control: VecDeque<DispatchControlRequestV1>,
    control_bindings: BTreeSet<(DispatchControlKindV1, DispatchQueueBindingV1)>,
    metrics: DispatchQueueMetricsV1,
}

impl DispatchQueueV1 {
    pub fn new_v1() -> Self {
        Self {
            ordinary: VecDeque::with_capacity(DISPATCH_QUEUE_ORDINARY_CAPACITY_V1),
            ordinary_bindings: BTreeSet::new(),
            control: VecDeque::with_capacity(DISPATCH_QUEUE_CONTROL_CAPACITY_V1),
            control_bindings: BTreeSet::new(),
            metrics: DispatchQueueMetricsV1::default(),
        }
    }

    pub fn admit_ordinary_v1(
        &mut self,
        binding: DispatchQueueBindingV1,
    ) -> DispatchQueueAdmissionV1 {
        if self.ordinary_bindings.contains(&binding) {
            increment_bounded_v1(&mut self.metrics.duplicate_count);
            return DispatchQueueAdmissionV1::ExactDuplicate;
        }
        if self.ordinary.len() >= DISPATCH_QUEUE_ORDINARY_CAPACITY_V1 {
            increment_bounded_v1(&mut self.metrics.backpressure_count);
            return DispatchQueueAdmissionV1::Backpressured {
                within_ms: DISPATCH_QUEUE_ORDINARY_BACKPRESSURE_LIMIT_MS_V1,
            };
        }

        let inserted = self.ordinary_bindings.insert(binding);
        debug_assert!(
            inserted,
            "ordinary duplicate check and insertion stay atomic"
        );
        self.ordinary.push_back(binding);
        increment_bounded_v1(&mut self.metrics.ordinary_accepted_count);
        DispatchQueueAdmissionV1::Accepted
    }

    pub fn admit_control_v1(
        &mut self,
        kind: DispatchControlKindV1,
        binding: DispatchQueueBindingV1,
    ) -> DispatchQueueAdmissionV1 {
        if self.control_bindings.contains(&(kind, binding)) {
            increment_bounded_v1(&mut self.metrics.duplicate_count);
            return DispatchQueueAdmissionV1::ExactDuplicate;
        }
        if self.control.len() >= DISPATCH_QUEUE_CONTROL_CAPACITY_V1 {
            increment_bounded_v1(&mut self.metrics.backpressure_count);
            return DispatchQueueAdmissionV1::Backpressured {
                within_ms: DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1,
            };
        }

        let inserted = self.control_bindings.insert((kind, binding));
        debug_assert!(
            inserted,
            "control duplicate check and insertion stay atomic"
        );
        self.control
            .push_back(DispatchControlRequestV1 { kind, binding });
        increment_bounded_v1(&mut self.metrics.control_accepted_count);
        DispatchQueueAdmissionV1::Accepted
    }

    pub fn dequeue_ordinary_v1(&mut self) -> Option<DispatchQueueBindingV1> {
        let binding = self.ordinary.pop_front()?;
        let removed = self.ordinary_bindings.remove(&binding);
        debug_assert!(removed, "ordinary queue and duplicate index stay aligned");
        Some(binding)
    }

    pub fn dequeue_control_v1(&mut self) -> Option<DispatchControlRequestV1> {
        let request = self.control.pop_front()?;
        let removed = self
            .control_bindings
            .remove(&(request.kind, request.binding));
        debug_assert!(removed, "control queue and duplicate index stay aligned");
        Some(request)
    }

    pub fn observe_control_latency_v1(&mut self, latency_ms: u64) {
        self.metrics.control_latency.observe_v1(latency_ms);
    }

    pub fn observe_dispatch_v1(&mut self) {
        increment_bounded_v1(&mut self.metrics.dispatch_count);
    }

    pub fn observe_inbox_v1(&mut self) {
        increment_bounded_v1(&mut self.metrics.inbox_count);
    }

    pub fn observe_receipt_v1(&mut self) {
        increment_bounded_v1(&mut self.metrics.receipt_count);
    }

    pub fn observe_refusal_v1(&mut self) {
        increment_bounded_v1(&mut self.metrics.refusal_count);
    }

    pub fn observe_ambiguity_v1(&mut self) {
        increment_bounded_v1(&mut self.metrics.ambiguity_count);
    }

    pub fn observe_conflict_v1(&mut self) {
        increment_bounded_v1(&mut self.metrics.conflict_count);
    }

    pub fn observe_recovery_v1(&mut self) {
        increment_bounded_v1(&mut self.metrics.recovery_count);
    }

    pub fn metrics_snapshot_v1(&self) -> DispatchQueueMetricsSnapshotV1 {
        DispatchQueueMetricsSnapshotV1 {
            ordinary_pending: self.ordinary.len(),
            control_pending: self.control.len(),
            ordinary_accepted_count: self.metrics.ordinary_accepted_count,
            control_accepted_count: self.metrics.control_accepted_count,
            duplicate_count: self.metrics.duplicate_count,
            backpressure_count: self.metrics.backpressure_count,
            control_latency_sample_count: self.metrics.control_latency.total_sample_count,
            control_latency_p99_ms: self.metrics.control_latency.p99_ms_v1(),
            dispatch_count: self.metrics.dispatch_count,
            inbox_count: self.metrics.inbox_count,
            receipt_count: self.metrics.receipt_count,
            refusal_count: self.metrics.refusal_count,
            ambiguity_count: self.metrics.ambiguity_count,
            conflict_count: self.metrics.conflict_count,
            recovery_count: self.metrics.recovery_count,
        }
    }
}

impl Default for DispatchQueueV1 {
    fn default() -> Self {
        Self::new_v1()
    }
}

impl fmt::Debug for DispatchQueueV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchQueueV1")
            .field("ordinary_pending", &self.ordinary.len())
            .field("control_pending", &self.control.len())
            .finish_non_exhaustive()
    }
}

/// Payload-free timings from one controlled saturation trial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchQueueTrialMeasurementV1 {
    ordinary_backpressure_ms: u64,
    pause_ms: u64,
    status_ms: u64,
    reconciliation_ms: u64,
}

impl DispatchQueueTrialMeasurementV1 {
    pub const ZERO: Self = Self {
        ordinary_backpressure_ms: 0,
        pause_ms: 0,
        status_ms: 0,
        reconciliation_ms: 0,
    };

    pub const fn new_v1(
        ordinary_backpressure_ms: u64,
        pause_ms: u64,
        status_ms: u64,
        reconciliation_ms: u64,
    ) -> Self {
        Self {
            ordinary_backpressure_ms: bounded_counter_const_v1(ordinary_backpressure_ms),
            pause_ms: bounded_counter_const_v1(pause_ms),
            status_ms: bounded_counter_const_v1(status_ms),
            reconciliation_ms: bounded_counter_const_v1(reconciliation_ms),
        }
    }

    pub const fn ordinary_backpressure_ms_v1(self) -> u64 {
        self.ordinary_backpressure_ms
    }

    pub const fn pause_ms_v1(self) -> u64 {
        self.pause_ms
    }

    pub const fn status_ms_v1(self) -> u64 {
        self.status_ms
    }

    pub const fn reconciliation_ms_v1(self) -> u64 {
        self.reconciliation_ms
    }
}

/// Exact 100-trial nearest-rank percentile summary for the controlled flood profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchQueueControlledProfileV1 {
    ordinary_backpressure_max_ms: u64,
    ordinary_backpressure_p95_ms: u64,
    pause_p99_ms: u64,
    status_p99_ms: u64,
    reconciliation_p99_ms: u64,
    control_p99_ms: u64,
}

impl DispatchQueueControlledProfileV1 {
    pub fn from_trials_v1(
        trials: [DispatchQueueTrialMeasurementV1; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1],
    ) -> Self {
        let mut ordinary = [0_u64; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1];
        let mut pause = [0_u64; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1];
        let mut status = [0_u64; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1];
        let mut reconciliation = [0_u64; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1];

        for (index, trial) in trials.into_iter().enumerate() {
            ordinary[index] = trial.ordinary_backpressure_ms;
            pause[index] = trial.pause_ms;
            status[index] = trial.status_ms;
            reconciliation[index] = trial.reconciliation_ms;
        }

        ordinary.sort_unstable();
        pause.sort_unstable();
        status.sort_unstable();
        reconciliation.sort_unstable();
        let ordinary_backpressure_max_ms = ordinary[DISPATCH_QUEUE_CONTROLLED_TRIALS_V1 - 1];
        let ordinary_backpressure_p95_ms =
            ordinary[nearest_rank_index_v1(DISPATCH_QUEUE_CONTROLLED_TRIALS_V1, 95)];
        let pause_p99_ms = pause[nearest_rank_index_v1(DISPATCH_QUEUE_CONTROLLED_TRIALS_V1, 99)];
        let status_p99_ms = status[nearest_rank_index_v1(DISPATCH_QUEUE_CONTROLLED_TRIALS_V1, 99)];
        let reconciliation_p99_ms =
            reconciliation[nearest_rank_index_v1(DISPATCH_QUEUE_CONTROLLED_TRIALS_V1, 99)];

        Self {
            ordinary_backpressure_max_ms,
            ordinary_backpressure_p95_ms,
            pause_p99_ms,
            status_p99_ms,
            reconciliation_p99_ms,
            control_p99_ms: pause_p99_ms.max(status_p99_ms).max(reconciliation_p99_ms),
        }
    }

    pub const fn trial_count_v1(self) -> usize {
        DISPATCH_QUEUE_CONTROLLED_TRIALS_V1
    }

    pub const fn duplicate_flood_per_trial_v1(self) -> usize {
        DISPATCH_QUEUE_DUPLICATE_FLOOD_V1
    }

    pub const fn ordinary_backpressure_max_ms_v1(self) -> u64 {
        self.ordinary_backpressure_max_ms
    }

    pub const fn ordinary_backpressure_p95_ms_v1(self) -> u64 {
        self.ordinary_backpressure_p95_ms
    }

    pub const fn pause_p99_ms_v1(self) -> u64 {
        self.pause_p99_ms
    }

    pub const fn status_p99_ms_v1(self) -> u64 {
        self.status_p99_ms
    }

    pub const fn reconciliation_p99_ms_v1(self) -> u64 {
        self.reconciliation_p99_ms
    }

    pub const fn control_p99_ms_v1(self) -> u64 {
        self.control_p99_ms
    }

    pub const fn meets_contract_v1(self) -> bool {
        self.ordinary_backpressure_max_ms <= DISPATCH_QUEUE_ORDINARY_BACKPRESSURE_LIMIT_MS_V1
            && self.pause_p99_ms <= DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1
            && self.status_p99_ms <= DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1
            && self.reconciliation_p99_ms <= DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1
    }
}

const fn nearest_rank_index_v1(sample_count: usize, percentile: usize) -> usize {
    let rank = (sample_count * percentile).div_ceil(100);
    rank.saturating_sub(1)
}

const fn bounded_counter_const_v1(value: u64) -> u64 {
    if value > DISPATCH_QUEUE_MAX_SAFE_INTEGER_V1 {
        DISPATCH_QUEUE_MAX_SAFE_INTEGER_V1
    } else {
        value
    }
}

fn bounded_counter_v1(value: u64) -> u64 {
    bounded_counter_const_v1(value)
}

fn increment_bounded_v1(counter: &mut u64) {
    *counter = counter
        .saturating_add(1)
        .min(DISPATCH_QUEUE_MAX_SAFE_INTEGER_V1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_v1(value: u64) -> DispatchQueueBindingV1 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        DispatchQueueBindingV1::new_v1(bytes)
    }

    #[test]
    fn ordinary_saturation_preserves_every_reserved_control_slot() {
        let mut queue = DispatchQueueV1::new_v1();
        for ordinal in 0..DISPATCH_QUEUE_ORDINARY_CAPACITY_V1 {
            assert_eq!(
                queue.admit_ordinary_v1(binding_v1(ordinal as u64)),
                DispatchQueueAdmissionV1::Accepted
            );
        }
        assert_eq!(
            queue.admit_ordinary_v1(binding_v1(2_000)),
            DispatchQueueAdmissionV1::Backpressured {
                within_ms: DISPATCH_QUEUE_ORDINARY_BACKPRESSURE_LIMIT_MS_V1
            }
        );
        for ordinal in 0..DISPATCH_QUEUE_CONTROL_CAPACITY_V1 {
            let kind = match ordinal % 3 {
                0 => DispatchControlKindV1::Pause,
                1 => DispatchControlKindV1::Status,
                _ => DispatchControlKindV1::Reconciliation,
            };
            assert_eq!(
                queue.admit_control_v1(kind, binding_v1(4_000 + ordinal as u64)),
                DispatchQueueAdmissionV1::Accepted
            );
        }
        let snapshot = queue.metrics_snapshot_v1();
        assert_eq!(
            snapshot.ordinary_pending_v1(),
            DISPATCH_QUEUE_ORDINARY_CAPACITY_V1
        );
        assert_eq!(
            snapshot.control_pending_v1(),
            DISPATCH_QUEUE_CONTROL_CAPACITY_V1
        );
    }

    #[test]
    fn ten_thousand_duplicates_consume_no_additional_capacity() {
        let mut queue = DispatchQueueV1::new_v1();
        let retained = binding_v1(7);
        assert_eq!(
            queue.admit_ordinary_v1(retained),
            DispatchQueueAdmissionV1::Accepted
        );
        for _ in 0..DISPATCH_QUEUE_DUPLICATE_FLOOD_V1 {
            assert_eq!(
                queue.admit_ordinary_v1(retained),
                DispatchQueueAdmissionV1::ExactDuplicate
            );
        }
        let snapshot = queue.metrics_snapshot_v1();
        assert_eq!(snapshot.ordinary_pending_v1(), 1);
        assert_eq!(
            snapshot.duplicate_count_v1(),
            DISPATCH_QUEUE_DUPLICATE_FLOOD_V1 as u64
        );
        assert_eq!(
            queue.admit_control_v1(DispatchControlKindV1::Pause, binding_v1(8)),
            DispatchQueueAdmissionV1::Accepted
        );
    }

    #[test]
    fn dequeue_releases_only_its_own_lane_and_duplicate_index() {
        let mut queue = DispatchQueueV1::new_v1();
        let ordinary = binding_v1(1);
        let control = binding_v1(2);
        assert!(queue.admit_ordinary_v1(ordinary).accepted_v1());
        assert!(queue
            .admit_control_v1(DispatchControlKindV1::Status, control)
            .accepted_v1());
        assert_eq!(queue.dequeue_ordinary_v1(), Some(ordinary));
        assert!(queue.admit_ordinary_v1(ordinary).accepted_v1());
        let request = queue.dequeue_control_v1().expect("reserved request exists");
        assert_eq!(request.kind_v1(), DispatchControlKindV1::Status);
        assert_eq!(request.binding_v1(), control);
        assert!(queue
            .admit_control_v1(DispatchControlKindV1::Status, control)
            .accepted_v1());
    }

    #[test]
    fn metrics_are_safe_integer_bounded_and_debug_omits_bindings() {
        let mut queue = DispatchQueueV1::new_v1();
        queue.metrics.duplicate_count = DISPATCH_QUEUE_MAX_SAFE_INTEGER_V1;
        assert!(queue.admit_ordinary_v1(binding_v1(5)).accepted_v1());
        assert!(queue.admit_ordinary_v1(binding_v1(5)).duplicate_v1());
        queue.observe_control_latency_v1(u64::MAX);
        assert_eq!(
            queue.metrics_snapshot_v1().duplicate_count_v1(),
            DISPATCH_QUEUE_MAX_SAFE_INTEGER_V1
        );
        assert_eq!(
            queue.metrics_snapshot_v1().control_latency_p99_ms_v1(),
            Some(DISPATCH_QUEUE_MAX_SAFE_INTEGER_V1)
        );
        let rendered = format!("{queue:?}");
        assert_eq!(
            rendered,
            "DispatchQueueV1 { ordinary_pending: 1, control_pending: 0, .. }"
        );
    }

    #[test]
    fn exact_hundred_trial_profile_uses_nearest_rank_percentiles() {
        let mut trials =
            [DispatchQueueTrialMeasurementV1::ZERO; DISPATCH_QUEUE_CONTROLLED_TRIALS_V1];
        for (index, trial) in trials.iter_mut().enumerate() {
            *trial = DispatchQueueTrialMeasurementV1::new_v1(20 + (index % 5) as u64, 40, 50, 60);
        }
        trials[DISPATCH_QUEUE_CONTROLLED_TRIALS_V1 - 1] =
            DispatchQueueTrialMeasurementV1::new_v1(25, 1_000, 1_000, 1_000);
        let profile = DispatchQueueControlledProfileV1::from_trials_v1(trials);
        assert_eq!(profile.trial_count_v1(), 100);
        assert_eq!(profile.duplicate_flood_per_trial_v1(), 10_000);
        assert_eq!(profile.pause_p99_ms_v1(), 40);
        assert_eq!(profile.status_p99_ms_v1(), 50);
        assert_eq!(profile.reconciliation_p99_ms_v1(), 60);
        assert!(profile.meets_contract_v1());

        trials[DISPATCH_QUEUE_CONTROLLED_TRIALS_V1 - 2] =
            DispatchQueueTrialMeasurementV1::new_v1(25, 1_000, 1_000, 1_000);
        let failing = DispatchQueueControlledProfileV1::from_trials_v1(trials);
        assert_eq!(failing.control_p99_ms_v1(), 1_000);
        assert!(!failing.meets_contract_v1());
    }
}
