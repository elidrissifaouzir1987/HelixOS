//! Adapter-owned bounded inbox and reserved control queue facade.

#![allow(dead_code)]

use helix_plan_dispatch::{
    DispatchControlKindV1, DispatchControlRequestV1, DispatchQueueAdmissionV1,
    DispatchQueueBindingV1, DispatchQueueControlledProfileV1, DispatchQueueMetricsSnapshotV1,
    DispatchQueueTrialMeasurementV1, DispatchQueueV1, DISPATCH_QUEUE_CONTROLLED_TRIALS_V1,
    DISPATCH_QUEUE_CONTROL_CAPACITY_V1, DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1,
    DISPATCH_QUEUE_DUPLICATE_FLOOD_V1, DISPATCH_QUEUE_ORDINARY_BACKPRESSURE_LIMIT_MS_V1,
    DISPATCH_QUEUE_ORDINARY_CAPACITY_V1,
};
use std::fmt;
use std::time::Instant;

pub const ADAPTER_QUEUE_ORDINARY_CAPACITY_V1: usize = 1024;
pub const ADAPTER_QUEUE_CONTROL_CAPACITY_V1: usize = 32;
pub const ADAPTER_QUEUE_BACKPRESSURE_LIMIT_MS_V1: u64 = 50;
pub const ADAPTER_QUEUE_CONTROL_P99_LIMIT_MS_V1: u64 = 100;
pub const ADAPTER_QUEUE_CONTROLLED_TRIALS_V1: usize = 100;
pub const ADAPTER_QUEUE_DUPLICATE_FLOOD_V1: usize = 10_000;

const _: [(); ADAPTER_QUEUE_ORDINARY_CAPACITY_V1] = [(); DISPATCH_QUEUE_ORDINARY_CAPACITY_V1];
const _: [(); ADAPTER_QUEUE_CONTROL_CAPACITY_V1] = [(); DISPATCH_QUEUE_CONTROL_CAPACITY_V1];
const _: [(); ADAPTER_QUEUE_CONTROLLED_TRIALS_V1] = [(); DISPATCH_QUEUE_CONTROLLED_TRIALS_V1];
const _: [(); ADAPTER_QUEUE_DUPLICATE_FLOOD_V1] = [(); DISPATCH_QUEUE_DUPLICATE_FLOOD_V1];
const _: [(); ADAPTER_QUEUE_BACKPRESSURE_LIMIT_MS_V1 as usize] =
    [(); DISPATCH_QUEUE_ORDINARY_BACKPRESSURE_LIMIT_MS_V1 as usize];
const _: [(); ADAPTER_QUEUE_CONTROL_P99_LIMIT_MS_V1 as usize] =
    [(); DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1 as usize];

/// Adapter-facing payload-free metric publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterDispatchQueueMetricsSnapshotV1 {
    pub ordinary_pending: usize,
    pub control_pending: usize,
    pub ordinary_accepted_count: u64,
    pub control_accepted_count: u64,
    pub duplicate_count: u64,
    pub backpressure_count: u64,
    pub control_latency_sample_count: u64,
    pub control_latency_p99_ms: Option<u64>,
    pub inbox_count: u64,
    pub receipt_count: u64,
    pub refusal_count: u64,
    pub ambiguity_count: u64,
    pub conflict_count: u64,
    pub recovery_count: u64,
}

impl From<DispatchQueueMetricsSnapshotV1> for AdapterDispatchQueueMetricsSnapshotV1 {
    fn from(snapshot: DispatchQueueMetricsSnapshotV1) -> Self {
        Self {
            ordinary_pending: snapshot.ordinary_pending_v1(),
            control_pending: snapshot.control_pending_v1(),
            ordinary_accepted_count: snapshot.ordinary_accepted_count_v1(),
            control_accepted_count: snapshot.control_accepted_count_v1(),
            duplicate_count: snapshot.duplicate_count_v1(),
            backpressure_count: snapshot.backpressure_count_v1(),
            control_latency_sample_count: snapshot.control_latency_sample_count_v1(),
            control_latency_p99_ms: snapshot.control_latency_p99_ms_v1(),
            inbox_count: snapshot.inbox_count_v1(),
            receipt_count: snapshot.receipt_count_v1(),
            refusal_count: snapshot.refusal_count_v1(),
            ambiguity_count: snapshot.ambiguity_count_v1(),
            conflict_count: snapshot.conflict_count_v1(),
            recovery_count: snapshot.recovery_count_v1(),
        }
    }
}

/// In-memory adapter admission accounting with no durable-record ownership.
///
/// Only opaque pending bindings and bounded counters are retained here. The ordinary
/// inbox lane and the PAUSE/status/reconciliation lane have independent capacities.
pub struct AdapterDispatchQueueV1 {
    queue: DispatchQueueV1,
}

impl AdapterDispatchQueueV1 {
    pub fn new_v1() -> Self {
        Self {
            queue: DispatchQueueV1::new_v1(),
        }
    }

    pub fn admit_inbox_v1(&mut self, binding: [u8; 32]) -> DispatchQueueAdmissionV1 {
        let admission = self
            .queue
            .admit_ordinary_v1(DispatchQueueBindingV1::new_v1(binding));
        if admission.accepted_v1() {
            self.queue.observe_inbox_v1();
        }
        admission
    }

    pub fn admit_pause_v1(&mut self, binding: [u8; 32]) -> DispatchQueueAdmissionV1 {
        self.admit_control_v1(DispatchControlKindV1::Pause, binding)
    }

    pub fn admit_status_v1(&mut self, binding: [u8; 32]) -> DispatchQueueAdmissionV1 {
        self.admit_control_v1(DispatchControlKindV1::Status, binding)
    }

    pub fn admit_reconciliation_v1(&mut self, binding: [u8; 32]) -> DispatchQueueAdmissionV1 {
        self.admit_control_v1(DispatchControlKindV1::Reconciliation, binding)
    }

    pub fn dequeue_inbox_v1(&mut self) -> Option<[u8; 32]> {
        self.queue
            .dequeue_ordinary_v1()
            .map(|binding| *binding.as_bytes_v1())
    }

    pub fn dequeue_control_v1(&mut self) -> Option<DispatchControlRequestV1> {
        self.queue.dequeue_control_v1()
    }

    pub fn observe_control_latency_v1(&mut self, latency_ms: u64) {
        self.queue.observe_control_latency_v1(latency_ms);
    }

    pub fn observe_receipt_v1(&mut self) {
        self.queue.observe_receipt_v1();
    }

    pub fn observe_refusal_v1(&mut self) {
        self.queue.observe_refusal_v1();
    }

    pub fn observe_ambiguity_v1(&mut self) {
        self.queue.observe_ambiguity_v1();
    }

    pub fn observe_conflict_v1(&mut self) {
        self.queue.observe_conflict_v1();
    }

    pub fn observe_recovery_v1(&mut self) {
        self.queue.observe_recovery_v1();
    }

    pub fn metrics_snapshot_v1(&self) -> AdapterDispatchQueueMetricsSnapshotV1 {
        self.queue.metrics_snapshot_v1().into()
    }

    fn admit_control_v1(
        &mut self,
        kind: DispatchControlKindV1,
        binding: [u8; 32],
    ) -> DispatchQueueAdmissionV1 {
        self.queue
            .admit_control_v1(kind, DispatchQueueBindingV1::new_v1(binding))
    }
}

impl Default for AdapterDispatchQueueV1 {
    fn default() -> Self {
        Self::new_v1()
    }
}

impl fmt::Debug for AdapterDispatchQueueV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterDispatchQueueV1")
            .field("metrics", &self.metrics_snapshot_v1())
            .finish_non_exhaustive()
    }
}

/// Closed failure from the deterministic controlled-profile driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterDispatchQueueProfileErrorV1 {
    OrdinaryFillInvariant,
    DuplicateInvariant,
    OrdinaryBackpressureInvariant,
    ControlAdmissionInvariant,
}

/// Measures the production adapter queue over exactly 100 saturation trials.
///
/// Every trial fills all 1024 ordinary slots, submits 10,000 exact duplicates, measures
/// immediate ordinary backpressure, then measures PAUSE, status and reconciliation on
/// the independent capacity-32 control lane. The returned profile publishes p95/p99
/// timings and the threshold verdict without retaining any queue binding.
pub fn measure_adapter_dispatch_queue_profile_v1(
) -> Result<DispatchQueueControlledProfileV1, AdapterDispatchQueueProfileErrorV1> {
    let mut trials = [DispatchQueueTrialMeasurementV1::ZERO; ADAPTER_QUEUE_CONTROLLED_TRIALS_V1];

    for (trial_index, trial) in trials.iter_mut().enumerate() {
        let mut queue = AdapterDispatchQueueV1::new_v1();
        for ordinal in 0..ADAPTER_QUEUE_ORDINARY_CAPACITY_V1 {
            if queue.admit_inbox_v1(profile_binding_v1(1, trial_index, ordinal))
                != DispatchQueueAdmissionV1::Accepted
            {
                return Err(AdapterDispatchQueueProfileErrorV1::OrdinaryFillInvariant);
            }
        }

        let retained = profile_binding_v1(1, trial_index, 0);
        for _ in 0..ADAPTER_QUEUE_DUPLICATE_FLOOD_V1 {
            if queue.admit_inbox_v1(retained) != DispatchQueueAdmissionV1::ExactDuplicate {
                return Err(AdapterDispatchQueueProfileErrorV1::DuplicateInvariant);
            }
        }

        let ordinary_started = Instant::now();
        let ordinary_admission = queue.admit_inbox_v1(profile_binding_v1(
            1,
            trial_index,
            ADAPTER_QUEUE_ORDINARY_CAPACITY_V1,
        ));
        let ordinary_backpressure_ms = elapsed_ms_v1(ordinary_started);
        if ordinary_admission
            != (DispatchQueueAdmissionV1::Backpressured {
                within_ms: ADAPTER_QUEUE_BACKPRESSURE_LIMIT_MS_V1,
            })
        {
            return Err(AdapterDispatchQueueProfileErrorV1::OrdinaryBackpressureInvariant);
        }

        let pause_started = Instant::now();
        let pause_admission = queue.admit_pause_v1(profile_binding_v1(2, trial_index, 0));
        let pause_ms = elapsed_ms_v1(pause_started);
        ensure_control_accepted_v1(pause_admission)?;
        queue.observe_control_latency_v1(pause_ms);

        let status_started = Instant::now();
        let status_admission = queue.admit_status_v1(profile_binding_v1(3, trial_index, 0));
        let status_ms = elapsed_ms_v1(status_started);
        ensure_control_accepted_v1(status_admission)?;
        queue.observe_control_latency_v1(status_ms);

        let reconciliation_started = Instant::now();
        let reconciliation_admission =
            queue.admit_reconciliation_v1(profile_binding_v1(4, trial_index, 0));
        let reconciliation_ms = elapsed_ms_v1(reconciliation_started);
        ensure_control_accepted_v1(reconciliation_admission)?;
        queue.observe_control_latency_v1(reconciliation_ms);

        *trial = DispatchQueueTrialMeasurementV1::new_v1(
            ordinary_backpressure_ms,
            pause_ms,
            status_ms,
            reconciliation_ms,
        );
    }

    Ok(DispatchQueueControlledProfileV1::from_trials_v1(trials))
}

fn ensure_control_accepted_v1(
    admission: DispatchQueueAdmissionV1,
) -> Result<(), AdapterDispatchQueueProfileErrorV1> {
    if admission == DispatchQueueAdmissionV1::Accepted {
        Ok(())
    } else {
        Err(AdapterDispatchQueueProfileErrorV1::ControlAdmissionInvariant)
    }
}

fn profile_binding_v1(lane: u8, trial: usize, ordinal: usize) -> [u8; 32] {
    let mut binding = [0_u8; 32];
    binding[0] = lane;
    binding[1..9].copy_from_slice(&(trial as u64).to_le_bytes());
    binding[9..17].copy_from_slice(&(ordinal as u64).to_le_bytes());
    binding
}

fn elapsed_ms_v1(started: Instant) -> u64 {
    let elapsed_ns = started.elapsed().as_nanos();
    u64::try_from(elapsed_ns.div_ceil(1_000_000)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_and_control_lanes_remain_independent() {
        let mut queue = AdapterDispatchQueueV1::new_v1();
        for ordinal in 0..ADAPTER_QUEUE_ORDINARY_CAPACITY_V1 {
            assert_eq!(
                queue.admit_inbox_v1(profile_binding_v1(1, 0, ordinal)),
                DispatchQueueAdmissionV1::Accepted
            );
        }
        assert_eq!(
            queue.admit_inbox_v1(profile_binding_v1(1, 0, 2_000)),
            DispatchQueueAdmissionV1::Backpressured {
                within_ms: ADAPTER_QUEUE_BACKPRESSURE_LIMIT_MS_V1
            }
        );
        assert_eq!(
            queue.admit_reconciliation_v1(profile_binding_v1(4, 0, 0)),
            DispatchQueueAdmissionV1::Accepted
        );
        let metrics = queue.metrics_snapshot_v1();
        assert_eq!(metrics.ordinary_pending, 1024);
        assert_eq!(metrics.control_pending, 1);
        assert_eq!(metrics.backpressure_count, 1);
    }

    #[test]
    fn profile_driver_has_exact_cardinalities_and_payload_free_output() {
        let profile = measure_adapter_dispatch_queue_profile_v1()
            .expect("controlled queue invariants remain intact");
        assert_eq!(profile.trial_count_v1(), 100);
        assert_eq!(profile.duplicate_flood_per_trial_v1(), 10_000);
        let rendered = format!("{profile:?}");
        assert!(rendered.contains("p99"));
        assert!(!rendered.contains("binding"));
    }
}
