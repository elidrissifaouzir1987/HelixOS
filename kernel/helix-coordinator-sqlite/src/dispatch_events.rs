//! Permanent redacted dispatch-event projection and payload-free metrics.

#![allow(dead_code)] // Wired into SqliteCoordinatorStoreV2 by T037.

use helix_contracts::MAX_SAFE_U64;
use rusqlite::{params, Transaction};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct DispatchEventRowV1<'row> {
    pub(crate) event_id: &'row [u8; 32],
    pub(crate) event_generation: i64,
    pub(crate) transition_generation: i64,
    pub(crate) operation_id: &'row str,
    pub(crate) grant_id: &'row [u8; 32],
    pub(crate) dispatch_attempt_id: &'row [u8; 32],
    pub(crate) task_id: &'row str,
    pub(crate) workload_id: &'row str,
    pub(crate) plan_id: &'row [u8; 32],
    pub(crate) task_lease_digest: &'row [u8; 32],
    pub(crate) latency_ms: i64,
    pub(crate) public_trace_id: &'row str,
}

impl fmt::Debug for DispatchEventRowV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchEventRowV1")
            .finish_non_exhaustive()
    }
}

/// Appends the public, payload-free projection for the initial durable dispatch.
///
/// No canonical grant bytes, authority digests, paths, arguments, or internal failure
/// values cross this boundary. The schema makes the row permanent and permits only its
/// later `PENDING -> DELIVERED` projection update.
pub(crate) fn stage_pending_dispatch_event_v1(
    transaction: &Transaction<'_>,
    row: DispatchEventRowV1<'_>,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO dispatch_events (\
             event_id, event_generation, transition_generation, operation_id, grant_id, \
             dispatch_attempt_id, task_id, workload_id, plan_id, task_lease_digest, \
             event_contract_version, grant_contract_version, receipt_contract_version, \
             effective_state, decision, latency_ms, event_kind, public_reason_code, \
             public_trace_id, delivery_state, delivered_generation\
         ) VALUES (\
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
             1, 1, 0, 'DISPATCHING', 'DISPATCHED', ?11, 'DISPATCHED', NULL, \
             ?12, 'PENDING', NULL\
         )",
        params![
            row.event_id.as_slice(),
            row.event_generation,
            row.transition_generation,
            row.operation_id,
            row.grant_id.as_slice(),
            row.dispatch_attempt_id.as_slice(),
            row.task_id,
            row.workload_id,
            row.plan_id.as_slice(),
            row.task_lease_digest.as_slice(),
            row.latency_ms,
            row.public_trace_id,
        ],
    )?;
    Ok(())
}

/// Bounded, label-free counters for the storage boundary.
///
/// Counters saturate at the portable safe-integer ceiling. They never retain operation,
/// grant, attempt, trace, canonical bytes, or failure payloads.
#[derive(Default)]
pub(crate) struct DispatchMetricsV1 {
    committed: AtomicU64,
    prior_exact: AtomicU64,
    confirmed_rollback: AtomicU64,
    uncertain: AtomicU64,
    conflict: AtomicU64,
    unavailable: AtomicU64,
    unhealthy: AtomicU64,
}

impl DispatchMetricsV1 {
    pub(crate) fn observe_committed_v1(&self) {
        increment_bounded_v1(&self.committed);
    }

    pub(crate) fn observe_prior_exact_v1(&self) {
        increment_bounded_v1(&self.prior_exact);
    }

    pub(crate) fn observe_confirmed_rollback_v1(&self) {
        increment_bounded_v1(&self.confirmed_rollback);
    }

    pub(crate) fn observe_uncertain_v1(&self) {
        increment_bounded_v1(&self.uncertain);
    }

    pub(crate) fn observe_conflict_v1(&self) {
        increment_bounded_v1(&self.conflict);
    }

    pub(crate) fn observe_unavailable_v1(&self) {
        increment_bounded_v1(&self.unavailable);
    }

    pub(crate) fn observe_unhealthy_v1(&self) {
        increment_bounded_v1(&self.unhealthy);
    }

    pub(crate) fn snapshot_v1(&self) -> DispatchMetricsSnapshotV1 {
        DispatchMetricsSnapshotV1 {
            committed: load_bounded_v1(&self.committed),
            prior_exact: load_bounded_v1(&self.prior_exact),
            confirmed_rollback: load_bounded_v1(&self.confirmed_rollback),
            uncertain: load_bounded_v1(&self.uncertain),
            conflict: load_bounded_v1(&self.conflict),
            unavailable: load_bounded_v1(&self.unavailable),
            unhealthy: load_bounded_v1(&self.unhealthy),
        }
    }
}

impl fmt::Debug for DispatchMetricsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchMetricsV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DispatchMetricsSnapshotV1 {
    pub(crate) committed: u64,
    pub(crate) prior_exact: u64,
    pub(crate) confirmed_rollback: u64,
    pub(crate) uncertain: u64,
    pub(crate) conflict: u64,
    pub(crate) unavailable: u64,
    pub(crate) unhealthy: u64,
}

fn increment_bounded_v1(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(1).min(MAX_SAFE_U64))
    });
}

fn load_bounded_v1(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed).min(MAX_SAFE_U64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_bounded_and_debug_is_payload_free() {
        let metrics = DispatchMetricsV1::default();
        metrics.committed.store(MAX_SAFE_U64, Ordering::Relaxed);
        metrics.observe_committed_v1();
        assert_eq!(metrics.snapshot_v1().committed, MAX_SAFE_U64);
        assert_eq!(format!("{metrics:?}"), "DispatchMetricsV1 { .. }");
    }
}
