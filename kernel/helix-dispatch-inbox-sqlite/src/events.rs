//! Internal append-only adapter event projection for terminal inbox decisions.

#![allow(dead_code)]

use helix_dispatch_contracts::Sha256Digest;
use rusqlite::{params, Transaction};

/// Complete sovereign binding for one terminal adapter event.
///
/// This remains crate-private because outward event and metric projections must never
/// expose the identifiers or digests retained by the sovereign store.
pub(crate) struct TerminalAdapterEventV1<'event> {
    pub(crate) event_id: Sha256Digest,
    pub(crate) event_generation: u64,
    pub(crate) transition_generation: u64,
    pub(crate) grant_id: Sha256Digest,
    pub(crate) operation_id: &'event str,
    pub(crate) dispatch_attempt_id: Sha256Digest,
    pub(crate) task_id: &'event str,
    pub(crate) workload_id: &'event str,
    pub(crate) plan_id: Sha256Digest,
    pub(crate) task_lease_digest: Sha256Digest,
    pub(crate) effective_state: &'static str,
    pub(crate) decision: &'static str,
    pub(crate) latency_ms: u64,
    pub(crate) event_kind: &'static str,
    pub(crate) public_reason_code: Option<&'static str>,
    pub(crate) public_trace_id: &'event str,
}

impl std::fmt::Debug for TerminalAdapterEventV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TerminalAdapterEventV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn append_terminal_adapter_event_v1(
    transaction: &Transaction<'_>,
    event: &TerminalAdapterEventV1<'_>,
) -> rusqlite::Result<usize> {
    transaction.execute(
        "INSERT INTO adapter_events (
            event_id, event_generation, transition_generation, grant_id,
            operation_id, dispatch_attempt_id, task_id, workload_id, plan_id,
            task_lease_digest, event_contract_version, grant_contract_version,
            receipt_contract_version, effective_state, decision, latency_ms,
            event_kind, public_reason_code, public_trace_id, delivery_state,
            delivered_generation
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            1, 1, 1, ?11, ?12, ?13, ?14, ?15, ?16, 'PENDING', NULL
         )",
        params![
            event.event_id.as_bytes().as_slice(),
            to_i64(event.event_generation)?,
            to_i64(event.transition_generation)?,
            event.grant_id.as_bytes().as_slice(),
            event.operation_id,
            event.dispatch_attempt_id.as_bytes().as_slice(),
            event.task_id,
            event.workload_id,
            event.plan_id.as_bytes().as_slice(),
            event.task_lease_digest.as_bytes().as_slice(),
            event.effective_state,
            event.decision,
            to_i64(event.latency_ms)?,
            event.event_kind,
            event.public_reason_code,
            event.public_trace_id,
        ],
    )
}

fn to_i64(value: u64) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
}
