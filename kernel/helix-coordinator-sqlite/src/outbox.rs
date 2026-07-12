//! Transactional preparation-event outbox writes.
//!
//! Events are staged by the same SQLite transaction as the operation transition. This
//! module deliberately owns no delivery worker and exposes no event payload outside the
//! coordinator crate.

use rusqlite::{named_params, Result as SqliteResult, Transaction};

pub(crate) struct PreparedEventRowV1<'row> {
    pub(crate) event_id: &'row [u8; 32],
    pub(crate) event_generation: i64,
    pub(crate) operation_id: &'row str,
    pub(crate) operation_state_generation: i64,
}

#[allow(dead_code)] // Some source-included positive-path tests do not compile failure.rs.
pub(crate) struct FailedEventRowV1<'row> {
    pub(crate) event_id: &'row [u8; 32],
    pub(crate) event_generation: i64,
    pub(crate) operation_id: &'row str,
    pub(crate) operation_state_generation: i64,
    pub(crate) reason_code: &'row str,
}

/// Stages the redacted `PREPARED/PENDING` event joined to the initial transition.
///
/// The caller retains the transaction and therefore controls the only publication
/// point. No identifier, digest, budget value, or provider diagnostic is serialized as
/// an outward event payload.
pub(crate) fn stage_prepared_event_v1(
    transaction: &Transaction<'_>,
    row: PreparedEventRowV1<'_>,
) -> SqliteResult<()> {
    transaction.execute(
        "INSERT INTO preparation_events (\
             event_id, event_generation, operation_id, operation_state_generation, \
             operation_state, event_kind, reason_code, delivery_state, \
             delivered_generation\
         ) VALUES (\
             :event_id, :event_generation, :operation_id, :state_generation, \
             'PREPARING', 'PREPARED', NULL, 'PENDING', NULL\
         )",
        named_params! {
            ":event_id": row.event_id.as_slice(),
            ":event_generation": row.event_generation,
            ":operation_id": row.operation_id,
            ":state_generation": row.operation_state_generation,
        },
    )?;
    Ok(())
}

/// Stages the one redacted `PREPARATION_FAILED/PENDING` event for a terminal transition.
#[allow(dead_code)] // Some source-included positive-path tests do not compile failure.rs.
pub(crate) fn stage_failed_event_v1(
    transaction: &Transaction<'_>,
    row: FailedEventRowV1<'_>,
) -> SqliteResult<()> {
    transaction.execute(
        "INSERT INTO preparation_events (\
             event_id, event_generation, operation_id, operation_state_generation, \
             operation_state, event_kind, reason_code, delivery_state, \
             delivered_generation\
         ) VALUES (\
             :event_id, :event_generation, :operation_id, :state_generation, \
             'FAILED', 'PREPARATION_FAILED', :reason_code, 'PENDING', NULL\
         )",
        named_params! {
            ":event_id": row.event_id.as_slice(),
            ":event_generation": row.event_generation,
            ":operation_id": row.operation_id,
            ":state_generation": row.operation_state_generation,
            ":reason_code": row.reason_code,
        },
    )?;
    Ok(())
}
