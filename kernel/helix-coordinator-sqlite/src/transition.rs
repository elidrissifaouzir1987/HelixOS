//! Private append-only operation-transition boundary.

use rusqlite::{named_params, Result as SqliteResult, Transaction};

pub(crate) struct FailedTransitionRowV1<'row> {
    pub(crate) state_generation: i64,
    pub(crate) operation_id: &'row str,
    pub(crate) event_id: &'row [u8; 32],
}

/// Appends the sole allowed terminal transition for a prepared operation.
///
/// The caller owns the surrounding transaction. Foreign-key custody binds this row to
/// the matching terminal operation row and failure event at commit.
pub(crate) fn stage_failed_transition_v1(
    transaction: &Transaction<'_>,
    row: FailedTransitionRowV1<'_>,
) -> SqliteResult<()> {
    transaction.execute(
        "INSERT INTO operation_transitions (\
             state_generation, operation_id, previous_state, new_state, event_id\
         ) VALUES (\
             :state_generation, :operation_id, 'PREPARING', 'FAILED', :event_id\
         )",
        named_params! {
            ":state_generation": row.state_generation,
            ":operation_id": row.operation_id,
            ":event_id": row.event_id.as_slice(),
        },
    )?;
    Ok(())
}
