//! Exact readback after an ambiguous initial dispatch COMMIT.

#![allow(dead_code)] // Wired into SqliteCoordinatorStoreV2 by T037.

use crate::dispatch::{
    CoordinatorDispatchCommitReceiptV1, CoordinatorDispatchUncertainCommitCustodyV1,
};
use helix_plan_dispatch::{DispatchAttemptIdV1, DispatchStoreReadbackOutcomeV1};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};
use sha2::{Digest as _, Sha256};

impl CoordinatorDispatchUncertainCommitCustodyV1 {
    pub(crate) fn matches_attempt_v1(&self, attempt: &DispatchAttemptIdV1) -> bool {
        self.dispatch_attempt_id == *attempt.as_bytes()
    }
}

/// Opens one writer-excluded snapshot, consumes uncertainty custody, and classifies
/// only exact retained evidence. The verifier must authenticate the same live snapshot.
pub(crate) fn readback_uncertain_dispatch_v1<F>(
    connection: &mut Connection,
    custody: CoordinatorDispatchUncertainCommitCustodyV1,
    verify_live_snapshot: F,
) -> DispatchStoreReadbackOutcomeV1<CoordinatorDispatchCommitReceiptV1>
where
    F: FnOnce(&Connection) -> bool,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return map_open_error_v1(error),
    };
    let outcome = if verify_live_snapshot(&transaction) {
        classify_exact_snapshot_v1(&transaction, &custody)
    } else {
        DispatchStoreReadbackOutcomeV1::Unhealthy
    };
    if transaction.rollback().is_err() {
        return DispatchStoreReadbackOutcomeV1::Unhealthy;
    }
    outcome
}

fn classify_exact_snapshot_v1(
    connection: &Connection,
    custody: &CoordinatorDispatchUncertainCommitCustodyV1,
) -> DispatchStoreReadbackOutcomeV1<CoordinatorDispatchCommitReceiptV1> {
    match load_complete_initial_graph_v1(connection, &custody.operation_id) {
        Ok(Some(graph)) => {
            if graph.matches_exact_attempt_v1(custody) {
                DispatchStoreReadbackOutcomeV1::ThisAttemptCommitted(graph.receipt)
            } else if graph.is_coherent_prior_v1(custody) {
                DispatchStoreReadbackOutcomeV1::PriorExactDispatch(graph.receipt)
            } else {
                DispatchStoreReadbackOutcomeV1::Conflict
            }
        }
        Ok(None) => match relevant_footprint_v1(connection, custody) {
            Ok(0) => DispatchStoreReadbackOutcomeV1::DefinitelyAbsent,
            Ok(_) => DispatchStoreReadbackOutcomeV1::Conflict,
            Err(error) => error.into_outcome_v1(),
        },
        Err(error) => error.into_outcome_v1(),
    }
}

#[derive(Clone, Copy)]
enum ReadbackErrorV1 {
    Unavailable,
    Unhealthy,
}

impl ReadbackErrorV1 {
    fn into_outcome_v1(self) -> DispatchStoreReadbackOutcomeV1<CoordinatorDispatchCommitReceiptV1> {
        match self {
            Self::Unavailable => DispatchStoreReadbackOutcomeV1::Unavailable,
            Self::Unhealthy => DispatchStoreReadbackOutcomeV1::Unhealthy,
        }
    }
}

struct CompleteDispatchGraphV1 {
    receipt: CoordinatorDispatchCommitReceiptV1,
    event_id: [u8; 32],
    canonical_grant: Box<[u8]>,
    canonical_grant_length: u64,
}

impl CompleteDispatchGraphV1 {
    fn matches_exact_attempt_v1(
        &self,
        custody: &CoordinatorDispatchUncertainCommitCustodyV1,
    ) -> bool {
        self.receipt.operation_id == custody.operation_id
            && self.receipt.dispatch_attempt_id == custody.dispatch_attempt_id
            && self.receipt.grant_id == custody.grant_id
            && self.receipt.grant_digest == custody.grant_digest
            && self.receipt.one_shot_nonce == custody.one_shot_nonce
            && self.receipt.transition_generation == custody.transition_generation
            && self.receipt.delivery_generation == custody.delivery_generation
            && self.receipt.event_generation == custody.event_generation
            && self.event_id == custody.event_id
            && self.canonical_grant_length
                == u64::try_from(custody.canonical_grant.len()).unwrap_or(u64::MAX)
            && self.canonical_grant.as_ref() == custody.canonical_grant.as_ref()
            && <[u8; 32]>::from(Sha256::digest(&self.canonical_grant))
                == custody.canonical_grant_sha256
    }

    fn is_coherent_prior_v1(&self, custody: &CoordinatorDispatchUncertainCommitCustodyV1) -> bool {
        self.receipt.operation_id == custody.operation_id
            && self.receipt.dispatch_attempt_id != custody.dispatch_attempt_id
            && !self.canonical_grant.is_empty()
            && self.canonical_grant_length
                == u64::try_from(self.canonical_grant.len()).unwrap_or(u64::MAX)
    }
}

fn load_complete_initial_graph_v1(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<CompleteDispatchGraphV1>, ReadbackErrorV1> {
    let raw = connection
        .query_row(
            "SELECT grant.dispatch_attempt_id, grant.grant_id, grant.grant_digest, \
                    grant.one_shot_nonce, grant.canonical_grant, \
                    grant.canonical_grant_length, transition.state_generation, \
                    outbox.initial_delivery_generation, event.event_generation, event.event_id \
             FROM dispatch_grants AS grant \
             JOIN dispatch_comparisons AS comparison \
               ON comparison.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND comparison.operation_id = grant.operation_id \
             JOIN dispatch_records AS record \
               ON record.operation_id = grant.operation_id \
              AND record.grant_id = grant.grant_id \
              AND record.dispatch_attempt_id = grant.dispatch_attempt_id \
             JOIN dispatch_transitions AS transition \
               ON transition.operation_id = grant.operation_id \
              AND transition.grant_id = grant.grant_id \
              AND transition.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND transition.previous_state = 'PREPARING' \
              AND transition.new_state = 'DISPATCHING' \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = grant.grant_id \
              AND outbox.operation_id = grant.operation_id \
              AND outbox.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND outbox.initial_delivery_generation = record.initial_delivery_generation \
             JOIN dispatch_events AS event \
               ON event.event_id = transition.event_id \
              AND event.operation_id = grant.operation_id \
              AND event.grant_id = grant.grant_id \
              AND event.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND event.transition_generation = transition.state_generation \
              AND event.effective_state = 'DISPATCHING' \
              AND event.event_kind = 'DISPATCHED' \
             WHERE grant.operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(map_query_error_v1)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let canonical_length = safe_u64_v1(raw.5)?;
    if canonical_length != u64::try_from(raw.4.len()).unwrap_or(u64::MAX)
        || raw.4.is_empty()
        || raw.4.len() > 1_048_576
    {
        return Err(ReadbackErrorV1::Unhealthy);
    }
    Ok(Some(CompleteDispatchGraphV1 {
        receipt: CoordinatorDispatchCommitReceiptV1 {
            operation_id: operation_id.to_owned(),
            dispatch_attempt_id: exact_array_v1(raw.0)?,
            grant_id: exact_array_v1(raw.1)?,
            grant_digest: exact_array_v1(raw.2)?,
            one_shot_nonce: exact_array_v1(raw.3)?,
            transition_generation: safe_u64_v1(raw.6)?,
            delivery_generation: safe_u64_v1(raw.7)?,
            event_generation: safe_u64_v1(raw.8)?,
        },
        event_id: exact_array_v1(raw.9)?,
        canonical_grant: raw.4.into_boxed_slice(),
        canonical_grant_length: canonical_length,
    }))
}

fn relevant_footprint_v1(
    connection: &Connection,
    custody: &CoordinatorDispatchUncertainCommitCustodyV1,
) -> Result<i64, ReadbackErrorV1> {
    connection
        .query_row(
            "SELECT \
                 (SELECT COUNT(*) FROM dispatch_comparisons \
                  WHERE dispatch_attempt_id = ?1 OR operation_id = ?2) + \
                 (SELECT COUNT(*) FROM dispatch_grants \
                  WHERE dispatch_attempt_id = ?1 OR operation_id = ?2 OR grant_id = ?3 \
                     OR grant_digest = ?4 OR one_shot_nonce = ?5) + \
                 (SELECT COUNT(*) FROM dispatch_records \
                  WHERE dispatch_attempt_id = ?1 OR operation_id = ?2 OR grant_id = ?3) + \
                 (SELECT COUNT(*) FROM dispatch_transitions \
                  WHERE dispatch_attempt_id = ?1 OR operation_id = ?2 OR grant_id = ?3) + \
                 (SELECT COUNT(*) FROM dispatch_outbox \
                  WHERE dispatch_attempt_id = ?1 OR operation_id = ?2 OR grant_id = ?3) + \
                 (SELECT COUNT(*) FROM dispatch_events \
                  WHERE dispatch_attempt_id = ?1 OR operation_id = ?2 OR grant_id = ?3 \
                     OR event_id = ?6)",
            params![
                custody.dispatch_attempt_id.as_slice(),
                custody.operation_id,
                custody.grant_id.as_slice(),
                custody.grant_digest.as_slice(),
                custody.one_shot_nonce.as_slice(),
                custody.event_id.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(map_query_error_v1)
}

fn exact_array_v1(value: Vec<u8>) -> Result<[u8; 32], ReadbackErrorV1> {
    value.try_into().map_err(|_| ReadbackErrorV1::Unhealthy)
}

fn safe_u64_v1(value: i64) -> Result<u64, ReadbackErrorV1> {
    u64::try_from(value).map_err(|_| ReadbackErrorV1::Unhealthy)
}

fn map_open_error_v1(
    error: rusqlite::Error,
) -> DispatchStoreReadbackOutcomeV1<CoordinatorDispatchCommitReceiptV1> {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy
                    | ErrorCode::DatabaseLocked
                    | ErrorCode::CannotOpen
                    | ErrorCode::ReadOnly
                    | ErrorCode::DiskFull
            ) =>
        {
            DispatchStoreReadbackOutcomeV1::Unavailable
        }
        _ => DispatchStoreReadbackOutcomeV1::Unhealthy,
    }
}

fn map_query_error_v1(error: rusqlite::Error) -> ReadbackErrorV1 {
    match map_open_error_v1(error) {
        DispatchStoreReadbackOutcomeV1::Unavailable => ReadbackErrorV1::Unavailable,
        _ => ReadbackErrorV1::Unhealthy,
    }
}
