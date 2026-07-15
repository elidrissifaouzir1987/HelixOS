//! Exact retained initial dispatch outbox member.

#![allow(dead_code)] // Initial staging is wired by T033; handoff loading is used by T064.

use crate::clock::read_safe_now;
use crate::connection::open_bound_existing_connection;
#[cfg(feature = "test-fault-injection")]
use crate::dispatch_fault::FaultBoundaryV1;
use crate::dispatch_schema::{verify_dispatch_schema_v2, SqliteCoordinatorStoreV2};
use helix_contracts::Ed25519KeyResolver;
#[cfg(not(feature = "test-fault-injection"))]
use helix_plan_dispatch::handoff_exact_grant_once_v1;
#[cfg(feature = "test-fault-injection")]
use helix_plan_dispatch::handoff_exact_grant_once_with_fault_probe_v1;
use helix_plan_dispatch::{
    DispatchHandoffOutcomeV1, DispatchHandoffValidationV1, DispatchTransportV1,
};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};
use std::fmt;

pub(crate) struct DispatchOutboxRowV1<'row> {
    pub(crate) grant_id: &'row [u8; 32],
    pub(crate) operation_id: &'row str,
    pub(crate) dispatch_attempt_id: &'row [u8; 32],
    pub(crate) initial_delivery_generation: i64,
    pub(crate) deadline_monotonic_ms: i64,
}

impl fmt::Debug for DispatchOutboxRowV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchOutboxRowV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn stage_pending_dispatch_outbox_v1(
    transaction: &Transaction<'_>,
    row: DispatchOutboxRowV1<'_>,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO dispatch_outbox (\
             grant_id, operation_id, dispatch_attempt_id, initial_delivery_generation, \
             delivery_state, delivery_generation, current_attempt_generation, receipt_id, \
             receipt_decision, deadline_monotonic_ms\
         ) VALUES (?1, ?2, ?3, ?4, 'PENDING', ?4, NULL, NULL, NULL, ?5)",
        params![
            row.grant_id.as_slice(),
            row.operation_id,
            row.dispatch_attempt_id.as_slice(),
            row.initial_delivery_generation,
            row.deadline_monotonic_ms,
        ],
    )?;
    Ok(())
}

/// Exact bytes and identity loaded from the durable grant/outbox join.
///
/// This is storage custody, not reconstructed authority. Diagnostics deliberately omit
/// every field and the byte buffer is never exposed through `Debug`.
pub(crate) struct RetainedDispatchOutboxV1 {
    pub(crate) grant_id: [u8; 32],
    pub(crate) operation_id: String,
    pub(crate) dispatch_attempt_id: [u8; 32],
    pub(crate) one_shot_nonce: [u8; 32],
    pub(crate) grant_digest: [u8; 32],
    pub(crate) canonical_grant: Box<[u8]>,
    pub(crate) initial_delivery_generation: u64,
    pub(crate) delivery_generation: u64,
    pub(crate) current_attempt_generation: Option<u64>,
    pub(crate) deadline_monotonic_ms: u64,
    pub(crate) delivery_state: Box<str>,
    pub(crate) effective_state: Box<str>,
}

impl fmt::Debug for RetainedDispatchOutboxV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedDispatchOutboxV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchOutboxLoadErrorV1 {
    Conflict,
    Unavailable,
    Unhealthy,
}

/// Loads the original signed envelope byte-for-byte; it never rebuilds authority.
pub(crate) fn load_exact_dispatch_outbox_v1(
    connection: &Connection,
    grant_id: &[u8; 32],
) -> Result<Option<RetainedDispatchOutboxV1>, DispatchOutboxLoadErrorV1> {
    let raw = connection
        .query_row(
            "SELECT grant.grant_id, grant.operation_id, grant.dispatch_attempt_id, \
                    grant.one_shot_nonce, grant.grant_digest, grant.canonical_grant, \
                    grant.canonical_grant_length, outbox.initial_delivery_generation, \
                    outbox.deadline_monotonic_ms, outbox.delivery_state, \
                    record.effective_state, outbox.delivery_generation, \
                    outbox.current_attempt_generation \
             FROM dispatch_grants AS grant \
             JOIN dispatch_records AS record \
               ON record.operation_id = grant.operation_id \
              AND record.grant_id = grant.grant_id \
              AND record.dispatch_attempt_id = grant.dispatch_attempt_id \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = grant.grant_id \
              AND outbox.operation_id = grant.operation_id \
              AND outbox.dispatch_attempt_id = grant.dispatch_attempt_id \
             WHERE grant.grant_id = ?1",
            [grant_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                ))
            },
        )
        .optional()
        .map_err(map_load_error_v1)?;
    let Some(raw) = raw else {
        let footprint: i64 = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM dispatch_grants WHERE grant_id = ?1) + \
                        (SELECT COUNT(*) FROM dispatch_outbox WHERE grant_id = ?1)",
                [grant_id.as_slice()],
                |row| row.get(0),
            )
            .map_err(map_load_error_v1)?;
        return if footprint == 0 {
            Ok(None)
        } else {
            Err(DispatchOutboxLoadErrorV1::Conflict)
        };
    };
    let exact_length = usize::try_from(raw.6).ok() == Some(raw.5.len());
    if raw.0.as_slice() != grant_id
        || !exact_length
        || raw.5.is_empty()
        || raw.5.len() > 1_048_576
        || !matches!(raw.9.as_str(), "PENDING" | "HANDED_OFF" | "UNKNOWN")
        || !matches!(
            raw.10.as_str(),
            "DISPATCHING" | "OUTCOME_UNKNOWN" | "RECONCILIATION_REQUIRED"
        )
    {
        return Err(DispatchOutboxLoadErrorV1::Conflict);
    }
    Ok(Some(RetainedDispatchOutboxV1 {
        grant_id: exact_array_v1(raw.0)?,
        operation_id: raw.1,
        dispatch_attempt_id: exact_array_v1(raw.2)?,
        one_shot_nonce: exact_array_v1(raw.3)?,
        grant_digest: exact_array_v1(raw.4)?,
        canonical_grant: raw.5.into_boxed_slice(),
        initial_delivery_generation: safe_u64_v1(raw.7)?,
        deadline_monotonic_ms: safe_u64_v1(raw.8)?,
        delivery_state: raw.9.into_boxed_str(),
        effective_state: raw.10.into_boxed_str(),
        delivery_generation: safe_u64_v1(raw.11)?,
        current_attempt_generation: raw.12.map(safe_u64_v1).transpose()?,
    }))
}

/// Closed coordinator result for one first, exact retained outbox handoff.
pub enum CoordinatorDispatchHandoffOutcomeV1<R> {
    Acknowledged(R),
    ConfirmedNoSend,
    PossibleHandoff,
    PausedBeforeHandoff,
    DeadlineReachedBeforeHandoff,
    NotFound,
    Conflict,
    Unavailable,
    Unhealthy,
}

impl<R> fmt::Debug for CoordinatorDispatchHandoffOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acknowledged(_) => "CoordinatorDispatchHandoffOutcomeV1::Acknowledged(..)",
            Self::ConfirmedNoSend => "CoordinatorDispatchHandoffOutcomeV1::ConfirmedNoSend",
            Self::PossibleHandoff => "CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff",
            Self::PausedBeforeHandoff => "CoordinatorDispatchHandoffOutcomeV1::PausedBeforeHandoff",
            Self::DeadlineReachedBeforeHandoff => {
                "CoordinatorDispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff"
            }
            Self::NotFound => "CoordinatorDispatchHandoffOutcomeV1::NotFound",
            Self::Conflict => "CoordinatorDispatchHandoffOutcomeV1::Conflict",
            Self::Unavailable => "CoordinatorDispatchHandoffOutcomeV1::Unavailable",
            Self::Unhealthy => "CoordinatorDispatchHandoffOutcomeV1::Unhealthy",
        })
    }
}

impl<C, R> SqliteCoordinatorStoreV2<C, R>
where
    C: crate::CoordinatorMonotonicClockV1,
    R: Ed25519KeyResolver,
{
    /// Loads and hands off the exact retained grant after durable possible-handoff evidence.
    ///
    /// Only a current `PENDING`/`DISPATCHING` member can start its first handoff. The
    /// SQLite writer closes before transport is invoked; the root/file lease and the
    /// transport guard remain held across the evidence-to-handoff boundary.
    pub fn handoff_pending_dispatch_v1<T>(
        &self,
        grant_id: [u8; 32],
        caller_deadline_monotonic_ms: u64,
        transport: &T,
    ) -> CoordinatorDispatchHandoffOutcomeV1<T::Response>
    where
        T: DispatchTransportV1,
    {
        let base = self.base_store_v1();
        let mut bound = match open_bound_existing_connection(
            &base.config,
            &base.clock,
            caller_deadline_monotonic_ms,
        ) {
            Ok(bound) => bound,
            Err(_) => return CoordinatorDispatchHandoffOutcomeV1::Unavailable,
        };
        let expected_root = bound.expected_root_identity();
        if verify_dispatch_schema_v2(
            bound.connection_mut(),
            expected_root,
            &base.historical_plan_keys,
        )
        .is_err()
        {
            return CoordinatorDispatchHandoffOutcomeV1::Unhealthy;
        }
        let retained = match load_exact_dispatch_outbox_v1(bound.connection_mut(), &grant_id) {
            Ok(Some(retained)) => retained,
            Ok(None) => return CoordinatorDispatchHandoffOutcomeV1::NotFound,
            Err(DispatchOutboxLoadErrorV1::Conflict) => {
                return CoordinatorDispatchHandoffOutcomeV1::Conflict
            }
            Err(DispatchOutboxLoadErrorV1::Unavailable) => {
                return CoordinatorDispatchHandoffOutcomeV1::Unavailable
            }
            Err(DispatchOutboxLoadErrorV1::Unhealthy) => {
                return CoordinatorDispatchHandoffOutcomeV1::Unhealthy
            }
        };
        #[cfg(feature = "test-fault-injection")]
        if self
            .dispatch_fault_probe_v1()
            .injected_at_v1(FaultBoundaryV1::Plan005Fb018)
        {
            return CoordinatorDispatchHandoffOutcomeV1::Unavailable;
        }
        if retained.delivery_state.as_ref() != "PENDING"
            || retained.effective_state.as_ref() != "DISPATCHING"
            || retained.current_attempt_generation.is_some()
        {
            return CoordinatorDispatchHandoffOutcomeV1::Conflict;
        }
        let now = match read_safe_now(&base.clock) {
            Ok(now) => now,
            Err(_) => return CoordinatorDispatchHandoffOutcomeV1::Unavailable,
        };
        let effective_deadline = retained
            .deadline_monotonic_ms
            .min(caller_deadline_monotonic_ms);
        let commit_possible_handoff_evidence = |handoff_guard_digest| {
            bound
                .arm_next_writer_wait_v1(&base.clock, effective_deadline)
                .map_err(|_| DispatchHandoffValidationV1::Unavailable)?;
            commit_possible_handoff_attempt_v1(
                bound.connection_mut(),
                &retained,
                handoff_guard_digest,
                |connection| {
                    verify_dispatch_schema_v2(connection, expected_root, &base.historical_plan_keys)
                        .is_ok()
                },
            )
            .map_err(|error| match error {
                DispatchOutboxLoadErrorV1::Conflict | DispatchOutboxLoadErrorV1::Unhealthy => {
                    DispatchHandoffValidationV1::Revoked
                }
                DispatchOutboxLoadErrorV1::Unavailable => DispatchHandoffValidationV1::Unavailable,
            })
        };
        let sample_now_after_evidence = || {
            #[cfg(feature = "test-fault-injection")]
            if self
                .dispatch_fault_probe_v1()
                .injected_at_v1(FaultBoundaryV1::Plan005Fb020)
            {
                return Err(DispatchHandoffValidationV1::Unavailable);
            }
            read_safe_now(&base.clock).map_err(|_| DispatchHandoffValidationV1::Unavailable)
        };
        #[cfg(not(feature = "test-fault-injection"))]
        let outcome = handoff_exact_grant_once_v1(
            transport,
            &retained.grant_id,
            &retained.canonical_grant,
            now,
            effective_deadline,
            commit_possible_handoff_evidence,
            sample_now_after_evidence,
        );
        #[cfg(feature = "test-fault-injection")]
        let outcome = {
            let fault_probe = self.dispatch_fault_probe_v1().portable_probe_v1();
            handoff_exact_grant_once_with_fault_probe_v1(
                transport,
                &retained.grant_id,
                &retained.canonical_grant,
                now,
                effective_deadline,
                commit_possible_handoff_evidence,
                sample_now_after_evidence,
                &fault_probe,
            )
        };
        if bound
            .revalidate(&base.clock, caller_deadline_monotonic_ms)
            .is_err()
            && !matches!(outcome, DispatchHandoffOutcomeV1::PossibleHandoff)
        {
            return CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff;
        }
        map_handoff_outcome_v1(outcome)
    }
}

fn commit_possible_handoff_attempt_v1<F>(
    connection: &mut Connection,
    retained: &RetainedDispatchOutboxV1,
    handoff_guard_digest: [u8; 32],
    verify_live_snapshot: F,
) -> Result<(), DispatchOutboxLoadErrorV1>
where
    F: FnOnce(&Connection) -> bool,
{
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_load_error_v1)?;
    if !verify_live_snapshot(&transaction) {
        return rollback_attempt_v1(transaction, DispatchOutboxLoadErrorV1::Unhealthy);
    }
    let current = load_exact_dispatch_outbox_v1(&transaction, &retained.grant_id)?
        .ok_or(DispatchOutboxLoadErrorV1::Conflict)?;
    if current.operation_id != retained.operation_id
        || current.dispatch_attempt_id != retained.dispatch_attempt_id
        || current.one_shot_nonce != retained.one_shot_nonce
        || current.grant_digest != retained.grant_digest
        || current.canonical_grant != retained.canonical_grant
        || current.initial_delivery_generation != retained.initial_delivery_generation
        || current.delivery_generation != retained.delivery_generation
        || current.deadline_monotonic_ms != retained.deadline_monotonic_ms
        || current.delivery_state.as_ref() != "PENDING"
        || current.effective_state.as_ref() != "DISPATCHING"
        || current.current_attempt_generation.is_some()
    {
        return rollback_attempt_v1(transaction, DispatchOutboxLoadErrorV1::Conflict);
    }

    let (store_generation, delivery_generation): (i64, i64) = transaction
        .query_row(
            "SELECT dispatch_store_generation, delivery_generation \
             FROM dispatch_store_meta WHERE singleton = 1 \
               AND root_lifecycle_state = 'ACTIVE'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_load_error_v1)?;
    let attempt_generation = next_generation_v1(store_generation)?;
    if delivery_generation != i64::try_from(retained.delivery_generation).unwrap_or(-1) {
        return rollback_attempt_v1(transaction, DispatchOutboxLoadErrorV1::Conflict);
    }
    let attempt_number: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(attempt_number), 0) + 1 \
             FROM dispatch_delivery_attempts WHERE grant_id = ?1",
            [retained.grant_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(map_load_error_v1)?;
    if !(1..=9_007_199_254_740_991_i64).contains(&attempt_number) {
        return rollback_attempt_v1(transaction, DispatchOutboxLoadErrorV1::Unhealthy);
    }
    transaction
        .execute(
            "INSERT INTO dispatch_delivery_attempts (\
                 attempt_generation, grant_id, operation_id, dispatch_attempt_id, \
                 attempt_number, handoff_guard_digest, classification, adapter_root_digest, \
                 adapter_epoch, readback_generation\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'POSSIBLE_HANDOFF', NULL, NULL, NULL)",
            params![
                attempt_generation,
                retained.grant_id.as_slice(),
                retained.operation_id,
                retained.dispatch_attempt_id.as_slice(),
                attempt_number,
                handoff_guard_digest.as_slice(),
            ],
        )
        .map_err(map_load_error_v1)?;
    let changed = transaction
        .execute(
            "UPDATE dispatch_outbox \
             SET delivery_state = 'HANDED_OFF', delivery_generation = ?1, \
                 current_attempt_generation = ?1 \
             WHERE grant_id = ?2 AND operation_id = ?3 AND dispatch_attempt_id = ?4 \
               AND delivery_state = 'PENDING' AND delivery_generation = ?5 \
               AND current_attempt_generation IS NULL AND deadline_monotonic_ms = ?6",
            params![
                attempt_generation,
                retained.grant_id.as_slice(),
                retained.operation_id,
                retained.dispatch_attempt_id.as_slice(),
                i64::try_from(retained.delivery_generation)
                    .map_err(|_| DispatchOutboxLoadErrorV1::Unhealthy)?,
                i64::try_from(retained.deadline_monotonic_ms)
                    .map_err(|_| DispatchOutboxLoadErrorV1::Unhealthy)?,
            ],
        )
        .map_err(map_load_error_v1)?;
    if changed != 1 {
        return rollback_attempt_v1(transaction, DispatchOutboxLoadErrorV1::Conflict);
    }
    let changed = transaction
        .execute(
            "UPDATE dispatch_store_meta \
             SET dispatch_store_generation = ?1, delivery_generation = ?1 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND dispatch_store_generation = ?2 AND delivery_generation = ?3",
            params![attempt_generation, store_generation, delivery_generation],
        )
        .map_err(map_load_error_v1)?;
    if changed != 1 {
        return rollback_attempt_v1(transaction, DispatchOutboxLoadErrorV1::Conflict);
    }
    transaction.commit().map_err(map_load_error_v1)
}

fn rollback_attempt_v1<T>(
    transaction: Transaction<'_>,
    error: DispatchOutboxLoadErrorV1,
) -> Result<T, DispatchOutboxLoadErrorV1> {
    if transaction.rollback().is_ok() {
        Err(error)
    } else {
        Err(DispatchOutboxLoadErrorV1::Unhealthy)
    }
}

fn next_generation_v1(current: i64) -> Result<i64, DispatchOutboxLoadErrorV1> {
    current
        .checked_add(1)
        .filter(|value| (1..=9_007_199_254_740_991_i64).contains(value))
        .ok_or(DispatchOutboxLoadErrorV1::Unhealthy)
}

fn map_handoff_outcome_v1<R>(
    outcome: DispatchHandoffOutcomeV1<R>,
) -> CoordinatorDispatchHandoffOutcomeV1<R> {
    match outcome {
        DispatchHandoffOutcomeV1::Acknowledged(response) => {
            CoordinatorDispatchHandoffOutcomeV1::Acknowledged(response)
        }
        DispatchHandoffOutcomeV1::ConfirmedNoSend => {
            CoordinatorDispatchHandoffOutcomeV1::ConfirmedNoSend
        }
        DispatchHandoffOutcomeV1::PossibleHandoff => {
            CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
        }
        DispatchHandoffOutcomeV1::PausedBeforeHandoff => {
            CoordinatorDispatchHandoffOutcomeV1::PausedBeforeHandoff
        }
        DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff => {
            CoordinatorDispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff
        }
        DispatchHandoffOutcomeV1::UnavailableBeforeHandoff => {
            CoordinatorDispatchHandoffOutcomeV1::Unavailable
        }
    }
}

fn exact_array_v1(value: Vec<u8>) -> Result<[u8; 32], DispatchOutboxLoadErrorV1> {
    value
        .try_into()
        .map_err(|_| DispatchOutboxLoadErrorV1::Unhealthy)
}

fn safe_u64_v1(value: i64) -> Result<u64, DispatchOutboxLoadErrorV1> {
    u64::try_from(value).map_err(|_| DispatchOutboxLoadErrorV1::Unhealthy)
}

fn map_load_error_v1(error: rusqlite::Error) -> DispatchOutboxLoadErrorV1 {
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
            DispatchOutboxLoadErrorV1::Unavailable
        }
        _ => DispatchOutboxLoadErrorV1::Unhealthy,
    }
}
