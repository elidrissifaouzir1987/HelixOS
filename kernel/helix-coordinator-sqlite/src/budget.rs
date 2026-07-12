//! Private trusted budget-scope provisioning and exact four-dimensional arithmetic.
//!
//! The provisioning seam is crate-private: agent input cannot create an allowance.
//! Reservation and release helpers classify the complete arithmetic vector before any
//! capacity decision so iteration order cannot change the public refusal.

#![allow(dead_code)] // Wired into serialized preparation/failure paths by T045/T047.

use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use rusqlite::{params, Connection, ErrorCode, TransactionBehavior};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BudgetVectorCheckErrorV1 {
    ArithmeticInvalid,
    Exhausted,
}

/// Computes the next held aggregate after validating every arithmetic leaf first.
pub(crate) fn checked_budget_reservation_v1(
    total: [u64; 4],
    held: [u64; 4],
    requested: [u64; 4],
) -> Result<[u64; 4], BudgetVectorCheckErrorV1> {
    let mut remaining = [0_u64; 4];
    let mut next_held = [0_u64; 4];
    for index in 0..4 {
        if total[index] > MAX_SAFE_U64
            || held[index] > MAX_SAFE_U64
            || requested[index] > MAX_SAFE_U64
        {
            return Err(BudgetVectorCheckErrorV1::ArithmeticInvalid);
        }
        remaining[index] = total[index]
            .checked_sub(held[index])
            .ok_or(BudgetVectorCheckErrorV1::ArithmeticInvalid)?;
        next_held[index] = held[index]
            .checked_add(requested[index])
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(BudgetVectorCheckErrorV1::ArithmeticInvalid)?;
    }
    if (0..4).any(|index| requested[index] > remaining[index]) {
        return Err(BudgetVectorCheckErrorV1::Exhausted);
    }
    Ok(next_held)
}

/// Subtracts the exact stored reservation vector once, refusing any underflow.
pub(crate) fn checked_budget_release_v1(
    held: [u64; 4],
    released: [u64; 4],
) -> Result<[u64; 4], BudgetVectorCheckErrorV1> {
    let mut next_held = [0_u64; 4];
    for index in 0..4 {
        if held[index] > MAX_SAFE_U64 || released[index] > MAX_SAFE_U64 {
            return Err(BudgetVectorCheckErrorV1::ArithmeticInvalid);
        }
        next_held[index] = held[index]
            .checked_sub(released[index])
            .ok_or(BudgetVectorCheckErrorV1::ArithmeticInvalid)?;
    }
    Ok(next_held)
}

/// Trusted decoded lease authority used only by maintenance provisioning.
pub(crate) struct TrustedBudgetScopeInputV1<'input> {
    pub(crate) scope_id: Sha256Digest,
    pub(crate) task_lease_digest: Sha256Digest,
    pub(crate) allowance_binding_digest: Sha256Digest,
    pub(crate) scope_generation: u64,
    pub(crate) currency_code: &'input str,
    pub(crate) price_table_id: &'input str,
    pub(crate) total: [u64; 4],
}

impl std::fmt::Debug for TrustedBudgetScopeInputV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedBudgetScopeInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BudgetScopeProvisionOutcomeV1 {
    Created,
    AlreadyExact,
    BindingConflict,
    ArithmeticInvalid,
    Busy,
    Unavailable,
    Unhealthy,
}

/// Provisions one create-only scope and its exact metadata high-water atomically.
pub(crate) fn provision_trusted_budget_scope_v1(
    connection: &mut Connection,
    input: &TrustedBudgetScopeInputV1<'_>,
) -> BudgetScopeProvisionOutcomeV1 {
    if let Err(outcome) = validate_scope_input_v1(input) {
        return outcome;
    }
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return map_sqlite_outcome_v1(&error),
    };

    let metadata = transaction.query_row(
        "SELECT store_generation, budget_generation FROM coordinator_store_meta
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    );
    let (store_generation, budget_generation) = match metadata {
        Ok((store, budget)) => match (safe_i64_v1(store), safe_i64_v1(budget)) {
            (Some(store), Some(budget)) if budget <= store => (store, budget),
            _ => return rollback_outcome_v1(transaction, BudgetScopeProvisionOutcomeV1::Unhealthy),
        },
        Err(_) => {
            return rollback_outcome_v1(transaction, BudgetScopeProvisionOutcomeV1::Unhealthy)
        }
    };

    let candidate_count = match transaction.query_row(
        "SELECT COUNT(*) FROM budget_scopes
         WHERE scope_id = ?1 OR task_lease_digest = ?2
            OR allowance_binding_digest = ?3 OR scope_generation = ?4",
        params![
            input.scope_id.as_bytes().as_slice(),
            input.task_lease_digest.as_bytes().as_slice(),
            input.allowance_binding_digest.as_bytes().as_slice(),
            to_i64_v1(input.scope_generation),
        ],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(count) if count >= 0 => count,
        _ => return rollback_outcome_v1(transaction, BudgetScopeProvisionOutcomeV1::Unhealthy),
    };
    if candidate_count != 0 {
        let exact_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM budget_scopes
                 WHERE scope_id = ?1 AND task_lease_digest = ?2
                   AND allowance_binding_digest = ?3 AND scope_generation = ?4
                   AND currency_code = ?5 AND price_table_id = ?6
                   AND total_cost_micro_units = ?7 AND total_action_count = ?8
                   AND total_egress_bytes = ?9 AND total_recovery_bytes = ?10
                   AND provisioning_profile = 'TRUSTED_LEASE_V1'",
                params![
                    input.scope_id.as_bytes().as_slice(),
                    input.task_lease_digest.as_bytes().as_slice(),
                    input.allowance_binding_digest.as_bytes().as_slice(),
                    to_i64_v1(input.scope_generation),
                    input.currency_code,
                    input.price_table_id,
                    to_i64_v1(input.total[0]),
                    to_i64_v1(input.total[1]),
                    to_i64_v1(input.total[2]),
                    to_i64_v1(input.total[3]),
                ],
                |row| row.get::<_, i64>(0),
            )
            .ok();
        let outcome = if candidate_count == 1 && exact_count == Some(1) {
            if input.scope_generation <= budget_generation {
                BudgetScopeProvisionOutcomeV1::AlreadyExact
            } else {
                BudgetScopeProvisionOutcomeV1::Unhealthy
            }
        } else {
            BudgetScopeProvisionOutcomeV1::BindingConflict
        };
        return rollback_outcome_v1(transaction, outcome);
    }
    if input.scope_generation <= budget_generation {
        return rollback_outcome_v1(transaction, BudgetScopeProvisionOutcomeV1::BindingConflict);
    }
    let next_store_generation = store_generation.max(input.scope_generation);
    let inserted = transaction.execute(
        "INSERT INTO budget_scopes (
             scope_id, task_lease_digest, allowance_binding_digest, scope_generation,
             currency_code, price_table_id, total_cost_micro_units, total_action_count,
             total_egress_bytes, total_recovery_bytes, held_cost_micro_units,
             held_action_count, held_egress_bytes, held_recovery_bytes, provisioning_profile
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, 0, 0, 0,
                   'TRUSTED_LEASE_V1')",
        params![
            input.scope_id.as_bytes().as_slice(),
            input.task_lease_digest.as_bytes().as_slice(),
            input.allowance_binding_digest.as_bytes().as_slice(),
            to_i64_v1(input.scope_generation),
            input.currency_code,
            input.price_table_id,
            to_i64_v1(input.total[0]),
            to_i64_v1(input.total[1]),
            to_i64_v1(input.total[2]),
            to_i64_v1(input.total[3]),
        ],
    );
    if let Err(error) = inserted {
        let outcome = map_sqlite_outcome_v1(&error);
        return rollback_outcome_v1(transaction, outcome);
    }
    let updated = transaction.execute(
        "UPDATE coordinator_store_meta SET store_generation = ?1, budget_generation = ?2
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
           AND store_generation = ?3 AND budget_generation = ?4",
        params![
            to_i64_v1(next_store_generation),
            to_i64_v1(input.scope_generation),
            to_i64_v1(store_generation),
            to_i64_v1(budget_generation),
        ],
    );
    if !matches!(updated, Ok(1)) {
        return rollback_outcome_v1(transaction, BudgetScopeProvisionOutcomeV1::Unhealthy);
    }
    match transaction.commit() {
        Ok(()) => BudgetScopeProvisionOutcomeV1::Created,
        Err(error) => map_sqlite_outcome_v1(&error),
    }
}

fn validate_scope_input_v1(
    input: &TrustedBudgetScopeInputV1<'_>,
) -> Result<(), BudgetScopeProvisionOutcomeV1> {
    if input.scope_generation == 0
        || input.scope_generation > MAX_SAFE_U64
        || input.total.into_iter().any(|value| value > MAX_SAFE_U64)
    {
        return Err(BudgetScopeProvisionOutcomeV1::ArithmeticInvalid);
    }
    let currency = input.currency_code.as_bytes();
    if currency.len() != 3 || !currency.iter().all(u8::is_ascii_uppercase) {
        return Err(BudgetScopeProvisionOutcomeV1::BindingConflict);
    }
    let price = input.price_table_id.as_bytes();
    if price.is_empty()
        || price.len() > 128
        || !price
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':'))
    {
        return Err(BudgetScopeProvisionOutcomeV1::BindingConflict);
    }
    Ok(())
}

fn rollback_outcome_v1(
    transaction: rusqlite::Transaction<'_>,
    outcome: BudgetScopeProvisionOutcomeV1,
) -> BudgetScopeProvisionOutcomeV1 {
    if transaction.rollback().is_ok() {
        outcome
    } else {
        BudgetScopeProvisionOutcomeV1::Unhealthy
    }
}

fn map_sqlite_outcome_v1(error: &rusqlite::Error) -> BudgetScopeProvisionOutcomeV1 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            BudgetScopeProvisionOutcomeV1::Busy
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::CannotOpen | ErrorCode::ReadOnly | ErrorCode::DiskFull
            ) =>
        {
            BudgetScopeProvisionOutcomeV1::Unavailable
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
                && matches!(failure.extended_code, 1_555 | 2_067) =>
        {
            BudgetScopeProvisionOutcomeV1::BindingConflict
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            BudgetScopeProvisionOutcomeV1::Unhealthy
        }
        _ => BudgetScopeProvisionOutcomeV1::Unhealthy,
    }
}

fn to_i64_v1(value: u64) -> i64 {
    debug_assert!(value <= MAX_SAFE_U64);
    value as i64
}

fn safe_i64_v1(value: i64) -> Option<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
}
