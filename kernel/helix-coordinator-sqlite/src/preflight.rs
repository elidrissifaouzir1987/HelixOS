//! Private read-only operation and budget preflight boundary.

#![allow(dead_code)] // T037 wires this crate-private classifier into the public store trait.

use crate::budget::{checked_budget_reservation_v1, BudgetVectorCheckErrorV1};
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use helix_plan_preparation::{
    BudgetPreflightInputV1, BudgetPreflightV1, BudgetVectorInputV1, BudgetVectorV1,
    PreparationPreflightOutcomeV1, PREPARATION_STORE_CONTRACT_VERSION_V1,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::fmt;

/// Scalar-only view assembled by the later store adapter from authenticated inputs.
///
/// Keeping this seam crate-private lets T033 exercise ordering without widening the
/// portable constructors or adding a direct eligibility dependency.
pub(crate) struct CoordinatorPreflightInputV1<'input> {
    pub(crate) operation_id: &'input str,
    pub(crate) attempt_id: Sha256Digest,
    pub(crate) plan_id: Sha256Digest,
    pub(crate) task_id: &'input str,
    pub(crate) workload_id: &'input str,
    pub(crate) reservation_id: &'input str,
    pub(crate) task_lease_digest: Sha256Digest,
    pub(crate) allowance_binding_digest: Sha256Digest,
    pub(crate) scope_generation: u64,
    pub(crate) currency_code: &'input str,
    pub(crate) price_table_id: &'input str,
    pub(crate) requested: [u64; 4],
}

impl fmt::Debug for CoordinatorPreflightInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorPreflightInputV1")
            .finish_non_exhaustive()
    }
}

struct ExistingOperationV1 {
    operation_id: String,
    attempt_id: Vec<u8>,
    plan_id: Vec<u8>,
    task_id: String,
    workload_id: String,
    reservation_id: String,
}

/// Closed result of the operation-first portion of one live preflight snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoordinatorOperationPreflightV1 {
    Absent,
    OperationConflict,
    AlreadyPrepared,
    Unavailable,
}

/// Classifies one already-verified, consistent SQLite snapshot without mutating it.
///
/// The fixed order is operation/attempt/plan identity, exact scope, permanent
/// reservation identity, checked arithmetic, then capacity. Connection/snapshot failures before
/// identity proof are operation-authority failures; failures afterward are budget-
/// authority failures.
pub(crate) fn classify_preflight_snapshot_v1(
    connection: &Connection,
    input: &CoordinatorPreflightInputV1<'_>,
) -> PreparationPreflightOutcomeV1 {
    match classify_preflight_operation_v1(connection, input) {
        CoordinatorOperationPreflightV1::Absent => classify_preflight_budget_v1(connection, input),
        CoordinatorOperationPreflightV1::OperationConflict => {
            PreparationPreflightOutcomeV1::OperationConflict
        }
        CoordinatorOperationPreflightV1::AlreadyPrepared => {
            PreparationPreflightOutcomeV1::AlreadyPrepared
        }
        CoordinatorOperationPreflightV1::Unavailable => {
            PreparationPreflightOutcomeV1::OperationAuthorityUnavailable
        }
    }
}

/// Proves operation/attempt/plan identity before any budget-domain query is issued.
pub(crate) fn classify_preflight_operation_v1(
    connection: &Connection,
    input: &CoordinatorPreflightInputV1<'_>,
) -> CoordinatorOperationPreflightV1 {
    let existing = match query_operation_identity(connection, input) {
        Ok(existing) => existing,
        Err(()) => return CoordinatorOperationPreflightV1::Unavailable,
    };
    if !existing.is_empty() {
        if existing.len() == 1 && is_exact_prior(&existing[0], input) {
            return CoordinatorOperationPreflightV1::AlreadyPrepared;
        }
        return CoordinatorOperationPreflightV1::OperationConflict;
    }
    CoordinatorOperationPreflightV1::Absent
}

/// Classifies scope identity, permanent reservation binding, arithmetic, then capacity.
///
/// The caller must invoke this only after operation identity was proved absent in the
/// same live snapshot. Query failures here are therefore row 30 budget-authority faults.
pub(crate) fn classify_preflight_budget_v1(
    connection: &Connection,
    input: &CoordinatorPreflightInputV1<'_>,
) -> PreparationPreflightOutcomeV1 {
    let lease_scope_count = match connection.query_row(
        "SELECT COUNT(*) FROM budget_scopes WHERE task_lease_digest = ?1",
        [input.task_lease_digest.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(count) if count >= 0 => count,
        _ => return PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable,
    };
    if lease_scope_count == 0 {
        return PreparationPreflightOutcomeV1::BudgetScopeMissing;
    }
    if lease_scope_count != 1 {
        return PreparationPreflightOutcomeV1::BudgetBindingConflict;
    }

    let scope = match query_exact_scope(connection, input) {
        Ok(Some(scope)) => scope,
        Ok(None) => return PreparationPreflightOutcomeV1::BudgetBindingConflict,
        Err(()) => return PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable,
    };
    let reservation_occupied = match connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM budget_reservations WHERE reservation_id = ?1)",
        [input.reservation_id],
        |row| row.get::<_, bool>(0),
    ) {
        Ok(occupied) => occupied,
        Err(_) => return PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable,
    };
    if reservation_occupied {
        return PreparationPreflightOutcomeV1::BudgetBindingConflict;
    }
    let remaining = match checked_remaining(scope.total, scope.held, input.requested) {
        Ok(remaining) => remaining,
        Err(ArithmeticOrCapacityV1::Arithmetic) => {
            return PreparationPreflightOutcomeV1::BudgetArithmeticInvalid
        }
        Err(ArithmeticOrCapacityV1::Capacity) => {
            return PreparationPreflightOutcomeV1::BudgetExhausted
        }
    };
    let observed_remaining = match BudgetVectorV1::try_new(BudgetVectorInputV1 {
        max_cost_micro_units: remaining[0],
        action_limit: remaining[1],
        egress_bytes_limit: remaining[2],
        recovery_bytes: remaining[3],
    }) {
        Ok(vector) => vector,
        Err(_) => return PreparationPreflightOutcomeV1::BudgetArithmeticInvalid,
    };
    match BudgetPreflightV1::try_new(BudgetPreflightInputV1 {
        contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
        observed_scope_generation: input.scope_generation,
        observed_scope_binding_digest: input.allowance_binding_digest,
        observed_remaining,
    }) {
        Ok(preflight) => PreparationPreflightOutcomeV1::Ready(preflight),
        Err(_) => PreparationPreflightOutcomeV1::BudgetArithmeticInvalid,
    }
}

fn query_operation_identity(
    connection: &Connection,
    input: &CoordinatorPreflightInputV1<'_>,
) -> Result<Vec<ExistingOperationV1>, ()> {
    let mut statement = connection
        .prepare(
            "SELECT operation_id, attempt_id, plan_id, task_id, workload_id, reservation_id \
             FROM prepared_operations \
             WHERE operation_id = ?1 OR attempt_id = ?2 OR plan_id = ?3 \
             ORDER BY operation_id LIMIT 2",
        )
        .map_err(|_| ())?;
    let rows = statement
        .query_map(
            params![
                input.operation_id,
                input.attempt_id.as_bytes().as_slice(),
                input.plan_id.as_bytes().as_slice(),
            ],
            |row| {
                Ok(ExistingOperationV1 {
                    operation_id: row.get(0)?,
                    attempt_id: row.get(1)?,
                    plan_id: row.get(2)?,
                    task_id: row.get(3)?,
                    workload_id: row.get(4)?,
                    reservation_id: row.get(5)?,
                })
            },
        )
        .map_err(|_| ())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|_| ())
}

fn is_exact_prior(existing: &ExistingOperationV1, input: &CoordinatorPreflightInputV1<'_>) -> bool {
    existing.operation_id == input.operation_id
        && existing.attempt_id.as_slice() == input.attempt_id.as_bytes()
        && existing.plan_id.as_slice() == input.plan_id.as_bytes()
        && existing.task_id == input.task_id
        && existing.workload_id == input.workload_id
        && existing.reservation_id == input.reservation_id
}

struct ScopeVectorsV1 {
    total: [i64; 4],
    held: [i64; 4],
}

fn query_exact_scope(
    connection: &Connection,
    input: &CoordinatorPreflightInputV1<'_>,
) -> Result<Option<ScopeVectorsV1>, ()> {
    connection
        .query_row(
            "SELECT scope_id, total_cost_micro_units, total_action_count, total_egress_bytes, \
                    total_recovery_bytes, held_cost_micro_units, held_action_count, \
                    held_egress_bytes, held_recovery_bytes \
             FROM budget_scopes \
             WHERE task_lease_digest = ?1 AND allowance_binding_digest = ?2 \
               AND scope_generation = ?3 AND currency_code = ?4 AND price_table_id = ?5",
            params![
                input.task_lease_digest.as_bytes().as_slice(),
                input.allowance_binding_digest.as_bytes().as_slice(),
                i64::try_from(input.scope_generation).map_err(|_| ())?,
                input.currency_code,
                input.price_table_id,
            ],
            |row| {
                let scope_id: Vec<u8> = row.get(0)?;
                if scope_id.len() != 32 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(ScopeVectorsV1 {
                    total: [row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?],
                    held: [row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?],
                })
            },
        )
        .optional()
        .map_err(|_| ())
}

enum ArithmeticOrCapacityV1 {
    Arithmetic,
    Capacity,
}

fn checked_remaining(
    total: [i64; 4],
    held: [i64; 4],
    requested: [u64; 4],
) -> Result<[u64; 4], ArithmeticOrCapacityV1> {
    let mut checked_total = [0_u64; 4];
    let mut checked_held = [0_u64; 4];
    let mut remaining = [0_u64; 4];
    for index in 0..4 {
        checked_total[index] = u64::try_from(total[index])
            .ok()
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(ArithmeticOrCapacityV1::Arithmetic)?;
        checked_held[index] = u64::try_from(held[index])
            .ok()
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(ArithmeticOrCapacityV1::Arithmetic)?;
        if requested[index] > MAX_SAFE_U64 {
            return Err(ArithmeticOrCapacityV1::Arithmetic);
        }
        remaining[index] = checked_total[index]
            .checked_sub(checked_held[index])
            .ok_or(ArithmeticOrCapacityV1::Arithmetic)?;
    }
    match checked_budget_reservation_v1(checked_total, checked_held, requested) {
        Ok(_) => {}
        Err(BudgetVectorCheckErrorV1::ArithmeticInvalid) => {
            return Err(ArithmeticOrCapacityV1::Arithmetic)
        }
        Err(BudgetVectorCheckErrorV1::Exhausted) => return Err(ArithmeticOrCapacityV1::Capacity),
    }
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn input() -> CoordinatorPreflightInputV1<'static> {
        CoordinatorPreflightInputV1 {
            operation_id: "operation:t033",
            attempt_id: digest(1),
            plan_id: digest(2),
            task_id: "task:t033",
            workload_id: "workload:t033",
            reservation_id: "reservation:t033",
            task_lease_digest: digest(3),
            allowance_binding_digest: digest(4),
            scope_generation: 1,
            currency_code: "USD",
            price_table_id: "prices:t033",
            requested: [3, 3, 3, 3],
        }
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("test database opens");
        connection
            .execute_batch(
                "CREATE TABLE prepared_operations (
                     operation_id TEXT PRIMARY KEY,
                     attempt_id BLOB NOT NULL UNIQUE,
                     plan_id BLOB NOT NULL UNIQUE,
                     task_id TEXT NOT NULL,
                     workload_id TEXT NOT NULL,
                     reservation_id TEXT NOT NULL UNIQUE
                 );
                 CREATE TABLE budget_scopes (
                     scope_id BLOB PRIMARY KEY,
                     task_lease_digest BLOB NOT NULL,
                     allowance_binding_digest BLOB NOT NULL,
                     scope_generation INTEGER NOT NULL,
                     currency_code TEXT NOT NULL,
                     price_table_id TEXT NOT NULL,
                     total_cost_micro_units INTEGER NOT NULL,
                     total_action_count INTEGER NOT NULL,
                     total_egress_bytes INTEGER NOT NULL,
                     total_recovery_bytes INTEGER NOT NULL,
                     held_cost_micro_units INTEGER NOT NULL,
                     held_action_count INTEGER NOT NULL,
                     held_egress_bytes INTEGER NOT NULL,
                     held_recovery_bytes INTEGER NOT NULL
                 );
                 CREATE TABLE budget_reservations (
                     reservation_id TEXT PRIMARY KEY
                 );",
            )
            .expect("test schema creates");
        connection
    }

    fn insert_operation(connection: &Connection, input: &CoordinatorPreflightInputV1<'_>) {
        connection
            .execute(
                "INSERT INTO prepared_operations VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    input.operation_id,
                    input.attempt_id.as_bytes().as_slice(),
                    input.plan_id.as_bytes().as_slice(),
                    input.task_id,
                    input.workload_id,
                    input.reservation_id,
                ],
            )
            .expect("operation fixture inserts");
    }

    fn insert_scope(connection: &Connection, input: &CoordinatorPreflightInputV1<'_>, held: i64) {
        connection
            .execute(
                "INSERT INTO budget_scopes VALUES (?1, ?2, ?3, ?4, ?5, ?6,
                     10, 10, 10, 10, ?7, ?7, ?7, ?7)",
                params![
                    digest(5).as_bytes().as_slice(),
                    input.task_lease_digest.as_bytes().as_slice(),
                    input.allowance_binding_digest.as_bytes().as_slice(),
                    input.scope_generation as i64,
                    input.currency_code,
                    input.price_table_id,
                    held,
                ],
            )
            .expect("scope fixture inserts");
    }

    fn assert_read_only(
        connection: &Connection,
        input: &CoordinatorPreflightInputV1<'_>,
        expected: fn(&PreparationPreflightOutcomeV1) -> bool,
    ) {
        let changes = connection.total_changes();
        let outcome = classify_preflight_snapshot_v1(connection, input);
        assert!(expected(&outcome), "unexpected outcome: {outcome:?}");
        assert_eq!(
            connection.total_changes(),
            changes,
            "preflight mutated state"
        );
    }

    #[test]
    fn operation_failure_conflict_and_prior_win_before_budget_queries() {
        let missing_schema = Connection::open_in_memory().expect("database opens");
        assert_read_only(&missing_schema, &input(), |outcome| {
            matches!(
                outcome,
                PreparationPreflightOutcomeV1::OperationAuthorityUnavailable
            )
        });

        let conflict_connection = connection();
        let mut conflict = input();
        conflict.task_id = "task:conflict";
        insert_operation(&conflict_connection, &input());
        conflict_connection
            .execute("DROP TABLE budget_scopes", [])
            .expect("budget table drops");
        assert_read_only(&conflict_connection, &conflict, |outcome| {
            matches!(outcome, PreparationPreflightOutcomeV1::OperationConflict)
        });

        let prior_connection = connection();
        insert_operation(&prior_connection, &input());
        prior_connection
            .execute("DROP TABLE budget_scopes", [])
            .expect("budget table drops");
        assert_read_only(&prior_connection, &input(), |outcome| {
            matches!(outcome, PreparationPreflightOutcomeV1::AlreadyPrepared)
        });

        let attempt_conflict_connection = connection();
        insert_operation(&attempt_conflict_connection, &input());
        let mut conflicting_attempt = input();
        conflicting_attempt.attempt_id = digest(9);
        assert_read_only(
            &attempt_conflict_connection,
            &conflicting_attempt,
            |outcome| matches!(outcome, PreparationPreflightOutcomeV1::OperationConflict),
        );
    }

    #[test]
    fn budget_order_is_scope_binding_arithmetic_then_capacity_and_is_read_only() {
        let missing = connection();
        assert_read_only(&missing, &input(), |outcome| {
            matches!(outcome, PreparationPreflightOutcomeV1::BudgetScopeMissing)
        });

        let binding = connection();
        let exact = input();
        let mut stored = input();
        stored.allowance_binding_digest = digest(9);
        insert_scope(&binding, &stored, 0);
        assert_read_only(&binding, &exact, |outcome| {
            matches!(
                outcome,
                PreparationPreflightOutcomeV1::BudgetBindingConflict
            )
        });

        let arithmetic = connection();
        insert_scope(&arithmetic, &input(), 11);
        assert_read_only(&arithmetic, &input(), |outcome| {
            matches!(
                outcome,
                PreparationPreflightOutcomeV1::BudgetArithmeticInvalid
            )
        });

        let capacity = connection();
        insert_scope(&capacity, &input(), 8);
        assert_read_only(&capacity, &input(), |outcome| {
            matches!(outcome, PreparationPreflightOutcomeV1::BudgetExhausted)
        });

        let ready = connection();
        insert_scope(&ready, &input(), 7);
        assert_read_only(&ready, &input(), |outcome| match outcome {
            PreparationPreflightOutcomeV1::Ready(receipt) => {
                receipt.observed_scope_generation() == 1
                    && receipt.observed_scope_binding_digest() == digest(4)
                    && receipt.observed_remaining().max_cost_micro_units() == 3
                    && receipt.observed_remaining().action_limit() == 3
                    && receipt.observed_remaining().egress_bytes_limit() == 3
                    && receipt.observed_remaining().recovery_bytes() == 3
            }
            _ => false,
        });
    }

    #[test]
    fn operation_absence_is_proved_before_budget_authority_failure() {
        let connection = connection();
        connection
            .execute("DROP TABLE budget_scopes", [])
            .expect("budget table drops");
        assert_eq!(
            classify_preflight_operation_v1(&connection, &input()),
            CoordinatorOperationPreflightV1::Absent
        );
        assert_read_only(&connection, &input(), |outcome| {
            matches!(
                outcome,
                PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable
            )
        });
    }

    #[test]
    fn incompatible_reservation_reuse_is_a_budget_binding_conflict() {
        let connection = connection();
        insert_scope(&connection, &input(), 0);
        connection
            .execute(
                "INSERT INTO budget_reservations (reservation_id) VALUES (?1)",
                [input().reservation_id],
            )
            .expect("occupied reservation inserts");
        assert_eq!(
            classify_preflight_operation_v1(&connection, &input()),
            CoordinatorOperationPreflightV1::Absent
        );
        assert_read_only(&connection, &input(), |outcome| {
            matches!(
                outcome,
                PreparationPreflightOutcomeV1::BudgetBindingConflict
            )
        });
    }
}
