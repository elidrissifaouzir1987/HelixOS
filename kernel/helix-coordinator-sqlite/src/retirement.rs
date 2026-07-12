//! Private guarded recovery-retirement boundary.

#[cfg(test)]
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
#[cfg(test)]
use helix_plan_preparation::RecoveryCleanupGuardV1;
#[cfg(test)]
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

#[cfg(all(test, feature = "test-fault-injection"))]
pub(crate) type RetirementFaultProbeV1 = crate::test_fault::FaultProbeV1;

#[cfg(all(test, not(feature = "test-fault-injection")))]
#[derive(Clone, Copy, Default)]
pub(crate) struct RetirementFaultProbeV1;

#[cfg(all(test, not(feature = "test-fault-injection")))]
impl RetirementFaultProbeV1 {
    const fn disabled_v1() -> Self {
        Self
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) struct SyntheticOperationRetirementInputV1<'input> {
    pub(crate) operation_id: &'input str,
    pub(crate) retirement_id: Sha256Digest,
    pub(crate) retirement_manifest_digest: Option<Sha256Digest>,
}

#[cfg(test)]
impl std::fmt::Debug for SyntheticOperationRetirementInputV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyntheticOperationRetirementInputV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) struct SyntheticOrphanRetirementInputV1 {
    pub(crate) quarantine_id: Sha256Digest,
    pub(crate) retirement_id: Sha256Digest,
    pub(crate) retirement_manifest_digest: Sha256Digest,
}

#[cfg(test)]
impl std::fmt::Debug for SyntheticOrphanRetirementInputV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyntheticOrphanRetirementInputV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticRetirementStepV1 {
    BeginPending,
    FinishTombstone,
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticRetirementOutcomeV1 {
    NotEligible,
    Pending,
    Retired,
    AlreadyRetired,
    Conflict,
    Unavailable,
    Unhealthy,
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) fn retire_synthetic_operation_bound_v1<G: RecoveryCleanupGuardV1>(
    connection: &mut Connection,
    input: &SyntheticOperationRetirementInputV1<'_>,
    step: SyntheticRetirementStepV1,
    cleanup_guard: &mut G,
) -> SyntheticRetirementOutcomeV1 {
    retire_synthetic_operation_bound_with_fault_probe_v1(
        connection,
        input,
        step,
        cleanup_guard,
        &RetirementFaultProbeV1::disabled_v1(),
    )
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the source-included T074 process driver.
pub(crate) fn retire_synthetic_operation_bound_with_fault_probe_v1<G: RecoveryCleanupGuardV1>(
    connection: &mut Connection,
    input: &SyntheticOperationRetirementInputV1<'_>,
    step: SyntheticRetirementStepV1,
    cleanup_guard: &mut G,
    fault_probe: &RetirementFaultProbeV1,
) -> SyntheticRetirementOutcomeV1 {
    let _retained_cleanup_custody = cleanup_guard;
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(_) => return SyntheticRetirementOutcomeV1::Unavailable,
    };
    let row = transaction
        .query_row(
            "SELECT operation.operation_state, reservation.reservation_state, \
                    recovery.recovery_mode, recovery.material_state, \
                    recovery.retirement_id, recovery.retirement_manifest_digest \
             FROM prepared_operations AS operation \
             JOIN budget_reservations AS reservation \
               ON reservation.operation_id = operation.operation_id \
             JOIN preparation_recovery_evidence AS recovery \
               ON recovery.operation_id = operation.operation_id \
             WHERE operation.operation_id = ?1",
            [input.operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional();
    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return rollback_operation_outcome_v1(
                transaction,
                SyntheticRetirementOutcomeV1::NotEligible,
            )
        }
        Err(_) => {
            return rollback_operation_outcome_v1(
                transaction,
                SyntheticRetirementOutcomeV1::Unhealthy,
            )
        }
    };
    if row.2 != "COMPENSATION" {
        return rollback_operation_outcome_v1(
            transaction,
            SyntheticRetirementOutcomeV1::NotEligible,
        );
    }
    let exact_retirement_id = row.4.as_deref() == Some(input.retirement_id.as_bytes().as_slice());
    match step {
        SyntheticRetirementStepV1::BeginPending => {
            if input.retirement_manifest_digest.is_some() {
                return rollback_operation_outcome_v1(
                    transaction,
                    SyntheticRetirementOutcomeV1::Conflict,
                );
            }
            match row.3.as_deref() {
                Some("RETIREMENT_PENDING") if exact_retirement_id => {
                    return rollback_operation_outcome_v1(
                        transaction,
                        SyntheticRetirementOutcomeV1::Pending,
                    )
                }
                Some("RETIRED_TOMBSTONE") if exact_retirement_id => {
                    return rollback_operation_outcome_v1(
                        transaction,
                        SyntheticRetirementOutcomeV1::AlreadyRetired,
                    )
                }
                Some("PUBLISHED") => {}
                _ => {
                    return rollback_operation_outcome_v1(
                        transaction,
                        SyntheticRetirementOutcomeV1::Conflict,
                    )
                }
            }
            if row.0 != "FAILED" || row.1 != "RELEASED" {
                return rollback_operation_outcome_v1(
                    transaction,
                    SyntheticRetirementOutcomeV1::NotEligible,
                );
            }
            let next = match next_store_generation_v1(&transaction) {
                Ok(next) => next,
                Err(outcome) => return rollback_operation_outcome_v1(transaction, outcome),
            };
            let updated = transaction.execute(
                "UPDATE preparation_recovery_evidence SET \
                     material_state = 'RETIREMENT_PENDING', retirement_id = ?1, \
                     retirement_generation = ?2 \
                 WHERE operation_id = ?3 AND recovery_mode = 'COMPENSATION' \
                   AND material_state = 'PUBLISHED' AND retirement_id IS NULL \
                   AND retirement_manifest_digest IS NULL AND retirement_generation IS NULL",
                params![
                    input.retirement_id.as_bytes().as_slice(),
                    to_i64_v1(next),
                    input.operation_id,
                ],
            );
            if !matches!(updated, Ok(1)) || !advance_store_generation_v1(&transaction, next) {
                return rollback_operation_outcome_v1(
                    transaction,
                    SyntheticRetirementOutcomeV1::Unhealthy,
                );
            }
            if transaction.commit().is_err() {
                return SyntheticRetirementOutcomeV1::Unavailable;
            }
            reach_operation_retirement_pending(fault_probe);
            SyntheticRetirementOutcomeV1::Pending
        }
        SyntheticRetirementStepV1::FinishTombstone => {
            let Some(retirement_manifest_digest) = input.retirement_manifest_digest else {
                return rollback_operation_outcome_v1(
                    transaction,
                    SyntheticRetirementOutcomeV1::Conflict,
                );
            };
            match row.3.as_deref() {
                Some("RETIRED_TOMBSTONE")
                    if exact_retirement_id
                        && row.5.as_deref()
                            == Some(retirement_manifest_digest.as_bytes().as_slice()) =>
                {
                    return rollback_operation_outcome_v1(
                        transaction,
                        SyntheticRetirementOutcomeV1::AlreadyRetired,
                    )
                }
                Some("RETIREMENT_PENDING") if exact_retirement_id => {}
                _ => {
                    return rollback_operation_outcome_v1(
                        transaction,
                        SyntheticRetirementOutcomeV1::Conflict,
                    )
                }
            }
            let next = match next_store_generation_v1(&transaction) {
                Ok(next) => next,
                Err(outcome) => return rollback_operation_outcome_v1(transaction, outcome),
            };
            let updated = transaction.execute(
                "UPDATE preparation_recovery_evidence SET \
                     material_state = 'RETIRED_TOMBSTONE', \
                     retirement_manifest_digest = ?1, retirement_generation = ?2 \
                 WHERE operation_id = ?3 AND material_state = 'RETIREMENT_PENDING' \
                   AND retirement_id = ?4 AND retirement_manifest_digest IS NULL",
                params![
                    retirement_manifest_digest.as_bytes().as_slice(),
                    to_i64_v1(next),
                    input.operation_id,
                    input.retirement_id.as_bytes().as_slice(),
                ],
            );
            if !matches!(updated, Ok(1)) || !advance_store_generation_v1(&transaction, next) {
                return rollback_operation_outcome_v1(
                    transaction,
                    SyntheticRetirementOutcomeV1::Unhealthy,
                );
            }
            if transaction.commit().is_err() {
                return SyntheticRetirementOutcomeV1::Unavailable;
            }
            reach_operation_retired(fault_probe);
            SyntheticRetirementOutcomeV1::Retired
        }
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) fn retire_synthetic_orphan_v1<G: RecoveryCleanupGuardV1>(
    connection: &mut Connection,
    input: &SyntheticOrphanRetirementInputV1,
    step: SyntheticRetirementStepV1,
    cleanup_guard: &mut G,
) -> SyntheticRetirementOutcomeV1 {
    retire_synthetic_orphan_with_fault_probe_v1(
        connection,
        input,
        step,
        cleanup_guard,
        &RetirementFaultProbeV1::disabled_v1(),
    )
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the source-included T074 process driver.
pub(crate) fn retire_synthetic_orphan_with_fault_probe_v1<G: RecoveryCleanupGuardV1>(
    connection: &mut Connection,
    input: &SyntheticOrphanRetirementInputV1,
    step: SyntheticRetirementStepV1,
    cleanup_guard: &mut G,
    fault_probe: &RetirementFaultProbeV1,
) -> SyntheticRetirementOutcomeV1 {
    let _retained_cleanup_custody = cleanup_guard;
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(_) => return SyntheticRetirementOutcomeV1::Unavailable,
    };
    let row = transaction
        .query_row(
            "SELECT quarantine_status, quarantine_reason, orphan_retirement_state, \
                    orphan_retirement_id, orphan_retirement_manifest_digest \
             FROM preparation_quarantines WHERE quarantine_id = ?1",
            [input.quarantine_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional();
    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return rollback_operation_outcome_v1(
                transaction,
                SyntheticRetirementOutcomeV1::NotEligible,
            )
        }
        Err(_) => {
            return rollback_operation_outcome_v1(
                transaction,
                SyntheticRetirementOutcomeV1::Unhealthy,
            )
        }
    };
    if row.0 != "RESOLVED_TOMBSTONE" || row.1 != "ORPHAN_MATERIAL" {
        return rollback_operation_outcome_v1(
            transaction,
            SyntheticRetirementOutcomeV1::NotEligible,
        );
    }
    let exact_retirement_id = row.3.as_deref() == Some(input.retirement_id.as_bytes().as_slice());
    if step == SyntheticRetirementStepV1::BeginPending {
        let outcome = if row.2.as_deref() == Some("RETIREMENT_PENDING") && exact_retirement_id {
            SyntheticRetirementOutcomeV1::Pending
        } else {
            SyntheticRetirementOutcomeV1::NotEligible
        };
        return rollback_operation_outcome_v1(transaction, outcome);
    }
    if row.2.as_deref() == Some("RETIRED_TOMBSTONE")
        && exact_retirement_id
        && row.4.as_deref() == Some(input.retirement_manifest_digest.as_bytes().as_slice())
    {
        return rollback_operation_outcome_v1(
            transaction,
            SyntheticRetirementOutcomeV1::AlreadyRetired,
        );
    }
    if row.2.as_deref() != Some("RETIREMENT_PENDING") || !exact_retirement_id {
        return rollback_operation_outcome_v1(transaction, SyntheticRetirementOutcomeV1::Conflict);
    }
    let next = match next_quarantine_generation_v1(&transaction) {
        Ok(next) => next,
        Err(outcome) => return rollback_operation_outcome_v1(transaction, outcome),
    };
    let updated = transaction.execute(
        "UPDATE preparation_quarantines SET \
             orphan_retirement_state = 'RETIRED_TOMBSTONE', \
             orphan_retired_generation = ?1, orphan_retirement_manifest_digest = ?2 \
         WHERE quarantine_id = ?3 AND quarantine_status = 'RESOLVED_TOMBSTONE' \
           AND orphan_retirement_state = 'RETIREMENT_PENDING' \
           AND orphan_retirement_id = ?4 AND orphan_retirement_manifest_digest IS NULL",
        params![
            to_i64_v1(next),
            input.retirement_manifest_digest.as_bytes().as_slice(),
            input.quarantine_id.as_bytes().as_slice(),
            input.retirement_id.as_bytes().as_slice(),
        ],
    );
    if !matches!(updated, Ok(1)) || !advance_quarantine_generation_v1(&transaction, next) {
        return rollback_operation_outcome_v1(transaction, SyntheticRetirementOutcomeV1::Unhealthy);
    }
    if transaction.commit().is_err() {
        return SyntheticRetirementOutcomeV1::Unavailable;
    }
    reach_orphan_retired(fault_probe);
    SyntheticRetirementOutcomeV1::Retired
}

#[cfg(test)]
fn next_store_generation_v1(
    transaction: &Transaction<'_>,
) -> Result<u64, SyntheticRetirementOutcomeV1> {
    let current = transaction
        .query_row(
            "SELECT store_generation FROM coordinator_store_meta \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| SyntheticRetirementOutcomeV1::Unhealthy)?;
    next_safe_v1(current)
}

#[cfg(test)]
fn next_quarantine_generation_v1(
    transaction: &Transaction<'_>,
) -> Result<u64, SyntheticRetirementOutcomeV1> {
    let current = transaction
        .query_row(
            "SELECT store_generation, quarantine_generation \
             FROM coordinator_store_meta \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| SyntheticRetirementOutcomeV1::Unhealthy)?;
    let store = safe_i64_v1(current.0)?;
    let quarantine = safe_i64_v1(current.1)?;
    let next = store
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_U64 && *value > quarantine)
        .ok_or(SyntheticRetirementOutcomeV1::Unhealthy)?;
    Ok(next)
}

#[cfg(test)]
fn advance_store_generation_v1(transaction: &Transaction<'_>, next: u64) -> bool {
    matches!(
        transaction.execute(
            "UPDATE coordinator_store_meta SET store_generation = ?1 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND store_generation = ?1 - 1",
            [to_i64_v1(next)],
        ),
        Ok(1)
    )
}

#[cfg(test)]
fn advance_quarantine_generation_v1(transaction: &Transaction<'_>, next: u64) -> bool {
    matches!(
        transaction.execute(
            "UPDATE coordinator_store_meta SET store_generation = ?1, \
                 quarantine_generation = ?1 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND store_generation = ?1 - 1 AND quarantine_generation < ?1",
            [to_i64_v1(next)],
        ),
        Ok(1)
    )
}

#[cfg(test)]
fn next_safe_v1(value: i64) -> Result<u64, SyntheticRetirementOutcomeV1> {
    safe_i64_v1(value)?
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(SyntheticRetirementOutcomeV1::Unhealthy)
}

#[cfg(test)]
fn safe_i64_v1(value: i64) -> Result<u64, SyntheticRetirementOutcomeV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(SyntheticRetirementOutcomeV1::Unhealthy)
}

#[cfg(test)]
fn to_i64_v1(value: u64) -> i64 {
    debug_assert!(value <= MAX_SAFE_U64);
    value as i64
}

#[cfg(test)]
fn rollback_operation_outcome_v1(
    transaction: Transaction<'_>,
    outcome: SyntheticRetirementOutcomeV1,
) -> SyntheticRetirementOutcomeV1 {
    if transaction.rollback().is_ok() {
        outcome
    } else {
        SyntheticRetirementOutcomeV1::Unhealthy
    }
}

#[cfg(test)]
#[inline]
fn reach_operation_retirement_pending(fault_probe: &RetirementFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::QuarantineAndRetirementOperationBoundRetirementPendingCommitted,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[cfg(test)]
#[inline]
fn reach_operation_retired(fault_probe: &RetirementFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::QuarantineAndRetirementOperationBoundRetiredTombstoneCommitted,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[cfg(test)]
#[inline]
fn reach_orphan_retired(fault_probe: &RetirementFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::QuarantineAndRetirementOrphanRetiredTombstoneCommitted,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}
