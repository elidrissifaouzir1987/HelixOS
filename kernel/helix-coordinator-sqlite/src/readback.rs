//! Private exact coordinator readback boundary.

#![allow(dead_code)] // T037 wires this classifier into the public store trait.

use crate::prepare::production::CoordinatorUncertainCommitCustodyV1;
use helix_contracts::{RecoveryClassV1, Sha256Digest, MAX_SAFE_U64};
use helix_coordinator_sqlite::CoordinatorFaultProbeV1;
use helix_plan_preparation::{
    BudgetReservationReceiptInputV1, BudgetReservationReceiptV1, BudgetReservationStateV1,
    PreparationCommitReceiptInputV1, PreparationCommitReceiptV1, PreparationCommitUncertainV1,
    PreparationReadbackOutcomeV1, PREPARATION_BUDGET_CONTRACT_VERSION_V1,
    PREPARATION_STORE_CONTRACT_VERSION_V1,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::path::Path;

pub(crate) struct CoordinatorReadbackInputV1<'input> {
    pub(crate) operation_id: &'input str,
    pub(crate) attempt_id: Sha256Digest,
    pub(crate) plan_id: Sha256Digest,
    pub(crate) task_id: &'input str,
    pub(crate) workload_id: &'input str,
    pub(crate) reservation_id: &'input str,
    pub(crate) replay_claim_id: Sha256Digest,
    pub(crate) replay_claimant_generation: u64,
    pub(crate) replay_binding_digest: Sha256Digest,
    pub(crate) task_lease_digest: Sha256Digest,
    pub(crate) allowance_binding_digest: Sha256Digest,
    pub(crate) scope_generation: u64,
    pub(crate) currency_code: &'input str,
    pub(crate) price_table_id: &'input str,
    pub(crate) requested: [u64; 4],
    pub(crate) recovery_mode: RecoveryClassV1,
    pub(crate) precondition_digest: Sha256Digest,
    pub(crate) precondition_length: u64,
    pub(crate) effective_expires_at_utc_ms: u64,
    pub(crate) effective_deadline_monotonic_ms: u64,
    /// Present only for the production one-shot uncertainty path. Synthetic T030/T035
    /// fixtures retain their frozen, narrower candidate classifier.
    pub(crate) exact_custody: Option<&'input CoordinatorUncertainCommitCustodyV1>,
    /// Legacy source-included fixture field. Classification deliberately ignores it:
    /// full verification is sampled only through `readback_with_live_snapshot_v1`.
    #[cfg(test)]
    pub(crate) full_store_verified: bool,
    /// Legacy source-included fixture field. Classification deliberately ignores it:
    /// writer exclusion is owned by the live `BEGIN IMMEDIATE` transaction.
    #[cfg(test)]
    pub(crate) definite_absence_writer_exclusion: bool,
}

impl CoordinatorReadbackInputV1<'_> {
    /// Exact prepared-event identity retained by the in-flight COMMIT custody.
    fn retained_event_id_v1(&self) -> Option<Sha256Digest> {
        self.exact_custody.map(|custody| custody.event_id)
    }

    /// Exact initial transition generation retained by the in-flight COMMIT custody.
    fn retained_transition_generation_v1(&self) -> Option<u64> {
        self.exact_custody
            .map(|custody| custody.operation_generation)
    }
}

/// Implemented only by the crate-private T034 synthetic transaction fixture.
pub(crate) trait SyntheticReadbackCaseV1 {
    fn coordinator_readback_input_v1(&self) -> CoordinatorReadbackInputV1<'_>;

    /// Fixture-specific counterpart of production `schema::verify_full`.
    fn verify_synthetic_full_store_v1(&self, connection: &Connection) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticReadbackModeV1 {
    Healthy,
    ContradictorySnapshot,
}

pub(crate) fn synthetic_uncertain_v1<C: SyntheticReadbackCaseV1>(
    case: &C,
) -> PreparationCommitUncertainV1 {
    let input = case.coordinator_readback_input_v1();
    PreparationCommitUncertainV1::try_new(PREPARATION_STORE_CONTRACT_VERSION_V1, input.attempt_id)
        .expect("crate-private synthetic readback input is v1")
}

pub(crate) fn readback_synthetic_attempt_v1<C: SyntheticReadbackCaseV1>(
    database: &Path,
    case: &C,
    uncertain: &PreparationCommitUncertainV1,
    mode: SyntheticReadbackModeV1,
) -> PreparationReadbackOutcomeV1 {
    readback_synthetic_attempt_with_probe_inner_v1(
        database,
        case,
        uncertain,
        mode,
        &CoordinatorFaultProbeV1::disabled_v1(),
    )
}

/// Runs the exact synthetic uncertainty handoff and live-snapshot classifier with one
/// explicitly selected coordinator process probe.
#[cfg(all(test, feature = "test-fault-injection"))]
pub(crate) fn readback_synthetic_attempt_with_fault_probe_v1<C: SyntheticReadbackCaseV1>(
    database: &Path,
    case: &C,
    uncertain: &PreparationCommitUncertainV1,
    mode: SyntheticReadbackModeV1,
    fault_probe: &CoordinatorFaultProbeV1,
) -> PreparationReadbackOutcomeV1 {
    readback_synthetic_attempt_with_probe_inner_v1(database, case, uncertain, mode, fault_probe)
}

fn readback_synthetic_attempt_with_probe_inner_v1<C: SyntheticReadbackCaseV1>(
    database: &Path,
    case: &C,
    uncertain: &PreparationCommitUncertainV1,
    mode: SyntheticReadbackModeV1,
    fault_probe: &CoordinatorFaultProbeV1,
) -> PreparationReadbackOutcomeV1 {
    let input = case.coordinator_readback_input_v1();
    if uncertain.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1
        || uncertain.attempt_id() != input.attempt_id
    {
        return classified_with_probe(PreparationReadbackOutcomeV1::Ambiguous, fault_probe);
    }
    record_uncertain_connection_closed_with_probe_v1(fault_probe);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut connection = match Connection::open_with_flags(database, flags) {
        Ok(connection) => connection,
        Err(_) => {
            return classified_with_probe(PreparationReadbackOutcomeV1::Ambiguous, fault_probe);
        }
    };
    readback_with_fault_probe_v1(&mut connection, &input, fault_probe, |snapshot| {
        mode == SyntheticReadbackModeV1::Healthy && case.verify_synthetic_full_store_v1(snapshot)
    })
}

/// Opens the only snapshot from which exact readback may be classified.
///
/// The verifier runs against the same live `BEGIN IMMEDIATE` transaction that excludes
/// concurrent SQLite publishers. Consequently, neither full-store verification nor
/// definite-absence writer exclusion can be copied into this API as a stale boolean.
/// T037 supplies the production `schema::verify_full` callback after opening and binding
/// the fresh readback connection; source-included synthetic tests supply their frozen
/// full-store counterpart.
pub(crate) fn readback_with_live_snapshot_v1<F>(
    connection: &mut Connection,
    input: &CoordinatorReadbackInputV1<'_>,
    verify_full_store: F,
) -> PreparationReadbackOutcomeV1
where
    F: FnOnce(&Connection) -> bool,
{
    readback_with_fault_probe_v1(
        connection,
        input,
        &CoordinatorFaultProbeV1::disabled_v1(),
        verify_full_store,
    )
}

/// Production readback path carrying the store-owned explicit fault probe.
pub(crate) fn readback_with_fault_probe_v1<F>(
    connection: &mut Connection,
    input: &CoordinatorReadbackInputV1<'_>,
    fault_probe: &CoordinatorFaultProbeV1,
    verify_full_store: F,
) -> PreparationReadbackOutcomeV1
where
    F: FnOnce(&Connection) -> bool,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(_) => {
            return classified_with_probe(PreparationReadbackOutcomeV1::Ambiguous, fault_probe)
        }
    };
    reach_snapshot_opened_with_probe(fault_probe);
    let outcome = if verify_full_store(&transaction) {
        classify_verified_readback_snapshot_v1(&transaction, input)
    } else {
        PreparationReadbackOutcomeV1::Ambiguous
    };
    if transaction.rollback().is_err() {
        return classified_with_probe(PreparationReadbackOutcomeV1::Ambiguous, fault_probe);
    }
    classified_with_probe(outcome, fault_probe)
}

/// Records that the connection which returned explicit uncertainty has been dropped
/// before the adapter opens its one fresh readback connection.
pub(crate) fn record_uncertain_connection_closed_v1() {
    reach_uncertain_connection_closed();
}

/// Production uncertainty handoff carrying the store-owned explicit fault probe.
pub(crate) fn record_uncertain_connection_closed_with_probe_v1(
    fault_probe: &CoordinatorFaultProbeV1,
) {
    reach_uncertain_connection_closed_with_probe(fault_probe);
}

/// Classifies only a full-store-verified snapshot while its writer exclusion is live.
fn classify_verified_readback_snapshot_v1(
    connection: &Connection,
    input: &CoordinatorReadbackInputV1<'_>,
) -> PreparationReadbackOutcomeV1 {
    let footprint = match relevant_key_footprint(connection, input) {
        Ok(footprint) => footprint,
        Err(()) => return PreparationReadbackOutcomeV1::Ambiguous,
    };
    if footprint.active_quarantine != 0 {
        return PreparationReadbackOutcomeV1::Ambiguous;
    }
    let candidates = match read_complete_candidates(connection, input) {
        Ok(candidates) => candidates,
        Err(()) => return PreparationReadbackOutcomeV1::Ambiguous,
    };
    if candidates.is_empty() {
        return if footprint.total == 0 {
            PreparationReadbackOutcomeV1::DefiniteAbsence
        } else {
            PreparationReadbackOutcomeV1::Ambiguous
        };
    }
    if candidates.iter().any(|candidate| !candidate.is_coherent()) {
        return PreparationReadbackOutcomeV1::Ambiguous;
    }
    if candidates.len() != 1 {
        return PreparationReadbackOutcomeV1::Conflict;
    }
    let candidate = &candidates[0];
    if !candidate.matches_binding(input) {
        return PreparationReadbackOutcomeV1::Conflict;
    }
    if candidate.attempt_id.as_slice() != input.attempt_id.as_bytes() {
        return PreparationReadbackOutcomeV1::PriorExactAttempt;
    }
    if let Some(custody) = input.exact_custody {
        match exact_same_attempt_bindings_v1(connection, input, custody) {
            Ok(true) => {}
            Ok(false) | Err(()) => return PreparationReadbackOutcomeV1::Ambiguous,
        }
    }
    match candidate.receipt(input.attempt_id, input.exact_custody) {
        Some(receipt) => PreparationReadbackOutcomeV1::ThisAttempt(receipt),
        None => PreparationReadbackOutcomeV1::Ambiguous,
    }
}

/// Rejoins every exact key retained before an uncertain COMMIT was attempted.
///
/// Metadata high-water generations may advance because of later unrelated commits, so
/// they are bounded below. Attempt-owned operation, transition, event, reservation,
/// comparison, scope and recovery bindings must remain byte-for-byte exact.
fn exact_same_attempt_bindings_v1(
    connection: &Connection,
    input: &CoordinatorReadbackInputV1<'_>,
    custody: &CoordinatorUncertainCommitCustodyV1,
) -> Result<bool, ()> {
    if custody.operation_id != input.operation_id
        || custody.attempt_id != input.attempt_id
        || custody.plan_id != input.plan_id
        || custody.reservation_id != input.reservation_id
        || custody.budget_scope_binding_digest != input.allowance_binding_digest
        || custody.budget_scope_generation != input.scope_generation
    {
        return Ok(false);
    }
    let exact: i64 = connection
        .query_row(
            r#"SELECT EXISTS (
                 SELECT 1
                 FROM prepared_operations AS operation
                 JOIN coordinator_store_meta AS metadata ON metadata.singleton = 1
                 JOIN operation_transitions AS transition
                   ON transition.operation_id = operation.operation_id
                  AND transition.state_generation = operation.state_generation
                 JOIN preparation_comparisons AS comparison
                   ON comparison.operation_id = operation.operation_id
                 JOIN budget_reservations AS reservation
                   ON reservation.operation_id = operation.operation_id
                 JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id
                 JOIN preparation_recovery_evidence AS recovery
                   ON recovery.operation_id = operation.operation_id
                 JOIN preparation_events AS event
                   ON event.event_id = operation.current_event_id
                 WHERE operation.operation_id = ?1
                   AND operation.attempt_id = ?2
                   AND operation.plan_id = ?3
                   AND operation.task_id = ?4
                   AND operation.workload_id = ?5
                   AND operation.reservation_id = ?6
                   AND operation.created_generation = ?7
                   AND operation.state_generation = ?8
                   AND operation.current_event_id = ?9
                   AND operation.effective_expires_at_utc_ms = ?10
                   AND operation.effective_deadline_monotonic_ms = ?11
                   AND operation.instance_epoch = ?19
                   AND operation.fencing_epoch = ?20
                   AND transition.state_generation = ?8
                   AND transition.event_id = ?9
                   AND comparison.comparison_digest = ?12
                   AND comparison.replay_claim_id = ?13
                   AND comparison.replay_claimant_generation = ?14
                   AND comparison.replay_binding_digest = ?15
                   AND comparison.budget_scope_id = ?16
                   AND comparison.budget_scope_generation = ?17
                   AND comparison.supervisor_generation = ?18
                   AND comparison.instance_epoch = ?19
                   AND comparison.fencing_epoch = ?20
                   AND reservation.scope_id = ?16
                   AND reservation.task_lease_digest = ?21
                   AND reservation.budget_generation = ?17
                   AND reservation.currency_code = ?22
                   AND reservation.price_table_id = ?23
                   AND reservation.reserved_cost_micro_units = ?24
                   AND reservation.reserved_action_count = ?25
                   AND reservation.reserved_egress_bytes = ?26
                   AND reservation.reserved_recovery_bytes = ?27
                   AND reservation.created_generation = ?28
                   AND scope.allowance_binding_digest = ?29
                   AND recovery.target_reference_digest = ?30
                   AND recovery.precondition_identity_digest = ?31
                   AND recovery.precondition_digest = ?32
                   AND recovery.precondition_length = ?33
                   AND recovery.boot_binding_digest = ?34
                   AND recovery.instance_epoch = ?19
                   AND recovery.fencing_epoch = ?20
                   AND event.event_id = ?9
                   AND event.event_generation = ?35
                   AND event.operation_state_generation = ?8
                   AND metadata.store_generation >= ?7
                   AND metadata.operation_generation >= ?8
                   AND metadata.budget_generation >= ?28
                   AND metadata.event_generation >= ?35
             )"#,
            params![
                input.operation_id,
                input.attempt_id.as_bytes().as_slice(),
                input.plan_id.as_bytes().as_slice(),
                input.task_id,
                input.workload_id,
                input.reservation_id,
                to_i64(custody.store_generation)?,
                to_i64(custody.operation_generation)?,
                custody.event_id.as_bytes().as_slice(),
                to_i64(input.effective_expires_at_utc_ms)?,
                to_i64(input.effective_deadline_monotonic_ms)?,
                custody.comparison_digest.as_bytes().as_slice(),
                custody.replay_claim_id.as_bytes().as_slice(),
                to_i64(custody.replay_claimant_generation)?,
                custody.replay_binding_digest.as_bytes().as_slice(),
                custody.scope_id.as_bytes().as_slice(),
                to_i64(custody.budget_scope_generation)?,
                to_i64(custody.supervisor_generation)?,
                to_i64(custody.instance_epoch)?,
                to_i64(custody.fencing_epoch)?,
                input.task_lease_digest.as_bytes().as_slice(),
                input.currency_code,
                input.price_table_id,
                to_i64(input.requested[0])?,
                to_i64(input.requested[1])?,
                to_i64(input.requested[2])?,
                to_i64(input.requested[3])?,
                to_i64(custody.reservation_created_generation)?,
                custody.budget_scope_binding_digest.as_bytes().as_slice(),
                custody.target_reference_digest.as_bytes().as_slice(),
                custody.precondition_identity_digest.as_bytes().as_slice(),
                input.precondition_digest.as_bytes().as_slice(),
                to_i64(input.precondition_length)?,
                custody.boot_binding_digest.as_bytes().as_slice(),
                to_i64(custody.event_generation)?,
            ],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    Ok(exact == 1)
}

struct KeyFootprintV1 {
    total: i64,
    active_quarantine: i64,
}

fn relevant_key_footprint(
    connection: &Connection,
    input: &CoordinatorReadbackInputV1<'_>,
) -> Result<KeyFootprintV1, ()> {
    let retained_event_id = input.retained_event_id_v1();
    let retained_event_id = retained_event_id
        .as_ref()
        .map(|event_id| event_id.as_bytes().as_slice());
    let retained_transition_generation = input
        .retained_transition_generation_v1()
        .map(to_i64)
        .transpose()?;
    connection
        .query_row(
            "SELECT \
                 (SELECT COUNT(*) FROM prepared_operations \
                   WHERE operation_id = ?1 OR attempt_id = ?2 OR plan_id = ?3 \
                      OR reservation_id = ?4 OR state_generation = ?5 \
                      OR current_event_id = ?6) + \
                 (SELECT COUNT(*) FROM budget_reservations \
                   WHERE operation_id = ?1 OR attempt_id = ?2 OR plan_id = ?3 \
                      OR reservation_id = ?4) + \
                 (SELECT COUNT(*) FROM operation_transitions \
                   WHERE operation_id = ?1 OR state_generation = ?5 OR event_id = ?6) + \
                 (SELECT COUNT(*) FROM preparation_comparisons WHERE operation_id = ?1) + \
                 (SELECT COUNT(*) FROM preparation_recovery_evidence WHERE operation_id = ?1) + \
                 (SELECT COUNT(*) FROM preparation_events \
                   WHERE operation_id = ?1 OR event_id = ?6 \
                      OR operation_state_generation = ?5), \
                 (SELECT COUNT(*) FROM preparation_quarantines \
                   WHERE attempt_id = ?2 AND quarantine_status = 'ACTIVE')",
            params![
                input.operation_id,
                input.attempt_id.as_bytes().as_slice(),
                input.plan_id.as_bytes().as_slice(),
                input.reservation_id,
                retained_transition_generation,
                retained_event_id,
            ],
            |row| {
                Ok(KeyFootprintV1 {
                    total: row.get(0)?,
                    active_quarantine: row.get(1)?,
                })
            },
        )
        .map_err(|_| ())
}

struct CompleteCandidateV1 {
    store_generation: i64,
    operation_id: String,
    attempt_id: Vec<u8>,
    plan_id: Vec<u8>,
    task_id: String,
    workload_id: String,
    operation_state: String,
    state_generation: i64,
    created_generation: i64,
    reservation_id: String,
    operation_recovery_mode: String,
    current_event_id: Vec<u8>,
    previous_state: Option<String>,
    transition_state: String,
    transition_event_id: Vec<u8>,
    replay_claim_id: Vec<u8>,
    replay_generation: i64,
    replay_binding_digest: Vec<u8>,
    reservation_operation_id: String,
    reservation_attempt_id: Vec<u8>,
    reservation_plan_id: Vec<u8>,
    task_lease_digest: Vec<u8>,
    budget_generation: i64,
    reserved: [i64; 4],
    reservation_state: String,
    reservation_created_generation: i64,
    released_generation: Option<i64>,
    allowance_binding_digest: Vec<u8>,
    scope_generation: i64,
    evidence_recovery_mode: String,
    event_id: Vec<u8>,
    event_generation: i64,
    event_operation_id: String,
    event_state_generation: i64,
    event_operation_state: String,
    event_kind: String,
    event_reason: Option<String>,
    delivery_state: String,
    delivered_generation: Option<i64>,
    member_counts: [i64; 5],
}

impl CompleteCandidateV1 {
    fn is_coherent(&self) -> bool {
        // `created_generation` is the enclosing store mutation while
        // `state_generation` is the operation-transition domain; equality is not required.
        self.store_generation >= self.created_generation
            && self.operation_state == "PREPARING"
            && self.previous_state.is_none()
            && self.transition_state == "PREPARING"
            && self.transition_event_id == self.current_event_id
            && self.reservation_operation_id == self.operation_id
            && self.reservation_attempt_id == self.attempt_id
            && self.reservation_plan_id == self.plan_id
            && self.reservation_state == "HELD"
            && self.reservation_created_generation == self.created_generation
            && self.released_generation.is_none()
            && self.evidence_recovery_mode == self.operation_recovery_mode
            && self.event_id == self.current_event_id
            && self.event_operation_id == self.operation_id
            && self.event_state_generation == self.state_generation
            && self.event_operation_state == "PREPARING"
            && self.event_kind == "PREPARED"
            && self.event_reason.is_none()
            && matches!(
                (self.delivery_state.as_str(), self.delivered_generation),
                ("PENDING", None) | ("DELIVERED", Some(_))
            )
            && self.member_counts == [1, 1, 1, 1, 1]
            && valid_safe(self.store_generation)
            && valid_safe(self.state_generation)
            && valid_safe(self.created_generation)
            && valid_safe(self.event_generation)
            && valid_safe(self.reservation_created_generation)
    }

    fn matches_binding(&self, input: &CoordinatorReadbackInputV1<'_>) -> bool {
        self.operation_id == input.operation_id
            && self.plan_id.as_slice() == input.plan_id.as_bytes()
            && self.task_id == input.task_id
            && self.workload_id == input.workload_id
            && self.reservation_id == input.reservation_id
            && self.replay_claim_id.as_slice() == input.replay_claim_id.as_bytes()
            && u64::try_from(self.replay_generation).ok() == Some(input.replay_claimant_generation)
            && self.replay_binding_digest.as_slice() == input.replay_binding_digest.as_bytes()
            && self.task_lease_digest.as_slice() == input.task_lease_digest.as_bytes()
            && self.allowance_binding_digest.as_slice() == input.allowance_binding_digest.as_bytes()
            && u64::try_from(self.budget_generation).ok() == Some(input.scope_generation)
            && u64::try_from(self.scope_generation).ok() == Some(input.scope_generation)
            && self
                .reserved
                .iter()
                .copied()
                .map(u64::try_from)
                .collect::<Result<Vec<_>, _>>()
                .ok()
                .as_deref()
                == Some(input.requested.as_slice())
            && self.operation_recovery_mode == recovery_mode(input.recovery_mode)
    }

    fn receipt(
        &self,
        attempt_id: Sha256Digest,
        exact_custody: Option<&CoordinatorUncertainCommitCustodyV1>,
    ) -> Option<PreparationCommitReceiptV1> {
        let store_generation = exact_custody.map_or_else(
            || u64::try_from(self.store_generation).ok(),
            |c| Some(c.store_generation),
        )?;
        let operation_generation = exact_custody.map_or_else(
            || u64::try_from(self.state_generation).ok(),
            |custody| Some(custody.operation_generation),
        )?;
        let event_generation = exact_custody.map_or_else(
            || u64::try_from(self.event_generation).ok(),
            |custody| Some(custody.event_generation),
        )?;
        let reservation_generation = exact_custody.map_or_else(
            || u64::try_from(self.reservation_created_generation).ok(),
            |custody| Some(custody.reservation_created_generation),
        )?;
        let budget_reservation =
            BudgetReservationReceiptV1::try_new(BudgetReservationReceiptInputV1 {
                contract_version: PREPARATION_BUDGET_CONTRACT_VERSION_V1,
                state: BudgetReservationStateV1::Held,
                reservation_generation,
            })
            .ok()?;
        PreparationCommitReceiptV1::try_new(PreparationCommitReceiptInputV1 {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            attempt_id,
            store_generation,
            operation_state_generation: operation_generation,
            transition_generation: operation_generation,
            event_generation,
            budget_reservation,
        })
        .ok()
    }
}

fn read_complete_candidates(
    connection: &Connection,
    input: &CoordinatorReadbackInputV1<'_>,
) -> Result<Vec<CompleteCandidateV1>, ()> {
    let mut statement = connection
        .prepare(
            "SELECT metadata.store_generation, operation.operation_id, operation.attempt_id, \
                    operation.plan_id, operation.task_id, operation.workload_id, \
                    operation.operation_state, operation.state_generation, \
                    operation.created_generation, operation.reservation_id, \
                    operation.recovery_mode, operation.current_event_id, \
                    transition.previous_state, transition.new_state, transition.event_id, \
                    comparison.replay_claim_id, comparison.replay_claimant_generation, \
                    comparison.replay_binding_digest, reservation.operation_id, \
                    reservation.attempt_id, reservation.plan_id, reservation.task_lease_digest, \
                    reservation.budget_generation, reservation.reserved_cost_micro_units, \
                    reservation.reserved_action_count, reservation.reserved_egress_bytes, \
                    reservation.reserved_recovery_bytes, reservation.reservation_state, \
                    reservation.created_generation, reservation.released_generation, \
                    scope.allowance_binding_digest, scope.scope_generation, \
                    recovery.recovery_mode, event.event_id, event.event_generation, \
                    event.operation_id, event.operation_state_generation, event.operation_state, \
                    event.event_kind, event.reason_code, event.delivery_state, \
                    event.delivered_generation, \
                    (SELECT COUNT(*) FROM operation_transitions WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM preparation_comparisons WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM budget_reservations WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM preparation_recovery_evidence WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM preparation_events WHERE operation_id = operation.operation_id) \
             FROM prepared_operations AS operation \
             JOIN coordinator_store_meta AS metadata ON metadata.singleton = 1 \
             JOIN operation_transitions AS transition \
               ON transition.operation_id = operation.operation_id \
              AND transition.state_generation = operation.state_generation \
             JOIN preparation_comparisons AS comparison \
               ON comparison.operation_id = operation.operation_id \
             JOIN budget_reservations AS reservation \
               ON reservation.operation_id = operation.operation_id \
             JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id \
             JOIN preparation_recovery_evidence AS recovery \
               ON recovery.operation_id = operation.operation_id \
             JOIN preparation_events AS event ON event.event_id = operation.current_event_id \
             WHERE operation.operation_id = ?1 OR operation.attempt_id = ?2 \
                OR operation.plan_id = ?3 OR operation.reservation_id = ?4 \
             ORDER BY operation.operation_id LIMIT 4",
        )
        .map_err(|_| ())?;
    let rows = statement
        .query_map(
            params![
                input.operation_id,
                input.attempt_id.as_bytes().as_slice(),
                input.plan_id.as_bytes().as_slice(),
                input.reservation_id,
            ],
            |row| {
                Ok(CompleteCandidateV1 {
                    store_generation: row.get(0)?,
                    operation_id: row.get(1)?,
                    attempt_id: row.get(2)?,
                    plan_id: row.get(3)?,
                    task_id: row.get(4)?,
                    workload_id: row.get(5)?,
                    operation_state: row.get(6)?,
                    state_generation: row.get(7)?,
                    created_generation: row.get(8)?,
                    reservation_id: row.get(9)?,
                    operation_recovery_mode: row.get(10)?,
                    current_event_id: row.get(11)?,
                    previous_state: row.get(12)?,
                    transition_state: row.get(13)?,
                    transition_event_id: row.get(14)?,
                    replay_claim_id: row.get(15)?,
                    replay_generation: row.get(16)?,
                    replay_binding_digest: row.get(17)?,
                    reservation_operation_id: row.get(18)?,
                    reservation_attempt_id: row.get(19)?,
                    reservation_plan_id: row.get(20)?,
                    task_lease_digest: row.get(21)?,
                    budget_generation: row.get(22)?,
                    reserved: [row.get(23)?, row.get(24)?, row.get(25)?, row.get(26)?],
                    reservation_state: row.get(27)?,
                    reservation_created_generation: row.get(28)?,
                    released_generation: row.get(29)?,
                    allowance_binding_digest: row.get(30)?,
                    scope_generation: row.get(31)?,
                    evidence_recovery_mode: row.get(32)?,
                    event_id: row.get(33)?,
                    event_generation: row.get(34)?,
                    event_operation_id: row.get(35)?,
                    event_state_generation: row.get(36)?,
                    event_operation_state: row.get(37)?,
                    event_kind: row.get(38)?,
                    event_reason: row.get(39)?,
                    delivery_state: row.get(40)?,
                    delivered_generation: row.get(41)?,
                    member_counts: [
                        row.get(42)?,
                        row.get(43)?,
                        row.get(44)?,
                        row.get(45)?,
                        row.get(46)?,
                    ],
                })
            },
        )
        .map_err(|_| ())?;
    rows.collect::<Result<Vec<_>, _>>().map_err(|_| ())
}

fn recovery_mode(mode: RecoveryClassV1) -> &'static str {
    match mode {
        RecoveryClassV1::Compensation => "COMPENSATION",
        RecoveryClassV1::Irreversible => "IRREVERSIBLE",
    }
}

fn valid_safe(value: i64) -> bool {
    u64::try_from(value)
        .ok()
        .is_some_and(|value| value <= MAX_SAFE_U64)
}

fn to_i64(value: u64) -> Result<i64, ()> {
    if value > MAX_SAFE_U64 {
        return Err(());
    }
    i64::try_from(value).map_err(|_| ())
}

enum ReadbackClassV1 {
    ThisAttempt,
    PriorExactAttempt,
    Conflict,
    DefiniteAbsence,
    Ambiguous,
}

fn classified(outcome: PreparationReadbackOutcomeV1) -> PreparationReadbackOutcomeV1 {
    classified_with_probe(outcome, &CoordinatorFaultProbeV1::disabled_v1())
}

fn classified_with_probe(
    outcome: PreparationReadbackOutcomeV1,
    fault_probe: &CoordinatorFaultProbeV1,
) -> PreparationReadbackOutcomeV1 {
    let class = match &outcome {
        PreparationReadbackOutcomeV1::ThisAttempt(_) => ReadbackClassV1::ThisAttempt,
        PreparationReadbackOutcomeV1::PriorExactAttempt => ReadbackClassV1::PriorExactAttempt,
        PreparationReadbackOutcomeV1::Conflict => ReadbackClassV1::Conflict,
        PreparationReadbackOutcomeV1::DefiniteAbsence => ReadbackClassV1::DefiniteAbsence,
        PreparationReadbackOutcomeV1::Ambiguous
        | PreparationReadbackOutcomeV1::Unavailable
        | PreparationReadbackOutcomeV1::Unhealthy => ReadbackClassV1::Ambiguous,
    };
    reach_readback_classification_with_probe(class, fault_probe);
    outcome
}

#[inline]
fn reach_snapshot_opened() {
    reach_snapshot_opened_with_probe(&CoordinatorFaultProbeV1::disabled_v1());
}

#[inline]
fn reach_snapshot_opened_with_probe(fault_probe: &CoordinatorFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_id_v1(
        crate::test_fault::FaultBoundaryV1::AcknowledgementReadbackSnapshotOpened.id(),
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_uncertain_connection_closed() {
    reach_uncertain_connection_closed_with_probe(&CoordinatorFaultProbeV1::disabled_v1());
}

#[inline]
fn reach_uncertain_connection_closed_with_probe(fault_probe: &CoordinatorFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_id_v1(
        crate::test_fault::FaultBoundaryV1::AcknowledgementUncertainConnectionClosed.id(),
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_readback_classification(class: ReadbackClassV1) {
    reach_readback_classification_with_probe(class, &CoordinatorFaultProbeV1::disabled_v1());
}

#[inline]
fn reach_readback_classification_with_probe(
    class: ReadbackClassV1,
    fault_probe: &CoordinatorFaultProbeV1,
) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_id_v1(match class {
        ReadbackClassV1::ThisAttempt => {
            crate::test_fault::FaultBoundaryV1::AcknowledgementReadbackClassifiedThisAttempt
        }
        ReadbackClassV1::PriorExactAttempt => {
            crate::test_fault::FaultBoundaryV1::AcknowledgementReadbackClassifiedPriorExactAttempt
        }
        ReadbackClassV1::Conflict => {
            crate::test_fault::FaultBoundaryV1::AcknowledgementReadbackClassifiedConflict
        }
        ReadbackClassV1::DefiniteAbsence => {
            crate::test_fault::FaultBoundaryV1::AcknowledgementReadbackClassifiedDefiniteAbsence
        }
        ReadbackClassV1::Ambiguous => {
            crate::test_fault::FaultBoundaryV1::AcknowledgementReadbackClassifiedAmbiguous
        }
    }
    .id());
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = (class, fault_probe);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn input() -> CoordinatorReadbackInputV1<'static> {
        CoordinatorReadbackInputV1 {
            operation_id: "operation:t035",
            attempt_id: digest(1),
            plan_id: digest(2),
            task_id: "task:t035",
            workload_id: "workload:t035",
            reservation_id: "reservation:t035",
            replay_claim_id: digest(3),
            replay_claimant_generation: 1,
            replay_binding_digest: digest(4),
            task_lease_digest: digest(5),
            allowance_binding_digest: digest(6),
            scope_generation: 1,
            currency_code: "USD",
            price_table_id: "prices:t035",
            requested: [1, 1, 1, 1],
            recovery_mode: RecoveryClassV1::Irreversible,
            precondition_digest: digest(11),
            precondition_length: 1,
            effective_expires_at_utc_ms: 10_000,
            effective_deadline_monotonic_ms: 1_000,
            exact_custody: None,
            full_store_verified: false,
            definite_absence_writer_exclusion: false,
        }
    }

    fn exact_custody() -> CoordinatorUncertainCommitCustodyV1 {
        CoordinatorUncertainCommitCustodyV1 {
            operation_id: input().operation_id.to_owned(),
            attempt_id: input().attempt_id,
            plan_id: input().plan_id,
            reservation_id: input().reservation_id.to_owned(),
            event_id: digest(8),
            scope_id: digest(7),
            budget_scope_binding_digest: input().allowance_binding_digest,
            comparison_digest: digest(12),
            replay_claim_id: input().replay_claim_id,
            replay_claimant_generation: input().replay_claimant_generation,
            replay_binding_digest: input().replay_binding_digest,
            target_reference_digest: digest(13),
            precondition_identity_digest: digest(14),
            boot_binding_digest: digest(15),
            budget_scope_generation: input().scope_generation,
            store_generation: 7,
            operation_generation: 3,
            event_generation: 4,
            reservation_created_generation: 7,
            supervisor_generation: 1,
            instance_epoch: 1,
            fencing_epoch: 1,
        }
    }

    fn classify_snapshot(
        connection: &mut Connection,
        input: &CoordinatorReadbackInputV1<'_>,
        full_store_verified: bool,
    ) -> PreparationReadbackOutcomeV1 {
        readback_with_live_snapshot_v1(connection, input, |_| full_store_verified)
    }

    fn empty_snapshot() -> Connection {
        let connection = Connection::open_in_memory().expect("snapshot opens");
        initialize_empty_snapshot(&connection);
        connection
    }

    fn initialize_empty_snapshot(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE coordinator_store_meta (singleton INTEGER, store_generation INTEGER);
                 INSERT INTO coordinator_store_meta VALUES (1, 0);
                 CREATE TABLE prepared_operations (
                   operation_id TEXT, attempt_id BLOB, plan_id BLOB, task_id TEXT,
                   workload_id TEXT, operation_state TEXT, state_generation INTEGER,
                   created_generation INTEGER, reservation_id TEXT, recovery_mode TEXT,
                   current_event_id BLOB);
                 CREATE TABLE operation_transitions (
                   operation_id TEXT, state_generation INTEGER, previous_state TEXT,
                   new_state TEXT, event_id BLOB);
                 CREATE TABLE preparation_comparisons (
                   operation_id TEXT, replay_claim_id BLOB,
                   replay_claimant_generation INTEGER, replay_binding_digest BLOB);
                 CREATE TABLE budget_scopes (
                   scope_id BLOB, allowance_binding_digest BLOB, scope_generation INTEGER);
                 CREATE TABLE budget_reservations (
                   reservation_id TEXT, operation_id TEXT, attempt_id BLOB, plan_id BLOB,
                   task_lease_digest BLOB, budget_generation INTEGER,
                   reserved_cost_micro_units INTEGER, reserved_action_count INTEGER,
                   reserved_egress_bytes INTEGER, reserved_recovery_bytes INTEGER,
                   reservation_state TEXT, created_generation INTEGER,
                   released_generation INTEGER, scope_id BLOB);
                 CREATE TABLE preparation_recovery_evidence (
                   operation_id TEXT, recovery_mode TEXT);
                 CREATE TABLE preparation_events (
                   event_id BLOB, event_generation INTEGER, operation_id TEXT,
                   operation_state_generation INTEGER, operation_state TEXT,
                   event_kind TEXT, reason_code TEXT, delivery_state TEXT,
                   delivered_generation INTEGER);
                 CREATE TABLE preparation_quarantines (
                   attempt_id BLOB, quarantine_status TEXT);",
            )
            .expect("snapshot schema creates");
    }

    struct TempReadbackDatabaseV1 {
        path: PathBuf,
    }

    impl TempReadbackDatabaseV1 {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).expect("test randomness is available");
            Self {
                path: std::env::temp_dir().join(format!(
                    "helix-t035-readback-{}-{:016x}.sqlite3",
                    std::process::id(),
                    u64::from_le_bytes(random)
                )),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempReadbackDatabaseV1 {
        fn drop(&mut self) {
            for suffix in ["", "-journal", "-wal", "-shm"] {
                let mut path = OsString::from(self.path.as_os_str());
                path.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(path));
            }
        }
    }

    fn insert_coherent_candidate(connection: &Connection) {
        connection
            .execute("UPDATE coordinator_store_meta SET store_generation = 9", [])
            .expect("metadata advances");
        connection
            .execute(
                "INSERT INTO budget_scopes VALUES (?1, ?2, 1)",
                params![
                    digest(7).as_bytes().as_slice(),
                    input().allowance_binding_digest.as_bytes().as_slice(),
                ],
            )
            .expect("scope inserts");
        connection
            .execute(
                "INSERT INTO prepared_operations VALUES (
                   ?1, ?2, ?3, ?4, ?5, 'PREPARING', 3, 7, ?6, 'IRREVERSIBLE', ?7)",
                params![
                    input().operation_id,
                    input().attempt_id.as_bytes().as_slice(),
                    input().plan_id.as_bytes().as_slice(),
                    input().task_id,
                    input().workload_id,
                    input().reservation_id,
                    digest(8).as_bytes().as_slice(),
                ],
            )
            .expect("operation inserts");
        connection
            .execute(
                "INSERT INTO operation_transitions VALUES (?1, 3, NULL, 'PREPARING', ?2)",
                params![input().operation_id, digest(8).as_bytes().as_slice(),],
            )
            .expect("transition inserts");
        connection
            .execute(
                "INSERT INTO preparation_comparisons VALUES (?1, ?2, 1, ?3)",
                params![
                    input().operation_id,
                    input().replay_claim_id.as_bytes().as_slice(),
                    input().replay_binding_digest.as_bytes().as_slice(),
                ],
            )
            .expect("comparison inserts");
        connection
            .execute(
                "INSERT INTO budget_reservations VALUES (
                   ?1, ?2, ?3, ?4, ?5, 1, 1, 1, 1, 1, 'HELD', 7, NULL, ?6)",
                params![
                    input().reservation_id,
                    input().operation_id,
                    input().attempt_id.as_bytes().as_slice(),
                    input().plan_id.as_bytes().as_slice(),
                    input().task_lease_digest.as_bytes().as_slice(),
                    digest(7).as_bytes().as_slice(),
                ],
            )
            .expect("reservation inserts");
        connection
            .execute(
                "INSERT INTO preparation_recovery_evidence VALUES (?1, 'IRREVERSIBLE')",
                [input().operation_id],
            )
            .expect("irreversibility inserts");
        connection
            .execute(
                "INSERT INTO preparation_events VALUES (
                   ?1, 4, ?2, 3, 'PREPARING', 'PREPARED', NULL, 'PENDING', NULL)",
                params![digest(8).as_bytes().as_slice(), input().operation_id,],
            )
            .expect("event inserts");
    }

    #[test]
    fn absence_requires_full_verification_inside_live_writer_exclusion() {
        let mut connection = empty_snapshot();
        assert!(matches!(
            classify_snapshot(&mut connection, &input(), false),
            PreparationReadbackOutcomeV1::Ambiguous
        ));

        assert!(matches!(
            classify_snapshot(&mut connection, &input(), true),
            PreparationReadbackOutcomeV1::DefiniteAbsence
        ));
    }

    #[test]
    fn held_writer_prevents_verification_and_never_becomes_definite_absence() {
        let database = TempReadbackDatabaseV1::new();
        let mut publisher = Connection::open(database.path()).expect("publisher opens");
        initialize_empty_snapshot(&publisher);
        let publisher_transaction = publisher
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("publisher holds writer exclusion");

        let mut readback = Connection::open(database.path()).expect("readback opens");
        readback
            .busy_timeout(Duration::ZERO)
            .expect("zero busy wait configures");
        let verifier_called = Cell::new(false);
        let outcome = readback_with_live_snapshot_v1(&mut readback, &input(), |_| {
            verifier_called.set(true);
            true
        });
        assert!(matches!(outcome, PreparationReadbackOutcomeV1::Ambiguous));
        assert!(!verifier_called.get());
        publisher_transaction
            .rollback()
            .expect("publisher exclusion releases");
    }

    #[test]
    fn any_partial_relevant_key_is_ambiguous_not_absent() {
        let mut connection = empty_snapshot();
        connection
            .execute(
                "INSERT INTO budget_reservations (
                   reservation_id, operation_id, attempt_id, plan_id, task_lease_digest,
                   budget_generation, reserved_cost_micro_units, reserved_action_count,
                   reserved_egress_bytes, reserved_recovery_bytes, reservation_state,
                   created_generation, released_generation, scope_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, 1, 1, 1, 'HELD', 1, NULL, ?6)",
                params![
                    input().reservation_id,
                    input().operation_id,
                    input().attempt_id.as_bytes().as_slice(),
                    input().plan_id.as_bytes().as_slice(),
                    input().task_lease_digest.as_bytes().as_slice(),
                    digest(7).as_bytes().as_slice(),
                ],
            )
            .expect("partial key inserts");
        assert!(matches!(
            classify_snapshot(&mut connection, &input(), true),
            PreparationReadbackOutcomeV1::Ambiguous
        ));
    }

    #[test]
    fn retained_event_and_transition_keys_preclude_definite_absence() {
        let custody = exact_custody();
        let mut exact = input();
        exact.exact_custody = Some(&custody);

        let mut event_occupied = empty_snapshot();
        event_occupied
            .execute(
                "INSERT INTO preparation_events VALUES \
                 (?1, 1, 'operation:other', 99, 'PREPARING', 'PREPARED', NULL, \
                  'PENDING', NULL)",
                [custody.event_id.as_bytes().as_slice()],
            )
            .expect("retained event key occupant inserts");
        assert!(matches!(
            classify_snapshot(&mut event_occupied, &exact, true),
            PreparationReadbackOutcomeV1::Ambiguous
        ));

        let mut transition_occupied = empty_snapshot();
        transition_occupied
            .execute(
                "INSERT INTO operation_transitions VALUES \
                 ('operation:other', ?1, NULL, 'PREPARING', ?2)",
                params![
                    i64::try_from(custody.operation_generation)
                        .expect("custody generation fits SQLite"),
                    digest(99).as_bytes().as_slice(),
                ],
            )
            .expect("retained transition generation occupant inserts");
        assert!(matches!(
            classify_snapshot(&mut transition_occupied, &exact, true),
            PreparationReadbackOutcomeV1::Ambiguous
        ));
    }

    #[test]
    fn coherent_package_distinguishes_this_prior_and_conflicting_attempts() {
        let mut connection = empty_snapshot();
        insert_coherent_candidate(&connection);
        let this_attempt = classify_snapshot(&mut connection, &input(), true);
        let PreparationReadbackOutcomeV1::ThisAttempt(receipt) = this_attempt else {
            panic!("coherent same attempt was not exact: {this_attempt:?}");
        };
        assert_eq!(receipt.store_generation(), 9);
        assert_eq!(receipt.operation_state_generation(), 3);
        assert_eq!(receipt.transition_generation(), 3);
        assert_eq!(receipt.event_generation(), 4);
        assert_eq!(receipt.budget_reservation().reservation_generation(), 7);

        let mut prior = input();
        prior.attempt_id = digest(9);
        assert!(matches!(
            classify_snapshot(&mut connection, &prior, true),
            PreparationReadbackOutcomeV1::PriorExactAttempt
        ));

        let mut conflict = input();
        conflict.plan_id = digest(10);
        assert!(matches!(
            classify_snapshot(&mut connection, &conflict, true),
            PreparationReadbackOutcomeV1::Conflict
        ));
    }
}
