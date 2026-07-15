//! Lookup-only reconstruction of authoritative PLAN-004 plus dispatch-V2 state.

#![allow(dead_code)]

use helix_plan_dispatch::DispatchLookupRequestV1;
use rusqlite::{Connection, OptionalExtension};
use std::fmt;

use super::COORDINATOR_DISPATCH_SCHEMA_VERSION_V2;

/// Complete durable state retained by the coordinator between reload and one commit.
/// No constructor or positive field is exposed to callers.
pub(crate) struct DurableDispatchReloadV1 {
    operation_id: Box<str>,
    preparation_attempt_id: [u8; 32],
    plan_digest: [u8; 32],
    preparation_transition_generation: u64,
    canonical_plan: Box<[u8]>,
    comparison_digest: [u8; 32],
    replay_claim_id: [u8; 32],
    replay_claimant_generation: u64,
    replay_binding_digest: [u8; 32],
    reservation_id: Box<str>,
    task_lease_digest: [u8; 32],
    recovery_target_digest: [u8; 32],
    current_preparation_event_id: [u8; 32],
    prior_grant_id: Option<[u8; 32]>,
    prior_dispatch_attempt_id: Option<[u8; 32]>,
    prior_grant_digest: Option<[u8; 32]>,
    prior_canonical_grant: Option<Box<[u8]>>,
    prior_dispatch_state: Option<Box<str>>,
    prior_dispatch_state_generation: Option<u64>,
}

impl fmt::Debug for DurableDispatchReloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableDispatchReloadV1")
            .finish_non_exhaustive()
    }
}

impl DurableDispatchReloadV1 {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) const fn preparation_attempt_id(&self) -> &[u8; 32] {
        &self.preparation_attempt_id
    }

    pub(crate) const fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }

    pub(crate) const fn preparation_transition_generation(&self) -> u64 {
        self.preparation_transition_generation
    }

    pub(crate) fn canonical_plan(&self) -> &[u8] {
        &self.canonical_plan
    }

    pub(crate) const fn comparison_digest(&self) -> &[u8; 32] {
        &self.comparison_digest
    }

    pub(crate) const fn replay_claim(&self) -> (&[u8; 32], u64, &[u8; 32]) {
        (
            &self.replay_claim_id,
            self.replay_claimant_generation,
            &self.replay_binding_digest,
        )
    }

    pub(crate) fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    pub(crate) const fn task_lease_digest(&self) -> &[u8; 32] {
        &self.task_lease_digest
    }

    pub(crate) const fn recovery_target_digest(&self) -> &[u8; 32] {
        &self.recovery_target_digest
    }

    pub(crate) const fn current_preparation_event_id(&self) -> &[u8; 32] {
        &self.current_preparation_event_id
    }

    pub(crate) const fn prior_grant_id(&self) -> Option<&[u8; 32]> {
        self.prior_grant_id.as_ref()
    }

    pub(crate) const fn prior_dispatch_attempt_id(&self) -> Option<&[u8; 32]> {
        self.prior_dispatch_attempt_id.as_ref()
    }

    pub(crate) const fn prior_grant_digest(&self) -> Option<&[u8; 32]> {
        self.prior_grant_digest.as_ref()
    }

    pub(crate) fn prior_canonical_grant(&self) -> Option<&[u8]> {
        self.prior_canonical_grant.as_deref()
    }

    pub(crate) fn prior_dispatch_state(&self) -> Option<&str> {
        self.prior_dispatch_state.as_deref()
    }

    pub(crate) const fn prior_dispatch_state_generation(&self) -> Option<u64> {
        self.prior_dispatch_state_generation
    }
}

/// Closed internal classification. `Torn` is kept distinct from a syntactic lookup
/// conflict so the outer store mapping can latch unhealthy state.
pub(crate) enum DispatchDurableReloadOutcomeV1 {
    Ready(DurableDispatchReloadV1),
    PriorExactDispatch(DurableDispatchReloadV1),
    Missing,
    Torn,
    Restored,
    Failed,
    Quarantined,
    Conflict,
    Unavailable,
    Unhealthy,
    UnsupportedVersion,
}

impl fmt::Debug for DispatchDurableReloadOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready(_) => "DispatchDurableReloadOutcomeV1::Ready(..)",
            Self::PriorExactDispatch(_) => "DispatchDurableReloadOutcomeV1::PriorExactDispatch(..)",
            Self::Missing => "DispatchDurableReloadOutcomeV1::Missing",
            Self::Torn => "DispatchDurableReloadOutcomeV1::Torn",
            Self::Restored => "DispatchDurableReloadOutcomeV1::Restored",
            Self::Failed => "DispatchDurableReloadOutcomeV1::Failed",
            Self::Quarantined => "DispatchDurableReloadOutcomeV1::Quarantined",
            Self::Conflict => "DispatchDurableReloadOutcomeV1::Conflict",
            Self::Unavailable => "DispatchDurableReloadOutcomeV1::Unavailable",
            Self::Unhealthy => "DispatchDurableReloadOutcomeV1::Unhealthy",
            Self::UnsupportedVersion => "DispatchDurableReloadOutcomeV1::UnsupportedVersion",
        })
    }
}

struct DurableReloadRowV1 {
    preparation_attempt_id: Vec<u8>,
    plan_digest: Vec<u8>,
    canonical_plan: Vec<u8>,
    operation_state: String,
    current_state_generation: i64,
    preparation_transition_generation: Option<i64>,
    reservation_id: String,
    restored_source_generation: Option<i64>,
    current_preparation_event_id: Vec<u8>,
    comparison_digest: Option<Vec<u8>>,
    replay_claim_id: Option<Vec<u8>>,
    replay_claimant_generation: Option<i64>,
    replay_binding_digest: Option<Vec<u8>>,
    reservation_attempt_id: Option<Vec<u8>>,
    reservation_plan_digest: Option<Vec<u8>>,
    reservation_state: Option<String>,
    reservation_released_generation: Option<i64>,
    task_lease_digest: Option<Vec<u8>>,
    recovery_target_digest: Option<Vec<u8>>,
    event_id: Option<Vec<u8>>,
    event_state_generation: Option<i64>,
    event_state: Option<String>,
    active_quarantines: i64,
    operation_transitions: i64,
    initial_transitions: i64,
    current_transitions: i64,
    comparison_members: i64,
    reservation_members: i64,
    recovery_members: i64,
    event_members: i64,
    grant_members: i64,
    record_members: i64,
    prior_grant_id: Option<Vec<u8>>,
    prior_dispatch_attempt_id: Option<Vec<u8>>,
    prior_preparation_attempt_id: Option<Vec<u8>>,
    prior_preparation_transition_generation: Option<i64>,
    prior_plan_digest: Option<Vec<u8>>,
    prior_reservation_id: Option<String>,
    prior_grant_digest: Option<Vec<u8>>,
    prior_canonical_grant: Option<Vec<u8>>,
    prior_dispatch_state: Option<String>,
    prior_dispatch_state_generation: Option<i64>,
}

/// Reloads every positive binding from SQLite using only the bounded lookup key and
/// expected digests/generation. No PLAN-004 projection, direct row or authority marker
/// can enter this boundary from the caller.
pub(crate) fn reload_authoritative_v1(
    connection: &Connection,
    request: &DispatchLookupRequestV1,
) -> DispatchDurableReloadOutcomeV1 {
    let user_version: i64 =
        match connection.pragma_query_value(None, "user_version", |row| row.get(0)) {
            Ok(version) => version,
            Err(_) => return DispatchDurableReloadOutcomeV1::Unavailable,
        };
    if user_version != COORDINATOR_DISPATCH_SCHEMA_VERSION_V2 {
        return DispatchDurableReloadOutcomeV1::UnsupportedVersion;
    }

    let lifecycle = connection.query_row(
        "SELECT base.root_lifecycle_state, dispatch.root_lifecycle_state \
         FROM coordinator_store_meta AS base \
         JOIN dispatch_store_meta AS dispatch ON dispatch.singleton = base.singleton \
         WHERE base.singleton = 1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    );
    let (base_lifecycle, dispatch_lifecycle) = match lifecycle {
        Ok(value) => value,
        Err(rusqlite::Error::QueryReturnedNoRows) => return DispatchDurableReloadOutcomeV1::Torn,
        Err(_) => return DispatchDurableReloadOutcomeV1::Unhealthy,
    };
    if base_lifecycle != dispatch_lifecycle {
        return DispatchDurableReloadOutcomeV1::Torn;
    }
    if base_lifecycle == "RESTORE_PENDING" {
        return DispatchDurableReloadOutcomeV1::Restored;
    }
    if base_lifecycle != "ACTIVE" {
        return DispatchDurableReloadOutcomeV1::Unhealthy;
    }

    let row = match load_durable_row_v1(connection, request.operation_id()) {
        Ok(Some(row)) => row,
        Ok(None) => return classify_absent_v1(connection, request),
        Err(_) => return DispatchDurableReloadOutcomeV1::Unhealthy,
    };
    if row.restored_source_generation.is_some() {
        return DispatchDurableReloadOutcomeV1::Restored;
    }
    let expected_history = match row.operation_state.as_str() {
        "PREPARING" => 1,
        "FAILED" => 2,
        _ => return DispatchDurableReloadOutcomeV1::Unhealthy,
    };
    if !complete_base_graph_v1(&row, expected_history) || !complete_dispatch_graph_v1(&row) {
        return DispatchDurableReloadOutcomeV1::Torn;
    }
    if row.preparation_attempt_id.as_slice() != request.expected_preparation_attempt_digest()
        || row.plan_digest.as_slice() != request.expected_plan_digest()
        || row.preparation_transition_generation.and_then(safe_u64)
            != Some(request.expected_preparation_transition_generation())
    {
        return DispatchDurableReloadOutcomeV1::Conflict;
    }
    if row.active_quarantines > 0 {
        return DispatchDurableReloadOutcomeV1::Quarantined;
    }
    if row.operation_state == "FAILED" {
        return DispatchDurableReloadOutcomeV1::Failed;
    }

    let durable = match decode_reload_v1(request.operation_id(), row) {
        Some(durable) => durable,
        None => return DispatchDurableReloadOutcomeV1::Torn,
    };
    if durable.prior_grant_id.is_some() {
        DispatchDurableReloadOutcomeV1::PriorExactDispatch(durable)
    } else {
        DispatchDurableReloadOutcomeV1::Ready(durable)
    }
}

fn classify_absent_v1(
    connection: &Connection,
    request: &DispatchLookupRequestV1,
) -> DispatchDurableReloadOutcomeV1 {
    let observed = connection.query_row(
        "SELECT \
            (SELECT COUNT(*) FROM preparation_quarantines \
             WHERE attempt_id = ?2 AND quarantine_status = 'ACTIVE'), \
            (SELECT COUNT(*) FROM operation_transitions WHERE operation_id = ?1) \
          + (SELECT COUNT(*) FROM preparation_comparisons WHERE operation_id = ?1) \
          + (SELECT COUNT(*) FROM budget_reservations \
             WHERE operation_id = ?1 OR attempt_id = ?2) \
          + (SELECT COUNT(*) FROM preparation_recovery_evidence WHERE operation_id = ?1) \
          + (SELECT COUNT(*) FROM preparation_events WHERE operation_id = ?1) \
          + (SELECT COUNT(*) FROM dispatch_grants \
             WHERE operation_id = ?1 OR preparation_attempt_id = ?2) \
          + (SELECT COUNT(*) FROM dispatch_records WHERE operation_id = ?1)",
        rusqlite::params![
            request.operation_id(),
            request.expected_preparation_attempt_digest().as_slice(),
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    );
    match observed {
        Ok((active_quarantines, _)) if active_quarantines > 0 => {
            DispatchDurableReloadOutcomeV1::Quarantined
        }
        Ok((_, relevant_members)) if relevant_members > 0 => DispatchDurableReloadOutcomeV1::Torn,
        Ok(_) => DispatchDurableReloadOutcomeV1::Missing,
        Err(_) => DispatchDurableReloadOutcomeV1::Unhealthy,
    }
}

fn load_durable_row_v1(
    connection: &Connection,
    operation_id: &str,
) -> rusqlite::Result<Option<DurableReloadRowV1>> {
    connection
        .query_row(
            "SELECT operation.attempt_id, operation.plan_id, operation.canonical_plan, \
                    operation.operation_state, operation.state_generation, \
                    (SELECT initial.state_generation FROM operation_transitions AS initial \
                     WHERE initial.operation_id = operation.operation_id \
                       AND initial.previous_state IS NULL \
                       AND initial.new_state = 'PREPARING'), \
                    operation.reservation_id, \
                    operation.restored_source_generation, operation.current_event_id, \
                    comparison.comparison_digest, comparison.replay_claim_id, \
                    comparison.replay_claimant_generation, comparison.replay_binding_digest, \
                    reservation.attempt_id, reservation.plan_id, reservation.reservation_state, \
                    reservation.released_generation, reservation.task_lease_digest, \
                    recovery.target_reference_digest, event.event_id, \
                    event.operation_state_generation, event.operation_state, \
                    (SELECT COUNT(*) FROM preparation_quarantines AS quarantine \
                     WHERE quarantine.attempt_id = operation.attempt_id \
                       AND quarantine.quarantine_status = 'ACTIVE'), \
                    (SELECT COUNT(*) FROM operation_transitions \
                     WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM operation_transitions \
                     WHERE operation_id = operation.operation_id \
                       AND previous_state IS NULL AND new_state = 'PREPARING'), \
                    (SELECT COUNT(*) FROM operation_transitions \
                     WHERE operation_id = operation.operation_id \
                       AND state_generation = operation.state_generation \
                       AND event_id = operation.current_event_id \
                       AND new_state = operation.operation_state), \
                    (SELECT COUNT(*) FROM preparation_comparisons \
                     WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM budget_reservations \
                     WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM preparation_recovery_evidence \
                     WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM preparation_events \
                     WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM dispatch_grants \
                     WHERE operation_id = operation.operation_id), \
                    (SELECT COUNT(*) FROM dispatch_records \
                     WHERE operation_id = operation.operation_id), \
                    grant.grant_id, grant.dispatch_attempt_id, grant.preparation_attempt_id, \
                    grant.preparation_transition_generation, grant.plan_id, \
                    grant.reservation_id, grant.grant_digest, grant.canonical_grant, \
                    record.effective_state, record.state_generation \
             FROM prepared_operations AS operation \
             LEFT JOIN preparation_comparisons AS comparison \
               ON comparison.operation_id = operation.operation_id \
             LEFT JOIN budget_reservations AS reservation \
               ON reservation.reservation_id = operation.reservation_id \
              AND reservation.operation_id = operation.operation_id \
             LEFT JOIN preparation_recovery_evidence AS recovery \
               ON recovery.operation_id = operation.operation_id \
             LEFT JOIN preparation_events AS event \
               ON event.event_id = operation.current_event_id \
              AND event.operation_id = operation.operation_id \
             LEFT JOIN dispatch_grants AS grant \
               ON grant.operation_id = operation.operation_id \
             LEFT JOIN dispatch_records AS record \
               ON record.operation_id = operation.operation_id \
              AND record.grant_id = grant.grant_id \
             WHERE operation.operation_id = ?1",
            [operation_id],
            |row| {
                Ok(DurableReloadRowV1 {
                    preparation_attempt_id: row.get(0)?,
                    plan_digest: row.get(1)?,
                    canonical_plan: row.get(2)?,
                    operation_state: row.get(3)?,
                    current_state_generation: row.get(4)?,
                    preparation_transition_generation: row.get(5)?,
                    reservation_id: row.get(6)?,
                    restored_source_generation: row.get(7)?,
                    current_preparation_event_id: row.get(8)?,
                    comparison_digest: row.get(9)?,
                    replay_claim_id: row.get(10)?,
                    replay_claimant_generation: row.get(11)?,
                    replay_binding_digest: row.get(12)?,
                    reservation_attempt_id: row.get(13)?,
                    reservation_plan_digest: row.get(14)?,
                    reservation_state: row.get(15)?,
                    reservation_released_generation: row.get(16)?,
                    task_lease_digest: row.get(17)?,
                    recovery_target_digest: row.get(18)?,
                    event_id: row.get(19)?,
                    event_state_generation: row.get(20)?,
                    event_state: row.get(21)?,
                    active_quarantines: row.get(22)?,
                    operation_transitions: row.get(23)?,
                    initial_transitions: row.get(24)?,
                    current_transitions: row.get(25)?,
                    comparison_members: row.get(26)?,
                    reservation_members: row.get(27)?,
                    recovery_members: row.get(28)?,
                    event_members: row.get(29)?,
                    grant_members: row.get(30)?,
                    record_members: row.get(31)?,
                    prior_grant_id: row.get(32)?,
                    prior_dispatch_attempt_id: row.get(33)?,
                    prior_preparation_attempt_id: row.get(34)?,
                    prior_preparation_transition_generation: row.get(35)?,
                    prior_plan_digest: row.get(36)?,
                    prior_reservation_id: row.get(37)?,
                    prior_grant_digest: row.get(38)?,
                    prior_canonical_grant: row.get(39)?,
                    prior_dispatch_state: row.get(40)?,
                    prior_dispatch_state_generation: row.get(41)?,
                })
            },
        )
        .optional()
}

fn complete_base_graph_v1(row: &DurableReloadRowV1, expected_history: i64) -> bool {
    let state_generation = safe_u64(row.current_state_generation);
    row.operation_transitions == expected_history
        && row.initial_transitions == 1
        && row.current_transitions == 1
        && row.event_members == expected_history
        && row.comparison_members == 1
        && row.reservation_members == 1
        && row.recovery_members == 1
        && row.comparison_digest.as_deref().is_some_and(is_digest)
        && row.replay_claim_id.as_deref().is_some_and(is_digest)
        && row.replay_binding_digest.as_deref().is_some_and(is_digest)
        && row.replay_claimant_generation.and_then(safe_u64).is_some()
        && row.reservation_attempt_id.as_deref() == Some(row.preparation_attempt_id.as_slice())
        && row.reservation_plan_digest.as_deref() == Some(row.plan_digest.as_slice())
        && row.task_lease_digest.as_deref().is_some_and(is_digest)
        && row.recovery_target_digest.as_deref().is_some_and(is_digest)
        && row.event_id.as_deref() == Some(row.current_preparation_event_id.as_slice())
        && row.event_state_generation.and_then(safe_u64) == state_generation
        && row.event_state.as_deref() == Some(row.operation_state.as_str())
        && row
            .preparation_transition_generation
            .and_then(safe_u64)
            .is_some()
        && match row.operation_state.as_str() {
            "PREPARING" => {
                row.reservation_state.as_deref() == Some("HELD")
                    && row.reservation_released_generation.is_none()
            }
            "FAILED" => {
                row.reservation_state.as_deref() == Some("RELEASED")
                    && row.reservation_released_generation.and_then(safe_u64) == state_generation
            }
            _ => false,
        }
}

fn complete_dispatch_graph_v1(row: &DurableReloadRowV1) -> bool {
    match (row.grant_members, row.record_members) {
        (0, 0) => {
            row.prior_grant_id.is_none()
                && row.prior_dispatch_attempt_id.is_none()
                && row.prior_dispatch_state.is_none()
                && row.prior_dispatch_state_generation.is_none()
        }
        (1, 1) => {
            row.prior_grant_id.as_deref().is_some_and(is_digest)
                && row
                    .prior_dispatch_attempt_id
                    .as_deref()
                    .is_some_and(is_digest)
                && row.prior_preparation_attempt_id.as_deref()
                    == Some(row.preparation_attempt_id.as_slice())
                && row
                    .prior_preparation_transition_generation
                    .and_then(safe_u64)
                    == row.preparation_transition_generation.and_then(safe_u64)
                && row.prior_plan_digest.as_deref() == Some(row.plan_digest.as_slice())
                && row.prior_reservation_id.as_deref() == Some(row.reservation_id.as_str())
                && row.prior_grant_digest.as_deref().is_some_and(is_digest)
                && row
                    .prior_canonical_grant
                    .as_deref()
                    .is_some_and(|bytes| !bytes.is_empty() && bytes.len() <= 1_048_576)
                && row
                    .prior_dispatch_state_generation
                    .and_then(safe_u64)
                    .is_some()
                && match row.operation_state.as_str() {
                    "PREPARING" => matches!(
                        row.prior_dispatch_state.as_deref(),
                        Some(
                            "DISPATCHING"
                                | "EXECUTING"
                                | "OUTCOME_UNKNOWN"
                                | "RECONCILIATION_REQUIRED"
                        )
                    ),
                    "FAILED" => row.prior_dispatch_state.as_deref() == Some("FAILED"),
                    _ => false,
                }
        }
        _ => false,
    }
}

fn decode_reload_v1(
    operation_id: &str,
    row: DurableReloadRowV1,
) -> Option<DurableDispatchReloadV1> {
    Some(DurableDispatchReloadV1 {
        operation_id: operation_id.into(),
        preparation_attempt_id: digest(row.preparation_attempt_id)?,
        plan_digest: digest(row.plan_digest)?,
        preparation_transition_generation: safe_u64(row.preparation_transition_generation?)?,
        canonical_plan: row.canonical_plan.into(),
        comparison_digest: digest(row.comparison_digest?)?,
        replay_claim_id: digest(row.replay_claim_id?)?,
        replay_claimant_generation: safe_u64(row.replay_claimant_generation?)?,
        replay_binding_digest: digest(row.replay_binding_digest?)?,
        reservation_id: row.reservation_id.into(),
        task_lease_digest: digest(row.task_lease_digest?)?,
        recovery_target_digest: digest(row.recovery_target_digest?)?,
        current_preparation_event_id: digest(row.current_preparation_event_id)?,
        prior_grant_id: optional_digest(row.prior_grant_id)?,
        prior_dispatch_attempt_id: optional_digest(row.prior_dispatch_attempt_id)?,
        prior_grant_digest: optional_digest(row.prior_grant_digest)?,
        prior_canonical_grant: row.prior_canonical_grant.map(Into::into),
        prior_dispatch_state: row.prior_dispatch_state.map(Into::into),
        prior_dispatch_state_generation: row.prior_dispatch_state_generation.and_then(safe_u64),
    })
}

fn optional_digest(value: Option<Vec<u8>>) -> Option<Option<[u8; 32]>> {
    match value {
        Some(value) => Some(Some(digest(value)?)),
        None => Some(None),
    }
}

fn digest(value: Vec<u8>) -> Option<[u8; 32]> {
    value.try_into().ok()
}

fn is_digest(value: &[u8]) -> bool {
    value.len() == 32
}

fn safe_u64(value: i64) -> Option<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= 9_007_199_254_740_991)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_plan_dispatch::{DispatchLookupRequestInputV1, DISPATCH_LOOKUP_CONTRACT_VERSION_V1};
    use rusqlite::params;

    fn request(plan: u8) -> DispatchLookupRequestV1 {
        DispatchLookupRequestV1::try_new(DispatchLookupRequestInputV1 {
            contract_version: DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
            operation_id: "operation:one",
            expected_plan_digest: [plan; 32],
            expected_preparation_attempt_digest: [0x22; 32],
            expected_preparation_transition_generation: 1,
            caller_deadline_monotonic_ms: 10_000,
        })
        .expect("lookup validates")
    }

    fn ready_fixture() -> Connection {
        let connection = Connection::open_in_memory().expect("fixture opens");
        connection
            .execute_batch(
                "CREATE TABLE coordinator_store_meta (
                   singleton INTEGER, root_lifecycle_state TEXT
                 );
                 CREATE TABLE dispatch_store_meta (
                   singleton INTEGER, root_lifecycle_state TEXT
                 );
                 CREATE TABLE prepared_operations (
                   operation_id TEXT, attempt_id BLOB, plan_id BLOB, canonical_plan BLOB,
                   operation_state TEXT, state_generation INTEGER, created_generation INTEGER,
                   reservation_id TEXT, restored_source_generation INTEGER,
                   current_event_id BLOB
                 );
                 CREATE TABLE operation_transitions (
                   operation_id TEXT, state_generation INTEGER,
                   previous_state TEXT, new_state TEXT, event_id BLOB
                 );
                 CREATE TABLE preparation_comparisons (
                   operation_id TEXT, comparison_digest BLOB, replay_claim_id BLOB,
                   replay_claimant_generation INTEGER, replay_binding_digest BLOB
                 );
                 CREATE TABLE budget_reservations (
                   reservation_id TEXT, operation_id TEXT, attempt_id BLOB, plan_id BLOB,
                   reservation_state TEXT, released_generation INTEGER,
                   task_lease_digest BLOB
                 );
                 CREATE TABLE preparation_recovery_evidence (
                   operation_id TEXT, target_reference_digest BLOB
                 );
                 CREATE TABLE preparation_events (
                   event_id BLOB, operation_id TEXT, operation_state_generation INTEGER,
                   operation_state TEXT
                 );
                 CREATE TABLE preparation_quarantines (
                   attempt_id BLOB, quarantine_status TEXT
                 );
                 CREATE TABLE dispatch_grants (
                   operation_id TEXT, grant_id BLOB, dispatch_attempt_id BLOB,
                   preparation_attempt_id BLOB, preparation_transition_generation INTEGER,
                   plan_id BLOB, reservation_id TEXT, grant_digest BLOB,
                   canonical_grant BLOB
                 );
                 CREATE TABLE dispatch_records (
                   operation_id TEXT, grant_id BLOB, effective_state TEXT,
                   state_generation INTEGER
                 );
                 INSERT INTO coordinator_store_meta VALUES (1, 'ACTIVE');
                 INSERT INTO dispatch_store_meta VALUES (1, 'ACTIVE');",
            )
            .expect("fixture schema installs");
        connection
            .pragma_update(None, "user_version", COORDINATOR_DISPATCH_SCHEMA_VERSION_V2)
            .expect("fixture publishes V2 identity");
        connection
            .execute(
                "INSERT INTO prepared_operations VALUES (
                   'operation:one', ?1, ?2, ?3, 'PREPARING', 1, 1,
                   'reservation:one', NULL, ?4
                 )",
                params![
                    [0x22_u8; 32].as_slice(),
                    [0x11_u8; 32].as_slice(),
                    b"canonical-plan".as_slice(),
                    [0x33_u8; 32].as_slice(),
                ],
            )
            .expect("operation installs");
        connection
            .execute(
                "INSERT INTO operation_transitions VALUES (
                   'operation:one', 1, NULL, 'PREPARING', ?1
                 )",
                [[0x33_u8; 32].as_slice()],
            )
            .expect("transition installs");
        connection
            .execute(
                "INSERT INTO preparation_comparisons VALUES (
                   'operation:one', ?1, ?2, 1, ?3
                 )",
                params![
                    [0x44_u8; 32].as_slice(),
                    [0x55_u8; 32].as_slice(),
                    [0x66_u8; 32].as_slice(),
                ],
            )
            .expect("comparison installs");
        connection
            .execute(
                "INSERT INTO budget_reservations VALUES (
                   'reservation:one', 'operation:one', ?1, ?2, 'HELD', NULL, ?3
                 )",
                params![
                    [0x22_u8; 32].as_slice(),
                    [0x11_u8; 32].as_slice(),
                    [0x77_u8; 32].as_slice(),
                ],
            )
            .expect("reservation installs");
        connection
            .execute(
                "INSERT INTO preparation_recovery_evidence VALUES ('operation:one', ?1)",
                [[0x88_u8; 32].as_slice()],
            )
            .expect("recovery installs");
        connection
            .execute(
                "INSERT INTO preparation_events VALUES (?1, 'operation:one', 1, 'PREPARING')",
                [[0x33_u8; 32].as_slice()],
            )
            .expect("event installs");
        connection
    }

    #[test]
    fn complete_lookup_only_graph_is_ready_and_binding_mismatch_is_conflict() {
        let connection = ready_fixture();
        assert!(matches!(
            reload_authoritative_v1(&connection, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Ready(_)
        ));
        assert!(matches!(
            reload_authoritative_v1(&connection, &request(0x12)),
            DispatchDurableReloadOutcomeV1::Conflict
        ));
    }

    #[test]
    fn missing_member_is_torn_not_positive_authority() {
        let connection = ready_fixture();
        connection
            .execute("DELETE FROM preparation_comparisons", [])
            .expect("fixture tears comparison");
        assert!(matches!(
            reload_authoritative_v1(&connection, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Torn
        ));
    }

    #[test]
    fn absence_requires_every_related_durable_key_to_be_absent() {
        let torn = ready_fixture();
        torn.execute("DELETE FROM prepared_operations", [])
            .expect("fixture removes only root row");
        assert!(matches!(
            reload_authoritative_v1(&torn, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Torn
        ));

        let missing = ready_fixture();
        missing
            .execute_batch(
                "DELETE FROM prepared_operations;
                 DELETE FROM operation_transitions;
                 DELETE FROM preparation_comparisons;
                 DELETE FROM budget_reservations;
                 DELETE FROM preparation_recovery_evidence;
                 DELETE FROM preparation_events;",
            )
            .expect("fixture removes complete graph");
        assert!(matches!(
            reload_authoritative_v1(&missing, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Missing
        ));

        missing
            .execute(
                "INSERT INTO preparation_quarantines VALUES (?1, 'ACTIVE')",
                [[0x22_u8; 32].as_slice()],
            )
            .expect("absent attempt quarantine installs");
        assert!(matches!(
            reload_authoritative_v1(&missing, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Quarantined
        ));
    }

    #[test]
    fn restore_quarantine_and_failed_are_closed_non_ready_states() {
        let restored = ready_fixture();
        restored
            .execute_batch(
                "UPDATE coordinator_store_meta SET root_lifecycle_state = 'RESTORE_PENDING';
                 UPDATE dispatch_store_meta SET root_lifecycle_state = 'RESTORE_PENDING';",
            )
            .expect("fixture becomes restored");
        assert!(matches!(
            reload_authoritative_v1(&restored, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Restored
        ));

        let quarantined = ready_fixture();
        quarantined
            .execute(
                "INSERT INTO preparation_quarantines VALUES (?1, 'ACTIVE')",
                [[0x22_u8; 32].as_slice()],
            )
            .expect("fixture quarantines attempt");
        assert!(matches!(
            reload_authoritative_v1(&quarantined, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Quarantined
        ));

        let failed = ready_fixture();
        failed
            .execute_batch(
                "INSERT INTO operation_transitions VALUES (
                   'operation:one', 2, 'PREPARING', 'FAILED',
                   X'9999999999999999999999999999999999999999999999999999999999999999'
                 );
                 INSERT INTO preparation_events VALUES (
                   X'9999999999999999999999999999999999999999999999999999999999999999',
                   'operation:one', 2, 'FAILED'
                 );
                 UPDATE prepared_operations
                    SET operation_state = 'FAILED', state_generation = 2,
                        current_event_id = X'9999999999999999999999999999999999999999999999999999999999999999';
                 UPDATE budget_reservations
                    SET reservation_state = 'RELEASED', released_generation = 2;",
            )
            .expect("fixture fails operation coherently");
        assert!(matches!(
            reload_authoritative_v1(&failed, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Failed
        ));
    }

    #[test]
    fn exact_persisted_dispatch_is_prior_and_partial_overlay_is_torn() {
        let connection = ready_fixture();
        connection
            .execute(
                "INSERT INTO dispatch_grants VALUES (
                   'operation:one', ?1, ?2, ?3, 1, ?4, 'reservation:one', ?5, ?6
                 )",
                params![
                    [0x91_u8; 32].as_slice(),
                    [0x92_u8; 32].as_slice(),
                    [0x22_u8; 32].as_slice(),
                    [0x11_u8; 32].as_slice(),
                    [0x93_u8; 32].as_slice(),
                    b"canonical-grant".as_slice(),
                ],
            )
            .expect("grant installs");
        assert!(matches!(
            reload_authoritative_v1(&connection, &request(0x11)),
            DispatchDurableReloadOutcomeV1::Torn
        ));
        connection
            .execute(
                "INSERT INTO dispatch_records VALUES (?1, ?2, 'DISPATCHING', 2)",
                params!["operation:one", [0x91_u8; 32].as_slice()],
            )
            .expect("record installs");
        assert!(matches!(
            reload_authoritative_v1(&connection, &request(0x11)),
            DispatchDurableReloadOutcomeV1::PriorExactDispatch(_)
        ));
    }
}
