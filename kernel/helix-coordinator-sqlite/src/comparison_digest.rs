//! Shared typed encoding for the persisted preparation-comparison digest.
//!
//! Both the transaction writer and the full-store verifier use this module. Keeping
//! the encoder independent of either path prevents a writer/verifier spelling drift.

use helix_contracts::MAX_SAFE_U64;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, Row};
use sha2::{Digest, Sha256};

const COMPARISON_DIGEST_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-COMPARISON-DIGEST\0V1\0";

/// The frozen v1 comparison-digest projection.
///
/// This is deliberately an allow-list rather than `table.*`. Preparation history outlives
/// mutable coordinator lifecycle fields: scope holds change for every reservation,
/// operations and reservations transition, and recovery material may later be retired.
/// Both the transaction writer and the verifier must select these columns in exactly this
/// order and pass column zero as the excluded persisted digest to
/// [`joined_comparison_digest_v1`].
pub(crate) const IMMUTABLE_COMPARISON_DIGEST_PROJECTION_V1_SQL: &str = r#"
    comparison.comparison_digest AS persisted_comparison_digest_v1,
    comparison.operation_id AS comparison_operation_id_v1,
    comparison.comparison_version AS comparison_version_v1,
    comparison.capture_generation AS comparison_capture_generation_v1,
    comparison.clock_generation AS comparison_clock_generation_v1,
    comparison.plan_deadline_generation AS comparison_plan_deadline_generation_v1,
    comparison.supervisor_generation AS comparison_supervisor_generation_v1,
    comparison.admission_state AS comparison_admission_state_v1,
    comparison.instance_epoch AS comparison_instance_epoch_v1,
    comparison.fencing_epoch AS comparison_fencing_epoch_v1,
    comparison.trust_generation AS comparison_trust_generation_v1,
    comparison.verified_key_fingerprint AS comparison_verified_key_fingerprint_v1,
    comparison.workload_generation AS comparison_workload_generation_v1,
    comparison.workload_evidence_digest AS comparison_workload_evidence_digest_v1,
    comparison.lease_generation AS comparison_lease_generation_v1,
    comparison.lease_digest AS comparison_lease_digest_v1,
    comparison.lease_decision_digest AS comparison_lease_decision_digest_v1,
    comparison.authorization_generation AS comparison_authorization_generation_v1,
    comparison.authorization_evidence_digest AS comparison_authorization_evidence_digest_v1,
    comparison.policy_generation AS comparison_policy_generation_v1,
    comparison.policy_decision_generation AS comparison_policy_decision_generation_v1,
    comparison.policy_content_digest AS comparison_policy_content_digest_v1,
    comparison.policy_decision_digest AS comparison_policy_decision_digest_v1,
    comparison.catalogue_generation AS comparison_catalogue_generation_v1,
    comparison.catalogue_decision_generation AS comparison_catalogue_decision_generation_v1,
    comparison.catalogue_content_digest AS comparison_catalogue_content_digest_v1,
    comparison.catalogue_decision_digest AS comparison_catalogue_decision_digest_v1,
    comparison.capability_generation AS comparison_capability_generation_v1,
    comparison.capability_report_digest AS comparison_capability_report_digest_v1,
    comparison.host_driver_context_digest AS comparison_host_driver_context_digest_v1,
    comparison.eligible_evaluated_at_utc_ms AS comparison_eligible_evaluated_at_utc_ms_v1,
    comparison.eligible_evaluated_at_monotonic_ms AS comparison_eligible_evaluated_at_monotonic_ms_v1,
    comparison.final_sample_utc_ms AS comparison_final_sample_utc_ms_v1,
    comparison.final_sample_monotonic_ms AS comparison_final_sample_monotonic_ms_v1,
    comparison.capability_observed_at_utc_ms AS comparison_capability_observed_at_utc_ms_v1,
    comparison.capability_max_age_ms AS comparison_capability_max_age_ms_v1,
    comparison.replay_claim_id AS comparison_replay_claim_id_v1,
    comparison.replay_claimant_generation AS comparison_replay_claimant_generation_v1,
    comparison.replay_binding_digest AS comparison_replay_binding_digest_v1,
    comparison.budget_scope_id AS comparison_budget_scope_id_v1,
    comparison.budget_scope_generation AS comparison_budget_scope_generation_v1,
    comparison.recovery_provider_generation AS comparison_recovery_provider_generation_v1,
    operation.operation_id AS operation_operation_id_v1,
    operation.attempt_id AS operation_attempt_id_v1,
    operation.plan_id AS operation_plan_id_v1,
    operation.task_id AS operation_task_id_v1,
    operation.workload_id AS operation_workload_id_v1,
    operation.canonical_plan AS operation_canonical_plan_v1,
    operation.canonical_plan_length AS operation_canonical_plan_length_v1,
    operation.created_generation AS operation_created_generation_v1,
    operation.boot_id AS operation_boot_id_v1,
    operation.instance_epoch AS operation_instance_epoch_v1,
    operation.fencing_epoch AS operation_fencing_epoch_v1,
    operation.effective_expires_at_utc_ms AS operation_effective_expires_at_utc_ms_v1,
    operation.effective_deadline_monotonic_ms AS operation_effective_deadline_monotonic_ms_v1,
    operation.reservation_id AS operation_reservation_id_v1,
    operation.recovery_mode AS operation_recovery_mode_v1,
    operation.restored_source_generation AS operation_restored_source_generation_v1,
    scope.scope_id AS scope_scope_id_v1,
    scope.task_lease_digest AS scope_task_lease_digest_v1,
    scope.allowance_binding_digest AS scope_allowance_binding_digest_v1,
    scope.scope_generation AS scope_generation_v1,
    scope.currency_code AS scope_currency_code_v1,
    scope.price_table_id AS scope_price_table_id_v1,
    scope.total_cost_micro_units AS scope_total_cost_micro_units_v1,
    scope.total_action_count AS scope_total_action_count_v1,
    scope.total_egress_bytes AS scope_total_egress_bytes_v1,
    scope.total_recovery_bytes AS scope_total_recovery_bytes_v1,
    scope.provisioning_profile AS scope_provisioning_profile_v1,
    reservation.reservation_id AS reservation_reservation_id_v1,
    reservation.operation_id AS reservation_operation_id_v1,
    reservation.attempt_id AS reservation_attempt_id_v1,
    reservation.plan_id AS reservation_plan_id_v1,
    reservation.scope_id AS reservation_scope_id_v1,
    reservation.task_lease_digest AS reservation_task_lease_digest_v1,
    reservation.budget_generation AS reservation_budget_generation_v1,
    reservation.currency_code AS reservation_currency_code_v1,
    reservation.price_table_id AS reservation_price_table_id_v1,
    reservation.reserved_cost_micro_units AS reservation_reserved_cost_micro_units_v1,
    reservation.reserved_action_count AS reservation_reserved_action_count_v1,
    reservation.reserved_egress_bytes AS reservation_reserved_egress_bytes_v1,
    reservation.reserved_recovery_bytes AS reservation_reserved_recovery_bytes_v1,
    reservation.created_generation AS reservation_created_generation_v1,
    recovery.operation_id AS recovery_operation_id_v1,
    recovery.evidence_version AS recovery_evidence_version_v1,
    recovery.recovery_mode AS recovery_mode_v1,
    recovery.recovery_class AS recovery_class_v1,
    recovery.atomicity AS recovery_atomicity_v1,
    recovery.risk_level AS recovery_risk_level_v1,
    recovery.target_reference_digest AS recovery_target_reference_digest_v1,
    recovery.precondition_identity_digest AS recovery_precondition_identity_digest_v1,
    recovery.precondition_digest AS recovery_precondition_digest_v1,
    recovery.precondition_length AS recovery_precondition_length_v1,
    recovery.reserved_capacity AS recovery_reserved_capacity_v1,
    recovery.provider_profile_id AS recovery_provider_profile_id_v1,
    recovery.provider_profile_version AS recovery_provider_profile_version_v1,
    recovery.provider_id AS recovery_provider_id_v1,
    recovery.provider_generation AS recovery_provider_generation_v1,
    recovery.evidence_class AS recovery_evidence_class_v1,
    recovery.at_rest_profile_id AS recovery_at_rest_profile_id_v1,
    recovery.capability_binding_digest AS recovery_capability_binding_digest_v1,
    recovery.material_id AS recovery_material_id_v1,
    recovery.publication_attempt_id AS recovery_publication_attempt_id_v1,
    recovery.manifest_digest AS recovery_manifest_digest_v1,
    recovery.material_digest AS recovery_material_digest_v1,
    recovery.material_length AS recovery_material_length_v1,
    recovery.boot_binding_digest AS recovery_boot_binding_digest_v1,
    recovery.instance_epoch AS recovery_instance_epoch_v1,
    recovery.fencing_epoch AS recovery_fencing_epoch_v1
"#;

const COMPARISON_DIGEST_JOIN_V1_SQL: &str = r#"
    FROM preparation_comparisons AS comparison
    JOIN prepared_operations AS operation
      ON operation.operation_id = comparison.operation_id
    JOIN budget_reservations AS reservation
      ON reservation.operation_id = operation.operation_id
    JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id
    JOIN preparation_recovery_evidence AS recovery
      ON recovery.operation_id = operation.operation_id
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComparisonDigestErrorV1 {
    InvalidValue,
    FieldCountOverflow,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PersistedComparisonDigestV1 {
    pub(crate) operation_id: String,
    pub(crate) persisted: [u8; 32],
    pub(crate) recomputed: [u8; 32],
}

/// Deterministic typed encoder for the reviewed v1 joined-row order.
pub(crate) struct ComparisonDigestV1Builder {
    field_count: u32,
    encoding: Vec<u8>,
}

impl ComparisonDigestV1Builder {
    pub(crate) const fn new() -> Self {
        Self {
            field_count: 0,
            encoding: Vec::new(),
        }
    }

    pub(crate) fn push_null(&mut self) -> Result<(), ComparisonDigestErrorV1> {
        self.push_field_tag(0)
    }

    pub(crate) fn push_safe_integer(&mut self, value: u64) -> Result<(), ComparisonDigestErrorV1> {
        if value > MAX_SAFE_U64 {
            return Err(ComparisonDigestErrorV1::InvalidValue);
        }
        self.push_field_tag(1)?;
        self.encoding.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    pub(crate) fn push_text(&mut self, value: &[u8]) -> Result<(), ComparisonDigestErrorV1> {
        self.push_bytes(2, value)
    }

    pub(crate) fn push_blob(&mut self, value: &[u8]) -> Result<(), ComparisonDigestErrorV1> {
        self.push_bytes(3, value)
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(COMPARISON_DIGEST_DOMAIN_V1);
        hasher.update(self.field_count.to_be_bytes());
        hasher.update(self.encoding);
        hasher.finalize().into()
    }

    fn push_bytes(&mut self, tag: u8, value: &[u8]) -> Result<(), ComparisonDigestErrorV1> {
        self.push_field_tag(tag)?;
        let length =
            u64::try_from(value.len()).map_err(|_| ComparisonDigestErrorV1::InvalidValue)?;
        self.encoding.extend_from_slice(&length.to_be_bytes());
        self.encoding.extend_from_slice(value);
        Ok(())
    }

    fn push_field_tag(&mut self, tag: u8) -> Result<(), ComparisonDigestErrorV1> {
        self.field_count = self
            .field_count
            .checked_add(1)
            .ok_or(ComparisonDigestErrorV1::FieldCountOverflow)?;
        self.encoding.push(tag);
        Ok(())
    }
}

/// Hashes one typed SQL row, excluding the persisted comparison-digest column itself.
pub(crate) fn joined_comparison_digest_v1(
    row: &Row<'_>,
    digest_index: usize,
) -> Result<[u8; 32], ComparisonDigestErrorV1> {
    if digest_index >= row.as_ref().column_count() {
        return Err(ComparisonDigestErrorV1::InvalidValue);
    }
    let mut builder = ComparisonDigestV1Builder::new();
    for index in 0..row.as_ref().column_count() {
        if index == digest_index {
            continue;
        }
        match row
            .get_ref(index)
            .map_err(|_| ComparisonDigestErrorV1::InvalidValue)?
        {
            ValueRef::Null => builder.push_null()?,
            ValueRef::Integer(value) => builder.push_safe_integer(
                u64::try_from(value)
                    .ok()
                    .filter(|value| *value <= MAX_SAFE_U64)
                    .ok_or(ComparisonDigestErrorV1::InvalidValue)?,
            )?,
            ValueRef::Text(value) => builder.push_text(value)?,
            ValueRef::Blob(value) => builder.push_blob(value)?,
            ValueRef::Real(_) => return Err(ComparisonDigestErrorV1::InvalidValue),
        }
    }
    Ok(builder.finish())
}

/// Recomputes one operation's digest from the frozen immutable projection.
///
/// `Transaction` dereferences to `Connection`, so the production writer can invoke this
/// inside the same transaction that staged the joined rows.
pub(crate) fn immutable_comparison_digest_for_operation_v1(
    connection: &Connection,
    operation_id: &str,
) -> Result<[u8; 32], ComparisonDigestErrorV1> {
    let sql = format!(
        "SELECT {IMMUTABLE_COMPARISON_DIGEST_PROJECTION_V1_SQL} \
         {COMPARISON_DIGEST_JOIN_V1_SQL} \
         WHERE comparison.operation_id = ?1"
    );
    connection
        .query_row(&sql, [operation_id], |row| {
            joined_comparison_digest_v1(row, 0).map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .optional()
        .map_err(|_| ComparisonDigestErrorV1::InvalidValue)?
        .ok_or(ComparisonDigestErrorV1::InvalidValue)
}

/// Reads persisted and recomputed digests from one immutable projection snapshot.
pub(crate) fn persisted_comparison_digests_v1(
    connection: &Connection,
) -> Result<Vec<PersistedComparisonDigestV1>, ComparisonDigestErrorV1> {
    let sql = format!(
        "SELECT {IMMUTABLE_COMPARISON_DIGEST_PROJECTION_V1_SQL} \
         {COMPARISON_DIGEST_JOIN_V1_SQL} \
         ORDER BY comparison.operation_id"
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| ComparisonDigestErrorV1::InvalidValue)?;
    let rows = statement
        .query_map([], |row| {
            let persisted = exact_digest(row, 0)?;
            let recomputed =
                joined_comparison_digest_v1(row, 0).map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(PersistedComparisonDigestV1 {
                operation_id: row.get(1)?,
                persisted,
                recomputed,
            })
        })
        .map_err(|_| ComparisonDigestErrorV1::InvalidValue)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| ComparisonDigestErrorV1::InvalidValue)
}

/// Verifies every persisted digest against the same immutable projection used by writers.
pub(crate) fn verify_persisted_comparison_digests_v1(
    connection: &Connection,
) -> Result<(), ComparisonDigestErrorV1> {
    for digest in persisted_comparison_digests_v1(connection)? {
        if digest.operation_id.is_empty() || digest.persisted != digest.recomputed {
            return Err(ComparisonDigestErrorV1::InvalidValue);
        }
    }
    Ok(())
}

fn exact_digest(row: &Row<'_>, index: usize) -> rusqlite::Result<[u8; 32]> {
    let value = row.get_ref(index)?;
    let bytes = value.as_blob()?;
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidColumnType(index, "digest".to_owned(), value.data_type())
    })
}
