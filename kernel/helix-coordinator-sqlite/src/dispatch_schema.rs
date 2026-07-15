//! Private strict schema-V2 verification for the additive PLAN-005 dispatch overlay.
//!
//! This module intentionally exposes no ordinary open or migration workflow. T027 must
//! acquire the reviewed maintenance custody, apply the overlay transaction, classify an
//! uncertain commit by readback, and only then construct the private V2 store seam.

#![allow(dead_code)]

use crate::connection::{open_and_verify_existing_store_v2, open_bound_existing_connection};
#[cfg(feature = "test-fault-injection")]
use crate::dispatch::dispatch_lookup_fault_injected_v1;
use crate::dispatch::{
    commit_dispatch_transaction_v1, derive_dispatch_commit_bindings_v1,
    CoordinatorDispatchCommitReceiptV1, CoordinatorDispatchUncertainCommitCustodyV1,
};
use crate::dispatch_events::DispatchMetricsV1;
#[cfg(feature = "test-fault-injection")]
use crate::dispatch_fault::CoordinatorDispatchFaultProbeV1;
use crate::dispatch_readback::readback_uncertain_dispatch_v1;
use crate::dispatch_receipt::{
    commit_execution_receipt_v1 as commit_execution_receipt_transaction_v1,
    CoordinatorReceiptCommitOutcomeV1, CoordinatorReceiptLookupV1,
};
#[cfg(not(feature = "test-fault-injection"))]
use crate::dispatch_reconciliation::commit_definite_refusal_v1 as commit_definite_refusal_transaction_v1;
#[cfg(feature = "test-fault-injection")]
use crate::dispatch_reconciliation::commit_definite_refusal_with_fault_probe_v1 as commit_definite_refusal_transaction_with_fault_probe_v1;
use crate::dispatch_reconciliation::{
    claim_or_resume_readback_sequence_v1 as claim_or_resume_readback_sequence_transaction_v1,
    commit_late_consumed_receipt_v1 as commit_late_consumed_receipt_transaction_v1,
    commit_outcome_unknown_v1 as commit_outcome_unknown_transaction_v1,
    commit_reconciliation_required_unknown_v1 as commit_reconciliation_required_transaction_v1,
    CoordinatorDefiniteRefusalOutcomeV1, CoordinatorReadbackExhaustionV1,
    CoordinatorReadbackSequenceClaimOutcomeV1, CoordinatorReadbackSequenceClaimV1,
    CoordinatorReconciliationLookupV1, CoordinatorReconciliationOutcomeV1,
};
use crate::error::InternalCoordinatorError;
use crate::root_safety::CoordinatorRootIdentityV1;
use crate::schema::{
    self, StoreSummary, COORDINATOR_STORE_APPLICATION_ID_V1, COORDINATOR_STORE_SCHEMA_V1_SQL,
};
use crate::{
    CoordinatorFaultProbeV1, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
    CoordinatorStoreOpenErrorV1, SqliteCoordinatorStoreV1,
};
use helix_contracts::{decode_and_verify_plan, Ed25519KeyResolver, MAX_SAFE_U64};
use helix_dispatch_contracts::{GrantKeyResolver, ReceiptKeyResolver};
use helix_dispatch_inbox_sqlite::{
    audit_and_retain_adapter_projection_v1, AdapterCorruptionAuditErrorV1,
    AdapterCorruptionAuditLifecycleV1, AdapterCorruptionAuditOutcomeV1,
    AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditPauseV1,
    AdapterCorruptionAuditSelectionV1, AdapterInboxStoreConfigV1, SqliteDispatchInboxStoreV1,
};
use helix_plan_dispatch::{
    DispatchCapacityVectorV1, DispatchCommitCandidateV1, DispatchCommitPermitV1,
    DispatchCommitResolutionV1, DispatchCoordinatorStoreV1, DispatchDefiniteAbsenceProofV1,
    DispatchEffectDescriptorV1, DispatchGuardValidationV1, DispatchLookupRequestV1,
    DispatchNoConsumptionTombstoneCustodyV1, DispatchReloadOutcomeV1, DispatchReloadedCandidateV1,
    DispatchRetainedProjectionV1, DispatchStoreCommitClassificationV1,
    DispatchStoreReadbackOutcomeV1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

#[path = "dispatch_preflight.rs"]
pub(crate) mod dispatch_preflight;

pub(crate) const COORDINATOR_DISPATCH_SCHEMA_VERSION_V2: i64 = 2;
pub(crate) const ACTIVE_HANDOFF_RECORD_STATE_V1: &str = "DISPATCHING";
pub(crate) const COORDINATOR_DISPATCH_SCHEMA_V2_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
));

const COORDINATOR_DISPATCH_SCHEMA_V2_SHA256: [u8; 32] = [
    0x87, 0x79, 0x9d, 0x20, 0xf2, 0xcb, 0xa3, 0xcd, 0x9d, 0x84, 0xe8, 0xc7, 0xd0, 0x6d, 0x21, 0xc9,
    0xbe, 0xcf, 0x06, 0xfc, 0x1a, 0x33, 0xf2, 0xa0, 0xe6, 0x18, 0x32, 0x87, 0x99, 0x48, 0xd4, 0x1f,
];

const REQUIRED_APPEND_ONLY_TRIGGERS_V2: &[&str] = &[
    "dispatch_store_meta_no_delete",
    "coordinator_v2_migrations_no_update",
    "coordinator_v2_migrations_no_delete",
    "dispatch_comparisons_no_update",
    "dispatch_comparisons_no_delete",
    "dispatch_grants_no_update",
    "dispatch_grants_no_delete",
    "dispatch_records_no_delete",
    "dispatch_transitions_no_update",
    "dispatch_transitions_no_delete",
    "dispatch_outbox_no_delete",
    "dispatch_delivery_attempts_no_update",
    "dispatch_delivery_attempts_no_delete",
    "dispatch_receipts_no_update",
    "dispatch_receipts_no_delete",
    "dispatch_reconciliations_no_update",
    "dispatch_reconciliations_no_delete",
    "dispatch_events_no_delete",
    "dispatch_definite_refusal_guards_no_update",
    "dispatch_definite_refusal_guards_no_delete",
];

const REQUIRED_ACTIVE_ROOT_TRIGGERS_V2: &[&str] = &[
    "dispatch_grants_active_root_guard",
    "dispatch_records_active_insert_guard",
    "dispatch_records_update_guard",
    "dispatch_outbox_update_guard",
    "dispatch_delivery_attempts_active_root_guard",
];

const REQUIRED_GRAPH_GUARDS_V2: &[&str] = &[
    "dispatch_store_meta_single_row_guard",
    "dispatch_store_meta_update_guard",
    "dispatch_transitions_current_projection_guard",
    "dispatch_overlay_guards_v1_operation",
    "dispatch_overlay_guards_v1_reservation",
];

const REQUIRED_PERMANENT_HISTORY_DELETE_GUARDS_V1: &[(&str, &str)] = &[
    ("dispatch_store_meta_no_delete", "dispatch_store_meta"),
    (
        "coordinator_v2_migrations_no_delete",
        "coordinator_v2_migrations",
    ),
    ("dispatch_comparisons_no_delete", "dispatch_comparisons"),
    ("dispatch_grants_no_delete", "dispatch_grants"),
    ("dispatch_records_no_delete", "dispatch_records"),
    ("dispatch_transitions_no_delete", "dispatch_transitions"),
    ("dispatch_outbox_no_delete", "dispatch_outbox"),
    (
        "dispatch_delivery_attempts_no_delete",
        "dispatch_delivery_attempts",
    ),
    ("dispatch_receipts_no_delete", "dispatch_receipts"),
    (
        "dispatch_reconciliations_no_delete",
        "dispatch_reconciliations",
    ),
    ("dispatch_events_no_delete", "dispatch_events"),
    (
        "dispatch_definite_refusal_guards_no_delete",
        "dispatch_definite_refusal_guards",
    ),
];

const REQUIRED_PERMANENT_HISTORY_GENERATION_INDEXES_V1: &[(&str, &str, &str)] = &[
    (
        "coordinator_v2_migrations_generation_uq",
        "coordinator_v2_migrations",
        "migration_generation",
    ),
    (
        "dispatch_comparisons_generation_uq",
        "dispatch_comparisons",
        "comparison_generation",
    ),
    (
        "dispatch_grants_generation_uq",
        "dispatch_grants",
        "created_generation",
    ),
    (
        "dispatch_records_state_generation_uq",
        "dispatch_records",
        "state_generation",
    ),
    (
        "dispatch_outbox_delivery_generation_uq",
        "dispatch_outbox",
        "delivery_generation",
    ),
    (
        "dispatch_receipts_generation_uq",
        "dispatch_receipts",
        "receipt_generation",
    ),
    (
        "dispatch_reconciliations_generation_uq",
        "dispatch_reconciliations",
        "reconciliation_generation",
    ),
    (
        "dispatch_events_generation_uq",
        "dispatch_events",
        "event_generation",
    ),
    (
        "dispatch_definite_refusal_guards_generation_uq",
        "dispatch_definite_refusal_guards",
        "guard_generation",
    ),
];

const DISPATCH_MIGRATION_SUMMARY_DOMAIN_V2: &[u8] =
    b"HELIXOS\0COORDINATOR-DISPATCH-MIGRATION-SUMMARY\0V2\0";
const DISPATCH_MIGRATION_FINAL_PRAGMA_V2: &str = "PRAGMA user_version = 2;\n";

#[derive(Clone, PartialEq, Eq)]
struct SchemaObjectV2 {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct DispatchGenerationsV2 {
    store: u64,
    dispatch: u64,
    delivery: u64,
    receipt: u64,
    reconciliation: u64,
    event: u64,
    migration: u64,
    restore_state: u64,
}

/// Signed generation projection for one ACTIVE coordinator dispatch backup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DispatchRestoreSourceGenerationsV1(DispatchGenerationsV2);

impl DispatchRestoreSourceGenerationsV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        store: u64,
        dispatch: u64,
        delivery: u64,
        receipt: u64,
        reconciliation: u64,
        event: u64,
        migration: u64,
        restore_state: u64,
    ) -> Result<Self, InternalCoordinatorError> {
        if [
            store,
            dispatch,
            delivery,
            receipt,
            reconciliation,
            event,
            migration,
            restore_state,
        ]
        .into_iter()
        .any(|generation| generation > MAX_SAFE_U64)
            || [
                dispatch,
                delivery,
                receipt,
                reconciliation,
                event,
                migration,
                restore_state,
            ]
            .into_iter()
            .any(|generation| generation > store)
            || migration == 0
            || restore_state != 0
        {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
        Ok(Self(DispatchGenerationsV2 {
            store,
            dispatch,
            delivery,
            receipt,
            reconciliation,
            event,
            migration,
            restore_state,
        }))
    }

    pub(crate) const fn store(self) -> u64 {
        self.0.store
    }
}

impl fmt::Debug for DispatchRestoreSourceGenerationsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchRestoreSourceGenerationsV1")
            .finish_non_exhaustive()
    }
}

/// Exact ACTIVE source proof retained before the local restore transition.
pub(crate) struct VerifiedImportedDispatchBackupV1 {
    source_root_identity: CoordinatorRootIdentityV1,
    base_generations: schema::CoordinatorLifecycleGenerationsV1,
    dispatch_generations: DispatchRestoreSourceGenerationsV1,
}

impl VerifiedImportedDispatchBackupV1 {
    pub(crate) const fn source_root_identity(&self) -> CoordinatorRootIdentityV1 {
        self.source_root_identity
    }

    pub(crate) const fn base_generations(&self) -> schema::CoordinatorLifecycleGenerationsV1 {
        self.base_generations
    }

    pub(crate) const fn dispatch_generations(&self) -> DispatchRestoreSourceGenerationsV1 {
        self.dispatch_generations
    }
}

impl fmt::Debug for VerifiedImportedDispatchBackupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedImportedDispatchBackupV1")
            .finish_non_exhaustive()
    }
}

/// Complete binding for the sole local coordinator-V2 ACTIVE -> RESTORE_PENDING change.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DispatchRestorePendingBindingsV1 {
    base: schema::RestorePendingBindingsV1,
    source_dispatch_generations: DispatchRestoreSourceGenerationsV1,
    restore_index_digest: [u8; 32],
}

impl DispatchRestorePendingBindingsV1 {
    pub(crate) fn try_new(
        source_base_generations: schema::CoordinatorLifecycleGenerationsV1,
        source_dispatch_generations: DispatchRestoreSourceGenerationsV1,
        new_root_identity: CoordinatorRootIdentityV1,
        restore_identity_digest: [u8; 32],
        restore_index_digest: [u8; 32],
    ) -> Result<Self, InternalCoordinatorError> {
        let base = schema::RestorePendingBindingsV1::try_new(
            source_base_generations,
            new_root_identity,
            helix_contracts::Sha256Digest::from_bytes(restore_identity_digest),
            helix_contracts::Sha256Digest::from_bytes(restore_index_digest),
            source_base_generations.store(),
        )?;
        source_dispatch_generations
            .store()
            .checked_add(1)
            .filter(|generation| *generation <= MAX_SAFE_U64)
            .ok_or(InternalCoordinatorError::InvariantFailed)?;
        Ok(Self {
            base,
            source_dispatch_generations,
            restore_index_digest,
        })
    }

    pub(crate) const fn new_root_identity(self) -> CoordinatorRootIdentityV1 {
        self.base.new_root_identity()
    }
}

impl fmt::Debug for DispatchRestorePendingBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchRestorePendingBindingsV1")
            .finish_non_exhaustive()
    }
}

/// Redacted proof that both metadata projections are pending under one local commit.
pub(crate) struct VerifiedDispatchRestorePendingV1 {
    base: schema::VerifiedRestorePendingV1,
    generations: DispatchGenerationsV2,
}

impl VerifiedDispatchRestorePendingV1 {
    pub(crate) const fn root_identity(&self) -> CoordinatorRootIdentityV1 {
        self.base.summary().root_identity
    }

    pub(crate) const fn store_generation(&self) -> u64 {
        self.generations.store
    }
}

impl fmt::Debug for VerifiedDispatchRestorePendingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDispatchRestorePendingV1")
            .field("store_generation", &self.generations.store)
            .finish_non_exhaustive()
    }
}

/// Closed PLAN-005 v1 retention and storage-claim policy.
///
/// This policy describes logical authority retention only. Requiring an approved
/// encrypted-at-rest profile is not a claim that SQLite can prove physical erasure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorDispatchRetentionPolicyV1 {
    history_is_permanent: bool,
    history_is_append_only: bool,
    history_deletion_enabled: bool,
    identifier_reuse_enabled: bool,
    generation_reuse_enabled: bool,
    automatic_pruning_enabled: bool,
    physical_secure_erasure_claimed: bool,
    requires_approved_encrypted_at_rest_profile: bool,
}

impl CoordinatorDispatchRetentionPolicyV1 {
    pub(crate) const fn history_is_permanent(self) -> bool {
        self.history_is_permanent
    }

    pub(crate) const fn history_is_append_only(self) -> bool {
        self.history_is_append_only
    }

    pub(crate) const fn history_deletion_enabled(self) -> bool {
        self.history_deletion_enabled
    }

    pub(crate) const fn identifier_reuse_enabled(self) -> bool {
        self.identifier_reuse_enabled
    }

    pub(crate) const fn generation_reuse_enabled(self) -> bool {
        self.generation_reuse_enabled
    }

    pub(crate) const fn automatic_pruning_enabled(self) -> bool {
        self.automatic_pruning_enabled
    }

    pub(crate) const fn physical_secure_erasure_claimed(self) -> bool {
        self.physical_secure_erasure_claimed
    }

    pub(crate) const fn requires_approved_encrypted_at_rest_profile(self) -> bool {
        self.requires_approved_encrypted_at_rest_profile
    }
}

pub(crate) const fn coordinator_dispatch_retention_policy_v1(
) -> CoordinatorDispatchRetentionPolicyV1 {
    CoordinatorDispatchRetentionPolicyV1 {
        history_is_permanent: true,
        history_is_append_only: true,
        history_deletion_enabled: false,
        identifier_reuse_enabled: false,
        generation_reuse_enabled: false,
        automatic_pruning_enabled: false,
        physical_secure_erasure_claimed: false,
        requires_approved_encrypted_at_rest_profile: true,
    }
}

/// Non-forgeable result of exact V1-base plus V2-overlay verification.
pub(crate) struct VerifiedDispatchSchemaV2 {
    base_summary: StoreSummary,
    generations: DispatchGenerationsV2,
}

/// Bounded, attempt-specific metadata supplied to the private maintenance workflow.
///
/// The verified backup digest and all source bindings are deliberately absent: they
/// are derived from the live quiescent cut and the reopened backup, never accepted
/// from the migration caller.
pub(crate) struct DispatchMigrationRequestV2 {
    migration_attempt_id: [u8; 32],
    migrated_at_utc_ms: u64,
    migrated_at_monotonic_ms: u64,
    tool_identity: Box<str>,
}

impl DispatchMigrationRequestV2 {
    pub(crate) fn try_new(
        migration_attempt_id: [u8; 32],
        migrated_at_utc_ms: u64,
        migrated_at_monotonic_ms: u64,
        tool_identity: &str,
    ) -> Result<Self, InternalCoordinatorError> {
        if migration_attempt_id == [0; 32]
            || migrated_at_utc_ms > MAX_SAFE_U64
            || migrated_at_monotonic_ms > MAX_SAFE_U64
            || !valid_tool_identity_v2(tool_identity)
        {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
        Ok(Self {
            migration_attempt_id,
            migrated_at_utc_ms,
            migrated_at_monotonic_ms,
            tool_identity: tool_identity.into(),
        })
    }
}

impl fmt::Debug for DispatchMigrationRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchMigrationRequestV2")
            .finish_non_exhaustive()
    }
}

/// Exact receipt bindings retained across a possibly uncertain COMMIT.
pub(crate) struct DispatchMigrationReceiptV2 {
    migration_attempt_id: [u8; 32],
    source_schema_digest: [u8; 32],
    source_root_identity: [u8; 32],
    source_summary_digest: [u8; 32],
    verified_backup_digest: [u8; 32],
    overlay_schema_digest: [u8; 32],
    migrated_at_utc_ms: u64,
    migrated_at_monotonic_ms: u64,
    tool_identity: Box<str>,
}

impl fmt::Debug for DispatchMigrationReceiptV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchMigrationReceiptV2")
            .finish_non_exhaustive()
    }
}

pub(crate) enum DispatchMigrationReadbackV2 {
    Committed(VerifiedDispatchSchemaV2),
    ConfirmedRollback,
    Conflict,
    Unavailable,
}

impl fmt::Debug for DispatchMigrationReadbackV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "DispatchMigrationReadbackV2::Committed(..)",
            Self::ConfirmedRollback => "DispatchMigrationReadbackV2::ConfirmedRollback",
            Self::Conflict => "DispatchMigrationReadbackV2::Conflict",
            Self::Unavailable => "DispatchMigrationReadbackV2::Unavailable",
        })
    }
}

impl fmt::Debug for VerifiedDispatchSchemaV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDispatchSchemaV2")
            .finish_non_exhaustive()
    }
}

/// Private type seam for the future explicit migration workflow.
///
/// It composes, rather than replaces, the unchanged PLAN-004 store. No constructor is
/// reachable from the public crate surface and no ordinary V1 open can produce it.
pub struct SqliteCoordinatorStoreV2<C, R> {
    base: SqliteCoordinatorStoreV1<C, R>,
    verified_schema: VerifiedDispatchSchemaV2,
    metrics: DispatchMetricsV1,
    #[cfg(feature = "test-fault-injection")]
    dispatch_fault_probe: CoordinatorDispatchFaultProbeV1,
}

struct RetainedAdapterCorruptionAuditPauseV1<'custody, P> {
    custody: &'custody mut P,
    evidence: AdapterCorruptionAuditPauseEvidenceV1,
    captured: bool,
}

impl<P> AdapterCorruptionAuditPauseV1 for RetainedAdapterCorruptionAuditPauseV1<'_, P>
where
    P: AdapterCorruptionAuditPauseV1,
{
    fn capture_adapter_corruption_audit_pause_v1(
        &mut self,
    ) -> Result<AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditErrorV1> {
        if self.captured {
            return Err(AdapterCorruptionAuditErrorV1::InvariantFailed);
        }
        self.captured = true;
        Ok(self.evidence)
    }

    fn recheck_adapter_corruption_audit_pause_v1(
        &mut self,
        expected: &AdapterCorruptionAuditPauseEvidenceV1,
    ) -> Result<(), AdapterCorruptionAuditErrorV1> {
        if !self.captured || expected != &self.evidence {
            return Err(AdapterCorruptionAuditErrorV1::InvariantFailed);
        }
        self.custody
            .recheck_adapter_corruption_audit_pause_v1(expected)
    }
}

fn map_adapter_corruption_coordinator_error_v1(
    error: InternalCoordinatorError,
) -> AdapterCorruptionAuditErrorV1 {
    match error {
        InternalCoordinatorError::RootBusy => AdapterCorruptionAuditErrorV1::Busy,
        InternalCoordinatorError::RestorePending => AdapterCorruptionAuditErrorV1::RestorePending,
        InternalCoordinatorError::ApplicationIdMismatch
        | InternalCoordinatorError::SchemaUnsupported
        | InternalCoordinatorError::SchemaInvalid
        | InternalCoordinatorError::IntegrityFailed
        | InternalCoordinatorError::InvariantFailed
        | InternalCoordinatorError::JsonContractInvalid
        | InternalCoordinatorError::ProvenanceInvalid
        | InternalCoordinatorError::RootIdentityMismatch => {
            AdapterCorruptionAuditErrorV1::InvariantFailed
        }
        InternalCoordinatorError::ClockUnavailable
        | InternalCoordinatorError::DeadlineReached
        | InternalCoordinatorError::RootInvalid
        | InternalCoordinatorError::RootNotDedicated
        | InternalCoordinatorError::RootRoleMismatch
        | InternalCoordinatorError::RootUnavailable
        | InternalCoordinatorError::UnknownRootMember
        | InternalCoordinatorError::DurabilityProfileUnavailable => {
            AdapterCorruptionAuditErrorV1::Unavailable
        }
    }
}

/// Opaque V2 reload retained between lookup and one guarded commit.
pub struct SqliteDispatchReloadedV1 {
    durable: dispatch_preflight::DurableDispatchReloadV1,
    target_root_id: Box<str>,
    target_components: Box<[String]>,
    precondition_digest: [u8; 32],
    content_digest: [u8; 32],
    content_byte_length: u64,
    content_media_type: Box<str>,
    required_capacity: DispatchCapacityVectorV1,
    held_capacity: DispatchCapacityVectorV1,
    prior: Option<DispatchRetainedProjectionV1>,
}

impl fmt::Debug for SqliteDispatchReloadedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteDispatchReloadedV1")
            .finish_non_exhaustive()
    }
}

impl DispatchReloadedCandidateV1 for SqliteDispatchReloadedV1 {
    fn effect_descriptor_v1(&self) -> Option<DispatchEffectDescriptorV1> {
        DispatchEffectDescriptorV1::try_from_portable_parts(
            self.durable.preparation_transition_generation(),
            &self.target_root_id,
            self.target_components.to_vec(),
            self.precondition_digest,
            self.content_digest,
            self.content_byte_length,
            self.content_media_type.to_string(),
        )
        .ok()
    }

    fn required_capacity_v1(&self) -> Option<DispatchCapacityVectorV1> {
        Some(self.required_capacity)
    }

    fn held_capacity_v1(&self) -> Option<DispatchCapacityVectorV1> {
        Some(self.held_capacity)
    }

    fn prior_dispatch_projection_v1(&self) -> Option<DispatchRetainedProjectionV1> {
        self.prior
    }
}

impl<C, R> SqliteCoordinatorStoreV2<C, R> {
    pub(crate) fn from_verified_parts(
        base: SqliteCoordinatorStoreV1<C, R>,
        verified_schema: VerifiedDispatchSchemaV2,
    ) -> Self {
        Self {
            base,
            verified_schema,
            metrics: DispatchMetricsV1::default(),
            #[cfg(feature = "test-fault-injection")]
            dispatch_fault_probe: CoordinatorDispatchFaultProbeV1::disabled_v1(),
        }
    }

    pub(crate) const fn base_store_v1(&self) -> &SqliteCoordinatorStoreV1<C, R> {
        &self.base
    }

    #[cfg(feature = "test-fault-injection")]
    pub(crate) const fn dispatch_fault_probe_v1(&self) -> &CoordinatorDispatchFaultProbeV1 {
        &self.dispatch_fault_probe
    }

    /// Selects one exact PLAN-005 checkpoint for a non-default conformance driver.
    #[doc(hidden)]
    #[cfg(feature = "test-fault-injection")]
    pub fn select_dispatch_fault_for_test_v1<F>(
        &mut self,
        boundary_id: &str,
        occurrence: u64,
        mode: helix_plan_dispatch::FaultInjectionModeV1,
        process_barrier: F,
    ) -> Result<(), helix_plan_dispatch::FaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        self.dispatch_fault_probe =
            CoordinatorDispatchFaultProbeV1::select_dispatch_handoff_readback_fault_id_v1(
                boundary_id,
                occurrence,
                mode,
                process_barrier,
            )?;
        Ok(())
    }

    /// Reports only whether the explicit feature-gated store probe injected once.
    #[doc(hidden)]
    #[cfg(feature = "test-fault-injection")]
    pub fn dispatch_fault_probe_injected_for_test_v1(&self) -> bool {
        self.dispatch_fault_probe.portable_probe_v1().injected_v1()
    }
}

impl<C, R> SqliteCoordinatorStoreV2<C, R>
where
    C: crate::CoordinatorMonotonicClockV1,
    R: Ed25519KeyResolver,
{
    /// Opens only an already-published exact V2 root.
    ///
    /// Empty/V1 roots are refused and no migration, repair, or downgrade is attempted.
    pub fn open_existing(
        config: CoordinatorStoreConfigV1,
        clock: C,
        historical_plan_keys: R,
        deadline_monotonic_ms: u64,
    ) -> Result<Self, CoordinatorStoreOpenErrorV1> {
        let (config, expected_identity, verified_schema, observer) =
            open_and_verify_existing_store_v2(
                config,
                &clock,
                deadline_monotonic_ms,
                |connection, expected_identity| {
                    let version: i64 = connection
                        .pragma_query_value(None, "user_version", |row| row.get(0))
                        .map_err(schema_invalid_v2)?;
                    if version != COORDINATOR_DISPATCH_SCHEMA_VERSION_V2 {
                        return Err(InternalCoordinatorError::SchemaUnsupported);
                    }
                    verify_dispatch_schema_v2(connection, expected_identity, &historical_plan_keys)
                },
            )
            .map_err(CoordinatorStoreOpenErrorV1::from_internal)?;
        let base_summary = verified_schema.base_summary;
        let base = SqliteCoordinatorStoreV1 {
            config,
            clock,
            historical_plan_keys,
            schema_cookie: base_summary.schema_cookie,
            operation_count: base_summary.operation_count,
            root_identity: CoordinatorRootIdentityEvidenceV1::from_internal(expected_identity),
            live_verification: Mutex::new(observer),
            uncertain_custody: Mutex::new(HashMap::new()),
            fault_probe: CoordinatorFaultProbeV1::disabled_v1(),
        };
        Ok(Self::from_verified_parts(base, verified_schema))
    }

    pub const fn operation_count(&self) -> u64 {
        self.base.operation_count
    }

    pub const fn root_identity_evidence(&self) -> CoordinatorRootIdentityEvidenceV1 {
        self.base.root_identity
    }

    /// Audits one adapter projection while retaining two complete strict coordinator-V2 roots.
    ///
    /// `self` is the separately retained trusted checkpoint. `observed_coordinator` is opened
    /// under its own provisioner-attested root/file lease and is never replaced by a synthetic
    /// two-table projection. Both complete V2 graphs are verified before the adapter begins its
    /// coordinator-first `BEGIN IMMEDIATE` cut, remain bound for the whole audit, and are fully
    /// verified and revalidated again before return.
    ///
    /// The coordinator supplies the exact lifecycle and bounded relationship selection while
    /// sovereign PAUSE custody is live. PAUSE is rechecked immediately before the adapter cut and
    /// after both coordinator roots have been revalidated. The only returned values are the
    /// adapter audit's payload-free outcome or closed error; no PAUSE proof, root identity, path,
    /// digest, connection, or execution authority escapes this boundary.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn audit_and_retain_adapter_corruption_under_pause_v1<P>(
        &self,
        pause_custody: &mut P,
        observed_coordinator: CoordinatorStoreConfigV1,
        trusted_adapter: &SqliteDispatchInboxStoreV1,
        observed_adapter: AdapterInboxStoreConfigV1,
        custody_adapter: AdapterInboxStoreConfigV1,
        selection: &AdapterCorruptionAuditSelectionV1,
        lifecycle: AdapterCorruptionAuditLifecycleV1,
        deadline_monotonic_ms: u64,
    ) -> Result<AdapterCorruptionAuditOutcomeV1, AdapterCorruptionAuditErrorV1>
    where
        P: AdapterCorruptionAuditPauseV1,
    {
        let pause = pause_custody.capture_adapter_corruption_audit_pause_v1()?;

        // Lock order is fixed across production callers: trusted coordinator root, observed
        // coordinator root, then the adapter-owned coordinator transaction and adapter roots.
        let mut trusted_bound = open_bound_existing_connection(
            &self.base.config,
            &self.base.clock,
            deadline_monotonic_ms,
        )
        .map_err(map_adapter_corruption_coordinator_error_v1)?;
        let trusted_identity = trusted_bound.expected_root_identity();
        verify_dispatch_schema_v2(
            trusted_bound.connection_mut(),
            trusted_identity,
            &self.base.historical_plan_keys,
        )
        .map_err(map_adapter_corruption_coordinator_error_v1)?;

        let mut observed_bound = open_bound_existing_connection(
            &observed_coordinator,
            &self.base.clock,
            deadline_monotonic_ms,
        )
        .map_err(map_adapter_corruption_coordinator_error_v1)?;
        let observed_identity = observed_bound.expected_root_identity();
        verify_dispatch_schema_v2(
            observed_bound.connection_mut(),
            observed_identity,
            &self.base.historical_plan_keys,
        )
        .map_err(map_adapter_corruption_coordinator_error_v1)?;

        let audit = {
            // The adapter owns the immediate counterpart/adapter transaction and must execute
            // its own before/after PAUSE checks. This wrapper returns the one proof already
            // captured by the coordinator, then delegates every recheck to the same sovereign
            // custody instead of creating a second PAUSE contract or taking a second capture.
            let mut retained_pause = RetainedAdapterCorruptionAuditPauseV1 {
                custody: pause_custody,
                evidence: pause,
                captured: false,
            };
            let audit = audit_and_retain_adapter_projection_v1(
                trusted_adapter,
                &mut retained_pause,
                observed_adapter,
                trusted_bound.connection_mut(),
                observed_bound.connection_mut(),
                custody_adapter,
                selection,
                lifecycle,
            );
            if retained_pause.captured {
                audit
            } else {
                Err(AdapterCorruptionAuditErrorV1::InvariantFailed)
            }
        };

        // Do every closing check even when the adapter reported an error. A local adapter fence
        // may already be durable while independent custody is temporarily unavailable.
        let trusted_schema = verify_dispatch_schema_v2(
            trusted_bound.connection_mut(),
            trusted_identity,
            &self.base.historical_plan_keys,
        );
        let observed_schema = verify_dispatch_schema_v2(
            observed_bound.connection_mut(),
            observed_identity,
            &self.base.historical_plan_keys,
        );
        let trusted_binding = trusted_bound.revalidate(&self.base.clock, deadline_monotonic_ms);
        let observed_binding = observed_bound.revalidate(&self.base.clock, deadline_monotonic_ms);
        let pause_recheck = pause_custody.recheck_adapter_corruption_audit_pause_v1(&pause);

        trusted_schema.map_err(map_adapter_corruption_coordinator_error_v1)?;
        observed_schema.map_err(map_adapter_corruption_coordinator_error_v1)?;
        trusted_binding.map_err(map_adapter_corruption_coordinator_error_v1)?;
        observed_binding.map_err(map_adapter_corruption_coordinator_error_v1)?;
        pause_recheck?;
        audit
    }

    /// Verifies and durably records one exact adapter receipt on this bound V2 root.
    ///
    /// The root/file lease is acquired before receipt bytes are inspected. The complete V2
    /// graph is reverified inside the same immediate writer transaction that retains the
    /// receipt and advances the dispatch projection, then the root is revalidated on return.
    pub fn commit_execution_receipt_v1<K>(
        &self,
        lookup: CoordinatorReceiptLookupV1,
        canonical_receipt: &[u8],
        deadline_monotonic_ms: u64,
        key_resolver: &K,
    ) -> CoordinatorReceiptCommitOutcomeV1
    where
        K: GrantKeyResolver + ReceiptKeyResolver,
    {
        let mut bound = match open_bound_existing_connection(
            &self.base.config,
            &self.base.clock,
            deadline_monotonic_ms,
        ) {
            Ok(bound) => bound,
            Err(_) => return CoordinatorReceiptCommitOutcomeV1::Unavailable,
        };
        let expected_root_identity = bound.expected_root_identity();
        let outcome = commit_execution_receipt_transaction_v1(
            bound.connection_mut(),
            lookup,
            canonical_receipt,
            key_resolver,
            #[cfg(feature = "test-fault-injection")]
            &self.dispatch_fault_probe,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
        );
        if bound
            .revalidate(&self.base.clock, deadline_monotonic_ms)
            .is_err()
            && !matches!(outcome, CoordinatorReceiptCommitOutcomeV1::Uncertain(_))
        {
            return CoordinatorReceiptCommitOutcomeV1::Unhealthy;
        }
        outcome
    }

    /// Atomically owns or resumes the one automatic readback sequence for a possible handoff.
    pub fn claim_or_resume_readback_sequence_v1(
        &self,
        lookup: &CoordinatorReconciliationLookupV1,
        claim: &CoordinatorReadbackSequenceClaimV1,
        deadline_monotonic_ms: u64,
    ) -> CoordinatorReadbackSequenceClaimOutcomeV1 {
        let mut bound = match open_bound_existing_connection(
            &self.base.config,
            &self.base.clock,
            deadline_monotonic_ms,
        ) {
            Ok(bound) => bound,
            Err(_) => return CoordinatorReadbackSequenceClaimOutcomeV1::Unavailable,
        };
        let expected_root_identity = bound.expected_root_identity();
        let outcome = claim_or_resume_readback_sequence_transaction_v1(
            bound.connection_mut(),
            lookup,
            claim,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
        );
        if bound
            .revalidate(&self.base.clock, deadline_monotonic_ms)
            .is_err()
            && !matches!(
                &outcome,
                CoordinatorReadbackSequenceClaimOutcomeV1::Uncertain
            )
        {
            return CoordinatorReadbackSequenceClaimOutcomeV1::Unhealthy;
        }
        outcome
    }

    /// Commits exhausted automatic readback as durable `OUTCOME_UNKNOWN` custody.
    pub fn commit_outcome_unknown_v1(
        &self,
        lookup: &CoordinatorReconciliationLookupV1,
        exhaustion: &CoordinatorReadbackExhaustionV1,
        deadline_monotonic_ms: u64,
    ) -> CoordinatorReconciliationOutcomeV1 {
        let mut bound = match open_bound_existing_connection(
            &self.base.config,
            &self.base.clock,
            deadline_monotonic_ms,
        ) {
            Ok(bound) => bound,
            Err(_) => return CoordinatorReconciliationOutcomeV1::Unavailable,
        };
        let expected_root_identity = bound.expected_root_identity();
        let outcome = commit_outcome_unknown_transaction_v1(
            bound.connection_mut(),
            lookup,
            exhaustion,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
        );
        if bound
            .revalidate(&self.base.clock, deadline_monotonic_ms)
            .is_err()
            && !matches!(&outcome, CoordinatorReconciliationOutcomeV1::Uncertain)
        {
            return CoordinatorReconciliationOutcomeV1::Unhealthy;
        }
        outcome
    }

    /// Advances retained unknown custody to explicit `RECONCILIATION_REQUIRED` once.
    pub fn commit_reconciliation_required_unknown_v1(
        &self,
        lookup: &CoordinatorReconciliationLookupV1,
        deadline_monotonic_ms: u64,
    ) -> CoordinatorReconciliationOutcomeV1 {
        let mut bound = match open_bound_existing_connection(
            &self.base.config,
            &self.base.clock,
            deadline_monotonic_ms,
        ) {
            Ok(bound) => bound,
            Err(_) => return CoordinatorReconciliationOutcomeV1::Unavailable,
        };
        let expected_root_identity = bound.expected_root_identity();
        let outcome = commit_reconciliation_required_transaction_v1(
            bound.connection_mut(),
            lookup,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
        );
        if bound
            .revalidate(&self.base.clock, deadline_monotonic_ms)
            .is_err()
            && !matches!(&outcome, CoordinatorReconciliationOutcomeV1::Uncertain)
        {
            return CoordinatorReconciliationOutcomeV1::Unhealthy;
        }
        outcome
    }

    /// Retains a consumed receipt discovered after unknown custody without restoring execution.
    pub fn commit_late_consumed_receipt_v1<K>(
        &self,
        lookup: &CoordinatorReconciliationLookupV1,
        adapter_root_id: [u8; 32],
        canonical_receipt: &[u8],
        deadline_monotonic_ms: u64,
        key_resolver: &K,
    ) -> CoordinatorReceiptCommitOutcomeV1
    where
        K: GrantKeyResolver + ReceiptKeyResolver,
    {
        let mut bound = match open_bound_existing_connection(
            &self.base.config,
            &self.base.clock,
            deadline_monotonic_ms,
        ) {
            Ok(bound) => bound,
            Err(_) => return CoordinatorReceiptCommitOutcomeV1::Unavailable,
        };
        let expected_root_identity = bound.expected_root_identity();
        let outcome = commit_late_consumed_receipt_transaction_v1(
            bound.connection_mut(),
            lookup,
            adapter_root_id,
            canonical_receipt,
            key_resolver,
            #[cfg(feature = "test-fault-injection")]
            &self.dispatch_fault_probe,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
        );
        if bound
            .revalidate(&self.base.clock, deadline_monotonic_ms)
            .is_err()
            && !matches!(&outcome, CoordinatorReceiptCommitOutcomeV1::Uncertain(_))
        {
            return CoordinatorReceiptCommitOutcomeV1::Unhealthy;
        }
        outcome
    }

    /// Atomically closes one exact fenced definite refusal and releases its reservation once.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_definite_refusal_v1<K>(
        &self,
        lookup: &CoordinatorReconciliationLookupV1,
        canonical_receipt: &[u8],
        deadline_monotonic_ms: u64,
        key_resolver: &K,
        proof: &DispatchDefiniteAbsenceProofV1,
        tombstone: &DispatchNoConsumptionTombstoneCustodyV1,
    ) -> CoordinatorDefiniteRefusalOutcomeV1
    where
        K: GrantKeyResolver + ReceiptKeyResolver,
    {
        let mut bound = match open_bound_existing_connection(
            &self.base.config,
            &self.base.clock,
            deadline_monotonic_ms,
        ) {
            Ok(bound) => bound,
            Err(_) => return CoordinatorDefiniteRefusalOutcomeV1::Unavailable,
        };
        let expected_root_identity = bound.expected_root_identity();
        #[cfg(not(feature = "test-fault-injection"))]
        let outcome = commit_definite_refusal_transaction_v1(
            bound.connection_mut(),
            lookup,
            canonical_receipt,
            key_resolver,
            proof,
            tombstone,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
        );
        #[cfg(feature = "test-fault-injection")]
        let outcome = commit_definite_refusal_transaction_with_fault_probe_v1(
            bound.connection_mut(),
            lookup,
            canonical_receipt,
            key_resolver,
            proof,
            tombstone,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
            &self.dispatch_fault_probe,
        );
        if bound
            .revalidate(&self.base.clock, deadline_monotonic_ms)
            .is_err()
            && !matches!(&outcome, CoordinatorDefiniteRefusalOutcomeV1::Uncertain(_))
        {
            return CoordinatorDefiniteRefusalOutcomeV1::Unhealthy;
        }
        outcome
    }
}

impl<C, R> fmt::Debug for SqliteCoordinatorStoreV2<C, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteCoordinatorStoreV2")
            .finish_non_exhaustive()
    }
}

impl<C, R> DispatchCoordinatorStoreV1 for SqliteCoordinatorStoreV2<C, R>
where
    C: crate::CoordinatorMonotonicClockV1,
    R: Ed25519KeyResolver + Send + Sync,
{
    type ReloadedState = SqliteDispatchReloadedV1;
    type CommitReceipt = CoordinatorDispatchCommitReceiptV1;
    type UncertainCommitCustody = CoordinatorDispatchUncertainCommitCustodyV1;
    type ReadbackEvidence = CoordinatorDispatchCommitReceiptV1;

    fn reload_authoritative_v1(
        &self,
        request: &DispatchLookupRequestV1,
    ) -> DispatchReloadOutcomeV1<Self::ReloadedState> {
        let deadline = request.caller_deadline_monotonic_ms();
        let mut bound =
            match open_bound_existing_connection(&self.base.config, &self.base.clock, deadline) {
                Ok(bound) => bound,
                Err(_) => return DispatchReloadOutcomeV1::Unavailable,
            };
        let expected_root_identity = bound.expected_root_identity();
        let transaction = match bound
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Deferred)
        {
            Ok(transaction) => transaction,
            Err(_) => return DispatchReloadOutcomeV1::Unavailable,
        };
        if verify_dispatch_schema_v2(
            &transaction,
            expected_root_identity,
            &self.base.historical_plan_keys,
        )
        .is_err()
        {
            return DispatchReloadOutcomeV1::Unhealthy;
        }
        let outcome = match dispatch_preflight::reload_authoritative_v1(&transaction, request) {
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Ready(reloaded) => {
                enrich_dispatch_reload_v1(&transaction, reloaded, &self.base.historical_plan_keys)
                    .map_or(
                        DispatchReloadOutcomeV1::Unhealthy,
                        DispatchReloadOutcomeV1::Ready,
                    )
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::PriorExactDispatch(reloaded) => {
                enrich_dispatch_reload_v1(&transaction, reloaded, &self.base.historical_plan_keys)
                    .map_or(
                        DispatchReloadOutcomeV1::Unhealthy,
                        DispatchReloadOutcomeV1::PriorExactDispatch,
                    )
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Missing => {
                DispatchReloadOutcomeV1::Missing
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Torn => {
                DispatchReloadOutcomeV1::Unhealthy
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Restored => {
                DispatchReloadOutcomeV1::Restored
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Failed => {
                DispatchReloadOutcomeV1::Failed
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Quarantined => {
                DispatchReloadOutcomeV1::Quarantined
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Conflict => {
                DispatchReloadOutcomeV1::Conflict
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Unavailable => {
                DispatchReloadOutcomeV1::Unavailable
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::Unhealthy => {
                DispatchReloadOutcomeV1::Unhealthy
            }
            dispatch_preflight::DispatchDurableReloadOutcomeV1::UnsupportedVersion => {
                DispatchReloadOutcomeV1::UnsupportedVersion
            }
        };
        #[cfg(feature = "test-fault-injection")]
        let outcome = if dispatch_lookup_fault_injected_v1(&self.dispatch_fault_probe) {
            DispatchReloadOutcomeV1::Unavailable
        } else {
            outcome
        };
        if transaction.rollback().is_err() || bound.revalidate(&self.base.clock, deadline).is_err()
        {
            return DispatchReloadOutcomeV1::Unhealthy;
        }
        outcome
    }

    fn commit_candidate_once_v1(
        &self,
        candidate: DispatchCommitCandidateV1<Self::ReloadedState>,
    ) -> DispatchStoreCommitClassificationV1<Self::CommitReceipt, Self::UncertainCommitCustody>
    {
        let bindings = derive_dispatch_commit_bindings_v1(&candidate);
        let deadline = bindings.effective_deadline_monotonic_ms;
        let mut bound =
            match open_bound_existing_connection(&self.base.config, &self.base.clock, deadline) {
                Ok(bound) => bound,
                Err(_) => return DispatchStoreCommitClassificationV1::Unavailable,
            };
        let expected_root_identity = bound.expected_root_identity();
        let permit = StoreClosurePermitV1 { deadline };
        let resolution = commit_dispatch_transaction_v1(
            bound.connection_mut(),
            candidate,
            bindings,
            permit,
            &self.metrics,
            #[cfg(feature = "test-fault-injection")]
            &self.dispatch_fault_probe,
            |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            },
        );
        let classification = classification_from_resolution_v1(resolution);
        if bound.revalidate(&self.base.clock, deadline).is_err()
            && !matches!(
                classification,
                DispatchStoreCommitClassificationV1::Uncertain(_)
            )
        {
            return DispatchStoreCommitClassificationV1::Unclassified;
        }
        classification
    }

    fn readback_uncertain_v1(
        &self,
        custody: Self::UncertainCommitCustody,
    ) -> DispatchStoreReadbackOutcomeV1<Self::ReadbackEvidence> {
        let deadline = custody.deadline_monotonic_ms;
        let mut bound =
            match open_bound_existing_connection(&self.base.config, &self.base.clock, deadline) {
                Ok(bound) => bound,
                Err(_) => return DispatchStoreReadbackOutcomeV1::Unavailable,
            };
        let expected_root_identity = bound.expected_root_identity();
        let outcome =
            readback_uncertain_dispatch_v1(bound.connection_mut(), custody, |connection| {
                verify_dispatch_schema_v2(
                    connection,
                    expected_root_identity,
                    &self.base.historical_plan_keys,
                )
                .is_ok()
            });
        if bound.revalidate(&self.base.clock, deadline).is_err() {
            return DispatchStoreReadbackOutcomeV1::Unhealthy;
        }
        outcome
    }
}

fn enrich_dispatch_reload_v1<R: Ed25519KeyResolver>(
    connection: &Connection,
    durable: dispatch_preflight::DurableDispatchReloadV1,
    historical_plan_keys: &R,
) -> Option<SqliteDispatchReloadedV1> {
    let authentic = decode_and_verify_plan(durable.canonical_plan(), historical_plan_keys).ok()?;
    let claims = authentic.preparation_claims();
    if claims.operation_id() != durable.operation_id()
        || claims.plan_id().as_bytes() != durable.plan_digest()
        || claims.task_lease_digest().as_bytes() != durable.task_lease_digest()
        || claims.budget().reservation_id() != durable.reservation_id()
        || crate::derive_target_reference_digest_v1(claims.target())
            .ok()?
            .as_bytes()
            != durable.recovery_target_digest()
    {
        return None;
    }
    let budget = claims.budget();
    let required_capacity = DispatchCapacityVectorV1::try_new(
        budget.max_cost_micro_units(),
        budget.action_limit(),
        budget.egress_bytes_limit(),
        claims.recovery_reserved_bytes(),
    )
    .ok()?;
    let held: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT reserved_cost_micro_units, reserved_action_count, \
                    reserved_egress_bytes, reserved_recovery_bytes \
             FROM budget_reservations WHERE reservation_id = ?1 AND operation_id = ?2 \
               AND reservation_state = 'HELD' AND released_generation IS NULL",
            params![durable.reservation_id(), durable.operation_id()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .ok()?;
    let held_capacity = DispatchCapacityVectorV1::try_new(
        safe_generation_v2(held.0).ok()?,
        safe_generation_v2(held.1).ok()?,
        safe_generation_v2(held.2).ok()?,
        safe_generation_v2(held.3).ok()?,
    )
    .ok()?;
    let prior = match (
        durable.prior_grant_id(),
        durable.prior_grant_digest(),
        durable.prior_dispatch_state_generation(),
    ) {
        (Some(grant_id), Some(grant_digest), Some(state_generation)) => Some(
            DispatchRetainedProjectionV1::try_new(*grant_id, *grant_digest, state_generation)?,
        ),
        (None, None, None) => None,
        _ => return None,
    };
    Some(SqliteDispatchReloadedV1 {
        target_root_id: claims.target().root_id().into(),
        target_components: claims.target().components().to_vec().into_boxed_slice(),
        precondition_digest: *claims.precondition_content_sha256().as_bytes(),
        content_digest: *claims.replacement_sha256().as_bytes(),
        content_byte_length: claims.replacement_byte_length(),
        content_media_type: claims.replacement_media_type().into(),
        required_capacity,
        held_capacity,
        prior,
        durable,
    })
}

struct StoreClosurePermitV1 {
    deadline: u64,
}

impl DispatchCommitPermitV1 for StoreClosurePermitV1 {
    fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline
    }

    fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
        if now_monotonic_ms < self.deadline {
            DispatchGuardValidationV1::Valid
        } else {
            DispatchGuardValidationV1::DeadlineReached
        }
    }

    fn commit_once<C, U, F>(self, commit: F) -> DispatchCommitResolutionV1<C, U>
    where
        C: Send,
        U: Send,
        F: FnOnce() -> DispatchStoreCommitClassificationV1<C, U>,
    {
        resolution_from_classification_v1(commit())
    }

    fn abandon_v1(self) {}
}

fn resolution_from_classification_v1<C, U>(
    classification: DispatchStoreCommitClassificationV1<C, U>,
) -> DispatchCommitResolutionV1<C, U> {
    match classification {
        DispatchStoreCommitClassificationV1::Committed(value) => {
            DispatchCommitResolutionV1::Committed(value)
        }
        DispatchStoreCommitClassificationV1::PriorExactDispatch(value) => {
            DispatchCommitResolutionV1::PriorExactDispatch(value)
        }
        DispatchStoreCommitClassificationV1::ConfirmedRollback => {
            DispatchCommitResolutionV1::ConfirmedRollback
        }
        DispatchStoreCommitClassificationV1::Uncertain(value) => {
            DispatchCommitResolutionV1::Uncertain(value)
        }
        DispatchStoreCommitClassificationV1::Conflict => DispatchCommitResolutionV1::Conflict,
        DispatchStoreCommitClassificationV1::Unavailable => DispatchCommitResolutionV1::Unavailable,
        DispatchStoreCommitClassificationV1::Unhealthy => DispatchCommitResolutionV1::Unclassified,
        DispatchStoreCommitClassificationV1::Unclassified => {
            DispatchCommitResolutionV1::Unclassified
        }
    }
}

fn classification_from_resolution_v1<C, U>(
    resolution: DispatchCommitResolutionV1<C, U>,
) -> DispatchStoreCommitClassificationV1<C, U> {
    match resolution {
        DispatchCommitResolutionV1::Committed(value) => {
            DispatchStoreCommitClassificationV1::Committed(value)
        }
        DispatchCommitResolutionV1::PriorExactDispatch(value) => {
            DispatchStoreCommitClassificationV1::PriorExactDispatch(value)
        }
        DispatchCommitResolutionV1::ConfirmedRollback => {
            DispatchStoreCommitClassificationV1::ConfirmedRollback
        }
        DispatchCommitResolutionV1::Uncertain(value) => {
            DispatchStoreCommitClassificationV1::Uncertain(value)
        }
        DispatchCommitResolutionV1::Conflict => DispatchStoreCommitClassificationV1::Conflict,
        DispatchCommitResolutionV1::Unavailable => DispatchStoreCommitClassificationV1::Unavailable,
        DispatchCommitResolutionV1::Revoked | DispatchCommitResolutionV1::DeadlineReached => {
            DispatchStoreCommitClassificationV1::ConfirmedRollback
        }
        DispatchCommitResolutionV1::Ambiguous | DispatchCommitResolutionV1::Unclassified => {
            DispatchStoreCommitClassificationV1::Unclassified
        }
    }
}

pub(crate) fn embedded_dispatch_schema_v2_sha256() -> [u8; 32] {
    Sha256::digest(COORDINATOR_DISPATCH_SCHEMA_V2_SQL.as_bytes()).into()
}

/// Verifies the permanent-history portion of the published coordinator V2 graph.
///
/// Exact schema comparison proves the frozen table constraints and identifier keys.
/// The additional named-object checks keep the retention proof explicit: every
/// authoritative table has a delete-aborting trigger, each retained generation axis
/// has a unique index, and the live generation high-water values still match history.
pub(crate) fn verify_permanent_dispatch_history_v1(
    connection: &Connection,
) -> Result<CoordinatorDispatchRetentionPolicyV1, InternalCoordinatorError> {
    verify_embedded_dispatch_schema_digest_v2()?;
    verify_dispatch_identity_v2(connection)?;
    verify_exact_dispatch_schema_v2(connection)?;
    verify_permanent_dispatch_schema_objects_v1(connection)?;
    let generations = decode_dispatch_generations_v2(connection)?;
    verify_dispatch_generation_high_water_v2(connection, generations)?;
    Ok(coordinator_dispatch_retention_policy_v1())
}

/// Strict dispatch-side checkpoint verification for the T097 cross-store auditor.
///
/// This deliberately excludes historical-plan signature resolution: the auditor receives
/// closed SQLite checkpoints rather than a plan-key authority. It still verifies the exact
/// published V2 schema, permanent guards, SQLite integrity and foreign keys, metadata,
/// generation high-water marks, the complete dispatch graph and the permanent corruption
/// fence before any trusted inventory is used as a comparison baseline.
#[cfg(feature = "test-fault-injection")]
pub(crate) fn verify_t097_trusted_dispatch_checkpoint_v1(
    connection: &Connection,
) -> Result<(), InternalCoordinatorError> {
    verify_embedded_dispatch_schema_digest_v2()?;
    verify_dispatch_identity_v2(connection)?;
    verify_exact_dispatch_schema_v2(connection)?;
    verify_permanent_dispatch_schema_objects_v1(connection)?;
    verify_dispatch_guard_contracts_v2(connection)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(invariant_v2)?;
    if integrity != "ok" {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    let foreign_key_violation: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(invariant_v2)?;
    if foreign_key_violation.is_some() {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    verify_no_active_dispatch_corruption_quarantine_v1(connection)?;
    let generations = decode_dispatch_generations_v2(connection)?;
    verify_dispatch_metadata_v2(connection, generations)?;
    verify_dispatch_generation_high_water_v2(connection, generations)?;
    verify_dispatch_composite_invariants_v2(connection)
}

/// Strictly verifies an already-published V2 connection without mutating it.
///
/// The caller must independently own the provisioned root/file binding and historical
/// key resolver. This verifier cannot apply the overlay, repair a partial schema, publish
/// `user_version`, or construct a store handle.
pub(crate) fn verify_dispatch_schema_v2<R: Ed25519KeyResolver>(
    connection: &Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &R,
) -> Result<VerifiedDispatchSchemaV2, InternalCoordinatorError> {
    verify_embedded_dispatch_schema_digest_v2()?;
    verify_dispatch_identity_v2(connection)?;
    verify_dispatch_graph_v2(connection, expected_root_identity, historical_plan_keys)
}

/// Verifies one imported, signed coordinator-V2 database while it is still ACTIVE.
///
/// The raw historical root identity is read only as an input to exact verification. The
/// package owner must separately compare its domain digest with the signed manifest before
/// this proof can authorize a destination transition.
pub(crate) fn verify_imported_active_dispatch_backup_v1<R: Ed25519KeyResolver>(
    connection: &Connection,
    expected_generations: DispatchRestoreSourceGenerationsV1,
    historical_plan_keys: &R,
) -> Result<VerifiedImportedDispatchBackupV1, InternalCoordinatorError> {
    let source_root_identity = schema::imported_dispatch_root_identity_v1(connection)?;
    let verified =
        verify_dispatch_schema_v2(connection, source_root_identity, historical_plan_keys)?;
    if verified.generations != expected_generations.0 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    let base_generations = schema::capture_dispatch_active_generations_v1(
        connection,
        source_root_identity,
        historical_plan_keys,
    )?;
    let imported = schema::verify_dispatch_imported_active_graph_v1(
        connection,
        base_generations,
        historical_plan_keys,
    )?;
    if imported.summary().root_identity != source_root_identity
        || imported.generations() != base_generations
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(VerifiedImportedDispatchBackupV1 {
        source_root_identity,
        base_generations,
        dispatch_generations: expected_generations,
    })
}

/// Atomically converts the unchanged base and additive dispatch metadata in one local DB.
///
/// This makes no cross-store atomicity claim. The adapter has an independent commit and the
/// cross-store orchestrator must retain PAUSE until both durable results are reopened.
pub(crate) fn transition_imported_dispatch_backup_to_restore_pending_v1<R: Ed25519KeyResolver>(
    connection: &mut Connection,
    bindings: DispatchRestorePendingBindingsV1,
    historical_plan_keys: &R,
) -> Result<VerifiedDispatchRestorePendingV1, InternalCoordinatorError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_restore_sqlite_error_v2(&error))?;
    let source = verify_imported_active_dispatch_backup_v1(
        &transaction,
        bindings.source_dispatch_generations,
        historical_plan_keys,
    )?;
    if source.base_generations != bindings.base.expected_source_generations() {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    if source.source_root_identity == bindings.base.new_root_identity() {
        return Err(InternalCoordinatorError::RootIdentityMismatch);
    }

    let source_dispatch = bindings.source_dispatch_generations.0;
    let next_store_generation = source_dispatch
        .store
        .checked_add(1)
        .filter(|generation| *generation <= MAX_SAFE_U64)
        .ok_or(InternalCoordinatorError::InvariantFailed)?;
    let changed = transaction
        .execute(
            "UPDATE dispatch_store_meta SET \
                 dispatch_store_generation = ?1, \
                 root_lifecycle_state = 'RESTORE_PENDING', \
                 restore_index_digest = ?2, \
                 restore_state_generation = ?1 \
             WHERE singleton = 1 \
               AND dispatch_store_generation = ?3 \
               AND dispatch_generation = ?4 \
               AND delivery_generation = ?5 \
               AND receipt_generation = ?6 \
               AND reconciliation_generation = ?7 \
               AND event_generation = ?8 \
               AND migration_generation = ?9 \
               AND root_lifecycle_state = 'ACTIVE' \
               AND restore_index_digest IS NULL \
               AND restore_state_generation = 0",
            params![
                to_i64_v2(next_store_generation)?,
                bindings.restore_index_digest.as_slice(),
                to_i64_v2(source_dispatch.store)?,
                to_i64_v2(source_dispatch.dispatch)?,
                to_i64_v2(source_dispatch.delivery)?,
                to_i64_v2(source_dispatch.receipt)?,
                to_i64_v2(source_dispatch.reconciliation)?,
                to_i64_v2(source_dispatch.event)?,
                to_i64_v2(source_dispatch.migration)?,
            ],
        )
        .map_err(invariant_v2)?;
    if changed != 1 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }

    // Enter the dispatch-side pending lifecycle first so the permanent overlay guard can
    // authorize exactly the base layer's NULL -> source-generation restore stamp. Both
    // metadata transitions and every stamp remain inside this one local transaction.
    schema::stage_imported_backup_restore_pending_graph_v1(
        &transaction,
        bindings.base,
        historical_plan_keys,
    )?;

    let verified =
        verify_dispatch_restore_pending_v1(&transaction, bindings, historical_plan_keys)?;
    transaction
        .commit()
        .map_err(|error| map_restore_sqlite_error_v2(&error))?;
    Ok(verified)
}

/// Reopens and fully verifies the exact pending bindings for one coordinator-V2 root.
pub(crate) fn verify_dispatch_restore_pending_v1<R: Ed25519KeyResolver>(
    connection: &Connection,
    bindings: DispatchRestorePendingBindingsV1,
    historical_plan_keys: &R,
) -> Result<VerifiedDispatchRestorePendingV1, InternalCoordinatorError> {
    verify_embedded_dispatch_schema_digest_v2()?;
    verify_dispatch_identity_v2(connection)?;
    verify_exact_dispatch_schema_v2(connection)?;
    verify_permanent_dispatch_schema_objects_v1(connection)?;
    verify_dispatch_guard_contracts_v2(connection)?;
    let base = schema::verify_dispatch_restore_pending_graph_v1(
        connection,
        bindings.base,
        historical_plan_keys,
    )?;
    verify_no_active_dispatch_corruption_quarantine_v1(connection)?;
    let generations = decode_dispatch_generations_v2(connection)?;
    verify_dispatch_metadata_v2(connection, generations)?;
    verify_dispatch_restore_metadata_v1(connection, generations, bindings)?;
    verify_dispatch_generation_high_water_v2(connection, generations)?;
    verify_dispatch_composite_invariants_v2(connection)?;
    Ok(VerifiedDispatchRestorePendingV1 { base, generations })
}

fn verify_dispatch_graph_v2<R: Ed25519KeyResolver>(
    connection: &Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &R,
) -> Result<VerifiedDispatchSchemaV2, InternalCoordinatorError> {
    verify_exact_dispatch_schema_v2(connection)?;
    verify_permanent_dispatch_schema_objects_v1(connection)?;
    verify_dispatch_guard_contracts_v2(connection)?;
    let base_summary = schema::verify_dispatch_base_graph_v1(
        connection,
        expected_root_identity,
        historical_plan_keys,
    )?;
    verify_no_active_dispatch_corruption_quarantine_v1(connection)?;
    let generations = decode_dispatch_generations_v2(connection)?;
    verify_dispatch_metadata_v2(connection, generations)?;
    verify_dispatch_generation_high_water_v2(connection, generations)?;
    verify_dispatch_composite_invariants_v2(connection)?;
    Ok(VerifiedDispatchSchemaV2 {
        base_summary,
        generations,
    })
}

/// Any retained global dispatch-corruption custody is a permanent V2 admission fence.
///
/// Retention itself deliberately enters through the base quarantine writer before this
/// verifier is called. Every later ordinary open and every operation on an existing V2
/// handle re-enters this verifier and therefore receives no activation or redelivery
/// authority. Status transitions cannot erase a historical corruption finding.
fn verify_no_active_dispatch_corruption_quarantine_v1(
    connection: &Connection,
) -> Result<(), InternalCoordinatorError> {
    let active: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM preparation_quarantines
             WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')",
            [],
            |row| row.get(0),
        )
        .map_err(invariant_v2)?;
    if active != 0 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

/// Applies the reviewed overlay inside the already-held maintenance
/// `BEGIN IMMEDIATE` transaction.
///
/// The caller is `maintenance.rs`, which owns live PAUSE/provider/root custody and a
/// freshly reopened backup. This function verifies exact V1 again under the writer
/// cut, installs objects and the attempt-bound receipt, proves the unpublished graph,
/// then publishes `user_version=2` as its last mutation.
pub(crate) fn stage_dispatch_migration_v2<R: Ed25519KeyResolver>(
    connection: &Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &R,
    verified_backup_digest: [u8; 32],
    request: &DispatchMigrationRequestV2,
) -> Result<DispatchMigrationReceiptV2, InternalCoordinatorError> {
    stage_dispatch_migration_with_checkpoints_v2(
        connection,
        expected_root_identity,
        historical_plan_keys,
        verified_backup_digest,
        request,
        |_| Ok(()),
    )
}

/// Feature-only migration fault wiring enters the same production staging body as the
/// inert path above. The callback receives only the closed FB074/FB075 ordinals and
/// carries no connection, receipt, identity, or migration authority.
#[cfg(not(test))]
pub(crate) fn stage_dispatch_migration_with_fault_probe_v2<
    R: Ed25519KeyResolver,
    F: FnMut(u8) -> Result<(), InternalCoordinatorError>,
>(
    connection: &Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &R,
    verified_backup_digest: [u8; 32],
    request: &DispatchMigrationRequestV2,
    checkpoint: F,
) -> Result<DispatchMigrationReceiptV2, InternalCoordinatorError> {
    stage_dispatch_migration_with_checkpoints_v2(
        connection,
        expected_root_identity,
        historical_plan_keys,
        verified_backup_digest,
        request,
        checkpoint,
    )
}

fn stage_dispatch_migration_with_checkpoints_v2<
    R: Ed25519KeyResolver,
    F: FnMut(u8) -> Result<(), InternalCoordinatorError>,
>(
    connection: &Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &R,
    verified_backup_digest: [u8; 32],
    request: &DispatchMigrationRequestV2,
    mut checkpoint: F,
) -> Result<DispatchMigrationReceiptV2, InternalCoordinatorError> {
    verify_embedded_dispatch_schema_digest_v2()?;
    let source = schema::verify_full(connection, expected_root_identity, historical_plan_keys)?;
    if pragma_i64_v2(connection, "user_version")? != 1 {
        return Err(InternalCoordinatorError::SchemaUnsupported);
    }
    let source_summary_digest = migration_source_summary_digest_v2(connection, source)?;
    let overlay_body = COORDINATOR_DISPATCH_SCHEMA_V2_SQL
        .strip_suffix(DISPATCH_MIGRATION_FINAL_PRAGMA_V2)
        .ok_or(InternalCoordinatorError::SchemaInvalid)?;
    connection
        .execute_batch(overlay_body)
        .map_err(schema_invalid_v2)?;

    let root_lifecycle_state: String = connection
        .query_row(
            "SELECT root_lifecycle_state FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(invariant_v2)?;
    connection
        .execute(
            "INSERT INTO dispatch_store_meta (\
                singleton, extension_format_version, dispatch_store_generation, \
                dispatch_generation, delivery_generation, receipt_generation, \
                reconciliation_generation, event_generation, migration_generation, \
                ordinary_queue_capacity, control_queue_capacity, root_lifecycle_state, \
                restore_index_digest, restore_state_generation\
             ) VALUES (1, 1, 1, 0, 0, 0, 0, 0, 1, 1024, 32, ?1, NULL, 0)",
            [&root_lifecycle_state],
        )
        .map_err(invariant_v2)?;

    let receipt = DispatchMigrationReceiptV2 {
        migration_attempt_id: request.migration_attempt_id,
        source_schema_digest: schema::embedded_schema_v1_sha256(),
        source_root_identity: *expected_root_identity.as_bytes(),
        source_summary_digest,
        verified_backup_digest,
        overlay_schema_digest: embedded_dispatch_schema_v2_sha256(),
        migrated_at_utc_ms: request.migrated_at_utc_ms,
        migrated_at_monotonic_ms: request.migrated_at_monotonic_ms,
        tool_identity: request.tool_identity.clone(),
    };
    connection
        .execute(
            "INSERT INTO coordinator_v2_migrations (\
                migration_attempt_id, source_schema_digest, source_root_identity, \
                source_summary_digest, verified_backup_digest, overlay_schema_digest, \
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms, \
                tool_identity\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9)",
            params![
                receipt.migration_attempt_id.as_slice(),
                receipt.source_schema_digest.as_slice(),
                receipt.source_root_identity.as_slice(),
                receipt.source_summary_digest.as_slice(),
                receipt.verified_backup_digest.as_slice(),
                receipt.overlay_schema_digest.as_slice(),
                to_i64_v2(receipt.migrated_at_utc_ms)?,
                to_i64_v2(receipt.migrated_at_monotonic_ms)?,
                receipt.tool_identity.as_ref(),
            ],
        )
        .map_err(invariant_v2)?;

    // FB074: all reviewed overlay objects, metadata, and the one attempt-bound
    // migration receipt now exist only inside the still-uncommitted writer cut.
    checkpoint(74)?;

    if pragma_i64_v2(connection, "user_version")? != 1 {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    verify_dispatch_graph_v2(connection, expected_root_identity, historical_plan_keys)?;
    verify_exact_migration_receipt_v2(connection, &receipt)?;

    // This is intentionally the final mutation before the owning maintenance cut
    // commits. All following work is read-only exact verification/readback.
    connection
        .pragma_update(None, "user_version", COORDINATOR_DISPATCH_SCHEMA_VERSION_V2)
        .map_err(schema_invalid_v2)?;
    verify_dispatch_schema_v2(connection, expected_root_identity, historical_plan_keys)?;
    verify_exact_migration_receipt_v2(connection, &receipt)?;

    // FB075: user_version=2 was the final mutation and the complete unpublished V2
    // graph has been reverified. The owning maintenance cut has not committed yet.
    checkpoint(75)?;
    Ok(receipt)
}

/// Resolves an uncertain migration only by reopening and comparing exact durable
/// schema plus the complete attempt receipt. It never executes migration SQL.
pub(crate) fn classify_dispatch_migration_readback_v2<R: Ed25519KeyResolver>(
    connection: &Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &R,
    expected_receipt: &DispatchMigrationReceiptV2,
) -> DispatchMigrationReadbackV2 {
    let version = match connection.pragma_query_value(None, "user_version", |row| row.get(0)) {
        Ok(version) => version,
        Err(_) => return DispatchMigrationReadbackV2::Unavailable,
    };
    match version {
        1 => match schema::verify_full(connection, expected_root_identity, historical_plan_keys) {
            Ok(_) => DispatchMigrationReadbackV2::ConfirmedRollback,
            Err(_) => DispatchMigrationReadbackV2::Conflict,
        },
        COORDINATOR_DISPATCH_SCHEMA_VERSION_V2 => {
            match verify_dispatch_schema_v2(
                connection,
                expected_root_identity,
                historical_plan_keys,
            )
            .and_then(|verified| {
                verify_exact_migration_receipt_v2(connection, expected_receipt)?;
                Ok(verified)
            }) {
                Ok(verified) => DispatchMigrationReadbackV2::Committed(verified),
                Err(_) => DispatchMigrationReadbackV2::Conflict,
            }
        }
        _ => DispatchMigrationReadbackV2::Conflict,
    }
}

/// No V2 database is ever rewritten in place as V1. The permanent migration receipt
/// itself is dispatch history, even before the first grant, so downgrade is refused.
pub(crate) fn refuse_in_place_dispatch_downgrade_v2(
    connection: &Connection,
) -> Result<(), InternalCoordinatorError> {
    let version = pragma_i64_v2(connection, "user_version")?;
    if version != COORDINATOR_DISPATCH_SCHEMA_VERSION_V2 {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    let history: i64 = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM coordinator_v2_migrations) \
                  + (SELECT COUNT(*) FROM dispatch_grants) \
                  + (SELECT COUNT(*) FROM dispatch_receipts) \
                  + (SELECT COUNT(*) FROM dispatch_reconciliations)",
            [],
            |row| row.get(0),
        )
        .map_err(invariant_v2)?;
    if history <= 0 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Err(InternalCoordinatorError::SchemaUnsupported)
}

fn verify_embedded_dispatch_schema_digest_v2() -> Result<(), InternalCoordinatorError> {
    if embedded_dispatch_schema_v2_sha256() != COORDINATOR_DISPATCH_SCHEMA_V2_SHA256 {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    Ok(())
}

fn verify_dispatch_identity_v2(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    let application_id = pragma_i64_v2(connection, "application_id")?;
    if application_id != COORDINATOR_STORE_APPLICATION_ID_V1 {
        return Err(InternalCoordinatorError::ApplicationIdMismatch);
    }
    let user_version = pragma_i64_v2(connection, "user_version")?;
    if user_version > COORDINATOR_DISPATCH_SCHEMA_VERSION_V2 {
        return Err(InternalCoordinatorError::SchemaUnsupported);
    }
    if user_version != COORDINATOR_DISPATCH_SCHEMA_VERSION_V2 {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    Ok(())
}

fn verify_exact_dispatch_schema_v2(
    connection: &Connection,
) -> Result<(), InternalCoordinatorError> {
    let actual = read_schema_objects_v2(connection)?;
    let expected = Connection::open_in_memory().map_err(schema_invalid_v2)?;
    expected
        .execute_batch(COORDINATOR_STORE_SCHEMA_V1_SQL)
        .map_err(schema_invalid_v2)?;
    expected
        .execute_batch(COORDINATOR_DISPATCH_SCHEMA_V2_SQL)
        .map_err(schema_invalid_v2)?;
    if actual != read_schema_objects_v2(&expected)? {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    Ok(())
}

fn verify_dispatch_guard_contracts_v2(
    connection: &Connection,
) -> Result<(), InternalCoordinatorError> {
    for name in REQUIRED_APPEND_ONLY_TRIGGERS_V2
        .iter()
        .chain(REQUIRED_GRAPH_GUARDS_V2)
    {
        let sql = trigger_sql_v2(connection, name)?;
        if !sql.contains("RAISE(ABORT") {
            return Err(InternalCoordinatorError::SchemaInvalid);
        }
    }
    for name in REQUIRED_ACTIVE_ROOT_TRIGGERS_V2 {
        let sql = trigger_sql_v2(connection, name)?;
        if !sql.contains("root_lifecycle_state = 'ACTIVE'") || !sql.contains("RAISE(ABORT") {
            return Err(InternalCoordinatorError::SchemaInvalid);
        }
    }
    Ok(())
}

fn verify_permanent_dispatch_schema_objects_v1(
    connection: &Connection,
) -> Result<(), InternalCoordinatorError> {
    for (trigger_name, table_name) in REQUIRED_PERMANENT_HISTORY_DELETE_GUARDS_V1 {
        let object = named_schema_object_v2(connection, "trigger", trigger_name)?;
        let delete_clause = format!("BEFORE DELETE ON {table_name}");
        if object.table_name != *table_name
            || !object.sql.contains(&delete_clause)
            || !object.sql.contains("RAISE(ABORT")
        {
            return Err(InternalCoordinatorError::SchemaInvalid);
        }
    }
    for (index_name, table_name, generation_column) in
        REQUIRED_PERMANENT_HISTORY_GENERATION_INDEXES_V1
    {
        let object = named_schema_object_v2(connection, "index", index_name)?;
        if object.table_name != *table_name
            || !object.sql.contains("CREATE UNIQUE INDEX")
            || !object.sql.contains(generation_column)
        {
            return Err(InternalCoordinatorError::SchemaInvalid);
        }
    }
    Ok(())
}

fn decode_dispatch_generations_v2(
    connection: &Connection,
) -> Result<DispatchGenerationsV2, InternalCoordinatorError> {
    let raw: (i64, i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT dispatch_store_generation, dispatch_generation, delivery_generation, \
                    receipt_generation, reconciliation_generation, event_generation, \
                    migration_generation, restore_state_generation \
             FROM dispatch_store_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .map_err(invariant_v2)?;
    Ok(DispatchGenerationsV2 {
        store: safe_generation_v2(raw.0)?,
        dispatch: safe_generation_v2(raw.1)?,
        delivery: safe_generation_v2(raw.2)?,
        receipt: safe_generation_v2(raw.3)?,
        reconciliation: safe_generation_v2(raw.4)?,
        event: safe_generation_v2(raw.5)?,
        migration: safe_generation_v2(raw.6)?,
        restore_state: safe_generation_v2(raw.7)?,
    })
}

fn verify_dispatch_metadata_v2(
    connection: &Connection,
    generations: DispatchGenerationsV2,
) -> Result<(), InternalCoordinatorError> {
    let source_digest = schema::embedded_schema_v1_sha256();
    let overlay_digest = embedded_dispatch_schema_v2_sha256();
    let exact: i64 = connection
        .query_row(
            "SELECT CASE WHEN \
                 (SELECT COUNT(*) FROM dispatch_store_meta) = 1 \
             AND (SELECT COUNT(*) FROM coordinator_v2_migrations) = 1 \
             AND NOT EXISTS (SELECT 1 FROM coordinator_v2_migrations \
                             WHERE source_schema_digest <> ?1 \
                                OR overlay_schema_digest <> ?2) \
             AND EXISTS (SELECT 1 FROM dispatch_store_meta AS dispatch_meta \
                         JOIN coordinator_store_meta AS base_meta ON base_meta.singleton = 1 \
                         WHERE dispatch_meta.singleton = 1 \
                           AND dispatch_meta.root_lifecycle_state \
                               = base_meta.root_lifecycle_state) \
             THEN 1 ELSE 0 END",
            params![source_digest.as_slice(), overlay_digest.as_slice()],
            |row| row.get(0),
        )
        .map_err(invariant_v2)?;
    if exact != 1 || generations.migration == 0 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn verify_dispatch_restore_metadata_v1(
    connection: &Connection,
    generations: DispatchGenerationsV2,
    bindings: DispatchRestorePendingBindingsV1,
) -> Result<(), InternalCoordinatorError> {
    let (lifecycle, restore_index_digest): (String, Vec<u8>) = connection
        .query_row(
            "SELECT root_lifecycle_state, restore_index_digest \
             FROM dispatch_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(invariant_v2)?;
    let source = bindings.source_dispatch_generations.0;
    let expected_restore_generation = source
        .store
        .checked_add(1)
        .filter(|generation| *generation <= MAX_SAFE_U64)
        .ok_or(InternalCoordinatorError::InvariantFailed)?;
    if lifecycle != "RESTORE_PENDING"
        || restore_index_digest.as_slice() != bindings.restore_index_digest
        || generations.store != expected_restore_generation
        || generations.restore_state != expected_restore_generation
        || generations.dispatch != source.dispatch
        || generations.delivery != source.delivery
        || generations.receipt != source.receipt
        || generations.reconciliation != source.reconciliation
        || generations.event != source.event
        || generations.migration != source.migration
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn verify_dispatch_generation_high_water_v2(
    connection: &Connection,
    generations: DispatchGenerationsV2,
) -> Result<(), InternalCoordinatorError> {
    let raw: (i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT \
                 COALESCE((SELECT MAX(generation) FROM (\
                     SELECT comparison_generation AS generation FROM dispatch_comparisons \
                     UNION ALL SELECT created_generation FROM dispatch_grants \
                     UNION ALL SELECT state_generation FROM dispatch_records \
                     UNION ALL SELECT state_generation FROM dispatch_transitions \
                     UNION ALL SELECT guard_generation FROM dispatch_definite_refusal_guards\
                 )), 0), \
                 COALESCE((SELECT MAX(generation) FROM (\
                     SELECT delivery_generation AS generation FROM dispatch_outbox \
                     UNION ALL SELECT attempt_generation FROM dispatch_delivery_attempts \
                     UNION ALL SELECT readback_generation FROM dispatch_delivery_attempts \
                         WHERE readback_generation IS NOT NULL\
                 )), 0), \
                 COALESCE((SELECT MAX(receipt_generation) FROM dispatch_receipts), 0), \
                 COALESCE((SELECT MAX(reconciliation_generation) \
                           FROM dispatch_reconciliations), 0), \
                 COALESCE((SELECT MAX(generation) FROM (\
                     SELECT event_generation AS generation FROM dispatch_events \
                     UNION ALL SELECT delivered_generation FROM dispatch_events \
                         WHERE delivered_generation IS NOT NULL\
                 )), 0), \
                 COALESCE((SELECT MAX(migration_generation) \
                           FROM coordinator_v2_migrations), 0)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(invariant_v2)?;
    let observed = [
        safe_generation_v2(raw.0)?,
        safe_generation_v2(raw.1)?,
        safe_generation_v2(raw.2)?,
        safe_generation_v2(raw.3)?,
        safe_generation_v2(raw.4)?,
        safe_generation_v2(raw.5)?,
    ];
    let declared = [
        generations.dispatch,
        generations.delivery,
        generations.receipt,
        generations.reconciliation,
        generations.event,
        generations.migration,
    ];
    let store_high_water = declared
        .into_iter()
        .chain([generations.restore_state])
        .max()
        .ok_or(InternalCoordinatorError::InvariantFailed)?;
    if observed != declared || generations.store != store_high_water {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn verify_dispatch_composite_invariants_v2(
    connection: &Connection,
) -> Result<(), InternalCoordinatorError> {
    let exact: i64 = connection
        .query_row(
            "SELECT CASE WHEN \
                 (SELECT COUNT(*) FROM dispatch_comparisons) \
                     = (SELECT COUNT(*) FROM dispatch_grants) \
             AND (SELECT COUNT(*) FROM dispatch_grants) \
                     = (SELECT COUNT(*) FROM dispatch_records) \
             AND (SELECT COUNT(*) FROM dispatch_records) \
                     = (SELECT COUNT(*) FROM dispatch_outbox) \
             AND (SELECT COUNT(*) FROM dispatch_transitions) \
                     = (SELECT COUNT(*) FROM dispatch_events) \
             AND (SELECT COUNT(*) FROM dispatch_definite_refusal_guards) \
                     = (SELECT COUNT(*) FROM dispatch_records \
                        WHERE effective_state = 'FAILED') \
             AND NOT EXISTS (\
                 SELECT 1 FROM dispatch_grants AS grant \
                 LEFT JOIN dispatch_records AS record ON record.grant_id = grant.grant_id \
                 LEFT JOIN dispatch_outbox AS outbox ON outbox.grant_id = grant.grant_id \
                 WHERE record.grant_id IS NULL OR outbox.grant_id IS NULL\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM dispatch_records AS record \
                 JOIN dispatch_grants AS grant ON grant.grant_id = record.grant_id \
                 JOIN prepared_operations AS operation \
                   ON operation.operation_id = record.operation_id \
                 JOIN budget_reservations AS reservation \
                   ON reservation.reservation_id = grant.reservation_id \
                 WHERE (record.effective_state <> 'FAILED' \
                        AND (operation.operation_state <> 'PREPARING' \
                             OR reservation.reservation_state <> 'HELD' \
                             OR reservation.released_generation IS NOT NULL)) \
                    OR (record.effective_state = 'FAILED' \
                        AND (operation.operation_state <> 'FAILED' \
                             OR reservation.reservation_state <> 'RELEASED' \
                             OR reservation.released_generation IS NULL))\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM dispatch_outbox AS outbox \
                 JOIN dispatch_records AS record \
                   ON record.operation_id = outbox.operation_id \
                  AND record.grant_id = outbox.grant_id \
                  AND record.dispatch_attempt_id = outbox.dispatch_attempt_id \
                 JOIN dispatch_delivery_attempts AS current_attempt \
                   ON current_attempt.attempt_generation = outbox.current_attempt_generation \
                  AND current_attempt.grant_id = outbox.grant_id \
                  AND current_attempt.operation_id = outbox.operation_id \
                 AND current_attempt.dispatch_attempt_id = outbox.dispatch_attempt_id \
                 WHERE outbox.delivery_state = 'ACKNOWLEDGED' \
                   AND NOT (\
                     outbox.receipt_decision = 'CONSUMED' \
                     AND (\
                     (record.effective_state = 'EXECUTING' \
                      AND record.receipt_id = outbox.receipt_id \
                      AND record.receipt_decision = 'CONSUMED' \
                      AND record.reconciliation_id IS NULL \
                      AND record.reconciliation_result IS NULL \
                      AND current_attempt.attempt_generation = outbox.delivery_generation \
                      AND current_attempt.attempt_number = 2 \
                      AND current_attempt.classification = 'ACKNOWLEDGED' \
                      AND typeof(current_attempt.adapter_root_digest) = 'blob' \
                      AND length(current_attempt.adapter_root_digest) = 32 \
                      AND current_attempt.adapter_root_digest <> zeroblob(32) \
                      AND current_attempt.adapter_epoch IS NOT NULL \
                      AND current_attempt.readback_generation IS NULL \
                      AND (SELECT COUNT(*) FROM dispatch_delivery_attempts AS all_attempts \
                           WHERE all_attempts.grant_id = outbox.grant_id \
                             AND all_attempts.operation_id = outbox.operation_id \
                             AND all_attempts.dispatch_attempt_id = outbox.dispatch_attempt_id) = 2 \
                      AND EXISTS (SELECT 1 FROM dispatch_delivery_attempts AS source \
                           WHERE source.grant_id = outbox.grant_id \
                             AND source.operation_id = outbox.operation_id \
                             AND source.dispatch_attempt_id = outbox.dispatch_attempt_id \
                             AND source.attempt_generation < current_attempt.attempt_generation \
                             AND source.attempt_number = 1 \
                             AND source.handoff_guard_digest = current_attempt.handoff_guard_digest \
                             AND source.classification = 'POSSIBLE_HANDOFF' \
                             AND source.adapter_root_digest IS NULL \
                             AND source.adapter_epoch IS NULL \
                             AND source.readback_generation IS NULL)) \
                     OR \
                     (record.receipt_id = outbox.receipt_id \
                      AND record.receipt_decision = 'CONSUMED' \
                      AND ((record.effective_state = 'EXECUTING' \
                            AND record.reconciliation_id IS NULL \
                            AND record.reconciliation_result IS NULL) \
                           OR (record.effective_state = 'RECONCILIATION_REQUIRED' \
                               AND record.reconciliation_id IS NOT NULL \
                               AND record.reconciliation_result = 'CONSUMED')) \
                      AND current_attempt.attempt_generation < outbox.delivery_generation \
                      AND current_attempt.attempt_number = 2 \
                      AND current_attempt.classification = 'POSSIBLE_HANDOFF' \
                      AND typeof(current_attempt.adapter_root_digest) = 'blob' \
                      AND length(current_attempt.adapter_root_digest) = 32 \
                      AND current_attempt.adapter_root_digest <> zeroblob(32) \
                      AND current_attempt.adapter_epoch IS NOT NULL \
                      AND current_attempt.readback_generation IS NOT NULL \
                      AND (SELECT COUNT(*) FROM dispatch_delivery_attempts AS all_attempts \
                           WHERE all_attempts.grant_id = outbox.grant_id \
                             AND all_attempts.operation_id = outbox.operation_id \
                             AND all_attempts.dispatch_attempt_id = outbox.dispatch_attempt_id) = 2 \
                      AND EXISTS (SELECT 1 FROM dispatch_delivery_attempts AS source \
                           WHERE source.grant_id = outbox.grant_id \
                             AND source.operation_id = outbox.operation_id \
                             AND source.dispatch_attempt_id = outbox.dispatch_attempt_id \
                             AND source.attempt_generation = current_attempt.readback_generation \
                             AND source.attempt_generation < current_attempt.attempt_generation \
                             AND source.attempt_number = 1 \
                             AND source.classification = 'POSSIBLE_HANDOFF' \
                             AND source.adapter_root_digest IS NULL \
                             AND source.adapter_epoch IS NULL \
                             AND source.readback_generation IS NULL))\
                     )\
                   )\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM dispatch_delivery_attempts AS acknowledged_attempt \
                 WHERE acknowledged_attempt.classification = 'ACKNOWLEDGED' \
                   AND NOT EXISTS (\
                     SELECT 1 FROM dispatch_outbox AS acknowledged_outbox \
                     WHERE acknowledged_outbox.delivery_state = 'ACKNOWLEDGED' \
                       AND acknowledged_outbox.current_attempt_generation = \
                           acknowledged_attempt.attempt_generation \
                       AND acknowledged_outbox.grant_id = acknowledged_attempt.grant_id \
                       AND acknowledged_outbox.operation_id = acknowledged_attempt.operation_id \
                       AND acknowledged_outbox.dispatch_attempt_id = \
                           acknowledged_attempt.dispatch_attempt_id\
                   )\
             ) \
             THEN 1 ELSE 0 END",
            [],
            |row| row.get(0),
        )
        .map_err(invariant_v2)?;
    if exact != 1 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn migration_source_summary_digest_v2(
    connection: &Connection,
    summary: StoreSummary,
) -> Result<[u8; 32], InternalCoordinatorError> {
    let generations: (i64, i64, i64, i64, i64, String) = connection
        .query_row(
            "SELECT store_generation, operation_generation, budget_generation, \
                    event_generation, quarantine_generation, root_lifecycle_state \
             FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(invariant_v2)?;
    if generations.5 != "ACTIVE" {
        return Err(InternalCoordinatorError::RestorePending);
    }
    let mut hasher = Sha256::new();
    hasher.update(DISPATCH_MIGRATION_SUMMARY_DOMAIN_V2);
    hasher.update(schema::embedded_schema_v1_sha256());
    hasher.update(summary.root_identity.as_bytes());
    hasher.update(
        u64::try_from(summary.schema_cookie)
            .map_err(|_| InternalCoordinatorError::InvariantFailed)?
            .to_be_bytes(),
    );
    hasher.update(summary.operation_count.to_be_bytes());
    for generation in [
        generations.0,
        generations.1,
        generations.2,
        generations.3,
        generations.4,
    ] {
        hasher.update(safe_generation_v2(generation)?.to_be_bytes());
    }
    Ok(hasher.finalize().into())
}

fn verify_exact_migration_receipt_v2(
    connection: &Connection,
    expected: &DispatchMigrationReceiptV2,
) -> Result<(), InternalCoordinatorError> {
    let receipt_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM coordinator_v2_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(invariant_v2)?;
    if receipt_count != 1 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    let exact = connection
        .query_row(
            "SELECT source_schema_digest, source_root_identity, source_summary_digest, \
                    verified_backup_digest, overlay_schema_digest, migration_generation, \
                    migrated_at_utc_ms, migrated_at_monotonic_ms, tool_identity \
             FROM coordinator_v2_migrations WHERE migration_attempt_id = ?1",
            [expected.migration_attempt_id.as_slice()],
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
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()
        .map_err(invariant_v2)?
        .ok_or(InternalCoordinatorError::InvariantFailed)?;
    if exact.0.as_slice() != expected.source_schema_digest
        || exact.1.as_slice() != expected.source_root_identity
        || exact.2.as_slice() != expected.source_summary_digest
        || exact.3.as_slice() != expected.verified_backup_digest
        || exact.4.as_slice() != expected.overlay_schema_digest
        || exact.5 != 1
        || safe_generation_v2(exact.6)? != expected.migrated_at_utc_ms
        || safe_generation_v2(exact.7)? != expected.migrated_at_monotonic_ms
        || exact.8 != expected.tool_identity.as_ref()
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn valid_tool_identity_v2(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn to_i64_v2(value: u64) -> Result<i64, InternalCoordinatorError> {
    if value > MAX_SAFE_U64 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    i64::try_from(value).map_err(|_| InternalCoordinatorError::InvariantFailed)
}

fn read_schema_objects_v2(
    connection: &Connection,
) -> Result<Vec<SchemaObjectV2>, InternalCoordinatorError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
        )
        .map_err(schema_invalid_v2)?;
    let rows = statement
        .query_map([], |row| {
            Ok(SchemaObjectV2 {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(schema_invalid_v2)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(schema_invalid_v2)
}

fn named_schema_object_v2(
    connection: &Connection,
    object_type: &str,
    name: &str,
) -> Result<SchemaObjectV2, InternalCoordinatorError> {
    connection
        .query_row(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| {
                Ok(SchemaObjectV2 {
                    object_type: row.get(0)?,
                    name: row.get(1)?,
                    table_name: row.get(2)?,
                    sql: row.get(3)?,
                })
            },
        )
        .map_err(schema_invalid_v2)
}

fn trigger_sql_v2(connection: &Connection, name: &str) -> Result<String, InternalCoordinatorError> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .map_err(schema_invalid_v2)
}

fn pragma_i64_v2(connection: &Connection, pragma: &str) -> Result<i64, InternalCoordinatorError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(schema_invalid_v2)
}

fn safe_generation_v2(value: i64) -> Result<u64, InternalCoordinatorError> {
    u64::try_from(value).map_err(|_| InternalCoordinatorError::InvariantFailed)
}

fn schema_invalid_v2(_: rusqlite::Error) -> InternalCoordinatorError {
    InternalCoordinatorError::SchemaInvalid
}

fn invariant_v2(_: rusqlite::Error) -> InternalCoordinatorError {
    InternalCoordinatorError::InvariantFailed
}

fn map_restore_sqlite_error_v2(_: &rusqlite::Error) -> InternalCoordinatorError {
    InternalCoordinatorError::RootUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_safety::CoordinatorRootIdentityV1;
    use helix_contracts::{ContractError, Result as ContractResult};
    use rusqlite::TransactionBehavior;

    struct HistoricalPlanKeys;

    impl Ed25519KeyResolver for HistoricalPlanKeys {
        fn resolve_ed25519(&self, _: &str) -> ContractResult<[u8; 32]> {
            Err(ContractError::UnknownKey)
        }
    }

    fn exact_empty_v1() -> (Connection, CoordinatorRootIdentityV1) {
        let connection = Connection::open_in_memory().expect("V2 fixture opens");
        connection
            .execute_batch(COORDINATOR_STORE_SCHEMA_V1_SQL)
            .expect("V1 schema installs");
        let root_identity = CoordinatorRootIdentityV1::from_bytes([0x41; 32]);
        connection
            .execute(
                "INSERT INTO coordinator_store_meta (\
                    singleton, format_version, store_generation, operation_generation, \
                    budget_generation, event_generation, quarantine_generation, root_identity, \
                    root_lifecycle_state, restore_identity_digest, restore_attestation_digest, \
                    restore_state_generation\
                 ) VALUES (1, 1, 0, 0, 0, 0, 0, ?1, 'ACTIVE', NULL, NULL, 0)",
                [root_identity.as_bytes().as_slice()],
            )
            .expect("base metadata installs");
        (connection, root_identity)
    }

    fn exact_empty_v2() -> (Connection, CoordinatorRootIdentityV1) {
        let (connection, root_identity) = exact_empty_v1();
        connection
            .execute_batch(COORDINATOR_DISPATCH_SCHEMA_V2_SQL)
            .expect("V2 overlay installs");
        connection
            .execute(
                "INSERT INTO dispatch_store_meta (\
                    singleton, extension_format_version, dispatch_store_generation, \
                    dispatch_generation, delivery_generation, receipt_generation, \
                    reconciliation_generation, event_generation, migration_generation, \
                    ordinary_queue_capacity, control_queue_capacity, root_lifecycle_state, \
                    restore_index_digest, restore_state_generation\
                 ) VALUES (1, 1, 1, 0, 0, 0, 0, 0, 1, 1024, 32, 'ACTIVE', NULL, 0)",
                [],
            )
            .expect("dispatch metadata installs");
        let source_digest = schema::embedded_schema_v1_sha256();
        let overlay_digest = embedded_dispatch_schema_v2_sha256();
        connection
            .execute(
                "INSERT INTO coordinator_v2_migrations (\
                    migration_attempt_id, source_schema_digest, source_root_identity, \
                    source_summary_digest, verified_backup_digest, overlay_schema_digest, \
                    migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms, \
                    tool_identity\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1000, 1000, 'helixos-test-v1')",
                params![
                    [0x42_u8; 32].as_slice(),
                    source_digest.as_slice(),
                    root_identity.as_bytes().as_slice(),
                    [0x43_u8; 32].as_slice(),
                    [0x44_u8; 32].as_slice(),
                    overlay_digest.as_slice(),
                ],
            )
            .expect("migration receipt installs");
        (connection, root_identity)
    }

    fn migration_request(byte: u8) -> DispatchMigrationRequestV2 {
        DispatchMigrationRequestV2::try_new([byte; 32], 1_000, 900, "helixos-dispatch-migrator-v2")
            .expect("migration request validates")
    }

    fn restore_stamp_guard_fixture() -> Connection {
        let connection = Connection::open_in_memory().expect("restore guard fixture opens");
        connection
            .execute_batch(
                "CREATE TABLE coordinator_store_meta (
                     singleton INTEGER, store_generation INTEGER, root_lifecycle_state TEXT,
                     restore_identity_digest BLOB, restore_attestation_digest BLOB,
                     restore_state_generation INTEGER
                 );
                 CREATE TABLE dispatch_store_meta (
                     singleton INTEGER, dispatch_store_generation INTEGER,
                     root_lifecycle_state TEXT, restore_index_digest BLOB,
                     restore_state_generation INTEGER
                 );
                 CREATE TABLE prepared_operations (
                     operation_id TEXT, attempt_id BLOB, plan_id BLOB, task_id TEXT,
                     workload_id TEXT, canonical_plan BLOB, canonical_plan_length INTEGER,
                     operation_state TEXT, state_generation INTEGER, created_generation INTEGER,
                     failed_generation INTEGER, failed_reason_code TEXT, boot_id TEXT,
                     instance_epoch INTEGER, fencing_epoch INTEGER,
                     effective_expires_at_utc_ms INTEGER,
                     effective_deadline_monotonic_ms INTEGER, reservation_id TEXT,
                     recovery_mode TEXT, current_event_id BLOB,
                     restored_source_generation INTEGER
                 );
                 CREATE TABLE dispatch_records (operation_id TEXT);
                 CREATE TABLE dispatch_definite_refusal_guards (
                     operation_id TEXT, preparation_attempt_id BLOB, reservation_id TEXT,
                     base_failure_transition_generation INTEGER, base_failure_event_id BLOB,
                     base_operation_state TEXT
                 );
                 INSERT INTO coordinator_store_meta
                 VALUES (1, 7, 'ACTIVE', NULL, NULL, 0);
                 INSERT INTO dispatch_store_meta VALUES (1, 3, 'ACTIVE', NULL, 0);
                 INSERT INTO prepared_operations VALUES (
                     'operation:restore-guard', x'11', x'22', 'task:restore-guard',
                     'workload:restore-guard', x'33', 1, 'PREPARING', 2, 1,
                     NULL, NULL, 'boot:restore-guard', 5, 9, 1000, 900,
                     'reservation:restore-guard', 'COMPENSATION', x'44', NULL
                 );
                 INSERT INTO dispatch_records VALUES ('operation:restore-guard');",
            )
            .expect("restore guard fixture installs");
        let start = COORDINATOR_DISPATCH_SCHEMA_V2_SQL
            .find("CREATE TRIGGER dispatch_overlay_guards_v1_operation")
            .expect("operation guard exists in embedded schema");
        let tail = &COORDINATOR_DISPATCH_SCHEMA_V2_SQL[start..];
        let end = tail
            .find("\nEND;")
            .map(|index| index + "\nEND;".len())
            .expect("operation guard terminates");
        connection
            .execute_batch(&tail[..end])
            .expect("exact embedded operation guard installs");
        connection
    }

    fn arm_restore_stamp_guard(connection: &Connection) {
        connection
            .execute(
                "UPDATE dispatch_store_meta SET
                     dispatch_store_generation = 4,
                     root_lifecycle_state = 'RESTORE_PENDING',
                     restore_index_digest = ?1,
                     restore_state_generation = 4
                 WHERE singleton = 1",
                [[0x55_u8; 32].as_slice()],
            )
            .expect("dispatch-side restore transition arms exact stamp");
    }

    fn restore_stamp_guard_row(connection: &Connection) -> Vec<rusqlite::types::Value> {
        connection
            .query_row(
                "SELECT operation_id, attempt_id, plan_id, task_id, workload_id, \
                        canonical_plan, canonical_plan_length, operation_state, \
                        state_generation, created_generation, failed_generation, \
                        failed_reason_code, boot_id, instance_epoch, fencing_epoch, \
                        effective_expires_at_utc_ms, effective_deadline_monotonic_ms, \
                        reservation_id, recovery_mode, current_event_id, \
                        restored_source_generation \
                 FROM prepared_operations",
                [],
                |row| {
                    (0..row.as_ref().column_count())
                        .map(|index| row.get(index))
                        .collect()
                },
            )
            .expect("restore guard operation row reads")
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RestoreStampGuardBaseMetadata {
        store_generation: i64,
        root_lifecycle_state: String,
        restore_identity_digest: Option<Vec<u8>>,
        restore_attestation_digest: Option<Vec<u8>>,
        restore_state_generation: i64,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RestoreStampGuardDispatchMetadata {
        store_generation: i64,
        root_lifecycle_state: String,
        restore_index_digest: Option<Vec<u8>>,
        restore_state_generation: i64,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RestoreStampGuardMetadata {
        base: RestoreStampGuardBaseMetadata,
        dispatch: RestoreStampGuardDispatchMetadata,
    }

    fn restore_stamp_guard_metadata(connection: &Connection) -> RestoreStampGuardMetadata {
        let base = connection
            .query_row(
                "SELECT store_generation, root_lifecycle_state, restore_identity_digest, \
                        restore_attestation_digest, restore_state_generation \
                 FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| {
                    Ok(RestoreStampGuardBaseMetadata {
                        store_generation: row.get(0)?,
                        root_lifecycle_state: row.get(1)?,
                        restore_identity_digest: row.get(2)?,
                        restore_attestation_digest: row.get(3)?,
                        restore_state_generation: row.get(4)?,
                    })
                },
            )
            .expect("restore guard base metadata reads");
        let dispatch = connection
            .query_row(
                "SELECT dispatch_store_generation, root_lifecycle_state, \
                        restore_index_digest, restore_state_generation \
                 FROM dispatch_store_meta WHERE singleton = 1",
                [],
                |row| {
                    Ok(RestoreStampGuardDispatchMetadata {
                        store_generation: row.get(0)?,
                        root_lifecycle_state: row.get(1)?,
                        restore_index_digest: row.get(2)?,
                        restore_state_generation: row.get(3)?,
                    })
                },
            )
            .expect("restore guard dispatch metadata reads");
        RestoreStampGuardMetadata { base, dispatch }
    }

    fn assert_restore_stamp_guard_rejects(connection: &Connection, sql: &str, context: &str) {
        let before = restore_stamp_guard_row(connection);
        let error = connection
            .execute(sql, [])
            .expect_err("non-exact restore stamp must be rejected");
        assert!(
            error
                .to_string()
                .contains("dispatch overlay permits only guarded definite-refusal failure"),
            "{context}: unexpected trigger error: {error}"
        );
        assert_eq!(
            restore_stamp_guard_row(connection),
            before,
            "{context}: rejected update changed the operation row"
        );
    }

    #[test]
    fn restore_stamp_guard_allows_only_exact_null_to_source_generation_after_pending_transition() {
        let connection = restore_stamp_guard_fixture();
        let before = restore_stamp_guard_row(&connection);
        arm_restore_stamp_guard(&connection);
        assert_eq!(
            connection
                .execute(
                    "UPDATE prepared_operations SET restored_source_generation = 7
                     WHERE operation_id = 'operation:restore-guard'",
                    [],
                )
                .expect("exact restore stamp is admitted"),
            1
        );
        let stamped: i64 = connection
            .query_row(
                "SELECT restored_source_generation FROM prepared_operations",
                [],
                |row| row.get(0),
            )
            .expect("restore stamp reads");
        assert_eq!(stamped, 7);
        let after = restore_stamp_guard_row(&connection);
        assert_eq!(&after[..20], &before[..20]);
        assert_eq!(before[20], rusqlite::types::Value::Null);
        assert_eq!(after[20], rusqlite::types::Value::Integer(7));
    }

    #[test]
    fn restore_stamp_guard_rejects_unarmed_wrong_closed_window_and_repeated_updates() {
        let unarmed = restore_stamp_guard_fixture();
        assert_restore_stamp_guard_rejects(
            &unarmed,
            "UPDATE prepared_operations SET restored_source_generation = 7",
            "dispatch-active window",
        );

        let wrong_generation = restore_stamp_guard_fixture();
        arm_restore_stamp_guard(&wrong_generation);
        assert_restore_stamp_guard_rejects(
            &wrong_generation,
            "UPDATE prepared_operations SET restored_source_generation = 8",
            "wrong source generation",
        );

        let closed_window = restore_stamp_guard_fixture();
        arm_restore_stamp_guard(&closed_window);
        closed_window
            .execute(
                "UPDATE coordinator_store_meta SET \
                     root_lifecycle_state = 'RESTORE_PENDING', \
                     restore_identity_digest = ?1, \
                     restore_attestation_digest = ?2, \
                     restore_state_generation = 8 \
                 WHERE singleton = 1",
                rusqlite::params![[0x66_u8; 32].as_slice(), [0x67_u8; 32].as_slice()],
            )
            .expect("base pending transition closes restore stamp window");
        assert_restore_stamp_guard_rejects(
            &closed_window,
            "UPDATE prepared_operations SET restored_source_generation = 7",
            "base-pending closed window",
        );

        let repeated = restore_stamp_guard_fixture();
        arm_restore_stamp_guard(&repeated);
        repeated
            .execute(
                "UPDATE prepared_operations SET restored_source_generation = 7",
                [],
            )
            .expect("first exact stamp succeeds");
        assert_restore_stamp_guard_rejects(
            &repeated,
            "UPDATE prepared_operations SET restored_source_generation = 7",
            "identical repeated stamp",
        );
        assert_restore_stamp_guard_rejects(
            &repeated,
            "UPDATE prepared_operations SET restored_source_generation = 8",
            "rewritten repeated stamp",
        );
    }

    #[test]
    fn restore_stamp_guard_rejects_every_concurrent_operation_column_mutation() {
        let mutations = [
            ("operation_id", "operation_id = 'operation:substituted'"),
            ("attempt_id", "attempt_id = x'12'"),
            ("plan_id", "plan_id = x'23'"),
            ("task_id", "task_id = 'task:substituted'"),
            ("workload_id", "workload_id = 'workload:substituted'"),
            ("canonical_plan", "canonical_plan = x'34'"),
            ("canonical_plan_length", "canonical_plan_length = 2"),
            ("operation_state", "operation_state = 'FAILED'"),
            ("state_generation", "state_generation = 3"),
            ("created_generation", "created_generation = 2"),
            ("failed_generation", "failed_generation = 2"),
            ("failed_reason_code", "failed_reason_code = 'GRANT_EXPIRED'"),
            ("boot_id", "boot_id = 'boot:substituted'"),
            ("instance_epoch", "instance_epoch = 6"),
            ("fencing_epoch", "fencing_epoch = 10"),
            (
                "effective_expires_at_utc_ms",
                "effective_expires_at_utc_ms = 1001",
            ),
            (
                "effective_deadline_monotonic_ms",
                "effective_deadline_monotonic_ms = 901",
            ),
            (
                "reservation_id",
                "reservation_id = 'reservation:substituted'",
            ),
            ("recovery_mode", "recovery_mode = 'REGENERATABLE'"),
            ("current_event_id", "current_event_id = x'45'"),
        ];
        assert_eq!(mutations.len(), 20);
        for (column, mutation) in mutations {
            let connection = restore_stamp_guard_fixture();
            arm_restore_stamp_guard(&connection);
            assert_restore_stamp_guard_rejects(
                &connection,
                &format!(
                    "UPDATE prepared_operations \
                     SET restored_source_generation = 7, {mutation}"
                ),
                column,
            );
        }
    }

    #[test]
    fn restore_stamp_guard_window_rolls_back_dispatch_pending_and_stamp_atomically() {
        let mut connection = restore_stamp_guard_fixture();
        let before_metadata = restore_stamp_guard_metadata(&connection);
        let before_row = restore_stamp_guard_row(&connection);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("restore guard transaction begins");
        arm_restore_stamp_guard(&transaction);
        transaction
            .execute(
                "UPDATE prepared_operations SET restored_source_generation = 7",
                [],
            )
            .expect("exact restore stamp stages");
        let error = transaction
            .execute(
                "UPDATE prepared_operations SET task_id = 'task:substituted'",
                [],
            )
            .expect_err("post-stamp mutation forces restore transaction refusal");
        assert!(error
            .to_string()
            .contains("dispatch overlay permits only guarded definite-refusal failure"));
        transaction
            .rollback()
            .expect("failed restore transaction rolls back");
        assert_eq!(restore_stamp_guard_metadata(&connection), before_metadata);
        assert_eq!(restore_stamp_guard_row(&connection), before_row);
    }

    #[test]
    fn exact_empty_v2_schema_and_composite_graph_verify() {
        let (connection, root_identity) = exact_empty_v2();
        let verified = verify_dispatch_schema_v2(&connection, root_identity, &HistoricalPlanKeys)
            .expect("exact empty V2 verifies");
        assert_eq!(verified.base_summary.operation_count, 0);
        assert_eq!(verified.generations.store, 1);
        assert_eq!(format!("{verified:?}"), "VerifiedDispatchSchemaV2 { .. }");
    }

    #[test]
    fn permanent_dispatch_history_policy_is_closed_and_tamper_is_typed() {
        let (connection, _) = exact_empty_v2();
        let policy = verify_permanent_dispatch_history_v1(&connection)
            .expect("exact retained history verifies");
        assert!(policy.history_is_permanent());
        assert!(policy.history_is_append_only());
        assert!(!policy.history_deletion_enabled());
        assert!(!policy.identifier_reuse_enabled());
        assert!(!policy.generation_reuse_enabled());
        assert!(!policy.automatic_pruning_enabled());
        assert!(!policy.physical_secure_erasure_claimed());
        assert!(policy.requires_approved_encrypted_at_rest_profile());

        connection
            .execute_batch("DROP INDEX dispatch_events_generation_uq")
            .expect("fixture generation key drops");
        assert_eq!(
            verify_permanent_dispatch_history_v1(&connection)
                .expect_err("generation-key tamper refuses"),
            InternalCoordinatorError::SchemaInvalid
        );
    }

    #[test]
    fn partial_or_tampered_v2_is_never_repaired() {
        let (connection, root_identity) = exact_empty_v2();
        connection
            .execute_batch("DROP TRIGGER dispatch_grants_no_delete")
            .expect("fixture trigger drops");
        assert_eq!(
            verify_dispatch_schema_v2(&connection, root_identity, &HistoricalPlanKeys)
                .expect_err("partial V2 denies"),
            InternalCoordinatorError::SchemaInvalid
        );
        assert_eq!(
            pragma_i64_v2(&connection, "user_version").expect("version reads"),
            COORDINATOR_DISPATCH_SCHEMA_VERSION_V2,
            "strict verification must not repair or roll back"
        );
    }

    #[test]
    fn explicit_immediate_migration_publishes_exact_receipt_and_readback() {
        let (mut connection, root_identity) = exact_empty_v1();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("immediate migration transaction begins");
        let receipt = stage_dispatch_migration_v2(
            &transaction,
            root_identity,
            &HistoricalPlanKeys,
            [0x51; 32],
            &migration_request(0x52),
        )
        .expect("exact V1 stages V2 once");
        assert_eq!(
            pragma_i64_v2(&transaction, "user_version").expect("staged version reads"),
            2
        );
        transaction.commit().expect("migration commits");

        assert!(matches!(
            classify_dispatch_migration_readback_v2(
                &connection,
                root_identity,
                &HistoricalPlanKeys,
                &receipt,
            ),
            DispatchMigrationReadbackV2::Committed(_)
        ));
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM coordinator_v2_migrations",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .expect("receipt count reads"),
            1
        );
        assert_eq!(
            refuse_in_place_dispatch_downgrade_v2(&connection)
                .expect_err("permanent history refuses downgrade"),
            InternalCoordinatorError::SchemaUnsupported
        );
    }

    #[test]
    fn rolled_back_migration_is_exactly_absent_and_is_not_rerun_by_readback() {
        let (mut connection, root_identity) = exact_empty_v1();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("immediate migration transaction begins");
        let receipt = stage_dispatch_migration_v2(
            &transaction,
            root_identity,
            &HistoricalPlanKeys,
            [0x61; 32],
            &migration_request(0x62),
        )
        .expect("migration stages");
        transaction.rollback().expect("migration rolls back");

        assert!(matches!(
            classify_dispatch_migration_readback_v2(
                &connection,
                root_identity,
                &HistoricalPlanKeys,
                &receipt,
            ),
            DispatchMigrationReadbackV2::ConfirmedRollback
        ));
        assert_eq!(
            pragma_i64_v2(&connection, "user_version").expect("V1 version reads"),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema \
                     WHERE name = 'coordinator_v2_migrations' OR name LIKE 'dispatch_%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("overlay absence reads"),
            0,
            "readback classification must never execute the overlay"
        );
    }

    #[test]
    fn migration_fault_callbacks_observe_exact_fb074_fb075_states_and_rollback() {
        for selected in [74_u8, 75_u8] {
            let (mut connection, root_identity) = exact_empty_v1();
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("immediate migration transaction begins");
            let mut reached = Vec::new();
            let error = stage_dispatch_migration_with_checkpoints_v2(
                &transaction,
                root_identity,
                &HistoricalPlanKeys,
                [selected; 32],
                &migration_request(selected),
                |ordinal| {
                    reached.push(ordinal);
                    if ordinal != selected {
                        return Ok(());
                    }
                    let version = pragma_i64_v2(&transaction, "user_version")?;
                    let receipt_count: i64 = transaction
                        .query_row(
                            "SELECT COUNT(*) FROM coordinator_v2_migrations",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(invariant_v2)?;
                    assert_eq!(receipt_count, 1, "FB{selected:03} sees the staged receipt");
                    if selected == 74 {
                        assert_eq!(version, 1, "FB074 precedes user_version publication");
                    } else {
                        assert_eq!(version, 2, "FB075 follows the final mutation");
                        verify_dispatch_schema_v2(
                            &transaction,
                            root_identity,
                            &HistoricalPlanKeys,
                        )?;
                    }
                    Err(InternalCoordinatorError::InvariantFailed)
                },
            )
            .expect_err("selected migration checkpoint interrupts staging");
            assert_eq!(error, InternalCoordinatorError::InvariantFailed);
            assert_eq!(
                reached,
                if selected == 74 {
                    vec![74]
                } else {
                    vec![74, 75]
                }
            );
            transaction
                .rollback()
                .expect("interrupted migration rolls back");

            schema::verify_full(&connection, root_identity, &HistoricalPlanKeys)
                .expect("interrupted migration reopens as exact V1");
            assert_eq!(
                pragma_i64_v2(&connection, "user_version").expect("version reads"),
                1
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_schema \
                         WHERE name = 'coordinator_v2_migrations' OR name LIKE 'dispatch_%'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("overlay absence reads"),
                0
            );
        }
    }

    #[test]
    fn committed_history_with_another_attempt_is_conflict_not_retry_authority() {
        let (mut connection, root_identity) = exact_empty_v1();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("immediate migration transaction begins");
        let receipt = stage_dispatch_migration_v2(
            &transaction,
            root_identity,
            &HistoricalPlanKeys,
            [0x71; 32],
            &migration_request(0x72),
        )
        .expect("migration stages");
        transaction.commit().expect("migration commits");
        let conflicting = DispatchMigrationReceiptV2 {
            migration_attempt_id: [0x73; 32],
            source_schema_digest: receipt.source_schema_digest,
            source_root_identity: receipt.source_root_identity,
            source_summary_digest: receipt.source_summary_digest,
            verified_backup_digest: receipt.verified_backup_digest,
            overlay_schema_digest: receipt.overlay_schema_digest,
            migrated_at_utc_ms: receipt.migrated_at_utc_ms,
            migrated_at_monotonic_ms: receipt.migrated_at_monotonic_ms,
            tool_identity: receipt.tool_identity.clone(),
        };

        assert!(matches!(
            classify_dispatch_migration_readback_v2(
                &connection,
                root_identity,
                &HistoricalPlanKeys,
                &conflicting,
            ),
            DispatchMigrationReadbackV2::Conflict
        ));
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM coordinator_v2_migrations",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .expect("receipt count reads"),
            1,
            "conflict classification must not append or rerun"
        );
    }

    #[test]
    fn dispatch_corruption_tombstone_remains_a_permanent_v2_admission_fence() {
        let connection = Connection::open_in_memory().expect("database opens");
        connection
            .execute_batch(
                "CREATE TABLE preparation_quarantines (
                     quarantine_reason TEXT NOT NULL,
                     quarantine_status TEXT NOT NULL
                 );
                 INSERT INTO preparation_quarantines VALUES (
                     'INVARIANT_CONFLICT', 'ACTIVE'
                 );",
            )
            .expect("quarantine fixture creates");
        assert_eq!(
            verify_no_active_dispatch_corruption_quarantine_v1(&connection),
            Err(InternalCoordinatorError::InvariantFailed)
        );
        connection
            .execute(
                "UPDATE preparation_quarantines
                 SET quarantine_status = 'RESOLVED_TOMBSTONE'",
                [],
            )
            .expect("fixture transitions to tombstone");
        assert_eq!(
            verify_no_active_dispatch_corruption_quarantine_v1(&connection),
            Err(InternalCoordinatorError::InvariantFailed),
            "status changes cannot lift a retained dispatch-corruption fence"
        );
    }
}
