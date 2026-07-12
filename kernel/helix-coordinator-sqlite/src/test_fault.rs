//! Private non-default fault-injection plumbing.
//!
//! This module owns the 86 provider/storage points in the closed v1 taxonomy. The
//! portable orchestration module owns the remaining 37 authority points. Hooks are
//! Selection is explicit and caller-owned; production call sites use a disabled session.

// T027 deliberately lands the closed seam before later tasks add every call site.
#![allow(dead_code)]

pub(crate) const CLOSED_FAULT_BOUNDARY_COUNT_V1: usize = 123;

macro_rules! closed_fault_boundaries_v1 {
    ($ids:ident; $($variant:ident => $id:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum FaultBoundaryV1 {
            $($variant),+
        }

impl FaultBoundaryV1 {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(crate) const fn id(self) -> &'static str {
                match self {
                    $(Self::$variant => $id),+
                }
            }

            pub(crate) const fn is_transactional_coordinator_v1(self) -> bool {
                matches!(
                    self,
                    Self::PositiveCoordinatorCommitCoordinatorRootAccepted
                        | Self::PositiveCoordinatorCommitCoordinatorProfileAccepted
                        | Self::PositiveCoordinatorCommitCoordinatorInvariantsAccepted
                        | Self::PositiveCoordinatorCommitBeginImmediateAcquired
                        | Self::PositiveCoordinatorCommitOperationAttemptIdentityClassified
                        | Self::PositiveCoordinatorCommitBudgetScopeLoaded
                        | Self::PositiveCoordinatorCommitFinalArithmeticCapacityClassified
                        | Self::PositiveCoordinatorCommitMemberStaged
                        | Self::PositiveCoordinatorCommitSqliteCommitInvoked
                        | Self::PositiveCoordinatorCommitSqliteCommitReturnedWithTrustedClassification
                        | Self::AcknowledgementUncertainConnectionClosed
                        | Self::AcknowledgementReadbackSnapshotOpened
                        | Self::AcknowledgementReadbackClassifiedThisAttempt
                        | Self::AcknowledgementReadbackClassifiedPriorExactAttempt
                        | Self::AcknowledgementReadbackClassifiedConflict
                        | Self::AcknowledgementReadbackClassifiedDefiniteAbsence
                        | Self::AcknowledgementReadbackClassifiedAmbiguous
                        | Self::KnownFailureBeginImmediateAcquired
                        | Self::KnownFailureOperationFailedStaged
                        | Self::KnownFailureTransitionStaged
                        | Self::KnownFailureScopeHeldSubtractionStaged
                        | Self::KnownFailureReservationReleasedStaged
                        | Self::KnownFailureEventStaged
                        | Self::KnownFailureMetadataStaged
                        | Self::KnownFailureCommitReturned
                        | Self::KnownFailureCommitClassified
                )
            }
        }

        pub(crate) const $ids: &[&str] = &[$($id),+];
    };
}

closed_fault_boundaries_v1!(COORDINATOR_BOUNDARY_IDS_V1;
    RecoveryPublicationGuardAcquired => "recovery_publication_guard_acquired",
    RecoveryStagingCreated => "recovery_staging_created",
    RecoveryStagingWritten => "recovery_staging_written",
    RecoveryStagingSynchronized => "recovery_staging_synchronized",
    RecoveryStagingClosed => "recovery_staging_closed",
    RecoveryStagingReopened => "recovery_staging_reopened",
    RecoveryMaterialDigestLengthCapacityVerified => "recovery_material_digest_length_capacity_verified",
    RecoveryMaterialPublished => "recovery_material_published",
    RecoveryManifestStaged => "recovery_manifest_staged",
    RecoveryManifestSynchronized => "recovery_manifest_synchronized",
    RecoveryManifestPublished => "recovery_manifest_published",
    RecoveryManifestReopened => "recovery_manifest_reopened",
    RecoveryReceiptReturned => "recovery_receipt_returned",
    PositiveCoordinatorCommitCoordinatorRootAccepted => "positive_coordinator_commit_coordinator_root_accepted",
    PositiveCoordinatorCommitCoordinatorProfileAccepted => "positive_coordinator_commit_coordinator_profile_accepted",
    PositiveCoordinatorCommitCoordinatorInvariantsAccepted => "positive_coordinator_commit_coordinator_invariants_accepted",
    PositiveCoordinatorCommitBeginImmediateAcquired => "positive_coordinator_commit_begin_immediate_acquired",
    PositiveCoordinatorCommitOperationAttemptIdentityClassified => "positive_coordinator_commit_operation_attempt_identity_classified",
    PositiveCoordinatorCommitBudgetScopeLoaded => "positive_coordinator_commit_budget_scope_loaded",
    PositiveCoordinatorCommitFinalArithmeticCapacityClassified => "positive_coordinator_commit_final_arithmetic_capacity_classified",
    PositiveCoordinatorCommitMemberStaged => "positive_coordinator_commit_member_staged",
    PositiveCoordinatorCommitSqliteCommitInvoked => "positive_coordinator_commit_sqlite_commit_invoked",
    PositiveCoordinatorCommitSqliteCommitReturnedWithTrustedClassification => "positive_coordinator_commit_sqlite_commit_returned_with_trusted_classification",
    AcknowledgementUncertainConnectionClosed => "acknowledgement_uncertain_connection_closed",
    AcknowledgementReadbackSnapshotOpened => "acknowledgement_readback_snapshot_opened",
    AcknowledgementReadbackClassifiedThisAttempt => "acknowledgement_readback_classified_this_attempt",
    AcknowledgementReadbackClassifiedPriorExactAttempt => "acknowledgement_readback_classified_prior_exact_attempt",
    AcknowledgementReadbackClassifiedConflict => "acknowledgement_readback_classified_conflict",
    AcknowledgementReadbackClassifiedDefiniteAbsence => "acknowledgement_readback_classified_definite_absence",
    AcknowledgementReadbackClassifiedAmbiguous => "acknowledgement_readback_classified_ambiguous",
    KnownFailureBeginImmediateAcquired => "known_failure_begin_immediate_acquired",
    KnownFailureOperationFailedStaged => "known_failure_operation_failed_staged",
    KnownFailureTransitionStaged => "known_failure_transition_staged",
    KnownFailureScopeHeldSubtractionStaged => "known_failure_scope_held_subtraction_staged",
    KnownFailureReservationReleasedStaged => "known_failure_reservation_released_staged",
    KnownFailureEventStaged => "known_failure_event_staged",
    KnownFailureMetadataStaged => "known_failure_metadata_staged",
    KnownFailureCommitReturned => "known_failure_commit_returned",
    KnownFailureCommitClassified => "known_failure_commit_classified",
    QuarantineAndRetirementQuarantineInserted => "quarantine_and_retirement_quarantine_inserted",
    QuarantineAndRetirementQuarantineResolved => "quarantine_and_retirement_quarantine_resolved",
    QuarantineAndRetirementOperationBoundRetirementPendingCommitted => "quarantine_and_retirement_operation_bound_retirement_pending_committed",
    QuarantineAndRetirementTrueOrphanDefinitiveProofReturned => "quarantine_and_retirement_true_orphan_definitive_proof_returned",
    QuarantineAndRetirementOrphanResolutionRetirementPendingTombstoneCommitted => "quarantine_and_retirement_orphan_resolution_retirement_pending_tombstone_committed",
    QuarantineAndRetirementProviderRetirementInvoked => "quarantine_and_retirement_provider_retirement_invoked",
    QuarantineAndRetirementProviderBytesRetired => "quarantine_and_retirement_provider_bytes_retired",
    QuarantineAndRetirementRetirementManifestPublished => "quarantine_and_retirement_retirement_manifest_published",
    QuarantineAndRetirementOperationBoundRetiredTombstoneCommitted => "quarantine_and_retirement_operation_bound_retired_tombstone_committed",
    QuarantineAndRetirementOrphanRetiredTombstoneCommitted => "quarantine_and_retirement_orphan_retired_tombstone_committed",
    BackupPausePersisted => "backup_pause_persisted",
    BackupProviderMaintenanceGuardAcquired => "backup_provider_maintenance_guard_acquired",
    BackupCoordinatorMaintenanceGuardAcquired => "backup_coordinator_maintenance_guard_acquired",
    BackupSourceProfilesVerified => "backup_source_profiles_verified",
    BackupSourceInvariantsVerified => "backup_source_invariants_verified",
    BackupSourceGenerationsCaptured => "backup_source_generations_captured",
    BackupSqliteOnlineBackupCompleted => "backup_sqlite_online_backup_completed",
    BackupSqliteOnlineBackupClosed => "backup_sqlite_online_backup_closed",
    BackupSqliteOnlineBackupIntegrityChecked => "backup_sqlite_online_backup_integrity_checked",
    BackupSqliteOnlineBackupHashed => "backup_sqlite_online_backup_hashed",
    BackupProviderEnumerationReconciled => "backup_provider_enumeration_reconciled",
    BackupMaterialPresentPackageExported => "backup_material_present_package_exported",
    BackupRetirementTombstoneExported => "backup_retirement_tombstone_exported",
    BackupInventoryJcsFinalized => "backup_inventory_jcs_finalized",
    BackupSourceGenerationsRechecked => "backup_source_generations_rechecked",
    BackupTopLevelManifestStaged => "backup_top_level_manifest_staged",
    BackupTopLevelManifestPublished => "backup_top_level_manifest_published",
    BackupAttestationProtectedJcsFinalized => "backup_attestation_protected_jcs_finalized",
    BackupAttestationSigned => "backup_attestation_signed",
    BackupAttestationStaged => "backup_attestation_staged",
    BackupAttestationPublished => "backup_attestation_published",
    BackupAttestationReopened => "backup_attestation_reopened",
    BackupAttestationVerified => "backup_attestation_verified",
    RestorePackageAndPinnedProvenanceAccepted => "restore_package_and_pinned_provenance_accepted",
    RestoreEmptyCoordinatorRootReserved => "restore_empty_coordinator_root_reserved",
    RestoreEmptyRecoveryRootReserved => "restore_empty_recovery_root_reserved",
    RestoreCoordinatorDatabaseImported => "restore_coordinator_database_imported",
    RestoreWalFullProfileEstablished => "restore_wal_full_profile_established",
    RestoreRecoveryPackageImported => "restore_recovery_package_imported",
    RestoreCoordinatorRestorePendingCommitted => "restore_coordinator_restore_pending_committed",
    RestoreCoordinatorPendingRootMarkerPublished => "restore_coordinator_pending_root_marker_published",
    RestoreRecoveryRestorePendingMetadataPublished => "restore_recovery_restore_pending_metadata_published",
    RestoreBothRootsClosed => "restore_both_roots_closed",
    RestoreBothRootsReopened => "restore_both_roots_reopened",
    RestoreBothRootsAgreementClassified => "restore_both_roots_agreement_classified",
    RestoreVerifiedPreparationRestoreReturned => "restore_verified_preparation_restore_returned",
    RestoreQuarantinePersisted => "restore_quarantine_persisted",
);

/// Reaches one coordinator v1 boundary through an explicit disabled session.
///
/// Selected sessions are carried by dedicated test operations and process probes; an
/// ordinary production call site cannot acquire injection authority implicitly.
#[inline]
pub(crate) fn reach(boundary: FaultBoundaryV1) {
    let decision = FaultSessionV1::disabled_v1().checkpoint_v1(boundary);
    assert_eq!(decision, FaultDecisionV1::Continue);
}

/// Closed action selected by a caller-owned fault-injection session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultEffectV1 {
    ReturnError,
    ProcessBarrier,
}

impl FaultEffectV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ReturnError => "RETURN_ERROR",
            Self::ProcessBarrier => "PROCESS_BARRIER",
        }
    }
}

impl std::fmt::Debug for FaultEffectV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Payload-free validation failure for an explicit fault selection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultSelectionErrorV1 {
    InvalidOccurrence,
}

impl FaultSelectionErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidOccurrence => "INVALID_FAULT_OCCURRENCE",
        }
    }
}

impl std::fmt::Debug for FaultSelectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::fmt::Display for FaultSelectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FaultSelectionErrorV1 {}

/// One exact, caller-supplied boundary occurrence to inject at most once.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FaultSelectionV1 {
    boundary: FaultBoundaryV1,
    occurrence: u64,
    effect: FaultEffectV1,
}

impl FaultSelectionV1 {
    pub(crate) const fn try_new(
        boundary: FaultBoundaryV1,
        occurrence: u64,
        effect: FaultEffectV1,
    ) -> Result<Self, FaultSelectionErrorV1> {
        if occurrence == 0 {
            return Err(FaultSelectionErrorV1::InvalidOccurrence);
        }
        Ok(Self {
            boundary,
            occurrence,
            effect,
        })
    }
}

impl std::fmt::Debug for FaultSelectionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FaultSelectionV1")
            .field("boundary", &self.boundary.id())
            .field("occurrence", &self.occurrence)
            .field("effect", &self.effect)
            .finish()
    }
}

/// Decision returned by an explicit session checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultDecisionV1 {
    Continue,
    Inject(FaultEffectV1),
}

/// Mutable occurrence counter owned by one test operation or child-process probe.
///
/// There is deliberately no ambient selector or shared registry. A production call
/// path can only inject after a test-only caller explicitly carries this session to a
/// checkpoint.
pub(crate) struct FaultSessionV1 {
    selection: Option<FaultSelectionV1>,
    matching_occurrences: u64,
    injected: bool,
}

/// Caller-owned bridge from an exact production checkpoint to the process harness.
///
/// The callback is transferred into one workflow together with the session. Nothing
/// can discover it through process state, a global registry or thread-local storage.
/// A `ProcessBarrier` callback is expected not to return because the parent terminates
/// the child after observing the private marker.
struct FaultProbeStateV1 {
    session: FaultSessionV1,
    process_barrier: Option<Box<dyn FnMut() + Send>>,
}

#[derive(Clone)]
pub(crate) struct FaultProbeV1 {
    state: std::sync::Arc<std::sync::Mutex<FaultProbeStateV1>>,
}

impl FaultProbeV1 {
    pub(crate) fn disabled_v1() -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(FaultProbeStateV1 {
                session: FaultSessionV1::disabled_v1(),
                process_barrier: None,
            })),
        }
    }

    pub(crate) fn selected_process_barrier_v1(
        selection: FaultSelectionV1,
        process_barrier: Box<dyn FnMut() + Send>,
    ) -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(FaultProbeStateV1 {
                session: FaultSessionV1::selected_v1(selection),
                process_barrier: Some(process_barrier),
            })),
        }
    }

    /// Reaches the exact call site using this workflow's explicit session custody.
    pub(crate) fn reach_v1(&self, boundary: FaultBoundaryV1) {
        // Move the one-shot callback out while deciding, then release the state lock
        // before entering caller code. A process barrier may block forever by design;
        // retaining the mutex across it would deadlock cloned observation handles.
        let (decision, process_barrier) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let decision = state.session.checkpoint_v1(boundary);
            let process_barrier =
                if decision == FaultDecisionV1::Inject(FaultEffectV1::ProcessBarrier) {
                    state.process_barrier.take()
                } else {
                    None
                };
            (decision, process_barrier)
        };
        match decision {
            FaultDecisionV1::Continue => {}
            FaultDecisionV1::Inject(FaultEffectV1::ProcessBarrier) => {
                let mut barrier = process_barrier
                    .expect("selected process barrier retains its caller-owned callback");
                barrier();
                panic!("PROCESS_BARRIER_RETURNED");
            }
            FaultDecisionV1::Inject(FaultEffectV1::ReturnError) => {
                panic!("RETURN_ERROR_REQUIRES_RESULT_BEARING_TEST_DRIVER");
            }
        }
    }

    pub(crate) fn injected_v1(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .session
            .injected
    }
}

impl Default for FaultProbeV1 {
    fn default() -> Self {
        Self::disabled_v1()
    }
}

impl std::fmt::Debug for FaultProbeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        formatter
            .debug_struct("FaultProbeV1")
            .field("session", &state.session)
            .field("process_barrier_present", &state.process_barrier.is_some())
            .finish_non_exhaustive()
    }
}

impl FaultSessionV1 {
    pub(crate) const fn disabled_v1() -> Self {
        Self {
            selection: None,
            matching_occurrences: 0,
            injected: false,
        }
    }

    pub(crate) const fn selected_v1(selection: FaultSelectionV1) -> Self {
        Self {
            selection: Some(selection),
            matching_occurrences: 0,
            injected: false,
        }
    }

    pub(crate) fn checkpoint_v1(&mut self, boundary: FaultBoundaryV1) -> FaultDecisionV1 {
        let Some(selection) = self.selection else {
            return FaultDecisionV1::Continue;
        };
        if self.injected || boundary != selection.boundary {
            return FaultDecisionV1::Continue;
        }

        self.matching_occurrences = self.matching_occurrences.saturating_add(1);
        if self.matching_occurrences == selection.occurrence {
            self.injected = true;
            FaultDecisionV1::Inject(selection.effect)
        } else {
            FaultDecisionV1::Continue
        }
    }
}

impl Default for FaultSessionV1 {
    fn default() -> Self {
        Self::disabled_v1()
    }
}

impl std::fmt::Debug for FaultSessionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FaultSessionV1")
            .field("enabled", &self.selection.is_some())
            .field("injected", &self.injected)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const EXPECTED_PORTABLE_BOUNDARY_IDS_V1: [&str; 37] = [
        "preliminary_attempt_identity_generated",
        "preliminary_context_returned",
        "preliminary_first_failure_group_classified",
        "preliminary_replay_snapshot_opened",
        "preliminary_replay_snapshot_classified",
        "preliminary_preflight_snapshot_opened",
        "preliminary_operation_identity_classified",
        "preliminary_budget_binding_classified",
        "preliminary_budget_arithmetic_classified",
        "preliminary_budget_capacity_classified",
        "final_comparison_guard_acquired",
        "final_comparison_context_returned",
        "final_comparison_first_failure_group_classified",
        "final_comparison_replay_snapshot_opened",
        "final_comparison_replay_snapshot_classified",
        "final_comparison_preflight_snapshot_opened",
        "final_comparison_operation_identity_classified",
        "final_comparison_budget_binding_classified",
        "final_comparison_budget_arithmetic_classified",
        "final_comparison_budget_capacity_classified",
        "final_comparison_recovery_receipt_reopened",
        "final_comparison_recovery_receipt_revalidated",
        "final_comparison_utc_sample_returned",
        "final_comparison_monotonic_sample_returned",
        "positive_coordinator_commit_enter_commit_permit_returned",
        "positive_coordinator_commit_permit_moved_to_commit_in_flight",
        "positive_coordinator_commit_permit_resolved_committed",
        "positive_coordinator_commit_permit_resolved_aborted",
        "positive_coordinator_commit_permit_resolved_ambiguous",
        "acknowledgement_post_commit_time_classified",
        "acknowledgement_post_commit_guards_classified",
        "acknowledgement_positive_marker_constructed",
        "acknowledgement_result_returned",
        "acknowledgement_all_final_guards_released",
        "known_failure_no_dispatch_guard_acquired",
        "known_failure_no_dispatch_guard_finally_revalidated",
        "known_failure_no_dispatch_guard_released",
    ];

    const EXPECTED_COORDINATOR_BOUNDARY_IDS_V1: [&str; 86] = [
        "recovery_publication_guard_acquired",
        "recovery_staging_created",
        "recovery_staging_written",
        "recovery_staging_synchronized",
        "recovery_staging_closed",
        "recovery_staging_reopened",
        "recovery_material_digest_length_capacity_verified",
        "recovery_material_published",
        "recovery_manifest_staged",
        "recovery_manifest_synchronized",
        "recovery_manifest_published",
        "recovery_manifest_reopened",
        "recovery_receipt_returned",
        "positive_coordinator_commit_coordinator_root_accepted",
        "positive_coordinator_commit_coordinator_profile_accepted",
        "positive_coordinator_commit_coordinator_invariants_accepted",
        "positive_coordinator_commit_begin_immediate_acquired",
        "positive_coordinator_commit_operation_attempt_identity_classified",
        "positive_coordinator_commit_budget_scope_loaded",
        "positive_coordinator_commit_final_arithmetic_capacity_classified",
        "positive_coordinator_commit_member_staged",
        "positive_coordinator_commit_sqlite_commit_invoked",
        "positive_coordinator_commit_sqlite_commit_returned_with_trusted_classification",
        "acknowledgement_uncertain_connection_closed",
        "acknowledgement_readback_snapshot_opened",
        "acknowledgement_readback_classified_this_attempt",
        "acknowledgement_readback_classified_prior_exact_attempt",
        "acknowledgement_readback_classified_conflict",
        "acknowledgement_readback_classified_definite_absence",
        "acknowledgement_readback_classified_ambiguous",
        "known_failure_begin_immediate_acquired",
        "known_failure_operation_failed_staged",
        "known_failure_transition_staged",
        "known_failure_scope_held_subtraction_staged",
        "known_failure_reservation_released_staged",
        "known_failure_event_staged",
        "known_failure_metadata_staged",
        "known_failure_commit_returned",
        "known_failure_commit_classified",
        "quarantine_and_retirement_quarantine_inserted",
        "quarantine_and_retirement_quarantine_resolved",
        "quarantine_and_retirement_operation_bound_retirement_pending_committed",
        "quarantine_and_retirement_true_orphan_definitive_proof_returned",
        "quarantine_and_retirement_orphan_resolution_retirement_pending_tombstone_committed",
        "quarantine_and_retirement_provider_retirement_invoked",
        "quarantine_and_retirement_provider_bytes_retired",
        "quarantine_and_retirement_retirement_manifest_published",
        "quarantine_and_retirement_operation_bound_retired_tombstone_committed",
        "quarantine_and_retirement_orphan_retired_tombstone_committed",
        "backup_pause_persisted",
        "backup_provider_maintenance_guard_acquired",
        "backup_coordinator_maintenance_guard_acquired",
        "backup_source_profiles_verified",
        "backup_source_invariants_verified",
        "backup_source_generations_captured",
        "backup_sqlite_online_backup_completed",
        "backup_sqlite_online_backup_closed",
        "backup_sqlite_online_backup_integrity_checked",
        "backup_sqlite_online_backup_hashed",
        "backup_provider_enumeration_reconciled",
        "backup_material_present_package_exported",
        "backup_retirement_tombstone_exported",
        "backup_inventory_jcs_finalized",
        "backup_source_generations_rechecked",
        "backup_top_level_manifest_staged",
        "backup_top_level_manifest_published",
        "backup_attestation_protected_jcs_finalized",
        "backup_attestation_signed",
        "backup_attestation_staged",
        "backup_attestation_published",
        "backup_attestation_reopened",
        "backup_attestation_verified",
        "restore_package_and_pinned_provenance_accepted",
        "restore_empty_coordinator_root_reserved",
        "restore_empty_recovery_root_reserved",
        "restore_coordinator_database_imported",
        "restore_wal_full_profile_established",
        "restore_recovery_package_imported",
        "restore_coordinator_restore_pending_committed",
        "restore_coordinator_pending_root_marker_published",
        "restore_recovery_restore_pending_metadata_published",
        "restore_both_roots_closed",
        "restore_both_roots_reopened",
        "restore_both_roots_agreement_classified",
        "restore_verified_preparation_restore_returned",
        "restore_quarantine_persisted",
    ];

    fn production_source(source: &'static str) -> &'static str {
        source
            .split_once("#[cfg(test)]")
            .expect("test module marker remains present")
            .0
    }

    fn occurrences(source: &str, needle: &str) -> usize {
        source.match_indices(needle).count()
    }

    fn source_region<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        let (_, remainder) = source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing source-region start {start}"));
        let (region, _) = remainder
            .split_once(end)
            .unwrap_or_else(|| panic!("missing source-region end {end}"));
        region
    }

    fn assert_strictly_ordered(source: &str, needles: &[&str]) {
        let mut remainder = source;
        for needle in needles {
            let position = remainder
                .find(needle)
                .unwrap_or_else(|| panic!("missing ordered boundary evidence {needle}"));
            remainder = &remainder[position + needle.len()..];
        }
    }

    fn assert_feature_guarded_callsite(source_name: &str, source: &str, variant: &str) {
        let needle = format!("FaultBoundaryV1::{variant}");
        let position = source
            .find(&needle)
            .unwrap_or_else(|| panic!("missing {variant} call site in {source_name}"));
        let prefix = &source[..position];
        let function_start = prefix
            .rfind("\nfn ")
            .unwrap_or_else(|| panic!("{variant} is not inside a private hook function"));
        let feature_gate = prefix
            .rfind("#[cfg(feature = \"test-fault-injection\")]")
            .unwrap_or_else(|| panic!("{variant} has no non-default feature gate"));
        assert!(
            feature_gate > function_start,
            "{variant} is not gated inside its hook function in {source_name}"
        );
    }

    fn taxonomy_variant_names(source: &str) -> Vec<String> {
        source
            .lines()
            .filter_map(|line| {
                let (variant, _) = line.trim().split_once(" => \"")?;
                (!variant.is_empty()
                    && variant
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
                .then(|| variant.to_owned())
            })
            .collect()
    }

    fn source_owns_hook(source: &str, variant: &str) -> bool {
        source.contains(&format!("FaultBoundaryV1::{variant}"))
            || source.contains(&format!("reach!({variant})"))
            || source.contains(&format!("reach!(fault_probe, {variant})"))
    }

    fn assert_owned_hook_is_feature_gated(source_name: &str, source: &str, variant: &str) {
        let macro_calls = [
            format!("reach!({variant})"),
            format!("reach!(fault_probe, {variant})"),
        ];
        if macro_calls.iter().any(|call| source.contains(call)) {
            let macro_start = source
                .find("macro_rules! reach")
                .unwrap_or_else(|| panic!("{variant} in {source_name} has no private reach macro"));
            let macro_remainder = &source[macro_start..];
            let macro_end = macro_remainder
                .find("\n}\n")
                .map_or(source.len(), |offset| macro_start + offset + 3);
            let macro_prefix = &source[macro_start..macro_end];
            assert!(
                macro_prefix.contains("#[cfg(feature = \"test-fault-injection\")]"),
                "{variant} in {source_name} has an ungated reach macro"
            );
        }

        let direct = format!("FaultBoundaryV1::{variant}");
        for (position, _) in source.match_indices(&direct) {
            let window_start = position.saturating_sub(1_024);
            assert!(
                source[window_start..position]
                    .contains("#[cfg(feature = \"test-fault-injection\")]"),
                "{variant} in {source_name} is not locally feature-gated"
            );
        }
    }

    #[test]
    fn coordinator_taxonomy_is_exact_unique_and_disabled_by_default() {
        let actual = FaultBoundaryV1::ALL
            .iter()
            .map(|boundary| boundary.id())
            .collect::<Vec<_>>();
        assert_eq!(actual, EXPECTED_COORDINATOR_BOUNDARY_IDS_V1);
        assert_eq!(
            COORDINATOR_BOUNDARY_IDS_V1,
            EXPECTED_COORDINATOR_BOUNDARY_IDS_V1
        );
        assert_eq!(
            COORDINATOR_BOUNDARY_IDS_V1.len(),
            FaultBoundaryV1::ALL.len()
        );
        assert_eq!(
            actual.iter().copied().collect::<BTreeSet<_>>().len(),
            actual.len()
        );
        for boundary in FaultBoundaryV1::ALL {
            reach(*boundary);
        }
    }

    #[test]
    fn disabled_session_never_injects_any_closed_boundary() {
        let mut session = FaultSessionV1::disabled_v1();
        for boundary in FaultBoundaryV1::ALL {
            assert_eq!(session.checkpoint_v1(*boundary), FaultDecisionV1::Continue);
        }
        assert_eq!(
            format!("{session:?}"),
            "FaultSessionV1 { enabled: false, injected: false, .. }"
        );
    }

    #[test]
    fn selected_session_injects_only_the_exact_matching_occurrence_once() {
        let selected = FaultSelectionV1::try_new(
            FaultBoundaryV1::KnownFailureEventStaged,
            2,
            FaultEffectV1::ProcessBarrier,
        )
        .expect("nonzero occurrence selects");
        let mut session = FaultSessionV1::selected_v1(selected);

        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::KnownFailureMetadataStaged),
            FaultDecisionV1::Continue,
            "unrelated boundaries do not consume the selected occurrence"
        );
        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::KnownFailureEventStaged),
            FaultDecisionV1::Continue
        );
        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::KnownFailureEventStaged),
            FaultDecisionV1::Inject(FaultEffectV1::ProcessBarrier)
        );
        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::KnownFailureEventStaged),
            FaultDecisionV1::Continue,
            "one selection injects at most once"
        );
        assert_eq!(
            format!("{session:?}"),
            "FaultSessionV1 { enabled: true, injected: true, .. }"
        );
    }

    #[test]
    fn selection_rejects_zero_and_debug_exposes_only_frozen_metadata() {
        assert_eq!(
            FaultSelectionV1::try_new(
                FaultBoundaryV1::KnownFailureCommitReturned,
                0,
                FaultEffectV1::ReturnError,
            ),
            Err(FaultSelectionErrorV1::InvalidOccurrence)
        );
        assert_eq!(
            format!("{:?}", FaultSelectionErrorV1::InvalidOccurrence),
            "INVALID_FAULT_OCCURRENCE"
        );

        let selection = FaultSelectionV1::try_new(
            FaultBoundaryV1::KnownFailureCommitReturned,
            3,
            FaultEffectV1::ReturnError,
        )
        .expect("nonzero occurrence selects");
        assert_eq!(
            format!("{selection:?}"),
            "FaultSelectionV1 { boundary: \"known_failure_commit_returned\", occurrence: 3, effect: RETURN_ERROR }"
        );
    }

    #[test]
    fn two_private_modules_form_the_exact_frozen_partition() {
        let portable_source = production_source(include_str!(
            "../../helix-plan-preparation/src/test_fault.rs"
        ));
        let coordinator_source = production_source(include_str!("test_fault.rs"));
        let all_ids = EXPECTED_PORTABLE_BOUNDARY_IDS_V1
            .iter()
            .chain(EXPECTED_COORDINATOR_BOUNDARY_IDS_V1.iter())
            .copied()
            .collect::<Vec<_>>();

        assert_eq!(all_ids.len(), 123);
        assert_eq!(CLOSED_FAULT_BOUNDARY_COUNT_V1, all_ids.len());
        assert!(portable_source.contains("const CLOSED_FAULT_BOUNDARY_COUNT_V1: usize = 123;"));
        assert_eq!(
            all_ids.iter().copied().collect::<BTreeSet<_>>().len(),
            all_ids.len()
        );
        for id in EXPECTED_PORTABLE_BOUNDARY_IDS_V1 {
            assert_eq!(occurrences(portable_source, id), 1, "portable ID {id}");
            assert_eq!(occurrences(coordinator_source, id), 0, "portable ID {id}");
        }
        for id in EXPECTED_COORDINATOR_BOUNDARY_IDS_V1 {
            assert_eq!(
                occurrences(coordinator_source, id),
                1,
                "coordinator ID {id}"
            );
            assert_eq!(occurrences(portable_source, id), 0, "coordinator ID {id}");
        }
    }

    #[test]
    fn coordinator_fault_plumbing_is_private_feature_only_and_non_ambient() {
        let lib = include_str!("lib.rs").replace("\r\n", "\n");
        let manifest = include_str!("../Cargo.toml");
        let source = production_source(include_str!("test_fault.rs"));

        assert!(lib.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
        assert!(!lib.contains("pub mod test_fault"));
        assert!(manifest.contains("default = []"));
        assert!(manifest.contains("test-fault-injection = ["));
        assert!(manifest.contains("\"helix-plan-preparation/test-fault-injection\""));
        assert!(source.contains("struct FaultSelectionV1"));
        assert!(source.contains("struct FaultSessionV1"));
        assert!(source.contains("struct FaultProbeV1"));
        assert!(source.contains("std::sync::Arc<std::sync::Mutex<FaultProbeStateV1>>"));
        assert!(source.contains("fn checkpoint_v1"));
        for forbidden in [
            "std::env",
            "thread_local!",
            "static mut",
            "OnceLock",
            "Atomic",
            "std::rc::Rc",
            "std::cell::RefCell",
            "option_env!",
            "env!",
            "pub enum FaultBoundaryV1",
            "pub fn reach",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden selector: {forbidden}"
            );
        }
    }

    #[test]
    fn transactional_probe_is_cloneable_send_sync_and_runs_callback_outside_lock() {
        fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
        assert_clone_send_sync::<FaultProbeV1>();

        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<FaultProbeV1>));
        let slot_for_callback = std::sync::Arc::clone(&slot);
        let callback_observed_injected =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_observed_injected_clone = std::sync::Arc::clone(&callback_observed_injected);
        let selection = FaultSelectionV1::try_new(
            FaultBoundaryV1::KnownFailureCommitReturned,
            1,
            FaultEffectV1::ProcessBarrier,
        )
        .expect("one selected occurrence is valid");
        let probe = FaultProbeV1::selected_process_barrier_v1(
            selection,
            Box::new(move || {
                let observation = slot_for_callback
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref()
                    .expect("observation clone is installed")
                    .clone();
                callback_observed_injected_clone.store(
                    observation.injected_v1(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }),
        );
        *slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(probe.clone());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            probe.reach_v1(FaultBoundaryV1::KnownFailureCommitReturned);
        }));
        assert!(result.is_err(), "a returning process barrier fails closed");
        assert!(callback_observed_injected.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn transactional_store_partition_is_exact() {
        let transactional = FaultBoundaryV1::ALL
            .iter()
            .copied()
            .filter(|boundary| boundary.is_transactional_coordinator_v1())
            .collect::<Vec<_>>();
        assert_eq!(transactional.len(), 26);
        assert!(transactional.iter().all(|boundary| {
            let id = boundary.id();
            id.starts_with("positive_coordinator_commit_")
                || id.starts_with("acknowledgement_")
                || id.starts_with("known_failure_")
        }));
    }

    #[test]
    fn one_store_owned_probe_reaches_all_three_transactional_phases() {
        let lib = include_str!("lib.rs");
        assert!(lib.contains("fault_probe: CoordinatorFaultProbeV1"));
        assert!(lib.contains("fault_probe: CoordinatorFaultProbeV1::disabled_v1()"));
        assert!(lib.contains("&self.fault_probe,\n            || self.clock"));
        assert!(
            lib.contains("record_uncertain_connection_closed_with_probe_v1(&self.fault_probe);")
        );
        assert!(lib.contains(
            "readback_with_fault_probe_v1(\n            bound.connection_mut(),\n            &coordinator_input,\n            &self.fault_probe,"
        ));
        assert!(lib.contains(
            "fail_before_dispatch_transaction_with_probe_v1(\n            bound.connection_mut(),\n            input,\n            no_dispatch_guard,\n            &self.fault_probe,"
        ));

        for source in [
            include_str!("prepare.rs"),
            include_str!("readback.rs"),
            include_str!("failure.rs"),
        ] {
            assert!(source.contains("CoordinatorFaultProbeV1"));
            assert!(source.contains("reach_id_v1"));
        }
    }

    #[test]
    fn us3_recovery_quarantine_retirement_call_sites_are_exact_and_feature_gated() {
        let common = include_str!("../tests/common/mod.rs");
        // These modules deliberately contain source-included synthetic seams before
        // their hook helpers, so audit the complete files rather than truncating at
        // the first `cfg(test)` marker.
        let quarantine = include_str!("quarantine.rs");
        let retirement = include_str!("retirement.rs");
        let maintenance = include_str!("maintenance.rs");
        let sources = [
            ("tests/common/mod.rs", common),
            ("src/quarantine.rs", quarantine),
            ("src/retirement.rs", retirement),
            ("src/maintenance.rs", maintenance),
        ];
        let expected = [
            ("RecoveryPublicationGuardAcquired", "tests/common/mod.rs"),
            ("RecoveryStagingCreated", "tests/common/mod.rs"),
            ("RecoveryStagingWritten", "tests/common/mod.rs"),
            ("RecoveryStagingSynchronized", "tests/common/mod.rs"),
            ("RecoveryStagingClosed", "tests/common/mod.rs"),
            ("RecoveryStagingReopened", "tests/common/mod.rs"),
            (
                "RecoveryMaterialDigestLengthCapacityVerified",
                "tests/common/mod.rs",
            ),
            ("RecoveryMaterialPublished", "tests/common/mod.rs"),
            ("RecoveryManifestStaged", "tests/common/mod.rs"),
            ("RecoveryManifestSynchronized", "tests/common/mod.rs"),
            ("RecoveryManifestPublished", "tests/common/mod.rs"),
            ("RecoveryManifestReopened", "tests/common/mod.rs"),
            ("RecoveryReceiptReturned", "tests/common/mod.rs"),
            (
                "QuarantineAndRetirementQuarantineInserted",
                "src/quarantine.rs",
            ),
            (
                "QuarantineAndRetirementQuarantineResolved",
                "src/quarantine.rs",
            ),
            (
                "QuarantineAndRetirementTrueOrphanDefinitiveProofReturned",
                "src/quarantine.rs",
            ),
            (
                "QuarantineAndRetirementOrphanResolutionRetirementPendingTombstoneCommitted",
                "src/quarantine.rs",
            ),
            (
                "QuarantineAndRetirementOperationBoundRetirementPendingCommitted",
                "src/retirement.rs",
            ),
            (
                "QuarantineAndRetirementOperationBoundRetiredTombstoneCommitted",
                "src/retirement.rs",
            ),
            (
                "QuarantineAndRetirementOrphanRetiredTombstoneCommitted",
                "src/retirement.rs",
            ),
            (
                "QuarantineAndRetirementProviderRetirementInvoked",
                "tests/common/mod.rs",
            ),
            (
                "QuarantineAndRetirementProviderBytesRetired",
                "tests/common/mod.rs",
            ),
            (
                "QuarantineAndRetirementRetirementManifestPublished",
                "tests/common/mod.rs",
            ),
            ("BackupProviderEnumerationReconciled", "src/maintenance.rs"),
        ];

        for (variant, expected_source) in expected {
            let needle = format!("FaultBoundaryV1::{variant}");
            let total = sources
                .iter()
                .map(|(_, source)| occurrences(source, &needle))
                .sum::<usize>();
            assert_eq!(total, 1, "{variant} must have one exact US3 call site");
            let (_, source) = sources
                .iter()
                .find(|(name, _)| *name == expected_source)
                .expect("expected source is in the closed audit set");
            assert_eq!(
                occurrences(source, &needle),
                1,
                "{variant} belongs in {expected_source}"
            );
            assert_feature_guarded_callsite(expected_source, source, variant);
        }
    }

    #[test]
    fn t074_provider_staging_sub_boundaries_follow_the_exact_durable_actions() {
        let common = include_str!("../tests/common/mod.rs");
        let publish = source_region(
            common,
            "fn publish_package_v1(",
            "fn verify_package_files_v1(",
        );
        let hook_calls = [
            "reach_recovery_staging_created_v1(&self.fault_probe);",
            "reach_recovery_staging_written_v1(&self.fault_probe);",
            "reach_recovery_staging_synchronized_v1(&self.fault_probe);",
            "reach_recovery_staging_closed_v1(&self.fault_probe);",
            "reach_recovery_staging_reopened_v1(&self.fault_probe);",
            "reach_recovery_material_verified_v1(&self.fault_probe);",
            "reach_recovery_material_published_v1(&self.fault_probe);",
            "reach_recovery_manifest_staged_v1(&self.fault_probe);",
            "reach_recovery_manifest_synchronized_v1(&self.fault_probe);",
            "reach_recovery_manifest_published_v1(&self.fault_probe);",
            "reach_recovery_manifest_reopened_v1(&self.fault_probe);",
        ];
        for hook in hook_calls {
            assert_eq!(
                occurrences(publish, hook),
                1,
                "{hook} must own one provider publication call site"
            );
        }

        assert_strictly_ordered(
            publish,
            &[
                ".open(&material_staging)",
                "reach_recovery_staging_created_v1(&self.fault_probe);",
                ".write_all(material)",
                "reach_recovery_staging_written_v1(&self.fault_probe);",
                ".sync_all()",
                "reach_recovery_staging_synchronized_v1(&self.fault_probe);",
                "drop(material_file);",
                "reach_recovery_staging_closed_v1(&self.fault_probe);",
                "let reopened_material = read_exact_file_v1(&material_staging)?;",
                "reach_recovery_staging_reopened_v1(&self.fault_probe);",
                "if reopened_material != material",
                "reach_recovery_material_verified_v1(&self.fault_probe);",
                "publish_no_clobber_v1(&material_staging, &material_final)?;",
                "reach_recovery_material_published_v1(&self.fault_probe);",
                ".open(&manifest_staging)",
                "reach_recovery_manifest_staged_v1(&self.fault_probe);",
                ".write_all(manifest)",
                ".sync_all()",
                "reach_recovery_manifest_synchronized_v1(&self.fault_probe);",
                "drop(manifest_file);",
                "publish_no_clobber_v1(&manifest_staging, &manifest_final)?;",
                "reach_recovery_manifest_published_v1(&self.fault_probe);",
                "let reopened_manifest = read_exact_file_v1(&manifest_final)?;",
                "reach_recovery_manifest_reopened_v1(&self.fault_probe);",
                "if reopened_manifest != manifest",
            ],
        );
    }

    #[test]
    fn t074_backup_attestation_and_restore_root_hooks_have_one_callsite_each() {
        let maintenance = include_str!("maintenance.rs");
        let hook_helpers = [
            "reach_backup_pause_persisted_v1",
            "reach_backup_provider_maintenance_guard_acquired_v1",
            "reach_backup_coordinator_maintenance_guard_acquired_v1",
            "reach_backup_source_profiles_verified_v1",
            "reach_backup_source_invariants_verified_v1",
            "reach_backup_source_generations_captured_v1",
            "reach_backup_sqlite_online_backup_completed_v1",
            "reach_backup_sqlite_online_backup_closed_v1",
            "reach_backup_sqlite_online_backup_integrity_checked_v1",
            "reach_backup_sqlite_online_backup_hashed_v1",
            "reach_provider_enumeration_reconciled_v1",
            "reach_backup_material_present_package_exported_v1",
            "reach_backup_retirement_tombstone_exported_v1",
            "reach_backup_inventory_jcs_finalized_v1",
            "reach_backup_source_generations_rechecked_v1",
            "reach_backup_top_level_manifest_staged_v1",
            "reach_backup_top_level_manifest_published_v1",
            "reach_backup_attestation_protected_jcs_finalized_v1",
            "reach_backup_attestation_signed_v1",
            "reach_backup_attestation_staged_v1",
            "reach_backup_attestation_published_v1",
            "reach_backup_attestation_reopened_v1",
            "reach_backup_attestation_verified_v1",
            "reach_restore_package_and_pinned_provenance_accepted_v1",
            "reach_restore_empty_coordinator_root_reserved_v1",
            "reach_restore_empty_recovery_root_reserved_v1",
            "reach_restore_coordinator_database_imported_v1",
            "reach_restore_wal_full_profile_established_v1",
            "reach_restore_recovery_package_imported_v1",
            "reach_restore_coordinator_restore_pending_committed_v1",
            "reach_restore_coordinator_pending_root_marker_published_v1",
            "reach_restore_recovery_restore_pending_metadata_published_v1",
            "reach_restore_both_roots_closed_v1",
            "reach_restore_both_roots_reopened_v1",
            "reach_restore_both_roots_agreement_classified_v1",
            "reach_restore_verified_preparation_restore_returned_v1",
            "reach_restore_quarantine_persisted_v1",
        ];
        for helper in hook_helpers {
            assert_eq!(
                occurrences(maintenance, helper),
                2,
                "{helper} must have exactly one definition and one semantic call site"
            );
        }
    }

    #[test]
    fn t074_attestation_and_independent_pending_root_actions_are_ordered() {
        let maintenance = include_str!("maintenance.rs");
        let backup = source_region(
            maintenance,
            "fn complete_quiescent_backup_under_cut_v1<",
            "pub(crate) struct CoordinatorBackupGenerationsV1",
        );
        assert_strictly_ordered(
            backup,
            &[
                "let inventory = codec.finalize_inventory_v1",
                "reach_backup_inventory_jcs_finalized_v1(&mut cut.fault_probe);",
                "stage_canonical_member_v1(BackupJsonMemberV1::TopLevelManifest",
                "reach_backup_top_level_manifest_staged_v1(&mut cut.fault_probe);",
                "publish_staged_member_v1(BackupJsonMemberV1::TopLevelManifest,",
                "let protected = codec.finalize_protected_v1",
                "reach_backup_attestation_protected_jcs_finalized_v1(&mut cut.fault_probe);",
                ".sign_backup_attestation_v1(&signing_message)",
                "reach_backup_attestation_signed_v1(&mut cut.fault_probe);",
                "let attestation = codec.finalize_attestation_v1",
                "stage_canonical_member_v1(BackupJsonMemberV1::Attestation",
                "reach_backup_attestation_staged_v1(&mut cut.fault_probe);",
                "publish_staged_member_v1(BackupJsonMemberV1::Attestation,",
                "reopen_published_member_v1(BackupJsonMemberV1::Attestation)",
                "reach_backup_attestation_reopened_v1(&mut cut.fault_probe);",
                "codec.verify_reopened_package_v1",
                "reach_backup_attestation_verified_v1(&mut cut.fault_probe);",
            ],
        );

        let publication = source_region(
            maintenance,
            "fn publish_staged_member_with_cleanup_v1<",
            "fn reopen_published_member_v1(",
        );
        let hard_link = publication
            .find("fs::hard_link(&staged, &published)")
            .expect("create-only hard-link publication remains explicit");
        for hook in [
            "reach_backup_top_level_manifest_published_v1(fault_probe);",
            "reach_backup_attestation_published_v1(fault_probe);",
        ] {
            let hook_position = publication
                .find(hook)
                .unwrap_or_else(|| panic!("missing independent publication hook {hook}"));
            assert!(
                hook_position > hard_link,
                "{hook} must follow the create-only publication point"
            );
        }

        let restore = source_region(
            maintenance,
            "pub(crate) fn restore_preparation_to_pending_v1<",
            "pub(crate) fn quarantine_existing_restore_attempt_v1<",
        );
        assert_strictly_ordered(
            restore,
            &[
                "begin_empty_restore_root_custody_v1(",
                "reach_restore_empty_coordinator_root_reserved_v1(&mut accepted.fault_probe);",
                ".begin_or_resume_restore_root_v1(&reservation",
                "reach_restore_empty_recovery_root_reserved_v1(&mut accepted.fault_probe);",
                ".import_recovery_backup_package_v1(",
                "source.finish_v1()?;",
                "reach_restore_recovery_package_imported_v1(&mut accepted.fault_probe);",
                "transition_imported_backup_to_restore_pending_v1(",
                "reach_restore_coordinator_restore_pending_committed_v1(&mut accepted.fault_probe);",
                ".finalize_restore_pending_publication_v1(",
                "reach_restore_coordinator_pending_root_marker_published_v1(&mut accepted.fault_probe);",
                ".publish_restore_pending_metadata_v1(recovery_metadata.bytes())",
                "reach_restore_recovery_restore_pending_metadata_published_v1(&mut accepted.fault_probe);",
                "drop(coordinator_pending_custody.take());",
                "reach_restore_both_roots_closed_v1(&mut accepted.fault_probe);",
                "reopen_restore_pending_root_custody_v1(",
                ".reopen_restore_pending_root_v1(&recovery_expected",
                "reach_restore_both_roots_reopened_v1(&mut accepted.fault_probe);",
                "reach_restore_both_roots_agreement_classified_v1(&mut accepted.fault_probe);",
                "let verified = VerifiedPreparationRestoreV1",
                "reach_restore_verified_preparation_restore_returned_v1(&mut accepted.fault_probe);",
            ],
        );
    }

    #[test]
    fn all_123_hook_ids_have_one_feature_gated_owner_source() {
        let portable_taxonomy = production_source(include_str!(
            "../../helix-plan-preparation/src/test_fault.rs"
        ));
        let coordinator_taxonomy = production_source(include_str!("test_fault.rs"));
        let portable_variants = taxonomy_variant_names(portable_taxonomy);
        let coordinator_variants = taxonomy_variant_names(coordinator_taxonomy);
        assert_eq!(portable_variants.len(), 37);
        assert_eq!(coordinator_variants.len(), 86);

        let portable_sources = [
            (
                "helix-plan-preparation/src/attempt.rs",
                include_str!("../../helix-plan-preparation/src/attempt.rs"),
            ),
            (
                "helix-plan-preparation/src/context.rs",
                include_str!("../../helix-plan-preparation/src/context.rs"),
            ),
            (
                "helix-plan-preparation/src/guard.rs",
                include_str!("../../helix-plan-preparation/src/guard.rs"),
            ),
            (
                "helix-plan-preparation/src/commit_gate.rs",
                include_str!("../../helix-plan-preparation/src/commit_gate.rs"),
            ),
            (
                "helix-plan-preparation/src/compare.rs",
                include_str!("../../helix-plan-preparation/src/compare.rs"),
            ),
            (
                "helix-plan-preparation/src/budget.rs",
                include_str!("../../helix-plan-preparation/src/budget.rs"),
            ),
            (
                "helix-plan-preparation/src/recovery.rs",
                include_str!("../../helix-plan-preparation/src/recovery.rs"),
            ),
            (
                "helix-plan-preparation/src/store.rs",
                include_str!("../../helix-plan-preparation/src/store.rs"),
            ),
            (
                "helix-plan-preparation/src/outcome.rs",
                include_str!("../../helix-plan-preparation/src/outcome.rs"),
            ),
            (
                "helix-plan-preparation/src/coordinator.rs",
                include_str!("../../helix-plan-preparation/src/coordinator.rs"),
            ),
            (
                "helix-plan-preparation/src/lib.rs",
                include_str!("../../helix-plan-preparation/src/lib.rs"),
            ),
        ];
        let coordinator_sources = [
            ("src/budget.rs", include_str!("budget.rs")),
            ("src/clock.rs", include_str!("clock.rs")),
            (
                "src/comparison_digest.rs",
                include_str!("comparison_digest.rs"),
            ),
            ("src/config.rs", include_str!("config.rs")),
            ("src/connection.rs", include_str!("connection.rs")),
            ("src/error.rs", include_str!("error.rs")),
            ("src/failure.rs", include_str!("failure.rs")),
            ("src/lib.rs", include_str!("lib.rs")),
            ("src/maintenance.rs", include_str!("maintenance.rs")),
            ("src/manifest.rs", include_str!("manifest.rs")),
            ("src/outbox.rs", include_str!("outbox.rs")),
            ("src/preflight.rs", include_str!("preflight.rs")),
            ("src/prepare.rs", include_str!("prepare.rs")),
            ("src/quarantine.rs", include_str!("quarantine.rs")),
            ("src/readback.rs", include_str!("readback.rs")),
            ("src/retirement.rs", include_str!("retirement.rs")),
            ("src/root_safety.rs", include_str!("root_safety.rs")),
            ("src/schema.rs", include_str!("schema.rs")),
            ("src/transition.rs", include_str!("transition.rs")),
            (
                "tests/common/mod.rs",
                include_str!("../tests/common/mod.rs"),
            ),
        ];

        let mut ownership_red = Vec::new();
        for (owner, variants, sources) in [
            ("portable", portable_variants, portable_sources.as_slice()),
            (
                "coordinator",
                coordinator_variants,
                coordinator_sources.as_slice(),
            ),
        ] {
            for variant in variants {
                let owners = sources
                    .iter()
                    .filter(|(_, source)| source_owns_hook(source, &variant))
                    .collect::<Vec<_>>();
                if owners.len() != 1 {
                    ownership_red.push(format!("{owner}:{variant}:owners={}", owners.len()));
                    continue;
                }
                let (source_name, source) = owners[0];
                assert_owned_hook_is_feature_gated(source_name, source, &variant);
            }
        }
        assert!(
            ownership_red.is_empty(),
            "T074 hook ownership RED: {}",
            ownership_red.join(",")
        );
    }
}
