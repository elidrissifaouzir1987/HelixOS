//! Private backup, restore, and maintenance boundary.

#![allow(dead_code)] // T058 is consumed by the guarded T069-T071 backup path.

#[cfg(not(test))]
use crate::clock::{remaining_monotonic_ms, CoordinatorMonotonicClockV1};
#[cfg(not(test))]
use crate::connection::{
    configure_deadline_bounded_busy_timeout_v1, BoundCoordinatorBackupCustodyV1,
    BoundCoordinatorBackupPairV1,
};
#[cfg(not(test))]
use crate::error::InternalCoordinatorError;
#[cfg(not(test))]
use crate::failure::{
    fail_restored_old_authority_transaction_v1, RestoredAuthorityRotationV1,
    RestoredNoDispatchAuthorityGuardV1, RestoredOldAuthorityBindingV1,
    RestoredOldAuthorityFailureInputV1, RestoredOldAuthorityFailureOutcomeV1,
};
#[cfg(all(feature = "test-fault-injection", not(test)))]
use crate::manifest::ProvisionerTrustViewV1;
#[cfg(not(test))]
use crate::manifest::{
    finalize_recovery_root_metadata_v1, verify_recovery_root_pending_bindings_v1,
    verify_restore_package_manifests_v1, ProvisionerTrustCustodyOutcomeV1,
    ProvisionerTrustCustodyV1, ProvisionerTrustResolverV1, RecoveryCustodyV1,
    RecoveryRootMetadataInputV1, RecoverySnapshotStateV1, VerifiedRestorePackageBindingsV1,
};
#[cfg(not(test))]
use crate::quarantine::{
    retain_base_quarantine_in_transaction_v1, retain_restored_old_authority_quarantine_v1,
    BaseQuarantineErrorV1, BaseQuarantineInputV1, BaseQuarantineReasonV1,
    RestoredOldAuthorityGuardFailureV1, RestoredOldAuthorityQuarantineInputV1,
    RestoredOldAuthorityQuarantineOutcomeV1,
};
#[cfg(all(feature = "test-fault-injection", not(test)))]
use crate::root_safety::COORDINATOR_DATABASE_FILENAME;
#[cfg(not(test))]
use crate::root_safety::{
    begin_empty_restore_root_custody_v1, capture_immutable_members_v1,
    inspect_existing_restore_root_custody_v1, reopen_restore_pending_root_custody_v1,
    CoordinatorPendingRootCustodyV1, CoordinatorRestoreRootCustodyV1, CoordinatorRootIdentityV1,
    ProvisionedEmptyCoordinatorRootV1, ProvisionedRestorePackageV1, RestorePackageCustodyV1,
};
#[cfg(not(test))]
use crate::root_safety::{
    MAX_RESTORE_PACKAGE_DIRECTORIES_V1, MAX_RESTORE_PACKAGE_FILES_V1,
    MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1, MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1,
};
#[cfg(not(test))]
use crate::schema;
#[cfg(not(test))]
use helix_contracts::Ed25519KeyResolver;
use helix_contracts::{Identifier, Sha256Digest, MAX_SAFE_U64};
use helix_plan_preparation::{RecoveryCleanupGuardV1, RecoveryEvidenceClassV1};
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, Error as SqliteError, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(feature = "test-fault-injection")]
type MaintenanceFaultProbeV1 = crate::test_fault::FaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
#[derive(Clone, Default)]
struct MaintenanceFaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
impl MaintenanceFaultProbeV1 {
    const fn disabled_v1() -> Self {
        Self
    }

    #[inline]
    fn reach_v1(&mut self) {}
}

const RECOVERY_PROVIDER_PROFILE_VERSION_V1: u16 = 1;
const BACKUP_ATTESTATION_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-BACKUP-ATTESTATION\0V1\0";
const BACKUP_EXTRA_ATTEMPT_DOMAIN_V1: &[u8] = b"HELIXOS\0RECOVERY-BACKUP-EXTRA-ATTEMPT\0V1\0";
const BACKUP_EXTRA_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0RECOVERY-BACKUP-EXTRA-BINDING\0V1\0";
const RECOVERY_PACKAGE_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0RECOVERY-BACKUP-PACKAGE-BINDING\0V1\0";
const BACKUP_PAGES_PER_STEP_V1: i32 = 64;
const MAX_BACKUP_STEPS_V1: usize = 1_000_000;
const MAX_BACKUP_BUSY_OR_LOCKED_STEPS_V1: usize = 64;
// The backup package always has staging, published and recovery-packages directories. Its
// worst-case file set includes the coordinator database, three published canonical members and
// their three staging hard links when best-effort staging cleanup is refused.
const BACKUP_PACKAGE_FIXED_DIRECTORIES_V1: usize = 3;
const BACKUP_PACKAGE_FIXED_WORST_CASE_FILES_V1: usize = 7;
const BACKUP_PACKAGE_CANONICAL_MEMBERS_V1: u64 = 3;
const BACKUP_PACKAGE_CANONICAL_MEMBER_PATHS_V1: u64 = 2;
const BACKUP_PACKAGE_MINIMUM_NONEMPTY_MEMBER_BYTES_V1: u64 = 1;
// maintenance.rs is source-included by downstream synthetic test harnesses that intentionally do
// not import the coordinator's root_safety module. Keep these test-only mirrors pinned by the
// exact cap/cap+1 producer tests below; production always imports the authoritative constants.
#[cfg(test)]
const MAX_RESTORE_PACKAGE_DIRECTORIES_V1: usize = 132;
#[cfg(test)]
const MAX_RESTORE_PACKAGE_FILES_V1: usize = 256;
#[cfg(test)]
const MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1: u64 = 64 * 1024 * 1024;
#[cfg(test)]
const MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1: u64 = 256 * 1024 * 1024;
#[cfg(not(test))]
const RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1: u64 = 4 * 1024 * 1024;
#[cfg(not(test))]
const RESTORE_COORDINATOR_MEMBER_V1: &str = "coordinator.sqlite3";
#[cfg(not(test))]
const RESTORE_INVENTORY_MEMBER_V1: &str = "published/recovery-inventory.json";
#[cfg(not(test))]
const RESTORE_TOP_LEVEL_MEMBER_V1: &str = "published/preparation-backup.json";
#[cfg(not(test))]
const RESTORE_ATTESTATION_MEMBER_V1: &str = "published/provenance-attestation.json";
#[cfg(not(test))]
const RESTORE_ATTEMPT_BINDING_DOMAIN_V1: &[u8] =
    b"HELIXOS\0PREPARATION-RESTORE-ATTEMPT-BINDING\0V1\0";
#[cfg(not(test))]
const RESTORE_IDENTITY_DOMAIN_V1: &[u8] = b"HELIXOS\0RESTORE-IDENTITY\0V1\0";

/// Closed validation returned by live PAUSE/provider maintenance custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceCustodyValidationV1 {
    Exact,
    Revoked,
    Unavailable,
    Unhealthy,
}

/// Opaque supervisor state captured when PAUSE becomes durable.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PausedBackupSourceV1 {
    supervisor_generation: u64,
    boot_identity_sha256: Sha256Digest,
    instance_epoch: u64,
    fencing_epoch: u64,
}

impl PausedBackupSourceV1 {
    pub(crate) fn try_new(
        supervisor_generation: u64,
        boot_identity_sha256: Sha256Digest,
        instance_epoch: u64,
        fencing_epoch: u64,
    ) -> Result<Self, QuiescentBackupErrorV1> {
        if !(1..=MAX_SAFE_U64).contains(&supervisor_generation)
            || !(1..=MAX_SAFE_U64).contains(&instance_epoch)
            || !(1..=MAX_SAFE_U64).contains(&fencing_epoch)
        {
            return Err(QuiescentBackupErrorV1::PauseUnhealthy);
        }
        Ok(Self {
            supervisor_generation,
            boot_identity_sha256,
            instance_epoch,
            fencing_epoch,
        })
    }
}

impl fmt::Debug for PausedBackupSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PausedBackupSourceV1")
            .finish_non_exhaustive()
    }
}

/// Linear supervisor custody proving PAUSE remains the exact captured state.
pub(crate) trait PausedBackupCustodyV1: Send {
    fn capture_paused_source_v1(
        &mut self,
    ) -> Result<PausedBackupSourceV1, MaintenanceCustodyValidationV1>;

    fn recheck_paused_source_v1(
        &mut self,
        expected: &PausedBackupSourceV1,
    ) -> MaintenanceCustodyValidationV1;

    fn release(self);
}

pub(crate) enum PausedBackupCustodyOutcomeV1<G> {
    Acquired(G),
    Contended,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

impl<G> fmt::Debug for PausedBackupCustodyOutcomeV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquired(_) => "PausedBackupCustodyOutcomeV1::Acquired(..)",
            Self::Contended => "PausedBackupCustodyOutcomeV1::Contended",
            Self::Unavailable => "PausedBackupCustodyOutcomeV1::Unavailable",
            Self::DeadlineReached => "PausedBackupCustodyOutcomeV1::DeadlineReached",
            Self::Unsupported => "PausedBackupCustodyOutcomeV1::Unsupported",
        })
    }
}

/// Sovereign control-lane boundary that persists PAUSE before either maintenance guard.
pub(crate) trait BackupPauseAuthorityV1: Send + Sync {
    type Custody: PausedBackupCustodyV1;

    fn persist_pause_for_backup_v1(
        &self,
        deadline_monotonic_ms: u64,
    ) -> PausedBackupCustodyOutcomeV1<Self::Custody>;
}

/// Opaque recovery-domain identity/profile/generation snapshot under provider custody.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecoveryMaintenanceSourceV1 {
    recovery_root_identity_sha256: Sha256Digest,
    instance_identity_sha256: Sha256Digest,
    provider_maintenance_generation: u64,
    profile_generation: u64,
    operation_retirement_pending: u64,
    orphan_retirement_pending: u64,
}

impl RecoveryMaintenanceSourceV1 {
    pub(crate) fn try_new(
        recovery_root_identity_sha256: Sha256Digest,
        instance_identity_sha256: Sha256Digest,
        provider_maintenance_generation: u64,
        profile_generation: u64,
    ) -> Result<Self, QuiescentBackupErrorV1> {
        Self::try_new_with_pending_counts(
            recovery_root_identity_sha256,
            instance_identity_sha256,
            provider_maintenance_generation,
            profile_generation,
            0,
            0,
        )
    }

    pub(crate) fn try_new_with_pending_counts(
        recovery_root_identity_sha256: Sha256Digest,
        instance_identity_sha256: Sha256Digest,
        provider_maintenance_generation: u64,
        profile_generation: u64,
        operation_retirement_pending: u64,
        orphan_retirement_pending: u64,
    ) -> Result<Self, QuiescentBackupErrorV1> {
        if !(1..=MAX_SAFE_U64).contains(&provider_maintenance_generation)
            || !(1..=MAX_SAFE_U64).contains(&profile_generation)
            || operation_retirement_pending > MAX_SAFE_U64
            || orphan_retirement_pending > MAX_SAFE_U64
        {
            return Err(QuiescentBackupErrorV1::ProviderUnhealthy);
        }
        Ok(Self {
            recovery_root_identity_sha256,
            instance_identity_sha256,
            provider_maintenance_generation,
            profile_generation,
            operation_retirement_pending,
            orphan_retirement_pending,
        })
    }

    pub(crate) const fn recovery_root_identity_sha256(&self) -> Sha256Digest {
        self.recovery_root_identity_sha256
    }

    pub(crate) const fn instance_identity_sha256(&self) -> Sha256Digest {
        self.instance_identity_sha256
    }

    pub(crate) const fn operation_retirement_pending(&self) -> u64 {
        self.operation_retirement_pending
    }

    pub(crate) const fn orphan_retirement_pending(&self) -> u64 {
        self.orphan_retirement_pending
    }
}

impl fmt::Debug for RecoveryMaintenanceSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryMaintenanceSourceV1")
            .finish_non_exhaustive()
    }
}

/// Provider-wide custody mutually exclusive with publication and every retirement path.
pub(crate) trait ProviderMaintenanceGuardV1: RecoveryCleanupGuardV1 {
    fn capture_recovery_source_v1(
        &mut self,
    ) -> Result<RecoveryMaintenanceSourceV1, MaintenanceCustodyValidationV1>;

    fn recheck_recovery_source_v1(
        &mut self,
        expected: &RecoveryMaintenanceSourceV1,
    ) -> MaintenanceCustodyValidationV1;
}

pub(crate) enum ProviderMaintenanceGuardOutcomeV1<G> {
    Acquired(G),
    Contended,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

impl<G> fmt::Debug for ProviderMaintenanceGuardOutcomeV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquired(_) => "ProviderMaintenanceGuardOutcomeV1::Acquired(..)",
            Self::Contended => "ProviderMaintenanceGuardOutcomeV1::Contended",
            Self::Unavailable => "ProviderMaintenanceGuardOutcomeV1::Unavailable",
            Self::DeadlineReached => "ProviderMaintenanceGuardOutcomeV1::DeadlineReached",
            Self::Unsupported => "ProviderMaintenanceGuardOutcomeV1::Unsupported",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRecoveryCustodyV1 {
    OperationBound,
    QuarantinedOrphan,
    OrphanResolutionTombstone,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRecoveryStateV1 {
    Published,
    RetiredTombstone,
}

pub(crate) struct ProviderRecoveryInventoryEntryInputV1 {
    pub(crate) provider_profile_id: Identifier,
    pub(crate) provider_profile_version: u16,
    pub(crate) provider_id: Identifier,
    pub(crate) provider_generation: u64,
    pub(crate) evidence_class: RecoveryEvidenceClassV1,
    pub(crate) at_rest_profile_id: Identifier,
    pub(crate) manifest_digest: Sha256Digest,
    pub(crate) material_digest: Sha256Digest,
    pub(crate) material_length: u64,
    pub(crate) reserved_capacity: u64,
    pub(crate) custody: ProviderRecoveryCustodyV1,
    pub(crate) state: ProviderRecoveryStateV1,
    pub(crate) retirement_manifest_digest: Option<Sha256Digest>,
}

impl fmt::Debug for ProviderRecoveryInventoryEntryInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRecoveryInventoryEntryInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRecoveryInventoryEntryBuildErrorV1 {
    InvalidEntry,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProviderRecoveryInventoryEntryV1 {
    provider_profile_id: Identifier,
    provider_profile_version: u16,
    provider_id: Identifier,
    provider_generation: u64,
    evidence_class: RecoveryEvidenceClassV1,
    at_rest_profile_id: Identifier,
    manifest_digest: Sha256Digest,
    material_digest: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
    custody: ProviderRecoveryCustodyV1,
    state: ProviderRecoveryStateV1,
    retirement_manifest_digest: Option<Sha256Digest>,
}

impl ProviderRecoveryInventoryEntryV1 {
    pub(crate) fn try_new(
        input: ProviderRecoveryInventoryEntryInputV1,
    ) -> Result<Self, ProviderRecoveryInventoryEntryBuildErrorV1> {
        if input.provider_profile_version != RECOVERY_PROVIDER_PROFILE_VERSION_V1
            || input.provider_generation == 0
            || input.provider_generation > MAX_SAFE_U64
            || input.material_length > MAX_SAFE_U64
            || input.reserved_capacity > MAX_SAFE_U64
            || input.reserved_capacity < input.material_length
            || !matches!(
                (input.state, input.custody, input.retirement_manifest_digest),
                (
                    ProviderRecoveryStateV1::Published,
                    ProviderRecoveryCustodyV1::OperationBound
                        | ProviderRecoveryCustodyV1::QuarantinedOrphan,
                    None,
                ) | (
                    ProviderRecoveryStateV1::RetiredTombstone,
                    ProviderRecoveryCustodyV1::OperationBound
                        | ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
                    Some(_),
                )
            )
        {
            return Err(ProviderRecoveryInventoryEntryBuildErrorV1::InvalidEntry);
        }
        Ok(Self {
            provider_profile_id: input.provider_profile_id,
            provider_profile_version: input.provider_profile_version,
            provider_id: input.provider_id,
            provider_generation: input.provider_generation,
            evidence_class: input.evidence_class,
            at_rest_profile_id: input.at_rest_profile_id,
            manifest_digest: input.manifest_digest,
            material_digest: input.material_digest,
            material_length: input.material_length,
            reserved_capacity: input.reserved_capacity,
            custody: input.custody,
            state: input.state,
            retirement_manifest_digest: input.retirement_manifest_digest,
        })
    }

    pub(crate) const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }

    pub(crate) const fn provider_profile_id(&self) -> &Identifier {
        &self.provider_profile_id
    }

    pub(crate) const fn provider_profile_version(&self) -> u16 {
        self.provider_profile_version
    }

    pub(crate) const fn provider_id(&self) -> &Identifier {
        &self.provider_id
    }

    pub(crate) const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub(crate) const fn evidence_class(&self) -> RecoveryEvidenceClassV1 {
        self.evidence_class
    }

    pub(crate) const fn at_rest_profile_id(&self) -> &Identifier {
        &self.at_rest_profile_id
    }

    pub(crate) const fn material_digest(&self) -> Sha256Digest {
        self.material_digest
    }

    pub(crate) const fn material_length(&self) -> u64 {
        self.material_length
    }

    pub(crate) const fn reserved_capacity(&self) -> u64 {
        self.reserved_capacity
    }

    pub(crate) const fn custody(&self) -> ProviderRecoveryCustodyV1 {
        self.custody
    }

    pub(crate) const fn state(&self) -> ProviderRecoveryStateV1 {
        self.state
    }

    pub(crate) const fn retirement_manifest_digest(&self) -> Option<Sha256Digest> {
        self.retirement_manifest_digest
    }
}

impl fmt::Debug for ProviderRecoveryInventoryEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRecoveryInventoryEntryV1")
            .finish_non_exhaustive()
    }
}

fn validate_backup_package_resource_shape_v1(
    entries: &[ProviderRecoveryInventoryEntryV1],
    coordinator_database_length: u64,
) -> Result<(), QuiescentBackupErrorV1> {
    BACKUP_PACKAGE_FIXED_DIRECTORIES_V1
        .checked_add(entries.len())
        .filter(|count| *count <= MAX_RESTORE_PACKAGE_DIRECTORIES_V1)
        .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;

    if coordinator_database_length == 0
        || coordinator_database_length > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1
    {
        return Err(QuiescentBackupErrorV1::BackupFailed);
    }
    // This is a sound lower bound, not a promise that the finished package will fit: the exact
    // runtime accounting below still charges the actual provider/canonical bytes. It reserves
    // the exact projected SQLite image, all three required non-empty canonical members under
    // both staging and published paths, and one required non-empty provider manifest per entry.
    let mandatory_canonical_bytes = BACKUP_PACKAGE_CANONICAL_MEMBERS_V1
        .checked_mul(BACKUP_PACKAGE_CANONICAL_MEMBER_PATHS_V1)
        .and_then(|paths| paths.checked_mul(BACKUP_PACKAGE_MINIMUM_NONEMPTY_MEMBER_BYTES_V1))
        .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
    let mut minimum_package_bytes = coordinator_database_length
        .checked_add(mandatory_canonical_bytes)
        .filter(|total| *total <= MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1)
        .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;

    let mut files = BACKUP_PACKAGE_FIXED_WORST_CASE_FILES_V1;
    for entry in entries {
        minimum_package_bytes = minimum_package_bytes
            .checked_add(BACKUP_PACKAGE_MINIMUM_NONEMPTY_MEMBER_BYTES_V1)
            .filter(|total| *total <= MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1)
            .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
        match entry.state() {
            ProviderRecoveryStateV1::Published => {
                if entry.material_length() > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1
                    || entry.reserved_capacity() > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1
                {
                    return Err(QuiescentBackupErrorV1::ProviderExportInvalid);
                }
                files = files
                    .checked_add(2)
                    .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
                minimum_package_bytes = minimum_package_bytes
                    .checked_add(entry.material_length())
                    .filter(|total| *total <= MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1)
                    .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
            }
            ProviderRecoveryStateV1::RetiredTombstone => {
                files = files
                    .checked_add(1)
                    .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
            }
        }
        if files > MAX_RESTORE_PACKAGE_FILES_V1 {
            return Err(QuiescentBackupErrorV1::ProviderExportInvalid);
        }
    }
    Ok(())
}

fn account_backup_package_member_bytes_v1(
    total: &mut u64,
    member_length: u64,
    directory_entry_copies: u64,
    error: QuiescentBackupErrorV1,
) -> Result<(), QuiescentBackupErrorV1> {
    if member_length > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 {
        return Err(error);
    }
    let added = member_length
        .checked_mul(directory_entry_copies)
        .ok_or(error)?;
    account_backup_package_bytes_v1(total, added, error)
}

fn account_backup_package_bytes_v1(
    total: &mut u64,
    added: u64,
    error: QuiescentBackupErrorV1,
) -> Result<(), QuiescentBackupErrorV1> {
    *total = total
        .checked_add(added)
        .filter(|value| *value <= MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1)
        .ok_or(error)?;
    Ok(())
}

fn projected_backup_sqlite_length_v1(source: &Connection) -> Result<u64, QuiescentBackupErrorV1> {
    let page_count = source
        .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
        .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnavailable)?;
    let page_size = source
        .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnavailable)?;
    let page_count =
        u64::try_from(page_count).map_err(|_| QuiescentBackupErrorV1::CoordinatorUnhealthy)?;
    let page_size =
        u64::try_from(page_size).map_err(|_| QuiescentBackupErrorV1::CoordinatorUnhealthy)?;
    let length = page_count
        .checked_mul(page_size)
        .ok_or(QuiescentBackupErrorV1::BackupFailed)?;
    if length == 0 || length > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 {
        return Err(QuiescentBackupErrorV1::BackupFailed);
    }
    Ok(length)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderRecoveryEnumerationErrorV1 {
    Unavailable,
    Unhealthy,
}

/// Provider enumeration is callable only while borrowed opaque cleanup custody remains live.
pub(crate) trait GuardedRecoveryInventoryProviderV1: Send + Sync {
    type Custody: RecoveryCleanupGuardV1;

    fn enumerate_recovery_inventory_v1(
        &self,
        custody: &mut Self::Custody,
    ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, ProviderRecoveryEnumerationErrorV1>;
}

/// Provider-wide extension used only by a quiescent backup cut.
pub(crate) trait QuiescentRecoveryMaintenanceProviderV1:
    GuardedRecoveryInventoryProviderV1
where
    Self::Custody: ProviderMaintenanceGuardV1,
{
    fn acquire_provider_maintenance_guard_v1(
        &self,
        deadline_monotonic_ms: u64,
    ) -> ProviderMaintenanceGuardOutcomeV1<Self::Custody>;
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ReconciledRecoveryInventoryV1 {
    provider_entries: Vec<ProviderRecoveryInventoryEntryV1>,
    operation_reference_count: u64,
    quarantine_reference_count: u64,
    operation_retirement_pending: u64,
    orphan_retirement_pending: u64,
}

impl ReconciledRecoveryInventoryV1 {
    pub(crate) fn provider_entries(&self) -> &[ProviderRecoveryInventoryEntryV1] {
        &self.provider_entries
    }

    pub(crate) const fn operation_reference_count(&self) -> u64 {
        self.operation_reference_count
    }

    pub(crate) const fn quarantine_reference_count(&self) -> u64 {
        self.quarantine_reference_count
    }

    pub(crate) const fn operation_retirement_pending(&self) -> u64 {
        self.operation_retirement_pending
    }

    pub(crate) const fn orphan_retirement_pending(&self) -> u64 {
        self.orphan_retirement_pending
    }
}

impl fmt::Debug for ReconciledRecoveryInventoryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconciledRecoveryInventoryV1")
            .field("provider_entry_count", &self.provider_entries.len())
            .field("operation_reference_count", &self.operation_reference_count)
            .field(
                "quarantine_reference_count",
                &self.quarantine_reference_count,
            )
            .field(
                "operation_retirement_pending",
                &self.operation_retirement_pending,
            )
            .field("orphan_retirement_pending", &self.orphan_retirement_pending)
            .finish_non_exhaustive()
    }
}

pub(crate) enum RecoveryMaintenanceOutcomeV1 {
    Ready(ReconciledRecoveryInventoryV1),
    BackupBlocked(ReconciledRecoveryInventoryV1),
}

impl RecoveryMaintenanceOutcomeV1 {
    pub(crate) const fn inventory(&self) -> &ReconciledRecoveryInventoryV1 {
        match self {
            Self::Ready(inventory) | Self::BackupBlocked(inventory) => inventory,
        }
    }

    pub(crate) const fn backup_allowed(&self) -> bool {
        matches!(self, Self::Ready(_))
    }
}

impl fmt::Debug for RecoveryMaintenanceOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(_) => formatter.write_str("RecoveryMaintenanceOutcomeV1::Ready(..)"),
            Self::BackupBlocked(_) => {
                formatter.write_str("RecoveryMaintenanceOutcomeV1::BackupBlocked(..)")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryMaintenanceErrorV1 {
    ProviderUnavailable,
    ProviderUnhealthy,
    DuplicateProviderEntry,
    DuplicateCoordinatorReference,
    MissingProviderEntry,
    ExtraProviderEntry,
    BindingConflict,
    StoreUnavailable,
    StoreUnhealthy,
}

/// Payload-free refusal from the quiescent-cut protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuiescentBackupErrorV1 {
    PauseContended,
    PauseUnavailable,
    PauseDeadlineReached,
    PauseUnsupported,
    PauseUnhealthy,
    ProviderContended,
    ProviderUnavailable,
    ProviderDeadlineReached,
    ProviderUnsupported,
    ProviderUnhealthy,
    CoordinatorUnavailable,
    CoordinatorUnhealthy,
    ProviderExtrasQuarantinedRetryRequired,
    RetirementPending,
    SourceChanged,
    DestinationExists,
    DestinationUnavailable,
    BackupFailed,
    IntegrityFailed,
    ProviderExportUnavailable,
    ProviderExportInvalid,
    ManifestInvalid,
    SigningUnavailable,
    ProvenanceInvalid,
    PublicationFailed,
}

/// Payload-free refusal from authenticated clean-root restore preparation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreparationRestoreErrorV1 {
    PlatformUnsupported,
    PackageUnavailable,
    PackageInvalid,
    ProvenanceInvalid,
    DeadlineReached,
    PauseContended,
    PauseUnavailable,
    PauseDeadlineReached,
    PauseUnsupported,
    PauseUnhealthy,
    CoordinatorDestinationUnavailable,
    RecoveryDestinationUnavailable,
    RecoveryImportInvalid,
    SourceChanged,
    AgreementFailed,
    QuarantineUnavailable,
}

impl fmt::Debug for PreparationRestoreErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl PreparationRestoreErrorV1 {
    /// Stable payload-free diagnostic code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlatformUnsupported => "RESTORE_PLATFORM_UNSUPPORTED",
            Self::PackageUnavailable => "RESTORE_PACKAGE_UNAVAILABLE",
            Self::PackageInvalid => "RESTORE_PACKAGE_INVALID",
            Self::ProvenanceInvalid => "RESTORE_PROVENANCE_INVALID",
            Self::DeadlineReached => "RESTORE_DEADLINE_REACHED",
            Self::PauseContended => "RESTORE_PAUSE_CONTENDED",
            Self::PauseUnavailable => "RESTORE_PAUSE_UNAVAILABLE",
            Self::PauseDeadlineReached => "RESTORE_PAUSE_DEADLINE_REACHED",
            Self::PauseUnsupported => "RESTORE_PAUSE_UNSUPPORTED",
            Self::PauseUnhealthy => "RESTORE_PAUSE_UNHEALTHY",
            Self::CoordinatorDestinationUnavailable => {
                "RESTORE_COORDINATOR_DESTINATION_UNAVAILABLE"
            }
            Self::RecoveryDestinationUnavailable => "RESTORE_RECOVERY_DESTINATION_UNAVAILABLE",
            Self::RecoveryImportInvalid => "RESTORE_RECOVERY_IMPORT_INVALID",
            Self::SourceChanged => "RESTORE_SOURCE_CHANGED",
            Self::AgreementFailed => "RESTORE_AGREEMENT_FAILED",
            Self::QuarantineUnavailable => "RESTORE_QUARANTINE_UNAVAILABLE",
        }
    }
}

impl fmt::Display for PreparationRestoreErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PreparationRestoreErrorV1 {}

#[cfg(not(test))]
#[derive(Clone)]
struct AcceptedProviderRestorePackageV1 {
    entry: ProviderRecoveryInventoryEntryV1,
    package_binding_sha256: Sha256Digest,
    relative_directory: String,
}

#[cfg(not(test))]
impl fmt::Debug for AcceptedProviderRestorePackageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedProviderRestorePackageV1")
            .finish_non_exhaustive()
    }
}

/// Immutable source-package custody plus every authenticated restore binding.
#[cfg(not(test))]
#[must_use = "accepted package custody must be consumed by restore or dropped"]
pub(crate) struct AcceptedPreparationRestorePackageV1 {
    custody: RestorePackageCustodyV1,
    source_connection: Connection,
    trust_custody: Box<dyn ProvisionerTrustCustodyV1>,
    package_directory_binding_sha256: Sha256Digest,
    bindings: VerifiedRestorePackageBindingsV1,
    source_generations: schema::CoordinatorLifecycleGenerationsV1,
    provider_packages: Vec<AcceptedProviderRestorePackageV1>,
    fault_probe: MaintenanceFaultProbeV1,
}

#[cfg(not(test))]
impl AcceptedPreparationRestorePackageV1 {
    pub(crate) const fn bindings(&self) -> &VerifiedRestorePackageBindingsV1 {
        &self.bindings
    }

    pub(crate) const fn source_generations(&self) -> schema::CoordinatorLifecycleGenerationsV1 {
        self.source_generations
    }

    fn revalidate_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
        &self,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<(), PreparationRestoreErrorV1> {
        remaining_monotonic_ms(clock, deadline_monotonic_ms)
            .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
        self.custody
            .revalidate_v1()
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        // A bounded package-wide content pass can consume the remaining budget. Every caller
        // uses this method immediately before a restore mutation/publication boundary.
        remaining_monotonic_ms(clock, deadline_monotonic_ms)
            .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
        Ok(())
    }

    fn reverify_provenance_v1(&mut self) -> Result<(), PreparationRestoreErrorV1> {
        let attestation = self
            .custody
            .read_member_v1(
                RESTORE_ATTESTATION_MEMBER_V1,
                RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1,
            )
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        let top_level = self
            .custody
            .read_member_v1(
                RESTORE_TOP_LEVEL_MEMBER_V1,
                RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1,
            )
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        let inventory = self
            .custody
            .read_member_v1(
                RESTORE_INVENTORY_MEMBER_V1,
                RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1,
            )
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        let current = verify_restore_package_manifests_v1(
            &attestation,
            &top_level,
            &inventory,
            &*self.trust_custody,
        )
        .map_err(|_| PreparationRestoreErrorV1::ProvenanceInvalid)?;
        if current != self.bindings {
            return Err(PreparationRestoreErrorV1::SourceChanged);
        }
        Ok(())
    }
}

#[cfg(not(test))]
impl fmt::Debug for AcceptedPreparationRestorePackageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedPreparationRestorePackageV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestorePackageQuarantineReasonV1 {
    PackageInvalid,
    ProvenanceInvalid,
    SourceChanged,
}

/// Opaque local package binding used to retain an invalid source without exposing its path.
#[cfg(not(test))]
pub(crate) struct RestorePackageQuarantineEvidenceV1 {
    package_directory_binding_sha256: Sha256Digest,
    reason: RestorePackageQuarantineReasonV1,
}

#[cfg(not(test))]
impl RestorePackageQuarantineEvidenceV1 {
    pub(crate) const fn package_directory_binding_sha256(&self) -> Sha256Digest {
        self.package_directory_binding_sha256
    }

    pub(crate) const fn reason(&self) -> RestorePackageQuarantineReasonV1 {
        self.reason
    }
}

#[cfg(not(test))]
impl fmt::Debug for RestorePackageQuarantineEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestorePackageQuarantineEvidenceV1")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// Accepts and freezes an authenticated backup package before either destination root
/// can be reserved. Every file, manifest, SQLite invariant and provider reference is
/// verified under retained immutable-member custody.
#[cfg(all(not(test), windows))]
pub(crate) fn accept_preparation_restore_package_v1<R, K, C, Q>(
    _package: ProvisionedRestorePackageV1,
    _quarantine_authority: &Q,
    _trust: &R,
    _historical_plan_keys: &K,
    _maximum_busy_wait_ms: u64,
    _clock: &C,
    _deadline_monotonic_ms: u64,
) -> Result<AcceptedPreparationRestorePackageV1, PreparationRestoreErrorV1>
where
    R: ProvisionerTrustResolverV1 + ?Sized,
    K: Ed25519KeyResolver,
    C: CoordinatorMonotonicClockV1 + ?Sized,
    Q: RestoreQuarantineAuthorityV1,
{
    // Refuse before deriving a package binding, capturing a member handle, acquiring
    // trust custody or invoking quarantine. Stable Rust cannot yet bind every later
    // path-based SQLite open to these exact Windows handles.
    Err(PreparationRestoreErrorV1::PlatformUnsupported)
}

#[cfg(all(not(test), not(windows)))]
pub(crate) fn accept_preparation_restore_package_v1<R, K, C, Q>(
    package: ProvisionedRestorePackageV1,
    quarantine_authority: &Q,
    trust: &R,
    historical_plan_keys: &K,
    maximum_busy_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<AcceptedPreparationRestorePackageV1, PreparationRestoreErrorV1>
where
    R: ProvisionerTrustResolverV1 + ?Sized,
    K: Ed25519KeyResolver,
    C: CoordinatorMonotonicClockV1 + ?Sized,
    Q: RestoreQuarantineAuthorityV1,
{
    accept_preparation_restore_package_with_probe_v1(
        package,
        quarantine_authority,
        trust,
        historical_plan_keys,
        maximum_busy_wait_ms,
        clock,
        deadline_monotonic_ms,
        MaintenanceFaultProbeV1::disabled_v1(),
    )
}

#[cfg(not(test))]
#[allow(clippy::too_many_arguments)]
fn accept_preparation_restore_package_with_probe_v1<R, K, C, Q>(
    package: ProvisionedRestorePackageV1,
    quarantine_authority: &Q,
    trust: &R,
    historical_plan_keys: &K,
    maximum_busy_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
    mut fault_probe: MaintenanceFaultProbeV1,
) -> Result<AcceptedPreparationRestorePackageV1, PreparationRestoreErrorV1>
where
    R: ProvisionerTrustResolverV1 + ?Sized,
    K: Ed25519KeyResolver,
    C: CoordinatorMonotonicClockV1 + ?Sized,
    Q: RestoreQuarantineAuthorityV1,
{
    let package_directory_binding_sha256 = package.attested_directory_binding_sha256_v1();
    let accepted = (|| {
        remaining_monotonic_ms(clock, deadline_monotonic_ms)
            .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
        let mut custody = capture_immutable_members_v1(&package)
            .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        // Package traversal and its bounded content pass may consume real time. Refuse before
        // interpreting the captured package if the caller's monotonic authority has expired.
        remaining_monotonic_ms(clock, deadline_monotonic_ms)
            .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
        let attestation = custody
            .read_member_v1(
                RESTORE_ATTESTATION_MEMBER_V1,
                RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1,
            )
            .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        let top_level = custody
            .read_member_v1(
                RESTORE_TOP_LEVEL_MEMBER_V1,
                RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1,
            )
            .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        let inventory = custody
            .read_member_v1(
                RESTORE_INVENTORY_MEMBER_V1,
                RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1,
            )
            .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        let trust_custody = match trust.acquire_restore_trust_custody_v1() {
            ProvisionerTrustCustodyOutcomeV1::Acquired(custody) => custody,
            ProvisionerTrustCustodyOutcomeV1::Revoked
            | ProvisionerTrustCustodyOutcomeV1::Unavailable => {
                return Err(PreparationRestoreErrorV1::ProvenanceInvalid)
            }
        };
        let bindings = verify_restore_package_manifests_v1(
            &attestation,
            &top_level,
            &inventory,
            &*trust_custody,
        )
        .map_err(|_| PreparationRestoreErrorV1::ProvenanceInvalid)?;
        validate_restore_lifecycle_requirements_v1(&bindings)?;
        if bindings.coordinator_schema_sha256()
            != Sha256Digest::from_bytes(schema::embedded_schema_v1_sha256())
        {
            return Err(PreparationRestoreErrorV1::PackageInvalid);
        }

        let source_generations = restore_source_generations_v1(&bindings)?;
        let provider_entries = restore_provider_entries_v1(&bindings)?;
        let provider_packages = validate_restore_package_layout_v1(
            &mut custody,
            provider_entries,
            bindings.coordinator_database_sha256(),
            bindings.inventory_sha256(),
            bindings.top_level_manifest_sha256(),
            bindings.attestation_sha256(),
        )?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)
            .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;

        // Deserialize exact bytes read through the retained package handle into SQLite-owned
        // memory. No ambient scratch file or new durable crash boundary is introduced.
        let source_bytes = custody
            .read_member_v1(RESTORE_COORDINATOR_MEMBER_V1, MAX_SAFE_U64)
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)
            .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
        if source_bytes.is_empty()
            || Sha256Digest::digest(&source_bytes) != bindings.coordinator_database_sha256()
        {
            return Err(PreparationRestoreErrorV1::SourceChanged);
        }
        let source_length = source_bytes.len();
        let mut source_connection = Connection::open_in_memory()
            .map_err(|_| PreparationRestoreErrorV1::PackageUnavailable)?;
        source_connection
            .deserialize_read_exact(
                rusqlite::MAIN_DB,
                std::io::Cursor::new(source_bytes),
                source_length,
                true,
            )
            .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        configure_deadline_bounded_busy_timeout_v1(
            &source_connection,
            maximum_busy_wait_ms,
            clock,
            deadline_monotonic_ms,
        )
        .map_err(|_| PreparationRestoreErrorV1::PackageUnavailable)?;
        source_connection
            .pragma_update(None, "foreign_keys", "ON")
            .and_then(|_| source_connection.pragma_update(None, "trusted_schema", "OFF"))
            .and_then(|_| source_connection.pragma_update(None, "cell_size_check", "ON"))
            .and_then(|_| source_connection.pragma_update(None, "recursive_triggers", "ON"))
            .and_then(|_| source_connection.pragma_update(None, "query_only", "ON"))
            .map_err(|_| PreparationRestoreErrorV1::PackageUnavailable)?;
        custody
            .revalidate_v1()
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        let imported = schema::verify_imported_active_backup_v1(
            &source_connection,
            source_generations,
            historical_plan_keys,
        )
        .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        if coordinator_root_identity_digest_v1(imported.summary().root_identity.as_bytes())
            != bindings.source_coordinator_root_identity_sha256()
            || imported.generations() != source_generations
            || !restore_counts_match_v1(imported.counts(), bindings.counts())
        {
            return Err(PreparationRestoreErrorV1::PackageInvalid);
        }
        let reconciled = reconcile_enumerated_inventory_v1(
            &source_connection,
            provider_packages
                .iter()
                .map(|package| package.entry.clone())
                .collect(),
        )
        .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        let reconciled = match reconciled {
            RecoveryMaintenanceOutcomeV1::Ready(inventory) => inventory,
            RecoveryMaintenanceOutcomeV1::BackupBlocked(_) => {
                return Err(PreparationRestoreErrorV1::PackageInvalid)
            }
        };
        if reconciled.provider_entries().len()
            != usize::try_from(bindings.entry_count())
                .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?
            || reconciled.operation_retirement_pending() != 0
            || reconciled.orphan_retirement_pending() != 0
        {
            return Err(PreparationRestoreErrorV1::PackageInvalid);
        }
        remaining_monotonic_ms(clock, deadline_monotonic_ms)
            .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
        custody
            .revalidate_v1()
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        reach_restore_package_and_pinned_provenance_accepted_v1(&mut fault_probe);
        Ok(AcceptedPreparationRestorePackageV1 {
            custody,
            source_connection,
            trust_custody,
            package_directory_binding_sha256,
            bindings,
            source_generations,
            provider_packages,
            fault_probe: fault_probe.clone(),
        })
    })();
    match accepted {
        Err(error @ PreparationRestoreErrorV1::PackageInvalid) => {
            remaining_monotonic_ms(clock, deadline_monotonic_ms)
                .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
            persist_package_quarantine_v1(
                quarantine_authority,
                package_directory_binding_sha256,
                RestorePackageQuarantineReasonV1::PackageInvalid,
                deadline_monotonic_ms,
                &mut fault_probe,
            )?;
            Err(error)
        }
        Err(error @ PreparationRestoreErrorV1::ProvenanceInvalid) => {
            remaining_monotonic_ms(clock, deadline_monotonic_ms)
                .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
            persist_package_quarantine_v1(
                quarantine_authority,
                package_directory_binding_sha256,
                RestorePackageQuarantineReasonV1::ProvenanceInvalid,
                deadline_monotonic_ms,
                &mut fault_probe,
            )?;
            Err(error)
        }
        Err(error @ PreparationRestoreErrorV1::SourceChanged) => {
            remaining_monotonic_ms(clock, deadline_monotonic_ms)
                .map_err(|_| PreparationRestoreErrorV1::DeadlineReached)?;
            persist_package_quarantine_v1(
                quarantine_authority,
                package_directory_binding_sha256,
                RestorePackageQuarantineReasonV1::SourceChanged,
                deadline_monotonic_ms,
                &mut fault_probe,
            )?;
            Err(error)
        }
        result => result,
    }
}

#[cfg(not(test))]
fn persist_package_quarantine_v1<Q: RestoreQuarantineAuthorityV1>(
    authority: &Q,
    package_directory_binding_sha256: Sha256Digest,
    reason: RestorePackageQuarantineReasonV1,
    deadline_monotonic_ms: u64,
    fault_probe: &mut MaintenanceFaultProbeV1,
) -> Result<(), PreparationRestoreErrorV1> {
    authority
        .persist_restore_package_quarantine_v1(
            &RestorePackageQuarantineEvidenceV1 {
                package_directory_binding_sha256,
                reason,
            },
            deadline_monotonic_ms,
        )
        .map_err(|_| PreparationRestoreErrorV1::QuarantineUnavailable)?;
    record_restore_quarantine_persisted_v1(fault_probe);
    Ok(())
}

#[cfg(not(test))]
fn persist_root_quarantine_v1<Q: RestoreQuarantineAuthorityV1>(
    authority: &Q,
    evidence: &RestoreQuarantineEvidenceV1,
    deadline_monotonic_ms: u64,
    fault_probe: &mut MaintenanceFaultProbeV1,
) -> Result<(), PreparationRestoreErrorV1> {
    authority
        .persist_restore_quarantine_v1(evidence, deadline_monotonic_ms)
        .map_err(|_| PreparationRestoreErrorV1::QuarantineUnavailable)?;
    record_restore_quarantine_persisted_v1(fault_probe);
    Ok(())
}

#[cfg(not(test))]
fn record_restore_quarantine_persisted_v1(fault_probe: &mut MaintenanceFaultProbeV1) {
    reach_restore_quarantine_persisted_v1(fault_probe);
}

#[cfg(not(test))]
fn validate_restore_lifecycle_requirements_v1(
    bindings: &VerifiedRestorePackageBindingsV1,
) -> Result<(), PreparationRestoreErrorV1> {
    let lifecycle = bindings.lifecycle();
    if lifecycle.source_root_lifecycle() != crate::manifest::RestorePackageRootLifecycleV1::Active
        || lifecycle.required_restore_root_lifecycle()
            != crate::manifest::RestorePackageRootLifecycleV1::RestorePending
        || !lifecycle.requires_paused_restore()
        || !lifecycle.requires_boot_epoch_rotation()
        || !lifecycle.requires_instance_epoch_rotation()
        || !lifecycle.requires_fencing_epoch_rotation()
        || !lifecycle.nonterminal_preparations_not_reactivatable()
        || !lifecycle.may_omit_work_after_generation()
        || !lifecycle.complete_reference_set()
        || !lifecycle.no_retirement_pending()
        || !lifecycle.all_required_entries_verified()
        || bindings.counts().operation_retirement_pending() != 0
        || bindings.counts().orphan_retirement_pending() != 0
    {
        return Err(PreparationRestoreErrorV1::PackageInvalid);
    }
    Ok(())
}

#[cfg(not(test))]
fn restore_source_generations_v1(
    bindings: &VerifiedRestorePackageBindingsV1,
) -> Result<schema::CoordinatorLifecycleGenerationsV1, PreparationRestoreErrorV1> {
    let generations = bindings.generations();
    schema::CoordinatorLifecycleGenerationsV1::try_new(
        generations.store(),
        generations.operation(),
        generations.budget(),
        generations.event(),
        generations.quarantine(),
    )
    .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)
}

#[cfg(not(test))]
fn restore_provider_entries_v1(
    bindings: &VerifiedRestorePackageBindingsV1,
) -> Result<Vec<AcceptedProviderRestorePackageV1>, PreparationRestoreErrorV1> {
    let expected_count = usize::try_from(bindings.entry_count())
        .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
    let mut packages = Vec::new();
    packages
        .try_reserve_exact(expected_count)
        .map_err(|_| PreparationRestoreErrorV1::PackageUnavailable)?;
    for provider in bindings.provider_sets() {
        let provider_profile_version = u16::try_from(provider.provider_profile_version())
            .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
        let evidence_class = match provider.evidence_class().as_str() {
            "SYNTHETIC_CONFORMANCE" => RecoveryEvidenceClassV1::SyntheticConformance,
            "APPROVED_PRODUCTION" => RecoveryEvidenceClassV1::ApprovedProduction,
            _ => return Err(PreparationRestoreErrorV1::PackageInvalid),
        };
        for entry in provider.entries() {
            let custody = match entry.custody() {
                RecoveryCustodyV1::OperationBound => ProviderRecoveryCustodyV1::OperationBound,
                RecoveryCustodyV1::QuarantinedOrphan => {
                    ProviderRecoveryCustodyV1::QuarantinedOrphan
                }
                RecoveryCustodyV1::OrphanResolutionTombstone => {
                    ProviderRecoveryCustodyV1::OrphanResolutionTombstone
                }
            };
            let state = match entry.state() {
                RecoverySnapshotStateV1::MaterialPresent => ProviderRecoveryStateV1::Published,
                RecoverySnapshotStateV1::RetiredTombstone => {
                    ProviderRecoveryStateV1::RetiredTombstone
                }
            };
            if state == ProviderRecoveryStateV1::Published
                && (entry.material_length() > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1
                    || entry.reserved_capacity() > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1)
            {
                return Err(PreparationRestoreErrorV1::PackageInvalid);
            }
            let provider_entry =
                ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                    provider_profile_id: provider.provider_profile_id().clone(),
                    provider_profile_version,
                    provider_id: provider.provider_id().clone(),
                    provider_generation: provider.provider_generation(),
                    evidence_class,
                    at_rest_profile_id: provider.at_rest_profile_id().clone(),
                    manifest_digest: entry.manifest_sha256(),
                    material_digest: entry.material_sha256(),
                    material_length: entry.material_length(),
                    reserved_capacity: entry.reserved_capacity(),
                    custody,
                    state,
                    retirement_manifest_digest: entry.retirement_manifest_sha256(),
                })
                .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
            packages.push(AcceptedProviderRestorePackageV1 {
                entry: provider_entry,
                package_binding_sha256: entry.package_binding_sha256(),
                relative_directory: String::new(),
            });
        }
    }
    if packages.len() != expected_count {
        return Err(PreparationRestoreErrorV1::PackageInvalid);
    }
    Ok(packages)
}

#[cfg(not(test))]
fn validate_restore_package_layout_v1(
    custody: &mut RestorePackageCustodyV1,
    mut packages: Vec<AcceptedProviderRestorePackageV1>,
    expected_coordinator_sha256: Sha256Digest,
    expected_inventory_sha256: Sha256Digest,
    expected_top_level_sha256: Sha256Digest,
    expected_attestation_sha256: Sha256Digest,
) -> Result<Vec<AcceptedProviderRestorePackageV1>, PreparationRestoreErrorV1> {
    let mut actual_directories = custody
        .directory_names_v1()
        .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut expected_directories = vec![
        "published".to_owned(),
        "recovery-packages".to_owned(),
        "staging".to_owned(),
    ];
    for index in 0..packages.len() {
        expected_directories.push(format!("recovery-packages/{index:016x}"));
    }
    actual_directories.sort();
    expected_directories.sort();
    if actual_directories != expected_directories {
        return Err(PreparationRestoreErrorV1::PackageInvalid);
    }

    let mut actual_members = custody
        .member_names_v1()
        .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut expected_members = vec![
        RESTORE_COORDINATOR_MEMBER_V1.to_owned(),
        RESTORE_INVENTORY_MEMBER_V1.to_owned(),
        RESTORE_TOP_LEVEL_MEMBER_V1.to_owned(),
        RESTORE_ATTESTATION_MEMBER_V1.to_owned(),
    ];
    let (coordinator_sha256, coordinator_length) = custody
        .hash_member_sha256_v1(RESTORE_COORDINATOR_MEMBER_V1, MAX_SAFE_U64)
        .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
    if coordinator_length == 0 || coordinator_sha256 != expected_coordinator_sha256 {
        return Err(PreparationRestoreErrorV1::PackageInvalid);
    }

    for (member, expected_digest) in [
        ("staging/recovery-inventory.json", expected_inventory_sha256),
        ("staging/preparation-backup.json", expected_top_level_sha256),
        (
            "staging/provenance-attestation.json",
            expected_attestation_sha256,
        ),
    ] {
        if actual_members.iter().any(|actual| actual == member) {
            let (digest, _) = custody
                .hash_member_sha256_v1(member, RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1)
                .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
            if digest != expected_digest {
                return Err(PreparationRestoreErrorV1::PackageInvalid);
            }
            expected_members.push(member.to_owned());
        }
    }

    for (directory_index, package) in packages.iter_mut().enumerate() {
        let directory = format!("recovery-packages/{directory_index:016x}");
        let manifest_name = format!("{directory}/manifest.json");
        let material_name = format!("{directory}/material.bin");
        let retirement_name = format!("{directory}/retirement-manifest.json");
        let has_manifest = actual_members.iter().any(|name| name == &manifest_name);
        let has_material = actual_members.iter().any(|name| name == &material_name);
        let has_retirement = actual_members.iter().any(|name| name == &retirement_name);

        if has_manifest && has_material && !has_retirement {
            let (manifest_digest, _) = custody
                .hash_member_sha256_v1(&manifest_name, MAX_SAFE_U64)
                .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
            let (material_digest, material_length) = custody
                .hash_member_sha256_v1(&material_name, MAX_SAFE_U64)
                .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
            expected_members.push(manifest_name);
            expected_members.push(material_name);
            if package.entry.state() != ProviderRecoveryStateV1::Published
                || package.entry.manifest_digest() != manifest_digest
                || package.entry.material_digest() != material_digest
                || package.entry.material_length() != material_length
            {
                return Err(PreparationRestoreErrorV1::PackageInvalid);
            }
        } else if !has_manifest && !has_material && has_retirement {
            let (retirement_digest, _) = custody
                .hash_member_sha256_v1(&retirement_name, MAX_SAFE_U64)
                .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;
            expected_members.push(retirement_name);
            if package.entry.state() != ProviderRecoveryStateV1::RetiredTombstone
                || package.entry.retirement_manifest_digest() != Some(retirement_digest)
            {
                return Err(PreparationRestoreErrorV1::PackageInvalid);
            }
        } else {
            return Err(PreparationRestoreErrorV1::PackageInvalid);
        }
        package.relative_directory = directory;
    }
    actual_members.sort();
    expected_members.sort();
    if actual_members != expected_members {
        return Err(PreparationRestoreErrorV1::PackageInvalid);
    }
    custody
        .revalidate_v1()
        .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
    Ok(packages)
}

#[cfg(not(test))]
fn restore_counts_match_v1(
    actual: schema::CoordinatorLifecycleCountsV1,
    expected: crate::manifest::VerifiedRestoreCoordinatorCountsV1,
) -> bool {
    actual.budget_scopes() == expected.budget_scopes()
        && actual.operations() == expected.operations()
        && actual.operation_transitions() == expected.operation_transitions()
        && actual.held_reservations() == expected.held_reservations()
        && actual.released_reservations() == expected.released_reservations()
        && actual.pending_events() == expected.pending_events()
        && actual.delivered_events() == expected.delivered_events()
        && actual.active_quarantines() == expected.active_quarantines()
        && actual.resolved_quarantines() == expected.resolved_quarantines()
}

/// Exact authenticated input to one durable begin-or-resume restore attempt.
///
/// The sovereign PAUSE authority persists this closed binding before returning rotated
/// authority. Repeating the exact input must return the same restore and destination-root
/// identities; a different input must contend or refuse rather than replacing the attempt.
#[cfg(not(test))]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RestoreAttemptInputV1 {
    attempt_binding_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    source_inventory_sha256: Sha256Digest,
    source_instance_identity_sha256: Sha256Digest,
    coordinator_destination_binding_sha256: Sha256Digest,
    recovery_destination_binding_sha256: Sha256Digest,
    source_generations: schema::CoordinatorLifecycleGenerationsV1,
}

#[cfg(not(test))]
impl RestoreAttemptInputV1 {
    fn from_verified_bindings_v1(
        bindings: &VerifiedRestorePackageBindingsV1,
        coordinator_destination_binding_sha256: Sha256Digest,
        recovery_destination_binding_sha256: Sha256Digest,
        source_generations: schema::CoordinatorLifecycleGenerationsV1,
    ) -> Self {
        Self {
            attempt_binding_sha256: derive_restore_attempt_binding_v1(
                [
                    bindings.attestation_sha256(),
                    bindings.top_level_manifest_sha256(),
                    bindings.inventory_sha256(),
                    bindings.source_coordinator_root_identity_sha256(),
                    bindings.source_recovery_root_identity_sha256(),
                    bindings.source_instance_identity_sha256(),
                    bindings.coordinator_schema_sha256(),
                    bindings.coordinator_database_sha256(),
                    coordinator_destination_binding_sha256,
                    recovery_destination_binding_sha256,
                ],
                bindings.at_rest_profile_id().as_str(),
            ),
            provenance_attestation_sha256: bindings.attestation_sha256(),
            source_inventory_sha256: bindings.inventory_sha256(),
            source_instance_identity_sha256: bindings.source_instance_identity_sha256(),
            coordinator_destination_binding_sha256,
            recovery_destination_binding_sha256,
            source_generations,
        }
    }

    pub(crate) const fn attempt_binding_sha256(&self) -> Sha256Digest {
        self.attempt_binding_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(&self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn source_instance_identity_sha256(&self) -> Sha256Digest {
        self.source_instance_identity_sha256
    }

    pub(crate) const fn source_inventory_sha256(&self) -> Sha256Digest {
        self.source_inventory_sha256
    }

    pub(crate) const fn coordinator_destination_binding_sha256(&self) -> Sha256Digest {
        self.coordinator_destination_binding_sha256
    }

    pub(crate) const fn recovery_destination_binding_sha256(&self) -> Sha256Digest {
        self.recovery_destination_binding_sha256
    }

    pub(crate) const fn source_generations(&self) -> schema::CoordinatorLifecycleGenerationsV1 {
        self.source_generations
    }
}

#[cfg(not(test))]
fn derive_restore_attempt_binding_v1(
    ordered_digests: [Sha256Digest; 10],
    at_rest_profile_id: &str,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(RESTORE_ATTEMPT_BINDING_DOMAIN_V1);
    for digest in ordered_digests {
        hasher.update(digest.as_bytes());
    }
    let profile = at_rest_profile_id.as_bytes();
    hasher.update(
        u64::try_from(profile.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(profile);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(not(test))]
impl fmt::Debug for RestoreAttemptInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoreAttemptInputV1")
            .finish_non_exhaustive()
    }
}

/// Sovereign PAUSE evidence binding both the source authority and fresh rotated epochs.
#[cfg(not(test))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PausedRotatedRestoreAuthorityV1 {
    attempt_binding_sha256: Sha256Digest,
    restore_identity_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    source_inventory_sha256: Sha256Digest,
    new_coordinator_root_identity: CoordinatorRootIdentityV1,
    new_recovery_root_identity_sha256: Sha256Digest,
    coordinator_destination_binding_sha256: Sha256Digest,
    recovery_destination_binding_sha256: Sha256Digest,
    supervisor_generation: u64,
    source_boot_identity_sha256: Sha256Digest,
    rotated_boot_identity_sha256: Sha256Digest,
    source_instance_identity_sha256: Sha256Digest,
    rotated_instance_identity_sha256: Sha256Digest,
    source_instance_epoch: u64,
    rotated_instance_epoch: u64,
    source_fencing_epoch: u64,
    rotated_fencing_epoch: u64,
    source_generations: schema::CoordinatorLifecycleGenerationsV1,
}

#[cfg(not(test))]
impl PausedRotatedRestoreAuthorityV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        attempt_binding_sha256: Sha256Digest,
        restore_identity_sha256: Sha256Digest,
        provenance_attestation_sha256: Sha256Digest,
        source_inventory_sha256: Sha256Digest,
        new_coordinator_root_identity: CoordinatorRootIdentityV1,
        new_recovery_root_identity_sha256: Sha256Digest,
        coordinator_destination_binding_sha256: Sha256Digest,
        recovery_destination_binding_sha256: Sha256Digest,
        supervisor_generation: u64,
        source_boot_identity_sha256: Sha256Digest,
        rotated_boot_identity_sha256: Sha256Digest,
        source_instance_identity_sha256: Sha256Digest,
        rotated_instance_identity_sha256: Sha256Digest,
        source_instance_epoch: u64,
        rotated_instance_epoch: u64,
        source_fencing_epoch: u64,
        rotated_fencing_epoch: u64,
        source_generations: schema::CoordinatorLifecycleGenerationsV1,
    ) -> Result<Self, PreparationRestoreErrorV1> {
        if [
            supervisor_generation,
            source_instance_epoch,
            rotated_instance_epoch,
            source_fencing_epoch,
            rotated_fencing_epoch,
        ]
        .into_iter()
        .any(|value| !(1..=MAX_SAFE_U64).contains(&value))
            || source_boot_identity_sha256 == rotated_boot_identity_sha256
            || source_instance_identity_sha256 == rotated_instance_identity_sha256
            || source_instance_epoch == rotated_instance_epoch
            || source_fencing_epoch == rotated_fencing_epoch
        {
            return Err(PreparationRestoreErrorV1::PauseUnhealthy);
        }
        Ok(Self {
            attempt_binding_sha256,
            restore_identity_sha256,
            provenance_attestation_sha256,
            source_inventory_sha256,
            new_coordinator_root_identity,
            new_recovery_root_identity_sha256,
            coordinator_destination_binding_sha256,
            recovery_destination_binding_sha256,
            supervisor_generation,
            source_boot_identity_sha256,
            rotated_boot_identity_sha256,
            source_instance_identity_sha256,
            rotated_instance_identity_sha256,
            source_instance_epoch,
            rotated_instance_epoch,
            source_fencing_epoch,
            rotated_fencing_epoch,
            source_generations,
        })
    }

    pub(crate) const fn source_instance_identity_sha256(self) -> Sha256Digest {
        self.source_instance_identity_sha256
    }

    pub(crate) const fn attempt_binding_sha256(self) -> Sha256Digest {
        self.attempt_binding_sha256
    }

    pub(crate) const fn restore_identity_sha256(self) -> Sha256Digest {
        self.restore_identity_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn source_inventory_sha256(self) -> Sha256Digest {
        self.source_inventory_sha256
    }

    pub(crate) const fn new_coordinator_root_identity(self) -> CoordinatorRootIdentityV1 {
        self.new_coordinator_root_identity
    }

    pub(crate) const fn new_recovery_root_identity_sha256(self) -> Sha256Digest {
        self.new_recovery_root_identity_sha256
    }

    pub(crate) const fn coordinator_destination_binding_sha256(self) -> Sha256Digest {
        self.coordinator_destination_binding_sha256
    }

    pub(crate) const fn recovery_destination_binding_sha256(self) -> Sha256Digest {
        self.recovery_destination_binding_sha256
    }

    pub(crate) const fn source_generations(self) -> schema::CoordinatorLifecycleGenerationsV1 {
        self.source_generations
    }

    /// Produces the only token accepted by restored-old-authority mutation paths.
    ///
    /// The token copies the exact old/new supervisor epochs from the still-held PAUSE
    /// custody. Callers therefore cannot supply rotated boot/instance/fencing values as
    /// independent fields or rebind an old operation to a newly selected authority.
    pub(crate) const fn old_authority_rotation_v1(self) -> RestoredAuthorityRotationV1 {
        RestoredAuthorityRotationV1 {
            source_boot_identity_sha256: self.source_boot_identity_sha256,
            rotated_boot_identity_sha256: self.rotated_boot_identity_sha256,
            source_instance_epoch: self.source_instance_epoch,
            rotated_instance_epoch: self.rotated_instance_epoch,
            source_fencing_epoch: self.source_fencing_epoch,
            rotated_fencing_epoch: self.rotated_fencing_epoch,
        }
    }
}

#[cfg(not(test))]
impl fmt::Debug for PausedRotatedRestoreAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PausedRotatedRestoreAuthorityV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
pub(crate) trait RestorePauseRotationCustodyV1: Send {
    fn capture_paused_rotated_authority_v1(
        &mut self,
    ) -> Result<PausedRotatedRestoreAuthorityV1, MaintenanceCustodyValidationV1>;

    fn recheck_paused_rotated_authority_v1(
        &mut self,
        expected: &PausedRotatedRestoreAuthorityV1,
    ) -> MaintenanceCustodyValidationV1;

    /// Releases PAUSE only after every coordinator and recovery-root custody is gone.
    ///
    /// While this custody is live, the sovereign implementation must serialize both
    /// provisioner-owned physical destination-binding namespaces in addition to the
    /// supervisor epochs. This is an exclusive namespace reservation, not merely a
    /// sampled equality check, and closes path/handle ABA across every SQLite open,
    /// mutation, publication and reopen boundary.
    fn release(self);
}

#[cfg(not(test))]
pub(crate) enum RestorePauseRotationOutcomeV1<G> {
    Acquired(G),
    Contended,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

#[cfg(not(test))]
pub(crate) trait RestorePauseRotationAuthorityV1 {
    type Custody: RestorePauseRotationCustodyV1;

    fn persist_pause_and_rotate_for_restore_v1(
        &self,
        attempt: &RestoreAttemptInputV1,
        deadline_monotonic_ms: u64,
    ) -> RestorePauseRotationOutcomeV1<Self::Custody>;

    /// Recovers only an already-persisted ticket by its two physical destination
    /// reservations. This grants quarantine/reconciliation authority, never a new restore.
    fn inspect_existing_restore_attempt_v1(
        &self,
        coordinator_destination_binding_sha256: Sha256Digest,
        recovery_destination_binding_sha256: Sha256Digest,
        deadline_monotonic_ms: u64,
    ) -> RestorePauseRotationOutcomeV1<Self::Custody>;
}

#[cfg(not(test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryRestoreProviderErrorV1 {
    Unavailable,
    Invalid,
}

/// Common immutable bindings supplied before a recovery root is reserved.
#[cfg(not(test))]
pub(crate) struct RecoveryRestoreReservationV1 {
    restore_identity_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    source_inventory_sha256: Sha256Digest,
    new_coordinator_root_identity_sha256: Sha256Digest,
    new_recovery_root_identity_sha256: Sha256Digest,
    recovery_destination_binding_sha256: Sha256Digest,
    at_rest_profile_id: Identifier,
}

#[cfg(not(test))]
impl RecoveryRestoreReservationV1 {
    pub(crate) const fn restore_identity_sha256(&self) -> Sha256Digest {
        self.restore_identity_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(&self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn source_inventory_sha256(&self) -> Sha256Digest {
        self.source_inventory_sha256
    }

    pub(crate) const fn new_coordinator_root_identity_sha256(&self) -> Sha256Digest {
        self.new_coordinator_root_identity_sha256
    }

    pub(crate) const fn new_recovery_root_identity_sha256(&self) -> Sha256Digest {
        self.new_recovery_root_identity_sha256
    }

    pub(crate) const fn recovery_destination_binding_sha256(&self) -> Sha256Digest {
        self.recovery_destination_binding_sha256
    }

    pub(crate) const fn at_rest_profile_id(&self) -> &Identifier {
        &self.at_rest_profile_id
    }
}

#[cfg(not(test))]
impl fmt::Debug for RecoveryRestoreReservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestoreReservationV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveryRestoreRootSourceV1 {
    root_identity_sha256: Sha256Digest,
    provider_generation: u64,
}

#[cfg(not(test))]
impl RecoveryRestoreRootSourceV1 {
    pub(crate) fn try_new(
        root_identity_sha256: Sha256Digest,
        provider_generation: u64,
    ) -> Result<Self, RecoveryRestoreProviderErrorV1> {
        if !(1..=MAX_SAFE_U64).contains(&provider_generation) {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        Ok(Self {
            root_identity_sha256,
            provider_generation,
        })
    }

    pub(crate) const fn root_identity_sha256(self) -> Sha256Digest {
        self.root_identity_sha256
    }

    pub(crate) const fn provider_generation(self) -> u64 {
        self.provider_generation
    }
}

#[cfg(not(test))]
impl fmt::Debug for RecoveryRestoreRootSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestoreRootSourceV1")
            .finish_non_exhaustive()
    }
}

/// Exact ticket and provisioner reservation used to reacquire recovery-root custody.
#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct RecoveryRestoreInspectionExpectationV1 {
    restore_identity_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    source_inventory_sha256: Sha256Digest,
    coordinator_root_identity_sha256: Sha256Digest,
    recovery_root_identity_sha256: Sha256Digest,
    coordinator_destination_binding_sha256: Sha256Digest,
    recovery_destination_binding_sha256: Sha256Digest,
    at_rest_profile_id: Identifier,
}

#[cfg(not(test))]
impl RecoveryRestoreInspectionExpectationV1 {
    pub(crate) const fn restore_identity_sha256(&self) -> Sha256Digest {
        self.restore_identity_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(&self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn source_inventory_sha256(&self) -> Sha256Digest {
        self.source_inventory_sha256
    }

    pub(crate) const fn coordinator_root_identity_sha256(&self) -> Sha256Digest {
        self.coordinator_root_identity_sha256
    }

    pub(crate) const fn recovery_root_identity_sha256(&self) -> Sha256Digest {
        self.recovery_root_identity_sha256
    }

    pub(crate) const fn coordinator_destination_binding_sha256(&self) -> Sha256Digest {
        self.coordinator_destination_binding_sha256
    }

    pub(crate) const fn recovery_destination_binding_sha256(&self) -> Sha256Digest {
        self.recovery_destination_binding_sha256
    }

    pub(crate) const fn at_rest_profile_id(&self) -> &Identifier {
        &self.at_rest_profile_id
    }
}

#[cfg(not(test))]
impl fmt::Debug for RecoveryRestoreInspectionExpectationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestoreInspectionExpectationV1")
            .finish_non_exhaustive()
    }
}

/// Stable recovery-root observation captured and rechecked under provider custody.
#[cfg(not(test))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveryRestoreInspectionStateV1 {
    destination_started: bool,
    state_generation: u64,
    private_state_binding_sha256: Sha256Digest,
}

#[cfg(not(test))]
impl RecoveryRestoreInspectionStateV1 {
    pub(crate) fn try_new(
        destination_started: bool,
        state_generation: u64,
        private_state_binding_sha256: Sha256Digest,
    ) -> Result<Self, RecoveryRestoreProviderErrorV1> {
        if (!destination_started && state_generation != 0) || state_generation > MAX_SAFE_U64 {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        Ok(Self {
            destination_started,
            state_generation,
            private_state_binding_sha256,
        })
    }

    pub(crate) const fn destination_started(self) -> bool {
        self.destination_started
    }

    pub(crate) const fn state_generation(self) -> u64 {
        self.state_generation
    }
}

#[cfg(not(test))]
impl fmt::Debug for RecoveryRestoreInspectionStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestoreInspectionStateV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct RecoveryRestorePendingExpectationV1 {
    root_identity_sha256: Sha256Digest,
    coordinator_root_identity_sha256: Sha256Digest,
    restore_identity_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    source_inventory_sha256: Sha256Digest,
    recovery_destination_binding_sha256: Sha256Digest,
    at_rest_profile_id: Identifier,
    state_generation: u64,
}

#[cfg(not(test))]
impl RecoveryRestorePendingExpectationV1 {
    pub(crate) const fn root_identity_sha256(&self) -> Sha256Digest {
        self.root_identity_sha256
    }

    pub(crate) const fn coordinator_root_identity_sha256(&self) -> Sha256Digest {
        self.coordinator_root_identity_sha256
    }

    pub(crate) const fn restore_identity_sha256(&self) -> Sha256Digest {
        self.restore_identity_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(&self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn source_inventory_sha256(&self) -> Sha256Digest {
        self.source_inventory_sha256
    }

    pub(crate) const fn recovery_destination_binding_sha256(&self) -> Sha256Digest {
        self.recovery_destination_binding_sha256
    }

    pub(crate) const fn at_rest_profile_id(&self) -> &Identifier {
        &self.at_rest_profile_id
    }

    pub(crate) const fn state_generation(&self) -> u64 {
        self.state_generation
    }
}

#[cfg(not(test))]
impl fmt::Debug for RecoveryRestorePendingExpectationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestorePendingExpectationV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
pub(crate) struct ProviderRestorePackageSourceV1<'package> {
    custody: &'package mut RestorePackageCustodyV1,
    package: &'package AcceptedProviderRestorePackageV1,
    manifest_read: bool,
    material_read: bool,
    retirement_read: bool,
}

#[cfg(not(test))]
impl ProviderRestorePackageSourceV1<'_> {
    pub(crate) const fn entry(&self) -> &ProviderRecoveryInventoryEntryV1 {
        &self.package.entry
    }

    pub(crate) const fn package_binding_sha256(&self) -> Sha256Digest {
        self.package.package_binding_sha256
    }

    pub(crate) fn read_manifest_v1(
        &mut self,
        maximum_length: u64,
    ) -> Result<Vec<u8>, RecoveryRestoreProviderErrorV1> {
        if self.package.entry.state() != ProviderRecoveryStateV1::Published {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        let member = format!("{}/manifest.json", self.package.relative_directory);
        let bytes = self
            .custody
            .read_member_v1(&member, maximum_length)
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        if Sha256Digest::digest(&bytes) != self.package.entry.manifest_digest() {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        self.manifest_read = true;
        Ok(bytes)
    }

    pub(crate) fn read_material_v1(
        &mut self,
        maximum_length: u64,
    ) -> Result<Vec<u8>, RecoveryRestoreProviderErrorV1> {
        if self.package.entry.state() != ProviderRecoveryStateV1::Published
            || self.package.entry.material_length() > maximum_length
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        let member = format!("{}/material.bin", self.package.relative_directory);
        let bytes = self
            .custody
            .read_member_v1(&member, maximum_length)
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        if u64::try_from(bytes.len()).ok() != Some(self.package.entry.material_length())
            || Sha256Digest::digest(&bytes) != self.package.entry.material_digest()
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        self.material_read = true;
        Ok(bytes)
    }

    pub(crate) fn read_retirement_manifest_v1(
        &mut self,
        maximum_length: u64,
    ) -> Result<Vec<u8>, RecoveryRestoreProviderErrorV1> {
        if self.package.entry.state() != ProviderRecoveryStateV1::RetiredTombstone {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        let member = format!(
            "{}/retirement-manifest.json",
            self.package.relative_directory
        );
        let bytes = self
            .custody
            .read_member_v1(&member, maximum_length)
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        if self.package.entry.retirement_manifest_digest() != Some(Sha256Digest::digest(&bytes)) {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        self.retirement_read = true;
        Ok(bytes)
    }

    fn finish_v1(&self) -> Result<(), PreparationRestoreErrorV1> {
        let complete = match self.package.entry.state() {
            ProviderRecoveryStateV1::Published => self.manifest_read && self.material_read,
            ProviderRecoveryStateV1::RetiredTombstone => self.retirement_read,
        };
        complete
            .then_some(())
            .ok_or(PreparationRestoreErrorV1::RecoveryImportInvalid)
    }
}

#[cfg(not(test))]
impl fmt::Debug for ProviderRestorePackageSourceV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRestorePackageSourceV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
pub(crate) trait RecoveryRestoreImportCustodyV1: RecoveryCleanupGuardV1 {
    fn capture_restore_root_source_v1(
        &mut self,
    ) -> Result<RecoveryRestoreRootSourceV1, RecoveryRestoreProviderErrorV1>;

    fn recheck_restore_root_source_v1(
        &mut self,
        expected: &RecoveryRestoreRootSourceV1,
    ) -> MaintenanceCustodyValidationV1;

    fn publish_restore_pending_metadata_v1(
        &mut self,
        canonical_metadata: &[u8],
    ) -> Result<(), RecoveryRestoreProviderErrorV1>;

    fn enumerate_imported_recovery_inventory_v1(
        &mut self,
    ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, RecoveryRestoreProviderErrorV1>;
}

#[cfg(not(test))]
pub(crate) trait RecoveryRestorePendingCustodyV1: RecoveryCleanupGuardV1 {
    fn read_restore_pending_metadata_v1(
        &mut self,
        maximum_length: u64,
    ) -> Result<Vec<u8>, RecoveryRestoreProviderErrorV1>;

    fn enumerate_pending_recovery_inventory_v1(
        &mut self,
    ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, RecoveryRestoreProviderErrorV1>;
}

#[cfg(not(test))]
pub(crate) trait RecoveryRestoreInspectionCustodyV1: RecoveryCleanupGuardV1 {
    fn capture_existing_restore_state_v1(
        &mut self,
    ) -> Result<RecoveryRestoreInspectionStateV1, RecoveryRestoreProviderErrorV1>;

    fn recheck_existing_restore_state_v1(
        &mut self,
        expected: &RecoveryRestoreInspectionStateV1,
    ) -> MaintenanceCustodyValidationV1;
}

#[cfg(not(test))]
pub(crate) enum RecoveryRestoreCustodyOutcomeV1<G> {
    Acquired(G),
    Contended,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

#[cfg(not(test))]
pub(crate) trait RecoveryRestoreProviderV1 {
    type ImportCustody: RecoveryRestoreImportCustodyV1;
    type PendingCustody: RecoveryRestorePendingCustodyV1;
    type InspectionCustody: RecoveryRestoreInspectionCustodyV1;

    /// Opaque provisioner-owned binding for the physical destination reservation. It must
    /// remain stable across an exact retry and differ for any other root.
    fn provisioned_restore_destination_binding_sha256_v1(
        &self,
    ) -> Result<Sha256Digest, RecoveryRestoreProviderErrorV1>;

    /// Reacquires only an existing physical reservation under exact ticket/root custody.
    /// This operation must not create, repair, import, publish, or activate root state.
    fn inspect_existing_restore_root_v1(
        &self,
        expected: &RecoveryRestoreInspectionExpectationV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryRestoreCustodyOutcomeV1<Self::InspectionCustody>;

    /// Durably begins or resumes the exact reservation. Repeating the same bindings is
    /// idempotent; a different attempt must contend or refuse without replacing state.
    fn begin_or_resume_restore_root_v1(
        &self,
        reservation: &RecoveryRestoreReservationV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryRestoreCustodyOutcomeV1<Self::ImportCustody>;

    fn import_recovery_backup_package_v1(
        &self,
        custody: &mut Self::ImportCustody,
        source: &mut ProviderRestorePackageSourceV1<'_>,
    ) -> Result<(), RecoveryRestoreProviderErrorV1>;

    fn reopen_restore_pending_root_v1(
        &self,
        expected: &RecoveryRestorePendingExpectationV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryRestoreCustodyOutcomeV1<Self::PendingCustody>;
}

#[cfg(not(test))]
pub(crate) struct RestoreQuarantineEvidenceV1 {
    restore_identity_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    source_inventory_sha256: Sha256Digest,
    new_coordinator_root_identity_sha256: Sha256Digest,
    new_recovery_root_identity_sha256: Sha256Digest,
    coordinator_destination_binding_sha256: Sha256Digest,
    recovery_destination_binding_sha256: Sha256Digest,
    recovery_state_generation: u64,
    coordinator_destination_started: bool,
    recovery_destination_started: bool,
}

#[cfg(not(test))]
impl RestoreQuarantineEvidenceV1 {
    pub(crate) const fn restore_identity_sha256(&self) -> Sha256Digest {
        self.restore_identity_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(&self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn source_inventory_sha256(&self) -> Sha256Digest {
        self.source_inventory_sha256
    }

    pub(crate) const fn new_coordinator_root_identity_sha256(&self) -> Sha256Digest {
        self.new_coordinator_root_identity_sha256
    }

    pub(crate) const fn new_recovery_root_identity_sha256(&self) -> Sha256Digest {
        self.new_recovery_root_identity_sha256
    }

    pub(crate) const fn coordinator_destination_binding_sha256(&self) -> Sha256Digest {
        self.coordinator_destination_binding_sha256
    }

    pub(crate) const fn recovery_destination_binding_sha256(&self) -> Sha256Digest {
        self.recovery_destination_binding_sha256
    }

    pub(crate) const fn recovery_state_generation(&self) -> u64 {
        self.recovery_state_generation
    }

    pub(crate) const fn coordinator_destination_started(&self) -> bool {
        self.coordinator_destination_started
    }

    pub(crate) const fn recovery_destination_started(&self) -> bool {
        self.recovery_destination_started
    }
}

#[cfg(not(test))]
impl fmt::Debug for RestoreQuarantineEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoreQuarantineEvidenceV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
pub(crate) trait RestoreQuarantineAuthorityV1 {
    fn persist_restore_package_quarantine_v1(
        &self,
        evidence: &RestorePackageQuarantineEvidenceV1,
        deadline_monotonic_ms: u64,
    ) -> Result<(), PreparationRestoreErrorV1>;

    fn persist_restore_quarantine_v1(
        &self,
        evidence: &RestoreQuarantineEvidenceV1,
        deadline_monotonic_ms: u64,
    ) -> Result<(), PreparationRestoreErrorV1>;
}

/// Redacted, non-authoritative evidence that both roots remain exactly pending.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPreparationRestoreV1 {
    store_generation: u64,
    operation_generation: u64,
    budget_generation: u64,
    event_generation: u64,
    quarantine_generation: u64,
    budget_scope_count: u64,
    operation_count: u64,
    operation_transition_count: u64,
    held_reservation_count: u64,
    released_reservation_count: u64,
    pending_event_count: u64,
    delivered_event_count: u64,
    active_quarantine_count: u64,
    resolved_quarantine_count: u64,
    provider_set_count: u64,
    entry_count: u64,
}

impl VerifiedPreparationRestoreV1 {
    #[cfg(not(test))]
    fn from_verified_pending_v1(
        generations: schema::CoordinatorLifecycleGenerationsV1,
        counts: schema::CoordinatorLifecycleCountsV1,
        provider_set_count: u64,
        entry_count: u64,
    ) -> Self {
        Self {
            store_generation: generations.store(),
            operation_generation: generations.operation(),
            budget_generation: generations.budget(),
            event_generation: generations.event(),
            quarantine_generation: generations.quarantine(),
            budget_scope_count: counts.budget_scopes(),
            operation_count: counts.operations(),
            operation_transition_count: counts.operation_transitions(),
            held_reservation_count: counts.held_reservations(),
            released_reservation_count: counts.released_reservations(),
            pending_event_count: counts.pending_events(),
            delivered_event_count: counts.delivered_events(),
            active_quarantine_count: counts.active_quarantines(),
            resolved_quarantine_count: counts.resolved_quarantines(),
            provider_set_count,
            entry_count,
        }
    }

    pub const fn provider_set_count(&self) -> u64 {
        self.provider_set_count
    }

    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub const fn store_generation(&self) -> u64 {
        self.store_generation
    }

    pub const fn operation_generation(&self) -> u64 {
        self.operation_generation
    }

    pub const fn budget_generation(&self) -> u64 {
        self.budget_generation
    }

    pub const fn event_generation(&self) -> u64 {
        self.event_generation
    }

    pub const fn quarantine_generation(&self) -> u64 {
        self.quarantine_generation
    }

    pub const fn budget_scope_count(&self) -> u64 {
        self.budget_scope_count
    }

    pub const fn operation_count(&self) -> u64 {
        self.operation_count
    }

    pub const fn operation_transition_count(&self) -> u64 {
        self.operation_transition_count
    }

    pub const fn held_reservation_count(&self) -> u64 {
        self.held_reservation_count
    }

    pub const fn released_reservation_count(&self) -> u64 {
        self.released_reservation_count
    }

    pub const fn pending_event_count(&self) -> u64 {
        self.pending_event_count
    }

    pub const fn delivered_event_count(&self) -> u64 {
        self.delivered_event_count
    }

    pub const fn active_quarantine_count(&self) -> u64 {
        self.active_quarantine_count
    }

    pub const fn resolved_quarantine_count(&self) -> u64 {
        self.resolved_quarantine_count
    }

    /// Fixed non-authoritative lifecycle requirement, never activation authority.
    pub const fn root_lifecycle_code(&self) -> &'static str {
        "RESTORE_PENDING"
    }

    pub const fn requires_paused_restore(&self) -> bool {
        true
    }

    pub const fn requires_boot_epoch_rotation(&self) -> bool {
        true
    }

    pub const fn requires_instance_epoch_rotation(&self) -> bool {
        true
    }

    pub const fn requires_fencing_epoch_rotation(&self) -> bool {
        true
    }

    pub const fn nonterminal_preparations_reactivatable(&self) -> bool {
        false
    }
}

impl fmt::Debug for VerifiedPreparationRestoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPreparationRestoreV1")
            .field("provider_set_count", &self.provider_set_count)
            .field("entry_count", &self.entry_count)
            .finish_non_exhaustive()
    }
}

const MAX_RESTORE_MAINTENANCE_OPERATIONS_V1: u64 = 4_096;
const MAX_RESTORE_MAINTENANCE_WAIT_MS_V1: u64 = 60_000;
const RESTORED_OPERATION_QUARANTINE_BINDING_DOMAIN_V1: &[u8] =
    b"HELIXOS\0RESTORED-OPERATION-QUARANTINE-BINDING\0V1\0";

/// Checked bounds for one restore-validation or old-authority reconciliation call.
///
/// The values are caller-owned limits, not persisted authority. They cannot select an
/// activation transition and are capped independently of the absolute deadline.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestoreMaintenanceLimitsV1 {
    maximum_operations: u64,
    maximum_root_wait_ms: u64,
    maximum_busy_wait_ms: u64,
}

impl RestoreMaintenanceLimitsV1 {
    pub fn try_new(
        maximum_operations: u64,
        maximum_root_wait_ms: u64,
        maximum_busy_wait_ms: u64,
    ) -> Result<Self, RestoreMaintenanceLimitErrorV1> {
        if !(1..=MAX_RESTORE_MAINTENANCE_OPERATIONS_V1).contains(&maximum_operations)
            || !(1..=MAX_RESTORE_MAINTENANCE_WAIT_MS_V1).contains(&maximum_root_wait_ms)
            || !(1..=MAX_RESTORE_MAINTENANCE_WAIT_MS_V1).contains(&maximum_busy_wait_ms)
        {
            return Err(RestoreMaintenanceLimitErrorV1::OutOfRange);
        }
        Ok(Self {
            maximum_operations,
            maximum_root_wait_ms,
            maximum_busy_wait_ms,
        })
    }

    pub const fn maximum_operations(self) -> u64 {
        self.maximum_operations
    }
}

impl fmt::Debug for RestoreMaintenanceLimitsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoreMaintenanceLimitsV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreMaintenanceLimitErrorV1 {
    OutOfRange,
}

impl RestoreMaintenanceLimitErrorV1 {
    pub const fn code(self) -> &'static str {
        "RESTORE_MAINTENANCE_LIMIT_OUT_OF_RANGE"
    }
}

impl fmt::Debug for RestoreMaintenanceLimitErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for RestoreMaintenanceLimitErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RestoreMaintenanceLimitErrorV1 {}

/// Stable payload-free refusal from pending-root maintenance.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreMaintenanceErrorV1 {
    DeadlineReached,
    WorkLimitExceeded,
    PauseContended,
    PauseUnavailable,
    PauseUnsupported,
    PauseUnhealthy,
    CoordinatorUnavailable,
    CoordinatorUnhealthy,
    RecoveryUnavailable,
    RecoveryUnhealthy,
    ReconciliationConflict,
}

impl RestoreMaintenanceErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DeadlineReached => "RESTORE_MAINTENANCE_DEADLINE_REACHED",
            Self::WorkLimitExceeded => "RESTORE_MAINTENANCE_WORK_LIMIT_EXCEEDED",
            Self::PauseContended => "RESTORE_MAINTENANCE_PAUSE_CONTENDED",
            Self::PauseUnavailable => "RESTORE_MAINTENANCE_PAUSE_UNAVAILABLE",
            Self::PauseUnsupported => "RESTORE_MAINTENANCE_PAUSE_UNSUPPORTED",
            Self::PauseUnhealthy => "RESTORE_MAINTENANCE_PAUSE_UNHEALTHY",
            Self::CoordinatorUnavailable => "RESTORE_MAINTENANCE_COORDINATOR_UNAVAILABLE",
            Self::CoordinatorUnhealthy => "RESTORE_MAINTENANCE_COORDINATOR_UNHEALTHY",
            Self::RecoveryUnavailable => "RESTORE_MAINTENANCE_RECOVERY_UNAVAILABLE",
            Self::RecoveryUnhealthy => "RESTORE_MAINTENANCE_RECOVERY_UNHEALTHY",
            Self::ReconciliationConflict => "RESTORE_MAINTENANCE_RECONCILIATION_CONFLICT",
        }
    }
}

impl fmt::Debug for RestoreMaintenanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for RestoreMaintenanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RestoreMaintenanceErrorV1 {}

/// Redacted result of one bounded reconciliation pass.
///
/// Every returned field is a safe count or the separately redacted pending-root
/// verification projection. This type contains no root path, identifier, nonce, digest,
/// budget vector, provider diagnostic, guard or activation capability.
pub struct RestoredPreparationMaintenanceEvidenceV1 {
    verification: VerifiedPreparationRestoreV1,
    inspected_count: u64,
    failed_count: u64,
    already_failed_count: u64,
    quarantine_retained_count: u64,
}

impl RestoredPreparationMaintenanceEvidenceV1 {
    pub const fn verification(&self) -> &VerifiedPreparationRestoreV1 {
        &self.verification
    }

    pub const fn inspected_count(&self) -> u64 {
        self.inspected_count
    }

    pub const fn failed_count(&self) -> u64 {
        self.failed_count
    }

    pub const fn already_failed_count(&self) -> u64 {
        self.already_failed_count
    }

    pub const fn quarantine_retained_count(&self) -> u64 {
        self.quarantine_retained_count
    }

    pub const fn remaining_unresolved_count(&self) -> u64 {
        0
    }

    pub const fn activation_authority_present(&self) -> bool {
        false
    }
}

impl fmt::Debug for RestoredPreparationMaintenanceEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoredPreparationMaintenanceEvidenceV1")
            .field("inspected_count", &self.inspected_count)
            .field("failed_count", &self.failed_count)
            .field("already_failed_count", &self.already_failed_count)
            .field("quarantine_retained_count", &self.quarantine_retained_count)
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
pub(crate) enum RestoredNoDispatchGuardAcquisitionV1<G> {
    Acquired(G),
    Missing,
    Mismatched,
    Revoked,
    DeadlineReached,
    Unavailable,
    Ambiguous,
    Unsupported,
}

/// Sovereign acquisition boundary for historical no-dispatch custody.
///
/// Implementations receive the exact redacted binding while the caller still retains
/// PAUSE and both physical root namespaces. `Acquired` must return a guard that can only
/// validate the same old authority; this trait has no dispatch, activation or epoch-
/// rotation method.
#[cfg(not(test))]
pub(crate) trait RestoredNoDispatchGuardAuthorityV1 {
    type Guard: RestoredNoDispatchAuthorityGuardV1;

    fn acquire_restored_no_dispatch_guard_v1(
        &self,
        expected: &RestoredOldAuthorityBindingV1<'_>,
        rotation: RestoredAuthorityRotationV1,
        deadline_monotonic_ms: u64,
    ) -> RestoredNoDispatchGuardAcquisitionV1<Self::Guard>;
}

#[cfg(not(test))]
struct RestoredPreparationCandidateV1 {
    operation_id: String,
    attempt_id: Sha256Digest,
    preparing_state_generation: u64,
    boot_id: String,
    instance_epoch: u64,
    fencing_epoch: u64,
    restored_source_generation: u64,
    has_active_quarantine: bool,
}

#[cfg(not(test))]
impl fmt::Debug for RestoredPreparationCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoredPreparationCandidateV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
fn derive_restore_identity_v1(
    provenance_attestation_sha256: Sha256Digest,
    restricted_attempt_nonce: &[u8; 32],
) -> Sha256Digest {
    let mut preimage = Vec::with_capacity(RESTORE_IDENTITY_DOMAIN_V1.len() + 64);
    preimage.extend_from_slice(RESTORE_IDENTITY_DOMAIN_V1);
    preimage.extend_from_slice(provenance_attestation_sha256.as_bytes());
    preimage.extend_from_slice(restricted_attempt_nonce);
    Sha256Digest::digest(&preimage)
}

#[cfg(not(test))]
fn recheck_restore_pause_v1<G: RestorePauseRotationCustodyV1>(
    custody: &mut G,
    expected: &PausedRotatedRestoreAuthorityV1,
) -> Result<(), PreparationRestoreErrorV1> {
    match custody.recheck_paused_rotated_authority_v1(expected) {
        MaintenanceCustodyValidationV1::Exact => Ok(()),
        MaintenanceCustodyValidationV1::Revoked => Err(PreparationRestoreErrorV1::SourceChanged),
        MaintenanceCustodyValidationV1::Unavailable => {
            Err(PreparationRestoreErrorV1::PauseUnavailable)
        }
        MaintenanceCustodyValidationV1::Unhealthy => Err(PreparationRestoreErrorV1::PauseUnhealthy),
    }
}

#[cfg(not(test))]
fn recheck_recovery_restore_root_v1<G: RecoveryRestoreImportCustodyV1>(
    custody: &mut G,
    expected: &RecoveryRestoreRootSourceV1,
) -> Result<(), PreparationRestoreErrorV1> {
    match custody.recheck_restore_root_source_v1(expected) {
        MaintenanceCustodyValidationV1::Exact => Ok(()),
        MaintenanceCustodyValidationV1::Revoked => Err(PreparationRestoreErrorV1::SourceChanged),
        MaintenanceCustodyValidationV1::Unavailable => {
            Err(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)
        }
        MaintenanceCustodyValidationV1::Unhealthy => {
            Err(PreparationRestoreErrorV1::RecoveryImportInvalid)
        }
    }
}

#[cfg(not(test))]
fn recheck_recovery_restore_inspection_v1<G: RecoveryRestoreInspectionCustodyV1>(
    custody: &mut G,
    expected: &RecoveryRestoreInspectionStateV1,
) -> Result<(), PreparationRestoreErrorV1> {
    match custody.recheck_existing_restore_state_v1(expected) {
        MaintenanceCustodyValidationV1::Exact => Ok(()),
        MaintenanceCustodyValidationV1::Revoked => Err(PreparationRestoreErrorV1::SourceChanged),
        MaintenanceCustodyValidationV1::Unavailable => {
            Err(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)
        }
        MaintenanceCustodyValidationV1::Unhealthy => {
            Err(PreparationRestoreErrorV1::RecoveryImportInvalid)
        }
    }
}

/// Reconciles every bounded historical preparation while both roots remain pending.
///
/// This orchestration acquires PAUSE first, then retains the coordinator root lease and
/// recovery cleanup custody through every SQLite mutation. The PAUSE token supplies the
/// sole typed rotation proof accepted by T073. Negative no-dispatch acquisition is
/// durably quarantined; exact acquisition may call only the guarded `PREPARING -> FAILED`
/// transaction. No branch writes `ACTIVE`, creates dispatch state or returns authority.
#[cfg(not(test))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_restored_old_authority_v1<A, P, G, K, C>(
    coordinator_root: &ProvisionedEmptyCoordinatorRootV1,
    pause_authority: &A,
    recovery_provider: &P,
    guard_authority: &G,
    historical_plan_keys: &K,
    limits: RestoreMaintenanceLimitsV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<RestoredPreparationMaintenanceEvidenceV1, RestoreMaintenanceErrorV1>
where
    A: RestorePauseRotationAuthorityV1,
    P: RecoveryRestoreProviderV1,
    G: RestoredNoDispatchGuardAuthorityV1,
    K: Ed25519KeyResolver,
    C: CoordinatorMonotonicClockV1 + ?Sized,
{
    remaining_monotonic_ms(clock, deadline_monotonic_ms)
        .map_err(|_| RestoreMaintenanceErrorV1::DeadlineReached)?;
    let coordinator_destination_binding_sha256 = coordinator_root
        .restore_reservation_binding_sha256_v1()
        .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
    let recovery_destination_binding_sha256 = recovery_provider
        .provisioned_restore_destination_binding_sha256_v1()
        .map_err(|_| RestoreMaintenanceErrorV1::RecoveryUnavailable)?;
    let mut pause_custody = match pause_authority.inspect_existing_restore_attempt_v1(
        coordinator_destination_binding_sha256,
        recovery_destination_binding_sha256,
        deadline_monotonic_ms,
    ) {
        RestorePauseRotationOutcomeV1::Acquired(custody) => custody,
        RestorePauseRotationOutcomeV1::Contended => {
            return Err(RestoreMaintenanceErrorV1::PauseContended)
        }
        RestorePauseRotationOutcomeV1::Unavailable => {
            return Err(RestoreMaintenanceErrorV1::PauseUnavailable)
        }
        RestorePauseRotationOutcomeV1::DeadlineReached => {
            return Err(RestoreMaintenanceErrorV1::DeadlineReached)
        }
        RestorePauseRotationOutcomeV1::Unsupported => {
            return Err(RestoreMaintenanceErrorV1::PauseUnsupported)
        }
    };

    let result = (|| {
        let paused = pause_custody
            .capture_paused_rotated_authority_v1()
            .map_err(|_| RestoreMaintenanceErrorV1::PauseUnhealthy)?;
        if paused.coordinator_destination_binding_sha256() != coordinator_destination_binding_sha256
            || paused.recovery_destination_binding_sha256() != recovery_destination_binding_sha256
        {
            return Err(RestoreMaintenanceErrorV1::PauseUnhealthy);
        }
        let new_coordinator_root_identity = paused.new_coordinator_root_identity();
        let new_coordinator_root_identity_sha256 =
            coordinator_root_identity_digest_v1(new_coordinator_root_identity.as_bytes());
        let at_rest_profile_id = coordinator_root
            .restore_at_rest_profile_id_v1()
            .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnavailable)?
            .clone();
        let pending_bindings = schema::RestorePendingBindingsV1::try_new(
            paused.source_generations(),
            new_coordinator_root_identity,
            paused.restore_identity_sha256(),
            paused.provenance_attestation_sha256(),
            paused.source_generations().store(),
        )
        .map_err(|_| RestoreMaintenanceErrorV1::PauseUnhealthy)?;

        // The inspection read discovers the provider-owned state generation without
        // creating or repairing recovery state. PAUSE retains both physical destination
        // namespaces across the inspection-to-pending-custody handoff.
        let inspection_expected = RecoveryRestoreInspectionExpectationV1 {
            restore_identity_sha256: paused.restore_identity_sha256(),
            provenance_attestation_sha256: paused.provenance_attestation_sha256(),
            source_inventory_sha256: paused.source_inventory_sha256(),
            coordinator_root_identity_sha256: new_coordinator_root_identity_sha256,
            recovery_root_identity_sha256: paused.new_recovery_root_identity_sha256(),
            coordinator_destination_binding_sha256,
            recovery_destination_binding_sha256,
            at_rest_profile_id: at_rest_profile_id.clone(),
        };
        let mut inspection_custody = match recovery_provider
            .inspect_existing_restore_root_v1(&inspection_expected, deadline_monotonic_ms)
        {
            RecoveryRestoreCustodyOutcomeV1::Acquired(custody) => custody,
            RecoveryRestoreCustodyOutcomeV1::Contended
            | RecoveryRestoreCustodyOutcomeV1::Unavailable
            | RecoveryRestoreCustodyOutcomeV1::DeadlineReached
            | RecoveryRestoreCustodyOutcomeV1::Unsupported => {
                return Err(RestoreMaintenanceErrorV1::RecoveryUnavailable)
            }
        };
        let inspected_recovery = inspection_custody
            .capture_existing_restore_state_v1()
            .map_err(|_| RestoreMaintenanceErrorV1::RecoveryUnhealthy)?;
        if !inspected_recovery.destination_started() {
            return Err(RestoreMaintenanceErrorV1::RecoveryUnhealthy);
        }
        recheck_recovery_restore_inspection_v1(&mut inspection_custody, &inspected_recovery)
            .map_err(map_restore_maintenance_recheck_error_v1)?;
        recheck_restore_pause_v1(&mut pause_custody, &paused)
            .map_err(map_restore_maintenance_recheck_error_v1)?;
        inspection_custody.release();

        let mut coordinator_custody = reopen_restore_pending_root_custody_v1(
            coordinator_root,
            new_coordinator_root_identity,
            limits.maximum_root_wait_ms,
            clock,
            deadline_monotonic_ms,
        )
        .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
        let recovery_expected = RecoveryRestorePendingExpectationV1 {
            root_identity_sha256: paused.new_recovery_root_identity_sha256(),
            coordinator_root_identity_sha256: new_coordinator_root_identity_sha256,
            restore_identity_sha256: paused.restore_identity_sha256(),
            provenance_attestation_sha256: paused.provenance_attestation_sha256(),
            source_inventory_sha256: paused.source_inventory_sha256(),
            recovery_destination_binding_sha256,
            at_rest_profile_id,
            state_generation: inspected_recovery.state_generation(),
        };
        let mut recovery_custody = match recovery_provider
            .reopen_restore_pending_root_v1(&recovery_expected, deadline_monotonic_ms)
        {
            RecoveryRestoreCustodyOutcomeV1::Acquired(custody) => custody,
            RecoveryRestoreCustodyOutcomeV1::Contended
            | RecoveryRestoreCustodyOutcomeV1::Unavailable
            | RecoveryRestoreCustodyOutcomeV1::DeadlineReached
            | RecoveryRestoreCustodyOutcomeV1::Unsupported => {
                return Err(RestoreMaintenanceErrorV1::RecoveryUnavailable)
            }
        };
        verify_recovery_pending_metadata_for_maintenance_v1(
            &mut recovery_custody,
            &recovery_expected,
        )?;
        recheck_restore_pause_v1(&mut pause_custody, &paused)
            .map_err(map_restore_maintenance_recheck_error_v1)?;

        let database_path = coordinator_custody
            .database_path_v1()
            .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
        let mut connection = Connection::open_with_flags(
            database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
        configure_deadline_bounded_busy_timeout_v1(
            &connection,
            limits.maximum_busy_wait_ms,
            clock,
            deadline_monotonic_ms,
        )
        .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
        let initial =
            schema::verify_restore_pending_v1(&connection, pending_bindings, historical_plan_keys)
                .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
        let initial_inventory = recovery_custody
            .enumerate_pending_recovery_inventory_v1()
            .map_err(|_| RestoreMaintenanceErrorV1::RecoveryUnhealthy)?;
        require_exact_recovery_inventory_for_maintenance_v1(&connection, initial_inventory)?;
        let candidates = load_restored_preparation_candidates_v1(
            &connection,
            limits.maximum_operations,
            paused.source_generations().store(),
        )?;

        let rotation = paused.old_authority_rotation_v1();
        let mut failed_count = 0_u64;
        let mut already_failed_count = 0_u64;
        let mut quarantine_retained_count = 0_u64;
        for candidate in &candidates {
            remaining_monotonic_ms(clock, deadline_monotonic_ms)
                .map_err(|_| RestoreMaintenanceErrorV1::DeadlineReached)?;
            coordinator_custody
                .revalidate_v1()
                .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
            verify_recovery_pending_metadata_for_maintenance_v1(
                &mut recovery_custody,
                &recovery_expected,
            )?;
            recheck_restore_pause_v1(&mut pause_custody, &paused)
                .map_err(map_restore_maintenance_recheck_error_v1)?;

            let binding = RestoredOldAuthorityBindingV1::try_new(
                &candidate.operation_id,
                candidate.attempt_id,
                candidate.preparing_state_generation,
                &candidate.boot_id,
                candidate.instance_epoch,
                candidate.fencing_epoch,
                deadline_monotonic_ms,
            )
            .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
            let binding_digest = restored_operation_quarantine_binding_v1(candidate);
            let guard_outcome = if candidate.has_active_quarantine {
                RestoredNoDispatchGuardAcquisitionV1::Ambiguous
            } else {
                guard_authority.acquire_restored_no_dispatch_guard_v1(
                    &binding,
                    rotation,
                    deadline_monotonic_ms,
                )
            };
            let disposition = match guard_outcome {
                RestoredNoDispatchGuardAcquisitionV1::Acquired(mut guard) => {
                    let failure_input = RestoredOldAuthorityFailureInputV1 {
                        binding: &binding,
                        restored_source_generation: candidate.restored_source_generation,
                        restore_identity_digest: paused.restore_identity_sha256(),
                        restore_attestation_digest: paused.provenance_attestation_sha256(),
                        restore_state_generation: paused
                            .source_generations()
                            .store()
                            .checked_add(1)
                            .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?,
                        rotation,
                    };
                    let failure = fail_restored_old_authority_transaction_v1(
                        &mut connection,
                        &failure_input,
                        pending_bindings,
                        historical_plan_keys,
                        &mut guard,
                        || clock.now_monotonic_ms().map_err(|_| ()),
                    );
                    guard.release();
                    match failure {
                        RestoredOldAuthorityFailureOutcomeV1::Failed => {
                            failed_count = checked_restore_maintenance_increment_v1(failed_count)?;
                            None
                        }
                        RestoredOldAuthorityFailureOutcomeV1::AlreadyFailed => {
                            already_failed_count =
                                checked_restore_maintenance_increment_v1(already_failed_count)?;
                            None
                        }
                        RestoredOldAuthorityFailureOutcomeV1::GuardMismatch => {
                            Some(RestoredOldAuthorityGuardFailureV1::Mismatched)
                        }
                        RestoredOldAuthorityFailureOutcomeV1::GuardDeadlineReached => {
                            Some(RestoredOldAuthorityGuardFailureV1::DeadlineReached)
                        }
                        RestoredOldAuthorityFailureOutcomeV1::GuardUnavailable => {
                            Some(RestoredOldAuthorityGuardFailureV1::Unavailable)
                        }
                        RestoredOldAuthorityFailureOutcomeV1::InvalidRotation
                        | RestoredOldAuthorityFailureOutcomeV1::Conflict
                        | RestoredOldAuthorityFailureOutcomeV1::Unhealthy => {
                            return Err(RestoreMaintenanceErrorV1::ReconciliationConflict)
                        }
                    }
                }
                other => Some(map_guard_acquisition_to_quarantine_v1(other)?),
            };
            if let Some(guard_failure) = disposition {
                coordinator_custody
                    .revalidate_v1()
                    .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
                verify_recovery_pending_metadata_for_maintenance_v1(
                    &mut recovery_custody,
                    &recovery_expected,
                )?;
                recheck_restore_pause_v1(&mut pause_custody, &paused)
                    .map_err(map_restore_maintenance_recheck_error_v1)?;
                let quarantine_input = RestoredOldAuthorityQuarantineInputV1 {
                    operation_id: &candidate.operation_id,
                    attempt_id: candidate.attempt_id,
                    operation_binding_digest: binding_digest,
                    preparing_state_generation: candidate.preparing_state_generation,
                    old_boot_id: &candidate.boot_id,
                    old_instance_epoch: candidate.instance_epoch,
                    old_fencing_epoch: candidate.fencing_epoch,
                    restored_source_generation: candidate.restored_source_generation,
                    restore_identity_digest: paused.restore_identity_sha256(),
                    restore_attestation_digest: paused.provenance_attestation_sha256(),
                    restore_state_generation: paused
                        .source_generations()
                        .store()
                        .checked_add(1)
                        .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?,
                    rotation,
                };
                match retain_restored_old_authority_quarantine_v1(
                    &mut connection,
                    &quarantine_input,
                    guard_failure,
                    pending_bindings,
                    historical_plan_keys,
                )
                .map_err(map_restore_maintenance_quarantine_error_v1)?
                {
                    RestoredOldAuthorityQuarantineOutcomeV1::Retained(_) => {
                        quarantine_retained_count =
                            checked_restore_maintenance_increment_v1(quarantine_retained_count)?;
                    }
                    RestoredOldAuthorityQuarantineOutcomeV1::AlreadyFailed => {
                        already_failed_count =
                            checked_restore_maintenance_increment_v1(already_failed_count)?;
                    }
                }
            }

            coordinator_custody
                .revalidate_v1()
                .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
            verify_recovery_pending_metadata_for_maintenance_v1(
                &mut recovery_custody,
                &recovery_expected,
            )?;
            recheck_restore_pause_v1(&mut pause_custody, &paused)
                .map_err(map_restore_maintenance_recheck_error_v1)?;
            schema::verify_restore_pending_v1(&connection, pending_bindings, historical_plan_keys)
                .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
        }

        let remaining = count_unresolved_restored_preparations_v1(&connection)?;
        if remaining != 0 {
            return Err(RestoreMaintenanceErrorV1::ReconciliationConflict);
        }
        let final_pending =
            schema::verify_restore_pending_v1(&connection, pending_bindings, historical_plan_keys)
                .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
        let final_inventory = recovery_custody
            .enumerate_pending_recovery_inventory_v1()
            .map_err(|_| RestoreMaintenanceErrorV1::RecoveryUnhealthy)?;
        let (provider_set_count, entry_count) =
            require_exact_recovery_inventory_for_maintenance_v1(&connection, final_inventory)?;
        coordinator_custody
            .revalidate_v1()
            .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnavailable)?;
        verify_recovery_pending_metadata_for_maintenance_v1(
            &mut recovery_custody,
            &recovery_expected,
        )?;
        recheck_restore_pause_v1(&mut pause_custody, &paused)
            .map_err(map_restore_maintenance_recheck_error_v1)?;
        drop(connection);
        recovery_custody.release();
        drop(coordinator_custody);

        let inspected_count = u64::try_from(candidates.len())
            .ok()
            .filter(|count| *count <= MAX_SAFE_U64)
            .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
        let verification = VerifiedPreparationRestoreV1::from_verified_pending_v1(
            final_pending.generations(),
            final_pending.counts(),
            provider_set_count,
            entry_count,
        );
        // The source proof must also have been exact before any maintenance work. This
        // read prevents a future optimization from accidentally dropping the initial gate.
        let _ = initial;
        Ok(RestoredPreparationMaintenanceEvidenceV1 {
            verification,
            inspected_count,
            failed_count,
            already_failed_count,
            quarantine_retained_count,
        })
    })();
    pause_custody.release();
    result
}

#[cfg(not(test))]
fn verify_recovery_pending_metadata_for_maintenance_v1<G: RecoveryRestorePendingCustodyV1>(
    custody: &mut G,
    expected: &RecoveryRestorePendingExpectationV1,
) -> Result<(), RestoreMaintenanceErrorV1> {
    let bytes = custody
        .read_restore_pending_metadata_v1(RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1)
        .map_err(|_| RestoreMaintenanceErrorV1::RecoveryUnavailable)?;
    let actual = verify_recovery_root_pending_bindings_v1(&bytes)
        .map_err(|_| RestoreMaintenanceErrorV1::RecoveryUnhealthy)?;
    if actual.root_identity_sha256() != expected.root_identity_sha256()
        || actual.state_generation() != expected.state_generation()
        || actual.at_rest_profile_id() != expected.at_rest_profile_id()
        || actual.restore_identity_sha256() != expected.restore_identity_sha256()
        || actual.provenance_attestation_sha256() != expected.provenance_attestation_sha256()
        || actual.source_inventory_sha256() != expected.source_inventory_sha256()
    {
        return Err(RestoreMaintenanceErrorV1::RecoveryUnhealthy);
    }
    Ok(())
}

#[cfg(not(test))]
fn require_exact_recovery_inventory_for_maintenance_v1(
    connection: &Connection,
    entries: Vec<ProviderRecoveryInventoryEntryV1>,
) -> Result<(u64, u64), RestoreMaintenanceErrorV1> {
    let outcome = reconcile_enumerated_inventory_v1(connection, entries)
        .map_err(|_| RestoreMaintenanceErrorV1::RecoveryUnhealthy)?;
    let inventory = match outcome {
        RecoveryMaintenanceOutcomeV1::Ready(inventory) => inventory,
        RecoveryMaintenanceOutcomeV1::BackupBlocked(_) => {
            return Err(RestoreMaintenanceErrorV1::RecoveryUnhealthy)
        }
    };
    let entry_count = u64::try_from(inventory.provider_entries().len())
        .ok()
        .filter(|count| *count <= MAX_SAFE_U64)
        .ok_or(RestoreMaintenanceErrorV1::RecoveryUnhealthy)?;
    let mut provider_set_count = 0_u64;
    let mut previous: Option<(&str, &str, u64)> = None;
    for entry in inventory.provider_entries() {
        let current = (
            entry.provider_profile_id().as_str(),
            entry.provider_id().as_str(),
            entry.provider_generation(),
        );
        if previous != Some(current) {
            provider_set_count = checked_restore_maintenance_increment_v1(provider_set_count)?;
            previous = Some(current);
        }
    }
    Ok((provider_set_count, entry_count))
}

#[cfg(not(test))]
fn load_restored_preparation_candidates_v1(
    connection: &Connection,
    maximum_operations: u64,
    expected_source_generation: u64,
) -> Result<Vec<RestoredPreparationCandidateV1>, RestoreMaintenanceErrorV1> {
    let limit = maximum_operations
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(RestoreMaintenanceErrorV1::WorkLimitExceeded)?;
    let mut statement = connection
        .prepare(
            "SELECT operation_id, attempt_id, state_generation, boot_id,
                    instance_epoch, fencing_epoch, restored_source_generation,
                    EXISTS (
                        SELECT 1 FROM preparation_quarantines q
                        WHERE q.attempt_id = prepared_operations.attempt_id
                          AND q.quarantine_status = 'ACTIVE'
                    )
             FROM prepared_operations
             WHERE operation_state = 'PREPARING'
             ORDER BY operation_id COLLATE BINARY
             LIMIT ?1",
        )
        .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
    let rows = statement
        .query_map([limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
    let mut candidates = Vec::new();
    for row in rows {
        let row = row.map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
        let attempt: [u8; 32] = row
            .1
            .try_into()
            .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
        let preparing_state_generation = decode_restore_maintenance_safe_positive_v1(row.2)?;
        let instance_epoch = decode_restore_maintenance_safe_positive_v1(row.4)?;
        let fencing_epoch = decode_restore_maintenance_safe_positive_v1(row.5)?;
        let restored_source_generation = row
            .6
            .map(decode_restore_maintenance_safe_positive_v1)
            .transpose()?
            .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
        if restored_source_generation != expected_source_generation || !matches!(row.7, 0 | 1) {
            return Err(RestoreMaintenanceErrorV1::CoordinatorUnhealthy);
        }
        candidates.push(RestoredPreparationCandidateV1 {
            operation_id: row.0,
            attempt_id: Sha256Digest::from_bytes(attempt),
            preparing_state_generation,
            boot_id: row.3,
            instance_epoch,
            fencing_epoch,
            restored_source_generation,
            has_active_quarantine: row.7 == 1,
        });
    }
    if u64::try_from(candidates.len()).ok() > Some(maximum_operations) {
        return Err(RestoreMaintenanceErrorV1::WorkLimitExceeded);
    }
    Ok(candidates)
}

#[cfg(not(test))]
fn count_unresolved_restored_preparations_v1(
    connection: &Connection,
) -> Result<u64, RestoreMaintenanceErrorV1> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM prepared_operations p
             WHERE p.operation_state = 'PREPARING'
               AND NOT EXISTS (
                   SELECT 1 FROM preparation_quarantines q
                   WHERE q.attempt_id = p.attempt_id
                     AND q.quarantine_status = 'ACTIVE'
               )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| RestoreMaintenanceErrorV1::CoordinatorUnhealthy)?;
    u64::try_from(count)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)
}

#[cfg(not(test))]
fn restored_operation_quarantine_binding_v1(
    candidate: &RestoredPreparationCandidateV1,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(RESTORED_OPERATION_QUARANTINE_BINDING_DOMAIN_V1);
    hasher.update(
        u64::try_from(candidate.operation_id.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(candidate.operation_id.as_bytes());
    hasher.update(candidate.attempt_id.as_bytes());
    hasher.update(candidate.preparing_state_generation.to_be_bytes());
    hasher.update(
        u64::try_from(candidate.boot_id.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(candidate.boot_id.as_bytes());
    hasher.update(candidate.instance_epoch.to_be_bytes());
    hasher.update(candidate.fencing_epoch.to_be_bytes());
    hasher.update(candidate.restored_source_generation.to_be_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(not(test))]
fn map_guard_acquisition_to_quarantine_v1<G>(
    outcome: RestoredNoDispatchGuardAcquisitionV1<G>,
) -> Result<RestoredOldAuthorityGuardFailureV1, RestoreMaintenanceErrorV1> {
    match outcome {
        RestoredNoDispatchGuardAcquisitionV1::Acquired(_) => {
            Err(RestoreMaintenanceErrorV1::ReconciliationConflict)
        }
        RestoredNoDispatchGuardAcquisitionV1::Missing => {
            Ok(RestoredOldAuthorityGuardFailureV1::Missing)
        }
        RestoredNoDispatchGuardAcquisitionV1::Mismatched => {
            Ok(RestoredOldAuthorityGuardFailureV1::Mismatched)
        }
        RestoredNoDispatchGuardAcquisitionV1::Revoked => {
            Ok(RestoredOldAuthorityGuardFailureV1::Revoked)
        }
        RestoredNoDispatchGuardAcquisitionV1::DeadlineReached => {
            Ok(RestoredOldAuthorityGuardFailureV1::DeadlineReached)
        }
        RestoredNoDispatchGuardAcquisitionV1::Unavailable
        | RestoredNoDispatchGuardAcquisitionV1::Unsupported => {
            Ok(RestoredOldAuthorityGuardFailureV1::Unavailable)
        }
        RestoredNoDispatchGuardAcquisitionV1::Ambiguous => {
            Ok(RestoredOldAuthorityGuardFailureV1::Ambiguous)
        }
    }
}

#[cfg(not(test))]
fn map_restore_maintenance_quarantine_error_v1(
    error: BaseQuarantineErrorV1,
) -> RestoreMaintenanceErrorV1 {
    match error {
        BaseQuarantineErrorV1::Unavailable => RestoreMaintenanceErrorV1::CoordinatorUnavailable,
        BaseQuarantineErrorV1::InvalidInput
        | BaseQuarantineErrorV1::Conflict
        | BaseQuarantineErrorV1::GenerationExhausted => {
            RestoreMaintenanceErrorV1::ReconciliationConflict
        }
        BaseQuarantineErrorV1::Unhealthy => RestoreMaintenanceErrorV1::CoordinatorUnhealthy,
    }
}

#[cfg(not(test))]
fn map_restore_maintenance_recheck_error_v1(
    error: PreparationRestoreErrorV1,
) -> RestoreMaintenanceErrorV1 {
    match error {
        PreparationRestoreErrorV1::DeadlineReached
        | PreparationRestoreErrorV1::PauseDeadlineReached => {
            RestoreMaintenanceErrorV1::DeadlineReached
        }
        PreparationRestoreErrorV1::PauseContended => RestoreMaintenanceErrorV1::PauseContended,
        PreparationRestoreErrorV1::PauseUnavailable => RestoreMaintenanceErrorV1::PauseUnavailable,
        PreparationRestoreErrorV1::PauseUnsupported => RestoreMaintenanceErrorV1::PauseUnsupported,
        PreparationRestoreErrorV1::PauseUnhealthy | PreparationRestoreErrorV1::SourceChanged => {
            RestoreMaintenanceErrorV1::PauseUnhealthy
        }
        PreparationRestoreErrorV1::RecoveryDestinationUnavailable => {
            RestoreMaintenanceErrorV1::RecoveryUnavailable
        }
        PreparationRestoreErrorV1::RecoveryImportInvalid => {
            RestoreMaintenanceErrorV1::RecoveryUnhealthy
        }
        _ => RestoreMaintenanceErrorV1::ReconciliationConflict,
    }
}

#[cfg(not(test))]
fn decode_restore_maintenance_safe_positive_v1(
    value: i64,
) -> Result<u64, RestoreMaintenanceErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_SAFE_U64).contains(value))
        .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)
}

#[cfg(not(test))]
fn checked_restore_maintenance_increment_v1(value: u64) -> Result<u64, RestoreMaintenanceErrorV1> {
    value
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(RestoreMaintenanceErrorV1::CoordinatorUnhealthy)
}

#[cfg(not(test))]
fn import_coordinator_database_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    source: &Connection,
    custody: &mut CoordinatorRestoreRootCustodyV1,
    maximum_busy_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
    fault_probe: &mut MaintenanceFaultProbeV1,
) -> Result<Connection, PreparationRestoreErrorV1> {
    let already_present = custody
        .database_import_already_present_v1()
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    custody
        .reserve_database_import_create_new_v1()
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    let path = custody
        .database_path_v1()
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    if !already_present {
        let mut destination = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        configure_deadline_bounded_busy_timeout_v1(
            &destination,
            maximum_busy_wait_ms,
            clock,
            deadline_monotonic_ms,
        )
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        let backup = Backup::new(source, &mut destination)
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        drive_online_backup_steps_v1(
            || backup.step(BACKUP_PAGES_PER_STEP_V1),
            MAX_BACKUP_STEPS_V1,
            MAX_BACKUP_BUSY_OR_LOCKED_STEPS_V1,
            Duration::from_millis(1),
        )
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        drop(backup);
        drop(destination);
    }
    custody
        .revalidate_imported_database_v1()
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    reach_restore_coordinator_database_imported_v1(fault_probe);

    let destination = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    configure_deadline_bounded_busy_timeout_v1(
        &destination,
        maximum_busy_wait_ms,
        clock,
        deadline_monotonic_ms,
    )
    .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    establish_restore_wal_full_profile_v1(&destination)?;
    custody
        .revalidate_imported_database_v1()
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    reach_restore_wal_full_profile_established_v1(fault_probe);
    Ok(destination)
}

#[cfg(not(test))]
fn establish_restore_wal_full_profile_v1(
    connection: &Connection,
) -> Result<(), PreparationRestoreErrorV1> {
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .and_then(|_| connection.pragma_update(None, "synchronous", "FULL"))
        .and_then(|_| connection.pragma_update(None, "wal_autocheckpoint", 0_i64))
        .and_then(|_| connection.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|_| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|_| connection.pragma_update(None, "cell_size_check", "ON"))
        .and_then(|_| connection.pragma_update(None, "recursive_triggers", "ON"))
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    let pragma = |name| {
        connection
            .pragma_query_value(None, name, |row| row.get::<_, i64>(0))
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)
    };
    if !journal_mode.eq_ignore_ascii_case("wal")
        || pragma("synchronous")? != 2
        || pragma("wal_autocheckpoint")? != 0
        || pragma("foreign_keys")? != 1
        || pragma("trusted_schema")? != 0
        || pragma("cell_size_check")? != 1
        || pragma("recursive_triggers")? != 1
    {
        return Err(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable);
    }
    Ok(())
}

#[cfg(not(test))]
enum VerifiedCoordinatorRestoreImportV1 {
    Active(schema::ImportedActiveBackupV1),
    RestorePending(schema::VerifiedRestorePendingV1),
}

#[cfg(not(test))]
fn verify_imported_restore_destination_v1<K: Ed25519KeyResolver>(
    connection: &Connection,
    accepted: &AcceptedPreparationRestorePackageV1,
    pending_bindings: schema::RestorePendingBindingsV1,
    historical_plan_keys: &K,
    provider_entries: Vec<ProviderRecoveryInventoryEntryV1>,
) -> Result<VerifiedCoordinatorRestoreImportV1, PreparationRestoreErrorV1> {
    let verified = match schema::verify_imported_active_backup_v1(
        connection,
        accepted.source_generations,
        historical_plan_keys,
    ) {
        Ok(imported)
            if coordinator_root_identity_digest_v1(imported.summary().root_identity.as_bytes())
                == accepted.bindings.source_coordinator_root_identity_sha256()
                && imported.generations() == accepted.source_generations
                && restore_counts_match_v1(imported.counts(), accepted.bindings.counts()) =>
        {
            VerifiedCoordinatorRestoreImportV1::Active(imported)
        }
        Ok(_) | Err(_) => {
            let pending = schema::verify_restore_pending_v1(
                connection,
                pending_bindings,
                historical_plan_keys,
            )
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
            if !restore_counts_match_v1(pending.counts(), accepted.bindings.counts()) {
                return Err(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable);
            }
            VerifiedCoordinatorRestoreImportV1::RestorePending(pending)
        }
    };
    match reconcile_enumerated_inventory_v1(connection, provider_entries)
        .map_err(|_| PreparationRestoreErrorV1::RecoveryImportInvalid)?
    {
        RecoveryMaintenanceOutcomeV1::Ready(inventory)
            if inventory.operation_retirement_pending() == 0
                && inventory.orphan_retirement_pending() == 0 => {}
        RecoveryMaintenanceOutcomeV1::Ready(_) | RecoveryMaintenanceOutcomeV1::BackupBlocked(_) => {
            return Err(PreparationRestoreErrorV1::RecoveryImportInvalid)
        }
    }
    Ok(verified)
}

/// Restores one accepted package only into independently provisioned empty roots and
/// returns non-authoritative evidence after both roots close, reopen and agree on the
/// same irreversible `RESTORE_PENDING` binding.
#[cfg(all(not(test), windows))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn restore_preparation_to_pending_v1<A, P, Q, K, C>(
    _accepted: AcceptedPreparationRestorePackageV1,
    _coordinator_root: &ProvisionedEmptyCoordinatorRootV1,
    _pause_authority: &A,
    _recovery_provider: &P,
    _quarantine_authority: &Q,
    _historical_plan_keys: &K,
    _maximum_root_wait_ms: u64,
    _maximum_busy_wait_ms: u64,
    _clock: &C,
    _deadline_monotonic_ms: u64,
) -> Result<VerifiedPreparationRestoreV1, PreparationRestoreErrorV1>
where
    A: RestorePauseRotationAuthorityV1,
    P: RecoveryRestoreProviderV1,
    Q: RestoreQuarantineAuthorityV1,
    K: Ed25519KeyResolver,
    C: CoordinatorMonotonicClockV1 + ?Sized,
{
    // Defensive second gate for an accepted value retained across an upgrade. No PAUSE,
    // destination reservation, import, publication or quarantine mutation is attempted.
    Err(PreparationRestoreErrorV1::PlatformUnsupported)
}

#[cfg(all(not(test), not(windows)))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn restore_preparation_to_pending_v1<A, P, Q, K, C>(
    mut accepted: AcceptedPreparationRestorePackageV1,
    coordinator_root: &ProvisionedEmptyCoordinatorRootV1,
    pause_authority: &A,
    recovery_provider: &P,
    quarantine_authority: &Q,
    historical_plan_keys: &K,
    maximum_root_wait_ms: u64,
    maximum_busy_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<VerifiedPreparationRestoreV1, PreparationRestoreErrorV1>
where
    A: RestorePauseRotationAuthorityV1,
    P: RecoveryRestoreProviderV1,
    Q: RestoreQuarantineAuthorityV1,
    K: Ed25519KeyResolver,
    C: CoordinatorMonotonicClockV1 + ?Sized,
{
    if let Err(error) = accepted.revalidate_v1(clock, deadline_monotonic_ms) {
        if error == PreparationRestoreErrorV1::SourceChanged {
            persist_package_quarantine_v1(
                quarantine_authority,
                accepted.package_directory_binding_sha256,
                RestorePackageQuarantineReasonV1::SourceChanged,
                deadline_monotonic_ms,
                &mut accepted.fault_probe,
            )?;
        }
        return Err(error);
    }
    if let Err(error) = accepted.reverify_provenance_v1() {
        let reason = match error {
            PreparationRestoreErrorV1::ProvenanceInvalid => {
                RestorePackageQuarantineReasonV1::ProvenanceInvalid
            }
            _ => RestorePackageQuarantineReasonV1::SourceChanged,
        };
        persist_package_quarantine_v1(
            quarantine_authority,
            accepted.package_directory_binding_sha256,
            reason,
            deadline_monotonic_ms,
            &mut accepted.fault_probe,
        )?;
        return Err(error);
    }
    let coordinator_destination_binding_sha256 = coordinator_root
        .restore_reservation_binding_sha256_v1()
        .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    if coordinator_root.restore_at_rest_profile_id_v1()
        != Some(accepted.bindings.at_rest_profile_id())
    {
        return Err(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable);
    }
    let recovery_destination_binding_sha256 = recovery_provider
        .provisioned_restore_destination_binding_sha256_v1()
        .map_err(map_recovery_restore_provider_error_v1)?;
    let attempt = RestoreAttemptInputV1::from_verified_bindings_v1(
        &accepted.bindings,
        coordinator_destination_binding_sha256,
        recovery_destination_binding_sha256,
        accepted.source_generations,
    );
    let mut pause_custody = match pause_authority
        .persist_pause_and_rotate_for_restore_v1(&attempt, deadline_monotonic_ms)
    {
        RestorePauseRotationOutcomeV1::Acquired(custody) => custody,
        RestorePauseRotationOutcomeV1::Contended => {
            return Err(PreparationRestoreErrorV1::PauseContended)
        }
        RestorePauseRotationOutcomeV1::Unavailable => {
            return Err(PreparationRestoreErrorV1::PauseUnavailable)
        }
        RestorePauseRotationOutcomeV1::DeadlineReached => {
            return Err(PreparationRestoreErrorV1::PauseDeadlineReached)
        }
        RestorePauseRotationOutcomeV1::Unsupported => {
            return Err(PreparationRestoreErrorV1::PauseUnsupported)
        }
    };
    let paused = match pause_custody.capture_paused_rotated_authority_v1() {
        Ok(paused)
            if paused.attempt_binding_sha256() == attempt.attempt_binding_sha256()
                && paused.source_instance_identity_sha256()
                    == attempt.source_instance_identity_sha256()
                && paused.source_generations() == attempt.source_generations()
                && paused.coordinator_destination_binding_sha256()
                    == coordinator_destination_binding_sha256
                && paused.recovery_destination_binding_sha256()
                    == recovery_destination_binding_sha256 =>
        {
            paused
        }
        Ok(_) | Err(MaintenanceCustodyValidationV1::Revoked) => {
            pause_custody.release();
            return Err(PreparationRestoreErrorV1::SourceChanged);
        }
        Err(MaintenanceCustodyValidationV1::Unavailable) => {
            pause_custody.release();
            return Err(PreparationRestoreErrorV1::PauseUnavailable);
        }
        Err(MaintenanceCustodyValidationV1::Unhealthy) => {
            pause_custody.release();
            return Err(PreparationRestoreErrorV1::PauseUnhealthy);
        }
        Err(MaintenanceCustodyValidationV1::Exact) => {
            pause_custody.release();
            return Err(PreparationRestoreErrorV1::PauseUnhealthy);
        }
    };

    let restore_identity_sha256 = paused.restore_identity_sha256();
    let new_coordinator_root_identity = paused.new_coordinator_root_identity();
    let new_coordinator_root_identity_sha256 =
        coordinator_root_identity_digest_v1(new_coordinator_root_identity.as_bytes());
    let new_recovery_root_identity_sha256 = paused.new_recovery_root_identity_sha256();
    if new_coordinator_root_identity_sha256
        == accepted.bindings.source_coordinator_root_identity_sha256()
        || new_recovery_root_identity_sha256
            == accepted.bindings.source_recovery_root_identity_sha256()
        || new_coordinator_root_identity_sha256 == new_recovery_root_identity_sha256
    {
        pause_custody.release();
        return Err(PreparationRestoreErrorV1::PauseUnhealthy);
    }
    let coordinator_root_path = coordinator_root.path().to_path_buf();
    let reservation = RecoveryRestoreReservationV1 {
        restore_identity_sha256,
        provenance_attestation_sha256: accepted.bindings.attestation_sha256(),
        source_inventory_sha256: accepted.bindings.inventory_sha256(),
        new_coordinator_root_identity_sha256,
        new_recovery_root_identity_sha256,
        recovery_destination_binding_sha256,
        at_rest_profile_id: accepted.bindings.at_rest_profile_id().clone(),
    };
    let quarantine_evidence = RestoreQuarantineEvidenceV1 {
        restore_identity_sha256,
        provenance_attestation_sha256: accepted.bindings.attestation_sha256(),
        source_inventory_sha256: accepted.bindings.inventory_sha256(),
        new_coordinator_root_identity_sha256,
        new_recovery_root_identity_sha256,
        coordinator_destination_binding_sha256,
        recovery_destination_binding_sha256,
        recovery_state_generation: 0,
        coordinator_destination_started: false,
        recovery_destination_started: false,
    };
    let mut quarantine_evidence = quarantine_evidence;
    let mut coordinator_import_custody: Option<CoordinatorRestoreRootCustodyV1> = None;
    let mut coordinator_pending_custody: Option<CoordinatorPendingRootCustodyV1> = None;
    let mut recovery_import_custody: Option<P::ImportCustody> = None;
    let mut recovery_pending_custody: Option<P::PendingCustody> = None;

    let restored = (|| {
        quarantine_evidence.coordinator_destination_started = true;
        match begin_empty_restore_root_custody_v1(
            coordinator_root,
            new_coordinator_root_identity,
            maximum_root_wait_ms,
            clock,
            deadline_monotonic_ms,
        ) {
            Ok(custody) => coordinator_import_custody = Some(custody),
            Err(_) => {
                coordinator_pending_custody = Some(
                    reopen_restore_pending_root_custody_v1(
                        coordinator_root,
                        new_coordinator_root_identity,
                        maximum_root_wait_ms,
                        clock,
                        deadline_monotonic_ms,
                    )
                    .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?,
                );
            }
        }
        reach_restore_empty_coordinator_root_reserved_v1(&mut accepted.fault_probe);

        quarantine_evidence.recovery_destination_started = true;
        let import_custody = match recovery_provider
            .begin_or_resume_restore_root_v1(&reservation, deadline_monotonic_ms)
        {
            RecoveryRestoreCustodyOutcomeV1::Acquired(custody) => custody,
            RecoveryRestoreCustodyOutcomeV1::Contended
            | RecoveryRestoreCustodyOutcomeV1::Unavailable
            | RecoveryRestoreCustodyOutcomeV1::DeadlineReached
            | RecoveryRestoreCustodyOutcomeV1::Unsupported => {
                return Err(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)
            }
        };
        recovery_import_custody = Some(import_custody);
        reach_restore_empty_recovery_root_reserved_v1(&mut accepted.fault_probe);
        let recovery_source = recovery_import_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .capture_restore_root_source_v1()
            .map_err(map_recovery_restore_provider_error_v1)?;
        quarantine_evidence.recovery_state_generation = recovery_source.provider_generation();
        if recovery_source.root_identity_sha256() != new_recovery_root_identity_sha256
            || recovery_source.root_identity_sha256()
                == accepted.bindings.source_recovery_root_identity_sha256()
        {
            return Err(PreparationRestoreErrorV1::RecoveryImportInvalid);
        }
        let pending_bindings = schema::RestorePendingBindingsV1::try_new(
            accepted.source_generations,
            new_coordinator_root_identity,
            restore_identity_sha256,
            accepted.bindings.attestation_sha256(),
            accepted.source_generations.store(),
        )
        .map_err(|_| PreparationRestoreErrorV1::PackageInvalid)?;

        accepted.revalidate_v1(clock, deadline_monotonic_ms)?;
        let mut destination = if let Some(custody) = coordinator_import_custody.as_mut() {
            import_coordinator_database_v1(
                &accepted.source_connection,
                custody,
                maximum_busy_wait_ms,
                clock,
                deadline_monotonic_ms,
                &mut accepted.fault_probe,
            )?
        } else {
            let path = coordinator_pending_custody
                .as_mut()
                .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
                .database_path_v1()
                .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
            let connection = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
            configure_deadline_bounded_busy_timeout_v1(
                &connection,
                maximum_busy_wait_ms,
                clock,
                deadline_monotonic_ms,
            )
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
            establish_restore_wal_full_profile_v1(&connection)?;
            connection
        };
        accepted.revalidate_v1(clock, deadline_monotonic_ms)?;

        let provider_packages = accepted.provider_packages.clone();
        for package in &provider_packages {
            let mut source = ProviderRestorePackageSourceV1 {
                custody: &mut accepted.custody,
                package,
                manifest_read: false,
                material_read: false,
                retirement_read: false,
            };
            recovery_provider
                .import_recovery_backup_package_v1(
                    recovery_import_custody
                        .as_mut()
                        .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?,
                    &mut source,
                )
                .map_err(map_recovery_restore_provider_error_v1)?;
            source.finish_v1()?;
            reach_restore_recovery_package_imported_v1(&mut accepted.fault_probe);
        }
        let imported_inventory = recovery_import_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .enumerate_imported_recovery_inventory_v1()
            .map_err(map_recovery_restore_provider_error_v1)?;
        let coordinator_state = verify_imported_restore_destination_v1(
            &destination,
            &accepted,
            pending_bindings,
            historical_plan_keys,
            imported_inventory,
        )?;
        if let Some(custody) = coordinator_import_custody.as_mut() {
            custody
                .revalidate_imported_database_v1()
                .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        } else {
            coordinator_pending_custody
                .as_mut()
                .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
                .revalidate_v1()
                .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        }
        recheck_recovery_restore_root_v1(
            recovery_import_custody
                .as_mut()
                .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?,
            &recovery_source,
        )?;
        recheck_restore_pause_v1(&mut pause_custody, &paused)?;
        accepted.revalidate_v1(clock, deadline_monotonic_ms)?;
        accepted.reverify_provenance_v1()?;

        match coordinator_state {
            VerifiedCoordinatorRestoreImportV1::Active(_imported) => {
                let _pending = schema::transition_imported_backup_to_restore_pending_v1(
                    &mut destination,
                    pending_bindings,
                    historical_plan_keys,
                )
                .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
                reach_restore_coordinator_restore_pending_committed_v1(&mut accepted.fault_probe);
            }
            VerifiedCoordinatorRestoreImportV1::RestorePending(_pending) => {
                // Exact crash resume: never overwrite or re-transition an already pending DB.
            }
        }
        drop(destination);
        if let Some(mut custody) = coordinator_import_custody.take() {
            custody
                .revalidate_imported_database_v1()
                .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
            coordinator_pending_custody = Some(
                custody
                    .finalize_restore_pending_publication_v1(
                        pending_bindings,
                        historical_plan_keys,
                        maximum_busy_wait_ms,
                        clock,
                        deadline_monotonic_ms,
                    )
                    .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?,
            );
            reach_restore_coordinator_pending_root_marker_published_v1(&mut accepted.fault_probe);
        } else {
            coordinator_pending_custody
                .as_mut()
                .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
                .revalidate_v1()
                .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        }
        recheck_restore_pause_v1(&mut pause_custody, &paused)?;
        accepted.revalidate_v1(clock, deadline_monotonic_ms)?;
        accepted.reverify_provenance_v1()?;
        recheck_recovery_restore_root_v1(
            recovery_import_custody
                .as_mut()
                .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?,
            &recovery_source,
        )?;
        let recovery_metadata =
            finalize_recovery_root_metadata_v1(RecoveryRootMetadataInputV1::RestorePending {
                root_identity_sha256: recovery_source.root_identity_sha256(),
                state_generation: recovery_source.provider_generation(),
                at_rest_profile_id: accepted.bindings.at_rest_profile_id().clone(),
                restore_identity_sha256,
                provenance_attestation_sha256: accepted.bindings.attestation_sha256(),
                source_inventory_sha256: accepted.bindings.inventory_sha256(),
            })
            .map_err(|_| PreparationRestoreErrorV1::RecoveryImportInvalid)?;
        recovery_import_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .publish_restore_pending_metadata_v1(recovery_metadata.bytes())
            .map_err(map_recovery_restore_provider_error_v1)?;
        reach_restore_recovery_restore_pending_metadata_published_v1(&mut accepted.fault_probe);

        recovery_import_custody
            .take()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .release();
        drop(coordinator_pending_custody.take());
        reach_restore_both_roots_closed_v1(&mut accepted.fault_probe);

        let reattested_coordinator =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
                coordinator_root_path.clone(),
                coordinator_destination_binding_sha256,
                accepted.bindings.at_rest_profile_id().clone(),
            )
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        coordinator_pending_custody = Some(
            reopen_restore_pending_root_custody_v1(
                &reattested_coordinator,
                new_coordinator_root_identity,
                maximum_root_wait_ms,
                clock,
                deadline_monotonic_ms,
            )
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?,
        );
        let recovery_expected = RecoveryRestorePendingExpectationV1 {
            root_identity_sha256: recovery_source.root_identity_sha256(),
            coordinator_root_identity_sha256: new_coordinator_root_identity_sha256,
            restore_identity_sha256,
            provenance_attestation_sha256: accepted.bindings.attestation_sha256(),
            source_inventory_sha256: accepted.bindings.inventory_sha256(),
            recovery_destination_binding_sha256,
            at_rest_profile_id: accepted.bindings.at_rest_profile_id().clone(),
            state_generation: recovery_source.provider_generation(),
        };
        let reopened_recovery = match recovery_provider
            .reopen_restore_pending_root_v1(&recovery_expected, deadline_monotonic_ms)
        {
            RecoveryRestoreCustodyOutcomeV1::Acquired(custody) => custody,
            RecoveryRestoreCustodyOutcomeV1::Contended
            | RecoveryRestoreCustodyOutcomeV1::Unavailable
            | RecoveryRestoreCustodyOutcomeV1::DeadlineReached
            | RecoveryRestoreCustodyOutcomeV1::Unsupported => {
                return Err(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)
            }
        };
        recovery_pending_custody = Some(reopened_recovery);
        reach_restore_both_roots_reopened_v1(&mut accepted.fault_probe);

        let recovery_metadata = recovery_pending_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .read_restore_pending_metadata_v1(RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1)
            .map_err(map_recovery_restore_provider_error_v1)?;
        let recovery_pending = verify_recovery_root_pending_bindings_v1(&recovery_metadata)
            .map_err(|_| PreparationRestoreErrorV1::AgreementFailed)?;
        let pending_inventory = recovery_pending_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .enumerate_pending_recovery_inventory_v1()
            .map_err(map_recovery_restore_provider_error_v1)?;

        let pending_path = coordinator_pending_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
            .database_path_v1()
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        let pending_connection = Connection::open_with_flags(
            pending_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        configure_deadline_bounded_busy_timeout_v1(
            &pending_connection,
            maximum_busy_wait_ms,
            clock,
            deadline_monotonic_ms,
        )
        .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
        establish_restore_wal_full_profile_v1(&pending_connection)?;
        let reopened_pending = schema::verify_restore_pending_v1(
            &pending_connection,
            pending_bindings,
            historical_plan_keys,
        )
        .map_err(|_| PreparationRestoreErrorV1::AgreementFailed)?;
        match reconcile_enumerated_inventory_v1(&pending_connection, pending_inventory)
            .map_err(|_| PreparationRestoreErrorV1::AgreementFailed)?
        {
            RecoveryMaintenanceOutcomeV1::Ready(inventory)
                if inventory.operation_retirement_pending() == 0
                    && inventory.orphan_retirement_pending() == 0 => {}
            RecoveryMaintenanceOutcomeV1::Ready(_)
            | RecoveryMaintenanceOutcomeV1::BackupBlocked(_) => {
                return Err(PreparationRestoreErrorV1::AgreementFailed)
            }
        }
        drop(pending_connection);
        coordinator_pending_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
            .revalidate_v1()
            .map_err(|_| PreparationRestoreErrorV1::AgreementFailed)?;
        if recovery_pending.root_identity_sha256() != recovery_expected.root_identity_sha256
            || recovery_pending.state_generation() != recovery_expected.state_generation
            || recovery_pending.at_rest_profile_id() != &recovery_expected.at_rest_profile_id
            || recovery_pending.restore_identity_sha256()
                != recovery_expected.restore_identity_sha256
            || recovery_pending.provenance_attestation_sha256()
                != recovery_expected.provenance_attestation_sha256
            || recovery_pending.source_inventory_sha256()
                != recovery_expected.source_inventory_sha256
        {
            return Err(PreparationRestoreErrorV1::AgreementFailed);
        }
        accepted.revalidate_v1(clock, deadline_monotonic_ms)?;
        accepted.reverify_provenance_v1()?;
        recheck_restore_pause_v1(&mut pause_custody, &paused)?;
        reach_restore_both_roots_agreement_classified_v1(&mut accepted.fault_probe);

        recovery_pending_custody
            .take()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .release();
        drop(coordinator_pending_custody.take());
        let verified = VerifiedPreparationRestoreV1::from_verified_pending_v1(
            reopened_pending.generations(),
            reopened_pending.counts(),
            accepted.bindings.provider_set_count(),
            accepted.bindings.entry_count(),
        );
        reach_restore_verified_preparation_restore_returned_v1(&mut accepted.fault_probe);
        Ok(verified)
    })();

    // On refusal, persist the exact attempt/root quarantine while PAUSE and every
    // still-open destination custody remain held. The deliberate BothRootsClosed
    // boundary necessarily has no root custody, but PAUSE still serializes the attempt.
    let result = match restored {
        Ok(verified) => Ok(verified),
        Err(error)
            if quarantine_evidence.coordinator_destination_started
                || quarantine_evidence.recovery_destination_started =>
        {
            persist_root_quarantine_v1(
                quarantine_authority,
                &quarantine_evidence,
                deadline_monotonic_ms,
                &mut accepted.fault_probe,
            )?;
            Err(error)
        }
        Err(
            error @ (PreparationRestoreErrorV1::ProvenanceInvalid
            | PreparationRestoreErrorV1::SourceChanged),
        ) => {
            let reason = if error == PreparationRestoreErrorV1::ProvenanceInvalid {
                RestorePackageQuarantineReasonV1::ProvenanceInvalid
            } else {
                RestorePackageQuarantineReasonV1::SourceChanged
            };
            match persist_package_quarantine_v1(
                quarantine_authority,
                accepted.package_directory_binding_sha256,
                reason,
                deadline_monotonic_ms,
                &mut accepted.fault_probe,
            ) {
                Ok(()) => Err(error),
                Err(_) => Err(PreparationRestoreErrorV1::QuarantineUnavailable),
            }
        }
        Err(error) => Err(error),
    };
    if let Some(custody) = recovery_pending_custody.take() {
        custody.release();
    }
    if let Some(custody) = recovery_import_custody.take() {
        custody.release();
    }
    drop(coordinator_pending_custody.take());
    drop(coordinator_import_custody.take());
    pause_custody.release();
    result
}

/// Quarantines a previously persisted restore ticket even when the source package or
/// provisioner trust is no longer available. This path cannot create, import, publish,
/// reopen, or activate either destination.
#[cfg(not(test))]
pub(crate) fn quarantine_existing_restore_attempt_v1<A, P, Q, C>(
    coordinator_root: &ProvisionedEmptyCoordinatorRootV1,
    pause_authority: &A,
    recovery_provider: &P,
    quarantine_authority: &Q,
    maximum_root_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<(), PreparationRestoreErrorV1>
where
    A: RestorePauseRotationAuthorityV1,
    P: RecoveryRestoreProviderV1,
    Q: RestoreQuarantineAuthorityV1,
    C: CoordinatorMonotonicClockV1 + ?Sized,
{
    let coordinator_destination_binding_sha256 = coordinator_root
        .restore_reservation_binding_sha256_v1()
        .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?;
    let recovery_destination_binding_sha256 = recovery_provider
        .provisioned_restore_destination_binding_sha256_v1()
        .map_err(map_recovery_restore_provider_error_v1)?;
    let mut pause_custody = match pause_authority.inspect_existing_restore_attempt_v1(
        coordinator_destination_binding_sha256,
        recovery_destination_binding_sha256,
        deadline_monotonic_ms,
    ) {
        RestorePauseRotationOutcomeV1::Acquired(custody) => custody,
        RestorePauseRotationOutcomeV1::Contended => {
            return Err(PreparationRestoreErrorV1::PauseContended)
        }
        RestorePauseRotationOutcomeV1::Unavailable => {
            return Err(PreparationRestoreErrorV1::PauseUnavailable)
        }
        RestorePauseRotationOutcomeV1::DeadlineReached => {
            return Err(PreparationRestoreErrorV1::PauseDeadlineReached)
        }
        RestorePauseRotationOutcomeV1::Unsupported => {
            return Err(PreparationRestoreErrorV1::PauseUnsupported)
        }
    };
    let mut coordinator_custody = None;
    let mut recovery_custody = None;
    let result = (|| {
        let paused = pause_custody
            .capture_paused_rotated_authority_v1()
            .map_err(|_| PreparationRestoreErrorV1::PauseUnhealthy)?;
        if paused.coordinator_destination_binding_sha256() != coordinator_destination_binding_sha256
            || paused.recovery_destination_binding_sha256() != recovery_destination_binding_sha256
        {
            return Err(PreparationRestoreErrorV1::SourceChanged);
        }
        let new_coordinator_root_identity = paused.new_coordinator_root_identity();
        let new_coordinator_root_identity_sha256 =
            coordinator_root_identity_digest_v1(new_coordinator_root_identity.as_bytes());
        let at_rest_profile_id = coordinator_root
            .restore_at_rest_profile_id_v1()
            .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
            .clone();
        coordinator_custody = Some(
            inspect_existing_restore_root_custody_v1(
                coordinator_root,
                coordinator_destination_binding_sha256,
                new_coordinator_root_identity,
                maximum_root_wait_ms,
                clock,
                deadline_monotonic_ms,
            )
            .map_err(|_| PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?,
        );
        let recovery_expectation = RecoveryRestoreInspectionExpectationV1 {
            restore_identity_sha256: paused.restore_identity_sha256(),
            provenance_attestation_sha256: paused.provenance_attestation_sha256(),
            source_inventory_sha256: paused.source_inventory_sha256(),
            coordinator_root_identity_sha256: new_coordinator_root_identity_sha256,
            recovery_root_identity_sha256: paused.new_recovery_root_identity_sha256(),
            coordinator_destination_binding_sha256,
            recovery_destination_binding_sha256,
            at_rest_profile_id,
        };
        recovery_custody = Some(
            match recovery_provider
                .inspect_existing_restore_root_v1(&recovery_expectation, deadline_monotonic_ms)
            {
                RecoveryRestoreCustodyOutcomeV1::Acquired(custody) => custody,
                RecoveryRestoreCustodyOutcomeV1::Contended
                | RecoveryRestoreCustodyOutcomeV1::Unavailable
                | RecoveryRestoreCustodyOutcomeV1::DeadlineReached
                | RecoveryRestoreCustodyOutcomeV1::Unsupported => {
                    return Err(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)
                }
            },
        );
        let recovery_state = recovery_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?
            .capture_existing_restore_state_v1()
            .map_err(map_recovery_restore_provider_error_v1)?;
        let coordinator_destination_started = coordinator_custody
            .as_ref()
            .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
            .restore_has_started_v1();
        let recovery_destination_started = recovery_state.destination_started();
        if !coordinator_destination_started && !recovery_destination_started {
            return Err(PreparationRestoreErrorV1::SourceChanged);
        }
        coordinator_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
            .revalidate_v1(coordinator_root)
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        recheck_recovery_restore_inspection_v1(
            recovery_custody
                .as_mut()
                .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?,
            &recovery_state,
        )?;
        recheck_restore_pause_v1(&mut pause_custody, &paused)?;
        let evidence = RestoreQuarantineEvidenceV1 {
            restore_identity_sha256: paused.restore_identity_sha256(),
            provenance_attestation_sha256: paused.provenance_attestation_sha256(),
            source_inventory_sha256: paused.source_inventory_sha256(),
            new_coordinator_root_identity_sha256,
            new_recovery_root_identity_sha256: paused.new_recovery_root_identity_sha256(),
            coordinator_destination_binding_sha256,
            recovery_destination_binding_sha256,
            recovery_state_generation: recovery_state.state_generation(),
            coordinator_destination_started,
            recovery_destination_started,
        };
        persist_root_quarantine_v1(
            quarantine_authority,
            &evidence,
            deadline_monotonic_ms,
            &mut MaintenanceFaultProbeV1::disabled_v1(),
        )?;
        coordinator_custody
            .as_mut()
            .ok_or(PreparationRestoreErrorV1::CoordinatorDestinationUnavailable)?
            .revalidate_v1(coordinator_root)
            .map_err(|_| PreparationRestoreErrorV1::SourceChanged)?;
        recheck_recovery_restore_inspection_v1(
            recovery_custody
                .as_mut()
                .ok_or(PreparationRestoreErrorV1::RecoveryDestinationUnavailable)?,
            &recovery_state,
        )?;
        recheck_restore_pause_v1(&mut pause_custody, &paused)?;
        Ok(())
    })();
    if let Some(custody) = recovery_custody.take() {
        custody.release();
    }
    drop(coordinator_custody.take());
    pause_custody.release();
    result
}

#[cfg(not(test))]
fn map_recovery_restore_provider_error_v1(
    error: RecoveryRestoreProviderErrorV1,
) -> PreparationRestoreErrorV1 {
    match error {
        RecoveryRestoreProviderErrorV1::Unavailable => {
            PreparationRestoreErrorV1::RecoveryDestinationUnavailable
        }
        RecoveryRestoreProviderErrorV1::Invalid => PreparationRestoreErrorV1::RecoveryImportInvalid,
    }
}

/// Provisioner-reserved package root. The native location never appears in diagnostics
/// and every member is created with no-clobber semantics.
pub(crate) struct ProvisionedBackupDestinationV1 {
    root: PathBuf,
    staging: PathBuf,
    published: PathBuf,
    provider_packages: PathBuf,
    coordinator_database: PathBuf,
    destination_connection: Option<Connection>,
    attestation_published: bool,
}

impl ProvisionedBackupDestinationV1 {
    pub(crate) fn try_reserve_create_only(root: PathBuf) -> Result<Self, QuiescentBackupErrorV1> {
        match fs::create_dir(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(QuiescentBackupErrorV1::DestinationExists)
            }
            Err(_) => return Err(QuiescentBackupErrorV1::DestinationUnavailable),
        }
        let staged = (|| {
            let staging = root.join("staging");
            let published = root.join("published");
            let provider_packages = root.join("recovery-packages");
            fs::create_dir(&staging).map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?;
            fs::create_dir(&published)
                .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?;
            fs::create_dir(&provider_packages)
                .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?;
            let coordinator_database = root.join("coordinator.sqlite3");
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&coordinator_database)
                .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?
                .sync_all()
                .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?;
            let destination_connection = Connection::open_with_flags(
                &coordinator_database,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?;
            Ok(Self {
                root: root.clone(),
                staging,
                published,
                provider_packages,
                coordinator_database,
                destination_connection: Some(destination_connection),
                attestation_published: false,
            })
        })();
        if staged.is_err() {
            let _ = fs::remove_dir_all(&root);
        }
        staged
    }

    /// Uses SQLite's online-backup API, closes it, reopens the result for integrity
    /// verification, then hashes the exact stable main-database bytes.
    fn backup_sqlite_v1(
        &mut self,
        source: &Connection,
        fault_probe: &mut MaintenanceFaultProbeV1,
    ) -> Result<Sha256Digest, QuiescentBackupErrorV1> {
        let destination = self
            .destination_connection
            .as_mut()
            .ok_or(QuiescentBackupErrorV1::DestinationUnavailable)?;
        let backup =
            Backup::new(source, destination).map_err(|_| QuiescentBackupErrorV1::BackupFailed)?;
        drive_online_backup_steps_v1(
            || backup.step(BACKUP_PAGES_PER_STEP_V1),
            MAX_BACKUP_STEPS_V1,
            MAX_BACKUP_BUSY_OR_LOCKED_STEPS_V1,
            Duration::from_millis(1),
        )?;
        reach_backup_sqlite_online_backup_completed_v1(fault_probe);
        drop(backup);
        reach_backup_sqlite_online_backup_closed_v1(fault_probe);

        drop(self.destination_connection.take());
        let verification = Connection::open_with_flags(
            &self.coordinator_database,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| QuiescentBackupErrorV1::IntegrityFailed)?;
        let journal_mode: String = verification
            .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
            .map_err(|_| QuiescentBackupErrorV1::IntegrityFailed)?;
        if !journal_mode.eq_ignore_ascii_case("delete") {
            return Err(QuiescentBackupErrorV1::IntegrityFailed);
        }
        let integrity: String = verification
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| QuiescentBackupErrorV1::IntegrityFailed)?;
        if integrity != "ok" {
            return Err(QuiescentBackupErrorV1::IntegrityFailed);
        }
        drop(verification);
        for sidecar in [
            self.root.join("coordinator.sqlite3-wal"),
            self.root.join("coordinator.sqlite3-shm"),
        ] {
            match fs::remove_file(sidecar) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(QuiescentBackupErrorV1::IntegrityFailed),
            }
        }
        reach_backup_sqlite_online_backup_integrity_checked_v1(fault_probe);
        let database_length = fs::metadata(&self.coordinator_database)
            .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?
            .len();
        if database_length == 0 || database_length > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 {
            return Err(QuiescentBackupErrorV1::BackupFailed);
        }
        let digest = hash_file_v1(&self.coordinator_database)?;
        reach_backup_sqlite_online_backup_hashed_v1(fault_probe);
        Ok(digest)
    }

    fn begin_provider_export_v1(
        &self,
        index: usize,
        state: ProviderRecoveryStateV1,
    ) -> Result<ProviderBackupExportDestinationV1, QuiescentBackupErrorV1> {
        let package = self.provider_packages.join(format!("{index:016x}"));
        fs::create_dir(&package).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                QuiescentBackupErrorV1::DestinationExists
            } else {
                QuiescentBackupErrorV1::DestinationUnavailable
            }
        })?;
        match state {
            ProviderRecoveryStateV1::Published => Ok(ProviderBackupExportDestinationV1 {
                state,
                manifest: Some(create_new_member_v1(&package, "manifest.json")?),
                material: Some(create_new_member_v1(&package, "material.bin")?),
                retirement_manifest: None,
            }),
            ProviderRecoveryStateV1::RetiredTombstone => Ok(ProviderBackupExportDestinationV1 {
                state,
                manifest: None,
                material: None,
                retirement_manifest: Some(create_new_member_v1(
                    &package,
                    "retirement-manifest.json",
                )?),
            }),
        }
    }

    fn stage_canonical_member_v1(
        &self,
        kind: BackupJsonMemberV1,
        member: &CanonicalBackupMemberV1,
    ) -> Result<(), QuiescentBackupErrorV1> {
        let member_length = u64::try_from(member.bytes().len())
            .map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?;
        if member_length > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 {
            return Err(QuiescentBackupErrorV1::ManifestInvalid);
        }
        let path = self.staging.join(kind.file_name());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    QuiescentBackupErrorV1::DestinationExists
                } else {
                    QuiescentBackupErrorV1::DestinationUnavailable
                }
            })?;
        file.write_all(member.bytes())
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)
    }

    fn publish_staged_member_v1(
        &mut self,
        kind: BackupJsonMemberV1,
        fault_probe: &mut MaintenanceFaultProbeV1,
    ) -> Result<(), QuiescentBackupErrorV1> {
        self.publish_staged_member_with_cleanup_v1(kind, fault_probe, |path| fs::remove_file(path))
    }

    fn publish_staged_member_with_cleanup_v1<F>(
        &mut self,
        kind: BackupJsonMemberV1,
        fault_probe: &mut MaintenanceFaultProbeV1,
        cleanup: F,
    ) -> Result<(), QuiescentBackupErrorV1>
    where
        F: FnOnce(&Path) -> std::io::Result<()>,
    {
        let staged = self.staging.join(kind.file_name());
        let published = self.published.join(kind.file_name());
        fs::hard_link(&staged, &published).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                QuiescentBackupErrorV1::DestinationExists
            } else {
                QuiescentBackupErrorV1::PublicationFailed
            }
        })?;
        match kind {
            BackupJsonMemberV1::RecoveryInventory => {}
            BackupJsonMemberV1::TopLevelManifest => {
                reach_backup_top_level_manifest_published_v1(fault_probe);
            }
            BackupJsonMemberV1::Attestation => {
                self.attestation_published = true;
                reach_backup_attestation_published_v1(fault_probe);
            }
        }
        // The hard link is the publication point. Staging cleanup is deliberately
        // best-effort: an unlink refusal must not turn an already visible final member
        // into an uninstrumented or unverified publication failure.
        let _ = cleanup(&staged);
        Ok(())
    }

    fn reopen_published_member_v1(
        &self,
        kind: BackupJsonMemberV1,
    ) -> Result<Vec<u8>, QuiescentBackupErrorV1> {
        fs::read(self.published.join(kind.file_name()))
            .map_err(|_| QuiescentBackupErrorV1::PublicationFailed)
    }
}

fn drive_online_backup_steps_v1<F>(
    mut step: F,
    maximum_steps: usize,
    maximum_busy_or_locked_steps: usize,
    retry_pause: Duration,
) -> Result<(), QuiescentBackupErrorV1>
where
    F: FnMut() -> Result<StepResult, SqliteError>,
{
    let mut busy_or_locked = 0_usize;
    for _ in 0..maximum_steps {
        match step().map_err(|_| QuiescentBackupErrorV1::BackupFailed)? {
            StepResult::Done => return Ok(()),
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => {
                busy_or_locked = busy_or_locked
                    .checked_add(1)
                    .ok_or(QuiescentBackupErrorV1::BackupFailed)?;
                if busy_or_locked > maximum_busy_or_locked_steps {
                    return Err(QuiescentBackupErrorV1::BackupFailed);
                }
                std::thread::sleep(retry_pause);
            }
            _ => return Err(QuiescentBackupErrorV1::BackupFailed),
        }
    }
    Err(QuiescentBackupErrorV1::BackupFailed)
}

impl fmt::Debug for ProvisionedBackupDestinationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedBackupDestinationV1")
            .field("attestation_published", &self.attestation_published)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackupJsonMemberV1 {
    RecoveryInventory,
    TopLevelManifest,
    Attestation,
}

impl BackupJsonMemberV1 {
    const fn file_name(self) -> &'static str {
        match self {
            Self::RecoveryInventory => "recovery-inventory.json",
            Self::TopLevelManifest => "preparation-backup.json",
            Self::Attestation => "provenance-attestation.json",
        }
    }
}

fn hash_file_v1(path: &Path) -> Result<Sha256Digest, QuiescentBackupErrorV1> {
    let mut file = File::open(path).map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn coordinator_root_identity_digest_v1(identity: &[u8; 32]) -> Sha256Digest {
    Sha256Digest::digest(identity)
}

fn create_new_member_v1(
    parent: &Path,
    name: &str,
) -> Result<(File, PathBuf), QuiescentBackupErrorV1> {
    let path = parent.join(name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                QuiescentBackupErrorV1::DestinationExists
            } else {
                QuiescentBackupErrorV1::DestinationUnavailable
            }
        })?;
    Ok((file, path))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderBackupExportErrorV1 {
    Unavailable,
    Invalid,
}

/// Opaque create-only files supplied to one trusted provider export invocation.
pub(crate) struct ProviderBackupExportDestinationV1 {
    state: ProviderRecoveryStateV1,
    manifest: Option<(File, PathBuf)>,
    material: Option<(File, PathBuf)>,
    retirement_manifest: Option<(File, PathBuf)>,
}

impl ProviderBackupExportDestinationV1 {
    pub(crate) fn write_manifest_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), ProviderBackupExportErrorV1> {
        write_provider_member_v1(self.manifest.as_mut(), bytes)
    }

    pub(crate) fn write_material_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), ProviderBackupExportErrorV1> {
        write_provider_member_v1(self.material.as_mut(), bytes)
    }

    pub(crate) fn write_retirement_manifest_v1(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), ProviderBackupExportErrorV1> {
        write_provider_member_v1(self.retirement_manifest.as_mut(), bytes)
    }

    fn finish_v1(
        mut self,
        expected: &ProviderRecoveryInventoryEntryV1,
    ) -> Result<u64, QuiescentBackupErrorV1> {
        for member in [
            self.manifest.as_mut(),
            self.material.as_mut(),
            self.retirement_manifest.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            member
                .0
                .flush()
                .and_then(|()| member.0.sync_all())
                .map_err(|_| QuiescentBackupErrorV1::ProviderExportInvalid)?;
        }
        let exported_bytes = match self.state {
            ProviderRecoveryStateV1::Published => {
                let manifest = self
                    .manifest
                    .as_ref()
                    .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
                let material = self
                    .material
                    .as_ref()
                    .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
                let manifest_length = provider_export_member_length_v1(manifest)?;
                let material_length = provider_export_member_length_v1(material)?;
                if manifest_length < BACKUP_PACKAGE_MINIMUM_NONEMPTY_MEMBER_BYTES_V1
                    || hash_file_v1(&manifest.1)? != expected.manifest_digest
                    || hash_file_v1(&material.1)? != expected.material_digest
                    || material_length != expected.material_length
                    || self.retirement_manifest.is_some()
                {
                    return Err(QuiescentBackupErrorV1::ProviderExportInvalid);
                }
                manifest_length
                    .checked_add(material_length)
                    .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?
            }
            ProviderRecoveryStateV1::RetiredTombstone => {
                let retirement = self
                    .retirement_manifest
                    .as_ref()
                    .ok_or(QuiescentBackupErrorV1::ProviderExportInvalid)?;
                let retirement_length = provider_export_member_length_v1(retirement)?;
                if retirement_length < BACKUP_PACKAGE_MINIMUM_NONEMPTY_MEMBER_BYTES_V1
                    || self.manifest.is_some()
                    || self.material.is_some()
                    || expected.retirement_manifest_digest.is_none()
                    || hash_file_v1(&retirement.1)? != expected.retirement_manifest_digest.unwrap()
                {
                    return Err(QuiescentBackupErrorV1::ProviderExportInvalid);
                }
                retirement_length
            }
        };
        Ok(exported_bytes)
    }
}

impl fmt::Debug for ProviderBackupExportDestinationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBackupExportDestinationV1")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn write_provider_member_v1(
    member: Option<&mut (File, PathBuf)>,
    bytes: &[u8],
) -> Result<(), ProviderBackupExportErrorV1> {
    let member = member.ok_or(ProviderBackupExportErrorV1::Invalid)?;
    let current_length = member
        .0
        .metadata()
        .map_err(|_| ProviderBackupExportErrorV1::Unavailable)?
        .len();
    let additional_length =
        u64::try_from(bytes.len()).map_err(|_| ProviderBackupExportErrorV1::Invalid)?;
    let expected_length = current_length
        .checked_add(additional_length)
        .filter(|length| *length <= MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1)
        .ok_or(ProviderBackupExportErrorV1::Invalid)?;
    member
        .0
        .write_all(bytes)
        .map_err(|_| ProviderBackupExportErrorV1::Unavailable)?;
    if member
        .0
        .metadata()
        .map_err(|_| ProviderBackupExportErrorV1::Unavailable)?
        .len()
        != expected_length
    {
        return Err(ProviderBackupExportErrorV1::Invalid);
    }
    Ok(())
}

fn provider_export_member_length_v1(
    member: &(File, PathBuf),
) -> Result<u64, QuiescentBackupErrorV1> {
    let length = member
        .0
        .metadata()
        .map_err(|_| QuiescentBackupErrorV1::ProviderExportInvalid)?
        .len();
    if length > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 {
        return Err(QuiescentBackupErrorV1::ProviderExportInvalid);
    }
    Ok(length)
}

/// Trusted provider export under the same provider-wide custody held by the cut.
pub(crate) trait GuardedRecoveryBackupExporterV1: Send + Sync {
    type Custody: ProviderMaintenanceGuardV1;

    fn export_recovery_backup_package_v1(
        &self,
        custody: &mut Self::Custody,
        entry: &ProviderRecoveryInventoryEntryV1,
        destination: &mut ProviderBackupExportDestinationV1,
    ) -> Result<(), ProviderBackupExportErrorV1>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BackupPendingRetirementCountsV1 {
    pub(crate) coordinator_operation_pending: u64,
    pub(crate) coordinator_orphan_pending: u64,
    pub(crate) provider_operation_pending: u64,
    pub(crate) provider_orphan_pending: u64,
}

impl BackupPendingRetirementCountsV1 {
    const fn all_zero(self) -> bool {
        self.coordinator_operation_pending == 0
            && self.coordinator_orphan_pending == 0
            && self.provider_operation_pending == 0
            && self.provider_orphan_pending == 0
    }
}

pub(crate) struct CanonicalBackupMemberV1 {
    bytes: Vec<u8>,
    sha256: Sha256Digest,
}

impl CanonicalBackupMemberV1 {
    pub(crate) fn try_new(bytes: Vec<u8>) -> Result<Self, QuiescentBackupErrorV1> {
        let byte_length =
            u64::try_from(bytes.len()).map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?;
        if bytes.is_empty()
            || byte_length > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1
            || bytes.starts_with(&[0xEF, 0xBB, 0xBF])
            || bytes.ends_with(b"\n")
        {
            return Err(QuiescentBackupErrorV1::ManifestInvalid);
        }
        Ok(Self {
            sha256: Sha256Digest::digest(&bytes),
            bytes,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn sha256(&self) -> Sha256Digest {
        self.sha256
    }
}

impl fmt::Debug for CanonicalBackupMemberV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalBackupMemberV1")
            .field("byte_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct BackupProviderGenerationV1 {
    pub(crate) provider_profile_id: Identifier,
    pub(crate) provider_profile_version: u16,
    pub(crate) provider_id: Identifier,
    pub(crate) provider_generation: u64,
}

impl fmt::Debug for BackupProviderGenerationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupProviderGenerationV1")
            .finish_non_exhaustive()
    }
}

pub(crate) struct FinalizedRecoveryInventoryV1 {
    pub(crate) member: CanonicalBackupMemberV1,
    pub(crate) provider_set_count: u64,
    pub(crate) entry_count: u64,
    pub(crate) provider_generations: Vec<BackupProviderGenerationV1>,
}

impl fmt::Debug for FinalizedRecoveryInventoryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedRecoveryInventoryV1")
            .field("provider_set_count", &self.provider_set_count)
            .field("entry_count", &self.entry_count)
            .finish_non_exhaustive()
    }
}

pub(crate) struct BackupTopLevelCodecInputV1 {
    pub(crate) source_coordinator_root_identity_sha256: Sha256Digest,
    pub(crate) source_recovery_root_identity_sha256: Sha256Digest,
    pub(crate) source_instance_identity_sha256: Sha256Digest,
    pub(crate) coordinator_schema_sha256: Sha256Digest,
    pub(crate) coordinator_database_sha256: Sha256Digest,
    pub(crate) at_rest_profile_id: Identifier,
    pub(crate) generations: CoordinatorBackupGenerationsV1,
    pub(crate) counts: CoordinatorBackupCountsV1,
    pub(crate) recovery_inventory_sha256: Sha256Digest,
    pub(crate) recovery_provider_set_count: u64,
    pub(crate) recovery_entry_count: u64,
}

pub(crate) struct BackupProtectedCodecInputV1 {
    pub(crate) top_level_manifest_sha256: Sha256Digest,
    pub(crate) source_coordinator_root_identity_sha256: Sha256Digest,
    pub(crate) source_recovery_root_identity_sha256: Sha256Digest,
    pub(crate) source_instance_identity_sha256: Sha256Digest,
    pub(crate) coordinator_generations: CoordinatorBackupGenerationsV1,
    pub(crate) recovery_inventory_sha256: Sha256Digest,
    pub(crate) recovery_entry_count: u64,
    pub(crate) recovery_provider_generations: Vec<BackupProviderGenerationV1>,
    pub(crate) at_rest_profile_id: Identifier,
    pub(crate) attestation_profile_id: Identifier,
    pub(crate) attestation_profile_version: u16,
    pub(crate) key_id: Identifier,
}

macro_rules! redacted_backup_input_debug {
    ($($type:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter
                        .debug_struct(stringify!($type))
                        .finish_non_exhaustive()
                }
            }
        )+
    };
}

redacted_backup_input_debug!(BackupTopLevelCodecInputV1, BackupProtectedCodecInputV1);

/// Closed codec seam. The production implementation in `manifest.rs` is the sole
/// adapter to the four T070 schema builders and pinned provenance verifier.
pub(crate) trait QuiescentBackupManifestCodecV1 {
    fn finalize_inventory_v1(
        &mut self,
        entries: &[ProviderRecoveryInventoryEntryV1],
        pending: BackupPendingRetirementCountsV1,
    ) -> Result<FinalizedRecoveryInventoryV1, QuiescentBackupErrorV1>;

    fn finalize_top_level_v1(
        &mut self,
        input: BackupTopLevelCodecInputV1,
        pending: BackupPendingRetirementCountsV1,
    ) -> Result<CanonicalBackupMemberV1, QuiescentBackupErrorV1>;

    fn finalize_protected_v1(
        &mut self,
        input: &BackupProtectedCodecInputV1,
    ) -> Result<CanonicalBackupMemberV1, QuiescentBackupErrorV1>;

    fn finalize_attestation_v1(
        &mut self,
        input: &BackupProtectedCodecInputV1,
        signature: [u8; 64],
    ) -> Result<CanonicalBackupMemberV1, QuiescentBackupErrorV1>;

    fn verify_reopened_package_v1(
        &mut self,
        attestation: &[u8],
        top_level: &[u8],
        inventory: &[u8],
        pending: BackupPendingRetirementCountsV1,
    ) -> Result<(), QuiescentBackupErrorV1>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvisionerBackupSigningErrorV1 {
    Unavailable,
    Refused,
}

/// Provisioner-owned signing custody exposes only identity and a domain-specific sign
/// operation; raw private key bytes never enter the coordinator.
pub(crate) trait ProvisionerBackupSigningCustodyV1: Send {
    fn attestation_profile_id_v1(&self) -> &Identifier;
    fn attestation_profile_version_v1(&self) -> u16;
    fn key_id_v1(&self) -> &Identifier;

    fn sign_backup_attestation_v1(
        &mut self,
        domain_separated_message: &[u8],
    ) -> Result<[u8; 64], ProvisionerBackupSigningErrorV1>;
}

pub(crate) struct VerifiedPreparationBackupV1 {
    destination: ProvisionedBackupDestinationV1,
    inventory_sha256: Sha256Digest,
    top_level_manifest_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    provider_set_count: u64,
    entry_count: u64,
}

impl VerifiedPreparationBackupV1 {
    pub(crate) const fn inventory_sha256(&self) -> Sha256Digest {
        self.inventory_sha256
    }

    pub(crate) const fn top_level_manifest_sha256(&self) -> Sha256Digest {
        self.top_level_manifest_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(&self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn provider_set_count(&self) -> u64 {
        self.provider_set_count
    }

    pub(crate) const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub(crate) fn into_destination(self) -> ProvisionedBackupDestinationV1 {
        self.destination
    }
}

impl fmt::Debug for VerifiedPreparationBackupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPreparationBackupV1")
            .field("provider_set_count", &self.provider_set_count)
            .field("entry_count", &self.entry_count)
            .finish_non_exhaustive()
    }
}

/// Completes and verifies one package while all three T069 custodians remain live.
pub(crate) fn complete_quiescent_backup_v1<P, R, E, S, C>(
    mut cut: QuiescentBackupCutV1<'_, '_, P, R>,
    exporter: &E,
    mut destination: ProvisionedBackupDestinationV1,
    at_rest_profile_id: Identifier,
    signer: &mut S,
    codec: &mut C,
) -> Result<VerifiedPreparationBackupV1, QuiescentBackupErrorV1>
where
    P: PausedBackupCustodyV1,
    R: ProviderMaintenanceGuardV1,
    E: GuardedRecoveryBackupExporterV1<Custody = R>,
    S: ProvisionerBackupSigningCustodyV1,
    C: QuiescentBackupManifestCodecV1,
{
    let result = complete_quiescent_backup_under_cut_v1(
        &mut cut,
        exporter,
        &mut destination,
        at_rest_profile_id,
        signer,
        codec,
    );
    let release = cut.release_v1();
    match result {
        Ok(verified) => {
            release?;
            Ok(VerifiedPreparationBackupV1 {
                destination,
                inventory_sha256: verified.inventory_sha256,
                top_level_manifest_sha256: verified.top_level_manifest_sha256,
                provenance_attestation_sha256: verified.provenance_attestation_sha256,
                provider_set_count: verified.provider_set_count,
                entry_count: verified.entry_count,
            })
        }
        Err(error) => {
            let _ = release;
            Err(error)
        }
    }
}

struct VerifiedBackupBindingsV1 {
    inventory_sha256: Sha256Digest,
    top_level_manifest_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    provider_set_count: u64,
    entry_count: u64,
}

fn provider_inventory_package_binding_sha256_v1(
    entry: &ProviderRecoveryInventoryEntryV1,
) -> Result<Sha256Digest, QuiescentBackupErrorV1> {
    fn append_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), QuiescentBackupErrorV1> {
        let length =
            u16::try_from(value.len()).map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    let evidence_class = match entry.evidence_class() {
        RecoveryEvidenceClassV1::SyntheticConformance => "SYNTHETIC_CONFORMANCE",
        RecoveryEvidenceClassV1::ApprovedProduction => "APPROVED_PRODUCTION",
    };
    let custody = match entry.custody() {
        ProviderRecoveryCustodyV1::OperationBound => "OPERATION_BOUND",
        ProviderRecoveryCustodyV1::QuarantinedOrphan => "QUARANTINED_ORPHAN",
        ProviderRecoveryCustodyV1::OrphanResolutionTombstone => "ORPHAN_RESOLUTION_TOMBSTONE",
    };
    let state = match entry.state() {
        ProviderRecoveryStateV1::Published => "MATERIAL_PRESENT",
        ProviderRecoveryStateV1::RetiredTombstone => "RETIRED_TOMBSTONE",
    };
    let mut preimage = Vec::with_capacity(384);
    preimage.extend_from_slice(RECOVERY_PACKAGE_BINDING_DOMAIN_V1);
    append_string(&mut preimage, entry.provider_profile_id().as_str())?;
    preimage.extend_from_slice(&u64::from(entry.provider_profile_version()).to_be_bytes());
    append_string(&mut preimage, entry.provider_id().as_str())?;
    preimage.extend_from_slice(&entry.provider_generation().to_be_bytes());
    append_string(&mut preimage, evidence_class)?;
    append_string(&mut preimage, entry.at_rest_profile_id().as_str())?;
    append_string(&mut preimage, custody)?;
    append_string(&mut preimage, state)?;
    preimage.extend_from_slice(entry.manifest_digest().as_bytes());
    preimage.extend_from_slice(entry.material_digest().as_bytes());
    preimage.extend_from_slice(&entry.material_length().to_be_bytes());
    preimage.extend_from_slice(&entry.reserved_capacity().to_be_bytes());
    match entry.retirement_manifest_digest() {
        None => preimage.push(0),
        Some(digest) => {
            preimage.push(1);
            preimage.extend_from_slice(digest.as_bytes());
        }
    }
    Ok(Sha256Digest::digest(&preimage))
}

fn complete_quiescent_backup_under_cut_v1<P, R, E, S, C>(
    cut: &mut QuiescentBackupCutV1<'_, '_, P, R>,
    exporter: &E,
    destination: &mut ProvisionedBackupDestinationV1,
    at_rest_profile_id: Identifier,
    signer: &mut S,
    codec: &mut C,
) -> Result<VerifiedBackupBindingsV1, QuiescentBackupErrorV1>
where
    P: PausedBackupCustodyV1,
    R: ProviderMaintenanceGuardV1,
    E: GuardedRecoveryBackupExporterV1<Custody = R>,
    S: ProvisionerBackupSigningCustodyV1,
    C: QuiescentBackupManifestCodecV1,
{
    // Fail before copying or publishing when the authenticated inventory cannot possibly fit
    // the restore-side directory/file/member/aggregate bounds.
    let projected_database_length = projected_backup_sqlite_length_v1(cut.source_connection())?;
    validate_backup_package_resource_shape_v1(
        &cut.inventory.provider_entries,
        projected_database_length,
    )?;
    let coordinator_database_sha256 =
        destination.backup_sqlite_v1(cut.backup_source, &mut cut.fault_probe)?;
    let database_length = fs::metadata(&destination.coordinator_database)
        .map_err(|_| QuiescentBackupErrorV1::DestinationUnavailable)?
        .len();
    if database_length != projected_database_length {
        return Err(QuiescentBackupErrorV1::SourceChanged);
    }
    let mut worst_case_package_bytes = 0_u64;
    account_backup_package_member_bytes_v1(
        &mut worst_case_package_bytes,
        database_length,
        1,
        QuiescentBackupErrorV1::BackupFailed,
    )?;
    cut.reenumerate_and_compare_inventory_v1()?;
    reach_provider_enumeration_reconciled_v1(&mut cut.fault_probe);

    let mut bound_entries = Vec::new();
    bound_entries
        .try_reserve_exact(cut.inventory.provider_entries.len())
        .map_err(|_| QuiescentBackupErrorV1::BackupFailed)?;
    for entry in cut.inventory.provider_entries.clone() {
        let package_binding = provider_inventory_package_binding_sha256_v1(&entry)?;
        bound_entries.push((package_binding, entry));
    }
    bound_entries.sort_by(|(left_binding, left), (right_binding, right)| {
        left.provider_profile_id()
            .as_str()
            .cmp(right.provider_profile_id().as_str())
            .then_with(|| {
                left.provider_id()
                    .as_str()
                    .cmp(right.provider_id().as_str())
            })
            .then_with(|| left.provider_generation().cmp(&right.provider_generation()))
            .then_with(|| left_binding.as_bytes().cmp(right_binding.as_bytes()))
    });
    let entries = bound_entries
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();
    for (index, entry) in entries.iter().enumerate() {
        let mut export = destination.begin_provider_export_v1(index, entry.state)?;
        exporter
            .export_recovery_backup_package_v1(cut.provider_custody_mut_v1()?, entry, &mut export)
            .map_err(|error| match error {
                ProviderBackupExportErrorV1::Unavailable => {
                    QuiescentBackupErrorV1::ProviderExportUnavailable
                }
                ProviderBackupExportErrorV1::Invalid => {
                    QuiescentBackupErrorV1::ProviderExportInvalid
                }
            })?;
        let exported_bytes = export.finish_v1(entry)?;
        account_backup_package_bytes_v1(
            &mut worst_case_package_bytes,
            exported_bytes,
            QuiescentBackupErrorV1::ProviderExportInvalid,
        )?;
        match entry.state {
            ProviderRecoveryStateV1::Published => {
                reach_backup_material_present_package_exported_v1(&mut cut.fault_probe)
            }
            ProviderRecoveryStateV1::RetiredTombstone => {
                reach_backup_retirement_tombstone_exported_v1(&mut cut.fault_probe)
            }
        }
    }

    let pending = BackupPendingRetirementCountsV1 {
        coordinator_operation_pending: cut.inventory.operation_retirement_pending,
        coordinator_orphan_pending: cut.inventory.orphan_retirement_pending,
        provider_operation_pending: cut.recovery_source.operation_retirement_pending(),
        provider_orphan_pending: cut.recovery_source.orphan_retirement_pending(),
    };
    if !pending.all_zero() {
        return Err(QuiescentBackupErrorV1::RetirementPending);
    }
    let inventory = codec.finalize_inventory_v1(&entries, pending)?;
    reach_backup_inventory_jcs_finalized_v1(&mut cut.fault_probe);
    account_backup_package_member_bytes_v1(
        &mut worst_case_package_bytes,
        u64::try_from(inventory.member.bytes().len())
            .map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?,
        2,
        QuiescentBackupErrorV1::ManifestInvalid,
    )?;
    destination
        .stage_canonical_member_v1(BackupJsonMemberV1::RecoveryInventory, &inventory.member)?;
    destination
        .publish_staged_member_v1(BackupJsonMemberV1::RecoveryInventory, &mut cut.fault_probe)?;

    #[cfg(not(test))]
    {
        let clock = cut.backup_clock;
        let deadline_monotonic_ms = cut.backup_deadline_monotonic_ms;
        cut.recheck_source_generations_v1(clock, deadline_monotonic_ms)?;
    }
    #[cfg(test)]
    cut.recheck_source_generations_v1()?;

    let recovery_source = cut.recovery_source().clone();
    let top_level = codec.finalize_top_level_v1(
        BackupTopLevelCodecInputV1 {
            source_coordinator_root_identity_sha256: cut.source_coordinator_root_identity_sha256(),
            source_recovery_root_identity_sha256: recovery_source.recovery_root_identity_sha256(),
            source_instance_identity_sha256: recovery_source.instance_identity_sha256(),
            coordinator_schema_sha256: cut.coordinator_schema_sha256(),
            coordinator_database_sha256,
            at_rest_profile_id: at_rest_profile_id.clone(),
            generations: cut.coordinator_generations(),
            counts: cut.coordinator_counts(),
            recovery_inventory_sha256: inventory.member.sha256(),
            recovery_provider_set_count: inventory.provider_set_count,
            recovery_entry_count: inventory.entry_count,
        },
        pending,
    )?;
    account_backup_package_member_bytes_v1(
        &mut worst_case_package_bytes,
        u64::try_from(top_level.bytes().len())
            .map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?,
        2,
        QuiescentBackupErrorV1::ManifestInvalid,
    )?;
    destination.stage_canonical_member_v1(BackupJsonMemberV1::TopLevelManifest, &top_level)?;
    reach_backup_top_level_manifest_staged_v1(&mut cut.fault_probe);
    destination
        .publish_staged_member_v1(BackupJsonMemberV1::TopLevelManifest, &mut cut.fault_probe)?;

    let protected_input = BackupProtectedCodecInputV1 {
        top_level_manifest_sha256: top_level.sha256(),
        source_coordinator_root_identity_sha256: cut.source_coordinator_root_identity_sha256(),
        source_recovery_root_identity_sha256: recovery_source.recovery_root_identity_sha256(),
        source_instance_identity_sha256: recovery_source.instance_identity_sha256(),
        coordinator_generations: cut.coordinator_generations(),
        recovery_inventory_sha256: inventory.member.sha256(),
        recovery_entry_count: inventory.entry_count,
        recovery_provider_generations: inventory.provider_generations.clone(),
        at_rest_profile_id,
        attestation_profile_id: signer.attestation_profile_id_v1().clone(),
        attestation_profile_version: signer.attestation_profile_version_v1(),
        key_id: signer.key_id_v1().clone(),
    };
    let protected = codec.finalize_protected_v1(&protected_input)?;
    reach_backup_attestation_protected_jcs_finalized_v1(&mut cut.fault_probe);
    let mut signing_message =
        Vec::with_capacity(BACKUP_ATTESTATION_DOMAIN_V1.len() + protected.bytes().len());
    signing_message.extend_from_slice(BACKUP_ATTESTATION_DOMAIN_V1);
    signing_message.extend_from_slice(protected.bytes());
    let signature = signer
        .sign_backup_attestation_v1(&signing_message)
        .map_err(|_| QuiescentBackupErrorV1::SigningUnavailable)?;
    reach_backup_attestation_signed_v1(&mut cut.fault_probe);
    let attestation = codec.finalize_attestation_v1(&protected_input, signature)?;
    account_backup_package_member_bytes_v1(
        &mut worst_case_package_bytes,
        u64::try_from(attestation.bytes().len())
            .map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?,
        2,
        QuiescentBackupErrorV1::ManifestInvalid,
    )?;
    destination.stage_canonical_member_v1(BackupJsonMemberV1::Attestation, &attestation)?;
    reach_backup_attestation_staged_v1(&mut cut.fault_probe);
    destination.publish_staged_member_v1(BackupJsonMemberV1::Attestation, &mut cut.fault_probe)?;

    let reopened_attestation =
        destination.reopen_published_member_v1(BackupJsonMemberV1::Attestation)?;
    reach_backup_attestation_reopened_v1(&mut cut.fault_probe);
    let reopened_top_level =
        destination.reopen_published_member_v1(BackupJsonMemberV1::TopLevelManifest)?;
    let reopened_inventory =
        destination.reopen_published_member_v1(BackupJsonMemberV1::RecoveryInventory)?;
    if reopened_attestation != attestation.bytes()
        || reopened_top_level != top_level.bytes()
        || reopened_inventory != inventory.member.bytes()
    {
        return Err(QuiescentBackupErrorV1::ProvenanceInvalid);
    }
    codec.verify_reopened_package_v1(
        &reopened_attestation,
        &reopened_top_level,
        &reopened_inventory,
        pending,
    )?;
    reach_backup_attestation_verified_v1(&mut cut.fault_probe);

    Ok(VerifiedBackupBindingsV1 {
        inventory_sha256: inventory.member.sha256(),
        top_level_manifest_sha256: top_level.sha256(),
        provenance_attestation_sha256: attestation.sha256(),
        provider_set_count: inventory.provider_set_count,
        entry_count: inventory.entry_count,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorBackupGenerationsV1 {
    store: u64,
    operation: u64,
    budget: u64,
    event: u64,
    quarantine: u64,
}

impl CoordinatorBackupGenerationsV1 {
    pub(crate) const fn store(self) -> u64 {
        self.store
    }

    pub(crate) const fn operation(self) -> u64 {
        self.operation
    }

    pub(crate) const fn budget(self) -> u64 {
        self.budget
    }

    pub(crate) const fn event(self) -> u64 {
        self.event
    }

    pub(crate) const fn quarantine(self) -> u64 {
        self.quarantine
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorBackupCountsV1 {
    budget_scopes: u64,
    operations: u64,
    operation_transitions: u64,
    held_reservations: u64,
    released_reservations: u64,
    pending_events: u64,
    delivered_events: u64,
    active_quarantines: u64,
    resolved_quarantines: u64,
}

impl CoordinatorBackupCountsV1 {
    pub(crate) const fn budget_scopes(self) -> u64 {
        self.budget_scopes
    }

    pub(crate) const fn operations(self) -> u64 {
        self.operations
    }

    pub(crate) const fn operation_transitions(self) -> u64 {
        self.operation_transitions
    }

    pub(crate) const fn held_reservations(self) -> u64 {
        self.held_reservations
    }

    pub(crate) const fn released_reservations(self) -> u64 {
        self.released_reservations
    }

    pub(crate) const fn pending_events(self) -> u64 {
        self.pending_events
    }

    pub(crate) const fn delivered_events(self) -> u64 {
        self.delivered_events
    }

    pub(crate) const fn active_quarantines(self) -> u64 {
        self.active_quarantines
    }

    pub(crate) const fn resolved_quarantines(self) -> u64 {
        self.resolved_quarantines
    }
}

pub(crate) struct CoordinatorMaintenanceGuardV1<'connection> {
    transaction: Transaction<'connection>,
}

impl CoordinatorMaintenanceGuardV1<'_> {
    pub(crate) fn source_connection(&self) -> &Connection {
        &self.transaction
    }

    fn rollback(self) -> Result<(), QuiescentBackupErrorV1> {
        self.transaction
            .rollback()
            .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnavailable)
    }

    #[cfg(not(test))]
    fn transaction_v1(&self) -> &Transaction<'_> {
        &self.transaction
    }

    #[cfg(not(test))]
    fn commit(self) -> Result<(), QuiescentBackupErrorV1> {
        self.transaction
            .commit()
            .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnavailable)
    }
}

impl fmt::Debug for CoordinatorMaintenanceGuardV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorMaintenanceGuardV1")
            .finish_non_exhaustive()
    }
}

/// Live quiescent source cut retained through package publication and final recheck.
///
/// The cut is linear custody. Dropping it without explicit completion still rolls back
/// the coordinator guard and releases provider/PAUSE custody in reverse acquisition
/// order; callers cannot accidentally strand maintenance mode on an early return.
#[must_use = "dropping the cut releases all backup maintenance custody"]
pub(crate) struct QuiescentBackupCutV1<
    'source,
    'guard,
    PauseCustody: PausedBackupCustodyV1,
    ProviderCustody: ProviderMaintenanceGuardV1,
> {
    backup_source: &'source Connection,
    inventory_provider: &'source dyn GuardedRecoveryInventoryProviderV1<Custody = ProviderCustody>,
    #[cfg(not(test))]
    pair_custody: &'source mut BoundCoordinatorBackupCustodyV1,
    #[cfg(not(test))]
    backup_clock: &'source dyn CoordinatorMonotonicClockV1,
    #[cfg(not(test))]
    backup_deadline_monotonic_ms: u64,
    pause_custody: Option<PauseCustody>,
    provider_custody: Option<ProviderCustody>,
    coordinator_guard: Option<CoordinatorMaintenanceGuardV1<'guard>>,
    paused_source: PausedBackupSourceV1,
    recovery_source: RecoveryMaintenanceSourceV1,
    coordinator_generations: CoordinatorBackupGenerationsV1,
    coordinator_counts: CoordinatorBackupCountsV1,
    inventory: ReconciledRecoveryInventoryV1,
    source_coordinator_root_identity_sha256: Sha256Digest,
    coordinator_schema_sha256: Sha256Digest,
    fault_probe: MaintenanceFaultProbeV1,
}

impl<P, R> fmt::Debug for QuiescentBackupCutV1<'_, '_, P, R>
where
    P: PausedBackupCustodyV1,
    R: ProviderMaintenanceGuardV1,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuiescentBackupCutV1")
            .finish_non_exhaustive()
    }
}

impl<P, R> QuiescentBackupCutV1<'_, '_, P, R>
where
    P: PausedBackupCustodyV1,
    R: ProviderMaintenanceGuardV1,
{
    pub(crate) fn source_connection(&self) -> &Connection {
        self.backup_source
    }

    pub(crate) const fn recovery_source(&self) -> &RecoveryMaintenanceSourceV1 {
        &self.recovery_source
    }

    pub(crate) const fn coordinator_generations(&self) -> CoordinatorBackupGenerationsV1 {
        self.coordinator_generations
    }

    pub(crate) const fn coordinator_counts(&self) -> CoordinatorBackupCountsV1 {
        self.coordinator_counts
    }

    pub(crate) const fn inventory(&self) -> &ReconciledRecoveryInventoryV1 {
        &self.inventory
    }

    fn provider_custody_mut_v1(&mut self) -> Result<&mut R, QuiescentBackupErrorV1> {
        self.provider_custody
            .as_mut()
            .ok_or(QuiescentBackupErrorV1::ProviderUnavailable)
    }

    fn coordinator_source_connection_v1(&self) -> Result<&Connection, QuiescentBackupErrorV1> {
        self.coordinator_guard
            .as_ref()
            .map(CoordinatorMaintenanceGuardV1::source_connection)
            .ok_or(QuiescentBackupErrorV1::CoordinatorUnavailable)
    }

    /// Performs the normative post-backup provider enumeration at its actual fault
    /// boundary and proves it is byte-for-byte the inventory captured by the cut.
    fn reenumerate_and_compare_inventory_v1(&mut self) -> Result<(), QuiescentBackupErrorV1> {
        let provider_entries = self
            .inventory_provider
            .enumerate_recovery_inventory_v1(
                self.provider_custody
                    .as_mut()
                    .ok_or(QuiescentBackupErrorV1::ProviderUnavailable)?,
            )
            .map_err(|error| match error {
                ProviderRecoveryEnumerationErrorV1::Unavailable => {
                    QuiescentBackupErrorV1::ProviderUnavailable
                }
                ProviderRecoveryEnumerationErrorV1::Unhealthy => {
                    QuiescentBackupErrorV1::ProviderUnhealthy
                }
            })?;
        #[cfg(test)]
        {
            if provider_entries == self.inventory.provider_entries {
                Ok(())
            } else {
                Err(QuiescentBackupErrorV1::SourceChanged)
            }
        }
        #[cfg(not(test))]
        {
            let coordinator = self
                .coordinator_guard
                .as_ref()
                .map(CoordinatorMaintenanceGuardV1::source_connection)
                .ok_or(QuiescentBackupErrorV1::CoordinatorUnavailable)?;
            let outcome = reconcile_enumerated_inventory_v1(coordinator, provider_entries)
                .map_err(map_reconciliation_to_inventory_recheck_error_v1)?;
            match outcome {
                RecoveryMaintenanceOutcomeV1::Ready(actual) if actual == self.inventory => Ok(()),
                RecoveryMaintenanceOutcomeV1::Ready(_)
                | RecoveryMaintenanceOutcomeV1::BackupBlocked(_) => {
                    Err(QuiescentBackupErrorV1::SourceChanged)
                }
            }
        }
    }

    pub(crate) const fn source_coordinator_root_identity_sha256(&self) -> Sha256Digest {
        self.source_coordinator_root_identity_sha256
    }

    pub(crate) const fn coordinator_schema_sha256(&self) -> Sha256Digest {
        self.coordinator_schema_sha256
    }

    #[cfg(not(test))]
    /// Revalidates root/file custody plus all three live source domains before publish.
    pub(crate) fn recheck_source_generations_v1<C>(
        &mut self,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<(), QuiescentBackupErrorV1>
    where
        C: CoordinatorMonotonicClockV1 + ?Sized,
    {
        self.pair_custody
            .revalidate(clock, deadline_monotonic_ms)
            .map_err(map_backup_pair_revalidation_error_v1)?;
        self.recheck_logical_source_generations_v1()
    }

    #[cfg(test)]
    pub(crate) fn recheck_source_generations_v1(&mut self) -> Result<(), QuiescentBackupErrorV1> {
        self.recheck_logical_source_generations_v1()
    }

    fn recheck_logical_source_generations_v1(&mut self) -> Result<(), QuiescentBackupErrorV1> {
        let pause_custody = self
            .pause_custody
            .as_mut()
            .ok_or(QuiescentBackupErrorV1::PauseUnavailable)?;
        map_pause_validation_v1(pause_custody.recheck_paused_source_v1(&self.paused_source))?;
        let provider_custody = self
            .provider_custody
            .as_mut()
            .ok_or(QuiescentBackupErrorV1::ProviderUnavailable)?;
        map_provider_validation_v1(
            provider_custody.recheck_recovery_source_v1(&self.recovery_source),
        )?;
        let source_observed = capture_coordinator_backup_state_v1(self.backup_source)?;
        let guard_observed =
            capture_coordinator_backup_state_v1(self.coordinator_source_connection_v1()?)?;
        if source_observed.0 != self.coordinator_generations
            || source_observed.1 != self.coordinator_counts
            || guard_observed != source_observed
        {
            return Err(QuiescentBackupErrorV1::SourceChanged);
        }
        reach_backup_source_generations_rechecked_v1(&mut self.fault_probe);
        Ok(())
    }

    /// Releases in reverse acquisition order after publication or refusal.
    pub(crate) fn release_v1(mut self) -> Result<(), QuiescentBackupErrorV1> {
        self.release_all_custody_v1()
    }

    fn release_all_custody_v1(&mut self) -> Result<(), QuiescentBackupErrorV1> {
        let rollback = self
            .coordinator_guard
            .take()
            .map_or(Ok(()), CoordinatorMaintenanceGuardV1::rollback);
        if let Some(provider_custody) = self.provider_custody.take() {
            provider_custody.release();
        }
        if let Some(pause_custody) = self.pause_custody.take() {
            pause_custody.release();
        }
        rollback
    }
}

impl<P, R> Drop for QuiescentBackupCutV1<'_, '_, P, R>
where
    P: PausedBackupCustodyV1,
    R: ProviderMaintenanceGuardV1,
{
    fn drop(&mut self) {
        let _ = self.release_all_custody_v1();
    }
}

/// Acquires PAUSE, provider-wide custody and the coordinator writer in the normative order.
#[cfg(not(test))]
pub(crate) fn begin_quiescent_backup_cut_v1<'source, A, P, K>(
    pair: &'source mut BoundCoordinatorBackupPairV1,
    pause_authority: &A,
    provider: &'source P,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &K,
    clock: &'source dyn CoordinatorMonotonicClockV1,
    deadline_monotonic_ms: u64,
) -> Result<QuiescentBackupCutV1<'source, 'source, A::Custody, P::Custody>, QuiescentBackupErrorV1>
where
    A: BackupPauseAuthorityV1,
    P: QuiescentRecoveryMaintenanceProviderV1,
    P::Custody: ProviderMaintenanceGuardV1,
    K: Ed25519KeyResolver,
{
    begin_quiescent_backup_cut_with_probe_v1(
        pair,
        pause_authority,
        provider,
        expected_root_identity,
        historical_plan_keys,
        clock,
        deadline_monotonic_ms,
        MaintenanceFaultProbeV1::disabled_v1(),
    )
}

#[cfg(not(test))]
#[allow(clippy::too_many_arguments)]
fn begin_quiescent_backup_cut_with_probe_v1<'source, A, P, K>(
    pair: &'source mut BoundCoordinatorBackupPairV1,
    pause_authority: &A,
    provider: &'source P,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &K,
    clock: &'source dyn CoordinatorMonotonicClockV1,
    deadline_monotonic_ms: u64,
    mut fault_probe: MaintenanceFaultProbeV1,
) -> Result<QuiescentBackupCutV1<'source, 'source, A::Custody, P::Custody>, QuiescentBackupErrorV1>
where
    A: BackupPauseAuthorityV1,
    P: QuiescentRecoveryMaintenanceProviderV1,
    P::Custody: ProviderMaintenanceGuardV1,
    K: Ed25519KeyResolver,
{
    if !pair
        .expected_root_identity()
        .matches(expected_root_identity.as_bytes())
    {
        return Err(QuiescentBackupErrorV1::SourceChanged);
    }
    pair.revalidate(clock, deadline_monotonic_ms)
        .map_err(map_backup_pair_revalidation_error_v1)?;
    let mut pause_custody = match pause_authority.persist_pause_for_backup_v1(deadline_monotonic_ms)
    {
        PausedBackupCustodyOutcomeV1::Acquired(custody) => custody,
        PausedBackupCustodyOutcomeV1::Contended => {
            return Err(QuiescentBackupErrorV1::PauseContended)
        }
        PausedBackupCustodyOutcomeV1::Unavailable => {
            return Err(QuiescentBackupErrorV1::PauseUnavailable)
        }
        PausedBackupCustodyOutcomeV1::DeadlineReached => {
            return Err(QuiescentBackupErrorV1::PauseDeadlineReached)
        }
        PausedBackupCustodyOutcomeV1::Unsupported => {
            return Err(QuiescentBackupErrorV1::PauseUnsupported)
        }
    };
    let paused_source = match pause_custody.capture_paused_source_v1() {
        Ok(source) => source,
        Err(validation) => {
            pause_custody.release();
            return Err(map_pause_validation_error_v1(validation));
        }
    };
    reach_backup_pause_persisted_v1(&mut fault_probe);

    let mut provider_custody =
        match provider.acquire_provider_maintenance_guard_v1(deadline_monotonic_ms) {
            ProviderMaintenanceGuardOutcomeV1::Acquired(custody) => custody,
            ProviderMaintenanceGuardOutcomeV1::Contended => {
                pause_custody.release();
                return Err(QuiescentBackupErrorV1::ProviderContended);
            }
            ProviderMaintenanceGuardOutcomeV1::Unavailable => {
                pause_custody.release();
                return Err(QuiescentBackupErrorV1::ProviderUnavailable);
            }
            ProviderMaintenanceGuardOutcomeV1::DeadlineReached => {
                pause_custody.release();
                return Err(QuiescentBackupErrorV1::ProviderDeadlineReached);
            }
            ProviderMaintenanceGuardOutcomeV1::Unsupported => {
                pause_custody.release();
                return Err(QuiescentBackupErrorV1::ProviderUnsupported);
            }
        };
    reach_backup_provider_maintenance_guard_acquired_v1(&mut fault_probe);

    let recovery_source = match provider_custody.capture_recovery_source_v1() {
        Ok(source) => source,
        Err(validation) => {
            provider_custody.release();
            pause_custody.release();
            return Err(map_provider_validation_error_v1(validation));
        }
    };
    if let Err(error) = pair.revalidate(clock, deadline_monotonic_ms) {
        provider_custody.release();
        pause_custody.release();
        return Err(map_backup_pair_revalidation_error_v1(error));
    }
    if pair
        .arm_writer_wait_v1(clock, deadline_monotonic_ms)
        .is_err()
    {
        provider_custody.release();
        pause_custody.release();
        return Err(QuiescentBackupErrorV1::CoordinatorUnavailable);
    }
    let (pair_custody, backup_source, guard_connection) = pair.parts_v1();
    let transaction =
        match guard_connection.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(transaction) => transaction,
            Err(_) => {
                provider_custody.release();
                pause_custody.release();
                return Err(QuiescentBackupErrorV1::CoordinatorUnavailable);
            }
        };
    let coordinator_guard = CoordinatorMaintenanceGuardV1 { transaction };
    reach_backup_coordinator_maintenance_guard_acquired_v1(&mut fault_probe);

    let staged = (|| {
        verify_backup_sqlite_profile_v1(backup_source)?;
        verify_backup_sqlite_profile_v1(coordinator_guard.source_connection())?;
        reach_backup_source_profiles_verified_v1(&mut fault_probe);
        schema::verify_full(backup_source, expected_root_identity, historical_plan_keys)
            .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnhealthy)?;
        schema::verify_full(
            coordinator_guard.source_connection(),
            expected_root_identity,
            historical_plan_keys,
        )
        .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnhealthy)?;
        reach_backup_source_invariants_verified_v1(&mut fault_probe);
        let source_state = capture_coordinator_backup_state_v1(backup_source)?;
        let guard_state =
            capture_coordinator_backup_state_v1(coordinator_guard.source_connection())?;
        if source_state != guard_state {
            return Err(QuiescentBackupErrorV1::SourceChanged);
        }
        let (coordinator_generations, coordinator_counts) = source_state;
        reach_backup_source_generations_captured_v1(&mut fault_probe);

        let inventory = enumerate_initial_inventory_under_cut_v1(
            coordinator_guard.source_connection(),
            provider,
            &mut provider_custody,
        )?;
        Ok((coordinator_generations, coordinator_counts, inventory))
    })();
    let (coordinator_generations, coordinator_counts, inventory) = match staged {
        Ok(staged) => staged,
        Err(error) => {
            let rollback = coordinator_guard.rollback();
            provider_custody.release();
            pause_custody.release();
            return Err(rollback.err().unwrap_or(error));
        }
    };
    let inventory = match inventory {
        InitialInventoryReconciliationV1::Ready(inventory) => inventory,
        InitialInventoryReconciliationV1::UnrecordedExtras(extras) => {
            let persisted = persist_unrecorded_provider_extras_v1(
                pair_custody,
                coordinator_guard.transaction_v1(),
                &extras,
                clock,
                deadline_monotonic_ms,
            )
            .and_then(|()| {
                schema::verify_full(
                    coordinator_guard.source_connection(),
                    expected_root_identity,
                    historical_plan_keys,
                )
                .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnhealthy)
            })
            .and_then(|_| {
                pair_custody
                    .revalidate(clock, deadline_monotonic_ms)
                    .map_err(map_backup_pair_revalidation_error_v1)
            });
            if let Err(error) = persisted {
                let rollback = coordinator_guard.rollback();
                provider_custody.release();
                pause_custody.release();
                return Err(rollback.err().unwrap_or(error));
            }
            let committed = coordinator_guard.commit();
            provider_custody.release();
            pause_custody.release();
            committed?;
            return Err(QuiescentBackupErrorV1::ProviderExtrasQuarantinedRetryRequired);
        }
    };

    Ok(QuiescentBackupCutV1 {
        backup_source,
        inventory_provider: provider,
        pair_custody,
        backup_clock: clock,
        backup_deadline_monotonic_ms: deadline_monotonic_ms,
        pause_custody: Some(pause_custody),
        provider_custody: Some(provider_custody),
        coordinator_guard: Some(coordinator_guard),
        paused_source,
        recovery_source,
        coordinator_generations,
        coordinator_counts,
        inventory,
        source_coordinator_root_identity_sha256: coordinator_root_identity_digest_v1(
            expected_root_identity.as_bytes(),
        ),
        coordinator_schema_sha256: Sha256Digest::from_bytes(schema::embedded_schema_v1_sha256()),
        fault_probe,
    })
}

#[cfg(not(test))]
fn map_backup_pair_revalidation_error_v1(
    error: InternalCoordinatorError,
) -> QuiescentBackupErrorV1 {
    match error {
        InternalCoordinatorError::ClockUnavailable
        | InternalCoordinatorError::DeadlineReached
        | InternalCoordinatorError::RootBusy
        | InternalCoordinatorError::RootUnavailable => {
            QuiescentBackupErrorV1::CoordinatorUnavailable
        }
        InternalCoordinatorError::RootInvalid
        | InternalCoordinatorError::RootNotDedicated
        | InternalCoordinatorError::RootRoleMismatch
        | InternalCoordinatorError::RootIdentityMismatch
        | InternalCoordinatorError::UnknownRootMember
        | InternalCoordinatorError::ApplicationIdMismatch
        | InternalCoordinatorError::SchemaUnsupported
        | InternalCoordinatorError::SchemaInvalid
        | InternalCoordinatorError::DurabilityProfileUnavailable
        | InternalCoordinatorError::IntegrityFailed
        | InternalCoordinatorError::InvariantFailed
        | InternalCoordinatorError::JsonContractInvalid
        | InternalCoordinatorError::ProvenanceInvalid
        | InternalCoordinatorError::RestorePending => QuiescentBackupErrorV1::SourceChanged,
    }
}

/// Reconciles one provider-stable enumeration against one read-only coordinator snapshot.
///
/// T069 supplies the provider-wide and coordinator maintenance guards plus generation
/// rechecks around this core. This function never mutates, repairs, prunes, or accepts a
/// native provider root.
pub(crate) fn reconcile_guarded_recovery_inventory_v1<P>(
    connection: &mut Connection,
    provider: &P,
    custody: &mut P::Custody,
) -> Result<RecoveryMaintenanceOutcomeV1, RecoveryMaintenanceErrorV1>
where
    P: GuardedRecoveryInventoryProviderV1,
{
    let provider_entries = provider
        .enumerate_recovery_inventory_v1(custody)
        .map_err(|error| match error {
            ProviderRecoveryEnumerationErrorV1::Unavailable => {
                RecoveryMaintenanceErrorV1::ProviderUnavailable
            }
            ProviderRecoveryEnumerationErrorV1::Unhealthy => {
                RecoveryMaintenanceErrorV1::ProviderUnhealthy
            }
        })?;

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|error| map_store_error_v1(&error))?;
    let reconciled = reconcile_enumerated_inventory_v1(&transaction, provider_entries);
    let rollback = transaction.rollback();
    if rollback.is_err() {
        return Err(RecoveryMaintenanceErrorV1::StoreUnavailable);
    }
    reconciled
}

fn reconcile_enumerated_inventory_v1(
    connection: &Connection,
    provider_entries: Vec<ProviderRecoveryInventoryEntryV1>,
) -> Result<RecoveryMaintenanceOutcomeV1, RecoveryMaintenanceErrorV1> {
    let provider_by_manifest = index_provider_entries_v1(&provider_entries)?;
    let loaded = load_coordinator_references_v1(connection)?;

    for (manifest, expected) in &loaded.references {
        let Some(index) = provider_by_manifest.get(manifest) else {
            return Err(RecoveryMaintenanceErrorV1::MissingProviderEntry);
        };
        if !expected.matches(&provider_entries[*index])? {
            return Err(RecoveryMaintenanceErrorV1::BindingConflict);
        }
    }
    if provider_by_manifest
        .keys()
        .any(|manifest| !loaded.references.contains_key(manifest))
    {
        return Err(RecoveryMaintenanceErrorV1::ExtraProviderEntry);
    }

    let inventory = ReconciledRecoveryInventoryV1 {
        provider_entries,
        operation_reference_count: loaded.operation_reference_count,
        quarantine_reference_count: loaded.quarantine_reference_count,
        operation_retirement_pending: loaded.operation_retirement_pending,
        orphan_retirement_pending: loaded.orphan_retirement_pending,
    };
    if inventory.operation_retirement_pending != 0 || inventory.orphan_retirement_pending != 0 {
        Ok(RecoveryMaintenanceOutcomeV1::BackupBlocked(inventory))
    } else {
        Ok(RecoveryMaintenanceOutcomeV1::Ready(inventory))
    }
}

enum InitialInventoryReconciliationV1 {
    Ready(ReconciledRecoveryInventoryV1),
    UnrecordedExtras(Vec<ProviderRecoveryInventoryEntryV1>),
}

fn enumerate_initial_inventory_under_cut_v1<P>(
    connection: &Connection,
    provider: &P,
    custody: &mut P::Custody,
) -> Result<InitialInventoryReconciliationV1, QuiescentBackupErrorV1>
where
    P: GuardedRecoveryInventoryProviderV1,
{
    let provider_entries = provider
        .enumerate_recovery_inventory_v1(custody)
        .map_err(|error| match error {
            ProviderRecoveryEnumerationErrorV1::Unavailable => {
                QuiescentBackupErrorV1::ProviderUnavailable
            }
            ProviderRecoveryEnumerationErrorV1::Unhealthy => {
                QuiescentBackupErrorV1::ProviderUnhealthy
            }
        })?;
    index_provider_entries_v1(&provider_entries).map_err(map_reconciliation_to_backup_error_v1)?;
    let loaded = load_coordinator_references_v1(connection)
        .map_err(map_reconciliation_to_backup_error_v1)?;
    let mut extras = provider_entries
        .iter()
        .filter(|entry| !loaded.references.contains_key(&entry.manifest_digest()))
        .cloned()
        .collect::<Vec<_>>();
    if !extras.is_empty() {
        extras.sort_by(|left, right| {
            left.manifest_digest()
                .as_bytes()
                .cmp(right.manifest_digest().as_bytes())
        });
        return Ok(InitialInventoryReconciliationV1::UnrecordedExtras(extras));
    }
    let outcome = reconcile_enumerated_inventory_v1(connection, provider_entries)
        .map_err(map_reconciliation_to_backup_error_v1)?;
    match outcome {
        RecoveryMaintenanceOutcomeV1::Ready(inventory) => {
            Ok(InitialInventoryReconciliationV1::Ready(inventory))
        }
        RecoveryMaintenanceOutcomeV1::BackupBlocked(_) => {
            Err(QuiescentBackupErrorV1::RetirementPending)
        }
    }
}

fn encode_unrecorded_provider_entry_v1(
    entry: &ProviderRecoveryInventoryEntryV1,
) -> Result<Vec<u8>, RecoveryMaintenanceErrorV1> {
    fn append_string_v1(
        bytes: &mut Vec<u8>,
        value: &str,
    ) -> Result<(), RecoveryMaintenanceErrorV1> {
        let length = u16::try_from(value.len())
            .map_err(|_| RecoveryMaintenanceErrorV1::ProviderUnhealthy)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    let evidence_class = match entry.evidence_class() {
        RecoveryEvidenceClassV1::SyntheticConformance => "SYNTHETIC_CONFORMANCE",
        RecoveryEvidenceClassV1::ApprovedProduction => "APPROVED_PRODUCTION",
    };
    let custody = match entry.custody() {
        ProviderRecoveryCustodyV1::OperationBound => "OPERATION_BOUND",
        ProviderRecoveryCustodyV1::QuarantinedOrphan => "QUARANTINED_ORPHAN",
        ProviderRecoveryCustodyV1::OrphanResolutionTombstone => "ORPHAN_RESOLUTION_TOMBSTONE",
    };
    let state = match entry.state() {
        ProviderRecoveryStateV1::Published => "MATERIAL_PRESENT",
        ProviderRecoveryStateV1::RetiredTombstone => "RETIRED_TOMBSTONE",
    };
    let mut encoded = Vec::with_capacity(384);
    append_string_v1(&mut encoded, entry.provider_profile_id().as_str())?;
    encoded.extend_from_slice(&entry.provider_profile_version().to_be_bytes());
    append_string_v1(&mut encoded, entry.provider_id().as_str())?;
    encoded.extend_from_slice(&entry.provider_generation().to_be_bytes());
    append_string_v1(&mut encoded, evidence_class)?;
    append_string_v1(&mut encoded, entry.at_rest_profile_id().as_str())?;
    append_string_v1(&mut encoded, custody)?;
    append_string_v1(&mut encoded, state)?;
    encoded.extend_from_slice(entry.manifest_digest().as_bytes());
    encoded.extend_from_slice(entry.material_digest().as_bytes());
    encoded.extend_from_slice(&entry.material_length().to_be_bytes());
    encoded.extend_from_slice(&entry.reserved_capacity().to_be_bytes());
    match entry.retirement_manifest_digest() {
        None => encoded.push(0),
        Some(digest) => {
            encoded.push(1);
            encoded.extend_from_slice(digest.as_bytes());
        }
    }
    Ok(encoded)
}

fn unrecorded_provider_entry_quarantine_digests_v1(
    entry: &ProviderRecoveryInventoryEntryV1,
) -> Result<(Sha256Digest, Sha256Digest), RecoveryMaintenanceErrorV1> {
    let encoded = encode_unrecorded_provider_entry_v1(entry)?;
    let mut attempt = Vec::with_capacity(BACKUP_EXTRA_ATTEMPT_DOMAIN_V1.len() + encoded.len());
    attempt.extend_from_slice(BACKUP_EXTRA_ATTEMPT_DOMAIN_V1);
    attempt.extend_from_slice(&encoded);
    let mut binding = Vec::with_capacity(BACKUP_EXTRA_BINDING_DOMAIN_V1.len() + encoded.len());
    binding.extend_from_slice(BACKUP_EXTRA_BINDING_DOMAIN_V1);
    binding.extend_from_slice(&encoded);
    Ok((
        Sha256Digest::digest(&attempt),
        Sha256Digest::digest(&binding),
    ))
}

#[cfg(not(test))]
fn persist_unrecorded_provider_extras_v1(
    pair_custody: &mut BoundCoordinatorBackupCustodyV1,
    transaction: &Transaction<'_>,
    extras: &[ProviderRecoveryInventoryEntryV1],
    clock: &dyn CoordinatorMonotonicClockV1,
    deadline_monotonic_ms: u64,
) -> Result<(), QuiescentBackupErrorV1> {
    for entry in extras {
        pair_custody
            .revalidate(clock, deadline_monotonic_ms)
            .map_err(map_backup_pair_revalidation_error_v1)?;
        let (attempt_id, operation_binding_digest) =
            unrecorded_provider_entry_quarantine_digests_v1(entry)
                .map_err(map_reconciliation_to_backup_error_v1)?;
        retain_base_quarantine_in_transaction_v1(
            transaction,
            &BaseQuarantineInputV1 {
                attempt_id,
                operation_binding_digest,
                reason: BaseQuarantineReasonV1::OrphanMaterial,
                recovery_manifest_digest: Some(entry.manifest_digest()),
            },
        )
        .map_err(map_extra_quarantine_error_v1)?;
    }
    pair_custody
        .revalidate(clock, deadline_monotonic_ms)
        .map_err(map_backup_pair_revalidation_error_v1)?;
    Ok(())
}

#[cfg(not(test))]
fn map_extra_quarantine_error_v1(error: BaseQuarantineErrorV1) -> QuiescentBackupErrorV1 {
    match error {
        BaseQuarantineErrorV1::Unavailable => QuiescentBackupErrorV1::CoordinatorUnavailable,
        BaseQuarantineErrorV1::InvalidInput
        | BaseQuarantineErrorV1::Conflict
        | BaseQuarantineErrorV1::Unhealthy
        | BaseQuarantineErrorV1::GenerationExhausted => {
            QuiescentBackupErrorV1::CoordinatorUnhealthy
        }
    }
}

fn index_provider_entries_v1(
    entries: &[ProviderRecoveryInventoryEntryV1],
) -> Result<HashMap<Sha256Digest, usize>, RecoveryMaintenanceErrorV1> {
    if u64::try_from(entries.len())
        .ok()
        .is_none_or(|count| count > MAX_SAFE_U64)
    {
        return Err(RecoveryMaintenanceErrorV1::ProviderUnhealthy);
    }
    let mut indexed = HashMap::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if indexed.insert(entry.manifest_digest(), index).is_some() {
            return Err(RecoveryMaintenanceErrorV1::DuplicateProviderEntry);
        }
    }
    Ok(indexed)
}

struct LoadedCoordinatorReferencesV1 {
    references: HashMap<Sha256Digest, ExpectedRecoveryReferenceV1>,
    operation_reference_count: u64,
    quarantine_reference_count: u64,
    operation_retirement_pending: u64,
    orphan_retirement_pending: u64,
}

struct OperationRecoveryBindingV1 {
    provider_profile_id: String,
    provider_profile_version: u16,
    provider_id: String,
    provider_generation: u64,
    evidence_class: RecoveryEvidenceClassV1,
    at_rest_profile_id: String,
    material_digest: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
}

enum ExpectedRecoveryStateV1 {
    OperationPublished,
    OperationPending,
    OperationRetired(Sha256Digest),
    QuarantinePublished,
    OrphanPending,
    OrphanRetired(Sha256Digest),
}

struct ExpectedRecoveryReferenceV1 {
    operation_binding: Option<OperationRecoveryBindingV1>,
    extra_quarantine_binding: Option<ExtraQuarantineBindingV1>,
    state: ExpectedRecoveryStateV1,
}

struct ExtraQuarantineBindingV1 {
    attempt_id: Sha256Digest,
    operation_binding_digest: Sha256Digest,
}

impl ExpectedRecoveryReferenceV1 {
    fn matches(
        &self,
        actual: &ProviderRecoveryInventoryEntryV1,
    ) -> Result<bool, RecoveryMaintenanceErrorV1> {
        if let Some(expected) = &self.operation_binding {
            if expected.provider_profile_id != actual.provider_profile_id.as_str()
                || expected.provider_profile_version != actual.provider_profile_version
                || expected.provider_id != actual.provider_id.as_str()
                || expected.provider_generation != actual.provider_generation
                || expected.evidence_class != actual.evidence_class
                || expected.at_rest_profile_id != actual.at_rest_profile_id.as_str()
                || expected.material_digest != actual.material_digest
                || expected.material_length != actual.material_length
                || expected.reserved_capacity != actual.reserved_capacity
            {
                return Ok(false);
            }
        }
        if let Some(expected) = &self.extra_quarantine_binding {
            let (actual_attempt, actual_binding) =
                unrecorded_provider_entry_quarantine_digests_v1(actual)?;
            return Ok(actual_attempt == expected.attempt_id
                && actual_binding == expected.operation_binding_digest);
        }
        Ok(match self.state {
            ExpectedRecoveryStateV1::OperationPublished => {
                actual.custody == ProviderRecoveryCustodyV1::OperationBound
                    && actual.state == ProviderRecoveryStateV1::Published
                    && actual.retirement_manifest_digest.is_none()
            }
            ExpectedRecoveryStateV1::OperationPending => {
                actual.custody == ProviderRecoveryCustodyV1::OperationBound
            }
            ExpectedRecoveryStateV1::OperationRetired(expected) => {
                actual.custody == ProviderRecoveryCustodyV1::OperationBound
                    && actual.state == ProviderRecoveryStateV1::RetiredTombstone
                    && actual.retirement_manifest_digest == Some(expected)
            }
            ExpectedRecoveryStateV1::QuarantinePublished => {
                actual.custody == ProviderRecoveryCustodyV1::QuarantinedOrphan
                    && actual.state == ProviderRecoveryStateV1::Published
                    && actual.retirement_manifest_digest.is_none()
            }
            ExpectedRecoveryStateV1::OrphanPending => matches!(
                (actual.state, actual.custody),
                (
                    ProviderRecoveryStateV1::Published,
                    ProviderRecoveryCustodyV1::QuarantinedOrphan
                ) | (
                    ProviderRecoveryStateV1::RetiredTombstone,
                    ProviderRecoveryCustodyV1::OrphanResolutionTombstone
                )
            ),
            ExpectedRecoveryStateV1::OrphanRetired(expected) => {
                actual.custody == ProviderRecoveryCustodyV1::OrphanResolutionTombstone
                    && actual.state == ProviderRecoveryStateV1::RetiredTombstone
                    && actual.retirement_manifest_digest == Some(expected)
            }
        })
    }
}

fn load_coordinator_references_v1(
    connection: &Connection,
) -> Result<LoadedCoordinatorReferencesV1, RecoveryMaintenanceErrorV1> {
    let mut loaded = LoadedCoordinatorReferencesV1 {
        references: HashMap::new(),
        operation_reference_count: 0,
        quarantine_reference_count: 0,
        operation_retirement_pending: 0,
        orphan_retirement_pending: 0,
    };
    load_operation_references_v1(connection, &mut loaded)?;
    load_quarantine_references_v1(connection, &mut loaded)?;
    Ok(loaded)
}

fn load_operation_references_v1(
    connection: &Connection,
    loaded: &mut LoadedCoordinatorReferencesV1,
) -> Result<(), RecoveryMaintenanceErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT provider_profile_id, provider_profile_version, provider_id, \
                    provider_generation, evidence_class, at_rest_profile_id, \
                    manifest_digest, material_digest, material_length, reserved_capacity, \
                    material_state, retirement_id, retirement_manifest_digest, \
                    retirement_generation \
             FROM preparation_recovery_evidence \
             WHERE recovery_mode = 'COMPENSATION'",
        )
        .map_err(|error| map_store_error_v1(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
                row.get::<_, Option<Vec<u8>>>(12)?,
                row.get::<_, Option<i64>>(13)?,
            ))
        })
        .map_err(|error| map_store_error_v1(&error))?;
    for row in rows {
        let row = row.map_err(|error| map_store_error_v1(&error))?;
        let manifest = decode_digest_v1(&row.6)?;
        let retirement_id = decode_optional_digest_v1(row.11.as_deref())?;
        let retirement_manifest = decode_optional_digest_v1(row.12.as_deref())?;
        let retirement_generation = decode_optional_positive_safe_v1(row.13)?;
        let state = match row.10.as_str() {
            "PUBLISHED"
                if retirement_id.is_none()
                    && retirement_manifest.is_none()
                    && retirement_generation.is_none() =>
            {
                ExpectedRecoveryStateV1::OperationPublished
            }
            "RETIREMENT_PENDING"
                if retirement_id.is_some()
                    && retirement_manifest.is_none()
                    && retirement_generation.is_some() =>
            {
                loaded.operation_retirement_pending =
                    checked_increment_v1(loaded.operation_retirement_pending)?;
                ExpectedRecoveryStateV1::OperationPending
            }
            "RETIRED_TOMBSTONE"
                if retirement_id.is_some()
                    && retirement_manifest.is_some()
                    && retirement_generation.is_some() =>
            {
                ExpectedRecoveryStateV1::OperationRetired(
                    retirement_manifest.ok_or(RecoveryMaintenanceErrorV1::StoreUnhealthy)?,
                )
            }
            _ => return Err(RecoveryMaintenanceErrorV1::StoreUnhealthy),
        };
        let binding = OperationRecoveryBindingV1 {
            provider_profile_id: validate_identifier_v1(row.0)?,
            provider_profile_version: decode_profile_version_v1(row.1)?,
            provider_id: validate_identifier_v1(row.2)?,
            provider_generation: decode_positive_safe_v1(row.3)?,
            evidence_class: decode_evidence_class_v1(&row.4)?,
            at_rest_profile_id: validate_identifier_v1(row.5)?,
            material_digest: decode_digest_v1(&row.7)?,
            material_length: decode_safe_v1(row.8)?,
            reserved_capacity: decode_safe_v1(row.9)?,
        };
        if binding.reserved_capacity < binding.material_length {
            return Err(RecoveryMaintenanceErrorV1::StoreUnhealthy);
        }
        insert_reference_v1(
            &mut loaded.references,
            manifest,
            ExpectedRecoveryReferenceV1 {
                operation_binding: Some(binding),
                extra_quarantine_binding: None,
                state,
            },
        )?;
        loaded.operation_reference_count = checked_increment_v1(loaded.operation_reference_count)?;
    }
    Ok(())
}

fn load_quarantine_references_v1(
    connection: &Connection,
    loaded: &mut LoadedCoordinatorReferencesV1,
) -> Result<(), RecoveryMaintenanceErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT quarantine_reason, quarantine_status, attempt_id, \
                    operation_binding_digest, created_generation, \
                    resolved_generation, recovery_manifest_digest, \
                    orphan_resolution_evidence_digest, orphan_retirement_id, \
                    orphan_retirement_state, orphan_retired_generation, \
                    orphan_retirement_manifest_digest \
             FROM preparation_quarantines \
             WHERE recovery_manifest_digest IS NOT NULL",
        )
        .map_err(|error| map_store_error_v1(&error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
            ))
        })
        .map_err(|error| map_store_error_v1(&error))?;
    for row in rows {
        let row = row.map_err(|error| map_store_error_v1(&error))?;
        if !is_closed_quarantine_reason_v1(&row.0) {
            return Err(RecoveryMaintenanceErrorV1::StoreUnhealthy);
        }
        let attempt_id = decode_digest_v1(&row.2)?;
        let operation_binding_digest = decode_digest_v1(&row.3)?;
        let created = decode_positive_safe_v1(row.4)?;
        let resolved = decode_optional_positive_safe_v1(row.5)?;
        let manifest = decode_digest_v1(&row.6)?;
        let resolution_digest = decode_optional_digest_v1(row.7.as_deref())?;
        let retirement_id = decode_optional_digest_v1(row.8.as_deref())?;
        let retired_generation = decode_optional_positive_safe_v1(row.10)?;
        let retirement_manifest = decode_optional_digest_v1(row.11.as_deref())?;
        let state = match (row.1.as_str(), row.0.as_str(), row.9.as_deref()) {
            ("ACTIVE", _, None)
                if resolved.is_none()
                    && resolution_digest.is_none()
                    && retirement_id.is_none()
                    && retired_generation.is_none()
                    && retirement_manifest.is_none() =>
            {
                ExpectedRecoveryStateV1::QuarantinePublished
            }
            ("RESOLVED_TOMBSTONE", "ORPHAN_MATERIAL", Some("RETIREMENT_PENDING"))
                if resolved.is_some_and(|value| value > created)
                    && resolution_digest.is_some()
                    && retirement_id.is_some()
                    && retired_generation.is_none()
                    && retirement_manifest.is_none() =>
            {
                loaded.orphan_retirement_pending =
                    checked_increment_v1(loaded.orphan_retirement_pending)?;
                ExpectedRecoveryStateV1::OrphanPending
            }
            ("RESOLVED_TOMBSTONE", "ORPHAN_MATERIAL", Some("RETIRED_TOMBSTONE"))
                if resolved.is_some_and(|value| value > created)
                    && resolution_digest.is_some()
                    && retirement_id.is_some()
                    && retired_generation
                        .zip(resolved)
                        .is_some_and(|(retired, resolved)| retired > resolved)
                    && retirement_manifest.is_some() =>
            {
                ExpectedRecoveryStateV1::OrphanRetired(
                    retirement_manifest.ok_or(RecoveryMaintenanceErrorV1::StoreUnhealthy)?,
                )
            }
            ("RESOLVED_TOMBSTONE", reason, None)
                if reason != "ORPHAN_MATERIAL"
                    && resolved.is_some_and(|value| value > created)
                    && resolution_digest.is_none()
                    && retirement_id.is_none()
                    && retired_generation.is_none()
                    && retirement_manifest.is_none() =>
            {
                // Only active quarantine and permanent true-orphan resolution custody
                // enter the complete provider reference set. A resolved ambiguity may
                // legitimately name the same manifest as its exact operation.
                continue;
            }
            _ => return Err(RecoveryMaintenanceErrorV1::StoreUnhealthy),
        };
        insert_reference_v1(
            &mut loaded.references,
            manifest,
            ExpectedRecoveryReferenceV1 {
                operation_binding: None,
                extra_quarantine_binding: (row.0 == "ORPHAN_MATERIAL" && row.1 == "ACTIVE")
                    .then_some(ExtraQuarantineBindingV1 {
                        attempt_id,
                        operation_binding_digest,
                    }),
                state,
            },
        )?;
        loaded.quarantine_reference_count =
            checked_increment_v1(loaded.quarantine_reference_count)?;
    }
    Ok(())
}

fn insert_reference_v1(
    references: &mut HashMap<Sha256Digest, ExpectedRecoveryReferenceV1>,
    manifest: Sha256Digest,
    reference: ExpectedRecoveryReferenceV1,
) -> Result<(), RecoveryMaintenanceErrorV1> {
    if references.insert(manifest, reference).is_some() {
        return Err(RecoveryMaintenanceErrorV1::DuplicateCoordinatorReference);
    }
    Ok(())
}

fn validate_identifier_v1(value: String) -> Result<String, RecoveryMaintenanceErrorV1> {
    Identifier::new(value.clone(), 128)
        .map(|_| value)
        .map_err(|_| RecoveryMaintenanceErrorV1::StoreUnhealthy)
}

fn decode_profile_version_v1(value: i64) -> Result<u16, RecoveryMaintenanceErrorV1> {
    u16::try_from(value)
        .ok()
        .filter(|value| *value == RECOVERY_PROVIDER_PROFILE_VERSION_V1)
        .ok_or(RecoveryMaintenanceErrorV1::StoreUnhealthy)
}

fn decode_evidence_class_v1(
    value: &str,
) -> Result<RecoveryEvidenceClassV1, RecoveryMaintenanceErrorV1> {
    match value {
        "SYNTHETIC_CONFORMANCE" => Ok(RecoveryEvidenceClassV1::SyntheticConformance),
        "APPROVED_PRODUCTION" => Ok(RecoveryEvidenceClassV1::ApprovedProduction),
        _ => Err(RecoveryMaintenanceErrorV1::StoreUnhealthy),
    }
}

fn is_closed_quarantine_reason_v1(value: &str) -> bool {
    matches!(
        value,
        "AMBIGUOUS_COMMIT"
            | "ORPHAN_MATERIAL"
            | "RESTORED_OLD_AUTHORITY"
            | "INVARIANT_CONFLICT"
            | "STORE_UNHEALTHY"
    )
}

fn decode_digest_v1(value: &[u8]) -> Result<Sha256Digest, RecoveryMaintenanceErrorV1> {
    value
        .try_into()
        .map(Sha256Digest::from_bytes)
        .map_err(|_| RecoveryMaintenanceErrorV1::StoreUnhealthy)
}

fn decode_optional_digest_v1(
    value: Option<&[u8]>,
) -> Result<Option<Sha256Digest>, RecoveryMaintenanceErrorV1> {
    value.map(decode_digest_v1).transpose()
}

fn decode_safe_v1(value: i64) -> Result<u64, RecoveryMaintenanceErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(RecoveryMaintenanceErrorV1::StoreUnhealthy)
}

fn decode_positive_safe_v1(value: i64) -> Result<u64, RecoveryMaintenanceErrorV1> {
    decode_safe_v1(value).and_then(|value| {
        (value != 0)
            .then_some(value)
            .ok_or(RecoveryMaintenanceErrorV1::StoreUnhealthy)
    })
}

fn decode_optional_positive_safe_v1(
    value: Option<i64>,
) -> Result<Option<u64>, RecoveryMaintenanceErrorV1> {
    value.map(decode_positive_safe_v1).transpose()
}

fn checked_increment_v1(value: u64) -> Result<u64, RecoveryMaintenanceErrorV1> {
    value
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(RecoveryMaintenanceErrorV1::StoreUnhealthy)
}

fn map_pause_validation_error_v1(
    validation: MaintenanceCustodyValidationV1,
) -> QuiescentBackupErrorV1 {
    match validation {
        MaintenanceCustodyValidationV1::Exact => QuiescentBackupErrorV1::PauseUnhealthy,
        MaintenanceCustodyValidationV1::Revoked => QuiescentBackupErrorV1::SourceChanged,
        MaintenanceCustodyValidationV1::Unavailable => QuiescentBackupErrorV1::PauseUnavailable,
        MaintenanceCustodyValidationV1::Unhealthy => QuiescentBackupErrorV1::PauseUnhealthy,
    }
}

fn map_pause_validation_v1(
    validation: MaintenanceCustodyValidationV1,
) -> Result<(), QuiescentBackupErrorV1> {
    match validation {
        MaintenanceCustodyValidationV1::Exact => Ok(()),
        other => Err(map_pause_validation_error_v1(other)),
    }
}

fn map_provider_validation_error_v1(
    validation: MaintenanceCustodyValidationV1,
) -> QuiescentBackupErrorV1 {
    match validation {
        MaintenanceCustodyValidationV1::Exact => QuiescentBackupErrorV1::ProviderUnhealthy,
        MaintenanceCustodyValidationV1::Revoked => QuiescentBackupErrorV1::SourceChanged,
        MaintenanceCustodyValidationV1::Unavailable => QuiescentBackupErrorV1::ProviderUnavailable,
        MaintenanceCustodyValidationV1::Unhealthy => QuiescentBackupErrorV1::ProviderUnhealthy,
    }
}

fn map_provider_validation_v1(
    validation: MaintenanceCustodyValidationV1,
) -> Result<(), QuiescentBackupErrorV1> {
    match validation {
        MaintenanceCustodyValidationV1::Exact => Ok(()),
        other => Err(map_provider_validation_error_v1(other)),
    }
}

fn map_reconciliation_to_backup_error_v1(
    error: RecoveryMaintenanceErrorV1,
) -> QuiescentBackupErrorV1 {
    match error {
        RecoveryMaintenanceErrorV1::ProviderUnavailable => {
            QuiescentBackupErrorV1::ProviderUnavailable
        }
        RecoveryMaintenanceErrorV1::ProviderUnhealthy
        | RecoveryMaintenanceErrorV1::DuplicateProviderEntry => {
            QuiescentBackupErrorV1::ProviderUnhealthy
        }
        RecoveryMaintenanceErrorV1::StoreUnavailable => {
            QuiescentBackupErrorV1::CoordinatorUnavailable
        }
        RecoveryMaintenanceErrorV1::DuplicateCoordinatorReference
        | RecoveryMaintenanceErrorV1::MissingProviderEntry
        | RecoveryMaintenanceErrorV1::ExtraProviderEntry
        | RecoveryMaintenanceErrorV1::BindingConflict
        | RecoveryMaintenanceErrorV1::StoreUnhealthy => {
            QuiescentBackupErrorV1::CoordinatorUnhealthy
        }
    }
}

fn map_reconciliation_to_inventory_recheck_error_v1(
    error: RecoveryMaintenanceErrorV1,
) -> QuiescentBackupErrorV1 {
    match error {
        RecoveryMaintenanceErrorV1::ProviderUnavailable => {
            QuiescentBackupErrorV1::ProviderUnavailable
        }
        RecoveryMaintenanceErrorV1::ProviderUnhealthy
        | RecoveryMaintenanceErrorV1::DuplicateProviderEntry => {
            QuiescentBackupErrorV1::ProviderUnhealthy
        }
        RecoveryMaintenanceErrorV1::StoreUnavailable => {
            QuiescentBackupErrorV1::CoordinatorUnavailable
        }
        RecoveryMaintenanceErrorV1::StoreUnhealthy
        | RecoveryMaintenanceErrorV1::DuplicateCoordinatorReference => {
            QuiescentBackupErrorV1::CoordinatorUnhealthy
        }
        RecoveryMaintenanceErrorV1::MissingProviderEntry
        | RecoveryMaintenanceErrorV1::ExtraProviderEntry
        | RecoveryMaintenanceErrorV1::BindingConflict => QuiescentBackupErrorV1::SourceChanged,
    }
}

fn verify_backup_sqlite_profile_v1(connection: &Connection) -> Result<(), QuiescentBackupErrorV1> {
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnavailable)?;
    let pragma = |name| {
        connection
            .pragma_query_value(None, name, |row| row.get::<_, i64>(0))
            .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnavailable)
    };
    if !journal_mode.eq_ignore_ascii_case("wal")
        || pragma("synchronous")? != 2
        || pragma("foreign_keys")? != 1
        || pragma("trusted_schema")? != 0
        || pragma("cell_size_check")? != 1
        || pragma("recursive_triggers")? != 1
        || pragma("wal_autocheckpoint")? != 0
    {
        return Err(QuiescentBackupErrorV1::CoordinatorUnhealthy);
    }
    Ok(())
}

fn capture_coordinator_backup_state_v1(
    connection: &Connection,
) -> Result<(CoordinatorBackupGenerationsV1, CoordinatorBackupCountsV1), QuiescentBackupErrorV1> {
    let raw = connection
        .query_row(
            "SELECT store_generation, operation_generation, budget_generation, \
                    event_generation, quarantine_generation \
             FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnhealthy)?;
    let safe = |value: i64| {
        u64::try_from(value)
            .ok()
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(QuiescentBackupErrorV1::CoordinatorUnhealthy)
    };
    let generations = CoordinatorBackupGenerationsV1 {
        store: safe(raw.0)?,
        operation: safe(raw.1)?,
        budget: safe(raw.2)?,
        event: safe(raw.3)?,
        quarantine: safe(raw.4)?,
    };
    let counts = CoordinatorBackupCountsV1 {
        budget_scopes: backup_count_v1(connection, "SELECT COUNT(*) FROM budget_scopes")?,
        operations: backup_count_v1(connection, "SELECT COUNT(*) FROM prepared_operations")?,
        operation_transitions: backup_count_v1(
            connection,
            "SELECT COUNT(*) FROM operation_transitions",
        )?,
        held_reservations: backup_count_v1(
            connection,
            "SELECT COUNT(*) FROM budget_reservations WHERE reservation_state = 'HELD'",
        )?,
        released_reservations: backup_count_v1(
            connection,
            "SELECT COUNT(*) FROM budget_reservations WHERE reservation_state = 'RELEASED'",
        )?,
        pending_events: backup_count_v1(
            connection,
            "SELECT COUNT(*) FROM preparation_events WHERE delivery_state = 'PENDING'",
        )?,
        delivered_events: backup_count_v1(
            connection,
            "SELECT COUNT(*) FROM preparation_events WHERE delivery_state = 'DELIVERED'",
        )?,
        active_quarantines: backup_count_v1(
            connection,
            "SELECT COUNT(*) FROM preparation_quarantines WHERE quarantine_status = 'ACTIVE'",
        )?,
        resolved_quarantines: backup_count_v1(
            connection,
            "SELECT COUNT(*) FROM preparation_quarantines WHERE quarantine_status = 'RESOLVED_TOMBSTONE'",
        )?,
    };
    Ok((generations, counts))
}

fn backup_count_v1(
    connection: &Connection,
    statement: &str,
) -> Result<u64, QuiescentBackupErrorV1> {
    let value = connection
        .query_row(statement, [], |row| row.get::<_, i64>(0))
        .map_err(|_| QuiescentBackupErrorV1::CoordinatorUnhealthy)?;
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(QuiescentBackupErrorV1::CoordinatorUnhealthy)
}

fn map_store_error_v1(error: &SqliteError) -> RecoveryMaintenanceErrorV1 {
    match error {
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseCorrupt
                    | rusqlite::ErrorCode::NotADatabase
                    | rusqlite::ErrorCode::SchemaChanged
            ) =>
        {
            RecoveryMaintenanceErrorV1::StoreUnhealthy
        }
        SqliteError::InvalidColumnType(..)
        | SqliteError::FromSqlConversionFailure(..)
        | SqliteError::QueryReturnedNoRows => RecoveryMaintenanceErrorV1::StoreUnhealthy,
        _ => RecoveryMaintenanceErrorV1::StoreUnavailable,
    }
}

#[inline]
fn reach_backup_pause_persisted_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupPausePersisted);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_provider_maintenance_guard_acquired_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupProviderMaintenanceGuardAcquired);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_coordinator_maintenance_guard_acquired_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupCoordinatorMaintenanceGuardAcquired);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_source_profiles_verified_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSourceProfilesVerified);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_source_invariants_verified_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSourceInvariantsVerified);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_source_generations_captured_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSourceGenerationsCaptured);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_sqlite_online_backup_completed_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSqliteOnlineBackupCompleted);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_sqlite_online_backup_closed_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSqliteOnlineBackupClosed);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_sqlite_online_backup_integrity_checked_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSqliteOnlineBackupIntegrityChecked);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_sqlite_online_backup_hashed_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSqliteOnlineBackupHashed);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_material_present_package_exported_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupMaterialPresentPackageExported);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_retirement_tombstone_exported_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupRetirementTombstoneExported);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_inventory_jcs_finalized_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupInventoryJcsFinalized);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_top_level_manifest_staged_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupTopLevelManifestStaged);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_top_level_manifest_published_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupTopLevelManifestPublished);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_attestation_protected_jcs_finalized_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupAttestationProtectedJcsFinalized);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_attestation_signed_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupAttestationSigned);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_attestation_staged_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupAttestationStaged);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_attestation_published_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupAttestationPublished);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_attestation_reopened_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupAttestationReopened);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_attestation_verified_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupAttestationVerified);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_backup_source_generations_rechecked_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupSourceGenerationsRechecked);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_provider_enumeration_reconciled_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::BackupProviderEnumerationReconciled);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_package_and_pinned_provenance_accepted_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestorePackageAndPinnedProvenanceAccepted);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_empty_coordinator_root_reserved_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreEmptyCoordinatorRootReserved);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_empty_recovery_root_reserved_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreEmptyRecoveryRootReserved);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_coordinator_database_imported_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreCoordinatorDatabaseImported);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_wal_full_profile_established_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreWalFullProfileEstablished);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_recovery_package_imported_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreRecoveryPackageImported);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_coordinator_restore_pending_committed_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreCoordinatorRestorePendingCommitted);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_coordinator_pending_root_marker_published_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe
        .reach_v1(crate::test_fault::FaultBoundaryV1::RestoreCoordinatorPendingRootMarkerPublished);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_recovery_restore_pending_metadata_published_v1(
    probe: &mut MaintenanceFaultProbeV1,
) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::RestoreRecoveryRestorePendingMetadataPublished,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_both_roots_closed_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreBothRootsClosed);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_both_roots_reopened_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreBothRootsReopened);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_both_roots_agreement_classified_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreBothRootsAgreementClassified);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_verified_preparation_restore_returned_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreVerifiedPreparationRestoreReturned);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

#[inline]
fn reach_restore_quarantine_persisted_v1(probe: &mut MaintenanceFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    probe.reach_v1(crate::test_fault::FaultBoundaryV1::RestoreQuarantinePersisted);
    #[cfg(not(feature = "test-fault-injection"))]
    probe.reach_v1();
}

/// Executes the exact production T071 path from one real attested coordinator root.
///
/// This is reachable only through the feature-gated hidden conformance facade. All
/// failures are reduced to static phase labels so native paths, SQLite diagnostics,
/// key material, and provider bindings never cross the test boundary.
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub(crate) fn run_t071_production_conformance_v1() -> Result<(), &'static str> {
    t071_production_conformance::run_v1()
}

/// Executes the exact non-test T072 clean-root restore path for conformance.
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub(crate) fn run_t072_production_conformance_v1() -> Result<(), &'static str> {
    t071_production_conformance::run_restore_v1()
}

/// Carries one caller-owned process probe through the exact production backup path.
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub(crate) fn run_t074_production_fault_probe_v1(
    boundary_id: &str,
    occurrence: u64,
    probe_root: PathBuf,
    process_barrier: Box<dyn FnMut() + Send>,
) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(&probe_root).map_err(|_| "fault-probe-root-invalid")?;
    if !probe_root.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("fault-probe-root-invalid");
    }
    let boundary = crate::test_fault::FaultBoundaryV1::ALL
        .iter()
        .copied()
        .find(|candidate| candidate.id() == boundary_id)
        .ok_or("fault-boundary-unsupported")?;
    if occurrence == 0 {
        return Err("fault-occurrence-invalid");
    }
    let selection = crate::test_fault::FaultSelectionV1::try_new(
        boundary,
        occurrence,
        crate::test_fault::FaultEffectV1::ProcessBarrier,
    )
    .map_err(|_| "fault-occurrence-invalid")?;
    let run_restore = if boundary_id.starts_with("backup_") {
        false
    } else if boundary_id.starts_with("restore_") {
        true
    } else {
        return Err("fault-boundary-workflow-unsupported");
    };
    let probe = MaintenanceFaultProbeV1::selected_process_barrier_v1(selection, process_barrier);
    t071_production_conformance::run_fault_probe_v1(probe, probe_root, run_restore)
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
mod t071_production_conformance {
    use super::*;
    use crate::config::CoordinatorStoreConfigV1;
    use crate::connection::{initialize_or_verify_store, open_bound_backup_pair_v1};
    use crate::error::CoordinatorClockUnavailableV1;
    use crate::manifest::{
        decode_backup_provenance_attestation_v1, decode_preparation_backup_manifest_v1,
        decode_recovery_snapshot_manifest_v1, PinnedEd25519KeyV1, ProductionBackupManifestCodecV1,
        ProvisionerTrustDecisionV1, ProvisionerTrustResolverV1,
    };
    use ed25519_dalek::{Signer as _, SigningKey};
    use helix_contracts::{ContractError, Result as ContractResult};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    const DEADLINE_MONOTONIC_MS: u64 = 10_000;

    struct FixedClockV1;

    impl CoordinatorMonotonicClockV1 for FixedClockV1 {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            Ok(1)
        }
    }

    struct NoHistoricalPlanKeysV1;

    impl Ed25519KeyResolver for NoHistoricalPlanKeysV1 {
        fn resolve_ed25519(&self, _key_id: &str) -> ContractResult<[u8; 32]> {
            Err(ContractError::UnknownKey)
        }
    }

    struct PauseAuthorityV1 {
        releases: Arc<AtomicU64>,
    }

    struct PauseCustodyV1 {
        releases: Arc<AtomicU64>,
    }

    impl BackupPauseAuthorityV1 for PauseAuthorityV1 {
        type Custody = PauseCustodyV1;

        fn persist_pause_for_backup_v1(
            &self,
            _deadline_monotonic_ms: u64,
        ) -> PausedBackupCustodyOutcomeV1<Self::Custody> {
            PausedBackupCustodyOutcomeV1::Acquired(PauseCustodyV1 {
                releases: Arc::clone(&self.releases),
            })
        }
    }

    impl PausedBackupCustodyV1 for PauseCustodyV1 {
        fn capture_paused_source_v1(
            &mut self,
        ) -> Result<PausedBackupSourceV1, MaintenanceCustodyValidationV1> {
            PausedBackupSourceV1::try_new(1, Sha256Digest::digest(b"t071-boot"), 1, 1)
                .map_err(|_| MaintenanceCustodyValidationV1::Unhealthy)
        }

        fn recheck_paused_source_v1(
            &mut self,
            expected: &PausedBackupSourceV1,
        ) -> MaintenanceCustodyValidationV1 {
            match self.capture_paused_source_v1() {
                Ok(actual) if &actual == expected => MaintenanceCustodyValidationV1::Exact,
                Ok(_) => MaintenanceCustodyValidationV1::Revoked,
                Err(error) => error,
            }
        }

        fn release(self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct ProviderV1 {
        releases: Arc<AtomicU64>,
        enumerations: Arc<AtomicU64>,
        enumeration_failures_remaining: Arc<AtomicU64>,
        entries: Vec<ProviderRecoveryInventoryEntryV1>,
        published_packages: Vec<(Vec<u8>, Vec<u8>)>,
        retirement_manifests: Vec<Vec<u8>>,
    }

    struct ProviderCustodyV1 {
        releases: Arc<AtomicU64>,
    }

    impl RecoveryCleanupGuardV1 for ProviderCustodyV1 {
        fn release(self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ProviderMaintenanceGuardV1 for ProviderCustodyV1 {
        fn capture_recovery_source_v1(
            &mut self,
        ) -> Result<RecoveryMaintenanceSourceV1, MaintenanceCustodyValidationV1> {
            RecoveryMaintenanceSourceV1::try_new(
                Sha256Digest::digest(b"t071-recovery-root"),
                Sha256Digest::digest(b"t071-instance"),
                1,
                1,
            )
            .map_err(|_| MaintenanceCustodyValidationV1::Unhealthy)
        }

        fn recheck_recovery_source_v1(
            &mut self,
            expected: &RecoveryMaintenanceSourceV1,
        ) -> MaintenanceCustodyValidationV1 {
            match self.capture_recovery_source_v1() {
                Ok(actual) if &actual == expected => MaintenanceCustodyValidationV1::Exact,
                Ok(_) => MaintenanceCustodyValidationV1::Revoked,
                Err(error) => error,
            }
        }
    }

    impl GuardedRecoveryInventoryProviderV1 for ProviderV1 {
        type Custody = ProviderCustodyV1;

        fn enumerate_recovery_inventory_v1(
            &self,
            _custody: &mut Self::Custody,
        ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, ProviderRecoveryEnumerationErrorV1>
        {
            self.enumerations.fetch_add(1, Ordering::SeqCst);
            if self
                .enumeration_failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(ProviderRecoveryEnumerationErrorV1::Unhealthy);
            }
            Ok(self.entries.clone())
        }
    }

    impl QuiescentRecoveryMaintenanceProviderV1 for ProviderV1 {
        fn acquire_provider_maintenance_guard_v1(
            &self,
            _deadline_monotonic_ms: u64,
        ) -> ProviderMaintenanceGuardOutcomeV1<Self::Custody> {
            ProviderMaintenanceGuardOutcomeV1::Acquired(ProviderCustodyV1 {
                releases: Arc::clone(&self.releases),
            })
        }
    }

    impl GuardedRecoveryBackupExporterV1 for ProviderV1 {
        type Custody = ProviderCustodyV1;

        fn export_recovery_backup_package_v1(
            &self,
            _custody: &mut Self::Custody,
            entry: &ProviderRecoveryInventoryEntryV1,
            destination: &mut ProviderBackupExportDestinationV1,
        ) -> Result<(), ProviderBackupExportErrorV1> {
            match entry.state() {
                ProviderRecoveryStateV1::Published => {
                    let (manifest, material) = self
                        .published_packages
                        .iter()
                        .find(|(manifest, material)| {
                            entry.manifest_digest() == Sha256Digest::digest(manifest)
                                && entry.material_digest() == Sha256Digest::digest(material)
                                && entry.material_length() == material.len() as u64
                        })
                        .ok_or(ProviderBackupExportErrorV1::Invalid)?;
                    destination.write_manifest_v1(manifest)?;
                    destination.write_material_v1(material)
                }
                ProviderRecoveryStateV1::RetiredTombstone => {
                    let retirement_manifest = self
                        .retirement_manifests
                        .iter()
                        .find(|manifest| {
                            entry.retirement_manifest_digest()
                                == Some(Sha256Digest::digest(manifest))
                        })
                        .ok_or(ProviderBackupExportErrorV1::Invalid)?;
                    destination.write_retirement_manifest_v1(retirement_manifest)
                }
            }
        }
    }

    struct ProvisionerSignerV1 {
        signing_key: SigningKey,
        profile_id: Identifier,
        key_id: Identifier,
    }

    impl ProvisionerBackupSigningCustodyV1 for ProvisionerSignerV1 {
        fn attestation_profile_id_v1(&self) -> &Identifier {
            &self.profile_id
        }

        fn attestation_profile_version_v1(&self) -> u16 {
            1
        }

        fn key_id_v1(&self) -> &Identifier {
            &self.key_id
        }

        fn sign_backup_attestation_v1(
            &mut self,
            domain_separated_message: &[u8],
        ) -> Result<[u8; 64], ProvisionerBackupSigningErrorV1> {
            Ok(self.signing_key.sign(domain_separated_message).to_bytes())
        }
    }

    struct PinnedTrustV1 {
        profile_id: Identifier,
        key_id: Identifier,
        key: PinnedEd25519KeyV1,
        serialization: Arc<PinnedTrustSerializationV1>,
    }

    struct PinnedTrustSerializationV1 {
        state: Mutex<PinnedTrustStateV1>,
        custody_released: Condvar,
    }

    struct PinnedTrustStateV1 {
        revoked: bool,
        active_custodies: u64,
    }

    struct PinnedTrustCustodyV1 {
        profile_id: Identifier,
        key_id: Identifier,
        key: PinnedEd25519KeyV1,
        serialization: Arc<PinnedTrustSerializationV1>,
    }

    impl ProvisionerTrustViewV1 for PinnedTrustCustodyV1 {
        fn resolve_ed25519(
            &self,
            attestation_profile_id: &str,
            attestation_profile_version: u64,
            key_id: &str,
        ) -> ProvisionerTrustDecisionV1 {
            if attestation_profile_id == self.profile_id.as_str()
                && attestation_profile_version == 1
                && key_id == self.key_id.as_str()
            {
                ProvisionerTrustDecisionV1::Trusted(self.key)
            } else {
                ProvisionerTrustDecisionV1::Unknown
            }
        }
    }

    impl ProvisionerTrustCustodyV1 for PinnedTrustCustodyV1 {}

    impl Drop for PinnedTrustCustodyV1 {
        fn drop(&mut self) {
            if let Ok(mut state) = self.serialization.state.lock() {
                state.active_custodies = state.active_custodies.saturating_sub(1);
                self.serialization.custody_released.notify_all();
            }
        }
    }

    impl ProvisionerTrustResolverV1 for PinnedTrustV1 {
        fn acquire_restore_trust_custody_v1(&self) -> ProvisionerTrustCustodyOutcomeV1 {
            let mut state = match self.serialization.state.lock() {
                Ok(state) => state,
                Err(_) => return ProvisionerTrustCustodyOutcomeV1::Unavailable,
            };
            if state.revoked {
                return ProvisionerTrustCustodyOutcomeV1::Revoked;
            }
            state.active_custodies = match state.active_custodies.checked_add(1) {
                Some(active_custodies) => active_custodies,
                None => return ProvisionerTrustCustodyOutcomeV1::Unavailable,
            };
            drop(state);
            ProvisionerTrustCustodyOutcomeV1::Acquired(Box::new(PinnedTrustCustodyV1 {
                profile_id: self.profile_id.clone(),
                key_id: self.key_id.clone(),
                key: self.key,
                serialization: Arc::clone(&self.serialization),
            }))
        }

        fn resolve_ed25519(
            &self,
            attestation_profile_id: &str,
            attestation_profile_version: u64,
            key_id: &str,
        ) -> ProvisionerTrustDecisionV1 {
            let state = match self.serialization.state.lock() {
                Ok(state) => state,
                Err(_) => return ProvisionerTrustDecisionV1::Unavailable,
            };
            if state.revoked {
                return ProvisionerTrustDecisionV1::Revoked;
            }
            if attestation_profile_id == self.profile_id.as_str()
                && attestation_profile_version == 1
                && key_id == self.key_id.as_str()
            {
                ProvisionerTrustDecisionV1::Trusted(self.key)
            } else {
                ProvisionerTrustDecisionV1::Unknown
            }
        }
    }

    struct RestorePauseAuthorityV1 {
        releases: Arc<AtomicU64>,
        attempt: Arc<Mutex<Option<(RestoreAttemptInputV1, PausedRotatedRestoreAuthorityV1)>>>,
    }

    struct RestorePauseCustodyV1 {
        paused: PausedRotatedRestoreAuthorityV1,
        releases: Arc<AtomicU64>,
    }

    struct SyntheticRestoredNoDispatchGuardV1;

    impl RestoredNoDispatchAuthorityGuardV1 for SyntheticRestoredNoDispatchGuardV1 {
        fn validate_restored_v1(
            &mut self,
            _expected: &RestoredOldAuthorityBindingV1<'_>,
            _now_monotonic_ms: u64,
        ) -> helix_plan_preparation::NoDispatchAuthorityValidationV1 {
            helix_plan_preparation::NoDispatchAuthorityValidationV1::Valid
        }

        fn release(self) {}
    }

    struct SyntheticRestoredNoDispatchAuthorityV1 {
        acquisitions: Arc<AtomicU64>,
    }

    impl RestoredNoDispatchGuardAuthorityV1 for SyntheticRestoredNoDispatchAuthorityV1 {
        type Guard = SyntheticRestoredNoDispatchGuardV1;

        fn acquire_restored_no_dispatch_guard_v1(
            &self,
            _expected: &RestoredOldAuthorityBindingV1<'_>,
            _rotation: RestoredAuthorityRotationV1,
            _deadline_monotonic_ms: u64,
        ) -> RestoredNoDispatchGuardAcquisitionV1<Self::Guard> {
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            RestoredNoDispatchGuardAcquisitionV1::Acquired(SyntheticRestoredNoDispatchGuardV1)
        }
    }

    impl RestorePauseRotationAuthorityV1 for RestorePauseAuthorityV1 {
        type Custody = RestorePauseCustodyV1;

        fn persist_pause_and_rotate_for_restore_v1(
            &self,
            attempt: &RestoreAttemptInputV1,
            _deadline_monotonic_ms: u64,
        ) -> RestorePauseRotationOutcomeV1<Self::Custody> {
            let mut persisted = match self.attempt.lock() {
                Ok(persisted) => persisted,
                Err(_) => return RestorePauseRotationOutcomeV1::Unavailable,
            };
            if let Some((persisted_input, paused)) = persisted.as_ref() {
                if persisted_input != attempt {
                    return RestorePauseRotationOutcomeV1::Contended;
                }
                return RestorePauseRotationOutcomeV1::Acquired(RestorePauseCustodyV1 {
                    paused: *paused,
                    releases: Arc::clone(&self.releases),
                });
            }
            let mut nonce_preimage = Vec::new();
            nonce_preimage.extend_from_slice(b"HELIXOS\0T072-SYNTHETIC-ATTEMPT-NONCE\0V1\0");
            nonce_preimage.extend_from_slice(attempt.attempt_binding_sha256().as_bytes());
            let nonce_digest = Sha256Digest::digest(&nonce_preimage);
            let nonce = *nonce_digest.as_bytes();
            let restore_identity_sha256 =
                derive_restore_identity_v1(attempt.provenance_attestation_sha256(), &nonce);
            let mut coordinator_preimage = Vec::new();
            coordinator_preimage
                .extend_from_slice(b"HELIXOS\0T072-SYNTHETIC-COORDINATOR-ROOT\0V1\0");
            coordinator_preimage.extend_from_slice(restore_identity_sha256.as_bytes());
            let coordinator_identity_digest = Sha256Digest::digest(&coordinator_preimage);
            let new_coordinator_root_identity =
                CoordinatorRootIdentityV1::from_bytes(*coordinator_identity_digest.as_bytes());
            let mut recovery_preimage = Vec::new();
            recovery_preimage.extend_from_slice(b"HELIXOS\0T072-SYNTHETIC-RECOVERY-ROOT\0V1\0");
            recovery_preimage.extend_from_slice(restore_identity_sha256.as_bytes());
            let new_recovery_root_identity_sha256 = Sha256Digest::digest(&recovery_preimage);
            let paused = match PausedRotatedRestoreAuthorityV1::try_new(
                attempt.attempt_binding_sha256(),
                restore_identity_sha256,
                attempt.provenance_attestation_sha256(),
                attempt.source_inventory_sha256(),
                new_coordinator_root_identity,
                new_recovery_root_identity_sha256,
                attempt.coordinator_destination_binding_sha256(),
                attempt.recovery_destination_binding_sha256(),
                1,
                Sha256Digest::digest(b"boot:fixture-1"),
                Sha256Digest::digest(b"t072-rotated-boot"),
                attempt.source_instance_identity_sha256(),
                Sha256Digest::digest(b"t072-rotated-instance"),
                1,
                2,
                9,
                10,
                attempt.source_generations(),
            ) {
                Ok(paused) => paused,
                Err(_) => return RestorePauseRotationOutcomeV1::Unavailable,
            };
            *persisted = Some((attempt.clone(), paused));
            RestorePauseRotationOutcomeV1::Acquired(RestorePauseCustodyV1 {
                paused,
                releases: Arc::clone(&self.releases),
            })
        }

        fn inspect_existing_restore_attempt_v1(
            &self,
            coordinator_destination_binding_sha256: Sha256Digest,
            recovery_destination_binding_sha256: Sha256Digest,
            _deadline_monotonic_ms: u64,
        ) -> RestorePauseRotationOutcomeV1<Self::Custody> {
            let persisted = match self.attempt.lock() {
                Ok(persisted) => persisted,
                Err(_) => return RestorePauseRotationOutcomeV1::Unavailable,
            };
            let Some((attempt, paused)) = persisted.as_ref() else {
                return RestorePauseRotationOutcomeV1::Unavailable;
            };
            if attempt.coordinator_destination_binding_sha256()
                != coordinator_destination_binding_sha256
                || attempt.recovery_destination_binding_sha256()
                    != recovery_destination_binding_sha256
            {
                return RestorePauseRotationOutcomeV1::Contended;
            }
            RestorePauseRotationOutcomeV1::Acquired(RestorePauseCustodyV1 {
                paused: *paused,
                releases: Arc::clone(&self.releases),
            })
        }
    }

    impl RestorePauseRotationCustodyV1 for RestorePauseCustodyV1 {
        fn capture_paused_rotated_authority_v1(
            &mut self,
        ) -> Result<PausedRotatedRestoreAuthorityV1, MaintenanceCustodyValidationV1> {
            Ok(self.paused)
        }

        fn recheck_paused_rotated_authority_v1(
            &mut self,
            expected: &PausedRotatedRestoreAuthorityV1,
        ) -> MaintenanceCustodyValidationV1 {
            match self.capture_paused_rotated_authority_v1() {
                Ok(actual) if &actual == expected => MaintenanceCustodyValidationV1::Exact,
                Ok(_) => MaintenanceCustodyValidationV1::Revoked,
                Err(error) => error,
            }
        }

        fn release(self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct SyntheticRestoreQuarantineV1 {
        path: PathBuf,
        calls: Arc<AtomicU64>,
    }

    #[derive(serde::Serialize)]
    struct SyntheticPackageQuarantineRecordV1 {
        schema: &'static str,
        package_directory_binding_sha256: String,
        reason: &'static str,
    }

    #[derive(serde::Serialize)]
    struct SyntheticRestoreQuarantineRecordV1 {
        schema: &'static str,
        restore_identity_sha256: String,
        provenance_attestation_sha256: String,
        source_inventory_sha256: String,
        coordinator_root_identity_sha256: String,
        recovery_root_identity_sha256: String,
        coordinator_destination_binding_sha256: String,
        recovery_destination_binding_sha256: String,
        recovery_state_generation: u64,
        coordinator_destination_started: bool,
        recovery_destination_started: bool,
    }

    impl RestoreQuarantineAuthorityV1 for SyntheticRestoreQuarantineV1 {
        fn persist_restore_package_quarantine_v1(
            &self,
            evidence: &RestorePackageQuarantineEvidenceV1,
            _deadline_monotonic_ms: u64,
        ) -> Result<(), PreparationRestoreErrorV1> {
            let reason = match evidence.reason() {
                RestorePackageQuarantineReasonV1::PackageInvalid => "PACKAGE_INVALID",
                RestorePackageQuarantineReasonV1::ProvenanceInvalid => "PROVENANCE_INVALID",
                RestorePackageQuarantineReasonV1::SourceChanged => "SOURCE_CHANGED",
            };
            let bytes = serde_json_canonicalizer::to_vec(&SyntheticPackageQuarantineRecordV1 {
                schema: "helixos.synthetic-package-quarantine/1",
                package_directory_binding_sha256: digest_hex_v1(
                    evidence.package_directory_binding_sha256(),
                ),
                reason,
            })
            .map_err(|_| PreparationRestoreErrorV1::QuarantineUnavailable)?;
            write_or_verify_exact_v1(&self.path, &bytes)
                .map_err(|_| PreparationRestoreErrorV1::QuarantineUnavailable)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn persist_restore_quarantine_v1(
            &self,
            evidence: &RestoreQuarantineEvidenceV1,
            _deadline_monotonic_ms: u64,
        ) -> Result<(), PreparationRestoreErrorV1> {
            if !evidence.coordinator_destination_started()
                && !evidence.recovery_destination_started()
            {
                return Err(PreparationRestoreErrorV1::QuarantineUnavailable);
            }
            let bytes = serde_json_canonicalizer::to_vec(&SyntheticRestoreQuarantineRecordV1 {
                schema: "helixos.synthetic-restore-quarantine/1",
                restore_identity_sha256: digest_hex_v1(evidence.restore_identity_sha256()),
                provenance_attestation_sha256: digest_hex_v1(
                    evidence.provenance_attestation_sha256(),
                ),
                source_inventory_sha256: digest_hex_v1(evidence.source_inventory_sha256()),
                coordinator_root_identity_sha256: digest_hex_v1(
                    evidence.new_coordinator_root_identity_sha256(),
                ),
                recovery_root_identity_sha256: digest_hex_v1(
                    evidence.new_recovery_root_identity_sha256(),
                ),
                coordinator_destination_binding_sha256: digest_hex_v1(
                    evidence.coordinator_destination_binding_sha256(),
                ),
                recovery_destination_binding_sha256: digest_hex_v1(
                    evidence.recovery_destination_binding_sha256(),
                ),
                recovery_state_generation: evidence.recovery_state_generation(),
                coordinator_destination_started: evidence.coordinator_destination_started(),
                recovery_destination_started: evidence.recovery_destination_started(),
            })
            .map_err(|_| PreparationRestoreErrorV1::QuarantineUnavailable)?;
            write_or_verify_exact_v1(&self.path, &bytes)
                .map_err(|_| PreparationRestoreErrorV1::QuarantineUnavailable)?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct SyntheticRecoveryRestoreProviderV1 {
        root: PathBuf,
        destination_binding_sha256: Sha256Digest,
        releases: Arc<AtomicU64>,
        substitute_metadata_on_reopen: bool,
    }

    struct SyntheticRecoveryImportCustodyV1 {
        root: PathBuf,
        root_identity_sha256: Sha256Digest,
        reservation_bytes: Vec<u8>,
        releases: Arc<AtomicU64>,
        _lock: File,
    }

    struct SyntheticRecoveryPendingCustodyV1 {
        root: PathBuf,
        expected: RecoveryRestorePendingExpectationV1,
        releases: Arc<AtomicU64>,
        substitute_metadata_on_reopen: bool,
        _lock: File,
    }

    struct SyntheticRecoveryInspectionCustodyV1 {
        root: PathBuf,
        expected: RecoveryRestoreInspectionExpectationV1,
        observed: RecoveryRestoreInspectionStateV1,
        directory_binding_sha256: Sha256Digest,
        lock_binding_sha256: Option<Sha256Digest>,
        releases: Arc<AtomicU64>,
        directory: File,
        lock: Option<File>,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SyntheticRestoreReservationRecordV1 {
        schema: String,
        restore_identity_sha256: String,
        provenance_attestation_sha256: String,
        source_inventory_sha256: String,
        coordinator_root_identity_sha256: String,
        recovery_root_identity_sha256: String,
        recovery_destination_binding_sha256: String,
        at_rest_profile_id: String,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SyntheticDurableRecoveryEntryV1 {
        schema: String,
        package_binding_sha256: String,
        provider_profile_id: String,
        provider_profile_version: u16,
        provider_id: String,
        provider_generation: u64,
        evidence_class: String,
        at_rest_profile_id: String,
        manifest_sha256: String,
        material_sha256: String,
        material_length: u64,
        reserved_capacity: u64,
        custody: String,
        state: String,
        retirement_manifest_sha256: Option<String>,
    }

    fn digest_hex_v1(digest: Sha256Digest) -> String {
        digest
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn parse_digest_hex_v1(value: &str) -> Result<Sha256Digest, RecoveryRestoreProviderErrorV1> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .ok_or(RecoveryRestoreProviderErrorV1::Invalid)?;
            let low = (chunk[1] as char)
                .to_digit(16)
                .ok_or(RecoveryRestoreProviderErrorV1::Invalid)?;
            bytes[index] = u8::try_from((high << 4) | low)
                .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
        }
        Ok(Sha256Digest::from_bytes(bytes))
    }

    fn encode_synthetic_restore_reservation_v1(
        reservation: &RecoveryRestoreReservationV1,
    ) -> Result<Vec<u8>, RecoveryRestoreProviderErrorV1> {
        serde_json_canonicalizer::to_vec(&SyntheticRestoreReservationRecordV1 {
            schema: "helixos.synthetic-restore-reservation/1".to_owned(),
            restore_identity_sha256: digest_hex_v1(reservation.restore_identity_sha256()),
            provenance_attestation_sha256: digest_hex_v1(
                reservation.provenance_attestation_sha256(),
            ),
            source_inventory_sha256: digest_hex_v1(reservation.source_inventory_sha256()),
            coordinator_root_identity_sha256: digest_hex_v1(
                reservation.new_coordinator_root_identity_sha256(),
            ),
            recovery_root_identity_sha256: digest_hex_v1(
                reservation.new_recovery_root_identity_sha256(),
            ),
            recovery_destination_binding_sha256: digest_hex_v1(
                reservation.recovery_destination_binding_sha256(),
            ),
            at_rest_profile_id: reservation.at_rest_profile_id().as_str().to_owned(),
        })
        .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)
    }

    fn encode_synthetic_recovery_entry_v1(
        package_binding_sha256: Sha256Digest,
        entry: &ProviderRecoveryInventoryEntryV1,
    ) -> Result<Vec<u8>, RecoveryRestoreProviderErrorV1> {
        let evidence_class = match entry.evidence_class() {
            RecoveryEvidenceClassV1::SyntheticConformance => "SYNTHETIC_CONFORMANCE",
            RecoveryEvidenceClassV1::ApprovedProduction => "APPROVED_PRODUCTION",
        };
        let custody = match entry.custody() {
            ProviderRecoveryCustodyV1::OperationBound => "OPERATION_BOUND",
            ProviderRecoveryCustodyV1::QuarantinedOrphan => "QUARANTINED_ORPHAN",
            ProviderRecoveryCustodyV1::OrphanResolutionTombstone => "ORPHAN_RESOLUTION_TOMBSTONE",
        };
        let state = match entry.state() {
            ProviderRecoveryStateV1::Published => "MATERIAL_PRESENT",
            ProviderRecoveryStateV1::RetiredTombstone => "RETIRED_TOMBSTONE",
        };
        serde_json_canonicalizer::to_vec(&SyntheticDurableRecoveryEntryV1 {
            schema: "helixos.synthetic-durable-recovery-entry/1".to_owned(),
            package_binding_sha256: digest_hex_v1(package_binding_sha256),
            provider_profile_id: entry.provider_profile_id().as_str().to_owned(),
            provider_profile_version: entry.provider_profile_version(),
            provider_id: entry.provider_id().as_str().to_owned(),
            provider_generation: entry.provider_generation(),
            evidence_class: evidence_class.to_owned(),
            at_rest_profile_id: entry.at_rest_profile_id().as_str().to_owned(),
            manifest_sha256: digest_hex_v1(entry.manifest_digest()),
            material_sha256: digest_hex_v1(entry.material_digest()),
            material_length: entry.material_length(),
            reserved_capacity: entry.reserved_capacity(),
            custody: custody.to_owned(),
            state: state.to_owned(),
            retirement_manifest_sha256: entry.retirement_manifest_digest().map(digest_hex_v1),
        })
        .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)
    }

    fn decode_synthetic_recovery_entry_v1(
        bytes: &[u8],
    ) -> Result<(Sha256Digest, ProviderRecoveryInventoryEntryV1), RecoveryRestoreProviderErrorV1>
    {
        let record: SyntheticDurableRecoveryEntryV1 =
            serde_json::from_slice(bytes).map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
        if record.schema != "helixos.synthetic-durable-recovery-entry/1"
            || serde_json_canonicalizer::to_vec(&record)
                .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?
                != bytes
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        let evidence_class = match record.evidence_class.as_str() {
            "SYNTHETIC_CONFORMANCE" => RecoveryEvidenceClassV1::SyntheticConformance,
            "APPROVED_PRODUCTION" => RecoveryEvidenceClassV1::ApprovedProduction,
            _ => return Err(RecoveryRestoreProviderErrorV1::Invalid),
        };
        let custody = match record.custody.as_str() {
            "OPERATION_BOUND" => ProviderRecoveryCustodyV1::OperationBound,
            "QUARANTINED_ORPHAN" => ProviderRecoveryCustodyV1::QuarantinedOrphan,
            "ORPHAN_RESOLUTION_TOMBSTONE" => ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
            _ => return Err(RecoveryRestoreProviderErrorV1::Invalid),
        };
        let state = match record.state.as_str() {
            "MATERIAL_PRESENT" => ProviderRecoveryStateV1::Published,
            "RETIRED_TOMBSTONE" => ProviderRecoveryStateV1::RetiredTombstone,
            _ => return Err(RecoveryRestoreProviderErrorV1::Invalid),
        };
        let package_binding_sha256 = parse_digest_hex_v1(&record.package_binding_sha256)?;
        let entry =
            ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                provider_profile_id: Identifier::new(record.provider_profile_id, 128)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?,
                provider_profile_version: record.provider_profile_version,
                provider_id: Identifier::new(record.provider_id, 128)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?,
                provider_generation: record.provider_generation,
                evidence_class,
                at_rest_profile_id: Identifier::new(record.at_rest_profile_id, 128)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?,
                manifest_digest: parse_digest_hex_v1(&record.manifest_sha256)?,
                material_digest: parse_digest_hex_v1(&record.material_sha256)?,
                material_length: record.material_length,
                reserved_capacity: record.reserved_capacity,
                custody,
                state,
                retirement_manifest_digest: record
                    .retirement_manifest_sha256
                    .as_deref()
                    .map(parse_digest_hex_v1)
                    .transpose()?,
            })
            .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
        Ok((package_binding_sha256, entry))
    }

    fn write_or_verify_exact_v1(
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), RecoveryRestoreProviderErrorV1> {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RecoveryRestoreProviderErrorV1::Invalid)?;
        let staging = path.with_file_name(format!(".{file_name}.staging"));
        if path.exists() {
            if fs::read(path).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)? != bytes {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            if staging.exists() {
                let staged =
                    fs::read(&staging).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                if staged.len() > bytes.len() || staged != bytes[..staged.len()] {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
                fs::remove_file(&staging)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                sync_parent_directory_v1(path)?;
            }
            return Ok(());
        }
        let mut staged = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&staging)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&staging)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&staging)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?
            }
            Err(_) => return Err(RecoveryRestoreProviderErrorV1::Unavailable),
        };
        let mut current = Vec::new();
        staged
            .read_to_end(&mut current)
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        if current.len() > bytes.len() || current != bytes[..current.len()] {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        staged
            .write_all(&bytes[current.len()..])
            .and_then(|()| staged.flush())
            .and_then(|()| staged.sync_all())
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        drop(staged);
        match fs::hard_link(&staging, path) {
            Ok(()) => sync_parent_directory_v1(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if fs::read(path).ok().as_deref() != Some(bytes) {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
            }
            Err(_) => return Err(RecoveryRestoreProviderErrorV1::Unavailable),
        }
        fs::remove_file(&staging).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        sync_parent_directory_v1(path)
    }

    fn ensure_exact_directory_v1(path: &Path) -> Result<(), RecoveryRestoreProviderErrorV1> {
        match fs::create_dir(path) {
            Ok(()) => sync_parent_directory_v1(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(path)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    Ok(())
                } else {
                    Err(RecoveryRestoreProviderErrorV1::Invalid)
                }
            }
            Err(_) => Err(RecoveryRestoreProviderErrorV1::Unavailable),
        }
    }

    fn sync_parent_directory_v1(path: &Path) -> Result<(), RecoveryRestoreProviderErrorV1> {
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .ok_or(RecoveryRestoreProviderErrorV1::Invalid)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(())
        }
    }

    fn verify_synthetic_restore_root_layout_v1(
        root: &Path,
        expected_reservation: &[u8],
        allow_metadata_staging: bool,
    ) -> Result<(), RecoveryRestoreProviderErrorV1> {
        let mut names = Vec::new();
        for entry in fs::read_dir(root).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)? {
            let entry = entry.map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            let known_metadata_staging = allow_metadata_staging
                && name == ".recovery-root-metadata.json.staging"
                && metadata.is_file();
            if metadata.file_type().is_symlink()
                || !(known_metadata_staging
                    || matches!(
                        (name.as_str(), metadata.is_file(), metadata.is_dir()),
                        (".restore-lock", true, false)
                            | ("restore-reservation.json", true, false)
                            | ("recovery-root-metadata.json", true, false)
                            | ("packages", false, true)
                    ))
            {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            names.push(name);
        }
        names.sort();
        let required = [".restore-lock", "packages", "restore-reservation.json"];
        if required
            .iter()
            .any(|required| !names.iter().any(|name| name == required))
            || fs::read(root.join("restore-reservation.json"))
                .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?
                != expected_reservation
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        Ok(())
    }

    fn verify_synthetic_pending_reservation_v1(
        root: &Path,
        expected: &RecoveryRestorePendingExpectationV1,
    ) -> Result<(), RecoveryRestoreProviderErrorV1> {
        let bytes = fs::read(root.join("restore-reservation.json"))
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        let record: SyntheticRestoreReservationRecordV1 =
            serde_json::from_slice(&bytes).map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
        if record.schema != "helixos.synthetic-restore-reservation/1"
            || serde_json_canonicalizer::to_vec(&record)
                .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?
                != bytes
            || parse_digest_hex_v1(&record.restore_identity_sha256)?
                != expected.restore_identity_sha256()
            || parse_digest_hex_v1(&record.provenance_attestation_sha256)?
                != expected.provenance_attestation_sha256()
            || parse_digest_hex_v1(&record.source_inventory_sha256)?
                != expected.source_inventory_sha256()
            || parse_digest_hex_v1(&record.recovery_root_identity_sha256)?
                != expected.root_identity_sha256()
            || parse_digest_hex_v1(&record.coordinator_root_identity_sha256)?
                != expected.coordinator_root_identity_sha256()
            || parse_digest_hex_v1(&record.recovery_destination_binding_sha256)?
                != expected.recovery_destination_binding_sha256()
            || record.at_rest_profile_id != expected.at_rest_profile_id().as_str()
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        verify_synthetic_restore_root_layout_v1(root, &bytes, false)
    }

    fn verify_synthetic_pending_root_v1(
        root: &Path,
        expected: &RecoveryRestorePendingExpectationV1,
    ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, RecoveryRestoreProviderErrorV1> {
        verify_synthetic_pending_reservation_v1(root, expected)?;
        let metadata = fs::read(root.join("recovery-root-metadata.json"))
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        let verified = verify_recovery_root_pending_bindings_v1(&metadata)
            .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
        if verified.root_identity_sha256() != expected.root_identity_sha256()
            || verified.restore_identity_sha256() != expected.restore_identity_sha256()
            || verified.provenance_attestation_sha256() != expected.provenance_attestation_sha256()
            || verified.source_inventory_sha256() != expected.source_inventory_sha256()
            || verified.at_rest_profile_id() != expected.at_rest_profile_id()
            || verified.state_generation() != expected.state_generation()
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        verify_synthetic_recovery_files_v1(root)
    }

    fn inspect_synthetic_existing_restore_state_v1(
        root: &Path,
        expected: &RecoveryRestoreInspectionExpectationV1,
    ) -> Result<RecoveryRestoreInspectionStateV1, RecoveryRestoreProviderErrorV1> {
        let mut members = Vec::new();
        for entry in fs::read_dir(root).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)? {
            let entry = entry.map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            if metadata.file_type().is_symlink()
                || !matches!(
                    (name.as_str(), metadata.is_file(), metadata.is_dir()),
                    (".restore-lock", true, false)
                        | ("restore-reservation.json", true, false)
                        | ("recovery-root-metadata.json", true, false)
                        | (".recovery-root-metadata.json.staging", true, false)
                        | ("packages", false, true)
                )
            {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            members.push(name);
        }
        members.sort();
        if members.is_empty() {
            return RecoveryRestoreInspectionStateV1::try_new(
                false,
                0,
                Sha256Digest::digest(b"HELIXOS\0SYNTHETIC-RECOVERY-INSPECTION\0EMPTY\0V1\0"),
            );
        }
        if !members.iter().any(|name| name == ".restore-lock") {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }

        let reservation_path = root.join("restore-reservation.json");
        let reservation = match fs::read(&reservation_path) {
            Ok(bytes) => {
                if bytes.len()
                    > usize::try_from(RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1).unwrap_or(usize::MAX)
                {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
                let record: SyntheticRestoreReservationRecordV1 = serde_json::from_slice(&bytes)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
                if record.schema != "helixos.synthetic-restore-reservation/1"
                    || serde_json_canonicalizer::to_vec(&record)
                        .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?
                        != bytes
                    || parse_digest_hex_v1(&record.restore_identity_sha256)?
                        != expected.restore_identity_sha256()
                    || parse_digest_hex_v1(&record.provenance_attestation_sha256)?
                        != expected.provenance_attestation_sha256()
                    || parse_digest_hex_v1(&record.source_inventory_sha256)?
                        != expected.source_inventory_sha256()
                    || parse_digest_hex_v1(&record.coordinator_root_identity_sha256)?
                        != expected.coordinator_root_identity_sha256()
                    || parse_digest_hex_v1(&record.recovery_root_identity_sha256)?
                        != expected.recovery_root_identity_sha256()
                    || parse_digest_hex_v1(&record.recovery_destination_binding_sha256)?
                        != expected.recovery_destination_binding_sha256()
                    || record.at_rest_profile_id != expected.at_rest_profile_id().as_str()
                {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
                verify_synthetic_restore_root_layout_v1(root, &bytes, true)?;
                Some(bytes)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(RecoveryRestoreProviderErrorV1::Unavailable),
        };
        if reservation.is_none() {
            if members
                .iter()
                .any(|name| !matches!(name.as_str(), ".restore-lock" | "packages"))
            {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            if root.join("packages").is_dir()
                && fs::read_dir(root.join("packages"))
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?
                    .next()
                    .is_some()
            {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
        }

        let metadata = match fs::read(root.join("recovery-root-metadata.json")) {
            Ok(bytes) => {
                if reservation.is_none()
                    || bytes.len()
                        > usize::try_from(RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1)
                            .unwrap_or(usize::MAX)
                {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
                let verified = verify_recovery_root_pending_bindings_v1(&bytes)
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
                if verified.root_identity_sha256() != expected.recovery_root_identity_sha256()
                    || verified.restore_identity_sha256() != expected.restore_identity_sha256()
                    || verified.provenance_attestation_sha256()
                        != expected.provenance_attestation_sha256()
                    || verified.source_inventory_sha256() != expected.source_inventory_sha256()
                    || verified.at_rest_profile_id() != expected.at_rest_profile_id()
                    || verified.state_generation() != 1
                {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
                Some((bytes, verified.state_generation()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(RecoveryRestoreProviderErrorV1::Unavailable),
        };
        let state_generation = metadata.as_ref().map_or(
            if reservation.is_some() { 1 } else { 0 },
            |(_, generation)| *generation,
        );
        let mut state_hasher = Sha256::new();
        state_hasher.update(b"HELIXOS\0SYNTHETIC-RECOVERY-INSPECTION\0V1\0");
        state_hasher.update(expected.coordinator_destination_binding_sha256().as_bytes());
        state_hasher.update(expected.recovery_destination_binding_sha256().as_bytes());
        for name in &members {
            state_hasher.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
            state_hasher.update(name.as_bytes());
        }
        if let Some(bytes) = reservation.as_ref() {
            state_hasher.update(Sha256Digest::digest(bytes).as_bytes());
        }
        if let Some((bytes, _)) = metadata.as_ref() {
            state_hasher.update(Sha256Digest::digest(bytes).as_bytes());
        }
        RecoveryRestoreInspectionStateV1::try_new(
            true,
            state_generation,
            Sha256Digest::from_bytes(state_hasher.finalize().into()),
        )
    }

    #[cfg(unix)]
    fn synthetic_directory_binding_sha256_v1(
        root: &Path,
        directory: &File,
    ) -> Result<Sha256Digest, RecoveryRestoreProviderErrorV1> {
        use std::os::unix::fs::MetadataExt as _;

        let path_metadata =
            fs::symlink_metadata(root).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        let held_metadata = directory
            .metadata()
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || !held_metadata.is_dir()
            || path_metadata.dev() != held_metadata.dev()
            || path_metadata.ino() != held_metadata.ino()
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"HELIXOS\0SYNTHETIC-RECOVERY-DIRECTORY-CUSTODY\0V1\0");
        hasher.update(path_metadata.dev().to_be_bytes());
        hasher.update(path_metadata.ino().to_be_bytes());
        Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
    }

    #[cfg(not(unix))]
    fn synthetic_directory_binding_sha256_v1(
        _root: &Path,
        _directory: &File,
    ) -> Result<Sha256Digest, RecoveryRestoreProviderErrorV1> {
        Err(RecoveryRestoreProviderErrorV1::Unavailable)
    }

    #[cfg(unix)]
    fn synthetic_file_binding_sha256_v1(
        path: &Path,
        file: &File,
    ) -> Result<Sha256Digest, RecoveryRestoreProviderErrorV1> {
        use std::os::unix::fs::MetadataExt as _;

        let path_metadata =
            fs::symlink_metadata(path).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        let held_metadata = file
            .metadata()
            .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || !held_metadata.is_file()
            || path_metadata.dev() != held_metadata.dev()
            || path_metadata.ino() != held_metadata.ino()
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"HELIXOS\0SYNTHETIC-RECOVERY-LOCK-CUSTODY\0V1\0");
        hasher.update(path_metadata.dev().to_be_bytes());
        hasher.update(path_metadata.ino().to_be_bytes());
        Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
    }

    #[cfg(not(unix))]
    fn synthetic_file_binding_sha256_v1(
        _path: &Path,
        _file: &File,
    ) -> Result<Sha256Digest, RecoveryRestoreProviderErrorV1> {
        Err(RecoveryRestoreProviderErrorV1::Unavailable)
    }

    fn recheck_synthetic_inspection_custody_v1(
        custody: &SyntheticRecoveryInspectionCustodyV1,
    ) -> Result<(), RecoveryRestoreProviderErrorV1> {
        if synthetic_directory_binding_sha256_v1(&custody.root, &custody.directory)?
            != custody.directory_binding_sha256
        {
            return Err(RecoveryRestoreProviderErrorV1::Invalid);
        }
        match (&custody.lock, custody.lock_binding_sha256) {
            (Some(lock), Some(expected))
                if synthetic_file_binding_sha256_v1(&custody.root.join(".restore-lock"), lock)?
                    == expected =>
            {
                Ok(())
            }
            (None, None) => {
                if fs::symlink_metadata(custody.root.join(".restore-lock")).is_ok() {
                    Err(RecoveryRestoreProviderErrorV1::Invalid)
                } else {
                    Ok(())
                }
            }
            _ => Err(RecoveryRestoreProviderErrorV1::Invalid),
        }
    }

    impl RecoveryCleanupGuardV1 for SyntheticRecoveryImportCustodyV1 {
        fn release(self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RecoveryCleanupGuardV1 for SyntheticRecoveryPendingCustodyV1 {
        fn release(self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RecoveryCleanupGuardV1 for SyntheticRecoveryInspectionCustodyV1 {
        fn release(self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RecoveryRestoreImportCustodyV1 for SyntheticRecoveryImportCustodyV1 {
        fn capture_restore_root_source_v1(
            &mut self,
        ) -> Result<RecoveryRestoreRootSourceV1, RecoveryRestoreProviderErrorV1> {
            RecoveryRestoreRootSourceV1::try_new(self.root_identity_sha256, 1)
        }

        fn recheck_restore_root_source_v1(
            &mut self,
            expected: &RecoveryRestoreRootSourceV1,
        ) -> MaintenanceCustodyValidationV1 {
            if verify_synthetic_restore_root_layout_v1(&self.root, &self.reservation_bytes, true)
                .is_ok()
                && expected.root_identity_sha256() == self.root_identity_sha256
                && expected.provider_generation() == 1
            {
                MaintenanceCustodyValidationV1::Exact
            } else {
                MaintenanceCustodyValidationV1::Revoked
            }
        }

        fn publish_restore_pending_metadata_v1(
            &mut self,
            canonical_metadata: &[u8],
        ) -> Result<(), RecoveryRestoreProviderErrorV1> {
            verify_recovery_root_pending_bindings_v1(canonical_metadata)
                .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
            write_or_verify_exact_v1(
                &self.root.join("recovery-root-metadata.json"),
                canonical_metadata,
            )?;
            Ok(())
        }

        fn enumerate_imported_recovery_inventory_v1(
            &mut self,
        ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, RecoveryRestoreProviderErrorV1> {
            verify_synthetic_recovery_files_v1(&self.root)
        }
    }

    impl RecoveryRestorePendingCustodyV1 for SyntheticRecoveryPendingCustodyV1 {
        fn read_restore_pending_metadata_v1(
            &mut self,
            maximum_length: u64,
        ) -> Result<Vec<u8>, RecoveryRestoreProviderErrorV1> {
            let _inventory = verify_synthetic_pending_root_v1(&self.root, &self.expected)?;
            if self.substitute_metadata_on_reopen {
                return Ok(b"{}".to_vec());
            }
            let bytes = fs::read(self.root.join("recovery-root-metadata.json"))
                .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            if u64::try_from(bytes.len())
                .ok()
                .is_none_or(|length| length > maximum_length)
            {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            Ok(bytes)
        }

        fn enumerate_pending_recovery_inventory_v1(
            &mut self,
        ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, RecoveryRestoreProviderErrorV1> {
            verify_synthetic_pending_root_v1(&self.root, &self.expected)
        }
    }

    impl RecoveryRestoreInspectionCustodyV1 for SyntheticRecoveryInspectionCustodyV1 {
        fn capture_existing_restore_state_v1(
            &mut self,
        ) -> Result<RecoveryRestoreInspectionStateV1, RecoveryRestoreProviderErrorV1> {
            recheck_synthetic_inspection_custody_v1(self)?;
            let actual = inspect_synthetic_existing_restore_state_v1(&self.root, &self.expected)?;
            if actual != self.observed {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            Ok(actual)
        }

        fn recheck_existing_restore_state_v1(
            &mut self,
            expected: &RecoveryRestoreInspectionStateV1,
        ) -> MaintenanceCustodyValidationV1 {
            if let Err(error) = recheck_synthetic_inspection_custody_v1(self) {
                return match error {
                    RecoveryRestoreProviderErrorV1::Invalid => {
                        MaintenanceCustodyValidationV1::Revoked
                    }
                    RecoveryRestoreProviderErrorV1::Unavailable => {
                        MaintenanceCustodyValidationV1::Unavailable
                    }
                };
            }
            match inspect_synthetic_existing_restore_state_v1(&self.root, &self.expected) {
                Ok(actual) if &actual == expected && actual == self.observed => {
                    MaintenanceCustodyValidationV1::Exact
                }
                Ok(_) | Err(RecoveryRestoreProviderErrorV1::Invalid) => {
                    MaintenanceCustodyValidationV1::Revoked
                }
                Err(RecoveryRestoreProviderErrorV1::Unavailable) => {
                    MaintenanceCustodyValidationV1::Unavailable
                }
            }
        }
    }

    impl RecoveryRestoreProviderV1 for SyntheticRecoveryRestoreProviderV1 {
        type ImportCustody = SyntheticRecoveryImportCustodyV1;
        type PendingCustody = SyntheticRecoveryPendingCustodyV1;
        type InspectionCustody = SyntheticRecoveryInspectionCustodyV1;

        fn provisioned_restore_destination_binding_sha256_v1(
            &self,
        ) -> Result<Sha256Digest, RecoveryRestoreProviderErrorV1> {
            Ok(self.destination_binding_sha256)
        }

        fn inspect_existing_restore_root_v1(
            &self,
            expected: &RecoveryRestoreInspectionExpectationV1,
            _deadline_monotonic_ms: u64,
        ) -> RecoveryRestoreCustodyOutcomeV1<Self::InspectionCustody> {
            if self.destination_binding_sha256 != expected.recovery_destination_binding_sha256() {
                return RecoveryRestoreCustodyOutcomeV1::Unavailable;
            }
            let directory = match File::open(&self.root) {
                Ok(directory) => directory,
                Err(_) => return RecoveryRestoreCustodyOutcomeV1::Unavailable,
            };
            let directory_binding_sha256 =
                match synthetic_directory_binding_sha256_v1(&self.root, &directory) {
                    Ok(binding) => binding,
                    Err(_) => return RecoveryRestoreCustodyOutcomeV1::Unavailable,
                };
            let lock_path = self.root.join(".restore-lock");
            let lock = match fs::symlink_metadata(&lock_path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return RecoveryRestoreCustodyOutcomeV1::Unavailable
                }
                Ok(_) => match OpenOptions::new().read(true).write(true).open(&lock_path) {
                    Ok(lock) if lock.try_lock().is_ok() => Some(lock),
                    Ok(_) => return RecoveryRestoreCustodyOutcomeV1::Contended,
                    Err(_) => return RecoveryRestoreCustodyOutcomeV1::Unavailable,
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return RecoveryRestoreCustodyOutcomeV1::Unavailable,
            };
            let lock_binding_sha256 = match lock.as_ref() {
                Some(lock) => match synthetic_file_binding_sha256_v1(&lock_path, lock) {
                    Ok(binding) => Some(binding),
                    Err(_) => return RecoveryRestoreCustodyOutcomeV1::Unavailable,
                },
                None => None,
            };
            let observed = match inspect_synthetic_existing_restore_state_v1(&self.root, expected) {
                Ok(observed) => observed,
                Err(_) => return RecoveryRestoreCustodyOutcomeV1::Unavailable,
            };
            if observed.destination_started() && lock.is_none() {
                return RecoveryRestoreCustodyOutcomeV1::Unavailable;
            }
            RecoveryRestoreCustodyOutcomeV1::Acquired(SyntheticRecoveryInspectionCustodyV1 {
                root: self.root.clone(),
                expected: expected.clone(),
                observed,
                directory_binding_sha256,
                lock_binding_sha256,
                releases: Arc::clone(&self.releases),
                directory,
                lock,
            })
        }

        fn begin_or_resume_restore_root_v1(
            &self,
            reservation: &RecoveryRestoreReservationV1,
            _deadline_monotonic_ms: u64,
        ) -> RecoveryRestoreCustodyOutcomeV1<Self::ImportCustody> {
            if reservation.at_rest_profile_id().as_str() != "at-rest.synthetic-v1" {
                return RecoveryRestoreCustodyOutcomeV1::Unavailable;
            }
            let reservation_bytes = match encode_synthetic_restore_reservation_v1(reservation) {
                Ok(bytes) => bytes,
                Err(_) => return RecoveryRestoreCustodyOutcomeV1::Unavailable,
            };
            let lock_path = self.root.join(".restore-lock");
            if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return RecoveryRestoreCustodyOutcomeV1::Unavailable;
                }
            }
            let lock = match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
            {
                Ok(lock) if lock.try_lock().is_ok() => lock,
                _ => return RecoveryRestoreCustodyOutcomeV1::Contended,
            };
            if sync_parent_directory_v1(&lock_path).is_err()
                || ensure_exact_directory_v1(&self.root.join("packages")).is_err()
                || write_or_verify_exact_v1(
                    &self.root.join("restore-reservation.json"),
                    &reservation_bytes,
                )
                .is_err()
                || verify_synthetic_restore_root_layout_v1(&self.root, &reservation_bytes, true)
                    .is_err()
            {
                return RecoveryRestoreCustodyOutcomeV1::Unavailable;
            }
            RecoveryRestoreCustodyOutcomeV1::Acquired(SyntheticRecoveryImportCustodyV1 {
                root: self.root.clone(),
                root_identity_sha256: reservation.new_recovery_root_identity_sha256(),
                reservation_bytes,
                releases: Arc::clone(&self.releases),
                _lock: lock,
            })
        }

        fn import_recovery_backup_package_v1(
            &self,
            custody: &mut Self::ImportCustody,
            source: &mut ProviderRestorePackageSourceV1<'_>,
        ) -> Result<(), RecoveryRestoreProviderErrorV1> {
            let entry = source.entry().clone();
            let package_binding_sha256 = source.package_binding_sha256();
            let package = custody
                .root
                .join("packages")
                .join(digest_hex_v1(package_binding_sha256));
            let mut members = Vec::new();
            match entry.state() {
                ProviderRecoveryStateV1::Published => {
                    let manifest =
                        source.read_manifest_v1(RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1)?;
                    let material = source.read_material_v1(entry.reserved_capacity())?;
                    members.push(("manifest.json", manifest));
                    members.push(("material.bin", material));
                }
                ProviderRecoveryStateV1::RetiredTombstone => {
                    let retirement = source
                        .read_retirement_manifest_v1(RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1)?;
                    members.push(("retirement-manifest.json", retirement));
                }
            }
            let entry_bytes = encode_synthetic_recovery_entry_v1(package_binding_sha256, &entry)?;
            ensure_exact_directory_v1(&package)?;
            for (name, bytes) in &members {
                write_or_verify_exact_v1(&package.join(name), bytes)?;
            }
            // The canonical entry record is the package publication point and is written last.
            write_or_verify_exact_v1(&package.join("entry.json"), &entry_bytes)?;
            Ok(())
        }

        fn reopen_restore_pending_root_v1(
            &self,
            expected: &RecoveryRestorePendingExpectationV1,
            _deadline_monotonic_ms: u64,
        ) -> RecoveryRestoreCustodyOutcomeV1<Self::PendingCustody> {
            if self.destination_binding_sha256 != expected.recovery_destination_binding_sha256() {
                return RecoveryRestoreCustodyOutcomeV1::Unavailable;
            }
            let lock = match OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.root.join(".restore-lock"))
            {
                Ok(lock) if lock.try_lock().is_ok() => lock,
                _ => return RecoveryRestoreCustodyOutcomeV1::Contended,
            };
            if verify_synthetic_pending_root_v1(&self.root, expected).is_err() {
                return RecoveryRestoreCustodyOutcomeV1::Unavailable;
            }
            RecoveryRestoreCustodyOutcomeV1::Acquired(SyntheticRecoveryPendingCustodyV1 {
                root: self.root.clone(),
                expected: expected.clone(),
                releases: Arc::clone(&self.releases),
                substitute_metadata_on_reopen: self.substitute_metadata_on_reopen,
                _lock: lock,
            })
        }
    }

    fn write_create_new_v1(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()
    }

    fn verify_synthetic_recovery_files_v1(
        root: &Path,
    ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, RecoveryRestoreProviderErrorV1> {
        let packages_root = root.join("packages");
        let mut package_directories = Vec::new();
        for directory in
            fs::read_dir(&packages_root).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?
        {
            let directory = directory.map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            let name = directory
                .file_name()
                .into_string()
                .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
            let metadata = fs::symlink_metadata(directory.path())
                .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            let binding = parse_digest_hex_v1(&name)?;
            if digest_hex_v1(binding) != name {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            package_directories.push((name, directory.path(), binding));
        }
        package_directories.sort_by(|left, right| left.0.cmp(&right.0));
        let mut entries = Vec::new();
        for (_name, package, directory_binding) in package_directories {
            let entry_bytes = fs::read(package.join("entry.json"))
                .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
            if entry_bytes.len()
                > usize::try_from(RESTORE_CANONICAL_MEMBER_MAX_BYTES_V1).unwrap_or(usize::MAX)
            {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            let (record_binding, entry) = decode_synthetic_recovery_entry_v1(&entry_bytes)?;
            if record_binding != directory_binding {
                return Err(RecoveryRestoreProviderErrorV1::Invalid);
            }
            let mut actual_names = Vec::new();
            for member in
                fs::read_dir(&package).map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?
            {
                let member = member.map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                let name = member
                    .file_name()
                    .into_string()
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Invalid)?;
                let metadata = fs::symlink_metadata(member.path())
                    .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(RecoveryRestoreProviderErrorV1::Invalid);
                }
                actual_names.push(name);
            }
            actual_names.sort();
            match entry.state() {
                ProviderRecoveryStateV1::Published => {
                    if actual_names != ["entry.json", "manifest.json", "material.bin"] {
                        return Err(RecoveryRestoreProviderErrorV1::Invalid);
                    }
                    let manifest = fs::read(package.join("manifest.json"))
                        .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                    let material = fs::read(package.join("material.bin"))
                        .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                    if Sha256Digest::digest(&manifest) != entry.manifest_digest()
                        || Sha256Digest::digest(&material) != entry.material_digest()
                        || u64::try_from(material.len()).ok() != Some(entry.material_length())
                    {
                        return Err(RecoveryRestoreProviderErrorV1::Invalid);
                    }
                }
                ProviderRecoveryStateV1::RetiredTombstone => {
                    if actual_names != ["entry.json", "retirement-manifest.json"] {
                        return Err(RecoveryRestoreProviderErrorV1::Invalid);
                    }
                    let retirement = fs::read(package.join("retirement-manifest.json"))
                        .map_err(|_| RecoveryRestoreProviderErrorV1::Unavailable)?;
                    if entry.retirement_manifest_digest() != Some(Sha256Digest::digest(&retirement))
                    {
                        return Err(RecoveryRestoreProviderErrorV1::Invalid);
                    }
                }
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    struct RestoreConformanceCleanupV1 {
        directories: Vec<PathBuf>,
        files: Vec<PathBuf>,
    }

    impl Drop for RestoreConformanceCleanupV1 {
        fn drop(&mut self) {
            for file in &self.files {
                let _ = fs::remove_file(file);
            }
            for directory in self.directories.iter().rev() {
                let _ = fs::remove_dir_all(directory);
            }
        }
    }

    fn run_restore_packages_v1(
        package_root: &Path,
        trust: &PinnedTrustV1,
        historical_plan_keys: &NoHistoricalPlanKeysV1,
        clock: &FixedClockV1,
        sequence: u64,
        expected_entry_count: u64,
        fault_probe: MaintenanceFaultProbeV1,
    ) -> Result<(), &'static str> {
        let attempt_binding_kat = derive_restore_attempt_binding_v1(
            std::array::from_fn(|index| Sha256Digest::from_bytes([index as u8; 32])),
            "at-rest.synthetic-v1",
        );
        if attempt_binding_kat
            != parse_digest_hex_v1(
                "8aa11233c25a272e7fbe2ca85b52b29fda269434eeaab673a80512b6531af0e9",
            )
            .map_err(|_| "restore-attempt-binding-kat-decode")?
            || derive_restore_identity_v1(Sha256Digest::from_bytes([0xaa; 32]), &[0xbb; 32])
                != parse_digest_hex_v1(
                    "f5579b4ce91922d67bb19920dfd866e543bcd88b34dad1393402433f8f18ef76",
                )
                .map_err(|_| "restore-identity-kat-decode")?
        {
            return Err("restore-binding-kat");
        }
        fs::hard_link(
            package_root.join(RESTORE_TOP_LEVEL_MEMBER_V1),
            package_root.join("staging/preparation-backup.json"),
        )
        .map_err(|_| "restore-staging-hardlink")?;
        let positive_coordinator = std::env::temp_dir().join(format!(
            "helixos-t072-positive-coordinator-{}-{sequence}",
            std::process::id()
        ));
        let positive_recovery = std::env::temp_dir().join(format!(
            "helixos-t072-positive-recovery-{}-{sequence}",
            std::process::id()
        ));
        let positive_quarantine = std::env::temp_dir().join(format!(
            "helixos-t072-positive-quarantine-{}-{sequence}",
            std::process::id()
        ));
        let negative_coordinator = std::env::temp_dir().join(format!(
            "helixos-t072-negative-coordinator-{}-{sequence}",
            std::process::id()
        ));
        let negative_recovery = std::env::temp_dir().join(format!(
            "helixos-t072-negative-recovery-{}-{sequence}",
            std::process::id()
        ));
        let negative_quarantine = std::env::temp_dir().join(format!(
            "helixos-t072-negative-quarantine-{}-{sequence}",
            std::process::id()
        ));
        let mismatched_coordinator = std::env::temp_dir().join(format!(
            "helixos-t072-mismatched-coordinator-{}-{sequence}",
            std::process::id()
        ));
        let mismatched_recovery = std::env::temp_dir().join(format!(
            "helixos-t072-mismatched-recovery-{}-{sequence}",
            std::process::id()
        ));
        let invalid_package_quarantine = std::env::temp_dir().join(format!(
            "helixos-t072-invalid-package-quarantine-{}-{sequence}",
            std::process::id()
        ));
        for root in [
            &positive_coordinator,
            &positive_recovery,
            &negative_coordinator,
            &negative_recovery,
            &mismatched_coordinator,
            &mismatched_recovery,
        ] {
            fs::create_dir(root).map_err(|_| "restore-root-create")?;
        }
        let _cleanup = RestoreConformanceCleanupV1 {
            directories: vec![
                positive_coordinator.clone(),
                positive_recovery.clone(),
                negative_coordinator.clone(),
                negative_recovery.clone(),
                mismatched_coordinator.clone(),
                mismatched_recovery.clone(),
            ],
            files: vec![
                positive_quarantine.clone(),
                negative_quarantine.clone(),
                invalid_package_quarantine.clone(),
            ],
        };

        let positive_pause_releases = Arc::new(AtomicU64::new(0));
        let positive_provider_releases = Arc::new(AtomicU64::new(0));
        let positive_quarantine_calls = Arc::new(AtomicU64::new(0));
        let positive_quarantine_authority = SyntheticRestoreQuarantineV1 {
            path: positive_quarantine.clone(),
            calls: Arc::clone(&positive_quarantine_calls),
        };
        let positive_pause_authority = RestorePauseAuthorityV1 {
            releases: Arc::clone(&positive_pause_releases),
            attempt: Arc::new(Mutex::new(None)),
        };
        let positive_provider = SyntheticRecoveryRestoreProviderV1 {
            root: positive_recovery.clone(),
            destination_binding_sha256: Sha256Digest::digest(b"t072-positive-recovery-destination"),
            releases: Arc::clone(&positive_provider_releases),
            substitute_metadata_on_reopen: false,
        };
        let positive_package =
            ProvisionedRestorePackageV1::try_from_attested(package_root.to_path_buf())
                .map_err(|_| "restore-package-attest")?;
        let positive_accepted = accept_preparation_restore_package_with_probe_v1(
            positive_package,
            &positive_quarantine_authority,
            trust,
            historical_plan_keys,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
            fault_probe.clone(),
        )
        .map_err(restore_error_phase_v1)?;
        let trust_serialization = Arc::clone(&trust.serialization);
        let (revocation_started_tx, revocation_started_rx) = std::sync::mpsc::sync_channel(0);
        let (revocation_completed_tx, revocation_completed_rx) = std::sync::mpsc::sync_channel(0);
        let revocation = std::thread::spawn(move || -> Result<(), ()> {
            let mut state = trust_serialization.state.lock().map_err(|_| ())?;
            revocation_started_tx.send(()).map_err(|_| ())?;
            while state.active_custodies != 0 {
                state = trust_serialization
                    .custody_released
                    .wait(state)
                    .map_err(|_| ())?;
            }
            state.revoked = true;
            revocation_completed_tx.send(()).map_err(|_| ())
        });
        revocation_started_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "restore-trust-revocation-not-started")?;
        if !matches!(
            revocation_completed_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ) {
            return Err("restore-trust-custody-did-not-serialize-revocation");
        }
        let positive_root =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
                positive_coordinator.clone(),
                Sha256Digest::digest(b"t072-positive-coordinator-destination"),
                Identifier::new("at-rest.synthetic-v1".to_owned(), 128)
                    .map_err(|_| "restore-coordinator-profile")?,
            )
            .map_err(|_| "restore-coordinator-attest")?;
        let positive_verified = restore_preparation_to_pending_v1(
            positive_accepted,
            &positive_root,
            &positive_pause_authority,
            &positive_provider,
            &positive_quarantine_authority,
            historical_plan_keys,
            2,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(restore_error_phase_v1)?;
        revocation_completed_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "restore-trust-revocation-remained-blocked")?;
        revocation
            .join()
            .map_err(|_| "restore-trust-revocation-panicked")?
            .map_err(|_| "restore-trust-revocation-failed")?;
        {
            let mut state = trust
                .serialization
                .state
                .lock()
                .map_err(|_| "restore-trust-state-poisoned")?;
            if !state.revoked || state.active_custodies != 0 {
                return Err("restore-trust-revocation-state-invalid");
            }
            state.revoked = false;
        }
        assert_pending_coordinator_file_v1(&positive_coordinator)?;

        // Exact begin-or-resume uses a fresh provider object and reconstructs all recovery
        // inventory from durable package records. No in-memory import state is reused.
        let resumed_provider = SyntheticRecoveryRestoreProviderV1 {
            root: positive_recovery.clone(),
            destination_binding_sha256: Sha256Digest::digest(b"t072-positive-recovery-destination"),
            releases: Arc::clone(&positive_provider_releases),
            substitute_metadata_on_reopen: false,
        };
        let resumed_package =
            ProvisionedRestorePackageV1::try_from_attested(package_root.to_path_buf())
                .map_err(|_| "resumed-package-attest")?;
        let resumed_accepted = accept_preparation_restore_package_v1(
            resumed_package,
            &positive_quarantine_authority,
            trust,
            historical_plan_keys,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(restore_error_phase_v1)?;
        let resumed_root =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
                positive_coordinator.clone(),
                Sha256Digest::digest(b"t072-positive-coordinator-destination"),
                Identifier::new("at-rest.synthetic-v1".to_owned(), 128)
                    .map_err(|_| "resumed-coordinator-profile")?,
            )
            .map_err(|_| "resumed-coordinator-attest")?;
        let resumed_verified = restore_preparation_to_pending_v1(
            resumed_accepted,
            &resumed_root,
            &positive_pause_authority,
            &resumed_provider,
            &positive_quarantine_authority,
            historical_plan_keys,
            2,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(restore_error_phase_v1)?;
        if positive_verified.store_generation() != expected_entry_count + 1
            || resumed_verified != positive_verified
            || positive_verified.active_quarantine_count() != expected_entry_count
            || positive_verified.provider_set_count() != 1
            || positive_verified.entry_count() != expected_entry_count
            || positive_pause_releases.load(Ordering::SeqCst) != 2
            || positive_provider_releases.load(Ordering::SeqCst) != 4
            || positive_quarantine_calls.load(Ordering::SeqCst) != 0
            || positive_quarantine.exists()
        {
            return Err("restore-positive-evidence");
        }
        assert_pending_coordinator_file_v1(&positive_coordinator)?;

        let mismatched_provider_releases = Arc::new(AtomicU64::new(0));
        let mismatched_provider = SyntheticRecoveryRestoreProviderV1 {
            root: mismatched_recovery.clone(),
            destination_binding_sha256: Sha256Digest::digest(
                b"t072-mismatched-recovery-destination",
            ),
            releases: Arc::clone(&mismatched_provider_releases),
            substitute_metadata_on_reopen: false,
        };
        let mismatched_package =
            ProvisionedRestorePackageV1::try_from_attested(package_root.to_path_buf())
                .map_err(|_| "mismatched-package-attest")?;
        let mismatched_accepted = accept_preparation_restore_package_v1(
            mismatched_package,
            &positive_quarantine_authority,
            trust,
            historical_plan_keys,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(restore_error_phase_v1)?;
        let mismatched_root =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
                mismatched_coordinator.clone(),
                Sha256Digest::digest(b"t072-mismatched-coordinator-destination"),
                Identifier::new("at-rest.synthetic-v1".to_owned(), 128)
                    .map_err(|_| "mismatched-coordinator-profile")?,
            )
            .map_err(|_| "mismatched-coordinator-attest")?;
        match restore_preparation_to_pending_v1(
            mismatched_accepted,
            &mismatched_root,
            &positive_pause_authority,
            &mismatched_provider,
            &positive_quarantine_authority,
            historical_plan_keys,
            2,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        ) {
            Err(PreparationRestoreErrorV1::PauseContended) => {}
            Err(_) => return Err("mismatched-destination-wrong-refusal"),
            Ok(_) => return Err("mismatched-destination-accepted"),
        }
        if fs::read_dir(&mismatched_coordinator)
            .map_err(|_| "mismatched-coordinator-read")?
            .next()
            .is_some()
            || fs::read_dir(&mismatched_recovery)
                .map_err(|_| "mismatched-recovery-read")?
                .next()
                .is_some()
            || mismatched_provider_releases.load(Ordering::SeqCst) != 0
        {
            return Err("mismatched-destination-mutated");
        }

        let invalid_package_calls = Arc::new(AtomicU64::new(0));
        let invalid_package_authority = SyntheticRestoreQuarantineV1 {
            path: invalid_package_quarantine.clone(),
            calls: Arc::clone(&invalid_package_calls),
        };
        let unexpected_member = package_root.join("unexpected-member.bin");
        write_create_new_v1(&unexpected_member, b"unexpected")
            .map_err(|_| "invalid-package-extra-create")?;
        let invalid_package =
            ProvisionedRestorePackageV1::try_from_attested(package_root.to_path_buf())
                .map_err(|_| "invalid-package-attest")?;
        match accept_preparation_restore_package_with_probe_v1(
            invalid_package,
            &invalid_package_authority,
            trust,
            historical_plan_keys,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
            fault_probe.clone(),
        ) {
            Err(PreparationRestoreErrorV1::PackageInvalid) => {}
            Err(_) => return Err("invalid-package-wrong-refusal"),
            Ok(_) => return Err("invalid-package-accepted"),
        }
        fs::remove_file(&unexpected_member).map_err(|_| "invalid-package-extra-remove")?;
        if invalid_package_calls.load(Ordering::SeqCst) != 1
            || !invalid_package_quarantine.is_file()
        {
            return Err("invalid-package-not-quarantined");
        }

        let negative_pause_releases = Arc::new(AtomicU64::new(0));
        let negative_provider_releases = Arc::new(AtomicU64::new(0));
        let negative_quarantine_calls = Arc::new(AtomicU64::new(0));
        let negative_quarantine_authority = SyntheticRestoreQuarantineV1 {
            path: negative_quarantine.clone(),
            calls: Arc::clone(&negative_quarantine_calls),
        };
        let negative_pause_authority = RestorePauseAuthorityV1 {
            releases: Arc::clone(&negative_pause_releases),
            attempt: Arc::new(Mutex::new(None)),
        };
        let negative_provider = SyntheticRecoveryRestoreProviderV1 {
            root: negative_recovery,
            destination_binding_sha256: Sha256Digest::digest(b"t072-negative-recovery-destination"),
            releases: Arc::clone(&negative_provider_releases),
            substitute_metadata_on_reopen: true,
        };
        let negative_package =
            ProvisionedRestorePackageV1::try_from_attested(package_root.to_path_buf())
                .map_err(|_| "negative-package-attest")?;
        let negative_accepted = accept_preparation_restore_package_v1(
            negative_package,
            &negative_quarantine_authority,
            trust,
            historical_plan_keys,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(restore_error_phase_v1)?;
        let negative_root =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
                negative_coordinator.clone(),
                Sha256Digest::digest(b"t072-negative-coordinator-destination"),
                Identifier::new("at-rest.synthetic-v1".to_owned(), 128)
                    .map_err(|_| "negative-coordinator-profile")?,
            )
            .map_err(|_| "negative-coordinator-attest")?;
        match restore_preparation_to_pending_v1(
            negative_accepted,
            &negative_root,
            &negative_pause_authority,
            &negative_provider,
            &negative_quarantine_authority,
            historical_plan_keys,
            2,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        ) {
            Err(PreparationRestoreErrorV1::AgreementFailed) => {}
            Err(_) => return Err("negative-restore-wrong-refusal"),
            Ok(_) => return Err("negative-restore-returned-evidence"),
        }
        quarantine_existing_restore_attempt_v1(
            &negative_root,
            &negative_pause_authority,
            &negative_provider,
            &negative_quarantine_authority,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(restore_error_phase_v1)?;
        let recovery_metadata_path = negative_provider.root.join("recovery-root-metadata.json");
        let original_recovery_metadata =
            fs::read(&recovery_metadata_path).map_err(|_| "negative-metadata-read")?;
        let mut changed_generation: serde_json::Value =
            serde_json::from_slice(&original_recovery_metadata)
                .map_err(|_| "negative-metadata-decode")?;
        changed_generation["state_generation"] = serde_json::Value::from(2_u64);
        let changed_generation = serde_json_canonicalizer::to_vec(&changed_generation)
            .map_err(|_| "negative-metadata-encode")?;
        fs::write(&recovery_metadata_path, changed_generation)
            .map_err(|_| "negative-metadata-generation-change")?;
        match quarantine_existing_restore_attempt_v1(
            &negative_root,
            &negative_pause_authority,
            &negative_provider,
            &negative_quarantine_authority,
            2,
            clock,
            DEADLINE_MONOTONIC_MS,
        ) {
            Err(PreparationRestoreErrorV1::RecoveryDestinationUnavailable) => {}
            Err(_) => return Err("negative-generation-change-wrong-refusal"),
            Ok(()) => return Err("negative-generation-change-accepted"),
        }
        fs::write(&recovery_metadata_path, original_recovery_metadata)
            .map_err(|_| "negative-metadata-restore")?;
        if negative_pause_releases.load(Ordering::SeqCst) != 3
            || negative_provider_releases.load(Ordering::SeqCst) != 3
            || negative_quarantine_calls.load(Ordering::SeqCst) != 2
            || !negative_quarantine.is_file()
        {
            return Err("negative-restore-quarantine-evidence");
        }
        assert_pending_coordinator_file_v1(&negative_coordinator)?;

        let maintenance_guard_acquisitions = Arc::new(AtomicU64::new(0));
        let maintenance_guard_authority = SyntheticRestoredNoDispatchAuthorityV1 {
            acquisitions: Arc::clone(&maintenance_guard_acquisitions),
        };
        let maintenance = reconcile_restored_old_authority_v1(
            &positive_root,
            &positive_pause_authority,
            &resumed_provider,
            &maintenance_guard_authority,
            historical_plan_keys,
            RestoreMaintenanceLimitsV1::try_new(16, 2, 2)
                .map_err(|_| "restore-maintenance-limits")?,
            clock,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(|_| "restore-maintenance")?;
        if maintenance.inspected_count() != 0
            || maintenance.failed_count() != 0
            || maintenance.already_failed_count() != 0
            || maintenance.quarantine_retained_count() != 0
            || maintenance.remaining_unresolved_count() != 0
            || maintenance.activation_authority_present()
            || maintenance.verification().root_lifecycle_code() != "RESTORE_PENDING"
            || maintenance_guard_acquisitions.load(Ordering::SeqCst) != 0
        {
            return Err("restore-maintenance-evidence");
        }
        assert_pending_coordinator_file_v1(&positive_coordinator)?;
        Ok(())
    }

    fn restore_error_phase_v1(error: PreparationRestoreErrorV1) -> &'static str {
        match error {
            PreparationRestoreErrorV1::PlatformUnsupported => "restore-platform-unsupported",
            PreparationRestoreErrorV1::PackageUnavailable => "restore-package-unavailable",
            PreparationRestoreErrorV1::PackageInvalid => "restore-package-invalid",
            PreparationRestoreErrorV1::ProvenanceInvalid => "restore-provenance-invalid",
            PreparationRestoreErrorV1::DeadlineReached => "restore-deadline",
            PreparationRestoreErrorV1::PauseContended
            | PreparationRestoreErrorV1::PauseUnavailable
            | PreparationRestoreErrorV1::PauseDeadlineReached
            | PreparationRestoreErrorV1::PauseUnsupported
            | PreparationRestoreErrorV1::PauseUnhealthy => "restore-pause",
            PreparationRestoreErrorV1::CoordinatorDestinationUnavailable => {
                "restore-coordinator-destination"
            }
            PreparationRestoreErrorV1::RecoveryDestinationUnavailable => {
                "restore-recovery-destination"
            }
            PreparationRestoreErrorV1::RecoveryImportInvalid => "restore-recovery-invalid",
            PreparationRestoreErrorV1::SourceChanged => "restore-source-changed",
            PreparationRestoreErrorV1::AgreementFailed => "restore-agreement",
            PreparationRestoreErrorV1::QuarantineUnavailable => "restore-quarantine",
        }
    }

    fn assert_pending_coordinator_file_v1(root: &Path) -> Result<(), &'static str> {
        let connection = Connection::open_with_flags(
            root.join(COORDINATOR_DATABASE_FILENAME),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| "pending-coordinator-open")?;
        let (lifecycle, restore_identity, attestation, state_generation): (
            String,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            i64,
        ) = connection
            .query_row(
                "SELECT root_lifecycle_state, restore_identity_digest, \
                        restore_attestation_digest, restore_state_generation \
                 FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| "pending-coordinator-read")?;
        if lifecycle != "RESTORE_PENDING"
            || restore_identity
                .as_deref()
                .is_none_or(|value| value.len() != 32)
            || attestation.as_deref().is_none_or(|value| value.len() != 32)
            || state_generation <= 0
        {
            return Err("pending-coordinator-invalid");
        }
        Ok(())
    }

    struct ConformancePathsV1 {
        coordinator_root: PathBuf,
        package_root: PathBuf,
    }

    impl Drop for ConformancePathsV1 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.package_root);
            let _ = fs::remove_dir_all(&self.coordinator_root);
        }
    }

    fn identifier_v1(value: &str) -> Result<Identifier, &'static str> {
        Identifier::new(value.to_owned(), 128).map_err(|_| "identifier")
    }

    fn assert_root_busy_v1(
        config: &CoordinatorStoreConfigV1,
        clock: &FixedClockV1,
    ) -> Result<(), &'static str> {
        match open_bound_backup_pair_v1(config, clock, DEADLINE_MONOTONIC_MS) {
            Ok(_) => Err("root-lease-not-exclusive"),
            Err(InternalCoordinatorError::RootBusy) => Ok(()),
            Err(_) => Err("root-lease-wrong-refusal"),
        }
    }

    fn cut_error_phase_v1(error: QuiescentBackupErrorV1) -> &'static str {
        match error {
            QuiescentBackupErrorV1::PauseContended
            | QuiescentBackupErrorV1::PauseUnavailable
            | QuiescentBackupErrorV1::PauseDeadlineReached
            | QuiescentBackupErrorV1::PauseUnsupported
            | QuiescentBackupErrorV1::PauseUnhealthy => "cut-pause",
            QuiescentBackupErrorV1::ProviderContended
            | QuiescentBackupErrorV1::ProviderUnavailable
            | QuiescentBackupErrorV1::ProviderDeadlineReached
            | QuiescentBackupErrorV1::ProviderUnsupported
            | QuiescentBackupErrorV1::ProviderUnhealthy => "cut-provider",
            QuiescentBackupErrorV1::CoordinatorUnavailable => "cut-coordinator-unavailable",
            QuiescentBackupErrorV1::CoordinatorUnhealthy => "cut-coordinator-unhealthy",
            QuiescentBackupErrorV1::ProviderExtrasQuarantinedRetryRequired => {
                "cut-provider-extras-quarantined"
            }
            QuiescentBackupErrorV1::RetirementPending => "cut-retirement-pending",
            QuiescentBackupErrorV1::SourceChanged => "cut-source-changed",
            QuiescentBackupErrorV1::DestinationExists
            | QuiescentBackupErrorV1::DestinationUnavailable
            | QuiescentBackupErrorV1::BackupFailed
            | QuiescentBackupErrorV1::ProviderExportUnavailable
            | QuiescentBackupErrorV1::ProviderExportInvalid
            | QuiescentBackupErrorV1::ManifestInvalid
            | QuiescentBackupErrorV1::SigningUnavailable
            | QuiescentBackupErrorV1::ProvenanceInvalid
            | QuiescentBackupErrorV1::PublicationFailed => "cut-unexpected-phase",
            QuiescentBackupErrorV1::IntegrityFailed => "backup-integrity",
        }
    }

    pub(super) fn run_v1() -> Result<(), &'static str> {
        run_internal_v1(false, MaintenanceFaultProbeV1::disabled_v1(), None)
    }

    pub(super) fn run_restore_v1() -> Result<(), &'static str> {
        run_internal_v1(true, MaintenanceFaultProbeV1::disabled_v1(), None)
    }

    pub(super) fn run_fault_probe_v1(
        fault_probe: MaintenanceFaultProbeV1,
        probe_root: PathBuf,
        run_restore: bool,
    ) -> Result<(), &'static str> {
        let observation = fault_probe.clone();
        run_internal_v1(run_restore, fault_probe, Some(probe_root))?;
        if observation.injected_v1() {
            Ok(())
        } else {
            Err("fault-boundary-not-reached")
        }
    }

    fn run_internal_v1(
        run_restore: bool,
        fault_probe: MaintenanceFaultProbeV1,
        probe_root: Option<PathBuf>,
    ) -> Result<(), &'static str> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let coordinator_root = probe_root.as_ref().map_or_else(
            || {
                std::env::temp_dir().join(format!(
                    "helixos-t071-production-root-{}-{sequence}",
                    std::process::id()
                ))
            },
            |root| root.join("coordinator-root-v1"),
        );
        let package_root = probe_root.as_ref().map_or_else(
            || {
                std::env::temp_dir().join(format!(
                    "helixos-t071-production-package-{}-{sequence}",
                    std::process::id()
                ))
            },
            |root| root.join("backup-package-v1"),
        );
        fs::create_dir(&coordinator_root).map_err(|_| "root-create")?;
        let _cleanup = ConformancePathsV1 {
            coordinator_root: coordinator_root.clone(),
            package_root: package_root.clone(),
        };
        let initial = CoordinatorStoreConfigV1::try_new_empty_attested(coordinator_root, 2)
            .map_err(|_| "root-attest-empty")?;
        let clock = FixedClockV1;
        let historical_plan_keys = NoHistoricalPlanKeysV1;
        let (existing, summary, _) = initialize_or_verify_store(
            initial,
            &clock,
            &historical_plan_keys,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(|_| "root-initialize")?;
        if let Some(root) = probe_root.as_ref() {
            write_create_new_v1(
                &root.join("coordinator-root-identity-v1"),
                summary.root_identity.as_bytes(),
            )
            .map_err(|_| "root-identity-publish")?;
        }
        let mut pair = open_bound_backup_pair_v1(&existing, &clock, DEADLINE_MONOTONIC_MS)
            .map_err(|_| "pair-open")?;
        assert_root_busy_v1(&existing, &clock)?;
        {
            let (_, source, guard) = pair.parts_v1();
            verify_backup_sqlite_profile_v1(source).map_err(|_| "source-profile-preflight")?;
            verify_backup_sqlite_profile_v1(guard).map_err(|_| "guard-profile-preflight")?;
            schema::verify_full(source, summary.root_identity, &historical_plan_keys)
                .map_err(|_| "source-schema-preflight")?;
            schema::verify_full(guard, summary.root_identity, &historical_plan_keys)
                .map_err(|_| "guard-schema-preflight")?;
            capture_coordinator_backup_state_v1(source).map_err(|_| "source-state-preflight")?;
            capture_coordinator_backup_state_v1(guard).map_err(|_| "guard-state-preflight")?;
        }

        let pause_releases = Arc::new(AtomicU64::new(0));
        let provider_releases = Arc::new(AtomicU64::new(0));
        let provider_enumerations = Arc::new(AtomicU64::new(0));
        let provider_enumeration_failures = Arc::new(AtomicU64::new(1));
        let pause_authority = PauseAuthorityV1 {
            releases: Arc::clone(&pause_releases),
        };
        let controlled_probe = probe_root.is_some();
        let published_count = if controlled_probe { 3_u8 } else { 1_u8 };
        let retired_count = if controlled_probe && !run_restore {
            2_u8
        } else {
            1_u8
        };
        let expected_entry_count = u64::from(published_count) + u64::from(retired_count);
        let expected_quarantine_count = i64::from(published_count) + i64::from(retired_count);
        let mut entries = Vec::new();
        let mut published_packages = Vec::new();
        let mut retirement_manifests = Vec::new();
        for index in 0..published_count {
            let manifest = format!(
                "{{\"index\":{index},\"schema\":\"helixos.synthetic-provider-manifest/1\"}}"
            )
            .into_bytes();
            let material = format!("helixos-t071-public-synthetic-material-{index}").into_bytes();
            entries.push(
                ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                    provider_profile_id: identifier_v1("profile.synthetic-v1")?,
                    provider_profile_version: RECOVERY_PROVIDER_PROFILE_VERSION_V1,
                    provider_id: identifier_v1("provider.synthetic-v1")?,
                    provider_generation: 1,
                    evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
                    at_rest_profile_id: identifier_v1("at-rest.synthetic-v1")?,
                    manifest_digest: Sha256Digest::digest(&manifest),
                    material_digest: Sha256Digest::digest(&material),
                    material_length: material.len() as u64,
                    reserved_capacity: material.len() as u64,
                    custody: ProviderRecoveryCustodyV1::QuarantinedOrphan,
                    state: ProviderRecoveryStateV1::Published,
                    retirement_manifest_digest: None,
                })
                .map_err(|_| "provider-entry")?,
            );
            published_packages.push((manifest, material));
        }
        for index in 0..retired_count {
            let retirement_manifest = format!(
                "{{\"index\":{index},\"schema\":\"helixos.synthetic-retirement-manifest/1\"}}"
            )
            .into_bytes();
            entries.push(
                ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                    provider_profile_id: identifier_v1("profile.synthetic-v1")?,
                    provider_profile_version: RECOVERY_PROVIDER_PROFILE_VERSION_V1,
                    provider_id: identifier_v1("provider.synthetic-v1")?,
                    provider_generation: 1,
                    evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
                    at_rest_profile_id: identifier_v1("at-rest.synthetic-v1")?,
                    manifest_digest: Sha256Digest::digest(
                        format!("retained-original-manifest-{index}").as_bytes(),
                    ),
                    material_digest: Sha256Digest::digest(
                        format!("retired-original-material-{index}").as_bytes(),
                    ),
                    material_length: 25,
                    reserved_capacity: 64,
                    custody: ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
                    state: ProviderRecoveryStateV1::RetiredTombstone,
                    retirement_manifest_digest: Some(Sha256Digest::digest(&retirement_manifest)),
                })
                .map_err(|_| "retired-provider-entry")?,
            );
            retirement_manifests.push(retirement_manifest);
        }
        let provider = ProviderV1 {
            releases: Arc::clone(&provider_releases),
            enumerations: Arc::clone(&provider_enumerations),
            enumeration_failures_remaining: Arc::clone(&provider_enumeration_failures),
            entries,
            published_packages,
            retirement_manifests,
        };
        let corrupt_root = std::env::temp_dir().join(format!(
            "helixos-t071-corrupt-root-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&corrupt_root).map_err(|_| "corrupt-root-create")?;
        let _corrupt_cleanup = ConformancePathsV1 {
            coordinator_root: corrupt_root.clone(),
            package_root: corrupt_root.join("never-created-package"),
        };
        let corrupt_initial = CoordinatorStoreConfigV1::try_new_empty_attested(corrupt_root, 2)
            .map_err(|_| "corrupt-root-attest-empty")?;
        let (corrupt_existing, corrupt_summary, _) = initialize_or_verify_store(
            corrupt_initial,
            &clock,
            &historical_plan_keys,
            DEADLINE_MONOTONIC_MS,
        )
        .map_err(|_| "corrupt-root-initialize")?;
        let mut corrupt_pair =
            open_bound_backup_pair_v1(&corrupt_existing, &clock, DEADLINE_MONOTONIC_MS)
                .map_err(|_| "corrupt-pair-open")?;
        {
            let (_, _, guard) = corrupt_pair.parts_v1();
            guard
                .execute("DROP INDEX budget_scopes_binding_uq", [])
                .map_err(|_| "corrupt-schema-stage")?;
        }
        for _ in 0..2 {
            match begin_quiescent_backup_cut_with_probe_v1(
                &mut corrupt_pair,
                &pause_authority,
                &provider,
                corrupt_summary.root_identity,
                &historical_plan_keys,
                &clock,
                DEADLINE_MONOTONIC_MS,
                fault_probe.clone(),
            ) {
                Err(QuiescentBackupErrorV1::CoordinatorUnhealthy) => {}
                Err(error) => return Err(cut_error_phase_v1(error)),
                Ok(_) => return Err("corrupt-schema-entered-cut"),
            }
        }
        if pause_releases.load(Ordering::SeqCst) != 2
            || provider_releases.load(Ordering::SeqCst) != 2
            || provider_enumerations.load(Ordering::SeqCst) != 0
        {
            return Err("corrupt-schema-custody-count");
        }
        {
            let (_, source, _) = corrupt_pair.parts_v1();
            let quarantines: i64 = source
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get(0)
                })
                .map_err(|_| "corrupt-schema-quarantine-read")?;
            if quarantines != 0 {
                return Err("corrupt-schema-mutated");
            }
        }
        drop(corrupt_pair);
        drop(corrupt_existing);

        match begin_quiescent_backup_cut_with_probe_v1(
            &mut pair,
            &pause_authority,
            &provider,
            summary.root_identity,
            &historical_plan_keys,
            &clock,
            DEADLINE_MONOTONIC_MS,
            fault_probe.clone(),
        ) {
            Err(QuiescentBackupErrorV1::ProviderUnhealthy) => {}
            Err(error) => return Err(cut_error_phase_v1(error)),
            Ok(_) => return Err("unhealthy-provider-entered-cut"),
        }
        if pause_releases.load(Ordering::SeqCst) != 3
            || provider_releases.load(Ordering::SeqCst) != 3
            || provider_enumerations.load(Ordering::SeqCst) != 1
        {
            return Err("initial-refusal-release-count");
        }
        {
            let (_, source, _) = pair.parts_v1();
            let quarantines: i64 = source
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get(0)
                })
                .map_err(|_| "initial-refusal-quarantine-read")?;
            if quarantines != 0 {
                return Err("initial-refusal-mutated");
            }
        }
        match begin_quiescent_backup_cut_with_probe_v1(
            &mut pair,
            &pause_authority,
            &provider,
            summary.root_identity,
            &historical_plan_keys,
            &clock,
            DEADLINE_MONOTONIC_MS,
            fault_probe.clone(),
        ) {
            Err(QuiescentBackupErrorV1::ProviderExtrasQuarantinedRetryRequired) => {}
            Err(error) => return Err(cut_error_phase_v1(error)),
            Ok(_) => return Err("unrecorded-provider-extra-entered-cut"),
        }
        if pause_releases.load(Ordering::SeqCst) != 4
            || provider_releases.load(Ordering::SeqCst) != 4
        {
            return Err("extra-quarantine-release-count");
        }
        {
            let (_, source, _) = pair.parts_v1();
            let (quarantines, store_generation): (i64, i64) = source
                .query_row(
                    "SELECT \
                         (SELECT COUNT(*) FROM preparation_quarantines \
                          WHERE quarantine_status = 'ACTIVE' \
                            AND quarantine_reason = 'ORPHAN_MATERIAL'), \
                         store_generation \
                     FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| "extra-quarantine-reopen")?;
            if quarantines != expected_quarantine_count
                || store_generation != expected_quarantine_count
            {
                return Err("extra-quarantine-count-or-generation");
            }
        }
        let cut = begin_quiescent_backup_cut_with_probe_v1(
            &mut pair,
            &pause_authority,
            &provider,
            summary.root_identity,
            &historical_plan_keys,
            &clock,
            DEADLINE_MONOTONIC_MS,
            fault_probe.clone(),
        )
        .map_err(cut_error_phase_v1)?;

        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let pinned_sha256: [u8; 32] = Sha256::digest(verifying_key).into();
        let pinned_key =
            PinnedEd25519KeyV1::try_new(verifying_key, pinned_sha256).map_err(|_| "trust-pin")?;
        let profile_id = identifier_v1("provisioner.synthetic-v1")?;
        let key_id = identifier_v1("key.synthetic-v1")?;
        let trust = PinnedTrustV1 {
            profile_id: profile_id.clone(),
            key_id: key_id.clone(),
            key: pinned_key,
            serialization: Arc::new(PinnedTrustSerializationV1 {
                state: Mutex::new(PinnedTrustStateV1 {
                    revoked: false,
                    active_custodies: 0,
                }),
                custody_released: Condvar::new(),
            }),
        };
        let mut signer = ProvisionerSignerV1 {
            signing_key,
            profile_id,
            key_id,
        };
        let mut codec = ProductionBackupManifestCodecV1::new(&trust);
        let destination =
            ProvisionedBackupDestinationV1::try_reserve_create_only(package_root.clone())
                .map_err(|_| "destination-reserve")?;
        let verified = complete_quiescent_backup_v1(
            cut,
            &provider,
            destination,
            identifier_v1("at-rest.synthetic-v1")?,
            &mut signer,
            &mut codec,
        )
        .map_err(cut_error_phase_v1)?;
        if verified.provider_set_count() != 1 {
            return Err("backup-provider-set-count");
        }
        if verified.entry_count() != expected_entry_count {
            return Err("backup-entry-count");
        }
        if pause_releases.load(Ordering::SeqCst) != 5 {
            return Err("backup-pause-release-count");
        }
        if provider_releases.load(Ordering::SeqCst) != 5 {
            return Err("backup-provider-release-count");
        }
        if provider_enumerations.load(Ordering::SeqCst) != 4 {
            return Err("backup-provider-enumeration-count");
        }
        let destination = verified.into_destination();
        let inventory = destination
            .reopen_published_member_v1(BackupJsonMemberV1::RecoveryInventory)
            .map_err(|_| "inventory-reopen")?;
        let top_level = destination
            .reopen_published_member_v1(BackupJsonMemberV1::TopLevelManifest)
            .map_err(|_| "top-level-reopen")?;
        let attestation = destination
            .reopen_published_member_v1(BackupJsonMemberV1::Attestation)
            .map_err(|_| "attestation-reopen")?;
        decode_recovery_snapshot_manifest_v1(&inventory).map_err(|_| "inventory-decode")?;
        decode_preparation_backup_manifest_v1(&top_level).map_err(|_| "top-level-decode")?;
        decode_backup_provenance_attestation_v1(&attestation).map_err(|_| "attestation-decode")?;
        drop(destination);
        drop(signer);

        if run_restore {
            run_restore_packages_v1(
                &package_root,
                &trust,
                &historical_plan_keys,
                &clock,
                sequence,
                expected_entry_count,
                fault_probe.clone(),
            )?;
        }

        {
            let (_, source, _) = pair.parts_v1();
            let (quarantines, store_generation): (i64, i64) = source
                .query_row(
                    "SELECT \
                         (SELECT COUNT(*) FROM preparation_quarantines \
                          WHERE quarantine_status = 'ACTIVE' \
                            AND quarantine_reason = 'ORPHAN_MATERIAL'), \
                         store_generation \
                     FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| "extra-quarantine-final-reopen")?;
            if quarantines != expected_quarantine_count
                || store_generation != expected_quarantine_count
            {
                return Err("extra-quarantine-repeat-mutated");
            }
        }

        assert_root_busy_v1(&existing, &clock)?;
        drop(pair);
        let mut reopened = open_bound_backup_pair_v1(&existing, &clock, DEADLINE_MONOTONIC_MS)
            .map_err(|_| "pair-reopen-after-drop")?;
        reopened
            .revalidate(&clock, DEADLINE_MONOTONIC_MS)
            .map_err(|_| "pair-reopen-revalidate")?;
        drop(reopened);
        drop(existing);
        Ok(())
    }
}

#[cfg(test)]
use crate::quarantine::{
    authorize_orphan_retirement_v1, OrphanRetirementAuthorizationInputV1,
    OrphanRetirementAuthorizationOutcomeV1,
};

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) struct SyntheticOrphanAuthorizationInputV1 {
    pub(crate) quarantine_id: Sha256Digest,
    pub(crate) retirement_id: Sha256Digest,
    pub(crate) no_reference_digest: Sha256Digest,
}

#[cfg(test)]
impl std::fmt::Debug for SyntheticOrphanAuthorizationInputV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyntheticOrphanAuthorizationInputV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticNoReferenceCaseV1 {
    TemporaryAbsence,
    Definitive,
    CommittedOperation,
    InFlightPermit,
    AmbiguousReference,
    StoreUnavailable,
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticOrphanAuthorizationOutcomeV1 {
    RetainedActive,
    AuthorizedPending,
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) fn authorize_synthetic_orphan_retirement_v1<G: RecoveryCleanupGuardV1>(
    connection: &mut Connection,
    input: &SyntheticOrphanAuthorizationInputV1,
    case: SyntheticNoReferenceCaseV1,
    cleanup_guard: &mut G,
) -> SyntheticOrphanAuthorizationOutcomeV1 {
    let _retained_cleanup_custody = cleanup_guard;
    if case != SyntheticNoReferenceCaseV1::Definitive {
        return SyntheticOrphanAuthorizationOutcomeV1::RetainedActive;
    }
    match authorize_orphan_retirement_v1(
        connection,
        &OrphanRetirementAuthorizationInputV1 {
            quarantine_id: input.quarantine_id,
            retirement_id: input.retirement_id,
            no_reference_digest: input.no_reference_digest,
        },
    ) {
        Ok(
            OrphanRetirementAuthorizationOutcomeV1::AuthorizedPending
            | OrphanRetirementAuthorizationOutcomeV1::AlreadyAuthorized,
        ) => SyntheticOrphanAuthorizationOutcomeV1::AuthorizedPending,
        Ok(OrphanRetirementAuthorizationOutcomeV1::ReferencePresent) | Err(_) => {
            SyntheticOrphanAuthorizationOutcomeV1::RetainedActive
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
    use rusqlite::params;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn restore_maintenance_limits_and_errors_remain_bounded_payload_free_v1() {
        let exact = RestoreMaintenanceLimitsV1::try_new(4_096, 60_000, 60_000)
            .expect("documented exact caps are accepted");
        assert_eq!(exact.maximum_operations(), 4_096);
        assert_eq!(format!("{exact:?}"), "RestoreMaintenanceLimitsV1 { .. }");

        for invalid in [
            RestoreMaintenanceLimitsV1::try_new(0, 1, 1),
            RestoreMaintenanceLimitsV1::try_new(4_097, 1, 1),
            RestoreMaintenanceLimitsV1::try_new(1, 0, 1),
            RestoreMaintenanceLimitsV1::try_new(1, 1, 60_001),
        ] {
            let error = invalid.expect_err("cap+1/zero must refuse");
            assert_eq!(error.code(), "RESTORE_MAINTENANCE_LIMIT_OUT_OF_RANGE");
            assert_eq!(format!("{error:?}"), error.code());
        }

        assert_eq!(
            PreparationRestoreErrorV1::PlatformUnsupported.code(),
            "RESTORE_PLATFORM_UNSUPPORTED"
        );
        assert_eq!(
            RestoreMaintenanceErrorV1::WorkLimitExceeded.code(),
            "RESTORE_MAINTENANCE_WORK_LIMIT_EXCEEDED"
        );
        assert_eq!(
            format!("{:?}", RestoreMaintenanceErrorV1::CoordinatorUnhealthy),
            "RESTORE_MAINTENANCE_COORDINATOR_UNHEALTHY"
        );
    }

    struct TestProviderCustodyV1 {
        live: bool,
        operation_pending: u64,
        release_count: Option<Arc<AtomicU64>>,
    }

    impl RecoveryCleanupGuardV1 for TestProviderCustodyV1 {
        fn release(self) {
            if let Some(release_count) = self.release_count {
                release_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    impl ProviderMaintenanceGuardV1 for TestProviderCustodyV1 {
        fn capture_recovery_source_v1(
            &mut self,
        ) -> Result<RecoveryMaintenanceSourceV1, MaintenanceCustodyValidationV1> {
            if !self.live {
                return Err(MaintenanceCustodyValidationV1::Unhealthy);
            }
            RecoveryMaintenanceSourceV1::try_new_with_pending_counts(
                digest(0x71),
                digest(0x72),
                7,
                3,
                self.operation_pending,
                0,
            )
            .map_err(|_| MaintenanceCustodyValidationV1::Unhealthy)
        }

        fn recheck_recovery_source_v1(
            &mut self,
            expected: &RecoveryMaintenanceSourceV1,
        ) -> MaintenanceCustodyValidationV1 {
            match self.capture_recovery_source_v1() {
                Ok(actual) if &actual == expected => MaintenanceCustodyValidationV1::Exact,
                Ok(_) => MaintenanceCustodyValidationV1::Revoked,
                Err(error) => error,
            }
        }
    }

    struct TestPauseCustodyV1 {
        live: bool,
        release_count: Option<Arc<AtomicU64>>,
    }

    impl PausedBackupCustodyV1 for TestPauseCustodyV1 {
        fn capture_paused_source_v1(
            &mut self,
        ) -> Result<PausedBackupSourceV1, MaintenanceCustodyValidationV1> {
            if !self.live {
                return Err(MaintenanceCustodyValidationV1::Revoked);
            }
            PausedBackupSourceV1::try_new(11, digest(0x73), 12, 13)
                .map_err(|_| MaintenanceCustodyValidationV1::Unhealthy)
        }

        fn recheck_paused_source_v1(
            &mut self,
            expected: &PausedBackupSourceV1,
        ) -> MaintenanceCustodyValidationV1 {
            match self.capture_paused_source_v1() {
                Ok(actual) if &actual == expected => MaintenanceCustodyValidationV1::Exact,
                Ok(_) => MaintenanceCustodyValidationV1::Revoked,
                Err(error) => error,
            }
        }

        fn release(self) {
            if let Some(release_count) = self.release_count {
                release_count.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct TestProviderV1 {
        entries: Vec<ProviderRecoveryInventoryEntryV1>,
        error: Option<ProviderRecoveryEnumerationErrorV1>,
        calls: AtomicU64,
    }

    impl TestProviderV1 {
        fn exact(entries: Vec<ProviderRecoveryInventoryEntryV1>) -> Self {
            Self {
                entries,
                error: None,
                calls: AtomicU64::new(0),
            }
        }

        fn failing(error: ProviderRecoveryEnumerationErrorV1) -> Self {
            Self {
                entries: Vec::new(),
                error: Some(error),
                calls: AtomicU64::new(0),
            }
        }
    }

    impl GuardedRecoveryInventoryProviderV1 for TestProviderV1 {
        type Custody = TestProviderCustodyV1;

        fn enumerate_recovery_inventory_v1(
            &self,
            custody: &mut Self::Custody,
        ) -> Result<Vec<ProviderRecoveryInventoryEntryV1>, ProviderRecoveryEnumerationErrorV1>
        {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if !custody.live {
                return Err(ProviderRecoveryEnumerationErrorV1::Unhealthy);
            }
            self.error.map_or_else(|| Ok(self.entries.clone()), Err)
        }
    }

    struct TestBackupExporterV1 {
        manifest: Vec<u8>,
        material: Vec<u8>,
        retirement_manifest: Vec<u8>,
        corrupt_material: bool,
    }

    impl GuardedRecoveryBackupExporterV1 for TestBackupExporterV1 {
        type Custody = TestProviderCustodyV1;

        fn export_recovery_backup_package_v1(
            &self,
            custody: &mut Self::Custody,
            entry: &ProviderRecoveryInventoryEntryV1,
            destination: &mut ProviderBackupExportDestinationV1,
        ) -> Result<(), ProviderBackupExportErrorV1> {
            if !custody.live {
                return Err(ProviderBackupExportErrorV1::Unavailable);
            }
            match entry.state() {
                ProviderRecoveryStateV1::Published => {
                    destination.write_manifest_v1(&self.manifest)?;
                    if self.corrupt_material {
                        destination.write_material_v1(b"substituted-material")?;
                    } else {
                        destination.write_material_v1(&self.material)?;
                    }
                }
                ProviderRecoveryStateV1::RetiredTombstone => {
                    destination.write_retirement_manifest_v1(&self.retirement_manifest)?;
                }
            }
            Ok(())
        }
    }

    struct TestProvisionerSignerV1 {
        signing_key: SigningKey,
        profile_id: Identifier,
        key_id: Identifier,
    }

    impl ProvisionerBackupSigningCustodyV1 for TestProvisionerSignerV1 {
        fn attestation_profile_id_v1(&self) -> &Identifier {
            &self.profile_id
        }

        fn attestation_profile_version_v1(&self) -> u16 {
            1
        }

        fn key_id_v1(&self) -> &Identifier {
            &self.key_id
        }

        fn sign_backup_attestation_v1(
            &mut self,
            domain_separated_message: &[u8],
        ) -> Result<[u8; 64], ProvisionerBackupSigningErrorV1> {
            if !domain_separated_message.starts_with(BACKUP_ATTESTATION_DOMAIN_V1) {
                return Err(ProvisionerBackupSigningErrorV1::Refused);
            }
            Ok(self.signing_key.sign(domain_separated_message).to_bytes())
        }
    }

    struct TestBackupCodecV1 {
        verifying_key: VerifyingKey,
        substitute_attestation: bool,
    }

    impl TestBackupCodecV1 {
        fn canonical_member(
            value: &Value,
        ) -> Result<CanonicalBackupMemberV1, QuiescentBackupErrorV1> {
            let bytes = serde_json_canonicalizer::to_vec(value)
                .map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?;
            CanonicalBackupMemberV1::try_new(bytes)
        }

        fn protected_value(input: &BackupProtectedCodecInputV1, substitute: bool) -> Value {
            let top_level = if substitute {
                Sha256Digest::from_bytes([0xFE; 32])
            } else {
                input.top_level_manifest_sha256
            };
            json!({
                "schema": "test.protected/1",
                "top_level_manifest_sha256": top_level.to_hex(),
                "recovery_inventory_sha256": input.recovery_inventory_sha256.to_hex(),
                "recovery_entry_count": input.recovery_entry_count,
                "at_rest_profile_id": input.at_rest_profile_id.as_str(),
                "attestation_profile_id": input.attestation_profile_id.as_str(),
                "attestation_profile_version": input.attestation_profile_version,
                "key_id": input.key_id.as_str()
            })
        }
    }

    impl QuiescentBackupManifestCodecV1 for TestBackupCodecV1 {
        fn finalize_inventory_v1(
            &mut self,
            entries: &[ProviderRecoveryInventoryEntryV1],
            pending: BackupPendingRetirementCountsV1,
        ) -> Result<FinalizedRecoveryInventoryV1, QuiescentBackupErrorV1> {
            if !pending.all_zero() {
                return Err(QuiescentBackupErrorV1::RetirementPending);
            }
            let mut generations = BTreeMap::new();
            for entry in entries {
                generations.insert(
                    (
                        entry.provider_profile_id().as_str().to_owned(),
                        entry.provider_id().as_str().to_owned(),
                        entry.provider_generation(),
                    ),
                    BackupProviderGenerationV1 {
                        provider_profile_id: entry.provider_profile_id().clone(),
                        provider_profile_version: entry.provider_profile_version(),
                        provider_id: entry.provider_id().clone(),
                        provider_generation: entry.provider_generation(),
                    },
                );
            }
            let entry_count = u64::try_from(entries.len())
                .map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?;
            let provider_set_count = u64::try_from(generations.len())
                .map_err(|_| QuiescentBackupErrorV1::ManifestInvalid)?;
            let value = json!({
                "schema": "test.recovery-inventory/1",
                "provider_set_count": provider_set_count,
                "entry_count": entry_count,
                "entries": entries.iter().map(|entry| json!({
                    "manifest_sha256": entry.manifest_digest().to_hex(),
                    "material_sha256": entry.material_digest().to_hex(),
                    "state": match entry.state() {
                        ProviderRecoveryStateV1::Published => "MATERIAL_PRESENT",
                        ProviderRecoveryStateV1::RetiredTombstone => "RETIRED_TOMBSTONE",
                    }
                })).collect::<Vec<_>>()
            });
            Ok(FinalizedRecoveryInventoryV1 {
                member: Self::canonical_member(&value)?,
                provider_set_count,
                entry_count,
                provider_generations: generations.into_values().collect(),
            })
        }

        fn finalize_top_level_v1(
            &mut self,
            input: BackupTopLevelCodecInputV1,
            pending: BackupPendingRetirementCountsV1,
        ) -> Result<CanonicalBackupMemberV1, QuiescentBackupErrorV1> {
            if !pending.all_zero() {
                return Err(QuiescentBackupErrorV1::RetirementPending);
            }
            Self::canonical_member(&json!({
                "schema": "test.preparation-backup/1",
                "source_coordinator_root_identity_sha256": input.source_coordinator_root_identity_sha256.to_hex(),
                "source_recovery_root_identity_sha256": input.source_recovery_root_identity_sha256.to_hex(),
                "source_instance_identity_sha256": input.source_instance_identity_sha256.to_hex(),
                "coordinator_schema_sha256": input.coordinator_schema_sha256.to_hex(),
                "coordinator_database_sha256": input.coordinator_database_sha256.to_hex(),
                "recovery_inventory_sha256": input.recovery_inventory_sha256.to_hex(),
                "recovery_provider_set_count": input.recovery_provider_set_count,
                "recovery_entry_count": input.recovery_entry_count,
                "at_rest_profile_id": input.at_rest_profile_id.as_str()
            }))
        }

        fn finalize_protected_v1(
            &mut self,
            input: &BackupProtectedCodecInputV1,
        ) -> Result<CanonicalBackupMemberV1, QuiescentBackupErrorV1> {
            Self::canonical_member(&Self::protected_value(input, false))
        }

        fn finalize_attestation_v1(
            &mut self,
            input: &BackupProtectedCodecInputV1,
            signature: [u8; 64],
        ) -> Result<CanonicalBackupMemberV1, QuiescentBackupErrorV1> {
            Self::canonical_member(&json!({
                "schema": "test.attestation/1",
                "protected": Self::protected_value(input, self.substitute_attestation),
                "signature_algorithm": "ed25519",
                "signature_base64url": URL_SAFE_NO_PAD.encode(signature)
            }))
        }

        fn verify_reopened_package_v1(
            &mut self,
            attestation: &[u8],
            top_level: &[u8],
            inventory: &[u8],
            pending: BackupPendingRetirementCountsV1,
        ) -> Result<(), QuiescentBackupErrorV1> {
            if !pending.all_zero() {
                return Err(QuiescentBackupErrorV1::RetirementPending);
            }
            let envelope: Value = serde_json::from_slice(attestation)
                .map_err(|_| QuiescentBackupErrorV1::ProvenanceInvalid)?;
            let protected = envelope
                .get("protected")
                .ok_or(QuiescentBackupErrorV1::ProvenanceInvalid)?;
            let top_digest = Sha256Digest::digest(top_level).to_hex();
            let inventory_digest = Sha256Digest::digest(inventory).to_hex();
            if protected["top_level_manifest_sha256"] != top_digest
                || protected["recovery_inventory_sha256"] != inventory_digest
            {
                return Err(QuiescentBackupErrorV1::ProvenanceInvalid);
            }
            let protected_bytes = serde_json_canonicalizer::to_vec(protected)
                .map_err(|_| QuiescentBackupErrorV1::ProvenanceInvalid)?;
            let mut message = BACKUP_ATTESTATION_DOMAIN_V1.to_vec();
            message.extend_from_slice(&protected_bytes);
            let signature = envelope["signature_base64url"]
                .as_str()
                .ok_or(QuiescentBackupErrorV1::ProvenanceInvalid)
                .and_then(|encoded| {
                    URL_SAFE_NO_PAD
                        .decode(encoded)
                        .map_err(|_| QuiescentBackupErrorV1::ProvenanceInvalid)
                })?;
            let signature: [u8; 64] = signature
                .try_into()
                .map_err(|_| QuiescentBackupErrorV1::ProvenanceInvalid)?;
            self.verifying_key
                .verify_strict(&message, &Signature::from_bytes(&signature))
                .map_err(|_| QuiescentBackupErrorV1::ProvenanceInvalid)
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value, 128).expect("public-synthetic identifier validates")
    }

    fn entry_input(
        manifest: u8,
        material: u8,
        custody: ProviderRecoveryCustodyV1,
        state: ProviderRecoveryStateV1,
        retirement_manifest: Option<u8>,
    ) -> ProviderRecoveryInventoryEntryInputV1 {
        ProviderRecoveryInventoryEntryInputV1 {
            provider_profile_id: identifier("profile.synthetic-v1"),
            provider_profile_version: 1,
            provider_id: identifier("provider.synthetic-v1"),
            provider_generation: 7,
            evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
            at_rest_profile_id: identifier("at-rest.synthetic-v1"),
            manifest_digest: digest(manifest),
            material_digest: digest(material),
            material_length: 8,
            reserved_capacity: 16,
            custody,
            state,
            retirement_manifest_digest: retirement_manifest.map(digest),
        }
    }

    fn entry(
        manifest: u8,
        material: u8,
        custody: ProviderRecoveryCustodyV1,
        state: ProviderRecoveryStateV1,
        retirement_manifest: Option<u8>,
    ) -> ProviderRecoveryInventoryEntryV1 {
        ProviderRecoveryInventoryEntryV1::try_new(entry_input(
            manifest,
            material,
            custody,
            state,
            retirement_manifest,
        ))
        .expect("valid synthetic provider entry builds")
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("maintenance database opens");
        connection
            .execute_batch(
                "CREATE TABLE preparation_recovery_evidence (
                     recovery_mode TEXT NOT NULL,
                     provider_profile_id TEXT,
                     provider_profile_version INTEGER,
                     provider_id TEXT,
                     provider_generation INTEGER,
                     evidence_class TEXT,
                     at_rest_profile_id TEXT,
                     manifest_digest BLOB,
                     material_digest BLOB,
                     material_length INTEGER,
                     reserved_capacity INTEGER,
                     material_state TEXT,
                     retirement_id BLOB,
                     retirement_manifest_digest BLOB,
                     retirement_generation INTEGER
                 );
                 CREATE TABLE preparation_quarantines (
                     quarantine_reason TEXT NOT NULL,
                     quarantine_status TEXT NOT NULL,
                     attempt_id BLOB NOT NULL,
                     operation_binding_digest BLOB NOT NULL,
                     created_generation INTEGER NOT NULL,
                     resolved_generation INTEGER,
                     recovery_manifest_digest BLOB,
                     orphan_resolution_evidence_digest BLOB,
                     orphan_retirement_id BLOB,
                     orphan_retirement_state TEXT,
                     orphan_retired_generation INTEGER,
                     orphan_retirement_manifest_digest BLOB
                 );",
            )
            .expect("maintenance fixture schema creates");
        connection
    }

    fn cut_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("cut database opens");
        connection
            .execute_batch(
                "CREATE TABLE coordinator_store_meta (
                     singleton INTEGER PRIMARY KEY,
                     store_generation INTEGER NOT NULL,
                     operation_generation INTEGER NOT NULL,
                     budget_generation INTEGER NOT NULL,
                     event_generation INTEGER NOT NULL,
                     quarantine_generation INTEGER NOT NULL
                 );
                 INSERT INTO coordinator_store_meta VALUES (1, 5, 1, 2, 3, 4);
                 CREATE TABLE budget_scopes (value INTEGER);
                 CREATE TABLE prepared_operations (value INTEGER);
                 CREATE TABLE operation_transitions (value INTEGER);
                 CREATE TABLE budget_reservations (reservation_state TEXT);
                 CREATE TABLE preparation_events (delivery_state TEXT);
                 CREATE TABLE preparation_quarantines (quarantine_status TEXT);",
            )
            .expect("cut fixture schema creates");
        connection
    }

    fn file_cut_connection(label: &str) -> (Connection, PathBuf) {
        let root = temporary_package_path(&format!("source-{label}"));
        fs::create_dir(&root).expect("file-backed source root creates");
        let connection = Connection::open(root.join("coordinator.sqlite3"))
            .expect("file-backed cut database opens");
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE coordinator_store_meta (
                     singleton INTEGER PRIMARY KEY,
                     store_generation INTEGER NOT NULL,
                     operation_generation INTEGER NOT NULL,
                     budget_generation INTEGER NOT NULL,
                     event_generation INTEGER NOT NULL,
                     quarantine_generation INTEGER NOT NULL
                 );
                 INSERT INTO coordinator_store_meta VALUES (1, 5, 1, 2, 3, 4);
                 CREATE TABLE budget_scopes (value INTEGER);
                 CREATE TABLE prepared_operations (value INTEGER);
                 CREATE TABLE operation_transitions (value INTEGER);
                 CREATE TABLE budget_reservations (reservation_state TEXT);
                 CREATE TABLE preparation_events (delivery_state TEXT);
                 CREATE TABLE preparation_quarantines (quarantine_status TEXT);",
            )
            .expect("file-backed cut fixture schema creates");
        (connection, root)
    }

    fn temporary_package_path(label: &str) -> PathBuf {
        static NEXT_PACKAGE: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT_PACKAGE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "helixos-t071-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn backup_entries(exporter: &TestBackupExporterV1) -> Vec<ProviderRecoveryInventoryEntryV1> {
        vec![
            ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                provider_profile_id: identifier("profile.synthetic-v1"),
                provider_profile_version: 1,
                provider_id: identifier("provider.synthetic-v1"),
                provider_generation: 7,
                evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
                at_rest_profile_id: identifier("at-rest.synthetic-v1"),
                manifest_digest: Sha256Digest::digest(&exporter.manifest),
                material_digest: Sha256Digest::digest(&exporter.material),
                material_length: u64::try_from(exporter.material.len()).unwrap(),
                reserved_capacity: 128,
                custody: ProviderRecoveryCustodyV1::OperationBound,
                state: ProviderRecoveryStateV1::Published,
                retirement_manifest_digest: None,
            })
            .expect("material-present backup entry builds"),
            ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                provider_profile_id: identifier("profile.synthetic-v1"),
                provider_profile_version: 1,
                provider_id: identifier("provider.synthetic-v1"),
                provider_generation: 7,
                evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
                at_rest_profile_id: identifier("at-rest.synthetic-v1"),
                manifest_digest: Sha256Digest::digest(b"retained-original-manifest"),
                material_digest: Sha256Digest::digest(b"retired-original-material"),
                material_length: 25,
                reserved_capacity: 128,
                custody: ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
                state: ProviderRecoveryStateV1::RetiredTombstone,
                retirement_manifest_digest: Some(Sha256Digest::digest(
                    &exporter.retirement_manifest,
                )),
            })
            .expect("retired-tombstone backup entry builds"),
        ]
    }

    fn run_complete_backup(
        label: &str,
        substitute_attestation: bool,
        provider_pending: bool,
        corrupt_material: bool,
        release_counts: Option<(Arc<AtomicU64>, Arc<AtomicU64>)>,
        entries_override: Option<Vec<ProviderRecoveryInventoryEntryV1>>,
    ) -> (
        Result<VerifiedPreparationBackupV1, QuiescentBackupErrorV1>,
        PathBuf,
    ) {
        let exporter = TestBackupExporterV1 {
            manifest: br#"{"schema":"test.provider-manifest/1"}"#.to_vec(),
            material: b"public-synthetic-recovery-material".to_vec(),
            retirement_manifest: br#"{"schema":"test.retirement-manifest/1"}"#.to_vec(),
            corrupt_material,
        };
        let entries = entries_override.unwrap_or_else(|| backup_entries(&exporter));
        let root = temporary_package_path(label);
        let destination = ProvisionedBackupDestinationV1::try_reserve_create_only(root.clone())
            .expect("fresh package destination reserves");
        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut signer = TestProvisionerSignerV1 {
            signing_key,
            profile_id: identifier("provisioner.synthetic-v1"),
            key_id: identifier("key.synthetic-v1"),
        };
        let mut codec = TestBackupCodecV1 {
            verifying_key,
            substitute_attestation,
        };
        let (source_connection, source_root) = file_cut_connection(label);
        source_connection
            .execute("INSERT INTO prepared_operations VALUES (9)", [])
            .expect("source preparation row inserts");
        let mut guard_connection = Connection::open(source_root.join("coordinator.sqlite3"))
            .expect("separate coordinator guard connection opens");
        let transaction = guard_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("coordinator maintenance transaction acquires");
        let coordinator_guard = CoordinatorMaintenanceGuardV1 { transaction };
        let (coordinator_generations, coordinator_counts) =
            capture_coordinator_backup_state_v1(coordinator_guard.source_connection())
                .expect("coordinator source state captures");
        let mut pause_custody = TestPauseCustodyV1 {
            live: true,
            release_count: release_counts.as_ref().map(|counts| Arc::clone(&counts.0)),
        };
        let paused_source = pause_custody
            .capture_paused_source_v1()
            .expect("paused source captures");
        let mut provider_custody = TestProviderCustodyV1 {
            live: true,
            operation_pending: u64::from(provider_pending),
            release_count: release_counts.as_ref().map(|counts| Arc::clone(&counts.1)),
        };
        let recovery_source = provider_custody
            .capture_recovery_source_v1()
            .expect("recovery source captures");
        let inventory_provider = TestProviderV1::exact(entries.clone());
        let cut = QuiescentBackupCutV1 {
            backup_source: &source_connection,
            inventory_provider: &inventory_provider,
            pause_custody: Some(pause_custody),
            provider_custody: Some(provider_custody),
            coordinator_guard: Some(coordinator_guard),
            paused_source,
            recovery_source,
            coordinator_generations,
            coordinator_counts,
            inventory: ReconciledRecoveryInventoryV1 {
                provider_entries: entries,
                operation_reference_count: 1,
                quarantine_reference_count: 1,
                operation_retirement_pending: 0,
                orphan_retirement_pending: 0,
            },
            source_coordinator_root_identity_sha256: digest(0xA3),
            coordinator_schema_sha256: digest(0xA4),
            fault_probe: MaintenanceFaultProbeV1::disabled_v1(),
        };
        let result = complete_quiescent_backup_v1(
            cut,
            &exporter,
            destination,
            identifier("at-rest.synthetic-v1"),
            &mut signer,
            &mut codec,
        );
        drop(guard_connection);
        drop(source_connection);
        fs::remove_dir_all(source_root).expect("file-backed source fixture cleans up");
        (result, root)
    }

    fn insert_operation_reference(
        connection: &Connection,
        manifest: u8,
        material: u8,
        state: &str,
        retirement_manifest: Option<u8>,
    ) {
        let has_retirement = state != "PUBLISHED";
        connection
            .execute(
                "INSERT INTO preparation_recovery_evidence (
                     recovery_mode, provider_profile_id, provider_profile_version,
                     provider_id, provider_generation, evidence_class, at_rest_profile_id,
                     manifest_digest, material_digest, material_length, reserved_capacity,
                     material_state, retirement_id, retirement_manifest_digest,
                     retirement_generation
                 ) VALUES (
                     'COMPENSATION', 'profile.synthetic-v1', 1,
                     'provider.synthetic-v1', 7, 'SYNTHETIC_CONFORMANCE',
                     'at-rest.synthetic-v1', ?1, ?2, 8, 16, ?3, ?4, ?5, ?6
                 )",
                params![
                    digest(manifest).as_bytes().as_slice(),
                    digest(material).as_bytes().as_slice(),
                    state,
                    has_retirement.then(|| digest(0xE1).as_bytes().to_vec()),
                    retirement_manifest.map(|byte| digest(byte).as_bytes().to_vec()),
                    has_retirement.then_some(10_i64),
                ],
            )
            .expect("operation recovery reference inserts");
    }

    fn insert_active_quarantine(connection: &Connection, manifest: u8, material: u8) {
        let provider_entry = entry(
            manifest,
            material,
            ProviderRecoveryCustodyV1::QuarantinedOrphan,
            ProviderRecoveryStateV1::Published,
            None,
        );
        let (attempt_id, operation_binding_digest) =
            unrecorded_provider_entry_quarantine_digests_v1(&provider_entry)
                .expect("active quarantine binding derives");
        connection
            .execute(
                "INSERT INTO preparation_quarantines VALUES (
                     'ORPHAN_MATERIAL', 'ACTIVE', ?1, ?2, 20, NULL, ?3,
                     NULL, NULL, NULL, NULL, NULL
                 )",
                params![
                    attempt_id.as_bytes().as_slice(),
                    operation_binding_digest.as_bytes().as_slice(),
                    digest(manifest).as_bytes().as_slice(),
                ],
            )
            .expect("active quarantine inserts");
    }

    fn insert_resolved_ambiguity(connection: &Connection, manifest: u8) {
        connection
            .execute(
                "INSERT INTO preparation_quarantines VALUES (
                     'AMBIGUOUS_COMMIT', 'RESOLVED_TOMBSTONE', ?1, ?2, 21, 22, ?3,
                     NULL, NULL, NULL, NULL, NULL
                 )",
                params![
                    digest(0xA1).as_bytes().as_slice(),
                    digest(0xA2).as_bytes().as_slice(),
                    digest(manifest).as_bytes().as_slice(),
                ],
            )
            .expect("resolved ambiguity tombstone inserts");
    }

    fn insert_orphan_pending(connection: &Connection, manifest: u8) {
        connection
            .execute(
                "INSERT INTO preparation_quarantines VALUES (
                     'ORPHAN_MATERIAL', 'RESOLVED_TOMBSTONE', ?1, ?2, 30, 31, ?3,
                     ?4, ?5, 'RETIREMENT_PENDING', NULL, NULL
                 )",
                params![
                    digest(0xB1).as_bytes().as_slice(),
                    digest(0xB2).as_bytes().as_slice(),
                    digest(manifest).as_bytes().as_slice(),
                    digest(0xD1).as_bytes().as_slice(),
                    digest(0xD2).as_bytes().as_slice(),
                ],
            )
            .expect("orphan pending tombstone inserts");
    }

    fn insert_orphan_retired(connection: &Connection, manifest: u8, retirement: u8) {
        connection
            .execute(
                "INSERT INTO preparation_quarantines VALUES (
                     'ORPHAN_MATERIAL', 'RESOLVED_TOMBSTONE', ?1, ?2, 40, 41, ?3,
                     ?4, ?5, 'RETIRED_TOMBSTONE', 42, ?6
                 )",
                params![
                    digest(0xC1).as_bytes().as_slice(),
                    digest(0xC2).as_bytes().as_slice(),
                    digest(manifest).as_bytes().as_slice(),
                    digest(0xD3).as_bytes().as_slice(),
                    digest(0xD4).as_bytes().as_slice(),
                    digest(retirement).as_bytes().as_slice(),
                ],
            )
            .expect("orphan retired tombstone inserts");
    }

    fn reconcile(
        connection: &mut Connection,
        provider: &TestProviderV1,
    ) -> Result<RecoveryMaintenanceOutcomeV1, RecoveryMaintenanceErrorV1> {
        reconcile_guarded_recovery_inventory_v1(
            connection,
            provider,
            &mut TestProviderCustodyV1 {
                live: true,
                operation_pending: 0,
                release_count: None,
            },
        )
    }

    #[test]
    fn entry_builder_closes_state_custody_capacity_and_safe_integer_combinations() {
        let mut invalid = entry_input(
            1,
            2,
            ProviderRecoveryCustodyV1::OperationBound,
            ProviderRecoveryStateV1::Published,
            None,
        );
        invalid.reserved_capacity = 7;
        assert_eq!(
            ProviderRecoveryInventoryEntryV1::try_new(invalid),
            Err(ProviderRecoveryInventoryEntryBuildErrorV1::InvalidEntry)
        );

        let mut invalid = entry_input(
            1,
            2,
            ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
            ProviderRecoveryStateV1::Published,
            None,
        );
        invalid.provider_generation = 0;
        assert_eq!(
            ProviderRecoveryInventoryEntryV1::try_new(invalid),
            Err(ProviderRecoveryInventoryEntryBuildErrorV1::InvalidEntry)
        );

        let invalid = entry_input(
            1,
            2,
            ProviderRecoveryCustodyV1::QuarantinedOrphan,
            ProviderRecoveryStateV1::RetiredTombstone,
            Some(3),
        );
        assert_eq!(
            ProviderRecoveryInventoryEntryV1::try_new(invalid),
            Err(ProviderRecoveryInventoryEntryBuildErrorV1::InvalidEntry)
        );
    }

    #[test]
    fn exact_published_and_tombstone_inventory_reconciles_without_mutation() {
        let mut connection = connection();
        insert_operation_reference(&connection, 1, 11, "PUBLISHED", None);
        insert_operation_reference(&connection, 2, 12, "RETIRED_TOMBSTONE", Some(22));
        insert_active_quarantine(&connection, 3, 13);
        insert_orphan_retired(&connection, 4, 24);
        insert_resolved_ambiguity(&connection, 1);
        let provider = TestProviderV1::exact(vec![
            entry(
                1,
                11,
                ProviderRecoveryCustodyV1::OperationBound,
                ProviderRecoveryStateV1::Published,
                None,
            ),
            entry(
                2,
                12,
                ProviderRecoveryCustodyV1::OperationBound,
                ProviderRecoveryStateV1::RetiredTombstone,
                Some(22),
            ),
            entry(
                3,
                13,
                ProviderRecoveryCustodyV1::QuarantinedOrphan,
                ProviderRecoveryStateV1::Published,
                None,
            ),
            entry(
                4,
                14,
                ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
                ProviderRecoveryStateV1::RetiredTombstone,
                Some(24),
            ),
        ]);
        let changes = connection.total_changes();
        let outcome = reconcile(&mut connection, &provider).expect("exact inventory reconciles");
        assert!(outcome.backup_allowed());
        let inventory = outcome.inventory();
        assert_eq!(inventory.provider_entries().len(), 4);
        assert_eq!(inventory.operation_reference_count(), 2);
        assert_eq!(inventory.quarantine_reference_count(), 2);
        assert_eq!(inventory.operation_retirement_pending(), 0);
        assert_eq!(inventory.orphan_retirement_pending(), 0);
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            connection.total_changes(),
            changes,
            "maintenance is read-only"
        );
    }

    #[test]
    fn either_pending_domain_returns_a_typed_backup_refusal_without_mutation() {
        let mut connection = connection();
        insert_operation_reference(&connection, 5, 15, "RETIREMENT_PENDING", None);
        insert_orphan_pending(&connection, 6);
        let provider = TestProviderV1::exact(vec![
            entry(
                5,
                15,
                ProviderRecoveryCustodyV1::OperationBound,
                ProviderRecoveryStateV1::Published,
                None,
            ),
            entry(
                6,
                16,
                ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
                ProviderRecoveryStateV1::RetiredTombstone,
                Some(26),
            ),
        ]);
        let changes = connection.total_changes();
        let outcome = reconcile(&mut connection, &provider).expect("pending inventory reconciles");
        assert!(!outcome.backup_allowed());
        assert!(matches!(
            outcome,
            RecoveryMaintenanceOutcomeV1::BackupBlocked(_)
        ));
        assert_eq!(outcome.inventory().operation_retirement_pending(), 1);
        assert_eq!(outcome.inventory().orphan_retirement_pending(), 1);
        assert_eq!(
            connection.total_changes(),
            changes,
            "pending scan is read-only"
        );
    }

    #[test]
    fn extras_missing_duplicates_and_binding_substitution_are_closed() {
        let exact = entry(
            7,
            17,
            ProviderRecoveryCustodyV1::OperationBound,
            ProviderRecoveryStateV1::Published,
            None,
        );

        let mut connection = connection();
        insert_operation_reference(&connection, 7, 17, "PUBLISHED", None);
        assert_eq!(
            reconcile(&mut connection, &TestProviderV1::exact(Vec::new())).unwrap_err(),
            RecoveryMaintenanceErrorV1::MissingProviderEntry
        );

        let extra = entry(
            8,
            18,
            ProviderRecoveryCustodyV1::QuarantinedOrphan,
            ProviderRecoveryStateV1::Published,
            None,
        );
        assert_eq!(
            reconcile(
                &mut connection,
                &TestProviderV1::exact(vec![exact.clone(), extra]),
            )
            .unwrap_err(),
            RecoveryMaintenanceErrorV1::ExtraProviderEntry
        );
        assert_eq!(
            reconcile(
                &mut connection,
                &TestProviderV1::exact(vec![exact.clone(), exact]),
            )
            .unwrap_err(),
            RecoveryMaintenanceErrorV1::DuplicateProviderEntry
        );

        let substituted = entry(
            7,
            99,
            ProviderRecoveryCustodyV1::OperationBound,
            ProviderRecoveryStateV1::Published,
            None,
        );
        assert_eq!(
            reconcile(&mut connection, &TestProviderV1::exact(vec![substituted]),).unwrap_err(),
            RecoveryMaintenanceErrorV1::BindingConflict
        );

        insert_active_quarantine(&connection, 7, 17);
        assert_eq!(
            reconcile(
                &mut connection,
                &TestProviderV1::exact(vec![entry(
                    7,
                    17,
                    ProviderRecoveryCustodyV1::OperationBound,
                    ProviderRecoveryStateV1::Published,
                    None,
                )]),
            )
            .unwrap_err(),
            RecoveryMaintenanceErrorV1::DuplicateCoordinatorReference
        );
    }

    #[test]
    fn quarantined_provider_extra_reloads_its_complete_binding_on_retry() {
        let mut connection = connection();
        insert_active_quarantine(&connection, 9, 19);
        let exact = entry(
            9,
            19,
            ProviderRecoveryCustodyV1::QuarantinedOrphan,
            ProviderRecoveryStateV1::Published,
            None,
        );
        assert!(
            reconcile(&mut connection, &TestProviderV1::exact(vec![exact.clone()]),)
                .expect("exact quarantined extra reconciles")
                .backup_allowed()
        );

        let mut substituted = exact;
        substituted.material_digest = digest(0xEE);
        assert_eq!(
            reconcile(&mut connection, &TestProviderV1::exact(vec![substituted]),).unwrap_err(),
            RecoveryMaintenanceErrorV1::BindingConflict
        );
    }

    #[test]
    fn provider_failures_are_redacted_and_do_not_fall_through_to_store_queries() {
        for (provider_error, expected) in [
            (
                ProviderRecoveryEnumerationErrorV1::Unavailable,
                RecoveryMaintenanceErrorV1::ProviderUnavailable,
            ),
            (
                ProviderRecoveryEnumerationErrorV1::Unhealthy,
                RecoveryMaintenanceErrorV1::ProviderUnhealthy,
            ),
        ] {
            let mut connection = connection();
            let provider = TestProviderV1::failing(provider_error);
            assert_eq!(reconcile(&mut connection, &provider).unwrap_err(), expected);
            assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn enumeration_requires_a_borrowed_live_provider_custody() {
        let mut connection = connection();
        let provider = TestProviderV1::exact(Vec::new());
        let result = reconcile_guarded_recovery_inventory_v1(
            &mut connection,
            &provider,
            &mut TestProviderCustodyV1 {
                live: false,
                operation_pending: 0,
                release_count: None,
            },
        );
        assert_eq!(
            result.unwrap_err(),
            RecoveryMaintenanceErrorV1::ProviderUnhealthy
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn diagnostics_hide_provider_bindings_digests_and_native_sentinels() {
        const PRIVATE: &str = "DO-NOT-DISCLOSE-/private/provider/root";
        let input = entry_input(
            9,
            19,
            ProviderRecoveryCustodyV1::OperationBound,
            ProviderRecoveryStateV1::Published,
            None,
        );
        let input_debug = format!("{input:?}");
        let built = ProviderRecoveryInventoryEntryV1::try_new(input)
            .expect("diagnostic fixture entry builds");
        let entry_debug = format!("{built:?}");
        let outcome_debug = format!(
            "{:?}",
            RecoveryMaintenanceOutcomeV1::Ready(ReconciledRecoveryInventoryV1 {
                provider_entries: vec![built],
                operation_reference_count: 1,
                quarantine_reference_count: 0,
                operation_retirement_pending: 0,
                orphan_retirement_pending: 0,
            })
        );
        for diagnostic in [input_debug, entry_debug, outcome_debug] {
            assert!(!diagnostic.contains(PRIVATE));
            assert!(!diagnostic.contains(&"09".repeat(32)));
            assert!(!diagnostic.contains("profile.synthetic-v1"));
            assert!(!diagnostic.contains("provider.synthetic-v1"));
        }
    }

    #[test]
    fn quiescent_source_snapshots_are_safe_integer_checked_and_redacted() {
        assert_eq!(
            PausedBackupSourceV1::try_new(0, digest(0x91), 1, 1).unwrap_err(),
            QuiescentBackupErrorV1::PauseUnhealthy
        );
        assert_eq!(
            RecoveryMaintenanceSourceV1::try_new(digest(0x92), digest(0x93), 1, 0).unwrap_err(),
            QuiescentBackupErrorV1::ProviderUnhealthy
        );
        let paused =
            PausedBackupSourceV1::try_new(1, digest(0x94), 2, 3).expect("safe PAUSE source builds");
        let provider = RecoveryMaintenanceSourceV1::try_new(digest(0x95), digest(0x96), 4, 5)
            .expect("safe provider source builds");
        for diagnostic in [format!("{paused:?}"), format!("{provider:?}")] {
            assert!(!diagnostic.contains(&"94".repeat(32)));
            assert!(!diagnostic.contains(&"95".repeat(32)));
            assert!(!diagnostic.contains(&"96".repeat(32)));
        }
    }

    #[test]
    fn coordinator_root_identity_binding_hashes_raw_identity_bytes() {
        let raw_identity = [0xAB; 32];
        let expected = Sha256Digest::parse_hex(
            "9a2db2e23f1504cd056606553ac049c5e718e8f9ce9233876df1a7a1821af885",
        )
        .expect("root-identity KAT digest parses");
        assert_eq!(coordinator_root_identity_digest_v1(&raw_identity), expected);
        assert_ne!(expected, Sha256Digest::from_bytes(raw_identity));
    }

    #[test]
    fn production_cut_requires_one_bound_pair_identity_before_any_custody_acquisition() {
        let source = include_str!("maintenance.rs");
        let bound_pair = source
            .find(".expected_root_identity()")
            .expect("production cut checks the indivisible pair identity");
        let pause = source
            .find("pause_authority.persist_pause_for_backup_v1")
            .expect("production cut acquires PAUSE custody");
        assert!(bound_pair < pause);
        let obsolete_two_lease_check = ["binds_same_database", "_file_v1"].concat();
        assert!(!source.contains(&obsolete_two_lease_check));
    }

    #[test]
    fn create_only_destination_runs_online_backup_then_reopens_integrity_and_hashes() {
        let source = cut_connection();
        source
            .execute("INSERT INTO prepared_operations VALUES (7)", [])
            .expect("source fixture row inserts");
        let root = temporary_package_path("online-backup");
        let mut destination = ProvisionedBackupDestinationV1::try_reserve_create_only(root.clone())
            .expect("fresh destination reserves");
        assert_eq!(
            ProvisionedBackupDestinationV1::try_reserve_create_only(root.clone()).unwrap_err(),
            QuiescentBackupErrorV1::DestinationExists
        );
        let digest = destination
            .backup_sqlite_v1(&source, &mut MaintenanceFaultProbeV1::disabled_v1())
            .expect("online backup completes and verifies");
        assert_eq!(
            digest,
            hash_file_v1(&destination.coordinator_database).expect("backup hashes again")
        );
        let reopened = Connection::open_with_flags(
            &destination.coordinator_database,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("verified destination reopens read-only");
        assert_eq!(
            reopened
                .query_row("SELECT value FROM prepared_operations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("copied row reads"),
            7
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("synthetic package cleans up");
    }

    #[test]
    fn backup_resource_preflight_accepts_exact_caps_and_refuses_cap_plus_one() {
        const REALISTIC_COORDINATOR_DATABASE_BYTES: u64 = 4 * 1024 * 1024;
        let published = |material_length| {
            ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                provider_profile_id: identifier("profile.resource-v1"),
                provider_profile_version: 1,
                provider_id: identifier("provider.resource-v1"),
                provider_generation: 1,
                evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
                at_rest_profile_id: identifier("at-rest.resource-v1"),
                manifest_digest: digest(0x31),
                material_digest: digest(0x32),
                material_length,
                reserved_capacity: material_length,
                custody: ProviderRecoveryCustodyV1::OperationBound,
                state: ProviderRecoveryStateV1::Published,
                retirement_manifest_digest: None,
            })
            .expect("published resource entry builds")
        };
        let retired =
            ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                provider_profile_id: identifier("profile.resource-v1"),
                provider_profile_version: 1,
                provider_id: identifier("provider.resource-v1"),
                provider_generation: 1,
                evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
                at_rest_profile_id: identifier("at-rest.resource-v1"),
                manifest_digest: digest(0x33),
                material_digest: digest(0x34),
                material_length: 1,
                reserved_capacity: 1,
                custody: ProviderRecoveryCustodyV1::OrphanResolutionTombstone,
                state: ProviderRecoveryStateV1::RetiredTombstone,
                retirement_manifest_digest: Some(digest(0x35)),
            })
            .expect("retired resource entry builds");

        // Seven fixed worst-case paths + 124 two-file packages + one tombstone = 256 files.
        let mut exact_file_count = vec![published(1); 124];
        exact_file_count.push(retired.clone());
        validate_backup_package_resource_shape_v1(
            &exact_file_count,
            REALISTIC_COORDINATOR_DATABASE_BYTES,
        )
        .expect("exact restore-side file cap is producible");
        exact_file_count.push(retired.clone());
        assert_eq!(
            validate_backup_package_resource_shape_v1(
                &exact_file_count,
                REALISTIC_COORDINATOR_DATABASE_BYTES,
            ),
            Err(QuiescentBackupErrorV1::ProviderExportInvalid)
        );

        // Three fixed directories + 129 provider-package directories = 132 directories.
        let exact_directory_count = vec![retired.clone(); 129];
        validate_backup_package_resource_shape_v1(
            &exact_directory_count,
            REALISTIC_COORDINATOR_DATABASE_BYTES,
        )
        .expect("exact restore-side directory cap is producible");
        let too_many_directories = vec![retired; 130];
        assert_eq!(
            validate_backup_package_resource_shape_v1(
                &too_many_directories,
                REALISTIC_COORDINATOR_DATABASE_BYTES,
            ),
            Err(QuiescentBackupErrorV1::ProviderExportInvalid)
        );

        // The exact lower-bound case includes a realistic SQLite image plus all mandatory
        // provider/canonical manifest paths; it never treats the entire aggregate as material.
        let fixed_and_manifest_overhead = REALISTIC_COORDINATOR_DATABASE_BYTES
            + BACKUP_PACKAGE_CANONICAL_MEMBERS_V1
                * BACKUP_PACKAGE_CANONICAL_MEMBER_PATHS_V1
                * BACKUP_PACKAGE_MINIMUM_NONEMPTY_MEMBER_BYTES_V1
            + 4 * BACKUP_PACKAGE_MINIMUM_NONEMPTY_MEMBER_BYTES_V1;
        let fourth_material = MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1
            .checked_sub(fixed_and_manifest_overhead)
            .and_then(|remaining| {
                remaining.checked_sub(3 * MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1)
            })
            .expect("realistic exact-bound fourth material fits");
        let exact_material_bytes = vec![
            published(MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1),
            published(MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1),
            published(MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1),
            published(fourth_material),
        ];
        validate_backup_package_resource_shape_v1(
            &exact_material_bytes,
            REALISTIC_COORDINATOR_DATABASE_BYTES,
        )
        .expect("exact aggregate lower bound including mandatory overhead fits");
        let mut cap_plus_one = exact_material_bytes;
        cap_plus_one[3] = published(fourth_material + 1);
        assert_eq!(
            validate_backup_package_resource_shape_v1(
                &cap_plus_one,
                REALISTIC_COORDINATOR_DATABASE_BYTES,
            ),
            Err(QuiescentBackupErrorV1::ProviderExportInvalid)
        );
        let four_maximum_materials = vec![published(MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1); 4];
        assert_eq!(
            validate_backup_package_resource_shape_v1(
                &four_maximum_materials,
                REALISTIC_COORDINATOR_DATABASE_BYTES,
            ),
            Err(QuiescentBackupErrorV1::ProviderExportInvalid)
        );
        assert_eq!(
            validate_backup_package_resource_shape_v1(
                &[published(MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 + 1,)],
                REALISTIC_COORDINATOR_DATABASE_BYTES
            ),
            Err(QuiescentBackupErrorV1::ProviderExportInvalid)
        );
    }

    #[test]
    fn impossible_resource_inventory_refuses_before_any_backup_destination_mutation() {
        let published =
            ProviderRecoveryInventoryEntryV1::try_new(ProviderRecoveryInventoryEntryInputV1 {
                provider_profile_id: identifier("profile.resource-v1"),
                provider_profile_version: 1,
                provider_id: identifier("provider.resource-v1"),
                provider_generation: 1,
                evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
                at_rest_profile_id: identifier("at-rest.resource-v1"),
                manifest_digest: digest(0x41),
                material_digest: digest(0x42),
                material_length: MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1,
                reserved_capacity: MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1,
                custody: ProviderRecoveryCustodyV1::OperationBound,
                state: ProviderRecoveryStateV1::Published,
                retirement_manifest_digest: None,
            })
            .expect("maximum-size published resource entry builds");
        let (result, root) = run_complete_backup(
            "resource-preflight-zero-mutation",
            false,
            false,
            false,
            None,
            Some(vec![published; 4]),
        );
        assert_eq!(
            result.unwrap_err(),
            QuiescentBackupErrorV1::ProviderExportInvalid
        );

        // Reservation itself creates only this empty skeleton. The resource refusal happens
        // before online backup, provider export, staging, hard-link publication or sidecars.
        assert_eq!(
            fs::metadata(root.join("coordinator.sqlite3"))
                .expect("reserved coordinator member metadata reads")
                .len(),
            0
        );
        for directory in ["staging", "published", "recovery-packages"] {
            assert!(
                fs::read_dir(root.join(directory))
                    .expect("reserved package directory reads")
                    .next()
                    .is_none(),
                "resource refusal must leave {directory} empty"
            );
        }
        assert!(!root.join("coordinator.sqlite3-wal").exists());
        assert!(!root.join("coordinator.sqlite3-shm").exists());
        fs::remove_dir_all(root).expect("resource refusal package fixture cleans up");
    }

    #[test]
    fn published_member_remains_successful_when_post_link_staging_cleanup_fails() {
        let root = temporary_package_path("publication-cleanup-refusal");
        let mut destination = ProvisionedBackupDestinationV1::try_reserve_create_only(root.clone())
            .expect("fresh destination reserves");
        let member = CanonicalBackupMemberV1::try_new(br#"{"schema":"synthetic/1"}"#.to_vec())
            .expect("synthetic canonical member builds");
        destination
            .stage_canonical_member_v1(BackupJsonMemberV1::TopLevelManifest, &member)
            .expect("member stages");

        destination
            .publish_staged_member_with_cleanup_v1(
                BackupJsonMemberV1::TopLevelManifest,
                &mut MaintenanceFaultProbeV1::disabled_v1(),
                |_| Err(std::io::Error::other("synthetic unlink refusal")),
            )
            .expect("visible hard-link publication is not reversed by cleanup refusal");

        assert_eq!(
            destination
                .reopen_published_member_v1(BackupJsonMemberV1::TopLevelManifest)
                .expect("published member reopens"),
            member.bytes()
        );
        assert!(destination
            .staging
            .join(BackupJsonMemberV1::TopLevelManifest.file_name())
            .is_file());
        fs::remove_dir_all(root).expect("synthetic package cleans up");
    }

    #[test]
    fn coordinator_backup_counts_the_authoritative_operation_transitions_table() {
        let connection = cut_connection();
        connection
            .execute("INSERT INTO operation_transitions VALUES (1), (2)", [])
            .expect("authoritative transition rows insert");
        let (_, counts) = capture_coordinator_backup_state_v1(&connection)
            .expect("coordinator backup state captures from real table name");
        assert_eq!(counts.operation_transitions(), 2);
    }

    #[test]
    fn online_backup_busy_locked_and_noncompletion_have_explicit_bounded_refusal() {
        let busy_calls = AtomicU64::new(0);
        assert_eq!(
            drive_online_backup_steps_v1(
                || {
                    busy_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(StepResult::Busy)
                },
                100,
                2,
                Duration::ZERO,
            ),
            Err(QuiescentBackupErrorV1::BackupFailed)
        );
        assert_eq!(busy_calls.load(Ordering::Relaxed), 3);

        let more_calls = AtomicU64::new(0);
        assert_eq!(
            drive_online_backup_steps_v1(
                || {
                    more_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(StepResult::More)
                },
                4,
                4,
                Duration::ZERO,
            ),
            Err(QuiescentBackupErrorV1::BackupFailed)
        );
        assert_eq!(more_calls.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn complete_backup_exports_both_states_publishes_attestation_last_and_reopens_verified() {
        let (result, root) = run_complete_backup("complete", false, false, false, None, None);
        let verified = result.expect("complete quiescent backup verifies");
        assert_eq!(verified.provider_set_count(), 1);
        assert_eq!(verified.entry_count(), 2);
        assert_ne!(verified.inventory_sha256(), digest(0));
        assert_ne!(verified.top_level_manifest_sha256(), digest(0));
        assert_ne!(verified.provenance_attestation_sha256(), digest(0));
        let destination = verified.into_destination();
        assert!(destination.attestation_published);
        assert!(!destination
            .reopen_published_member_v1(BackupJsonMemberV1::RecoveryInventory)
            .expect("inventory reopens")
            .is_empty());
        assert!(!destination
            .reopen_published_member_v1(BackupJsonMemberV1::TopLevelManifest)
            .expect("top-level manifest reopens")
            .is_empty());
        assert!(!destination
            .reopen_published_member_v1(BackupJsonMemberV1::Attestation)
            .expect("attestation reopens")
            .is_empty());
        let first = destination.provider_packages.join("0000000000000000");
        let second = destination.provider_packages.join("0000000000000001");
        let first_published = first.join("manifest.json").is_file()
            && first.join("material.bin").is_file()
            && !first.join("retirement-manifest.json").exists();
        let second_published = second.join("manifest.json").is_file()
            && second.join("material.bin").is_file()
            && !second.join("retirement-manifest.json").exists();
        let first_retired = first.join("retirement-manifest.json").is_file()
            && !first.join("manifest.json").exists()
            && !first.join("material.bin").exists();
        let second_retired = second.join("retirement-manifest.json").is_file()
            && !second.join("manifest.json").exists()
            && !second.join("material.bin").exists();
        assert!((first_published && second_retired) || (first_retired && second_published));
        assert!(!format!("{destination:?}").contains(root.to_string_lossy().as_ref()));
        drop(destination);
        fs::remove_dir_all(root).expect("complete package fixture cleans up");
    }

    #[test]
    fn coherent_attestation_substitution_pending_and_corrupt_export_fail_closed() {
        for (label, substituted, pending, corrupt, expected) in [
            (
                "substitution",
                true,
                false,
                false,
                QuiescentBackupErrorV1::ProvenanceInvalid,
            ),
            (
                "provider-pending",
                false,
                true,
                false,
                QuiescentBackupErrorV1::RetirementPending,
            ),
            (
                "corrupt-export",
                false,
                false,
                true,
                QuiescentBackupErrorV1::ProviderExportInvalid,
            ),
        ] {
            let (result, root) =
                run_complete_backup(label, substituted, pending, corrupt, None, None);
            assert_eq!(result.unwrap_err(), expected, "case {label}");
            assert!(
                !root.join("published/provenance-attestation.json").is_file()
                    || expected == QuiescentBackupErrorV1::ProvenanceInvalid,
                "only a reopened provenance failure may occur after final publication"
            );
            fs::remove_dir_all(root).expect("negative package fixture cleans up");
        }
    }

    #[test]
    fn complete_backup_early_error_releases_pause_and_provider_once() {
        let pause_releases = Arc::new(AtomicU64::new(0));
        let provider_releases = Arc::new(AtomicU64::new(0));
        let (result, root) = run_complete_backup(
            "release-on-error",
            false,
            false,
            true,
            Some((Arc::clone(&pause_releases), Arc::clone(&provider_releases))),
            None,
        );
        assert_eq!(
            result.unwrap_err(),
            QuiescentBackupErrorV1::ProviderExportInvalid
        );
        assert_eq!(pause_releases.load(Ordering::SeqCst), 1);
        assert_eq!(provider_releases.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(root).expect("early-error package fixture cleans up");
    }

    #[test]
    fn live_cut_rechecks_all_three_custodies_and_detects_generation_change() {
        let (source_connection, source_root) = file_cut_connection("generation-recheck");
        let mut guard_connection = Connection::open(source_root.join("coordinator.sqlite3"))
            .expect("generation guard connection opens");
        let transaction = guard_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("coordinator maintenance writer acquires");
        let coordinator_guard = CoordinatorMaintenanceGuardV1 { transaction };
        let (coordinator_generations, coordinator_counts) =
            capture_coordinator_backup_state_v1(coordinator_guard.source_connection())
                .expect("cut state captures");
        let mut pause_custody = TestPauseCustodyV1 {
            live: true,
            release_count: None,
        };
        let paused_source = pause_custody
            .capture_paused_source_v1()
            .expect("PAUSE source captures");
        let mut provider_custody = TestProviderCustodyV1 {
            live: true,
            operation_pending: 0,
            release_count: None,
        };
        let recovery_source = provider_custody
            .capture_recovery_source_v1()
            .expect("provider source captures");
        let inventory_provider = TestProviderV1::exact(Vec::new());
        let mut cut = QuiescentBackupCutV1 {
            backup_source: &source_connection,
            inventory_provider: &inventory_provider,
            pause_custody: Some(pause_custody),
            provider_custody: Some(provider_custody),
            coordinator_guard: Some(coordinator_guard),
            paused_source,
            recovery_source,
            coordinator_generations,
            coordinator_counts,
            inventory: ReconciledRecoveryInventoryV1 {
                provider_entries: Vec::new(),
                operation_reference_count: 0,
                quarantine_reference_count: 0,
                operation_retirement_pending: 0,
                orphan_retirement_pending: 0,
            },
            source_coordinator_root_identity_sha256: digest(0x97),
            coordinator_schema_sha256: digest(0x98),
            fault_probe: MaintenanceFaultProbeV1::disabled_v1(),
        };
        cut.recheck_source_generations_v1()
            .expect("unchanged cut rechecks");
        cut.coordinator_guard
            .as_ref()
            .expect("live cut retains coordinator guard")
            .source_connection()
            .execute(
                "UPDATE coordinator_store_meta SET store_generation = 6 WHERE singleton = 1",
                [],
            )
            .expect("synthetic mutation stages");
        assert_eq!(
            cut.recheck_source_generations_v1().unwrap_err(),
            QuiescentBackupErrorV1::SourceChanged
        );
        cut.release_v1().expect("cut rolls back and releases");
        assert_eq!(
            source_connection
                .query_row(
                    "SELECT store_generation FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("generation reads after release"),
            5
        );
        drop(guard_connection);
        drop(source_connection);
        fs::remove_dir_all(source_root).expect("generation source fixture cleans up");
    }

    #[test]
    fn post_backup_provider_reenumeration_refuses_inventory_change() {
        let (source_connection, source_root) = file_cut_connection("provider-reenumeration");
        let mut guard_connection = Connection::open(source_root.join("coordinator.sqlite3"))
            .expect("provider re-enumeration guard connection opens");
        let transaction = guard_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("coordinator maintenance writer acquires");
        let coordinator_guard = CoordinatorMaintenanceGuardV1 { transaction };
        let (coordinator_generations, coordinator_counts) =
            capture_coordinator_backup_state_v1(coordinator_guard.source_connection())
                .expect("cut state captures");
        let mut pause_custody = TestPauseCustodyV1 {
            live: true,
            release_count: None,
        };
        let paused_source = pause_custody
            .capture_paused_source_v1()
            .expect("PAUSE source captures");
        let mut provider_custody = TestProviderCustodyV1 {
            live: true,
            operation_pending: 0,
            release_count: None,
        };
        let recovery_source = provider_custody
            .capture_recovery_source_v1()
            .expect("provider source captures");
        let inventory_provider = TestProviderV1::exact(vec![entry(
            0x91,
            0x92,
            ProviderRecoveryCustodyV1::QuarantinedOrphan,
            ProviderRecoveryStateV1::Published,
            None,
        )]);
        let mut cut = QuiescentBackupCutV1 {
            backup_source: &source_connection,
            inventory_provider: &inventory_provider,
            pause_custody: Some(pause_custody),
            provider_custody: Some(provider_custody),
            coordinator_guard: Some(coordinator_guard),
            paused_source,
            recovery_source,
            coordinator_generations,
            coordinator_counts,
            inventory: ReconciledRecoveryInventoryV1 {
                provider_entries: Vec::new(),
                operation_reference_count: 0,
                quarantine_reference_count: 0,
                operation_retirement_pending: 0,
                orphan_retirement_pending: 0,
            },
            source_coordinator_root_identity_sha256: digest(0x97),
            coordinator_schema_sha256: digest(0x98),
            fault_probe: MaintenanceFaultProbeV1::disabled_v1(),
        };

        assert_eq!(
            cut.reenumerate_and_compare_inventory_v1().unwrap_err(),
            QuiescentBackupErrorV1::SourceChanged
        );
        assert_eq!(inventory_provider.calls.load(Ordering::SeqCst), 1);
        cut.release_v1().expect("cut rolls back and releases");
        drop(guard_connection);
        drop(source_connection);
        fs::remove_dir_all(source_root).expect("provider source fixture cleans up");
    }

    #[test]
    fn dropping_unfinished_cut_rolls_back_and_releases_each_custody_once() {
        let (source_connection, source_root) = file_cut_connection("drop-release");
        let mut guard_connection = Connection::open(source_root.join("coordinator.sqlite3"))
            .expect("drop-release guard connection opens");
        let transaction = guard_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("drop-release maintenance writer acquires");
        let coordinator_guard = CoordinatorMaintenanceGuardV1 { transaction };
        let (coordinator_generations, coordinator_counts) =
            capture_coordinator_backup_state_v1(coordinator_guard.source_connection())
                .expect("drop-release state captures");
        coordinator_guard
            .source_connection()
            .execute(
                "UPDATE coordinator_store_meta SET store_generation = 99 WHERE singleton = 1",
                [],
            )
            .expect("drop-release mutation stages");
        let pause_releases = Arc::new(AtomicU64::new(0));
        let provider_releases = Arc::new(AtomicU64::new(0));
        let mut pause_custody = TestPauseCustodyV1 {
            live: true,
            release_count: Some(Arc::clone(&pause_releases)),
        };
        let paused_source = pause_custody
            .capture_paused_source_v1()
            .expect("drop-release PAUSE source captures");
        let mut provider_custody = TestProviderCustodyV1 {
            live: true,
            operation_pending: 0,
            release_count: Some(Arc::clone(&provider_releases)),
        };
        let recovery_source = provider_custody
            .capture_recovery_source_v1()
            .expect("drop-release provider source captures");
        let inventory_provider = TestProviderV1::exact(Vec::new());
        let cut = QuiescentBackupCutV1 {
            backup_source: &source_connection,
            inventory_provider: &inventory_provider,
            pause_custody: Some(pause_custody),
            provider_custody: Some(provider_custody),
            coordinator_guard: Some(coordinator_guard),
            paused_source,
            recovery_source,
            coordinator_generations,
            coordinator_counts,
            inventory: ReconciledRecoveryInventoryV1 {
                provider_entries: Vec::new(),
                operation_reference_count: 0,
                quarantine_reference_count: 0,
                operation_retirement_pending: 0,
                orphan_retirement_pending: 0,
            },
            source_coordinator_root_identity_sha256: digest(0x99),
            coordinator_schema_sha256: digest(0x9A),
            fault_probe: MaintenanceFaultProbeV1::disabled_v1(),
        };
        drop(cut);
        assert_eq!(pause_releases.load(Ordering::SeqCst), 1);
        assert_eq!(provider_releases.load(Ordering::SeqCst), 1);
        assert_eq!(
            source_connection
                .query_row(
                    "SELECT store_generation FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("rolled-back generation reads"),
            5
        );
        drop(guard_connection);
        drop(source_connection);
        fs::remove_dir_all(source_root).expect("drop-release source fixture cleans up");
    }

    #[test]
    fn every_t069_section_14_hook_has_one_production_call_site() {
        let source = include_str!("maintenance.rs");
        let hooks = [
            ["Backup", "PausePersisted"].concat(),
            ["BackupProvider", "MaintenanceGuardAcquired"].concat(),
            ["BackupCoordinator", "MaintenanceGuardAcquired"].concat(),
            ["BackupSource", "ProfilesVerified"].concat(),
            ["BackupSource", "InvariantsVerified"].concat(),
            ["BackupSource", "GenerationsCaptured"].concat(),
            ["BackupProvider", "EnumerationReconciled"].concat(),
            ["BackupSource", "GenerationsRechecked"].concat(),
        ];
        for hook in hooks {
            assert_eq!(source.matches(&hook).count(), 1, "hook {hook}");
        }
    }

    #[test]
    fn every_t071_section_14_hook_has_one_production_call_site() {
        let source = include_str!("maintenance.rs");
        for hook in [
            ["BackupSqlite", "OnlineBackupCompleted"].concat(),
            ["BackupSqlite", "OnlineBackupClosed"].concat(),
            ["BackupSqlite", "OnlineBackupIntegrityChecked"].concat(),
            ["BackupSqlite", "OnlineBackupHashed"].concat(),
            ["BackupMaterial", "PresentPackageExported"].concat(),
            ["BackupRetirement", "TombstoneExported"].concat(),
            ["BackupInventory", "JcsFinalized"].concat(),
            ["BackupTopLevel", "ManifestStaged"].concat(),
            ["BackupTopLevel", "ManifestPublished"].concat(),
            ["BackupAttestationProtected", "JcsFinalized"].concat(),
            ["BackupAttestation", "Signed"].concat(),
            ["BackupAttestation", "Staged"].concat(),
            ["BackupAttestation", "Published"].concat(),
            ["BackupAttestation", "Reopened"].concat(),
            ["BackupAttestation", "Verified"].concat(),
        ] {
            assert_eq!(source.matches(&hook).count(), 1, "hook {hook}");
        }
    }

    #[test]
    fn exact_section_14_reconciliation_hook_is_present_once() {
        let hook = ["BackupProvider", "EnumerationReconciled"].concat();
        assert_eq!(include_str!("maintenance.rs").matches(&hook).count(), 1);
    }
}
