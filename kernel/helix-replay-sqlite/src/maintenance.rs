use crate::clock::remaining_monotonic_ms;
use crate::config::{
    backup_database_path, backup_manifest_path, ensure_empty, revalidate_backup_root,
    roots_are_same, ReplayStoreConfigV1, TrustedLocalStoreRootV1, DATABASE_FILENAME,
};
use crate::connection::{configure_writable_connection, map_sqlite_error, open_existing_for_claim};
use crate::error::{InternalStoreError, ReplayStoreMaintenanceErrorV1};
use crate::manifest::{read_manifest_v1_file, sha256_file_hex, BackupManifestV1};
use crate::root_safety::{
    acquire_backup_package_lease, acquire_checked_live_root_lease,
    publish_restored_activation_marker, quarantine_with_held_live_lease,
    reserve_new_destination_root, verify_restored_activation_marker, RootLeaseV1, RootStateV1,
};
use crate::schema::{
    latch_unhealthy, verify_full, verify_lightweight, StoreSummary, REPLAY_STORE_APPLICATION_ID_V1,
    REPLAY_STORE_SCHEMA_VERSION_V1,
};
use crate::{ReplayMonotonicClockV1, SqliteReplayClaimantV1};
use helix_contracts::MAX_SAFE_U64;
use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

const BACKUP_DATABASE_STAGING_FILENAME: &str = ".replay-backup.sqlite3.staging";
const BACKUP_MANIFEST_STAGING_FILENAME: &str = ".backup-manifest-v1.json.staging";
const RESTORE_DATABASE_STAGING_FILENAME: &str = ".replay.sqlite3.restore-staging";

/// Closed checkpoint modes; claims never invoke either mode implicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayCheckpointModeV1 {
    Passive,
    QuiescentTruncate,
}

/// Redacted proof that the live store passed full SQLite and application verification.
pub struct ReplayStoreVerificationV1 {
    claimant_generation: u64,
    claim_count: u64,
}

impl ReplayStoreVerificationV1 {
    pub const fn application_id(&self) -> i64 {
        REPLAY_STORE_APPLICATION_ID_V1
    }

    pub const fn store_schema_version(&self) -> i64 {
        REPLAY_STORE_SCHEMA_VERSION_V1
    }

    pub const fn claimant_generation(&self) -> u64 {
        self.claimant_generation
    }

    pub const fn claim_count(&self) -> u64 {
        self.claim_count
    }
}

impl fmt::Debug for ReplayStoreVerificationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayStoreVerificationV1")
            .finish_non_exhaustive()
    }
}

/// Redacted bounded checkpoint result.
pub struct ReplayCheckpointEvidenceV1 {
    mode: ReplayCheckpointModeV1,
    log_frames: u64,
    checkpointed_frames: u64,
    complete: bool,
    claimant_generation_before: u64,
    claimant_generation_after: u64,
}

impl ReplayCheckpointEvidenceV1 {
    pub const fn mode(&self) -> ReplayCheckpointModeV1 {
        self.mode
    }

    pub const fn log_frames(&self) -> u64 {
        self.log_frames
    }

    pub const fn checkpointed_frames(&self) -> u64 {
        self.checkpointed_frames
    }

    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    pub const fn claimant_generation_before(&self) -> u64 {
        self.claimant_generation_before
    }

    pub const fn claimant_generation_after(&self) -> u64 {
        self.claimant_generation_after
    }
}

impl fmt::Debug for ReplayCheckpointEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayCheckpointEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Redacted evidence for one manifest-last online backup package.
pub struct ReplayBackupEvidenceV1 {
    claimant_generation: u64,
    claim_count: u64,
}

impl ReplayBackupEvidenceV1 {
    pub const fn claimant_generation(&self) -> u64 {
        self.claimant_generation
    }

    pub const fn claim_count(&self) -> u64 {
        self.claim_count
    }
}

impl fmt::Debug for ReplayBackupEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayBackupEvidenceV1")
            .finish_non_exhaustive()
    }
}

struct VerifiedBackupPackageV1 {
    _lease: RootLeaseV1,
    source: Connection,
    manifest: BackupManifestV1,
    summary: StoreSummary,
}

/// Verified restore result that still requires paused external activation and epoch rotation.
pub struct VerifiedRestoreEvidenceV1 {
    claimant_generation: u64,
    claim_count: u64,
    restored_activation_marker_present: bool,
}

impl VerifiedRestoreEvidenceV1 {
    pub const fn claimant_generation(&self) -> u64 {
        self.claimant_generation
    }

    pub const fn claim_count(&self) -> u64 {
        self.claim_count
    }

    pub const fn requires_paused_activation(&self) -> bool {
        true
    }

    pub const fn requires_instance_epoch_rotation(&self) -> bool {
        true
    }

    pub const fn requires_fencing_epoch_rotation(&self) -> bool {
        true
    }

    pub const fn may_omit_claims_after_generation(&self) -> bool {
        true
    }

    pub const fn restored_activation_marker_present(&self) -> bool {
        self.restored_activation_marker_present
    }
}

impl fmt::Debug for VerifiedRestoreEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRestoreEvidenceV1")
            .finish_non_exhaustive()
    }
}

impl<C: ReplayMonotonicClockV1> SqliteReplayClaimantV1<C> {
    pub fn verify_integrity_v1(
        &self,
        deadline_monotonic_ms: u64,
    ) -> Result<ReplayStoreVerificationV1, ReplayStoreMaintenanceErrorV1> {
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;
        let mut connection =
            open_existing_for_claim(&self.config, &self.clock, deadline_monotonic_ms)
                .map_err(|error| error.to_maintenance())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                map_sqlite_error(&error, InternalStoreError::StoreUnavailable).to_maintenance()
            })?;

        let mut root_lease = match acquire_checked_live_root_lease(
            self.config.root(),
            self.config.maximum_busy_wait_ms(),
            &self.clock,
            deadline_monotonic_ms,
        ) {
            Ok(lease) => lease,
            Err(error) => return rollback_then(transaction, root_maintenance_error(error)),
        };

        if let Err(error) = maintenance_remaining(&self.clock, deadline_monotonic_ms) {
            return rollback_then(transaction, error);
        }
        if let Err(error) = verify_lightweight(&transaction, self.schema_cookie) {
            if error.requires_durable_quarantine()
                && quarantine_with_held_live_lease(&mut root_lease, self.config.root()).is_err()
            {
                latch_unhealthy(&self.healthy);
                return rollback_then(transaction, ReplayStoreMaintenanceErrorV1::StoreUnavailable);
            }
            latch_for_store_failure(&self.healthy, error);
            return rollback_then(transaction, error.to_maintenance());
        }
        let summary = match verify_full(&transaction) {
            Ok(summary) => summary,
            Err(error) => {
                if error.requires_durable_quarantine()
                    && quarantine_with_held_live_lease(&mut root_lease, self.config.root()).is_err()
                {
                    latch_unhealthy(&self.healthy);
                    return rollback_then(
                        transaction,
                        ReplayStoreMaintenanceErrorV1::StoreUnavailable,
                    );
                }
                latch_for_store_failure(&self.healthy, error);
                return rollback_then(transaction, error.to_maintenance());
            }
        };
        drop(root_lease);
        transaction
            .rollback()
            .map_err(|_| ReplayStoreMaintenanceErrorV1::StoreUnavailable)?;
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;
        Ok(verification_evidence(summary))
    }

    pub fn checkpoint_v1(
        &self,
        mode: ReplayCheckpointModeV1,
        deadline_monotonic_ms: u64,
    ) -> Result<ReplayCheckpointEvidenceV1, ReplayStoreMaintenanceErrorV1> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(ReplayStoreMaintenanceErrorV1::StoreUnavailable);
        }
        let before = self.verify_integrity_v1(deadline_monotonic_ms)?;
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;
        let connection = open_existing_for_claim(&self.config, &self.clock, deadline_monotonic_ms)
            .map_err(|error| error.to_maintenance())?;
        if let Err(error) = verify_lightweight(&connection, self.schema_cookie) {
            latch_for_store_failure(&self.healthy, error);
            return Err(error.to_maintenance());
        }
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;

        let statement = match mode {
            ReplayCheckpointModeV1::Passive => "PRAGMA wal_checkpoint(PASSIVE)",
            ReplayCheckpointModeV1::QuiescentTruncate => "PRAGMA wal_checkpoint(TRUNCATE)",
        };
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::CheckpointBeforeMutation);
        let (busy, log_frames, checkpointed_frames): (i64, i64, i64) = connection
            .query_row(statement, [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|error| {
                let mapped = map_sqlite_error(&error, InternalStoreError::StoreUnavailable);
                if mapped.is_busy() {
                    ReplayStoreMaintenanceErrorV1::StoreBusy
                } else {
                    mapped.to_maintenance()
                }
            })?;
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::CheckpointReturned);
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;
        drop(connection);
        let after = self.verify_integrity_v1(deadline_monotonic_ms)?;

        let log_frames = safe_frame_count(log_frames)?;
        let checkpointed_frames = safe_frame_count(checkpointed_frames)?;
        let complete = busy == 0
            && match mode {
                ReplayCheckpointModeV1::Passive => checkpointed_frames == log_frames,
                ReplayCheckpointModeV1::QuiescentTruncate => {
                    log_frames == 0 && checkpointed_frames == 0
                }
            };
        if matches!(mode, ReplayCheckpointModeV1::QuiescentTruncate) && !complete {
            return Err(ReplayStoreMaintenanceErrorV1::StoreBusy);
        }
        if after.claimant_generation() < before.claimant_generation() {
            latch_unhealthy(&self.healthy);
            return Err(ReplayStoreMaintenanceErrorV1::InvariantFailed);
        }
        Ok(ReplayCheckpointEvidenceV1 {
            mode,
            log_frames,
            checkpointed_frames,
            complete,
            claimant_generation_before: before.claimant_generation(),
            claimant_generation_after: after.claimant_generation(),
        })
    }

    pub fn backup_v1(
        &self,
        empty_destination: TrustedLocalStoreRootV1,
        deadline_monotonic_ms: u64,
    ) -> Result<ReplayBackupEvidenceV1, ReplayStoreMaintenanceErrorV1> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(ReplayStoreMaintenanceErrorV1::StoreUnavailable);
        }
        if roots_are_same(self.config.root().path(), empty_destination.path()) {
            return Err(ReplayStoreMaintenanceErrorV1::SourceDestinationConflict);
        }
        ensure_empty(empty_destination.path())
            .map_err(|_| ReplayStoreMaintenanceErrorV1::DestinationNotEmpty)?;
        let _destination_lease = reserve_new_destination_root(
            &empty_destination,
            RootStateV1::BackupPackage,
            &self.clock,
            deadline_monotonic_ms,
        )
        .map_err(root_maintenance_error)?;
        self.verify_integrity_v1(deadline_monotonic_ms)?;
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;
        let source = open_existing_for_claim(&self.config, &self.clock, deadline_monotonic_ms)
            .map_err(|error| error.to_maintenance())?;
        if let Err(error) = verify_lightweight(&source, self.schema_cookie) {
            latch_for_store_failure(&self.healthy, error);
            return Err(error.to_maintenance());
        }

        let staging_database = empty_destination
            .path()
            .join(BACKUP_DATABASE_STAGING_FILENAME);
        let staging_manifest = empty_destination
            .path()
            .join(BACKUP_MANIFEST_STAGING_FILENAME);
        let final_database = backup_database_path(&empty_destination);
        let final_manifest = backup_manifest_path(&empty_destination);
        ensure_paths_absent(&[
            &staging_database,
            &staging_manifest,
            &final_database,
            &final_manifest,
        ])?;

        let mut destination = open_new_sqlite_database(
            &staging_database,
            ReplayStoreMaintenanceErrorV1::BackupIncomplete,
        )?;
        run_online_backup(
            &source,
            &mut destination,
            &self.clock,
            deadline_monotonic_ms,
            self.config.backup_step_pages(),
            self.config.backup_retry_wait_ms(),
            ReplayStoreMaintenanceErrorV1::BackupIncomplete,
        )?;
        make_backup_standalone(
            &destination,
            ReplayStoreMaintenanceErrorV1::BackupIncomplete,
        )?;
        let summary = verify_full(&destination).map_err(|error| error.to_maintenance())?;
        let sqlite_source_id = read_sqlite_source_id(&destination)?;
        drop(destination);
        drop(source);

        sync_file(
            &staging_database,
            ReplayStoreMaintenanceErrorV1::BackupIncomplete,
        )?;
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::BackupDatabaseComplete);
        let database_sha256 = sha256_file_hex(&staging_database)
            .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;
        let manifest = BackupManifestV1::from_verified_snapshot(
            summary.claimant_generation,
            summary.claim_count,
            database_sha256,
            rusqlite::version().to_owned(),
            sqlite_source_id,
        )?;
        write_new_synced_file(&staging_manifest, &manifest.encode_v1()?)?;
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::BackupManifestStaged);
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;

        publish_no_clobber(
            &staging_database,
            &final_database,
            ReplayStoreMaintenanceErrorV1::BackupIncomplete,
        )?;
        maintenance_remaining(&self.clock, deadline_monotonic_ms)?;
        publish_no_clobber(
            &staging_manifest,
            &final_manifest,
            ReplayStoreMaintenanceErrorV1::BackupIncomplete,
        )?;
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::BackupPublished);
        revalidate_backup_root(&empty_destination)
            .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;

        Ok(ReplayBackupEvidenceV1 {
            claimant_generation: summary.claimant_generation,
            claim_count: summary.claim_count,
        })
    }
}

pub fn restore_replay_store_v1<C: ReplayMonotonicClockV1>(
    backup_root: TrustedLocalStoreRootV1,
    empty_destination_config: ReplayStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<VerifiedRestoreEvidenceV1, ReplayStoreMaintenanceErrorV1> {
    if roots_are_same(backup_root.path(), empty_destination_config.root().path()) {
        return Err(ReplayStoreMaintenanceErrorV1::SourceDestinationConflict);
    }
    ensure_empty(empty_destination_config.root().path())
        .map_err(|_| ReplayStoreMaintenanceErrorV1::DestinationNotEmpty)?;
    let verified_backup = verify_backup_package_v1(
        &backup_root,
        empty_destination_config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    let VerifiedBackupPackageV1 {
        _lease: _backup_package_lease,
        source,
        manifest,
        summary: _source_summary,
    } = verified_backup;

    let _destination_lease = reserve_new_destination_root(
        empty_destination_config.root(),
        RootStateV1::RestorePending,
        clock,
        deadline_monotonic_ms,
    )
    .map_err(root_maintenance_error)?;
    publish_restored_activation_marker(empty_destination_config.root())
        .map_err(|_| ReplayStoreMaintenanceErrorV1::RestoreIncomplete)?;
    #[cfg(feature = "test-fault-injection")]
    crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::RestoreReserved);
    maintenance_remaining(clock, deadline_monotonic_ms)?;
    #[cfg(feature = "test-fault-injection")]
    if crate::test_fault::return_error_requested(
        crate::test_fault::ReplayReturnErrorPointV1::RestoreBeforeCopy,
    ) {
        return Err(ReplayStoreMaintenanceErrorV1::RestoreIncomplete);
    }

    let staging_database = empty_destination_config
        .root()
        .path()
        .join(RESTORE_DATABASE_STAGING_FILENAME);
    let final_database = empty_destination_config
        .root()
        .path()
        .join(DATABASE_FILENAME);
    ensure_paths_absent(&[&staging_database, &final_database])?;
    let mut destination = open_new_sqlite_database(
        &staging_database,
        ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
    )?;
    run_online_backup(
        &source,
        &mut destination,
        clock,
        deadline_monotonic_ms,
        empty_destination_config.backup_step_pages(),
        empty_destination_config.backup_retry_wait_ms(),
        ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
    )?;
    make_backup_standalone(
        &destination,
        ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
    )?;
    let restored_staging = verify_full(&destination).map_err(|error| error.to_maintenance())?;
    drop(destination);
    drop(source);
    if restored_staging.claimant_generation != manifest.claimant_generation()
        || restored_staging.claim_count != manifest.claim_count()
    {
        return Err(ReplayStoreMaintenanceErrorV1::RestoreIncomplete);
    }
    sync_file(
        &staging_database,
        ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
    )?;
    #[cfg(feature = "test-fault-injection")]
    crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::RestoreDatabaseStaged);
    maintenance_remaining(clock, deadline_monotonic_ms)?;
    publish_no_clobber(
        &staging_database,
        &final_database,
        ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
    )?;
    #[cfg(feature = "test-fault-injection")]
    crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::RestorePublished);
    maintenance_remaining(clock, deadline_monotonic_ms)?;

    let remaining_ms = maintenance_remaining(clock, deadline_monotonic_ms)?;
    let restored_connection = Connection::open_with_flags(
        &final_database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ReplayStoreMaintenanceErrorV1::RestoreIncomplete)?;
    configure_writable_connection(
        &restored_connection,
        remaining_ms.min(empty_destination_config.maximum_busy_wait_ms()),
        true,
    )
    .map_err(InternalStoreError::to_maintenance)?;
    let restored = verify_full(&restored_connection).map_err(InternalStoreError::to_maintenance)?;
    if restored.claimant_generation != manifest.claimant_generation()
        || restored.claim_count != manifest.claim_count()
    {
        return Err(ReplayStoreMaintenanceErrorV1::RestoreIncomplete);
    }
    drop(restored_connection);
    sync_file(
        &final_database,
        ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
    )?;
    let remaining_ms = maintenance_remaining(clock, deadline_monotonic_ms)?;

    let reopened_connection = Connection::open_with_flags(
        &final_database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ReplayStoreMaintenanceErrorV1::RestoreIncomplete)?;
    configure_writable_connection(
        &reopened_connection,
        remaining_ms.min(empty_destination_config.maximum_busy_wait_ms()),
        false,
    )
    .map_err(InternalStoreError::to_maintenance)?;
    let reopened = verify_full(&reopened_connection).map_err(InternalStoreError::to_maintenance)?;
    if reopened.claimant_generation != manifest.claimant_generation()
        || reopened.claim_count != manifest.claim_count()
    {
        return Err(ReplayStoreMaintenanceErrorV1::RestoreIncomplete);
    }
    drop(reopened_connection);
    verify_restored_activation_marker(empty_destination_config.root())
        .map_err(|_| ReplayStoreMaintenanceErrorV1::RestoreIncomplete)?;
    #[cfg(feature = "test-fault-injection")]
    crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::RestoreProfileVerified);
    maintenance_remaining(clock, deadline_monotonic_ms)?;
    Ok(VerifiedRestoreEvidenceV1 {
        claimant_generation: reopened.claimant_generation,
        claim_count: reopened.claim_count,
        restored_activation_marker_present: true,
    })
}

/// Verifies a complete, manifest-last backup package without activating or restoring it.
pub fn verify_replay_backup_v1<C: ReplayMonotonicClockV1>(
    backup_root: TrustedLocalStoreRootV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<ReplayBackupEvidenceV1, ReplayStoreMaintenanceErrorV1> {
    let maximum_wait_ms = maintenance_remaining(clock, deadline_monotonic_ms)?;
    let verified =
        verify_backup_package_v1(&backup_root, maximum_wait_ms, clock, deadline_monotonic_ms)?;
    Ok(ReplayBackupEvidenceV1 {
        claimant_generation: verified.summary.claimant_generation,
        claim_count: verified.summary.claim_count,
    })
}

fn verify_backup_package_v1<C: ReplayMonotonicClockV1>(
    backup_root: &TrustedLocalStoreRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<VerifiedBackupPackageV1, ReplayStoreMaintenanceErrorV1> {
    maintenance_remaining(clock, deadline_monotonic_ms)?;
    let lease =
        acquire_backup_package_lease(backup_root, maximum_wait_ms, clock, deadline_monotonic_ms)
            .map_err(backup_lease_error)?;

    let backup_database = backup_database_path(backup_root);
    let backup_manifest = backup_manifest_path(backup_root);
    let database_staging = backup_root.path().join(BACKUP_DATABASE_STAGING_FILENAME);
    let manifest_staging = backup_root.path().join(BACKUP_MANIFEST_STAGING_FILENAME);
    if !backup_member_present(&backup_manifest)? {
        if backup_member_present(&database_staging)? || backup_member_present(&manifest_staging)? {
            return Err(ReplayStoreMaintenanceErrorV1::BackupIncomplete);
        }
        return Err(ReplayStoreMaintenanceErrorV1::ManifestMissing);
    }
    if !backup_member_present(&backup_database)? {
        return Err(ReplayStoreMaintenanceErrorV1::BackupIncomplete);
    }
    revalidate_backup_root(backup_root)
        .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;
    maintenance_remaining(clock, deadline_monotonic_ms)?;

    let manifest =
        read_manifest_v1_file(&backup_manifest).map_err(|error| error.to_maintenance())?;
    let digest = sha256_file_hex(&backup_database)
        .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;
    if digest != manifest.database_sha256() {
        return Err(ReplayStoreMaintenanceErrorV1::DatabaseDigestMismatch);
    }

    let source = open_read_only_for_verification(&backup_database)?;
    let summary = verify_full(&source).map_err(|error| error.to_maintenance())?;
    if summary.claimant_generation != manifest.claimant_generation()
        || summary.claim_count != manifest.claim_count()
        || rusqlite::version() != manifest.sqlite_version()
        || read_sqlite_source_id(&source)? != manifest.sqlite_source_id()
    {
        return Err(ReplayStoreMaintenanceErrorV1::ManifestInvalid);
    }
    revalidate_backup_root(backup_root)
        .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;
    maintenance_remaining(clock, deadline_monotonic_ms)?;
    Ok(VerifiedBackupPackageV1 {
        _lease: lease,
        source,
        manifest,
        summary,
    })
}

fn verification_evidence(summary: StoreSummary) -> ReplayStoreVerificationV1 {
    ReplayStoreVerificationV1 {
        claimant_generation: summary.claimant_generation,
        claim_count: summary.claim_count,
    }
}

fn maintenance_remaining<C: ReplayMonotonicClockV1>(
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<u64, ReplayStoreMaintenanceErrorV1> {
    remaining_monotonic_ms(clock, deadline_monotonic_ms).map_err(|error| match error {
        InternalStoreError::ClockUnavailable => ReplayStoreMaintenanceErrorV1::ClockUnavailable,
        _ => ReplayStoreMaintenanceErrorV1::MaintenanceDeadlineReached,
    })
}

fn root_maintenance_error(error: InternalStoreError) -> ReplayStoreMaintenanceErrorV1 {
    match error {
        InternalStoreError::ClockUnavailable => ReplayStoreMaintenanceErrorV1::ClockUnavailable,
        InternalStoreError::DeadlineReached | InternalStoreError::MaintenanceDeadlineReached => {
            ReplayStoreMaintenanceErrorV1::MaintenanceDeadlineReached
        }
        _ => error.to_maintenance(),
    }
}

fn backup_lease_error(error: InternalStoreError) -> ReplayStoreMaintenanceErrorV1 {
    match error {
        InternalStoreError::ClockUnavailable
        | InternalStoreError::DeadlineReached
        | InternalStoreError::MaintenanceDeadlineReached
        | InternalStoreError::StoreBusy
        | InternalStoreError::StoreUnavailable => root_maintenance_error(error),
        _ => ReplayStoreMaintenanceErrorV1::BackupIncomplete,
    }
}

fn backup_member_present(path: &Path) -> Result<bool, ReplayStoreMaintenanceErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ReplayStoreMaintenanceErrorV1::BackupIncomplete),
    }
}

fn rollback_then<T>(
    transaction: rusqlite::Transaction<'_>,
    error: ReplayStoreMaintenanceErrorV1,
) -> Result<T, ReplayStoreMaintenanceErrorV1> {
    transaction
        .rollback()
        .map_err(|_| ReplayStoreMaintenanceErrorV1::StoreUnavailable)?;
    Err(error)
}

fn latch_for_store_failure(healthy: &std::sync::atomic::AtomicBool, error: InternalStoreError) {
    if error.requires_unhealthy_latch() {
        latch_unhealthy(healthy);
    }
}

fn safe_frame_count(value: i64) -> Result<u64, ReplayStoreMaintenanceErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(ReplayStoreMaintenanceErrorV1::InvariantFailed)
}

fn ensure_paths_absent(paths: &[&Path]) -> Result<(), ReplayStoreMaintenanceErrorV1> {
    if paths.iter().any(|path| path.exists()) {
        return Err(ReplayStoreMaintenanceErrorV1::DestinationNotEmpty);
    }
    Ok(())
}

fn open_new_sqlite_database(
    path: &Path,
    failure: ReplayStoreMaintenanceErrorV1,
) -> Result<Connection, ReplayStoreMaintenanceErrorV1> {
    let reservation = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| failure)?;
    reservation.sync_all().map_err(|_| failure)?;
    drop(reservation);
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| failure)
}

fn publish_no_clobber(
    staging: &Path,
    final_path: &Path,
    failure: ReplayStoreMaintenanceErrorV1,
) -> Result<(), ReplayStoreMaintenanceErrorV1> {
    fs::hard_link(staging, final_path).map_err(|_| failure)?;
    sync_file(final_path, failure)?;
    fs::remove_file(staging).map_err(|_| failure)
}

fn open_read_only_for_verification(
    path: &Path,
) -> Result<Connection, ReplayStoreMaintenanceErrorV1> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|()| connection.pragma_update(None, "cell_size_check", "ON"))
        .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;
    Ok(connection)
}

fn run_online_backup<C: ReplayMonotonicClockV1>(
    source: &Connection,
    destination: &mut Connection,
    clock: &C,
    deadline_monotonic_ms: u64,
    pages_per_step: u32,
    retry_wait_ms: u64,
    failure: ReplayStoreMaintenanceErrorV1,
) -> Result<(), ReplayStoreMaintenanceErrorV1> {
    let pages = i32::try_from(pages_per_step).map_err(|_| failure)?;
    let backup = Backup::new(source, destination).map_err(|_| failure)?;
    loop {
        maintenance_remaining(clock, deadline_monotonic_ms)?;
        match backup.step(pages).map_err(|_| failure)? {
            StepResult::Done => break,
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => {
                if retry_wait_ms == 0 {
                    return Err(ReplayStoreMaintenanceErrorV1::StoreBusy);
                }
                let remaining = maintenance_remaining(clock, deadline_monotonic_ms)?;
                if remaining <= retry_wait_ms {
                    return Err(ReplayStoreMaintenanceErrorV1::MaintenanceDeadlineReached);
                }
                thread::sleep(Duration::from_millis(retry_wait_ms));
            }
            _ => return Err(failure),
        }
    }
    maintenance_remaining(clock, deadline_monotonic_ms)?;
    Ok(())
}

fn make_backup_standalone(
    connection: &Connection,
    failure: ReplayStoreMaintenanceErrorV1,
) -> Result<(), ReplayStoreMaintenanceErrorV1> {
    let mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .map_err(|_| failure)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(failure);
    }
    Ok(())
}

fn read_sqlite_source_id(connection: &Connection) -> Result<String, ReplayStoreMaintenanceErrorV1> {
    connection
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)
}

fn sync_file(
    path: &Path,
    failure: ReplayStoreMaintenanceErrorV1,
) -> Result<(), ReplayStoreMaintenanceErrorV1> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| failure)
}

fn write_new_synced_file(
    path: &Path,
    contents: &[u8],
) -> Result<(), ReplayStoreMaintenanceErrorV1> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| ReplayStoreMaintenanceErrorV1::BackupIncomplete)
}
