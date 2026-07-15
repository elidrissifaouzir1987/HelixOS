//! Paused, quiescent online backup for the independent dispatch inbox.
//!
//! The component backup is independently coherent. It is not a cross-store snapshot and
//! does not publish a top-level backup package; the coordinator-side maintenance workflow
//! binds this artifact to its own independently completed backup and publishes the signed
//! index last.

use crate::config::{AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1};
use crate::connection;
use crate::inbox::SqliteDispatchInboxStoreV1;
use crate::manifest::{
    decode_adapter_inbox_backup_manifest_v1, finalize_adapter_inbox_backup_manifest_v1,
    AdapterCountsInputV1, AdapterGenerationsInputV1, AdapterInboxBackupManifestInputV1,
    AdapterInventoriesInputV1, BackupRootLifecycleStateV1,
};
use crate::root_safety::{
    bind_initializing_restore_root_v1, ensure_restore_initializing_marker,
    initialization_database_present, reserve_database_file, sync_root_directory,
    AdapterInitializingRestoreRootCustodyV1,
};
use crate::schema::{
    self, AdapterInboxStoreSummaryV1, AdapterRestorePendingBindingsV1, AdapterRootLifecycleStateV1,
};
#[cfg(feature = "test-fault-injection")]
use crate::test_fault::{AdapterDispatchRestoreFaultProbeV1, FaultBoundaryV1};
use helix_dispatch_contracts::{SignedExecutionGrantV1, SignedExecutionReceiptV1};
use rusqlite::backup::{Backup, StepResult};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const MAX_SAFE_INTEGER_V1: u64 = 9_007_199_254_740_991;
const BACKUP_PAGES_PER_STEP_V1: i32 = 64;
const MAX_BACKUP_STEPS_V1: usize = 1_000_000;
const MAX_BACKUP_BUSY_STEPS_V1: usize = 64;
const MAX_BACKUP_DATABASE_BYTES_V1: u64 = 256 * 1024 * 1024;
const ADAPTER_ROOT_DIGEST_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-BACKUP\0ADAPTER-ROOT\0V1\0";
const ADAPTER_PAUSE_EVIDENCE_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-BACKUP\0ADAPTER-PAUSE\0V1\0";
const ADAPTER_QUIESCENCE_EVIDENCE_DOMAIN_V1: &[u8] =
    b"HELIXOS\0DISPATCH-BACKUP\0ADAPTER-QUIESCENCE\0V1\0";
const TABLE_INVENTORY_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-BACKUP\0TABLE-INVENTORY\0V1\0";
const COMPLETE_STORE_INVENTORY_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-BACKUP\0COMPLETE-STORE\0V1\0";
const ADAPTER_RESTORE_PAUSE_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-RESTORE\0ADAPTER-PAUSE\0V1\0";
const ADAPTER_RESTORE_SOURCE_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-RESTORE\0ADAPTER-SOURCE\0V1\0";
const ADAPTER_RESTORE_ATTEMPT_DOMAIN_V1: &[u8] =
    b"HELIXOS\0DISPATCH-RESTORE\0ADAPTER-ATTEMPT\0V1\0";
const RESTORE_COPY_BUFFER_BYTES_V1: usize = 64 * 1024;

const ADAPTER_DATABASE_STAGING_V1: &str = "adapter-inbox.sqlite3.staging";
const ADAPTER_MANIFEST_STAGING_V1: &str = "adapter-inbox-manifest.json.staging";
const ADAPTER_COMPLETE_STAGING_V1: &str = "adapter-inbox-component.complete.staging";
const ADAPTER_DATABASE_PUBLISHED_V1: &str = "adapter-inbox.sqlite3";
const ADAPTER_MANIFEST_PUBLISHED_V1: &str = "adapter-inbox-manifest.json";
const ADAPTER_COMPLETE_PUBLISHED_V1: &str = "adapter-inbox-component.complete";

const ADAPTER_INVENTORY_TABLES_V1: &[(&str, &str)] = &[
    ("grant_inbox", "grant_id"),
    ("inbox_transitions", "transition_generation"),
    ("execution_receipts", "receipt_id"),
    ("inbox_conflicts", "conflict_id"),
    ("inbox_quarantines", "quarantine_id"),
    ("adapter_events", "event_id"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterDispatchBackupErrorV1 {
    PauseContended,
    PauseUnavailable,
    PauseDeadlineReached,
    PauseUnsupported,
    PauseChanged,
    StoreUnavailable,
    StoreInvalid,
    DestinationExists,
    DestinationUnavailable,
    BackupFailed,
    IntegrityFailed,
    ManifestInvalid,
    PublicationFailed,
}

impl AdapterDispatchBackupErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PauseContended => "PAUSE_CONTENDED",
            Self::PauseUnavailable => "PAUSE_UNAVAILABLE",
            Self::PauseDeadlineReached => "PAUSE_DEADLINE_REACHED",
            Self::PauseUnsupported => "PAUSE_UNSUPPORTED",
            Self::PauseChanged => "PAUSE_CHANGED",
            Self::StoreUnavailable => "STORE_UNAVAILABLE",
            Self::StoreInvalid => "STORE_INVALID",
            Self::DestinationExists => "DESTINATION_EXISTS",
            Self::DestinationUnavailable => "DESTINATION_UNAVAILABLE",
            Self::BackupFailed => "BACKUP_FAILED",
            Self::IntegrityFailed => "INTEGRITY_FAILED",
            Self::ManifestInvalid => "MANIFEST_INVALID",
            Self::PublicationFailed => "PUBLICATION_FAILED",
        }
    }
}

impl fmt::Display for AdapterDispatchBackupErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterDispatchBackupErrorV1 {}

/// Closed, payload-free adapter restore rejection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterDispatchRestoreErrorV1 {
    PauseChanged,
    SourceInvalid,
    SourceChanged,
    SourceTooLarge,
    DestinationInvalid,
    DestinationConflict,
    DestinationUnavailable,
    AuthorityInvalid,
    StoreInvalid,
    IntegrityFailed,
    PublicationFailed,
    FaultInjected,
}

impl AdapterDispatchRestoreErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PauseChanged => "PAUSE_CHANGED",
            Self::SourceInvalid => "SOURCE_INVALID",
            Self::SourceChanged => "SOURCE_CHANGED",
            Self::SourceTooLarge => "SOURCE_TOO_LARGE",
            Self::DestinationInvalid => "DESTINATION_INVALID",
            Self::DestinationConflict => "DESTINATION_CONFLICT",
            Self::DestinationUnavailable => "DESTINATION_UNAVAILABLE",
            Self::AuthorityInvalid => "AUTHORITY_INVALID",
            Self::StoreInvalid => "STORE_INVALID",
            Self::IntegrityFailed => "INTEGRITY_FAILED",
            Self::PublicationFailed => "PUBLICATION_FAILED",
            Self::FaultInjected => "FAULT_INJECTED",
        }
    }
}

impl fmt::Display for AdapterDispatchRestoreErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterDispatchRestoreErrorV1 {}

/// Signed-manifest generation projection required to verify one ACTIVE adapter source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterDispatchRestoreGenerationsV1 {
    store: u64,
    inbox: u64,
    consumption: u64,
    receipt: u64,
    conflict: u64,
    quarantine: u64,
    event: u64,
    epoch_observer: u64,
    restore_state: u64,
}

impl AdapterDispatchRestoreGenerationsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        store: u64,
        inbox: u64,
        consumption: u64,
        receipt: u64,
        conflict: u64,
        quarantine: u64,
        event: u64,
        epoch_observer: u64,
        restore_state: u64,
    ) -> Result<Self, AdapterDispatchRestoreErrorV1> {
        if [
            store,
            inbox,
            consumption,
            receipt,
            conflict,
            quarantine,
            event,
        ]
        .into_iter()
        .any(|value| value > MAX_SAFE_INTEGER_V1)
            || [inbox, consumption, receipt, conflict, quarantine, event]
                .into_iter()
                .any(|value| value > store)
            || !(1..=MAX_SAFE_INTEGER_V1).contains(&epoch_observer)
            || restore_state != 0
        {
            return Err(AdapterDispatchRestoreErrorV1::SourceInvalid);
        }
        Ok(Self {
            store,
            inbox,
            consumption,
            receipt,
            conflict,
            quarantine,
            event,
            epoch_observer,
            restore_state,
        })
    }
}

impl fmt::Debug for AdapterDispatchRestoreGenerationsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterDispatchRestoreGenerationsV1")
            .finish_non_exhaustive()
    }
}

/// Signed-manifest table counts for one immutable adapter source cut.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterDispatchRestoreCountsV1 {
    inbox_entries: u64,
    transitions: u64,
    receipts: u64,
    conflicts: u64,
    quarantines: u64,
    events: u64,
}

impl AdapterDispatchRestoreCountsV1 {
    pub fn try_new(
        inbox_entries: u64,
        transitions: u64,
        receipts: u64,
        conflicts: u64,
        quarantines: u64,
        events: u64,
    ) -> Result<Self, AdapterDispatchRestoreErrorV1> {
        if [
            inbox_entries,
            transitions,
            receipts,
            conflicts,
            quarantines,
            events,
        ]
        .into_iter()
        .any(|value| value > MAX_SAFE_INTEGER_V1)
        {
            return Err(AdapterDispatchRestoreErrorV1::SourceInvalid);
        }
        Ok(Self {
            inbox_entries,
            transitions,
            receipts,
            conflicts,
            quarantines,
            events,
        })
    }
}

impl fmt::Debug for AdapterDispatchRestoreCountsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterDispatchRestoreCountsV1")
            .finish_non_exhaustive()
    }
}

/// Signed-manifest inventory digests for the six permanent adapter histories.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterDispatchRestoreInventoriesV1 {
    inbox_entries: [u8; 32],
    transitions: [u8; 32],
    receipts: [u8; 32],
    conflicts: [u8; 32],
    quarantines: [u8; 32],
    events: [u8; 32],
    complete_store: [u8; 32],
}

impl AdapterDispatchRestoreInventoriesV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        inbox_entries: [u8; 32],
        transitions: [u8; 32],
        receipts: [u8; 32],
        conflicts: [u8; 32],
        quarantines: [u8; 32],
        events: [u8; 32],
        complete_store: [u8; 32],
    ) -> Self {
        Self {
            inbox_entries,
            transitions,
            receipts,
            conflicts,
            quarantines,
            events,
            complete_store,
        }
    }
}

impl fmt::Debug for AdapterDispatchRestoreInventoriesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterDispatchRestoreInventoriesV1")
            .finish_non_exhaustive()
    }
}

/// Exact signed source bindings projected by the cross-store package verifier.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterDispatchRestoreSourceBindingsV1 {
    source_root_identity: AdapterInboxRootIdentityEvidenceV1,
    expected_root_identity_digest: [u8; 32],
    source_supervisor_epoch: u64,
    generations: AdapterDispatchRestoreGenerationsV1,
    counts: AdapterDispatchRestoreCountsV1,
    inventories: AdapterDispatchRestoreInventoriesV1,
}

impl AdapterDispatchRestoreSourceBindingsV1 {
    pub fn try_new(
        source_root_identity: AdapterInboxRootIdentityEvidenceV1,
        expected_root_identity_digest: [u8; 32],
        source_supervisor_epoch: u64,
        generations: AdapterDispatchRestoreGenerationsV1,
        counts: AdapterDispatchRestoreCountsV1,
        inventories: AdapterDispatchRestoreInventoriesV1,
    ) -> Result<Self, AdapterDispatchRestoreErrorV1> {
        let actual_root_digest = domain_digest(
            ADAPTER_ROOT_DIGEST_DOMAIN_V1,
            &[&source_root_identity.to_attested_bytes()],
        );
        if source_root_identity.to_attested_bytes() == [0; 32]
            || expected_root_identity_digest == [0; 32]
            || source_supervisor_epoch > MAX_SAFE_INTEGER_V1
            || actual_root_digest != expected_root_identity_digest
        {
            return Err(AdapterDispatchRestoreErrorV1::SourceInvalid);
        }
        Ok(Self {
            source_root_identity,
            expected_root_identity_digest,
            source_supervisor_epoch,
            generations,
            counts,
            inventories,
        })
    }
}

impl fmt::Debug for AdapterDispatchRestoreSourceBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterDispatchRestoreSourceBindingsV1")
            .finish_non_exhaustive()
    }
}

/// Read-only, byte-bounded adapter database member retained by the package owner.
pub struct ProvisionedAdapterDispatchRestoreSourceV1 {
    file: File,
    database_length: u64,
    database_sha256: [u8; 32],
    source_binding_sha256: [u8; 32],
    bindings: AdapterDispatchRestoreSourceBindingsV1,
}

impl ProvisionedAdapterDispatchRestoreSourceV1 {
    pub fn try_new(
        mut file: File,
        database_length: u64,
        database_sha256: [u8; 32],
        bindings: AdapterDispatchRestoreSourceBindingsV1,
    ) -> Result<Self, AdapterDispatchRestoreErrorV1> {
        let metadata = file
            .metadata()
            .map_err(|_| AdapterDispatchRestoreErrorV1::SourceInvalid)?;
        if !metadata.is_file()
            || metadata.len() != database_length
            || !(1..=MAX_BACKUP_DATABASE_BYTES_V1).contains(&database_length)
        {
            return Err(if database_length > MAX_BACKUP_DATABASE_BYTES_V1 {
                AdapterDispatchRestoreErrorV1::SourceTooLarge
            } else {
                AdapterDispatchRestoreErrorV1::SourceInvalid
            });
        }
        if hash_restore_source_handle_v1(&mut file, database_length)? != database_sha256 {
            return Err(AdapterDispatchRestoreErrorV1::SourceInvalid);
        }
        let source_binding_sha256 = domain_digest(
            ADAPTER_RESTORE_SOURCE_DOMAIN_V1,
            &[
                &database_sha256,
                &database_length.to_be_bytes(),
                &bindings.expected_root_identity_digest,
            ],
        );
        Ok(Self {
            file,
            database_length,
            database_sha256,
            source_binding_sha256,
            bindings,
        })
    }

    fn revalidate_v1(&mut self) -> Result<(), AdapterDispatchRestoreErrorV1> {
        let metadata = self
            .file
            .metadata()
            .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
        if !metadata.is_file()
            || metadata.len() != self.database_length
            || hash_restore_source_handle_v1(&mut self.file, self.database_length)?
                != self.database_sha256
        {
            return Err(AdapterDispatchRestoreErrorV1::SourceChanged);
        }
        Ok(())
    }

    fn copy_to_v1(&mut self, destination: &mut File) -> Result<(), AdapterDispatchRestoreErrorV1> {
        self.revalidate_v1()?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
        destination
            .seek(SeekFrom::Start(0))
            .and_then(|_| destination.set_len(0))
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
        let mut remaining = self.database_length;
        let mut buffer = [0_u8; RESTORE_COPY_BUFFER_BYTES_V1];
        let mut hasher = Sha256::new();
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| AdapterDispatchRestoreErrorV1::SourceTooLarge)?;
            self.file
                .read_exact(&mut buffer[..wanted])
                .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
            destination
                .write_all(&buffer[..wanted])
                .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
            hasher.update(&buffer[..wanted]);
            remaining -= wanted as u64;
        }
        let mut trailing = [0_u8; 1];
        if self
            .file
            .read(&mut trailing)
            .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?
            != 0
            || <[u8; 32]>::from(hasher.finalize()) != self.database_sha256
        {
            return Err(AdapterDispatchRestoreErrorV1::SourceChanged);
        }
        destination
            .sync_all()
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
        self.revalidate_v1()
    }
}

impl fmt::Debug for ProvisionedAdapterDispatchRestoreSourceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedAdapterDispatchRestoreSourceV1")
            .finish_non_exhaustive()
    }
}

/// Adapter slice of the live sovereign PAUSE and rotated supervisor authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterPausedDispatchRestoreV1 {
    source_root_identity: AdapterInboxRootIdentityEvidenceV1,
    new_root_identity: AdapterInboxRootIdentityEvidenceV1,
    source_supervisor_identity: [u8; 32],
    new_supervisor_identity: [u8; 32],
    source_supervisor_epoch: u64,
    new_supervisor_epoch: u64,
    source_epoch_observer_generation: u64,
    new_epoch_observer_generation: u64,
    restore_index_digest: [u8; 32],
    pause_generation: u64,
    fencing_generation: u64,
    pause_evidence_digest: [u8; 32],
}

impl AdapterPausedDispatchRestoreV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        source_root_identity: AdapterInboxRootIdentityEvidenceV1,
        new_root_identity: AdapterInboxRootIdentityEvidenceV1,
        source_supervisor_identity: [u8; 32],
        new_supervisor_identity: [u8; 32],
        source_supervisor_epoch: u64,
        new_supervisor_epoch: u64,
        source_epoch_observer_generation: u64,
        new_epoch_observer_generation: u64,
        restore_index_digest: [u8; 32],
        pause_generation: u64,
        fencing_generation: u64,
    ) -> Result<Self, AdapterDispatchRestoreErrorV1> {
        if source_root_identity.to_attested_bytes() == [0; 32]
            || new_root_identity.to_attested_bytes() == [0; 32]
            || source_root_identity == new_root_identity
            || source_supervisor_identity == [0; 32]
            || new_supervisor_identity == [0; 32]
            || source_supervisor_identity == new_supervisor_identity
            || restore_index_digest == [0; 32]
            || source_supervisor_epoch > MAX_SAFE_INTEGER_V1
            || new_supervisor_epoch > MAX_SAFE_INTEGER_V1
            || new_supervisor_epoch <= source_supervisor_epoch
            || source_epoch_observer_generation > MAX_SAFE_INTEGER_V1
            || new_epoch_observer_generation > MAX_SAFE_INTEGER_V1
            || new_epoch_observer_generation <= source_epoch_observer_generation
            || !(1..=MAX_SAFE_INTEGER_V1).contains(&pause_generation)
            || !(1..=MAX_SAFE_INTEGER_V1).contains(&fencing_generation)
        {
            return Err(AdapterDispatchRestoreErrorV1::AuthorityInvalid);
        }
        let pause_evidence_digest = domain_digest(
            ADAPTER_RESTORE_PAUSE_DOMAIN_V1,
            &[
                &source_root_identity.to_attested_bytes(),
                &new_root_identity.to_attested_bytes(),
                &source_supervisor_identity,
                &new_supervisor_identity,
                &source_supervisor_epoch.to_be_bytes(),
                &new_supervisor_epoch.to_be_bytes(),
                &source_epoch_observer_generation.to_be_bytes(),
                &new_epoch_observer_generation.to_be_bytes(),
                &restore_index_digest,
                &pause_generation.to_be_bytes(),
                &fencing_generation.to_be_bytes(),
            ],
        );
        Ok(Self {
            source_root_identity,
            new_root_identity,
            source_supervisor_identity,
            new_supervisor_identity,
            source_supervisor_epoch,
            new_supervisor_epoch,
            source_epoch_observer_generation,
            new_epoch_observer_generation,
            restore_index_digest,
            pause_generation,
            fencing_generation,
            pause_evidence_digest,
        })
    }

    pub const fn pause_evidence_digest(self) -> [u8; 32] {
        self.pause_evidence_digest
    }

    pub const fn source_root_identity(self) -> AdapterInboxRootIdentityEvidenceV1 {
        self.source_root_identity
    }

    pub const fn restore_index_digest(self) -> [u8; 32] {
        self.restore_index_digest
    }

    pub const fn new_root_identity(self) -> AdapterInboxRootIdentityEvidenceV1 {
        self.new_root_identity
    }

    pub const fn new_supervisor_epoch(self) -> u64 {
        self.new_supervisor_epoch
    }

    pub const fn source_supervisor_identity(self) -> [u8; 32] {
        self.source_supervisor_identity
    }

    pub const fn new_supervisor_identity(self) -> [u8; 32] {
        self.new_supervisor_identity
    }

    pub const fn source_supervisor_epoch(self) -> u64 {
        self.source_supervisor_epoch
    }

    pub const fn source_epoch_observer_generation(self) -> u64 {
        self.source_epoch_observer_generation
    }

    pub const fn new_epoch_observer_generation(self) -> u64 {
        self.new_epoch_observer_generation
    }

    pub const fn pause_generation(self) -> u64 {
        self.pause_generation
    }

    pub const fn fencing_generation(self) -> u64 {
        self.fencing_generation
    }

    pub const fn control_state_code(self) -> &'static str {
        "PAUSED"
    }
}

impl fmt::Debug for AdapterPausedDispatchRestoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterPausedDispatchRestoreV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterDispatchRestorePauseValidationV1 {
    Exact,
    Revoked,
    Unavailable,
    Unhealthy,
}

/// Redacted fresh-or-retry observation of one provisioner-attested adapter root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterDispatchRestoreDestinationEvidenceV1 {
    entry_count: u64,
}

impl AdapterDispatchRestoreDestinationEvidenceV1 {
    pub const fn entry_count(self) -> u64 {
        self.entry_count
    }

    pub const fn is_fresh(self) -> bool {
        self.entry_count == 0
    }

    pub const fn is_retry(self) -> bool {
        self.entry_count != 0
    }
}

/// Rescans one attested root without exposing its path or member names.
pub fn inspect_adapter_dispatch_restore_destination_v1(
    destination: &AdapterInboxStoreConfigV1,
) -> Result<AdapterDispatchRestoreDestinationEvidenceV1, AdapterDispatchRestoreErrorV1> {
    revalidate_restore_destination_v1(destination)?;
    let entry_count = fs::read_dir(destination.root_path())
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?
        .try_fold(0_u64, |count, entry| {
            entry.map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
            count
                .checked_add(1)
                .filter(|value| *value <= 4)
                .ok_or(AdapterDispatchRestoreErrorV1::DestinationInvalid)
        })?;
    revalidate_restore_destination_v1(destination)?;
    Ok(AdapterDispatchRestoreDestinationEvidenceV1 { entry_count })
}

/// Caller-owned custody that keeps the new supervisor fenced throughout both local commits.
pub trait AdapterDispatchRestorePauseCustodyV1: Send {
    fn recheck_paused_dispatch_restore_v1(
        &mut self,
        expected: &AdapterPausedDispatchRestoreV1,
    ) -> AdapterDispatchRestorePauseValidationV1;

    fn release(self);
}

enum PreparedAdapterDispatchRestoreRootV1 {
    Initializing(AdapterInitializingRestoreRootCustodyV1),
    Existing,
}

/// Prepared adapter copy retained without committing or publishing new authority.
pub struct PreparedAdapterDispatchRestoreV1 {
    destination: AdapterInboxStoreConfigV1,
    root: PreparedAdapterDispatchRestoreRootV1,
    source_summary: AdapterInboxStoreSummaryV1,
    source_inventory: SourceInventoryEvidenceV1,
    source_bindings: AdapterDispatchRestoreSourceBindingsV1,
    paused: AdapterPausedDispatchRestoreV1,
    database_sha256: [u8; 32],
    database_length: u64,
    source_binding_sha256: [u8; 32],
    initial_destination_entry_count: u64,
    already_pending: bool,
}

impl fmt::Debug for PreparedAdapterDispatchRestoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAdapterDispatchRestoreV1")
            .finish_non_exhaustive()
    }
}

/// Redacted, non-authoritative proof of one exact pending adapter restore.
pub struct VerifiedAdapterDispatchRestoreV1 {
    root_identity: AdapterInboxRootIdentityEvidenceV1,
    store_generation: u64,
    inbox_count: u64,
    receipt_count: u64,
    source_inventory_digest: [u8; 32],
    restored_inventory_digest: [u8; 32],
    restore_index_digest: [u8; 32],
    pause_evidence_digest: [u8; 32],
    automatic_consumption_count: u64,
    automatic_redelivery_count: u64,
    possible_consumption_quarantine_count: u64,
    reconciliation_required_count: u64,
    reconciliation_grant_set_digest: [u8; 32],
    reconciliation_grant_ids: Box<[[u8; 32]]>,
    initial_destination_entry_count: u64,
}

impl VerifiedAdapterDispatchRestoreV1 {
    pub const fn root_identity(&self) -> AdapterInboxRootIdentityEvidenceV1 {
        self.root_identity
    }

    pub const fn store_generation(&self) -> u64 {
        self.store_generation
    }

    pub const fn inbox_count(&self) -> u64 {
        self.inbox_count
    }

    pub const fn receipt_count(&self) -> u64 {
        self.receipt_count
    }

    pub const fn source_inventory_digest(&self) -> [u8; 32] {
        self.source_inventory_digest
    }

    pub const fn restored_inventory_digest(&self) -> [u8; 32] {
        self.restored_inventory_digest
    }

    pub const fn restore_index_digest(&self) -> [u8; 32] {
        self.restore_index_digest
    }

    pub const fn pause_evidence_digest(&self) -> [u8; 32] {
        self.pause_evidence_digest
    }

    pub const fn automatic_consumption_count(&self) -> u64 {
        self.automatic_consumption_count
    }

    pub const fn automatic_redelivery_count(&self) -> u64 {
        self.automatic_redelivery_count
    }

    pub const fn possible_consumption_quarantine_count(&self) -> u64 {
        self.possible_consumption_quarantine_count
    }

    pub const fn reconciliation_required_count(&self) -> u64 {
        self.reconciliation_required_count
    }

    /// Canonical digest of the sorted grant identifiers covered by restore-only proofs.
    pub const fn reconciliation_grant_set_digest(&self) -> [u8; 32] {
        self.reconciliation_grant_set_digest
    }

    /// Sorted grant identifiers for private provider-side subset verification.
    pub fn reconciliation_grant_ids(&self) -> &[[u8; 32]] {
        &self.reconciliation_grant_ids
    }

    pub const fn initial_destination_entry_count(&self) -> u64 {
        self.initial_destination_entry_count
    }

    pub const fn root_lifecycle_code(&self) -> &'static str {
        "RESTORE_PENDING"
    }

    pub const fn control_state_code(&self) -> &'static str {
        "PAUSED"
    }
}

impl fmt::Debug for VerifiedAdapterDispatchRestoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAdapterDispatchRestoreV1")
            .field("store_generation", &self.store_generation)
            .field("inbox_count", &self.inbox_count)
            .field("receipt_count", &self.receipt_count)
            .field(
                "automatic_consumption_count",
                &self.automatic_consumption_count,
            )
            .field(
                "automatic_redelivery_count",
                &self.automatic_redelivery_count,
            )
            .field(
                "possible_consumption_quarantine_count",
                &self.possible_consumption_quarantine_count,
            )
            .field(
                "reconciliation_required_count",
                &self.reconciliation_required_count,
            )
            .field(
                "initial_destination_entry_count",
                &self.initial_destination_entry_count,
            )
            .finish_non_exhaustive()
    }
}

/// Installs and verifies the adapter database copy while retaining the INITIALIZING root.
/// The caller keeps the same PAUSE custody for the later local commit.
pub fn prepare_adapter_dispatch_restore_v1<C: AdapterDispatchRestorePauseCustodyV1>(
    custody: &mut C,
    paused: AdapterPausedDispatchRestoreV1,
    source: ProvisionedAdapterDispatchRestoreSourceV1,
    destination: AdapterInboxStoreConfigV1,
) -> Result<PreparedAdapterDispatchRestoreV1, AdapterDispatchRestoreErrorV1> {
    prepare_adapter_dispatch_restore_with_checkpoint_v1(
        custody,
        paused,
        source,
        destination,
        || Ok(()),
    )
}

/// Feature-gated selector for the real adapter restore-copy checkpoint.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)] // Closed test seam carries the complete portable selector.
pub fn prepare_adapter_dispatch_restore_with_fault_for_test_v1<C, F>(
    custody: &mut C,
    paused: AdapterPausedDispatchRestoreV1,
    source: ProvisionedAdapterDispatchRestoreSourceV1,
    destination: AdapterInboxStoreConfigV1,
    boundary_id: &str,
    occurrence: u64,
    mode: helix_plan_dispatch::FaultInjectionModeV1,
    process_barrier: F,
) -> Result<PreparedAdapterDispatchRestoreV1, AdapterDispatchRestoreErrorV1>
where
    C: AdapterDispatchRestorePauseCustodyV1,
    F: FnMut() + Send + 'static,
{
    let probe = AdapterDispatchRestoreFaultProbeV1::select_id_v1(
        boundary_id,
        occurrence,
        mode,
        process_barrier,
    )
    .map_err(|_| AdapterDispatchRestoreErrorV1::FaultInjected)?;
    prepare_adapter_dispatch_restore_with_checkpoint_v1(
        custody,
        paused,
        source,
        destination,
        || {
            probe
                .checkpoint_v1()
                .map_err(|_| AdapterDispatchRestoreErrorV1::FaultInjected)
        },
    )
}

fn prepare_adapter_dispatch_restore_with_checkpoint_v1<C, F>(
    custody: &mut C,
    paused: AdapterPausedDispatchRestoreV1,
    mut source: ProvisionedAdapterDispatchRestoreSourceV1,
    destination: AdapterInboxStoreConfigV1,
    reach_restore_copy_checkpoint: F,
) -> Result<PreparedAdapterDispatchRestoreV1, AdapterDispatchRestoreErrorV1>
where
    C: AdapterDispatchRestorePauseCustodyV1,
    F: FnOnce() -> Result<(), AdapterDispatchRestoreErrorV1>,
{
    recheck_restore_pause_v1(custody, &paused)?;
    let initial_destination = inspect_adapter_dispatch_restore_destination_v1(&destination)?;
    validate_restore_authority_bindings_v1(&source.bindings, &destination, &paused)?;
    source.revalidate_v1()?;
    let expected_source = expected_source_summary_v1(&source.bindings);
    let pending_bindings = pending_schema_bindings_v1(expected_source, paused)?;

    if destination.existing_root().is_some() {
        let opened = connection::open_existing(destination.clone())
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
        let pending = schema::verify_restore_pending_v1(opened.connection(), pending_bindings)
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
        let source_inventory = capture_adapter_source_inventory_v1(
            opened.connection(),
            source.bindings.generations.quarantine,
        )
        .map_err(map_backup_to_restore_error_v1)?;
        verify_source_inventory_v1(&source_inventory, &source.bindings)?;
        let restored_inventory = capture_adapter_inventory_v1(opened.connection())
            .map_err(map_backup_to_restore_error_v1)?;
        verify_restore_additions_v1(&restored_inventory, &source_inventory, &pending)?;
        drop(opened);
        source.revalidate_v1()?;
        recheck_restore_pause_v1(custody, &paused)?;
        return Ok(PreparedAdapterDispatchRestoreV1 {
            destination,
            root: PreparedAdapterDispatchRestoreRootV1::Existing,
            source_summary: expected_source,
            source_inventory,
            source_bindings: source.bindings,
            paused,
            database_sha256: source.database_sha256,
            database_length: source.database_length,
            source_binding_sha256: source.source_binding_sha256,
            initial_destination_entry_count: initial_destination.entry_count,
            already_pending: true,
        });
    }

    let empty_root = destination
        .empty_root()
        .ok_or(AdapterDispatchRestoreErrorV1::DestinationInvalid)?;
    let restore_attempt_digest = domain_digest(
        ADAPTER_RESTORE_ATTEMPT_DOMAIN_V1,
        &[&source.source_binding_sha256, &paused.pause_evidence_digest],
    );
    ensure_restore_initializing_marker(empty_root, restore_attempt_digest)
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationInvalid)?;
    let database_present = initialization_database_present(empty_root)
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationInvalid)?;
    let copied_now = !database_present;
    if copied_now {
        let mut reservation = reserve_database_file(empty_root)
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
        source.copy_to_v1(&mut reservation)?;
        drop(reservation);
        sync_root_directory(destination.root_path())
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
    }

    let connection = open_initializing_restore_connection_v1(&destination)?;
    let (source_inventory, already_pending) = match schema::verify_full(
        &connection,
        source.bindings.source_root_identity.into_internal(),
    ) {
        Ok(summary)
            if summary == expected_source
                && summary.root_lifecycle_state == AdapterRootLifecycleStateV1::Active =>
        {
            let inventory = capture_adapter_inventory_v1(&connection)
                .map_err(map_backup_to_restore_error_v1)?;
            let source_inventory = inventory.source_evidence_v1();
            verify_source_inventory_v1(&source_inventory, &source.bindings)?;
            (source_inventory, false)
        }
        _ => {
            let pending = schema::verify_restore_pending_v1(&connection, pending_bindings)
                .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
            let source_inventory = capture_adapter_source_inventory_v1(
                &connection,
                source.bindings.generations.quarantine,
            )
            .map_err(map_backup_to_restore_error_v1)?;
            verify_source_inventory_v1(&source_inventory, &source.bindings)?;
            let restored_inventory = capture_adapter_inventory_v1(&connection)
                .map_err(map_backup_to_restore_error_v1)?;
            verify_restore_additions_v1(&restored_inventory, &source_inventory, &pending)?;
            (source_inventory, true)
        }
    };
    drop(connection);
    source.revalidate_v1()?;
    let root = bind_initializing_restore_root_v1(empty_root, restore_attempt_digest)
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
    root.revalidate_v1()
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
    recheck_restore_pause_v1(custody, &paused)?;
    if copied_now {
        reach_restore_copy_checkpoint()?;
    }

    Ok(PreparedAdapterDispatchRestoreV1 {
        destination,
        root: PreparedAdapterDispatchRestoreRootV1::Initializing(root),
        source_summary: expected_source,
        source_inventory,
        source_bindings: source.bindings,
        paused,
        database_sha256: source.database_sha256,
        database_length: source.database_length,
        source_binding_sha256: source.source_binding_sha256,
        initial_destination_entry_count: initial_destination.entry_count,
        already_pending,
    })
}

/// Commits the independently owned adapter transition, publishes its marker and reopens it.
pub fn commit_adapter_dispatch_restore_to_pending_v1<C: AdapterDispatchRestorePauseCustodyV1>(
    custody: &mut C,
    prepared: PreparedAdapterDispatchRestoreV1,
) -> Result<VerifiedAdapterDispatchRestoreV1, AdapterDispatchRestoreErrorV1> {
    let PreparedAdapterDispatchRestoreV1 {
        destination,
        root,
        source_summary,
        source_inventory,
        source_bindings,
        paused,
        database_sha256,
        database_length,
        source_binding_sha256,
        initial_destination_entry_count,
        already_pending,
    } = prepared;
    recheck_restore_pause_v1(custody, &paused)?;
    let repeated_source_binding = domain_digest(
        ADAPTER_RESTORE_SOURCE_DOMAIN_V1,
        &[
            &database_sha256,
            &database_length.to_be_bytes(),
            &source_bindings.expected_root_identity_digest,
        ],
    );
    if repeated_source_binding != source_binding_sha256 {
        return Err(AdapterDispatchRestoreErrorV1::SourceChanged);
    }
    let pending_bindings = pending_schema_bindings_v1(source_summary, paused)?;

    let destination = match root {
        PreparedAdapterDispatchRestoreRootV1::Initializing(root) => {
            root.revalidate_v1()
                .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
            if root
                .database_path_v1()
                .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?
                != destination.database_path()
            {
                return Err(AdapterDispatchRestoreErrorV1::DestinationConflict);
            }
            let mut connection = open_initializing_restore_connection_v1(&destination)?;
            let pending = if already_pending {
                schema::verify_restore_pending_v1(&connection, pending_bindings)
                    .map_err(|_| AdapterDispatchRestoreErrorV1::StoreInvalid)?
            } else {
                schema::transition_imported_backup_to_restore_pending_v1(
                    &mut connection,
                    pending_bindings,
                )
                .map_err(|_| AdapterDispatchRestoreErrorV1::StoreInvalid)?
            };
            let committed_source = capture_adapter_source_inventory_v1(
                &connection,
                source_bindings.generations.quarantine,
            )
            .map_err(map_backup_to_restore_error_v1)?;
            verify_source_inventory_v1(&committed_source, &source_bindings)?;
            if committed_source != source_inventory {
                return Err(AdapterDispatchRestoreErrorV1::IntegrityFailed);
            }
            let committed = capture_adapter_inventory_v1(&connection)
                .map_err(map_backup_to_restore_error_v1)?;
            verify_restore_additions_v1(&committed, &source_inventory, &pending)?;
            drop(connection);
            sync_root_directory(destination.root_path())
                .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
            root.revalidate_v1()
                .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
            recheck_restore_pause_v1(custody, &paused)?;
            let published = root
                .publish_existing_v1()
                .map_err(|_| AdapterDispatchRestoreErrorV1::PublicationFailed)?;
            published
                .revalidate()
                .map_err(|_| AdapterDispatchRestoreErrorV1::PublicationFailed)?;
            destination
                .into_existing()
                .map_err(|_| AdapterDispatchRestoreErrorV1::PublicationFailed)?
        }
        PreparedAdapterDispatchRestoreRootV1::Existing => destination,
    };

    recheck_restore_pause_v1(custody, &paused)?;
    let reopened = connection::open_existing(destination)
        .map_err(|_| AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    let verified = schema::verify_restore_pending_v1(reopened.connection(), pending_bindings)
        .map_err(|_| AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    let reopened_source = capture_adapter_source_inventory_v1(
        reopened.connection(),
        source_bindings.generations.quarantine,
    )
    .map_err(map_backup_to_restore_error_v1)?;
    verify_source_inventory_v1(&reopened_source, &source_bindings)?;
    if reopened_source != source_inventory {
        return Err(AdapterDispatchRestoreErrorV1::IntegrityFailed);
    }
    let final_inventory = capture_adapter_inventory_v1(reopened.connection())
        .map_err(map_backup_to_restore_error_v1)?;
    verify_restore_additions_v1(&final_inventory, &source_inventory, &verified)?;
    let summary = verified.summary();
    let automatic_consumption_count = summary
        .consumption_generation
        .checked_sub(source_summary.consumption_generation)
        .ok_or(AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    let receipt_generation_delta = summary
        .receipt_generation
        .checked_sub(source_summary.receipt_generation)
        .ok_or(AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    let inbox_generation_delta = summary
        .inbox_generation
        .checked_sub(source_summary.inbox_generation)
        .ok_or(AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    let inbox_entry_delta = final_inventory.tables[0]
        .count
        .checked_sub(source_inventory.tables[0].count)
        .ok_or(AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    let inbox_transition_delta = final_inventory.tables[1]
        .count
        .checked_sub(source_inventory.tables[1].count)
        .ok_or(AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    let automatic_redelivery_count = inbox_generation_delta
        .checked_add(inbox_entry_delta)
        .and_then(|count| count.checked_add(inbox_transition_delta))
        .ok_or(AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    if automatic_consumption_count != 0
        || receipt_generation_delta != 0
        || automatic_redelivery_count != 0
    {
        return Err(AdapterDispatchRestoreErrorV1::IntegrityFailed);
    }
    recheck_restore_pause_v1(custody, &paused)?;
    Ok(VerifiedAdapterDispatchRestoreV1 {
        root_identity: summary.root_identity,
        store_generation: summary.store_generation,
        inbox_count: summary.inbox_count,
        receipt_count: summary.receipt_count,
        source_inventory_digest: source_inventory.complete_store_digest,
        restored_inventory_digest: final_inventory.complete_store_digest,
        restore_index_digest: paused.restore_index_digest,
        pause_evidence_digest: paused.pause_evidence_digest,
        automatic_consumption_count,
        automatic_redelivery_count,
        possible_consumption_quarantine_count: verified.reconciliation_proof_count(),
        reconciliation_required_count: verified.reconciliation_proof_count(),
        reconciliation_grant_set_digest: verified.reconciliation_grant_set_digest(),
        reconciliation_grant_ids: verified.reconciliation_grant_ids().into(),
        initial_destination_entry_count,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterBackupPauseValidationV1 {
    Exact,
    Revoked,
    Unavailable,
    Unhealthy,
}

/// Opaque proof that delivery admission is closed, transport is fenced and every
/// previously admitted delivery has drained before the adapter store lock is trusted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterPausedQuiescenceV1 {
    supervisor_epoch: u64,
    pause_generation: u64,
    fencing_generation: u64,
    drained_delivery_generation: u64,
}

impl AdapterPausedQuiescenceV1 {
    pub fn try_new(
        supervisor_epoch: u64,
        pause_generation: u64,
        fencing_generation: u64,
        drained_delivery_generation: u64,
    ) -> Result<Self, AdapterDispatchBackupErrorV1> {
        if supervisor_epoch > MAX_SAFE_INTEGER_V1
            || !(1..=MAX_SAFE_INTEGER_V1).contains(&pause_generation)
            || !(1..=MAX_SAFE_INTEGER_V1).contains(&fencing_generation)
            || drained_delivery_generation > MAX_SAFE_INTEGER_V1
        {
            return Err(AdapterDispatchBackupErrorV1::PauseChanged);
        }
        Ok(Self {
            supervisor_epoch,
            pause_generation,
            fencing_generation,
            drained_delivery_generation,
        })
    }

    pub const fn supervisor_epoch(self) -> u64 {
        self.supervisor_epoch
    }

    /// Monotonic generation of the persisted PAUSE decision. This is evidence only and
    /// grants no admission, transport, or release authority.
    pub const fn pause_generation(self) -> u64 {
        self.pause_generation
    }

    /// Generation of the transport fence retained by this custody evidence.
    pub const fn fencing_generation(self) -> u64 {
        self.fencing_generation
    }

    /// Last delivery generation proved drained before the cut.
    pub const fn drained_delivery_generation(self) -> u64 {
        self.drained_delivery_generation
    }

    /// Domain-separated PAUSE evidence digest for a cross-store manifest binding.
    pub fn pause_evidence_digest(self) -> [u8; 32] {
        domain_digest(
            ADAPTER_PAUSE_EVIDENCE_DOMAIN_V1,
            &[
                &self.supervisor_epoch.to_be_bytes(),
                &self.pause_generation.to_be_bytes(),
            ],
        )
    }

    /// Domain-separated drain/fence evidence digest for a cross-store manifest binding.
    pub fn quiescence_evidence_digest(self) -> [u8; 32] {
        domain_digest(
            ADAPTER_QUIESCENCE_EVIDENCE_DOMAIN_V1,
            &[
                &self.supervisor_epoch.to_be_bytes(),
                &self.pause_generation.to_be_bytes(),
                &self.fencing_generation.to_be_bytes(),
                &self.drained_delivery_generation.to_be_bytes(),
            ],
        )
    }
}

impl fmt::Debug for AdapterPausedQuiescenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterPausedQuiescenceV1")
            .finish_non_exhaustive()
    }
}

pub trait AdapterBackupPauseCustodyV1: Send {
    fn capture_paused_quiescence_v1(
        &mut self,
    ) -> Result<AdapterPausedQuiescenceV1, AdapterBackupPauseValidationV1>;

    fn recheck_paused_quiescence_v1(
        &mut self,
        expected: &AdapterPausedQuiescenceV1,
    ) -> AdapterBackupPauseValidationV1;

    fn release(self);
}

pub enum AdapterBackupPauseCustodyOutcomeV1<C> {
    Acquired(C),
    Contended,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

impl<C> fmt::Debug for AdapterBackupPauseCustodyOutcomeV1<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquired(_) => "AdapterBackupPauseCustodyOutcomeV1::Acquired(..)",
            Self::Contended => "AdapterBackupPauseCustodyOutcomeV1::Contended",
            Self::Unavailable => "AdapterBackupPauseCustodyOutcomeV1::Unavailable",
            Self::DeadlineReached => "AdapterBackupPauseCustodyOutcomeV1::DeadlineReached",
            Self::Unsupported => "AdapterBackupPauseCustodyOutcomeV1::Unsupported",
        })
    }
}

pub trait AdapterBackupPauseAuthorityV1: Send + Sync {
    type Custody: AdapterBackupPauseCustodyV1;

    /// Persists PAUSE, closes delivery admission, fences transport and waits for the
    /// previously admitted delivery set to drain before returning custody.
    fn persist_pause_fence_and_drain_v1(
        &self,
        deadline_monotonic_ms: u64,
    ) -> AdapterBackupPauseCustodyOutcomeV1<Self::Custody>;
}

/// Create-only component destination. Native paths never appear in diagnostics or
/// returned evidence.
pub struct ProvisionedAdapterDispatchBackupDestinationV1 {
    staging: PathBuf,
    published: PathBuf,
}

impl ProvisionedAdapterDispatchBackupDestinationV1 {
    pub fn try_reserve_create_only(root: PathBuf) -> Result<Self, AdapterDispatchBackupErrorV1> {
        match fs::create_dir(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(AdapterDispatchBackupErrorV1::DestinationExists)
            }
            Err(_) => return Err(AdapterDispatchBackupErrorV1::DestinationUnavailable),
        }
        let result = (|| {
            let staging = root.join("staging");
            let published = root.join("published");
            fs::create_dir(&staging)
                .and_then(|()| fs::create_dir(&published))
                .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
            sync_root_directory(&root)
                .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
            Ok(Self { staging, published })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(root);
        }
        result
    }

    fn staging_database(&self) -> PathBuf {
        self.staging.join(ADAPTER_DATABASE_STAGING_V1)
    }

    fn staging_manifest(&self) -> PathBuf {
        self.staging.join(ADAPTER_MANIFEST_STAGING_V1)
    }

    fn staging_complete_marker(&self) -> PathBuf {
        self.staging.join(ADAPTER_COMPLETE_STAGING_V1)
    }

    fn published_database(&self) -> PathBuf {
        self.published.join(ADAPTER_DATABASE_PUBLISHED_V1)
    }

    fn published_manifest(&self) -> PathBuf {
        self.published.join(ADAPTER_MANIFEST_PUBLISHED_V1)
    }

    fn published_complete_marker(&self) -> PathBuf {
        self.published.join(ADAPTER_COMPLETE_PUBLISHED_V1)
    }
}

impl fmt::Debug for ProvisionedAdapterDispatchBackupDestinationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedAdapterDispatchBackupDestinationV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdapterGrantInventoryEntryV1 {
    grant_id: [u8; 32],
    grant_digest: [u8; 32],
}

impl AdapterGrantInventoryEntryV1 {
    pub const fn grant_id(self) -> [u8; 32] {
        self.grant_id
    }

    pub const fn grant_digest(self) -> [u8; 32] {
        self.grant_digest
    }
}

impl fmt::Debug for AdapterGrantInventoryEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterGrantInventoryEntryV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdapterReceiptInventoryEntryV1 {
    grant_id: [u8; 32],
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
}

impl AdapterReceiptInventoryEntryV1 {
    pub const fn grant_id(self) -> [u8; 32] {
        self.grant_id
    }

    pub const fn receipt_id(self) -> [u8; 32] {
        self.receipt_id
    }

    pub const fn receipt_digest(self) -> [u8; 32] {
        self.receipt_digest
    }
}

impl fmt::Debug for AdapterReceiptInventoryEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterReceiptInventoryEntryV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AdapterSignerInventoryEntryV1 {
    key_id: String,
    key_fingerprint: [u8; 32],
}

impl AdapterSignerInventoryEntryV1 {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub const fn key_fingerprint(&self) -> [u8; 32] {
        self.key_fingerprint
    }
}

impl fmt::Debug for AdapterSignerInventoryEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterSignerInventoryEntryV1")
            .finish_non_exhaustive()
    }
}

/// Independently verified adapter component. It contains only database/manifest bytes,
/// public relationship inventory and PAUSE evidence; no signer or private key custody.
pub struct VerifiedAdapterDispatchBackupV1 {
    destination: ProvisionedAdapterDispatchBackupDestinationV1,
    database_sha256: [u8; 32],
    manifest_digest: [u8; 32],
    manifest_package_sha256: [u8; 32],
    manifest_package_bytes: Vec<u8>,
    completed_at_utc_ms: u64,
    supervisor_epoch: u64,
    pause_evidence_digest: [u8; 32],
    quiescence_evidence_digest: [u8; 32],
    grants_inventory_digest: [u8; 32],
    receipts_inventory_digest: [u8; 32],
    grants: Vec<AdapterGrantInventoryEntryV1>,
    receipts: Vec<AdapterReceiptInventoryEntryV1>,
    grant_signers: Vec<AdapterSignerInventoryEntryV1>,
    receipt_signers: Vec<AdapterSignerInventoryEntryV1>,
}

impl VerifiedAdapterDispatchBackupV1 {
    pub const fn database_sha256(&self) -> [u8; 32] {
        self.database_sha256
    }

    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub const fn manifest_package_sha256(&self) -> [u8; 32] {
        self.manifest_package_sha256
    }

    pub fn manifest_package_bytes(&self) -> &[u8] {
        &self.manifest_package_bytes
    }

    pub const fn completed_at_utc_ms(&self) -> u64 {
        self.completed_at_utc_ms
    }

    pub const fn supervisor_epoch(&self) -> u64 {
        self.supervisor_epoch
    }

    pub const fn pause_evidence_digest(&self) -> [u8; 32] {
        self.pause_evidence_digest
    }

    pub const fn quiescence_evidence_digest(&self) -> [u8; 32] {
        self.quiescence_evidence_digest
    }

    pub const fn grants_inventory_digest(&self) -> [u8; 32] {
        self.grants_inventory_digest
    }

    pub const fn receipts_inventory_digest(&self) -> [u8; 32] {
        self.receipts_inventory_digest
    }

    pub fn grants(&self) -> &[AdapterGrantInventoryEntryV1] {
        &self.grants
    }

    pub fn receipts(&self) -> &[AdapterReceiptInventoryEntryV1] {
        &self.receipts
    }

    pub fn grant_signers(&self) -> &[AdapterSignerInventoryEntryV1] {
        &self.grant_signers
    }

    pub fn receipt_signers(&self) -> &[AdapterSignerInventoryEntryV1] {
        &self.receipt_signers
    }

    pub fn into_destination(self) -> ProvisionedAdapterDispatchBackupDestinationV1 {
        self.destination
    }
}

impl fmt::Debug for VerifiedAdapterDispatchBackupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAdapterDispatchBackupV1")
            .finish_non_exhaustive()
    }
}

impl SqliteDispatchInboxStoreV1 {
    /// Completes one independently coherent adapter backup under live PAUSE/fence custody.
    /// The store mutex is retained from the drained-custody recheck through publication,
    /// so no crate admission or consumption path can mutate the source during the cut.
    pub fn backup_paused_dispatch_inbox_v1<A: AdapterBackupPauseAuthorityV1>(
        &self,
        pause_authority: &A,
        destination: ProvisionedAdapterDispatchBackupDestinationV1,
        completed_at_utc_ms: u64,
        deadline_monotonic_ms: u64,
    ) -> Result<VerifiedAdapterDispatchBackupV1, AdapterDispatchBackupErrorV1> {
        if completed_at_utc_ms > MAX_SAFE_INTEGER_V1 || deadline_monotonic_ms > MAX_SAFE_INTEGER_V1
        {
            return Err(AdapterDispatchBackupErrorV1::PauseDeadlineReached);
        }
        let mut custody =
            match pause_authority.persist_pause_fence_and_drain_v1(deadline_monotonic_ms) {
                AdapterBackupPauseCustodyOutcomeV1::Acquired(custody) => custody,
                AdapterBackupPauseCustodyOutcomeV1::Contended => {
                    return Err(AdapterDispatchBackupErrorV1::PauseContended)
                }
                AdapterBackupPauseCustodyOutcomeV1::Unavailable => {
                    return Err(AdapterDispatchBackupErrorV1::PauseUnavailable)
                }
                AdapterBackupPauseCustodyOutcomeV1::DeadlineReached => {
                    return Err(AdapterDispatchBackupErrorV1::PauseDeadlineReached)
                }
                AdapterBackupPauseCustodyOutcomeV1::Unsupported => {
                    return Err(AdapterDispatchBackupErrorV1::PauseUnsupported)
                }
            };
        let paused = match custody.capture_paused_quiescence_v1() {
            Ok(paused) => paused,
            Err(_) => {
                custody.release();
                return Err(AdapterDispatchBackupErrorV1::PauseChanged);
            }
        };
        let result = self.backup_under_paused_dispatch_custody_v1(
            &mut custody,
            paused,
            destination,
            completed_at_utc_ms,
        );
        custody.release();
        result
    }

    /// Component step used by a cross-store orchestrator that already owns and retains
    /// the adapter PAUSE/fence custody across the preceding coordinator backup.
    pub fn backup_under_paused_dispatch_custody_v1<C: AdapterBackupPauseCustodyV1>(
        &self,
        custody: &mut C,
        paused: AdapterPausedQuiescenceV1,
        destination: ProvisionedAdapterDispatchBackupDestinationV1,
        completed_at_utc_ms: u64,
    ) -> Result<VerifiedAdapterDispatchBackupV1, AdapterDispatchBackupErrorV1> {
        if completed_at_utc_ms > MAX_SAFE_INTEGER_V1 {
            return Err(AdapterDispatchBackupErrorV1::PauseDeadlineReached);
        }
        let opened = match self.lock_store() {
            Ok(opened) => opened,
            Err(_) => return Err(AdapterDispatchBackupErrorV1::StoreUnavailable),
        };
        let result = (|| {
            recheck_pause(custody, &paused)?;
            let source = opened.connection();
            let expected_identity = opened.summary().root_identity.into_internal();
            let summary = schema::verify_full(source, expected_identity)
                .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
            if summary.root_lifecycle_state != AdapterRootLifecycleStateV1::Active
                || summary.supervisor_epoch != paused.supervisor_epoch()
            {
                return Err(AdapterDispatchBackupErrorV1::PauseChanged);
            }

            let inventory = capture_adapter_inventory_v1(source)?;
            let database_sha256 = backup_adapter_database_v1(
                source,
                expected_identity,
                &destination.staging_database(),
            )?;
            recheck_pause(custody, &paused)?;

            let root_identity_digest = domain_digest(
                ADAPTER_ROOT_DIGEST_DOMAIN_V1,
                &[&summary.root_identity.to_attested_bytes()],
            );
            let finalized =
                finalize_adapter_inbox_backup_manifest_v1(AdapterInboxBackupManifestInputV1 {
                    root_identity_digest,
                    schema_digest: schema::embedded_adapter_inbox_schema_v1_sha256(),
                    database_digest: database_sha256,
                    root_lifecycle_state: match summary.root_lifecycle_state {
                        AdapterRootLifecycleStateV1::Active => BackupRootLifecycleStateV1::Active,
                        AdapterRootLifecycleStateV1::RestorePending => {
                            BackupRootLifecycleStateV1::RestorePending
                        }
                    },
                    supervisor_epoch: summary.supervisor_epoch,
                    generations: AdapterGenerationsInputV1 {
                        store: summary.store_generation,
                        inbox: summary.inbox_generation,
                        consumption: summary.consumption_generation,
                        receipt: summary.receipt_generation,
                        conflict: summary.conflict_generation,
                        quarantine: summary.quarantine_generation,
                        event: summary.event_generation,
                        epoch_observer: summary.epoch_observer_generation,
                        restore_state: inventory.restore_state_generation,
                    },
                    counts: AdapterCountsInputV1 {
                        inbox_entries: inventory.tables[0].count,
                        transitions: inventory.tables[1].count,
                        receipts: inventory.tables[2].count,
                        conflicts: inventory.tables[3].count,
                        quarantines: inventory.tables[4].count,
                        events: inventory.tables[5].count,
                    },
                    inventory_digests: AdapterInventoriesInputV1 {
                        inbox_entries: inventory.tables[0].digest,
                        transitions: inventory.tables[1].digest,
                        receipts: inventory.tables[2].digest,
                        conflicts: inventory.tables[3].digest,
                        quarantines: inventory.tables[4].digest,
                        events: inventory.tables[5].digest,
                        complete_store: inventory.complete_store_digest,
                    },
                })
                .map_err(|_| AdapterDispatchBackupErrorV1::ManifestInvalid)?;
            let decoded = decode_adapter_inbox_backup_manifest_v1(finalized.bytes())
                .map_err(|_| AdapterDispatchBackupErrorV1::ManifestInvalid)?;
            let body_digest: [u8; 32] = Sha256::digest(finalized.body_bytes()).into();
            if decoded.sha256() != finalized.sha256() || body_digest != finalized.manifest_digest()
            {
                return Err(AdapterDispatchBackupErrorV1::ManifestInvalid);
            }
            write_create_only_synced(&destination.staging_manifest(), finalized.body_bytes())?;
            recheck_pause(custody, &paused)?;
            let repeated = capture_adapter_inventory_v1(source)?;
            let repeated_summary = schema::verify_full(source, expected_identity)
                .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
            if repeated != inventory || repeated_summary != summary {
                return Err(AdapterDispatchBackupErrorV1::StoreInvalid);
            }

            publish_create_only(
                &destination.staging_database(),
                &destination.published_database(),
                &destination.published,
            )?;
            publish_create_only(
                &destination.staging_manifest(),
                &destination.published_manifest(),
                &destination.published,
            )?;
            verify_published_member(
                &destination.published_database(),
                database_sha256,
                MAX_BACKUP_DATABASE_BYTES_V1,
            )?;
            verify_published_member(
                &destination.published_manifest(),
                finalized.manifest_digest(),
                1024 * 1024,
            )?;
            let complete_marker =
                component_complete_marker_v1(database_sha256, finalized.manifest_digest());
            write_create_only_synced(&destination.staging_complete_marker(), &complete_marker)?;
            let staged_marker = fs::read(destination.staging_complete_marker())
                .map_err(|_| AdapterDispatchBackupErrorV1::PublicationFailed)?;
            if staged_marker != complete_marker {
                return Err(AdapterDispatchBackupErrorV1::PublicationFailed);
            }
            recheck_pause(custody, &paused)?;
            publish_create_only(
                &destination.staging_complete_marker(),
                &destination.published_complete_marker(),
                &destination.published,
            )?;
            #[cfg(feature = "test-fault-injection")]
            self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb079)
                .map_err(|_| AdapterDispatchBackupErrorV1::PublicationFailed)?;

            Ok(VerifiedAdapterDispatchBackupV1 {
                destination,
                database_sha256,
                manifest_digest: finalized.manifest_digest(),
                manifest_package_sha256: finalized.sha256(),
                manifest_package_bytes: finalized.bytes().to_vec(),
                completed_at_utc_ms,
                supervisor_epoch: paused.supervisor_epoch(),
                pause_evidence_digest: paused.pause_evidence_digest(),
                quiescence_evidence_digest: paused.quiescence_evidence_digest(),
                grants_inventory_digest: inventory.tables[0].digest,
                receipts_inventory_digest: inventory.tables[2].digest,
                grants: inventory.grants,
                receipts: inventory.receipts,
                grant_signers: inventory.grant_signers,
                receipt_signers: inventory.receipt_signers,
            })
        })();
        drop(opened);
        result
    }
}

fn recheck_restore_pause_v1<C: AdapterDispatchRestorePauseCustodyV1>(
    custody: &mut C,
    expected: &AdapterPausedDispatchRestoreV1,
) -> Result<(), AdapterDispatchRestoreErrorV1> {
    match custody.recheck_paused_dispatch_restore_v1(expected) {
        AdapterDispatchRestorePauseValidationV1::Exact => Ok(()),
        AdapterDispatchRestorePauseValidationV1::Revoked
        | AdapterDispatchRestorePauseValidationV1::Unavailable
        | AdapterDispatchRestorePauseValidationV1::Unhealthy => {
            Err(AdapterDispatchRestoreErrorV1::PauseChanged)
        }
    }
}

fn revalidate_restore_destination_v1(
    destination: &AdapterInboxStoreConfigV1,
) -> Result<(), AdapterDispatchRestoreErrorV1> {
    if let Some(root) = destination.empty_root() {
        root.revalidate()
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationInvalid)
    } else if let Some(root) = destination.existing_root() {
        root.revalidate()
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationInvalid)
    } else {
        Err(AdapterDispatchRestoreErrorV1::DestinationInvalid)
    }
}

fn validate_restore_authority_bindings_v1(
    source: &AdapterDispatchRestoreSourceBindingsV1,
    destination: &AdapterInboxStoreConfigV1,
    paused: &AdapterPausedDispatchRestoreV1,
) -> Result<(), AdapterDispatchRestoreErrorV1> {
    let destination_identity = if let Some(empty) = destination.empty_root() {
        AdapterInboxRootIdentityEvidenceV1::from_internal(empty.provisioned_identity())
    } else if let Some(existing) = destination.existing_root() {
        AdapterInboxRootIdentityEvidenceV1::from_internal(existing.expected_identity())
    } else {
        return Err(AdapterDispatchRestoreErrorV1::DestinationInvalid);
    };
    if source.source_root_identity != paused.source_root_identity
        || source.source_supervisor_epoch != paused.source_supervisor_epoch
        || source.generations.epoch_observer != paused.source_epoch_observer_generation
        || destination_identity != paused.new_root_identity
    {
        return Err(AdapterDispatchRestoreErrorV1::AuthorityInvalid);
    }
    Ok(())
}

fn expected_source_summary_v1(
    source: &AdapterDispatchRestoreSourceBindingsV1,
) -> AdapterInboxStoreSummaryV1 {
    AdapterInboxStoreSummaryV1 {
        root_identity: source.source_root_identity,
        root_lifecycle_state: AdapterRootLifecycleStateV1::Active,
        store_generation: source.generations.store,
        inbox_generation: source.generations.inbox,
        consumption_generation: source.generations.consumption,
        receipt_generation: source.generations.receipt,
        conflict_generation: source.generations.conflict,
        quarantine_generation: source.generations.quarantine,
        event_generation: source.generations.event,
        supervisor_epoch: source.source_supervisor_epoch,
        epoch_observer_generation: source.generations.epoch_observer,
        inbox_count: source.counts.inbox_entries,
        receipt_count: source.counts.receipts,
    }
}

fn pending_schema_bindings_v1(
    expected_source: AdapterInboxStoreSummaryV1,
    paused: AdapterPausedDispatchRestoreV1,
) -> Result<AdapterRestorePendingBindingsV1, AdapterDispatchRestoreErrorV1> {
    AdapterRestorePendingBindingsV1::try_new(
        expected_source,
        paused.new_root_identity.into_internal(),
        paused.new_supervisor_epoch,
        paused.new_epoch_observer_generation,
        paused.restore_index_digest,
        paused.pause_evidence_digest,
    )
    .map_err(|_| AdapterDispatchRestoreErrorV1::AuthorityInvalid)
}

fn open_initializing_restore_connection_v1(
    config: &AdapterInboxStoreConfigV1,
) -> Result<Connection, AdapterDispatchRestoreErrorV1> {
    let root = config
        .empty_root()
        .ok_or(AdapterDispatchRestoreErrorV1::DestinationInvalid)?;
    root.revalidate()
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
    let metadata = fs::symlink_metadata(config.database_path())
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdapterDispatchRestoreErrorV1::DestinationInvalid);
    }
    let connection = Connection::open_with_flags(
        config.database_path(),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
    connection
        .busy_timeout(Duration::from_millis(config.maximum_busy_wait_ms()))
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(AdapterDispatchRestoreErrorV1::DestinationUnavailable);
    }
    connection
        .pragma_update(None, "synchronous", "FULL")
        .and_then(|()| connection.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|()| connection.pragma_update(None, "cell_size_check", "ON"))
        .and_then(|()| connection.pragma_update(None, "recursive_triggers", "ON"))
        .and_then(|()| connection.pragma_update(None, "wal_autocheckpoint", 0_i64))
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
    let expected_busy_timeout = i64::try_from(config.maximum_busy_wait_ms())
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
    for (pragma, expected) in [
        ("synchronous", 2_i64),
        ("foreign_keys", 1_i64),
        ("trusted_schema", 0_i64),
        ("cell_size_check", 1_i64),
        ("recursive_triggers", 1_i64),
        ("wal_autocheckpoint", 0_i64),
        ("busy_timeout", expected_busy_timeout),
    ] {
        let actual: i64 = connection
            .pragma_query_value(None, pragma, |row| row.get(0))
            .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationUnavailable)?;
        if actual != expected {
            return Err(AdapterDispatchRestoreErrorV1::DestinationUnavailable);
        }
    }
    root.revalidate()
        .map_err(|_| AdapterDispatchRestoreErrorV1::DestinationConflict)?;
    Ok(connection)
}

fn verify_source_inventory_v1(
    actual: &SourceInventoryEvidenceV1,
    expected: &AdapterDispatchRestoreSourceBindingsV1,
) -> Result<(), AdapterDispatchRestoreErrorV1> {
    let expected_counts = [
        expected.counts.inbox_entries,
        expected.counts.transitions,
        expected.counts.receipts,
        expected.counts.conflicts,
        expected.counts.quarantines,
        expected.counts.events,
    ];
    let expected_digests = [
        expected.inventories.inbox_entries,
        expected.inventories.transitions,
        expected.inventories.receipts,
        expected.inventories.conflicts,
        expected.inventories.quarantines,
        expected.inventories.events,
    ];
    if actual
        .tables
        .iter()
        .zip(expected_counts)
        .any(|(inventory, count)| inventory.count != count)
        || actual
            .tables
            .iter()
            .zip(expected_digests)
            .any(|(inventory, digest)| inventory.digest != digest)
        || actual.complete_store_digest != expected.inventories.complete_store
    {
        return Err(AdapterDispatchRestoreErrorV1::IntegrityFailed);
    }
    Ok(())
}

fn verify_restore_additions_v1(
    restored: &CapturedAdapterInventoryV1,
    source: &SourceInventoryEvidenceV1,
    pending: &schema::VerifiedAdapterRestorePendingV1,
) -> Result<(), AdapterDispatchRestoreErrorV1> {
    let proof_count = pending.reconciliation_proof_count();
    let expected_quarantine_count = source.tables[4]
        .count
        .checked_add(proof_count)
        .ok_or(AdapterDispatchRestoreErrorV1::IntegrityFailed)?;
    if [0_usize, 1, 2, 3, 5]
        .into_iter()
        .any(|index| restored.tables[index] != source.tables[index])
        || restored.tables[4].count != expected_quarantine_count
        || restored.restore_state_generation != pending.summary().store_generation
        || restored.consumed_count != source.consumed_count
        || restored.reconciliation_candidate_count != source.reconciliation_candidate_count
    {
        return Err(AdapterDispatchRestoreErrorV1::IntegrityFailed);
    }
    Ok(())
}

fn hash_restore_source_handle_v1(
    file: &mut File,
    expected_length: u64,
) -> Result<[u8; 32], AdapterDispatchRestoreErrorV1> {
    let before = file
        .metadata()
        .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
    if !before.is_file() || before.len() != expected_length {
        return Err(AdapterDispatchRestoreErrorV1::SourceChanged);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
    let mut remaining = expected_length;
    let mut buffer = [0_u8; RESTORE_COPY_BUFFER_BYTES_V1];
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| AdapterDispatchRestoreErrorV1::SourceTooLarge)?;
        file.read_exact(&mut buffer[..wanted])
            .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
        hasher.update(&buffer[..wanted]);
        remaining -= wanted as u64;
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?
        != 0
    {
        return Err(AdapterDispatchRestoreErrorV1::SourceChanged);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
    let after = file
        .metadata()
        .map_err(|_| AdapterDispatchRestoreErrorV1::SourceChanged)?;
    if after.len() != expected_length {
        return Err(AdapterDispatchRestoreErrorV1::SourceChanged);
    }
    Ok(hasher.finalize().into())
}

fn map_backup_to_restore_error_v1(
    error: AdapterDispatchBackupErrorV1,
) -> AdapterDispatchRestoreErrorV1 {
    match error {
        AdapterDispatchBackupErrorV1::StoreInvalid
        | AdapterDispatchBackupErrorV1::ManifestInvalid => {
            AdapterDispatchRestoreErrorV1::StoreInvalid
        }
        AdapterDispatchBackupErrorV1::IntegrityFailed => {
            AdapterDispatchRestoreErrorV1::IntegrityFailed
        }
        AdapterDispatchBackupErrorV1::DestinationExists
        | AdapterDispatchBackupErrorV1::DestinationUnavailable
        | AdapterDispatchBackupErrorV1::PublicationFailed => {
            AdapterDispatchRestoreErrorV1::DestinationUnavailable
        }
        AdapterDispatchBackupErrorV1::PauseContended
        | AdapterDispatchBackupErrorV1::PauseUnavailable
        | AdapterDispatchBackupErrorV1::PauseDeadlineReached
        | AdapterDispatchBackupErrorV1::PauseUnsupported
        | AdapterDispatchBackupErrorV1::PauseChanged
        | AdapterDispatchBackupErrorV1::StoreUnavailable
        | AdapterDispatchBackupErrorV1::BackupFailed => AdapterDispatchRestoreErrorV1::StoreInvalid,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableInventoryV1 {
    count: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceInventoryEvidenceV1 {
    tables: [TableInventoryV1; 6],
    complete_store_digest: [u8; 32],
    consumed_count: u64,
    reconciliation_candidate_count: u64,
}

#[derive(Clone, PartialEq, Eq)]
struct CapturedAdapterInventoryV1 {
    tables: [TableInventoryV1; 6],
    complete_store_digest: [u8; 32],
    restore_state_generation: u64,
    consumed_count: u64,
    reconciliation_candidate_count: u64,
    grants: Vec<AdapterGrantInventoryEntryV1>,
    receipts: Vec<AdapterReceiptInventoryEntryV1>,
    grant_signers: Vec<AdapterSignerInventoryEntryV1>,
    receipt_signers: Vec<AdapterSignerInventoryEntryV1>,
}

impl CapturedAdapterInventoryV1 {
    const fn source_evidence_v1(&self) -> SourceInventoryEvidenceV1 {
        SourceInventoryEvidenceV1 {
            tables: self.tables,
            complete_store_digest: self.complete_store_digest,
            consumed_count: self.consumed_count,
            reconciliation_candidate_count: self.reconciliation_candidate_count,
        }
    }
}

fn capture_adapter_inventory_v1(
    connection: &Connection,
) -> Result<CapturedAdapterInventoryV1, AdapterDispatchBackupErrorV1> {
    let mut tables = [TableInventoryV1 {
        count: 0,
        digest: [0; 32],
    }; 6];
    for (index, (table, order)) in ADAPTER_INVENTORY_TABLES_V1.iter().enumerate() {
        tables[index] = table_inventory_v1(connection, table, order)?;
    }
    let restore_state_generation = connection
        .query_row(
            "SELECT restore_state_generation FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)
        .and_then(safe_u64)?;
    let consumed_count = connection
        .query_row(
            "SELECT COUNT(*) FROM grant_inbox WHERE inbox_state = 'CONSUMED'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)
        .and_then(safe_u64)?;
    let reconciliation_candidate_count = connection
        .query_row(
            "SELECT COUNT(*) FROM grant_inbox
             WHERE inbox_state IN ('RECEIVED', 'CONSUMED', 'QUARANTINED')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)
        .and_then(safe_u64)?;
    let grants = load_grant_relationships_v1(connection)?;
    let receipts = load_receipt_relationships_v1(connection)?;
    let grant_signers = load_grant_signers_v1(connection)?;
    let receipt_signers = load_receipt_signers_v1(connection)?;
    if usize::try_from(tables[0].count).ok() != Some(grants.len())
        || usize::try_from(tables[2].count).ok() != Some(receipts.len())
    {
        return Err(AdapterDispatchBackupErrorV1::StoreInvalid);
    }
    Ok(CapturedAdapterInventoryV1 {
        tables,
        complete_store_digest: complete_store_inventory_digest_v1(tables)?,
        restore_state_generation,
        consumed_count,
        reconciliation_candidate_count,
        grants,
        receipts,
        grant_signers,
        receipt_signers,
    })
}

fn capture_adapter_source_inventory_v1(
    connection: &Connection,
    source_quarantine_generation: u64,
) -> Result<SourceInventoryEvidenceV1, AdapterDispatchBackupErrorV1> {
    if source_quarantine_generation > MAX_SAFE_INTEGER_V1 {
        return Err(AdapterDispatchBackupErrorV1::StoreInvalid);
    }
    let captured = capture_adapter_inventory_v1(connection)?;
    let mut tables = captured.tables;
    tables[4] = table_inventory_v1_with_predicate(
        connection,
        "inbox_quarantines",
        "quarantine_id",
        &format!("quarantine_generation <= {source_quarantine_generation}"),
    )?;
    Ok(SourceInventoryEvidenceV1 {
        tables,
        complete_store_digest: complete_store_inventory_digest_v1(tables)?,
        consumed_count: captured.consumed_count,
        reconciliation_candidate_count: captured.reconciliation_candidate_count,
    })
}

fn complete_store_inventory_digest_v1(
    tables: [TableInventoryV1; 6],
) -> Result<[u8; 32], AdapterDispatchBackupErrorV1> {
    let mut hasher = Sha256::new();
    hasher.update(COMPLETE_STORE_INVENTORY_DOMAIN_V1);
    for ((table, _), inventory) in ADAPTER_INVENTORY_TABLES_V1.iter().zip(tables) {
        update_len_prefixed(&mut hasher, table.as_bytes())?;
        hasher.update(inventory.count.to_be_bytes());
        hasher.update(inventory.digest);
    }
    Ok(hasher.finalize().into())
}

fn table_inventory_v1(
    connection: &Connection,
    table: &str,
    order: &str,
) -> Result<TableInventoryV1, AdapterDispatchBackupErrorV1> {
    table_inventory_v1_with_predicate(connection, table, order, "1 = 1")
}

fn table_inventory_v1_with_predicate(
    connection: &Connection,
    table: &str,
    order: &str,
    predicate: &str,
) -> Result<TableInventoryV1, AdapterDispatchBackupErrorV1> {
    let sql = format!("SELECT * FROM {table} WHERE {predicate} ORDER BY {order}");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let column_count = statement.column_count();
    let mut rows = statement
        .query([])
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let mut hasher = Sha256::new();
    hasher.update(TABLE_INVENTORY_DOMAIN_V1);
    update_len_prefixed(&mut hasher, table.as_bytes())?;
    let mut count = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?
    {
        count = count
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_INTEGER_V1)
            .ok_or(AdapterDispatchBackupErrorV1::StoreInvalid)?;
        hasher.update(count.to_be_bytes());
        for index in 0..column_count {
            hash_sql_value(
                &mut hasher,
                row.get_ref(index)
                    .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?,
            )?;
        }
    }
    Ok(TableInventoryV1 {
        count,
        digest: hasher.finalize().into(),
    })
}

fn load_grant_relationships_v1(
    connection: &Connection,
) -> Result<Vec<AdapterGrantInventoryEntryV1>, AdapterDispatchBackupErrorV1> {
    let mut statement = connection
        .prepare("SELECT grant_id, grant_digest FROM grant_inbox ORDER BY grant_id")
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let rows = statement
        .query_map([], |row| {
            Ok(AdapterGrantInventoryEntryV1 {
                grant_id: exact_digest(row.get_ref(0)?)?,
                grant_digest: exact_digest(row.get_ref(1)?)?,
            })
        })
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)
}

fn load_receipt_relationships_v1(
    connection: &Connection,
) -> Result<Vec<AdapterReceiptInventoryEntryV1>, AdapterDispatchBackupErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT grant_id, receipt_id, receipt_digest \
             FROM execution_receipts ORDER BY grant_id, receipt_id",
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let rows = statement
        .query_map([], |row| {
            Ok(AdapterReceiptInventoryEntryV1 {
                grant_id: exact_digest(row.get_ref(0)?)?,
                receipt_id: exact_digest(row.get_ref(1)?)?,
                receipt_digest: exact_digest(row.get_ref(2)?)?,
            })
        })
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)
}

fn load_grant_signers_v1(
    connection: &Connection,
) -> Result<Vec<AdapterSignerInventoryEntryV1>, AdapterDispatchBackupErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT grant_digest, canonical_grant, canonical_grant_length, \
                    coordinator_key_fingerprint \
             FROM grant_inbox ORDER BY grant_id",
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let mut rows = statement
        .query([])
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let mut signers = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?
    {
        let digest = exact_digest(
            row.get_ref(0)
                .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?,
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let canonical: Vec<u8> = row
            .get(1)
            .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let canonical_length: i64 = row
            .get(2)
            .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let key_fingerprint = exact_digest(
            row.get_ref(3)
                .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?,
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let signed: SignedExecutionGrantV1 = serde_json::from_slice(&canonical)
            .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        if u64::try_from(canonical_length).ok() != Some(canonical.len() as u64)
            || signed.to_canonical_json().ok().as_deref() != Some(canonical.as_slice())
            || *signed.grant_digest().as_bytes() != digest
        {
            return Err(AdapterDispatchBackupErrorV1::StoreInvalid);
        }
        signers.push(AdapterSignerInventoryEntryV1 {
            key_id: signed.protected().key_id().to_owned(),
            key_fingerprint,
        });
    }
    signers.sort();
    signers.dedup();
    Ok(signers)
}

fn load_receipt_signers_v1(
    connection: &Connection,
) -> Result<Vec<AdapterSignerInventoryEntryV1>, AdapterDispatchBackupErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT receipt_digest, canonical_receipt, canonical_receipt_length, \
                    adapter_key_id, adapter_key_fingerprint \
             FROM execution_receipts ORDER BY receipt_id",
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let mut rows = statement
        .query([])
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
    let mut signers = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?
    {
        let digest = exact_digest(
            row.get_ref(0)
                .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?,
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let canonical: Vec<u8> = row
            .get(1)
            .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let canonical_length: i64 = row
            .get(2)
            .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let stored_key_id: String = row
            .get(3)
            .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let key_fingerprint = exact_digest(
            row.get_ref(4)
                .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?,
        )
        .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        let signed: SignedExecutionReceiptV1 = serde_json::from_slice(&canonical)
            .map_err(|_| AdapterDispatchBackupErrorV1::StoreInvalid)?;
        if u64::try_from(canonical_length).ok() != Some(canonical.len() as u64)
            || signed.to_canonical_json().ok().as_deref() != Some(canonical.as_slice())
            || *signed.receipt_digest().as_bytes() != digest
            || signed.protected().key_id() != stored_key_id
        {
            return Err(AdapterDispatchBackupErrorV1::StoreInvalid);
        }
        signers.push(AdapterSignerInventoryEntryV1 {
            key_id: stored_key_id,
            key_fingerprint,
        });
    }
    signers.sort();
    signers.dedup();
    Ok(signers)
}

fn exact_digest(value: ValueRef<'_>) -> rusqlite::Result<[u8; 32]> {
    let ValueRef::Blob(bytes) = value else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn backup_adapter_database_v1(
    source: &Connection,
    expected_identity: crate::root_safety::AdapterRootIdentityV1,
    staging_database: &Path,
) -> Result<[u8; 32], AdapterDispatchBackupErrorV1> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging_database)
        .and_then(|file| file.sync_all())
        .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
    let mut destination = Connection::open_with_flags(
        staging_database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
    let backup = Backup::new(source, &mut destination)
        .map_err(|_| AdapterDispatchBackupErrorV1::BackupFailed)?;
    let mut busy_steps = 0_usize;
    for _ in 0..MAX_BACKUP_STEPS_V1 {
        match backup
            .step(BACKUP_PAGES_PER_STEP_V1)
            .map_err(|_| AdapterDispatchBackupErrorV1::BackupFailed)?
        {
            StepResult::Done => break,
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => {
                busy_steps += 1;
                if busy_steps > MAX_BACKUP_BUSY_STEPS_V1 {
                    return Err(AdapterDispatchBackupErrorV1::BackupFailed);
                }
                thread::sleep(Duration::from_millis(1));
            }
            _ => return Err(AdapterDispatchBackupErrorV1::BackupFailed),
        }
    }
    if backup.progress().remaining != 0 {
        return Err(AdapterDispatchBackupErrorV1::BackupFailed);
    }
    drop(backup);
    let mode: String = destination
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(|_| AdapterDispatchBackupErrorV1::IntegrityFailed)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(AdapterDispatchBackupErrorV1::IntegrityFailed);
    }
    drop(destination);
    remove_sqlite_sidecars(staging_database)?;
    let metadata = fs::metadata(staging_database)
        .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
    if metadata.len() == 0 || metadata.len() > MAX_BACKUP_DATABASE_BYTES_V1 {
        return Err(AdapterDispatchBackupErrorV1::BackupFailed);
    }
    reopen_and_verify_adapter_backup_v1(staging_database, expected_identity)?;
    hash_file(staging_database, MAX_BACKUP_DATABASE_BYTES_V1)
}

fn reopen_and_verify_adapter_backup_v1(
    database: &Path,
    expected_identity: crate::root_safety::AdapterRootIdentityV1,
) -> Result<(), AdapterDispatchBackupErrorV1> {
    require_sqlite_sidecars_absent(database)?;
    let reopened = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| AdapterDispatchBackupErrorV1::IntegrityFailed)?;
    let mode: String = reopened
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| AdapterDispatchBackupErrorV1::IntegrityFailed)?;
    let integrity: String = reopened
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| AdapterDispatchBackupErrorV1::IntegrityFailed)?;
    if !mode.eq_ignore_ascii_case("delete")
        || integrity != "ok"
        || schema::verify_full(&reopened, expected_identity).is_err()
    {
        return Err(AdapterDispatchBackupErrorV1::IntegrityFailed);
    }
    drop(reopened);
    require_sqlite_sidecars_absent(database)
}

fn remove_sqlite_sidecars(database: &Path) -> Result<(), AdapterDispatchBackupErrorV1> {
    for suffix in ["-wal", "-shm"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        match fs::remove_file(PathBuf::from(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AdapterDispatchBackupErrorV1::IntegrityFailed),
        }
    }
    Ok(())
}

fn require_sqlite_sidecars_absent(database: &Path) -> Result<(), AdapterDispatchBackupErrorV1> {
    for suffix in ["-wal", "-shm"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        match fs::symlink_metadata(PathBuf::from(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(AdapterDispatchBackupErrorV1::IntegrityFailed),
        }
    }
    Ok(())
}

fn recheck_pause<C: AdapterBackupPauseCustodyV1>(
    custody: &mut C,
    paused: &AdapterPausedQuiescenceV1,
) -> Result<(), AdapterDispatchBackupErrorV1> {
    match custody.recheck_paused_quiescence_v1(paused) {
        AdapterBackupPauseValidationV1::Exact => Ok(()),
        AdapterBackupPauseValidationV1::Revoked
        | AdapterBackupPauseValidationV1::Unavailable
        | AdapterBackupPauseValidationV1::Unhealthy => {
            Err(AdapterDispatchBackupErrorV1::PauseChanged)
        }
    }
}

fn publish_create_only(
    staged: &Path,
    published: &Path,
    published_root: &Path,
) -> Result<(), AdapterDispatchBackupErrorV1> {
    fs::hard_link(staged, published)
        .map_err(|_| AdapterDispatchBackupErrorV1::PublicationFailed)?;
    let staging_root = staged
        .parent()
        .ok_or(AdapterDispatchBackupErrorV1::PublicationFailed)?;
    let committed = (|| {
        File::open(published)
            .and_then(|file| file.sync_all())
            .map_err(|_| AdapterDispatchBackupErrorV1::PublicationFailed)?;
        sync_root_directory(published_root)
            .map_err(|_| AdapterDispatchBackupErrorV1::PublicationFailed)?;
        fs::remove_file(staged).map_err(|_| AdapterDispatchBackupErrorV1::PublicationFailed)?;
        sync_root_directory(staging_root)
            .map_err(|_| AdapterDispatchBackupErrorV1::PublicationFailed)
    })();
    if committed.is_err() {
        let _ = fs::remove_file(published);
        let _ = sync_root_directory(published_root);
        return Err(AdapterDispatchBackupErrorV1::PublicationFailed);
    }
    Ok(())
}

fn write_create_only_synced(path: &Path, bytes: &[u8]) -> Result<(), AdapterDispatchBackupErrorV1> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)
}

fn verify_published_member(
    path: &Path,
    expected: [u8; 32],
    maximum_bytes: u64,
) -> Result<(), AdapterDispatchBackupErrorV1> {
    if hash_file(path, maximum_bytes)? != expected {
        return Err(AdapterDispatchBackupErrorV1::PublicationFailed);
    }
    Ok(())
}

fn hash_file(path: &Path, maximum_bytes: u64) -> Result<[u8; 32], AdapterDispatchBackupErrorV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(AdapterDispatchBackupErrorV1::DestinationUnavailable);
    }
    let mut file =
        File::open(path).map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
    let mut hasher = Sha256::new();
    let mut read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|_| AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
        if length == 0 {
            break;
        }
        read = read
            .checked_add(length as u64)
            .filter(|length| *length <= maximum_bytes)
            .ok_or(AdapterDispatchBackupErrorV1::DestinationUnavailable)?;
        hasher.update(&buffer[..length]);
    }
    if read != metadata.len() {
        return Err(AdapterDispatchBackupErrorV1::DestinationUnavailable);
    }
    Ok(hasher.finalize().into())
}

fn hash_sql_value(
    hasher: &mut Sha256,
    value: ValueRef<'_>,
) -> Result<(), AdapterDispatchBackupErrorV1> {
    match value {
        ValueRef::Null => hasher.update([0]),
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            hasher.update([3]);
            update_len_prefixed(hasher, value)?;
        }
        ValueRef::Blob(value) => {
            hasher.update([4]);
            update_len_prefixed(hasher, value)?;
        }
    }
    Ok(())
}

fn update_len_prefixed(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), AdapterDispatchBackupErrorV1> {
    let length = u64::try_from(bytes.len())
        .ok()
        .filter(|length| *length <= MAX_SAFE_INTEGER_V1)
        .ok_or(AdapterDispatchBackupErrorV1::StoreInvalid)?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn safe_u64(value: i64) -> Result<u64, AdapterDispatchBackupErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_INTEGER_V1)
        .ok_or(AdapterDispatchBackupErrorV1::StoreInvalid)
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn component_complete_marker_v1(database_sha256: [u8; 32], manifest_digest: [u8; 32]) -> Vec<u8> {
    let mut marker = b"HELIXOS_DISPATCH_ADAPTER_BACKUP_COMPONENT_V1\nDATABASE_SHA256=".to_vec();
    marker.extend_from_slice(encode_lower_hex(database_sha256).as_bytes());
    marker.extend_from_slice(b"\nMANIFEST_DIGEST=");
    marker.extend_from_slice(encode_lower_hex(manifest_digest).as_bytes());
    marker.push(b'\n');
    marker
}

fn encode_lower_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
