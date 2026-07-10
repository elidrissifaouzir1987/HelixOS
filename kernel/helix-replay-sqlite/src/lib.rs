//! Crash-aware durable replay claimant for HelixOS.
//!
//! This crate is a host storage adapter for feature 002's `ReplayClaimantV1`. A
//! successful receipt is still only eligibility evidence; it is never preparation,
//! dispatch, adapter, or effect authority.

#![forbid(unsafe_code)]

mod claim;
mod clock;
mod config;
mod connection;
mod error;
mod maintenance;
mod manifest;
mod root_safety;
mod schema;

#[cfg(feature = "test-fault-injection")]
mod test_fault;

pub use clock::ReplayMonotonicClockV1;
pub use config::{ReplayStoreConfigV1, TrustedEmptyLocalRootV1, TrustedLocalStoreRootV1};
pub use error::{
    ReplayClockUnavailableV1, ReplayStoreConfigErrorV1, ReplayStoreLocationErrorV1,
    ReplayStoreMaintenanceErrorV1, ReplayStoreOpenErrorV1,
};
pub use maintenance::{
    restore_replay_store_v1, verify_replay_backup_v1, ReplayBackupEvidenceV1,
    ReplayCheckpointEvidenceV1, ReplayCheckpointModeV1, ReplayStoreVerificationV1,
    VerifiedRestoreEvidenceV1,
};
pub use manifest::{
    embedded_backup_manifest_schema_v1_sha256, BackupManifestV1, BACKUP_MANIFEST_SCHEMA_V1,
};
pub use schema::{
    embedded_schema_v1_sha256, REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1,
};

use crate::connection::initialize_or_verify_store;
use std::fmt;
use std::sync::atomic::AtomicBool;

/// Durable SQLite implementation of feature 002's one-shot replay claimant.
pub struct SqliteReplayClaimantV1<C> {
    pub(crate) config: ReplayStoreConfigV1,
    pub(crate) clock: C,
    pub(crate) healthy: AtomicBool,
    pub(crate) schema_cookie: i64,
}

impl<C: ReplayMonotonicClockV1> SqliteReplayClaimantV1<C> {
    /// Opens or transactionally initializes one dedicated replay store.
    pub fn open_or_create(
        config: ReplayStoreConfigV1,
        clock: C,
        deadline_monotonic_ms: u64,
    ) -> Result<Self, ReplayStoreOpenErrorV1> {
        let summary = initialize_or_verify_store(&config, &clock, deadline_monotonic_ms)
            .map_err(|error| error.to_open())?;
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::Opened);
        Ok(Self {
            config,
            clock,
            healthy: AtomicBool::new(true),
            schema_cookie: summary.schema_cookie,
        })
    }
}

impl<C> fmt::Debug for SqliteReplayClaimantV1<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteReplayClaimantV1")
            .finish_non_exhaustive()
    }
}
