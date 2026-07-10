use crate::error::{ReplayStoreConfigErrorV1, ReplayStoreLocationErrorV1};
use helix_contracts::MAX_SAFE_U64;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const DATABASE_FILENAME: &str = "replay.sqlite3";
pub(crate) const WAL_FILENAME: &str = "replay.sqlite3-wal";
pub(crate) const SHM_FILENAME: &str = "replay.sqlite3-shm";
pub(crate) const ROLLBACK_JOURNAL_FILENAME: &str = "replay.sqlite3-journal";
pub(crate) const BACKUP_DATABASE_FILENAME: &str = "replay-backup.sqlite3";
pub(crate) const BACKUP_MANIFEST_FILENAME: &str = "backup-manifest-v1.json";
pub(crate) const ROOT_LOCK_FILENAME: &str = ".helix-replay-root-v1.lock";
pub(crate) const LIVE_INITIALIZATION_INTENT_FILENAME: &str = ".helix-replay-live-initializing-v1";
pub(crate) const QUARANTINE_MARKER_FILENAME: &str = ".helix-replay-quarantined-v1";
pub(crate) const RESTORED_ACTIVATION_MARKER_FILENAME: &str =
    ".helix-replay-restored-activation-required-v1";

const MAX_BACKUP_STEP_PAGES: u32 = 4096;
const MAX_BACKUP_RETRY_WAIT_MS: u64 = 1000;

/// Native root whose local-filesystem assurance was established by host provisioning.
///
/// This type checks syntax, existence and dedicated contents only. It cannot infer
/// trustworthy locality from a path; the caller's provisioning assertion is a security
/// precondition.
#[derive(Clone)]
pub struct TrustedLocalStoreRootV1 {
    root: PathBuf,
}

impl TrustedLocalStoreRootV1 {
    pub fn try_from_provisioned(root: PathBuf) -> Result<Self, ReplayStoreLocationErrorV1> {
        validate_root_syntax(&root)?;
        let canonical =
            fs::canonicalize(&root).map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
        validate_root_syntax(&canonical)?;
        validate_provisioned_contents(&canonical)?;
        Ok(Self { root: canonical })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.root
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.root.join(DATABASE_FILENAME)
    }
}

impl fmt::Debug for TrustedLocalStoreRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedLocalStoreRootV1")
            .finish_non_exhaustive()
    }
}

/// Dedicated host-provisioned directory that was empty when checked.
#[derive(Clone)]
pub struct TrustedEmptyLocalRootV1 {
    root: TrustedLocalStoreRootV1,
}

impl TrustedEmptyLocalRootV1 {
    pub fn try_from_provisioned(root: PathBuf) -> Result<Self, ReplayStoreLocationErrorV1> {
        let root = TrustedLocalStoreRootV1::try_from_provisioned(root)?;
        ensure_empty(root.path()).map_err(|_| ReplayStoreLocationErrorV1::LocationNotDedicated)?;
        Ok(Self { root })
    }

    pub fn into_store_root(self) -> TrustedLocalStoreRootV1 {
        self.root
    }
}

impl fmt::Debug for TrustedEmptyLocalRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedEmptyLocalRootV1")
            .finish_non_exhaustive()
    }
}

/// Checked replay-store configuration. Durability and schema settings are fixed by v1.
#[derive(Clone)]
pub struct ReplayStoreConfigV1 {
    root: TrustedLocalStoreRootV1,
    maximum_busy_wait_ms: u64,
    backup_step_pages: u32,
    backup_retry_wait_ms: u64,
}

impl ReplayStoreConfigV1 {
    pub fn try_new(
        root: TrustedLocalStoreRootV1,
        maximum_busy_wait_ms: u64,
        backup_step_pages: u32,
        backup_retry_wait_ms: u64,
    ) -> Result<Self, ReplayStoreConfigErrorV1> {
        if !(1..=MAX_SAFE_U64).contains(&maximum_busy_wait_ms) {
            return Err(ReplayStoreConfigErrorV1::InvalidBusyBound);
        }
        if !(1..=MAX_BACKUP_STEP_PAGES).contains(&backup_step_pages) {
            return Err(ReplayStoreConfigErrorV1::InvalidBackupStep);
        }
        if backup_retry_wait_ms > MAX_BACKUP_RETRY_WAIT_MS {
            return Err(ReplayStoreConfigErrorV1::InvalidBackupWait);
        }
        Ok(Self {
            root,
            maximum_busy_wait_ms,
            backup_step_pages,
            backup_retry_wait_ms,
        })
    }

    pub(crate) fn root(&self) -> &TrustedLocalStoreRootV1 {
        &self.root
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.root.database_path()
    }

    pub(crate) const fn maximum_busy_wait_ms(&self) -> u64 {
        self.maximum_busy_wait_ms
    }

    pub(crate) const fn backup_step_pages(&self) -> u32 {
        self.backup_step_pages
    }

    pub(crate) const fn backup_retry_wait_ms(&self) -> u64 {
        self.backup_retry_wait_ms
    }
}

impl fmt::Debug for ReplayStoreConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayStoreConfigV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn roots_are_same(left: &Path, right: &Path) -> bool {
    left == right
}

pub(crate) fn revalidate_live_root(
    root: &TrustedLocalStoreRootV1,
) -> Result<(), ReplayStoreLocationErrorV1> {
    validate_root_syntax(root.path())?;
    validate_live_contents(root.path())
}

pub(crate) fn revalidate_backup_root(
    root: &TrustedLocalStoreRootV1,
) -> Result<(), ReplayStoreLocationErrorV1> {
    validate_root_syntax(root.path())?;
    validate_backup_contents(root.path())
}

pub(crate) fn backup_database_path(root: &TrustedLocalStoreRootV1) -> PathBuf {
    root.path().join(BACKUP_DATABASE_FILENAME)
}

pub(crate) fn backup_manifest_path(root: &TrustedLocalStoreRootV1) -> PathBuf {
    root.path().join(BACKUP_MANIFEST_FILENAME)
}

pub(crate) fn ensure_empty(root: &Path) -> std::io::Result<()> {
    let mut entries = fs::read_dir(root)?;
    if entries.next().transpose()?.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "dedicated destination is not empty",
        ));
    }
    Ok(())
}

fn validate_root_syntax(root: &Path) -> Result<(), ReplayStoreLocationErrorV1> {
    if !root.is_absolute() || root.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(ReplayStoreLocationErrorV1::LocationInvalid);
    }
    let metadata = fs::metadata(root).map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
    if !metadata.is_dir() {
        return Err(ReplayStoreLocationErrorV1::LocationInvalid);
    }
    Ok(())
}

fn validate_live_contents(root: &Path) -> Result<(), ReplayStoreLocationErrorV1> {
    let entries = fs::read_dir(root).map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
    let mut database_present = false;
    let mut lock_present = false;
    let mut live_initialization_intent_present = false;
    let mut quarantine_present = false;
    let mut activation_present = false;
    let mut count = 0_u8;
    for entry in entries {
        let entry = entry.map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
        let file_type = entry
            .file_type()
            .map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
        let name = entry.file_name();
        let allowed = is_live_filename(&name);
        if !allowed || !file_type.is_file() {
            return Err(ReplayStoreLocationErrorV1::LocationNotDedicated);
        }
        count = count
            .checked_add(1)
            .ok_or(ReplayStoreLocationErrorV1::LocationNotDedicated)?;
        database_present |= name == OsStr::new(DATABASE_FILENAME);
        lock_present |= name == OsStr::new(ROOT_LOCK_FILENAME);
        live_initialization_intent_present |=
            name == OsStr::new(LIVE_INITIALIZATION_INTENT_FILENAME);
        quarantine_present |= name == OsStr::new(QUARANTINE_MARKER_FILENAME);
        activation_present |= name == OsStr::new(RESTORED_ACTIVATION_MARKER_FILENAME);
    }
    if count == 0 {
        return Ok(());
    }
    if database_present && !lock_present {
        return Err(ReplayStoreLocationErrorV1::LocationNotDedicated);
    }
    if !database_present {
        let valid_transient_or_empty_live_state = (lock_present
            && !live_initialization_intent_present
            && !activation_present
            && !quarantine_present
            && count == 1)
            || (!lock_present
                && live_initialization_intent_present
                && !activation_present
                && !quarantine_present
                && count == 1)
            || (lock_present
                && live_initialization_intent_present
                && !activation_present
                && !quarantine_present
                && count == 2)
            || (lock_present
                && !live_initialization_intent_present
                && activation_present
                && !quarantine_present
                && count == 2);
        if !valid_transient_or_empty_live_state {
            return Err(ReplayStoreLocationErrorV1::LocationNotDedicated);
        }
    }
    Ok(())
}

fn validate_provisioned_contents(root: &Path) -> Result<(), ReplayStoreLocationErrorV1> {
    if ensure_empty(root).is_ok() {
        return Ok(());
    }
    if validate_live_contents(root).is_ok() || validate_backup_contents(root).is_ok() {
        return Ok(());
    }
    Err(ReplayStoreLocationErrorV1::LocationNotDedicated)
}

fn validate_backup_contents(root: &Path) -> Result<(), ReplayStoreLocationErrorV1> {
    let entries = fs::read_dir(root).map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
    let mut database_present = false;
    let mut manifest_present = false;
    let mut lock_present = false;
    let mut count = 0_u8;
    for entry in entries {
        let entry = entry.map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
        let file_type = entry
            .file_type()
            .map_err(|_| ReplayStoreLocationErrorV1::LocationInvalid)?;
        if !file_type.is_file() {
            return Err(ReplayStoreLocationErrorV1::LocationNotDedicated);
        }
        count = count
            .checked_add(1)
            .ok_or(ReplayStoreLocationErrorV1::LocationNotDedicated)?;
        let name = entry.file_name();
        if name == OsStr::new(BACKUP_DATABASE_FILENAME) {
            database_present = true;
        } else if name == OsStr::new(BACKUP_MANIFEST_FILENAME) {
            manifest_present = true;
        } else if name == OsStr::new(ROOT_LOCK_FILENAME) {
            lock_present = true;
        } else {
            return Err(ReplayStoreLocationErrorV1::LocationNotDedicated);
        }
    }
    if count != 3 || !database_present || !manifest_present || !lock_present {
        return Err(ReplayStoreLocationErrorV1::LocationNotDedicated);
    }
    Ok(())
}

fn is_live_filename(name: &OsStr) -> bool {
    name == OsStr::new(DATABASE_FILENAME)
        || name == OsStr::new(WAL_FILENAME)
        || name == OsStr::new(SHM_FILENAME)
        || name == OsStr::new(ROLLBACK_JOURNAL_FILENAME)
        || name == OsStr::new(ROOT_LOCK_FILENAME)
        || name == OsStr::new(LIVE_INITIALIZATION_INTENT_FILENAME)
        || name == OsStr::new(QUARANTINE_MARKER_FILENAME)
        || name == OsStr::new(RESTORED_ACTIVATION_MARKER_FILENAME)
}
