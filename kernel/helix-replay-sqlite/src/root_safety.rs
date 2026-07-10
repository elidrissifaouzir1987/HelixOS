use crate::clock::remaining_monotonic_ms;
use crate::config::{
    ensure_empty, TrustedLocalStoreRootV1, DATABASE_FILENAME, LIVE_INITIALIZATION_INTENT_FILENAME,
    QUARANTINE_MARKER_FILENAME, RESTORED_ACTIVATION_MARKER_FILENAME, ROOT_LOCK_FILENAME,
};
use crate::error::InternalStoreError;
use crate::ReplayMonotonicClockV1;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

const LIVE_ROOT_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=LIVE_READY\n";
const BACKUP_ROOT_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=BACKUP_PACKAGE\n";
const RESTORE_ROOT_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=RESTORE_PENDING\n";
const QUARANTINE_MARKER_CONTENT: &[u8] = b"HELIXOS_REPLAY_QUARANTINE_V1\n";
const RESTORED_ACTIVATION_MARKER_CONTENT: &[u8] =
    b"HELIXOS_REPLAY_RESTORED_ACTIVATION_REQUIRED_V1\n";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootStateV1 {
    LiveReady,
    LiveQuarantined,
    BackupPackage,
    RestorePending,
}

impl RootStateV1 {
    const fn content(self) -> &'static [u8] {
        match self {
            Self::LiveReady => LIVE_ROOT_LOCK_CONTENT,
            Self::LiveQuarantined => b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=LIVE_QUARANTINED\n",
            Self::BackupPackage => BACKUP_ROOT_LOCK_CONTENT,
            Self::RestorePending => RESTORE_ROOT_LOCK_CONTENT,
        }
    }
}

/// An exclusive advisory lease understood by cooperating Helix processes.
///
/// The native file handle owns the lock and releases it when this value drops.
/// This is not a mandatory OS sandbox boundary.
pub(crate) struct RootLeaseV1 {
    file: File,
}

impl RootLeaseV1 {
    pub(crate) fn verify_state(&mut self, state: RootStateV1) -> Result<(), InternalStoreError> {
        verify_exact_file(&mut self.file, state.content())
    }

    pub(crate) fn transition_live_to_quarantined(&mut self) -> Result<(), InternalStoreError> {
        self.verify_state(RootStateV1::LiveReady)?;
        self.file
            .set_len(0)
            .and_then(|()| self.file.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| self.file.write_all(RootStateV1::LiveQuarantined.content()))
            .and_then(|()| self.file.sync_all())
            .map_err(|_| InternalStoreError::StoreUnavailable)?;
        self.verify_state(RootStateV1::LiveQuarantined)
    }
}

pub(crate) fn acquire_live_root_lease<C: ReplayMonotonicClockV1>(
    root: &TrustedLocalStoreRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<RootLeaseV1, InternalStoreError> {
    acquire_or_create_root_lease(
        root,
        RootStateV1::LiveReady,
        maximum_wait_ms,
        clock,
        deadline_monotonic_ms,
    )
}

pub(crate) fn acquire_checked_live_root_lease<C: ReplayMonotonicClockV1>(
    root: &TrustedLocalStoreRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<RootLeaseV1, InternalStoreError> {
    let lease = acquire_live_root_lease(root, maximum_wait_ms, clock, deadline_monotonic_ms)?;
    check_live_root_markers(root)?;
    Ok(lease)
}

pub(crate) fn acquire_backup_package_lease<C: ReplayMonotonicClockV1>(
    root: &TrustedLocalStoreRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<RootLeaseV1, InternalStoreError> {
    acquire_existing_root_lease(
        root,
        RootStateV1::BackupPackage,
        maximum_wait_ms,
        clock,
        deadline_monotonic_ms,
    )
}

pub(crate) fn reserve_new_destination_root<C: ReplayMonotonicClockV1>(
    root: &TrustedLocalStoreRootV1,
    state: RootStateV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<RootLeaseV1, InternalStoreError> {
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    ensure_empty(root.path()).map_err(|_| InternalStoreError::DestinationNotEmpty)?;
    let path = root.path().join(ROOT_LOCK_FILENAME);
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(InternalStoreError::DestinationNotEmpty)
        }
        Err(_) => return Err(InternalStoreError::StoreUnavailable),
    };
    file.try_lock()
        .map_err(|_| InternalStoreError::StoreUnavailable)?;
    write_and_sync_exact(&mut file, state.content())?;
    Ok(RootLeaseV1 { file })
}

fn acquire_or_create_root_lease<C: ReplayMonotonicClockV1>(
    root: &TrustedLocalStoreRootV1,
    state: RootStateV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<RootLeaseV1, InternalStoreError> {
    let path = root.path().join(ROOT_LOCK_FILENAME);
    if state == RootStateV1::LiveReady {
        prepare_live_initialization_intent(root, &path)?;
    }
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            match file.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => {
                    drop(file);
                    let lease = acquire_existing_root_lease(
                        root,
                        state,
                        maximum_wait_ms,
                        clock,
                        deadline_monotonic_ms,
                    )?;
                    if state == RootStateV1::LiveReady {
                        consume_live_initialization_intent(root)?;
                    }
                    return Ok(lease);
                }
                Err(TryLockError::Error(_)) => return Err(InternalStoreError::StoreUnavailable),
            }
            verify_or_repair_locked_root_role(root, state, &mut file)?;
            if state == RootStateV1::LiveReady {
                consume_live_initialization_intent(root)?;
            }
            remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
            Ok(RootLeaseV1 { file })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let lease = acquire_existing_root_lease(
                root,
                state,
                maximum_wait_ms,
                clock,
                deadline_monotonic_ms,
            )?;
            if state == RootStateV1::LiveReady {
                consume_live_initialization_intent(root)?;
            }
            Ok(lease)
        }
        Err(_) => Err(InternalStoreError::StoreUnavailable),
    }
}

fn acquire_existing_root_lease<C: ReplayMonotonicClockV1>(
    root: &TrustedLocalStoreRootV1,
    state: RootStateV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<RootLeaseV1, InternalStoreError> {
    let initial_remaining = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    let attempts = initial_remaining.min(maximum_wait_ms).max(1);
    let path = root.path().join(ROOT_LOCK_FILENAME);
    reject_non_regular_file(&path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| InternalStoreError::StoreUnavailable)?;

    for attempt in 0..attempts {
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        match file.try_lock() {
            Ok(()) => {
                verify_or_repair_locked_root_role(root, state, &mut file)?;
                return Ok(RootLeaseV1 { file });
            }
            Err(TryLockError::WouldBlock) if attempt + 1 < attempts => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => return Err(InternalStoreError::StoreBusy),
            Err(TryLockError::Error(_)) => return Err(InternalStoreError::StoreUnavailable),
        }
    }
    Err(InternalStoreError::StoreBusy)
}

/// Accepts a role another initializer published before this lock holder ran,
/// or completes only the exact empty live-initialization reservation.
/// Unknown or partially published role contents are never overwritten.
fn verify_or_repair_locked_root_role(
    root: &TrustedLocalStoreRootV1,
    state: RootStateV1,
    file: &mut File,
) -> Result<(), InternalStoreError> {
    match verify_exact_file(file, state.content()) {
        Ok(()) => Ok(()),
        Err(InternalStoreError::LocationNotDedicated) => {
            let recoverable_empty_live_reservation = state == RootStateV1::LiveReady
                && root_contains_exact_live_reservation(root.path(), file)?;
            if !recoverable_empty_live_reservation {
                return Err(InternalStoreError::LocationNotDedicated);
            }
            file.set_len(0)
                .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
                .map_err(|_| InternalStoreError::StoreUnavailable)?;
            write_and_sync_exact(file, state.content())
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn check_live_root_markers(
    root: &TrustedLocalStoreRootV1,
) -> Result<(), InternalStoreError> {
    check_absent_or_exact_blocking_marker(
        &root.path().join(QUARANTINE_MARKER_FILENAME),
        QUARANTINE_MARKER_CONTENT,
    )?;
    check_absent_or_exact_blocking_marker(
        &root.path().join(RESTORED_ACTIVATION_MARKER_FILENAME),
        RESTORED_ACTIVATION_MARKER_CONTENT,
    )?;
    Ok(())
}

pub(crate) fn quarantine_with_held_live_lease(
    lease: &mut RootLeaseV1,
    root: &TrustedLocalStoreRootV1,
) -> Result<(), InternalStoreError> {
    reject_non_regular_file(&root.path().join(DATABASE_FILENAME))?;
    lease.transition_live_to_quarantined()?;
    publish_fixed_marker(
        &root.path().join(QUARANTINE_MARKER_FILENAME),
        QUARANTINE_MARKER_CONTENT,
    )
}

pub(crate) fn quarantine_unopenable_live_root<C: ReplayMonotonicClockV1>(
    root: &TrustedLocalStoreRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<(), InternalStoreError> {
    reject_non_regular_file(&root.path().join(DATABASE_FILENAME))?;
    let mut lease = acquire_live_root_lease(root, maximum_wait_ms, clock, deadline_monotonic_ms)?;
    quarantine_with_held_live_lease(&mut lease, root)
}

pub(crate) fn publish_restored_activation_marker(
    root: &TrustedLocalStoreRootV1,
) -> Result<(), InternalStoreError> {
    publish_fixed_marker(
        &root.path().join(RESTORED_ACTIVATION_MARKER_FILENAME),
        RESTORED_ACTIVATION_MARKER_CONTENT,
    )
}

pub(crate) fn verify_restored_activation_marker(
    root: &TrustedLocalStoreRootV1,
) -> Result<(), InternalStoreError> {
    let path = root.path().join(RESTORED_ACTIVATION_MARKER_FILENAME);
    let mut file = open_regular_file(&path)?;
    verify_exact_file(&mut file, RESTORED_ACTIVATION_MARKER_CONTENT)
}

fn check_absent_or_exact_blocking_marker(
    path: &Path,
    expected: &[u8],
) -> Result<(), InternalStoreError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InternalStoreError::StoreUnavailable),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(InternalStoreError::LocationNotDedicated)
        }
        Ok(_) => {
            let mut file = File::open(path).map_err(|_| InternalStoreError::StoreUnavailable)?;
            verify_exact_file(&mut file, expected)?;
            Err(InternalStoreError::StoreUnavailable)
        }
    }
}

fn publish_fixed_marker(path: &Path, contents: &[u8]) -> Result<(), InternalStoreError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file
            .write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|_| InternalStoreError::StoreUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut file = open_regular_file(path)?;
            verify_exact_file(&mut file, contents)
        }
        Err(_) => Err(InternalStoreError::StoreUnavailable),
    }
}

fn write_and_sync_exact(file: &mut File, contents: &[u8]) -> Result<(), InternalStoreError> {
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| InternalStoreError::StoreUnavailable)?;
    verify_exact_file(file, contents)
}

fn verify_exact_file(file: &mut File, expected: &[u8]) -> Result<(), InternalStoreError> {
    let expected_len =
        u64::try_from(expected.len()).map_err(|_| InternalStoreError::StoreUnavailable)?;
    if file
        .metadata()
        .map_err(|_| InternalStoreError::StoreUnavailable)?
        .len()
        != expected_len
    {
        return Err(InternalStoreError::LocationNotDedicated);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InternalStoreError::StoreUnavailable)?;
    let mut actual = Vec::with_capacity(expected.len());
    file.read_to_end(&mut actual)
        .map_err(|_| InternalStoreError::StoreUnavailable)?;
    if actual != expected {
        return Err(InternalStoreError::LocationNotDedicated);
    }
    Ok(())
}

fn reject_non_regular_file(path: &Path) -> Result<(), InternalStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InternalStoreError::StoreUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InternalStoreError::LocationNotDedicated);
    }
    Ok(())
}

fn open_regular_file(path: &Path) -> Result<File, InternalStoreError> {
    reject_non_regular_file(path)?;
    File::open(path).map_err(|_| InternalStoreError::StoreUnavailable)
}

fn prepare_live_initialization_intent(
    root: &TrustedLocalStoreRootV1,
    root_lock_path: &Path,
) -> Result<(), InternalStoreError> {
    if root_lock_path.exists() {
        return Ok(());
    }
    let intent_path = root.path().join(LIVE_INITIALIZATION_INTENT_FILENAME);
    if !intent_path.exists() {
        if ensure_empty(root.path()).is_err() {
            if root_lock_path.exists() {
                return Ok(());
            }
            if !intent_path.exists() {
                return Err(InternalStoreError::LocationNotDedicated);
            }
        }
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&intent_path)
        {
            Ok(file) => file
                .sync_all()
                .map_err(|_| InternalStoreError::StoreUnavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(InternalStoreError::StoreUnavailable),
        }
    }
    if root_lock_path.exists() || root_contains_only_regular_live_intent(root.path())? {
        Ok(())
    } else {
        Err(InternalStoreError::LocationNotDedicated)
    }
}

fn consume_live_initialization_intent(
    root: &TrustedLocalStoreRootV1,
) -> Result<(), InternalStoreError> {
    let path = root.path().join(LIVE_INITIALIZATION_INTENT_FILENAME);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(InternalStoreError::StoreUnavailable),
        Ok(metadata)
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 0 =>
        {
            Err(InternalStoreError::LocationNotDedicated)
        }
        Ok(_) => fs::remove_file(path).map_err(|_| InternalStoreError::StoreUnavailable),
    }
}

fn root_contains_only_regular_live_intent(root: &Path) -> Result<bool, InternalStoreError> {
    Ok(
        root_contains_exact_regular_names(root, &[LIVE_INITIALIZATION_INTENT_FILENAME])?
            && live_initialization_intent_is_empty(root)?,
    )
}

fn root_contains_exact_live_reservation(
    root: &Path,
    locked_role: &File,
) -> Result<bool, InternalStoreError> {
    let locked_metadata = locked_role
        .metadata()
        .map_err(|_| InternalStoreError::StoreUnavailable)?;
    let published_metadata = fs::symlink_metadata(root.join(ROOT_LOCK_FILENAME))
        .map_err(|_| InternalStoreError::StoreUnavailable)?;
    Ok(locked_metadata.is_file()
        && locked_metadata.len() == 0
        && !published_metadata.file_type().is_symlink()
        && published_metadata.is_file()
        && published_metadata.len() == 0
        && root_contains_exact_regular_names(
            root,
            &[LIVE_INITIALIZATION_INTENT_FILENAME, ROOT_LOCK_FILENAME],
        )?
        && live_initialization_intent_is_empty(root)?)
}

fn live_initialization_intent_is_empty(root: &Path) -> Result<bool, InternalStoreError> {
    let metadata = fs::symlink_metadata(root.join(LIVE_INITIALIZATION_INTENT_FILENAME))
        .map_err(|_| InternalStoreError::StoreUnavailable)?;
    Ok(!metadata.file_type().is_symlink() && metadata.is_file() && metadata.len() == 0)
}

fn root_contains_exact_regular_names(
    root: &Path,
    expected_names: &[&str],
) -> Result<bool, InternalStoreError> {
    let mut entries = fs::read_dir(root).map_err(|_| InternalStoreError::StoreUnavailable)?;
    let mut actual_names = Vec::with_capacity(expected_names.len());
    for entry in &mut entries {
        let entry = entry.map_err(|_| InternalStoreError::StoreUnavailable)?;
        let file_type = entry
            .file_type()
            .map_err(|_| InternalStoreError::StoreUnavailable)?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Ok(false);
        }
        actual_names.push(entry.file_name());
        if actual_names.len() > expected_names.len() {
            return Ok(false);
        }
    }
    if actual_names.len() != expected_names.len() {
        return Ok(false);
    }
    Ok(expected_names.iter().all(|expected| {
        actual_names
            .iter()
            .any(|actual| actual == std::ffi::OsStr::new(expected))
    }))
}

#[cfg(test)]
mod tests;
