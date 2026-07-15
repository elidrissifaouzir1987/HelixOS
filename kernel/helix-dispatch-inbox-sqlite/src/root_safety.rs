//! Dedicated adapter-root identity and publication custody.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const ADAPTER_DATABASE_FILENAME: &str = "dispatch-inbox.sqlite3";
pub(crate) const ADAPTER_WAL_FILENAME: &str = "dispatch-inbox.sqlite3-wal";
pub(crate) const ADAPTER_SHM_FILENAME: &str = "dispatch-inbox.sqlite3-shm";
pub(crate) const ADAPTER_ROOT_MARKER_FILENAME: &str = ".helix-dispatch-inbox-root-v1";

const ROOT_MARKER_PREFIX: &[u8] = b"HELIXOS_DISPATCH_INBOX_ROOT_V1\nROOT_IDENTITY=";
const INITIALIZING_SUFFIX: &[u8] = b"\nSTATE=INITIALIZING\n";
const RESTORE_INITIALIZING_SUFFIX_PREFIX: &[u8] = b"\nSTATE=RESTORE_INITIALIZING\nATTEMPT_DIGEST=";
const EXISTING_SUFFIX: &[u8] = b"\nSTATE=EXISTING\n";
const HEX_IDENTITY_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterRootSafetyErrorV1 {
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    UnknownRootMember,
    RootUnavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdapterRootIdentityV1([u8; 32]);

impl AdapterRootIdentityV1 {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AdapterRootIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterRootIdentityV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct FilesystemIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u32,
    #[cfg(windows)]
    file_index: u64,
}

/// Provisioner-attested dedicated root that is empty or recovering initialization.
#[derive(Clone)]
pub(crate) struct ProvisionedEmptyAdapterRootV1 {
    path: PathBuf,
    directory_identity: FilesystemIdentityV1,
    provisioned_identity: AdapterRootIdentityV1,
}

impl ProvisionedEmptyAdapterRootV1 {
    pub(crate) fn try_from_provisioned(
        path: PathBuf,
        provisioned_identity: AdapterRootIdentityV1,
    ) -> Result<Self, AdapterRootSafetyErrorV1> {
        let (path, directory_identity) = validate_provisioned_directory(path)?;
        validate_empty_or_initializing_members(&path, provisioned_identity)?;
        Ok(Self {
            path,
            directory_identity,
            provisioned_identity,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn provisioned_identity(&self) -> AdapterRootIdentityV1 {
        self.provisioned_identity
    }

    pub(crate) fn revalidate(&self) -> Result<(), AdapterRootSafetyErrorV1> {
        revalidate_directory_identity(&self.path, &self.directory_identity)?;
        validate_empty_or_initializing_members(&self.path, self.provisioned_identity)
    }
}

impl fmt::Debug for ProvisionedEmptyAdapterRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedEmptyAdapterRootV1")
            .finish_non_exhaustive()
    }
}

/// Provisioner-attested dedicated root whose exact identity is already published.
#[derive(Clone)]
pub(crate) struct ProvisionedExistingAdapterRootV1 {
    path: PathBuf,
    directory_identity: FilesystemIdentityV1,
    marker_identity: FilesystemIdentityV1,
    database_identity: FilesystemIdentityV1,
    expected_identity: AdapterRootIdentityV1,
}

impl ProvisionedExistingAdapterRootV1 {
    pub(crate) fn try_from_provisioned(
        path: PathBuf,
        expected_identity: AdapterRootIdentityV1,
    ) -> Result<Self, AdapterRootSafetyErrorV1> {
        let (path, directory_identity) = validate_provisioned_directory(path)?;
        validate_existing_members(&path, expected_identity)?;
        let marker_identity = regular_file_identity(&path.join(ADAPTER_ROOT_MARKER_FILENAME))?;
        let database_identity = regular_file_identity(&path.join(ADAPTER_DATABASE_FILENAME))?;
        Ok(Self {
            path,
            directory_identity,
            marker_identity,
            database_identity,
            expected_identity,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn expected_identity(&self) -> AdapterRootIdentityV1 {
        self.expected_identity
    }

    pub(crate) fn revalidate(&self) -> Result<(), AdapterRootSafetyErrorV1> {
        revalidate_directory_identity(&self.path, &self.directory_identity)?;
        validate_existing_members(&self.path, self.expected_identity)?;
        if regular_file_identity(&self.path.join(ADAPTER_ROOT_MARKER_FILENAME))?
            != self.marker_identity
            || regular_file_identity(&self.path.join(ADAPTER_DATABASE_FILENAME))?
                != self.database_identity
        {
            return Err(AdapterRootSafetyErrorV1::RootRoleMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ProvisionedExistingAdapterRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedExistingAdapterRootV1")
            .finish_non_exhaustive()
    }
}

/// Identity-bound custody for one imported database under a RESTORE_INITIALIZING marker.
///
/// The provisioned root alone binds the directory and marker contents. Restore additionally
/// retains the marker and database file identities so an import cannot be replaced between
/// verification, the local RESTORE_PENDING commit and marker publication.
pub(crate) struct AdapterInitializingRestoreRootCustodyV1 {
    root: ProvisionedEmptyAdapterRootV1,
    marker_identity: FilesystemIdentityV1,
    database_identity: FilesystemIdentityV1,
    restore_attempt_digest: [u8; 32],
}

impl AdapterInitializingRestoreRootCustodyV1 {
    pub(crate) fn database_path_v1(&self) -> Result<PathBuf, AdapterRootSafetyErrorV1> {
        self.revalidate_v1()?;
        Ok(self.root.path.join(ADAPTER_DATABASE_FILENAME))
    }

    pub(crate) fn revalidate_v1(&self) -> Result<(), AdapterRootSafetyErrorV1> {
        self.root.revalidate()?;
        validate_initializing_members(&self.root.path, self.root.provisioned_identity)?;
        verify_marker(
            &self.root.path.join(ADAPTER_ROOT_MARKER_FILENAME),
            self.root.provisioned_identity,
            RootMarkerRoleV1::RestoreInitializing(self.restore_attempt_digest),
        )?;
        if regular_file_identity(&self.root.path.join(ADAPTER_ROOT_MARKER_FILENAME))?
            != self.marker_identity
            || regular_file_identity(&self.root.path.join(ADAPTER_DATABASE_FILENAME))?
                != self.database_identity
        {
            return Err(AdapterRootSafetyErrorV1::RootRoleMismatch);
        }
        Ok(())
    }

    pub(crate) fn publish_existing_v1(
        self,
    ) -> Result<ProvisionedExistingAdapterRootV1, AdapterRootSafetyErrorV1> {
        self.revalidate_v1()?;
        publish_restore_existing_marker(&self.root, self.restore_attempt_digest)?;
        ProvisionedExistingAdapterRootV1::try_from_provisioned(
            self.root.path,
            self.root.provisioned_identity,
        )
    }
}

impl fmt::Debug for AdapterInitializingRestoreRootCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInitializingRestoreRootCustodyV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn ensure_initializing_marker(
    root: &ProvisionedEmptyAdapterRootV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    root.revalidate()?;
    let marker_path = root.path.join(ADAPTER_ROOT_MARKER_FILENAME);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
    {
        Ok(mut marker) => {
            marker
                .write_all(&marker_bytes(
                    root.provisioned_identity,
                    RootMarkerRoleV1::Initializing,
                ))
                .and_then(|()| marker.sync_all())
                .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
            sync_root_directory(root.path())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_marker(
                &marker_path,
                root.provisioned_identity,
                RootMarkerRoleV1::Initializing,
            )?;
        }
        Err(_) => return Err(AdapterRootSafetyErrorV1::RootUnavailable),
    }
    root.revalidate()
}

/// Creates or verifies a restore-only marker bound to the exact signed attempt.
pub(crate) fn ensure_restore_initializing_marker(
    root: &ProvisionedEmptyAdapterRootV1,
    restore_attempt_digest: [u8; 32],
) -> Result<(), AdapterRootSafetyErrorV1> {
    root.revalidate()?;
    let marker_path = root.path.join(ADAPTER_ROOT_MARKER_FILENAME);
    let role = RootMarkerRoleV1::RestoreInitializing(restore_attempt_digest);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
    {
        Ok(mut marker) => {
            marker
                .write_all(&marker_bytes(root.provisioned_identity, role))
                .and_then(|()| marker.sync_all())
                .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
            sync_root_directory(root.path())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_marker(&marker_path, root.provisioned_identity, role)?;
        }
        Err(_) => return Err(AdapterRootSafetyErrorV1::RootUnavailable),
    }
    root.revalidate()?;
    verify_marker(&marker_path, root.provisioned_identity, role)
}

pub(crate) fn publish_existing_marker(
    root: &ProvisionedEmptyAdapterRootV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    publish_existing_marker_from_role(root, RootMarkerRoleV1::Initializing)
}

fn publish_restore_existing_marker(
    root: &ProvisionedEmptyAdapterRootV1,
    restore_attempt_digest: [u8; 32],
) -> Result<(), AdapterRootSafetyErrorV1> {
    publish_existing_marker_from_role(
        root,
        RootMarkerRoleV1::RestoreInitializing(restore_attempt_digest),
    )
}

fn publish_existing_marker_from_role(
    root: &ProvisionedEmptyAdapterRootV1,
    expected_role: RootMarkerRoleV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    revalidate_directory_identity(root.path(), &root.directory_identity)?;
    validate_initializing_members(root.path(), root.provisioned_identity)?;
    let path = root.path.join(ADAPTER_ROOT_MARKER_FILENAME);
    let mut marker = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    verify_marker_handle(&mut marker, root.provisioned_identity, expected_role)?;
    marker
        .seek(SeekFrom::Start(0))
        .and_then(|_| marker.set_len(0))
        .and_then(|()| {
            marker.write_all(&marker_bytes(
                root.provisioned_identity,
                RootMarkerRoleV1::Existing,
            ))
        })
        .and_then(|()| marker.sync_all())
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    sync_root_directory(root.path())?;
    validate_existing_members(root.path(), root.provisioned_identity)
}

pub(crate) fn initialization_database_present(
    root: &ProvisionedEmptyAdapterRootV1,
) -> Result<bool, AdapterRootSafetyErrorV1> {
    root.revalidate()?;
    root.path
        .join(ADAPTER_DATABASE_FILENAME)
        .try_exists()
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)
}

pub(crate) fn reserve_database_file(
    root: &ProvisionedEmptyAdapterRootV1,
) -> Result<File, AdapterRootSafetyErrorV1> {
    root.revalidate()?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.path.join(ADAPTER_DATABASE_FILENAME))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AdapterRootSafetyErrorV1::RootRoleMismatch
            } else {
                AdapterRootSafetyErrorV1::RootUnavailable
            }
        })
}

/// Captures the exact imported database and marker before any restore transaction starts.
pub(crate) fn bind_initializing_restore_root_v1(
    root: &ProvisionedEmptyAdapterRootV1,
    restore_attempt_digest: [u8; 32],
) -> Result<AdapterInitializingRestoreRootCustodyV1, AdapterRootSafetyErrorV1> {
    root.revalidate()?;
    validate_initializing_members(root.path(), root.provisioned_identity())?;
    verify_marker(
        &root.path.join(ADAPTER_ROOT_MARKER_FILENAME),
        root.provisioned_identity(),
        RootMarkerRoleV1::RestoreInitializing(restore_attempt_digest),
    )?;
    let custody = AdapterInitializingRestoreRootCustodyV1 {
        root: root.clone(),
        marker_identity: regular_file_identity(&root.path.join(ADAPTER_ROOT_MARKER_FILENAME))?,
        database_identity: regular_file_identity(&root.path.join(ADAPTER_DATABASE_FILENAME))?,
        restore_attempt_digest,
    };
    custody.revalidate_v1()?;
    Ok(custody)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootMarkerRoleV1 {
    Initializing,
    RestoreInitializing([u8; 32]),
    Existing,
}

fn validate_provisioned_directory(
    path: PathBuf,
) -> Result<(PathBuf, FilesystemIdentityV1), AdapterRootSafetyErrorV1> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(AdapterRootSafetyErrorV1::RootInvalid);
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| AdapterRootSafetyErrorV1::RootInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdapterRootSafetyErrorV1::RootInvalid);
    }
    let canonical = fs::canonicalize(path).map_err(|_| AdapterRootSafetyErrorV1::RootInvalid)?;
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|_| AdapterRootSafetyErrorV1::RootInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdapterRootSafetyErrorV1::RootInvalid);
    }
    let identity = filesystem_identity(&metadata)?;
    Ok((canonical, identity))
}

fn revalidate_directory_identity(
    path: &Path,
    expected: &FilesystemIdentityV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdapterRootSafetyErrorV1::RootNotDedicated);
    }
    if &filesystem_identity(&metadata)? != expected {
        return Err(AdapterRootSafetyErrorV1::RootRoleMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RootMembersV1 {
    database: bool,
    marker: bool,
    wal: bool,
    shm: bool,
}

fn scan_known_members(root: &Path) -> Result<RootMembersV1, AdapterRootSafetyErrorV1> {
    let mut members = RootMembersV1 {
        database: false,
        marker: false,
        wal: false,
        shm: false,
    };
    let entries = fs::read_dir(root).map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
        let file_type = entry
            .file_type()
            .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
        if !file_type.is_file() {
            return Err(AdapterRootSafetyErrorV1::RootNotDedicated);
        }
        let name = entry.file_name();
        let slot = if name == OsStr::new(ADAPTER_DATABASE_FILENAME) {
            &mut members.database
        } else if name == OsStr::new(ADAPTER_ROOT_MARKER_FILENAME) {
            &mut members.marker
        } else if name == OsStr::new(ADAPTER_WAL_FILENAME) {
            &mut members.wal
        } else if name == OsStr::new(ADAPTER_SHM_FILENAME) {
            &mut members.shm
        } else {
            return Err(AdapterRootSafetyErrorV1::UnknownRootMember);
        };
        if *slot {
            return Err(AdapterRootSafetyErrorV1::RootNotDedicated);
        }
        *slot = true;
    }
    Ok(members)
}

fn validate_empty_or_initializing_members(
    root: &Path,
    identity: AdapterRootIdentityV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    let members = scan_known_members(root)?;
    if !members.marker && !members.database && !members.wal && !members.shm {
        return Ok(());
    }
    validate_initializing_snapshot(members)?;
    verify_any_initializing_marker(&root.join(ADAPTER_ROOT_MARKER_FILENAME), identity)
}

fn validate_initializing_members(
    root: &Path,
    identity: AdapterRootIdentityV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    let members = scan_known_members(root)?;
    validate_initializing_snapshot(members)?;
    if !members.database {
        return Err(AdapterRootSafetyErrorV1::RootRoleMismatch);
    }
    verify_any_initializing_marker(&root.join(ADAPTER_ROOT_MARKER_FILENAME), identity)
}

fn validate_initializing_snapshot(members: RootMembersV1) -> Result<(), AdapterRootSafetyErrorV1> {
    if !members.marker || (members.wal || members.shm) && !members.database {
        return Err(AdapterRootSafetyErrorV1::RootRoleMismatch);
    }
    Ok(())
}

fn validate_existing_members(
    root: &Path,
    identity: AdapterRootIdentityV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    let members = scan_known_members(root)?;
    if !members.marker || !members.database {
        return Err(AdapterRootSafetyErrorV1::RootRoleMismatch);
    }
    verify_marker(
        &root.join(ADAPTER_ROOT_MARKER_FILENAME),
        identity,
        RootMarkerRoleV1::Existing,
    )
}

fn marker_bytes(identity: AdapterRootIdentityV1, role: RootMarkerRoleV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ROOT_MARKER_PREFIX.len() + HEX_IDENTITY_LENGTH * 2 + 64);
    bytes.extend_from_slice(ROOT_MARKER_PREFIX);
    push_lower_hex(&mut bytes, identity.as_bytes());
    match role {
        RootMarkerRoleV1::Initializing => bytes.extend_from_slice(INITIALIZING_SUFFIX),
        RootMarkerRoleV1::RestoreInitializing(digest) => {
            bytes.extend_from_slice(RESTORE_INITIALIZING_SUFFIX_PREFIX);
            push_lower_hex(&mut bytes, &digest);
            bytes.push(b'\n');
        }
        RootMarkerRoleV1::Existing => bytes.extend_from_slice(EXISTING_SUFFIX),
    }
    bytes
}

fn push_lower_hex(destination: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        destination.push(HEX[usize::from(byte >> 4)]);
        destination.push(HEX[usize::from(byte & 0x0f)]);
    }
}

fn verify_any_initializing_marker(
    path: &Path,
    identity: AdapterRootIdentityV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AdapterRootSafetyErrorV1::RootRoleMismatch)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdapterRootSafetyErrorV1::RootNotDedicated);
    }
    let mut marker = File::open(path).map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    marker
        .seek(SeekFrom::Start(0))
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    let mut actual = Vec::new();
    marker
        .take(256)
        .read_to_end(&mut actual)
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    if actual == marker_bytes(identity, RootMarkerRoleV1::Initializing) {
        return Ok(());
    }
    let mut restore_prefix = marker_bytes(identity, RootMarkerRoleV1::Initializing);
    restore_prefix.truncate(restore_prefix.len() - INITIALIZING_SUFFIX.len());
    restore_prefix.extend_from_slice(RESTORE_INITIALIZING_SUFFIX_PREFIX);
    let digest_offset = restore_prefix.len();
    if actual.len() != digest_offset + HEX_IDENTITY_LENGTH + 1
        || !actual.starts_with(&restore_prefix)
        || actual.last() != Some(&b'\n')
        || !actual[digest_offset..digest_offset + HEX_IDENTITY_LENGTH]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(AdapterRootSafetyErrorV1::RootIdentityMismatch);
    }
    Ok(())
}

fn verify_marker(
    path: &Path,
    identity: AdapterRootIdentityV1,
    role: RootMarkerRoleV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AdapterRootSafetyErrorV1::RootRoleMismatch)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdapterRootSafetyErrorV1::RootNotDedicated);
    }
    let mut marker = File::open(path).map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    verify_marker_handle(&mut marker, identity, role)
}

fn verify_marker_handle(
    marker: &mut File,
    identity: AdapterRootIdentityV1,
    role: RootMarkerRoleV1,
) -> Result<(), AdapterRootSafetyErrorV1> {
    marker
        .seek(SeekFrom::Start(0))
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    let mut actual = Vec::new();
    marker
        .take(256)
        .read_to_end(&mut actual)
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    if actual != marker_bytes(identity, role) {
        return Err(AdapterRootSafetyErrorV1::RootIdentityMismatch);
    }
    Ok(())
}

fn regular_file_identity(path: &Path) -> Result<FilesystemIdentityV1, AdapterRootSafetyErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AdapterRootSafetyErrorV1::RootNotDedicated);
    }
    filesystem_identity(&metadata)
}

pub(crate) fn regular_files_share_identity_v1(
    left: &Path,
    right: &Path,
) -> Result<bool, AdapterRootSafetyErrorV1> {
    Ok(regular_file_identity(left)? == regular_file_identity(right)?)
}

#[cfg(unix)]
fn filesystem_identity(
    metadata: &fs::Metadata,
) -> Result<FilesystemIdentityV1, AdapterRootSafetyErrorV1> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(FilesystemIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn filesystem_identity(
    metadata: &fs::Metadata,
) -> Result<FilesystemIdentityV1, AdapterRootSafetyErrorV1> {
    use std::os::windows::fs::MetadataExt as _;
    Ok(FilesystemIdentityV1 {
        volume_serial_number: metadata
            .volume_serial_number()
            .ok_or(AdapterRootSafetyErrorV1::RootUnavailable)?,
        file_index: metadata
            .file_index()
            .ok_or(AdapterRootSafetyErrorV1::RootUnavailable)?,
    })
}

#[cfg(unix)]
pub(crate) fn sync_root_directory(root: &Path) -> Result<(), AdapterRootSafetyErrorV1> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AdapterRootSafetyErrorV1::RootUnavailable)
}

#[cfg(windows)]
pub(crate) fn sync_root_directory(_root: &Path) -> Result<(), AdapterRootSafetyErrorV1> {
    // Stable Rust cannot open a directory for flush without platform flags. File content
    // is synchronized and every later admission revalidates high-resolution file identity;
    // this is not promoted to a Windows directory-fsync or power-loss claim.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TemporaryRoot(PathBuf);

    impl TemporaryRoot {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock follows epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "helix-dispatch-inbox-root-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("temporary root creates");
            Self(path)
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn provisioned_root_rejects_unknown_member() {
        let root = TemporaryRoot::new();
        File::create(root.0.join("foreign")).expect("foreign member creates");
        assert_eq!(
            ProvisionedEmptyAdapterRootV1::try_from_provisioned(
                root.0.clone(),
                AdapterRootIdentityV1::from_bytes([1; 32]),
            )
            .unwrap_err(),
            AdapterRootSafetyErrorV1::UnknownRootMember
        );
    }

    #[test]
    fn initializing_marker_is_bound_to_provisioned_identity() {
        let root = TemporaryRoot::new();
        let provisioned = ProvisionedEmptyAdapterRootV1::try_from_provisioned(
            root.0.clone(),
            AdapterRootIdentityV1::from_bytes([2; 32]),
        )
        .expect("empty root attests");
        ensure_initializing_marker(&provisioned).expect("marker publishes");
        assert!(ProvisionedEmptyAdapterRootV1::try_from_provisioned(
            root.0.clone(),
            AdapterRootIdentityV1::from_bytes([3; 32]),
        )
        .is_err());
    }

    #[test]
    fn restore_marker_binds_attempt_until_existing_publication() {
        let root = TemporaryRoot::new();
        let identity = AdapterRootIdentityV1::from_bytes([4; 32]);
        let provisioned =
            ProvisionedEmptyAdapterRootV1::try_from_provisioned(root.0.clone(), identity)
                .expect("empty restore root attests");
        ensure_restore_initializing_marker(&provisioned, [5; 32])
            .expect("restore marker publishes");
        ensure_restore_initializing_marker(&provisioned, [5; 32])
            .expect("same restore attempt resumes");
        assert_eq!(
            ensure_restore_initializing_marker(&provisioned, [6; 32]).unwrap_err(),
            AdapterRootSafetyErrorV1::RootIdentityMismatch
        );
        assert!(ensure_initializing_marker(&provisioned).is_err());
        File::create(root.0.join(ADAPTER_DATABASE_FILENAME)).expect("database inode reserves");
        let custody = bind_initializing_restore_root_v1(&provisioned, [5; 32])
            .expect("restore inode custody binds exact attempt");
        let existing = custody
            .publish_existing_v1()
            .expect("restore marker publishes existing role");
        existing
            .revalidate()
            .expect("published existing marker remains exact");
    }
}
