//! Provisioner-attested ownership of the dedicated HLXA filesystem root.
//!
//! A path is native adapter state, never portable authority.  Every admitted root is
//! canonicalized, bound to a high-resolution filesystem identity and revalidated before
//! use.  Publication uses a small exact marker bound to provisioner-held opaque bytes.

#![allow(dead_code)] // Foundation consumed by the exclusive store open and initialization path.

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub(crate) const AUTHORITY_DATABASE_FILENAME: &str = "task-authority.sqlite3";
pub(crate) const AUTHORITY_WAL_FILENAME: &str = "task-authority.sqlite3-wal";
pub(crate) const AUTHORITY_SHM_FILENAME: &str = "task-authority.sqlite3-shm";
pub(crate) const AUTHORITY_ROOT_MARKER_FILENAME: &str = ".helix-task-authority-root-v1";

const ROOT_MARKER_PREFIX: &[u8] = b"HELIXOS_TASK_AUTHORITY_ROOT_V1\nROOT_IDENTITY=";
const INITIALIZING_SUFFIX: &[u8] = b"\nSTATE=INITIALIZING\n";
const EXISTING_SUFFIX: &[u8] = b"\nSTATE=EXISTING\n";
const HEX_IDENTITY_LENGTH: usize = 64;
const MAX_MARKER_BYTES: u64 = 256;

/// Closed internal root-safety classifications.  No variant carries a native path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityRootSafetyErrorV1 {
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    UnknownRootMember,
    RootUnavailable,
}

/// Opaque identity assigned by the provisioner, distinct from filesystem identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityRootIdentityV1([u8; 32]);

impl AuthorityRootIdentityV1 {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AuthorityRootIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRootIdentityV1")
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
    volume_serial_number: u64,
    #[cfg(windows)]
    file_id: u128,
}

#[derive(Clone, Copy)]
enum FilesystemObjectKindV1 {
    Directory,
    RegularFile,
}

/// Provisioner-attested root that is empty or contains the same interrupted bootstrap.
#[derive(Clone)]
pub(crate) struct ProvisionedEmptyAuthorityRootV1 {
    path: PathBuf,
    directory_identity: FilesystemIdentityV1,
    provisioned_identity: AuthorityRootIdentityV1,
}

impl ProvisionedEmptyAuthorityRootV1 {
    pub(crate) fn try_from_provisioned(
        path: PathBuf,
        provisioned_identity: AuthorityRootIdentityV1,
    ) -> Result<Self, AuthorityRootSafetyErrorV1> {
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

    pub(crate) const fn provisioned_identity(&self) -> AuthorityRootIdentityV1 {
        self.provisioned_identity
    }

    pub(crate) fn revalidate(&self) -> Result<(), AuthorityRootSafetyErrorV1> {
        revalidate_directory_identity(&self.path, &self.directory_identity)?;
        validate_empty_or_initializing_members(&self.path, self.provisioned_identity)
    }
}

impl fmt::Debug for ProvisionedEmptyAuthorityRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedEmptyAuthorityRootV1")
            .finish_non_exhaustive()
    }
}

/// Provisioner-attested root whose exact identity has been published as existing.
#[derive(Clone)]
pub(crate) struct ProvisionedExistingAuthorityRootV1 {
    path: PathBuf,
    directory_identity: FilesystemIdentityV1,
    marker_identity: FilesystemIdentityV1,
    database_identity: FilesystemIdentityV1,
    expected_identity: AuthorityRootIdentityV1,
}

impl ProvisionedExistingAuthorityRootV1 {
    pub(crate) fn try_from_provisioned(
        path: PathBuf,
        expected_identity: AuthorityRootIdentityV1,
    ) -> Result<Self, AuthorityRootSafetyErrorV1> {
        let (path, directory_identity) = validate_provisioned_directory(path)?;
        validate_existing_members(&path, expected_identity)?;
        let marker_identity = regular_file_identity(&path.join(AUTHORITY_ROOT_MARKER_FILENAME))?;
        let database_identity = regular_file_identity(&path.join(AUTHORITY_DATABASE_FILENAME))?;
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

    pub(crate) const fn expected_identity(&self) -> AuthorityRootIdentityV1 {
        self.expected_identity
    }

    pub(crate) fn revalidate(&self) -> Result<(), AuthorityRootSafetyErrorV1> {
        revalidate_directory_identity(&self.path, &self.directory_identity)?;
        validate_existing_members(&self.path, self.expected_identity)?;
        if regular_file_identity(&self.path.join(AUTHORITY_ROOT_MARKER_FILENAME))?
            != self.marker_identity
            || regular_file_identity(&self.path.join(AUTHORITY_DATABASE_FILENAME))?
                != self.database_identity
        {
            return Err(AuthorityRootSafetyErrorV1::RootRoleMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ProvisionedExistingAuthorityRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedExistingAuthorityRootV1")
            .finish_non_exhaustive()
    }
}

/// Creates or verifies the exact marker for an interrupted bootstrap.
pub(crate) fn ensure_initializing_marker(
    root: &ProvisionedEmptyAuthorityRootV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    root.revalidate()?;
    let marker_path = root.path.join(AUTHORITY_ROOT_MARKER_FILENAME);
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
                .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
            sync_root_directory(root.path())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => verify_marker(
            &marker_path,
            root.provisioned_identity,
            RootMarkerRoleV1::Initializing,
        )?,
        Err(_) => return Err(AuthorityRootSafetyErrorV1::RootUnavailable),
    }
    root.revalidate()
}

/// Reports whether an interrupted initialization already reserved its database member.
pub(crate) fn initialization_database_present(
    root: &ProvisionedEmptyAuthorityRootV1,
) -> Result<bool, AuthorityRootSafetyErrorV1> {
    root.revalidate()?;
    root.path
        .join(AUTHORITY_DATABASE_FILENAME)
        .try_exists()
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)
}

/// Exclusively reserves the only database filename after root revalidation.
pub(crate) fn reserve_database_file(
    root: &ProvisionedEmptyAuthorityRootV1,
) -> Result<File, AuthorityRootSafetyErrorV1> {
    root.revalidate()?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(root.path.join(AUTHORITY_DATABASE_FILENAME))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AuthorityRootSafetyErrorV1::RootRoleMismatch
            } else {
                AuthorityRootSafetyErrorV1::RootUnavailable
            }
        })
}

/// Publishes an initialized database by changing the identity-bound marker last.
pub(crate) fn publish_existing_marker(
    root: &ProvisionedEmptyAuthorityRootV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    revalidate_directory_identity(root.path(), &root.directory_identity)?;
    validate_initializing_members(root.path(), root.provisioned_identity)?;

    let marker_path = root.path.join(AUTHORITY_ROOT_MARKER_FILENAME);
    let mut marker = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&marker_path)
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    verify_marker_handle(
        &mut marker,
        root.provisioned_identity,
        RootMarkerRoleV1::Initializing,
    )?;
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
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    sync_root_directory(root.path())?;
    validate_existing_members(root.path(), root.provisioned_identity)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootMarkerRoleV1 {
    Initializing,
    Existing,
}

fn validate_provisioned_directory(
    path: PathBuf,
) -> Result<(PathBuf, FilesystemIdentityV1), AuthorityRootSafetyErrorV1> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(AuthorityRootSafetyErrorV1::RootInvalid);
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| AuthorityRootSafetyErrorV1::RootInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuthorityRootSafetyErrorV1::RootInvalid);
    }
    let canonical = fs::canonicalize(path).map_err(|_| AuthorityRootSafetyErrorV1::RootInvalid)?;
    let metadata =
        fs::symlink_metadata(&canonical).map_err(|_| AuthorityRootSafetyErrorV1::RootInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuthorityRootSafetyErrorV1::RootInvalid);
    }
    let identity = filesystem_identity(&canonical, &metadata, FilesystemObjectKindV1::Directory)?;
    Ok((canonical, identity))
}

fn revalidate_directory_identity(
    path: &Path,
    expected: &FilesystemIdentityV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuthorityRootSafetyErrorV1::RootNotDedicated);
    }
    if &filesystem_identity(path, &metadata, FilesystemObjectKindV1::Directory)? != expected {
        return Err(AuthorityRootSafetyErrorV1::RootRoleMismatch);
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

fn scan_known_members(root: &Path) -> Result<RootMembersV1, AuthorityRootSafetyErrorV1> {
    let mut members = RootMembersV1 {
        database: false,
        marker: false,
        wal: false,
        shm: false,
    };
    let entries = fs::read_dir(root).map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    for entry in entries {
        let entry = entry.map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
        let file_type = entry
            .file_type()
            .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
        if !file_type.is_file() {
            return Err(AuthorityRootSafetyErrorV1::RootNotDedicated);
        }
        let name = entry.file_name();
        let slot = if name == OsStr::new(AUTHORITY_DATABASE_FILENAME) {
            &mut members.database
        } else if name == OsStr::new(AUTHORITY_ROOT_MARKER_FILENAME) {
            &mut members.marker
        } else if name == OsStr::new(AUTHORITY_WAL_FILENAME) {
            &mut members.wal
        } else if name == OsStr::new(AUTHORITY_SHM_FILENAME) {
            &mut members.shm
        } else {
            return Err(AuthorityRootSafetyErrorV1::UnknownRootMember);
        };
        if *slot {
            return Err(AuthorityRootSafetyErrorV1::RootNotDedicated);
        }
        *slot = true;
    }
    Ok(members)
}

fn validate_empty_or_initializing_members(
    root: &Path,
    identity: AuthorityRootIdentityV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    let members = scan_known_members(root)?;
    if !members.database && !members.marker && !members.wal && !members.shm {
        return Ok(());
    }
    validate_initializing_snapshot(members)?;
    verify_marker(
        &root.join(AUTHORITY_ROOT_MARKER_FILENAME),
        identity,
        RootMarkerRoleV1::Initializing,
    )
}

fn validate_initializing_members(
    root: &Path,
    identity: AuthorityRootIdentityV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    let members = scan_known_members(root)?;
    validate_initializing_snapshot(members)?;
    if !members.database {
        return Err(AuthorityRootSafetyErrorV1::RootRoleMismatch);
    }
    verify_marker(
        &root.join(AUTHORITY_ROOT_MARKER_FILENAME),
        identity,
        RootMarkerRoleV1::Initializing,
    )
}

fn validate_initializing_snapshot(
    members: RootMembersV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    if !members.marker || (!members.database && (members.wal || members.shm)) {
        return Err(AuthorityRootSafetyErrorV1::RootRoleMismatch);
    }
    Ok(())
}

fn validate_existing_members(
    root: &Path,
    identity: AuthorityRootIdentityV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    let members = scan_known_members(root)?;
    if !members.marker || !members.database {
        return Err(AuthorityRootSafetyErrorV1::RootRoleMismatch);
    }
    verify_marker(
        &root.join(AUTHORITY_ROOT_MARKER_FILENAME),
        identity,
        RootMarkerRoleV1::Existing,
    )
}

fn marker_bytes(identity: AuthorityRootIdentityV1, role: RootMarkerRoleV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(ROOT_MARKER_PREFIX.len() + HEX_IDENTITY_LENGTH + 24);
    bytes.extend_from_slice(ROOT_MARKER_PREFIX);
    push_lower_hex(&mut bytes, identity.as_bytes());
    match role {
        RootMarkerRoleV1::Initializing => bytes.extend_from_slice(INITIALIZING_SUFFIX),
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

fn verify_marker(
    path: &Path,
    identity: AuthorityRootIdentityV1,
    role: RootMarkerRoleV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AuthorityRootSafetyErrorV1::RootRoleMismatch)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AuthorityRootSafetyErrorV1::RootNotDedicated);
    }
    let mut marker = File::open(path).map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    verify_marker_handle(&mut marker, identity, role)
}

fn verify_marker_handle(
    marker: &mut File,
    identity: AuthorityRootIdentityV1,
    role: RootMarkerRoleV1,
) -> Result<(), AuthorityRootSafetyErrorV1> {
    marker
        .seek(SeekFrom::Start(0))
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    let mut actual = Vec::new();
    marker
        .take(MAX_MARKER_BYTES)
        .read_to_end(&mut actual)
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    if actual != marker_bytes(identity, role) {
        return Err(AuthorityRootSafetyErrorV1::RootIdentityMismatch);
    }
    Ok(())
}

fn regular_file_identity(path: &Path) -> Result<FilesystemIdentityV1, AuthorityRootSafetyErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AuthorityRootSafetyErrorV1::RootNotDedicated);
    }
    filesystem_identity(path, &metadata, FilesystemObjectKindV1::RegularFile)
}

#[cfg(unix)]
fn filesystem_identity(
    _path: &Path,
    metadata: &fs::Metadata,
    _expected_kind: FilesystemObjectKindV1,
) -> Result<FilesystemIdentityV1, AuthorityRootSafetyErrorV1> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(FilesystemIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn filesystem_identity(
    path: &Path,
    _metadata: &fs::Metadata,
    expected_kind: FilesystemObjectKindV1,
) -> Result<FilesystemIdentityV1, AuthorityRootSafetyErrorV1> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

    const FILE_FLAG_BACKUP_SEMANTICS_V1: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT_V1: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT_V1: u32 = 0x0000_0400;

    let file = OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS_V1 | FILE_FLAG_OPEN_REPARSE_POINT_V1)
        .open(path)
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    let bound_metadata = file
        .metadata()
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    let expected_type = match expected_kind {
        FilesystemObjectKindV1::Directory => bound_metadata.is_dir(),
        FilesystemObjectKindV1::RegularFile => bound_metadata.is_file(),
    };
    if !expected_type || bound_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_V1 != 0 {
        return Err(AuthorityRootSafetyErrorV1::RootNotDedicated);
    }
    let identity =
        fs_id::FileID::new(&file).map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)?;
    Ok(FilesystemIdentityV1 {
        volume_serial_number: identity.storage_id(),
        file_id: identity.internal_file_id(),
    })
}

#[cfg(unix)]
fn sync_root_directory(root: &Path) -> Result<(), AuthorityRootSafetyErrorV1> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AuthorityRootSafetyErrorV1::RootUnavailable)
}

#[cfg(windows)]
fn sync_root_directory(_root: &Path) -> Result<(), AuthorityRootSafetyErrorV1> {
    // Stable Rust has no portable directory-flush API.  File contents are synchronized,
    // and every subsequent admission revalidates the high-resolution object identity.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMPORARY_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TemporaryRoot {
        parent: PathBuf,
        root: PathBuf,
    }

    impl TemporaryRoot {
        fn new() -> Self {
            loop {
                let nonce = NEXT_TEMPORARY_ROOT.fetch_add(1, Ordering::Relaxed);
                let parent = std::env::temp_dir().join(format!(
                    "helix-task-authority-root-{}-{nonce}",
                    std::process::id()
                ));
                match fs::create_dir(&parent) {
                    Ok(()) => {
                        let root = parent.join("root");
                        fs::create_dir(&root).expect("temporary authority root creates");
                        return Self { parent, root };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary parent creates: {error}"),
                }
            }
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    fn identity(value: u8) -> AuthorityRootIdentityV1 {
        AuthorityRootIdentityV1::from_bytes([value; 32])
    }

    #[test]
    fn provisioned_root_rejects_relative_missing_and_unknown_members() {
        assert_eq!(
            ProvisionedEmptyAuthorityRootV1::try_from_provisioned(
                PathBuf::from("relative"),
                identity(1),
            )
            .unwrap_err(),
            AuthorityRootSafetyErrorV1::RootInvalid
        );

        let temporary = TemporaryRoot::new();
        File::create(temporary.root.join("foreign")).expect("foreign member creates");
        assert_eq!(
            ProvisionedEmptyAuthorityRootV1::try_from_provisioned(
                temporary.root.clone(),
                identity(1),
            )
            .unwrap_err(),
            AuthorityRootSafetyErrorV1::UnknownRootMember
        );
    }

    #[test]
    fn root_identity_and_debug_are_opaque_and_replacement_is_detected() {
        let temporary = TemporaryRoot::new();
        let root = ProvisionedEmptyAuthorityRootV1::try_from_provisioned(
            temporary.root.clone(),
            identity(7),
        )
        .expect("empty root attests");
        let rendered = format!("{root:?} {:?}", identity(7));
        assert!(!rendered.contains(temporary.root.to_string_lossy().as_ref()));
        assert!(!rendered.contains("07070707"));

        let displaced = temporary.parent.join("displaced");
        fs::rename(&temporary.root, displaced).expect("attested directory displaces");
        fs::create_dir(&temporary.root).expect("replacement directory creates");
        assert_eq!(
            root.revalidate().unwrap_err(),
            AuthorityRootSafetyErrorV1::RootRoleMismatch
        );
    }

    #[test]
    fn initialization_marker_binds_identity_and_publication_requires_database() {
        let temporary = TemporaryRoot::new();
        let root = ProvisionedEmptyAuthorityRootV1::try_from_provisioned(
            temporary.root.clone(),
            identity(3),
        )
        .expect("empty root attests");
        ensure_initializing_marker(&root).expect("initializing marker publishes");
        assert_eq!(
            publish_existing_marker(&root).unwrap_err(),
            AuthorityRootSafetyErrorV1::RootRoleMismatch
        );
        let database = reserve_database_file(&root).expect("database name reserves exclusively");
        database.sync_all().expect("empty reservation synchronizes");
        publish_existing_marker(&root).expect("existing marker publishes last");
        ProvisionedExistingAuthorityRootV1::try_from_provisioned(
            temporary.root.clone(),
            identity(3),
        )
        .expect("published root reopens");
        assert!(ProvisionedExistingAuthorityRootV1::try_from_provisioned(
            temporary.root.clone(),
            identity(4),
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn final_component_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;

        let temporary = TemporaryRoot::new();
        let link = temporary.parent.join("root-link");
        symlink(&temporary.root, &link).expect("test symlink creates");
        assert_eq!(
            ProvisionedEmptyAuthorityRootV1::try_from_provisioned(link, identity(8)).unwrap_err(),
            AuthorityRootSafetyErrorV1::RootInvalid
        );
    }
}
