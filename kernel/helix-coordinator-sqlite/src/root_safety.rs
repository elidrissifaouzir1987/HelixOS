//! Private coordinator-root ownership, crash recovery and lifecycle boundary.

#![allow(dead_code)]

use crate::clock::{remaining_monotonic_ms, CoordinatorMonotonicClockV1};
#[cfg(not(test))]
use crate::connection::configure_deadline_bounded_busy_timeout_v1;
use crate::error::InternalCoordinatorError;
#[cfg(not(test))]
use helix_contracts::Ed25519KeyResolver;
use helix_contracts::{Identifier, Sha256Digest};
#[cfg(not(test))]
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest as _, Sha256};
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;

pub(crate) const COORDINATOR_DATABASE_FILENAME: &str = "coordinator.sqlite3";
pub(crate) const COORDINATOR_WAL_FILENAME: &str = "coordinator.sqlite3-wal";
pub(crate) const COORDINATOR_SHM_FILENAME: &str = "coordinator.sqlite3-shm";
pub(crate) const ROOT_LOCK_FILENAME: &str = ".helix-coordinator-root-v1.lock";

const ROOT_MARKER_MAGIC: &[u8] = b"HELIXOS_COORDINATOR_ROOT_LOCK_V1\n";
const EMPTY_ROOT_LOCK_CONTENT: &[u8] = b"HELIXOS_COORDINATOR_ROOT_LOCK_V1\nSTATE=EMPTY\n";
const IDENTITY_MARKER_PREFIX: &[u8] = b"HELIXOS_COORDINATOR_ROOT_LOCK_V1\nROOT_IDENTITY=";
const INITIALIZING_STATE_SUFFIX: &[u8] = b"STATE=INITIALIZING\n";
const EXISTING_STATE_SUFFIX: &[u8] = b"STATE=EXISTING\n";
const HEX_IDENTITY_LENGTH: usize = 64;
pub(crate) const MAX_RESTORE_PACKAGE_DIRECTORIES_V1: usize = 132;
pub(crate) const MAX_RESTORE_PACKAGE_FILES_V1: usize = 256;
const MAX_RESTORE_PACKAGE_COMPONENT_DEPTH_V1: usize = 3;
pub(crate) const MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoordinatorRootIdentityV1([u8; 32]);

impl CoordinatorRootIdentityV1 {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn matches(&self, candidate: &[u8; 32]) -> bool {
        self.0 == *candidate
    }
}

impl fmt::Debug for CoordinatorRootIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorRootIdentityV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoordinatorRootRoleV1 {
    Empty,
    Initializing,
    Existing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DurableRootMarkerV1 {
    Empty,
    Initializing(CoordinatorRootIdentityV1),
    Existing(CoordinatorRootIdentityV1),
}

impl DurableRootMarkerV1 {
    const fn role(self) -> CoordinatorRootRoleV1 {
        match self {
            Self::Empty => CoordinatorRootRoleV1::Empty,
            Self::Initializing(_) => CoordinatorRootRoleV1::Initializing,
            Self::Existing(_) => CoordinatorRootRoleV1::Existing,
        }
    }

    const fn identity(self) -> Option<CoordinatorRootIdentityV1> {
        match self {
            Self::Empty => None,
            Self::Initializing(identity) | Self::Existing(identity) => Some(identity),
        }
    }

    fn exact_bytes(self) -> Vec<u8> {
        match self {
            Self::Empty => EMPTY_ROOT_LOCK_CONTENT.to_vec(),
            Self::Initializing(identity) => {
                identity_marker_bytes(identity, INITIALIZING_STATE_SUFFIX)
            }
            Self::Existing(identity) => identity_marker_bytes(identity, EXISTING_STATE_SUFFIX),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
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

/// Provisioner-attested read-only backup package root.
///
/// This is deliberately distinct from both coordinator-root attestation types: it grants no
/// mutation authority, creates no marker and fabricates no advisory lock. Exact member custody
/// is acquired separately so callers cannot mistake path attestation for a stable snapshot.
#[derive(Clone)]
pub(crate) struct ProvisionedRestorePackageV1 {
    path: PathBuf,
    directory_identity: FilesystemIdentityV1,
}

impl ProvisionedRestorePackageV1 {
    pub(crate) fn try_from_attested(path: PathBuf) -> Result<Self, InternalCoordinatorError> {
        let (path, directory_identity) = validate_attested_directory(path)?;
        // Reject malformed names, symlinks and special file types at the attestation boundary.
        // Capture repeats this scan while binding every regular file to an open read handle.
        scan_restore_package_shape_v1(&path)?;
        Ok(Self {
            path,
            directory_identity,
        })
    }

    pub(crate) fn attested_directory_binding_sha256_v1(&self) -> Sha256Digest {
        filesystem_identity_binding_sha256_v1(
            b"HELIXOS_RESTORE_PACKAGE_DIRECTORY_BINDING_V1\0",
            self.directory_identity,
        )
    }
}

impl fmt::Debug for ProvisionedRestorePackageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedRestorePackageV1")
            .finish_non_exhaustive()
    }
}

struct RestorePackageDirectoryBindingV1 {
    relative_name: String,
    identity: FilesystemIdentityV1,
}

struct RestorePackageFileBindingV1 {
    relative_name: String,
    file: File,
    identity: FilesystemIdentityV1,
    length: u64,
    sha256: Sha256Digest,
}

/// Read-only, identity-bound custody over one exact restore-package snapshot.
pub(crate) struct RestorePackageCustodyV1 {
    root: PathBuf,
    root_identity: FilesystemIdentityV1,
    directories: Vec<RestorePackageDirectoryBindingV1>,
    files: Vec<RestorePackageFileBindingV1>,
}

impl RestorePackageCustodyV1 {
    /// Returns normalized file-member names only after the exact package is revalidated.
    pub(crate) fn member_names_v1(&self) -> Result<Vec<&str>, InternalCoordinatorError> {
        self.revalidate_v1()?;
        Ok(self
            .files
            .iter()
            .map(|binding| binding.relative_name.as_str())
            .collect())
    }

    /// Returns normalized non-root directory names for strict layout validation.
    pub(crate) fn directory_names_v1(&self) -> Result<Vec<&str>, InternalCoordinatorError> {
        self.revalidate_v1()?;
        Ok(self
            .directories
            .iter()
            .map(|binding| binding.relative_name.as_str())
            .collect())
    }

    /// Returns a crate-private member path for SQLite after exact custody revalidation.
    ///
    /// The caller must bind its own read-only handle and revalidate this custody immediately
    /// after opening or importing. Returning the path does not transfer mutation authority.
    pub(crate) fn member_path_v1(
        &self,
        relative_name: &str,
    ) -> Result<PathBuf, InternalCoordinatorError> {
        validate_normalized_restore_member_name_v1(relative_name)?;
        let index = self.file_index_v1(relative_name)?;
        self.revalidate_member_content_v1(index)?;
        Ok(restore_package_member_path_v1(&self.root, relative_name))
    }

    /// Reads one exact member from its retained handle under an explicit byte bound.
    pub(crate) fn read_member_v1(
        &mut self,
        relative_name: &str,
        maximum_length: u64,
    ) -> Result<Vec<u8>, InternalCoordinatorError> {
        validate_normalized_restore_member_name_v1(relative_name)?;
        let index = self.file_index_v1(relative_name)?;
        let length = self.files[index].length;
        if length > maximum_length {
            return Err(InternalCoordinatorError::RootInvalid);
        }
        self.revalidate_member_metadata_v1(index)?;
        let length = usize::try_from(length).map_err(|_| InternalCoordinatorError::RootInvalid)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        bytes.resize(length, 0);
        let read_result = read_exact_bound_member_v1(&mut self.files[index].file, &mut bytes);
        read_result?;
        if Sha256Digest::digest(&bytes) != self.files[index].sha256 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        self.revalidate_member_metadata_v1(index)?;
        Ok(bytes)
    }

    /// Hashes one exact member from its retained handle without loading it into memory.
    pub(crate) fn hash_member_sha256_v1(
        &mut self,
        relative_name: &str,
        maximum_length: u64,
    ) -> Result<(Sha256Digest, u64), InternalCoordinatorError> {
        validate_normalized_restore_member_name_v1(relative_name)?;
        let index = self.file_index_v1(relative_name)?;
        let length = self.files[index].length;
        if length > maximum_length {
            return Err(InternalCoordinatorError::RootInvalid);
        }
        self.revalidate_member_metadata_v1(index)?;
        let digest = hash_exact_bound_member_v1(&self.files[index].file, length)?;
        if digest != self.files[index].sha256 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        self.revalidate_member_metadata_v1(index)?;
        Ok((digest, length))
    }

    /// Clones the retained read-only handle for a provider-neutral restore port.
    ///
    /// The clone carries no path and is returned only after the exact inode, length and
    /// captured digest are revalidated. The package custody remains authoritative and must
    /// be rechecked again after the provider finishes with the clone.
    pub(crate) fn clone_member_file_v1(
        &self,
        relative_name: &str,
        maximum_length: u64,
    ) -> Result<(File, u64, Sha256Digest), InternalCoordinatorError> {
        validate_normalized_restore_member_name_v1(relative_name)?;
        let index = self.file_index_v1(relative_name)?;
        let binding = &self.files[index];
        if binding.length > maximum_length {
            return Err(InternalCoordinatorError::RootInvalid);
        }
        self.revalidate_member_content_v1(index)?;
        let file = binding
            .file
            .try_clone()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if !metadata.is_file() || metadata.len() != binding.length {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        self.revalidate_member_content_v1(index)?;
        Ok((file, binding.length, binding.sha256))
    }

    /// Copies one captured member into an already-created empty regular file.
    ///
    /// Source bytes are read only through the retained package handle. The destination is
    /// synced, hashed through its own handle and rewound before the package is revalidated.
    pub(crate) fn copy_member_to_v1(
        &self,
        relative_name: &str,
        destination: &mut File,
        maximum_length: u64,
    ) -> Result<(Sha256Digest, u64), InternalCoordinatorError> {
        validate_normalized_restore_member_name_v1(relative_name)?;
        let index = self.file_index_v1(relative_name)?;
        let binding = &self.files[index];
        if binding.length > maximum_length {
            return Err(InternalCoordinatorError::RootInvalid);
        }
        self.revalidate_member_metadata_v1(index)?;
        if hash_exact_bound_member_v1(&binding.file, binding.length)? != binding.sha256 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        self.revalidate_member_metadata_v1(index)?;
        let digest = copy_exact_bound_member_to_v1(&binding.file, destination, binding.length)?;
        if digest != binding.sha256 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        if hash_exact_bound_member_v1(destination, binding.length)? != binding.sha256 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        self.revalidate_member_metadata_v1(index)?;
        destination
            .seek(SeekFrom::Start(0))
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        Ok((binding.sha256, binding.length))
    }

    /// Rescans the exact member set, then checks identities and captured handle content.
    ///
    /// Member reads, hashes and copies use their retained handle and captured digest directly;
    /// they do not rehash every unrelated member. This full pass is reserved for package-wide
    /// authority boundaries where same-inode, same-length mutation of any member must be caught.
    pub(crate) fn revalidate_v1(&self) -> Result<(), InternalCoordinatorError> {
        self.revalidate_shape_and_metadata_v1()?;
        for binding in &self.files {
            verify_restore_package_file_binding_v1(&self.root, binding)?;
        }
        // Close additions, removals or directory substitutions racing the content pass.
        self.revalidate_shape_and_metadata_v1()
    }

    fn revalidate_shape_and_metadata_v1(&self) -> Result<(), InternalCoordinatorError> {
        let actual = scan_restore_package_shape_v1(&self.root)?;
        if actual.directories.len() != self.directories.len()
            || actual.files.len() != self.files.len()
            || !actual
                .directories
                .iter()
                .zip(&self.directories)
                .all(|(current, bound)| current.relative_name == bound.relative_name)
            || !actual
                .files
                .iter()
                .zip(&self.files)
                .all(|(current, bound)| current.relative_name == bound.relative_name)
        {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }

        revalidate_directory_identity(&self.root, self.root_identity)?;
        for binding in &self.directories {
            let path = restore_package_member_path_v1(&self.root, &binding.relative_name);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || filesystem_identity(&path, &metadata)? != binding.identity
            {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
        }
        for binding in &self.files {
            verify_restore_package_file_binding_metadata_v1(&self.root, binding)?;
        }
        Ok(())
    }

    fn revalidate_member_metadata_v1(
        &self,
        file_index: usize,
    ) -> Result<(), InternalCoordinatorError> {
        let binding = self
            .files
            .get(file_index)
            .ok_or(InternalCoordinatorError::UnknownRootMember)?;
        revalidate_directory_identity(&self.root, self.root_identity)?;

        let mut ancestor = String::new();
        let mut components = binding.relative_name.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            let directory_index = self
                .directories
                .binary_search_by(|candidate| candidate.relative_name.as_str().cmp(&ancestor))
                .map_err(|_| InternalCoordinatorError::RootRoleMismatch)?;
            let directory_binding = &self.directories[directory_index];
            let path = restore_package_member_path_v1(&self.root, &ancestor);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || filesystem_identity(&path, &metadata)? != directory_binding.identity
            {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
        }
        verify_restore_package_file_binding_metadata_v1(&self.root, binding)
    }

    fn revalidate_member_content_v1(
        &self,
        file_index: usize,
    ) -> Result<(), InternalCoordinatorError> {
        self.revalidate_member_metadata_v1(file_index)?;
        let binding = &self.files[file_index];
        if hash_exact_bound_member_v1(&binding.file, binding.length)? != binding.sha256 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        self.revalidate_member_metadata_v1(file_index)
    }

    fn file_index_v1(&self, relative_name: &str) -> Result<usize, InternalCoordinatorError> {
        self.files
            .binary_search_by(|binding| binding.relative_name.as_str().cmp(relative_name))
            .map_err(|_| InternalCoordinatorError::UnknownRootMember)
    }
}

impl fmt::Debug for RestorePackageCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestorePackageCustodyV1")
            .finish_non_exhaustive()
    }
}

/// Captures every regular file by handle and every directory by filesystem identity.
pub(crate) fn capture_immutable_members_v1(
    package: &ProvisionedRestorePackageV1,
) -> Result<RestorePackageCustodyV1, InternalCoordinatorError> {
    revalidate_directory_identity(&package.path, package.directory_identity)?;
    let mut directories = Vec::new();
    let mut files = Vec::new();
    capture_restore_package_directory_v1(&package.path, "", &mut directories, &mut files)?;
    directories.sort_by(|left, right| left.relative_name.cmp(&right.relative_name));
    files.sort_by(|left, right| left.relative_name.cmp(&right.relative_name));
    let custody = RestorePackageCustodyV1 {
        root: package.path.clone(),
        root_identity: package.directory_identity,
        directories,
        files,
    };
    custody.revalidate_v1()?;
    Ok(custody)
}

/// Provisioner-attested dedicated root that is empty or recovering initialization.
#[derive(Clone)]
pub(crate) struct ProvisionedEmptyCoordinatorRootV1 {
    path: PathBuf,
    directory_identity: FilesystemIdentityV1,
    attested_lock_identity: Option<FilesystemIdentityV1>,
    restore_reservation_binding_sha256: Option<Sha256Digest>,
    restore_at_rest_profile_id: Option<Identifier>,
}

impl ProvisionedEmptyCoordinatorRootV1 {
    pub(crate) fn try_from_attested(path: PathBuf) -> Result<Self, InternalCoordinatorError> {
        let (path, directory_identity) = validate_attested_directory(path)?;
        validate_initialization_attestation_members(&path)?;
        let attested_lock_identity = lock_path_identity_if_present(&path)?;
        Ok(Self {
            path,
            directory_identity,
            attested_lock_identity,
            restore_reservation_binding_sha256: None,
            restore_at_rest_profile_id: None,
        })
    }

    /// Constructs the restore-only attestation with a provisioner-owned reservation binding.
    /// The binding, unlike the local filesystem identity, is portable and must be unique to
    /// this physical destination across exact process restarts.
    pub(crate) fn try_from_attested_restore_reservation_v1(
        path: PathBuf,
        restore_reservation_binding_sha256: Sha256Digest,
        restore_at_rest_profile_id: Identifier,
    ) -> Result<Self, InternalCoordinatorError> {
        let mut attested = Self::try_from_attested(path)?;
        attested.restore_reservation_binding_sha256 = Some(restore_reservation_binding_sha256);
        attested.restore_at_rest_profile_id = Some(restore_at_rest_profile_id);
        Ok(attested)
    }

    pub(crate) const fn restore_reservation_binding_sha256_v1(&self) -> Option<Sha256Digest> {
        self.restore_reservation_binding_sha256
    }

    pub(crate) const fn restore_at_rest_profile_id_v1(&self) -> Option<&Identifier> {
        self.restore_at_rest_profile_id.as_ref()
    }

    pub(crate) fn restore_state_has_started_v1(&self) -> Result<bool, InternalCoordinatorError> {
        revalidate_directory_identity(&self.path, self.directory_identity)?;
        validate_initialization_attestation_members(&self.path)?;
        Ok(lock_path_identity_if_present(&self.path)?.is_some())
    }

    /// Counts the exact attested destination members before any restore mutation.
    pub(crate) fn destination_entry_count_v1(&self) -> Result<u64, InternalCoordinatorError> {
        revalidate_directory_identity(&self.path, self.directory_identity)?;
        validate_initialization_attestation_members(&self.path)?;
        let count = fs::read_dir(&self.path)
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?
            .try_fold(0_u64, |count, entry| {
                entry.map_err(|_| InternalCoordinatorError::RootUnavailable)?;
                count
                    .checked_add(1)
                    .filter(|value| *value <= 4)
                    .ok_or(InternalCoordinatorError::RootNotDedicated)
            })?;
        revalidate_directory_identity(&self.path, self.directory_identity)?;
        validate_initialization_attestation_members(&self.path)?;
        Ok(count)
    }

    pub(crate) fn attested_directory_binding_sha256_v1(&self) -> Sha256Digest {
        filesystem_identity_binding_sha256_v1(
            b"HELIXOS_EMPTY_COORDINATOR_ROOT_DIRECTORY_BINDING_V1\0",
            self.directory_identity,
        )
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for ProvisionedEmptyCoordinatorRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedEmptyCoordinatorRootV1")
            .finish_non_exhaustive()
    }
}

/// Provisioner-attested root expected to contain one initialized coordinator store.
#[derive(Clone)]
pub(crate) struct ProvisionedExistingCoordinatorRootV1 {
    path: PathBuf,
    directory_identity: FilesystemIdentityV1,
    attested_lock_identity: FilesystemIdentityV1,
    expected_identity: CoordinatorRootIdentityV1,
}

impl ProvisionedExistingCoordinatorRootV1 {
    pub(crate) fn try_from_attested(
        path: PathBuf,
        expected_identity: CoordinatorRootIdentityV1,
    ) -> Result<Self, InternalCoordinatorError> {
        let (path, directory_identity) = validate_attested_directory(path)?;
        validate_existing_members(&path)?;
        let attested_lock_identity = lock_path_identity_if_present(&path)?
            .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        Ok(Self {
            path,
            directory_identity,
            attested_lock_identity,
            expected_identity,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn expected_identity(&self) -> CoordinatorRootIdentityV1 {
        self.expected_identity
    }
}

impl fmt::Debug for ProvisionedExistingCoordinatorRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionedExistingCoordinatorRootV1")
            .finish_non_exhaustive()
    }
}

/// Exclusive advisory lease retained by cooperating coordinator processes.
pub(crate) struct CoordinatorRootLeaseV1 {
    file: File,
    marker: DurableRootMarkerV1,
    root: PathBuf,
    directory_identity: FilesystemIdentityV1,
    lock_identity: FilesystemIdentityV1,
}

impl CoordinatorRootLeaseV1 {
    pub(crate) fn verify_role(
        &mut self,
        expected: CoordinatorRootRoleV1,
    ) -> Result<(), InternalCoordinatorError> {
        self.revalidate_filesystem_identity()?;
        if self.marker.role() != expected {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        validate_members_for_marker(&self.root, self.marker)?;
        let actual = read_exact_file(&mut self.file)?;
        if parse_exact_marker(&actual) != Some(self.marker) {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        self.revalidate_filesystem_identity()
    }

    /// Identity already durably assigned to an interrupted initialization, if any.
    pub(crate) const fn initializing_identity(&self) -> Option<CoordinatorRootIdentityV1> {
        match self.marker {
            DurableRootMarkerV1::Initializing(identity) => Some(identity),
            DurableRootMarkerV1::Empty | DurableRootMarkerV1::Existing(_) => None,
        }
    }

    /// Identity carried by an exact or recoverable initialization marker.
    ///
    /// For `Existing`, authority comes from the exact marker on the same attested lock
    /// inode, never from coordinator database content.
    pub(crate) const fn recovery_identity(&self) -> Option<CoordinatorRootIdentityV1> {
        self.marker.identity()
    }

    /// Exact marker role acquired for initialization crash recovery.
    pub(crate) const fn recovery_role(&self) -> CoordinatorRootRoleV1 {
        self.marker.role()
    }

    /// Durably assigns identity before any coordinator database file may be created.
    pub(crate) fn begin_initialization(
        &mut self,
        identity: CoordinatorRootIdentityV1,
    ) -> Result<(), InternalCoordinatorError> {
        self.revalidate_filesystem_identity()?;
        match self.marker {
            DurableRootMarkerV1::Initializing(current) if current == identity => {
                return self.verify_role(CoordinatorRootRoleV1::Initializing);
            }
            DurableRootMarkerV1::Empty => {}
            DurableRootMarkerV1::Initializing(_) | DurableRootMarkerV1::Existing(_) => {
                return Err(InternalCoordinatorError::RootIdentityMismatch);
            }
        }
        validate_empty_members(&self.root)?;
        verify_exact_file(&mut self.file, EMPTY_ROOT_LOCK_CONTENT)?;
        let marker = DurableRootMarkerV1::Initializing(identity);
        rewrite_and_sync_exact(&mut self.file, &marker.exact_bytes())?;
        self.marker = marker;
        self.verify_role(CoordinatorRootRoleV1::Initializing)
    }

    /// Reports database presence only after revalidating directory, lock and members.
    pub(crate) fn database_present(&mut self) -> Result<bool, InternalCoordinatorError> {
        self.revalidate_filesystem_identity()?;
        let members = scan_known_members(&self.root)?;
        match self.marker {
            DurableRootMarkerV1::Empty => {
                if members.database_present || members.wal_present || members.shm_present {
                    return Err(InternalCoordinatorError::RootRoleMismatch);
                }
            }
            DurableRootMarkerV1::Initializing(_) => {
                validate_initializing_snapshot(members)?;
            }
            DurableRootMarkerV1::Existing(_) => {
                validate_existing_snapshot(members)?;
            }
        }
        self.revalidate_filesystem_identity()?;
        Ok(members.database_present)
    }

    /// Reads the exact marker through the retained lease handle for fault tests.
    #[cfg(test)]
    pub(crate) fn exact_marker_bytes_for_test_v1(
        &mut self,
    ) -> Result<Vec<u8>, InternalCoordinatorError> {
        self.revalidate_filesystem_identity()?;
        let marker = read_exact_file(&mut self.file)?;
        self.revalidate_filesystem_identity()?;
        Ok(marker)
    }

    /// Replaces marker bytes through the retained lease handle for fault tests.
    #[cfg(test)]
    pub(crate) fn replace_marker_bytes_for_test_v1(
        &mut self,
        replacement: &[u8],
    ) -> Result<(), InternalCoordinatorError> {
        self.revalidate_filesystem_identity()?;
        rewrite_and_sync_exact(&mut self.file, replacement)?;
        self.revalidate_filesystem_identity()
    }

    /// Publishes exact EXISTING identity after connection-level committed-store proof.
    ///
    /// The identity prefix is written and synchronized by `begin_initialization` before
    /// SQLite creation. Finalization rewrites only the trailing state field, so a crash
    /// cannot destroy the recoverable identity prefix of a committed database.
    pub(crate) fn finalize_committed_initialization(
        &mut self,
        identity: CoordinatorRootIdentityV1,
    ) -> Result<(), InternalCoordinatorError> {
        self.revalidate_filesystem_identity()?;
        match self.marker {
            DurableRootMarkerV1::Existing(current) if current == identity => {
                return self.verify_role(CoordinatorRootRoleV1::Existing);
            }
            DurableRootMarkerV1::Initializing(current) if current == identity => {}
            DurableRootMarkerV1::Initializing(_) | DurableRootMarkerV1::Existing(_) => {
                return Err(InternalCoordinatorError::RootIdentityMismatch);
            }
            DurableRootMarkerV1::Empty => {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
        }
        if !self.database_present()? {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        let actual = read_exact_file(&mut self.file)?;
        if recoverable_marker_identity(&actual) != Some(identity) {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        rewrite_identity_state(&mut self.file, identity, EXISTING_STATE_SUFFIX)?;
        self.marker = DurableRootMarkerV1::Existing(identity);
        self.verify_role(CoordinatorRootRoleV1::Existing)
    }

    /// Compatibility wrapper for callers that already published INITIALIZING identity.
    pub(crate) fn promote_empty_to_existing(&mut self) -> Result<(), InternalCoordinatorError> {
        let identity = self
            .initializing_identity()
            .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        self.finalize_committed_initialization(identity)
    }

    fn revalidate_filesystem_identity(&self) -> Result<(), InternalCoordinatorError> {
        revalidate_directory_identity(&self.root, self.directory_identity)?;
        let path = self.root.join(ROOT_LOCK_FILENAME);
        let path_metadata =
            fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(InternalCoordinatorError::RootNotDedicated);
        }
        let path_identity = filesystem_identity(&path, &path_metadata)?;
        let held_metadata = self
            .file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if filesystem_identity(&path, &held_metadata)? != self.lock_identity
            || path_identity != self.lock_identity
        {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for CoordinatorRootLeaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorRootLeaseV1")
            .finish_non_exhaustive()
    }
}

struct RestoreDatabaseBindingV1 {
    file: File,
    identity: FilesystemIdentityV1,
}

/// Linear custody for one create-only coordinator import into an attested empty root.
///
/// This value can only be obtained from `ProvisionedEmptyCoordinatorRootV1`. It retains the
/// exclusive root lease and the destination database inode from reservation until the caller
/// proves RESTORE_PENDING and publishes the durable EXISTING marker.
pub(crate) struct CoordinatorRestoreRootCustodyV1 {
    root: PathBuf,
    new_root_identity: CoordinatorRootIdentityV1,
    database_binding: Option<RestoreDatabaseBindingV1>,
    database_import_already_present: bool,
    // Declared last so the exclusive root lock outlives the imported file binding.
    root_lease: CoordinatorRootLeaseV1,
}

impl CoordinatorRestoreRootCustodyV1 {
    /// Reports whether this exact import inode was present when custody began or resumed.
    ///
    /// A database reserved later by this custody does not change the answer. The method is
    /// read-only and revalidates the INITIALIZING root plus any retained database handle.
    pub(crate) fn database_import_already_present_v1(
        &mut self,
    ) -> Result<bool, InternalCoordinatorError> {
        self.root_lease
            .verify_role(CoordinatorRootRoleV1::Initializing)?;
        match self.database_binding.as_ref() {
            Some(binding) => verify_restore_database_binding_v1(&self.root, binding)?,
            None => {
                if self.database_import_already_present || self.root_lease.database_present()? {
                    return Err(InternalCoordinatorError::RootRoleMismatch);
                }
            }
        }
        Ok(self.database_import_already_present)
    }

    /// Reserves the sole database member with create-new semantics before SQLite import.
    pub(crate) fn reserve_database_import_create_new_v1(
        &mut self,
    ) -> Result<(), InternalCoordinatorError> {
        self.root_lease
            .verify_role(CoordinatorRootRoleV1::Initializing)?;
        if self.database_binding.is_some() {
            return self.revalidate_imported_database_v1();
        }
        if self.root_lease.database_present()? {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        let path = self.root.join(COORDINATOR_DATABASE_FILENAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    InternalCoordinatorError::RootRoleMismatch
                } else {
                    InternalCoordinatorError::RootUnavailable
                }
            })?;
        file.sync_all()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        let identity = filesystem_identity(
            &path,
            &file
                .metadata()
                .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
        )?;
        sync_directory_entry(&self.root)?;
        self.database_binding = Some(RestoreDatabaseBindingV1 { file, identity });
        self.revalidate_imported_database_v1()
    }

    /// Installs one immutable package member into the create-only destination inode.
    pub(crate) fn import_package_database_member_v1(
        &mut self,
        package: &RestorePackageCustodyV1,
        relative_name: &str,
        maximum_length: u64,
    ) -> Result<(Sha256Digest, u64), InternalCoordinatorError> {
        if self.database_import_already_present {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        if self.database_binding.is_none() {
            self.reserve_database_import_create_new_v1()?;
        }
        self.revalidate_imported_database_v1()?;
        let binding = self
            .database_binding
            .as_mut()
            .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        if binding
            .file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?
            .len()
            != 0
        {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        let copied = package.copy_member_to_v1(relative_name, &mut binding.file, maximum_length)?;
        sync_directory_entry(&self.root)?;
        self.revalidate_imported_database_v1()?;
        Ok(copied)
    }

    /// Returns the create-only reserved path to the crate-private SQLite restore pipeline.
    pub(crate) fn database_path_v1(&mut self) -> Result<PathBuf, InternalCoordinatorError> {
        self.revalidate_imported_database_v1()?;
        Ok(self.root.join(COORDINATOR_DATABASE_FILENAME))
    }

    /// Revalidates directory, lock, known members and the held database inode.
    pub(crate) fn revalidate_imported_database_v1(
        &mut self,
    ) -> Result<(), InternalCoordinatorError> {
        self.root_lease
            .verify_role(CoordinatorRootRoleV1::Initializing)?;
        let binding = self
            .database_binding
            .as_ref()
            .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        verify_restore_database_binding_v1(&self.root, binding)
    }

    /// Publishes the exact pending root identity only after schema-level pending proof.
    #[cfg(not(test))]
    pub(crate) fn finalize_restore_pending_publication_v1<C, R>(
        mut self,
        pending_bindings: crate::schema::RestorePendingBindingsV1,
        historical_plan_keys: &R,
        maximum_busy_wait_ms: u64,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<CoordinatorPendingRootCustodyV1, InternalCoordinatorError>
    where
        C: CoordinatorMonotonicClockV1 + ?Sized,
        R: Ed25519KeyResolver,
    {
        self.revalidate_imported_database_v1()?;
        let connection = open_restore_pending_verification_connection_v1(
            &self.root,
            maximum_busy_wait_ms,
            clock,
            deadline_monotonic_ms,
        )?;
        let pending_proof = crate::schema::verify_restore_pending_v1(
            &connection,
            pending_bindings,
            historical_plan_keys,
        )?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        self.revalidate_imported_database_v1()?;
        if pending_proof.summary().root_identity != self.new_root_identity {
            return Err(InternalCoordinatorError::RootIdentityMismatch);
        }
        drop(connection);
        self.revalidate_imported_database_v1()?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        self.finalize_verified_restore_pending_v1()
    }

    /// Dispatch-V2 counterpart of the base finalizer; it proves both metadata projections.
    #[cfg(not(test))]
    pub(crate) fn finalize_dispatch_restore_pending_publication_v1<C, R>(
        mut self,
        pending_bindings: crate::dispatch_schema::DispatchRestorePendingBindingsV1,
        historical_plan_keys: &R,
        maximum_busy_wait_ms: u64,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<CoordinatorPendingRootCustodyV1, InternalCoordinatorError>
    where
        C: CoordinatorMonotonicClockV1 + ?Sized,
        R: Ed25519KeyResolver,
    {
        self.revalidate_imported_database_v1()?;
        let connection = open_restore_pending_verification_connection_v1(
            &self.root,
            maximum_busy_wait_ms,
            clock,
            deadline_monotonic_ms,
        )?;
        let pending_proof = crate::dispatch_schema::verify_dispatch_restore_pending_v1(
            &connection,
            pending_bindings,
            historical_plan_keys,
        )?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        self.revalidate_imported_database_v1()?;
        if pending_proof.root_identity() != self.new_root_identity {
            return Err(InternalCoordinatorError::RootIdentityMismatch);
        }
        drop(connection);
        self.revalidate_imported_database_v1()?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        self.finalize_verified_restore_pending_v1()
    }

    #[cfg(test)]
    fn finalize_restore_pending_publication_for_test_v1(
        mut self,
        verified_root_identity: CoordinatorRootIdentityV1,
    ) -> Result<CoordinatorPendingRootCustodyV1, InternalCoordinatorError> {
        self.revalidate_imported_database_v1()?;
        if verified_root_identity != self.new_root_identity {
            return Err(InternalCoordinatorError::RootIdentityMismatch);
        }
        self.finalize_verified_restore_pending_v1()
    }

    fn finalize_verified_restore_pending_v1(
        mut self,
    ) -> Result<CoordinatorPendingRootCustodyV1, InternalCoordinatorError> {
        self.root_lease
            .finalize_committed_initialization(self.new_root_identity)?;
        let database_binding = self
            .database_binding
            .take()
            .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        let mut pending = CoordinatorPendingRootCustodyV1 {
            root_lease: self.root_lease,
            root: self.root,
            expected_identity: self.new_root_identity,
            database_binding,
        };
        pending.revalidate_v1()?;
        Ok(pending)
    }
}

impl fmt::Debug for CoordinatorRestoreRootCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorRestoreRootCustodyV1")
            .finish_non_exhaustive()
    }
}

/// Maintenance-only custody for a root whose database must verify RESTORE_PENDING.
pub(crate) struct CoordinatorPendingRootCustodyV1 {
    root: PathBuf,
    expected_identity: CoordinatorRootIdentityV1,
    database_binding: RestoreDatabaseBindingV1,
    // Declared last so the exclusive root lock outlives the pending database binding.
    root_lease: CoordinatorRootLeaseV1,
}

/// Read-only custody for reconciling one already-ticketed restore destination.
///
/// Unlike initialization custody, acquisition never creates or repairs the marker. An
/// absent marker is retained as an exact unstarted observation; an existing marker must be
/// canonical and, once restore has started, carry the ticket's coordinator-root identity.
pub(crate) struct CoordinatorRestoreInspectionCustodyV1 {
    root: PathBuf,
    expected_reservation_binding_sha256: Sha256Digest,
    expected_root_identity: CoordinatorRootIdentityV1,
    observed_marker: Option<DurableRootMarkerV1>,
    database_binding: Option<RestoreDatabaseBindingV1>,
    #[cfg(unix)]
    directory: File,
    root_lease: Option<CoordinatorRootLeaseV1>,
}

impl CoordinatorRestoreInspectionCustodyV1 {
    /// Whether the exact ticket identity has been durably assigned to this root.
    pub(crate) const fn restore_has_started_v1(&self) -> bool {
        matches!(
            self.observed_marker,
            Some(DurableRootMarkerV1::Initializing(_) | DurableRootMarkerV1::Existing(_))
        )
    }

    /// Rechecks the reservation, root path, marker role/identity and any database inode.
    pub(crate) fn revalidate_v1(
        &mut self,
        root: &ProvisionedEmptyCoordinatorRootV1,
    ) -> Result<(), InternalCoordinatorError> {
        if root.restore_reservation_binding_sha256_v1()
            != Some(self.expected_reservation_binding_sha256)
        {
            return Err(InternalCoordinatorError::RootIdentityMismatch);
        }
        revalidate_directory_identity(&self.root, root.directory_identity)?;
        #[cfg(unix)]
        {
            let held = self
                .directory
                .metadata()
                .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
            if !held.is_dir() || filesystem_identity(&self.root, &held)? != root.directory_identity
            {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
        }

        match (&mut self.root_lease, self.observed_marker) {
            (None, None) => {
                validate_empty_members(&self.root)?;
                if lock_path_identity_if_present(&self.root)?.is_some() {
                    return Err(InternalCoordinatorError::RootRoleMismatch);
                }
            }
            (Some(lease), Some(marker)) => {
                lease.verify_role(marker.role())?;
                if lease.recovery_identity() != marker.identity() {
                    return Err(InternalCoordinatorError::RootIdentityMismatch);
                }
                match marker {
                    DurableRootMarkerV1::Empty => {
                        if self.database_binding.is_some() || lease.database_present()? {
                            return Err(InternalCoordinatorError::RootRoleMismatch);
                        }
                    }
                    DurableRootMarkerV1::Initializing(identity)
                    | DurableRootMarkerV1::Existing(identity) => {
                        if identity != self.expected_root_identity {
                            return Err(InternalCoordinatorError::RootIdentityMismatch);
                        }
                        let present = lease.database_present()?;
                        match self.database_binding.as_ref() {
                            Some(binding) if present => {
                                verify_restore_database_binding_v1(&self.root, binding)?;
                            }
                            None if !present
                                && marker.role() == CoordinatorRootRoleV1::Initializing => {}
                            _ => return Err(InternalCoordinatorError::RootRoleMismatch),
                        }
                    }
                }
            }
            _ => return Err(InternalCoordinatorError::RootRoleMismatch),
        }
        Ok(())
    }
}

impl fmt::Debug for CoordinatorRestoreInspectionCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorRestoreInspectionCustodyV1")
            .finish_non_exhaustive()
    }
}

impl CoordinatorPendingRootCustodyV1 {
    pub(crate) fn database_path_v1(&mut self) -> Result<PathBuf, InternalCoordinatorError> {
        self.revalidate_v1()?;
        Ok(self.root.join(COORDINATOR_DATABASE_FILENAME))
    }

    pub(crate) fn revalidate_v1(&mut self) -> Result<(), InternalCoordinatorError> {
        self.root_lease
            .verify_role(CoordinatorRootRoleV1::Existing)?;
        if self.root_lease.recovery_identity() != Some(self.expected_identity) {
            return Err(InternalCoordinatorError::RootIdentityMismatch);
        }
        verify_restore_database_binding_v1(&self.root, &self.database_binding)
    }
}

impl fmt::Debug for CoordinatorPendingRootCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorPendingRootCustodyV1")
            .finish_non_exhaustive()
    }
}

/// Generates a fresh restricted destination identity without exposing raw bytes publicly.
pub(crate) fn generate_restore_root_identity_v1(
) -> Result<CoordinatorRootIdentityV1, InternalCoordinatorError> {
    let mut identity = [0_u8; 32];
    getrandom::fill(&mut identity).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    Ok(CoordinatorRootIdentityV1::from_bytes(identity))
}

/// Begins a clean-root restore and retains exclusive custody across every import boundary.
pub(crate) fn begin_empty_restore_root_custody_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedEmptyCoordinatorRootV1,
    new_root_identity: CoordinatorRootIdentityV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorRestoreRootCustodyV1, InternalCoordinatorError> {
    let mut root_lease =
        acquire_initialization_root_lease(root, maximum_wait_ms, clock, deadline_monotonic_ms)?;
    match root_lease.recovery_role() {
        CoordinatorRootRoleV1::Empty => {
            root_lease.begin_initialization(new_root_identity)?;
            if root_lease.database_present()? {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
        }
        CoordinatorRootRoleV1::Initializing => {
            if root_lease.recovery_identity() != Some(new_root_identity) {
                return Err(InternalCoordinatorError::RootIdentityMismatch);
            }
            root_lease.verify_role(CoordinatorRootRoleV1::Initializing)?;
        }
        CoordinatorRootRoleV1::Existing => {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
    }
    let database_import_already_present = root_lease.database_present()?;
    let database_binding = if database_import_already_present {
        Some(bind_restore_database_v1(root.path())?)
    } else {
        None
    };
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    Ok(CoordinatorRestoreRootCustodyV1 {
        root_lease,
        root: root.path().to_path_buf(),
        new_root_identity,
        database_binding,
        database_import_already_present,
    })
}

/// Reopens only a provisioner-re-attested restore root under maintenance custody.
pub(crate) fn reopen_restore_pending_root_custody_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedEmptyCoordinatorRootV1,
    expected_identity: CoordinatorRootIdentityV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorPendingRootCustodyV1, InternalCoordinatorError> {
    let mut root_lease =
        acquire_initialization_root_lease(root, maximum_wait_ms, clock, deadline_monotonic_ms)?;
    root_lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    if root_lease.recovery_identity() != Some(expected_identity) {
        return Err(InternalCoordinatorError::RootIdentityMismatch);
    }
    if !root_lease.database_present()? {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    let database_binding = bind_restore_database_v1(root.path())?;
    let mut pending = CoordinatorPendingRootCustodyV1 {
        root_lease,
        root: root.path().to_path_buf(),
        expected_identity,
        database_binding,
    };
    pending.revalidate_v1()?;
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    Ok(pending)
}

/// Reacquires an existing restore destination without creating or repairing any state.
pub(crate) fn inspect_existing_restore_root_custody_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedEmptyCoordinatorRootV1,
    expected_reservation_binding_sha256: Sha256Digest,
    expected_root_identity: CoordinatorRootIdentityV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorRestoreInspectionCustodyV1, InternalCoordinatorError> {
    if root.restore_reservation_binding_sha256_v1() != Some(expected_reservation_binding_sha256) {
        return Err(InternalCoordinatorError::RootIdentityMismatch);
    }
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    revalidate_directory_identity(root.path(), root.directory_identity)?;
    validate_initialization_attestation_members(root.path())?;
    inspect_validated_existing_restore_root_custody_v1(
        root,
        expected_reservation_binding_sha256,
        expected_root_identity,
        maximum_wait_ms,
        clock,
        deadline_monotonic_ms,
    )
}

#[cfg(not(unix))]
fn inspect_validated_existing_restore_root_custody_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    _root: &ProvisionedEmptyCoordinatorRootV1,
    _expected_reservation_binding_sha256: Sha256Digest,
    _expected_root_identity: CoordinatorRootIdentityV1,
    _maximum_wait_ms: u64,
    _clock: &C,
    _deadline_monotonic_ms: u64,
) -> Result<CoordinatorRestoreInspectionCustodyV1, InternalCoordinatorError> {
    // Stable std cannot retain an exact directory handle on these targets. Refuse this
    // reconciliation path until the provisioner supplies an equivalent native custody.
    Err(InternalCoordinatorError::RootUnavailable)
}

#[cfg(unix)]
fn inspect_validated_existing_restore_root_custody_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedEmptyCoordinatorRootV1,
    expected_reservation_binding_sha256: Sha256Digest,
    expected_root_identity: CoordinatorRootIdentityV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorRestoreInspectionCustodyV1, InternalCoordinatorError> {
    let directory = {
        let directory =
            File::open(root.path()).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        let metadata = directory
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if !metadata.is_dir()
            || filesystem_identity(root.path(), &metadata)? != root.directory_identity
        {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        directory
    };

    let (observed_marker, mut root_lease) = if lock_path_identity_if_present(root.path())?.is_some()
    {
        let (file, lock_identity) = acquire_lock_file(
            root.path(),
            root.directory_identity,
            root.attested_lock_identity,
            maximum_wait_ms,
            clock,
            deadline_monotonic_ms,
        )?;
        let mut lease = CoordinatorRootLeaseV1 {
            file,
            marker: DurableRootMarkerV1::Empty,
            root: root.path().to_path_buf(),
            directory_identity: root.directory_identity,
            lock_identity,
        };
        let actual = read_exact_file(&mut lease.file)?;
        let marker =
            parse_exact_marker(&actual).ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        lease.marker = marker;
        lease.verify_role(marker.role())?;
        (Some(marker), Some(lease))
    } else {
        validate_empty_members(root.path())?;
        (None, None)
    };

    let database_binding = match observed_marker {
        Some(DurableRootMarkerV1::Initializing(identity))
        | Some(DurableRootMarkerV1::Existing(identity)) => {
            if identity != expected_root_identity {
                return Err(InternalCoordinatorError::RootIdentityMismatch);
            }
            let lease = root_lease
                .as_mut()
                .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
            if lease.database_present()? {
                Some(bind_restore_database_v1(root.path())?)
            } else if observed_marker
                == Some(DurableRootMarkerV1::Initializing(expected_root_identity))
            {
                None
            } else {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
        }
        Some(DurableRootMarkerV1::Empty) | None => None,
    };
    let mut custody = CoordinatorRestoreInspectionCustodyV1 {
        root: root.path().to_path_buf(),
        expected_reservation_binding_sha256,
        expected_root_identity,
        observed_marker,
        database_binding,
        directory,
        root_lease,
    };
    custody.revalidate_v1(root)?;
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    Ok(custody)
}

#[cfg(not(test))]
fn open_restore_pending_verification_connection_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &Path,
    maximum_busy_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<Connection, InternalCoordinatorError> {
    let path = root.join(COORDINATOR_DATABASE_FILENAME);
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    configure_deadline_bounded_busy_timeout_v1(
        &connection,
        maximum_busy_wait_ms,
        clock,
        deadline_monotonic_ms,
    )?;
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| InternalCoordinatorError::DurabilityProfileUnavailable)?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .and_then(|_| connection.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|_| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|_| connection.pragma_update(None, "cell_size_check", "ON"))
        .and_then(|_| connection.pragma_update(None, "recursive_triggers", "ON"))
        .and_then(|_| connection.pragma_update(None, "wal_autocheckpoint", 0_i64))
        .map_err(|_| InternalCoordinatorError::DurabilityProfileUnavailable)?;
    let pragma = |name| {
        connection
            .pragma_query_value(None, name, |row| row.get::<_, i64>(0))
            .map_err(|_| InternalCoordinatorError::DurabilityProfileUnavailable)
    };
    if !journal_mode.eq_ignore_ascii_case("wal")
        || pragma("synchronous")? != 2
        || pragma("foreign_keys")? != 1
        || pragma("trusted_schema")? != 0
        || pragma("cell_size_check")? != 1
        || pragma("recursive_triggers")? != 1
        || pragma("wal_autocheckpoint")? != 0
    {
        return Err(InternalCoordinatorError::DurabilityProfileUnavailable);
    }
    configure_deadline_bounded_busy_timeout_v1(
        &connection,
        maximum_busy_wait_ms,
        clock,
        deadline_monotonic_ms,
    )?;
    Ok(connection)
}

/// Acquires either exact EMPTY or a recoverable INITIALIZING marker.
pub(crate) fn acquire_initialization_root_lease<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedEmptyCoordinatorRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorRootLeaseV1, InternalCoordinatorError> {
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    revalidate_directory_identity(root.path(), root.directory_identity)?;
    validate_initialization_attestation_members(root.path())?;
    let path = root.path().join(ROOT_LOCK_FILENAME);
    if root.attested_lock_identity.is_some() {
        return acquire_existing_initialization_marker(
            root,
            maximum_wait_ms,
            clock,
            deadline_monotonic_ms,
        );
    }
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            file.try_lock().map_err(map_lock_error)?;
            let lock_identity = filesystem_identity(
                &path,
                &file
                    .metadata()
                    .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
            )?;
            write_and_sync_exact(&mut file, EMPTY_ROOT_LOCK_CONTENT)?;
            sync_directory_entry(root.path())?;
            let mut lease = CoordinatorRootLeaseV1 {
                file,
                marker: DurableRootMarkerV1::Empty,
                root: root.path().to_path_buf(),
                directory_identity: root.directory_identity,
                lock_identity,
            };
            lease.verify_role(CoordinatorRootRoleV1::Empty)?;
            remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
            Ok(lease)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            acquire_existing_initialization_marker(
                root,
                maximum_wait_ms,
                clock,
                deadline_monotonic_ms,
            )
        }
        Err(_) => Err(InternalCoordinatorError::RootUnavailable),
    }
}

/// Compatibility API retaining the original strict empty-only reservation behavior.
pub(crate) fn reserve_empty_root<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedEmptyCoordinatorRootV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorRootLeaseV1, InternalCoordinatorError> {
    let mut lease = acquire_initialization_root_lease(root, 1, clock, deadline_monotonic_ms)?;
    lease.verify_role(CoordinatorRootRoleV1::Empty)?;
    Ok(lease)
}

pub(crate) fn acquire_existing_root_lease<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedExistingCoordinatorRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorRootLeaseV1, InternalCoordinatorError> {
    revalidate_directory_identity(root.path(), root.directory_identity)?;
    validate_existing_members(root.path())?;
    let (file, lock_identity) = acquire_lock_file(
        root.path(),
        root.directory_identity,
        Some(root.attested_lock_identity),
        maximum_wait_ms,
        clock,
        deadline_monotonic_ms,
    )?;
    let mut lease = CoordinatorRootLeaseV1 {
        file,
        marker: DurableRootMarkerV1::Existing(root.expected_identity),
        root: root.path().to_path_buf(),
        directory_identity: root.directory_identity,
        lock_identity,
    };
    let actual = read_exact_file(&mut lease.file)?;
    match parse_exact_marker(&actual) {
        Some(DurableRootMarkerV1::Existing(identity)) if identity == root.expected_identity => {}
        Some(DurableRootMarkerV1::Existing(_)) => {
            return Err(InternalCoordinatorError::RootIdentityMismatch);
        }
        _ => return Err(InternalCoordinatorError::RootRoleMismatch),
    }
    lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    Ok(lease)
}

fn acquire_existing_initialization_marker<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &ProvisionedEmptyCoordinatorRootV1,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<CoordinatorRootLeaseV1, InternalCoordinatorError> {
    let (file, lock_identity) = acquire_lock_file(
        root.path(),
        root.directory_identity,
        root.attested_lock_identity,
        maximum_wait_ms,
        clock,
        deadline_monotonic_ms,
    )?;
    let mut lease = CoordinatorRootLeaseV1 {
        file,
        marker: DurableRootMarkerV1::Empty,
        root: root.path().to_path_buf(),
        directory_identity: root.directory_identity,
        lock_identity,
    };
    let members = scan_known_members(root.path())?;
    let actual = read_exact_file(&mut lease.file)?;
    match parse_exact_marker(&actual) {
        Some(DurableRootMarkerV1::Empty) => {
            if members.database_present || members.wal_present || members.shm_present {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
        }
        Some(DurableRootMarkerV1::Initializing(identity)) => {
            validate_initializing_snapshot(members)?;
            lease.marker = DurableRootMarkerV1::Initializing(identity);
        }
        Some(DurableRootMarkerV1::Existing(identity)) => {
            validate_existing_snapshot(members)?;
            lease.marker = DurableRootMarkerV1::Existing(identity);
        }
        None if !members.database_present && !members.wal_present && !members.shm_present => {
            rewrite_and_sync_exact(&mut lease.file, EMPTY_ROOT_LOCK_CONTENT)?;
        }
        None => {
            let identity = recoverable_marker_identity(&actual)
                .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
            validate_initializing_snapshot(members)?;
            rewrite_identity_state(&mut lease.file, identity, INITIALIZING_STATE_SUFFIX)?;
            lease.marker = DurableRootMarkerV1::Initializing(identity);
        }
    }
    lease.verify_role(lease.marker.role())?;
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    Ok(lease)
}

fn bind_restore_database_v1(
    root: &Path,
) -> Result<RestoreDatabaseBindingV1, InternalCoordinatorError> {
    validate_existing_members(root)?;
    let path = root.join(COORDINATOR_DATABASE_FILENAME);
    let before =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let identity = filesystem_identity(
        &path,
        &file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )?;
    let binding = RestoreDatabaseBindingV1 { file, identity };
    verify_restore_database_binding_v1(root, &binding)?;
    Ok(binding)
}

fn verify_restore_database_binding_v1(
    root: &Path,
    binding: &RestoreDatabaseBindingV1,
) -> Result<(), InternalCoordinatorError> {
    let members = scan_known_members(root)?;
    if !members.lock_present || !members.database_present {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    let path = root.join(COORDINATOR_DATABASE_FILENAME);
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let held_metadata = binding
        .file
        .metadata()
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || filesystem_identity(&path, &path_metadata)? != binding.identity
        || filesystem_identity(&path, &held_metadata)? != binding.identity
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn acquire_lock_file<C: CoordinatorMonotonicClockV1 + ?Sized>(
    root: &Path,
    directory_identity: FilesystemIdentityV1,
    expected_lock_identity: Option<FilesystemIdentityV1>,
    maximum_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<(File, FilesystemIdentityV1), InternalCoordinatorError> {
    let remaining = remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    let attempts = remaining.min(maximum_wait_ms).max(1);
    revalidate_directory_identity(root, directory_identity)?;
    let path = root.join(ROOT_LOCK_FILENAME);
    reject_non_regular_file(&path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let lock_identity = filesystem_identity(
        &path,
        &file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )?;
    if expected_lock_identity.is_some_and(|expected| expected != lock_identity) {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if filesystem_identity(&path, &path_metadata)? != lock_identity {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }

    for attempt in 0..attempts {
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        match file.try_lock() {
            Ok(()) => {
                revalidate_directory_identity(root, directory_identity)?;
                let path_metadata = fs::symlink_metadata(&path)
                    .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
                if path_metadata.file_type().is_symlink()
                    || !path_metadata.is_file()
                    || filesystem_identity(&path, &path_metadata)? != lock_identity
                {
                    return Err(InternalCoordinatorError::RootRoleMismatch);
                }
                return Ok((file, lock_identity));
            }
            Err(TryLockError::WouldBlock) if attempt + 1 < attempts => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => return Err(InternalCoordinatorError::RootBusy),
            Err(TryLockError::Error(_)) => return Err(InternalCoordinatorError::RootUnavailable),
        }
    }
    Err(InternalCoordinatorError::RootBusy)
}

struct RestorePackageDirectoryShapeV1 {
    relative_name: String,
}

struct RestorePackageFileShapeV1 {
    relative_name: String,
}

struct RestorePackageShapeV1 {
    directories: Vec<RestorePackageDirectoryShapeV1>,
    files: Vec<RestorePackageFileShapeV1>,
}

fn scan_restore_package_shape_v1(
    root: &Path,
) -> Result<RestorePackageShapeV1, InternalCoordinatorError> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut total_file_bytes = 0_u64;
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let remaining_directories = MAX_RESTORE_PACKAGE_DIRECTORIES_V1
            .checked_sub(directories.len())
            .ok_or(InternalCoordinatorError::RootInvalid)?;
        let remaining_files = MAX_RESTORE_PACKAGE_FILES_V1
            .checked_sub(files.len())
            .ok_or(InternalCoordinatorError::RootInvalid)?;
        for entry in
            sorted_restore_package_entries_v1(&directory, remaining_directories, remaining_files)?
        {
            let relative_name = normalized_restore_relative_name_v1(&prefix, &entry.name);
            if relative_name.split('/').count() > MAX_RESTORE_PACKAGE_COMPONENT_DEPTH_V1 {
                return Err(InternalCoordinatorError::RootInvalid);
            }
            if entry.metadata.file_type().is_symlink() {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
            if entry.metadata.is_dir() {
                directories.push(RestorePackageDirectoryShapeV1 {
                    relative_name: relative_name.clone(),
                });
                if directories.len() > MAX_RESTORE_PACKAGE_DIRECTORIES_V1 {
                    return Err(InternalCoordinatorError::RootInvalid);
                }
                pending.push((entry.path, relative_name));
            } else if entry.metadata.is_file() {
                if entry.metadata.len() > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 {
                    return Err(InternalCoordinatorError::RootInvalid);
                }
                total_file_bytes = total_file_bytes
                    .checked_add(entry.metadata.len())
                    .filter(|total| *total <= MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1)
                    .ok_or(InternalCoordinatorError::RootInvalid)?;
                files.push(RestorePackageFileShapeV1 { relative_name });
                if files.len() > MAX_RESTORE_PACKAGE_FILES_V1 {
                    return Err(InternalCoordinatorError::RootInvalid);
                }
            } else {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
        }
    }
    directories.sort_by(|left, right| left.relative_name.cmp(&right.relative_name));
    files.sort_by(|left, right| left.relative_name.cmp(&right.relative_name));
    Ok(RestorePackageShapeV1 { directories, files })
}

fn capture_restore_package_directory_v1(
    root: &Path,
    initial_prefix: &str,
    directories: &mut Vec<RestorePackageDirectoryBindingV1>,
    files: &mut Vec<RestorePackageFileBindingV1>,
) -> Result<(), InternalCoordinatorError> {
    let mut pending = vec![(root.to_path_buf(), initial_prefix.to_owned())];
    let mut total_file_bytes = 0_u64;
    while let Some((directory, prefix)) = pending.pop() {
        let remaining_directories = MAX_RESTORE_PACKAGE_DIRECTORIES_V1
            .checked_sub(directories.len())
            .ok_or(InternalCoordinatorError::RootInvalid)?;
        let remaining_files = MAX_RESTORE_PACKAGE_FILES_V1
            .checked_sub(files.len())
            .ok_or(InternalCoordinatorError::RootInvalid)?;
        for entry in
            sorted_restore_package_entries_v1(&directory, remaining_directories, remaining_files)?
        {
            let relative_name = normalized_restore_relative_name_v1(&prefix, &entry.name);
            if relative_name.split('/').count() > MAX_RESTORE_PACKAGE_COMPONENT_DEPTH_V1 {
                return Err(InternalCoordinatorError::RootInvalid);
            }
            if entry.metadata.file_type().is_symlink() {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
            if entry.metadata.is_dir() {
                directories.push(RestorePackageDirectoryBindingV1 {
                    relative_name: relative_name.clone(),
                    identity: filesystem_identity(&entry.path, &entry.metadata)?,
                });
                if directories.len() > MAX_RESTORE_PACKAGE_DIRECTORIES_V1 {
                    return Err(InternalCoordinatorError::RootInvalid);
                }
                pending.push((entry.path, relative_name));
            } else if entry.metadata.is_file() {
                if entry.metadata.len() > MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 {
                    return Err(InternalCoordinatorError::RootInvalid);
                }
                total_file_bytes = total_file_bytes
                    .checked_add(entry.metadata.len())
                    .filter(|total| *total <= MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1)
                    .ok_or(InternalCoordinatorError::RootInvalid)?;
                if files.len() >= MAX_RESTORE_PACKAGE_FILES_V1 {
                    return Err(InternalCoordinatorError::RootInvalid);
                }
                files.push(open_restore_package_file_binding_v1(
                    &entry.path,
                    relative_name,
                    &entry.metadata,
                )?);
            } else {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
        }
    }
    Ok(())
}

struct RestorePackageScannedEntryV1 {
    name: String,
    path: PathBuf,
    metadata: fs::Metadata,
}

fn sorted_restore_package_entries_v1(
    directory: &Path,
    maximum_directories: usize,
    maximum_files: usize,
) -> Result<Vec<RestorePackageScannedEntryV1>, InternalCoordinatorError> {
    let entries = fs::read_dir(directory).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let maximum_entries = maximum_directories
        .checked_add(maximum_files)
        .ok_or(InternalCoordinatorError::RootInvalid)?;
    let mut scanned = Vec::with_capacity(maximum_entries.min(32));
    let mut directories = 0_usize;
    let mut files = 0_usize;
    for entry in entries {
        // Sorting is required for a canonical member-set comparison, but read_dir is attacker
        // controlled. Refuse while enumerating instead of first accumulating an unbounded Vec.
        if scanned.len() >= maximum_entries {
            return Err(InternalCoordinatorError::RootInvalid);
        }
        let entry = entry.map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        let raw_name = entry.file_name();
        let name = validate_restore_package_component_v1(&raw_name)?.to_owned();
        let path = directory.join(&raw_name);
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if metadata.is_dir() {
            directories = directories
                .checked_add(1)
                .filter(|count| *count <= maximum_directories)
                .ok_or(InternalCoordinatorError::RootInvalid)?;
        } else if metadata.is_file() {
            files = files
                .checked_add(1)
                .filter(|count| *count <= maximum_files)
                .ok_or(InternalCoordinatorError::RootInvalid)?;
        }
        scanned.push(RestorePackageScannedEntryV1 {
            name,
            path,
            metadata,
        });
    }
    scanned.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(scanned)
}

fn open_restore_package_file_binding_v1(
    path: &Path,
    relative_name: String,
    before: &fs::Metadata,
) -> Result<RestorePackageFileBindingV1, InternalCoordinatorError> {
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    // File::open requests read-only access and neither creates nor truncates package state.
    let file = File::open(path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let held = file
        .metadata()
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let after_open =
        fs::symlink_metadata(path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if after_open.file_type().is_symlink() || !after_open.is_file() || !held.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    let identity = filesystem_identity(path, &held)?;
    if filesystem_identity(path, before)? != identity
        || filesystem_identity(path, &after_open)? != identity
        || before.len() != held.len()
        || after_open.len() != held.len()
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    let length = held.len();
    let sha256 = hash_exact_bound_member_v1(&file, length)?;

    // The digest is an authority binding only if the same retained handle is still the exact
    // regular file named by the package after hashing. Capture's final full revalidation repeats
    // both this identity check and the handle-based digest before custody can escape.
    let held_after_hash = file
        .metadata()
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let path_after_hash =
        fs::symlink_metadata(path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if path_after_hash.file_type().is_symlink()
        || !path_after_hash.is_file()
        || !held_after_hash.is_file()
    {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    if filesystem_identity(path, &held_after_hash)? != identity
        || filesystem_identity(path, &path_after_hash)? != identity
        || held_after_hash.len() != length
        || path_after_hash.len() != length
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(RestorePackageFileBindingV1 {
        relative_name,
        file,
        identity,
        length,
        sha256,
    })
}

fn verify_restore_package_file_binding_v1(
    root: &Path,
    binding: &RestorePackageFileBindingV1,
) -> Result<(), InternalCoordinatorError> {
    verify_restore_package_file_binding_metadata_v1(root, binding)?;
    if hash_exact_bound_member_v1(&binding.file, binding.length)? != binding.sha256 {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    // Close the digest-vs-path race before returning: a path substitution or resize during the
    // streaming hash cannot inherit the retained handle's binding.
    verify_restore_package_file_binding_metadata_v1(root, binding)
}

fn verify_restore_package_file_binding_metadata_v1(
    root: &Path,
    binding: &RestorePackageFileBindingV1,
) -> Result<(), InternalCoordinatorError> {
    let path = restore_package_member_path_v1(root, &binding.relative_name);
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    let held_metadata = binding
        .file
        .metadata()
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if !held_metadata.is_file()
        || filesystem_identity(&path, &path_metadata)? != binding.identity
        || filesystem_identity(&path, &held_metadata)? != binding.identity
        || path_metadata.len() != binding.length
        || held_metadata.len() != binding.length
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn validate_restore_package_component_v1(
    raw_name: &OsStr,
) -> Result<&str, InternalCoordinatorError> {
    let name = raw_name
        .to_str()
        .ok_or(InternalCoordinatorError::RootInvalid)?;
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return Err(InternalCoordinatorError::RootInvalid);
    }
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == raw_name => Ok(name),
        _ => Err(InternalCoordinatorError::RootInvalid),
    }
}

fn validate_normalized_restore_member_name_v1(
    relative_name: &str,
) -> Result<(), InternalCoordinatorError> {
    if relative_name.is_empty()
        || relative_name.starts_with('/')
        || relative_name.contains(['\\', '\0'])
    {
        return Err(InternalCoordinatorError::RootInvalid);
    }
    for component in relative_name.split('/') {
        validate_restore_package_component_v1(OsStr::new(component))?;
    }
    Ok(())
}

fn normalized_restore_relative_name_v1(prefix: &str, component: &str) -> String {
    if prefix.is_empty() {
        component.to_owned()
    } else {
        format!("{prefix}/{component}")
    }
}

fn restore_package_member_path_v1(root: &Path, relative_name: &str) -> PathBuf {
    relative_name
        .split('/')
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

fn read_exact_bound_member_v1(
    file: &mut File,
    bytes: &mut [u8],
) -> Result<(), InternalCoordinatorError> {
    let result = (|| {
        file.seek(SeekFrom::Start(0))
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if let Err(error) = file.read_exact(bytes) {
            return Err(if error.kind() == std::io::ErrorKind::UnexpectedEof {
                InternalCoordinatorError::RootRoleMismatch
            } else {
                InternalCoordinatorError::RootUnavailable
            });
        }
        let mut extra = [0_u8; 1];
        if file
            .read(&mut extra)
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?
            != 0
        {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        Ok(())
    })();
    let rewind = file
        .seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|_| InternalCoordinatorError::RootUnavailable);
    result.and(rewind)
}

fn copy_exact_bound_member_to_v1(
    source: &File,
    destination: &mut File,
    length: u64,
) -> Result<Sha256Digest, InternalCoordinatorError> {
    let source_metadata = source
        .metadata()
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let destination_metadata = destination
        .metadata()
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if !source_metadata.is_file()
        || !destination_metadata.is_file()
        || destination_metadata.len() != 0
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }

    let result = (|| {
        destination
            .seek(SeekFrom::Start(0))
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        while offset < length {
            let remaining = length
                .checked_sub(offset)
                .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| InternalCoordinatorError::RootInvalid)?;
            let read = read_restore_package_file_at_v1(source, &mut buffer[..wanted], offset)?;
            if read == 0 {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
            destination
                .write_all(&buffer[..read])
                .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
            hasher.update(&buffer[..read]);
            offset = offset
                .checked_add(
                    u64::try_from(read).map_err(|_| InternalCoordinatorError::RootInvalid)?,
                )
                .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        }
        let mut extra = [0_u8; 1];
        if read_restore_package_file_at_v1(source, &mut extra, length)? != 0 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        destination
            .sync_all()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if destination
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?
            .len()
            != length
        {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
    })();
    let rewind = destination
        .seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|_| InternalCoordinatorError::RootUnavailable);
    match result {
        Ok(digest) => {
            rewind?;
            Ok(digest)
        }
        Err(error) => {
            let _ = rewind;
            Err(error)
        }
    }
}

fn hash_exact_bound_member_v1(
    file: &File,
    length: u64,
) -> Result<Sha256Digest, InternalCoordinatorError> {
    // Positional reads keep the digest tied to the captured handle without sharing or changing
    // its stream cursor. Exactly `length` bytes plus a one-byte EOF probe are the read bound.
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while offset < length {
        let remaining = length
            .checked_sub(offset)
            .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| InternalCoordinatorError::RootInvalid)?;
        let read = read_restore_package_file_at_v1(file, &mut buffer[..wanted], offset)?;
        if read == 0 {
            return Err(InternalCoordinatorError::RootRoleMismatch);
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| InternalCoordinatorError::RootInvalid)?)
            .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
    }
    let mut extra = [0_u8; 1];
    if read_restore_package_file_at_v1(file, &mut extra, length)? != 0 {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

#[cfg(unix)]
fn read_restore_package_file_at_v1(
    file: &File,
    bytes: &mut [u8],
    offset: u64,
) -> Result<usize, InternalCoordinatorError> {
    use std::os::unix::fs::FileExt as _;

    file.read_at(bytes, offset)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)
}

#[cfg(windows)]
fn read_restore_package_file_at_v1(
    file: &File,
    bytes: &mut [u8],
    offset: u64,
) -> Result<usize, InternalCoordinatorError> {
    use std::os::windows::fs::FileExt as _;

    file.seek_read(bytes, offset)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)
}

fn validate_attested_directory(
    path: PathBuf,
) -> Result<(PathBuf, FilesystemIdentityV1), InternalCoordinatorError> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(InternalCoordinatorError::RootInvalid);
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InternalCoordinatorError::RootInvalid);
    }
    let path = fs::canonicalize(path).map_err(|_| InternalCoordinatorError::RootInvalid)?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InternalCoordinatorError::RootInvalid);
    }
    let identity =
        filesystem_identity(&path, &metadata).map_err(|_| InternalCoordinatorError::RootInvalid)?;
    Ok((path, identity))
}

fn revalidate_directory_identity(
    root: &Path,
    expected: FilesystemIdentityV1,
) -> Result<(), InternalCoordinatorError> {
    let metadata =
        fs::symlink_metadata(root).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    if filesystem_identity(root, &metadata)? != expected {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn lock_path_identity_if_present(
    root: &Path,
) -> Result<Option<FilesystemIdentityV1>, InternalCoordinatorError> {
    let path = root.join(ROOT_LOCK_FILENAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(InternalCoordinatorError::RootNotDedicated)
        }
        Ok(metadata) => Ok(Some(filesystem_identity(&path, &metadata)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(InternalCoordinatorError::RootUnavailable),
    }
}

#[derive(Clone, Copy)]
struct RootMembersV1 {
    database_present: bool,
    lock_present: bool,
    wal_present: bool,
    shm_present: bool,
}

fn scan_known_members(root: &Path) -> Result<RootMembersV1, InternalCoordinatorError> {
    let entries = fs::read_dir(root).map_err(|_| InternalCoordinatorError::RootInvalid)?;
    let mut members = RootMembersV1 {
        database_present: false,
        lock_present: false,
        wal_present: false,
        shm_present: false,
    };
    for entry in entries {
        let entry = entry.map_err(|_| InternalCoordinatorError::RootInvalid)?;
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .map_err(|_| InternalCoordinatorError::RootInvalid)?;
        if !file_type.is_file() {
            return Err(InternalCoordinatorError::RootNotDedicated);
        }
        if name == OsStr::new(COORDINATOR_DATABASE_FILENAME) {
            if members.database_present {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
            members.database_present = true;
        } else if name == OsStr::new(ROOT_LOCK_FILENAME) {
            if members.lock_present {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
            members.lock_present = true;
        } else if name == OsStr::new(COORDINATOR_WAL_FILENAME) {
            if members.wal_present {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
            members.wal_present = true;
        } else if name == OsStr::new(COORDINATOR_SHM_FILENAME) {
            if members.shm_present {
                return Err(InternalCoordinatorError::RootNotDedicated);
            }
            members.shm_present = true;
        } else {
            return Err(InternalCoordinatorError::UnknownRootMember);
        }
    }
    Ok(members)
}

fn validate_initialization_attestation_members(
    root: &Path,
) -> Result<(), InternalCoordinatorError> {
    let members = scan_known_members(root)?;
    if (members.database_present || members.wal_present || members.shm_present)
        && !members.lock_present
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    if (members.wal_present || members.shm_present) && !members.database_present {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn validate_empty_members(root: &Path) -> Result<(), InternalCoordinatorError> {
    let members = scan_known_members(root)?;
    if members.database_present || members.wal_present || members.shm_present {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn validate_initializing_snapshot(members: RootMembersV1) -> Result<(), InternalCoordinatorError> {
    if !members.lock_present
        || (members.wal_present || members.shm_present) && !members.database_present
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn validate_existing_snapshot(members: RootMembersV1) -> Result<(), InternalCoordinatorError> {
    if !members.database_present || !members.lock_present {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn validate_existing_members(root: &Path) -> Result<(), InternalCoordinatorError> {
    validate_existing_snapshot(scan_known_members(root)?)
}

fn validate_members_for_marker(
    root: &Path,
    marker: DurableRootMarkerV1,
) -> Result<(), InternalCoordinatorError> {
    match marker {
        DurableRootMarkerV1::Empty => validate_empty_members(root),
        DurableRootMarkerV1::Initializing(_) => {
            validate_initializing_snapshot(scan_known_members(root)?)
        }
        DurableRootMarkerV1::Existing(_) => validate_existing_members(root),
    }
}

fn map_lock_error(error: TryLockError) -> InternalCoordinatorError {
    match error {
        TryLockError::WouldBlock => InternalCoordinatorError::RootBusy,
        TryLockError::Error(_) => InternalCoordinatorError::RootUnavailable,
    }
}

fn identity_marker_prefix(identity: CoordinatorRootIdentityV1) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = Vec::with_capacity(IDENTITY_MARKER_PREFIX.len() + HEX_IDENTITY_LENGTH + 1);
    bytes.extend_from_slice(IDENTITY_MARKER_PREFIX);
    for byte in identity.as_bytes() {
        bytes.push(HEX[usize::from(byte >> 4)]);
        bytes.push(HEX[usize::from(byte & 0x0f)]);
    }
    bytes.push(b'\n');
    bytes
}

fn identity_marker_bytes(identity: CoordinatorRootIdentityV1, state: &[u8]) -> Vec<u8> {
    let mut bytes = identity_marker_prefix(identity);
    bytes.extend_from_slice(state);
    bytes
}

fn parse_exact_marker(bytes: &[u8]) -> Option<DurableRootMarkerV1> {
    if bytes == EMPTY_ROOT_LOCK_CONTENT {
        return Some(DurableRootMarkerV1::Empty);
    }
    let identity = recoverable_marker_identity(bytes)?;
    let prefix_length = IDENTITY_MARKER_PREFIX.len() + HEX_IDENTITY_LENGTH + 1;
    match bytes.get(prefix_length..) {
        Some(suffix) if suffix == INITIALIZING_STATE_SUFFIX => {
            Some(DurableRootMarkerV1::Initializing(identity))
        }
        Some(suffix) if suffix == EXISTING_STATE_SUFFIX => {
            Some(DurableRootMarkerV1::Existing(identity))
        }
        _ => None,
    }
}

fn recoverable_marker_identity(bytes: &[u8]) -> Option<CoordinatorRootIdentityV1> {
    if !bytes.starts_with(IDENTITY_MARKER_PREFIX) {
        return None;
    }
    let start = IDENTITY_MARKER_PREFIX.len();
    let end = start.checked_add(HEX_IDENTITY_LENGTH)?;
    let encoded = bytes.get(start..end)?;
    if bytes.get(end) != Some(&b'\n') {
        return None;
    }
    let mut identity = [0_u8; 32];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        identity[index] = decode_lower_hex(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_lower_hex(pair[1])?)?;
    }
    Some(CoordinatorRootIdentityV1::from_bytes(identity))
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn write_and_sync_exact(file: &mut File, expected: &[u8]) -> Result<(), InternalCoordinatorError> {
    file.write_all(expected)
        .and_then(|()| file.sync_all())
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    verify_exact_file(file, expected)
}

fn rewrite_and_sync_exact(
    file: &mut File,
    expected: &[u8],
) -> Result<(), InternalCoordinatorError> {
    file.set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    write_and_sync_exact(file, expected)
}

fn rewrite_identity_state(
    file: &mut File,
    identity: CoordinatorRootIdentityV1,
    state: &[u8],
) -> Result<(), InternalCoordinatorError> {
    let prefix = identity_marker_prefix(identity);
    let actual = read_exact_file(file)?;
    if !actual.starts_with(&prefix) {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    let offset =
        u64::try_from(prefix.len()).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.write_all(state))
        .and_then(|()| {
            let length = offset
                .checked_add(u64::try_from(state.len()).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "marker length")
                })?)
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "marker length")
                })?;
            file.set_len(length)
        })
        .and_then(|()| file.sync_all())
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    verify_exact_file(file, &identity_marker_bytes(identity, state))
}

fn verify_exact_file(file: &mut File, expected: &[u8]) -> Result<(), InternalCoordinatorError> {
    if read_exact_file(file)? != expected {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn read_exact_file(file: &mut File) -> Result<Vec<u8>, InternalCoordinatorError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let mut actual = Vec::new();
    file.read_to_end(&mut actual)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    Ok(actual)
}

fn reject_non_regular_file(path: &Path) -> Result<(), InternalCoordinatorError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    Ok(())
}

fn filesystem_identity_binding_sha256_v1(
    domain: &[u8],
    identity: FilesystemIdentityV1,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    #[cfg(unix)]
    {
        hasher.update(b"unix\0");
        hasher.update(identity.device.to_be_bytes());
        hasher.update(identity.inode.to_be_bytes());
    }
    #[cfg(windows)]
    {
        hasher.update(b"windows\0");
        hasher.update(identity.volume_serial_number.to_be_bytes());
        hasher.update(identity.file_id.to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(unix)]
fn filesystem_identity(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<FilesystemIdentityV1, InternalCoordinatorError> {
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
) -> Result<FilesystemIdentityV1, InternalCoordinatorError> {
    match file_id::get_high_res_file_id(path)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?
    {
        file_id::FileId::HighRes {
            volume_serial_number,
            file_id,
        } => Ok(FilesystemIdentityV1 {
            volume_serial_number,
            file_id,
        }),
        file_id::FileId::Inode { .. } | file_id::FileId::LowRes { .. } => {
            Err(InternalCoordinatorError::RootUnavailable)
        }
    }
}

#[cfg(unix)]
pub(crate) fn sync_directory_entry(root: &Path) -> Result<(), InternalCoordinatorError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InternalCoordinatorError::RootUnavailable)
}

#[cfg(windows)]
pub(crate) fn sync_directory_entry(_root: &Path) -> Result<(), InternalCoordinatorError> {
    // Stable std cannot open a directory with FILE_FLAG_BACKUP_SEMANTICS without unsafe
    // platform bindings. The newly-created lock file itself is flushed above; all later
    // admission boundaries still revalidate its high-resolution volume/file identity.
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::ROOT_LOCK_FILENAME;
    use super::{
        begin_empty_restore_root_custody_v1, capture_immutable_members_v1,
        inspect_existing_restore_root_custody_v1, reopen_restore_pending_root_custody_v1,
        CoordinatorRootIdentityV1, ProvisionedEmptyCoordinatorRootV1, ProvisionedRestorePackageV1,
        COORDINATOR_DATABASE_FILENAME, MAX_RESTORE_PACKAGE_DIRECTORIES_V1,
        MAX_RESTORE_PACKAGE_FILES_V1, MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1,
        MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1,
    };
    use crate::clock::CoordinatorMonotonicClockV1;
    use crate::error::{CoordinatorClockUnavailableV1, InternalCoordinatorError};
    use helix_contracts::{Identifier, Sha256Digest};
    use std::fs::{self, File, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const DEADLINE_MS: u64 = 10_000;

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl CoordinatorMonotonicClockV1 for FixedClock {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            Ok(1_000)
        }
    }

    struct SyntheticRoot(PathBuf);

    impl SyntheticRoot {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "helixos-restore-root-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("synthetic restore root creates");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for SyntheticRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn restore_package_custody_is_bounded_normalized_read_only_and_redacted() {
        const PRIVATE_ROOT: &str = "DO-NOT-DISCLOSE-package-root";
        const PRIVATE_MEMBER: &str = "DO-NOT-DISCLOSE-provider-manifest.json";
        const DATABASE: &[u8] = b"synthetic coordinator database";
        const MANIFEST: &[u8] = b"synthetic provider manifest";
        let root = SyntheticRoot::new(PRIVATE_ROOT);
        fs::create_dir(root.path().join("published")).expect("published creates");
        fs::create_dir(root.path().join("staging")).expect("staging creates");
        fs::create_dir(root.path().join("recovery-packages")).expect("recovery packages creates");
        fs::create_dir(root.path().join("recovery-packages/package-0001"))
            .expect("package directory creates");
        fs::write(root.path().join(COORDINATOR_DATABASE_FILENAME), DATABASE)
            .expect("database writes");
        fs::write(
            root.path()
                .join("recovery-packages/package-0001")
                .join(PRIVATE_MEMBER),
            MANIFEST,
        )
        .expect("manifest writes");

        let provisioned = ProvisionedRestorePackageV1::try_from_attested(root.path().to_path_buf())
            .expect("restore package attests");
        assert_eq!(
            format!("{provisioned:?}"),
            "ProvisionedRestorePackageV1 { .. }"
        );
        let mut custody =
            capture_immutable_members_v1(&provisioned).expect("package custody captures");
        let debug = format!("{custody:?}");
        assert_eq!(debug, "RestorePackageCustodyV1 { .. }");
        assert!(!debug.contains(PRIVATE_ROOT));
        assert!(!debug.contains(PRIVATE_MEMBER));
        assert_eq!(
            custody
                .directory_names_v1()
                .expect("directory names revalidate"),
            vec![
                "published",
                "recovery-packages",
                "recovery-packages/package-0001",
                "staging",
            ]
        );
        let normalized_member = format!("recovery-packages/package-0001/{PRIVATE_MEMBER}");
        assert_eq!(
            custody.member_names_v1().expect("member names revalidate"),
            vec![COORDINATOR_DATABASE_FILENAME, normalized_member.as_str()]
        );
        assert_eq!(
            custody
                .member_path_v1(COORDINATOR_DATABASE_FILENAME)
                .expect("member path revalidates"),
            fs::canonicalize(root.path())
                .expect("package canonicalizes")
                .join(COORDINATOR_DATABASE_FILENAME)
        );
        assert_eq!(
            custody
                .member_path_v1("../coordinator.sqlite3")
                .expect_err("traversal member name must be refused"),
            InternalCoordinatorError::RootInvalid
        );
        assert_eq!(
            custody
                .read_member_v1(COORDINATOR_DATABASE_FILENAME, DATABASE.len() as u64 - 1)
                .expect_err("explicit byte bound must be enforced"),
            InternalCoordinatorError::RootInvalid
        );
        assert_eq!(
            custody
                .read_member_v1(COORDINATOR_DATABASE_FILENAME, DATABASE.len() as u64)
                .expect("exact bounded member reads"),
            DATABASE
        );
        let (digest, length) = custody
            .hash_member_sha256_v1(COORDINATOR_DATABASE_FILENAME, DATABASE.len() as u64)
            .expect("member hashes through retained handle");
        assert_eq!(digest, Sha256Digest::digest(DATABASE));
        assert_eq!(length, DATABASE.len() as u64);
        assert_eq!(
            custody
                .read_member_v1(COORDINATOR_DATABASE_FILENAME, DATABASE.len() as u64)
                .expect("hash rewinds retained handle"),
            DATABASE
        );

        let snapshot_root = SyntheticRoot::new("private-package-snapshot");
        let snapshot_path = snapshot_root.path().join("coordinator.snapshot");
        let mut snapshot = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&snapshot_path)
            .expect("private create-only snapshot opens");
        let (snapshot_digest, snapshot_length) = custody
            .copy_member_to_v1(
                COORDINATOR_DATABASE_FILENAME,
                &mut snapshot,
                DATABASE.len() as u64,
            )
            .expect("captured handle streams into private snapshot");
        assert_eq!(snapshot_digest, Sha256Digest::digest(DATABASE));
        assert_eq!(snapshot_length, DATABASE.len() as u64);
        assert_eq!(
            fs::read(snapshot_path).expect("private snapshot reads"),
            DATABASE
        );
    }

    #[test]
    fn restore_package_attestation_refuses_every_resource_cap_plus_one() {
        let oversized = SyntheticRoot::new("package-oversized-member");
        let sparse = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(oversized.path().join("oversized.bin"))
            .expect("sparse file creates");
        sparse
            .set_len(MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1 + 1)
            .expect("sparse file length sets without materializing bytes");
        assert_eq!(
            ProvisionedRestorePackageV1::try_from_attested(oversized.path().to_path_buf())
                .expect_err("cap plus one refuses before hashing"),
            InternalCoordinatorError::RootInvalid
        );

        let too_many = SyntheticRoot::new("package-too-many-members");
        for index in 0..=MAX_RESTORE_PACKAGE_FILES_V1 {
            File::create(too_many.path().join(format!("member-{index:04}")))
                .expect("bounded empty member creates");
        }
        assert_eq!(
            ProvisionedRestorePackageV1::try_from_attested(too_many.path().to_path_buf())
                .expect_err("file count cap plus one refuses"),
            InternalCoordinatorError::RootInvalid
        );

        let aggregate = SyntheticRoot::new("package-aggregate-over-cap");
        for index in 0..5 {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(aggregate.path().join(format!("member-{index}")))
                .expect("aggregate sparse member creates");
            file.set_len(if index == 4 {
                1
            } else {
                MAX_RESTORE_PACKAGE_TOTAL_FILE_BYTES_V1 / 4
            })
            .expect("aggregate sparse length sets");
        }
        assert_eq!(
            ProvisionedRestorePackageV1::try_from_attested(aggregate.path().to_path_buf())
                .expect_err("aggregate cap plus one refuses"),
            InternalCoordinatorError::RootInvalid
        );

        let too_many_directories = SyntheticRoot::new("package-too-many-directories");
        for index in 0..=MAX_RESTORE_PACKAGE_DIRECTORIES_V1 {
            fs::create_dir(too_many_directories.path().join(format!("dir-{index:04}")))
                .expect("bounded empty directory creates");
        }
        assert_eq!(
            ProvisionedRestorePackageV1::try_from_attested(
                too_many_directories.path().to_path_buf(),
            )
            .expect_err("directory count cap plus one refuses"),
            InternalCoordinatorError::RootInvalid
        );

        let too_deep = SyntheticRoot::new("package-too-deep");
        fs::create_dir_all(too_deep.path().join("one/two/three/four"))
            .expect("deep package tree creates");
        assert_eq!(
            ProvisionedRestorePackageV1::try_from_attested(too_deep.path().to_path_buf())
                .expect_err("component depth cap plus one refuses"),
            InternalCoordinatorError::RootInvalid
        );
    }

    #[test]
    fn restore_package_attestation_accepts_exact_resource_caps() {
        let exact_counts = SyntheticRoot::new("package-exact-member-counts");
        for index in 0..MAX_RESTORE_PACKAGE_DIRECTORIES_V1 {
            fs::create_dir(exact_counts.path().join(format!("dir-{index:04}")))
                .expect("exact-cap directory creates");
        }
        for index in 0..MAX_RESTORE_PACKAGE_FILES_V1 {
            File::create(exact_counts.path().join(format!("member-{index:04}")))
                .expect("exact-cap file creates");
        }
        ProvisionedRestorePackageV1::try_from_attested(exact_counts.path().to_path_buf())
            .expect("exact directory and file-count caps attest");

        let exact_bytes = SyntheticRoot::new("package-exact-byte-counts");
        for index in 0..4 {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(exact_bytes.path().join(format!("member-{index}")))
                .expect("exact-cap sparse member creates");
            file.set_len(MAX_RESTORE_PACKAGE_SINGLE_FILE_BYTES_V1)
                .expect("exact-cap sparse member length sets");
        }
        ProvisionedRestorePackageV1::try_from_attested(exact_bytes.path().to_path_buf())
            .expect("exact single-file and total-byte caps attest");

        let exact_depth = SyntheticRoot::new("package-exact-depth");
        fs::create_dir_all(exact_depth.path().join("one/two/three"))
            .expect("exact-depth package tree creates");
        ProvisionedRestorePackageV1::try_from_attested(exact_depth.path().to_path_buf())
            .expect("exact component-depth cap attests");
    }

    #[test]
    fn attested_directory_bindings_are_domain_separated_stable_and_debug_redacted() {
        const PRIVATE_LABEL: &str = "DO-NOT-DISCLOSE-directory-binding";
        let root = SyntheticRoot::new(PRIVATE_LABEL);
        let empty = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
            .expect("empty root attests");
        let package = ProvisionedRestorePackageV1::try_from_attested(root.path().to_path_buf())
            .expect("package root attests");
        let empty_binding = empty.attested_directory_binding_sha256_v1();
        let package_binding = package.attested_directory_binding_sha256_v1();
        assert_eq!(
            empty_binding,
            empty.clone().attested_directory_binding_sha256_v1()
        );
        assert_eq!(
            package_binding,
            package.clone().attested_directory_binding_sha256_v1()
        );
        assert_ne!(empty_binding, package_binding);
        let empty_debug = format!("{empty:?}");
        let package_debug = format!("{package:?}");
        assert!(!empty_debug.contains(PRIVATE_LABEL));
        assert!(!package_debug.contains(PRIVATE_LABEL));
        assert!(!empty_debug.contains(&empty_binding.to_hex()));
        assert!(!package_debug.contains(&package_binding.to_hex()));
    }

    #[test]
    fn restore_package_custody_detects_extra_file_and_empty_directory() {
        let root = SyntheticRoot::new("package-extra-members");
        fs::write(root.path().join("manifest.json"), b"manifest").expect("manifest writes");
        let provisioned = ProvisionedRestorePackageV1::try_from_attested(root.path().to_path_buf())
            .expect("restore package attests");
        let custody = capture_immutable_members_v1(&provisioned).expect("package custody captures");

        fs::write(root.path().join("late-extra"), b"extra").expect("late extra writes");
        assert_eq!(
            custody
                .revalidate_v1()
                .expect_err("late extra file changes exact package set"),
            InternalCoordinatorError::RootRoleMismatch
        );
        fs::remove_file(root.path().join("late-extra")).expect("late extra removes");
        fs::create_dir(root.path().join("late-empty-directory"))
            .expect("late empty directory creates");
        assert_eq!(
            custody
                .revalidate_v1()
                .expect_err("late empty directory changes exact package set"),
            InternalCoordinatorError::RootRoleMismatch
        );
    }

    #[test]
    fn restore_package_custody_detects_same_inode_same_length_content_mutation() {
        const ORIGINAL: &[u8] = b"captured-content";
        const MUTATED: &[u8] = b"tampered-content";
        assert_eq!(ORIGINAL.len(), MUTATED.len());

        let root = SyntheticRoot::new("package-same-inode-content-mutation");
        let member = root.path().join("manifest.json");
        fs::write(&member, ORIGINAL).expect("original member writes");
        let provisioned = ProvisionedRestorePackageV1::try_from_attested(root.path().to_path_buf())
            .expect("restore package attests");
        let mut custody =
            capture_immutable_members_v1(&provisioned).expect("package custody captures");

        fs::write(&member, MUTATED).expect("same-length in-place mutation writes");
        assert_eq!(
            custody
                .revalidate_v1()
                .expect_err("same-inode same-length mutation must invalidate custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        assert_eq!(
            custody
                .member_path_v1("manifest.json")
                .expect_err("mutated member path must not escape custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        assert_eq!(
            custody
                .read_member_v1("manifest.json", ORIGINAL.len() as u64)
                .expect_err("mutated member bytes must not escape custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        assert_eq!(
            custody
                .hash_member_sha256_v1("manifest.json", ORIGINAL.len() as u64)
                .expect_err("mutated member digest must not escape custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        let snapshot_root = SyntheticRoot::new("refused-mutated-package-snapshot");
        let snapshot_path = snapshot_root.path().join("manifest.snapshot");
        let mut snapshot = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&snapshot_path)
            .expect("empty private snapshot opens");
        assert_eq!(
            custody
                .copy_member_to_v1("manifest.json", &mut snapshot, ORIGINAL.len() as u64,)
                .expect_err("mutated source must not populate a private snapshot"),
            InternalCoordinatorError::RootRoleMismatch
        );
        assert_eq!(
            fs::metadata(snapshot_path)
                .expect("refused snapshot metadata reads")
                .len(),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_package_custody_rejects_symlink_at_capture_and_revalidation() {
        use std::os::unix::fs::symlink;

        let root = SyntheticRoot::new("package-symlink");
        let outside = root.path().with_extension("outside-member");
        fs::write(&outside, b"outside").expect("outside file writes");
        symlink(&outside, root.path().join("member")).expect("initial package symlink creates");
        assert_eq!(
            ProvisionedRestorePackageV1::try_from_attested(root.path().to_path_buf())
                .expect_err("package symlink must fail attestation"),
            InternalCoordinatorError::RootNotDedicated
        );

        fs::remove_file(root.path().join("member")).expect("initial symlink removes");
        fs::write(root.path().join("member"), b"outside").expect("regular member writes");
        let provisioned = ProvisionedRestorePackageV1::try_from_attested(root.path().to_path_buf())
            .expect("regular package attests");
        let custody = capture_immutable_members_v1(&provisioned).expect("regular package captures");
        fs::remove_file(root.path().join("member")).expect("regular member removes");
        symlink(&outside, root.path().join("member")).expect("replacement symlink creates");
        assert_eq!(
            custody
                .revalidate_v1()
                .expect_err("replacement symlink must fail custody"),
            InternalCoordinatorError::RootNotDedicated
        );
        fs::remove_file(outside).expect("outside file removes");
    }

    #[cfg(unix)]
    #[test]
    fn restore_package_file_and_directory_inode_substitution_is_detected() {
        let root = SyntheticRoot::new("package-inode-substitution");
        fs::create_dir(root.path().join("nested")).expect("nested creates");
        fs::write(root.path().join("nested/member"), b"same-length").expect("member writes");
        let provisioned = ProvisionedRestorePackageV1::try_from_attested(root.path().to_path_buf())
            .expect("restore package attests");
        let mut custody =
            capture_immutable_members_v1(&provisioned).expect("package custody captures");

        let member = root.path().join("nested/member");
        let displaced_member = root.path().with_extension("displaced-member");
        fs::rename(&member, &displaced_member).expect("held member displaces");
        fs::write(&member, b"same-length").expect("replacement member writes");
        assert_eq!(
            custody
                .revalidate_v1()
                .expect_err("same-length replacement inode cannot inherit custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        assert_eq!(
            custody
                .member_path_v1("nested/member")
                .expect_err("replacement path cannot escape retained-handle custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        assert_eq!(
            custody
                .hash_member_sha256_v1("nested/member", b"same-length".len() as u64)
                .expect_err("replacement path cannot inherit the captured member digest"),
            InternalCoordinatorError::RootRoleMismatch
        );

        fs::remove_file(&member).expect("replacement member removes");
        fs::rename(&displaced_member, &member).expect("held member restores");
        custody
            .revalidate_v1()
            .expect("restored held member identity revalidates");
        let displaced_directory = root.path().with_extension("displaced-directory");
        fs::rename(root.path().join("nested"), &displaced_directory)
            .expect("held directory displaces");
        fs::create_dir(root.path().join("nested")).expect("replacement directory creates");
        fs::write(root.path().join("nested/member"), b"same-length")
            .expect("replacement nested member writes");
        assert_eq!(
            custody
                .revalidate_v1()
                .expect_err("replacement directory cannot inherit custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        fs::remove_dir_all(root.path().join("nested")).expect("replacement directory tree removes");
        fs::rename(displaced_directory, root.path().join("nested"))
            .expect("held directory restores for cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn restore_package_member_validation_rejects_non_utf8_name() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let name = OsString::from_vec(vec![b'm', 0xff, b'r']);
        assert_eq!(
            super::validate_restore_package_component_v1(&name)
                .expect_err("non-utf8 package member must be refused"),
            InternalCoordinatorError::RootInvalid
        );
    }

    #[test]
    fn restore_inspection_refuses_wrong_ticket_binding_and_marker_identity() {
        let root = SyntheticRoot::new("restore-inspection-wrong-ticket");
        let binding = Sha256Digest::digest(b"restore-inspection-destination");
        let profile = Identifier::new("at-rest.synthetic-v1".to_owned(), 128)
            .expect("synthetic profile validates");
        let attested = ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
            root.path().to_path_buf(),
            binding,
            profile,
        )
        .expect("restore reservation attests");
        let persisted_identity = CoordinatorRootIdentityV1::from_bytes([0x41; 32]);
        let expected_identity = CoordinatorRootIdentityV1::from_bytes([0x42; 32]);
        drop(
            begin_empty_restore_root_custody_v1(
                &attested,
                persisted_identity,
                1,
                &FixedClock,
                DEADLINE_MS,
            )
            .expect("persisted marker starts"),
        );

        assert_eq!(
            inspect_existing_restore_root_custody_v1(
                &attested,
                Sha256Digest::digest(b"different-destination"),
                persisted_identity,
                1,
                &FixedClock,
                DEADLINE_MS,
            )
            .expect_err("a different provisioner reservation must refuse"),
            InternalCoordinatorError::RootIdentityMismatch
        );
        let wrong_marker_identity = inspect_existing_restore_root_custody_v1(
            &attested,
            binding,
            expected_identity,
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect_err("a marker for another ticket root must refuse");
        #[cfg(unix)]
        assert_eq!(
            wrong_marker_identity,
            InternalCoordinatorError::RootIdentityMismatch
        );
        #[cfg(not(unix))]
        assert_eq!(
            wrong_marker_identity,
            InternalCoordinatorError::RootUnavailable,
            "non-Unix inspection remains unavailable without native directory-handle custody"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_inspection_detects_marker_mutation_and_directory_swap() {
        let binding = Sha256Digest::digest(b"restore-inspection-held-destination");
        let profile = Identifier::new("at-rest.synthetic-v1".to_owned(), 128)
            .expect("synthetic profile validates");
        let root = SyntheticRoot::new("restore-inspection-marker-mutation");
        let attested = ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
            root.path().to_path_buf(),
            binding,
            profile.clone(),
        )
        .expect("restore reservation attests");
        let identity = CoordinatorRootIdentityV1::from_bytes([0x51; 32]);
        drop(
            begin_empty_restore_root_custody_v1(&attested, identity, 1, &FixedClock, DEADLINE_MS)
                .expect("persisted marker starts"),
        );
        let mut custody = inspect_existing_restore_root_custody_v1(
            &attested,
            binding,
            identity,
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect("exact started root is inspected");
        assert!(custody.restore_has_started_v1());
        fs::write(
            root.path().join(ROOT_LOCK_FILENAME),
            super::identity_marker_bytes(
                CoordinatorRootIdentityV1::from_bytes([0x52; 32]),
                super::INITIALIZING_STATE_SUFFIX,
            ),
        )
        .expect("adversarial in-place marker mutation writes");
        assert_eq!(
            custody
                .revalidate_v1(&attested)
                .expect_err("held inspection rejects changed marker identity"),
            InternalCoordinatorError::RootRoleMismatch
        );
        drop(custody);

        let unstarted = SyntheticRoot::new("restore-inspection-directory-swap");
        let unstarted_attested =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested_restore_reservation_v1(
                unstarted.path().to_path_buf(),
                binding,
                profile,
            )
            .expect("unstarted reservation attests");
        let mut unstarted_custody = inspect_existing_restore_root_custody_v1(
            &unstarted_attested,
            binding,
            identity,
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect("unstarted exact directory is inspected");
        assert!(!unstarted_custody.restore_has_started_v1());
        let displaced = unstarted.path().with_extension("displaced-root");
        fs::rename(unstarted.path(), &displaced).expect("attested directory displaces");
        fs::create_dir(unstarted.path()).expect("replacement directory creates");
        assert_eq!(
            unstarted_custody
                .revalidate_v1(&unstarted_attested)
                .expect_err("replacement directory cannot inherit reservation custody"),
            InternalCoordinatorError::RootRoleMismatch
        );
        drop(unstarted_custody);
        fs::remove_dir(unstarted.path()).expect("replacement directory removes");
        fs::rename(displaced, unstarted.path()).expect("attested directory restores for cleanup");
    }

    #[test]
    fn restore_custody_is_empty_only_create_new_and_redacted() {
        const PRIVATE_LABEL: &str = "DO-NOT-DISCLOSE-restore-root";
        let root = SyntheticRoot::new(PRIVATE_LABEL);
        let attested =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
                .expect("empty restore root attests");
        let identity = CoordinatorRootIdentityV1::from_bytes([0xA5; 32]);
        let mut custody =
            begin_empty_restore_root_custody_v1(&attested, identity, 1, &FixedClock, DEADLINE_MS)
                .expect("empty restore custody begins");
        let debug = format!("{custody:?}");
        assert_eq!(debug, "CoordinatorRestoreRootCustodyV1 { .. }");
        assert!(!debug.contains(PRIVATE_LABEL));
        assert!(!debug.contains(&"a5".repeat(32)));
        let marker = super::read_exact_file(&mut custody.root_lease.file)
            .expect("initializing marker reads through retained custody");
        assert!(marker.ends_with(b"STATE=INITIALIZING\n"));

        custody
            .reserve_database_import_create_new_v1()
            .expect("database inode reserves create-new");
        assert!(root.path().join(COORDINATOR_DATABASE_FILENAME).is_file());
        custody
            .reserve_database_import_create_new_v1()
            .expect("exact interrupted reservation resumes without clobbering");

        const PRIVATE_MEMBER: &str = "DO-NOT-DISCLOSE-foreign-member";
        File::create(root.path().join(PRIVATE_MEMBER)).expect("foreign member creates");
        let error = custody
            .revalidate_imported_database_v1()
            .expect_err("late unknown member denies restore custody");
        assert_eq!(error, InternalCoordinatorError::UnknownRootMember);
        assert!(!format!("{error:?}").contains(PRIVATE_MEMBER));
    }

    #[test]
    fn restore_custody_reports_database_present_at_begin_without_mutation() {
        let root = SyntheticRoot::new("restore-import-resume-observation");
        let attested =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
                .expect("empty restore root attests");
        let identity = CoordinatorRootIdentityV1::from_bytes([0xD8; 32]);
        let mut initial =
            begin_empty_restore_root_custody_v1(&attested, identity, 1, &FixedClock, DEADLINE_MS)
                .expect("initial restore custody begins");
        assert!(!initial
            .database_import_already_present_v1()
            .expect("empty import observation revalidates"));
        assert!(!root.path().join(COORDINATOR_DATABASE_FILENAME).exists());

        initial
            .reserve_database_import_create_new_v1()
            .expect("initial import inode reserves");
        assert!(!initial
            .database_import_already_present_v1()
            .expect("same custody preserves begin observation"));
        drop(initial);

        let interrupted =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
                .expect("interrupted import root re-attests");
        let mut resumed = begin_empty_restore_root_custody_v1(
            &interrupted,
            identity,
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect("interrupted import custody resumes");
        assert!(resumed
            .database_import_already_present_v1()
            .expect("resumed import observation revalidates retained inode"));
    }

    #[test]
    fn pending_publication_reopens_only_under_exact_maintenance_identity() {
        const PRIVATE_LABEL: &str = "DO-NOT-DISCLOSE-pending-root";
        let root = SyntheticRoot::new(PRIVATE_LABEL);
        let attested =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
                .expect("empty restore root attests");
        let identity = CoordinatorRootIdentityV1::from_bytes([0xB6; 32]);
        let mut importing =
            begin_empty_restore_root_custody_v1(&attested, identity, 1, &FixedClock, DEADLINE_MS)
                .expect("restore custody begins");
        importing
            .reserve_database_import_create_new_v1()
            .expect("database import reserves");
        assert_eq!(
            importing
                .finalize_restore_pending_publication_for_test_v1(
                    CoordinatorRootIdentityV1::from_bytes([0xC7; 32]),
                )
                .expect_err("mismatched schema proof cannot publish marker"),
            InternalCoordinatorError::RootIdentityMismatch
        );

        // Simulates process loss after the database commit but before EXISTING marker
        // publication. Re-attestation must recover the exact INITIALIZING identity and
        // held database inode rather than treating the root as a fresh empty target.
        let interrupted =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
                .expect("interrupted restore root re-attests");
        let mut resumed = begin_empty_restore_root_custody_v1(
            &interrupted,
            identity,
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect("matching INITIALIZING restore resumes");
        resumed
            .reserve_database_import_create_new_v1()
            .expect("existing bound database reservation resumes idempotently");
        let mut pending = resumed
            .finalize_restore_pending_publication_for_test_v1(identity)
            .expect("pending marker publication finalizes");
        let debug = format!("{pending:?}");
        assert_eq!(debug, "CoordinatorPendingRootCustodyV1 { .. }");
        assert!(!debug.contains(PRIVATE_LABEL));
        assert!(!debug.contains(&"b6".repeat(32)));
        pending
            .revalidate_v1()
            .expect("held pending custody verifies");
        drop(pending);

        let reattested =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
                .expect("maintenance re-attests pending root members");
        let wrong = reopen_restore_pending_root_custody_v1(
            &reattested,
            CoordinatorRootIdentityV1::from_bytes([0xC7; 32]),
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect_err("wrong pending identity denies");
        assert_eq!(wrong, InternalCoordinatorError::RootIdentityMismatch);

        let mut reopened = reopen_restore_pending_root_custody_v1(
            &reattested,
            identity,
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect("exact pending maintenance custody reopens");
        assert_eq!(
            reopened.database_path_v1().expect("bound path is usable"),
            fs::canonicalize(root.path())
                .expect("synthetic root canonicalizes")
                .join(COORDINATOR_DATABASE_FILENAME)
        );
        reopened.revalidate_v1().expect("reopened custody verifies");
    }

    #[cfg(unix)]
    #[test]
    fn restore_database_inode_replacement_is_detected_while_custody_is_held() {
        let root = SyntheticRoot::new("database-inode-replacement");
        let attested =
            ProvisionedEmptyCoordinatorRootV1::try_from_attested(root.path().to_path_buf())
                .expect("empty restore root attests");
        let mut custody = begin_empty_restore_root_custody_v1(
            &attested,
            CoordinatorRootIdentityV1::from_bytes([0xD8; 32]),
            1,
            &FixedClock,
            DEADLINE_MS,
        )
        .expect("restore custody begins");
        custody
            .reserve_database_import_create_new_v1()
            .expect("database import reserves");
        let database = root.path().join(COORDINATOR_DATABASE_FILENAME);
        let displaced = root.path().with_extension("displaced-database");
        fs::rename(&database, &displaced).expect("held database displaces");
        File::create(&database).expect("replacement database creates");

        assert_eq!(
            custody
                .revalidate_imported_database_v1()
                .expect_err("replacement inode cannot inherit restore custody"),
            InternalCoordinatorError::RootRoleMismatch
        );

        fs::remove_file(&database).expect("replacement removes");
        fs::rename(displaced, database).expect("held inode restores for cleanup");
    }
}
