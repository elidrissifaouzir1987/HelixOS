//! Trusted coordinator-store configuration.

use crate::error::InternalCoordinatorError;
use crate::root_safety::{
    CoordinatorRootIdentityV1, ProvisionedEmptyCoordinatorRootV1,
    ProvisionedExistingCoordinatorRootV1, COORDINATOR_DATABASE_FILENAME,
};
use helix_contracts::MAX_SAFE_U64;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

/// Opaque provisioner custody evidence for one coordinator root identity.
///
/// This value is deliberately non-Serde and redacted under formatting. The provisioner
/// may persist its exact bytes in its own restricted custody and attest them on reopen.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorRootIdentityEvidenceV1([u8; 32]);

impl CoordinatorRootIdentityEvidenceV1 {
    pub const fn from_attested_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_attested_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) const fn from_internal(identity: CoordinatorRootIdentityV1) -> Self {
        Self(*identity.as_bytes())
    }

    pub(crate) const fn into_internal(self) -> CoordinatorRootIdentityV1 {
        CoordinatorRootIdentityV1::from_bytes(self.0)
    }
}

impl fmt::Debug for CoordinatorRootIdentityEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorRootIdentityEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Closed, payload-free failure returned while constructing trusted configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorStoreConfigErrorV1 {
    InvalidBusyBound,
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    UnknownRootMember,
}

impl CoordinatorStoreConfigErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBusyBound => "INVALID_BUSY_BOUND",
            Self::RootInvalid => "ROOT_INVALID",
            Self::RootNotDedicated => "ROOT_NOT_DEDICATED",
            Self::RootRoleMismatch => "ROOT_ROLE_MISMATCH",
            Self::UnknownRootMember => "UNKNOWN_ROOT_MEMBER",
        }
    }

    const fn from_internal(error: InternalCoordinatorError) -> Self {
        match error {
            InternalCoordinatorError::RootInvalid => Self::RootInvalid,
            InternalCoordinatorError::RootNotDedicated => Self::RootNotDedicated,
            InternalCoordinatorError::UnknownRootMember => Self::UnknownRootMember,
            _ => Self::RootRoleMismatch,
        }
    }
}

impl fmt::Debug for CoordinatorStoreConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for CoordinatorStoreConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for CoordinatorStoreConfigErrorV1 {}

#[derive(Clone)]
enum CoordinatorRootConfigV1 {
    Empty(ProvisionedEmptyCoordinatorRootV1),
    Existing(ProvisionedExistingCoordinatorRootV1),
}

/// Checked coordinator-store configuration with a provisioner-attested root role.
///
/// An empty root receives OS-random opaque storage authority during initialization. An
/// existing root carries the provisioner-attested expected identity matched on every
/// healthy open; identity is never inferred from a filesystem path.
#[derive(Clone)]
pub struct CoordinatorStoreConfigV1 {
    root: CoordinatorRootConfigV1,
    maximum_busy_wait_ms: u64,
}

impl CoordinatorStoreConfigV1 {
    /// Checks a provisioner-attested empty or interrupted-publication root.
    ///
    /// Open generates and durably reserves a fresh identity before first database creation, or
    /// resumes the identity already reserved by an interrupted initialization. If SQLite v1 was
    /// fully committed and `EXISTING` was published just before the provisioner lost the return
    /// value, this same attested recovery path may return that marker identity only after full
    /// marker-to-metadata verification. It never admits a database identity from contents alone.
    pub fn try_new_empty_attested(
        root: PathBuf,
        maximum_busy_wait_ms: u64,
    ) -> Result<Self, CoordinatorStoreConfigErrorV1> {
        validate_busy_bound(maximum_busy_wait_ms)?;
        let root = ProvisionedEmptyCoordinatorRootV1::try_from_attested(root)
            .map_err(CoordinatorStoreConfigErrorV1::from_internal)?;
        Ok(Self {
            root: CoordinatorRootConfigV1::Empty(root),
            maximum_busy_wait_ms,
        })
    }

    /// Checks a provisioner-attested initialized root and binds its expected identity.
    pub fn try_new_existing_attested(
        root: PathBuf,
        expected_root_identity: CoordinatorRootIdentityEvidenceV1,
        maximum_busy_wait_ms: u64,
    ) -> Result<Self, CoordinatorStoreConfigErrorV1> {
        validate_busy_bound(maximum_busy_wait_ms)?;
        let identity = expected_root_identity.into_internal();
        let root = ProvisionedExistingCoordinatorRootV1::try_from_attested(root, identity)
            .map_err(CoordinatorStoreConfigErrorV1::from_internal)?;
        Ok(Self {
            root: CoordinatorRootConfigV1::Existing(root),
            maximum_busy_wait_ms,
        })
    }

    pub(crate) fn empty_root(&self) -> Option<&ProvisionedEmptyCoordinatorRootV1> {
        match &self.root {
            CoordinatorRootConfigV1::Empty(root) => Some(root),
            CoordinatorRootConfigV1::Existing(_) => None,
        }
    }

    pub(crate) fn existing_root(&self) -> Option<&ProvisionedExistingCoordinatorRootV1> {
        match &self.root {
            CoordinatorRootConfigV1::Empty(_) => None,
            CoordinatorRootConfigV1::Existing(root) => Some(root),
        }
    }

    pub(crate) fn root_path(&self) -> &Path {
        match &self.root {
            CoordinatorRootConfigV1::Empty(root) => root.path(),
            CoordinatorRootConfigV1::Existing(root) => root.path(),
        }
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.root_path().join(COORDINATOR_DATABASE_FILENAME)
    }

    pub(crate) const fn maximum_busy_wait_ms(&self) -> u64 {
        self.maximum_busy_wait_ms
    }

    pub(crate) fn into_existing(
        self,
        initialized_identity: CoordinatorRootIdentityV1,
    ) -> Result<Self, InternalCoordinatorError> {
        match self.root {
            CoordinatorRootConfigV1::Existing(root) => {
                if root.expected_identity() != initialized_identity {
                    return Err(InternalCoordinatorError::RootIdentityMismatch);
                }
                Ok(Self {
                    root: CoordinatorRootConfigV1::Existing(root),
                    maximum_busy_wait_ms: self.maximum_busy_wait_ms,
                })
            }
            CoordinatorRootConfigV1::Empty(root) => {
                let existing = ProvisionedExistingCoordinatorRootV1::try_from_attested(
                    root.path().to_path_buf(),
                    initialized_identity,
                )?;
                Ok(Self {
                    root: CoordinatorRootConfigV1::Existing(existing),
                    maximum_busy_wait_ms: self.maximum_busy_wait_ms,
                })
            }
        }
    }
}

impl fmt::Debug for CoordinatorStoreConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorStoreConfigV1")
            .finish_non_exhaustive()
    }
}

fn validate_busy_bound(maximum_busy_wait_ms: u64) -> Result<(), CoordinatorStoreConfigErrorV1> {
    if !(1..=MAX_SAFE_U64).contains(&maximum_busy_wait_ms) {
        return Err(CoordinatorStoreConfigErrorV1::InvalidBusyBound);
    }
    Ok(())
}
