//! Provisioner-bound configuration for the independent adapter inbox.

use crate::root_safety::{
    AdapterRootIdentityV1, AdapterRootSafetyErrorV1, ProvisionedEmptyAdapterRootV1,
    ProvisionedExistingAdapterRootV1, ADAPTER_DATABASE_FILENAME,
};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

const MAX_SQLITE_BUSY_TIMEOUT_MS: u64 = i32::MAX as u64;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Opaque provisioner custody evidence for one dedicated adapter-root identity.
///
/// The bytes are deliberately non-Serde and redacted under formatting. A path is never
/// accepted as identity evidence: the provisioner must retain and present these bytes on
/// every ordinary reopen.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterInboxRootIdentityEvidenceV1([u8; 32]);

impl AdapterInboxRootIdentityEvidenceV1 {
    pub const fn from_attested_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_attested_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) const fn into_internal(self) -> AdapterRootIdentityV1 {
        AdapterRootIdentityV1::from_bytes(self.0)
    }

    pub(crate) const fn from_internal(identity: AdapterRootIdentityV1) -> Self {
        Self(*identity.as_bytes())
    }
}

impl fmt::Debug for AdapterInboxRootIdentityEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInboxRootIdentityEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Trusted, bounded values inserted with the singleton row during empty-root publication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterInboxInitializationV1 {
    supervisor_epoch: u64,
    epoch_observer_generation: u64,
    receipt_signer_profile_digest: [u8; 32],
}

impl AdapterInboxInitializationV1 {
    pub fn try_new(
        supervisor_epoch: u64,
        epoch_observer_generation: u64,
        receipt_signer_profile_digest: [u8; 32],
    ) -> Result<Self, AdapterInboxStoreConfigErrorV1> {
        if supervisor_epoch > MAX_SAFE_INTEGER
            || !(1..=MAX_SAFE_INTEGER).contains(&epoch_observer_generation)
        {
            return Err(AdapterInboxStoreConfigErrorV1::InvalidInitialObservation);
        }
        Ok(Self {
            supervisor_epoch,
            epoch_observer_generation,
            receipt_signer_profile_digest,
        })
    }

    pub(crate) const fn supervisor_epoch(self) -> u64 {
        self.supervisor_epoch
    }

    pub(crate) const fn epoch_observer_generation(self) -> u64 {
        self.epoch_observer_generation
    }

    pub(crate) const fn receipt_signer_profile_digest(self) -> [u8; 32] {
        self.receipt_signer_profile_digest
    }
}

impl fmt::Debug for AdapterInboxInitializationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInboxInitializationV1")
            .finish_non_exhaustive()
    }
}

/// Closed, payload-free configuration rejection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterInboxStoreConfigErrorV1 {
    InvalidBusyBound,
    InvalidInitialObservation,
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    UnknownRootMember,
}

impl AdapterInboxStoreConfigErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidBusyBound => "INVALID_BUSY_BOUND",
            Self::InvalidInitialObservation => "INVALID_INITIAL_OBSERVATION",
            Self::RootInvalid => "ROOT_INVALID",
            Self::RootNotDedicated => "ROOT_NOT_DEDICATED",
            Self::RootRoleMismatch => "ROOT_ROLE_MISMATCH",
            Self::RootIdentityMismatch => "ROOT_IDENTITY_MISMATCH",
            Self::UnknownRootMember => "UNKNOWN_ROOT_MEMBER",
        }
    }

    const fn from_root(error: AdapterRootSafetyErrorV1) -> Self {
        match error {
            AdapterRootSafetyErrorV1::RootInvalid => Self::RootInvalid,
            AdapterRootSafetyErrorV1::RootNotDedicated => Self::RootNotDedicated,
            AdapterRootSafetyErrorV1::RootRoleMismatch => Self::RootRoleMismatch,
            AdapterRootSafetyErrorV1::RootIdentityMismatch => Self::RootIdentityMismatch,
            AdapterRootSafetyErrorV1::UnknownRootMember => Self::UnknownRootMember,
            AdapterRootSafetyErrorV1::RootUnavailable => Self::RootInvalid,
        }
    }
}

impl fmt::Debug for AdapterInboxStoreConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AdapterInboxStoreConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterInboxStoreConfigErrorV1 {}

#[derive(Clone)]
enum AdapterRootConfigV1 {
    Empty(ProvisionedEmptyAdapterRootV1),
    Existing(ProvisionedExistingAdapterRootV1),
}

/// Checked configuration carrying a provisioner-attested dedicated-root role.
#[derive(Clone)]
pub struct AdapterInboxStoreConfigV1 {
    root: AdapterRootConfigV1,
    maximum_busy_wait_ms: u64,
}

impl AdapterInboxStoreConfigV1 {
    /// Admits only a dedicated empty root or an interrupted initialization bound to the
    /// same provisioner-supplied fresh identity.
    pub fn try_new_empty_attested(
        root: PathBuf,
        new_root_identity: AdapterInboxRootIdentityEvidenceV1,
        maximum_busy_wait_ms: u64,
    ) -> Result<Self, AdapterInboxStoreConfigErrorV1> {
        validate_busy_bound(maximum_busy_wait_ms)?;
        let root = ProvisionedEmptyAdapterRootV1::try_from_provisioned(
            root,
            new_root_identity.into_internal(),
        )
        .map_err(AdapterInboxStoreConfigErrorV1::from_root)?;
        Ok(Self {
            root: AdapterRootConfigV1::Empty(root),
            maximum_busy_wait_ms,
        })
    }

    /// Admits only an already-published root whose marker is bound to the exact expected
    /// provisioner identity.
    pub fn try_new_existing_attested(
        root: PathBuf,
        expected_root_identity: AdapterInboxRootIdentityEvidenceV1,
        maximum_busy_wait_ms: u64,
    ) -> Result<Self, AdapterInboxStoreConfigErrorV1> {
        validate_busy_bound(maximum_busy_wait_ms)?;
        let root = ProvisionedExistingAdapterRootV1::try_from_provisioned(
            root,
            expected_root_identity.into_internal(),
        )
        .map_err(AdapterInboxStoreConfigErrorV1::from_root)?;
        Ok(Self {
            root: AdapterRootConfigV1::Existing(root),
            maximum_busy_wait_ms,
        })
    }

    pub(crate) fn empty_root(&self) -> Option<&ProvisionedEmptyAdapterRootV1> {
        match &self.root {
            AdapterRootConfigV1::Empty(root) => Some(root),
            AdapterRootConfigV1::Existing(_) => None,
        }
    }

    pub(crate) fn existing_root(&self) -> Option<&ProvisionedExistingAdapterRootV1> {
        match &self.root {
            AdapterRootConfigV1::Empty(_) => None,
            AdapterRootConfigV1::Existing(root) => Some(root),
        }
    }

    pub(crate) fn root_path(&self) -> &Path {
        match &self.root {
            AdapterRootConfigV1::Empty(root) => root.path(),
            AdapterRootConfigV1::Existing(root) => root.path(),
        }
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.root_path().join(ADAPTER_DATABASE_FILENAME)
    }

    pub(crate) const fn maximum_busy_wait_ms(&self) -> u64 {
        self.maximum_busy_wait_ms
    }

    pub(crate) fn into_existing(self) -> Result<Self, AdapterRootSafetyErrorV1> {
        match self.root {
            AdapterRootConfigV1::Existing(root) => Ok(Self {
                root: AdapterRootConfigV1::Existing(root),
                maximum_busy_wait_ms: self.maximum_busy_wait_ms,
            }),
            AdapterRootConfigV1::Empty(root) => {
                let existing = ProvisionedExistingAdapterRootV1::try_from_provisioned(
                    root.path().to_path_buf(),
                    root.provisioned_identity(),
                )?;
                Ok(Self {
                    root: AdapterRootConfigV1::Existing(existing),
                    maximum_busy_wait_ms: self.maximum_busy_wait_ms,
                })
            }
        }
    }
}

impl fmt::Debug for AdapterInboxStoreConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInboxStoreConfigV1")
            .finish_non_exhaustive()
    }
}

fn validate_busy_bound(value: u64) -> Result<(), AdapterInboxStoreConfigErrorV1> {
    if !(1..=MAX_SQLITE_BUSY_TIMEOUT_MS).contains(&value) {
        return Err(AdapterInboxStoreConfigErrorV1::InvalidBusyBound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_errors_are_payload_free() {
        assert_eq!(
            format!("{:?}", AdapterInboxStoreConfigErrorV1::RootInvalid),
            "ROOT_INVALID"
        );
    }

    #[test]
    fn observation_bounds_are_safe_integer_bounded() {
        assert!(AdapterInboxInitializationV1::try_new(0, 1, [7; 32]).is_ok());
        assert_eq!(
            AdapterInboxInitializationV1::try_new(0, 0, [7; 32]).unwrap_err(),
            AdapterInboxStoreConfigErrorV1::InvalidInitialObservation
        );
    }
}
