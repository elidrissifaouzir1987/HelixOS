//! Provisioner-bound configuration for the independent HLXA authority store.

#![allow(dead_code)] // Foundation consumed by the story-specific SQLite authority adapter.

use crate::root_safety::{
    AuthorityRootIdentityV1, AuthorityRootSafetyErrorV1, ProvisionedEmptyAuthorityRootV1,
    ProvisionedExistingAuthorityRootV1, AUTHORITY_DATABASE_FILENAME,
};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

const MAX_SQLITE_BUSY_WAIT_MS: u64 = i32::MAX as u64;

/// Opaque provisioner custody evidence for one dedicated authority-root identity.
///
/// The bytes are deliberately non-Serde and formatting is redacted.  A native path is
/// not identity evidence; the provisioner supplies these bytes on every reopen.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthorityRootIdentityEvidenceV1([u8; 32]);

impl AuthorityRootIdentityEvidenceV1 {
    pub const fn from_attested_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_attested_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) const fn into_internal(self) -> AuthorityRootIdentityV1 {
        AuthorityRootIdentityV1::from_bytes(self.0)
    }

    pub(crate) const fn from_internal(identity: AuthorityRootIdentityV1) -> Self {
        Self(*identity.as_bytes())
    }
}

impl fmt::Debug for AuthorityRootIdentityEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRootIdentityEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Closed, payload-free configuration rejection.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityStoreConfigErrorV1 {
    InvalidBusyBound,
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    UnknownRootMember,
}

impl AuthorityStoreConfigErrorV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::InvalidBusyBound => "AUTHORITY_INVALID_BUSY_BOUND",
            Self::RootInvalid => "AUTHORITY_ROOT_INVALID",
            Self::RootNotDedicated => "AUTHORITY_ROOT_NOT_DEDICATED",
            Self::RootRoleMismatch => "AUTHORITY_ROOT_ROLE_MISMATCH",
            Self::RootIdentityMismatch => "AUTHORITY_ROOT_IDENTITY_MISMATCH",
            Self::UnknownRootMember => "AUTHORITY_UNKNOWN_ROOT_MEMBER",
        }
    }

    pub const fn code(self) -> &'static str {
        self.code_v1()
    }

    const fn from_root(error: AuthorityRootSafetyErrorV1) -> Self {
        match error {
            AuthorityRootSafetyErrorV1::RootInvalid => Self::RootInvalid,
            AuthorityRootSafetyErrorV1::RootNotDedicated => Self::RootNotDedicated,
            AuthorityRootSafetyErrorV1::RootRoleMismatch => Self::RootRoleMismatch,
            AuthorityRootSafetyErrorV1::RootIdentityMismatch => Self::RootIdentityMismatch,
            AuthorityRootSafetyErrorV1::UnknownRootMember => Self::UnknownRootMember,
            AuthorityRootSafetyErrorV1::RootUnavailable => Self::RootInvalid,
        }
    }
}

impl fmt::Debug for AuthorityStoreConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityStoreConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl Error for AuthorityStoreConfigErrorV1 {}

#[derive(Clone)]
enum AuthorityRootConfigV1 {
    Empty(ProvisionedEmptyAuthorityRootV1),
    Existing(ProvisionedExistingAuthorityRootV1),
}

/// Checked configuration carrying one provisioner-attested dedicated-root role.
#[derive(Clone)]
pub struct AuthorityStoreConfigV1 {
    root: AuthorityRootConfigV1,
    maximum_busy_wait_ms: u64,
}

impl AuthorityStoreConfigV1 {
    /// Admits only an empty root or the same identity-bound interrupted initialization.
    pub fn try_new_empty_attested(
        root: PathBuf,
        new_root_identity: AuthorityRootIdentityEvidenceV1,
        maximum_busy_wait_ms: u64,
    ) -> Result<Self, AuthorityStoreConfigErrorV1> {
        validate_busy_bound(maximum_busy_wait_ms)?;
        let root = ProvisionedEmptyAuthorityRootV1::try_from_provisioned(
            root,
            new_root_identity.into_internal(),
        )
        .map_err(AuthorityStoreConfigErrorV1::from_root)?;
        Ok(Self {
            root: AuthorityRootConfigV1::Empty(root),
            maximum_busy_wait_ms,
        })
    }

    /// Admits only a published root bound to the exact provisioner-held identity.
    pub fn try_new_existing_attested(
        root: PathBuf,
        expected_root_identity: AuthorityRootIdentityEvidenceV1,
        maximum_busy_wait_ms: u64,
    ) -> Result<Self, AuthorityStoreConfigErrorV1> {
        validate_busy_bound(maximum_busy_wait_ms)?;
        let root = ProvisionedExistingAuthorityRootV1::try_from_provisioned(
            root,
            expected_root_identity.into_internal(),
        )
        .map_err(AuthorityStoreConfigErrorV1::from_root)?;
        Ok(Self {
            root: AuthorityRootConfigV1::Existing(root),
            maximum_busy_wait_ms,
        })
    }

    pub(crate) fn empty_root(&self) -> Option<&ProvisionedEmptyAuthorityRootV1> {
        match &self.root {
            AuthorityRootConfigV1::Empty(root) => Some(root),
            AuthorityRootConfigV1::Existing(_) => None,
        }
    }

    pub(crate) fn existing_root(&self) -> Option<&ProvisionedExistingAuthorityRootV1> {
        match &self.root {
            AuthorityRootConfigV1::Empty(_) => None,
            AuthorityRootConfigV1::Existing(root) => Some(root),
        }
    }

    pub(crate) fn root_path(&self) -> &Path {
        match &self.root {
            AuthorityRootConfigV1::Empty(root) => root.path(),
            AuthorityRootConfigV1::Existing(root) => root.path(),
        }
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.root_path().join(AUTHORITY_DATABASE_FILENAME)
    }

    pub(crate) const fn maximum_busy_wait_ms(&self) -> u64 {
        self.maximum_busy_wait_ms
    }

    pub(crate) fn into_existing(self) -> Result<Self, AuthorityRootSafetyErrorV1> {
        match self.root {
            AuthorityRootConfigV1::Existing(root) => Ok(Self {
                root: AuthorityRootConfigV1::Existing(root),
                maximum_busy_wait_ms: self.maximum_busy_wait_ms,
            }),
            AuthorityRootConfigV1::Empty(root) => {
                let existing = ProvisionedExistingAuthorityRootV1::try_from_provisioned(
                    root.path().to_path_buf(),
                    root.provisioned_identity(),
                )?;
                Ok(Self {
                    root: AuthorityRootConfigV1::Existing(existing),
                    maximum_busy_wait_ms: self.maximum_busy_wait_ms,
                })
            }
        }
    }
}

impl fmt::Debug for AuthorityStoreConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityStoreConfigV1")
            .finish_non_exhaustive()
    }
}

fn validate_busy_bound(value: u64) -> Result<(), AuthorityStoreConfigErrorV1> {
    if !(1..=MAX_SQLITE_BUSY_WAIT_MS).contains(&value) {
        return Err(AuthorityStoreConfigErrorV1::InvalidBusyBound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_safety::{
        ensure_initializing_marker, publish_existing_marker, reserve_database_file,
    };
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_CONFIG_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TemporaryRoot(PathBuf);

    impl TemporaryRoot {
        fn new() -> Self {
            loop {
                let nonce = NEXT_CONFIG_ROOT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "helix-task-authority-config-{}-{nonce}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary config root creates: {error}"),
                }
            }
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn evidence(value: u8) -> AuthorityRootIdentityEvidenceV1 {
        AuthorityRootIdentityEvidenceV1::from_attested_bytes([value; 32])
    }

    #[test]
    fn configuration_bounds_have_frozen_payload_free_codes() {
        let invalid = AuthorityStoreConfigV1::try_new_empty_attested(
            PathBuf::from("not-inspected"),
            evidence(1),
            0,
        )
        .unwrap_err();
        assert_eq!(invalid, AuthorityStoreConfigErrorV1::InvalidBusyBound);
        assert_eq!(format!("{invalid:?}"), "AUTHORITY_INVALID_BUSY_BOUND");
        assert_eq!(invalid.to_string(), "AUTHORITY_INVALID_BUSY_BOUND");
    }

    #[test]
    fn configuration_and_identity_debug_never_expose_native_or_attested_values() {
        let temporary = TemporaryRoot::new();
        let config =
            AuthorityStoreConfigV1::try_new_empty_attested(temporary.0.clone(), evidence(9), 25)
                .expect("empty authority configuration admits");
        let rendered = format!("{config:?} {:?}", evidence(9));
        assert!(!rendered.contains(temporary.0.to_string_lossy().as_ref()));
        assert!(!rendered.contains("09090909"));
    }

    #[test]
    fn existing_configuration_requires_exact_published_identity() {
        let temporary = TemporaryRoot::new();
        let config =
            AuthorityStoreConfigV1::try_new_empty_attested(temporary.0.clone(), evidence(4), 25)
                .expect("empty authority configuration admits");
        let root = config
            .empty_root()
            .expect("configuration retains empty role");
        ensure_initializing_marker(root).expect("marker initializes");
        reserve_database_file(root).expect("database reserves");
        publish_existing_marker(root).expect("root publishes last");

        AuthorityStoreConfigV1::try_new_existing_attested(temporary.0.clone(), evidence(4), 25)
            .expect("exact published identity reopens");
        assert_eq!(
            AuthorityStoreConfigV1::try_new_existing_attested(
                temporary.0.clone(),
                evidence(5),
                25,
            )
            .unwrap_err(),
            AuthorityStoreConfigErrorV1::RootIdentityMismatch
        );
    }
}
