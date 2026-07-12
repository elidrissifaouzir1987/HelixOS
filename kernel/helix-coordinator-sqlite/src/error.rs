//! Private closed coordinator error mapping.

#![allow(dead_code)]

use std::error::Error;
use std::fmt;

/// Closed failure returned by the injected boot-monotonic clock.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorClockUnavailableV1;

impl CoordinatorClockUnavailableV1 {
    pub const fn new() -> Self {
        Self
    }

    pub const fn code(self) -> &'static str {
        "CLOCK_UNAVAILABLE"
    }
}

impl Default for CoordinatorClockUnavailableV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CoordinatorClockUnavailableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for CoordinatorClockUnavailableV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for CoordinatorClockUnavailableV1 {}

/// Payload-free internal classification used before public outcome mapping.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum InternalCoordinatorError {
    ClockUnavailable,
    DeadlineReached,
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    RootBusy,
    RootUnavailable,
    UnknownRootMember,
    ApplicationIdMismatch,
    SchemaUnsupported,
    SchemaInvalid,
    DurabilityProfileUnavailable,
    IntegrityFailed,
    InvariantFailed,
    JsonContractInvalid,
    ProvenanceInvalid,
    RestorePending,
}

impl InternalCoordinatorError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ClockUnavailable => "CLOCK_UNAVAILABLE",
            Self::DeadlineReached => "DEADLINE_REACHED",
            Self::RootInvalid => "ROOT_INVALID",
            Self::RootNotDedicated => "ROOT_NOT_DEDICATED",
            Self::RootRoleMismatch => "ROOT_ROLE_MISMATCH",
            Self::RootIdentityMismatch => "ROOT_IDENTITY_MISMATCH",
            Self::RootBusy => "ROOT_BUSY",
            Self::RootUnavailable => "ROOT_UNAVAILABLE",
            Self::UnknownRootMember => "UNKNOWN_ROOT_MEMBER",
            Self::ApplicationIdMismatch => "APPLICATION_ID_MISMATCH",
            Self::SchemaUnsupported => "SCHEMA_UNSUPPORTED",
            Self::SchemaInvalid => "SCHEMA_INVALID",
            Self::DurabilityProfileUnavailable => "DURABILITY_PROFILE_UNAVAILABLE",
            Self::IntegrityFailed => "INTEGRITY_FAILED",
            Self::InvariantFailed => "INVARIANT_FAILED",
            Self::JsonContractInvalid => "JSON_CONTRACT_INVALID",
            Self::ProvenanceInvalid => "PROVENANCE_INVALID",
            Self::RestorePending => "RESTORE_PENDING",
        }
    }

    pub(crate) const fn requires_unhealthy_latch(self) -> bool {
        matches!(
            self,
            Self::ApplicationIdMismatch
                | Self::SchemaUnsupported
                | Self::SchemaInvalid
                | Self::IntegrityFailed
                | Self::InvariantFailed
                | Self::RootIdentityMismatch
        )
    }
}

impl fmt::Debug for InternalCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for InternalCoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for InternalCoordinatorError {}
