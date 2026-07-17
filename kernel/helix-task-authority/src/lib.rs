//! Portable orchestration for durable signed task authority.
//!
//! This crate owns no SQLite root, OS adapter, network transport, ambient authority
//! or host effect. The setup surface exposes no caller-constructible current authority.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod request {}
mod lease {}
mod delegation {}
mod decision {}
mod revocation {}
mod control;
mod guard;
mod outcome;
mod projection;
mod store;

#[cfg(feature = "test-fault-injection")]
mod test_fault {}

pub use control::{
    capture_authority_deadline_v1, AuthorityAdmissionClassV1, AuthorityAdmissionLaneV1,
    AuthorityCapacityProfileV1, AuthorityClockObservationV1, AuthorityClockProviderV1,
    AuthorityControlErrorV1, AuthorityDeadlineV1, AuthorityDeadlineValidationV1,
    AUTHORITY_ORDINARY_CAPACITY_V1, AUTHORITY_RESERVED_CONTROL_CAPACITY_V1,
};
pub use guard::{
    acquire_authority_lease_guard_v1, AuthorityDownstreamCommitPermitV1,
    AuthorityDownstreamCommitV1, AuthorityDownstreamPermitReleaseOutcomeV1,
    AuthorityGuardAcquisitionV1, AuthorityGuardBackendV1, AuthorityGuardCommitOutcomeV1,
    AuthorityGuardProviderV1, AuthorityGuardRefusalV1, AuthorityGuardReleaseOutcomeV1,
    AuthorityGuardValidationPointV1, AuthorityGuardValidationV1, AuthorityLeaseGuardV1,
    AuthorityProjectionGuardV1,
};
pub use outcome::{
    AuthorityMutationOutcomeV1, AuthorityReadbackOutcomeV1, AuthorityRetainedOutcomeCodeV1,
};
pub use projection::{
    AuthorityProjectionOpenOutcomeV1, AuthorityProjectionOutcomeV1, AuthorityProjectionProviderV1,
    AuthorityProjectionRefusalV1, AuthorityProjectionRequestV1, AuthorityProjectionSnapshotV1,
    CurrentAuthorityProjectionV1, CurrentAuthorizationProjectionV1, CurrentLeaseProjectionV1,
};
pub use store::{
    AuthorityAtomicMutationV1, AuthorityAtomicStoreV1, AuthorityAttemptBindingV1,
    AuthorityAttemptIdV1, AuthorityCounterKindV1, AuthorityIdempotencyPreimageV1,
    AuthorityInputGraphDigestV1, AuthorityKeyStatusReasonV1, AuthorityKeyStatusV1,
    AuthorityLifecyclePreimageV1, AuthorityLifecycleV1, AuthorityNamespaceDigestV1,
    AuthorityObservationBindingV1, AuthorityOperationKindV1, AuthorityOutcomeBindingDigestV1,
    AuthorityRetainedAttemptV1, AuthorityRetainedGraphV1, AuthorityRevocationReasonV1,
    AuthorityRevocationSubjectKindV1, AuthorityRevokePreimageV1, AuthoritySignerPurposeV1,
    AuthorityUncertainReadbackResolverV1, AuthorityUncertainReadbackV1, BackupPublishPreimageV1,
    BootstrapPreimageV1, ChildLeaseIssuePreimageV1, CounterConsumePreimageV1,
    DecisionRetainPreimageV1, KeyStatusChangePreimageV1, RestorePublishPreimageV1,
    RootLeaseIssuePreimageV1,
};
