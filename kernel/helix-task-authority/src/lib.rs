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
mod projection {}
mod guard {}
mod outcome;
mod store;
mod control {}

#[cfg(feature = "test-fault-injection")]
mod test_fault {}

pub use outcome::{
    AuthorityMutationOutcomeV1, AuthorityReadbackOutcomeV1, AuthorityRetainedOutcomeCodeV1,
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
