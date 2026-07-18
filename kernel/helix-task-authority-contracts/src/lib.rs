//! Closed canonical wire contracts for durable signed task authority.
//!
//! Signed values are opaque evidence and authentic values are linear verifier results.
//! Neither surface exposes protected bytes, signatures, key material, native paths or
//! a caller-constructible current-authority marker.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

// These reviewed helpers are wired now and become reachable from the contract-specific
// decoders in T030, T031 and T057. They remain private during this foundation step.
#[allow(dead_code)]
mod canonical;
#[allow(dead_code)]
mod crypto;
mod digest;
mod error;
#[allow(dead_code)]
mod validation;

mod human_request_grant;

mod task_lease;

mod approval_decision {
    use std::fmt;

    /// Opaque signed ApprovalDecision v1 evidence.
    pub struct SignedApprovalDecisionV1 {
        _private: (),
    }

    impl fmt::Debug for SignedApprovalDecisionV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SignedApprovalDecisionV1")
                .finish_non_exhaustive()
        }
    }

    /// Linear verifier result for authentic ApprovalDecision v1 evidence.
    pub struct AuthenticApprovalDecisionV1 {
        _private: (),
    }

    impl fmt::Debug for AuthenticApprovalDecisionV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("AuthenticApprovalDecisionV1")
                .finish_non_exhaustive()
        }
    }
}

pub use approval_decision::{AuthenticApprovalDecisionV1, SignedApprovalDecisionV1};
pub use crypto::{
    ApprovalDecisionKeyResolver, ApprovalDecisionSigner, ApprovalDecisionVerificationKeyV1,
    HumanRequestGrantKeyResolver, HumanRequestGrantSigner, HumanRequestGrantVerificationKeyV1,
    TaskLeaseKeyResolver, TaskLeaseSigner, TaskLeaseVerificationKeyV1, VerificationKeyStatusV1,
};
pub use digest::Sha256Digest;
pub use error::{ContractError, Result};
pub use human_request_grant::{
    decode_and_verify_human_request_grant_v1, decode_and_verify_retained_human_request_grant_v1,
    sign_human_request_grant_v1, AuthenticHumanRequestGrantV1, HumanRequestGrantClaimsV1,
    HumanRequestGrantInputV1, HumanRequestGrantProtectedV1, RetainedHumanRequestGrantClaimsV1,
    RetainedHumanRequestGrantEvidenceV1, SignedHumanRequestGrantV1,
};
pub use task_lease::{
    decode_and_verify_retained_task_lease_v1, decode_and_verify_task_lease_v1, sign_task_lease_v1,
    AuthenticTaskLeaseV1, RetainedTaskLeaseClaimsV1, RetainedTaskLeaseEvidenceV1,
    RootTaskLeaseBoundsV1, RootTaskLeaseInputV1, SignedTaskLeaseV1, TaskLeaseBudgetV1,
    TaskLeaseCatalogueBoundV1, TaskLeaseClaimsV1, TaskLeaseCounterLimitsV1, TaskLeaseProtectedV1,
    TaskLeaseTrustBoundV1,
};
pub use validation::{
    ApprovalDecisionValueV1, AuthenticationProfileV1, CurrencyCodeV1, DelegationDepthV1,
    DelegationModeV1, Generation, Identifier, LeaseSourceKindV1, MinimumAuthenticationProfileV1,
    Nonce128, ResourceRootV1, RiskLevelV1, SafeU64, TaskIntentionV1, MAX_SAFE_U64,
};
