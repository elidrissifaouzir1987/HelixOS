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

mod human_request_grant {
    use std::fmt;

    /// Opaque signed HumanRequestGrant v1 evidence.
    pub struct SignedHumanRequestGrantV1 {
        _private: (),
    }

    impl fmt::Debug for SignedHumanRequestGrantV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SignedHumanRequestGrantV1")
                .finish_non_exhaustive()
        }
    }

    /// Linear verifier result for authentic HumanRequestGrant v1 evidence.
    pub struct AuthenticHumanRequestGrantV1 {
        _private: (),
    }

    impl fmt::Debug for AuthenticHumanRequestGrantV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("AuthenticHumanRequestGrantV1")
                .finish_non_exhaustive()
        }
    }
}

mod task_lease {
    use std::fmt;

    /// Opaque signed TaskLease v1 evidence.
    pub struct SignedTaskLeaseV1 {
        _private: (),
    }

    impl fmt::Debug for SignedTaskLeaseV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SignedTaskLeaseV1")
                .finish_non_exhaustive()
        }
    }

    /// Linear verifier result for authentic TaskLease v1 evidence.
    pub struct AuthenticTaskLeaseV1 {
        _private: (),
    }

    impl fmt::Debug for AuthenticTaskLeaseV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("AuthenticTaskLeaseV1")
                .finish_non_exhaustive()
        }
    }
}

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
pub use human_request_grant::{AuthenticHumanRequestGrantV1, SignedHumanRequestGrantV1};
pub use task_lease::{AuthenticTaskLeaseV1, SignedTaskLeaseV1};
pub use validation::{
    ApprovalDecisionValueV1, AuthenticationProfileV1, CurrencyCodeV1, DelegationDepthV1,
    DelegationModeV1, Generation, Identifier, LeaseSourceKindV1, MinimumAuthenticationProfileV1,
    Nonce128, ResourceRootV1, RiskLevelV1, SafeU64, TaskIntentionV1, MAX_SAFE_U64,
};
