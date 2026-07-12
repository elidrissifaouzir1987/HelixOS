#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod canonical;
mod crypto;
mod digest;
mod error;
mod plan;
mod resource;
mod validation;

pub use crypto::{
    decode_and_verify_plan, sign_plan_v1, sign_protected_plan_v1, Ed25519KeyResolver, Ed25519Signer,
};
pub use digest::Sha256Digest;
pub use error::{ContractError, Result};
pub use plan::{
    AtomicityV1, AuthenticPlanEnvelopeV1, BudgetInputV1, FilePreconditionInputV1,
    PlanEligibilityBudgetClaimsV1, PlanEligibilityClaimsV1, PlanInputV1, PlanPreparationClaimsV1,
    PlanProtectedV1, RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, RiskLevelV1,
    SignedPlanEnvelopeV1,
};
pub use resource::ResourceRefV1;
pub use validation::{Identifier, Nonce128, SafeU64, MAX_SAFE_U64};
