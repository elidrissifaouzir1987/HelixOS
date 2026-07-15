//! Canonical wire contracts for durable one-shot dispatch.
//!
//! This crate is intentionally authority-minimal. It will expose reviewed signed
//! grant and receipt values, but never an execution token or host-effect handle.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod canonical;
mod crypto;
mod digest;
mod error;
mod grant;
mod receipt;
mod validation;

pub use crypto::{
    GrantKeyResolver, GrantSigner, GrantVerificationKeyV1, ReceiptKeyResolver, ReceiptSigner,
    ReceiptVerificationKeyV1, VerificationKeyStatusV1,
};
pub use digest::Sha256Digest;
pub use error::{ContractError, Result};
pub use grant::{
    decode_and_verify_execution_grant_v1, decode_and_verify_retained_execution_grant_v1,
    sign_execution_grant_v1, AuthenticExecutionGrantV1, ExecutionGrantClaimsV1,
    ExecutionGrantInputV1, ExecutionGrantProtectedV1, RecoveryModeV1,
    RetainedExecutionGrantClaimsV1, RetainedExecutionGrantEvidenceV1, SignedExecutionGrantV1,
};
pub use receipt::{
    decode_and_verify_execution_receipt_v1, sign_execution_receipt_v1, AuthenticExecutionReceiptV1,
    ExecutionReceiptClaimsV1, ExecutionReceiptDecisionV1, ExecutionReceiptInputV1,
    ExecutionReceiptProtectedV1, ExecutionReceiptRefusalCodeV1, ReceiptVerificationBindingsV1,
    SignedExecutionReceiptV1,
};
pub use validation::{Generation, Identifier, ResourceRefV1, SafeU64, MAX_SAFE_U64};
