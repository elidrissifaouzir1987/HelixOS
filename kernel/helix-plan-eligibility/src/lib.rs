#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
//! Portable, point-in-time plan eligibility for the HelixOS sovereign core.
//!
//! The crate accepts only a signature-verified
//! [`helix_contracts::AuthenticPlanEnvelopeV1`], compares it with an explicit
//! core-owned [`EligibilityContextV1`], then invokes [`ReplayClaimantV1::claim_once`]
//! exactly once as the final operation. A matching new receipt produces an opaque
//! [`EligiblePlanV1`]; every rejection returns [`EligibilityFailureV1`] with the
//! authentic plan still owned by the caller.
//!
//! `EligiblePlanV1` is a necessary point-in-time prerequisite only. It is not approval,
//! durable prepare authority, an `ExecutionGrant`, or an adapter input, and this crate
//! performs no filesystem, network, native-handle, clock, or ambient-state access.
//! The leaf may therefore be removed before coordinator adoption without a database or
//! serialized-authority migration; the complete removal drill is maintained in the
//! feature quickstart.
// Returning the owned authentic plan avoids a fallible heap allocation after replay.
#![allow(clippy::result_large_err)]

mod context;
mod denial;
mod evaluator;
mod marker;
mod replay;

pub use context::*;
pub use denial::*;
pub use evaluator::evaluate_and_claim_plan_v1;
pub use marker::*;
pub use replay::*;
