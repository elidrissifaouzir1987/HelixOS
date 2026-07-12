#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Portable durable-preparation protocol for HelixOS.
//!
//! This crate creates no dispatch or effect authority.

mod attempt;
mod budget;
mod commit_gate;
mod compare;
mod context;
#[cfg(feature = "controlled-benchmark")]
mod controlled_benchmark;
mod coordinator;
mod guard;
mod outcome;
mod recovery;
mod store;

#[cfg(feature = "test-fault-injection")]
mod test_fault;

pub use attempt::PreparationAttemptIdV1;
pub use budget::*;
pub use commit_gate::*;
pub use context::*;
#[cfg(feature = "controlled-benchmark")]
#[doc(hidden)]
pub use controlled_benchmark::*;
pub use coordinator::prepare_plan_v1;
#[cfg(feature = "test-fault-injection")]
#[doc(hidden)]
pub use coordinator::prepare_plan_with_fault_probe_v1;
pub use guard::*;
pub use outcome::*;
pub use recovery::*;
pub use store::*;

#[cfg(feature = "test-fault-injection")]
#[doc(hidden)]
pub use test_fault::{FaultProbeSelectionErrorV1, FaultProbeV1, ProcessBarrierV1};
