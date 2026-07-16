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
mod store {}
mod outcome {}
mod control {}

#[cfg(feature = "test-fault-injection")]
mod test_fault {}
