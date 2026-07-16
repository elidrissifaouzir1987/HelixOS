//! Strict SQLite persistence for durable signed task authority.
//!
//! This crate alone owns the HLXA root. Default builds contain no fault selector,
//! and public diagnostics remain closed, payload-free and redacted.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod config {}
mod clock {}
mod connection {}
mod root_safety {}
mod schema {}
mod grant {}
mod lease {}
mod delegation {}
mod decision {}
mod revocation {}
mod projection {}
mod guard {}
mod readback {}
mod event {}
mod queue {}
mod maintenance {}
mod manifest {}

#[cfg(feature = "test-fault-injection")]
mod test_fault {}
