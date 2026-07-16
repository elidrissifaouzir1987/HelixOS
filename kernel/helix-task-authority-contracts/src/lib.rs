//! Closed canonical wire contracts for durable signed task authority.
//!
//! This setup surface exports no authority-bearing value. Reviewed v1 modules may
//! later expose only strict signed/authentic markers and closed payload-free errors;
//! protected bytes, identifiers, digests, key material and native paths remain redacted.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod canonical {}
mod crypto {}
mod digest {}
mod error {}
mod validation {}
mod human_request_grant {}
mod task_lease {}
mod approval_decision {}
