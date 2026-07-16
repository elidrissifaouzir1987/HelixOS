//! Leaf adapters from verified current authority into existing plan seams.
//!
//! This crate adapts only into PLAN-002, PLAN-004 and PLAN-005. It owns no SQLite,
//! coordinator, inbox or legacy-runtime dependency and exposes no positive constructor.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod eligibility {}
mod preparation {}
mod dispatch {}
mod guards {}
