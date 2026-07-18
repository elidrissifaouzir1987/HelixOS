//! Strict SQLite persistence for durable signed task authority.
//!
//! This crate alone owns the HLXA root. Default builds contain no fault selector,
//! and public diagnostics remain closed, payload-free and redacted.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod clock;
mod config;
mod connection;
mod grant;
mod lease;
mod root_safety;
mod schema;
mod delegation {}
mod decision {}
mod revocation;
mod projection {}
mod guard {}
mod event;
mod queue;
mod readback;
mod maintenance {}
mod manifest {}

#[cfg(feature = "test-fault-injection")]
mod test_fault;

pub use clock::{
    AuthorityTrustedClockOutcomeV1, AuthorityTrustedClockSampleV1, AuthorityTrustedClockSourceV1,
    InjectedAuthorityClockProviderV1,
};
pub use config::{
    AuthorityRootIdentityEvidenceV1, AuthorityStoreConfigErrorV1, AuthorityStoreConfigV1,
};
pub use connection::AuthorityStoreOpenErrorV1;
pub use lease::{RetainedRootLeaseV1, SqliteRootLeaseStoreV1};
pub use schema::{
    embedded_task_authority_store_schema_v1_sha256, TASK_AUTHORITY_STORE_APPLICATION_ID_V1,
    TASK_AUTHORITY_STORE_FORMAT_VERSION_V1, TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256,
    TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX, TASK_AUTHORITY_STORE_SCHEMA_V1_SQL,
    TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1,
};
