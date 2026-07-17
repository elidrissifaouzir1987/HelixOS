//! Non-wire current-authority projection boundaries.
//!
//! Positive projection providers are sealed to core-owned verified wrappers. The
//! durable SQLite crate will supply raw graph data to that wrapper; neither callers nor
//! an external backend can implement this surface or fabricate a `Current` value.

use crate::AuthorityDeadlineV1;
use helix_contracts::{AuthenticPlanEnvelopeV1, RequestSourceKindV1};
use helix_task_authority_contracts::Sha256Digest;
use std::fmt;

pub(crate) mod sealed {
    pub trait ProjectionSnapshotV1 {}
    pub trait ProjectionProviderV1 {}
}

/// Closed reasons why no positive current projection is available.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityProjectionRefusalV1 {
    Denied,
    Expired,
    Exhausted,
    Revoked,
    ChainNonCurrent,
    BootMismatch,
    InstanceMismatch,
    FencingMismatch,
    WeakEvidence,
    HistoricalOnly,
    DeadlineReached,
    Unavailable,
    Inconsistent,
    Unsupported,
}

impl AuthorityProjectionRefusalV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Denied => "AUTHORITY_PROJECTION_DENIED",
            Self::Expired => "AUTHORITY_PROJECTION_EXPIRED",
            Self::Exhausted => "AUTHORITY_PROJECTION_EXHAUSTED",
            Self::Revoked => "AUTHORITY_PROJECTION_REVOKED",
            Self::ChainNonCurrent => "AUTHORITY_PROJECTION_CHAIN_NON_CURRENT",
            Self::BootMismatch => "AUTHORITY_PROJECTION_BOOT_MISMATCH",
            Self::InstanceMismatch => "AUTHORITY_PROJECTION_INSTANCE_MISMATCH",
            Self::FencingMismatch => "AUTHORITY_PROJECTION_FENCING_MISMATCH",
            Self::WeakEvidence => "AUTHORITY_PROJECTION_WEAK_EVIDENCE",
            Self::HistoricalOnly => "AUTHORITY_PROJECTION_HISTORICAL_ONLY",
            Self::DeadlineReached => "AUTHORITY_PROJECTION_DEADLINE_REACHED",
            Self::Unavailable => "AUTHORITY_PROJECTION_UNAVAILABLE",
            Self::Inconsistent => "AUTHORITY_PROJECTION_INCONSISTENT",
            Self::Unsupported => "AUTHORITY_PROJECTION_UNSUPPORTED",
        }
    }
}

impl fmt::Debug for AuthorityProjectionRefusalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityProjectionRefusalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl std::error::Error for AuthorityProjectionRefusalV1 {}

/// A projection request derived only from an authentic PLAN-001 envelope.
///
/// No raw-parts constructor exists. The exact canonical signed-envelope digest is
/// computed internally and remains distinct from the PLAN-001 plan ID. Deadline
/// custody is passed separately and linearly into the provider/guard boundary.
pub struct AuthorityProjectionRequestV1<'plan> {
    authentic_plan: &'plan AuthenticPlanEnvelopeV1,
    plan_envelope_digest: Sha256Digest,
}

impl<'plan> AuthorityProjectionRequestV1<'plan> {
    pub fn try_from_authentic_plan_v1(
        authentic_plan: &'plan AuthenticPlanEnvelopeV1,
    ) -> Result<Self, AuthorityProjectionRefusalV1> {
        if authentic_plan.eligibility_claims().request_source_kind()
            != RequestSourceKindV1::HumanRequestGrant
        {
            return Err(AuthorityProjectionRefusalV1::Unsupported);
        }

        let canonical_envelope = authentic_plan
            .canonical_signed_envelope_bytes()
            .map_err(|_| AuthorityProjectionRefusalV1::Inconsistent)?;
        Ok(Self {
            authentic_plan,
            plan_envelope_digest: Sha256Digest::digest(&canonical_envelope),
        })
    }

    pub const fn authentic_plan_v1(&self) -> &'plan AuthenticPlanEnvelopeV1 {
        self.authentic_plan
    }

    pub const fn plan_envelope_digest_v1(&self) -> Sha256Digest {
        self.plan_envelope_digest
    }
}

impl fmt::Debug for AuthorityProjectionRequestV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityProjectionRequestV1(..)")
    }
}

/// Core-owned verified facts. T071 fills this private structure with the complete
/// grant/lease/ancestor/decision/revocation graph; T016 freezes its custody boundary.
pub(crate) struct VerifiedAuthorityProjectionV1 {
    _private: (),
}

impl VerifiedAuthorityProjectionV1 {
    pub(crate) const fn from_complete_verified_graph_v1() -> Self {
        Self { _private: () }
    }
}

/// Borrowed opaque positive projection tied to one live verified snapshot or guard.
///
/// The value has no public constructor, owns no detachable facts and is neither
/// clonable nor serializable. Its lifetime is a real borrow of core-owned verified
/// state, rather than a synthetic `'static` marker.
///
/// ```compile_fail
/// use helix_task_authority::CurrentAuthorityProjectionV1;
///
/// fn duplicate<'custody>(projection: CurrentAuthorityProjectionV1<'custody>) {
///     let _copy = projection.clone();
/// }
/// ```
///
/// ```compile_fail
/// use helix_task_authority::CurrentAuthorityProjectionV1;
///
/// fn fabricate<'custody>() -> CurrentAuthorityProjectionV1<'custody> {
///     CurrentAuthorityProjectionV1 {}
/// }
/// ```
///
/// ```compile_fail
/// use helix_task_authority::{CurrentAuthorityProjectionV1, CurrentLeaseProjectionV1};
///
/// fn escape<'custody>(
///     current: CurrentAuthorityProjectionV1<'custody>,
/// ) -> CurrentLeaseProjectionV1<'custody> {
///     current.lease_v1()
/// }
/// ```
///
/// ```compile_fail
/// use helix_task_authority::CurrentAuthorityProjectionV1;
///
/// fn cannot_serialize<'custody>(current: CurrentAuthorityProjectionV1<'custody>) {
///     let _wire = serde_json::to_vec(&current);
/// }
/// ```
pub struct CurrentAuthorityProjectionV1<'custody> {
    verified: &'custody VerifiedAuthorityProjectionV1,
}

impl<'custody> CurrentAuthorityProjectionV1<'custody> {
    pub(crate) const fn from_verified_custody_v1(
        verified: &'custody VerifiedAuthorityProjectionV1,
    ) -> Self {
        Self { verified }
    }

    pub const fn lease_v1(&self) -> CurrentLeaseProjectionV1<'_> {
        CurrentLeaseProjectionV1 {
            verified: self.verified,
        }
    }

    pub const fn authorization_v1(&self) -> CurrentAuthorizationProjectionV1<'_> {
        CurrentAuthorizationProjectionV1 {
            verified: self.verified,
        }
    }
}

impl fmt::Debug for CurrentAuthorityProjectionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrentAuthorityProjectionV1(..)")
    }
}

/// Borrowed closed lease subview of a positive current projection.
pub struct CurrentLeaseProjectionV1<'custody> {
    verified: &'custody VerifiedAuthorityProjectionV1,
}

impl fmt::Debug for CurrentLeaseProjectionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.verified;
        formatter.write_str("CurrentLeaseProjectionV1(..)")
    }
}

/// Borrowed closed authorization subview of a positive current projection.
pub struct CurrentAuthorizationProjectionV1<'custody> {
    verified: &'custody VerifiedAuthorityProjectionV1,
}

impl fmt::Debug for CurrentAuthorizationProjectionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self.verified;
        formatter.write_str("CurrentAuthorizationProjectionV1(..)")
    }
}

/// Closed result from one verified snapshot lookup.
pub enum AuthorityProjectionOutcomeV1<'snapshot> {
    Current(CurrentAuthorityProjectionV1<'snapshot>),
    Refused(AuthorityProjectionRefusalV1),
}

impl fmt::Debug for AuthorityProjectionOutcomeV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Current(_) => "AuthorityProjectionOutcomeV1::Current(..)",
            Self::Refused(_) => "AuthorityProjectionOutcomeV1::Refused(..)",
        })
    }
}

/// Closed result from opening a verified projection snapshot.
pub enum AuthorityProjectionOpenOutcomeV1<S> {
    Opened(S),
    Refused(AuthorityProjectionRefusalV1),
}

impl<S> fmt::Debug for AuthorityProjectionOpenOutcomeV1<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Opened(_) => "AuthorityProjectionOpenOutcomeV1::Opened(..)",
            Self::Refused(_) => "AuthorityProjectionOpenOutcomeV1::Refused(..)",
        })
    }
}

/// Core-owned verified snapshot capability. The private supertrait prevents direct
/// implementation by the SQLite or projection-adapter crates.
pub trait AuthorityProjectionSnapshotV1: sealed::ProjectionSnapshotV1 + Send {
    fn resolve_current_projection_v1<'snapshot>(
        &'snapshot mut self,
        request: &AuthorityProjectionRequestV1<'_>,
    ) -> AuthorityProjectionOutcomeV1<'snapshot>;
}

/// Core-owned configured projection provider. A future public raw-graph loader can be
/// implemented by SQLite, while this sealed wrapper alone performs complete T071
/// verification and constructs positive borrowed views.
///
/// ```compile_fail
/// use helix_task_authority::{
///     AuthorityProjectionOutcomeV1, AuthorityProjectionRefusalV1,
///     AuthorityProjectionRequestV1, AuthorityProjectionSnapshotV1,
/// };
///
/// struct ExternalSnapshot;
///
/// impl AuthorityProjectionSnapshotV1 for ExternalSnapshot {
///     fn resolve_current_projection_v1<'snapshot>(
///         &'snapshot mut self,
///         _request: &AuthorityProjectionRequestV1<'_>,
///     ) -> AuthorityProjectionOutcomeV1<'snapshot> {
///         AuthorityProjectionOutcomeV1::Refused(AuthorityProjectionRefusalV1::Unavailable)
///     }
/// }
/// ```
pub trait AuthorityProjectionProviderV1: sealed::ProjectionProviderV1 + Send + Sync {
    type Snapshot: AuthorityProjectionSnapshotV1;

    fn open_projection_snapshot_v1(
        &self,
        deadline: &AuthorityDeadlineV1,
    ) -> AuthorityProjectionOpenOutcomeV1<Self::Snapshot>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_projection_and_views_have_payload_free_debug() {
        let verified = VerifiedAuthorityProjectionV1::from_complete_verified_graph_v1();
        let current = CurrentAuthorityProjectionV1::from_verified_custody_v1(&verified);
        assert_eq!(format!("{current:?}"), "CurrentAuthorityProjectionV1(..)");
        assert_eq!(
            format!("{:?}", current.lease_v1()),
            "CurrentLeaseProjectionV1(..)"
        );
        assert_eq!(
            format!("{:?}", current.authorization_v1()),
            "CurrentAuthorizationProjectionV1(..)"
        );
    }

    #[test]
    fn every_refusal_has_a_stable_payload_free_code() {
        let refusals = [
            AuthorityProjectionRefusalV1::Denied,
            AuthorityProjectionRefusalV1::Expired,
            AuthorityProjectionRefusalV1::Exhausted,
            AuthorityProjectionRefusalV1::Revoked,
            AuthorityProjectionRefusalV1::ChainNonCurrent,
            AuthorityProjectionRefusalV1::BootMismatch,
            AuthorityProjectionRefusalV1::InstanceMismatch,
            AuthorityProjectionRefusalV1::FencingMismatch,
            AuthorityProjectionRefusalV1::WeakEvidence,
            AuthorityProjectionRefusalV1::HistoricalOnly,
            AuthorityProjectionRefusalV1::DeadlineReached,
            AuthorityProjectionRefusalV1::Unavailable,
            AuthorityProjectionRefusalV1::Inconsistent,
            AuthorityProjectionRefusalV1::Unsupported,
        ];
        for refusal in refusals {
            let code = refusal.code_v1();
            assert!(code.starts_with("AUTHORITY_PROJECTION_"));
            assert_eq!(format!("{refusal:?}"), code);
            assert_eq!(refusal.to_string(), code);
        }
    }
}
