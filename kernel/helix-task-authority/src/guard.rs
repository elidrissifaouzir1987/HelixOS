//! Unified non-cloneable authority guard custody.
//!
//! One physical backend guard is acquired at the logical Lease slot, validates
//! Authorization inside the same snapshot, and remains alive through final current
//! verification and downstream commit classification. The exact request and linear
//! deadline are captured once by the guard and cannot be substituted between phases.

use crate::{
    projection::VerifiedAuthorityProjectionV1, AuthorityDeadlineV1, AuthorityProjectionRequestV1,
    CurrentAuthorityProjectionV1,
};
use std::fmt;

pub(crate) mod sealed {
    pub trait GuardBackendV1 {}
    pub trait GuardProviderV1 {}
}

/// Logical validation points traversed by one physical HLXA writer guard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityGuardValidationPointV1 {
    Lease,
    Authorization,
    FinalCommit,
}

/// Closed result from the core-owned verified backend at one logical slot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityGuardValidationV1 {
    Current,
    Denied,
    Expired,
    Exhausted,
    Revoked,
    ChainNonCurrent,
    DeadlineReached,
    Unavailable,
    Inconsistent,
    Unsupported,
    OrderViolated,
}

impl AuthorityGuardValidationV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Current => "AUTHORITY_GUARD_CURRENT",
            Self::Denied => "AUTHORITY_GUARD_DENIED",
            Self::Expired => "AUTHORITY_GUARD_EXPIRED",
            Self::Exhausted => "AUTHORITY_GUARD_EXHAUSTED",
            Self::Revoked => "AUTHORITY_GUARD_REVOKED",
            Self::ChainNonCurrent => "AUTHORITY_GUARD_CHAIN_NON_CURRENT",
            Self::DeadlineReached => "AUTHORITY_GUARD_DEADLINE_REACHED",
            Self::Unavailable => "AUTHORITY_GUARD_UNAVAILABLE",
            Self::Inconsistent => "AUTHORITY_GUARD_INCONSISTENT",
            Self::Unsupported => "AUTHORITY_GUARD_UNSUPPORTED",
            Self::OrderViolated => "AUTHORITY_GUARD_ORDER_VIOLATED",
        }
    }
}

impl fmt::Debug for AuthorityGuardValidationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

/// Closed public refusal from guard acquisition or validation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityGuardRefusalV1 {
    Denied,
    Expired,
    Exhausted,
    Revoked,
    ChainNonCurrent,
    DeadlineReached,
    Unavailable,
    Inconsistent,
    Unsupported,
    OrderViolated,
}

impl AuthorityGuardRefusalV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Denied => "AUTHORITY_GUARD_DENIED",
            Self::Expired => "AUTHORITY_GUARD_EXPIRED",
            Self::Exhausted => "AUTHORITY_GUARD_EXHAUSTED",
            Self::Revoked => "AUTHORITY_GUARD_REVOKED",
            Self::ChainNonCurrent => "AUTHORITY_GUARD_CHAIN_NON_CURRENT",
            Self::DeadlineReached => "AUTHORITY_GUARD_DEADLINE_REACHED",
            Self::Unavailable => "AUTHORITY_GUARD_UNAVAILABLE",
            Self::Inconsistent => "AUTHORITY_GUARD_INCONSISTENT",
            Self::Unsupported => "AUTHORITY_GUARD_UNSUPPORTED",
            Self::OrderViolated => "AUTHORITY_GUARD_ORDER_VIOLATED",
        }
    }
}

impl fmt::Debug for AuthorityGuardRefusalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityGuardRefusalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl std::error::Error for AuthorityGuardRefusalV1 {}

impl From<AuthorityGuardValidationV1> for AuthorityGuardRefusalV1 {
    fn from(value: AuthorityGuardValidationV1) -> Self {
        match value {
            AuthorityGuardValidationV1::Current => Self::Inconsistent,
            AuthorityGuardValidationV1::Denied => Self::Denied,
            AuthorityGuardValidationV1::Expired => Self::Expired,
            AuthorityGuardValidationV1::Exhausted => Self::Exhausted,
            AuthorityGuardValidationV1::Revoked => Self::Revoked,
            AuthorityGuardValidationV1::ChainNonCurrent => Self::ChainNonCurrent,
            AuthorityGuardValidationV1::DeadlineReached => Self::DeadlineReached,
            AuthorityGuardValidationV1::Unavailable => Self::Unavailable,
            AuthorityGuardValidationV1::Inconsistent => Self::Inconsistent,
            AuthorityGuardValidationV1::Unsupported => Self::Unsupported,
            AuthorityGuardValidationV1::OrderViolated => Self::OrderViolated,
        }
    }
}

/// Closed acquisition outcome. Acquired payloads are always redacted by `Debug`.
pub enum AuthorityGuardAcquisitionV1<G> {
    Acquired(G),
    Refused(AuthorityGuardRefusalV1),
}

impl<G> fmt::Debug for AuthorityGuardAcquisitionV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquired(_) => "AuthorityGuardAcquisitionV1::Acquired(..)",
            Self::Refused(_) => "AuthorityGuardAcquisitionV1::Refused(..)",
        })
    }
}

/// Result of explicitly releasing the physical HLXA custody.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityGuardReleaseOutcomeV1 {
    Released,
    Unavailable,
    Inconsistent,
}

impl fmt::Debug for AuthorityGuardReleaseOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Released => "AUTHORITY_GUARD_RELEASED",
            Self::Unavailable => "AUTHORITY_GUARD_RELEASE_UNAVAILABLE",
            Self::Inconsistent => "AUTHORITY_GUARD_RELEASE_INCONSISTENT",
        })
    }
}

/// Core-owned verified backend over one physical HLXA writer transaction.
///
/// The private supertrait prevents external crates from returning the public `Current`
/// enum and thereby fabricating positive authority. T071 will provide the core wrapper
/// around a raw SQLite graph loader. No implementation may call an earlier provider or
/// acquire an earlier guard while this backend is live.
///
/// ```compile_fail
/// use helix_task_authority::{
///     AuthorityDeadlineV1, AuthorityGuardBackendV1, AuthorityGuardReleaseOutcomeV1,
///     AuthorityGuardValidationPointV1, AuthorityGuardValidationV1,
///     AuthorityProjectionRequestV1,
/// };
///
/// struct ExternalFake;
///
/// impl AuthorityGuardBackendV1 for ExternalFake {
///     fn validate_v1(
///         &mut self,
///         _point: AuthorityGuardValidationPointV1,
///         _request: &AuthorityProjectionRequestV1<'_>,
///         _deadline: &AuthorityDeadlineV1,
///     ) -> AuthorityGuardValidationV1 {
///         AuthorityGuardValidationV1::Current
///     }
///
///     fn release_after_classification_v1(self) -> AuthorityGuardReleaseOutcomeV1 {
///         AuthorityGuardReleaseOutcomeV1::Released
///     }
///
///     fn rollback_and_release_v1(self) -> AuthorityGuardReleaseOutcomeV1 {
///         AuthorityGuardReleaseOutcomeV1::Released
///     }
/// }
/// ```
pub trait AuthorityGuardBackendV1: sealed::GuardBackendV1 + Send {
    fn validate_v1(
        &mut self,
        point: AuthorityGuardValidationPointV1,
        request: &AuthorityProjectionRequestV1<'_>,
        deadline: &AuthorityDeadlineV1,
    ) -> AuthorityGuardValidationV1;

    fn release_after_classification_v1(self) -> AuthorityGuardReleaseOutcomeV1;

    fn rollback_and_release_v1(self) -> AuthorityGuardReleaseOutcomeV1;
}

/// Core-owned configured source of one deadline-bounded HLXA writer guard.
pub trait AuthorityGuardProviderV1: sealed::GuardProviderV1 + Send + Sync {
    type Backend: AuthorityGuardBackendV1;

    fn acquire_backend_v1(
        &self,
        request: &AuthorityProjectionRequestV1<'_>,
        deadline: &AuthorityDeadlineV1,
    ) -> AuthorityGuardAcquisitionV1<Self::Backend>;
}

/// First typestate: the one physical guard is live and Lease has validated.
///
/// The exact request is borrowed and the non-cloneable deadline is owned. Neither can
/// be replaced at Authorization or FinalCommit.
///
/// ```compile_fail
/// use helix_task_authority::{AuthorityGuardBackendV1, AuthorityLeaseGuardV1};
///
/// fn duplicate<B: AuthorityGuardBackendV1>(guard: AuthorityLeaseGuardV1<'_, '_, B>) {
///     let _copy = guard.clone();
/// }
/// ```
pub struct AuthorityLeaseGuardV1<'request, 'plan, B: AuthorityGuardBackendV1> {
    backend: Option<B>,
    request: &'request AuthorityProjectionRequestV1<'plan>,
    deadline: Option<AuthorityDeadlineV1>,
}

impl<'request, 'plan, B: AuthorityGuardBackendV1> AuthorityLeaseGuardV1<'request, 'plan, B> {
    /// Consumes the Lease typestate and validates Authorization using the same request,
    /// absolute deadline, physical transaction and snapshot.
    pub fn validate_authorization_v1(
        mut self,
    ) -> AuthorityGuardAcquisitionV1<AuthorityProjectionGuardV1<'request, 'plan, B>> {
        let validation = self
            .backend
            .as_mut()
            .expect("authority lease guard backend is present")
            .validate_v1(
                AuthorityGuardValidationPointV1::Authorization,
                self.request,
                self.deadline
                    .as_ref()
                    .expect("authority lease guard deadline is present"),
            );
        match validation {
            AuthorityGuardValidationV1::Current => {
                let backend = self
                    .backend
                    .take()
                    .expect("authority lease guard backend is present");
                let deadline = self
                    .deadline
                    .take()
                    .expect("authority lease guard deadline is present");
                AuthorityGuardAcquisitionV1::Acquired(AuthorityProjectionGuardV1 {
                    backend: Some(backend),
                    request: self.request,
                    deadline: Some(deadline),
                    verified: VerifiedAuthorityProjectionV1::from_complete_verified_graph_v1(),
                })
            }
            refusal => {
                let release = self.rollback_and_release_v1();
                AuthorityGuardAcquisitionV1::Refused(release_refusal_v1(refusal.into(), release))
            }
        }
    }

    fn rollback_and_release_v1(&mut self) -> AuthorityGuardReleaseOutcomeV1 {
        match self.backend.take() {
            Some(backend) => backend.rollback_and_release_v1(),
            None => AuthorityGuardReleaseOutcomeV1::Inconsistent,
        }
    }
}

impl<B: AuthorityGuardBackendV1> fmt::Debug for AuthorityLeaseGuardV1<'_, '_, B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityLeaseGuardV1(..)")
    }
}

impl<B: AuthorityGuardBackendV1> Drop for AuthorityLeaseGuardV1<'_, '_, B> {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() {
            let _ = backend.rollback_and_release_v1();
        }
    }
}

/// Final typestate: Lease and Authorization are current in the same held snapshot.
///
/// ```compile_fail
/// use helix_task_authority::{AuthorityGuardBackendV1, AuthorityProjectionGuardV1};
///
/// fn duplicate<B: AuthorityGuardBackendV1>(guard: AuthorityProjectionGuardV1<'_, '_, B>) {
///     let _copy = guard.clone();
/// }
/// ```
pub struct AuthorityProjectionGuardV1<'request, 'plan, B: AuthorityGuardBackendV1> {
    backend: Option<B>,
    request: &'request AuthorityProjectionRequestV1<'plan>,
    deadline: Option<AuthorityDeadlineV1>,
    verified: VerifiedAuthorityProjectionV1,
}

impl<B: AuthorityGuardBackendV1> AuthorityProjectionGuardV1<'_, '_, B> {
    /// Borrows a positive view from the live guard. The view cannot outlive or be moved
    /// out of the guard because it contains a real borrow of `verified`.
    pub const fn current_projection_v1(&self) -> CurrentAuthorityProjectionV1<'_> {
        CurrentAuthorityProjectionV1::from_verified_custody_v1(&self.verified)
    }

    /// Revalidates the same request in the same snapshot, invokes one pre-acquired
    /// downstream permit, then releases HLXA only after commit classification and any
    /// uncertainty-custody transfer. The permit must perform the existing trusted final
    /// clock capture, enforce the supplied absolute deadline, release all later guards
    /// in reverse order, and return only then.
    pub fn commit_with_custody_v1<C, U, P>(
        mut self,
        permit: P,
    ) -> AuthorityGuardCommitOutcomeV1<C, U>
    where
        P: AuthorityDownstreamCommitPermitV1<C, U>,
    {
        let validation = self
            .backend
            .as_mut()
            .expect("authority projection guard backend is present")
            .validate_v1(
                AuthorityGuardValidationPointV1::FinalCommit,
                self.request,
                self.deadline
                    .as_ref()
                    .expect("authority projection guard deadline is present"),
            );
        if validation != AuthorityGuardValidationV1::Current {
            let permit_release = permit.abandon_v1();
            let release = self.rollback_and_release_v1();
            let refusal = release_refusal_v1(validation.into(), release);
            return AuthorityGuardCommitOutcomeV1::Refused(permit_release_refusal_v1(
                refusal,
                permit_release,
            ));
        }

        let classified = permit.commit_once_v1(
            CurrentAuthorityProjectionV1::from_verified_custody_v1(&self.verified),
            self.deadline
                .as_ref()
                .expect("authority projection guard deadline is present"),
        );
        let backend = self
            .backend
            .take()
            .expect("authority projection guard backend is present");
        match backend.release_after_classification_v1() {
            AuthorityGuardReleaseOutcomeV1::Released => classified.into(),
            failure => AuthorityGuardCommitOutcomeV1::ReleaseUncertain(classified, failure),
        }
    }

    fn rollback_and_release_v1(&mut self) -> AuthorityGuardReleaseOutcomeV1 {
        match self.backend.take() {
            Some(backend) => backend.rollback_and_release_v1(),
            None => AuthorityGuardReleaseOutcomeV1::Inconsistent,
        }
    }
}

impl<B: AuthorityGuardBackendV1> fmt::Debug for AuthorityProjectionGuardV1<'_, '_, B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityProjectionGuardV1(..)")
    }
}

impl<B: AuthorityGuardBackendV1> Drop for AuthorityProjectionGuardV1<'_, '_, B> {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() {
            let _ = backend.rollback_and_release_v1();
        }
    }
}

/// One pre-acquired, one-shot downstream commit capability.
///
/// Implementations are the reviewed PLAN-004/005 adapter permits. They already own all
/// later ordered guards, must not acquire any earlier provider/guard, must finish before
/// the immutable deadline and must transfer uncertainty readback custody before return.
pub trait AuthorityDownstreamCommitPermitV1<C, U>: Send {
    fn commit_once_v1(
        self,
        projection: CurrentAuthorityProjectionV1<'_>,
        deadline: &AuthorityDeadlineV1,
    ) -> AuthorityDownstreamCommitV1<C, U>;

    /// Explicitly releases all later guards in reverse order when final authority
    /// validation refuses before the downstream commit may run.
    fn abandon_v1(self) -> AuthorityDownstreamPermitReleaseOutcomeV1;
}

/// Closed result from explicitly abandoning a pre-acquired downstream permit.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityDownstreamPermitReleaseOutcomeV1 {
    Released,
    Unavailable,
    Inconsistent,
}

impl fmt::Debug for AuthorityDownstreamPermitReleaseOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Released => "AUTHORITY_DOWNSTREAM_PERMIT_RELEASED",
            Self::Unavailable => "AUTHORITY_DOWNSTREAM_PERMIT_RELEASE_UNAVAILABLE",
            Self::Inconsistent => "AUTHORITY_DOWNSTREAM_PERMIT_RELEASE_INCONSISTENT",
        })
    }
}

/// Existing downstream commit classification formed while authority custody is live.
pub enum AuthorityDownstreamCommitV1<C, U> {
    Committed(C),
    PriorExact(C),
    ConfirmedRollback,
    UncertainReadbackCustodyTransferred(U),
    Conflict,
    AmbiguousReconciliationRequired,
    DeadlineReached,
    Unavailable,
}

impl<C, U> fmt::Debug for AuthorityDownstreamCommitV1<C, U> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "AuthorityDownstreamCommitV1::Committed(..)",
            Self::PriorExact(_) => "AuthorityDownstreamCommitV1::PriorExact(..)",
            Self::ConfirmedRollback => "AuthorityDownstreamCommitV1::ConfirmedRollback",
            Self::UncertainReadbackCustodyTransferred(_) => {
                "AuthorityDownstreamCommitV1::UncertainReadbackCustodyTransferred(..)"
            }
            Self::Conflict => "AuthorityDownstreamCommitV1::Conflict",
            Self::AmbiguousReconciliationRequired => {
                "AuthorityDownstreamCommitV1::AmbiguousReconciliationRequired"
            }
            Self::DeadlineReached => "AuthorityDownstreamCommitV1::DeadlineReached",
            Self::Unavailable => "AuthorityDownstreamCommitV1::Unavailable",
        })
    }
}

/// Public result after explicit HLXA release.
pub enum AuthorityGuardCommitOutcomeV1<C, U> {
    Committed(C),
    PriorExact(C),
    ConfirmedRollback,
    UncertainReadbackCustodyTransferred(U),
    Conflict,
    AmbiguousReconciliationRequired,
    DeadlineReached,
    Unavailable,
    Refused(AuthorityGuardRefusalV1),
    ReleaseUncertain(
        AuthorityDownstreamCommitV1<C, U>,
        AuthorityGuardReleaseOutcomeV1,
    ),
}

impl<C, U> From<AuthorityDownstreamCommitV1<C, U>> for AuthorityGuardCommitOutcomeV1<C, U> {
    fn from(value: AuthorityDownstreamCommitV1<C, U>) -> Self {
        match value {
            AuthorityDownstreamCommitV1::Committed(value) => Self::Committed(value),
            AuthorityDownstreamCommitV1::PriorExact(value) => Self::PriorExact(value),
            AuthorityDownstreamCommitV1::ConfirmedRollback => Self::ConfirmedRollback,
            AuthorityDownstreamCommitV1::UncertainReadbackCustodyTransferred(value) => {
                Self::UncertainReadbackCustodyTransferred(value)
            }
            AuthorityDownstreamCommitV1::Conflict => Self::Conflict,
            AuthorityDownstreamCommitV1::AmbiguousReconciliationRequired => {
                Self::AmbiguousReconciliationRequired
            }
            AuthorityDownstreamCommitV1::DeadlineReached => Self::DeadlineReached,
            AuthorityDownstreamCommitV1::Unavailable => Self::Unavailable,
        }
    }
}

impl<C, U> fmt::Debug for AuthorityGuardCommitOutcomeV1<C, U> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "AuthorityGuardCommitOutcomeV1::Committed(..)",
            Self::PriorExact(_) => "AuthorityGuardCommitOutcomeV1::PriorExact(..)",
            Self::ConfirmedRollback => "AuthorityGuardCommitOutcomeV1::ConfirmedRollback",
            Self::UncertainReadbackCustodyTransferred(_) => {
                "AuthorityGuardCommitOutcomeV1::UncertainReadbackCustodyTransferred(..)"
            }
            Self::Conflict => "AuthorityGuardCommitOutcomeV1::Conflict",
            Self::AmbiguousReconciliationRequired => {
                "AuthorityGuardCommitOutcomeV1::AmbiguousReconciliationRequired"
            }
            Self::DeadlineReached => "AuthorityGuardCommitOutcomeV1::DeadlineReached",
            Self::Unavailable => "AuthorityGuardCommitOutcomeV1::Unavailable",
            Self::Refused(_) => "AuthorityGuardCommitOutcomeV1::Refused(..)",
            Self::ReleaseUncertain(_, _) => "AuthorityGuardCommitOutcomeV1::ReleaseUncertain(..)",
        })
    }
}

/// Acquires one physical guard and validates the logical Lease slot.
pub fn acquire_authority_lease_guard_v1<'request, 'plan, P>(
    provider: &P,
    request: &'request AuthorityProjectionRequestV1<'plan>,
    deadline: AuthorityDeadlineV1,
) -> AuthorityGuardAcquisitionV1<AuthorityLeaseGuardV1<'request, 'plan, P::Backend>>
where
    P: AuthorityGuardProviderV1 + ?Sized,
{
    let backend = match provider.acquire_backend_v1(request, &deadline) {
        AuthorityGuardAcquisitionV1::Acquired(backend) => backend,
        AuthorityGuardAcquisitionV1::Refused(refusal) => {
            return AuthorityGuardAcquisitionV1::Refused(refusal)
        }
    };

    let mut guard = AuthorityLeaseGuardV1 {
        backend: Some(backend),
        request,
        deadline: Some(deadline),
    };
    let validation = guard
        .backend
        .as_mut()
        .expect("authority lease guard backend is present")
        .validate_v1(
            AuthorityGuardValidationPointV1::Lease,
            guard.request,
            guard
                .deadline
                .as_ref()
                .expect("authority lease guard deadline is present"),
        );
    match validation {
        AuthorityGuardValidationV1::Current => AuthorityGuardAcquisitionV1::Acquired(guard),
        refusal => {
            let release = guard.rollback_and_release_v1();
            AuthorityGuardAcquisitionV1::Refused(release_refusal_v1(refusal.into(), release))
        }
    }
}

fn release_refusal_v1(
    original: AuthorityGuardRefusalV1,
    release: AuthorityGuardReleaseOutcomeV1,
) -> AuthorityGuardRefusalV1 {
    match release {
        AuthorityGuardReleaseOutcomeV1::Released => original,
        AuthorityGuardReleaseOutcomeV1::Unavailable => AuthorityGuardRefusalV1::Unavailable,
        AuthorityGuardReleaseOutcomeV1::Inconsistent => AuthorityGuardRefusalV1::Inconsistent,
    }
}

fn permit_release_refusal_v1(
    original: AuthorityGuardRefusalV1,
    release: AuthorityDownstreamPermitReleaseOutcomeV1,
) -> AuthorityGuardRefusalV1 {
    match release {
        AuthorityDownstreamPermitReleaseOutcomeV1::Released => original,
        AuthorityDownstreamPermitReleaseOutcomeV1::Unavailable => {
            AuthorityGuardRefusalV1::Unavailable
        }
        AuthorityDownstreamPermitReleaseOutcomeV1::Inconsistent => {
            AuthorityGuardRefusalV1::Inconsistent
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthorityClockObservationV1;
    use ed25519_dalek::{Signer as _, SigningKey};
    use helix_contracts::{
        sign_plan_v1, AtomicityV1, BudgetInputV1, ContractError, Ed25519KeyResolver, Ed25519Signer,
        FilePreconditionInputV1, Nonce128, PlanInputV1, RecoveryClassV1, RecoveryInputV1,
        RequestSourceKindV1, ResourceRefV1, RiskLevelV1, Sha256Digest,
    };
    use helix_task_authority_contracts::{Generation, Identifier, SafeU64};
    use std::sync::{Arc, Mutex};

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("valid generation")
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("valid safe integer")
    }

    fn deadline() -> AuthorityDeadlineV1 {
        AuthorityDeadlineV1::try_capture_v1(
            AuthorityClockObservationV1::from_trusted_provider_parts_v1(
                Identifier::new("boot-a").expect("valid boot"),
                generation(1),
                generation(1),
                safe(100),
                safe(200),
            ),
            safe(900),
            safe(800),
            safe(700),
        )
        .expect("live deadline")
    }

    struct Backend {
        events: Arc<Mutex<Vec<&'static str>>>,
        refusal: Option<AuthorityGuardValidationPointV1>,
        release_outcome: AuthorityGuardReleaseOutcomeV1,
        rollback_outcome: AuthorityGuardReleaseOutcomeV1,
    }

    impl sealed::GuardBackendV1 for Backend {}

    impl AuthorityGuardBackendV1 for Backend {
        fn validate_v1(
            &mut self,
            point: AuthorityGuardValidationPointV1,
            _request: &AuthorityProjectionRequestV1<'_>,
            _deadline: &AuthorityDeadlineV1,
        ) -> AuthorityGuardValidationV1 {
            self.events.lock().expect("events").push(match point {
                AuthorityGuardValidationPointV1::Lease => "lease",
                AuthorityGuardValidationPointV1::Authorization => "authorization",
                AuthorityGuardValidationPointV1::FinalCommit => "final",
            });
            if self.refusal == Some(point) {
                AuthorityGuardValidationV1::Revoked
            } else {
                AuthorityGuardValidationV1::Current
            }
        }

        fn release_after_classification_v1(self) -> AuthorityGuardReleaseOutcomeV1 {
            self.events.lock().expect("events").push("release");
            self.release_outcome
        }

        fn rollback_and_release_v1(self) -> AuthorityGuardReleaseOutcomeV1 {
            self.events.lock().expect("events").push("rollback");
            self.rollback_outcome
        }
    }

    struct Provider {
        events: Arc<Mutex<Vec<&'static str>>>,
        refusal: Option<AuthorityGuardValidationPointV1>,
        release_outcome: AuthorityGuardReleaseOutcomeV1,
        rollback_outcome: AuthorityGuardReleaseOutcomeV1,
    }

    impl sealed::GuardProviderV1 for Provider {}

    impl AuthorityGuardProviderV1 for Provider {
        type Backend = Backend;

        fn acquire_backend_v1(
            &self,
            _request: &AuthorityProjectionRequestV1<'_>,
            _deadline: &AuthorityDeadlineV1,
        ) -> AuthorityGuardAcquisitionV1<Self::Backend> {
            self.events.lock().expect("events").push("acquire");
            AuthorityGuardAcquisitionV1::Acquired(Backend {
                events: Arc::clone(&self.events),
                refusal: self.refusal,
                release_outcome: self.release_outcome,
                rollback_outcome: self.rollback_outcome,
            })
        }
    }

    struct Permit {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl AuthorityDownstreamCommitPermitV1<u8, u8> for Permit {
        fn commit_once_v1(
            self,
            _projection: CurrentAuthorityProjectionV1<'_>,
            _deadline: &AuthorityDeadlineV1,
        ) -> AuthorityDownstreamCommitV1<u8, u8> {
            self.events.lock().expect("events").push("commit");
            AuthorityDownstreamCommitV1::Committed(7)
        }

        fn abandon_v1(self) -> AuthorityDownstreamPermitReleaseOutcomeV1 {
            self.events.lock().expect("events").push("abandon");
            AuthorityDownstreamPermitReleaseOutcomeV1::Released
        }
    }

    struct TestSigner(SigningKey);

    impl Ed25519Signer for TestSigner {
        fn key_id(&self) -> &str {
            "key-a"
        }

        fn sign_ed25519(&self, message: &[u8]) -> helix_contracts::Result<[u8; 64]> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    struct Resolver([u8; 32]);

    impl Ed25519KeyResolver for Resolver {
        fn resolve_ed25519(&self, key_id: &str) -> helix_contracts::Result<[u8; 32]> {
            if key_id == "key-a" {
                Ok(self.0)
            } else {
                Err(ContractError::UnknownKey)
            }
        }
    }

    fn with_request<R>(test: impl FnOnce(&AuthorityProjectionRequestV1<'_>) -> R) -> R {
        let signer = TestSigner(SigningKey::from_bytes(&[7_u8; 32]));
        let signed = sign_plan_v1(plan_input(RequestSourceKindV1::HumanRequestGrant), &signer)
            .expect("sign plan");
        let authentic = helix_contracts::decode_and_verify_plan(
            &signed.to_canonical_json().expect("canonical plan"),
            &Resolver(signer.0.verifying_key().to_bytes()),
        )
        .expect("authentic plan");
        let request = AuthorityProjectionRequestV1::try_from_authentic_plan_v1(&authentic)
            .expect("projection request");
        test(&request)
    }

    fn plan_input(request_source_kind: RequestSourceKindV1) -> PlanInputV1 {
        PlanInputV1 {
            operation_id: "operation-private-sentinel".to_owned(),
            task_id: "task-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            boot_id: "boot-a".to_owned(),
            task_lease_digest: Sha256Digest::digest(b"lease"),
            request_source_kind,
            request_source_digest: Sha256Digest::digest(b"grant"),
            catalog_version: "catalog-a".to_owned(),
            policy_version: "policy-a".to_owned(),
            risk_level: RiskLevelV1::L1,
            target: ResourceRefV1::new("root-a", ["file"]).expect("valid target"),
            precondition: FilePreconditionInputV1 {
                volume_id: "volume-a".to_owned(),
                file_id: "file-a".to_owned(),
                content_sha256: Sha256Digest::digest(b"before"),
                byte_length: 6,
            },
            replacement_bytes: b"after".to_vec(),
            replacement_media_type: "text/plain".to_owned(),
            recovery: RecoveryInputV1 {
                class: RecoveryClassV1::Compensation,
                atomicity: AtomicityV1::AtomicReplace,
                reserved_bytes: 16,
            },
            capability_report_digest: Sha256Digest::digest(b"capability"),
            capability_observed_at_unix_ms: 99,
            required_capabilities: vec!["filesystem.atomic-replace".to_owned()],
            budget: BudgetInputV1 {
                reservation_id: "budget-a".to_owned(),
                currency_code: "EUR".to_owned(),
                price_table_id: "price-a".to_owned(),
                max_cost_micro_units: 0,
                action_limit: 1,
                egress_bytes_limit: 0,
            },
            issued_at_unix_ms: 100,
            expires_at_unix_ms: 700,
            nonce: Nonce128::from_bytes([1_u8; 16]),
            instance_epoch: 1,
            fencing_epoch: 1,
        }
    }

    fn authentic_plan(
        request_source_kind: RequestSourceKindV1,
    ) -> helix_contracts::AuthenticPlanEnvelopeV1 {
        let signer = TestSigner(SigningKey::from_bytes(&[7_u8; 32]));
        let signed = sign_plan_v1(plan_input(request_source_kind), &signer).expect("sign plan");
        helix_contracts::decode_and_verify_plan(
            &signed.to_canonical_json().expect("canonical plan"),
            &Resolver(signer.0.verifying_key().to_bytes()),
        )
        .expect("authentic plan")
    }

    #[test]
    fn request_hashes_the_exact_envelope_and_refuses_registered_triggers() {
        let authentic = authentic_plan(RequestSourceKindV1::HumanRequestGrant);
        let request = AuthorityProjectionRequestV1::try_from_authentic_plan_v1(&authentic)
            .expect("human request projection");
        let expected = helix_task_authority_contracts::Sha256Digest::digest(
            &authentic
                .canonical_signed_envelope_bytes()
                .expect("canonical envelope"),
        );

        assert_eq!(request.plan_envelope_digest_v1(), expected);
        assert_ne!(
            request.plan_envelope_digest_v1().as_bytes(),
            authentic.plan_id().as_bytes()
        );
        assert!(!format!("{request:?}").contains("operation-private-sentinel"));

        let trigger = authentic_plan(RequestSourceKindV1::RegisteredTrigger);
        assert_eq!(
            AuthorityProjectionRequestV1::try_from_authentic_plan_v1(&trigger)
                .expect_err("registered trigger must be unsupported"),
            crate::AuthorityProjectionRefusalV1::Unsupported
        );
    }

    #[test]
    fn generic_guard_and_commit_debug_never_renders_payloads() {
        #[derive(Debug)]
        struct Leaky(&'static str);

        let secret = "guard-provider-private-sentinel";
        let acquisition = AuthorityGuardAcquisitionV1::Acquired(Leaky(secret));
        let downstream = AuthorityDownstreamCommitV1::<Leaky, Leaky>::Committed(Leaky(secret));
        let uncertain = AuthorityGuardCommitOutcomeV1::ReleaseUncertain(
            AuthorityDownstreamCommitV1::<Leaky, Leaky>::UncertainReadbackCustodyTransferred(
                Leaky(secret),
            ),
            AuthorityGuardReleaseOutcomeV1::Unavailable,
        );
        let rendered = format!("{acquisition:?} {downstream:?} {uncertain:?}");

        assert!(!rendered.contains(secret));
        match acquisition {
            AuthorityGuardAcquisitionV1::Acquired(Leaky(value)) => assert_eq!(value, secret),
            AuthorityGuardAcquisitionV1::Refused(_) => panic!("unexpected refusal"),
        }
    }

    #[test]
    fn one_physical_guard_spans_all_slots_and_releases_after_classification() {
        with_request(|request| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let provider = Provider {
                events: Arc::clone(&events),
                refusal: None,
                release_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                rollback_outcome: AuthorityGuardReleaseOutcomeV1::Released,
            };
            let lease = match acquire_authority_lease_guard_v1(&provider, request, deadline()) {
                AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
            };
            let projection = match lease.validate_authorization_v1() {
                AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
            };
            let outcome = projection.commit_with_custody_v1(Permit {
                events: Arc::clone(&events),
            });

            assert!(matches!(
                outcome,
                AuthorityGuardCommitOutcomeV1::Committed(7)
            ));
            assert_eq!(
                events.lock().expect("events").as_slice(),
                [
                    "acquire",
                    "lease",
                    "authorization",
                    "final",
                    "commit",
                    "release"
                ]
            );
        });
    }

    #[test]
    fn refusal_never_invokes_downstream_and_rolls_back_once() {
        with_request(|request| {
            for point in [
                AuthorityGuardValidationPointV1::Lease,
                AuthorityGuardValidationPointV1::Authorization,
                AuthorityGuardValidationPointV1::FinalCommit,
            ] {
                let events = Arc::new(Mutex::new(Vec::new()));
                let provider = Provider {
                    events: Arc::clone(&events),
                    refusal: Some(point),
                    release_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                    rollback_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                };
                let lease = acquire_authority_lease_guard_v1(&provider, request, deadline());
                match (point, lease) {
                    (
                        AuthorityGuardValidationPointV1::Lease,
                        AuthorityGuardAcquisitionV1::Refused(AuthorityGuardRefusalV1::Revoked),
                    ) => {}
                    (_, AuthorityGuardAcquisitionV1::Acquired(lease)) => {
                        let projection = lease.validate_authorization_v1();
                        match (point, projection) {
                            (
                                AuthorityGuardValidationPointV1::Authorization,
                                AuthorityGuardAcquisitionV1::Refused(
                                    AuthorityGuardRefusalV1::Revoked,
                                ),
                            ) => {}
                            (_, AuthorityGuardAcquisitionV1::Acquired(projection)) => {
                                let outcome = projection.commit_with_custody_v1(Permit {
                                    events: Arc::clone(&events),
                                });
                                assert!(matches!(
                                    outcome,
                                    AuthorityGuardCommitOutcomeV1::Refused(
                                        AuthorityGuardRefusalV1::Revoked
                                    )
                                ));
                            }
                            _ => panic!("unexpected authorization outcome"),
                        }
                    }
                    _ => panic!("unexpected lease outcome"),
                }
                let observed = events.lock().expect("events");
                assert_eq!(
                    observed
                        .iter()
                        .filter(|event| **event == "rollback")
                        .count(),
                    1
                );
                assert!(!observed.contains(&"commit"));
                if point == AuthorityGuardValidationPointV1::FinalCommit {
                    assert!(observed.ends_with(&["final", "abandon", "rollback"]));
                }
            }
        });
    }

    #[test]
    fn release_failures_never_collapse_into_success_or_the_original_refusal() {
        struct AbandonFailurePermit;

        impl AuthorityDownstreamCommitPermitV1<u8, u8> for AbandonFailurePermit {
            fn commit_once_v1(
                self,
                _projection: CurrentAuthorityProjectionV1<'_>,
                _deadline: &AuthorityDeadlineV1,
            ) -> AuthorityDownstreamCommitV1<u8, u8> {
                panic!("a refused final validation must never commit")
            }

            fn abandon_v1(self) -> AuthorityDownstreamPermitReleaseOutcomeV1 {
                AuthorityDownstreamPermitReleaseOutcomeV1::Inconsistent
            }
        }

        with_request(|request| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let provider = Provider {
                events: Arc::clone(&events),
                refusal: None,
                release_outcome: AuthorityGuardReleaseOutcomeV1::Unavailable,
                rollback_outcome: AuthorityGuardReleaseOutcomeV1::Released,
            };
            let lease = match acquire_authority_lease_guard_v1(&provider, request, deadline()) {
                AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
            };
            let projection = match lease.validate_authorization_v1() {
                AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
            };
            let outcome = projection.commit_with_custody_v1(Permit {
                events: Arc::clone(&events),
            });
            assert!(matches!(
                outcome,
                AuthorityGuardCommitOutcomeV1::ReleaseUncertain(
                    AuthorityDownstreamCommitV1::Committed(7),
                    AuthorityGuardReleaseOutcomeV1::Unavailable
                )
            ));

            let rollback_events = Arc::new(Mutex::new(Vec::new()));
            let rollback_provider = Provider {
                events: Arc::clone(&rollback_events),
                refusal: Some(AuthorityGuardValidationPointV1::Lease),
                release_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                rollback_outcome: AuthorityGuardReleaseOutcomeV1::Inconsistent,
            };
            assert!(matches!(
                acquire_authority_lease_guard_v1(&rollback_provider, request, deadline()),
                AuthorityGuardAcquisitionV1::Refused(AuthorityGuardRefusalV1::Inconsistent)
            ));

            let abandon_events = Arc::new(Mutex::new(Vec::new()));
            let abandon_provider = Provider {
                events: Arc::clone(&abandon_events),
                refusal: Some(AuthorityGuardValidationPointV1::FinalCommit),
                release_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                rollback_outcome: AuthorityGuardReleaseOutcomeV1::Released,
            };
            let abandon_lease =
                match acquire_authority_lease_guard_v1(&abandon_provider, request, deadline()) {
                    AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                    AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
                };
            let abandon_projection = match abandon_lease.validate_authorization_v1() {
                AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
            };
            assert!(matches!(
                abandon_projection.commit_with_custody_v1(AbandonFailurePermit),
                AuthorityGuardCommitOutcomeV1::Refused(AuthorityGuardRefusalV1::Inconsistent)
            ));
        });
    }

    #[test]
    fn abandoning_either_typestate_rolls_back_exactly_once() {
        with_request(|request| {
            for abandon_projection in [false, true] {
                let events = Arc::new(Mutex::new(Vec::new()));
                let provider = Provider {
                    events: Arc::clone(&events),
                    refusal: None,
                    release_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                    rollback_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                };
                let lease = match acquire_authority_lease_guard_v1(&provider, request, deadline()) {
                    AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                    AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
                };
                if abandon_projection {
                    let projection = match lease.validate_authorization_v1() {
                        AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                        AuthorityGuardAcquisitionV1::Refused(reason) => {
                            panic!("refused: {reason}")
                        }
                    };
                    drop(projection);
                } else {
                    drop(lease);
                }
                let observed = events.lock().expect("events");
                assert_eq!(
                    observed
                        .iter()
                        .filter(|event| **event == "rollback")
                        .count(),
                    1
                );
            }
        });
    }

    #[test]
    fn downstream_unwind_runs_explicit_rollback_once() {
        struct PanickingPermit;

        impl AuthorityDownstreamCommitPermitV1<u8, u8> for PanickingPermit {
            fn commit_once_v1(
                self,
                _projection: CurrentAuthorityProjectionV1<'_>,
                _deadline: &AuthorityDeadlineV1,
            ) -> AuthorityDownstreamCommitV1<u8, u8> {
                panic!("synthetic downstream unwind")
            }

            fn abandon_v1(self) -> AuthorityDownstreamPermitReleaseOutcomeV1 {
                AuthorityDownstreamPermitReleaseOutcomeV1::Released
            }
        }

        with_request(|request| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let provider = Provider {
                events: Arc::clone(&events),
                refusal: None,
                release_outcome: AuthorityGuardReleaseOutcomeV1::Released,
                rollback_outcome: AuthorityGuardReleaseOutcomeV1::Released,
            };
            let lease = match acquire_authority_lease_guard_v1(&provider, request, deadline()) {
                AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
            };
            let projection = match lease.validate_authorization_v1() {
                AuthorityGuardAcquisitionV1::Acquired(guard) => guard,
                AuthorityGuardAcquisitionV1::Refused(reason) => panic!("refused: {reason}"),
            };
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = projection.commit_with_custody_v1(PanickingPermit);
            }));

            assert!(unwound.is_err());
            assert_eq!(
                events
                    .lock()
                    .expect("events")
                    .iter()
                    .filter(|event| **event == "rollback")
                    .count(),
                1
            );
        });
    }
}
