//! Ephemeral external-authority guard boundary.
//!
//! Guards represent non-serializable, non-transferable custody acquired in the frozen
//! global order. Provider implementations and native synchronization remain outside
//! this portable crate.

#![allow(dead_code)]

use crate::attempt::PreparationAttemptIdV1;
use crate::commit_gate::FinalCommitGateV1;
use crate::context::PreparationContextV1;
use helix_contracts::SafeU64;
use helix_plan_eligibility::EligiblePlanV1;
use std::fmt;

const MAX_GUARD_IDENTIFIER_BYTES: usize = 128;

/// Frozen external guard order. The coordinator writer is acquired afterward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityGuardKindV1 {
    RecoveryPublication,
    ExternalClockDeadline,
    Supervisor,
    SignerTrust,
    Workload,
    Lease,
    Authorization,
    Policy,
    Catalogue,
    Capabilities,
}

impl AuthorityGuardKindV1 {
    pub const COUNT: usize = 10;

    pub const fn acquisition_order() -> [Self; Self::COUNT] {
        [
            Self::RecoveryPublication,
            Self::ExternalClockDeadline,
            Self::Supervisor,
            Self::SignerTrust,
            Self::Workload,
            Self::Lease,
            Self::Authorization,
            Self::Policy,
            Self::Catalogue,
            Self::Capabilities,
        ]
    }
}

/// Opaque proof that Phase B already acquired and retained the first global guard.
///
/// Only ordered orchestration can construct this value, immediately after the
/// recovery provider returns its exclusive publication custody.
pub struct RecoveryPublicationGuardSlotV1 {
    _private: (),
}

impl fmt::Debug for RecoveryPublicationGuardSlotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryPublicationGuardSlotV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn record_recovery_publication_guard_v1() -> RecoveryPublicationGuardSlotV1 {
    RecoveryPublicationGuardSlotV1 { _private: () }
}

/// The provider reported an acquisition outside the frozen v1 order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityGuardAcquisitionOrderErrorV1 {
    UnexpectedGuard,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorityGuardValidationV1 {
    Valid,
    Revoked,
    Unavailable,
    DeadlineReached,
    Mismatch,
}

/// One opaque provider guard. Implementations must be non-Clone and non-Serde.
pub trait AuthorityGuardV1: Send {
    fn kind(&self) -> AuthorityGuardKindV1;

    fn validate(
        &mut self,
        now_monotonic_ms: u64,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardValidationV1;
}

/// Complete live guard custody acquired in the frozen order and released in reverse.
///
/// The set also implements [`FinalCommitGateV1`] so the store receives one mutable
/// borrow that remains tied to every live external guard through commit resolution.
pub trait AuthorityGuardSetV1: FinalCommitGateV1 + Send {
    fn capture_final(
        &mut self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> PreparationContextV1;

    fn validate_all(
        &mut self,
        now_monotonic_ms: u64,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardValidationV1;

    fn release_reverse(self);
}

pub enum AuthorityGuardAcquisitionV1<G> {
    Acquired(G),
    Unavailable,
    DeadlineReached,
    Revoked,
    Unsupported,
}

/// Closed portable classification used by ordered orchestration after guard calls.
///
/// A changed guarded binding is indistinguishable from revocation at the final commit
/// boundary: neither may cross into a store commit.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AuthorityGuardRefusalV1 {
    Revoked,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

pub(crate) fn classify_authority_guard_acquisition_v1<G>(
    outcome: AuthorityGuardAcquisitionV1<G>,
) -> Result<G, AuthorityGuardRefusalV1> {
    match outcome {
        AuthorityGuardAcquisitionV1::Acquired(guards) => Ok(guards),
        AuthorityGuardAcquisitionV1::Revoked => Err(AuthorityGuardRefusalV1::Revoked),
        AuthorityGuardAcquisitionV1::Unavailable => Err(AuthorityGuardRefusalV1::Unavailable),
        AuthorityGuardAcquisitionV1::DeadlineReached => {
            Err(AuthorityGuardRefusalV1::DeadlineReached)
        }
        AuthorityGuardAcquisitionV1::Unsupported => Err(AuthorityGuardRefusalV1::Unsupported),
    }
}

pub(crate) fn classify_authority_guard_validation_v1(
    outcome: AuthorityGuardValidationV1,
) -> Result<(), AuthorityGuardRefusalV1> {
    match outcome {
        AuthorityGuardValidationV1::Valid => Ok(()),
        AuthorityGuardValidationV1::Revoked | AuthorityGuardValidationV1::Mismatch => {
            Err(AuthorityGuardRefusalV1::Revoked)
        }
        AuthorityGuardValidationV1::Unavailable => Err(AuthorityGuardRefusalV1::Unavailable),
        AuthorityGuardValidationV1::DeadlineReached => {
            Err(AuthorityGuardRefusalV1::DeadlineReached)
        }
    }
}

impl<G> fmt::Debug for AuthorityGuardAcquisitionV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Acquired(_) => "Acquired(..)",
            Self::Unavailable => "Unavailable",
            Self::DeadlineReached => "DeadlineReached",
            Self::Revoked => "Revoked",
            Self::Unsupported => "Unsupported",
        };
        write!(formatter, "AuthorityGuardAcquisitionV1::{variant}")
    }
}

/// Trusted provider wiring for preliminary capture and final guarded capture.
pub trait PreparationAuthoritySourceV1: Send + Sync {
    type GuardSet: AuthorityGuardSetV1;

    fn capture_preliminary(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> PreparationContextV1;

    fn acquire_final_guards(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardAcquisitionV1<Self::GuardSet>;

    /// Acquires guards one by one and reports each acquisition at its exact boundary.
    ///
    /// Phase B already owns `RecoveryPublication`. An implementation must invoke
    /// `after_acquisition` exactly once, immediately after each remaining real guard is
    /// held, in `AuthorityGuardKindV1::acquisition_order()[1..]`.
    /// If the callback refuses the step or any later acquisition fails, the provider
    /// must release the current and all earlier guards in reverse order before
    /// returning. The fail-closed default preserves existing implementations without
    /// silently approximating the section-14 boundary.
    fn acquire_final_guards_ordered_v1(
        &self,
        _eligible: &EligiblePlanV1,
        _attempt: &PreparationAttemptIdV1,
        _deadline_monotonic_ms: u64,
        _after_acquisition: &mut dyn FnMut(
            AuthorityGuardKindV1,
        )
            -> Result<(), AuthorityGuardAcquisitionOrderErrorV1>,
    ) -> AuthorityGuardAcquisitionV1<Self::GuardSet> {
        AuthorityGuardAcquisitionV1::Unsupported
    }

    /// Trusted orchestration path that enforces order and reaches every acquisition
    /// hook before returning the complete live guard set.
    fn acquire_final_guards_instrumented_v1(
        &self,
        _recovery_publication: &RecoveryPublicationGuardSlotV1,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardAcquisitionV1<Self::GuardSet>
    where
        Self: Sized,
    {
        acquire_final_guards_observed_v1(self, eligible, attempt, deadline_monotonic_ms, || {})
    }
}

struct FrozenAuthorityGuardOrderV1 {
    next: usize,
    violated: bool,
}

impl FrozenAuthorityGuardOrderV1 {
    const fn after_recovery_publication() -> Self {
        Self {
            next: 1,
            violated: false,
        }
    }

    fn record(
        &mut self,
        kind: AuthorityGuardKindV1,
    ) -> Result<(), AuthorityGuardAcquisitionOrderErrorV1> {
        if self.violated
            || AuthorityGuardKindV1::acquisition_order()
                .get(self.next)
                .copied()
                != Some(kind)
        {
            self.violated = true;
            return Err(AuthorityGuardAcquisitionOrderErrorV1::UnexpectedGuard);
        }
        self.next += 1;
        Ok(())
    }

    const fn is_complete(&self) -> bool {
        self.next == AuthorityGuardKindV1::COUNT && !self.violated
    }
}

pub(crate) fn acquire_final_guards_observed_v1<S, O>(
    source: &S,
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    deadline_monotonic_ms: u64,
    mut after_acquisition: O,
) -> AuthorityGuardAcquisitionV1<S::GuardSet>
where
    S: PreparationAuthoritySourceV1,
    O: FnMut(),
{
    let mut order = FrozenAuthorityGuardOrderV1::after_recovery_publication();
    let outcome = source.acquire_final_guards_ordered_v1(
        eligible,
        attempt,
        deadline_monotonic_ms,
        &mut |kind| {
            order.record(kind)?;
            after_acquisition();
            Ok(())
        },
    );

    match outcome {
        AuthorityGuardAcquisitionV1::Acquired(guards) if !order.is_complete() => {
            guards.release_reverse();
            AuthorityGuardAcquisitionV1::Unsupported
        }
        _ if order.violated => AuthorityGuardAcquisitionV1::Unsupported,
        other => other,
    }
}

pub struct NoDispatchAuthorityBindingInputV1<'binding> {
    pub operation_id: &'binding str,
    pub attempt: &'binding PreparationAttemptIdV1,
    pub preparing_state_generation: u64,
    pub boot_id: &'binding str,
    pub instance_epoch: u64,
    pub fencing_epoch: u64,
    pub revocation_generation: u64,
    pub deadline_monotonic_ms: u64,
}

impl fmt::Debug for NoDispatchAuthorityBindingInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoDispatchAuthorityBindingInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NoDispatchAuthorityBindingErrorV1 {
    InvalidIdentifier,
    IntegerOutOfRange,
}

/// Exact expected binding presented to injected no-dispatch authority wiring.
pub struct NoDispatchAuthorityBindingV1<'binding> {
    operation_id: &'binding str,
    attempt: &'binding PreparationAttemptIdV1,
    preparing_state_generation: SafeU64,
    boot_id: &'binding str,
    instance_epoch: SafeU64,
    fencing_epoch: SafeU64,
    revocation_generation: SafeU64,
    deadline_monotonic_ms: SafeU64,
}

impl<'binding> NoDispatchAuthorityBindingV1<'binding> {
    pub fn try_new(
        input: NoDispatchAuthorityBindingInputV1<'binding>,
    ) -> Result<Self, NoDispatchAuthorityBindingErrorV1> {
        validate_identifier(input.operation_id)?;
        validate_identifier(input.boot_id)?;
        Ok(Self {
            operation_id: input.operation_id,
            attempt: input.attempt,
            preparing_state_generation: safe(input.preparing_state_generation)?,
            boot_id: input.boot_id,
            instance_epoch: safe(input.instance_epoch)?,
            fencing_epoch: safe(input.fencing_epoch)?,
            revocation_generation: safe(input.revocation_generation)?,
            deadline_monotonic_ms: safe(input.deadline_monotonic_ms)?,
        })
    }

    pub const fn operation_id(&self) -> &str {
        self.operation_id
    }

    pub const fn attempt(&self) -> &PreparationAttemptIdV1 {
        self.attempt
    }

    pub const fn preparing_state_generation(&self) -> u64 {
        self.preparing_state_generation.get()
    }

    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }

    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }

    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch.get()
    }

    pub const fn revocation_generation(&self) -> u64 {
        self.revocation_generation.get()
    }

    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }

    pub const fn is_live_at(&self, now_monotonic_ms: u64) -> bool {
        now_monotonic_ms < self.deadline_monotonic_ms.get()
    }
}

impl fmt::Debug for NoDispatchAuthorityBindingV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NoDispatchAuthorityBindingV1")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NoDispatchAuthorityValidationV1 {
    Valid,
    Mismatch,
    Revoked,
    DeadlineReached,
    Unavailable,
}

/// Opaque live custody proving that no dispatch authority exists for one operation.
pub trait NoDispatchAuthorityGuardV1: Send {
    fn validate(
        &mut self,
        expected: &NoDispatchAuthorityBindingV1<'_>,
        now_monotonic_ms: u64,
    ) -> NoDispatchAuthorityValidationV1;

    fn release(self);
}

/// Records that trusted failure orchestration obtained live no-dispatch custody.
///
/// This feature-only helper carries no authority and exposes no guard material; it lets
/// the SQLite adapter place the closed section-14 boundary without exporting fault
/// plumbing itself.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn note_known_failure_guard_acquired_v1() {
    note_known_failure_guard_acquired_with_fault_probe_v1(
        &crate::test_fault::FaultProbeV1::disabled_v1(),
    );
}

/// Probe-aware form used only by the explicit process-kill driver.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn note_known_failure_guard_acquired_with_fault_probe_v1(
    fault_probe: &crate::test_fault::FaultProbeV1,
) {
    fault_probe.reach_v1(crate::test_fault::FaultBoundaryV1::KnownFailureNoDispatchGuardAcquired);
}

/// Records the final live validation immediately before the failure COMMIT.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn note_known_failure_guard_finally_revalidated_v1() {
    note_known_failure_guard_finally_revalidated_with_fault_probe_v1(
        &crate::test_fault::FaultProbeV1::disabled_v1(),
    );
}

/// Probe-aware form used only by the explicit process-kill driver.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn note_known_failure_guard_finally_revalidated_with_fault_probe_v1(
    fault_probe: &crate::test_fault::FaultProbeV1,
) {
    fault_probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::KnownFailureNoDispatchGuardFinallyRevalidated,
    );
}

/// Releases sovereign no-dispatch custody at its owner and records the closed boundary.
#[doc(hidden)]
pub fn release_known_failure_guard_v1<G: NoDispatchAuthorityGuardV1>(guard: G) {
    #[cfg(feature = "test-fault-injection")]
    return release_known_failure_guard_with_fault_probe_v1(
        guard,
        &crate::test_fault::FaultProbeV1::disabled_v1(),
    );
    #[cfg(not(feature = "test-fault-injection"))]
    guard.release();
}

/// Probe-aware form used only by the explicit process-kill driver.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn release_known_failure_guard_with_fault_probe_v1<G: NoDispatchAuthorityGuardV1>(
    guard: G,
    fault_probe: &crate::test_fault::FaultProbeV1,
) {
    fault_probe.reach_v1(crate::test_fault::FaultBoundaryV1::KnownFailureNoDispatchGuardReleased);
    guard.release();
}

pub enum NoDispatchAuthorityGuardAcquisitionV1<G> {
    Acquired(G),
    Mismatch,
    Revoked,
    DeadlineReached,
    Unavailable,
}

impl<G> fmt::Debug for NoDispatchAuthorityGuardAcquisitionV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Acquired(_) => "Acquired(..)",
            Self::Mismatch => "Mismatch",
            Self::Revoked => "Revoked",
            Self::DeadlineReached => "DeadlineReached",
            Self::Unavailable => "Unavailable",
        };
        write!(
            formatter,
            "NoDispatchAuthorityGuardAcquisitionV1::{variant}"
        )
    }
}

/// Externally injected supervisor/dispatch-authority source for failure reconciliation.
pub trait NoDispatchAuthoritySourceV1: Send + Sync {
    type Guard: NoDispatchAuthorityGuardV1;

    fn acquire_no_dispatch_guard(
        &self,
        binding: &NoDispatchAuthorityBindingV1<'_>,
    ) -> NoDispatchAuthorityGuardAcquisitionV1<Self::Guard>;
}

fn safe(value: u64) -> Result<SafeU64, NoDispatchAuthorityBindingErrorV1> {
    SafeU64::new(value).map_err(|_| NoDispatchAuthorityBindingErrorV1::IntegerOutOfRange)
}

fn validate_identifier(value: &str) -> Result<(), NoDispatchAuthorityBindingErrorV1> {
    if value.is_empty()
        || value.len() > MAX_GUARD_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(NoDispatchAuthorityBindingErrorV1::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_guard_observer_accepts_only_the_complete_exact_order() {
        let mut complete = FrozenAuthorityGuardOrderV1::after_recovery_publication();
        for kind in AuthorityGuardKindV1::acquisition_order()
            .into_iter()
            .skip(1)
        {
            assert_eq!(complete.record(kind), Ok(()));
        }
        assert!(complete.is_complete());

        let mut reordered = FrozenAuthorityGuardOrderV1::after_recovery_publication();
        assert_eq!(
            reordered.record(AuthorityGuardKindV1::Supervisor),
            Err(AuthorityGuardAcquisitionOrderErrorV1::UnexpectedGuard)
        );
        assert_eq!(
            reordered.record(AuthorityGuardKindV1::RecoveryPublication),
            Err(AuthorityGuardAcquisitionOrderErrorV1::UnexpectedGuard)
        );
        assert!(!reordered.is_complete());
    }

    #[test]
    fn guard_acquisition_classification_is_closed_and_lossless() {
        assert_eq!(
            classify_authority_guard_acquisition_v1(AuthorityGuardAcquisitionV1::Acquired(7_u8)),
            Ok(7)
        );
        assert_eq!(
            classify_authority_guard_acquisition_v1::<u8>(AuthorityGuardAcquisitionV1::Revoked),
            Err(AuthorityGuardRefusalV1::Revoked)
        );
        assert_eq!(
            classify_authority_guard_acquisition_v1::<u8>(AuthorityGuardAcquisitionV1::Unavailable),
            Err(AuthorityGuardRefusalV1::Unavailable)
        );
        assert_eq!(
            classify_authority_guard_acquisition_v1::<u8>(
                AuthorityGuardAcquisitionV1::DeadlineReached
            ),
            Err(AuthorityGuardRefusalV1::DeadlineReached)
        );
        assert_eq!(
            classify_authority_guard_acquisition_v1::<u8>(AuthorityGuardAcquisitionV1::Unsupported),
            Err(AuthorityGuardRefusalV1::Unsupported)
        );
    }

    #[test]
    fn mismatch_and_revocation_share_the_closed_guard_refusal() {
        assert_eq!(
            classify_authority_guard_validation_v1(AuthorityGuardValidationV1::Valid),
            Ok(())
        );
        for outcome in [
            AuthorityGuardValidationV1::Revoked,
            AuthorityGuardValidationV1::Mismatch,
        ] {
            assert_eq!(
                classify_authority_guard_validation_v1(outcome),
                Err(AuthorityGuardRefusalV1::Revoked)
            );
        }
        assert_eq!(
            classify_authority_guard_validation_v1(AuthorityGuardValidationV1::Unavailable),
            Err(AuthorityGuardRefusalV1::Unavailable)
        );
        assert_eq!(
            classify_authority_guard_validation_v1(AuthorityGuardValidationV1::DeadlineReached),
            Err(AuthorityGuardRefusalV1::DeadlineReached)
        );
    }
}
