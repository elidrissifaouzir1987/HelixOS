//! Fixed-order live authority guards and linearizable dispatch permit.

#![allow(dead_code)]

use crate::store::DispatchStoreCommitClassificationV1;
use crate::{DispatchAttemptIdV1, DispatchAuthorityCaptureOutcomeV1, DispatchLookupRequestV1};
use std::fmt;

/// The PLAN-004 global guard order retained by PLAN-005 before store-writer entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DispatchGuardClassV1 {
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

impl DispatchGuardClassV1 {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchGuardValidationV1 {
    Valid,
    Revoked,
    Unavailable,
    DeadlineReached,
    Mismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchGuardOrderErrorV1 {
    UnexpectedClass,
}

/// Closed cursor used by the acquisition wrapper; providers cannot skip or reorder a class.
pub(crate) struct DispatchGuardOrderTrackerV1 {
    next_index: usize,
    violated: bool,
}

impl DispatchGuardOrderTrackerV1 {
    pub(crate) const fn new_v1() -> Self {
        Self {
            next_index: 0,
            violated: false,
        }
    }

    pub(crate) fn observe_v1(
        &mut self,
        class: DispatchGuardClassV1,
    ) -> Result<(), DispatchGuardOrderErrorV1> {
        let order = DispatchGuardClassV1::acquisition_order();
        if self.violated || order.get(self.next_index) != Some(&class) {
            self.violated = true;
            return Err(DispatchGuardOrderErrorV1::UnexpectedClass);
        }
        self.next_index += 1;
        Ok(())
    }

    pub(crate) const fn is_complete_v1(&self) -> bool {
        !self.violated && self.next_index == DispatchGuardClassV1::COUNT
    }
}

impl fmt::Debug for DispatchGuardOrderTrackerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchGuardOrderTrackerV1")
            .finish_non_exhaustive()
    }
}

/// One terminal resolution after consuming a live permit and at most one store closure.
pub enum DispatchCommitResolutionV1<C, U> {
    Committed(C),
    PriorExactDispatch(C),
    ConfirmedRollback,
    Uncertain(U),
    Conflict,
    Revoked,
    Unavailable,
    DeadlineReached,
    Ambiguous,
    Unclassified,
}

impl<C, U> fmt::Debug for DispatchCommitResolutionV1<C, U> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed(_) => formatter.write_str("DispatchCommitResolutionV1::Committed(..)"),
            Self::PriorExactDispatch(_) => {
                formatter.write_str("DispatchCommitResolutionV1::PriorExactDispatch(..)")
            }
            Self::ConfirmedRollback => {
                formatter.write_str("DispatchCommitResolutionV1::ConfirmedRollback")
            }
            Self::Uncertain(_) => formatter.write_str("DispatchCommitResolutionV1::Uncertain(..)"),
            Self::Conflict => formatter.write_str("DispatchCommitResolutionV1::Conflict"),
            Self::Revoked => formatter.write_str("DispatchCommitResolutionV1::Revoked"),
            Self::Unavailable => formatter.write_str("DispatchCommitResolutionV1::Unavailable"),
            Self::DeadlineReached => {
                formatter.write_str("DispatchCommitResolutionV1::DeadlineReached")
            }
            Self::Ambiguous => formatter.write_str("DispatchCommitResolutionV1::Ambiguous"),
            Self::Unclassified => formatter.write_str("DispatchCommitResolutionV1::Unclassified"),
        }
    }
}

/// Live permit custody held across final comparison and exactly one commit closure.
///
/// ```compile_fail,E0382
/// use helix_plan_dispatch::{
///     DispatchCommitPermitV1, DispatchStoreCommitClassificationV1,
/// };
///
/// fn cannot_reuse<P: DispatchCommitPermitV1>(permit: P) {
///     let _ = permit.commit_once(|| {
///         DispatchStoreCommitClassificationV1::<(), ()>::ConfirmedRollback
///     });
///     permit.abandon_v1();
/// }
/// ```
pub trait DispatchCommitPermitV1: Send + Sized {
    fn deadline_monotonic_ms(&self) -> u64;

    fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1;

    fn commit_once<C, U, F>(self, commit: F) -> DispatchCommitResolutionV1<C, U>
    where
        C: Send,
        U: Send,
        F: FnOnce() -> DispatchStoreCommitClassificationV1<C, U>;

    fn abandon_v1(self);
}

/// All PLAN-004-order guards retained through final capture and commit resolution.
pub trait DispatchGuardSetV1: Send {
    type Permit: DispatchCommitPermitV1;

    fn capture_final_authority_v1(&mut self) -> DispatchAuthorityCaptureOutcomeV1;

    fn validate_all_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1;

    fn acquire_commit_permit_v1(
        &mut self,
        attempt: &DispatchAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> DispatchCommitPermitOutcomeV1<Self::Permit>;

    fn release_reverse_v1(self);
}

pub enum DispatchGuardAcquisitionV1<G> {
    Acquired(G),
    Unavailable,
    DeadlineReached,
    Revoked,
    OrderViolated,
    Unsupported,
}

impl<G> fmt::Debug for DispatchGuardAcquisitionV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquired(_) => formatter.write_str("DispatchGuardAcquisitionV1::Acquired(..)"),
            Self::Unavailable => formatter.write_str("DispatchGuardAcquisitionV1::Unavailable"),
            Self::DeadlineReached => {
                formatter.write_str("DispatchGuardAcquisitionV1::DeadlineReached")
            }
            Self::Revoked => formatter.write_str("DispatchGuardAcquisitionV1::Revoked"),
            Self::OrderViolated => formatter.write_str("DispatchGuardAcquisitionV1::OrderViolated"),
            Self::Unsupported => formatter.write_str("DispatchGuardAcquisitionV1::Unsupported"),
        }
    }
}

pub enum DispatchCommitPermitOutcomeV1<P> {
    Permitted(P),
    Unavailable,
    DeadlineReached,
    Revoked,
    Unsupported,
}

impl<P> fmt::Debug for DispatchCommitPermitOutcomeV1<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permitted(_) => {
                formatter.write_str("DispatchCommitPermitOutcomeV1::Permitted(..)")
            }
            Self::Unavailable => formatter.write_str("DispatchCommitPermitOutcomeV1::Unavailable"),
            Self::DeadlineReached => {
                formatter.write_str("DispatchCommitPermitOutcomeV1::DeadlineReached")
            }
            Self::Revoked => formatter.write_str("DispatchCommitPermitOutcomeV1::Revoked"),
            Self::Unsupported => formatter.write_str("DispatchCommitPermitOutcomeV1::Unsupported"),
        }
    }
}

pub trait DispatchGuardProviderV1: Send + Sync {
    type GuardSet: DispatchGuardSetV1;

    fn acquire_in_fixed_order_v1(
        &self,
        request: &DispatchLookupRequestV1,
        attempt: &DispatchAttemptIdV1,
        after_acquisition: &mut dyn FnMut(
            DispatchGuardClassV1,
        ) -> Result<(), DispatchGuardOrderErrorV1>,
    ) -> DispatchGuardAcquisitionV1<Self::GuardSet>;
}

pub(crate) fn acquire_dispatch_guards_in_fixed_order_v1<P: DispatchGuardProviderV1>(
    provider: &P,
    request: &DispatchLookupRequestV1,
    attempt: &DispatchAttemptIdV1,
) -> DispatchGuardAcquisitionV1<P::GuardSet> {
    let mut tracker = DispatchGuardOrderTrackerV1::new_v1();
    let mut observe = |class| tracker.observe_v1(class);
    let outcome = provider.acquire_in_fixed_order_v1(request, attempt, &mut observe);
    if tracker.is_complete_v1() {
        return outcome;
    }
    match outcome {
        DispatchGuardAcquisitionV1::Acquired(guards) => {
            guards.release_reverse_v1();
            DispatchGuardAcquisitionV1::OrderViolated
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_dispatch_guard_order_is_the_plan004_order() {
        assert_eq!(
            DispatchGuardClassV1::acquisition_order(),
            [
                DispatchGuardClassV1::RecoveryPublication,
                DispatchGuardClassV1::ExternalClockDeadline,
                DispatchGuardClassV1::Supervisor,
                DispatchGuardClassV1::SignerTrust,
                DispatchGuardClassV1::Workload,
                DispatchGuardClassV1::Lease,
                DispatchGuardClassV1::Authorization,
                DispatchGuardClassV1::Policy,
                DispatchGuardClassV1::Catalogue,
                DispatchGuardClassV1::Capabilities,
            ]
        );
    }

    #[test]
    fn order_tracker_rejects_skip_duplicate_and_incomplete_sequences() {
        let order = DispatchGuardClassV1::acquisition_order();
        let mut exact = DispatchGuardOrderTrackerV1::new_v1();
        for class in order {
            exact.observe_v1(class).unwrap();
        }
        assert!(exact.is_complete_v1());

        let mut skipped = DispatchGuardOrderTrackerV1::new_v1();
        assert_eq!(
            skipped.observe_v1(DispatchGuardClassV1::ExternalClockDeadline),
            Err(DispatchGuardOrderErrorV1::UnexpectedClass)
        );
        assert!(!skipped.is_complete_v1());

        let mut duplicate = DispatchGuardOrderTrackerV1::new_v1();
        duplicate
            .observe_v1(DispatchGuardClassV1::RecoveryPublication)
            .unwrap();
        assert_eq!(
            duplicate.observe_v1(DispatchGuardClassV1::RecoveryPublication),
            Err(DispatchGuardOrderErrorV1::UnexpectedClass)
        );

        let mut incomplete = DispatchGuardOrderTrackerV1::new_v1();
        incomplete
            .observe_v1(DispatchGuardClassV1::RecoveryPublication)
            .unwrap();
        assert!(!incomplete.is_complete_v1());
    }
}
