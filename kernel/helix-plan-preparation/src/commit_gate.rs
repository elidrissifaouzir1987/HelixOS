//! Final commit-gate and one-shot permit boundary.
//!
//! This module coordinates borrowed live guards with the store commit boundary. It
//! creates no operation by itself and owns no production supervisor thread, fencing
//! store, SQLite connection, or ambient deadline source.

#![allow(dead_code)]

use crate::attempt::PreparationAttemptIdV1;
use helix_contracts::{SafeU64, MAX_SAFE_U64};
use std::fmt;

pub const FINAL_COMMIT_PERMIT_CEILING_MS: u64 = 250;

#[derive(Debug, PartialEq, Eq)]
pub enum FinalCommitPermitRequestErrorV1 {
    IntegerOutOfRange,
}

pub struct FinalCommitPermitRequestInputV1<'attempt> {
    pub attempt: &'attempt PreparationAttemptIdV1,
    pub expected_supervisor_generation: u64,
    pub caller_deadline_monotonic_ms: u64,
    pub permit_entry_monotonic_ms: u64,
}

impl fmt::Debug for FinalCommitPermitRequestInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalCommitPermitRequestInputV1")
            .finish_non_exhaustive()
    }
}

/// Explicit, checked request passed to the injected supervisor-owned commit gate.
pub struct FinalCommitPermitRequestV1<'attempt> {
    attempt: &'attempt PreparationAttemptIdV1,
    expected_supervisor_generation: SafeU64,
    caller_deadline_monotonic_ms: u64,
    permit_entry_monotonic_ms: u64,
    permit_deadline_monotonic_ms: u64,
}

impl<'attempt> FinalCommitPermitRequestV1<'attempt> {
    pub fn try_new(
        input: FinalCommitPermitRequestInputV1<'attempt>,
    ) -> Result<Self, FinalCommitPermitRequestErrorV1> {
        let expected_supervisor_generation = safe(input.expected_supervisor_generation)?;
        safe(input.caller_deadline_monotonic_ms)?;
        safe(input.permit_entry_monotonic_ms)?;
        let permit_deadline_monotonic_ms = compute_final_commit_permit_deadline_v1(
            input.caller_deadline_monotonic_ms,
            input.permit_entry_monotonic_ms,
        )?;
        Ok(Self {
            attempt: input.attempt,
            expected_supervisor_generation,
            caller_deadline_monotonic_ms: input.caller_deadline_monotonic_ms,
            permit_entry_monotonic_ms: input.permit_entry_monotonic_ms,
            permit_deadline_monotonic_ms,
        })
    }

    pub const fn attempt(&self) -> &PreparationAttemptIdV1 {
        self.attempt
    }

    pub const fn expected_supervisor_generation(&self) -> u64 {
        self.expected_supervisor_generation.get()
    }

    pub const fn caller_deadline_monotonic_ms(&self) -> u64 {
        self.caller_deadline_monotonic_ms
    }

    pub const fn permit_entry_monotonic_ms(&self) -> u64 {
        self.permit_entry_monotonic_ms
    }

    pub const fn permit_deadline_monotonic_ms(&self) -> u64 {
        self.permit_deadline_monotonic_ms
    }

    /// The permit lease is exclusive; equality is already expired.
    pub const fn is_live_at(&self, now_monotonic_ms: u64) -> bool {
        now_monotonic_ms < self.permit_deadline_monotonic_ms
    }
}

impl fmt::Debug for FinalCommitPermitRequestV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalCommitPermitRequestV1")
            .finish_non_exhaustive()
    }
}

/// Computes `min(caller deadline, permit entry + 250 ms)` without overflow.
pub fn compute_final_commit_permit_deadline_v1(
    caller_deadline_monotonic_ms: u64,
    permit_entry_monotonic_ms: u64,
) -> Result<u64, FinalCommitPermitRequestErrorV1> {
    safe(caller_deadline_monotonic_ms)?;
    safe(permit_entry_monotonic_ms)?;
    let caller = u128::from(caller_deadline_monotonic_ms);
    let ceiling =
        u128::from(permit_entry_monotonic_ms) + u128::from(FINAL_COMMIT_PERMIT_CEILING_MS);
    u64::try_from(caller.min(ceiling))
        .map_err(|_| FinalCommitPermitRequestErrorV1::IntegerOutOfRange)
}

/// Closed gate result before any store commit is invoked.
pub enum FinalCommitPermitOutcomeV1<P> {
    Permitted(P),
    Revoked,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

impl<P> fmt::Debug for FinalCommitPermitOutcomeV1<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Permitted(_) => "Permitted(..)",
            Self::Revoked => "Revoked",
            Self::Unavailable => "Unavailable",
            Self::DeadlineReached => "DeadlineReached",
            Self::Unsupported => "Unsupported",
        };
        write!(formatter, "FinalCommitPermitOutcomeV1::{variant}")
    }
}

/// Trusted store classification returned by the single commit attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum FinalCommitStoreClassificationV1 {
    Committed,
    ConfirmedRollback,
    Uncertain,
    Unclassified,
}

/// Resolution immediately after the one-shot store commit call.
pub enum FinalCommitResolutionV1<I> {
    Committed,
    Aborted,
    Uncertain(I),
    Ambiguous,
}

impl<I> fmt::Debug for FinalCommitResolutionV1<I> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Committed => "Committed",
            Self::Aborted => "Aborted",
            Self::Uncertain(_) => "Uncertain(..)",
            Self::Ambiguous => "Ambiguous",
        };
        write!(formatter, "FinalCommitResolutionV1::{variant}")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FinalCommitReadbackResolutionV1 {
    ThisAttemptCommitted,
    PriorExactAttempt,
    Conflict,
    DefinitelyAbsent,
    Inconclusive,
    LateOrRevoked,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FinalCommitTerminalResolutionV1 {
    Committed,
    Aborted,
    Ambiguous,
}

/// Supervisor-owned gate that linearizes revocation against permit entry.
pub trait FinalCommitGateV1: Send {
    type Permit: FinalCommitPermitV1;

    fn enter_commit_permit(
        &mut self,
        request: &FinalCommitPermitRequestV1<'_>,
    ) -> FinalCommitPermitOutcomeV1<Self::Permit>;

    /// Trusted host path that also reaches the frozen permit-return boundary.
    fn enter_commit_permit_instrumented_v1(
        &mut self,
        request: &FinalCommitPermitRequestV1<'_>,
    ) -> FinalCommitPermitOutcomeV1<Self::Permit>
    where
        Self: Sized,
    {
        enter_final_commit_permit_v1(self, request)
    }
}

/// Opaque one-shot permit held across exactly one actual store commit.
///
/// Implementations are injected supervisor custody and must not implement Clone or
/// Serde. Consuming `self` ensures the portable caller cannot invoke commit twice.
pub trait FinalCommitPermitV1: Send {
    type InFlight: FinalCommitInFlightV1;

    fn permit_deadline_monotonic_ms(&self) -> u64;

    fn commit_once<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
    where
        C: FnOnce() -> FinalCommitStoreClassificationV1;

    /// Trusted host path that instruments the move to in-flight and terminal result.
    fn commit_once_instrumented_v1<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
    where
        Self: Sized,
        C: FnOnce() -> FinalCommitStoreClassificationV1,
    {
        commit_final_once_v1(self, commit)
    }
}

/// Opaque custody retained only for the one bounded exact-readback window.
pub trait FinalCommitInFlightV1: Send {
    fn permit_deadline_monotonic_ms(&self) -> u64;

    fn resolve_readback(
        self,
        resolution: FinalCommitReadbackResolutionV1,
    ) -> FinalCommitTerminalResolutionV1;

    /// Trusted host path that instruments the one bounded readback resolution.
    fn resolve_readback_instrumented_v1(
        self,
        resolution: FinalCommitReadbackResolutionV1,
    ) -> FinalCommitTerminalResolutionV1
    where
        Self: Sized,
    {
        resolve_final_commit_readback_v1(self, resolution)
    }
}

#[cfg(feature = "test-fault-injection")]
pub(crate) struct FaultProbedFinalCommitPermitV1<P> {
    permit: P,
    fault_probe: crate::test_fault::FaultProbeV1,
}

#[cfg(feature = "test-fault-injection")]
impl<P> FaultProbedFinalCommitPermitV1<P> {
    pub(crate) fn new(permit: P, fault_probe: crate::test_fault::FaultProbeV1) -> Self {
        Self {
            permit,
            fault_probe,
        }
    }
}

#[cfg(feature = "test-fault-injection")]
pub(crate) struct FaultProbedFinalCommitInFlightV1<I> {
    in_flight: I,
    fault_probe: crate::test_fault::FaultProbeV1,
}

#[cfg(feature = "test-fault-injection")]
impl<P> FinalCommitPermitV1 for FaultProbedFinalCommitPermitV1<P>
where
    P: FinalCommitPermitV1,
{
    type InFlight = FaultProbedFinalCommitInFlightV1<P::InFlight>;

    fn permit_deadline_monotonic_ms(&self) -> u64 {
        self.permit.permit_deadline_monotonic_ms()
    }

    fn commit_once<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
    where
        C: FnOnce() -> FinalCommitStoreClassificationV1,
    {
        let Self {
            permit,
            fault_probe,
        } = self;
        let resolution = permit.commit_once(|| {
            #[cfg(feature = "test-fault-injection")]
            fault_probe.reach_v1(
                crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitMovedToCommitInFlight,
            );
            commit()
        });
        match resolution {
            FinalCommitResolutionV1::Committed => {
                #[cfg(feature = "test-fault-injection")]
                fault_probe.reach_v1(
                    crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedCommitted,
                );
                FinalCommitResolutionV1::Committed
            }
            FinalCommitResolutionV1::Aborted => {
                #[cfg(feature = "test-fault-injection")]
                fault_probe.reach_v1(
                    crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedAborted,
                );
                FinalCommitResolutionV1::Aborted
            }
            FinalCommitResolutionV1::Uncertain(in_flight) => {
                FinalCommitResolutionV1::Uncertain(FaultProbedFinalCommitInFlightV1 {
                    in_flight,
                    fault_probe,
                })
            }
            FinalCommitResolutionV1::Ambiguous => {
                #[cfg(feature = "test-fault-injection")]
                fault_probe.reach_v1(
                    crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedAmbiguous,
                );
                FinalCommitResolutionV1::Ambiguous
            }
        }
    }
}

#[cfg(feature = "test-fault-injection")]
impl<I> FinalCommitInFlightV1 for FaultProbedFinalCommitInFlightV1<I>
where
    I: FinalCommitInFlightV1,
{
    fn permit_deadline_monotonic_ms(&self) -> u64 {
        self.in_flight.permit_deadline_monotonic_ms()
    }

    fn resolve_readback(
        self,
        resolution: FinalCommitReadbackResolutionV1,
    ) -> FinalCommitTerminalResolutionV1 {
        let terminal = self.in_flight.resolve_readback(resolution);
        #[cfg(feature = "test-fault-injection")]
        let boundary = match terminal {
            FinalCommitTerminalResolutionV1::Committed => {
                crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedCommitted
            }
            FinalCommitTerminalResolutionV1::Aborted => {
                crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedAborted
            }
            FinalCommitTerminalResolutionV1::Ambiguous => {
                crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedAmbiguous
            }
        };
        #[cfg(feature = "test-fault-injection")]
        self.fault_probe.reach_v1(boundary);
        terminal
    }
}

#[cfg(feature = "test-fault-injection")]
struct T074TerminalClassificationPermitV1;

#[cfg(feature = "test-fault-injection")]
struct T074UnreachableInFlightV1;

#[cfg(feature = "test-fault-injection")]
impl FinalCommitPermitV1 for T074TerminalClassificationPermitV1 {
    type InFlight = T074UnreachableInFlightV1;

    fn permit_deadline_monotonic_ms(&self) -> u64 {
        MAX_SAFE_U64
    }

    fn commit_once<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
    where
        C: FnOnce() -> FinalCommitStoreClassificationV1,
    {
        match commit() {
            FinalCommitStoreClassificationV1::Committed => FinalCommitResolutionV1::Committed,
            FinalCommitStoreClassificationV1::ConfirmedRollback => FinalCommitResolutionV1::Aborted,
            FinalCommitStoreClassificationV1::Uncertain => {
                FinalCommitResolutionV1::Uncertain(T074UnreachableInFlightV1)
            }
            FinalCommitStoreClassificationV1::Unclassified => FinalCommitResolutionV1::Ambiguous,
        }
    }
}

#[cfg(feature = "test-fault-injection")]
impl FinalCommitInFlightV1 for T074UnreachableInFlightV1 {
    fn permit_deadline_monotonic_ms(&self) -> u64 {
        MAX_SAFE_U64
    }

    fn resolve_readback(
        self,
        _resolution: FinalCommitReadbackResolutionV1,
    ) -> FinalCommitTerminalResolutionV1 {
        FinalCommitTerminalResolutionV1::Ambiguous
    }
}

/// Drives one of the two non-committed terminal classifications through the real
/// fault-probed permit wrapper for the private T074 process-kill harness.
///
/// No permit or in-flight custody escapes, and every ID outside the two closed terminal
/// boundaries is rejected before callback custody is created.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn run_t074_terminal_commit_classification_for_test_v1<P>(
    boundary_id: &str,
    occurrence: u64,
    process_barrier: P,
) -> Result<(), &'static str>
where
    P: crate::test_fault::ProcessBarrierV1 + 'static,
{
    if occurrence != 1 {
        return Err("fault-occurrence-invalid");
    }
    let classification = match boundary_id {
        "positive_coordinator_commit_permit_resolved_aborted" => {
            FinalCommitStoreClassificationV1::ConfirmedRollback
        }
        "positive_coordinator_commit_permit_resolved_ambiguous" => {
            FinalCommitStoreClassificationV1::Unclassified
        }
        _ => return Err("fault-boundary-workflow-unsupported"),
    };
    let fault_probe = crate::test_fault::FaultProbeV1::selected_process_barrier_v1(
        boundary_id,
        occurrence,
        process_barrier,
    )
    .map_err(|_| "fault-occurrence-invalid")?;
    let permit =
        FaultProbedFinalCommitPermitV1::new(T074TerminalClassificationPermitV1, fault_probe);
    let resolution = permit.commit_once_instrumented_v1(|| classification);
    let expected = match boundary_id {
        "positive_coordinator_commit_permit_resolved_aborted" => {
            matches!(resolution, FinalCommitResolutionV1::Aborted)
        }
        "positive_coordinator_commit_permit_resolved_ambiguous" => {
            matches!(resolution, FinalCommitResolutionV1::Ambiguous)
        }
        _ => false,
    };
    if expected {
        Ok(())
    } else {
        Err("terminal-commit-classification-invalid")
    }
}

#[cfg(feature = "test-fault-injection")]
pub(crate) fn reach_fault_probed_commit_permit_returned_v1(
    fault_probe: &crate::test_fault::FaultProbeV1,
) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitEnterCommitPermitReturned,
    );
}

pub(crate) fn enter_final_commit_permit_v1<G: FinalCommitGateV1>(
    gate: &mut G,
    request: &FinalCommitPermitRequestV1<'_>,
) -> FinalCommitPermitOutcomeV1<G::Permit> {
    let outcome = gate.enter_commit_permit(request);
    #[cfg(feature = "test-fault-injection")]
    crate::test_fault::reach(
        crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitEnterCommitPermitReturned,
    );
    outcome
}

pub(crate) fn commit_final_once_v1<P, C>(
    permit: P,
    commit: C,
) -> FinalCommitResolutionV1<P::InFlight>
where
    P: FinalCommitPermitV1,
    C: FnOnce() -> FinalCommitStoreClassificationV1,
{
    let resolution = permit.commit_once(|| {
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(
            crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitMovedToCommitInFlight,
        );
        commit()
    });
    reach_terminal_resolution_v1(&resolution);
    resolution
}

pub(crate) fn resolve_final_commit_readback_v1<I: FinalCommitInFlightV1>(
    in_flight: I,
    resolution: FinalCommitReadbackResolutionV1,
) -> FinalCommitTerminalResolutionV1 {
    let terminal = in_flight.resolve_readback(resolution);
    reach_terminal_resolution_v1(&terminal);
    terminal
}

trait TerminalResolutionV1 {
    fn terminal_kind_v1(&self) -> Option<FinalCommitTerminalResolutionV1>;
}

impl<I> TerminalResolutionV1 for FinalCommitResolutionV1<I> {
    fn terminal_kind_v1(&self) -> Option<FinalCommitTerminalResolutionV1> {
        match self {
            Self::Committed => Some(FinalCommitTerminalResolutionV1::Committed),
            Self::Aborted => Some(FinalCommitTerminalResolutionV1::Aborted),
            Self::Ambiguous => Some(FinalCommitTerminalResolutionV1::Ambiguous),
            Self::Uncertain(_) => None,
        }
    }
}

impl TerminalResolutionV1 for FinalCommitTerminalResolutionV1 {
    fn terminal_kind_v1(&self) -> Option<FinalCommitTerminalResolutionV1> {
        Some(match self {
            Self::Committed => FinalCommitTerminalResolutionV1::Committed,
            Self::Aborted => FinalCommitTerminalResolutionV1::Aborted,
            Self::Ambiguous => FinalCommitTerminalResolutionV1::Ambiguous,
        })
    }
}

fn reach_terminal_resolution_v1<T: TerminalResolutionV1>(resolution: &T) {
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = resolution;
    #[cfg(feature = "test-fault-injection")]
    if let Some(terminal) = resolution.terminal_kind_v1() {
        let boundary = match terminal {
            FinalCommitTerminalResolutionV1::Committed => {
                crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedCommitted
            }
            FinalCommitTerminalResolutionV1::Aborted => {
                crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedAborted
            }
            FinalCommitTerminalResolutionV1::Ambiguous => {
                crate::test_fault::FaultBoundaryV1::PositiveCoordinatorCommitPermitResolvedAmbiguous
            }
        };
        crate::test_fault::reach(boundary);
    }
}

fn safe(value: u64) -> Result<SafeU64, FinalCommitPermitRequestErrorV1> {
    if value > MAX_SAFE_U64 {
        return Err(FinalCommitPermitRequestErrorV1::IntegerOutOfRange);
    }
    SafeU64::new(value).map_err(|_| FinalCommitPermitRequestErrorV1::IntegerOutOfRange)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeGate;
    struct FakePermit;
    struct FakeInFlight;

    impl FinalCommitGateV1 for FakeGate {
        type Permit = FakePermit;

        fn enter_commit_permit(
            &mut self,
            request: &FinalCommitPermitRequestV1<'_>,
        ) -> FinalCommitPermitOutcomeV1<Self::Permit> {
            if request.is_live_at(request.permit_entry_monotonic_ms()) {
                FinalCommitPermitOutcomeV1::Permitted(FakePermit)
            } else {
                FinalCommitPermitOutcomeV1::DeadlineReached
            }
        }
    }

    impl FinalCommitPermitV1 for FakePermit {
        type InFlight = FakeInFlight;

        fn permit_deadline_monotonic_ms(&self) -> u64 {
            250
        }

        fn commit_once<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
        where
            C: FnOnce() -> FinalCommitStoreClassificationV1,
        {
            match commit() {
                FinalCommitStoreClassificationV1::Committed => FinalCommitResolutionV1::Committed,
                FinalCommitStoreClassificationV1::ConfirmedRollback => {
                    FinalCommitResolutionV1::Aborted
                }
                FinalCommitStoreClassificationV1::Uncertain => {
                    FinalCommitResolutionV1::Uncertain(FakeInFlight)
                }
                FinalCommitStoreClassificationV1::Unclassified => {
                    FinalCommitResolutionV1::Ambiguous
                }
            }
        }
    }

    impl FinalCommitInFlightV1 for FakeInFlight {
        fn permit_deadline_monotonic_ms(&self) -> u64 {
            250
        }

        fn resolve_readback(
            self,
            resolution: FinalCommitReadbackResolutionV1,
        ) -> FinalCommitTerminalResolutionV1 {
            match resolution {
                FinalCommitReadbackResolutionV1::ThisAttemptCommitted => {
                    FinalCommitTerminalResolutionV1::Committed
                }
                FinalCommitReadbackResolutionV1::PriorExactAttempt
                | FinalCommitReadbackResolutionV1::Conflict
                | FinalCommitReadbackResolutionV1::DefinitelyAbsent => {
                    FinalCommitTerminalResolutionV1::Aborted
                }
                FinalCommitReadbackResolutionV1::Inconclusive
                | FinalCommitReadbackResolutionV1::LateOrRevoked => {
                    FinalCommitTerminalResolutionV1::Ambiguous
                }
            }
        }
    }

    #[test]
    fn permit_deadline_uses_the_earlier_exclusive_bound() {
        assert_eq!(
            compute_final_commit_permit_deadline_v1(1_000, 900),
            Ok(1_000)
        );
        assert_eq!(
            compute_final_commit_permit_deadline_v1(2_000, 900),
            Ok(1_150)
        );
        assert_eq!(
            compute_final_commit_permit_deadline_v1(MAX_SAFE_U64, MAX_SAFE_U64),
            Ok(MAX_SAFE_U64)
        );
    }

    #[test]
    fn public_instrumented_traits_preserve_every_commit_and_readback_classification() {
        assert!(matches!(
            FakePermit
                .commit_once_instrumented_v1(|| { FinalCommitStoreClassificationV1::Committed }),
            FinalCommitResolutionV1::Committed
        ));
        assert!(matches!(
            FakePermit.commit_once_instrumented_v1(|| {
                FinalCommitStoreClassificationV1::ConfirmedRollback
            }),
            FinalCommitResolutionV1::Aborted
        ));
        let in_flight = match FakePermit
            .commit_once_instrumented_v1(|| FinalCommitStoreClassificationV1::Uncertain)
        {
            FinalCommitResolutionV1::Uncertain(value) => value,
            other => panic!("unexpected resolution: {other:?}"),
        };
        assert_eq!(
            in_flight.resolve_readback_instrumented_v1(
                FinalCommitReadbackResolutionV1::DefinitelyAbsent,
            ),
            FinalCommitTerminalResolutionV1::Aborted
        );
        assert!(matches!(
            FakePermit
                .commit_once_instrumented_v1(|| { FinalCommitStoreClassificationV1::Unclassified }),
            FinalCommitResolutionV1::Ambiguous
        ));
    }

    #[test]
    fn enter_helper_preserves_the_injected_gate_outcome() {
        let attempt = PreparationAttemptIdV1::generate().expect("test randomness is available");
        let request = FinalCommitPermitRequestV1::try_new(FinalCommitPermitRequestInputV1 {
            attempt: &attempt,
            expected_supervisor_generation: 1,
            caller_deadline_monotonic_ms: 1_000,
            permit_entry_monotonic_ms: 900,
        })
        .expect("request is valid");
        assert!(matches!(
            FakeGate.enter_commit_permit_instrumented_v1(&request),
            FinalCommitPermitOutcomeV1::Permitted(_)
        ));
    }
}
