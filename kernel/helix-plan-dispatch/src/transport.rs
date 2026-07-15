//! Exact-byte delivery and linearizable handoff fencing boundary.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchHandoffValidationV1 {
    Live,
    Paused,
    DeadlineReached,
    Revoked,
    Unavailable,
}

pub trait DispatchHandoffGuardV1: Send {
    /// Stable digest binding this guard to one transport-owned handoff epoch.
    ///
    /// The coordinator persists this value before the external handoff can begin. It is
    /// evidence only: it contains no transport handle and grants no delivery authority.
    fn evidence_binding_v1(&self) -> [u8; 32];

    fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchHandoffValidationV1;

    fn release_v1(self);
}

pub enum DispatchHandoffOutcomeV1<R> {
    Acknowledged(R),
    ConfirmedNoSend,
    PossibleHandoff,
    PausedBeforeHandoff,
    DeadlineReachedBeforeHandoff,
    UnavailableBeforeHandoff,
}

impl<R> fmt::Debug for DispatchHandoffOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acknowledged(_) => {
                formatter.write_str("DispatchHandoffOutcomeV1::Acknowledged(..)")
            }
            Self::ConfirmedNoSend => {
                formatter.write_str("DispatchHandoffOutcomeV1::ConfirmedNoSend")
            }
            Self::PossibleHandoff => {
                formatter.write_str("DispatchHandoffOutcomeV1::PossibleHandoff")
            }
            Self::PausedBeforeHandoff => {
                formatter.write_str("DispatchHandoffOutcomeV1::PausedBeforeHandoff")
            }
            Self::DeadlineReachedBeforeHandoff => {
                formatter.write_str("DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff")
            }
            Self::UnavailableBeforeHandoff => {
                formatter.write_str("DispatchHandoffOutcomeV1::UnavailableBeforeHandoff")
            }
        }
    }
}

/// Local replaceable transport. It receives only exact already-retained grant bytes.
pub trait DispatchTransportV1: Send + Sync {
    type Guard: DispatchHandoffGuardV1;
    type Response: Send;

    fn acquire_handoff_guard_v1(
        &self,
        grant_binding: &[u8; 32],
        deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1>;

    fn deliver_exact_v1(
        &self,
        guard: &mut Self::Guard,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response>;
}

/// Performs one exact-byte handoff while a transport guard remains linearizably held.
///
/// `commit_possible_handoff_evidence` must durably bind the guard digest and the exact
/// retained grant before it returns `Ok(())`. `sample_now_after_evidence` must obtain a
/// fresh reading after that commit. The held guard and the exclusive deadline are then
/// revalidated immediately before delivery. Once evidence commits, every stop or error
/// is conservatively classified as `PossibleHandoff`: only failures observed before
/// that commit may be called confirmed no-send.
pub fn handoff_exact_grant_once_v1<T, F, N>(
    transport: &T,
    grant_binding: &[u8; 32],
    exact_signed_grant_bytes: &[u8],
    now_monotonic_ms: u64,
    exclusive_deadline_monotonic_ms: u64,
    commit_possible_handoff_evidence: F,
    sample_now_after_evidence: N,
) -> DispatchHandoffOutcomeV1<T::Response>
where
    T: DispatchTransportV1,
    F: FnOnce([u8; 32]) -> Result<(), DispatchHandoffValidationV1>,
    N: FnOnce() -> Result<u64, DispatchHandoffValidationV1>,
{
    handoff_exact_grant_once_inner_v1(
        transport,
        grant_binding,
        exact_signed_grant_bytes,
        now_monotonic_ms,
        exclusive_deadline_monotonic_ms,
        commit_possible_handoff_evidence,
        sample_now_after_evidence,
        &NoDispatchHandoffFaultsV1,
    )
}

/// Feature-only handoff seam for the closed PLAN-005 fault registry.
///
/// Ordinary callers use [`handoff_exact_grant_once_v1`]. This seam differs only by
/// reaching the three portable delivery checkpoints carried by an explicit probe.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
// Keep the feature-only seam byte-for-byte parallel with the ordinary public boundary;
// the explicit probe is its sole additional argument.
#[allow(clippy::too_many_arguments)]
pub fn handoff_exact_grant_once_with_fault_probe_v1<T, F, N>(
    transport: &T,
    grant_binding: &[u8; 32],
    exact_signed_grant_bytes: &[u8],
    now_monotonic_ms: u64,
    exclusive_deadline_monotonic_ms: u64,
    commit_possible_handoff_evidence: F,
    sample_now_after_evidence: N,
    fault_probe: &crate::DispatchFaultProbeV1,
) -> DispatchHandoffOutcomeV1<T::Response>
where
    T: DispatchTransportV1,
    F: FnOnce([u8; 32]) -> Result<(), DispatchHandoffValidationV1>,
    N: FnOnce() -> Result<u64, DispatchHandoffValidationV1>,
{
    handoff_exact_grant_once_inner_v1(
        transport,
        grant_binding,
        exact_signed_grant_bytes,
        now_monotonic_ms,
        exclusive_deadline_monotonic_ms,
        commit_possible_handoff_evidence,
        sample_now_after_evidence,
        &DispatchHandoffFaultProbeV1(fault_probe),
    )
}

// This private core preserves the same explicit authority, deadline, evidence, and clock
// inputs while abstracting only the feature-gated checkpoints.
#[allow(clippy::too_many_arguments)]
fn handoff_exact_grant_once_inner_v1<T, F, N, P>(
    transport: &T,
    grant_binding: &[u8; 32],
    exact_signed_grant_bytes: &[u8],
    now_monotonic_ms: u64,
    exclusive_deadline_monotonic_ms: u64,
    commit_possible_handoff_evidence: F,
    sample_now_after_evidence: N,
    fault_checkpoints: &P,
) -> DispatchHandoffOutcomeV1<T::Response>
where
    T: DispatchTransportV1,
    F: FnOnce([u8; 32]) -> Result<(), DispatchHandoffValidationV1>,
    N: FnOnce() -> Result<u64, DispatchHandoffValidationV1>,
    P: DispatchHandoffFaultCheckpointsV1,
{
    if now_monotonic_ms >= exclusive_deadline_monotonic_ms {
        return DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff;
    }

    let mut guard =
        match transport.acquire_handoff_guard_v1(grant_binding, exclusive_deadline_monotonic_ms) {
            Ok(guard) => guard,
            Err(error) => return pre_handoff_outcome_v1(error),
        };
    let validation = guard.validate_at_v1(now_monotonic_ms);
    if validation != DispatchHandoffValidationV1::Live {
        guard.release_v1();
        return pre_handoff_outcome_v1(validation);
    }
    if fault_checkpoints.after_guard_acquisition_v1() {
        guard.release_v1();
        return DispatchHandoffOutcomeV1::UnavailableBeforeHandoff;
    }

    if let Err(error) = commit_possible_handoff_evidence(guard.evidence_binding_v1()) {
        guard.release_v1();
        return pre_handoff_outcome_v1(error);
    }

    let now_after_evidence = match sample_now_after_evidence() {
        Ok(now) if now < exclusive_deadline_monotonic_ms => now,
        Ok(_) | Err(_) => {
            guard.release_v1();
            return DispatchHandoffOutcomeV1::PossibleHandoff;
        }
    };
    if guard.validate_at_v1(now_after_evidence) != DispatchHandoffValidationV1::Live {
        guard.release_v1();
        return DispatchHandoffOutcomeV1::PossibleHandoff;
    }
    if fault_checkpoints.immediately_before_external_handoff_v1() {
        guard.release_v1();
        return DispatchHandoffOutcomeV1::PossibleHandoff;
    }

    let outcome = transport.deliver_exact_v1(&mut guard, exact_signed_grant_bytes);
    if fault_checkpoints.after_possible_handoff_before_result_evidence_v1() {
        guard.release_v1();
        return DispatchHandoffOutcomeV1::PossibleHandoff;
    }
    guard.release_v1();
    match outcome {
        DispatchHandoffOutcomeV1::Acknowledged(response) => {
            DispatchHandoffOutcomeV1::Acknowledged(response)
        }
        DispatchHandoffOutcomeV1::ConfirmedNoSend
        | DispatchHandoffOutcomeV1::PossibleHandoff
        | DispatchHandoffOutcomeV1::PausedBeforeHandoff
        | DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff
        | DispatchHandoffOutcomeV1::UnavailableBeforeHandoff => {
            DispatchHandoffOutcomeV1::PossibleHandoff
        }
    }
}

trait DispatchHandoffFaultCheckpointsV1 {
    fn after_guard_acquisition_v1(&self) -> bool;

    fn immediately_before_external_handoff_v1(&self) -> bool;

    fn after_possible_handoff_before_result_evidence_v1(&self) -> bool;
}

struct NoDispatchHandoffFaultsV1;

impl DispatchHandoffFaultCheckpointsV1 for NoDispatchHandoffFaultsV1 {
    fn after_guard_acquisition_v1(&self) -> bool {
        false
    }

    fn immediately_before_external_handoff_v1(&self) -> bool {
        false
    }

    fn after_possible_handoff_before_result_evidence_v1(&self) -> bool {
        false
    }
}

#[cfg(feature = "test-fault-injection")]
struct DispatchHandoffFaultProbeV1<'probe>(&'probe crate::DispatchFaultProbeV1);

#[cfg(feature = "test-fault-injection")]
impl DispatchHandoffFaultCheckpointsV1 for DispatchHandoffFaultProbeV1<'_> {
    fn after_guard_acquisition_v1(&self) -> bool {
        dispatch_fault_injected_v1(self.0, crate::test_fault::FaultBoundaryV1::Plan005Fb019)
    }

    fn immediately_before_external_handoff_v1(&self) -> bool {
        dispatch_fault_injected_v1(self.0, crate::test_fault::FaultBoundaryV1::Plan005Fb021)
    }

    fn after_possible_handoff_before_result_evidence_v1(&self) -> bool {
        dispatch_fault_injected_v1(self.0, crate::test_fault::FaultBoundaryV1::Plan005Fb022)
    }
}

#[cfg(feature = "test-fault-injection")]
fn dispatch_fault_injected_v1(
    fault_probe: &crate::DispatchFaultProbeV1,
    boundary: crate::test_fault::FaultBoundaryV1,
) -> bool {
    !matches!(
        fault_probe.reach_id_v1(boundary.id()),
        Ok(crate::FaultInjectionDecisionV1::Continue)
    )
}

fn pre_handoff_outcome_v1<R>(
    validation: DispatchHandoffValidationV1,
) -> DispatchHandoffOutcomeV1<R> {
    match validation {
        DispatchHandoffValidationV1::Live => DispatchHandoffOutcomeV1::ConfirmedNoSend,
        DispatchHandoffValidationV1::Paused | DispatchHandoffValidationV1::Revoked => {
            DispatchHandoffOutcomeV1::PausedBeforeHandoff
        }
        DispatchHandoffValidationV1::DeadlineReached => {
            DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff
        }
        DispatchHandoffValidationV1::Unavailable => {
            DispatchHandoffOutcomeV1::UnavailableBeforeHandoff
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum StepV1 {
        Acquire,
        Validate,
        Persist,
        RefreshClock,
        Deliver,
        Release,
    }

    struct Guard {
        events: Arc<Mutex<Vec<StepV1>>>,
        validation: DispatchHandoffValidationV1,
    }

    impl DispatchHandoffGuardV1 for Guard {
        fn evidence_binding_v1(&self) -> [u8; 32] {
            [0x44; 32]
        }

        fn validate_at_v1(&mut self, _now_monotonic_ms: u64) -> DispatchHandoffValidationV1 {
            self.events.lock().unwrap().push(StepV1::Validate);
            self.validation
        }

        fn release_v1(self) {
            self.events.lock().unwrap().push(StepV1::Release);
        }
    }

    struct Transport {
        events: Arc<Mutex<Vec<StepV1>>>,
        validation: DispatchHandoffValidationV1,
        outcome: DispatchHandoffOutcomeV1<u8>,
    }

    impl DispatchTransportV1 for Transport {
        type Guard = Guard;
        type Response = u8;

        fn acquire_handoff_guard_v1(
            &self,
            _grant_binding: &[u8; 32],
            _deadline_monotonic_ms: u64,
        ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
            self.events.lock().unwrap().push(StepV1::Acquire);
            Ok(Guard {
                events: Arc::clone(&self.events),
                validation: self.validation,
            })
        }

        fn deliver_exact_v1(
            &self,
            _guard: &mut Self::Guard,
            exact_signed_grant_bytes: &[u8],
        ) -> DispatchHandoffOutcomeV1<Self::Response> {
            assert_eq!(exact_signed_grant_bytes, b"exact-signed-grant");
            self.events.lock().unwrap().push(StepV1::Deliver);
            match self.outcome {
                DispatchHandoffOutcomeV1::Acknowledged(value) => {
                    DispatchHandoffOutcomeV1::Acknowledged(value)
                }
                DispatchHandoffOutcomeV1::ConfirmedNoSend => {
                    DispatchHandoffOutcomeV1::ConfirmedNoSend
                }
                DispatchHandoffOutcomeV1::PossibleHandoff => {
                    DispatchHandoffOutcomeV1::PossibleHandoff
                }
                DispatchHandoffOutcomeV1::PausedBeforeHandoff => {
                    DispatchHandoffOutcomeV1::PausedBeforeHandoff
                }
                DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff => {
                    DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff
                }
                DispatchHandoffOutcomeV1::UnavailableBeforeHandoff => {
                    DispatchHandoffOutcomeV1::UnavailableBeforeHandoff
                }
            }
        }
    }

    #[test]
    fn deadline_equality_stops_before_guard_or_evidence() {
        let transport = Transport {
            events: Arc::new(Mutex::new(Vec::new())),
            validation: DispatchHandoffValidationV1::Live,
            outcome: DispatchHandoffOutcomeV1::Acknowledged(7),
        };
        let outcome = handoff_exact_grant_once_v1(
            &transport,
            &[1; 32],
            b"exact-signed-grant",
            500,
            500,
            |_| panic!("expired authority must not persist handoff evidence"),
            || panic!("expired authority must not refresh after absent evidence"),
        );
        assert!(matches!(
            outcome,
            DispatchHandoffOutcomeV1::DeadlineReachedBeforeHandoff
        ));
        assert!(transport.events.lock().unwrap().is_empty());
    }

    #[test]
    fn evidence_commits_before_exact_external_handoff() {
        let transport = Transport {
            events: Arc::new(Mutex::new(Vec::new())),
            validation: DispatchHandoffValidationV1::Live,
            outcome: DispatchHandoffOutcomeV1::Acknowledged(7),
        };
        let outcome = handoff_exact_grant_once_v1(
            &transport,
            &[1; 32],
            b"exact-signed-grant",
            499,
            500,
            |binding| {
                assert_eq!(binding, [0x44; 32]);
                transport.events.lock().unwrap().push(StepV1::Persist);
                Ok(())
            },
            || {
                transport.events.lock().unwrap().push(StepV1::RefreshClock);
                Ok(499)
            },
        );
        assert!(matches!(outcome, DispatchHandoffOutcomeV1::Acknowledged(7)));
        assert_eq!(
            *transport.events.lock().unwrap(),
            vec![
                StepV1::Acquire,
                StepV1::Validate,
                StepV1::Persist,
                StepV1::RefreshClock,
                StepV1::Validate,
                StepV1::Deliver,
                StepV1::Release,
            ]
        );
    }

    #[test]
    fn post_evidence_no_send_claim_remains_possible_handoff() {
        let transport = Transport {
            events: Arc::new(Mutex::new(Vec::new())),
            validation: DispatchHandoffValidationV1::Live,
            outcome: DispatchHandoffOutcomeV1::ConfirmedNoSend,
        };
        let outcome = handoff_exact_grant_once_v1(
            &transport,
            &[1; 32],
            b"exact-signed-grant",
            10,
            20,
            |_| Ok(()),
            || Ok(10),
        );
        assert!(matches!(outcome, DispatchHandoffOutcomeV1::PossibleHandoff));
    }

    #[test]
    fn deadline_crossing_after_evidence_stops_before_transport_and_stays_possible() {
        let transport = Transport {
            events: Arc::new(Mutex::new(Vec::new())),
            validation: DispatchHandoffValidationV1::Live,
            outcome: DispatchHandoffOutcomeV1::Acknowledged(7),
        };
        let outcome = handoff_exact_grant_once_v1(
            &transport,
            &[1; 32],
            b"exact-signed-grant",
            499,
            500,
            |_| {
                transport.events.lock().unwrap().push(StepV1::Persist);
                Ok(())
            },
            || {
                transport.events.lock().unwrap().push(StepV1::RefreshClock);
                Ok(500)
            },
        );

        assert!(matches!(outcome, DispatchHandoffOutcomeV1::PossibleHandoff));
        assert_eq!(
            *transport.events.lock().unwrap(),
            vec![
                StepV1::Acquire,
                StepV1::Validate,
                StepV1::Persist,
                StepV1::RefreshClock,
                StepV1::Release,
            ]
        );
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn fb019_stops_after_validated_guard_without_persisting_evidence() {
        let transport = Transport {
            events: Arc::new(Mutex::new(Vec::new())),
            validation: DispatchHandoffValidationV1::Live,
            outcome: DispatchHandoffOutcomeV1::Acknowledged(7),
        };
        let probe = crate::DispatchFaultProbeV1::selected_v1(
            "PLAN005-FB-019",
            1,
            crate::FaultInjectionModeV1::InProcess,
            || {},
        )
        .unwrap();

        let outcome = handoff_exact_grant_once_with_fault_probe_v1(
            &transport,
            &[1; 32],
            b"exact-signed-grant",
            10,
            20,
            |_| panic!("FB019 precedes possible-handoff evidence"),
            || panic!("FB019 precedes the post-evidence clock sample"),
            &probe,
        );

        assert!(matches!(
            outcome,
            DispatchHandoffOutcomeV1::UnavailableBeforeHandoff
        ));
        assert!(probe.injected_v1());
        assert_eq!(
            *transport.events.lock().unwrap(),
            vec![StepV1::Acquire, StepV1::Validate, StepV1::Release]
        );
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn fb021_stops_immediately_before_transport_with_possible_handoff_custody() {
        let transport = Transport {
            events: Arc::new(Mutex::new(Vec::new())),
            validation: DispatchHandoffValidationV1::Live,
            outcome: DispatchHandoffOutcomeV1::Acknowledged(7),
        };
        let probe = crate::DispatchFaultProbeV1::selected_v1(
            "PLAN005-FB-021",
            1,
            crate::FaultInjectionModeV1::InProcess,
            || {},
        )
        .unwrap();

        let outcome = handoff_exact_grant_once_with_fault_probe_v1(
            &transport,
            &[1; 32],
            b"exact-signed-grant",
            10,
            20,
            |_| {
                transport.events.lock().unwrap().push(StepV1::Persist);
                Ok(())
            },
            || {
                transport.events.lock().unwrap().push(StepV1::RefreshClock);
                Ok(10)
            },
            &probe,
        );

        assert!(matches!(outcome, DispatchHandoffOutcomeV1::PossibleHandoff));
        assert!(probe.injected_v1());
        assert_eq!(
            *transport.events.lock().unwrap(),
            vec![
                StepV1::Acquire,
                StepV1::Validate,
                StepV1::Persist,
                StepV1::RefreshClock,
                StepV1::Validate,
                StepV1::Release,
            ]
        );
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn fb022_discards_the_transport_result_into_possible_handoff_custody() {
        let transport = Transport {
            events: Arc::new(Mutex::new(Vec::new())),
            validation: DispatchHandoffValidationV1::Live,
            outcome: DispatchHandoffOutcomeV1::Acknowledged(7),
        };
        let probe = crate::DispatchFaultProbeV1::selected_v1(
            "PLAN005-FB-022",
            1,
            crate::FaultInjectionModeV1::InProcess,
            || {},
        )
        .unwrap();

        let outcome = handoff_exact_grant_once_with_fault_probe_v1(
            &transport,
            &[1; 32],
            b"exact-signed-grant",
            10,
            20,
            |_| {
                transport.events.lock().unwrap().push(StepV1::Persist);
                Ok(())
            },
            || {
                transport.events.lock().unwrap().push(StepV1::RefreshClock);
                Ok(10)
            },
            &probe,
        );

        assert!(matches!(outcome, DispatchHandoffOutcomeV1::PossibleHandoff));
        assert!(probe.injected_v1());
        assert_eq!(
            *transport.events.lock().unwrap(),
            vec![
                StepV1::Acquire,
                StepV1::Validate,
                StepV1::Persist,
                StepV1::RefreshClock,
                StepV1::Validate,
                StepV1::Deliver,
                StepV1::Release,
            ]
        );
    }
}
