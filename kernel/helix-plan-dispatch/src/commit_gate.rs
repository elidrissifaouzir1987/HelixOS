//! Linearizable supervisor-owned dispatch commit gate and one-shot permit.

#![allow(dead_code)]

use crate::guard::{
    DispatchCommitPermitOutcomeV1, DispatchCommitPermitV1, DispatchCommitResolutionV1,
    DispatchGuardValidationV1,
};
use crate::store::DispatchStoreCommitClassificationV1;
use crate::{DispatchAdmissionStateV1, DispatchAttemptIdV1};
use helix_dispatch_contracts::MAX_SAFE_U64;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) const DISPATCH_COMMIT_PERMIT_CEILING_MS_V1: u64 = 250;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchCommitGateErrorV1 {
    IntegerOutOfRange,
    DeadlineReached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PermitStateV1 {
    Idle,
    Permitted,
    CommitInFlight,
    Resolved,
    ResolvedAmbiguous,
}

struct SharedCommitGateV1 {
    admission: DispatchAdmissionStateV1,
    supervisor_generation: u64,
    permit_state: PermitStateV1,
    permit_serial: u64,
    permit_deadline_monotonic_ms: u64,
    permit_attempt_digest: [u8; 32],
    pause_activations: u64,
}

impl fmt::Debug for SharedCommitGateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedCommitGateV1")
            .finish_non_exhaustive()
    }
}

/// Supervisor-side gate. The handle may be cloned; permits may not.
pub(crate) struct LinearizableDispatchCommitGateV1 {
    shared: Arc<Mutex<SharedCommitGateV1>>,
}

impl LinearizableDispatchCommitGateV1 {
    pub(crate) fn try_new(supervisor_generation: u64) -> Result<Self, DispatchCommitGateErrorV1> {
        if supervisor_generation == 0 || supervisor_generation > MAX_SAFE_U64 {
            return Err(DispatchCommitGateErrorV1::IntegerOutOfRange);
        }
        Ok(Self {
            shared: Arc::new(Mutex::new(SharedCommitGateV1 {
                admission: DispatchAdmissionStateV1::Running,
                supervisor_generation,
                permit_state: PermitStateV1::Idle,
                permit_serial: 0,
                permit_deadline_monotonic_ms: 0,
                permit_attempt_digest: [0; 32],
                pause_activations: 0,
            })),
        })
    }

    pub(crate) fn control_handle_v1(&self) -> DispatchCommitGateControlV1 {
        DispatchCommitGateControlV1 {
            shared: Arc::clone(&self.shared),
        }
    }

    pub(crate) fn acquire_commit_permit_v1(
        &self,
        attempt: &DispatchAttemptIdV1,
        expected_supervisor_generation: u64,
        caller_or_grant_deadline_monotonic_ms: u64,
        permit_entry_monotonic_ms: u64,
    ) -> DispatchCommitPermitOutcomeV1<LinearizedDispatchCommitPermitV1> {
        let permit_deadline = match compute_dispatch_commit_permit_deadline_v1(
            caller_or_grant_deadline_monotonic_ms,
            permit_entry_monotonic_ms,
        ) {
            Ok(deadline) => deadline,
            Err(DispatchCommitGateErrorV1::DeadlineReached) => {
                return DispatchCommitPermitOutcomeV1::DeadlineReached;
            }
            Err(DispatchCommitGateErrorV1::IntegerOutOfRange) => {
                return DispatchCommitPermitOutcomeV1::Unsupported;
            }
        };
        let mut shared = lock_shared_v1(&self.shared);
        match shared.admission {
            DispatchAdmissionStateV1::Paused | DispatchAdmissionStateV1::Halted => {
                return DispatchCommitPermitOutcomeV1::Revoked;
            }
            DispatchAdmissionStateV1::Unavailable => {
                return DispatchCommitPermitOutcomeV1::Unavailable;
            }
            DispatchAdmissionStateV1::Running => {}
        }
        if shared.supervisor_generation != expected_supervisor_generation
            || shared.permit_state != PermitStateV1::Idle
        {
            return DispatchCommitPermitOutcomeV1::Revoked;
        }
        shared.permit_serial = match shared.permit_serial.checked_add(1) {
            Some(serial) if serial <= MAX_SAFE_U64 => serial,
            _ => return DispatchCommitPermitOutcomeV1::Unavailable,
        };
        shared.permit_state = PermitStateV1::Permitted;
        shared.permit_deadline_monotonic_ms = permit_deadline;
        shared.permit_attempt_digest = *attempt.as_bytes();
        let serial = shared.permit_serial;
        drop(shared);
        DispatchCommitPermitOutcomeV1::Permitted(LinearizedDispatchCommitPermitV1 {
            shared: Arc::clone(&self.shared),
            serial,
            armed: true,
        })
    }
}

impl fmt::Debug for LinearizableDispatchCommitGateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearizableDispatchCommitGateV1")
            .finish_non_exhaustive()
    }
}

/// Cloneable control/deadman custody retained by the supervisor, never by the permit owner.
#[derive(Clone)]
pub(crate) struct DispatchCommitGateControlV1 {
    shared: Arc<Mutex<SharedCommitGateV1>>,
}

impl DispatchCommitGateControlV1 {
    pub(crate) fn admission_state_v1(&self) -> DispatchAdmissionStateV1 {
        lock_shared_v1(&self.shared).admission
    }

    pub(crate) fn request_pause_v1(&self) {
        let mut shared = lock_shared_v1(&self.shared);
        if shared.admission != DispatchAdmissionStateV1::Paused {
            shared.pause_activations = shared.pause_activations.saturating_add(1);
        }
        shared.admission = DispatchAdmissionStateV1::Paused;
        revoke_or_ambiguate_v1(&mut shared);
    }

    pub(crate) fn request_halt_v1(&self) {
        let mut shared = lock_shared_v1(&self.shared);
        shared.admission = DispatchAdmissionStateV1::Halted;
        revoke_or_ambiguate_v1(&mut shared);
    }

    pub(crate) fn mark_unavailable_v1(&self) {
        let mut shared = lock_shared_v1(&self.shared);
        shared.admission = DispatchAdmissionStateV1::Unavailable;
        revoke_or_ambiguate_v1(&mut shared);
    }

    pub(crate) fn owner_lost_v1(&self) -> bool {
        let mut shared = lock_shared_v1(&self.shared);
        resolve_ambiguous_and_activate_pause_v1(&mut shared)
    }

    pub(crate) fn expire_if_due_v1(&self, now_monotonic_ms: u64) -> bool {
        let mut shared = lock_shared_v1(&self.shared);
        if !matches!(
            shared.permit_state,
            PermitStateV1::Permitted | PermitStateV1::CommitInFlight
        ) || now_monotonic_ms < shared.permit_deadline_monotonic_ms
        {
            return false;
        }
        resolve_ambiguous_and_activate_pause_v1(&mut shared)
    }

    #[cfg(test)]
    fn pause_activations_test_only(&self) -> u64 {
        lock_shared_v1(&self.shared).pause_activations
    }

    #[cfg(test)]
    fn permit_state_test_only(&self) -> PermitStateV1 {
        lock_shared_v1(&self.shared).permit_state
    }
}

impl fmt::Debug for DispatchCommitGateControlV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchCommitGateControlV1")
            .finish_non_exhaustive()
    }
}

/// Fresh consuming permit. It intentionally implements neither `Clone` nor Serde.
pub(crate) struct LinearizedDispatchCommitPermitV1 {
    shared: Arc<Mutex<SharedCommitGateV1>>,
    serial: u64,
    armed: bool,
}

impl LinearizedDispatchCommitPermitV1 {
    fn is_current_v1(&self, shared: &SharedCommitGateV1) -> bool {
        shared.permit_serial == self.serial
    }
}

impl DispatchCommitPermitV1 for LinearizedDispatchCommitPermitV1 {
    fn deadline_monotonic_ms(&self) -> u64 {
        let shared = lock_shared_v1(&self.shared);
        if self.is_current_v1(&shared) {
            shared.permit_deadline_monotonic_ms
        } else {
            0
        }
    }

    fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
        let mut shared = lock_shared_v1(&self.shared);
        if !self.is_current_v1(&shared) {
            return DispatchGuardValidationV1::Revoked;
        }
        match shared.admission {
            DispatchAdmissionStateV1::Paused | DispatchAdmissionStateV1::Halted => {
                return DispatchGuardValidationV1::Revoked;
            }
            DispatchAdmissionStateV1::Unavailable => {
                return DispatchGuardValidationV1::Unavailable;
            }
            DispatchAdmissionStateV1::Running => {}
        }
        if now_monotonic_ms >= shared.permit_deadline_monotonic_ms {
            resolve_ambiguous_and_activate_pause_v1(&mut shared);
            return DispatchGuardValidationV1::DeadlineReached;
        }
        if shared.permit_state != PermitStateV1::Permitted {
            return DispatchGuardValidationV1::Revoked;
        }
        DispatchGuardValidationV1::Valid
    }

    fn commit_once<C, U, F>(mut self, commit: F) -> DispatchCommitResolutionV1<C, U>
    where
        C: Send,
        U: Send,
        F: FnOnce() -> DispatchStoreCommitClassificationV1<C, U>,
    {
        {
            let mut shared = lock_shared_v1(&self.shared);
            if !self.is_current_v1(&shared) {
                self.armed = false;
                return DispatchCommitResolutionV1::Revoked;
            }
            match shared.permit_state {
                PermitStateV1::ResolvedAmbiguous => {
                    self.armed = false;
                    return DispatchCommitResolutionV1::Ambiguous;
                }
                PermitStateV1::Permitted => {}
                PermitStateV1::Idle | PermitStateV1::CommitInFlight | PermitStateV1::Resolved => {
                    self.armed = false;
                    return DispatchCommitResolutionV1::Revoked;
                }
            }
            match shared.admission {
                DispatchAdmissionStateV1::Running => {
                    shared.permit_state = PermitStateV1::CommitInFlight;
                }
                DispatchAdmissionStateV1::Paused | DispatchAdmissionStateV1::Halted => {
                    shared.permit_state = PermitStateV1::Resolved;
                    self.armed = false;
                    return DispatchCommitResolutionV1::Revoked;
                }
                DispatchAdmissionStateV1::Unavailable => {
                    shared.permit_state = PermitStateV1::Resolved;
                    self.armed = false;
                    return DispatchCommitResolutionV1::Unavailable;
                }
            }
        }

        let classification = commit();
        let mut shared = lock_shared_v1(&self.shared);
        self.armed = false;
        if !self.is_current_v1(&shared) || shared.permit_state == PermitStateV1::ResolvedAmbiguous {
            return DispatchCommitResolutionV1::Ambiguous;
        }
        if shared.permit_state != PermitStateV1::CommitInFlight {
            return DispatchCommitResolutionV1::Unclassified;
        }
        shared.permit_state = PermitStateV1::Resolved;
        match classification {
            DispatchStoreCommitClassificationV1::Committed(receipt) => {
                DispatchCommitResolutionV1::Committed(receipt)
            }
            DispatchStoreCommitClassificationV1::PriorExactDispatch(receipt) => {
                DispatchCommitResolutionV1::PriorExactDispatch(receipt)
            }
            DispatchStoreCommitClassificationV1::ConfirmedRollback => {
                DispatchCommitResolutionV1::ConfirmedRollback
            }
            DispatchStoreCommitClassificationV1::Uncertain(custody) => {
                DispatchCommitResolutionV1::Uncertain(custody)
            }
            DispatchStoreCommitClassificationV1::Conflict => DispatchCommitResolutionV1::Conflict,
            DispatchStoreCommitClassificationV1::Unavailable => {
                DispatchCommitResolutionV1::Unavailable
            }
            DispatchStoreCommitClassificationV1::Unhealthy
            | DispatchStoreCommitClassificationV1::Unclassified => {
                DispatchCommitResolutionV1::Unclassified
            }
        }
    }

    fn abandon_v1(mut self) {
        let mut shared = lock_shared_v1(&self.shared);
        if self.is_current_v1(&shared) && shared.permit_state == PermitStateV1::Permitted {
            shared.permit_state = PermitStateV1::Resolved;
        }
        self.armed = false;
    }
}

impl Drop for LinearizedDispatchCommitPermitV1 {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut shared = lock_shared_v1(&self.shared);
        if self.is_current_v1(&shared) {
            resolve_ambiguous_and_activate_pause_v1(&mut shared);
        }
        self.armed = false;
    }
}

impl fmt::Debug for LinearizedDispatchCommitPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearizedDispatchCommitPermitV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn compute_dispatch_commit_permit_deadline_v1(
    caller_or_grant_deadline_monotonic_ms: u64,
    permit_entry_monotonic_ms: u64,
) -> Result<u64, DispatchCommitGateErrorV1> {
    if caller_or_grant_deadline_monotonic_ms == 0
        || caller_or_grant_deadline_monotonic_ms > MAX_SAFE_U64
        || permit_entry_monotonic_ms > MAX_SAFE_U64
    {
        return Err(DispatchCommitGateErrorV1::IntegerOutOfRange);
    }
    let ceiling = permit_entry_monotonic_ms
        .checked_add(DISPATCH_COMMIT_PERMIT_CEILING_MS_V1)
        .unwrap_or(MAX_SAFE_U64)
        .min(MAX_SAFE_U64);
    let deadline = caller_or_grant_deadline_monotonic_ms.min(ceiling);
    if permit_entry_monotonic_ms >= deadline {
        return Err(DispatchCommitGateErrorV1::DeadlineReached);
    }
    Ok(deadline)
}

fn revoke_or_ambiguate_v1(shared: &mut SharedCommitGateV1) {
    match shared.permit_state {
        PermitStateV1::CommitInFlight => {
            shared.permit_state = PermitStateV1::ResolvedAmbiguous;
        }
        PermitStateV1::Permitted => shared.permit_state = PermitStateV1::Resolved,
        PermitStateV1::Idle | PermitStateV1::Resolved | PermitStateV1::ResolvedAmbiguous => {}
    }
}

fn resolve_ambiguous_and_activate_pause_v1(shared: &mut SharedCommitGateV1) -> bool {
    if !matches!(
        shared.permit_state,
        PermitStateV1::Permitted | PermitStateV1::CommitInFlight
    ) {
        return false;
    }
    shared.permit_state = PermitStateV1::ResolvedAmbiguous;
    if shared.admission != DispatchAdmissionStateV1::Paused {
        shared.pause_activations = shared.pause_activations.saturating_add(1);
    }
    shared.admission = DispatchAdmissionStateV1::Paused;
    true
}

fn lock_shared_v1(shared: &Arc<Mutex<SharedCommitGateV1>>) -> MutexGuard<'_, SharedCommitGateV1> {
    shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{
        DispatchEntropyDomainV1, DispatchEntropyErrorV1, DispatchEntropySourceV1,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;

    struct FixedEntropy;

    impl DispatchEntropySourceV1 for FixedEntropy {
        fn fill_entropy_v1(
            &self,
            domain: DispatchEntropyDomainV1,
            destination: &mut [u8],
        ) -> Result<(), DispatchEntropyErrorV1> {
            assert_eq!(domain, DispatchEntropyDomainV1::AttemptIdentity);
            destination.fill(7);
            Ok(())
        }
    }

    fn attempt() -> DispatchAttemptIdV1 {
        DispatchAttemptIdV1::generate(&FixedEntropy).unwrap()
    }

    fn permit(gate: &LinearizableDispatchCommitGateV1) -> LinearizedDispatchCommitPermitV1 {
        match gate.acquire_commit_permit_v1(&attempt(), 1, 1_000, 100) {
            DispatchCommitPermitOutcomeV1::Permitted(permit) => permit,
            other => panic!("unexpected permit outcome: {other:?}"),
        }
    }

    #[test]
    fn equality_and_owner_loss_pause_once_before_or_during_commit() {
        for owner_loss in [false, true] {
            let gate = LinearizableDispatchCommitGateV1::try_new(1).unwrap();
            let control = gate.control_handle_v1();
            let mut permit = permit(&gate);
            if owner_loss {
                assert!(control.owner_lost_v1());
            } else {
                assert_eq!(
                    permit.validate_at_v1(350),
                    DispatchGuardValidationV1::DeadlineReached
                );
            }
            let calls = AtomicUsize::new(0);
            assert!(matches!(
                permit.commit_once(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    DispatchStoreCommitClassificationV1::<(), ()>::Committed(())
                }),
                DispatchCommitResolutionV1::Ambiguous
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(control.pause_activations_test_only(), 1);
        }

        let gate = LinearizableDispatchCommitGateV1::try_new(1).unwrap();
        let control = gate.control_handle_v1();
        let permit = permit(&gate);
        let resolution = permit.commit_once(|| {
            assert!(control.owner_lost_v1());
            DispatchStoreCommitClassificationV1::<(), ()>::Committed(())
        });
        assert!(matches!(resolution, DispatchCommitResolutionV1::Ambiguous));
        assert_eq!(control.pause_activations_test_only(), 1);
    }

    #[test]
    fn pause_and_halt_before_permit_or_during_commit_are_linearized() {
        for halted in [false, true] {
            let gate = LinearizableDispatchCommitGateV1::try_new(1).unwrap();
            let control = gate.control_handle_v1();
            if halted {
                control.request_halt_v1();
            } else {
                control.request_pause_v1();
            }
            assert!(matches!(
                gate.acquire_commit_permit_v1(&attempt(), 1, 1_000, 100),
                DispatchCommitPermitOutcomeV1::Revoked
            ));
        }

        for halted in [false, true] {
            let gate = LinearizableDispatchCommitGateV1::try_new(1).unwrap();
            let control = gate.control_handle_v1();
            let permit = permit(&gate);
            let calls = AtomicUsize::new(0);
            let resolution = permit.commit_once(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                if halted {
                    control.request_halt_v1();
                } else {
                    control.request_pause_v1();
                }
                DispatchStoreCommitClassificationV1::<(), ()>::Committed(())
            });
            assert!(matches!(resolution, DispatchCommitResolutionV1::Ambiguous));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                control.admission_state_v1(),
                if halted {
                    DispatchAdmissionStateV1::Halted
                } else {
                    DispatchAdmissionStateV1::Paused
                }
            );
        }
    }

    #[test]
    fn dropped_owner_activates_pause_but_explicit_abandon_does_not() {
        let gate = LinearizableDispatchCommitGateV1::try_new(1).unwrap();
        let control = gate.control_handle_v1();
        drop(permit(&gate));
        assert_eq!(
            control.permit_state_test_only(),
            PermitStateV1::ResolvedAmbiguous
        );
        assert_eq!(
            control.admission_state_v1(),
            DispatchAdmissionStateV1::Paused
        );

        let gate = LinearizableDispatchCommitGateV1::try_new(1).unwrap();
        let control = gate.control_handle_v1();
        permit(&gate).abandon_v1();
        assert_eq!(control.permit_state_test_only(), PermitStateV1::Resolved);
        assert_eq!(control.pause_activations_test_only(), 0);
    }

    #[test]
    fn concurrent_owner_loss_linearizes_against_commit_in_flight_once() {
        let gate = LinearizableDispatchCommitGateV1::try_new(1).unwrap();
        let control = gate.control_handle_v1();
        let permit = permit(&gate);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            permit.commit_once(|| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                DispatchStoreCommitClassificationV1::<(), ()>::Committed(())
            })
        });

        entered_rx.recv().unwrap();
        assert!(control.owner_lost_v1());
        assert!(!control.owner_lost_v1());
        resume_tx.send(()).unwrap();
        assert!(matches!(
            worker.join().unwrap(),
            DispatchCommitResolutionV1::Ambiguous
        ));
        assert_eq!(control.pause_activations_test_only(), 1);
    }

    #[test]
    fn permit_deadline_is_earlier_of_caller_and_250ms_ceiling() {
        assert_eq!(
            compute_dispatch_commit_permit_deadline_v1(200, 100),
            Ok(200)
        );
        assert_eq!(
            compute_dispatch_commit_permit_deadline_v1(1_000, 100),
            Ok(350)
        );
        assert_eq!(
            compute_dispatch_commit_permit_deadline_v1(100, 100),
            Err(DispatchCommitGateErrorV1::DeadlineReached)
        );
    }
}
