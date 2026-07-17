//! Closed, explicit, non-default PLAN-006 fault-selection carrier.
//!
//! The phase contract is frozen now; concrete transaction boundary instances are
//! derived later after operations stabilize. Selection is caller-owned and contains
//! no environment, argument, global process, or ambient fallback.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// Frozen PLAN-006 fault phases. Concrete boundary IDs are deliberately not invented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AuthorityFaultPhaseV1 {
    Contract,
    RootIssue,
    Delegation,
    Counter,
    Decision,
    TrustRevocation,
    ProjectionGuard,
    Bootstrap,
    Backup,
    Restore,
    CorruptionReadback,
}

impl AuthorityFaultPhaseV1 {
    const ALL: [Self; 11] = [
        Self::Contract,
        Self::RootIssue,
        Self::Delegation,
        Self::Counter,
        Self::Decision,
        Self::TrustRevocation,
        Self::ProjectionGuard,
        Self::Bootstrap,
        Self::Backup,
        Self::Restore,
        Self::CorruptionReadback,
    ];

    const fn id_v1(self) -> &'static str {
        match self {
            Self::Contract => "P00-CONTRACT",
            Self::RootIssue => "P01-ROOT-ISSUE",
            Self::Delegation => "P02-DELEGATION",
            Self::Counter => "P03-COUNTER",
            Self::Decision => "P04-DECISION",
            Self::TrustRevocation => "P05-TRUST-REVOCATION",
            Self::ProjectionGuard => "P06-PROJECTION-GUARD",
            Self::Bootstrap => "P07-BOOTSTRAP",
            Self::Backup => "P08-BACKUP",
            Self::Restore => "P09-RESTORE",
            Self::CorruptionReadback => "P10-CORRUPTION-READBACK",
        }
    }

    fn from_id_v1(id: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.id_v1() == id)
    }

    /// P00 and P10 have no durable publication boundary and therefore permit only
    /// the in-process model frozen by the fault registry.
    const fn supports_mode_v1(self, mode: AuthorityFaultModeV1) -> bool {
        match mode {
            AuthorityFaultModeV1::InProcess => true,
            AuthorityFaultModeV1::ProcessKill => {
                !matches!(self, Self::Contract | Self::CorruptionReadback)
            }
        }
    }
}

/// Explicit non-production fault model selected by a test driver.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityFaultModeV1 {
    InProcess,
    ProcessKill,
}

/// Closed decision produced at one selected phase checkpoint.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityFaultDecisionV1 {
    Continue,
    InjectInProcess,
    ProcessBarrierReached,
}

/// Payload-free selection failure.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityFaultSelectionErrorV1 {
    UnknownPhase,
    InvalidOccurrence,
    UnsupportedFaultModel,
    StateUnavailable,
}

impl AuthorityFaultSelectionErrorV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::UnknownPhase => "AUTHORITY_UNKNOWN_FAULT_PHASE",
            Self::InvalidOccurrence => "AUTHORITY_INVALID_FAULT_OCCURRENCE",
            Self::UnsupportedFaultModel => "AUTHORITY_UNSUPPORTED_FAULT_MODEL",
            Self::StateUnavailable => "AUTHORITY_FAULT_STATE_UNAVAILABLE",
        }
    }
}

impl fmt::Debug for AuthorityFaultSelectionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityFaultSelectionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl std::error::Error for AuthorityFaultSelectionErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthorityFaultSelectionV1 {
    phase: AuthorityFaultPhaseV1,
    occurrence: u64,
    mode: AuthorityFaultModeV1,
}

struct AuthorityFaultStateV1 {
    selection: Option<AuthorityFaultSelectionV1>,
    matching_occurrences: u64,
    injected: bool,
    process_barrier: Option<Box<dyn FnMut() + Send>>,
}

impl AuthorityFaultStateV1 {
    const fn disabled_v1() -> Self {
        Self {
            selection: None,
            matching_occurrences: 0,
            injected: false,
            process_barrier: None,
        }
    }

    fn reach_v1(
        &mut self,
        phase: AuthorityFaultPhaseV1,
    ) -> (AuthorityFaultDecisionV1, Option<Box<dyn FnMut() + Send>>) {
        let Some(selection) = self.selection else {
            return (AuthorityFaultDecisionV1::Continue, None);
        };
        if self.injected || selection.phase != phase {
            return (AuthorityFaultDecisionV1::Continue, None);
        }
        self.matching_occurrences = self.matching_occurrences.saturating_add(1);
        if self.matching_occurrences != selection.occurrence {
            return (AuthorityFaultDecisionV1::Continue, None);
        }
        self.injected = true;
        match selection.mode {
            AuthorityFaultModeV1::InProcess => (AuthorityFaultDecisionV1::InjectInProcess, None),
            AuthorityFaultModeV1::ProcessKill => (
                AuthorityFaultDecisionV1::ProcessBarrierReached,
                self.process_barrier.take(),
            ),
        }
    }
}

/// Opaque feature-only probe shared by deterministic in-process and child drivers.
#[doc(hidden)]
#[derive(Clone)]
pub struct AuthorityFaultProbeV1 {
    state: Arc<Mutex<AuthorityFaultStateV1>>,
}

impl AuthorityFaultProbeV1 {
    pub fn disabled_v1() -> Self {
        Self::default()
    }

    pub fn selected_phase_v1<F>(
        phase_id: &str,
        occurrence: u64,
        mode: AuthorityFaultModeV1,
        process_barrier: F,
    ) -> Result<Self, AuthorityFaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        let phase = AuthorityFaultPhaseV1::from_id_v1(phase_id)
            .ok_or(AuthorityFaultSelectionErrorV1::UnknownPhase)?;
        if occurrence == 0 {
            return Err(AuthorityFaultSelectionErrorV1::InvalidOccurrence);
        }
        if !phase.supports_mode_v1(mode) {
            return Err(AuthorityFaultSelectionErrorV1::UnsupportedFaultModel);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(AuthorityFaultStateV1 {
                selection: Some(AuthorityFaultSelectionV1 {
                    phase,
                    occurrence,
                    mode,
                }),
                matching_occurrences: 0,
                injected: false,
                process_barrier: match mode {
                    AuthorityFaultModeV1::InProcess => None,
                    AuthorityFaultModeV1::ProcessKill => Some(Box::new(process_barrier)),
                },
            })),
        })
    }

    pub fn reach_phase_id_v1(
        &self,
        phase_id: &str,
    ) -> Result<AuthorityFaultDecisionV1, AuthorityFaultSelectionErrorV1> {
        let phase = AuthorityFaultPhaseV1::from_id_v1(phase_id)
            .ok_or(AuthorityFaultSelectionErrorV1::UnknownPhase)?;
        let (decision, barrier) = lock_state_v1(&self.state)?.reach_v1(phase);
        if let Some(mut barrier) = barrier {
            barrier();
        }
        Ok(decision)
    }

    pub fn injected_v1(&self) -> Result<bool, AuthorityFaultSelectionErrorV1> {
        Ok(lock_state_v1(&self.state)?.injected)
    }
}

impl Default for AuthorityFaultProbeV1 {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(AuthorityFaultStateV1::disabled_v1())),
        }
    }
}

impl fmt::Debug for AuthorityFaultProbeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityFaultProbeV1(..)")
    }
}

fn lock_state_v1(
    state: &Mutex<AuthorityFaultStateV1>,
) -> Result<MutexGuard<'_, AuthorityFaultStateV1>, AuthorityFaultSelectionErrorV1> {
    state
        .lock()
        .map_err(|_| AuthorityFaultSelectionErrorV1::StateUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn phase_contract_is_closed_and_ordered() {
        assert_eq!(
            AuthorityFaultPhaseV1::ALL.map(AuthorityFaultPhaseV1::id_v1),
            [
                "P00-CONTRACT",
                "P01-ROOT-ISSUE",
                "P02-DELEGATION",
                "P03-COUNTER",
                "P04-DECISION",
                "P05-TRUST-REVOCATION",
                "P06-PROJECTION-GUARD",
                "P07-BOOTSTRAP",
                "P08-BACKUP",
                "P09-RESTORE",
                "P10-CORRUPTION-READBACK",
            ]
        );
    }

    #[test]
    fn phase_fault_models_match_the_frozen_registry() {
        for phase in AuthorityFaultPhaseV1::ALL {
            assert!(phase.supports_mode_v1(AuthorityFaultModeV1::InProcess));
            assert_eq!(
                phase.supports_mode_v1(AuthorityFaultModeV1::ProcessKill),
                !matches!(
                    phase,
                    AuthorityFaultPhaseV1::Contract | AuthorityFaultPhaseV1::CorruptionReadback
                ),
                "unexpected process-kill support for {}",
                phase.id_v1()
            );
        }
        for phase_id in ["P00-CONTRACT", "P10-CORRUPTION-READBACK"] {
            assert_eq!(
                AuthorityFaultProbeV1::selected_phase_v1(
                    phase_id,
                    1,
                    AuthorityFaultModeV1::ProcessKill,
                    || {},
                )
                .unwrap_err(),
                AuthorityFaultSelectionErrorV1::UnsupportedFaultModel
            );
        }
    }

    #[test]
    fn selection_is_explicit_one_shot_and_occurrence_bounded() {
        assert_eq!(
            AuthorityFaultProbeV1::selected_phase_v1(
                "P01-ROOT-ISSUE",
                0,
                AuthorityFaultModeV1::InProcess,
                || {},
            )
            .unwrap_err(),
            AuthorityFaultSelectionErrorV1::InvalidOccurrence
        );
        let probe = AuthorityFaultProbeV1::selected_phase_v1(
            "P01-ROOT-ISSUE",
            2,
            AuthorityFaultModeV1::InProcess,
            || {},
        )
        .expect("closed phase selects");
        assert_eq!(
            probe.reach_phase_id_v1("P01-ROOT-ISSUE"),
            Ok(AuthorityFaultDecisionV1::Continue)
        );
        assert_eq!(
            probe.reach_phase_id_v1("P01-ROOT-ISSUE"),
            Ok(AuthorityFaultDecisionV1::InjectInProcess)
        );
        assert_eq!(
            probe.reach_phase_id_v1("P01-ROOT-ISSUE"),
            Ok(AuthorityFaultDecisionV1::Continue)
        );
        assert_eq!(probe.injected_v1(), Ok(true));
    }

    #[test]
    fn process_barrier_is_callback_owned_and_default_is_inert() {
        let disabled = AuthorityFaultProbeV1::default();
        assert_eq!(
            disabled.reach_phase_id_v1("P09-RESTORE"),
            Ok(AuthorityFaultDecisionV1::Continue)
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let probe = AuthorityFaultProbeV1::selected_phase_v1(
            "P09-RESTORE",
            1,
            AuthorityFaultModeV1::ProcessKill,
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("process phase selects explicitly");
        assert_eq!(
            probe.reach_phase_id_v1("P09-RESTORE"),
            Ok(AuthorityFaultDecisionV1::ProcessBarrierReached)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn in_process_selection_never_invokes_the_process_barrier() {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let probe = AuthorityFaultProbeV1::selected_phase_v1(
            "P01-ROOT-ISSUE",
            1,
            AuthorityFaultModeV1::InProcess,
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("in-process phase selects");
        assert_eq!(
            probe.reach_phase_id_v1("P01-ROOT-ISSUE"),
            Ok(AuthorityFaultDecisionV1::InjectInProcess)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn concurrent_reach_is_exactly_one_shot() {
        const CONCURRENCY: usize = 16;
        let probe = AuthorityFaultProbeV1::selected_phase_v1(
            "P04-DECISION",
            1,
            AuthorityFaultModeV1::InProcess,
            || {},
        )
        .expect("decision phase selects");
        let barrier = Arc::new(Barrier::new(CONCURRENCY));
        let handles: Vec<_> = (0..CONCURRENCY)
            .map(|_| {
                let probe = probe.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    probe.reach_phase_id_v1("P04-DECISION")
                })
            })
            .collect();
        let injected = handles
            .into_iter()
            .map(|handle| handle.join().expect("fault worker does not panic"))
            .filter(|decision| *decision == Ok(AuthorityFaultDecisionV1::InjectInProcess))
            .count();
        assert_eq!(injected, 1);
        assert_eq!(probe.injected_v1(), Ok(true));
    }

    #[test]
    fn poisoned_state_fails_closed_instead_of_recovering() {
        let probe = AuthorityFaultProbeV1::disabled_v1();
        let state = Arc::clone(&probe.state);
        let _ = thread::spawn(move || {
            let _guard = state.lock().expect("state starts healthy");
            panic!("poison the feature-only probe state");
        })
        .join();

        assert_eq!(
            probe.reach_phase_id_v1("P01-ROOT-ISSUE"),
            Err(AuthorityFaultSelectionErrorV1::StateUnavailable)
        );
        assert_eq!(
            probe.injected_v1(),
            Err(AuthorityFaultSelectionErrorV1::StateUnavailable)
        );
        assert_eq!(format!("{probe:?}"), "AuthorityFaultProbeV1(..)");
    }
}
