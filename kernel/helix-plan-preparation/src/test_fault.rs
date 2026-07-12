//! Private non-default fault-injection plumbing.
//!
//! This module owns the 37 portable orchestration/authority points in the closed v1
//! taxonomy. The coordinator module owns the remaining 86 provider/storage points.
//! Selection is explicit and caller-owned; production call sites use a disabled probe.

// T027 deliberately lands the closed seam before later tasks add every call site.
#![allow(dead_code)]

use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) const CLOSED_FAULT_BOUNDARY_COUNT_V1: usize = 123;

macro_rules! closed_fault_boundaries_v1 {
    ($ids:ident; $($variant:ident => $id:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum FaultBoundaryV1 {
            $($variant),+
        }

        impl FaultBoundaryV1 {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub(crate) const fn id(self) -> &'static str {
                match self {
                    $(Self::$variant => $id),+
                }
            }
        }

        pub(crate) const $ids: &[&str] = &[$($id),+];
    };
}

closed_fault_boundaries_v1!(PORTABLE_BOUNDARY_IDS_V1;
    PreliminaryAttemptIdentityGenerated => "preliminary_attempt_identity_generated",
    PreliminaryContextReturned => "preliminary_context_returned",
    PreliminaryFirstFailureGroupClassified => "preliminary_first_failure_group_classified",
    PreliminaryReplaySnapshotOpened => "preliminary_replay_snapshot_opened",
    PreliminaryReplaySnapshotClassified => "preliminary_replay_snapshot_classified",
    PreliminaryPreflightSnapshotOpened => "preliminary_preflight_snapshot_opened",
    PreliminaryOperationIdentityClassified => "preliminary_operation_identity_classified",
    PreliminaryBudgetBindingClassified => "preliminary_budget_binding_classified",
    PreliminaryBudgetArithmeticClassified => "preliminary_budget_arithmetic_classified",
    PreliminaryBudgetCapacityClassified => "preliminary_budget_capacity_classified",
    FinalComparisonGuardAcquired => "final_comparison_guard_acquired",
    FinalComparisonContextReturned => "final_comparison_context_returned",
    FinalComparisonFirstFailureGroupClassified => "final_comparison_first_failure_group_classified",
    FinalComparisonReplaySnapshotOpened => "final_comparison_replay_snapshot_opened",
    FinalComparisonReplaySnapshotClassified => "final_comparison_replay_snapshot_classified",
    FinalComparisonPreflightSnapshotOpened => "final_comparison_preflight_snapshot_opened",
    FinalComparisonOperationIdentityClassified => "final_comparison_operation_identity_classified",
    FinalComparisonBudgetBindingClassified => "final_comparison_budget_binding_classified",
    FinalComparisonBudgetArithmeticClassified => "final_comparison_budget_arithmetic_classified",
    FinalComparisonBudgetCapacityClassified => "final_comparison_budget_capacity_classified",
    FinalComparisonRecoveryReceiptReopened => "final_comparison_recovery_receipt_reopened",
    FinalComparisonRecoveryReceiptRevalidated => "final_comparison_recovery_receipt_revalidated",
    FinalComparisonUtcSampleReturned => "final_comparison_utc_sample_returned",
    FinalComparisonMonotonicSampleReturned => "final_comparison_monotonic_sample_returned",
    PositiveCoordinatorCommitEnterCommitPermitReturned => "positive_coordinator_commit_enter_commit_permit_returned",
    PositiveCoordinatorCommitPermitMovedToCommitInFlight => "positive_coordinator_commit_permit_moved_to_commit_in_flight",
    PositiveCoordinatorCommitPermitResolvedCommitted => "positive_coordinator_commit_permit_resolved_committed",
    PositiveCoordinatorCommitPermitResolvedAborted => "positive_coordinator_commit_permit_resolved_aborted",
    PositiveCoordinatorCommitPermitResolvedAmbiguous => "positive_coordinator_commit_permit_resolved_ambiguous",
    AcknowledgementPostCommitTimeClassified => "acknowledgement_post_commit_time_classified",
    AcknowledgementPostCommitGuardsClassified => "acknowledgement_post_commit_guards_classified",
    AcknowledgementPositiveMarkerConstructed => "acknowledgement_positive_marker_constructed",
    AcknowledgementResultReturned => "acknowledgement_result_returned",
    AcknowledgementAllFinalGuardsReleased => "acknowledgement_all_final_guards_released",
    KnownFailureNoDispatchGuardAcquired => "known_failure_no_dispatch_guard_acquired",
    KnownFailureNoDispatchGuardFinallyRevalidated => "known_failure_no_dispatch_guard_finally_revalidated",
    KnownFailureNoDispatchGuardReleased => "known_failure_no_dispatch_guard_released",
);

/// Closed action selected by a caller-owned fault-injection session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultEffectV1 {
    ReturnError,
    ProcessBarrier,
}

impl FaultEffectV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ReturnError => "RETURN_ERROR",
            Self::ProcessBarrier => "PROCESS_BARRIER",
        }
    }
}

impl std::fmt::Debug for FaultEffectV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Payload-free validation failure for an explicit fault selection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultSelectionErrorV1 {
    UnknownBoundary,
    InvalidOccurrence,
}

impl FaultSelectionErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::UnknownBoundary => "UNKNOWN_FAULT_BOUNDARY",
            Self::InvalidOccurrence => "INVALID_FAULT_OCCURRENCE",
        }
    }
}

impl std::fmt::Debug for FaultSelectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::fmt::Display for FaultSelectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FaultSelectionErrorV1 {}

/// Payload-free validation failure exposed by the feature-only process probe facade.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FaultProbeSelectionErrorV1 {
    UnknownBoundary,
    InvalidOccurrence,
}

impl FaultProbeSelectionErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownBoundary => "UNKNOWN_FAULT_BOUNDARY",
            Self::InvalidOccurrence => "INVALID_FAULT_OCCURRENCE",
        }
    }
}

impl std::fmt::Debug for FaultProbeSelectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::fmt::Display for FaultProbeSelectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FaultProbeSelectionErrorV1 {}

impl From<FaultSelectionErrorV1> for FaultProbeSelectionErrorV1 {
    fn from(error: FaultSelectionErrorV1) -> Self {
        match error {
            FaultSelectionErrorV1::UnknownBoundary => Self::UnknownBoundary,
            FaultSelectionErrorV1::InvalidOccurrence => Self::InvalidOccurrence,
        }
    }
}

/// One exact, caller-supplied boundary occurrence to inject at most once.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FaultSelectionV1 {
    boundary: FaultBoundaryV1,
    occurrence: u64,
    effect: FaultEffectV1,
}

impl FaultSelectionV1 {
    pub(crate) const fn try_new(
        boundary: FaultBoundaryV1,
        occurrence: u64,
        effect: FaultEffectV1,
    ) -> Result<Self, FaultSelectionErrorV1> {
        if occurrence == 0 {
            return Err(FaultSelectionErrorV1::InvalidOccurrence);
        }
        Ok(Self {
            boundary,
            occurrence,
            effect,
        })
    }
}

impl std::fmt::Debug for FaultSelectionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FaultSelectionV1")
            .field("boundary", &self.boundary.id())
            .field("occurrence", &self.occurrence)
            .field("effect", &self.effect)
            .finish()
    }
}

/// Decision returned by an explicit session checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultDecisionV1 {
    Continue,
    Inject(FaultEffectV1),
}

/// Mutable occurrence counter owned by one test operation or child-process probe.
///
/// There is deliberately no ambient selector or shared registry. A production call
/// path can only inject after a test-only caller explicitly carries this session to a
/// checkpoint.
pub(crate) struct FaultSessionV1 {
    selection: Option<FaultSelectionV1>,
    matching_occurrences: u64,
    injected: bool,
}

impl FaultSessionV1 {
    pub(crate) const fn disabled_v1() -> Self {
        Self {
            selection: None,
            matching_occurrences: 0,
            injected: false,
        }
    }

    pub(crate) const fn selected_v1(selection: FaultSelectionV1) -> Self {
        Self {
            selection: Some(selection),
            matching_occurrences: 0,
            injected: false,
        }
    }

    pub(crate) fn checkpoint_v1(&mut self, boundary: FaultBoundaryV1) -> FaultDecisionV1 {
        let Some(selection) = self.selection else {
            return FaultDecisionV1::Continue;
        };
        if self.injected || boundary != selection.boundary {
            return FaultDecisionV1::Continue;
        }

        self.matching_occurrences = self.matching_occurrences.saturating_add(1);
        if self.matching_occurrences == selection.occurrence {
            self.injected = true;
            FaultDecisionV1::Inject(selection.effect)
        } else {
            FaultDecisionV1::Continue
        }
    }
}

impl Default for FaultSessionV1 {
    fn default() -> Self {
        Self::disabled_v1()
    }
}

impl std::fmt::Debug for FaultSessionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FaultSessionV1")
            .field("enabled", &self.selection.is_some())
            .field("injected", &self.injected)
            .finish_non_exhaustive()
    }
}

/// Feature-only callback reached by the real child-process action at one selected
/// boundary occurrence.
///
/// The portable probe never assumes how the callback coordinates with its parent. A
/// process driver normally publishes its exact marker here and blocks until the parent
/// terminates the child.
#[doc(hidden)]
pub trait ProcessBarrierV1: Send + Sync {
    fn reached_v1(&self);
}

impl<F> ProcessBarrierV1 for F
where
    F: Fn() + Send + Sync,
{
    fn reached_v1(&self) {
        self();
    }
}

struct FaultProbeStateV1 {
    session: FaultSessionV1,
    process_barrier: Option<Arc<dyn ProcessBarrierV1>>,
}

/// Explicit caller-owned probe for the non-default process-kill harness.
///
/// Clones share one occurrence counter and one at-most-once selection. The callback is
/// cloned while the counter is locked and is always invoked after that lock is dropped,
/// so a blocking child-process barrier cannot retain the probe mutex.
#[doc(hidden)]
#[derive(Clone)]
pub struct FaultProbeV1 {
    state: Arc<Mutex<FaultProbeStateV1>>,
}

impl FaultProbeV1 {
    pub(crate) fn disabled_v1() -> Self {
        Self {
            state: Arc::new(Mutex::new(FaultProbeStateV1 {
                session: FaultSessionV1::disabled_v1(),
                process_barrier: None,
            })),
        }
    }

    /// Selects one exact frozen boundary occurrence for a process barrier.
    ///
    /// Boundary IDs are accepted as strings so the closed private taxonomy does not
    /// become a public authority surface.
    pub fn selected_process_barrier_v1<P>(
        boundary_id: &str,
        occurrence: u64,
        process_barrier: P,
    ) -> Result<Self, FaultProbeSelectionErrorV1>
    where
        P: ProcessBarrierV1 + 'static,
    {
        let boundary = FaultBoundaryV1::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.id() == boundary_id)
            .ok_or(FaultProbeSelectionErrorV1::UnknownBoundary)?;
        let selection =
            FaultSelectionV1::try_new(boundary, occurrence, FaultEffectV1::ProcessBarrier)?;
        Ok(Self {
            state: Arc::new(Mutex::new(FaultProbeStateV1 {
                session: FaultSessionV1::selected_v1(selection),
                process_barrier: Some(Arc::new(process_barrier)),
            })),
        })
    }

    pub(crate) fn reach_v1(&self, boundary: FaultBoundaryV1) {
        let process_barrier = {
            let mut state = lock_probe_state_v1(&self.state);
            match state.session.checkpoint_v1(boundary) {
                FaultDecisionV1::Continue | FaultDecisionV1::Inject(FaultEffectV1::ReturnError) => {
                    None
                }
                FaultDecisionV1::Inject(FaultEffectV1::ProcessBarrier) => {
                    state.process_barrier.clone()
                }
            }
        };
        if let Some(process_barrier) = process_barrier {
            process_barrier.reached_v1();
        }
    }
}

impl Default for FaultProbeV1 {
    fn default() -> Self {
        Self::disabled_v1()
    }
}

impl std::fmt::Debug for FaultProbeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = lock_probe_state_v1(&self.state);
        formatter
            .debug_struct("FaultProbeV1")
            .field("enabled", &state.session.selection.is_some())
            .field("injected", &state.session.injected)
            .finish_non_exhaustive()
    }
}

fn lock_probe_state_v1(state: &Mutex<FaultProbeStateV1>) -> MutexGuard<'_, FaultProbeStateV1> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Reaches one portable v1 boundary through an explicit disabled session.
///
/// Selected sessions are carried by dedicated test operations and process probes; an
/// ordinary production call site cannot acquire injection authority implicitly.
#[inline]
pub(crate) fn reach(boundary: FaultBoundaryV1) {
    FaultProbeV1::disabled_v1().reach_v1(boundary);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Weak;

    const EXPECTED_PORTABLE_BOUNDARY_IDS_V1: [&str; 37] = [
        "preliminary_attempt_identity_generated",
        "preliminary_context_returned",
        "preliminary_first_failure_group_classified",
        "preliminary_replay_snapshot_opened",
        "preliminary_replay_snapshot_classified",
        "preliminary_preflight_snapshot_opened",
        "preliminary_operation_identity_classified",
        "preliminary_budget_binding_classified",
        "preliminary_budget_arithmetic_classified",
        "preliminary_budget_capacity_classified",
        "final_comparison_guard_acquired",
        "final_comparison_context_returned",
        "final_comparison_first_failure_group_classified",
        "final_comparison_replay_snapshot_opened",
        "final_comparison_replay_snapshot_classified",
        "final_comparison_preflight_snapshot_opened",
        "final_comparison_operation_identity_classified",
        "final_comparison_budget_binding_classified",
        "final_comparison_budget_arithmetic_classified",
        "final_comparison_budget_capacity_classified",
        "final_comparison_recovery_receipt_reopened",
        "final_comparison_recovery_receipt_revalidated",
        "final_comparison_utc_sample_returned",
        "final_comparison_monotonic_sample_returned",
        "positive_coordinator_commit_enter_commit_permit_returned",
        "positive_coordinator_commit_permit_moved_to_commit_in_flight",
        "positive_coordinator_commit_permit_resolved_committed",
        "positive_coordinator_commit_permit_resolved_aborted",
        "positive_coordinator_commit_permit_resolved_ambiguous",
        "acknowledgement_post_commit_time_classified",
        "acknowledgement_post_commit_guards_classified",
        "acknowledgement_positive_marker_constructed",
        "acknowledgement_result_returned",
        "acknowledgement_all_final_guards_released",
        "known_failure_no_dispatch_guard_acquired",
        "known_failure_no_dispatch_guard_finally_revalidated",
        "known_failure_no_dispatch_guard_released",
    ];

    #[test]
    fn portable_taxonomy_is_exact_unique_and_disabled_by_default() {
        let actual = FaultBoundaryV1::ALL
            .iter()
            .map(|boundary| boundary.id())
            .collect::<Vec<_>>();
        assert_eq!(actual, EXPECTED_PORTABLE_BOUNDARY_IDS_V1);
        assert_eq!(PORTABLE_BOUNDARY_IDS_V1, EXPECTED_PORTABLE_BOUNDARY_IDS_V1);
        assert_eq!(CLOSED_FAULT_BOUNDARY_COUNT_V1, 123);
        assert_eq!(PORTABLE_BOUNDARY_IDS_V1.len(), FaultBoundaryV1::ALL.len());
        assert_eq!(
            actual.iter().copied().collect::<BTreeSet<_>>().len(),
            actual.len()
        );
        for boundary in FaultBoundaryV1::ALL {
            reach(*boundary);
        }
    }

    #[test]
    fn disabled_session_never_injects_any_closed_boundary() {
        let mut session = FaultSessionV1::disabled_v1();
        for boundary in FaultBoundaryV1::ALL {
            assert_eq!(session.checkpoint_v1(*boundary), FaultDecisionV1::Continue);
        }
        assert_eq!(
            format!("{session:?}"),
            "FaultSessionV1 { enabled: false, injected: false, .. }"
        );
    }

    #[test]
    fn selected_session_injects_only_the_exact_matching_occurrence_once() {
        let selected = FaultSelectionV1::try_new(
            FaultBoundaryV1::FinalComparisonContextReturned,
            2,
            FaultEffectV1::ProcessBarrier,
        )
        .expect("nonzero occurrence selects");
        let mut session = FaultSessionV1::selected_v1(selected);

        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::PreliminaryContextReturned),
            FaultDecisionV1::Continue,
            "unrelated boundaries do not consume the selected occurrence"
        );
        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::FinalComparisonContextReturned),
            FaultDecisionV1::Continue
        );
        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::FinalComparisonContextReturned),
            FaultDecisionV1::Inject(FaultEffectV1::ProcessBarrier)
        );
        assert_eq!(
            session.checkpoint_v1(FaultBoundaryV1::FinalComparisonContextReturned),
            FaultDecisionV1::Continue,
            "one selection injects at most once"
        );
        assert_eq!(
            format!("{session:?}"),
            "FaultSessionV1 { enabled: true, injected: true, .. }"
        );
    }

    #[test]
    fn selection_rejects_zero_and_debug_exposes_only_frozen_metadata() {
        assert_eq!(
            FaultSelectionV1::try_new(
                FaultBoundaryV1::AcknowledgementResultReturned,
                0,
                FaultEffectV1::ReturnError,
            ),
            Err(FaultSelectionErrorV1::InvalidOccurrence)
        );
        assert_eq!(
            format!("{:?}", FaultSelectionErrorV1::InvalidOccurrence),
            "INVALID_FAULT_OCCURRENCE"
        );

        let selection = FaultSelectionV1::try_new(
            FaultBoundaryV1::AcknowledgementResultReturned,
            3,
            FaultEffectV1::ReturnError,
        )
        .expect("nonzero occurrence selects");
        assert_eq!(
            format!("{selection:?}"),
            "FaultSelectionV1 { boundary: \"acknowledgement_result_returned\", occurrence: 3, effect: RETURN_ERROR }"
        );
    }

    #[test]
    fn cloned_probe_shares_occurrences_and_calls_process_barrier_outside_its_mutex() {
        fn assert_probe_traits<T: Clone + Send + Sync>() {}
        assert_probe_traits::<FaultProbeV1>();

        let state_reference = Arc::new(Mutex::new(None::<Weak<Mutex<FaultProbeStateV1>>>));
        let callback_state_reference = Arc::clone(&state_reference);
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let probe = FaultProbeV1::selected_process_barrier_v1(
            "final_comparison_first_failure_group_classified",
            2,
            move || {
                let weak = callback_state_reference
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                    .expect("test installs the probe state before reaching it");
                let state = weak.upgrade().expect("the selected probe remains alive");
                assert!(
                    state.try_lock().is_ok(),
                    "process callback must run after the probe mutex is released"
                );
                callback_calls.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("frozen boundary and nonzero occurrence select");
        *state_reference
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Arc::downgrade(&probe.state));

        let cloned = probe.clone();
        cloned.reach_v1(FaultBoundaryV1::FinalComparisonFirstFailureGroupClassified);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        probe.reach_v1(FaultBoundaryV1::FinalComparisonFirstFailureGroupClassified);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        cloned.reach_v1(FaultBoundaryV1::FinalComparisonFirstFailureGroupClassified);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "selection injects once");
        assert_eq!(
            format!("{probe:?}"),
            "FaultProbeV1 { enabled: true, injected: true, .. }"
        );
    }

    #[test]
    fn public_probe_facade_rejects_unknown_boundary_and_zero_occurrence() {
        assert!(matches!(
            FaultProbeV1::selected_process_barrier_v1("not_in_the_closed_taxonomy", 1, || {}),
            Err(FaultProbeSelectionErrorV1::UnknownBoundary)
        ));
        assert!(matches!(
            FaultProbeV1::selected_process_barrier_v1("acknowledgement_result_returned", 0, || {},),
            Err(FaultProbeSelectionErrorV1::InvalidOccurrence)
        ));
        assert_eq!(
            FaultProbeSelectionErrorV1::UnknownBoundary.to_string(),
            "UNKNOWN_FAULT_BOUNDARY"
        );
    }

    #[test]
    fn portable_fault_plumbing_is_private_feature_only_and_non_ambient() {
        let lib = include_str!("lib.rs").replace("\r\n", "\n");
        let manifest = include_str!("../Cargo.toml");
        let source = include_str!("test_fault.rs")
            .split_once("#[cfg(test)]")
            .expect("test module marker remains present")
            .0;

        assert!(lib.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
        assert!(!lib.contains("pub mod test_fault"));
        assert!(lib.contains(
            "pub use test_fault::{FaultProbeSelectionErrorV1, FaultProbeV1, ProcessBarrierV1};"
        ));
        assert!(manifest.contains("default = []"));
        assert!(manifest.contains("test-fault-injection = []"));
        assert!(source.contains("struct FaultSelectionV1"));
        assert!(source.contains("struct FaultSessionV1"));
        assert!(source.contains("pub struct FaultProbeV1"));
        assert!(source.contains("Arc<Mutex<FaultProbeStateV1>>"));
        assert!(source.contains("pub trait ProcessBarrierV1: Send + Sync"));
        assert!(source.contains("fn checkpoint_v1"));
        for forbidden in [
            "std::env",
            "thread_local!",
            "static mut",
            "OnceLock",
            "Atomic",
            "option_env!",
            "env!",
            "pub enum FaultBoundaryV1",
            "pub fn reach",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden selector: {forbidden}"
            );
        }
    }
}
