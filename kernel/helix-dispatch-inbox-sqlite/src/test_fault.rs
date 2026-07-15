//! Private adapter projection of the PLAN-005 receive/consume/receipt fault registry.

#![allow(dead_code)]

use helix_plan_dispatch::{
    DispatchFaultProbeV1, FaultInjectionDecisionV1, FaultInjectionModeV1, FaultSelectionErrorV1,
};

pub(crate) const ADAPTER_DISPATCH_FAULT_BOUNDARY_COUNT_V1: usize = 19;

macro_rules! adapter_fault_boundaries_v1 {
    ($($variant:ident => $id:literal),+ $(,)?) => {
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

            pub(crate) fn from_id_v1(boundary_id: &str) -> Option<Self> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|candidate| candidate.id() == boundary_id)
            }
        }
    };
}

adapter_fault_boundaries_v1!(
    Plan005Fb023 => "PLAN005-FB-023",
    Plan005Fb024 => "PLAN005-FB-024",
    Plan005Fb025 => "PLAN005-FB-025",
    Plan005Fb026 => "PLAN005-FB-026",
    Plan005Fb027 => "PLAN005-FB-027",
    Plan005Fb028 => "PLAN005-FB-028",
    Plan005Fb029 => "PLAN005-FB-029",
    Plan005Fb030 => "PLAN005-FB-030",
    Plan005Fb031 => "PLAN005-FB-031",
    Plan005Fb032 => "PLAN005-FB-032",
    Plan005Fb033 => "PLAN005-FB-033",
    Plan005Fb034 => "PLAN005-FB-034",
    Plan005Fb035 => "PLAN005-FB-035",
    Plan005Fb036 => "PLAN005-FB-036",
    Plan005Fb037 => "PLAN005-FB-037",
    Plan005Fb038 => "PLAN005-FB-038",
    Plan005Fb039 => "PLAN005-FB-039",
    Plan005Fb079 => "PLAN005-FB-079",
    Plan005Fb087 => "PLAN005-FB-087",
);

const _: [(); ADAPTER_DISPATCH_FAULT_BOUNDARY_COUNT_V1] = [(); FaultBoundaryV1::ALL.len()];

/// Closed signal consumed by production call sites when a selected checkpoint fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterDispatchFaultReachedV1;

/// Caller-owned adapter carrier; both fault modes delegate to the portable selector.
#[derive(Clone, Debug, Default)]
pub(crate) struct AdapterDispatchFaultProbeV1 {
    inner: DispatchFaultProbeV1,
}

impl AdapterDispatchFaultProbeV1 {
    pub(crate) fn disabled_v1() -> Self {
        Self::default()
    }

    pub(crate) fn select_receive_consume_receipt_acknowledgement_fault_v1<F>(
        boundary: FaultBoundaryV1,
        occurrence: u64,
        mode: FaultInjectionModeV1,
        process_barrier: F,
    ) -> Result<Self, FaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        DispatchFaultProbeV1::selected_v1(boundary.id(), occurrence, mode, process_barrier)
            .map(|inner| Self { inner })
    }

    pub(crate) fn select_id_v1<F>(
        boundary_id: &str,
        occurrence: u64,
        mode: FaultInjectionModeV1,
        process_barrier: F,
    ) -> Result<Self, FaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        let boundary = FaultBoundaryV1::from_id_v1(boundary_id)
            .filter(|boundary| !matches!(boundary, FaultBoundaryV1::Plan005Fb087))
            .ok_or(FaultSelectionErrorV1::UnknownBoundary)?;
        Self::select_receive_consume_receipt_acknowledgement_fault_v1(
            boundary,
            occurrence,
            mode,
            process_barrier,
        )
    }

    pub(crate) fn reach_receive_consume_receipt_acknowledgement_fault_v1(
        &self,
        boundary: FaultBoundaryV1,
    ) -> Result<FaultInjectionDecisionV1, FaultSelectionErrorV1> {
        self.inner.reach_id_v1(boundary.id())
    }

    /// Reaches the one portable checkpoint used by both fault modes and fails closed.
    ///
    /// A process callback is invoked by `DispatchFaultProbeV1::reach_id_v1` before its
    /// decision is returned. If a test callback returns instead of terminating the child,
    /// the production operation still stops at the selected boundary.
    pub(crate) fn checkpoint_v1(
        &self,
        boundary: FaultBoundaryV1,
    ) -> Result<(), AdapterDispatchFaultReachedV1> {
        match self.reach_receive_consume_receipt_acknowledgement_fault_v1(boundary) {
            Ok(FaultInjectionDecisionV1::Continue) => Ok(()),
            Ok(
                FaultInjectionDecisionV1::InjectInProcess
                | FaultInjectionDecisionV1::ProcessBarrierReached,
            )
            | Err(_) => Err(AdapterDispatchFaultReachedV1),
        }
    }

    pub(crate) fn injected_v1(&self) -> bool {
        self.inner.injected_v1()
    }

    pub(crate) fn portable_probe_v1(&self) -> DispatchFaultProbeV1 {
        self.inner.clone()
    }
}

/// Restore-only projection of FB087. Keeping this carrier separate prevents the
/// receive/consume/receipt selector from gaining maintenance authority.
#[derive(Clone, Debug, Default)]
pub(crate) struct AdapterDispatchRestoreFaultProbeV1 {
    inner: DispatchFaultProbeV1,
}

impl AdapterDispatchRestoreFaultProbeV1 {
    pub(crate) fn select_id_v1<F>(
        boundary_id: &str,
        occurrence: u64,
        mode: FaultInjectionModeV1,
        process_barrier: F,
    ) -> Result<Self, FaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        let boundary = FaultBoundaryV1::from_id_v1(boundary_id)
            .filter(|boundary| matches!(boundary, FaultBoundaryV1::Plan005Fb087))
            .ok_or(FaultSelectionErrorV1::UnknownBoundary)?;
        DispatchFaultProbeV1::selected_v1(boundary.id(), occurrence, mode, process_barrier)
            .map(|inner| Self { inner })
    }

    /// Reaches only the post-copy, pre-commit boundary and fails closed if selected.
    pub(crate) fn checkpoint_v1(&self) -> Result<(), AdapterDispatchFaultReachedV1> {
        match self.inner.reach_id_v1(FaultBoundaryV1::Plan005Fb087.id()) {
            Ok(FaultInjectionDecisionV1::Continue) => Ok(()),
            Ok(
                FaultInjectionDecisionV1::InjectInProcess
                | FaultInjectionDecisionV1::ProcessBarrierReached,
            )
            | Err(_) => Err(AdapterDispatchFaultReachedV1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_projection_is_closed_ordered_and_delegates_once() {
        assert_eq!(ADAPTER_DISPATCH_FAULT_BOUNDARY_COUNT_V1, 19);
        assert_eq!(FaultBoundaryV1::ALL.len(), 19);
        assert!(FaultBoundaryV1::ALL
            .windows(2)
            .all(|pair| pair[0].id() < pair[1].id()));

        let selected = FaultBoundaryV1::Plan005Fb038;
        let probe =
            AdapterDispatchFaultProbeV1::select_receive_consume_receipt_acknowledgement_fault_v1(
                selected,
                1,
                FaultInjectionModeV1::InProcess,
                || {},
            )
            .expect("adapter projection selects through the portable registry");
        assert_eq!(
            probe.reach_receive_consume_receipt_acknowledgement_fault_v1(selected),
            Ok(FaultInjectionDecisionV1::InjectInProcess)
        );
        assert_eq!(
            probe.reach_receive_consume_receipt_acknowledgement_fault_v1(selected),
            Ok(FaultInjectionDecisionV1::Continue)
        );
    }

    #[test]
    fn both_modes_use_one_reach_and_fail_closed_if_the_callback_returns() {
        let in_process = AdapterDispatchFaultProbeV1::select_id_v1(
            "PLAN005-FB-023",
            1,
            FaultInjectionModeV1::InProcess,
            || {},
        )
        .expect("in-process adapter boundary selects");
        assert_eq!(
            in_process.checkpoint_v1(FaultBoundaryV1::Plan005Fb023),
            Err(AdapterDispatchFaultReachedV1)
        );
        assert!(in_process.injected_v1());

        let callback_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_observation = std::sync::Arc::clone(&callback_count);
        let process_kill = AdapterDispatchFaultProbeV1::select_id_v1(
            "PLAN005-FB-023",
            1,
            FaultInjectionModeV1::ProcessKill,
            move || {
                callback_observation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        )
        .expect("process-kill adapter boundary selects");
        assert_eq!(
            process_kill.checkpoint_v1(FaultBoundaryV1::Plan005Fb023),
            Err(AdapterDispatchFaultReachedV1)
        );
        assert_eq!(callback_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(process_kill.injected_v1());
    }

    #[test]
    fn real_store_selector_rejects_boundaries_owned_by_other_adapter_workflows() {
        for boundary_id in ["PLAN005-FB-001", "PLAN005-FB-087"] {
            assert!(matches!(
                AdapterDispatchFaultProbeV1::select_id_v1(
                    boundary_id,
                    1,
                    FaultInjectionModeV1::InProcess,
                    || {},
                ),
                Err(FaultSelectionErrorV1::UnknownBoundary)
            ));
        }
        assert!(AdapterDispatchFaultProbeV1::select_id_v1(
            "PLAN005-FB-079",
            1,
            FaultInjectionModeV1::InProcess,
            || {},
        )
        .is_ok());
    }

    #[test]
    fn restore_selector_owns_only_fb087_and_fails_closed() {
        for boundary_id in ["PLAN005-FB-023", "PLAN005-FB-079", "PLAN005-FB-088"] {
            assert!(matches!(
                AdapterDispatchRestoreFaultProbeV1::select_id_v1(
                    boundary_id,
                    1,
                    FaultInjectionModeV1::InProcess,
                    || {},
                ),
                Err(FaultSelectionErrorV1::UnknownBoundary)
            ));
        }
        let probe = AdapterDispatchRestoreFaultProbeV1::select_id_v1(
            "PLAN005-FB-087",
            1,
            FaultInjectionModeV1::InProcess,
            || {},
        )
        .expect("restore-only FB087 selects");
        assert_eq!(probe.checkpoint_v1(), Err(AdapterDispatchFaultReachedV1));
        assert_eq!(probe.checkpoint_v1(), Ok(()));
    }
}
