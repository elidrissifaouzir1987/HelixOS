//! Private coordinator projection of the PLAN-005 dispatch fault registry.

#![allow(dead_code)]

use helix_plan_dispatch::{
    DispatchFaultProbeV1, FaultInjectionDecisionV1, FaultInjectionModeV1, FaultSelectionErrorV1,
};

pub(crate) const COORDINATOR_DISPATCH_FAULT_BOUNDARY_COUNT_V1: usize = 57;

macro_rules! coordinator_fault_boundaries_v1 {
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
        }
    };
}

coordinator_fault_boundaries_v1!(
    Plan005Fb001 => "PLAN005-FB-001",
    Plan005Fb008 => "PLAN005-FB-008",
    Plan005Fb009 => "PLAN005-FB-009",
    Plan005Fb010 => "PLAN005-FB-010",
    Plan005Fb011 => "PLAN005-FB-011",
    Plan005Fb012 => "PLAN005-FB-012",
    Plan005Fb013 => "PLAN005-FB-013",
    Plan005Fb014 => "PLAN005-FB-014",
    Plan005Fb015 => "PLAN005-FB-015",
    Plan005Fb016 => "PLAN005-FB-016",
    Plan005Fb017 => "PLAN005-FB-017",
    Plan005Fb018 => "PLAN005-FB-018",
    Plan005Fb020 => "PLAN005-FB-020",
    Plan005Fb044 => "PLAN005-FB-044",
    Plan005Fb045 => "PLAN005-FB-045",
    Plan005Fb046 => "PLAN005-FB-046",
    Plan005Fb047 => "PLAN005-FB-047",
    Plan005Fb048 => "PLAN005-FB-048",
    Plan005Fb049 => "PLAN005-FB-049",
    Plan005Fb050 => "PLAN005-FB-050",
    Plan005Fb051 => "PLAN005-FB-051",
    Plan005Fb052 => "PLAN005-FB-052",
    Plan005Fb053 => "PLAN005-FB-053",
    Plan005Fb054 => "PLAN005-FB-054",
    Plan005Fb055 => "PLAN005-FB-055",
    Plan005Fb056 => "PLAN005-FB-056",
    Plan005Fb057 => "PLAN005-FB-057",
    Plan005Fb058 => "PLAN005-FB-058",
    Plan005Fb059 => "PLAN005-FB-059",
    Plan005Fb060 => "PLAN005-FB-060",
    Plan005Fb061 => "PLAN005-FB-061",
    Plan005Fb062 => "PLAN005-FB-062",
    Plan005Fb063 => "PLAN005-FB-063",
    Plan005Fb064 => "PLAN005-FB-064",
    Plan005Fb065 => "PLAN005-FB-065",
    Plan005Fb066 => "PLAN005-FB-066",
    Plan005Fb067 => "PLAN005-FB-067",
    Plan005Fb068 => "PLAN005-FB-068",
    Plan005Fb069 => "PLAN005-FB-069",
    Plan005Fb070 => "PLAN005-FB-070",
    Plan005Fb071 => "PLAN005-FB-071",
    Plan005Fb072 => "PLAN005-FB-072",
    Plan005Fb073 => "PLAN005-FB-073",
    Plan005Fb074 => "PLAN005-FB-074",
    Plan005Fb075 => "PLAN005-FB-075",
    Plan005Fb076 => "PLAN005-FB-076",
    Plan005Fb077 => "PLAN005-FB-077",
    Plan005Fb078 => "PLAN005-FB-078",
    Plan005Fb080 => "PLAN005-FB-080",
    Plan005Fb081 => "PLAN005-FB-081",
    Plan005Fb082 => "PLAN005-FB-082",
    Plan005Fb083 => "PLAN005-FB-083",
    Plan005Fb084 => "PLAN005-FB-084",
    Plan005Fb086 => "PLAN005-FB-086",
    Plan005Fb088 => "PLAN005-FB-088",
    Plan005Fb089 => "PLAN005-FB-089",
    Plan005Fb090 => "PLAN005-FB-090",
);

const _: [(); COORDINATOR_DISPATCH_FAULT_BOUNDARY_COUNT_V1] = [(); FaultBoundaryV1::ALL.len()];

/// Caller-owned coordinator carrier; selection remains in `helix-plan-dispatch`.
#[derive(Clone, Debug, Default)]
pub(crate) struct CoordinatorDispatchFaultProbeV1 {
    inner: DispatchFaultProbeV1,
}

impl CoordinatorDispatchFaultProbeV1 {
    pub(crate) fn disabled_v1() -> Self {
        Self::default()
    }

    pub(crate) fn select_dispatch_handoff_readback_fault_v1<F>(
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

    pub(crate) fn select_dispatch_handoff_readback_fault_id_v1<F>(
        boundary_id: &str,
        occurrence: u64,
        mode: FaultInjectionModeV1,
        process_barrier: F,
    ) -> Result<Self, FaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        let coordinator_owned = FaultBoundaryV1::ALL
            .iter()
            .any(|candidate| candidate.id() == boundary_id);
        if !coordinator_owned && !portable_coordinator_boundary_id_v1(boundary_id) {
            return Err(FaultSelectionErrorV1::UnknownBoundary);
        }
        DispatchFaultProbeV1::selected_v1(boundary_id, occurrence, mode, process_barrier)
            .map(|inner| Self { inner })
    }

    pub(crate) fn reach_dispatch_handoff_readback_fault_v1(
        &self,
        boundary: FaultBoundaryV1,
    ) -> Result<FaultInjectionDecisionV1, FaultSelectionErrorV1> {
        self.inner.reach_id_v1(boundary.id())
    }

    pub(crate) fn portable_probe_v1(&self) -> DispatchFaultProbeV1 {
        self.inner.clone()
    }

    pub(crate) fn injected_at_v1(&self, boundary: FaultBoundaryV1) -> bool {
        !matches!(
            self.reach_dispatch_handoff_readback_fault_v1(boundary),
            Ok(FaultInjectionDecisionV1::Continue)
        )
    }
}

fn portable_coordinator_boundary_id_v1(boundary_id: &str) -> bool {
    matches!(
        boundary_id,
        "PLAN005-FB-002"
            | "PLAN005-FB-003"
            | "PLAN005-FB-004"
            | "PLAN005-FB-005"
            | "PLAN005-FB-006"
            | "PLAN005-FB-007"
            | "PLAN005-FB-019"
            | "PLAN005-FB-021"
            | "PLAN005-FB-022"
            | "PLAN005-FB-040"
            | "PLAN005-FB-041"
            | "PLAN005-FB-042"
            | "PLAN005-FB-043"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_projection_is_closed_ordered_and_delegates_once() {
        assert_eq!(COORDINATOR_DISPATCH_FAULT_BOUNDARY_COUNT_V1, 57);
        assert_eq!(FaultBoundaryV1::ALL.len(), 57);
        assert!(FaultBoundaryV1::ALL
            .windows(2)
            .all(|pair| pair[0].id() < pair[1].id()));

        let selected = FaultBoundaryV1::Plan005Fb052;
        let probe = CoordinatorDispatchFaultProbeV1::select_dispatch_handoff_readback_fault_v1(
            selected,
            1,
            FaultInjectionModeV1::InProcess,
            || {},
        )
        .expect("coordinator projection selects through the portable registry");
        assert_eq!(
            probe.reach_dispatch_handoff_readback_fault_v1(selected),
            Ok(FaultInjectionDecisionV1::InjectInProcess)
        );
        assert_eq!(
            probe.reach_dispatch_handoff_readback_fault_v1(selected),
            Ok(FaultInjectionDecisionV1::Continue)
        );

        let portable =
            CoordinatorDispatchFaultProbeV1::select_dispatch_handoff_readback_fault_id_v1(
                "PLAN005-FB-019",
                1,
                FaultInjectionModeV1::InProcess,
                || {},
            )
            .expect("portable coordinator-owned handoff checkpoint is selectable");
        assert_eq!(
            portable.portable_probe_v1().reach_id_v1("PLAN005-FB-019"),
            Ok(FaultInjectionDecisionV1::InjectInProcess)
        );
        assert!(matches!(
            CoordinatorDispatchFaultProbeV1::select_dispatch_handoff_readback_fault_id_v1(
                "PLAN005-FB-023",
                1,
                FaultInjectionModeV1::InProcess,
                || {},
            ),
            Err(FaultSelectionErrorV1::UnknownBoundary)
        ));
    }
}
