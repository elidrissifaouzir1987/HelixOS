//! Private non-default PLAN-005 fault registry and T056/T063 contracts.
//!
//! The normative inventory lives in
//! `specs/005-durable-dispatch/contracts/fault-boundaries-v1.json`; the repository
//! fixture expands every boundary into one in-process and one process-kill case. The
//! closed enum stays crate-private; a feature-only opaque facade gives both drivers one
//! identical caller-owned selection path. Default production builds cannot discover a
//! selector.

use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) const CLOSED_FAULT_BOUNDARY_COUNT_V1: usize = 90;

macro_rules! closed_fault_boundaries_v1 {
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

closed_fault_boundaries_v1!(
    Plan005Fb001 => "PLAN005-FB-001",
    Plan005Fb002 => "PLAN005-FB-002",
    Plan005Fb003 => "PLAN005-FB-003",
    Plan005Fb004 => "PLAN005-FB-004",
    Plan005Fb005 => "PLAN005-FB-005",
    Plan005Fb006 => "PLAN005-FB-006",
    Plan005Fb007 => "PLAN005-FB-007",
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
    Plan005Fb019 => "PLAN005-FB-019",
    Plan005Fb020 => "PLAN005-FB-020",
    Plan005Fb021 => "PLAN005-FB-021",
    Plan005Fb022 => "PLAN005-FB-022",
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
    Plan005Fb040 => "PLAN005-FB-040",
    Plan005Fb041 => "PLAN005-FB-041",
    Plan005Fb042 => "PLAN005-FB-042",
    Plan005Fb043 => "PLAN005-FB-043",
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
    Plan005Fb079 => "PLAN005-FB-079",
    Plan005Fb080 => "PLAN005-FB-080",
    Plan005Fb081 => "PLAN005-FB-081",
    Plan005Fb082 => "PLAN005-FB-082",
    Plan005Fb083 => "PLAN005-FB-083",
    Plan005Fb084 => "PLAN005-FB-084",
    Plan005Fb085 => "PLAN005-FB-085",
    Plan005Fb086 => "PLAN005-FB-086",
    Plan005Fb087 => "PLAN005-FB-087",
    Plan005Fb088 => "PLAN005-FB-088",
    Plan005Fb089 => "PLAN005-FB-089",
    Plan005Fb090 => "PLAN005-FB-090",
);

const _: [(); CLOSED_FAULT_BOUNDARY_COUNT_V1] = [(); FaultBoundaryV1::ALL.len()];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultEffectV1 {
    ReturnError,
    ProcessBarrier,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaultDecisionV1 {
    Continue,
    Inject(FaultEffectV1),
}

/// Non-default test mode carried by one explicit caller-owned selection.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultInjectionModeV1 {
    InProcess,
    ProcessKill,
}

/// Closed decision returned at a private PLAN-005 checkpoint.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultInjectionDecisionV1 {
    Continue,
    InjectInProcess,
    ProcessBarrierReached,
}

/// Payload-free rejection for a feature-only fault selection or checkpoint.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultSelectionErrorV1 {
    UnknownBoundary,
    InvalidOccurrence,
}

impl FaultSelectionErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownBoundary => "UNKNOWN_FAULT_BOUNDARY",
            Self::InvalidOccurrence => "INVALID_FAULT_OCCURRENCE",
        }
    }
}

impl std::fmt::Display for FaultSelectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for FaultSelectionErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FaultSelectionV1 {
    boundary: FaultBoundaryV1,
    occurrence: u64,
    effect: FaultEffectV1,
}

impl FaultSelectionV1 {
    const fn try_new(
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

#[derive(Debug)]
struct FaultSessionV1 {
    selection: Option<FaultSelectionV1>,
    matching_occurrences: u64,
    injected: bool,
}

impl FaultSessionV1 {
    const fn disabled_v1() -> Self {
        Self {
            selection: None,
            matching_occurrences: 0,
            injected: false,
        }
    }

    const fn selected_v1(selection: FaultSelectionV1) -> Self {
        Self {
            selection: Some(selection),
            matching_occurrences: 0,
            injected: false,
        }
    }

    fn checkpoint_v1(&mut self, boundary: FaultBoundaryV1) -> FaultDecisionV1 {
        let Some(selection) = self.selection else {
            return FaultDecisionV1::Continue;
        };
        if self.injected || selection.boundary != boundary {
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

struct FaultProbeStateV1 {
    session: FaultSessionV1,
    process_barrier: Option<Box<dyn FnMut() + Send>>,
}

#[derive(Clone)]
struct FaultProbeV1 {
    state: Arc<Mutex<FaultProbeStateV1>>,
}

impl FaultProbeV1 {
    fn disabled_v1() -> Self {
        Self {
            state: Arc::new(Mutex::new(FaultProbeStateV1 {
                session: FaultSessionV1::disabled_v1(),
                process_barrier: None,
            })),
        }
    }

    fn selected_v1<F>(selection: FaultSelectionV1, process_barrier: F) -> Self
    where
        F: FnMut() + Send + 'static,
    {
        Self {
            state: Arc::new(Mutex::new(FaultProbeStateV1 {
                session: FaultSessionV1::selected_v1(selection),
                process_barrier: Some(Box::new(process_barrier)),
            })),
        }
    }

    fn reach_v1(&self, boundary: FaultBoundaryV1) -> FaultDecisionV1 {
        let (decision, process_barrier) = {
            let mut state = lock_probe_state_v1(&self.state);
            let decision = state.session.checkpoint_v1(boundary);
            let process_barrier = match decision {
                FaultDecisionV1::Inject(FaultEffectV1::ProcessBarrier) => {
                    state.process_barrier.take()
                }
                FaultDecisionV1::Continue | FaultDecisionV1::Inject(FaultEffectV1::ReturnError) => {
                    None
                }
            };
            (decision, process_barrier)
        };
        if let Some(mut process_barrier) = process_barrier {
            process_barrier();
        }
        decision
    }

    fn injected_v1(&self) -> bool {
        lock_probe_state_v1(&self.state).session.injected
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

/// Opaque feature-only carrier shared by the in-process and process-kill drivers.
///
/// Both modes pass through `selected_v1`, the same private selection/session and the
/// same `reach_id_v1` checkpoint. There is no ambient selector and `Default` is inert.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct DispatchFaultProbeV1 {
    inner: FaultProbeV1,
}

impl DispatchFaultProbeV1 {
    pub fn disabled_v1() -> Self {
        Self::default()
    }

    pub fn selected_v1<F>(
        boundary_id: &str,
        occurrence: u64,
        mode: FaultInjectionModeV1,
        process_barrier: F,
    ) -> Result<Self, FaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        let boundary = FaultBoundaryV1::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.id() == boundary_id)
            .ok_or(FaultSelectionErrorV1::UnknownBoundary)?;
        let effect = match mode {
            FaultInjectionModeV1::InProcess => FaultEffectV1::ReturnError,
            FaultInjectionModeV1::ProcessKill => FaultEffectV1::ProcessBarrier,
        };
        let selection = FaultSelectionV1::try_new(boundary, occurrence, effect)?;
        Ok(Self {
            inner: FaultProbeV1::selected_v1(selection, process_barrier),
        })
    }

    pub fn reach_id_v1(
        &self,
        boundary_id: &str,
    ) -> Result<FaultInjectionDecisionV1, FaultSelectionErrorV1> {
        let boundary = FaultBoundaryV1::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.id() == boundary_id)
            .ok_or(FaultSelectionErrorV1::UnknownBoundary)?;
        Ok(match self.inner.reach_v1(boundary) {
            FaultDecisionV1::Continue => FaultInjectionDecisionV1::Continue,
            FaultDecisionV1::Inject(FaultEffectV1::ReturnError) => {
                FaultInjectionDecisionV1::InjectInProcess
            }
            FaultDecisionV1::Inject(FaultEffectV1::ProcessBarrier) => {
                FaultInjectionDecisionV1::ProcessBarrierReached
            }
        })
    }

    pub fn injected_v1(&self) -> bool {
        self.inner.injected_v1()
    }
}

impl std::fmt::Debug for DispatchFaultProbeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DispatchFaultProbeV1")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const AUTHORITATIVE_REGISTRY: &str =
        include_str!("../../../specs/005-durable-dispatch/contracts/fault-boundaries-v1.json");
    const FAULT_FIXTURE: &str =
        include_str!("../../../contracts/fixtures/durable-dispatch-v1/fault-boundaries.json");
    const LIB_SOURCE: &str = include_str!("lib.rs");
    const SELF_SOURCE: &str = include_str!("test_fault.rs");
    const AUTHORITATIVE_SHA256: &str =
        "afef6e0b580a8ea62906227e25c59e7b067c7aa5dc55d5458d9ccf92f0b1ff26";
    const PLAN004_SOURCE_SHA256: &str =
        "f9d9fd0ff4c3cb1bc7f48f52c0484031c9964c22ff3ce4c29b8f3dc24be07db9";
    const PLAN004_FIXTURE_SHA256: &str =
        "086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d";

    #[derive(Debug, PartialEq, Eq)]
    struct Boundary<'a> {
        ordinal: u64,
        id: &'a str,
        category: &'a str,
        owner: &'a str,
        phase: &'a str,
        boundary: &'a str,
        expected_class: &'a str,
        coverage: Vec<&'a str>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FaultCase<'a> {
        case_ordinal: u64,
        case_id: &'a str,
        boundary_ordinal: u64,
        boundary_id: &'a str,
        mode: &'a str,
        selected_boundary_ids: Vec<&'a str>,
        expected_reach_count: u64,
        expected_injection_count: u64,
        expected_class: &'a str,
    }

    #[test]
    fn fixture_cardinality_and_order_match_the_authoritative_registry() {
        assert!(
            AUTHORITATIVE_REGISTRY.contains("\"schema\": \"helixos.dispatch-fault-boundaries/1\"")
        );
        assert!(AUTHORITATIVE_REGISTRY.contains("\"registry_id\": \"plan005-durable-dispatch-v1\""));
        assert!(AUTHORITATIVE_REGISTRY.contains("\"boundary_count\": 90"));
        assert!(AUTHORITATIVE_REGISTRY.contains("\"required_case_count\": 180"));
        assert!(AUTHORITATIVE_REGISTRY.contains("\"lifecycle\": \"frozen-v1\""));
        assert!(AUTHORITATIVE_REGISTRY
            .contains("\"ordering\": \"ascending ordinal and byte-identical PLAN005-FB-NNN id\""));
        assert!(AUTHORITATIVE_REGISTRY.contains(
            "\"injection_semantics\": \"select exactly one boundary; inject immediately after the named event; then classify only by authoritative durable readback\""
        ));

        assert!(FAULT_FIXTURE.contains("\"schema\": \"helixos.durable-dispatch-fault-cases/1\""));
        assert!(FAULT_FIXTURE.contains("\"authoritative_lifecycle\": \"frozen-v1\""));
        assert!(FAULT_FIXTURE
            .contains("\"ordering\": \"ascending ordinal and byte-identical PLAN005-FB-NNN id\""));
        assert!(FAULT_FIXTURE.contains(
            "\"injection_semantics\": \"select exactly one boundary; inject immediately after the named event; then classify only by authoritative durable readback\""
        ));
        assert!(FAULT_FIXTURE.contains(&format!(
            "\"authoritative_sha256\": \"{AUTHORITATIVE_SHA256}\""
        )));
        assert!(FAULT_FIXTURE.contains("\"boundary_count\": 90"));
        assert!(FAULT_FIXTURE.contains("\"declared_case_count\": 180"));

        let authoritative = boundaries(AUTHORITATIVE_REGISTRY);
        let fixture = boundaries(FAULT_FIXTURE);
        assert_eq!(authoritative.len(), 90);
        assert_eq!(
            fixture, authoritative,
            "fixture must consume the exact registry"
        );

        let mut category_counts = BTreeMap::<&str, usize>::new();
        let mut ids = BTreeSet::new();
        for (index, boundary) in fixture.iter().enumerate() {
            let ordinal = u64::try_from(index + 1).expect("90 ordinals fit u64");
            assert_eq!(boundary.ordinal, ordinal);
            assert_eq!(boundary.id, format!("PLAN005-FB-{ordinal:03}"));
            assert!(ids.insert(boundary.id), "boundary IDs are unique");
            assert_eq!(boundary.coverage, ["in-process", "process-kill"]);
            *category_counts.entry(boundary.category).or_default() += 1;
        }
        assert_eq!(ids.len(), 90);
        assert_eq!(
            category_counts,
            BTreeMap::from([
                ("ack-readback-reconciliation", 33),
                ("adapter-consume-receipt", 8),
                ("adapter-receive", 8),
                ("backup", 7),
                ("coordinator-dispatch", 17),
                ("delivery-handoff", 5),
                ("migration", 5),
                ("restore", 7),
            ])
        );
    }

    #[test]
    fn fixture_declares_all_180_reachable_one_fault_cases() {
        let boundaries = boundaries(FAULT_FIXTURE);
        let cases = fault_cases(FAULT_FIXTURE);
        assert_eq!(boundaries.len(), 90);
        assert_eq!(cases.len(), 180);

        let mut pairs = BTreeSet::new();
        for (index, case) in cases.iter().enumerate() {
            let case_ordinal = u64::try_from(index + 1).expect("180 ordinals fit u64");
            let boundary = &boundaries[index / 2];
            let expected_mode = if index % 2 == 0 {
                "in-process"
            } else {
                "process-kill"
            };

            assert_eq!(case.case_ordinal, case_ordinal);
            assert_eq!(case.boundary_ordinal, boundary.ordinal);
            assert_eq!(case.boundary_id, boundary.id);
            assert_eq!(case.mode, expected_mode);
            assert_eq!(case.case_id, format!("{}::{expected_mode}", boundary.id));
            assert_eq!(case.selected_boundary_ids, [boundary.id]);
            assert_eq!(case.expected_reach_count, 1);
            assert_eq!(case.expected_injection_count, 1);
            assert_eq!(case.expected_class, boundary.expected_class);
            assert!(pairs.insert((case.boundary_id, case.mode)));
        }

        assert_eq!(pairs.len(), 180);
        for boundary in &boundaries {
            assert!(pairs.contains(&(boundary.id, "in-process")));
            assert!(pairs.contains(&(boundary.id, "process-kill")));
        }
    }

    #[test]
    fn plan004_registry_pins_remain_separate_and_immutable() {
        for (document, needle) in [
            (AUTHORITATIVE_REGISTRY, PLAN004_SOURCE_SHA256),
            (AUTHORITATIVE_REGISTRY, PLAN004_FIXTURE_SHA256),
            (FAULT_FIXTURE, PLAN004_SOURCE_SHA256),
            (FAULT_FIXTURE, PLAN004_FIXTURE_SHA256),
        ] {
            assert!(document.contains(needle));
        }
        assert!(AUTHORITATIVE_REGISTRY
            .contains("\"source_path\": \"kernel/helix-plan-preparation/src/test_fault.rs\""));
        assert!(AUTHORITATIVE_REGISTRY.contains(
            "\"fixture_path\": \"contracts/fixtures/durable-preparation-v1/cases.json\""
        ));
    }

    #[test]
    fn compiled_registry_is_the_exact_ordered_fixture_inventory() {
        let expected = boundaries(FAULT_FIXTURE)
            .into_iter()
            .map(|boundary| boundary.id)
            .collect::<Vec<_>>();
        let actual = FaultBoundaryV1::ALL
            .iter()
            .map(|boundary| boundary.id())
            .collect::<Vec<_>>();
        assert_eq!(CLOSED_FAULT_BOUNDARY_COUNT_V1, 90);
        assert_eq!(actual, expected);
    }

    #[test]
    fn disabled_probe_is_inert_across_the_closed_registry() {
        let probe = DispatchFaultProbeV1::disabled_v1();
        for boundary in FaultBoundaryV1::ALL {
            assert_eq!(
                probe.reach_id_v1(boundary.id()),
                Ok(FaultInjectionDecisionV1::Continue)
            );
        }
        assert!(!probe.injected_v1());
        assert_eq!(
            format!("{probe:?}"),
            "DispatchFaultProbeV1 { inner: FaultProbeV1 { enabled: false, injected: false, .. } }"
        );
    }

    #[test]
    fn one_selection_injects_only_the_exact_matching_occurrence_once() {
        let selected = FaultBoundaryV1::Plan005Fb041;
        let unrelated = FaultBoundaryV1::Plan005Fb040;
        let callback_calls = Arc::new(AtomicUsize::new(0));
        let callback_observer = Arc::clone(&callback_calls);
        let probe = DispatchFaultProbeV1::selected_v1(
            selected.id(),
            2,
            FaultInjectionModeV1::InProcess,
            move || {
                callback_observer.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("closed ID and nonzero occurrence select");

        assert_eq!(
            probe.reach_id_v1(unrelated.id()),
            Ok(FaultInjectionDecisionV1::Continue)
        );
        assert_eq!(
            probe.reach_id_v1(selected.id()),
            Ok(FaultInjectionDecisionV1::Continue)
        );
        assert_eq!(
            probe.reach_id_v1(selected.id()),
            Ok(FaultInjectionDecisionV1::InjectInProcess)
        );
        assert_eq!(
            probe.reach_id_v1(selected.id()),
            Ok(FaultInjectionDecisionV1::Continue)
        );
        assert!(probe.injected_v1());
        assert_eq!(callback_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn process_driver_uses_the_same_selection_and_calls_one_barrier() {
        let selected = FaultBoundaryV1::Plan005Fb038;
        let callback_calls = Arc::new(AtomicUsize::new(0));
        let callback_observer = Arc::clone(&callback_calls);
        let probe = DispatchFaultProbeV1::selected_v1(
            selected.id(),
            1,
            FaultInjectionModeV1::ProcessKill,
            move || {
                callback_observer.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("closed ID and nonzero occurrence select");

        assert_eq!(
            probe.reach_id_v1(selected.id()),
            Ok(FaultInjectionDecisionV1::ProcessBarrierReached)
        );
        assert_eq!(
            probe.reach_id_v1(selected.id()),
            Ok(FaultInjectionDecisionV1::Continue)
        );
        assert_eq!(callback_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn selection_rejects_unknown_ids_and_zero_occurrence_payload_free() {
        assert!(matches!(
            DispatchFaultProbeV1::selected_v1(
                "not-in-the-closed-registry",
                1,
                FaultInjectionModeV1::InProcess,
                || {},
            ),
            Err(FaultSelectionErrorV1::UnknownBoundary)
        ));
        assert!(matches!(
            DispatchFaultProbeV1::selected_v1(
                FaultBoundaryV1::Plan005Fb001.id(),
                0,
                FaultInjectionModeV1::InProcess,
                || {},
            ),
            Err(FaultSelectionErrorV1::InvalidOccurrence)
        ));
        assert_eq!(
            FaultSelectionErrorV1::UnknownBoundary.to_string(),
            "UNKNOWN_FAULT_BOUNDARY"
        );
        assert_eq!(
            FaultSelectionErrorV1::InvalidOccurrence.to_string(),
            "INVALID_FAULT_OCCURRENCE"
        );
    }

    #[test]
    fn red_closed_registry_has_exactly_90_ordered_production_members() {
        let production = production_source();
        assert!(
            production.contains("CLOSED_FAULT_BOUNDARY_COUNT_V1"),
            "T056 RED -> T063: missing closed production boundary count"
        );
        assert!(
            production.contains("enum FaultBoundaryV1"),
            "T056 RED -> T063: missing closed production fault enum"
        );

        let positions = boundaries(FAULT_FIXTURE)
            .into_iter()
            .map(|boundary| {
                let quoted = format!("\"{}\"", boundary.id);
                let occurrences = production.matches(&quoted).count();
                assert_eq!(
                    occurrences, 1,
                    "T056 RED -> T063: {} must occur exactly once in the production registry",
                    boundary.id
                );
                production
                    .find(&quoted)
                    .expect("the exact production registry member was counted")
            })
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 90);
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "T056 RED -> T063: production IDs must follow strict contract order"
        );
    }

    #[test]
    fn red_every_fixture_boundary_is_reachable_by_one_private_probe_path() {
        let production = production_source();
        for required in [
            "FaultBoundaryV1::ALL",
            "struct FaultSessionV1",
            "struct FaultProbeV1",
            "fn reach_v1",
            "fn checkpoint_v1",
        ] {
            assert!(
                production.contains(required),
                "T056 RED -> T063: missing private reachability seam {required}"
            );
        }

        for boundary in boundaries(FAULT_FIXTURE) {
            let quoted = format!("\"{}\"", boundary.id);
            assert_eq!(
                production.matches(&quoted).count(),
                1,
                "T056 RED -> T063: {} has no unique reachable registry member",
                boundary.id
            );
        }
    }

    #[test]
    fn red_one_fault_selection_is_at_most_once_private_and_non_ambient() {
        let production = production_source();
        let normalized_lib = LIB_SOURCE.replace("\r\n", "\n");
        assert!(
            normalized_lib.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"),
            "T056 RED -> T063: private fault module is not feature-gated into the crate"
        );
        assert!(!normalized_lib.contains("pub mod test_fault;"));

        for required in [
            "struct FaultSelectionV1",
            "occurrence:",
            "matching_occurrences:",
            "injected: bool",
            "InvalidOccurrence",
            "FaultDecisionV1::Inject",
            "if self.injected",
        ] {
            assert!(
                production.contains(required),
                "T056 RED -> T063: missing exactly-one-fault invariant {required}"
            );
        }
        for forbidden in [
            concat!("std::", "env"),
            "thread_local!",
            concat!("static ", "mut"),
            "OnceLock",
            "option_env!",
            "env!",
            "pub enum FaultBoundaryV1",
        ] {
            assert!(
                !production.contains(forbidden),
                "T056/T063: forbidden ambient or public selector {forbidden}"
            );
        }
    }

    fn production_source() -> &'static str {
        SELF_SOURCE
            .split_once("#[cfg(test)]")
            .expect("the RED test module marker remains present")
            .0
    }

    fn boundaries(document: &str) -> Vec<Boundary<'_>> {
        document
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("{\"ordinal\":"))
            .map(|line| Boundary {
                ordinal: integer_field(line, "ordinal"),
                id: string_field(line, "id"),
                category: string_field(line, "category"),
                owner: string_field(line, "owner"),
                phase: string_field(line, "phase"),
                boundary: string_field(line, "boundary"),
                expected_class: string_field(line, "expected_class"),
                coverage: string_array_field(line, "coverage"),
            })
            .collect()
    }

    fn fault_cases(document: &str) -> Vec<FaultCase<'_>> {
        document
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("{\"case_ordinal\":"))
            .map(|line| FaultCase {
                case_ordinal: integer_field(line, "case_ordinal"),
                case_id: string_field(line, "case_id"),
                boundary_ordinal: integer_field(line, "boundary_ordinal"),
                boundary_id: string_field(line, "boundary_id"),
                mode: string_field(line, "mode"),
                selected_boundary_ids: string_array_field(line, "selected_boundary_ids"),
                expected_reach_count: integer_field(line, "expected_reach_count"),
                expected_injection_count: integer_field(line, "expected_injection_count"),
                expected_class: string_field(line, "expected_class"),
            })
            .collect()
    }

    fn string_field<'a>(line: &'a str, field: &str) -> &'a str {
        let needle = format!("\"{field}\": \"");
        let start = line
            .find(&needle)
            .unwrap_or_else(|| panic!("missing string field {field}"))
            + needle.len();
        let rest = &line[start..];
        let end = rest
            .find('"')
            .unwrap_or_else(|| panic!("unterminated string field {field}"));
        &rest[..end]
    }

    fn integer_field(line: &str, field: &str) -> u64 {
        let needle = format!("\"{field}\": ");
        let start = line
            .find(&needle)
            .unwrap_or_else(|| panic!("missing integer field {field}"))
            + needle.len();
        let digits = line[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        digits
            .parse()
            .unwrap_or_else(|_| panic!("invalid integer field {field}"))
    }

    fn string_array_field<'a>(line: &'a str, field: &str) -> Vec<&'a str> {
        let needle = format!("\"{field}\": [");
        let start = line
            .find(&needle)
            .unwrap_or_else(|| panic!("missing array field {field}"))
            + needle.len();
        let rest = &line[start..];
        let end = rest
            .find(']')
            .unwrap_or_else(|| panic!("unterminated array field {field}"));
        let body = &rest[..end];
        if body.is_empty() {
            return Vec::new();
        }
        body.split(',')
            .map(|value| value.trim().trim_matches('"'))
            .collect()
    }
}
