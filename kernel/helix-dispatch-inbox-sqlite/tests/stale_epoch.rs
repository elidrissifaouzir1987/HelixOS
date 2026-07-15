//! PLAN-005 T042 independent supervisor-epoch observer contracts.

use std::collections::VecDeque;
use std::fs;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EpochEvidenceV1 {
    boot_id: &'static str,
    supervisor_epoch: u64,
    observer_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScriptedObservationV1 {
    Current(EpochEvidenceV1),
    Unavailable,
    Unreadable,
    Stale(EpochEvidenceV1),
}

#[derive(Debug)]
struct ScriptedEpochObserverV1 {
    observations: VecDeque<ScriptedObservationV1>,
    calls: usize,
}

impl ScriptedEpochObserverV1 {
    fn new(observations: impl IntoIterator<Item = ScriptedObservationV1>) -> Self {
        Self {
            observations: observations.into_iter().collect(),
            calls: 0,
        }
    }

    fn observe(&mut self) -> ScriptedObservationV1 {
        self.calls += 1;
        self.observations
            .pop_front()
            .expect("T042 scripted independent epoch observation exists")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceivedGrantV1 {
    expected_boot_id: &'static str,
    expected_supervisor_epoch: u64,
    received_observer_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiveGateV1 {
    Received(ReceivedGrantV1),
    EpochUnavailable,
    EpochUnreadable,
    EpochStale,
    EpochMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsumeGateV1 {
    Consumed,
    RefusedSupervisorEpochMismatch,
    EpochUnavailable,
    EpochUnreadable,
    EpochStale,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ConsumptionCounterV1 {
    consumptions: usize,
}

fn receive_with_independent_epoch(
    observer: &mut ScriptedEpochObserverV1,
    grant_boot_id: &'static str,
    grant_supervisor_epoch: u64,
) -> ReceiveGateV1 {
    match observer.observe() {
        ScriptedObservationV1::Unavailable => ReceiveGateV1::EpochUnavailable,
        ScriptedObservationV1::Unreadable => ReceiveGateV1::EpochUnreadable,
        ScriptedObservationV1::Stale(_) => ReceiveGateV1::EpochStale,
        ScriptedObservationV1::Current(observed)
            if observed.boot_id != grant_boot_id
                || observed.supervisor_epoch != grant_supervisor_epoch =>
        {
            ReceiveGateV1::EpochMismatch
        }
        ScriptedObservationV1::Current(observed) => ReceiveGateV1::Received(ReceivedGrantV1 {
            expected_boot_id: grant_boot_id,
            expected_supervisor_epoch: grant_supervisor_epoch,
            received_observer_generation: observed.observer_generation,
        }),
    }
}

fn consume_after_second_epoch_observation(
    received: ReceivedGrantV1,
    observer: &mut ScriptedEpochObserverV1,
    counter: &mut ConsumptionCounterV1,
) -> ConsumeGateV1 {
    match observer.observe() {
        ScriptedObservationV1::Unavailable => ConsumeGateV1::EpochUnavailable,
        ScriptedObservationV1::Unreadable => ConsumeGateV1::EpochUnreadable,
        ScriptedObservationV1::Stale(_) => ConsumeGateV1::EpochStale,
        ScriptedObservationV1::Current(observed)
            if observed.boot_id != received.expected_boot_id
                || observed.supervisor_epoch != received.expected_supervisor_epoch
                || observed.observer_generation <= received.received_observer_generation =>
        {
            ConsumeGateV1::RefusedSupervisorEpochMismatch
        }
        ScriptedObservationV1::Current(_) => {
            counter.consumptions += 1;
            ConsumeGateV1::Consumed
        }
    }
}

fn current(epoch: u64, generation: u64) -> ScriptedObservationV1 {
    ScriptedObservationV1::Current(EpochEvidenceV1 {
        boot_id: "boot-current",
        supervisor_epoch: epoch,
        observer_generation: generation,
    })
}

#[test]
fn unavailable_unreadable_stale_or_mismatching_initial_observation_consumes_nothing() {
    let cases = [
        (
            ScriptedObservationV1::Unavailable,
            ReceiveGateV1::EpochUnavailable,
        ),
        (
            ScriptedObservationV1::Unreadable,
            ReceiveGateV1::EpochUnreadable,
        ),
        (
            ScriptedObservationV1::Stale(EpochEvidenceV1 {
                boot_id: "boot-current",
                supervisor_epoch: 41,
                observer_generation: 6,
            }),
            ReceiveGateV1::EpochStale,
        ),
        (current(42, 7), ReceiveGateV1::EpochMismatch),
    ];

    for (observation, expected) in cases {
        let mut observer = ScriptedEpochObserverV1::new([observation]);
        let counter = ConsumptionCounterV1::default();
        let outcome = receive_with_independent_epoch(&mut observer, "boot-current", 41);
        assert_eq!(outcome, expected);
        assert_eq!(observer.calls, 1, "T042 observer must be consulted");
        assert_eq!(counter.consumptions, 0);
        assert!(
            !matches!(outcome, ReceiveGateV1::Received(_)),
            "T042 failed initial epoch observation must stop before RECEIVED"
        );
    }
}

#[test]
fn grant_carried_epoch_never_substitutes_for_an_unavailable_independent_observer() {
    let mut observer = ScriptedEpochObserverV1::new([ScriptedObservationV1::Unavailable]);
    let outcome = receive_with_independent_epoch(&mut observer, "boot-current", 41);
    assert_eq!(outcome, ReceiveGateV1::EpochUnavailable);
    assert_eq!(observer.calls, 1);
}

#[test]
fn epoch_change_between_receive_and_consume_refuses_with_zero_consumption() {
    let mut observer = ScriptedEpochObserverV1::new([current(41, 7), current(42, 8)]);
    let received = match receive_with_independent_epoch(&mut observer, "boot-current", 41) {
        ReceiveGateV1::Received(received) => received,
        denied => panic!("T042 first current observation must receive: {denied:?}"),
    };
    let mut counter = ConsumptionCounterV1::default();
    let outcome = consume_after_second_epoch_observation(received, &mut observer, &mut counter);

    assert_eq!(outcome, ConsumeGateV1::RefusedSupervisorEpochMismatch);
    assert_eq!(observer.calls, 2, "T042 must observe again before consume");
    assert_eq!(counter.consumptions, 0);
}

#[test]
fn unavailable_unreadable_or_stale_second_observation_consumes_nothing() {
    for second in [
        ScriptedObservationV1::Unavailable,
        ScriptedObservationV1::Unreadable,
        ScriptedObservationV1::Stale(EpochEvidenceV1 {
            boot_id: "boot-current",
            supervisor_epoch: 41,
            observer_generation: 7,
        }),
    ] {
        let mut observer = ScriptedEpochObserverV1::new([current(41, 7), second]);
        let received = match receive_with_independent_epoch(&mut observer, "boot-current", 41) {
            ReceiveGateV1::Received(received) => received,
            denied => panic!("T042 first current observation must receive: {denied:?}"),
        };
        let mut counter = ConsumptionCounterV1::default();
        let outcome = consume_after_second_epoch_observation(received, &mut observer, &mut counter);

        assert!(matches!(
            outcome,
            ConsumeGateV1::EpochUnavailable
                | ConsumeGateV1::EpochUnreadable
                | ConsumeGateV1::EpochStale
        ));
        assert_eq!(observer.calls, 2);
        assert_eq!(counter.consumptions, 0);
    }
}

#[test]
fn unchanged_epoch_with_a_fresher_generation_consumes_once() {
    let mut observer = ScriptedEpochObserverV1::new([current(41, 7), current(41, 8)]);
    let received = match receive_with_independent_epoch(&mut observer, "boot-current", 41) {
        ReceiveGateV1::Received(received) => received,
        denied => panic!("T042 first current observation must receive: {denied:?}"),
    };
    let mut counter = ConsumptionCounterV1::default();
    assert_eq!(
        consume_after_second_epoch_observation(received, &mut observer, &mut counter),
        ConsumeGateV1::Consumed
    );
    assert_eq!(observer.calls, 2);
    assert_eq!(counter.consumptions, 1);
}

#[test]
fn production_epoch_boundary_is_injected_and_reobserved_before_consumption() {
    let epoch = required_production_source(
        "epoch.rs",
        "T042/T046 independent supervisor epoch observer",
    );
    let inbox = required_production_source(
        "inbox.rs",
        "T042/T047 independent epoch validation before RECEIVED",
    );
    let receipt = required_production_source(
        "receipt.rs",
        "T042/T049 second epoch validation before terminal decision",
    );
    let crate_root = required_production_source("lib.rs", "T042 compiled module wiring");

    for module in ["mod epoch;", "mod inbox;", "mod receipt;"] {
        assert!(
            crate_root.contains(module),
            "T042 RED: production crate root must compile {module}"
        );
    }
    for required in [
        "SupervisorEpochObserverV1",
        "EpochObservationV1",
        "Unavailable",
        "Unreadable",
        "Stale",
        "observer_generation",
        "supervisor_epoch",
        "boot_id",
    ] {
        assert!(
            epoch.contains(required),
            "T042 RED: T046 independent epoch boundary omits {required}"
        );
    }
    for required in [
        "epoch_observer",
        "observe",
        "epoch_observer_generation",
        "observed_supervisor_epoch",
        "RECEIVED",
    ] {
        assert!(
            inbox.contains(required),
            "T042 RED: T047 receive validation omits {required}"
        );
    }
    for required in [
        "epoch_observer",
        "observe",
        "epoch_observer_generation",
        "observed_supervisor_epoch",
        "SUPERVISOR_EPOCH_MISMATCH",
        "REFUSED_DEFINITE",
    ] {
        assert!(
            receipt.contains(required),
            "T042 RED: T049 consume revalidation omits {required}"
        );
    }
    assert!(
        inbox.matches("observe").count() >= 1 && receipt.matches("observe").count() >= 1,
        "T042 RED: independent epoch must be observed once before receive and again before consume"
    );
    assert!(
        !epoch.contains("impl SupervisorEpochObserverV1 for AuthenticExecutionGrantV1"),
        "T042: a grant-carried epoch must not implement the independent observer"
    );
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T042 RED: missing future production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut block_depth = 0_u64;
    for line in source.lines() {
        let mut remaining = line;
        loop {
            if block_depth > 0 {
                let Some(end) = remaining.find("*/") else {
                    break;
                };
                block_depth -= 1;
                remaining = &remaining[end + 2..];
                continue;
            }
            let line_comment = remaining.find("//");
            let block_comment = remaining.find("/*");
            match (line_comment, block_comment) {
                (Some(line_start), Some(block_start)) if block_start < line_start => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (Some(line_start), _) => {
                    output.push_str(&remaining[..line_start]);
                    break;
                }
                (None, Some(block_start)) => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (None, None) => {
                    output.push_str(remaining);
                    break;
                }
            }
        }
        output.push('\n');
    }
    assert_eq!(block_depth, 0, "T042 source comments are balanced");
    output
}
