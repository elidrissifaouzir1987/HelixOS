//! PLAN-005 T058 bounded delivery readback and ambiguity-custody contracts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);

const AUTOMATIC_READBACK_BACKOFFS_MS_V1: [u64; 4] = [0, 25, 75, 175];
const AUTOMATIC_READBACK_OFFSETS_MS_V1: [u64; 4] = [0, 25, 100, 275];
const AUTOMATIC_READBACK_MAX_OBSERVATIONS_V1: usize = 4;
const AUTOMATIC_READBACK_BUDGET_MS_V1: u64 = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandoffClassificationV1 {
    ConfirmedNoSend,
    PossibleHandoff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadbackObservationV1 {
    Absent,
    ReceivedWithoutReceipt,
    RetainedReceipt,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadbackContractOutcomeV1 {
    PendingExactGrant,
    ReceiptRecovered,
    OutcomeUnknownThenReconciliationRequired,
}

#[derive(Debug, PartialEq, Eq)]
struct ReadbackBoundsV1 {
    hard_end_monotonic_ms: u64,
    effective_end_monotonic_ms: u64,
    eligible_offsets_ms: Vec<u64>,
}

fn readback_bounds_v1(
    first_observation_monotonic_ms: u64,
    caller_deadline_monotonic_ms: u64,
    grant_deadline_monotonic_ms: u64,
) -> ReadbackBoundsV1 {
    let hard_end_monotonic_ms = first_observation_monotonic_ms
        .checked_add(AUTOMATIC_READBACK_BUDGET_MS_V1)
        .expect("T058 oracle uses bounded monotonic samples");
    let effective_end_monotonic_ms = hard_end_monotonic_ms
        .min(caller_deadline_monotonic_ms)
        .min(grant_deadline_monotonic_ms);
    let eligible_offsets_ms = AUTOMATIC_READBACK_OFFSETS_MS_V1
        .into_iter()
        .filter(|offset| {
            first_observation_monotonic_ms
                .checked_add(*offset)
                .is_some_and(|sample| sample < effective_end_monotonic_ms)
        })
        .collect();

    ReadbackBoundsV1 {
        hard_end_monotonic_ms,
        effective_end_monotonic_ms,
        eligible_offsets_ms,
    }
}

#[derive(Default)]
struct AutomaticReadbackOracleV1 {
    started_attempts: BTreeSet<u64>,
    terminal_outcomes: BTreeMap<u64, ReadbackContractOutcomeV1>,
    observation_offsets_ms: BTreeMap<u64, Vec<u64>>,
    unknown_transitions: usize,
    reconciliation_transitions: usize,
}

impl AutomaticReadbackOracleV1 {
    #[allow(clippy::too_many_arguments)]
    fn classify_attempt_v1(
        &mut self,
        delivery_attempt: u64,
        handoff: HandoffClassificationV1,
        first_observation_monotonic_ms: u64,
        caller_deadline_monotonic_ms: u64,
        grant_deadline_monotonic_ms: u64,
        observations: &[ReadbackObservationV1],
    ) -> ReadbackContractOutcomeV1 {
        if handoff == HandoffClassificationV1::ConfirmedNoSend {
            return ReadbackContractOutcomeV1::PendingExactGrant;
        }
        if let Some(outcome) = self.terminal_outcomes.get(&delivery_attempt) {
            return *outcome;
        }

        assert!(
            self.started_attempts.insert(delivery_attempt),
            "one possible-handoff attempt starts at most one automatic sequence"
        );
        let bounds = readback_bounds_v1(
            first_observation_monotonic_ms,
            caller_deadline_monotonic_ms,
            grant_deadline_monotonic_ms,
        );
        let mut observed_offsets = Vec::new();
        for (index, offset) in bounds.eligible_offsets_ms.iter().copied().enumerate() {
            assert!(index < AUTOMATIC_READBACK_MAX_OBSERVATIONS_V1);
            observed_offsets.push(offset);
            match observations
                .get(index)
                .copied()
                .unwrap_or(ReadbackObservationV1::Unavailable)
            {
                ReadbackObservationV1::RetainedReceipt => {
                    self.observation_offsets_ms
                        .insert(delivery_attempt, observed_offsets);
                    self.terminal_outcomes.insert(
                        delivery_attempt,
                        ReadbackContractOutcomeV1::ReceiptRecovered,
                    );
                    return ReadbackContractOutcomeV1::ReceiptRecovered;
                }
                ReadbackObservationV1::Unavailable => {
                    self.observation_offsets_ms
                        .insert(delivery_attempt, observed_offsets);
                    return self.retain_unknown_once_v1(delivery_attempt);
                }
                ReadbackObservationV1::Absent | ReadbackObservationV1::ReceivedWithoutReceipt => {}
            }
        }
        self.observation_offsets_ms
            .insert(delivery_attempt, observed_offsets);
        self.retain_unknown_once_v1(delivery_attempt)
    }

    fn retain_unknown_once_v1(&mut self, delivery_attempt: u64) -> ReadbackContractOutcomeV1 {
        let outcome = ReadbackContractOutcomeV1::OutcomeUnknownThenReconciliationRequired;
        self.unknown_transitions += 1;
        self.reconciliation_transitions += 1;
        self.terminal_outcomes.insert(delivery_attempt, outcome);
        outcome
    }
}

#[test]
fn reviewed_overlay_distinguishes_confirmed_no_send_from_possible_handoff() {
    for required in [
        "CREATE TABLE dispatch_delivery_attempts",
        "classification IN ('CONFIRMED_NO_SEND', 'POSSIBLE_HANDOFF', 'ACKNOWLEDGED', 'QUIESCED')",
        "CREATE UNIQUE INDEX dispatch_delivery_attempts_complete_identity_uq",
        "dispatch_delivery_attempts_attempt_uq UNIQUE (grant_id, attempt_number)",
        "dispatch delivery attempts are append-only",
        "dispatch delivery attempts are permanent",
    ] {
        assert!(
            V2_OVERLAY.contains(required),
            "T058 reviewed coordinator overlay omits {required}"
        );
    }

    let mut oracle = AutomaticReadbackOracleV1::default();
    assert_eq!(
        oracle.classify_attempt_v1(
            1,
            HandoffClassificationV1::ConfirmedNoSend,
            1_000,
            2_000,
            2_000,
            &[],
        ),
        ReadbackContractOutcomeV1::PendingExactGrant
    );
    assert_eq!(oracle.started_attempts.len(), 0);

    assert_eq!(
        oracle.classify_attempt_v1(
            2,
            HandoffClassificationV1::PossibleHandoff,
            1_000,
            2_000,
            2_000,
            &[ReadbackObservationV1::Unavailable],
        ),
        ReadbackContractOutcomeV1::OutcomeUnknownThenReconciliationRequired
    );
    assert_eq!(oracle.started_attempts, BTreeSet::from([2]));
}

#[test]
fn automatic_sequence_has_exact_backoffs_offsets_and_all_deadline_bounds() {
    let derived_offsets = AUTOMATIC_READBACK_BACKOFFS_MS_V1
        .into_iter()
        .scan(0_u64, |offset, backoff| {
            *offset += backoff;
            Some(*offset)
        })
        .collect::<Vec<_>>();
    assert_eq!(derived_offsets, AUTOMATIC_READBACK_OFFSETS_MS_V1);
    assert_eq!(
        AUTOMATIC_READBACK_OFFSETS_MS_V1.len(),
        AUTOMATIC_READBACK_MAX_OBSERVATIONS_V1
    );

    assert_eq!(
        readback_bounds_v1(10_000, 20_000, 20_000),
        ReadbackBoundsV1 {
            hard_end_monotonic_ms: 10_500,
            effective_end_monotonic_ms: 10_500,
            eligible_offsets_ms: vec![0, 25, 100, 275],
        }
    );
    assert_eq!(
        readback_bounds_v1(10_000, 10_100, 20_000),
        ReadbackBoundsV1 {
            hard_end_monotonic_ms: 10_500,
            effective_end_monotonic_ms: 10_100,
            eligible_offsets_ms: vec![0, 25],
        },
        "caller deadline equality is exclusive"
    );
    assert_eq!(
        readback_bounds_v1(10_000, 20_000, 10_025),
        ReadbackBoundsV1 {
            hard_end_monotonic_ms: 10_500,
            effective_end_monotonic_ms: 10_025,
            eligible_offsets_ms: vec![0],
        },
        "grant deadline equality is exclusive"
    );
}

#[test]
fn empty_inbox_after_possible_handoff_is_never_definite_absence() {
    let mut oracle = AutomaticReadbackOracleV1::default();
    let outcome = oracle.classify_attempt_v1(
        7,
        HandoffClassificationV1::PossibleHandoff,
        4_000,
        5_000,
        5_000,
        &[
            ReadbackObservationV1::Absent,
            ReadbackObservationV1::Absent,
            ReadbackObservationV1::Absent,
            ReadbackObservationV1::Absent,
        ],
    );

    assert_eq!(
        outcome,
        ReadbackContractOutcomeV1::OutcomeUnknownThenReconciliationRequired
    );
    assert_eq!(
        oracle.observation_offsets_ms.get(&7).map(Vec::as_slice),
        Some(AUTOMATIC_READBACK_OFFSETS_MS_V1.as_slice())
    );
    assert_eq!(oracle.unknown_transitions, 1);
    assert_eq!(oracle.reconciliation_transitions, 1);
}

#[test]
fn exhaustion_or_unavailability_enters_unknown_once_without_an_automatic_loop() {
    for (attempt, observations) in [
        (
            11,
            vec![
                ReadbackObservationV1::ReceivedWithoutReceipt,
                ReadbackObservationV1::Absent,
                ReadbackObservationV1::ReceivedWithoutReceipt,
                ReadbackObservationV1::Absent,
            ],
        ),
        (12, vec![ReadbackObservationV1::Unavailable]),
    ] {
        let mut oracle = AutomaticReadbackOracleV1::default();
        let first = oracle.classify_attempt_v1(
            attempt,
            HandoffClassificationV1::PossibleHandoff,
            1_000,
            2_000,
            2_000,
            &observations,
        );
        let repeated_recovery = oracle.classify_attempt_v1(
            attempt,
            HandoffClassificationV1::PossibleHandoff,
            1_500,
            2_500,
            2_500,
            &[ReadbackObservationV1::RetainedReceipt],
        );

        assert_eq!(
            first,
            ReadbackContractOutcomeV1::OutcomeUnknownThenReconciliationRequired
        );
        assert_eq!(repeated_recovery, first);
        assert_eq!(oracle.started_attempts, BTreeSet::from([attempt]));
        assert_eq!(oracle.unknown_transitions, 1);
        assert_eq!(oracle.reconciliation_transitions, 1);
    }
}

#[test]
fn production_delivery_orchestration_must_own_the_bounded_sequence_contract() {
    let source = required_portable_source(
        "coordinator.rs",
        "T058/T065 possible-handoff automatic readback sequence",
    );

    for required in [
        "AUTOMATIC_READBACK_BACKOFFS_MS_V1",
        "AUTOMATIC_READBACK_OFFSETS_MS_V1",
        "AUTOMATIC_READBACK_MAX_OBSERVATIONS_V1",
        "AUTOMATIC_READBACK_BUDGET_MS_V1",
        "run_automatic_readback_once_v1",
        "ConfirmedNoSend",
        "PossibleHandoff",
        "DispatchInboxReadbackOutcomeV1::Absent",
        "DispatchInboxReadbackOutcomeV1::Unavailable",
        "ReadbackExhausted",
        "ReadbackUnavailable",
        "PossibleConsumption",
        "caller_deadline_monotonic_ms",
        "grant_deadline_monotonic_ms",
    ] {
        assert!(
            source.contains(required),
            "T058 RED: production delivery/readback orchestration omits {required}"
        );
    }
    for forbidden in [
        "replacement_grant",
        "new_grant_after_handoff",
        "AbsentMeansDefinitelyAbsent",
        "restart_automatic_readback_sequence",
    ] {
        assert!(
            !source.contains(forbidden),
            "T058: delivery ambiguity crosses the one-shot boundary through {forbidden}"
        );
    }
}

fn required_portable_source(file: &str, contract: &str) -> String {
    let coordinator_crate = Path::new(env!("CARGO_MANIFEST_DIR"));
    let kernel = coordinator_crate
        .parent()
        .expect("coordinator crate is a direct kernel member");
    let path = kernel.join("helix-plan-dispatch").join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T058 RED: missing portable module {} required for {contract}: {error}",
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
    assert_eq!(block_depth, 0, "T058 source comments are balanced");
    output
}
