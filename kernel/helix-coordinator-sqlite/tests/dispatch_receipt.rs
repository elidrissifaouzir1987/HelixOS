//! PLAN-005 T044 coordinator receipt verification and state-advance contracts.

use std::fs;
use std::path::Path;

const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EffectiveDispatchStateV1 {
    Dispatching,
    Executing,
    OutcomeUnknown,
    ReconciliationRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptAdvanceV1 {
    AdvanceToExecuting,
    RetainForReconciliation,
    RejectBinding,
}

fn classify_consumed_receipt_v1(
    state: EffectiveDispatchStateV1,
    exact_bindings: bool,
    decided_before_exclusive_deadline: bool,
) -> ReceiptAdvanceV1 {
    if !exact_bindings || !decided_before_exclusive_deadline {
        return ReceiptAdvanceV1::RejectBinding;
    }
    match state {
        EffectiveDispatchStateV1::Dispatching => ReceiptAdvanceV1::AdvanceToExecuting,
        EffectiveDispatchStateV1::OutcomeUnknown
        | EffectiveDispatchStateV1::ReconciliationRequired => {
            ReceiptAdvanceV1::RetainForReconciliation
        }
        EffectiveDispatchStateV1::Executing => ReceiptAdvanceV1::RejectBinding,
    }
}

#[test]
fn reviewed_overlay_retains_exact_receipt_before_the_executing_transition() {
    for required in [
        "CREATE TABLE dispatch_receipts",
        "canonical_receipt BLOB NOT NULL",
        "receipt_digest BLOB NOT NULL",
        "CREATE UNIQUE INDEX dispatch_receipts_grant_uq",
        "CREATE UNIQUE INDEX dispatch_receipts_operation_uq",
        "CREATE UNIQUE INDEX dispatch_receipts_digest_uq",
        "previous_state = 'DISPATCHING' AND new_state = 'EXECUTING'",
        "receipt_decision = 'CONSUMED'",
        "dispatch receipts are append-only",
        "dispatch receipts are permanent",
    ] {
        assert!(
            V2_OVERLAY.contains(required),
            "T044 reviewed coordinator overlay omits {required}"
        );
    }
}

#[test]
fn only_an_exact_timely_consumed_receipt_advances_current_dispatching_state() {
    assert_eq!(
        classify_consumed_receipt_v1(EffectiveDispatchStateV1::Dispatching, true, true),
        ReceiptAdvanceV1::AdvanceToExecuting
    );
    assert_eq!(
        classify_consumed_receipt_v1(EffectiveDispatchStateV1::Dispatching, false, true),
        ReceiptAdvanceV1::RejectBinding
    );
    assert_eq!(
        classify_consumed_receipt_v1(EffectiveDispatchStateV1::Dispatching, true, false),
        ReceiptAdvanceV1::RejectBinding
    );
    assert_eq!(
        classify_consumed_receipt_v1(EffectiveDispatchStateV1::Executing, true, true),
        ReceiptAdvanceV1::RejectBinding
    );
}

#[test]
fn consumed_receipt_after_unknown_never_jumps_back_to_executing() {
    for state in [
        EffectiveDispatchStateV1::OutcomeUnknown,
        EffectiveDispatchStateV1::ReconciliationRequired,
    ] {
        assert_eq!(
            classify_consumed_receipt_v1(state, true, true),
            ReceiptAdvanceV1::RetainForReconciliation
        );
    }
    assert!(V2_OVERLAY.contains("OUTCOME_UNKNOWN"));
    assert!(V2_OVERLAY.contains("RECONCILIATION_REQUIRED"));
}

#[test]
fn production_receipt_path_verifies_then_commits_one_exact_state_advance() {
    let source = required_production_source(
        "dispatch_receipt.rs",
        "T044/T052 strict coordinator receipt verification and atomic state advance",
    );

    for required in [
        "decode_and_verify_execution_receipt_v1",
        "ReceiptVerificationBindingsV1",
        "AuthenticExecutionReceiptV1",
        "TransactionBehavior::Immediate",
        "dispatch_receipts",
        "canonical_receipt",
        "dispatch_records",
        "dispatch_transitions",
        "dispatch_outbox",
        "dispatch_events",
        "DISPATCHING",
        "EXECUTING",
        "OUTCOME_UNKNOWN",
        "RECONCILIATION_REQUIRED",
        "CONSUMED",
        "ACKNOWLEDGED",
    ] {
        assert!(
            source.contains(required),
            "T044 RED: coordinator receipt implementation omits {required}"
        );
    }

    for forbidden in [
        "execute_effect",
        "host_effect",
        "ExecutionToken",
        "execution_token",
        "SUCCESS",
        "settle_budget",
        "release_reservation",
    ] {
        assert!(
            !source.contains(forbidden),
            "T044: receipt state advance crosses the no-effect boundary through {forbidden}"
        );
    }
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T044 RED: missing production module {} required for {contract}: {error}",
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
    assert_eq!(block_depth, 0, "T044 source comments are balanced");
    output
}
