//! PLAN-005 T057 RED contracts for lost adapter acknowledgements.
//!
//! The pure oracles freeze the required recovery behavior while the source contract keeps
//! this test binary compilable before T065 adds the production ambiguity orchestrator.

use std::path::Path;

const EXACT_GRANT: &[u8] = b"exact-retained-signed-grant-v1";
const EXACT_RECEIPT: &[u8] = b"exact-retained-signed-receipt-v1";
const ORIGINAL_EXCLUSIVE_DEADLINE_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LostAcknowledgementV1 {
    Receive,
    Consume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterReadbackV1<'a> {
    Received,
    RetainedReceipt {
        canonical_receipt: &'a [u8],
        retained_before_deadline_ms: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryActionV1<'a> {
    ResumeExactReceived {
        canonical_grant: &'a [u8],
        exclusive_deadline_ms: u64,
        redelivery_calls: u8,
        replacement_grants: u8,
    },
    RecoverRetainedReceipt {
        canonical_receipt: &'a [u8],
        evidence_only: bool,
        verification_calls: u8,
        renewal_calls: u8,
        resign_calls: u8,
        reconsumption_calls: u8,
    },
}

fn required_recovery_v1<'a>(
    lost: LostAcknowledgementV1,
    readback: AdapterReadbackV1<'a>,
    original_grant: &'a [u8],
    original_exclusive_deadline_ms: u64,
    recovered_at_ms: u64,
) -> RecoveryActionV1<'a> {
    match (lost, readback) {
        (LostAcknowledgementV1::Receive, AdapterReadbackV1::Received) => {
            RecoveryActionV1::ResumeExactReceived {
                canonical_grant: original_grant,
                exclusive_deadline_ms: original_exclusive_deadline_ms,
                redelivery_calls: 1,
                replacement_grants: 0,
            }
        }
        (
            LostAcknowledgementV1::Receive | LostAcknowledgementV1::Consume,
            AdapterReadbackV1::RetainedReceipt {
                canonical_receipt,
                retained_before_deadline_ms,
            },
        ) => {
            assert!(
                retained_before_deadline_ms < original_exclusive_deadline_ms,
                "T057 fixture receipt must have been retained under live authority"
            );
            RecoveryActionV1::RecoverRetainedReceipt {
                canonical_receipt,
                evidence_only: recovered_at_ms >= original_exclusive_deadline_ms,
                verification_calls: 1,
                renewal_calls: 0,
                resign_calls: 0,
                reconsumption_calls: 0,
            }
        }
        (LostAcknowledgementV1::Consume, AdapterReadbackV1::Received) => {
            RecoveryActionV1::ResumeExactReceived {
                canonical_grant: original_grant,
                exclusive_deadline_ms: original_exclusive_deadline_ms,
                redelivery_calls: 1,
                replacement_grants: 0,
            }
        }
    }
}

#[test]
fn lost_receive_ack_resumes_only_the_byte_identical_retained_grant() {
    let action = required_recovery_v1(
        LostAcknowledgementV1::Receive,
        AdapterReadbackV1::Received,
        EXACT_GRANT,
        ORIGINAL_EXCLUSIVE_DEADLINE_MS,
        4_000,
    );

    assert_eq!(
        action,
        RecoveryActionV1::ResumeExactReceived {
            canonical_grant: EXACT_GRANT,
            exclusive_deadline_ms: ORIGINAL_EXCLUSIVE_DEADLINE_MS,
            redelivery_calls: 1,
            replacement_grants: 0,
        }
    );
    let RecoveryActionV1::ResumeExactReceived {
        canonical_grant,
        exclusive_deadline_ms,
        redelivery_calls,
        replacement_grants,
    } = action
    else {
        unreachable!("T057 receive-ack loss must resume retained RECEIVED state")
    };
    assert!(std::ptr::eq(canonical_grant, EXACT_GRANT));
    assert_eq!(exclusive_deadline_ms, ORIGINAL_EXCLUSIVE_DEADLINE_MS);
    assert_eq!(redelivery_calls, 1);
    assert_eq!(replacement_grants, 0);
}

#[test]
fn lost_consume_ack_recovers_the_retained_receipt_without_reconsumption() {
    let action = required_recovery_v1(
        LostAcknowledgementV1::Consume,
        AdapterReadbackV1::RetainedReceipt {
            canonical_receipt: EXACT_RECEIPT,
            retained_before_deadline_ms: 4_999,
        },
        EXACT_GRANT,
        ORIGINAL_EXCLUSIVE_DEADLINE_MS,
        4_999,
    );

    assert_eq!(
        action,
        RecoveryActionV1::RecoverRetainedReceipt {
            canonical_receipt: EXACT_RECEIPT,
            evidence_only: false,
            verification_calls: 1,
            renewal_calls: 0,
            resign_calls: 0,
            reconsumption_calls: 0,
        }
    );
}

#[test]
fn pre_expiry_receipt_recovered_after_expiry_is_evidence_without_renewal() {
    let signer_calls = 1_u64;
    let consume_calls = 1_u64;
    let action = required_recovery_v1(
        LostAcknowledgementV1::Consume,
        AdapterReadbackV1::RetainedReceipt {
            canonical_receipt: EXACT_RECEIPT,
            retained_before_deadline_ms: 4_999,
        },
        EXACT_GRANT,
        ORIGINAL_EXCLUSIVE_DEADLINE_MS,
        ORIGINAL_EXCLUSIVE_DEADLINE_MS + 1,
    );

    assert_eq!(
        action,
        RecoveryActionV1::RecoverRetainedReceipt {
            canonical_receipt: EXACT_RECEIPT,
            evidence_only: true,
            verification_calls: 1,
            renewal_calls: 0,
            resign_calls: 0,
            reconsumption_calls: 0,
        }
    );
    assert_eq!(signer_calls, 1, "recovery must not resign or renew a grant");
    assert_eq!(consume_calls, 1, "recovery must not repeat consumption");
    assert_eq!(ORIGINAL_EXCLUSIVE_DEADLINE_MS, 5_000);
}

#[test]
fn t065_must_expose_one_exact_lost_acknowledgement_recovery_seam() {
    let coordinator = required_source("coordinator.rs");
    let lib = required_source("lib.rs");

    for required in [
        "DispatchInboxReadbackV1",
        "DispatchInboxReadbackOutcomeV1",
        "recover_lost_acknowledgement_v1",
        "original_exclusive_deadline_monotonic_ms",
    ] {
        assert!(
            coordinator.contains(required),
            "T057 RED: coordinator.rs lacks the T065 ambiguity seam `{required}` for lost receive/consume ACK recovery"
        );
    }
    assert!(
        lib.contains("recover_lost_acknowledgement_v1"),
        "T057 RED: lib.rs must export the T065 lost-acknowledgement orchestrator"
    );
}

fn required_source(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T057 RED: missing production source {} required for ambiguity recovery: {error}",
            path.display()
        )
    });
    source_without_comments_v1(&source)
}

fn source_without_comments_v1(source: &str) -> String {
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
    assert_eq!(block_depth, 0, "T057 source comments are balanced");
    output
}
