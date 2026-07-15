//! PLAN-005 T059 RED contracts for fenced definite-absence classification.
//!
//! Empty or unavailable inbox readback is intentionally absent from this oracle: only one
//! exact, healthy, fenced and quiesced proof may classify definite absence.

use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DefiniteAbsenceEvidenceV1 {
    transport_fenced: bool,
    transport_quiesced: bool,
    adapter_healthy: bool,
    expected_adapter_root: [u8; 32],
    observed_adapter_root: [u8; 32],
    expected_supervisor_epoch: u64,
    observed_supervisor_epoch: u64,
    expected_delivery_attempt_id: [u8; 32],
    observed_delivery_attempt_id: [u8; 32],
    authoritative_handoff_generation: u64,
    observed_readback_generation: u64,
    exclusive_deadline_monotonic_ms: u64,
    observed_monotonic_ms: u64,
}

fn definite_absence_is_proved_v1(evidence: DefiniteAbsenceEvidenceV1) -> bool {
    evidence.transport_fenced
        && evidence.transport_quiesced
        && evidence.adapter_healthy
        && evidence.observed_adapter_root == evidence.expected_adapter_root
        && evidence.observed_supervisor_epoch == evidence.expected_supervisor_epoch
        && evidence.observed_delivery_attempt_id == evidence.expected_delivery_attempt_id
        && evidence.observed_readback_generation == evidence.authoritative_handoff_generation
        && evidence.observed_monotonic_ms >= evidence.exclusive_deadline_monotonic_ms
}

fn exact_valid_evidence_v1() -> DefiniteAbsenceEvidenceV1 {
    DefiniteAbsenceEvidenceV1 {
        transport_fenced: true,
        transport_quiesced: true,
        adapter_healthy: true,
        expected_adapter_root: [0x31; 32],
        observed_adapter_root: [0x31; 32],
        expected_supervisor_epoch: 7,
        observed_supervisor_epoch: 7,
        expected_delivery_attempt_id: [0x41; 32],
        observed_delivery_attempt_id: [0x41; 32],
        authoritative_handoff_generation: 11,
        observed_readback_generation: 11,
        exclusive_deadline_monotonic_ms: 5_000,
        observed_monotonic_ms: 5_000,
    }
}

#[test]
fn exact_fenced_quiesced_root_epoch_generation_and_closed_deadline_proves_absence() {
    assert!(definite_absence_is_proved_v1(exact_valid_evidence_v1()));
}

#[test]
fn removing_any_required_absence_binding_fails_closed() {
    let exact = exact_valid_evidence_v1();
    let mutations = [
        DefiniteAbsenceEvidenceV1 {
            transport_fenced: false,
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            transport_quiesced: false,
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            adapter_healthy: false,
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            observed_adapter_root: [0x32; 32],
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            observed_supervisor_epoch: exact.expected_supervisor_epoch + 1,
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            observed_delivery_attempt_id: [0x42; 32],
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            observed_readback_generation: exact.authoritative_handoff_generation - 1,
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            observed_readback_generation: exact.authoritative_handoff_generation + 1,
            ..exact
        },
        DefiniteAbsenceEvidenceV1 {
            observed_monotonic_ms: exact.exclusive_deadline_monotonic_ms - 1,
            ..exact
        },
    ];

    for (index, mutation) in mutations.into_iter().enumerate() {
        assert!(
            !definite_absence_is_proved_v1(mutation),
            "T059 absence mutation {index} must remain unknown/reconcilable"
        );
    }
}

#[test]
fn deadline_is_exclusive_and_equality_is_the_first_closed_instant() {
    let exact = exact_valid_evidence_v1();
    assert!(definite_absence_is_proved_v1(exact));
    assert!(!definite_absence_is_proved_v1(DefiniteAbsenceEvidenceV1 {
        observed_monotonic_ms: exact.exclusive_deadline_monotonic_ms - 1,
        ..exact
    }));
}

#[test]
fn t066_must_compile_one_fenced_definite_absence_classifier() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let reconciliation_path = manifest.join("src/reconciliation.rs");
    let reconciliation = std::fs::read_to_string(&reconciliation_path).unwrap_or_else(|error| {
        panic!(
            "T059 RED: missing {} for T066 fenced/quiesced definite-absence classification: {error}",
            reconciliation_path.display()
        )
    });
    let production = source_without_comments_v1(&reconciliation);
    let lib = std::fs::read_to_string(manifest.join("src/lib.rs"))
        .expect("T059 crate root remains readable");

    assert!(
        lib.contains("mod reconciliation;"),
        "T059 RED: reconciliation.rs must be compiled into helix-plan-dispatch"
    );
    for required in [
        "DispatchDefiniteAbsenceEvidenceV1",
        "classify_definite_absence_v1",
        "transport_fenced",
        "transport_quiesced",
        "adapter_root",
        "supervisor_epoch",
        "delivery_attempt_id",
        "readback_generation",
        "exclusive_deadline_monotonic_ms",
    ] {
        assert!(
            production.contains(required),
            "T059 RED: reconciliation.rs lacks required definite-absence binding `{required}`"
        );
    }
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
    assert_eq!(block_depth, 0, "T059 source comments are balanced");
    output
}
