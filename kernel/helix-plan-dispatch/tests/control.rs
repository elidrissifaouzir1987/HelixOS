//! PLAN-005 T061 RED contracts for cancellation, PAUSE, and audit ordering.
//!
//! Before handoff these controls prevent a new delivery. Once handoff is possible they can
//! only preserve authority evidence and route to readback/reconciliation; they can never
//! manufacture confirmed absence or a pre-dispatch failure.

use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeliveryBoundaryV1 {
    BeforeHandoff,
    PossibleHandoff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlObservationV1 {
    CancellationRequested,
    PauseRequested,
    AuditUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequiredControlDispositionV1 {
    PreventNewDeliveryRetainGrant,
    PreventNewDeliveryAuditBlockedRetainGrant,
    PreserveGrantAndRequireReadback,
    PreserveGrantAuditPendingUnknown,
}

fn required_control_disposition_v1(
    boundary: DeliveryBoundaryV1,
    observation: ControlObservationV1,
) -> RequiredControlDispositionV1 {
    match (boundary, observation) {
        (
            DeliveryBoundaryV1::BeforeHandoff,
            ControlObservationV1::CancellationRequested | ControlObservationV1::PauseRequested,
        ) => RequiredControlDispositionV1::PreventNewDeliveryRetainGrant,
        (DeliveryBoundaryV1::BeforeHandoff, ControlObservationV1::AuditUnavailable) => {
            RequiredControlDispositionV1::PreventNewDeliveryAuditBlockedRetainGrant
        }
        (
            DeliveryBoundaryV1::PossibleHandoff,
            ControlObservationV1::CancellationRequested | ControlObservationV1::PauseRequested,
        ) => RequiredControlDispositionV1::PreserveGrantAndRequireReadback,
        (DeliveryBoundaryV1::PossibleHandoff, ControlObservationV1::AuditUnavailable) => {
            RequiredControlDispositionV1::PreserveGrantAuditPendingUnknown
        }
    }
}

#[test]
fn cancellation_and_pause_prevent_delivery_only_before_handoff() {
    for control in [
        ControlObservationV1::CancellationRequested,
        ControlObservationV1::PauseRequested,
    ] {
        assert_eq!(
            required_control_disposition_v1(DeliveryBoundaryV1::BeforeHandoff, control),
            RequiredControlDispositionV1::PreventNewDeliveryRetainGrant
        );
        assert_eq!(
            required_control_disposition_v1(DeliveryBoundaryV1::PossibleHandoff, control),
            RequiredControlDispositionV1::PreserveGrantAndRequireReadback
        );
    }
}

#[test]
fn audit_failure_before_handoff_fails_closed_but_after_handoff_is_audit_pending_unknown() {
    assert_eq!(
        required_control_disposition_v1(
            DeliveryBoundaryV1::BeforeHandoff,
            ControlObservationV1::AuditUnavailable,
        ),
        RequiredControlDispositionV1::PreventNewDeliveryAuditBlockedRetainGrant
    );
    assert_eq!(
        required_control_disposition_v1(
            DeliveryBoundaryV1::PossibleHandoff,
            ControlObservationV1::AuditUnavailable,
        ),
        RequiredControlDispositionV1::PreserveGrantAuditPendingUnknown
    );
}

#[test]
fn every_post_handoff_control_disposition_preserves_authority_evidence() {
    for control in [
        ControlObservationV1::CancellationRequested,
        ControlObservationV1::PauseRequested,
        ControlObservationV1::AuditUnavailable,
    ] {
        let disposition =
            required_control_disposition_v1(DeliveryBoundaryV1::PossibleHandoff, control);
        assert!(matches!(
            disposition,
            RequiredControlDispositionV1::PreserveGrantAndRequireReadback
                | RequiredControlDispositionV1::PreserveGrantAuditPendingUnknown
        ));
        assert!(
            !matches!(
                disposition,
                RequiredControlDispositionV1::PreventNewDeliveryRetainGrant
                    | RequiredControlDispositionV1::PreventNewDeliveryAuditBlockedRetainGrant
            ),
            "T061 possible handoff must never be rewritten as confirmed no-send"
        );
    }
}

#[test]
fn every_pre_and_post_handoff_control_outcome_retains_committed_grant_evidence() {
    for boundary in [
        DeliveryBoundaryV1::BeforeHandoff,
        DeliveryBoundaryV1::PossibleHandoff,
    ] {
        for observation in [
            ControlObservationV1::CancellationRequested,
            ControlObservationV1::PauseRequested,
            ControlObservationV1::AuditUnavailable,
        ] {
            let disposition = required_control_disposition_v1(boundary, observation);
            assert!(matches!(
                disposition,
                RequiredControlDispositionV1::PreventNewDeliveryRetainGrant
                    | RequiredControlDispositionV1::PreventNewDeliveryAuditBlockedRetainGrant
                    | RequiredControlDispositionV1::PreserveGrantAndRequireReadback
                    | RequiredControlDispositionV1::PreserveGrantAuditPendingUnknown
            ));
        }
    }
}

#[test]
fn t068_must_compile_phase_aware_control_and_audit_pending_custody() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let control_path = manifest.join("src/control.rs");
    let control = std::fs::read_to_string(&control_path).unwrap_or_else(|error| {
        panic!(
            "T061 RED: missing {} for T068 delivery control: {error}",
            control_path.display()
        )
    });
    let production = source_without_comments_v1(&control);
    let lib = std::fs::read_to_string(manifest.join("src/lib.rs"))
        .expect("T061 crate root remains readable");

    for required in [
        "DispatchDeliveryControlPhaseV1",
        "DispatchDeliveryControlOutcomeV1",
        "classify_delivery_control_v1",
        "CancellationRequested",
        "PossibleHandoff",
        "AuditPendingUnknown",
        "RetainGrant",
    ] {
        assert!(
            production.contains(required),
            "T061 RED: control.rs lacks the phase-aware T068 seam `{required}`"
        );
    }
    assert!(
        lib.contains("DispatchDeliveryControlPhaseV1")
            && lib.contains("DispatchDeliveryControlOutcomeV1"),
        "T061 RED: lib.rs must export the phase-aware delivery control outcomes"
    );
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
    assert_eq!(block_depth, 0, "T061 source comments are balanced");
    output
}
