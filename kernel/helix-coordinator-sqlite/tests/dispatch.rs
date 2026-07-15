//! PLAN-005 T021 lookup-only durable reload contracts.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const V1_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);
const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReloadCaseV1 {
    id: &'static str,
    required_marker: &'static str,
    evidence_source: &'static str,
}

const RELOAD_CASES: [ReloadCaseV1; 6] = [
    ReloadCaseV1 {
        id: "missing",
        required_marker: "Missing",
        evidence_source: "prepared_operations",
    },
    ReloadCaseV1 {
        id: "torn",
        required_marker: "Torn",
        evidence_source: "preparation_comparisons",
    },
    ReloadCaseV1 {
        id: "restored",
        required_marker: "Restored",
        evidence_source: "root_lifecycle_state",
    },
    ReloadCaseV1 {
        id: "failed",
        required_marker: "Failed",
        evidence_source: "operation_state",
    },
    ReloadCaseV1 {
        id: "quarantined",
        required_marker: "Quarantined",
        evidence_source: "preparation_quarantines",
    },
    ReloadCaseV1 {
        id: "already-overlaid",
        required_marker: "PriorExactDispatch",
        evidence_source: "dispatch_records",
    },
];

#[test]
fn reviewed_schemas_retain_every_reload_evidence_domain() {
    assert!(V1_SCHEMA.contains("CREATE TABLE prepared_operations"));
    assert!(V1_SCHEMA.contains("CREATE TABLE preparation_comparisons"));
    assert!(V1_SCHEMA.contains("CREATE TABLE preparation_quarantines"));
    assert!(V1_SCHEMA.contains("operation_state IN ('PREPARING', 'FAILED')"));
    assert!(V2_OVERLAY.contains("CREATE TABLE dispatch_records"));
    assert!(V2_OVERLAY.contains("root_lifecycle_state = 'RESTORE_PENDING'"));
    assert!(V2_OVERLAY.contains("preparation_state = 'PREPARING'"));

    let ids = RELOAD_CASES
        .iter()
        .map(|case| case.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), RELOAD_CASES.len());
    for case in RELOAD_CASES {
        assert!(
            V1_SCHEMA.contains(case.evidence_source) || V2_OVERLAY.contains(case.evidence_source),
            "{} lacks its reviewed durable evidence source {}",
            case.id,
            case.evidence_source
        );
    }
}

#[test]
fn authoritative_reload_is_lookup_only_and_exhaustively_classifies_non_current_state() {
    let source = required_production_source(
        "dispatch_preflight.rs",
        "T021/T028 authoritative lookup-only dispatch reload",
    );

    for required in [
        "DispatchLookupRequestV1",
        "reload_authoritative_v1",
        "prepared_operations",
        "preparation_comparisons",
        "replay_claim",
        "budget_reservations",
        "preparation_recovery_evidence",
        "preparation_events",
        "preparation_quarantines",
        "dispatch_records",
        "expected_plan",
        "expected_preparation_attempt",
        "expected_preparation_transition_generation",
    ] {
        assert!(
            source.contains(required),
            "T021 RED: dispatch_preflight.rs must reload and compare {required}"
        );
    }
    for case in RELOAD_CASES {
        assert!(
            source.contains(case.required_marker),
            "T021 RED: durable reload omits the closed {} classification marker {}",
            case.id,
            case.required_marker
        );
    }
    for forbidden in [
        "PreparedOperationV1",
        "ExecutionGrantInputV1",
        "SignedExecutionReceiptV1",
        "caller_prepared",
        "caller_row",
    ] {
        assert!(
            !source.contains(forbidden),
            "T021: lookup preflight accepts forbidden caller-positive surface {forbidden}"
        );
    }
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T021 RED: missing production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
