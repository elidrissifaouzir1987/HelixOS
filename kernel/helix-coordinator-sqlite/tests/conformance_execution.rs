//! T066 private fault-corpus execution against the frozen Feature 004 corpus.
//!
//! Run this target with `--features test-fault-injection -- --test-threads=1`.
//! The corpus and the two private taxonomies are authoritative; this test never
//! selects a fault through an environment variable, process global, or target-OS
//! branch. T074 must replace the remaining no-op hook seam with explicitly carried
//! caller-owned sessions. The dedicated RED below names that missing work rather than
//! pretending that iterating a registry has exercised a production checkpoint.

#![cfg(feature = "test-fault-injection")]

#[path = "../src/test_fault.rs"]
mod coordinator_test_fault;
#[path = "../../helix-plan-preparation/src/test_fault.rs"]
mod portable_test_fault;

use coordinator_test_fault::{
    FaultBoundaryV1 as CoordinatorBoundaryV1, FaultDecisionV1, FaultEffectV1, FaultSelectionV1,
    FaultSessionV1,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/cases.json");
const EXPECTED_OUTCOMES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/expected-outcomes.json");
const COORDINATOR_FAULT_SOURCE: &str = include_str!("../src/test_fault.rs");
const PORTABLE_FAULT_SOURCE: &str = include_str!("../../helix-plan-preparation/src/test_fault.rs");
const CASES_SHA256: &str = "086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d";
const EXPECTED_OUTCOMES_SHA256: &str =
    "87bd23eeed048fe47ca4f785d17cdca80364454bae30c81dc4b3e9e7ecf3ac2b";
const CONTROLLED_MATERIAL_PACKAGES: u64 = 3;
const CONTROLLED_RETIREMENT_TOMBSTONES: u64 = 2;
const CONTROLLED_RESTORE_PACKAGES: u64 = 4;

#[derive(Debug, Deserialize)]
struct CasesCorpusV1 {
    schema: String,
    counts: serde_json::Value,
    fault_boundaries: Vec<FaultBoundaryRowV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultBoundaryRowV1 {
    boundary_id: String,
    expected_registry_occurrences: u64,
    multiplicity: String,
    order: u64,
    owner: String,
    phase: String,
    prepared_success_occurrences: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedCorpusV1 {
    cases: Vec<ExpectedProjectionV1>,
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedProjectionV1 {
    case_id: String,
    code: String,
    event_generation_delta: String,
    operation_generation_delta: String,
    outcome: String,
    recovery_may_remain_quarantined: bool,
    recovery_provider_calls: ProviderCallsV1,
    replay_claim_released: bool,
    reservation_generation_delta: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCallsV1 {
    acquire: u64,
    prepare: u64,
    total: u64,
    verify: u64,
}

fn decode_cases_v1() -> CasesCorpusV1 {
    serde_json::from_slice(CASES_BYTES).expect("T061 cases corpus decodes")
}

fn decode_expected_v1() -> ExpectedCorpusV1 {
    serde_json::from_slice(EXPECTED_OUTCOMES_BYTES).expect("T061 expected corpus decodes")
}

fn sha256_hex_v1(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn production_source_v1(source: &'static str) -> &'static str {
    source
        .split_once("#[cfg(test)]")
        .expect("private source retains a test-module delimiter")
        .0
}

fn occurrences_v1(source: &str, needle: &str) -> usize {
    source.match_indices(needle).count()
}

fn controlled_occurrences_v1(row: &FaultBoundaryRowV1) -> u64 {
    match row.multiplicity.as_str() {
        "unit" => 1,
        "preliminary-groups" => 12,
        "final-guards" => 10,
        "final-groups" => 12,
        "commit-members" => 8,
        "material-packages" => CONTROLLED_MATERIAL_PACKAGES,
        "retirement-tombstones" => CONTROLLED_RETIREMENT_TOMBSTONES,
        "restore-packages" => CONTROLLED_RESTORE_PACKAGES,
        other => panic!("unknown T061 multiplicity {other}"),
    }
}

fn assert_strictly_sorted_unique_v1(values: impl IntoIterator<Item = String>) {
    let values = values.into_iter().collect::<Vec<_>>();
    assert!(
        values.windows(2).all(|pair| pair[0] < pair[1]),
        "T061 projection IDs remain strictly ASCII-sorted and unique"
    );
}

fn increment_v1(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_owned()).or_default() += 1;
}

#[test]
fn frozen_registry_is_the_exact_private_123_id_partition() {
    let corpus = decode_cases_v1();
    assert_eq!(corpus.schema, "helixos.durable-preparation-cases/1");
    assert_eq!(corpus.fault_boundaries.len(), 123);
    assert_eq!(corpus.counts["fault_boundary_count"], 123);

    let coordinator_ids = CoordinatorBoundaryV1::ALL
        .iter()
        .map(|boundary| boundary.id())
        .collect::<BTreeSet<_>>();
    let portable_ids = portable_test_fault::FaultBoundaryV1::ALL
        .iter()
        .map(|boundary| boundary.id())
        .collect::<BTreeSet<_>>();
    assert_eq!(coordinator_ids.len(), 86);
    assert_eq!(portable_ids.len(), 37);
    assert!(coordinator_ids.is_disjoint(&portable_ids));

    let coordinator_source = production_source_v1(COORDINATOR_FAULT_SOURCE);
    let portable_source = production_source_v1(PORTABLE_FAULT_SOURCE);
    let mut corpus_ids = BTreeSet::new();
    let mut phase_counts = BTreeMap::new();
    let mut owner_counts = BTreeMap::new();
    let mut prepared_checkpoint_count = 0_u64;

    for (index, row) in corpus.fault_boundaries.iter().enumerate() {
        assert_eq!(row.order, index as u64 + 1);
        assert_eq!(row.expected_registry_occurrences, 1);
        assert!(corpus_ids.insert(row.boundary_id.as_str()));
        increment_v1(&mut phase_counts, &row.phase);
        increment_v1(&mut owner_counts, &row.owner);
        prepared_checkpoint_count = prepared_checkpoint_count
            .checked_add(row.prepared_success_occurrences)
            .expect("prepared checkpoint sum remains safe");

        let quoted = format!("\"{}\"", row.boundary_id);
        match row.owner.as_str() {
            "coordinator" => {
                assert!(coordinator_ids.contains(row.boundary_id.as_str()));
                assert_eq!(occurrences_v1(coordinator_source, &quoted), 1);
                assert_eq!(occurrences_v1(portable_source, &quoted), 0);
            }
            "portable" => {
                assert!(portable_ids.contains(row.boundary_id.as_str()));
                assert_eq!(occurrences_v1(portable_source, &quoted), 1);
                assert_eq!(occurrences_v1(coordinator_source, &quoted), 0);
            }
            other => panic!("unknown T061 boundary owner {other}"),
        }
    }

    assert_eq!(corpus_ids.len(), 123);
    assert_eq!(
        owner_counts,
        BTreeMap::from([("coordinator".into(), 86), ("portable".into(), 37)])
    );
    assert_eq!(
        phase_counts,
        BTreeMap::from([
            ("acknowledgement-and-readback".into(), 12),
            ("backup".into(), 23),
            ("final-comparison".into(), 14),
            ("known-failure".into(), 12),
            ("positive-coordinator-commit".into(), 15),
            ("preliminary".into(), 10),
            ("quarantine-and-retirement".into(), 10),
            ("recovery".into(), 13),
            ("restore".into(), 14),
        ])
    );
    assert_eq!(prepared_checkpoint_count, 93);
}

#[test]
fn coordinator_private_session_executes_every_selected_occurrence_serially() {
    let corpus = decode_cases_v1();
    let rows = corpus
        .fault_boundaries
        .iter()
        .filter(|row| row.owner == "coordinator")
        .collect::<Vec<_>>();
    let mut executions = 0_u64;

    for boundary in CoordinatorBoundaryV1::ALL {
        let row = rows
            .iter()
            .copied()
            .find(|row| row.boundary_id == boundary.id())
            .expect("each private coordinator boundary exists in T061");
        for selected_occurrence in 1..=controlled_occurrences_v1(row) {
            let selection = FaultSelectionV1::try_new(
                *boundary,
                selected_occurrence,
                FaultEffectV1::ReturnError,
            )
            .expect("every controlled occurrence is nonzero");
            let mut session = FaultSessionV1::selected_v1(selection);

            for _ in 1..selected_occurrence {
                assert_eq!(session.checkpoint_v1(*boundary), FaultDecisionV1::Continue);
            }
            assert_eq!(
                session.checkpoint_v1(*boundary),
                FaultDecisionV1::Inject(FaultEffectV1::ReturnError)
            );
            assert_eq!(
                session.checkpoint_v1(*boundary),
                FaultDecisionV1::Continue,
                "one private selection injects at most once"
            );
            assert_eq!(
                format!("{selection:?}"),
                format!(
                    "FaultSelectionV1 {{ boundary: \"{}\", occurrence: {}, effect: RETURN_ERROR }}",
                    boundary.id(),
                    selected_occurrence
                )
            );
            executions += 1;
        }
    }

    // 86 coordinator IDs plus seven extra commit-member occurrences and the
    // controlled M-1, T-1 and P-1 package occurrences.
    assert_eq!(executions, 99);
}

#[test]
fn expected_projection_bytes_counts_and_redacted_fields_are_stable() {
    let cases_value: serde_json::Value =
        serde_json::from_slice(CASES_BYTES).expect("T061 cases JSON decodes");
    let expected_value: serde_json::Value =
        serde_json::from_slice(EXPECTED_OUTCOMES_BYTES).expect("T061 expected JSON decodes");
    assert_eq!(
        serde_json_canonicalizer::to_vec(&cases_value).expect("cases JCS"),
        CASES_BYTES
    );
    assert_eq!(
        serde_json_canonicalizer::to_vec(&expected_value).expect("expected JCS"),
        EXPECTED_OUTCOMES_BYTES
    );
    assert_eq!(sha256_hex_v1(CASES_BYTES), CASES_SHA256);
    assert_eq!(
        sha256_hex_v1(EXPECTED_OUTCOMES_BYTES),
        EXPECTED_OUTCOMES_SHA256
    );

    let expected = decode_expected_v1();
    assert_eq!(expected.schema, "helixos.durable-preparation-summary/1");
    assert_eq!(expected.cases.len(), 335);
    assert_strictly_sorted_unique_v1(expected.cases.iter().map(|row| row.case_id.clone()));

    let allowed_outcomes = BTreeSet::from(["ambiguous", "denied", "failed", "prepared"]);
    let allowed_deltas = BTreeSet::from(["one", "zero", "zero-or-one"]);
    let mut outcome_counts = BTreeMap::new();
    let mut delta_counts = BTreeMap::new();
    let mut quarantine_counts = BTreeMap::new();
    let mut total_call_counts = BTreeMap::new();

    for row in &expected.cases {
        assert!(allowed_outcomes.contains(row.outcome.as_str()));
        assert!(allowed_deltas.contains(row.event_generation_delta.as_str()));
        assert!(allowed_deltas.contains(row.operation_generation_delta.as_str()));
        assert!(allowed_deltas.contains(row.reservation_generation_delta.as_str()));
        assert!(!row.replay_claim_released);
        assert!(!row.code.is_empty());
        assert_eq!(
            row.recovery_provider_calls.total,
            row.recovery_provider_calls.acquire
                + row.recovery_provider_calls.prepare
                + row.recovery_provider_calls.verify
        );
        assert_eq!(row.event_generation_delta, row.operation_generation_delta);
        assert_eq!(row.event_generation_delta, row.reservation_generation_delta);
        increment_v1(&mut outcome_counts, &row.outcome);
        increment_v1(&mut delta_counts, &row.event_generation_delta);
        increment_v1(
            &mut quarantine_counts,
            if row.recovery_may_remain_quarantined {
                "true"
            } else {
                "false"
            },
        );
        increment_v1(
            &mut total_call_counts,
            &row.recovery_provider_calls.total.to_string(),
        );
    }

    assert_eq!(
        outcome_counts,
        BTreeMap::from([
            ("ambiguous".into(), 12),
            ("denied".into(), 299),
            ("failed".into(), 21),
            ("prepared".into(), 3),
        ])
    );
    assert_eq!(
        delta_counts,
        BTreeMap::from([
            ("one".into(), 3),
            ("zero".into(), 323),
            ("zero-or-one".into(), 9),
        ])
    );
    assert_eq!(
        quarantine_counts,
        BTreeMap::from([("false".into(), 105), ("true".into(), 230)])
    );
    assert_eq!(
        total_call_counts,
        BTreeMap::from([
            ("0".into(), 101),
            ("1".into(), 2),
            ("2".into(), 16),
            ("3".into(), 189),
            ("5".into(), 27),
        ])
    );
}

#[test]
fn fault_selection_is_private_explicit_and_never_ambient() {
    for (name, source) in [
        (
            "coordinator",
            production_source_v1(COORDINATOR_FAULT_SOURCE),
        ),
        ("portable", production_source_v1(PORTABLE_FAULT_SOURCE)),
    ] {
        for forbidden in [
            "std::env",
            "thread_local!",
            "static mut",
            "OnceLock",
            "option_env!",
            "env!",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} private fault selection must not use ambient {forbidden}"
            );
        }
        assert!(!source.contains("pub mod test_fault"));
        assert!(!source.contains("pub enum FaultBoundaryV1"));
    }

    let coordinator_source = production_source_v1(COORDINATOR_FAULT_SOURCE);
    let portable_source = production_source_v1(PORTABLE_FAULT_SOURCE);
    assert!(coordinator_source.contains("struct FaultSelectionV1"));
    assert!(coordinator_source.contains("struct FaultSessionV1"));
    assert!(coordinator_source.contains("std::sync::Arc<std::sync::Mutex<FaultProbeStateV1>>"));
    assert!(portable_source.contains("Arc<Mutex<FaultProbeStateV1>>"));

    // T074 RED: registry iteration or `reach` with a discarded argument is not fault
    // execution. Both owners must accept explicitly carried caller-owned selection
    // custody before the process-kill matrix can claim a real checkpoint.
    let portable_has_session = portable_source.contains("struct FaultSelectionV1")
        && portable_source.contains("struct FaultSessionV1");
    let no_owner_has_a_noop_reach = !coordinator_source.contains("let _ = boundary;")
        && !portable_source.contains("let _ = boundary;");
    assert!(
        portable_has_session && no_owner_has_a_noop_reach,
        "T074 RED: add an explicit caller-owned portable fault session and remove both no-op reach seams; do not add an environment/global selector"
    );
}
