//! Portable drift checker and no-effect lifecycle runner for the frozen PLAN-005 corpus.
//!
//! Its required conformance feature executes the ordinary portable APIs together with the
//! hidden two-store SQLite facade and T077 clean-restore proof, then emits one path-free
//! canonical summary whose production evidence is measured from durable projections.

#![forbid(unsafe_code)]

use helix_coordinator_sqlite::T080ProductionCorpusEvidenceV1;
use helix_dispatch_contracts::{
    decode_and_verify_execution_grant_v1, ContractError as DispatchContractErrorV1,
    GrantKeyResolver, GrantVerificationKeyV1,
};
use helix_plan_dispatch::{
    handoff_exact_grant_once_v1, receive_and_consume_exact_grant_v1,
    recover_lost_acknowledgement_v1, DispatchHandoffGuardV1, DispatchHandoffOutcomeV1,
    DispatchHandoffValidationV1, DispatchInboxAdapterOutcomeV1, DispatchInboxConsumeOutcomeV1,
    DispatchInboxConsumerV1, DispatchInboxReadbackOutcomeV1, DispatchInboxReadbackV1,
    DispatchInboxReceiveOutcomeV1, DispatchInboxV1, DispatchLostAcknowledgementRecoveryV1,
    DispatchReconciliationReasonV1, DispatchTransportV1, DispatchUnknownReasonV1,
};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const CASES_SHA256: &str = "70d91b274d70c974ecd198dc1d70698346fbaa8c9785cd824f0aa2a84427601a";
const EXPECTED_SHA256: &str = "8a34adce4a2d4c20cdc033eb1586d37c7d1281cde3c7645f82b4cc4e401198a4";
const CASES_JCS_SHA256: &str = "5aa36b610d3bc9a8cdf0603a947bb6a97d7c83c77c8d8c30e169734f9e3ad42b";
const EXPECTED_JCS_SHA256: &str =
    "7b9283a4f315319f6cc187c29fc01733c530ae50e7ff4002250e5cbe5161bf78";
const END_TO_END_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-dispatch-v1/end-to-end-cases.json");
const END_TO_END_SHA256: &str = "d075223c2bbf58f0e434796f5aa44058c73f826de7ecec895330f690377bb44c";
const SUMMARY_SHA256: &str = "11341e7c2b0a840d020947111ca0892046f23ca4c799c83b432800224fee99f7";
const CASES_LEN: u64 = 56_529;
const EXPECTED_LEN: u64 = 25_825;
const CASE_COUNT: usize = 143;
const FIXTURE_GRANT_KEY_ID: &str = "fixture-grant-key-v1";
const FIXTURE_GRANT_PUBLIC_KEY: [u8; 32] = [
    167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246, 103,
    165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
];

#[derive(Serialize)]
struct StableSummaryV1 {
    schema: &'static str,
    case_count: u64,
    scenario_count: u64,
    cases_sha256: &'static str,
    end_to_end_cases_sha256: &'static str,
    expected_outcomes_sha256: &'static str,
    subsystem_only: bool,
    production_evidence: ProductionEvidenceSummaryV1,
    scenarios: Vec<ScenarioSummaryV1>,
}

#[derive(Serialize)]
struct ProductionEvidenceSummaryV1 {
    migration_count: u64,
    coordinator_grant_count: u64,
    coordinator_executing_count: u64,
    coordinator_reconciliation_required_count: u64,
    coordinator_receipt_count: u64,
    adapter_grant_count: u64,
    adapter_consumed_count: u64,
    adapter_receipt_count: u64,
    adapter_transition_count: u64,
    replacement_grant_count: u64,
    automatic_redelivery_count: u64,
    execution_authority_object_count: u64,
    clean_restore_verified: bool,
}

#[derive(Serialize)]
struct ScenarioSummaryV1 {
    name: String,
    ordinal: u64,
    execution: String,
    outcome: String,
    effect_authorized: bool,
}

fn main() {
    if let Err(code) = run_v1() {
        eprintln!("durable_dispatch_corpus: {code}");
        std::process::exit(1);
    }
}

fn run_v1() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let cases_path = arguments.next().ok_or("usage-error")?;
    let expected_path = arguments.next().ok_or("usage-error")?;
    if arguments.next().is_some() {
        return Err("usage-error");
    }

    let cases_bytes = read_exact_bounded_v1(Path::new(&cases_path), CASES_LEN)?;
    let expected_bytes = read_exact_bounded_v1(Path::new(&expected_path), EXPECTED_LEN)?;
    let cases = require_pinned_json_v1(&cases_bytes, CASES_SHA256, CASES_JCS_SHA256)?;
    let expected = require_pinned_json_v1(&expected_bytes, EXPECTED_SHA256, EXPECTED_JCS_SHA256)?;
    let end_to_end = require_pinned_jcs_v1(END_TO_END_BYTES, END_TO_END_SHA256)?;
    verify_corpus_projection_v1(&cases, &expected)?;
    let scenarios = verify_end_to_end_corpus_v1(&end_to_end)?;
    let production_evidence = run_no_effect_scenarios_v1(
        cases.as_object().ok_or("corpus-object-invalid")?,
        &scenarios,
    )?;

    let summary = stable_summary_v1(scenarios, production_evidence);
    let summary_bytes = serde_json_canonicalizer::to_vec(&summary)
        .map_err(|_| "summary-canonicalization-failed")?;
    let actual_summary_sha256 = lowercase_hex_v1(Sha256::digest(&summary_bytes).into());
    if actual_summary_sha256 != SUMMARY_SHA256 {
        return Err("stable-summary-drift");
    }
    let summary_text = String::from_utf8(summary_bytes).map_err(|_| "summary-encoding-failed")?;
    println!("{summary_text}");
    println!("summary_sha256={actual_summary_sha256}");
    Ok(())
}

fn read_exact_bounded_v1(path: &Path, expected_len: u64) -> Result<Vec<u8>, &'static str> {
    let file = File::open(path).map_err(|_| "corpus-open-failed")?;
    if file.metadata().map_err(|_| "corpus-metadata-failed")?.len() != expected_len {
        return Err("corpus-length-mismatch");
    }
    let capacity = usize::try_from(expected_len).map_err(|_| "corpus-length-mismatch")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(expected_len.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "corpus-read-failed")?;
    if bytes.len() != capacity {
        return Err("corpus-length-mismatch");
    }
    Ok(bytes)
}

fn require_pinned_json_v1(
    bytes: &[u8],
    expected_sha256: &str,
    expected_jcs_sha256: &str,
) -> Result<Value, &'static str> {
    if lowercase_hex_v1(Sha256::digest(bytes).into()) != expected_sha256 {
        return Err("corpus-digest-mismatch");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "corpus-json-invalid")?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| "corpus-jcs-invalid")?;
    if lowercase_hex_v1(Sha256::digest(&canonical).into()) != expected_jcs_sha256
        || serde_json::from_slice::<Value>(&canonical).map_err(|_| "corpus-jcs-invalid")? != value
    {
        return Err("corpus-jcs-projection-mismatch");
    }
    Ok(value)
}

fn require_pinned_jcs_v1(bytes: &[u8], expected_sha256: &str) -> Result<Value, &'static str> {
    if lowercase_hex_v1(Sha256::digest(bytes).into()) != expected_sha256 {
        return Err("corpus-digest-mismatch");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "corpus-json-invalid")?;
    if serde_json_canonicalizer::to_vec(&value).map_err(|_| "corpus-jcs-invalid")? != bytes {
        return Err("corpus-bytes-not-jcs");
    }
    Ok(value)
}

fn verify_corpus_projection_v1(cases: &Value, expected: &Value) -> Result<(), &'static str> {
    let cases = exact_object_v1(
        cases,
        &[
            "base_envelopes",
            "cases",
            "contract_version",
            "coverage",
            "description",
            "mutation_vocabulary",
            "schema",
            "verification_keys",
        ],
    )?;
    let expected = exact_object_v1(
        expected,
        &[
            "authority_vocabulary",
            "case_count",
            "contract_version",
            "outcomes",
            "result_vocabulary",
            "schema",
        ],
    )?;
    if required_str_v1(cases, "schema")? != "helixos.durable-dispatch-fixtures/1"
        || required_str_v1(expected, "schema")? != "helixos.durable-dispatch-expected-outcomes/1"
        || required_u64_v1(cases, "contract_version")? != 1
        || required_u64_v1(expected, "contract_version")? != 1
        || required_u64_v1(expected, "case_count")? != CASE_COUNT as u64
    {
        return Err("corpus-schema-mismatch");
    }

    let case_rows = required_array_v1(cases, "cases")?;
    let outcome_rows = required_array_v1(expected, "outcomes")?;
    if case_rows.len() != CASE_COUNT || outcome_rows.len() != CASE_COUNT {
        return Err("corpus-cardinality-mismatch");
    }
    verify_frozen_inventory_v1(cases, expected)?;

    let base_envelopes = cases
        .get("base_envelopes")
        .and_then(Value::as_object)
        .ok_or("corpus-base-inventory-invalid")?;
    let mut case_ids = BTreeSet::new();
    let mut outcome_ids = BTreeSet::new();
    for (case, outcome) in case_rows.iter().zip(outcome_rows) {
        let case = exact_object_v1(
            case,
            &["base", "contract", "expected_outcome_id", "id", "mutation"],
        )?;
        let outcome = exact_object_v1(outcome, &["authority", "id", "reason", "result", "stage"])?;
        let case_id = required_str_v1(case, "id")?;
        let outcome_id = required_str_v1(outcome, "id")?;
        if case_id != outcome_id
            || case_id != required_str_v1(case, "expected_outcome_id")?
            || !case_ids.insert(case_id)
            || !outcome_ids.insert(outcome_id)
        {
            return Err("corpus-case-projection-mismatch");
        }
        let contract = required_str_v1(case, "contract")?;
        let base = required_str_v1(case, "base")?;
        if !matches!(contract, "grant" | "receipt")
            || !base_envelopes.contains_key(base)
            || !base.starts_with(contract)
        {
            return Err("corpus-case-binding-invalid");
        }
        verify_mutation_v1(case.get("mutation").ok_or("corpus-mutation-invalid")?)?;
        verify_expected_outcome_v1(outcome)?;
    }
    if case_ids != outcome_ids || case_ids.len() != CASE_COUNT {
        return Err("corpus-case-projection-mismatch");
    }
    Ok(())
}

fn verify_frozen_inventory_v1(
    cases: &Map<String, Value>,
    expected: &Map<String, Value>,
) -> Result<(), &'static str> {
    let bases = cases
        .get("base_envelopes")
        .and_then(Value::as_object)
        .ok_or("corpus-base-inventory-invalid")?;
    let expected_bases = BTreeSet::from([
        "grant.valid",
        "receipt.consumed.valid",
        "receipt.refused.adapter-paused.valid",
        "receipt.refused.grant-expired.valid",
        "receipt.refused.supervisor-epoch-mismatch.valid",
    ]);
    if bases.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_bases {
        return Err("corpus-base-inventory-invalid");
    }

    let mutation_vocabulary = string_set_v1(required_array_v1(cases, "mutation_vocabulary")?)?;
    if mutation_vocabulary != BTreeSet::from(["add", "none", "raw-transform", "remove", "replace"])
    {
        return Err("corpus-mutation-vocabulary-invalid");
    }
    let result_vocabulary = string_set_v1(required_array_v1(expected, "result_vocabulary")?)?;
    let authority_vocabulary = string_set_v1(required_array_v1(expected, "authority_vocabulary")?)?;
    if result_vocabulary != BTreeSet::from(["ACCEPT_GRANT", "ACCEPT_RECEIPT", "DENY"])
        || authority_vocabulary
            != BTreeSet::from([
                "CONSUMED_EVIDENCE",
                "DEFINITE_REFUSAL_EVIDENCE",
                "GRANT_ONLY",
                "NONE",
            ])
    {
        return Err("corpus-outcome-vocabulary-invalid");
    }

    let coverage = cases
        .get("coverage")
        .and_then(Value::as_object)
        .ok_or("corpus-coverage-invalid")?;
    exact_key_set_v1(
        coverage,
        &["grant_protected_fields", "receipt_protected_fields"],
    )?;
    if required_array_v1(coverage, "grant_protected_fields")?.len() != 69
        || required_array_v1(coverage, "receipt_protected_fields")?.len() != 25
    {
        return Err("corpus-coverage-invalid");
    }
    Ok(())
}

fn verify_mutation_v1(value: &Value) -> Result<(), &'static str> {
    let mutation = value.as_object().ok_or("corpus-mutation-invalid")?;
    let operation = required_str_v1(mutation, "op")?;
    let path = required_str_v1(mutation, "path")?;
    match operation {
        "none" if path.is_empty() => exact_key_set_v1(mutation, &["op", "path"]),
        "remove" => {
            if path.is_empty() {
                return Err("corpus-mutation-invalid");
            }
            exact_key_set_v1(mutation, &["op", "path"])
        }
        "raw-transform" => {
            let transform = mutation
                .get("value")
                .and_then(Value::as_str)
                .ok_or("corpus-mutation-invalid")?;
            if !path.is_empty()
                || !matches!(
                    transform,
                    "duplicate-member"
                        | "leading-whitespace"
                        | "noncanonical-key-order"
                        | "oversize"
                        | "trailing-newline"
                        | "utf8-bom"
                )
            {
                return Err("corpus-mutation-invalid");
            }
            exact_key_set_v1(mutation, &["op", "path", "value"])
        }
        "add" | "replace" => {
            if path.is_empty() || !mutation.contains_key("value") {
                return Err("corpus-mutation-invalid");
            }
            exact_key_set_v1(mutation, &["op", "path", "value"])
        }
        _ => Err("corpus-mutation-invalid"),
    }
}

fn verify_expected_outcome_v1(outcome: &Map<String, Value>) -> Result<(), &'static str> {
    let result = required_str_v1(outcome, "result")?;
    let authority = required_str_v1(outcome, "authority")?;
    let stage = required_str_v1(outcome, "stage")?;
    let reason = required_str_v1(outcome, "reason")?;
    if !matches!(result, "ACCEPT_GRANT" | "ACCEPT_RECEIPT" | "DENY")
        || !matches!(
            authority,
            "GRANT_ONLY" | "CONSUMED_EVIDENCE" | "DEFINITE_REFUSAL_EVIDENCE" | "NONE"
        )
        || !matches!(
            stage,
            "binding"
                | "complete"
                | "deadline"
                | "decision"
                | "decode"
                | "digest"
                | "schema"
                | "signature"
        )
        || reason.is_empty()
    {
        return Err("corpus-outcome-invalid");
    }
    Ok(())
}

fn verify_end_to_end_corpus_v1(value: &Value) -> Result<Vec<ScenarioSummaryV1>, &'static str> {
    let root = exact_object_v1(
        value,
        &["case_count", "cases", "contract_version", "schema"],
    )?;
    if required_str_v1(root, "schema")? != "helixos.durable-dispatch-end-to-end-cases/1"
        || required_u64_v1(root, "contract_version")? != 1
        || required_u64_v1(root, "case_count")? != 6
    {
        return Err("end-to-end-corpus-schema-mismatch");
    }
    let rows = required_array_v1(root, "cases")?;
    if rows.len() != 6 {
        return Err("end-to-end-corpus-cardinality-mismatch");
    }

    let mut identifiers = BTreeSet::new();
    let mut summaries = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let row = exact_object_v1(
            row,
            &[
                "activation_authorized",
                "automatic_redelivery_count",
                "control_state",
                "durable_evidence",
                "durable_projection",
                "effect_authorized",
                "evidence_scope",
                "execution",
                "host_effect_count",
                "id",
                "ordinal",
                "outcome",
                "replacement_grant_count",
                "state",
                "subsystem_only",
            ],
        )?;
        let identifier = required_str_v1(row, "id")?;
        let control_state = required_str_v1(row, "control_state")?;
        let execution = required_str_v1(row, "execution")?;
        let outcome = required_str_v1(row, "outcome")?;
        if !identifiers.insert(identifier)
            || required_u64_v1(row, "ordinal")? != index as u64 + 1
            || !matches!(
                execution,
                "external-store-evidence" | "portable-production-path"
            )
            || outcome.is_empty()
            || required_str_v1(row, "durable_evidence")? != "cross-store-production-facade"
            || required_str_v1(row, "durable_projection")?.is_empty()
            || required_str_v1(row, "state")?.is_empty()
            || (index + 1 == rows.len() && control_state != "PAUSED")
            || (index + 1 != rows.len() && control_state != "RUNNING")
            || required_str_v1(row, "evidence_scope")? != "subsystem-only"
            || required_bool_v1(row, "activation_authorized")?
            || required_bool_v1(row, "effect_authorized")?
            || !required_bool_v1(row, "subsystem_only")?
            || required_u64_v1(row, "host_effect_count")? != 0
            || required_u64_v1(row, "automatic_redelivery_count")? != 0
            || required_u64_v1(row, "replacement_grant_count")? != 0
        {
            return Err("end-to-end-corpus-case-invalid");
        }
        summaries.push(ScenarioSummaryV1 {
            name: identifier.to_owned(),
            ordinal: index as u64 + 1,
            execution: execution.to_owned(),
            outcome: outcome.to_owned(),
            effect_authorized: false,
        });
    }
    Ok(summaries)
}

fn run_no_effect_scenarios_v1(
    cases: &Map<String, Value>,
    scenarios: &[ScenarioSummaryV1],
) -> Result<T080ProductionCorpusEvidenceV1, &'static str> {
    let grant_value = cases
        .get("base_envelopes")
        .and_then(Value::as_object)
        .and_then(|bases| bases.get("grant.valid"))
        .ok_or("portable-grant-fixture-missing")?;
    let exact_grant =
        serde_json_canonicalizer::to_vec(grant_value).map_err(|_| "portable-grant-invalid")?;
    let authentic = decode_and_verify_execution_grant_v1(&exact_grant, &FixtureGrantResolverV1)
        .map_err(|_| "portable-grant-invalid")?;
    if authentic
        .canonical_signed_envelope_bytes()
        .map_err(|_| "portable-grant-invalid")?
        != exact_grant
    {
        return Err("portable-grant-invalid");
    }
    let grant_binding = *authentic.claims().grant_id().as_bytes();

    for scenario in scenarios {
        match scenario.name.as_str() {
            "migration" | "clean-restore" => {}
            "dispatch" => run_dispatch_scenario_v1(&grant_binding, &exact_grant)?,
            "consume" => run_consume_scenario_v1(&grant_binding, &exact_grant)?,
            "lost-ack" => run_lost_ack_scenario_v1(&grant_binding, &exact_grant)?,
            "unknown" => run_unknown_scenario_v1(&grant_binding, &exact_grant)?,
            _ => return Err("end-to-end-corpus-case-unsupported"),
        }
    }

    helix_coordinator_sqlite::run_t080_production_corpus_for_test_v1()
}

fn run_dispatch_scenario_v1(
    grant_binding: &[u8; 32],
    exact_grant: &[u8],
) -> Result<(), &'static str> {
    let transport = NoEffectTransportV1::new_v1(grant_binding, exact_grant);
    if !matches!(
        transport.acquire_handoff_guard_v1(&[0; 32], 200),
        Err(DispatchHandoffValidationV1::Revoked)
    ) {
        return Err("portable-dispatch-binding-check-failed");
    }
    let mut retained_evidence = None;
    let outcome = handoff_exact_grant_once_v1(
        &transport,
        grant_binding,
        exact_grant,
        100,
        200,
        |evidence| {
            retained_evidence = Some(evidence);
            Ok(())
        },
        || Ok(101),
    );
    if !matches!(
        outcome,
        DispatchHandoffOutcomeV1::Acknowledged(NoEffectAckV1)
    ) || retained_evidence != Some(NoEffectGuardV1::EVIDENCE)
        || transport.deliveries.load(Ordering::SeqCst) != 1
        || transport.releases.load(Ordering::SeqCst) != 1
    {
        return Err("portable-dispatch-scenario-failed");
    }
    Ok(())
}

fn run_consume_scenario_v1(
    grant_binding: &[u8; 32],
    exact_grant: &[u8],
) -> Result<(), &'static str> {
    let inbox = PortableInboxV1::fresh_v1(grant_binding, exact_grant);
    let outcome = receive_and_consume_exact_grant_v1(&inbox, exact_grant);
    if !matches!(
        outcome,
        DispatchInboxAdapterOutcomeV1::Consumed(NoEffectReceiptV1)
    ) {
        return Err("portable-consume-scenario-failed");
    }
    let counters = inbox.counters_v1()?;
    if counters != (1, 1, 0) {
        return Err("portable-consume-scenario-failed");
    }
    Ok(())
}

fn run_lost_ack_scenario_v1(
    grant_binding: &[u8; 32],
    exact_grant: &[u8],
) -> Result<(), &'static str> {
    let inbox = PortableInboxV1::with_retained_receipt_v1(grant_binding, exact_grant);
    if !matches!(
        inbox.readback_grant_v1(&[0; 32]),
        DispatchInboxReadbackOutcomeV1::Conflict
    ) {
        return Err("portable-lost-ack-binding-check-failed");
    }
    let recovery =
        recover_lost_acknowledgement_v1(&inbox, grant_binding, exact_grant, 5_000, 5_001);
    if !matches!(
        recovery,
        DispatchLostAcknowledgementRecoveryV1::RetainedReceipt {
            receipt: NoEffectReceiptV1,
            evidence_only: true,
        }
    ) || inbox.counters_v1()? != (0, 0, 1)
    {
        return Err("portable-lost-ack-scenario-failed");
    }
    Ok(())
}

fn run_unknown_scenario_v1(
    grant_binding: &[u8; 32],
    exact_grant: &[u8],
) -> Result<(), &'static str> {
    let inbox = PortableInboxV1::unavailable_v1(grant_binding, exact_grant);
    if !matches!(
        inbox.readback_grant_v1(&[0; 32]),
        DispatchInboxReadbackOutcomeV1::Conflict
    ) {
        return Err("portable-unknown-binding-check-failed");
    }
    let recovery =
        recover_lost_acknowledgement_v1(&inbox, grant_binding, exact_grant, 5_000, 4_999);
    if !matches!(
        recovery,
        DispatchLostAcknowledgementRecoveryV1::OutcomeUnknownThenReconciliationRequired {
            unknown_reason: DispatchUnknownReasonV1::ReadbackUnavailable,
            reconciliation_reason: DispatchReconciliationReasonV1::PossibleConsumption,
        }
    ) || inbox.counters_v1()? != (0, 0, 1)
    {
        return Err("portable-unknown-scenario-failed");
    }
    Ok(())
}

struct FixtureGrantResolverV1;

impl GrantKeyResolver for FixtureGrantResolverV1 {
    fn resolve_grant_key(
        &self,
        key_id: &str,
    ) -> Result<GrantVerificationKeyV1, DispatchContractErrorV1> {
        if key_id == FIXTURE_GRANT_KEY_ID {
            Ok(GrantVerificationKeyV1::current(FIXTURE_GRANT_PUBLIC_KEY))
        } else {
            Err(DispatchContractErrorV1::UnknownKey)
        }
    }
}

#[derive(Clone, Copy)]
struct NoEffectAckV1;

struct NoEffectTransportV1 {
    grant_binding: [u8; 32],
    exact_grant: Vec<u8>,
    deliveries: Arc<AtomicU64>,
    releases: Arc<AtomicU64>,
}

impl NoEffectTransportV1 {
    fn new_v1(grant_binding: &[u8; 32], exact_grant: &[u8]) -> Self {
        Self {
            grant_binding: *grant_binding,
            exact_grant: exact_grant.to_vec(),
            deliveries: Arc::new(AtomicU64::new(0)),
            releases: Arc::new(AtomicU64::new(0)),
        }
    }
}

struct NoEffectGuardV1 {
    releases: Arc<AtomicU64>,
}

impl NoEffectGuardV1 {
    const EVIDENCE: [u8; 32] = [0x80; 32];
}

impl DispatchHandoffGuardV1 for NoEffectGuardV1 {
    fn evidence_binding_v1(&self) -> [u8; 32] {
        Self::EVIDENCE
    }

    fn validate_at_v1(&mut self, _now_monotonic_ms: u64) -> DispatchHandoffValidationV1 {
        DispatchHandoffValidationV1::Live
    }

    fn release_v1(self) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

impl DispatchTransportV1 for NoEffectTransportV1 {
    type Guard = NoEffectGuardV1;
    type Response = NoEffectAckV1;

    fn acquire_handoff_guard_v1(
        &self,
        grant_binding: &[u8; 32],
        _deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
        if grant_binding != &self.grant_binding {
            return Err(DispatchHandoffValidationV1::Revoked);
        }
        Ok(NoEffectGuardV1 {
            releases: Arc::clone(&self.releases),
        })
    }

    fn deliver_exact_v1(
        &self,
        _guard: &mut Self::Guard,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response> {
        if exact_signed_grant_bytes != self.exact_grant {
            return DispatchHandoffOutcomeV1::ConfirmedNoSend;
        }
        self.deliveries.fetch_add(1, Ordering::SeqCst);
        DispatchHandoffOutcomeV1::Acknowledged(NoEffectAckV1)
    }
}

#[derive(Clone, Copy)]
struct NoEffectReceivedV1;

#[derive(Clone, Copy)]
struct NoEffectReceiptV1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PortableInboxModeV1 {
    Fresh,
    RetainedReceipt,
    Unavailable,
}

struct PortableInboxStateV1 {
    mode: PortableInboxModeV1,
    received: bool,
    consumed: bool,
    receive_calls: u64,
    consume_calls: u64,
    readback_calls: u64,
}

struct PortableInboxV1 {
    grant_binding: [u8; 32],
    exact_grant: Vec<u8>,
    state: Mutex<PortableInboxStateV1>,
}

impl PortableInboxV1 {
    fn fresh_v1(grant_binding: &[u8; 32], exact_grant: &[u8]) -> Self {
        Self::new_v1(grant_binding, exact_grant, PortableInboxModeV1::Fresh)
    }

    fn with_retained_receipt_v1(grant_binding: &[u8; 32], exact_grant: &[u8]) -> Self {
        Self::new_v1(
            grant_binding,
            exact_grant,
            PortableInboxModeV1::RetainedReceipt,
        )
    }

    fn unavailable_v1(grant_binding: &[u8; 32], exact_grant: &[u8]) -> Self {
        Self::new_v1(grant_binding, exact_grant, PortableInboxModeV1::Unavailable)
    }

    fn new_v1(grant_binding: &[u8; 32], exact_grant: &[u8], mode: PortableInboxModeV1) -> Self {
        Self {
            grant_binding: *grant_binding,
            exact_grant: exact_grant.to_vec(),
            state: Mutex::new(PortableInboxStateV1 {
                mode,
                received: false,
                consumed: mode == PortableInboxModeV1::RetainedReceipt,
                receive_calls: 0,
                consume_calls: 0,
                readback_calls: 0,
            }),
        }
    }

    fn counters_v1(&self) -> Result<(u64, u64, u64), &'static str> {
        let state = self
            .state
            .lock()
            .map_err(|_| "portable-inbox-lock-failed")?;
        Ok((
            state.receive_calls,
            state.consume_calls,
            state.readback_calls,
        ))
    }
}

impl DispatchInboxV1 for PortableInboxV1 {
    type RetainedState = NoEffectReceivedV1;
    type RetainedReceipt = NoEffectReceiptV1;

    fn receive_exact_grant_v1(
        &self,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        let Ok(mut state) = self.state.lock() else {
            return DispatchInboxReceiveOutcomeV1::Unhealthy;
        };
        state.receive_calls = state.receive_calls.saturating_add(1);
        if exact_signed_grant_bytes != self.exact_grant {
            return DispatchInboxReceiveOutcomeV1::Conflict;
        }
        match state.mode {
            PortableInboxModeV1::Unavailable => DispatchInboxReceiveOutcomeV1::Unavailable,
            PortableInboxModeV1::RetainedReceipt => {
                DispatchInboxReceiveOutcomeV1::RetainedReceipt(NoEffectReceiptV1)
            }
            PortableInboxModeV1::Fresh if state.consumed => {
                DispatchInboxReceiveOutcomeV1::RetainedReceipt(NoEffectReceiptV1)
            }
            PortableInboxModeV1::Fresh if state.received => {
                DispatchInboxReceiveOutcomeV1::RetainedState(NoEffectReceivedV1)
            }
            PortableInboxModeV1::Fresh => {
                state.received = true;
                DispatchInboxReceiveOutcomeV1::DurablyReceived(NoEffectReceivedV1)
            }
        }
    }
}

impl DispatchInboxConsumerV1 for PortableInboxV1 {
    fn consume_received_once_v1(
        &self,
        _retained_state: Self::RetainedState,
    ) -> DispatchInboxConsumeOutcomeV1<Self::RetainedReceipt> {
        let Ok(mut state) = self.state.lock() else {
            return DispatchInboxConsumeOutcomeV1::Unhealthy;
        };
        state.consume_calls = state.consume_calls.saturating_add(1);
        if state.mode != PortableInboxModeV1::Fresh || !state.received {
            return DispatchInboxConsumeOutcomeV1::Conflict;
        }
        if state.consumed {
            DispatchInboxConsumeOutcomeV1::RetainedReceipt(NoEffectReceiptV1)
        } else {
            state.consumed = true;
            DispatchInboxConsumeOutcomeV1::Consumed(NoEffectReceiptV1)
        }
    }
}

impl DispatchInboxReadbackV1 for PortableInboxV1 {
    type RetainedState = NoEffectReceivedV1;
    type RetainedReceipt = NoEffectReceiptV1;

    fn readback_grant_v1(
        &self,
        grant_binding: &[u8; 32],
    ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        if grant_binding != &self.grant_binding {
            return DispatchInboxReadbackOutcomeV1::Conflict;
        }
        let Ok(mut state) = self.state.lock() else {
            return DispatchInboxReadbackOutcomeV1::Unhealthy;
        };
        state.readback_calls = state.readback_calls.saturating_add(1);
        match state.mode {
            PortableInboxModeV1::Unavailable => DispatchInboxReadbackOutcomeV1::Unavailable,
            PortableInboxModeV1::RetainedReceipt => {
                DispatchInboxReadbackOutcomeV1::RetainedReceipt(NoEffectReceiptV1)
            }
            PortableInboxModeV1::Fresh if state.consumed => {
                DispatchInboxReadbackOutcomeV1::RetainedReceipt(NoEffectReceiptV1)
            }
            PortableInboxModeV1::Fresh if state.received => {
                DispatchInboxReadbackOutcomeV1::Received(NoEffectReceivedV1)
            }
            PortableInboxModeV1::Fresh => DispatchInboxReadbackOutcomeV1::Absent,
        }
    }
}

fn stable_summary_v1(
    scenarios: Vec<ScenarioSummaryV1>,
    production: T080ProductionCorpusEvidenceV1,
) -> StableSummaryV1 {
    StableSummaryV1 {
        schema: "helixos.durable-dispatch-corpus-run/1",
        case_count: CASE_COUNT as u64,
        scenario_count: scenarios.len() as u64,
        cases_sha256: CASES_SHA256,
        end_to_end_cases_sha256: END_TO_END_SHA256,
        expected_outcomes_sha256: EXPECTED_SHA256,
        subsystem_only: true,
        production_evidence: ProductionEvidenceSummaryV1 {
            migration_count: production.migration_count(),
            coordinator_grant_count: production.coordinator_grant_count(),
            coordinator_executing_count: production.coordinator_executing_count(),
            coordinator_reconciliation_required_count: production
                .coordinator_reconciliation_required_count(),
            coordinator_receipt_count: production.coordinator_receipt_count(),
            adapter_grant_count: production.adapter_grant_count(),
            adapter_consumed_count: production.adapter_consumed_count(),
            adapter_receipt_count: production.adapter_receipt_count(),
            adapter_transition_count: production.adapter_transition_count(),
            replacement_grant_count: production.replacement_grant_count(),
            automatic_redelivery_count: production.automatic_redelivery_count(),
            execution_authority_object_count: production.execution_authority_object_count(),
            clean_restore_verified: production.clean_restore_verified(),
        },
        scenarios,
    }
}

fn exact_object_v1<'value>(
    value: &'value Value,
    expected_keys: &[&str],
) -> Result<&'value Map<String, Value>, &'static str> {
    let object = value.as_object().ok_or("corpus-object-invalid")?;
    exact_key_set_v1(object, expected_keys)?;
    Ok(object)
}

fn exact_key_set_v1(
    object: &Map<String, Value>,
    expected_keys: &[&str],
) -> Result<(), &'static str> {
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected_keys.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("corpus-member-set-mismatch");
    }
    Ok(())
}

fn required_array_v1<'value>(
    object: &'value Map<String, Value>,
    key: &str,
) -> Result<&'value [Value], &'static str> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or("corpus-array-invalid")
}

fn required_str_v1<'value>(
    object: &'value Map<String, Value>,
    key: &str,
) -> Result<&'value str, &'static str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or("corpus-string-invalid")
}

fn required_u64_v1(object: &Map<String, Value>, key: &str) -> Result<u64, &'static str> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or("corpus-integer-invalid")
}

fn required_bool_v1(object: &Map<String, Value>, key: &str) -> Result<bool, &'static str> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or("corpus-boolean-invalid")
}

fn string_set_v1(rows: &[Value]) -> Result<BTreeSet<&str>, &'static str> {
    rows.iter()
        .map(|row| row.as_str().ok_or("corpus-string-set-invalid"))
        .collect()
}

fn lowercase_hex_v1(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
