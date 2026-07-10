mod common;
#[path = "../test-support/conformance_cases.rs"]
mod conformance_cases;
#[path = "../test-support/replay_claimant.rs"]
mod replay_claimant;

use conformance_cases::{
    canonical_bytes, execute_manifest, generated_manifest, CaseStageV1, CasesManifestV1,
    ClaimantProfileV1, OutcomeCaseV1, OutcomeSummaryV1, OutcomeV1,
};
use helix_contracts::Sha256Digest;
use helix_plan_eligibility::{EligibilityContextBuildErrorV1, EligibilityDenialV1};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeSet;

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-eligibility-v1/cases.json");
const OUTCOMES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-eligibility-v1/expected-outcomes.json");
const CASES_SCHEMA: &str = "helixos.plan-eligibility-cases/1";
const OUTCOMES_SCHEMA: &str = "helixos.plan-eligibility-summary/1";
const CASES_SHA256: &str = "eefc1403e8b267afc3dde30b29d4064fa2d3c16cdeaeb1a5154377289a253b7a";
const OUTCOMES_SHA256: &str = "258fcd002c335a1f25070e593ae97eb7472b2fe55342134058e2e4e470af7bbb";
const EXPECTED_BUILD_CASES: usize = 5;
const EXPECTED_RUNTIME_DENIAL_CASES: usize = 100;
const EXPECTED_TOTAL_CASES: usize = 106;

#[test]
fn committed_artifacts_are_closed_canonical_sorted_and_digest_pinned() {
    let manifest: CasesManifestV1 =
        decode_strict(CASES_BYTES, "cases.json").expect("strict cases.json");
    let outcomes: OutcomeSummaryV1 =
        decode_strict(OUTCOMES_BYTES, "expected-outcomes.json").expect("strict outcomes");

    validate_manifest(&manifest).expect("closed manifest contract");
    validate_summary(&outcomes).expect("closed summary contract");
    assert_eq!(
        Sha256Digest::digest(CASES_BYTES).to_string(),
        CASES_SHA256,
        "cases.json digest drift"
    );
    assert_eq!(
        Sha256Digest::digest(OUTCOMES_BYTES).to_string(),
        OUTCOMES_SHA256,
        "expected-outcomes.json digest drift"
    );
}

#[test]
fn generator_and_actual_execution_are_byte_identical_to_the_committed_corpus() {
    let committed_manifest: CasesManifestV1 =
        decode_strict(CASES_BYTES, "cases.json").expect("strict cases.json");
    let committed_outcomes: OutcomeSummaryV1 =
        decode_strict(OUTCOMES_BYTES, "expected-outcomes.json").expect("strict outcomes");
    let generated = generated_manifest();

    assert_eq!(generated, committed_manifest, "manifest registry drift");
    assert_eq!(
        canonical_bytes(&generated),
        CASES_BYTES,
        "generated cases.json byte drift"
    );

    let projected = project_expectations(&committed_manifest);
    assert_eq!(
        projected, committed_outcomes,
        "expected summary is not the exact manifest projection"
    );

    let actual = execute_manifest(&committed_manifest);
    assert_eq!(actual, committed_outcomes, "actual outcome drift");
    let actual_bytes = canonical_bytes(&actual);
    assert_eq!(
        actual_bytes, OUTCOMES_BYTES,
        "actual canonical summary byte drift"
    );
    assert_eq!(
        Sha256Digest::digest(&actual_bytes),
        Sha256Digest::digest(OUTCOMES_BYTES),
        "actual summary digest drift"
    );
}

#[test]
fn malformed_noncanonical_or_platform_specific_artifacts_are_rejected() {
    let manifest: CasesManifestV1 =
        decode_strict(CASES_BYTES, "cases.json").expect("strict cases.json");
    let summary: OutcomeSummaryV1 =
        decode_strict(OUTCOMES_BYTES, "expected-outcomes.json").expect("strict outcomes");

    let mut with_newline = CASES_BYTES.to_vec();
    with_newline.push(b'\n');
    assert!(decode_strict::<CasesManifestV1>(&with_newline, "newline").is_err());

    let mut with_bom = vec![0xef, 0xbb, 0xbf];
    with_bom.extend_from_slice(CASES_BYTES);
    assert!(decode_strict::<CasesManifestV1>(&with_bom, "BOM").is_err());
    assert!(decode_strict::<CasesManifestV1>(&[0xff], "non-UTF-8").is_err());

    let duplicate_top = br#"{"cases":[],"schema":"helixos.plan-eligibility-cases/1","schema":"helixos.plan-eligibility-cases/1"}"#;
    assert!(serde_json::from_slice::<CasesManifestV1>(duplicate_top).is_err());

    let duplicate_case = br#"{"cases":[{"case_id":"eligible-coherent","case_id":"eligible-coherent","claimant":"claimed-matching","expected_claimant_reached":true,"expected_code":"NONE","expected_outcome":"eligible","fault":"none","profile":"coherent-v1","stage":"runtime"}],"schema":"helixos.plan-eligibility-cases/1"}"#;
    assert!(serde_json::from_slice::<CasesManifestV1>(duplicate_case).is_err());

    let duplicate_summary = br#"{"cases":[],"schema":"helixos.plan-eligibility-summary/1","schema":"helixos.plan-eligibility-summary/1"}"#;
    assert!(serde_json::from_slice::<OutcomeSummaryV1>(duplicate_summary).is_err());

    let duplicate_summary_case = br#"{"cases":[{"case_id":"eligible-coherent","case_id":"eligible-coherent","claimant_reached":true,"code":"NONE","outcome":"eligible"}],"schema":"helixos.plan-eligibility-summary/1"}"#;
    assert!(serde_json::from_slice::<OutcomeSummaryV1>(duplicate_summary_case).is_err());

    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value
        .as_object_mut()
        .expect("manifest object")
        .insert("os".to_owned(), serde_json::json!("windows"));
    assert_manifest_decode_rejected(&value);

    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value["cases"][0]["arch"] = serde_json::json!("aarch64");
    assert_manifest_decode_rejected(&value);

    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value["cases"][0]["stage"] = serde_json::json!("host_selected");
    assert_manifest_decode_rejected(&value);

    let mut value = serde_json::to_value(&manifest).expect("manifest value");
    value["cases"][0]
        .as_object_mut()
        .expect("case object")
        .remove("fault");
    assert_manifest_decode_rejected(&value);

    let mut value = serde_json::to_value(&summary).expect("summary value");
    value["cases"][0]["provider_error"] = serde_json::json!("forbidden");
    let bytes = serde_json_canonicalizer::to_vec(&value).expect("summary mutation JCS");
    assert!(serde_json::from_slice::<OutcomeSummaryV1>(&bytes).is_err());

    let mut invalid_id = manifest.clone();
    invalid_id.cases[0].case_id = "Windows_X64".to_owned();
    assert!(validate_manifest(&invalid_id).is_err());

    let mut unsorted = manifest.clone();
    unsorted.cases.swap(0, 1);
    assert!(validate_manifest(&unsorted).is_err());

    let mut duplicate = manifest;
    duplicate.cases[1].case_id = duplicate.cases[0].case_id.clone();
    assert!(validate_manifest(&duplicate).is_err());
}

fn decode_strict<T>(bytes: &[u8], label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(format!("{label}: UTF-8 BOM is forbidden"));
    }
    std::str::from_utf8(bytes).map_err(|_| format!("{label}: invalid UTF-8"))?;
    let decoded: T = serde_json::from_slice(bytes).map_err(|error| format!("{label}: {error}"))?;
    if canonical_bytes(&decoded) != bytes {
        return Err(format!("{label}: bytes are not exact RFC 8785 JCS"));
    }
    Ok(decoded)
}

fn validate_manifest(manifest: &CasesManifestV1) -> Result<(), String> {
    if manifest.schema != CASES_SCHEMA {
        return Err("unknown manifest schema".to_owned());
    }
    if EligibilityContextBuildErrorV1::ALL.len() != EXPECTED_BUILD_CASES
        || EligibilityDenialV1::ALL.len() != EXPECTED_RUNTIME_DENIAL_CASES
        || manifest.cases.len() != EXPECTED_TOTAL_CASES
    {
        return Err("frozen taxonomy or corpus count drift".to_owned());
    }

    let build_codes: BTreeSet<&str> = EligibilityContextBuildErrorV1::ALL
        .iter()
        .map(|error| error.code())
        .collect();
    let runtime_codes: BTreeSet<&str> = EligibilityDenialV1::ALL
        .iter()
        .map(|denial| denial.code())
        .collect();
    let mut seen_build = BTreeSet::new();
    let mut seen_runtime = BTreeSet::new();
    let mut previous_id: Option<&str> = None;
    let mut eligible_count = 0;

    for case in &manifest.cases {
        if !is_public_case_id(&case.case_id) || !is_public_case_id(&case.fault) {
            return Err("invalid public case or fault token".to_owned());
        }
        if previous_id.is_some_and(|previous| previous >= case.case_id.as_str()) {
            return Err("case IDs are duplicate or not ASCII-sorted".to_owned());
        }
        previous_id = Some(&case.case_id);

        match case.stage {
            CaseStageV1::ContextBuild => {
                if case.expected_outcome != OutcomeV1::ContextBuildDenied
                    || case.claimant != ClaimantProfileV1::NotReached
                    || case.expected_claimant_reached
                    || !build_codes.contains(case.expected_code.as_str())
                    || !seen_build.insert(case.expected_code.as_str())
                {
                    return Err("invalid or duplicate context-build case".to_owned());
                }
            }
            CaseStageV1::Runtime if case.expected_outcome == OutcomeV1::Eligible => {
                eligible_count += 1;
                if case.case_id != "eligible-coherent"
                    || case.fault != "none"
                    || case.expected_code != "NONE"
                    || case.claimant != ClaimantProfileV1::ClaimedMatching
                    || !case.expected_claimant_reached
                {
                    return Err("invalid coherent case".to_owned());
                }
            }
            CaseStageV1::Runtime => {
                if case.expected_outcome != OutcomeV1::Denied
                    || !runtime_codes.contains(case.expected_code.as_str())
                    || !seen_runtime.insert(case.expected_code.as_str())
                {
                    return Err("invalid or duplicate runtime denial case".to_owned());
                }
                validate_runtime_claimant(case)?;
            }
        }
    }

    if eligible_count != 1 || seen_build != build_codes || seen_runtime != runtime_codes {
        return Err("corpus does not cover the complete frozen taxonomy exactly once".to_owned());
    }
    Ok(())
}

fn validate_runtime_claimant(case: &conformance_cases::CaseV1) -> Result<(), String> {
    let expected_profile = match case.expected_code.as_str() {
        "REPLAY_ALREADY_CLAIMED" => ClaimantProfileV1::AlreadyClaimed,
        "REPLAY_BINDING_CONFLICT" => ClaimantProfileV1::BindingConflict,
        "REPLAY_UNAVAILABLE" => ClaimantProfileV1::Unavailable,
        "REPLAY_AMBIGUOUS" => ClaimantProfileV1::Ambiguous,
        "REPLAY_RECEIPT_BINDING_MISMATCH" => ClaimantProfileV1::ClaimedWrongBinding,
        _ => ClaimantProfileV1::NotReached,
    };
    let expected_reached = expected_profile != ClaimantProfileV1::NotReached;
    if case.claimant != expected_profile || case.expected_claimant_reached != expected_reached {
        return Err("claimant profile or reached probe contradicts denial code".to_owned());
    }
    Ok(())
}

fn validate_summary(summary: &OutcomeSummaryV1) -> Result<(), String> {
    if summary.schema != OUTCOMES_SCHEMA || summary.cases.len() != EXPECTED_TOTAL_CASES {
        return Err("unknown summary schema or case count".to_owned());
    }
    let mut previous_id: Option<&str> = None;
    for case in &summary.cases {
        if !is_public_case_id(&case.case_id)
            || previous_id.is_some_and(|previous| previous >= case.case_id.as_str())
        {
            return Err("summary IDs are invalid, duplicate, or unsorted".to_owned());
        }
        previous_id = Some(&case.case_id);
        match case.outcome {
            OutcomeV1::Eligible if case.code == "NONE" && case.claimant_reached => {}
            OutcomeV1::Denied if case.code != "NONE" => {}
            OutcomeV1::ContextBuildDenied if case.code.starts_with("CONTEXT_BUILD_") => {}
            _ => return Err("invalid summary outcome relationship".to_owned()),
        }
    }
    Ok(())
}

fn project_expectations(manifest: &CasesManifestV1) -> OutcomeSummaryV1 {
    OutcomeSummaryV1 {
        schema: OUTCOMES_SCHEMA.to_owned(),
        cases: manifest
            .cases
            .iter()
            .map(|case| OutcomeCaseV1 {
                case_id: case.case_id.clone(),
                claimant_reached: case.expected_claimant_reached,
                code: case.expected_code.clone(),
                outcome: case.expected_outcome,
            })
            .collect(),
    }
}

fn is_public_case_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 96
        || !bytes[0].is_ascii_lowercase()
        || bytes.last() == Some(&b'-')
    {
        return false;
    }
    let mut previous_hyphen = false;
    for &byte in &bytes[1..] {
        if byte == b'-' {
            if previous_hyphen {
                return false;
            }
            previous_hyphen = true;
        } else if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
            previous_hyphen = false;
        } else {
            return false;
        }
    }
    true
}

fn assert_manifest_decode_rejected(value: &serde_json::Value) {
    let bytes = serde_json_canonicalizer::to_vec(value).expect("mutated JSON canonicalizes");
    assert!(serde_json::from_slice::<CasesManifestV1>(&bytes).is_err());
}
