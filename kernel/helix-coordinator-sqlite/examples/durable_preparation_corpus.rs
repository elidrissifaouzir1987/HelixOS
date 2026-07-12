//! Portable drift checker and stable summary for the frozen Feature 004 corpus.

#![forbid(unsafe_code)]

use helix_contracts::Sha256Digest;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/cases.json");
const EXPECTED_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/expected-outcomes.json");
const CASES_SHA256: &str = "086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d";
const EXPECTED_SHA256: &str = "87bd23eeed048fe47ca4f785d17cdca80364454bae30c81dc4b3e9e7ecf3ac2b";
const SUMMARY_SHA256: &str = "e0dac29c01276a7f6168a83bff51accefc86a129f1046065ebea5f136bbddd87";

#[derive(Serialize)]
struct StableSummaryV1 {
    schema: &'static str,
    cases: u64,
    fault_boundaries: u64,
    prepared: u64,
    denied: u64,
    failed: u64,
    ambiguous: u64,
    cases_sha256: &'static str,
    expected_outcomes_sha256: &'static str,
}

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args_os().len() != 1 {
        return Err("usage: durable_preparation_corpus".into());
    }
    require_pinned_jcs_v1(CASES_BYTES, CASES_SHA256)?;
    require_pinned_jcs_v1(EXPECTED_BYTES, EXPECTED_SHA256)?;

    let cases: Value = serde_json::from_slice(CASES_BYTES)?;
    let expected: Value = serde_json::from_slice(EXPECTED_BYTES)?;
    let case_object = exact_object_v1(
        &cases,
        &[
            "cases",
            "counts",
            "domain_encodings",
            "fault_boundaries",
            "package_binding_kats",
            "schema",
        ],
    )?;
    let expected_object = exact_object_v1(&expected, &["cases", "schema"])?;
    if case_object.get("schema").and_then(Value::as_str)
        != Some("helixos.durable-preparation-cases/1")
        || expected_object.get("schema").and_then(Value::as_str)
            != Some("helixos.durable-preparation-summary/1")
    {
        return Err("corpus schema mismatch".into());
    }

    let case_rows = required_array_v1(case_object, "cases")?;
    let expected_rows = required_array_v1(expected_object, "cases")?;
    let boundaries = required_array_v1(case_object, "fault_boundaries")?;
    let kats = required_array_v1(case_object, "package_binding_kats")?;
    let counts = case_object
        .get("counts")
        .and_then(Value::as_object)
        .ok_or("corpus counts are absent")?;
    if case_rows.len() != 335
        || expected_rows.len() != 335
        || boundaries.len() != 123
        || kats.len() != 2
        || counts.get("case_count").and_then(Value::as_u64) != Some(335)
        || counts.get("fault_boundary_count").and_then(Value::as_u64) != Some(123)
    {
        return Err("corpus frozen count mismatch".into());
    }

    let case_ids = sorted_ids_v1(case_rows, "case_id")?;
    let expected_ids = sorted_ids_v1(expected_rows, "case_id")?;
    if case_ids != expected_ids {
        return Err("corpus case projection mismatch".into());
    }
    require_ordered_boundaries_v1(boundaries)?;

    let mut outcomes = BTreeMap::<&str, u64>::new();
    for row in expected_rows {
        let row = row.as_object().ok_or("expected row is not an object")?;
        let outcome = row
            .get("outcome")
            .and_then(Value::as_str)
            .ok_or("expected outcome is absent")?;
        if !matches!(outcome, "prepared" | "denied" | "failed" | "ambiguous") {
            return Err("expected outcome is outside the closed vocabulary".into());
        }
        *outcomes.entry(outcome).or_default() += 1;
        if row.get("replay_claim_released").and_then(Value::as_bool) != Some(false) {
            return Err("corpus attempts to release a replay claim".into());
        }
        let calls = row
            .get("recovery_provider_calls")
            .and_then(Value::as_object)
            .ok_or("provider call projection is absent")?;
        let acquire = required_u64_v1(calls, "acquire")?;
        let prepare = required_u64_v1(calls, "prepare")?;
        let verify = required_u64_v1(calls, "verify")?;
        if acquire
            .checked_add(prepare)
            .and_then(|value| value.checked_add(verify))
            != Some(required_u64_v1(calls, "total")?)
        {
            return Err("provider call total is inconsistent".into());
        }
    }

    let summary = StableSummaryV1 {
        schema: "helixos.durable-preparation-corpus-run/1",
        cases: 335,
        fault_boundaries: 123,
        prepared: exact_outcome_count_v1(&outcomes, "prepared", 3)?,
        denied: exact_outcome_count_v1(&outcomes, "denied", 299)?,
        failed: exact_outcome_count_v1(&outcomes, "failed", 21)?,
        ambiguous: exact_outcome_count_v1(&outcomes, "ambiguous", 12)?,
        cases_sha256: CASES_SHA256,
        expected_outcomes_sha256: EXPECTED_SHA256,
    };
    let summary_bytes = serde_json_canonicalizer::to_vec(&summary)?;
    let summary_sha256 = Sha256Digest::digest(&summary_bytes);
    if summary_sha256.to_string() != SUMMARY_SHA256 {
        return Err("stable corpus summary drift".into());
    }
    println!("{}", String::from_utf8(summary_bytes)?);
    println!("summary_sha256={summary_sha256}");
    Ok(())
}

fn require_pinned_jcs_v1(bytes: &[u8], expected_sha256: &str) -> Result<(), Box<dyn Error>> {
    if Sha256Digest::digest(bytes).to_string() != expected_sha256 {
        return Err("corpus digest mismatch".into());
    }
    let value: Value = serde_json::from_slice(bytes)?;
    if serde_json_canonicalizer::to_vec(&value)? != bytes {
        return Err("corpus bytes are not exact JCS".into());
    }
    Ok(())
}

fn exact_object_v1<'value>(
    value: &'value Value,
    expected_keys: &[&str],
) -> Result<&'value Map<String, Value>, Box<dyn Error>> {
    let object = value.as_object().ok_or("corpus root is not an object")?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected_keys.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("corpus root member set mismatch".into());
    }
    Ok(object)
}

fn required_array_v1<'value>(
    object: &'value Map<String, Value>,
    key: &str,
) -> Result<&'value [Value], Box<dyn Error>> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| "corpus array is absent".into())
}

fn sorted_ids_v1(rows: &[Value], key: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let ids = rows
        .iter()
        .map(|row| {
            row.as_object()
                .and_then(|object| object.get(key))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or("corpus ID is absent")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err("corpus IDs are not strictly sorted and unique".into());
    }
    Ok(ids)
}

fn require_ordered_boundaries_v1(rows: &[Value]) -> Result<(), Box<dyn Error>> {
    let mut ids = BTreeSet::new();
    for (index, row) in rows.iter().enumerate() {
        let row = row.as_object().ok_or("boundary row is not an object")?;
        let id = row
            .get("boundary_id")
            .and_then(Value::as_str)
            .ok_or("boundary ID is absent")?;
        if !ids.insert(id)
            || row.get("order").and_then(Value::as_u64) != Some(index as u64 + 1)
            || row
                .get("expected_registry_occurrences")
                .and_then(Value::as_u64)
                != Some(1)
        {
            return Err("boundary registry is not exact and ordered".into());
        }
    }
    Ok(())
}

fn required_u64_v1(object: &Map<String, Value>, key: &str) -> Result<u64, Box<dyn Error>> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| "corpus integer is absent".into())
}

fn exact_outcome_count_v1(
    outcomes: &BTreeMap<&str, u64>,
    outcome: &str,
    expected: u64,
) -> Result<u64, Box<dyn Error>> {
    match outcomes.get(outcome).copied() {
        Some(actual) if actual == expected => Ok(actual),
        _ => Err("stable outcome count mismatch".into()),
    }
}
