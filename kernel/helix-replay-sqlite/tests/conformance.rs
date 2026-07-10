//! Frozen, host-independent validation of the durable-replay conformance corpus.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-replay-store-v1/cases.json");
const EXPECTED_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-replay-store-v1/expected-outcomes.json");

const CASES_SCHEMA: &str = "helixos.durable-replay-store-cases/1";
const SUMMARY_SCHEMA: &str = "helixos.durable-replay-store-summary/1";
const EVIDENCE_SCHEMA: &str = "helixos.durable-replay-store-corpus-evidence/1";
const CASES_SHA256: &str = "7db71958d28d135d1880daaaf57788b4476950a7835a4c85d633e8d921a3a5ff";
const EXPECTED_SHA256: &str = "687c562f05fe7e449f3df2b09505057a26420407e7df9c91b109a1d3950f25ac";

const EXPECTED_CASE_IDS: [&str; 68] = [
    "backup-deadline-reached",
    "backup-incomplete-staging",
    "backup-live-consistent",
    "claim-commit-readback-absence",
    "claim-commit-readback-conflict",
    "claim-commit-readback-exact",
    "claim-commit-readback-failed",
    "claim-commit-readback-prior",
    "claim-exact-repeat",
    "claim-fresh",
    "claim-generation-exhausted",
    "claim-independent-binding",
    "claim-nonce-conflict",
    "claim-operation-conflict",
    "claim-postcommit-late",
    "claim-precommit-confirmed-rollback",
    "claim-prewrite-store-unavailable",
    "claim-rng-unavailable",
    "contention-independent-bindings",
    "contention-operation-conflict",
    "contention-process-exact",
    "contention-thread-exact",
    "contention-thread-nonce-conflict",
    "corruption-application-id-mismatch",
    "corruption-integrity-failed",
    "corruption-invalid-row",
    "corruption-invariant-failed",
    "corruption-schema-altered",
    "corruption-truncated-database",
    "crash-backup-database-complete",
    "crash-backup-manifest-staged",
    "crash-backup-published",
    "crash-before-commit",
    "crash-before-result-ack",
    "crash-begin-acquired",
    "crash-commit-returned",
    "crash-generation-updated",
    "crash-opened",
    "crash-row-inserted",
    "deadline-after-commit",
    "deadline-already-reached",
    "deadline-before-commit",
    "deadline-clock-unavailable",
    "deadline-readback-late",
    "deadline-writer-lock",
    "initialization-clock-unavailable",
    "initialization-concurrent",
    "initialization-deadline-reached",
    "initialization-durability-profile-unavailable",
    "initialization-empty-v1",
    "initialization-invalid-backup-step",
    "initialization-invalid-backup-wait",
    "initialization-invalid-busy-bound",
    "initialization-location-invalid",
    "initialization-location-not-dedicated",
    "initialization-store-busy",
    "initialization-store-unavailable",
    "maintenance-deadline-reached",
    "maintenance-verify-healthy",
    "migration-newer-schema-refused",
    "restore-backup-incomplete",
    "restore-database-digest-mismatch",
    "restore-destination-not-empty",
    "restore-incomplete",
    "restore-manifest-invalid",
    "restore-manifest-missing",
    "restore-source-destination-conflict",
    "restore-valid-clean-root",
];

const CLOSED_OUTCOMES: [&str; 8] = [
    "already_claimed",
    "ambiguous",
    "binding_conflict",
    "claimed",
    "recovered",
    "rejected",
    "unavailable",
    "verified",
];

const CLOSED_STATES: [&str; 11] = [
    "commit-unknown",
    "empty-store",
    "existing-claim-unchanged",
    "healthy-store",
    "no-store",
    "one-complete-claim",
    "source-unchanged",
    "store-unhealthy",
    "two-complete-claims",
    "valid-backup",
    "verified-restore",
];

const CLOSED_CODES: [&str; 35] = [
    "ALL_INDEPENDENT_COMMITTED",
    "ALREADY_CLAIMED",
    "AMBIGUOUS",
    "APPLICATION_ID_MISMATCH",
    "BACKUP_INCOMPLETE",
    "BACKUP_VERIFIED",
    "BINDING_CONFLICT",
    "CLAIMED",
    "CLOCK_UNAVAILABLE",
    "DATABASE_DIGEST_MISMATCH",
    "DEADLINE_REACHED",
    "DESTINATION_NOT_EMPTY",
    "DURABILITY_PROFILE_UNAVAILABLE",
    "INTEGRITY_FAILED",
    "INVALID_BACKUP_STEP",
    "INVALID_BACKUP_WAIT",
    "INVALID_BUSY_BOUND",
    "INVARIANT_FAILED",
    "LOCATION_INVALID",
    "LOCATION_NOT_DEDICATED",
    "MAINTENANCE_DEADLINE_REACHED",
    "MANIFEST_INVALID",
    "MANIFEST_MISSING",
    "ONE_DURABLE_WINNER",
    "PROCESS_CRASH_RECOVERED",
    "RESTORE_INCOMPLETE",
    "RESTORE_VERIFIED",
    "SCHEMA_INVALID",
    "SCHEMA_UNSUPPORTED",
    "SOURCE_DESTINATION_CONFLICT",
    "STORE_BUSY",
    "STORE_INITIALIZED",
    "STORE_UNAVAILABLE",
    "STORE_VERIFIED",
    "UNAVAILABLE",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseManifest<'a> {
    #[serde(borrow)]
    cases: Vec<Case<'a>>,
    schema: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case<'a> {
    action: &'a str,
    case_id: &'a str,
    category: &'a str,
    expected_code: &'a str,
    expected_outcome: &'a str,
    expected_state: &'a str,
    fault: &'a str,
    profile: &'a str,
    setup: &'a str,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedManifest<'a> {
    #[serde(borrow)]
    cases: Vec<ExpectedCase<'a>>,
    schema: &'a str,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedCase<'a> {
    case_id: &'a str,
    code: &'a str,
    outcome: &'a str,
    state: &'a str,
}

#[derive(Serialize)]
struct CorpusEvidence<'a> {
    case_count: usize,
    cases_sha256: &'a str,
    expected_outcomes_sha256: &'a str,
    schema: &'a str,
}

fn parse_cases(bytes: &[u8]) -> Result<CaseManifest<'_>, String> {
    let parsed: CaseManifest<'_> =
        serde_json::from_slice(bytes).map_err(|_| "CORPUS_INVALID".to_owned())?;
    let canonical = serde_json::to_vec(&parsed).map_err(|_| "CORPUS_INVALID".to_owned())?;
    if canonical != bytes {
        return Err("CORPUS_NON_CANONICAL".to_owned());
    }
    Ok(parsed)
}

fn parse_expected(bytes: &[u8]) -> Result<ExpectedManifest<'_>, String> {
    let parsed: ExpectedManifest<'_> =
        serde_json::from_slice(bytes).map_err(|_| "SUMMARY_INVALID".to_owned())?;
    let canonical = serde_json::to_vec(&parsed).map_err(|_| "SUMMARY_INVALID".to_owned())?;
    if canonical != bytes {
        return Err("SUMMARY_NON_CANONICAL".to_owned());
    }
    Ok(parsed)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

#[test]
fn frozen_corpus_has_exact_digest_ids_and_closed_vocabulary() {
    let manifest = parse_cases(CASES_BYTES).expect("frozen case manifest must be canonical");

    assert_eq!(manifest.schema, CASES_SCHEMA);
    assert_eq!(sha256_hex(CASES_BYTES), CASES_SHA256);
    assert_eq!(manifest.cases.len(), EXPECTED_CASE_IDS.len());

    let actual_ids: Vec<_> = manifest.cases.iter().map(|case| case.case_id).collect();
    assert_eq!(actual_ids, EXPECTED_CASE_IDS);
    assert!(actual_ids.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        actual_ids.iter().copied().collect::<BTreeSet<_>>().len(),
        68
    );

    let expected_categories = BTreeMap::from([
        ("backup", 3_usize),
        ("claim", 15),
        ("contention", 5),
        ("corruption", 6),
        ("crash", 10),
        ("deadline", 6),
        ("initialization", 12),
        ("maintenance", 2),
        ("migration", 1),
        ("restore", 8),
    ]);
    let mut actual_categories = BTreeMap::new();
    for case in &manifest.cases {
        *actual_categories.entry(case.category).or_insert(0_usize) += 1;
        assert_eq!(case.profile, "synthetic-v1");
        assert!(valid_token(case.action));
        assert!(valid_token(case.case_id));
        assert!(valid_token(case.category));
        assert!(valid_token(case.fault));
        assert!(valid_token(case.setup));
        assert!(CLOSED_OUTCOMES.contains(&case.expected_outcome));
        assert!(CLOSED_STATES.contains(&case.expected_state));
        assert!(CLOSED_CODES.contains(&case.expected_code));
    }
    assert_eq!(actual_categories, expected_categories);
}

#[test]
fn redacted_summary_is_the_exact_manifest_projection() {
    let manifest = parse_cases(CASES_BYTES).expect("frozen case manifest must be canonical");
    let expected = parse_expected(EXPECTED_BYTES).expect("frozen summary must be canonical");

    assert_eq!(expected.schema, SUMMARY_SCHEMA);
    assert_eq!(sha256_hex(EXPECTED_BYTES), EXPECTED_SHA256);

    let projected = ExpectedManifest {
        cases: manifest
            .cases
            .iter()
            .map(|case| ExpectedCase {
                case_id: case.case_id,
                code: case.expected_code,
                outcome: case.expected_outcome,
                state: case.expected_state,
            })
            .collect(),
        schema: SUMMARY_SCHEMA,
    };
    assert_eq!(projected, expected);
    assert_eq!(serde_json::to_vec(&projected).unwrap(), EXPECTED_BYTES);
}

#[test]
fn corpus_evidence_is_stable_bounded_and_redacted() {
    let evidence = CorpusEvidence {
        case_count: EXPECTED_CASE_IDS.len(),
        cases_sha256: CASES_SHA256,
        expected_outcomes_sha256: EXPECTED_SHA256,
        schema: EVIDENCE_SCHEMA,
    };
    let json = serde_json::to_string(&evidence).unwrap();
    assert_eq!(
        json,
        concat!(
            "{\"case_count\":68,",
            "\"cases_sha256\":\"7db71958d28d135d1880daaaf57788b4476950a7835a4c85d633e8d921a3a5ff\",",
            "\"expected_outcomes_sha256\":\"687c562f05fe7e449f3df2b09505057a26420407e7df9c91b109a1d3950f25ac\",",
            "\"schema\":\"helixos.durable-replay-store-corpus-evidence/1\"}"
        )
    );
    assert!(json.is_ascii());
    assert!(json.len() < 320);
}

#[test]
fn strict_decoder_rejects_encoding_shape_and_canonicalization_drift() {
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(CASES_BYTES);
    assert_eq!(parse_cases(&bom).unwrap_err(), "CORPUS_INVALID");

    let mut trailing_newline = CASES_BYTES.to_vec();
    trailing_newline.push(b'\n');
    assert_eq!(
        parse_cases(&trailing_newline).unwrap_err(),
        "CORPUS_NON_CANONICAL"
    );

    assert_eq!(parse_cases(&[0xff]).unwrap_err(), "CORPUS_INVALID");
    assert_eq!(
        parse_cases(
            br#"{"cases":[],"schema":"helixos.durable-replay-store-cases/1","extra":true}"#
        )
        .unwrap_err(),
        "CORPUS_INVALID"
    );
    assert_eq!(
        parse_cases(br#"{"cases":[],"cases":[],"schema":"helixos.durable-replay-store-cases/1"}"#)
            .unwrap_err(),
        "CORPUS_INVALID"
    );
    assert_eq!(
        parse_cases(br#"{"schema":"helixos.durable-replay-store-cases/1"}"#).unwrap_err(),
        "CORPUS_INVALID"
    );
}
