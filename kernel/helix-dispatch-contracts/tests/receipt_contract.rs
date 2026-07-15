//! Frozen ExecutionReceiptV1 schema, decision, binding, and signature contract.
//!
//! These fixture oracles stay executable before the production receipt decoder exists;
//! the final source-contract test supplies the deliberate, precise TDD red state. T013
//! must additionally drive the decoder through all 143 frozen cases: source markers are
//! not a substitute for behavioral decode-and-verify conformance.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

const RECEIPT_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/execution-receipt-v1.schema.json");
const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const OUTCOMES: &str =
    include_str!("../../../contracts/fixtures/durable-dispatch-v1/expected-outcomes.json");

const GRANT_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-GRANT\0V1\0";
const RECEIPT_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-RECEIPT\0V1\0";
const POST_RECEIVED_REFUSALS: [&str; 3] = [
    "ADAPTER_PAUSED",
    "GRANT_EXPIRED",
    "SUPERVISOR_EPOCH_MISMATCH",
];
const PRE_RECEIVED_REFUSALS: [&str; 4] = [
    "CAPABILITY_MISMATCH",
    "DESTINATION_MISMATCH",
    "INBOX_CAPACITY_EXHAUSTED",
    "PROTOCOL_UNSUPPORTED",
];

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("reviewed PLAN-005 JSON must decode")
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("reviewed inventory must be an array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("reviewed inventory member must be a string")
                .to_owned()
        })
        .collect()
}

fn object_key_set(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("reviewed schema member must be an object")
        .keys()
        .cloned()
        .collect()
}

fn outcome_by_id(outcomes: &Value) -> BTreeMap<&str, &Value> {
    outcomes["outcomes"]
        .as_array()
        .expect("outcome inventory must be an array")
        .iter()
        .map(|outcome| {
            (
                outcome["id"].as_str().expect("outcome ID must be a string"),
                outcome,
            )
        })
        .collect()
}

fn decode_base64<const N: usize>(encoded: &str) -> [u8; N] {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("fixture base64url must decode")
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| {
            panic!("fixture byte length was {}, expected {N}", bytes.len())
        })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn receipt_schema_is_closed_exhaustive_and_matches_the_frozen_inventory() {
    let schema = json(RECEIPT_SCHEMA);
    let corpus = json(CASES);
    let protected = &schema["$defs"]["protectedReceipt"];

    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(protected["type"], "object");
    assert_eq!(protected["additionalProperties"], false);

    let expected_outer = BTreeSet::from([
        "protected".to_owned(),
        "receipt_digest".to_owned(),
        "signature".to_owned(),
    ]);
    assert_eq!(string_set(&schema["required"]), expected_outer);
    assert_eq!(object_key_set(&schema["properties"]), expected_outer);

    let required = string_set(&protected["required"]);
    let properties = object_key_set(&protected["properties"]);
    let frozen = string_set(&corpus["coverage"]["receipt_protected_fields"]);
    assert_eq!(required.len(), 25, "v1 receipt field count changed");
    assert_eq!(required, properties, "required/properties schema drift");
    assert_eq!(required, frozen, "schema/corpus field inventory drift");

    assert_eq!(
        protected["properties"]["schema"]["const"],
        "helixos.execution-receipt/1"
    );
    assert_eq!(
        protected["properties"]["digest_algorithm"]["const"],
        "sha-256"
    );
    assert_eq!(
        protected["properties"]["signature_algorithm"]["const"],
        "ed25519"
    );
    assert_eq!(
        protected["properties"]["key_purpose"]["const"],
        "adapter-receipt-signing"
    );
    assert_eq!(protected["properties"]["protocol_version"]["const"], 1);
}

#[test]
fn receipt_decision_and_post_received_refusal_vocabularies_are_exactly_closed() {
    let schema = json(RECEIPT_SCHEMA);
    let protected = &schema["$defs"]["protectedReceipt"];
    let expected_decisions = BTreeSet::from(["CONSUMED".to_owned(), "REFUSED_DEFINITE".to_owned()]);
    let expected_refusals = POST_RECEIVED_REFUSALS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        string_set(&protected["properties"]["decision"]["enum"]),
        expected_decisions
    );
    assert_eq!(
        string_set(&schema["$defs"]["nullableRefusalCode"]["oneOf"][0]["enum"]),
        expected_refusals
    );
    assert_eq!(
        string_set(&protected["oneOf"][1]["properties"]["refusal_code"]["enum"]),
        expected_refusals
    );

    let serialized_schema = serde_json_canonicalizer::to_string(&schema).unwrap();
    for forbidden in PRE_RECEIVED_REFUSALS {
        assert!(
            !serialized_schema.contains(forbidden),
            "pre-RECEIVED code {forbidden} must not be serializable as a receipt"
        );
    }

    let consumed = &protected["oneOf"][0]["properties"];
    assert_eq!(consumed["decision"]["const"], "CONSUMED");
    for null_member in [
        "refusal_generation",
        "refusal_code",
        "no_consumption_tombstone_digest",
    ] {
        assert_eq!(consumed[null_member]["type"], "null");
    }
    let refused = &protected["oneOf"][1]["properties"];
    assert_eq!(refused["decision"]["const"], "REFUSED_DEFINITE");
    assert_eq!(refused["consumption_generation"]["type"], "null");
}

#[test]
fn every_receipt_field_has_one_missing_field_case_and_one_closed_outcome() {
    let corpus = json(CASES);
    let outcomes = json(OUTCOMES);
    let outcome_index = outcome_by_id(&outcomes);
    let cases = corpus["cases"]
        .as_array()
        .expect("case inventory must be an array");

    for field in string_set(&corpus["coverage"]["receipt_protected_fields"]) {
        let path = format!("/protected/{field}");
        let matches: Vec<_> = cases
            .iter()
            .filter(|case| {
                case["contract"] == "receipt"
                    && case["mutation"]["op"] == "remove"
                    && case["mutation"]["path"] == path
            })
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "missing exhaustive removal case for {field}"
        );
        let id = matches[0]["id"].as_str().unwrap();
        let outcome = outcome_index[id];
        assert_eq!(outcome["result"], "DENY");
        assert_eq!(outcome["stage"], "schema");
        assert_eq!(outcome["reason"], "MISSING_REQUIRED_FIELD");
        assert_eq!(outcome["authority"], "NONE");
    }
}

#[test]
fn corpus_proves_pre_received_codes_bindings_shapes_size_and_tamper_deny() {
    let outcomes = json(OUTCOMES);
    let index = outcome_by_id(&outcomes);

    for code in PRE_RECEIVED_REFUSALS {
        let id = format!("RECEIPT-PRE-RECEIVED-CODE-{}", code.replace('_', "-"));
        let outcome = index
            .get(id.as_str())
            .unwrap_or_else(|| panic!("missing corpus outcome {id}"));
        assert_eq!(outcome["result"], "DENY");
        assert_eq!(outcome["stage"], "decision");
        assert_eq!(outcome["reason"], "PRE_RECEIVED_CODE_NOT_RECEIPT");
        assert_eq!(outcome["authority"], "NONE");
    }

    let expected = [
        ("RECEIPT-RAW-DUPLICATE-MEMBER", "decode", "DUPLICATE_MEMBER"),
        (
            "RECEIPT-RAW-NONCANONICAL-KEY-ORDER",
            "decode",
            "NON_CANONICAL_WIRE",
        ),
        ("RECEIPT-RAW-OVERSIZE", "decode", "WIRE_TOO_LARGE"),
        ("RECEIPT-TAMPERED-DIGEST", "digest", "DIGEST_MISMATCH"),
        (
            "RECEIPT-TAMPERED-SIGNATURE",
            "signature",
            "SIGNATURE_INVALID",
        ),
        (
            "RECEIPT-WRONG-KEY-PURPOSE",
            "signature",
            "WRONG_KEY_PURPOSE",
        ),
        (
            "RECEIPT-UNSUPPORTED-PROTOCOL",
            "binding",
            "UNSUPPORTED_PROTOCOL",
        ),
        (
            "RECEIPT-GRANT-BINDING-MISMATCH",
            "binding",
            "GRANT_BINDING_MISMATCH",
        ),
        (
            "RECEIPT-OPERATION-BINDING-MISMATCH",
            "binding",
            "OPERATION_BINDING_MISMATCH",
        ),
        (
            "RECEIPT-DESTINATION-BINDING-MISMATCH",
            "binding",
            "DESTINATION_BINDING_MISMATCH",
        ),
        (
            "RECEIPT-ADAPTER-ROOT-BINDING-MISMATCH",
            "binding",
            "ADAPTER_ROOT_BINDING_MISMATCH",
        ),
        (
            "RECEIPT-SUPERVISOR-EPOCH-BINDING-MISMATCH",
            "binding",
            "SUPERVISOR_EPOCH_BINDING_MISMATCH",
        ),
        (
            "RECEIPT-CONSUMED-WITH-REFUSAL-CODE",
            "decision",
            "INVALID_DECISION_SHAPE",
        ),
        (
            "RECEIPT-REFUSED-WITH-CONSUMPTION-GENERATION",
            "decision",
            "INVALID_DECISION_SHAPE",
        ),
    ];
    for (id, stage, reason) in expected {
        let outcome = index
            .get(id)
            .unwrap_or_else(|| panic!("missing corpus outcome {id}"));
        assert_eq!(outcome["result"], "DENY", "{id}");
        assert_eq!(outcome["stage"], stage, "{id}");
        assert_eq!(outcome["reason"], reason, "{id}");
        assert_eq!(outcome["authority"], "NONE", "{id}");
    }
}

#[test]
fn all_reviewed_receipt_bases_have_exact_digest_domain_purpose_and_signature() {
    let corpus = json(CASES);
    let receipt_key = decode_base64::<32>(
        corpus["verification_keys"]["receipt"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    );
    let grant_key = decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    );
    let receipt_verifier = VerifyingKey::from_bytes(&receipt_key).unwrap();
    let grant_verifier = VerifyingKey::from_bytes(&grant_key).unwrap();

    let bases = corpus["base_envelopes"].as_object().unwrap();
    let receipt_bases: Vec<_> = bases
        .iter()
        .filter(|(name, _)| name.starts_with("receipt."))
        .collect();
    assert_eq!(receipt_bases.len(), 4);

    let mut decisions = BTreeSet::new();
    let mut refusals = BTreeSet::new();
    for (name, receipt) in receipt_bases {
        let protected = &receipt["protected"];
        assert_eq!(
            protected["key_purpose"], "adapter-receipt-signing",
            "{name}"
        );
        assert_eq!(
            protected["key_id"],
            corpus["verification_keys"]["receipt"]["key_id"]
        );
        let protected_bytes = serde_json_canonicalizer::to_vec(protected).unwrap();
        assert_eq!(
            lowercase_hex(&Sha256::digest(&protected_bytes)),
            receipt["receipt_digest"].as_str().unwrap(),
            "{name}"
        );
        let signature =
            Signature::from_bytes(&decode_base64::<64>(receipt["signature"].as_str().unwrap()));
        let mut message = RECEIPT_DOMAIN.to_vec();
        message.extend_from_slice(&protected_bytes);
        receipt_verifier
            .verify_strict(&message, &signature)
            .unwrap_or_else(|_| panic!("reviewed receipt signature failed for {name}"));
        assert!(
            grant_verifier.verify_strict(&message, &signature).is_err(),
            "{name}"
        );

        let mut wrong_domain_message = GRANT_DOMAIN.to_vec();
        wrong_domain_message.extend_from_slice(&protected_bytes);
        assert!(
            receipt_verifier
                .verify_strict(&wrong_domain_message, &signature)
                .is_err(),
            "{name}"
        );
        decisions.insert(protected["decision"].as_str().unwrap().to_owned());
        if let Some(code) = protected["refusal_code"].as_str() {
            refusals.insert(code.to_owned());
        }
    }

    assert_eq!(
        decisions,
        BTreeSet::from(["CONSUMED".to_owned(), "REFUSED_DEFINITE".to_owned()])
    );
    assert_eq!(
        refusals,
        POST_RECEIVED_REFUSALS
            .iter()
            .map(|value| (*value).to_owned())
            .collect()
    );
}

fn production_source(name: &str) -> Option<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(name);
    fs::read_to_string(path).ok()
}

fn closed_unit_enum_variants(source: &str, enum_name: &str) -> BTreeSet<String> {
    let declaration = format!("enum {enum_name}");
    let after_declaration = source
        .split_once(&declaration)
        .unwrap_or_else(|| panic!("production receipt source omits {enum_name}"))
        .1;
    let body_start = after_declaration
        .find('{')
        .unwrap_or_else(|| panic!("{enum_name} has no enum body"));
    let mut depth = 0_u32;
    let mut body_end = None;
    for (offset, character) in after_declaration[body_start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    body_end = Some(body_start + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &after_declaration[body_start + 1..body_end.expect("enum body must close")];
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with("#"))
        .map(|line| line.trim_end_matches(',').to_owned())
        .collect()
}

#[test]
fn production_receipt_decoder_implements_the_frozen_contract() {
    let required_modules = [
        "canonical.rs",
        "crypto.rs",
        "digest.rs",
        "error.rs",
        "receipt.rs",
        "validation.rs",
    ];
    let missing: Vec<_> = required_modules
        .iter()
        .copied()
        .filter(|name| production_source(name).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "T008 RED: T010--T013 must add the production receipt contract modules; missing {missing:?}"
    );

    let receipt_source = production_source("receipt.rs").unwrap();
    let sources = required_modules
        .iter()
        .map(|name| production_source(name).unwrap())
        .chain([production_source("lib.rs").unwrap()])
        .collect::<Vec<_>>()
        .join("\n");
    for public_type in [
        "ExecutionReceiptProtectedV1",
        "SignedExecutionReceiptV1",
        "AuthenticExecutionReceiptV1",
    ] {
        assert!(
            sources.contains(public_type),
            "production surface omits {public_type}"
        );
    }
    assert!(
        sources.contains("decode_and_verify_execution_receipt_v1")
            || sources.contains("decode_and_verify_receipt_v1"),
        "production surface must export a strict receipt decode-and-verify entry point"
    );
    assert!(sources.contains("HELIXOS\\0EXECUTION-RECEIPT\\0V1\\0"));
    assert!(sources.contains("adapter-receipt-signing"));
    assert!(sources.contains("65_536") || sources.contains("65536"));
    assert!(
        (sources.contains("ReceiptSigner") || sources.contains("ReceiptSigning"))
            && sources.contains("Receipt")
            && sources.contains("Resolver"),
        "receipt signing and resolution must use purpose-specific traits"
    );
    assert_eq!(
        closed_unit_enum_variants(&receipt_source, "ExecutionReceiptRefusalCodeV1"),
        BTreeSet::from([
            "AdapterPaused".to_owned(),
            "GrantExpired".to_owned(),
            "SupervisorEpochMismatch".to_owned(),
        ]),
        "the signed receipt refusal enum must contain exactly the three post-RECEIVED variants"
    );
    for allowed in POST_RECEIVED_REFUSALS {
        assert!(
            receipt_source.contains(allowed),
            "wire mapping omits {allowed}"
        );
    }
}
