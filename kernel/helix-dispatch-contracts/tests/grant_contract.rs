//! Frozen ExecutionGrantV1 schema, corpus, and cryptographic-profile contract.
//!
//! The fixture and schema assertions are independent oracles. The final source-contract
//! test intentionally stays red until T010--T013 add the reviewed production decoder.
//! T013 must additionally drive that decoder through all 143 frozen cases; source markers
//! are a compile-safe TDD seam, not behavioral conformance evidence.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use helix_dispatch_contracts::{
    decode_and_verify_execution_grant_v1, decode_and_verify_execution_receipt_v1,
    decode_and_verify_retained_execution_grant_v1, ContractError, ExecutionReceiptDecisionV1,
    ExecutionReceiptInputV1, ExecutionReceiptProtectedV1, ExecutionReceiptRefusalCodeV1,
    Generation, GrantKeyResolver, GrantVerificationKeyV1, Identifier, ReceiptKeyResolver,
    ReceiptVerificationBindingsV1, ReceiptVerificationKeyV1, ResourceRefV1,
    Result as ContractResult, SafeU64, Sha256Digest, VerificationKeyStatusV1,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

const GRANT_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/execution-grant-v1.schema.json");
const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const OUTCOMES: &str =
    include_str!("../../../contracts/fixtures/durable-dispatch-v1/expected-outcomes.json");

const GRANT_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-GRANT\0V1\0";
const RECEIPT_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-RECEIPT\0V1\0";

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

#[test]
fn grant_schema_is_closed_exhaustive_and_matches_the_frozen_inventory() {
    let schema = json(GRANT_SCHEMA);
    let corpus = json(CASES);
    let protected = &schema["$defs"]["protectedGrant"];

    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(protected["type"], "object");
    assert_eq!(protected["additionalProperties"], false);

    let outer_required = string_set(&schema["required"]);
    let outer_properties = object_key_set(&schema["properties"]);
    let expected_outer = BTreeSet::from([
        "grant_digest".to_owned(),
        "protected".to_owned(),
        "signature".to_owned(),
    ]);
    assert_eq!(outer_required, expected_outer);
    assert_eq!(outer_properties, expected_outer);

    let required = string_set(&protected["required"]);
    let properties = object_key_set(&protected["properties"]);
    let frozen = string_set(&corpus["coverage"]["grant_protected_fields"]);
    assert_eq!(required.len(), 69, "v1 grant field count changed");
    assert_eq!(required, properties, "required/properties schema drift");
    assert_eq!(required, frozen, "schema/corpus field inventory drift");

    assert_eq!(
        protected["properties"]["schema"]["const"],
        "helixos.execution-grant/1"
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
        "coordinator-dispatch-signing"
    );
    assert_eq!(protected["properties"]["protocol_version"]["const"], 1);
}

#[test]
fn every_grant_field_has_one_missing_field_case_and_one_closed_outcome() {
    let corpus = json(CASES);
    let outcomes = json(OUTCOMES);
    let outcome_index = outcome_by_id(&outcomes);
    let cases = corpus["cases"]
        .as_array()
        .expect("case inventory must be an array");

    let case_ids: BTreeSet<_> = cases
        .iter()
        .map(|case| case["id"].as_str().expect("case ID must be a string"))
        .collect();
    assert_eq!(case_ids.len(), cases.len(), "case IDs must be unique");
    assert_eq!(
        outcome_index.len(),
        outcomes["case_count"].as_u64().unwrap() as usize
    );
    assert_eq!(case_ids, outcome_index.keys().copied().collect());
    assert!(cases
        .iter()
        .all(|case| case["id"] == case["expected_outcome_id"]));

    for field in string_set(&corpus["coverage"]["grant_protected_fields"]) {
        let path = format!("/protected/{field}");
        let matches: Vec<_> = cases
            .iter()
            .filter(|case| {
                case["contract"] == "grant"
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
fn frozen_grant_corpus_covers_canonical_version_size_deadline_and_tamper_denials() {
    let outcomes = json(OUTCOMES);
    let index = outcome_by_id(&outcomes);
    let expected = [
        ("GRANT-RAW-DUPLICATE-MEMBER", "decode", "DUPLICATE_MEMBER"),
        (
            "GRANT-RAW-LEADING-WHITESPACE",
            "decode",
            "NON_CANONICAL_WIRE",
        ),
        ("GRANT-RAW-TRAILING-NEWLINE", "decode", "NON_CANONICAL_WIRE"),
        ("GRANT-RAW-UTF8-BOM", "decode", "NON_CANONICAL_WIRE"),
        (
            "GRANT-RAW-NONCANONICAL-KEY-ORDER",
            "decode",
            "NON_CANONICAL_WIRE",
        ),
        ("GRANT-RAW-OVERSIZE", "decode", "WIRE_TOO_LARGE"),
        ("GRANT-TAMPERED-DIGEST", "digest", "DIGEST_MISMATCH"),
        ("GRANT-TAMPERED-SIGNATURE", "signature", "SIGNATURE_INVALID"),
        ("GRANT-UNSUPPORTED-SCHEMA", "schema", "UNSUPPORTED_SCHEMA"),
        (
            "GRANT-UNSUPPORTED-DIGEST-ALGORITHM",
            "schema",
            "UNSUPPORTED_DIGEST_ALGORITHM",
        ),
        (
            "GRANT-UNSUPPORTED-SIGNATURE-ALGORITHM",
            "schema",
            "UNSUPPORTED_SIGNATURE_ALGORITHM",
        ),
        ("GRANT-WRONG-KEY-PURPOSE", "signature", "WRONG_KEY_PURPOSE"),
        (
            "GRANT-GRANT-LIFETIME-EXCEEDED",
            "deadline",
            "GRANT_LIFETIME_EXCEEDED",
        ),
        (
            "GRANT-UNSUPPORTED-PROTOCOL",
            "binding",
            "UNSUPPORTED_PROTOCOL",
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
fn reviewed_grant_base_has_exact_digest_domain_purpose_and_authentic_signature() {
    let corpus = json(CASES);
    let grant = &corpus["base_envelopes"]["grant.valid"];
    let protected = &grant["protected"];
    let protected_bytes =
        serde_json_canonicalizer::to_vec(protected).expect("protected grant must canonicalize");

    assert_eq!(
        lowercase_hex(&Sha256::digest(&protected_bytes)),
        grant["grant_digest"].as_str().unwrap()
    );
    assert_eq!(protected["key_purpose"], "coordinator-dispatch-signing");
    assert_eq!(
        protected["key_id"],
        corpus["verification_keys"]["grant"]["key_id"]
    );
    assert_eq!(
        corpus["verification_keys"]["grant"]["purpose"],
        "coordinator-dispatch-signing"
    );

    let public_key = decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    );
    let receipt_key = decode_base64::<32>(
        corpus["verification_keys"]["receipt"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    );
    let signature =
        Signature::from_bytes(&decode_base64::<64>(grant["signature"].as_str().unwrap()));
    let mut message = GRANT_DOMAIN.to_vec();
    message.extend_from_slice(&protected_bytes);

    let verifier = VerifyingKey::from_bytes(&public_key).expect("grant fixture key must be valid");
    verifier
        .verify_strict(&message, &signature)
        .expect("reviewed grant fixture signature must verify");
    assert!(VerifyingKey::from_bytes(&receipt_key)
        .unwrap()
        .verify_strict(&message, &signature)
        .is_err());

    let mut wrong_domain_message = RECEIPT_DOMAIN.to_vec();
    wrong_domain_message.extend_from_slice(&protected_bytes);
    assert!(verifier
        .verify_strict(&wrong_domain_message, &signature)
        .is_err());

    let issued = protected["issued_at_monotonic_ms"].as_u64().unwrap();
    let deadline = protected["deadline_monotonic_ms"].as_u64().unwrap();
    assert_eq!(deadline - issued, 5_000);
    let one_shot_ids = BTreeSet::from([
        protected["grant_id"].as_str().unwrap(),
        protected["dispatch_attempt_id"].as_str().unwrap(),
        protected["one_shot_nonce"].as_str().unwrap(),
    ]);
    assert_eq!(
        one_shot_ids.len(),
        3,
        "one-shot identities must be distinct"
    );

    let outer_bytes = serde_json_canonicalizer::to_vec(grant).unwrap();
    let reparsed: Value = serde_json::from_slice(&outer_bytes).unwrap();
    assert_eq!(
        serde_json_canonicalizer::to_vec(&reparsed).unwrap(),
        outer_bytes
    );
}

fn production_source(name: &str) -> Option<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(name);
    fs::read_to_string(path).ok()
}

#[test]
fn production_grant_decoder_implements_the_frozen_contract() {
    let required_modules = [
        "canonical.rs",
        "crypto.rs",
        "digest.rs",
        "error.rs",
        "grant.rs",
        "validation.rs",
    ];
    let missing: Vec<_> = required_modules
        .iter()
        .copied()
        .filter(|name| production_source(name).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "T007 RED: T010--T013 must add the production grant contract modules; missing {missing:?}"
    );

    let sources = required_modules
        .iter()
        .map(|name| production_source(name).unwrap())
        .chain([production_source("lib.rs").unwrap()])
        .collect::<Vec<_>>()
        .join("\n");
    for public_type in [
        "ExecutionGrantProtectedV1",
        "SignedExecutionGrantV1",
        "AuthenticExecutionGrantV1",
    ] {
        assert!(
            sources.contains(public_type),
            "production surface omits {public_type}"
        );
    }
    assert!(
        sources.contains("decode_and_verify_execution_grant_v1")
            || sources.contains("decode_and_verify_grant_v1"),
        "production surface must export a strict grant decode-and-verify entry point"
    );
    assert!(
        sources.contains("HELIXOS\\0EXECUTION-GRANT\\0V1\\0"),
        "production verifier must use the exact grant signature domain"
    );
    assert!(sources.contains("coordinator-dispatch-signing"));
    assert!(sources.contains("1_048_576") || sources.contains("1048576"));
    assert!(sources.contains("5_000") || sources.contains("5000"));
    assert!(
        (sources.contains("GrantSigner") || sources.contains("GrantSigning"))
            && sources.contains("Grant")
            && sources.contains("Resolver"),
        "grant signing and resolution must use purpose-specific traits"
    );
}

fn source_impl_block<'source>(source: &'source str, marker: &str) -> &'source str {
    let start = source
        .find(marker)
        .expect("reviewed impl marker must exist");
    let opening = source[start..].find('{').unwrap() + start;
    let mut depth = 0_u32;
    for (relative, character) in source[opening..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..opening + relative + 1];
                }
            }
            _ => {}
        }
    }
    panic!("reviewed impl block must close")
}

#[test]
fn authentic_claim_projections_expose_every_frozen_field_read_only() {
    let corpus = json(CASES);
    let grant_source = production_source("grant.rs").unwrap();
    let receipt_source = production_source("receipt.rs").unwrap();
    let grant_claims =
        source_impl_block(&grant_source, "impl<'grant> ExecutionGrantClaimsV1<'grant>");
    let receipt_claims = source_impl_block(
        &receipt_source,
        "impl<'receipt> ExecutionReceiptClaimsV1<'receipt>",
    );
    for field in string_set(&corpus["coverage"]["grant_protected_fields"]) {
        assert!(
            grant_claims.contains(&format!("fn {field}(")),
            "authentic grant projection omits {field}"
        );
    }
    for field in string_set(&corpus["coverage"]["receipt_protected_fields"]) {
        assert!(
            receipt_claims.contains(&format!("fn {field}(")),
            "authentic receipt projection omits {field}"
        );
    }
    let retained_claims = source_impl_block(
        &grant_source,
        "impl<'evidence> RetainedExecutionGrantClaimsV1<'evidence>",
    );
    for field in [
        "grant_id",
        "grant_digest",
        "operation_id",
        "destination_adapter_id",
        "protocol_version",
        "boot_id",
        "supervisor_epoch",
        "issued_at_monotonic_ms",
        "deadline_monotonic_ms",
    ] {
        assert!(
            retained_claims.contains(&format!("fn {field}(")),
            "retained evidence projection omits receipt binding {field}"
        );
    }
}

struct FixtureGrantResolver([u8; 32]);

impl GrantKeyResolver for FixtureGrantResolver {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        assert_eq!(key_id, "fixture-grant-key-v1");
        Ok(GrantVerificationKeyV1::current(self.0))
    }
}

struct HistoricalFixtureGrantResolver([u8; 32]);

impl GrantKeyResolver for HistoricalFixtureGrantResolver {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        assert_eq!(key_id, "fixture-grant-key-v1");
        Ok(GrantVerificationKeyV1::historical(self.0))
    }
}

struct FixtureReceiptResolver([u8; 32]);

impl ReceiptKeyResolver for FixtureReceiptResolver {
    fn resolve_receipt_key(&self, key_id: &str) -> ContractResult<ReceiptVerificationKeyV1> {
        assert_eq!(key_id, "fixture-receipt-key-v1");
        Ok(ReceiptVerificationKeyV1::current(self.0))
    }
}

struct HistoricalFixtureReceiptResolver([u8; 32]);

impl ReceiptKeyResolver for HistoricalFixtureReceiptResolver {
    fn resolve_receipt_key(&self, key_id: &str) -> ContractResult<ReceiptVerificationKeyV1> {
        assert_eq!(key_id, "fixture-receipt-key-v1");
        Ok(ReceiptVerificationKeyV1::historical(self.0))
    }
}

fn apply_json_mutation(value: &mut Value, mutation: &Value) {
    let path = mutation["path"].as_str().unwrap();
    let (parent_path, member) = path
        .rsplit_once('/')
        .expect("reviewed JSON mutation path must name one member");
    let object = value
        .pointer_mut(parent_path)
        .expect("reviewed JSON mutation parent must exist")
        .as_object_mut()
        .expect("reviewed JSON mutation parent must be an object");
    match mutation["op"].as_str().unwrap() {
        "remove" => {
            object
                .remove(member)
                .expect("reviewed removal member must exist");
        }
        "add" | "replace" => {
            object.insert(member.to_owned(), mutation["value"].clone());
        }
        operation => panic!("unsupported reviewed JSON mutation {operation}"),
    }
}

fn mutated_wire(base: &Value, mutation: &Value, contract: &str) -> Vec<u8> {
    let operation = mutation["op"].as_str().unwrap();
    if operation == "none" {
        return serde_json_canonicalizer::to_vec(base).unwrap();
    }
    if operation != "raw-transform" {
        let mut value = base.clone();
        apply_json_mutation(&mut value, mutation);
        return serde_json_canonicalizer::to_vec(&value).unwrap();
    }

    let canonical = serde_json_canonicalizer::to_vec(base).unwrap();
    match mutation["value"].as_str().unwrap() {
        "duplicate-member" => {
            let duplicate = serde_json::to_string(&base["signature"]).unwrap();
            format!(
                "{{\"signature\":{duplicate},{}",
                std::str::from_utf8(&canonical[1..]).unwrap()
            )
            .into_bytes()
        }
        "leading-whitespace" => [b" ".as_slice(), canonical.as_slice()].concat(),
        "trailing-newline" => [canonical.as_slice(), b"\n".as_slice()].concat(),
        "utf8-bom" => [[0xef, 0xbb, 0xbf].as_slice(), canonical.as_slice()].concat(),
        "noncanonical-key-order" => {
            let digest_name = if contract == "grant" {
                "grant_digest"
            } else {
                "receipt_digest"
            };
            format!(
                "{{\"signature\":{},\"protected\":{},\"{digest_name}\":{}}}",
                serde_json::to_string(&base["signature"]).unwrap(),
                serde_json_canonicalizer::to_string(&base["protected"]).unwrap(),
                serde_json::to_string(&base[digest_name]).unwrap(),
            )
            .into_bytes()
        }
        "oversize" => vec![
            b' ';
            if contract == "grant" {
                1_048_577
            } else {
                65_537
            }
        ],
        transform => panic!("unsupported reviewed raw transform {transform}"),
    }
}

#[test]
fn production_decoders_branch_over_all_143_frozen_cases() {
    let corpus = json(CASES);
    let outcomes = json(OUTCOMES);
    let outcome_index = outcome_by_id(&outcomes);
    let grant_resolver = FixtureGrantResolver(decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let receipt_resolver = FixtureReceiptResolver(decode_base64::<32>(
        corpus["verification_keys"]["receipt"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let canonical_grant =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap();
    let authentic_grant =
        decode_and_verify_execution_grant_v1(&canonical_grant, &grant_resolver).unwrap();
    let adapter_root = Sha256Digest::parse_hex(
        corpus["base_envelopes"]["receipt.consumed.valid"]["protected"]["adapter_root_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let receipt_bindings = ReceiptVerificationBindingsV1::new(&authentic_grant, adapter_root);

    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 143);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let contract = case["contract"].as_str().unwrap();
        let base = &corpus["base_envelopes"][case["base"].as_str().unwrap()];
        let wire = mutated_wire(base, &case["mutation"], contract);
        let expected = outcome_index[id];
        match contract {
            "grant" => match decode_and_verify_execution_grant_v1(&wire, &grant_resolver) {
                Ok(_) => {
                    assert_eq!(expected["result"], "ACCEPT_GRANT", "{id}");
                    assert_eq!(expected["reason"], "VALID", "{id}");
                }
                Err(error) => {
                    assert_eq!(expected["result"], "DENY", "{id}: {error}");
                    assert_eq!(error.code(), expected["reason"].as_str().unwrap(), "{id}");
                }
            },
            "receipt" => match decode_and_verify_execution_receipt_v1(
                &wire,
                &receipt_resolver,
                &receipt_bindings,
            ) {
                Ok(receipt) => {
                    assert_eq!(expected["result"], "ACCEPT_RECEIPT", "{id}");
                    let reason = match (
                        receipt.protected().decision(),
                        receipt.protected().refusal_code(),
                    ) {
                        (ExecutionReceiptDecisionV1::Consumed, None) => "CONSUMED",
                        (
                            ExecutionReceiptDecisionV1::RefusedDefinite,
                            Some(ExecutionReceiptRefusalCodeV1::GrantExpired),
                        ) => "GRANT_EXPIRED",
                        (
                            ExecutionReceiptDecisionV1::RefusedDefinite,
                            Some(ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch),
                        ) => "SUPERVISOR_EPOCH_MISMATCH",
                        (
                            ExecutionReceiptDecisionV1::RefusedDefinite,
                            Some(ExecutionReceiptRefusalCodeV1::AdapterPaused),
                        ) => "ADAPTER_PAUSED",
                        shape => panic!("unexpected authentic receipt shape {shape:?}"),
                    };
                    assert_eq!(reason, expected["reason"].as_str().unwrap(), "{id}");
                }
                Err(error) => {
                    assert_eq!(expected["result"], "DENY", "{id}: {error}");
                    assert_eq!(error.code(), expected["reason"].as_str().unwrap(), "{id}");
                }
            },
            unexpected => panic!("unexpected frozen contract {unexpected}"),
        }
    }
}

#[test]
fn retained_receipt_verifies_with_historical_public_key_as_evidence_only() {
    let corpus = json(CASES);
    let grant_resolver = FixtureGrantResolver(decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let historical_receipt_resolver = HistoricalFixtureReceiptResolver(decode_base64::<32>(
        corpus["verification_keys"]["receipt"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let grant_wire =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap();
    let grant = decode_and_verify_execution_grant_v1(&grant_wire, &grant_resolver).unwrap();
    let adapter_root = Sha256Digest::parse_hex(
        corpus["base_envelopes"]["receipt.consumed.valid"]["protected"]["adapter_root_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let bindings = ReceiptVerificationBindingsV1::new(&grant, adapter_root);
    let receipt_wire =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["receipt.consumed.valid"])
            .unwrap();
    let evidence = decode_and_verify_execution_receipt_v1(
        &receipt_wire,
        &historical_receipt_resolver,
        &bindings,
    )
    .unwrap();

    assert_eq!(
        evidence.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(
        evidence.canonical_signed_envelope_bytes().unwrap(),
        receipt_wire
    );
    assert_eq!(
        evidence.protected().decision(),
        ExecutionReceiptDecisionV1::Consumed
    );
}

#[test]
fn historical_grant_key_cannot_create_current_authority_but_can_verify_retained_evidence() {
    let corpus = json(CASES);
    let resolver = HistoricalFixtureGrantResolver(decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let wire = serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap();

    assert_eq!(
        decode_and_verify_execution_grant_v1(&wire, &resolver)
            .expect_err("historical keys cannot create current grant authority"),
        ContractError::HistoricalKeyNotAuthority
    );
    let evidence = decode_and_verify_retained_execution_grant_v1(&wire, &resolver)
        .expect("historical public keys still verify retained signed evidence");
    assert_eq!(
        evidence.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(evidence.canonical_signed_envelope_bytes().unwrap(), wire);
}

#[test]
fn historical_grant_and_receipt_keys_verify_cross_bound_evidence_after_restart() {
    let corpus = json(CASES);
    let grant_resolver = HistoricalFixtureGrantResolver(decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let receipt_resolver = HistoricalFixtureReceiptResolver(decode_base64::<32>(
        corpus["verification_keys"]["receipt"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let grant_wire =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap();
    let retained_grant =
        decode_and_verify_retained_execution_grant_v1(&grant_wire, &grant_resolver).unwrap();
    let adapter_root = Sha256Digest::parse_hex(
        corpus["base_envelopes"]["receipt.consumed.valid"]["protected"]["adapter_root_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let bindings =
        ReceiptVerificationBindingsV1::from_retained_grant_evidence(&retained_grant, adapter_root);
    let receipt_wire =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["receipt.consumed.valid"])
            .unwrap();
    let receipt =
        decode_and_verify_execution_receipt_v1(&receipt_wire, &receipt_resolver, &bindings)
            .unwrap();

    assert_eq!(
        retained_grant.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(
        receipt.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(
        receipt.claims().grant_id(),
        retained_grant.claims().grant_id()
    );
    assert_eq!(
        receipt.claims().grant_digest(),
        retained_grant.claims().grant_digest()
    );
}

#[test]
fn authentic_claim_projections_cover_inbox_coordinator_and_durability_bindings() {
    let corpus = json(CASES);
    let grant_resolver = FixtureGrantResolver(decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let receipt_resolver = FixtureReceiptResolver(decode_base64::<32>(
        corpus["verification_keys"]["receipt"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let grant_wire =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap();
    let grant = decode_and_verify_execution_grant_v1(&grant_wire, &grant_resolver).unwrap();
    let grant_claims = grant.claims();
    assert_eq!(grant_claims.schema(), "helixos.execution-grant/1");
    assert_eq!(grant_claims.key_purpose(), "coordinator-dispatch-signing");
    assert_ne!(grant_claims.grant_id(), grant_claims.one_shot_nonce());
    assert_eq!(grant_claims.operation_id(), "operation-v1");
    assert_eq!(grant_claims.target().root_id(), "workspace");
    assert_eq!(grant_claims.capability_report_generation(), 10);
    assert_eq!(grant_claims.replay_claimant_generation(), 11);
    assert_eq!(grant_claims.budget_scope_generation(), 12);
    assert_eq!(grant_claims.reservation_generation(), 13);
    assert_eq!(grant_claims.supervisor_epoch(), 15);
    assert_eq!(grant_claims.clock_generation(), 17);
    assert_eq!(grant_claims.deadline_monotonic_ms(), 6_000);

    let adapter_root = Sha256Digest::parse_hex(
        corpus["base_envelopes"]["receipt.consumed.valid"]["protected"]["adapter_root_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let bindings = ReceiptVerificationBindingsV1::new(&grant, adapter_root);
    let receipt_wire =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["receipt.consumed.valid"])
            .unwrap();
    let receipt =
        decode_and_verify_execution_receipt_v1(&receipt_wire, &receipt_resolver, &bindings)
            .unwrap();
    let receipt_claims = receipt.claims();
    assert_eq!(receipt_claims.schema(), "helixos.execution-receipt/1");
    assert_eq!(receipt_claims.grant_id(), grant_claims.grant_id());
    assert_eq!(receipt_claims.grant_digest(), grant_claims.grant_digest());
    assert_eq!(receipt_claims.operation_id(), grant_claims.operation_id());
    assert_eq!(receipt_claims.inbox_generation(), 1);
    assert_eq!(receipt_claims.consumption_generation(), Some(2));
    assert_eq!(receipt_claims.refusal_generation(), None);
    assert_eq!(receipt_claims.receipt_generation(), 3);
    assert_eq!(receipt_claims.observed_supervisor_epoch(), 15);
}

#[test]
fn resource_components_require_nfc_and_reject_default_ignorables() {
    ResourceRefV1::try_new("workspace", vec!["café.txt".to_owned()])
        .expect("precomposed NFC is portable");
    for forbidden in ["cafe\u{0301}.txt", "soft\u{00ad}hyphen", "join\u{034f}er"] {
        assert!(
            ResourceRefV1::try_new("workspace", vec![forbidden.to_owned()]).is_err(),
            "non-NFC/default-ignorable component must deny"
        );
    }
}

#[test]
fn receipt_temporal_and_epoch_refusal_shapes_deny_when_relationally_incoherent() {
    let corpus = json(CASES);
    let grant_resolver = FixtureGrantResolver(decode_base64::<32>(
        corpus["verification_keys"]["grant"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let receipt_resolver = FixtureReceiptResolver(decode_base64::<32>(
        corpus["verification_keys"]["receipt"]["public_key_base64url"]
            .as_str()
            .unwrap(),
    ));
    let grant_wire =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"]).unwrap();
    let grant = decode_and_verify_execution_grant_v1(&grant_wire, &grant_resolver).unwrap();
    let adapter_root = Sha256Digest::parse_hex(
        corpus["base_envelopes"]["receipt.consumed.valid"]["protected"]["adapter_root_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let bindings = ReceiptVerificationBindingsV1::new(&grant, adapter_root);

    let cases = [
        (
            "receipt.consumed.valid",
            "/protected/decided_at_monotonic_ms",
            json!(6_000),
            ContractError::GrantBindingMismatch,
        ),
        (
            "receipt.refused.grant-expired.valid",
            "/protected/decided_at_monotonic_ms",
            json!(5_999),
            ContractError::GrantBindingMismatch,
        ),
        (
            "receipt.refused.supervisor-epoch-mismatch.valid",
            "/protected/observed_supervisor_epoch",
            json!(15),
            ContractError::SupervisorEpochBindingMismatch,
        ),
        (
            "receipt.consumed.valid",
            "/protected/decided_at_monotonic_ms",
            json!(999),
            ContractError::GrantBindingMismatch,
        ),
        (
            "receipt.consumed.valid",
            "/protected/consumption_generation",
            json!(1),
            ContractError::InvalidField,
        ),
        (
            "receipt.refused.adapter-paused.valid",
            "/protected/refusal_generation",
            json!(3),
            ContractError::InvalidField,
        ),
    ];
    for (base, path, replacement, expected) in cases {
        let mut value = corpus["base_envelopes"][base].clone();
        *value.pointer_mut(path).unwrap() = replacement;
        let wire = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            decode_and_verify_execution_receipt_v1(&wire, &receipt_resolver, &bindings)
                .expect_err("incoherent receipt relationship must deny"),
            expected,
            "{base}"
        );
    }
}

fn receipt_input(decision: ExecutionReceiptDecisionV1) -> ExecutionReceiptInputV1 {
    let digest = Sha256Digest::from_bytes([0x31; 32]);
    let (consumption_generation, refusal_generation, refusal_code, tombstone) = match decision {
        ExecutionReceiptDecisionV1::Consumed => {
            (Some(Generation::new(2).unwrap()), None, None, None)
        }
        ExecutionReceiptDecisionV1::RefusedDefinite => (
            None,
            Some(Generation::new(2).unwrap()),
            Some(ExecutionReceiptRefusalCodeV1::AdapterPaused),
            Some(digest),
        ),
    };
    ExecutionReceiptInputV1 {
        receipt_id: Sha256Digest::from_bytes([0x30; 32]),
        grant_id: Sha256Digest::from_bytes([0x20; 32]),
        grant_digest: Sha256Digest::from_bytes([0x21; 32]),
        operation_id: Identifier::new("operation-v1").unwrap(),
        destination_adapter_id: Identifier::new("adapter-v1").unwrap(),
        adapter_root_id: Sha256Digest::from_bytes([0x22; 32]),
        inbox_generation: Generation::new(1).unwrap(),
        consumption_generation,
        refusal_generation,
        receipt_generation: Generation::new(3).unwrap(),
        observed_boot_id: Identifier::new("boot-v1").unwrap(),
        observed_supervisor_epoch: SafeU64::new(15).unwrap(),
        epoch_observer_generation: Generation::new(18).unwrap(),
        decision,
        refusal_code,
        no_consumption_tombstone_digest: tombstone,
        decided_at_utc_ms: SafeU64::new(1_000_100).unwrap(),
        decided_at_monotonic_ms: SafeU64::new(1_100).unwrap(),
        trace_id: Identifier::new("trace-v1").unwrap(),
    }
}

#[test]
fn receipt_constructor_enforces_internal_generation_order_for_both_decisions() {
    let key_id = || Identifier::new("fixture-receipt-key-v1").unwrap();
    ExecutionReceiptProtectedV1::try_new(
        receipt_input(ExecutionReceiptDecisionV1::Consumed),
        key_id(),
    )
    .expect("ordered consumed generations are valid");
    ExecutionReceiptProtectedV1::try_new(
        receipt_input(ExecutionReceiptDecisionV1::RefusedDefinite),
        key_id(),
    )
    .expect("ordered refusal generations are valid");

    let mut consumed = receipt_input(ExecutionReceiptDecisionV1::Consumed);
    consumed.consumption_generation = Some(Generation::new(1).unwrap());
    assert_eq!(
        ExecutionReceiptProtectedV1::try_new(consumed, key_id())
            .expect_err("receive must precede consumption"),
        ContractError::InvalidField
    );

    let mut refused = receipt_input(ExecutionReceiptDecisionV1::RefusedDefinite);
    refused.receipt_generation = Generation::new(2).unwrap();
    assert_eq!(
        ExecutionReceiptProtectedV1::try_new(refused, key_id())
            .expect_err("decision must precede receipt retention"),
        ContractError::InvalidField
    );
}
