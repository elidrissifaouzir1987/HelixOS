//! Cross-contract foundation tests for PLAN-006.
//!
//! The schema and primitive oracles are executable before the production foundation
//! exists. The final source-contract test is the intentional T009 RED seam: it stays
//! compilable and reports the exact T011--T014 modules still missing.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

const GRANT_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/human-request-grant-v1.schema.json"
);
const LEASE_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/task-lease-v1.schema.json"
);
const DECISION_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/approval-decision-v1.schema.json"
);

#[derive(Clone, Copy, Debug)]
struct Profile {
    protected_definition: &'static str,
    protected_schema: &'static str,
    outer_digest: &'static str,
    key_purpose: &'static str,
    domain_source: &'static str,
}

const PROFILES: [Profile; 3] = [
    Profile {
        protected_definition: "protectedGrant",
        protected_schema: "helixos.human-request-grant/1",
        outer_digest: "grant_digest",
        key_purpose: "request-surface-grant-signing",
        domain_source: "HELIXOS\\0HUMAN-REQUEST-GRANT\\0V1\\0",
    },
    Profile {
        protected_definition: "protectedLease",
        protected_schema: "helixos.task-lease/1",
        outer_digest: "lease_digest",
        key_purpose: "core-task-lease-signing",
        domain_source: "HELIXOS\\0TASK-LEASE\\0V1\\0",
    },
    Profile {
        protected_definition: "protectedDecision",
        protected_schema: "helixos.approval-decision/1",
        outer_digest: "decision_digest",
        key_purpose: "core-approval-decision-signing",
        domain_source: "HELIXOS\\0APPROVAL-DECISION\\0V1\\0",
    },
];

fn parse_schema(text: &str) -> Value {
    serde_json::from_str(text).expect("reviewed PLAN-006 schema must decode")
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("reviewed inventory must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
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

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(key) || object.values().any(|child| contains_key(child, key))
        }
        Value::Array(array) => array.iter().any(|child| contains_key(child, key)),
        _ => false,
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn schemas_freeze_three_distinct_closed_v1_profiles() {
    let schemas = [
        parse_schema(GRANT_SCHEMA),
        parse_schema(LEASE_SCHEMA),
        parse_schema(DECISION_SCHEMA),
    ];

    let mut schema_names = BTreeSet::new();
    let mut digest_members = BTreeSet::new();
    let mut purposes = BTreeSet::new();
    let mut domains = BTreeSet::new();

    for (schema, profile) in schemas.iter().zip(PROFILES) {
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        assert!(!contains_key(schema, "default"), "v1 has no defaults");

        let expected_outer = BTreeSet::from([
            "protected".to_owned(),
            profile.outer_digest.to_owned(),
            "signature".to_owned(),
        ]);
        assert_eq!(string_set(&schema["required"]), expected_outer);
        assert_eq!(object_key_set(&schema["properties"]), expected_outer);

        let protected = &schema["$defs"][profile.protected_definition];
        assert_eq!(protected["type"], "object");
        assert_eq!(protected["additionalProperties"], false);
        assert_eq!(
            string_set(&protected["required"]),
            object_key_set(&protected["properties"]),
            "{} required/properties drift",
            profile.protected_schema
        );
        assert_eq!(
            protected["properties"]["schema"]["const"],
            profile.protected_schema
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
            profile.key_purpose
        );

        schema_names.insert(profile.protected_schema);
        digest_members.insert(profile.outer_digest);
        purposes.insert(profile.key_purpose);
        domains.insert(profile.domain_source);
    }

    assert_eq!(schema_names.len(), 3);
    assert_eq!(digest_members.len(), 3);
    assert_eq!(purposes.len(), 3);
    assert_eq!(domains.len(), 3);
}

#[test]
fn schemas_share_exact_safe_integer_digest_identifier_and_signature_domains() {
    let schemas = [
        parse_schema(GRANT_SCHEMA),
        parse_schema(LEASE_SCHEMA),
        parse_schema(DECISION_SCHEMA),
    ];

    for schema in &schemas {
        let definitions = &schema["$defs"];
        assert_eq!(definitions["safeInteger"]["type"], "integer");
        assert_eq!(definitions["safeInteger"]["minimum"], 0);
        assert_eq!(
            definitions["safeInteger"]["maximum"],
            9_007_199_254_740_991_u64
        );
        assert_eq!(definitions["generation"]["type"], "integer");
        assert_eq!(definitions["generation"]["minimum"], 1);
        assert_eq!(
            definitions["generation"]["maximum"],
            9_007_199_254_740_991_u64
        );
        assert_eq!(definitions["identifier"]["type"], "string");
        assert_eq!(definitions["identifier"]["minLength"], 1);
        assert_eq!(definitions["identifier"]["maxLength"], 128);
        assert_eq!(definitions["identifier"]["pattern"], "^[-A-Za-z0-9._:]+$");
        assert_eq!(definitions["sha256Digest"]["pattern"], "^[0-9a-f]{64}$");
        assert_eq!(definitions["ed25519Signature"]["minLength"], 86);
        assert_eq!(definitions["ed25519Signature"]["maxLength"], 86);
        assert_eq!(
            definitions["ed25519Signature"]["pattern"],
            "^[A-Za-z0-9_-]{85}[AQgw]$"
        );
    }
}

#[test]
fn independent_canonical_digest_and_base64url_oracles_are_exact() {
    let canonical = serde_json_canonicalizer::to_vec(&json!({
        "z": 0,
        "a": 1.0,
        "nested": {"y": true, "x": "é"}
    }))
    .expect("test JSON canonicalizes");
    assert_eq!(
        canonical,
        r#"{"a":1,"nested":{"x":"é","y":true},"z":0}"#.as_bytes()
    );

    assert_eq!(
        lowercase_hex(&Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        lowercase_hex(&Sha256::digest(b"{}")),
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );

    for bytes in [[0_u8; 64], [0xff_u8; 64]] {
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(encoded.len(), 86);
        assert!(matches!(
            encoded.as_bytes().last(),
            Some(b'A' | b'Q' | b'g' | b'w')
        ));
        assert!(!encoded.contains(['=', '+', '/', ' ', '\n', '\r', '\t']));
        assert_eq!(URL_SAFE_NO_PAD.decode(&encoded).unwrap(), bytes);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(URL_SAFE_NO_PAD.decode(&encoded).unwrap()),
            encoded
        );
    }

    // A plain serde_json::Value parse retains only one duplicate. The production
    // boundary therefore needs a duplicate-aware seed/visitor before materializing
    // Value and before canonical byte comparison.
    let duplicate: Value = serde_json::from_str(r#"{"a":1,"\u0061":2}"#).unwrap();
    assert_eq!(duplicate.as_object().unwrap().len(), 1);
    assert_eq!(duplicate["a"], 2);
}

fn source_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(name)
}

fn production_source(name: &str) -> Option<String> {
    fs::read_to_string(source_path(name)).ok()
}

fn code_without_line_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn braced_block_after<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing source contract {marker}"));
    let suffix = &source[start..];
    let opening = suffix
        .find('{')
        .unwrap_or_else(|| panic!("{marker} has no body"));
    let mut depth = 0_u32;
    for (offset, character) in suffix[opening..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1).expect("balanced source block");
                if depth == 0 {
                    return &suffix[..opening + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("{marker} body must close")
}

fn assert_block_contains(source: &str, marker: &str, required: &[&str]) {
    let block = braced_block_after(source, marker);
    for token in required {
        assert!(
            block.contains(token),
            "{marker} omits required operation {token}"
        );
    }
}

#[test]
fn production_foundation_implements_the_frozen_cross_contract_oracles() {
    let required = [
        "canonical.rs",
        "crypto.rs",
        "digest.rs",
        "error.rs",
        "validation.rs",
    ];
    let missing = required
        .iter()
        .copied()
        .filter(|name| production_source(name).is_none())
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "T009 RED: T011--T014 must add the common contract foundation; missing {missing:?}"
    );

    let lib = code_without_line_comments(
        &production_source("lib.rs").expect("contract crate root must exist"),
    );
    for module in ["canonical", "crypto", "digest", "error", "validation"] {
        assert!(
            lib.contains(&format!("mod {module};")),
            "T009 RED: lib.rs must wire the real private {module}.rs module"
        );
        assert!(
            !lib.contains(&format!("mod {module} {{")),
            "T009 RED: the empty inline {module} skeleton must be removed"
        );
        assert!(
            !lib.contains(&format!("pub mod {module}")),
            "canonical helpers must remain private"
        );
    }

    let canonical = code_without_line_comments(&production_source("canonical.rs").unwrap());
    assert_block_contains(
        &canonical,
        "fn decode_canonical_value(",
        &[
            "wire.len()",
            "maximum",
            "WireTooLarge",
            "serde_json::from_slice::<UniqueJsonValue>",
            "DuplicateMember",
            "to_jcs_vec(&value)",
            "!= wire",
            "NonCanonicalWire",
        ],
    );
    assert_block_contains(
        &canonical,
        "fn visit_map<",
        &[
            "next_key",
            "names.insert",
            "duplicate JSON member",
            "next_value_seed",
        ],
    );
    assert_block_contains(
        &canonical,
        "fn require_closed_object(",
        &[
            "contains_key",
            "MissingRequiredField",
            "object.len()",
            "UnknownField",
        ],
    );
    assert_block_contains(
        &canonical,
        "fn to_jcs_vec<",
        &["serde_json_canonicalizer::to_vec"],
    );

    let digest = code_without_line_comments(&production_source("digest.rs").unwrap());
    assert_block_contains(
        &digest,
        "impl Sha256Digest",
        &[
            "Sha256::digest",
            "parse_hex",
            "HEX_LEN",
            "is_ascii_digit",
            "b'a'..=b'f'",
        ],
    );

    let crypto = code_without_line_comments(&production_source("crypto.rs").unwrap());
    assert_block_contains(
        &crypto,
        "fn decode_signature(",
        &[
            "encoded.len() != 86",
            "URL_SAFE_NO_PAD",
            ".decode(encoded)",
            ".encode(&decoded) != encoded",
            "InvalidEncoding",
        ],
    );
    assert_block_contains(
        &crypto,
        "fn verify(",
        &[
            "VerifyingKey::from_bytes",
            "verify_strict",
            "SignatureInvalid",
        ],
    );
    assert_block_contains(
        &crypto,
        "fn signature_message(",
        &["domain", "protected", "extend_from_slice"],
    );

    let validation = code_without_line_comments(&production_source("validation.rs").unwrap());
    assert!(validation.contains("9_007_199_254_740_991"));
    assert_block_contains(
        &validation,
        "impl SafeU64",
        &["MAX_SAFE_U64", "InvalidField"],
    );
    assert_block_contains(
        &validation,
        "impl Generation",
        &["SafeU64::new", "!= 0", "InvalidField"],
    );
    assert_block_contains(
        &validation,
        "impl Identifier",
        &[
            "value.is_empty()",
            "value.len() > 128",
            "is_ascii_alphanumeric",
            "InvalidField",
        ],
    );

    let errors = code_without_line_comments(&production_source("error.rs").unwrap());
    for required_token in [
        "DuplicateMember",
        "NonCanonicalWire",
        "WireTooLarge",
        "UnsupportedSchema",
        "UnsupportedDigestAlgorithm",
        "UnsupportedSignatureAlgorithm",
        "WrongKeyPurpose",
        "DigestMismatch",
        "InvalidEncoding",
        "SignatureInvalid",
        "MalformedJson",
        "MissingRequiredField",
        "UnknownField",
    ] {
        assert!(
            [
                canonical.as_str(),
                crypto.as_str(),
                digest.as_str(),
                errors.as_str(),
                validation.as_str(),
            ]
            .iter()
            .any(|source| source.contains(required_token)),
            "T011--T014 production foundation omits {required_token}"
        );
    }

    assert!(
        errors.contains("fn code(&self)") || errors.contains("fn code(self)"),
        "T013 must expose stable payload-free error codes"
    );

    let exports = [
        "ContractError",
        "Generation",
        "Identifier",
        "SafeU64",
        "Sha256Digest",
    ];
    for export in exports {
        assert!(
            lib.contains(export),
            "T014 must expose the reviewed primitive {export}"
        );
    }

    let source_inventory = BTreeMap::from_iter(
        required
            .iter()
            .map(|name| ((*name).to_owned(), source_path(name))),
    );
    assert_eq!(source_inventory.len(), required.len());
}
