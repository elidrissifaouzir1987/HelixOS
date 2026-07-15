//! Redaction and public-surface contract for signed dispatch values and failures.

use helix_dispatch_contracts::{
    ContractError, Generation, GrantVerificationKeyV1, Identifier, ReceiptVerificationKeyV1,
    ResourceRefV1, SafeU64, Sha256Digest,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const GRANT_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/execution-grant-v1.schema.json");
const RECEIPT_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/execution-receipt-v1.schema.json");
const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const OUTCOMES: &str =
    include_str!("../../../contracts/fixtures/durable-dispatch-v1/expected-outcomes.json");

const PRIVATE_SENTINELS: [&str; 8] = [
    "/Users/private-operator/secret-dispatch.json",
    "C:\\Users\\private-operator\\secret-dispatch.json",
    "dispatch-private-key-seed",
    "credential-private-seed",
    "replacement-content-private-seed",
    "raw-provider-diagnostic-private-seed",
    "execution-token-private-seed",
    "-----BEGIN PRIVATE KEY-----",
];

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("reviewed PLAN-005 JSON must decode")
}

fn protected_field_names(schema: &Value, definition: &str) -> BTreeSet<String> {
    schema["$defs"][definition]["properties"]
        .as_object()
        .expect("protected schema properties must be an object")
        .keys()
        .cloned()
        .collect()
}

fn assert_bounded_public_text(text: &str) {
    assert!(
        text.is_ascii(),
        "public diagnostic vocabulary must be ASCII"
    );
    assert!(
        text.len() <= 96,
        "public diagnostic vocabulary must stay bounded"
    );
    for sentinel in PRIVATE_SENTINELS {
        assert!(
            !text.contains(sentinel),
            "public diagnostic leaked a private sentinel"
        );
    }
}

#[test]
fn wire_schemas_expose_no_secret_path_content_or_execution_token_field() {
    let grant = json(GRANT_SCHEMA);
    let receipt = json(RECEIPT_SCHEMA);
    let fields = protected_field_names(&grant, "protectedGrant")
        .into_iter()
        .chain(protected_field_names(&receipt, "protectedReceipt"))
        .collect::<BTreeSet<_>>();

    for forbidden in [
        "argument",
        "arguments",
        "credential",
        "effect_handle",
        "execution_token",
        "native_path",
        "private_key",
        "raw_content",
        "replacement_bytes",
        "secret",
    ] {
        assert!(
            !fields.contains(forbidden),
            "wire schema exposed forbidden private field {forbidden}"
        );
    }

    // The portable target reference and trace correlation are sovereign wire data,
    // but neither allows native paths, free-form content, or unbounded diagnostics.
    assert!(fields.contains("target"));
    assert!(fields.contains("trace_id"));
    assert_eq!(
        grant["$defs"]["resourceRef"]["properties"]["components"]["maxItems"],
        128
    );
    assert_eq!(receipt["$defs"]["identifier"]["maxLength"], 128);
}

#[test]
fn frozen_fixture_carries_public_keys_only_and_no_private_regeneration_material() {
    let corpus = json(CASES);
    let rendered = serde_json_canonicalizer::to_string(&corpus).unwrap();
    for sentinel in PRIVATE_SENTINELS {
        assert!(!rendered.contains(sentinel));
    }
    for forbidden_key in [
        "private_key",
        "private_key_base64url",
        "secret_key",
        "signing_key",
        "seed",
        "credential",
        "native_path",
        "replacement_bytes",
        "execution_token",
    ] {
        assert!(
            !rendered.contains(&format!("\"{forbidden_key}\"")),
            "fixture retained forbidden regeneration material {forbidden_key}"
        );
    }

    let keys = corpus["verification_keys"].as_object().unwrap();
    assert_eq!(keys.len(), 2);
    for key in keys.values() {
        assert_eq!(key["algorithm"], "ed25519");
        assert!(key.get("public_key_base64url").is_some());
        assert_eq!(key.as_object().unwrap().len(), 4);
    }
}

#[test]
fn expected_public_outcome_vocabulary_is_closed_bounded_and_payload_free() {
    let outcomes = json(OUTCOMES);
    let allowed_results = BTreeSet::from(["ACCEPT_GRANT", "ACCEPT_RECEIPT", "DENY"]);
    let allowed_authority = BTreeSet::from([
        "CONSUMED_EVIDENCE",
        "DEFINITE_REFUSAL_EVIDENCE",
        "GRANT_ONLY",
        "NONE",
    ]);
    assert_eq!(
        outcomes["result_vocabulary"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        allowed_results
    );
    assert_eq!(
        outcomes["authority_vocabulary"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        allowed_authority
    );

    for outcome in outcomes["outcomes"].as_array().unwrap() {
        for member in ["result", "stage", "reason", "authority"] {
            assert_bounded_public_text(outcome[member].as_str().unwrap());
        }
        assert_eq!(outcome.as_object().unwrap().len(), 5);
    }
}

fn production_source(name: &str) -> Option<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(name);
    fs::read_to_string(path).ok()
}

fn code_without_line_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn manual_impl_block<'a>(source: &'a str, trait_name: &str, type_name: &str) -> &'a str {
    [
        format!("impl {trait_name} for {type_name}"),
        format!("impl fmt::{trait_name} for {type_name}"),
        format!("impl std::fmt::{trait_name} for {type_name}"),
    ]
    .iter()
    .find_map(|marker| {
        source
            .find(marker)
            .map(|start| braced_block(&source[start..]))
    })
    .unwrap_or_else(|| {
        panic!("{type_name} needs an explicit bounded redacted {trait_name} implementation")
    })
}

fn public_declarations(source: &str) -> String {
    let mut declarations = Vec::new();
    let mut current = String::new();
    let mut public_use = false;

    for line in code_without_line_comments(source).lines() {
        let trimmed = line.trim_start();
        if current.is_empty() {
            if !trimmed.starts_with("pub ") {
                continue;
            }
            public_use = trimmed.starts_with("pub use ");
        }
        current.push_str(trimmed);
        current.push('\n');
        let finished = if public_use {
            trimmed.contains(';')
        } else {
            trimmed.contains(';') || trimmed.contains('{')
        };
        if finished {
            declarations.push(std::mem::take(&mut current));
            public_use = false;
        }
    }
    if !current.is_empty() {
        declarations.push(current);
    }
    declarations.join("\n")
}

fn braced_block(source: &str) -> &str {
    let opening = source
        .find('{')
        .expect("manual implementation must have a body");
    let mut depth = 0_u32;
    for (offset, character) in source[opening..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1).expect("balanced implementation body");
                if depth == 0 {
                    return &source[..opening + offset + character.len_utf8()];
                }
            }
            _ => {}
        }
    }
    panic!("manual implementation body must close")
}

fn identifier_count(source: &str, identifier: &str) -> usize {
    source
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|candidate| *candidate == identifier)
        .count()
}

#[test]
fn production_debug_errors_and_public_exports_are_redacted_and_path_free() {
    let required_modules = ["error.rs", "grant.rs", "receipt.rs"];
    let missing: Vec<_> = required_modules
        .iter()
        .copied()
        .filter(|name| production_source(name).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "T009 RED: T010--T013 must add redacted contract/error surfaces; missing {missing:?}"
    );

    let error_source = code_without_line_comments(&production_source("error.rs").unwrap());
    let grant_source = code_without_line_comments(&production_source("grant.rs").unwrap());
    let receipt_source = code_without_line_comments(&production_source("receipt.rs").unwrap());
    let lib_source = code_without_line_comments(&production_source("lib.rs").unwrap());
    let value_sources = format!("{grant_source}\n{receipt_source}");

    // T010--T013 must add seeded runtime formatting checks once these values have
    // reviewed constructors. This source contract prevents a field-bearing formatter
    // from being accepted as an interim redacted projection.
    for type_name in [
        "ExecutionGrantProtectedV1",
        "ExecutionGrantInputV1",
        "SignedExecutionGrantV1",
        "AuthenticExecutionGrantV1",
        "ExecutionGrantClaimsV1",
        "RetainedExecutionGrantEvidenceV1",
        "RetainedExecutionGrantClaimsV1",
        "ExecutionReceiptProtectedV1",
        "ExecutionReceiptInputV1",
        "SignedExecutionReceiptV1",
        "AuthenticExecutionReceiptV1",
        "ExecutionReceiptClaimsV1",
    ] {
        let debug = manual_impl_block(&value_sources, "Debug", type_name);
        assert!(debug.contains(&format!("debug_struct(\"{type_name}\")")));
        assert!(debug.contains(".finish_non_exhaustive()"));
        assert_eq!(debug.matches("debug_struct(").count(), 1);
        assert_eq!(debug.matches(".finish_non_exhaustive()").count(), 1);
        assert_eq!(
            identifier_count(debug, "self"),
            1,
            "{type_name} Debug may reference self only in the receiver"
        );
        for forbidden in [
            ".field(",
            "debug_tuple",
            "debug_map",
            "debug_list",
            "write!",
            "writeln!",
            ".write_str(",
            ".write_fmt(",
            "format_args!",
            "{:?}",
            "{:#?}",
        ] {
            assert!(
                !debug.contains(forbidden),
                "{type_name} Debug exposes payload access through {forbidden}"
            );
        }
    }

    assert!(error_source.contains("ContractError"));
    assert!(
        error_source.contains("fn code(&self)") || error_source.contains("fn code(self)"),
        "contract failures need stable closed public codes"
    );
    assert!(
        error_source.contains("impl std::error::Error")
            || error_source.contains("impl Error")
            || error_source.contains("derive(Debug, Error)"),
        "ContractError must implement std::error::Error without wrapping private sources"
    );
    for forbidden in ["#[source]", "#[from]", "Box<dyn", "PathBuf"] {
        assert!(
            !error_source.contains(forbidden),
            "ContractError must not retain private source payloads: {forbidden}"
        );
    }

    let display = manual_impl_block(&error_source, "Display", "ContractError");
    let compact_display = display
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    assert!(
        compact_display.contains(".write_str(self.code())"),
        "ContractError Display must be one direct write of its closed code"
    );
    assert_eq!(compact_display.matches("self.code()").count(), 1);
    assert_eq!(compact_display.matches(".write_str(").count(), 1);
    assert_eq!(
        identifier_count(display, "self"),
        2,
        "ContractError Display may reference self only as receiver and self.code()"
    );
    let display_without_code = compact_display.replace("self.code()", "");
    for forbidden in [
        "self.",
        "source",
        "{:?}",
        "{:#?}",
        ".field(",
        "matchself",
        "iflet",
        "let",
        "write!",
        "writeln!",
        "write_fmt",
        "format_args!",
    ] {
        assert!(
            !display_without_code.contains(forbidden),
            "ContractError Display exposes private payload through {forbidden}"
        );
    }

    let public_surface = public_declarations(&lib_source);
    for forbidden in [
        "ExecutionToken",
        "EffectHandle",
        "PrivateKey",
        "SigningKey",
        "PathBuf",
        "std::path",
        "pub mod canonical",
        "pub mod crypto",
        "pub mod digest",
        "pub mod error",
        "pub mod grant",
        "pub mod receipt",
        "pub mod validation",
    ] {
        assert!(
            !public_surface.contains(forbidden),
            "public contract surface exposed forbidden authority/private type {forbidden}"
        );
    }
}

#[test]
fn runtime_public_values_and_closed_errors_never_format_private_payloads() {
    let identifier = Identifier::new("dispatch-private-key-seed").unwrap();
    let target = ResourceRefV1::try_new(
        "workspace",
        vec!["replacement-content-private-seed".to_owned()],
    )
    .unwrap();
    let digest = Sha256Digest::from_bytes([0x5a; 32]);
    let values = [
        format!("{identifier:?}"),
        format!("{target:?}"),
        format!("{digest:?}"),
        format!("{:?}", SafeU64::new(9_007_199_254_740_991).unwrap()),
        format!("{:?}", Generation::new(1).unwrap()),
        format!("{:?}", GrantVerificationKeyV1::current([0x41; 32])),
        format!("{:?}", ReceiptVerificationKeyV1::historical([0x42; 32])),
    ];
    for formatted in values {
        assert_bounded_public_text(&formatted);
        assert!(!formatted.contains("5a5a5a5a"));
        assert!(!formatted.contains("41414141"));
        assert!(!formatted.contains("42424242"));
    }

    let errors = [
        ContractError::AdapterRootBindingMismatch,
        ContractError::CanonicalizationFailed,
        ContractError::DestinationBindingMismatch,
        ContractError::DigestMismatch,
        ContractError::DuplicateMember,
        ContractError::GrantBindingMismatch,
        ContractError::GrantLifetimeExceeded,
        ContractError::HistoricalKeyNotAuthority,
        ContractError::InvalidDecisionShape,
        ContractError::InvalidEncoding,
        ContractError::InvalidField,
        ContractError::InvalidPublicKey,
        ContractError::MalformedJson,
        ContractError::MissingOuterField,
        ContractError::MissingRequiredField,
        ContractError::NonCanonicalWire,
        ContractError::OperationBindingMismatch,
        ContractError::PreReceivedCodeNotReceipt,
        ContractError::SignatureInvalid,
        ContractError::SigningFailed,
        ContractError::SupervisorEpochBindingMismatch,
        ContractError::UnknownDecision,
        ContractError::UnknownField,
        ContractError::UnknownKey,
        ContractError::UnsupportedDigestAlgorithm,
        ContractError::UnsupportedProtocol,
        ContractError::UnsupportedSchema,
        ContractError::UnsupportedSignatureAlgorithm,
        ContractError::WireTooLarge,
        ContractError::WrongKeyPurpose,
    ];
    for error in errors {
        assert_eq!(error.to_string(), error.code());
        assert_bounded_public_text(error.code());
        assert_bounded_public_text(&format!("{error:?}"));
    }
}
