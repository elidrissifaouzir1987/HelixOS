//! Public redaction and payload-free error contract for PLAN-006 foundations.

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const GRANT_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/human-request-grant-v1.schema.json"
);
const LEASE_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/task-lease-v1.schema.json"
);
const DECISION_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/approval-decision-v1.schema.json"
);
const CASES: &str =
    include_str!("../../../contracts/fixtures/durable-signed-task-authority-v1/cases.json");
const CHAIN_CASES: &str =
    include_str!("../../../contracts/fixtures/durable-signed-task-authority-v1/chain-cases.json");
const OUTCOMES: &str = include_str!(
    "../../../contracts/fixtures/durable-signed-task-authority-v1/expected-outcomes.json"
);
const PUBLIC_KEYS: &str =
    include_str!("../../../contracts/fixtures/durable-signed-task-authority-v1/public-keys.json");

const PRIVATE_SENTINELS: [&str; 9] = [
    "/Users/private-operator/task-authority.json",
    "C:\\Users\\private-operator\\task-authority.json",
    "raw-message-private-seed",
    "authentication-assertion-private-seed",
    "Bearer task-authority-private-seed",
    "-----BEGIN PRIVATE KEY-----",
    "task-authority-private-identifier-seed",
    "abababababababababababababababababababababababababababababababab",
    "ed25519-provider-private-diagnostic",
];

fn parse_json(text: &str) -> Value {
    serde_json::from_str(text).expect("reviewed PLAN-006 JSON must decode")
}

fn collect_property_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                names.extend(properties.keys().cloned());
            }
            for child in object.values() {
                collect_property_names(child, names);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_property_names(child, names);
            }
        }
        _ => {}
    }
}

#[test]
fn schemas_and_fixture_inventory_expose_no_prohibited_payload_fields() {
    let schemas = [
        parse_json(GRANT_SCHEMA),
        parse_json(LEASE_SCHEMA),
        parse_json(DECISION_SCHEMA),
    ];
    let mut property_names = BTreeSet::new();
    for schema in &schemas {
        collect_property_names(schema, &mut property_names);
    }

    for forbidden in [
        "raw_message",
        "message_text",
        "notification_body",
        "authentication_assertion",
        "bearer_token",
        "cookie",
        "credential",
        "private_key",
        "secret",
        "native_path",
        "provider_error",
        "provider_detail",
        "host_handle",
        "execution_token",
        "replacement_bytes",
    ] {
        assert!(
            !property_names.contains(forbidden),
            "wire schema exposes prohibited payload field {forbidden}"
        );
    }
    assert!(property_names.contains("message_digest"));
    assert!(property_names.contains("authentication_evidence_digest"));

    let reviewed_public_inputs = [
        GRANT_SCHEMA,
        LEASE_SCHEMA,
        DECISION_SCHEMA,
        CASES,
        CHAIN_CASES,
        OUTCOMES,
        PUBLIC_KEYS,
    ]
    .join("\n");
    for sentinel in PRIVATE_SENTINELS {
        assert!(
            !reviewed_public_inputs.contains(sentinel),
            "reviewed public artifact contains private sentinel"
        );
    }
    for forbidden_key in [
        "\"private_key\"",
        "\"secret_key\"",
        "\"signing_key\"",
        "\"seed\"",
        "\"credential\"",
        "\"native_path\"",
        "\"raw_message\"",
        "\"authentication_assertion\"",
        "\"bearer_token\"",
    ] {
        assert!(
            ![CASES, CHAIN_CASES, OUTCOMES, PUBLIC_KEYS]
                .iter()
                .any(|fixture| fixture.contains(forbidden_key)),
            "fixture retained forbidden regeneration or payload field {forbidden_key}"
        );
    }
}

fn source_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name)
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
        .unwrap_or_else(|| panic!("missing source marker {marker}"));
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
            .map(|_| braced_block_after(source, marker))
    })
    .unwrap_or_else(|| {
        panic!("{type_name} needs an explicit bounded redacted {trait_name} implementation")
    })
}

fn identifier_count(source: &str, identifier: &str) -> usize {
    source
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|candidate| *candidate == identifier)
        .count()
}

fn contains_private_sentinel(output: &str) -> bool {
    PRIVATE_SENTINELS
        .iter()
        .any(|sentinel| output.contains(sentinel))
}

#[test]
fn seeded_redaction_oracle_self_test_detects_every_private_payload_class() {
    for sentinel in PRIVATE_SENTINELS {
        let leaked_debug = format!("PublicAuthorityValue {{ private: {sentinel} }}");
        let leaked_error = format!("AUTHORITY_REJECTED: {sentinel}");
        assert!(
            contains_private_sentinel(&leaked_debug),
            "debug oracle missed seeded private payload {sentinel}"
        );
        assert!(
            contains_private_sentinel(&leaked_error),
            "error oracle missed seeded private payload {sentinel}"
        );
    }

    for redacted in [
        "Sha256Digest { .. }",
        "AuthenticTaskLeaseV1 { .. }",
        "INVALID_ENCODING",
        "SIGNATURE_INVALID",
    ] {
        assert!(
            !contains_private_sentinel(redacted),
            "closed redacted output was classified as private"
        );
    }
}

#[test]
fn public_debug_errors_and_exports_are_opaque_and_payload_free() {
    let required = ["crypto.rs", "digest.rs", "error.rs", "validation.rs"];
    let missing = required
        .iter()
        .copied()
        .filter(|name| production_source(name).is_none())
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "T010 RED: T011--T014 must add redacted primitive/error surfaces; missing {missing:?}"
    );

    let lib = code_without_line_comments(
        &production_source("lib.rs").expect("contract crate root must exist"),
    );
    let production = required
        .iter()
        .map(|name| code_without_line_comments(&production_source(name).unwrap()))
        .chain([lib.clone()])
        .collect::<Vec<_>>()
        .join("\n");

    for type_name in [
        "Sha256Digest",
        "Identifier",
        "SignedHumanRequestGrantV1",
        "AuthenticHumanRequestGrantV1",
        "SignedTaskLeaseV1",
        "AuthenticTaskLeaseV1",
        "SignedApprovalDecisionV1",
        "AuthenticApprovalDecisionV1",
    ] {
        let debug = manual_impl_block(&production, "Debug", type_name);
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

    let error_source = code_without_line_comments(&production_source("error.rs").unwrap());
    assert!(error_source.contains("ContractError"));
    let error_enum = braced_block_after(&error_source, "pub enum ContractError");
    for line in error_enum.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "}" {
            continue;
        }
        assert!(
            trimmed.ends_with(','),
            "ContractError variants must be one closed unit variant per line: {trimmed}"
        );
        let variant = trimmed.trim_end_matches(',');
        assert!(
            !variant.is_empty()
                && variant
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_'),
            "ContractError variant carries a private payload or discriminant: {trimmed}"
        );
    }
    assert!(
        error_source.contains("fn code(&self)") || error_source.contains("fn code(self)"),
        "ContractError needs stable closed public codes"
    );
    for forbidden in [
        "#[source]",
        "#[from]",
        "Box<dyn",
        "PathBuf",
        "String",
        "Vec<",
        "source:",
        "message:",
        "details:",
    ] {
        assert!(
            !error_source.contains(forbidden),
            "ContractError retains private payload through {forbidden}"
        );
    }
    let display = manual_impl_block(&error_source, "Display", "ContractError");
    let compact_display = display
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    assert!(
        compact_display.contains(".write_str(self.code())"),
        "ContractError Display must directly emit one closed code"
    );
    assert_eq!(compact_display.matches("self.code()").count(), 1);
    assert_eq!(compact_display.matches(".write_str(").count(), 1);

    for module in ["canonical", "crypto", "digest", "error", "validation"] {
        assert!(
            !lib.contains(&format!("pub mod {module}")),
            "internal helper module {module} became public"
        );
    }
    for forbidden in [
        "PrivateKey",
        "SigningKey",
        "BearerToken",
        "AuthenticationAssertion",
        "NativePath",
        "PathBuf",
        "ProviderError",
        "pub protected",
        "pub signature",
        "pub key_material",
    ] {
        assert!(
            !lib.contains(forbidden),
            "public contract surface exposes forbidden payload {forbidden}"
        );
    }

    assert!(
        !contains_private_sentinel(&production),
        "production public surface contains a seeded private sentinel"
    );
}
