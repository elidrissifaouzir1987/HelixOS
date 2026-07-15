//! Closed source contracts for portable dispatch outcomes and reason codes.

use std::collections::BTreeSet;
use std::path::Path;

const REQUEST_VARIANTS: [&str; 5] = [
    "Dispatched",
    "AlreadyDispatched",
    "Denied",
    "Failed",
    "Ambiguous",
];
const DELIVERY_VARIANTS: [&str; 6] = [
    "Consumed",
    "DefinitelyRefused",
    "Pending",
    "Conflict",
    "OutcomeUnknown",
    "ReconciliationRequired",
];
const RECONCILIATION_VARIANTS: [&str; 2] = ["ReconciliationRequired", "Failed"];

#[test]
fn outcome_contract_has_one_explicit_supported_version() {
    let outcome = required_outcome_source();

    let version_constants = outcome
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("pub const ")
                && line.contains("OUTCOME")
                && line.contains("VERSION_V1: u16 = 1;")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        version_constants.len(),
        1,
        "T015 RED: outcome.rs must expose one exact public u16 v1 outcome contract version"
    );
    for forbidden in [
        "VERSION_V0",
        "VERSION_V2",
        "CurrentVersion",
        "LatestVersion",
    ] {
        assert!(
            !outcome.contains(forbidden),
            "T015: unsupported version alias is forbidden in the v1 outcome contract: {forbidden}"
        );
    }
}

#[test]
fn request_and_delivery_vocabularies_are_exact_and_reconciliation_is_closed() {
    let outcome = required_outcome_source();

    assert_exact_variants(&outcome, "DispatchRequestOutcomeV1", &REQUEST_VARIANTS);
    assert_exact_variants(&outcome, "DispatchDeliveryOutcomeV1", &DELIVERY_VARIANTS);
    assert_exact_variants(
        &outcome,
        "DispatchReconciliationOutcomeV1",
        &RECONCILIATION_VARIANTS,
    );

    for forbidden in ["Other(", "Custom(", "String)", "&'static str)"] {
        assert!(
            !outcome.contains(forbidden),
            "T015: open-ended outcome vocabulary is forbidden: {forbidden}"
        );
    }
}

#[test]
fn every_negative_outcome_uses_a_versioned_payload_free_reason_enum() {
    let outcome = required_outcome_source();
    let mut reason_types = BTreeSet::new();

    for (outcome_type, variants) in [
        (
            "DispatchRequestOutcomeV1",
            &["Denied", "Failed", "Ambiguous"][..],
        ),
        (
            "DispatchDeliveryOutcomeV1",
            &["Conflict", "OutcomeUnknown", "ReconciliationRequired"][..],
        ),
        (
            "DispatchReconciliationOutcomeV1",
            &["ReconciliationRequired", "Failed"][..],
        ),
    ] {
        let body = enum_body(&outcome, outcome_type);
        for variant in variants {
            let payload = tuple_payload(body, variant);
            assert!(
                is_local_versioned_type(payload),
                "T015: {outcome_type}::{variant} must carry one local versioned bounded payload, got {payload}"
            );
            reason_types.insert(reason_type_for_payload(&outcome, payload));
        }
    }

    assert!(
        !reason_types.is_empty(),
        "T015 RED: negative outcome payloads must bind closed typed reason-code enums"
    );
    for reason_type in reason_types {
        assert_payload_free_reason_enum(&outcome, &reason_type);
    }
}

#[test]
fn closed_reason_codes_are_static_uppercase_ascii() {
    let outcome = required_outcome_source();

    let codes = outcome
        .lines()
        .filter_map(|line| line.split_once("=> \"").map(|(_, suffix)| suffix))
        .filter_map(|suffix| suffix.split_once('"').map(|(code, _)| code))
        .filter(|code| {
            code.contains('_')
                && code
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_uppercase())
        })
        .collect::<Vec<_>>();
    assert!(
        !codes.is_empty(),
        "T015 RED: reason enums must map their variants to closed public codes"
    );
    for code in codes {
        assert!(
            !code.is_empty()
                && code.is_ascii()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
            "T015: reason code is not closed uppercase ASCII: {code}"
        );
    }
}

fn required_outcome_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("outcome.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T015 RED: missing production module {} required for closed dispatch outcomes: {error}",
            path.display()
        )
    })
}

fn assert_exact_variants(source: &str, enum_name: &str, expected: &[&str]) {
    let actual = enum_variant_names(enum_body(source, enum_name));
    let actual_set = actual.iter().cloned().collect::<BTreeSet<_>>();
    let expected_set = expected
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual.len(),
        expected.len(),
        "T015: {enum_name} has an unexpected number of variants: {actual:?}"
    );
    assert_eq!(
        actual_set, expected_set,
        "T015: {enum_name} must preserve the reviewed closed vocabulary"
    );
}

fn enum_body<'a>(source: &'a str, enum_name: &str) -> &'a str {
    let anchor = format!("pub enum {enum_name}");
    let block = braced_block(source, &anchor);
    let open = block.find('{').expect("enum block has an opening brace");
    &block[open + 1..block.len() - 1]
}

fn enum_variant_names(body: &str) -> Vec<String> {
    split_top_level(body)
        .into_iter()
        .filter_map(|item| {
            let declaration = item
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with('#')
                })
                .collect::<Vec<_>>()
                .join(" ");
            let name = declaration
                .trim()
                .split(|character: char| {
                    character.is_whitespace()
                        || character == '('
                        || character == '{'
                        || character == '='
                })
                .next()
                .unwrap_or("");
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

fn tuple_payload<'a>(body: &'a str, variant: &str) -> &'a str {
    let item = split_top_level(body)
        .into_iter()
        .find(|item| {
            let trimmed = item.trim_start();
            trimmed.starts_with(variant)
                && trimmed
                    .as_bytes()
                    .get(variant.len())
                    .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'(')
        })
        .unwrap_or_else(|| panic!("T015: missing closed variant {variant}"));
    let open = item
        .find('(')
        .unwrap_or_else(|| panic!("T015: {variant} must carry a typed reason"));
    let close = item
        .rfind(')')
        .unwrap_or_else(|| panic!("T015: {variant} has an unterminated typed reason"));
    let payload = item[open + 1..close].trim();
    assert!(
        !payload.contains(','),
        "T015: {variant} reason must be one payload-free typed value"
    );
    payload
}

fn is_local_versioned_type(payload: &str) -> bool {
    payload.ends_with("V1")
        && payload
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn reason_type_for_payload(source: &str, payload_type: &str) -> String {
    if source.contains(&format!("pub enum {payload_type} {{"))
        || source.contains(&format!("pub enum {payload_type},"))
    {
        return payload_type.to_owned();
    }

    let declaration = [
        format!("pub struct {payload_type}"),
        format!("pub(crate) struct {payload_type}"),
        format!("struct {payload_type}"),
    ]
    .into_iter()
    .find(|candidate| source.contains(candidate))
    .unwrap_or_else(|| {
        panic!(
            "T015 RED: negative payload {payload_type} must be a reason enum or a bounded custody struct containing one"
        )
    });
    let structure = braced_block(source, &declaration);
    let reason_type = structure
        .lines()
        .filter_map(|line| line.trim().trim_end_matches(',').split_once(':'))
        .find_map(|(field, field_type)| {
            let field = field.trim();
            let field = field
                .strip_prefix("pub(crate) ")
                .or_else(|| field.strip_prefix("pub(super) "))
                .or_else(|| field.strip_prefix("pub "))
                .unwrap_or(field)
                .trim();
            (field == "reason" || field.ends_with("_reason") || field.ends_with("_reason_code"))
                .then(|| field_type.trim())
        })
        .unwrap_or_else(|| {
            panic!("T015: negative payload {payload_type} must contain one typed reason field")
        });
    assert!(
        is_local_versioned_type(reason_type),
        "T015: {payload_type} reason field must use one local versioned type, got {reason_type}"
    );
    reason_type.to_owned()
}

fn assert_payload_free_reason_enum(source: &str, reason_type: &str) {
    let direct_anchor = format!("pub enum {reason_type}");
    assert!(
        source.contains(&direct_anchor),
        "T015 RED: missing public closed reason enum {reason_type}"
    );

    if source.contains(&format!("pub enum {reason_type} {{")) {
        let body = enum_body(source, reason_type);
        for item in split_top_level(body) {
            let declaration = item
                .lines()
                .filter(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with('#')
                })
                .collect::<Vec<_>>()
                .join(" ");
            let declaration = declaration.trim();
            if declaration.is_empty() || declaration.starts_with("//") {
                continue;
            }
            assert!(
                !declaration.contains('(')
                    && !declaration.contains('{')
                    && !declaration.contains('='),
                "T015: reason enum {reason_type} must be payload-free: {declaration}"
            );
        }
    } else {
        assert!(
            source.contains(&format!("pub enum {reason_type},")),
            "T015: macro-defined reason enum {reason_type} must use the reviewed closed-code form"
        );
    }
}

fn split_top_level(body: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut paren_depth = 0_u32;
    let mut brace_depth = 0_u32;
    let mut bracket_depth = 0_u32;
    let mut angle_depth = 0_u32;
    for (index, character) in body.char_indices() {
        match character {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            ',' if paren_depth == 0
                && brace_depth == 0
                && bracket_depth == 0
                && angle_depth == 0 =>
            {
                items.push(&body[start..index]);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if !body[start..].trim().is_empty() {
        items.push(&body[start..]);
    }
    items
}

fn braced_block<'a>(source: &'a str, anchor: &str) -> &'a str {
    let start = source
        .find(anchor)
        .unwrap_or_else(|| panic!("T015 RED: missing required source contract {anchor}"));
    let relative_open = source[start..]
        .find('{')
        .unwrap_or_else(|| panic!("T015: contract {anchor} has no body"));
    let open = start + relative_open;
    let mut depth = 0_u32;
    for (relative, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1).expect("balanced Rust source braces");
                if depth == 0 {
                    return &source[start..open + relative + character.len_utf8()];
                }
            }
            _ => {}
        }
    }
    panic!("T015: contract {anchor} has an unterminated body");
}
