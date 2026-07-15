//! Source-level redaction contracts for the portable dispatch boundary.

use std::path::{Path, PathBuf};

#[test]
fn untrusted_request_attempt_and_ready_context_use_opaque_debug() {
    let request = required_source("request.rs", "T015 redacted untrusted request");
    let attempt = required_source("attempt.rs", "T015 redacted attempt identity");
    let authority = required_source("authority.rs", "T015 redacted ready context");

    assert_opaque_debug(&request, "DispatchLookupRequestV1");
    assert_opaque_debug(&attempt, "DispatchAttemptIdV1");
    assert_opaque_debug(&authority, "ReadyDispatchContextV1");
}

#[test]
fn every_closed_outcome_debug_projection_hides_its_payload() {
    let outcome = required_source("outcome.rs", "T015 redacted closed outcomes");

    assert_closed_outcome_debug(
        &outcome,
        "DispatchRequestOutcomeV1",
        &[
            "Dispatched",
            "AlreadyDispatched",
            "Denied",
            "Failed",
            "Ambiguous",
        ],
    );
    assert_closed_outcome_debug(
        &outcome,
        "DispatchDeliveryOutcomeV1",
        &[
            "Consumed",
            "DefinitelyRefused",
            "Pending",
            "Conflict",
            "OutcomeUnknown",
            "ReconciliationRequired",
        ],
    );
    assert_closed_outcome_debug(
        &outcome,
        "DispatchReconciliationOutcomeV1",
        &["ReconciliationRequired", "Failed"],
    );
}

#[test]
fn private_markers_native_paths_and_ad_hoc_logs_never_enter_portable_sources() {
    let production = production_source_tree();

    for forbidden in [
        "/Users/",
        "C:\\\\Users\\\\",
        "BEGIN PRIVATE KEY",
        "PRIVATE KEY-----",
        "password=",
        "credential=",
        "secret=",
        "PathBuf",
        "std::path",
        "std::fs",
        "std::env",
        "std::process",
        "println!",
        "eprintln!",
        "dbg!",
        "trace!",
        "debug!",
        "info!",
        "warn!",
        "error!",
    ] {
        assert!(
            !production.contains(forbidden),
            "T015: portable production source exposes forbidden diagnostic/native surface {forbidden}"
        );
    }
}

fn required_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T015 RED: missing production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    let mut block_depth = 0_u32;
    while cursor < bytes.len() {
        if block_depth > 0 {
            if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                block_depth += 1;
                cursor += 2;
            } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
                block_depth -= 1;
                cursor += 2;
            } else {
                if bytes[cursor] == b'\n' {
                    output.push('\n');
                }
                cursor += 1;
            }
        } else if bytes.get(cursor..cursor + 2) == Some(b"//") {
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
        } else if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            block_depth = 1;
            cursor += 2;
        } else {
            output.push(char::from(bytes[cursor]));
            cursor += 1;
        }
    }
    assert_eq!(block_depth, 0, "portable source comments remain balanced");
    output
}

fn assert_opaque_debug(source: &str, type_name: &str) {
    assert_no_derive_before(source, type_name, "Debug");
    let implementation = braced_block(source, &format!("impl fmt::Debug for {type_name}"));
    let compact = implementation
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let debug_struct_projection = compact.matches("debug_struct(").count() == 1
        && compact.matches(".finish_non_exhaustive()").count() == 1
        && compact.matches(".write_str(").count() == 0;
    let fixed_string_projection = compact.matches(".write_str(\"").count() == 1
        && compact.matches(".write_str(").count() == 1
        && compact.matches("debug_struct(").count() == 0
        && compact.matches(".finish_non_exhaustive()").count() == 0;
    assert!(
        debug_struct_projection || fixed_string_projection,
        "T015 RED: {type_name} Debug must emit one fixed opaque projection"
    );
    assert_eq!(
        identifier_count(implementation, "self"),
        1,
        "T015: {type_name} Debug may reference self only in the receiver"
    );
    for forbidden in [
        ".field(",
        "debug_tuple",
        "debug_map",
        "debug_list",
        "write!",
        "writeln!",
        "write_fmt",
        "format_args!",
        "{:?}",
        "{:#?}",
        "{}",
        "self.",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "T015: {type_name} Debug exposes a payload through {forbidden}"
        );
    }
}

fn assert_closed_outcome_debug(source: &str, type_name: &str, variants: &[&str]) {
    assert_no_derive_before(source, type_name, "Debug");
    let implementation = braced_block(source, &format!("impl fmt::Debug for {type_name}"));
    let compact = implementation
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    for variant in variants {
        assert!(
            implementation.contains(&format!("Self::{variant}(_)"))
                || implementation.contains(&format!("Self::{variant}(..)")),
            "T015 RED: {type_name}::{variant} Debug must match and discard its payload"
        );
    }
    assert_eq!(
        identifier_count(implementation, "self"),
        2,
        "T015: {type_name} Debug may reference self only as receiver and match subject"
    );
    assert_eq!(
        compact.matches(".write_str(\"").count(),
        variants.len(),
        "T015: {type_name} must emit one fixed projection per closed variant"
    );
    assert_eq!(compact.matches(".write_str(").count(), variants.len());
    for forbidden in [
        ".field(",
        "debug_tuple",
        "debug_map",
        "debug_list",
        "write!",
        "writeln!",
        "write_fmt",
        "format_args!",
        "{}",
        "{:?}",
        "{:#?}",
        ".code()",
        "self.",
        "grant_id",
        "operation_id",
        "receipt_id",
        "attempt_id",
        "digest",
        "path",
        "secret",
    ] {
        assert!(
            !implementation.contains(forbidden),
            "T015: {type_name} Debug exposes forbidden payload token {forbidden}"
        );
    }
}

fn assert_no_derive_before(source: &str, type_name: &str, forbidden: &str) {
    let declarations = [
        format!("pub struct {type_name}"),
        format!("pub(crate) struct {type_name}"),
        format!("pub enum {type_name}"),
    ];
    let declaration = declarations
        .iter()
        .filter_map(|candidate| source.find(candidate).map(|position| (position, candidate)))
        .min_by_key(|(position, _)| *position)
        .map(|(_, declaration)| declaration)
        .unwrap_or_else(|| panic!("T015 RED: missing declaration for {type_name}"));
    let before = source
        .split_once(declaration)
        .unwrap_or_else(|| panic!("T015 RED: missing declaration for {type_name}"))
        .0;
    let attributes = attributes_before_declaration(before);
    assert!(
        !(attributes.contains("derive") && attributes.contains(forbidden)),
        "T015: {type_name} derives forbidden payload-revealing {forbidden}"
    );
}

fn attributes_before_declaration(before: &str) -> String {
    let mut collected = Vec::new();
    let mut inside_multiline_attribute = false;
    for line in before.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }
        if inside_multiline_attribute {
            collected.push(trimmed);
            if trimmed.starts_with("#[") {
                inside_multiline_attribute = false;
            }
            continue;
        }
        if trimmed.ends_with(']') {
            collected.push(trimmed);
            inside_multiline_attribute = !trimmed.starts_with("#[");
            continue;
        }
        break;
    }
    collected.reverse();
    collected.join("\n")
}

fn rust_source_tree() -> Vec<(PathBuf, String)> {
    fn visit(directory: &Path, sources: &mut Vec<(PathBuf, String)>) {
        let mut entries = std::fs::read_dir(directory)
            .expect("dispatch source directory is readable")
            .map(|entry| entry.expect("dispatch source entry is readable").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(&path, sources);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let source = std::fs::read_to_string(&path).expect("dispatch Rust source is UTF-8");
                sources.push((path, source));
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    visit(&root, &mut sources);
    sources
}

fn production_source_tree() -> String {
    rust_source_tree()
        .into_iter()
        .map(|(_, source)| {
            source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n")
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

fn identifier_count(source: &str, identifier: &str) -> usize {
    source
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|candidate| *candidate == identifier)
        .count()
}
