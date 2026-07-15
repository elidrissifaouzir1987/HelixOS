//! Source contracts for the portable dispatch authority boundary.
//!
//! These tests intentionally remain compilable before the production modules exist.
//! During the TDD red phase, a missing module is reported as the precise contract that
//! still has to be implemented instead of turning the entire test binary into a
//! compiler error.

use std::path::{Path, PathBuf};

#[test]
fn ready_dispatch_context_is_private_linear_and_non_wire() {
    let authority = required_source("authority.rs", "T014/T016 private dispatch context");
    let declaration = "pub(crate) struct ReadyDispatchContextV1";

    assert!(
        authority.contains(declaration),
        "T014 RED: authority.rs must declare the coordinator-only {declaration}"
    );
    assert_no_derive_before(&authority, declaration, "Clone");
    assert_no_derive_before(&authority, declaration, "Serialize");
    assert_no_derive_before(&authority, declaration, "Deserialize");

    let structure = braced_block(&authority, declaration);
    assert!(
        structure
            .lines()
            .skip(1)
            .all(|line| !line.trim_start().starts_with("pub ")),
        "T014: ReadyDispatchContextV1 fields must remain crate-private"
    );

    for implementation in inherent_impl_blocks(&authority, "ReadyDispatchContextV1") {
        for constructor in [
            "pub fn new",
            "pub const fn new",
            "pub fn try_new",
            "pub const fn try_new",
            "pub fn from_",
            "pub const fn from_",
        ] {
            assert!(
                !implementation.contains(constructor),
                "T014: ReadyDispatchContextV1 exposes forbidden constructor surface {constructor}"
            );
        }
        assert_no_public_function_returning(implementation, "Self");
    }
    assert_no_public_function_returning(&authority, "ReadyDispatchContextV1");
}

#[test]
fn dispatch_commit_permit_has_no_clone_serde_or_public_constructor_surface() {
    let guard = required_source("guard.rs", "T014/T016 dispatch permit custody");
    let declaration = find_declaration(
        &guard,
        &[
            "pub trait DispatchCommitPermitV1",
            "pub struct DispatchCommitPermitV1",
            "pub(crate) struct DispatchCommitPermitV1",
        ],
        "DispatchCommitPermitV1",
    );
    let permit = braced_block(&guard, declaration);
    if declaration.contains("struct") {
        assert_no_derive_before(&guard, declaration, "Clone");
        assert_no_derive_before(&guard, declaration, "Serialize");
        assert_no_derive_before(&guard, declaration, "Deserialize");
    }
    for forbidden in ["Clone", "Serialize", "Deserialize"] {
        assert!(
            !permit.contains(forbidden),
            "T014: DispatchCommitPermitV1 exposes forbidden surface {forbidden}"
        );
    }

    for implementation in inherent_impl_blocks(&guard, "DispatchCommitPermitV1") {
        for constructor in [
            "pub fn new",
            "pub const fn new",
            "pub fn try_new",
            "pub const fn try_new",
        ] {
            assert!(
                !implementation.contains(constructor),
                "T014: DispatchCommitPermitV1 exposes forbidden public constructor {constructor}"
            );
        }
        assert_no_public_function_returning(implementation, "Self");
    }
    assert_no_public_function_returning(&guard, "DispatchCommitPermitV1");
}

#[test]
fn portable_public_surface_has_no_preparation_marker_or_execution_token_api() {
    let production = production_source_tree();

    for forbidden in [
        "PreparedOperationV1",
        "ExecutionToken",
        "ExecutionPermit",
        "EffectToken",
        "EffectHandoff",
        "HostEffectHandle",
        "execution_token",
        "effect_token",
        "into_execution",
        "execute_host",
        "perform_effect",
    ] {
        assert!(
            !production.contains(forbidden),
            "T014: portable dispatch production source exposes forbidden authority token {forbidden}"
        );
    }
}

fn required_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T014 RED: missing production module {} required for {contract}: {error}",
            path.display()
        )
    })
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
        .map(|(_, source)| production_lines(&source))
        .collect::<Vec<_>>()
        .join("\n")
}

fn production_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn braced_block<'a>(source: &'a str, anchor: &str) -> &'a str {
    let start = source
        .find(anchor)
        .unwrap_or_else(|| panic!("T014 RED: missing required source contract {anchor}"));
    let relative_open = source[start..]
        .find('{')
        .unwrap_or_else(|| panic!("T014: contract {anchor} has no body"));
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
    panic!("T014: contract {anchor} has an unterminated body");
}

fn assert_no_derive_before(source: &str, declaration: &str, forbidden: &str) {
    let before = source
        .split_once(declaration)
        .unwrap_or_else(|| panic!("T014 RED: missing declaration {declaration}"))
        .0;
    let attributes = attributes_before_declaration(before);
    assert!(
        !(attributes.contains("derive") && attributes.contains(forbidden)),
        "T014: {declaration} derives forbidden trait {forbidden}"
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

fn inherent_impl_blocks<'a>(source: &'a str, type_name: &str) -> Vec<&'a str> {
    let mut blocks = Vec::new();
    let mut offset = 0;
    while let Some(relative_start) = source[offset..].find("impl") {
        let start = offset + relative_start;
        let next = source[start + "impl".len()..].chars().next();
        let boundary_before = start == 0
            || source[..start]
                .chars()
                .next_back()
                .is_some_and(|character| !character.is_ascii_alphanumeric() && character != '_');
        let boundary_after =
            next.is_some_and(|character| character.is_whitespace() || character == '<');
        if !boundary_before || !boundary_after {
            offset = start + "impl".len();
            continue;
        }

        let Some(relative_open) = source[start..].find('{') else {
            break;
        };
        let open = start + relative_open;
        let header = &source[start..open];
        if header.contains(type_name) && !header.contains(" for ") {
            blocks.push(braced_block_at(source, start, type_name));
        }
        offset = open + 1;
    }
    blocks
}

fn assert_no_public_function_returning(source: &str, type_name: &str) {
    let normalized = production_lines(source)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for marker in [
        "pub fn ",
        "pub const fn ",
        "pub async fn ",
        "pub unsafe fn ",
        "pub const unsafe fn ",
    ] {
        let mut offset = 0;
        while let Some(relative_start) = normalized[offset..].find(marker) {
            let start = offset + relative_start;
            let remainder = &normalized[start..];
            let end = remainder.find(['{', ';']).unwrap_or(remainder.len());
            let signature = &remainder[..end];
            if let Some((_, return_type)) = signature.split_once("->") {
                assert!(
                    !returns_owned_type(return_type, type_name),
                    "T014: public function returns caller-constructible {type_name}: {signature}"
                );
            }
            offset = start + marker.len();
        }
    }
}

fn returns_owned_type(return_type: &str, type_name: &str) -> bool {
    let compact = return_type
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let mut offset = 0;
    while let Some(relative) = compact[offset..].find(type_name) {
        let position = offset + relative;
        let prefix = &compact[..position];
        let boundary = prefix
            .rfind(['<', '(', ',', '='])
            .map_or(0, |index| index + 1);
        let borrowed = prefix[boundary..].contains('&');
        if !borrowed {
            return true;
        }
        offset = position + type_name.len();
    }
    false
}

fn braced_block_at<'a>(source: &'a str, start: usize, contract: &str) -> &'a str {
    let relative_open = source[start..]
        .find('{')
        .unwrap_or_else(|| panic!("T014: contract {contract} has no body"));
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
    panic!("T014: contract {contract} has an unterminated body");
}

fn find_declaration<'a>(source: &str, candidates: &'a [&'a str], contract: &str) -> &'a str {
    candidates
        .iter()
        .copied()
        .find(|candidate| source.contains(candidate))
        .unwrap_or_else(|| panic!("T014 RED: missing required source declaration {contract}"))
}
