//! Closed dependency, source and marker boundaries for PLAN-006 wire contracts.
//!
//! Missing implementation files are loaded at runtime so the T010 RED phase remains a
//! precise test failure instead of an integration-test compiler failure.

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST: &str = include_str!("../Cargo.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const LEASE_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/task-lease-v1.schema.json"
);

fn section_keys<'manifest>(manifest: &'manifest str, section: &str) -> BTreeSet<&'manifest str> {
    let header = format!("[{section}]");
    manifest
        .split_once(&header)
        .unwrap_or_else(|| panic!("missing [{section}] section"))
        .1
        .lines()
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty() && !name.starts_with('#'))
        .collect()
}

fn all_dependency_names(manifest: &str) -> BTreeSet<&str> {
    let mut in_dependency_section = false;
    let mut names = BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependency_section = line == "[dependencies]"
                || line == "[dev-dependencies]"
                || line == "[build-dependencies]"
                || line.ends_with(".dependencies]")
                || line.ends_with(".dev-dependencies]")
                || line.ends_with(".build-dependencies]");
            continue;
        }
        if in_dependency_section {
            if let Some((name, _)) = line.split_once('=') {
                let name = name.trim();
                if !name.is_empty() && !name.starts_with('#') {
                    names.insert(name);
                }
            }
        }
    }
    names
}

fn kernel_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("contract crate is directly below the kernel workspace")
        .to_owned()
}

#[test]
fn dependency_boundary_is_exact_pinned_and_prior_plan_free() {
    assert_eq!(
        section_keys(MANIFEST, "dependencies"),
        BTreeSet::from([
            "base64",
            "ed25519-dalek",
            "serde",
            "serde_json",
            "serde_json_canonicalizer",
            "sha2",
            "unicode-normalization",
        ])
    );
    assert_eq!(
        section_keys(MANIFEST, "dev-dependencies"),
        BTreeSet::from(["proptest"])
    );
    assert_eq!(
        section_keys(MANIFEST, "features"),
        BTreeSet::from(["default"])
    );

    for exact in [
        "base64 = { version = \"=0.22.1\", default-features = false, features = [\"std\"] }",
        "ed25519-dalek = { version = \"=2.2.0\", default-features = false, features = [\"std\"] }",
        "serde = { version = \"=1.0.228\", default-features = false, features = [\"derive\", \"std\"] }",
        "serde_json = { version = \"=1.0.150\", default-features = false, features = [\"std\"] }",
        "serde_json_canonicalizer = \"=0.3.2\"",
        "sha2 = { version = \"=0.10.9\", default-features = false }",
        "unicode-normalization = \"=0.1.25\"",
        "proptest = \"=1.11.0\"",
        "default = []",
    ] {
        assert!(
            MANIFEST.contains(exact),
            "missing exact portable dependency boundary: {exact}"
        );
    }

    for forbidden in [
        "helix-contracts",
        "helix-plan-eligibility",
        "helix-replay-sqlite",
        "helix-plan-preparation",
        "helix-coordinator-sqlite",
        "helix-dispatch-contracts",
        "helix-plan-dispatch",
        "helix-dispatch-inbox-sqlite",
        "helixos-kernel",
        "helixos-mcp-shim",
        "helixos-provision",
        "rusqlite",
        "getrandom",
        "tokio",
        "async-std",
        "reqwest",
        "hyper",
        "tonic",
        "sqlx",
        "uuid",
        "[target.",
        "[build-dependencies]",
    ] {
        assert!(
            !MANIFEST.contains(forbidden),
            "contract crate acquired forbidden dependency or section {forbidden}"
        );
    }

    let mut consumers = Vec::new();
    for entry in fs::read_dir(kernel_root()).expect("kernel workspace is readable") {
        let entry = entry.expect("workspace entry is readable");
        if !entry.file_type().expect("entry type is readable").is_dir()
            || entry.path() == Path::new(env!("CARGO_MANIFEST_DIR"))
        {
            continue;
        }
        let manifest_path = entry.path().join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest = fs::read_to_string(manifest_path).expect("package manifest is UTF-8");
        if all_dependency_names(&manifest).contains("helix-task-authority-contracts") {
            consumers.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    consumers.sort();
    assert_eq!(
        consumers,
        [
            "helix-task-authority",
            "helix-task-authority-projections",
            "helix-task-authority-sqlite",
        ],
        "only the three reviewed PLAN-006 downstream crates may consume the contract leaf"
    );
}

#[test]
fn resource_schema_uses_only_opaque_os_neutral_components() {
    let schema: Value = serde_json::from_str(LEASE_SCHEMA).unwrap();
    let definitions = &schema["$defs"];
    assert_eq!(
        definitions["rootIdentifier"]["pattern"],
        "^[a-z0-9][a-z0-9._-]{0,63}$"
    );
    assert_eq!(
        definitions["resourceRoot"]["properties"]["components"]["maxItems"],
        128
    );
    assert_eq!(definitions["resourceComponent"]["maxLength"], 255);
    let component_pattern = definitions["resourceComponent"]["pattern"]
        .as_str()
        .expect("component pattern");
    for denied in ["/", "\\\\", ":", "\\u0000", "\\u001F", "\\u007F"] {
        assert!(
            component_pattern.contains(denied),
            "component pattern must deny {denied}"
        );
    }
    let rendered = serde_json_canonicalizer::to_string(&schema).unwrap();
    for forbidden in [
        "\"native_path\"",
        "\"path_buf\"",
        "\"file_handle\"",
        "\"socket\"",
        "\"platform\"",
        "\"floating_point\"",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "wire schema exposed native primitive {forbidden}"
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

#[test]
fn foundation_sources_are_private_complete_and_os_neutral() {
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
        "T010 RED: T011--T014 must add the portable contract foundation; missing {missing:?}"
    );

    let lib = code_without_line_comments(LIB_SOURCE);
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    for module in ["canonical", "crypto", "digest", "error", "validation"] {
        assert!(lib.contains(&format!("mod {module};")));
        assert!(!lib.contains(&format!("mod {module} {{")));
        assert!(!lib.contains(&format!("pub mod {module}")));
    }

    let production = required
        .iter()
        .map(|name| code_without_line_comments(&production_source(name).unwrap()))
        .chain([lib])
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "PathBuf",
        "OsStr",
        "OsString",
        "std::net",
        "std::os",
        "std::process",
        "std::env",
        "std::time",
        "SystemTime",
        "Instant",
        "target_os",
        "target_arch",
        "target_family",
        "cfg(windows)",
        "cfg(unix)",
        "RawFd",
        "OwnedFd",
        "RawHandle",
        "OwnedHandle",
        "RawSocket",
        "OwnedSocket",
        "TcpStream",
        "UdpSocket",
        "UnixStream",
        "rusqlite",
        "sqlite3",
        "tokio",
        "async fn",
        "reqwest",
        "hyper",
        "tonic",
        "f32",
        "f64",
        "println!",
        "eprintln!",
        "dbg!",
        "tracing::",
        "log::",
        "unsafe {",
        "unsafe fn",
    ] {
        assert!(
            !production.contains(forbidden),
            "portable production source contains forbidden primitive {forbidden}"
        );
    }
}

fn declaration_prefix<'a>(source: &'a str, declaration: &str) -> &'a str {
    source
        .split_once(declaration)
        .unwrap_or_else(|| panic!("T010 RED: missing authority marker {declaration}"))
        .0
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

fn braced_block<'a>(source: &'a str, declaration: &str) -> &'a str {
    let start = source
        .find(declaration)
        .unwrap_or_else(|| panic!("missing declaration {declaration}"));
    let suffix = &source[start..];
    let opening = suffix
        .find('{')
        .unwrap_or_else(|| panic!("{declaration} has no body"));
    let mut depth = 0_u32;
    for (offset, character) in suffix[opening..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1).expect("balanced declaration");
                if depth == 0 {
                    return &suffix[..opening + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("{declaration} body must close")
}

fn all_braced_blocks<'a>(source: &'a str, marker: &str) -> Vec<&'a str> {
    let mut blocks = Vec::new();
    let mut search_offset = 0;
    while let Some(relative_start) = source[search_offset..].find(marker) {
        let start = search_offset + relative_start;
        let suffix = &source[start..];
        let block = braced_block(suffix, marker);
        blocks.push(block);
        search_offset = start + block.len();
    }
    blocks
}

fn identifier_tokens(source: &str) -> Vec<&str> {
    source
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .collect()
}

fn assert_no_derive(source: &str, declaration: &str, forbidden: &str) {
    let attributes = attributes_before_declaration(declaration_prefix(source, declaration));
    let tokens = identifier_tokens(&attributes);
    assert!(
        !(tokens.contains(&"derive") && tokens.contains(&forbidden)),
        "{declaration} derives forbidden trait {forbidden}"
    );
}

fn all_impl_headers(source: &str) -> Vec<String> {
    let mut headers = Vec::new();
    let mut current = String::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if current.is_empty() {
            if !(trimmed.starts_with("impl ")
                || trimmed.starts_with("impl<")
                || trimmed.starts_with("unsafe impl "))
            {
                continue;
            }
        } else {
            current.push(' ');
        }
        current.push_str(trimmed);
        if let Some(opening) = current.find('{') {
            current.truncate(opening);
            headers.push(std::mem::take(&mut current));
            continue;
        }
    }
    headers
}

fn assert_no_trait_impl(source: &str, type_name: &str, forbidden: &str) {
    for header in all_impl_headers(source) {
        let tokens = identifier_tokens(&header);
        let Some(separator) = tokens.iter().rposition(|token| *token == "for") else {
            continue;
        };
        assert!(
            !(tokens[..separator].contains(&forbidden)
                && tokens[separator + 1..].contains(&type_name)),
            "{type_name} implements forbidden trait {forbidden} through {header}"
        );
    }
}

fn assert_no_public_constructor(source: &str, type_name: &str) {
    let impl_marker = format!("impl {type_name}");
    for implementation in all_braced_blocks(source, &impl_marker) {
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
                "{type_name} exposes forbidden constructor {constructor}"
            );
        }

        for public_function in ["pub fn ", "pub const fn ", "pub async fn "] {
            let mut search_offset = 0;
            while let Some(relative_start) = implementation[search_offset..].find(public_function) {
                let start = search_offset + relative_start;
                let signature = &implementation[start
                    ..start
                        + implementation[start..]
                            .find('{')
                            .expect("public associated function must have a body")];
                if let Some((_, return_type)) = signature.split_once("->") {
                    let return_tokens = identifier_tokens(return_type);
                    assert!(
                        !return_tokens.contains(&"Self") && !return_tokens.contains(&type_name),
                        "{type_name} exposes a public constructor-like return through {signature}"
                    );
                }
                search_offset = start + public_function.len();
            }
        }
    }
}

#[test]
fn marker_source_oracle_detects_multiline_derives_and_late_constructors() {
    let multiline_derive = r#"
#[derive(
    Debug,
    Clone,
)]
pub struct AuthenticProbe {
    private: (),
}
"#;
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_derive(multiline_derive, "pub struct AuthenticProbe", "Clone");
        })
        .is_err(),
        "multiline forbidden derives must be detected"
    );

    let late_constructor = r#"
pub struct AuthenticProbe {
    private: (),
}
impl AuthenticProbe {
    fn private() -> Self { Self { private: () } }
}
impl AuthenticProbe {
    pub fn new() -> Self { Self { private: () } }
}
"#;
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_public_constructor(late_constructor, "AuthenticProbe");
        })
        .is_err(),
        "public constructors in later inherent impl blocks must be detected"
    );

    let qualified_trait_impl = r#"
pub struct AuthenticProbe {
    private: (),
}
impl std::clone::Clone for AuthenticProbe {
    fn clone(&self) -> Self { Self { private: () } }
}
"#;
    assert!(
        std::panic::catch_unwind(|| {
            assert_no_trait_impl(qualified_trait_impl, "AuthenticProbe", "Clone");
        })
        .is_err(),
        "qualified forbidden trait implementations must be detected"
    );
}

#[test]
fn authentic_markers_are_linear_non_wire_and_constructor_closed() {
    let mut production = fs::read_dir(source_path("."))
        .expect("source directory is readable")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|value| value.to_str()) == Some("rs"))
        .map(|entry| fs::read_to_string(entry.path()).expect("Rust source is UTF-8"))
        .collect::<Vec<_>>()
        .join("\n");
    production = code_without_line_comments(&production);

    for type_name in [
        "AuthenticHumanRequestGrantV1",
        "AuthenticTaskLeaseV1",
        "AuthenticApprovalDecisionV1",
    ] {
        let declaration = format!("pub struct {type_name}");
        for forbidden in [
            "Clone",
            "Copy",
            "Serialize",
            "Deserialize",
            "Default",
            "From",
            "TryFrom",
            "FromStr",
        ] {
            assert_no_derive(&production, &declaration, forbidden);
            assert_no_trait_impl(&production, type_name, forbidden);
        }
        let body = braced_block(&production, &declaration);
        assert!(
            body.lines()
                .skip(1)
                .all(|line| !line.trim_start().starts_with("pub ")),
            "{type_name} exposes a public field"
        );
        assert!(
            production.contains(&format!("impl Debug for {type_name}"))
                || production.contains(&format!("impl fmt::Debug for {type_name}"))
                || production.contains(&format!("impl std::fmt::Debug for {type_name}")),
            "{type_name} requires explicit redacted Debug"
        );
        assert_no_public_constructor(&production, type_name);
    }
}
