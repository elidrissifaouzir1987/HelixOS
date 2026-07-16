//! Closed source, dependency, egress and removal boundaries for the adapter inbox.

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const ROOT_SAFETY_SOURCE: &str = include_str!("../src/root_safety.rs");
const SCHEMA_SOURCE: &str = include_str!("../src/schema.rs");
const FAULT_REGISTRY: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/contracts/fault-boundaries-v1.json");
const PLAN004_FAULT_SOURCE: &[u8] =
    include_bytes!("../../helix-plan-preparation/src/test_fault.rs");
const PLAN004_FAULT_FIXTURES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/cases.json");
const REMOVAL_PROTECTED_FILES: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/evidence/removal-protected-files.json");

#[derive(Debug)]
struct SourceView {
    name: String,
    structure: String,
    without_comments: String,
}

fn dependencies_in<'manifest>(manifest: &'manifest str, section: &str) -> BTreeSet<&'manifest str> {
    let header = format!("[{section}]");
    let body = manifest
        .split_once(&header)
        .unwrap_or_else(|| panic!("missing [{section}] section"))
        .1;
    body.lines()
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty() && !name.starts_with('#'))
        .collect()
}

fn all_dependency_names(manifest: &str) -> BTreeSet<&str> {
    let mut in_dependencies = false;
    let mut names = BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]"
                || line == "[dev-dependencies]"
                || line == "[build-dependencies]"
                || line.ends_with(".dependencies]")
                || line.ends_with(".dev-dependencies]")
                || line.ends_with(".build-dependencies]");
            continue;
        }
        if in_dependencies {
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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("adapter crate is directly below the kernel workspace")
        .to_owned()
}

fn production_sources() -> Vec<SourceView> {
    fn visit(root: &Path, directory: &Path, views: &mut Vec<SourceView>) {
        let mut entries = fs::read_dir(directory)
            .expect("adapter source directory is readable")
            .map(|entry| entry.expect("adapter source entry is readable").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(root, &path, views);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let raw = fs::read_to_string(&path).expect("adapter Rust source is UTF-8");
                let structure = rust_view(&raw, true);
                let cutoff = terminal_cfg_test_cutoff(&structure, &path);
                let without_comments = rust_view(&raw, false);
                views.push(SourceView {
                    name: path
                        .strip_prefix(root)
                        .expect("source is below adapter root")
                        .to_string_lossy()
                        .replace('\\', "/"),
                    structure: structure[..cutoff].to_owned(),
                    without_comments: without_comments[..cutoff].to_owned(),
                });
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut views = Vec::new();
    visit(&root, &root, &mut views);
    views
}

fn terminal_cfg_test_cutoff(structure: &str, path: &Path) -> usize {
    let Some(cutoff) = structure.find("#[cfg(test)]") else {
        return structure.len();
    };
    let suffix = &structure[cutoff..];
    let opening = suffix
        .find('{')
        .unwrap_or_else(|| panic!("{} has cfg(test) without a module body", path.display()));
    assert_eq!(
        compact(&suffix[..opening]),
        "#[cfg(test)]modtests",
        "{} must use one terminal cfg(test) module",
        path.display()
    );

    let mut depth = 0_usize;
    let mut closing = None;
    for (index, byte) in suffix.as_bytes().iter().enumerate().skip(opening) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                assert!(
                    depth > 0,
                    "{} has an unbalanced test module",
                    path.display()
                );
                depth -= 1;
                if depth == 0 {
                    closing = Some(index + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let closing = closing
        .unwrap_or_else(|| panic!("{} has an unterminated cfg(test) module", path.display()));
    assert!(
        suffix[closing..].trim().is_empty(),
        "{} has code after its cfg(test) module",
        path.display()
    );
    cutoff
}

fn identifiers(source: &str) -> BTreeSet<&str> {
    source
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .collect()
}

fn compact(source: &str) -> String {
    source.split_whitespace().collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn json_string_set(value: &Value, pointer: &str) -> BTreeSet<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing JSON string array at {pointer}"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("non-string entry at {pointer}"))
                .to_owned()
        })
        .collect()
}

#[test]
fn dependency_boundary_is_exact_pinned_bundled_and_non_ambient() {
    assert_eq!(
        dependencies_in(CARGO_TOML, "dependencies"),
        BTreeSet::from([
            "helix-dispatch-contracts",
            "helix-plan-dispatch",
            "rusqlite",
            "serde",
            "serde_json",
            "serde_json_canonicalizer",
            "sha2",
        ])
    );
    assert_eq!(
        dependencies_in(CARGO_TOML, "dev-dependencies"),
        BTreeSet::from(["ed25519-dalek"])
    );
    assert_eq!(
        dependencies_in(CARGO_TOML, "target.'cfg(windows)'.dependencies"),
        BTreeSet::from(["fs-id"])
    );
    for exact in [
        "helix-dispatch-contracts = { path = \"../helix-dispatch-contracts\" }",
        "helix-plan-dispatch = { path = \"../helix-plan-dispatch\" }",
        "rusqlite = { version = \"=0.40.1\", default-features = false, features = [\"backup\", \"bundled\"] }",
        "serde = { version = \"=1.0.228\", default-features = false, features = [\"derive\", \"std\"] }",
        "serde_json = { version = \"=1.0.150\", default-features = false, features = [\"std\"] }",
        "serde_json_canonicalizer = \"=0.3.2\"",
        "sha2 = { version = \"=0.10.9\", default-features = false }",
        "ed25519-dalek = { version = \"=2.2.0\", default-features = false, features = [\"std\"] }",
        "fs-id = { version = \"=0.2.0\", default-features = false }",
        "default = []",
        "test-fault-injection = [\"helix-plan-dispatch/test-fault-injection\"]",
    ] {
        assert!(CARGO_TOML.contains(exact), "missing exact manifest boundary: {exact}");
    }
    for forbidden in [
        "helixos-kernel",
        "helix-coordinator-sqlite",
        "helix-plan-preparation",
        "helix-plan-eligibility",
        "libsqlite3-sys =",
        "load_extension",
        "tokio",
        "async-std",
        "reqwest",
        "hyper",
        "tonic",
        "sqlx",
        "uuid",
        "getrandom",
    ] {
        assert!(
            !CARGO_TOML.contains(forbidden),
            "forbidden dependency/feature {forbidden}"
        );
    }
}

#[test]
fn windows_identity_binds_type_reparse_guard_and_high_resolution_id_to_one_handle() {
    assert!(ROOT_SAFETY_SOURCE.contains("FILE_FLAG_OPEN_REPARSE_POINT_V1"));
    assert!(ROOT_SAFETY_SOURCE.contains("FILE_ATTRIBUTE_REPARSE_POINT_V1"));
    assert!(ROOT_SAFETY_SOURCE.contains(
        ".custom_flags(FILE_FLAG_BACKUP_SEMANTICS_V1 | FILE_FLAG_OPEN_REPARSE_POINT_V1)"
    ));
    assert!(ROOT_SAFETY_SOURCE.contains("let bound_metadata = file"));
    assert!(ROOT_SAFETY_SOURCE.contains("fs_id::FileID::new(&file)"));
    assert!(ROOT_SAFETY_SOURCE.contains("identity.storage_id()"));
    assert!(ROOT_SAFETY_SOURCE.contains("identity.internal_file_id()"));
    assert!(!ROOT_SAFETY_SOURCE.contains("file_id::get_high_res_file_id(path)"));
    assert!(ROOT_SAFETY_SOURCE.contains("MetadataExt as _"));
    assert!(!ROOT_SAFETY_SOURCE.contains(".volume_serial_number()"));
    assert!(!ROOT_SAFETY_SOURCE.contains(".file_index()"));
}

#[test]
fn adapter_is_a_separate_sqlite_leaf_with_one_reviewed_consumer() {
    let kernel = repo_root().join("kernel");
    let mut consumers = Vec::new();
    for entry in fs::read_dir(&kernel).expect("kernel workspace is readable") {
        let entry = entry.expect("workspace entry is readable");
        if !entry
            .file_type()
            .expect("workspace entry type is readable")
            .is_dir()
        {
            continue;
        }
        let manifest_path = entry.path().join("Cargo.toml");
        if !manifest_path.is_file() || entry.file_name() == "helix-dispatch-inbox-sqlite" {
            continue;
        }
        let manifest = fs::read_to_string(manifest_path).expect("workspace manifest is UTF-8");
        if all_dependency_names(&manifest).contains("helix-dispatch-inbox-sqlite") {
            consumers.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    consumers.sort();
    assert_eq!(consumers, ["helix-coordinator-sqlite"]);

    assert!(SCHEMA_SOURCE.contains("ADAPTER_INBOX_APPLICATION_ID_V1: i64 = 1212962889"));
    assert!(
        ROOT_SAFETY_SOURCE.contains("ADAPTER_DATABASE_FILENAME: &str = \"dispatch-inbox.sqlite3\"")
    );
    assert!(!LIB_SOURCE.contains("pub use rusqlite"));
    assert!(!LIB_SOURCE.contains("helix_coordinator_sqlite"));
}

#[test]
fn production_source_has_no_legacy_authority_effect_handle_or_egress() {
    let views = production_sources();
    assert!(!views.is_empty());
    for view in &views {
        let ids = identifiers(&view.structure);
        for forbidden in [
            "TaskLease",
            "ApprovalDecision",
            "ScopeLease",
            "PreparedOperationV1",
            "PreparationOutcomeV1",
            "ExecutionToken",
            "EffectToken",
            "EffectHandle",
            "HostEffect",
            "HostEffectHandle",
            "EffectHandoff",
            "PerformEffect",
            "SigningKey",
            "PrivateKey",
            "SecretString",
            "SecretVec",
            "api_key",
            "password",
            "private_key",
            "secret_key",
            "access_token",
            "bearer_token",
            "Credential",
            "Password",
            "ApiKey",
            "AccessToken",
            "BearerToken",
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            "UnixStream",
            "VsockStream",
            "reqwest",
            "hyper",
            "tonic",
            "tokio",
            "curl",
        ] {
            assert!(
                !ids.contains(forbidden),
                "{} contains forbidden identifier {forbidden}",
                view.name
            );
        }
        let structural = compact(&view.structure);
        for forbidden in [
            "std::net::",
            "std::process::",
            "Command::new(",
            "std::env::",
            ".display(",
            ".to_string_lossy(",
            "unsafe{",
            "unsafefn",
            "unsafeimpl",
            "println!(",
            "eprintln!(",
            "dbg!(",
            "tracing::",
            "log::",
        ] {
            assert!(
                !structural.contains(forbidden),
                "{} contains forbidden boundary {forbidden}",
                view.name
            );
        }
    }
    assert!(LIB_SOURCE.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn production_literals_have_no_secret_private_checkout_or_external_endpoint() {
    let private_markers = [
        ["/", "Users", "/"].concat(),
        ["/", "home", "/"].concat(),
        ["C:", "\\\\", "Users", "\\\\"].concat(),
        ["file", "://"].concat(),
    ];
    let secret_markers = [
        ["github", "_pat_"].concat(),
        ["gh", "p_"].concat(),
        ["AK", "IA"].concat(),
        ["BEGIN ", "PRIVATE KEY"].concat(),
        ["GITHUB", "_TOKEN"].concat(),
    ];
    let endpoint_markers = [
        ["http", "://"].concat(),
        ["https", "://"].concat(),
        ["ssh", "://"].concat(),
    ];
    for view in production_sources() {
        for marker in private_markers
            .iter()
            .chain(secret_markers.iter())
            .chain(endpoint_markers.iter())
        {
            assert!(
                !view.without_comments.contains(marker),
                "{} contains forbidden literal marker",
                view.name
            );
        }
    }
}

#[test]
fn platform_specific_identity_code_is_confined_and_symmetric() {
    for view in production_sources() {
        if view.name == "root_safety.rs" {
            assert!(view.structure.contains("#[cfg(unix)]"));
            assert!(view.structure.contains("#[cfg(windows)]"));
            assert!(view.structure.contains("fn filesystem_identity"));
            continue;
        }
        for forbidden in [
            "#[cfg(unix)]",
            "#[cfg(windows)]",
            "std::os::unix",
            "std::os::windows",
            "target_os",
            "target_arch",
            "target_family",
        ] {
            assert!(
                !view.structure.contains(forbidden),
                "{} contains platform branch {forbidden}",
                view.name
            );
        }
    }
}

#[test]
fn plan005_fault_registry_and_plan004_anchor_are_frozen() {
    assert_eq!(
        sha256_hex(FAULT_REGISTRY),
        "afef6e0b580a8ea62906227e25c59e7b067c7aa5dc55d5458d9ccf92f0b1ff26"
    );
    let registry: Value = serde_json::from_slice(FAULT_REGISTRY).expect("fault registry is JSON");
    assert_eq!(registry["schema"], "helixos.dispatch-fault-boundaries/1");
    assert_eq!(registry["registry_id"], "plan005-durable-dispatch-v1");
    assert_eq!(registry["lifecycle"], "frozen-v1");
    assert_eq!(registry["boundary_count"], 90);
    assert_eq!(registry["required_case_count"], 180);
    let boundaries = registry["boundaries"]
        .as_array()
        .expect("boundaries are an array");
    assert_eq!(boundaries.len(), 90);
    for (index, boundary) in boundaries.iter().enumerate() {
        let ordinal = index + 1;
        assert_eq!(boundary["ordinal"], ordinal as u64);
        assert_eq!(boundary["id"], format!("PLAN005-FB-{ordinal:03}"));
        assert_eq!(
            boundary["coverage"],
            serde_json::json!(["in-process", "process-kill"])
        );
    }
    let plan004 = &registry["plan004_registry"];
    assert_eq!(plan004["mutation_policy"], "must-remain-byte-identical");
    assert_eq!(plan004["boundary_count"], 123);
    assert_eq!(plan004["declared_fault_case_count"], 167);
    assert_eq!(plan004["fixture_total_case_count"], 335);
    assert_eq!(
        plan004["source_sha256"],
        "f9d9fd0ff4c3cb1bc7f48f52c0484031c9964c22ff3ce4c29b8f3dc24be07db9"
    );
    assert_eq!(
        plan004["fixture_sha256"],
        "086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d"
    );
    assert_eq!(sha256_hex(PLAN004_FAULT_SOURCE), plan004["source_sha256"]);
    assert_eq!(
        sha256_hex(PLAN004_FAULT_FIXTURES),
        plan004["fixture_sha256"]
    );
}

#[test]
fn removal_allowlist_owns_plan005_adapter_and_preserves_plan004() {
    let evidence: Value = serde_json::from_slice(REMOVAL_PROTECTED_FILES)
        .expect("removal protected-file evidence is JSON");
    assert_eq!(
        json_string_set(&evidence, "/removal_policy/added_prefixes_removed"),
        BTreeSet::from([
            "contracts/fixtures/durable-dispatch-v1/".to_owned(),
            "contracts/fixtures/durable-signed-task-authority-v1/".to_owned(),
            "graphify-out/memory/".to_owned(),
            "kernel/helix-dispatch-contracts/".to_owned(),
            "kernel/helix-dispatch-inbox-sqlite/".to_owned(),
            "kernel/helix-plan-dispatch/".to_owned(),
            "kernel/helix-task-authority-contracts/".to_owned(),
            "kernel/helix-task-authority-projections/".to_owned(),
            "kernel/helix-task-authority-sqlite/".to_owned(),
            "kernel/helix-task-authority/".to_owned(),
        ])
    );
    assert_eq!(
        json_string_set(
            &evidence,
            "/removal_policy/added_prefixes_retained_for_audit"
        ),
        BTreeSet::from([
            "specs/005-durable-dispatch/".to_owned(),
            "specs/006-durable-signed-task-authority/".to_owned(),
        ])
    );
    let restored = json_string_set(&evidence, "/removal_policy/baseline_paths_restored");
    for required in [
        "kernel/Cargo.toml",
        "kernel/Cargo.lock",
        "kernel/helix-coordinator-sqlite/Cargo.toml",
        "kernel/helix-coordinator-sqlite/tests/portability.rs",
    ] {
        assert!(
            restored.contains(required),
            "PLAN-004 path is not restored: {required}"
        );
    }
    assert_eq!(
        json_string_set(&evidence, "/expected_post_removal_workspace_packages"),
        BTreeSet::from([
            "helix-contracts".to_owned(),
            "helix-coordinator-sqlite".to_owned(),
            "helix-plan-eligibility".to_owned(),
            "helix-plan-preparation".to_owned(),
            "helix-replay-sqlite".to_owned(),
            "helixos-kernel".to_owned(),
            "helixos-mcp-shim".to_owned(),
            "helixos-provision".to_owned(),
        ])
    );
}

/// Removes Rust comments and optionally string contents while preserving byte offsets.
/// Keeping offsets lets the production cut happen at the structural `cfg(test)` marker,
/// so test-only canaries and prose cannot create portability false positives.
fn rust_view(source: &str, blank_strings: bool) -> String {
    let input = source.as_bytes();
    let mut output = input.to_vec();
    let mut index = 0_usize;
    while index < input.len() {
        if input[index..].starts_with(b"//") {
            let start = index;
            index += 2;
            while index < input.len() && input[index] != b'\n' {
                index += 1;
            }
            blank_preserving_newlines(&mut output, start, index);
            continue;
        }
        if input[index..].starts_with(b"/*") {
            let start = index;
            let mut depth = 1_u32;
            index += 2;
            while index < input.len() && depth > 0 {
                if input[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if input[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            blank_preserving_newlines(&mut output, start, index);
            continue;
        }
        if input[index] == b'r' {
            let mut opening = index + 1;
            while opening < input.len() && input[opening] == b'#' {
                opening += 1;
            }
            if opening < input.len() && input[opening] == b'"' {
                let hashes = opening - index - 1;
                let start = index;
                index = opening + 1;
                while index < input.len() {
                    if input[index] == b'"'
                        && input
                            .get(index + 1..index + 1 + hashes)
                            .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                    {
                        index += 1 + hashes;
                        break;
                    }
                    index += 1;
                }
                if blank_strings {
                    blank_preserving_newlines(&mut output, start, index);
                }
                continue;
            }
        }
        if input[index] == b'"' {
            let start = index;
            index += 1;
            while index < input.len() {
                match input[index] {
                    b'\\' => index = (index + 2).min(input.len()),
                    b'"' => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            if blank_strings {
                blank_preserving_newlines(&mut output, start, index);
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("blanked Rust source remains UTF-8")
}

fn blank_preserving_newlines(output: &mut [u8], start: usize, end: usize) {
    for byte in &mut output[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}
