//! Closed source, dependency and removal gates for portable dispatch orchestration.

#![forbid(unsafe_code)]

use helix_dispatch_contracts::Sha256Digest;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const FAULT_SOURCE: &str = include_str!("../src/test_fault.rs");
const SOURCES: [(&str, &str); 16] = [
    ("attempt.rs", include_str!("../src/attempt.rs")),
    ("authority.rs", include_str!("../src/authority.rs")),
    ("commit_gate.rs", include_str!("../src/commit_gate.rs")),
    ("compare.rs", include_str!("../src/compare.rs")),
    ("control.rs", include_str!("../src/control.rs")),
    ("coordinator.rs", include_str!("../src/coordinator.rs")),
    ("guard.rs", include_str!("../src/guard.rs")),
    ("inbox.rs", include_str!("../src/inbox.rs")),
    ("lib.rs", LIB_SOURCE),
    ("outcome.rs", include_str!("../src/outcome.rs")),
    ("queue.rs", include_str!("../src/queue.rs")),
    (
        "reconciliation.rs",
        include_str!("../src/reconciliation.rs"),
    ),
    ("request.rs", include_str!("../src/request.rs")),
    ("store.rs", include_str!("../src/store.rs")),
    ("test_fault.rs", FAULT_SOURCE),
    ("transport.rs", include_str!("../src/transport.rs")),
];

const FAULT_REGISTRY_BYTES: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/contracts/fault-boundaries-v1.json");
const REMOVAL_MANIFEST_BYTES: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/evidence/removal-protected-files.json");
const FAULT_REGISTRY_SHA256: &str =
    "afef6e0b580a8ea62906227e25c59e7b067c7aa5dc55d5458d9ccf92f0b1ff26";
const REMOVAL_MANIFEST_SHA256: &str =
    "66569b2d563beca2d4d35c6fb15e456d8d190d7341e20790e92af109006776e0";

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

fn code_without_line_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    for line in source.lines() {
        let mut in_string = false;
        let mut escaped = false;
        let mut chars = line.char_indices().peekable();
        let mut end = line.len();
        while let Some((index, character)) = chars.next() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
                continue;
            }
            if character == '"' {
                in_string = true;
            } else if character == '/' && chars.peek().is_some_and(|(_, next)| *next == '/') {
                end = index;
                break;
            }
        }
        output.push_str(&line[..end]);
        output.push('\n');
    }
    output
}

fn assert_code_absent(forbidden: &[&str]) {
    for (name, source) in SOURCES {
        let code = code_without_line_comments(source);
        for token in forbidden {
            assert!(
                !code.contains(token),
                "{name} contains forbidden code token {token}"
            );
        }
    }
}

fn source_inventory() -> BTreeSet<String> {
    fn visit(root: &std::path::Path, directory: &std::path::Path, paths: &mut BTreeSet<String>) {
        let mut entries = std::fs::read_dir(directory)
            .expect("portable source directory is readable")
            .map(|entry| entry.expect("portable source entry is readable").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(root, &path, paths);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                paths.insert(
                    path.strip_prefix(root)
                        .expect("source is below portable crate root")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = BTreeSet::new();
    visit(&root, &root, &mut paths);
    paths
}

fn required_string_array<'value>(value: &'value Value, key: &str) -> Vec<&'value str> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("{key} members must be strings"))
        })
        .collect()
}

#[test]
fn production_source_has_no_storage_os_platform_or_concrete_egress_primitive() {
    assert_eq!(
        source_inventory(),
        SOURCES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect::<BTreeSet<_>>(),
        "every Rust source must be explicitly included in the closed portability scan"
    );
    assert_code_absent(&[
        "std::fs::",
        "std::path::",
        "std::net::",
        "std::process::",
        "std::os::",
        "Command::new(",
        "File::open(",
        "OpenOptions::new(",
        "TcpStream",
        "UdpSocket",
        "UnixStream",
        "rusqlite::",
        "sqlite3",
        "tokio::",
        "async fn",
        "reqwest::",
        "hyper::",
        "tonic::",
        "SystemTime",
        "std::env::",
        "target_os",
        "target_arch",
        "target_family",
        "cfg(windows)",
        "cfg(unix)",
        "println!(",
        "eprintln!(",
        "dbg!(",
        "tracing::",
        "log::",
        "unsafe {",
        "unsafe fn",
    ]);
    assert!(LIB_SOURCE.contains("#![forbid(unsafe_code)]"));
    assert!(LIB_SOURCE.contains("transport and effect execution remain outside this crate"));
}

#[test]
fn dependency_and_feature_graph_is_exact_closed_and_legacy_free() {
    assert_eq!(
        section_keys(CARGO_TOML, "dependencies"),
        BTreeSet::from(["getrandom", "helix-dispatch-contracts"])
    );
    assert_eq!(
        section_keys(CARGO_TOML, "dev-dependencies"),
        BTreeSet::from(["serde_json", "serde_json_canonicalizer"])
    );
    assert_eq!(
        section_keys(CARGO_TOML, "features"),
        BTreeSet::from(["controlled-benchmark", "default", "test-fault-injection"])
    );
    assert!(CARGO_TOML.contains("getrandom = { version = \"=0.4.3\", default-features = false }"));
    assert!(CARGO_TOML
        .contains("helix-dispatch-contracts = { path = \"../helix-dispatch-contracts\" }"));
    for feature in [
        "default = []",
        "controlled-benchmark = []",
        "test-fault-injection = []",
    ] {
        assert!(CARGO_TOML.contains(feature), "feature drift: {feature}");
    }
    for forbidden in [
        "helix-contracts",
        "helix-plan-eligibility",
        "helix-plan-preparation",
        "helix-replay-sqlite",
        "helix-coordinator-sqlite",
        "helix-dispatch-inbox-sqlite",
        "helixos-kernel",
        "helixos-mcp-shim",
        "helixos-provision",
        "rusqlite",
        "tokio",
        "reqwest",
        "sqlx",
    ] {
        assert!(
            !CARGO_TOML.contains(forbidden),
            "forbidden dependency {forbidden}"
        );
    }
}

#[test]
fn orchestration_accepts_only_injected_traits_and_has_no_legacy_authority_edge() {
    assert_code_absent(&[
        "helix_plan_eligibility::",
        "helix_plan_preparation::",
        "helix_replay_sqlite::",
        "helix_coordinator_sqlite::",
        "helix_dispatch_inbox_sqlite::",
        "helixos_kernel::",
        "PreparedOperationV1",
        "PreparationStoreV1",
        "TaskLease",
        "ApprovalDecision",
    ]);
    for required in [
        "pub trait DispatchAuthorityProviderV1",
        "pub trait DispatchCoordinatorStoreV1",
        "pub trait DispatchTransportV1",
        "pub trait DispatchInboxV1",
        "pub trait DispatchClockV1",
        "pub trait DispatchEntropySourceV1",
        "pub trait DispatchGrantSignerV1",
    ] {
        assert!(
            SOURCES.iter().any(|(_, source)| source.contains(required)),
            "missing {required}"
        );
    }
}

#[test]
fn public_surface_has_no_execution_token_or_host_effect_handoff() {
    for forbidden in [
        "ExecutionToken",
        "execution_token",
        "EffectHandoff",
        "effect_handoff",
        "execute_effect",
        "execute_host",
        "authorize_effect",
        "host_effect_v1",
    ] {
        assert!(
            !LIB_SOURCE.contains(forbidden),
            "public surface exposes {forbidden}"
        );
        assert_code_absent(&[forbidden]);
    }
    let coordinator = SOURCES
        .iter()
        .find(|(name, _)| *name == "coordinator.rs")
        .expect("coordinator source")
        .1;
    assert!(coordinator.contains("Effect-only projection loaded from durable PLAN-004 state"));
    assert!(coordinator.contains("It contains no host handle"));
    assert!(!coordinator.contains("pub content_bytes"));
    assert!(!coordinator.contains("pub host_handle"));
}

#[test]
fn source_has_no_secret_material_or_private_native_path_literal() {
    let forbidden = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "github_pat_",
        "ghp_",
        "AKIA",
        "ASIA",
        "api_key",
        "private_key",
        "password",
        "passwd",
        "Bearer ",
        "/Users/",
        "/home/",
        "C:\\\\Users\\\\",
        "file://",
    ];
    for (name, source) in SOURCES {
        let source = code_without_line_comments(source);
        for token in forbidden {
            assert!(
                !source.contains(token),
                "{name} contains sensitive marker {token}"
            );
        }
    }
}

#[test]
fn frozen_fault_registry_has_exact_digest_order_owners_and_compiled_ids() {
    assert_eq!(
        Sha256Digest::digest(FAULT_REGISTRY_BYTES).to_hex(),
        FAULT_REGISTRY_SHA256
    );
    let registry: Value = serde_json::from_slice(FAULT_REGISTRY_BYTES).expect("registry JSON");
    assert_eq!(registry["schema"], "helixos.dispatch-fault-boundaries/1");
    assert_eq!(registry["registry_id"], "plan005-durable-dispatch-v1");
    assert_eq!(registry["lifecycle"], "frozen-v1");
    assert_eq!(registry["boundary_count"], 90);
    assert_eq!(registry["required_case_count"], 180);
    let boundaries = registry["boundaries"].as_array().expect("boundaries");
    assert_eq!(boundaries.len(), 90);
    let allowed_owners = BTreeSet::from([
        "helix-coordinator-sqlite",
        "helix-dispatch-contracts",
        "helix-dispatch-inbox-sqlite",
        "helix-plan-dispatch",
    ]);
    let mut owner_counts = BTreeMap::new();
    for (index, boundary) in boundaries.iter().enumerate() {
        let ordinal = u64::try_from(index + 1).expect("90 ordinals fit u64");
        let id = format!("PLAN005-FB-{ordinal:03}");
        assert_eq!(boundary["ordinal"], ordinal);
        assert_eq!(boundary["id"], id);
        let owner = boundary["owner"].as_str().expect("owner");
        assert!(allowed_owners.contains(owner), "unreviewed owner {owner}");
        *owner_counts.entry(owner).or_insert(0_usize) += 1;
        assert_eq!(
            required_string_array(boundary, "coverage"),
            vec!["in-process", "process-kill"]
        );
        assert_eq!(FAULT_SOURCE.matches(&format!("=> \"{id}\"")).count(), 1);
    }
    assert_eq!(owner_counts.values().sum::<usize>(), 90);
    assert!(FAULT_SOURCE.contains("CLOSED_FAULT_BOUNDARY_COUNT_V1: usize = 90"));
    let normalized_lib_source = LIB_SOURCE.replace("\r\n", "\n");
    assert!(normalized_lib_source
        .contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
    assert!(!normalized_lib_source.contains("pub mod test_fault"));
}

#[test]
fn removal_boundary_owns_the_portable_crate_and_all_direct_consumers() {
    assert_eq!(
        Sha256Digest::digest(REMOVAL_MANIFEST_BYTES).to_hex(),
        REMOVAL_MANIFEST_SHA256
    );
    let manifest: Value =
        serde_json::from_slice(REMOVAL_MANIFEST_BYTES).expect("removal manifest JSON");
    let policy = &manifest["removal_policy"];
    let removed_prefixes = required_string_array(policy, "added_prefixes_removed");
    let retained_prefixes = required_string_array(policy, "added_prefixes_retained_for_audit");
    assert!(removed_prefixes.contains(&"kernel/helix-plan-dispatch/"));
    assert!(removed_prefixes.contains(&"kernel/helix-dispatch-contracts/"));
    assert!(removed_prefixes.contains(&"kernel/helix-dispatch-inbox-sqlite/"));
    assert_eq!(retained_prefixes, vec!["specs/005-durable-dispatch/"]);
    assert!(retained_prefixes
        .iter()
        .all(|prefix| !"kernel/helix-plan-dispatch/".starts_with(prefix)));

    let restored = required_string_array(policy, "baseline_paths_restored");
    assert!(restored.contains(&"kernel/Cargo.toml"));
    assert!(restored.contains(&"kernel/helix-coordinator-sqlite/Cargo.toml"));

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate is directly below the kernel workspace");
    let mut consumers = Vec::new();
    for entry in std::fs::read_dir(workspace).expect("kernel workspace is readable") {
        let entry = entry.expect("workspace entry");
        if !entry.file_type().expect("entry type").is_dir() {
            continue;
        }
        let cargo = entry.path().join("Cargo.toml");
        if !cargo.is_file() {
            continue;
        }
        let source = std::fs::read_to_string(cargo).expect("manifest is UTF-8");
        if section_keys(&source, "dependencies").contains("helix-plan-dispatch") {
            consumers.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    consumers.sort();
    assert_eq!(
        consumers,
        vec![
            "helix-coordinator-sqlite".to_owned(),
            "helix-dispatch-inbox-sqlite".to_owned(),
        ]
    );
}
