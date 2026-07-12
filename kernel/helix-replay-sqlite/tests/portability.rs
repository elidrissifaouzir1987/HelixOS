//! Source and dependency gates for portable, non-authoritative host storage.

use std::collections::BTreeSet;

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const CLAIM_SOURCE: &str = include_str!("../src/claim.rs");
const CONNECTION_SOURCE: &str = include_str!("../src/connection.rs");
const VERIFICATION_SOURCE: &str = include_str!("../src/verification.rs");
const DEFAULT_SOURCES: [(&str, &str); 11] = [
    ("claim.rs", CLAIM_SOURCE),
    ("clock.rs", include_str!("../src/clock.rs")),
    ("config.rs", include_str!("../src/config.rs")),
    ("connection.rs", CONNECTION_SOURCE),
    ("error.rs", include_str!("../src/error.rs")),
    ("lib.rs", LIB),
    ("maintenance.rs", include_str!("../src/maintenance.rs")),
    ("manifest.rs", include_str!("../src/manifest.rs")),
    ("root_safety.rs", include_str!("../src/root_safety.rs")),
    ("schema.rs", include_str!("../src/schema.rs")),
    ("verification.rs", VERIFICATION_SOURCE),
];
const TEST_FAULT_SOURCE: &str = include_str!("../src/test_fault.rs");

fn normalize_line_endings(source: &str) -> String {
    source.replace("\r\n", "\n")
}

fn assert_absent(sources: &[(&str, &str)], forbidden: &[&str]) {
    for (name, source) in sources {
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "{name} contains forbidden source token {needle}"
            );
        }
    }
}

fn dependencies_in(section: &str) -> BTreeSet<&str> {
    let header = format!("[{section}]");
    let body = CARGO_TOML
        .split_once(&header)
        .unwrap_or_else(|| panic!("dependency section is missing"))
        .1;
    body.lines()
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty())
        .collect()
}

#[test]
fn implementation_has_no_os_architecture_or_host_tool_branch() {
    let mut all_sources = DEFAULT_SOURCES.to_vec();
    all_sources.push(("test_fault.rs", TEST_FAULT_SOURCE));
    assert_absent(
        &all_sources,
        &[
            "target_os",
            "target_arch",
            "target_family",
            "cfg!(windows)",
            "cfg(windows)",
            "cfg!(unix)",
            "cfg(unix)",
            "std::os::",
            "windows_sys",
            "windows-sys",
            "winapi",
            "libc::",
            "core_foundation",
            "objc::",
            "Command::new",
            "std::process::",
            "cmd.exe",
            "/bin/sh",
            "powershell",
            "C:\\\\Users\\\\",
            "/Users/",
            "/home/",
        ],
    );
}

#[test]
fn default_adapter_has_no_network_ambient_clock_or_diagnostic_sink() {
    assert_absent(
        &DEFAULT_SOURCES,
        &[
            "std::net::",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper::",
            "tonic::",
            "tokio::",
            "async fn",
            "SystemTime",
            "Instant::",
            "std::env::",
            "println!",
            "eprintln!",
            "dbg!",
            "tracing::",
            "log::",
            ".field(",
            "debug_map(",
            "debug_list(",
            "debug_tuple(",
        ],
    );
    assert!(LIB.contains("#![forbid(unsafe_code)]"));
    assert_absent(&DEFAULT_SOURCES, &["unsafe {"]);
}

#[test]
fn fault_process_io_is_non_default_and_not_publicly_exported() {
    let lib = normalize_line_endings(LIB);
    assert!(lib.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
    assert!(!lib.contains("pub mod test_fault"));
    assert!(TEST_FAULT_SOURCE.contains("Non-default process-crash barriers"));
    assert!(TEST_FAULT_SOURCE.contains("HELIX_REPLAY_TEST_FAULT_POINT"));
}

#[test]
fn claim_fault_selection_is_feature_gated_private_and_native_by_default() {
    let claim_source = normalize_line_endings(CLAIM_SOURCE);
    assert!(CARGO_TOML.contains("default = []"));
    assert!(CARGO_TOML.contains("test-fault-injection = []"));
    assert!(claim_source
        .contains("#[cfg(feature = \"test-fault-injection\")]\nconst TEST_CLAIM_SCENARIO_ENV"));
    assert!(claim_source
        .contains("#[cfg(feature = \"test-fault-injection\")]\n        if let Some(scenario)"));
    assert!(claim_source.contains("self.claim_once_with_io::<NativeClaimIoV1>(binding)\n    }"));
    assert!(claim_source.contains("struct NativeClaimRandomV1;"));
    assert!(claim_source.contains("struct NativeClaimIoV1;"));
    assert!(!LIB.contains("pub mod claim"));
    assert!(!LIB.contains("TEST_CLAIM_SCENARIO_ENV"));
    assert!(!claim_source.contains("pub enum TestClaimScenarioV1"));
    assert!(!claim_source.contains("pub struct UnavailableClaimRandomV1"));
}

#[test]
fn exact_verifier_is_private_query_only_and_separate_from_replay_admission() {
    let lib = normalize_line_endings(LIB);
    assert!(lib.contains("mod verification;"));
    assert!(!lib.contains("pub mod verification;"));

    let query_only_attempt = CONNECTION_SOURCE
        .split_once("fn open_existing_query_only_attempt")
        .expect("query-only open attempt exists")
        .1
        .split_once("fn preflight_database_file")
        .expect("query-only open attempt is bounded")
        .0;
    assert!(query_only_attempt.contains("OpenFlags::SQLITE_OPEN_READ_ONLY"));
    assert!(query_only_attempt.contains("configure_query_only_connection"));
    assert!(!query_only_attempt.contains("SQLITE_OPEN_READ_WRITE"));
    assert!(!query_only_attempt.contains("SQLITE_OPEN_CREATE"));
    assert!(!query_only_attempt.contains("configure_writable_connection"));

    let query_only_profile = CONNECTION_SOURCE
        .split_once("fn configure_query_only_connection")
        .expect("query-only connection profile exists")
        .1
        .split_once("fn verify_initialization_candidate")
        .expect("query-only connection profile is bounded")
        .0;
    assert!(query_only_profile.contains("\"query_only\", \"ON\""));
    assert!(query_only_profile.contains("pragma_i64(connection, \"query_only\")? != 1"));
    assert!(!query_only_profile.contains("pragma_update(None, \"journal_mode\""));

    assert_absent(
        &[("verification.rs", VERIFICATION_SOURCE)],
        &[
            "claim_once(",
            "ReplayClaimReceiptV1",
            "getrandom",
            "INSERT INTO",
            "UPDATE replay_",
            "DELETE FROM",
            "DROP TABLE",
            "DROP INDEX",
        ],
    );
}

#[test]
fn source_guard_normalization_is_lf_and_crlf_independent() {
    assert_eq!(normalize_line_endings("first\nsecond\n"), "first\nsecond\n");
    assert_eq!(
        normalize_line_endings("first\r\nsecond\r\n"),
        "first\nsecond\n"
    );
}

#[test]
fn direct_dependency_graph_is_closed_and_has_no_legacy_runtime_edge() {
    assert_eq!(
        dependencies_in("dependencies"),
        BTreeSet::from([
            "getrandom",
            "helix-contracts",
            "helix-plan-eligibility",
            "rusqlite",
            "serde",
            "serde_json",
            "sha2",
        ])
    );
    assert_eq!(
        dependencies_in("dev-dependencies"),
        BTreeSet::from(["ed25519-dalek"])
    );

    let joined_sources = DEFAULT_SOURCES
        .iter()
        .map(|(_, source)| *source)
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "helixos-kernel",
        "helixos_kernel",
        "helixos-mcp-shim",
        "helixos_mcp_shim",
        "frontier",
    ] {
        assert!(!CARGO_TOML.contains(forbidden));
        assert!(!joined_sources.contains(forbidden));
    }
}

#[test]
fn crate_surface_remains_storage_evidence_not_execution_authority() {
    assert!(LIB.contains("successful receipt is still only eligibility evidence"));
    assert!(LIB.contains("never preparation,"));
    assert!(LIB.contains("dispatch, adapter, or effect authority"));
    assert_absent(
        &DEFAULT_SOURCES,
        &[
            "dispatch_plan",
            "execute_plan",
            "prepare_effect",
            "authorize_effect",
            "effect_capability",
        ],
    );
}

#[test]
fn feature_004_removal_keeps_replay_adapter_read_only_and_dependency_free() {
    for forbidden in [
        "helix-plan-preparation",
        "helix-coordinator-sqlite",
        "PreparationStoreV1",
        "PreparedOperationV1",
        "PreparationOutcomeV1",
        "RESTORE_PENDING",
    ] {
        assert!(
            !CARGO_TOML.contains(forbidden),
            "replay manifest acquired a Feature 004 edge {forbidden}"
        );
        assert!(
            !VERIFICATION_SOURCE.contains(forbidden),
            "read-only replay verifier acquired Feature 004 authority {forbidden}"
        );
    }
    assert!(VERIFICATION_SOURCE.contains("ReplayClaimVerificationViewV1"));
    assert!(VERIFICATION_SOURCE.contains("ReplayClaimVerificationV1"));
    assert_absent(
        &[("verification.rs", VERIFICATION_SOURCE)],
        &[
            "claim_once",
            "release",
            "reset",
            "INSERT",
            "UPDATE",
            "DELETE",
        ],
    );
}
