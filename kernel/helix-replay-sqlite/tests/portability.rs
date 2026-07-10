//! Source and dependency gates for portable, non-authoritative host storage.

use std::collections::BTreeSet;

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const CLAIM_SOURCE: &str = include_str!("../src/claim.rs");
const DEFAULT_SOURCES: [(&str, &str); 10] = [
    ("claim.rs", CLAIM_SOURCE),
    ("clock.rs", include_str!("../src/clock.rs")),
    ("config.rs", include_str!("../src/config.rs")),
    ("connection.rs", include_str!("../src/connection.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("lib.rs", LIB),
    ("maintenance.rs", include_str!("../src/maintenance.rs")),
    ("manifest.rs", include_str!("../src/manifest.rs")),
    ("root_safety.rs", include_str!("../src/root_safety.rs")),
    ("schema.rs", include_str!("../src/schema.rs")),
];
const TEST_FAULT_SOURCE: &str = include_str!("../src/test_fault.rs");

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
    assert!(LIB.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
    assert!(!LIB.contains("pub mod test_fault"));
    assert!(TEST_FAULT_SOURCE.contains("Non-default process-crash barriers"));
    assert!(TEST_FAULT_SOURCE.contains("HELIX_REPLAY_TEST_FAULT_POINT"));
}

#[test]
fn claim_fault_selection_is_feature_gated_private_and_native_by_default() {
    assert!(CARGO_TOML.contains("default = []"));
    assert!(CARGO_TOML.contains("test-fault-injection = []"));
    assert!(CLAIM_SOURCE
        .contains("#[cfg(feature = \"test-fault-injection\")]\nconst TEST_CLAIM_SCENARIO_ENV"));
    assert!(CLAIM_SOURCE
        .contains("#[cfg(feature = \"test-fault-injection\")]\n        if let Some(scenario)"));
    assert!(CLAIM_SOURCE.contains("self.claim_once_with_io::<NativeClaimIoV1>(binding)\n    }"));
    assert!(CLAIM_SOURCE.contains("struct NativeClaimRandomV1;"));
    assert!(CLAIM_SOURCE.contains("struct NativeClaimIoV1;"));
    assert!(!LIB.contains("pub mod claim"));
    assert!(!LIB.contains("TEST_CLAIM_SCENARIO_ENV"));
    assert!(!CLAIM_SOURCE.contains("pub enum TestClaimScenarioV1"));
    assert!(!CLAIM_SOURCE.contains("pub struct UnavailableClaimRandomV1"));
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
