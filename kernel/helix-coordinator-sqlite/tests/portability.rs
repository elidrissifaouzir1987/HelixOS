//! OS-neutral semantics, pinned bytes and closed dependency/source gates.

use helix_coordinator_sqlite::{embedded_schema_v1_sha256, COORDINATOR_STORE_SCHEMA_V1_SQL};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const PORTABLE_CARGO: &str = include_str!("../../helix-plan-preparation/Cargo.toml");
const COORDINATOR_CARGO: &str = include_str!("../Cargo.toml");
const COORDINATOR_LIB: &str = include_str!("../src/lib.rs");
const CONNECTION_SOURCE: &str = include_str!("../src/connection.rs");
const ROOT_SAFETY_SOURCE: &str = include_str!("../src/root_safety.rs");
const MANIFEST_SOURCE: &str = include_str!("../src/manifest.rs");
const SCHEMA_SOURCE: &str = include_str!("../src/schema.rs");
const TEST_FAULT_SOURCE: &str = include_str!("../src/test_fault.rs");

const PORTABLE_SOURCES: [(&str, &str); 11] = [
    (
        "attempt.rs",
        include_str!("../../helix-plan-preparation/src/attempt.rs"),
    ),
    (
        "budget.rs",
        include_str!("../../helix-plan-preparation/src/budget.rs"),
    ),
    (
        "commit_gate.rs",
        include_str!("../../helix-plan-preparation/src/commit_gate.rs"),
    ),
    (
        "compare.rs",
        include_str!("../../helix-plan-preparation/src/compare.rs"),
    ),
    (
        "context.rs",
        include_str!("../../helix-plan-preparation/src/context.rs"),
    ),
    (
        "coordinator.rs",
        include_str!("../../helix-plan-preparation/src/coordinator.rs"),
    ),
    (
        "guard.rs",
        include_str!("../../helix-plan-preparation/src/guard.rs"),
    ),
    (
        "lib.rs",
        include_str!("../../helix-plan-preparation/src/lib.rs"),
    ),
    (
        "outcome.rs",
        include_str!("../../helix-plan-preparation/src/outcome.rs"),
    ),
    (
        "recovery.rs",
        include_str!("../../helix-plan-preparation/src/recovery.rs"),
    ),
    (
        "store.rs",
        include_str!("../../helix-plan-preparation/src/store.rs"),
    ),
];

const COORDINATOR_COMMON_SOURCES: [(&str, &str); 16] = [
    ("budget.rs", include_str!("../src/budget.rs")),
    ("clock.rs", include_str!("../src/clock.rs")),
    (
        "comparison_digest.rs",
        include_str!("../src/comparison_digest.rs"),
    ),
    ("config.rs", include_str!("../src/config.rs")),
    ("error.rs", include_str!("../src/error.rs")),
    ("failure.rs", include_str!("../src/failure.rs")),
    ("lib.rs", COORDINATOR_LIB),
    ("maintenance.rs", include_str!("../src/maintenance.rs")),
    ("manifest.rs", MANIFEST_SOURCE),
    ("outbox.rs", include_str!("../src/outbox.rs")),
    ("preflight.rs", include_str!("../src/preflight.rs")),
    ("prepare.rs", include_str!("../src/prepare.rs")),
    ("quarantine.rs", include_str!("../src/quarantine.rs")),
    ("readback.rs", include_str!("../src/readback.rs")),
    ("schema.rs", SCHEMA_SOURCE),
    ("transition.rs", include_str!("../src/transition.rs")),
];

const CONTRACT_SQL: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);
const BACKUP_MANIFEST_SCHEMA: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/preparation-backup-manifest-v1.schema.json"
);
const PROVENANCE_SCHEMA: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/preparation-backup-provenance-attestation-v1.schema.json"
);
const RECOVERY_ROOT_SCHEMA: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/recovery-root-metadata-v1.schema.json"
);
const RECOVERY_SNAPSHOT_SCHEMA: &[u8] = include_bytes!(
    "../../../specs/004-durable-preparation/contracts/recovery-snapshot-manifest-v1.schema.json"
);

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
        .filter(|name| !name.is_empty())
        .collect()
}

fn assert_absent(sources: &[(&str, &str)], forbidden: &[&str]) {
    for (name, source) in sources {
        for token in forbidden {
            assert!(
                !source.contains(token),
                "{name} contains forbidden token {token}"
            );
        }
    }
}

fn assert_tokens_in_order(source: &str, tokens: &[&str]) {
    let mut remaining = source;
    for token in tokens {
        let (_, tail) = remaining
            .split_once(token)
            .unwrap_or_else(|| panic!("missing ordered token {token}"));
        remaining = tail;
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn portable_semantics_have_no_os_filesystem_sqlite_or_ambient_branch() {
    assert_absent(
        &PORTABLE_SOURCES,
        &[
            "target_os",
            "target_arch",
            "target_family",
            "#[cfg(unix)]",
            "#[cfg(windows)]",
            "std::os::",
            "std::path::",
            "std::fs::",
            "rusqlite",
            "sqlite3",
            "SystemTime",
            "Instant::",
            "std::env::",
            "std::net::",
            "tokio::",
            "async fn",
            "Command::new",
            "std::process::",
        ],
    );
    assert!(PORTABLE_SOURCES
        .iter()
        .all(|(_, source)| source.contains("#![forbid(unsafe_code)]")
            || !source.contains("unsafe {")));
}

#[test]
fn platform_cfg_is_confined_to_legitimate_filesystem_identity_modules() {
    for (name, source) in COORDINATOR_COMMON_SOURCES {
        if name == "maintenance.rs" {
            // The sole semantic exception is a fail-closed Windows restore refusal:
            // acceptance and the defensive restore entry each split before any custody,
            // trust or mutation. This does not authorize an alternate implementation.
            let normalized_source = source.replace("\r\n", "\n");
            let semantic_source = normalized_source
                .split_once(
                    "#[cfg(all(feature = \"test-fault-injection\", not(test)))]\nmod t071_production_conformance",
                )
                .expect("feature-only production conformance module remains isolated")
                .0;
            assert_eq!(
                semantic_source
                    .matches("#[cfg(all(not(test), windows))]")
                    .count(),
                2
            );
            assert_eq!(
                semantic_source
                    .matches("#[cfg(all(not(test), not(windows)))]")
                    .count(),
                2
            );
            assert!(semantic_source.contains("RESTORE_PLATFORM_UNSUPPORTED"));
            assert!(!semantic_source.contains("#[cfg(windows)]"));
            assert!(!semantic_source.contains("#[cfg(unix)]"));
            assert!(!semantic_source.contains("target_os"));
            assert!(!semantic_source.contains("target_arch"));
            continue;
        }
        assert!(
            !source.contains("#[cfg(unix)]") && !source.contains("#[cfg(windows)]"),
            "common semantic module {name} must not select outcomes by host OS"
        );
        assert!(!source.contains("target_os"));
        assert!(!source.contains("target_arch"));
    }

    for (name, source) in [
        ("connection.rs", CONNECTION_SOURCE),
        ("root_safety.rs", ROOT_SAFETY_SOURCE),
    ] {
        assert!(
            source.contains("#[cfg(unix)]"),
            "{name} lacks Unix identity binding"
        );
        assert!(
            source.contains("#[cfg(windows)]"),
            "{name} lacks Windows identity binding"
        );
        assert!(!source.contains("target_os"));
        assert!(!source.contains("target_arch"));
    }
    assert!(ROOT_SAFETY_SOURCE.contains("fn filesystem_identity"));
    assert!(CONNECTION_SOURCE.contains("fn file_identity"));
}

#[test]
fn direct_dependencies_are_closed_pinned_and_bundled() {
    assert_eq!(
        dependencies_in(PORTABLE_CARGO, "dependencies"),
        BTreeSet::from(["getrandom", "helix-contracts", "helix-plan-eligibility"])
    );
    assert_eq!(
        dependencies_in(PORTABLE_CARGO, "dev-dependencies"),
        BTreeSet::from([
            "ed25519-dalek",
            "proptest",
            "serde",
            "serde_json",
            "serde_json_canonicalizer",
        ])
    );
    assert_eq!(
        dependencies_in(COORDINATOR_CARGO, "dependencies"),
        BTreeSet::from([
            "base64",
            "ed25519-dalek",
            "getrandom",
            "helix-contracts",
            "helix-dispatch-contracts",
            "helix-dispatch-inbox-sqlite",
            "helix-plan-dispatch",
            "helix-plan-preparation",
            "rusqlite",
            "serde",
            "serde_json",
            "serde_json_canonicalizer",
            "sha2",
        ])
    );
    assert_eq!(
        dependencies_in(COORDINATOR_CARGO, "dev-dependencies"),
        BTreeSet::from(["helix-replay-sqlite", "proptest"])
    );
    assert!(COORDINATOR_CARGO.contains(
        "rusqlite = { version = \"=0.40.1\", default-features = false, features = [\"backup\", \"bundled\", \"serialize\"] }"
    ));
    assert!(
        COORDINATOR_CARGO.contains("sha2 = { version = \"=0.10.9\", default-features = false }")
    );
    for forbidden in [
        "tokio",
        "async-std",
        "reqwest",
        "hyper",
        "tonic",
        "sqlx",
        "libsqlite3-sys =",
        "load_extension",
        "bundled-windows",
        "helixos-kernel",
        "helixos-mcp-shim",
    ] {
        assert!(!PORTABLE_CARGO.contains(forbidden));
        assert!(!COORDINATOR_CARGO.contains(forbidden));
    }
}

#[test]
fn reviewed_sql_and_json_schema_bytes_have_exact_pinned_digests() {
    assert_eq!(
        COORDINATOR_STORE_SCHEMA_V1_SQL.as_bytes(),
        CONTRACT_SQL.as_bytes()
    );
    assert_eq!(
        embedded_schema_v1_sha256(),
        <[u8; 32]>::from(Sha256::digest(CONTRACT_SQL.as_bytes()))
    );
    for (bytes, expected) in [
        (
            CONTRACT_SQL.as_bytes(),
            "e7b7c6c70f356afe4e45b3e2c7210b38c4ccc0f69a012cbdaddd103a8827880e",
        ),
        (
            BACKUP_MANIFEST_SCHEMA,
            "163cfd72f54983f993b2d5f6ad3fcd00df84a1b8cbc7eb971fcc8c1d0019199e",
        ),
        (
            PROVENANCE_SCHEMA,
            "6b752fc1a8f0c92fd69a03ce418d07087e615eaf55f3b2e1959668e15237728f",
        ),
        (
            RECOVERY_ROOT_SCHEMA,
            "0fb080c12df1b1e99ef7d0a19ca53ded97d8d170e0c2825e93fd3d57c53bf25f",
        ),
        (
            RECOVERY_SNAPSHOT_SCHEMA,
            "371e94fbf5c52d462e8363c9b3237a57288c4b0ae1c766e12c2c904d5f6cf646",
        ),
    ] {
        assert!(!bytes.starts_with(&[0xef, 0xbb, 0xbf]));
        assert_eq!(sha256_hex(bytes), expected);
    }
    assert!(SCHEMA_SOURCE.contains("COORDINATOR_STORE_SCHEMA_V1_SQL: &str = include_str!"));
    assert!(
        MANIFEST_SOURCE.contains("PREPARATION_BACKUP_MANIFEST_V1_JSON_SCHEMA: &str = include_str!")
    );
    assert!(MANIFEST_SOURCE
        .contains("BACKUP_PROVENANCE_ATTESTATION_V1_JSON_SCHEMA: &str = include_str!"));
    assert!(MANIFEST_SOURCE.contains("RECOVERY_ROOT_METADATA_V1_JSON_SCHEMA: &str = include_str!"));
    assert!(
        MANIFEST_SOURCE.contains("RECOVERY_SNAPSHOT_MANIFEST_V1_JSON_SCHEMA: &str = include_str!")
    );
}

#[test]
fn package_binding_provider_fields_are_hashed_in_the_normative_order() {
    let encoder = MANIFEST_SOURCE
        .split_once("fn compute_package_binding_sha256(")
        .expect("package-binding encoder must exist")
        .1
        .split_once("fn update_string(")
        .expect("package-binding encoder must remain bounded")
        .0;
    assert_tokens_in_order(
        encoder,
        &[
            "PACKAGE_BINDING_DOMAIN_V1",
            "provider.provider_profile_id",
            "provider.provider_profile_version.to_be_bytes()",
            "provider.provider_id",
            "provider.provider_generation.to_be_bytes()",
            "provider.evidence_class",
            "provider.at_rest_profile_id",
            "entry.custody.as_str()",
            "entry.state.as_str()",
            "entry.manifest_sha256",
            "entry.material_sha256",
            "entry.material_length.to_be_bytes()",
            "entry.reserved_capacity.to_be_bytes()",
            "entry.retirement_manifest_sha256",
        ],
    );
    assert!(!encoder.contains("cfg("));
    assert!(!encoder.contains("to_ne_bytes"));
    assert!(!encoder.contains("to_le_bytes"));
    assert!(!encoder.contains("package_binding_sha256"));
    let string_encoder = MANIFEST_SOURCE
        .split_once("fn update_string(")
        .expect("string encoder must exist")
        .1
        .split_once("fn decode_signature(")
        .expect("string encoder must remain bounded")
        .0;
    assert!(string_encoder.contains("u16::try_from(value.len())"));
    assert!(string_encoder.contains("length.to_be_bytes()"));
    assert!(string_encoder.contains("value.as_bytes()"));
}

#[test]
fn durability_and_supply_chain_have_no_weaker_semantic_fallback() {
    let configure = CONNECTION_SOURCE
        .split_once("fn configure_connection(")
        .expect("connection profile configurator must exist")
        .1
        .split_once("fn configure_busy_timeout(")
        .expect("connection profile configurator must remain bounded")
        .0;
    for required in [
        "PRAGMA journal_mode = WAL",
        "PRAGMA synchronous = FULL;",
        "PRAGMA foreign_keys = ON;",
        "PRAGMA trusted_schema = OFF;",
        "PRAGMA cell_size_check = ON;",
        "PRAGMA recursive_triggers = ON;",
        "PRAGMA wal_autocheckpoint = 0;",
        "verify_profile(connection)",
    ] {
        assert!(
            configure.contains(required),
            "missing strict durability step {required}"
        );
    }
    let verify = CONNECTION_SOURCE
        .split_once("fn verify_profile(")
        .expect("connection profile verifier must exist")
        .1
        .split_once("fn profile_pragma_i64(")
        .expect("connection profile verifier must remain bounded")
        .0;
    for required in [
        "(SELECT journal_mode FROM temp.pragma_journal_mode())",
        "(SELECT synchronous FROM temp.pragma_synchronous())",
        "(SELECT foreign_keys FROM temp.pragma_foreign_keys())",
        "(SELECT trusted_schema FROM temp.pragma_trusted_schema())",
        "(SELECT cell_size_check FROM temp.pragma_cell_size_check())",
        "(SELECT recursive_triggers FROM temp.pragma_recursive_triggers())",
        "profile.1 != 2",
        "profile.2 != 1",
        "profile.3 != 0",
        "profile.4 != 1",
        "profile.5 != 1",
        "profile_pragma_i64(connection, \"wal_autocheckpoint\")? != 0",
    ] {
        assert!(
            verify.contains(required),
            "missing strict durability verification {required}"
        );
    }
    assert_absent(
        &COORDINATOR_COMMON_SOURCES,
        &[
            "journal_mode = DELETE",
            "journal_mode = MEMORY",
            "synchronous\", \"NORMAL",
            "synchronous\", \"OFF",
            "load_extension",
            "enable_load_extension",
            "std::net::",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "tokio::",
            "async fn",
            "println!",
            "eprintln!",
            "dbg!",
            "tracing::",
            "log::",
        ],
    );
    for pinned in [
        "self.rusqlite_version != \"0.40.1\"",
        "self.libsqlite3_sys_version != \"0.38.1\"",
        "self.bundled_sqlite_version != \"3.53.2\"",
        "self.link_profile != \"rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static\"",
        "self.journal_mode != \"WAL\"",
        "self.synchronous != \"FULL\"",
    ] {
        assert!(
            MANIFEST_SOURCE.contains(pinned),
            "missing fail-closed pin {pinned}"
        );
    }
}

#[test]
fn fault_session_is_private_non_default_and_non_ambient() {
    let normalized_lib = COORDINATOR_LIB.replace("\r\n", "\n");
    let production_fault_source = TEST_FAULT_SOURCE
        .split_once("#[cfg(test)]")
        .map_or(TEST_FAULT_SOURCE, |(production, _)| production);
    assert!(normalized_lib.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
    assert!(!normalized_lib.contains("pub mod test_fault"));
    assert!(COORDINATOR_CARGO.contains("default = []"));
    let (_, test_fault_feature) = COORDINATOR_CARGO
        .split_once("test-fault-injection = [")
        .expect("coordinator test-fault feature remains declared");
    let (test_fault_members, _) = test_fault_feature
        .split_once(']')
        .expect("coordinator test-fault feature remains a closed member list");
    assert!(test_fault_members.contains("\"helix-plan-preparation/test-fault-injection\""));
    assert!(production_fault_source.contains("pub(crate) struct FaultSessionV1"));
    assert!(production_fault_source.contains("pub(crate) const fn disabled_v1()"));
    assert!(!production_fault_source.contains("std::env"));
    assert!(!production_fault_source.contains("Command::new"));
    assert!(!production_fault_source.contains("std::process::"));
    assert!(!COORDINATOR_LIB.contains("FaultSessionV1"));
}

#[test]
fn feature_004_dependency_and_removal_boundary_is_exact() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("coordinator crate is directly below the kernel workspace");
    let mut preparation_consumers = Vec::new();
    let mut coordinator_consumers = Vec::new();
    for entry in std::fs::read_dir(workspace).expect("kernel workspace is readable") {
        let entry = entry.expect("workspace directory entry is readable");
        if !entry.file_type().expect("entry type is readable").is_dir() {
            continue;
        }
        let manifest = entry.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let source = std::fs::read_to_string(&manifest).expect("workspace manifest is UTF-8");
        let package = entry.file_name().to_string_lossy().into_owned();
        if package != "helix-plan-preparation" && source.contains("helix-plan-preparation") {
            preparation_consumers.push(package.clone());
        }
        if package != "helix-coordinator-sqlite" && source.contains("helix-coordinator-sqlite") {
            coordinator_consumers.push(package);
        }
    }
    preparation_consumers.sort();
    coordinator_consumers.sort();
    assert_eq!(
        preparation_consumers,
        vec![
            "helix-coordinator-sqlite".to_owned(),
            "helix-task-authority-projections".to_owned(),
        ]
    );
    assert!(coordinator_consumers.is_empty());

    for (name, manifest) in [
        (
            "legacy-kernel",
            include_str!("../../helixos-kernel/Cargo.toml"),
        ),
        (
            "mcp-shim",
            include_str!("../../helixos-mcp-shim/Cargo.toml"),
        ),
        (
            "provision-cli",
            include_str!("../../helixos-provision/Cargo.toml"),
        ),
    ] {
        for forbidden in ["helix-plan-preparation", "helix-coordinator-sqlite"] {
            assert!(
                !manifest.contains(forbidden),
                "{name} acquired forbidden Feature 004 dependency {forbidden}"
            );
        }
    }
}
