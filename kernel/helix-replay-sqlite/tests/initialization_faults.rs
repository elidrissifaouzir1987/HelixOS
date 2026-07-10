//! Private initialization-provider fault seam proofs.

mod common;

use common::{InjectedClock, SyntheticTempRoot, OPEN_DEADLINE_MONOTONIC_MS};
use helix_replay_sqlite::SqliteReplayClaimantV1;
#[cfg(feature = "test-fault-injection")]
use helix_replay_sqlite::{REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1};
#[cfg(feature = "test-fault-injection")]
use rusqlite::{Connection, OpenFlags};
#[cfg(feature = "test-fault-injection")]
use std::fs;
#[cfg(feature = "test-fault-injection")]
use std::path::Path;
use std::process::Command;

const INITIALIZATION_FAULT_ENV: &str = "HELIX_REPLAY_TEST_INITIALIZATION_FAULT";
const PROVIDER_OPEN_UNAVAILABLE: &str = "provider_open_unavailable";
const WRITABLE_PROFILE_UNAVAILABLE: &str = "writable_profile_unavailable";
#[cfg(feature = "test-fault-injection")]
const UNRECOGNIZED_SCENARIO: &str = "provider-open-unavailable";
#[cfg(feature = "test-fault-injection")]
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[test]
fn initialization_fault_seam_is_source_guarded_and_private() {
    let source = include_str!("../src/connection.rs").replace("\r\n", "\n");
    assert!(source
        .contains("#[cfg(feature = \"test-fault-injection\")]\nconst INITIALIZATION_FAULT_ENV"));
    assert!(
        source.contains("#[cfg(feature = \"test-fault-injection\")]\nfn fail_initialization_at")
    );
    assert_eq!(
        source.matches("env::var(INITIALIZATION_FAULT_ENV)").count(),
        1
    );
    assert!(!source.contains("pub(crate) fn fail_initialization_at"));
    assert!(!source.contains("pub fn fail_initialization_at"));
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn provider_open_fault_is_store_unavailable_before_root_mutation() {
    run_child_scenario(PROVIDER_OPEN_UNAVAILABLE);
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn writable_profile_fault_precedes_valid_schema_initialization() {
    run_child_scenario(WRITABLE_PROFILE_UNAVAILABLE);
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn only_exact_initialization_fault_scenarios_are_selectable() {
    run_child_scenario(UNRECOGNIZED_SCENARIO);
}

#[cfg(not(feature = "test-fault-injection"))]
#[test]
fn default_build_has_no_selectable_initialization_fault_behavior() {
    run_child_scenario(PROVIDER_OPEN_UNAVAILABLE);
    run_child_scenario(WRITABLE_PROFILE_UNAVAILABLE);
}

#[test]
fn initialization_fault_child() {
    let Some(scenario) = std::env::var(INITIALIZATION_FAULT_ENV).ok() else {
        return;
    };
    let root = SyntheticTempRoot::new("initialization-fault-child");
    let result = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    );

    #[cfg(feature = "test-fault-injection")]
    match scenario.as_str() {
        PROVIDER_OPEN_UNAVAILABLE => {
            let error = result.expect_err("provider-open fault unexpectedly initialized a store");
            assert_eq!(error.code(), "STORE_UNAVAILABLE");
            assert_eq!(
                fs::read_dir(root.path())
                    .unwrap_or_else(|_| panic!("provider-fault root became unreadable"))
                    .count(),
                0,
                "provider-open failure mutated the dedicated root"
            );
        }
        WRITABLE_PROFILE_UNAVAILABLE => {
            let error = result.expect_err("profile fault unexpectedly initialized a store");
            assert_eq!(error.code(), "DURABILITY_PROFILE_UNAVAILABLE");
            assert!(
                !contains_valid_v1_schema(root.path()),
                "profile failure left a valid initialized schema"
            );
            std::env::remove_var(INITIALIZATION_FAULT_ENV);
            SqliteReplayClaimantV1::open_or_create(
                root.config(),
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("profile-fault root was not recoverable"));
        }
        _ => {
            result.unwrap_or_else(|_| panic!("unrecognized scenario selected fault behavior"));
        }
    }

    #[cfg(not(feature = "test-fault-injection"))]
    {
        assert!(
            matches!(
                scenario.as_str(),
                PROVIDER_OPEN_UNAVAILABLE | WRITABLE_PROFILE_UNAVAILABLE
            ),
            "unrecognized initialization fault scenario"
        );
        result.unwrap_or_else(|_| panic!("default build selected private fault behavior"));
    }
}

fn run_child_scenario(scenario: &str) {
    let executable =
        std::env::current_exe().unwrap_or_else(|_| panic!("fault test executable unavailable"));
    let status = Command::new(executable)
        .args([
            "--exact",
            "initialization_fault_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(INITIALIZATION_FAULT_ENV, scenario)
        .status()
        .unwrap_or_else(|_| panic!("initialization fault child failed to start"));
    assert!(status.success(), "initialization fault child failed");
}

#[cfg(feature = "test-fault-injection")]
fn contains_valid_v1_schema(root: &Path) -> bool {
    fs::read_dir(root)
        .unwrap_or_else(|_| panic!("profile-fault root became unreadable"))
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .filter(|entry| {
            fs::read(entry.path())
                .ok()
                .and_then(|bytes| bytes.get(..SQLITE_HEADER.len()).map(<[u8]>::to_vec))
                .as_deref()
                == Some(SQLITE_HEADER.as_slice())
        })
        .any(|entry| valid_v1_schema_at(&entry.path()))
}

#[cfg(feature = "test-fault-injection")]
fn valid_v1_schema_at(path: &Path) -> bool {
    let Ok(connection) = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return false;
    };
    let application_id = connection.pragma_query_value(None, "application_id", |row| row.get(0));
    let user_version = connection.pragma_query_value(None, "user_version", |row| row.get(0));
    let object_count: rusqlite::Result<i64> = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    );
    matches!(
        (application_id, user_version, object_count),
        (Ok(REPLAY_STORE_APPLICATION_ID_V1), Ok(REPLAY_STORE_SCHEMA_VERSION_V1), Ok(count))
            if count > 0
    )
}
