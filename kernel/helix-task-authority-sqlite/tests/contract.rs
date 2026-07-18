//! PLAN-006 foundation contracts shared by default and non-default builds.

mod support;

use helix_task_authority::{
    issue_root_lease_v1, AuthorityAdmissionClassV1, AuthorityCapacityProfileV1,
    AuthorityClockProviderV1, RootLeaseRequestOutcomeV1, AUTHORITY_ORDINARY_CAPACITY_V1,
    AUTHORITY_RESERVED_CONTROL_CAPACITY_V1,
};
use helix_task_authority_contracts::{Generation, Identifier, SafeU64};
use helix_task_authority_sqlite::{
    embedded_task_authority_store_schema_v1_sha256, AuthorityStoreOpenErrorV1,
    AuthorityTrustedClockOutcomeV1, AuthorityTrustedClockSampleV1, AuthorityTrustedClockSourceV1,
    InjectedAuthorityClockProviderV1, TASK_AUTHORITY_STORE_APPLICATION_ID_V1,
    TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256, TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
    TASK_AUTHORITY_STORE_SCHEMA_V1_SQL, TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1,
};
use rusqlite::Connection;

#[test]
fn exact_hlxa_schema_identity_digest_and_inventory_are_frozen() {
    assert_eq!(TASK_AUTHORITY_STORE_APPLICATION_ID_V1, 0x484c_5841);
    assert_eq!(TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1, 1);
    assert_eq!(
        embedded_task_authority_store_schema_v1_sha256(),
        TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256
    );
    assert_eq!(
        TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
        "f2a1124440c68d50da60e678c16dabccfe0588048ecc63d3cd7d3074bd92c5b8"
    );

    let connection = Connection::open_in_memory().expect("foundation SQLite opens");
    connection
        .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
        .expect("exact reviewed schema executes");
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .expect("application id reads");
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("user version reads");
    assert_eq!(application_id, TASK_AUTHORITY_STORE_APPLICATION_ID_V1);
    assert_eq!(user_version, TASK_AUTHORITY_STORE_SCHEMA_VERSION_V1);

    for (object_type, expected) in [("table", 17_i64), ("index", 4), ("trigger", 34)] {
        let actual: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema \
                 WHERE type = ?1 AND name NOT LIKE 'sqlite_%'",
                [object_type],
                |row| row.get(0),
            )
            .expect("schema inventory counts");
        assert_eq!(actual, expected, "{object_type} inventory drifted");
    }
}

#[test]
fn fixed_lanes_never_borrow_capacity() {
    let profile = AuthorityCapacityProfileV1::FIXED;
    assert_eq!(
        profile.ordinary_capacity_v1(),
        AUTHORITY_ORDINARY_CAPACITY_V1
    );
    assert_eq!(
        profile.reserved_control_capacity_v1(),
        AUTHORITY_RESERVED_CONTROL_CAPACITY_V1
    );
    for class in AuthorityAdmissionClassV1::ALL {
        let expected_control = matches!(
            class,
            AuthorityAdmissionClassV1::KeyStatusChange
                | AuthorityAdmissionClassV1::Revocation
                | AuthorityAdmissionClassV1::StatusLookup
        );
        assert_eq!(
            class.lane_v1(),
            if expected_control {
                helix_task_authority::AuthorityAdmissionLaneV1::ReservedControl
            } else {
                helix_task_authority::AuthorityAdmissionLaneV1::Ordinary
            }
        );
    }
}

struct FixedInjectedClock;

impl AuthorityTrustedClockSourceV1 for FixedInjectedClock {
    fn capture_trusted_v1(
        &self,
        _absolute_deadline_monotonic_ms: SafeU64,
    ) -> AuthorityTrustedClockOutcomeV1 {
        AuthorityTrustedClockOutcomeV1::Current(AuthorityTrustedClockSampleV1::new(
            Identifier::new("foundation-boot").expect("boot id is bounded"),
            Generation::new(1).expect("clock generation is positive"),
            Generation::new(1).expect("instance epoch is positive"),
            SafeU64::new(1_000).expect("UTC is safe"),
            SafeU64::new(100).expect("monotonic is safe"),
        ))
    }
}

#[test]
fn trusted_clock_is_injected_and_deadline_exclusive() {
    let provider = InjectedAuthorityClockProviderV1::new(FixedInjectedClock);
    let observation = provider
        .capture_v1(SafeU64::new(101).expect("deadline is safe"))
        .expect("strictly earlier sample admits");
    assert_eq!(observation.sampled_monotonic_ms_v1().get(), 100);
    assert!(provider
        .capture_v1(SafeU64::new(100).expect("deadline is safe"))
        .is_err());
}

#[test]
fn public_open_errors_are_closed_and_payload_free() {
    for error in [
        AuthorityStoreOpenErrorV1::RootInvalid,
        AuthorityStoreOpenErrorV1::RootIdentityMismatch,
        AuthorityStoreOpenErrorV1::ClockUnavailable,
        AuthorityStoreOpenErrorV1::DeadlineReached,
        AuthorityStoreOpenErrorV1::StoreBusy,
        AuthorityStoreOpenErrorV1::ApplicationIdMismatch,
        AuthorityStoreOpenErrorV1::SchemaUnsupported,
        AuthorityStoreOpenErrorV1::SchemaInvalid,
        AuthorityStoreOpenErrorV1::LifecycleUnavailable,
        AuthorityStoreOpenErrorV1::DurabilityProfileUnavailable,
        AuthorityStoreOpenErrorV1::IntegrityFailed,
        AuthorityStoreOpenErrorV1::InvariantFailed,
    ] {
        assert_eq!(format!("{error:?}"), error.code_v1());
        assert_eq!(error.to_string(), error.code_v1());
        assert!(!error.to_string().contains('/'));
    }
}

#[test]
fn fault_selection_has_no_ambient_environment_or_process_selector() {
    const CORE_LIB: &str = include_str!("../../helix-task-authority/src/lib.rs");
    const CORE_FAULT: &str = include_str!("../../helix-task-authority/src/test_fault.rs");
    const CORE_MANIFEST: &str = include_str!("../../helix-task-authority/Cargo.toml");
    const SQLITE_LIB: &str = include_str!("../src/lib.rs");
    const SQLITE_FAULT: &str = include_str!("../src/test_fault.rs");
    const SQLITE_MANIFEST: &str = include_str!("../Cargo.toml");

    assert!(CORE_LIB.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
    assert!(SQLITE_LIB.contains("#[cfg(feature = \"test-fault-injection\")]\nmod test_fault;"));
    assert!(CORE_MANIFEST.contains("[features]\ndefault = []"));
    assert!(SQLITE_MANIFEST.contains("[features]\ndefault = []"));
    assert!(CORE_MANIFEST.contains("test-fault-injection = []"));
    assert!(SQLITE_MANIFEST
        .contains("test-fault-injection = [\"helix-task-authority/test-fault-injection\"]"));
    for source in [CORE_FAULT, SQLITE_FAULT] {
        for forbidden in [
            "std::env",
            "env::",
            "getenv",
            "option_env!",
            "env!",
            "std::process",
            "process::",
            "Command::new",
            "OnceLock",
            "OnceCell",
            "thread_local!",
            "lazy_static!",
            "static mut",
        ] {
            assert!(
                !source.contains(forbidden),
                "fault seam contains ambient selector: {forbidden}"
            );
        }
    }
}

#[test]
fn fault_phase_ids_and_applicable_models_match_the_frozen_registry() {
    const REGISTRY: &str = include_str!(
        "../../../specs/006-durable-signed-task-authority/contracts/fault-boundaries-v1.json"
    );
    const EXPECTED: [(&str, &[&str]); 11] = [
        ("P00-CONTRACT", &["IN_PROCESS_SINGLE_FAULT"]),
        (
            "P01-ROOT-ISSUE",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P02-DELEGATION",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P03-COUNTER",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P04-DECISION",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P05-TRUST-REVOCATION",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P06-PROJECTION-GUARD",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P07-BOOTSTRAP",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P08-BACKUP",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        (
            "P09-RESTORE",
            &["IN_PROCESS_SINGLE_FAULT", "PROCESS_KILL_SINGLE_FAULT"],
        ),
        ("P10-CORRUPTION-READBACK", &["IN_PROCESS_SINGLE_FAULT"]),
    ];

    let registry: serde_json::Value = serde_json::from_str(REGISTRY).expect("registry is JSON");
    let phases = registry["phases"]
        .as_array()
        .expect("registry phases are an ordered array");
    assert_eq!(phases.len(), EXPECTED.len());
    for (phase, (expected_id, expected_models)) in phases.iter().zip(EXPECTED) {
        assert_eq!(phase["phase_id"].as_str(), Some(expected_id));
        let models: Vec<_> = phase["required_fault_models"]
            .as_array()
            .expect("required models are an array")
            .iter()
            .map(|model| model.as_str().expect("fault model is a string"))
            .collect();
        assert_eq!(models, expected_models);
    }
}

#[test]
fn root_issuance_graph_is_all_absent_or_all_visible_with_exact_generations() {
    let root = support::TestRoot::provision();
    let store = root.store();
    let signer = support::LeaseSignerV1::fixed();

    assert!(matches!(
        issue_root_lease_v1(support::request(50, 99), &signer, &store),
        RootLeaseRequestOutcomeV1::DeniedDefinite
    ));
    {
        let connection = root.connection();
        for table in [
            "human_request_grants",
            "human_grant_claims",
            "task_leases",
            "task_lease_usage",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "denied transaction leaked {table}");
        }
    }

    let retained = match issue_root_lease_v1(support::request(50, 3), &signer, &store) {
        RootLeaseRequestOutcomeV1::CommittedRetained(retained) => retained,
        outcome => panic!("valid root issuance failed: {outcome:?}"),
    };
    assert!(!retained.source_grant_wire_v1().is_empty());
    assert!(!retained.root_lease_wire_v1().is_empty());

    let connection = root.connection();
    for (table, expected) in [
        ("human_request_grants", 1_i64),
        ("human_grant_claims", 1),
        ("task_leases", 1),
        ("task_lease_usage", 1),
        ("authority_attempts", 4),
        ("authority_events", 4),
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected, "{table} cardinality");
    }
    let metadata: (i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT store_generation, trust_generation, grant_generation,
                    lease_generation, allocation_generation, counter_generation,
                    event_generation FROM authority_store_metadata",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(metadata, (4, 3, 4, 4, 4, 4, 4));
}

#[test]
fn exact_retry_reads_back_identical_root_bytes_without_resigning_persistence() {
    let root = support::TestRoot::provision();
    let store = root.store();
    let signer = support::LeaseSignerV1::fixed();
    let first = match issue_root_lease_v1(support::request(50, 3), &signer, &store) {
        RootLeaseRequestOutcomeV1::CommittedRetained(retained) => retained,
        outcome => panic!("first issuance failed: {outcome:?}"),
    };
    let first_wire = first.root_lease_wire_v1().to_vec();
    for _ in 0..32 {
        let retry = match issue_root_lease_v1(support::request(50, 3), &signer, &store) {
            RootLeaseRequestOutcomeV1::CommittedRetained(retained) => retained,
            outcome => panic!("exact retry failed: {outcome:?}"),
        };
        assert_eq!(retry.root_lease_wire_v1(), first_wire);
    }
    let connection = root.connection();
    let cardinality: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM human_grant_claims),
                (SELECT COUNT(*) FROM task_leases),
                (SELECT COUNT(*) FROM authority_attempts)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(cardinality, (1, 1, 4));
}

#[test]
fn signer_revocation_preserves_historical_key_bytes_but_denies_new_consumption() {
    let root = support::TestRoot::provision();
    root.revoke_request_signer();
    let store = root.store();
    let signer = support::LeaseSignerV1::fixed();
    assert!(matches!(
        issue_root_lease_v1(support::request(50, 4), &signer, &store),
        RootLeaseRequestOutcomeV1::DeniedDefinite
    ));
    let connection = root.connection();
    let counts: (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM authority_verification_keys),
                (SELECT COUNT(*) FROM human_request_grants),
                (SELECT COUNT(*) FROM task_leases)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(counts, (2, 0, 0));
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn non_default_probe_requires_an_explicit_closed_selection() {
    use helix_task_authority::{
        AuthorityFaultDecisionV1, AuthorityFaultModeV1, AuthorityFaultProbeV1,
        AuthorityFaultSelectionErrorV1,
    };

    let disabled = AuthorityFaultProbeV1::disabled_v1();
    assert_eq!(
        disabled.reach_phase_id_v1("P05-TRUST-REVOCATION"),
        Ok(AuthorityFaultDecisionV1::Continue)
    );
    let selected = AuthorityFaultProbeV1::selected_phase_v1(
        "P05-TRUST-REVOCATION",
        1,
        AuthorityFaultModeV1::InProcess,
        || {},
    )
    .expect("closed phase selects explicitly");
    assert_eq!(
        selected.reach_phase_id_v1("P05-TRUST-REVOCATION"),
        Ok(AuthorityFaultDecisionV1::InjectInProcess)
    );
    for phase_id in ["P00-CONTRACT", "P10-CORRUPTION-READBACK"] {
        assert_eq!(
            AuthorityFaultProbeV1::selected_phase_v1(
                phase_id,
                1,
                AuthorityFaultModeV1::ProcessKill,
                || {},
            )
            .unwrap_err(),
            AuthorityFaultSelectionErrorV1::UnsupportedFaultModel
        );
    }
}
