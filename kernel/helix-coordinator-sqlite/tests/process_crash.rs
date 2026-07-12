//! T062 release-only process-kill matrix for the closed Feature 004 fault registry.
//!
//! The ordinary test derives and validates the complete matrix without spawning. The
//! ignored release test requires T074's real child drivers in `common/process_probe.rs`:
//! one driver must carry an explicit private fault session through a production
//! workflow, publish READY, wait for GO, publish `boundary-reached` only from the
//! selected checkpoint, and block for parent termination. A second child must reopen
//! the killed roots, run full invariants, and publish one closed state token. Until
//! those drivers exist, the ignored test fails immediately with a named T074 RED; it
//! never substitutes a synthetic sleep or a registry-only no-op for a real boundary.

#![cfg(feature = "test-fault-injection")]

mod common;

#[path = "common/t074_quarantine.rs"]
mod t074_quarantine;
#[path = "common/t074_recovery.rs"]
mod t074_recovery;
#[path = "common/t074_transactions.rs"]
mod t074_transactions;

// The quarantine/retirement phase reuses the reviewed crate-private conformance
// transactions. Source inclusion keeps those seams private to this integration binary;
// the production library still exposes no quarantine or retirement authority.
#[path = "../src/budget.rs"]
mod budget;
#[path = "../src/comparison_digest.rs"]
mod comparison_digest;
#[path = "../src/failure.rs"]
mod failure;
#[path = "../src/outbox.rs"]
mod outbox;
#[path = "../src/prepare.rs"]
mod prepare;
#[path = "../src/quarantine.rs"]
mod quarantine;
#[path = "../src/readback.rs"]
mod readback;
#[path = "../src/retirement.rs"]
mod retirement;
#[path = "../src/test_fault.rs"]
mod test_fault;
#[path = "../src/transition.rs"]
mod transition;

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/cases.json");
const PROCESS_PROBE_SOURCE: &str = include_str!("common/process_probe.rs");
const FAULT_CHILD_TEST_V1: &str = "process_crash_fault_router_child_v1";
const REOPEN_CHILD_TEST_V1: &str = "process_crash_reopen_router_child_v1";

// Private child-only protocol. Native paths never enter a public diagnostic.
const PROTOCOL_ROOT_ENV: &str = "HELIXOS_T062_PROTOCOL_ROOT";
const BOUNDARY_ID_ENV: &str = "HELIXOS_T062_BOUNDARY_ID";
const BOUNDARY_OCCURRENCE_ENV: &str = "HELIXOS_T062_BOUNDARY_OCCURRENCE";
const BOUNDARY_PHASE_ENV: &str = "HELIXOS_T062_BOUNDARY_PHASE";
const MATERIAL_PACKAGES_ENV: &str = "HELIXOS_T062_MATERIAL_PACKAGES";
const RETIREMENT_TOMBSTONES_ENV: &str = "HELIXOS_T062_RETIREMENT_TOMBSTONES";
const RESTORE_PACKAGES_ENV: &str = "HELIXOS_T062_RESTORE_PACKAGES";
const READY_MARKER: &str = "ready";
const GO_MARKER: &str = "go";
const BOUNDARY_REACHED_MARKER: &str = "boundary-reached";
const REOPEN_RESULT_MARKER: &str = "reopen-result";

const CONTROLLED_MATERIAL_PACKAGES: u64 = 3;
const CONTROLLED_RETIREMENT_TOMBSTONES: u64 = 2;
const CONTROLLED_RESTORE_PACKAGES: u64 = 4;
const EXPECTED_MATRIX_CASES: usize = 167;
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(30);
const PROTOCOL_POLL: Duration = Duration::from_millis(2);
const MAX_REOPEN_RESULT_BYTES: usize = 64;
const CLOSED_REOPEN_STATES: [&[u8]; 4] = [b"absent", b"preparing", b"failed", b"quarantine"];
const T074_TRANSACTION_BOUNDARY_IDS_V1: &[&str] = &[
    "positive_coordinator_commit_permit_resolved_aborted",
    "positive_coordinator_commit_permit_resolved_ambiguous",
    "acknowledgement_uncertain_connection_closed",
    "acknowledgement_readback_snapshot_opened",
    "acknowledgement_readback_classified_this_attempt",
    "acknowledgement_readback_classified_prior_exact_attempt",
    "acknowledgement_readback_classified_conflict",
    "acknowledgement_readback_classified_definite_absence",
    "acknowledgement_readback_classified_ambiguous",
    "known_failure_no_dispatch_guard_acquired",
    "known_failure_no_dispatch_guard_finally_revalidated",
    "known_failure_begin_immediate_acquired",
    "known_failure_operation_failed_staged",
    "known_failure_transition_staged",
    "known_failure_scope_held_subtraction_staged",
    "known_failure_reservation_released_staged",
    "known_failure_event_staged",
    "known_failure_metadata_staged",
    "known_failure_commit_returned",
    "known_failure_commit_classified",
    "known_failure_no_dispatch_guard_released",
];
const WINDOWS_PRODUCTION_UNREACHABLE_RESTORE_BOUNDARY_IDS_V1: &[&str] = &[
    "restore_package_and_pinned_provenance_accepted",
    "restore_empty_coordinator_root_reserved",
    "restore_empty_recovery_root_reserved",
    "restore_coordinator_database_imported",
    "restore_wal_full_profile_established",
    "restore_recovery_package_imported",
    "restore_coordinator_restore_pending_committed",
    "restore_coordinator_pending_root_marker_published",
    "restore_recovery_restore_pending_metadata_published",
    "restore_both_roots_closed",
    "restore_both_roots_reopened",
    "restore_both_roots_agreement_classified",
    "restore_verified_preparation_restore_returned",
    "restore_quarantine_persisted",
];
static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
struct CasesCorpusV1 {
    fault_boundaries: Vec<FaultBoundaryRowV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultBoundaryRowV1 {
    boundary_id: String,
    expected_registry_occurrences: u64,
    multiplicity: String,
    order: u64,
    owner: String,
    phase: String,
    prepared_success_occurrences: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CrashCaseV1 {
    boundary_id: String,
    occurrence: u64,
    phase: String,
}

struct T074RouterChildProtocolV1 {
    root: PathBuf,
    boundary_id: String,
    occurrence: u64,
    phase: String,
}

#[derive(Clone, Copy)]
enum T074IsolatedWorkflowV1 {
    RecoveryPublication,
    QuarantineAndRetirement,
    Transactions,
}

impl T074IsolatedWorkflowV1 {
    fn for_boundary_v1(boundary_id: &str) -> Option<Self> {
        if t074_recovery::supports_boundary_v1(boundary_id) {
            Some(Self::RecoveryPublication)
        } else if t074_quarantine::supports_boundary_v1(boundary_id) {
            Some(Self::QuarantineAndRetirement)
        } else if t074_transactions::supports_boundary_v1(boundary_id) {
            Some(Self::Transactions)
        } else {
            None
        }
    }

    fn prepare_fixture_v1(self, protocol: &T074RouterChildProtocolV1) -> Result<(), &'static str> {
        match self {
            Self::RecoveryPublication => t074_recovery::prepare_fixture_v1(&protocol.root)
                .map_err(|_| "recovery-fixture-prepare-failed"),
            Self::QuarantineAndRetirement => t074_quarantine::prepare_fixture_v1(&protocol.root),
            Self::Transactions => {
                t074_transactions::prepare_fixture_v1(&protocol.root, &protocol.boundary_id)
            }
        }
    }

    fn run_boundary_v1(
        self,
        protocol: &T074RouterChildProtocolV1,
        process_barrier: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), &'static str> {
        match self {
            Self::RecoveryPublication => t074_recovery::run_boundary_v1(
                &protocol.root,
                &protocol.boundary_id,
                protocol.occurrence,
                process_barrier,
            )
            .map_err(|_| "recovery-boundary-run-failed"),
            Self::QuarantineAndRetirement => t074_quarantine::run_boundary_v1(
                &protocol.root,
                &protocol.boundary_id,
                protocol.occurrence,
                process_barrier,
            ),
            Self::Transactions => t074_transactions::run_boundary_v1(
                &protocol.root,
                &protocol.boundary_id,
                protocol.occurrence,
                process_barrier,
            ),
        }
    }

    fn reopen_state_v1(
        self,
        protocol: &T074RouterChildProtocolV1,
    ) -> Result<&'static [u8], &'static str> {
        match self {
            Self::RecoveryPublication => {
                t074_recovery::reopen_state_v1(&protocol.root).map_err(|_| "recovery-reopen-failed")
            }
            Self::QuarantineAndRetirement => t074_quarantine::reopen_state_v1(&protocol.root),
            Self::Transactions => t074_transactions::reopen_state_v1(&protocol.root),
        }
    }
}

fn decode_boundaries_v1() -> Vec<FaultBoundaryRowV1> {
    serde_json::from_slice::<CasesCorpusV1>(CASES_BYTES)
        .expect("T061 cases corpus decodes")
        .fault_boundaries
}

fn occurrence_count_v1(row: &FaultBoundaryRowV1) -> u64 {
    match row.multiplicity.as_str() {
        "unit" => 1,
        "preliminary-groups" => 12,
        "final-guards" => 10,
        "final-groups" => 12,
        "commit-members" => 8,
        "material-packages" => CONTROLLED_MATERIAL_PACKAGES,
        "retirement-tombstones" => CONTROLLED_RETIREMENT_TOMBSTONES,
        "restore-packages" => CONTROLLED_RESTORE_PACKAGES,
        other => panic!("unknown T061 multiplicity {other}"),
    }
}

impl T074RouterChildProtocolV1 {
    fn from_environment_v1() -> Result<Option<Self>, &'static str> {
        let Some(root) = std::env::var_os(PROTOCOL_ROOT_ENV) else {
            return Ok(None);
        };
        let root = PathBuf::from(root);
        let metadata = fs::symlink_metadata(&root).map_err(|_| "protocol-root-unavailable")?;
        if !root.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("protocol-root-invalid");
        }

        let boundary_id = required_router_utf8_v1(BOUNDARY_ID_ENV)?;
        if boundary_id.is_empty()
            || boundary_id.len() > 128
            || !boundary_id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err("boundary-id-invalid");
        }
        let occurrence = required_router_u64_v1(BOUNDARY_OCCURRENCE_ENV)?;
        if occurrence == 0 {
            return Err("boundary-occurrence-invalid");
        }
        let phase = required_router_utf8_v1(BOUNDARY_PHASE_ENV)?;
        let material_packages = required_router_u64_v1(MATERIAL_PACKAGES_ENV)?;
        let retirement_tombstones = required_router_u64_v1(RETIREMENT_TOMBSTONES_ENV)?;
        let restore_packages = required_router_u64_v1(RESTORE_PACKAGES_ENV)?;
        if material_packages != CONTROLLED_MATERIAL_PACKAGES
            || retirement_tombstones != CONTROLLED_RETIREMENT_TOMBSTONES
            || restore_packages != CONTROLLED_RESTORE_PACKAGES
        {
            return Err("controlled-multiplicity-invalid");
        }

        let boundaries = decode_boundaries_v1();
        let row = boundaries
            .iter()
            .find(|row| row.boundary_id == boundary_id)
            .ok_or("boundary-id-unknown")?;
        if row.expected_registry_occurrences != 1
            || row.order == 0
            || row.prepared_success_occurrences > 12
            || row.phase != phase
            || occurrence > occurrence_count_v1(row)
            || !matches!(row.owner.as_str(), "portable" | "coordinator")
        {
            return Err("boundary-protocol-mismatch");
        }
        if matches!(
            T074IsolatedWorkflowV1::for_boundary_v1(&boundary_id),
            Some(
                T074IsolatedWorkflowV1::RecoveryPublication
                    | T074IsolatedWorkflowV1::QuarantineAndRetirement
            )
        ) && row.owner != "coordinator"
        {
            return Err("isolated-boundary-owner-invalid");
        }

        Ok(Some(Self {
            root,
            boundary_id,
            occurrence,
            phase,
        }))
    }

    fn isolated_workflow_v1(&self) -> Option<T074IsolatedWorkflowV1> {
        match (
            self.phase.as_str(),
            T074IsolatedWorkflowV1::for_boundary_v1(&self.boundary_id),
        ) {
            ("recovery", Some(T074IsolatedWorkflowV1::RecoveryPublication)) => {
                Some(T074IsolatedWorkflowV1::RecoveryPublication)
            }
            (
                "quarantine-and-retirement",
                Some(T074IsolatedWorkflowV1::QuarantineAndRetirement),
            ) => Some(T074IsolatedWorkflowV1::QuarantineAndRetirement),
            (
                "positive-coordinator-commit" | "acknowledgement-and-readback" | "known-failure",
                Some(T074IsolatedWorkflowV1::Transactions),
            ) => Some(T074IsolatedWorkflowV1::Transactions),
            _ => None,
        }
    }

    fn marker_v1(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn publish_ready_and_wait_for_go_v1(&self) -> Result<(), &'static str> {
        publish_child_marker_v1(&self.marker_v1(READY_MARKER), b"ready")?;
        let marker = self.marker_v1(GO_MARKER);
        let deadline = Instant::now() + PROTOCOL_TIMEOUT;
        loop {
            match fs::symlink_metadata(&marker) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err("go-marker-invalid");
                    }
                    let value = fs::read(&marker).map_err(|_| "go-marker-unreadable")?;
                    if value == b"go" {
                        return Ok(());
                    }
                    if !value.is_empty() {
                        return Err("go-marker-invalid");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("go-marker-unavailable"),
            }
            if Instant::now() >= deadline {
                return Err("go-marker-timeout");
            }
            thread::sleep(PROTOCOL_POLL);
        }
    }

    fn process_barrier_v1(&self) -> Arc<dyn Fn() + Send + Sync> {
        let marker = self.marker_v1(BOUNDARY_REACHED_MARKER);
        Arc::new(move || {
            publish_child_marker_v1(&marker, b"boundary-reached")
                .expect("T074 isolated process barrier publishes");
            loop {
                thread::park();
            }
        })
    }

    fn publish_reopen_result_v1(&self, state: &[u8]) -> Result<(), &'static str> {
        if !CLOSED_REOPEN_STATES.contains(&state) {
            return Err("reopen-state-invalid");
        }
        publish_child_marker_v1(&self.marker_v1(REOPEN_RESULT_MARKER), state)
    }
}

fn required_router_utf8_v1(name: &str) -> Result<String, &'static str> {
    std::env::var_os(name)
        .ok_or("private-protocol-value-missing")?
        .into_string()
        .map_err(|_| "private-protocol-value-invalid")
}

fn required_router_u64_v1(name: &str) -> Result<u64, &'static str> {
    let value = required_router_utf8_v1(name)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("private-protocol-number-invalid");
    }
    value
        .parse::<u64>()
        .map_err(|_| "private-protocol-number-invalid")
}

fn publish_child_marker_v1(path: &Path, value: &[u8]) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > MAX_REOPEN_RESULT_BYTES {
        return Err("child-marker-value-invalid");
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "child-marker-create-failed")?;
    file.write_all(value)
        .and_then(|()| file.sync_all())
        .map_err(|_| "child-marker-write-failed")
}

fn crash_matrix_v1() -> Vec<CrashCaseV1> {
    decode_boundaries_v1()
        .into_iter()
        .flat_map(|row| {
            let count = occurrence_count_v1(&row);
            (1..=count).map(move |occurrence| CrashCaseV1 {
                boundary_id: row.boundary_id.clone(),
                occurrence,
                phase: row.phase.clone(),
            })
        })
        .collect()
}

fn phase_counts_v1(cases: &[CrashCaseV1]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for case in cases {
        *counts.entry(case.phase.clone()).or_default() += 1;
    }
    counts
}

fn shared_process_driver_supports_v1(row: &FaultBoundaryRowV1) -> bool {
    match row.phase.as_str() {
        "preliminary" | "final-comparison" => row.owner == "portable",
        "positive-coordinator-commit" => row.prepared_success_occurrences > 0,
        "acknowledgement-and-readback" => {
            row.owner == "portable" && row.prepared_success_occurrences > 0
        }
        "backup" | "restore" => row.owner == "coordinator",
        _ => false,
    }
}

fn process_router_supports_v1(row: &FaultBoundaryRowV1) -> bool {
    shared_process_driver_supports_v1(row)
        || t074_recovery::supports_boundary_v1(&row.boundary_id)
        || t074_quarantine::supports_boundary_v1(&row.boundary_id)
        || t074_transactions::supports_boundary_v1(&row.boundary_id)
}

fn release_process_kill_case_is_reachable_v1(case: &CrashCaseV1) -> bool {
    // The public Windows v1 restore contract refuses before package capture, PAUSE or
    // destination mutation, so none of the frozen restore boundaries is a production-
    // reachable process-kill point on that host. The full registry remains unchanged,
    // and production_restore_conformance plus restore_maintenance_api prove the exact
    // fail-closed refusal independently.
    !cfg!(windows)
        || !WINDOWS_PRODUCTION_UNREACHABLE_RESTORE_BOUNDARY_IDS_V1
            .contains(&case.boundary_id.as_str())
}

#[test]
fn frozen_registry_expands_to_the_exact_controlled_release_matrix() {
    let boundaries = decode_boundaries_v1();
    assert_eq!(boundaries.len(), 123);
    assert_eq!(
        boundaries
            .iter()
            .map(|row| row.boundary_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        123
    );
    assert!(boundaries
        .iter()
        .enumerate()
        .all(|(index, row)| row.order == index as u64 + 1));
    assert!(boundaries
        .iter()
        .all(|row| row.expected_registry_occurrences == 1));
    assert!(boundaries
        .iter()
        .all(|row| matches!(row.owner.as_str(), "portable" | "coordinator")));

    let repeated = boundaries
        .iter()
        .filter(|row| row.multiplicity != "unit")
        .map(|row| {
            (
                row.multiplicity.as_str(),
                occurrence_count_v1(row),
                row.prepared_success_occurrences,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        repeated,
        vec![
            ("preliminary-groups", 12, 12),
            ("final-guards", 10, 10),
            ("final-groups", 12, 12),
            ("commit-members", 8, 8),
            ("material-packages", CONTROLLED_MATERIAL_PACKAGES, 0),
            ("retirement-tombstones", CONTROLLED_RETIREMENT_TOMBSTONES, 0,),
            ("restore-packages", CONTROLLED_RESTORE_PACKAGES, 0),
        ]
    );

    let matrix = crash_matrix_v1();
    assert_eq!(matrix.len(), EXPECTED_MATRIX_CASES);
    assert_eq!(
        phase_counts_v1(&matrix),
        BTreeMap::from([
            ("acknowledgement-and-readback".into(), 12),
            ("backup".into(), 26),
            ("final-comparison".into(), 34),
            ("known-failure".into(), 12),
            ("positive-coordinator-commit".into(), 22),
            ("preliminary".into(), 21),
            ("quarantine-and-retirement".into(), 10),
            ("recovery".into(), 13),
            ("restore".into(), 17),
        ])
    );
    assert_eq!(
        matrix
            .iter()
            .filter(|case| case.boundary_id == "preliminary_first_failure_group_classified")
            .map(|case| case.occurrence)
            .collect::<Vec<_>>(),
        (1..=12).collect::<Vec<_>>()
    );
    assert_eq!(
        matrix
            .iter()
            .filter(|case| case.boundary_id == "final_comparison_guard_acquired")
            .map(|case| case.occurrence)
            .collect::<Vec<_>>(),
        (1..=10).collect::<Vec<_>>()
    );
    assert_eq!(
        matrix
            .iter()
            .filter(|case| case.boundary_id == "final_comparison_first_failure_group_classified")
            .map(|case| case.occurrence)
            .collect::<Vec<_>>(),
        (1..=12).collect::<Vec<_>>()
    );
    assert_eq!(
        matrix
            .iter()
            .filter(|case| case.boundary_id == "positive_coordinator_commit_member_staged")
            .map(|case| case.occurrence)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
}

#[test]
fn t074_process_router_partition_is_explicit_v1() {
    let boundaries = decode_boundaries_v1();
    let mut supported_boundary_count = 0_usize;
    let mut supported_case_count = 0_u64;
    let mut unsupported_boundary_ids = Vec::new();

    for row in &boundaries {
        if process_router_supports_v1(row) {
            supported_boundary_count += 1;
            supported_case_count += occurrence_count_v1(row);
        } else {
            unsupported_boundary_ids.push(row.boundary_id.as_str());
        }
    }

    assert_eq!(supported_boundary_count, 123);
    assert_eq!(supported_case_count, 167);
    assert!(unsupported_boundary_ids.is_empty());
}

#[test]
fn t086_release_process_kill_partition_matches_production_platform_contract_v1() {
    let boundaries = decode_boundaries_v1();
    let matrix = crash_matrix_v1();
    let restore_boundary_ids = boundaries
        .iter()
        .filter(|row| row.phase == "restore")
        .map(|row| row.boundary_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        restore_boundary_ids,
        WINDOWS_PRODUCTION_UNREACHABLE_RESTORE_BOUNDARY_IDS_V1
    );

    let reachable = matrix
        .iter()
        .filter(|case| release_process_kill_case_is_reachable_v1(case))
        .collect::<Vec<_>>();
    let unreachable = matrix
        .iter()
        .filter(|case| !release_process_kill_case_is_reachable_v1(case))
        .collect::<Vec<_>>();

    if cfg!(windows) {
        assert_eq!(reachable.len(), 150);
        assert_eq!(unreachable.len(), 17);
        assert!(unreachable.iter().all(|case| case.phase == "restore"));
        assert_eq!(
            unreachable
                .iter()
                .map(|case| case.boundary_id.as_str())
                .collect::<BTreeSet<_>>(),
            WINDOWS_PRODUCTION_UNREACHABLE_RESTORE_BOUNDARY_IDS_V1
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            unreachable
                .iter()
                .filter(|case| case.boundary_id == "restore_recovery_package_imported")
                .map(|case| case.occurrence)
                .collect::<Vec<_>>(),
            (1..=CONTROLLED_RESTORE_PACKAGES).collect::<Vec<_>>()
        );
    } else {
        assert_eq!(reachable.len(), EXPECTED_MATRIX_CASES);
        assert!(unreachable.is_empty());
    }
}

struct ProbeRootV1 {
    path: PathBuf,
}

impl ProbeRootV1 {
    fn new_v1() -> Self {
        for _ in 0..64 {
            let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let candidate = std::env::temp_dir().join(format!(
                "helixos-t062-process-crash-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    let path = fs::canonicalize(candidate)
                        .expect("T062 private process root canonicalizes");
                    return Self { path };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("T062 private process root creation failed"),
            }
        }
        panic!("T062 private process root allocation exhausted")
    }

    fn marker_v1(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for ProbeRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn t074_isolated_fixtures_prepare_before_ready_v1() {
    for (boundary_id, phase, expected_state) in [
        (
            "recovery_publication_guard_acquired",
            "recovery",
            Some(b"absent".as_slice()),
        ),
        (
            "quarantine_and_retirement_quarantine_inserted",
            "quarantine-and-retirement",
            None,
        ),
        (
            "positive_coordinator_commit_permit_resolved_aborted",
            "positive-coordinator-commit",
            Some(b"absent".as_slice()),
        ),
        (
            "acknowledgement_uncertain_connection_closed",
            "acknowledgement-and-readback",
            Some(b"preparing".as_slice()),
        ),
        (
            "known_failure_no_dispatch_guard_acquired",
            "known-failure",
            Some(b"preparing".as_slice()),
        ),
        (
            "known_failure_begin_immediate_acquired",
            "known-failure",
            Some(b"preparing".as_slice()),
        ),
    ] {
        let root = ProbeRootV1::new_v1();
        let protocol = T074RouterChildProtocolV1 {
            root: root.path.clone(),
            boundary_id: boundary_id.to_owned(),
            occurrence: 1,
            phase: phase.to_owned(),
        };
        let workflow = protocol
            .isolated_workflow_v1()
            .expect("T074 isolated workflow selects");
        workflow
            .prepare_fixture_v1(&protocol)
            .expect("T074 isolated fixture prepares before READY");
        if let Some(expected_state) = expected_state {
            assert_eq!(
                workflow
                    .reopen_state_v1(&protocol)
                    .expect("T074 isolated fixture reopens"),
                expected_state
            );
        }
    }
}

fn private_environment_v1(root: &ProbeRootV1, case: &CrashCaseV1) -> [(&'static str, OsString); 7] {
    [
        (PROTOCOL_ROOT_ENV, root.path.as_os_str().to_owned()),
        (BOUNDARY_ID_ENV, OsString::from(&case.boundary_id)),
        (
            BOUNDARY_OCCURRENCE_ENV,
            OsString::from(case.occurrence.to_string()),
        ),
        (BOUNDARY_PHASE_ENV, OsString::from(&case.phase)),
        (
            MATERIAL_PACKAGES_ENV,
            OsString::from(CONTROLLED_MATERIAL_PACKAGES.to_string()),
        ),
        (
            RETIREMENT_TOMBSTONES_ENV,
            OsString::from(CONTROLLED_RETIREMENT_TOMBSTONES.to_string()),
        ),
        (
            RESTORE_PACKAGES_ENV,
            OsString::from(CONTROLLED_RESTORE_PACKAGES.to_string()),
        ),
    ]
}

fn spawn_child_v1(exact_test_name: &str, environment: &[(&'static str, OsString)]) -> Child {
    let executable = std::env::current_exe().expect("T062 integration-test executable exists");
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(exact_test_name)
        .arg("--ignored")
        .arg("--nocapture")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in environment {
        command.env(name, value);
    }
    command.spawn().expect("T062 private child spawns")
}

fn wait_for_marker_v1(child: &mut Child, marker: &Path, stage: &str) {
    let deadline = Instant::now() + PROTOCOL_TIMEOUT;
    loop {
        if marker.is_file() {
            return;
        }
        if child
            .try_wait()
            .expect("T062 child status remains observable")
            .is_some()
        {
            panic!("T062 child exited before {stage}");
        }
        assert!(
            Instant::now() < deadline,
            "T062 child timed out before {stage}"
        );
        thread::sleep(PROTOCOL_POLL);
    }
}

fn wait_for_success_v1(child: &mut Child, stage: &str) {
    let deadline = Instant::now() + PROTOCOL_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .expect("T062 child status remains observable")
        {
            assert!(status.success(), "T062 child failed during {stage}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "T062 child timed out during {stage}"
        );
        thread::sleep(PROTOCOL_POLL);
    }
}

fn assert_t074_process_drivers_exist_v1() {
    let _: fn() = process_crash_fault_router_child_v1;
    let _: fn() = process_crash_reopen_router_child_v1;
    let _: fn() = common::process_probe::tests::process_crash_fault_child_v1;
    let _: fn() = common::process_probe::tests::process_crash_reopen_child_v1;
    assert!(
        !PROCESS_PROBE_SOURCE.contains("for current in 1..=protocol.occurrence"),
        "T074 RED: the fault child must cross the selected checkpoint from a production workflow, not replay a registry-only checkpoint loop"
    );
    for required in [
        "fn process_crash_fault_child_v1",
        "fn process_crash_reopen_child_v1",
        "fn run_selected_production_workflow_v1",
        BOUNDARY_REACHED_MARKER,
        REOPEN_RESULT_MARKER,
        "FaultSessionV1",
        "ProcessBarrier",
    ] {
        assert!(
            PROCESS_PROBE_SOURCE.contains(required),
            "T074 RED: common/process_probe.rs must provide {required} using an explicitly carried private session"
        );
    }
    assert!(
        t074_recovery::supports_boundary_v1("recovery_publication_guard_acquired")
            && t074_quarantine::supports_boundary_v1(
                "quarantine_and_retirement_quarantine_inserted"
            )
            && T074_TRANSACTION_BOUNDARY_IDS_V1
                .iter()
                .all(|boundary_id| t074_transactions::supports_boundary_v1(boundary_id))
            && t074_transactions::SUPPORTED_BOUNDARY_IDS_V1.as_slice()
                == T074_TRANSACTION_BOUNDARY_IDS_V1,
        "T074 RED: the isolated process router must carry recovery, quarantine and all 21 transaction workflows"
    );
}

fn run_kill_and_reopen_case_v1(case: &CrashCaseV1) {
    let root = ProbeRootV1::new_v1();
    let environment = private_environment_v1(&root, case);
    let mut fault_child = spawn_child_v1(FAULT_CHILD_TEST_V1, &environment);
    wait_for_marker_v1(&mut fault_child, &root.marker_v1(READY_MARKER), "READY");
    fs::write(root.marker_v1(GO_MARKER), b"go").expect("T062 GO publishes");
    let selected_stage = format!(
        "the exact selected boundary occurrence {}#{}",
        case.boundary_id, case.occurrence
    );
    wait_for_marker_v1(
        &mut fault_child,
        &root.marker_v1(BOUNDARY_REACHED_MARKER),
        &selected_stage,
    );

    fault_child.kill().expect("T062 selected child terminates");
    let _ = fault_child.wait().expect("T062 selected child is reaped");

    let mut reopen_child = spawn_child_v1(REOPEN_CHILD_TEST_V1, &environment);
    wait_for_marker_v1(
        &mut reopen_child,
        &root.marker_v1(REOPEN_RESULT_MARKER),
        "closed reopen classification",
    );
    wait_for_success_v1(&mut reopen_child, "reopen verification");
    let result =
        fs::read(root.marker_v1(REOPEN_RESULT_MARKER)).expect("T062 closed reopen result reads");
    assert!(
        !result.is_empty() && result.len() <= MAX_REOPEN_RESULT_BYTES,
        "T062 reopen result remains bounded"
    );
    assert!(
        CLOSED_REOPEN_STATES.contains(&result.as_slice()),
        "T062 reopen must classify only absence, coherent PREPARING, atomic FAILED, or quarantine"
    );
}

#[test]
#[ignore = "private T074 fault router child; invoked only by the release process-kill parent"]
fn process_crash_fault_router_child_v1() {
    let Some(protocol) = T074RouterChildProtocolV1::from_environment_v1()
        .expect("T074 private router protocol validates")
    else {
        return;
    };
    let Some(workflow) = protocol.isolated_workflow_v1() else {
        common::process_probe::tests::process_crash_fault_child_v1();
        return;
    };

    workflow
        .prepare_fixture_v1(&protocol)
        .expect("T074 isolated fixture prepares before READY");
    protocol
        .publish_ready_and_wait_for_go_v1()
        .expect("T074 isolated READY/GO protocol validates");
    workflow
        .run_boundary_v1(&protocol, protocol.process_barrier_v1())
        .expect("T074 isolated production workflow reaches selected boundary");
    panic!("T074 isolated workflow returned without its process barrier")
}

#[test]
#[ignore = "private T074 reopen router child; invoked only by the release process-kill parent"]
fn process_crash_reopen_router_child_v1() {
    let Some(protocol) = T074RouterChildProtocolV1::from_environment_v1()
        .expect("T074 private reopen router protocol validates")
    else {
        return;
    };
    let Some(workflow) = protocol.isolated_workflow_v1() else {
        common::process_probe::tests::process_crash_reopen_child_v1();
        return;
    };

    let state = workflow
        .reopen_state_v1(&protocol)
        .expect("T074 isolated workflow reopens to a closed state");
    protocol
        .publish_reopen_result_v1(state)
        .expect("T074 isolated reopen state publishes");
}

#[test]
#[ignore = "release-only exhaustive process-kill/fault-injection matrix; requires T074 child drivers"]
fn release_process_kill_matrix_reopens_to_one_closed_state() {
    // This preflight makes the tests-first RED immediate and legible. It intentionally
    // precedes process creation so an absent T074 driver cannot turn into 30-second
    // protocol timeouts or a fake checkpoint.
    assert_t074_process_drivers_exist_v1();

    let matrix = crash_matrix_v1();
    assert_eq!(matrix.len(), EXPECTED_MATRIX_CASES);
    let reachable_case_count = matrix
        .iter()
        .filter(|case| release_process_kill_case_is_reachable_v1(case))
        .count();
    assert_eq!(
        reachable_case_count,
        if cfg!(windows) {
            150
        } else {
            EXPECTED_MATRIX_CASES
        }
    );
    for case in matrix
        .iter()
        .filter(|case| release_process_kill_case_is_reachable_v1(case))
    {
        run_kill_and_reopen_case_v1(case);
    }
}
