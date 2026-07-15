//! PLAN-005 migration, backup, and restore fault evidence (FB072-FB090).
//!
//! The release-only process gate re-executes this integration binary, carries one
//! explicit caller-owned process barrier through the real lifecycle workflow, kills
//! the blocked child, and delegates durable verification to a separate reopen child.
//! This is synthetic process-kill evidence, not physical power-loss evidence.

#![cfg(feature = "test-fault-injection")]

mod common;

use common::process_probe::{
    private_process_argument_v1, ProcessProbeChildV1, ProcessProbeEnvironmentV1,
    SynchronizedProcessProbeV1,
};
use helix_coordinator_sqlite::{
    resume_t070_dispatch_lifecycle_fault_recovery_for_test_v1,
    run_t070_dispatch_lifecycle_fault_probe_for_test_v1,
    run_t070_migration_fault_probe_for_test_v1,
    verify_t070_dispatch_lifecycle_fault_readback_for_test_v1,
    verify_t070_migration_fault_readback_for_test_v1,
};
use helix_plan_dispatch::FaultInjectionModeV1;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

const REGISTRY_BYTES: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/contracts/fault-boundaries-v1.json");
const REQUIRED_BOUNDARY_COUNT: usize = 90;
const REQUIRED_CASE_COUNT: usize = 180;
const COORDINATOR_DISPATCH_BOUNDARY_COUNT: usize = 54;
const ADAPTER_DISPATCH_BOUNDARY_COUNT: usize = 17;
const LIFECYCLE_BOUNDARY_COUNT: usize = 19;
const PROCESS_CHILD_TEST_V1: &str = "dispatch_lifecycle_fault_process_child_v1";
const REOPEN_CHILD_TEST_V1: &str = "dispatch_lifecycle_fault_reopen_child_v1";
const RECOVERY_CHILD_TEST_V1: &str = "dispatch_lifecycle_fault_recovery_child_v1";
const PROCESS_CASE_ROOT_ENV: &str = "HELIXOS_T070_LIFECYCLE_CASE_ROOT";
const PROCESS_BOUNDARY_ID_ENV: &str = "HELIXOS_T070_LIFECYCLE_BOUNDARY_ID";
const BOUNDARY_REACHED_TOKEN: &[u8] = b"boundary-reached";
const DURABLE_READBACK_TOKEN: &[u8] = b"durable-readback";
const IDEMPOTENT_RECOVERY_TOKEN: &[u8] = b"idempotent-recovery";
static PROCESS_CASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
struct RegistryV1 {
    boundary_count: usize,
    required_case_count: usize,
    coverage_modes: Vec<String>,
    boundaries: Vec<BoundaryV1>,
}

#[derive(Clone, Debug, Deserialize)]
struct BoundaryV1 {
    ordinal: usize,
    id: String,
    category: String,
    owner: String,
    phase: String,
    expected_class: String,
    coverage: Vec<String>,
}

fn registry_v1() -> RegistryV1 {
    serde_json::from_slice(REGISTRY_BYTES).expect("T070 frozen lifecycle registry parses")
}

fn lifecycle_boundaries_v1(registry: &RegistryV1) -> Vec<&BoundaryV1> {
    registry
        .boundaries
        .iter()
        .filter(|boundary| (72..=90).contains(&boundary.ordinal))
        .collect()
}

fn lifecycle_boundary_v1(ordinal: usize) -> BoundaryV1 {
    registry_v1()
        .boundaries
        .into_iter()
        .find(|boundary| boundary.ordinal == ordinal)
        .unwrap_or_else(|| panic!("missing frozen lifecycle boundary {ordinal}"))
}

struct ProcessCaseRootV1 {
    path: PathBuf,
}

impl ProcessCaseRootV1 {
    fn new_v1() -> Self {
        for _ in 0..64 {
            let sequence = PROCESS_CASE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let candidate = std::env::temp_dir().join(format!(
                "helixos-t070-lifecycle-process-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    return Self {
                        path: fs::canonicalize(candidate)
                            .expect("T070 lifecycle case root canonicalizes"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("T070 lifecycle case root creation failed: {error}"),
            }
        }
        panic!("T070 lifecycle case root allocation exhausted")
    }

    fn environment_v1(&self, boundary_id: &str) -> [ProcessProbeEnvironmentV1; 2] {
        [
            ProcessProbeEnvironmentV1::new(PROCESS_CASE_ROOT_ENV, self.path.as_os_str().to_owned()),
            ProcessProbeEnvironmentV1::new(PROCESS_BOUNDARY_ID_ENV, boundary_id),
        ]
    }
}

impl Drop for ProcessCaseRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn prepare_in_process_lifecycle_case_v1(ordinal: usize) -> ProcessCaseRootV1 {
    let boundary = lifecycle_boundary_v1(ordinal);
    let case = ProcessCaseRootV1::new_v1();
    run_lifecycle_case_v1(
        &boundary,
        &case.path,
        FaultInjectionModeV1::InProcess,
        || Ok(()),
        || {},
    )
    .unwrap_or_else(|error| panic!("{} fixture failed: {error}", boundary.id));
    case
}

fn restore_authority_path_v1(root: &Path) -> PathBuf {
    root.join("dispatch-restore-authority-v1")
        .join("pause-rotation-v1.json")
}

fn case_tree_snapshot_v1(root: &Path) -> Vec<(PathBuf, bool, Vec<u8>)> {
    fn visit_v1(root: &Path, current: &Path, output: &mut Vec<(PathBuf, bool, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .expect("case snapshot directory reads")
            .map(|entry| entry.expect("case snapshot entry reads"))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("case snapshot metadata reads");
            assert!(!metadata.file_type().is_symlink());
            let relative = path
                .strip_prefix(root)
                .expect("case snapshot stays below its root")
                .to_path_buf();
            if metadata.is_dir() {
                output.push((relative, true, Vec::new()));
                visit_v1(root, &path, output);
            } else {
                assert!(metadata.is_file());
                output.push((
                    relative,
                    false,
                    fs::read(path).expect("case snapshot file reads"),
                ));
            }
        }
    }

    let mut output = Vec::new();
    visit_v1(root, root, &mut output);
    output
}

struct ProcessCaseProtocolV1 {
    root: PathBuf,
    boundary_id: String,
    ordinal: usize,
}

impl ProcessCaseProtocolV1 {
    fn from_environment_v1() -> Option<Self> {
        let root = PathBuf::from(private_process_argument_v1(PROCESS_CASE_ROOT_ENV)?);
        let metadata = fs::symlink_metadata(&root).ok()?;
        assert!(root.is_absolute());
        assert!(!metadata.file_type().is_symlink() && metadata.is_dir());
        let boundary_id = private_process_argument_v1(PROCESS_BOUNDARY_ID_ENV)?
            .into_string()
            .expect("T070 lifecycle boundary ID is UTF-8");
        let registry = registry_v1();
        let boundary = lifecycle_boundaries_v1(&registry)
            .into_iter()
            .find(|boundary| boundary.id == boundary_id)
            .expect("T070 lifecycle child accepts only FB072-FB090");
        Some(Self {
            root,
            boundary_id,
            ordinal: boundary.ordinal,
        })
    }
}

fn run_lifecycle_case_v1<F, G>(
    boundary: &BoundaryV1,
    root: &Path,
    mode: FaultInjectionModeV1,
    workflow_ready: F,
    process_barrier: G,
) -> Result<(), &'static str>
where
    F: FnOnce() -> Result<(), &'static str>,
    G: FnMut() + Send + 'static,
{
    if (72..=76).contains(&boundary.ordinal) {
        run_t070_migration_fault_probe_for_test_v1(
            &boundary.id,
            1,
            mode,
            root.to_path_buf(),
            workflow_ready,
            process_barrier,
        )
    } else {
        run_t070_dispatch_lifecycle_fault_probe_for_test_v1(
            &boundary.id,
            1,
            mode,
            root.to_path_buf(),
            workflow_ready,
            process_barrier,
        )
    }
}

fn verify_lifecycle_case_v1(boundary: &BoundaryV1, root: &Path) -> Result<(), &'static str> {
    if (72..=76).contains(&boundary.ordinal) {
        verify_t070_migration_fault_readback_for_test_v1(&boundary.id, root.to_path_buf())
    } else {
        verify_t070_dispatch_lifecycle_fault_readback_for_test_v1(&boundary.id, root.to_path_buf())
    }
}

#[test]
#[ignore = "private synchronized PLAN-005 lifecycle process-kill child"]
fn dispatch_lifecycle_fault_process_child_v1() {
    let Some(child) = ProcessProbeChildV1::from_environment_v1()
        .expect("T070 lifecycle process child protocol validates")
    else {
        return;
    };
    assert_eq!(child.index_v1(), 0);
    let protocol = ProcessCaseProtocolV1::from_environment_v1()
        .expect("T070 lifecycle process child receives an exact private case");
    let registry = registry_v1();
    let boundary = lifecycle_boundaries_v1(&registry)
        .into_iter()
        .find(|boundary| boundary.ordinal == protocol.ordinal)
        .expect("T070 lifecycle process boundary remains frozen");

    let ready_child = child.clone();
    let barrier_child = child.clone();
    let result = run_lifecycle_case_v1(
        boundary,
        &protocol.root,
        FaultInjectionModeV1::ProcessKill,
        move || {
            ready_child
                .publish_ready_and_wait_for_go_v1()
                .map_err(|_| "lifecycle-process-ready-failed")
        },
        move || {
            barrier_child
                .publish_result_v1(BOUNDARY_REACHED_TOKEN)
                .expect("T070 lifecycle checkpoint publishes before termination");
            loop {
                thread::park();
            }
        },
    );
    panic!(
        "T070 lifecycle process child returned before kill at {}: {result:?}",
        protocol.boundary_id
    );
}

#[test]
#[ignore = "private authoritative PLAN-005 lifecycle reopen child"]
fn dispatch_lifecycle_fault_reopen_child_v1() {
    let Some(child) = ProcessProbeChildV1::from_environment_v1()
        .expect("T070 lifecycle reopen child protocol validates")
    else {
        return;
    };
    assert_eq!(child.index_v1(), 0);
    let protocol = ProcessCaseProtocolV1::from_environment_v1()
        .expect("T070 lifecycle reopen child receives an exact private case");
    let registry = registry_v1();
    let boundary = lifecycle_boundaries_v1(&registry)
        .into_iter()
        .find(|boundary| boundary.ordinal == protocol.ordinal)
        .expect("T070 lifecycle reopen boundary remains frozen");

    child
        .publish_ready_and_wait_for_go_v1()
        .expect("T070 lifecycle reopen child synchronizes before strict readback");
    verify_lifecycle_case_v1(boundary, &protocol.root)
        .expect("T070 lifecycle durable readback satisfies its exact oracle");
    child
        .publish_result_v1(DURABLE_READBACK_TOKEN)
        .expect("T070 lifecycle reopen child publishes one closed result");
}

#[test]
#[ignore = "private mutating PLAN-005 lifecycle recovery child"]
fn dispatch_lifecycle_fault_recovery_child_v1() {
    let Some(child) = ProcessProbeChildV1::from_environment_v1()
        .expect("T070 lifecycle recovery child protocol validates")
    else {
        return;
    };
    assert_eq!(child.index_v1(), 0);
    let protocol = ProcessCaseProtocolV1::from_environment_v1()
        .expect("T070 lifecycle recovery child receives an exact private case");
    assert!(
        (84..=90).contains(&protocol.ordinal),
        "only restore boundaries have a mutating recovery phase"
    );

    child
        .publish_ready_and_wait_for_go_v1()
        .expect("T070 lifecycle recovery child synchronizes after strict readback");
    resume_t070_dispatch_lifecycle_fault_recovery_for_test_v1(&protocol.boundary_id, protocol.root)
        .expect("T070 lifecycle recovery is exact and idempotent");
    child
        .publish_result_v1(IDEMPOTENT_RECOVERY_TOKEN)
        .expect("T070 lifecycle recovery child publishes one closed result");
}

#[test]
fn frozen_primary_ledger_is_exactly_90_boundaries_and_180_unique_cases() {
    let registry = registry_v1();
    assert_eq!(registry.boundary_count, REQUIRED_BOUNDARY_COUNT);
    assert_eq!(registry.required_case_count, REQUIRED_CASE_COUNT);
    assert_eq!(registry.boundaries.len(), REQUIRED_BOUNDARY_COUNT);
    assert_eq!(registry.coverage_modes, ["in-process", "process-kill"]);

    let mut ids = BTreeSet::new();
    let mut cases = BTreeSet::new();
    for (index, boundary) in registry.boundaries.iter().enumerate() {
        assert_eq!(boundary.ordinal, index + 1);
        assert_eq!(boundary.id, format!("PLAN005-FB-{:03}", index + 1));
        assert!(ids.insert(boundary.id.clone()));
        assert!(!boundary.category.is_empty());
        assert!(!boundary.owner.is_empty());
        assert!(!boundary.phase.is_empty());
        assert!(!boundary.expected_class.is_empty());
        assert_eq!(boundary.coverage, registry.coverage_modes);
        for mode in &boundary.coverage {
            assert!(cases.insert(format!("{}::{mode}", boundary.id)));
        }
    }
    assert_eq!(ids.len(), REQUIRED_BOUNDARY_COUNT);
    assert_eq!(cases.len(), REQUIRED_CASE_COUNT);

    let coordinator = registry
        .boundaries
        .iter()
        .filter(|boundary| {
            (1..=22).contains(&boundary.ordinal) || (40..=71).contains(&boundary.ordinal)
        })
        .map(|boundary| boundary.id.clone())
        .collect::<BTreeSet<_>>();
    let adapter = registry
        .boundaries
        .iter()
        .filter(|boundary| (23..=39).contains(&boundary.ordinal))
        .map(|boundary| boundary.id.clone())
        .collect::<BTreeSet<_>>();
    let lifecycle = lifecycle_boundaries_v1(&registry)
        .into_iter()
        .map(|boundary| boundary.id.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(coordinator.len(), COORDINATOR_DISPATCH_BOUNDARY_COUNT);
    assert_eq!(adapter.len(), ADAPTER_DISPATCH_BOUNDARY_COUNT);
    assert_eq!(lifecycle.len(), LIFECYCLE_BOUNDARY_COUNT);
    assert!(coordinator.is_disjoint(&adapter));
    assert!(coordinator.is_disjoint(&lifecycle));
    assert!(adapter.is_disjoint(&lifecycle));
    let mut primary_partition = coordinator;
    primary_partition.extend(adapter);
    primary_partition.extend(lifecycle);
    assert_eq!(primary_partition.len(), REQUIRED_BOUNDARY_COUNT);
}

#[test]
fn fb084_precedes_identity_authority_and_strict_readback_is_non_mutating() {
    let fb084 = prepare_in_process_lifecycle_case_v1(84);
    assert!(
        !restore_authority_path_v1(&fb084.path).exists(),
        "FB084 must precede every persisted replacement identity"
    );
    let before_fb084 = case_tree_snapshot_v1(&fb084.path);
    verify_t070_dispatch_lifecycle_fault_readback_for_test_v1("PLAN005-FB-084", fb084.path.clone())
        .expect("FB084 strict readback succeeds");
    assert_eq!(
        case_tree_snapshot_v1(&fb084.path),
        before_fb084,
        "strict FB084 readback must not perform recovery writes"
    );

    let fb085 = prepare_in_process_lifecycle_case_v1(85);
    assert!(
        restore_authority_path_v1(&fb085.path).is_file(),
        "FB085 must follow durable replacement-identity publication"
    );
    let before_fb085 = case_tree_snapshot_v1(&fb085.path);
    verify_t070_dispatch_lifecycle_fault_readback_for_test_v1("PLAN005-FB-085", fb085.path.clone())
        .expect("FB085 strict readback succeeds");
    assert_eq!(
        case_tree_snapshot_v1(&fb085.path),
        before_fb085,
        "strict FB085 readback must not perform recovery writes"
    );
}

#[test]
fn canonical_authority_identity_substitution_is_rejected() {
    for (member, replacement) in [
        ("new_coordinator_root_identity", 0xa1_u8),
        ("new_adapter_root_identity", 0xa2),
        ("new_boot_identity", 0xa3),
        ("new_instance_identity", 0xa4),
        ("new_supervisor_identity", 0xa5),
    ] {
        let case = prepare_in_process_lifecycle_case_v1(85);
        let authority_path = restore_authority_path_v1(&case.path);
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&authority_path).expect("authority fixture reads"))
                .expect("authority fixture parses");
        record[member] = serde_json::Value::Array(vec![replacement.into(); 32]);
        let substituted =
            serde_json_canonicalizer::to_vec(&record).expect("substituted authority canonicalizes");
        fs::write(&authority_path, substituted).expect("substituted authority writes");

        assert!(
            verify_t070_dispatch_lifecycle_fault_readback_for_test_v1(
                "PLAN005-FB-085",
                case.path.clone(),
            )
            .is_err(),
            "canonical substitution of {member} must not become restore authority"
        );
    }
}

#[test]
fn noncanonical_authority_is_rejected_before_recovery() {
    let case = prepare_in_process_lifecycle_case_v1(85);
    let authority_path = restore_authority_path_v1(&case.path);
    let mut bytes = fs::read(&authority_path).expect("authority fixture reads");
    bytes.push(b'\n');
    fs::write(&authority_path, bytes).expect("noncanonical authority writes");
    assert!(
        verify_t070_dispatch_lifecycle_fault_readback_for_test_v1(
            "PLAN005-FB-085",
            case.path.clone(),
        )
        .is_err(),
        "noncanonical authority must fail before any retry"
    );
}

#[test]
#[ignore = "release in-process gate: drive FB072-FB090 through real migration, backup, and restore workflows"]
fn release_dispatch_lifecycle_in_process_matrix() {
    let registry = registry_v1();
    let selected = lifecycle_boundaries_v1(&registry);
    assert_eq!(selected.len(), LIFECYCLE_BOUNDARY_COUNT);
    for boundary in selected {
        let case = ProcessCaseRootV1::new_v1();
        run_lifecycle_case_v1(
            boundary,
            &case.path,
            FaultInjectionModeV1::InProcess,
            || Ok(()),
            || {},
        )
        .unwrap_or_else(|error| {
            panic!(
                "T070 in-process lifecycle case {} failed: {error}",
                boundary.id
            )
        });
        verify_lifecycle_case_v1(boundary, &case.path).unwrap_or_else(|error| {
            panic!(
                "T070 in-process lifecycle readback {} failed: {error}",
                boundary.id
            )
        });
        if boundary.ordinal >= 84 {
            resume_t070_dispatch_lifecycle_fault_recovery_for_test_v1(
                &boundary.id,
                case.path.clone(),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "T070 in-process lifecycle recovery {} failed: {error}",
                    boundary.id
                )
            });
        }
    }
}

#[test]
#[ignore = "release process-kill gate: drive FB072-FB090 through real workflows and a separate strict reopen child"]
fn release_dispatch_lifecycle_process_kill_matrix() {
    let registry = registry_v1();
    let selected = lifecycle_boundaries_v1(&registry);
    assert_eq!(selected.len(), LIFECYCLE_BOUNDARY_COUNT);

    for boundary in selected {
        let case = ProcessCaseRootV1::new_v1();
        let environment = case.environment_v1(&boundary.id);
        let mut fault =
            SynchronizedProcessProbeV1::spawn_v1(PROCESS_CHILD_TEST_V1, 1, &environment)
                .expect("T070 lifecycle production fault child spawns");
        assert_eq!(
            fault
                .execute_until_result_and_terminate_v1()
                .unwrap_or_else(|error| {
                    panic!(
                        "T070 lifecycle fault child {} failed before its checkpoint: {error:?}",
                        boundary.id
                    )
                }),
            [BOUNDARY_REACHED_TOKEN.to_vec()],
            "{} publishes only after its real lifecycle checkpoint",
            boundary.id,
        );

        let mut reopen =
            SynchronizedProcessProbeV1::spawn_v1(REOPEN_CHILD_TEST_V1, 1, &environment)
                .expect("T070 lifecycle authoritative reopen child spawns");
        assert_eq!(
            reopen.execute_v1().unwrap_or_else(|error| {
                panic!(
                    "T070 lifecycle reopen child {} failed: {error:?}",
                    boundary.id
                )
            }),
            [DURABLE_READBACK_TOKEN.to_vec()],
            "{} satisfies its durable lifecycle oracle",
            boundary.id,
        );

        if boundary.ordinal >= 84 {
            let mut recovery =
                SynchronizedProcessProbeV1::spawn_v1(RECOVERY_CHILD_TEST_V1, 1, &environment)
                    .expect("T070 lifecycle explicit recovery child spawns");
            assert_eq!(
                recovery.execute_v1().unwrap_or_else(|error| {
                    panic!(
                        "T070 lifecycle recovery child {} failed: {error:?}",
                        boundary.id
                    )
                }),
                [IDEMPOTENT_RECOVERY_TOKEN.to_vec()],
                "{} recovers only after strict readback and retries exactly",
                boundary.id,
            );
        }
    }
}
