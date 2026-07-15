//! Private cross-process coordinator probe.
//!
//! The parent re-executes the current integration-test binary and owns every child,
//! READY/GO marker and result file. Native paths are transported only through private
//! environment values and are never included in diagnostics.

#![allow(dead_code)]

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const PROBE_ROOT_ENV: &str = "HELIXOS_COORDINATOR_PROCESS_PROBE_ROOT";
const PROBE_INDEX_ENV: &str = "HELIXOS_COORDINATOR_PROCESS_PROBE_INDEX";
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(30);
const PROTOCOL_POLL: Duration = Duration::from_millis(2);
const MAX_RESULT_BYTES: usize = 64;
static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessProbeErrorV1 {
    InvalidInput,
    ExecutableUnavailable,
    RootCreateFailed,
    SpawnFailed,
    ProtocolFailed,
    TimedOut,
    ChildFailed,
    ResultInvalid,
}

impl ProcessProbeErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "PROCESS_PROBE_INVALID_INPUT",
            Self::ExecutableUnavailable => "PROCESS_PROBE_EXECUTABLE_UNAVAILABLE",
            Self::RootCreateFailed => "PROCESS_PROBE_ROOT_CREATE_FAILED",
            Self::SpawnFailed => "PROCESS_PROBE_SPAWN_FAILED",
            Self::ProtocolFailed => "PROCESS_PROBE_PROTOCOL_FAILED",
            Self::TimedOut => "PROCESS_PROBE_TIMED_OUT",
            Self::ChildFailed => "PROCESS_PROBE_CHILD_FAILED",
            Self::ResultInvalid => "PROCESS_PROBE_RESULT_INVALID",
        }
    }
}

impl fmt::Debug for ProcessProbeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

#[derive(Clone)]
pub(crate) struct ProcessProbeEnvironmentV1 {
    name: &'static str,
    value: OsString,
}

impl ProcessProbeEnvironmentV1 {
    pub(crate) fn new(name: &'static str, value: impl Into<OsString>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }
}

impl fmt::Debug for ProcessProbeEnvironmentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessProbeEnvironmentV1")
            .finish_non_exhaustive()
    }
}

pub(crate) struct SynchronizedProcessProbeV1 {
    root: PathBuf,
    children: Vec<Child>,
    contender_count: usize,
}

impl SynchronizedProcessProbeV1 {
    pub(crate) fn spawn_v1(
        exact_test_name: &str,
        contender_count: usize,
        environment: &[ProcessProbeEnvironmentV1],
    ) -> Result<Self, ProcessProbeErrorV1> {
        if exact_test_name.is_empty()
            || contender_count == 0
            || environment.iter().any(|entry| {
                entry.name.is_empty() || matches!(entry.name, PROBE_ROOT_ENV | PROBE_INDEX_ENV)
            })
        {
            return Err(ProcessProbeErrorV1::InvalidInput);
        }
        let executable =
            std::env::current_exe().map_err(|_| ProcessProbeErrorV1::ExecutableUnavailable)?;
        let mut probe = Self {
            root: create_probe_root_v1()?,
            children: Vec::with_capacity(contender_count),
            contender_count,
        };
        for index in 0..contender_count {
            let mut command = Command::new(&executable);
            command
                .arg("--exact")
                .arg(exact_test_name)
                .arg("--ignored")
                .arg("--nocapture")
                .env(PROBE_ROOT_ENV, &probe.root)
                .env(PROBE_INDEX_ENV, index.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            for entry in environment {
                command.env(entry.name, &entry.value);
            }
            let child = command
                .spawn()
                .map_err(|_| ProcessProbeErrorV1::SpawnFailed)?;
            probe.children.push(child);
        }
        Ok(probe)
    }

    pub(crate) fn execute_v1(&mut self) -> Result<Vec<Vec<u8>>, ProcessProbeErrorV1> {
        self.wait_for_markers_v1("ready")?;
        fs::write(self.root.join("go"), b"go").map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        self.wait_for_markers_v1("result")?;
        self.wait_for_success_v1()?;
        (0..self.contender_count)
            .map(|index| {
                let value = fs::read(marker_path_v1(&self.root, "result", index))
                    .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
                if value.is_empty() || value.len() > MAX_RESULT_BYTES {
                    return Err(ProcessProbeErrorV1::ResultInvalid);
                }
                Ok(value)
            })
            .collect()
    }

    /// Runs until every child publishes its selected production-boundary result, then
    /// terminates and reaps the blocked children. A separate probe may subsequently
    /// reopen the durable case root supplied through the caller's private environment.
    pub(crate) fn execute_until_result_and_terminate_v1(
        &mut self,
    ) -> Result<Vec<Vec<u8>>, ProcessProbeErrorV1> {
        let result = (|| {
            self.wait_for_markers_v1("ready")?;
            fs::write(self.root.join("go"), b"go")
                .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
            self.wait_for_markers_v1("result")?;
            (0..self.contender_count)
                .map(|index| {
                    let value = fs::read(marker_path_v1(&self.root, "result", index))
                        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
                    if value.is_empty() || value.len() > MAX_RESULT_BYTES {
                        return Err(ProcessProbeErrorV1::ResultInvalid);
                    }
                    Ok(value)
                })
                .collect()
        })();
        self.terminate_and_wait_v1();
        result
    }

    fn wait_for_markers_v1(&mut self, kind: &str) -> Result<(), ProcessProbeErrorV1> {
        let deadline = Instant::now() + PROTOCOL_TIMEOUT;
        loop {
            let complete = (0..self.contender_count)
                .all(|index| marker_path_v1(&self.root, kind, index).is_file());
            if complete {
                return Ok(());
            }
            for (index, child) in self.children.iter_mut().enumerate() {
                if !marker_path_v1(&self.root, kind, index).is_file()
                    && child
                        .try_wait()
                        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?
                        .is_some()
                {
                    return Err(ProcessProbeErrorV1::ChildFailed);
                }
            }
            if Instant::now() >= deadline {
                return Err(ProcessProbeErrorV1::TimedOut);
            }
            thread::sleep(PROTOCOL_POLL);
        }
    }

    fn wait_for_success_v1(&mut self) -> Result<(), ProcessProbeErrorV1> {
        let deadline = Instant::now() + PROTOCOL_TIMEOUT;
        loop {
            let mut all_finished = true;
            for child in &mut self.children {
                match child
                    .try_wait()
                    .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?
                {
                    Some(status) if status.success() => {}
                    Some(_) => return Err(ProcessProbeErrorV1::ChildFailed),
                    None => all_finished = false,
                }
            }
            if all_finished {
                self.children.clear();
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ProcessProbeErrorV1::TimedOut);
            }
            thread::sleep(PROTOCOL_POLL);
        }
    }

    fn terminate_and_wait_v1(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.children.clear();
    }
}

impl fmt::Debug for SynchronizedProcessProbeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SynchronizedProcessProbeV1")
            .field("contender_count", &self.contender_count)
            .finish_non_exhaustive()
    }
}

impl Drop for SynchronizedProcessProbeV1 {
    fn drop(&mut self) {
        self.terminate_and_wait_v1();
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
pub(crate) struct ProcessProbeChildV1 {
    root: PathBuf,
    index: usize,
}

impl ProcessProbeChildV1 {
    pub(crate) fn from_environment_v1() -> Result<Option<Self>, ProcessProbeErrorV1> {
        let Some(root) = std::env::var_os(PROBE_ROOT_ENV) else {
            return Ok(None);
        };
        let index = std::env::var_os(PROBE_INDEX_ENV)
            .ok_or(ProcessProbeErrorV1::InvalidInput)?
            .to_string_lossy()
            .parse::<usize>()
            .map_err(|_| ProcessProbeErrorV1::InvalidInput)?;
        let root = PathBuf::from(root);
        if !root.is_dir() {
            return Err(ProcessProbeErrorV1::InvalidInput);
        }
        Ok(Some(Self { root, index }))
    }

    pub(crate) const fn index_v1(&self) -> usize {
        self.index
    }

    pub(crate) fn publish_ready_and_wait_for_go_v1(&self) -> Result<(), ProcessProbeErrorV1> {
        fs::write(marker_path_v1(&self.root, "ready", self.index), b"ready")
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let deadline = Instant::now() + PROTOCOL_TIMEOUT;
        while !self.root.join("go").is_file() {
            if Instant::now() >= deadline {
                return Err(ProcessProbeErrorV1::TimedOut);
            }
            thread::sleep(PROTOCOL_POLL);
        }
        Ok(())
    }

    pub(crate) fn publish_result_v1(&self, value: &[u8]) -> Result<(), ProcessProbeErrorV1> {
        use std::io::Write as _;

        if value.is_empty() || value.len() > MAX_RESULT_BYTES {
            return Err(ProcessProbeErrorV1::ResultInvalid);
        }
        // Publishing by `fs::write(final_path, ..)` exposes the newly-created file before
        // its bytes are complete. The polling parent can then observe a zero-length result
        // and kill an otherwise-correct boundary child. Write and sync a private marker,
        // then atomically hard-link it into the create-only protocol namespace.
        let pending = marker_path_v1(&self.root, "result-pending", self.index);
        let published = marker_path_v1(&self.root, "result", self.index);
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pending)
                .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
            file.write_all(value)
                .and_then(|()| file.sync_all())
                .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
            drop(file);
            fs::hard_link(&pending, &published).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
            let _ = fs::remove_file(&pending);
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&pending);
        }
        result
    }
}

impl fmt::Debug for ProcessProbeChildV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessProbeChildV1")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

fn create_probe_root_v1() -> Result<PathBuf, ProcessProbeErrorV1> {
    for _ in 0..64 {
        let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let candidate = std::env::temp_dir().join(format!(
            "helixos-coordinator-process-probe-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ProcessProbeErrorV1::RootCreateFailed),
        }
    }
    Err(ProcessProbeErrorV1::RootCreateFailed)
}

fn marker_path_v1(root: &Path, kind: &str, index: usize) -> PathBuf {
    root.join(format!("{kind}-{index}"))
}

pub(crate) fn private_process_argument_v1(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[cfg(feature = "test-fault-injection")]
    use ed25519_dalek::{Signer as _, SigningKey};
    #[cfg(feature = "test-fault-injection")]
    use helix_contracts::{
        decode_and_verify_plan, sign_plan_v1, AtomicityV1, BudgetInputV1, ContractError,
        Ed25519KeyResolver, Ed25519Signer, FilePreconditionInputV1, Nonce128, PlanInputV1,
        RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, ResourceRefV1,
        Result as ContractResult, RiskLevelV1, Sha256Digest,
    };
    #[cfg(feature = "test-fault-injection")]
    use helix_coordinator_sqlite::{
        run_t074_production_fault_probe_for_test_v1,
        select_t074_coordinator_fault_probe_for_test_v1, CoordinatorClockUnavailableV1,
        CoordinatorMonotonicClockV1, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
        SqliteCoordinatorStoreV1,
    };
    #[cfg(feature = "test-fault-injection")]
    use helix_plan_preparation::{
        build_controlled_benchmark_case_v1, ControlledBenchmarkCaseV1, ControlledBenchmarkClockV1,
        FaultProbeV1, ProcessBarrierV1, CONTROLLED_BENCHMARK_BOOT_ID_V1,
        CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1,
        CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1, CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
        CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1, CONTROLLED_BENCHMARK_KEY_ID_V1,
        CONTROLLED_BENCHMARK_POLICY_VERSION_V1, CONTROLLED_BENCHMARK_WORKLOAD_ID_V1,
    };
    #[cfg(feature = "test-fault-injection")]
    use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
    #[cfg(feature = "test-fault-injection")]
    use serde::Deserialize;
    #[cfg(feature = "test-fault-injection")]
    use std::io::Write as _;

    #[cfg(feature = "test-fault-injection")]
    const T062_CASES_BYTES: &[u8] =
        include_bytes!("../../../../contracts/fixtures/durable-preparation-v1/cases.json");
    #[cfg(feature = "test-fault-injection")]
    const T062_PROTOCOL_ROOT_ENV: &str = "HELIXOS_T062_PROTOCOL_ROOT";
    #[cfg(feature = "test-fault-injection")]
    const T062_BOUNDARY_ID_ENV: &str = "HELIXOS_T062_BOUNDARY_ID";
    #[cfg(feature = "test-fault-injection")]
    const T062_BOUNDARY_OCCURRENCE_ENV: &str = "HELIXOS_T062_BOUNDARY_OCCURRENCE";
    #[cfg(feature = "test-fault-injection")]
    const T062_BOUNDARY_PHASE_ENV: &str = "HELIXOS_T062_BOUNDARY_PHASE";
    #[cfg(feature = "test-fault-injection")]
    const T062_MATERIAL_PACKAGES_ENV: &str = "HELIXOS_T062_MATERIAL_PACKAGES";
    #[cfg(feature = "test-fault-injection")]
    const T062_RETIREMENT_TOMBSTONES_ENV: &str = "HELIXOS_T062_RETIREMENT_TOMBSTONES";
    #[cfg(feature = "test-fault-injection")]
    const T062_RESTORE_PACKAGES_ENV: &str = "HELIXOS_T062_RESTORE_PACKAGES";
    #[cfg(feature = "test-fault-injection")]
    const T062_READY_MARKER: &str = "ready";
    #[cfg(feature = "test-fault-injection")]
    const T062_GO_MARKER: &str = "go";
    #[cfg(feature = "test-fault-injection")]
    const T062_BOUNDARY_REACHED_MARKER: &str = "boundary-reached";
    #[cfg(feature = "test-fault-injection")]
    const T062_REOPEN_RESULT_MARKER: &str = "reopen-result";
    #[cfg(feature = "test-fault-injection")]
    const T062_COORDINATOR_ROOT_DIRECTORY: &str = "coordinator-root-v1";
    #[cfg(feature = "test-fault-injection")]
    const T062_COORDINATOR_IDENTITY_FILE: &str = "coordinator-root-identity-v1";
    #[cfg(feature = "test-fault-injection")]
    const T062_COORDINATOR_DATABASE_FILE: &str = "coordinator.sqlite3";
    #[cfg(feature = "test-fault-injection")]
    const T062_MAXIMUM_BUSY_WAIT_MS: u64 = 50;
    #[cfg(feature = "test-fault-injection")]
    const T074_PREPARATION_DEADLINE_BUDGET_MS: u64 = 60_000;
    #[cfg(feature = "test-fault-injection")]
    const T074_SIGNING_KEY_BYTES_V1: [u8; 32] = [0x42; 32];
    #[cfg(feature = "test-fault-injection")]
    const T062_CONTROLLED_MATERIAL_PACKAGES: u64 = 3;
    #[cfg(feature = "test-fault-injection")]
    const T062_CONTROLLED_RETIREMENT_TOMBSTONES: u64 = 2;
    #[cfg(feature = "test-fault-injection")]
    const T062_CONTROLLED_RESTORE_PACKAGES: u64 = 4;
    #[cfg(feature = "test-fault-injection")]
    const T074_EXPLICITLY_UNSUPPORTED_BOUNDARY_IDS_V1: &[&str] = &[
        "recovery_publication_guard_acquired",
        "recovery_staging_created",
        "recovery_staging_written",
        "recovery_staging_synchronized",
        "recovery_staging_closed",
        "recovery_staging_reopened",
        "recovery_material_digest_length_capacity_verified",
        "recovery_material_published",
        "recovery_manifest_staged",
        "recovery_manifest_synchronized",
        "recovery_manifest_published",
        "recovery_manifest_reopened",
        "recovery_receipt_returned",
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
        "quarantine_and_retirement_quarantine_inserted",
        "quarantine_and_retirement_quarantine_resolved",
        "quarantine_and_retirement_operation_bound_retirement_pending_committed",
        "quarantine_and_retirement_true_orphan_definitive_proof_returned",
        "quarantine_and_retirement_orphan_resolution_retirement_pending_tombstone_committed",
        "quarantine_and_retirement_provider_retirement_invoked",
        "quarantine_and_retirement_provider_bytes_retired",
        "quarantine_and_retirement_retirement_manifest_published",
        "quarantine_and_retirement_operation_bound_retired_tombstone_committed",
        "quarantine_and_retirement_orphan_retired_tombstone_committed",
    ];

    #[cfg(feature = "test-fault-injection")]
    #[derive(Deserialize)]
    struct T062CasesCorpusV1 {
        fault_boundaries: Vec<T062FaultBoundaryRowV1>,
    }

    #[cfg(feature = "test-fault-injection")]
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct T062FaultBoundaryRowV1 {
        boundary_id: String,
        expected_registry_occurrences: u64,
        multiplicity: String,
        order: u64,
        owner: String,
        phase: String,
        prepared_success_occurrences: u64,
    }

    #[cfg(feature = "test-fault-injection")]
    struct T062ChildProtocolV1 {
        root: PathBuf,
        boundary_id: String,
        occurrence: u64,
        phase: String,
        owner: T062FaultOwnerV1,
    }

    #[cfg(feature = "test-fault-injection")]
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum T062FaultOwnerV1 {
        Portable,
        Coordinator,
    }

    #[cfg(feature = "test-fault-injection")]
    #[derive(Clone)]
    struct T074CoordinatorClockV1(ControlledBenchmarkClockV1);

    #[cfg(feature = "test-fault-injection")]
    impl CoordinatorMonotonicClockV1 for T074CoordinatorClockV1 {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            self.0
                .now_absolute_monotonic_ms_v1()
                .map_err(|_| CoordinatorClockUnavailableV1)
        }
    }

    #[cfg(feature = "test-fault-injection")]
    struct T074PlanSignerV1 {
        key: SigningKey,
    }

    #[cfg(feature = "test-fault-injection")]
    impl T074PlanSignerV1 {
        fn new_v1() -> Self {
            Self {
                key: SigningKey::from_bytes(&T074_SIGNING_KEY_BYTES_V1),
            }
        }

        fn resolver_v1(&self) -> T074PlanResolverV1 {
            T074PlanResolverV1 {
                public_key: self.key.verifying_key().to_bytes(),
            }
        }
    }

    #[cfg(feature = "test-fault-injection")]
    impl Ed25519Signer for T074PlanSignerV1 {
        fn key_id(&self) -> &str {
            CONTROLLED_BENCHMARK_KEY_ID_V1
        }

        fn sign_ed25519(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
            Ok(self.key.sign(message).to_bytes())
        }
    }

    #[cfg(feature = "test-fault-injection")]
    #[derive(Clone)]
    struct T074PlanResolverV1 {
        public_key: [u8; 32],
    }

    #[cfg(feature = "test-fault-injection")]
    impl Ed25519KeyResolver for T074PlanResolverV1 {
        fn resolve_ed25519(&self, key_id: &str) -> Result<[u8; 32], ContractError> {
            if key_id == CONTROLLED_BENCHMARK_KEY_ID_V1 {
                Ok(self.public_key)
            } else {
                Err(ContractError::UnknownKey)
            }
        }
    }

    #[cfg(feature = "test-fault-injection")]
    type T074CoordinatorStoreV1 =
        SqliteCoordinatorStoreV1<T074CoordinatorClockV1, T074PlanResolverV1>;

    #[cfg(feature = "test-fault-injection")]
    struct T074ControlledPreparationV1 {
        case: ControlledBenchmarkCaseV1,
        store: T074CoordinatorStoreV1,
        clock: ControlledBenchmarkClockV1,
    }

    #[cfg(feature = "test-fault-injection")]
    enum T074PreparedWorkflowV1 {
        ControlledPreparation(Box<T074ControlledPreparationV1>),
        Maintenance,
        Unsupported,
    }

    /// The compiled `FaultProbeV1` retains private `FaultSessionV1` custody; this
    /// barrier is the only callback transferred from the child protocol into it.
    #[cfg(feature = "test-fault-injection")]
    #[derive(Clone)]
    struct T062ProcessBarrierV1 {
        marker: PathBuf,
    }

    #[cfg(feature = "test-fault-injection")]
    impl T062ProcessBarrierV1 {
        fn new_v1(protocol: &T062ChildProtocolV1) -> Self {
            Self {
                marker: protocol.marker_v1(T062_BOUNDARY_REACHED_MARKER),
            }
        }
    }

    #[cfg(feature = "test-fault-injection")]
    impl ProcessBarrierV1 for T062ProcessBarrierV1 {
        fn reached_v1(&self) {
            publish_create_new_v1(&self.marker, b"boundary-reached")
                .expect("T062 selected production ProcessBarrier publishes exact marker");
            loop {
                thread::park();
            }
        }
    }

    #[cfg(feature = "test-fault-injection")]
    impl T062ChildProtocolV1 {
        fn from_environment_v1() -> Result<Option<Self>, ProcessProbeErrorV1> {
            let Some(root) = std::env::var_os(T062_PROTOCOL_ROOT_ENV) else {
                return Ok(None);
            };
            let root = PathBuf::from(root);
            let metadata =
                fs::symlink_metadata(&root).map_err(|_| ProcessProbeErrorV1::InvalidInput)?;
            if !root.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ProcessProbeErrorV1::InvalidInput);
            }

            let boundary_id = required_private_utf8_v1(T062_BOUNDARY_ID_ENV)?;
            if boundary_id.is_empty()
                || boundary_id.len() > 128
                || !boundary_id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(ProcessProbeErrorV1::InvalidInput);
            }
            let occurrence = required_private_u64_v1(T062_BOUNDARY_OCCURRENCE_ENV)?;
            if occurrence == 0 {
                return Err(ProcessProbeErrorV1::InvalidInput);
            }
            let phase = required_private_utf8_v1(T062_BOUNDARY_PHASE_ENV)?;
            let material_packages = required_private_u64_v1(T062_MATERIAL_PACKAGES_ENV)?;
            let retirement_tombstones = required_private_u64_v1(T062_RETIREMENT_TOMBSTONES_ENV)?;
            let restore_packages = required_private_u64_v1(T062_RESTORE_PACKAGES_ENV)?;
            if material_packages != T062_CONTROLLED_MATERIAL_PACKAGES
                || retirement_tombstones != T062_CONTROLLED_RETIREMENT_TOMBSTONES
                || restore_packages != T062_CONTROLLED_RESTORE_PACKAGES
            {
                return Err(ProcessProbeErrorV1::InvalidInput);
            }

            let corpus: T062CasesCorpusV1 = serde_json::from_slice(T062_CASES_BYTES)
                .map_err(|_| ProcessProbeErrorV1::InvalidInput)?;
            let row = corpus
                .fault_boundaries
                .iter()
                .find(|row| row.boundary_id == boundary_id)
                .ok_or(ProcessProbeErrorV1::InvalidInput)?;
            if row.expected_registry_occurrences != 1
                || row.order == 0
                || row.prepared_success_occurrences > 12
                || row.phase != phase
                || occurrence
                    > controlled_occurrences_v1(
                        &row.multiplicity,
                        material_packages,
                        retirement_tombstones,
                        restore_packages,
                    )?
            {
                return Err(ProcessProbeErrorV1::InvalidInput);
            }
            let owner = match row.owner.as_str() {
                "portable" => T062FaultOwnerV1::Portable,
                "coordinator" => T062FaultOwnerV1::Coordinator,
                _ => return Err(ProcessProbeErrorV1::InvalidInput),
            };

            Ok(Some(Self {
                root,
                boundary_id,
                occurrence,
                phase,
                owner,
            }))
        }

        fn coordinator_root_v1(&self) -> PathBuf {
            self.root.join(T062_COORDINATOR_ROOT_DIRECTORY)
        }

        fn coordinator_identity_file_v1(&self) -> PathBuf {
            self.root.join(T062_COORDINATOR_IDENTITY_FILE)
        }

        fn marker_v1(&self, marker: &str) -> PathBuf {
            self.root.join(marker)
        }

        fn uses_controlled_preparation_v1(&self) -> bool {
            match (self.phase.as_str(), self.owner) {
                ("preliminary" | "final-comparison", T062FaultOwnerV1::Portable) => true,
                ("positive-coordinator-commit", T062FaultOwnerV1::Coordinator) => true,
                ("positive-coordinator-commit", T062FaultOwnerV1::Portable) => !matches!(
                    self.boundary_id.as_str(),
                    "positive_coordinator_commit_permit_resolved_aborted"
                        | "positive_coordinator_commit_permit_resolved_ambiguous"
                ),
                ("acknowledgement-and-readback", T062FaultOwnerV1::Portable) => matches!(
                    self.boundary_id.as_str(),
                    "acknowledgement_post_commit_time_classified"
                        | "acknowledgement_post_commit_guards_classified"
                        | "acknowledgement_positive_marker_constructed"
                        | "acknowledgement_result_returned"
                        | "acknowledgement_all_final_guards_released"
                ),
                _ => false,
            }
        }

        fn uses_maintenance_v1(&self) -> bool {
            self.owner == T062FaultOwnerV1::Coordinator
                && matches!(self.phase.as_str(), "backup" | "restore")
        }
    }

    #[cfg(feature = "test-fault-injection")]
    fn controlled_occurrences_v1(
        multiplicity: &str,
        material_packages: u64,
        retirement_tombstones: u64,
        restore_packages: u64,
    ) -> Result<u64, ProcessProbeErrorV1> {
        match multiplicity {
            "unit" => Ok(1),
            "preliminary-groups" => Ok(12),
            "final-guards" => Ok(10),
            "final-groups" => Ok(12),
            "commit-members" => Ok(8),
            "material-packages" => Ok(material_packages),
            "retirement-tombstones" => Ok(retirement_tombstones),
            "restore-packages" => Ok(restore_packages),
            _ => Err(ProcessProbeErrorV1::InvalidInput),
        }
    }

    #[cfg(feature = "test-fault-injection")]
    fn required_private_utf8_v1(name: &str) -> Result<String, ProcessProbeErrorV1> {
        std::env::var_os(name)
            .ok_or(ProcessProbeErrorV1::InvalidInput)?
            .into_string()
            .map_err(|_| ProcessProbeErrorV1::InvalidInput)
    }

    #[cfg(feature = "test-fault-injection")]
    fn required_private_u64_v1(name: &str) -> Result<u64, ProcessProbeErrorV1> {
        let value = required_private_utf8_v1(name)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ProcessProbeErrorV1::InvalidInput);
        }
        value
            .parse::<u64>()
            .map_err(|_| ProcessProbeErrorV1::InvalidInput)
    }

    #[cfg(feature = "test-fault-injection")]
    fn publish_create_new_v1(path: &Path, value: &[u8]) -> Result<(), ProcessProbeErrorV1> {
        if value.is_empty() || value.len() > MAX_RESULT_BYTES {
            return Err(ProcessProbeErrorV1::ResultInvalid);
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        file.write_all(value)
            .and_then(|()| file.sync_all())
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)
    }

    #[cfg(feature = "test-fault-injection")]
    fn wait_for_private_go_v1(protocol: &T062ChildProtocolV1) -> Result<(), ProcessProbeErrorV1> {
        let marker = protocol.marker_v1(T062_GO_MARKER);
        let deadline = Instant::now() + PROTOCOL_TIMEOUT;
        loop {
            match fs::symlink_metadata(&marker) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(ProcessProbeErrorV1::ProtocolFailed);
                    }
                    let value =
                        fs::read(&marker).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
                    if value == b"go" {
                        return Ok(());
                    }
                    if !value.is_empty() {
                        return Err(ProcessProbeErrorV1::ProtocolFailed);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(ProcessProbeErrorV1::ProtocolFailed),
            }
            if Instant::now() >= deadline {
                return Err(ProcessProbeErrorV1::TimedOut);
            }
            thread::sleep(PROTOCOL_POLL);
        }
    }

    #[cfg(feature = "test-fault-injection")]
    fn prepare_selected_workflow_v1(
        protocol: &T062ChildProtocolV1,
    ) -> Result<T074PreparedWorkflowV1, ProcessProbeErrorV1> {
        if protocol.uses_maintenance_v1() {
            return Ok(T074PreparedWorkflowV1::Maintenance);
        }
        if !protocol.uses_controlled_preparation_v1() {
            return Ok(T074PreparedWorkflowV1::Unsupported);
        }

        let coordinator_root = protocol.coordinator_root_v1();
        fs::create_dir(&coordinator_root).map_err(|_| ProcessProbeErrorV1::RootCreateFailed)?;
        let coordinator_root = fs::canonicalize(coordinator_root)
            .map_err(|_| ProcessProbeErrorV1::RootCreateFailed)?;
        let clock = ControlledBenchmarkClockV1::start_v1();
        let coordinator_clock = T074CoordinatorClockV1(clock.clone());
        let signer = T074PlanSignerV1::new_v1();
        let resolver = signer.resolver_v1();
        let initialization_deadline = clock
            .deadline_after_ms_v1(T074_PREPARATION_DEADLINE_BUDGET_MS)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let config = CoordinatorStoreConfigV1::try_new_empty_attested(
            coordinator_root.clone(),
            T062_MAXIMUM_BUSY_WAIT_MS,
        )
        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let store = SqliteCoordinatorStoreV1::open_or_create(
            config,
            coordinator_clock,
            resolver.clone(),
            initialization_deadline,
        )
        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let identity = store.root_identity_evidence().to_attested_bytes();
        publish_create_new_v1(&protocol.coordinator_identity_file_v1(), &identity)?;

        let signed = sign_plan_v1(t074_plan_input_v1()?, &signer)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let canonical = signed
            .to_canonical_json()
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let authentic = decode_and_verify_plan(&canonical, &resolver)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let plan_deadline = clock
            .deadline_after_ms_v1(T074_PREPARATION_DEADLINE_BUDGET_MS)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let case = build_controlled_benchmark_case_v1(authentic, clock.clone(), plan_deadline, 1)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        provision_t074_budget_scope_v1(&coordinator_root, &case)?;

        Ok(T074PreparedWorkflowV1::ControlledPreparation(Box::new(
            T074ControlledPreparationV1 { case, store, clock },
        )))
    }

    #[cfg(feature = "test-fault-injection")]
    fn t074_plan_input_v1() -> Result<PlanInputV1, ProcessProbeErrorV1> {
        Ok(PlanInputV1 {
            operation_id: "operation:t074-process-probe-v1".to_owned(),
            task_id: "task:t074-process-probe-v1".to_owned(),
            workload_id: CONTROLLED_BENCHMARK_WORKLOAD_ID_V1.to_owned(),
            boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1.to_owned(),
            task_lease_digest: t074_digest_v1(b"task-lease"),
            request_source_kind: RequestSourceKindV1::HumanRequestGrant,
            request_source_digest: t074_digest_v1(b"request-source"),
            catalog_version: CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1.to_owned(),
            policy_version: CONTROLLED_BENCHMARK_POLICY_VERSION_V1.to_owned(),
            risk_level: RiskLevelV1::L2,
            target: ResourceRefV1::new("vault-t074-process-probe", ["Public", "Target.txt"])
                .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?,
            precondition: FilePreconditionInputV1 {
                volume_id: "volume:t074-process-probe-v1".to_owned(),
                file_id: "file:t074-process-probe-v1".to_owned(),
                content_sha256: t074_digest_v1(b"precondition"),
                byte_length: 7,
            },
            replacement_bytes: b"after\n".to_vec(),
            replacement_media_type: "text/plain;charset=utf-8".to_owned(),
            recovery: RecoveryInputV1 {
                class: RecoveryClassV1::Irreversible,
                atomicity: AtomicityV1::NonAtomic,
                reserved_bytes: 0,
            },
            capability_report_digest: t074_digest_v1(b"capability-report"),
            capability_observed_at_unix_ms: CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1,
            required_capabilities: vec![
                "filesystem.verify-by-handle".to_owned(),
                "filesystem.atomic-replace".to_owned(),
            ],
            budget: BudgetInputV1 {
                reservation_id: "budget:t074-process-probe-v1".to_owned(),
                currency_code: "EUR".to_owned(),
                price_table_id: "price-table:controlled-benchmark-v1".to_owned(),
                max_cost_micro_units: 0,
                action_limit: 1,
                egress_bytes_limit: 0,
            },
            issued_at_unix_ms: CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1,
            expires_at_unix_ms: CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
            nonce: Nonce128::from_bytes([0x74; 16]),
            instance_epoch: 1,
            fencing_epoch: 9,
        })
    }

    #[cfg(feature = "test-fault-injection")]
    fn t074_digest_v1(domain: &[u8]) -> Sha256Digest {
        let mut bytes = b"HELIXOS\0T074-PROCESS-PROBE\0V1\0".to_vec();
        bytes.extend_from_slice(
            &u64::try_from(domain.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        bytes.extend_from_slice(domain);
        Sha256Digest::digest(&bytes)
    }

    #[cfg(feature = "test-fault-injection")]
    fn provision_t074_budget_scope_v1(
        coordinator_root: &Path,
        case: &ControlledBenchmarkCaseV1,
    ) -> Result<(), ProcessProbeErrorV1> {
        let database = coordinator_root.join(T062_COORDINATOR_DATABASE_FILE);
        let mut connection = Connection::open_with_flags(
            database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 PRAGMA wal_autocheckpoint=0;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;
                 PRAGMA cell_size_check=ON;
                 PRAGMA recursive_triggers=ON;",
            )
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let scope = case.budget_scope_v1();
        let total = scope.total_v1();
        let inserted = transaction
            .execute(
                "INSERT INTO budget_scopes (
                     scope_id, task_lease_digest, allowance_binding_digest, scope_generation,
                     currency_code, price_table_id, total_cost_micro_units, total_action_count,
                     total_egress_bytes, total_recovery_bytes, held_cost_micro_units,
                     held_action_count, held_egress_bytes, held_recovery_bytes,
                     provisioning_profile
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                           0, 0, 0, 0, 'TRUSTED_LEASE_V1')",
                params![
                    scope.scope_id_v1().as_bytes().as_slice(),
                    scope.task_lease_digest_v1().as_bytes().as_slice(),
                    scope.allowance_binding_digest_v1().as_bytes().as_slice(),
                    i64::try_from(scope.scope_generation_v1())
                        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?,
                    scope.currency_code_v1(),
                    scope.price_table_id_v1(),
                    i64::try_from(total[0]).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?,
                    i64::try_from(total[1]).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?,
                    i64::try_from(total[2]).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?,
                    i64::try_from(total[3]).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?,
                ],
            )
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        if inserted != 1 {
            return Err(ProcessProbeErrorV1::ProtocolFailed);
        }
        let updated = transaction
            .execute(
                "UPDATE coordinator_store_meta
                 SET store_generation=1, budget_generation=1
                 WHERE singleton=1 AND root_lifecycle_state='ACTIVE'
                   AND store_generation=0 AND budget_generation=0",
                [],
            )
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        if updated != 1 {
            return Err(ProcessProbeErrorV1::ProtocolFailed);
        }
        transaction
            .commit()
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)
    }

    #[cfg(feature = "test-fault-injection")]
    fn read_retained_identity_v1(
        protocol: &T062ChildProtocolV1,
    ) -> Result<CoordinatorRootIdentityEvidenceV1, ProcessProbeErrorV1> {
        let path = protocol.coordinator_identity_file_v1();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 32 {
            return Err(ProcessProbeErrorV1::ProtocolFailed);
        }
        let bytes = fs::read(path).map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        Ok(CoordinatorRootIdentityEvidenceV1::from_attested_bytes(
            bytes,
        ))
    }

    #[cfg(feature = "test-fault-injection")]
    fn reopen_and_classify_v1(
        protocol: &T062ChildProtocolV1,
    ) -> Result<&'static [u8], ProcessProbeErrorV1> {
        let identity = read_retained_identity_v1(protocol)?;
        let coordinator_root = fs::canonicalize(protocol.coordinator_root_v1())
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let config = CoordinatorStoreConfigV1::try_new_existing_attested(
            coordinator_root.clone(),
            identity,
            T062_MAXIMUM_BUSY_WAIT_MS,
        )
        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let clock = ControlledBenchmarkClockV1::start_v1();
        let deadline = clock
            .deadline_after_ms_v1(T074_PREPARATION_DEADLINE_BUDGET_MS)
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let store = SqliteCoordinatorStoreV1::open_or_create(
            config,
            T074CoordinatorClockV1(clock),
            T074PlanSignerV1::new_v1().resolver_v1(),
            deadline,
        )
        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let verified_operation_count = store.operation_count();
        drop(store);

        let connection = Connection::open_with_flags(
            coordinator_root.join(T062_COORDINATOR_DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let (total, preparing, failed): (i64, i64, i64) = connection
            .query_row(
                "SELECT COUNT(*), \
                        COALESCE(SUM(CASE WHEN operation_state = 'PREPARING' THEN 1 ELSE 0 END), 0), \
                        COALESCE(SUM(CASE WHEN operation_state = 'FAILED' THEN 1 ELSE 0 END), 0) \
                   FROM prepared_operations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let active_quarantines: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM preparation_quarantines \
                  WHERE quarantine_status = 'ACTIVE'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
        let total = u64::try_from(total).map_err(|_| ProcessProbeErrorV1::ResultInvalid)?;
        let preparing = u64::try_from(preparing).map_err(|_| ProcessProbeErrorV1::ResultInvalid)?;
        let failed = u64::try_from(failed).map_err(|_| ProcessProbeErrorV1::ResultInvalid)?;
        let active_quarantines =
            u64::try_from(active_quarantines).map_err(|_| ProcessProbeErrorV1::ResultInvalid)?;
        if total != verified_operation_count || preparing + failed != total {
            return Err(ProcessProbeErrorV1::ResultInvalid);
        }
        match (active_quarantines, total, preparing, failed) {
            (1.., _, _, _) => Ok(b"quarantine"),
            (0, 0, 0, 0) => Ok(b"absent"),
            (0, total, preparing, 0) if total == preparing => Ok(b"preparing"),
            (0, total, 0, failed) if total == failed => Ok(b"failed"),
            _ => Err(ProcessProbeErrorV1::ResultInvalid),
        }
    }

    #[cfg(feature = "test-fault-injection")]
    fn run_selected_production_workflow_v1(
        protocol: &T062ChildProtocolV1,
        prepared: T074PreparedWorkflowV1,
    ) -> Result<(), ProcessProbeErrorV1> {
        let barrier = T062ProcessBarrierV1::new_v1(protocol);
        match prepared {
            T074PreparedWorkflowV1::ControlledPreparation(prepared) => {
                let T074ControlledPreparationV1 {
                    case,
                    mut store,
                    clock,
                } = *prepared;
                let portable_probe = match protocol.owner {
                    T062FaultOwnerV1::Portable => FaultProbeV1::selected_process_barrier_v1(
                        &protocol.boundary_id,
                        protocol.occurrence,
                        barrier,
                    )
                    .map_err(|_| ProcessProbeErrorV1::InvalidInput)?,
                    T062FaultOwnerV1::Coordinator => {
                        let coordinator_barrier = barrier;
                        select_t074_coordinator_fault_probe_for_test_v1(
                            &mut store,
                            &protocol.boundary_id,
                            protocol.occurrence,
                            move || coordinator_barrier.reached_v1(),
                        )
                        .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
                        FaultProbeV1::default()
                    }
                };
                let deadline = clock
                    .deadline_after_ms_v1(T074_PREPARATION_DEADLINE_BUDGET_MS)
                    .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
                case.prepare_once_with_fault_probe_v1(&store, deadline, portable_probe)
                    .map_err(|_| ProcessProbeErrorV1::ProtocolFailed)?;
                Err(ProcessProbeErrorV1::ProtocolFailed)
            }
            T074PreparedWorkflowV1::Maintenance => run_t074_production_fault_probe_for_test_v1(
                &protocol.boundary_id,
                protocol.occurrence,
                protocol.root.clone(),
                move || barrier.reached_v1(),
            )
            .map_err(|_| ProcessProbeErrorV1::ProtocolFailed),
            T074PreparedWorkflowV1::Unsupported => Err(ProcessProbeErrorV1::InvalidInput),
        }
    }

    #[test]
    fn diagnostics_never_expose_native_environment_values() {
        let secret = std::env::temp_dir().join("private-probe-value");
        let environment = ProcessProbeEnvironmentV1::new("HELIXOS_PRIVATE_TEST_VALUE", &secret);
        let child = ProcessProbeChildV1 {
            root: secret.clone(),
            index: 7,
        };
        let probe = std::mem::ManuallyDrop::new(SynchronizedProcessProbeV1 {
            root: secret.clone(),
            children: Vec::new(),
            contender_count: 8,
        });
        let secret = secret.to_string_lossy();
        assert!(!format!("{environment:?}").contains(secret.as_ref()));
        assert!(!format!("{child:?}").contains(secret.as_ref()));
        assert!(!format!("{:?}", &*probe).contains(secret.as_ref()));
        assert_eq!(
            format!("{:?}", ProcessProbeErrorV1::TimedOut),
            "PROCESS_PROBE_TIMED_OUT"
        );
    }

    #[test]
    fn result_marker_is_complete_create_only_and_leaves_no_pending_file() {
        let root = create_probe_root_v1().expect("private result-marker root creates");
        let child = ProcessProbeChildV1 {
            root: root.clone(),
            index: 0,
        };
        let payload = b"boundary-reached";

        child
            .publish_result_v1(payload)
            .expect("first complete result marker publishes");
        assert_eq!(
            fs::read(marker_path_v1(&root, "result", 0)).expect("published marker reads"),
            payload
        );
        assert!(!marker_path_v1(&root, "result-pending", 0).exists());
        assert_eq!(
            child.publish_result_v1(b"replacement").unwrap_err(),
            ProcessProbeErrorV1::ProtocolFailed
        );
        assert_eq!(
            fs::read(marker_path_v1(&root, "result", 0)).expect("original marker remains"),
            payload
        );
        assert!(!marker_path_v1(&root, "result-pending", 0).exists());
        fs::remove_dir_all(root).expect("private result-marker root removes");
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn t074_compiled_driver_partition_is_explicit_v1() {
        let corpus: T062CasesCorpusV1 =
            serde_json::from_slice(T062_CASES_BYTES).expect("T062 cases corpus decodes");
        let mut supported_boundary_count = 0_usize;
        let mut supported_case_count = 0_u64;
        let mut unsupported_boundary_ids = Vec::new();

        for row in &corpus.fault_boundaries {
            let owner = match row.owner.as_str() {
                "portable" => T062FaultOwnerV1::Portable,
                "coordinator" => T062FaultOwnerV1::Coordinator,
                other => panic!("unexpected T062 owner {other}"),
            };
            let protocol = T062ChildProtocolV1 {
                root: PathBuf::new(),
                boundary_id: row.boundary_id.clone(),
                occurrence: 1,
                phase: row.phase.clone(),
                owner,
            };
            if protocol.uses_controlled_preparation_v1() || protocol.uses_maintenance_v1() {
                supported_boundary_count += 1;
                supported_case_count += controlled_occurrences_v1(
                    &row.multiplicity,
                    T062_CONTROLLED_MATERIAL_PACKAGES,
                    T062_CONTROLLED_RETIREMENT_TOMBSTONES,
                    T062_CONTROLLED_RESTORE_PACKAGES,
                )
                .expect("T062 controlled multiplicity is known");
            } else {
                unsupported_boundary_ids.push(row.boundary_id.as_str());
            }
        }

        assert_eq!(corpus.fault_boundaries.len(), 123);
        assert_eq!(supported_boundary_count, 79);
        assert_eq!(supported_case_count, 123);
        assert_eq!(unsupported_boundary_ids.len(), 44);
        assert_eq!(
            unsupported_boundary_ids,
            T074_EXPLICITLY_UNSUPPORTED_BOUNDARY_IDS_V1
        );
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn t074_controlled_fixture_exists_before_ready_v1() {
        let root = create_probe_root_v1().expect("T074 probe root creates");
        let protocol = T062ChildProtocolV1 {
            root: root.clone(),
            boundary_id: "preliminary_attempt_identity_generated".to_owned(),
            occurrence: 1,
            phase: "preliminary".to_owned(),
            owner: T062FaultOwnerV1::Portable,
        };

        let prepared =
            prepare_selected_workflow_v1(&protocol).expect("T074 controlled fixture prepares");
        let T074PreparedWorkflowV1::ControlledPreparation(prepared) = prepared else {
            panic!("T074 preliminary boundary must select controlled preparation");
        };
        let T074ControlledPreparationV1 { store, .. } = *prepared;
        let identity = fs::read(protocol.coordinator_identity_file_v1())
            .expect("T074 retained coordinator identity exists before READY");
        assert_eq!(identity.len(), 32);
        assert_eq!(store.operation_count(), 0);

        let coordinator_root = fs::canonicalize(protocol.coordinator_root_v1())
            .expect("T074 coordinator root canonicalizes before READY");
        let connection = Connection::open_with_flags(
            coordinator_root.join(T062_COORDINATOR_DATABASE_FILE),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("T074 real coordinator database opens before READY");
        let budget_scope_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM budget_scopes", [], |row| row.get(0))
            .expect("T074 benchmark budget scope is queryable before READY");
        let prepared_operation_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM prepared_operations", [], |row| {
                row.get(0)
            })
            .expect("T074 prepared operations are queryable before READY");
        assert_eq!(budget_scope_count, 1);
        assert_eq!(prepared_operation_count, 0);

        drop(connection);
        drop(store);
        fs::remove_dir_all(root).expect("T074 probe root removes");
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn t074_go_wait_tolerates_only_the_transient_empty_create_state_v1() {
        let root = create_probe_root_v1().expect("T074 probe root creates");
        let protocol = T062ChildProtocolV1 {
            root: root.clone(),
            boundary_id: "preliminary_attempt_identity_generated".to_owned(),
            occurrence: 1,
            phase: "preliminary".to_owned(),
            owner: T062FaultOwnerV1::Portable,
        };
        let marker = protocol.marker_v1(T062_GO_MARKER);
        fs::write(&marker, []).expect("T074 transient empty GO marker creates");
        let writer = thread::spawn(move || {
            thread::sleep(PROTOCOL_POLL.saturating_mul(2));
            fs::write(marker, b"go").expect("T074 complete GO marker writes");
        });

        wait_for_private_go_v1(&protocol).expect("T074 complete GO marker validates");
        writer.join().expect("T074 GO marker writer joins");
        fs::remove_dir_all(root).expect("T074 probe root removes");
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    #[ignore = "private T062 fault child; invoked only by the release process-kill parent"]
    pub(crate) fn process_crash_fault_child_v1() {
        let Some(protocol) = T062ChildProtocolV1::from_environment_v1()
            .expect("T062 private child protocol validates")
        else {
            return;
        };
        let prepared = prepare_selected_workflow_v1(&protocol)
            .expect("T062 selected workflow fixture prepares before READY");
        publish_create_new_v1(&protocol.marker_v1(T062_READY_MARKER), b"ready")
            .expect("T062 READY publishes");
        wait_for_private_go_v1(&protocol).expect("T062 GO validates");
        run_selected_production_workflow_v1(&protocol, prepared)
            .expect("T062 explicitly carried production workflow reaches selection");
        panic!("T062 selected production occurrence did not inject ProcessBarrier")
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    #[ignore = "private T062 reopen child; invoked only by the release process-kill parent"]
    pub(crate) fn process_crash_reopen_child_v1() {
        let Some(protocol) = T062ChildProtocolV1::from_environment_v1()
            .expect("T062 private reopen protocol validates")
        else {
            return;
        };
        let state = reopen_and_classify_v1(&protocol)
            .expect("T062 production reopen and full invariants classify");
        publish_create_new_v1(&protocol.marker_v1(T062_REOPEN_RESULT_MARKER), state)
            .expect("T062 bounded closed reopen state publishes");
    }
}
