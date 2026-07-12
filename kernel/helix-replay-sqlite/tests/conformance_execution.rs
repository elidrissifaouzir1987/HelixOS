//! Executable projection of every conformance case reachable through the public API.
//!
//! Cases requiring a provider fault seam are kept in a closed, asserted blocklist unless
//! the private, non-default fault feature executes the real classification path.

mod common;
#[path = "common/process_probe.rs"]
mod process_probe;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, DEFAULT_BACKUP_RETRY_WAIT_MS,
    DEFAULT_BACKUP_STEP_PAGES, DEFAULT_BUSY_WAIT_MS, MAINTENANCE_DEADLINE_MONOTONIC_MS,
    OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_replay_sqlite::{
    restore_replay_store_v1, verify_replay_backup_v1, BackupManifestV1, ReplayClockUnavailableV1,
    ReplayMonotonicClockV1, ReplayStoreConfigV1, SqliteReplayClaimantV1, TrustedLocalStoreRootV1,
    REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1,
};
use process_probe::{run_process_round, ProcessOutcome};
use rusqlite::{params, Connection, Error as SqliteError, ErrorCode, OpenFlags};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
#[cfg(feature = "test-fault-injection")]
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
#[cfg(feature = "test-fault-injection")]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "test-fault-injection")]
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-replay-store-v1/cases.json");
const CORPUS_SCHEMA: &str = "helixos.durable-replay-store-cases/1";
const CLAIM_DEADLINE_MONOTONIC_MS: u64 = common::feature002::PLAN_DEADLINE_MS;
const THREAD_CONTENDERS: usize = 64;
const PROCESS_CONTENDERS: usize = 8;
const CONTENTION_BUSY_WAIT_MS: u64 = 5_000;
const INITIALIZATION_CORRECTNESS_BUSY_WAIT_MS: u64 = 5_000;
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

const WORKER_ENV: &str = "HELIX_REPLAY_CORPUS_WORKER";
const ROOT_ENV: &str = "HELIX_REPLAY_CORPUS_ROOT";
const BACKUP_ROOT_ENV: &str = "HELIX_REPLAY_CORPUS_BACKUP_ROOT";
const FAULT_ENV: &str = "HELIX_REPLAY_TEST_FAULT_POINT";
#[cfg(feature = "test-fault-injection")]
const CLAIM_SCENARIO_ENV: &str = "HELIX_REPLAY_TEST_CLAIM_SCENARIO";
const ROOT_LOCK_FILENAME: &str = ".helix-replay-root-v1.lock";
const BACKUP_STAGING_DATABASE_FILENAME: &str = ".replay-backup.sqlite3.staging";
#[cfg(feature = "test-fault-injection")]
const RESTORE_STAGING_DATABASE_FILENAME: &str = ".replay.sqlite3.restore-staging";
#[cfg(feature = "test-fault-injection")]
const ACTIVATION_MARKER_FILENAME: &str = ".helix-replay-restored-activation-required-v1";
const BACKUP_PACKAGE_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=BACKUP_PACKAGE\n";
#[cfg(feature = "test-fault-injection")]
const RESTORE_PENDING_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=RESTORE_PENDING\n";
#[cfg(feature = "test-fault-injection")]
const RESTORED_ACTIVATION_MARKER_CONTENT: &[u8] =
    b"HELIXOS_REPLAY_RESTORED_ACTIVATION_REQUIRED_V1\n";

#[cfg(feature = "test-fault-injection")]
const FEATURE_FAULT_WORKER_ENV: &str = "HELIX_REPLAY_CORPUS_FEATURE_FAULT_WORKER";
#[cfg(feature = "test-fault-injection")]
const FEATURE_FAULT_CASE_ENV: &str = "HELIX_REPLAY_CORPUS_FEATURE_FAULT_CASE";
#[cfg(feature = "test-fault-injection")]
const FEATURE_FAULT_PACKAGE_ENV: &str = "HELIX_REPLAY_CORPUS_FEATURE_FAULT_PACKAGE";
#[cfg(feature = "test-fault-injection")]
const INITIALIZATION_FAULT_ENV: &str = "HELIX_REPLAY_TEST_INITIALIZATION_FAULT";
#[cfg(feature = "test-fault-injection")]
const RETURN_ERROR_ENV: &str = "HELIX_REPLAY_TEST_RETURN_ERROR";
#[cfg(feature = "test-fault-injection")]
const FEATURE_FAULT_RESULT_PREFIX: &str = "HELIX_CORPUS_FEATURE_FAULT_ACTUAL=";

#[cfg(not(feature = "test-fault-injection"))]
const FEATURE_FAULT_BLOCKED_CASES: [(&str, &str); 3] = [
    (
        "initialization-durability-profile-unavailable",
        "requires the non-default initialization fault feature",
    ),
    (
        "initialization-store-unavailable",
        "requires the non-default initialization fault feature",
    ),
    (
        "restore-incomplete",
        "requires the non-default restore fault feature",
    ),
];

#[cfg(not(feature = "test-fault-injection"))]
const CLAIM_FAULT_BLOCKED_CASES: [(&str, &str); 8] = [
    (
        "claim-commit-readback-absence",
        "missing commit-error and healthy-absence readback seam",
    ),
    (
        "claim-commit-readback-conflict",
        "missing commit-error and conflicting-readback seam",
    ),
    (
        "claim-commit-readback-exact",
        "missing commit-error and exact-attempt readback seam",
    ),
    (
        "claim-commit-readback-failed",
        "missing commit-error and failed-readback seam",
    ),
    (
        "claim-commit-readback-prior",
        "missing commit-error and prior-attempt readback seam",
    ),
    (
        "claim-generation-exhausted",
        "no constructible healthy maximum-generation v1 store",
    ),
    (
        "claim-rng-unavailable",
        "missing random-source failure seam",
    ),
    (
        "deadline-readback-late",
        "missing commit-error and late-readback clock seam",
    ),
];

const CRASH_CASES: [&str; 10] = [
    "crash-backup-database-complete",
    "crash-backup-manifest-staged",
    "crash-backup-published",
    "crash-before-commit",
    "crash-before-result-ack",
    "crash-begin-acquired",
    "crash-commit-returned",
    "crash-generation-updated",
    "crash-opened",
    "crash-row-inserted",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseManifest {
    cases: Vec<Case>,
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    action: String,
    case_id: String,
    category: String,
    expected_code: String,
    expected_outcome: String,
    expected_state: String,
    fault: String,
    profile: String,
    setup: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Actual {
    code: String,
    outcome: String,
    state: String,
}

impl Actual {
    fn new(code: &str, outcome: &str, state: &str) -> Self {
        Self {
            code: code.to_owned(),
            outcome: outcome.to_owned(),
            state: state.to_owned(),
        }
    }
}

#[derive(Clone)]
struct ToggleClock {
    unavailable: Arc<AtomicBool>,
}

impl ToggleClock {
    fn available() -> Self {
        Self {
            unavailable: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }
}

impl fmt::Debug for ToggleClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToggleClock")
            .finish_non_exhaustive()
    }
}

impl ReplayMonotonicClockV1 for ToggleClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        if self.unavailable.load(Ordering::SeqCst) {
            Err(ReplayClockUnavailableV1::new())
        } else {
            Ok(common::feature002::NOW_MONOTONIC_MS)
        }
    }
}

#[derive(Clone)]
struct AlwaysUnavailableClock;

impl fmt::Debug for AlwaysUnavailableClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlwaysUnavailableClock")
            .finish_non_exhaustive()
    }
}

impl ReplayMonotonicClockV1 for AlwaysUnavailableClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        Err(ReplayClockUnavailableV1::new())
    }
}

#[derive(Clone)]
struct ExpireWhenWriterHeldClock {
    database: Arc<PathBuf>,
    armed: Arc<AtomicBool>,
}

impl ExpireWhenWriterHeldClock {
    fn new(root: &SyntheticTempRoot) -> Self {
        Self {
            database: Arc::new(root.closed_database_path()),
            armed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl fmt::Debug for ExpireWhenWriterHeldClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpireWhenWriterHeldClock")
            .finish_non_exhaustive()
    }
}

impl ReplayMonotonicClockV1 for ExpireWhenWriterHeldClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        if !self.armed.load(Ordering::SeqCst) {
            return Ok(common::feature002::NOW_MONOTONIC_MS);
        }
        let connection = Connection::open_with_flags(
            self.database.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ReplayClockUnavailableV1::new())?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(|_| ReplayClockUnavailableV1::new())?;
        match connection.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => {
                connection
                    .execute_batch("ROLLBACK")
                    .map_err(|_| ReplayClockUnavailableV1::new())?;
                Ok(common::feature002::NOW_MONOTONIC_MS)
            }
            Err(SqliteError::SqliteFailure(failure, _))
                if matches!(
                    failure.code,
                    ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
                ) =>
            {
                Ok(CLAIM_DEADLINE_MONOTONIC_MS)
            }
            Err(_) => Err(ReplayClockUnavailableV1::new()),
        }
    }
}

#[derive(Clone)]
struct ExpireWhenDurableClaimClock {
    database: Arc<PathBuf>,
}

impl ExpireWhenDurableClaimClock {
    fn new(root: &SyntheticTempRoot) -> Self {
        Self {
            database: Arc::new(root.closed_database_path()),
        }
    }
}

impl fmt::Debug for ExpireWhenDurableClaimClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpireWhenDurableClaimClock")
            .finish_non_exhaustive()
    }
}

impl ReplayMonotonicClockV1 for ExpireWhenDurableClaimClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        let connection = Connection::open_with_flags(
            self.database.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ReplayClockUnavailableV1::new())?;
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |row| row.get(0))
            .map_err(|_| ReplayClockUnavailableV1::new())?;
        if count == 0 {
            Ok(common::feature002::NOW_MONOTONIC_MS)
        } else {
            Ok(CLAIM_DEADLINE_MONOTONIC_MS)
        }
    }
}

#[cfg(feature = "test-fault-injection")]
struct ClaimScenarioGuard {
    previous: Option<std::ffi::OsString>,
}

#[cfg(feature = "test-fault-injection")]
impl ClaimScenarioGuard {
    fn install(root: &SyntheticTempRoot, scenario: &str) -> Self {
        let previous = std::env::var_os(CLAIM_SCENARIO_ENV);
        let canonical_root = fs::canonicalize(root.path())
            .unwrap_or_else(|_| panic!("claim scenario root canonicalization failed"));
        std::env::set_var(
            CLAIM_SCENARIO_ENV,
            format!("{scenario}\n{}", canonical_root.to_string_lossy()),
        );
        Self { previous }
    }
}

#[cfg(feature = "test-fault-injection")]
impl Drop for ClaimScenarioGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var(CLAIM_SCENARIO_ENV, previous);
        } else {
            std::env::remove_var(CLAIM_SCENARIO_ENV);
        }
    }
}

#[cfg(feature = "test-fault-injection")]
#[derive(Clone)]
struct ExpireDuringReadbackClock {
    database: Arc<PathBuf>,
    root_lock: Arc<PathBuf>,
}

#[cfg(feature = "test-fault-injection")]
impl ExpireDuringReadbackClock {
    fn new(root: &SyntheticTempRoot) -> Self {
        Self {
            database: Arc::new(root.closed_database_path()),
            root_lock: Arc::new(root.path().join(".helix-replay-root-v1.lock")),
        }
    }

    fn durable_claim_exists(&self) -> bool {
        if !self.database.is_file() {
            return false;
        }
        Connection::open_with_flags(
            self.database.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .and_then(|connection| {
            connection.query_row("SELECT COUNT(*) FROM replay_claims", [], |row| {
                row.get::<_, i64>(0)
            })
        })
        .is_ok_and(|count| count > 0)
    }

    fn readback_lease_is_held(&self) -> Result<bool, ReplayClockUnavailableV1> {
        if !self.root_lock.is_file() {
            return Ok(false);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.root_lock.as_ref())
            .map_err(|_| ReplayClockUnavailableV1::new())?;
        match file.try_lock() {
            Ok(()) => {
                std::fs::File::unlock(&file).map_err(|_| ReplayClockUnavailableV1::new())?;
                Ok(false)
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(true),
            Err(std::fs::TryLockError::Error(_)) => Err(ReplayClockUnavailableV1::new()),
        }
    }
}

#[cfg(feature = "test-fault-injection")]
impl fmt::Debug for ExpireDuringReadbackClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExpireDuringReadbackClock")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "test-fault-injection")]
impl ReplayMonotonicClockV1 for ExpireDuringReadbackClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        if self.durable_claim_exists() && self.readback_lease_is_held()? {
            Ok(CLAIM_DEADLINE_MONOTONIC_MS)
        } else {
            Ok(common::feature002::NOW_MONOTONIC_MS)
        }
    }
}

#[test]
fn every_corpus_case_is_executed_or_explicitly_blocked_by_a_missing_seam() {
    let manifest: CaseManifest =
        serde_json::from_slice(CASES_BYTES).unwrap_or_else(|_| panic!("corpus decode failed"));
    assert_eq!(manifest.schema, CORPUS_SCHEMA);
    assert_eq!(manifest.cases.len(), 68);
    let focused_case = std::env::var("HELIX_REPLAY_CORPUS_FOCUSED_CASE").ok();

    let mut blocked = BTreeMap::new();
    let mut executed = 0_usize;
    for case in &manifest.cases {
        assert_case_shape(case);
        if focused_case
            .as_deref()
            .is_some_and(|focused| focused != case.case_id)
        {
            continue;
        }
        if let Some(reason) = blocked_reason(&case.case_id) {
            assert!(blocked.insert(case.case_id.as_str(), reason).is_none());
            continue;
        }

        let actual = execute_case(case);
        assert_eq!(
            actual,
            Actual::new(
                &case.expected_code,
                &case.expected_outcome,
                &case.expected_state
            ),
            "executable conformance mismatch for {}",
            case.case_id
        );
        executed += 1;
    }

    if focused_case.is_some() {
        assert_eq!(executed + blocked.len(), 1);
        return;
    }

    #[cfg(feature = "test-fault-injection")]
    let expected_blocked = BTreeMap::<&str, &str>::new();
    #[cfg(not(feature = "test-fault-injection"))]
    let expected_blocked = FEATURE_FAULT_BLOCKED_CASES
        .into_iter()
        .chain(CLAIM_FAULT_BLOCKED_CASES)
        .chain(
            CRASH_CASES
                .into_iter()
                .map(|id| (id, "requires the non-default process fault feature")),
        )
        .collect::<BTreeMap<_, _>>();

    assert_eq!(blocked, expected_blocked);
    assert_eq!(executed + blocked.len(), manifest.cases.len());
    #[cfg(feature = "test-fault-injection")]
    assert_eq!(executed, 68);
    #[cfg(not(feature = "test-fault-injection"))]
    assert_eq!(executed, 47);
}

fn assert_case_shape(case: &Case) {
    assert!(!case.action.is_empty());
    assert!(!case.category.is_empty());
    assert!(!case.fault.is_empty());
    assert_eq!(case.profile, "synthetic-v1");
    assert!(!case.setup.is_empty());
}

fn blocked_reason(_case_id: &str) -> Option<&'static str> {
    #[cfg(not(feature = "test-fault-injection"))]
    if let Some((_, reason)) = FEATURE_FAULT_BLOCKED_CASES
        .iter()
        .find(|(id, _)| *id == _case_id)
    {
        return Some(*reason);
    }
    #[cfg(not(feature = "test-fault-injection"))]
    if let Some((_, reason)) = CLAIM_FAULT_BLOCKED_CASES
        .iter()
        .find(|(id, _)| *id == _case_id)
    {
        return Some(*reason);
    }
    #[cfg(not(feature = "test-fault-injection"))]
    if CRASH_CASES.contains(&_case_id) {
        return Some("requires the non-default process fault feature");
    }
    None
}

fn execute_case(case: &Case) -> Actual {
    match case.case_id.as_str() {
        "backup-deadline-reached" | "backup-incomplete-staging" | "backup-live-consistent" => {
            run_backup_case(&case.case_id)
        }
        "claim-exact-repeat"
        | "claim-commit-readback-absence"
        | "claim-commit-readback-conflict"
        | "claim-commit-readback-exact"
        | "claim-commit-readback-failed"
        | "claim-commit-readback-prior"
        | "claim-fresh"
        | "claim-generation-exhausted"
        | "claim-independent-binding"
        | "claim-nonce-conflict"
        | "claim-operation-conflict"
        | "claim-postcommit-late"
        | "claim-precommit-confirmed-rollback"
        | "claim-prewrite-store-unavailable"
        | "claim-rng-unavailable"
        | "deadline-after-commit"
        | "deadline-already-reached"
        | "deadline-before-commit"
        | "deadline-clock-unavailable"
        | "deadline-readback-late"
        | "deadline-writer-lock" => run_claim_case(&case.case_id),
        "contention-independent-bindings"
        | "contention-operation-conflict"
        | "contention-process-exact"
        | "contention-thread-exact"
        | "contention-thread-nonce-conflict" => run_contention_case(&case.case_id),
        "corruption-application-id-mismatch"
        | "corruption-integrity-failed"
        | "corruption-invalid-row"
        | "corruption-invariant-failed"
        | "corruption-schema-altered"
        | "corruption-truncated-database" => run_corruption_case(&case.case_id),
        id if CRASH_CASES.contains(&id) => run_crash_case(id),
        "initialization-clock-unavailable"
        | "initialization-concurrent"
        | "initialization-deadline-reached"
        | "initialization-durability-profile-unavailable"
        | "initialization-empty-v1"
        | "initialization-invalid-backup-step"
        | "initialization-invalid-backup-wait"
        | "initialization-invalid-busy-bound"
        | "initialization-location-invalid"
        | "initialization-location-not-dedicated"
        | "initialization-store-busy"
        | "initialization-store-unavailable"
        | "migration-newer-schema-refused" => run_initialization_case(&case.case_id),
        "maintenance-deadline-reached" | "maintenance-verify-healthy" => {
            run_maintenance_case(&case.case_id)
        }
        "restore-backup-incomplete"
        | "restore-database-digest-mismatch"
        | "restore-destination-not-empty"
        | "restore-incomplete"
        | "restore-manifest-invalid"
        | "restore-manifest-missing"
        | "restore-source-destination-conflict"
        | "restore-valid-clean-root" => run_restore_case(&case.case_id),
        _ => panic!("corpus case lacks an executable route: {}", case.case_id),
    }
}

fn run_claim_case(case_id: &str) -> Actual {
    match case_id {
        #[cfg(feature = "test-fault-injection")]
        "claim-commit-readback-absence"
        | "claim-commit-readback-conflict"
        | "claim-commit-readback-exact"
        | "claim-commit-readback-failed"
        | "claim-commit-readback-prior"
        | "claim-generation-exhausted"
        | "claim-rng-unavailable"
        | "deadline-readback-late" => run_claim_fault_case(case_id),
        "claim-exact-repeat" => {
            let root = SyntheticTempRoot::new("corpus-claim-repeat");
            let claimant = open_store(&root, InjectedClock::coherent());
            assert_claimed(&claimant, Feature002Variant::Coherent);
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            claim_actual(observed, verified_count(&claimant))
        }
        "claim-fresh" => {
            let root = SyntheticTempRoot::new("corpus-claim-fresh");
            let claimant = open_store(&root, InjectedClock::coherent());
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            claim_actual(observed, verified_count(&claimant))
        }
        "claim-independent-binding" => {
            let root = SyntheticTempRoot::new("corpus-claim-independent");
            let claimant = open_store(&root, InjectedClock::coherent());
            assert_claimed(&claimant, Feature002Variant::Coherent);
            let observed = observe_claim(&claimant, Feature002Variant::Independent);
            claim_actual(observed, verified_count(&claimant))
        }
        "claim-nonce-conflict" => {
            let root = SyntheticTempRoot::new("corpus-claim-nonce-conflict");
            let claimant = open_store(&root, InjectedClock::coherent());
            assert_claimed(&claimant, Feature002Variant::Coherent);
            let observed = observe_claim(&claimant, Feature002Variant::SameNonceDifferentOperation);
            claim_actual(observed, verified_count(&claimant))
        }
        "claim-operation-conflict" => {
            let root = SyntheticTempRoot::new("corpus-claim-operation-conflict");
            let claimant = open_store(&root, InjectedClock::coherent());
            assert_claimed(&claimant, Feature002Variant::Coherent);
            let observed = observe_claim(&claimant, Feature002Variant::SameOperationDifferentNonce);
            claim_actual(observed, verified_count(&claimant))
        }
        "claim-postcommit-late" | "deadline-after-commit" => {
            let root = SyntheticTempRoot::new("corpus-claim-postcommit-late");
            drop(open_store(&root, InjectedClock::coherent()));
            let clock = ExpireWhenDurableClaimClock::new(&root);
            let claimant = SqliteReplayClaimantV1::open_or_create(
                root.config(),
                clock,
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("postcommit-late store open failed"));
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            drop(claimant);
            let reopened = open_store(&root, InjectedClock::coherent());
            claim_actual(observed, verified_count(&reopened))
        }
        "claim-precommit-confirmed-rollback" | "deadline-before-commit" => {
            let root = SyntheticTempRoot::new("corpus-claim-precommit-late");
            drop(open_store(&root, InjectedClock::coherent()));
            let clock = ExpireWhenWriterHeldClock::new(&root);
            let claimant = SqliteReplayClaimantV1::open_or_create(
                root.config(),
                clock.clone(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("precommit-late store open failed"));
            clock.arm();
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            drop(claimant);
            let reopened = open_store(&root, InjectedClock::coherent());
            claim_actual(observed, verified_count(&reopened))
        }
        "claim-prewrite-store-unavailable" => {
            let root = SyntheticTempRoot::new("corpus-claim-store-unavailable");
            let claimant = open_store(&root, InjectedClock::coherent());
            let database = root.closed_database_path();
            let holding = root.path().join("temporarily-unavailable");
            fs::rename(&database, &holding)
                .unwrap_or_else(|_| panic!("store-unavailable fixture could not hide database"));
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            fs::rename(&holding, &database)
                .unwrap_or_else(|_| panic!("store-unavailable fixture could not restore database"));
            claim_actual(observed, verified_count(&claimant))
        }
        "deadline-already-reached" => {
            let root = SyntheticTempRoot::new("corpus-deadline-reached");
            let clock = InjectedClock::coherent();
            let claimant = open_store(&root, clock.clone());
            clock.set(CLAIM_DEADLINE_MONOTONIC_MS);
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            clock.set(common::feature002::NOW_MONOTONIC_MS);
            claim_actual(observed, verified_count(&claimant))
        }
        "deadline-clock-unavailable" => {
            let root = SyntheticTempRoot::new("corpus-deadline-clock-unavailable");
            let clock = ToggleClock::available();
            let claimant = SqliteReplayClaimantV1::open_or_create(
                root.config(),
                clock.clone(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("clock-unavailable store open failed"));
            clock.set_unavailable(true);
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            clock.set_unavailable(false);
            claim_actual(observed, verified_count(&claimant))
        }
        "deadline-writer-lock" => {
            let root = SyntheticTempRoot::new("corpus-deadline-writer-lock");
            let config = ReplayStoreConfigV1::try_new(
                root.trusted_root(),
                10,
                DEFAULT_BACKUP_STEP_PAGES,
                DEFAULT_BACKUP_RETRY_WAIT_MS,
            )
            .unwrap_or_else(|_| panic!("writer-lock configuration failed"));
            let claimant = SqliteReplayClaimantV1::open_or_create(
                config,
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("writer-lock store open failed"));
            let blocker = Connection::open(root.closed_database_path())
                .unwrap_or_else(|_| panic!("writer-lock blocker open failed"));
            blocker
                .execute_batch("BEGIN IMMEDIATE")
                .unwrap_or_else(|_| panic!("writer-lock blocker acquisition failed"));
            let observed = observe_claim(&claimant, Feature002Variant::Coherent);
            blocker
                .execute_batch("ROLLBACK")
                .unwrap_or_else(|_| panic!("writer-lock blocker release failed"));
            claim_actual(observed, verified_count(&claimant))
        }
        _ => unreachable!(),
    }
}

#[cfg(feature = "test-fault-injection")]
fn run_claim_fault_case(case_id: &str) -> Actual {
    let root = SyntheticTempRoot::new(case_id);
    drop(open_store(&root, InjectedClock::coherent()));

    let scenario = match case_id {
        "claim-commit-readback-absence" => "commit-readback-absence",
        "claim-commit-readback-conflict" => "commit-readback-conflict",
        "claim-commit-readback-exact" => "commit-readback-exact",
        "claim-commit-readback-failed" => "commit-readback-failed",
        "claim-commit-readback-prior" => "commit-readback-prior",
        "claim-generation-exhausted" => "generation-exhausted",
        "claim-rng-unavailable" => "rng-unavailable",
        "deadline-readback-late" => "deadline-readback-late",
        _ => unreachable!(),
    };

    let observed = if case_id == "deadline-readback-late" {
        let claimant = SqliteReplayClaimantV1::open_or_create(
            root.config(),
            ExpireDuringReadbackClock::new(&root),
            OPEN_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("readback-late store open failed"));
        let _scenario = ClaimScenarioGuard::install(&root, scenario);
        observe_claim(&claimant, Feature002Variant::Coherent)
    } else {
        let claimant = open_store(&root, InjectedClock::coherent());
        let _scenario = ClaimScenarioGuard::install(&root, scenario);
        observe_claim(&claimant, Feature002Variant::Coherent)
    };

    let reopened = open_store(&root, InjectedClock::coherent());
    let claim_count = verified_count(&reopened);
    let generation: u64 = Connection::open(root.closed_database_path())
        .and_then(|connection| {
            connection.query_row(
                "SELECT claimant_generation FROM replay_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
        })
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| panic!("fault-case generation was unreadable"));
    assert_eq!(generation, claim_count);

    match case_id {
        "claim-commit-readback-absence" | "claim-rng-unavailable" => {
            assert_eq!(claim_count, 0);
            claim_actual(observed, claim_count)
        }
        "claim-commit-readback-exact" => {
            assert_eq!(claim_count, 1);
            claim_actual(observed, claim_count)
        }
        "claim-commit-readback-conflict" | "claim-commit-readback-prior" => {
            assert_eq!(claim_count, 1);
            claim_actual(observed, claim_count)
        }
        "claim-commit-readback-failed" => {
            assert!(matches!(observed, ObservedReplayOutcome::Ambiguous));
            assert_eq!(claim_count, 0);
            Actual::new("AMBIGUOUS", "ambiguous", "commit-unknown")
        }
        "deadline-readback-late" => {
            assert!(matches!(observed, ObservedReplayOutcome::Ambiguous));
            assert_eq!(claim_count, 1);
            Actual::new("AMBIGUOUS", "ambiguous", "commit-unknown")
        }
        "claim-generation-exhausted" => {
            assert!(matches!(observed, ObservedReplayOutcome::Unavailable));
            assert_eq!((generation, claim_count), (0, 0));
            Actual::new("UNAVAILABLE", "unavailable", "existing-claim-unchanged")
        }
        _ => unreachable!(),
    }
}

fn observe_claim<C: ReplayMonotonicClockV1>(
    claimant: &SqliteReplayClaimantV1<C>,
    variant: Feature002Variant,
) -> ObservedReplayOutcome {
    let (result, observed) = evaluate_with_observation(feature002_fixture(variant), claimant);
    if matches!(observed, ObservedReplayOutcome::Claimed { .. }) {
        assert!(result.is_ok());
    } else {
        assert!(result.is_err());
    }
    observed
}

fn assert_claimed<C: ReplayMonotonicClockV1>(
    claimant: &SqliteReplayClaimantV1<C>,
    variant: Feature002Variant,
) {
    assert!(matches!(
        observe_claim(claimant, variant),
        ObservedReplayOutcome::Claimed {
            receipt_matches_binding: true,
            claim_id_is_nonzero: true,
            ..
        }
    ));
}

fn verified_count<C: ReplayMonotonicClockV1>(claimant: &SqliteReplayClaimantV1<C>) -> u64 {
    claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("claim state verification failed"))
        .claim_count()
}

fn claim_actual(observed: ObservedReplayOutcome, claim_count: u64) -> Actual {
    let state = match claim_count {
        0 => "empty-store",
        1 => "one-complete-claim",
        2 => "two-complete-claims",
        _ => panic!("unexpected conformance claim count"),
    };
    match observed {
        ObservedReplayOutcome::Claimed {
            receipt_matches_binding: true,
            claim_id_is_nonzero: true,
            ..
        } => Actual::new("CLAIMED", "claimed", state),
        ObservedReplayOutcome::Claimed { .. } => panic!("claim receipt was malformed"),
        ObservedReplayOutcome::AlreadyClaimed => Actual::new(
            "ALREADY_CLAIMED",
            "already_claimed",
            "existing-claim-unchanged",
        ),
        ObservedReplayOutcome::BindingConflict => Actual::new(
            "BINDING_CONFLICT",
            "binding_conflict",
            "existing-claim-unchanged",
        ),
        ObservedReplayOutcome::Unavailable => Actual::new("UNAVAILABLE", "unavailable", state),
        ObservedReplayOutcome::Ambiguous => Actual::new("AMBIGUOUS", "ambiguous", state),
    }
}

#[derive(Clone, Copy)]
enum ContentionScenario {
    Exact,
    NonceConflict,
    OperationConflict,
    Independent,
}

impl ContentionScenario {
    fn variant(self, contender: usize) -> Feature002Variant {
        match self {
            Self::Exact => Feature002Variant::Coherent,
            Self::NonceConflict if contender.is_multiple_of(2) => Feature002Variant::Coherent,
            Self::NonceConflict => Feature002Variant::SameNonceDifferentOperation,
            Self::OperationConflict if contender.is_multiple_of(2) => Feature002Variant::Coherent,
            Self::OperationConflict => Feature002Variant::SameOperationDifferentNonce,
            Self::Independent if contender.is_multiple_of(2) => Feature002Variant::Coherent,
            Self::Independent => Feature002Variant::Independent,
        }
    }

    fn expected_claims(self) -> usize {
        match self {
            Self::Independent => 2,
            _ => 1,
        }
    }
}

fn contention_config(root: &SyntheticTempRoot) -> ReplayStoreConfigV1 {
    ReplayStoreConfigV1::try_new(
        root.trusted_root(),
        CONTENTION_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("contention configuration failed"))
}

fn run_contention_case(case_id: &str) -> Actual {
    let (scenario, process) = match case_id {
        "contention-independent-bindings" => (ContentionScenario::Independent, false),
        "contention-operation-conflict" => (ContentionScenario::OperationConflict, false),
        "contention-process-exact" => (ContentionScenario::Exact, true),
        "contention-thread-exact" => (ContentionScenario::Exact, false),
        "contention-thread-nonce-conflict" => (ContentionScenario::NonceConflict, false),
        _ => unreachable!(),
    };
    let root = SyntheticTempRoot::new(case_id);
    let claim_count = if process {
        drop(
            SqliteReplayClaimantV1::open_or_create(
                contention_config(&root),
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("process contention initialization failed")),
        );
        let variants = (0..PROCESS_CONTENDERS)
            .map(|index| scenario.variant(index))
            .collect::<Vec<_>>();
        let outcomes = run_process_round(root.path(), &variants);
        assert_eq!(outcomes.len(), PROCESS_CONTENDERS);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ProcessOutcome::Claimed))
                .count(),
            scenario.expected_claims()
        );
        let claimant = open_store(&root, InjectedClock::coherent());
        verified_count(&claimant)
    } else {
        let claimant = Arc::new(
            SqliteReplayClaimantV1::open_or_create(
                contention_config(&root),
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("thread contention initialization failed")),
        );
        let barrier = Arc::new(Barrier::new(THREAD_CONTENDERS));
        let mut handles = Vec::with_capacity(THREAD_CONTENDERS);
        for index in 0..THREAD_CONTENDERS {
            let claimant = Arc::clone(&claimant);
            let barrier = Arc::clone(&barrier);
            let variant = scenario.variant(index);
            handles.push(thread::spawn(move || {
                barrier.wait();
                observe_claim(claimant.as_ref(), variant)
            }));
        }
        let outcomes = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("thread contender panicked"))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ObservedReplayOutcome::Claimed { .. }))
                .count(),
            scenario.expected_claims()
        );
        verified_count(claimant.as_ref())
    };
    assert_eq!(claim_count as usize, scenario.expected_claims());
    let code = if matches!(scenario, ContentionScenario::Independent) {
        "ALL_INDEPENDENT_COMMITTED"
    } else {
        "ONE_DURABLE_WINNER"
    };
    let state = if claim_count == 2 {
        "two-complete-claims"
    } else {
        "one-complete-claim"
    };
    Actual::new(code, "verified", state)
}

#[test]
fn process_probe_worker() {
    let _worker_ran = process_probe::run_worker_if_requested();
}

fn run_backup_case(case_id: &str) -> Actual {
    let source = SyntheticTempRoot::new("corpus-backup-source");
    let destination = SyntheticTempRoot::new("corpus-backup-destination");
    let claimant = open_store(&source, InjectedClock::coherent());
    assert_claimed(&claimant, Feature002Variant::Coherent);
    match case_id {
        "backup-deadline-reached" => {
            let error = claimant
                .backup_v1(
                    destination.trusted_root(),
                    common::feature002::NOW_MONOTONIC_MS,
                )
                .expect_err("expired backup unexpectedly succeeded");
            assert_eq!(verified_count(&claimant), 1);
            Actual::new(error.code(), "rejected", "source-unchanged")
        }
        "backup-incomplete-staging" => {
            let retained_backup_root = destination.trusted_root();
            write_new_synced_file(
                &destination.path().join(ROOT_LOCK_FILENAME),
                BACKUP_PACKAGE_LOCK_CONTENT,
            );
            write_new_synced_file(
                &destination.path().join(BACKUP_STAGING_DATABASE_FILENAME),
                b"incomplete SQLite backup staging member",
            );
            let error = verify_replay_backup_v1(
                retained_backup_root,
                &InjectedClock::coherent(),
                MAINTENANCE_DEADLINE_MONOTONIC_MS,
            )
            .expect_err("incomplete staging package unexpectedly verified");
            assert_eq!(verified_count(&claimant), 1);
            assert_eq!(
                fs::read(destination.path().join(ROOT_LOCK_FILENAME))
                    .unwrap_or_else(|_| panic!("backup package role became unreadable")),
                BACKUP_PACKAGE_LOCK_CONTENT
            );
            assert!(destination
                .path()
                .join(BACKUP_STAGING_DATABASE_FILENAME)
                .is_file());
            Actual::new(error.code(), "rejected", "source-unchanged")
        }
        "backup-live-consistent" => {
            let evidence = claimant
                .backup_v1(
                    destination.trusted_root(),
                    MAINTENANCE_DEADLINE_MONOTONIC_MS,
                )
                .unwrap_or_else(|_| panic!("live backup failed"));
            assert_eq!(evidence.claim_count(), 1);
            let (_, manifest) = package_members(&destination);
            assert_eq!(manifest.claim_count(), 1);
            Actual::new("BACKUP_VERIFIED", "verified", "valid-backup")
        }
        _ => unreachable!(),
    }
}

fn write_new_synced_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|_| panic!("corpus fixture file creation failed"));
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .unwrap_or_else(|_| panic!("corpus fixture file publication failed"));
}

fn run_maintenance_case(case_id: &str) -> Actual {
    let root = SyntheticTempRoot::new("corpus-maintenance");
    let claimant = open_store(&root, InjectedClock::coherent());
    match case_id {
        "maintenance-deadline-reached" => {
            let error = claimant
                .verify_integrity_v1(common::feature002::NOW_MONOTONIC_MS)
                .expect_err("expired verification unexpectedly succeeded");
            Actual::new(error.code(), "rejected", "source-unchanged")
        }
        "maintenance-verify-healthy" => {
            let evidence = claimant
                .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
                .unwrap_or_else(|_| panic!("healthy verification failed"));
            assert_eq!(evidence.claim_count(), 0);
            Actual::new("STORE_VERIFIED", "verified", "healthy-store")
        }
        _ => unreachable!(),
    }
}

fn run_initialization_case(case_id: &str) -> Actual {
    match case_id {
        "initialization-clock-unavailable" => {
            let root = SyntheticTempRoot::new("corpus-init-clock-unavailable");
            let error = SqliteReplayClaimantV1::open_or_create(
                root.config(),
                AlwaysUnavailableClock,
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .expect_err("clock-unavailable initialization succeeded");
            assert!(root.closed_database_path_if_present().is_none());
            Actual::new(error.code(), "rejected", "no-store")
        }
        "initialization-deadline-reached" => {
            let root = SyntheticTempRoot::new("corpus-init-deadline");
            let error = SqliteReplayClaimantV1::open_or_create(
                root.config(),
                InjectedClock::coherent(),
                common::feature002::NOW_MONOTONIC_MS,
            )
            .expect_err("expired initialization succeeded");
            assert!(root.closed_database_path_if_present().is_none());
            Actual::new(error.code(), "rejected", "no-store")
        }
        "initialization-durability-profile-unavailable" => {
            #[cfg(feature = "test-fault-injection")]
            {
                let root = SyntheticTempRoot::new("corpus-init-profile-unavailable");
                let code = run_feature_fault_worker(case_id, &root, None);
                assert!(
                    !contains_valid_v1_schema(root.path()),
                    "profile failure left a valid initialized replay store"
                );
                Actual {
                    code,
                    outcome: "rejected".to_owned(),
                    state: "no-store".to_owned(),
                }
            }
            #[cfg(not(feature = "test-fault-injection"))]
            unreachable!("private initialization fault case was not blocklisted")
        }
        "initialization-empty-v1" => {
            let root = SyntheticTempRoot::new("corpus-init-empty");
            let claimant = open_store(&root, InjectedClock::coherent());
            assert_eq!(verified_count(&claimant), 0);
            Actual::new("STORE_INITIALIZED", "verified", "healthy-store")
        }
        "initialization-concurrent" => {
            let root = SyntheticTempRoot::new("corpus-init-concurrent");
            let path = Arc::new(root.path().to_path_buf());
            let barrier = Arc::new(Barrier::new(2));
            let mut handles = Vec::new();
            for _ in 0..2 {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                handles.push(thread::spawn(move || {
                    let trusted = TrustedLocalStoreRootV1::try_from_provisioned((*path).clone())
                        .unwrap_or_else(|_| panic!("concurrent root rejected"));
                    // This proves convergence, not a 250 ms scheduling oracle. Production
                    // retains its independent, deadline-checked 5,000-attempt setup-gate cap.
                    let config = ReplayStoreConfigV1::try_new(
                        trusted,
                        INITIALIZATION_CORRECTNESS_BUSY_WAIT_MS,
                        16,
                        1,
                    )
                    .unwrap_or_else(|_| panic!("concurrent config rejected"));
                    barrier.wait();
                    SqliteReplayClaimantV1::open_or_create(
                        config,
                        InjectedClock::coherent(),
                        OPEN_DEADLINE_MONOTONIC_MS,
                    )
                }));
            }
            for handle in handles {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("concurrent initializer panicked"))
                    .unwrap_or_else(|error| {
                        panic!("concurrent initializer failed: {}", error.code())
                    });
            }
            let claimant = open_store(&root, InjectedClock::coherent());
            assert_eq!(verified_count(&claimant), 0);
            Actual::new("STORE_INITIALIZED", "verified", "healthy-store")
        }
        "initialization-invalid-backup-step" => {
            let root = SyntheticTempRoot::new("corpus-init-invalid-step");
            let error = ReplayStoreConfigV1::try_new(
                root.trusted_root(),
                DEFAULT_BUSY_WAIT_MS,
                0,
                DEFAULT_BACKUP_RETRY_WAIT_MS,
            )
            .expect_err("zero backup step accepted");
            Actual::new(error.code(), "rejected", "no-store")
        }
        "initialization-invalid-backup-wait" => {
            let root = SyntheticTempRoot::new("corpus-init-invalid-wait");
            let error = ReplayStoreConfigV1::try_new(
                root.trusted_root(),
                DEFAULT_BUSY_WAIT_MS,
                DEFAULT_BACKUP_STEP_PAGES,
                1_001,
            )
            .expect_err("excessive backup wait accepted");
            Actual::new(error.code(), "rejected", "no-store")
        }
        "initialization-invalid-busy-bound" => {
            let root = SyntheticTempRoot::new("corpus-init-invalid-busy");
            let error = ReplayStoreConfigV1::try_new(
                root.trusted_root(),
                0,
                DEFAULT_BACKUP_STEP_PAGES,
                DEFAULT_BACKUP_RETRY_WAIT_MS,
            )
            .expect_err("zero busy bound accepted");
            Actual::new(error.code(), "rejected", "no-store")
        }
        "initialization-location-invalid" => {
            let error = TrustedLocalStoreRootV1::try_from_provisioned(PathBuf::from("relative"))
                .expect_err("relative root accepted");
            Actual::new(error.code(), "rejected", "no-store")
        }
        "initialization-location-not-dedicated" => {
            let root = SyntheticTempRoot::new("corpus-init-foreign");
            root.create_foreign_file();
            let error = TrustedLocalStoreRootV1::try_from_provisioned(root.path().to_path_buf())
                .expect_err("foreign root accepted");
            Actual::new(error.code(), "rejected", "no-store")
        }
        "initialization-store-busy" => {
            let root = SyntheticTempRoot::new("corpus-init-busy");
            drop(open_store(&root, InjectedClock::coherent()));
            let blocker = Connection::open(root.closed_database_path())
                .unwrap_or_else(|_| panic!("init-busy blocker open failed"));
            blocker
                .execute_batch("BEGIN IMMEDIATE")
                .unwrap_or_else(|_| panic!("init-busy blocker acquisition failed"));
            let config = ReplayStoreConfigV1::try_new(
                root.trusted_root(),
                10,
                DEFAULT_BACKUP_STEP_PAGES,
                DEFAULT_BACKUP_RETRY_WAIT_MS,
            )
            .unwrap_or_else(|_| panic!("init-busy config failed"));
            let error = SqliteReplayClaimantV1::open_or_create(
                config,
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .expect_err("busy store opened");
            blocker
                .execute_batch("ROLLBACK")
                .unwrap_or_else(|_| panic!("init-busy blocker release failed"));
            Actual::new(error.code(), "rejected", "source-unchanged")
        }
        "initialization-store-unavailable" => {
            #[cfg(feature = "test-fault-injection")]
            {
                let root = SyntheticTempRoot::new("corpus-init-unavailable");
                assert!(
                    fs::read_dir(root.path())
                        .unwrap_or_else(|_| panic!("unavailable root preflight failed"))
                        .next()
                        .is_none(),
                    "provider-fault fixture was not initially empty"
                );
                let code = run_feature_fault_worker(case_id, &root, None);
                assert!(
                    fs::read_dir(root.path())
                        .unwrap_or_else(|_| panic!("provider-fault root became unreadable"))
                        .next()
                        .is_none(),
                    "provider-open failure mutated the dedicated root"
                );
                Actual {
                    code,
                    outcome: "rejected".to_owned(),
                    state: "source-unchanged".to_owned(),
                }
            }
            #[cfg(not(feature = "test-fault-injection"))]
            unreachable!("private initialization fault case was not blocklisted")
        }
        "migration-newer-schema-refused" => {
            let root = SyntheticTempRoot::new("corpus-newer-schema");
            drop(open_store(&root, InjectedClock::coherent()));
            let connection = Connection::open(root.closed_database_path())
                .unwrap_or_else(|_| panic!("newer-schema fixture open failed"));
            connection
                .pragma_update(None, "user_version", REPLAY_STORE_SCHEMA_VERSION_V1 + 1)
                .unwrap_or_else(|_| panic!("newer-schema mutation failed"));
            drop(connection);
            let error = SqliteReplayClaimantV1::open_or_create(
                root.config(),
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .expect_err("newer schema opened");
            Actual::new(error.code(), "rejected", "source-unchanged")
        }
        _ => unreachable!(),
    }
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

fn run_corruption_case(case_id: &str) -> Actual {
    let root = SyntheticTempRoot::new(case_id);
    let claimant = open_store(&root, InjectedClock::coherent());
    let database = root.closed_database_path();
    match case_id {
        "corruption-application-id-mismatch" => {
            drop(claimant);
            let connection = Connection::open(&database)
                .unwrap_or_else(|_| panic!("application-id corruption open failed"));
            connection
                .pragma_update(None, "application_id", REPLAY_STORE_APPLICATION_ID_V1 + 1)
                .unwrap_or_else(|_| panic!("application-id corruption failed"));
            drop(connection);
            open_corrupt_actual(&root)
        }
        "corruption-integrity-failed" => {
            let connection = Connection::open(&database)
                .unwrap_or_else(|_| panic!("integrity corruption open failed"));
            connection
                .execute_batch(
                    "PRAGMA ignore_check_constraints = ON;
                     BEGIN IMMEDIATE;
                     UPDATE replay_store_meta SET claimant_generation = 1 WHERE singleton = 1;
                     INSERT INTO replay_claims (
                       instance_epoch, nonce, operation_id, binding_digest, claim_id,
                       claimant_generation
                     ) VALUES (
                       1, X'111111111111111111111111111111', 'operation:corpus-integrity',
                       X'2222222222222222222222222222222222222222222222222222222222222222',
                       X'3333333333333333333333333333333333333333333333333333333333333333', 1
                     );
                     COMMIT;
                     PRAGMA ignore_check_constraints = OFF;",
                )
                .unwrap_or_else(|_| panic!("integrity corruption failed"));
            drop(connection);
            let error = claimant
                .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
                .expect_err("integrity corruption verified");
            Actual::new(error.code(), "rejected", "store-unhealthy")
        }
        "corruption-invalid-row" | "corruption-invariant-failed" => {
            let connection = Connection::open(&database)
                .unwrap_or_else(|_| panic!("invariant corruption open failed"));
            connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     UPDATE replay_store_meta SET claimant_generation = 2 WHERE singleton = 1;
                     INSERT INTO replay_claims (
                       instance_epoch, nonce, operation_id, binding_digest, claim_id,
                       claimant_generation
                     ) VALUES (
                       1, X'44444444444444444444444444444444', 'operation:corpus-gap',
                       X'5555555555555555555555555555555555555555555555555555555555555555',
                       X'6666666666666666666666666666666666666666666666666666666666666666', 2
                     );
                     COMMIT;",
                )
                .unwrap_or_else(|_| panic!("invariant corruption failed"));
            drop(connection);
            if case_id == "corruption-invalid-row" {
                drop(claimant);
                open_corrupt_actual(&root)
            } else {
                let error = claimant
                    .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
                    .expect_err("invariant corruption verified");
                Actual::new(error.code(), "rejected", "store-unhealthy")
            }
        }
        "corruption-schema-altered" => {
            drop(claimant);
            let connection = Connection::open(&database)
                .unwrap_or_else(|_| panic!("schema corruption open failed"));
            connection
                .execute_batch("DROP INDEX replay_claims_operation_id_uq")
                .unwrap_or_else(|_| panic!("schema corruption failed"));
            drop(connection);
            open_corrupt_actual(&root)
        }
        "corruption-truncated-database" => {
            drop(claimant);
            populate_then_truncate_last_page(&database);
            open_corrupt_actual(&root)
        }
        _ => unreachable!(),
    }
}

fn open_corrupt_actual(root: &SyntheticTempRoot) -> Actual {
    let error = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("corrupt store opened");
    Actual::new(error.code(), "rejected", "store-unhealthy")
}

fn populate_then_truncate_last_page(database: &Path) {
    let mut connection =
        Connection::open(database).unwrap_or_else(|_| panic!("truncation population open failed"));
    let transaction = connection
        .transaction()
        .unwrap_or_else(|_| panic!("truncation population transaction failed"));
    for generation in 1_i64..=512 {
        let mut nonce = [0_u8; 16];
        nonce[..8].copy_from_slice(&(generation as u64).to_be_bytes());
        let mut digest = [0x55_u8; 32];
        digest[..8].copy_from_slice(&(generation as u64).to_be_bytes());
        let mut claim_id = [0x66_u8; 32];
        claim_id[..8].copy_from_slice(&(generation as u64).to_be_bytes());
        transaction
            .execute(
                "INSERT INTO replay_claims (
                   instance_epoch, nonce, operation_id, binding_digest, claim_id,
                   claimant_generation
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    1_i64,
                    &nonce[..],
                    format!("operation:corpus-truncate-{generation:04}"),
                    &digest[..],
                    &claim_id[..],
                    generation,
                ],
            )
            .unwrap_or_else(|_| panic!("truncation population insert failed"));
    }
    transaction
        .execute(
            "UPDATE replay_store_meta SET claimant_generation = 512 WHERE singleton = 1",
            [],
        )
        .unwrap_or_else(|_| panic!("truncation population metadata failed"));
    transaction
        .commit()
        .unwrap_or_else(|_| panic!("truncation population commit failed"));
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap_or_else(|_| panic!("truncation checkpoint failed"));
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap_or_else(|_| panic!("truncation page size read failed"));
    drop(connection);
    let file = OpenOptions::new()
        .write(true)
        .open(database)
        .unwrap_or_else(|_| panic!("truncation file open failed"));
    let length = file
        .metadata()
        .unwrap_or_else(|_| panic!("truncation metadata failed"))
        .len();
    assert!(length > page_size as u64 * 4);
    file.set_len(length - page_size as u64)
        .and_then(|()| file.sync_all())
        .unwrap_or_else(|_| panic!("truncation failed"));
}

fn package_members(root: &SyntheticTempRoot) -> (PathBuf, BackupManifestV1) {
    let mut database = None;
    let mut manifest = None;
    for entry in
        fs::read_dir(root.path()).unwrap_or_else(|_| panic!("backup package enumeration failed"))
    {
        let path = entry
            .unwrap_or_else(|_| panic!("backup package entry failed"))
            .path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).unwrap_or_else(|_| panic!("backup package read failed"));
        if bytes.get(..SQLITE_HEADER.len()) == Some(SQLITE_HEADER.as_slice()) {
            assert!(database.replace(path).is_none());
        } else if let Ok(decoded) = BackupManifestV1::decode_v1(&bytes) {
            assert!(manifest.replace(decoded).is_none());
        }
    }
    (
        database.unwrap_or_else(|| panic!("backup database missing")),
        manifest.unwrap_or_else(|| panic!("backup manifest missing")),
    )
}

fn successful_backup(source: &SyntheticTempRoot, package: &SyntheticTempRoot) {
    let claimant = open_store(source, InjectedClock::coherent());
    assert_claimed(&claimant, Feature002Variant::Coherent);
    claimant
        .backup_v1(package.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("fixture backup failed"));
}

fn run_restore_case(case_id: &str) -> Actual {
    let source = SyntheticTempRoot::new("corpus-restore-source");
    let package = SyntheticTempRoot::new("corpus-restore-package");
    let destination = SyntheticTempRoot::new("corpus-restore-destination");
    let package_root = package.trusted_root();
    let same_root_config = package.config();
    successful_backup(&source, &package);
    let (database, _) = package_members(&package);

    match case_id {
        "restore-backup-incomplete" => {
            fs::remove_file(database)
                .unwrap_or_else(|_| panic!("incomplete backup mutation failed"));
            restore_error_actual(package_root, destination.config(), "no-store")
        }
        "restore-database-digest-mismatch" => {
            OpenOptions::new()
                .append(true)
                .open(database)
                .and_then(|mut file| file.write_all(b"digest-mismatch"))
                .unwrap_or_else(|_| panic!("digest mismatch mutation failed"));
            restore_error_actual(package_root, destination.config(), "no-store")
        }
        "restore-destination-not-empty" => {
            let destination_config = destination.config();
            destination.create_foreign_file();
            restore_error_actual(package_root, destination_config, "source-unchanged")
        }
        "restore-incomplete" => {
            #[cfg(feature = "test-fault-injection")]
            {
                let destination_config = destination.config();
                let code = run_feature_fault_worker(case_id, &destination, Some(&package));
                assert_eq!(
                    fs::read(destination.path().join(ROOT_LOCK_FILENAME))
                        .unwrap_or_else(|_| panic!("pending restore role was unreadable")),
                    RESTORE_PENDING_LOCK_CONTENT
                );
                assert_eq!(
                    fs::read(destination.path().join(ACTIVATION_MARKER_FILENAME))
                        .unwrap_or_else(|_| panic!("pending restore marker was unreadable")),
                    RESTORED_ACTIVATION_MARKER_CONTENT
                );
                assert!(!destination.path().join("replay.sqlite3").exists());
                assert!(!destination
                    .path()
                    .join(RESTORE_STAGING_DATABASE_FILENAME)
                    .exists());
                let open_error = SqliteReplayClaimantV1::open_or_create(
                    destination_config,
                    InjectedClock::coherent(),
                    OPEN_DEADLINE_MONOTONIC_MS,
                )
                .expect_err("RESTORE_PENDING destination became claimable");
                assert_eq!(open_error.code(), "LOCATION_NOT_DEDICATED");
                Actual {
                    code,
                    outcome: "rejected".to_owned(),
                    state: "no-store".to_owned(),
                }
            }
            #[cfg(not(feature = "test-fault-injection"))]
            unreachable!("private restore fault case was not blocklisted")
        }
        "restore-manifest-invalid" => {
            let manifest_path = fs::read_dir(package.path())
                .unwrap_or_else(|_| panic!("manifest enumeration failed"))
                .map(|entry| {
                    entry
                        .unwrap_or_else(|_| panic!("manifest entry failed"))
                        .path()
                })
                .find(|path| {
                    fs::read(path)
                        .ok()
                        .is_some_and(|bytes| BackupManifestV1::decode_v1(&bytes).is_ok())
                })
                .unwrap_or_else(|| panic!("manifest path missing"));
            fs::write(manifest_path, b"{}")
                .unwrap_or_else(|_| panic!("invalid manifest mutation failed"));
            restore_error_actual(package_root, destination.config(), "no-store")
        }
        "restore-manifest-missing" => {
            let manifest_path = fs::read_dir(package.path())
                .unwrap_or_else(|_| panic!("manifest enumeration failed"))
                .map(|entry| {
                    entry
                        .unwrap_or_else(|_| panic!("manifest entry failed"))
                        .path()
                })
                .find(|path| {
                    fs::read(path)
                        .ok()
                        .is_some_and(|bytes| BackupManifestV1::decode_v1(&bytes).is_ok())
                })
                .unwrap_or_else(|| panic!("manifest path missing"));
            fs::remove_file(manifest_path)
                .unwrap_or_else(|_| panic!("missing manifest mutation failed"));
            restore_error_actual(package_root, destination.config(), "no-store")
        }
        "restore-source-destination-conflict" => {
            restore_error_actual(package_root, same_root_config, "source-unchanged")
        }
        "restore-valid-clean-root" => {
            let evidence = restore_replay_store_v1(
                package_root,
                destination.config(),
                &InjectedClock::coherent(),
                MAINTENANCE_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("valid restore failed"));
            assert_eq!(evidence.claim_count(), 1);
            assert!(evidence.requires_paused_activation());
            assert!(evidence.requires_instance_epoch_rotation());
            assert!(evidence.requires_fencing_epoch_rotation());
            Actual::new("RESTORE_VERIFIED", "verified", "verified-restore")
        }
        _ => unreachable!(),
    }
}

fn restore_error_actual(
    backup: TrustedLocalStoreRootV1,
    destination: ReplayStoreConfigV1,
    state: &str,
) -> Actual {
    let error = restore_replay_store_v1(
        backup,
        destination,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("invalid restore succeeded");
    Actual::new(error.code(), "rejected", state)
}

#[cfg(feature = "test-fault-injection")]
fn run_feature_fault_worker(
    case_id: &str,
    root: &SyntheticTempRoot,
    package: Option<&SyntheticTempRoot>,
) -> String {
    let executable =
        std::env::current_exe().unwrap_or_else(|_| panic!("feature-fault executable unavailable"));
    let mut command = Command::new(executable);
    command
        .args([
            "--exact",
            "corpus_feature_fault_worker",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_remove(WORKER_ENV)
        .env_remove(FAULT_ENV)
        .env_remove(CLAIM_SCENARIO_ENV)
        .env_remove(INITIALIZATION_FAULT_ENV)
        .env_remove(RETURN_ERROR_ENV)
        .env_remove(FEATURE_FAULT_PACKAGE_ENV)
        .env(FEATURE_FAULT_WORKER_ENV, "1")
        .env(FEATURE_FAULT_CASE_ENV, case_id)
        .env(ROOT_ENV, root.path());
    match case_id {
        "initialization-durability-profile-unavailable" => {
            command.env(INITIALIZATION_FAULT_ENV, "writable_profile_unavailable");
        }
        "initialization-store-unavailable" => {
            command.env(INITIALIZATION_FAULT_ENV, "provider_open_unavailable");
        }
        "restore-incomplete" => {
            let package = package.unwrap_or_else(|| panic!("restore fault package missing"));
            command
                .env(RETURN_ERROR_ENV, "restore_before_copy")
                .env(FEATURE_FAULT_PACKAGE_ENV, package.path());
        }
        _ => unreachable!(),
    }
    let output = command
        .output()
        .unwrap_or_else(|_| panic!("feature-fault worker could not start"));
    assert!(
        output.status.success(),
        "feature-fault worker failed for {case_id}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let codes = stdout
        .split(FEATURE_FAULT_RESULT_PREFIX)
        .skip(1)
        .filter_map(|suffix| suffix.split_whitespace().next())
        .collect::<Vec<_>>();
    assert_eq!(
        codes.len(),
        1,
        "feature-fault worker returned no unique actual code for {case_id}: {stdout}"
    );
    codes[0].to_owned()
}

#[cfg(feature = "test-fault-injection")]
#[test]
#[ignore = "private corpus feature-fault entry point"]
fn corpus_feature_fault_worker() {
    if std::env::var(FEATURE_FAULT_WORKER_ENV).ok().as_deref() != Some("1") {
        return;
    }
    let case_id = std::env::var(FEATURE_FAULT_CASE_ENV)
        .unwrap_or_else(|_| panic!("feature-fault case missing"));
    let root = std::env::var_os(ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("feature-fault root missing"));
    let trusted = TrustedLocalStoreRootV1::try_from_provisioned(root)
        .unwrap_or_else(|_| panic!("feature-fault root rejected"));
    let config = ReplayStoreConfigV1::try_new(
        trusted,
        DEFAULT_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("feature-fault config rejected"));
    let code = match case_id.as_str() {
        "initialization-durability-profile-unavailable" | "initialization-store-unavailable" => {
            SqliteReplayClaimantV1::open_or_create(
                config,
                InjectedClock::coherent(),
                OPEN_DEADLINE_MONOTONIC_MS,
            )
            .expect_err("injected initialization unexpectedly succeeded")
            .code()
            .to_owned()
        }
        "restore-incomplete" => {
            let package = std::env::var_os(FEATURE_FAULT_PACKAGE_ENV)
                .map(PathBuf::from)
                .unwrap_or_else(|| panic!("feature-fault package missing"));
            let package = TrustedLocalStoreRootV1::try_from_provisioned(package)
                .unwrap_or_else(|_| panic!("feature-fault package rejected"));
            restore_replay_store_v1(
                package,
                config,
                &InjectedClock::coherent(),
                MAINTENANCE_DEADLINE_MONOTONIC_MS,
            )
            .expect_err("injected restore unexpectedly succeeded")
            .code()
            .to_owned()
        }
        _ => panic!("unsupported feature-fault case {case_id}"),
    };
    println!("{FEATURE_FAULT_RESULT_PREFIX}{code}");
}

#[cfg(feature = "test-fault-injection")]
fn run_crash_case(case_id: &str) -> Actual {
    let phase = case_id
        .strip_prefix("crash-")
        .unwrap_or_else(|| unreachable!());
    if phase.starts_with("backup-") {
        let phase = phase.replace('-', "_");
        let source = SyntheticTempRoot::new("corpus-crash-backup-source");
        let package = SyntheticTempRoot::new("corpus-crash-backup-package");
        kill_worker_at_phase(&source, Some(&package), &phase);
        let claimant = open_store(&source, InjectedClock::coherent());
        assert_eq!(verified_count(&claimant), 1);
        if phase == "backup_published" {
            let (_, manifest) = package_members(&package);
            assert_eq!(manifest.claim_count(), 1);
            Actual::new("PROCESS_CRASH_RECOVERED", "recovered", "valid-backup")
        } else {
            Actual::new("PROCESS_CRASH_RECOVERED", "recovered", "source-unchanged")
        }
    } else {
        let phase = phase.replace('-', "_");
        let root = SyntheticTempRoot::new("corpus-crash-claim");
        kill_worker_at_phase(&root, None, &phase);
        let claimant = open_store(&root, InjectedClock::coherent());
        let count = verified_count(&claimant);
        let committed = matches!(phase.as_str(), "commit_returned" | "before_result_ack");
        assert_eq!(count, u64::from(committed));
        Actual::new(
            "PROCESS_CRASH_RECOVERED",
            "recovered",
            if committed {
                "one-complete-claim"
            } else {
                "empty-store"
            },
        )
    }
}

#[cfg(not(feature = "test-fault-injection"))]
fn run_crash_case(_case_id: &str) -> Actual {
    unreachable!("crash cases are blocklisted without the fault feature")
}

#[test]
#[ignore = "private corpus process-fault entry point"]
fn corpus_fault_worker_process() {
    if std::env::var(WORKER_ENV).ok().as_deref() != Some("fault") {
        return;
    }
    let root = std::env::var_os(ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("fault worker root missing"));
    let trusted = TrustedLocalStoreRootV1::try_from_provisioned(root)
        .unwrap_or_else(|_| panic!("fault worker root rejected"));
    let config = ReplayStoreConfigV1::try_new(
        trusted,
        DEFAULT_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("fault worker config rejected"));
    let claimant = SqliteReplayClaimantV1::open_or_create(
        config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("fault worker open failed"));
    let _ = feature002_fixture(Feature002Variant::Coherent).evaluate(&claimant);
    if std::env::var(FAULT_ENV)
        .unwrap_or_default()
        .starts_with("backup_")
    {
        let backup = std::env::var_os(BACKUP_ROOT_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("fault worker backup root missing"));
        let trusted = TrustedLocalStoreRootV1::try_from_provisioned(backup)
            .unwrap_or_else(|_| panic!("fault worker backup root rejected"));
        claimant
            .backup_v1(trusted, MAINTENANCE_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("fault worker backup failed"));
    }
}

#[cfg(feature = "test-fault-injection")]
fn kill_worker_at_phase(
    source: &SyntheticTempRoot,
    backup: Option<&SyntheticTempRoot>,
    phase: &str,
) {
    let executable =
        std::env::current_exe().unwrap_or_else(|_| panic!("fault worker executable unavailable"));
    let mut command = Command::new(executable);
    command
        .args([
            "--exact",
            "corpus_fault_worker_process",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(WORKER_ENV, "fault")
        .env(ROOT_ENV, source.path())
        .env(FAULT_ENV, phase)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(backup) = backup {
        command.env(BACKUP_ROOT_ENV, backup.path());
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|_| panic!("fault worker spawn failed"));
    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("fault worker stdout unavailable"));
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    let expected = format!("AT:{phase}");
    let reached = (0..64).any(|_| {
        receiver
            .recv_timeout(Duration::from_millis(250))
            .is_ok_and(|line| line.contains(&expected))
    });
    if !reached {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        panic!("fault worker did not reach {phase}");
    }
    child
        .kill()
        .unwrap_or_else(|_| panic!("fault worker kill failed"));
    child
        .wait()
        .unwrap_or_else(|_| panic!("fault worker reap failed"));
    reader
        .join()
        .unwrap_or_else(|_| panic!("fault worker reader failed"));
}
