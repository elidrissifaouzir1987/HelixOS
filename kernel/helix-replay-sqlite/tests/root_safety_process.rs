//! Cross-process initialization and waiting-writer root-state proofs.
//!
//! The process-kill case is an OS process-crash test. Its exact kill phase is
//! scheduler-dependent and it is deliberately not described as power-loss evidence.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, DEFAULT_BACKUP_RETRY_WAIT_MS,
    DEFAULT_BACKUP_STEP_PAGES, MAINTENANCE_DEADLINE_MONOTONIC_MS, OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_replay_sqlite::{
    ReplayClockUnavailableV1, ReplayMonotonicClockV1, ReplayStoreConfigV1, SqliteReplayClaimantV1,
    TrustedLocalStoreRootV1,
};
use rusqlite::{Connection, OpenFlags};
use std::fs::OpenOptions;
use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

const ROOT_LOCK_FILENAME: &str = ".helix-replay-root-v1.lock";
const LIVE_INITIALIZATION_INTENT_FILENAME: &str = ".helix-replay-live-initializing-v1";
const QUARANTINE_MARKER_FILENAME: &str = ".helix-replay-quarantined-v1";
const LIVE_READY_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=LIVE_READY\n";
const LIVE_QUARANTINED_LOCK_CONTENT: &[u8] =
    b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=LIVE_QUARANTINED\n";
const QUARANTINE_MARKER_CONTENT: &[u8] = b"HELIXOS_REPLAY_QUARANTINE_V1\n";

const CLAIM_BUSY_WAIT_MS: u64 = 5_000;
const CLAIM_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const CLAIM_BLOCK_OBSERVATION: Duration = Duration::from_millis(50);
const PROCESS_WATCHDOG: Duration = Duration::from_secs(20);
const INITIALIZER_COUNT: usize = 6;

const INITIALIZER_WORKER_ENV: &str = "HELIX_REPLAY_INITIALIZER_WORKER";
const INITIALIZER_ROOT_ENV: &str = "HELIX_REPLAY_INITIALIZER_ROOT";
const WORKER_READY: &str = "HELIX_INIT_READY";
const WORKER_STARTING: &str = "HELIX_INIT_STARTING";
const WORKER_OK: &str = "HELIX_INIT_OK";
const WORKER_GO: u8 = b'G';
const WORKER_EXIT: u8 = b'X';

#[test]
fn zero_role_is_recovered_only_with_distinct_live_initialization_intent() {
    let ambiguous = SyntheticTempRoot::new("zero-role-without-live-intent");
    let ambiguous_config = ambiguous.config();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ambiguous.path().join(ROOT_LOCK_FILENAME))
        .unwrap_or_else(|_| panic!("ambiguous zero-role fixture creation failed"));
    let error = SqliteReplayClaimantV1::open_or_create(
        ambiguous_config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("zero role without live intent was promoted"));
    assert_eq!(error.code(), "LOCATION_NOT_DEDICATED");
    assert!(!ambiguous.path().join("replay.sqlite3").exists());

    let recoverable = SyntheticTempRoot::new("zero-role-with-live-intent");
    let recoverable_config = recoverable.config();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(recoverable.path().join(LIVE_INITIALIZATION_INTENT_FILENAME))
        .unwrap_or_else(|_| panic!("live-intent fixture creation failed"));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(recoverable.path().join(ROOT_LOCK_FILENAME))
        .unwrap_or_else(|_| panic!("recoverable zero-role fixture creation failed"));

    let claimant = SqliteReplayClaimantV1::open_or_create(
        recoverable_config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("distinct live initialization reservation did not recover"));
    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("recovered live initialization failed verification"));
    assert_eq!(verification.claim_count(), 0);
    assert_eq!(verification.claimant_generation(), 0);
    assert!(!recoverable
        .path()
        .join(LIVE_INITIALIZATION_INTENT_FILENAME)
        .exists());
    assert_eq!(
        std::fs::read(recoverable.path().join(ROOT_LOCK_FILENAME))
            .unwrap_or_else(|_| panic!("recovered live role could not be read")),
        LIVE_READY_LOCK_CONTENT
    );
}

/// The ninth post-arm clock sample is the final deadline sample returned by
/// `open_existing_for_claim` on the already initialized, uncontended root path.
/// Reaching it proves the claimant released its first LIVE_READY lease. With a
/// test-side BEGIN IMMEDIATE still held, it cannot acquire its writer transaction.
const POST_PREFLIGHT_CLOCK_SAMPLE: u64 = 9;

#[derive(Clone)]
struct ProbeClock {
    now_monotonic_ms: u64,
    calls: Arc<AtomicU64>,
    armed: Arc<AtomicBool>,
    samples: mpsc::Sender<u64>,
}

impl ProbeClock {
    fn new(now_monotonic_ms: u64, samples: mpsc::Sender<u64>) -> Self {
        Self {
            now_monotonic_ms,
            calls: Arc::new(AtomicU64::new(0)),
            armed: Arc::new(AtomicBool::new(false)),
            samples,
        }
    }

    fn arm(&self) {
        self.calls.store(0, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl ReplayMonotonicClockV1 for ProbeClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        let sample = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.armed.load(Ordering::SeqCst) {
            let _ignored = self.samples.send(sample);
        }
        Ok(self.now_monotonic_ms)
    }
}

#[test]
fn waiting_writer_rechecks_durable_root_state_after_begin() {
    let root = SyntheticTempRoot::new("waiting-writer-root-state");
    let (sample_sender, sample_receiver) = mpsc::channel();
    let clock = ProbeClock::new(common::feature002::NOW_MONOTONIC_MS, sample_sender);
    let config = ReplayStoreConfigV1::try_new(
        root.trusted_root(),
        CLAIM_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("waiting-writer configuration was rejected"));
    let claimant =
        SqliteReplayClaimantV1::open_or_create(config, clock.clone(), OPEN_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("waiting-writer store initialization failed"));

    let database_path = root.closed_database_path();
    let writer = Connection::open(&database_path)
        .unwrap_or_else(|_| panic!("waiting-writer test connection failed to open"));
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap_or_else(|_| panic!("waiting-writer test could not hold BEGIN IMMEDIATE"));

    clock.arm();
    let (outcome_sender, outcome_receiver) = mpsc::channel();
    let claim_thread = thread::spawn(move || {
        let (result, observed) =
            evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
        let _ignored = outcome_sender.send((result.is_ok(), observed));
    });

    wait_for_post_preflight_sample(&sample_receiver);
    assert!(
        matches!(
            outcome_receiver.recv_timeout(CLAIM_BLOCK_OBSERVATION),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "claimant returned while the test-side SQLite writer was still held"
    );

    transition_live_root_to_quarantined(root.path());
    writer
        .execute_batch("ROLLBACK")
        .unwrap_or_else(|_| panic!("waiting-writer test could not release SQLite writer"));

    let (eligible, observed) = outcome_receiver
        .recv_timeout(CLAIM_PROBE_TIMEOUT)
        .unwrap_or_else(|_| panic!("waiting claimant did not finish within the watchdog"));
    claim_thread
        .join()
        .unwrap_or_else(|_| panic!("waiting claimant thread panicked"));
    assert!(!eligible, "quarantined waiting claimant was admitted");
    assert_eq!(observed, ObservedReplayOutcome::Unavailable);

    let inspection = Connection::open_with_flags(
        &database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap_or_else(|_| panic!("quarantined store could not be inspected read-only"));
    let claim_count: i64 = inspection
        .query_row("SELECT COUNT(*) FROM replay_claims", [], |row| row.get(0))
        .unwrap_or_else(|_| panic!("quarantined claim count could not be read"));
    let generation: i64 = inspection
        .query_row(
            "SELECT claimant_generation FROM replay_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|_| panic!("quarantined generation could not be read"));
    assert_eq!(claim_count, 0, "waiting claimant added a durable row");
    assert_eq!(generation, 0, "waiting claimant advanced the generation");
    drop(inspection);

    let error = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("durably quarantined root reopened"));
    assert_eq!(error.code(), "LOCATION_NOT_DEDICATED");
}

fn wait_for_post_preflight_sample(samples: &mpsc::Receiver<u64>) {
    let deadline = Instant::now() + CLAIM_PROBE_TIMEOUT;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match samples.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(sample) if sample >= POST_PREFLIGHT_CLOCK_SAMPLE => return,
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("waiting claimant clock probe disconnected")
            }
        }
    }
    panic!("waiting claimant did not pass its initial root-state check")
}

fn transition_live_root_to_quarantined(root: &Path) {
    let lock_path = root.join(ROOT_LOCK_FILENAME);
    let mut lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap_or_else(|_| panic!("root-state test could not open the root lock"));
    lock.try_lock()
        .unwrap_or_else(|_| panic!("root-state test could not acquire the root lock"));
    let mut original = Vec::new();
    lock.read_to_end(&mut original)
        .unwrap_or_else(|_| panic!("root-state test could not read the root lock"));
    assert_eq!(original, LIVE_READY_LOCK_CONTENT);
    lock.set_len(0)
        .and_then(|()| lock.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| lock.write_all(LIVE_QUARANTINED_LOCK_CONTENT))
        .and_then(|()| lock.sync_all())
        .unwrap_or_else(|_| panic!("root-state test could not publish LIVE_QUARANTINED"));

    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(QUARANTINE_MARKER_FILENAME))
        .unwrap_or_else(|_| panic!("root-state test could not create quarantine marker"));
    marker
        .write_all(QUARANTINE_MARKER_CONTENT)
        .and_then(|()| marker.sync_all())
        .unwrap_or_else(|_| panic!("root-state test could not publish quarantine marker"));
}

#[test]
#[ignore = "private concurrent-initializer child entry point"]
fn concurrent_initializer_worker() {
    if std::env::var(INITIALIZER_WORKER_ENV).ok().as_deref() != Some("1") {
        return;
    }

    let root_path = std::env::var_os(INITIALIZER_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("initializer worker root was not supplied"));
    let trusted = TrustedLocalStoreRootV1::try_from_provisioned(root_path)
        .unwrap_or_else(|_| panic!("initializer worker root was rejected"));
    let config = ReplayStoreConfigV1::try_new(
        trusted,
        CLAIM_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("initializer worker configuration was rejected"));

    worker_line(WORKER_READY);
    assert_eq!(worker_byte(), WORKER_GO, "initializer worker GO mismatch");
    worker_line(WORKER_STARTING);

    let claimant = match SqliteReplayClaimantV1::open_or_create(
        config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    ) {
        Ok(claimant) => claimant,
        Err(error) => {
            worker_line(&format!("HELIX_INIT_ERROR_OPEN_{}", error.code()));
            panic!("initializer worker failed to converge")
        }
    };
    let verification = match claimant.verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS) {
        Ok(verification) => verification,
        Err(error) => {
            worker_line(&format!("HELIX_INIT_ERROR_VERIFY_{}", error.code()));
            panic!("initializer worker full verification failed")
        }
    };
    assert_eq!(verification.claim_count(), 0);
    assert_eq!(verification.claimant_generation(), 0);
    worker_line(WORKER_OK);

    // Keeping the process alive until acknowledgement makes the victim's kill
    // deterministic even when initialization finishes before the parent schedules.
    assert_eq!(
        worker_byte(),
        WORKER_EXIT,
        "initializer worker EXIT mismatch"
    );
}

fn worker_line(line: &str) {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{line}").unwrap_or_else(|_| panic!("initializer worker stdout failed"));
    stdout
        .flush()
        .unwrap_or_else(|_| panic!("initializer worker stdout flush failed"));
}

fn worker_byte() -> u8 {
    let mut byte = [0_u8; 1];
    std::io::stdin()
        .lock()
        .read_exact(&mut byte)
        .unwrap_or_else(|_| panic!("initializer worker control channel closed"));
    byte[0]
}

#[test]
fn concurrent_initializers_converge_when_one_process_is_killed() {
    let root = SyntheticTempRoot::new("process-init-kill");
    let mut workers = (0..INITIALIZER_COUNT)
        .map(|_| InitWorker::spawn(root.path()))
        .collect::<Vec<_>>();

    for worker in &mut workers {
        worker.wait_for_line(WORKER_READY, PROCESS_WATCHDOG);
    }
    for worker in &mut workers {
        worker.send(WORKER_GO);
    }

    workers[0].wait_for_line(WORKER_STARTING, PROCESS_WATCHDOG);
    let killed = workers[0].kill_and_reap();
    assert!(
        !killed.success(),
        "initializer victim exited successfully instead of being killed"
    );

    for worker in workers.iter_mut().skip(1) {
        worker.wait_for_line(WORKER_OK, PROCESS_WATCHDOG);
        worker.send(WORKER_EXIT);
    }
    for worker in workers.iter_mut().skip(1) {
        let status = worker.wait_and_reap(PROCESS_WATCHDOG);
        assert!(status.success(), "surviving initializer did not succeed");
    }

    let fresh_trusted = TrustedLocalStoreRootV1::try_from_provisioned(root.path().to_path_buf())
        .unwrap_or_else(|_| panic!("fresh parent rejected the converged replay root"));
    let fresh_config = ReplayStoreConfigV1::try_new(
        fresh_trusted,
        CLAIM_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("fresh parent configuration was rejected"));
    let reopened = SqliteReplayClaimantV1::open_or_create(
        fresh_config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("fresh parent could not reopen converged replay root"));
    let verification = reopened
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("fresh parent full verification failed"));
    assert_eq!(verification.claim_count(), 0);
    assert_eq!(verification.claimant_generation(), 0);

    eprintln!(
        "initializer victim kill phase was scheduler-dependent; this is process-kill, not power-loss evidence"
    );
}

struct InitWorker {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
    reader: Option<thread::JoinHandle<()>>,
}

impl InitWorker {
    fn spawn(root: &Path) -> Self {
        let executable = std::env::current_exe()
            .unwrap_or_else(|_| panic!("initializer test executable was unavailable"));
        let mut child = Command::new(executable)
            .args([
                "--exact",
                "concurrent_initializer_worker",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(INITIALIZER_WORKER_ENV, "1")
            .env(INITIALIZER_ROOT_ENV, root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|_| panic!("initializer worker failed to spawn"));
        let stdin = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("initializer worker stdin was unavailable"));
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("initializer worker stdout was unavailable"));
        let (line_sender, lines) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if line_sender.send(line).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            child: Some(child),
            stdin: Some(stdin),
            lines,
            reader: Some(reader),
        }
    }

    fn wait_for_line(&mut self, expected: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("initializer worker watchdog expired before {expected}");
            }
            match self
                .lines
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(line) if line.contains(expected) => return,
                Ok(line) if line.contains("HELIX_INIT_ERROR_") => {
                    panic!("initializer worker reported closed failure: {line}")
                }
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(status) = self.try_status() {
                        panic!("initializer worker exited before {expected}: {status}");
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let status = self.try_status();
                    panic!(
                        "initializer worker output disconnected before {expected}; status={status:?}"
                    )
                }
            }
        }
    }

    fn send(&mut self, byte: u8) {
        self.stdin
            .as_mut()
            .unwrap_or_else(|| panic!("initializer worker control channel was unavailable"))
            .write_all(&[byte])
            .and_then(|()| {
                self.stdin
                    .as_mut()
                    .expect("initializer worker control channel disappeared")
                    .flush()
            })
            .unwrap_or_else(|_| panic!("initializer worker control write failed"));
    }

    fn try_status(&mut self) -> Option<ExitStatus> {
        self.child
            .as_mut()
            .unwrap_or_else(|| panic!("initializer worker was already reaped"))
            .try_wait()
            .unwrap_or_else(|_| panic!("initializer worker status probe failed"))
    }

    fn kill_and_reap(&mut self) -> ExitStatus {
        assert!(
            self.try_status().is_none(),
            "initializer victim exited before kill"
        );
        self.child
            .as_mut()
            .expect("initializer victim was already reaped")
            .kill()
            .unwrap_or_else(|_| panic!("initializer victim kill failed"));
        self.reap_blocking()
    }

    fn wait_and_reap(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if self.try_status().is_some() {
                return self.reap_blocking();
            }
            if Instant::now() >= deadline {
                panic!("initializer worker exit watchdog expired");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn reap_blocking(&mut self) -> ExitStatus {
        self.stdin.take();
        let mut child = self
            .child
            .take()
            .unwrap_or_else(|| panic!("initializer worker was already reaped"));
        let status = child
            .wait()
            .unwrap_or_else(|_| panic!("initializer worker reap failed"));
        self.join_reader();
        status
    }

    fn join_reader(&mut self) {
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .unwrap_or_else(|_| panic!("initializer worker reader panicked"));
        }
    }
}

impl Drop for InitWorker {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ignored = child.kill();
            }
            let _ignored = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ignored = reader.join();
        }
    }
}
