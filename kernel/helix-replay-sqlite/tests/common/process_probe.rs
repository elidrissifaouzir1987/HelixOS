//! Shell-free child-process readiness protocol for T025.

use crate::common::{
    evaluate_with_observation, feature002_fixture, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, DEFAULT_BACKUP_RETRY_WAIT_MS, DEFAULT_BACKUP_STEP_PAGES,
    OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_replay_sqlite::{ReplayStoreConfigV1, SqliteReplayClaimantV1, TrustedLocalStoreRootV1};
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const ROLE_ENV: &str = "HELIX_REPLAY_TEST_ROLE";
const ROOT_ENV: &str = "HELIX_REPLAY_TEST_ROOT";
const VARIANT_ENV: &str = "HELIX_REPLAY_TEST_VARIANT";
const WORKER_ROLE: &str = "process-contender-v1";
const READY_TOKEN: &str = "HELIX_READY_V1";
const GO_TOKEN: &str = "HELIX_GO_V1";
const RESULT_PREFIX: &str = "HELIX_RESULT_V1:";
const PROCESS_BUSY_WAIT_MS: u64 = 5_000;
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(15);
const WAIT_POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessOutcome {
    Claimed,
    AlreadyClaimed,
    BindingConflict,
    Unavailable,
    Ambiguous,
}

enum ReaderEvent {
    Ready,
    Outcome(ProcessOutcome),
}

struct Worker {
    child: Child,
    stdin: Option<ChildStdin>,
    events: Receiver<ReaderEvent>,
    reader: Option<JoinHandle<()>>,
    reaped: bool,
}

impl Worker {
    fn spawn(root: &Path, variant: Feature002Variant) -> Self {
        let executable =
            std::env::current_exe().unwrap_or_else(|_| panic!("process probe executable missing"));
        let mut child = Command::new(executable)
            .args([
                "--exact",
                "process_probe_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROLE_ENV, WORKER_ROLE)
            .env(ROOT_ENV, root.as_os_str())
            .env(VARIANT_ENV, variant_token(variant))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|_| panic!("process probe spawn failed"));
        let stdin = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("process probe stdin missing"));
        let stdout = child
            .stdout
            .take()
            .unwrap_or_else(|| panic!("process probe stdout missing"));
        let (sender, events) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if line.contains(READY_TOKEN) {
                            let _ignored = sender.send(ReaderEvent::Ready);
                        }
                        if let Some(index) = line.find(RESULT_PREFIX) {
                            let token = line[index + RESULT_PREFIX.len()..]
                                .split_whitespace()
                                .next()
                                .unwrap_or("");
                            if let Some(outcome) = parse_outcome(token) {
                                let _ignored = sender.send(ReaderEvent::Outcome(outcome));
                            }
                        }
                    }
                }
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            events,
            reader: Some(reader),
            reaped: false,
        }
    }

    fn wait_ready(&self) {
        match self.events.recv_timeout(PROTOCOL_TIMEOUT) {
            Ok(ReaderEvent::Ready) => {}
            Ok(ReaderEvent::Outcome(_)) => panic!("process probe returned before readiness"),
            Err(_) => panic!("process probe readiness timed out"),
        }
    }

    fn send_go(&mut self) {
        let stdin = self
            .stdin
            .as_mut()
            .unwrap_or_else(|| panic!("process probe stdin unavailable"));
        writeln!(stdin, "{GO_TOKEN}")
            .and_then(|()| stdin.flush())
            .unwrap_or_else(|_| panic!("process probe go signal failed"));
    }

    fn finish(mut self) -> ProcessOutcome {
        let outcome = match self.events.recv_timeout(PROTOCOL_TIMEOUT) {
            Ok(ReaderEvent::Outcome(outcome)) => outcome,
            Ok(ReaderEvent::Ready) => panic!("process probe emitted duplicate readiness"),
            Err(_) => panic!("process probe result timed out"),
        };
        self.stdin.take();
        self.wait_bounded();
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .unwrap_or_else(|_| panic!("process probe reader panicked"));
        }
        outcome
    }

    fn wait_bounded(&mut self) {
        let deadline = Instant::now() + PROTOCOL_TIMEOUT;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    assert!(status.success(), "process probe exited unsuccessfully");
                    return;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(WAIT_POLL),
                Ok(None) | Err(_) => {
                    let _ignored = self.child.kill();
                    let _ignored = self.child.wait();
                    self.reaped = true;
                    panic!("process probe exit timed out");
                }
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if !self.reaped {
            let _ignored = self.child.kill();
            let _ignored = self.child.wait();
            self.reaped = true;
        }
        if let Some(reader) = self.reader.take() {
            let _ignored = reader.join();
        }
    }
}

pub fn run_process_round(root: &Path, variants: &[Feature002Variant]) -> Vec<ProcessOutcome> {
    assert_eq!(variants.len(), 8, "process round requires eight contenders");
    let mut workers = variants
        .iter()
        .copied()
        .map(|variant| Worker::spawn(root, variant))
        .collect::<Vec<_>>();
    for worker in &workers {
        worker.wait_ready();
    }
    for worker in &mut workers {
        worker.send_go();
    }
    workers.into_iter().map(Worker::finish).collect()
}

/// Runs inside the exact-filtered child test. Returns false in the parent test process.
pub fn run_worker_if_requested() -> bool {
    if std::env::var_os(ROLE_ENV).as_deref() != Some(OsStr::new(WORKER_ROLE)) {
        return false;
    }
    let root = std::env::var_os(ROOT_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| panic!("process probe root missing"));
    let variant = std::env::var(VARIANT_ENV)
        .ok()
        .and_then(|token| parse_variant(&token))
        .unwrap_or_else(|| panic!("process probe variant invalid"));
    let trusted = TrustedLocalStoreRootV1::try_from_provisioned(root)
        .unwrap_or_else(|_| panic!("process probe root rejected"));
    let config = ReplayStoreConfigV1::try_new(
        trusted,
        PROCESS_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("process probe configuration rejected"));
    let claimant = SqliteReplayClaimantV1::open_or_create(
        config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("process probe store open failed"));

    println!("{READY_TOKEN}");
    std::io::stdout()
        .flush()
        .unwrap_or_else(|_| panic!("process probe readiness flush failed"));
    let mut command = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut command)
        .unwrap_or_else(|_| panic!("process probe go read failed"));
    assert_eq!(command.trim(), GO_TOKEN, "process probe go token invalid");

    let (result, observed) = evaluate_with_observation(feature002_fixture(variant), &claimant);
    let outcome = match observed {
        ObservedReplayOutcome::Claimed { .. } => {
            assert!(result.is_ok());
            ProcessOutcome::Claimed
        }
        ObservedReplayOutcome::AlreadyClaimed => {
            assert!(result.is_err());
            ProcessOutcome::AlreadyClaimed
        }
        ObservedReplayOutcome::BindingConflict => {
            assert!(result.is_err());
            ProcessOutcome::BindingConflict
        }
        ObservedReplayOutcome::Unavailable => {
            assert!(result.is_err());
            ProcessOutcome::Unavailable
        }
        ObservedReplayOutcome::Ambiguous => {
            assert!(result.is_err());
            ProcessOutcome::Ambiguous
        }
    };
    println!("{RESULT_PREFIX}{}", outcome_token(outcome));
    std::io::stdout()
        .flush()
        .unwrap_or_else(|_| panic!("process probe result flush failed"));
    true
}

fn variant_token(variant: Feature002Variant) -> &'static str {
    match variant {
        Feature002Variant::Coherent => "coherent",
        Feature002Variant::SameNonceDifferentOperation => "nonce-conflict",
        Feature002Variant::SameOperationDifferentNonce => "operation-conflict",
        Feature002Variant::Independent => "independent",
    }
}

fn parse_variant(token: &str) -> Option<Feature002Variant> {
    match token {
        "coherent" => Some(Feature002Variant::Coherent),
        "nonce-conflict" => Some(Feature002Variant::SameNonceDifferentOperation),
        "operation-conflict" => Some(Feature002Variant::SameOperationDifferentNonce),
        "independent" => Some(Feature002Variant::Independent),
        _ => None,
    }
}

fn outcome_token(outcome: ProcessOutcome) -> &'static str {
    match outcome {
        ProcessOutcome::Claimed => "CLAIMED",
        ProcessOutcome::AlreadyClaimed => "ALREADY_CLAIMED",
        ProcessOutcome::BindingConflict => "BINDING_CONFLICT",
        ProcessOutcome::Unavailable => "UNAVAILABLE",
        ProcessOutcome::Ambiguous => "AMBIGUOUS",
    }
}

fn parse_outcome(token: &str) -> Option<ProcessOutcome> {
    match token {
        "CLAIMED" => Some(ProcessOutcome::Claimed),
        "ALREADY_CLAIMED" => Some(ProcessOutcome::AlreadyClaimed),
        "BINDING_CONFLICT" => Some(ProcessOutcome::BindingConflict),
        "UNAVAILABLE" => Some(ProcessOutcome::Unavailable),
        "AMBIGUOUS" => Some(ProcessOutcome::Ambiguous),
        _ => None,
    }
}
