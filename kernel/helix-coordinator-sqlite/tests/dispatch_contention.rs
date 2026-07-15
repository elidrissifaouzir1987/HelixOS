//! PLAN-005 T025 contention contract for one durable grant/operation/nonce identity.
//!
//! Ordinary tests validate the bounded harness with reduced deterministic loads. The
//! exact release cardinalities are retained behind `#[ignore]`. These harness oracles
//! are not release evidence by themselves: T032/T033 must provide the real coordinator
//! transaction, and T038 must run the same cardinalities through that production seam.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const RELEASE_DUPLICATE_REQUESTS: usize = 10_000;
const RELEASE_THREAD_ROUNDS: usize = 100;
const RELEASE_THREAD_CONTENDERS: usize = 64;
const RELEASE_PROCESS_ROUNDS: usize = 20;
const RELEASE_PROCESS_CONTENDERS: usize = 8;

const ORDINARY_DUPLICATE_REQUESTS: usize = 128;
const ORDINARY_THREAD_CONTENDERS: usize = 8;
const ORDINARY_PROCESS_CONTENDERS: usize = 2;
const PROCESS_WAIT_LIMIT: Duration = Duration::from_secs(15);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
const CHILD_ROOT_ENV: &str = "HELIXOS_T025_CHILD_ROOT";
const CHILD_INDEX_ENV: &str = "HELIXOS_T025_CHILD_INDEX";
const CHILD_TEST_NAME: &str = "dispatch_contention_oracle_child_v1";

#[derive(Clone, Debug, PartialEq, Eq)]
struct DispatchIdentityOracleV1 {
    grant_id: String,
    operation_id: String,
    one_shot_nonce: String,
}

impl DispatchIdentityOracleV1 {
    fn candidate(ordinal: usize) -> Self {
        Self {
            grant_id: format!("grant:t025:{ordinal:08}"),
            operation_id: "operation:t025:duplicate".to_owned(),
            one_shot_nonce: format!("nonce:t025:{ordinal:08}"),
        }
    }

    fn encode(&self) -> String {
        format!(
            "{}\n{}\n{}\n",
            self.grant_id, self.operation_id, self.one_shot_nonce
        )
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.lines();
        let value = Self {
            grant_id: lines.next()?.to_owned(),
            operation_id: lines.next()?.to_owned(),
            one_shot_nonce: lines.next()?.to_owned(),
        };
        (lines.next().is_none()
            && value.grant_id.starts_with("grant:t025:")
            && value.operation_id == "operation:t025:duplicate"
            && value.one_shot_nonce.starts_with("nonce:t025:"))
        .then_some(value)
    }
}

#[derive(Default)]
struct InMemoryIdentityOracleV1 {
    retained: Mutex<Option<DispatchIdentityOracleV1>>,
    winners: AtomicUsize,
}

impl InMemoryIdentityOracleV1 {
    fn claim(&self, candidate: DispatchIdentityOracleV1) -> DispatchIdentityOracleV1 {
        let mut retained = self
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = retained.as_ref() {
            return existing.clone();
        }
        self.winners.fetch_add(1, Ordering::Relaxed);
        *retained = Some(candidate.clone());
        candidate
    }

    fn assert_exactly_one(&self, observations: &[DispatchIdentityOracleV1]) {
        assert!(!observations.is_empty());
        assert_eq!(self.winners.load(Ordering::Relaxed), 1);
        let retained = self
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("one identity is retained");
        assert!(observations.iter().all(|value| value == &retained));
    }
}

struct ProcessOracleRootV1 {
    path: PathBuf,
}

impl ProcessOracleRootV1 {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-t025-process-oracle-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("T025 process oracle root creates");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn member(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for ProcessOracleRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_duplicate_oracle(requests: usize) {
    let oracle = InMemoryIdentityOracleV1::default();
    let observations = (0..requests)
        .map(|ordinal| oracle.claim(DispatchIdentityOracleV1::candidate(ordinal)))
        .collect::<Vec<_>>();
    oracle.assert_exactly_one(&observations);
}

fn run_thread_oracle_round(contenders: usize) {
    let oracle = Arc::new(InMemoryIdentityOracleV1::default());
    let barrier = Arc::new(Barrier::new(contenders));
    let workers = (0..contenders)
        .map(|ordinal| {
            let oracle = Arc::clone(&oracle);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                oracle.claim(DispatchIdentityOracleV1::candidate(ordinal))
            })
        })
        .collect::<Vec<_>>();
    let observations = workers
        .into_iter()
        .map(|worker| worker.join().expect("T025 thread contender does not panic"))
        .collect::<Vec<_>>();
    oracle.assert_exactly_one(&observations);
}

fn run_process_oracle_round(contenders: usize) {
    let root = ProcessOracleRootV1::new();
    let executable = std::env::current_exe().expect("T025 test executable resolves");
    let mut children = (0..contenders)
        .map(|index| {
            Command::new(&executable)
                .arg("--exact")
                .arg(CHILD_TEST_NAME)
                .arg("--ignored")
                .arg("--nocapture")
                .env(CHILD_ROOT_ENV, root.path())
                .env(CHILD_INDEX_ENV, index.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("T025 child process spawns")
        })
        .collect::<Vec<_>>();

    wait_until_v1(
        || (0..contenders).all(|index| root.member(&format!("ready-{index}")).exists()),
        "all child READY markers",
    );
    fs::write(root.member("go"), b"GO\n").expect("T025 GO marker publishes");
    wait_for_children_v1(&mut children);

    let mut winners = 0_usize;
    let observations = (0..contenders)
        .map(|index| {
            let result =
                fs::read(root.member(&format!("result-{index}"))).expect("T025 child result reads");
            let (class, identity) = result.split_first().expect("T025 child result is nonempty");
            winners += usize::from(*class == b'W');
            DispatchIdentityOracleV1::decode(identity).expect("T025 child identity decodes")
        })
        .collect::<Vec<_>>();
    assert_eq!(winners, 1);
    assert!(observations.iter().all(|value| value == &observations[0]));
}

fn wait_for_children_v1(children: &mut [Child]) {
    for child in children {
        let status = child.wait().expect("T025 child process wait succeeds");
        assert!(status.success(), "T025 child process failed: {status}");
    }
}

fn wait_until_v1(mut predicate: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + PROCESS_WAIT_LIMIT;
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "T025 timed out waiting for {label}"
        );
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn read_claim_v1(path: &Path) -> DispatchIdentityOracleV1 {
    let mut decoded = None;
    wait_until_v1(
        || {
            decoded = fs::read(path)
                .ok()
                .and_then(|bytes| DispatchIdentityOracleV1::decode(&bytes));
            decoded.is_some()
        },
        "complete create-only identity claim",
    );
    decoded.expect("T025 claim was decoded")
}

fn source_without_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut block_depth = 0_u64;
    for line in source.lines() {
        let mut remaining = line;
        loop {
            if block_depth > 0 {
                let Some(end) = remaining.find("*/") else {
                    break;
                };
                block_depth -= 1;
                remaining = &remaining[end + 2..];
                continue;
            }
            let line_comment = remaining.find("//");
            let block_comment = remaining.find("/*");
            match (line_comment, block_comment) {
                (Some(line_start), Some(block_start)) if block_start < line_start => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (Some(line_start), _) => {
                    output.push_str(&remaining[..line_start]);
                    break;
                }
                (None, Some(block_start)) => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (None, None) => {
                    output.push_str(remaining);
                    break;
                }
            }
        }
        output.push('\n');
    }
    assert_eq!(block_depth, 0, "T025 source comments are balanced");
    output
}

#[test]
fn release_cardinalities_are_exact_and_bounded() {
    assert_eq!(RELEASE_DUPLICATE_REQUESTS, 10_000);
    assert_eq!(RELEASE_THREAD_ROUNDS, 100);
    assert_eq!(RELEASE_THREAD_CONTENDERS, 64);
    assert_eq!(RELEASE_PROCESS_ROUNDS, 20);
    assert_eq!(RELEASE_PROCESS_CONTENDERS, 8);
    assert_eq!(RELEASE_THREAD_ROUNDS * RELEASE_THREAD_CONTENDERS, 6_400);
    assert_eq!(RELEASE_PROCESS_ROUNDS * RELEASE_PROCESS_CONTENDERS, 160);
}

#[test]
fn reduced_duplicate_harness_retains_one_identity_triple() {
    run_duplicate_oracle(ORDINARY_DUPLICATE_REQUESTS);
}

#[test]
fn reduced_thread_harness_retains_one_identity_triple() {
    run_thread_oracle_round(ORDINARY_THREAD_CONTENDERS);
}

#[test]
fn reduced_process_harness_retains_one_identity_triple() {
    run_process_oracle_round(ORDINARY_PROCESS_CONTENDERS);
}

#[test]
fn t032_dispatch_source_closes_grant_operation_and_nonce_namespaces() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dispatch.rs");
    let source = source_without_comments(&fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "T025 RED: {} must provide the T032 production dispatch identity seam",
            path.display()
        )
    }));

    for required in [
        "dispatch_grants",
        "dispatch_records",
        "dispatch_outbox",
        "grant_id",
        "operation_id",
        "one_shot_nonce",
    ] {
        assert!(
            source.contains(required),
            "T025 production seam omits {required}"
        );
    }
    let has_dispatch_api = source.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("fn ") && line.contains("dispatch") && line.contains("v1")
    });
    assert!(
        has_dispatch_api,
        "T025 production dispatch API candidate is missing"
    );
    for forbidden_delivery in ["DispatchTransportV1", "deliver_exact_v1"] {
        assert!(
            !source.contains(forbidden_delivery),
            "T025 coordinator commit invoked transport through {forbidden_delivery}"
        );
    }
}

#[test]
#[ignore = "private T025 child entry; invoked only by process harness rounds"]
fn dispatch_contention_oracle_child_v1() {
    let Some(root) = std::env::var_os(CHILD_ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let index = std::env::var(CHILD_INDEX_ENV)
        .expect("T025 child index is present")
        .parse::<usize>()
        .expect("T025 child index parses");
    fs::write(root.join(format!("ready-{index}")), b"READY\n")
        .expect("T025 child READY marker publishes");
    wait_until_v1(|| root.join("go").exists(), "parent GO marker");

    let claim_path = root.join("claim");
    let candidate = DispatchIdentityOracleV1::candidate(index);
    let won = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&claim_path)
    {
        Ok(mut claim) => {
            claim
                .write_all(candidate.encode().as_bytes())
                .expect("T025 identity claim writes");
            claim.sync_all().expect("T025 identity claim synchronizes");
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => panic!("T025 identity claim failed: {error}"),
    };
    let retained = read_claim_v1(&claim_path);
    let mut result = vec![if won { b'W' } else { b'R' }];
    result.extend_from_slice(retained.encode().as_bytes());
    fs::write(root.join(format!("result-{index}")), result).expect("T025 child result publishes");
}

#[test]
#[ignore = "release PLAN-005 gate: exactly 10,000 duplicate requests"]
fn release_10_000_duplicate_requests_retain_one_identity() {
    run_duplicate_oracle(RELEASE_DUPLICATE_REQUESTS);
}

#[test]
#[ignore = "release PLAN-005 gate: 100 rounds x 64 synchronized threads"]
fn release_100_by_64_thread_contention_retain_one_identity_per_round() {
    for _ in 0..RELEASE_THREAD_ROUNDS {
        run_thread_oracle_round(RELEASE_THREAD_CONTENDERS);
    }
}

#[test]
#[ignore = "release PLAN-005 gate: 20 rounds x 8 synchronized child processes"]
fn release_20_by_8_process_contention_retain_one_identity_per_round() {
    for _ in 0..RELEASE_PROCESS_ROUNDS {
        run_process_oracle_round(RELEASE_PROCESS_CONTENDERS);
    }
}
