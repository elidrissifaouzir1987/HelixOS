//! PLAN-005 T041 RED contract for adapter duplicate/conflict linearizability.
//!
//! The ordinary cases are small deterministic specification oracles. The exact
//! SC-001 cardinalities remain explicit and ignored until T047--T050 provide the
//! real SQLite adapter boundary; the final source guard deliberately keeps this
//! target RED while that boundary is absent.

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
const CHILD_ROOT_ENV: &str = "HELIXOS_T041_CHILD_ROOT";
const CHILD_INDEX_ENV: &str = "HELIXOS_T041_CHILD_INDEX";
const CHILD_TEST_NAME: &str = "t041_process_oracle_child_v1";
const RETAINED_RECEIPT: &[u8] = b"t041-retained-receipt-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeliveryV1 {
    grant_id: [u8; 32],
    operation_id: &'static str,
    one_shot_nonce: [u8; 32],
    grant_digest: [u8; 32],
    signing_key_id: &'static str,
    canonical_grant: Vec<u8>,
}

impl DeliveryV1 {
    fn exact() -> Self {
        Self {
            grant_id: [1; 32],
            operation_id: "operation-t041",
            one_shot_nonce: [2; 32],
            grant_digest: [3; 32],
            signing_key_id: "coordinator-key-current",
            canonical_grant: b"canonical-grant-t041-v1".to_vec(),
        }
    }

    fn collides_with(&self, other: &Self) -> bool {
        self.grant_id == other.grant_id
            || self.operation_id == other.operation_id
            || self.one_shot_nonce == other.one_shot_nonce
            || self.grant_digest == other.grant_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeliveryClassV1 {
    Consumed(Vec<u8>),
    ExactDuplicate(Vec<u8>),
    Conflict,
}

#[derive(Default)]
struct InboxOracleV1 {
    retained: Mutex<Option<DeliveryV1>>,
    consumptions: AtomicUsize,
    duplicates: AtomicUsize,
    conflicts: AtomicUsize,
}

impl InboxOracleV1 {
    fn deliver(&self, candidate: DeliveryV1) -> DeliveryClassV1 {
        let mut retained = self
            .retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match retained.as_ref() {
            Some(existing) if existing == &candidate => {
                self.duplicates.fetch_add(1, Ordering::Relaxed);
                DeliveryClassV1::ExactDuplicate(RETAINED_RECEIPT.to_vec())
            }
            Some(existing) => {
                assert!(
                    existing.collides_with(&candidate),
                    "T041 conflict fixtures must collide in a create-only namespace"
                );
                self.conflicts.fetch_add(1, Ordering::Relaxed);
                DeliveryClassV1::Conflict
            }
            None => {
                self.consumptions.fetch_add(1, Ordering::Relaxed);
                *retained = Some(candidate);
                DeliveryClassV1::Consumed(RETAINED_RECEIPT.to_vec())
            }
        }
    }

    fn counts(&self) -> (usize, usize, usize) {
        (
            self.consumptions.load(Ordering::Relaxed),
            self.duplicates.load(Ordering::Relaxed),
            self.conflicts.load(Ordering::Relaxed),
        )
    }
}

fn run_duplicate_oracle(requests: usize) {
    let oracle = InboxOracleV1::default();
    for ordinal in 0..requests {
        let outcome = oracle.deliver(DeliveryV1::exact());
        let receipt = match outcome {
            DeliveryClassV1::Consumed(receipt) if ordinal == 0 => receipt,
            DeliveryClassV1::ExactDuplicate(receipt) if ordinal > 0 => receipt,
            other => panic!("unexpected duplicate outcome: {other:?}"),
        };
        assert_eq!(receipt, RETAINED_RECEIPT);
    }
    assert_eq!(oracle.counts(), (1, requests - 1, 0));
}

fn run_thread_oracle_round(contenders: usize) {
    let oracle = Arc::new(InboxOracleV1::default());
    let barrier = Arc::new(Barrier::new(contenders));
    let workers = (0..contenders)
        .map(|_| {
            let oracle = Arc::clone(&oracle);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                oracle.deliver(DeliveryV1::exact())
            })
        })
        .collect::<Vec<_>>();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("T041 contender must not panic"))
        .collect::<Vec<_>>();

    assert_eq!(oracle.counts(), (1, contenders - 1, 0));
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, DeliveryClassV1::Consumed(_)))
            .count(),
        1
    );
    assert!(outcomes.iter().all(|outcome| match outcome {
        DeliveryClassV1::Consumed(receipt) | DeliveryClassV1::ExactDuplicate(receipt) =>
            receipt == RETAINED_RECEIPT,
        DeliveryClassV1::Conflict => false,
    }));
}

struct ProcessOracleRootV1(PathBuf);

impl ProcessOracleRootV1 {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-t041-process-oracle-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("T041 process root creates");
        Self(path)
    }
}

impl Drop for ProcessOracleRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wait_until_v1(mut predicate: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + PROCESS_WAIT_LIMIT;
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "T041 timed out waiting for {label}"
        );
        thread::sleep(PROCESS_POLL_INTERVAL);
    }
}

fn wait_for_children_v1(children: &mut [Child]) {
    for child in children {
        let status = child.wait().expect("T041 child wait succeeds");
        assert!(status.success(), "T041 child failed: {status}");
    }
}

fn run_process_oracle_round(contenders: usize) {
    let root = ProcessOracleRootV1::new();
    let executable = std::env::current_exe().expect("T041 test executable resolves");
    let mut children = (0..contenders)
        .map(|index| {
            Command::new(&executable)
                .arg("--exact")
                .arg(CHILD_TEST_NAME)
                .arg("--ignored")
                .arg("--nocapture")
                .env(CHILD_ROOT_ENV, &root.0)
                .env(CHILD_INDEX_ENV, index.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("T041 child process spawns")
        })
        .collect::<Vec<_>>();

    wait_until_v1(
        || (0..contenders).all(|index| root.0.join(format!("ready-{index}")).exists()),
        "all child READY markers",
    );
    fs::write(root.0.join("go"), b"GO\n").expect("T041 GO marker publishes");
    wait_for_children_v1(&mut children);

    let mut consumed = 0_usize;
    let mut duplicates = 0_usize;
    for index in 0..contenders {
        let result =
            fs::read(root.0.join(format!("result-{index}"))).expect("T041 child result reads");
        let (class, receipt) = result.split_first().expect("T041 child result is nonempty");
        consumed += usize::from(*class == b'C');
        duplicates += usize::from(*class == b'D');
        assert_eq!(receipt, RETAINED_RECEIPT);
    }
    assert_eq!((consumed, duplicates), (1, contenders - 1));
}

fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

fn adapter_production_sources() -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    [
        "connection.rs",
        "inbox.rs",
        "quarantine.rs",
        "receipt.rs",
        "readback.rs",
    ]
    .into_iter()
    .map(|name| {
        let path = root.join(name);
        fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "T041 RED: T047--T050 must provide the real SQLite adapter boundary; missing {}",
                path.display()
            )
        })
    })
    .map(|source| source_without_comments(&source))
    .collect::<Vec<_>>()
    .join("\n")
}

#[test]
fn exact_duplicate_returns_one_retained_receipt_without_reconsumption() {
    run_duplicate_oracle(ORDINARY_DUPLICATE_REQUESTS);
}

#[test]
fn every_create_only_binding_conflict_authorizes_zero_additional_consumption() {
    let exact = DeliveryV1::exact();
    let mut cases = Vec::new();

    let mut grant_conflict = exact.clone();
    grant_conflict.operation_id = "operation-t041-other";
    cases.push(("grant", grant_conflict));

    let mut operation_conflict = exact.clone();
    operation_conflict.grant_id = [4; 32];
    cases.push(("operation", operation_conflict));

    let mut nonce_conflict = exact.clone();
    nonce_conflict.grant_id = [5; 32];
    nonce_conflict.operation_id = "operation-t041-nonce";
    nonce_conflict.grant_digest = [6; 32];
    nonce_conflict.canonical_grant = b"canonical-grant-t041-nonce-conflict".to_vec();
    cases.push(("nonce", nonce_conflict));

    let mut digest_conflict = exact.clone();
    digest_conflict.grant_digest = [7; 32];
    digest_conflict.canonical_grant = b"canonical-grant-t041-digest-conflict".to_vec();
    cases.push(("digest", digest_conflict));

    let mut rotation_conflict = exact.clone();
    rotation_conflict.signing_key_id = "coordinator-key-rotated";
    rotation_conflict.canonical_grant = b"canonical-grant-t041-key-rotation".to_vec();
    cases.push(("key-rotation", rotation_conflict));

    for (label, conflict) in cases {
        let oracle = InboxOracleV1::default();
        assert!(matches!(
            oracle.deliver(exact.clone()),
            DeliveryClassV1::Consumed(_)
        ));
        let before = oracle.counts().0;
        assert_eq!(
            oracle.deliver(conflict),
            DeliveryClassV1::Conflict,
            "{label}"
        );
        assert_eq!(oracle.counts(), (before, 0, 1), "{label}");
        assert_eq!(
            oracle.deliver(exact.clone()),
            DeliveryClassV1::ExactDuplicate(RETAINED_RECEIPT.to_vec()),
            "{label} conflict must not replace retained bytes"
        );
        assert_eq!(oracle.counts(), (before, 1, 1), "{label}");
    }
}

#[test]
fn reduced_thread_contention_has_one_consumption_and_zero_duplicate_consumptions() {
    run_thread_oracle_round(ORDINARY_THREAD_CONTENDERS);
}

#[test]
fn reduced_process_contention_has_one_consumption_and_zero_duplicate_consumptions() {
    run_process_oracle_round(ORDINARY_PROCESS_CONTENDERS);
}

#[test]
fn sc001_release_cardinalities_are_exact() {
    assert_eq!(RELEASE_DUPLICATE_REQUESTS, 10_000);
    assert_eq!(
        (RELEASE_THREAD_ROUNDS, RELEASE_THREAD_CONTENDERS),
        (100, 64)
    );
    assert_eq!(
        (RELEASE_PROCESS_ROUNDS, RELEASE_PROCESS_CONTENDERS),
        (20, 8)
    );
    assert_eq!(RELEASE_THREAD_ROUNDS * RELEASE_THREAD_CONTENDERS, 6_400);
    assert_eq!(RELEASE_PROCESS_ROUNDS * RELEASE_PROCESS_CONTENDERS, 160);
}

#[test]
fn production_seam_is_a_real_sqlite_create_only_adapter_boundary() {
    let source = adapter_production_sources();
    for required in [
        "rusqlite",
        "Connection",
        "TransactionBehavior::Immediate",
        "decode_and_verify_execution_grant_v1",
        "grant_inbox",
        "inbox_transitions",
        "execution_receipts",
        "inbox_conflicts",
        "canonical_grant",
        "canonical_receipt",
        "one_shot_nonce",
        "operation_id",
        "grant_digest",
    ] {
        assert!(
            source.contains(required),
            "T041 adapter seam omits {required}"
        );
    }
    assert!(
        source.lines().any(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("fn ")
                && line.contains("v1")
                && (line.contains("receive") || line.contains("deliver"))
        }),
        "T041 RED: no production receive/deliver v1 entry crosses the SQLite adapter boundary"
    );
    assert!(
        !source.contains("HashMap<") && !source.contains("BTreeMap<"),
        "T041 production boundary must not substitute an in-memory identity oracle"
    );
}

#[test]
#[ignore = "private T041 child entry used only by synchronized process rounds"]
fn t041_process_oracle_child_v1() {
    let Some(root) = std::env::var_os(CHILD_ROOT_ENV).map(PathBuf::from) else {
        return;
    };
    let index = std::env::var(CHILD_INDEX_ENV)
        .expect("T041 child index exists")
        .parse::<usize>()
        .expect("T041 child index parses");
    fs::write(root.join(format!("ready-{index}")), b"READY\n")
        .expect("T041 child READY marker publishes");
    wait_until_v1(|| root.join("go").exists(), "parent GO marker");

    let claim = root.join("consumption");
    let consumed = match OpenOptions::new().write(true).create_new(true).open(&claim) {
        Ok(mut file) => {
            file.write_all(RETAINED_RECEIPT)
                .expect("T041 retained receipt writes");
            file.sync_all().expect("T041 retained receipt synchronizes");
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => panic!("T041 process oracle failed: {error}"),
    };
    let mut receipt = None;
    wait_until_v1(
        || {
            receipt = fs::read(&claim)
                .ok()
                .filter(|bytes| bytes == RETAINED_RECEIPT);
            receipt.is_some()
        },
        "complete retained receipt",
    );
    let mut result = vec![if consumed { b'C' } else { b'D' }];
    result.extend_from_slice(&receipt.expect("T041 receipt was retained"));
    fs::write(root.join(format!("result-{index}")), result).expect("T041 child result publishes");
}

#[test]
#[ignore = "release SC-001 gate: exactly 10,000 requests through the production adapter boundary"]
fn release_10_000_duplicate_requests() {
    let _ = adapter_production_sources();
    run_duplicate_oracle(RELEASE_DUPLICATE_REQUESTS);
}

#[test]
#[ignore = "release SC-001 gate: exactly 100 rounds x 64 threads through the production adapter boundary"]
fn release_100_by_64_thread_contention() {
    let _ = adapter_production_sources();
    for _ in 0..RELEASE_THREAD_ROUNDS {
        run_thread_oracle_round(RELEASE_THREAD_CONTENDERS);
    }
}

#[test]
#[ignore = "release SC-001 gate: exactly 20 rounds x 8 processes through the production adapter boundary"]
fn release_20_by_8_process_contention() {
    let _ = adapter_production_sources();
    for _ in 0..RELEASE_PROCESS_ROUNDS {
        run_process_oracle_round(RELEASE_PROCESS_CONTENDERS);
    }
}
