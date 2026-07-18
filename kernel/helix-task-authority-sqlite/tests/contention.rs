mod support;

use helix_task_authority::{issue_root_lease_v1, RootLeaseRequestOutcomeV1};
use helix_task_authority_contracts::Sha256Digest;
use std::path::PathBuf;
use std::process::Command;

const SEQUENTIAL_RETRIES: usize = 10_000;
const THREAD_ROUNDS: usize = 100;
const THREADS_PER_ROUND: usize = 64;
const PROCESS_ROUNDS: usize = 20;
const PROCESSES_PER_ROUND: usize = 8;

fn issue_retry(root: &support::TestRoot) -> Vec<u8> {
    let store = root.store();
    let signer = support::LeaseSignerV1::fixed();
    match issue_root_lease_v1(support::request(50, 3), &signer, &store) {
        RootLeaseRequestOutcomeV1::CommittedRetained(retained) => {
            retained.root_lease_wire_v1().to_vec()
        }
        outcome => panic!("root retry did not retain exact graph: {outcome:?}"),
    }
}

fn assert_single_root_graph(root: &support::TestRoot) {
    let connection = root.connection();
    let counts: (i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM human_request_grants),
                 (SELECT COUNT(*) FROM human_grant_claims),
                 (SELECT COUNT(*) FROM task_leases),
                 (SELECT COUNT(*) FROM task_lease_usage),
                 (SELECT COUNT(*) FROM authority_conflict_tombstones)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(counts, (1, 1, 1, 1, 0));
}

#[test]
fn default_contention_smoke_keeps_one_exact_root() {
    let root = support::TestRoot::provision();
    let exact = issue_retry(&root);
    for _ in 0..128 {
        assert_eq!(issue_retry(&root), exact);
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS_PER_ROUND)
            .map(|_| scope.spawn(|| issue_retry(&root)))
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), exact);
        }
    });
    assert_single_root_graph(&root);
}

#[test]
#[ignore = "controlled PLAN-006 conformance profile"]
fn ten_thousand_sequential_retries_return_identical_bytes() {
    let root = support::TestRoot::provision();
    let exact = issue_retry(&root);
    for _ in 0..SEQUENTIAL_RETRIES {
        assert_eq!(issue_retry(&root), exact);
    }
    assert_single_root_graph(&root);
}

#[test]
#[ignore = "controlled PLAN-006 conformance profile"]
fn one_hundred_rounds_of_sixty_four_threads_return_identical_bytes() {
    let root = support::TestRoot::provision();
    let exact = issue_retry(&root);
    for _ in 0..THREAD_ROUNDS {
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS_PER_ROUND)
                .map(|_| scope.spawn(|| issue_retry(&root)))
                .collect();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), exact);
            }
        });
    }
    assert_single_root_graph(&root);
}

#[test]
fn process_worker_one_retry() {
    let Some(root_path) = std::env::var_os("HELIX_TEST_ROOT_PATH") else {
        return;
    };
    let root_id = std::env::var("HELIX_TEST_ROOT_ID").expect("worker root ID is supplied");
    let expected = std::env::var("HELIX_TEST_EXPECTED_LEASE_SHA256")
        .expect("worker expected digest is supplied");
    let store = support::store_for_existing_path(PathBuf::from(root_path), &root_id);
    let signer = support::LeaseSignerV1::fixed();
    let retained = match issue_root_lease_v1(support::request(50, 3), &signer, &store) {
        RootLeaseRequestOutcomeV1::CommittedRetained(retained) => retained,
        outcome => panic!("process retry failed: {outcome:?}"),
    };
    assert_eq!(
        Sha256Digest::digest(retained.root_lease_wire_v1()).to_hex(),
        expected
    );
}

#[test]
#[ignore = "controlled PLAN-006 conformance profile"]
fn twenty_rounds_of_eight_processes_return_identical_bytes() {
    let root = support::TestRoot::provision();
    let exact = issue_retry(&root);
    let expected = Sha256Digest::digest(&exact).to_hex();
    let executable = std::env::current_exe().unwrap();
    for _ in 0..PROCESS_ROUNDS {
        let mut children = Vec::with_capacity(PROCESSES_PER_ROUND);
        for _ in 0..PROCESSES_PER_ROUND {
            children.push(
                Command::new(&executable)
                    .arg("--exact")
                    .arg("process_worker_one_retry")
                    .arg("--nocapture")
                    .env("HELIX_TEST_ROOT_PATH", root.path())
                    .env("HELIX_TEST_ROOT_ID", root.root_id())
                    .env("HELIX_TEST_EXPECTED_LEASE_SHA256", &expected)
                    .spawn()
                    .expect("contention worker starts"),
            );
        }
        for mut child in children {
            assert!(child.wait().expect("worker exits").success());
        }
    }
    assert_single_root_graph(&root);
}
