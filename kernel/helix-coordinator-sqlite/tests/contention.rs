//! T042 red tests for serialized preparation and shared-budget contention.
//!
//! The ordinary cases run one 64-thread and one 8-process round. The controlled
//! release workload retains the contract's 100 x 64-thread and 20 x 8-process
//! evidence behind `#[ignore]`. Child processes re-execute this integration-test
//! binary; no separately trusted probe executable or public fixture API is needed.
//!
//! Expected private implementation seam (T044/T045/T049): a deadline-bounded
//! synthetic commit, create-only scope provisioning with an explicit total vector,
//! and deterministic distinct signed operations that retain one shared scope binding.

mod common;

#[path = "../src/comparison_digest.rs"]
mod comparison_digest;
#[path = "../src/outbox.rs"]
mod outbox;
#[path = "../src/prepare.rs"]
mod prepare;
#[path = "../src/readback.rs"]
mod readback;
#[cfg(feature = "test-fault-injection")]
#[path = "../src/test_fault.rs"]
mod test_fault;

use common::process_probe::{
    private_process_argument_v1, ProcessProbeChildV1, ProcessProbeEnvironmentV1,
    SynchronizedProcessProbeV1,
};
use common::{
    SyntheticCoordinatorClockV1, SyntheticCoordinatorRootV1, SyntheticHistoricalPlanKeyResolverV1,
};
use helix_coordinator_sqlite::{CoordinatorClockUnavailableV1, CoordinatorMonotonicClockV1};
use helix_plan_preparation::PreparationCommitOutcomeV1;
use prepare::{
    commit_synthetic_preparation_until_v1, provision_synthetic_budget_scope_v1,
    provision_synthetic_budget_scope_with_total_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use rusqlite::{Connection, OpenFlags};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const OPEN_NOW_MS: u64 = 100;
const OPEN_DEADLINE_MS: u64 = 10_000;
const CONTENTION_CLOCK_BASE_MS: u64 = 1_000;
// Test-only correctness window for heavily oversubscribed hosted runners. The strict
// controlled wall-clock oracle is owned by deadline.rs and keeps its 40 ms + 50 ms bound.
const CONTENTION_DEADLINE_DELTA_MS: u64 = 60_000;
const CONTENTION_BUSY_WAIT_MS: u64 = 30_000;
const THREAD_CONTENDERS: usize = 64;
const PROCESS_CONTENDERS: usize = 8;
const RELEASE_THREAD_ROUNDS: usize = 100;
const RELEASE_PROCESS_ROUNDS: usize = 20;
const SHARED_CONTENDERS: usize = 8;
const SHARED_WINNERS: usize = 4;
const SHARED_REQUEST: [u64; 4] = [1, 1, 1, 1];
const SHARED_TOTAL: [u64; 4] = [4, 4, 4, 4];
const PROBE_MODE_ENV: &str = "HELIXOS_T042_PROCESS_PROBE_MODE";
const PROBE_DATABASE_ENV: &str = "HELIXOS_T042_PROCESS_PROBE_DATABASE";
const PROBE_SAME_OPERATION: &str = "same-operation";
const PROBE_SHARED_ALLOWANCE: &str = "shared-allowance";

#[derive(Clone)]
struct ElapsedCoordinatorClockV1 {
    origin: Arc<Instant>,
    base_ms: u64,
}

impl ElapsedCoordinatorClockV1 {
    fn new(base_ms: u64) -> Self {
        Self {
            origin: Arc::new(Instant::now()),
            base_ms,
        }
    }

    fn deadline_v1(&self) -> u64 {
        self.base_ms + CONTENTION_DEADLINE_DELTA_MS
    }
}

impl CoordinatorMonotonicClockV1 for ElapsedCoordinatorClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        let elapsed = u64::try_from(self.origin.elapsed().as_millis())
            .map_err(|_| CoordinatorClockUnavailableV1::new())?;
        self.base_ms
            .checked_add(elapsed)
            .ok_or_else(CoordinatorClockUnavailableV1::new)
    }
}

struct ContentionRootV1 {
    // A sequential table read maps the WAL index before synchronized workers touch it.
    // Keep this idle/autocommit handle first so panic cleanup closes it before the
    // synthetic root attempts to remove the directory on Windows.
    _wal_anchor: Connection,
    root: SyntheticCoordinatorRootV1,
    identity: helix_coordinator_sqlite::CoordinatorRootIdentityEvidenceV1,
    database: PathBuf,
}

impl ContentionRootV1 {
    fn new() -> Self {
        let root = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root");
        let store = root
            .open_empty_v1(
                SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                OPEN_DEADLINE_MS,
            )
            .expect("empty coordinator initializes");
        let identity = store.root_identity_evidence();
        drop(store);
        let database = fs::canonicalize(root.path())
            .expect("synthetic coordinator root canonicalizes")
            .join("coordinator.sqlite3");
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let wal_anchor = Connection::open_with_flags(&database, flags)
            .expect("contention WAL anchor opens sequentially");
        let journal_mode: String = wal_anchor
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("contention WAL anchor reads the persistent journal mode");
        assert!(journal_mode.eq_ignore_ascii_case("wal"));
        let singleton: i64 = wal_anchor
            .query_row(
                "SELECT COUNT(*) FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("contention WAL anchor maps and reads the WAL index");
        assert_eq!(singleton, 1);
        assert!(wal_anchor.is_autocommit());
        Self {
            _wal_anchor: wal_anchor,
            root,
            identity,
            database,
        }
    }

    fn reopen_and_verify(self, expected_operations: u64) {
        let Self {
            _wal_anchor,
            root,
            identity,
            database: _,
        } = self;
        // Exercise a genuine last-close/reopen after the contention assertions.
        drop(_wal_anchor);
        let reopened = root
            .open_existing_v1(
                identity,
                SyntheticCoordinatorClockV1::new(OPEN_NOW_MS + 1),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                OPEN_DEADLINE_MS,
            )
            .expect("contention result passes full invariant reopen");
        assert_eq!(reopened.operation_count(), expected_operations);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DurableContentionObservationV1 {
    operations: i64,
    reservations: i64,
    events: i64,
    total: [i64; 4],
    held: [i64; 4],
}

impl DurableContentionObservationV1 {
    fn read(database: &Path) -> Self {
        let connection = Connection::open(database).expect("contention database opens");
        let operations = count_v1(
            &connection,
            "prepared_operations",
            "operation_state = 'PREPARING'",
        );
        let reservations = count_v1(
            &connection,
            "budget_reservations",
            "reservation_state = 'HELD' AND released_generation IS NULL",
        );
        let events = count_v1(
            &connection,
            "preparation_events",
            "event_kind = 'PREPARED' AND delivery_state = 'PENDING'",
        );
        let (total, held) = connection
            .query_row(
                "SELECT total_cost_micro_units, total_action_count, total_egress_bytes, \
                        total_recovery_bytes, held_cost_micro_units, held_action_count, \
                        held_egress_bytes, held_recovery_bytes FROM budget_scopes",
                [],
                |row| {
                    Ok((
                        [row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?],
                        [row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?],
                    ))
                },
            )
            .expect("one shared scope reads");
        Self {
            operations,
            reservations,
            events,
            total,
            held,
        }
    }

    fn assert_exact_same_operation_winner_v1(self) {
        assert_eq!(self.operations, 1, "one PREPARING operation");
        assert_eq!(self.reservations, 1, "one HELD reservation");
        assert_eq!(self.events, 1, "one PREPARED event");
        assert_eq!(self.held, [0, 1, 0, 4_096]);
        assert_eq!(self.held, self.total, "the one-operation scope is exact");
    }

    fn assert_exact_shared_allowance_v1(self) {
        assert_eq!(self.operations, SHARED_WINNERS as i64);
        assert_eq!(self.reservations, SHARED_WINNERS as i64);
        assert_eq!(self.events, SHARED_WINNERS as i64);
        assert_eq!(self.total, SHARED_TOTAL.map(|value| value as i64));
        assert_eq!(self.held, SHARED_TOTAL.map(|value| value as i64));
        for (held, total) in self.held.into_iter().zip(self.total) {
            assert!(held <= total, "shared allowance exceeded a v1 dimension");
        }
    }
}

fn count_v1(connection: &Connection, table: &str, predicate: &str) -> i64 {
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
            [],
            |row| row.get(0),
        )
        .expect("contention member count reads")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitClassV1 {
    Committed,
    Unclassified,
    Conflict,
    Exhausted,
    Busy,
    Deadline,
    Unavailable,
    Unhealthy,
    Other,
}

fn classify_v1(outcome: PreparationCommitOutcomeV1) -> CommitClassV1 {
    match outcome {
        PreparationCommitOutcomeV1::Committed(_) => CommitClassV1::Committed,
        PreparationCommitOutcomeV1::Unclassified => CommitClassV1::Unclassified,
        PreparationCommitOutcomeV1::Conflict => CommitClassV1::Conflict,
        PreparationCommitOutcomeV1::BudgetExhausted => CommitClassV1::Exhausted,
        PreparationCommitOutcomeV1::Busy => CommitClassV1::Busy,
        PreparationCommitOutcomeV1::PermitDeadlineReached => CommitClassV1::Deadline,
        PreparationCommitOutcomeV1::Unavailable => CommitClassV1::Unavailable,
        PreparationCommitOutcomeV1::Unhealthy => CommitClassV1::Unhealthy,
        _ => CommitClassV1::Other,
    }
}

fn assert_same_operation_classes_v1(
    classes: &[CommitClassV1],
    contender_count: usize,
    observation: DurableContentionObservationV1,
) {
    assert_eq!(classes.len(), contender_count);
    let committed = classes
        .iter()
        .filter(|class| **class == CommitClassV1::Committed)
        .count();
    let conflicts = classes
        .iter()
        .filter(|class| **class == CommitClassV1::Conflict)
        .count();
    assert_eq!(
        committed,
        1,
        "exactly one contender must acknowledge commit; classes={classes:?}; observation={observation:?}",
    );
    assert_eq!(
        conflicts,
        contender_count - 1,
        "serialized same-operation losers must classify as conflicts; classes={classes:?}; observation={observation:?}",
    );
    assert_eq!(
        committed + conflicts,
        contender_count,
        "busy, deadline, unavailable, unhealthy, unclassified and other outcomes remain failures; classes={classes:?}; observation={observation:?}",
    );
    // This offline observation is independent SC-003 state evidence. It never upgrades an
    // unclassified commit into an acknowledged result or substitutes for production readback.
    observation.assert_exact_same_operation_winner_v1();
}

fn assert_shared_allowance_classes_v1(classes: &[CommitClassV1]) {
    assert_eq!(classes.len(), SHARED_CONTENDERS);
    let committed = classes
        .iter()
        .filter(|class| **class == CommitClassV1::Committed)
        .count();
    let exhausted = classes
        .iter()
        .filter(|class| **class == CommitClassV1::Exhausted)
        .count();
    assert_eq!(
        committed, SHARED_WINNERS,
        "the exact aggregate allowance must admit four contenders; classes={classes:?}",
    );
    assert_eq!(
        exhausted,
        SHARED_CONTENDERS - SHARED_WINNERS,
        "every serialized over-capacity contender must be exhausted; classes={classes:?}",
    );
    assert_eq!(
        committed + exhausted,
        SHARED_CONTENDERS,
        "no other outcome class is accepted; classes={classes:?}",
    );
}

fn run_same_operation_thread_round_v1() {
    let fixture = ContentionRootV1::new();
    let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
    provision_synthetic_budget_scope_v1(&fixture.database, &case)
        .expect("same-operation scope provisions");
    let clock = ElapsedCoordinatorClockV1::new(CONTENTION_CLOCK_BASE_MS);
    let deadline = clock.deadline_v1();
    let barrier = Arc::new(Barrier::new(THREAD_CONTENDERS));
    let mut workers = Vec::with_capacity(THREAD_CONTENDERS);
    for _ in 0..THREAD_CONTENDERS {
        let database = fixture.database.clone();
        let case = case.clone();
        let clock = clock.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            classify_v1(commit_synthetic_preparation_until_v1(
                &database,
                &case,
                SyntheticCommitModeV1::Acknowledged,
                &clock,
                deadline,
                CONTENTION_BUSY_WAIT_MS,
            ))
        }));
    }
    let classes = workers
        .into_iter()
        .map(|worker| worker.join().expect("thread contender did not panic"))
        .collect::<Vec<_>>();
    assert_same_operation_classes_v1(
        &classes,
        THREAD_CONTENDERS,
        DurableContentionObservationV1::read(&fixture.database),
    );
    fixture.reopen_and_verify(1);
}

fn shared_cases_v1() -> Vec<SyntheticPreparationCaseV1> {
    let base = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
    (0..SHARED_CONTENDERS)
        .map(|ordinal| base.distinct_operation_in_shared_scope_v1(ordinal as u64, SHARED_REQUEST))
        .collect()
}

fn run_shared_allowance_thread_round_v1() {
    let fixture = ContentionRootV1::new();
    let cases = shared_cases_v1();
    provision_synthetic_budget_scope_with_total_v1(&fixture.database, &cases[0], SHARED_TOTAL)
        .expect("shared allowance provisions once");
    let clock = ElapsedCoordinatorClockV1::new(CONTENTION_CLOCK_BASE_MS);
    let deadline = clock.deadline_v1();
    let barrier = Arc::new(Barrier::new(SHARED_CONTENDERS));
    let workers = cases
        .into_iter()
        .map(|case| {
            let database = fixture.database.clone();
            let clock = clock.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                classify_v1(commit_synthetic_preparation_until_v1(
                    &database,
                    &case,
                    SyntheticCommitModeV1::Acknowledged,
                    &clock,
                    deadline,
                    CONTENTION_BUSY_WAIT_MS,
                ))
            })
        })
        .collect::<Vec<_>>();
    let classes = workers
        .into_iter()
        .map(|worker| worker.join().expect("shared contender did not panic"))
        .collect::<Vec<_>>();
    assert_shared_allowance_classes_v1(&classes);
    DurableContentionObservationV1::read(&fixture.database).assert_exact_shared_allowance_v1();
    fixture.reopen_and_verify(SHARED_WINNERS as u64);
}

fn run_process_round_v1(mode: &str) {
    let fixture = ContentionRootV1::new();
    let same_case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
    if mode == PROBE_SAME_OPERATION {
        provision_synthetic_budget_scope_v1(&fixture.database, &same_case)
            .expect("process same-operation scope provisions");
    } else {
        let cases = shared_cases_v1();
        provision_synthetic_budget_scope_with_total_v1(&fixture.database, &cases[0], SHARED_TOTAL)
            .expect("process shared scope provisions");
    }

    let environment = [
        ProcessProbeEnvironmentV1::new(PROBE_MODE_ENV, mode),
        ProcessProbeEnvironmentV1::new(PROBE_DATABASE_ENV, fixture.database.as_os_str()),
    ];
    let mut probe = SynchronizedProcessProbeV1::spawn_v1(
        "process_probe_child_v1",
        PROCESS_CONTENDERS,
        &environment,
    )
    .expect("synchronized process probes spawn");
    let classes = probe
        .execute_v1()
        .expect("synchronized process probes complete")
        .into_iter()
        .map(|bytes| match bytes.as_slice() {
            b"committed" => CommitClassV1::Committed,
            b"unclassified" => CommitClassV1::Unclassified,
            b"conflict" => CommitClassV1::Conflict,
            b"exhausted" => CommitClassV1::Exhausted,
            b"busy" => CommitClassV1::Busy,
            b"deadline" => CommitClassV1::Deadline,
            b"unavailable" => CommitClassV1::Unavailable,
            b"unhealthy" => CommitClassV1::Unhealthy,
            _ => CommitClassV1::Other,
        })
        .collect::<Vec<_>>();
    if mode == PROBE_SAME_OPERATION {
        assert_same_operation_classes_v1(
            &classes,
            PROCESS_CONTENDERS,
            DurableContentionObservationV1::read(&fixture.database),
        );
        fixture.reopen_and_verify(1);
    } else {
        assert_shared_allowance_classes_v1(&classes);
        DurableContentionObservationV1::read(&fixture.database).assert_exact_shared_allowance_v1();
        fixture.reopen_and_verify(SHARED_WINNERS as u64);
    }
}

fn required_env_v1(name: &str) -> OsString {
    private_process_argument_v1(name).unwrap_or_else(|| panic!("missing private probe input"))
}

#[test]
#[ignore = "private child process entry; invoked only by synchronized parent cases"]
fn process_probe_child_v1() {
    let Some(child) =
        ProcessProbeChildV1::from_environment_v1().expect("private child process inputs validate")
    else {
        return;
    };
    let mode = required_env_v1(PROBE_MODE_ENV);
    let mode = mode.to_string_lossy();
    let database = PathBuf::from(required_env_v1(PROBE_DATABASE_ENV));
    child
        .publish_ready_and_wait_for_go_v1()
        .expect("process READY/GO protocol completes");

    let base = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
    let index = child.index_v1();
    let case = if mode == PROBE_SAME_OPERATION {
        base
    } else if mode == PROBE_SHARED_ALLOWANCE {
        base.distinct_operation_in_shared_scope_v1(index as u64, SHARED_REQUEST)
    } else {
        panic!("unknown private process-probe mode")
    };
    let clock = ElapsedCoordinatorClockV1::new(CONTENTION_CLOCK_BASE_MS);
    let outcome = classify_v1(commit_synthetic_preparation_until_v1(
        &database,
        &case,
        SyntheticCommitModeV1::Acknowledged,
        &clock,
        clock.deadline_v1(),
        CONTENTION_BUSY_WAIT_MS,
    ));
    let result = match outcome {
        CommitClassV1::Committed => b"committed".as_slice(),
        CommitClassV1::Unclassified => b"unclassified".as_slice(),
        CommitClassV1::Conflict => b"conflict".as_slice(),
        CommitClassV1::Exhausted => b"exhausted".as_slice(),
        CommitClassV1::Busy => b"busy".as_slice(),
        CommitClassV1::Deadline => b"deadline".as_slice(),
        CommitClassV1::Unavailable => b"unavailable".as_slice(),
        CommitClassV1::Unhealthy => b"unhealthy".as_slice(),
        CommitClassV1::Other => b"other".as_slice(),
    };
    child
        .publish_result_v1(result)
        .expect("process result publishes");
}

#[test]
fn normal_64_thread_same_operation_commits_exactly_once() {
    run_same_operation_thread_round_v1();
}

#[test]
fn normal_distinct_operations_never_exceed_shared_four_dimension_allowance() {
    run_shared_allowance_thread_round_v1();
}

#[test]
fn normal_8_process_same_and_shared_allowance_contention_is_exact() {
    run_process_round_v1(PROBE_SAME_OPERATION);
    run_process_round_v1(PROBE_SHARED_ALLOWANCE);
}

#[test]
#[ignore = "release PLAN-004 gate: 100 rounds x 64 synchronized threads"]
fn release_64_thread_contention_workload() {
    for _ in 0..RELEASE_THREAD_ROUNDS {
        run_same_operation_thread_round_v1();
    }
}

#[test]
#[ignore = "release PLAN-004 gate: 20 rounds x 8 synchronized child processes"]
fn release_8_process_contention_workload() {
    for _ in 0..RELEASE_PROCESS_ROUNDS {
        run_process_round_v1(PROBE_SAME_OPERATION);
    }
}

#[test]
#[ignore = "release PLAN-004 aggregate gate: distinct operations share all four limits"]
fn release_shared_allowance_contention_workload() {
    for _ in 0..RELEASE_THREAD_ROUNDS {
        run_shared_allowance_thread_round_v1();
    }
    for _ in 0..RELEASE_PROCESS_ROUNDS {
        run_process_round_v1(PROBE_SHARED_ALLOWANCE);
    }
}
