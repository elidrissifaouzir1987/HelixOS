//! T043 red tests for caller-owned absolute writer deadlines.
//!
//! These cases hold `BEGIN IMMEDIATE`, require the injected monotonic deadline to win
//! over a longer configured busy wait, and then observe/reopen for at least 250 ms to
//! prove that no detached preparation mutation appears after return.
//!
//! Expected private implementation seam (T049): the synthetic commit accepts an
//! injected coordinator clock, absolute caller deadline and configured busy-wait cap.

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

use common::{
    SyntheticCoordinatorClockV1, SyntheticCoordinatorRootV1, SyntheticHistoricalPlanKeyResolverV1,
};
use helix_coordinator_sqlite::{CoordinatorClockUnavailableV1, CoordinatorMonotonicClockV1};
use helix_plan_preparation::PreparationCommitOutcomeV1;
use prepare::{
    commit_synthetic_preparation_until_v1, provision_synthetic_budget_scope_v1,
    SyntheticCommitModeV1, SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const OPEN_NOW_MS: u64 = 100;
const OPEN_DEADLINE_MS: u64 = 10_000;
const DEADLINE_CLOCK_BASE_MS: u64 = 1_000;
const CALLER_DEADLINE_DELTA_MS: u64 = 40;
const LONGER_BUSY_WAIT_MS: u64 = 500;
const SCHEDULER_TOLERANCE_MS: u64 = 50;
const POST_RETURN_OBSERVATION: Duration = Duration::from_millis(275);
const RELEASE_ATTEMPTS: usize = 1_000;

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
        self.base_ms + CALLER_DEADLINE_DELTA_MS
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

#[derive(Clone, Copy)]
enum FixedReadingV1 {
    Now(u64),
    Unavailable,
}

#[derive(Clone, Copy)]
struct FixedCoordinatorClockV1(FixedReadingV1);

impl CoordinatorMonotonicClockV1 for FixedCoordinatorClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        match self.0 {
            FixedReadingV1::Now(now) => Ok(now),
            FixedReadingV1::Unavailable => Err(CoordinatorClockUnavailableV1::new()),
        }
    }
}

struct DeadlineRootV1 {
    root: SyntheticCoordinatorRootV1,
    identity: helix_coordinator_sqlite::CoordinatorRootIdentityEvidenceV1,
    database: PathBuf,
    case: SyntheticPreparationCaseV1,
    baseline: DeadlineObservationV1,
}

impl DeadlineRootV1 {
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
        let database = std::fs::canonicalize(root.path())
            .expect("synthetic coordinator root canonicalizes")
            .join("coordinator.sqlite3");
        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
        provision_synthetic_budget_scope_v1(&database, &case)
            .expect("deadline scope provisions once");
        let baseline = DeadlineObservationV1::read(&database);
        baseline.assert_empty_v1();
        Self {
            root,
            identity,
            database,
            case,
            baseline,
        }
    }

    fn reopen_and_assert_empty_v1(&self) {
        let reopened = self
            .root
            .open_existing_v1(
                self.identity,
                SyntheticCoordinatorClockV1::new(OPEN_NOW_MS + 1),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                OPEN_DEADLINE_MS,
            )
            .expect("deadline result passes full invariant reopen");
        assert_eq!(reopened.operation_count(), 0);
        drop(reopened);
        assert_eq!(DeadlineObservationV1::read(&self.database), self.baseline);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeadlineObservationV1 {
    metadata: [i64; 4],
    operations: i64,
    reservations: i64,
    events: i64,
    held: [i64; 4],
}

impl DeadlineObservationV1 {
    fn read(database: &Path) -> Self {
        let connection = Connection::open(database).expect("deadline database opens");
        let metadata = connection
            .query_row(
                "SELECT store_generation, operation_generation, budget_generation, \
                        event_generation FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
            )
            .expect("deadline metadata reads");
        let held = connection
            .query_row(
                "SELECT held_cost_micro_units, held_action_count, held_egress_bytes, \
                        held_recovery_bytes FROM budget_scopes",
                [],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
            )
            .expect("deadline held vector reads");
        Self {
            metadata,
            operations: count_v1(
                &connection,
                "prepared_operations",
                "operation_state = 'PREPARING'",
            ),
            reservations: count_v1(
                &connection,
                "budget_reservations",
                "reservation_state = 'HELD' AND released_generation IS NULL",
            ),
            events: count_v1(
                &connection,
                "preparation_events",
                "event_kind = 'PREPARED' AND delivery_state = 'PENDING'",
            ),
            held,
        }
    }

    fn assert_empty_v1(self) {
        assert_eq!(self.operations, 0);
        assert_eq!(self.reservations, 0);
        assert_eq!(self.events, 0);
        assert_eq!(self.held, [0; 4]);
    }
}

fn count_v1(connection: &Connection, table: &str, predicate: &str) -> i64 {
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
            [],
            |row| row.get(0),
        )
        .expect("deadline member count reads")
}

fn open_writer_blocker_v1(database: &Path) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection =
        Connection::open_with_flags(database, flags).expect("held-writer connection opens");
    connection
        .busy_timeout(Duration::ZERO)
        .expect("held-writer busy timeout configures");
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .expect("held writer acquires BEGIN IMMEDIATE");
    connection
}

fn release_writer_v1(blocker: Connection) {
    blocker
        .execute_batch("ROLLBACK")
        .expect("held writer rolls back");
}

fn assert_deadline_bound_v1(elapsed: Duration) {
    let maximum = Duration::from_millis(CALLER_DEADLINE_DELTA_MS + SCHEDULER_TOLERANCE_MS);
    assert!(
        elapsed <= maximum,
        "held-writer elapsed_ms={} exceeded caller_delta_ms={} + tolerance_ms={}",
        elapsed.as_millis(),
        CALLER_DEADLINE_DELTA_MS,
        SCHEDULER_TOLERANCE_MS,
    );
}

fn run_held_writer_attempt_v1(fixture: &DeadlineRootV1) {
    let blocker = open_writer_blocker_v1(&fixture.database);
    let clock = ElapsedCoordinatorClockV1::new(DEADLINE_CLOCK_BASE_MS);
    let deadline = clock.deadline_v1();
    let started = Instant::now();
    let outcome = commit_synthetic_preparation_until_v1(
        &fixture.database,
        &fixture.case,
        SyntheticCommitModeV1::Acknowledged,
        &clock,
        deadline,
        LONGER_BUSY_WAIT_MS,
    );
    let elapsed = started.elapsed();
    assert!(
        matches!(outcome, PreparationCommitOutcomeV1::Busy),
        "writer loss before the caller deadline must classify as store busy: {outcome:?}",
    );
    assert_deadline_bound_v1(elapsed);
    assert_eq!(
        DeadlineObservationV1::read(&fixture.database),
        fixture.baseline
    );

    release_writer_v1(blocker);
    let observation_started = Instant::now();
    std::thread::sleep(POST_RETURN_OBSERVATION);
    assert!(observation_started.elapsed() >= Duration::from_millis(250));
    fixture.reopen_and_assert_empty_v1();
}

#[test]
fn held_writer_returns_by_absolute_injected_deadline_and_never_mutates_later() {
    let fixture = DeadlineRootV1::new();
    run_held_writer_attempt_v1(&fixture);
}

#[test]
fn deadline_equality_is_exclusive_and_does_not_wait_or_mutate() {
    let fixture = DeadlineRootV1::new();
    let blocker = open_writer_blocker_v1(&fixture.database);
    let deadline = DEADLINE_CLOCK_BASE_MS;
    let clock = FixedCoordinatorClockV1(FixedReadingV1::Now(deadline));
    let started = Instant::now();
    let outcome = commit_synthetic_preparation_until_v1(
        &fixture.database,
        &fixture.case,
        SyntheticCommitModeV1::Acknowledged,
        &clock,
        deadline,
        LONGER_BUSY_WAIT_MS,
    );
    assert!(
        matches!(outcome, PreparationCommitOutcomeV1::PermitDeadlineReached),
        "now == deadline is already expired: {outcome:?}",
    );
    assert!(started.elapsed() <= Duration::from_millis(SCHEDULER_TOLERANCE_MS));
    assert_eq!(
        DeadlineObservationV1::read(&fixture.database),
        fixture.baseline
    );
    release_writer_v1(blocker);
    fixture.reopen_and_assert_empty_v1();
}

#[test]
fn unavailable_injected_clock_fails_closed_without_writer_or_mutation() {
    let fixture = DeadlineRootV1::new();
    let clock = FixedCoordinatorClockV1(FixedReadingV1::Unavailable);
    let outcome = commit_synthetic_preparation_until_v1(
        &fixture.database,
        &fixture.case,
        SyntheticCommitModeV1::Acknowledged,
        &clock,
        DEADLINE_CLOCK_BASE_MS + CALLER_DEADLINE_DELTA_MS,
        LONGER_BUSY_WAIT_MS,
    );
    assert!(matches!(outcome, PreparationCommitOutcomeV1::Unavailable));
    fixture.reopen_and_assert_empty_v1();
}

#[test]
#[ignore = "release PLAN-004 gate: 1,000 held-writer deadlines plus 250 ms observations"]
fn release_held_writer_deadline_and_no_late_mutation_workload() {
    let fixture = DeadlineRootV1::new();
    for _ in 0..RELEASE_ATTEMPTS {
        run_held_writer_attempt_v1(&fixture);
    }
}
