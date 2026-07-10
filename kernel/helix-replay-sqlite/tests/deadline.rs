//! Ownership: T023 held-writer deadlines and no-detached-work behavior.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, DEFAULT_BACKUP_RETRY_WAIT_MS,
    DEFAULT_BACKUP_STEP_PAGES, MAINTENANCE_DEADLINE_MONOTONIC_MS, OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_plan_eligibility::EligibilityDenialV1;
use helix_replay_sqlite::{
    ReplayClockUnavailableV1, ReplayMonotonicClockV1, ReplayStoreConfigV1, SqliteReplayClaimantV1,
};
use rusqlite::{Connection, Error as SqliteError, ErrorCode, OpenFlags};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CLAIM_DEADLINE_MONOTONIC_MS: u64 = common::feature002::PLAN_DEADLINE_MS;
const HELD_WRITER_BUSY_CAP_MS: u64 = 40;
const HOST_SCHEDULER_TOLERANCE_MS: u64 = 50;
const HELD_WRITER_MAX_ELAPSED: Duration =
    Duration::from_millis(HELD_WRITER_BUSY_CAP_MS + HOST_SCHEDULER_TOLERANCE_MS);

#[derive(Clone, Copy)]
enum ScriptedReading {
    Now(u64),
    Unavailable,
}

#[derive(Clone)]
struct ScriptedClock {
    calls: Arc<AtomicU64>,
    switch_on_call: Arc<AtomicU64>,
    before: ScriptedReading,
    after: ScriptedReading,
}

impl ScriptedClock {
    fn new(switch_on_call: u64, before: ScriptedReading, after: ScriptedReading) -> Self {
        Self {
            calls: Arc::new(AtomicU64::new(0)),
            switch_on_call: Arc::new(AtomicU64::new(switch_on_call)),
            before,
            after,
        }
    }

    fn switch_after_before_reads(&self, before_reads: u64) {
        let current = self.calls.load(Ordering::SeqCst);
        self.switch_on_call.store(
            current.saturating_add(before_reads).saturating_add(1),
            Ordering::SeqCst,
        );
    }

    fn reading(reading: ScriptedReading) -> Result<u64, ReplayClockUnavailableV1> {
        match reading {
            ScriptedReading::Now(value) => Ok(value),
            ScriptedReading::Unavailable => Err(ReplayClockUnavailableV1::new()),
        }
    }
}

impl fmt::Debug for ScriptedClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptedClock")
            .finish_non_exhaustive()
    }
}

impl ReplayMonotonicClockV1 for ScriptedClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let reading = if call < self.switch_on_call.load(Ordering::SeqCst) {
            self.before
        } else {
            self.after
        };
        Self::reading(reading)
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

impl ReplayMonotonicClockV1 for ExpireWhenDurableClaimClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        let connection = Connection::open_with_flags(
            self.database.as_ref(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ReplayClockUnavailableV1::new())?;
        let claim_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |row| row.get(0))
            .map_err(|_| ReplayClockUnavailableV1::new())?;
        if claim_count == 0 {
            Ok(common::feature002::NOW_MONOTONIC_MS)
        } else {
            Ok(CLAIM_DEADLINE_MONOTONIC_MS)
        }
    }
}

#[derive(Clone)]
struct ExpireWhenWriterHeldClock {
    database: Arc<PathBuf>,
    enabled: Arc<AtomicBool>,
}

impl ExpireWhenWriterHeldClock {
    fn new(root: &SyntheticTempRoot) -> Self {
        Self {
            database: Arc::new(root.closed_database_path()),
            enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
}

impl ReplayMonotonicClockV1 for ExpireWhenWriterHeldClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        if !self.enabled.load(Ordering::SeqCst) {
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

fn config_with_busy_cap(root: &SyntheticTempRoot, cap_ms: u64) -> ReplayStoreConfigV1 {
    ReplayStoreConfigV1::try_new(
        root.trusted_root(),
        cap_ms,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("controlled deadline configuration was rejected"))
}

fn assert_replay_denial(
    result: Result<
        helix_plan_eligibility::EligiblePlanV1,
        helix_plan_eligibility::EligibilityFailureV1,
    >,
    expected: EligibilityDenialV1,
) {
    let failure = result
        .err()
        .unwrap_or_else(|| panic!("deadline-denied fixture was accepted"));
    assert_eq!(failure.denial(), expected);
}

fn assert_empty(root: &SyntheticTempRoot) {
    let claimant = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("deadline fixture reopen failed"));
    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("deadline fixture verification failed"));
    assert_eq!(verification.claim_count(), 0);
    assert_eq!(verification.claimant_generation(), 0);
}

fn open_blocker(root: &SyntheticTempRoot) -> Connection {
    let connection = Connection::open(root.closed_database_path())
        .unwrap_or_else(|_| panic!("held-writer fixture open failed"));
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap_or_else(|_| panic!("held-writer fixture lock failed"));
    connection
}

#[test]
fn already_expired_binding_returns_unavailable_without_mutation() {
    let root = SyntheticTempRoot::new("deadline-expired");
    let clock = InjectedClock::coherent();
    let claimant = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("expired deadline store open failed"));
    clock.set(CLAIM_DEADLINE_MONOTONIC_MS);

    let (result, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert_replay_denial(result, EligibilityDenialV1::ReplayUnavailable);
    assert_eq!(observed, ObservedReplayOutcome::Unavailable);
    drop(claimant);
    assert_empty(&root);
}

#[test]
fn clock_unavailable_after_open_returns_unavailable_without_mutation() {
    let root = SyntheticTempRoot::new("deadline-clock-unavailable");
    let clock = ScriptedClock::new(
        u64::MAX,
        ScriptedReading::Now(common::feature002::NOW_MONOTONIC_MS),
        ScriptedReading::Unavailable,
    );
    let claimant = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("scripted clock store open failed"));
    clock.switch_after_before_reads(0);

    let (result, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert_replay_denial(result, EligibilityDenialV1::ReplayUnavailable);
    assert_eq!(observed, ObservedReplayOutcome::Unavailable);
    drop(claimant);
    assert_empty(&root);
}

#[test]
fn deadline_reached_after_writer_acquisition_rolls_back_without_a_row() {
    let root = SyntheticTempRoot::new("deadline-after-writer");
    drop(open_store(&root, InjectedClock::coherent()));
    // The injected clock probes the writer lock: it stays live during setup and reaches
    // the deadline only after the claimant owns BEGIN IMMEDIATE.
    let clock = ExpireWhenWriterHeldClock::new(&root);
    let claimant = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("post-writer deadline store open failed"));
    clock.enable();

    let (result, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert_replay_denial(result, EligibilityDenialV1::ReplayUnavailable);
    assert_eq!(observed, ObservedReplayOutcome::Unavailable);
    drop(claimant);
    assert_empty(&root);
}

#[test]
fn held_writer_returns_within_the_configured_busy_bound_and_is_unavailable() {
    let root = SyntheticTempRoot::new("deadline-held-writer");
    let claimant = SqliteReplayClaimantV1::open_or_create(
        config_with_busy_cap(&root, HELD_WRITER_BUSY_CAP_MS),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("held-writer store open failed"));
    let blocker = open_blocker(&root);

    let started = Instant::now();
    let (result, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    let elapsed = started.elapsed();
    assert_replay_denial(result, EligibilityDenialV1::ReplayUnavailable);
    assert_eq!(observed, ObservedReplayOutcome::Unavailable);
    assert!(
        elapsed <= HELD_WRITER_MAX_ELAPSED,
        "held-writer elapsed_ms={} exceeded max_ms={}",
        elapsed.as_millis(),
        HELD_WRITER_MAX_ELAPSED.as_millis()
    );
    println!(
        "PLAN-003 held-writer scenario=bounded-unavailable busy_cap_ms={} scheduler_tolerance_ms={} elapsed_ns={} status=pass",
        HELD_WRITER_BUSY_CAP_MS,
        HOST_SCHEDULER_TOLERANCE_MS,
        elapsed.as_nanos()
    );

    blocker
        .execute_batch("ROLLBACK")
        .unwrap_or_else(|_| panic!("held-writer fixture rollback failed"));
    drop(blocker);
}

#[test]
fn deadline_reached_after_commit_returns_ambiguous_and_retains_the_row() {
    let root = SyntheticTempRoot::new("deadline-post-commit");
    drop(open_store(&root, InjectedClock::coherent()));
    // A separate read view sees zero rows before commit and one row only after the
    // durable commit becomes visible, so this test is independent of clock read count.
    let clock = ExpireWhenDurableClaimClock::new(&root);
    let claimant =
        SqliteReplayClaimantV1::open_or_create(root.config(), clock, OPEN_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("post-commit deadline store open failed"));

    let (result, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert_replay_denial(result, EligibilityDenialV1::ReplayAmbiguous);
    assert_eq!(observed, ObservedReplayOutcome::Ambiguous);
    drop(claimant);

    let claimant = SqliteReplayClaimantV1::open_or_create(
        root.config(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("post-commit deadline reopen failed"));
    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("post-commit durable row verification failed"));
    assert_eq!(verification.claim_count(), 1);
    assert_eq!(verification.claimant_generation(), 1);

    let (repeat, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert_replay_denial(repeat, EligibilityDenialV1::ReplayAlreadyClaimed);
    assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);
}

#[test]
fn timed_out_held_writer_does_not_create_a_row_after_return() {
    let root = SyntheticTempRoot::new("deadline-no-detached-row");
    let claimant = SqliteReplayClaimantV1::open_or_create(
        config_with_busy_cap(&root, HELD_WRITER_BUSY_CAP_MS),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("no-detached-row store open failed"));
    let blocker = open_blocker(&root);
    let started = Instant::now();
    let (result, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    let elapsed = started.elapsed();
    assert_replay_denial(result, EligibilityDenialV1::ReplayUnavailable);
    assert_eq!(observed, ObservedReplayOutcome::Unavailable);
    assert!(
        elapsed <= HELD_WRITER_MAX_ELAPSED,
        "no-detached-row elapsed_ms={} exceeded max_ms={}",
        elapsed.as_millis(),
        HELD_WRITER_MAX_ELAPSED.as_millis()
    );
    println!(
        "PLAN-003 held-writer scenario=no-detached-row busy_cap_ms={} scheduler_tolerance_ms={} elapsed_ns={} status=pass",
        HELD_WRITER_BUSY_CAP_MS,
        HOST_SCHEDULER_TOLERANCE_MS,
        elapsed.as_nanos()
    );

    blocker
        .execute_batch("ROLLBACK")
        .unwrap_or_else(|_| panic!("no-detached-row blocker rollback failed"));
    drop(blocker);
    drop(claimant);
    assert_empty(&root);
}
