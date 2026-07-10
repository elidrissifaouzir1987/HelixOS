use super::*;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

const SCRIPT_NOW_MONOTONIC_MS: u64 = 10;
const SCRIPT_OPEN_DEADLINE_MONOTONIC_MS: u64 = 1_000;
static SCRIPT_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn attempt() -> ClaimAttemptV1 {
    ClaimAttemptV1 {
        instance_epoch: 7,
        nonce: [0x11; 16],
        operation_id: "operation:test-readback".to_owned(),
        binding_digest: Sha256Digest::digest(b"synthetic binding"),
        deadline_monotonic_ms: 100,
        claim_id: Sha256Digest::digest(b"synthetic attempt"),
    }
}

fn receipt(attempt: &ClaimAttemptV1, generation: u64) -> ReplayClaimReceiptV1 {
    ReplayClaimReceiptV1::try_new(attempt.claim_id, generation, attempt.binding_digest)
        .expect("synthetic receipt is valid")
}

fn stored(attempt: &ClaimAttemptV1, generation: u64) -> StoredClaimV1 {
    StoredClaimV1 {
        instance_epoch: attempt.instance_epoch,
        nonce: attempt.nonce,
        operation_id: attempt.operation_id.clone(),
        binding_digest: attempt.binding_digest,
        claim_id: attempt.claim_id,
        claimant_generation: generation,
    }
}

#[derive(Clone)]
struct ScriptClockV1 {
    now_monotonic_ms: Arc<AtomicU64>,
}

impl ScriptClockV1 {
    fn new(now_monotonic_ms: u64) -> Self {
        Self {
            now_monotonic_ms: Arc::new(AtomicU64::new(now_monotonic_ms)),
        }
    }

    fn set(&self, now_monotonic_ms: u64) {
        self.now_monotonic_ms
            .store(now_monotonic_ms, Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        self.now_monotonic_ms.load(Ordering::SeqCst)
    }
}

impl ReplayMonotonicClockV1 for ScriptClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, crate::ReplayClockUnavailableV1> {
        Ok(self.now())
    }
}

struct ScriptRootV1 {
    path: PathBuf,
}

impl ScriptRootV1 {
    fn new(label: &str) -> Self {
        let sequence = SCRIPT_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helix-replay-claim-io-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("scripted claim root is created");
        Self { path }
    }

    fn config(&self) -> crate::ReplayStoreConfigV1 {
        let root = crate::TrustedLocalStoreRootV1::try_from_provisioned(self.path.clone())
            .expect("scripted claim root is trusted for the test");
        crate::ReplayStoreConfigV1::try_new(root, 250, 64, 1)
            .expect("scripted claim configuration is valid")
    }
}

impl Drop for ScriptRootV1 {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct ScriptFixtureV1 {
    claimant: SqliteReplayClaimantV1<ScriptClockV1>,
    clock: ScriptClockV1,
    _root: ScriptRootV1,
}

impl ScriptFixtureV1 {
    fn new(label: &str) -> Self {
        let root = ScriptRootV1::new(label);
        let clock = ScriptClockV1::new(SCRIPT_NOW_MONOTONIC_MS);
        let claimant = SqliteReplayClaimantV1::open_or_create(
            root.config(),
            clock.clone(),
            SCRIPT_OPEN_DEADLINE_MONOTONIC_MS,
        )
        .expect("scripted claim store opens");
        Self {
            claimant,
            clock,
            _root: root,
        }
    }

    fn persisted_summary(&self) -> (u64, u64) {
        let connection = Connection::open(self.claimant.config.database_path())
            .expect("scripted claim store is readable");
        let generation = connection
            .query_row(
                "SELECT claimant_generation FROM replay_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("scripted generation is readable");
        let claim_count = connection
            .query_row("SELECT COUNT(*) FROM replay_claims", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("scripted claim count is readable");
        (
            u64::try_from(generation).expect("scripted generation is non-negative"),
            u64::try_from(claim_count).expect("scripted claim count is non-negative"),
        )
    }
}

fn synthetic_commit_error() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR), None)
}

fn commit_then_report_error(transaction: Transaction<'_>) -> rusqlite::Result<()> {
    transaction.commit()?;
    Err(synthetic_commit_error())
}

fn rollback_then_report_error(transaction: Transaction<'_>) -> rusqlite::Result<()> {
    transaction.rollback()?;
    Err(synthetic_commit_error())
}

fn native_scripted_readback(
    claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
    attempt: &ClaimAttemptV1,
    receipt: &ReplayClaimReceiptV1,
) -> Result<Connection, InternalStoreError> {
    <NativeClaimIoV1 as ClaimIoV1<ScriptClockV1>>::open_readback(claimant, attempt, receipt)
}

fn install_scripted_row(
    claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
    row: &StoredClaimV1,
) -> Result<(), InternalStoreError> {
    let mut connection = Connection::open(claimant.config.database_path())
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    let updated = transaction
        .execute(
            "UPDATE replay_store_meta
             SET claimant_generation = ?1
             WHERE singleton = 1 AND claimant_generation = 0",
            [row.claimant_generation as i64],
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    if updated != 1 {
        return Err(InternalStoreError::InvariantFailed);
    }
    let inserted = transaction
        .execute(
            "INSERT INTO replay_claims (
                instance_epoch, nonce, operation_id, binding_digest, claim_id,
                claimant_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.instance_epoch as i64,
                row.nonce.as_slice(),
                row.operation_id.as_str(),
                row.binding_digest.as_bytes().as_slice(),
                row.claim_id.as_bytes().as_slice(),
                row.claimant_generation as i64,
            ],
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    if inserted != 1 {
        return Err(InternalStoreError::InvariantFailed);
    }
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))
}

fn install_unrelated_generation_gap(
    claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
) -> Result<(), InternalStoreError> {
    let mut connection = Connection::open(claimant.config.database_path())
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    let updated = transaction
        .execute(
            "UPDATE replay_store_meta
             SET claimant_generation = 3
             WHERE singleton = 1 AND claimant_generation = 1",
            [],
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    if updated != 1 {
        return Err(InternalStoreError::InvariantFailed);
    }
    let inserted = transaction
        .execute(
            "INSERT INTO replay_claims (
                instance_epoch, nonce, operation_id, binding_digest, claim_id,
                claimant_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                99_i64,
                &[0x99_u8; 16][..],
                "operation:scripted-unrelated-gap",
                &[0x88_u8; 32][..],
                &[0x77_u8; 32][..],
                3_i64,
            ],
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    if inserted != 1 {
        return Err(InternalStoreError::InvariantFailed);
    }
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))
}

struct CommitErrorExactIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorExactIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        commit_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        native_scripted_readback(claimant, attempt, receipt)
    }
}

struct CommitErrorPriorExactIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorPriorExactIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        let mut row = stored(attempt, receipt.claimant_generation());
        row.claim_id = Sha256Digest::digest(b"scripted prior exact claim");
        install_scripted_row(claimant, &row)?;
        native_scripted_readback(claimant, attempt, receipt)
    }
}

struct CommitErrorConflictIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorConflictIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        let mut row = stored(attempt, receipt.claimant_generation());
        row.operation_id = "operation:scripted-conflict".to_owned();
        row.binding_digest = Sha256Digest::digest(b"scripted conflicting binding");
        row.claim_id = Sha256Digest::digest(b"scripted conflicting claim");
        install_scripted_row(claimant, &row)?;
        native_scripted_readback(claimant, attempt, receipt)
    }
}

struct CommitErrorHealthyAbsenceIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorHealthyAbsenceIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        native_scripted_readback(claimant, attempt, receipt)
    }
}

struct CommitErrorFailedReadbackIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorFailedReadbackIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        _claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        _attempt: &ClaimAttemptV1,
        _receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        Err(InternalStoreError::StoreUnavailable)
    }
}

struct CommitErrorCandidateCollisionIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorCandidateCollisionIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        let row = StoredClaimV1 {
            instance_epoch: attempt.instance_epoch + 1,
            nonce: [0x66; 16],
            operation_id: "operation:scripted-candidate-collision".to_owned(),
            binding_digest: Sha256Digest::digest(b"scripted candidate collision binding"),
            claim_id: attempt.claim_id,
            claimant_generation: receipt.claimant_generation(),
        };
        install_scripted_row(claimant, &row)?;
        native_scripted_readback(claimant, attempt, receipt)
    }
}

struct CommitErrorLateReadbackIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorLateReadbackIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        commit_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        native_scripted_readback(claimant, attempt, receipt)
    }

    fn after_readback_lease_acquired(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
    ) {
        claimant.clock.set(attempt.deadline_monotonic_ms);
    }
}

struct CommitErrorExactInvariantAtDeadlineIoV1;

impl ClaimIoV1<ScriptClockV1> for CommitErrorExactInvariantAtDeadlineIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        commit_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        install_unrelated_generation_gap(claimant)?;
        native_scripted_readback(claimant, attempt, receipt)
    }

    fn after_readback_lease_acquired(
        claimant: &SqliteReplayClaimantV1<ScriptClockV1>,
        attempt: &ClaimAttemptV1,
    ) {
        claimant.clock.set(attempt.deadline_monotonic_ms);
    }
}

#[test]
fn private_native_claim_io_is_zero_sized() {
    assert_eq!(std::mem::size_of::<NativeClaimIoV1>(), 0);
}

#[test]
fn commit_error_exact_attempt_is_recovered_as_claimed() {
    let fixture = ScriptFixtureV1::new("exact");
    let attempt = attempt();
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorExactIoV1>(&attempt);
    let ReplayClaimOutcomeV1::Claimed(receipt) = outcome else {
        panic!("exact commit-error readback was not claimed");
    };
    assert_eq!(receipt.claim_id(), attempt.claim_id);
    assert_eq!(receipt.claimant_generation(), 1);
    assert_eq!(receipt.binding_digest(), attempt.binding_digest);
    assert_eq!(fixture.persisted_summary(), (1, 1));
}

#[test]
fn commit_error_prior_exact_is_recovered_as_already_claimed() {
    let fixture = ScriptFixtureV1::new("prior-exact");
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorPriorExactIoV1>(&attempt());
    assert!(matches!(outcome, ReplayClaimOutcomeV1::AlreadyClaimed));
    assert_eq!(fixture.persisted_summary(), (1, 1));
}

#[test]
fn commit_error_conflict_is_recovered_as_binding_conflict() {
    let fixture = ScriptFixtureV1::new("conflict");
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorConflictIoV1>(&attempt());
    assert!(matches!(outcome, ReplayClaimOutcomeV1::BindingConflict));
    assert_eq!(fixture.persisted_summary(), (1, 1));
}

#[test]
fn commit_error_healthy_absence_is_recovered_as_unavailable() {
    let fixture = ScriptFixtureV1::new("healthy-absence");
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorHealthyAbsenceIoV1>(&attempt());
    assert!(matches!(outcome, ReplayClaimOutcomeV1::Unavailable));
    assert_eq!(fixture.persisted_summary(), (0, 0));
}

#[test]
fn commit_error_failed_readback_remains_ambiguous() {
    let fixture = ScriptFixtureV1::new("failed-readback");
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorFailedReadbackIoV1>(&attempt());
    assert!(matches!(outcome, ReplayClaimOutcomeV1::Ambiguous));
    assert_eq!(fixture.persisted_summary(), (0, 0));
}

#[test]
fn commit_error_candidate_collision_remains_ambiguous() {
    let fixture = ScriptFixtureV1::new("candidate-collision");
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorCandidateCollisionIoV1>(&attempt());
    assert!(matches!(outcome, ReplayClaimOutcomeV1::Ambiguous));
    assert_eq!(fixture.persisted_summary(), (1, 1));
}

#[test]
fn commit_error_late_readback_remains_ambiguous_after_exact_commit() {
    let fixture = ScriptFixtureV1::new("late-readback");
    let attempt = attempt();
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorLateReadbackIoV1>(&attempt);
    assert!(matches!(outcome, ReplayClaimOutcomeV1::Ambiguous));
    assert_eq!(fixture.clock.now(), attempt.deadline_monotonic_ms);
    assert_eq!(fixture.persisted_summary(), (1, 1));
}

#[test]
fn invariant_detected_as_deadline_expires_is_quarantined_with_held_readback_lease() {
    let fixture = ScriptFixtureV1::new("invariant-at-deadline");
    let attempt = attempt();
    let outcome = fixture
        .claimant
        .claim_attempt_with_io::<CommitErrorExactInvariantAtDeadlineIoV1>(&attempt);
    assert!(matches!(outcome, ReplayClaimOutcomeV1::Ambiguous));
    assert_eq!(fixture.clock.now(), attempt.deadline_monotonic_ms);
    assert!(!fixture.claimant.healthy.load(Ordering::Acquire));
    assert!(fixture
        ._root
        .path
        .join(crate::config::QUARANTINE_MARKER_FILENAME)
        .is_file());
    assert_eq!(fixture.persisted_summary(), (3, 2));
}

#[test]
fn commit_readback_requires_exact_attempt_identity_and_live_deadline() {
    let attempt = attempt();
    let receipt = receipt(&attempt, 3);
    let row = stored(&attempt, 3);
    assert_eq!(
        classify_readback(Some(&row), Some(&row), Some(&row), &attempt, &receipt, true,),
        ReadbackDecisionV1::ThisAttempt
    );
    assert_eq!(
        classify_readback(
            Some(&row),
            Some(&row),
            Some(&row),
            &attempt,
            &receipt,
            false,
        ),
        ReadbackDecisionV1::Ambiguous
    );
}

#[test]
fn later_exact_contender_is_prior_not_this_attempt() {
    let attempt = attempt();
    let receipt = receipt(&attempt, 3);
    let mut later = stored(&attempt, 3);
    later.claim_id = Sha256Digest::digest(b"different attempt identity");
    assert_eq!(
        classify_readback(Some(&later), Some(&later), None, &attempt, &receipt, true,),
        ReadbackDecisionV1::PriorExact
    );
}

#[test]
fn healthy_absence_and_conflicts_remain_closed() {
    let attempt = attempt();
    let receipt = receipt(&attempt, 3);
    assert_eq!(
        classify_readback(None, None, None, &attempt, &receipt, true),
        ReadbackDecisionV1::Absent
    );

    let mut conflict = stored(&attempt, 2);
    conflict.binding_digest = Sha256Digest::digest(b"conflicting binding");
    assert_eq!(
        classify_readback(
            Some(&conflict),
            Some(&conflict),
            None,
            &attempt,
            &receipt,
            true,
        ),
        ReadbackDecisionV1::Conflict
    );
    assert_eq!(
        classify_readback(Some(&conflict), None, None, &attempt, &receipt, true,),
        ReadbackDecisionV1::Conflict
    );

    conflict.claim_id = attempt.claim_id;
    assert_eq!(
        classify_readback(
            Some(&conflict),
            Some(&conflict),
            Some(&conflict),
            &attempt,
            &receipt,
            true,
        ),
        ReadbackDecisionV1::Ambiguous
    );
}

#[test]
fn candidate_claim_id_is_required_for_exact_commit_and_for_proven_absence() {
    let attempt = attempt();
    let receipt = receipt(&attempt, 3);
    let exact = stored(&attempt, 3);
    assert_eq!(
        classify_readback(Some(&exact), Some(&exact), None, &attempt, &receipt, true,),
        ReadbackDecisionV1::Ambiguous
    );

    let mut occupied_candidate = exact.clone();
    occupied_candidate.operation_id = "operation:unrelated-collision".to_owned();
    occupied_candidate.nonce = [0x77; 16];
    assert_eq!(
        classify_readback(
            None,
            None,
            Some(&occupied_candidate),
            &attempt,
            &receipt,
            true,
        ),
        ReadbackDecisionV1::Ambiguous
    );
}

#[test]
fn every_late_readback_is_ambiguous() {
    let attempt = attempt();
    let receipt = receipt(&attempt, 3);
    let exact = stored(&attempt, 3);
    let mut prior = exact.clone();
    prior.claim_id = Sha256Digest::digest(b"prior exact attempt");
    let mut conflict = exact.clone();
    conflict.binding_digest = Sha256Digest::digest(b"conflicting binding");

    assert_eq!(
        classify_readback(None, None, None, &attempt, &receipt, false),
        ReadbackDecisionV1::Ambiguous
    );
    assert_eq!(
        classify_readback(Some(&prior), Some(&prior), None, &attempt, &receipt, false,),
        ReadbackDecisionV1::Ambiguous
    );
    assert_eq!(
        classify_readback(
            Some(&conflict),
            Some(&conflict),
            None,
            &attempt,
            &receipt,
            false,
        ),
        ReadbackDecisionV1::Ambiguous
    );
}

#[test]
fn every_definitive_readback_requires_full_store_health() {
    fn schema_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("in-memory SQLite is available");
        connection
            .execute_batch(crate::schema::REPLAY_STORE_SCHEMA_V1_SQL)
            .expect("embedded replay schema is valid");
        connection
    }

    let mut healthy = schema_connection();
    let transaction = healthy
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .expect("healthy read transaction starts");
    assert_eq!(
        verify_definitive_readback(&transaction, ReadbackDecisionV1::Absent),
        Ok(())
    );
    transaction
        .rollback()
        .expect("healthy read transaction rolls back");

    let invalid = schema_connection();
    invalid
        .execute(
            "UPDATE replay_store_meta SET claimant_generation = 1 WHERE singleton = 1",
            [],
        )
        .expect("inconsistent metadata fixture is installed");
    let mut invalid = invalid;
    let transaction = invalid
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .expect("invalid read transaction starts");
    assert_eq!(
        verify_definitive_readback(&transaction, ReadbackDecisionV1::ThisAttempt),
        Err(InternalStoreError::InvariantFailed)
    );
    transaction
        .rollback()
        .expect("invalid read transaction rolls back");
}

#[test]
fn transient_and_provider_query_errors_do_not_latch_claimant_unhealthy() {
    let busy =
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None);
    let provider_failure = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
        None,
    );
    let healthy = AtomicBool::new(true);

    let busy = map_claim_query_error(&busy);
    assert_eq!(busy, InternalStoreError::StoreBusy);
    latch_unhealthy_for_claim_error(&healthy, busy);
    assert!(healthy.load(Ordering::Acquire));

    let unavailable = map_claim_query_error(&provider_failure);
    assert_eq!(unavailable, InternalStoreError::StoreUnavailable);
    latch_unhealthy_for_claim_error(&healthy, unavailable);
    assert!(healthy.load(Ordering::Acquire));
}

#[test]
fn persisted_decode_errors_are_invariants_and_latch_unhealthy() {
    let conversion =
        rusqlite::Error::InvalidColumnType(0, "nonce".to_owned(), rusqlite::types::Type::Text);
    let mapped = map_claim_query_error(&conversion);
    assert_eq!(mapped, InternalStoreError::InvariantFailed);

    let raw = (
        7,
        vec![0x11; 15],
        "operation:invalid-nonce".to_owned(),
        vec![0x22; 32],
        vec![0x33; 32],
        1,
    );
    assert!(matches!(
        decode_raw_claim(raw),
        Err(InternalStoreError::InvariantFailed)
    ));

    let healthy = AtomicBool::new(true);
    latch_unhealthy_for_claim_error(&healthy, mapped);
    assert!(!healthy.load(Ordering::Acquire));
}

#[test]
fn generation_exhaustion_is_distinct_from_missing_or_invalid_metadata() {
    fn connection_with_generation(generation: Option<i64>) -> Connection {
        let connection = Connection::open_in_memory().expect("in-memory SQLite is available");
        connection
            .execute_batch(
                "CREATE TABLE replay_store_meta (
                    singleton INTEGER PRIMARY KEY,
                    claimant_generation INTEGER NOT NULL
                 );",
            )
            .expect("synthetic metadata schema is valid");
        if let Some(generation) = generation {
            connection
                .execute(
                    "INSERT INTO replay_store_meta (singleton, claimant_generation)
                     VALUES (1, ?1)",
                    [generation],
                )
                .expect("synthetic generation is inserted");
        }
        connection
    }

    let mut exhausted = connection_with_generation(Some(MAX_SAFE_U64 as i64));
    let transaction = exhausted
        .transaction()
        .expect("exhaustion transaction starts");
    assert_eq!(allocate_generation(&transaction), Ok(None));
    transaction
        .rollback()
        .expect("exhaustion transaction rolls back");

    for generation in [None, Some(-1)] {
        let mut invalid = connection_with_generation(generation);
        let transaction = invalid
            .transaction()
            .expect("invalid metadata transaction starts");
        let error = allocate_generation(&transaction)
            .expect_err("missing or invalid metadata must fail closed");
        assert_eq!(error, InternalStoreError::InvariantFailed);
        assert!(error.requires_unhealthy_latch());
        transaction
            .rollback()
            .expect("invalid metadata transaction rolls back");
    }
}
