use crate::connection::{map_sqlite_error, open_existing_for_claim};
use crate::error::InternalStoreError;
use crate::root_safety::{
    acquire_checked_live_root_lease, quarantine_with_held_live_lease, RootLeaseV1,
};
use crate::schema::{verify_full, verify_lightweight};
use crate::{ReplayMonotonicClockV1, SqliteReplayClaimantV1};
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use helix_plan_eligibility::{
    ReplayBindingV1, ReplayClaimOutcomeV1, ReplayClaimReceiptV1, ReplayClaimVerificationViewV1,
    ReplayClaimantV1,
};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use sha2::{Digest as _, Sha256};
#[cfg(feature = "test-fault-injection")]
use std::env;
#[cfg(feature = "test-fault-injection")]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

const ATTEMPT_ID_DOMAIN: &[u8] = b"HELIXOS\0REPLAY-CLAIM-ATTEMPT\0V1\0";
#[cfg(feature = "test-fault-injection")]
const TEST_CLAIM_SCENARIO_ENV: &str = "HELIX_REPLAY_TEST_CLAIM_SCENARIO";

trait ClaimRandomV1 {
    fn fill(random: &mut [u8; 32]) -> Result<(), ()>;
}

struct NativeClaimRandomV1;

impl ClaimRandomV1 for NativeClaimRandomV1 {
    fn fill(random: &mut [u8; 32]) -> Result<(), ()> {
        getrandom::fill(random).map_err(|_| ())
    }
}

#[cfg(feature = "test-fault-injection")]
struct UnavailableClaimRandomV1;

#[cfg(feature = "test-fault-injection")]
impl ClaimRandomV1 for UnavailableClaimRandomV1 {
    fn fill(_random: &mut [u8; 32]) -> Result<(), ()> {
        Err(())
    }
}

struct ClaimAttemptV1 {
    instance_epoch: u64,
    nonce: [u8; 16],
    operation_id: String,
    binding_digest: Sha256Digest,
    deadline_monotonic_ms: u64,
    claim_id: Sha256Digest,
}

impl ClaimAttemptV1 {
    fn from_binding<R: ClaimRandomV1>(binding: &ReplayBindingV1<'_>) -> Option<Self> {
        if binding.instance_epoch() > MAX_SAFE_U64
            || binding.claim_deadline_monotonic_ms() > MAX_SAFE_U64
        {
            return None;
        }

        let mut random = [0_u8; 32];
        R::fill(&mut random).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(ATTEMPT_ID_DOMAIN);
        hasher.update(random);
        let claim_id = Sha256Digest::from_bytes(hasher.finalize().into());

        Some(Self {
            instance_epoch: binding.instance_epoch(),
            nonce: *binding.nonce().as_bytes(),
            operation_id: binding.operation_id().to_owned(),
            binding_digest: binding.binding_digest(),
            deadline_monotonic_ms: binding.claim_deadline_monotonic_ms(),
            claim_id,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct StoredClaimV1 {
    instance_epoch: u64,
    nonce: [u8; 16],
    operation_id: String,
    binding_digest: Sha256Digest,
    claim_id: Sha256Digest,
    claimant_generation: u64,
}

impl StoredClaimV1 {
    fn matches_binding(&self, attempt: &ClaimAttemptV1) -> bool {
        self.instance_epoch == attempt.instance_epoch
            && self.nonce == attempt.nonce
            && self.operation_id == attempt.operation_id
            && self.binding_digest == attempt.binding_digest
    }

    fn matches_attempt(&self, attempt: &ClaimAttemptV1, receipt: &ReplayClaimReceiptV1) -> bool {
        self.matches_binding(attempt)
            && self.claim_id == attempt.claim_id
            && self.claim_id == receipt.claim_id()
            && self.claimant_generation == receipt.claimant_generation()
            && self.binding_digest == receipt.binding_digest()
    }

    pub(crate) fn matches_verification_view(
        &self,
        view: &ReplayClaimVerificationViewV1<'_>,
    ) -> bool {
        self.instance_epoch == view.instance_epoch()
            && self.nonce == *view.nonce().as_bytes()
            && self.operation_id == view.operation_id()
            && self.binding_digest == view.binding_digest()
            && self.claim_id == view.claim_id()
            && self.claimant_generation == view.claimant_generation()
    }
}

enum ClaimExecutionV1 {
    Final(ReplayClaimOutcomeV1),
    CommitUncertain(ReplayClaimReceiptV1),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadbackDecisionV1 {
    ThisAttempt,
    PriorExact,
    Conflict,
    Absent,
    Ambiguous,
}

trait ClaimIoV1<C: ReplayMonotonicClockV1> {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()>;

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<C>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError>;

    fn maximum_generation() -> u64 {
        MAX_SAFE_U64
    }

    #[cfg(test)]
    fn after_readback_lease_acquired(
        _claimant: &SqliteReplayClaimantV1<C>,
        _attempt: &ClaimAttemptV1,
    ) {
    }
}

struct NativeClaimIoV1;

impl<C: ReplayMonotonicClockV1> ClaimIoV1<C> for NativeClaimIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        transaction.commit()
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<C>,
        attempt: &ClaimAttemptV1,
        _receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        open_existing_for_claim(
            &claimant.config,
            &claimant.clock,
            attempt.deadline_monotonic_ms,
        )
    }
}

#[cfg(feature = "test-fault-injection")]
#[derive(Clone, Copy)]
enum TestClaimScenarioV1 {
    CommitReadbackAbsence,
    CommitReadbackConflict,
    CommitReadbackExact,
    CommitReadbackFailed,
    CommitReadbackPrior,
    DeadlineReadbackLate,
    GenerationExhausted,
    RngUnavailable,
}

#[cfg(feature = "test-fault-injection")]
impl TestClaimScenarioV1 {
    fn from_environment_for_root(root: &Path) -> Option<Self> {
        let requested = env::var(TEST_CLAIM_SCENARIO_ENV).ok()?;
        let (scenario, requested_root) = requested.split_once('\n')?;
        if requested_root != root.to_string_lossy() {
            return None;
        }
        match scenario {
            "commit-readback-absence" => Some(Self::CommitReadbackAbsence),
            "commit-readback-conflict" => Some(Self::CommitReadbackConflict),
            "commit-readback-exact" => Some(Self::CommitReadbackExact),
            "commit-readback-failed" => Some(Self::CommitReadbackFailed),
            "commit-readback-prior" => Some(Self::CommitReadbackPrior),
            "deadline-readback-late" => Some(Self::DeadlineReadbackLate),
            "generation-exhausted" => Some(Self::GenerationExhausted),
            "rng-unavailable" => Some(Self::RngUnavailable),
            _ => None,
        }
    }
}

#[cfg(feature = "test-fault-injection")]
fn synthetic_commit_error() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR), None)
}

#[cfg(feature = "test-fault-injection")]
fn commit_then_report_error(transaction: Transaction<'_>) -> rusqlite::Result<()> {
    transaction.commit()?;
    Err(synthetic_commit_error())
}

#[cfg(feature = "test-fault-injection")]
fn rollback_then_report_error(transaction: Transaction<'_>) -> rusqlite::Result<()> {
    transaction.rollback()?;
    Err(synthetic_commit_error())
}

#[cfg(feature = "test-fault-injection")]
fn native_test_readback<C: ReplayMonotonicClockV1>(
    claimant: &SqliteReplayClaimantV1<C>,
    attempt: &ClaimAttemptV1,
    receipt: &ReplayClaimReceiptV1,
) -> Result<Connection, InternalStoreError> {
    <NativeClaimIoV1 as ClaimIoV1<C>>::open_readback(claimant, attempt, receipt)
}

#[cfg(feature = "test-fault-injection")]
fn install_test_readback_row<C: ReplayMonotonicClockV1>(
    claimant: &SqliteReplayClaimantV1<C>,
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

#[cfg(feature = "test-fault-injection")]
fn test_readback_row(attempt: &ClaimAttemptV1, receipt: &ReplayClaimReceiptV1) -> StoredClaimV1 {
    StoredClaimV1 {
        instance_epoch: attempt.instance_epoch,
        nonce: attempt.nonce,
        operation_id: attempt.operation_id.clone(),
        binding_digest: attempt.binding_digest,
        claim_id: attempt.claim_id,
        claimant_generation: receipt.claimant_generation(),
    }
}

#[cfg(feature = "test-fault-injection")]
struct CommitReadbackExactIoV1;

#[cfg(feature = "test-fault-injection")]
impl<C: ReplayMonotonicClockV1> ClaimIoV1<C> for CommitReadbackExactIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        commit_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<C>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        native_test_readback(claimant, attempt, receipt)
    }
}

#[cfg(feature = "test-fault-injection")]
struct CommitReadbackAbsenceIoV1;

#[cfg(feature = "test-fault-injection")]
impl<C: ReplayMonotonicClockV1> ClaimIoV1<C> for CommitReadbackAbsenceIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<C>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        native_test_readback(claimant, attempt, receipt)
    }
}

#[cfg(feature = "test-fault-injection")]
struct CommitReadbackFailedIoV1;

#[cfg(feature = "test-fault-injection")]
impl<C: ReplayMonotonicClockV1> ClaimIoV1<C> for CommitReadbackFailedIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        _claimant: &SqliteReplayClaimantV1<C>,
        _attempt: &ClaimAttemptV1,
        _receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        Err(InternalStoreError::StoreUnavailable)
    }
}

#[cfg(feature = "test-fault-injection")]
struct CommitReadbackPriorIoV1;

#[cfg(feature = "test-fault-injection")]
impl<C: ReplayMonotonicClockV1> ClaimIoV1<C> for CommitReadbackPriorIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<C>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        let mut row = test_readback_row(attempt, receipt);
        row.claim_id = Sha256Digest::digest(b"test-fault prior exact claim");
        install_test_readback_row(claimant, &row)?;
        native_test_readback(claimant, attempt, receipt)
    }
}

#[cfg(feature = "test-fault-injection")]
struct CommitReadbackConflictIoV1;

#[cfg(feature = "test-fault-injection")]
impl<C: ReplayMonotonicClockV1> ClaimIoV1<C> for CommitReadbackConflictIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        rollback_then_report_error(transaction)
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<C>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        let mut row = test_readback_row(attempt, receipt);
        row.operation_id = "operation:test-fault-conflict".to_owned();
        row.binding_digest = Sha256Digest::digest(b"test-fault conflicting binding");
        row.claim_id = Sha256Digest::digest(b"test-fault conflicting claim");
        install_test_readback_row(claimant, &row)?;
        native_test_readback(claimant, attempt, receipt)
    }
}

#[cfg(feature = "test-fault-injection")]
struct GenerationExhaustedIoV1;

#[cfg(feature = "test-fault-injection")]
impl<C: ReplayMonotonicClockV1> ClaimIoV1<C> for GenerationExhaustedIoV1 {
    fn commit(transaction: Transaction<'_>) -> rusqlite::Result<()> {
        transaction.commit()
    }

    fn open_readback(
        claimant: &SqliteReplayClaimantV1<C>,
        attempt: &ClaimAttemptV1,
        receipt: &ReplayClaimReceiptV1,
    ) -> Result<Connection, InternalStoreError> {
        native_test_readback(claimant, attempt, receipt)
    }

    fn maximum_generation() -> u64 {
        0
    }
}

impl<C: ReplayMonotonicClockV1> ReplayClaimantV1 for SqliteReplayClaimantV1<C> {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1 {
        #[cfg(feature = "test-fault-injection")]
        if let Some(scenario) =
            TestClaimScenarioV1::from_environment_for_root(self.config.root().path())
        {
            return match scenario {
                TestClaimScenarioV1::CommitReadbackAbsence => {
                    self.claim_once_with_io::<CommitReadbackAbsenceIoV1>(binding)
                }
                TestClaimScenarioV1::CommitReadbackConflict => {
                    self.claim_once_with_io::<CommitReadbackConflictIoV1>(binding)
                }
                TestClaimScenarioV1::CommitReadbackExact
                | TestClaimScenarioV1::DeadlineReadbackLate => {
                    self.claim_once_with_io::<CommitReadbackExactIoV1>(binding)
                }
                TestClaimScenarioV1::CommitReadbackFailed => {
                    self.claim_once_with_io::<CommitReadbackFailedIoV1>(binding)
                }
                TestClaimScenarioV1::CommitReadbackPrior => {
                    self.claim_once_with_io::<CommitReadbackPriorIoV1>(binding)
                }
                TestClaimScenarioV1::GenerationExhausted => {
                    self.claim_once_with_io::<GenerationExhaustedIoV1>(binding)
                }
                TestClaimScenarioV1::RngUnavailable => self
                    .claim_once_with_io_and_random::<NativeClaimIoV1, UnavailableClaimRandomV1>(
                        binding,
                    ),
            };
        }
        self.claim_once_with_io::<NativeClaimIoV1>(binding)
    }
}

impl<C: ReplayMonotonicClockV1> SqliteReplayClaimantV1<C> {
    fn claim_once_with_io<I: ClaimIoV1<C>>(
        &self,
        binding: &ReplayBindingV1<'_>,
    ) -> ReplayClaimOutcomeV1 {
        self.claim_once_with_io_and_random::<I, NativeClaimRandomV1>(binding)
    }

    fn claim_once_with_io_and_random<I: ClaimIoV1<C>, R: ClaimRandomV1>(
        &self,
        binding: &ReplayBindingV1<'_>,
    ) -> ReplayClaimOutcomeV1 {
        if !self.healthy.load(Ordering::Acquire) {
            return ReplayClaimOutcomeV1::Unavailable;
        }

        if self
            .remaining_ms(binding.claim_deadline_monotonic_ms())
            .is_none()
        {
            return ReplayClaimOutcomeV1::Unavailable;
        }
        let Some(attempt) = ClaimAttemptV1::from_binding::<R>(binding) else {
            return ReplayClaimOutcomeV1::Unavailable;
        };
        self.claim_attempt_with_io::<I>(&attempt)
    }

    fn claim_attempt_with_io<I: ClaimIoV1<C>>(
        &self,
        attempt: &ClaimAttemptV1,
    ) -> ReplayClaimOutcomeV1 {
        if !self.healthy.load(Ordering::Acquire) {
            return ReplayClaimOutcomeV1::Unavailable;
        }
        if self.remaining_ms(attempt.deadline_monotonic_ms).is_none() {
            return ReplayClaimOutcomeV1::Unavailable;
        }

        let execution = {
            let Ok(mut connection) =
                open_existing_for_claim(&self.config, &self.clock, attempt.deadline_monotonic_ms)
            else {
                return ReplayClaimOutcomeV1::Unavailable;
            };
            if let Err(error) = verify_lightweight(&connection, self.schema_cookie) {
                self.observe_claim_error(error);
                return ReplayClaimOutcomeV1::Unavailable;
            }
            self.execute_claim::<I>(&mut connection, attempt)
        };

        match execution {
            ClaimExecutionV1::Final(outcome) => outcome,
            ClaimExecutionV1::CommitUncertain(receipt) => {
                self.readback_after_commit_error::<I>(attempt, receipt)
            }
        }
    }

    fn now_ms(&self) -> Option<u64> {
        self.clock
            .now_monotonic_ms()
            .ok()
            .filter(|value| *value <= MAX_SAFE_U64)
    }

    fn remaining_ms(&self, deadline_monotonic_ms: u64) -> Option<u64> {
        let now = self.now_ms()?;
        (now < deadline_monotonic_ms).then_some(deadline_monotonic_ms - now)
    }

    fn execute_claim<I: ClaimIoV1<C>>(
        &self,
        connection: &mut Connection,
        attempt: &ClaimAttemptV1,
    ) -> ClaimExecutionV1 {
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(_) => {
                return ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Unavailable);
            }
        };
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::BeginAcquired);

        if self.remaining_ms(attempt.deadline_monotonic_ms).is_none() {
            return rollback_before_mutation(transaction);
        }
        let mut root_lease = match acquire_checked_live_root_lease(
            self.config.root(),
            self.config.maximum_busy_wait_ms(),
            &self.clock,
            attempt.deadline_monotonic_ms,
        ) {
            Ok(lease) => lease,
            Err(_) => return rollback_before_mutation(transaction),
        };
        if self.remaining_ms(attempt.deadline_monotonic_ms).is_none() {
            return rollback_before_mutation(transaction);
        }
        if let Err(error) = verify_lightweight(&transaction, self.schema_cookie) {
            self.observe_claim_error_under_writer(error, &mut root_lease);
            return rollback_before_mutation(transaction);
        }

        let nonce_claim = match lookup_by_nonce(&transaction, attempt) {
            Ok(claim) => claim,
            Err(error) => {
                self.observe_claim_error_under_writer(error, &mut root_lease);
                let _ = transaction.rollback();
                return ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Unavailable);
            }
        };
        let operation_claim = match lookup_by_operation(&transaction, attempt) {
            Ok(claim) => claim,
            Err(error) => {
                self.observe_claim_error_under_writer(error, &mut root_lease);
                let _ = transaction.rollback();
                return ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Unavailable);
            }
        };

        match (&nonce_claim, &operation_claim) {
            (None, None) => {}
            (Some(nonce), Some(operation))
                if nonce == operation && nonce.matches_binding(attempt) =>
            {
                let _ = transaction.rollback();
                return ClaimExecutionV1::Final(ReplayClaimOutcomeV1::AlreadyClaimed);
            }
            _ => {
                let _ = transaction.rollback();
                return ClaimExecutionV1::Final(ReplayClaimOutcomeV1::BindingConflict);
            }
        }

        if self.remaining_ms(attempt.deadline_monotonic_ms).is_none() {
            return rollback_before_mutation(transaction);
        }

        let generation =
            match allocate_generation_with_maximum(&transaction, I::maximum_generation()) {
                Ok(Some(generation)) => generation,
                Ok(None) => {
                    return rollback_after_mutation(transaction);
                }
                Err(error) => {
                    self.observe_claim_error_under_writer(error, &mut root_lease);
                    return rollback_after_mutation(transaction);
                }
            };
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::GenerationUpdated);
        let receipt = match ReplayClaimReceiptV1::try_new(
            attempt.claim_id,
            generation,
            attempt.binding_digest,
        ) {
            Ok(receipt) => receipt,
            Err(_) => return rollback_after_mutation(transaction),
        };

        if let Err(error) = insert_claim(&transaction, attempt, generation) {
            self.observe_claim_error_under_writer(error, &mut root_lease);
            return rollback_after_mutation(transaction);
        }
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::RowInserted);
        if self.remaining_ms(attempt.deadline_monotonic_ms).is_none() {
            return rollback_after_mutation(transaction);
        }

        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::BeforeCommit);
        let commit_result = I::commit(transaction);
        #[cfg(feature = "test-fault-injection")]
        crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::CommitReturned);
        match commit_result {
            Ok(()) if self.remaining_ms(attempt.deadline_monotonic_ms).is_some() => {
                #[cfg(feature = "test-fault-injection")]
                crate::test_fault::reach(crate::test_fault::ReplayFaultPointV1::BeforeResultAck);
                ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Claimed(receipt))
            }
            Ok(()) => ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Ambiguous),
            Err(_) => ClaimExecutionV1::CommitUncertain(receipt),
        }
    }

    fn readback_after_commit_error<I: ClaimIoV1<C>>(
        &self,
        attempt: &ClaimAttemptV1,
        receipt: ReplayClaimReceiptV1,
    ) -> ReplayClaimOutcomeV1 {
        if self.remaining_ms(attempt.deadline_monotonic_ms).is_none() {
            return ReplayClaimOutcomeV1::Ambiguous;
        }
        let Ok(mut connection) = I::open_readback(self, attempt, &receipt) else {
            return ReplayClaimOutcomeV1::Ambiguous;
        };
        let mut root_lease = match acquire_checked_live_root_lease(
            self.config.root(),
            self.config.maximum_busy_wait_ms(),
            &self.clock,
            attempt.deadline_monotonic_ms,
        ) {
            Ok(root_lease) => root_lease,
            Err(_) => return ReplayClaimOutcomeV1::Ambiguous,
        };
        #[cfg(test)]
        I::after_readback_lease_acquired(self, attempt);
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Deferred)
        {
            Ok(transaction) => transaction,
            Err(_) => return ReplayClaimOutcomeV1::Ambiguous,
        };
        if let Err(error) = verify_lightweight(&transaction, self.schema_cookie) {
            self.observe_readback_error(error, &mut root_lease);
            let _ = transaction.rollback();
            return ReplayClaimOutcomeV1::Ambiguous;
        }

        let nonce_claim = match lookup_by_nonce_connection(
            &transaction,
            attempt.instance_epoch,
            &attempt.nonce,
        ) {
            Ok(claim) => claim,
            Err(error) => {
                self.observe_readback_error(error, &mut root_lease);
                let _ = transaction.rollback();
                return ReplayClaimOutcomeV1::Ambiguous;
            }
        };
        let operation_claim =
            match lookup_by_operation_connection(&transaction, &attempt.operation_id) {
                Ok(claim) => claim,
                Err(error) => {
                    self.observe_readback_error(error, &mut root_lease);
                    let _ = transaction.rollback();
                    return ReplayClaimOutcomeV1::Ambiguous;
                }
            };
        let candidate_claim = match lookup_by_claim_id_connection(&transaction, attempt.claim_id) {
            Ok(claim) => claim,
            Err(error) => {
                self.observe_readback_error(error, &mut root_lease);
                let _ = transaction.rollback();
                return ReplayClaimOutcomeV1::Ambiguous;
            }
        };

        let preliminary = classify_readback(
            nonce_claim.as_ref(),
            operation_claim.as_ref(),
            candidate_claim.as_ref(),
            attempt,
            &receipt,
            true,
        );
        if let Err(error) = verify_definitive_readback(&transaction, preliminary) {
            self.observe_readback_error(error, &mut root_lease);
            let _ = transaction.rollback();
            return ReplayClaimOutcomeV1::Ambiguous;
        }

        let decision = classify_readback(
            nonce_claim.as_ref(),
            operation_claim.as_ref(),
            candidate_claim.as_ref(),
            attempt,
            &receipt,
            self.remaining_ms(attempt.deadline_monotonic_ms).is_some(),
        );
        if transaction.rollback().is_err() {
            return ReplayClaimOutcomeV1::Ambiguous;
        }

        match decision {
            ReadbackDecisionV1::ThisAttempt => ReplayClaimOutcomeV1::Claimed(receipt),
            ReadbackDecisionV1::PriorExact => ReplayClaimOutcomeV1::AlreadyClaimed,
            ReadbackDecisionV1::Conflict => ReplayClaimOutcomeV1::BindingConflict,
            ReadbackDecisionV1::Absent => ReplayClaimOutcomeV1::Unavailable,
            ReadbackDecisionV1::Ambiguous => ReplayClaimOutcomeV1::Ambiguous,
        }
    }

    fn observe_claim_error(&self, error: InternalStoreError) {
        latch_unhealthy_for_claim_error(&self.healthy, error);
    }

    fn observe_claim_error_under_writer(
        &self,
        error: InternalStoreError,
        root_lease: &mut RootLeaseV1,
    ) {
        if error.requires_durable_quarantine() {
            let _ = quarantine_with_held_live_lease(root_lease, self.config.root());
        }
        self.observe_claim_error(error);
    }

    fn observe_readback_error(&self, error: InternalStoreError, root_lease: &mut RootLeaseV1) {
        self.observe_claim_error_under_writer(error, root_lease);
    }
}

fn latch_unhealthy_for_claim_error(healthy: &AtomicBool, error: InternalStoreError) {
    if error.requires_unhealthy_latch() {
        healthy.store(false, Ordering::Release);
    }
}

fn classify_readback(
    nonce_claim: Option<&StoredClaimV1>,
    operation_claim: Option<&StoredClaimV1>,
    candidate_claim: Option<&StoredClaimV1>,
    attempt: &ClaimAttemptV1,
    receipt: &ReplayClaimReceiptV1,
    timely: bool,
) -> ReadbackDecisionV1 {
    if !timely {
        return ReadbackDecisionV1::Ambiguous;
    }

    match (nonce_claim, operation_claim) {
        (None, None) => {
            if candidate_claim.is_none() {
                ReadbackDecisionV1::Absent
            } else {
                ReadbackDecisionV1::Ambiguous
            }
        }
        (Some(nonce), Some(operation)) if nonce == operation => {
            if nonce.matches_attempt(attempt, receipt) {
                if candidate_claim == Some(nonce) {
                    ReadbackDecisionV1::ThisAttempt
                } else {
                    ReadbackDecisionV1::Ambiguous
                }
            } else if nonce.matches_binding(attempt) {
                if nonce.claim_id != attempt.claim_id && candidate_claim.is_none() {
                    ReadbackDecisionV1::PriorExact
                } else {
                    ReadbackDecisionV1::Ambiguous
                }
            } else if candidate_claim.is_none() {
                ReadbackDecisionV1::Conflict
            } else {
                ReadbackDecisionV1::Ambiguous
            }
        }
        _ if candidate_claim.is_none() => ReadbackDecisionV1::Conflict,
        _ => ReadbackDecisionV1::Ambiguous,
    }
}

fn verify_definitive_readback(
    transaction: &Transaction<'_>,
    decision: ReadbackDecisionV1,
) -> Result<(), InternalStoreError> {
    if decision != ReadbackDecisionV1::Ambiguous {
        verify_full(transaction)?;
    }
    Ok(())
}

fn rollback_after_mutation(transaction: Transaction<'_>) -> ClaimExecutionV1 {
    match transaction.rollback() {
        Ok(()) => ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Unavailable),
        Err(_) => ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Ambiguous),
    }
}

fn rollback_before_mutation(transaction: Transaction<'_>) -> ClaimExecutionV1 {
    match transaction.rollback() {
        Ok(()) => ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Unavailable),
        Err(_) => ClaimExecutionV1::Final(ReplayClaimOutcomeV1::Ambiguous),
    }
}

#[cfg(test)]
fn allocate_generation(transaction: &Transaction<'_>) -> Result<Option<u64>, InternalStoreError> {
    allocate_generation_with_maximum(transaction, MAX_SAFE_U64)
}

fn allocate_generation_with_maximum(
    transaction: &Transaction<'_>,
    maximum_generation: u64,
) -> Result<Option<u64>, InternalStoreError> {
    let result = transaction.query_row(
        "UPDATE replay_store_meta
         SET claimant_generation = claimant_generation + 1
         WHERE singleton = 1 AND claimant_generation < ?1
         RETURNING claimant_generation",
        [maximum_generation as i64],
        |row| row.get::<_, i64>(0),
    );
    match result {
        Ok(value) => decode_allocated_generation(value).map(Some),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            verify_exhausted_generation(transaction, maximum_generation)?;
            Ok(None)
        }
        Err(error) => Err(map_claim_query_error(&error)),
    }
}

fn decode_allocated_generation(value: i64) -> Result<u64, InternalStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| (1..=MAX_SAFE_U64).contains(value))
        .ok_or(InternalStoreError::InvariantFailed)
}

fn verify_exhausted_generation(
    transaction: &Transaction<'_>,
    maximum_generation: u64,
) -> Result<(), InternalStoreError> {
    let generation = transaction
        .query_row(
            "SELECT claimant_generation
             FROM replay_store_meta
             WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| map_claim_query_error(&error))?
        .ok_or(InternalStoreError::InvariantFailed)?;
    let generation = u64::try_from(generation)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(InternalStoreError::InvariantFailed)?;
    if generation != maximum_generation {
        return Err(InternalStoreError::InvariantFailed);
    }
    Ok(())
}

fn insert_claim(
    transaction: &Transaction<'_>,
    attempt: &ClaimAttemptV1,
    generation: u64,
) -> Result<(), InternalStoreError> {
    let inserted = transaction
        .execute(
            "INSERT INTO replay_claims (
                instance_epoch,
                nonce,
                operation_id,
                binding_digest,
                claim_id,
                claimant_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                attempt.instance_epoch as i64,
                attempt.nonce.as_slice(),
                attempt.operation_id.as_str(),
                attempt.binding_digest.as_bytes().as_slice(),
                attempt.claim_id.as_bytes().as_slice(),
                generation as i64,
            ],
        )
        .map_err(|error| map_sqlite_error(&error, InternalStoreError::StoreUnavailable))?;
    (inserted == 1)
        .then_some(())
        .ok_or(InternalStoreError::InvariantFailed)
}

fn lookup_by_nonce(
    transaction: &Transaction<'_>,
    attempt: &ClaimAttemptV1,
) -> Result<Option<StoredClaimV1>, InternalStoreError> {
    lookup_by_nonce_connection(transaction, attempt.instance_epoch, &attempt.nonce)
}

fn lookup_by_operation(
    transaction: &Transaction<'_>,
    attempt: &ClaimAttemptV1,
) -> Result<Option<StoredClaimV1>, InternalStoreError> {
    lookup_by_operation_connection(transaction, &attempt.operation_id)
}

pub(crate) fn lookup_by_nonce_connection(
    connection: &Connection,
    instance_epoch: u64,
    nonce: &[u8; 16],
) -> Result<Option<StoredClaimV1>, InternalStoreError> {
    let raw = connection
        .query_row(
            "SELECT instance_epoch, nonce, operation_id, binding_digest, claim_id,
                    claimant_generation
             FROM replay_claims
             WHERE instance_epoch = ?1 AND nonce = ?2",
            params![instance_epoch as i64, nonce.as_slice()],
            read_raw_claim,
        )
        .optional()
        .map_err(|error| map_claim_query_error(&error))?;
    raw.map(decode_raw_claim).transpose()
}

pub(crate) fn lookup_by_operation_connection(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<StoredClaimV1>, InternalStoreError> {
    let raw = connection
        .query_row(
            "SELECT instance_epoch, nonce, operation_id, binding_digest, claim_id,
                    claimant_generation
             FROM replay_claims
             WHERE operation_id = ?1",
            [operation_id],
            read_raw_claim,
        )
        .optional()
        .map_err(|error| map_claim_query_error(&error))?;
    raw.map(decode_raw_claim).transpose()
}

pub(crate) fn lookup_by_claim_id_connection(
    connection: &Connection,
    claim_id: Sha256Digest,
) -> Result<Option<StoredClaimV1>, InternalStoreError> {
    let raw = connection
        .query_row(
            "SELECT instance_epoch, nonce, operation_id, binding_digest, claim_id,
                    claimant_generation
             FROM replay_claims
             WHERE claim_id = ?1",
            [claim_id.as_bytes().as_slice()],
            read_raw_claim,
        )
        .optional()
        .map_err(|error| map_claim_query_error(&error))?;
    raw.map(decode_raw_claim).transpose()
}

type RawClaimV1 = (i64, Vec<u8>, String, Vec<u8>, Vec<u8>, i64);

fn read_raw_claim(row: &Row<'_>) -> rusqlite::Result<RawClaimV1> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn decode_raw_claim(raw: RawClaimV1) -> Result<StoredClaimV1, InternalStoreError> {
    let instance_epoch = u64::try_from(raw.0).map_err(|_| InternalStoreError::InvariantFailed)?;
    let nonce: [u8; 16] = raw
        .1
        .try_into()
        .map_err(|_| InternalStoreError::InvariantFailed)?;
    if raw.2.is_empty()
        || raw.2.len() > 128
        || !raw
            .2
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(InternalStoreError::InvariantFailed);
    }
    let binding_digest: [u8; 32] = raw
        .3
        .try_into()
        .map_err(|_| InternalStoreError::InvariantFailed)?;
    let claim_id: [u8; 32] = raw
        .4
        .try_into()
        .map_err(|_| InternalStoreError::InvariantFailed)?;
    let claimant_generation =
        u64::try_from(raw.5).map_err(|_| InternalStoreError::InvariantFailed)?;
    if instance_epoch > MAX_SAFE_U64 || !(1..=MAX_SAFE_U64).contains(&claimant_generation) {
        return Err(InternalStoreError::InvariantFailed);
    }
    Ok(StoredClaimV1 {
        instance_epoch,
        nonce,
        operation_id: raw.2,
        binding_digest: Sha256Digest::from_bytes(binding_digest),
        claim_id: Sha256Digest::from_bytes(claim_id),
        claimant_generation,
    })
}

fn map_claim_query_error(error: &rusqlite::Error) -> InternalStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::Utf8Error(..)
        | rusqlite::Error::InvalidColumnType(..) => InternalStoreError::InvariantFailed,
        _ => map_sqlite_error(error, InternalStoreError::StoreUnavailable),
    }
}

#[cfg(test)]
mod tests;
