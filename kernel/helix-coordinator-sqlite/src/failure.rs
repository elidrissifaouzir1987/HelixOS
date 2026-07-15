//! Private known pre-dispatch failure transaction boundary.
//!
//! A terminal failure is one append-only SQLite transaction. The live no-dispatch
//! guard is sampled before writer admission and again immediately before COMMIT; it is
//! never serialized into the coordinator store.

use crate::budget::{checked_budget_release_v1, BudgetVectorCheckErrorV1};
use crate::outbox::{stage_failed_event_v1, FailedEventRowV1};
#[cfg(not(test))]
use crate::schema::{self, RestorePendingBindingsV1};
use crate::transition::{stage_failed_transition_v1, FailedTransitionRowV1};
#[cfg(not(test))]
use helix_contracts::Ed25519KeyResolver;
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use helix_coordinator_sqlite::CoordinatorFaultProbeV1;
#[cfg(test)]
use helix_plan_preparation::NoDispatchAuthorityBindingV1;
use helix_plan_preparation::{
    NoDispatchAuthorityGuardV1, NoDispatchAuthorityValidationV1, PreparationFailureInputV1,
    PreparationFailureOutcomeV1, PREPARATION_STORE_CONTRACT_VERSION_V1,
};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::{Digest as _, Sha256};

const FAILED_EVENT_ID_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-FAILED-EVENT-ID\0V1\0";

macro_rules! reach {
    ($probe:expr, $boundary:ident) => {
        #[cfg(feature = "test-fault-injection")]
        $probe.reach_id_v1(crate::test_fault::FaultBoundaryV1::$boundary.id())
    };
}

/// Opaque proof copied from live sovereign PAUSE custody.
///
/// Production construction exists only on `PausedRotatedRestoreAuthorityV1`; failure
/// and quarantine can validate an old binding but cannot select replacement epochs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestoredAuthorityRotationV1 {
    pub(super) source_boot_identity_sha256: Sha256Digest,
    pub(super) rotated_boot_identity_sha256: Sha256Digest,
    pub(super) source_instance_epoch: u64,
    pub(super) rotated_instance_epoch: u64,
    pub(super) source_fencing_epoch: u64,
    pub(super) rotated_fencing_epoch: u64,
}

impl RestoredAuthorityRotationV1 {
    pub(crate) fn binds_old_authority_v1(
        self,
        old_boot_id: &str,
        old_instance_epoch: u64,
        old_fencing_epoch: u64,
    ) -> bool {
        Sha256Digest::digest(old_boot_id.as_bytes()) == self.source_boot_identity_sha256
            && old_instance_epoch == self.source_instance_epoch
            && old_fencing_epoch == self.source_fencing_epoch
            && self.rotated_boot_identity_sha256 != self.source_boot_identity_sha256
            && self.rotated_instance_epoch != self.source_instance_epoch
            && self.rotated_fencing_epoch != self.source_fencing_epoch
    }

    #[cfg(test)]
    #[allow(dead_code)] // Some source-included harnesses do not include quarantine tests.
    pub(crate) fn for_test_v1(
        old_boot_id: &str,
        old_instance_epoch: u64,
        old_fencing_epoch: u64,
    ) -> Self {
        Self {
            source_boot_identity_sha256: Sha256Digest::digest(old_boot_id.as_bytes()),
            rotated_boot_identity_sha256: Sha256Digest::digest(b"test-rotated-boot"),
            source_instance_epoch: old_instance_epoch,
            rotated_instance_epoch: old_instance_epoch.saturating_add(1),
            source_fencing_epoch: old_fencing_epoch,
            rotated_fencing_epoch: old_fencing_epoch.saturating_add(1),
        }
    }
}

impl std::fmt::Debug for RestoredAuthorityRotationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoredAuthorityRotationV1")
            .finish_non_exhaustive()
    }
}

struct FailureBindingV1<'binding> {
    operation_id: &'binding str,
    attempt_id: [u8; 32],
    preparing_state_generation: u64,
    boot_id: &'binding str,
    instance_epoch: u64,
    fencing_epoch: u64,
}

/// Exact historical operation authority loaded only from a fully verified
/// `RESTORE_PENDING` coordinator root.
///
/// Unlike the live preparation binding, this type can be reconstructed after a clean
/// restore without creating a selectable `PreparationAttemptIdV1`. Its diagnostic
/// surface is redacted and it carries no dispatch or activation permission.
#[allow(dead_code)] // Production-only T075 orchestration; unit tests exercise the inner transaction.
pub(crate) struct RestoredOldAuthorityBindingV1<'binding> {
    operation_id: &'binding str,
    attempt_id: Sha256Digest,
    preparing_state_generation: u64,
    boot_id: &'binding str,
    instance_epoch: u64,
    fencing_epoch: u64,
    deadline_monotonic_ms: u64,
}

#[allow(dead_code)]
impl<'binding> RestoredOldAuthorityBindingV1<'binding> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        operation_id: &'binding str,
        attempt_id: Sha256Digest,
        preparing_state_generation: u64,
        boot_id: &'binding str,
        instance_epoch: u64,
        fencing_epoch: u64,
        deadline_monotonic_ms: u64,
    ) -> Option<Self> {
        let valid_identifier = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':')
                })
        };
        if !valid_identifier(operation_id)
            || !valid_identifier(boot_id)
            || preparing_state_generation == 0
            || preparing_state_generation > MAX_SAFE_U64
            || instance_epoch == 0
            || instance_epoch > MAX_SAFE_U64
            || fencing_epoch == 0
            || fencing_epoch > MAX_SAFE_U64
            || deadline_monotonic_ms > MAX_SAFE_U64
        {
            return None;
        }
        Some(Self {
            operation_id,
            attempt_id,
            preparing_state_generation,
            boot_id,
            instance_epoch,
            fencing_epoch,
            deadline_monotonic_ms,
        })
    }

    pub(crate) const fn operation_id(&self) -> &str {
        self.operation_id
    }

    pub(crate) const fn attempt_id(&self) -> Sha256Digest {
        self.attempt_id
    }

    pub(crate) const fn preparing_state_generation(&self) -> u64 {
        self.preparing_state_generation
    }

    pub(crate) const fn boot_id(&self) -> &str {
        self.boot_id
    }

    pub(crate) const fn instance_epoch(&self) -> u64 {
        self.instance_epoch
    }

    pub(crate) const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }

    pub(crate) const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms
    }
}

impl std::fmt::Debug for RestoredOldAuthorityBindingV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoredOldAuthorityBindingV1")
            .finish_non_exhaustive()
    }
}

/// Live sovereign proof that one historical operation has no dispatch authority.
#[allow(dead_code)] // Production-only T075 authority boundary.
pub(crate) trait RestoredNoDispatchAuthorityGuardV1: Send {
    fn validate_restored_v1(
        &mut self,
        expected: &RestoredOldAuthorityBindingV1<'_>,
        now_monotonic_ms: u64,
    ) -> NoDispatchAuthorityValidationV1;

    fn release(self);
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // Wired by the bounded restore-maintenance API in T075.
struct RestorePendingFailureCasV1 {
    restore_identity_digest: Sha256Digest,
    restore_attestation_digest: Sha256Digest,
    restore_state_generation: u64,
    restored_source_generation: u64,
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // RestorePending is consumed by the T073/T075 maintenance seam.
enum FailureRootModeV1<'mode> {
    Active,
    RestorePending(&'mode RestorePendingFailureCasV1),
}

/// Exact old/new authority and pending-root bindings for the maintenance-only failure
/// transition. The old operation authority remains immutable; the rotated values are
/// proof inputs and are never written into the restored record.
#[allow(dead_code)] // Wired by the bounded restore-maintenance API in T075.
pub(crate) struct RestoredOldAuthorityFailureInputV1<'binding> {
    pub(crate) binding: &'binding RestoredOldAuthorityBindingV1<'binding>,
    pub(crate) restored_source_generation: u64,
    pub(crate) restore_identity_digest: Sha256Digest,
    pub(crate) restore_attestation_digest: Sha256Digest,
    pub(crate) restore_state_generation: u64,
    pub(crate) rotation: RestoredAuthorityRotationV1,
}

impl std::fmt::Debug for RestoredOldAuthorityFailureInputV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoredOldAuthorityFailureInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Wired by the bounded restore-maintenance API in T075.
pub(crate) enum RestoredOldAuthorityFailureOutcomeV1 {
    Failed,
    AlreadyFailed,
    GuardMismatch,
    GuardDeadlineReached,
    GuardUnavailable,
    InvalidRotation,
    Conflict,
    Unhealthy,
}

#[derive(Clone, Copy)]
struct FailureGenerationsV1 {
    store: u64,
    operation: u64,
    budget: u64,
    event: u64,
}

struct PreparingOperationV1 {
    reservation_id: String,
}

struct HeldReservationV1 {
    scope_id: Vec<u8>,
    held: [u64; 4],
    reserved: [u64; 4],
}

#[derive(Clone, Copy)]
enum FailureTransactionErrorV1 {
    Mismatch,
    ArithmeticInvalid,
    Busy,
    Unavailable,
    Unhealthy,
    Conflict,
}

/// Executes the production failure transaction while retaining the borrowed sovereign
/// guard through SQLite COMMIT.
#[allow(dead_code)] // Source-included integration fixtures call the synthetic seam instead.
pub(crate) fn fail_before_dispatch_transaction_v1<G, N, V>(
    connection: &mut Connection,
    input: &PreparationFailureInputV1<'_>,
    no_dispatch_guard: &mut G,
    now_monotonic_ms: N,
    verify_full: V,
) -> PreparationFailureOutcomeV1
where
    G: NoDispatchAuthorityGuardV1,
    N: FnMut() -> Result<u64, ()>,
    V: FnMut(&Connection) -> bool,
{
    fail_before_dispatch_transaction_with_probe_v1(
        connection,
        input,
        no_dispatch_guard,
        &CoordinatorFaultProbeV1::disabled_v1(),
        now_monotonic_ms,
        verify_full,
    )
}

/// Production failure path carrying the store-owned explicit fault probe.
#[allow(dead_code)]
pub(crate) fn fail_before_dispatch_transaction_with_probe_v1<G, N, V>(
    connection: &mut Connection,
    input: &PreparationFailureInputV1<'_>,
    no_dispatch_guard: &mut G,
    fault_probe: &CoordinatorFaultProbeV1,
    mut now_monotonic_ms: N,
    mut verify_full: V,
) -> PreparationFailureOutcomeV1
where
    G: NoDispatchAuthorityGuardV1,
    N: FnMut() -> Result<u64, ()>,
    V: FnMut(&Connection) -> bool,
{
    if input.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1 {
        return PreparationFailureOutcomeV1::Mismatch;
    }
    let expected = input.binding();
    let binding = FailureBindingV1 {
        operation_id: expected.operation_id(),
        attempt_id: *expected.attempt().as_bytes(),
        preparing_state_generation: expected.preparing_state_generation(),
        boot_id: expected.boot_id(),
        instance_epoch: expected.instance_epoch(),
        fencing_epoch: expected.fencing_epoch(),
    };
    let mut validate_guard = || {
        let now = match now_monotonic_ms() {
            Ok(now) => now,
            Err(()) => return NoDispatchAuthorityValidationV1::Unavailable,
        };
        if !expected.is_live_at(now) {
            return NoDispatchAuthorityValidationV1::DeadlineReached;
        }
        no_dispatch_guard.validate(expected, now)
    };
    fail_transaction_v1(
        connection,
        &binding,
        input.reason().code(),
        &mut validate_guard,
        &mut verify_full,
        fault_probe,
    )
}

/// Reconciles exactly one restored historical `PREPARING` row while the destination
/// root remains irreversibly `RESTORE_PENDING`.
///
/// This entry requires a real borrowed no-dispatch guard. Negative or ambiguous guard
/// acquisition never enters this function and must use the restore-pending quarantine
/// CAS in `quarantine.rs`. A guard that becomes non-live before COMMIT rolls back every
/// staged release and returns a closed refusal for that same quarantine path.
#[cfg(not(test))]
#[allow(dead_code)] // Wired by the bounded restore-maintenance API in T075.
pub(crate) fn fail_restored_old_authority_transaction_v1<G, N, R>(
    connection: &mut Connection,
    input: &RestoredOldAuthorityFailureInputV1<'_>,
    pending_bindings: RestorePendingBindingsV1,
    historical_plan_keys: &R,
    no_dispatch_guard: &mut G,
    mut now_monotonic_ms: N,
) -> RestoredOldAuthorityFailureOutcomeV1
where
    G: RestoredNoDispatchAuthorityGuardV1,
    N: FnMut() -> Result<u64, ()>,
    R: Ed25519KeyResolver,
{
    if !restored_authority_rotation_is_valid_v1(input) {
        return RestoredOldAuthorityFailureOutcomeV1::InvalidRotation;
    }
    if !pending_failure_bindings_are_exact_v1(input, pending_bindings) {
        return RestoredOldAuthorityFailureOutcomeV1::Conflict;
    }
    let expected = input.binding;
    let binding = FailureBindingV1 {
        operation_id: expected.operation_id(),
        attempt_id: *expected.attempt_id().as_bytes(),
        preparing_state_generation: expected.preparing_state_generation(),
        boot_id: expected.boot_id(),
        instance_epoch: expected.instance_epoch(),
        fencing_epoch: expected.fencing_epoch(),
    };
    let pending = RestorePendingFailureCasV1 {
        restore_identity_digest: input.restore_identity_digest,
        restore_attestation_digest: input.restore_attestation_digest,
        restore_state_generation: input.restore_state_generation,
        restored_source_generation: input.restored_source_generation,
    };
    let mut validate_guard = || {
        let now = match now_monotonic_ms() {
            Ok(now) => now,
            Err(()) => return NoDispatchAuthorityValidationV1::Unavailable,
        };
        if now >= expected.deadline_monotonic_ms() {
            return NoDispatchAuthorityValidationV1::DeadlineReached;
        }
        no_dispatch_guard.validate_restored_v1(expected, now)
    };
    // This verifier is deliberately created inside the storage module from concrete
    // authenticated restore bindings and the injected historical PLAN-001 resolver.
    // No production caller can substitute a boolean verifier. The core invokes it on
    // the live BEGIN IMMEDIATE transaction before staging and again after staging.
    let mut verify_pending = |transaction: &Connection| {
        schema::verify_restore_pending_v1(transaction, pending_bindings, historical_plan_keys)
            .is_ok()
    };
    map_restored_failure_outcome_v1(fail_transaction_in_mode_v1(
        connection,
        &binding,
        "PREPARATION_STORE_COMMIT_ABORTED",
        &mut validate_guard,
        &mut verify_pending,
        &CoordinatorFaultProbeV1::disabled_v1(),
        FailureRootModeV1::RestorePending(&pending),
    ))
}

#[cfg(not(test))]
fn pending_failure_bindings_are_exact_v1(
    input: &RestoredOldAuthorityFailureInputV1<'_>,
    pending_bindings: RestorePendingBindingsV1,
) -> bool {
    pending_bindings.restored_source_generation() == input.restored_source_generation
        && pending_bindings.restore_identity_digest() == input.restore_identity_digest
        && pending_bindings.restore_attestation_digest() == input.restore_attestation_digest
        && pending_bindings
            .expected_source_generations()
            .store()
            .checked_add(1)
            == Some(input.restore_state_generation)
}

fn fail_transaction_v1<G, V>(
    connection: &mut Connection,
    binding: &FailureBindingV1<'_>,
    reason_code: &str,
    validate_guard: &mut G,
    verify_full: &mut V,
    fault_probe: &CoordinatorFaultProbeV1,
) -> PreparationFailureOutcomeV1
where
    G: FnMut() -> NoDispatchAuthorityValidationV1,
    V: FnMut(&Connection) -> bool,
{
    fail_transaction_in_mode_v1(
        connection,
        binding,
        reason_code,
        validate_guard,
        verify_full,
        fault_probe,
        FailureRootModeV1::Active,
    )
}

fn fail_transaction_in_mode_v1<G, V>(
    connection: &mut Connection,
    binding: &FailureBindingV1<'_>,
    reason_code: &str,
    validate_guard: &mut G,
    verify_full: &mut V,
    fault_probe: &CoordinatorFaultProbeV1,
    root_mode: FailureRootModeV1<'_>,
) -> PreparationFailureOutcomeV1
where
    G: FnMut() -> NoDispatchAuthorityValidationV1,
    V: FnMut(&Connection) -> bool,
{
    let mut note_guard_acquired = || {
        #[cfg(feature = "test-fault-injection")]
        helix_plan_preparation::note_known_failure_guard_acquired_v1();
    };
    let mut note_guard_finally_revalidated = || {
        #[cfg(feature = "test-fault-injection")]
        helix_plan_preparation::note_known_failure_guard_finally_revalidated_v1();
    };
    fail_transaction_in_mode_instrumented_v1(
        connection,
        binding,
        reason_code,
        validate_guard,
        verify_full,
        fault_probe,
        root_mode,
        &mut note_guard_acquired,
        &mut note_guard_finally_revalidated,
    )
}

#[cfg(feature = "test-fault-injection")]
#[allow(dead_code)] // Called only by the source-included T074 process transaction driver.
#[allow(clippy::too_many_arguments)]
fn fail_transaction_in_mode_with_fault_probes_v1<G, V>(
    connection: &mut Connection,
    binding: &FailureBindingV1<'_>,
    reason_code: &str,
    validate_guard: &mut G,
    verify_full: &mut V,
    coordinator_fault_probe: &CoordinatorFaultProbeV1,
    portable_fault_probe: &helix_plan_preparation::FaultProbeV1,
    root_mode: FailureRootModeV1<'_>,
) -> PreparationFailureOutcomeV1
where
    G: FnMut() -> NoDispatchAuthorityValidationV1,
    V: FnMut(&Connection) -> bool,
{
    let mut note_guard_acquired = || {
        helix_plan_preparation::note_known_failure_guard_acquired_with_fault_probe_v1(
            portable_fault_probe,
        );
    };
    let mut note_guard_finally_revalidated = || {
        helix_plan_preparation::note_known_failure_guard_finally_revalidated_with_fault_probe_v1(
            portable_fault_probe,
        );
    };
    fail_transaction_in_mode_instrumented_v1(
        connection,
        binding,
        reason_code,
        validate_guard,
        verify_full,
        coordinator_fault_probe,
        root_mode,
        &mut note_guard_acquired,
        &mut note_guard_finally_revalidated,
    )
}

#[allow(clippy::too_many_arguments)]
fn fail_transaction_in_mode_instrumented_v1<G, V, A, R>(
    connection: &mut Connection,
    binding: &FailureBindingV1<'_>,
    reason_code: &str,
    validate_guard: &mut G,
    verify_full: &mut V,
    fault_probe: &CoordinatorFaultProbeV1,
    root_mode: FailureRootModeV1<'_>,
    note_guard_acquired: &mut A,
    note_guard_finally_revalidated: &mut R,
) -> PreparationFailureOutcomeV1
where
    G: FnMut() -> NoDispatchAuthorityValidationV1,
    V: FnMut(&Connection) -> bool,
    A: FnMut(),
    R: FnMut(),
{
    if let Err(outcome) = classify_guard_validation_v1(validate_guard()) {
        return outcome;
    }
    note_guard_acquired();

    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return map_transaction_error_v1(map_sqlite_error_v1(error)),
    };
    reach!(fault_probe, KnownFailureBeginImmediateAcquired);

    // PLAN-004 known-failure is valid only before any durable dispatch authority exists.
    // V1 roots have no overlay table and retain their exact historical behavior. On V2,
    // the check runs under the same writer exclusion as the release transaction so an
    // overlay can neither race this decision nor lose HELD/recovery custody.
    match dispatch_overlay_blocks_known_failure_v1(&transaction, binding.operation_id) {
        Ok(false) => {}
        Ok(true) => return rollback_outcome_v1(transaction, PreparationFailureOutcomeV1::Mismatch),
        Err(error) => {
            return rollback_outcome_v1(transaction, map_transaction_error_v1(error));
        }
    }

    let operation = match load_preparing_operation_v1(&transaction, binding, reason_code, root_mode)
    {
        Ok(OperationClassificationV1::Preparing(operation)) => operation,
        Ok(OperationClassificationV1::AlreadyFailed) => {
            if !verify_full(&transaction) {
                return rollback_outcome_v1(transaction, PreparationFailureOutcomeV1::Unhealthy);
            }
            let outcome = match classify_guard_validation_v1(validate_guard()) {
                Ok(()) => PreparationFailureOutcomeV1::AlreadyFailed,
                Err(outcome) => outcome,
            };
            return rollback_outcome_v1(transaction, outcome);
        }
        Err(error) => {
            return rollback_outcome_v1(transaction, map_transaction_error_v1(error));
        }
    };
    let reservation = match load_held_reservation_v1(&transaction, binding, &operation) {
        Ok(reservation) => reservation,
        Err(error) => {
            return rollback_outcome_v1(transaction, map_transaction_error_v1(error));
        }
    };
    let next_held = match checked_budget_release_v1(reservation.held, reservation.reserved) {
        Ok(next_held) => next_held,
        Err(BudgetVectorCheckErrorV1::ArithmeticInvalid) => {
            return rollback_outcome_v1(transaction, PreparationFailureOutcomeV1::Unhealthy)
        }
        Err(BudgetVectorCheckErrorV1::Exhausted) => {
            return rollback_outcome_v1(transaction, PreparationFailureOutcomeV1::Unhealthy)
        }
    };
    let generations = match allocate_failure_generations_v1(&transaction, root_mode) {
        Ok(generations) => generations,
        Err(error) => {
            return rollback_outcome_v1(transaction, map_transaction_error_v1(error));
        }
    };
    if !verify_full(&transaction) {
        return rollback_outcome_v1(transaction, PreparationFailureOutcomeV1::Unhealthy);
    }
    let event_id = derive_failed_event_id_v1(binding, reason_code, generations);

    let staged = stage_failure_v1(
        &transaction,
        binding,
        &operation,
        &reservation,
        next_held,
        generations,
        &event_id,
        reason_code,
        fault_probe,
        root_mode,
    );
    if let Err(error) = staged {
        return rollback_outcome_v1(transaction, map_transaction_error_v1(error));
    }
    if !verify_foreign_keys_v1(&transaction) || !verify_full(&transaction) {
        return rollback_outcome_v1(transaction, PreparationFailureOutcomeV1::Unhealthy);
    }
    let final_validation = classify_guard_validation_v1(validate_guard());
    note_guard_finally_revalidated();
    if let Err(outcome) = final_validation {
        return rollback_outcome_v1(transaction, outcome);
    }

    let committed = transaction.commit();
    reach!(fault_probe, KnownFailureCommitReturned);
    let outcome = match committed {
        Ok(()) => PreparationFailureOutcomeV1::Failed,
        Err(error) => map_transaction_error_v1(map_sqlite_error_v1(error)),
    };
    reach!(fault_probe, KnownFailureCommitClassified);
    outcome
}

fn dispatch_overlay_blocks_known_failure_v1(
    transaction: &Transaction<'_>,
    operation_id: &str,
) -> Result<bool, FailureTransactionErrorV1> {
    let overlay_exists: bool = transaction
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_schema \
                            WHERE type = 'table' AND name = 'dispatch_records')",
            [],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error_v1)?;
    if !overlay_exists {
        return Ok(false);
    }
    transaction
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM dispatch_records WHERE operation_id = ?1)",
            [operation_id],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error_v1)
}

enum OperationClassificationV1 {
    Preparing(PreparingOperationV1),
    AlreadyFailed,
}

fn load_preparing_operation_v1(
    transaction: &Transaction<'_>,
    binding: &FailureBindingV1<'_>,
    reason_code: &str,
    root_mode: FailureRootModeV1<'_>,
) -> Result<OperationClassificationV1, FailureTransactionErrorV1> {
    if matches!(root_mode, FailureRootModeV1::RestorePending(_)) {
        let quarantined = transaction
            .query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM preparation_quarantines
                     WHERE attempt_id = ?1 AND quarantine_status = 'ACTIVE'
                 )",
                [binding.attempt_id.as_slice()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| FailureTransactionErrorV1::Unhealthy)?;
        if quarantined {
            return Err(FailureTransactionErrorV1::Conflict);
        }
    }
    let row = transaction
        .query_row(
            "SELECT attempt_id, operation_state, state_generation, boot_id, instance_epoch, \
                    fencing_epoch, reservation_id, restored_source_generation \
             FROM prepared_operations WHERE operation_id = ?1",
            [binding.operation_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| FailureTransactionErrorV1::Unhealthy)?
        .ok_or(FailureTransactionErrorV1::Mismatch)?;
    let exact_identity = row.0.as_slice() == binding.attempt_id
        && row.3 == binding.boot_id
        && safe_i64_v1(row.4)? == binding.instance_epoch
        && safe_i64_v1(row.5)? == binding.fencing_epoch;
    if !exact_identity {
        return Err(FailureTransactionErrorV1::Mismatch);
    }
    if let FailureRootModeV1::RestorePending(pending) = root_mode {
        let restored_source_generation = row
            .7
            .map(safe_i64_v1)
            .transpose()?
            .ok_or(FailureTransactionErrorV1::Mismatch)?;
        if restored_source_generation != pending.restored_source_generation {
            return Err(FailureTransactionErrorV1::Mismatch);
        }
    }
    match row.1.as_str() {
        "PREPARING" if safe_i64_v1(row.2)? == binding.preparing_state_generation => {
            Ok(OperationClassificationV1::Preparing(PreparingOperationV1 {
                reservation_id: row.6,
            }))
        }
        "FAILED" if terminal_failure_is_exact_v1(transaction, binding, reason_code)? => {
            Ok(OperationClassificationV1::AlreadyFailed)
        }
        _ => Err(FailureTransactionErrorV1::Mismatch),
    }
}

fn terminal_failure_is_exact_v1(
    transaction: &Transaction<'_>,
    binding: &FailureBindingV1<'_>,
    reason_code: &str,
) -> Result<bool, FailureTransactionErrorV1> {
    let count = transaction
        .query_row(
            "SELECT COUNT(*) \
             FROM prepared_operations AS operation \
             JOIN budget_reservations AS reservation \
               ON reservation.reservation_id = operation.reservation_id \
              AND reservation.operation_id = operation.operation_id \
             JOIN operation_transitions AS transition \
               ON transition.operation_id = operation.operation_id \
              AND transition.state_generation = operation.state_generation \
              AND transition.event_id = operation.current_event_id \
             JOIN preparation_events AS event \
               ON event.event_id = operation.current_event_id \
              AND event.operation_id = operation.operation_id \
              AND event.operation_state_generation = operation.state_generation \
             WHERE operation.operation_id = ?1 AND operation.attempt_id = ?2 \
               AND operation.operation_state = 'FAILED' \
               AND operation.failed_reason_code = ?3 \
               AND operation.boot_id = ?4 AND operation.instance_epoch = ?5 \
               AND operation.fencing_epoch = ?6 \
               AND reservation.attempt_id = ?2 AND reservation.reservation_state = 'RELEASED' \
               AND reservation.released_generation = operation.failed_generation \
               AND transition.previous_state = 'PREPARING' \
               AND transition.new_state = 'FAILED' \
               AND event.operation_state = 'FAILED' \
               AND event.event_kind = 'PREPARATION_FAILED' \
               AND event.reason_code = ?3 \
               AND EXISTS (SELECT 1 FROM operation_transitions AS initial \
                           WHERE initial.operation_id = operation.operation_id \
                             AND initial.state_generation = ?7 \
                             AND initial.previous_state IS NULL \
                             AND initial.new_state = 'PREPARING')",
            params![
                binding.operation_id,
                binding.attempt_id.as_slice(),
                reason_code,
                binding.boot_id,
                to_i64_v1(binding.instance_epoch)?,
                to_i64_v1(binding.fencing_epoch)?,
                to_i64_v1(binding.preparing_state_generation)?,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| FailureTransactionErrorV1::Unhealthy)?;
    Ok(count == 1)
}

fn load_held_reservation_v1(
    transaction: &Transaction<'_>,
    binding: &FailureBindingV1<'_>,
    operation: &PreparingOperationV1,
) -> Result<HeldReservationV1, FailureTransactionErrorV1> {
    let row = transaction
        .query_row(
            "SELECT reservation.scope_id, reservation.reserved_cost_micro_units, \
                    reservation.reserved_action_count, reservation.reserved_egress_bytes, \
                    reservation.reserved_recovery_bytes, scope.held_cost_micro_units, \
                    scope.held_action_count, scope.held_egress_bytes, scope.held_recovery_bytes \
             FROM budget_reservations AS reservation \
             JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id \
             WHERE reservation.reservation_id = ?1 \
               AND reservation.operation_id = ?2 AND reservation.attempt_id = ?3 \
               AND reservation.reservation_state = 'HELD' \
               AND reservation.released_generation IS NULL",
            params![
                operation.reservation_id,
                binding.operation_id,
                binding.attempt_id.as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    [
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ],
                    [
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ],
                ))
            },
        )
        .optional()
        .map_err(|_| FailureTransactionErrorV1::Unhealthy)?
        .ok_or(FailureTransactionErrorV1::Mismatch)?;
    if row.0.len() != 32 {
        return Err(FailureTransactionErrorV1::Unhealthy);
    }
    Ok(HeldReservationV1 {
        scope_id: row.0,
        reserved: safe_vector_v1(row.1)?,
        held: safe_vector_v1(row.2)?,
    })
}

fn allocate_failure_generations_v1(
    transaction: &Transaction<'_>,
    root_mode: FailureRootModeV1<'_>,
) -> Result<FailureGenerationsV1, FailureTransactionErrorV1> {
    let current = transaction
        .query_row(
            "SELECT store_generation, operation_generation, budget_generation, \
                    event_generation, root_lifecycle_state, restore_identity_digest, \
                    restore_attestation_digest, restore_state_generation \
             FROM coordinator_store_meta \
             WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .map_err(|_| FailureTransactionErrorV1::Unhealthy)?;
    let lifecycle_exact = match root_mode {
        FailureRootModeV1::Active => {
            current.4 == "ACTIVE" && current.5.is_none() && current.6.is_none() && current.7 == 0
        }
        FailureRootModeV1::RestorePending(pending) => {
            current.4 == "RESTORE_PENDING"
                && current.5.as_deref()
                    == Some(pending.restore_identity_digest.as_bytes().as_slice())
                && current.6.as_deref()
                    == Some(pending.restore_attestation_digest.as_bytes().as_slice())
                && safe_i64_v1(current.7)? == pending.restore_state_generation
        }
    };
    if !lifecycle_exact {
        return Err(FailureTransactionErrorV1::Mismatch);
    }
    let current = [
        safe_i64_v1(current.0)?,
        safe_i64_v1(current.1)?,
        safe_i64_v1(current.2)?,
        safe_i64_v1(current.3)?,
    ];
    if current[1..]
        .iter()
        .any(|generation| *generation > current[0])
    {
        return Err(FailureTransactionErrorV1::Unhealthy);
    }
    let store = next_safe_v1(current[0])?;
    Ok(FailureGenerationsV1 {
        store,
        operation: next_safe_v1(current[1])?,
        budget: store,
        event: next_safe_v1(current[3])?,
    })
}

#[allow(clippy::too_many_arguments)]
fn stage_failure_v1(
    transaction: &Transaction<'_>,
    binding: &FailureBindingV1<'_>,
    operation: &PreparingOperationV1,
    reservation: &HeldReservationV1,
    next_held: [u64; 4],
    generations: FailureGenerationsV1,
    event_id: &[u8; 32],
    reason_code: &str,
    fault_probe: &CoordinatorFaultProbeV1,
    root_mode: FailureRootModeV1<'_>,
) -> Result<(), FailureTransactionErrorV1> {
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
    let operation_updated = transaction
        .execute(
            "UPDATE prepared_operations \
             SET operation_state = 'FAILED', state_generation = ?1, \
                 failed_generation = ?2, failed_reason_code = ?3, current_event_id = ?4 \
             WHERE operation_id = ?5 AND attempt_id = ?6 \
               AND operation_state = 'PREPARING' AND state_generation = ?7 \
               AND failed_generation IS NULL AND failed_reason_code IS NULL \
               AND reservation_id = ?8 AND boot_id = ?9 \
               AND instance_epoch = ?10 AND fencing_epoch = ?11",
            params![
                to_i64_v1(generations.operation)?,
                to_i64_v1(generations.store)?,
                reason_code,
                event_id.as_slice(),
                binding.operation_id,
                binding.attempt_id.as_slice(),
                to_i64_v1(binding.preparing_state_generation)?,
                operation.reservation_id,
                binding.boot_id,
                to_i64_v1(binding.instance_epoch)?,
                to_i64_v1(binding.fencing_epoch)?,
            ],
        )
        .map_err(map_sqlite_error_v1)?;
    if operation_updated != 1 {
        return Err(FailureTransactionErrorV1::Conflict);
    }
    reach!(fault_probe, KnownFailureOperationFailedStaged);

    stage_failed_transition_v1(
        transaction,
        FailedTransitionRowV1 {
            state_generation: to_i64_v1(generations.operation)?,
            operation_id: binding.operation_id,
            event_id,
        },
    )
    .map_err(map_sqlite_error_v1)?;
    reach!(fault_probe, KnownFailureTransitionStaged);

    let scope_updated = transaction
        .execute(
            "UPDATE budget_scopes \
             SET held_cost_micro_units = ?1, held_action_count = ?2, \
                 held_egress_bytes = ?3, held_recovery_bytes = ?4 \
             WHERE scope_id = ?5 AND held_cost_micro_units = ?6 \
               AND held_action_count = ?7 AND held_egress_bytes = ?8 \
               AND held_recovery_bytes = ?9",
            params![
                to_i64_v1(next_held[0])?,
                to_i64_v1(next_held[1])?,
                to_i64_v1(next_held[2])?,
                to_i64_v1(next_held[3])?,
                reservation.scope_id,
                to_i64_v1(reservation.held[0])?,
                to_i64_v1(reservation.held[1])?,
                to_i64_v1(reservation.held[2])?,
                to_i64_v1(reservation.held[3])?,
            ],
        )
        .map_err(map_sqlite_error_v1)?;
    if scope_updated != 1 {
        return Err(FailureTransactionErrorV1::Conflict);
    }
    reach!(fault_probe, KnownFailureScopeHeldSubtractionStaged);

    let reservation_updated = transaction
        .execute(
            "UPDATE budget_reservations \
             SET reservation_state = 'RELEASED', released_generation = ?1 \
             WHERE reservation_id = ?2 AND operation_id = ?3 AND attempt_id = ?4 \
               AND reservation_state = 'HELD' AND released_generation IS NULL",
            params![
                to_i64_v1(generations.store)?,
                operation.reservation_id,
                binding.operation_id,
                binding.attempt_id.as_slice(),
            ],
        )
        .map_err(map_sqlite_error_v1)?;
    if reservation_updated != 1 {
        return Err(FailureTransactionErrorV1::Conflict);
    }
    reach!(fault_probe, KnownFailureReservationReleasedStaged);

    stage_failed_event_v1(
        transaction,
        FailedEventRowV1 {
            event_id,
            event_generation: to_i64_v1(generations.event)?,
            operation_id: binding.operation_id,
            operation_state_generation: to_i64_v1(generations.operation)?,
            reason_code,
        },
    )
    .map_err(map_sqlite_error_v1)?;
    reach!(fault_probe, KnownFailureEventStaged);

    let metadata_updated = match root_mode {
        FailureRootModeV1::Active => transaction.execute(
            "UPDATE coordinator_store_meta \
             SET store_generation = ?1, operation_generation = ?2, \
                 budget_generation = ?3, event_generation = ?4 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND store_generation = ?1 - 1 AND operation_generation = ?2 - 1 \
               AND event_generation = ?4 - 1 AND budget_generation <= ?1 - 1",
            params![
                to_i64_v1(generations.store)?,
                to_i64_v1(generations.operation)?,
                to_i64_v1(generations.budget)?,
                to_i64_v1(generations.event)?,
            ],
        ),
        FailureRootModeV1::RestorePending(pending) => transaction.execute(
            "UPDATE coordinator_store_meta \
             SET store_generation = ?1, operation_generation = ?2, \
                 budget_generation = ?3, event_generation = ?4 \
             WHERE singleton = 1 AND root_lifecycle_state = 'RESTORE_PENDING' \
               AND restore_identity_digest = ?5 AND restore_attestation_digest = ?6 \
               AND restore_state_generation = ?7 \
               AND store_generation = ?1 - 1 AND operation_generation = ?2 - 1 \
               AND event_generation = ?4 - 1 AND budget_generation <= ?1 - 1",
            params![
                to_i64_v1(generations.store)?,
                to_i64_v1(generations.operation)?,
                to_i64_v1(generations.budget)?,
                to_i64_v1(generations.event)?,
                pending.restore_identity_digest.as_bytes().as_slice(),
                pending.restore_attestation_digest.as_bytes().as_slice(),
                to_i64_v1(pending.restore_state_generation)?,
            ],
        ),
    }
    .map_err(map_sqlite_error_v1)?;
    if metadata_updated != 1 {
        return Err(FailureTransactionErrorV1::Conflict);
    }
    reach!(fault_probe, KnownFailureMetadataStaged);
    Ok(())
}

#[allow(dead_code)] // Used by the T073 production seam before T075 exports it.
fn restored_authority_rotation_is_valid_v1(input: &RestoredOldAuthorityFailureInputV1<'_>) -> bool {
    input.restored_source_generation > 0
        && input.restored_source_generation <= MAX_SAFE_U64
        && input.restore_state_generation > 0
        && input.restore_state_generation <= MAX_SAFE_U64
        && input.rotation.binds_old_authority_v1(
            input.binding.boot_id(),
            input.binding.instance_epoch(),
            input.binding.fencing_epoch(),
        )
}

#[allow(dead_code)] // Used by the T073 production seam before T075 exports it.
fn map_restored_failure_outcome_v1(
    outcome: PreparationFailureOutcomeV1,
) -> RestoredOldAuthorityFailureOutcomeV1 {
    match outcome {
        PreparationFailureOutcomeV1::Failed => RestoredOldAuthorityFailureOutcomeV1::Failed,
        PreparationFailureOutcomeV1::AlreadyFailed => {
            RestoredOldAuthorityFailureOutcomeV1::AlreadyFailed
        }
        PreparationFailureOutcomeV1::Mismatch => {
            RestoredOldAuthorityFailureOutcomeV1::GuardMismatch
        }
        PreparationFailureOutcomeV1::DeadlineReached => {
            RestoredOldAuthorityFailureOutcomeV1::GuardDeadlineReached
        }
        PreparationFailureOutcomeV1::Unavailable => {
            RestoredOldAuthorityFailureOutcomeV1::GuardUnavailable
        }
        PreparationFailureOutcomeV1::Unhealthy => RestoredOldAuthorityFailureOutcomeV1::Unhealthy,
        PreparationFailureOutcomeV1::Conflict => RestoredOldAuthorityFailureOutcomeV1::Conflict,
    }
}

fn verify_foreign_keys_v1(transaction: &Transaction<'_>) -> bool {
    transaction
        .prepare("PRAGMA foreign_key_check")
        .and_then(|mut statement| statement.exists([]))
        .map(|has_violation| !has_violation)
        .unwrap_or(false)
}

fn derive_failed_event_id_v1(
    binding: &FailureBindingV1<'_>,
    reason_code: &str,
    generations: FailureGenerationsV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FAILED_EVENT_ID_DOMAIN_V1);
    hasher.update((binding.operation_id.len() as u64).to_be_bytes());
    hasher.update(binding.operation_id.as_bytes());
    hasher.update(binding.attempt_id);
    hasher.update(generations.operation.to_be_bytes());
    hasher.update(generations.event.to_be_bytes());
    hasher.update((reason_code.len() as u64).to_be_bytes());
    hasher.update(reason_code.as_bytes());
    hasher.finalize().into()
}

fn classify_guard_validation_v1(
    validation: NoDispatchAuthorityValidationV1,
) -> Result<(), PreparationFailureOutcomeV1> {
    match validation {
        NoDispatchAuthorityValidationV1::Valid => Ok(()),
        NoDispatchAuthorityValidationV1::Mismatch | NoDispatchAuthorityValidationV1::Revoked => {
            Err(PreparationFailureOutcomeV1::Mismatch)
        }
        NoDispatchAuthorityValidationV1::DeadlineReached => {
            Err(PreparationFailureOutcomeV1::DeadlineReached)
        }
        NoDispatchAuthorityValidationV1::Unavailable => {
            Err(PreparationFailureOutcomeV1::Unavailable)
        }
    }
}

fn safe_vector_v1(values: [i64; 4]) -> Result<[u64; 4], FailureTransactionErrorV1> {
    Ok([
        safe_i64_v1(values[0])?,
        safe_i64_v1(values[1])?,
        safe_i64_v1(values[2])?,
        safe_i64_v1(values[3])?,
    ])
}

fn safe_i64_v1(value: i64) -> Result<u64, FailureTransactionErrorV1> {
    let value = u64::try_from(value).map_err(|_| FailureTransactionErrorV1::ArithmeticInvalid)?;
    if value > MAX_SAFE_U64 {
        return Err(FailureTransactionErrorV1::ArithmeticInvalid);
    }
    Ok(value)
}

fn to_i64_v1(value: u64) -> Result<i64, FailureTransactionErrorV1> {
    if value > MAX_SAFE_U64 {
        return Err(FailureTransactionErrorV1::ArithmeticInvalid);
    }
    i64::try_from(value).map_err(|_| FailureTransactionErrorV1::ArithmeticInvalid)
}

fn next_safe_v1(value: u64) -> Result<u64, FailureTransactionErrorV1> {
    value
        .checked_add(1)
        .filter(|next| *next <= MAX_SAFE_U64)
        .ok_or(FailureTransactionErrorV1::ArithmeticInvalid)
}

fn map_sqlite_error_v1(error: rusqlite::Error) -> FailureTransactionErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            FailureTransactionErrorV1::Busy
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::CannotOpen | ErrorCode::ReadOnly | ErrorCode::DiskFull
            ) =>
        {
            FailureTransactionErrorV1::Unavailable
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
                && matches!(failure.extended_code, 1_555 | 2_067) =>
        {
            FailureTransactionErrorV1::Conflict
        }
        _ => FailureTransactionErrorV1::Unhealthy,
    }
}

fn map_transaction_error_v1(error: FailureTransactionErrorV1) -> PreparationFailureOutcomeV1 {
    match error {
        FailureTransactionErrorV1::Mismatch => PreparationFailureOutcomeV1::Mismatch,
        FailureTransactionErrorV1::ArithmeticInvalid | FailureTransactionErrorV1::Unhealthy => {
            PreparationFailureOutcomeV1::Unhealthy
        }
        FailureTransactionErrorV1::Busy => PreparationFailureOutcomeV1::Conflict,
        FailureTransactionErrorV1::Unavailable => PreparationFailureOutcomeV1::Unavailable,
        FailureTransactionErrorV1::Conflict => PreparationFailureOutcomeV1::Conflict,
    }
}

fn rollback_outcome_v1(
    transaction: Transaction<'_>,
    outcome: PreparationFailureOutcomeV1,
) -> PreparationFailureOutcomeV1 {
    if transaction.rollback().is_ok() {
        outcome
    } else {
        PreparationFailureOutcomeV1::Unhealthy
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the source-included cancellation integration test.
pub(crate) struct SyntheticKnownFailureCaseV1 {
    operation_id: String,
    attempt_id: [u8; 32],
    preparing_state_generation: u64,
    boot_id: String,
    instance_epoch: u64,
    fencing_epoch: u64,
    revocation_generation: u64,
    deadline_monotonic_ms: u64,
}

#[cfg(test)]
impl std::fmt::Debug for SyntheticKnownFailureCaseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyntheticKnownFailureCaseV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the source-included cancellation integration test.
impl SyntheticKnownFailureCaseV1 {
    pub(crate) fn load_preparing_v1(
        database: &std::path::Path,
        operation_id: &str,
        revocation_generation: u64,
        deadline_monotonic_ms: u64,
    ) -> Result<Self, ()> {
        let connection = Connection::open(database).map_err(|_| ())?;
        let row = connection
            .query_row(
                "SELECT attempt_id, state_generation, boot_id, instance_epoch, fencing_epoch \
                 FROM prepared_operations \
                 WHERE operation_id = ?1 AND operation_state = 'PREPARING'",
                [operation_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .map_err(|_| ())?;
        let attempt_id: [u8; 32] = row.0.try_into().map_err(|_| ())?;
        Ok(Self {
            operation_id: operation_id.to_owned(),
            attempt_id,
            preparing_state_generation: safe_i64_v1(row.1).map_err(|_| ())?,
            boot_id: row.2,
            instance_epoch: safe_i64_v1(row.3).map_err(|_| ())?,
            fencing_epoch: safe_i64_v1(row.4).map_err(|_| ())?,
            revocation_generation,
            deadline_monotonic_ms,
        })
    }
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the source-included cancellation integration test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticNoDispatchGuardCaseV1 {
    Exact,
    Absent,
    WrongOperation,
    WrongAttempt,
    WrongStateGeneration,
    WrongBootId,
    WrongInstanceEpoch,
    WrongFencingEpoch,
    WrongRevocationGeneration,
    Expired,
    RevokedBeforeCommit,
    Unavailable,
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the source-included cancellation integration test.
pub(crate) fn fail_synthetic_before_dispatch_v1(
    database: &std::path::Path,
    known: &SyntheticKnownFailureCaseV1,
    guard_case: SyntheticNoDispatchGuardCaseV1,
    now_monotonic_ms: u64,
) -> PreparationFailureOutcomeV1 {
    fail_synthetic_before_dispatch_with_probes_inner_v1(
        database,
        known,
        guard_case,
        now_monotonic_ms,
        &CoordinatorFaultProbeV1::disabled_v1(),
        SyntheticPortableFaultProbeV1::Disabled(std::marker::PhantomData),
    )
}

/// Runs the exact synthetic known-failure transaction with explicit coordinator and
/// portable process probes while retaining one live synthetic no-dispatch guard.
#[cfg(all(test, feature = "test-fault-injection"))]
#[allow(dead_code)] // Not every source-including integration root drives process faults.
pub(crate) fn fail_synthetic_before_dispatch_with_fault_probes_v1(
    database: &std::path::Path,
    known: &SyntheticKnownFailureCaseV1,
    guard_case: SyntheticNoDispatchGuardCaseV1,
    now_monotonic_ms: u64,
    coordinator_fault_probe: &CoordinatorFaultProbeV1,
    portable_fault_probe: &helix_plan_preparation::FaultProbeV1,
) -> PreparationFailureOutcomeV1 {
    fail_synthetic_before_dispatch_with_probes_inner_v1(
        database,
        known,
        guard_case,
        now_monotonic_ms,
        coordinator_fault_probe,
        SyntheticPortableFaultProbeV1::Selected(portable_fault_probe),
    )
}

#[cfg(test)]
#[allow(dead_code)] // `Selected` is used only by the T074 process-crash integration root.
#[derive(Clone, Copy)]
enum SyntheticPortableFaultProbeV1<'probe> {
    Disabled(std::marker::PhantomData<&'probe ()>),
    #[cfg(feature = "test-fault-injection")]
    Selected(&'probe helix_plan_preparation::FaultProbeV1),
}

#[cfg(test)]
struct SyntheticKnownFailureGuardV1<'case> {
    known: &'case SyntheticKnownFailureCaseV1,
    guard_case: SyntheticNoDispatchGuardCaseV1,
    now_monotonic_ms: u64,
    validation_count: u8,
}

#[cfg(test)]
impl SyntheticKnownFailureGuardV1<'_> {
    fn validate_synthetic_v1(&mut self) -> NoDispatchAuthorityValidationV1 {
        self.validation_count = self.validation_count.saturating_add(1);
        match self.guard_case {
            SyntheticNoDispatchGuardCaseV1::Exact
                if self.now_monotonic_ms < self.known.deadline_monotonic_ms
                    && self.known.revocation_generation > 0 =>
            {
                NoDispatchAuthorityValidationV1::Valid
            }
            SyntheticNoDispatchGuardCaseV1::RevokedBeforeCommit if self.validation_count == 1 => {
                NoDispatchAuthorityValidationV1::Valid
            }
            SyntheticNoDispatchGuardCaseV1::Expired => {
                NoDispatchAuthorityValidationV1::DeadlineReached
            }
            SyntheticNoDispatchGuardCaseV1::Unavailable => {
                NoDispatchAuthorityValidationV1::Unavailable
            }
            _ => NoDispatchAuthorityValidationV1::Mismatch,
        }
    }
}

#[cfg(test)]
impl NoDispatchAuthorityGuardV1 for SyntheticKnownFailureGuardV1<'_> {
    fn validate(
        &mut self,
        _expected: &NoDispatchAuthorityBindingV1<'_>,
        _now_monotonic_ms: u64,
    ) -> NoDispatchAuthorityValidationV1 {
        self.validate_synthetic_v1()
    }

    fn release(self) {}
}

#[cfg(test)]
fn fail_synthetic_before_dispatch_with_probes_inner_v1(
    database: &std::path::Path,
    known: &SyntheticKnownFailureCaseV1,
    guard_case: SyntheticNoDispatchGuardCaseV1,
    now_monotonic_ms: u64,
    coordinator_fault_probe: &CoordinatorFaultProbeV1,
    portable_fault_probe: SyntheticPortableFaultProbeV1<'_>,
) -> PreparationFailureOutcomeV1 {
    if matches!(guard_case, SyntheticNoDispatchGuardCaseV1::Absent) {
        return PreparationFailureOutcomeV1::Unavailable;
    }
    let binding = FailureBindingV1 {
        operation_id: &known.operation_id,
        attempt_id: known.attempt_id,
        preparing_state_generation: known.preparing_state_generation,
        boot_id: &known.boot_id,
        instance_epoch: known.instance_epoch,
        fencing_epoch: known.fencing_epoch,
    };
    let mut guard = SyntheticKnownFailureGuardV1 {
        known,
        guard_case,
        now_monotonic_ms,
        validation_count: 0,
    };
    let mut connection = match Connection::open(database) {
        Ok(connection) => connection,
        Err(_) => return PreparationFailureOutcomeV1::Unavailable,
    };
    if connection
        .pragma_update(None, "foreign_keys", "ON")
        .is_err()
    {
        return PreparationFailureOutcomeV1::Unhealthy;
    }
    let outcome = {
        let mut validate_guard = || guard.validate_synthetic_v1();
        match portable_fault_probe {
            SyntheticPortableFaultProbeV1::Disabled(_) => fail_transaction_v1(
                &mut connection,
                &binding,
                "PREPARATION_STORE_COMMIT_ABORTED",
                &mut validate_guard,
                &mut |_| true,
                coordinator_fault_probe,
            ),
            #[cfg(feature = "test-fault-injection")]
            SyntheticPortableFaultProbeV1::Selected(portable_fault_probe) => {
                fail_transaction_in_mode_with_fault_probes_v1(
                    &mut connection,
                    &binding,
                    "PREPARATION_STORE_COMMIT_ABORTED",
                    &mut validate_guard,
                    &mut |_| true,
                    coordinator_fault_probe,
                    portable_fault_probe,
                    FailureRootModeV1::Active,
                )
            }
        }
    };
    match portable_fault_probe {
        SyntheticPortableFaultProbeV1::Disabled(_) => {
            helix_plan_preparation::release_known_failure_guard_v1(guard);
        }
        #[cfg(feature = "test-fault-injection")]
        SyntheticPortableFaultProbeV1::Selected(portable_fault_probe) => {
            helix_plan_preparation::release_known_failure_guard_with_fault_probe_v1(
                guard,
                portable_fault_probe,
            );
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prepare::{
        commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1,
        SyntheticCommitModeV1, SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
    };
    use helix_plan_preparation::PreparationCommitOutcomeV1;
    use rusqlite::params;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const STORE_SCHEMA: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
    ));

    struct PendingFailureFixtureV1 {
        directory: PathBuf,
        database: PathBuf,
        operation_id: String,
        known: SyntheticKnownFailureCaseV1,
        pending: RestorePendingFailureCasV1,
    }

    impl PendingFailureFixtureV1 {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "helixos-t073-old-authority-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("fixture directory creates");
            let directory = fs::canonicalize(directory).expect("fixture canonicalizes");
            let database = directory.join("coordinator.sqlite3");
            let connection = Connection::open(&database).expect("fixture database creates");
            connection
                .execute_batch(STORE_SCHEMA)
                .expect("reviewed schema installs");
            connection
                .execute(
                    "INSERT INTO coordinator_store_meta (
                         singleton, format_version, store_generation, operation_generation,
                         budget_generation, event_generation, quarantine_generation, root_identity,
                         root_lifecycle_state, restore_identity_digest,
                         restore_attestation_digest, restore_state_generation
                     ) VALUES (1, 1, 0, 0, 0, 0, 0, ?1, 'ACTIVE', NULL, NULL, 0)",
                    params![[0x41_u8; 32].as_slice()],
                )
                .expect("active metadata initializes");
            drop(connection);

            let case =
                SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
            provision_synthetic_budget_scope_v1(&database, &case)
                .expect("synthetic scope provisions");
            assert!(matches!(
                commit_synthetic_preparation_v1(
                    &database,
                    &case,
                    SyntheticCommitModeV1::Acknowledged,
                ),
                PreparationCommitOutcomeV1::Committed(_)
            ));

            let connection = Connection::open(&database).expect("fixture reopens");
            let operation_id = connection
                .query_row("SELECT operation_id FROM prepared_operations", [], |row| {
                    row.get::<_, String>(0)
                })
                .expect("operation id reads");
            let source_generation = connection
                .query_row(
                    "SELECT store_generation FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("source generation reads") as u64;
            connection
                .execute(
                    "UPDATE prepared_operations SET restored_source_generation = ?1
                     WHERE operation_id = ?2 AND operation_state = 'PREPARING'",
                    params![source_generation as i64, operation_id],
                )
                .expect("restored source generation stamps");
            let restore_state_generation = source_generation + 1;
            connection
                .execute(
                    "UPDATE coordinator_store_meta SET
                         store_generation = ?1, root_identity = ?2,
                         root_lifecycle_state = 'RESTORE_PENDING',
                         restore_identity_digest = ?3, restore_attestation_digest = ?4,
                         restore_state_generation = ?1
                     WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
                       AND store_generation = ?5",
                    params![
                        restore_state_generation as i64,
                        [0x42_u8; 32].as_slice(),
                        [0x51_u8; 32].as_slice(),
                        [0x52_u8; 32].as_slice(),
                        source_generation as i64,
                    ],
                )
                .expect("one-way pending transition commits");
            drop(connection);

            let known = SyntheticKnownFailureCaseV1::load_preparing_v1(
                &database,
                &operation_id,
                17,
                10_000,
            )
            .expect("old authority binding loads");
            Self {
                directory,
                database,
                operation_id,
                known,
                pending: RestorePendingFailureCasV1 {
                    restore_identity_digest: Sha256Digest::from_bytes([0x51; 32]),
                    restore_attestation_digest: Sha256Digest::from_bytes([0x52; 32]),
                    restore_state_generation,
                    restored_source_generation: source_generation,
                },
            }
        }

        fn binding(&self) -> FailureBindingV1<'_> {
            FailureBindingV1 {
                operation_id: &self.known.operation_id,
                attempt_id: self.known.attempt_id,
                preparing_state_generation: self.known.preparing_state_generation,
                boot_id: &self.known.boot_id,
                instance_epoch: self.known.instance_epoch,
                fencing_epoch: self.known.fencing_epoch,
            }
        }

        fn connection(&self) -> Connection {
            let connection = Connection::open(&self.database).expect("fixture opens");
            connection
                .pragma_update(None, "foreign_keys", "ON")
                .expect("foreign keys enable");
            connection
        }

        fn snapshot(&self) -> PendingFailureSnapshotV1 {
            PendingFailureSnapshotV1::read(&self.database, &self.operation_id)
        }
    }

    impl Drop for PendingFailureFixtureV1 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct PendingFailureSnapshotV1 {
        metadata: (i64, i64, i64, i64, i64, String, Vec<u8>, Vec<u8>),
        operation: (String, i64, Option<i64>, String, i64, i64, Option<i64>),
        reservation: (String, Option<i64>),
        scope_held: [i64; 4],
        transitions: i64,
        events: i64,
        quarantines: i64,
    }

    impl PendingFailureSnapshotV1 {
        fn read(database: &Path, operation_id: &str) -> Self {
            let connection = Connection::open(database).expect("snapshot opens");
            let metadata = connection
                .query_row(
                    "SELECT store_generation, operation_generation, budget_generation,
                            event_generation, restore_state_generation, root_lifecycle_state,
                            restore_identity_digest, restore_attestation_digest
                     FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .expect("metadata reads");
            let operation = connection
                .query_row(
                    "SELECT operation_state, state_generation, failed_generation, boot_id,
                            instance_epoch, fencing_epoch, restored_source_generation
                     FROM prepared_operations WHERE operation_id = ?1",
                    [operation_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .expect("operation reads");
            let reservation = connection
                .query_row(
                    "SELECT reservation_state, released_generation
                     FROM budget_reservations WHERE operation_id = ?1",
                    [operation_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("reservation reads");
            let scope_held = connection
                .query_row(
                    "SELECT held_cost_micro_units, held_action_count, held_egress_bytes,
                            held_recovery_bytes FROM budget_scopes",
                    [],
                    |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
                )
                .expect("scope reads");
            let count = |table: &str| {
                connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("count reads")
            };
            Self {
                metadata,
                operation,
                reservation,
                scope_held,
                transitions: count("operation_transitions"),
                events: count("preparation_events"),
                quarantines: count("preparation_quarantines"),
            }
        }
    }

    #[test]
    fn restore_pending_exact_guard_releases_once_without_rebinding_old_authority() {
        let fixture = PendingFailureFixtureV1::new();
        let before = fixture.snapshot();
        let mut connection = fixture.connection();
        let mut exact_guard = || NoDispatchAuthorityValidationV1::Valid;
        let first = fail_transaction_in_mode_v1(
            &mut connection,
            &fixture.binding(),
            "PREPARATION_STORE_COMMIT_ABORTED",
            &mut exact_guard,
            &mut |_| true,
            &CoordinatorFaultProbeV1::disabled_v1(),
            FailureRootModeV1::RestorePending(&fixture.pending),
        );
        assert!(matches!(first, PreparationFailureOutcomeV1::Failed));
        drop(connection);

        let failed = fixture.snapshot();
        assert_eq!(failed.operation.0, "FAILED");
        assert_eq!(failed.reservation.0, "RELEASED");
        assert_eq!(failed.scope_held, [0; 4]);
        assert_eq!(failed.transitions, before.transitions + 1);
        assert_eq!(failed.events, before.events + 1);
        assert_eq!(failed.quarantines, 0);
        assert_eq!(failed.metadata.0, before.metadata.0 + 1);
        assert_eq!(failed.metadata.1, before.metadata.1 + 1);
        assert_eq!(failed.metadata.2, failed.metadata.0);
        assert_eq!(failed.metadata.3, before.metadata.3 + 1);
        assert_eq!(failed.metadata.4, before.metadata.4);
        assert_eq!(failed.metadata.5, "RESTORE_PENDING");
        assert_eq!(failed.metadata.6, before.metadata.6);
        assert_eq!(failed.metadata.7, before.metadata.7);
        assert_eq!(failed.operation.3, before.operation.3);
        assert_eq!(failed.operation.4, before.operation.4);
        assert_eq!(failed.operation.5, before.operation.5);
        assert_eq!(failed.operation.6, before.operation.6);

        let mut connection = fixture.connection();
        let repeated = fail_transaction_in_mode_v1(
            &mut connection,
            &fixture.binding(),
            "PREPARATION_STORE_COMMIT_ABORTED",
            &mut exact_guard,
            &mut |_| true,
            &CoordinatorFaultProbeV1::disabled_v1(),
            FailureRootModeV1::RestorePending(&fixture.pending),
        );
        assert!(matches!(
            repeated,
            PreparationFailureOutcomeV1::AlreadyFailed
        ));
        drop(connection);
        assert_eq!(fixture.snapshot(), failed);
    }

    #[test]
    fn restore_pending_guard_revoked_before_commit_rolls_back_every_release_stage() {
        let fixture = PendingFailureFixtureV1::new();
        let before = fixture.snapshot();
        let mut validations = 0_u8;
        let mut revoked = || {
            validations += 1;
            if validations == 1 {
                NoDispatchAuthorityValidationV1::Valid
            } else {
                NoDispatchAuthorityValidationV1::Revoked
            }
        };
        let mut connection = fixture.connection();
        let outcome = fail_transaction_in_mode_v1(
            &mut connection,
            &fixture.binding(),
            "PREPARATION_STORE_COMMIT_ABORTED",
            &mut revoked,
            &mut |_| true,
            &CoordinatorFaultProbeV1::disabled_v1(),
            FailureRootModeV1::RestorePending(&fixture.pending),
        );
        assert!(matches!(outcome, PreparationFailureOutcomeV1::Mismatch));
        drop(connection);
        assert_eq!(fixture.snapshot(), before);
    }

    #[test]
    fn restore_pending_verifier_refusal_after_staging_rolls_back_every_release_stage() {
        let fixture = PendingFailureFixtureV1::new();
        let before = fixture.snapshot();
        let mut verification_calls = 0_u8;
        let mut verify_pending = |_: &Connection| {
            verification_calls += 1;
            verification_calls == 1
        };
        let mut exact_guard = || NoDispatchAuthorityValidationV1::Valid;
        let mut connection = fixture.connection();
        let outcome = fail_transaction_in_mode_v1(
            &mut connection,
            &fixture.binding(),
            "PREPARATION_STORE_COMMIT_ABORTED",
            &mut exact_guard,
            &mut verify_pending,
            &CoordinatorFaultProbeV1::disabled_v1(),
            FailureRootModeV1::RestorePending(&fixture.pending),
        );
        assert!(matches!(outcome, PreparationFailureOutcomeV1::Unhealthy));
        assert_eq!(verification_calls, 2);
        drop(connection);
        assert_eq!(fixture.snapshot(), before);
    }
}
