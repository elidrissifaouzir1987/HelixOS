//! Private ambiguity and orphan-quarantine custody boundary.

#![allow(dead_code)] // T037/T056 wire base custody into orchestration and maintenance.

use crate::failure::RestoredAuthorityRotationV1;
#[cfg(not(test))]
use crate::schema::{self, RestorePendingBindingsV1};
#[cfg(not(test))]
use helix_contracts::Ed25519KeyResolver;
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use rusqlite::{
    ffi::ErrorCode, params, Connection, Error as SqliteError, OptionalExtension,
    TransactionBehavior,
};
use std::fmt;

const QUARANTINE_ID_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-QUARANTINE\0V1\0";

#[cfg(feature = "test-fault-injection")]
pub(crate) type QuarantineFaultProbeV1 = crate::test_fault::FaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
#[derive(Clone, Copy, Default)]
pub(crate) struct QuarantineFaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
impl QuarantineFaultProbeV1 {
    const fn disabled_v1() -> Self {
        Self
    }
}

type ActiveQuarantineMetadataRowV1 = (i64, i64, String, Option<Vec<u8>>, Option<Vec<u8>>, i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BaseQuarantineReasonV1 {
    AmbiguousCommit,
    OrphanMaterial,
    RestoredOldAuthority,
}

impl BaseQuarantineReasonV1 {
    const fn persisted(self) -> &'static str {
        match self {
            Self::AmbiguousCommit => "AMBIGUOUS_COMMIT",
            Self::OrphanMaterial => "ORPHAN_MATERIAL",
            Self::RestoredOldAuthority => "RESTORED_OLD_AUTHORITY",
        }
    }
}

pub(crate) struct BaseQuarantineInputV1 {
    pub(crate) attempt_id: Sha256Digest,
    pub(crate) operation_binding_digest: Sha256Digest,
    pub(crate) reason: BaseQuarantineReasonV1,
    pub(crate) recovery_manifest_digest: Option<Sha256Digest>,
}

impl fmt::Debug for BaseQuarantineInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaseQuarantineInputV1")
            .finish_non_exhaustive()
    }
}

pub(crate) struct BaseQuarantineCustodyV1 {
    quarantine_id: Sha256Digest,
    created_generation: u64,
}

impl BaseQuarantineCustodyV1 {
    pub(crate) const fn quarantine_id(&self) -> Sha256Digest {
        self.quarantine_id
    }

    pub(crate) const fn created_generation(&self) -> u64 {
        self.created_generation
    }
}

impl fmt::Debug for BaseQuarantineCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BaseQuarantineCustodyV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BaseQuarantineErrorV1 {
    InvalidInput,
    Conflict,
    Unavailable,
    Unhealthy,
    GenerationExhausted,
}

/// Result of retaining base custody inside a caller-owned transaction.
///
/// The distinction lets the caller commit a newly inserted row while rolling back an
/// exact, read-only repeat. The helper itself never closes the transaction.
pub(crate) enum BaseQuarantineTransactionOutcomeV1 {
    Inserted(BaseQuarantineCustodyV1),
    Existing(BaseQuarantineCustodyV1),
}

/// Persists ambiguity custody without inserting or inferring an operation.
///
/// Exact repeats return the same permanent row, including after it becomes a resolved
/// tombstone. A differently bound repeat is a permanent conflict. True-orphan custody
/// requires a manifest reference from the provider domain; ambiguous commit custody may
/// exist before that reference is known.
pub(crate) fn retain_base_quarantine_v1(
    connection: &mut Connection,
    input: &BaseQuarantineInputV1,
) -> Result<BaseQuarantineCustodyV1, BaseQuarantineErrorV1> {
    retain_base_quarantine_with_fault_probe_v1(
        connection,
        input,
        &QuarantineFaultProbeV1::disabled_v1(),
    )
}

fn retain_base_quarantine_with_fault_probe_v1(
    connection: &mut Connection,
    input: &BaseQuarantineInputV1,
    fault_probe: &QuarantineFaultProbeV1,
) -> Result<BaseQuarantineCustodyV1, BaseQuarantineErrorV1> {
    // Preserve the original fail-fast boundary: invalid inputs never acquire a writer.
    validate_base_quarantine_input_v1(input)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_store_error(&error))?;
    let outcome = match retain_base_quarantine_in_transaction_with_fault_probe_v1(
        &transaction,
        input,
        fault_probe,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            transaction
                .rollback()
                .map_err(|rollback_error| map_store_error(&rollback_error))?;
            return Err(error);
        }
    };
    match outcome {
        BaseQuarantineTransactionOutcomeV1::Inserted(custody) => {
            transaction
                .commit()
                .map_err(|error| map_store_error(&error))?;
            Ok(custody)
        }
        BaseQuarantineTransactionOutcomeV1::Existing(custody) => {
            transaction
                .rollback()
                .map_err(|error| map_store_error(&error))?;
            Ok(custody)
        }
    }
}

/// Retains ambiguity custody in an already-open writer transaction.
///
/// This validates the ordinary ACTIVE lifecycle, classifies exact repeats, and performs
/// all generation and quarantine-row mutations. It deliberately performs neither commit
/// nor rollback; every outcome leaves that durability decision with the caller.
pub(crate) fn retain_base_quarantine_in_transaction_v1(
    transaction: &rusqlite::Transaction<'_>,
    input: &BaseQuarantineInputV1,
) -> Result<BaseQuarantineTransactionOutcomeV1, BaseQuarantineErrorV1> {
    retain_base_quarantine_in_transaction_with_fault_probe_v1(
        transaction,
        input,
        &QuarantineFaultProbeV1::disabled_v1(),
    )
}

fn retain_base_quarantine_in_transaction_with_fault_probe_v1(
    transaction: &rusqlite::Transaction<'_>,
    input: &BaseQuarantineInputV1,
    fault_probe: &QuarantineFaultProbeV1,
) -> Result<BaseQuarantineTransactionOutcomeV1, BaseQuarantineErrorV1> {
    validate_base_quarantine_input_v1(input)?;
    let (
        store_generation,
        quarantine_generation,
        root_lifecycle_state,
        restore_identity_digest,
        restore_attestation_digest,
        restore_state_generation,
    ): ActiveQuarantineMetadataRowV1 = transaction
        .query_row(
            "SELECT store_generation, quarantine_generation, root_lifecycle_state, \
                    restore_identity_digest, restore_attestation_digest, \
                    restore_state_generation \
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
                ))
            },
        )
        .map_err(|error| map_store_error(&error))?;
    if root_lifecycle_state != "ACTIVE"
        || restore_identity_digest.is_some()
        || restore_attestation_digest.is_some()
        || restore_state_generation != 0
    {
        return Err(BaseQuarantineErrorV1::Conflict);
    }
    let store_generation = decode_generation(store_generation)?;
    let quarantine_generation = decode_generation(quarantine_generation)?;
    let existing = read_by_attempt(transaction, input.attempt_id)?;
    if !existing.is_empty() {
        return classify_existing(&existing, input)
            .map(BaseQuarantineTransactionOutcomeV1::Existing);
    }

    let quarantine_id = generate_quarantine_id()?;
    let next = store_generation
        .checked_add(1)
        .filter(|generation| *generation <= MAX_SAFE_U64 && *generation > quarantine_generation)
        .ok_or(BaseQuarantineErrorV1::GenerationExhausted)?;
    let updated = transaction
        .execute(
            "UPDATE coordinator_store_meta \
             SET store_generation = ?1, quarantine_generation = ?1 \
             WHERE singleton = 1 AND store_generation = ?2 \
               AND quarantine_generation = ?3 \
               AND root_lifecycle_state = 'ACTIVE' \
               AND restore_identity_digest IS NULL \
               AND restore_attestation_digest IS NULL \
               AND restore_state_generation = 0",
            params![
                next as i64,
                store_generation as i64,
                quarantine_generation as i64
            ],
        )
        .map_err(|error| map_store_error(&error))?;
    if updated != 1 {
        return Err(BaseQuarantineErrorV1::Unhealthy);
    }
    transaction
        .execute(
            "INSERT INTO preparation_quarantines (
                 quarantine_id, attempt_id, operation_binding_digest, quarantine_reason,
                 quarantine_status, created_generation, resolved_generation,
                 recovery_manifest_digest, orphan_resolution_evidence_digest,
                 orphan_retirement_id, orphan_retirement_state, orphan_retired_generation,
                 orphan_retirement_manifest_digest
             ) VALUES (?1, ?2, ?3, ?4, 'ACTIVE', ?5, NULL, ?6, NULL, NULL, NULL, NULL, NULL)",
            params![
                quarantine_id.as_bytes().as_slice(),
                input.attempt_id.as_bytes().as_slice(),
                input.operation_binding_digest.as_bytes().as_slice(),
                input.reason.persisted(),
                next as i64,
                input
                    .recovery_manifest_digest
                    .as_ref()
                    .map(Sha256Digest::as_bytes)
                    .map(<[u8; 32]>::as_slice),
            ],
        )
        .map_err(|error| map_insert_error(&error))?;
    reach_quarantine_inserted(fault_probe);
    Ok(BaseQuarantineTransactionOutcomeV1::Inserted(
        BaseQuarantineCustodyV1 {
            quarantine_id,
            created_generation: next,
        },
    ))
}

fn validate_base_quarantine_input_v1(
    input: &BaseQuarantineInputV1,
) -> Result<(), BaseQuarantineErrorV1> {
    // Restored authority is accepted only by the restore-pending CAS below. Keeping
    // that lifecycle exception out of the ordinary ACTIVE custody path prevents a
    // caller from relabeling native ambiguity as restored evidence.
    if input.reason == BaseQuarantineReasonV1::RestoredOldAuthority {
        return Err(BaseQuarantineErrorV1::InvalidInput);
    }
    if input.reason == BaseQuarantineReasonV1::OrphanMaterial
        && input.recovery_manifest_digest.is_none()
    {
        return Err(BaseQuarantineErrorV1::InvalidInput);
    }
    Ok(())
}

/// Exact restored operation and root bindings used only while the destination root is
/// irreversibly `RESTORE_PENDING`.
pub(crate) struct RestoredOldAuthorityQuarantineInputV1<'binding> {
    pub(crate) operation_id: &'binding str,
    pub(crate) attempt_id: Sha256Digest,
    pub(crate) operation_binding_digest: Sha256Digest,
    pub(crate) preparing_state_generation: u64,
    pub(crate) old_boot_id: &'binding str,
    pub(crate) old_instance_epoch: u64,
    pub(crate) old_fencing_epoch: u64,
    pub(crate) restored_source_generation: u64,
    pub(crate) restore_identity_digest: Sha256Digest,
    pub(crate) restore_attestation_digest: Sha256Digest,
    pub(crate) restore_state_generation: u64,
    pub(crate) rotation: RestoredAuthorityRotationV1,
}

impl fmt::Debug for RestoredOldAuthorityQuarantineInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoredOldAuthorityQuarantineInputV1")
            .finish_non_exhaustive()
    }
}

/// Closed reasons for choosing quarantine instead of attempting a budget release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestoredOldAuthorityGuardFailureV1 {
    Missing,
    Mismatched,
    Revoked,
    DeadlineReached,
    Unavailable,
    Ambiguous,
}

#[derive(Debug)]
pub(crate) enum RestoredOldAuthorityQuarantineOutcomeV1 {
    Retained(BaseQuarantineCustodyV1),
    AlreadyFailed,
}

/// Durably chooses the no-release disposition for one restored preparation.
///
/// The guard-failure value is deliberately required, so the normal ACTIVE ambiguity
/// path cannot call this lifecycle exception. The writer transaction compares the
/// complete pending-root identity and the immutable old operation authority before it
/// allocates a quarantine generation. It never updates an operation, reservation,
/// authority epoch, restore binding, or root lifecycle field.
#[cfg(not(test))]
pub(crate) fn retain_restored_old_authority_quarantine_v1<R>(
    connection: &mut Connection,
    input: &RestoredOldAuthorityQuarantineInputV1<'_>,
    guard_failure: RestoredOldAuthorityGuardFailureV1,
    pending_bindings: RestorePendingBindingsV1,
    historical_plan_keys: &R,
) -> Result<RestoredOldAuthorityQuarantineOutcomeV1, BaseQuarantineErrorV1>
where
    R: Ed25519KeyResolver,
{
    if !pending_quarantine_bindings_are_exact_v1(input, pending_bindings) {
        return Err(BaseQuarantineErrorV1::InvalidInput);
    }
    // The production verifier is closed over concrete authenticated restore bindings;
    // callers cannot replace full schema/canonical-plan verification with a boolean.
    let mut verify_pending = |transaction: &Connection| {
        schema::verify_restore_pending_v1(transaction, pending_bindings, historical_plan_keys)
            .is_ok()
    };
    retain_restored_old_authority_quarantine_with_verifier_v1(
        connection,
        input,
        guard_failure,
        &mut verify_pending,
    )
}

#[cfg(not(test))]
fn pending_quarantine_bindings_are_exact_v1(
    input: &RestoredOldAuthorityQuarantineInputV1<'_>,
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

/// Test-only verifier injection retained for source-included legacy fixtures. Production
/// code has no corresponding callback-bearing entry point.
#[cfg(test)]
fn retain_restored_old_authority_quarantine_for_test_v1<V>(
    connection: &mut Connection,
    input: &RestoredOldAuthorityQuarantineInputV1<'_>,
    guard_failure: RestoredOldAuthorityGuardFailureV1,
    verify_pending: &mut V,
) -> Result<RestoredOldAuthorityQuarantineOutcomeV1, BaseQuarantineErrorV1>
where
    V: FnMut(&Connection) -> bool,
{
    retain_restored_old_authority_quarantine_with_verifier_v1(
        connection,
        input,
        guard_failure,
        verify_pending,
    )
}

fn retain_restored_old_authority_quarantine_with_verifier_v1<V>(
    connection: &mut Connection,
    input: &RestoredOldAuthorityQuarantineInputV1<'_>,
    _guard_failure: RestoredOldAuthorityGuardFailureV1,
    verify_pending: &mut V,
) -> Result<RestoredOldAuthorityQuarantineOutcomeV1, BaseQuarantineErrorV1>
where
    V: FnMut(&Connection) -> bool,
{
    validate_restored_old_authority_input_v1(input)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_store_error(&error))?;
    let metadata = read_restore_pending_metadata_v1(&transaction, input)?;
    if !verify_pending(&transaction) {
        return rollback_restored_quarantine_v1(transaction, Err(BaseQuarantineErrorV1::Unhealthy));
    }

    let base_input = BaseQuarantineInputV1 {
        attempt_id: input.attempt_id,
        operation_binding_digest: input.operation_binding_digest,
        reason: BaseQuarantineReasonV1::RestoredOldAuthority,
        recovery_manifest_digest: None,
    };
    let existing = read_by_attempt(&transaction, input.attempt_id)?;
    if !existing.is_empty() {
        let result = classify_existing(&existing, &base_input)
            .map(RestoredOldAuthorityQuarantineOutcomeV1::Retained);
        return rollback_restored_quarantine_v1(transaction, result);
    }

    match classify_exact_restored_operation_v1(&transaction, input)? {
        RestoredOperationStateV1::Preparing => {}
        RestoredOperationStateV1::Failed => {
            return rollback_restored_quarantine_v1(
                transaction,
                Ok(RestoredOldAuthorityQuarantineOutcomeV1::AlreadyFailed),
            )
        }
    }

    let next = metadata
        .store_generation
        .checked_add(1)
        .filter(|generation| {
            *generation <= MAX_SAFE_U64 && *generation > metadata.quarantine_generation
        })
        .ok_or(BaseQuarantineErrorV1::GenerationExhausted)?;
    let quarantine_id = generate_quarantine_id()?;
    transaction
        .execute(
            "INSERT INTO preparation_quarantines (
                 quarantine_id, attempt_id, operation_binding_digest, quarantine_reason,
                 quarantine_status, created_generation, resolved_generation,
                 recovery_manifest_digest, orphan_resolution_evidence_digest,
                 orphan_retirement_id, orphan_retirement_state, orphan_retired_generation,
                 orphan_retirement_manifest_digest
             ) VALUES (?1, ?2, ?3, 'RESTORED_OLD_AUTHORITY', 'ACTIVE', ?4,
                       NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
            params![
                quarantine_id.as_bytes().as_slice(),
                input.attempt_id.as_bytes().as_slice(),
                input.operation_binding_digest.as_bytes().as_slice(),
                i64::try_from(next).map_err(|_| BaseQuarantineErrorV1::GenerationExhausted)?,
            ],
        )
        .map_err(|error| map_insert_error(&error))?;
    reach_quarantine_inserted(&QuarantineFaultProbeV1::disabled_v1());
    let updated = transaction
        .execute(
            "UPDATE coordinator_store_meta
             SET store_generation = ?1, quarantine_generation = ?1
             WHERE singleton = 1 AND root_lifecycle_state = 'RESTORE_PENDING'
               AND restore_identity_digest = ?2 AND restore_attestation_digest = ?3
               AND restore_state_generation = ?4 AND store_generation = ?5
               AND quarantine_generation = ?6",
            params![
                i64::try_from(next).map_err(|_| BaseQuarantineErrorV1::GenerationExhausted)?,
                input.restore_identity_digest.as_bytes().as_slice(),
                input.restore_attestation_digest.as_bytes().as_slice(),
                i64::try_from(input.restore_state_generation)
                    .map_err(|_| BaseQuarantineErrorV1::InvalidInput)?,
                i64::try_from(metadata.store_generation)
                    .map_err(|_| BaseQuarantineErrorV1::Unhealthy)?,
                i64::try_from(metadata.quarantine_generation)
                    .map_err(|_| BaseQuarantineErrorV1::Unhealthy)?,
            ],
        )
        .map_err(|error| map_store_error(&error))?;
    if updated != 1 || !verify_pending(&transaction) {
        return rollback_restored_quarantine_v1(transaction, Err(BaseQuarantineErrorV1::Unhealthy));
    }
    transaction
        .commit()
        .map_err(|error| map_store_error(&error))?;
    Ok(RestoredOldAuthorityQuarantineOutcomeV1::Retained(
        BaseQuarantineCustodyV1 {
            quarantine_id,
            created_generation: next,
        },
    ))
}

struct RestorePendingMetadataV1 {
    store_generation: u64,
    quarantine_generation: u64,
}

fn read_restore_pending_metadata_v1(
    connection: &Connection,
    input: &RestoredOldAuthorityQuarantineInputV1<'_>,
) -> Result<RestorePendingMetadataV1, BaseQuarantineErrorV1> {
    connection
        .query_row(
            "SELECT store_generation, quarantine_generation
             FROM coordinator_store_meta
             WHERE singleton = 1 AND root_lifecycle_state = 'RESTORE_PENDING'
               AND restore_identity_digest = ?1 AND restore_attestation_digest = ?2
               AND restore_state_generation = ?3",
            params![
                input.restore_identity_digest.as_bytes().as_slice(),
                input.restore_attestation_digest.as_bytes().as_slice(),
                i64::try_from(input.restore_state_generation)
                    .map_err(|_| BaseQuarantineErrorV1::InvalidInput)?,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()
        .map_err(|error| map_store_error(&error))?
        .ok_or(BaseQuarantineErrorV1::Conflict)
        .and_then(|(store_generation, quarantine_generation)| {
            Ok(RestorePendingMetadataV1 {
                store_generation: decode_generation(store_generation)?,
                quarantine_generation: decode_generation(quarantine_generation)?,
            })
        })
}

enum RestoredOperationStateV1 {
    Preparing,
    Failed,
}

fn classify_exact_restored_operation_v1(
    connection: &Connection,
    input: &RestoredOldAuthorityQuarantineInputV1<'_>,
) -> Result<RestoredOperationStateV1, BaseQuarantineErrorV1> {
    let row = connection
        .query_row(
            "SELECT attempt_id, operation_state, state_generation, boot_id,
                    instance_epoch, fencing_epoch, restored_source_generation
             FROM prepared_operations WHERE operation_id = ?1",
            [input.operation_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_store_error(&error))?
        .ok_or(BaseQuarantineErrorV1::Conflict)?;
    let state_generation = decode_generation(row.2)?;
    let exact_identity = row.0.as_slice() == input.attempt_id.as_bytes()
        && row.3 == input.old_boot_id
        && decode_generation(row.4)? == input.old_instance_epoch
        && decode_generation(row.5)? == input.old_fencing_epoch
        && row.6.map(decode_generation).transpose()? == Some(input.restored_source_generation);
    if !exact_identity {
        return Err(BaseQuarantineErrorV1::Conflict);
    }
    match row.1.as_str() {
        "PREPARING" if state_generation == input.preparing_state_generation => {
            Ok(RestoredOperationStateV1::Preparing)
        }
        "FAILED" if state_generation > input.preparing_state_generation => {
            Ok(RestoredOperationStateV1::Failed)
        }
        "PREPARING" | "FAILED" => Err(BaseQuarantineErrorV1::Conflict),
        _ => Err(BaseQuarantineErrorV1::Unhealthy),
    }
}

fn validate_restored_old_authority_input_v1(
    input: &RestoredOldAuthorityQuarantineInputV1<'_>,
) -> Result<(), BaseQuarantineErrorV1> {
    let valid_identifier = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':')
            })
    };
    let generations = [
        input.preparing_state_generation,
        input.old_instance_epoch,
        input.old_fencing_epoch,
        input.restored_source_generation,
        input.restore_state_generation,
    ];
    if !valid_identifier(input.operation_id)
        || !valid_identifier(input.old_boot_id)
        || generations.iter().any(|value| *value > MAX_SAFE_U64)
        || input.preparing_state_generation == 0
        || input.restored_source_generation == 0
        || input.restore_state_generation == 0
        || !input.rotation.binds_old_authority_v1(
            input.old_boot_id,
            input.old_instance_epoch,
            input.old_fencing_epoch,
        )
    {
        return Err(BaseQuarantineErrorV1::InvalidInput);
    }
    Ok(())
}

fn rollback_restored_quarantine_v1<T>(
    transaction: rusqlite::Transaction<'_>,
    outcome: Result<T, BaseQuarantineErrorV1>,
) -> Result<T, BaseQuarantineErrorV1> {
    transaction
        .rollback()
        .map_err(|error| map_store_error(&error))?;
    outcome
}

/// Public-synthetic true-orphan input used only by the PLAN-004 conformance harness.
#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) struct SyntheticOrphanInputV1 {
    pub(crate) attempt_id: Sha256Digest,
    pub(crate) operation_binding_digest: Sha256Digest,
    pub(crate) recovery_manifest_digest: Sha256Digest,
}

#[cfg(test)]
impl fmt::Debug for SyntheticOrphanInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticOrphanInputV1")
            .finish_non_exhaustive()
    }
}

/// Inserts or reopens exact active orphan custody without fabricating an operation.
#[cfg(test)]
#[allow(dead_code)] // Consumed by source-included US3 integration tests.
pub(crate) fn retain_synthetic_orphan_v1(
    connection: &mut Connection,
    input: &SyntheticOrphanInputV1,
) -> Result<BaseQuarantineCustodyV1, BaseQuarantineErrorV1> {
    retain_synthetic_orphan_with_fault_probe_v1(
        connection,
        input,
        &QuarantineFaultProbeV1::disabled_v1(),
    )
}

#[cfg(test)]
#[allow(dead_code)] // Consumed by the source-included T074 process driver.
pub(crate) fn retain_synthetic_orphan_with_fault_probe_v1(
    connection: &mut Connection,
    input: &SyntheticOrphanInputV1,
    fault_probe: &QuarantineFaultProbeV1,
) -> Result<BaseQuarantineCustodyV1, BaseQuarantineErrorV1> {
    retain_base_quarantine_with_fault_probe_v1(
        connection,
        &BaseQuarantineInputV1 {
            attempt_id: input.attempt_id,
            operation_binding_digest: input.operation_binding_digest,
            reason: BaseQuarantineReasonV1::OrphanMaterial,
            recovery_manifest_digest: Some(input.recovery_manifest_digest),
        },
        fault_probe,
    )
}

pub(crate) struct OrphanRetirementAuthorizationInputV1 {
    pub(crate) quarantine_id: Sha256Digest,
    pub(crate) retirement_id: Sha256Digest,
    pub(crate) no_reference_digest: Sha256Digest,
}

impl fmt::Debug for OrphanRetirementAuthorizationInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrphanRetirementAuthorizationInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrphanRetirementAuthorizationOutcomeV1 {
    AuthorizedPending,
    AlreadyAuthorized,
    ReferencePresent,
}

struct ActiveOrphanV1 {
    attempt_id: Vec<u8>,
    manifest_digest: Vec<u8>,
}

/// Commits the permanent true-orphan retirement authorization only after one healthy,
/// writer-excluded view proves that no durable reference exists.
pub(crate) fn authorize_orphan_retirement_v1(
    connection: &mut Connection,
    input: &OrphanRetirementAuthorizationInputV1,
) -> Result<OrphanRetirementAuthorizationOutcomeV1, BaseQuarantineErrorV1> {
    authorize_orphan_retirement_with_fault_probe_v1(
        connection,
        input,
        &QuarantineFaultProbeV1::disabled_v1(),
    )
}

#[cfg(feature = "test-fault-injection")]
#[allow(dead_code)] // Consumed by the source-included T074 process driver.
pub(crate) fn authorize_orphan_retirement_with_fault_probe_v1(
    connection: &mut Connection,
    input: &OrphanRetirementAuthorizationInputV1,
    fault_probe: &QuarantineFaultProbeV1,
) -> Result<OrphanRetirementAuthorizationOutcomeV1, BaseQuarantineErrorV1> {
    authorize_orphan_retirement_internal_v1(connection, input, fault_probe)
}

#[cfg(not(feature = "test-fault-injection"))]
fn authorize_orphan_retirement_with_fault_probe_v1(
    connection: &mut Connection,
    input: &OrphanRetirementAuthorizationInputV1,
    fault_probe: &QuarantineFaultProbeV1,
) -> Result<OrphanRetirementAuthorizationOutcomeV1, BaseQuarantineErrorV1> {
    authorize_orphan_retirement_internal_v1(connection, input, fault_probe)
}

fn authorize_orphan_retirement_internal_v1(
    connection: &mut Connection,
    input: &OrphanRetirementAuthorizationInputV1,
    fault_probe: &QuarantineFaultProbeV1,
) -> Result<OrphanRetirementAuthorizationOutcomeV1, BaseQuarantineErrorV1> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_store_error(&error))?;
    let existing = transaction
        .query_row(
            "SELECT attempt_id, recovery_manifest_digest, quarantine_reason, \
                    quarantine_status, orphan_resolution_evidence_digest, \
                    orphan_retirement_id, orphan_retirement_state \
             FROM preparation_quarantines WHERE quarantine_id = ?1",
            [input.quarantine_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_store_error(&error))?
        .ok_or(BaseQuarantineErrorV1::Conflict)?;
    if existing.2 != "ORPHAN_MATERIAL" {
        return rollback_authorization_v1(transaction, Err(BaseQuarantineErrorV1::Conflict));
    }
    if existing.3 == "RESOLVED_TOMBSTONE" {
        let exact = existing.4.as_deref() == Some(input.no_reference_digest.as_bytes().as_slice())
            && existing.5.as_deref() == Some(input.retirement_id.as_bytes().as_slice())
            && matches!(
                existing.6.as_deref(),
                Some("RETIREMENT_PENDING" | "RETIRED_TOMBSTONE")
            );
        let outcome = if exact {
            Ok(OrphanRetirementAuthorizationOutcomeV1::AlreadyAuthorized)
        } else {
            Err(BaseQuarantineErrorV1::Conflict)
        };
        return rollback_authorization_v1(transaction, outcome);
    }
    let (Some(attempt_id), Some(manifest_digest)) = (existing.0, existing.1) else {
        return rollback_authorization_v1(transaction, Err(BaseQuarantineErrorV1::Unhealthy));
    };
    if existing.3 != "ACTIVE" || attempt_id.len() != 32 || manifest_digest.len() != 32 {
        return rollback_authorization_v1(transaction, Err(BaseQuarantineErrorV1::Unhealthy));
    }
    let active = ActiveOrphanV1 {
        attempt_id,
        manifest_digest,
    };
    if !definitive_no_reference_v1(&transaction, input.quarantine_id, &active)? {
        return rollback_authorization_v1(
            transaction,
            Ok(OrphanRetirementAuthorizationOutcomeV1::ReferencePresent),
        );
    }
    reach_true_orphan_definitive_proof(fault_probe);

    let (store_generation, quarantine_generation): (i64, i64) = transaction
        .query_row(
            "SELECT store_generation, quarantine_generation \
             FROM coordinator_store_meta \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| map_store_error(&error))?;
    let store_generation = decode_generation(store_generation)?;
    let quarantine_generation = decode_generation(quarantine_generation)?;
    let next = store_generation
        .checked_add(1)
        .filter(|generation| *generation <= MAX_SAFE_U64 && *generation > quarantine_generation)
        .ok_or(BaseQuarantineErrorV1::GenerationExhausted)?;
    let updated = transaction
        .execute(
            "UPDATE preparation_quarantines SET \
                 quarantine_status = 'RESOLVED_TOMBSTONE', resolved_generation = ?1, \
                 orphan_resolution_evidence_digest = ?2, orphan_retirement_id = ?3, \
                 orphan_retirement_state = 'RETIREMENT_PENDING' \
             WHERE quarantine_id = ?4 AND quarantine_reason = 'ORPHAN_MATERIAL' \
               AND quarantine_status = 'ACTIVE'",
            params![
                i64::try_from(next).map_err(|_| BaseQuarantineErrorV1::GenerationExhausted)?,
                input.no_reference_digest.as_bytes().as_slice(),
                input.retirement_id.as_bytes().as_slice(),
                input.quarantine_id.as_bytes().as_slice(),
            ],
        )
        .map_err(|error| map_insert_error(&error))?;
    if updated != 1 {
        return rollback_authorization_v1(transaction, Err(BaseQuarantineErrorV1::Conflict));
    }
    reach_quarantine_resolved(fault_probe);
    let metadata = transaction
        .execute(
            "UPDATE coordinator_store_meta SET \
                 store_generation = ?1, quarantine_generation = ?1 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND store_generation = ?2 AND quarantine_generation = ?3",
            params![
                i64::try_from(next).map_err(|_| BaseQuarantineErrorV1::GenerationExhausted)?,
                i64::try_from(store_generation)
                    .map_err(|_| BaseQuarantineErrorV1::GenerationExhausted)?,
                i64::try_from(quarantine_generation)
                    .map_err(|_| BaseQuarantineErrorV1::GenerationExhausted)?,
            ],
        )
        .map_err(|error| map_store_error(&error))?;
    if metadata != 1 {
        return rollback_authorization_v1(transaction, Err(BaseQuarantineErrorV1::Unhealthy));
    }
    transaction
        .commit()
        .map_err(|error| map_store_error(&error))?;
    reach_orphan_retirement_pending(fault_probe);
    Ok(OrphanRetirementAuthorizationOutcomeV1::AuthorizedPending)
}

fn definitive_no_reference_v1(
    connection: &Connection,
    quarantine_id: Sha256Digest,
    orphan: &ActiveOrphanV1,
) -> Result<bool, BaseQuarantineErrorV1> {
    connection
        .query_row(
            "SELECT \
                 NOT EXISTS (SELECT 1 FROM prepared_operations WHERE attempt_id = ?1) \
             AND NOT EXISTS (SELECT 1 FROM budget_reservations WHERE attempt_id = ?1) \
             AND NOT EXISTS ( \
                 SELECT 1 FROM preparation_events AS event \
                 JOIN prepared_operations AS operation \
                   ON operation.operation_id = event.operation_id \
                 WHERE operation.attempt_id = ?1 \
             ) \
             AND NOT EXISTS ( \
                 SELECT 1 FROM preparation_quarantines \
                 WHERE quarantine_id <> ?2 AND quarantine_status = 'ACTIVE' \
                   AND (attempt_id = ?1 OR recovery_manifest_digest = ?3) \
             )",
            params![
                orphan.attempt_id,
                quarantine_id.as_bytes().as_slice(),
                orphan.manifest_digest,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| map_store_error(&error))
}

fn rollback_authorization_v1(
    transaction: rusqlite::Transaction<'_>,
    outcome: Result<OrphanRetirementAuthorizationOutcomeV1, BaseQuarantineErrorV1>,
) -> Result<OrphanRetirementAuthorizationOutcomeV1, BaseQuarantineErrorV1> {
    transaction
        .rollback()
        .map_err(|error| map_store_error(&error))?;
    outcome
}

struct ExistingBaseQuarantineV1 {
    quarantine_id: Vec<u8>,
    operation_binding_digest: Vec<u8>,
    reason: String,
    status: String,
    created_generation: i64,
    recovery_manifest_digest: Option<Vec<u8>>,
}

fn read_by_attempt(
    connection: &Connection,
    attempt_id: Sha256Digest,
) -> Result<Vec<ExistingBaseQuarantineV1>, BaseQuarantineErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT quarantine_id, operation_binding_digest, quarantine_reason,
                    quarantine_status, created_generation, recovery_manifest_digest
             FROM preparation_quarantines
             WHERE attempt_id = ?1
             ORDER BY created_generation
             LIMIT 2",
        )
        .map_err(|error| map_store_error(&error))?;
    let rows = statement
        .query_map([attempt_id.as_bytes().as_slice()], |row| {
            Ok(ExistingBaseQuarantineV1 {
                quarantine_id: row.get(0)?,
                operation_binding_digest: row.get(1)?,
                reason: row.get(2)?,
                status: row.get(3)?,
                created_generation: row.get(4)?,
                recovery_manifest_digest: row.get(5)?,
            })
        })
        .map_err(|error| map_store_error(&error))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_store_error(&error))
}

fn classify_existing(
    existing: &[ExistingBaseQuarantineV1],
    input: &BaseQuarantineInputV1,
) -> Result<BaseQuarantineCustodyV1, BaseQuarantineErrorV1> {
    let [existing] = existing else {
        return Err(BaseQuarantineErrorV1::Conflict);
    };
    if existing.quarantine_id.len() != 32
        || existing.operation_binding_digest.len() != 32
        || existing
            .recovery_manifest_digest
            .as_ref()
            .is_some_and(|digest| digest.len() != 32)
        || !matches!(existing.status.as_str(), "ACTIVE" | "RESOLVED_TOMBSTONE")
        || !is_closed_reason(&existing.reason)
    {
        return Err(BaseQuarantineErrorV1::Unhealthy);
    }
    if existing.reason != input.reason.persisted()
        || existing.operation_binding_digest.as_slice() != input.operation_binding_digest.as_bytes()
        || existing.recovery_manifest_digest.as_deref()
            != input
                .recovery_manifest_digest
                .as_ref()
                .map(Sha256Digest::as_bytes)
                .map(<[u8; 32]>::as_slice)
    {
        return Err(BaseQuarantineErrorV1::Conflict);
    }
    Ok(BaseQuarantineCustodyV1 {
        quarantine_id: Sha256Digest::from_bytes(
            existing
                .quarantine_id
                .as_slice()
                .try_into()
                .map_err(|_| BaseQuarantineErrorV1::Unhealthy)?,
        ),
        created_generation: decode_generation(existing.created_generation)?,
    })
}

fn is_closed_reason(reason: &str) -> bool {
    matches!(
        reason,
        "AMBIGUOUS_COMMIT"
            | "ORPHAN_MATERIAL"
            | "RESTORED_OLD_AUTHORITY"
            | "INVARIANT_CONFLICT"
            | "STORE_UNHEALTHY"
    )
}

fn generate_quarantine_id() -> Result<Sha256Digest, BaseQuarantineErrorV1> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|_| BaseQuarantineErrorV1::Unavailable)?;
    let mut preimage = Vec::with_capacity(QUARANTINE_ID_DOMAIN_V1.len() + random.len());
    preimage.extend_from_slice(QUARANTINE_ID_DOMAIN_V1);
    preimage.extend_from_slice(&random);
    let digest = Sha256Digest::digest(&preimage);
    random.fill(0);
    preimage.fill(0);
    Ok(digest)
}

fn decode_generation(value: i64) -> Result<u64, BaseQuarantineErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(BaseQuarantineErrorV1::Unhealthy)
}

fn map_insert_error(error: &SqliteError) -> BaseQuarantineErrorV1 {
    match error {
        SqliteError::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
                && matches!(
                    failure.extended_code,
                    rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                        | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                        | rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER
                ) =>
        {
            BaseQuarantineErrorV1::Conflict
        }
        SqliteError::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            BaseQuarantineErrorV1::Unhealthy
        }
        _ => map_store_error(error),
    }
}

fn map_store_error(error: &SqliteError) -> BaseQuarantineErrorV1 {
    match error {
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase | ErrorCode::SchemaChanged
            ) =>
        {
            BaseQuarantineErrorV1::Unhealthy
        }
        SqliteError::InvalidColumnType(..)
        | SqliteError::FromSqlConversionFailure(..)
        | SqliteError::QueryReturnedNoRows => BaseQuarantineErrorV1::Unhealthy,
        _ => BaseQuarantineErrorV1::Unavailable,
    }
}

#[inline]
fn reach_quarantine_inserted(fault_probe: &QuarantineFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe
        .reach_v1(crate::test_fault::FaultBoundaryV1::QuarantineAndRetirementQuarantineInserted);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_true_orphan_definitive_proof(fault_probe: &QuarantineFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::QuarantineAndRetirementTrueOrphanDefinitiveProofReturned,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_quarantine_resolved(fault_probe: &QuarantineFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe
        .reach_v1(crate::test_fault::FaultBoundaryV1::QuarantineAndRetirementQuarantineResolved);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_orphan_retirement_pending(fault_probe: &QuarantineFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        crate::test_fault::FaultBoundaryV1::QuarantineAndRetirementOrphanResolutionRetirementPendingTombstoneCommitted,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prepare::{
        commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1,
        SyntheticCommitModeV1, SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
    };
    use helix_plan_preparation::PreparationCommitOutcomeV1;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("database opens");
        initialize_schema(&connection);
        connection
    }

    fn initialize_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE coordinator_store_meta (
                     singleton INTEGER PRIMARY KEY, store_generation INTEGER NOT NULL,
                     quarantine_generation INTEGER NOT NULL,
                     root_lifecycle_state TEXT NOT NULL,
                     restore_identity_digest BLOB,
                     restore_attestation_digest BLOB,
                     restore_state_generation INTEGER NOT NULL
                 );
                 INSERT INTO coordinator_store_meta VALUES (
                     1, 0, 0, 'ACTIVE', NULL, NULL, 0
                 );
                 CREATE TABLE prepared_operations (operation_id TEXT PRIMARY KEY);
                 CREATE TABLE preparation_quarantines (
                     quarantine_id BLOB PRIMARY KEY, attempt_id BLOB,
                     operation_binding_digest BLOB NOT NULL, quarantine_reason TEXT NOT NULL,
                     quarantine_status TEXT NOT NULL, created_generation INTEGER NOT NULL,
                     resolved_generation INTEGER, recovery_manifest_digest BLOB,
                     orphan_resolution_evidence_digest BLOB, orphan_retirement_id BLOB,
                     orphan_retirement_state TEXT, orphan_retired_generation INTEGER,
                     orphan_retirement_manifest_digest BLOB
                 );",
            )
            .expect("schema creates");
    }

    fn restore_pending_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("pending database opens");
        connection
            .execute_batch(
                "CREATE TABLE coordinator_store_meta (
                     singleton INTEGER PRIMARY KEY,
                     store_generation INTEGER NOT NULL,
                     quarantine_generation INTEGER NOT NULL,
                     root_lifecycle_state TEXT NOT NULL,
                     restore_identity_digest BLOB,
                     restore_attestation_digest BLOB,
                     restore_state_generation INTEGER NOT NULL
                 );
                 INSERT INTO coordinator_store_meta VALUES (
                     1, 5, 0, 'RESTORE_PENDING',
                     x'5151515151515151515151515151515151515151515151515151515151515151',
                     x'5252525252525252525252525252525252525252525252525252525252525252',
                     5
                 );
                 CREATE TABLE prepared_operations (
                     operation_id TEXT PRIMARY KEY,
                     attempt_id BLOB NOT NULL,
                     operation_state TEXT NOT NULL,
                     state_generation INTEGER NOT NULL,
                     boot_id TEXT NOT NULL,
                     instance_epoch INTEGER NOT NULL,
                     fencing_epoch INTEGER NOT NULL,
                     restored_source_generation INTEGER
                 );
                 INSERT INTO prepared_operations VALUES (
                     'operation:restored',
                     x'1111111111111111111111111111111111111111111111111111111111111111',
                     'PREPARING', 3, 'boot:old', 7, 9, 4
                 );
                 CREATE TABLE budget_scopes (
                     held_cost_micro_units INTEGER NOT NULL,
                     held_action_count INTEGER NOT NULL,
                     held_egress_bytes INTEGER NOT NULL,
                     held_recovery_bytes INTEGER NOT NULL
                 );
                 INSERT INTO budget_scopes VALUES (11, 12, 13, 14);
                 CREATE TABLE budget_reservations (
                     attempt_id BLOB NOT NULL,
                     reservation_state TEXT NOT NULL,
                     released_generation INTEGER
                 );
                 INSERT INTO budget_reservations VALUES (
                     x'1111111111111111111111111111111111111111111111111111111111111111',
                     'HELD', NULL
                 );
                 CREATE TABLE preparation_quarantines (
                     quarantine_id BLOB PRIMARY KEY, attempt_id BLOB,
                     operation_binding_digest BLOB NOT NULL, quarantine_reason TEXT NOT NULL,
                     quarantine_status TEXT NOT NULL, created_generation INTEGER NOT NULL,
                     resolved_generation INTEGER, recovery_manifest_digest BLOB,
                     orphan_resolution_evidence_digest BLOB, orphan_retirement_id BLOB,
                     orphan_retirement_state TEXT, orphan_retired_generation INTEGER,
                     orphan_retirement_manifest_digest BLOB
                 );",
            )
            .expect("pending schema creates");
        connection
    }

    fn restored_input() -> RestoredOldAuthorityQuarantineInputV1<'static> {
        RestoredOldAuthorityQuarantineInputV1 {
            operation_id: "operation:restored",
            attempt_id: digest(0x11),
            operation_binding_digest: digest(0x31),
            preparing_state_generation: 3,
            old_boot_id: "boot:old",
            old_instance_epoch: 7,
            old_fencing_epoch: 9,
            restored_source_generation: 4,
            restore_identity_digest: digest(0x51),
            restore_attestation_digest: digest(0x52),
            restore_state_generation: 5,
            rotation: rotation("boot:old", 7, 9),
        }
    }

    fn rotation(
        old_boot_id: &str,
        old_instance_epoch: u64,
        old_fencing_epoch: u64,
    ) -> RestoredAuthorityRotationV1 {
        RestoredAuthorityRotationV1::for_test_v1(old_boot_id, old_instance_epoch, old_fencing_epoch)
    }

    struct TempDatabaseV1 {
        path: PathBuf,
    }

    impl TempDatabaseV1 {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).expect("test randomness is available");
            let name = format!(
                "helix-t035-quarantine-{}-{:016x}.sqlite3",
                std::process::id(),
                u64::from_le_bytes(random)
            );
            let temporary_root = std::fs::canonicalize(std::env::temp_dir())
                .expect("temporary root canonicalizes for SQLITE_OPEN_NOFOLLOW");
            Self {
                path: temporary_root.join(name),
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDatabaseV1 {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let mut path = OsString::from(self.path.as_os_str());
                path.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(path));
            }
        }
    }

    #[test]
    fn base_custody_is_idempotent_and_never_fabricates_an_operation() {
        let mut connection = connection();
        let input = BaseQuarantineInputV1 {
            attempt_id: digest(1),
            operation_binding_digest: digest(2),
            reason: BaseQuarantineReasonV1::AmbiguousCommit,
            recovery_manifest_digest: None,
        };
        let first = retain_base_quarantine_v1(&mut connection, &input).expect("custody inserts");
        let repeat = retain_base_quarantine_v1(&mut connection, &input).expect("repeat reads");
        assert_eq!(first.quarantine_id(), repeat.quarantine_id());
        assert_eq!(first.created_generation(), 1);
        assert_eq!(repeat.created_generation(), 1);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count reads"),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM prepared_operations", [], |row| row
                    .get::<_, i64>(0))
                .expect("operation count reads"),
            0
        );
    }

    #[test]
    fn transaction_helper_leaves_commit_and_rollback_to_the_caller() {
        let mut connection = connection();
        let input = BaseQuarantineInputV1 {
            attempt_id: digest(3),
            operation_binding_digest: digest(4),
            reason: BaseQuarantineReasonV1::OrphanMaterial,
            recovery_manifest_digest: Some(digest(5)),
        };

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("caller transaction starts");
        let first = retain_base_quarantine_in_transaction_v1(&transaction, &input)
            .expect("helper inserts without closing the transaction");
        let first = match first {
            BaseQuarantineTransactionOutcomeV1::Inserted(custody) => custody,
            BaseQuarantineTransactionOutcomeV1::Existing(_) => {
                panic!("first retention must insert")
            }
        };
        assert_eq!(first.created_generation(), 1);
        assert_eq!(
            transaction
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("transaction observes its insert"),
            1
        );
        transaction.rollback().expect("caller rolls back");
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("rollback is visible"),
            0
        );

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("second caller transaction starts");
        let inserted = retain_base_quarantine_in_transaction_v1(&transaction, &input)
            .expect("helper inserts again after rollback");
        let inserted = match inserted {
            BaseQuarantineTransactionOutcomeV1::Inserted(custody) => custody,
            BaseQuarantineTransactionOutcomeV1::Existing(_) => {
                panic!("rolled-back retention must not exist")
            }
        };
        transaction.commit().expect("caller commits");

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("repeat caller transaction starts");
        let repeat = retain_base_quarantine_in_transaction_v1(&transaction, &input)
            .expect("helper classifies the exact repeat");
        let repeat = match repeat {
            BaseQuarantineTransactionOutcomeV1::Existing(custody) => custody,
            BaseQuarantineTransactionOutcomeV1::Inserted(_) => {
                panic!("exact repeat must not insert")
            }
        };
        assert_eq!(repeat.quarantine_id(), inserted.quarantine_id());
        assert_eq!(repeat.created_generation(), inserted.created_generation());
        transaction
            .rollback()
            .expect("caller rolls back read-only repeat");
    }

    #[test]
    fn exact_repeat_returns_the_same_permanent_resolved_tombstone() {
        let mut connection = connection();
        let input = BaseQuarantineInputV1 {
            attempt_id: digest(11),
            operation_binding_digest: digest(12),
            reason: BaseQuarantineReasonV1::AmbiguousCommit,
            recovery_manifest_digest: None,
        };
        let inserted = retain_base_quarantine_v1(&mut connection, &input).expect("row inserts");
        connection
            .execute(
                "UPDATE preparation_quarantines
                 SET quarantine_status = 'RESOLVED_TOMBSTONE', resolved_generation = 2
                 WHERE quarantine_id = ?1",
                [inserted.quarantine_id().as_bytes().as_slice()],
            )
            .expect("test row resolves");
        connection
            .execute(
                "UPDATE coordinator_store_meta
                 SET store_generation = 2, quarantine_generation = 2
                 WHERE singleton = 1",
                [],
            )
            .expect("test metadata advances");

        let repeat = retain_base_quarantine_v1(&mut connection, &input)
            .expect("resolved exact history remains idempotent");
        assert_eq!(repeat.quarantine_id(), inserted.quarantine_id());
        assert_eq!(repeat.created_generation(), inserted.created_generation());
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("history count reads"),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT store_generation, quarantine_generation
                     FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| Ok([row.get::<_, i64>(0)?, row.get::<_, i64>(1)?]),
                )
                .expect("metadata reads"),
            [2, 2]
        );

        let conflicting = BaseQuarantineInputV1 {
            attempt_id: input.attempt_id,
            operation_binding_digest: digest(13),
            reason: input.reason,
            recovery_manifest_digest: None,
        };
        assert!(matches!(
            retain_base_quarantine_v1(&mut connection, &conflicting),
            Err(BaseQuarantineErrorV1::Conflict)
        ));
    }

    #[test]
    fn concurrent_exact_repeats_serialize_before_the_identity_read() {
        let database = TempDatabaseV1::new();
        let mut blocker = Connection::open(database.path()).expect("file database opens");
        blocker
            .execute_batch("PRAGMA journal_mode = WAL;")
            .expect("WAL enables");
        initialize_schema(&blocker);
        let blocker_transaction = blocker
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("writer exclusion starts");

        let start = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let path = database.path().to_path_buf();
            let start = Arc::clone(&start);
            workers.push(std::thread::spawn(move || {
                let mut connection = Connection::open(path).expect("worker database opens");
                connection
                    .busy_timeout(Duration::from_secs(5))
                    .expect("bounded worker timeout configures");
                start.wait();
                retain_base_quarantine_v1(
                    &mut connection,
                    &BaseQuarantineInputV1 {
                        attempt_id: digest(21),
                        operation_binding_digest: digest(22),
                        reason: BaseQuarantineReasonV1::AmbiguousCommit,
                        recovery_manifest_digest: None,
                    },
                )
            }));
        }
        start.wait();
        std::thread::sleep(Duration::from_millis(100));
        blocker_transaction
            .commit()
            .expect("writer exclusion releases");

        let first = workers
            .remove(0)
            .join()
            .expect("first worker joins")
            .expect("first exact repeat succeeds");
        let second = workers
            .remove(0)
            .join()
            .expect("second worker joins")
            .expect("second exact repeat succeeds");
        assert_eq!(first.quarantine_id(), second.quarantine_id());
        assert_eq!(first.created_generation(), 1);
        assert_eq!(second.created_generation(), 1);

        drop(blocker);
        let verification = Connection::open(database.path()).expect("database reopens");
        assert_eq!(
            verification
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("quarantine count reads"),
            1
        );
    }

    #[test]
    fn only_constraint_failures_map_to_binding_conflict() {
        let constraint = SqliteError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE),
            None,
        );
        let check = SqliteError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_CHECK),
            None,
        );
        let io = SqliteError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
            None,
        );
        assert_eq!(
            map_insert_error(&constraint),
            BaseQuarantineErrorV1::Conflict
        );
        assert_eq!(map_insert_error(&check), BaseQuarantineErrorV1::Unhealthy);
        assert_eq!(map_insert_error(&io), BaseQuarantineErrorV1::Unavailable);
    }

    #[test]
    fn every_negative_guard_class_retains_one_restore_pending_quarantine_without_release() {
        let failures = [
            RestoredOldAuthorityGuardFailureV1::Missing,
            RestoredOldAuthorityGuardFailureV1::Mismatched,
            RestoredOldAuthorityGuardFailureV1::Revoked,
            RestoredOldAuthorityGuardFailureV1::DeadlineReached,
            RestoredOldAuthorityGuardFailureV1::Unavailable,
            RestoredOldAuthorityGuardFailureV1::Ambiguous,
        ];
        for failure in failures {
            let mut connection = restore_pending_connection();
            let first = retain_restored_old_authority_quarantine_for_test_v1(
                &mut connection,
                &restored_input(),
                failure,
                &mut |_| true,
            )
            .expect("negative guard durably quarantines");
            let RestoredOldAuthorityQuarantineOutcomeV1::Retained(first) = first else {
                panic!("PREPARING must retain quarantine")
            };
            let repeat = retain_restored_old_authority_quarantine_for_test_v1(
                &mut connection,
                &restored_input(),
                failure,
                &mut |_| true,
            )
            .expect("exact repeat is idempotent");
            let RestoredOldAuthorityQuarantineOutcomeV1::Retained(repeat) = repeat else {
                panic!("repeat must retain quarantine")
            };
            assert_eq!(first.quarantine_id(), repeat.quarantine_id());
            assert_eq!(first.created_generation(), 6);
            assert_eq!(repeat.created_generation(), 6);

            let metadata = connection
                .query_row(
                    "SELECT store_generation, quarantine_generation, root_lifecycle_state,
                            restore_identity_digest, restore_attestation_digest,
                            restore_state_generation
                     FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
                .expect("pending metadata reads");
            assert_eq!(metadata.0, 6);
            assert_eq!(metadata.1, 6);
            assert_eq!(metadata.2, "RESTORE_PENDING");
            assert_eq!(metadata.3.as_slice(), digest(0x51).as_bytes());
            assert_eq!(metadata.4.as_slice(), digest(0x52).as_bytes());
            assert_eq!(metadata.5, 5);
            assert_eq!(
                connection
                    .query_row(
                        "SELECT operation_state, state_generation, boot_id,
                                instance_epoch, fencing_epoch, restored_source_generation
                         FROM prepared_operations",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, i64>(4)?,
                                row.get::<_, i64>(5)?,
                            ))
                        },
                    )
                    .expect("old operation reads"),
                ("PREPARING".to_owned(), 3, "boot:old".to_owned(), 7, 9, 4),
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT reservation_state, released_generation
                         FROM budget_reservations",
                        [],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?)),
                    )
                    .expect("reservation reads"),
                ("HELD".to_owned(), None),
            );
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("quarantine count reads"),
                1,
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT quarantine_reason FROM preparation_quarantines",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .expect("reason reads"),
                "RESTORED_OLD_AUTHORITY",
            );
        }
    }

    #[test]
    fn restored_authority_diagnostics_are_payload_free_and_active_base_path_refuses_reason() {
        let input = restored_input();
        let debug = format!("{input:?}");
        let private = [
            input.operation_id.to_owned(),
            input.old_boot_id.to_owned(),
            input.attempt_id.to_hex(),
            input.restore_identity_digest.to_hex(),
        ];
        for value in private {
            assert!(!debug.contains(&value));
        }
        assert_eq!(
            format!("{:?}", RestoredOldAuthorityGuardFailureV1::Ambiguous),
            "Ambiguous"
        );

        let mut active = connection();
        assert!(matches!(
            retain_base_quarantine_v1(
                &mut active,
                &BaseQuarantineInputV1 {
                    attempt_id: digest(0x11),
                    operation_binding_digest: digest(0x31),
                    reason: BaseQuarantineReasonV1::RestoredOldAuthority,
                    recovery_manifest_digest: None,
                },
            ),
            Err(BaseQuarantineErrorV1::InvalidInput)
        ));
    }

    #[test]
    fn ordinary_quarantine_path_refuses_restore_pending_without_mutation() {
        let mut pending = restore_pending_connection();
        let before: (i64, i64, i64) = pending
            .query_row(
                "SELECT store_generation, quarantine_generation,
                        (SELECT COUNT(*) FROM preparation_quarantines)
                 FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("pending baseline reads");
        assert_eq!(
            retain_base_quarantine_v1(
                &mut pending,
                &BaseQuarantineInputV1 {
                    attempt_id: digest(0x81),
                    operation_binding_digest: digest(0x82),
                    reason: BaseQuarantineReasonV1::AmbiguousCommit,
                    recovery_manifest_digest: None,
                },
            )
            .unwrap_err(),
            BaseQuarantineErrorV1::Conflict
        );
        let after: (i64, i64, i64) = pending
            .query_row(
                "SELECT store_generation, quarantine_generation,
                        (SELECT COUNT(*) FROM preparation_quarantines)
                 FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("pending refusal reads");
        assert_eq!(after, before);
    }

    #[test]
    fn reviewed_schema_accepts_the_structural_pending_cas_without_budget_release() {
        const STORE_SCHEMA: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
        ));
        let database = TempDatabaseV1::new();
        let connection = Connection::open(database.path()).expect("database creates");
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

        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Irreversible);
        provision_synthetic_budget_scope_v1(database.path(), &case)
            .expect("synthetic scope provisions");
        assert!(matches!(
            commit_synthetic_preparation_v1(
                database.path(),
                &case,
                SyntheticCommitModeV1::Acknowledged,
            ),
            PreparationCommitOutcomeV1::Committed(_)
        ));

        let connection = Connection::open(database.path()).expect("database reopens");
        let operation = connection
            .query_row(
                "SELECT operation_id, attempt_id, state_generation, boot_id,
                        instance_epoch, fencing_epoch
                 FROM prepared_operations WHERE operation_state = 'PREPARING'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .expect("prepared operation reads");
        let source_generation = connection
            .query_row(
                "SELECT store_generation FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("source generation reads");
        connection
            .execute(
                "UPDATE prepared_operations SET restored_source_generation = ?1
                 WHERE operation_id = ?2",
                params![source_generation, operation.0],
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
                    restore_state_generation,
                    [0x42_u8; 32].as_slice(),
                    [0x51_u8; 32].as_slice(),
                    [0x52_u8; 32].as_slice(),
                    source_generation,
                ],
            )
            .expect("one-way pending transition commits");
        drop(connection);

        let attempt = Sha256Digest::from_bytes(
            operation
                .1
                .try_into()
                .expect("stored attempt has fixed digest length"),
        );
        let input = RestoredOldAuthorityQuarantineInputV1 {
            operation_id: &operation.0,
            attempt_id: attempt,
            operation_binding_digest: digest(0x31),
            preparing_state_generation: operation.2 as u64,
            old_boot_id: &operation.3,
            old_instance_epoch: operation.4 as u64,
            old_fencing_epoch: operation.5 as u64,
            restored_source_generation: source_generation as u64,
            restore_identity_digest: digest(0x51),
            restore_attestation_digest: digest(0x52),
            restore_state_generation: restore_state_generation as u64,
            rotation: rotation(&operation.3, operation.4 as u64, operation.5 as u64),
        };
        let mut connection = Connection::open(database.path()).expect("database reopens");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("foreign keys enable");
        let outcome = retain_restored_old_authority_quarantine_for_test_v1(
            &mut connection,
            &input,
            RestoredOldAuthorityGuardFailureV1::Ambiguous,
            &mut |_| true,
        )
        .expect("reviewed schema accepts quarantine CAS");
        assert!(matches!(
            outcome,
            RestoredOldAuthorityQuarantineOutcomeV1::Retained(_)
        ));
        assert_eq!(
            connection
                .query_row(
                    "SELECT root_lifecycle_state FROM coordinator_store_meta",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("root lifecycle reads"),
            "RESTORE_PENDING",
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT reservation_state FROM budget_reservations WHERE attempt_id = ?1",
                    [attempt.as_bytes().as_slice()],
                    |row| row.get::<_, String>(0),
                )
                .expect("reservation reads"),
            "HELD",
        );
    }

    #[test]
    fn restore_pending_quarantine_refuses_wrong_root_cas_and_mismatched_rotation_token() {
        let mut connection = restore_pending_connection();
        let before = connection
            .query_row(
                "SELECT store_generation, quarantine_generation, root_lifecycle_state
                 FROM coordinator_store_meta",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("metadata reads");
        let mut wrong_root = restored_input();
        wrong_root.restore_identity_digest = digest(0x99);
        assert!(matches!(
            retain_restored_old_authority_quarantine_for_test_v1(
                &mut connection,
                &wrong_root,
                RestoredOldAuthorityGuardFailureV1::Missing,
                &mut |_| true,
            ),
            Err(BaseQuarantineErrorV1::Conflict)
        ));

        let mut wrong_boot_rotation = restored_input();
        wrong_boot_rotation.rotation = rotation("boot:other", 7, 9);
        assert!(matches!(
            retain_restored_old_authority_quarantine_for_test_v1(
                &mut connection,
                &wrong_boot_rotation,
                RestoredOldAuthorityGuardFailureV1::Ambiguous,
                &mut |_| true,
            ),
            Err(BaseQuarantineErrorV1::InvalidInput)
        ));

        let mut wrong_epoch_rotation = restored_input();
        wrong_epoch_rotation.rotation = rotation("boot:old", 8, 9);
        assert!(matches!(
            retain_restored_old_authority_quarantine_for_test_v1(
                &mut connection,
                &wrong_epoch_rotation,
                RestoredOldAuthorityGuardFailureV1::Ambiguous,
                &mut |_| true,
            ),
            Err(BaseQuarantineErrorV1::InvalidInput)
        ));
        assert_eq!(
            connection
                .query_row(
                    "SELECT store_generation, quarantine_generation, root_lifecycle_state
                     FROM coordinator_store_meta",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .expect("metadata rereads"),
            before,
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("quarantine count reads"),
            0,
        );
    }

    #[test]
    fn pending_verifier_refusal_after_staging_rolls_back_quarantine_and_generation() {
        let mut connection = restore_pending_connection();
        let mut verification_calls = 0_u8;
        let mut verify_pending = |_: &Connection| {
            verification_calls += 1;
            verification_calls == 1
        };
        let outcome = retain_restored_old_authority_quarantine_for_test_v1(
            &mut connection,
            &restored_input(),
            RestoredOldAuthorityGuardFailureV1::Revoked,
            &mut verify_pending,
        )
        .expect_err("post-staging verifier refusal must fail closed");
        assert_eq!(outcome, BaseQuarantineErrorV1::Unhealthy);
        assert_eq!(verification_calls, 2);
        assert_eq!(
            connection
                .query_row(
                    "SELECT store_generation, quarantine_generation,
                            (SELECT COUNT(*) FROM preparation_quarantines)
                     FROM coordinator_store_meta",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .expect("rolled-back metadata reads"),
            (5, 0, 0),
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT operation_state,
                            (SELECT reservation_state FROM budget_reservations)
                     FROM prepared_operations",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .expect("old operation and reservation read"),
            ("PREPARING".to_owned(), "HELD".to_owned()),
        );
    }

    #[test]
    fn partial_failed_row_is_corruption_and_cannot_become_a_second_disposition() {
        let mut connection = restore_pending_connection();
        connection
            .execute(
                "UPDATE prepared_operations
                 SET operation_state = 'FAILED', state_generation = 4",
                [],
            )
            .expect("synthetic terminal writer commits");
        let outcome = retain_restored_old_authority_quarantine_for_test_v1(
            &mut connection,
            &restored_input(),
            RestoredOldAuthorityGuardFailureV1::Revoked,
            // A real full RESTORE_PENDING verification rejects this impossible partial
            // terminal state: no released reservation, transition, event, or generation
            // update accompanies the row flip.
            &mut |_| false,
        )
        .expect_err("partial FAILED state must fail closed");
        assert_eq!(outcome, BaseQuarantineErrorV1::Unhealthy);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("quarantine count reads"),
            0,
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT store_generation, quarantine_generation
                     FROM coordinator_store_meta",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .expect("metadata reads"),
            (5, 0),
        );
    }
}
