//! Coordinator schema identity, initialization, and invariant verification.

use crate::clock::{remaining_monotonic_ms, CoordinatorMonotonicClockV1};
use crate::comparison_digest::{
    persisted_comparison_digests_v1, verify_persisted_comparison_digests_v1,
};
use crate::connection::map_sqlite_error;
use crate::error::InternalCoordinatorError;
use crate::root_safety::CoordinatorRootIdentityV1;
use helix_contracts::{
    decode_and_verify_plan, AtomicityV1, Ed25519KeyResolver, RecoveryClassV1, RiskLevelV1,
    Sha256Digest, MAX_SAFE_U64,
};
use helix_plan_preparation::{
    recovery_boot_binding_digest_v1, recovery_precondition_identity_digest_v1,
    recovery_target_reference_digest_v1, RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
    RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};

pub const COORDINATOR_STORE_APPLICATION_ID_V1: i64 = 1_212_962_883;
pub const COORDINATOR_STORE_SCHEMA_VERSION_V1: i64 = 1;
pub const COORDINATOR_STORE_FORMAT_VERSION_V1: i64 = 1;
pub const COORDINATOR_STORE_SCHEMA_V1_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
));

const COORDINATOR_STORE_SCHEMA_V1_SHA256: [u8; 32] = [
    0xe7, 0xb7, 0xc6, 0xc7, 0x0f, 0x35, 0x6a, 0xfe, 0x4e, 0x45, 0xb3, 0xe2, 0xc7, 0x21, 0x0b, 0x38,
    0xc4, 0xcc, 0xc0, 0xf6, 0x9a, 0x01, 0x2c, 0xbd, 0xad, 0xdd, 0x10, 0x3a, 0x88, 0x27, 0x88, 0x0e,
];

const INITIAL_METADATA_INSERT: &str = "INSERT INTO coordinator_store_meta (\
    singleton, format_version, store_generation, operation_generation, budget_generation, \
    event_generation, quarantine_generation, root_identity, root_lifecycle_state, \
    restore_identity_digest, restore_attestation_digest, restore_state_generation\
) VALUES (1, 1, 0, 0, 0, 0, 0, ?1, 'ACTIVE', NULL, NULL, 0)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StoreSummary {
    pub(crate) schema_cookie: i64,
    pub(crate) operation_count: u64,
    pub(crate) root_identity: CoordinatorRootIdentityV1,
}

/// Exact bounded generation vector carried by a reviewed coordinator backup manifest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoordinatorLifecycleGenerationsV1 {
    store: u64,
    operation: u64,
    budget: u64,
    event: u64,
    quarantine: u64,
}

impl CoordinatorLifecycleGenerationsV1 {
    #[allow(dead_code)] // Constructed from the authenticated manifest by T072 maintenance.
    pub(crate) fn try_new(
        store: u64,
        operation: u64,
        budget: u64,
        event: u64,
        quarantine: u64,
    ) -> Result<Self, InternalCoordinatorError> {
        if [store, operation, budget, event, quarantine]
            .into_iter()
            .any(|generation| generation > MAX_SAFE_U64)
            || [operation, budget, event, quarantine]
                .into_iter()
                .any(|generation| generation > store)
        {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
        Ok(Self {
            store,
            operation,
            budget,
            event,
            quarantine,
        })
    }

    pub(crate) const fn store(self) -> u64 {
        self.store
    }

    pub(crate) const fn operation(self) -> u64 {
        self.operation
    }

    pub(crate) const fn budget(self) -> u64 {
        self.budget
    }

    pub(crate) const fn event(self) -> u64 {
        self.event
    }

    pub(crate) const fn quarantine(self) -> u64 {
        self.quarantine
    }
}

impl std::fmt::Debug for CoordinatorLifecycleGenerationsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoordinatorLifecycleGenerationsV1")
            .finish_non_exhaustive()
    }
}

/// Bounded, non-authoritative counts returned by lifecycle verification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoordinatorLifecycleCountsV1 {
    budget_scopes: u64,
    operations: u64,
    operation_transitions: u64,
    held_reservations: u64,
    released_reservations: u64,
    pending_events: u64,
    delivered_events: u64,
    active_quarantines: u64,
    resolved_quarantines: u64,
}

#[allow(dead_code)] // Read by the bounded T072/T075 maintenance evidence surface.
impl CoordinatorLifecycleCountsV1 {
    pub(crate) const fn budget_scopes(self) -> u64 {
        self.budget_scopes
    }

    pub(crate) const fn operations(self) -> u64 {
        self.operations
    }

    pub(crate) const fn operation_transitions(self) -> u64 {
        self.operation_transitions
    }

    pub(crate) const fn held_reservations(self) -> u64 {
        self.held_reservations
    }

    pub(crate) const fn released_reservations(self) -> u64 {
        self.released_reservations
    }

    pub(crate) const fn pending_events(self) -> u64 {
        self.pending_events
    }

    pub(crate) const fn delivered_events(self) -> u64 {
        self.delivered_events
    }

    pub(crate) const fn active_quarantines(self) -> u64 {
        self.active_quarantines
    }

    pub(crate) const fn resolved_quarantines(self) -> u64 {
        self.resolved_quarantines
    }
}

impl std::fmt::Debug for CoordinatorLifecycleCountsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CoordinatorLifecycleCountsV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // All fields are consumed through typed restore proof accessors.
struct VerifiedCoordinatorLifecycleV1 {
    summary: StoreSummary,
    generations: CoordinatorLifecycleGenerationsV1,
    counts: CoordinatorLifecycleCountsV1,
}

/// Full invariant proof that an imported database is still the exact ACTIVE source cut.
#[derive(Clone, Copy)]
#[allow(dead_code)] // Returned to the T072 maintenance import pipeline.
pub(crate) struct ImportedActiveBackupV1(VerifiedCoordinatorLifecycleV1);

#[allow(dead_code)] // Read by the T072 maintenance import pipeline.
impl ImportedActiveBackupV1 {
    pub(crate) const fn summary(self) -> StoreSummary {
        self.0.summary
    }

    pub(crate) const fn generations(self) -> CoordinatorLifecycleGenerationsV1 {
        self.0.generations
    }

    pub(crate) const fn counts(self) -> CoordinatorLifecycleCountsV1 {
        self.0.counts
    }
}

impl std::fmt::Debug for ImportedActiveBackupV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportedActiveBackupV1")
            .finish_non_exhaustive()
    }
}

/// Exact bindings for the sole coordinator ACTIVE -> RESTORE_PENDING transition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestorePendingBindingsV1 {
    expected_source_generations: CoordinatorLifecycleGenerationsV1,
    new_root_identity: CoordinatorRootIdentityV1,
    restore_identity_digest: Sha256Digest,
    restore_attestation_digest: Sha256Digest,
    restored_source_generation: u64,
}

#[allow(dead_code)] // Constructed and inspected by the T072 maintenance agreement pipeline.
impl RestorePendingBindingsV1 {
    pub(crate) fn try_new(
        expected_source_generations: CoordinatorLifecycleGenerationsV1,
        new_root_identity: CoordinatorRootIdentityV1,
        restore_identity_digest: Sha256Digest,
        restore_attestation_digest: Sha256Digest,
        restored_source_generation: u64,
    ) -> Result<Self, InternalCoordinatorError> {
        if restored_source_generation != expected_source_generations.store()
            || expected_source_generations.store() >= MAX_SAFE_U64
        {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
        Ok(Self {
            expected_source_generations,
            new_root_identity,
            restore_identity_digest,
            restore_attestation_digest,
            restored_source_generation,
        })
    }

    pub(crate) const fn expected_source_generations(self) -> CoordinatorLifecycleGenerationsV1 {
        self.expected_source_generations
    }

    pub(crate) const fn new_root_identity(self) -> CoordinatorRootIdentityV1 {
        self.new_root_identity
    }

    pub(crate) const fn restore_identity_digest(self) -> Sha256Digest {
        self.restore_identity_digest
    }

    pub(crate) const fn restore_attestation_digest(self) -> Sha256Digest {
        self.restore_attestation_digest
    }

    pub(crate) const fn restored_source_generation(self) -> u64 {
        self.restored_source_generation
    }
}

impl std::fmt::Debug for RestorePendingBindingsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestorePendingBindingsV1")
            .finish_non_exhaustive()
    }
}

/// Full invariant proof for one non-activatable coordinator restore root.
#[derive(Clone, Copy)]
#[allow(dead_code)] // Returned to the T072/T075 maintenance evidence pipeline.
pub(crate) struct VerifiedRestorePendingV1(VerifiedCoordinatorLifecycleV1);

#[allow(dead_code)] // Read by the T072/T075 maintenance evidence pipeline.
impl VerifiedRestorePendingV1 {
    pub(crate) const fn summary(self) -> StoreSummary {
        self.0.summary
    }

    pub(crate) const fn generations(self) -> CoordinatorLifecycleGenerationsV1 {
        self.0.generations
    }

    pub(crate) const fn counts(self) -> CoordinatorLifecycleCountsV1 {
        self.0.counts
    }
}

impl std::fmt::Debug for VerifiedRestorePendingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedRestorePendingV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitializationCandidateV1 {
    ExactEmpty,
    CommittedV1,
}

#[derive(Clone, PartialEq, Eq)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootLifecycleV1 {
    Active,
    RestorePending {
        restore_identity_digest: Sha256Digest,
        restore_attestation_digest: Sha256Digest,
        restore_state_generation: u64,
    },
}

#[derive(Clone, Copy)]
struct CoordinatorStoreMetadataRow {
    store_generation: u64,
    operation_generation: u64,
    budget_generation: u64,
    event_generation: u64,
    quarantine_generation: u64,
    root_identity: CoordinatorRootIdentityV1,
    root_lifecycle: RootLifecycleV1,
}

impl CoordinatorStoreMetadataRow {
    const fn generations(self) -> CoordinatorLifecycleGenerationsV1 {
        CoordinatorLifecycleGenerationsV1 {
            store: self.store_generation,
            operation: self.operation_generation,
            budget: self.budget_generation,
            event: self.event_generation,
            quarantine: self.quarantine_generation,
        }
    }
}

#[derive(Clone, Copy)]
enum LifecycleExpectationV1 {
    ActiveBound(CoordinatorRootIdentityV1),
    ImportedActive(CoordinatorLifecycleGenerationsV1),
    RestorePending(RestorePendingBindingsV1),
}

/// SHA-256 of the byte-exact reviewed SQL embedded in this build.
pub fn embedded_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(COORDINATOR_STORE_SCHEMA_V1_SQL.as_bytes()).into()
}

/// Classifies only the two database states an `INITIALIZING` marker may safely resume.
///
/// A partially initialized or foreign database is deliberately not treated as empty: callers
/// must never execute the v1 schema over any file containing unbound persistent state.
pub(crate) fn classify_initialization_candidate(
    connection: &Connection,
) -> Result<InitializationCandidateV1, InternalCoordinatorError> {
    let application_id = pragma_i64(connection, "application_id")?;
    let user_version = pragma_i64(connection, "user_version")?;
    let object_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))?;

    match (application_id, user_version, object_count) {
        (0, 0, 0) => Ok(InitializationCandidateV1::ExactEmpty),
        (COORDINATOR_STORE_APPLICATION_ID_V1, COORDINATOR_STORE_SCHEMA_VERSION_V1, count)
            if count > 0 =>
        {
            Ok(InitializationCandidateV1::CommittedV1)
        }
        (COORDINATOR_STORE_APPLICATION_ID_V1, version, _)
            if version > COORDINATOR_STORE_SCHEMA_VERSION_V1 =>
        {
            Err(InternalCoordinatorError::SchemaUnsupported)
        }
        (0 | COORDINATOR_STORE_APPLICATION_ID_V1, _, _) => {
            Err(InternalCoordinatorError::SchemaInvalid)
        }
        _ => Err(InternalCoordinatorError::ApplicationIdMismatch),
    }
}

pub(crate) fn initialize_empty_to_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    connection: &mut Connection,
    root_identity: CoordinatorRootIdentityV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<(), InternalCoordinatorError> {
    verify_embedded_schema_digest()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))?;

    if classify_initialization_candidate(&transaction)? != InitializationCandidateV1::ExactEmpty {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }

    transaction
        .execute_batch(COORDINATOR_STORE_SCHEMA_V1_SQL)
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))?;
    transaction
        .execute(
            INITIAL_METADATA_INSERT,
            [root_identity.as_bytes().as_slice()],
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))?;
    verify_identity(&transaction)?;
    verify_exact_schema(&transaction)?;
    let metadata = decode_single_metadata_row(&transaction)?;
    if metadata.root_lifecycle != RootLifecycleV1::Active
        || metadata.root_identity != root_identity
        || metadata.store_generation != 0
        || metadata.operation_generation != 0
        || metadata.budget_generation != 0
        || metadata.event_generation != 0
        || metadata.quarantine_generation != 0
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))
}

pub(crate) fn verify_full<R: Ed25519KeyResolver>(
    connection: &Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    historical_plan_keys: &R,
) -> Result<StoreSummary, InternalCoordinatorError> {
    verify_lifecycle_v1(
        connection,
        LifecycleExpectationV1::ActiveBound(expected_root_identity),
        historical_plan_keys,
    )
    .map(|verified| verified.summary)
}

/// Verifies an authenticated SQLite backup before destination-root authority is published.
///
/// Unlike ordinary open, source root identity is historical package evidence rather than
/// destination authority. The exact manifest generations and a still-ACTIVE lifecycle are
/// required, and every restore-only operation field must still be null.
#[allow(dead_code)] // Consumed by the T072 maintenance restore pipeline.
pub(crate) fn verify_imported_active_backup_v1<R: Ed25519KeyResolver>(
    connection: &Connection,
    expected_source_generations: CoordinatorLifecycleGenerationsV1,
    historical_plan_keys: &R,
) -> Result<ImportedActiveBackupV1, InternalCoordinatorError> {
    verify_lifecycle_v1(
        connection,
        LifecycleExpectationV1::ImportedActive(expected_source_generations),
        historical_plan_keys,
    )
    .map(ImportedActiveBackupV1)
}

/// Atomically converts one fully verified imported ACTIVE cut into non-activatable custody.
///
/// The writer transaction re-verifies the entire source before mutation, CAS-binds every source
/// generation and old root identity, stamps all restored operations, refreshes their exact
/// comparison digests, and verifies the complete RESTORE_PENDING state before commit.
#[allow(dead_code)] // Consumed by the T072 maintenance restore pipeline.
pub(crate) fn transition_imported_backup_to_restore_pending_v1<R: Ed25519KeyResolver>(
    connection: &mut Connection,
    bindings: RestorePendingBindingsV1,
    historical_plan_keys: &R,
) -> Result<VerifiedRestorePendingV1, InternalCoordinatorError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))?;
    let source = verify_lifecycle_v1(
        &transaction,
        LifecycleExpectationV1::ImportedActive(bindings.expected_source_generations),
        historical_plan_keys,
    )?;
    if source.summary.root_identity == bindings.new_root_identity {
        return Err(InternalCoordinatorError::RootIdentityMismatch);
    }

    stamp_restored_source_generation_v1(
        &transaction,
        bindings.restored_source_generation,
        source.summary.operation_count,
    )?;
    refresh_restored_comparison_digests_v1(&transaction, source.summary.operation_count)?;

    let next_store_generation = bindings
        .expected_source_generations
        .store()
        .checked_add(1)
        .filter(|generation| *generation <= MAX_SAFE_U64)
        .ok_or(InternalCoordinatorError::InvariantFailed)?;
    let changed = transaction
        .execute(
            "UPDATE coordinator_store_meta SET \
                 store_generation = ?1, \
                 root_identity = ?2, \
                 root_lifecycle_state = 'RESTORE_PENDING', \
                 restore_identity_digest = ?3, \
                 restore_attestation_digest = ?4, \
                 restore_state_generation = ?1 \
             WHERE singleton = 1 \
               AND store_generation = ?5 \
               AND operation_generation = ?6 \
               AND budget_generation = ?7 \
               AND event_generation = ?8 \
               AND quarantine_generation = ?9 \
               AND root_identity = ?10 \
               AND root_lifecycle_state = 'ACTIVE' \
               AND restore_identity_digest IS NULL \
               AND restore_attestation_digest IS NULL \
               AND restore_state_generation = 0",
            params![
                safe_u64_to_i64(next_store_generation)?,
                bindings.new_root_identity.as_bytes().as_slice(),
                bindings.restore_identity_digest.as_bytes().as_slice(),
                bindings.restore_attestation_digest.as_bytes().as_slice(),
                safe_u64_to_i64(bindings.expected_source_generations.store())?,
                safe_u64_to_i64(bindings.expected_source_generations.operation())?,
                safe_u64_to_i64(bindings.expected_source_generations.budget())?,
                safe_u64_to_i64(bindings.expected_source_generations.event())?,
                safe_u64_to_i64(bindings.expected_source_generations.quarantine())?,
                source.summary.root_identity.as_bytes().as_slice(),
            ],
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    if changed != 1 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }

    let verified = verify_lifecycle_v1(
        &transaction,
        LifecycleExpectationV1::RestorePending(bindings),
        historical_plan_keys,
    )?;
    transaction
        .commit()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))?;
    Ok(VerifiedRestorePendingV1(verified))
}

/// Full maintenance-only verification of one exact RESTORE_PENDING coordinator root.
#[allow(dead_code)] // Consumed by the T072 maintenance restore/reopen agreement pipeline.
pub(crate) fn verify_restore_pending_v1<R: Ed25519KeyResolver>(
    connection: &Connection,
    bindings: RestorePendingBindingsV1,
    historical_plan_keys: &R,
) -> Result<VerifiedRestorePendingV1, InternalCoordinatorError> {
    verify_lifecycle_v1(
        connection,
        LifecycleExpectationV1::RestorePending(bindings),
        historical_plan_keys,
    )
    .map(VerifiedRestorePendingV1)
}

fn verify_lifecycle_v1<R: Ed25519KeyResolver>(
    connection: &Connection,
    expectation: LifecycleExpectationV1,
    historical_plan_keys: &R,
) -> Result<VerifiedCoordinatorLifecycleV1, InternalCoordinatorError> {
    verify_embedded_schema_digest()?;
    verify_identity(connection)?;
    verify_exact_schema(connection)?;
    verify_integrity_check(connection)?;
    verify_foreign_key_check(connection)?;

    let metadata = decode_single_metadata_row(connection)?;
    verify_expected_lifecycle_v1(metadata, expectation)?;

    let operation_count = verify_historical_canonical_plans(connection, historical_plan_keys)?;
    let recovery_count = verify_recovery_immutable_bindings(connection, historical_plan_keys)?;
    if recovery_count != operation_count {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    verify_comparison_digests(connection)?;
    verify_cross_record_invariants(connection, metadata, operation_count)?;
    let expected_restored_generation = match expectation {
        LifecycleExpectationV1::ActiveBound(_) | LifecycleExpectationV1::ImportedActive(_) => None,
        LifecycleExpectationV1::RestorePending(bindings) => {
            Some(bindings.restored_source_generation)
        }
    };
    verify_restored_source_generations_v1(
        connection,
        expected_restored_generation,
        operation_count,
    )?;
    let counts = read_lifecycle_counts_v1(connection)?;
    if counts.operations != operation_count {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(VerifiedCoordinatorLifecycleV1 {
        summary: StoreSummary {
            schema_cookie: schema_cookie(connection)?,
            operation_count,
            root_identity: metadata.root_identity,
        },
        generations: metadata.generations(),
        counts,
    })
}

fn verify_expected_lifecycle_v1(
    metadata: CoordinatorStoreMetadataRow,
    expectation: LifecycleExpectationV1,
) -> Result<(), InternalCoordinatorError> {
    match (expectation, metadata.root_lifecycle) {
        (LifecycleExpectationV1::ActiveBound(_), RootLifecycleV1::RestorePending { .. })
        | (LifecycleExpectationV1::ImportedActive(_), RootLifecycleV1::RestorePending { .. }) => {
            Err(InternalCoordinatorError::RestorePending)
        }
        (LifecycleExpectationV1::ActiveBound(expected), RootLifecycleV1::Active) => {
            if metadata.root_identity != expected {
                return Err(InternalCoordinatorError::RootIdentityMismatch);
            }
            Ok(())
        }
        (LifecycleExpectationV1::ImportedActive(expected), RootLifecycleV1::Active) => {
            if metadata.generations() != expected {
                return Err(InternalCoordinatorError::InvariantFailed);
            }
            Ok(())
        }
        (LifecycleExpectationV1::RestorePending(_), RootLifecycleV1::Active) => {
            Err(InternalCoordinatorError::InvariantFailed)
        }
        (
            LifecycleExpectationV1::RestorePending(bindings),
            RootLifecycleV1::RestorePending {
                restore_identity_digest,
                restore_attestation_digest,
                restore_state_generation,
            },
        ) => {
            if metadata.root_identity != bindings.new_root_identity {
                return Err(InternalCoordinatorError::RootIdentityMismatch);
            }
            let source = bindings.expected_source_generations;
            let expected_store = source
                .store()
                .checked_add(1)
                .filter(|generation| *generation <= MAX_SAFE_U64)
                .ok_or(InternalCoordinatorError::InvariantFailed)?;
            // `restore_state_generation` permanently identifies the initial
            // ACTIVE -> RESTORE_PENDING publication. Maintenance reconciliation may
            // subsequently advance the ordinary high-water marks while the root stays
            // pending, so reopen requires monotonicity rather than freezing the cut.
            // Full cross-record verification below still proves every current maximum.
            if restore_state_generation != expected_store
                || metadata.store_generation < expected_store
                || metadata.operation_generation < source.operation()
                || metadata.budget_generation < source.budget()
                || metadata.event_generation < source.event()
                || metadata.quarantine_generation < source.quarantine()
                || restore_identity_digest != bindings.restore_identity_digest
                || restore_attestation_digest != bindings.restore_attestation_digest
            {
                return Err(InternalCoordinatorError::InvariantFailed);
            }
            Ok(())
        }
    }
}

fn verify_restored_source_generations_v1(
    connection: &Connection,
    expected: Option<u64>,
    expected_operation_count: u64,
) -> Result<(), InternalCoordinatorError> {
    let expected_i64 = expected.map(safe_u64_to_i64).transpose()?;
    let (total, matching): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), \
                    COALESCE(SUM(CASE \
                        WHEN (?1 IS NULL AND restored_source_generation IS NULL) \
                          OR restored_source_generation = ?1 \
                        THEN 1 ELSE 0 END), 0) \
             FROM prepared_operations",
            [expected_i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    if safe_i64(total)? != expected_operation_count
        || safe_i64(matching)? != expected_operation_count
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn stamp_restored_source_generation_v1(
    connection: &Connection,
    restored_source_generation: u64,
    expected_operation_count: u64,
) -> Result<(), InternalCoordinatorError> {
    let changed = connection
        .execute(
            "UPDATE prepared_operations SET restored_source_generation = ?1 \
             WHERE restored_source_generation IS NULL",
            [safe_u64_to_i64(restored_source_generation)?],
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    if u64::try_from(changed).map_err(|_| InternalCoordinatorError::InvariantFailed)?
        != expected_operation_count
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    verify_restored_source_generations_v1(
        connection,
        Some(restored_source_generation),
        expected_operation_count,
    )
}

fn refresh_restored_comparison_digests_v1(
    connection: &Connection,
    expected_operation_count: u64,
) -> Result<(), InternalCoordinatorError> {
    let digests = persisted_comparison_digests_v1(connection)
        .map_err(|_| InternalCoordinatorError::InvariantFailed)?;
    if u64::try_from(digests.len()).map_err(|_| InternalCoordinatorError::InvariantFailed)?
        != expected_operation_count
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    for digest in digests {
        let changed = connection
            .execute(
                "UPDATE preparation_comparisons SET comparison_digest = ?1 \
                 WHERE operation_id = ?2 AND comparison_digest = ?3",
                params![
                    digest.recomputed.as_slice(),
                    digest.operation_id,
                    digest.persisted.as_slice(),
                ],
            )
            .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
        if changed != 1 {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
    }
    verify_comparison_digests(connection)
}

fn read_lifecycle_counts_v1(
    connection: &Connection,
) -> Result<CoordinatorLifecycleCountsV1, InternalCoordinatorError> {
    let raw: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT \
                 (SELECT COUNT(*) FROM budget_scopes), \
                 (SELECT COUNT(*) FROM prepared_operations), \
                 (SELECT COUNT(*) FROM operation_transitions), \
                 (SELECT COUNT(*) FROM budget_reservations \
                    WHERE reservation_state = 'HELD'), \
                 (SELECT COUNT(*) FROM budget_reservations \
                    WHERE reservation_state = 'RELEASED'), \
                 (SELECT COUNT(*) FROM preparation_events \
                    WHERE delivery_state = 'PENDING'), \
                 (SELECT COUNT(*) FROM preparation_events \
                    WHERE delivery_state = 'DELIVERED'), \
                 (SELECT COUNT(*) FROM preparation_quarantines \
                    WHERE quarantine_status = 'ACTIVE'), \
                 (SELECT COUNT(*) FROM preparation_quarantines \
                    WHERE quarantine_status = 'RESOLVED_TOMBSTONE')",
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
                    row.get(8)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    Ok(CoordinatorLifecycleCountsV1 {
        budget_scopes: safe_i64(raw.0)?,
        operations: safe_i64(raw.1)?,
        operation_transitions: safe_i64(raw.2)?,
        held_reservations: safe_i64(raw.3)?,
        released_reservations: safe_i64(raw.4)?,
        pending_events: safe_i64(raw.5)?,
        delivered_events: safe_i64(raw.6)?,
        active_quarantines: safe_i64(raw.7)?,
        resolved_quarantines: safe_i64(raw.8)?,
    })
}

fn safe_u64_to_i64(value: u64) -> Result<i64, InternalCoordinatorError> {
    if value > MAX_SAFE_U64 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    i64::try_from(value).map_err(|_| InternalCoordinatorError::InvariantFailed)
}

pub(crate) fn schema_cookie(connection: &Connection) -> Result<i64, InternalCoordinatorError> {
    pragma_i64(connection, "schema_version").map_err(|_| InternalCoordinatorError::SchemaInvalid)
}

fn verify_embedded_schema_digest() -> Result<(), InternalCoordinatorError> {
    if embedded_schema_v1_sha256() != COORDINATOR_STORE_SCHEMA_V1_SHA256 {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    Ok(())
}

fn verify_identity(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    let application_id = pragma_i64(connection, "application_id")?;
    if application_id != COORDINATOR_STORE_APPLICATION_ID_V1 {
        return Err(InternalCoordinatorError::ApplicationIdMismatch);
    }
    let user_version = pragma_i64(connection, "user_version")?;
    if user_version > COORDINATOR_STORE_SCHEMA_VERSION_V1 {
        return Err(InternalCoordinatorError::SchemaUnsupported);
    }
    if user_version != COORDINATOR_STORE_SCHEMA_VERSION_V1 {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    Ok(())
}

fn verify_exact_schema(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    let actual = read_schema_objects(connection)?;
    let expected_connection = Connection::open_in_memory()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))?;
    expected_connection
        .execute_batch(COORDINATOR_STORE_SCHEMA_V1_SQL)
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))?;
    let expected = read_schema_objects(&expected_connection)?;
    if actual != expected {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    Ok(())
}

fn verify_integrity_check(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::IntegrityFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::IntegrityFailed))?;
    let first = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::IntegrityFailed))?
        .ok_or(InternalCoordinatorError::IntegrityFailed)?;
    let result: String = first
        .get(0)
        .map_err(|_| InternalCoordinatorError::IntegrityFailed)?;
    if result != "ok"
        || rows
            .next()
            .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::IntegrityFailed))?
            .is_some()
    {
        return Err(InternalCoordinatorError::IntegrityFailed);
    }
    Ok(())
}

fn verify_foreign_key_check(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    if statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?
        .is_some()
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn decode_single_metadata_row(
    connection: &Connection,
) -> Result<CoordinatorStoreMetadataRow, InternalCoordinatorError> {
    let mut statement = connection
        .prepare(
            "SELECT singleton, format_version, store_generation, operation_generation, \
             budget_generation, event_generation, quarantine_generation, root_identity, \
             root_lifecycle_state, restore_identity_digest, restore_attestation_digest, \
             restore_state_generation FROM coordinator_store_meta",
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    let row = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?
        .ok_or(InternalCoordinatorError::InvariantFailed)?;

    let singleton = strict_safe_integer(row.get_ref(0).map_err(invariant)?)?;
    let format_version = strict_safe_integer(row.get_ref(1).map_err(invariant)?)?;
    let store_generation = strict_safe_integer(row.get_ref(2).map_err(invariant)?)?;
    let operation_generation = strict_safe_integer(row.get_ref(3).map_err(invariant)?)?;
    let budget_generation = strict_safe_integer(row.get_ref(4).map_err(invariant)?)?;
    let event_generation = strict_safe_integer(row.get_ref(5).map_err(invariant)?)?;
    let quarantine_generation = strict_safe_integer(row.get_ref(6).map_err(invariant)?)?;
    let root_identity = CoordinatorRootIdentityV1::from_bytes(
        strict_blob(row.get_ref(7).map_err(invariant)?, 32)?
            .try_into()
            .map_err(|_| InternalCoordinatorError::InvariantFailed)?,
    );
    let root_lifecycle_state = strict_text(row.get_ref(8).map_err(invariant)?)?;
    let restore_identity_digest = strict_optional_digest(row.get_ref(9).map_err(invariant)?)?;
    let restore_attestation_digest = strict_optional_digest(row.get_ref(10).map_err(invariant)?)?;
    let restore_state_generation = strict_safe_integer(row.get_ref(11).map_err(invariant)?)?;
    let root_lifecycle = match (
        root_lifecycle_state,
        restore_identity_digest,
        restore_attestation_digest,
        restore_state_generation,
    ) {
        (b"ACTIVE", None, None, 0) => RootLifecycleV1::Active,
        (b"RESTORE_PENDING", Some(identity), Some(attestation), generation)
            if generation > 0 && generation <= store_generation =>
        {
            RootLifecycleV1::RestorePending {
                restore_identity_digest: identity,
                restore_attestation_digest: attestation,
                restore_state_generation: generation,
            }
        }
        _ => return Err(InternalCoordinatorError::InvariantFailed),
    };

    if singleton != 1
        || format_version != COORDINATOR_STORE_FORMAT_VERSION_V1 as u64
        || rows
            .next()
            .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?
            .is_some()
    {
        return Err(InternalCoordinatorError::InvariantFailed);
    }

    Ok(CoordinatorStoreMetadataRow {
        store_generation,
        operation_generation,
        budget_generation,
        event_generation,
        quarantine_generation,
        root_identity,
        root_lifecycle,
    })
}

fn verify_historical_canonical_plans<R: Ed25519KeyResolver>(
    connection: &Connection,
    historical_plan_keys: &R,
) -> Result<u64, InternalCoordinatorError> {
    let mut statement = connection
        .prepare(
            "SELECT operation.operation_id, operation.plan_id, operation.task_id, \
                    operation.workload_id, operation.canonical_plan, \
                    operation.canonical_plan_length, operation.reservation_id, \
                    operation.recovery_mode, operation.boot_id, operation.instance_epoch, \
                    operation.fencing_epoch, operation.effective_expires_at_utc_ms, \
                    comparison.instance_epoch, comparison.fencing_epoch, \
                    comparison.verified_key_fingerprint, comparison.capability_report_digest, \
                    reservation.task_lease_digest, reservation.currency_code, \
                    reservation.price_table_id, reservation.reserved_cost_micro_units, \
                    reservation.reserved_action_count, reservation.reserved_egress_bytes, \
                    reservation.reserved_recovery_bytes, recovery.recovery_mode, \
                    recovery.atomicity, recovery.risk_level, recovery.precondition_digest, \
                    recovery.precondition_length, recovery.reserved_capacity, \
                    recovery.material_digest, recovery.material_length \
             FROM prepared_operations AS operation \
             JOIN preparation_comparisons AS comparison \
               ON comparison.operation_id = operation.operation_id \
             JOIN budget_reservations AS reservation \
               ON reservation.operation_id = operation.operation_id \
             JOIN preparation_recovery_evidence AS recovery \
               ON recovery.operation_id = operation.operation_id \
             ORDER BY operation.operation_id",
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    let mut count = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?
    {
        let operation_id = strict_text(row.get_ref(0).map_err(invariant)?)?;
        let plan_id = strict_blob(row.get_ref(1).map_err(invariant)?, 32)?;
        let task_id = strict_text(row.get_ref(2).map_err(invariant)?)?;
        let workload_id = strict_text(row.get_ref(3).map_err(invariant)?)?;
        let canonical_plan = strict_blob_range(row.get_ref(4).map_err(invariant)?, 1, 1_048_576)?;
        let canonical_plan_length = strict_safe_integer(row.get_ref(5).map_err(invariant)?)?;
        let reservation_id = strict_text(row.get_ref(6).map_err(invariant)?)?;
        let recovery_mode = strict_text(row.get_ref(7).map_err(invariant)?)?;
        let boot_id = strict_text(row.get_ref(8).map_err(invariant)?)?;
        let operation_instance_epoch = strict_safe_integer(row.get_ref(9).map_err(invariant)?)?;
        let operation_fencing_epoch = strict_safe_integer(row.get_ref(10).map_err(invariant)?)?;
        let effective_expires_at_utc_ms = strict_safe_integer(row.get_ref(11).map_err(invariant)?)?;
        let comparison_instance_epoch = strict_safe_integer(row.get_ref(12).map_err(invariant)?)?;
        let comparison_fencing_epoch = strict_safe_integer(row.get_ref(13).map_err(invariant)?)?;
        let verified_key_fingerprint = strict_blob(row.get_ref(14).map_err(invariant)?, 32)?;
        let capability_report_digest = strict_blob(row.get_ref(15).map_err(invariant)?, 32)?;
        let task_lease_digest = strict_blob(row.get_ref(16).map_err(invariant)?, 32)?;
        let currency_code = strict_text(row.get_ref(17).map_err(invariant)?)?;
        let price_table_id = strict_text(row.get_ref(18).map_err(invariant)?)?;
        let reserved_cost = strict_safe_integer(row.get_ref(19).map_err(invariant)?)?;
        let reserved_actions = strict_safe_integer(row.get_ref(20).map_err(invariant)?)?;
        let reserved_egress = strict_safe_integer(row.get_ref(21).map_err(invariant)?)?;
        let reserved_recovery = strict_safe_integer(row.get_ref(22).map_err(invariant)?)?;
        let evidence_recovery_mode = strict_text(row.get_ref(23).map_err(invariant)?)?;
        let evidence_atomicity = strict_text(row.get_ref(24).map_err(invariant)?)?;
        let evidence_risk_level = strict_text(row.get_ref(25).map_err(invariant)?)?;
        let evidence_precondition_digest = strict_blob(row.get_ref(26).map_err(invariant)?, 32)?;
        let evidence_precondition_length =
            strict_safe_integer(row.get_ref(27).map_err(invariant)?)?;
        let evidence_reserved_capacity = strict_safe_integer(row.get_ref(28).map_err(invariant)?)?;
        let evidence_material_digest =
            strict_optional_blob(row.get_ref(29).map_err(invariant)?, 32)?;
        let evidence_material_length =
            strict_optional_safe_integer(row.get_ref(30).map_err(invariant)?)?;
        if canonical_plan_length
            != u64::try_from(canonical_plan.len())
                .map_err(|_| InternalCoordinatorError::InvariantFailed)?
        {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
        let authentic = decode_and_verify_plan(canonical_plan, historical_plan_keys)
            .map_err(|_| InternalCoordinatorError::InvariantFailed)?;
        let claims = authentic.preparation_claims();
        let eligibility = authentic.eligibility_claims();
        let expected_recovery_mode = match claims.recovery_class() {
            RecoveryClassV1::Compensation => b"COMPENSATION".as_slice(),
            RecoveryClassV1::Irreversible => b"IRREVERSIBLE".as_slice(),
        };
        let expected_atomicity = match claims.atomicity() {
            AtomicityV1::AtomicReplace => b"ATOMIC_REPLACE".as_slice(),
            AtomicityV1::NonAtomic => b"NON_ATOMIC".as_slice(),
        };
        let expected_risk_level = match eligibility.risk_level() {
            RiskLevelV1::L0 => b"L0".as_slice(),
            RiskLevelV1::L1 => b"L1".as_slice(),
            RiskLevelV1::L2 => b"L2".as_slice(),
        };
        let budget = claims.budget();
        let material_matches_plan = match claims.recovery_class() {
            RecoveryClassV1::Compensation => {
                evidence_material_digest
                    == Some(claims.precondition_content_sha256().as_bytes().as_slice())
                    && evidence_material_length == Some(claims.precondition_byte_length())
            }
            RecoveryClassV1::Irreversible => {
                evidence_material_digest.is_none() && evidence_material_length.is_none()
            }
        };
        if authentic.plan_id().as_bytes().as_slice() != plan_id
            || claims.operation_id().as_bytes() != operation_id
            || claims.task_id().as_bytes() != task_id
            || claims.workload_id().as_bytes() != workload_id
            || budget.reservation_id().as_bytes() != reservation_id
            || expected_recovery_mode != recovery_mode
            || eligibility.boot_id().as_bytes() != boot_id
            || eligibility.instance_epoch() != operation_instance_epoch
            || eligibility.fencing_epoch() != operation_fencing_epoch
            || operation_instance_epoch != comparison_instance_epoch
            || operation_fencing_epoch != comparison_fencing_epoch
            || effective_expires_at_utc_ms > eligibility.expires_at_unix_ms()
            || eligibility.verified_key_fingerprint().as_bytes().as_slice()
                != verified_key_fingerprint
            || eligibility.capability_report_digest().as_bytes().as_slice()
                != capability_report_digest
            || claims.task_lease_digest().as_bytes().as_slice() != task_lease_digest
            || budget.currency_code().as_bytes() != currency_code
            || budget.price_table_id().as_bytes() != price_table_id
            || budget.max_cost_micro_units() != reserved_cost
            || budget.action_limit() != reserved_actions
            || budget.egress_bytes_limit() != reserved_egress
            || claims.recovery_reserved_bytes() != reserved_recovery
            || expected_recovery_mode != evidence_recovery_mode
            || expected_atomicity != evidence_atomicity
            || expected_risk_level != evidence_risk_level
            || claims.precondition_content_sha256().as_bytes().as_slice()
                != evidence_precondition_digest
            || claims.precondition_byte_length() != evidence_precondition_length
            || claims.recovery_reserved_bytes() != evidence_reserved_capacity
            || !material_matches_plan
        {
            return Err(InternalCoordinatorError::InvariantFailed);
        }

        // Canonical target/precondition/boot domains and the complete recovery column
        // shape are rejoined below. Keep signature/canonical-plan verification here
        // independent so neither verifier can substitute for the other.
        count = count
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(InternalCoordinatorError::InvariantFailed)?;
    }
    Ok(count)
}

/// Rejoins every immutable recovery field to its authenticated plan and boot epochs.
///
/// `material_state` and the three retirement columns are intentionally decoded only as
/// a closed lifecycle tuple. They may advance after a coherent `PREPARING -> FAILED`
/// transition, while every provider/material identity and canonical binding remains
/// immutable and stays covered by the comparison digest.
fn verify_recovery_immutable_bindings<R: Ed25519KeyResolver>(
    connection: &Connection,
    historical_plan_keys: &R,
) -> Result<u64, InternalCoordinatorError> {
    let mut statement = connection
        .prepare(
            "SELECT operation.canonical_plan, operation.operation_id, operation.boot_id, \
                    operation.instance_epoch, operation.fencing_epoch, operation.recovery_mode, \
                    comparison.recovery_provider_generation, \
                    reservation.reserved_recovery_bytes, recovery.evidence_version, \
                    recovery.recovery_mode, recovery.recovery_class, recovery.atomicity, \
                    recovery.risk_level, recovery.target_reference_digest, \
                    recovery.precondition_identity_digest, recovery.precondition_digest, \
                    recovery.precondition_length, recovery.reserved_capacity, \
                    recovery.provider_profile_id, recovery.provider_profile_version, \
                    recovery.provider_id, recovery.provider_generation, recovery.evidence_class, \
                    recovery.at_rest_profile_id, recovery.capability_binding_digest, \
                    recovery.material_id, recovery.publication_attempt_id, \
                    recovery.manifest_digest, recovery.material_digest, recovery.material_length, \
                    recovery.material_state, recovery.retirement_id, \
                    recovery.retirement_manifest_digest, recovery.retirement_generation, \
                    recovery.boot_binding_digest, recovery.instance_epoch, \
                    recovery.fencing_epoch \
             FROM prepared_operations AS operation \
             JOIN preparation_comparisons AS comparison \
               ON comparison.operation_id = operation.operation_id \
             JOIN budget_reservations AS reservation \
               ON reservation.operation_id = operation.operation_id \
             JOIN preparation_recovery_evidence AS recovery \
               ON recovery.operation_id = operation.operation_id \
             ORDER BY operation.operation_id",
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    let mut count = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?
    {
        let canonical_plan = strict_blob_range(row.get_ref(0).map_err(invariant)?, 1, 1_048_576)?;
        let operation_id = strict_text(row.get_ref(1).map_err(invariant)?)?;
        let operation_boot_id = strict_text(row.get_ref(2).map_err(invariant)?)?;
        let operation_instance_epoch = strict_safe_integer(row.get_ref(3).map_err(invariant)?)?;
        let operation_fencing_epoch = strict_safe_integer(row.get_ref(4).map_err(invariant)?)?;
        let operation_recovery_mode = strict_text(row.get_ref(5).map_err(invariant)?)?;
        let comparison_provider_generation =
            strict_optional_safe_integer(row.get_ref(6).map_err(invariant)?)?;
        let reservation_recovery = strict_safe_integer(row.get_ref(7).map_err(invariant)?)?;
        let evidence_version = strict_safe_integer(row.get_ref(8).map_err(invariant)?)?;
        let recovery_mode = strict_text(row.get_ref(9).map_err(invariant)?)?;
        let recovery_class = strict_text(row.get_ref(10).map_err(invariant)?)?;
        let atomicity = strict_text(row.get_ref(11).map_err(invariant)?)?;
        let risk_level = strict_text(row.get_ref(12).map_err(invariant)?)?;
        let target_reference_digest = strict_blob(row.get_ref(13).map_err(invariant)?, 32)?;
        let precondition_identity_digest = strict_blob(row.get_ref(14).map_err(invariant)?, 32)?;
        let precondition_digest = strict_blob(row.get_ref(15).map_err(invariant)?, 32)?;
        let precondition_length = strict_safe_integer(row.get_ref(16).map_err(invariant)?)?;
        let reserved_capacity = strict_safe_integer(row.get_ref(17).map_err(invariant)?)?;
        let provider_profile_id = strict_optional_text(row.get_ref(18).map_err(invariant)?)?;
        let provider_profile_version =
            strict_optional_safe_integer(row.get_ref(19).map_err(invariant)?)?;
        let provider_id = strict_optional_text(row.get_ref(20).map_err(invariant)?)?;
        let provider_generation =
            strict_optional_safe_integer(row.get_ref(21).map_err(invariant)?)?;
        let evidence_class = strict_optional_text(row.get_ref(22).map_err(invariant)?)?;
        let at_rest_profile_id = strict_optional_text(row.get_ref(23).map_err(invariant)?)?;
        let capability_binding_digest =
            strict_optional_blob(row.get_ref(24).map_err(invariant)?, 32)?;
        let material_id = strict_optional_blob(row.get_ref(25).map_err(invariant)?, 32)?;
        let publication_attempt_id = strict_optional_blob(row.get_ref(26).map_err(invariant)?, 32)?;
        let manifest_digest = strict_optional_blob(row.get_ref(27).map_err(invariant)?, 32)?;
        let material_digest = strict_optional_blob(row.get_ref(28).map_err(invariant)?, 32)?;
        let material_length = strict_optional_safe_integer(row.get_ref(29).map_err(invariant)?)?;
        let material_state = strict_optional_text(row.get_ref(30).map_err(invariant)?)?;
        let retirement_id = strict_optional_blob(row.get_ref(31).map_err(invariant)?, 32)?;
        let retirement_manifest_digest =
            strict_optional_blob(row.get_ref(32).map_err(invariant)?, 32)?;
        let retirement_generation =
            strict_optional_safe_integer(row.get_ref(33).map_err(invariant)?)?;
        let boot_binding_digest = strict_blob(row.get_ref(34).map_err(invariant)?, 32)?;
        let recovery_instance_epoch = strict_safe_integer(row.get_ref(35).map_err(invariant)?)?;
        let recovery_fencing_epoch = strict_safe_integer(row.get_ref(36).map_err(invariant)?)?;

        let authentic = decode_and_verify_plan(canonical_plan, historical_plan_keys)
            .map_err(|_| InternalCoordinatorError::InvariantFailed)?;
        let claims = authentic.preparation_claims();
        let eligibility = authentic.eligibility_claims();
        let expected_mode = match claims.recovery_class() {
            RecoveryClassV1::Compensation => b"COMPENSATION".as_slice(),
            RecoveryClassV1::Irreversible => b"IRREVERSIBLE".as_slice(),
        };
        let expected_atomicity = match claims.atomicity() {
            AtomicityV1::AtomicReplace => b"ATOMIC_REPLACE".as_slice(),
            AtomicityV1::NonAtomic => b"NON_ATOMIC".as_slice(),
        };
        let expected_risk = match eligibility.risk_level() {
            RiskLevelV1::L0 => b"L0".as_slice(),
            RiskLevelV1::L1 => b"L1".as_slice(),
            RiskLevelV1::L2 => b"L2".as_slice(),
        };
        let expected_target = recovery_target_reference_digest_v1(claims.target())
            .map_err(|_| InternalCoordinatorError::InvariantFailed)?;
        let expected_precondition_identity = recovery_precondition_identity_digest_v1(
            claims.precondition_volume_id(),
            claims.precondition_file_id(),
        )
        .map_err(|_| InternalCoordinatorError::InvariantFailed)?;
        let expected_boot = recovery_boot_binding_digest_v1(
            eligibility.boot_id(),
            eligibility.instance_epoch(),
            eligibility.fencing_epoch(),
        )
        .map_err(|_| InternalCoordinatorError::InvariantFailed)?;

        let common_exact = evidence_version == u64::from(RECOVERY_RECEIPT_CONTRACT_VERSION_V1)
            && claims.operation_id().as_bytes() == operation_id
            && eligibility.boot_id().as_bytes() == operation_boot_id
            && eligibility.instance_epoch() == operation_instance_epoch
            && eligibility.fencing_epoch() == operation_fencing_epoch
            && expected_mode == operation_recovery_mode
            && expected_mode == recovery_mode
            && expected_mode == recovery_class
            && expected_atomicity == atomicity
            && expected_risk == risk_level
            && expected_target.as_bytes().as_slice() == target_reference_digest
            && expected_precondition_identity.as_bytes().as_slice() == precondition_identity_digest
            && claims.precondition_content_sha256().as_bytes().as_slice() == precondition_digest
            && claims.precondition_byte_length() == precondition_length
            && claims.recovery_reserved_bytes() == reservation_recovery
            && claims.recovery_reserved_bytes() == reserved_capacity
            && expected_boot.as_bytes().as_slice() == boot_binding_digest
            && eligibility.instance_epoch() == recovery_instance_epoch
            && eligibility.fencing_epoch() == recovery_fencing_epoch;
        if !common_exact {
            return Err(InternalCoordinatorError::InvariantFailed);
        }

        let mode_exact = match claims.recovery_class() {
            RecoveryClassV1::Compensation => {
                let lifecycle_exact = match material_state {
                    Some(b"PUBLISHED") => {
                        retirement_id.is_none()
                            && retirement_manifest_digest.is_none()
                            && retirement_generation.is_none()
                    }
                    Some(b"RETIREMENT_PENDING") => {
                        retirement_id.is_some()
                            && retirement_manifest_digest.is_none()
                            && retirement_generation.is_some_and(|value| value > 0)
                    }
                    Some(b"RETIRED_TOMBSTONE") => {
                        retirement_id.is_some()
                            && retirement_manifest_digest.is_some()
                            && retirement_generation.is_some_and(|value| value > 0)
                    }
                    _ => false,
                };
                provider_profile_id.is_some_and(|value| !value.is_empty())
                    && provider_profile_version
                        == Some(u64::from(RECOVERY_PROVIDER_CONTRACT_VERSION_V1))
                    && provider_id.is_some_and(|value| !value.is_empty())
                    && provider_generation.is_some_and(|value| value > 0)
                    && comparison_provider_generation == provider_generation
                    && matches!(
                        evidence_class,
                        Some(b"SYNTHETIC_CONFORMANCE" | b"APPROVED_PRODUCTION")
                    )
                    && at_rest_profile_id.is_some_and(|value| !value.is_empty())
                    && capability_binding_digest.is_some()
                    && material_id.is_some()
                    && publication_attempt_id.is_some()
                    && manifest_digest.is_some()
                    && claims
                        .preimage_sha256()
                        .is_some_and(|digest| material_digest == Some(digest.as_bytes().as_slice()))
                    && material_length == Some(claims.precondition_byte_length())
                    && reserved_capacity >= claims.precondition_byte_length()
                    && lifecycle_exact
            }
            RecoveryClassV1::Irreversible => {
                eligibility.risk_level() == RiskLevelV1::L2
                    && claims.preimage_sha256().is_none()
                    && comparison_provider_generation.is_none()
                    && provider_profile_id.is_none()
                    && provider_profile_version.is_none()
                    && provider_id.is_none()
                    && provider_generation.is_none()
                    && evidence_class.is_none()
                    && at_rest_profile_id.is_none()
                    && capability_binding_digest.is_none()
                    && material_id.is_none()
                    && publication_attempt_id.is_none()
                    && manifest_digest.is_none()
                    && material_digest.is_none()
                    && material_length.is_none()
                    && material_state.is_none()
                    && retirement_id.is_none()
                    && retirement_manifest_digest.is_none()
                    && retirement_generation.is_none()
            }
        };
        if !mode_exact {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
        count = count
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(InternalCoordinatorError::InvariantFailed)?;
    }
    Ok(count)
}

fn verify_comparison_digests(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    verify_persisted_comparison_digests_v1(connection)
        .map_err(|_| InternalCoordinatorError::InvariantFailed)
}

fn verify_transition_graph(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    // `created_generation`/`failed_generation` belong to the enclosing store-generation domain;
    // `state_generation` belongs to the per-operation transition domain. Reservation bindings
    // connect the former, so these values must never be equated here.
    let exact: i64 = connection
        .query_row(
            "SELECT CASE WHEN NOT EXISTS (\
                 SELECT 1 FROM prepared_operations AS operation \
                 WHERE operation.state_generation <> (\
                           SELECT MAX(transition.state_generation) \
                           FROM operation_transitions AS transition \
                           WHERE transition.operation_id = operation.operation_id\
                       ) \
                    OR (operation.operation_state = 'PREPARING' AND (\
                           (SELECT COUNT(*) FROM operation_transitions AS transition \
                            WHERE transition.operation_id = operation.operation_id) <> 1 \
                           OR (SELECT COUNT(*) FROM preparation_events AS event \
                               WHERE event.operation_id = operation.operation_id) <> 1 \
                           OR NOT EXISTS (\
                               SELECT 1 FROM operation_transitions AS transition \
                               JOIN preparation_events AS event \
                                 ON event.event_id = transition.event_id \
                               WHERE transition.operation_id = operation.operation_id \
                                 AND transition.previous_state IS NULL \
                                 AND transition.new_state = 'PREPARING' \
                                 AND transition.state_generation = operation.state_generation \
                                 AND transition.event_id = operation.current_event_id \
                                 AND event.operation_state_generation \
                                     = transition.state_generation \
                                 AND event.operation_state = 'PREPARING' \
                                 AND event.event_kind = 'PREPARED' \
                                 AND event.reason_code IS NULL\
                           )\
                       )) \
                    OR (operation.operation_state = 'FAILED' AND (\
                           (SELECT COUNT(*) FROM operation_transitions AS transition \
                               WHERE transition.operation_id = operation.operation_id) <> 2 \
                           OR (SELECT COUNT(*) FROM preparation_events AS event \
                               WHERE event.operation_id = operation.operation_id) <> 2 \
                           OR NOT EXISTS (\
                               SELECT 1 FROM operation_transitions AS transition \
                               JOIN preparation_events AS event \
                                 ON event.event_id = transition.event_id \
                               WHERE transition.operation_id = operation.operation_id \
                                 AND transition.previous_state IS NULL \
                                 AND transition.new_state = 'PREPARING' \
                                 AND transition.state_generation < operation.state_generation \
                                 AND event.operation_state_generation \
                                     = transition.state_generation \
                                 AND event.operation_state = 'PREPARING' \
                                 AND event.event_kind = 'PREPARED' \
                                 AND event.reason_code IS NULL\
                           ) \
                           OR NOT EXISTS (\
                               SELECT 1 FROM operation_transitions AS transition \
                               JOIN preparation_events AS event \
                                 ON event.event_id = transition.event_id \
                               WHERE transition.operation_id = operation.operation_id \
                                 AND transition.previous_state = 'PREPARING' \
                                 AND transition.new_state = 'FAILED' \
                                 AND transition.state_generation = operation.state_generation \
                                 AND transition.event_id = operation.current_event_id \
                                 AND event.operation_state_generation \
                                     = transition.state_generation \
                                 AND event.operation_state = 'FAILED' \
                                 AND event.event_kind = 'PREPARATION_FAILED' \
                                 AND event.reason_code IS operation.failed_reason_code\
                           )\
                       ))\
             ) THEN 1 ELSE 0 END",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    if exact != 1 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    verify_failure_reason_codes(connection)
}

fn verify_failure_reason_codes(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    let mut statement = connection
        .prepare(
            "SELECT failed_reason_code FROM prepared_operations \
             WHERE failed_reason_code IS NOT NULL \
             UNION ALL \
             SELECT reason_code FROM preparation_events WHERE reason_code IS NOT NULL",
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    let mut rows = statement
        .query([])
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?
    {
        if !is_persisted_failure_reason(strict_text(row.get_ref(0).map_err(invariant)?)?) {
            return Err(InternalCoordinatorError::InvariantFailed);
        }
    }
    Ok(())
}

fn is_persisted_failure_reason(reason: &[u8]) -> bool {
    matches!(
        reason,
        b"PREPARATION_RECOVERY_UNAVAILABLE"
            | b"PREPARATION_STORE_UNAVAILABLE"
            | b"PREPARATION_STORE_BUSY"
            | b"PREPARATION_STORE_UNHEALTHY"
            | b"PREPARATION_STORE_CONFLICT"
            | b"PREPARATION_STORE_COMMIT_ABORTED"
            | b"PREPARATION_STORE_DEFINITE_ABSENCE"
    )
}

fn verify_generation_high_water(
    connection: &Connection,
    metadata: CoordinatorStoreMetadataRow,
) -> Result<(), InternalCoordinatorError> {
    let duplicate_domain_generation: i64 = connection
        .query_row(
            "SELECT EXISTS (\
                 SELECT generation FROM (\
                     SELECT scope_generation AS generation FROM budget_scopes \
                     UNION ALL \
                     SELECT created_generation FROM budget_reservations \
                     UNION ALL \
                     SELECT released_generation FROM budget_reservations \
                     WHERE released_generation IS NOT NULL\
                 ) GROUP BY generation HAVING COUNT(*) > 1\
             ) OR EXISTS (\
                 SELECT generation FROM (\
                     SELECT created_generation AS generation FROM preparation_quarantines \
                     UNION ALL \
                     SELECT resolved_generation FROM preparation_quarantines \
                     WHERE resolved_generation IS NOT NULL \
                     UNION ALL \
                     SELECT orphan_retired_generation FROM preparation_quarantines \
                     WHERE orphan_retired_generation IS NOT NULL\
                 ) GROUP BY generation HAVING COUNT(*) > 1\
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    if duplicate_domain_generation != 0 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    let observed: (u64, u64, u64, u64, u64) = connection
        .query_row(
            "SELECT \
                 COALESCE((SELECT MAX(state_generation) FROM operation_transitions), 0), \
                 MAX(\
                     COALESCE((SELECT MAX(scope_generation) FROM budget_scopes), 0), \
                     COALESCE((SELECT MAX(budget_generation) FROM budget_reservations), 0), \
                     COALESCE((SELECT MAX(created_generation) FROM budget_reservations), 0), \
                     COALESCE((SELECT MAX(released_generation) FROM budget_reservations), 0)\
                 ), \
                 COALESCE((SELECT MAX(event_generation) FROM preparation_events), 0), \
                 MAX(\
                     COALESCE((SELECT MAX(created_generation) FROM preparation_quarantines), 0), \
                     COALESCE((SELECT MAX(resolved_generation) FROM preparation_quarantines), 0), \
                     COALESCE((SELECT MAX(orphan_retired_generation) \
                               FROM preparation_quarantines), 0)\
                 ), \
                 MAX(\
                     COALESCE((SELECT MAX(created_generation) FROM prepared_operations), 0), \
                     COALESCE((SELECT MAX(failed_generation) FROM prepared_operations), 0), \
                     COALESCE((SELECT MAX(state_generation) FROM operation_transitions), 0), \
                     COALESCE((SELECT MAX(scope_generation) FROM budget_scopes), 0), \
                     COALESCE((SELECT MAX(created_generation) FROM budget_reservations), 0), \
                     COALESCE((SELECT MAX(released_generation) FROM budget_reservations), 0), \
                     COALESCE((SELECT MAX(event_generation) FROM preparation_events), 0), \
                     COALESCE((SELECT MAX(delivered_generation) FROM preparation_events), 0), \
                     COALESCE((SELECT MAX(created_generation) FROM preparation_quarantines), 0), \
                     COALESCE((SELECT MAX(resolved_generation) FROM preparation_quarantines), 0), \
                     COALESCE((SELECT MAX(orphan_retired_generation) \
                               FROM preparation_quarantines), 0), \
                     COALESCE((SELECT MAX(retirement_generation) \
                               FROM preparation_recovery_evidence), 0)\
                 )",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))
        .and_then(|values| {
            Ok((
                safe_i64(values.0)?,
                safe_i64(values.1)?,
                safe_i64(values.2)?,
                safe_i64(values.3)?,
                safe_i64(values.4)?,
            ))
        })?;
    let observed_store_generation = match metadata.root_lifecycle {
        RootLifecycleV1::Active => observed.4,
        RootLifecycleV1::RestorePending {
            restore_state_generation,
            ..
        } => observed.4.max(restore_state_generation),
    };
    let exact_domains = observed.0 == metadata.operation_generation
        && observed.1 == metadata.budget_generation
        && observed.2 == metadata.event_generation
        && observed.3 == metadata.quarantine_generation
        && observed_store_generation == metadata.store_generation;
    let bounded_by_store = [
        metadata.operation_generation,
        metadata.budget_generation,
        metadata.event_generation,
        metadata.quarantine_generation,
    ]
    .into_iter()
    .all(|generation| generation <= metadata.store_generation);
    if !exact_domains || !bounded_by_store {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(())
}

fn verify_cross_record_invariants(
    connection: &Connection,
    metadata: CoordinatorStoreMetadataRow,
    operation_count: u64,
) -> Result<(), InternalCoordinatorError> {
    let operation_count =
        i64::try_from(operation_count).map_err(|_| InternalCoordinatorError::InvariantFailed)?;
    let counts_and_joins_are_exact: i64 = connection
        .query_row(
            "SELECT CASE WHEN \
                 (SELECT COUNT(*) FROM prepared_operations) = ?1 \
             AND (SELECT COUNT(*) FROM preparation_comparisons) = ?1 \
             AND (SELECT COUNT(*) FROM budget_reservations) = ?1 \
             AND (SELECT COUNT(*) FROM preparation_recovery_evidence) = ?1 \
             AND NOT EXISTS (\
                 SELECT 1 FROM prepared_operations AS operation \
                 LEFT JOIN preparation_comparisons AS comparison \
                   ON comparison.operation_id = operation.operation_id \
                 LEFT JOIN budget_reservations AS reservation \
                   ON reservation.operation_id = operation.operation_id \
                  AND reservation.reservation_id = operation.reservation_id \
                  AND reservation.attempt_id = operation.attempt_id \
                  AND reservation.plan_id = operation.plan_id \
                 LEFT JOIN preparation_recovery_evidence AS recovery \
                   ON recovery.operation_id = operation.operation_id \
                  AND recovery.recovery_mode = operation.recovery_mode \
                 WHERE comparison.operation_id IS NULL \
                    OR reservation.operation_id IS NULL \
                    OR recovery.operation_id IS NULL\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM prepared_operations AS operation \
                 JOIN budget_reservations AS reservation \
                   ON reservation.operation_id = operation.operation_id \
                 JOIN preparation_events AS event \
                   ON event.event_id = operation.current_event_id \
                 WHERE (operation.operation_state = 'PREPARING' \
                        AND (reservation.reservation_state <> 'HELD' \
                             OR event.event_kind <> 'PREPARED')) \
                    OR (operation.operation_state = 'FAILED' \
                        AND (reservation.reservation_state <> 'RELEASED' \
                             OR event.event_kind <> 'PREPARATION_FAILED'))\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM prepared_operations AS operation \
                 JOIN preparation_comparisons AS comparison \
                   ON comparison.operation_id = operation.operation_id \
                 JOIN budget_reservations AS reservation \
                   ON reservation.operation_id = operation.operation_id \
                 JOIN preparation_recovery_evidence AS recovery \
                   ON recovery.operation_id = operation.operation_id \
                 WHERE reservation.created_generation IS NOT operation.created_generation \
                    OR (operation.operation_state = 'PREPARING' \
                        AND reservation.released_generation IS NOT NULL) \
                    OR (operation.operation_state = 'FAILED' \
                        AND reservation.released_generation \
                            IS NOT operation.failed_generation) \
                    OR recovery.instance_epoch IS NOT operation.instance_epoch \
                    OR recovery.fencing_epoch IS NOT operation.fencing_epoch \
                    OR comparison.instance_epoch IS NOT operation.instance_epoch \
                    OR comparison.fencing_epoch IS NOT operation.fencing_epoch \
                    OR (operation.recovery_mode = 'COMPENSATION' \
                        AND (comparison.recovery_provider_generation \
                                 IS NOT recovery.provider_generation \
                             OR (operation.operation_state = 'PREPARING' \
                                 AND recovery.material_state <> 'PUBLISHED'))) \
                    OR (operation.recovery_mode = 'IRREVERSIBLE' \
                        AND (comparison.recovery_provider_generation IS NOT NULL \
                             OR recovery.provider_generation IS NOT NULL \
                             OR recovery.material_state IS NOT NULL))\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM budget_reservations AS reservation \
                 JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id \
                 WHERE reservation.task_lease_digest IS NOT scope.task_lease_digest \
                    OR reservation.budget_generation <> scope.scope_generation \
                    OR reservation.currency_code <> scope.currency_code \
                    OR reservation.price_table_id <> scope.price_table_id\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM preparation_comparisons AS comparison \
                 JOIN budget_reservations AS reservation \
                   ON reservation.operation_id = comparison.operation_id \
                 JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id \
                 WHERE comparison.budget_scope_id IS NOT reservation.scope_id \
                    OR comparison.budget_scope_generation <> scope.scope_generation\
             ) \
             AND NOT EXISTS (\
                 SELECT 1 FROM budget_scopes AS scope \
                 WHERE scope.held_cost_micro_units <> COALESCE((\
                           SELECT SUM(reservation.reserved_cost_micro_units) \
                           FROM budget_reservations AS reservation \
                           WHERE reservation.scope_id = scope.scope_id \
                             AND reservation.reservation_state = 'HELD'\
                       ), 0) \
                    OR scope.held_action_count <> COALESCE((\
                           SELECT SUM(reservation.reserved_action_count) \
                           FROM budget_reservations AS reservation \
                           WHERE reservation.scope_id = scope.scope_id \
                             AND reservation.reservation_state = 'HELD'\
                       ), 0) \
                    OR scope.held_egress_bytes <> COALESCE((\
                           SELECT SUM(reservation.reserved_egress_bytes) \
                           FROM budget_reservations AS reservation \
                           WHERE reservation.scope_id = scope.scope_id \
                             AND reservation.reservation_state = 'HELD'\
                       ), 0) \
                    OR scope.held_recovery_bytes <> COALESCE((\
                           SELECT SUM(reservation.reserved_recovery_bytes) \
                           FROM budget_reservations AS reservation \
                           WHERE reservation.scope_id = scope.scope_id \
                             AND reservation.reservation_state = 'HELD'\
                       ), 0)\
             ) \
             THEN 1 ELSE 0 END",
            [operation_count],
            |row| row.get(0),
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::InvariantFailed))?;
    if counts_and_joins_are_exact != 1 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }

    verify_transition_graph(connection)?;

    verify_generation_high_water(connection, metadata)?;
    Ok(())
}

fn read_schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObject>, InternalCoordinatorError> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
        )
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))?;
    let rows = statement
        .query_map([], |row| {
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))
}

fn pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, InternalCoordinatorError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::SchemaInvalid))
}

fn strict_safe_integer(value: ValueRef<'_>) -> Result<u64, InternalCoordinatorError> {
    match value {
        ValueRef::Integer(value) => safe_i64(value),
        _ => Err(InternalCoordinatorError::InvariantFailed),
    }
}

fn safe_i64(value: i64) -> Result<u64, InternalCoordinatorError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(InternalCoordinatorError::InvariantFailed)
}

fn strict_blob(value: ValueRef<'_>, length: usize) -> Result<&[u8], InternalCoordinatorError> {
    match value {
        ValueRef::Blob(value) if value.len() == length => Ok(value),
        _ => Err(InternalCoordinatorError::InvariantFailed),
    }
}

fn strict_blob_range(
    value: ValueRef<'_>,
    minimum: usize,
    maximum: usize,
) -> Result<&[u8], InternalCoordinatorError> {
    match value {
        ValueRef::Blob(value) if (minimum..=maximum).contains(&value.len()) => Ok(value),
        _ => Err(InternalCoordinatorError::InvariantFailed),
    }
}

fn strict_optional_blob(
    value: ValueRef<'_>,
    length: usize,
) -> Result<Option<&[u8]>, InternalCoordinatorError> {
    match value {
        ValueRef::Null => Ok(None),
        ValueRef::Blob(value) if value.len() == length => Ok(Some(value)),
        _ => Err(InternalCoordinatorError::InvariantFailed),
    }
}

fn strict_optional_digest(
    value: ValueRef<'_>,
) -> Result<Option<Sha256Digest>, InternalCoordinatorError> {
    strict_optional_blob(value, Sha256Digest::BYTE_LEN)?
        .map(|bytes| {
            bytes
                .try_into()
                .map(Sha256Digest::from_bytes)
                .map_err(|_| InternalCoordinatorError::InvariantFailed)
        })
        .transpose()
}

fn strict_optional_safe_integer(
    value: ValueRef<'_>,
) -> Result<Option<u64>, InternalCoordinatorError> {
    match value {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(value) => safe_i64(value).map(Some),
        _ => Err(InternalCoordinatorError::InvariantFailed),
    }
}

fn strict_optional_text(value: ValueRef<'_>) -> Result<Option<&[u8]>, InternalCoordinatorError> {
    match value {
        ValueRef::Null => Ok(None),
        ValueRef::Text(value) => Ok(Some(value)),
        _ => Err(InternalCoordinatorError::InvariantFailed),
    }
}

fn strict_text(value: ValueRef<'_>) -> Result<&[u8], InternalCoordinatorError> {
    match value {
        ValueRef::Text(value) => Ok(value),
        _ => Err(InternalCoordinatorError::InvariantFailed),
    }
}

fn invariant(_: rusqlite::Error) -> InternalCoordinatorError {
    InternalCoordinatorError::InvariantFailed
}

#[cfg(test)]
mod tests {
    use super::{
        classify_initialization_candidate, initialize_empty_to_v1,
        stamp_restored_source_generation_v1, transition_imported_backup_to_restore_pending_v1,
        verify_expected_lifecycle_v1, verify_failure_reason_codes, verify_full,
        verify_generation_high_water, verify_historical_canonical_plans,
        verify_imported_active_backup_v1, verify_recovery_immutable_bindings,
        verify_restore_pending_v1, verify_transition_graph, CoordinatorLifecycleGenerationsV1,
        CoordinatorStoreMetadataRow, InitializationCandidateV1, LifecycleExpectationV1,
        RestorePendingBindingsV1, RootLifecycleV1, COORDINATOR_STORE_SCHEMA_V1_SQL,
    };
    use crate::clock::CoordinatorMonotonicClockV1;
    use crate::comparison_digest::IMMUTABLE_COMPARISON_DIGEST_PROJECTION_V1_SQL;
    use crate::error::{CoordinatorClockUnavailableV1, InternalCoordinatorError};
    use crate::root_safety::CoordinatorRootIdentityV1;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use helix_contracts::{
        decode_and_verify_plan, ContractError, Ed25519KeyResolver, Sha256Digest,
    };
    use helix_plan_preparation::{
        recovery_boot_binding_digest_v1, recovery_precondition_identity_digest_v1,
        recovery_target_reference_digest_v1,
    };
    use rusqlite::{params, Connection};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl CoordinatorMonotonicClockV1 for FixedClock {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            Ok(1_000)
        }
    }

    const FIXTURE_PLAN: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/plan-envelope-v1/valid-plan.envelope.jcs"
    ));
    const FIXTURE_PLAN_ID: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/plan-envelope-v1/valid-plan.plan-id"
    ));
    const FIXTURE_PUBLIC_KEY: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/plan-envelope-v1/valid-plan.public-key"
    ));

    struct HistoricalFixtureResolver {
        calls: AtomicUsize,
    }

    struct UnknownHistoricalResolver;

    impl Ed25519KeyResolver for UnknownHistoricalResolver {
        fn resolve_ed25519(&self, _: &str) -> helix_contracts::Result<[u8; 32]> {
            Err(ContractError::UnknownKey)
        }
    }

    struct WrongHistoricalResolver;

    impl Ed25519KeyResolver for WrongHistoricalResolver {
        fn resolve_ed25519(&self, _: &str) -> helix_contracts::Result<[u8; 32]> {
            Ok([0xA5_u8; 32])
        }
    }

    impl Ed25519KeyResolver for HistoricalFixtureResolver {
        fn resolve_ed25519(&self, _: &str) -> helix_contracts::Result<[u8; 32]> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            URL_SAFE_NO_PAD
                .decode(FIXTURE_PUBLIC_KEY)
                .map_err(|_| ContractError::InvalidPublicKey)?
                .try_into()
                .map_err(|_| ContractError::InvalidPublicKey)
        }
    }

    #[test]
    fn initialization_candidate_accepts_only_exact_empty_or_committed_v1() {
        let connection = Connection::open_in_memory().expect("memory database opens");
        assert_eq!(
            classify_initialization_candidate(&connection).unwrap(),
            InitializationCandidateV1::ExactEmpty
        );

        connection
            .execute_batch("CREATE TABLE partial (value INTEGER) STRICT;")
            .expect("partial object creates");
        assert!(classify_initialization_candidate(&connection).is_err());

        let internal_only = Connection::open_in_memory().expect("third memory database opens");
        internal_only
            .execute_batch(
                "CREATE TABLE sequenced (id INTEGER PRIMARY KEY AUTOINCREMENT) STRICT; \
                 DROP TABLE sequenced;",
            )
            .expect("internal sqlite_sequence residue creates");
        assert!(classify_initialization_candidate(&internal_only).is_err());

        let committed = Connection::open_in_memory().expect("second memory database opens");
        committed
            .execute_batch(&format!(
                "PRAGMA application_id = {}; PRAGMA user_version = 1; \
                 CREATE TABLE committed (value INTEGER) STRICT;",
                super::COORDINATOR_STORE_APPLICATION_ID_V1
            ))
            .expect("v1 identity fixture creates");
        assert_eq!(
            classify_initialization_candidate(&committed).unwrap(),
            InitializationCandidateV1::CommittedV1
        );
    }

    #[test]
    fn imported_active_transitions_once_and_pending_verification_is_exact_and_redacted() {
        let mut connection = Connection::open_in_memory().expect("memory database opens");
        let source_identity = CoordinatorRootIdentityV1::from_bytes([0x11; 32]);
        initialize_empty_to_v1(&mut connection, source_identity, &FixedClock, 10_000)
            .expect("source v1 initializes");
        verify_full(&connection, source_identity, &UnknownHistoricalResolver)
            .expect("ordinary ACTIVE verification remains unchanged");
        let source_generations = CoordinatorLifecycleGenerationsV1::try_new(0, 0, 0, 0, 0).unwrap();
        let imported = verify_imported_active_backup_v1(
            &connection,
            source_generations,
            &UnknownHistoricalResolver,
        )
        .expect("exact ACTIVE source cut verifies");
        assert_eq!(imported.summary().root_identity, source_identity);
        assert_eq!(imported.generations(), source_generations);
        assert_eq!(imported.counts().operations(), 0);
        assert_eq!(imported.counts().budget_scopes(), 0);
        assert_eq!(imported.counts().operation_transitions(), 0);
        assert_eq!(imported.counts().held_reservations(), 0);
        assert_eq!(imported.counts().released_reservations(), 0);
        assert_eq!(imported.counts().pending_events(), 0);
        assert_eq!(imported.counts().delivered_events(), 0);
        assert_eq!(imported.counts().active_quarantines(), 0);
        assert_eq!(imported.counts().resolved_quarantines(), 0);

        let new_identity = CoordinatorRootIdentityV1::from_bytes([0x22; 32]);
        let bindings = RestorePendingBindingsV1::try_new(
            source_generations,
            new_identity,
            Sha256Digest::from_bytes([0x33; 32]),
            Sha256Digest::from_bytes([0x44; 32]),
            0,
        )
        .unwrap();
        let transitioned = transition_imported_backup_to_restore_pending_v1(
            &mut connection,
            bindings,
            &UnknownHistoricalResolver,
        )
        .expect("ACTIVE source transitions once to pending");
        assert_eq!(transitioned.summary().root_identity, new_identity);
        assert_eq!(transitioned.generations().store(), 1);
        assert_eq!(transitioned.counts().operations(), 0);

        let reopened = verify_restore_pending_v1(&connection, bindings, &UnknownHistoricalResolver)
            .expect("exact pending bindings reopen");
        assert_eq!(reopened.summary().root_identity, new_identity);
        assert_eq!(
            verify_full(&connection, new_identity, &UnknownHistoricalResolver).unwrap_err(),
            InternalCoordinatorError::RestorePending
        );
        assert_eq!(
            transition_imported_backup_to_restore_pending_v1(
                &mut connection,
                bindings,
                &UnknownHistoricalResolver,
            )
            .unwrap_err(),
            InternalCoordinatorError::RestorePending
        );

        let wrong_identity = RestorePendingBindingsV1::try_new(
            source_generations,
            CoordinatorRootIdentityV1::from_bytes([0x55; 32]),
            bindings.restore_identity_digest(),
            bindings.restore_attestation_digest(),
            bindings.restored_source_generation(),
        )
        .unwrap();
        assert_eq!(
            verify_restore_pending_v1(&connection, wrong_identity, &UnknownHistoricalResolver,)
                .unwrap_err(),
            InternalCoordinatorError::RootIdentityMismatch
        );
        let wrong_digest = RestorePendingBindingsV1::try_new(
            source_generations,
            new_identity,
            Sha256Digest::from_bytes([0x66; 32]),
            bindings.restore_attestation_digest(),
            bindings.restored_source_generation(),
        )
        .unwrap();
        assert_eq!(
            verify_restore_pending_v1(&connection, wrong_digest, &UnknownHistoricalResolver)
                .unwrap_err(),
            InternalCoordinatorError::InvariantFailed
        );

        let proof_debug = format!("{reopened:?}");
        let bindings_debug = format!("{bindings:?}");
        assert_eq!(proof_debug, "VerifiedRestorePendingV1 { .. }");
        assert_eq!(bindings_debug, "RestorePendingBindingsV1 { .. }");
        for private in ["22".repeat(32), "33".repeat(32), "44".repeat(32)] {
            assert!(!proof_debug.contains(&private));
            assert!(!bindings_debug.contains(&private));
        }
    }

    #[test]
    fn pending_binding_survives_monotonic_old_authority_reconciliation() {
        let source = CoordinatorLifecycleGenerationsV1::try_new(10, 4, 5, 6, 7).unwrap();
        let root_identity = CoordinatorRootIdentityV1::from_bytes([0x61; 32]);
        let restore_identity = Sha256Digest::from_bytes([0x62; 32]);
        let attestation = Sha256Digest::from_bytes([0x63; 32]);
        let bindings = RestorePendingBindingsV1::try_new(
            source,
            root_identity,
            restore_identity,
            attestation,
            source.store(),
        )
        .unwrap();
        let reconciled = CoordinatorStoreMetadataRow {
            store_generation: 15,
            operation_generation: 11,
            budget_generation: 12,
            event_generation: 13,
            quarantine_generation: 14,
            root_identity,
            root_lifecycle: RootLifecycleV1::RestorePending {
                restore_identity_digest: restore_identity,
                restore_attestation_digest: attestation,
                restore_state_generation: 11,
            },
        };
        verify_expected_lifecycle_v1(reconciled, LifecycleExpectationV1::RestorePending(bindings))
            .expect("pending root remains verifiable after monotonic reconciliation");

        let regressed = CoordinatorStoreMetadataRow {
            operation_generation: 3,
            ..reconciled
        };
        assert_eq!(
            verify_expected_lifecycle_v1(
                regressed,
                LifecycleExpectationV1::RestorePending(bindings),
            )
            .unwrap_err(),
            InternalCoordinatorError::InvariantFailed
        );
    }

    #[test]
    fn pending_lifecycle_cannot_return_to_active_or_rewrite_restore_bindings() {
        let mut connection = Connection::open_in_memory().expect("memory database opens");
        let source_identity = CoordinatorRootIdentityV1::from_bytes([0x71; 32]);
        initialize_empty_to_v1(&mut connection, source_identity, &FixedClock, 10_000)
            .expect("source v1 initializes");
        let source_generations = CoordinatorLifecycleGenerationsV1::try_new(0, 0, 0, 0, 0).unwrap();
        let bindings = RestorePendingBindingsV1::try_new(
            source_generations,
            CoordinatorRootIdentityV1::from_bytes([0x72; 32]),
            Sha256Digest::from_bytes([0x73; 32]),
            Sha256Digest::from_bytes([0x74; 32]),
            0,
        )
        .unwrap();
        transition_imported_backup_to_restore_pending_v1(
            &mut connection,
            bindings,
            &UnknownHistoricalResolver,
        )
        .expect("source becomes pending");

        assert!(connection
            .execute(
                "UPDATE coordinator_store_meta SET \
                     store_generation = 2, root_identity = ?1, \
                     root_lifecycle_state = 'ACTIVE', \
                     restore_identity_digest = NULL, restore_attestation_digest = NULL, \
                     restore_state_generation = 0 WHERE singleton = 1",
                [source_identity.as_bytes().as_slice()],
            )
            .is_err());
        assert!(connection
            .execute(
                "UPDATE coordinator_store_meta SET restore_identity_digest = ?1 \
                 WHERE singleton = 1",
                [Sha256Digest::from_bytes([0x75; 32]).as_bytes().as_slice()],
            )
            .is_err());
        verify_restore_pending_v1(&connection, bindings, &UnknownHistoricalResolver)
            .expect("failed reverse and rewrite leave exact pending state");
    }

    #[test]
    fn restored_source_generation_stamp_is_exact_all_or_none() {
        let connection = Connection::open_in_memory().expect("memory database opens");
        connection
            .execute_batch(
                "CREATE TABLE prepared_operations (\
                     operation_id TEXT PRIMARY KEY, restored_source_generation INTEGER\
                 ) STRICT, WITHOUT ROWID; \
                 INSERT INTO prepared_operations VALUES ('operation:1', NULL); \
                 INSERT INTO prepared_operations VALUES ('operation:2', NULL);",
            )
            .expect("minimal restored-generation fixture creates");
        stamp_restored_source_generation_v1(&connection, 9, 2)
            .expect("every imported operation is stamped");
        let stamped: Vec<i64> = connection
            .prepare(
                "SELECT restored_source_generation FROM prepared_operations \
                 ORDER BY operation_id",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(stamped, vec![9, 9]);
        assert_eq!(
            stamp_restored_source_generation_v1(&connection, 9, 2).unwrap_err(),
            InternalCoordinatorError::InvariantFailed
        );
    }

    #[test]
    fn every_historical_table_has_an_exact_no_delete_trigger() {
        let connection = Connection::open_in_memory().expect("memory database opens");
        connection
            .execute_batch(COORDINATOR_STORE_SCHEMA_V1_SQL)
            .expect("reviewed schema installs");
        let expected = [
            ("budget_scopes", "budget_scopes_no_delete"),
            ("prepared_operations", "prepared_operations_no_delete"),
            ("operation_transitions", "operation_transitions_no_delete"),
            (
                "preparation_comparisons",
                "preparation_comparisons_no_delete",
            ),
            ("budget_reservations", "budget_reservations_no_delete"),
            (
                "preparation_recovery_evidence",
                "preparation_recovery_evidence_no_delete",
            ),
            ("preparation_events", "preparation_events_no_delete"),
            (
                "preparation_quarantines",
                "preparation_quarantines_no_delete",
            ),
        ];
        for (table, trigger) in expected {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema \
                     WHERE type = 'trigger' AND tbl_name = ?1 AND name = ?2 \
                       AND sql LIKE '%BEFORE DELETE%'",
                    params![table, trigger],
                    |row| row.get(0),
                )
                .expect("trigger inventory reads");
            assert_eq!(count, 1, "missing exact permanence trigger {trigger}");
        }
    }

    #[test]
    fn persisted_failure_reasons_are_a_closed_vocabulary() {
        let connection = Connection::open_in_memory().expect("memory database opens");
        connection
            .execute_batch(
                "CREATE TABLE prepared_operations (failed_reason_code TEXT) STRICT; \
                 CREATE TABLE preparation_events (reason_code TEXT) STRICT; \
                 INSERT INTO prepared_operations VALUES \
                     ('PREPARATION_STORE_COMMIT_ABORTED'); \
                 INSERT INTO preparation_events VALUES \
                     ('PREPARATION_RECOVERY_UNAVAILABLE');",
            )
            .expect("failure reason fixture creates");
        verify_failure_reason_codes(&connection).expect("documented reasons verify");

        connection
            .execute(
                "UPDATE preparation_events SET reason_code = 'PREPARATION_UNSPECIFIED'",
                [],
            )
            .expect("reason mutates");
        assert!(verify_failure_reason_codes(&connection).is_err());
    }

    #[test]
    fn retained_canonical_plan_requires_the_injected_historical_key_resolver() {
        let connection = Connection::open_in_memory().expect("memory database opens");
        connection
            .execute_batch(
                "CREATE TABLE prepared_operations (\
                     operation_id TEXT PRIMARY KEY, \
                     plan_id BLOB NOT NULL, \
                     task_id TEXT NOT NULL, \
                     workload_id TEXT NOT NULL, \
                     canonical_plan BLOB NOT NULL, \
                     canonical_plan_length INTEGER NOT NULL, \
                     reservation_id TEXT NOT NULL, \
                     recovery_mode TEXT NOT NULL, \
                     boot_id TEXT NOT NULL, \
                     instance_epoch INTEGER NOT NULL, \
                     fencing_epoch INTEGER NOT NULL, \
                     effective_expires_at_utc_ms INTEGER NOT NULL\
                 ) STRICT, WITHOUT ROWID; \
                 CREATE TABLE preparation_comparisons (\
                     operation_id TEXT PRIMARY KEY, instance_epoch INTEGER NOT NULL, \
                     fencing_epoch INTEGER NOT NULL, verified_key_fingerprint BLOB NOT NULL, \
                     capability_report_digest BLOB NOT NULL, \
                     recovery_provider_generation INTEGER\
                 ) STRICT, WITHOUT ROWID; \
                 CREATE TABLE budget_reservations (\
                     operation_id TEXT PRIMARY KEY, task_lease_digest BLOB NOT NULL, \
                     currency_code TEXT NOT NULL, price_table_id TEXT NOT NULL, \
                     reserved_cost_micro_units INTEGER NOT NULL, \
                     reserved_action_count INTEGER NOT NULL, \
                     reserved_egress_bytes INTEGER NOT NULL, \
                     reserved_recovery_bytes INTEGER NOT NULL\
                 ) STRICT, WITHOUT ROWID; \
                 CREATE TABLE preparation_recovery_evidence (\
                     operation_id TEXT PRIMARY KEY, evidence_version INTEGER NOT NULL, \
                     recovery_mode TEXT NOT NULL, recovery_class TEXT NOT NULL, \
                     atomicity TEXT NOT NULL, risk_level TEXT NOT NULL, \
                     target_reference_digest BLOB NOT NULL, \
                     precondition_identity_digest BLOB NOT NULL, \
                     precondition_digest BLOB NOT NULL, precondition_length INTEGER NOT NULL, \
                     reserved_capacity INTEGER NOT NULL, provider_profile_id TEXT, \
                     provider_profile_version INTEGER, provider_id TEXT, \
                     provider_generation INTEGER, evidence_class TEXT, at_rest_profile_id TEXT, \
                     capability_binding_digest BLOB, material_id BLOB, \
                     publication_attempt_id BLOB, manifest_digest BLOB, material_digest BLOB, \
                     material_length INTEGER, material_state TEXT, retirement_id BLOB, \
                     retirement_manifest_digest BLOB, retirement_generation INTEGER, \
                     boot_binding_digest BLOB NOT NULL, instance_epoch INTEGER NOT NULL, \
                     fencing_epoch INTEGER NOT NULL\
                 ) STRICT, WITHOUT ROWID;",
            )
            .expect("minimal custody table creates");
        let plan_id = Sha256Digest::parse_hex(FIXTURE_PLAN_ID).expect("fixture plan id parses");
        let public_key = URL_SAFE_NO_PAD
            .decode(FIXTURE_PUBLIC_KEY)
            .expect("fixture public key decodes");
        let key_fingerprint = Sha256Digest::digest(&public_key);
        let capability_digest = Sha256Digest::parse_hex(
            "cfef6749eda83045ddb28e7f7c05a8cf5bb3eddfa2e98641f7b1cbf5151f400a",
        )
        .expect("capability digest parses");
        let lease_digest = Sha256Digest::parse_hex(
            "6dd5d425d81126012c51e15165e7520808884fb6997a31690010b03b115b174e",
        )
        .expect("lease digest parses");
        let precondition_digest = Sha256Digest::parse_hex(
            "9160d4be34c8695bd172a76c7c7966587ea5a4d991ad22c87b2b91af54aa9ebb",
        )
        .expect("precondition digest parses");
        let binding_resolver = HistoricalFixtureResolver {
            calls: AtomicUsize::new(0),
        };
        let authentic = decode_and_verify_plan(FIXTURE_PLAN, &binding_resolver)
            .expect("fixture plan authenticates for canonical recovery bindings");
        let claims = authentic.preparation_claims();
        let eligibility = authentic.eligibility_claims();
        let target_reference_digest = recovery_target_reference_digest_v1(claims.target())
            .expect("fixture target digest derives");
        let precondition_identity_digest = recovery_precondition_identity_digest_v1(
            claims.precondition_volume_id(),
            claims.precondition_file_id(),
        )
        .expect("fixture precondition identity digest derives");
        let boot_binding_digest = recovery_boot_binding_digest_v1(
            eligibility.boot_id(),
            eligibility.instance_epoch(),
            eligibility.fencing_epoch(),
        )
        .expect("fixture boot binding digest derives");
        connection
            .execute(
                "INSERT INTO prepared_operations VALUES \
                 (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    "operation:00000000-0000-4000-8000-000000000001",
                    plan_id.as_bytes().as_slice(),
                    "task:fixture-1",
                    "workload:agent-vm-1",
                    FIXTURE_PLAN,
                    i64::try_from(FIXTURE_PLAN.len()).expect("fixture length fits"),
                    "budget:fixture-1",
                    "COMPENSATION",
                    "boot:fixture-1",
                    1_i64,
                    9_i64,
                    1_750_000_120_000_i64,
                ],
            )
            .expect("historical custody row inserts");
        connection
            .execute(
                "INSERT INTO preparation_comparisons VALUES (?1, 1, 9, ?2, ?3, 1)",
                params![
                    "operation:00000000-0000-4000-8000-000000000001",
                    key_fingerprint.as_bytes().as_slice(),
                    capability_digest.as_bytes().as_slice(),
                ],
            )
            .expect("comparison fixture inserts");
        connection
            .execute(
                "INSERT INTO budget_reservations VALUES (?1, ?2, 'EUR', \
                 'price-table:fixture-1', 0, 1, 0, 4096)",
                params![
                    "operation:00000000-0000-4000-8000-000000000001",
                    lease_digest.as_bytes().as_slice(),
                ],
            )
            .expect("reservation fixture inserts");
        connection
            .execute(
                "INSERT INTO preparation_recovery_evidence (\
                     operation_id, evidence_version, recovery_mode, recovery_class, atomicity, \
                     risk_level, target_reference_digest, precondition_identity_digest, \
                     precondition_digest, precondition_length, reserved_capacity, \
                     provider_profile_id, provider_profile_version, provider_id, \
                     provider_generation, evidence_class, at_rest_profile_id, \
                     capability_binding_digest, material_id, publication_attempt_id, \
                     manifest_digest, material_digest, material_length, material_state, \
                     retirement_id, retirement_manifest_digest, retirement_generation, \
                     boot_binding_digest, instance_epoch, fencing_epoch\
                 ) VALUES (\
                     ?1, 1, 'COMPENSATION', 'COMPENSATION', 'ATOMIC_REPLACE', 'L1', \
                     ?2, ?3, ?4, 7, 4096, 'recovery-profile:fixture-v1', 1, \
                     'recovery-provider:fixture-v1', 1, 'SYNTHETIC_CONFORMANCE', \
                     'at-rest:fixture-v1', ?5, ?6, ?7, ?8, ?4, 7, 'PUBLISHED', \
                     NULL, NULL, NULL, ?9, 1, 9)",
                params![
                    "operation:00000000-0000-4000-8000-000000000001",
                    target_reference_digest.as_bytes().as_slice(),
                    precondition_identity_digest.as_bytes().as_slice(),
                    precondition_digest.as_bytes().as_slice(),
                    capability_digest.as_bytes().as_slice(),
                    [0x21_u8; 32].as_slice(),
                    [0x22_u8; 32].as_slice(),
                    [0x23_u8; 32].as_slice(),
                    boot_binding_digest.as_bytes().as_slice(),
                ],
            )
            .expect("recovery fixture inserts");

        let resolver = HistoricalFixtureResolver {
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            verify_historical_canonical_plans(&connection, &resolver).unwrap(),
            1
        );
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            verify_recovery_immutable_bindings(&connection, &resolver).unwrap(),
            1
        );
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);
        assert!(
            verify_historical_canonical_plans(&connection, &UnknownHistoricalResolver).is_err()
        );
        assert!(verify_historical_canonical_plans(&connection, &WrongHistoricalResolver).is_err());

        connection
            .execute(
                "UPDATE preparation_recovery_evidence SET target_reference_digest = ?1",
                [[0x99_u8; 32].as_slice()],
            )
            .expect("canonical target binding corrupts");
        assert!(verify_recovery_immutable_bindings(&connection, &resolver).is_err());
        connection
            .execute(
                "UPDATE preparation_recovery_evidence SET target_reference_digest = ?1",
                [target_reference_digest.as_bytes().as_slice()],
            )
            .expect("canonical target binding restores");

        connection
            .execute(
                "UPDATE preparation_recovery_evidence SET reserved_capacity = 4095",
                [],
            )
            .expect("signed recovery capacity corrupts");
        assert!(verify_recovery_immutable_bindings(&connection, &resolver).is_err());
        connection
            .execute(
                "UPDATE preparation_recovery_evidence SET reserved_capacity = 4096, \
                 material_state = 'RETIREMENT_PENDING', retirement_id = ?1, \
                 retirement_generation = 2",
                [[0x31_u8; 32].as_slice()],
            )
            .expect("recovery lifecycle advances without immutable mutation");
        verify_recovery_immutable_bindings(&connection, &resolver)
            .expect("retirement-pending lifecycle preserves immutable evidence");
        connection
            .execute(
                "UPDATE preparation_recovery_evidence \
                 SET material_state = 'RETIRED_TOMBSTONE', \
                     retirement_manifest_digest = ?1",
                [[0x32_u8; 32].as_slice()],
            )
            .expect("recovery lifecycle reaches retained tombstone");
        verify_recovery_immutable_bindings(&connection, &resolver)
            .expect("retired lifecycle preserves immutable evidence");
        connection
            .execute(
                "UPDATE preparation_recovery_evidence SET material_state = 'PUBLISHED', \
                 retirement_id = NULL, retirement_manifest_digest = NULL, \
                 retirement_generation = NULL",
                [],
            )
            .expect("isolated fixture restores published lifecycle");

        connection
            .execute(
                "UPDATE preparation_recovery_evidence SET material_length = 8",
                [],
            )
            .expect("material length corrupts");
        assert!(verify_historical_canonical_plans(&connection, &resolver).is_err());
        connection
            .execute(
                "UPDATE preparation_recovery_evidence SET material_length = 7",
                [],
            )
            .expect("material length restores");

        let mut bad_signature = FIXTURE_PLAN.to_vec();
        let signature_prefix = b"\"signature\":\"";
        let signature_start = bad_signature
            .windows(signature_prefix.len())
            .position(|window| window == signature_prefix)
            .expect("signature field exists")
            + signature_prefix.len();
        bad_signature[signature_start] = if bad_signature[signature_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        connection
            .execute(
                "UPDATE prepared_operations SET canonical_plan = ?1, \
                 canonical_plan_length = ?2",
                params![
                    bad_signature,
                    i64::try_from(FIXTURE_PLAN.len()).expect("fixture length fits")
                ],
            )
            .expect("signature corrupts");
        assert!(verify_historical_canonical_plans(&connection, &resolver).is_err());

        let mut noncanonical = FIXTURE_PLAN.to_vec();
        noncanonical.push(b'\n');
        connection
            .execute(
                "UPDATE prepared_operations SET canonical_plan = ?1, \
                 canonical_plan_length = ?2",
                params![
                    noncanonical,
                    i64::try_from(FIXTURE_PLAN.len() + 1).expect("fixture length fits")
                ],
            )
            .expect("noncanonical wire stores");
        assert!(verify_historical_canonical_plans(&connection, &resolver).is_err());
    }

    #[test]
    fn comparison_digest_projection_is_an_explicit_immutable_allow_list() {
        for mutable_column in [
            "operation.operation_state",
            "operation.state_generation",
            "operation.failed_generation",
            "operation.failed_reason_code",
            "operation.current_event_id",
            "scope.held_cost_micro_units",
            "scope.held_action_count",
            "scope.held_egress_bytes",
            "scope.held_recovery_bytes",
            "reservation.reservation_state",
            "reservation.released_generation",
            "recovery.material_state",
            "recovery.retirement_id",
            "recovery.retirement_manifest_digest",
            "recovery.retirement_generation",
        ] {
            assert!(
                !IMMUTABLE_COMPARISON_DIGEST_PROJECTION_V1_SQL.contains(mutable_column),
                "mutable lifecycle column leaked into comparison digest: {mutable_column}",
            );
        }
        for immutable_column in [
            "comparison.capture_generation",
            "operation.attempt_id",
            "scope.allowance_binding_digest",
            "reservation.created_generation",
            "recovery.precondition_digest",
        ] {
            assert!(
                IMMUTABLE_COMPARISON_DIGEST_PROJECTION_V1_SQL.contains(immutable_column),
                "immutable binding missing from comparison digest: {immutable_column}",
            );
        }
    }

    #[test]
    fn preparing_operation_keeps_store_and_state_generations_distinct_and_rejects_surplus_graph() {
        let connection = Connection::open_in_memory().expect("memory database opens");
        connection
            .execute_batch(
                "CREATE TABLE prepared_operations (\
                     operation_id TEXT PRIMARY KEY, state_generation INTEGER NOT NULL, \
                     created_generation INTEGER NOT NULL, operation_state TEXT NOT NULL, \
                     failed_generation INTEGER, failed_reason_code TEXT, \
                     current_event_id BLOB NOT NULL\
                 ) STRICT, WITHOUT ROWID; \
                 CREATE TABLE operation_transitions (\
                     state_generation INTEGER PRIMARY KEY, operation_id TEXT NOT NULL, \
                     previous_state TEXT, new_state TEXT NOT NULL, event_id BLOB NOT NULL\
                 ) STRICT, WITHOUT ROWID; \
                 CREATE TABLE preparation_events (\
                     event_id BLOB PRIMARY KEY, operation_id TEXT NOT NULL, \
                     operation_state_generation INTEGER NOT NULL, operation_state TEXT NOT NULL, \
                     event_kind TEXT NOT NULL, reason_code TEXT\
                 ) STRICT, WITHOUT ROWID;",
            )
            .expect("minimal transition schema creates");
        connection
            .execute(
                "INSERT INTO prepared_operations VALUES \
                 ('operation:1', 1, 7, 'PREPARING', NULL, NULL, ?1)",
                [[1_u8; 32].as_slice()],
            )
            .expect("operation inserts");
        // Store generation 7 is intentionally independent from state generation 1.
        connection
            .execute(
                "INSERT INTO operation_transitions VALUES \
                 (1, 'operation:1', NULL, 'PREPARING', ?1)",
                [[1_u8; 32].as_slice()],
            )
            .expect("initial transition inserts");
        connection
            .execute(
                "INSERT INTO preparation_events VALUES \
                 (?1, 'operation:1', 1, 'PREPARING', 'PREPARED', NULL)",
                [[1_u8; 32].as_slice()],
            )
            .expect("initial event inserts");
        verify_transition_graph(&connection).expect("exact preparing graph verifies");

        connection
            .execute(
                "INSERT INTO operation_transitions VALUES \
                 (2, 'operation:1', 'PREPARING', 'FAILED', ?1)",
                [[2_u8; 32].as_slice()],
            )
            .expect("surplus failed transition inserts");
        connection
            .execute(
                "INSERT INTO preparation_events VALUES \
                 (?1, 'operation:1', 2, 'FAILED', 'PREPARATION_FAILED', 'FAILED')",
                [[2_u8; 32].as_slice()],
            )
            .expect("surplus failed event inserts");
        assert!(verify_transition_graph(&connection).is_err());
    }

    #[test]
    fn exact_generation_high_water_rejects_release_duplicates_inflation_and_missing_last_rows() {
        let connection = Connection::open_in_memory().expect("memory database opens");
        connection
            .execute_batch(
                "CREATE TABLE operation_transitions (state_generation INTEGER) STRICT; \
                 CREATE TABLE budget_scopes (scope_generation INTEGER) STRICT; \
                 CREATE TABLE budget_reservations (\
                     budget_generation INTEGER, created_generation INTEGER, \
                     released_generation INTEGER\
                 ) STRICT; \
                 CREATE TABLE preparation_events (\
                     event_generation INTEGER, delivered_generation INTEGER\
                 ) STRICT; \
                 CREATE TABLE preparation_quarantines (\
                     created_generation INTEGER, resolved_generation INTEGER, \
                     orphan_retired_generation INTEGER\
                 ) STRICT; \
                 CREATE TABLE prepared_operations (\
                     created_generation INTEGER, failed_generation INTEGER\
                 ) STRICT; \
                 CREATE TABLE preparation_recovery_evidence (retirement_generation INTEGER) \
                 STRICT; \
                 INSERT INTO operation_transitions VALUES (1); \
                 INSERT INTO budget_scopes VALUES (1); \
                 INSERT INTO budget_reservations VALUES (1, 2, 3); \
                 INSERT INTO preparation_events VALUES (1, 3); \
                 INSERT INTO prepared_operations VALUES (2, 3); \
                 INSERT INTO preparation_recovery_evidence VALUES (NULL);",
            )
            .expect("generation fixture inserts");
        let metadata = CoordinatorStoreMetadataRow {
            store_generation: 3,
            operation_generation: 1,
            budget_generation: 3,
            event_generation: 1,
            quarantine_generation: 0,
            root_identity: CoordinatorRootIdentityV1::from_bytes([1_u8; 32]),
            root_lifecycle: RootLifecycleV1::Active,
        };
        verify_generation_high_water(&connection, metadata)
            .expect("exact release high-water verifies");

        let inflated = CoordinatorStoreMetadataRow {
            store_generation: 4,
            ..metadata
        };
        assert!(verify_generation_high_water(&connection, inflated).is_err());
        connection
            .execute("DELETE FROM preparation_events", [])
            .expect("last event deletes");
        assert!(verify_generation_high_water(&connection, metadata).is_err());
        connection
            .execute("INSERT INTO preparation_events VALUES (1, 3)", [])
            .expect("event restores");
        connection
            .execute("DELETE FROM operation_transitions", [])
            .expect("last transition deletes");
        assert!(verify_generation_high_water(&connection, metadata).is_err());

        connection
            .execute("INSERT INTO operation_transitions VALUES (1)", [])
            .expect("transition restores");
        connection
            .execute("INSERT INTO budget_scopes VALUES (2)", [])
            .expect("duplicate budget transition generation inserts");
        assert!(verify_generation_high_water(&connection, metadata).is_err());
    }
}
