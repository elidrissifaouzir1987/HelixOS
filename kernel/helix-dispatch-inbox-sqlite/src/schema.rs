//! Exact create-only adapter inbox schema and durable invariant verification.

#![allow(dead_code)]

use crate::config::{AdapterInboxInitializationV1, AdapterInboxRootIdentityEvidenceV1};
use crate::connection::AdapterInboxStoreOpenErrorV1;
use crate::quarantine::ensure_no_active_global_adapter_corruption_quarantine_v1;
use crate::root_safety::AdapterRootIdentityV1;
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest as _, Sha256};

pub const ADAPTER_INBOX_APPLICATION_ID_V1: i64 = 1212962889;
pub const ADAPTER_INBOX_SCHEMA_VERSION_V1: i64 = 1;
pub const ADAPTER_INBOX_FORMAT_VERSION_V1: i64 = 1;
pub const ADAPTER_INBOX_SCHEMA_V1_SQL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/005-durable-dispatch/contracts/adapter-inbox-schema-v1.sql"
));

const ADAPTER_INBOX_SCHEMA_V1_SHA256: [u8; 32] = [
    0xf6, 0xd4, 0x91, 0x71, 0x75, 0x03, 0x8f, 0xf7, 0x26, 0xec, 0x6d, 0x27, 0xa1, 0xc5, 0x9d, 0xe7,
    0x21, 0x0f, 0x58, 0xa1, 0x07, 0x9c, 0xf4, 0x28, 0x58, 0x61, 0x30, 0x86, 0x2c, 0x05, 0x07, 0x24,
];
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const RESTORE_RECONCILIATION_QUARANTINE_ID_DOMAIN_V1: &[u8] =
    b"HELIXOS\0DISPATCH-RESTORE\0ADAPTER-QUARANTINE-ID\0V1\0";
const RESTORE_RECONCILIATION_EVIDENCE_DOMAIN_V1: &[u8] =
    b"HELIXOS\0DISPATCH-RESTORE\0ADAPTER-RECONCILIATION\0V1\0";
const RESTORE_RECONCILIATION_GRANT_SET_DOMAIN_V1: &[u8] =
    b"HELIXOS\0DISPATCH-RESTORE\0ADAPTER-RECONCILIATION-GRANT-SET\0V1\0";
const RESTORE_RECONCILIATION_REASON_V1: &str = "RESTORE_RECONCILIATION_REQUIRED";

const REQUIRED_PERMANENT_HISTORY_DELETE_GUARDS_V1: &[(&str, &str)] = &[
    ("adapter_store_meta_no_delete", "adapter_store_meta"),
    ("grant_inbox_no_delete", "grant_inbox"),
    ("inbox_transitions_no_delete", "inbox_transitions"),
    ("execution_receipts_no_delete", "execution_receipts"),
    ("inbox_conflicts_no_delete", "inbox_conflicts"),
    ("inbox_quarantines_no_delete", "inbox_quarantines"),
    ("adapter_events_no_delete", "adapter_events"),
];

const REQUIRED_PERMANENT_HISTORY_GENERATION_INDEXES_V1: &[(&str, &str, &str)] = &[
    (
        "grant_inbox_received_generation_uq",
        "grant_inbox",
        "received_generation",
    ),
    (
        "grant_inbox_current_generation_uq",
        "grant_inbox",
        "current_generation",
    ),
    (
        "execution_receipts_generation_uq",
        "execution_receipts",
        "receipt_generation",
    ),
    (
        "inbox_conflicts_generation_uq",
        "inbox_conflicts",
        "conflict_generation",
    ),
    (
        "inbox_quarantines_generation_uq",
        "inbox_quarantines",
        "quarantine_generation",
    ),
    (
        "adapter_events_generation_uq",
        "adapter_events",
        "event_generation",
    ),
];

/// Closed PLAN-005 v1 retention and storage-claim policy for the adapter inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterInboxRetentionPolicyV1 {
    history_is_permanent: bool,
    history_is_append_only: bool,
    history_deletion_enabled: bool,
    identifier_reuse_enabled: bool,
    generation_reuse_enabled: bool,
    automatic_pruning_enabled: bool,
    physical_secure_erasure_claimed: bool,
    requires_approved_encrypted_at_rest_profile: bool,
}

impl AdapterInboxRetentionPolicyV1 {
    pub(crate) const fn history_is_permanent(self) -> bool {
        self.history_is_permanent
    }

    pub(crate) const fn history_is_append_only(self) -> bool {
        self.history_is_append_only
    }

    pub(crate) const fn history_deletion_enabled(self) -> bool {
        self.history_deletion_enabled
    }

    pub(crate) const fn identifier_reuse_enabled(self) -> bool {
        self.identifier_reuse_enabled
    }

    pub(crate) const fn generation_reuse_enabled(self) -> bool {
        self.generation_reuse_enabled
    }

    pub(crate) const fn automatic_pruning_enabled(self) -> bool {
        self.automatic_pruning_enabled
    }

    pub(crate) const fn physical_secure_erasure_claimed(self) -> bool {
        self.physical_secure_erasure_claimed
    }

    pub(crate) const fn requires_approved_encrypted_at_rest_profile(self) -> bool {
        self.requires_approved_encrypted_at_rest_profile
    }
}

pub(crate) const fn adapter_inbox_retention_policy_v1() -> AdapterInboxRetentionPolicyV1 {
    AdapterInboxRetentionPolicyV1 {
        history_is_permanent: true,
        history_is_append_only: true,
        history_deletion_enabled: false,
        identifier_reuse_enabled: false,
        generation_reuse_enabled: false,
        automatic_pruning_enabled: false,
        physical_secure_erasure_claimed: false,
        requires_approved_encrypted_at_rest_profile: true,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterRootLifecycleStateV1 {
    Active,
    RestorePending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterInboxStoreSummaryV1 {
    pub(crate) root_identity: AdapterInboxRootIdentityEvidenceV1,
    pub(crate) root_lifecycle_state: AdapterRootLifecycleStateV1,
    pub(crate) store_generation: u64,
    pub(crate) inbox_generation: u64,
    pub(crate) consumption_generation: u64,
    pub(crate) receipt_generation: u64,
    pub(crate) conflict_generation: u64,
    pub(crate) quarantine_generation: u64,
    pub(crate) event_generation: u64,
    pub(crate) supervisor_epoch: u64,
    pub(crate) epoch_observer_generation: u64,
    pub(crate) inbox_count: u64,
    pub(crate) receipt_count: u64,
}

/// Exact source and rotated metadata for the sole adapter ACTIVE -> RESTORE_PENDING edge.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdapterRestorePendingBindingsV1 {
    expected_source: AdapterInboxStoreSummaryV1,
    new_root_identity: AdapterRootIdentityV1,
    new_supervisor_epoch: u64,
    new_epoch_observer_generation: u64,
    restore_index_digest: [u8; 32],
    pause_evidence_digest: [u8; 32],
}

impl AdapterRestorePendingBindingsV1 {
    pub(crate) fn try_new(
        expected_source: AdapterInboxStoreSummaryV1,
        new_root_identity: AdapterRootIdentityV1,
        new_supervisor_epoch: u64,
        new_epoch_observer_generation: u64,
        restore_index_digest: [u8; 32],
        pause_evidence_digest: [u8; 32],
    ) -> Result<Self, AdapterInboxStoreOpenErrorV1> {
        if expected_source.root_lifecycle_state != AdapterRootLifecycleStateV1::Active
            || expected_source.root_identity.into_internal() == new_root_identity
            || expected_source.store_generation >= MAX_SAFE_INTEGER
            || expected_source.supervisor_epoch > MAX_SAFE_INTEGER
            || new_supervisor_epoch > MAX_SAFE_INTEGER
            || new_supervisor_epoch <= expected_source.supervisor_epoch
            || expected_source.epoch_observer_generation > MAX_SAFE_INTEGER
            || new_epoch_observer_generation > MAX_SAFE_INTEGER
            || new_epoch_observer_generation <= expected_source.epoch_observer_generation
            || restore_index_digest == [0; 32]
            || pause_evidence_digest == [0; 32]
        {
            return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
        }
        Ok(Self {
            expected_source,
            new_root_identity,
            new_supervisor_epoch,
            new_epoch_observer_generation,
            restore_index_digest,
            pause_evidence_digest,
        })
    }

    pub(crate) const fn expected_source(self) -> AdapterInboxStoreSummaryV1 {
        self.expected_source
    }

    pub(crate) const fn new_root_identity(self) -> AdapterRootIdentityV1 {
        self.new_root_identity
    }

    pub(crate) const fn new_supervisor_epoch(self) -> u64 {
        self.new_supervisor_epoch
    }

    pub(crate) const fn new_epoch_observer_generation(self) -> u64 {
        self.new_epoch_observer_generation
    }

    pub(crate) const fn restore_index_digest(self) -> [u8; 32] {
        self.restore_index_digest
    }

    pub(crate) const fn pause_evidence_digest(self) -> [u8; 32] {
        self.pause_evidence_digest
    }
}

impl std::fmt::Debug for AdapterRestorePendingBindingsV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterRestorePendingBindingsV1")
            .finish_non_exhaustive()
    }
}

/// Non-authoritative proof that one exact imported adapter cut is durably pending.
#[derive(Clone)]
pub(crate) struct VerifiedAdapterRestorePendingV1 {
    summary: AdapterInboxStoreSummaryV1,
    reconciliation_proof_count: u64,
    reconciliation_grant_set_digest: [u8; 32],
    reconciliation_grant_ids: Box<[[u8; 32]]>,
}

impl VerifiedAdapterRestorePendingV1 {
    pub(crate) const fn summary(&self) -> AdapterInboxStoreSummaryV1 {
        self.summary
    }

    pub(crate) const fn reconciliation_proof_count(&self) -> u64 {
        self.reconciliation_proof_count
    }

    pub(crate) const fn reconciliation_grant_set_digest(&self) -> [u8; 32] {
        self.reconciliation_grant_set_digest
    }

    pub(crate) fn reconciliation_grant_ids(&self) -> &[[u8; 32]] {
        &self.reconciliation_grant_ids
    }
}

impl std::fmt::Debug for VerifiedAdapterRestorePendingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAdapterRestorePendingV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SchemaObjectV1 {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

#[derive(Clone, Copy)]
struct MetadataV1 {
    root_identity: AdapterRootIdentityV1,
    lifecycle: AdapterRootLifecycleStateV1,
    store_generation: u64,
    inbox_generation: u64,
    consumption_generation: u64,
    receipt_generation: u64,
    conflict_generation: u64,
    quarantine_generation: u64,
    event_generation: u64,
    supervisor_epoch: u64,
    epoch_observer_generation: u64,
}

pub fn embedded_adapter_inbox_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(ADAPTER_INBOX_SCHEMA_V1_SQL.as_bytes()).into()
}

/// Verifies the adapter's permanent authority history and returns the closed policy.
///
/// The exact-schema proof covers table constraints and identifier keys; the explicit
/// retention inventory additionally checks every delete guard and unique generation
/// index before comparing retained rows with the metadata high-water values.
pub(crate) fn verify_permanent_adapter_history_v1(
    connection: &Connection,
    expected_root_identity: AdapterRootIdentityV1,
) -> Result<AdapterInboxRetentionPolicyV1, AdapterInboxStoreOpenErrorV1> {
    verify_exact_schema(connection)?;
    verify_permanent_adapter_schema_objects_v1(connection)?;
    let metadata = decode_metadata(connection, expected_root_identity)?;
    verify_generation_high_water(connection, metadata)?;
    Ok(adapter_inbox_retention_policy_v1())
}

pub(crate) fn initialize_empty_schema(
    connection: &mut Connection,
    root_identity: AdapterRootIdentityV1,
    initial: AdapterInboxInitializationV1,
) -> Result<AdapterInboxStoreSummaryV1, AdapterInboxStoreOpenErrorV1> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| AdapterInboxStoreOpenErrorV1::RootUnavailable)?;
    transaction
        .execute_batch(ADAPTER_INBOX_SCHEMA_V1_SQL)
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)?;
    transaction
        .execute(
            "INSERT INTO adapter_store_meta (
                singleton, format_version, store_generation, inbox_generation,
                consumption_generation, receipt_generation, conflict_generation,
                quarantine_generation, event_generation, root_identity,
                root_lifecycle_state, supervisor_epoch, epoch_observer_generation,
                ordinary_queue_capacity, control_queue_capacity,
                receipt_signer_profile_digest, restore_index_digest,
                restore_state_generation
             ) VALUES (
                1, 1, 0, 0, 0, 0, 0, 0, 0, ?1,
                'ACTIVE', ?2, ?3, 1024, 32, ?4, NULL, 0
             )",
            params![
                root_identity.as_bytes().as_slice(),
                i64::try_from(initial.supervisor_epoch())
                    .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?,
                i64::try_from(initial.epoch_observer_generation())
                    .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?,
                initial.receipt_signer_profile_digest().as_slice(),
            ],
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let summary = verify_full(&transaction, root_identity)?;
    transaction
        .commit()
        .map_err(|_| AdapterInboxStoreOpenErrorV1::RootUnavailable)?;
    Ok(summary)
}

/// Verifies exact identity/version/object SQL, physical integrity, foreign keys and all
/// cross-record projections. Unknown future versions are refused distinctly.
pub(crate) fn verify_full(
    connection: &Connection,
    expected_root_identity: AdapterRootIdentityV1,
) -> Result<AdapterInboxStoreSummaryV1, AdapterInboxStoreOpenErrorV1> {
    verify_exact_schema(connection)?;
    verify_permanent_adapter_schema_objects_v1(connection)?;
    verify_integrity_check(connection)?;
    verify_foreign_key_check(connection)?;
    let metadata = decode_metadata(connection, expected_root_identity)?;
    verify_generation_high_water(connection, metadata)?;
    verify_cross_record_invariants(connection)?;
    ensure_no_active_global_adapter_corruption_quarantine_v1(connection)
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;

    Ok(AdapterInboxStoreSummaryV1 {
        root_identity: AdapterInboxRootIdentityEvidenceV1::from_internal(metadata.root_identity),
        root_lifecycle_state: metadata.lifecycle,
        store_generation: metadata.store_generation,
        inbox_generation: metadata.inbox_generation,
        consumption_generation: metadata.consumption_generation,
        receipt_generation: metadata.receipt_generation,
        conflict_generation: metadata.conflict_generation,
        quarantine_generation: metadata.quarantine_generation,
        event_generation: metadata.event_generation,
        supervisor_epoch: metadata.supervisor_epoch,
        epoch_observer_generation: metadata.epoch_observer_generation,
        inbox_count: table_count(connection, "grant_inbox")?,
        receipt_count: table_count(connection, "execution_receipts")?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestoreReconciliationProofV1 {
    quarantine_id: [u8; 32],
    grant_id: [u8; 32],
    evidence_digest: [u8; 32],
    quarantine_generation: u64,
}

struct RestoreReconciliationReadbackV1 {
    proof_count: u64,
    grant_set_digest: [u8; 32],
    grant_ids: Box<[[u8; 32]]>,
}

/// Atomically retains restore reconciliation proofs and rotates the imported root into
/// non-activatable custody. The source grant history is never rewritten.
pub(crate) fn transition_imported_backup_to_restore_pending_v1(
    connection: &mut Connection,
    bindings: AdapterRestorePendingBindingsV1,
) -> Result<VerifiedAdapterRestorePendingV1, AdapterInboxStoreOpenErrorV1> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| AdapterInboxStoreOpenErrorV1::RootUnavailable)?;
    let source_identity = bindings.expected_source.root_identity.into_internal();
    let source = verify_full(&transaction, source_identity)?;
    if source != bindings.expected_source {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }

    let proofs = derive_restore_reconciliation_proofs_v1(&transaction, bindings)?;
    let proof_count =
        u64::try_from(proofs.len()).map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let (next_store_generation, next_quarantine_generation) =
        restore_pending_generations_v1(bindings, proof_count)?;
    for proof in &proofs {
        let inserted = transaction
            .execute(
                "INSERT INTO inbox_quarantines (
                     quarantine_id, grant_id, evidence_digest, public_reason_code,
                     quarantine_generation, resolved_generation
                 ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                params![
                    proof.quarantine_id.as_slice(),
                    proof.grant_id.as_slice(),
                    proof.evidence_digest.as_slice(),
                    RESTORE_RECONCILIATION_REASON_V1,
                    to_i64(proof.quarantine_generation)?,
                ],
            )
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        if inserted != 1 {
            return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
        }
    }
    let changed = transaction
        .execute(
            "UPDATE adapter_store_meta SET
                 store_generation = ?1,
                 quarantine_generation = ?2,
                 root_identity = ?3,
                 root_lifecycle_state = 'RESTORE_PENDING',
                 supervisor_epoch = ?4,
                 epoch_observer_generation = ?5,
                 restore_index_digest = ?6,
                 restore_state_generation = ?1
             WHERE singleton = 1
               AND store_generation = ?7
               AND inbox_generation = ?8
               AND consumption_generation = ?9
               AND receipt_generation = ?10
               AND conflict_generation = ?11
               AND quarantine_generation = ?12
               AND event_generation = ?13
               AND root_identity = ?14
               AND root_lifecycle_state = 'ACTIVE'
               AND supervisor_epoch = ?15
               AND epoch_observer_generation = ?16
               AND restore_index_digest IS NULL
               AND restore_state_generation = 0",
            params![
                to_i64(next_store_generation)?,
                to_i64(next_quarantine_generation)?,
                bindings.new_root_identity.as_bytes().as_slice(),
                to_i64(bindings.new_supervisor_epoch)?,
                to_i64(bindings.new_epoch_observer_generation)?,
                bindings.restore_index_digest.as_slice(),
                to_i64(source.store_generation)?,
                to_i64(source.inbox_generation)?,
                to_i64(source.consumption_generation)?,
                to_i64(source.receipt_generation)?,
                to_i64(source.conflict_generation)?,
                to_i64(source.quarantine_generation)?,
                to_i64(source.event_generation)?,
                source.root_identity.to_attested_bytes().as_slice(),
                to_i64(source.supervisor_epoch)?,
                to_i64(source.epoch_observer_generation)?,
            ],
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    if changed != 1 {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }

    let verified = verify_restore_pending_v1(&transaction, bindings)?;
    transaction
        .commit()
        .map_err(|_| AdapterInboxStoreOpenErrorV1::RootUnavailable)?;
    Ok(verified)
}

/// Strict maintenance-only readback of one exact pending adapter root.
pub(crate) fn verify_restore_pending_v1(
    connection: &Connection,
    bindings: AdapterRestorePendingBindingsV1,
) -> Result<VerifiedAdapterRestorePendingV1, AdapterInboxStoreOpenErrorV1> {
    let proofs = derive_restore_reconciliation_proofs_v1(connection, bindings)?;
    let proof_count =
        u64::try_from(proofs.len()).map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let (restore_state_generation, quarantine_generation) =
        restore_pending_generations_v1(bindings, proof_count)?;
    let summary = verify_full(connection, bindings.new_root_identity)?;
    let source = bindings.expected_source;
    if summary.root_lifecycle_state != AdapterRootLifecycleStateV1::RestorePending
        || summary.store_generation != restore_state_generation
        || summary.inbox_generation != source.inbox_generation
        || summary.consumption_generation != source.consumption_generation
        || summary.receipt_generation != source.receipt_generation
        || summary.conflict_generation != source.conflict_generation
        || summary.quarantine_generation != quarantine_generation
        || summary.event_generation != source.event_generation
        || summary.supervisor_epoch != bindings.new_supervisor_epoch
        || summary.epoch_observer_generation != bindings.new_epoch_observer_generation
        || summary.inbox_count != source.inbox_count
        || summary.receipt_count != source.receipt_count
    {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    let (restore_index_digest, restore_state_generation): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT restore_index_digest, restore_state_generation
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    if restore_index_digest.as_slice() != bindings.restore_index_digest.as_slice()
        || strict_safe_i64(restore_state_generation)? != summary.store_generation
    {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    let persisted = verify_restore_reconciliation_proofs_v1(connection, bindings, &proofs)?;
    Ok(VerifiedAdapterRestorePendingV1 {
        summary,
        reconciliation_proof_count: persisted.proof_count,
        reconciliation_grant_set_digest: persisted.grant_set_digest,
        reconciliation_grant_ids: persisted.grant_ids,
    })
}

fn derive_restore_reconciliation_proofs_v1(
    connection: &Connection,
    bindings: AdapterRestorePendingBindingsV1,
) -> Result<Vec<RestoreReconciliationProofV1>, AdapterInboxStoreOpenErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT grant_id, inbox_state FROM grant_inbox
             WHERE inbox_state IN ('RECEIVED', 'CONSUMED', 'QUARANTINED')
             ORDER BY grant_id",
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let mut proofs = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?
    {
        let grant_id = row
            .get::<_, Vec<u8>>(0)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?
            .try_into()
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let source_state = row
            .get::<_, String>(1)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        if !matches!(
            source_state.as_str(),
            "RECEIVED" | "CONSUMED" | "QUARANTINED"
        ) {
            return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
        }
        let ordinal = u64::try_from(proofs.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let quarantine_generation = bindings
            .expected_source
            .store_generation
            .checked_add(ordinal)
            .filter(|value| *value <= MAX_SAFE_INTEGER)
            .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let evidence_digest =
            restore_reconciliation_evidence_digest_v1(bindings, grant_id, source_state.as_bytes());
        let mut id_hasher = Sha256::new();
        id_hasher.update(RESTORE_RECONCILIATION_QUARANTINE_ID_DOMAIN_V1);
        id_hasher.update(evidence_digest);
        proofs.push(RestoreReconciliationProofV1 {
            quarantine_id: id_hasher.finalize().into(),
            grant_id,
            evidence_digest,
            quarantine_generation,
        });
    }
    if u64::try_from(proofs.len()).ok().is_none_or(|count| {
        count > bindings.expected_source.inbox_count
            || bindings
                .expected_source
                .store_generation
                .checked_add(count)
                .and_then(|value| value.checked_add(1))
                .is_none_or(|value| value > MAX_SAFE_INTEGER)
    }) {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    Ok(proofs)
}

fn restore_reconciliation_evidence_digest_v1(
    bindings: AdapterRestorePendingBindingsV1,
    grant_id: [u8; 32],
    source_state: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RESTORE_RECONCILIATION_EVIDENCE_DOMAIN_V1);
    hasher.update(bindings.expected_source.root_identity.to_attested_bytes());
    hasher.update(bindings.expected_source.supervisor_epoch.to_be_bytes());
    hasher.update(bindings.new_root_identity.as_bytes());
    hasher.update(bindings.new_supervisor_epoch.to_be_bytes());
    hasher.update(bindings.new_epoch_observer_generation.to_be_bytes());
    hasher.update(bindings.restore_index_digest);
    hasher.update(bindings.pause_evidence_digest);
    hasher.update(grant_id);
    hasher.update((source_state.len() as u64).to_be_bytes());
    hasher.update(source_state);
    hasher.finalize().into()
}

fn restore_pending_generations_v1(
    bindings: AdapterRestorePendingBindingsV1,
    proof_count: u64,
) -> Result<(u64, u64), AdapterInboxStoreOpenErrorV1> {
    let last_proof_generation = bindings
        .expected_source
        .store_generation
        .checked_add(proof_count)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let restore_state_generation = last_proof_generation
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let quarantine_generation = if proof_count == 0 {
        bindings.expected_source.quarantine_generation
    } else {
        last_proof_generation
    };
    Ok((restore_state_generation, quarantine_generation))
}

fn verify_restore_reconciliation_proofs_v1(
    connection: &Connection,
    bindings: AdapterRestorePendingBindingsV1,
    expected: &[RestoreReconciliationProofV1],
) -> Result<RestoreReconciliationReadbackV1, AdapterInboxStoreOpenErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT quarantine_id, grant_id, evidence_digest, public_reason_code,
                    quarantine_generation, resolved_generation
             FROM inbox_quarantines
             WHERE quarantine_generation > ?1
             ORDER BY quarantine_generation, quarantine_id",
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let mut rows = statement
        .query([to_i64(bindings.expected_source.quarantine_generation)?])
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let mut persisted_count = 0_u64;
    let mut persisted_grant_ids = Vec::with_capacity(expected.len());
    for proof in expected {
        let row = rows
            .next()
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?
            .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let quarantine_id = row
            .get::<_, Vec<u8>>(0)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let grant_id = row
            .get::<_, Option<Vec<u8>>>(1)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let evidence_digest = row
            .get::<_, Vec<u8>>(2)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let reason = row
            .get::<_, String>(3)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let generation = row
            .get::<_, i64>(4)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let resolved_generation = row
            .get::<_, Option<i64>>(5)
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        let grant_id: [u8; 32] = grant_id
            .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?
            .try_into()
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        if quarantine_id.as_slice() != proof.quarantine_id.as_slice()
            || grant_id != proof.grant_id
            || evidence_digest.as_slice() != proof.evidence_digest.as_slice()
            || reason != RESTORE_RECONCILIATION_REASON_V1
            || strict_safe_i64(generation)? != proof.quarantine_generation
            || resolved_generation.is_some()
        {
            return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
        }
        persisted_count = persisted_count
            .checked_add(1)
            .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        persisted_grant_ids.push(grant_id);
    }
    if rows
        .next()
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?
        .is_some()
    {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    persisted_grant_ids.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(RESTORE_RECONCILIATION_GRANT_SET_DOMAIN_V1);
    hasher.update(persisted_count.to_be_bytes());
    for grant_id in &persisted_grant_ids {
        hasher.update(grant_id);
    }
    Ok(RestoreReconciliationReadbackV1 {
        proof_count: persisted_count,
        grant_set_digest: hasher.finalize().into(),
        grant_ids: persisted_grant_ids.into_boxed_slice(),
    })
}

pub(crate) fn verify_exact_schema(
    connection: &Connection,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    if embedded_adapter_inbox_schema_v1_sha256() != ADAPTER_INBOX_SCHEMA_V1_SHA256 {
        return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
    }
    verify_application_and_version(connection)?;
    let actual = read_schema_objects(connection)?;
    let expected_connection =
        Connection::open_in_memory().map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)?;
    expected_connection
        .execute_batch(ADAPTER_INBOX_SCHEMA_V1_SQL)
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)?;
    let expected = read_schema_objects(&expected_connection)?;
    if actual != expected {
        return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
    }
    Ok(())
}

fn verify_permanent_adapter_schema_objects_v1(
    connection: &Connection,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    for (trigger_name, table_name) in REQUIRED_PERMANENT_HISTORY_DELETE_GUARDS_V1 {
        let object = named_schema_object_v1(connection, "trigger", trigger_name)?;
        let delete_clause = format!("BEFORE DELETE ON {table_name}");
        if object.table_name != *table_name
            || !object.sql.contains(&delete_clause)
            || !object.sql.contains("RAISE(ABORT")
        {
            return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
        }
    }
    for (index_name, table_name, generation_column) in
        REQUIRED_PERMANENT_HISTORY_GENERATION_INDEXES_V1
    {
        let object = named_schema_object_v1(connection, "index", index_name)?;
        if object.table_name != *table_name
            || !object.sql.contains("CREATE UNIQUE INDEX")
            || !object.sql.contains(generation_column)
        {
            return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
        }
    }

    let transition_table = named_schema_object_v1(connection, "table", "inbox_transitions")?;
    if !transition_table
        .sql
        .contains("PRIMARY KEY (transition_generation)")
    {
        return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
    }
    let metadata_guard =
        named_schema_object_v1(connection, "trigger", "adapter_store_meta_update_guard")?;
    if metadata_guard.table_name != "adapter_store_meta"
        || !metadata_guard
            .sql
            .contains("NEW.store_generation > OLD.store_generation")
        || !metadata_guard.sql.contains("RAISE(ABORT")
    {
        return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
    }
    Ok(())
}

fn verify_application_and_version(
    connection: &Connection,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    let application_id = pragma_i64(connection, "application_id")?;
    if application_id != ADAPTER_INBOX_APPLICATION_ID_V1 {
        return Err(AdapterInboxStoreOpenErrorV1::ApplicationIdMismatch);
    }
    let user_version = pragma_i64(connection, "user_version")?;
    if user_version > ADAPTER_INBOX_SCHEMA_VERSION_V1 {
        return Err(AdapterInboxStoreOpenErrorV1::SchemaUnsupported);
    }
    if user_version != ADAPTER_INBOX_SCHEMA_VERSION_V1 {
        return Err(AdapterInboxStoreOpenErrorV1::SchemaInvalid);
    }
    Ok(())
}

fn verify_integrity_check(connection: &Connection) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    let mut statement = connection
        .prepare("PRAGMA integrity_check")
        .map_err(|_| AdapterInboxStoreOpenErrorV1::IntegrityFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| AdapterInboxStoreOpenErrorV1::IntegrityFailed)?;
    let first = rows
        .next()
        .map_err(|_| AdapterInboxStoreOpenErrorV1::IntegrityFailed)?
        .ok_or(AdapterInboxStoreOpenErrorV1::IntegrityFailed)?;
    let result: String = first
        .get(0)
        .map_err(|_| AdapterInboxStoreOpenErrorV1::IntegrityFailed)?;
    if result != "ok"
        || rows
            .next()
            .map_err(|_| AdapterInboxStoreOpenErrorV1::IntegrityFailed)?
            .is_some()
    {
        return Err(AdapterInboxStoreOpenErrorV1::IntegrityFailed);
    }
    Ok(())
}

fn verify_foreign_key_check(connection: &Connection) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    if statement
        .query([])
        .and_then(|mut rows| rows.next().map(|row| row.is_some()))
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?
    {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    Ok(())
}

fn decode_metadata(
    connection: &Connection,
    expected_root_identity: AdapterRootIdentityV1,
) -> Result<MetadataV1, AdapterInboxStoreOpenErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT singleton, format_version, store_generation, inbox_generation,
                    consumption_generation, receipt_generation, conflict_generation,
                    quarantine_generation, event_generation, root_identity,
                    root_lifecycle_state, supervisor_epoch, epoch_observer_generation,
                    ordinary_queue_capacity, control_queue_capacity,
                    receipt_signer_profile_digest, restore_index_digest,
                    restore_state_generation
             FROM adapter_store_meta",
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let row = rows
        .next()
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?
        .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)?;

    let singleton = strict_safe_integer(row.get_ref(0).map_err(invariant)?)?;
    let format_version = strict_safe_integer(row.get_ref(1).map_err(invariant)?)?;
    let store_generation = strict_safe_integer(row.get_ref(2).map_err(invariant)?)?;
    let inbox_generation = strict_safe_integer(row.get_ref(3).map_err(invariant)?)?;
    let consumption_generation = strict_safe_integer(row.get_ref(4).map_err(invariant)?)?;
    let receipt_generation = strict_safe_integer(row.get_ref(5).map_err(invariant)?)?;
    let conflict_generation = strict_safe_integer(row.get_ref(6).map_err(invariant)?)?;
    let quarantine_generation = strict_safe_integer(row.get_ref(7).map_err(invariant)?)?;
    let event_generation = strict_safe_integer(row.get_ref(8).map_err(invariant)?)?;
    let root_identity = strict_blob(row.get_ref(9).map_err(invariant)?, 32)?;
    let mut root_identity_bytes = [0_u8; 32];
    root_identity_bytes.copy_from_slice(root_identity);
    let lifecycle = match strict_text(row.get_ref(10).map_err(invariant)?)? {
        b"ACTIVE" => AdapterRootLifecycleStateV1::Active,
        b"RESTORE_PENDING" => AdapterRootLifecycleStateV1::RestorePending,
        _ => return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed),
    };
    let supervisor_epoch = strict_safe_integer(row.get_ref(11).map_err(invariant)?)?;
    let epoch_observer_generation = strict_safe_integer(row.get_ref(12).map_err(invariant)?)?;
    let ordinary_capacity = strict_safe_integer(row.get_ref(13).map_err(invariant)?)?;
    let control_capacity = strict_safe_integer(row.get_ref(14).map_err(invariant)?)?;
    let signer_digest = strict_blob(row.get_ref(15).map_err(invariant)?, 32)?;
    let restore_digest = row.get_ref(16).map_err(invariant)?;
    let restore_digest_is_null = matches!(restore_digest, ValueRef::Null);
    let restore_digest_is_exact = strict_blob(restore_digest, 32).is_ok();
    let restore_state_generation = strict_safe_integer(row.get_ref(17).map_err(invariant)?)?;
    if singleton != 1
        || format_version != ADAPTER_INBOX_FORMAT_VERSION_V1 as u64
        || ordinary_capacity != 1024
        || control_capacity != 32
        || epoch_observer_generation == 0
        || signer_digest.len() != 32
        || root_identity_bytes != *expected_root_identity.as_bytes()
        || rows
            .next()
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?
            .is_some()
    {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    match lifecycle {
        AdapterRootLifecycleStateV1::Active
            if restore_digest_is_null && restore_state_generation == 0 => {}
        AdapterRootLifecycleStateV1::RestorePending
            if restore_digest_is_exact
                && (1..=store_generation).contains(&restore_state_generation) => {}
        _ => return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed),
    }
    Ok(MetadataV1 {
        root_identity: AdapterRootIdentityV1::from_bytes(root_identity_bytes),
        lifecycle,
        store_generation,
        inbox_generation,
        consumption_generation,
        receipt_generation,
        conflict_generation,
        quarantine_generation,
        event_generation,
        supervisor_epoch,
        epoch_observer_generation,
    })
}

fn verify_generation_high_water(
    connection: &Connection,
    metadata: MetadataV1,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    let observed = [
        maximum_generation(connection, "grant_inbox", "received_generation")?,
        maximum_generation_where(
            connection,
            "inbox_transitions",
            "transition_generation",
            "new_state <> 'RECEIVED'",
        )?,
        maximum_generation(connection, "execution_receipts", "receipt_generation")?,
        maximum_generation(connection, "inbox_conflicts", "conflict_generation")?,
        maximum_generation(connection, "inbox_quarantines", "quarantine_generation")?,
        maximum_generation(connection, "adapter_events", "event_generation")?,
    ];
    let retained = [
        metadata.inbox_generation,
        metadata.consumption_generation,
        metadata.receipt_generation,
        metadata.conflict_generation,
        metadata.quarantine_generation,
        metadata.event_generation,
    ];
    if observed != retained
        || retained
            .iter()
            .any(|value| *value > metadata.store_generation)
    {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    Ok(())
}

fn verify_cross_record_invariants(
    connection: &Connection,
) -> Result<(), AdapterInboxStoreOpenErrorV1> {
    const QUERIES: [&str; 5] = [
        "SELECT COUNT(*) FROM grant_inbox AS grant_row
         WHERE NOT EXISTS (
             SELECT 1 FROM inbox_transitions AS transition_row
             WHERE transition_row.grant_id = grant_row.grant_id
               AND transition_row.operation_id = grant_row.operation_id
               AND transition_row.transition_generation = grant_row.received_generation
               AND transition_row.previous_state = 'ABSENT'
               AND transition_row.new_state = 'RECEIVED'
         )",
        "SELECT COUNT(*) FROM grant_inbox AS grant_row
         WHERE (grant_row.inbox_state = 'RECEIVED' AND
                (SELECT COUNT(*) FROM inbox_transitions AS transition_row
                 WHERE transition_row.grant_id = grant_row.grant_id) <> 1)
            OR (grant_row.inbox_state <> 'RECEIVED' AND
                (SELECT COUNT(*) FROM inbox_transitions AS transition_row
                 WHERE transition_row.grant_id = grant_row.grant_id) <> 2)",
        // The frozen wire orders inbox < decision/current transition < receipt.
        "SELECT COUNT(*) FROM execution_receipts AS receipt_row
         WHERE NOT EXISTS (
             SELECT 1 FROM grant_inbox AS grant_row
             WHERE grant_row.grant_id = receipt_row.grant_id
               AND grant_row.operation_id = receipt_row.operation_id
               AND grant_row.receipt_id = receipt_row.receipt_id
               AND grant_row.receipt_decision = receipt_row.decision
               AND receipt_row.receipt_generation > grant_row.current_generation
         )",
        "SELECT COUNT(*) FROM grant_inbox AS grant_row
         WHERE grant_row.receipt_id IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM inbox_transitions AS transition_row
             WHERE transition_row.grant_id = grant_row.grant_id
               AND transition_row.operation_id = grant_row.operation_id
               AND transition_row.transition_generation = grant_row.current_generation
               AND transition_row.receipt_id = grant_row.receipt_id
               AND transition_row.receipt_decision = grant_row.receipt_decision
         )",
        "SELECT COUNT(*) FROM inbox_transitions AS transition_row
         WHERE NOT EXISTS (
             SELECT 1 FROM adapter_events AS event_row
             WHERE event_row.event_id = transition_row.event_id
               AND event_row.grant_id = transition_row.grant_id
               AND event_row.operation_id = transition_row.operation_id
               AND event_row.transition_generation = transition_row.transition_generation
               AND event_row.effective_state = transition_row.new_state
         )",
    ];
    for query in QUERIES {
        let anomaly_count: i64 = connection
            .query_row(query, [], |row| row.get(0))
            .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
        if anomaly_count != 0 {
            return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
        }
    }
    Ok(())
}

fn read_schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObjectV1>, AdapterInboxStoreOpenErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)?;
    let objects = statement
        .query_map([], |row| {
            Ok(SchemaObjectV1 {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)?;
    Ok(objects)
}

fn named_schema_object_v1(
    connection: &Connection,
    object_type: &str,
    name: &str,
) -> Result<SchemaObjectV1, AdapterInboxStoreOpenErrorV1> {
    connection
        .query_row(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema
             WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| {
                Ok(SchemaObjectV1 {
                    object_type: row.get(0)?,
                    name: row.get(1)?,
                    table_name: row.get(2)?,
                    sql: row.get(3)?,
                })
            },
        )
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)
}

fn table_count(connection: &Connection, table: &str) -> Result<u64, AdapterInboxStoreOpenErrorV1> {
    let query = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection
        .query_row(&query, [], |row| row.get(0))
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    u64::try_from(count).map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)
}

fn maximum_generation(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<u64, AdapterInboxStoreOpenErrorV1> {
    maximum_generation_where(connection, table, column, "1 = 1")
}

fn maximum_generation_where(
    connection: &Connection,
    table: &str,
    column: &str,
    predicate: &str,
) -> Result<u64, AdapterInboxStoreOpenErrorV1> {
    let query = format!("SELECT COALESCE(MAX({column}), 0) FROM {table} WHERE {predicate}");
    let value: i64 = connection
        .query_row(&query, [], |row| row.get(0))
        .map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    let value = u64::try_from(value).map_err(|_| AdapterInboxStoreOpenErrorV1::InvariantFailed)?;
    if value > MAX_SAFE_INTEGER {
        return Err(AdapterInboxStoreOpenErrorV1::InvariantFailed);
    }
    Ok(value)
}

fn pragma_i64(connection: &Connection, pragma: &str) -> Result<i64, AdapterInboxStoreOpenErrorV1> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|_| AdapterInboxStoreOpenErrorV1::SchemaInvalid)
}

fn strict_safe_integer(value: ValueRef<'_>) -> Result<u64, AdapterInboxStoreOpenErrorV1> {
    match value {
        ValueRef::Integer(value) if value >= 0 && value as u64 <= MAX_SAFE_INTEGER => {
            Ok(value as u64)
        }
        _ => Err(AdapterInboxStoreOpenErrorV1::InvariantFailed),
    }
}

fn strict_safe_i64(value: i64) -> Result<u64, AdapterInboxStoreOpenErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)
}

fn to_i64(value: u64) -> Result<i64, AdapterInboxStoreOpenErrorV1> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value >= 0 && *value as u64 <= MAX_SAFE_INTEGER)
        .ok_or(AdapterInboxStoreOpenErrorV1::InvariantFailed)
}

fn strict_blob(value: ValueRef<'_>, length: usize) -> Result<&[u8], AdapterInboxStoreOpenErrorV1> {
    match value {
        ValueRef::Blob(bytes) if bytes.len() == length => Ok(bytes),
        _ => Err(AdapterInboxStoreOpenErrorV1::InvariantFailed),
    }
}

fn strict_text(value: ValueRef<'_>) -> Result<&[u8], AdapterInboxStoreOpenErrorV1> {
    match value {
        ValueRef::Text(bytes) => Ok(bytes),
        _ => Err(AdapterInboxStoreOpenErrorV1::InvariantFailed),
    }
}

fn invariant(_: rusqlite::Error) -> AdapterInboxStoreOpenErrorV1 {
    AdapterInboxStoreOpenErrorV1::InvariantFailed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_empty_store() -> (Connection, AdapterRootIdentityV1) {
        let mut connection = Connection::open_in_memory().expect("SQLite opens");
        let identity = AdapterRootIdentityV1::from_bytes([0x41; 32]);
        initialize_empty_schema(
            &mut connection,
            identity,
            AdapterInboxInitializationV1::try_new(7, 1, [0x52; 32])
                .expect("initial metadata validates"),
        )
        .expect("schema initializes");
        (connection, identity)
    }

    #[test]
    fn exact_empty_schema_and_metadata_verify() {
        let (connection, identity) = exact_empty_store();
        let summary = verify_full(&connection, identity).expect("store verifies");
        assert_eq!(summary.store_generation, 0);
        assert_eq!(summary.inbox_count, 0);
    }

    #[test]
    fn permanent_adapter_history_policy_is_closed_and_tamper_is_typed() {
        let (connection, identity) = exact_empty_store();
        let policy = verify_permanent_adapter_history_v1(&connection, identity)
            .expect("exact retained history verifies");
        assert!(policy.history_is_permanent());
        assert!(policy.history_is_append_only());
        assert!(!policy.history_deletion_enabled());
        assert!(!policy.identifier_reuse_enabled());
        assert!(!policy.generation_reuse_enabled());
        assert!(!policy.automatic_pruning_enabled());
        assert!(!policy.physical_secure_erasure_claimed());
        assert!(policy.requires_approved_encrypted_at_rest_profile());

        connection
            .execute_batch("DROP TRIGGER adapter_events_no_delete")
            .expect("fixture delete guard drops");
        assert_eq!(
            verify_permanent_adapter_history_v1(&connection, identity)
                .expect_err("delete-guard tamper refuses"),
            AdapterInboxStoreOpenErrorV1::SchemaInvalid
        );
    }

    #[test]
    fn unknown_future_version_is_refused() {
        let (connection, identity) = exact_empty_store();
        connection
            .pragma_update(None, "user_version", 2_i64)
            .expect("version mutates for test");
        assert_eq!(
            verify_full(&connection, identity).unwrap_err(),
            AdapterInboxStoreOpenErrorV1::SchemaUnsupported
        );
    }

    #[test]
    fn wrong_expected_root_identity_is_refused() {
        let (connection, _) = exact_empty_store();
        assert_eq!(
            verify_full(&connection, AdapterRootIdentityV1::from_bytes([0x42; 32])).unwrap_err(),
            AdapterInboxStoreOpenErrorV1::InvariantFailed
        );
    }

    #[test]
    fn restore_transition_is_one_exact_active_to_pending_commit() {
        let (mut connection, source_identity) = exact_empty_store();
        let source = verify_full(&connection, source_identity).expect("source verifies");
        let new_identity = AdapterRootIdentityV1::from_bytes([0x43; 32]);
        assert_eq!(
            AdapterRestorePendingBindingsV1::try_new(
                source,
                new_identity,
                8,
                2,
                [0; 32],
                [0x55; 32],
            )
            .unwrap_err(),
            AdapterInboxStoreOpenErrorV1::InvariantFailed
        );
        let bindings = AdapterRestorePendingBindingsV1::try_new(
            source,
            new_identity,
            8,
            2,
            [0x54; 32],
            [0x55; 32],
        )
        .expect("rotated restore bindings validate");
        let verified = transition_imported_backup_to_restore_pending_v1(&mut connection, bindings)
            .expect("active source commits pending once");
        let pending = verified.summary();
        assert_eq!(
            pending.root_lifecycle_state,
            AdapterRootLifecycleStateV1::RestorePending
        );
        assert_eq!(pending.root_identity.into_internal(), new_identity);
        assert_eq!(pending.store_generation, 1);
        assert_eq!(pending.inbox_generation, source.inbox_generation);
        assert_eq!(
            pending.consumption_generation,
            source.consumption_generation
        );
        assert_eq!(pending.receipt_generation, source.receipt_generation);
        verify_restore_pending_v1(&connection, bindings)
            .expect("exact pending readback is idempotent");
        assert_eq!(
            transition_imported_backup_to_restore_pending_v1(&mut connection, bindings)
                .unwrap_err(),
            AdapterInboxStoreOpenErrorV1::InvariantFailed
        );
    }
}
