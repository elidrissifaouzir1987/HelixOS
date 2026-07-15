//! Permanent redacted pre-receive diagnostics and create-only conflict evidence.

#![allow(dead_code)]

use helix_dispatch_contracts::{Sha256Digest, MAX_SAFE_U64};
use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::path::PathBuf;

const PRE_RECEIVED_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_PRE_RECEIVED_QUARANTINE_V1\0";
const CROSS_STORE_CORRUPTION_DOMAIN_V1: &[u8] =
    b"HELIXOS_ADAPTER_CROSS_STORE_CORRUPTION_QUARANTINE_V1\0";
const CROSS_STORE_EVIDENCE_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_CROSS_STORE_CORRUPTION_V1\0";
const ADAPTER_HISTORY_TABLE_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_HISTORY_TABLE_V1\0";
const ADAPTER_HISTORY_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_HISTORY_V1\0";
const ADAPTER_HISTORY_ROW_KEY_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_HISTORY_ROW_KEY_V1\0";
const ADAPTER_HISTORY_ROW_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_HISTORY_ROW_V1\0";
const ADAPTER_HISTORY_CHECKPOINT_MISMATCH_DOMAIN_V1: &[u8] =
    b"HELIXOS_ADAPTER_HISTORY_CHECKPOINT_MISMATCH_V1\0";
const ADAPTER_GENERATION_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_GENERATION_BINDING_SQL_V1\0";
const ADAPTER_GRANT_GENERATION_BINDING_DOMAIN_V1: &[u8] =
    b"HELIXOS_ADAPTER_GRANT_GENERATION_BINDING_V1\0";
const ADAPTER_RECEIPT_GENERATION_BINDING_DOMAIN_V1: &[u8] =
    b"HELIXOS_ADAPTER_RECEIPT_GENERATION_BINDING_V1\0";
const ADAPTER_CROSS_STORE_INVENTORY_DOMAIN_V1: &[u8] =
    b"HELIXOS_ADAPTER_CROSS_STORE_INVENTORY_V1\0";
const ADAPTER_GRANT_INVENTORY_ROW_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_GRANT_INVENTORY_ROW_V1\0";
const COORDINATOR_GRANT_INVENTORY_ROW_DOMAIN_V1: &[u8] =
    b"HELIXOS_COORDINATOR_GRANT_INVENTORY_ROW_V1\0";
const ADAPTER_RECEIPT_INVENTORY_ROW_DOMAIN_V1: &[u8] =
    b"HELIXOS_ADAPTER_RECEIPT_INVENTORY_ROW_V1\0";
const COORDINATOR_RECEIPT_INVENTORY_ROW_DOMAIN_V1: &[u8] =
    b"HELIXOS_COORDINATOR_RECEIPT_INVENTORY_ROW_V1\0";
const CONFLICT_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_INBOX_CONFLICT_V1\0";
const CONFLICT_EVENT_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_INBOX_CONFLICT_EVENT_V1\0";

const ADAPTER_HISTORY_TABLES_V1: [(&str, &str); 6] = [
    ("grant_inbox", "grant_id"),
    ("inbox_transitions", "transition_generation, grant_id"),
    ("execution_receipts", "receipt_id"),
    ("inbox_conflicts", "conflict_id"),
    ("inbox_quarantines", "quarantine_id"),
    ("adapter_events", "event_id"),
];

// These are the exact generation-uniqueness axes required by the reviewed adapter schema.
// `inbox_transitions.transition_generation` is also retained even though its primary key already
// provides uniqueness: the scanner must continue to detect reuse after an out-of-band table
// rebuild removes that guard.
const ADAPTER_GENERATION_AXES_V1: [(&str, &str, &str); 7] = [
    ("grant_inbox", "received_generation", "grant_id"),
    ("grant_inbox", "current_generation", "grant_id"),
    (
        "inbox_transitions",
        "transition_generation",
        "transition_generation",
    ),
    ("execution_receipts", "receipt_generation", "receipt_id"),
    ("inbox_conflicts", "conflict_generation", "conflict_id"),
    (
        "inbox_quarantines",
        "quarantine_generation",
        "quarantine_id",
    ),
    ("adapter_events", "event_generation", "event_id"),
];

pub(crate) const GLOBAL_ADAPTER_CORRUPTION_REASON_CODES_V1: [&str; 11] = [
    "ORPHAN_ADAPTER_INBOX",
    "ORPHAN_ADAPTER_RECEIPT",
    "GRANT_DIGEST_CONFLICT",
    "RECEIPT_DIGEST_CONFLICT",
    "CROSS_GENERATION_CONFLICT",
    "ADAPTER_STORE_ROLLBACK",
    "ADAPTER_ROOT_ROLLBACK",
    "ADAPTER_GENERATION_ROLLBACK",
    "ADAPTER_HISTORY_TRUNCATED",
    "ADAPTER_GENERATION_REUSED",
    "CROSS_STORE_DISAGREEMENT",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterCrossStoreCorruptionV1 {
    OrphanAdapterInbox,
    OrphanAdapterReceipt,
    GrantDigestConflict,
    ReceiptDigestConflict,
    CrossGenerationConflict,
    AdapterStoreRollback,
    AdapterRootRollback,
    AdapterGenerationRollback,
    AdapterHistoryTruncated,
    AdapterGenerationReused,
    CrossStoreDisagreement,
}

impl AdapterCrossStoreCorruptionV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::OrphanAdapterInbox => "ORPHAN_ADAPTER_INBOX",
            Self::OrphanAdapterReceipt => "ORPHAN_ADAPTER_RECEIPT",
            Self::GrantDigestConflict => "GRANT_DIGEST_CONFLICT",
            Self::ReceiptDigestConflict => "RECEIPT_DIGEST_CONFLICT",
            Self::CrossGenerationConflict => "CROSS_GENERATION_CONFLICT",
            Self::AdapterStoreRollback => "ADAPTER_STORE_ROLLBACK",
            Self::AdapterRootRollback => "ADAPTER_ROOT_ROLLBACK",
            Self::AdapterGenerationRollback => "ADAPTER_GENERATION_ROLLBACK",
            Self::AdapterHistoryTruncated => "ADAPTER_HISTORY_TRUNCATED",
            Self::AdapterGenerationReused => "ADAPTER_GENERATION_REUSED",
            Self::CrossStoreDisagreement => "CROSS_STORE_DISAGREEMENT",
        }
    }

    fn from_reason_code(reason_code: &str) -> Option<Self> {
        match reason_code {
            "ORPHAN_ADAPTER_INBOX" => Some(Self::OrphanAdapterInbox),
            "ORPHAN_ADAPTER_RECEIPT" => Some(Self::OrphanAdapterReceipt),
            "GRANT_DIGEST_CONFLICT" => Some(Self::GrantDigestConflict),
            "RECEIPT_DIGEST_CONFLICT" => Some(Self::ReceiptDigestConflict),
            "CROSS_GENERATION_CONFLICT" => Some(Self::CrossGenerationConflict),
            "ADAPTER_STORE_ROLLBACK" => Some(Self::AdapterStoreRollback),
            "ADAPTER_ROOT_ROLLBACK" => Some(Self::AdapterRootRollback),
            "ADAPTER_GENERATION_ROLLBACK" => Some(Self::AdapterGenerationRollback),
            "ADAPTER_HISTORY_TRUNCATED" => Some(Self::AdapterHistoryTruncated),
            "ADAPTER_GENERATION_REUSED" => Some(Self::AdapterGenerationReused),
            "CROSS_STORE_DISAGREEMENT" => Some(Self::CrossStoreDisagreement),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterLifecycleRelationshipV1 {
    Prepared,
    Dispatching,
    AdapterReceived,
    Consumed,
    Ambiguous,
}

impl AdapterLifecycleRelationshipV1 {
    const fn evidence_tag(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Dispatching => 2,
            Self::AdapterReceived => 3,
            Self::Consumed => 4,
            Self::Ambiguous => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterCorruptionCustodyV1 {
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterCorruptionExecutionV1 {
    Refused,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdapterCorruptionDispositionV1 {
    corruption: AdapterCrossStoreCorruptionV1,
    custody: AdapterCorruptionCustodyV1,
    execution: AdapterCorruptionExecutionV1,
    evidence_digest: Sha256Digest,
}

impl std::fmt::Debug for AdapterCorruptionDispositionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterCorruptionDispositionV1")
            .field("corruption", &self.corruption)
            .field("custody", &self.custody)
            .field("execution", &self.execution)
            .finish_non_exhaustive()
    }
}

impl AdapterCorruptionDispositionV1 {
    const fn from_retained_v1(
        corruption: AdapterCrossStoreCorruptionV1,
        evidence_digest: Sha256Digest,
    ) -> Self {
        Self {
            corruption,
            custody: AdapterCorruptionCustodyV1::Quarantined,
            execution: AdapterCorruptionExecutionV1::Refused,
            evidence_digest,
        }
    }

    pub(crate) const fn corruption(self) -> AdapterCrossStoreCorruptionV1 {
        self.corruption
    }

    pub(crate) const fn custody(self) -> AdapterCorruptionCustodyV1 {
        self.custody
    }

    pub(crate) const fn execution(self) -> AdapterCorruptionExecutionV1 {
        self.execution
    }

    pub(crate) const fn evidence_digest(self) -> Sha256Digest {
        self.evidence_digest
    }

    pub(crate) const fn reason_code(self) -> &'static str {
        self.corruption.reason_code()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterCrossStoreRecordV1 {
    pub(crate) canonical_digest: Sha256Digest,
    pub(crate) generation_binding_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterGenerationVectorV1 {
    pub(crate) store: u64,
    pub(crate) inbox: u64,
    pub(crate) consumption: u64,
    pub(crate) receipt: u64,
    pub(crate) conflict: u64,
    pub(crate) quarantine: u64,
    pub(crate) event: u64,
    pub(crate) epoch_observer: u64,
    pub(crate) restore_state: u64,
}

impl AdapterGenerationVectorV1 {
    fn regressed_from(self, trusted: Self) -> bool {
        self.inbox < trusted.inbox
            || self.consumption < trusted.consumption
            || self.receipt < trusted.receipt
            || self.conflict < trusted.conflict
            || self.quarantine < trusted.quarantine
            || self.event < trusted.event
            || self.epoch_observer < trusted.epoch_observer
            || self.restore_state < trusted.restore_state
    }

    fn exceeds_store(self) -> bool {
        [
            self.inbox,
            self.consumption,
            self.receipt,
            self.conflict,
            self.quarantine,
            self.event,
            self.restore_state,
        ]
        .into_iter()
        .any(|generation| generation > self.store)
    }

    fn hash_into(self, hasher: &mut Sha256) {
        for generation in [
            self.store,
            self.inbox,
            self.consumption,
            self.receipt,
            self.conflict,
            self.quarantine,
            self.event,
            self.epoch_observer,
            self.restore_state,
        ] {
            hasher.update(generation.to_be_bytes());
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterHistorySnapshotV1 {
    pub(crate) root_identity_digest: Sha256Digest,
    pub(crate) generations: AdapterGenerationVectorV1,
    pub(crate) history_generation: u64,
    pub(crate) history_rows: u64,
    pub(crate) history_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterObservedHistoryV1 {
    pub(crate) root_identity_digest: Sha256Digest,
    pub(crate) generations: AdapterGenerationVectorV1,
    pub(crate) history_generation: u64,
    pub(crate) history_rows: u64,
    pub(crate) retained_checkpoint_digest: Sha256Digest,
    pub(crate) complete_history_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdapterCrossStoreHistoryInputV1 {
    pub(crate) relationship: AdapterLifecycleRelationshipV1,
    pub(crate) trusted: AdapterHistorySnapshotV1,
    pub(crate) observed: AdapterObservedHistoryV1,
    pub(crate) coordinator_grant: Option<AdapterCrossStoreRecordV1>,
    pub(crate) adapter_inbox: Option<AdapterCrossStoreRecordV1>,
    pub(crate) coordinator_receipt: Option<AdapterCrossStoreRecordV1>,
    pub(crate) adapter_receipt: Option<AdapterCrossStoreRecordV1>,
    pub(crate) expected_cross_store_inventory_digest: Sha256Digest,
    pub(crate) observed_cross_store_inventory_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterHistoryVerificationV1 {
    NoCorruptionObserved,
    Corrupted(AdapterCorruptionDispositionV1),
}

/// Classifies one exact retained adapter checkpoint and its cross-store observation.
/// A clean result is only an integrity observation and does not convey effect authority.
pub(crate) fn verify_adapter_cross_store_history_v1(
    input: &AdapterCrossStoreHistoryInputV1,
) -> AdapterHistoryVerificationV1 {
    let corruption = detect_adapter_corruption_v1(input);
    match corruption {
        Some(corruption) => {
            AdapterHistoryVerificationV1::Corrupted(AdapterCorruptionDispositionV1 {
                corruption,
                custody: AdapterCorruptionCustodyV1::Quarantined,
                execution: AdapterCorruptionExecutionV1::Refused,
                evidence_digest: adapter_corruption_evidence_digest_v1(input, corruption),
            })
        }
        None => AdapterHistoryVerificationV1::NoCorruptionObserved,
    }
}

fn detect_adapter_corruption_v1(
    input: &AdapterCrossStoreHistoryInputV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    if let Some(corruption) = detect_adapter_history_corruption_v1(input) {
        return Some(corruption);
    }

    detect_adapter_relationship_corruption_v1(input).or_else(|| {
        (input.expected_cross_store_inventory_digest != input.observed_cross_store_inventory_digest)
            .then_some(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement)
    })
}

fn detect_adapter_relationship_corruption_v1(
    input: &AdapterCrossStoreHistoryInputV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    if let Some(corruption) = detect_record_pair_corruption_v1(
        input.adapter_inbox,
        input.coordinator_grant,
        AdapterCrossStoreCorruptionV1::OrphanAdapterInbox,
        AdapterCrossStoreCorruptionV1::GrantDigestConflict,
    ) {
        return Some(corruption);
    }
    if let Some(corruption) = detect_record_pair_corruption_v1(
        input.adapter_receipt,
        input.coordinator_receipt,
        AdapterCrossStoreCorruptionV1::OrphanAdapterReceipt,
        AdapterCrossStoreCorruptionV1::ReceiptDigestConflict,
    ) {
        return Some(corruption);
    }

    let grant_shape = (
        input.coordinator_grant.is_some(),
        input.adapter_inbox.is_some(),
    );
    let receipt_shape = (
        input.coordinator_receipt.is_some(),
        input.adapter_receipt.is_some(),
    );
    let lifecycle_relationship_is_exact = match input.relationship {
        AdapterLifecycleRelationshipV1::Prepared => {
            grant_shape == (false, false) && receipt_shape == (false, false)
        }
        AdapterLifecycleRelationshipV1::Dispatching | AdapterLifecycleRelationshipV1::Ambiguous => {
            grant_shape == (true, false) && receipt_shape == (false, false)
        }
        AdapterLifecycleRelationshipV1::AdapterReceived => {
            grant_shape == (true, true) && receipt_shape == (false, false)
        }
        AdapterLifecycleRelationshipV1::Consumed => {
            grant_shape == (true, true) && receipt_shape == (true, true)
        }
    };
    if !lifecycle_relationship_is_exact {
        return Some(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement);
    }
    None
}

fn detect_adapter_history_corruption_v1(
    input: &AdapterCrossStoreHistoryInputV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    let trusted = input.trusted;
    let observed = input.observed;

    if observed.root_identity_digest != trusted.root_identity_digest {
        return Some(AdapterCrossStoreCorruptionV1::AdapterRootRollback);
    }
    if observed.generations.store < trusted.generations.store {
        return Some(AdapterCrossStoreCorruptionV1::AdapterStoreRollback);
    }
    if observed.generations.regressed_from(trusted.generations)
        || observed.history_generation < trusted.history_generation
    {
        return Some(AdapterCrossStoreCorruptionV1::AdapterGenerationRollback);
    }
    if observed.history_rows < trusted.history_rows {
        return Some(AdapterCrossStoreCorruptionV1::AdapterHistoryTruncated);
    }
    if observed.history_generation == trusted.history_generation
        && observed.retained_checkpoint_digest != trusted.history_digest
    {
        return Some(AdapterCrossStoreCorruptionV1::AdapterGenerationReused);
    }
    if observed.retained_checkpoint_digest != trusted.history_digest {
        return Some(AdapterCrossStoreCorruptionV1::AdapterHistoryTruncated);
    }
    if observed.generations.exceeds_store()
        || observed.history_generation > observed.generations.store
    {
        return Some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict);
    }
    None
}

/// Corruptions that remain authoritative before deciding whether two strict roots represent the
/// same exact paused checkpoint. A clean monotonic advance is intentionally not classified here.
fn detect_adapter_history_corruption_before_checkpoint_v1(
    input: &AdapterCrossStoreHistoryInputV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    let trusted = input.trusted;
    let observed = input.observed;

    if observed.root_identity_digest != trusted.root_identity_digest {
        return Some(AdapterCrossStoreCorruptionV1::AdapterRootRollback);
    }
    if observed.generations.store < trusted.generations.store {
        return Some(AdapterCrossStoreCorruptionV1::AdapterStoreRollback);
    }
    if observed.generations.regressed_from(trusted.generations)
        || observed.history_generation < trusted.history_generation
    {
        return Some(AdapterCrossStoreCorruptionV1::AdapterGenerationRollback);
    }
    if observed.history_rows < trusted.history_rows {
        return Some(AdapterCrossStoreCorruptionV1::AdapterHistoryTruncated);
    }
    if observed.history_generation == trusted.history_generation
        && observed.retained_checkpoint_digest != trusted.history_digest
    {
        return Some(AdapterCrossStoreCorruptionV1::AdapterGenerationReused);
    }
    if observed.generations.exceeds_store()
        || observed.history_generation > observed.generations.store
    {
        return Some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict);
    }
    None
}

fn detect_record_pair_corruption_v1(
    adapter: Option<AdapterCrossStoreRecordV1>,
    coordinator: Option<AdapterCrossStoreRecordV1>,
    orphan: AdapterCrossStoreCorruptionV1,
    digest_conflict: AdapterCrossStoreCorruptionV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    match (adapter, coordinator) {
        (Some(_), None) => Some(orphan),
        (Some(adapter), Some(coordinator))
            if adapter.canonical_digest != coordinator.canonical_digest =>
        {
            Some(digest_conflict)
        }
        (Some(adapter), Some(coordinator))
            if adapter.generation_binding_digest != coordinator.generation_binding_digest =>
        {
            Some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict)
        }
        (Some(_), Some(_)) | (None, Some(_)) | (None, None) => None,
    }
}

fn adapter_corruption_evidence_digest_v1(
    input: &AdapterCrossStoreHistoryInputV1,
    corruption: AdapterCrossStoreCorruptionV1,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(CROSS_STORE_EVIDENCE_DOMAIN_V1);
    hasher.update(corruption.reason_code().as_bytes());
    hasher.update([input.relationship.evidence_tag()]);
    hash_adapter_trusted_v1(&mut hasher, input.trusted);
    hash_adapter_observed_v1(&mut hasher, input.observed);
    hash_adapter_record_v1(&mut hasher, input.coordinator_grant);
    hash_adapter_record_v1(&mut hasher, input.adapter_inbox);
    hash_adapter_record_v1(&mut hasher, input.coordinator_receipt);
    hash_adapter_record_v1(&mut hasher, input.adapter_receipt);
    hasher.update(input.expected_cross_store_inventory_digest.as_bytes());
    hasher.update(input.observed_cross_store_inventory_digest.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_adapter_trusted_v1(hasher: &mut Sha256, history: AdapterHistorySnapshotV1) {
    hasher.update(history.root_identity_digest.as_bytes());
    history.generations.hash_into(hasher);
    hasher.update(history.history_generation.to_be_bytes());
    hasher.update(history.history_rows.to_be_bytes());
    hasher.update(history.history_digest.as_bytes());
}

fn hash_adapter_observed_v1(hasher: &mut Sha256, history: AdapterObservedHistoryV1) {
    hasher.update(history.root_identity_digest.as_bytes());
    history.generations.hash_into(hasher);
    hasher.update(history.history_generation.to_be_bytes());
    hasher.update(history.history_rows.to_be_bytes());
    hasher.update(history.retained_checkpoint_digest.as_bytes());
    hasher.update(history.complete_history_digest.as_bytes());
}

fn hash_adapter_record_v1(hasher: &mut Sha256, record: Option<AdapterCrossStoreRecordV1>) {
    match record {
        Some(record) => {
            hasher.update([1]);
            hasher.update(record.canonical_digest.as_bytes());
            hasher.update(record.generation_binding_digest.as_bytes());
        }
        None => hasher.update([0]),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuarantineStoreErrorV1 {
    Busy,
    Unavailable,
    RestorePending,
    InvariantFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedQuarantineV1 {
    pub(crate) generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetainedConflictV1 {
    pub(crate) generation: u64,
}

pub(crate) struct ConflictEvidenceInputV1<'evidence> {
    pub(crate) observed_grant_id: Sha256Digest,
    pub(crate) operation_id: &'evidence str,
    pub(crate) one_shot_nonce: Sha256Digest,
    pub(crate) retained_binding_digest: Sha256Digest,
    pub(crate) conflicting_binding_digest: Sha256Digest,
}

impl std::fmt::Debug for ConflictEvidenceInputV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConflictEvidenceInputV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn retain_pre_received_refusal_v1(
    transaction: &Transaction<'_>,
    grant_id: Option<Sha256Digest>,
    evidence_digest: Sha256Digest,
    public_reason_code: &str,
) -> Result<RetainedQuarantineV1, QuarantineStoreErrorV1> {
    retain_quarantine_with_domain_v1(
        transaction,
        PRE_RECEIVED_DOMAIN_V1,
        grant_id,
        evidence_digest,
        public_reason_code,
    )
}

/// Retains one deterministic append-only cross-store corruption record.
///
/// The caller owns the transaction and must commit only after its surrounding trusted
/// cut remains valid. Repeating the exact evidence returns its original generation.
pub(crate) fn retain_adapter_corruption_quarantine_v1(
    transaction: &Transaction<'_>,
    disposition: AdapterCorruptionDispositionV1,
) -> Result<RetainedQuarantineV1, QuarantineStoreErrorV1> {
    retain_quarantine_with_domain_v1(
        transaction,
        CROSS_STORE_CORRUPTION_DOMAIN_V1,
        None,
        disposition.evidence_digest(),
        disposition.reason_code(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterCorruptionCustodyOutcomeV1 {
    NoCorruptionObserved,
    CheckpointMismatch,
    Quarantined {
        corruption: AdapterCrossStoreCorruptionV1,
        generation: u64,
    },
}

/// Classifies one exact cross-store cut and, when corrupt, retains only redacted custody.
///
/// This function intentionally returns no grant, receipt, permit, replay token, or other
/// execution authority. An exact retry on the same already-open custody connection returns
/// the original generation; a different corruption cannot extend a root after its global
/// fence has become active.
pub(crate) fn classify_and_retain_adapter_cross_store_corruption_v1(
    connection: &mut Connection,
    input: &AdapterCrossStoreHistoryInputV1,
) -> Result<AdapterCorruptionCustodyOutcomeV1, QuarantineStoreErrorV1> {
    let disposition = match verify_adapter_cross_store_history_v1(input) {
        AdapterHistoryVerificationV1::NoCorruptionObserved => {
            return Ok(AdapterCorruptionCustodyOutcomeV1::NoCorruptionObserved)
        }
        AdapterHistoryVerificationV1::Corrupted(disposition) => disposition,
    };
    retain_adapter_corruption_disposition_v1(connection, disposition)
}

fn retain_adapter_corruption_disposition_v1(
    connection: &mut Connection,
    disposition: AdapterCorruptionDispositionV1,
) -> Result<AdapterCorruptionCustodyOutcomeV1, QuarantineStoreErrorV1> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    let outcome =
        retain_adapter_corruption_disposition_in_transaction_v1(&transaction, disposition)?;
    transaction.commit().map_err(map_sqlite_error)?;
    Ok(outcome)
}

fn retain_adapter_corruption_disposition_in_transaction_v1(
    transaction: &Transaction<'_>,
    disposition: AdapterCorruptionDispositionV1,
) -> Result<AdapterCorruptionCustodyOutcomeV1, QuarantineStoreErrorV1> {
    let before = active_global_adapter_corruption_quarantine_count_v1(transaction)?;
    let retained = retain_adapter_corruption_quarantine_v1(transaction, disposition)?;
    let after = active_global_adapter_corruption_quarantine_count_v1(transaction)?;
    if after != 1 || (before > 0 && after != before) {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(AdapterCorruptionCustodyOutcomeV1::Quarantined {
        corruption: disposition.corruption(),
        generation: retained.generation,
    })
}

#[derive(Clone, Copy)]
struct RetainedGlobalAdapterCorruptionV1 {
    disposition: AdapterCorruptionDispositionV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalFenceCommitReadbackV1 {
    ExactPresent,
    Absent,
    Conflict,
}

fn load_retained_global_adapter_corruption_v1(
    connection: &Connection,
) -> Result<Option<RetainedGlobalAdapterCorruptionV1>, QuarantineStoreErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT quarantine_id, evidence_digest, public_reason_code,
                    quarantine_generation, resolved_generation
             FROM inbox_quarantines
             WHERE grant_id IS NULL
               AND public_reason_code IN (
                   'ORPHAN_ADAPTER_INBOX',
                   'ORPHAN_ADAPTER_RECEIPT',
                   'GRANT_DIGEST_CONFLICT',
                   'RECEIPT_DIGEST_CONFLICT',
                   'CROSS_GENERATION_CONFLICT',
                   'ADAPTER_STORE_ROLLBACK',
                   'ADAPTER_ROOT_ROLLBACK',
                   'ADAPTER_GENERATION_ROLLBACK',
                   'ADAPTER_HISTORY_TRUNCATED',
                   'ADAPTER_GENERATION_REUSED',
                   'CROSS_STORE_DISAGREEMENT'
               )
             ORDER BY quarantine_generation, quarantine_id",
        )
        .map_err(map_sqlite_error)?;
    let mut rows = statement.query([]).map_err(map_sqlite_error)?;
    let Some(row) = rows.next().map_err(map_sqlite_error)? else {
        return Ok(None);
    };
    let quarantine_id: Vec<u8> = row.get(0).map_err(map_sqlite_error)?;
    let evidence_digest: Vec<u8> = row.get(1).map_err(map_sqlite_error)?;
    let reason_code: String = row.get(2).map_err(map_sqlite_error)?;
    let generation: i64 = row.get(3).map_err(map_sqlite_error)?;
    let resolved_generation: Option<i64> = row.get(4).map_err(map_sqlite_error)?;
    if rows.next().map_err(map_sqlite_error)?.is_some() {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    let evidence_digest = Sha256Digest::from_bytes(
        evidence_digest
            .try_into()
            .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)?,
    );
    let corruption = AdapterCrossStoreCorruptionV1::from_reason_code(&reason_code)
        .ok_or(QuarantineStoreErrorV1::InvariantFailed)?;
    let expected_quarantine_id = domain_digest(&[
        CROSS_STORE_CORRUPTION_DOMAIN_V1,
        &[0],
        &[],
        evidence_digest.as_bytes(),
        reason_code.as_bytes(),
    ]);
    if quarantine_id.as_slice() != expected_quarantine_id.as_bytes() {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    let generation = strict_generation(generation)?;
    if resolved_generation
        .map(strict_generation)
        .transpose()?
        .is_some_and(|resolved| resolved <= generation)
    {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(Some(RetainedGlobalAdapterCorruptionV1 {
        disposition: AdapterCorruptionDispositionV1::from_retained_v1(corruption, evidence_digest),
    }))
}

/// Resolves only the durable local disposition after a SQLite COMMIT error.
///
/// A read failure is deliberately collapsed to `InvariantFailed`: the caller must not infer
/// either commit or rollback when the database cannot prove the exact retained incident.
fn readback_local_fence_after_commit_error_v1(
    connection: &Connection,
    expected: AdapterCorruptionDispositionV1,
) -> Result<LocalFenceCommitReadbackV1, QuarantineStoreErrorV1> {
    match load_retained_global_adapter_corruption_v1(connection)
        .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)?
    {
        None => Ok(LocalFenceCommitReadbackV1::Absent),
        Some(retained) if retained.disposition == expected => {
            Ok(LocalFenceCommitReadbackV1::ExactPresent)
        }
        Some(_) => Ok(LocalFenceCommitReadbackV1::Conflict),
    }
}

pub(crate) fn active_global_adapter_corruption_quarantine_count_v1(
    connection: &Connection,
) -> Result<u64, QuarantineStoreErrorV1> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM inbox_quarantines
             WHERE grant_id IS NULL
               AND public_reason_code IN (
                   'ORPHAN_ADAPTER_INBOX',
                   'ORPHAN_ADAPTER_RECEIPT',
                   'GRANT_DIGEST_CONFLICT',
                   'RECEIPT_DIGEST_CONFLICT',
                   'CROSS_GENERATION_CONFLICT',
                   'ADAPTER_STORE_ROLLBACK',
                   'ADAPTER_ROOT_ROLLBACK',
                   'ADAPTER_GENERATION_ROLLBACK',
                   'ADAPTER_HISTORY_TRUNCATED',
                   'ADAPTER_GENERATION_REUSED',
                   'CROSS_STORE_DISAGREEMENT'
               )",
            [],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    strict_safe_integer(count)
}

pub(crate) fn ensure_no_active_global_adapter_corruption_quarantine_v1(
    connection: &Connection,
) -> Result<(), QuarantineStoreErrorV1> {
    if active_global_adapter_corruption_quarantine_count_v1(connection)? == 0 {
        Ok(())
    } else {
        Err(QuarantineStoreErrorV1::InvariantFailed)
    }
}

fn verify_adapter_audit_custody_v1(connection: &Connection) -> Result<(), QuarantineStoreErrorV1> {
    let root_identity = read_adapter_root_identity_v1(connection)?;
    let retained = load_retained_global_adapter_corruption_v1(connection)?;
    if retained.is_none() {
        return crate::schema::verify_full(connection, root_identity)
            .map(|_| ())
            .map_err(|_| QuarantineStoreErrorV1::InvariantFailed);
    }

    // Ordinary strict open intentionally rejects a root after global custody is retained. A
    // restart audit therefore replays every non-authority structural gate explicitly and permits
    // only the one exact validated global row loaded above.
    crate::schema::verify_exact_schema(connection)
        .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)?;
    verify_sqlite_integrity_and_foreign_keys_v1(connection)?;
    if active_global_adapter_corruption_quarantine_count_v1(connection)? != 1
        || has_duplicate_adapter_generation_v1(connection)?
    {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    let captured = capture_adapter_history_raw_v1(connection)?;
    if captured.snapshot.generations.exceeds_store()
        || captured.snapshot.generations.inbox
            != maximum_generation_with_filter_v1(
                connection,
                "grant_inbox",
                "received_generation",
                None,
            )?
        || captured.snapshot.generations.consumption
            != maximum_generation_with_filter_v1(
                connection,
                "inbox_transitions",
                "transition_generation",
                Some("new_state <> 'RECEIVED'"),
            )?
        || captured.snapshot.generations.receipt
            != maximum_generation_with_filter_v1(
                connection,
                "execution_receipts",
                "receipt_generation",
                None,
            )?
        || captured.snapshot.generations.conflict
            != maximum_generation_with_filter_v1(
                connection,
                "inbox_conflicts",
                "conflict_generation",
                None,
            )?
        || captured.snapshot.generations.quarantine
            != maximum_generation_with_filter_v1(
                connection,
                "inbox_quarantines",
                "quarantine_generation",
                None,
            )?
        || captured.snapshot.generations.event
            != maximum_generation_with_filter_v1(
                connection,
                "adapter_events",
                "event_generation",
                None,
            )?
    {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(())
}

fn maximum_generation_with_filter_v1(
    connection: &Connection,
    table: &str,
    generation_column: &str,
    filter: Option<&str>,
) -> Result<u64, QuarantineStoreErrorV1> {
    let filter = filter
        .map(|value| format!(" WHERE {value}"))
        .unwrap_or_default();
    let sql = format!("SELECT COALESCE(MAX({generation_column}), 0) FROM {table}{filter}");
    connection
        .query_row(&sql, [], |row| row.get::<_, i64>(0))
        .map_err(map_sqlite_error)
        .and_then(strict_safe_integer)
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AdapterHistoryRowInventoryV1 {
    key_digest: Sha256Digest,
    row_digest: Sha256Digest,
}

struct AdapterHistoryTableInventoryV1 {
    count: u64,
    digest: Sha256Digest,
    rows: Vec<AdapterHistoryRowInventoryV1>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AdapterGenerationBindingV1 {
    generation: u64,
    key_digest: Sha256Digest,
}

struct CapturedAdapterHistoryV1 {
    snapshot: AdapterHistorySnapshotV1,
    tables: [AdapterHistoryTableInventoryV1; 6],
    generation_axes: [Vec<AdapterGenerationBindingV1>; 7],
}

/// Captures a strict-openable adapter root into the non-authoritative history projection used
/// by the cross-store classifier. All values come from the reviewed SQLite schema; paths and
/// canonical wire bytes are hashed and never returned.
fn capture_adapter_history_v1(
    connection: &Connection,
) -> Result<CapturedAdapterHistoryV1, QuarantineStoreErrorV1> {
    let root_identity = read_adapter_root_identity_v1(connection)?;
    crate::schema::verify_full(connection, root_identity)
        .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)?;
    capture_adapter_history_raw_v1(connection)
}

fn capture_adapter_history_raw_v1(
    connection: &Connection,
) -> Result<CapturedAdapterHistoryV1, QuarantineStoreErrorV1> {
    let raw = connection
        .query_row(
            "SELECT root_identity, store_generation, inbox_generation,
                    consumption_generation, receipt_generation, conflict_generation,
                    quarantine_generation, event_generation,
                    epoch_observer_generation, restore_state_generation
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .map_err(map_sqlite_error)?;
    let root_identity: [u8; 32] = raw
        .0
        .try_into()
        .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)?;
    let generations = AdapterGenerationVectorV1 {
        store: strict_safe_integer(raw.1)?,
        inbox: strict_safe_integer(raw.2)?,
        consumption: strict_safe_integer(raw.3)?,
        receipt: strict_safe_integer(raw.4)?,
        conflict: strict_safe_integer(raw.5)?,
        quarantine: strict_safe_integer(raw.6)?,
        event: strict_safe_integer(raw.7)?,
        epoch_observer: strict_safe_integer(raw.8)?,
        restore_state: strict_safe_integer(raw.9)?,
    };
    let tables = capture_adapter_history_tables_v1(connection)?;
    let generation_axes = capture_adapter_generation_axes_v1(connection)?;
    let history_rows = tables.iter().try_fold(0_u64, |total, table| {
        total
            .checked_add(table.count)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(QuarantineStoreErrorV1::InvariantFailed)
    })?;
    Ok(CapturedAdapterHistoryV1 {
        snapshot: AdapterHistorySnapshotV1 {
            root_identity_digest: Sha256Digest::digest(&root_identity),
            generations,
            history_generation: generations.store,
            history_rows,
            history_digest: adapter_history_inventory_digest_v1(&tables),
        },
        tables,
        generation_axes,
    })
}

fn read_adapter_root_identity_v1(
    connection: &Connection,
) -> Result<crate::root_safety::AdapterRootIdentityV1, QuarantineStoreErrorV1> {
    let bytes = connection
        .query_row(
            "SELECT root_identity FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(map_sqlite_error)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)?;
    Ok(crate::root_safety::AdapterRootIdentityV1::from_bytes(bytes))
}

fn capture_adapter_history_tables_v1(
    connection: &Connection,
) -> Result<[AdapterHistoryTableInventoryV1; 6], QuarantineStoreErrorV1> {
    let mut tables: [AdapterHistoryTableInventoryV1; 6] =
        std::array::from_fn(|_| AdapterHistoryTableInventoryV1 {
            count: 0,
            digest: Sha256Digest::from_bytes([0; 32]),
            rows: Vec::new(),
        });
    for (index, (table, order)) in ADAPTER_HISTORY_TABLES_V1.into_iter().enumerate() {
        tables[index] = capture_adapter_history_table_v1(connection, table, order)?;
    }
    Ok(tables)
}

fn capture_adapter_history_table_v1(
    connection: &Connection,
    table: &str,
    order: &str,
) -> Result<AdapterHistoryTableInventoryV1, QuarantineStoreErrorV1> {
    let sql = format!("SELECT * FROM {table} ORDER BY {order}");
    let mut statement = connection.prepare(&sql).map_err(map_sqlite_error)?;
    let column_count = statement.column_count();
    let mut rows = statement.query([]).map_err(map_sqlite_error)?;
    let mut count = 0_u64;
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_HISTORY_TABLE_DOMAIN_V1);
    hash_len_prefixed_v1(&mut hasher, table.as_bytes())?;
    let mut inventory_rows = Vec::new();
    while let Some(row) = rows.next().map_err(map_sqlite_error)? {
        count = count
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(QuarantineStoreErrorV1::InvariantFailed)?;
        let mut key_hasher = Sha256::new();
        key_hasher.update(ADAPTER_HISTORY_ROW_KEY_DOMAIN_V1);
        hash_len_prefixed_v1(&mut key_hasher, table.as_bytes())?;
        hash_sql_value_v1(&mut key_hasher, row.get_ref(0).map_err(map_sqlite_error)?)?;
        let key_digest = Sha256Digest::from_bytes(key_hasher.finalize().into());

        let mut row_hasher = Sha256::new();
        row_hasher.update(ADAPTER_HISTORY_ROW_DOMAIN_V1);
        hash_len_prefixed_v1(&mut row_hasher, table.as_bytes())?;
        row_hasher.update(key_digest.as_bytes());
        hasher.update(count.to_be_bytes());
        for index in 0..column_count {
            hash_sql_value_v1(
                &mut row_hasher,
                row.get_ref(index).map_err(map_sqlite_error)?,
            )?;
        }
        let row_digest = Sha256Digest::from_bytes(row_hasher.finalize().into());
        hasher.update(key_digest.as_bytes());
        hasher.update(row_digest.as_bytes());
        inventory_rows.push(AdapterHistoryRowInventoryV1 {
            key_digest,
            row_digest,
        });
    }
    Ok(AdapterHistoryTableInventoryV1 {
        count,
        digest: Sha256Digest::from_bytes(hasher.finalize().into()),
        rows: inventory_rows,
    })
}

fn capture_adapter_generation_axes_v1(
    connection: &Connection,
) -> Result<[Vec<AdapterGenerationBindingV1>; 7], QuarantineStoreErrorV1> {
    let mut axes: [Vec<AdapterGenerationBindingV1>; 7] = std::array::from_fn(|_| Vec::new());
    for (index, (table, generation_column, key_column)) in
        ADAPTER_GENERATION_AXES_V1.into_iter().enumerate()
    {
        let sql = format!(
            "SELECT {generation_column}, {key_column}
             FROM {table}
             ORDER BY {generation_column}, {key_column}"
        );
        let mut statement = connection.prepare(&sql).map_err(map_sqlite_error)?;
        let mut rows = statement.query([]).map_err(map_sqlite_error)?;
        while let Some(row) = rows.next().map_err(map_sqlite_error)? {
            let generation = strict_safe_integer(row.get(0).map_err(map_sqlite_error)?)?;
            let mut hasher = Sha256::new();
            hasher.update(ADAPTER_GENERATION_BINDING_DOMAIN_V1);
            hash_len_prefixed_v1(&mut hasher, table.as_bytes())?;
            hash_len_prefixed_v1(&mut hasher, generation_column.as_bytes())?;
            hash_sql_value_v1(&mut hasher, row.get_ref(1).map_err(map_sqlite_error)?)?;
            axes[index].push(AdapterGenerationBindingV1 {
                generation,
                key_digest: Sha256Digest::from_bytes(hasher.finalize().into()),
            });
        }
    }
    Ok(axes)
}

fn adapter_history_inventory_digest_v1(
    tables: &[AdapterHistoryTableInventoryV1; 6],
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_HISTORY_DOMAIN_V1);
    for ((table, _), inventory) in ADAPTER_HISTORY_TABLES_V1.into_iter().zip(tables) {
        hasher.update((table.len() as u64).to_be_bytes());
        hasher.update(table.as_bytes());
        hasher.update(inventory.count.to_be_bytes());
        hasher.update(inventory.digest.as_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_sql_value_v1(
    hasher: &mut Sha256,
    value: ValueRef<'_>,
) -> Result<(), QuarantineStoreErrorV1> {
    match value {
        ValueRef::Null => hasher.update([0]),
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            hasher.update([2]);
            hasher.update(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => {
            hasher.update([3]);
            hash_len_prefixed_v1(hasher, value)?;
        }
        ValueRef::Blob(value) => {
            hasher.update([4]);
            hash_len_prefixed_v1(hasher, value)?;
        }
    }
    Ok(())
}

fn hash_len_prefixed_v1(hasher: &mut Sha256, value: &[u8]) -> Result<(), QuarantineStoreErrorV1> {
    let length = u64::try_from(value.len())
        .ok()
        .filter(|length| *length <= MAX_SAFE_U64)
        .ok_or(QuarantineStoreErrorV1::InvariantFailed)?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn project_adapter_observed_history_v1(
    trusted: &CapturedAdapterHistoryV1,
    observed: &CapturedAdapterHistoryV1,
) -> AdapterObservedHistoryV1 {
    AdapterObservedHistoryV1 {
        root_identity_digest: observed.snapshot.root_identity_digest,
        generations: observed.snapshot.generations,
        history_generation: observed.snapshot.history_generation,
        history_rows: observed.snapshot.history_rows,
        retained_checkpoint_digest: exact_retained_checkpoint_digest_v1(trusted, observed),
        complete_history_digest: observed.snapshot.history_digest,
    }
}

fn exact_retained_checkpoint_digest_v1(
    trusted: &CapturedAdapterHistoryV1,
    observed: &CapturedAdapterHistoryV1,
) -> Sha256Digest {
    let all_trusted_rows_remain_exact =
        trusted
            .tables
            .iter()
            .zip(&observed.tables)
            .all(|(trusted_table, observed_table)| {
                trusted_table.rows.iter().all(|trusted_row| {
                    observed_table.rows.iter().any(|observed_row| {
                        observed_row.key_digest == trusted_row.key_digest
                            && observed_row.row_digest == trusted_row.row_digest
                    })
                })
            });
    if all_trusted_rows_remain_exact {
        return trusted.snapshot.history_digest;
    }

    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_HISTORY_CHECKPOINT_MISMATCH_DOMAIN_V1);
    hasher.update(trusted.snapshot.history_digest.as_bytes());
    hasher.update(observed.snapshot.history_digest.as_bytes());
    for (trusted_table, observed_table) in trusted.tables.iter().zip(&observed.tables) {
        for trusted_row in &trusted_table.rows {
            hasher.update(trusted_row.key_digest.as_bytes());
            match observed_table
                .rows
                .iter()
                .find(|observed_row| observed_row.key_digest == trusted_row.key_digest)
            {
                Some(observed_row) => {
                    hasher.update([1]);
                    hasher.update(observed_row.row_digest.as_bytes());
                }
                None => hasher.update([0]),
            }
        }
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn adapter_generation_reuse_observed_v1(
    trusted: &CapturedAdapterHistoryV1,
    observed: &CapturedAdapterHistoryV1,
) -> bool {
    trusted
        .generation_axes
        .iter()
        .zip(&observed.generation_axes)
        .any(|(trusted_axis, observed_axis)| {
            let duplicate_observed_generation = observed_axis
                .windows(2)
                .any(|pair| pair[0].generation == pair[1].generation);
            let rebound_trusted_generation = trusted_axis.iter().any(|trusted_binding| {
                let observed_at_generation = observed_axis
                    .iter()
                    .filter(|observed_binding| {
                        observed_binding.generation == trusted_binding.generation
                    })
                    .collect::<Vec<_>>();
                !observed_at_generation.is_empty()
                    && observed_at_generation.iter().all(|observed_binding| {
                        observed_binding.key_digest != trusted_binding.key_digest
                    })
            });
            duplicate_observed_generation || rebound_trusted_generation
        })
}

fn has_duplicate_adapter_generation_v1(
    connection: &Connection,
) -> Result<bool, QuarantineStoreErrorV1> {
    for (table, generation_column, _) in ADAPTER_GENERATION_AXES_V1 {
        let sql = format!(
            "SELECT 1 FROM {table}
             GROUP BY {generation_column}
             HAVING COUNT(*) > 1
             LIMIT 1"
        );
        let reused: Option<i64> = connection
            .query_row(&sql, [], |row| row.get(0))
            .optional()
            .map_err(map_sqlite_error)?;
        if reused.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

struct AdapterCrossStoreSelectionV1<'selection> {
    grant_id: Sha256Digest,
    operation_id: &'selection str,
    dispatch_attempt_id: Sha256Digest,
    receipt_id: Option<Sha256Digest>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct GrantInventoryRecordV1 {
    grant_id: [u8; 32],
    projection: AdapterCrossStoreRecordV1,
    source_generation_digest: Sha256Digest,
    row_digest: Sha256Digest,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReceiptInventoryRecordV1 {
    receipt_id: [u8; 32],
    projection: AdapterCrossStoreRecordV1,
    source_generation_digest: Sha256Digest,
    row_digest: Sha256Digest,
}

struct CrossStoreInventoryV1 {
    grants: Vec<GrantInventoryRecordV1>,
    receipts: Vec<ReceiptInventoryRecordV1>,
    digest: Sha256Digest,
}

impl CrossStoreInventoryV1 {
    fn grant(&self, grant_id: Sha256Digest) -> Option<GrantInventoryRecordV1> {
        self.grants
            .iter()
            .copied()
            .find(|record| record.grant_id.as_slice() == grant_id.as_bytes())
    }

    fn receipt(&self, receipt_id: Sha256Digest) -> Option<ReceiptInventoryRecordV1> {
        self.receipts
            .iter()
            .copied()
            .find(|record| record.receipt_id.as_slice() == receipt_id.as_bytes())
    }
}

fn cross_store_grant_binding_digest_v1(
    grant_id: Sha256Digest,
    operation_id: &str,
    dispatch_attempt_id: Sha256Digest,
) -> Sha256Digest {
    domain_digest(&[
        ADAPTER_GRANT_GENERATION_BINDING_DOMAIN_V1,
        grant_id.as_bytes(),
        operation_id.as_bytes(),
        dispatch_attempt_id.as_bytes(),
    ])
}

fn cross_store_receipt_binding_digest_v1(
    grant_id: Sha256Digest,
    receipt_id: Sha256Digest,
    operation_id: &str,
    dispatch_attempt_id: Sha256Digest,
) -> Sha256Digest {
    domain_digest(&[
        ADAPTER_RECEIPT_GENERATION_BINDING_DOMAIN_V1,
        grant_id.as_bytes(),
        receipt_id.as_bytes(),
        operation_id.as_bytes(),
        dispatch_attempt_id.as_bytes(),
    ])
}

fn load_adapter_cross_store_inventory_v1(
    connection: &Connection,
) -> Result<CrossStoreInventoryV1, QuarantineStoreErrorV1> {
    let grants = load_grant_inventory_v1(
        connection,
        "SELECT grant_id, operation_id, dispatch_attempt_id, grant_digest,
                received_generation, current_generation, epoch_observer_generation
         FROM grant_inbox ORDER BY grant_id",
        ADAPTER_GRANT_INVENTORY_ROW_DOMAIN_V1,
        3,
    )?;
    let receipts = load_receipt_inventory_v1(
        connection,
        "SELECT receipt_id, grant_id, operation_id, dispatch_attempt_id, receipt_digest,
                receipt_generation
         FROM execution_receipts ORDER BY receipt_id",
        ADAPTER_RECEIPT_INVENTORY_ROW_DOMAIN_V1,
        1,
    )?;
    Ok(finish_cross_store_inventory_v1(b'A', grants, receipts))
}

fn load_counterpart_cross_store_inventory_v1(
    connection: &Connection,
) -> Result<CrossStoreInventoryV1, QuarantineStoreErrorV1> {
    let grants = load_grant_inventory_v1(
        connection,
        "SELECT grant_id, operation_id, dispatch_attempt_id, grant_digest,
                created_generation, preparation_transition_generation
         FROM dispatch_grants ORDER BY grant_id",
        COORDINATOR_GRANT_INVENTORY_ROW_DOMAIN_V1,
        2,
    )?;
    let receipts = load_receipt_inventory_v1(
        connection,
        "SELECT receipt_id, grant_id, operation_id, dispatch_attempt_id, receipt_digest,
                receipt_generation
         FROM dispatch_receipts ORDER BY receipt_id",
        COORDINATOR_RECEIPT_INVENTORY_ROW_DOMAIN_V1,
        1,
    )?;
    Ok(finish_cross_store_inventory_v1(b'C', grants, receipts))
}

fn load_grant_inventory_v1(
    connection: &Connection,
    sql: &str,
    row_domain: &[u8],
    generation_count: usize,
) -> Result<Vec<GrantInventoryRecordV1>, QuarantineStoreErrorV1> {
    let mut statement = connection.prepare(sql).map_err(map_sqlite_error)?;
    let mut rows = statement.query([]).map_err(map_sqlite_error)?;
    let mut inventory = Vec::new();
    while let Some(row) = rows.next().map_err(map_sqlite_error)? {
        let grant_id = exact_digest_bytes_v1(row.get(0).map_err(map_sqlite_error)?)?;
        let operation_id: String = row.get(1).map_err(map_sqlite_error)?;
        let dispatch_attempt_id = exact_digest_bytes_v1(row.get(2).map_err(map_sqlite_error)?)?;
        let canonical_digest = exact_digest_bytes_v1(row.get(3).map_err(map_sqlite_error)?)?;
        let generations = (0..generation_count)
            .map(|index| {
                row.get::<_, i64>(4 + index)
                    .map_err(map_sqlite_error)
                    .and_then(strict_safe_integer)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let projection = AdapterCrossStoreRecordV1 {
            canonical_digest: Sha256Digest::from_bytes(canonical_digest),
            generation_binding_digest: cross_store_grant_binding_digest_v1(
                Sha256Digest::from_bytes(grant_id),
                &operation_id,
                Sha256Digest::from_bytes(dispatch_attempt_id),
            ),
        };
        inventory.push(GrantInventoryRecordV1 {
            grant_id,
            projection,
            source_generation_digest: generation_digest_v1(row_domain, &generations),
            row_digest: inventory_row_digest_v1(row_domain, projection, &generations),
        });
    }
    Ok(inventory)
}

fn load_receipt_inventory_v1(
    connection: &Connection,
    sql: &str,
    row_domain: &[u8],
    generation_count: usize,
) -> Result<Vec<ReceiptInventoryRecordV1>, QuarantineStoreErrorV1> {
    let mut statement = connection.prepare(sql).map_err(map_sqlite_error)?;
    let mut rows = statement.query([]).map_err(map_sqlite_error)?;
    let mut inventory = Vec::new();
    while let Some(row) = rows.next().map_err(map_sqlite_error)? {
        let receipt_id = exact_digest_bytes_v1(row.get(0).map_err(map_sqlite_error)?)?;
        let grant_id = exact_digest_bytes_v1(row.get(1).map_err(map_sqlite_error)?)?;
        let operation_id: String = row.get(2).map_err(map_sqlite_error)?;
        let dispatch_attempt_id = exact_digest_bytes_v1(row.get(3).map_err(map_sqlite_error)?)?;
        let canonical_digest = exact_digest_bytes_v1(row.get(4).map_err(map_sqlite_error)?)?;
        let generations = (0..generation_count)
            .map(|index| {
                row.get::<_, i64>(5 + index)
                    .map_err(map_sqlite_error)
                    .and_then(strict_safe_integer)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let projection = AdapterCrossStoreRecordV1 {
            canonical_digest: Sha256Digest::from_bytes(canonical_digest),
            generation_binding_digest: cross_store_receipt_binding_digest_v1(
                Sha256Digest::from_bytes(grant_id),
                Sha256Digest::from_bytes(receipt_id),
                &operation_id,
                Sha256Digest::from_bytes(dispatch_attempt_id),
            ),
        };
        inventory.push(ReceiptInventoryRecordV1 {
            receipt_id,
            projection,
            source_generation_digest: generation_digest_v1(row_domain, &generations),
            row_digest: inventory_row_digest_v1(row_domain, projection, &generations),
        });
    }
    Ok(inventory)
}

fn exact_digest_bytes_v1(bytes: Vec<u8>) -> Result<[u8; 32], QuarantineStoreErrorV1> {
    bytes
        .try_into()
        .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)
}

fn generation_digest_v1(domain: &[u8], generations: &[u64]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((generations.len() as u64).to_be_bytes());
    for generation in generations {
        hasher.update(generation.to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn inventory_row_digest_v1(
    domain: &[u8],
    projection: AdapterCrossStoreRecordV1,
    generations: &[u64],
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(projection.canonical_digest.as_bytes());
    hasher.update(projection.generation_binding_digest.as_bytes());
    hasher.update((generations.len() as u64).to_be_bytes());
    for generation in generations {
        hasher.update(generation.to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn finish_cross_store_inventory_v1(
    side: u8,
    grants: Vec<GrantInventoryRecordV1>,
    receipts: Vec<ReceiptInventoryRecordV1>,
) -> CrossStoreInventoryV1 {
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_CROSS_STORE_INVENTORY_DOMAIN_V1);
    hasher.update([side]);
    hasher.update((grants.len() as u64).to_be_bytes());
    for record in &grants {
        hasher.update(record.grant_id);
        hasher.update(record.row_digest.as_bytes());
    }
    hasher.update((receipts.len() as u64).to_be_bytes());
    for record in &receipts {
        hasher.update(record.receipt_id);
        hasher.update(record.row_digest.as_bytes());
    }
    CrossStoreInventoryV1 {
        grants,
        receipts,
        digest: Sha256Digest::from_bytes(hasher.finalize().into()),
    }
}

fn cross_store_inventory_digest_v1(
    adapter: &CrossStoreInventoryV1,
    counterpart: &CrossStoreInventoryV1,
    relationship: AdapterLifecycleRelationshipV1,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(ADAPTER_CROSS_STORE_INVENTORY_DOMAIN_V1);
    hasher.update([relationship.evidence_tag()]);
    hasher.update(adapter.digest.as_bytes());
    hasher.update(counterpart.digest.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn exact_adapter_projection_checkpoint_v1(
    trusted_history: &CapturedAdapterHistoryV1,
    observed_history: &CapturedAdapterHistoryV1,
    trusted_adapter: &CrossStoreInventoryV1,
    observed_adapter: &CrossStoreInventoryV1,
    trusted_counterpart: &CrossStoreInventoryV1,
    observed_counterpart: &CrossStoreInventoryV1,
) -> bool {
    trusted_history.snapshot == observed_history.snapshot
        && trusted_adapter.digest == observed_adapter.digest
        && trusted_counterpart.digest == observed_counterpart.digest
}

fn detect_exhaustive_relation_corruption_v1(
    adapter: &CrossStoreInventoryV1,
    counterpart: &CrossStoreInventoryV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    for adapter_record in &adapter.grants {
        let counterpart_record = counterpart
            .grants
            .iter()
            .find(|record| record.grant_id == adapter_record.grant_id);
        match counterpart_record {
            None => return Some(AdapterCrossStoreCorruptionV1::OrphanAdapterInbox),
            Some(counterpart_record)
                if adapter_record.projection.canonical_digest
                    != counterpart_record.projection.canonical_digest =>
            {
                return Some(AdapterCrossStoreCorruptionV1::GrantDigestConflict)
            }
            Some(counterpart_record)
                if adapter_record.projection.generation_binding_digest
                    != counterpart_record.projection.generation_binding_digest =>
            {
                return Some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict)
            }
            Some(_) => {}
        }
    }
    for adapter_record in &adapter.receipts {
        let counterpart_record = counterpart
            .receipts
            .iter()
            .find(|record| record.receipt_id == adapter_record.receipt_id);
        match counterpart_record {
            None => return Some(AdapterCrossStoreCorruptionV1::OrphanAdapterReceipt),
            Some(counterpart_record)
                if adapter_record.projection.canonical_digest
                    != counterpart_record.projection.canonical_digest =>
            {
                return Some(AdapterCrossStoreCorruptionV1::ReceiptDigestConflict)
            }
            Some(counterpart_record)
                if adapter_record.projection.generation_binding_digest
                    != counterpart_record.projection.generation_binding_digest =>
            {
                return Some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict)
            }
            Some(_) => {}
        }
    }
    // A coordinator receipt can only be retained after the adapter has durably retained the
    // matching receipt. Unlike a coordinator-only grant (the valid DISPATCHING shape), a
    // coordinator-only receipt is not a legitimate lifecycle advance and therefore remains an
    // intrinsic cross-store disagreement even when both individual roots are structurally strict.
    if counterpart.receipts.iter().any(|counterpart_record| {
        !adapter
            .receipts
            .iter()
            .any(|adapter_record| adapter_record.receipt_id == counterpart_record.receipt_id)
    }) {
        return Some(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement);
    }
    None
}

fn detect_counterpart_generation_rebind_v1(
    trusted: &CrossStoreInventoryV1,
    observed: &CrossStoreInventoryV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    let grant_rebound = trusted.grants.iter().any(|trusted_record| {
        observed
            .grants
            .iter()
            .find(|record| record.grant_id == trusted_record.grant_id)
            .is_some_and(|observed_record| {
                observed_record.source_generation_digest != trusted_record.source_generation_digest
            })
    });
    let receipt_rebound = trusted.receipts.iter().any(|trusted_record| {
        observed
            .receipts
            .iter()
            .find(|record| record.receipt_id == trusted_record.receipt_id)
            .is_some_and(|observed_record| {
                observed_record.source_generation_digest != trusted_record.source_generation_digest
            })
    });
    (grant_rebound || receipt_rebound)
        .then_some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict)
}

fn detect_same_store_inventory_change_v1(
    trusted: &CrossStoreInventoryV1,
    observed: &CrossStoreInventoryV1,
) -> Option<AdapterCrossStoreCorruptionV1> {
    for trusted_record in &trusted.grants {
        let Some(observed_record) = observed
            .grants
            .iter()
            .find(|record| record.grant_id == trusted_record.grant_id)
        else {
            return Some(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement);
        };
        if observed_record.projection.canonical_digest != trusted_record.projection.canonical_digest
        {
            return Some(AdapterCrossStoreCorruptionV1::GrantDigestConflict);
        }
        if observed_record.projection.generation_binding_digest
            != trusted_record.projection.generation_binding_digest
            || observed_record.source_generation_digest != trusted_record.source_generation_digest
        {
            return Some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict);
        }
        if observed_record.row_digest != trusted_record.row_digest {
            return Some(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement);
        }
    }
    for trusted_record in &trusted.receipts {
        let Some(observed_record) = observed
            .receipts
            .iter()
            .find(|record| record.receipt_id == trusted_record.receipt_id)
        else {
            return Some(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement);
        };
        if observed_record.projection.canonical_digest != trusted_record.projection.canonical_digest
        {
            return Some(AdapterCrossStoreCorruptionV1::ReceiptDigestConflict);
        }
        if observed_record.projection.generation_binding_digest
            != trusted_record.projection.generation_binding_digest
            || observed_record.source_generation_digest != trusted_record.source_generation_digest
        {
            return Some(AdapterCrossStoreCorruptionV1::CrossGenerationConflict);
        }
        if observed_record.row_digest != trusted_record.row_digest {
            return Some(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement);
        }
    }
    None
}

fn lifecycle_inventory_is_exact_v1(
    relationship: AdapterLifecycleRelationshipV1,
    adapter: &CrossStoreInventoryV1,
    counterpart: &CrossStoreInventoryV1,
) -> bool {
    match relationship {
        AdapterLifecycleRelationshipV1::Prepared => {
            adapter.grants.is_empty()
                && adapter.receipts.is_empty()
                && counterpart.grants.is_empty()
                && counterpart.receipts.is_empty()
        }
        AdapterLifecycleRelationshipV1::Dispatching | AdapterLifecycleRelationshipV1::Ambiguous => {
            adapter.grants.is_empty()
                && adapter.receipts.is_empty()
                && counterpart.receipts.is_empty()
                && !counterpart.grants.is_empty()
        }
        AdapterLifecycleRelationshipV1::AdapterReceived => {
            !adapter.grants.is_empty()
                && adapter.grants.len() == counterpart.grants.len()
                && adapter.receipts.is_empty()
                && counterpart.receipts.is_empty()
        }
        AdapterLifecycleRelationshipV1::Consumed => {
            !adapter.grants.is_empty()
                && adapter.grants.len() == counterpart.grants.len()
                && !adapter.receipts.is_empty()
                && adapter.receipts.len() == counterpart.receipts.len()
        }
    }
}

/// Lifecycle shape selected by the coordinator for one redacted adapter projection audit.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterCorruptionAuditLifecycleV1 {
    Prepared,
    Dispatching,
    AdapterReceived,
    Consumed,
    Ambiguous,
}

impl From<AdapterCorruptionAuditLifecycleV1> for AdapterLifecycleRelationshipV1 {
    fn from(value: AdapterCorruptionAuditLifecycleV1) -> Self {
        match value {
            AdapterCorruptionAuditLifecycleV1::Prepared => Self::Prepared,
            AdapterCorruptionAuditLifecycleV1::Dispatching => Self::Dispatching,
            AdapterCorruptionAuditLifecycleV1::AdapterReceived => Self::AdapterReceived,
            AdapterCorruptionAuditLifecycleV1::Consumed => Self::Consumed,
            AdapterCorruptionAuditLifecycleV1::Ambiguous => Self::Ambiguous,
        }
    }
}

/// Opaque proof that the adapter and its sovereign coordinator remain in one exact PAUSE cut.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdapterCorruptionAuditPauseEvidenceV1 {
    pause_generation: u64,
    pause_binding_sha256: [u8; 32],
}

impl AdapterCorruptionAuditPauseEvidenceV1 {
    #[doc(hidden)]
    pub fn try_new(
        pause_generation: u64,
        pause_binding_sha256: [u8; 32],
    ) -> Result<Self, AdapterCorruptionAuditErrorV1> {
        if !(1..=MAX_SAFE_U64).contains(&pause_generation) || pause_binding_sha256 == [0_u8; 32] {
            return Err(AdapterCorruptionAuditErrorV1::InvariantFailed);
        }
        Ok(Self {
            pause_generation,
            pause_binding_sha256,
        })
    }
}

impl std::fmt::Debug for AdapterCorruptionAuditPauseEvidenceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterCorruptionAuditPauseEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Caller-owned PAUSE custody required by the default adapter corruption audit.
///
/// Implementations must compare the exact opaque proof on every recheck. The audit captures the
/// proof before any SQLite lock, rechecks it immediately before the locked cut, and rechecks it
/// after all adapter roots have been revalidated. Neither method grants execution authority.
#[doc(hidden)]
pub trait AdapterCorruptionAuditPauseV1 {
    fn capture_adapter_corruption_audit_pause_v1(
        &mut self,
    ) -> Result<AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditErrorV1>;

    fn recheck_adapter_corruption_audit_pause_v1(
        &mut self,
        expected: &AdapterCorruptionAuditPauseEvidenceV1,
    ) -> Result<(), AdapterCorruptionAuditErrorV1>;
}

/// Bounded relationship identity for a projection-only adapter corruption audit.
#[doc(hidden)]
pub struct AdapterCorruptionAuditSelectionV1 {
    grant_id: Sha256Digest,
    operation_id: String,
    dispatch_attempt_id: Sha256Digest,
    receipt_id: Option<Sha256Digest>,
}

impl AdapterCorruptionAuditSelectionV1 {
    pub fn try_new(
        grant_id: [u8; 32],
        operation_id: impl Into<String>,
        dispatch_attempt_id: [u8; 32],
        receipt_id: Option<[u8; 32]>,
    ) -> Result<Self, AdapterCorruptionAuditErrorV1> {
        let operation_id = operation_id.into();
        if operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(AdapterCorruptionAuditErrorV1::InvariantFailed);
        }
        Ok(Self {
            grant_id: Sha256Digest::from_bytes(grant_id),
            operation_id,
            dispatch_attempt_id: Sha256Digest::from_bytes(dispatch_attempt_id),
            receipt_id: receipt_id.map(Sha256Digest::from_bytes),
        })
    }

    fn as_internal_v1(&self) -> AdapterCrossStoreSelectionV1<'_> {
        AdapterCrossStoreSelectionV1 {
            grant_id: self.grant_id,
            operation_id: &self.operation_id,
            dispatch_attempt_id: self.dispatch_attempt_id,
            receipt_id: self.receipt_id,
        }
    }
}

impl std::fmt::Debug for AdapterCorruptionAuditSelectionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterCorruptionAuditSelectionV1")
            .finish_non_exhaustive()
    }
}

/// Redacted permanent corruption custody returned by the default-compiled audit boundary.
#[doc(hidden)]
pub struct AdapterRetainedCorruptionAuditV1 {
    reason_code: &'static str,
    quarantine_generation: u64,
}

impl AdapterRetainedCorruptionAuditV1 {
    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub const fn quarantine_generation(&self) -> u64 {
        self.quarantine_generation
    }
}

impl std::fmt::Debug for AdapterRetainedCorruptionAuditV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterRetainedCorruptionAuditV1")
            .finish_non_exhaustive()
    }
}

/// Non-authoritative result of an adapter projection audit.
#[doc(hidden)]
pub enum AdapterCorruptionAuditOutcomeV1 {
    NoCorruptionObserved,
    Quarantined(AdapterRetainedCorruptionAuditV1),
}

impl std::fmt::Debug for AdapterCorruptionAuditOutcomeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCorruptionObserved => {
                formatter.write_str("AdapterCorruptionAuditOutcomeV1::NoCorruptionObserved")
            }
            Self::Quarantined(_) => {
                formatter.write_str("AdapterCorruptionAuditOutcomeV1::Quarantined(..)")
            }
        }
    }
}

/// Payload-free failure returned by the default-compiled adapter audit boundary.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterCorruptionAuditErrorV1 {
    Busy,
    Unavailable,
    RestorePending,
    CheckpointMismatch,
    InvariantFailed,
}

impl AdapterCorruptionAuditErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Busy => "BUSY",
            Self::Unavailable => "UNAVAILABLE",
            Self::RestorePending => "RESTORE_PENDING",
            Self::CheckpointMismatch => "CHECKPOINT_MISMATCH",
            Self::InvariantFailed => "INVARIANT_FAILED",
        }
    }
}

impl std::fmt::Debug for AdapterCorruptionAuditErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::fmt::Display for AdapterCorruptionAuditErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AdapterCorruptionAuditErrorV1 {}

impl From<QuarantineStoreErrorV1> for AdapterCorruptionAuditErrorV1 {
    fn from(value: QuarantineStoreErrorV1) -> Self {
        match value {
            QuarantineStoreErrorV1::Busy => Self::Busy,
            QuarantineStoreErrorV1::Unavailable => Self::Unavailable,
            QuarantineStoreErrorV1::RestorePending => Self::RestorePending,
            QuarantineStoreErrorV1::InvariantFailed => Self::InvariantFailed,
        }
    }
}

#[cfg(feature = "test-fault-injection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterLifecycleRelationshipForTestV1 {
    Prepared,
    Dispatching,
    AdapterReceived,
    Consumed,
    Ambiguous,
}

#[cfg(feature = "test-fault-injection")]
impl From<AdapterLifecycleRelationshipForTestV1> for AdapterLifecycleRelationshipV1 {
    fn from(value: AdapterLifecycleRelationshipForTestV1) -> Self {
        match value {
            AdapterLifecycleRelationshipForTestV1::Prepared => Self::Prepared,
            AdapterLifecycleRelationshipForTestV1::Dispatching => Self::Dispatching,
            AdapterLifecycleRelationshipForTestV1::AdapterReceived => Self::AdapterReceived,
            AdapterLifecycleRelationshipForTestV1::Consumed => Self::Consumed,
            AdapterLifecycleRelationshipForTestV1::Ambiguous => Self::Ambiguous,
        }
    }
}

/// Exact identities selecting one relationship from real adapter/coordinator SQLite roots.
#[cfg(feature = "test-fault-injection")]
pub struct AdapterCrossStoreIdsForTestV1 {
    grant_id: Sha256Digest,
    operation_id: String,
    dispatch_attempt_id: Sha256Digest,
    receipt_id: Option<Sha256Digest>,
}

#[cfg(feature = "test-fault-injection")]
impl AdapterCrossStoreIdsForTestV1 {
    pub fn try_new(
        grant_id: [u8; 32],
        operation_id: impl Into<String>,
        dispatch_attempt_id: [u8; 32],
        receipt_id: Option<[u8; 32]>,
    ) -> Result<Self, AdapterCorruptionTestErrorV1> {
        let operation_id = operation_id.into();
        if operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(AdapterCorruptionTestErrorV1::InvariantFailed);
        }
        Ok(Self {
            grant_id: Sha256Digest::from_bytes(grant_id),
            operation_id,
            dispatch_attempt_id: Sha256Digest::from_bytes(dispatch_attempt_id),
            receipt_id: receipt_id.map(Sha256Digest::from_bytes),
        })
    }
}

#[cfg(feature = "test-fault-injection")]
impl std::fmt::Debug for AdapterCrossStoreIdsForTestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterCrossStoreIdsForTestV1")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "test-fault-injection")]
pub struct AdapterRetainedCorruptionForTestV1 {
    reason_code: &'static str,
    quarantine_generation: u64,
}

#[cfg(feature = "test-fault-injection")]
impl AdapterRetainedCorruptionForTestV1 {
    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub const fn quarantine_generation(&self) -> u64 {
        self.quarantine_generation
    }
}

#[cfg(feature = "test-fault-injection")]
impl std::fmt::Debug for AdapterRetainedCorruptionForTestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdapterRetainedCorruptionForTestV1")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "test-fault-injection")]
pub enum AdapterHistoryCustodyForTestV1 {
    NoCorruptionObserved,
    Quarantined(AdapterRetainedCorruptionForTestV1),
}

#[cfg(feature = "test-fault-injection")]
impl std::fmt::Debug for AdapterHistoryCustodyForTestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCorruptionObserved => {
                formatter.write_str("AdapterHistoryCustodyForTestV1::NoCorruptionObserved")
            }
            Self::Quarantined(_) => {
                formatter.write_str("AdapterHistoryCustodyForTestV1::Quarantined(..)")
            }
        }
    }
}

#[cfg(feature = "test-fault-injection")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterCorruptionTestErrorV1 {
    Busy,
    Unavailable,
    RestorePending,
    CheckpointMismatch,
    InvariantFailed,
}

#[cfg(feature = "test-fault-injection")]
impl AdapterCorruptionTestErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Busy => "BUSY",
            Self::Unavailable => "UNAVAILABLE",
            Self::RestorePending => "RESTORE_PENDING",
            Self::CheckpointMismatch => "CHECKPOINT_MISMATCH",
            Self::InvariantFailed => "INVARIANT_FAILED",
        }
    }
}

#[cfg(feature = "test-fault-injection")]
impl std::fmt::Debug for AdapterCorruptionTestErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(feature = "test-fault-injection")]
impl std::fmt::Display for AdapterCorruptionTestErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

#[cfg(feature = "test-fault-injection")]
impl std::error::Error for AdapterCorruptionTestErrorV1 {}

#[cfg(feature = "test-fault-injection")]
impl From<QuarantineStoreErrorV1> for AdapterCorruptionTestErrorV1 {
    fn from(value: QuarantineStoreErrorV1) -> Self {
        match value {
            QuarantineStoreErrorV1::Busy => Self::Busy,
            QuarantineStoreErrorV1::Unavailable => Self::Unavailable,
            QuarantineStoreErrorV1::RestorePending => Self::RestorePending,
            QuarantineStoreErrorV1::InvariantFailed => Self::InvariantFailed,
        }
    }
}

#[cfg(feature = "test-fault-injection")]
impl From<AdapterCorruptionAuditErrorV1> for AdapterCorruptionTestErrorV1 {
    fn from(value: AdapterCorruptionAuditErrorV1) -> Self {
        match value {
            AdapterCorruptionAuditErrorV1::Busy => Self::Busy,
            AdapterCorruptionAuditErrorV1::Unavailable => Self::Unavailable,
            AdapterCorruptionAuditErrorV1::RestorePending => Self::RestorePending,
            AdapterCorruptionAuditErrorV1::CheckpointMismatch => Self::CheckpointMismatch,
            AdapterCorruptionAuditErrorV1::InvariantFailed => Self::InvariantFailed,
        }
    }
}

fn classify_and_retain_adapter_connections_v1(
    trusted: &Connection,
    observed: &mut Connection,
    trusted_counterpart: &Connection,
    observed_counterpart: &mut Connection,
    custody: &mut Connection,
    selection: &AdapterCrossStoreSelectionV1<'_>,
    relationship: AdapterLifecycleRelationshipV1,
) -> Result<AdapterCorruptionCustodyOutcomeV1, QuarantineStoreErrorV1> {
    // Freeze the coordinator projection first, then the adapter branch. Both writer cuts remain
    // held through the branch-local fence commit, so neither half of the observed relationship can
    // advance between capture and fail-closed retention.
    let observed_counterpart_transaction = observed_counterpart
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    let observed_transaction = observed
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sqlite_error)?;
    ensure_distinct_adapter_audit_connections_v1(
        trusted,
        &observed_transaction,
        trusted_counterpart,
        &observed_counterpart_transaction,
        custody,
    )?;
    verify_adapter_audit_custody_v1(custody)?;

    // Classification and the branch-local fence share the writer transaction acquired above:
    // no receive or consume writer can commit between the observed cut and its permanent fence.
    if let Some(retained) = load_retained_global_adapter_corruption_v1(&observed_transaction)? {
        observed_transaction.rollback().map_err(map_sqlite_error)?;
        observed_counterpart_transaction
            .rollback()
            .map_err(map_sqlite_error)?;
        let outcome = retain_adapter_corruption_disposition_v1(custody, retained.disposition)?;
        let AdapterCorruptionCustodyOutcomeV1::Quarantined {
            corruption,
            generation: _,
        } = outcome
        else {
            return Err(QuarantineStoreErrorV1::InvariantFailed);
        };
        if corruption != retained.disposition.corruption() {
            return Err(QuarantineStoreErrorV1::InvariantFailed);
        }
        return Ok(outcome);
    }

    // Strictness belongs to the same writer-frozen snapshot as classification. Checking it on a
    // detached pre-open connection would permit the observed root to advance between proof and
    // comparison, defeating the exact PAUSE checkpoint contract.
    let observed_root_identity = read_adapter_root_identity_v1(&observed_transaction)?;
    let observed_is_strict =
        crate::schema::verify_full(&observed_transaction, observed_root_identity).is_ok();

    let trusted_history = capture_adapter_history_v1(trusted)?;
    let observed_captured_history = capture_adapter_history_raw_v1(&observed_transaction)?;
    let observed_history =
        project_adapter_observed_history_v1(&trusted_history, &observed_captured_history);
    let generation_reuse_observed = has_duplicate_adapter_generation_v1(&observed_transaction)?
        || adapter_generation_reuse_observed_v1(&trusted_history, &observed_captured_history);
    verify_counterpart_readable_v1(trusted_counterpart)?;
    verify_counterpart_readable_v1(&observed_counterpart_transaction)?;

    let trusted_adapter_inventory = load_adapter_cross_store_inventory_v1(trusted)?;
    let observed_adapter_inventory = load_adapter_cross_store_inventory_v1(&observed_transaction)?;
    let trusted_counterpart_inventory =
        load_counterpart_cross_store_inventory_v1(trusted_counterpart)?;
    let observed_counterpart_inventory =
        load_counterpart_cross_store_inventory_v1(&observed_counterpart_transaction)?;

    let trusted_adapter_grant = trusted_adapter_inventory
        .grant(selection.grant_id)
        .map(|record| record.projection);
    let trusted_counterpart_grant = trusted_counterpart_inventory
        .grant(selection.grant_id)
        .map(|record| record.projection);
    let trusted_adapter_receipt = selection
        .receipt_id
        .and_then(|receipt_id| trusted_adapter_inventory.receipt(receipt_id))
        .map(|record| record.projection);
    let trusted_counterpart_receipt = selection
        .receipt_id
        .and_then(|receipt_id| trusted_counterpart_inventory.receipt(receipt_id))
        .map(|record| record.projection);
    let expected_grant_binding = cross_store_grant_binding_digest_v1(
        selection.grant_id,
        selection.operation_id,
        selection.dispatch_attempt_id,
    );
    if [trusted_adapter_grant, trusted_counterpart_grant]
        .into_iter()
        .flatten()
        .any(|record| record.generation_binding_digest != expected_grant_binding)
    {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    if let Some(receipt_id) = selection.receipt_id {
        let expected_receipt_binding = cross_store_receipt_binding_digest_v1(
            selection.grant_id,
            receipt_id,
            selection.operation_id,
            selection.dispatch_attempt_id,
        );
        if [trusted_adapter_receipt, trusted_counterpart_receipt]
            .into_iter()
            .flatten()
            .any(|record| record.generation_binding_digest != expected_receipt_binding)
        {
            return Err(QuarantineStoreErrorV1::InvariantFailed);
        }
    }
    let trusted_inventory = cross_store_inventory_digest_v1(
        &trusted_adapter_inventory,
        &trusted_counterpart_inventory,
        relationship,
    );
    let trusted_input = AdapterCrossStoreHistoryInputV1 {
        relationship,
        trusted: trusted_history.snapshot,
        observed: project_adapter_observed_history_v1(&trusted_history, &trusted_history),
        coordinator_grant: trusted_counterpart_grant,
        adapter_inbox: trusted_adapter_grant,
        coordinator_receipt: trusted_counterpart_receipt,
        adapter_receipt: trusted_adapter_receipt,
        expected_cross_store_inventory_digest: trusted_inventory,
        observed_cross_store_inventory_digest: trusted_inventory,
    };
    if verify_adapter_cross_store_history_v1(&trusted_input)
        != AdapterHistoryVerificationV1::NoCorruptionObserved
    {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    let input = AdapterCrossStoreHistoryInputV1 {
        relationship,
        trusted: trusted_history.snapshot,
        observed: observed_history,
        coordinator_grant: observed_counterpart_inventory
            .grant(selection.grant_id)
            .map(|record| record.projection),
        adapter_inbox: observed_adapter_inventory
            .grant(selection.grant_id)
            .map(|record| record.projection),
        coordinator_receipt: selection
            .receipt_id
            .and_then(|receipt_id| observed_counterpart_inventory.receipt(receipt_id))
            .map(|record| record.projection),
        adapter_receipt: selection
            .receipt_id
            .and_then(|receipt_id| observed_adapter_inventory.receipt(receipt_id))
            .map(|record| record.projection),
        expected_cross_store_inventory_digest: trusted_inventory,
        observed_cross_store_inventory_digest: cross_store_inventory_digest_v1(
            &observed_adapter_inventory,
            &observed_counterpart_inventory,
            relationship,
        ),
    };

    // Corruption that is intrinsic to the frozen observed cut takes precedence over a clean
    // checkpoint mismatch. In particular, same-generation forks and relation digest conflicts
    // remain T097 corruption even if the observed root still satisfies its local strict schema.
    let corruption_before_checkpoint = generation_reuse_observed
        .then_some(AdapterCrossStoreCorruptionV1::AdapterGenerationReused)
        .or_else(|| detect_adapter_history_corruption_before_checkpoint_v1(&input))
        .or_else(|| {
            detect_exhaustive_relation_corruption_v1(
                &observed_adapter_inventory,
                &observed_counterpart_inventory,
            )
        })
        .or_else(|| {
            detect_counterpart_generation_rebind_v1(
                &trusted_counterpart_inventory,
                &observed_counterpart_inventory,
            )
        });

    let exact_checkpoint = exact_adapter_projection_checkpoint_v1(
        &trusted_history,
        &observed_captured_history,
        &trusted_adapter_inventory,
        &observed_adapter_inventory,
        &trusted_counterpart_inventory,
        &observed_counterpart_inventory,
    );

    if corruption_before_checkpoint.is_none() && observed_is_strict {
        observed_transaction.rollback().map_err(map_sqlite_error)?;
        observed_counterpart_transaction
            .rollback()
            .map_err(map_sqlite_error)?;
        return Ok(if exact_checkpoint {
            AdapterCorruptionCustodyOutcomeV1::NoCorruptionObserved
        } else {
            AdapterCorruptionCustodyOutcomeV1::CheckpointMismatch
        });
    }

    let mut anchor_input = input;
    anchor_input.observed_cross_store_inventory_digest =
        anchor_input.expected_cross_store_inventory_digest;
    let corruption = corruption_before_checkpoint
        .or_else(|| detect_adapter_history_corruption_v1(&input))
        .or_else(|| {
            detect_same_store_inventory_change_v1(
                &trusted_adapter_inventory,
                &observed_adapter_inventory,
            )
        })
        .or_else(|| {
            detect_same_store_inventory_change_v1(
                &trusted_counterpart_inventory,
                &observed_counterpart_inventory,
            )
        })
        .or_else(|| detect_adapter_corruption_v1(&anchor_input))
        // A root that failed strict verification can never be reported as a clean checkpoint.
        .unwrap_or(AdapterCrossStoreCorruptionV1::CrossStoreDisagreement);
    let disposition = AdapterCorruptionDispositionV1 {
        corruption,
        custody: AdapterCorruptionCustodyV1::Quarantined,
        execution: AdapterCorruptionExecutionV1::Refused,
        evidence_digest: adapter_corruption_evidence_digest_v1(&input, corruption),
    };

    // Fence the observed branch first. If the independent custody write is interrupted,
    // the branch remains fail-closed and a retry copies the exact retained incident into
    // custody without reclassifying the now-fenced history.
    let local = retain_adapter_corruption_disposition_in_transaction_v1(
        &observed_transaction,
        disposition,
    )?;
    let AdapterCorruptionCustodyOutcomeV1::Quarantined {
        corruption: local_corruption,
        ..
    } = local
    else {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    };
    if local_corruption != disposition.corruption() {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    let local_commit_error = observed_transaction.commit().err();
    let uncertain_commit_readback = local_commit_error
        .as_ref()
        .map(|_| readback_local_fence_after_commit_error_v1(observed, disposition))
        .transpose()?;
    observed_counterpart_transaction
        .rollback()
        .map_err(map_sqlite_error)?;
    if let Some(commit_error) = local_commit_error {
        match uncertain_commit_readback {
            Some(LocalFenceCommitReadbackV1::ExactPresent) => {
                // The local branch proved the exact incident despite the COMMIT return value.
                // Continue only with the independent redacted custody copy.
            }
            Some(LocalFenceCommitReadbackV1::Absent) => {
                return Err(map_sqlite_error(commit_error));
            }
            Some(LocalFenceCommitReadbackV1::Conflict) | None => {
                return Err(QuarantineStoreErrorV1::InvariantFailed);
            }
        }
    }

    let custody_outcome = retain_adapter_corruption_disposition_v1(custody, disposition)?;
    let AdapterCorruptionCustodyOutcomeV1::Quarantined {
        corruption: custody_corruption,
        ..
    } = custody_outcome
    else {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    };
    if custody_corruption != disposition.corruption() {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(custody_outcome)
}

/// Audits one identity-bound adapter branch against a strict-opened trusted adapter store.
///
/// The adapter roots are opened from provisioner-attested configs inside this function. The
/// observed root is deliberately *not* admitted as an ordinary store: a removed guard or unique
/// generation index is evidence the scanner must retain and fence. Custody is likewise opened by
/// identity so a restart can idempotently read a custody root whose prior global fence correctly
/// prevents ordinary strict open. Coordinator connections remain a projection-only input; the
/// coordinator caller must separately prove its complete V2 store.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn audit_and_retain_adapter_projection_v1(
    trusted_adapter: &crate::inbox::SqliteDispatchInboxStoreV1,
    pause: &mut dyn AdapterCorruptionAuditPauseV1,
    observed_config: crate::config::AdapterInboxStoreConfigV1,
    trusted_counterpart: &Connection,
    observed_counterpart: &mut Connection,
    custody_config: crate::config::AdapterInboxStoreConfigV1,
    selection: &AdapterCorruptionAuditSelectionV1,
    lifecycle: AdapterCorruptionAuditLifecycleV1,
) -> Result<AdapterCorruptionAuditOutcomeV1, AdapterCorruptionAuditErrorV1> {
    let pause_evidence = pause.capture_adapter_corruption_audit_pause_v1()?;
    let mut observed = crate::connection::open_existing_for_corruption_audit_v1(observed_config)
        .map_err(map_audit_open_error_v1)?;
    let mut custody = crate::connection::open_existing_for_corruption_audit_v1(custody_config)
        .map_err(map_audit_open_error_v1)?;
    let custody_expected_identity = custody
        .expected_root_identity()
        .map_err(map_audit_open_error_v1)?;
    if read_adapter_root_identity_v1(custody.connection_mut())? != custody_expected_identity {
        return Err(AdapterCorruptionAuditErrorV1::InvariantFailed);
    }
    pause.recheck_adapter_corruption_audit_pause_v1(&pause_evidence)?;
    let trusted = trusted_adapter
        .lock_store()
        .map_err(|_| AdapterCorruptionAuditErrorV1::Unavailable)?;
    let internal_selection = selection.as_internal_v1();
    let result = classify_and_retain_adapter_connections_v1(
        trusted.connection(),
        observed.connection_mut(),
        trusted_counterpart,
        observed_counterpart,
        custody.connection_mut(),
        &internal_selection,
        lifecycle.into(),
    );
    drop(trusted);

    // A path/file replacement during the cut never becomes a successful audit. The live SQLite
    // handles may have been fenced, but only the original provisioner-bound roots are reportable.
    let observed_revalidation = observed.revalidate().map_err(map_audit_open_error_v1);
    let custody_revalidation = custody.revalidate().map_err(map_audit_open_error_v1);
    let pause_revalidation = pause.recheck_adapter_corruption_audit_pause_v1(&pause_evidence);
    observed_revalidation?;
    custody_revalidation?;
    pause_revalidation?;
    audit_outcome_from_internal_v1(result?)
}

/// Internal bridge for the feature-gated real-root corruption matrix.
///
#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_and_retain_adapter_projection_connections_v1(
    trusted: &Connection,
    pause: &mut dyn AdapterCorruptionAuditPauseV1,
    observed: &mut Connection,
    trusted_counterpart: &Connection,
    observed_counterpart: &mut Connection,
    custody: &mut Connection,
    selection: &AdapterCorruptionAuditSelectionV1,
    lifecycle: AdapterCorruptionAuditLifecycleV1,
) -> Result<AdapterCorruptionAuditOutcomeV1, AdapterCorruptionAuditErrorV1> {
    let pause_evidence = pause.capture_adapter_corruption_audit_pause_v1()?;
    pause.recheck_adapter_corruption_audit_pause_v1(&pause_evidence)?;
    let internal_selection = selection.as_internal_v1();
    let result = classify_and_retain_adapter_connections_v1(
        trusted,
        observed,
        trusted_counterpart,
        observed_counterpart,
        custody,
        &internal_selection,
        lifecycle.into(),
    );
    pause.recheck_adapter_corruption_audit_pause_v1(&pause_evidence)?;
    audit_outcome_from_internal_v1(result?)
}

fn audit_outcome_from_internal_v1(
    result: AdapterCorruptionCustodyOutcomeV1,
) -> Result<AdapterCorruptionAuditOutcomeV1, AdapterCorruptionAuditErrorV1> {
    match result {
        AdapterCorruptionCustodyOutcomeV1::NoCorruptionObserved => {
            Ok(AdapterCorruptionAuditOutcomeV1::NoCorruptionObserved)
        }
        AdapterCorruptionCustodyOutcomeV1::CheckpointMismatch => {
            Err(AdapterCorruptionAuditErrorV1::CheckpointMismatch)
        }
        AdapterCorruptionCustodyOutcomeV1::Quarantined {
            corruption,
            generation,
        } => Ok(AdapterCorruptionAuditOutcomeV1::Quarantined(
            AdapterRetainedCorruptionAuditV1 {
                reason_code: corruption.reason_code(),
                quarantine_generation: generation,
            },
        )),
    }
}

fn map_audit_open_error_v1(
    error: crate::connection::AdapterInboxStoreOpenErrorV1,
) -> AdapterCorruptionAuditErrorV1 {
    match error {
        crate::connection::AdapterInboxStoreOpenErrorV1::RootBusy => {
            AdapterCorruptionAuditErrorV1::Busy
        }
        crate::connection::AdapterInboxStoreOpenErrorV1::ApplicationIdMismatch
        | crate::connection::AdapterInboxStoreOpenErrorV1::SchemaUnsupported
        | crate::connection::AdapterInboxStoreOpenErrorV1::SchemaInvalid
        | crate::connection::AdapterInboxStoreOpenErrorV1::IntegrityFailed
        | crate::connection::AdapterInboxStoreOpenErrorV1::InvariantFailed => {
            AdapterCorruptionAuditErrorV1::InvariantFailed
        }
        crate::connection::AdapterInboxStoreOpenErrorV1::RootInvalid
        | crate::connection::AdapterInboxStoreOpenErrorV1::RootNotDedicated
        | crate::connection::AdapterInboxStoreOpenErrorV1::RootRoleMismatch
        | crate::connection::AdapterInboxStoreOpenErrorV1::RootIdentityMismatch
        | crate::connection::AdapterInboxStoreOpenErrorV1::RootUnavailable
        | crate::connection::AdapterInboxStoreOpenErrorV1::UnknownRootMember
        | crate::connection::AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable => {
            AdapterCorruptionAuditErrorV1::Unavailable
        }
    }
}

fn ensure_distinct_adapter_audit_connections_v1(
    trusted: &Connection,
    observed: &Connection,
    trusted_counterpart: &Connection,
    observed_counterpart: &Connection,
    custody: &Connection,
) -> Result<(), QuarantineStoreErrorV1> {
    let connections = [
        trusted,
        observed,
        trusted_counterpart,
        observed_counterpart,
        custody,
    ];
    for (index, connection) in connections.iter().enumerate() {
        if connections[(index + 1)..]
            .iter()
            .any(|other| std::ptr::eq(*connection, *other))
        {
            return Err(QuarantineStoreErrorV1::InvariantFailed);
        }
    }

    let paths = connections
        .into_iter()
        .map(connection_main_database_path_v1)
        .collect::<Result<Vec<_>, _>>()?;
    for (index, path) in paths.iter().enumerate() {
        for other in &paths[(index + 1)..] {
            let same_file = path == other
                || crate::root_safety::regular_files_share_identity_v1(path, other)
                    .map_err(|_| QuarantineStoreErrorV1::InvariantFailed)?;
            if same_file {
                return Err(QuarantineStoreErrorV1::InvariantFailed);
            }
        }
    }
    Ok(())
}

fn connection_main_database_path_v1(
    connection: &Connection,
) -> Result<PathBuf, QuarantineStoreErrorV1> {
    let path: String = connection
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    if path.is_empty() {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    let canonical_path = fs::canonicalize(path).map_err(|_| QuarantineStoreErrorV1::Unavailable)?;
    let metadata =
        fs::symlink_metadata(&canonical_path).map_err(|_| QuarantineStoreErrorV1::Unavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(canonical_path)
}

/// Feature-gated integration seam over real filesystem SQLite roots.
///
/// `trusted` must strict-open. `observed` is captured before mutation even when its structural
/// invariants are the corruption being classified, then receives a permanent local fence before
/// the same redacted incident is retained in distinct custody. The counterpart arguments expose
/// only the reviewed `dispatch_grants` and `dispatch_receipts` projection columns; this seam does
/// not claim to verify the coordinator schema as a whole. The result is diagnostic only and
/// carries no execution authority.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
struct StableAdapterCorruptionAuditPauseForTestV1 {
    evidence: AdapterCorruptionAuditPauseEvidenceV1,
}

#[cfg(feature = "test-fault-injection")]
impl StableAdapterCorruptionAuditPauseForTestV1 {
    fn new() -> Result<Self, AdapterCorruptionAuditErrorV1> {
        Ok(Self {
            evidence: AdapterCorruptionAuditPauseEvidenceV1::try_new(1, [0xa5; 32])?,
        })
    }
}

#[cfg(feature = "test-fault-injection")]
impl AdapterCorruptionAuditPauseV1 for StableAdapterCorruptionAuditPauseForTestV1 {
    fn capture_adapter_corruption_audit_pause_v1(
        &mut self,
    ) -> Result<AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditErrorV1> {
        Ok(self.evidence)
    }

    fn recheck_adapter_corruption_audit_pause_v1(
        &mut self,
        expected: &AdapterCorruptionAuditPauseEvidenceV1,
    ) -> Result<(), AdapterCorruptionAuditErrorV1> {
        if *expected == self.evidence {
            Ok(())
        } else {
            Err(AdapterCorruptionAuditErrorV1::Unavailable)
        }
    }
}

#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn classify_and_retain_adapter_connections_for_test_v1(
    trusted: &Connection,
    observed: &mut Connection,
    trusted_counterpart: &Connection,
    observed_counterpart: &mut Connection,
    custody: &mut Connection,
    ids: &AdapterCrossStoreIdsForTestV1,
    lifecycle: AdapterLifecycleRelationshipForTestV1,
) -> Result<AdapterHistoryCustodyForTestV1, AdapterCorruptionTestErrorV1> {
    let lifecycle = match lifecycle {
        AdapterLifecycleRelationshipForTestV1::Prepared => {
            AdapterCorruptionAuditLifecycleV1::Prepared
        }
        AdapterLifecycleRelationshipForTestV1::Dispatching => {
            AdapterCorruptionAuditLifecycleV1::Dispatching
        }
        AdapterLifecycleRelationshipForTestV1::AdapterReceived => {
            AdapterCorruptionAuditLifecycleV1::AdapterReceived
        }
        AdapterLifecycleRelationshipForTestV1::Consumed => {
            AdapterCorruptionAuditLifecycleV1::Consumed
        }
        AdapterLifecycleRelationshipForTestV1::Ambiguous => {
            AdapterCorruptionAuditLifecycleV1::Ambiguous
        }
    };
    let selection = AdapterCorruptionAuditSelectionV1 {
        grant_id: ids.grant_id,
        operation_id: ids.operation_id.clone(),
        dispatch_attempt_id: ids.dispatch_attempt_id,
        receipt_id: ids.receipt_id,
    };
    let mut pause = StableAdapterCorruptionAuditPauseForTestV1::new()?;
    match audit_and_retain_adapter_projection_connections_v1(
        trusted,
        &mut pause,
        observed,
        trusted_counterpart,
        observed_counterpart,
        custody,
        &selection,
        lifecycle,
    )? {
        AdapterCorruptionAuditOutcomeV1::NoCorruptionObserved => {
            Ok(AdapterHistoryCustodyForTestV1::NoCorruptionObserved)
        }
        AdapterCorruptionAuditOutcomeV1::Quarantined(retained) => Ok(
            AdapterHistoryCustodyForTestV1::Quarantined(AdapterRetainedCorruptionForTestV1 {
                reason_code: retained.reason_code(),
                quarantine_generation: retained.quarantine_generation(),
            }),
        ),
    }
}

fn verify_counterpart_readable_v1(counterpart: &Connection) -> Result<(), QuarantineStoreErrorV1> {
    verify_sqlite_integrity_and_foreign_keys_v1(counterpart)?;
    for table in ["dispatch_grants", "dispatch_receipts"] {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        let count: i64 = counterpart
            .query_row(&sql, [], |row| row.get(0))
            .map_err(map_sqlite_error)?;
        strict_safe_integer(count)?;
    }
    Ok(())
}

fn verify_sqlite_integrity_and_foreign_keys_v1(
    connection: &Connection,
) -> Result<(), QuarantineStoreErrorV1> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    if integrity != "ok" {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    let foreign_key_violation: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sqlite_error)?;
    if foreign_key_violation.is_some() {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(())
}

fn retain_quarantine_with_domain_v1(
    transaction: &Transaction<'_>,
    domain: &[u8],
    grant_id: Option<Sha256Digest>,
    evidence_digest: Sha256Digest,
    public_reason_code: &str,
) -> Result<RetainedQuarantineV1, QuarantineStoreErrorV1> {
    let grant_id_bytes = grant_id.map(|value| value.as_bytes().to_vec());
    let grant_identity_tag = [u8::from(grant_id_bytes.is_some())];
    let quarantine_id = domain_digest(&[
        domain,
        &grant_identity_tag,
        grant_id_bytes.as_deref().unwrap_or_default(),
        evidence_digest.as_bytes(),
        public_reason_code.as_bytes(),
    ]);
    if let Some((retained_grant, retained_evidence, retained_reason, generation)) = transaction
        .query_row(
            "SELECT grant_id, evidence_digest, public_reason_code, quarantine_generation
             FROM inbox_quarantines WHERE quarantine_id = ?1",
            [quarantine_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
    {
        if retained_grant.as_deref() != grant_id_bytes.as_deref()
            || retained_evidence.as_slice() != evidence_digest.as_bytes()
            || retained_reason != public_reason_code
        {
            return Err(QuarantineStoreErrorV1::InvariantFailed);
        }
        return Ok(RetainedQuarantineV1 {
            generation: strict_generation(generation)?,
        });
    }

    let (previous_store_generation, next_generation) = next_store_generation(transaction)?;
    update_generation(
        transaction,
        "quarantine_generation",
        previous_store_generation,
        next_generation,
    )?;
    transaction
        .execute(
            "INSERT INTO inbox_quarantines (
                quarantine_id, grant_id, evidence_digest, public_reason_code,
                quarantine_generation, resolved_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![
                quarantine_id.as_bytes().as_slice(),
                grant_id_bytes.as_deref(),
                evidence_digest.as_bytes().as_slice(),
                public_reason_code,
                to_i64(next_generation)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(RetainedQuarantineV1 {
        generation: next_generation,
    })
}

pub(crate) fn retain_binding_conflict_v1(
    transaction: &Transaction<'_>,
    evidence: &ConflictEvidenceInputV1<'_>,
) -> Result<RetainedConflictV1, QuarantineStoreErrorV1> {
    let operation_digest = Sha256Digest::digest(evidence.operation_id.as_bytes());
    let nonce_digest = Sha256Digest::digest(evidence.one_shot_nonce.as_bytes());
    let conflict_id = domain_digest(&[
        CONFLICT_DOMAIN_V1,
        evidence.observed_grant_id.as_bytes(),
        operation_digest.as_bytes(),
        nonce_digest.as_bytes(),
        evidence.retained_binding_digest.as_bytes(),
        evidence.conflicting_binding_digest.as_bytes(),
    ]);
    let event_id = domain_digest(&[CONFLICT_EVENT_DOMAIN_V1, conflict_id.as_bytes()]);
    if let Some((retained_binding, conflicting_binding, generation)) = transaction
        .query_row(
            "SELECT retained_binding_digest, conflicting_binding_digest,
                    conflict_generation
             FROM inbox_conflicts WHERE conflict_id = ?1",
            [conflict_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?
    {
        if retained_binding.as_slice() != evidence.retained_binding_digest.as_bytes()
            || conflicting_binding.as_slice() != evidence.conflicting_binding_digest.as_bytes()
        {
            return Err(QuarantineStoreErrorV1::InvariantFailed);
        }
        let event_matches: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM adapter_events
                 WHERE event_id = ?1 AND event_generation = ?2
                   AND transition_generation IS NULL AND grant_id IS NULL
                   AND operation_id IS NULL AND event_kind = 'GRANT_CONFLICT'
                   AND decision = 'CONFLICT' AND effective_state IS NULL
                   AND public_reason_code = 'BINDING_CONFLICT'",
                params![event_id.as_bytes().as_slice(), generation,],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)?;
        if event_matches != 1 {
            return Err(QuarantineStoreErrorV1::InvariantFailed);
        }
        return Ok(RetainedConflictV1 {
            generation: strict_generation(generation)?,
        });
    }

    let (previous_store_generation, next_generation) = next_store_generation(transaction)?;
    update_conflict_and_event_generation(transaction, previous_store_generation, next_generation)?;
    transaction
        .execute(
            "INSERT INTO inbox_conflicts (
                conflict_id, observed_grant_id, observed_operation_digest,
                observed_nonce_digest, retained_binding_digest,
                conflicting_binding_digest, public_reason_code, conflict_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'BINDING_CONFLICT', ?7)",
            params![
                conflict_id.as_bytes().as_slice(),
                evidence.observed_grant_id.as_bytes().as_slice(),
                operation_digest.as_bytes().as_slice(),
                nonce_digest.as_bytes().as_slice(),
                evidence.retained_binding_digest.as_bytes().as_slice(),
                evidence.conflicting_binding_digest.as_bytes().as_slice(),
                to_i64(next_generation)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    transaction
        .execute(
            "INSERT INTO adapter_events (
                event_id, event_generation, transition_generation, grant_id,
                operation_id, dispatch_attempt_id, task_id, workload_id, plan_id,
                task_lease_digest, event_contract_version, grant_contract_version,
                receipt_contract_version, effective_state, decision, latency_ms,
                event_kind, public_reason_code, public_trace_id, delivery_state,
                delivered_generation
             ) VALUES (
                ?1, ?2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                1, 0, 0, NULL, 'CONFLICT', 0, 'GRANT_CONFLICT',
                'BINDING_CONFLICT', ?3, 'PENDING', NULL
             )",
            params![
                event_id.as_bytes().as_slice(),
                to_i64(next_generation)?,
                event_id.to_hex(),
            ],
        )
        .map_err(map_sqlite_error)?;
    Ok(RetainedConflictV1 {
        generation: next_generation,
    })
}

fn update_conflict_and_event_generation(
    transaction: &Transaction<'_>,
    previous_store_generation: u64,
    next_generation: u64,
) -> Result<(), QuarantineStoreErrorV1> {
    let changed = transaction
        .execute(
            "UPDATE adapter_store_meta
             SET store_generation = ?1, conflict_generation = ?1,
                 event_generation = ?1
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
               AND store_generation = ?2",
            params![to_i64(next_generation)?, to_i64(previous_store_generation)?,],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(())
}

fn next_store_generation(
    transaction: &Transaction<'_>,
) -> Result<(u64, u64), QuarantineStoreErrorV1> {
    let (generation, lifecycle): (i64, String) = transaction
        .query_row(
            "SELECT store_generation, root_lifecycle_state
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(map_sqlite_error)?;
    if lifecycle != "ACTIVE" {
        return Err(QuarantineStoreErrorV1::RestorePending);
    }
    let generation = strict_safe_integer(generation)?;
    let next = generation
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(QuarantineStoreErrorV1::InvariantFailed)?;
    Ok((generation, next))
}

fn update_generation(
    transaction: &Transaction<'_>,
    domain_column: &str,
    previous_store_generation: u64,
    next_generation: u64,
) -> Result<(), QuarantineStoreErrorV1> {
    let statement = format!(
        "UPDATE adapter_store_meta
         SET store_generation = ?1, {domain_column} = ?1
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
           AND store_generation = ?2"
    );
    let changed = transaction
        .execute(
            &statement,
            params![to_i64(next_generation)?, to_i64(previous_store_generation)?,],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(QuarantineStoreErrorV1::InvariantFailed);
    }
    Ok(())
}

fn domain_digest(parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn strict_safe_integer(value: i64) -> Result<u64, QuarantineStoreErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(QuarantineStoreErrorV1::InvariantFailed)
}

fn strict_generation(value: i64) -> Result<u64, QuarantineStoreErrorV1> {
    strict_safe_integer(value).and_then(|value| {
        (value > 0)
            .then_some(value)
            .ok_or(QuarantineStoreErrorV1::InvariantFailed)
    })
}

fn to_i64(value: u64) -> Result<i64, QuarantineStoreErrorV1> {
    i64::try_from(value).map_err(|_| QuarantineStoreErrorV1::InvariantFailed)
}

fn map_sqlite_error(error: rusqlite::Error) -> QuarantineStoreErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy
                    | rusqlite::ErrorCode::DatabaseLocked
                    | rusqlite::ErrorCode::SchemaChanged
                    | rusqlite::ErrorCode::FileLockingProtocolFailed
            ) =>
        {
            QuarantineStoreErrorV1::Busy
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            QuarantineStoreErrorV1::InvariantFailed
        }
        _ => QuarantineStoreErrorV1::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_safety::AdapterRootIdentityV1;
    use crate::schema::{verify_full, ADAPTER_INBOX_SCHEMA_V1_SQL};
    use rusqlite::Connection;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn generations(store: u64) -> AdapterGenerationVectorV1 {
        AdapterGenerationVectorV1 {
            store,
            inbox: store,
            consumption: store,
            receipt: store,
            conflict: store,
            quarantine: store,
            event: store,
            epoch_observer: store,
            restore_state: 0,
        }
    }

    fn record(byte: u8) -> AdapterCrossStoreRecordV1 {
        AdapterCrossStoreRecordV1 {
            canonical_digest: digest(byte),
            generation_binding_digest: digest(byte.wrapping_add(1)),
        }
    }

    fn exact_input() -> AdapterCrossStoreHistoryInputV1 {
        AdapterCrossStoreHistoryInputV1 {
            relationship: AdapterLifecycleRelationshipV1::Consumed,
            trusted: AdapterHistorySnapshotV1 {
                root_identity_digest: digest(1),
                generations: generations(7),
                history_generation: 7,
                history_rows: 4,
                history_digest: digest(2),
            },
            observed: AdapterObservedHistoryV1 {
                root_identity_digest: digest(1),
                generations: generations(7),
                history_generation: 7,
                history_rows: 4,
                retained_checkpoint_digest: digest(2),
                complete_history_digest: digest(2),
            },
            coordinator_grant: Some(record(3)),
            adapter_inbox: Some(record(3)),
            coordinator_receipt: Some(record(5)),
            adapter_receipt: Some(record(5)),
            expected_cross_store_inventory_digest: digest(7),
            observed_cross_store_inventory_digest: digest(7),
        }
    }

    fn corruption_kind(input: &AdapterCrossStoreHistoryInputV1) -> AdapterCrossStoreCorruptionV1 {
        match verify_adapter_cross_store_history_v1(input) {
            AdapterHistoryVerificationV1::Corrupted(disposition) => {
                assert_eq!(
                    disposition.custody(),
                    AdapterCorruptionCustodyV1::Quarantined
                );
                assert_eq!(
                    disposition.execution(),
                    AdapterCorruptionExecutionV1::Refused
                );
                disposition.corruption()
            }
            AdapterHistoryVerificationV1::NoCorruptionObserved => {
                panic!("fixture must classify corruption")
            }
        }
    }

    fn initialized_memory_adapter_v1(identity_tag: u8) -> Connection {
        let connection = Connection::open_in_memory().expect("memory database opens");
        let root_identity = AdapterRootIdentityV1::from_bytes([identity_tag; 32]);
        connection
            .execute_batch(ADAPTER_INBOX_SCHEMA_V1_SQL)
            .expect("reviewed adapter schema installs");
        connection
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
                     'ACTIVE', 7, 1, 1024, 32, ?2, NULL, 0
                 )",
                params![
                    root_identity.as_bytes().as_slice(),
                    [0x42_u8; 32].as_slice(),
                ],
            )
            .expect("exact adapter metadata installs");
        connection
    }

    fn alternate_disposition() -> AdapterCorruptionDispositionV1 {
        let mut input = exact_input();
        input.coordinator_receipt = None;
        match verify_adapter_cross_store_history_v1(&input) {
            AdapterHistoryVerificationV1::Corrupted(value) => value,
            AdapterHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
        }
    }

    #[test]
    fn exact_adapter_history_is_only_an_integrity_observation() {
        assert_eq!(
            verify_adapter_cross_store_history_v1(&exact_input()),
            AdapterHistoryVerificationV1::NoCorruptionObserved
        );
    }

    #[test]
    fn five_t096_lifecycle_relationships_are_exact_negative_controls() {
        let mut prepared = exact_input();
        prepared.relationship = AdapterLifecycleRelationshipV1::Prepared;
        prepared.coordinator_grant = None;
        prepared.adapter_inbox = None;
        prepared.coordinator_receipt = None;
        prepared.adapter_receipt = None;

        let mut dispatching = prepared;
        dispatching.relationship = AdapterLifecycleRelationshipV1::Dispatching;
        dispatching.coordinator_grant = Some(record(3));

        let mut received = dispatching;
        received.relationship = AdapterLifecycleRelationshipV1::AdapterReceived;
        received.adapter_inbox = received.coordinator_grant;

        let consumed = exact_input();

        let mut ambiguous = dispatching;
        ambiguous.relationship = AdapterLifecycleRelationshipV1::Ambiguous;

        for input in [prepared, dispatching, received, consumed, ambiguous] {
            assert_eq!(
                verify_adapter_cross_store_history_v1(&input),
                AdapterHistoryVerificationV1::NoCorruptionObserved
            );
        }
    }

    #[test]
    fn every_adapter_corruption_class_is_closed() {
        let mut input = exact_input();
        input.coordinator_grant = None;
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::OrphanAdapterInbox
        );

        let mut input = exact_input();
        input.coordinator_receipt = None;
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::OrphanAdapterReceipt
        );

        let mut input = exact_input();
        input.coordinator_grant = Some(record(9));
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::GrantDigestConflict
        );

        let mut input = exact_input();
        input.coordinator_receipt = Some(record(9));
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::ReceiptDigestConflict
        );

        let mut input = exact_input();
        input.coordinator_grant = Some(AdapterCrossStoreRecordV1 {
            canonical_digest: record(3).canonical_digest,
            generation_binding_digest: digest(99),
        });
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::CrossGenerationConflict
        );

        let mut input = exact_input();
        input.observed.generations.store = 6;
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::AdapterStoreRollback
        );

        let mut input = exact_input();
        input.observed.root_identity_digest = digest(99);
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::AdapterRootRollback
        );

        let mut input = exact_input();
        input.observed.generations.receipt = 6;
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::AdapterGenerationRollback
        );

        let mut input = exact_input();
        input.observed.history_rows = 3;
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::AdapterHistoryTruncated
        );

        let mut input = exact_input();
        input.observed.retained_checkpoint_digest = digest(99);
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::AdapterGenerationReused
        );

        let mut input = exact_input();
        input.observed_cross_store_inventory_digest = digest(99);
        assert_eq!(
            corruption_kind(&input),
            AdapterCrossStoreCorruptionV1::CrossStoreDisagreement
        );
    }

    fn disposition() -> AdapterCorruptionDispositionV1 {
        let mut input = exact_input();
        input.coordinator_grant = None;
        match verify_adapter_cross_store_history_v1(&input) {
            AdapterHistoryVerificationV1::Corrupted(value) => value,
            AdapterHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
        }
    }

    #[test]
    fn corruption_quarantine_retention_is_append_only_and_idempotent() {
        let mut connection = initialized_memory_adapter_v1(0x41);
        let root_identity = AdapterRootIdentityV1::from_bytes([0x41; 32]);

        let transaction = connection.transaction().expect("transaction opens");
        let first = retain_adapter_corruption_quarantine_v1(&transaction, disposition())
            .expect("first evidence retains");
        let repeat = retain_adapter_corruption_quarantine_v1(&transaction, disposition())
            .expect("exact repeat reads");
        assert_eq!(first, repeat);
        let count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| {
                row.get(0)
            })
            .expect("count reads");
        assert_eq!(count, 1);
        transaction.commit().expect("quarantine commits");

        let retained: (String, i64) = connection
            .query_row(
                "SELECT public_reason_code, quarantine_generation
                 FROM inbox_quarantines",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("retained evidence reads");
        assert_eq!(retained, ("ORPHAN_ADAPTER_INBOX".to_owned(), 1));
        assert_eq!(
            verify_full(&connection, root_identity).unwrap_err(),
            crate::connection::AdapterInboxStoreOpenErrorV1::InvariantFailed,
            "global cross-store custody permanently fences ordinary strict open"
        );
    }

    #[test]
    fn uncertain_local_commit_readback_distinguishes_present_absent_and_conflict() {
        let expected = disposition();

        let mut present = initialized_memory_adapter_v1(0x51);
        let transaction = present.transaction().expect("present transaction begins");
        retain_adapter_corruption_quarantine_v1(&transaction, expected)
            .expect("expected local fence retains");
        transaction.commit().expect("expected local fence commits");
        assert_eq!(
            readback_local_fence_after_commit_error_v1(&present, expected)
                .expect("present readback is readable"),
            LocalFenceCommitReadbackV1::ExactPresent
        );

        let absent = initialized_memory_adapter_v1(0x52);
        assert_eq!(
            readback_local_fence_after_commit_error_v1(&absent, expected)
                .expect("absent readback is readable"),
            LocalFenceCommitReadbackV1::Absent
        );

        let mut conflict = initialized_memory_adapter_v1(0x53);
        let transaction = conflict.transaction().expect("conflict transaction begins");
        retain_adapter_corruption_quarantine_v1(&transaction, alternate_disposition())
            .expect("different local fence retains");
        transaction.commit().expect("different local fence commits");
        assert_eq!(
            readback_local_fence_after_commit_error_v1(&conflict, expected)
                .expect("conflict readback is readable"),
            LocalFenceCommitReadbackV1::Conflict
        );
    }
}
