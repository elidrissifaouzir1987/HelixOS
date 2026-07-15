//! Closed corruption classification for coordinator and cross-store dispatch history.
//!
//! Dispatch corruption reuses the permanent preparation-quarantine relation. The frozen
//! base schema already admits the global `INVARIANT_CONFLICT` and `STORE_UNHEALTHY`
//! reasons, so retention needs no opportunistic DDL or V2 schema migration.

#![allow(dead_code)]

use crate::clock::CoordinatorMonotonicClockV1;
#[cfg(all(feature = "test-fault-injection", not(test)))]
use crate::config::CoordinatorRootIdentityEvidenceV1;
use crate::config::CoordinatorStoreConfigV1;
use crate::connection::open_bound_existing_connection;
#[cfg(all(feature = "test-fault-injection", not(test)))]
use crate::dispatch_schema::verify_t097_trusted_dispatch_checkpoint_v1;
#[cfg(all(feature = "test-fault-injection", not(test)))]
use crate::error::CoordinatorClockUnavailableV1;
use crate::quarantine::{
    read_exact_base_quarantine_v1, retain_base_quarantine_in_transaction_v1, BaseQuarantineErrorV1,
    BaseQuarantineInputV1, BaseQuarantineReasonV1, BaseQuarantineTransactionOutcomeV1,
};
use helix_contracts::Sha256Digest as BaseSha256Digest;
use helix_dispatch_contracts::{Sha256Digest, MAX_SAFE_U64};
#[cfg(all(feature = "test-fault-injection", not(test)))]
use helix_dispatch_inbox_sqlite::{
    AdapterInboxProfileV1, AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1,
    SqliteDispatchInboxStoreV1,
};
use rusqlite::types::ValueRef;
#[cfg(all(feature = "test-fault-injection", not(test)))]
use rusqlite::OpenFlags;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::fmt;
#[cfg(all(feature = "test-fault-injection", not(test)))]
use std::path::Path;
#[cfg(all(feature = "test-fault-injection", not(test)))]
use std::sync::{Arc, Barrier, Mutex, OnceLock};
#[cfg(all(feature = "test-fault-injection", not(test)))]
use std::time::Instant;

const EVIDENCE_DOMAIN_V1: &[u8] = b"HELIXOS_COORDINATOR_DISPATCH_CORRUPTION_V1\0";
const INCIDENT_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-CORRUPTION-INCIDENT\0V1\0";
const ATTEMPT_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-CORRUPTION-ATTEMPT\0V1\0";
const BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-CORRUPTION-BINDING\0V1\0";
const ROOT_IDENTITY_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-HISTORY-ROOT\0V1\0";
const HISTORY_TABLE_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-HISTORY-TABLE\0V1\0";
const HISTORY_ROW_KEY_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-HISTORY-ROW-KEY\0V1\0";
const HISTORY_ROW_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-HISTORY-ROW\0V1\0";
const HISTORY_STORE_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-HISTORY-STORE\0V1\0";
const HISTORY_CHECKPOINT_MISMATCH_DOMAIN_V1: &[u8] =
    b"HELIXOS\0DISPATCH-HISTORY-CHECKPOINT-MISMATCH\0V1\0";
const RELATION_GENERATION_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-RELATION-GENERATION\0V1\0";
const RELATION_SEMANTIC_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-RELATION-SEMANTIC\0V1\0";
const CROSS_STORE_INVENTORY_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-CROSS-STORE-INVENTORY\0V1\0";

// Each second component is the row-identity column used for exact checkpoint comparison.
const COORDINATOR_HISTORY_TABLES_V1: &[(&str, &str)] = &[
    ("coordinator_v2_migrations", "migration_attempt_id"),
    ("dispatch_comparisons", "dispatch_attempt_id"),
    ("dispatch_grants", "grant_id"),
    ("dispatch_records", "operation_id"),
    ("dispatch_transitions", "state_generation"),
    ("dispatch_outbox", "grant_id"),
    ("dispatch_delivery_attempts", "attempt_generation"),
    ("dispatch_receipts", "receipt_id"),
    ("dispatch_reconciliations", "reconciliation_id"),
    ("dispatch_events", "event_id"),
    ("dispatch_definite_refusal_guards", "guard_id"),
];

const COORDINATOR_GENERATION_COLUMNS_V1: &[(&str, &str)] = &[
    ("coordinator_v2_migrations", "migration_generation"),
    ("dispatch_comparisons", "comparison_generation"),
    ("dispatch_grants", "created_generation"),
    ("dispatch_records", "state_generation"),
    ("dispatch_transitions", "state_generation"),
    ("dispatch_outbox", "delivery_generation"),
    ("dispatch_delivery_attempts", "attempt_generation"),
    ("dispatch_receipts", "receipt_generation"),
    ("dispatch_reconciliations", "reconciliation_generation"),
    ("dispatch_events", "event_generation"),
    ("dispatch_definite_refusal_guards", "guard_generation"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchCorruptionKindV1 {
    OrphanCoordinatorGrant,
    OrphanCoordinatorReceipt,
    GrantDigestConflict,
    ReceiptDigestConflict,
    CrossGenerationConflict,
    CoordinatorStoreRollback,
    CoordinatorRootRollback,
    CoordinatorGenerationRollback,
    CoordinatorHistoryTruncated,
    CoordinatorGenerationReused,
    CrossStoreDisagreement,
}

impl DispatchCorruptionKindV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::OrphanCoordinatorGrant => "ORPHAN_COORDINATOR_GRANT",
            Self::OrphanCoordinatorReceipt => "ORPHAN_COORDINATOR_RECEIPT",
            Self::GrantDigestConflict => "GRANT_DIGEST_CONFLICT",
            Self::ReceiptDigestConflict => "RECEIPT_DIGEST_CONFLICT",
            Self::CrossGenerationConflict => "CROSS_GENERATION_CONFLICT",
            Self::CoordinatorStoreRollback => "COORDINATOR_STORE_ROLLBACK",
            Self::CoordinatorRootRollback => "COORDINATOR_ROOT_ROLLBACK",
            Self::CoordinatorGenerationRollback => "COORDINATOR_GENERATION_ROLLBACK",
            Self::CoordinatorHistoryTruncated => "COORDINATOR_HISTORY_TRUNCATED",
            Self::CoordinatorGenerationReused => "COORDINATOR_GENERATION_REUSED",
            Self::CrossStoreDisagreement => "CROSS_STORE_DISAGREEMENT",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchCorruptionCustodyV1 {
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchCorruptionExecutionV1 {
    Refused,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DispatchCorruptionDispositionV1 {
    kind: DispatchCorruptionKindV1,
    custody: DispatchCorruptionCustodyV1,
    execution: DispatchCorruptionExecutionV1,
    incident_digest: Sha256Digest,
    evidence_digest: Sha256Digest,
}

impl DispatchCorruptionDispositionV1 {
    pub(crate) const fn kind(self) -> DispatchCorruptionKindV1 {
        self.kind
    }

    pub(crate) const fn custody(self) -> DispatchCorruptionCustodyV1 {
        self.custody
    }

    pub(crate) const fn execution(self) -> DispatchCorruptionExecutionV1 {
        self.execution
    }

    pub(crate) const fn evidence_digest(self) -> Sha256Digest {
        self.evidence_digest
    }

    pub(crate) const fn reason_code(self) -> &'static str {
        self.kind.reason_code()
    }
}

impl fmt::Debug for DispatchCorruptionDispositionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchCorruptionDispositionV1")
            .field("kind", &self.kind)
            .field("custody", &self.custody)
            .field("execution", &self.execution)
            .finish_non_exhaustive()
    }
}

/// Closed relationship context established by durable lifecycle state before comparing
/// the two sovereign stores. It prevents legitimate, pre-handoff one-sided history from
/// being relabelled as corruption merely because the adapter has not accepted a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchRelationLifecycleV1 {
    Prepared,
    Dispatching,
    AdapterReceived,
    Consumed,
    Ambiguous,
}

impl DispatchRelationLifecycleV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Dispatching => 2,
            Self::AdapterReceived => 3,
            Self::Consumed => 4,
            Self::Ambiguous => 5,
        }
    }

    const fn permits_pre_handoff_grant(self) -> bool {
        matches!(self, Self::Dispatching | Self::Ambiguous)
    }

    const fn accepts_relationship_shape(self, shape: DispatchRelationshipShapeV1) -> bool {
        match self {
            Self::Prepared => {
                shape.coordinator_grants == 0
                    && shape.adapter_grants == 0
                    && shape.coordinator_receipts == 0
                    && shape.adapter_receipts == 0
            }
            Self::Dispatching | Self::Ambiguous => {
                shape.coordinator_grants > 0
                    && shape.adapter_grants == 0
                    && shape.coordinator_receipts == 0
                    && shape.adapter_receipts == 0
            }
            Self::AdapterReceived => {
                shape.coordinator_grants > 0
                    && shape.coordinator_grants == shape.adapter_grants
                    && shape.coordinator_receipts == 0
                    && shape.adapter_receipts == 0
            }
            Self::Consumed => {
                shape.coordinator_grants > 0
                    && shape.coordinator_grants == shape.adapter_grants
                    && shape.coordinator_grants == shape.coordinator_receipts
                    && shape.coordinator_grants == shape.adapter_receipts
            }
        }
    }

    /// Accepts the retained lifecycle shape or a monotonic forward lifecycle reached while
    /// comparing a separately retained exact checkpoint. A valid forward shape is a
    /// checkpoint mismatch, never corruption merely because the checkpoint is newer.
    const fn accepts_same_or_later_relationship_shape(
        self,
        shape: DispatchRelationshipShapeV1,
    ) -> bool {
        match self {
            Self::Prepared => {
                Self::Prepared.accepts_relationship_shape(shape)
                    || Self::Dispatching.accepts_relationship_shape(shape)
                    || Self::AdapterReceived.accepts_relationship_shape(shape)
                    || Self::Consumed.accepts_relationship_shape(shape)
            }
            Self::Dispatching | Self::Ambiguous => {
                Self::Dispatching.accepts_relationship_shape(shape)
                    || Self::AdapterReceived.accepts_relationship_shape(shape)
                    || Self::Consumed.accepts_relationship_shape(shape)
            }
            Self::AdapterReceived => {
                Self::AdapterReceived.accepts_relationship_shape(shape)
                    || Self::Consumed.accepts_relationship_shape(shape)
            }
            Self::Consumed => Self::Consumed.accepts_relationship_shape(shape),
        }
    }
}

/// One exact immutable row projected from each sovereign store.
///
/// `canonical_digest` binds the retained grant or receipt bytes. The generation digest
/// binds the generations encoded by that same record without assuming that independent
/// SQLite stores allocate equal numeric generations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DispatchCrossStoreRecordV1 {
    pub(crate) canonical_digest: Sha256Digest,
    pub(crate) semantic_binding_digest: Sha256Digest,
    pub(crate) generation_binding_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DispatchRelationshipShapeV1 {
    pub(crate) coordinator_grants: u64,
    pub(crate) adapter_grants: u64,
    pub(crate) coordinator_receipts: u64,
    pub(crate) adapter_receipts: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorGenerationVectorV1 {
    pub(crate) store: u64,
    pub(crate) dispatch: u64,
    pub(crate) delivery: u64,
    pub(crate) receipt: u64,
    pub(crate) reconciliation: u64,
    pub(crate) event: u64,
    pub(crate) migration: u64,
}

impl CoordinatorGenerationVectorV1 {
    fn regressed_from(self, trusted: Self) -> bool {
        self.dispatch < trusted.dispatch
            || self.delivery < trusted.delivery
            || self.receipt < trusted.receipt
            || self.reconciliation < trusted.reconciliation
            || self.event < trusted.event
            || self.migration < trusted.migration
    }

    fn exceeds_store(self) -> bool {
        [
            self.dispatch,
            self.delivery,
            self.receipt,
            self.reconciliation,
            self.event,
            self.migration,
        ]
        .into_iter()
        .any(|generation| generation > self.store)
    }

    fn hash_into(self, hasher: &mut Sha256) {
        for generation in [
            self.store,
            self.dispatch,
            self.delivery,
            self.receipt,
            self.reconciliation,
            self.event,
            self.migration,
        ] {
            hasher.update(generation.to_be_bytes());
        }
    }
}

/// Trusted checkpoint and the corresponding observation from one exact PAUSE cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorHistorySnapshotV1 {
    pub(crate) root_identity_digest: Sha256Digest,
    pub(crate) generations: CoordinatorGenerationVectorV1,
    pub(crate) history_generation: u64,
    pub(crate) history_rows: u64,
    pub(crate) history_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorObservedHistoryV1 {
    pub(crate) root_identity_digest: Sha256Digest,
    pub(crate) generations: CoordinatorGenerationVectorV1,
    pub(crate) history_generation: u64,
    pub(crate) history_rows: u64,
    /// Digest proving every keyed trusted checkpoint row remains byte-identical.
    pub(crate) trusted_checkpoint_rows_digest: Sha256Digest,
    pub(crate) complete_history_digest: Sha256Digest,
    /// Set only after exact enumeration proves two distinct rows reused one generation.
    pub(crate) duplicate_generation_observed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DispatchCrossStoreHistoryInputV1 {
    pub(crate) relation_lifecycle: DispatchRelationLifecycleV1,
    pub(crate) trusted: CoordinatorHistorySnapshotV1,
    pub(crate) observed: CoordinatorObservedHistoryV1,
    pub(crate) relationship_shape: DispatchRelationshipShapeV1,
    pub(crate) relationship_corruption: Option<DispatchCorruptionKindV1>,
    pub(crate) expected_adapter_root_identity_digest: Sha256Digest,
    pub(crate) observed_adapter_root_identity_digest: Sha256Digest,
    pub(crate) expected_cross_store_inventory_digest: Sha256Digest,
    pub(crate) observed_cross_store_inventory_digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchHistoryVerificationV1 {
    NoCorruptionObserved,
    CheckpointMismatch,
    Corrupted(DispatchCorruptionDispositionV1),
}

/// Classifies exact immutable history without creating any execution authority.
pub(crate) fn verify_cross_store_dispatch_history_v1(
    input: &DispatchCrossStoreHistoryInputV1,
) -> DispatchHistoryVerificationV1 {
    match detect_corruption_v1(input) {
        Some(kind) => DispatchHistoryVerificationV1::Corrupted(DispatchCorruptionDispositionV1 {
            kind,
            custody: DispatchCorruptionCustodyV1::Quarantined,
            execution: DispatchCorruptionExecutionV1::Refused,
            incident_digest: corruption_incident_digest_v1(input, kind),
            evidence_digest: corruption_evidence_digest_v1(input, kind),
        }),
        None if exact_checkpoint_matches_v1(input) => {
            DispatchHistoryVerificationV1::NoCorruptionObserved
        }
        None => DispatchHistoryVerificationV1::CheckpointMismatch,
    }
}

fn detect_corruption_v1(
    input: &DispatchCrossStoreHistoryInputV1,
) -> Option<DispatchCorruptionKindV1> {
    let trusted = input.trusted;
    let observed = input.observed;

    if observed.root_identity_digest != trusted.root_identity_digest {
        return Some(DispatchCorruptionKindV1::CoordinatorRootRollback);
    }
    if input.observed_adapter_root_identity_digest != input.expected_adapter_root_identity_digest {
        return Some(DispatchCorruptionKindV1::CrossStoreDisagreement);
    }
    if observed.generations.store < trusted.generations.store {
        return Some(DispatchCorruptionKindV1::CoordinatorStoreRollback);
    }
    if observed.generations.regressed_from(trusted.generations)
        || observed.history_generation < trusted.history_generation
    {
        return Some(DispatchCorruptionKindV1::CoordinatorGenerationRollback);
    }
    if observed.history_rows < trusted.history_rows {
        return Some(DispatchCorruptionKindV1::CoordinatorHistoryTruncated);
    }
    if observed.duplicate_generation_observed
        || (observed.history_generation == trusted.history_generation
            && (observed.history_rows != trusted.history_rows
                || observed.complete_history_digest != trusted.history_digest))
    {
        return Some(DispatchCorruptionKindV1::CoordinatorGenerationReused);
    }
    if observed.generations.exceeds_store()
        || observed.history_generation > observed.generations.store
    {
        return Some(DispatchCorruptionKindV1::CrossGenerationConflict);
    }

    if let Some(kind) = input.relationship_corruption {
        return Some(kind);
    }

    if !input
        .relation_lifecycle
        .accepts_same_or_later_relationship_shape(input.relationship_shape)
    {
        return Some(DispatchCorruptionKindV1::CrossStoreDisagreement);
    }

    None
}

fn exact_checkpoint_matches_v1(input: &DispatchCrossStoreHistoryInputV1) -> bool {
    input.observed.root_identity_digest == input.trusted.root_identity_digest
        && input.observed.generations == input.trusted.generations
        && input.observed.history_generation == input.trusted.history_generation
        && input.observed.history_rows == input.trusted.history_rows
        && input.observed.complete_history_digest == input.trusted.history_digest
        && input.observed.trusted_checkpoint_rows_digest == input.trusted.history_digest
        && input.observed_adapter_root_identity_digest
            == input.expected_adapter_root_identity_digest
        && input
            .relation_lifecycle
            .accepts_relationship_shape(input.relationship_shape)
        && input.expected_cross_store_inventory_digest
            == input.observed_cross_store_inventory_digest
}

fn corruption_incident_digest_v1(
    input: &DispatchCrossStoreHistoryInputV1,
    kind: DispatchCorruptionKindV1,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(INCIDENT_DOMAIN_V1);
    hasher.update(kind.reason_code().as_bytes());
    hasher.update(input.trusted.root_identity_digest.as_bytes());
    hasher.update(input.expected_cross_store_inventory_digest.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn corruption_evidence_digest_v1(
    input: &DispatchCrossStoreHistoryInputV1,
    kind: DispatchCorruptionKindV1,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_DOMAIN_V1);
    hasher.update(kind.reason_code().as_bytes());
    hasher.update([input.relation_lifecycle.tag()]);
    hash_trusted_v1(&mut hasher, input.trusted);
    hash_observed_v1(&mut hasher, input.observed);
    for count in [
        input.relationship_shape.coordinator_grants,
        input.relationship_shape.adapter_grants,
        input.relationship_shape.coordinator_receipts,
        input.relationship_shape.adapter_receipts,
    ] {
        hasher.update(count.to_be_bytes());
    }
    match input.relationship_corruption {
        Some(kind) => {
            hasher.update([1]);
            hasher.update(kind.reason_code().as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(input.expected_adapter_root_identity_digest.as_bytes());
    hasher.update(input.observed_adapter_root_identity_digest.as_bytes());
    hasher.update(input.expected_cross_store_inventory_digest.as_bytes());
    hasher.update(input.observed_cross_store_inventory_digest.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn hash_trusted_v1(hasher: &mut Sha256, history: CoordinatorHistorySnapshotV1) {
    hasher.update(history.root_identity_digest.as_bytes());
    history.generations.hash_into(hasher);
    hasher.update(history.history_generation.to_be_bytes());
    hasher.update(history.history_rows.to_be_bytes());
    hasher.update(history.history_digest.as_bytes());
}

fn hash_observed_v1(hasher: &mut Sha256, history: CoordinatorObservedHistoryV1) {
    hasher.update(history.root_identity_digest.as_bytes());
    history.generations.hash_into(hasher);
    hasher.update(history.history_generation.to_be_bytes());
    hasher.update(history.history_rows.to_be_bytes());
    hasher.update(history.trusted_checkpoint_rows_digest.as_bytes());
    hasher.update(history.complete_history_digest.as_bytes());
    hasher.update([u8::from(history.duplicate_generation_observed)]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchCorruptionRetentionErrorV1 {
    InvalidInput,
    Conflict,
    Unavailable,
    Unhealthy,
    GenerationExhausted,
}

/// Opaque permanent base-row custody. No identifier, evidence digest, or root path is
/// exposed through `Debug`; callers can compare only the monotonic retained generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DispatchCorruptionRetentionV1 {
    created_generation: u64,
}

impl DispatchCorruptionRetentionV1 {
    pub(crate) const fn created_generation(self) -> u64 {
        self.created_generation
    }
}

impl fmt::Debug for DispatchCorruptionRetentionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchCorruptionRetentionV1")
            .field("created_generation", &self.created_generation)
            .finish_non_exhaustive()
    }
}

/// Retains one corruption incident in the already-reviewed permanent base relation.
///
/// The stable attempt key identifies the incident while the separately domain-bound
/// evidence digest classifies an exact retry. Consequently exact retries read the same
/// row and generation, whereas changed evidence for the same incident fails closed.
pub(crate) fn retain_dispatch_corruption_quarantine_v1(
    connection: &mut Connection,
    disposition: DispatchCorruptionDispositionV1,
) -> Result<DispatchCorruptionRetentionV1, DispatchCorruptionRetentionErrorV1> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| DispatchCorruptionRetentionErrorV1::Unavailable)?;
    let outcome =
        match retain_dispatch_corruption_quarantine_in_transaction_v1(&transaction, disposition) {
            Ok(outcome) => outcome,
            Err(error) => {
                transaction
                    .rollback()
                    .map_err(|_| DispatchCorruptionRetentionErrorV1::Unavailable)?;
                return Err(error);
            }
        };
    match outcome {
        DispatchCorruptionTransactionOutcomeV1::Inserted(retained) => {
            transaction
                .commit()
                .map_err(|_| DispatchCorruptionRetentionErrorV1::Unavailable)?;
            Ok(retained)
        }
        DispatchCorruptionTransactionOutcomeV1::Existing(retained) => {
            transaction
                .rollback()
                .map_err(|_| DispatchCorruptionRetentionErrorV1::Unavailable)?;
            Ok(retained)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchCorruptionTransactionOutcomeV1 {
    Inserted(DispatchCorruptionRetentionV1),
    Existing(DispatchCorruptionRetentionV1),
}

fn retain_dispatch_corruption_quarantine_in_transaction_v1(
    transaction: &Transaction<'_>,
    disposition: DispatchCorruptionDispositionV1,
) -> Result<DispatchCorruptionTransactionOutcomeV1, DispatchCorruptionRetentionErrorV1> {
    let input = base_quarantine_input_v1(disposition);
    let outcome = retain_base_quarantine_in_transaction_v1(transaction, &input)
        .map_err(map_retention_error_v1)?;
    Ok(match outcome {
        BaseQuarantineTransactionOutcomeV1::Inserted(custody) => {
            DispatchCorruptionTransactionOutcomeV1::Inserted(DispatchCorruptionRetentionV1 {
                created_generation: custody.created_generation(),
            })
        }
        BaseQuarantineTransactionOutcomeV1::Existing(custody) => {
            DispatchCorruptionTransactionOutcomeV1::Existing(DispatchCorruptionRetentionV1 {
                created_generation: custody.created_generation(),
            })
        }
    })
}

fn base_quarantine_input_v1(disposition: DispatchCorruptionDispositionV1) -> BaseQuarantineInputV1 {
    let attempt_id = domain_digest_v1(ATTEMPT_DOMAIN_V1, &[disposition.incident_digest.as_bytes()]);
    let operation_binding_digest = domain_digest_v1(
        BINDING_DOMAIN_V1,
        &[
            disposition.incident_digest.as_bytes(),
            disposition.evidence_digest.as_bytes(),
        ],
    );
    let reason = match disposition.kind {
        DispatchCorruptionKindV1::CoordinatorStoreRollback
        | DispatchCorruptionKindV1::CoordinatorRootRollback
        | DispatchCorruptionKindV1::CoordinatorGenerationRollback
        | DispatchCorruptionKindV1::CoordinatorHistoryTruncated
        | DispatchCorruptionKindV1::CoordinatorGenerationReused => {
            BaseQuarantineReasonV1::StoreUnhealthy
        }
        DispatchCorruptionKindV1::OrphanCoordinatorGrant
        | DispatchCorruptionKindV1::OrphanCoordinatorReceipt
        | DispatchCorruptionKindV1::GrantDigestConflict
        | DispatchCorruptionKindV1::ReceiptDigestConflict
        | DispatchCorruptionKindV1::CrossGenerationConflict
        | DispatchCorruptionKindV1::CrossStoreDisagreement => {
            BaseQuarantineReasonV1::InvariantConflict
        }
    };
    BaseQuarantineInputV1 {
        attempt_id: BaseSha256Digest::from_bytes(*attempt_id.as_bytes()),
        operation_binding_digest: BaseSha256Digest::from_bytes(
            *operation_binding_digest.as_bytes(),
        ),
        reason,
        recovery_manifest_digest: None,
    }
}

fn domain_digest_v1(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

const fn map_retention_error_v1(
    error: BaseQuarantineErrorV1,
) -> DispatchCorruptionRetentionErrorV1 {
    match error {
        BaseQuarantineErrorV1::InvalidInput => DispatchCorruptionRetentionErrorV1::InvalidInput,
        BaseQuarantineErrorV1::Conflict => DispatchCorruptionRetentionErrorV1::Conflict,
        BaseQuarantineErrorV1::Unavailable => DispatchCorruptionRetentionErrorV1::Unavailable,
        BaseQuarantineErrorV1::Unhealthy => DispatchCorruptionRetentionErrorV1::Unhealthy,
        BaseQuarantineErrorV1::GenerationExhausted => {
            DispatchCorruptionRetentionErrorV1::GenerationExhausted
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchHistoryObservationErrorV1 {
    Unavailable,
    Invalid,
}

#[derive(Clone)]
struct DispatchTableRowObservationV1 {
    key_digest: Sha256Digest,
    row_digest: Sha256Digest,
}

#[derive(Clone)]
struct DispatchTableObservationV1 {
    count: u64,
    digest: Sha256Digest,
    rows: Vec<DispatchTableRowObservationV1>,
}

#[derive(Clone)]
struct DispatchRelationshipEntryV1 {
    primary_id: [u8; 32],
    secondary_id: Option<[u8; 32]>,
    record: DispatchCrossStoreRecordV1,
}

struct CoordinatorHistoryProjectionV1 {
    root_identity_digest: Sha256Digest,
    generations: CoordinatorGenerationVectorV1,
    history_rows: u64,
    history_digest: Sha256Digest,
    tables: Vec<DispatchTableObservationV1>,
    duplicate_generation_observed: bool,
    grants: Vec<DispatchRelationshipEntryV1>,
    receipts: Vec<DispatchRelationshipEntryV1>,
}

struct AdapterRelationshipProjectionV1 {
    root_identity_digest: Sha256Digest,
    grants: Vec<DispatchRelationshipEntryV1>,
    receipts: Vec<DispatchRelationshipEntryV1>,
}

#[derive(Clone, Copy)]
struct DispatchRelationshipInventoryAnalysisV1 {
    shape: DispatchRelationshipShapeV1,
    corruption: Option<DispatchCorruptionKindV1>,
}

/// Projects one exact trusted checkpoint and one observed PAUSE cut from real, closed
/// SQLite files. The caller supplies lifecycle context, never a corruption label or verdict.
fn observe_cross_store_dispatch_history_v1(
    trusted_coordinator: &Connection,
    trusted_adapter: &Connection,
    observed_coordinator: &Connection,
    observed_adapter: &Connection,
    relation_lifecycle: DispatchRelationLifecycleV1,
) -> Result<DispatchCrossStoreHistoryInputV1, DispatchHistoryObservationErrorV1> {
    let trusted = project_coordinator_history_v1(trusted_coordinator)?;
    let observed = project_coordinator_history_v1(observed_coordinator)?;
    let trusted_adapter = project_adapter_relationships_v1(trusted_adapter)?;
    let observed_adapter = project_adapter_relationships_v1(observed_adapter)?;

    let trusted_relationships = analyze_relationship_inventories_v1(
        &trusted.grants,
        &trusted_adapter.grants,
        &trusted.receipts,
        &trusted_adapter.receipts,
        None,
        None,
        None,
        None,
        relation_lifecycle,
        false,
    )?;
    if trusted_relationships.corruption.is_some()
        || !relationship_shape_is_expected_v1(trusted_relationships.shape, relation_lifecycle)
    {
        return Err(DispatchHistoryObservationErrorV1::Invalid);
    }
    let observed_relationships = analyze_relationship_inventories_v1(
        &observed.grants,
        &observed_adapter.grants,
        &observed.receipts,
        &observed_adapter.receipts,
        Some(&trusted.grants),
        Some(&trusted_adapter.grants),
        Some(&trusted.receipts),
        Some(&trusted_adapter.receipts),
        relation_lifecycle,
        true,
    )?;

    if trusted.tables.len() != observed.tables.len()
        || trusted.tables.len() != COORDINATOR_HISTORY_TABLES_V1.len()
    {
        return Err(DispatchHistoryObservationErrorV1::Invalid);
    }
    let observed_checkpoint_rows_digest =
        exact_trusted_history_checkpoint_rows_digest_v1(&trusted, &observed)?;
    let expected_cross_store_inventory_digest =
        cross_store_inventory_digest_v1(&trusted, &trusted_adapter)?;
    let observed_cross_store_inventory_digest =
        cross_store_inventory_digest_v1(&observed, &observed_adapter)?;

    Ok(DispatchCrossStoreHistoryInputV1 {
        relation_lifecycle,
        trusted: CoordinatorHistorySnapshotV1 {
            root_identity_digest: trusted.root_identity_digest,
            generations: trusted.generations,
            history_generation: trusted.generations.store,
            history_rows: trusted.history_rows,
            history_digest: trusted.history_digest,
        },
        observed: CoordinatorObservedHistoryV1 {
            root_identity_digest: observed.root_identity_digest,
            generations: observed.generations,
            history_generation: observed.generations.store,
            history_rows: observed.history_rows,
            trusted_checkpoint_rows_digest: observed_checkpoint_rows_digest,
            complete_history_digest: observed.history_digest,
            duplicate_generation_observed: observed.duplicate_generation_observed,
        },
        relationship_shape: observed_relationships.shape,
        relationship_corruption: observed_relationships.corruption,
        expected_adapter_root_identity_digest: trusted_adapter.root_identity_digest,
        observed_adapter_root_identity_digest: observed_adapter.root_identity_digest,
        expected_cross_store_inventory_digest,
        observed_cross_store_inventory_digest,
    })
}

fn project_coordinator_history_v1(
    connection: &Connection,
) -> Result<CoordinatorHistoryProjectionV1, DispatchHistoryObservationErrorV1> {
    let root_identity = exact_digest_bytes_v1(
        connection
            .query_row(
                "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?,
    )?;
    let root_identity_digest = domain_digest_v1(ROOT_IDENTITY_DOMAIN_V1, &[&root_identity]);
    let raw: (i64, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT dispatch_store_generation, dispatch_generation, delivery_generation,
                    receipt_generation, reconciliation_generation, event_generation,
                    migration_generation
             FROM dispatch_store_meta WHERE singleton = 1",
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
                ))
            },
        )
        .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?;
    let generations = CoordinatorGenerationVectorV1 {
        store: observation_generation_v1(raw.0)?,
        dispatch: observation_generation_v1(raw.1)?,
        delivery: observation_generation_v1(raw.2)?,
        receipt: observation_generation_v1(raw.3)?,
        reconciliation: observation_generation_v1(raw.4)?,
        event: observation_generation_v1(raw.5)?,
        migration: observation_generation_v1(raw.6)?,
    };
    let mut tables = Vec::with_capacity(COORDINATOR_HISTORY_TABLES_V1.len());
    let mut history_rows = 0_u64;
    for (table, key_column) in COORDINATOR_HISTORY_TABLES_V1 {
        let observation = dispatch_table_observation_v1(connection, table, key_column)?;
        history_rows = history_rows
            .checked_add(observation.count)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(DispatchHistoryObservationErrorV1::Invalid)?;
        tables.push(observation);
    }
    let history_digest = dispatch_history_store_digest_v1(&tables)?;
    Ok(CoordinatorHistoryProjectionV1 {
        root_identity_digest,
        generations,
        history_rows,
        history_digest,
        tables,
        duplicate_generation_observed: duplicate_generation_observed_v1(connection)?,
        grants: load_coordinator_grant_relationships_v1(connection)?,
        receipts: load_coordinator_receipt_relationships_v1(connection)?,
    })
}

fn project_adapter_relationships_v1(
    connection: &Connection,
) -> Result<AdapterRelationshipProjectionV1, DispatchHistoryObservationErrorV1> {
    let root_identity = exact_digest_bytes_v1(
        connection
            .query_row(
                "SELECT root_identity FROM adapter_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?,
    )?;
    Ok(AdapterRelationshipProjectionV1 {
        root_identity_digest: domain_digest_v1(ROOT_IDENTITY_DOMAIN_V1, &[&root_identity]),
        grants: load_adapter_grant_relationships_v1(connection)?,
        receipts: load_adapter_receipt_relationships_v1(connection)?,
    })
}

fn dispatch_table_observation_v1(
    connection: &Connection,
    table: &str,
    key_column: &str,
) -> Result<DispatchTableObservationV1, DispatchHistoryObservationErrorV1> {
    let sql = format!("SELECT * FROM {table} ORDER BY {key_column}");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?;
    let column_count = statement.column_count();
    let key_index = statement
        .column_index(key_column)
        .map_err(|_| DispatchHistoryObservationErrorV1::Invalid)?;
    let mut rows = statement
        .query([])
        .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(HISTORY_TABLE_DOMAIN_V1);
    hash_len_prefixed_v1(&mut hasher, table.as_bytes())?;
    let mut count = 0_u64;
    let mut inventory_rows = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?
    {
        count = count
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(DispatchHistoryObservationErrorV1::Invalid)?;
        hasher.update(count.to_be_bytes());

        let mut key_hasher = Sha256::new();
        key_hasher.update(HISTORY_ROW_KEY_DOMAIN_V1);
        hash_len_prefixed_v1(&mut key_hasher, table.as_bytes())?;
        hash_len_prefixed_v1(&mut key_hasher, key_column.as_bytes())?;
        hash_sql_value_v1(
            &mut key_hasher,
            row.get_ref(key_index)
                .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?,
        )?;
        let key_digest = Sha256Digest::from_bytes(key_hasher.finalize().into());

        let mut row_hasher = Sha256::new();
        row_hasher.update(HISTORY_ROW_DOMAIN_V1);
        hash_len_prefixed_v1(&mut row_hasher, table.as_bytes())?;
        row_hasher.update(key_digest.as_bytes());
        for index in 0..column_count {
            hash_sql_value_v1(
                &mut hasher,
                row.get_ref(index)
                    .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?,
            )?;
            hash_sql_value_v1(
                &mut row_hasher,
                row.get_ref(index)
                    .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?,
            )?;
        }
        inventory_rows.push(DispatchTableRowObservationV1 {
            key_digest,
            row_digest: Sha256Digest::from_bytes(row_hasher.finalize().into()),
        });
    }
    Ok(DispatchTableObservationV1 {
        count,
        digest: Sha256Digest::from_bytes(hasher.finalize().into()),
        rows: inventory_rows,
    })
}

fn exact_trusted_history_checkpoint_rows_digest_v1(
    trusted: &CoordinatorHistoryProjectionV1,
    observed: &CoordinatorHistoryProjectionV1,
) -> Result<Sha256Digest, DispatchHistoryObservationErrorV1> {
    if trusted.tables.len() != observed.tables.len()
        || trusted.tables.len() != COORDINATOR_HISTORY_TABLES_V1.len()
    {
        return Err(DispatchHistoryObservationErrorV1::Invalid);
    }
    let all_trusted_rows_remain_exact =
        trusted
            .tables
            .iter()
            .zip(&observed.tables)
            .all(|(trusted_table, observed_table)| {
                trusted_table.rows.iter().all(|trusted_row| {
                    let mut same_key = observed_table
                        .rows
                        .iter()
                        .filter(|observed_row| observed_row.key_digest == trusted_row.key_digest);
                    same_key.next().is_some_and(|observed_row| {
                        observed_row.row_digest == trusted_row.row_digest
                    }) && same_key.next().is_none()
                })
            });
    if all_trusted_rows_remain_exact {
        return Ok(trusted.history_digest);
    }

    let mut hasher = Sha256::new();
    hasher.update(HISTORY_CHECKPOINT_MISMATCH_DOMAIN_V1);
    hasher.update(trusted.history_digest.as_bytes());
    hasher.update(observed.history_digest.as_bytes());
    for (((table, _), trusted_table), observed_table) in COORDINATOR_HISTORY_TABLES_V1
        .iter()
        .zip(&trusted.tables)
        .zip(&observed.tables)
    {
        hash_len_prefixed_v1(&mut hasher, table.as_bytes())?;
        for trusted_row in &trusted_table.rows {
            hasher.update(trusted_row.key_digest.as_bytes());
            hasher.update(trusted_row.row_digest.as_bytes());
            let same_key = observed_table
                .rows
                .iter()
                .filter(|observed_row| observed_row.key_digest == trusted_row.key_digest);
            let mut matches = 0_u64;
            for observed_row in same_key {
                matches = matches
                    .checked_add(1)
                    .filter(|value| *value <= MAX_SAFE_U64)
                    .ok_or(DispatchHistoryObservationErrorV1::Invalid)?;
                hasher.update(observed_row.row_digest.as_bytes());
            }
            hasher.update(matches.to_be_bytes());
        }
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn dispatch_history_store_digest_v1(
    tables: &[DispatchTableObservationV1],
) -> Result<Sha256Digest, DispatchHistoryObservationErrorV1> {
    if tables.len() != COORDINATOR_HISTORY_TABLES_V1.len() {
        return Err(DispatchHistoryObservationErrorV1::Invalid);
    }
    let mut hasher = Sha256::new();
    hasher.update(HISTORY_STORE_DOMAIN_V1);
    for ((table, _), observation) in COORDINATOR_HISTORY_TABLES_V1.iter().zip(tables) {
        hash_len_prefixed_v1(&mut hasher, table.as_bytes())?;
        hasher.update(observation.count.to_be_bytes());
        hasher.update(observation.digest.as_bytes());
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn duplicate_generation_observed_v1(
    connection: &Connection,
) -> Result<bool, DispatchHistoryObservationErrorV1> {
    for (table, generation) in COORDINATOR_GENERATION_COLUMNS_V1 {
        let sql = format!(
            "SELECT EXISTS(
                 SELECT 1 FROM {table}
                 GROUP BY {generation} HAVING COUNT(*) > 1
             )"
        );
        let duplicate = connection
            .query_row(&sql, [], |row| row.get::<_, bool>(0))
            .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?;
        if duplicate {
            return Ok(true);
        }
    }
    Ok(false)
}

fn load_coordinator_grant_relationships_v1(
    connection: &Connection,
) -> Result<Vec<DispatchRelationshipEntryV1>, DispatchHistoryObservationErrorV1> {
    load_relationships_v1(
        connection,
        "SELECT grant_id, NULL, grant_digest, operation_id, dispatch_attempt_id,
                created_generation, preparation_transition_generation
         FROM dispatch_grants ORDER BY grant_id",
        2,
    )
}

fn load_coordinator_receipt_relationships_v1(
    connection: &Connection,
) -> Result<Vec<DispatchRelationshipEntryV1>, DispatchHistoryObservationErrorV1> {
    load_relationships_v1(
        connection,
        "SELECT grant_id, receipt_id, receipt_digest, operation_id, dispatch_attempt_id,
                receipt_generation
         FROM dispatch_receipts ORDER BY grant_id, receipt_id",
        1,
    )
}

fn load_adapter_grant_relationships_v1(
    connection: &Connection,
) -> Result<Vec<DispatchRelationshipEntryV1>, DispatchHistoryObservationErrorV1> {
    load_relationships_v1(
        connection,
        "SELECT grant_id, NULL, grant_digest, operation_id, dispatch_attempt_id,
                received_generation, current_generation, epoch_observer_generation
         FROM grant_inbox ORDER BY grant_id",
        3,
    )
}

fn load_adapter_receipt_relationships_v1(
    connection: &Connection,
) -> Result<Vec<DispatchRelationshipEntryV1>, DispatchHistoryObservationErrorV1> {
    load_relationships_v1(
        connection,
        "SELECT grant_id, receipt_id, receipt_digest, operation_id, dispatch_attempt_id,
                receipt_generation
         FROM execution_receipts ORDER BY grant_id, receipt_id",
        1,
    )
}

fn load_relationships_v1(
    connection: &Connection,
    sql: &str,
    generation_column_count: usize,
) -> Result<Vec<DispatchRelationshipEntryV1>, DispatchHistoryObservationErrorV1> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?;
    let rows = statement
        .query_map([], |row| {
            let mut generations = Vec::with_capacity(generation_column_count);
            for index in 0..generation_column_count {
                generations.push(row.get::<_, i64>(5 + index)?);
            }
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                generations,
            ))
        })
        .map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?;
    let mut entries = Vec::new();
    for row in rows {
        let (
            primary_id,
            secondary_id,
            canonical_digest,
            operation_id,
            dispatch_attempt_id,
            raw_generations,
        ) = row.map_err(|_| DispatchHistoryObservationErrorV1::Unavailable)?;
        let primary_id = exact_digest_bytes_v1(primary_id)?;
        let secondary_id = secondary_id.map(exact_digest_bytes_v1).transpose()?;
        let canonical_digest = exact_digest_bytes_v1(canonical_digest)?;
        let dispatch_attempt_id = exact_digest_bytes_v1(dispatch_attempt_id)?;
        let relation_tag = if secondary_id.is_some() {
            b"RECEIPT".as_slice()
        } else {
            b"GRANT".as_slice()
        };
        let mut semantic_parts: Vec<&[u8]> = vec![relation_tag, &primary_id];
        if let Some(secondary_id) = secondary_id.as_ref() {
            semantic_parts.push(secondary_id);
        }
        semantic_parts.push(operation_id.as_bytes());
        semantic_parts.push(&dispatch_attempt_id);
        let semantic_binding_digest =
            domain_digest_v1(RELATION_SEMANTIC_DOMAIN_V1, &semantic_parts);
        let generations = raw_generations
            .into_iter()
            .map(observation_generation_v1)
            .collect::<Result<Vec<_>, _>>()?;
        let mut generation_hasher = Sha256::new();
        generation_hasher.update(RELATION_GENERATION_DOMAIN_V1);
        generation_hasher.update((generations.len() as u64).to_be_bytes());
        for generation in generations {
            generation_hasher.update(generation.to_be_bytes());
        }
        entries.push(DispatchRelationshipEntryV1 {
            primary_id,
            secondary_id,
            record: DispatchCrossStoreRecordV1 {
                canonical_digest: Sha256Digest::from_bytes(canonical_digest),
                semantic_binding_digest,
                generation_binding_digest: Sha256Digest::from_bytes(
                    generation_hasher.finalize().into(),
                ),
            },
        });
    }
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn analyze_relationship_inventories_v1(
    coordinator_grants: &[DispatchRelationshipEntryV1],
    adapter_grants: &[DispatchRelationshipEntryV1],
    coordinator_receipts: &[DispatchRelationshipEntryV1],
    adapter_receipts: &[DispatchRelationshipEntryV1],
    trusted_coordinator_grants: Option<&[DispatchRelationshipEntryV1]>,
    trusted_adapter_grants: Option<&[DispatchRelationshipEntryV1]>,
    trusted_coordinator_receipts: Option<&[DispatchRelationshipEntryV1]>,
    trusted_adapter_receipts: Option<&[DispatchRelationshipEntryV1]>,
    lifecycle: DispatchRelationLifecycleV1,
    permit_forward_lifecycle: bool,
) -> Result<DispatchRelationshipInventoryAnalysisV1, DispatchHistoryObservationErrorV1> {
    let shape = DispatchRelationshipShapeV1 {
        coordinator_grants: safe_relationship_count_v1(coordinator_grants.len())?,
        adapter_grants: safe_relationship_count_v1(adapter_grants.len())?,
        coordinator_receipts: safe_relationship_count_v1(coordinator_receipts.len())?,
        adapter_receipts: safe_relationship_count_v1(adapter_receipts.len())?,
    };
    let grant_corruption = classify_relationship_pairs_v1(
        coordinator_grants,
        adapter_grants,
        false,
        lifecycle.permits_pre_handoff_grant()
            || (permit_forward_lifecycle
                && matches!(lifecycle, DispatchRelationLifecycleV1::Prepared)),
    );
    let receipt_corruption =
        classify_relationship_pairs_v1(coordinator_receipts, adapter_receipts, true, false);
    let generation_corruption = [
        (trusted_coordinator_grants, coordinator_grants),
        (trusted_adapter_grants, adapter_grants),
        (trusted_coordinator_receipts, coordinator_receipts),
        (trusted_adapter_receipts, adapter_receipts),
    ]
    .into_iter()
    .any(|(trusted, observed)| {
        trusted.is_some_and(|trusted| generation_binding_changed_v1(trusted, observed))
    })
    .then_some(DispatchCorruptionKindV1::CrossGenerationConflict);
    Ok(DispatchRelationshipInventoryAnalysisV1 {
        shape,
        corruption: grant_corruption
            .or(receipt_corruption)
            .or(generation_corruption),
    })
}

fn classify_relationship_pairs_v1(
    coordinator: &[DispatchRelationshipEntryV1],
    adapter: &[DispatchRelationshipEntryV1],
    receipt: bool,
    permits_coordinator_only: bool,
) -> Option<DispatchCorruptionKindV1> {
    for coordinator_entry in coordinator {
        let Some(adapter_entry) = adapter
            .iter()
            .find(|entry| same_relationship_key_v1(coordinator_entry, entry))
        else {
            if permits_coordinator_only && adapter.is_empty() {
                continue;
            }
            return Some(if receipt {
                DispatchCorruptionKindV1::OrphanCoordinatorReceipt
            } else {
                DispatchCorruptionKindV1::OrphanCoordinatorGrant
            });
        };
        if coordinator_entry.record.canonical_digest != adapter_entry.record.canonical_digest {
            return Some(if receipt {
                DispatchCorruptionKindV1::ReceiptDigestConflict
            } else {
                DispatchCorruptionKindV1::GrantDigestConflict
            });
        }
        if coordinator_entry.record.semantic_binding_digest
            != adapter_entry.record.semantic_binding_digest
        {
            return Some(DispatchCorruptionKindV1::CrossStoreDisagreement);
        }
    }
    adapter
        .iter()
        .any(|adapter_entry| {
            !coordinator
                .iter()
                .any(|entry| same_relationship_key_v1(entry, adapter_entry))
        })
        .then_some(DispatchCorruptionKindV1::CrossStoreDisagreement)
}

fn generation_binding_changed_v1(
    trusted: &[DispatchRelationshipEntryV1],
    observed: &[DispatchRelationshipEntryV1],
) -> bool {
    observed.iter().any(|observed_entry| {
        trusted
            .iter()
            .find(|entry| same_relationship_key_v1(entry, observed_entry))
            .is_some_and(|trusted_entry| {
                trusted_entry.record.semantic_binding_digest
                    == observed_entry.record.semantic_binding_digest
                    && trusted_entry.record.canonical_digest
                        == observed_entry.record.canonical_digest
                    && trusted_entry.record.generation_binding_digest
                        != observed_entry.record.generation_binding_digest
            })
    })
}

fn relationship_shape_is_expected_v1(
    shape: DispatchRelationshipShapeV1,
    lifecycle: DispatchRelationLifecycleV1,
) -> bool {
    lifecycle.accepts_relationship_shape(shape)
}

fn safe_relationship_count_v1(count: usize) -> Result<u64, DispatchHistoryObservationErrorV1> {
    u64::try_from(count)
        .ok()
        .filter(|count| *count <= MAX_SAFE_U64)
        .ok_or(DispatchHistoryObservationErrorV1::Invalid)
}

fn same_relationship_key_v1(
    left: &DispatchRelationshipEntryV1,
    right: &DispatchRelationshipEntryV1,
) -> bool {
    left.primary_id == right.primary_id && left.secondary_id == right.secondary_id
}

fn cross_store_inventory_digest_v1(
    coordinator: &CoordinatorHistoryProjectionV1,
    adapter: &AdapterRelationshipProjectionV1,
) -> Result<Sha256Digest, DispatchHistoryObservationErrorV1> {
    let mut hasher = Sha256::new();
    hasher.update(CROSS_STORE_INVENTORY_DOMAIN_V1);
    hasher.update(coordinator.root_identity_digest.as_bytes());
    hasher.update(adapter.root_identity_digest.as_bytes());
    hash_relationship_inventory_v1(&mut hasher, b"COORDINATOR-GRANTS", &coordinator.grants)?;
    hash_relationship_inventory_v1(&mut hasher, b"ADAPTER-GRANTS", &adapter.grants)?;
    hash_relationship_inventory_v1(&mut hasher, b"COORDINATOR-RECEIPTS", &coordinator.receipts)?;
    hash_relationship_inventory_v1(&mut hasher, b"ADAPTER-RECEIPTS", &adapter.receipts)?;
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn hash_relationship_inventory_v1(
    hasher: &mut Sha256,
    label: &[u8],
    entries: &[DispatchRelationshipEntryV1],
) -> Result<(), DispatchHistoryObservationErrorV1> {
    hash_len_prefixed_v1(hasher, label)?;
    hasher.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher.update(entry.primary_id);
        match entry.secondary_id {
            Some(secondary) => {
                hasher.update([1]);
                hasher.update(secondary);
            }
            None => hasher.update([0]),
        }
        hasher.update(entry.record.canonical_digest.as_bytes());
        hasher.update(entry.record.generation_binding_digest.as_bytes());
    }
    Ok(())
}

fn exact_digest_bytes_v1(bytes: Vec<u8>) -> Result<[u8; 32], DispatchHistoryObservationErrorV1> {
    bytes
        .try_into()
        .map_err(|_| DispatchHistoryObservationErrorV1::Invalid)
}

fn observation_generation_v1(value: i64) -> Result<u64, DispatchHistoryObservationErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(DispatchHistoryObservationErrorV1::Invalid)
}

fn hash_len_prefixed_v1(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), DispatchHistoryObservationErrorV1> {
    let length =
        u64::try_from(bytes.len()).map_err(|_| DispatchHistoryObservationErrorV1::Invalid)?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn hash_sql_value_v1(
    hasher: &mut Sha256,
    value: ValueRef<'_>,
) -> Result<(), DispatchHistoryObservationErrorV1> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum T097CoordinatorAuditOutcomeV1 {
    NoCorruptionObserved,
    Quarantined {
        disposition: DispatchCorruptionDispositionV1,
        custody: DispatchCorruptionRetentionV1,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum T097CoordinatorAuditErrorV1 {
    ObservedUnavailable,
    ObservedAdapterUnavailable,
    CustodyUnavailable,
    ObservationUnavailable,
    ObservationInvalid,
    CheckpointMismatch,
    LocalRetentionInvalid,
    LocalRetentionConflict,
    LocalRetentionUnavailable,
    LocalRetentionUnhealthy,
    LocalRetentionGenerationExhausted,
    LocalFenceCommitUncertain,
    LocallyFencedCustodyPending,
}

/// Classifies one observed coordinator branch against the same exact PAUSE checkpoint under
/// its provisioner-attested root/file lease. The `BEGIN IMMEDIATE` snapshot is acquired before
/// any projection. A strictly valid newer checkpoint returns a payload-free mismatch without
/// mutation; corruption commits the generic local fence before the same redacted disposition
/// is copied to the distinct healthy custody root.
///
/// This core is compiled in ordinary builds even though the filesystem facade below is an
/// integration-evidence seam. A failure after the local fence is known durable is
/// deliberately collapsed to `LocallyFencedCustodyPending`: the observed branch is no
/// longer authority, and an exact retry can finish external custody. An uncertain commit
/// is read back exactly before that durable-fence conclusion is made.
#[allow(clippy::too_many_arguments)]
fn classify_and_retain_t097_coordinator_history_v1<C, F, G, H>(
    trusted_coordinator: &Connection,
    trusted_adapter: &Connection,
    observed_config: &CoordinatorStoreConfigV1,
    observed_adapter: &mut Connection,
    revalidate_observed_adapter: &F,
    verify_observed_coordinator: &G,
    verify_observed_adapter_checkpoint: &H,
    custody_config: &CoordinatorStoreConfigV1,
    lifecycle: DispatchRelationLifecycleV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<T097CoordinatorAuditOutcomeV1, T097CoordinatorAuditErrorV1>
where
    C: CoordinatorMonotonicClockV1 + ?Sized,
    F: Fn(&Connection) -> Result<(), ()> + ?Sized,
    G: Fn(&Connection) -> Result<(), ()> + ?Sized,
    H: Fn(&Connection) -> Result<(), ()> + ?Sized,
{
    let mut observed =
        open_bound_existing_connection(observed_config, clock, deadline_monotonic_ms)
            .map_err(|_| T097CoordinatorAuditErrorV1::ObservedUnavailable)?;

    observed
        .arm_next_writer_wait_v1(clock, deadline_monotonic_ms)
        .map_err(|_| T097CoordinatorAuditErrorV1::ObservedUnavailable)?;
    let observed_transaction = observed
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| T097CoordinatorAuditErrorV1::ObservedUnavailable)?;
    if revalidate_observed_adapter(observed_adapter).is_err() {
        observed_transaction
            .rollback()
            .map_err(|_| T097CoordinatorAuditErrorV1::ObservedUnavailable)?;
        return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
    }
    let observed_adapter_transaction =
        match observed_adapter.transaction_with_behavior(TransactionBehavior::Immediate) {
            Ok(transaction) => transaction,
            Err(_) => {
                observed_transaction
                    .rollback()
                    .map_err(|_| T097CoordinatorAuditErrorV1::ObservedUnavailable)?;
                return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
            }
        };
    if revalidate_observed_adapter(&observed_adapter_transaction).is_err() {
        let adapter_rollback = observed_adapter_transaction.rollback();
        let coordinator_rollback = observed_transaction.rollback();
        if coordinator_rollback.is_err() {
            return Err(T097CoordinatorAuditErrorV1::ObservedUnavailable);
        }
        if adapter_rollback.is_err() {
            return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
        }
        return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
    }
    let input = match observe_cross_store_dispatch_history_v1(
        trusted_coordinator,
        trusted_adapter,
        &observed_transaction,
        &observed_adapter_transaction,
        lifecycle,
    ) {
        Ok(input) => input,
        Err(error) => {
            let adapter_rollback = observed_adapter_transaction.rollback();
            let coordinator_rollback = observed_transaction.rollback();
            if coordinator_rollback.is_err() {
                return Err(T097CoordinatorAuditErrorV1::ObservedUnavailable);
            }
            if adapter_rollback.is_err() {
                return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
            }
            return Err(match error {
                DispatchHistoryObservationErrorV1::Unavailable => {
                    T097CoordinatorAuditErrorV1::ObservationUnavailable
                }
                DispatchHistoryObservationErrorV1::Invalid => {
                    T097CoordinatorAuditErrorV1::ObservationInvalid
                }
            });
        }
    };
    #[cfg(all(feature = "test-fault-injection", not(test)))]
    reach_t097_after_cross_store_projection_v1();
    let mut verification = verify_cross_store_dispatch_history_v1(&input);
    let needs_strict_checkpoint_decision = matches!(
        verification,
        DispatchHistoryVerificationV1::NoCorruptionObserved
            | DispatchHistoryVerificationV1::CheckpointMismatch
    ) || matches!(
        verification,
        DispatchHistoryVerificationV1::Corrupted(disposition)
            if disposition.kind() == DispatchCorruptionKindV1::CrossGenerationConflict
    );
    let strict_checkpoint_valid = needs_strict_checkpoint_decision.then(|| {
        verify_observed_coordinator(&observed_transaction).is_ok()
            && verify_observed_adapter_checkpoint(&observed_adapter_transaction).is_ok()
    });
    if strict_checkpoint_valid == Some(true)
        && matches!(
            verification,
            DispatchHistoryVerificationV1::Corrupted(disposition)
                if disposition.kind() == DispatchCorruptionKindV1::CrossGenerationConflict
        )
    {
        verification = DispatchHistoryVerificationV1::CheckpointMismatch;
    }
    let disposition = match verification {
        DispatchHistoryVerificationV1::NoCorruptionObserved
        | DispatchHistoryVerificationV1::CheckpointMismatch => {
            if strict_checkpoint_valid != Some(true) {
                let adapter_rollback = observed_adapter_transaction.rollback();
                let coordinator_rollback = observed_transaction.rollback();
                if coordinator_rollback.is_err() {
                    return Err(T097CoordinatorAuditErrorV1::ObservedUnavailable);
                }
                if adapter_rollback.is_err()
                    || revalidate_observed_adapter(observed_adapter).is_err()
                {
                    return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
                }
                observed
                    .revalidate(clock, deadline_monotonic_ms)
                    .map_err(|_| T097CoordinatorAuditErrorV1::ObservedUnavailable)?;
                return Err(T097CoordinatorAuditErrorV1::ObservationInvalid);
            }
            let adapter_rollback = observed_adapter_transaction.rollback();
            let coordinator_rollback = observed_transaction.rollback();
            if coordinator_rollback.is_err() {
                return Err(T097CoordinatorAuditErrorV1::ObservedUnavailable);
            }
            if adapter_rollback.is_err() || revalidate_observed_adapter(observed_adapter).is_err() {
                return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
            }
            observed
                .revalidate(clock, deadline_monotonic_ms)
                .map_err(|_| T097CoordinatorAuditErrorV1::ObservedUnavailable)?;
            return match verification {
                DispatchHistoryVerificationV1::NoCorruptionObserved => {
                    Ok(T097CoordinatorAuditOutcomeV1::NoCorruptionObserved)
                }
                DispatchHistoryVerificationV1::CheckpointMismatch => {
                    Err(T097CoordinatorAuditErrorV1::CheckpointMismatch)
                }
                DispatchHistoryVerificationV1::Corrupted(_) => unreachable!(),
            };
        }
        DispatchHistoryVerificationV1::Corrupted(disposition) => disposition,
    };

    let local = match retain_dispatch_corruption_quarantine_in_transaction_v1(
        &observed_transaction,
        disposition,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            let adapter_rollback = observed_adapter_transaction.rollback();
            let coordinator_rollback = observed_transaction.rollback();
            if coordinator_rollback.is_err() {
                return Err(T097CoordinatorAuditErrorV1::ObservedUnavailable);
            }
            if adapter_rollback.is_err() || revalidate_observed_adapter(observed_adapter).is_err() {
                return Err(T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable);
            }
            return Err(map_local_retention_error_v1(error));
        }
    };
    match local {
        DispatchCorruptionTransactionOutcomeV1::Inserted(_) => {
            if observed_transaction.commit().is_err() {
                let adapter_rollback = observed_adapter_transaction.rollback();
                if adapter_rollback.is_err()
                    || revalidate_observed_adapter(observed_adapter).is_err()
                {
                    return Err(T097CoordinatorAuditErrorV1::LocalFenceCommitUncertain);
                }
                if observed.revalidate(clock, deadline_monotonic_ms).is_err() {
                    return Err(T097CoordinatorAuditErrorV1::LocalFenceCommitUncertain);
                }
                return Err(classify_uncertain_local_fence_readback_v1(
                    observed.connection_mut(),
                    disposition,
                ));
            }
            if observed_adapter_transaction.rollback().is_err()
                || revalidate_observed_adapter(observed_adapter).is_err()
            {
                return Err(T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending);
            }
        }
        DispatchCorruptionTransactionOutcomeV1::Existing(_) => {
            let adapter_rollback = observed_adapter_transaction.rollback();
            let coordinator_rollback = observed_transaction.rollback();
            if coordinator_rollback.is_err()
                || adapter_rollback.is_err()
                || revalidate_observed_adapter(observed_adapter).is_err()
            {
                return Err(T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending);
            }
        }
    }
    observed
        .revalidate(clock, deadline_monotonic_ms)
        .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;

    let mut custody = open_bound_existing_connection(custody_config, clock, deadline_monotonic_ms)
        .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;
    custody
        .arm_next_writer_wait_v1(clock, deadline_monotonic_ms)
        .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;
    let custody_transaction = custody
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;
    let external = match retain_dispatch_corruption_quarantine_in_transaction_v1(
        &custody_transaction,
        disposition,
    ) {
        Ok(outcome) => outcome,
        Err(_) => {
            custody_transaction
                .rollback()
                .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;
            return Err(T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending);
        }
    };
    let retained = match external {
        DispatchCorruptionTransactionOutcomeV1::Inserted(retained) => {
            custody_transaction
                .commit()
                .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;
            retained
        }
        DispatchCorruptionTransactionOutcomeV1::Existing(retained) => {
            custody_transaction
                .rollback()
                .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;
            retained
        }
    };
    custody
        .revalidate(clock, deadline_monotonic_ms)
        .map_err(|_| T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending)?;
    Ok(T097CoordinatorAuditOutcomeV1::Quarantined {
        disposition,
        custody: retained,
    })
}

/// Classifies the durable readback after SQLite returned an uncertain local-fence commit.
///
/// Only an exact retained row proves that the observed coordinator source is already
/// fenced. Exact absence permits a later retention retry, while a different row under the
/// same incident key remains a permanent conflict. Any unreadable or malformed state keeps
/// the commit outcome explicitly uncertain.
fn classify_uncertain_local_fence_readback_v1(
    connection: &Connection,
    disposition: DispatchCorruptionDispositionV1,
) -> T097CoordinatorAuditErrorV1 {
    let input = base_quarantine_input_v1(disposition);
    match read_exact_base_quarantine_v1(connection, &input) {
        Ok(Some(_)) => T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending,
        Ok(None) => T097CoordinatorAuditErrorV1::LocalRetentionUnavailable,
        Err(BaseQuarantineErrorV1::Conflict) => T097CoordinatorAuditErrorV1::LocalRetentionConflict,
        Err(_) => T097CoordinatorAuditErrorV1::LocalFenceCommitUncertain,
    }
}

const fn map_local_retention_error_v1(
    error: DispatchCorruptionRetentionErrorV1,
) -> T097CoordinatorAuditErrorV1 {
    match error {
        DispatchCorruptionRetentionErrorV1::InvalidInput => {
            T097CoordinatorAuditErrorV1::LocalRetentionInvalid
        }
        DispatchCorruptionRetentionErrorV1::Conflict => {
            T097CoordinatorAuditErrorV1::LocalRetentionConflict
        }
        DispatchCorruptionRetentionErrorV1::Unavailable => {
            T097CoordinatorAuditErrorV1::LocalRetentionUnavailable
        }
        DispatchCorruptionRetentionErrorV1::Unhealthy => {
            T097CoordinatorAuditErrorV1::LocalRetentionUnhealthy
        }
        DispatchCorruptionRetentionErrorV1::GenerationExhausted => {
            T097CoordinatorAuditErrorV1::LocalRetentionGenerationExhausted
        }
    }
}

/// Closed lifecycle selector for the feature-gated T097 filesystem observer.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T097CoordinatorLifecycleForTestV1 {
    Prepared,
    Dispatching,
    AdapterReceived,
    Consumed,
    Ambiguous,
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
impl From<T097CoordinatorLifecycleForTestV1> for DispatchRelationLifecycleV1 {
    fn from(value: T097CoordinatorLifecycleForTestV1) -> Self {
        match value {
            T097CoordinatorLifecycleForTestV1::Prepared => Self::Prepared,
            T097CoordinatorLifecycleForTestV1::Dispatching => Self::Dispatching,
            T097CoordinatorLifecycleForTestV1::AdapterReceived => Self::AdapterReceived,
            T097CoordinatorLifecycleForTestV1::Consumed => Self::Consumed,
            T097CoordinatorLifecycleForTestV1::Ambiguous => Self::Ambiguous,
        }
    }
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
struct T097AfterProjectionBarrierV1 {
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
static T097_AFTER_PROJECTION_BARRIER_V1: OnceLock<Mutex<Option<T097AfterProjectionBarrierV1>>> =
    OnceLock::new();

/// Installs one process-local deterministic integration barrier after both observed
/// sovereign-store projections and before the coordinator local fence is retained.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub fn install_t097_after_projection_barrier_for_test_v1(
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
) -> Result<(), &'static str> {
    let mut slot = T097_AFTER_PROJECTION_BARRIER_V1
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "t097-projection-barrier-poisoned")?;
    if slot.is_some() {
        return Err("t097-projection-barrier-already-installed");
    }
    *slot = Some(T097AfterProjectionBarrierV1 { reached, release });
    Ok(())
}

/// Clears the feature-only deterministic projection barrier after one integration test.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub fn clear_t097_after_projection_barrier_for_test_v1() -> Result<(), &'static str> {
    let mut slot = T097_AFTER_PROJECTION_BARRIER_V1
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| "t097-projection-barrier-poisoned")?;
    *slot = None;
    Ok(())
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
fn reach_t097_after_cross_store_projection_v1() {
    let barrier = T097_AFTER_PROJECTION_BARRIER_V1
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|slot| {
            slot.as_ref()
                .map(|barrier| (Arc::clone(&barrier.reached), Arc::clone(&barrier.release)))
        });
    if let Some((reached, release)) = barrier {
        reached.wait();
        release.wait();
    }
}

/// Payload-free result of one real-filesystem T097 observation.
///
/// It intentionally contains no path, root identity, row identifier, canonical wire,
/// evidence digest, execution permit, or redelivery capability.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct T097CoordinatorObservationEvidenceV1 {
    corruption_reason_code: Option<&'static str>,
    base_reason_code: Option<&'static str>,
    created_generation: Option<u64>,
    retained_row_count: u64,
    execution_refused: bool,
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
impl T097CoordinatorObservationEvidenceV1 {
    pub const fn corruption_reason_code(self) -> Option<&'static str> {
        self.corruption_reason_code
    }

    pub const fn base_reason_code(self) -> Option<&'static str> {
        self.base_reason_code
    }

    pub const fn created_generation(self) -> Option<u64> {
        self.created_generation
    }

    pub const fn retained_row_count(self) -> u64 {
        self.retained_row_count
    }

    pub const fn execution_refused(self) -> bool {
        self.execution_refused
    }
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
impl fmt::Debug for T097CoordinatorObservationEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("T097CoordinatorObservationEvidenceV1")
            .field("corruption_reason_code", &self.corruption_reason_code)
            .field("base_reason_code", &self.base_reason_code)
            .field("created_generation", &self.created_generation)
            .field("retained_row_count", &self.retained_row_count)
            .field("execution_refused", &self.execution_refused)
            .finish()
    }
}

/// Observes real trusted/observed coordinator and adapter files, classifies their exact
/// relationship, and retains corruption only in the separately supplied healthy root.
///
/// The seam is non-default test evidence. It accepts no corruption case or expected
/// verdict, and returns no authority-bearing object.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub fn classify_and_retain_t097_coordinator_history_for_test_v1(
    trusted_coordinator_database: &Path,
    trusted_adapter_database: &Path,
    observed_coordinator_database: &Path,
    observed_adapter_database: &Path,
    healthy_custody_database: &Path,
    lifecycle: T097CoordinatorLifecycleForTestV1,
) -> Result<T097CoordinatorObservationEvidenceV1, &'static str> {
    let source_paths = [
        canonical_database_path_v1(trusted_coordinator_database)
            .map_err(|_| "t097-trusted-coordinator-unavailable")?,
        canonical_database_path_v1(trusted_adapter_database)
            .map_err(|_| "t097-trusted-adapter-unavailable")?,
        canonical_database_path_v1(observed_coordinator_database)
            .map_err(|_| "t097-observed-coordinator-unavailable")?,
        canonical_database_path_v1(observed_adapter_database)
            .map_err(|_| "t097-observed-adapter-unavailable")?,
        canonical_database_path_v1(healthy_custody_database)
            .map_err(|_| "t097-custody-unavailable")?,
    ];
    for (index, path) in source_paths.iter().enumerate() {
        for candidate in source_paths.iter().skip(index + 1) {
            if database_paths_alias_v1(path, candidate)? {
                return Err("t097-database-alias-refused");
            }
        }
    }
    let trusted_coordinator = open_observation_database_v1(&source_paths[0])
        .map_err(|_| "t097-trusted-coordinator-unavailable")?;
    let trusted_adapter = open_observation_database_v1(&source_paths[1])
        .map_err(|_| "t097-trusted-adapter-unavailable")?;
    let observed_adapter_binding = T097DatabasePathBindingV1::capture(&source_paths[3])
        .map_err(|_| "t097-observed-adapter-unavailable")?;
    let mut observed_adapter = open_mutable_observation_database_v1(&source_paths[3])
        .map_err(|_| "t097-observed-adapter-unavailable")?;
    observed_adapter_binding
        .revalidate(&observed_adapter)
        .map_err(|_| "t097-observed-adapter-unavailable")?;
    verify_t097_trusted_dispatch_checkpoint_v1(&trusted_coordinator)
        .map_err(|_| "t097-trusted-coordinator-invalid")?;
    verify_trusted_adapter_checkpoint_v1(&source_paths[1], &trusted_adapter)?;
    let observed_config = coordinator_audit_config_v1(&source_paths[2])
        .map_err(|_| "t097-observed-coordinator-unavailable")?;
    let custody_config =
        coordinator_audit_config_v1(&source_paths[4]).map_err(|_| "t097-custody-unavailable")?;
    let clock = T097CoordinatorAuditClockV1::new();
    let outcome = classify_and_retain_t097_coordinator_history_v1(
        &trusted_coordinator,
        &trusted_adapter,
        &observed_config,
        &mut observed_adapter,
        &|connection| observed_adapter_binding.revalidate(connection),
        &|connection| verify_t097_trusted_dispatch_checkpoint_v1(connection).map_err(|_| ()),
        &|connection| {
            verify_trusted_adapter_checkpoint_v1(&source_paths[3], connection).map_err(|_| ())
        },
        &custody_config,
        lifecycle.into(),
        &clock,
        T097_COORDINATOR_AUDIT_DEADLINE_MS_V1,
    )
    .map_err(map_t097_audit_error_v1)?;
    drop(observed_adapter);
    drop(trusted_adapter);
    drop(trusted_coordinator);

    let (disposition, retained) = match outcome {
        T097CoordinatorAuditOutcomeV1::NoCorruptionObserved => {
            return Ok(T097CoordinatorObservationEvidenceV1 {
                corruption_reason_code: None,
                base_reason_code: None,
                created_generation: None,
                retained_row_count: 0,
                execution_refused: true,
            });
        }
        T097CoordinatorAuditOutcomeV1::Quarantined {
            disposition,
            custody,
        } => (disposition, custody),
    };
    let custody =
        open_observation_database_v1(&source_paths[4]).map_err(|_| "t097-custody-unavailable")?;
    let (retained_row_count, base_reason_code): (i64, String) =
        custody
            .query_row(
                "SELECT
                 (SELECT COUNT(*) FROM preparation_quarantines
                  WHERE quarantine_reason IN ('INVARIANT_CONFLICT', 'STORE_UNHEALTHY')),
                 quarantine_reason
             FROM preparation_quarantines
             WHERE created_generation = ?1",
                [i64::try_from(retained.created_generation())
                    .map_err(|_| "t097-custody-unhealthy")?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| "t097-custody-unhealthy")?;
    let retained_row_count =
        u64::try_from(retained_row_count).map_err(|_| "t097-custody-unhealthy")?;
    let expected_base_reason = match disposition.kind() {
        DispatchCorruptionKindV1::CoordinatorStoreRollback
        | DispatchCorruptionKindV1::CoordinatorRootRollback
        | DispatchCorruptionKindV1::CoordinatorGenerationRollback
        | DispatchCorruptionKindV1::CoordinatorHistoryTruncated
        | DispatchCorruptionKindV1::CoordinatorGenerationReused => "STORE_UNHEALTHY",
        DispatchCorruptionKindV1::OrphanCoordinatorGrant
        | DispatchCorruptionKindV1::OrphanCoordinatorReceipt
        | DispatchCorruptionKindV1::GrantDigestConflict
        | DispatchCorruptionKindV1::ReceiptDigestConflict
        | DispatchCorruptionKindV1::CrossGenerationConflict
        | DispatchCorruptionKindV1::CrossStoreDisagreement => "INVARIANT_CONFLICT",
    };
    if base_reason_code != expected_base_reason {
        return Err("t097-custody-unhealthy");
    }
    Ok(T097CoordinatorObservationEvidenceV1 {
        corruption_reason_code: Some(disposition.reason_code()),
        base_reason_code: Some(expected_base_reason),
        created_generation: Some(retained.created_generation()),
        retained_row_count,
        execution_refused: disposition.execution() == DispatchCorruptionExecutionV1::Refused,
    })
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
const T097_COORDINATOR_AUDIT_DEADLINE_MS_V1: u64 = 30_000;

#[cfg(all(feature = "test-fault-injection", not(test)))]
struct T097CoordinatorAuditClockV1 {
    started: Instant,
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
impl T097CoordinatorAuditClockV1 {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
impl CoordinatorMonotonicClockV1 for T097CoordinatorAuditClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        u64::try_from(self.started.elapsed().as_millis())
            .ok()
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(CoordinatorClockUnavailableV1)
    }
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
const fn map_t097_audit_error_v1(error: T097CoordinatorAuditErrorV1) -> &'static str {
    match error {
        T097CoordinatorAuditErrorV1::ObservedUnavailable => "t097-observed-coordinator-unavailable",
        T097CoordinatorAuditErrorV1::ObservedAdapterUnavailable => {
            "t097-observed-adapter-unavailable"
        }
        T097CoordinatorAuditErrorV1::CustodyUnavailable => "t097-custody-unavailable",
        T097CoordinatorAuditErrorV1::ObservationUnavailable => "t097-observation-unavailable",
        T097CoordinatorAuditErrorV1::ObservationInvalid => "t097-observation-invalid",
        T097CoordinatorAuditErrorV1::CheckpointMismatch => "CHECKPOINT_MISMATCH",
        T097CoordinatorAuditErrorV1::LocalRetentionInvalid => "t097-local-custody-invalid",
        T097CoordinatorAuditErrorV1::LocalRetentionConflict => "t097-local-custody-conflict",
        T097CoordinatorAuditErrorV1::LocalRetentionUnavailable => "t097-local-custody-unavailable",
        T097CoordinatorAuditErrorV1::LocalRetentionUnhealthy => "t097-local-custody-unhealthy",
        T097CoordinatorAuditErrorV1::LocalRetentionGenerationExhausted => {
            "t097-local-custody-generation-exhausted"
        }
        T097CoordinatorAuditErrorV1::LocalFenceCommitUncertain => {
            "t097-local-fence-commit-uncertain"
        }
        T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending => {
            "t097-locally-fenced-custody-pending"
        }
    }
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
fn coordinator_audit_config_v1(path: &Path) -> Result<CoordinatorStoreConfigV1, &'static str> {
    let database_path = canonical_database_path_v1(path)?;
    let root = database_path
        .parent()
        .ok_or("t097-observation-unavailable")?
        .to_path_buf();
    let connection = open_observation_database_v1(&database_path)?;
    let identity = exact_digest_bytes_v1(
        connection
            .query_row(
                "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| "t097-observation-unavailable")?,
    )
    .map_err(|_| "t097-observation-unavailable")?;
    CoordinatorStoreConfigV1::try_new_existing_attested(
        root,
        CoordinatorRootIdentityEvidenceV1::from_attested_bytes(identity),
        25,
    )
    .map_err(|_| "t097-observation-unavailable")
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
fn open_observation_database_v1(path: &Path) -> Result<Connection, &'static str> {
    let path = canonical_database_path_v1(path)?;
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "t097-observation-unavailable")
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
fn open_mutable_observation_database_v1(path: &Path) -> Result<Connection, &'static str> {
    let path = canonical_database_path_v1(path)?;
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "t097-observation-unavailable")
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
#[derive(Clone, Copy, PartialEq, Eq)]
struct T097DatabaseFileIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(windows)]
    file_id: u128,
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
struct T097DatabasePathBindingV1 {
    canonical_path: std::path::PathBuf,
    identity: T097DatabaseFileIdentityV1,
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
impl T097DatabasePathBindingV1 {
    fn capture(path: &Path) -> Result<Self, ()> {
        let canonical_path = std::fs::canonicalize(path).map_err(|_| ())?;
        let metadata = std::fs::metadata(&canonical_path).map_err(|_| ())?;
        if !metadata.is_file() {
            return Err(());
        }
        Ok(Self {
            identity: t097_database_file_identity_v1(&canonical_path, &metadata)?,
            canonical_path,
        })
    }

    fn revalidate(&self, connection: &Connection) -> Result<(), ()> {
        let database_path: String = connection
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name = 'main'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ())?;
        let canonical_path = std::fs::canonicalize(database_path).map_err(|_| ())?;
        if canonical_path != self.canonical_path {
            return Err(());
        }
        let metadata = std::fs::metadata(&canonical_path).map_err(|_| ())?;
        if !metadata.is_file()
            || t097_database_file_identity_v1(&canonical_path, &metadata)? != self.identity
        {
            return Err(());
        }
        Ok(())
    }
}

#[cfg(all(feature = "test-fault-injection", not(test), unix))]
fn t097_database_file_identity_v1(
    _path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<T097DatabaseFileIdentityV1, ()> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(T097DatabaseFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(all(feature = "test-fault-injection", not(test), windows))]
fn t097_database_file_identity_v1(
    path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<T097DatabaseFileIdentityV1, ()> {
    match file_id::get_high_res_file_id(path).map_err(|_| ())? {
        file_id::FileId::HighRes {
            volume_serial_number,
            file_id,
        } => Ok(T097DatabaseFileIdentityV1 {
            volume_serial_number,
            file_id,
        }),
        file_id::FileId::Inode { .. } | file_id::FileId::LowRes { .. } => Err(()),
    }
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
fn verify_trusted_adapter_checkpoint_v1(
    database_path: &Path,
    connection: &Connection,
) -> Result<(), &'static str> {
    let root_identity = exact_digest_bytes_v1(
        connection
            .query_row(
                "SELECT root_identity FROM adapter_store_meta WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(|_| "t097-trusted-adapter-invalid")?,
    )
    .map_err(|_| "t097-trusted-adapter-invalid")?;
    let root = database_path
        .parent()
        .ok_or("t097-trusted-adapter-invalid")?
        .to_path_buf();
    let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
        root,
        AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(root_identity),
        25,
    )
    .map_err(|_| "t097-trusted-adapter-invalid")?;
    let profile = AdapterInboxProfileV1::try_new(
        "adapter-t097-checkpoint-v1",
        1,
        Sha256Digest::digest(b"HELIXOS\0T097-TRUSTED-ADAPTER-PROFILE\0V1\0"),
    )
    .map_err(|_| "t097-trusted-adapter-invalid")?;
    drop(
        SqliteDispatchInboxStoreV1::open_existing_v1(config, profile)
            .map_err(|_| "t097-trusted-adapter-invalid")?,
    );
    Ok(())
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
fn canonical_database_path_v1(path: &Path) -> Result<std::path::PathBuf, &'static str> {
    let canonical = std::fs::canonicalize(path).map_err(|_| "t097-observation-unavailable")?;
    if !std::fs::metadata(&canonical)
        .map_err(|_| "t097-observation-unavailable")?
        .is_file()
    {
        return Err("t097-observation-unavailable");
    }
    Ok(canonical)
}

#[cfg(all(feature = "test-fault-injection", not(test)))]
fn database_paths_alias_v1(left: &Path, right: &Path) -> Result<bool, &'static str> {
    if left == right {
        return Ok(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let left = std::fs::metadata(left).map_err(|_| "t097-observation-unavailable")?;
        let right = std::fs::metadata(right).map_err(|_| "t097-observation-unavailable")?;
        return Ok(left.dev() == right.dev() && left.ino() == right.ino());
    }
    #[cfg(windows)]
    {
        let left =
            file_id::get_high_res_file_id(left).map_err(|_| "t097-observation-unavailable")?;
        let right =
            file_id::get_high_res_file_id(right).map_err(|_| "t097-observation-unavailable")?;
        return Ok(left == right);
    }
    #[allow(unreachable_code)]
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn generations(store: u64) -> CoordinatorGenerationVectorV1 {
        CoordinatorGenerationVectorV1 {
            store,
            dispatch: store,
            delivery: store,
            receipt: store,
            reconciliation: store,
            event: store,
            migration: store,
        }
    }

    fn record(byte: u8) -> DispatchCrossStoreRecordV1 {
        DispatchCrossStoreRecordV1 {
            canonical_digest: digest(byte),
            semantic_binding_digest: digest(byte.wrapping_add(1)),
            generation_binding_digest: digest(byte.wrapping_add(1)),
        }
    }

    fn exact_input() -> DispatchCrossStoreHistoryInputV1 {
        DispatchCrossStoreHistoryInputV1 {
            relation_lifecycle: DispatchRelationLifecycleV1::Consumed,
            trusted: CoordinatorHistorySnapshotV1 {
                root_identity_digest: digest(1),
                generations: generations(7),
                history_generation: 7,
                history_rows: 4,
                history_digest: digest(2),
            },
            observed: CoordinatorObservedHistoryV1 {
                root_identity_digest: digest(1),
                generations: generations(7),
                history_generation: 7,
                history_rows: 4,
                trusted_checkpoint_rows_digest: digest(2),
                complete_history_digest: digest(2),
                duplicate_generation_observed: false,
            },
            relationship_shape: DispatchRelationshipShapeV1 {
                coordinator_grants: 1,
                adapter_grants: 1,
                coordinator_receipts: 1,
                adapter_receipts: 1,
            },
            relationship_corruption: None,
            expected_adapter_root_identity_digest: digest(8),
            observed_adapter_root_identity_digest: digest(8),
            expected_cross_store_inventory_digest: digest(7),
            observed_cross_store_inventory_digest: digest(7),
        }
    }

    fn corruption_kind(input: &DispatchCrossStoreHistoryInputV1) -> DispatchCorruptionKindV1 {
        match verify_cross_store_dispatch_history_v1(input) {
            DispatchHistoryVerificationV1::Corrupted(disposition) => {
                assert_eq!(
                    disposition.custody(),
                    DispatchCorruptionCustodyV1::Quarantined
                );
                assert_eq!(
                    disposition.execution(),
                    DispatchCorruptionExecutionV1::Refused
                );
                disposition.kind()
            }
            DispatchHistoryVerificationV1::NoCorruptionObserved => {
                panic!("fixture must classify corruption")
            }
            DispatchHistoryVerificationV1::CheckpointMismatch => {
                panic!("fixture must classify corruption, not checkpoint mismatch")
            }
        }
    }

    #[test]
    fn exact_cross_store_history_is_only_an_integrity_observation() {
        assert_eq!(
            verify_cross_store_dispatch_history_v1(&exact_input()),
            DispatchHistoryVerificationV1::NoCorruptionObserved
        );
    }

    #[test]
    fn strict_candidate_progression_is_a_non_corruption_checkpoint_mismatch() {
        let mut newer = exact_input();
        newer.observed.generations = generations(8);
        newer.observed.history_generation = 8;
        newer.observed.complete_history_digest = digest(9);
        newer.observed.trusted_checkpoint_rows_digest = digest(10);
        assert_eq!(
            verify_cross_store_dispatch_history_v1(&newer),
            DispatchHistoryVerificationV1::CheckpointMismatch
        );

        let mut paired_lifecycle_progression = exact_input();
        paired_lifecycle_progression.relation_lifecycle = DispatchRelationLifecycleV1::Prepared;
        paired_lifecycle_progression.observed.generations = generations(8);
        paired_lifecycle_progression.observed.history_generation = 8;
        paired_lifecycle_progression.observed.history_rows = 8;
        paired_lifecycle_progression
            .observed
            .complete_history_digest = digest(9);
        paired_lifecycle_progression
            .observed
            .trusted_checkpoint_rows_digest = digest(10);
        paired_lifecycle_progression.observed_cross_store_inventory_digest = digest(11);
        assert_eq!(
            verify_cross_store_dispatch_history_v1(&paired_lifecycle_progression),
            DispatchHistoryVerificationV1::CheckpointMismatch
        );
    }

    #[test]
    fn all_five_restore_lifecycles_accept_their_legitimate_relationship_shape() {
        let mut prepared = exact_input();
        prepared.relation_lifecycle = DispatchRelationLifecycleV1::Prepared;
        prepared.relationship_shape = DispatchRelationshipShapeV1 {
            coordinator_grants: 0,
            adapter_grants: 0,
            coordinator_receipts: 0,
            adapter_receipts: 0,
        };

        let mut dispatching = prepared;
        dispatching.relation_lifecycle = DispatchRelationLifecycleV1::Dispatching;
        dispatching.relationship_shape.coordinator_grants = 1;

        let mut adapter_received = prepared;
        adapter_received.relation_lifecycle = DispatchRelationLifecycleV1::AdapterReceived;
        adapter_received.relationship_shape.coordinator_grants = 1;
        adapter_received.relationship_shape.adapter_grants = 1;

        let consumed = exact_input();

        let mut ambiguous = dispatching;
        ambiguous.relation_lifecycle = DispatchRelationLifecycleV1::Ambiguous;

        for input in [prepared, dispatching, adapter_received, consumed, ambiguous] {
            assert_eq!(
                verify_cross_store_dispatch_history_v1(&input),
                DispatchHistoryVerificationV1::NoCorruptionObserved
            );
        }
    }

    #[test]
    fn every_coordinator_corruption_class_is_closed() {
        let mut input = exact_input();
        input.relationship_corruption = Some(DispatchCorruptionKindV1::OrphanCoordinatorGrant);
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::OrphanCoordinatorGrant
        );

        let mut input = exact_input();
        input.relationship_corruption = Some(DispatchCorruptionKindV1::OrphanCoordinatorReceipt);
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::OrphanCoordinatorReceipt
        );

        let mut input = exact_input();
        input.relationship_corruption = Some(DispatchCorruptionKindV1::GrantDigestConflict);
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::GrantDigestConflict
        );

        let mut input = exact_input();
        input.relationship_corruption = Some(DispatchCorruptionKindV1::ReceiptDigestConflict);
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::ReceiptDigestConflict
        );

        let mut input = exact_input();
        input.relationship_corruption = Some(DispatchCorruptionKindV1::CrossGenerationConflict);
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::CrossGenerationConflict
        );

        let mut input = exact_input();
        input.observed.generations.store = 6;
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::CoordinatorStoreRollback
        );

        let mut input = exact_input();
        input.observed.root_identity_digest = digest(99);
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::CoordinatorRootRollback
        );

        let mut input = exact_input();
        input.observed.generations.receipt = 6;
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::CoordinatorGenerationRollback
        );

        let mut input = exact_input();
        input.observed.history_rows = 3;
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::CoordinatorHistoryTruncated
        );

        let mut input = exact_input();
        input.observed.duplicate_generation_observed = true;
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::CoordinatorGenerationReused
        );

        let mut input = exact_input();
        input.relationship_corruption = Some(DispatchCorruptionKindV1::CrossStoreDisagreement);
        assert_eq!(
            corruption_kind(&input),
            DispatchCorruptionKindV1::CrossStoreDisagreement
        );
    }

    fn retention_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("database opens");
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
            .expect("retention schema creates");
        connection
    }

    #[test]
    fn evidence_and_permanent_retention_are_deterministic_and_redacted() {
        let mut input = exact_input();
        input.relationship_corruption = Some(DispatchCorruptionKindV1::OrphanCoordinatorGrant);
        let first = match verify_cross_store_dispatch_history_v1(&input) {
            DispatchHistoryVerificationV1::Corrupted(value) => value,
            DispatchHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
            DispatchHistoryVerificationV1::CheckpointMismatch => {
                panic!("corruption expected, not checkpoint mismatch")
            }
        };
        let second = match verify_cross_store_dispatch_history_v1(&input) {
            DispatchHistoryVerificationV1::Corrupted(value) => value,
            DispatchHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
            DispatchHistoryVerificationV1::CheckpointMismatch => {
                panic!("corruption expected, not checkpoint mismatch")
            }
        };
        assert_eq!(first.evidence_digest(), second.evidence_digest());
        assert_eq!(first.reason_code(), "ORPHAN_COORDINATOR_GRANT");
        let debug = format!("{first:?}");
        assert!(!debug.contains(&format!("{:?}", first.evidence_digest())));
        let mut connection = retention_connection();
        let retained = retain_dispatch_corruption_quarantine_v1(&mut connection, first)
            .expect("first custody retains");
        let repeat = retain_dispatch_corruption_quarantine_v1(&mut connection, second)
            .expect("exact retry reads custody");
        assert_eq!(retained, repeat);
        assert_eq!(retained.created_generation(), 1);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM preparation_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                },)
                .expect("custody count reads"),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT quarantine_reason FROM preparation_quarantines",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("reason reads"),
            "INVARIANT_CONFLICT"
        );
    }

    #[test]
    fn changed_evidence_for_one_incident_is_a_permanent_conflict() {
        let mut original = exact_input();
        original.relationship_corruption = Some(DispatchCorruptionKindV1::OrphanCoordinatorGrant);
        let original = match verify_cross_store_dispatch_history_v1(&original) {
            DispatchHistoryVerificationV1::Corrupted(value) => value,
            DispatchHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
            DispatchHistoryVerificationV1::CheckpointMismatch => {
                panic!("corruption expected, not checkpoint mismatch")
            }
        };
        let mut changed = exact_input();
        changed.relationship_corruption = Some(DispatchCorruptionKindV1::OrphanCoordinatorGrant);
        changed.observed_cross_store_inventory_digest = digest(99);
        let changed = match verify_cross_store_dispatch_history_v1(&changed) {
            DispatchHistoryVerificationV1::Corrupted(value) => value,
            DispatchHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
            DispatchHistoryVerificationV1::CheckpointMismatch => {
                panic!("corruption expected, not checkpoint mismatch")
            }
        };
        let mut connection = retention_connection();
        retain_dispatch_corruption_quarantine_v1(&mut connection, original)
            .expect("original custody retains");
        assert_eq!(
            retain_dispatch_corruption_quarantine_v1(&mut connection, changed),
            Err(DispatchCorruptionRetentionErrorV1::Conflict)
        );
    }

    #[test]
    fn uncertain_local_fence_readback_classifies_present_absent_and_conflicting_rows() {
        let mut original = exact_input();
        original.relationship_corruption = Some(DispatchCorruptionKindV1::OrphanCoordinatorGrant);
        let original = match verify_cross_store_dispatch_history_v1(&original) {
            DispatchHistoryVerificationV1::Corrupted(value) => value,
            DispatchHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
            DispatchHistoryVerificationV1::CheckpointMismatch => {
                panic!("corruption expected, not checkpoint mismatch")
            }
        };

        let absent = retention_connection();
        assert_eq!(
            classify_uncertain_local_fence_readback_v1(&absent, original),
            T097CoordinatorAuditErrorV1::LocalRetentionUnavailable,
            "exact absence must not claim that the source fence committed"
        );

        let mut retained = retention_connection();
        retain_dispatch_corruption_quarantine_v1(&mut retained, original)
            .expect("original local fence retains");
        assert_eq!(
            classify_uncertain_local_fence_readback_v1(&retained, original),
            T097CoordinatorAuditErrorV1::LocallyFencedCustodyPending,
            "an exact visible row proves the local fence and leaves external custody pending"
        );

        let mut changed = exact_input();
        changed.relationship_corruption = Some(DispatchCorruptionKindV1::OrphanCoordinatorGrant);
        changed.observed_cross_store_inventory_digest = digest(99);
        let changed = match verify_cross_store_dispatch_history_v1(&changed) {
            DispatchHistoryVerificationV1::Corrupted(value) => value,
            DispatchHistoryVerificationV1::NoCorruptionObserved => panic!("corruption expected"),
            DispatchHistoryVerificationV1::CheckpointMismatch => {
                panic!("corruption expected, not checkpoint mismatch")
            }
        };
        assert_eq!(
            classify_uncertain_local_fence_readback_v1(&retained, changed),
            T097CoordinatorAuditErrorV1::LocalRetentionConflict,
            "same incident with different evidence must remain a permanent conflict"
        );
    }
}
