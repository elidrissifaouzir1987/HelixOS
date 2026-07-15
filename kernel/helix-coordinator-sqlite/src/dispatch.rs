//! Canonical initial coordinator dispatch transaction.

#![allow(dead_code)] // Integrated with SqliteCoordinatorStoreV2 by T037.

use crate::dispatch_events::{
    stage_pending_dispatch_event_v1, DispatchEventRowV1, DispatchMetricsV1,
};
#[cfg(feature = "test-fault-injection")]
use crate::dispatch_fault::{CoordinatorDispatchFaultProbeV1, FaultBoundaryV1};
use crate::dispatch_outbox::{stage_pending_dispatch_outbox_v1, DispatchOutboxRowV1};
use helix_contracts::MAX_SAFE_U64;
#[cfg(not(test))]
pub(crate) use helix_dispatch_contracts::{
    SignedExecutionGrantV1 as RetainedDispatchGrantEnvelopeV1,
    SignedExecutionReceiptV1 as RetainedDispatchReceiptEnvelopeV1,
};
use helix_plan_dispatch::{
    classify_delivery_control_v1, DispatchCommitCandidateV1, DispatchCommitEvidenceV1,
    DispatchCommitPermitV1, DispatchCommitResolutionV1, DispatchDeliveryControlOutcomeV1,
    DispatchDeliveryControlPhaseV1, DispatchDeliveryControlSignalV1,
    DispatchStoreCommitClassificationV1,
};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt;

const CANONICAL_GRANT_MAX_BYTES_V1: usize = 1_048_576;

/// Store columns supplied by the already-verified final comparison and grant builder.
///
/// This type is crate-private, non-Serde, and redacted. It carries no transport or
/// signing capability; the candidate already owns the one exact signed envelope.
pub(crate) struct CoordinatorDispatchCommitBindingsV1 {
    pub(crate) preparation_attempt_id: [u8; 32],
    pub(crate) preparation_transition_generation: u64,
    pub(crate) plan_id: [u8; 32],
    pub(crate) task_id: String,
    pub(crate) workload_id: String,
    pub(crate) task_lease_digest: [u8; 32],
    pub(crate) reservation_id: String,
    pub(crate) boot_id: String,
    pub(crate) instance_epoch: u64,
    pub(crate) fencing_epoch: u64,
    pub(crate) one_shot_nonce: [u8; 32],
    pub(crate) preliminary_context_digest: [u8; 32],
    pub(crate) final_context_digest: [u8; 32],
    pub(crate) authority_vector_digest: [u8; 32],
    pub(crate) destination_binding_digest: [u8; 32],
    pub(crate) signer_profile_digest: [u8; 32],
    pub(crate) signer_key_id: String,
    pub(crate) signer_key_fingerprint: [u8; 32],
    pub(crate) destination_adapter_id: String,
    pub(crate) protocol_version: u8,
    pub(crate) sampled_utc_ms: u64,
    pub(crate) sampled_monotonic_ms: u64,
    pub(crate) issued_at_monotonic_ms: u64,
    pub(crate) effective_deadline_monotonic_ms: u64,
    pub(crate) event_id: [u8; 32],
    pub(crate) transition_evidence_digest: [u8; 32],
    pub(crate) latency_ms: u64,
    pub(crate) public_trace_id: String,
}

impl fmt::Debug for CoordinatorDispatchCommitBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDispatchCommitBindingsV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CoordinatorDispatchCommitReceiptV1 {
    pub(crate) operation_id: String,
    pub(crate) dispatch_attempt_id: [u8; 32],
    pub(crate) grant_id: [u8; 32],
    pub(crate) grant_digest: [u8; 32],
    pub(crate) one_shot_nonce: [u8; 32],
    pub(crate) transition_generation: u64,
    pub(crate) delivery_generation: u64,
    pub(crate) event_generation: u64,
}

impl fmt::Debug for CoordinatorDispatchCommitReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDispatchCommitReceiptV1")
            .finish_non_exhaustive()
    }
}

/// Exact keys and bytes transferred only after SQLite COMMIT returns ambiguously.
pub struct CoordinatorDispatchUncertainCommitCustodyV1 {
    pub(crate) operation_id: String,
    pub(crate) dispatch_attempt_id: [u8; 32],
    pub(crate) grant_id: [u8; 32],
    pub(crate) grant_digest: [u8; 32],
    pub(crate) one_shot_nonce: [u8; 32],
    pub(crate) canonical_grant: Box<[u8]>,
    pub(crate) canonical_grant_sha256: [u8; 32],
    pub(crate) event_id: [u8; 32],
    pub(crate) transition_generation: u64,
    pub(crate) delivery_generation: u64,
    pub(crate) event_generation: u64,
    pub(crate) deadline_monotonic_ms: u64,
}

impl DispatchCommitEvidenceV1 for CoordinatorDispatchCommitReceiptV1 {
    fn grant_id_v1(&self) -> [u8; 32] {
        self.grant_id
    }

    fn grant_digest_v1(&self) -> [u8; 32] {
        self.grant_digest
    }

    fn state_generation_v1(&self) -> u64 {
        self.transition_generation
    }
}

pub(crate) fn derive_dispatch_commit_bindings_v1<R>(
    candidate: &DispatchCommitCandidateV1<R>,
) -> CoordinatorDispatchCommitBindingsV1 {
    let projection = candidate.store_projection_v1();
    let mut event_preimage = Vec::with_capacity(160);
    event_preimage.extend_from_slice(b"HELIXOS\0DISPATCH-EVENT-ID\0V1\0");
    event_preimage.extend_from_slice(candidate.attempt_id().as_bytes());
    event_preimage.extend_from_slice(candidate.exact_grant().signed().grant_digest().as_bytes());
    let event_id: [u8; 32] = Sha256::digest(&event_preimage).into();

    let mut transition_preimage = Vec::with_capacity(160);
    transition_preimage.extend_from_slice(b"HELIXOS\0DISPATCH-TRANSITION-EVIDENCE\0V1\0");
    transition_preimage.extend_from_slice(candidate.attempt_id().as_bytes());
    transition_preimage.extend_from_slice(candidate.final_context_digest().as_bytes());
    transition_preimage
        .extend_from_slice(candidate.exact_grant().signed().grant_digest().as_bytes());
    let transition_evidence_digest: [u8; 32] = Sha256::digest(&transition_preimage).into();

    CoordinatorDispatchCommitBindingsV1 {
        preparation_attempt_id: projection.preparation_attempt_id(),
        preparation_transition_generation: projection.preparation_transition_generation(),
        plan_id: projection.plan_id(),
        task_id: projection.task_id().to_owned(),
        workload_id: projection.workload_id().to_owned(),
        task_lease_digest: projection.task_lease_digest(),
        reservation_id: projection.reservation_id().to_owned(),
        boot_id: projection.boot_id().to_owned(),
        instance_epoch: projection.instance_epoch(),
        fencing_epoch: projection.supervisor_epoch(),
        one_shot_nonce: projection.one_shot_nonce(),
        preliminary_context_digest: projection.preliminary_context_digest(),
        final_context_digest: projection.final_context_digest(),
        authority_vector_digest: projection.authority_vector_digest(),
        destination_binding_digest: projection.destination_binding_digest(),
        signer_profile_digest: projection.signer_profile_digest(),
        signer_key_id: projection.signer_key_id().to_owned(),
        signer_key_fingerprint: projection.signer_key_fingerprint(),
        destination_adapter_id: projection.destination_adapter_id().to_owned(),
        protocol_version: projection.protocol_version(),
        sampled_utc_ms: projection.sampled_utc_ms(),
        sampled_monotonic_ms: projection.sampled_monotonic_ms(),
        issued_at_monotonic_ms: projection.issued_at_monotonic_ms(),
        effective_deadline_monotonic_ms: projection.effective_deadline_monotonic_ms(),
        event_id,
        transition_evidence_digest,
        latency_ms: 0,
        public_trace_id: "dispatch-v1".to_owned(),
    }
}

impl fmt::Debug for CoordinatorDispatchUncertainCommitCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDispatchUncertainCommitCustodyV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct DispatchGenerationsV1 {
    store: u64,
    dispatch: u64,
    delivery: u64,
    event: u64,
}

struct StagedDispatchV1 {
    receipt: CoordinatorDispatchCommitReceiptV1,
    custody: CoordinatorDispatchUncertainCommitCustodyV1,
}

enum StageOutcomeV1 {
    Ready(Box<StagedDispatchV1>),
    PriorExact(Box<CoordinatorDispatchCommitReceiptV1>),
    Error(DispatchStageErrorV1),
}

#[derive(Clone, Copy)]
enum DispatchStageErrorV1 {
    ConfirmedRollback,
    Conflict,
    Unavailable,
    Unhealthy,
}

/// Coordinator custody selected by the portable T068 control classifier.
///
/// These are plans for the already-committed dispatch graph, not new state transitions.
/// T067 owns unknown/reconciliation persistence. Every variant explicitly retains the
/// exact grant and PLAN-004 hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoordinatorDispatchControlCustodyV1 {
    Pending,
    AuditBlockedPending,
    ReadbackRequired,
    AuditPendingUnknown,
}

/// Pure, non-authoritative projection used before any coordinator mutation is selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorDispatchControlDecisionV1 {
    portable: DispatchDeliveryControlOutcomeV1,
    custody: CoordinatorDispatchControlCustodyV1,
}

impl CoordinatorDispatchControlDecisionV1 {
    pub(crate) const fn portable_outcome_v1(self) -> DispatchDeliveryControlOutcomeV1 {
        self.portable
    }

    pub(crate) const fn custody_v1(self) -> CoordinatorDispatchControlCustodyV1 {
        self.custody
    }

    pub(crate) const fn blocks_new_delivery_v1(self) -> bool {
        self.portable.blocks_new_delivery()
    }

    pub(crate) const fn retains_committed_grant_v1(self) -> bool {
        self.portable.retains_committed_grant()
    }

    pub(crate) const fn retains_held_authority_v1(self) -> bool {
        self.portable.retains_held_authority()
    }

    pub(crate) const fn requires_readback_or_reconciliation_v1(self) -> bool {
        self.portable.requires_readback_or_reconciliation()
    }

    pub(crate) const fn audit_pending_v1(self) -> bool {
        self.portable.audit_pending()
    }

    pub(crate) const fn permits_evidence_deletion_v1(self) -> bool {
        self.portable.permits_evidence_deletion()
    }

    pub(crate) const fn permits_replacement_grant_v1(self) -> bool {
        self.portable.permits_replacement_grant()
    }

    pub(crate) const fn permits_held_authority_release_v1(self) -> bool {
        self.portable.permits_held_authority_release()
    }

    pub(crate) const fn claims_pre_dispatch_failure_v1(self) -> bool {
        self.portable.claims_pre_dispatch_failure()
    }
}

/// Maps portable delivery control into coordinator custody without touching SQLite.
///
/// Callers may use this decision to block a not-yet-handed-off delivery, enter exact
/// readback, or request T067 audit-pending/unknown custody. It cannot delete evidence,
/// mint a grant, release the reservation, or report that dispatch never committed.
pub(crate) fn classify_coordinator_dispatch_control_v1(
    phase: DispatchDeliveryControlPhaseV1,
    signal: DispatchDeliveryControlSignalV1,
) -> CoordinatorDispatchControlDecisionV1 {
    let portable = classify_delivery_control_v1(phase, signal);
    let custody = match portable {
        DispatchDeliveryControlOutcomeV1::PreventNewDeliveryRetainGrant => {
            CoordinatorDispatchControlCustodyV1::Pending
        }
        DispatchDeliveryControlOutcomeV1::PreventNewDeliveryAuditBlockedRetainGrant => {
            CoordinatorDispatchControlCustodyV1::AuditBlockedPending
        }
        DispatchDeliveryControlOutcomeV1::PreserveGrantAndRequireReadback => {
            CoordinatorDispatchControlCustodyV1::ReadbackRequired
        }
        DispatchDeliveryControlOutcomeV1::PreserveGrantAuditPendingUnknown => {
            CoordinatorDispatchControlCustodyV1::AuditPendingUnknown
        }
    };
    CoordinatorDispatchControlDecisionV1 { portable, custody }
}

/// Persists exactly seven members in one `BEGIN IMMEDIATE` transaction while the
/// non-cloneable supervisor permit owns the entire closure.
///
/// The closure performs no signature construction and no I/O beyond SQLite. A COMMIT
/// error is always conservatively handed to exact readback custody; a failure before
/// COMMIT is explicitly rolled back.
pub(crate) fn commit_dispatch_transaction_v1<R, P, V>(
    connection: &mut Connection,
    candidate: DispatchCommitCandidateV1<R>,
    bindings: CoordinatorDispatchCommitBindingsV1,
    permit: P,
    metrics: &DispatchMetricsV1,
    #[cfg(feature = "test-fault-injection")] fault_probe: &CoordinatorDispatchFaultProbeV1,
    mut verify_live_snapshot: V,
) -> DispatchCommitResolutionV1<
    CoordinatorDispatchCommitReceiptV1,
    CoordinatorDispatchUncertainCommitCustodyV1,
>
where
    P: DispatchCommitPermitV1,
    V: FnMut(&Connection) -> bool,
{
    if !candidate_and_bindings_are_exact_v1(&candidate, &bindings)
        || permit.deadline_monotonic_ms() > bindings.effective_deadline_monotonic_ms
    {
        permit.abandon_v1();
        metrics.observe_conflict_v1();
        return DispatchCommitResolutionV1::Conflict;
    }

    let resolution = permit.commit_once(|| {
        let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(error) => return map_begin_classification_v1(error),
        };
        #[cfg(feature = "test-fault-injection")]
        if dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb008) {
            return rollback_classification_v1(
                transaction,
                DispatchStoreCommitClassificationV1::ConfirmedRollback,
            );
        }
        if !verify_live_snapshot(&transaction) {
            return rollback_classification_v1(
                transaction,
                DispatchStoreCommitClassificationV1::Unhealthy,
            );
        }
        match stage_all_dispatch_members_v1(
            &transaction,
            &candidate,
            &bindings,
            #[cfg(feature = "test-fault-injection")]
            fault_probe,
        ) {
            StageOutcomeV1::PriorExact(receipt) => match transaction.rollback() {
                Ok(()) => DispatchStoreCommitClassificationV1::PriorExactDispatch(*receipt),
                Err(_) => DispatchStoreCommitClassificationV1::Unhealthy,
            },
            StageOutcomeV1::Error(DispatchStageErrorV1::ConfirmedRollback) => {
                rollback_classification_v1(
                    transaction,
                    DispatchStoreCommitClassificationV1::ConfirmedRollback,
                )
            }
            StageOutcomeV1::Error(DispatchStageErrorV1::Conflict) => rollback_classification_v1(
                transaction,
                DispatchStoreCommitClassificationV1::Conflict,
            ),
            StageOutcomeV1::Error(DispatchStageErrorV1::Unavailable) => rollback_classification_v1(
                transaction,
                DispatchStoreCommitClassificationV1::Unavailable,
            ),
            StageOutcomeV1::Error(DispatchStageErrorV1::Unhealthy) => rollback_classification_v1(
                transaction,
                DispatchStoreCommitClassificationV1::Unhealthy,
            ),
            StageOutcomeV1::Ready(staged) => {
                if !verify_live_snapshot(&transaction) {
                    return rollback_classification_v1(
                        transaction,
                        DispatchStoreCommitClassificationV1::ConfirmedRollback,
                    );
                }
                #[cfg(feature = "test-fault-injection")]
                if dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb016) {
                    return rollback_classification_v1(
                        transaction,
                        DispatchStoreCommitClassificationV1::ConfirmedRollback,
                    );
                }
                match transaction.commit() {
                    Ok(()) => {
                        #[cfg(feature = "test-fault-injection")]
                        if dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb017) {
                            return DispatchStoreCommitClassificationV1::Uncertain(staged.custody);
                        }
                        DispatchStoreCommitClassificationV1::Committed(staged.receipt)
                    }
                    Err(_) => DispatchStoreCommitClassificationV1::Uncertain(staged.custody),
                }
            }
        }
    });
    observe_resolution_v1(metrics, &resolution);
    resolution
}

fn stage_all_dispatch_members_v1<R>(
    transaction: &Transaction<'_>,
    candidate: &DispatchCommitCandidateV1<R>,
    bindings: &CoordinatorDispatchCommitBindingsV1,
    #[cfg(feature = "test-fault-injection")] fault_probe: &CoordinatorDispatchFaultProbeV1,
) -> StageOutcomeV1 {
    if let Some(outcome) = classify_existing_dispatch_v1(transaction, candidate, bindings) {
        return outcome;
    }
    if let Err(error) = verify_live_base_custody_v1(transaction, candidate, bindings) {
        return StageOutcomeV1::Error(error);
    }
    let generations = match allocate_dispatch_generations_v1(transaction) {
        Ok(generations) => generations,
        Err(error) => return StageOutcomeV1::Error(error),
    };
    let signed = candidate.exact_grant().signed();
    let protected = signed.protected();
    let attempt = candidate.attempt_id().as_bytes();
    let grant_id = protected.grant_id();
    let grant_digest = signed.grant_digest();
    let exact_bytes = candidate.exact_grant().exact_bytes();
    let dispatch_generation = match to_i64_v1(generations.dispatch) {
        Ok(value) => value,
        Err(error) => return StageOutcomeV1::Error(error),
    };
    let delivery_generation = match to_i64_v1(generations.delivery) {
        Ok(value) => value,
        Err(error) => return StageOutcomeV1::Error(error),
    };
    let event_generation = match to_i64_v1(generations.event) {
        Ok(value) => value,
        Err(error) => return StageOutcomeV1::Error(error),
    };

    let staged = (|| -> rusqlite::Result<()> {
        transaction.execute(
            "INSERT INTO dispatch_comparisons (\
                 dispatch_attempt_id, operation_id, operation_state_generation, \
                 preparation_attempt_id, preparation_transition_generation, preparation_state, \
                 preliminary_context_digest, final_context_digest, authority_vector_digest, \
                 destination_binding_digest, signer_profile_digest, sampled_utc_ms, \
                 sampled_monotonic_ms, effective_deadline_monotonic_ms, comparison_generation\
             ) VALUES (?1, ?2, ?3, ?4, ?3, 'PREPARING', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                attempt.as_slice(),
                candidate.operation_id(),
                to_i64_v1(bindings.preparation_transition_generation).map_err(sql_input_v1)?,
                bindings.preparation_attempt_id.as_slice(),
                bindings.preliminary_context_digest.as_slice(),
                bindings.final_context_digest.as_slice(),
                bindings.authority_vector_digest.as_slice(),
                bindings.destination_binding_digest.as_slice(),
                bindings.signer_profile_digest.as_slice(),
                to_i64_v1(bindings.sampled_utc_ms).map_err(sql_input_v1)?,
                to_i64_v1(bindings.sampled_monotonic_ms).map_err(sql_input_v1)?,
                to_i64_v1(bindings.effective_deadline_monotonic_ms).map_err(sql_input_v1)?,
                dispatch_generation,
            ],
        )?;
        #[cfg(feature = "test-fault-injection")]
        dispatch_fault_sql_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb009)?;
        transaction.execute(
            "INSERT INTO dispatch_grants (\
                 grant_id, dispatch_attempt_id, operation_id, preparation_attempt_id, \
                 preparation_transition_generation, plan_id, task_id, workload_id, \
                 task_lease_digest, reservation_id, one_shot_nonce, grant_digest, \
                 canonical_grant, canonical_grant_length, signer_key_id, \
                 signer_key_fingerprint, destination_adapter_id, protocol_version, \
                 issued_at_monotonic_ms, deadline_monotonic_ms, created_generation\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                       ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            params![
                grant_id.as_bytes().as_slice(),
                attempt.as_slice(),
                candidate.operation_id(),
                bindings.preparation_attempt_id.as_slice(),
                to_i64_v1(bindings.preparation_transition_generation).map_err(sql_input_v1)?,
                bindings.plan_id.as_slice(),
                bindings.task_id,
                bindings.workload_id,
                bindings.task_lease_digest.as_slice(),
                bindings.reservation_id,
                bindings.one_shot_nonce.as_slice(),
                grant_digest.as_bytes().as_slice(),
                exact_bytes,
                i64::try_from(exact_bytes.len())
                    .map_err(|_| sql_input_v1(DispatchStageErrorV1::Unhealthy))?,
                bindings.signer_key_id,
                bindings.signer_key_fingerprint.as_slice(),
                bindings.destination_adapter_id,
                i64::from(bindings.protocol_version),
                to_i64_v1(bindings.issued_at_monotonic_ms).map_err(sql_input_v1)?,
                to_i64_v1(bindings.effective_deadline_monotonic_ms).map_err(sql_input_v1)?,
                dispatch_generation,
            ],
        )?;
        #[cfg(feature = "test-fault-injection")]
        dispatch_fault_sql_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb010)?;
        transaction.execute(
            "INSERT INTO dispatch_records (\
                 operation_id, grant_id, dispatch_attempt_id, initial_delivery_generation, \
                 effective_state, state_generation, receipt_id, receipt_decision, \
                 reconciliation_id, reconciliation_result, current_event_id\
             ) VALUES (?1, ?2, ?3, ?4, 'DISPATCHING', ?5, NULL, NULL, NULL, NULL, ?6)",
            params![
                candidate.operation_id(),
                grant_id.as_bytes().as_slice(),
                attempt.as_slice(),
                delivery_generation,
                dispatch_generation,
                bindings.event_id.as_slice()
            ],
        )?;
        #[cfg(feature = "test-fault-injection")]
        dispatch_fault_sql_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb011)?;
        transaction.execute(
            "INSERT INTO dispatch_transitions (\
                 state_generation, previous_transition_generation, operation_id, grant_id, \
                 dispatch_attempt_id, previous_state, new_state, event_id, evidence_digest, \
                 receipt_id, receipt_decision, reconciliation_id, reconciliation_result, \
                 definite_refusal_guard_id\
             ) VALUES (?1, NULL, ?2, ?3, ?4, 'PREPARING', 'DISPATCHING', ?5, ?6, \
                       NULL, NULL, NULL, NULL, NULL)",
            params![
                dispatch_generation,
                candidate.operation_id(),
                grant_id.as_bytes().as_slice(),
                attempt.as_slice(),
                bindings.event_id.as_slice(),
                bindings.transition_evidence_digest.as_slice()
            ],
        )?;
        #[cfg(feature = "test-fault-injection")]
        dispatch_fault_sql_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb012)?;
        stage_pending_dispatch_outbox_v1(
            transaction,
            DispatchOutboxRowV1 {
                grant_id: grant_id.as_bytes(),
                operation_id: candidate.operation_id(),
                dispatch_attempt_id: attempt,
                initial_delivery_generation: delivery_generation,
                deadline_monotonic_ms: to_i64_v1(bindings.effective_deadline_monotonic_ms)
                    .map_err(sql_input_v1)?,
            },
        )?;
        #[cfg(feature = "test-fault-injection")]
        dispatch_fault_sql_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb013)?;
        stage_pending_dispatch_event_v1(
            transaction,
            DispatchEventRowV1 {
                event_id: &bindings.event_id,
                event_generation,
                transition_generation: dispatch_generation,
                operation_id: candidate.operation_id(),
                grant_id: grant_id.as_bytes(),
                dispatch_attempt_id: attempt,
                task_id: &bindings.task_id,
                workload_id: &bindings.workload_id,
                plan_id: &bindings.plan_id,
                task_lease_digest: &bindings.task_lease_digest,
                latency_ms: to_i64_v1(bindings.latency_ms).map_err(sql_input_v1)?,
                public_trace_id: &bindings.public_trace_id,
            },
        )?;
        #[cfg(feature = "test-fault-injection")]
        dispatch_fault_sql_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb014)?;
        stage_dispatch_store_meta_v1(transaction, generations).map_err(sql_input_v1)?;
        #[cfg(feature = "test-fault-injection")]
        dispatch_fault_sql_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb015)?;
        Ok(())
    })();
    if staged.is_err() {
        return StageOutcomeV1::Error(DispatchStageErrorV1::ConfirmedRollback);
    }
    if !foreign_keys_are_exact_v1(transaction) || !staged_graph_is_exact_v1(transaction, candidate)
    {
        return StageOutcomeV1::Error(DispatchStageErrorV1::ConfirmedRollback);
    }

    let receipt = CoordinatorDispatchCommitReceiptV1 {
        operation_id: candidate.operation_id().to_owned(),
        dispatch_attempt_id: *attempt,
        grant_id: *grant_id.as_bytes(),
        grant_digest: *grant_digest.as_bytes(),
        one_shot_nonce: bindings.one_shot_nonce,
        transition_generation: generations.dispatch,
        delivery_generation: generations.delivery,
        event_generation: generations.event,
    };
    let custody = CoordinatorDispatchUncertainCommitCustodyV1 {
        operation_id: receipt.operation_id.clone(),
        dispatch_attempt_id: receipt.dispatch_attempt_id,
        grant_id: receipt.grant_id,
        grant_digest: receipt.grant_digest,
        one_shot_nonce: receipt.one_shot_nonce,
        canonical_grant: exact_bytes.to_vec().into_boxed_slice(),
        canonical_grant_sha256: Sha256::digest(exact_bytes).into(),
        event_id: bindings.event_id,
        transition_generation: generations.dispatch,
        delivery_generation: generations.delivery,
        event_generation: generations.event,
        deadline_monotonic_ms: bindings.effective_deadline_monotonic_ms,
    };
    StageOutcomeV1::Ready(Box::new(StagedDispatchV1 { receipt, custody }))
}

#[cfg(feature = "test-fault-injection")]
pub(crate) fn dispatch_lookup_fault_injected_v1(
    fault_probe: &CoordinatorDispatchFaultProbeV1,
) -> bool {
    dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb001)
}

#[cfg(feature = "test-fault-injection")]
fn dispatch_fault_injected_v1(
    fault_probe: &CoordinatorDispatchFaultProbeV1,
    boundary: FaultBoundaryV1,
) -> bool {
    fault_probe.injected_at_v1(boundary)
}

#[cfg(feature = "test-fault-injection")]
fn dispatch_fault_sql_checkpoint_v1(
    fault_probe: &CoordinatorDispatchFaultProbeV1,
    boundary: FaultBoundaryV1,
) -> rusqlite::Result<()> {
    if dispatch_fault_injected_v1(fault_probe, boundary) {
        Err(rusqlite::Error::InvalidQuery)
    } else {
        Ok(())
    }
}

fn candidate_and_bindings_are_exact_v1<R>(
    candidate: &DispatchCommitCandidateV1<R>,
    bindings: &CoordinatorDispatchCommitBindingsV1,
) -> bool {
    let exact = candidate.exact_grant();
    let signed = exact.signed();
    let protected = signed.protected();
    let exact_identifier = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':')
            })
    };
    exact.to_canonical_json_is_exact_v1()
        && !exact.exact_bytes().is_empty()
        && exact.exact_bytes().len() <= CANONICAL_GRANT_MAX_BYTES_V1
        && candidate.final_context_digest().as_bytes() == &bindings.final_context_digest
        && protected.operation_id() == candidate.operation_id()
        && protected.grant_id() != candidate.attempt_id().digest()
        && protected.key_id() == bindings.signer_key_id
        && protected.destination_adapter_id() == bindings.destination_adapter_id
        && protected.protocol_version() == bindings.protocol_version
        && protected.boot_id() == bindings.boot_id
        && protected.deadline_monotonic_ms() == bindings.effective_deadline_monotonic_ms
        && canonical_protected_matches_bindings_v1(exact.exact_bytes(), candidate, bindings)
        && bindings.preparation_transition_generation > 0
        && bindings.preparation_transition_generation <= MAX_SAFE_U64
        && bindings.instance_epoch <= MAX_SAFE_U64
        && bindings.fencing_epoch <= MAX_SAFE_U64
        && bindings.sampled_utc_ms <= MAX_SAFE_U64
        && bindings.sampled_monotonic_ms < bindings.effective_deadline_monotonic_ms
        && bindings.issued_at_monotonic_ms == bindings.sampled_monotonic_ms
        && bindings.effective_deadline_monotonic_ms <= MAX_SAFE_U64
        && bindings.effective_deadline_monotonic_ms - bindings.sampled_monotonic_ms <= 5_000
        && bindings.latency_ms <= MAX_SAFE_U64
        && exact_identifier(&bindings.task_id)
        && exact_identifier(&bindings.workload_id)
        && exact_identifier(&bindings.reservation_id)
        && exact_identifier(&bindings.signer_key_id)
        && exact_identifier(&bindings.destination_adapter_id)
        && exact_identifier(&bindings.boot_id)
        && exact_identifier(&bindings.public_trace_id)
        && bindings.protocol_version == 1
}

fn canonical_protected_matches_bindings_v1<R>(
    canonical_grant: &[u8],
    candidate: &DispatchCommitCandidateV1<R>,
    bindings: &CoordinatorDispatchCommitBindingsV1,
) -> bool {
    let Ok(Value::Object(envelope)) = serde_json::from_slice::<Value>(canonical_grant) else {
        return false;
    };
    let Some(Value::Object(protected)) = envelope.get("protected") else {
        return false;
    };
    let signed = candidate.exact_grant().signed();
    json_digest_matches_v1(
        envelope.get("grant_digest"),
        signed.grant_digest().as_bytes(),
    ) && json_digest_matches_v1(
        protected.get("grant_id"),
        signed.protected().grant_id().as_bytes(),
    ) && json_digest_matches_v1(
        protected.get("dispatch_attempt_id"),
        candidate.attempt_id().as_bytes(),
    ) && json_digest_matches_v1(protected.get("one_shot_nonce"), &bindings.one_shot_nonce)
        && json_text_matches_v1(protected.get("operation_id"), candidate.operation_id())
        && json_u64_matches_v1(
            protected.get("operation_state_generation"),
            bindings.preparation_transition_generation,
        )
        && json_digest_matches_v1(
            protected.get("preparation_attempt_id"),
            &bindings.preparation_attempt_id,
        )
        && json_u64_matches_v1(
            protected.get("preparation_transition_generation"),
            bindings.preparation_transition_generation,
        )
        && json_digest_matches_v1(protected.get("plan_id"), &bindings.plan_id)
        && json_text_matches_v1(protected.get("task_id"), &bindings.task_id)
        && json_text_matches_v1(protected.get("workload_id"), &bindings.workload_id)
        && json_digest_matches_v1(protected.get("lease_digest"), &bindings.task_lease_digest)
        && json_text_matches_v1(protected.get("reservation_id"), &bindings.reservation_id)
        && json_text_matches_v1(protected.get("key_id"), &bindings.signer_key_id)
        && json_text_matches_v1(
            protected.get("destination_adapter_id"),
            &bindings.destination_adapter_id,
        )
        && json_u64_matches_v1(
            protected.get("protocol_version"),
            u64::from(bindings.protocol_version),
        )
        && json_text_matches_v1(protected.get("boot_id"), &bindings.boot_id)
        && json_u64_matches_v1(protected.get("instance_epoch"), bindings.instance_epoch)
        && json_u64_matches_v1(protected.get("issued_at_utc_ms"), bindings.sampled_utc_ms)
        && json_u64_matches_v1(
            protected.get("issued_at_monotonic_ms"),
            bindings.issued_at_monotonic_ms,
        )
        && json_u64_matches_v1(
            protected.get("deadline_monotonic_ms"),
            bindings.effective_deadline_monotonic_ms,
        )
}

fn json_text_matches_v1(value: Option<&Value>, expected: &str) -> bool {
    value.and_then(Value::as_str) == Some(expected)
}

fn json_u64_matches_v1(value: Option<&Value>, expected: u64) -> bool {
    value.and_then(Value::as_u64) == Some(expected)
}

fn json_digest_matches_v1(value: Option<&Value>, expected: &[u8; 32]) -> bool {
    let Some(text) = value.and_then(Value::as_str) else {
        return false;
    };
    if text.len() != 64 {
        return false;
    }
    text.as_bytes()
        .chunks_exact(2)
        .zip(expected)
        .all(|(pair, expected_byte)| {
            decode_hex_nibble_v1(pair[0])
                .zip(decode_hex_nibble_v1(pair[1]))
                .is_some_and(|(high, low)| (high << 4) | low == *expected_byte)
        })
}

fn decode_hex_nibble_v1(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

trait ExactCanonicalGrantCheckV1 {
    fn to_canonical_json_is_exact_v1(&self) -> bool;
}

impl ExactCanonicalGrantCheckV1 for helix_plan_dispatch::ExactSignedGrantV1 {
    fn to_canonical_json_is_exact_v1(&self) -> bool {
        self.signed()
            .to_canonical_json()
            .is_ok_and(|canonical| canonical.as_slice() == self.exact_bytes())
    }
}

fn verify_live_base_custody_v1<R>(
    transaction: &Transaction<'_>,
    candidate: &DispatchCommitCandidateV1<R>,
    bindings: &CoordinatorDispatchCommitBindingsV1,
) -> Result<(), DispatchStageErrorV1> {
    // The caller has just run the complete V2 snapshot verifier on this same private
    // connection inside this same BEGIN IMMEDIATE transaction. Re-reading four connection
    // PRAGMAs here cannot observe a different profile; the exact live custody join below and
    // the post-stage foreign-key/graph checks remain the mutation-specific proof.
    let exact: i64 = transaction
        .query_row(
            "SELECT COUNT(*) \
             FROM prepared_operations AS operation \
             JOIN operation_transitions AS transition \
               ON transition.operation_id = operation.operation_id \
              AND transition.state_generation = operation.state_generation \
              AND transition.event_id = operation.current_event_id \
              AND transition.new_state = operation.operation_state \
             JOIN preparation_events AS event \
               ON event.event_id = operation.current_event_id \
              AND event.operation_id = operation.operation_id \
              AND event.operation_state_generation = operation.state_generation \
             JOIN preparation_comparisons AS comparison \
               ON comparison.operation_id = operation.operation_id \
             JOIN budget_reservations AS reservation \
               ON reservation.reservation_id = operation.reservation_id \
              AND reservation.operation_id = operation.operation_id \
              AND reservation.attempt_id = operation.attempt_id \
             JOIN preparation_recovery_evidence AS recovery \
               ON recovery.operation_id = operation.operation_id \
             JOIN coordinator_store_meta AS base_meta ON base_meta.singleton = 1 \
             JOIN dispatch_store_meta AS dispatch_meta ON dispatch_meta.singleton = 1 \
             WHERE operation.operation_id = ?1 AND operation.attempt_id = ?2 \
               AND operation.plan_id = ?3 AND operation.task_id = ?4 \
               AND operation.workload_id = ?5 AND operation.reservation_id = ?6 \
               AND operation.operation_state = 'PREPARING' \
               AND operation.state_generation = ?7 \
               AND operation.failed_generation IS NULL \
               AND operation.failed_reason_code IS NULL \
               AND operation.boot_id = ?8 AND operation.instance_epoch = ?9 \
               AND operation.fencing_epoch = ?10 \
               AND operation.restored_source_generation IS NULL \
               AND operation.effective_deadline_monotonic_ms >= ?11 \
               AND transition.previous_state IS NULL \
               AND event.operation_state = 'PREPARING' AND event.event_kind = 'PREPARED' \
               AND reservation.plan_id = ?3 AND reservation.task_lease_digest = ?12 \
               AND reservation.reservation_state = 'HELD' \
               AND reservation.released_generation IS NULL \
               AND comparison.admission_state = 'OPEN' \
               AND ((recovery.recovery_mode = 'COMPENSATION' \
                     AND recovery.material_state = 'PUBLISHED' \
                     AND recovery.retirement_id IS NULL) \
                    OR (recovery.recovery_mode = 'IRREVERSIBLE' \
                        AND recovery.material_state IS NULL)) \
               AND base_meta.root_lifecycle_state = 'ACTIVE' \
               AND dispatch_meta.root_lifecycle_state = 'ACTIVE' \
               AND NOT EXISTS (SELECT 1 FROM preparation_quarantines AS quarantine \
                               WHERE quarantine.attempt_id = operation.attempt_id \
                                 AND quarantine.quarantine_status = 'ACTIVE')",
            params![
                candidate.operation_id(),
                bindings.preparation_attempt_id.as_slice(),
                bindings.plan_id.as_slice(),
                bindings.task_id,
                bindings.workload_id,
                bindings.reservation_id,
                to_i64_v1(bindings.preparation_transition_generation)
                    .map_err(|_| DispatchStageErrorV1::Unhealthy)?,
                bindings.boot_id,
                to_i64_v1(bindings.instance_epoch).map_err(|_| DispatchStageErrorV1::Unhealthy)?,
                to_i64_v1(bindings.fencing_epoch).map_err(|_| DispatchStageErrorV1::Unhealthy)?,
                to_i64_v1(bindings.effective_deadline_monotonic_ms)
                    .map_err(|_| DispatchStageErrorV1::Unhealthy)?,
                bindings.task_lease_digest.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(map_query_error_v1)?;
    if exact == 1 {
        Ok(())
    } else {
        Err(DispatchStageErrorV1::Conflict)
    }
}

fn classify_existing_dispatch_v1<R>(
    transaction: &Transaction<'_>,
    candidate: &DispatchCommitCandidateV1<R>,
    bindings: &CoordinatorDispatchCommitBindingsV1,
) -> Option<StageOutcomeV1> {
    let operation_occupied: bool = match transaction.query_row(
        "SELECT EXISTS (SELECT 1 FROM dispatch_records WHERE operation_id = ?1)",
        [candidate.operation_id()],
        |row| row.get(0),
    ) {
        Ok(value) => value,
        Err(error) => return Some(StageOutcomeV1::Error(map_query_error_v1(error))),
    };
    if operation_occupied {
        return Some(
            match load_prior_exact_receipt_v1(transaction, candidate.operation_id(), bindings) {
                Ok(Some(receipt)) => StageOutcomeV1::PriorExact(Box::new(receipt)),
                Ok(None) => StageOutcomeV1::Error(DispatchStageErrorV1::Unhealthy),
                Err(error) => StageOutcomeV1::Error(error),
            },
        );
    }
    let signed = candidate.exact_grant().signed();
    let occupied: bool = match transaction.query_row(
        "SELECT EXISTS (SELECT 1 FROM dispatch_grants \
                        WHERE grant_id = ?1 OR dispatch_attempt_id = ?2 \
                           OR one_shot_nonce = ?3 OR grant_digest = ?4)",
        params![
            signed.protected().grant_id().as_bytes().as_slice(),
            candidate.attempt_id().as_bytes().as_slice(),
            bindings.one_shot_nonce.as_slice(),
            signed.grant_digest().as_bytes().as_slice()
        ],
        |row| row.get(0),
    ) {
        Ok(value) => value,
        Err(error) => return Some(StageOutcomeV1::Error(map_query_error_v1(error))),
    };
    occupied.then_some(StageOutcomeV1::Error(DispatchStageErrorV1::Conflict))
}

fn load_prior_exact_receipt_v1(
    transaction: &Transaction<'_>,
    operation_id: &str,
    bindings: &CoordinatorDispatchCommitBindingsV1,
) -> Result<Option<CoordinatorDispatchCommitReceiptV1>, DispatchStageErrorV1> {
    let raw = transaction
        .query_row(
            "SELECT grant.dispatch_attempt_id, grant.grant_id, grant.grant_digest, \
                    grant.one_shot_nonce, transition.state_generation, \
                    outbox.initial_delivery_generation, event.event_generation \
             FROM dispatch_grants AS grant \
             JOIN dispatch_comparisons AS comparison \
               ON comparison.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND comparison.operation_id = grant.operation_id \
             JOIN dispatch_records AS record \
               ON record.operation_id = grant.operation_id \
              AND record.grant_id = grant.grant_id \
              AND record.dispatch_attempt_id = grant.dispatch_attempt_id \
             JOIN dispatch_transitions AS transition \
               ON transition.operation_id = grant.operation_id \
              AND transition.grant_id = grant.grant_id \
              AND transition.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND transition.previous_state = 'PREPARING' \
              AND transition.new_state = 'DISPATCHING' \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = grant.grant_id \
              AND outbox.operation_id = grant.operation_id \
              AND outbox.dispatch_attempt_id = grant.dispatch_attempt_id \
             JOIN dispatch_events AS event \
               ON event.event_id = transition.event_id \
              AND event.transition_generation = transition.state_generation \
              AND event.event_kind = 'DISPATCHED' \
             WHERE grant.operation_id = ?1 AND grant.preparation_attempt_id = ?2 \
               AND grant.preparation_transition_generation = ?3 \
               AND grant.plan_id = ?4 AND grant.task_id = ?5 AND grant.workload_id = ?6 \
               AND grant.task_lease_digest = ?7 AND grant.reservation_id = ?8 \
               AND grant.destination_adapter_id = ?9 AND grant.protocol_version = ?10",
            params![
                operation_id,
                bindings.preparation_attempt_id.as_slice(),
                to_i64_v1(bindings.preparation_transition_generation)
                    .map_err(|_| DispatchStageErrorV1::Unhealthy)?,
                bindings.plan_id.as_slice(),
                bindings.task_id,
                bindings.workload_id,
                bindings.task_lease_digest.as_slice(),
                bindings.reservation_id,
                bindings.destination_adapter_id,
                i64::from(bindings.protocol_version)
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(map_query_error_v1)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    Ok(Some(CoordinatorDispatchCommitReceiptV1 {
        operation_id: operation_id.to_owned(),
        dispatch_attempt_id: exact_array_v1(raw.0)?,
        grant_id: exact_array_v1(raw.1)?,
        grant_digest: exact_array_v1(raw.2)?,
        one_shot_nonce: exact_array_v1(raw.3)?,
        transition_generation: safe_u64_v1(raw.4)?,
        delivery_generation: safe_u64_v1(raw.5)?,
        event_generation: safe_u64_v1(raw.6)?,
    }))
}

fn allocate_dispatch_generations_v1(
    transaction: &Transaction<'_>,
) -> Result<DispatchGenerationsV1, DispatchStageErrorV1> {
    let current: (i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT dispatch_store_generation, dispatch_generation, delivery_generation, \
                    event_generation FROM dispatch_store_meta \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(map_query_error_v1)?;
    let store = next_safe_v1(safe_u64_v1(current.0)?)?;
    for axis in [current.1, current.2, current.3] {
        if safe_u64_v1(axis)? >= store {
            return Err(DispatchStageErrorV1::Unhealthy);
        }
    }
    Ok(DispatchGenerationsV1 {
        store,
        dispatch: store,
        delivery: store,
        event: store,
    })
}

fn stage_dispatch_store_meta_v1(
    transaction: &Transaction<'_>,
    generations: DispatchGenerationsV1,
) -> Result<(), DispatchStageErrorV1> {
    let updated = transaction
        .execute(
            "UPDATE dispatch_store_meta SET dispatch_store_generation = ?1, \
                    dispatch_generation = ?2, delivery_generation = ?3, event_generation = ?4 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND dispatch_store_generation = ?1 - 1 \
               AND dispatch_generation < ?2 AND delivery_generation < ?3 \
               AND event_generation < ?4",
            params![
                to_i64_v1(generations.store)?,
                to_i64_v1(generations.dispatch)?,
                to_i64_v1(generations.delivery)?,
                to_i64_v1(generations.event)?
            ],
        )
        .map_err(map_mutation_error_v1)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(DispatchStageErrorV1::Unhealthy)
    }
}

fn staged_graph_is_exact_v1<R>(
    transaction: &Transaction<'_>,
    candidate: &DispatchCommitCandidateV1<R>,
) -> bool {
    transaction
        .query_row(
            "SELECT CASE WHEN \
                 (SELECT COUNT(*) FROM dispatch_comparisons WHERE operation_id = ?1) = 1 \
             AND (SELECT COUNT(*) FROM dispatch_grants WHERE operation_id = ?1) = 1 \
             AND (SELECT COUNT(*) FROM dispatch_records WHERE operation_id = ?1) = 1 \
             AND (SELECT COUNT(*) FROM dispatch_transitions WHERE operation_id = ?1) = 1 \
             AND (SELECT COUNT(*) FROM dispatch_outbox WHERE operation_id = ?1) = 1 \
             AND (SELECT COUNT(*) FROM dispatch_events WHERE operation_id = ?1) = 1 \
             THEN 1 ELSE 0 END",
            [candidate.operation_id()],
            |row| row.get::<_, i64>(0),
        )
        .is_ok_and(|exact| exact == 1)
}

fn foreign_keys_are_exact_v1(transaction: &Transaction<'_>) -> bool {
    let mut statement = match transaction.prepare("PRAGMA foreign_key_check") {
        Ok(statement) => statement,
        Err(_) => return false,
    };
    statement
        .query([])
        .and_then(|mut rows| rows.next().map(|row| row.is_none()))
        .unwrap_or(false)
}

fn rollback_classification_v1<C, U>(
    transaction: Transaction<'_>,
    classification: DispatchStoreCommitClassificationV1<C, U>,
) -> DispatchStoreCommitClassificationV1<C, U> {
    if transaction.rollback().is_ok() {
        classification
    } else {
        DispatchStoreCommitClassificationV1::Unhealthy
    }
}

fn map_begin_classification_v1<C, U>(
    error: rusqlite::Error,
) -> DispatchStoreCommitClassificationV1<C, U> {
    match map_mutation_error_v1(error) {
        DispatchStageErrorV1::ConfirmedRollback => {
            DispatchStoreCommitClassificationV1::ConfirmedRollback
        }
        DispatchStageErrorV1::Unavailable => DispatchStoreCommitClassificationV1::Unavailable,
        DispatchStageErrorV1::Conflict => DispatchStoreCommitClassificationV1::Conflict,
        DispatchStageErrorV1::Unhealthy => DispatchStoreCommitClassificationV1::Unhealthy,
    }
}

fn map_mutation_error_v1(error: rusqlite::Error) -> DispatchStageErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            DispatchStageErrorV1::Unavailable
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::CannotOpen | ErrorCode::ReadOnly | ErrorCode::DiskFull
            ) =>
        {
            DispatchStageErrorV1::Unavailable
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
                && matches!(failure.extended_code, 1_555 | 2_067) =>
        {
            DispatchStageErrorV1::Conflict
        }
        _ => DispatchStageErrorV1::Unhealthy,
    }
}

fn map_query_error_v1(error: rusqlite::Error) -> DispatchStageErrorV1 {
    match map_mutation_error_v1(error) {
        DispatchStageErrorV1::Unavailable => DispatchStageErrorV1::Unavailable,
        DispatchStageErrorV1::ConfirmedRollback
        | DispatchStageErrorV1::Conflict
        | DispatchStageErrorV1::Unhealthy => DispatchStageErrorV1::Unhealthy,
    }
}

fn exact_array_v1(value: Vec<u8>) -> Result<[u8; 32], DispatchStageErrorV1> {
    value
        .try_into()
        .map_err(|_| DispatchStageErrorV1::Unhealthy)
}

fn safe_u64_v1(value: i64) -> Result<u64, DispatchStageErrorV1> {
    u64::try_from(value).map_err(|_| DispatchStageErrorV1::Unhealthy)
}

fn next_safe_v1(value: u64) -> Result<u64, DispatchStageErrorV1> {
    value
        .checked_add(1)
        .filter(|next| *next <= MAX_SAFE_U64)
        .ok_or(DispatchStageErrorV1::Unhealthy)
}

fn to_i64_v1(value: u64) -> Result<i64, DispatchStageErrorV1> {
    if value > MAX_SAFE_U64 {
        return Err(DispatchStageErrorV1::Unhealthy);
    }
    i64::try_from(value).map_err(|_| DispatchStageErrorV1::Unhealthy)
}

fn sql_input_v1(_: DispatchStageErrorV1) -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}

fn observe_resolution_v1<C, U>(
    metrics: &DispatchMetricsV1,
    resolution: &DispatchCommitResolutionV1<C, U>,
) {
    match resolution {
        DispatchCommitResolutionV1::Committed(_) => metrics.observe_committed_v1(),
        DispatchCommitResolutionV1::PriorExactDispatch(_) => metrics.observe_prior_exact_v1(),
        DispatchCommitResolutionV1::ConfirmedRollback => metrics.observe_confirmed_rollback_v1(),
        DispatchCommitResolutionV1::Uncertain(_) => metrics.observe_uncertain_v1(),
        DispatchCommitResolutionV1::Conflict => metrics.observe_conflict_v1(),
        DispatchCommitResolutionV1::Unavailable => metrics.observe_unavailable_v1(),
        DispatchCommitResolutionV1::Revoked
        | DispatchCommitResolutionV1::DeadlineReached
        | DispatchCommitResolutionV1::Ambiguous
        | DispatchCommitResolutionV1::Unclassified => metrics.observe_unhealthy_v1(),
    }
}

#[cfg(test)]
mod control_tests {
    use super::*;

    #[test]
    fn t068_coordinator_control_projection_is_exact_and_non_mutating() {
        let cases = [
            (
                DispatchDeliveryControlPhaseV1::BeforeHandoff,
                DispatchDeliveryControlSignalV1::CancellationRequested,
                CoordinatorDispatchControlCustodyV1::Pending,
            ),
            (
                DispatchDeliveryControlPhaseV1::BeforeHandoff,
                DispatchDeliveryControlSignalV1::PauseRequested,
                CoordinatorDispatchControlCustodyV1::Pending,
            ),
            (
                DispatchDeliveryControlPhaseV1::BeforeHandoff,
                DispatchDeliveryControlSignalV1::HaltRequested,
                CoordinatorDispatchControlCustodyV1::Pending,
            ),
            (
                DispatchDeliveryControlPhaseV1::BeforeHandoff,
                DispatchDeliveryControlSignalV1::AuditUnavailable,
                CoordinatorDispatchControlCustodyV1::AuditBlockedPending,
            ),
            (
                DispatchDeliveryControlPhaseV1::PossibleHandoff,
                DispatchDeliveryControlSignalV1::CancellationRequested,
                CoordinatorDispatchControlCustodyV1::ReadbackRequired,
            ),
            (
                DispatchDeliveryControlPhaseV1::PossibleHandoff,
                DispatchDeliveryControlSignalV1::PauseRequested,
                CoordinatorDispatchControlCustodyV1::ReadbackRequired,
            ),
            (
                DispatchDeliveryControlPhaseV1::PossibleHandoff,
                DispatchDeliveryControlSignalV1::HaltRequested,
                CoordinatorDispatchControlCustodyV1::ReadbackRequired,
            ),
            (
                DispatchDeliveryControlPhaseV1::PossibleHandoff,
                DispatchDeliveryControlSignalV1::AuditUnavailable,
                CoordinatorDispatchControlCustodyV1::AuditPendingUnknown,
            ),
        ];

        for (phase, signal, expected_custody) in cases {
            let decision = classify_coordinator_dispatch_control_v1(phase, signal);
            assert_eq!(decision.custody_v1(), expected_custody);
            assert_eq!(
                decision.portable_outcome_v1(),
                classify_delivery_control_v1(phase, signal)
            );
            assert!(decision.blocks_new_delivery_v1());
            assert!(decision.retains_committed_grant_v1());
            assert!(decision.retains_held_authority_v1());
            assert_eq!(
                decision.requires_readback_or_reconciliation_v1(),
                phase == DispatchDeliveryControlPhaseV1::PossibleHandoff
            );
            assert_eq!(
                decision.audit_pending_v1(),
                phase == DispatchDeliveryControlPhaseV1::PossibleHandoff
                    && signal == DispatchDeliveryControlSignalV1::AuditUnavailable
            );
            assert!(!decision.permits_evidence_deletion_v1());
            assert!(!decision.permits_replacement_grant_v1());
            assert!(!decision.permits_held_authority_release_v1());
            assert!(!decision.claims_pre_dispatch_failure_v1());
        }
    }
}
