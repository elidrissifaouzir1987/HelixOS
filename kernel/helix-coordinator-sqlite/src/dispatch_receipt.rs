//! Strict coordinator receipt verification and durable state advance.
//!
//! This boundary accepts only lookup keys plus exact signed receipt bytes. It reloads the
//! retained grant, verifies both signed envelopes through `helix-dispatch-contracts`, and then
//! rechecks the complete current projection under one immediate SQLite writer transaction.

#[cfg(feature = "test-fault-injection")]
use crate::dispatch_fault::{CoordinatorDispatchFaultProbeV1, FaultBoundaryV1};

use helix_dispatch_contracts::{
    decode_and_verify_execution_receipt_v1, decode_and_verify_retained_execution_grant_v1,
    AuthenticExecutionReceiptV1, ExecutionReceiptDecisionV1, GrantKeyResolver, ReceiptKeyResolver,
    ReceiptVerificationBindingsV1, Sha256Digest,
};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::{Digest as _, Sha256};
use std::fmt;

const COORDINATOR_APPLICATION_ID_V1: i64 = 1_212_962_883;
const COORDINATOR_DISPATCH_SCHEMA_VERSION_V2: i64 = 2;
const MAX_SAFE_U64_V1: u64 = 9_007_199_254_740_991;
const MAX_RECEIPT_BYTES_V1: usize = 65_536;

/// Lookup-only input for one coordinator receipt observation.
///
/// The adapter root identifier must come from the trusted acknowledged-handoff/readback boundary
/// and match the independently verified signed receipt. This value carries no receipt authenticity
/// and no authority to advance state by itself.
pub struct CoordinatorReceiptLookupV1 {
    operation_id: Box<str>,
    grant_id: [u8; 32],
    adapter_root_id: [u8; 32],
}

impl CoordinatorReceiptLookupV1 {
    pub fn try_new(
        operation_id: String,
        grant_id: [u8; 32],
        adapter_root_id: [u8; 32],
    ) -> Result<Self, CoordinatorReceiptLookupErrorV1> {
        if adapter_root_id == [0; 32]
            || operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._:".contains(&byte))
        {
            return Err(CoordinatorReceiptLookupErrorV1::InvalidLookup);
        }
        Ok(Self {
            operation_id: operation_id.into_boxed_str(),
            grant_id,
            adapter_root_id,
        })
    }
}

impl fmt::Debug for CoordinatorReceiptLookupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReceiptLookupV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorReceiptLookupErrorV1 {
    InvalidLookup,
}

/// Opaque durable evidence returned only after SQLite reports a successful commit.
#[derive(Clone, PartialEq, Eq)]
pub struct CoordinatorReceiptCommitEvidenceV1 {
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
    effective_state: CoordinatorReceiptEffectiveStateV1,
    state_generation: u64,
    delivery_generation: u64,
    receipt_generation: u64,
    reconciliation_generation: Option<u64>,
    event_generation: u64,
}

impl CoordinatorReceiptCommitEvidenceV1 {
    pub const fn effective_state(&self) -> CoordinatorReceiptEffectiveStateV1 {
        self.effective_state
    }

    pub const fn state_generation(&self) -> u64 {
        self.state_generation
    }
}

impl fmt::Debug for CoordinatorReceiptCommitEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReceiptCommitEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Exact custody retained when SQLite COMMIT does not provide a definite answer.
pub struct CoordinatorReceiptUncertainCustodyV1 {
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
    canonical_receipt: Box<[u8]>,
    canonical_receipt_sha256: [u8; 32],
    intended_state: CoordinatorReceiptEffectiveStateV1,
}

impl fmt::Debug for CoordinatorReceiptUncertainCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReceiptUncertainCustodyV1")
            .finish_non_exhaustive()
    }
}

impl CoordinatorReceiptUncertainCustodyV1 {
    /// Digest-only identity of the receipt retained for exact readback.
    pub const fn receipt_id(&self) -> [u8; 32] {
        self.receipt_id
    }

    /// Signed-claims digest retained for exact readback.
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    /// Independent digest of the exact canonical bytes held in custody.
    pub const fn canonical_receipt_sha256(&self) -> [u8; 32] {
        self.canonical_receipt_sha256
    }

    /// Intended durable state; this is evidence only and grants no commit authority.
    pub const fn intended_state(&self) -> CoordinatorReceiptEffectiveStateV1 {
        self.intended_state
    }

    /// Length of the retained canonical bytes without exposing their signed contents.
    pub fn canonical_receipt_len(&self) -> usize {
        self.canonical_receipt.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorReceiptEffectiveStateV1 {
    Executing,
    ReconciliationRequired,
}

/// Closed result of one exact receipt observation.
pub enum CoordinatorReceiptCommitOutcomeV1 {
    Committed(CoordinatorReceiptCommitEvidenceV1),
    PriorExact(CoordinatorReceiptCommitEvidenceV1),
    Uncertain(CoordinatorReceiptUncertainCustodyV1),
    RejectedNoAdvance,
    Conflict,
    Unavailable,
    Unhealthy,
}

impl fmt::Debug for CoordinatorReceiptCommitOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "CoordinatorReceiptCommitOutcomeV1::Committed(..)",
            Self::PriorExact(_) => "CoordinatorReceiptCommitOutcomeV1::PriorExact(..)",
            Self::Uncertain(_) => "CoordinatorReceiptCommitOutcomeV1::Uncertain(..)",
            Self::RejectedNoAdvance => "CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance",
            Self::Conflict => "CoordinatorReceiptCommitOutcomeV1::Conflict",
            Self::Unavailable => "CoordinatorReceiptCommitOutcomeV1::Unavailable",
            Self::Unhealthy => "CoordinatorReceiptCommitOutcomeV1::Unhealthy",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableStateV1 {
    Dispatching,
    Executing,
    OutcomeUnknown,
    ReconciliationRequired,
}

impl DurableStateV1 {
    fn decode(value: &str) -> Option<Self> {
        match value {
            "DISPATCHING" => Some(Self::Dispatching),
            "EXECUTING" => Some(Self::Executing),
            "OUTCOME_UNKNOWN" => Some(Self::OutcomeUnknown),
            "RECONCILIATION_REQUIRED" => Some(Self::ReconciliationRequired),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CurrentReceiptContextV1 {
    state: DurableStateV1,
    state_generation: u64,
    current_event_id: [u8; 32],
    dispatch_attempt_id: [u8; 32],
    grant_digest: [u8; 32],
    canonical_grant: Box<[u8]>,
    task_id: String,
    workload_id: String,
    plan_id: [u8; 32],
    task_lease_digest: [u8; 32],
    destination_adapter_id: String,
    protocol_version: u8,
    delivery_state: String,
    delivery_generation: u64,
    current_attempt_generation: Option<u64>,
    current_attempt_number: u64,
    current_handoff_guard_digest: [u8; 32],
    current_attempt_classification: String,
    adapter_root_id: Option<[u8; 32]>,
    adapter_epoch: Option<u64>,
    readback_generation: Option<u64>,
    reconciliation_id: Option<[u8; 32]>,
    reconciliation_result: Option<String>,
    transport_quiescence_digest: Option<[u8; 32]>,
}

struct VerifiedReceiptCandidateV1 {
    canonical_receipt: Box<[u8]>,
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
    adapter_key_fingerprint: [u8; 32],
    adapter_root_id: [u8; 32],
    adapter_epoch: u64,
    trace_id: Box<str>,
}

impl VerifiedReceiptCandidateV1 {
    fn from_authentic(authentic: &AuthenticExecutionReceiptV1, exact_bytes: &[u8]) -> Option<Self> {
        let claims = authentic.claims();
        if claims.decision() != ExecutionReceiptDecisionV1::Consumed
            || claims.refusal_code().is_some()
            || claims.no_consumption_tombstone_digest().is_some()
            || exact_bytes.is_empty()
            || exact_bytes.len() > MAX_RECEIPT_BYTES_V1
            || authentic.canonical_signed_envelope_bytes().ok()?.as_slice() != exact_bytes
        {
            return None;
        }
        Some(Self {
            canonical_receipt: exact_bytes.to_vec().into_boxed_slice(),
            receipt_id: *claims.receipt_id().as_bytes(),
            receipt_digest: *claims.receipt_digest().as_bytes(),
            adapter_key_fingerprint: *authentic.verified_key_fingerprint().as_bytes(),
            adapter_root_id: *claims.adapter_root_id().as_bytes(),
            adapter_epoch: claims.observed_supervisor_epoch(),
            trace_id: Box::from(claims.trace_id()),
        })
    }
}

#[derive(Clone, Copy)]
struct ReceiptGenerationsV1 {
    store: u64,
    state: u64,
    delivery: u64,
    receipt: u64,
    reconciliation: Option<u64>,
    reconciliation_high_water: u64,
    event: u64,
}

struct DerivedReceiptIdsV1 {
    event_id: [u8; 32],
    evidence_digest: [u8; 32],
    reconciliation_id: Option<[u8; 32]>,
}

#[derive(Clone, Copy)]
struct LateReceiptGenerationsV1 {
    previous_store: u64,
    previous_dispatch: u64,
    previous_delivery: u64,
    previous_receipt: u64,
    previous_reconciliation: u64,
    previous_event: u64,
    store: u64,
    receipt: u64,
    reconciliation: u64,
}

#[derive(Clone, Copy)]
enum ReceiptStageErrorV1 {
    Conflict,
    Unavailable,
    Unhealthy,
}

/// Transaction helper for one root-bound `SqliteCoordinatorStoreV2` receipt observation.
pub(crate) fn commit_execution_receipt_v1<K, F>(
    connection: &mut Connection,
    lookup: CoordinatorReceiptLookupV1,
    canonical_receipt: &[u8],
    key_resolver: &K,
    #[cfg(feature = "test-fault-injection")] fault_probe: &CoordinatorDispatchFaultProbeV1,
    mut verify_live_snapshot: F,
) -> CoordinatorReceiptCommitOutcomeV1
where
    K: GrantKeyResolver + ReceiptKeyResolver,
    F: FnMut(&Connection) -> bool,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return outcome_from_error_v1(map_sql_error_v1(error)),
    };
    #[cfg(feature = "test-fault-injection")]
    if receipt_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb044) {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Unavailable);
    }
    if !verify_live_snapshot(&transaction) {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Unhealthy);
    }
    let context = match load_current_receipt_context_v1(&transaction, &lookup) {
        Ok(Some(context)) => context,
        Ok(None) => {
            return rollback_outcome_v1(
                transaction,
                CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance,
            )
        }
        Err(error) => return rollback_outcome_v1(transaction, outcome_from_error_v1(error)),
    };
    let candidate =
        match verify_exact_receipt_v1(&context, &lookup, canonical_receipt, key_resolver) {
            Some(candidate) => candidate,
            None => {
                return rollback_outcome_v1(
                    transaction,
                    CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance,
                )
            }
        };
    let target = match target_state_v1(context.state, ExecutionReceiptDecisionV1::Consumed) {
        Some(target) => target,
        None => {
            let outcome = classify_prior_exact_without_advance_v1(
                &transaction,
                &lookup,
                &candidate,
                &context,
            );
            return rollback_outcome_v1(transaction, outcome);
        }
    };
    if !receipt_delivery_context_is_exact_v1(&context, &candidate)
        || (target == CoordinatorReceiptEffectiveStateV1::ReconciliationRequired
            && (context.reconciliation_id.is_none()
                || context.reconciliation_result.as_deref() != Some("OUTCOME_UNKNOWN")
                || context.transport_quiescence_digest.is_none()))
    {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Conflict);
    }
    if readback_bound_context_is_exact_v1(&context, &candidate) {
        match readback_attempt_history_is_exact_v1(&transaction, &lookup, &context, &candidate) {
            Ok(true) => {}
            Ok(false) => {
                return rollback_outcome_v1(
                    transaction,
                    CoordinatorReceiptCommitOutcomeV1::Conflict,
                )
            }
            Err(error) => return rollback_outcome_v1(transaction, outcome_from_error_v1(error)),
        }
    }
    let staged = stage_receipt_advance_v1(
        &transaction,
        &lookup,
        &context,
        &candidate,
        target,
        #[cfg(feature = "test-fault-injection")]
        fault_probe,
    );
    let evidence = match staged {
        Ok(evidence) => evidence,
        Err(error) => {
            return if transaction.rollback().is_ok() {
                outcome_from_error_v1(error)
            } else {
                CoordinatorReceiptCommitOutcomeV1::Unhealthy
            }
        }
    };
    let transaction =
        match retain_post_stage_verified_transaction_v1(transaction, &mut verify_live_snapshot) {
            Ok(transaction) => transaction,
            Err(error) => return outcome_from_error_v1(error),
        };
    let custody = CoordinatorReceiptUncertainCustodyV1 {
        receipt_id: candidate.receipt_id,
        receipt_digest: candidate.receipt_digest,
        canonical_receipt_sha256: Sha256::digest(&candidate.canonical_receipt).into(),
        canonical_receipt: candidate.canonical_receipt,
        intended_state: target,
    };
    #[cfg(feature = "test-fault-injection")]
    if receipt_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb051) {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Unavailable);
    }
    match transaction.commit() {
        Ok(()) => {
            #[cfg(feature = "test-fault-injection")]
            if receipt_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb052) {
                return CoordinatorReceiptCommitOutcomeV1::Uncertain(custody);
            }
            CoordinatorReceiptCommitOutcomeV1::Committed(evidence)
        }
        Err(_) => CoordinatorReceiptCommitOutcomeV1::Uncertain(custody),
    }
}

/// Retains the staged writer only while the complete root snapshot still verifies.
///
/// A rejected post-stage snapshot consumes and explicitly rolls back the transaction, so no
/// receipt member can survive to the FB051/COMMIT boundary.
fn retain_post_stage_verified_transaction_v1<'connection, F>(
    transaction: Transaction<'connection>,
    verify_live_snapshot: &mut F,
) -> Result<Transaction<'connection>, ReceiptStageErrorV1>
where
    F: FnMut(&Connection) -> bool,
{
    if verify_live_snapshot(&transaction) {
        Ok(transaction)
    } else {
        let _ = transaction.rollback();
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

/// Retains a newly recovered consumed receipt after unknown custody became explicit.
///
/// This transaction deliberately leaves the current `RECONCILIATION_REQUIRED` projection,
/// outbox and event unchanged. The signed receipt and a `CONSUMED` reconciliation row are
/// permanent evidence only; PLAN-005 never returns a post-unknown operation to `EXECUTING`.
#[allow(dead_code)] // Wired by the T067 reconciliation facade in the same implementation stage.
pub(crate) fn commit_late_reconciliation_consumed_receipt_v1<K, F>(
    connection: &mut Connection,
    lookup: CoordinatorReceiptLookupV1,
    canonical_receipt: &[u8],
    key_resolver: &K,
    #[cfg(feature = "test-fault-injection")] fault_probe: &CoordinatorDispatchFaultProbeV1,
    mut verify_live_snapshot: F,
) -> CoordinatorReceiptCommitOutcomeV1
where
    K: GrantKeyResolver + ReceiptKeyResolver,
    F: FnMut(&Connection) -> bool,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return outcome_from_error_v1(map_sql_error_v1(error)),
    };
    #[cfg(feature = "test-fault-injection")]
    if receipt_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb044) {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Unavailable);
    }
    if sqlite_profile_is_exact_v1(&transaction).is_err() || !verify_live_snapshot(&transaction) {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Unhealthy);
    }
    let context = match load_current_receipt_context_v1(&transaction, &lookup) {
        Ok(Some(context)) => context,
        Ok(None) => {
            return rollback_outcome_v1(
                transaction,
                CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance,
            )
        }
        Err(error) => return rollback_outcome_v1(transaction, outcome_from_error_v1(error)),
    };
    let candidate =
        match verify_exact_receipt_v1(&context, &lookup, canonical_receipt, key_resolver) {
            Some(candidate) => candidate,
            None => {
                return rollback_outcome_v1(
                    transaction,
                    CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance,
                )
            }
        };
    if context.state != DurableStateV1::ReconciliationRequired
        || !readback_bound_context_is_exact_v1(&context, &candidate)
        || context.reconciliation_id.is_none()
        || context.reconciliation_result.as_deref() != Some("OUTCOME_UNKNOWN")
        || context.transport_quiescence_digest.is_none()
    {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Conflict);
    }
    match readback_attempt_history_is_exact_v1(&transaction, &lookup, &context, &candidate) {
        Ok(true) => {}
        Ok(false) => {
            return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Conflict)
        }
        Err(error) => return rollback_outcome_v1(transaction, outcome_from_error_v1(error)),
    }
    let ids = derive_receipt_ids_v1(
        &candidate,
        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired,
    );
    match load_late_consumed_evidence_v1(&transaction, &lookup, &context, &candidate, &ids) {
        Ok(Some(evidence)) => {
            return rollback_outcome_v1(
                transaction,
                CoordinatorReceiptCommitOutcomeV1::PriorExact(evidence),
            )
        }
        Ok(None) => {}
        Err(error) => return rollback_outcome_v1(transaction, outcome_from_error_v1(error)),
    }
    let generations = match allocate_late_receipt_generations_v1(&transaction) {
        Ok(generations) => generations,
        Err(error) => return rollback_outcome_v1(transaction, outcome_from_error_v1(error)),
    };
    if let Err(error) = insert_receipt_v1(
        &transaction,
        &lookup,
        &context,
        &candidate,
        generations.receipt,
    ) {
        return rollback_outcome_v1(transaction, outcome_from_error_v1(error));
    }
    #[cfg(feature = "test-fault-injection")]
    if let Err(error) = receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb045) {
        return rollback_outcome_v1(transaction, outcome_from_error_v1(error));
    }
    if let Err(error) = insert_late_consumed_reconciliation_v1(
        &transaction,
        &lookup,
        &context,
        &candidate,
        &ids,
        generations.reconciliation,
    ) {
        return rollback_outcome_v1(transaction, outcome_from_error_v1(error));
    }
    if let Err(error) = update_late_receipt_metadata_v1(&transaction, generations) {
        return rollback_outcome_v1(transaction, outcome_from_error_v1(error));
    }
    #[cfg(feature = "test-fault-injection")]
    if let Err(error) = receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb050) {
        return rollback_outcome_v1(transaction, outcome_from_error_v1(error));
    }
    let evidence =
        match load_late_consumed_evidence_v1(&transaction, &lookup, &context, &candidate, &ids) {
            Ok(Some(evidence))
                if evidence.state_generation == context.state_generation
                    && evidence.delivery_generation == context.delivery_generation
                    && evidence.receipt_generation == generations.receipt
                    && evidence.reconciliation_generation == Some(generations.reconciliation) =>
            {
                evidence
            }
            _ => {
                return rollback_outcome_v1(
                    transaction,
                    CoordinatorReceiptCommitOutcomeV1::Unhealthy,
                )
            }
        };
    if foreign_key_check_has_rows_v1(&transaction).unwrap_or(true)
        || !verify_live_snapshot(&transaction)
    {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Unhealthy);
    }
    let custody = CoordinatorReceiptUncertainCustodyV1 {
        receipt_id: candidate.receipt_id,
        receipt_digest: candidate.receipt_digest,
        canonical_receipt_sha256: Sha256::digest(&candidate.canonical_receipt).into(),
        canonical_receipt: candidate.canonical_receipt,
        intended_state: CoordinatorReceiptEffectiveStateV1::ReconciliationRequired,
    };
    #[cfg(feature = "test-fault-injection")]
    if receipt_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb051) {
        return rollback_outcome_v1(transaction, CoordinatorReceiptCommitOutcomeV1::Unavailable);
    }
    match transaction.commit() {
        Ok(()) => {
            #[cfg(feature = "test-fault-injection")]
            if receipt_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb052) {
                return CoordinatorReceiptCommitOutcomeV1::Uncertain(custody);
            }
            CoordinatorReceiptCommitOutcomeV1::Committed(evidence)
        }
        Err(_) => CoordinatorReceiptCommitOutcomeV1::Uncertain(custody),
    }
}

fn rollback_outcome_v1(
    transaction: Transaction<'_>,
    outcome: CoordinatorReceiptCommitOutcomeV1,
) -> CoordinatorReceiptCommitOutcomeV1 {
    if transaction.rollback().is_ok() {
        outcome
    } else {
        CoordinatorReceiptCommitOutcomeV1::Unhealthy
    }
}

fn verify_exact_receipt_v1<K>(
    context: &CurrentReceiptContextV1,
    lookup: &CoordinatorReceiptLookupV1,
    canonical_receipt: &[u8],
    key_resolver: &K,
) -> Option<VerifiedReceiptCandidateV1>
where
    K: GrantKeyResolver + ReceiptKeyResolver,
{
    let retained_grant =
        decode_and_verify_retained_execution_grant_v1(&context.canonical_grant, key_resolver)
            .ok()?;
    let grant_claims = retained_grant.claims();
    if grant_claims.grant_id().as_bytes() != &lookup.grant_id
        || grant_claims.grant_digest().as_bytes() != &context.grant_digest
        || grant_claims.operation_id() != &*lookup.operation_id
        || grant_claims.destination_adapter_id() != context.destination_adapter_id
        || grant_claims.protocol_version() != context.protocol_version
        || retained_grant
            .canonical_signed_envelope_bytes()
            .ok()?
            .as_slice()
            != &*context.canonical_grant
    {
        return None;
    }
    let bindings = ReceiptVerificationBindingsV1::from_retained_grant_evidence(
        &retained_grant,
        Sha256Digest::from_bytes(lookup.adapter_root_id),
    );
    let authentic =
        decode_and_verify_execution_receipt_v1(canonical_receipt, key_resolver, &bindings).ok()?;
    let claims = authentic.claims();
    if claims.grant_id().as_bytes() != &lookup.grant_id
        || claims.grant_digest().as_bytes() != &context.grant_digest
        || claims.operation_id() != &*lookup.operation_id
        || claims.adapter_root_id().as_bytes() != &lookup.adapter_root_id
        || context
            .adapter_root_id
            .is_some_and(|retained| retained != lookup.adapter_root_id)
        || context
            .adapter_epoch
            .is_some_and(|retained| retained != claims.observed_supervisor_epoch())
    {
        return None;
    }
    VerifiedReceiptCandidateV1::from_authentic(&authentic, canonical_receipt)
}

fn receipt_delivery_context_is_exact_v1(
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
) -> bool {
    direct_acknowledged_source_is_exact_v1(context)
        || readback_bound_context_is_exact_v1(context, candidate)
}

fn direct_acknowledged_source_is_exact_v1(context: &CurrentReceiptContextV1) -> bool {
    context.state == DurableStateV1::Dispatching
        && context.delivery_state == "HANDED_OFF"
        && context.current_attempt_generation == Some(context.delivery_generation)
        && context.current_attempt_number == 1
        && context.current_attempt_classification == "POSSIBLE_HANDOFF"
        && context.adapter_root_id.is_none()
        && context.adapter_epoch.is_none()
        && context.readback_generation.is_none()
        && context.reconciliation_id.is_none()
        && context.reconciliation_result.is_none()
        && context.transport_quiescence_digest.is_none()
}

fn readback_bound_context_is_exact_v1(
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
) -> bool {
    let Some(attempt_generation) = context.current_attempt_generation else {
        return false;
    };
    context.delivery_state == "UNKNOWN"
        && attempt_generation == context.delivery_generation
        && context.current_attempt_number == 2
        && context.current_attempt_classification == "POSSIBLE_HANDOFF"
        && context.adapter_root_id == Some(candidate.adapter_root_id)
        && context.adapter_epoch == Some(candidate.adapter_epoch)
        && context
            .readback_generation
            .is_some_and(|source| source < attempt_generation)
}

fn readback_attempt_history_is_exact_v1(
    connection: &Connection,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
) -> Result<bool, ReceiptStageErrorV1> {
    if context.current_attempt_classification != "POSSIBLE_HANDOFF"
        || context.adapter_root_id != Some(candidate.adapter_root_id)
        || context.adapter_epoch != Some(candidate.adapter_epoch)
    {
        return Ok(false);
    }
    let claim_generation = context
        .current_attempt_generation
        .ok_or(ReceiptStageErrorV1::Conflict)?;
    let source_generation = context
        .readback_generation
        .ok_or(ReceiptStageErrorV1::Conflict)?;
    if source_generation >= claim_generation {
        return Ok(false);
    }
    let source_attempt_number = context
        .current_attempt_number
        .checked_sub(1)
        .filter(|number| *number > 0)
        .ok_or(ReceiptStageErrorV1::Conflict)?;
    let exact: i64 = connection
        .query_row(
            "SELECT CASE WHEN \
                 (SELECT COUNT(*) FROM dispatch_delivery_attempts \
                    WHERE grant_id = ?1 AND operation_id = ?2 \
                      AND dispatch_attempt_id = ?3) = 2 \
             AND EXISTS (SELECT 1 FROM dispatch_delivery_attempts \
                    WHERE grant_id = ?1 AND operation_id = ?2 \
                      AND dispatch_attempt_id = ?3 AND attempt_generation = ?4 \
                      AND attempt_number = ?5 AND classification = 'POSSIBLE_HANDOFF' \
                      AND adapter_root_digest IS NULL AND adapter_epoch IS NULL \
                      AND readback_generation IS NULL) \
             AND EXISTS (SELECT 1 FROM dispatch_delivery_attempts \
                    WHERE grant_id = ?1 AND operation_id = ?2 \
                      AND dispatch_attempt_id = ?3 AND attempt_generation = ?6 \
                      AND attempt_number = ?7 AND handoff_guard_digest = ?8 \
                      AND classification = 'POSSIBLE_HANDOFF' \
                      AND adapter_root_digest = ?9 AND adapter_epoch = ?10 \
                      AND readback_generation = ?4) \
             THEN 1 ELSE 0 END",
            params![
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(source_generation)?,
                to_i64_v1(source_attempt_number)?,
                to_i64_v1(claim_generation)?,
                to_i64_v1(context.current_attempt_number)?,
                context.current_handoff_guard_digest.as_slice(),
                candidate.adapter_root_id.as_slice(),
                to_i64_v1(candidate.adapter_epoch)?,
            ],
            |row| row.get(0),
        )
        .map_err(map_sql_error_v1)?;
    Ok(exact == 1)
}

fn target_state_v1(
    current: DurableStateV1,
    decision: ExecutionReceiptDecisionV1,
) -> Option<CoordinatorReceiptEffectiveStateV1> {
    if decision != ExecutionReceiptDecisionV1::Consumed {
        return None;
    }
    match current {
        DurableStateV1::Dispatching => Some(CoordinatorReceiptEffectiveStateV1::Executing),
        DurableStateV1::OutcomeUnknown => {
            Some(CoordinatorReceiptEffectiveStateV1::ReconciliationRequired)
        }
        DurableStateV1::Executing | DurableStateV1::ReconciliationRequired => None,
    }
}

fn stage_receipt_advance_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    expected: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    target: CoordinatorReceiptEffectiveStateV1,
    #[cfg(feature = "test-fault-injection")] fault_probe: &CoordinatorDispatchFaultProbeV1,
) -> Result<CoordinatorReceiptCommitEvidenceV1, ReceiptStageErrorV1> {
    // `commit_execution_receipt_v1` loaded `expected` immediately after the complete V2
    // snapshot verifier acquired this same BEGIN IMMEDIATE writer. No mutation or connection
    // profile change can occur before this private staging helper, so repeating the profile
    // reads and the nine-table context join would not strengthen the snapshot proof. Every
    // staged write below still uses exact expected-value/CAS predicates and is followed by the
    // complete post-stage verifier before COMMIT.
    if let Some(prior) = load_existing_receipt_v1(transaction, lookup, expected, candidate)? {
        return Err(if prior == target {
            ReceiptStageErrorV1::Conflict
        } else {
            ReceiptStageErrorV1::Unhealthy
        });
    }

    let generations = allocate_receipt_generations_v1(transaction, target)?;
    let ids = derive_receipt_ids_v1(candidate, target);
    insert_receipt_v1(
        transaction,
        lookup,
        expected,
        candidate,
        generations.receipt,
    )?;
    #[cfg(feature = "test-fault-injection")]
    receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb045)?;
    let acknowledged_attempt_generation = if direct_acknowledged_source_is_exact_v1(expected) {
        append_acknowledged_attempt_v1(
            transaction,
            lookup,
            expected,
            candidate,
            generations.delivery,
        )?;
        generations.delivery
    } else {
        expected
            .current_attempt_generation
            .ok_or(ReceiptStageErrorV1::Conflict)?
    };
    if target == CoordinatorReceiptEffectiveStateV1::ReconciliationRequired {
        insert_consumed_reconciliation_v1(
            transaction,
            lookup,
            expected,
            candidate,
            &ids,
            generations,
        )?;
    }
    // The frozen `dispatch_transitions_current_projection_guard` requires the current
    // record projection to exist before its append-only transition and event. Registry
    // ordinals are stable boundary identifiers; they do not override this SQL order.
    update_current_record_v1(
        transaction,
        lookup,
        expected,
        candidate,
        &ids,
        generations,
        target,
    )?;
    #[cfg(feature = "test-fault-injection")]
    receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb049)?;
    insert_receipt_transition_v1(
        transaction,
        lookup,
        expected,
        candidate,
        &ids,
        generations,
        target,
    )?;
    #[cfg(feature = "test-fault-injection")]
    receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb046)?;
    acknowledge_outbox_v1(
        transaction,
        lookup,
        expected,
        candidate,
        generations.delivery,
        acknowledged_attempt_generation,
    )?;
    #[cfg(feature = "test-fault-injection")]
    receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb048)?;
    insert_receipt_event_v1(
        transaction,
        lookup,
        expected,
        candidate,
        &ids,
        generations,
        target,
    )?;
    #[cfg(feature = "test-fault-injection")]
    receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb047)?;
    update_receipt_metadata_v1(transaction, generations)?;
    #[cfg(feature = "test-fault-injection")]
    receipt_fault_checkpoint_v1(fault_probe, FaultBoundaryV1::Plan005Fb050)?;
    verify_staged_receipt_graph_v1(
        transaction,
        lookup,
        expected,
        candidate,
        &ids,
        generations,
        target,
    )?;

    Ok(CoordinatorReceiptCommitEvidenceV1 {
        receipt_id: candidate.receipt_id,
        receipt_digest: candidate.receipt_digest,
        effective_state: target,
        state_generation: generations.state,
        delivery_generation: generations.delivery,
        receipt_generation: generations.receipt,
        reconciliation_generation: generations.reconciliation,
        event_generation: generations.event,
    })
}

fn insert_receipt_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    receipt_generation: u64,
) -> Result<(), ReceiptStageErrorV1> {
    let canonical_receipt_length = u64::try_from(candidate.canonical_receipt.len())
        .map_err(|_| ReceiptStageErrorV1::Unhealthy)?;
    let inserted = transaction
        .execute(
            "INSERT INTO dispatch_receipts (receipt_id, grant_id, operation_id, \
                 dispatch_attempt_id, receipt_digest, canonical_receipt, \
                 canonical_receipt_length, adapter_key_fingerprint, decision, refusal_code, \
                 no_consumption_tombstone_digest, receipt_generation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'CONSUMED', NULL, NULL, ?9)",
            params![
                candidate.receipt_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                candidate.receipt_digest.as_slice(),
                &*candidate.canonical_receipt,
                to_i64_v1(canonical_receipt_length)?,
                candidate.adapter_key_fingerprint.as_slice(),
                to_i64_v1(receipt_generation)?,
            ],
        )
        .map_err(map_sql_error_v1)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

fn insert_consumed_reconciliation_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    ids: &DerivedReceiptIdsV1,
    generations: ReceiptGenerationsV1,
) -> Result<(), ReceiptStageErrorV1> {
    let reconciliation_id = ids
        .reconciliation_id
        .ok_or(ReceiptStageErrorV1::Unhealthy)?;
    let transport_digest = context
        .transport_quiescence_digest
        .ok_or(ReceiptStageErrorV1::Unhealthy)?;
    let inserted = transaction
        .execute(
            "INSERT INTO dispatch_reconciliations (reconciliation_id, grant_id, operation_id, \
                 dispatch_attempt_id, evidence_digest, transport_quiescence_digest, \
                 no_inflight_proof_digest, result, receipt_id, receipt_decision, \
                 reconciliation_generation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'CONSUMED', ?7, 'CONSUMED', ?8)",
            params![
                reconciliation_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                ids.evidence_digest.as_slice(),
                transport_digest.as_slice(),
                candidate.receipt_id.as_slice(),
                to_i64_v1(
                    generations
                        .reconciliation
                        .ok_or(ReceiptStageErrorV1::Unhealthy)?
                )?,
            ],
        )
        .map_err(map_sql_error_v1)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

fn allocate_late_receipt_generations_v1(
    transaction: &Transaction<'_>,
) -> Result<LateReceiptGenerationsV1, ReceiptStageErrorV1> {
    let raw: (i64, i64, i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT dispatch_store_generation, dispatch_generation, delivery_generation, \
                    receipt_generation, reconciliation_generation, event_generation \
             FROM dispatch_store_meta WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
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
        .map_err(map_sql_error_v1)?;
    let previous_store = safe_u64_v1(raw.0)?;
    let previous_dispatch = safe_u64_v1(raw.1)?;
    let previous_delivery = safe_u64_v1(raw.2)?;
    let previous_receipt = safe_u64_v1(raw.3)?;
    let previous_reconciliation = safe_u64_v1(raw.4)?;
    let previous_event = safe_u64_v1(raw.5)?;
    if [
        previous_dispatch,
        previous_delivery,
        previous_receipt,
        previous_reconciliation,
        previous_event,
    ]
    .into_iter()
    .any(|axis| axis > previous_store)
    {
        return Err(ReceiptStageErrorV1::Unhealthy);
    }
    let store = next_safe_v1(previous_store)?;
    let receipt = store;
    let reconciliation = store;
    Ok(LateReceiptGenerationsV1 {
        previous_store,
        previous_dispatch,
        previous_delivery,
        previous_receipt,
        previous_reconciliation,
        previous_event,
        store,
        receipt,
        reconciliation,
    })
}

fn insert_late_consumed_reconciliation_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    ids: &DerivedReceiptIdsV1,
    reconciliation_generation: u64,
) -> Result<(), ReceiptStageErrorV1> {
    let reconciliation_id = ids
        .reconciliation_id
        .ok_or(ReceiptStageErrorV1::Unhealthy)?;
    let transport_digest = context
        .transport_quiescence_digest
        .ok_or(ReceiptStageErrorV1::Unhealthy)?;
    let inserted = transaction
        .execute(
            "INSERT INTO dispatch_reconciliations (reconciliation_id, grant_id, operation_id, \
                 dispatch_attempt_id, evidence_digest, transport_quiescence_digest, \
                 no_inflight_proof_digest, result, receipt_id, receipt_decision, \
                 reconciliation_generation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'CONSUMED', ?7, 'CONSUMED', ?8)",
            params![
                reconciliation_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                ids.evidence_digest.as_slice(),
                transport_digest.as_slice(),
                candidate.receipt_id.as_slice(),
                to_i64_v1(reconciliation_generation)?,
            ],
        )
        .map_err(map_sql_error_v1)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

fn update_late_receipt_metadata_v1(
    transaction: &Transaction<'_>,
    generations: LateReceiptGenerationsV1,
) -> Result<(), ReceiptStageErrorV1> {
    let updated = transaction
        .execute(
            "UPDATE dispatch_store_meta \
             SET dispatch_store_generation = ?1, receipt_generation = ?2, \
                 reconciliation_generation = ?3 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND dispatch_store_generation = ?4 AND dispatch_generation = ?5 \
               AND delivery_generation = ?6 AND receipt_generation = ?7 \
               AND reconciliation_generation = ?8 AND event_generation = ?9",
            params![
                to_i64_v1(generations.store)?,
                to_i64_v1(generations.receipt)?,
                to_i64_v1(generations.reconciliation)?,
                to_i64_v1(generations.previous_store)?,
                to_i64_v1(generations.previous_dispatch)?,
                to_i64_v1(generations.previous_delivery)?,
                to_i64_v1(generations.previous_receipt)?,
                to_i64_v1(generations.previous_reconciliation)?,
                to_i64_v1(generations.previous_event)?,
            ],
        )
        .map_err(map_sql_error_v1)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Conflict)
    }
}

fn load_late_consumed_evidence_v1(
    connection: &Connection,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    ids: &DerivedReceiptIdsV1,
) -> Result<Option<CoordinatorReceiptCommitEvidenceV1>, ReceiptStageErrorV1> {
    let retained = connection
        .query_row(
            "SELECT receipt_id, grant_id, operation_id, dispatch_attempt_id, receipt_digest, \
                    canonical_receipt, canonical_receipt_length, adapter_key_fingerprint, \
                    decision \
             FROM dispatch_receipts \
             WHERE receipt_id = ?1 OR grant_id = ?2 OR operation_id = ?3 \
                OR receipt_digest = ?4",
            params![
                candidate.receipt_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                candidate.receipt_digest.as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?;
    let Some(retained) = retained else {
        return Ok(None);
    };
    if retained.0.as_slice() != candidate.receipt_id
        || retained.1.as_slice() != lookup.grant_id
        || retained.2.as_str() != lookup.operation_id.as_ref()
        || retained.3.as_slice() != context.dispatch_attempt_id
        || retained.4.as_slice() != candidate.receipt_digest
        || retained.5.as_slice() != &*candidate.canonical_receipt
        || usize::try_from(retained.6).ok() != Some(candidate.canonical_receipt.len())
        || retained.7.as_slice() != candidate.adapter_key_fingerprint
        || retained.8 != "CONSUMED"
    {
        return Err(ReceiptStageErrorV1::Conflict);
    }
    let reconciliation_id = ids
        .reconciliation_id
        .ok_or(ReceiptStageErrorV1::Unhealthy)?;
    let transport_digest = context
        .transport_quiescence_digest
        .ok_or(ReceiptStageErrorV1::Unhealthy)?;
    let raw = connection
        .query_row(
            "SELECT record.state_generation, outbox.delivery_generation, \
                    receipt.receipt_generation, consumed.reconciliation_generation, \
                    event.event_generation \
             FROM dispatch_records AS record \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = record.grant_id \
              AND outbox.operation_id = record.operation_id \
              AND outbox.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_events AS event \
               ON event.event_id = record.current_event_id \
              AND event.operation_id = record.operation_id \
              AND event.grant_id = record.grant_id \
              AND event.transition_generation = record.state_generation \
              AND event.effective_state = record.effective_state \
             JOIN dispatch_reconciliations AS unknown \
               ON unknown.reconciliation_id = record.reconciliation_id \
              AND unknown.grant_id = record.grant_id \
              AND unknown.operation_id = record.operation_id \
              AND unknown.dispatch_attempt_id = record.dispatch_attempt_id \
              AND unknown.result = 'OUTCOME_UNKNOWN' \
             JOIN dispatch_receipts AS receipt \
               ON receipt.receipt_id = ?1 AND receipt.grant_id = record.grant_id \
              AND receipt.operation_id = record.operation_id \
              AND receipt.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_reconciliations AS consumed \
               ON consumed.reconciliation_id = ?2 \
              AND consumed.grant_id = record.grant_id \
              AND consumed.operation_id = record.operation_id \
              AND consumed.dispatch_attempt_id = record.dispatch_attempt_id \
              AND consumed.evidence_digest = ?3 \
              AND consumed.transport_quiescence_digest = ?4 \
              AND consumed.no_inflight_proof_digest IS NULL \
              AND consumed.result = 'CONSUMED' \
              AND consumed.receipt_id = receipt.receipt_id \
              AND consumed.receipt_decision = 'CONSUMED' \
             WHERE record.operation_id = ?5 AND record.grant_id = ?6 \
               AND record.dispatch_attempt_id = ?7 \
               AND record.effective_state = 'RECONCILIATION_REQUIRED' \
               AND record.state_generation = ?8 AND record.current_event_id = ?9 \
               AND record.receipt_id IS NULL AND record.receipt_decision IS NULL \
               AND record.reconciliation_id = ?10 \
               AND record.reconciliation_result = 'OUTCOME_UNKNOWN' \
               AND outbox.delivery_state = 'UNKNOWN' \
               AND outbox.delivery_generation = ?11 \
               AND outbox.current_attempt_generation = ?12 \
               AND outbox.receipt_id IS NULL AND outbox.receipt_decision IS NULL \
               AND unknown.transport_quiescence_digest = ?4 \
               AND receipt.receipt_digest = ?13 \
               AND receipt.canonical_receipt = ?14 \
               AND receipt.canonical_receipt_length = ?15 \
               AND receipt.adapter_key_fingerprint = ?16 \
               AND receipt.decision = 'CONSUMED'",
            params![
                candidate.receipt_id.as_slice(),
                reconciliation_id.as_slice(),
                ids.evidence_digest.as_slice(),
                transport_digest.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(context.state_generation)?,
                context.current_event_id.as_slice(),
                context
                    .reconciliation_id
                    .ok_or(ReceiptStageErrorV1::Unhealthy)?
                    .as_slice(),
                to_i64_v1(context.delivery_generation)?,
                to_i64_v1(
                    context
                        .current_attempt_generation
                        .ok_or(ReceiptStageErrorV1::Unhealthy)?
                )?,
                candidate.receipt_digest.as_slice(),
                &*candidate.canonical_receipt,
                to_i64_v1(
                    u64::try_from(candidate.canonical_receipt.len())
                        .map_err(|_| ReceiptStageErrorV1::Unhealthy)?
                )?,
                candidate.adapter_key_fingerprint.as_slice(),
            ],
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
        .optional()
        .map_err(map_sql_error_v1)?
        .ok_or(ReceiptStageErrorV1::Unhealthy)?;
    Ok(Some(CoordinatorReceiptCommitEvidenceV1 {
        receipt_id: candidate.receipt_id,
        receipt_digest: candidate.receipt_digest,
        effective_state: CoordinatorReceiptEffectiveStateV1::ReconciliationRequired,
        state_generation: safe_u64_v1(raw.0)?,
        delivery_generation: safe_u64_v1(raw.1)?,
        receipt_generation: safe_u64_v1(raw.2)?,
        reconciliation_generation: Some(safe_u64_v1(raw.3)?),
        event_generation: safe_u64_v1(raw.4)?,
    }))
}

fn update_current_record_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    ids: &DerivedReceiptIdsV1,
    generations: ReceiptGenerationsV1,
    target: CoordinatorReceiptEffectiveStateV1,
) -> Result<(), ReceiptStageErrorV1> {
    let updated = match target {
        CoordinatorReceiptEffectiveStateV1::Executing => transaction.execute(
            "UPDATE dispatch_records SET effective_state = 'EXECUTING', state_generation = ?1, \
                 receipt_id = ?2, receipt_decision = 'CONSUMED', current_event_id = ?3 \
             WHERE operation_id = ?4 AND grant_id = ?5 AND dispatch_attempt_id = ?6 \
               AND effective_state = 'DISPATCHING' AND state_generation = ?7 \
               AND current_event_id = ?8 AND receipt_id IS NULL AND reconciliation_id IS NULL",
            params![
                to_i64_v1(generations.state)?,
                candidate.receipt_id.as_slice(),
                ids.event_id.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(context.state_generation)?,
                context.current_event_id.as_slice(),
            ],
        ),
        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired => {
            let reconciliation_id = ids
                .reconciliation_id
                .ok_or(ReceiptStageErrorV1::Unhealthy)?;
            transaction.execute(
                "UPDATE dispatch_records SET effective_state = 'RECONCILIATION_REQUIRED', \
                     state_generation = ?1, receipt_id = ?2, receipt_decision = 'CONSUMED', \
                     reconciliation_id = ?3, reconciliation_result = 'CONSUMED', \
                     current_event_id = ?4 \
                 WHERE operation_id = ?5 AND grant_id = ?6 AND dispatch_attempt_id = ?7 \
                   AND effective_state = 'OUTCOME_UNKNOWN' AND state_generation = ?8 \
                   AND current_event_id = ?9 AND receipt_id IS NULL \
                   AND reconciliation_result = 'OUTCOME_UNKNOWN'",
                params![
                    to_i64_v1(generations.state)?,
                    candidate.receipt_id.as_slice(),
                    reconciliation_id.as_slice(),
                    ids.event_id.as_slice(),
                    &*lookup.operation_id,
                    lookup.grant_id.as_slice(),
                    context.dispatch_attempt_id.as_slice(),
                    to_i64_v1(context.state_generation)?,
                    context.current_event_id.as_slice(),
                ],
            )
        }
    }
    .map_err(map_sql_error_v1)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Conflict)
    }
}

fn insert_receipt_transition_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    ids: &DerivedReceiptIdsV1,
    generations: ReceiptGenerationsV1,
    target: CoordinatorReceiptEffectiveStateV1,
) -> Result<(), ReceiptStageErrorV1> {
    let (previous, next) = match target {
        CoordinatorReceiptEffectiveStateV1::Executing => ("DISPATCHING", "EXECUTING"),
        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired => {
            ("OUTCOME_UNKNOWN", "RECONCILIATION_REQUIRED")
        }
    };
    let inserted = transaction
        .execute(
            "INSERT INTO dispatch_transitions (state_generation, \
                 previous_transition_generation, operation_id, grant_id, dispatch_attempt_id, \
                 previous_state, new_state, event_id, evidence_digest, receipt_id, \
                 receipt_decision, reconciliation_id, reconciliation_result, \
                 definite_refusal_guard_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'CONSUMED', ?11, ?12, NULL)",
            params![
                to_i64_v1(generations.state)?,
                to_i64_v1(context.state_generation)?,
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                previous,
                next,
                ids.event_id.as_slice(),
                ids.evidence_digest.as_slice(),
                candidate.receipt_id.as_slice(),
                ids.reconciliation_id.as_ref().map(|value| value.as_slice()),
                (target == CoordinatorReceiptEffectiveStateV1::ReconciliationRequired)
                    .then_some("CONSUMED"),
            ],
        )
        .map_err(map_sql_error_v1)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

fn append_acknowledged_attempt_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    attempt_generation: u64,
) -> Result<(), ReceiptStageErrorV1> {
    if context.delivery_state != "HANDED_OFF"
        || !receipt_delivery_context_is_exact_v1(context, candidate)
        || candidate.adapter_root_id != lookup.adapter_root_id
    {
        return Err(ReceiptStageErrorV1::Conflict);
    }
    let prior_generation = context
        .current_attempt_generation
        .ok_or(ReceiptStageErrorV1::Conflict)?;
    let attempt_number = next_safe_v1(context.current_attempt_number)?;
    let inserted = transaction
        .execute(
            "INSERT INTO dispatch_delivery_attempts (
                 attempt_generation, grant_id, operation_id, dispatch_attempt_id,
                 attempt_number, handoff_guard_digest, classification, adapter_root_digest,
                 adapter_epoch, readback_generation)
             SELECT ?1, grant_id, operation_id, dispatch_attempt_id,
                    ?2, handoff_guard_digest, 'ACKNOWLEDGED', ?3, ?4, NULL
             FROM dispatch_delivery_attempts
             WHERE attempt_generation = ?5 AND grant_id = ?6 AND operation_id = ?7
               AND dispatch_attempt_id = ?8 AND attempt_number = ?9
               AND handoff_guard_digest = ?10 AND classification = 'POSSIBLE_HANDOFF'
               AND adapter_root_digest IS NULL AND adapter_epoch IS NULL
               AND readback_generation IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM dispatch_delivery_attempts AS other
                   WHERE other.grant_id = ?6 AND other.operation_id = ?7
                     AND other.dispatch_attempt_id = ?8
                     AND other.attempt_generation <> ?5
               )",
            params![
                to_i64_v1(attempt_generation)?,
                to_i64_v1(attempt_number)?,
                candidate.adapter_root_id.as_slice(),
                to_i64_v1(candidate.adapter_epoch)?,
                to_i64_v1(prior_generation)?,
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(context.current_attempt_number)?,
                context.current_handoff_guard_digest.as_slice(),
            ],
        )
        .map_err(map_sql_error_v1)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Conflict)
    }
}

fn acknowledge_outbox_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    delivery_generation: u64,
    acknowledged_attempt_generation: u64,
) -> Result<(), ReceiptStageErrorV1> {
    let updated = transaction
        .execute(
            "UPDATE dispatch_outbox SET delivery_state = 'ACKNOWLEDGED', \
                 delivery_generation = ?1, current_attempt_generation = ?2, \
                 receipt_id = ?3, receipt_decision = 'CONSUMED' \
             WHERE grant_id = ?4 AND operation_id = ?5 AND dispatch_attempt_id = ?6 \
               AND delivery_state = ?7 AND delivery_generation = ?8 \
               AND current_attempt_generation = ?9 AND receipt_id IS NULL \
               AND receipt_decision IS NULL",
            params![
                to_i64_v1(delivery_generation)?,
                to_i64_v1(acknowledged_attempt_generation)?,
                candidate.receipt_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                context.delivery_state,
                to_i64_v1(context.delivery_generation)?,
                to_i64_v1(
                    context
                        .current_attempt_generation
                        .ok_or(ReceiptStageErrorV1::Conflict)?
                )?,
            ],
        )
        .map_err(map_sql_error_v1)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Conflict)
    }
}

fn insert_receipt_event_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    ids: &DerivedReceiptIdsV1,
    generations: ReceiptGenerationsV1,
    target: CoordinatorReceiptEffectiveStateV1,
) -> Result<(), ReceiptStageErrorV1> {
    let (state, kind) = match target {
        CoordinatorReceiptEffectiveStateV1::Executing => ("EXECUTING", "GRANT_CONSUMED"),
        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired => {
            ("RECONCILIATION_REQUIRED", "DISPATCH_RECONCILED")
        }
    };
    let inserted = transaction
        .execute(
            "INSERT INTO dispatch_events (event_id, event_generation, transition_generation, \
                 operation_id, grant_id, dispatch_attempt_id, task_id, workload_id, plan_id, \
                 task_lease_digest, event_contract_version, grant_contract_version, \
                 receipt_contract_version, effective_state, decision, latency_ms, event_kind, \
                 public_reason_code, public_trace_id, delivery_state, delivered_generation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, 1, 1, ?11, \
                     'CONSUMED', 0, ?12, NULL, ?13, 'PENDING', NULL)",
            params![
                ids.event_id.as_slice(),
                to_i64_v1(generations.event)?,
                to_i64_v1(generations.state)?,
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                context.task_id,
                context.workload_id,
                context.plan_id.as_slice(),
                context.task_lease_digest.as_slice(),
                state,
                kind,
                &*candidate.trace_id,
            ],
        )
        .map_err(map_sql_error_v1)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

fn update_receipt_metadata_v1(
    transaction: &Transaction<'_>,
    generations: ReceiptGenerationsV1,
) -> Result<(), ReceiptStageErrorV1> {
    let updated = transaction
        .execute(
            "UPDATE dispatch_store_meta SET dispatch_store_generation = ?1, \
                 dispatch_generation = ?2, delivery_generation = ?3, receipt_generation = ?4, \
                 reconciliation_generation = ?5, event_generation = ?6 \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
               AND dispatch_store_generation = ?1 - 1 \
               AND dispatch_generation < ?2 AND delivery_generation < ?3 \
               AND receipt_generation < ?4 AND event_generation < ?6 \
               AND reconciliation_generation <= ?5",
            params![
                to_i64_v1(generations.store)?,
                to_i64_v1(generations.state)?,
                to_i64_v1(generations.delivery)?,
                to_i64_v1(generations.receipt)?,
                to_i64_v1(generations.reconciliation_high_water)?,
                to_i64_v1(generations.event)?,
            ],
        )
        .map_err(map_sql_error_v1)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

fn allocate_receipt_generations_v1(
    transaction: &Transaction<'_>,
    target: CoordinatorReceiptEffectiveStateV1,
) -> Result<ReceiptGenerationsV1, ReceiptStageErrorV1> {
    let current: (i64, i64, i64, i64, i64, i64) = transaction
        .query_row(
            "SELECT dispatch_store_generation, dispatch_generation, delivery_generation, \
                    receipt_generation, reconciliation_generation, event_generation \
             FROM dispatch_store_meta WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
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
        .map_err(map_sql_error_v1)?;
    let current_reconciliation = safe_u64_v1(current.4)?;
    let store = next_safe_v1(safe_u64_v1(current.0)?)?;
    for axis in [current.1, current.2, current.3, current.4, current.5] {
        if safe_u64_v1(axis)? >= store {
            return Err(ReceiptStageErrorV1::Unhealthy);
        }
    }
    let reconciliation =
        (target == CoordinatorReceiptEffectiveStateV1::ReconciliationRequired).then_some(store);
    Ok(ReceiptGenerationsV1 {
        store,
        state: store,
        delivery: store,
        receipt: store,
        reconciliation,
        reconciliation_high_water: reconciliation.unwrap_or(current_reconciliation),
        event: store,
    })
}

fn derive_receipt_ids_v1(
    candidate: &VerifiedReceiptCandidateV1,
    target: CoordinatorReceiptEffectiveStateV1,
) -> DerivedReceiptIdsV1 {
    let state = match target {
        CoordinatorReceiptEffectiveStateV1::Executing => b"EXECUTING".as_slice(),
        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired => {
            b"RECONCILIATION_REQUIRED".as_slice()
        }
    };
    let event_id = digest_parts_v1(
        b"HELIXOS\0DISPATCH-RECEIPT-EVENT\0V1\0",
        &[&candidate.receipt_id, &candidate.receipt_digest, state],
    );
    let evidence_digest = digest_parts_v1(
        b"HELIXOS\0DISPATCH-RECEIPT-EVIDENCE\0V1\0",
        &[&candidate.receipt_id, &candidate.receipt_digest, state],
    );
    let reconciliation_id = (target == CoordinatorReceiptEffectiveStateV1::ReconciliationRequired)
        .then(|| {
            digest_parts_v1(
                b"HELIXOS\0DISPATCH-RECONCILIATION-ID\0V1\0",
                &[&candidate.receipt_id, &candidate.receipt_digest],
            )
        });
    DerivedReceiptIdsV1 {
        event_id,
        evidence_digest,
        reconciliation_id,
    }
}

fn digest_parts_v1(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn verify_staged_attempt_history_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    expected: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    acknowledged_attempt_generation: u64,
) -> Result<bool, ReceiptStageErrorV1> {
    if direct_acknowledged_source_is_exact_v1(expected) {
        let source_generation = expected
            .current_attempt_generation
            .ok_or(ReceiptStageErrorV1::Conflict)?;
        let acknowledged_attempt_number = next_safe_v1(expected.current_attempt_number)?;
        if acknowledged_attempt_generation <= source_generation {
            return Ok(false);
        }
        let exact: i64 = transaction
            .query_row(
                "SELECT CASE WHEN \
                     (SELECT COUNT(*) FROM dispatch_delivery_attempts \
                        WHERE grant_id = ?1 AND operation_id = ?2 \
                          AND dispatch_attempt_id = ?3) = 2 \
                 AND EXISTS (SELECT 1 FROM dispatch_delivery_attempts \
                        WHERE grant_id = ?1 AND operation_id = ?2 \
                          AND dispatch_attempt_id = ?3 AND attempt_generation = ?4 \
                          AND attempt_number = ?5 AND handoff_guard_digest = ?6 \
                          AND classification = 'POSSIBLE_HANDOFF' \
                          AND adapter_root_digest IS NULL AND adapter_epoch IS NULL \
                          AND readback_generation IS NULL) \
                 AND EXISTS (SELECT 1 FROM dispatch_delivery_attempts \
                        WHERE grant_id = ?1 AND operation_id = ?2 \
                          AND dispatch_attempt_id = ?3 AND attempt_generation = ?7 \
                          AND attempt_number = ?8 AND handoff_guard_digest = ?6 \
                          AND classification = 'ACKNOWLEDGED' \
                          AND adapter_root_digest = ?9 AND adapter_epoch = ?10 \
                          AND readback_generation IS NULL) \
                 THEN 1 ELSE 0 END",
                params![
                    lookup.grant_id.as_slice(),
                    &*lookup.operation_id,
                    expected.dispatch_attempt_id.as_slice(),
                    to_i64_v1(source_generation)?,
                    to_i64_v1(expected.current_attempt_number)?,
                    expected.current_handoff_guard_digest.as_slice(),
                    to_i64_v1(acknowledged_attempt_generation)?,
                    to_i64_v1(acknowledged_attempt_number)?,
                    candidate.adapter_root_id.as_slice(),
                    to_i64_v1(candidate.adapter_epoch)?,
                ],
                |row| row.get(0),
            )
            .map_err(map_sql_error_v1)?;
        return Ok(exact == 1);
    }

    if acknowledged_attempt_generation
        != expected
            .current_attempt_generation
            .ok_or(ReceiptStageErrorV1::Conflict)?
    {
        return Ok(false);
    }
    readback_attempt_history_is_exact_v1(transaction, lookup, expected, candidate)
}

fn verify_staged_receipt_graph_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReceiptLookupV1,
    expected: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
    ids: &DerivedReceiptIdsV1,
    generations: ReceiptGenerationsV1,
    target: CoordinatorReceiptEffectiveStateV1,
) -> Result<(), ReceiptStageErrorV1> {
    let acknowledged_attempt_generation = if direct_acknowledged_source_is_exact_v1(expected) {
        generations.delivery
    } else {
        expected
            .current_attempt_generation
            .ok_or(ReceiptStageErrorV1::Conflict)?
    };
    if !verify_staged_attempt_history_v1(
        transaction,
        lookup,
        expected,
        candidate,
        acknowledged_attempt_generation,
    )? {
        return Err(ReceiptStageErrorV1::Unhealthy);
    }
    let expected_state = match target {
        CoordinatorReceiptEffectiveStateV1::Executing => "EXECUTING",
        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired => "RECONCILIATION_REQUIRED",
    };
    let exact: i64 = transaction
        .query_row(
            "SELECT CASE WHEN \
                 EXISTS (SELECT 1 FROM dispatch_receipts WHERE receipt_id = ?1 \
                    AND grant_id = ?2 AND operation_id = ?3 \
                    AND dispatch_attempt_id = ?11 AND receipt_digest = ?4 \
                    AND canonical_receipt = ?12 AND canonical_receipt_length = ?13 \
                    AND adapter_key_fingerprint = ?14 AND decision = 'CONSUMED' \
                    AND receipt_generation = ?15) \
             AND EXISTS (SELECT 1 FROM dispatch_records WHERE operation_id = ?3 \
                    AND grant_id = ?2 AND dispatch_attempt_id = ?11 \
                    AND receipt_id = ?1 AND receipt_decision = 'CONSUMED' \
                    AND effective_state = ?5 AND state_generation = ?6 \
                    AND current_event_id = ?7) \
             AND EXISTS (SELECT 1 FROM dispatch_transitions WHERE operation_id = ?3 \
                    AND grant_id = ?2 AND dispatch_attempt_id = ?11 \
                    AND receipt_id = ?1 AND receipt_decision = 'CONSUMED' AND new_state = ?5 \
                    AND state_generation = ?6 AND event_id = ?7) \
             AND EXISTS (SELECT 1 FROM dispatch_outbox WHERE operation_id = ?3 \
                    AND grant_id = ?2 AND dispatch_attempt_id = ?11 \
                    AND receipt_id = ?1 AND receipt_decision = 'CONSUMED' \
                    AND delivery_state = 'ACKNOWLEDGED' \
                    AND delivery_generation = ?8 AND current_attempt_generation = ?10) \
             AND EXISTS (SELECT 1 FROM dispatch_events WHERE operation_id = ?3 \
                    AND grant_id = ?2 AND dispatch_attempt_id = ?11 \
                    AND event_id = ?7 AND effective_state = ?5 \
                    AND decision = 'CONSUMED' AND event_generation = ?9) \
             THEN 1 ELSE 0 END",
            params![
                candidate.receipt_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                candidate.receipt_digest.as_slice(),
                expected_state,
                to_i64_v1(generations.state)?,
                ids.event_id.as_slice(),
                to_i64_v1(generations.delivery)?,
                to_i64_v1(generations.event)?,
                to_i64_v1(acknowledged_attempt_generation)?,
                expected.dispatch_attempt_id.as_slice(),
                &*candidate.canonical_receipt,
                to_i64_v1(
                    u64::try_from(candidate.canonical_receipt.len())
                        .map_err(|_| ReceiptStageErrorV1::Unhealthy)?
                )?,
                candidate.adapter_key_fingerprint.as_slice(),
                to_i64_v1(generations.receipt)?,
            ],
            |row| row.get(0),
        )
        .map_err(map_sql_error_v1)?;
    if exact != 1 || foreign_key_check_has_rows_v1(transaction)? {
        return Err(ReceiptStageErrorV1::Unhealthy);
    }
    Ok(())
}

fn completed_receipt_attempt_history_is_exact_v1(
    connection: &Connection,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
) -> Result<bool, ReceiptStageErrorV1> {
    let Some(current_generation) = context.current_attempt_generation else {
        return Ok(false);
    };
    if context.delivery_state != "ACKNOWLEDGED"
        || context.adapter_root_id != Some(candidate.adapter_root_id)
        || context.adapter_epoch != Some(candidate.adapter_epoch)
    {
        return Ok(false);
    }

    if context.current_attempt_classification == "ACKNOWLEDGED" {
        if context.state != DurableStateV1::Executing
            || current_generation != context.delivery_generation
            || context.current_attempt_number != 2
            || context.readback_generation.is_some()
            || context.reconciliation_id.is_some()
            || context.reconciliation_result.is_some()
            || context.transport_quiescence_digest.is_some()
        {
            return Ok(false);
        }
        let exact: i64 = connection
            .query_row(
                "SELECT CASE WHEN \
                     (SELECT COUNT(*) FROM dispatch_delivery_attempts \
                        WHERE grant_id = ?1 AND operation_id = ?2 \
                          AND dispatch_attempt_id = ?3) = 2 \
                 AND (SELECT COUNT(*) FROM dispatch_delivery_attempts \
                        WHERE grant_id = ?1 AND operation_id = ?2 \
                          AND dispatch_attempt_id = ?3 AND attempt_generation < ?4 \
                          AND attempt_number = 1 AND handoff_guard_digest = ?5 \
                          AND classification = 'POSSIBLE_HANDOFF' \
                          AND adapter_root_digest IS NULL AND adapter_epoch IS NULL \
                          AND readback_generation IS NULL) = 1 \
                 AND (SELECT COUNT(*) FROM dispatch_delivery_attempts \
                        WHERE grant_id = ?1 AND operation_id = ?2 \
                          AND dispatch_attempt_id = ?3 AND attempt_generation = ?4 \
                          AND attempt_number = 2 AND handoff_guard_digest = ?5 \
                          AND classification = 'ACKNOWLEDGED' \
                          AND adapter_root_digest = ?6 AND adapter_epoch = ?7 \
                          AND readback_generation IS NULL) = 1 \
                 THEN 1 ELSE 0 END",
                params![
                    lookup.grant_id.as_slice(),
                    &*lookup.operation_id,
                    context.dispatch_attempt_id.as_slice(),
                    to_i64_v1(current_generation)?,
                    context.current_handoff_guard_digest.as_slice(),
                    candidate.adapter_root_id.as_slice(),
                    to_i64_v1(candidate.adapter_epoch)?,
                ],
                |row| row.get(0),
            )
            .map_err(map_sql_error_v1)?;
        return Ok(exact == 1);
    }

    if context.current_attempt_classification != "POSSIBLE_HANDOFF"
        || context.current_attempt_number != 2
        || context.delivery_generation <= current_generation
        || match context.state {
            DurableStateV1::Executing => {
                context.reconciliation_id.is_some()
                    || context.reconciliation_result.is_some()
                    || context.transport_quiescence_digest.is_some()
            }
            DurableStateV1::ReconciliationRequired => {
                context.reconciliation_id.is_none()
                    || context.reconciliation_result.as_deref() != Some("CONSUMED")
                    || context.transport_quiescence_digest.is_none()
            }
            DurableStateV1::Dispatching | DurableStateV1::OutcomeUnknown => true,
        }
    {
        return Ok(false);
    }
    readback_attempt_history_is_exact_v1(connection, lookup, context, candidate)
}

fn load_existing_receipt_v1(
    connection: &Connection,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
) -> Result<Option<CoordinatorReceiptEffectiveStateV1>, ReceiptStageErrorV1> {
    let row = connection
        .query_row(
            "SELECT receipt.receipt_id, receipt.receipt_digest, receipt.canonical_receipt, \
                    receipt.canonical_receipt_length, receipt.adapter_key_fingerprint, \
                    receipt.decision, receipt.grant_id, receipt.operation_id, \
                    receipt.dispatch_attempt_id, record.effective_state, record.receipt_id, \
                    record.receipt_decision, record.reconciliation_result, outbox.receipt_id, \
                    outbox.receipt_decision, outbox.delivery_state \
             FROM dispatch_receipts AS receipt \
             JOIN dispatch_records AS record ON record.operation_id = receipt.operation_id \
                AND record.grant_id = receipt.grant_id \
                AND record.dispatch_attempt_id = receipt.dispatch_attempt_id \
             JOIN dispatch_outbox AS outbox ON outbox.operation_id = receipt.operation_id \
                AND outbox.grant_id = receipt.grant_id \
                AND outbox.dispatch_attempt_id = receipt.dispatch_attempt_id \
             WHERE receipt.receipt_id = ?1 OR receipt.grant_id = ?2 \
                OR receipt.operation_id = ?3 OR receipt.receipt_digest = ?4",
            params![
                candidate.receipt_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                candidate.receipt_digest.as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<Vec<u8>>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, String>(15)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let exact = row.0.as_slice() == candidate.receipt_id
        && row.1.as_slice() == candidate.receipt_digest
        && row.2.as_slice() == &*candidate.canonical_receipt
        && usize::try_from(row.3).ok() == Some(candidate.canonical_receipt.len())
        && row.4.as_slice() == candidate.adapter_key_fingerprint
        && row.5 == "CONSUMED"
        && row.6.as_slice() == lookup.grant_id
        && row.7.as_str() == lookup.operation_id.as_ref()
        && row.8.as_slice() == context.dispatch_attempt_id
        && row.10.as_deref() == Some(candidate.receipt_id.as_slice())
        && row.11.as_deref() == Some("CONSUMED")
        && row.13.as_deref() == Some(candidate.receipt_id.as_slice())
        && row.14.as_deref() == Some("CONSUMED")
        && row.15 == "ACKNOWLEDGED";
    if !exact {
        return Err(ReceiptStageErrorV1::Conflict);
    }
    match (row.9.as_str(), row.12.as_deref()) {
        ("EXECUTING", None) => Ok(Some(CoordinatorReceiptEffectiveStateV1::Executing)),
        ("RECONCILIATION_REQUIRED", Some("CONSUMED")) => Ok(Some(
            CoordinatorReceiptEffectiveStateV1::ReconciliationRequired,
        )),
        _ => Err(ReceiptStageErrorV1::Conflict),
    }
}

fn classify_prior_exact_without_advance_v1(
    connection: &Connection,
    lookup: &CoordinatorReceiptLookupV1,
    candidate: &VerifiedReceiptCandidateV1,
    context: &CurrentReceiptContextV1,
) -> CoordinatorReceiptCommitOutcomeV1 {
    let result = load_existing_receipt_v1(connection, lookup, context, candidate);
    let attempt_history =
        completed_receipt_attempt_history_is_exact_v1(connection, lookup, context, candidate);
    match (context.state, result, attempt_history) {
        (
            DurableStateV1::Executing,
            Ok(Some(CoordinatorReceiptEffectiveStateV1::Executing)),
            Ok(true),
        ) => load_prior_evidence_v1(connection, lookup, context, candidate)
            .map_or(CoordinatorReceiptCommitOutcomeV1::Unhealthy, |value| {
                CoordinatorReceiptCommitOutcomeV1::PriorExact(value)
            }),
        (
            DurableStateV1::ReconciliationRequired,
            Ok(Some(CoordinatorReceiptEffectiveStateV1::ReconciliationRequired)),
            Ok(true),
        ) => load_prior_evidence_v1(connection, lookup, context, candidate)
            .map_or(CoordinatorReceiptCommitOutcomeV1::Unhealthy, |value| {
                CoordinatorReceiptCommitOutcomeV1::PriorExact(value)
            }),
        (_, Ok(None), Ok(_)) => CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance,
        (_, Err(error), _) | (_, _, Err(error)) => outcome_from_error_v1(error),
        _ => CoordinatorReceiptCommitOutcomeV1::Conflict,
    }
}

fn load_prior_evidence_v1(
    connection: &Connection,
    lookup: &CoordinatorReceiptLookupV1,
    context: &CurrentReceiptContextV1,
    candidate: &VerifiedReceiptCandidateV1,
) -> Option<CoordinatorReceiptCommitEvidenceV1> {
    let current_attempt_generation = context.current_attempt_generation?;
    connection
        .query_row(
            "SELECT record.effective_state, record.state_generation, outbox.delivery_generation, \
                    receipt.receipt_generation, reconciliation.reconciliation_generation, \
                    event.event_generation \
             FROM dispatch_records AS record \
             JOIN dispatch_receipts AS receipt ON receipt.receipt_id = record.receipt_id \
                AND receipt.grant_id = record.grant_id \
                AND receipt.operation_id = record.operation_id \
                AND receipt.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_outbox AS outbox ON outbox.grant_id = record.grant_id \
                AND outbox.operation_id = record.operation_id \
                AND outbox.dispatch_attempt_id = record.dispatch_attempt_id \
                AND outbox.receipt_id = receipt.receipt_id \
                AND outbox.receipt_decision = receipt.decision \
             JOIN dispatch_events AS event ON event.event_id = record.current_event_id \
                AND event.operation_id = record.operation_id \
                AND event.grant_id = record.grant_id \
                AND event.dispatch_attempt_id = record.dispatch_attempt_id \
                AND event.transition_generation = record.state_generation \
                AND event.effective_state = record.effective_state \
             LEFT JOIN dispatch_reconciliations AS reconciliation \
               ON reconciliation.reconciliation_id = record.reconciliation_id \
                AND reconciliation.grant_id = record.grant_id \
                AND reconciliation.operation_id = record.operation_id \
                AND reconciliation.dispatch_attempt_id = record.dispatch_attempt_id \
             WHERE record.operation_id = ?1 AND record.grant_id = ?2 \
               AND record.dispatch_attempt_id = ?5 \
               AND record.receipt_decision = 'CONSUMED' \
               AND receipt.receipt_id = ?3 AND receipt.receipt_digest = ?4 \
               AND receipt.decision = 'CONSUMED' \
               AND outbox.delivery_state = 'ACKNOWLEDGED' \
               AND outbox.current_attempt_generation = ?6 \
               AND event.decision = 'CONSUMED'",
            params![
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                candidate.receipt_id.as_slice(),
                candidate.receipt_digest.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(current_attempt_generation).ok()?,
            ],
            |row| {
                let state = row.get::<_, String>(0)?;
                Ok((
                    state,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .ok()
        .and_then(|row| {
            Some(CoordinatorReceiptCommitEvidenceV1 {
                receipt_id: candidate.receipt_id,
                receipt_digest: candidate.receipt_digest,
                effective_state: match row.0.as_str() {
                    "EXECUTING" => CoordinatorReceiptEffectiveStateV1::Executing,
                    "RECONCILIATION_REQUIRED" => {
                        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired
                    }
                    _ => return None,
                },
                state_generation: safe_u64_v1(row.1).ok()?,
                delivery_generation: safe_u64_v1(row.2).ok()?,
                receipt_generation: safe_u64_v1(row.3).ok()?,
                reconciliation_generation: row.4.map(safe_u64_v1).transpose().ok()?,
                event_generation: safe_u64_v1(row.5).ok()?,
            })
        })
}

fn load_current_receipt_context_v1(
    connection: &Connection,
    lookup: &CoordinatorReceiptLookupV1,
) -> Result<Option<CurrentReceiptContextV1>, ReceiptStageErrorV1> {
    let raw = connection
        .query_row(
            "SELECT record.effective_state, record.state_generation, record.current_event_id, \
                    grant.dispatch_attempt_id, grant.grant_digest, grant.canonical_grant, \
                    grant.canonical_grant_length, grant.task_id, grant.workload_id, grant.plan_id, \
                    grant.task_lease_digest, grant.destination_adapter_id, grant.protocol_version, \
                    outbox.delivery_state, outbox.delivery_generation, \
                    outbox.current_attempt_generation, record.reconciliation_id, \
                    record.reconciliation_result, reconciliation.transport_quiescence_digest, \
                    attempt.attempt_number, attempt.handoff_guard_digest, \
                    attempt.classification, attempt.adapter_root_digest, attempt.adapter_epoch, \
                    attempt.readback_generation \
             FROM dispatch_records AS record \
             JOIN dispatch_grants AS grant ON grant.grant_id = record.grant_id \
                AND grant.operation_id = record.operation_id \
                AND grant.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_outbox AS outbox ON outbox.grant_id = record.grant_id \
                AND outbox.operation_id = record.operation_id \
                AND outbox.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_delivery_attempts AS attempt \
                ON attempt.attempt_generation = outbox.current_attempt_generation \
                AND attempt.grant_id = outbox.grant_id \
                AND attempt.operation_id = outbox.operation_id \
                AND attempt.dispatch_attempt_id = outbox.dispatch_attempt_id \
             JOIN dispatch_transitions AS transition \
                ON transition.operation_id = record.operation_id \
                AND transition.grant_id = record.grant_id \
                AND transition.dispatch_attempt_id = record.dispatch_attempt_id \
                AND transition.state_generation = record.state_generation \
                AND transition.event_id = record.current_event_id \
                AND transition.new_state = record.effective_state \
             JOIN dispatch_events AS event ON event.event_id = record.current_event_id \
                AND event.transition_generation = record.state_generation \
                AND event.effective_state = record.effective_state \
             JOIN prepared_operations AS base ON base.operation_id = record.operation_id \
                AND base.operation_state = 'PREPARING' AND base.failed_generation IS NULL \
             JOIN budget_reservations AS reservation ON reservation.reservation_id = grant.reservation_id \
                AND reservation.operation_id = grant.operation_id \
                AND reservation.reservation_state = 'HELD' \
                AND reservation.released_generation IS NULL \
             JOIN dispatch_store_meta AS meta ON meta.singleton = 1 \
                AND meta.root_lifecycle_state = 'ACTIVE' \
             LEFT JOIN dispatch_reconciliations AS reconciliation \
                ON reconciliation.reconciliation_id = record.reconciliation_id \
             WHERE record.operation_id = ?1 AND record.grant_id = ?2",
            params![&*lookup.operation_id, lookup.grant_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Option<i64>>(15)?,
                    row.get::<_, Option<Vec<u8>>>(16)?,
                    row.get::<_, Option<String>>(17)?,
                    row.get::<_, Option<Vec<u8>>>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, Vec<u8>>(20)?,
                    row.get::<_, String>(21)?,
                    row.get::<_, Option<Vec<u8>>>(22)?,
                    row.get::<_, Option<i64>>(23)?,
                    row.get::<_, Option<i64>>(24)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    if usize::try_from(raw.6).ok() != Some(raw.5.len()) || raw.5.is_empty() {
        return Err(ReceiptStageErrorV1::Unhealthy);
    }
    let protocol_version = u8::try_from(raw.12).map_err(|_| ReceiptStageErrorV1::Unhealthy)?;
    let adapter_root_id = raw.22.map(exact_array_v1).transpose()?;
    let adapter_epoch = raw.23.map(safe_u64_v1).transpose()?;
    if adapter_root_id.is_some_and(|value| value == [0; 32])
        || adapter_root_id.is_some() != adapter_epoch.is_some()
    {
        return Err(ReceiptStageErrorV1::Unhealthy);
    }
    Ok(Some(CurrentReceiptContextV1 {
        state: DurableStateV1::decode(&raw.0).ok_or(ReceiptStageErrorV1::Unhealthy)?,
        state_generation: safe_u64_v1(raw.1)?,
        current_event_id: exact_array_v1(raw.2)?,
        dispatch_attempt_id: exact_array_v1(raw.3)?,
        grant_digest: exact_array_v1(raw.4)?,
        canonical_grant: raw.5.into_boxed_slice(),
        task_id: raw.7,
        workload_id: raw.8,
        plan_id: exact_array_v1(raw.9)?,
        task_lease_digest: exact_array_v1(raw.10)?,
        destination_adapter_id: raw.11,
        protocol_version,
        delivery_state: raw.13,
        delivery_generation: safe_u64_v1(raw.14)?,
        current_attempt_generation: raw.15.map(safe_u64_v1).transpose()?,
        current_attempt_number: safe_u64_v1(raw.19)?,
        current_handoff_guard_digest: exact_array_v1(raw.20)?,
        current_attempt_classification: raw.21,
        adapter_root_id,
        adapter_epoch,
        readback_generation: raw.24.map(safe_u64_v1).transpose()?,
        reconciliation_id: raw.16.map(exact_array_v1).transpose()?,
        reconciliation_result: raw.17,
        transport_quiescence_digest: raw.18.map(exact_array_v1).transpose()?,
    }))
}

fn sqlite_profile_is_exact_v1(connection: &Connection) -> Result<(), ReceiptStageErrorV1> {
    let profile = (
        pragma_i64_v1(connection, "application_id")?,
        pragma_i64_v1(connection, "user_version")?,
        pragma_i64_v1(connection, "foreign_keys")?,
        pragma_i64_v1(connection, "recursive_triggers")?,
    );
    if profile
        == (
            COORDINATOR_APPLICATION_ID_V1,
            COORDINATOR_DISPATCH_SCHEMA_VERSION_V2,
            1,
            1,
        )
    {
        Ok(())
    } else {
        Err(ReceiptStageErrorV1::Unhealthy)
    }
}

fn foreign_key_check_has_rows_v1(
    transaction: &Transaction<'_>,
) -> Result<bool, ReceiptStageErrorV1> {
    let mut statement = transaction
        .prepare("PRAGMA foreign_key_check")
        .map_err(map_sql_error_v1)?;
    let mut rows = statement.query([]).map_err(map_sql_error_v1)?;
    rows.next()
        .map(|row| row.is_some())
        .map_err(map_sql_error_v1)
}

fn pragma_i64_v1(connection: &Connection, pragma: &str) -> Result<i64, ReceiptStageErrorV1> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(map_sql_error_v1)
}

fn exact_array_v1(value: Vec<u8>) -> Result<[u8; 32], ReceiptStageErrorV1> {
    value.try_into().map_err(|_| ReceiptStageErrorV1::Unhealthy)
}

fn safe_u64_v1(value: i64) -> Result<u64, ReceiptStageErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64_V1)
        .ok_or(ReceiptStageErrorV1::Unhealthy)
}

fn next_safe_v1(value: u64) -> Result<u64, ReceiptStageErrorV1> {
    value
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_U64_V1)
        .ok_or(ReceiptStageErrorV1::Unhealthy)
}

fn to_i64_v1(value: u64) -> Result<i64, ReceiptStageErrorV1> {
    if value > MAX_SAFE_U64_V1 {
        return Err(ReceiptStageErrorV1::Unhealthy);
    }
    i64::try_from(value).map_err(|_| ReceiptStageErrorV1::Unhealthy)
}

fn map_sql_error_v1(error: rusqlite::Error) -> ReceiptStageErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy
                    | ErrorCode::DatabaseLocked
                    | ErrorCode::CannotOpen
                    | ErrorCode::ReadOnly
                    | ErrorCode::DiskFull
            ) =>
        {
            ReceiptStageErrorV1::Unavailable
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation
                && matches!(failure.extended_code, 1_555 | 2_067) =>
        {
            ReceiptStageErrorV1::Conflict
        }
        _ => ReceiptStageErrorV1::Unhealthy,
    }
}

fn outcome_from_error_v1(error: ReceiptStageErrorV1) -> CoordinatorReceiptCommitOutcomeV1 {
    match error {
        ReceiptStageErrorV1::Conflict => CoordinatorReceiptCommitOutcomeV1::Conflict,
        ReceiptStageErrorV1::Unavailable => CoordinatorReceiptCommitOutcomeV1::Unavailable,
        ReceiptStageErrorV1::Unhealthy => CoordinatorReceiptCommitOutcomeV1::Unhealthy,
    }
}

#[cfg(feature = "test-fault-injection")]
fn receipt_fault_injected_v1(
    fault_probe: &CoordinatorDispatchFaultProbeV1,
    boundary: FaultBoundaryV1,
) -> bool {
    fault_probe.injected_at_v1(boundary)
}

#[cfg(feature = "test-fault-injection")]
fn receipt_fault_checkpoint_v1(
    fault_probe: &CoordinatorDispatchFaultProbeV1,
    boundary: FaultBoundaryV1,
) -> Result<(), ReceiptStageErrorV1> {
    if receipt_fault_injected_v1(fault_probe, boundary) {
        Err(ReceiptStageErrorV1::Unavailable)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_stage_snapshot_refusal_is_called_second_and_rolls_back_every_mutation() {
        let mut connection = Connection::open_in_memory().expect("memory database opens");
        connection
            .execute_batch("CREATE TABLE receipt_stage_probe (member INTEGER NOT NULL) STRICT;")
            .expect("post-stage rollback probe creates");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("post-stage rollback transaction begins");
        let verification_calls = std::cell::Cell::new(0_u64);
        let mut verify_live_snapshot = |snapshot: &Connection| {
            let call = verification_calls.get() + 1;
            verification_calls.set(call);
            let members = snapshot
                .query_row("SELECT COUNT(*) FROM receipt_stage_probe", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("post-stage snapshot reads staged members");
            match call {
                1 => {
                    assert_eq!(members, 0, "initial verification must precede staging");
                    true
                }
                2 => {
                    assert_eq!(members, 1, "second verification must observe staged state");
                    false
                }
                _ => panic!("receipt snapshot was verified more than twice"),
            }
        };

        assert!(verify_live_snapshot(&transaction));
        assert_eq!(
            transaction
                .execute("INSERT INTO receipt_stage_probe VALUES (1)", [])
                .expect("one receipt member stages"),
            1
        );
        match retain_post_stage_verified_transaction_v1(transaction, &mut verify_live_snapshot) {
            Err(ReceiptStageErrorV1::Unhealthy) => {}
            Err(ReceiptStageErrorV1::Conflict | ReceiptStageErrorV1::Unavailable) => {
                panic!("post-stage snapshot refusal changed classification")
            }
            Ok(transaction) => {
                drop(transaction);
                panic!("post-stage snapshot refusal retained commit authority")
            }
        }
        assert_eq!(verification_calls.get(), 2);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM receipt_stage_probe", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("rolled-back receipt member count reads"),
            0,
            "post-stage refusal must leave no mutation",
        );
    }

    #[test]
    fn only_current_dispatching_consumption_can_enter_executing() {
        assert_eq!(
            target_state_v1(
                DurableStateV1::Dispatching,
                ExecutionReceiptDecisionV1::Consumed
            ),
            Some(CoordinatorReceiptEffectiveStateV1::Executing)
        );
        assert_eq!(
            target_state_v1(
                DurableStateV1::OutcomeUnknown,
                ExecutionReceiptDecisionV1::Consumed
            ),
            Some(CoordinatorReceiptEffectiveStateV1::ReconciliationRequired)
        );
        for state in [
            DurableStateV1::Executing,
            DurableStateV1::ReconciliationRequired,
        ] {
            assert_eq!(
                target_state_v1(state, ExecutionReceiptDecisionV1::Consumed),
                None
            );
        }
        for state in [
            DurableStateV1::Dispatching,
            DurableStateV1::OutcomeUnknown,
            DurableStateV1::Executing,
            DurableStateV1::ReconciliationRequired,
        ] {
            assert_eq!(
                target_state_v1(state, ExecutionReceiptDecisionV1::RefusedDefinite),
                None
            );
        }
    }

    #[test]
    fn event_and_reconciliation_identifiers_are_domain_separated() {
        let candidate = VerifiedReceiptCandidateV1 {
            canonical_receipt: vec![1_u8].into_boxed_slice(),
            receipt_id: [2_u8; 32],
            receipt_digest: [3_u8; 32],
            adapter_key_fingerprint: [4_u8; 32],
            adapter_root_id: [5_u8; 32],
            adapter_epoch: 1,
            trace_id: Box::from("trace-v1"),
        };
        let executing =
            derive_receipt_ids_v1(&candidate, CoordinatorReceiptEffectiveStateV1::Executing);
        let reconciliation = derive_receipt_ids_v1(
            &candidate,
            CoordinatorReceiptEffectiveStateV1::ReconciliationRequired,
        );
        assert_ne!(executing.event_id, executing.evidence_digest);
        assert_ne!(executing.event_id, reconciliation.event_id);
        assert!(executing.reconciliation_id.is_none());
        assert!(reconciliation.reconciliation_id.is_some());
    }
}
