//! Durable coordinator custody for ambiguous dispatch and exact definite refusal.
//!
//! The portable readback loop is deliberately not the durability boundary.  This module
//! first claims an ambiguous possible-handoff attempt by appending a new immutable delivery
//! attempt while leaving the record `DISPATCHING`, so a receipt recovered during bounded readback
//! can still advance to `EXECUTING`.  Only the fresh committed claim carries a non-cloneable
//! one-shot permit; reopening it after a crash returns custody without authorising another
//! automatic sequence.  Exhaustion then appends `DISPATCHING -> OUTCOME_UNKNOWN`, and explicit
//! closure appends `OUTCOME_UNKNOWN -> RECONCILIATION_REQUIRED`, each atomically.
//!
//! A definite refusal is stronger.  Exact retained grant and receipt bytes are verified again,
//! the portable fenced-absence proof is rebound to the current SQLite graph, and one transaction
//! retains the receipt/tombstone/reconciliation, completes the overlay chain, closes the PLAN-004
//! base operation, subtracts and releases the exact held reservation once, and appends both event
//! chains.  No caller-provided boolean or digest can by itself authorise that release.

#![allow(dead_code)] // Wired through SqliteCoordinatorStoreV2 by the T067 integration step.

use crate::dispatch_receipt::{
    commit_execution_receipt_v1, commit_late_reconciliation_consumed_receipt_v1,
    CoordinatorReceiptCommitOutcomeV1, CoordinatorReceiptLookupV1,
};
use helix_dispatch_contracts::{
    decode_and_verify_execution_receipt_v1, decode_and_verify_retained_execution_grant_v1,
    AuthenticExecutionReceiptV1, ExecutionReceiptDecisionV1, ExecutionReceiptRefusalCodeV1,
    GrantKeyResolver, ReceiptKeyResolver, ReceiptVerificationBindingsV1, Sha256Digest,
};
use helix_plan_dispatch::{
    classify_no_consumption_receipt_v1, DispatchAutomaticReadbackGateV1,
    DispatchDefiniteAbsenceProofV1, DispatchNoConsumptionTombstoneCustodyV1,
};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

const COORDINATOR_APPLICATION_ID_V1: i64 = 1_212_962_883;
const COORDINATOR_DISPATCH_SCHEMA_VERSION_V2: i64 = 2;
const MAX_SAFE_U64_V1: u64 = 9_007_199_254_740_991;
const MAX_RECEIPT_BYTES_V1: usize = 65_536;

const UNKNOWN_RECONCILIATION_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-UNKNOWN-RECONCILIATION\0V1\0";
const REFUSAL_RECONCILIATION_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-REFUSAL-RECONCILIATION\0V1\0";
const RECONCILIATION_EVENT_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-RECONCILIATION-EVENT\0V1\0";
const RECONCILIATION_EVIDENCE_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-RECONCILIATION-EVIDENCE\0V1\0";
const READBACK_CLAIM_GUARD_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-READBACK-CLAIM-GUARD\0V1\0";
const TRANSPORT_QUIESCENCE_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-TRANSPORT-QUIESCENCE\0V1\0";
const NO_INFLIGHT_PROOF_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-NO-INFLIGHT-PROOF\0V1\0";
const REFUSAL_GUARD_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-REFUSAL-GUARD\0V1\0";
const BASE_FAILED_EVENT_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-BASE-FAILED-EVENT\0V1\0";

/// Stable operation/grant identity for an ambiguous dispatch attempt.
///
/// Adapter-root authority is intentionally absent.  It is supplied separately by the trusted
/// readback claim and is reverified against any authentic receipt or fenced-absence proof.
pub struct CoordinatorReconciliationLookupV1 {
    operation_id: Box<str>,
    grant_id: [u8; 32],
}

impl CoordinatorReconciliationLookupV1 {
    pub fn try_new(
        operation_id: String,
        grant_id: [u8; 32],
    ) -> Result<Self, CoordinatorReconciliationLookupErrorV1> {
        if !valid_identifier_v1(&operation_id) || grant_id == [0; 32] {
            return Err(CoordinatorReconciliationLookupErrorV1::InvalidLookup);
        }
        Ok(Self {
            operation_id: operation_id.into_boxed_str(),
            grant_id,
        })
    }
}

impl fmt::Debug for CoordinatorReconciliationLookupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReconciliationLookupV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorReconciliationLookupErrorV1 {
    InvalidLookup,
}

/// Opaque readback-exhaustion evidence used only after the durable sequence claim.
///
/// This digest is custody, not a definite-absence proof.  Supplying any value here can move only
/// to unknown/reconciliation custody; it can never release budget or recovery authority.
pub struct CoordinatorReadbackExhaustionV1 {
    observation_digest: [u8; 32],
    public_trace_id: Box<str>,
    latency_ms: u64,
}

impl CoordinatorReadbackExhaustionV1 {
    pub fn try_new(
        observation_digest: [u8; 32],
        public_trace_id: String,
        latency_ms: u64,
    ) -> Result<Self, CoordinatorReadbackExhaustionErrorV1> {
        if observation_digest == [0; 32]
            || !valid_identifier_v1(&public_trace_id)
            || latency_ms > MAX_SAFE_U64_V1
        {
            return Err(CoordinatorReadbackExhaustionErrorV1::InvalidExhaustion);
        }
        Ok(Self {
            observation_digest,
            public_trace_id: public_trace_id.into_boxed_str(),
            latency_ms,
        })
    }
}

impl fmt::Debug for CoordinatorReadbackExhaustionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReadbackExhaustionV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorReadbackExhaustionErrorV1 {
    InvalidExhaustion,
}

/// Trusted adapter-root observation used to own the one bounded readback sequence.
pub struct CoordinatorReadbackSequenceClaimV1 {
    adapter_root_id: [u8; 32],
    adapter_epoch: u64,
}

impl CoordinatorReadbackSequenceClaimV1 {
    pub fn try_new(
        adapter_root_id: [u8; 32],
        adapter_epoch: u64,
    ) -> Result<Self, CoordinatorReadbackSequenceClaimErrorV1> {
        if adapter_root_id == [0; 32] || adapter_epoch > MAX_SAFE_U64_V1 {
            return Err(CoordinatorReadbackSequenceClaimErrorV1::InvalidClaim);
        }
        Ok(Self {
            adapter_root_id,
            adapter_epoch,
        })
    }
}

impl fmt::Debug for CoordinatorReadbackSequenceClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReadbackSequenceClaimV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorReadbackSequenceClaimErrorV1 {
    InvalidClaim,
}

/// Immutable SQLite claim which owns the one automatic readback sequence.
#[derive(Clone, PartialEq, Eq)]
pub struct CoordinatorReadbackSequenceClaimEvidenceV1 {
    claim_attempt_generation: u64,
    source_handoff_generation: u64,
    claim_guard_digest: [u8; 32],
    adapter_root_id: [u8; 32],
    adapter_epoch: u64,
}

/// In-memory authority to start the freshly committed automatic readback sequence once.
///
/// This permit is deliberately neither `Clone` nor reconstructible from persisted evidence.
/// Reopening a retained SQLite claim therefore yields `Resumed` without any authority to launch
/// a second automatic sequence.
pub struct CoordinatorAutomaticReadbackPermitV1 {
    source_handoff_generation: u64,
    begun: AtomicBool,
}

impl CoordinatorAutomaticReadbackPermitV1 {
    fn new_v1(source_handoff_generation: u64) -> Self {
        Self {
            source_handoff_generation,
            begun: AtomicBool::new(false),
        }
    }
}

impl fmt::Debug for CoordinatorAutomaticReadbackPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorAutomaticReadbackPermitV1")
            .finish_non_exhaustive()
    }
}

impl DispatchAutomaticReadbackGateV1 for CoordinatorAutomaticReadbackPermitV1 {
    fn try_begin_automatic_readback_once_v1(&self, delivery_attempt_generation: u64) -> bool {
        delivery_attempt_generation == self.source_handoff_generation
            && self
                .begun
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }
}

impl CoordinatorReadbackSequenceClaimEvidenceV1 {
    pub const fn claim_attempt_generation(&self) -> u64 {
        self.claim_attempt_generation
    }

    pub const fn source_handoff_generation(&self) -> u64 {
        self.source_handoff_generation
    }
}

impl fmt::Debug for CoordinatorReadbackSequenceClaimEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReadbackSequenceClaimEvidenceV1")
            .finish_non_exhaustive()
    }
}

pub enum CoordinatorReadbackSequenceClaimOutcomeV1 {
    Claimed {
        evidence: CoordinatorReadbackSequenceClaimEvidenceV1,
        permit: CoordinatorAutomaticReadbackPermitV1,
    },
    Resumed(CoordinatorReadbackSequenceClaimEvidenceV1),
    Uncertain,
    RejectedNoAdvance,
    Conflict,
    Unavailable,
    Unhealthy,
}

impl fmt::Debug for CoordinatorReadbackSequenceClaimOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Claimed { .. } => "CoordinatorReadbackSequenceClaimOutcomeV1::Claimed { .. }",
            Self::Resumed(_) => "CoordinatorReadbackSequenceClaimOutcomeV1::Resumed(..)",
            Self::Uncertain => "CoordinatorReadbackSequenceClaimOutcomeV1::Uncertain",
            Self::RejectedNoAdvance => {
                "CoordinatorReadbackSequenceClaimOutcomeV1::RejectedNoAdvance"
            }
            Self::Conflict => "CoordinatorReadbackSequenceClaimOutcomeV1::Conflict",
            Self::Unavailable => "CoordinatorReadbackSequenceClaimOutcomeV1::Unavailable",
            Self::Unhealthy => "CoordinatorReadbackSequenceClaimOutcomeV1::Unhealthy",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorReconciliationStateV1 {
    OutcomeUnknown,
    ReconciliationRequired,
}

/// Durable readback claim/reconciliation evidence, returned only from exact SQLite readback.
#[derive(Clone, PartialEq, Eq)]
pub struct CoordinatorReconciliationEvidenceV1 {
    reconciliation_id: [u8; 32],
    state: CoordinatorReconciliationStateV1,
    state_generation: u64,
    claim_attempt_generation: u64,
}

impl CoordinatorReconciliationEvidenceV1 {
    pub const fn reconciliation_id(&self) -> [u8; 32] {
        self.reconciliation_id
    }

    pub const fn state(&self) -> CoordinatorReconciliationStateV1 {
        self.state
    }

    pub const fn state_generation(&self) -> u64 {
        self.state_generation
    }

    /// Immutable delivery-attempt generation which owns the automatic readback claim.
    pub const fn claim_attempt_generation(&self) -> u64 {
        self.claim_attempt_generation
    }
}

impl fmt::Debug for CoordinatorReconciliationEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorReconciliationEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Closed result for durable claim and unknown-to-reconciliation transactions.
pub enum CoordinatorReconciliationOutcomeV1 {
    Committed(CoordinatorReconciliationEvidenceV1),
    Resumed(CoordinatorReconciliationEvidenceV1),
    Uncertain,
    RejectedNoAdvance,
    Conflict,
    Unavailable,
    Unhealthy,
}

impl fmt::Debug for CoordinatorReconciliationOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "CoordinatorReconciliationOutcomeV1::Committed(..)",
            Self::Resumed(_) => "CoordinatorReconciliationOutcomeV1::Resumed(..)",
            Self::Uncertain => "CoordinatorReconciliationOutcomeV1::Uncertain",
            Self::RejectedNoAdvance => "CoordinatorReconciliationOutcomeV1::RejectedNoAdvance",
            Self::Conflict => "CoordinatorReconciliationOutcomeV1::Conflict",
            Self::Unavailable => "CoordinatorReconciliationOutcomeV1::Unavailable",
            Self::Unhealthy => "CoordinatorReconciliationOutcomeV1::Unhealthy",
        })
    }
}

/// Exact terminal evidence for one signed definite refusal closure.
#[derive(Clone, PartialEq, Eq)]
pub struct CoordinatorDefiniteRefusalEvidenceV1 {
    receipt_id: [u8; 32],
    reconciliation_id: [u8; 32],
    guard_id: [u8; 32],
    refusal_transition_generation: u64,
    base_failure_transition_generation: u64,
    reservation_released_generation: u64,
}

impl CoordinatorDefiniteRefusalEvidenceV1 {
    pub const fn receipt_id(&self) -> [u8; 32] {
        self.receipt_id
    }

    pub const fn reconciliation_id(&self) -> [u8; 32] {
        self.reconciliation_id
    }

    pub const fn reservation_released_generation(&self) -> u64 {
        self.reservation_released_generation
    }
}

impl fmt::Debug for CoordinatorDefiniteRefusalEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDefiniteRefusalEvidenceV1")
            .finish_non_exhaustive()
    }
}

/// Exact receipt custody retained when COMMIT itself has no definite answer.
pub struct CoordinatorDefiniteRefusalUncertainCustodyV1 {
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
    canonical_receipt: Box<[u8]>,
    canonical_receipt_sha256: [u8; 32],
    no_inflight_proof_digest: [u8; 32],
}

impl CoordinatorDefiniteRefusalUncertainCustodyV1 {
    pub const fn receipt_id(&self) -> [u8; 32] {
        self.receipt_id
    }

    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    pub const fn canonical_receipt_sha256(&self) -> [u8; 32] {
        self.canonical_receipt_sha256
    }

    pub const fn no_inflight_proof_digest(&self) -> [u8; 32] {
        self.no_inflight_proof_digest
    }

    pub fn canonical_receipt_len(&self) -> usize {
        self.canonical_receipt.len()
    }
}

impl fmt::Debug for CoordinatorDefiniteRefusalUncertainCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDefiniteRefusalUncertainCustodyV1")
            .finish_non_exhaustive()
    }
}

pub enum CoordinatorDefiniteRefusalOutcomeV1 {
    Committed(CoordinatorDefiniteRefusalEvidenceV1),
    PriorExact(CoordinatorDefiniteRefusalEvidenceV1),
    Uncertain(CoordinatorDefiniteRefusalUncertainCustodyV1),
    RejectedNoAdvance,
    Conflict,
    Unavailable,
    Unhealthy,
}

impl fmt::Debug for CoordinatorDefiniteRefusalOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Committed(_) => "CoordinatorDefiniteRefusalOutcomeV1::Committed(..)",
            Self::PriorExact(_) => "CoordinatorDefiniteRefusalOutcomeV1::PriorExact(..)",
            Self::Uncertain(_) => "CoordinatorDefiniteRefusalOutcomeV1::Uncertain(..)",
            Self::RejectedNoAdvance => "CoordinatorDefiniteRefusalOutcomeV1::RejectedNoAdvance",
            Self::Conflict => "CoordinatorDefiniteRefusalOutcomeV1::Conflict",
            Self::Unavailable => "CoordinatorDefiniteRefusalOutcomeV1::Unavailable",
            Self::Unhealthy => "CoordinatorDefiniteRefusalOutcomeV1::Unhealthy",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableDispatchStateV1 {
    Dispatching,
    Executing,
    OutcomeUnknown,
    ReconciliationRequired,
    Failed,
}

impl DurableDispatchStateV1 {
    fn decode(value: &str) -> Option<Self> {
        match value {
            "DISPATCHING" => Some(Self::Dispatching),
            "EXECUTING" => Some(Self::Executing),
            "OUTCOME_UNKNOWN" => Some(Self::OutcomeUnknown),
            "RECONCILIATION_REQUIRED" => Some(Self::ReconciliationRequired),
            "FAILED" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct CurrentReconciliationContextV1 {
    state: DurableDispatchStateV1,
    state_generation: u64,
    current_event_id: [u8; 32],
    receipt_id: Option<[u8; 32]>,
    receipt_decision: Option<String>,
    reconciliation_id: Option<[u8; 32]>,
    reconciliation_result: Option<String>,
    dispatch_attempt_id: [u8; 32],
    grant_digest: [u8; 32],
    canonical_grant: Box<[u8]>,
    preparation_attempt_id: [u8; 32],
    plan_id: [u8; 32],
    task_id: String,
    workload_id: String,
    task_lease_digest: [u8; 32],
    reservation_id: String,
    destination_adapter_id: String,
    protocol_version: u8,
    outbox_state: String,
    delivery_generation: u64,
    current_attempt_generation: u64,
    deadline_monotonic_ms: u64,
    current_attempt_number: u64,
    current_handoff_guard_digest: [u8; 32],
    current_attempt_classification: String,
    current_adapter_root_id: Option<[u8; 32]>,
    current_adapter_epoch: Option<u64>,
    current_readback_generation: Option<u64>,
    initial_handoff_generation: u64,
    base_operation_state: String,
    base_state_generation: u64,
    base_current_event_id: [u8; 32],
    base_failed_generation: Option<u64>,
    base_failed_reason_code: Option<String>,
    reservation_state: String,
    reservation_released_generation: Option<u64>,
    scope_id: [u8; 32],
    reserved: [u64; 4],
    held: [u64; 4],
}

struct VerifiedRefusalCandidateV1 {
    canonical_receipt: Box<[u8]>,
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
    adapter_key_fingerprint: [u8; 32],
    refusal_code: ExecutionReceiptRefusalCodeV1,
    refusal_code_text: &'static str,
    no_consumption_tombstone_digest: [u8; 32],
    observed_supervisor_epoch: u64,
    trace_id: Box<str>,
}

#[derive(Clone, Copy)]
struct UnknownIdsV1 {
    reconciliation_id: [u8; 32],
    evidence_digest: [u8; 32],
    event_id: [u8; 32],
    transport_observation_digest: [u8; 32],
}

struct PersistedUnknownExhaustionV1 {
    reconciliation_id: [u8; 32],
    reconciliation_evidence_digest: [u8; 32],
    transport_observation_digest: [u8; 32],
    transition_evidence_digest: [u8; 32],
    event_id: [u8; 32],
    public_trace_id: String,
    latency_ms: u64,
}

#[derive(Clone, Copy)]
struct RefusalIdsV1 {
    unknown_reconciliation_id: [u8; 32],
    unknown_evidence_digest: [u8; 32],
    unknown_event_id: [u8; 32],
    reconciliation_id: [u8; 32],
    reconciliation_evidence_digest: [u8; 32],
    reconciliation_event_id: [u8; 32],
    failed_event_id: [u8; 32],
    base_failed_event_id: [u8; 32],
    transport_quiescence_digest: [u8; 32],
    no_inflight_proof_digest: [u8; 32],
    quiesced_handoff_guard_digest: [u8; 32],
    guard_id: [u8; 32],
}

#[derive(Clone, Copy)]
struct DispatchMetaV1 {
    store: u64,
    dispatch: u64,
    delivery: u64,
    receipt: u64,
    reconciliation: u64,
    event: u64,
}

#[derive(Clone, Copy)]
struct BaseMetaV1 {
    store: u64,
    operation: u64,
    budget: u64,
    event: u64,
}

#[derive(Clone, Copy)]
struct UnknownGenerationsV1 {
    previous: DispatchMetaV1,
    final_store: u64,
    state: u64,
    reconciliation: u64,
    event: u64,
}

#[derive(Clone, Copy)]
struct SequenceClaimGenerationsV1 {
    previous: DispatchMetaV1,
    final_store: u64,
    delivery: u64,
}

#[derive(Clone, Copy)]
struct RequiredGenerationsV1 {
    previous: DispatchMetaV1,
    final_store: u64,
    state: u64,
    event: u64,
}

struct RefusalGenerationsV1 {
    dispatch_previous: DispatchMetaV1,
    base_previous: BaseMetaV1,
    dispatch_final_store: u64,
    state: Vec<u64>,
    event: Vec<u64>,
    delivery: u64,
    receipt: u64,
    unknown_reconciliation: Option<u64>,
    refusal_reconciliation: u64,
    base_store: u64,
    base_operation: u64,
    base_budget: u64,
    base_event: u64,
}

#[derive(Clone, Copy)]
enum ReconciliationStageErrorV1 {
    Rejected,
    Conflict,
    Unavailable,
    Unhealthy,
    Injected,
}

#[derive(Clone, Copy)]
enum RefusalCheckpointV1 {
    Begin,
    Receipt,
    UnknownTransition,
    UnknownEvent,
    RequiredTransition,
    RequiredEvent,
    Reconciliation,
    FencedProof,
    Tombstone,
    BaseTransition,
    Reservation,
    BaseEvent,
    FailedTransition,
    FailedEvent,
    Outbox,
    FinalRecord,
    Metadata,
    BeforeCommit,
    AfterCommit,
}

trait RefusalFaultProbeV1 {
    fn checkpoint_v1(
        &self,
        checkpoint: RefusalCheckpointV1,
    ) -> Result<(), ReconciliationStageErrorV1>;
}

struct DisabledRefusalFaultProbeV1;

impl RefusalFaultProbeV1 for DisabledRefusalFaultProbeV1 {
    fn checkpoint_v1(
        &self,
        _checkpoint: RefusalCheckpointV1,
    ) -> Result<(), ReconciliationStageErrorV1> {
        Ok(())
    }
}

#[cfg(feature = "test-fault-injection")]
struct SelectedRefusalFaultProbeV1<'probe>(
    &'probe crate::dispatch_fault::CoordinatorDispatchFaultProbeV1,
);

#[cfg(feature = "test-fault-injection")]
impl RefusalFaultProbeV1 for SelectedRefusalFaultProbeV1<'_> {
    fn checkpoint_v1(
        &self,
        checkpoint: RefusalCheckpointV1,
    ) -> Result<(), ReconciliationStageErrorV1> {
        use crate::dispatch_fault::FaultBoundaryV1;
        let injected = match checkpoint {
            RefusalCheckpointV1::Begin => self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb053),
            RefusalCheckpointV1::Receipt => self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb054),
            RefusalCheckpointV1::UnknownTransition => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb055)
            }
            RefusalCheckpointV1::UnknownEvent => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb056)
            }
            RefusalCheckpointV1::RequiredTransition => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb057)
            }
            RefusalCheckpointV1::RequiredEvent => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb058)
            }
            RefusalCheckpointV1::Reconciliation => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb059)
            }
            RefusalCheckpointV1::FencedProof => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb060)
            }
            RefusalCheckpointV1::Tombstone => self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb061),
            RefusalCheckpointV1::BaseTransition => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb062)
            }
            RefusalCheckpointV1::Reservation => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb063)
            }
            RefusalCheckpointV1::BaseEvent => self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb064),
            RefusalCheckpointV1::FailedTransition => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb065)
            }
            RefusalCheckpointV1::FailedEvent => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb066)
            }
            RefusalCheckpointV1::Outbox => self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb067),
            RefusalCheckpointV1::FinalRecord => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb068)
            }
            RefusalCheckpointV1::Metadata => self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb069),
            RefusalCheckpointV1::BeforeCommit => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb070)
            }
            RefusalCheckpointV1::AfterCommit => {
                self.0.injected_at_v1(FaultBoundaryV1::Plan005Fb071)
            }
        };
        if injected {
            Err(ReconciliationStageErrorV1::Injected)
        } else {
            Ok(())
        }
    }
}

fn valid_identifier_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:".contains(&byte))
}

fn exact_array_v1(value: Vec<u8>) -> Result<[u8; 32], ReconciliationStageErrorV1> {
    value
        .try_into()
        .map_err(|_| ReconciliationStageErrorV1::Unhealthy)
}

fn optional_exact_array_v1(
    value: Option<Vec<u8>>,
) -> Result<Option<[u8; 32]>, ReconciliationStageErrorV1> {
    value.map(exact_array_v1).transpose()
}

fn safe_u64_v1(value: i64) -> Result<u64, ReconciliationStageErrorV1> {
    let value = u64::try_from(value).map_err(|_| ReconciliationStageErrorV1::Unhealthy)?;
    if value > MAX_SAFE_U64_V1 {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    Ok(value)
}

fn optional_safe_u64_v1(value: Option<i64>) -> Result<Option<u64>, ReconciliationStageErrorV1> {
    value.map(safe_u64_v1).transpose()
}

fn to_i64_v1(value: u64) -> Result<i64, ReconciliationStageErrorV1> {
    if value > MAX_SAFE_U64_V1 {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    i64::try_from(value).map_err(|_| ReconciliationStageErrorV1::Unhealthy)
}

fn next_safe_v1(value: u64) -> Result<u64, ReconciliationStageErrorV1> {
    value
        .checked_add(1)
        .filter(|next| *next <= MAX_SAFE_U64_V1)
        .ok_or(ReconciliationStageErrorV1::Unhealthy)
}

fn digest_parts_v1(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn map_sql_error_v1(error: rusqlite::Error) -> ReconciliationStageErrorV1 {
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
            ReconciliationStageErrorV1::Unavailable
        }
        _ => ReconciliationStageErrorV1::Unhealthy,
    }
}

fn sqlite_profile_is_exact_v1(connection: &Connection) -> Result<(), ReconciliationStageErrorV1> {
    let application_id: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(map_sql_error_v1)?;
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(map_sql_error_v1)?;
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(map_sql_error_v1)?;
    let recursive_triggers: i64 = connection
        .pragma_query_value(None, "recursive_triggers", |row| row.get(0))
        .map_err(map_sql_error_v1)?;
    let active_roots: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM dispatch_store_meta AS dispatch_meta \
             JOIN coordinator_store_meta AS base_meta ON base_meta.singleton = 1 \
             WHERE dispatch_meta.singleton = 1 \
               AND dispatch_meta.root_lifecycle_state = 'ACTIVE' \
               AND base_meta.root_lifecycle_state = 'ACTIVE'",
            [],
            |row| row.get(0),
        )
        .map_err(map_sql_error_v1)?;
    if application_id == COORDINATOR_APPLICATION_ID_V1
        && user_version == COORDINATOR_DISPATCH_SCHEMA_VERSION_V2
        && foreign_keys == 1
        && recursive_triggers == 1
        && active_roots == 1
    {
        Ok(())
    } else {
        Err(ReconciliationStageErrorV1::Unhealthy)
    }
}

fn foreign_key_check_has_rows_v1(
    connection: &Connection,
) -> Result<bool, ReconciliationStageErrorV1> {
    connection
        .prepare("PRAGMA foreign_key_check")
        .and_then(|mut statement| statement.exists([]))
        .map_err(map_sql_error_v1)
}

fn load_current_context_v1(
    connection: &Connection,
    lookup: &CoordinatorReconciliationLookupV1,
) -> Result<Option<CurrentReconciliationContextV1>, ReconciliationStageErrorV1> {
    struct RawV1 {
        state: String,
        state_generation: i64,
        current_event_id: Vec<u8>,
        receipt_id: Option<Vec<u8>>,
        receipt_decision: Option<String>,
        reconciliation_id: Option<Vec<u8>>,
        reconciliation_result: Option<String>,
        dispatch_attempt_id: Vec<u8>,
        grant_digest: Vec<u8>,
        canonical_grant: Vec<u8>,
        canonical_grant_length: i64,
        preparation_attempt_id: Vec<u8>,
        plan_id: Vec<u8>,
        task_id: String,
        workload_id: String,
        task_lease_digest: Vec<u8>,
        reservation_id: String,
        destination_adapter_id: String,
        protocol_version: i64,
        outbox_state: String,
        delivery_generation: i64,
        current_attempt_generation: i64,
        deadline_monotonic_ms: i64,
        current_attempt_number: i64,
        current_handoff_guard_digest: Vec<u8>,
        current_attempt_classification: String,
        initial_handoff_generation: i64,
        base_operation_state: String,
        base_state_generation: i64,
        base_current_event_id: Vec<u8>,
        base_failed_generation: Option<i64>,
        base_failed_reason_code: Option<String>,
        reservation_state: String,
        reservation_released_generation: Option<i64>,
        scope_id: Vec<u8>,
        reserved: [i64; 4],
        held: [i64; 4],
        current_adapter_root_id: Option<Vec<u8>>,
        current_adapter_epoch: Option<i64>,
        current_readback_generation: Option<i64>,
    }

    let raw = connection
        .query_row(
            "SELECT record.effective_state, record.state_generation, record.current_event_id, \
                    record.receipt_id, record.receipt_decision, record.reconciliation_id, \
                    record.reconciliation_result, grant.dispatch_attempt_id, grant.grant_digest, \
                    grant.canonical_grant, grant.canonical_grant_length, \
                    grant.preparation_attempt_id, grant.plan_id, grant.task_id, grant.workload_id, \
                    grant.task_lease_digest, grant.reservation_id, grant.destination_adapter_id, \
                    grant.protocol_version, outbox.delivery_state, outbox.delivery_generation, \
                    outbox.current_attempt_generation, outbox.deadline_monotonic_ms, \
                    (SELECT MAX(numbered.attempt_number) \
                       FROM dispatch_delivery_attempts AS numbered \
                      WHERE numbered.grant_id = grant.grant_id \
                        AND numbered.operation_id = grant.operation_id \
                        AND numbered.dispatch_attempt_id = grant.dispatch_attempt_id), \
                    attempt.handoff_guard_digest, \
                    attempt.classification, \
                    (SELECT MIN(source.attempt_generation) \
                       FROM dispatch_delivery_attempts AS source \
                      WHERE source.grant_id = grant.grant_id \
                        AND source.operation_id = grant.operation_id \
                        AND source.dispatch_attempt_id = grant.dispatch_attempt_id \
                        AND source.classification = 'POSSIBLE_HANDOFF' \
                        AND source.adapter_root_digest IS NULL \
                        AND source.adapter_epoch IS NULL \
                        AND source.readback_generation IS NULL), \
                    operation.operation_state, operation.state_generation, \
                    operation.current_event_id, operation.failed_generation, \
                    operation.failed_reason_code, reservation.reservation_state, \
                    reservation.released_generation, reservation.scope_id, \
                    reservation.reserved_cost_micro_units, \
                    reservation.reserved_action_count, reservation.reserved_egress_bytes, \
                    reservation.reserved_recovery_bytes, scope.held_cost_micro_units, \
                    scope.held_action_count, scope.held_egress_bytes, \
                    scope.held_recovery_bytes, attempt.adapter_root_digest, \
                    attempt.adapter_epoch, attempt.readback_generation \
             FROM dispatch_records AS record \
             JOIN dispatch_grants AS grant \
               ON grant.grant_id = record.grant_id \
              AND grant.operation_id = record.operation_id \
              AND grant.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = grant.grant_id \
              AND outbox.operation_id = grant.operation_id \
              AND outbox.dispatch_attempt_id = grant.dispatch_attempt_id \
             JOIN dispatch_delivery_attempts AS attempt \
               ON attempt.attempt_generation = outbox.current_attempt_generation \
              AND attempt.grant_id = grant.grant_id \
              AND attempt.operation_id = grant.operation_id \
              AND attempt.dispatch_attempt_id = grant.dispatch_attempt_id \
             JOIN prepared_operations AS operation \
               ON operation.operation_id = grant.operation_id \
              AND operation.attempt_id = grant.preparation_attempt_id \
              AND operation.plan_id = grant.plan_id \
              AND operation.task_id = grant.task_id \
              AND operation.workload_id = grant.workload_id \
             JOIN budget_reservations AS reservation \
               ON reservation.reservation_id = grant.reservation_id \
              AND reservation.operation_id = grant.operation_id \
              AND reservation.attempt_id = grant.preparation_attempt_id \
              AND reservation.plan_id = grant.plan_id \
              AND reservation.task_lease_digest = grant.task_lease_digest \
             JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id \
             WHERE record.operation_id = ?1 AND record.grant_id = ?2",
            params![&*lookup.operation_id, lookup.grant_id.as_slice()],
            |row| {
                Ok(RawV1 {
                    state: row.get(0)?,
                    state_generation: row.get(1)?,
                    current_event_id: row.get(2)?,
                    receipt_id: row.get(3)?,
                    receipt_decision: row.get(4)?,
                    reconciliation_id: row.get(5)?,
                    reconciliation_result: row.get(6)?,
                    dispatch_attempt_id: row.get(7)?,
                    grant_digest: row.get(8)?,
                    canonical_grant: row.get(9)?,
                    canonical_grant_length: row.get(10)?,
                    preparation_attempt_id: row.get(11)?,
                    plan_id: row.get(12)?,
                    task_id: row.get(13)?,
                    workload_id: row.get(14)?,
                    task_lease_digest: row.get(15)?,
                    reservation_id: row.get(16)?,
                    destination_adapter_id: row.get(17)?,
                    protocol_version: row.get(18)?,
                    outbox_state: row.get(19)?,
                    delivery_generation: row.get(20)?,
                    current_attempt_generation: row.get(21)?,
                    deadline_monotonic_ms: row.get(22)?,
                    current_attempt_number: row.get(23)?,
                    current_handoff_guard_digest: row.get(24)?,
                    current_attempt_classification: row.get(25)?,
                    initial_handoff_generation: row.get(26)?,
                    base_operation_state: row.get(27)?,
                    base_state_generation: row.get(28)?,
                    base_current_event_id: row.get(29)?,
                    base_failed_generation: row.get(30)?,
                    base_failed_reason_code: row.get(31)?,
                    reservation_state: row.get(32)?,
                    reservation_released_generation: row.get(33)?,
                    scope_id: row.get(34)?,
                    reserved: [row.get(35)?, row.get(36)?, row.get(37)?, row.get(38)?],
                    held: [row.get(39)?, row.get(40)?, row.get(41)?, row.get(42)?],
                    current_adapter_root_id: row.get(43)?,
                    current_adapter_epoch: row.get(44)?,
                    current_readback_generation: row.get(45)?,
                })
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.canonical_grant.is_empty()
        || raw.canonical_grant.len() > 1_048_576
        || safe_u64_v1(raw.canonical_grant_length)?
            != u64::try_from(raw.canonical_grant.len())
                .map_err(|_| ReconciliationStageErrorV1::Unhealthy)?
        || raw.protocol_version != 1
    {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    let safe_vector = |values: [i64; 4]| {
        Ok::<[u64; 4], ReconciliationStageErrorV1>([
            safe_u64_v1(values[0])?,
            safe_u64_v1(values[1])?,
            safe_u64_v1(values[2])?,
            safe_u64_v1(values[3])?,
        ])
    };
    Ok(Some(CurrentReconciliationContextV1 {
        state: DurableDispatchStateV1::decode(&raw.state)
            .ok_or(ReconciliationStageErrorV1::Unhealthy)?,
        state_generation: safe_u64_v1(raw.state_generation)?,
        current_event_id: exact_array_v1(raw.current_event_id)?,
        receipt_id: optional_exact_array_v1(raw.receipt_id)?,
        receipt_decision: raw.receipt_decision,
        reconciliation_id: optional_exact_array_v1(raw.reconciliation_id)?,
        reconciliation_result: raw.reconciliation_result,
        dispatch_attempt_id: exact_array_v1(raw.dispatch_attempt_id)?,
        grant_digest: exact_array_v1(raw.grant_digest)?,
        canonical_grant: raw.canonical_grant.into_boxed_slice(),
        preparation_attempt_id: exact_array_v1(raw.preparation_attempt_id)?,
        plan_id: exact_array_v1(raw.plan_id)?,
        task_id: raw.task_id,
        workload_id: raw.workload_id,
        task_lease_digest: exact_array_v1(raw.task_lease_digest)?,
        reservation_id: raw.reservation_id,
        destination_adapter_id: raw.destination_adapter_id,
        protocol_version: u8::try_from(raw.protocol_version)
            .map_err(|_| ReconciliationStageErrorV1::Unhealthy)?,
        outbox_state: raw.outbox_state,
        delivery_generation: safe_u64_v1(raw.delivery_generation)?,
        current_attempt_generation: safe_u64_v1(raw.current_attempt_generation)?,
        deadline_monotonic_ms: safe_u64_v1(raw.deadline_monotonic_ms)?,
        current_attempt_number: safe_u64_v1(raw.current_attempt_number)?,
        current_handoff_guard_digest: exact_array_v1(raw.current_handoff_guard_digest)?,
        current_attempt_classification: raw.current_attempt_classification,
        current_adapter_root_id: optional_exact_array_v1(raw.current_adapter_root_id)?,
        current_adapter_epoch: optional_safe_u64_v1(raw.current_adapter_epoch)?,
        current_readback_generation: optional_safe_u64_v1(raw.current_readback_generation)?,
        initial_handoff_generation: safe_u64_v1(raw.initial_handoff_generation)?,
        base_operation_state: raw.base_operation_state,
        base_state_generation: safe_u64_v1(raw.base_state_generation)?,
        base_current_event_id: exact_array_v1(raw.base_current_event_id)?,
        base_failed_generation: optional_safe_u64_v1(raw.base_failed_generation)?,
        base_failed_reason_code: raw.base_failed_reason_code,
        reservation_state: raw.reservation_state,
        reservation_released_generation: optional_safe_u64_v1(raw.reservation_released_generation)?,
        scope_id: exact_array_v1(raw.scope_id)?,
        reserved: safe_vector(raw.reserved)?,
        held: safe_vector(raw.held)?,
    }))
}

fn load_dispatch_meta_v1(
    connection: &Connection,
) -> Result<DispatchMetaV1, ReconciliationStageErrorV1> {
    let raw: (i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT dispatch_store_generation, dispatch_generation, delivery_generation, \
                    receipt_generation, reconciliation_generation, event_generation \
             FROM dispatch_store_meta \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
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
    let meta = DispatchMetaV1 {
        store: safe_u64_v1(raw.0)?,
        dispatch: safe_u64_v1(raw.1)?,
        delivery: safe_u64_v1(raw.2)?,
        receipt: safe_u64_v1(raw.3)?,
        reconciliation: safe_u64_v1(raw.4)?,
        event: safe_u64_v1(raw.5)?,
    };
    if [
        meta.dispatch,
        meta.delivery,
        meta.receipt,
        meta.reconciliation,
        meta.event,
    ]
    .iter()
    .any(|axis| *axis > meta.store)
    {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    Ok(meta)
}

fn load_base_meta_v1(connection: &Connection) -> Result<BaseMetaV1, ReconciliationStageErrorV1> {
    let raw: (i64, i64, i64, i64) = connection
        .query_row(
            "SELECT store_generation, operation_generation, budget_generation, event_generation \
             FROM coordinator_store_meta \
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(map_sql_error_v1)?;
    let meta = BaseMetaV1 {
        store: safe_u64_v1(raw.0)?,
        operation: safe_u64_v1(raw.1)?,
        budget: safe_u64_v1(raw.2)?,
        event: safe_u64_v1(raw.3)?,
    };
    if [meta.operation, meta.budget, meta.event]
        .iter()
        .any(|axis| *axis > meta.store)
    {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    Ok(meta)
}

fn derive_unknown_ids_v1(
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    exhaustion: &CoordinatorReadbackExhaustionV1,
) -> UnknownIdsV1 {
    derive_unknown_ids_from_bindings_v1(
        &lookup.operation_id,
        lookup.grant_id,
        context.dispatch_attempt_id,
        context.current_handoff_guard_digest,
        exhaustion,
    )
}

fn derive_unknown_ids_from_bindings_v1(
    operation_id: &str,
    grant_id: [u8; 32],
    dispatch_attempt_id: [u8; 32],
    current_handoff_guard_digest: [u8; 32],
    exhaustion: &CoordinatorReadbackExhaustionV1,
) -> UnknownIdsV1 {
    let transport_observation_digest = digest_parts_v1(
        TRANSPORT_QUIESCENCE_DOMAIN_V1,
        &[
            operation_id.as_bytes(),
            &grant_id,
            &dispatch_attempt_id,
            &current_handoff_guard_digest,
            &exhaustion.observation_digest,
        ],
    );
    let reconciliation_id = digest_parts_v1(
        UNKNOWN_RECONCILIATION_DOMAIN_V1,
        &[
            operation_id.as_bytes(),
            &grant_id,
            &dispatch_attempt_id,
            &transport_observation_digest,
        ],
    );
    let evidence_digest = digest_parts_v1(
        RECONCILIATION_EVIDENCE_DOMAIN_V1,
        &[&reconciliation_id, b"OUTCOME_UNKNOWN"],
    );
    let event_id = digest_parts_v1(
        RECONCILIATION_EVENT_DOMAIN_V1,
        &[&reconciliation_id, b"OUTCOME_UNKNOWN"],
    );
    UnknownIdsV1 {
        reconciliation_id,
        evidence_digest,
        event_id,
        transport_observation_digest,
    }
}

fn derive_sequence_claim_guard_v1(
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    claim: &CoordinatorReadbackSequenceClaimV1,
) -> [u8; 32] {
    digest_parts_v1(
        READBACK_CLAIM_GUARD_DOMAIN_V1,
        &[
            lookup.operation_id.as_bytes(),
            &lookup.grant_id,
            &context.dispatch_attempt_id,
            &context.current_handoff_guard_digest,
            &context.initial_handoff_generation.to_be_bytes(),
            &claim.adapter_root_id,
            &claim.adapter_epoch.to_be_bytes(),
            b"AUTOMATIC_READBACK_SEQUENCE",
        ],
    )
}

fn allocate_sequence_claim_generations_v1(
    connection: &Connection,
) -> Result<SequenceClaimGenerationsV1, ReconciliationStageErrorV1> {
    let previous = load_dispatch_meta_v1(connection)?;
    let final_store = next_safe_v1(previous.store)?;
    let delivery = final_store;
    Ok(SequenceClaimGenerationsV1 {
        previous,
        final_store,
        delivery,
    })
}

fn allocate_unknown_generations_v1(
    connection: &Connection,
) -> Result<UnknownGenerationsV1, ReconciliationStageErrorV1> {
    let meta = load_dispatch_meta_v1(connection)?;
    let final_store = next_safe_v1(meta.store)?;
    let state = final_store;
    let reconciliation = final_store;
    let event = final_store;
    Ok(UnknownGenerationsV1 {
        previous: meta,
        final_store,
        state,
        reconciliation,
        event,
    })
}

fn load_readback_sequence_claim_v1(
    connection: &Connection,
    lookup: &CoordinatorReconciliationLookupV1,
) -> Result<Option<CoordinatorReadbackSequenceClaimEvidenceV1>, ReconciliationStageErrorV1> {
    let claim_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) \
             FROM dispatch_delivery_attempts AS claim \
             JOIN dispatch_delivery_attempts AS source \
               ON source.attempt_generation = claim.readback_generation \
              AND source.grant_id = claim.grant_id \
              AND source.operation_id = claim.operation_id \
              AND source.dispatch_attempt_id = claim.dispatch_attempt_id \
             WHERE claim.operation_id = ?1 AND claim.grant_id = ?2 \
               AND source.classification = 'POSSIBLE_HANDOFF' \
               AND source.adapter_root_digest IS NULL AND source.adapter_epoch IS NULL \
               AND source.readback_generation IS NULL \
               AND claim.classification = 'POSSIBLE_HANDOFF' \
               AND typeof(claim.adapter_root_digest) = 'blob' \
               AND length(claim.adapter_root_digest) = 32 \
               AND claim.adapter_epoch IS NOT NULL \
               AND claim.readback_generation = source.attempt_generation \
               AND source.attempt_generation = ( \
                   SELECT MIN(first_handoff.attempt_generation) \
                   FROM dispatch_delivery_attempts AS first_handoff \
                   WHERE first_handoff.grant_id = claim.grant_id \
                     AND first_handoff.operation_id = claim.operation_id \
                     AND first_handoff.dispatch_attempt_id = claim.dispatch_attempt_id \
                     AND first_handoff.classification = 'POSSIBLE_HANDOFF' \
                     AND first_handoff.adapter_root_digest IS NULL \
                     AND first_handoff.adapter_epoch IS NULL \
                     AND first_handoff.readback_generation IS NULL)",
            params![&*lookup.operation_id, lookup.grant_id.as_slice()],
            |row| row.get(0),
        )
        .map_err(map_sql_error_v1)?;
    match claim_count {
        0 => return Ok(None),
        1 => {}
        _ => return Err(ReconciliationStageErrorV1::Unhealthy),
    }

    struct RawClaimV1 {
        claim_attempt_generation: i64,
        source_handoff_generation: i64,
        claim_guard_digest: Vec<u8>,
        adapter_root_id: Vec<u8>,
        adapter_epoch: i64,
        claim_attempt_number: i64,
        source_attempt_number: i64,
        source_handoff_guard_digest: Vec<u8>,
        dispatch_attempt_id: Vec<u8>,
    }

    let raw = connection
        .query_row(
            "SELECT claim.attempt_generation, source.attempt_generation, \
                    claim.handoff_guard_digest, claim.adapter_root_digest, \
                    claim.adapter_epoch, claim.attempt_number, source.attempt_number, \
                    source.handoff_guard_digest, claim.dispatch_attempt_id \
             FROM dispatch_delivery_attempts AS claim \
             JOIN dispatch_delivery_attempts AS source \
               ON source.attempt_generation = claim.readback_generation \
              AND source.grant_id = claim.grant_id \
              AND source.operation_id = claim.operation_id \
              AND source.dispatch_attempt_id = claim.dispatch_attempt_id \
             WHERE claim.operation_id = ?1 AND claim.grant_id = ?2 \
               AND source.classification = 'POSSIBLE_HANDOFF' \
               AND source.adapter_root_digest IS NULL AND source.adapter_epoch IS NULL \
               AND source.readback_generation IS NULL \
               AND claim.classification = 'POSSIBLE_HANDOFF' \
               AND typeof(claim.adapter_root_digest) = 'blob' \
               AND length(claim.adapter_root_digest) = 32 \
               AND claim.adapter_epoch IS NOT NULL \
               AND claim.readback_generation = source.attempt_generation \
               AND source.attempt_generation = ( \
                   SELECT MIN(first_handoff.attempt_generation) \
                   FROM dispatch_delivery_attempts AS first_handoff \
                   WHERE first_handoff.grant_id = claim.grant_id \
                     AND first_handoff.operation_id = claim.operation_id \
                     AND first_handoff.dispatch_attempt_id = claim.dispatch_attempt_id \
                     AND first_handoff.classification = 'POSSIBLE_HANDOFF' \
                     AND first_handoff.adapter_root_digest IS NULL \
                     AND first_handoff.adapter_epoch IS NULL \
                     AND first_handoff.readback_generation IS NULL)",
            params![&*lookup.operation_id, lookup.grant_id.as_slice()],
            |row| {
                Ok(RawClaimV1 {
                    claim_attempt_generation: row.get(0)?,
                    source_handoff_generation: row.get(1)?,
                    claim_guard_digest: row.get(2)?,
                    adapter_root_id: row.get(3)?,
                    adapter_epoch: row.get(4)?,
                    claim_attempt_number: row.get(5)?,
                    source_attempt_number: row.get(6)?,
                    source_handoff_guard_digest: row.get(7)?,
                    dispatch_attempt_id: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?
        .ok_or(ReconciliationStageErrorV1::Unhealthy)?;

    let claim_attempt_generation = safe_u64_v1(raw.claim_attempt_generation)?;
    let source_handoff_generation = safe_u64_v1(raw.source_handoff_generation)?;
    let claim_guard_digest = exact_array_v1(raw.claim_guard_digest)?;
    let adapter_root_id = exact_array_v1(raw.adapter_root_id)?;
    let adapter_epoch = safe_u64_v1(raw.adapter_epoch)?;
    let claim_attempt_number = safe_u64_v1(raw.claim_attempt_number)?;
    let source_attempt_number = safe_u64_v1(raw.source_attempt_number)?;
    let source_handoff_guard_digest = exact_array_v1(raw.source_handoff_guard_digest)?;
    let dispatch_attempt_id = exact_array_v1(raw.dispatch_attempt_id)?;
    if adapter_root_id == [0; 32]
        || claim_attempt_generation <= source_handoff_generation
        || claim_attempt_number != next_safe_v1(source_attempt_number)?
    {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    let expected_guard = digest_parts_v1(
        READBACK_CLAIM_GUARD_DOMAIN_V1,
        &[
            lookup.operation_id.as_bytes(),
            &lookup.grant_id,
            &dispatch_attempt_id,
            &source_handoff_guard_digest,
            &source_handoff_generation.to_be_bytes(),
            &adapter_root_id,
            &adapter_epoch.to_be_bytes(),
            b"AUTOMATIC_READBACK_SEQUENCE",
        ],
    );
    if claim_guard_digest != expected_guard {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    Ok(Some(CoordinatorReadbackSequenceClaimEvidenceV1 {
        claim_attempt_generation,
        source_handoff_generation,
        claim_guard_digest,
        adapter_root_id,
        adapter_epoch,
    }))
}

/// Atomically owns or resumes the single automatic readback sequence.
///
/// The retained claim records the trusted adapter root/epoch and source handoff generation, then
/// moves only the outbox to `UNKNOWN`.  The dispatch record remains exactly `DISPATCHING`, so a
/// receipt found by the bounded sequence can still take the timely consumed path to `EXECUTING`.
pub(crate) fn claim_or_resume_readback_sequence_v1<F>(
    connection: &mut Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    claim: &CoordinatorReadbackSequenceClaimV1,
    mut verify_live_snapshot: F,
) -> CoordinatorReadbackSequenceClaimOutcomeV1
where
    F: FnMut(&Connection) -> bool,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return sequence_claim_outcome_from_error_v1(map_sql_error_v1(error)),
    };
    if sqlite_profile_is_exact_v1(&transaction).is_err() || !verify_live_snapshot(&transaction) {
        return rollback_sequence_claim_outcome_v1(
            transaction,
            CoordinatorReadbackSequenceClaimOutcomeV1::Unhealthy,
        );
    }
    match load_readback_sequence_claim_v1(&transaction, lookup) {
        Ok(Some(evidence)) => {
            let outcome = if evidence.adapter_root_id == claim.adapter_root_id
                && evidence.adapter_epoch == claim.adapter_epoch
            {
                CoordinatorReadbackSequenceClaimOutcomeV1::Resumed(evidence)
            } else {
                CoordinatorReadbackSequenceClaimOutcomeV1::Conflict
            };
            return rollback_sequence_claim_outcome_v1(transaction, outcome);
        }
        Ok(None) => {}
        Err(error) => {
            return rollback_sequence_claim_outcome_v1(
                transaction,
                sequence_claim_outcome_from_error_v1(error),
            )
        }
    }
    let context = match load_current_context_v1(&transaction, lookup) {
        Ok(Some(context)) => context,
        Ok(None) => {
            return rollback_sequence_claim_outcome_v1(
                transaction,
                CoordinatorReadbackSequenceClaimOutcomeV1::RejectedNoAdvance,
            )
        }
        Err(error) => {
            return rollback_sequence_claim_outcome_v1(
                transaction,
                sequence_claim_outcome_from_error_v1(error),
            )
        }
    };
    if !context_can_claim_sequence_v1(&context) {
        return rollback_sequence_claim_outcome_v1(
            transaction,
            CoordinatorReadbackSequenceClaimOutcomeV1::Conflict,
        );
    }
    let claim_guard_digest = derive_sequence_claim_guard_v1(lookup, &context, claim);
    let generations = match allocate_sequence_claim_generations_v1(&transaction) {
        Ok(generations) => generations,
        Err(error) => {
            return rollback_sequence_claim_outcome_v1(
                transaction,
                sequence_claim_outcome_from_error_v1(error),
            )
        }
    };
    if let Err(error) = stage_readback_sequence_claim_v1(
        &transaction,
        lookup,
        &context,
        claim,
        claim_guard_digest,
        generations,
    ) {
        return rollback_sequence_claim_outcome_v1(
            transaction,
            sequence_claim_outcome_from_error_v1(error),
        );
    }
    if foreign_key_check_has_rows_v1(&transaction).unwrap_or(true)
        || !verify_live_snapshot(&transaction)
    {
        return rollback_sequence_claim_outcome_v1(
            transaction,
            CoordinatorReadbackSequenceClaimOutcomeV1::Unhealthy,
        );
    }
    let evidence = match load_readback_sequence_claim_v1(&transaction, lookup) {
        Ok(Some(evidence))
            if evidence.claim_attempt_generation == generations.delivery
                && evidence.source_handoff_generation == context.initial_handoff_generation
                && evidence.claim_guard_digest == claim_guard_digest
                && evidence.adapter_root_id == claim.adapter_root_id
                && evidence.adapter_epoch == claim.adapter_epoch =>
        {
            evidence
        }
        _ => {
            return rollback_sequence_claim_outcome_v1(
                transaction,
                CoordinatorReadbackSequenceClaimOutcomeV1::Unhealthy,
            )
        }
    };
    let source_handoff_generation = evidence.source_handoff_generation;
    match transaction.commit() {
        Ok(()) => CoordinatorReadbackSequenceClaimOutcomeV1::Claimed {
            evidence,
            permit: CoordinatorAutomaticReadbackPermitV1::new_v1(source_handoff_generation),
        },
        Err(_) => CoordinatorReadbackSequenceClaimOutcomeV1::Uncertain,
    }
}

fn context_can_claim_sequence_v1(context: &CurrentReconciliationContextV1) -> bool {
    context.state == DurableDispatchStateV1::Dispatching
        && context.receipt_id.is_none()
        && context.receipt_decision.is_none()
        && context.reconciliation_id.is_none()
        && context.reconciliation_result.is_none()
        && context.outbox_state == "HANDED_OFF"
        && context.current_attempt_classification == "POSSIBLE_HANDOFF"
        && context.current_attempt_generation == context.initial_handoff_generation
        && context.current_adapter_root_id.is_none()
        && context.current_adapter_epoch.is_none()
        && context.current_readback_generation.is_none()
        && context.base_operation_state == "PREPARING"
        && context.base_failed_generation.is_none()
        && context.base_failed_reason_code.is_none()
        && context.reservation_state == "HELD"
        && context.reservation_released_generation.is_none()
        && context
            .held
            .iter()
            .zip(context.reserved)
            .all(|(held, reserved)| *held >= reserved)
}

fn stage_readback_sequence_claim_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    claim: &CoordinatorReadbackSequenceClaimV1,
    claim_guard_digest: [u8; 32],
    generations: SequenceClaimGenerationsV1,
) -> Result<(), ReconciliationStageErrorV1> {
    let claim_attempt_number = next_safe_v1(context.current_attempt_number)?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_delivery_attempts (attempt_generation, grant_id, operation_id, \
             dispatch_attempt_id, attempt_number, handoff_guard_digest, classification, \
             adapter_root_digest, adapter_epoch, readback_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'POSSIBLE_HANDOFF', ?7, ?8, ?9)",
        params![
            to_i64_v1(generations.delivery)?,
            lookup.grant_id.as_slice(),
            &*lookup.operation_id,
            context.dispatch_attempt_id.as_slice(),
            to_i64_v1(claim_attempt_number)?,
            claim_guard_digest.as_slice(),
            claim.adapter_root_id.as_slice(),
            to_i64_v1(claim.adapter_epoch)?,
            to_i64_v1(context.initial_handoff_generation)?,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_outbox \
         SET delivery_state = 'UNKNOWN', delivery_generation = ?1, \
             current_attempt_generation = ?1 \
         WHERE grant_id = ?2 AND operation_id = ?3 AND dispatch_attempt_id = ?4 \
           AND delivery_state = 'HANDED_OFF' AND delivery_generation = ?5 \
           AND current_attempt_generation = ?6 AND receipt_id IS NULL \
           AND receipt_decision IS NULL",
        params![
            to_i64_v1(generations.delivery)?,
            lookup.grant_id.as_slice(),
            &*lookup.operation_id,
            context.dispatch_attempt_id.as_slice(),
            to_i64_v1(context.delivery_generation)?,
            to_i64_v1(context.current_attempt_generation)?,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_store_meta \
         SET dispatch_store_generation = ?1, delivery_generation = ?2 \
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
           AND dispatch_store_generation = ?3 AND dispatch_generation = ?4 \
           AND delivery_generation = ?5 AND receipt_generation = ?6 \
           AND reconciliation_generation = ?7 AND event_generation = ?8",
        params![
            to_i64_v1(generations.final_store)?,
            to_i64_v1(generations.delivery)?,
            to_i64_v1(generations.previous.store)?,
            to_i64_v1(generations.previous.dispatch)?,
            to_i64_v1(generations.previous.delivery)?,
            to_i64_v1(generations.previous.receipt)?,
            to_i64_v1(generations.previous.reconciliation)?,
            to_i64_v1(generations.previous.event)?,
        ],
    ))?;
    Ok(())
}

/// Records bounded readback exhaustion only after an exact durable sequence claim exists.
pub(crate) fn commit_outcome_unknown_v1<F>(
    connection: &mut Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    exhaustion: &CoordinatorReadbackExhaustionV1,
    mut verify_live_snapshot: F,
) -> CoordinatorReconciliationOutcomeV1
where
    F: FnMut(&Connection) -> bool,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return reconciliation_outcome_from_error_v1(map_sql_error_v1(error)),
    };
    if sqlite_profile_is_exact_v1(&transaction).is_err() || !verify_live_snapshot(&transaction) {
        return rollback_reconciliation_outcome_v1(
            transaction,
            CoordinatorReconciliationOutcomeV1::Unhealthy,
        );
    }
    match load_persisted_unknown_evidence_v1(&transaction, lookup) {
        Ok(Some(evidence)) => {
            let exact = match persisted_unknown_exhaustion_is_exact_v1(
                &transaction,
                lookup,
                &evidence,
                exhaustion,
            ) {
                Ok(exact) => exact,
                Err(error) => {
                    return rollback_reconciliation_outcome_v1(
                        transaction,
                        reconciliation_outcome_from_error_v1(error),
                    )
                }
            };
            return rollback_reconciliation_outcome_v1(
                transaction,
                if exact {
                    CoordinatorReconciliationOutcomeV1::Resumed(evidence)
                } else {
                    CoordinatorReconciliationOutcomeV1::Conflict
                },
            );
        }
        Ok(None) => {}
        Err(error) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                reconciliation_outcome_from_error_v1(error),
            )
        }
    }
    let claim = match load_readback_sequence_claim_v1(&transaction, lookup) {
        Ok(Some(claim)) => claim,
        Ok(None) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                CoordinatorReconciliationOutcomeV1::RejectedNoAdvance,
            )
        }
        Err(error) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                reconciliation_outcome_from_error_v1(error),
            )
        }
    };
    let context = match load_current_context_v1(&transaction, lookup) {
        Ok(Some(context)) => context,
        Ok(None) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                CoordinatorReconciliationOutcomeV1::RejectedNoAdvance,
            )
        }
        Err(error) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                reconciliation_outcome_from_error_v1(error),
            )
        }
    };
    if !context_can_commit_exhaustion_v1(&context, &claim) {
        return rollback_reconciliation_outcome_v1(
            transaction,
            CoordinatorReconciliationOutcomeV1::Conflict,
        );
    }
    let ids = derive_unknown_ids_v1(lookup, &context, exhaustion);
    let generations = match allocate_unknown_generations_v1(&transaction) {
        Ok(generations) => generations,
        Err(error) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                reconciliation_outcome_from_error_v1(error),
            )
        }
    };
    if let Err(error) =
        stage_outcome_unknown_v1(&transaction, lookup, &context, exhaustion, ids, generations)
    {
        return rollback_reconciliation_outcome_v1(
            transaction,
            reconciliation_outcome_from_error_v1(error),
        );
    }
    if foreign_key_check_has_rows_v1(&transaction).unwrap_or(true)
        || !verify_live_snapshot(&transaction)
    {
        return rollback_reconciliation_outcome_v1(
            transaction,
            CoordinatorReconciliationOutcomeV1::Unhealthy,
        );
    }
    let evidence = match load_persisted_unknown_evidence_v1(&transaction, lookup) {
        Ok(Some(evidence))
            if evidence.state == CoordinatorReconciliationStateV1::OutcomeUnknown
                && evidence.reconciliation_id == ids.reconciliation_id
                && evidence.state_generation == generations.state
                && evidence.claim_attempt_generation == claim.claim_attempt_generation =>
        {
            evidence
        }
        _ => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                CoordinatorReconciliationOutcomeV1::Unhealthy,
            )
        }
    };
    match transaction.commit() {
        Ok(()) => CoordinatorReconciliationOutcomeV1::Committed(evidence),
        Err(_) => CoordinatorReconciliationOutcomeV1::Uncertain,
    }
}

fn context_can_commit_exhaustion_v1(
    context: &CurrentReconciliationContextV1,
    claim: &CoordinatorReadbackSequenceClaimEvidenceV1,
) -> bool {
    context.state == DurableDispatchStateV1::Dispatching
        && context.receipt_id.is_none()
        && context.receipt_decision.is_none()
        && context.reconciliation_id.is_none()
        && context.reconciliation_result.is_none()
        && context.outbox_state == "UNKNOWN"
        && context.current_attempt_classification == "POSSIBLE_HANDOFF"
        && context.current_attempt_generation == claim.claim_attempt_generation
        && context.current_adapter_root_id == Some(claim.adapter_root_id)
        && context.current_adapter_epoch == Some(claim.adapter_epoch)
        && context.current_readback_generation == Some(claim.source_handoff_generation)
        && context.base_operation_state == "PREPARING"
        && context.base_failed_generation.is_none()
        && context.base_failed_reason_code.is_none()
        && context.reservation_state == "HELD"
        && context.reservation_released_generation.is_none()
}

fn stage_outcome_unknown_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    exhaustion: &CoordinatorReadbackExhaustionV1,
    ids: UnknownIdsV1,
    generations: UnknownGenerationsV1,
) -> Result<(), ReconciliationStageErrorV1> {
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_reconciliations (reconciliation_id, grant_id, operation_id, \
             dispatch_attempt_id, evidence_digest, transport_quiescence_digest, \
             no_inflight_proof_digest, result, receipt_id, receipt_decision, \
             reconciliation_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'OUTCOME_UNKNOWN', NULL, NULL, ?7)",
        params![
            ids.reconciliation_id.as_slice(),
            lookup.grant_id.as_slice(),
            &*lookup.operation_id,
            context.dispatch_attempt_id.as_slice(),
            ids.evidence_digest.as_slice(),
            ids.transport_observation_digest.as_slice(),
            to_i64_v1(generations.reconciliation)?,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_records \
         SET effective_state = 'OUTCOME_UNKNOWN', state_generation = ?1, \
             reconciliation_id = ?2, reconciliation_result = 'OUTCOME_UNKNOWN', \
             current_event_id = ?3 \
         WHERE operation_id = ?4 AND grant_id = ?5 AND dispatch_attempt_id = ?6 \
           AND effective_state = 'DISPATCHING' AND state_generation = ?7 \
           AND current_event_id = ?8 AND receipt_id IS NULL AND receipt_decision IS NULL \
           AND reconciliation_id IS NULL AND reconciliation_result IS NULL",
        params![
            to_i64_v1(generations.state)?,
            ids.reconciliation_id.as_slice(),
            ids.event_id.as_slice(),
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            to_i64_v1(context.state_generation)?,
            context.current_event_id.as_slice(),
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_transitions (state_generation, previous_transition_generation, \
             operation_id, grant_id, dispatch_attempt_id, previous_state, new_state, event_id, \
             evidence_digest, receipt_id, receipt_decision, reconciliation_id, \
             reconciliation_result, definite_refusal_guard_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'DISPATCHING', 'OUTCOME_UNKNOWN', ?6, ?7, \
                 NULL, NULL, ?8, 'OUTCOME_UNKNOWN', NULL)",
        params![
            to_i64_v1(generations.state)?,
            to_i64_v1(context.state_generation)?,
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            ids.event_id.as_slice(),
            ids.evidence_digest.as_slice(),
            ids.reconciliation_id.as_slice(),
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_events (event_id, event_generation, transition_generation, \
             operation_id, grant_id, dispatch_attempt_id, task_id, workload_id, plan_id, \
             task_lease_digest, event_contract_version, grant_contract_version, \
             receipt_contract_version, effective_state, decision, latency_ms, event_kind, \
             public_reason_code, public_trace_id, delivery_state, delivered_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, 1, 0, \
                 'OUTCOME_UNKNOWN', 'OUTCOME_UNKNOWN', ?11, 'DISPATCH_UNKNOWN', \
                 NULL, ?12, 'PENDING', NULL)",
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
            to_i64_v1(exhaustion.latency_ms)?,
            &*exhaustion.public_trace_id,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_store_meta \
         SET dispatch_store_generation = ?1, dispatch_generation = ?2, \
             reconciliation_generation = ?3, event_generation = ?4 \
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
           AND dispatch_store_generation = ?5 AND dispatch_generation = ?6 \
           AND delivery_generation = ?7 AND receipt_generation = ?8 \
           AND reconciliation_generation = ?9 AND event_generation = ?10",
        params![
            to_i64_v1(generations.final_store)?,
            to_i64_v1(generations.state)?,
            to_i64_v1(generations.reconciliation)?,
            to_i64_v1(generations.event)?,
            to_i64_v1(generations.previous.store)?,
            to_i64_v1(generations.previous.dispatch)?,
            to_i64_v1(generations.previous.delivery)?,
            to_i64_v1(generations.previous.receipt)?,
            to_i64_v1(generations.previous.reconciliation)?,
            to_i64_v1(generations.previous.event)?,
        ],
    ))?;
    Ok(())
}

fn load_persisted_unknown_evidence_v1(
    connection: &Connection,
    lookup: &CoordinatorReconciliationLookupV1,
) -> Result<Option<CoordinatorReconciliationEvidenceV1>, ReconciliationStageErrorV1> {
    let raw = connection
        .query_row(
            "SELECT record.effective_state, record.state_generation, \
                    record.reconciliation_id, outbox.current_attempt_generation \
             FROM dispatch_records AS record \
             JOIN dispatch_reconciliations AS reconciliation \
               ON reconciliation.reconciliation_id = record.reconciliation_id \
              AND reconciliation.grant_id = record.grant_id \
              AND reconciliation.operation_id = record.operation_id \
              AND reconciliation.dispatch_attempt_id = record.dispatch_attempt_id \
              AND reconciliation.result = 'OUTCOME_UNKNOWN' \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = record.grant_id \
              AND outbox.operation_id = record.operation_id \
              AND outbox.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_delivery_attempts AS attempt \
               ON attempt.attempt_generation = outbox.current_attempt_generation \
              AND attempt.grant_id = record.grant_id \
              AND attempt.operation_id = record.operation_id \
              AND attempt.dispatch_attempt_id = record.dispatch_attempt_id \
             JOIN dispatch_transitions AS current_transition \
               ON current_transition.operation_id = record.operation_id \
              AND current_transition.grant_id = record.grant_id \
              AND current_transition.dispatch_attempt_id = record.dispatch_attempt_id \
              AND current_transition.state_generation = record.state_generation \
              AND current_transition.event_id = record.current_event_id \
              AND current_transition.new_state = record.effective_state \
              AND current_transition.receipt_id IS NULL \
              AND current_transition.receipt_decision IS NULL \
              AND current_transition.reconciliation_id = record.reconciliation_id \
              AND current_transition.reconciliation_result = 'OUTCOME_UNKNOWN' \
             JOIN dispatch_events AS current_event \
               ON current_event.event_id = record.current_event_id \
              AND current_event.operation_id = record.operation_id \
              AND current_event.grant_id = record.grant_id \
              AND current_event.transition_generation = record.state_generation \
              AND current_event.effective_state = record.effective_state \
              AND current_event.decision = 'OUTCOME_UNKNOWN' \
             WHERE record.operation_id = ?1 AND record.grant_id = ?2 \
               AND record.effective_state IN ('OUTCOME_UNKNOWN', 'RECONCILIATION_REQUIRED') \
               AND record.receipt_id IS NULL AND record.receipt_decision IS NULL \
               AND record.reconciliation_result = 'OUTCOME_UNKNOWN' \
               AND outbox.delivery_state = 'UNKNOWN' AND outbox.receipt_id IS NULL \
               AND attempt.classification = 'POSSIBLE_HANDOFF' \
               AND typeof(attempt.adapter_root_digest) = 'blob' \
               AND length(attempt.adapter_root_digest) = 32 \
               AND attempt.adapter_epoch IS NOT NULL \
               AND attempt.readback_generation = ( \
                   SELECT MIN(source.attempt_generation) \
                   FROM dispatch_delivery_attempts AS source \
                   WHERE source.grant_id = attempt.grant_id \
                     AND source.operation_id = attempt.operation_id \
                     AND source.dispatch_attempt_id = attempt.dispatch_attempt_id \
                     AND source.classification = 'POSSIBLE_HANDOFF' \
                     AND source.adapter_root_digest IS NULL \
                     AND source.adapter_epoch IS NULL \
                     AND source.readback_generation IS NULL) \
               AND ((record.effective_state = 'OUTCOME_UNKNOWN' \
                     AND current_transition.previous_state = 'DISPATCHING' \
                     AND current_event.event_kind = 'DISPATCH_UNKNOWN' \
                     AND current_event.decision = 'OUTCOME_UNKNOWN') \
                    OR (record.effective_state = 'RECONCILIATION_REQUIRED' \
                     AND current_transition.previous_state = 'OUTCOME_UNKNOWN' \
                     AND current_event.event_kind = 'DISPATCH_RECONCILED' \
                     AND current_event.decision = 'OUTCOME_UNKNOWN')) \
               AND EXISTS (SELECT 1 FROM dispatch_transitions AS unknown_transition \
                           JOIN dispatch_events AS unknown_event \
                             ON unknown_event.event_id = unknown_transition.event_id \
                            AND unknown_event.operation_id = unknown_transition.operation_id \
                            AND unknown_event.grant_id = unknown_transition.grant_id \
                            AND unknown_event.transition_generation = \
                                unknown_transition.state_generation \
                           WHERE unknown_transition.operation_id = record.operation_id \
                             AND unknown_transition.grant_id = record.grant_id \
                             AND unknown_transition.previous_state = 'DISPATCHING' \
                             AND unknown_transition.new_state = 'OUTCOME_UNKNOWN' \
                             AND unknown_transition.reconciliation_id = record.reconciliation_id \
                             AND unknown_transition.reconciliation_result = 'OUTCOME_UNKNOWN' \
                             AND unknown_event.event_kind = 'DISPATCH_UNKNOWN')",
            params![&*lookup.operation_id, lookup.grant_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?;
    let evidence = raw
        .map(|raw| {
            let state = match raw.0.as_str() {
                "OUTCOME_UNKNOWN" => CoordinatorReconciliationStateV1::OutcomeUnknown,
                "RECONCILIATION_REQUIRED" => {
                    CoordinatorReconciliationStateV1::ReconciliationRequired
                }
                _ => return Err(ReconciliationStageErrorV1::Unhealthy),
            };
            Ok(CoordinatorReconciliationEvidenceV1 {
                reconciliation_id: exact_array_v1(raw.2)?,
                state,
                state_generation: safe_u64_v1(raw.1)?,
                claim_attempt_generation: safe_u64_v1(raw.3)?,
            })
        })
        .transpose()?;
    let Some(evidence) = evidence else {
        return Ok(None);
    };
    let claim = load_readback_sequence_claim_v1(connection, lookup)?
        .ok_or(ReconciliationStageErrorV1::Unhealthy)?;
    if evidence.claim_attempt_generation != claim.claim_attempt_generation {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    Ok(Some(evidence))
}

fn load_persisted_unknown_exhaustion_v1(
    connection: &Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    reconciliation_id: [u8; 32],
) -> Result<Option<PersistedUnknownExhaustionV1>, ReconciliationStageErrorV1> {
    connection
        .query_row(
            "SELECT reconciliation.evidence_digest, \
                    reconciliation.transport_quiescence_digest, \
                    transition.evidence_digest, transition.event_id, \
                    event.public_trace_id, event.latency_ms \
             FROM dispatch_reconciliations AS reconciliation \
             JOIN dispatch_transitions AS transition \
               ON transition.operation_id = reconciliation.operation_id \
              AND transition.grant_id = reconciliation.grant_id \
              AND transition.dispatch_attempt_id = reconciliation.dispatch_attempt_id \
              AND transition.reconciliation_id = reconciliation.reconciliation_id \
              AND transition.reconciliation_result = 'OUTCOME_UNKNOWN' \
              AND transition.previous_state = 'DISPATCHING' \
              AND transition.new_state = 'OUTCOME_UNKNOWN' \
              AND transition.receipt_id IS NULL \
              AND transition.receipt_decision IS NULL \
             JOIN dispatch_events AS event \
               ON event.event_id = transition.event_id \
              AND event.operation_id = transition.operation_id \
              AND event.grant_id = transition.grant_id \
              AND event.dispatch_attempt_id = transition.dispatch_attempt_id \
              AND event.transition_generation = transition.state_generation \
              AND event.effective_state = 'OUTCOME_UNKNOWN' \
              AND event.decision = 'OUTCOME_UNKNOWN' \
              AND event.event_kind = 'DISPATCH_UNKNOWN' \
             WHERE reconciliation.reconciliation_id = ?1 \
               AND reconciliation.operation_id = ?2 \
               AND reconciliation.grant_id = ?3 \
               AND reconciliation.result = 'OUTCOME_UNKNOWN' \
               AND reconciliation.receipt_id IS NULL \
               AND reconciliation.receipt_decision IS NULL \
               AND reconciliation.no_inflight_proof_digest IS NULL",
            params![
                reconciliation_id.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?
        .map(|raw| {
            Ok(PersistedUnknownExhaustionV1 {
                reconciliation_id,
                reconciliation_evidence_digest: exact_array_v1(raw.0)?,
                transport_observation_digest: exact_array_v1(raw.1)?,
                transition_evidence_digest: exact_array_v1(raw.2)?,
                event_id: exact_array_v1(raw.3)?,
                public_trace_id: raw.4,
                latency_ms: safe_u64_v1(raw.5)?,
            })
        })
        .transpose()
}

fn persisted_unknown_exhaustion_bindings_match_v1(
    persisted: &PersistedUnknownExhaustionV1,
    expected: &UnknownIdsV1,
    exhaustion: &CoordinatorReadbackExhaustionV1,
) -> bool {
    persisted.reconciliation_id == expected.reconciliation_id
        && persisted.reconciliation_evidence_digest == expected.evidence_digest
        && persisted.transport_observation_digest == expected.transport_observation_digest
        && persisted.transition_evidence_digest == expected.evidence_digest
        && persisted.event_id == expected.event_id
        && persisted.public_trace_id == exhaustion.public_trace_id.as_ref()
        && persisted.latency_ms == exhaustion.latency_ms
}

fn persisted_unknown_exhaustion_is_exact_v1(
    connection: &Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    evidence: &CoordinatorReconciliationEvidenceV1,
    exhaustion: &CoordinatorReadbackExhaustionV1,
) -> Result<bool, ReconciliationStageErrorV1> {
    let context = load_current_context_v1(connection, lookup)?
        .ok_or(ReconciliationStageErrorV1::Unhealthy)?;
    let expected = derive_unknown_ids_v1(lookup, &context, exhaustion);
    let persisted =
        load_persisted_unknown_exhaustion_v1(connection, lookup, evidence.reconciliation_id)?;
    Ok(match persisted {
        Some(persisted) => {
            persisted_unknown_exhaustion_bindings_match_v1(&persisted, &expected, exhaustion)
        }
        None => false,
    })
}

fn exactly_one_v1(
    result: Result<usize, rusqlite::Error>,
) -> Result<(), ReconciliationStageErrorV1> {
    match result.map_err(map_sql_error_v1)? {
        1 => Ok(()),
        _ => Err(ReconciliationStageErrorV1::Conflict),
    }
}

fn rollback_sequence_claim_outcome_v1(
    transaction: Transaction<'_>,
    outcome: CoordinatorReadbackSequenceClaimOutcomeV1,
) -> CoordinatorReadbackSequenceClaimOutcomeV1 {
    if transaction.rollback().is_ok() {
        outcome
    } else {
        CoordinatorReadbackSequenceClaimOutcomeV1::Unhealthy
    }
}

fn sequence_claim_outcome_from_error_v1(
    error: ReconciliationStageErrorV1,
) -> CoordinatorReadbackSequenceClaimOutcomeV1 {
    match error {
        ReconciliationStageErrorV1::Rejected => {
            CoordinatorReadbackSequenceClaimOutcomeV1::RejectedNoAdvance
        }
        ReconciliationStageErrorV1::Conflict => CoordinatorReadbackSequenceClaimOutcomeV1::Conflict,
        ReconciliationStageErrorV1::Unavailable | ReconciliationStageErrorV1::Injected => {
            CoordinatorReadbackSequenceClaimOutcomeV1::Unavailable
        }
        ReconciliationStageErrorV1::Unhealthy => {
            CoordinatorReadbackSequenceClaimOutcomeV1::Unhealthy
        }
    }
}

fn rollback_reconciliation_outcome_v1(
    transaction: Transaction<'_>,
    outcome: CoordinatorReconciliationOutcomeV1,
) -> CoordinatorReconciliationOutcomeV1 {
    if transaction.rollback().is_ok() {
        outcome
    } else {
        CoordinatorReconciliationOutcomeV1::Unhealthy
    }
}

fn reconciliation_outcome_from_error_v1(
    error: ReconciliationStageErrorV1,
) -> CoordinatorReconciliationOutcomeV1 {
    match error {
        ReconciliationStageErrorV1::Rejected => {
            CoordinatorReconciliationOutcomeV1::RejectedNoAdvance
        }
        ReconciliationStageErrorV1::Conflict => CoordinatorReconciliationOutcomeV1::Conflict,
        ReconciliationStageErrorV1::Unavailable | ReconciliationStageErrorV1::Injected => {
            CoordinatorReconciliationOutcomeV1::Unavailable
        }
        ReconciliationStageErrorV1::Unhealthy => CoordinatorReconciliationOutcomeV1::Unhealthy,
    }
}

/// Atomically closes a retained unknown claim into explicit reconciliation custody.
///
/// This is a CAS on the exact unknown transition/reconciliation graph.  Retrying after an
/// uncertain commit returns `Resumed`; no second successor transition or event is appended.
pub(crate) fn commit_reconciliation_required_unknown_v1<F>(
    connection: &mut Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    mut verify_live_snapshot: F,
) -> CoordinatorReconciliationOutcomeV1
where
    F: FnMut(&Connection) -> bool,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return reconciliation_outcome_from_error_v1(map_sql_error_v1(error)),
    };
    if sqlite_profile_is_exact_v1(&transaction).is_err() || !verify_live_snapshot(&transaction) {
        return rollback_reconciliation_outcome_v1(
            transaction,
            CoordinatorReconciliationOutcomeV1::Unhealthy,
        );
    }
    let prior = match load_persisted_unknown_evidence_v1(&transaction, lookup) {
        Ok(Some(evidence)) => evidence,
        Ok(None) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                CoordinatorReconciliationOutcomeV1::RejectedNoAdvance,
            )
        }
        Err(error) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                reconciliation_outcome_from_error_v1(error),
            )
        }
    };
    if prior.state == CoordinatorReconciliationStateV1::ReconciliationRequired {
        return rollback_reconciliation_outcome_v1(
            transaction,
            CoordinatorReconciliationOutcomeV1::Resumed(prior),
        );
    }
    let context = match load_current_context_v1(&transaction, lookup) {
        Ok(Some(context)) => context,
        Ok(None) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                CoordinatorReconciliationOutcomeV1::Conflict,
            )
        }
        Err(error) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                reconciliation_outcome_from_error_v1(error),
            )
        }
    };
    if context.state != DurableDispatchStateV1::OutcomeUnknown
        || context.receipt_id.is_some()
        || context.receipt_decision.is_some()
        || context.reconciliation_id != Some(prior.reconciliation_id)
        || context.reconciliation_result.as_deref() != Some("OUTCOME_UNKNOWN")
        || context.outbox_state != "UNKNOWN"
        || context.current_attempt_generation != prior.claim_attempt_generation
        || context.current_attempt_classification != "POSSIBLE_HANDOFF"
        || context.base_operation_state != "PREPARING"
        || context.base_failed_generation.is_some()
        || context.base_failed_reason_code.is_some()
        || context.reservation_state != "HELD"
        || context.reservation_released_generation.is_some()
        || !context
            .held
            .iter()
            .zip(context.reserved)
            .all(|(held, reserved)| *held >= reserved)
    {
        return rollback_reconciliation_outcome_v1(
            transaction,
            CoordinatorReconciliationOutcomeV1::Conflict,
        );
    }
    let generations = match allocate_required_generations_v1(&transaction) {
        Ok(generations) => generations,
        Err(error) => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                reconciliation_outcome_from_error_v1(error),
            )
        }
    };
    let event_id = digest_parts_v1(
        RECONCILIATION_EVENT_DOMAIN_V1,
        &[&prior.reconciliation_id, b"RECONCILIATION_REQUIRED"],
    );
    let evidence_digest = digest_parts_v1(
        RECONCILIATION_EVIDENCE_DOMAIN_V1,
        &[&prior.reconciliation_id, b"RECONCILIATION_REQUIRED"],
    );
    if let Err(error) = stage_reconciliation_required_v1(
        &transaction,
        lookup,
        &context,
        prior.reconciliation_id,
        event_id,
        evidence_digest,
        generations,
    ) {
        return rollback_reconciliation_outcome_v1(
            transaction,
            reconciliation_outcome_from_error_v1(error),
        );
    }
    if foreign_key_check_has_rows_v1(&transaction).unwrap_or(true)
        || !verify_live_snapshot(&transaction)
    {
        return rollback_reconciliation_outcome_v1(
            transaction,
            CoordinatorReconciliationOutcomeV1::Unhealthy,
        );
    }
    let evidence = match load_persisted_unknown_evidence_v1(&transaction, lookup) {
        Ok(Some(evidence))
            if evidence.state == CoordinatorReconciliationStateV1::ReconciliationRequired
                && evidence.reconciliation_id == prior.reconciliation_id
                && evidence.state_generation == generations.state
                && evidence.claim_attempt_generation == prior.claim_attempt_generation =>
        {
            evidence
        }
        _ => {
            return rollback_reconciliation_outcome_v1(
                transaction,
                CoordinatorReconciliationOutcomeV1::Unhealthy,
            )
        }
    };
    match transaction.commit() {
        Ok(()) => CoordinatorReconciliationOutcomeV1::Committed(evidence),
        Err(_) => CoordinatorReconciliationOutcomeV1::Uncertain,
    }
}

fn allocate_required_generations_v1(
    connection: &Connection,
) -> Result<RequiredGenerationsV1, ReconciliationStageErrorV1> {
    let previous = load_dispatch_meta_v1(connection)?;
    let final_store = next_safe_v1(previous.store)?;
    let state = final_store;
    let event = final_store;
    Ok(RequiredGenerationsV1 {
        previous,
        final_store,
        state,
        event,
    })
}

#[allow(clippy::too_many_arguments)]
fn stage_reconciliation_required_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    reconciliation_id: [u8; 32],
    event_id: [u8; 32],
    evidence_digest: [u8; 32],
    generations: RequiredGenerationsV1,
) -> Result<(), ReconciliationStageErrorV1> {
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_records \
         SET effective_state = 'RECONCILIATION_REQUIRED', state_generation = ?1, \
             current_event_id = ?2 \
         WHERE operation_id = ?3 AND grant_id = ?4 AND dispatch_attempt_id = ?5 \
           AND effective_state = 'OUTCOME_UNKNOWN' AND state_generation = ?6 \
           AND current_event_id = ?7 AND receipt_id IS NULL AND receipt_decision IS NULL \
           AND reconciliation_id = ?8 AND reconciliation_result = 'OUTCOME_UNKNOWN'",
        params![
            to_i64_v1(generations.state)?,
            event_id.as_slice(),
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            to_i64_v1(context.state_generation)?,
            context.current_event_id.as_slice(),
            reconciliation_id.as_slice(),
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_transitions (state_generation, previous_transition_generation, \
             operation_id, grant_id, dispatch_attempt_id, previous_state, new_state, event_id, \
             evidence_digest, receipt_id, receipt_decision, reconciliation_id, \
             reconciliation_result, definite_refusal_guard_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'OUTCOME_UNKNOWN', 'RECONCILIATION_REQUIRED', \
                 ?6, ?7, NULL, NULL, ?8, 'OUTCOME_UNKNOWN', NULL)",
        params![
            to_i64_v1(generations.state)?,
            to_i64_v1(context.state_generation)?,
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            event_id.as_slice(),
            evidence_digest.as_slice(),
            reconciliation_id.as_slice(),
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_events (event_id, event_generation, transition_generation, \
             operation_id, grant_id, dispatch_attempt_id, task_id, workload_id, plan_id, \
             task_lease_digest, event_contract_version, grant_contract_version, \
             receipt_contract_version, effective_state, decision, latency_ms, event_kind, \
             public_reason_code, public_trace_id, delivery_state, delivered_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, 1, 0, \
                 'RECONCILIATION_REQUIRED', 'OUTCOME_UNKNOWN', 0, \
                 'DISPATCH_RECONCILED', NULL, 'dispatch-reconciliation', 'PENDING', NULL)",
        params![
            event_id.as_slice(),
            to_i64_v1(generations.event)?,
            to_i64_v1(generations.state)?,
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            context.task_id,
            context.workload_id,
            context.plan_id.as_slice(),
            context.task_lease_digest.as_slice(),
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_store_meta \
         SET dispatch_store_generation = ?1, dispatch_generation = ?2, \
             event_generation = ?3 \
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
           AND dispatch_store_generation = ?4 AND dispatch_generation = ?5 \
           AND delivery_generation = ?6 AND receipt_generation = ?7 \
           AND reconciliation_generation = ?8 AND event_generation = ?9",
        params![
            to_i64_v1(generations.final_store)?,
            to_i64_v1(generations.state)?,
            to_i64_v1(generations.event)?,
            to_i64_v1(generations.previous.store)?,
            to_i64_v1(generations.previous.dispatch)?,
            to_i64_v1(generations.previous.delivery)?,
            to_i64_v1(generations.previous.receipt)?,
            to_i64_v1(generations.previous.reconciliation)?,
            to_i64_v1(generations.previous.event)?,
        ],
    ))?;
    Ok(())
}

/// Routes an authentic consumed receipt recovered after ambiguity into reconciliation custody.
///
/// From `OUTCOME_UNKNOWN` the ordinary receipt boundary closes to `RECONCILIATION_REQUIRED`.
/// Once explicit reconciliation custody already exists, the append-only late boundary retains
/// the receipt and consumed reconciliation evidence without rewriting that projection.  Both
/// paths reverify the exact grant, signed receipt, adapter root and live SQLite snapshot and never
/// return a post-unknown operation to `EXECUTING`.
pub(crate) fn commit_late_consumed_receipt_v1<K, F>(
    connection: &mut Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    adapter_root_id: [u8; 32],
    canonical_receipt: &[u8],
    key_resolver: &K,
    #[cfg(feature = "test-fault-injection")]
    fault_probe: &crate::dispatch_fault::CoordinatorDispatchFaultProbeV1,
    mut verify_live_snapshot: F,
) -> CoordinatorReceiptCommitOutcomeV1
where
    K: GrantKeyResolver + ReceiptKeyResolver,
    F: FnMut(&Connection) -> bool,
{
    let make_receipt_lookup = || {
        CoordinatorReceiptLookupV1::try_new(
            lookup.operation_id.to_string(),
            lookup.grant_id,
            adapter_root_id,
        )
        .map_err(|_| ())
    };
    let route_to_append_only_custody = match connection
        .query_row(
            "SELECT effective_state, reconciliation_result \
             FROM dispatch_records WHERE operation_id = ?1 AND grant_id = ?2",
            params![&*lookup.operation_id, lookup.grant_id.as_slice()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()
    {
        Ok(Some((state, result))) => {
            state == "RECONCILIATION_REQUIRED" && result.as_deref() == Some("OUTCOME_UNKNOWN")
        }
        Ok(None) => false,
        Err(error) => {
            return match map_sql_error_v1(error) {
                ReconciliationStageErrorV1::Unavailable => {
                    CoordinatorReceiptCommitOutcomeV1::Unavailable
                }
                _ => CoordinatorReceiptCommitOutcomeV1::Unhealthy,
            }
        }
    };
    let receipt_lookup = match make_receipt_lookup() {
        Ok(receipt_lookup) => receipt_lookup,
        Err(()) => return CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance,
    };
    if route_to_append_only_custody {
        return commit_late_reconciliation_consumed_receipt_v1(
            connection,
            receipt_lookup,
            canonical_receipt,
            key_resolver,
            #[cfg(feature = "test-fault-injection")]
            fault_probe,
            |snapshot| verify_live_snapshot(snapshot),
        );
    }

    let outcome = commit_execution_receipt_v1(
        connection,
        receipt_lookup,
        canonical_receipt,
        key_resolver,
        #[cfg(feature = "test-fault-injection")]
        fault_probe,
        |snapshot| verify_live_snapshot(snapshot),
    );
    if !matches!(
        outcome,
        CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance
            | CoordinatorReceiptCommitOutcomeV1::Conflict
    ) {
        return outcome;
    }
    let raced_to_append_only_custody = match connection.query_row(
        "SELECT COUNT(*) FROM dispatch_records \
             WHERE operation_id = ?1 AND grant_id = ?2 \
               AND effective_state = 'RECONCILIATION_REQUIRED' \
               AND reconciliation_result = 'OUTCOME_UNKNOWN' \
               AND receipt_id IS NULL AND receipt_decision IS NULL",
        params![&*lookup.operation_id, lookup.grant_id.as_slice()],
        |row| row.get::<_, i64>(0),
    ) {
        Ok(count) => count == 1,
        Err(error) => {
            return match map_sql_error_v1(error) {
                ReconciliationStageErrorV1::Unavailable => {
                    CoordinatorReceiptCommitOutcomeV1::Unavailable
                }
                _ => CoordinatorReceiptCommitOutcomeV1::Unhealthy,
            }
        }
    };
    if !raced_to_append_only_custody {
        return outcome;
    }
    let receipt_lookup = match make_receipt_lookup() {
        Ok(receipt_lookup) => receipt_lookup,
        Err(()) => return CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance,
    };
    commit_late_reconciliation_consumed_receipt_v1(
        connection,
        receipt_lookup,
        canonical_receipt,
        key_resolver,
        #[cfg(feature = "test-fault-injection")]
        fault_probe,
        |snapshot| verify_live_snapshot(snapshot),
    )
}

impl VerifiedRefusalCandidateV1 {
    fn from_authentic_v1(
        authentic: &AuthenticExecutionReceiptV1,
        exact_bytes: &[u8],
    ) -> Option<Self> {
        let claims = authentic.claims();
        if claims.decision() != ExecutionReceiptDecisionV1::RefusedDefinite
            || claims.consumption_generation().is_some()
            || claims.refusal_generation().is_none()
            || exact_bytes.is_empty()
            || exact_bytes.len() > MAX_RECEIPT_BYTES_V1
            || authentic.canonical_signed_envelope_bytes().ok()?.as_slice() != exact_bytes
        {
            return None;
        }
        let refusal_code = claims.refusal_code()?;
        let refusal_code_text = match refusal_code {
            ExecutionReceiptRefusalCodeV1::GrantExpired => "GRANT_EXPIRED",
            ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch => "SUPERVISOR_EPOCH_MISMATCH",
            ExecutionReceiptRefusalCodeV1::AdapterPaused => "ADAPTER_PAUSED",
        };
        let no_consumption_tombstone_digest = *claims.no_consumption_tombstone_digest()?.as_bytes();
        Some(Self {
            canonical_receipt: exact_bytes.to_vec().into_boxed_slice(),
            receipt_id: *claims.receipt_id().as_bytes(),
            receipt_digest: *claims.receipt_digest().as_bytes(),
            adapter_key_fingerprint: *authentic.verified_key_fingerprint().as_bytes(),
            refusal_code,
            refusal_code_text,
            no_consumption_tombstone_digest,
            observed_supervisor_epoch: claims.observed_supervisor_epoch(),
            trace_id: Box::from(claims.trace_id()),
        })
    }
}

fn verify_exact_refusal_v1<K>(
    context: &CurrentReconciliationContextV1,
    lookup: &CoordinatorReconciliationLookupV1,
    canonical_receipt: &[u8],
    key_resolver: &K,
    proof: &DispatchDefiniteAbsenceProofV1,
    tombstone: &DispatchNoConsumptionTombstoneCustodyV1,
) -> Option<VerifiedRefusalCandidateV1>
where
    K: GrantKeyResolver + ReceiptKeyResolver,
{
    if proof.adapter_root() == [0; 32]
        || proof.delivery_attempt_id() != context.dispatch_attempt_id
        || proof.readback_generation() != context.initial_handoff_generation
        || proof.exclusive_deadline_monotonic_ms() != context.deadline_monotonic_ms
        || context.current_adapter_root_id != Some(proof.adapter_root())
        || context.current_adapter_epoch != Some(proof.supervisor_epoch())
        || context.current_readback_generation != Some(proof.readback_generation())
    {
        return None;
    }
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
        Sha256Digest::from_bytes(proof.adapter_root()),
    );
    let authentic =
        decode_and_verify_execution_receipt_v1(canonical_receipt, key_resolver, &bindings).ok()?;
    let claims = authentic.claims();
    if claims.grant_id().as_bytes() != &lookup.grant_id
        || claims.grant_digest().as_bytes() != &context.grant_digest
        || claims.operation_id() != &*lookup.operation_id
        || claims.adapter_root_id().as_bytes() != &proof.adapter_root()
        || claims.observed_supervisor_epoch() != proof.supervisor_epoch()
    {
        return None;
    }
    let candidate = VerifiedRefusalCandidateV1::from_authentic_v1(&authentic, canonical_receipt)?;
    let classified = classify_no_consumption_receipt_v1(&authentic)?;
    if classified.receipt_id() != tombstone.receipt_id()
        || classified.receipt_digest() != tombstone.receipt_digest()
        || classified.refusal_code() != tombstone.refusal_code()
        || classified.no_consumption_tombstone_digest()
            != tombstone.no_consumption_tombstone_digest()
        || candidate.receipt_id != tombstone.receipt_id()
        || candidate.receipt_digest != tombstone.receipt_digest()
        || candidate.refusal_code != tombstone.refusal_code()
        || candidate.no_consumption_tombstone_digest != tombstone.no_consumption_tombstone_digest()
    {
        return None;
    }
    Some(candidate)
}

fn derive_refusal_ids_v1(
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    candidate: &VerifiedRefusalCandidateV1,
    proof: &DispatchDefiniteAbsenceProofV1,
) -> RefusalIdsV1 {
    let transport_quiescence_digest = digest_parts_v1(
        TRANSPORT_QUIESCENCE_DOMAIN_V1,
        &[
            lookup.operation_id.as_bytes(),
            &lookup.grant_id,
            &context.dispatch_attempt_id,
            &proof.adapter_root(),
            &proof.supervisor_epoch().to_be_bytes(),
            &proof.readback_generation().to_be_bytes(),
            &proof.exclusive_deadline_monotonic_ms().to_be_bytes(),
        ],
    );
    let no_inflight_proof_digest = digest_parts_v1(
        NO_INFLIGHT_PROOF_DOMAIN_V1,
        &[
            &transport_quiescence_digest,
            &candidate.receipt_id,
            &candidate.receipt_digest,
            &candidate.no_consumption_tombstone_digest,
            &context.initial_handoff_generation.to_be_bytes(),
        ],
    );
    let unknown_reconciliation_id = digest_parts_v1(
        UNKNOWN_RECONCILIATION_DOMAIN_V1,
        &[
            lookup.operation_id.as_bytes(),
            &lookup.grant_id,
            &context.dispatch_attempt_id,
            &transport_quiescence_digest,
        ],
    );
    let unknown_evidence_digest = digest_parts_v1(
        RECONCILIATION_EVIDENCE_DOMAIN_V1,
        &[&unknown_reconciliation_id, b"OUTCOME_UNKNOWN"],
    );
    let unknown_event_id = digest_parts_v1(
        RECONCILIATION_EVENT_DOMAIN_V1,
        &[&unknown_reconciliation_id, b"OUTCOME_UNKNOWN"],
    );
    let reconciliation_id = digest_parts_v1(
        REFUSAL_RECONCILIATION_DOMAIN_V1,
        &[
            &candidate.receipt_id,
            &candidate.receipt_digest,
            &transport_quiescence_digest,
            &no_inflight_proof_digest,
        ],
    );
    let reconciliation_evidence_digest = digest_parts_v1(
        RECONCILIATION_EVIDENCE_DOMAIN_V1,
        &[
            &reconciliation_id,
            &candidate.receipt_digest,
            b"REFUSED_DEFINITE",
        ],
    );
    let reconciliation_event_id = digest_parts_v1(
        RECONCILIATION_EVENT_DOMAIN_V1,
        &[&reconciliation_id, b"RECONCILIATION_REQUIRED"],
    );
    let failed_event_id = digest_parts_v1(
        RECONCILIATION_EVENT_DOMAIN_V1,
        &[&reconciliation_id, b"FAILED"],
    );
    let base_failed_event_id = digest_parts_v1(
        BASE_FAILED_EVENT_DOMAIN_V1,
        &[
            lookup.operation_id.as_bytes(),
            &context.preparation_attempt_id,
            &candidate.receipt_id,
            candidate.refusal_code_text.as_bytes(),
        ],
    );
    let quiesced_handoff_guard_digest = digest_parts_v1(
        READBACK_CLAIM_GUARD_DOMAIN_V1,
        &[
            &transport_quiescence_digest,
            &no_inflight_proof_digest,
            &candidate.receipt_digest,
        ],
    );
    let guard_id = digest_parts_v1(
        REFUSAL_GUARD_DOMAIN_V1,
        &[
            lookup.operation_id.as_bytes(),
            &lookup.grant_id,
            &context.dispatch_attempt_id,
            &candidate.receipt_id,
            &reconciliation_id,
            &no_inflight_proof_digest,
        ],
    );
    RefusalIdsV1 {
        unknown_reconciliation_id,
        unknown_evidence_digest,
        unknown_event_id,
        reconciliation_id,
        reconciliation_evidence_digest,
        reconciliation_event_id,
        failed_event_id,
        base_failed_event_id,
        transport_quiescence_digest,
        no_inflight_proof_digest,
        quiesced_handoff_guard_digest,
        guard_id,
    }
}

fn allocate_refusal_generations_v1(
    connection: &Connection,
    starting_state: DurableDispatchStateV1,
) -> Result<RefusalGenerationsV1, ReconciliationStageErrorV1> {
    let dispatch_previous = load_dispatch_meta_v1(connection)?;
    let base_previous = load_base_meta_v1(connection)?;
    let transition_count = match starting_state {
        DurableDispatchStateV1::Dispatching => 3,
        DurableDispatchStateV1::OutcomeUnknown => 2,
        DurableDispatchStateV1::ReconciliationRequired => 1,
        _ => return Err(ReconciliationStageErrorV1::Conflict),
    };
    let mut state = Vec::with_capacity(transition_count);
    let mut event = Vec::with_capacity(transition_count);
    let mut next_generation = dispatch_previous.store;
    for _ in 0..transition_count {
        next_generation = next_safe_v1(next_generation)?;
        state.push(next_generation);
        event.push(next_generation);
    }
    let dispatch_final_store = *state.last().ok_or(ReconciliationStageErrorV1::Unhealthy)?;
    let delivery = dispatch_final_store;
    let receipt = dispatch_final_store;
    let unknown_reconciliation = if starting_state == DurableDispatchStateV1::Dispatching {
        Some(*state.first().ok_or(ReconciliationStageErrorV1::Unhealthy)?)
    } else {
        None
    };
    let refusal_reconciliation = dispatch_final_store;
    let base_store = next_safe_v1(base_previous.store)?;
    let base_operation = base_store;
    let base_event = base_store;
    Ok(RefusalGenerationsV1 {
        dispatch_previous,
        base_previous,
        dispatch_final_store,
        state,
        event,
        delivery,
        receipt,
        unknown_reconciliation,
        refusal_reconciliation,
        base_store,
        base_operation,
        base_budget: base_store,
        base_event,
    })
}

fn context_can_close_refusal_v1(context: &CurrentReconciliationContextV1) -> bool {
    let overlay_shape = match context.state {
        DurableDispatchStateV1::Dispatching => {
            context.receipt_id.is_none()
                && context.receipt_decision.is_none()
                && context.reconciliation_id.is_none()
                && context.reconciliation_result.is_none()
                && context.outbox_state == "UNKNOWN"
        }
        DurableDispatchStateV1::OutcomeUnknown | DurableDispatchStateV1::ReconciliationRequired => {
            context.receipt_id.is_none()
                && context.receipt_decision.is_none()
                && context.reconciliation_id.is_some()
                && context.reconciliation_result.as_deref() == Some("OUTCOME_UNKNOWN")
                && context.outbox_state == "UNKNOWN"
        }
        _ => false,
    };
    overlay_shape
        && context.current_attempt_classification == "POSSIBLE_HANDOFF"
        && context.current_adapter_root_id.is_some()
        && context.current_adapter_epoch.is_some()
        && context.current_readback_generation == Some(context.initial_handoff_generation)
        && context.base_operation_state == "PREPARING"
        && context.base_failed_generation.is_none()
        && context.base_failed_reason_code.is_none()
        && context.reservation_state == "HELD"
        && context.reservation_released_generation.is_none()
        && context
            .held
            .iter()
            .zip(context.reserved)
            .all(|(held, reserved)| *held >= reserved)
}

fn checked_scope_release_v1(
    context: &CurrentReconciliationContextV1,
) -> Result<[u64; 4], ReconciliationStageErrorV1> {
    Ok([
        context.held[0]
            .checked_sub(context.reserved[0])
            .ok_or(ReconciliationStageErrorV1::Unhealthy)?,
        context.held[1]
            .checked_sub(context.reserved[1])
            .ok_or(ReconciliationStageErrorV1::Unhealthy)?,
        context.held[2]
            .checked_sub(context.reserved[2])
            .ok_or(ReconciliationStageErrorV1::Unhealthy)?,
        context.held[3]
            .checked_sub(context.reserved[3])
            .ok_or(ReconciliationStageErrorV1::Unhealthy)?,
    ])
}

/// Verifies and atomically closes one exact signed post-`RECEIVED` definite refusal.
pub(crate) fn commit_definite_refusal_v1<K, F>(
    connection: &mut Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    canonical_receipt: &[u8],
    key_resolver: &K,
    proof: &DispatchDefiniteAbsenceProofV1,
    tombstone: &DispatchNoConsumptionTombstoneCustodyV1,
    verify_live_snapshot: F,
) -> CoordinatorDefiniteRefusalOutcomeV1
where
    K: GrantKeyResolver + ReceiptKeyResolver,
    F: FnMut(&Connection) -> bool,
{
    commit_definite_refusal_inner_v1(
        connection,
        lookup,
        canonical_receipt,
        key_resolver,
        proof,
        tombstone,
        verify_live_snapshot,
        &DisabledRefusalFaultProbeV1,
    )
}

#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_definite_refusal_with_fault_probe_v1<K, F>(
    connection: &mut Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    canonical_receipt: &[u8],
    key_resolver: &K,
    proof: &DispatchDefiniteAbsenceProofV1,
    tombstone: &DispatchNoConsumptionTombstoneCustodyV1,
    verify_live_snapshot: F,
    fault_probe: &crate::dispatch_fault::CoordinatorDispatchFaultProbeV1,
) -> CoordinatorDefiniteRefusalOutcomeV1
where
    K: GrantKeyResolver + ReceiptKeyResolver,
    F: FnMut(&Connection) -> bool,
{
    commit_definite_refusal_inner_v1(
        connection,
        lookup,
        canonical_receipt,
        key_resolver,
        proof,
        tombstone,
        verify_live_snapshot,
        &SelectedRefusalFaultProbeV1(fault_probe),
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_definite_refusal_inner_v1<K, F, P>(
    connection: &mut Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    canonical_receipt: &[u8],
    key_resolver: &K,
    proof: &DispatchDefiniteAbsenceProofV1,
    tombstone: &DispatchNoConsumptionTombstoneCustodyV1,
    mut verify_live_snapshot: F,
    fault_probe: &P,
) -> CoordinatorDefiniteRefusalOutcomeV1
where
    K: GrantKeyResolver + ReceiptKeyResolver,
    F: FnMut(&Connection) -> bool,
    P: RefusalFaultProbeV1,
{
    let transaction = match connection.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(transaction) => transaction,
        Err(error) => return refusal_outcome_from_error_v1(map_sql_error_v1(error)),
    };
    if fault_probe
        .checkpoint_v1(RefusalCheckpointV1::Begin)
        .is_err()
    {
        return rollback_refusal_outcome_v1(
            transaction,
            CoordinatorDefiniteRefusalOutcomeV1::Unavailable,
        );
    }
    if sqlite_profile_is_exact_v1(&transaction).is_err() || !verify_live_snapshot(&transaction) {
        return rollback_refusal_outcome_v1(
            transaction,
            CoordinatorDefiniteRefusalOutcomeV1::Unhealthy,
        );
    }
    let context = match load_current_context_v1(&transaction, lookup) {
        Ok(Some(context)) => context,
        Ok(None) => {
            return rollback_refusal_outcome_v1(
                transaction,
                CoordinatorDefiniteRefusalOutcomeV1::RejectedNoAdvance,
            )
        }
        Err(error) => {
            return rollback_refusal_outcome_v1(transaction, refusal_outcome_from_error_v1(error))
        }
    };
    let candidate = match verify_exact_refusal_v1(
        &context,
        lookup,
        canonical_receipt,
        key_resolver,
        proof,
        tombstone,
    ) {
        Some(candidate) => candidate,
        None => {
            return rollback_refusal_outcome_v1(
                transaction,
                CoordinatorDefiniteRefusalOutcomeV1::RejectedNoAdvance,
            )
        }
    };
    let ids = derive_refusal_ids_v1(lookup, &context, &candidate, proof);
    if context.state == DurableDispatchStateV1::Failed {
        let prior =
            load_exact_terminal_refusal_v1(&transaction, lookup, &context, &candidate, &ids);
        return match prior {
            Ok(Some(evidence)) => rollback_refusal_outcome_v1(
                transaction,
                CoordinatorDefiniteRefusalOutcomeV1::PriorExact(evidence),
            ),
            Ok(None) => rollback_refusal_outcome_v1(
                transaction,
                CoordinatorDefiniteRefusalOutcomeV1::Conflict,
            ),
            Err(error) => {
                rollback_refusal_outcome_v1(transaction, refusal_outcome_from_error_v1(error))
            }
        };
    }
    if !context_can_close_refusal_v1(&context) {
        return rollback_refusal_outcome_v1(
            transaction,
            CoordinatorDefiniteRefusalOutcomeV1::Conflict,
        );
    }
    if matches!(
        context.state,
        DurableDispatchStateV1::OutcomeUnknown | DurableDispatchStateV1::ReconciliationRequired
    ) {
        match load_persisted_unknown_evidence_v1(&transaction, lookup) {
            Ok(Some(evidence)) if Some(evidence.reconciliation_id) == context.reconciliation_id => {
            }
            Ok(_) => {
                return rollback_refusal_outcome_v1(
                    transaction,
                    CoordinatorDefiniteRefusalOutcomeV1::Conflict,
                )
            }
            Err(error) => {
                return rollback_refusal_outcome_v1(
                    transaction,
                    refusal_outcome_from_error_v1(error),
                )
            }
        }
    }
    let receipt_footprint = transaction
        .query_row(
            "SELECT COUNT(*) FROM dispatch_receipts \
             WHERE receipt_id = ?1 OR receipt_digest = ?2 OR grant_id = ?3 OR operation_id = ?4",
            params![
                candidate.receipt_id.as_slice(),
                candidate.receipt_digest.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(map_sql_error_v1);
    match receipt_footprint {
        Ok(0) => {}
        Ok(_) => {
            return rollback_refusal_outcome_v1(
                transaction,
                CoordinatorDefiniteRefusalOutcomeV1::Conflict,
            )
        }
        Err(error) => {
            return rollback_refusal_outcome_v1(transaction, refusal_outcome_from_error_v1(error))
        }
    }
    let generations = match allocate_refusal_generations_v1(&transaction, context.state) {
        Ok(generations) => generations,
        Err(error) => {
            return rollback_refusal_outcome_v1(transaction, refusal_outcome_from_error_v1(error))
        }
    };
    let next_held = match checked_scope_release_v1(&context) {
        Ok(next_held) => next_held,
        Err(error) => {
            return rollback_refusal_outcome_v1(transaction, refusal_outcome_from_error_v1(error))
        }
    };
    if let Err(error) = stage_definite_refusal_v1(
        &transaction,
        lookup,
        &context,
        &candidate,
        proof,
        &ids,
        &generations,
        next_held,
        fault_probe,
    ) {
        return rollback_refusal_outcome_v1(transaction, refusal_outcome_from_error_v1(error));
    }
    if foreign_key_check_has_rows_v1(&transaction).unwrap_or(true)
        || !verify_live_snapshot(&transaction)
    {
        return rollback_refusal_outcome_v1(
            transaction,
            CoordinatorDefiniteRefusalOutcomeV1::Unhealthy,
        );
    }
    let evidence =
        match load_exact_terminal_refusal_v1(&transaction, lookup, &context, &candidate, &ids) {
            Ok(Some(evidence)) => evidence,
            Ok(None) => {
                return rollback_refusal_outcome_v1(
                    transaction,
                    CoordinatorDefiniteRefusalOutcomeV1::Unhealthy,
                )
            }
            Err(error) => {
                return rollback_refusal_outcome_v1(
                    transaction,
                    refusal_outcome_from_error_v1(error),
                )
            }
        };
    if fault_probe
        .checkpoint_v1(RefusalCheckpointV1::BeforeCommit)
        .is_err()
    {
        return rollback_refusal_outcome_v1(
            transaction,
            CoordinatorDefiniteRefusalOutcomeV1::Unavailable,
        );
    }
    let custody = CoordinatorDefiniteRefusalUncertainCustodyV1 {
        receipt_id: candidate.receipt_id,
        receipt_digest: candidate.receipt_digest,
        canonical_receipt_sha256: Sha256::digest(&candidate.canonical_receipt).into(),
        canonical_receipt: candidate.canonical_receipt,
        no_inflight_proof_digest: ids.no_inflight_proof_digest,
    };
    let commit_result = transaction.commit();
    if fault_probe
        .checkpoint_v1(RefusalCheckpointV1::AfterCommit)
        .is_err()
    {
        return CoordinatorDefiniteRefusalOutcomeV1::Uncertain(custody);
    }
    match commit_result {
        Ok(()) => CoordinatorDefiniteRefusalOutcomeV1::Committed(evidence),
        Err(_) => CoordinatorDefiniteRefusalOutcomeV1::Uncertain(custody),
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_definite_refusal_v1<P: RefusalFaultProbeV1>(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    candidate: &VerifiedRefusalCandidateV1,
    proof: &DispatchDefiniteAbsenceProofV1,
    ids: &RefusalIdsV1,
    generations: &RefusalGenerationsV1,
    next_held: [u64; 4],
    fault_probe: &P,
) -> Result<(), ReconciliationStageErrorV1> {
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_receipts (receipt_id, grant_id, operation_id, \
             dispatch_attempt_id, receipt_digest, canonical_receipt, canonical_receipt_length, \
             adapter_key_fingerprint, decision, refusal_code, \
             no_consumption_tombstone_digest, receipt_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'REFUSED_DEFINITE', ?9, ?10, ?11)",
        params![
            candidate.receipt_id.as_slice(),
            lookup.grant_id.as_slice(),
            &*lookup.operation_id,
            context.dispatch_attempt_id.as_slice(),
            candidate.receipt_digest.as_slice(),
            &*candidate.canonical_receipt,
            to_i64_v1(
                u64::try_from(candidate.canonical_receipt.len())
                    .map_err(|_| ReconciliationStageErrorV1::Unhealthy)?
            )?,
            candidate.adapter_key_fingerprint.as_slice(),
            candidate.refusal_code_text,
            candidate.no_consumption_tombstone_digest.as_slice(),
            to_i64_v1(generations.receipt)?,
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::Receipt)?;

    let mut previous_state = context.state;
    let mut previous_generation = context.state_generation;
    let mut previous_event_id = context.current_event_id;
    let mut state_index = 0_usize;
    let mut event_index = 0_usize;

    if context.state == DurableDispatchStateV1::Dispatching {
        exactly_one_v1(transaction.execute(
            "INSERT INTO dispatch_reconciliations (reconciliation_id, grant_id, operation_id, \
                 dispatch_attempt_id, evidence_digest, transport_quiescence_digest, \
                 no_inflight_proof_digest, result, receipt_id, receipt_decision, \
                 reconciliation_generation) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 'OUTCOME_UNKNOWN', NULL, NULL, ?7)",
            params![
                ids.unknown_reconciliation_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                ids.unknown_evidence_digest.as_slice(),
                ids.transport_quiescence_digest.as_slice(),
                to_i64_v1(
                    generations
                        .unknown_reconciliation
                        .ok_or(ReconciliationStageErrorV1::Unhealthy)?
                )?,
            ],
        ))?;
        let state_generation = generations.state[state_index];
        let event_generation = generations.event[event_index];
        exactly_one_v1(transaction.execute(
            "UPDATE dispatch_records \
             SET effective_state = 'OUTCOME_UNKNOWN', state_generation = ?1, \
                 reconciliation_id = ?2, reconciliation_result = 'OUTCOME_UNKNOWN', \
                 current_event_id = ?3 \
             WHERE operation_id = ?4 AND grant_id = ?5 AND dispatch_attempt_id = ?6 \
               AND effective_state = 'DISPATCHING' AND state_generation = ?7 \
               AND current_event_id = ?8 AND receipt_id IS NULL \
               AND reconciliation_id IS NULL",
            params![
                to_i64_v1(state_generation)?,
                ids.unknown_reconciliation_id.as_slice(),
                ids.unknown_event_id.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(previous_generation)?,
                previous_event_id.as_slice(),
            ],
        ))?;
        exactly_one_v1(transaction.execute(
            "INSERT INTO dispatch_transitions (state_generation, \
                 previous_transition_generation, operation_id, grant_id, dispatch_attempt_id, \
                 previous_state, new_state, event_id, evidence_digest, receipt_id, \
                 receipt_decision, reconciliation_id, reconciliation_result, \
                 definite_refusal_guard_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'DISPATCHING', 'OUTCOME_UNKNOWN', ?6, ?7, \
                     NULL, NULL, ?8, 'OUTCOME_UNKNOWN', NULL)",
            params![
                to_i64_v1(state_generation)?,
                to_i64_v1(previous_generation)?,
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                ids.unknown_event_id.as_slice(),
                ids.unknown_evidence_digest.as_slice(),
                ids.unknown_reconciliation_id.as_slice(),
            ],
        ))?;
        fault_probe.checkpoint_v1(RefusalCheckpointV1::UnknownTransition)?;
        insert_dispatch_event_v1(
            transaction,
            lookup,
            context,
            ids.unknown_event_id,
            event_generation,
            state_generation,
            "OUTCOME_UNKNOWN",
            "OUTCOME_UNKNOWN",
            0,
            "DISPATCH_UNKNOWN",
            None,
            &candidate.trace_id,
        )?;
        fault_probe.checkpoint_v1(RefusalCheckpointV1::UnknownEvent)?;
        previous_state = DurableDispatchStateV1::OutcomeUnknown;
        previous_generation = state_generation;
        previous_event_id = ids.unknown_event_id;
        state_index += 1;
        event_index += 1;
    }

    if previous_state == DurableDispatchStateV1::OutcomeUnknown {
        let state_generation = generations.state[state_index];
        let event_generation = generations.event[event_index];
        exactly_one_v1(transaction.execute(
            "UPDATE dispatch_records \
             SET effective_state = 'RECONCILIATION_REQUIRED', state_generation = ?1, \
                 receipt_id = ?2, receipt_decision = 'REFUSED_DEFINITE', \
                 reconciliation_id = ?3, reconciliation_result = 'REFUSED_DEFINITE', \
                 current_event_id = ?4 \
             WHERE operation_id = ?5 AND grant_id = ?6 AND dispatch_attempt_id = ?7 \
               AND effective_state = 'OUTCOME_UNKNOWN' AND state_generation = ?8 \
               AND current_event_id = ?9 AND receipt_id IS NULL \
               AND reconciliation_result = 'OUTCOME_UNKNOWN'",
            params![
                to_i64_v1(state_generation)?,
                candidate.receipt_id.as_slice(),
                ids.reconciliation_id.as_slice(),
                ids.reconciliation_event_id.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(previous_generation)?,
                previous_event_id.as_slice(),
            ],
        ))?;
        exactly_one_v1(transaction.execute(
            "INSERT INTO dispatch_transitions (state_generation, \
                 previous_transition_generation, operation_id, grant_id, dispatch_attempt_id, \
                 previous_state, new_state, event_id, evidence_digest, receipt_id, \
                 receipt_decision, reconciliation_id, reconciliation_result, \
                 definite_refusal_guard_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'OUTCOME_UNKNOWN', \
                     'RECONCILIATION_REQUIRED', ?6, ?7, ?8, 'REFUSED_DEFINITE', ?9, \
                     'REFUSED_DEFINITE', NULL)",
            params![
                to_i64_v1(state_generation)?,
                to_i64_v1(previous_generation)?,
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                ids.reconciliation_event_id.as_slice(),
                ids.reconciliation_evidence_digest.as_slice(),
                candidate.receipt_id.as_slice(),
                ids.reconciliation_id.as_slice(),
            ],
        ))?;
        fault_probe.checkpoint_v1(RefusalCheckpointV1::RequiredTransition)?;
        insert_dispatch_event_v1(
            transaction,
            lookup,
            context,
            ids.reconciliation_event_id,
            event_generation,
            state_generation,
            "RECONCILIATION_REQUIRED",
            "REFUSED_DEFINITE",
            1,
            "DISPATCH_RECONCILED",
            Some(candidate.refusal_code_text),
            &candidate.trace_id,
        )?;
        fault_probe.checkpoint_v1(RefusalCheckpointV1::RequiredEvent)?;
        previous_generation = state_generation;
        previous_event_id = ids.reconciliation_event_id;
        state_index += 1;
        event_index += 1;
    }

    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_reconciliations (reconciliation_id, grant_id, operation_id, \
             dispatch_attempt_id, evidence_digest, transport_quiescence_digest, \
             no_inflight_proof_digest, result, receipt_id, receipt_decision, \
             reconciliation_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'REFUSED_DEFINITE', ?8, \
                 'REFUSED_DEFINITE', ?9)",
        params![
            ids.reconciliation_id.as_slice(),
            lookup.grant_id.as_slice(),
            &*lookup.operation_id,
            context.dispatch_attempt_id.as_slice(),
            ids.reconciliation_evidence_digest.as_slice(),
            ids.transport_quiescence_digest.as_slice(),
            ids.no_inflight_proof_digest.as_slice(),
            candidate.receipt_id.as_slice(),
            to_i64_v1(generations.refusal_reconciliation)?,
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::Reconciliation)?;
    verify_fenced_no_inflight_proof_binding_v1(
        transaction,
        lookup,
        context,
        candidate,
        proof,
        ids,
    )?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::FencedProof)?;
    verify_permanent_no_consumption_tombstone_binding_v1(transaction, lookup, context, candidate)?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::Tombstone)?;

    let refusal_state_generation = *generations
        .state
        .last()
        .ok_or(ReconciliationStageErrorV1::Unhealthy)?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_definite_refusal_guards (guard_id, operation_id, grant_id, \
             dispatch_attempt_id, preparation_attempt_id, plan_id, task_lease_digest, \
             receipt_id, receipt_digest, reconciliation_id, transport_quiescence_digest, \
             no_inflight_proof_digest, refusal_transition_generation, refusal_event_id, \
             base_failure_transition_generation, base_failure_event_id, reservation_id, \
             reservation_released_generation, guard_generation, receipt_decision, \
             reconciliation_result, final_dispatch_state, base_operation_state, \
             reservation_state) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                 ?15, ?16, ?17, ?18, ?19, 'REFUSED_DEFINITE', 'REFUSED_DEFINITE', \
                 'FAILED', 'FAILED', 'RELEASED')",
        params![
            ids.guard_id.as_slice(),
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            context.preparation_attempt_id.as_slice(),
            context.plan_id.as_slice(),
            context.task_lease_digest.as_slice(),
            candidate.receipt_id.as_slice(),
            candidate.receipt_digest.as_slice(),
            ids.reconciliation_id.as_slice(),
            ids.transport_quiescence_digest.as_slice(),
            ids.no_inflight_proof_digest.as_slice(),
            to_i64_v1(refusal_state_generation)?,
            ids.failed_event_id.as_slice(),
            to_i64_v1(generations.base_operation)?,
            ids.base_failed_event_id.as_slice(),
            context.reservation_id,
            to_i64_v1(generations.base_store)?,
            to_i64_v1(generations.dispatch_final_store)?,
        ],
    ))?;

    exactly_one_v1(transaction.execute(
        "UPDATE prepared_operations \
         SET operation_state = 'FAILED', state_generation = ?1, failed_generation = ?2, \
             failed_reason_code = ?3, current_event_id = ?4 \
         WHERE operation_id = ?5 AND attempt_id = ?6 AND plan_id = ?7 \
           AND operation_state = 'PREPARING' AND state_generation = ?8 \
           AND current_event_id = ?9 AND failed_generation IS NULL \
           AND failed_reason_code IS NULL AND reservation_id = ?10",
        params![
            to_i64_v1(generations.base_operation)?,
            to_i64_v1(generations.base_store)?,
            candidate.refusal_code_text,
            ids.base_failed_event_id.as_slice(),
            &*lookup.operation_id,
            context.preparation_attempt_id.as_slice(),
            context.plan_id.as_slice(),
            to_i64_v1(context.base_state_generation)?,
            context.base_current_event_id.as_slice(),
            context.reservation_id,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO operation_transitions (state_generation, operation_id, previous_state, \
             new_state, event_id) VALUES (?1, ?2, 'PREPARING', 'FAILED', ?3)",
        params![
            to_i64_v1(generations.base_operation)?,
            &*lookup.operation_id,
            ids.base_failed_event_id.as_slice(),
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::BaseTransition)?;

    exactly_one_v1(transaction.execute(
        "UPDATE budget_scopes \
         SET held_cost_micro_units = ?1, held_action_count = ?2, held_egress_bytes = ?3, \
             held_recovery_bytes = ?4 \
         WHERE scope_id = ?5 AND held_cost_micro_units = ?6 AND held_action_count = ?7 \
           AND held_egress_bytes = ?8 AND held_recovery_bytes = ?9",
        params![
            to_i64_v1(next_held[0])?,
            to_i64_v1(next_held[1])?,
            to_i64_v1(next_held[2])?,
            to_i64_v1(next_held[3])?,
            context.scope_id.as_slice(),
            to_i64_v1(context.held[0])?,
            to_i64_v1(context.held[1])?,
            to_i64_v1(context.held[2])?,
            to_i64_v1(context.held[3])?,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE budget_reservations \
         SET reservation_state = 'RELEASED', released_generation = ?1 \
         WHERE reservation_id = ?2 AND operation_id = ?3 AND attempt_id = ?4 \
           AND plan_id = ?5 AND task_lease_digest = ?6 \
           AND reservation_state = 'HELD' AND released_generation IS NULL",
        params![
            to_i64_v1(generations.base_store)?,
            context.reservation_id,
            &*lookup.operation_id,
            context.preparation_attempt_id.as_slice(),
            context.plan_id.as_slice(),
            context.task_lease_digest.as_slice(),
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::Reservation)?;

    exactly_one_v1(transaction.execute(
        "INSERT INTO preparation_events (event_id, event_generation, operation_id, \
             operation_state_generation, operation_state, event_kind, reason_code, \
             delivery_state, delivered_generation) \
         VALUES (?1, ?2, ?3, ?4, 'FAILED', 'PREPARATION_FAILED', ?5, 'PENDING', NULL)",
        params![
            ids.base_failed_event_id.as_slice(),
            to_i64_v1(generations.base_event)?,
            &*lookup.operation_id,
            to_i64_v1(generations.base_operation)?,
            candidate.refusal_code_text,
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::BaseEvent)?;

    let failed_state_generation = generations.state[state_index];
    let failed_event_generation = generations.event[event_index];
    // The current-projection trigger requires this record mutation before the append-only
    // FAILED transition. FB068 therefore belongs here even though registry ordinals remain
    // a stable catalogue order rather than the execution order of this SQL path.
    let final_update = if context.state == DurableDispatchStateV1::ReconciliationRequired {
        transaction.execute(
            "UPDATE dispatch_records \
             SET effective_state = 'FAILED', state_generation = ?1, receipt_id = ?2, \
                 receipt_decision = 'REFUSED_DEFINITE', reconciliation_id = ?3, \
                 reconciliation_result = 'REFUSED_DEFINITE', current_event_id = ?4 \
             WHERE operation_id = ?5 AND grant_id = ?6 AND dispatch_attempt_id = ?7 \
               AND effective_state = 'RECONCILIATION_REQUIRED' AND state_generation = ?8 \
               AND current_event_id = ?9 AND receipt_id IS NULL \
               AND reconciliation_result = 'OUTCOME_UNKNOWN'",
            params![
                to_i64_v1(failed_state_generation)?,
                candidate.receipt_id.as_slice(),
                ids.reconciliation_id.as_slice(),
                ids.failed_event_id.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(previous_generation)?,
                previous_event_id.as_slice(),
            ],
        )
    } else {
        transaction.execute(
            "UPDATE dispatch_records \
             SET effective_state = 'FAILED', state_generation = ?1, current_event_id = ?2 \
             WHERE operation_id = ?3 AND grant_id = ?4 AND dispatch_attempt_id = ?5 \
               AND effective_state = 'RECONCILIATION_REQUIRED' AND state_generation = ?6 \
               AND current_event_id = ?7 AND receipt_id = ?8 \
               AND receipt_decision = 'REFUSED_DEFINITE' AND reconciliation_id = ?9 \
               AND reconciliation_result = 'REFUSED_DEFINITE'",
            params![
                to_i64_v1(failed_state_generation)?,
                ids.failed_event_id.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(previous_generation)?,
                previous_event_id.as_slice(),
                candidate.receipt_id.as_slice(),
                ids.reconciliation_id.as_slice(),
            ],
        )
    };
    exactly_one_v1(final_update)?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::FinalRecord)?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_transitions (state_generation, previous_transition_generation, \
             operation_id, grant_id, dispatch_attempt_id, previous_state, new_state, event_id, \
             evidence_digest, receipt_id, receipt_decision, reconciliation_id, \
             reconciliation_result, definite_refusal_guard_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'RECONCILIATION_REQUIRED', 'FAILED', ?6, ?7, ?8, \
                 'REFUSED_DEFINITE', ?9, 'REFUSED_DEFINITE', ?10)",
        params![
            to_i64_v1(failed_state_generation)?,
            to_i64_v1(previous_generation)?,
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            ids.failed_event_id.as_slice(),
            ids.reconciliation_evidence_digest.as_slice(),
            candidate.receipt_id.as_slice(),
            ids.reconciliation_id.as_slice(),
            ids.guard_id.as_slice(),
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::FailedTransition)?;
    insert_dispatch_event_v1(
        transaction,
        lookup,
        context,
        ids.failed_event_id,
        failed_event_generation,
        failed_state_generation,
        "FAILED",
        "REFUSED_DEFINITE",
        1,
        "DISPATCH_REFUSED",
        Some(candidate.refusal_code_text),
        &candidate.trace_id,
    )?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::FailedEvent)?;

    let quiesced_attempt_number = next_safe_v1(context.current_attempt_number)?;
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_delivery_attempts (attempt_generation, grant_id, operation_id, \
             dispatch_attempt_id, attempt_number, handoff_guard_digest, classification, \
             adapter_root_digest, adapter_epoch, readback_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'QUIESCED', ?7, ?8, ?9)",
        params![
            to_i64_v1(generations.delivery)?,
            lookup.grant_id.as_slice(),
            &*lookup.operation_id,
            context.dispatch_attempt_id.as_slice(),
            to_i64_v1(quiesced_attempt_number)?,
            ids.quiesced_handoff_guard_digest.as_slice(),
            proof.adapter_root().as_slice(),
            to_i64_v1(proof.supervisor_epoch())?,
            to_i64_v1(proof.readback_generation())?,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_outbox \
         SET delivery_state = 'QUIESCED', delivery_generation = ?1, \
             current_attempt_generation = ?1, receipt_id = ?2, \
             receipt_decision = 'REFUSED_DEFINITE' \
         WHERE grant_id = ?3 AND operation_id = ?4 AND dispatch_attempt_id = ?5 \
           AND delivery_state = ?6 AND delivery_generation = ?7 \
           AND current_attempt_generation = ?8 AND receipt_id IS NULL",
        params![
            to_i64_v1(generations.delivery)?,
            candidate.receipt_id.as_slice(),
            lookup.grant_id.as_slice(),
            &*lookup.operation_id,
            context.dispatch_attempt_id.as_slice(),
            context.outbox_state,
            to_i64_v1(context.delivery_generation)?,
            to_i64_v1(context.current_attempt_generation)?,
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::Outbox)?;

    exactly_one_v1(transaction.execute(
        "UPDATE coordinator_store_meta \
         SET store_generation = ?1, operation_generation = ?2, budget_generation = ?3, \
             event_generation = ?4 \
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
           AND store_generation = ?5 AND operation_generation = ?6 \
           AND budget_generation = ?7 AND event_generation = ?8",
        params![
            to_i64_v1(generations.base_store)?,
            to_i64_v1(generations.base_operation)?,
            to_i64_v1(generations.base_budget)?,
            to_i64_v1(generations.base_event)?,
            to_i64_v1(generations.base_previous.store)?,
            to_i64_v1(generations.base_previous.operation)?,
            to_i64_v1(generations.base_previous.budget)?,
            to_i64_v1(generations.base_previous.event)?,
        ],
    ))?;
    exactly_one_v1(transaction.execute(
        "UPDATE dispatch_store_meta \
         SET dispatch_store_generation = ?1, dispatch_generation = ?2, \
             delivery_generation = ?3, receipt_generation = ?4, \
             reconciliation_generation = ?5, event_generation = ?6 \
         WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE' \
           AND dispatch_store_generation = ?7 AND dispatch_generation = ?8 \
           AND delivery_generation = ?9 AND receipt_generation = ?10 \
           AND reconciliation_generation = ?11 AND event_generation = ?12",
        params![
            to_i64_v1(generations.dispatch_final_store)?,
            to_i64_v1(failed_state_generation)?,
            to_i64_v1(generations.delivery)?,
            to_i64_v1(generations.receipt)?,
            to_i64_v1(generations.refusal_reconciliation)?,
            to_i64_v1(failed_event_generation)?,
            to_i64_v1(generations.dispatch_previous.store)?,
            to_i64_v1(generations.dispatch_previous.dispatch)?,
            to_i64_v1(generations.dispatch_previous.delivery)?,
            to_i64_v1(generations.dispatch_previous.receipt)?,
            to_i64_v1(generations.dispatch_previous.reconciliation)?,
            to_i64_v1(generations.dispatch_previous.event)?,
        ],
    ))?;
    fault_probe.checkpoint_v1(RefusalCheckpointV1::Metadata)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_dispatch_event_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    event_id: [u8; 32],
    event_generation: u64,
    transition_generation: u64,
    state: &str,
    decision: &str,
    receipt_contract_version: u8,
    event_kind: &str,
    public_reason_code: Option<&str>,
    public_trace_id: &str,
) -> Result<(), ReconciliationStageErrorV1> {
    exactly_one_v1(transaction.execute(
        "INSERT INTO dispatch_events (event_id, event_generation, transition_generation, \
             operation_id, grant_id, dispatch_attempt_id, task_id, workload_id, plan_id, \
             task_lease_digest, event_contract_version, grant_contract_version, \
             receipt_contract_version, effective_state, decision, latency_ms, event_kind, \
             public_reason_code, public_trace_id, delivery_state, delivered_generation) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, 1, ?11, ?12, ?13, 0, \
                 ?14, ?15, ?16, 'PENDING', NULL)",
        params![
            event_id.as_slice(),
            to_i64_v1(event_generation)?,
            to_i64_v1(transition_generation)?,
            &*lookup.operation_id,
            lookup.grant_id.as_slice(),
            context.dispatch_attempt_id.as_slice(),
            context.task_id,
            context.workload_id,
            context.plan_id.as_slice(),
            context.task_lease_digest.as_slice(),
            i64::from(receipt_contract_version),
            state,
            decision,
            event_kind,
            public_reason_code,
            public_trace_id,
        ],
    ))
}

fn verify_fenced_no_inflight_proof_binding_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    candidate: &VerifiedRefusalCandidateV1,
    proof: &DispatchDefiniteAbsenceProofV1,
    ids: &RefusalIdsV1,
) -> Result<(), ReconciliationStageErrorV1> {
    if proof.delivery_attempt_id() != context.dispatch_attempt_id
        || proof.readback_generation() != context.initial_handoff_generation
        || proof.exclusive_deadline_monotonic_ms() != context.deadline_monotonic_ms
        || proof.supervisor_epoch() != candidate.observed_supervisor_epoch
        || proof.adapter_root() == [0; 32]
        || context.current_adapter_root_id != Some(proof.adapter_root())
        || context.current_adapter_epoch != Some(proof.supervisor_epoch())
        || context.current_readback_generation != Some(proof.readback_generation())
    {
        return Err(ReconciliationStageErrorV1::Rejected);
    }
    let exact: i64 = transaction
        .query_row(
            "SELECT CASE WHEN \
                 (SELECT COUNT(*) FROM dispatch_delivery_attempts \
                   WHERE grant_id = ?1 AND operation_id = ?2 AND dispatch_attempt_id = ?3 \
                     AND attempt_generation = ?4 AND classification = 'POSSIBLE_HANDOFF' \
                     AND adapter_root_digest IS NULL AND adapter_epoch IS NULL \
                     AND readback_generation IS NULL) = 1 \
             AND (SELECT COUNT(*) FROM dispatch_reconciliations \
                   WHERE reconciliation_id = ?5 AND grant_id = ?1 AND operation_id = ?2 \
                     AND dispatch_attempt_id = ?3 AND result = 'REFUSED_DEFINITE' \
                     AND receipt_id = ?6 AND receipt_decision = 'REFUSED_DEFINITE' \
                     AND transport_quiescence_digest = ?7 \
                     AND no_inflight_proof_digest = ?8) = 1 \
             THEN 1 ELSE 0 END",
            params![
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                to_i64_v1(context.initial_handoff_generation)?,
                ids.reconciliation_id.as_slice(),
                candidate.receipt_id.as_slice(),
                ids.transport_quiescence_digest.as_slice(),
                ids.no_inflight_proof_digest.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(map_sql_error_v1)?;
    if exact == 1 {
        Ok(())
    } else {
        Err(ReconciliationStageErrorV1::Unhealthy)
    }
}

fn verify_permanent_no_consumption_tombstone_binding_v1(
    transaction: &Transaction<'_>,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    candidate: &VerifiedRefusalCandidateV1,
) -> Result<(), ReconciliationStageErrorV1> {
    let canonical_length = to_i64_v1(
        u64::try_from(candidate.canonical_receipt.len())
            .map_err(|_| ReconciliationStageErrorV1::Unhealthy)?,
    )?;
    let exact: i64 = transaction
        .query_row(
            "SELECT CASE WHEN (SELECT COUNT(*) FROM dispatch_receipts \
                   WHERE receipt_id = ?1 AND grant_id = ?2 AND operation_id = ?3 \
                     AND dispatch_attempt_id = ?4 AND receipt_digest = ?5 \
                     AND canonical_receipt = ?6 AND canonical_receipt_length = ?7 \
                     AND adapter_key_fingerprint = ?8 \
                     AND decision = 'REFUSED_DEFINITE' AND refusal_code = ?9 \
                     AND no_consumption_tombstone_digest = ?10) = 1 \
             THEN 1 ELSE 0 END",
            params![
                candidate.receipt_id.as_slice(),
                lookup.grant_id.as_slice(),
                &*lookup.operation_id,
                context.dispatch_attempt_id.as_slice(),
                candidate.receipt_digest.as_slice(),
                &*candidate.canonical_receipt,
                canonical_length,
                candidate.adapter_key_fingerprint.as_slice(),
                candidate.refusal_code_text,
                candidate.no_consumption_tombstone_digest.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(map_sql_error_v1)?;
    if exact == 1 {
        Ok(())
    } else {
        Err(ReconciliationStageErrorV1::Unhealthy)
    }
}

fn load_exact_terminal_refusal_v1(
    connection: &Connection,
    lookup: &CoordinatorReconciliationLookupV1,
    context: &CurrentReconciliationContextV1,
    candidate: &VerifiedRefusalCandidateV1,
    ids: &RefusalIdsV1,
) -> Result<Option<CoordinatorDefiniteRefusalEvidenceV1>, ReconciliationStageErrorV1> {
    let raw = connection
        .query_row(
            "SELECT guard.receipt_id, guard.reconciliation_id, guard.guard_id, \
                    guard.refusal_transition_generation, \
                    guard.base_failure_transition_generation, \
                    guard.reservation_released_generation \
             FROM dispatch_definite_refusal_guards AS guard \
             JOIN dispatch_records AS record \
               ON record.operation_id = guard.operation_id \
              AND record.grant_id = guard.grant_id \
              AND record.dispatch_attempt_id = guard.dispatch_attempt_id \
              AND record.receipt_id = guard.receipt_id \
              AND record.reconciliation_id = guard.reconciliation_id \
              AND record.state_generation = guard.refusal_transition_generation \
              AND record.current_event_id = guard.refusal_event_id \
              AND record.effective_state = 'FAILED' \
             JOIN dispatch_receipts AS receipt \
               ON receipt.receipt_id = guard.receipt_id \
              AND receipt.grant_id = guard.grant_id \
              AND receipt.operation_id = guard.operation_id \
              AND receipt.dispatch_attempt_id = guard.dispatch_attempt_id \
              AND receipt.decision = 'REFUSED_DEFINITE' \
              AND receipt.receipt_digest = guard.receipt_digest \
             JOIN dispatch_reconciliations AS reconciliation \
               ON reconciliation.reconciliation_id = guard.reconciliation_id \
              AND reconciliation.grant_id = guard.grant_id \
              AND reconciliation.operation_id = guard.operation_id \
              AND reconciliation.dispatch_attempt_id = guard.dispatch_attempt_id \
              AND reconciliation.result = 'REFUSED_DEFINITE' \
              AND reconciliation.receipt_id = guard.receipt_id \
              AND reconciliation.transport_quiescence_digest = \
                  guard.transport_quiescence_digest \
              AND reconciliation.no_inflight_proof_digest = guard.no_inflight_proof_digest \
             JOIN dispatch_transitions AS final_transition \
               ON final_transition.definite_refusal_guard_id = guard.guard_id \
              AND final_transition.operation_id = guard.operation_id \
              AND final_transition.grant_id = guard.grant_id \
              AND final_transition.dispatch_attempt_id = guard.dispatch_attempt_id \
              AND final_transition.state_generation = guard.refusal_transition_generation \
              AND final_transition.event_id = guard.refusal_event_id \
              AND final_transition.previous_state = 'RECONCILIATION_REQUIRED' \
              AND final_transition.new_state = 'FAILED' \
             JOIN dispatch_events AS final_event \
               ON final_event.event_id = guard.refusal_event_id \
              AND final_event.operation_id = guard.operation_id \
              AND final_event.grant_id = guard.grant_id \
              AND final_event.transition_generation = guard.refusal_transition_generation \
              AND final_event.effective_state = 'FAILED' \
              AND final_event.event_kind = 'DISPATCH_REFUSED' \
              AND final_event.decision = 'REFUSED_DEFINITE' \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = guard.grant_id \
              AND outbox.operation_id = guard.operation_id \
              AND outbox.dispatch_attempt_id = guard.dispatch_attempt_id \
              AND outbox.delivery_state = 'QUIESCED' \
              AND outbox.receipt_id = guard.receipt_id \
              AND outbox.receipt_decision = 'REFUSED_DEFINITE' \
             JOIN dispatch_delivery_attempts AS quiesced \
               ON quiesced.attempt_generation = outbox.current_attempt_generation \
              AND quiesced.grant_id = guard.grant_id \
              AND quiesced.operation_id = guard.operation_id \
              AND quiesced.dispatch_attempt_id = guard.dispatch_attempt_id \
              AND quiesced.classification = 'QUIESCED' \
             JOIN prepared_operations AS operation \
               ON operation.operation_id = guard.operation_id \
              AND operation.attempt_id = guard.preparation_attempt_id \
              AND operation.reservation_id = guard.reservation_id \
              AND operation.state_generation = guard.base_failure_transition_generation \
              AND operation.current_event_id = guard.base_failure_event_id \
              AND operation.operation_state = 'FAILED' \
             JOIN operation_transitions AS base_transition \
               ON base_transition.operation_id = guard.operation_id \
              AND base_transition.state_generation = guard.base_failure_transition_generation \
              AND base_transition.event_id = guard.base_failure_event_id \
              AND base_transition.previous_state = 'PREPARING' \
              AND base_transition.new_state = 'FAILED' \
             JOIN preparation_events AS base_event \
               ON base_event.event_id = guard.base_failure_event_id \
              AND base_event.operation_id = guard.operation_id \
              AND base_event.operation_state_generation = \
                  guard.base_failure_transition_generation \
              AND base_event.operation_state = 'FAILED' \
              AND base_event.event_kind = 'PREPARATION_FAILED' \
             JOIN budget_reservations AS reservation \
               ON reservation.reservation_id = guard.reservation_id \
              AND reservation.operation_id = guard.operation_id \
              AND reservation.attempt_id = guard.preparation_attempt_id \
              AND reservation.plan_id = guard.plan_id \
              AND reservation.task_lease_digest = guard.task_lease_digest \
              AND reservation.reservation_state = 'RELEASED' \
              AND reservation.released_generation = guard.reservation_released_generation \
             WHERE guard.guard_id = ?1 AND guard.operation_id = ?2 AND guard.grant_id = ?3 \
               AND guard.dispatch_attempt_id = ?4 AND guard.receipt_id = ?5 \
               AND guard.receipt_digest = ?6 AND guard.reconciliation_id = ?7 \
               AND guard.transport_quiescence_digest = ?8 \
               AND guard.no_inflight_proof_digest = ?9 \
               AND guard.refusal_event_id = ?10 AND guard.base_failure_event_id = ?11 \
               AND receipt.canonical_receipt = ?12 \
               AND receipt.canonical_receipt_length = ?13 \
               AND receipt.adapter_key_fingerprint = ?14 AND receipt.refusal_code = ?15 \
               AND receipt.no_consumption_tombstone_digest = ?16 \
               AND reconciliation.evidence_digest = ?17 \
               AND quiesced.handoff_guard_digest = ?18 \
               AND quiesced.readback_generation = ?19 \
               AND quiesced.adapter_root_digest = ?20 \
               AND quiesced.adapter_epoch = ?21 \
               AND operation.failed_generation = guard.reservation_released_generation \
               AND operation.failed_reason_code = ?15 \
               AND base_event.reason_code = ?15",
            params![
                ids.guard_id.as_slice(),
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                context.dispatch_attempt_id.as_slice(),
                candidate.receipt_id.as_slice(),
                candidate.receipt_digest.as_slice(),
                ids.reconciliation_id.as_slice(),
                ids.transport_quiescence_digest.as_slice(),
                ids.no_inflight_proof_digest.as_slice(),
                ids.failed_event_id.as_slice(),
                ids.base_failed_event_id.as_slice(),
                &*candidate.canonical_receipt,
                to_i64_v1(
                    u64::try_from(candidate.canonical_receipt.len())
                        .map_err(|_| ReconciliationStageErrorV1::Unhealthy)?
                )?,
                candidate.adapter_key_fingerprint.as_slice(),
                candidate.refusal_code_text,
                candidate.no_consumption_tombstone_digest.as_slice(),
                ids.reconciliation_evidence_digest.as_slice(),
                ids.quiesced_handoff_guard_digest.as_slice(),
                to_i64_v1(context.initial_handoff_generation)?,
                context
                    .current_adapter_root_id
                    .ok_or(ReconciliationStageErrorV1::Unhealthy)?
                    .as_slice(),
                to_i64_v1(
                    context
                        .current_adapter_epoch
                        .ok_or(ReconciliationStageErrorV1::Unhealthy)?
                )?,
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql_error_v1)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let chain_exact: i64 = connection
        .query_row(
            "SELECT CASE WHEN \
                 (SELECT COUNT(*) FROM dispatch_transitions \
                   WHERE operation_id = ?1 AND grant_id = ?2 \
                     AND previous_state = 'DISPATCHING' AND new_state = 'OUTCOME_UNKNOWN') = 1 \
             AND (SELECT COUNT(*) FROM dispatch_transitions \
                   WHERE operation_id = ?1 AND grant_id = ?2 \
                     AND previous_state = 'OUTCOME_UNKNOWN' \
                     AND new_state = 'RECONCILIATION_REQUIRED') = 1 \
             AND (SELECT COUNT(*) FROM dispatch_transitions \
                   WHERE operation_id = ?1 AND grant_id = ?2 \
                     AND previous_state = 'RECONCILIATION_REQUIRED' \
                     AND new_state = 'FAILED' AND receipt_id = ?3 \
                     AND reconciliation_id = ?4 AND definite_refusal_guard_id = ?5) = 1 \
             AND (SELECT COUNT(*) FROM dispatch_events \
                   WHERE operation_id = ?1 AND grant_id = ?2 \
                     AND event_kind IN ('DISPATCH_UNKNOWN', 'DISPATCH_RECONCILED', \
                                        'DISPATCH_REFUSED')) = 3 \
             AND (SELECT COUNT(*) FROM operation_transitions \
                   WHERE operation_id = ?1 AND previous_state = 'PREPARING' \
                     AND new_state = 'FAILED') = 1 \
             AND (SELECT COUNT(*) FROM budget_reservations \
                   WHERE operation_id = ?1 AND reservation_state = 'RELEASED' \
                     AND released_generation IS NOT NULL) = 1 \
             THEN 1 ELSE 0 END",
            params![
                &*lookup.operation_id,
                lookup.grant_id.as_slice(),
                candidate.receipt_id.as_slice(),
                ids.reconciliation_id.as_slice(),
                ids.guard_id.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(map_sql_error_v1)?;
    if chain_exact != 1 {
        return Err(ReconciliationStageErrorV1::Unhealthy);
    }
    Ok(Some(CoordinatorDefiniteRefusalEvidenceV1 {
        receipt_id: exact_array_v1(raw.0)?,
        reconciliation_id: exact_array_v1(raw.1)?,
        guard_id: exact_array_v1(raw.2)?,
        refusal_transition_generation: safe_u64_v1(raw.3)?,
        base_failure_transition_generation: safe_u64_v1(raw.4)?,
        reservation_released_generation: safe_u64_v1(raw.5)?,
    }))
}

fn rollback_refusal_outcome_v1(
    transaction: Transaction<'_>,
    outcome: CoordinatorDefiniteRefusalOutcomeV1,
) -> CoordinatorDefiniteRefusalOutcomeV1 {
    if transaction.rollback().is_ok() {
        outcome
    } else {
        CoordinatorDefiniteRefusalOutcomeV1::Unhealthy
    }
}

fn refusal_outcome_from_error_v1(
    error: ReconciliationStageErrorV1,
) -> CoordinatorDefiniteRefusalOutcomeV1 {
    match error {
        ReconciliationStageErrorV1::Rejected => {
            CoordinatorDefiniteRefusalOutcomeV1::RejectedNoAdvance
        }
        ReconciliationStageErrorV1::Conflict => CoordinatorDefiniteRefusalOutcomeV1::Conflict,
        ReconciliationStageErrorV1::Unavailable | ReconciliationStageErrorV1::Injected => {
            CoordinatorDefiniteRefusalOutcomeV1::Unavailable
        }
        ReconciliationStageErrorV1::Unhealthy => CoordinatorDefiniteRefusalOutcomeV1::Unhealthy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn generation_fixture_v1() -> Connection {
        let connection = Connection::open_in_memory().expect("generation fixture opens");
        connection
            .execute_batch(
                "CREATE TABLE dispatch_store_meta ( \
                     singleton INTEGER PRIMARY KEY, dispatch_store_generation INTEGER NOT NULL, \
                     dispatch_generation INTEGER NOT NULL, delivery_generation INTEGER NOT NULL, \
                     receipt_generation INTEGER NOT NULL, \
                     reconciliation_generation INTEGER NOT NULL, event_generation INTEGER NOT NULL, \
                     root_lifecycle_state TEXT NOT NULL); \
                 INSERT INTO dispatch_store_meta VALUES (1, 20, 7, 20, 3, 5, 11, 'ACTIVE'); \
                 CREATE TABLE coordinator_store_meta ( \
                     singleton INTEGER PRIMARY KEY, store_generation INTEGER NOT NULL, \
                     operation_generation INTEGER NOT NULL, budget_generation INTEGER NOT NULL, \
                     event_generation INTEGER NOT NULL, root_lifecycle_state TEXT NOT NULL); \
                 INSERT INTO coordinator_store_meta VALUES (1, 30, 15, 30, 18, 'ACTIVE');",
            )
            .expect("generation fixture schema is valid");
        connection
    }

    fn unknown_exhaustion_fixture_v1(
        observation_digest: [u8; 32],
        public_trace_id: &str,
        latency_ms: u64,
    ) -> CoordinatorReadbackExhaustionV1 {
        CoordinatorReadbackExhaustionV1::try_new(
            observation_digest,
            public_trace_id.to_owned(),
            latency_ms,
        )
        .expect("unknown exhaustion fixture is valid")
    }

    fn persisted_unknown_exhaustion_fixture_v1(
        exhaustion: &CoordinatorReadbackExhaustionV1,
    ) -> PersistedUnknownExhaustionV1 {
        let ids = derive_unknown_ids_from_bindings_v1(
            "operation:t067:unknown",
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            exhaustion,
        );
        PersistedUnknownExhaustionV1 {
            reconciliation_id: ids.reconciliation_id,
            reconciliation_evidence_digest: ids.evidence_digest,
            transport_observation_digest: ids.transport_observation_digest,
            transition_evidence_digest: ids.evidence_digest,
            event_id: ids.event_id,
            public_trace_id: exhaustion.public_trace_id.to_string(),
            latency_ms: exhaustion.latency_ms,
        }
    }

    fn expected_unknown_ids_fixture_v1(
        exhaustion: &CoordinatorReadbackExhaustionV1,
    ) -> UnknownIdsV1 {
        derive_unknown_ids_from_bindings_v1(
            "operation:t067:unknown",
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            exhaustion,
        )
    }

    #[test]
    fn fresh_readback_permit_is_generation_bound_and_concurrently_one_shot() {
        let source_generation = 41;
        let permit = Arc::new(CoordinatorAutomaticReadbackPermitV1::new_v1(
            source_generation,
        ));
        assert!(!permit.try_begin_automatic_readback_once_v1(source_generation - 1));

        let starts = (0..16)
            .map(|_| {
                let permit = Arc::clone(&permit);
                std::thread::spawn(move || {
                    permit.try_begin_automatic_readback_once_v1(source_generation)
                })
            })
            .map(|thread| thread.join().expect("readback gate thread must not panic"))
            .filter(|started| *started)
            .count();

        assert_eq!(starts, 1);
        assert!(!permit.try_begin_automatic_readback_once_v1(source_generation));
    }

    #[test]
    fn exact_unknown_exhaustion_repeat_is_resumable() {
        let persisted_exhaustion =
            unknown_exhaustion_fixture_v1([0x44; 32], "trace:t067:readback-exhausted", 275);
        let persisted = persisted_unknown_exhaustion_fixture_v1(&persisted_exhaustion);
        let repeated =
            unknown_exhaustion_fixture_v1([0x44; 32], "trace:t067:readback-exhausted", 275);
        let expected = expected_unknown_ids_fixture_v1(&repeated);

        assert!(persisted_unknown_exhaustion_bindings_match_v1(
            &persisted, &expected, &repeated,
        ));
    }

    #[test]
    fn unknown_exhaustion_observation_digest_mismatch_is_conflict() {
        let persisted_exhaustion =
            unknown_exhaustion_fixture_v1([0x44; 32], "trace:t067:readback-exhausted", 275);
        let persisted = persisted_unknown_exhaustion_fixture_v1(&persisted_exhaustion);
        let mismatched =
            unknown_exhaustion_fixture_v1([0x45; 32], "trace:t067:readback-exhausted", 275);
        let expected = expected_unknown_ids_fixture_v1(&mismatched);

        assert!(!persisted_unknown_exhaustion_bindings_match_v1(
            &persisted,
            &expected,
            &mismatched,
        ));
    }

    #[test]
    fn unknown_exhaustion_trace_id_mismatch_is_conflict() {
        let persisted_exhaustion =
            unknown_exhaustion_fixture_v1([0x44; 32], "trace:t067:readback-exhausted", 275);
        let persisted = persisted_unknown_exhaustion_fixture_v1(&persisted_exhaustion);
        let mismatched = unknown_exhaustion_fixture_v1([0x44; 32], "trace:t067:other", 275);
        let expected = expected_unknown_ids_fixture_v1(&mismatched);

        assert!(!persisted_unknown_exhaustion_bindings_match_v1(
            &persisted,
            &expected,
            &mismatched,
        ));
    }

    #[test]
    fn unknown_exhaustion_latency_mismatch_is_conflict() {
        let persisted_exhaustion =
            unknown_exhaustion_fixture_v1([0x44; 32], "trace:t067:readback-exhausted", 275);
        let persisted = persisted_unknown_exhaustion_fixture_v1(&persisted_exhaustion);
        let mismatched =
            unknown_exhaustion_fixture_v1([0x44; 32], "trace:t067:readback-exhausted", 276);
        let expected = expected_unknown_ids_fixture_v1(&mismatched);

        assert!(!persisted_unknown_exhaustion_bindings_match_v1(
            &persisted,
            &expected,
            &mismatched,
        ));
    }

    #[test]
    fn generation_allocators_advance_mutated_axes_from_the_global_high_water() {
        let connection = generation_fixture_v1();

        let claim = allocate_sequence_claim_generations_v1(&connection)
            .unwrap_or_else(|_| panic!("claim generations allocate"));
        assert_eq!((claim.final_store, claim.delivery), (21, 21));

        let unknown = allocate_unknown_generations_v1(&connection)
            .unwrap_or_else(|_| panic!("unknown generations allocate"));
        assert_eq!(
            (
                unknown.final_store,
                unknown.state,
                unknown.reconciliation,
                unknown.event,
            ),
            (21, 21, 21, 21),
        );

        let required = allocate_required_generations_v1(&connection)
            .unwrap_or_else(|_| panic!("required generations allocate"));
        assert_eq!(
            (required.final_store, required.state, required.event),
            (21, 21, 21),
        );
    }

    #[test]
    fn refusal_allocations_form_global_sequences_and_close_both_store_high_waters() {
        let expected = [
            (
                DurableDispatchStateV1::Dispatching,
                vec![21, 22, 23],
                Some(21),
                23,
            ),
            (
                DurableDispatchStateV1::OutcomeUnknown,
                vec![21, 22],
                None,
                22,
            ),
            (
                DurableDispatchStateV1::ReconciliationRequired,
                vec![21],
                None,
                21,
            ),
        ];
        for (state, sequence, unknown_reconciliation, final_store) in expected {
            let connection = generation_fixture_v1();
            let generations = allocate_refusal_generations_v1(&connection, state)
                .unwrap_or_else(|_| panic!("refusal generations allocate"));
            assert_eq!(generations.state, sequence);
            assert_eq!(generations.event, sequence);
            assert_eq!(generations.unknown_reconciliation, unknown_reconciliation);
            assert_eq!(generations.dispatch_final_store, final_store);
            assert_eq!(generations.delivery, final_store);
            assert_eq!(generations.receipt, final_store);
            assert_eq!(generations.refusal_reconciliation, final_store);
            assert_eq!(generations.base_store, 31);
            assert_eq!(generations.base_operation, 31);
            assert_eq!(generations.base_budget, 31);
            assert_eq!(generations.base_event, 31);
        }
    }
}
