//! Portable orchestration traits for durable one-shot dispatch.
//!
//! The public boundary is synchronous and platform-neutral. Durable storage,
//! transport and effect execution remain outside this crate.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod attempt;
mod authority;
mod commit_gate;
mod compare;
mod control;
mod coordinator;
mod guard;
mod inbox;
mod outcome;
mod queue;
mod reconciliation;
mod request;
mod store;
mod transport;

#[cfg(feature = "test-fault-injection")]
mod test_fault;

pub use attempt::DispatchAttemptIdV1;
pub use authority::{
    DispatchAuthorityCaptureOutcomeV1, DispatchAuthorityCapturePhaseV1,
    DispatchAuthorityProviderV1, DispatchAuthorityViewBuildErrorV1, DispatchAuthorityViewInputV1,
    DispatchAuthorityViewV1, DISPATCH_AUTHORITY_VIEW_VERSION_V1,
};
pub use compare::{
    DispatchAuthorityComparisonErrorV1, DispatchCapacityVectorV1,
    EXECUTION_GRANT_MAX_LIFETIME_MS_V1,
};
pub use control::{
    classify_delivery_control_v1, DispatchAdmissionStateV1, DispatchClockV1,
    DispatchControlLaneOutcomeV1, DispatchControlLaneV1, DispatchDeliveryControlOutcomeV1,
    DispatchDeliveryControlPhaseV1, DispatchDeliveryControlSignalV1, DispatchEntropyDomainV1,
    DispatchEntropyErrorV1, DispatchEntropySourceV1, DispatchGrantSignerV1,
    DispatchTimeCaptureOutcomeV1, DispatchTimeCaptureV1, ExactSignedGrantV1,
    DISPATCH_CONTROL_CAPACITY_V1, DISPATCH_ORDINARY_PENDING_CAPACITY_V1,
};
pub use coordinator::{
    dispatch_prepared_once_v1, receive_and_consume_exact_grant_v1, recover_lost_acknowledgement_v1,
    run_automatic_readback_once_v1, DispatchAutomaticHandoffClassificationV1,
    DispatchAutomaticReadbackGateV1, DispatchAutomaticReadbackOutcomeV1,
    DispatchAutomaticReadbackScheduleV1, DispatchCandidateBuildErrorV1,
    DispatchEffectDescriptorInputV1, DispatchEffectDescriptorV1,
    DispatchLostAcknowledgementRecoveryV1, DispatchReadbackWaitOutcomeV1,
    DispatchReloadedCandidateV1, DispatchRetainedProjectionV1, AUTOMATIC_READBACK_BACKOFFS_MS_V1,
    AUTOMATIC_READBACK_BUDGET_MS_V1, AUTOMATIC_READBACK_MAX_OBSERVATIONS_V1,
    AUTOMATIC_READBACK_OFFSETS_MS_V1,
};
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub use coordinator::{
    dispatch_prepared_once_with_fault_probe_v1, recover_lost_acknowledgement_with_fault_probe_v1,
    run_automatic_readback_once_with_fault_probe_v1,
};
pub use guard::{
    DispatchCommitPermitOutcomeV1, DispatchCommitPermitV1, DispatchCommitResolutionV1,
    DispatchGuardAcquisitionV1, DispatchGuardClassV1, DispatchGuardOrderErrorV1,
    DispatchGuardProviderV1, DispatchGuardSetV1, DispatchGuardValidationV1,
};
pub use inbox::{
    DispatchInboxAdapterOutcomeV1, DispatchInboxConsumeOutcomeV1, DispatchInboxConsumerV1,
    DispatchInboxReadbackOutcomeV1, DispatchInboxReadbackV1, DispatchInboxReceiveOutcomeV1,
    DispatchInboxV1, DispatchPreReceiveRefusalV1,
};
pub use outcome::{
    AmbiguousDispatchV1, ConflictDispatchV1, ConsumedDispatchV1, DefinitelyRefusedDispatchV1,
    DeniedDispatchV1, DispatchAmbiguityReasonV1, DispatchConflictReasonV1,
    DispatchDeliveryOutcomeV1, DispatchDenialReasonV1, DispatchFailureReasonV1,
    DispatchReconciliationFailureReasonV1, DispatchReconciliationOutcomeV1,
    DispatchReconciliationReasonV1, DispatchRequestOutcomeV1, DispatchUnknownReasonV1,
    FailedDispatchV1, FailedReconciliationV1, OutcomeUnknownDispatchV1, PendingDispatchV1,
    ReconciliationRequiredDispatchV1, RetainedDispatchV1, DISPATCH_OUTCOME_CONTRACT_VERSION_V1,
};
pub use queue::{
    DispatchControlKindV1, DispatchControlRequestV1, DispatchQueueAdmissionV1,
    DispatchQueueBindingV1, DispatchQueueControlledProfileV1, DispatchQueueMetricsSnapshotV1,
    DispatchQueueTrialMeasurementV1, DispatchQueueV1, DISPATCH_QUEUE_CONTROLLED_TRIALS_V1,
    DISPATCH_QUEUE_CONTROL_CAPACITY_V1, DISPATCH_QUEUE_CONTROL_P99_LIMIT_MS_V1,
    DISPATCH_QUEUE_DUPLICATE_FLOOD_V1, DISPATCH_QUEUE_ORDINARY_BACKPRESSURE_LIMIT_MS_V1,
    DISPATCH_QUEUE_ORDINARY_CAPACITY_V1,
};
pub use reconciliation::{
    classify_definite_absence_v1, classify_no_consumption_receipt_v1,
    pre_receive_diagnostic_requires_reconciliation_v1, DispatchDefiniteAbsenceClassificationV1,
    DispatchDefiniteAbsenceEvidenceInputV1, DispatchDefiniteAbsenceEvidenceV1,
    DispatchDefiniteAbsenceProofV1, DispatchNoConsumptionTombstoneCustodyV1,
};
pub use request::{
    DispatchLookupRequestBuildErrorV1, DispatchLookupRequestInputV1, DispatchLookupRequestV1,
    DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
};
pub use store::{
    DispatchCommitCandidateV1, DispatchCommitEvidenceV1, DispatchCoordinatorStoreV1,
    DispatchReloadOutcomeV1, DispatchStoreCommitClassificationV1, DispatchStoreProjectionV1,
    DispatchStoreReadbackOutcomeV1,
};
pub use transport::{
    handoff_exact_grant_once_v1, DispatchHandoffGuardV1, DispatchHandoffOutcomeV1,
    DispatchHandoffValidationV1, DispatchTransportV1,
};

#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub use transport::handoff_exact_grant_once_with_fault_probe_v1;

#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub use test_fault::{
    DispatchFaultProbeV1, FaultInjectionDecisionV1, FaultInjectionModeV1, FaultSelectionErrorV1,
};
