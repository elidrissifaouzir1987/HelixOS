//! Durable SQLite inbox for one-shot dispatch grants and receipts.
//!
//! The crate owns no host-effect implementation and exposes no transferable
//! execution authority. Public diagnostics must remain payload-free and redacted.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod clock;
mod config;
mod connection;
mod epoch;
mod events;
mod inbox;
mod maintenance;
#[allow(dead_code)] // T075 codecs are consumed by the T076-T078 backup/restore path.
mod manifest;
mod quarantine;
mod queue;
mod readback;
mod receipt;
mod root_safety;
mod schema;

#[cfg(feature = "test-fault-injection")]
mod test_fault;

pub use clock::{AdapterClockObservationV1, AdapterClockV1, AdapterTimeSampleV1};
pub use config::{
    AdapterInboxInitializationV1, AdapterInboxRootIdentityEvidenceV1,
    AdapterInboxStoreConfigErrorV1, AdapterInboxStoreConfigV1,
};
pub use connection::AdapterInboxStoreOpenErrorV1;
pub use epoch::{EpochObservationV1, SupervisorEpochObservationV1, SupervisorEpochObserverV1};
pub use inbox::{
    AdapterInboxConflictEvidenceV1, AdapterInboxExactDuplicateV1, AdapterInboxProfileErrorV1,
    AdapterInboxProfileV1, AdapterInboxReceiveErrorV1, AdapterInboxReceiveOutcomeV1,
    AdapterInboxRetainedStateV1, AdapterPreReceiveRefusalV1, AdapterPreReceivedRefusalEvidenceV1,
    ReceivedInboxGrantV1, SqliteDispatchInboxStoreV1, ADAPTER_ORDINARY_QUEUE_CAPACITY_V1,
};
#[cfg(feature = "test-fault-injection")]
pub use maintenance::prepare_adapter_dispatch_restore_with_fault_for_test_v1;
pub use maintenance::{
    commit_adapter_dispatch_restore_to_pending_v1, inspect_adapter_dispatch_restore_destination_v1,
    prepare_adapter_dispatch_restore_v1, AdapterBackupPauseAuthorityV1,
    AdapterBackupPauseCustodyOutcomeV1, AdapterBackupPauseCustodyV1,
    AdapterBackupPauseValidationV1, AdapterDispatchBackupErrorV1, AdapterDispatchRestoreCountsV1,
    AdapterDispatchRestoreDestinationEvidenceV1, AdapterDispatchRestoreErrorV1,
    AdapterDispatchRestoreGenerationsV1, AdapterDispatchRestoreInventoriesV1,
    AdapterDispatchRestorePauseCustodyV1, AdapterDispatchRestorePauseValidationV1,
    AdapterDispatchRestoreSourceBindingsV1, AdapterGrantInventoryEntryV1,
    AdapterPausedDispatchRestoreV1, AdapterPausedQuiescenceV1, AdapterReceiptInventoryEntryV1,
    AdapterSignerInventoryEntryV1, PreparedAdapterDispatchRestoreV1,
    ProvisionedAdapterDispatchBackupDestinationV1, ProvisionedAdapterDispatchRestoreSourceV1,
    VerifiedAdapterDispatchBackupV1, VerifiedAdapterDispatchRestoreV1,
};
#[doc(hidden)]
pub use quarantine::{
    audit_and_retain_adapter_projection_v1, AdapterCorruptionAuditErrorV1,
    AdapterCorruptionAuditLifecycleV1, AdapterCorruptionAuditOutcomeV1,
    AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditPauseV1,
    AdapterCorruptionAuditSelectionV1, AdapterRetainedCorruptionAuditV1,
};
#[cfg(feature = "test-fault-injection")]
#[doc(hidden)]
pub use quarantine::{
    classify_and_retain_adapter_connections_for_test_v1, AdapterCorruptionTestErrorV1,
    AdapterCrossStoreIdsForTestV1, AdapterHistoryCustodyForTestV1,
    AdapterLifecycleRelationshipForTestV1, AdapterRetainedCorruptionForTestV1,
};
pub use queue::{
    measure_adapter_dispatch_queue_profile_v1, AdapterDispatchQueueMetricsSnapshotV1,
    AdapterDispatchQueueProfileErrorV1, AdapterDispatchQueueV1,
    ADAPTER_QUEUE_BACKPRESSURE_LIMIT_MS_V1, ADAPTER_QUEUE_CONTROLLED_TRIALS_V1,
    ADAPTER_QUEUE_CONTROL_CAPACITY_V1, ADAPTER_QUEUE_CONTROL_P99_LIMIT_MS_V1,
    ADAPTER_QUEUE_DUPLICATE_FLOOD_V1, ADAPTER_QUEUE_ORDINARY_CAPACITY_V1,
};
pub use readback::{AdapterInboxReadbackErrorV1, AdapterInboxReadbackOutcomeV1};
pub use receipt::{
    AdapterConsumptionAdmissionObservationV1, AdapterConsumptionAdmissionObserverV1,
    AdapterInboxConsumeErrorV1, AdapterInboxConsumeOutcomeV1, AdapterReceiptEntropyDomainV1,
    AdapterReceiptEntropyErrorV1, AdapterReceiptEntropyV1, AdapterReceiptSigningProfileErrorV1,
    AdapterReceiptSigningProfileV1, AdapterRetainedReceiptDecisionV1, RetainedAdapterReceiptV1,
};
