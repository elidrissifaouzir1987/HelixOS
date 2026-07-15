//! PLAN-005 T055 production-path dispatch-to-inbox contention evidence.
//!
//! The coordinator side starts from one genuine PLAN-004 preparation and opens the
//! resulting root through the strict V2 store. The only transport used here is a
//! read-only SQL observation of the exact retained outbox grant: T064 owns durable
//! handoff state and this test must neither claim nor mutate it.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

mod common;

#[path = "../src/comparison_digest.rs"]
mod comparison_digest;
#[path = "../src/outbox.rs"]
mod outbox;
#[path = "../src/prepare.rs"]
mod prepare;
#[path = "../src/readback.rs"]
mod readback;
#[cfg(feature = "test-fault-injection")]
#[path = "../src/test_fault.rs"]
mod test_fault;

use common::process_probe::{
    private_process_argument_v1, ProcessProbeChildV1, ProcessProbeEnvironmentV1,
    SynchronizedProcessProbeV1,
};
use common::{
    SyntheticCoordinatorClockV1, SyntheticCoordinatorRootV1, SyntheticHistoricalPlanKeyResolverV1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use helix_coordinator_sqlite::{
    embedded_schema_v1_sha256, CoordinatorDefiniteRefusalOutcomeV1,
    CoordinatorDispatchHandoffOutcomeV1, CoordinatorReadbackExhaustionV1,
    CoordinatorReadbackSequenceClaimOutcomeV1, CoordinatorReadbackSequenceClaimV1,
    CoordinatorReceiptCommitOutcomeV1, CoordinatorReceiptEffectiveStateV1,
    CoordinatorReceiptLookupV1, CoordinatorReconciliationLookupV1,
    CoordinatorReconciliationOutcomeV1, CoordinatorReconciliationStateV1,
    CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1, CoordinatorStoreOpenErrorV1,
    SqliteCoordinatorStoreV2,
};
use helix_dispatch_contracts::{
    decode_and_verify_execution_receipt_v1, decode_and_verify_retained_execution_grant_v1,
    ContractError, ExecutionReceiptDecisionV1, ExecutionReceiptRefusalCodeV1, Generation,
    GrantKeyResolver, GrantSigner, GrantVerificationKeyV1, Identifier, ReceiptKeyResolver,
    ReceiptSigner, ReceiptVerificationBindingsV1, ReceiptVerificationKeyV1, RecoveryModeV1,
    Result as DispatchContractResult, SafeU64, Sha256Digest,
};
use helix_dispatch_inbox_sqlite::{
    AdapterClockObservationV1, AdapterClockV1, AdapterConsumptionAdmissionObservationV1,
    AdapterConsumptionAdmissionObserverV1, AdapterInboxConsumeErrorV1,
    AdapterInboxConsumeOutcomeV1, AdapterInboxInitializationV1, AdapterInboxProfileV1,
    AdapterInboxReadbackErrorV1, AdapterInboxReadbackOutcomeV1, AdapterInboxReceiveErrorV1,
    AdapterInboxReceiveOutcomeV1, AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1,
    AdapterPreReceiveRefusalV1 as SqliteAdapterPreReceiveRefusalV1, AdapterReceiptEntropyDomainV1,
    AdapterReceiptEntropyErrorV1, AdapterReceiptEntropyV1, AdapterReceiptSigningProfileV1,
    AdapterRetainedReceiptDecisionV1, AdapterTimeSampleV1, EpochObservationV1,
    ReceivedInboxGrantV1, RetainedAdapterReceiptV1, SqliteDispatchInboxStoreV1,
    SupervisorEpochObservationV1, SupervisorEpochObserverV1,
};
use helix_plan_dispatch::{
    classify_definite_absence_v1, classify_no_consumption_receipt_v1, dispatch_prepared_once_v1,
    receive_and_consume_exact_grant_v1, DispatchAttemptIdV1, DispatchAuthorityCaptureOutcomeV1,
    DispatchAuthorityCapturePhaseV1, DispatchAuthorityProviderV1, DispatchAuthorityViewInputV1,
    DispatchAuthorityViewV1, DispatchCommitPermitOutcomeV1, DispatchCommitPermitV1,
    DispatchCommitResolutionV1, DispatchDefiniteAbsenceClassificationV1,
    DispatchDefiniteAbsenceEvidenceInputV1, DispatchDefiniteAbsenceEvidenceV1,
    DispatchEntropyDomainV1, DispatchEntropyErrorV1, DispatchEntropySourceV1,
    DispatchGuardAcquisitionV1, DispatchGuardClassV1, DispatchGuardOrderErrorV1,
    DispatchGuardProviderV1, DispatchGuardSetV1, DispatchGuardValidationV1, DispatchHandoffGuardV1,
    DispatchHandoffOutcomeV1, DispatchHandoffValidationV1, DispatchInboxAdapterOutcomeV1,
    DispatchInboxConsumeOutcomeV1, DispatchInboxConsumerV1, DispatchInboxReceiveOutcomeV1,
    DispatchInboxV1, DispatchLookupRequestInputV1, DispatchLookupRequestV1,
    DispatchPreReceiveRefusalV1, DispatchRequestOutcomeV1, DispatchStoreCommitClassificationV1,
    DispatchTransportV1, DISPATCH_AUTHORITY_VIEW_VERSION_V1, DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
};
use helix_plan_preparation::PreparationCommitOutcomeV1;
use prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use rusqlite::{params, Connection, OpenFlags};
use sha2::{Digest as _, Sha256};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);

const RELEASE_DUPLICATE_REQUESTS: usize = 10_000;
const RELEASE_THREAD_ROUNDS: usize = 100;
const RELEASE_THREAD_CONTENDERS: usize = 64;
const RELEASE_PROCESS_ROUNDS: usize = 20;
const RELEASE_PROCESS_CONTENDERS: usize = 8;

const COORDINATOR_DATABASE_FILENAME: &str = "coordinator.sqlite3";
const ADAPTER_DATABASE_FILENAME: &str = "dispatch-inbox.sqlite3";
const STORE_NOW_MONOTONIC_MS: u64 = 100;
const STORE_DEADLINE_MONOTONIC_MS: u64 = 5_000;
const SQLITE_BUSY_WAIT_MS: u64 = 30_000;
const AUTHORITY_PRELIMINARY_MONOTONIC_MS: u64 = 1_000;
const AUTHORITY_FINAL_MONOTONIC_MS: u64 = AUTHORITY_PRELIMINARY_MONOTONIC_MS;
const AUTHORITY_BASE_UTC_MS: u64 = 1_750_000_000_000;
const ADAPTER_TIME_MONOTONIC_MS: u64 = 1_100;
const ADAPTER_TIME_UTC_MS: u64 = AUTHORITY_BASE_UTC_MS + 1_100;
const ADAPTER_OBSERVER_GENERATION: u64 = 7;
const DESTINATION_ADAPTER_ID: &str = "adapter:t055:no-effect-v1";
const DISPATCH_SIGNER_KEY_ID: &str = "dispatch-key:t055-v1";
const DISPATCH_SIGNING_KEY_BYTES: [u8; 32] = [0x35; 32];
const DISPATCH_VERIFYING_KEY_BYTES: [u8; 32] = [
    166, 210, 69, 94, 163, 165, 119, 26, 186, 159, 203, 3, 121, 36, 17, 76, 146, 249, 243, 37, 4,
    159, 107, 66, 105, 231, 57, 217, 4, 139, 184, 105,
];
const RECEIPT_SIGNER_KEY_ID: &str = "receipt-key:t055-v1";
const RECEIPT_SIGNING_KEY_BYTES: [u8; 32] = [0x55; 32];
const RECEIPT_SIGNER_PROFILE_DIGEST: [u8; 32] = [0x75; 32];
const ADAPTER_CAPABILITY_DIGEST: [u8; 32] = [0x63; 32];

const PROCESS_CHILD_TEST_NAME: &str = "t055_private_process_child_v1";
const PROCESS_COORDINATOR_ROOT_ENV: &str = "HELIXOS_T055_COORDINATOR_ROOT";
const PROCESS_COORDINATOR_IDENTITY_ENV: &str = "HELIXOS_T055_COORDINATOR_IDENTITY";
const PROCESS_ADAPTER_ROOT_ENV: &str = "HELIXOS_T055_ADAPTER_ROOT";
const PROCESS_ADAPTER_IDENTITY_ENV: &str = "HELIXOS_T055_ADAPTER_IDENTITY";
const PROCESS_ROUND_ENV: &str = "HELIXOS_T055_ROUND";

static ADAPTER_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static NO_EFFECT_CALLS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct PreparedDispatchBindingsV1 {
    operation_id: String,
    preparation_attempt_id: [u8; 32],
    plan_id: [u8; 32],
    preparation_transition_generation: u64,
    task_id: String,
    workload_id: String,
    boot_id: String,
    instance_epoch: u64,
    supervisor_epoch: u64,
    reservation_id: String,
    task_lease_digest: [u8; 32],
    recovery_mode: RecoveryModeV1,
}

impl PreparedDispatchBindingsV1 {
    fn load_strict_v1(database: &Path) -> Self {
        let connection = open_read_only_v1(database);
        let row = connection
            .query_row(
                "SELECT operation.operation_id, operation.attempt_id, operation.plan_id, \
                        operation.state_generation, operation.task_id, operation.workload_id, \
                        operation.boot_id, operation.instance_epoch, operation.fencing_epoch, \
                        operation.reservation_id, reservation.task_lease_digest, \
                        operation.recovery_mode \
                 FROM prepared_operations AS operation \
                 JOIN operation_transitions AS transition \
                   ON transition.operation_id = operation.operation_id \
                  AND transition.state_generation = operation.state_generation \
                  AND transition.event_id = operation.current_event_id \
                  AND transition.previous_state IS NULL \
                  AND transition.new_state = 'PREPARING' \
                 JOIN budget_reservations AS reservation \
                   ON reservation.reservation_id = operation.reservation_id \
                  AND reservation.operation_id = operation.operation_id \
                  AND reservation.attempt_id = operation.attempt_id \
                  AND reservation.plan_id = operation.plan_id \
                  AND reservation.reservation_state = 'HELD' \
                  AND reservation.released_generation IS NULL \
                 WHERE operation.operation_state = 'PREPARING'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, Vec<u8>>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .expect("T055 exact prepared binding graph reads");
        let operation_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM prepared_operations", [], |row| {
                row.get(0)
            })
            .expect("T055 prepared operation count reads");
        assert_eq!(
            operation_count, 1,
            "T055 fixture owns one prepared operation"
        );
        Self {
            operation_id: row.0,
            preparation_attempt_id: exact_array_v1(row.1),
            plan_id: exact_array_v1(row.2),
            preparation_transition_generation: safe_u64_v1(row.3),
            task_id: row.4,
            workload_id: row.5,
            boot_id: row.6,
            instance_epoch: safe_u64_v1(row.7),
            supervisor_epoch: safe_u64_v1(row.8),
            reservation_id: row.9,
            task_lease_digest: exact_array_v1(row.10),
            recovery_mode: match row.11.as_str() {
                "COMPENSATION" => RecoveryModeV1::Compensation,
                "IRREVERSIBLE" => RecoveryModeV1::Irreversible,
                _ => panic!("T055 preparation retained an unsupported recovery mode"),
            },
        }
    }

    fn lookup_request_v1(&self) -> DispatchLookupRequestV1 {
        DispatchLookupRequestV1::try_new(DispatchLookupRequestInputV1 {
            contract_version: DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
            operation_id: &self.operation_id,
            expected_plan_digest: self.plan_id,
            expected_preparation_attempt_digest: self.preparation_attempt_id,
            expected_preparation_transition_generation: self.preparation_transition_generation,
            caller_deadline_monotonic_ms: STORE_DEADLINE_MONOTONIC_MS,
        })
        .expect("T055 exact prepared lookup constructs")
    }
}

impl fmt::Debug for PreparedDispatchBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDispatchBindingsV1")
            .finish_non_exhaustive()
    }
}

struct PreparedCoordinatorRootV1 {
    wal_anchor: Option<Connection>,
    root: SyntheticCoordinatorRootV1,
    root_identity: CoordinatorRootIdentityEvidenceV1,
    database: PathBuf,
    bindings: PreparedDispatchBindingsV1,
}

impl PreparedCoordinatorRootV1 {
    fn new_v1() -> Self {
        let root = SyntheticCoordinatorRootV1::new().expect("T055 coordinator root creates");
        let v1 = root
            .open_empty_v1(
                SyntheticCoordinatorClockV1::new(STORE_NOW_MONOTONIC_MS),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                STORE_DEADLINE_MONOTONIC_MS,
            )
            .expect("T055 exact V1 coordinator initializes");
        let root_identity = v1.root_identity_evidence();
        drop(v1);

        let database = fs::canonicalize(root.path())
            .expect("T055 coordinator root canonicalizes")
            .join(COORDINATOR_DATABASE_FILENAME);
        let preparation = SyntheticPreparationCaseV1::dispatch_compatible_v1(
            SyntheticRecoveryModeV1::Irreversible,
        );
        provision_synthetic_budget_scope_v1(&database, &preparation)
            .expect("T055 real PLAN-004 budget scope provisions");
        assert!(matches!(
            commit_synthetic_preparation_v1(
                &database,
                &preparation,
                SyntheticCommitModeV1::Acknowledged,
            ),
            PreparationCommitOutcomeV1::Committed(_)
        ));

        install_exact_v2_overlay_v1(&database);
        let bindings = PreparedDispatchBindingsV1::load_strict_v1(&database);
        let descriptor = CoordinatorDescriptorV1 {
            root: root.path().to_path_buf(),
            root_identity,
            database: database.clone(),
            bindings: bindings.clone(),
        };
        drop(descriptor.open_store_v1());

        let wal_anchor = open_read_only_v1(&database);
        let journal_mode: String = wal_anchor
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("T055 coordinator WAL mode reads");
        assert!(journal_mode.eq_ignore_ascii_case("wal"));
        Self {
            wal_anchor: Some(wal_anchor),
            root,
            root_identity,
            database,
            bindings,
        }
    }

    fn descriptor_v1(&self) -> CoordinatorDescriptorV1 {
        CoordinatorDescriptorV1 {
            root: self.root.path().to_path_buf(),
            root_identity: self.root_identity,
            database: self.database.clone(),
            bindings: self.bindings.clone(),
        }
    }

    fn force_last_close_v1(&mut self) {
        drop(self.wal_anchor.take());
    }

    fn reopen_anchor_v1(&mut self) {
        assert!(self.wal_anchor.is_none());
        self.wal_anchor = Some(open_read_only_v1(&self.database));
    }
}

impl fmt::Debug for PreparedCoordinatorRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCoordinatorRootV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct CoordinatorDescriptorV1 {
    root: PathBuf,
    root_identity: CoordinatorRootIdentityEvidenceV1,
    database: PathBuf,
    bindings: PreparedDispatchBindingsV1,
}

impl CoordinatorDescriptorV1 {
    fn open_store_v1(
        &self,
    ) -> SqliteCoordinatorStoreV2<SyntheticCoordinatorClockV1, SyntheticHistoricalPlanKeyResolverV1>
    {
        let config = CoordinatorStoreConfigV1::try_new_existing_attested(
            self.root.clone(),
            self.root_identity,
            SQLITE_BUSY_WAIT_MS,
        )
        .expect("T055 coordinator existing config validates");
        SqliteCoordinatorStoreV2::open_existing(
            config,
            SyntheticCoordinatorClockV1::new(STORE_NOW_MONOTONIC_MS),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            STORE_DEADLINE_MONOTONIC_MS,
        )
        .expect("T055 strict coordinator V2 opens")
    }
}

impl fmt::Debug for CoordinatorDescriptorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDescriptorV1")
            .finish_non_exhaustive()
    }
}

struct AdapterRootV1 {
    path: PathBuf,
    root_identity: AdapterInboxRootIdentityEvidenceV1,
    database: PathBuf,
    wal_anchor: Option<Connection>,
}

impl AdapterRootV1 {
    fn new_v1(supervisor_epoch: u64) -> Self {
        let sequence = ADAPTER_ROOT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "helixos-t055-adapter-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("T055 dedicated adapter root creates");
        let mut identity_preimage = Vec::new();
        identity_preimage.extend_from_slice(b"HELIXOS\0T055-ADAPTER-ROOT\0V1\0");
        identity_preimage.extend_from_slice(&std::process::id().to_be_bytes());
        identity_preimage.extend_from_slice(&sequence.to_be_bytes());
        let identity_digest = Sha256Digest::digest(&identity_preimage);
        let root_identity =
            AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(*identity_digest.as_bytes());
        let config = AdapterInboxStoreConfigV1::try_new_empty_attested(
            path.clone(),
            root_identity,
            SQLITE_BUSY_WAIT_MS,
        )
        .expect("T055 empty adapter config validates");
        let initial = AdapterInboxInitializationV1::try_new(
            supervisor_epoch,
            ADAPTER_OBSERVER_GENERATION,
            RECEIPT_SIGNER_PROFILE_DIGEST,
        )
        .expect("T055 initial adapter observation validates");
        let store =
            SqliteDispatchInboxStoreV1::initialize_empty_v1(config, initial, adapter_profile_v1())
                .expect("T055 independent adapter store initializes");
        drop(store);
        let database = fs::canonicalize(&path)
            .expect("T055 adapter root canonicalizes")
            .join(ADAPTER_DATABASE_FILENAME);
        let wal_anchor = Some(open_read_only_v1(&database));
        Self {
            path,
            root_identity,
            database,
            wal_anchor,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn descriptor_v1(&self, prepared: &PreparedDispatchBindingsV1) -> AdapterDescriptorV1 {
        AdapterDescriptorV1 {
            root: self.path.clone(),
            root_identity: self.root_identity,
            database: self.database.clone(),
            boot_id: prepared.boot_id.clone(),
            supervisor_epoch: prepared.supervisor_epoch,
        }
    }

    fn force_last_close_v1(&mut self) {
        drop(self.wal_anchor.take());
    }

    fn reopen_anchor_v1(&mut self) {
        assert!(self.wal_anchor.is_none());
        self.wal_anchor = Some(open_read_only_v1(&self.database));
    }
}

impl fmt::Debug for AdapterRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterRootV1")
            .finish_non_exhaustive()
    }
}

impl Drop for AdapterRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct AdapterDescriptorV1 {
    root: PathBuf,
    root_identity: AdapterInboxRootIdentityEvidenceV1,
    database: PathBuf,
    boot_id: String,
    supervisor_epoch: u64,
}

impl AdapterDescriptorV1 {
    fn open_store_v1(&self) -> SqliteDispatchInboxStoreV1 {
        let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
            self.root.clone(),
            self.root_identity,
            SQLITE_BUSY_WAIT_MS,
        )
        .expect("T055 existing adapter config validates");
        SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile_v1())
            .expect("T055 strict independent adapter store opens")
    }

    fn open_consumer_v1(&self, entropy_seed: u64) -> SqliteAdapterConsumerV1 {
        self.open_consumer_with_admission_v1(entropy_seed, ScriptedAdmissionObserverV1::Running)
    }

    fn open_paused_consumer_v1(&self, entropy_seed: u64) -> SqliteAdapterConsumerV1 {
        self.open_consumer_with_admission_v1(entropy_seed, ScriptedAdmissionObserverV1::Paused)
    }

    fn open_consumer_with_admission_v1(
        &self,
        entropy_seed: u64,
        admission_observer: ScriptedAdmissionObserverV1,
    ) -> SqliteAdapterConsumerV1 {
        SqliteAdapterConsumerV1 {
            store: self.open_store_v1(),
            grant_resolver: DispatchGrantResolverV1::fixed_v1(),
            receipt_keys: ReceiptKeysV1::fixed_v1(),
            clock: FixedAdapterClockV1 {
                boot_id: self.boot_id.clone(),
            },
            epoch_observer: FreshAdapterEpochObserverV1 {
                database: self.database.clone(),
                boot_id: self.boot_id.clone(),
                supervisor_epoch: self.supervisor_epoch,
            },
            admission_observer,
            receipt_entropy: SeededReceiptEntropyV1(entropy_seed),
            signing_profile: receipt_signing_profile_v1(),
        }
    }
}

impl fmt::Debug for AdapterDescriptorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterDescriptorV1")
            .finish_non_exhaustive()
    }
}

fn adapter_profile_v1() -> AdapterInboxProfileV1 {
    AdapterInboxProfileV1::try_new(
        DESTINATION_ADAPTER_ID,
        1,
        Sha256Digest::from_bytes(ADAPTER_CAPABILITY_DIGEST),
    )
    .expect("T055 adapter profile validates")
}

fn receipt_signing_profile_v1() -> AdapterReceiptSigningProfileV1 {
    let keys = ReceiptKeysV1::fixed_v1();
    AdapterReceiptSigningProfileV1::try_new(
        RECEIPT_SIGNER_KEY_ID,
        Sha256Digest::digest(&keys.signing_key.verifying_key().to_bytes()),
        Sha256Digest::from_bytes(RECEIPT_SIGNER_PROFILE_DIGEST),
    )
    .expect("T055 receipt signer profile validates")
}

#[derive(Clone)]
struct ReceiptKeysV1 {
    signing_key: SigningKey,
}

impl ReceiptKeysV1 {
    fn fixed_v1() -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&RECEIPT_SIGNING_KEY_BYTES),
        }
    }
}

impl ReceiptSigner for ReceiptKeysV1 {
    fn key_id(&self) -> &str {
        RECEIPT_SIGNER_KEY_ID
    }

    fn sign_execution_receipt(&self, message: &[u8]) -> DispatchContractResult<[u8; 64]> {
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

impl ReceiptKeyResolver for ReceiptKeysV1 {
    fn resolve_receipt_key(
        &self,
        key_id: &str,
    ) -> DispatchContractResult<ReceiptVerificationKeyV1> {
        if key_id == RECEIPT_SIGNER_KEY_ID {
            Ok(ReceiptVerificationKeyV1::current(
                self.signing_key.verifying_key().to_bytes(),
            ))
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

struct CoordinatorReceiptKeysV1;

impl GrantKeyResolver for CoordinatorReceiptKeysV1 {
    fn resolve_grant_key(&self, key_id: &str) -> DispatchContractResult<GrantVerificationKeyV1> {
        DispatchGrantResolverV1::fixed_v1().resolve_grant_key(key_id)
    }
}

impl ReceiptKeyResolver for CoordinatorReceiptKeysV1 {
    fn resolve_receipt_key(
        &self,
        key_id: &str,
    ) -> DispatchContractResult<ReceiptVerificationKeyV1> {
        ReceiptKeysV1::fixed_v1().resolve_receipt_key(key_id)
    }
}

struct FixedAdapterClockV1 {
    boot_id: String,
}

impl FixedAdapterClockV1 {
    fn sample_v1(&self, generation: u64) -> AdapterTimeSampleV1 {
        AdapterTimeSampleV1::new(
            identifier_v1(&self.boot_id),
            generation_v1(generation),
            safe_v1(ADAPTER_TIME_UTC_MS),
            safe_v1(ADAPTER_TIME_MONOTONIC_MS),
        )
    }
}

impl AdapterClockV1 for FixedAdapterClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        AdapterClockObservationV1::Current(self.sample_v1(1))
    }
}

/// Test wiring for a fresh supervisor-observation generation.
///
/// The supervisor epoch itself is independently fixed by the prepared binding. Only the
/// persisted observer-generation watermark is consulted, read-only, so a newly opened
/// process can return its strict successor while the adapter writer transaction is held.
struct FreshAdapterEpochObserverV1 {
    database: PathBuf,
    boot_id: String,
    supervisor_epoch: u64,
}

impl SupervisorEpochObserverV1 for FreshAdapterEpochObserverV1 {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
        let Ok(connection) = Connection::open_with_flags(
            &self.database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ) else {
            return SupervisorEpochObservationV1::Unavailable;
        };
        let Ok(watermark) = connection.query_row(
            "SELECT epoch_observer_generation FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            return SupervisorEpochObservationV1::Unreadable;
        };
        let Some(next) = safe_u64_v1(watermark).checked_add(1) else {
            return SupervisorEpochObservationV1::Stale;
        };
        SupervisorEpochObservationV1::Current(EpochObservationV1::new(
            safe_v1(self.supervisor_epoch),
            generation_v1(next),
            FixedAdapterClockV1 {
                boot_id: self.boot_id.clone(),
            }
            .sample_v1(next),
        ))
    }
}

#[derive(Clone, Copy)]
enum ScriptedAdmissionObserverV1 {
    Running,
    Paused,
}

impl AdapterConsumptionAdmissionObserverV1 for ScriptedAdmissionObserverV1 {
    fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1 {
        match self {
            Self::Running => AdapterConsumptionAdmissionObservationV1::Running,
            Self::Paused => AdapterConsumptionAdmissionObservationV1::Paused,
        }
    }
}

struct SeededReceiptEntropyV1(u64);

impl AdapterReceiptEntropyV1 for SeededReceiptEntropyV1 {
    fn fill_receipt_entropy_v1(
        &self,
        domain: AdapterReceiptEntropyDomainV1,
        destination: &mut [u8; 32],
    ) -> Result<(), AdapterReceiptEntropyErrorV1> {
        assert_eq!(domain, AdapterReceiptEntropyDomainV1::ReceiptIdentity);
        let mut hasher = Sha256::new();
        hasher.update(b"HELIXOS\0T055-RECEIPT-ENTROPY\0V1\0");
        hasher.update(self.0.to_be_bytes());
        destination.copy_from_slice(&hasher.finalize());
        Ok(())
    }
}

struct SqliteAdapterConsumerV1 {
    store: SqliteDispatchInboxStoreV1,
    grant_resolver: DispatchGrantResolverV1,
    receipt_keys: ReceiptKeysV1,
    clock: FixedAdapterClockV1,
    epoch_observer: FreshAdapterEpochObserverV1,
    admission_observer: ScriptedAdmissionObserverV1,
    receipt_entropy: SeededReceiptEntropyV1,
    signing_profile: AdapterReceiptSigningProfileV1,
}

impl DispatchInboxV1 for SqliteAdapterConsumerV1 {
    type RetainedState = ReceivedInboxGrantV1;
    type RetainedReceipt = RetainedAdapterReceiptV1;

    fn receive_exact_grant_v1(
        &self,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        // The duplicate fast path intentionally exposes neither grant identity nor receipt
        // bytes. Recover identity only by re-verifying the caller's exact canonical input,
        // then cross the independently verified T050 readback boundary.
        let grant_id = match decode_and_verify_retained_execution_grant_v1(
            exact_signed_grant_bytes,
            &self.grant_resolver,
        ) {
            Ok(grant) => grant.claims().grant_id(),
            Err(_) => return DispatchInboxReceiveOutcomeV1::Unhealthy,
        };
        match self.store.receive_grant_v1(
            exact_signed_grant_bytes,
            &self.grant_resolver,
            &self.clock,
            &self.epoch_observer,
        ) {
            Ok(AdapterInboxReceiveOutcomeV1::Received(received)) => {
                DispatchInboxReceiveOutcomeV1::DurablyReceived(received)
            }
            Ok(AdapterInboxReceiveOutcomeV1::ExactDuplicate(duplicate)) => {
                match self.store.readback_grant_v1(
                    grant_id,
                    &self.grant_resolver,
                    &self.receipt_keys,
                ) {
                    Ok(AdapterInboxReadbackOutcomeV1::Received(received))
                        if duplicate.state()
                            == helix_dispatch_inbox_sqlite::AdapterInboxRetainedStateV1::Received
                            && !duplicate.receipt_retained() =>
                    {
                        DispatchInboxReceiveOutcomeV1::RetainedState(received)
                    }
                    Ok(AdapterInboxReadbackOutcomeV1::RetainedReceipt(receipt))
                        if matches!(
                            duplicate.state(),
                            helix_dispatch_inbox_sqlite::AdapterInboxRetainedStateV1::Consumed
                                | helix_dispatch_inbox_sqlite::AdapterInboxRetainedStateV1::Refused
                        ) && duplicate.receipt_retained() =>
                    {
                        DispatchInboxReceiveOutcomeV1::RetainedReceipt(receipt)
                    }
                    Ok(AdapterInboxReadbackOutcomeV1::Conflict) => {
                        DispatchInboxReceiveOutcomeV1::Conflict
                    }
                    Ok(AdapterInboxReadbackOutcomeV1::Quarantined) => {
                        DispatchInboxReceiveOutcomeV1::Quarantined
                    }
                    Ok(AdapterInboxReadbackOutcomeV1::Absent)
                    | Ok(AdapterInboxReadbackOutcomeV1::Received(_))
                    | Ok(AdapterInboxReadbackOutcomeV1::RetainedReceipt(_)) => {
                        DispatchInboxReceiveOutcomeV1::Unhealthy
                    }
                    Err(error) => map_readback_error_v1(error),
                }
            }
            Ok(AdapterInboxReceiveOutcomeV1::PreReceivedRefusal(refusal)) => {
                DispatchInboxReceiveOutcomeV1::RefusedBeforeReceive(map_refusal_v1(
                    refusal.reason(),
                ))
            }
            Ok(AdapterInboxReceiveOutcomeV1::Conflict(_)) => {
                DispatchInboxReceiveOutcomeV1::Conflict
            }
            Err(error) => map_receive_error_v1(error),
        }
    }
}

impl DispatchInboxConsumerV1 for SqliteAdapterConsumerV1 {
    fn consume_received_once_v1(
        &self,
        retained_state: Self::RetainedState,
    ) -> DispatchInboxConsumeOutcomeV1<Self::RetainedReceipt> {
        match self.store.consume_received_v1(
            retained_state,
            &self.grant_resolver,
            &self.clock,
            &self.epoch_observer,
            &self.admission_observer,
            &self.receipt_entropy,
            &self.signing_profile,
            &self.receipt_keys,
            &self.receipt_keys,
        ) {
            Ok(AdapterInboxConsumeOutcomeV1::Consumed(receipt)) => {
                DispatchInboxConsumeOutcomeV1::Consumed(receipt)
            }
            Ok(AdapterInboxConsumeOutcomeV1::DefinitelyRefused(receipt)) => {
                DispatchInboxConsumeOutcomeV1::DefinitelyRefused(receipt)
            }
            Ok(AdapterInboxConsumeOutcomeV1::RetainedReceipt(receipt)) => {
                DispatchInboxConsumeOutcomeV1::RetainedReceipt(receipt)
            }
            Ok(AdapterInboxConsumeOutcomeV1::Conflict) => DispatchInboxConsumeOutcomeV1::Conflict,
            Ok(AdapterInboxConsumeOutcomeV1::Quarantined) => {
                DispatchInboxConsumeOutcomeV1::Quarantined
            }
            Err(error) => map_consume_error_v1(error),
        }
    }
}

fn map_refusal_v1(reason: SqliteAdapterPreReceiveRefusalV1) -> DispatchPreReceiveRefusalV1 {
    match reason {
        SqliteAdapterPreReceiveRefusalV1::DestinationMismatch => {
            DispatchPreReceiveRefusalV1::DestinationMismatch
        }
        SqliteAdapterPreReceiveRefusalV1::ProtocolUnsupported => {
            DispatchPreReceiveRefusalV1::ProtocolUnsupported
        }
        SqliteAdapterPreReceiveRefusalV1::CapabilityMismatch => {
            DispatchPreReceiveRefusalV1::CapabilityMismatch
        }
        SqliteAdapterPreReceiveRefusalV1::InboxCapacityExhausted => {
            DispatchPreReceiveRefusalV1::InboxCapacityExhausted
        }
    }
}

fn map_receive_error_v1(
    error: AdapterInboxReceiveErrorV1,
) -> DispatchInboxReceiveOutcomeV1<ReceivedInboxGrantV1, RetainedAdapterReceiptV1> {
    match error {
        AdapterInboxReceiveErrorV1::StoreBusy
        | AdapterInboxReceiveErrorV1::StoreUnavailable
        | AdapterInboxReceiveErrorV1::ClockUnavailable
        | AdapterInboxReceiveErrorV1::EpochObserverUnavailable => {
            DispatchInboxReceiveOutcomeV1::Unavailable
        }
        _ => DispatchInboxReceiveOutcomeV1::Unhealthy,
    }
}

fn map_readback_error_v1(
    error: AdapterInboxReadbackErrorV1,
) -> DispatchInboxReceiveOutcomeV1<ReceivedInboxGrantV1, RetainedAdapterReceiptV1> {
    match error {
        AdapterInboxReadbackErrorV1::StoreBusy | AdapterInboxReadbackErrorV1::StoreUnavailable => {
            DispatchInboxReceiveOutcomeV1::Unavailable
        }
        _ => DispatchInboxReceiveOutcomeV1::Unhealthy,
    }
}

fn map_consume_error_v1(
    error: AdapterInboxConsumeErrorV1,
) -> DispatchInboxConsumeOutcomeV1<RetainedAdapterReceiptV1> {
    match error {
        AdapterInboxConsumeErrorV1::StoreBusy
        | AdapterInboxConsumeErrorV1::StoreUnavailable
        | AdapterInboxConsumeErrorV1::ClockUnavailable
        | AdapterInboxConsumeErrorV1::EpochObserverUnavailable
        | AdapterInboxConsumeErrorV1::AdmissionUnavailable => {
            DispatchInboxConsumeOutcomeV1::Unavailable
        }
        _ => DispatchInboxConsumeOutcomeV1::Unhealthy,
    }
}

#[derive(Clone)]
struct AuthorityFixtureV1 {
    prepared: PreparedDispatchBindingsV1,
}

impl AuthorityFixtureV1 {
    fn view_v1(&self, phase: DispatchAuthorityCapturePhaseV1) -> DispatchAuthorityViewV1 {
        let sampled_monotonic_ms = match phase {
            DispatchAuthorityCapturePhaseV1::Preliminary => AUTHORITY_PRELIMINARY_MONOTONIC_MS,
            DispatchAuthorityCapturePhaseV1::FinalGuarded => AUTHORITY_FINAL_MONOTONIC_MS,
        };
        DispatchAuthorityViewV1::try_new(DispatchAuthorityViewInputV1 {
            contract_version: DISPATCH_AUTHORITY_VIEW_VERSION_V1,
            phase,
            time: helix_plan_dispatch::DispatchTimeCaptureV1::new(
                identifier_v1(&self.prepared.boot_id),
                generation_v1(1),
                safe_v1(AUTHORITY_BASE_UTC_MS + sampled_monotonic_ms),
                safe_v1(sampled_monotonic_ms),
            ),
            task_id: identifier_v1(&self.prepared.task_id),
            workload_id: identifier_v1(&self.prepared.workload_id),
            instance_epoch: safe_v1(self.prepared.instance_epoch),
            supervisor_epoch: safe_v1(self.prepared.supervisor_epoch),
            supervisor_generation: generation_v1(1),
            trust_generation: generation_v1(1),
            verified_key_fingerprint: digest_byte_v1(1),
            workload_generation: generation_v1(1),
            workload_evidence_digest: digest_byte_v1(2),
            lease_generation: generation_v1(1),
            lease_digest: Sha256Digest::from_bytes(self.prepared.task_lease_digest),
            lease_decision_digest: digest_byte_v1(3),
            authorization_generation: generation_v1(1),
            authorization_evidence_digest: digest_byte_v1(4),
            policy_generation: generation_v1(1),
            policy_decision_generation: generation_v1(1),
            policy_content_digest: digest_byte_v1(5),
            policy_decision_digest: digest_byte_v1(6),
            catalogue_generation: generation_v1(1),
            catalogue_decision_generation: generation_v1(1),
            catalogue_content_digest: digest_byte_v1(7),
            catalogue_decision_digest: digest_byte_v1(8),
            capability_report_generation: generation_v1(1),
            capability_report_digest: digest_byte_v1(9),
            host_driver_context_digest: digest_byte_v1(10),
            capability_observed_at_utc_ms: safe_v1(AUTHORITY_BASE_UTC_MS + 900),
            capability_max_age_ms: safe_v1(500),
            adapter_capability_digest: Sha256Digest::from_bytes(ADAPTER_CAPABILITY_DIGEST),
            replay_claim_id: digest_byte_v1(11),
            replay_claimant_generation: generation_v1(1),
            replay_binding_digest: digest_byte_v1(12),
            budget_scope_id: identifier_v1("scope:t055-v1"),
            budget_scope_generation: generation_v1(1),
            budget_scope_binding_digest: digest_byte_v1(13),
            reservation_id: identifier_v1(&self.prepared.reservation_id),
            reservation_generation: generation_v1(1),
            reservation_binding_digest: digest_byte_v1(14),
            reservation_vector_digest: digest_byte_v1(15),
            recovery_reference_digest: digest_byte_v1(16),
            recovery_mode: self.prepared.recovery_mode,
            recovery_profile_digest: digest_byte_v1(17),
            recovery_binding_digest: digest_byte_v1(18),
            recovery_receipt_digest: digest_byte_v1(19),
            destination_adapter_id: identifier_v1(DESTINATION_ADAPTER_ID),
            protocol_version: 1,
            signer_key_id: identifier_v1(DISPATCH_SIGNER_KEY_ID),
            signer_generation: generation_v1(1),
            // The V1 portable projection binds the retained signer-key fingerprint to
            // this profile digest, so the synthetic profile uses the real fixed key.
            signer_profile_digest: dispatch_key_fingerprint_v1(),
            earliest_authority_deadline_monotonic_ms: generation_v1(STORE_DEADLINE_MONOTONIC_MS),
        })
        .expect("T055 coherent authority view constructs")
    }
}

impl DispatchAuthorityProviderV1 for AuthorityFixtureV1 {
    fn capture_authority_v1(
        &self,
        phase: DispatchAuthorityCapturePhaseV1,
        _request: &DispatchLookupRequestV1,
        _attempt: &DispatchAttemptIdV1,
    ) -> DispatchAuthorityCaptureOutcomeV1 {
        DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(self.view_v1(phase)))
    }
}

struct GuardSetV1 {
    authority: AuthorityFixtureV1,
}

impl DispatchGuardSetV1 for GuardSetV1 {
    type Permit = PermitV1;

    fn capture_final_authority_v1(&mut self) -> DispatchAuthorityCaptureOutcomeV1 {
        DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(
            self.authority
                .view_v1(DispatchAuthorityCapturePhaseV1::FinalGuarded),
        ))
    }

    fn validate_all_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
        if now_monotonic_ms < STORE_DEADLINE_MONOTONIC_MS {
            DispatchGuardValidationV1::Valid
        } else {
            DispatchGuardValidationV1::DeadlineReached
        }
    }

    fn acquire_commit_permit_v1(
        &mut self,
        _attempt: &DispatchAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> DispatchCommitPermitOutcomeV1<Self::Permit> {
        DispatchCommitPermitOutcomeV1::Permitted(PermitV1 {
            deadline_monotonic_ms,
        })
    }

    fn release_reverse_v1(self) {}
}

impl DispatchGuardProviderV1 for AuthorityFixtureV1 {
    type GuardSet = GuardSetV1;

    fn acquire_in_fixed_order_v1(
        &self,
        _request: &DispatchLookupRequestV1,
        _attempt: &DispatchAttemptIdV1,
        after_acquisition: &mut dyn FnMut(
            DispatchGuardClassV1,
        ) -> Result<(), DispatchGuardOrderErrorV1>,
    ) -> DispatchGuardAcquisitionV1<Self::GuardSet> {
        for class in DispatchGuardClassV1::acquisition_order() {
            if after_acquisition(class).is_err() {
                return DispatchGuardAcquisitionV1::OrderViolated;
            }
        }
        DispatchGuardAcquisitionV1::Acquired(GuardSetV1 {
            authority: self.clone(),
        })
    }
}

struct PermitV1 {
    deadline_monotonic_ms: u64,
}

impl DispatchCommitPermitV1 for PermitV1 {
    fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms
    }

    fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
        if now_monotonic_ms < self.deadline_monotonic_ms {
            DispatchGuardValidationV1::Valid
        } else {
            DispatchGuardValidationV1::DeadlineReached
        }
    }

    fn commit_once<C, U, F>(self, commit: F) -> DispatchCommitResolutionV1<C, U>
    where
        C: Send,
        U: Send,
        F: FnOnce() -> DispatchStoreCommitClassificationV1<C, U>,
    {
        match commit() {
            DispatchStoreCommitClassificationV1::Committed(receipt) => {
                DispatchCommitResolutionV1::Committed(receipt)
            }
            DispatchStoreCommitClassificationV1::PriorExactDispatch(receipt) => {
                DispatchCommitResolutionV1::PriorExactDispatch(receipt)
            }
            DispatchStoreCommitClassificationV1::ConfirmedRollback => {
                DispatchCommitResolutionV1::ConfirmedRollback
            }
            DispatchStoreCommitClassificationV1::Uncertain(custody) => {
                DispatchCommitResolutionV1::Uncertain(custody)
            }
            DispatchStoreCommitClassificationV1::Conflict => DispatchCommitResolutionV1::Conflict,
            DispatchStoreCommitClassificationV1::Unavailable => {
                DispatchCommitResolutionV1::Unavailable
            }
            DispatchStoreCommitClassificationV1::Unhealthy
            | DispatchStoreCommitClassificationV1::Unclassified => {
                DispatchCommitResolutionV1::Unclassified
            }
        }
    }

    fn abandon_v1(self) {}
}

struct SeededEntropyV1(u64);

impl DispatchEntropySourceV1 for SeededEntropyV1 {
    fn fill_entropy_v1(
        &self,
        domain: DispatchEntropyDomainV1,
        destination: &mut [u8],
    ) -> Result<(), DispatchEntropyErrorV1> {
        for (block, chunk) in destination.chunks_mut(32).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(b"HELIXOS\0T055-SYNTHETIC-ENTROPY\0V1\0");
            hasher.update(self.0.to_be_bytes());
            hasher.update([entropy_domain_tag_v1(domain)]);
            hasher.update((block as u64).to_be_bytes());
            let digest = hasher.finalize();
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
        Ok(())
    }
}

fn entropy_domain_tag_v1(domain: DispatchEntropyDomainV1) -> u8 {
    match domain {
        DispatchEntropyDomainV1::AttemptIdentity => 1,
        DispatchEntropyDomainV1::GrantIdentity => 2,
        DispatchEntropyDomainV1::OneShotNonce => 3,
        DispatchEntropyDomainV1::TraceIdentity => 4,
    }
}

#[derive(Clone)]
struct DispatchKeysV1 {
    signing_key: SigningKey,
}

impl DispatchKeysV1 {
    fn fixed_v1() -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&DISPATCH_SIGNING_KEY_BYTES),
        }
    }
}

impl GrantSigner for DispatchKeysV1 {
    fn key_id(&self) -> &str {
        DISPATCH_SIGNER_KEY_ID
    }

    fn sign_execution_grant(&self, message: &[u8]) -> DispatchContractResult<[u8; 64]> {
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

#[derive(Clone, Copy)]
struct DispatchGrantResolverV1 {
    verifying_key: [u8; 32],
}

impl DispatchGrantResolverV1 {
    fn fixed_v1() -> Self {
        Self {
            verifying_key: DISPATCH_VERIFYING_KEY_BYTES,
        }
    }
}

impl GrantKeyResolver for DispatchGrantResolverV1 {
    fn resolve_grant_key(&self, key_id: &str) -> DispatchContractResult<GrantVerificationKeyV1> {
        if key_id == DISPATCH_SIGNER_KEY_ID {
            Ok(GrantVerificationKeyV1::current(self.verifying_key))
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinatorDispatchClassV1 {
    Committed,
    PriorExact,
}

fn dispatch_once_v1(
    store: &SqliteCoordinatorStoreV2<
        SyntheticCoordinatorClockV1,
        SyntheticHistoricalPlanKeyResolverV1,
    >,
    bindings: &PreparedDispatchBindingsV1,
    entropy_seed: u64,
) -> CoordinatorDispatchClassV1 {
    let authority = AuthorityFixtureV1 {
        prepared: bindings.clone(),
    };
    match dispatch_prepared_once_v1(
        store,
        bindings.lookup_request_v1(),
        &authority,
        &SeededEntropyV1(entropy_seed),
        &DispatchKeysV1::fixed_v1(),
        &authority,
    ) {
        DispatchRequestOutcomeV1::Dispatched(_) => CoordinatorDispatchClassV1::Committed,
        DispatchRequestOutcomeV1::AlreadyDispatched(_) => CoordinatorDispatchClassV1::PriorExact,
        DispatchRequestOutcomeV1::Failed(failed) => {
            panic!("T055 production dispatch failed: {:?}", failed.reason())
        }
        DispatchRequestOutcomeV1::Denied(denied) => {
            panic!("T055 production dispatch was denied: {:?}", denied.reason())
        }
        DispatchRequestOutcomeV1::Ambiguous(ambiguous) => {
            panic!(
                "T055 production dispatch was ambiguous: {:?}",
                ambiguous.reason()
            )
        }
    }
}

struct RetainedGrantTransportV1 {
    grant_id: Sha256Digest,
    canonical_grant: Vec<u8>,
}

impl fmt::Debug for RetainedGrantTransportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedGrantTransportV1")
            .finish_non_exhaustive()
    }
}

fn load_pending_grant_read_only_v1(
    database: &Path,
    operation_id: &str,
) -> RetainedGrantTransportV1 {
    let connection = open_read_only_v1(database);
    let counts = (
        count_where_v1(&connection, "dispatch_grants", "1 = 1"),
        count_where_v1(
            &connection,
            "dispatch_records",
            "effective_state = 'DISPATCHING'",
        ),
        count_where_v1(
            &connection,
            "dispatch_transitions",
            "previous_state = 'PREPARING' AND new_state = 'DISPATCHING'",
        ),
        count_where_v1(
            &connection,
            "dispatch_outbox",
            "delivery_state = 'PENDING' AND current_attempt_generation IS NULL",
        ),
    );
    assert_eq!(counts, (1, 1, 1, 1), "T055 retains one pending grant graph");
    let (grant_id, canonical_grant, canonical_length) = connection
        .query_row(
            "SELECT grant.grant_id, grant.canonical_grant, grant.canonical_grant_length \
             FROM dispatch_grants AS grant \
             JOIN dispatch_records AS record \
               ON record.operation_id = grant.operation_id \
              AND record.grant_id = grant.grant_id \
              AND record.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND record.effective_state = 'DISPATCHING' \
             JOIN dispatch_outbox AS outbox \
               ON outbox.grant_id = grant.grant_id \
              AND outbox.operation_id = grant.operation_id \
              AND outbox.dispatch_attempt_id = grant.dispatch_attempt_id \
              AND outbox.delivery_state = 'PENDING' \
              AND outbox.current_attempt_generation IS NULL \
             WHERE grant.operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .expect("T055 exact retained grant reads through the test transport");
    assert_eq!(
        usize::try_from(canonical_length).expect("T055 canonical length is nonnegative"),
        canonical_grant.len()
    );
    let grant_id = Sha256Digest::from_bytes(exact_array_v1(grant_id));
    let retained = decode_and_verify_retained_execution_grant_v1(
        &canonical_grant,
        &DispatchGrantResolverV1::fixed_v1(),
    )
    .expect("T055 retained coordinator grant authenticates");
    assert_eq!(retained.claims().grant_id(), grant_id);
    assert_eq!(retained.claims().operation_id(), operation_id);
    assert_eq!(
        retained
            .canonical_signed_envelope_bytes()
            .expect("T055 retained grant canonicalizes"),
        canonical_grant
    );
    RetainedGrantTransportV1 {
        grant_id,
        canonical_grant,
    }
}

struct LivePossibleHandoffGuardV1;

impl DispatchHandoffGuardV1 for LivePossibleHandoffGuardV1 {
    fn evidence_binding_v1(&self) -> [u8; 32] {
        [0xa5; 32]
    }

    fn validate_at_v1(&mut self, _now_monotonic_ms: u64) -> DispatchHandoffValidationV1 {
        DispatchHandoffValidationV1::Live
    }

    fn release_v1(self) {}
}

struct PossibleHandoffTransportV1;

impl DispatchTransportV1 for PossibleHandoffTransportV1 {
    type Guard = LivePossibleHandoffGuardV1;
    type Response = ();

    fn acquire_handoff_guard_v1(
        &self,
        _grant_binding: &[u8; 32],
        _deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
        Ok(LivePossibleHandoffGuardV1)
    }

    fn deliver_exact_v1(
        &self,
        _guard: &mut Self::Guard,
        _exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response> {
        DispatchHandoffOutcomeV1::PossibleHandoff
    }
}

struct AcknowledgedAdapterTransportV1<'a> {
    consumer: &'a SqliteAdapterConsumerV1,
}

impl DispatchTransportV1 for AcknowledgedAdapterTransportV1<'_> {
    type Guard = LivePossibleHandoffGuardV1;
    type Response = ReceivedInboxGrantV1;

    fn acquire_handoff_guard_v1(
        &self,
        _grant_binding: &[u8; 32],
        _deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
        Ok(LivePossibleHandoffGuardV1)
    }

    fn deliver_exact_v1(
        &self,
        _guard: &mut Self::Guard,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response> {
        match self
            .consumer
            .receive_exact_grant_v1(exact_signed_grant_bytes)
        {
            DispatchInboxReceiveOutcomeV1::DurablyReceived(received) => {
                DispatchHandoffOutcomeV1::Acknowledged(received)
            }
            _ => DispatchHandoffOutcomeV1::PossibleHandoff,
        }
    }
}

struct ExactAcknowledgedAttemptLineageV1 {
    source_generation: i64,
    source_number: i64,
    source_guard: Vec<u8>,
    acknowledged_generation: i64,
    acknowledged_number: i64,
    acknowledged_guard: Vec<u8>,
    adapter_root: Vec<u8>,
    adapter_epoch: i64,
    delivery_generation: i64,
    current_attempt_generation: i64,
}

#[test]
fn acknowledged_consumed_receipt_commits_without_claiming_ambiguous_readback() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    let coordinator = PreparedCoordinatorRootV1::new_v1();
    let coordinator_descriptor = coordinator.descriptor_v1();
    let adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
    let adapter_descriptor = adapter.descriptor_v1(&coordinator.bindings);
    let coordinator_store = coordinator_descriptor.open_store_v1();
    let consumer = adapter_descriptor.open_consumer_v1(95);

    assert_eq!(
        dispatch_once_v1(&coordinator_store, &coordinator.bindings, 95),
        CoordinatorDispatchClassV1::Committed
    );
    let retained = load_pending_grant_read_only_v1(
        &coordinator_descriptor.database,
        &coordinator.bindings.operation_id,
    );
    let received = match coordinator_store.handoff_pending_dispatch_v1(
        *retained.grant_id.as_bytes(),
        STORE_DEADLINE_MONOTONIC_MS,
        &AcknowledgedAdapterTransportV1 {
            consumer: &consumer,
        },
    ) {
        CoordinatorDispatchHandoffOutcomeV1::Acknowledged(received) => received,
        other => panic!("T095 durable adapter handoff was not acknowledged: {other:?}"),
    };
    let receipt = match consumer.consume_received_once_v1(received) {
        DispatchInboxConsumeOutcomeV1::Consumed(receipt) => receipt,
        other => panic!("T095 acknowledged grant was not consumed: {other:?}"),
    };
    let canonical_receipt = receipt.canonical_receipt().to_vec();
    let wrong_root = [0x7b; 32];
    assert_ne!(
        wrong_root,
        adapter_descriptor.root_identity.to_attested_bytes()
    );
    let wrong_lookup = CoordinatorReceiptLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
        wrong_root,
    )
    .expect("T095 wrong-root lookup is structurally valid");
    assert!(matches!(
        coordinator_store.commit_execution_receipt_v1(
            wrong_lookup,
            &canonical_receipt,
            STORE_DEADLINE_MONOTONIC_MS,
            &CoordinatorReceiptKeysV1,
        ),
        CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance
    ));
    let rejected = open_read_only_v1(&coordinator_descriptor.database);
    assert_eq!(
        count_where_v1(&rejected, "dispatch_receipts", "decision = 'CONSUMED'"),
        0
    );
    assert_eq!(
        count_where_v1(
            &rejected,
            "dispatch_delivery_attempts",
            "classification = 'ACKNOWLEDGED'"
        ),
        0
    );
    assert_eq!(
        count_where_v1(
            &rejected,
            "dispatch_outbox",
            "delivery_state = 'HANDED_OFF' AND receipt_id IS NULL"
        ),
        1
    );
    drop(rejected);
    let lookup = CoordinatorReceiptLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
        adapter_descriptor.root_identity.to_attested_bytes(),
    )
    .expect("T095 exact coordinator receipt lookup constructs");
    let outcome = coordinator_store.commit_execution_receipt_v1(
        lookup,
        &canonical_receipt,
        STORE_DEADLINE_MONOTONIC_MS,
        &CoordinatorReceiptKeysV1,
    );
    let CoordinatorReceiptCommitOutcomeV1::Committed(evidence) = outcome else {
        panic!("T095 acknowledged consumed receipt did not commit directly: {outcome:?}");
    };
    assert_eq!(
        evidence.effective_state(),
        CoordinatorReceiptEffectiveStateV1::Executing
    );

    drop(coordinator_store);
    let reopened = coordinator_descriptor.open_store_v1();
    let repeated_lookup = CoordinatorReceiptLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
        adapter_descriptor.root_identity.to_attested_bytes(),
    )
    .expect("T095 repeated exact lookup constructs");
    assert!(matches!(
        reopened.commit_execution_receipt_v1(
            repeated_lookup,
            &canonical_receipt,
            STORE_DEADLINE_MONOTONIC_MS,
            &CoordinatorReceiptKeysV1,
        ),
        CoordinatorReceiptCommitOutcomeV1::PriorExact(_)
    ));
    let connection = open_read_only_v1(&coordinator_descriptor.database);
    assert_eq!(
        count_where_v1(
            &connection,
            "dispatch_delivery_attempts",
            "classification = 'ACKNOWLEDGED' AND adapter_root_digest IS NOT NULL \
             AND adapter_epoch IS NOT NULL AND readback_generation IS NULL",
        ),
        1,
    );
    assert_eq!(
        count_where_v1(
            &connection,
            "dispatch_delivery_attempts",
            "classification = 'POSSIBLE_HANDOFF' AND adapter_root_digest IS NOT NULL",
        ),
        0,
        "acknowledged success must not claim ambiguous readback custody",
    );
    let exact_attempts: ExactAcknowledgedAttemptLineageV1 = connection
        .query_row(
            "SELECT source.attempt_generation, source.attempt_number, \
                        source.handoff_guard_digest, acknowledged.attempt_generation, \
                        acknowledged.attempt_number, acknowledged.handoff_guard_digest, \
                        acknowledged.adapter_root_digest, acknowledged.adapter_epoch, \
                        outbox.delivery_generation, outbox.current_attempt_generation \
                 FROM dispatch_delivery_attempts AS acknowledged \
                 JOIN dispatch_delivery_attempts AS source \
                   ON source.grant_id = acknowledged.grant_id \
                  AND source.operation_id = acknowledged.operation_id \
                  AND source.dispatch_attempt_id = acknowledged.dispatch_attempt_id \
                  AND source.attempt_number = acknowledged.attempt_number - 1 \
                 JOIN dispatch_outbox AS outbox \
                   ON outbox.grant_id = acknowledged.grant_id \
                  AND outbox.operation_id = acknowledged.operation_id \
                  AND outbox.dispatch_attempt_id = acknowledged.dispatch_attempt_id \
                  AND outbox.current_attempt_generation = acknowledged.attempt_generation \
                 WHERE acknowledged.grant_id = ?1 \
                   AND acknowledged.classification = 'ACKNOWLEDGED' \
                   AND acknowledged.readback_generation IS NULL \
                   AND source.classification = 'POSSIBLE_HANDOFF' \
                   AND source.adapter_root_digest IS NULL \
                   AND source.adapter_epoch IS NULL \
                   AND source.readback_generation IS NULL \
                   AND outbox.delivery_state = 'ACKNOWLEDGED' \
                   AND outbox.receipt_decision = 'CONSUMED'",
            [retained.grant_id.as_bytes().as_slice()],
            |row| {
                Ok(ExactAcknowledgedAttemptLineageV1 {
                    source_generation: row.get(0)?,
                    source_number: row.get(1)?,
                    source_guard: row.get(2)?,
                    acknowledged_generation: row.get(3)?,
                    acknowledged_number: row.get(4)?,
                    acknowledged_guard: row.get(5)?,
                    adapter_root: row.get(6)?,
                    adapter_epoch: row.get(7)?,
                    delivery_generation: row.get(8)?,
                    current_attempt_generation: row.get(9)?,
                })
            },
        )
        .expect("T095 exact direct acknowledged lineage remains queryable");
    assert!(exact_attempts.source_generation < exact_attempts.acknowledged_generation);
    assert_eq!(exact_attempts.source_number, 1);
    assert_eq!(
        exact_attempts.acknowledged_number,
        exact_attempts.source_number + 1
    );
    assert_eq!(
        exact_attempts.source_guard,
        exact_attempts.acknowledged_guard
    );
    assert_eq!(
        exact_attempts.adapter_root.as_slice(),
        adapter_descriptor.root_identity.to_attested_bytes()
    );
    assert_eq!(
        u64::try_from(exact_attempts.adapter_epoch).expect("T095 exact adapter epoch is safe"),
        coordinator.bindings.supervisor_epoch
    );
    assert_eq!(
        exact_attempts.acknowledged_generation,
        exact_attempts.delivery_generation
    );
    assert_eq!(
        exact_attempts.acknowledged_generation,
        exact_attempts.current_attempt_generation
    );
    let attempt_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM dispatch_delivery_attempts WHERE grant_id = ?1",
            [retained.grant_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("T095 exact attempt count remains queryable");
    assert_eq!(attempt_count, 2);
    assert_eq!(NO_EFFECT_CALLS.load(Ordering::SeqCst), 0);

    drop(connection);
    drop(reopened);
    let mut corruption = Connection::open_with_flags(
        &coordinator_descriptor.database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("T095 corruption probe opens the completed coordinator root");
    corruption
        .pragma_update(None, "foreign_keys", true)
        .expect("T095 corruption probe enables foreign keys");
    corruption
        .pragma_update(None, "recursive_triggers", true)
        .expect("T095 corruption probe enables recursive triggers");
    let transaction = corruption
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("T095 corruption probe acquires one writer");
    let current_store_generation: i64 = transaction
        .query_row(
            "SELECT dispatch_store_generation FROM dispatch_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("T095 current store generation reads");
    let orphan_generation = current_store_generation + 1;
    assert_eq!(
        transaction
            .execute(
                "INSERT INTO dispatch_delivery_attempts (attempt_generation, grant_id, \
                     operation_id, dispatch_attempt_id, attempt_number, handoff_guard_digest, \
                     classification, adapter_root_digest, adapter_epoch, readback_generation) \
                 SELECT ?1, grant_id, operation_id, dispatch_attempt_id, 3, \
                        handoff_guard_digest, 'POSSIBLE_HANDOFF', NULL, NULL, NULL \
                 FROM dispatch_delivery_attempts \
                 WHERE grant_id = ?2 AND classification = 'ACKNOWLEDGED'",
                params![orphan_generation, retained.grant_id.as_bytes().as_slice()],
            )
            .expect("T095 structurally valid orphan attempt appends"),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE dispatch_store_meta \
                 SET dispatch_store_generation = ?1, delivery_generation = ?1 \
                 WHERE singleton = 1 AND dispatch_store_generation = ?2",
                params![orphan_generation, current_store_generation],
            )
            .expect("T095 corruption probe advances exact delivery high-water"),
        1
    );
    transaction
        .commit()
        .expect("T095 corruption probe commits its isolated malformed graph");
    drop(corruption);

    let corrupted_config = CoordinatorStoreConfigV1::try_new_existing_attested(
        coordinator_descriptor.root.clone(),
        coordinator_descriptor.root_identity,
        SQLITE_BUSY_WAIT_MS,
    )
    .expect("T095 corrupted existing coordinator config remains structurally valid");
    assert!(matches!(
        SqliteCoordinatorStoreV2::open_existing(
            corrupted_config,
            SyntheticCoordinatorClockV1::new(STORE_NOW_MONOTONIC_MS),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            STORE_DEADLINE_MONOTONIC_MS,
        ),
        Err(CoordinatorStoreOpenErrorV1::InvariantFailed)
    ));
}

#[test]
fn possible_handoff_consumed_receipt_commits_and_reopens_idempotently() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    let coordinator = PreparedCoordinatorRootV1::new_v1();
    let coordinator_descriptor = coordinator.descriptor_v1();
    let adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
    let adapter_descriptor = adapter.descriptor_v1(&coordinator.bindings);
    let coordinator_store = coordinator_descriptor.open_store_v1();

    assert_eq!(
        dispatch_once_v1(&coordinator_store, &coordinator.bindings, 41),
        CoordinatorDispatchClassV1::Committed
    );
    let retained = load_pending_grant_read_only_v1(
        &coordinator_descriptor.database,
        &coordinator.bindings.operation_id,
    );
    assert!(matches!(
        coordinator_store.handoff_pending_dispatch_v1(
            *retained.grant_id.as_bytes(),
            STORE_DEADLINE_MONOTONIC_MS,
            &PossibleHandoffTransportV1,
        ),
        CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
    ));

    let reconciliation_lookup = CoordinatorReconciliationLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
    )
    .expect("T067 exact reconciliation lookup constructs");
    let sequence_claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_descriptor.root_identity.to_attested_bytes(),
        coordinator.bindings.supervisor_epoch,
    )
    .expect("T067 exact readback claim constructs");
    let claim_evidence = match coordinator_store.claim_or_resume_readback_sequence_v1(
        &reconciliation_lookup,
        &sequence_claim,
        STORE_DEADLINE_MONOTONIC_MS,
    ) {
        CoordinatorReadbackSequenceClaimOutcomeV1::Claimed { evidence, .. } => evidence,
        other => panic!("T067 real readback sequence was not claimed: {other:?}"),
    };
    let repeated_claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_descriptor.root_identity.to_attested_bytes(),
        coordinator.bindings.supervisor_epoch,
    )
    .expect("T067 repeated exact readback claim constructs");
    let CoordinatorReadbackSequenceClaimOutcomeV1::Resumed(repeated_evidence) = coordinator_store
        .claim_or_resume_readback_sequence_v1(
            &reconciliation_lookup,
            &repeated_claim,
            STORE_DEADLINE_MONOTONIC_MS,
        )
    else {
        panic!("T067 repeated sequence claim minted another permit");
    };
    assert_eq!(
        repeated_evidence.claim_attempt_generation(),
        claim_evidence.claim_attempt_generation()
    );
    assert_eq!(
        repeated_evidence.source_handoff_generation(),
        claim_evidence.source_handoff_generation()
    );

    let consumer = adapter_descriptor.open_consumer_v1(41);
    let receipt = match receive_and_consume_exact_grant_v1(&consumer, &retained.canonical_grant) {
        DispatchInboxAdapterOutcomeV1::Consumed(receipt) => receipt,
        other => panic!("T052 real consumed receipt path returned {other:?}"),
    };
    let canonical_receipt = receipt.canonical_receipt().to_vec();
    let lookup = CoordinatorReceiptLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
        adapter_descriptor.root_identity.to_attested_bytes(),
    )
    .expect("T052 exact coordinator receipt lookup constructs");

    let first = coordinator_store.commit_execution_receipt_v1(
        lookup,
        &canonical_receipt,
        STORE_DEADLINE_MONOTONIC_MS,
        &CoordinatorReceiptKeysV1,
    );
    let CoordinatorReceiptCommitOutcomeV1::Committed(evidence) = first else {
        panic!("T052 real consumed receipt did not commit: {first:?}");
    };
    assert_eq!(
        evidence.effective_state(),
        CoordinatorReceiptEffectiveStateV1::Executing
    );

    drop(coordinator_store);
    let reopened = coordinator_descriptor.open_store_v1();
    let repeated_lookup = CoordinatorReceiptLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
        adapter_descriptor.root_identity.to_attested_bytes(),
    )
    .expect("T052 repeated exact lookup constructs");
    assert!(matches!(
        reopened.commit_execution_receipt_v1(
            repeated_lookup,
            &canonical_receipt,
            STORE_DEADLINE_MONOTONIC_MS,
            &CoordinatorReceiptKeysV1,
        ),
        CoordinatorReceiptCommitOutcomeV1::PriorExact(_)
    ));
    let connection = open_read_only_v1(&coordinator_descriptor.database);
    assert_eq!(
        (
            count_where_v1(
                &connection,
                "dispatch_records",
                "effective_state = 'EXECUTING'"
            ),
            count_where_v1(&connection, "dispatch_receipts", "decision = 'CONSUMED'"),
            count_where_v1(
                &connection,
                "budget_reservations",
                "reservation_state = 'HELD' AND released_generation IS NULL",
            ),
        ),
        (1, 1, 1),
        "consumed authority advances only the V2 overlay and retains the PLAN-004 hold",
    );
    assert_eq!(NO_EFFECT_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn exhausted_readback_and_late_consumed_receipt_remain_in_reconciliation_custody() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    let coordinator = PreparedCoordinatorRootV1::new_v1();
    let coordinator_descriptor = coordinator.descriptor_v1();
    let adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
    let adapter_descriptor = adapter.descriptor_v1(&coordinator.bindings);
    let coordinator_store = coordinator_descriptor.open_store_v1();

    assert_eq!(
        dispatch_once_v1(&coordinator_store, &coordinator.bindings, 42),
        CoordinatorDispatchClassV1::Committed
    );
    let retained = load_pending_grant_read_only_v1(
        &coordinator_descriptor.database,
        &coordinator.bindings.operation_id,
    );
    assert!(matches!(
        coordinator_store.handoff_pending_dispatch_v1(
            *retained.grant_id.as_bytes(),
            STORE_DEADLINE_MONOTONIC_MS,
            &PossibleHandoffTransportV1,
        ),
        CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
    ));
    let reconciliation_lookup = CoordinatorReconciliationLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
    )
    .expect("T067 exact reconciliation lookup constructs");
    let sequence_claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_descriptor.root_identity.to_attested_bytes(),
        coordinator.bindings.supervisor_epoch,
    )
    .expect("T067 exact readback claim constructs");
    assert!(matches!(
        coordinator_store.claim_or_resume_readback_sequence_v1(
            &reconciliation_lookup,
            &sequence_claim,
            STORE_DEADLINE_MONOTONIC_MS,
        ),
        CoordinatorReadbackSequenceClaimOutcomeV1::Claimed { .. }
    ));

    let consumer = adapter_descriptor.open_consumer_v1(42);
    let receipt = match receive_and_consume_exact_grant_v1(&consumer, &retained.canonical_grant) {
        DispatchInboxAdapterOutcomeV1::Consumed(receipt) => receipt,
        other => panic!("T067 late-consumed fixture returned {other:?}"),
    };
    let canonical_receipt = receipt.canonical_receipt().to_vec();
    let exhaustion = CoordinatorReadbackExhaustionV1::try_new(
        [0xe7; 32],
        "trace:t067:readback-exhausted".to_owned(),
        275,
    )
    .expect("T067 exhaustion evidence constructs");
    let unknown = coordinator_store.commit_outcome_unknown_v1(
        &reconciliation_lookup,
        &exhaustion,
        STORE_DEADLINE_MONOTONIC_MS,
    );
    let CoordinatorReconciliationOutcomeV1::Committed(unknown_evidence) = unknown else {
        panic!("T067 exhaustion did not commit unknown custody: {unknown:?}");
    };
    assert_eq!(
        unknown_evidence.state(),
        CoordinatorReconciliationStateV1::OutcomeUnknown
    );
    let required = coordinator_store.commit_reconciliation_required_unknown_v1(
        &reconciliation_lookup,
        STORE_DEADLINE_MONOTONIC_MS,
    );
    let CoordinatorReconciliationOutcomeV1::Committed(required_evidence) = required else {
        panic!("T067 unknown did not enter explicit reconciliation: {required:?}");
    };
    assert_eq!(
        required_evidence.state(),
        CoordinatorReconciliationStateV1::ReconciliationRequired
    );
    assert!(matches!(
        coordinator_store.commit_reconciliation_required_unknown_v1(
            &reconciliation_lookup,
            STORE_DEADLINE_MONOTONIC_MS,
        ),
        CoordinatorReconciliationOutcomeV1::Resumed(_)
    ));

    let late = coordinator_store.commit_late_consumed_receipt_v1(
        &reconciliation_lookup,
        adapter_descriptor.root_identity.to_attested_bytes(),
        &canonical_receipt,
        STORE_DEADLINE_MONOTONIC_MS,
        &CoordinatorReceiptKeysV1,
    );
    let CoordinatorReceiptCommitOutcomeV1::Committed(late_evidence) = late else {
        panic!("T067 late consumed receipt was not retained: {late:?}");
    };
    assert_eq!(
        late_evidence.effective_state(),
        CoordinatorReceiptEffectiveStateV1::ReconciliationRequired
    );
    assert!(matches!(
        coordinator_store.commit_late_consumed_receipt_v1(
            &reconciliation_lookup,
            adapter_descriptor.root_identity.to_attested_bytes(),
            &canonical_receipt,
            STORE_DEADLINE_MONOTONIC_MS,
            &CoordinatorReceiptKeysV1,
        ),
        CoordinatorReceiptCommitOutcomeV1::PriorExact(_)
    ));

    drop(coordinator_store);
    let reopened = coordinator_descriptor.open_store_v1();
    assert!(matches!(
        reopened.commit_late_consumed_receipt_v1(
            &reconciliation_lookup,
            adapter_descriptor.root_identity.to_attested_bytes(),
            &canonical_receipt,
            STORE_DEADLINE_MONOTONIC_MS,
            &CoordinatorReceiptKeysV1,
        ),
        CoordinatorReceiptCommitOutcomeV1::PriorExact(_)
    ));
    let connection = open_read_only_v1(&coordinator_descriptor.database);
    assert_eq!(
        (
            count_where_v1(
                &connection,
                "dispatch_records",
                "effective_state = 'RECONCILIATION_REQUIRED' \
                 AND reconciliation_result = 'OUTCOME_UNKNOWN' AND receipt_id IS NULL",
            ),
            count_where_v1(&connection, "dispatch_receipts", "decision = 'CONSUMED'"),
            count_where_v1(
                &connection,
                "dispatch_reconciliations",
                "result IN ('OUTCOME_UNKNOWN', 'CONSUMED')",
            ),
            count_where_v1(
                &connection,
                "budget_reservations",
                "reservation_state = 'HELD' AND released_generation IS NULL",
            ),
        ),
        (1, 1, 2, 1),
        "late consumed evidence remains append-only under held reconciliation custody",
    );
    assert_eq!(NO_EFFECT_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn definite_paused_refusal_closes_failed_and_releases_reservation_once() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    let coordinator = PreparedCoordinatorRootV1::new_v1();
    let coordinator_descriptor = coordinator.descriptor_v1();
    let adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
    let adapter_descriptor = adapter.descriptor_v1(&coordinator.bindings);
    let coordinator_store = coordinator_descriptor.open_store_v1();

    assert_eq!(
        dispatch_once_v1(&coordinator_store, &coordinator.bindings, 43),
        CoordinatorDispatchClassV1::Committed
    );
    let retained = load_pending_grant_read_only_v1(
        &coordinator_descriptor.database,
        &coordinator.bindings.operation_id,
    );
    assert!(matches!(
        coordinator_store.handoff_pending_dispatch_v1(
            *retained.grant_id.as_bytes(),
            STORE_DEADLINE_MONOTONIC_MS,
            &PossibleHandoffTransportV1,
        ),
        CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
    ));

    let reconciliation_lookup = CoordinatorReconciliationLookupV1::try_new(
        coordinator.bindings.operation_id.clone(),
        *retained.grant_id.as_bytes(),
    )
    .expect("T067 exact definite-refusal lookup constructs");
    let sequence_claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_descriptor.root_identity.to_attested_bytes(),
        coordinator.bindings.supervisor_epoch,
    )
    .expect("T067 definite-refusal readback claim constructs");
    let claim_evidence = match coordinator_store.claim_or_resume_readback_sequence_v1(
        &reconciliation_lookup,
        &sequence_claim,
        STORE_DEADLINE_MONOTONIC_MS,
    ) {
        CoordinatorReadbackSequenceClaimOutcomeV1::Claimed { evidence, .. } => evidence,
        other => panic!("T067 definite-refusal readback was not claimed: {other:?}"),
    };

    let consumer = adapter_descriptor.open_paused_consumer_v1(43);
    let receipt = match receive_and_consume_exact_grant_v1(&consumer, &retained.canonical_grant) {
        DispatchInboxAdapterOutcomeV1::DefinitelyRefused(receipt) => receipt,
        other => panic!("T067 real paused adapter did not definitely refuse: {other:?}"),
    };
    assert_eq!(
        receipt.decision(),
        AdapterRetainedReceiptDecisionV1::RefusedDefinite
    );
    assert_eq!(
        receipt.refusal_code(),
        Some(ExecutionReceiptRefusalCodeV1::AdapterPaused)
    );
    let canonical_receipt = receipt.canonical_receipt().to_vec();
    let retained_grant = decode_and_verify_retained_execution_grant_v1(
        &retained.canonical_grant,
        &DispatchGrantResolverV1::fixed_v1(),
    )
    .expect("T067 retained grant authenticates for refusal verification");
    let adapter_root = adapter_descriptor.root_identity.to_attested_bytes();
    let receipt_bindings = ReceiptVerificationBindingsV1::from_retained_grant_evidence(
        &retained_grant,
        Sha256Digest::from_bytes(adapter_root),
    );
    let authentic_receipt = decode_and_verify_execution_receipt_v1(
        &canonical_receipt,
        &ReceiptKeysV1::fixed_v1(),
        &receipt_bindings,
    )
    .expect("T067 signed ADAPTER_PAUSED receipt authenticates");
    assert_eq!(
        authentic_receipt.claims().decision(),
        ExecutionReceiptDecisionV1::RefusedDefinite
    );
    assert_eq!(
        authentic_receipt.claims().refusal_code(),
        Some(ExecutionReceiptRefusalCodeV1::AdapterPaused)
    );
    let tombstone = classify_no_consumption_receipt_v1(&authentic_receipt)
        .expect("T067 authentic paused receipt classifies as no consumption");
    assert_eq!(
        tombstone.refusal_code(),
        ExecutionReceiptRefusalCodeV1::AdapterPaused
    );
    assert_eq!(
        tombstone.receipt_id(),
        *authentic_receipt.claims().receipt_id().as_bytes()
    );
    assert_eq!(
        tombstone.receipt_digest(),
        *authentic_receipt.claims().receipt_digest().as_bytes()
    );
    assert_eq!(
        Some(tombstone.no_consumption_tombstone_digest()),
        authentic_receipt
            .claims()
            .no_consumption_tombstone_digest()
            .map(|digest| *digest.as_bytes())
    );

    let dispatch_attempt_id = exact_array_v1(
        open_read_only_v1(&coordinator_descriptor.database)
            .query_row(
                "SELECT dispatch_attempt_id FROM dispatch_grants \
                 WHERE operation_id = ?1 AND grant_id = ?2",
                rusqlite::params![
                    &coordinator.bindings.operation_id,
                    retained.grant_id.as_bytes().as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("T067 exact durable dispatch-attempt binding reads"),
    );
    let deadline_monotonic_ms = retained_grant.claims().deadline_monotonic_ms();
    let absence_evidence =
        DispatchDefiniteAbsenceEvidenceV1::try_new(DispatchDefiniteAbsenceEvidenceInputV1 {
            transport_fenced: true,
            transport_quiesced: true,
            adapter_healthy: true,
            expected_adapter_root: adapter_root,
            observed_adapter_root: adapter_root,
            expected_supervisor_epoch: coordinator.bindings.supervisor_epoch,
            observed_supervisor_epoch: coordinator.bindings.supervisor_epoch,
            expected_delivery_attempt_id: dispatch_attempt_id,
            observed_delivery_attempt_id: dispatch_attempt_id,
            authoritative_handoff_generation: claim_evidence.source_handoff_generation(),
            observed_readback_generation: claim_evidence.source_handoff_generation(),
            exclusive_deadline_monotonic_ms: deadline_monotonic_ms,
            observed_monotonic_ms: deadline_monotonic_ms,
        })
        .expect("T067 exact definite-absence evidence validates");
    let DispatchDefiniteAbsenceClassificationV1::DefiniteAbsence(proof) =
        classify_definite_absence_v1(absence_evidence)
    else {
        panic!("T067 exact fenced evidence remained possible consumption");
    };
    assert_eq!(proof.adapter_root(), adapter_root);
    assert_eq!(
        proof.supervisor_epoch(),
        coordinator.bindings.supervisor_epoch
    );
    assert_eq!(proof.delivery_attempt_id(), dispatch_attempt_id);
    assert_eq!(
        proof.readback_generation(),
        claim_evidence.source_handoff_generation()
    );
    assert_eq!(
        proof.exclusive_deadline_monotonic_ms(),
        deadline_monotonic_ms
    );

    let first = coordinator_store.commit_definite_refusal_v1(
        &reconciliation_lookup,
        &canonical_receipt,
        STORE_DEADLINE_MONOTONIC_MS,
        &CoordinatorReceiptKeysV1,
        &proof,
        &tombstone,
    );
    let CoordinatorDefiniteRefusalOutcomeV1::Committed(first_evidence) = first else {
        panic!("T067 exact definite refusal did not commit: {first:?}");
    };
    let repeated = coordinator_store.commit_definite_refusal_v1(
        &reconciliation_lookup,
        &canonical_receipt,
        STORE_DEADLINE_MONOTONIC_MS,
        &CoordinatorReceiptKeysV1,
        &proof,
        &tombstone,
    );
    let CoordinatorDefiniteRefusalOutcomeV1::PriorExact(repeated_evidence) = repeated else {
        panic!("T067 same-process retry was not prior exact: {repeated:?}");
    };
    assert_eq!(repeated_evidence, first_evidence);

    drop(coordinator_store);
    let reopened = coordinator_descriptor.open_store_v1();
    let reopened_retry = reopened.commit_definite_refusal_v1(
        &reconciliation_lookup,
        &canonical_receipt,
        STORE_DEADLINE_MONOTONIC_MS,
        &CoordinatorReceiptKeysV1,
        &proof,
        &tombstone,
    );
    let CoordinatorDefiniteRefusalOutcomeV1::PriorExact(reopened_evidence) = reopened_retry else {
        panic!("T067 reopened retry was not prior exact: {reopened_retry:?}");
    };
    assert_eq!(reopened_evidence, first_evidence);

    let connection = open_read_only_v1(&coordinator_descriptor.database);
    assert_eq!(
        (
            count_where_v1(
                &connection,
                "dispatch_records",
                "effective_state = 'FAILED' AND receipt_decision = 'REFUSED_DEFINITE' \
                 AND reconciliation_result = 'REFUSED_DEFINITE'",
            ),
            count_where_v1(
                &connection,
                "dispatch_receipts",
                "decision = 'REFUSED_DEFINITE' AND refusal_code = 'ADAPTER_PAUSED'",
            ),
            count_where_v1(
                &connection,
                "dispatch_definite_refusal_guards",
                "final_dispatch_state = 'FAILED' AND base_operation_state = 'FAILED' \
                 AND reservation_state = 'RELEASED'",
            ),
            count_where_v1(
                &connection,
                "prepared_operations",
                "operation_state = 'FAILED' AND failed_reason_code = 'ADAPTER_PAUSED'",
            ),
            count_where_v1(
                &connection,
                "budget_reservations",
                "reservation_state = 'RELEASED' AND released_generation IS NOT NULL",
            ),
            count_where_v1(
                &connection,
                "budget_reservations",
                "reservation_state = 'HELD' OR released_generation IS NULL",
            ),
        ),
        (1, 1, 1, 1, 1, 0),
        "one refused receipt closes both projections and releases the hold once",
    );
    assert_eq!(
        (
            count_where_v1(
                &connection,
                "dispatch_transitions",
                "previous_state = 'DISPATCHING' AND new_state = 'OUTCOME_UNKNOWN'",
            ),
            count_where_v1(
                &connection,
                "dispatch_transitions",
                "previous_state = 'OUTCOME_UNKNOWN' AND new_state = 'RECONCILIATION_REQUIRED'",
            ),
            count_where_v1(
                &connection,
                "dispatch_transitions",
                "previous_state = 'RECONCILIATION_REQUIRED' AND new_state = 'FAILED'",
            ),
            count_where_v1(
                &connection,
                "operation_transitions",
                "previous_state = 'PREPARING' AND new_state = 'FAILED'",
            ),
            count_where_v1(
                &connection,
                "preparation_events",
                "operation_state = 'FAILED' AND event_kind = 'PREPARATION_FAILED' \
                 AND reason_code = 'ADAPTER_PAUSED'",
            ),
        ),
        (1, 1, 1, 1, 1),
        "terminal closure appends every required transition and base failure exactly once",
    );
    let released_generation = connection
        .query_row(
            "SELECT released_generation FROM budget_reservations \
             WHERE reservation_state = 'RELEASED'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("T067 exact release generation reads");
    assert_eq!(
        safe_u64_v1(released_generation),
        first_evidence.reservation_released_generation()
    );
    assert_eq!(NO_EFFECT_CALLS.load(Ordering::SeqCst), 0);
}

#[test]
fn one_real_dispatch_reaches_one_adapter_consumption_and_survives_restart() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    let mut coordinator = PreparedCoordinatorRootV1::new_v1();
    let coordinator_descriptor = coordinator.descriptor_v1();
    let mut adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
    assert!(adapter.path().is_dir());
    let adapter_descriptor = adapter.descriptor_v1(&coordinator.bindings);
    assert_eq!(
        live_commit_custody_count_v1(
            &coordinator_descriptor.database,
            &coordinator.bindings,
            STORE_DEADLINE_MONOTONIC_MS,
        ),
        1,
        "T055 real PLAN-004 graph must satisfy the production commit custody join",
    );

    let coordinator_store = coordinator_descriptor.open_store_v1();
    assert_eq!(
        dispatch_once_v1(&coordinator_store, &coordinator.bindings, 1),
        CoordinatorDispatchClassV1::Committed
    );
    drop(coordinator_store);
    let retained = load_pending_grant_read_only_v1(
        &coordinator_descriptor.database,
        &coordinator.bindings.operation_id,
    );

    let consumer = adapter_descriptor.open_consumer_v1(1);
    let first_receipt =
        match receive_and_consume_exact_grant_v1(&consumer, &retained.canonical_grant) {
            DispatchInboxAdapterOutcomeV1::Consumed(receipt) => receipt,
            other => panic!("T055 first adapter traversal did not consume once: {other:?}"),
        };
    assert_eq!(
        first_receipt.decision(),
        AdapterRetainedReceiptDecisionV1::Consumed
    );
    assert!(first_receipt.refusal_code().is_none());
    let canonical_receipt = first_receipt.canonical_receipt().to_vec();
    verify_consumed_receipt_v1(
        &retained,
        &canonical_receipt,
        adapter_descriptor.root_identity,
    );
    drop(first_receipt);
    drop(consumer);
    assert_exact_durable_graph_v1(
        &coordinator_descriptor.database,
        &adapter_descriptor.database,
    );

    // No store or WAL anchor remains open across this boundary. Both independent roots
    // are then reopened strictly, exercising retained coordinator and adapter evidence.
    coordinator.force_last_close_v1();
    adapter.force_last_close_v1();
    let reopened_coordinator_store = coordinator_descriptor.open_store_v1();
    assert_eq!(
        dispatch_once_v1(&reopened_coordinator_store, &coordinator.bindings, 2),
        CoordinatorDispatchClassV1::PriorExact
    );
    drop(reopened_coordinator_store);
    let reloaded = load_pending_grant_read_only_v1(
        &coordinator_descriptor.database,
        &coordinator.bindings.operation_id,
    );
    assert_eq!(reloaded.grant_id, retained.grant_id);
    assert_eq!(reloaded.canonical_grant, retained.canonical_grant);

    let reopened_consumer = adapter_descriptor.open_consumer_v1(2);
    let retained_receipt =
        match receive_and_consume_exact_grant_v1(&reopened_consumer, &reloaded.canonical_grant) {
            DispatchInboxAdapterOutcomeV1::RetainedReceipt(receipt) => receipt,
            other => panic!("T055 restart did not return the retained receipt: {other:?}"),
        };
    assert_eq!(retained_receipt.canonical_receipt(), canonical_receipt);
    verify_consumed_receipt_v1(
        &reloaded,
        retained_receipt.canonical_receipt(),
        adapter_descriptor.root_identity,
    );
    drop(retained_receipt);
    drop(reopened_consumer);
    coordinator.reopen_anchor_v1();
    adapter.reopen_anchor_v1();
    assert_exact_durable_graph_v1(
        &coordinator_descriptor.database,
        &adapter_descriptor.database,
    );
    assert_eq!(NO_EFFECT_CALLS.load(Ordering::SeqCst), 0);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinatorAttemptClassV1 {
    Committed,
    PriorExact,
    Denied,
    Failed,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterAttemptClassV1 {
    Consumed,
    RetainedReceipt,
    DefinitelyRefused,
    RefusedBeforeReceive,
    Conflict,
    Quarantined,
    Unavailable,
    Unhealthy,
    NotReached,
}

struct AttemptObservationV1 {
    coordinator: CoordinatorAttemptClassV1,
    adapter: AdapterAttemptClassV1,
    grant_id: Option<Sha256Digest>,
    canonical_grant_sha256: Option<Sha256Digest>,
    canonical_receipt: Option<Vec<u8>>,
}

impl fmt::Debug for AttemptObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttemptObservationV1")
            .field("coordinator", &self.coordinator)
            .field("adapter", &self.adapter)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct MatrixCountsV1 {
    coordinator_committed: usize,
    coordinator_prior_exact: usize,
    coordinator_denied: usize,
    coordinator_failed: usize,
    coordinator_ambiguous: usize,
    adapter_consumed: usize,
    adapter_retained_receipt: usize,
    adapter_definitely_refused: usize,
    adapter_refused_before_receive: usize,
    adapter_conflict: usize,
    adapter_quarantined: usize,
    adapter_unavailable: usize,
    adapter_unhealthy: usize,
    adapter_not_reached: usize,
}

impl MatrixCountsV1 {
    fn observe_v1(&mut self, observation: &AttemptObservationV1) {
        match observation.coordinator {
            CoordinatorAttemptClassV1::Committed => self.coordinator_committed += 1,
            CoordinatorAttemptClassV1::PriorExact => self.coordinator_prior_exact += 1,
            CoordinatorAttemptClassV1::Denied => self.coordinator_denied += 1,
            CoordinatorAttemptClassV1::Failed => self.coordinator_failed += 1,
            CoordinatorAttemptClassV1::Ambiguous => self.coordinator_ambiguous += 1,
        }
        match observation.adapter {
            AdapterAttemptClassV1::Consumed => self.adapter_consumed += 1,
            AdapterAttemptClassV1::RetainedReceipt => self.adapter_retained_receipt += 1,
            AdapterAttemptClassV1::DefinitelyRefused => self.adapter_definitely_refused += 1,
            AdapterAttemptClassV1::RefusedBeforeReceive => {
                self.adapter_refused_before_receive += 1;
            }
            AdapterAttemptClassV1::Conflict => self.adapter_conflict += 1,
            AdapterAttemptClassV1::Quarantined => self.adapter_quarantined += 1,
            AdapterAttemptClassV1::Unavailable => self.adapter_unavailable += 1,
            AdapterAttemptClassV1::Unhealthy => self.adapter_unhealthy += 1,
            AdapterAttemptClassV1::NotReached => self.adapter_not_reached += 1,
        }
    }

    fn assert_exact_v1(&self, contenders: usize) {
        assert_eq!(self.coordinator_committed, 1);
        assert_eq!(self.coordinator_prior_exact, contenders - 1);
        assert_eq!(
            (
                self.coordinator_denied,
                self.coordinator_failed,
                self.coordinator_ambiguous,
            ),
            (0, 0, 0),
            "T055 coordinator contention has no denial/failure/conflict ambiguity",
        );
        assert_eq!(self.adapter_consumed, 1);
        assert_eq!(self.adapter_retained_receipt, contenders - 1);
        assert_eq!(
            (
                self.adapter_definitely_refused,
                self.adapter_refused_before_receive,
                self.adapter_conflict,
                self.adapter_quarantined,
                self.adapter_unavailable,
                self.adapter_unhealthy,
                self.adapter_not_reached,
            ),
            (0, 0, 0, 0, 0, 0, 0),
            "T055 adapter contention has no duplicate consumption or closed failure",
        );
    }
}

fn observe_end_to_end_attempt_v1(
    coordinator: &CoordinatorDescriptorV1,
    adapter: &AdapterDescriptorV1,
    entropy_seed: u64,
) -> AttemptObservationV1 {
    let coordinator_store = coordinator.open_store_v1();
    let consumer = adapter.open_consumer_v1(entropy_seed);
    observe_end_to_end_with_open_stores_v1(
        coordinator,
        &coordinator_store,
        adapter,
        &consumer,
        entropy_seed,
    )
}

fn observe_end_to_end_with_open_stores_v1(
    coordinator: &CoordinatorDescriptorV1,
    coordinator_store: &SqliteCoordinatorStoreV2<
        SyntheticCoordinatorClockV1,
        SyntheticHistoricalPlanKeyResolverV1,
    >,
    adapter: &AdapterDescriptorV1,
    consumer: &SqliteAdapterConsumerV1,
    entropy_seed: u64,
) -> AttemptObservationV1 {
    let authority = AuthorityFixtureV1 {
        prepared: coordinator.bindings.clone(),
    };
    let coordinator_class = match dispatch_prepared_once_v1(
        coordinator_store,
        coordinator.bindings.lookup_request_v1(),
        &authority,
        &SeededEntropyV1(entropy_seed),
        &DispatchKeysV1::fixed_v1(),
        &authority,
    ) {
        DispatchRequestOutcomeV1::Dispatched(_) => CoordinatorAttemptClassV1::Committed,
        DispatchRequestOutcomeV1::AlreadyDispatched(_) => CoordinatorAttemptClassV1::PriorExact,
        DispatchRequestOutcomeV1::Denied(_) => CoordinatorAttemptClassV1::Denied,
        DispatchRequestOutcomeV1::Failed(_) => CoordinatorAttemptClassV1::Failed,
        DispatchRequestOutcomeV1::Ambiguous(_) => CoordinatorAttemptClassV1::Ambiguous,
    };
    if !matches!(
        coordinator_class,
        CoordinatorAttemptClassV1::Committed | CoordinatorAttemptClassV1::PriorExact
    ) {
        return AttemptObservationV1 {
            coordinator: coordinator_class,
            adapter: AdapterAttemptClassV1::NotReached,
            grant_id: None,
            canonical_grant_sha256: None,
            canonical_receipt: None,
        };
    }

    let retained =
        load_pending_grant_read_only_v1(&coordinator.database, &coordinator.bindings.operation_id);
    let (adapter_class, receipt) =
        match receive_and_consume_exact_grant_v1(consumer, &retained.canonical_grant) {
            DispatchInboxAdapterOutcomeV1::Consumed(receipt) => {
                (AdapterAttemptClassV1::Consumed, Some(receipt))
            }
            DispatchInboxAdapterOutcomeV1::RetainedReceipt(receipt) => {
                (AdapterAttemptClassV1::RetainedReceipt, Some(receipt))
            }
            DispatchInboxAdapterOutcomeV1::DefinitelyRefused(receipt) => {
                (AdapterAttemptClassV1::DefinitelyRefused, Some(receipt))
            }
            DispatchInboxAdapterOutcomeV1::RefusedBeforeReceive(_) => {
                (AdapterAttemptClassV1::RefusedBeforeReceive, None)
            }
            DispatchInboxAdapterOutcomeV1::Conflict => (AdapterAttemptClassV1::Conflict, None),
            DispatchInboxAdapterOutcomeV1::Quarantined => {
                (AdapterAttemptClassV1::Quarantined, None)
            }
            DispatchInboxAdapterOutcomeV1::ReceiveUnavailable
            | DispatchInboxAdapterOutcomeV1::ConsumeUnavailable => {
                (AdapterAttemptClassV1::Unavailable, None)
            }
            DispatchInboxAdapterOutcomeV1::ReceiveUnhealthy
            | DispatchInboxAdapterOutcomeV1::ConsumeUnhealthy => {
                (AdapterAttemptClassV1::Unhealthy, None)
            }
        };
    let canonical_receipt = receipt.map(|receipt| receipt.canonical_receipt().to_vec());
    if matches!(
        adapter_class,
        AdapterAttemptClassV1::Consumed | AdapterAttemptClassV1::RetainedReceipt
    ) {
        verify_consumed_receipt_v1(
            &retained,
            canonical_receipt
                .as_deref()
                .expect("T055 positive adapter outcome retains receipt bytes"),
            adapter.root_identity,
        );
    }
    AttemptObservationV1 {
        coordinator: coordinator_class,
        adapter: adapter_class,
        grant_id: Some(retained.grant_id),
        canonical_grant_sha256: Some(Sha256Digest::digest(&retained.canonical_grant)),
        canonical_receipt,
    }
}

fn assert_matrix_observations_v1(
    observations: &[AttemptObservationV1],
    expected: usize,
) -> Vec<u8> {
    assert_eq!(observations.len(), expected);
    let mut counts = MatrixCountsV1::default();
    for observation in observations {
        counts.observe_v1(observation);
    }
    counts.assert_exact_v1(expected);
    let first = observations.first().expect("T055 matrix has contenders");
    let grant_id = first
        .grant_id
        .expect("T055 first contender observes retained grant");
    let grant_wire_digest = first
        .canonical_grant_sha256
        .expect("T055 first contender observes exact retained bytes");
    let canonical_receipt = first
        .canonical_receipt
        .as_ref()
        .expect("T055 first contender observes retained receipt")
        .clone();
    for observation in observations {
        assert_eq!(observation.grant_id, Some(grant_id));
        assert_eq!(observation.canonical_grant_sha256, Some(grant_wire_digest));
        assert_eq!(
            observation.canonical_receipt.as_deref(),
            Some(canonical_receipt.as_slice()),
            "T055 every contender receives byte-identical authentic receipt evidence",
        );
    }
    assert_eq!(NO_EFFECT_CALLS.load(Ordering::SeqCst), 0);
    canonical_receipt
}

fn assert_restart_checkpoint_v1(
    coordinator: &CoordinatorDescriptorV1,
    adapter: &AdapterDescriptorV1,
    expected_receipt: &[u8],
) {
    drop(coordinator.open_store_v1());
    let retained =
        load_pending_grant_read_only_v1(&coordinator.database, &coordinator.bindings.operation_id);
    let adapter_store = adapter.open_store_v1();
    let readback = adapter_store
        .readback_grant_v1(
            retained.grant_id,
            &DispatchGrantResolverV1::fixed_v1(),
            &ReceiptKeysV1::fixed_v1(),
        )
        .expect("T055 restart receipt readback succeeds");
    let receipt = match readback {
        AdapterInboxReadbackOutcomeV1::RetainedReceipt(receipt) => receipt,
        other => panic!("T055 restart checkpoint returned {other:?}"),
    };
    assert_eq!(receipt.canonical_receipt(), expected_receipt);
    verify_consumed_receipt_v1(
        &retained,
        receipt.canonical_receipt(),
        adapter.root_identity,
    );
}

#[test]
fn exact_10_000_sequential_duplicates_retain_one_dispatch_and_one_consumption() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    let mut coordinator = PreparedCoordinatorRootV1::new_v1();
    let coordinator_descriptor = coordinator.descriptor_v1();
    let mut adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
    let adapter_descriptor = adapter.descriptor_v1(&coordinator.bindings);
    let mut observations = Vec::with_capacity(RELEASE_DUPLICATE_REQUESTS);

    let midpoint = RELEASE_DUPLICATE_REQUESTS / 2;
    for (segment_index, segment) in [0..midpoint, midpoint..RELEASE_DUPLICATE_REQUESTS]
        .into_iter()
        .enumerate()
    {
        let coordinator_store = coordinator_descriptor.open_store_v1();
        let consumer = adapter_descriptor.open_consumer_v1(
            u64::try_from(segment.start + 1).expect("T055 segment seed fits u64"),
        );
        for ordinal in segment {
            observations.push(observe_end_to_end_with_open_stores_v1(
                &coordinator_descriptor,
                &coordinator_store,
                &adapter_descriptor,
                &consumer,
                u64::try_from(ordinal + 1).expect("T055 sequential seed fits u64"),
            ));
        }
        drop(consumer);
        drop(coordinator_store);
        if segment_index == 0 {
            coordinator.force_last_close_v1();
            adapter.force_last_close_v1();
            let retained_receipt = observations
                .first()
                .and_then(|observation: &AttemptObservationV1| {
                    observation.canonical_receipt.as_deref()
                })
                .expect("T055 midpoint has one retained receipt");
            assert_restart_checkpoint_v1(
                &coordinator_descriptor,
                &adapter_descriptor,
                retained_receipt,
            );
            coordinator.reopen_anchor_v1();
            adapter.reopen_anchor_v1();
        }
    }

    let canonical_receipt =
        assert_matrix_observations_v1(&observations, RELEASE_DUPLICATE_REQUESTS);
    assert_exact_durable_graph_v1(
        &coordinator_descriptor.database,
        &adapter_descriptor.database,
    );
    coordinator.force_last_close_v1();
    adapter.force_last_close_v1();
    assert_restart_checkpoint_v1(
        &coordinator_descriptor,
        &adapter_descriptor,
        &canonical_receipt,
    );
    coordinator.reopen_anchor_v1();
    adapter.reopen_anchor_v1();
}

#[test]
fn exact_100_rounds_of_64_threads_retain_one_dispatch_and_consumption_per_round() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    for round in 0..RELEASE_THREAD_ROUNDS {
        let mut coordinator = PreparedCoordinatorRootV1::new_v1();
        let coordinator_descriptor = Arc::new(coordinator.descriptor_v1());
        let mut adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
        let adapter_descriptor = Arc::new(adapter.descriptor_v1(&coordinator.bindings));
        let barrier = Arc::new(Barrier::new(RELEASE_THREAD_CONTENDERS));
        // Strict root opening is a fail-closed setup boundary protected by the root
        // lease, not part of the dispatch contention being measured here. Prepare one
        // independently verified handle per contender before releasing the wave, while
        // the idle anchors keep the WAL lifecycle stable. The operations below still
        // contend through the production root/SQLite gates.
        let prepared_contenders = (0..RELEASE_THREAD_CONTENDERS)
            .map(|contender| {
                let seed = ((round as u64) << 32) | (contender as u64 + 1);
                (
                    seed,
                    coordinator_descriptor.open_store_v1(),
                    adapter_descriptor.open_consumer_v1(seed),
                )
            })
            .collect::<Vec<_>>();
        let workers = prepared_contenders
            .into_iter()
            .map(|(seed, coordinator_store, consumer)| {
                let coordinator = Arc::clone(&coordinator_descriptor);
                let adapter = Arc::clone(&adapter_descriptor);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    observe_end_to_end_with_open_stores_v1(
                        &coordinator,
                        &coordinator_store,
                        &adapter,
                        &consumer,
                        seed,
                    )
                })
            })
            .collect::<Vec<_>>();
        let observations = workers
            .into_iter()
            .map(|worker| worker.join().expect("T055 thread contender does not panic"))
            .collect::<Vec<_>>();
        let canonical_receipt =
            assert_matrix_observations_v1(&observations, RELEASE_THREAD_CONTENDERS);
        assert_exact_durable_graph_v1(
            &coordinator_descriptor.database,
            &adapter_descriptor.database,
        );
        coordinator.force_last_close_v1();
        adapter.force_last_close_v1();
        assert_restart_checkpoint_v1(
            &coordinator_descriptor,
            &adapter_descriptor,
            &canonical_receipt,
        );
        coordinator.reopen_anchor_v1();
        adapter.reopen_anchor_v1();
    }
}

#[test]
fn exact_20_rounds_of_8_processes_retain_one_dispatch_and_consumption_per_round() {
    NO_EFFECT_CALLS.store(0, Ordering::SeqCst);
    for round in 0..RELEASE_PROCESS_ROUNDS {
        let mut coordinator = PreparedCoordinatorRootV1::new_v1();
        let coordinator_descriptor = coordinator.descriptor_v1();
        let mut adapter = AdapterRootV1::new_v1(coordinator.bindings.supervisor_epoch);
        let adapter_descriptor = adapter.descriptor_v1(&coordinator.bindings);
        coordinator.force_last_close_v1();
        adapter.force_last_close_v1();
        let environment = [
            ProcessProbeEnvironmentV1::new(
                PROCESS_COORDINATOR_ROOT_ENV,
                coordinator_descriptor.root.clone().into_os_string(),
            ),
            ProcessProbeEnvironmentV1::new(
                PROCESS_COORDINATOR_IDENTITY_ENV,
                hex_v1(coordinator_descriptor.root_identity.to_attested_bytes()),
            ),
            ProcessProbeEnvironmentV1::new(
                PROCESS_ADAPTER_ROOT_ENV,
                adapter_descriptor.root.clone().into_os_string(),
            ),
            ProcessProbeEnvironmentV1::new(
                PROCESS_ADAPTER_IDENTITY_ENV,
                hex_v1(adapter_descriptor.root_identity.to_attested_bytes()),
            ),
            ProcessProbeEnvironmentV1::new(PROCESS_ROUND_ENV, round.to_string()),
        ];
        let mut probe = SynchronizedProcessProbeV1::spawn_v1(
            PROCESS_CHILD_TEST_NAME,
            RELEASE_PROCESS_CONTENDERS,
            &environment,
        )
        .expect("T055 process contenders spawn");
        let results = probe
            .execute_v1()
            .expect("T055 process contenders complete");
        assert_process_results_v1(&results);

        let retained = load_pending_grant_read_only_v1(
            &coordinator_descriptor.database,
            &coordinator_descriptor.bindings.operation_id,
        );
        let adapter_store = adapter_descriptor.open_store_v1();
        let receipt = match adapter_store
            .readback_grant_v1(
                retained.grant_id,
                &DispatchGrantResolverV1::fixed_v1(),
                &ReceiptKeysV1::fixed_v1(),
            )
            .expect("T055 process-round receipt reads")
        {
            AdapterInboxReadbackOutcomeV1::RetainedReceipt(receipt) => receipt,
            other => panic!("T055 process round retained unexpected state: {other:?}"),
        };
        verify_consumed_receipt_v1(
            &retained,
            receipt.canonical_receipt(),
            adapter_descriptor.root_identity,
        );
        let expected_receipt_digest = Sha256Digest::digest(receipt.canonical_receipt());
        assert!(results.iter().all(|result| {
            result.len() == 34 && result[2..] == expected_receipt_digest.as_bytes()[..]
        }));
        let canonical_receipt = receipt.canonical_receipt().to_vec();
        drop(receipt);
        drop(adapter_store);
        assert_exact_durable_graph_v1(
            &coordinator_descriptor.database,
            &adapter_descriptor.database,
        );
        assert_restart_checkpoint_v1(
            &coordinator_descriptor,
            &adapter_descriptor,
            &canonical_receipt,
        );
        coordinator.reopen_anchor_v1();
        adapter.reopen_anchor_v1();
    }
}

fn assert_process_results_v1(results: &[Vec<u8>]) {
    assert_eq!(results.len(), RELEASE_PROCESS_CONTENDERS);
    assert!(results.iter().all(|result| result.len() == 34));
    assert_eq!(results.iter().filter(|result| result[0] == b'C').count(), 1,);
    assert_eq!(
        results.iter().filter(|result| result[0] == b'P').count(),
        RELEASE_PROCESS_CONTENDERS - 1,
    );
    assert_eq!(results.iter().filter(|result| result[1] == b'C').count(), 1,);
    assert_eq!(
        results.iter().filter(|result| result[1] == b'R').count(),
        RELEASE_PROCESS_CONTENDERS - 1,
    );
    assert!(results.iter().all(|result| result[2..] == results[0][2..]));
}

#[test]
#[ignore = "private synchronized T055 child; parent process owns READY/GO"]
fn t055_private_process_child_v1() {
    let Some(child) = ProcessProbeChildV1::from_environment_v1()
        .expect("T055 private child environment validates")
    else {
        return;
    };
    child
        .publish_ready_and_wait_for_go_v1()
        .expect("T055 private child synchronizes");
    let coordinator_root = PathBuf::from(
        private_process_argument_v1(PROCESS_COORDINATOR_ROOT_ENV)
            .expect("T055 private coordinator root exists"),
    );
    let coordinator_identity =
        CoordinatorRootIdentityEvidenceV1::from_attested_bytes(parse_hex_v1(
            private_process_argument_v1(PROCESS_COORDINATOR_IDENTITY_ENV)
                .expect("T055 private coordinator identity exists"),
        ));
    let coordinator_database = fs::canonicalize(&coordinator_root)
        .expect("T055 private coordinator root canonicalizes")
        .join(COORDINATOR_DATABASE_FILENAME);
    let bindings = PreparedDispatchBindingsV1::load_strict_v1(&coordinator_database);
    let coordinator = CoordinatorDescriptorV1 {
        root: coordinator_root,
        root_identity: coordinator_identity,
        database: coordinator_database,
        bindings: bindings.clone(),
    };
    let adapter_root = PathBuf::from(
        private_process_argument_v1(PROCESS_ADAPTER_ROOT_ENV)
            .expect("T055 private adapter root exists"),
    );
    let adapter_identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(parse_hex_v1(
        private_process_argument_v1(PROCESS_ADAPTER_IDENTITY_ENV)
            .expect("T055 private adapter identity exists"),
    ));
    let adapter = AdapterDescriptorV1 {
        database: fs::canonicalize(&adapter_root)
            .expect("T055 private adapter root canonicalizes")
            .join(ADAPTER_DATABASE_FILENAME),
        root: adapter_root,
        root_identity: adapter_identity,
        boot_id: bindings.boot_id.clone(),
        supervisor_epoch: bindings.supervisor_epoch,
    };
    let round = private_process_argument_v1(PROCESS_ROUND_ENV)
        .expect("T055 private round exists")
        .to_string_lossy()
        .parse::<u64>()
        .expect("T055 private round parses");
    let seed = (round << 32) | (child.index_v1() as u64 + 1);
    let observation = observe_end_to_end_attempt_v1(&coordinator, &adapter, seed);
    assert!(matches!(
        observation.coordinator,
        CoordinatorAttemptClassV1::Committed | CoordinatorAttemptClassV1::PriorExact
    ));
    assert!(matches!(
        observation.adapter,
        AdapterAttemptClassV1::Consumed | AdapterAttemptClassV1::RetainedReceipt
    ));
    let mut result = Vec::with_capacity(34);
    result.push(match observation.coordinator {
        CoordinatorAttemptClassV1::Committed => b'C',
        CoordinatorAttemptClassV1::PriorExact => b'P',
        _ => unreachable!("T055 private child asserted coordinator success"),
    });
    result.push(match observation.adapter {
        AdapterAttemptClassV1::Consumed => b'C',
        AdapterAttemptClassV1::RetainedReceipt => b'R',
        _ => unreachable!("T055 private child asserted adapter success"),
    });
    result.extend_from_slice(
        Sha256Digest::digest(
            observation
                .canonical_receipt
                .as_deref()
                .expect("T055 private child retains receipt bytes"),
        )
        .as_bytes(),
    );
    assert_eq!(NO_EFFECT_CALLS.load(Ordering::SeqCst), 0);
    child
        .publish_result_v1(&result)
        .expect("T055 private child publishes classified receipt digest");
}

fn live_commit_custody_count_v1(
    database: &Path,
    bindings: &PreparedDispatchBindingsV1,
    effective_deadline_monotonic_ms: u64,
) -> i64 {
    let connection = open_read_only_v1(database);
    connection
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
            rusqlite::params![
                bindings.operation_id,
                bindings.preparation_attempt_id.as_slice(),
                bindings.plan_id.as_slice(),
                bindings.task_id,
                bindings.workload_id,
                bindings.reservation_id,
                bindings.preparation_transition_generation as i64,
                bindings.boot_id,
                bindings.instance_epoch as i64,
                bindings.supervisor_epoch as i64,
                effective_deadline_monotonic_ms as i64,
                bindings.task_lease_digest.as_slice(),
            ],
            |row| row.get(0),
        )
        .expect("T055 live commit custody count reads")
}

fn verify_consumed_receipt_v1(
    grant: &RetainedGrantTransportV1,
    canonical_receipt: &[u8],
    adapter_root_identity: AdapterInboxRootIdentityEvidenceV1,
) {
    let retained_grant = decode_and_verify_retained_execution_grant_v1(
        &grant.canonical_grant,
        &DispatchGrantResolverV1::fixed_v1(),
    )
    .expect("T055 receipt grant binding authenticates");
    let bindings = ReceiptVerificationBindingsV1::from_retained_grant_evidence(
        &retained_grant,
        Sha256Digest::from_bytes(adapter_root_identity.to_attested_bytes()),
    );
    let authentic_receipt = decode_and_verify_execution_receipt_v1(
        canonical_receipt,
        &ReceiptKeysV1::fixed_v1(),
        &bindings,
    )
    .expect("T055 retained adapter receipt authenticates");
    assert_eq!(
        authentic_receipt.claims().decision(),
        ExecutionReceiptDecisionV1::Consumed
    );
    assert_eq!(authentic_receipt.claims().grant_id(), grant.grant_id);
    assert_eq!(
        authentic_receipt
            .canonical_signed_envelope_bytes()
            .expect("T055 retained receipt canonicalizes"),
        canonical_receipt
    );
}

fn assert_exact_durable_graph_v1(coordinator_database: &Path, adapter_database: &Path) {
    let coordinator = open_read_only_v1(coordinator_database);
    assert_eq!(
        (
            count_where_v1(&coordinator, "dispatch_grants", "1 = 1"),
            count_where_v1(
                &coordinator,
                "dispatch_records",
                "effective_state = 'DISPATCHING'",
            ),
            count_where_v1(&coordinator, "dispatch_transitions", "1 = 1"),
            count_where_v1(
                &coordinator,
                "dispatch_outbox",
                "delivery_state = 'PENDING' AND current_attempt_generation IS NULL",
            ),
            count_where_v1(&coordinator, "dispatch_delivery_attempts", "1 = 1"),
            count_where_v1(&coordinator, "dispatch_receipts", "1 = 1"),
        ),
        (1, 1, 1, 1, 0, 0),
        "T055 stops before T064 handoff and before T052 coordinator receipt commit",
    );

    let adapter = open_read_only_v1(adapter_database);
    assert_eq!(
        (
            count_where_v1(&adapter, "grant_inbox", "inbox_state = 'CONSUMED'"),
            count_where_v1(&adapter, "inbox_transitions", "1 = 1"),
            count_where_v1(&adapter, "execution_receipts", "decision = 'CONSUMED'"),
            count_where_v1(&adapter, "adapter_events", "1 = 1"),
            count_where_v1(&adapter, "inbox_conflicts", "1 = 1"),
            count_where_v1(&adapter, "inbox_quarantines", "1 = 1"),
        ),
        (1, 2, 1, 2, 0, 0),
        "T055 retains exactly one adapter receive/consume/receipt graph",
    );
}

fn install_exact_v2_overlay_v1(database: &Path) {
    let connection = Connection::open(database).expect("T055 V1 database opens for V2 fixture");
    let root_identity: Vec<u8> = connection
        .query_row(
            "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("T055 coordinator identity reads for V2 fixture");
    connection
        .execute_batch(V2_OVERLAY)
        .expect("T055 reviewed V2 overlay installs");
    connection
        .execute(
            "INSERT INTO dispatch_store_meta (\
                singleton, extension_format_version, dispatch_store_generation, \
                dispatch_generation, delivery_generation, receipt_generation, \
                reconciliation_generation, event_generation, migration_generation, \
                ordinary_queue_capacity, control_queue_capacity, root_lifecycle_state, \
                restore_index_digest, restore_state_generation\
             ) VALUES (1, 1, 1, 0, 0, 0, 0, 0, 1, 1024, 32, 'ACTIVE', NULL, 0)",
            [],
        )
        .expect("T055 V2 metadata installs");
    connection
        .execute(
            "INSERT INTO coordinator_v2_migrations (\
                migration_attempt_id, source_schema_digest, source_root_identity, \
                source_summary_digest, verified_backup_digest, overlay_schema_digest, \
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms, \
                tool_identity\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1000, 1000, 'helixos-t055-test-v1')",
            rusqlite::params![
                [0x42_u8; 32].as_slice(),
                embedded_schema_v1_sha256().as_slice(),
                root_identity,
                [0x43_u8; 32].as_slice(),
                [0x44_u8; 32].as_slice(),
                <[u8; 32]>::from(Sha256::digest(V2_OVERLAY.as_bytes())).as_slice(),
            ],
        )
        .expect("T055 V2 migration receipt installs");
}

fn open_read_only_v1(database: &Path) -> Connection {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .expect("T055 strict read-only SQLite observation opens")
}

fn count_where_v1(connection: &Connection, table: &str, predicate: &str) -> i64 {
    let allowed = [
        "prepared_operations",
        "operation_transitions",
        "preparation_events",
        "dispatch_grants",
        "dispatch_records",
        "dispatch_transitions",
        "dispatch_outbox",
        "dispatch_delivery_attempts",
        "dispatch_events",
        "dispatch_receipts",
        "dispatch_reconciliations",
        "dispatch_definite_refusal_guards",
        "budget_reservations",
        "execution_receipts",
        "grant_inbox",
        "inbox_transitions",
        "adapter_events",
        "inbox_conflicts",
        "inbox_quarantines",
    ];
    assert!(allowed.contains(&table));
    let statement = format!("SELECT COUNT(*) FROM {table} WHERE {predicate}");
    connection
        .query_row(&statement, [], |row| row.get(0))
        .expect("T055 exact durable count reads")
}

fn exact_array_v1(bytes: Vec<u8>) -> [u8; 32] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("T055 expected one exact 32-byte binding"))
}

fn safe_u64_v1(value: i64) -> u64 {
    u64::try_from(value).expect("T055 durable generation is nonnegative")
}

fn identifier_v1(value: &str) -> Identifier {
    Identifier::new(value).expect("T055 identifier is valid")
}

fn generation_v1(value: u64) -> Generation {
    Generation::new(value).expect("T055 generation is valid")
}

fn safe_v1(value: u64) -> SafeU64 {
    SafeU64::new(value).expect("T055 safe integer is valid")
}

fn digest_byte_v1(value: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([value; 32])
}

fn dispatch_key_fingerprint_v1() -> Sha256Digest {
    Sha256Digest::digest(&DispatchGrantResolverV1::fixed_v1().verifying_key)
}

fn hex_v1(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_hex_v1(value: OsString) -> [u8; 32] {
    let value = value
        .into_string()
        .unwrap_or_else(|_| panic!("T055 private identity argument is UTF-8"));
    assert_eq!(value.len(), 64);
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble_v1(pair[0]) << 4) | hex_nibble_v1(pair[1]);
    }
    bytes
}

fn hex_nibble_v1(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("T055 private identity argument is canonical hex"),
    }
}
