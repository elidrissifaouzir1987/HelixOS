//! PLAN-005 coordinator, handoff, readback, and closure fault evidence.
//!
//! The release-only matrix re-executes this integration binary, prepares one durable
//! V2 root before READY, carries one explicit process-barrier selection through the
//! corresponding production workflow, terminates the blocked child, and delegates
//! authoritative reopen verification to a second child. This is process-kill evidence;
//! it is deliberately not labelled as power-loss evidence.

#![cfg(feature = "test-fault-injection")]

mod common;

#[path = "../src/comparison_digest.rs"]
mod comparison_digest;
#[path = "../src/outbox.rs"]
mod outbox;
#[path = "../src/prepare.rs"]
mod prepare;
#[path = "../src/readback.rs"]
mod readback;
#[path = "../src/test_fault.rs"]
mod test_fault;

use common::process_probe::{
    private_process_argument_v1, ProcessProbeChildV1, ProcessProbeEnvironmentV1,
    SynchronizedProcessProbeV1,
};
use common::{SyntheticCoordinatorClockV1, SyntheticHistoricalPlanKeyResolverV1};
use ed25519_dalek::{Signer as _, SigningKey};
use helix_coordinator_sqlite::{
    embedded_schema_v1_sha256, CoordinatorDispatchHandoffOutcomeV1,
    CoordinatorReadbackSequenceClaimOutcomeV1, CoordinatorReadbackSequenceClaimV1,
    CoordinatorReceiptCommitOutcomeV1, CoordinatorReceiptLookupV1,
    CoordinatorReconciliationLookupV1, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
    SqliteCoordinatorStoreV1, SqliteCoordinatorStoreV2,
};
use helix_dispatch_contracts::{
    decode_and_verify_execution_receipt_v1, decode_and_verify_retained_execution_grant_v1,
    sign_execution_receipt_v1, ContractError, ExecutionReceiptDecisionV1, ExecutionReceiptInputV1,
    ExecutionReceiptProtectedV1, ExecutionReceiptRefusalCodeV1, Generation, GrantKeyResolver,
    GrantSigner, GrantVerificationKeyV1, Identifier, ReceiptKeyResolver, ReceiptSigner,
    ReceiptVerificationBindingsV1, ReceiptVerificationKeyV1, RecoveryModeV1,
    Result as DispatchContractResult, SafeU64, Sha256Digest,
};
use helix_plan_dispatch::{
    classify_definite_absence_v1, classify_no_consumption_receipt_v1, dispatch_prepared_once_v1,
    dispatch_prepared_once_with_fault_probe_v1, recover_lost_acknowledgement_with_fault_probe_v1,
    run_automatic_readback_once_with_fault_probe_v1, DispatchAttemptIdV1,
    DispatchAuthorityCaptureOutcomeV1, DispatchAuthorityCapturePhaseV1,
    DispatchAuthorityProviderV1, DispatchAuthorityViewInputV1, DispatchAuthorityViewV1,
    DispatchAutomaticHandoffClassificationV1, DispatchAutomaticReadbackGateV1,
    DispatchAutomaticReadbackScheduleV1, DispatchCommitPermitOutcomeV1, DispatchCommitPermitV1,
    DispatchCommitResolutionV1, DispatchDefiniteAbsenceClassificationV1,
    DispatchDefiniteAbsenceEvidenceInputV1, DispatchDefiniteAbsenceEvidenceV1,
    DispatchDefiniteAbsenceProofV1, DispatchEntropyDomainV1, DispatchEntropyErrorV1,
    DispatchEntropySourceV1, DispatchFaultProbeV1, DispatchGuardAcquisitionV1,
    DispatchGuardClassV1, DispatchGuardOrderErrorV1, DispatchGuardProviderV1, DispatchGuardSetV1,
    DispatchGuardValidationV1, DispatchHandoffGuardV1, DispatchHandoffOutcomeV1,
    DispatchHandoffValidationV1, DispatchInboxReadbackOutcomeV1, DispatchInboxReadbackV1,
    DispatchInboxReceiveOutcomeV1, DispatchInboxV1, DispatchLookupRequestInputV1,
    DispatchLookupRequestV1, DispatchNoConsumptionTombstoneCustodyV1,
    DispatchReadbackWaitOutcomeV1, DispatchRequestOutcomeV1, DispatchStoreCommitClassificationV1,
    DispatchTransportV1, FaultInjectionModeV1, DISPATCH_AUTHORITY_VIEW_VERSION_V1,
    DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
};
use helix_plan_preparation::PreparationCommitOutcomeV1;
use prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use rusqlite::{params, Connection, OpenFlags};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

const REGISTRY_BYTES: &[u8] =
    include_bytes!("../../../specs/005-durable-dispatch/contracts/fault-boundaries-v1.json");
const REQUIRED_BOUNDARY_COUNT: usize = 90;
const REQUIRED_CASE_COUNT: usize = 180;
const COORDINATOR_PROCESS_BOUNDARY_COUNT: usize = 54;
const PROCESS_CHILD_TEST_V1: &str = "dispatch_fault_process_child_v1";
const REOPEN_CHILD_TEST_V1: &str = "dispatch_fault_reopen_child_v1";
const PROCESS_CASE_ROOT_ENV: &str = "HELIXOS_T070_COORDINATOR_CASE_ROOT";
const PROCESS_BOUNDARY_ID_ENV: &str = "HELIXOS_T070_COORDINATOR_BOUNDARY_ID";
const COORDINATOR_ROOT_DIRECTORY: &str = "coordinator-root-v2";
const COORDINATOR_IDENTITY_FILE: &str = "coordinator-root-identity-v2";
const COORDINATOR_DATABASE_FILENAME: &str = "coordinator.sqlite3";
const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);
const STORE_NOW_MONOTONIC_MS: u64 = 100;
const STORE_DEADLINE_MONOTONIC_MS: u64 = 5_000;
const SQLITE_BUSY_WAIT_MS: u64 = 30_000;
const AUTHORITY_PRELIMINARY_MONOTONIC_MS: u64 = 1_000;
const AUTHORITY_FINAL_MONOTONIC_MS: u64 = AUTHORITY_PRELIMINARY_MONOTONIC_MS;
const AUTHORITY_BASE_UTC_MS: u64 = 1_750_000_000_000;
const DESTINATION_ADAPTER_ID: &str = "adapter:t070:no-effect-v1";
const DISPATCH_SIGNER_KEY_ID: &str = "dispatch-key:t070-v1";
const DISPATCH_SIGNING_KEY_BYTES: [u8; 32] = [0x35; 32];
const RECEIPT_SIGNER_KEY_ID: &str = "receipt-key:t070-v1";
const RECEIPT_SIGNING_KEY_BYTES: [u8; 32] = [0x55; 32];
const ADAPTER_ROOT_ID: [u8; 32] = [0xa7; 32];
const ADAPTER_CAPABILITY_DIGEST: [u8; 32] = [0x63; 32];
const BOUNDARY_REACHED_TOKEN: &[u8] = b"boundary-reached";
const PREPARED_ROLLBACK_TOKEN: &[u8] = b"prepared-rollback";
const DISPATCHING_EXACT_TOKEN: &[u8] = b"dispatching-exact";
const EXECUTING_EXACT_TOKEN: &[u8] = b"executing-exact";
const FAILED_RELEASED_TOKEN: &[u8] = b"failed-released";
static PROCESS_CASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
struct RegistryV1 {
    boundary_count: usize,
    required_case_count: usize,
    boundaries: Vec<BoundaryV1>,
}

#[derive(Debug, Deserialize)]
struct BoundaryV1 {
    ordinal: usize,
    id: String,
    category: String,
    owner: String,
    phase: String,
    coverage: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableClassificationV1 {
    NoAuthorityOrExactReadback,
    SameGrantOnly,
    ReceiptRecoveryOrUnknown,
    ConsumedOrExactReadback,
    RefusedDefiniteOrExactReadback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoordinatorRestartStateV1 {
    PreparedWithoutDeliverableGrant,
    DispatchingWithExactGrant,
    DispatchingWithRecoverableReceipt,
    ExecutingWithExactConsumedReceipt,
    FailedWithOneReservationRelease,
}

fn registry_v1() -> RegistryV1 {
    serde_json::from_slice(REGISTRY_BYTES).expect("T060 frozen fault registry must parse")
}

fn coordinator_handoff_readback_boundaries_v1(registry: &RegistryV1) -> Vec<&BoundaryV1> {
    registry
        .boundaries
        .iter()
        .filter(|boundary| {
            (1..=22).contains(&boundary.ordinal) || (40..=71).contains(&boundary.ordinal)
        })
        .collect()
}

fn expected_classification_v1(ordinal: usize) -> DurableClassificationV1 {
    match ordinal {
        1..=16 => DurableClassificationV1::NoAuthorityOrExactReadback,
        17..=21 => DurableClassificationV1::SameGrantOnly,
        22 | 40..=43 => DurableClassificationV1::ReceiptRecoveryOrUnknown,
        44..=52 => DurableClassificationV1::ConsumedOrExactReadback,
        53..=71 => DurableClassificationV1::RefusedDefiniteOrExactReadback,
        other => panic!("T060 coordinator oracle received unsupported boundary {other}"),
    }
}

fn expected_restart_state_v1(ordinal: usize) -> CoordinatorRestartStateV1 {
    match ordinal {
        1..=16 => CoordinatorRestartStateV1::PreparedWithoutDeliverableGrant,
        17..=22 => CoordinatorRestartStateV1::DispatchingWithExactGrant,
        40..=51 | 53..=70 => CoordinatorRestartStateV1::DispatchingWithRecoverableReceipt,
        52 => CoordinatorRestartStateV1::ExecutingWithExactConsumedReceipt,
        71 => CoordinatorRestartStateV1::FailedWithOneReservationRelease,
        other => panic!("T060 coordinator restart oracle received unsupported boundary {other}"),
    }
}

fn expected_restart_token_v1(ordinal: usize) -> &'static [u8] {
    match expected_restart_state_v1(ordinal) {
        CoordinatorRestartStateV1::PreparedWithoutDeliverableGrant => PREPARED_ROLLBACK_TOKEN,
        CoordinatorRestartStateV1::DispatchingWithExactGrant
        | CoordinatorRestartStateV1::DispatchingWithRecoverableReceipt => DISPATCHING_EXACT_TOKEN,
        CoordinatorRestartStateV1::ExecutingWithExactConsumedReceipt => EXECUTING_EXACT_TOKEN,
        CoordinatorRestartStateV1::FailedWithOneReservationRelease => FAILED_RELEASED_TOKEN,
    }
}

struct ProcessCaseRootV1 {
    path: PathBuf,
}

impl ProcessCaseRootV1 {
    fn new_v1() -> Self {
        for _ in 0..64 {
            let sequence = PROCESS_CASE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let candidate = std::env::temp_dir().join(format!(
                "helixos-t070-coordinator-process-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    return Self {
                        path: fs::canonicalize(candidate)
                            .expect("T070 process case root canonicalizes"),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("T070 process case root creation failed: {error}"),
            }
        }
        panic!("T070 process case root allocation exhausted")
    }

    fn environment_v1(&self, boundary_id: &str) -> [ProcessProbeEnvironmentV1; 2] {
        [
            ProcessProbeEnvironmentV1::new(PROCESS_CASE_ROOT_ENV, self.path.as_os_str().to_owned()),
            ProcessProbeEnvironmentV1::new(PROCESS_BOUNDARY_ID_ENV, boundary_id),
        ]
    }
}

impl Drop for ProcessCaseRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ProcessCaseProtocolV1 {
    root: PathBuf,
    boundary_id: String,
    ordinal: usize,
}

impl ProcessCaseProtocolV1 {
    fn for_boundary_v1(case: &ProcessCaseRootV1, boundary: &BoundaryV1) -> Self {
        Self {
            root: case.path.clone(),
            boundary_id: boundary.id.clone(),
            ordinal: boundary.ordinal,
        }
    }

    fn from_environment_v1() -> Option<Self> {
        let root = PathBuf::from(private_process_argument_v1(PROCESS_CASE_ROOT_ENV)?);
        let metadata = fs::symlink_metadata(&root).ok()?;
        assert!(root.is_absolute());
        assert!(!metadata.file_type().is_symlink() && metadata.is_dir());
        let boundary_id = private_process_argument_v1(PROCESS_BOUNDARY_ID_ENV)?
            .into_string()
            .expect("T070 boundary ID is UTF-8");
        let registry = registry_v1();
        let boundary = coordinator_handoff_readback_boundaries_v1(&registry)
            .into_iter()
            .find(|boundary| boundary.id == boundary_id)
            .expect("T070 child accepts only its exact 54-boundary partition");
        Some(Self {
            root,
            boundary_id,
            ordinal: boundary.ordinal,
        })
    }

    fn coordinator_root_v1(&self) -> PathBuf {
        self.root.join(COORDINATOR_ROOT_DIRECTORY)
    }

    fn coordinator_identity_file_v1(&self) -> PathBuf {
        self.root.join(COORDINATOR_IDENTITY_FILE)
    }
}

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
            .expect("T070 exact prepared binding graph reads");
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
                other => panic!("T070 unsupported retained recovery mode {other}"),
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
        .expect("T070 exact prepared dispatch lookup constructs")
    }
}

impl fmt::Debug for PreparedDispatchBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDispatchBindingsV1")
            .finish_non_exhaustive()
    }
}

type CoordinatorStoreV2 =
    SqliteCoordinatorStoreV2<SyntheticCoordinatorClockV1, SyntheticHistoricalPlanKeyResolverV1>;

struct PreparedCoordinatorFixtureV1 {
    root: PathBuf,
    database: PathBuf,
    root_identity: CoordinatorRootIdentityEvidenceV1,
    bindings: PreparedDispatchBindingsV1,
}

impl PreparedCoordinatorFixtureV1 {
    fn prepare_v1(protocol: &ProcessCaseProtocolV1) -> Self {
        let root = protocol.coordinator_root_v1();
        fs::create_dir(&root).expect("T070 coordinator root creates before READY");
        let config =
            CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), SQLITE_BUSY_WAIT_MS)
                .expect("T070 empty coordinator config validates");
        let v1 = SqliteCoordinatorStoreV1::open_or_create(
            config,
            SyntheticCoordinatorClockV1::new(STORE_NOW_MONOTONIC_MS),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            STORE_DEADLINE_MONOTONIC_MS,
        )
        .expect("T070 V1 coordinator initializes");
        let root_identity = v1.root_identity_evidence();
        fs::write(
            protocol.coordinator_identity_file_v1(),
            root_identity.to_attested_bytes(),
        )
        .expect("T070 retained coordinator identity writes before READY");
        drop(v1);

        let root = fs::canonicalize(root).expect("T070 coordinator root canonicalizes");
        let database = root.join(COORDINATOR_DATABASE_FILENAME);
        let preparation = SyntheticPreparationCaseV1::dispatch_compatible_v1(
            SyntheticRecoveryModeV1::Irreversible,
        );
        provision_synthetic_budget_scope_v1(&database, &preparation)
            .expect("T070 PLAN-004 budget scope provisions");
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
        let fixture = Self {
            root,
            database,
            root_identity,
            bindings,
        };
        drop(fixture.open_store_v1());
        fixture
    }

    fn open_store_v1(&self) -> CoordinatorStoreV2 {
        let config = CoordinatorStoreConfigV1::try_new_existing_attested(
            self.root.clone(),
            self.root_identity,
            SQLITE_BUSY_WAIT_MS,
        )
        .expect("T070 existing coordinator config validates");
        SqliteCoordinatorStoreV2::open_existing(
            config,
            SyntheticCoordinatorClockV1::new(STORE_NOW_MONOTONIC_MS),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            STORE_DEADLINE_MONOTONIC_MS,
        )
        .expect("T070 strict V2 coordinator reopens")
    }
}

fn reopen_verified_store_v1(protocol: &ProcessCaseProtocolV1) -> (CoordinatorStoreV2, PathBuf) {
    let identity = fs::read(protocol.coordinator_identity_file_v1())
        .expect("T070 retained coordinator identity reads on reopen");
    let identity: [u8; 32] = identity
        .try_into()
        .expect("T070 retained coordinator identity is exact");
    let root = fs::canonicalize(protocol.coordinator_root_v1())
        .expect("T070 coordinator root canonicalizes on reopen");
    let database = root.join(COORDINATOR_DATABASE_FILENAME);
    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        root,
        CoordinatorRootIdentityEvidenceV1::from_attested_bytes(identity),
        SQLITE_BUSY_WAIT_MS,
    )
    .expect("T070 reopened coordinator config validates");
    let store = SqliteCoordinatorStoreV2::open_existing(
        config,
        SyntheticCoordinatorClockV1::new(STORE_NOW_MONOTONIC_MS),
        SyntheticHistoricalPlanKeyResolverV1::default(),
        STORE_DEADLINE_MONOTONIC_MS,
    )
    .expect("T070 killed coordinator root reopens through strict V2 verification");
    (store, database)
}

impl fmt::Debug for PreparedCoordinatorFixtureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCoordinatorFixtureV1")
            .finish_non_exhaustive()
    }
}

fn install_exact_v2_overlay_v1(database: &Path) {
    let connection = Connection::open(database).expect("T070 V1 database opens for V2 fixture");
    let root_identity: Vec<u8> = connection
        .query_row(
            "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("T070 coordinator identity reads for V2 fixture");
    connection
        .execute_batch(V2_OVERLAY)
        .expect("T070 reviewed V2 overlay installs");
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
        .expect("T070 V2 metadata installs");
    connection
        .execute(
            "INSERT INTO coordinator_v2_migrations (\
                migration_attempt_id, source_schema_digest, source_root_identity, \
                source_summary_digest, verified_backup_digest, overlay_schema_digest, \
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms, \
                tool_identity\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1000, 1000, 'helixos-t070-test-v1')",
            params![
                [0x42_u8; 32].as_slice(),
                embedded_schema_v1_sha256().as_slice(),
                root_identity,
                [0x43_u8; 32].as_slice(),
                [0x44_u8; 32].as_slice(),
                <[u8; 32]>::from(Sha256::digest(V2_OVERLAY.as_bytes())).as_slice(),
            ],
        )
        .expect("T070 V2 migration receipt installs");
}

fn open_read_only_v1(database: &Path) -> Connection {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .expect("T070 strict read-only SQLite observation opens")
}

fn exact_array_v1(bytes: Vec<u8>) -> [u8; 32] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("T070 expected one exact 32-byte binding"))
}

fn safe_u64_v1(value: i64) -> u64 {
    u64::try_from(value).expect("T070 durable generation is nonnegative")
}

fn identifier_v1(value: &str) -> Identifier {
    Identifier::new(value).expect("T070 identifier is valid")
}

fn generation_v1(value: u64) -> Generation {
    Generation::new(value).expect("T070 generation is valid")
}

fn safe_v1(value: u64) -> SafeU64 {
    SafeU64::new(value).expect("T070 safe integer is valid")
}

fn digest_byte_v1(value: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([value; 32])
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
            budget_scope_id: identifier_v1("scope:t070-v1"),
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
            signer_profile_digest: dispatch_key_fingerprint_v1(),
            earliest_authority_deadline_monotonic_ms: generation_v1(STORE_DEADLINE_MONOTONIC_MS),
        })
        .expect("T070 coherent authority view constructs")
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
            hasher.update(b"HELIXOS\0T070-SYNTHETIC-ENTROPY\0V1\0");
            hasher.update(self.0.to_be_bytes());
            hasher.update([match domain {
                DispatchEntropyDomainV1::AttemptIdentity => 1,
                DispatchEntropyDomainV1::GrantIdentity => 2,
                DispatchEntropyDomainV1::OneShotNonce => 3,
                DispatchEntropyDomainV1::TraceIdentity => 4,
            }]);
            hasher.update((block as u64).to_be_bytes());
            let digest = hasher.finalize();
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
        Ok(())
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
            verifying_key: DispatchKeysV1::fixed_v1()
                .signing_key
                .verifying_key()
                .to_bytes(),
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

fn dispatch_key_fingerprint_v1() -> Sha256Digest {
    Sha256Digest::digest(&DispatchGrantResolverV1::fixed_v1().verifying_key)
}

fn dispatch_once_v1(store: &CoordinatorStoreV2, bindings: &PreparedDispatchBindingsV1) {
    let authority = AuthorityFixtureV1 {
        prepared: bindings.clone(),
    };
    match dispatch_prepared_once_v1(
        store,
        bindings.lookup_request_v1(),
        &authority,
        &SeededEntropyV1(70),
        &DispatchKeysV1::fixed_v1(),
        &authority,
    ) {
        DispatchRequestOutcomeV1::Dispatched(_) => {}
        other => panic!("T070 fixture dispatch did not commit: {other:?}"),
    }
}

struct RetainedGrantV1 {
    grant_id: [u8; 32],
    canonical_grant: Vec<u8>,
}

fn load_retained_grant_v1(fixture: &PreparedCoordinatorFixtureV1) -> RetainedGrantV1 {
    let connection = open_read_only_v1(&fixture.database);
    let (grant_id, canonical_grant, canonical_length) = connection
        .query_row(
            "SELECT grant.grant_id, grant.canonical_grant, grant.canonical_grant_length \
             FROM dispatch_grants AS grant \
             JOIN dispatch_records AS record \
               ON record.operation_id = grant.operation_id \
              AND record.grant_id = grant.grant_id \
              AND record.dispatch_attempt_id = grant.dispatch_attempt_id \
             WHERE grant.operation_id = ?1 AND record.effective_state = 'DISPATCHING'",
            [&fixture.bindings.operation_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .expect("T070 exact retained grant reads");
    assert_eq!(
        safe_u64_v1(canonical_length) as usize,
        canonical_grant.len()
    );
    let grant_id = exact_array_v1(grant_id);
    let retained = decode_and_verify_retained_execution_grant_v1(
        &canonical_grant,
        &DispatchGrantResolverV1::fixed_v1(),
    )
    .expect("T070 retained grant authenticates");
    assert_eq!(*retained.claims().grant_id().as_bytes(), grant_id);
    RetainedGrantV1 {
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

fn handoff_and_claim_readback_v1(
    store: &CoordinatorStoreV2,
    fixture: &PreparedCoordinatorFixtureV1,
    retained: &RetainedGrantV1,
) -> (CoordinatorReconciliationLookupV1, u64) {
    assert!(matches!(
        store.handoff_pending_dispatch_v1(
            retained.grant_id,
            STORE_DEADLINE_MONOTONIC_MS,
            &PossibleHandoffTransportV1,
        ),
        CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
    ));
    let lookup = CoordinatorReconciliationLookupV1::try_new(
        fixture.bindings.operation_id.clone(),
        retained.grant_id,
    )
    .expect("T070 exact reconciliation lookup constructs");
    let claim = CoordinatorReadbackSequenceClaimV1::try_new(
        ADAPTER_ROOT_ID,
        fixture.bindings.supervisor_epoch,
    )
    .expect("T070 exact readback sequence claim constructs");
    let generation = match store.claim_or_resume_readback_sequence_v1(
        &lookup,
        &claim,
        STORE_DEADLINE_MONOTONIC_MS,
    ) {
        CoordinatorReadbackSequenceClaimOutcomeV1::Claimed { evidence, .. } => {
            evidence.source_handoff_generation()
        }
        other => panic!("T070 real readback sequence was not claimed: {other:?}"),
    };
    (lookup, generation)
}

fn canonical_receipt_v1(
    retained: &RetainedGrantV1,
    decision: ExecutionReceiptDecisionV1,
) -> Vec<u8> {
    let grant = decode_and_verify_retained_execution_grant_v1(
        &retained.canonical_grant,
        &DispatchGrantResolverV1::fixed_v1(),
    )
    .expect("T070 retained grant authenticates for receipt construction");
    let claims = grant.claims();
    let refused = decision == ExecutionReceiptDecisionV1::RefusedDefinite;
    let protected = ExecutionReceiptProtectedV1::try_new(
        ExecutionReceiptInputV1 {
            receipt_id: Sha256Digest::from_bytes(if refused { [0xd1; 32] } else { [0xc1; 32] }),
            grant_id: claims.grant_id(),
            grant_digest: claims.grant_digest(),
            operation_id: identifier_v1(claims.operation_id()),
            destination_adapter_id: identifier_v1(claims.destination_adapter_id()),
            adapter_root_id: Sha256Digest::from_bytes(ADAPTER_ROOT_ID),
            inbox_generation: generation_v1(1),
            consumption_generation: (!refused).then(|| generation_v1(2)),
            refusal_generation: refused.then(|| generation_v1(2)),
            receipt_generation: generation_v1(3),
            observed_boot_id: identifier_v1(claims.boot_id()),
            observed_supervisor_epoch: safe_v1(claims.supervisor_epoch()),
            epoch_observer_generation: generation_v1(4),
            decision,
            refusal_code: refused.then_some(ExecutionReceiptRefusalCodeV1::AdapterPaused),
            no_consumption_tombstone_digest: refused.then(|| digest_byte_v1(0x91)),
            decided_at_utc_ms: safe_v1(AUTHORITY_BASE_UTC_MS + 1_100),
            decided_at_monotonic_ms: safe_v1(1_100),
            trace_id: identifier_v1("trace:t070:receipt-v1"),
        },
        identifier_v1(RECEIPT_SIGNER_KEY_ID),
    )
    .expect("T070 coherent execution receipt constructs");
    sign_execution_receipt_v1(protected, &ReceiptKeysV1::fixed_v1())
        .and_then(|receipt| receipt.to_canonical_json())
        .expect("T070 coherent execution receipt signs canonically")
}

fn consumed_receipt_lookup_v1(
    fixture: &PreparedCoordinatorFixtureV1,
    retained: &RetainedGrantV1,
) -> (CoordinatorReceiptLookupV1, Vec<u8>) {
    let canonical = canonical_receipt_v1(retained, ExecutionReceiptDecisionV1::Consumed);
    let lookup = CoordinatorReceiptLookupV1::try_new(
        fixture.bindings.operation_id.clone(),
        retained.grant_id,
        ADAPTER_ROOT_ID,
    )
    .expect("T070 exact consumed receipt lookup constructs");
    (lookup, canonical)
}

struct RefusalInputsV1 {
    reconciliation_lookup: CoordinatorReconciliationLookupV1,
    canonical_receipt: Vec<u8>,
    proof: DispatchDefiniteAbsenceProofV1,
    tombstone: DispatchNoConsumptionTombstoneCustodyV1,
}

fn refusal_inputs_v1(
    fixture: &PreparedCoordinatorFixtureV1,
    retained: &RetainedGrantV1,
    reconciliation_lookup: CoordinatorReconciliationLookupV1,
    handoff_generation: u64,
) -> RefusalInputsV1 {
    let canonical_receipt =
        canonical_receipt_v1(retained, ExecutionReceiptDecisionV1::RefusedDefinite);
    let retained_grant = decode_and_verify_retained_execution_grant_v1(
        &retained.canonical_grant,
        &DispatchGrantResolverV1::fixed_v1(),
    )
    .expect("T070 retained grant authenticates for refusal classification");
    let bindings = ReceiptVerificationBindingsV1::from_retained_grant_evidence(
        &retained_grant,
        Sha256Digest::from_bytes(ADAPTER_ROOT_ID),
    );
    let authentic = decode_and_verify_execution_receipt_v1(
        &canonical_receipt,
        &ReceiptKeysV1::fixed_v1(),
        &bindings,
    )
    .expect("T070 signed definite-refusal receipt authenticates");
    let tombstone = classify_no_consumption_receipt_v1(&authentic)
        .expect("T070 authentic refusal yields no-consumption custody");
    let dispatch_attempt_id = exact_array_v1(
        open_read_only_v1(&fixture.database)
            .query_row(
                "SELECT dispatch_attempt_id FROM dispatch_grants \
                 WHERE operation_id = ?1 AND grant_id = ?2",
                params![&fixture.bindings.operation_id, retained.grant_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("T070 exact dispatch-attempt binding reads"),
    );
    let deadline = retained_grant.claims().deadline_monotonic_ms();
    let evidence =
        DispatchDefiniteAbsenceEvidenceV1::try_new(DispatchDefiniteAbsenceEvidenceInputV1 {
            transport_fenced: true,
            transport_quiesced: true,
            adapter_healthy: true,
            expected_adapter_root: ADAPTER_ROOT_ID,
            observed_adapter_root: ADAPTER_ROOT_ID,
            expected_supervisor_epoch: fixture.bindings.supervisor_epoch,
            observed_supervisor_epoch: fixture.bindings.supervisor_epoch,
            expected_delivery_attempt_id: dispatch_attempt_id,
            observed_delivery_attempt_id: dispatch_attempt_id,
            authoritative_handoff_generation: handoff_generation,
            observed_readback_generation: handoff_generation,
            exclusive_deadline_monotonic_ms: deadline,
            observed_monotonic_ms: deadline,
        })
        .expect("T070 exact definite-absence evidence constructs");
    let DispatchDefiniteAbsenceClassificationV1::DefiniteAbsence(proof) =
        classify_definite_absence_v1(evidence)
    else {
        panic!("T070 exact fenced evidence remained possible consumption")
    };
    RefusalInputsV1 {
        reconciliation_lookup,
        canonical_receipt,
        proof,
        tombstone,
    }
}

fn process_barrier_probe_v1(
    child: &ProcessProbeChildV1,
    boundary_id: &str,
) -> DispatchFaultProbeV1 {
    let barrier_child = child.clone();
    DispatchFaultProbeV1::selected_v1(
        boundary_id,
        1,
        FaultInjectionModeV1::ProcessKill,
        move || {
            barrier_child
                .publish_result_v1(BOUNDARY_REACHED_TOKEN)
                .expect("T070 selected production boundary publishes before termination");
            loop {
                thread::park();
            }
        },
    )
    .expect("T070 portable process boundary selection validates")
}

fn select_store_process_barrier_v1(
    store: &mut CoordinatorStoreV2,
    child: &ProcessProbeChildV1,
    boundary_id: &str,
) {
    let barrier_child = child.clone();
    store
        .select_dispatch_fault_for_test_v1(
            boundary_id,
            1,
            FaultInjectionModeV1::ProcessKill,
            move || {
                barrier_child
                    .publish_result_v1(BOUNDARY_REACHED_TOKEN)
                    .expect("T070 coordinator production boundary publishes before termination");
                loop {
                    thread::park();
                }
            },
        )
        .expect("T070 coordinator process boundary selection validates");
}

fn in_process_probe_v1(boundary_id: &str) -> DispatchFaultProbeV1 {
    DispatchFaultProbeV1::selected_v1(boundary_id, 1, FaultInjectionModeV1::InProcess, || {})
        .expect("T070 portable in-process boundary selection validates")
}

fn select_store_in_process_v1(store: &mut CoordinatorStoreV2, boundary_id: &str) {
    store
        .select_dispatch_fault_for_test_v1(boundary_id, 1, FaultInjectionModeV1::InProcess, || {})
        .expect("T070 coordinator in-process boundary selection validates");
}

struct ScriptedReadbackInboxV1 {
    retained_receipt: bool,
}

impl DispatchInboxReadbackV1 for ScriptedReadbackInboxV1 {
    type RetainedState = ();
    type RetainedReceipt = ();

    fn readback_grant_v1(
        &self,
        _grant_binding: &[u8; 32],
    ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        if self.retained_receipt {
            DispatchInboxReadbackOutcomeV1::RetainedReceipt(())
        } else {
            DispatchInboxReadbackOutcomeV1::Absent
        }
    }
}

impl DispatchInboxV1 for ScriptedReadbackInboxV1 {
    type RetainedState = ();
    type RetainedReceipt = ();

    fn receive_exact_grant_v1(
        &self,
        _exact_signed_grant_bytes: &[u8],
    ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        DispatchInboxReceiveOutcomeV1::DurablyReceived(())
    }
}

struct OneShotReadbackGateV1;

impl DispatchAutomaticReadbackGateV1 for OneShotReadbackGateV1 {
    fn try_begin_automatic_readback_once_v1(&self, _delivery_attempt_generation: u64) -> bool {
        true
    }
}

struct ImmediateReadbackScheduleV1;

impl DispatchAutomaticReadbackScheduleV1 for ImmediateReadbackScheduleV1 {
    fn wait_until_readback_offset_v1(
        &mut self,
        requested_monotonic_ms: u64,
        _effective_end_monotonic_ms: u64,
    ) -> DispatchReadbackWaitOutcomeV1 {
        DispatchReadbackWaitOutcomeV1::ObservedAt(requested_monotonic_ms)
    }
}

fn selected_boundary_was_not_reached_v1() -> ! {
    std::process::exit(91)
}

#[test]
#[ignore = "private synchronized process-kill workflow child"]
fn dispatch_fault_process_child_v1() {
    let Some(child) =
        ProcessProbeChildV1::from_environment_v1().expect("T070 process child protocol validates")
    else {
        return;
    };
    assert_eq!(child.index_v1(), 0);
    let protocol = ProcessCaseProtocolV1::from_environment_v1()
        .expect("T070 process child receives an exact private case");
    let fixture = PreparedCoordinatorFixtureV1::prepare_v1(&protocol);

    match protocol.ordinal {
        1..=17 => {
            let mut store = fixture.open_store_v1();
            let portable = if (2..=7).contains(&protocol.ordinal) {
                process_barrier_probe_v1(&child, &protocol.boundary_id)
            } else {
                select_store_process_barrier_v1(&mut store, &child, &protocol.boundary_id);
                DispatchFaultProbeV1::disabled_v1()
            };
            let authority = AuthorityFixtureV1 {
                prepared: fixture.bindings.clone(),
            };
            child
                .publish_ready_and_wait_for_go_v1()
                .expect("T070 dispatch child synchronizes before production workflow");
            let _ = dispatch_prepared_once_with_fault_probe_v1(
                &store,
                fixture.bindings.lookup_request_v1(),
                &authority,
                &SeededEntropyV1(70),
                &DispatchKeysV1::fixed_v1(),
                &authority,
                &portable,
            );
        }
        18..=22 => {
            let mut store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            select_store_process_barrier_v1(&mut store, &child, &protocol.boundary_id);
            child
                .publish_ready_and_wait_for_go_v1()
                .expect("T070 handoff child synchronizes before production workflow");
            let _ = store.handoff_pending_dispatch_v1(
                retained.grant_id,
                STORE_DEADLINE_MONOTONIC_MS,
                &PossibleHandoffTransportV1,
            );
        }
        40..=43 => {
            let store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            let (_, delivery_generation) =
                handoff_and_claim_readback_v1(&store, &fixture, &retained);
            let portable = process_barrier_probe_v1(&child, &protocol.boundary_id);
            child
                .publish_ready_and_wait_for_go_v1()
                .expect("T070 readback child synchronizes before production workflow");
            if protocol.ordinal == 40 {
                let inbox = ScriptedReadbackInboxV1 {
                    retained_receipt: false,
                };
                let _ = recover_lost_acknowledgement_with_fault_probe_v1(
                    &inbox,
                    &retained.grant_id,
                    &retained.canonical_grant,
                    STORE_DEADLINE_MONOTONIC_MS,
                    1_100,
                    &portable,
                );
            } else {
                let inbox = ScriptedReadbackInboxV1 {
                    retained_receipt: protocol.ordinal == 43,
                };
                let mut schedule = ImmediateReadbackScheduleV1;
                let _ = run_automatic_readback_once_with_fault_probe_v1(
                    &inbox,
                    &OneShotReadbackGateV1,
                    &mut schedule,
                    delivery_generation,
                    DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
                    &retained.grant_id,
                    1_000,
                    STORE_DEADLINE_MONOTONIC_MS,
                    STORE_DEADLINE_MONOTONIC_MS,
                    &portable,
                );
            }
        }
        44..=52 => {
            let mut store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            let _ = handoff_and_claim_readback_v1(&store, &fixture, &retained);
            let (lookup, canonical_receipt) = consumed_receipt_lookup_v1(&fixture, &retained);
            select_store_process_barrier_v1(&mut store, &child, &protocol.boundary_id);
            child
                .publish_ready_and_wait_for_go_v1()
                .expect("T070 consumed-closure child synchronizes before production workflow");
            let _ = store.commit_execution_receipt_v1(
                lookup,
                &canonical_receipt,
                STORE_DEADLINE_MONOTONIC_MS,
                &CoordinatorReceiptKeysV1,
            );
        }
        53..=71 => {
            let mut store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            let (lookup, handoff_generation) =
                handoff_and_claim_readback_v1(&store, &fixture, &retained);
            let refusal = refusal_inputs_v1(&fixture, &retained, lookup, handoff_generation);
            select_store_process_barrier_v1(&mut store, &child, &protocol.boundary_id);
            child
                .publish_ready_and_wait_for_go_v1()
                .expect("T070 refusal-closure child synchronizes before production workflow");
            let _ = store.commit_definite_refusal_v1(
                &refusal.reconciliation_lookup,
                &refusal.canonical_receipt,
                STORE_DEADLINE_MONOTONIC_MS,
                &CoordinatorReceiptKeysV1,
                &refusal.proof,
                &refusal.tombstone,
            );
        }
        _ => unreachable!("private protocol accepts only the coordinator partition"),
    }
    selected_boundary_was_not_reached_v1();
}

fn run_coordinator_in_process_case_v1(boundary: &BoundaryV1) {
    let case = ProcessCaseRootV1::new_v1();
    let protocol = ProcessCaseProtocolV1::for_boundary_v1(&case, boundary);
    let fixture = PreparedCoordinatorFixtureV1::prepare_v1(&protocol);

    match protocol.ordinal {
        1..=17 => {
            let mut store = fixture.open_store_v1();
            let portable = if (2..=7).contains(&protocol.ordinal) {
                in_process_probe_v1(&protocol.boundary_id)
            } else {
                select_store_in_process_v1(&mut store, &protocol.boundary_id);
                DispatchFaultProbeV1::disabled_v1()
            };
            let authority = AuthorityFixtureV1 {
                prepared: fixture.bindings.clone(),
            };
            let _ = dispatch_prepared_once_with_fault_probe_v1(
                &store,
                fixture.bindings.lookup_request_v1(),
                &authority,
                &SeededEntropyV1(70),
                &DispatchKeysV1::fixed_v1(),
                &authority,
                &portable,
            );
            let injected = if (2..=7).contains(&protocol.ordinal) {
                portable.injected_v1()
            } else {
                store.dispatch_fault_probe_injected_for_test_v1()
            };
            assert!(
                injected,
                "{} must inject once in its real dispatch workflow",
                protocol.boundary_id,
            );
        }
        18..=22 => {
            let mut store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            select_store_in_process_v1(&mut store, &protocol.boundary_id);
            let _ = store.handoff_pending_dispatch_v1(
                retained.grant_id,
                STORE_DEADLINE_MONOTONIC_MS,
                &PossibleHandoffTransportV1,
            );
            assert!(
                store.dispatch_fault_probe_injected_for_test_v1(),
                "{} must inject once in its real handoff workflow",
                protocol.boundary_id,
            );
        }
        40..=43 => {
            let store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            let (_, delivery_generation) =
                handoff_and_claim_readback_v1(&store, &fixture, &retained);
            let portable = in_process_probe_v1(&protocol.boundary_id);
            if protocol.ordinal == 40 {
                let inbox = ScriptedReadbackInboxV1 {
                    retained_receipt: false,
                };
                let _ = recover_lost_acknowledgement_with_fault_probe_v1(
                    &inbox,
                    &retained.grant_id,
                    &retained.canonical_grant,
                    STORE_DEADLINE_MONOTONIC_MS,
                    1_100,
                    &portable,
                );
            } else {
                let inbox = ScriptedReadbackInboxV1 {
                    retained_receipt: protocol.ordinal == 43,
                };
                let mut schedule = ImmediateReadbackScheduleV1;
                let _ = run_automatic_readback_once_with_fault_probe_v1(
                    &inbox,
                    &OneShotReadbackGateV1,
                    &mut schedule,
                    delivery_generation,
                    DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
                    &retained.grant_id,
                    1_000,
                    STORE_DEADLINE_MONOTONIC_MS,
                    STORE_DEADLINE_MONOTONIC_MS,
                    &portable,
                );
            }
            assert!(
                portable.injected_v1(),
                "{} must inject once in its real readback workflow",
                protocol.boundary_id,
            );
        }
        44..=52 => {
            let mut store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            let _ = handoff_and_claim_readback_v1(&store, &fixture, &retained);
            let (lookup, canonical_receipt) = consumed_receipt_lookup_v1(&fixture, &retained);
            select_store_in_process_v1(&mut store, &protocol.boundary_id);
            let _ = store.commit_execution_receipt_v1(
                lookup,
                &canonical_receipt,
                STORE_DEADLINE_MONOTONIC_MS,
                &CoordinatorReceiptKeysV1,
            );
            assert!(
                store.dispatch_fault_probe_injected_for_test_v1(),
                "{} must inject once in its real consumed-closure workflow",
                protocol.boundary_id,
            );
        }
        53..=71 => {
            let mut store = fixture.open_store_v1();
            dispatch_once_v1(&store, &fixture.bindings);
            let retained = load_retained_grant_v1(&fixture);
            let (lookup, handoff_generation) =
                handoff_and_claim_readback_v1(&store, &fixture, &retained);
            let refusal = refusal_inputs_v1(&fixture, &retained, lookup, handoff_generation);
            select_store_in_process_v1(&mut store, &protocol.boundary_id);
            let _ = store.commit_definite_refusal_v1(
                &refusal.reconciliation_lookup,
                &refusal.canonical_receipt,
                STORE_DEADLINE_MONOTONIC_MS,
                &CoordinatorReceiptKeysV1,
                &refusal.proof,
                &refusal.tombstone,
            );
            assert!(
                store.dispatch_fault_probe_injected_for_test_v1(),
                "{} must inject once in its real refusal-closure workflow",
                protocol.boundary_id,
            );
        }
        _ => unreachable!("in-process protocol accepts only the coordinator partition"),
    }

    assert_eq!(
        classify_reopened_authority_v1(&protocol),
        expected_restart_token_v1(protocol.ordinal),
        "{} must satisfy its closed restart-state oracle after in-process injection",
        protocol.boundary_id,
    );
}

fn count_where_v1(connection: &Connection, table: &str, predicate: &str) -> u64 {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE {predicate}");
    safe_u64_v1(
        connection
            .query_row(&sql, [], |row| row.get::<_, i64>(0))
            .expect("T070 authoritative restart count reads"),
    )
}

fn assert_preparing_hold_v1(connection: &Connection) {
    assert_eq!(
        count_where_v1(
            connection,
            "prepared_operations",
            "operation_state = 'PREPARING'"
        ),
        1,
    );
    assert_eq!(
        count_where_v1(
            connection,
            "budget_reservations",
            "reservation_state = 'HELD' AND released_generation IS NULL",
        ),
        1,
    );
    assert_eq!(
        count_where_v1(
            connection,
            "budget_reservations",
            "reservation_state = 'RELEASED'",
        ),
        0,
    );
}

fn assert_dispatching_authority_v1(connection: &Connection) {
    assert_preparing_hold_v1(connection);
    assert_eq!(count_where_v1(connection, "dispatch_grants", "1 = 1"), 1);
    assert_eq!(
        count_where_v1(
            connection,
            "dispatch_records",
            "effective_state = 'DISPATCHING' AND receipt_id IS NULL",
        ),
        1,
    );
    assert_eq!(count_where_v1(connection, "dispatch_receipts", "1 = 1"), 0);
}

fn classify_reopened_authority_v1(protocol: &ProcessCaseProtocolV1) -> &'static [u8] {
    let (store, database) = reopen_verified_store_v1(protocol);
    drop(store);
    let connection = open_read_only_v1(&database);
    match expected_restart_state_v1(protocol.ordinal) {
        CoordinatorRestartStateV1::PreparedWithoutDeliverableGrant => {
            assert_preparing_hold_v1(&connection);
            for table in [
                "dispatch_comparisons",
                "dispatch_grants",
                "dispatch_records",
                "dispatch_outbox",
                "dispatch_delivery_attempts",
                "dispatch_receipts",
                "dispatch_reconciliations",
                "dispatch_definite_refusal_guards",
            ] {
                assert_eq!(count_where_v1(&connection, table, "1 = 1"), 0);
            }
            PREPARED_ROLLBACK_TOKEN
        }
        CoordinatorRestartStateV1::DispatchingWithExactGrant => {
            assert_dispatching_authority_v1(&connection);
            assert_eq!(count_where_v1(&connection, "dispatch_outbox", "1 = 1"), 1);
            let (state, attempts) = if protocol.ordinal <= 19 {
                ("delivery_state = 'PENDING'", 0)
            } else {
                ("delivery_state = 'HANDED_OFF'", 1)
            };
            assert_eq!(count_where_v1(&connection, "dispatch_outbox", state), 1);
            assert_eq!(
                count_where_v1(&connection, "dispatch_delivery_attempts", "1 = 1"),
                attempts,
            );
            if protocol.ordinal >= 20 {
                assert_eq!(
                    count_where_v1(
                        &connection,
                        "dispatch_delivery_attempts",
                        "classification = 'POSSIBLE_HANDOFF' \
                         AND adapter_root_digest IS NULL \
                         AND adapter_epoch IS NULL AND readback_generation IS NULL",
                    ),
                    1,
                );
            }
            DISPATCHING_EXACT_TOKEN
        }
        CoordinatorRestartStateV1::DispatchingWithRecoverableReceipt => {
            assert_dispatching_authority_v1(&connection);
            assert_eq!(
                count_where_v1(
                    &connection,
                    "dispatch_outbox",
                    "delivery_state = 'UNKNOWN' AND receipt_id IS NULL",
                ),
                1,
            );
            assert_eq!(
                count_where_v1(&connection, "dispatch_delivery_attempts", "1 = 1"),
                2,
            );
            assert_eq!(
                count_where_v1(
                    &connection,
                    "dispatch_delivery_attempts",
                    "classification = 'POSSIBLE_HANDOFF' \
                     AND adapter_root_digest IS NOT NULL AND readback_generation IS NOT NULL",
                ),
                1,
            );
            assert_eq!(
                count_where_v1(&connection, "dispatch_reconciliations", "1 = 1"),
                0,
            );
            DISPATCHING_EXACT_TOKEN
        }
        CoordinatorRestartStateV1::ExecutingWithExactConsumedReceipt => {
            assert_preparing_hold_v1(&connection);
            assert_eq!(count_where_v1(&connection, "dispatch_grants", "1 = 1"), 1);
            assert_eq!(
                count_where_v1(
                    &connection,
                    "dispatch_records",
                    "effective_state = 'EXECUTING' AND receipt_decision = 'CONSUMED'",
                ),
                1,
            );
            assert_eq!(
                count_where_v1(&connection, "dispatch_receipts", "decision = 'CONSUMED'",),
                1,
            );
            assert_eq!(
                count_where_v1(
                    &connection,
                    "dispatch_outbox",
                    "delivery_state = 'ACKNOWLEDGED' AND receipt_decision = 'CONSUMED'",
                ),
                1,
            );
            EXECUTING_EXACT_TOKEN
        }
        CoordinatorRestartStateV1::FailedWithOneReservationRelease => {
            assert_eq!(
                count_where_v1(
                    &connection,
                    "prepared_operations",
                    "operation_state = 'FAILED' AND failed_generation IS NOT NULL",
                ),
                1,
            );
            assert_eq!(
                count_where_v1(
                    &connection,
                    "budget_reservations",
                    "reservation_state = 'RELEASED' AND released_generation IS NOT NULL",
                ),
                1,
            );
            assert_eq!(
                count_where_v1(
                    &connection,
                    "budget_reservations",
                    "reservation_state = 'HELD'",
                ),
                0,
            );
            assert_eq!(
                count_where_v1(
                    &connection,
                    "dispatch_records",
                    "effective_state = 'FAILED' \
                     AND receipt_decision = 'REFUSED_DEFINITE'",
                ),
                1,
            );
            assert_eq!(
                count_where_v1(
                    &connection,
                    "dispatch_receipts",
                    "decision = 'REFUSED_DEFINITE'",
                ),
                1,
            );
            assert_eq!(
                count_where_v1(&connection, "dispatch_definite_refusal_guards", "1 = 1"),
                1,
            );
            assert_eq!(
                count_where_v1(
                    &connection,
                    "dispatch_outbox",
                    "delivery_state = 'QUIESCED' \
                     AND receipt_decision = 'REFUSED_DEFINITE'",
                ),
                1,
            );
            FAILED_RELEASED_TOKEN
        }
    }
}

#[test]
#[ignore = "private authoritative coordinator reopen child"]
fn dispatch_fault_reopen_child_v1() {
    let Some(child) =
        ProcessProbeChildV1::from_environment_v1().expect("T070 reopen child protocol validates")
    else {
        return;
    };
    assert_eq!(child.index_v1(), 0);
    let protocol = ProcessCaseProtocolV1::from_environment_v1()
        .expect("T070 reopen child receives an exact private case");
    child
        .publish_ready_and_wait_for_go_v1()
        .expect("T070 reopen child synchronizes before authoritative verification");
    child
        .publish_result_v1(classify_reopened_authority_v1(&protocol))
        .expect("T070 reopen child publishes only its closed restart classification");
}

#[test]
fn frozen_registry_exposes_every_coordinator_handoff_and_readback_fault_once() {
    let registry = registry_v1();
    assert_eq!(registry.boundary_count, REQUIRED_BOUNDARY_COUNT);
    assert_eq!(registry.required_case_count, REQUIRED_CASE_COUNT);

    let selected = coordinator_handoff_readback_boundaries_v1(&registry);
    assert_eq!(selected.len(), COORDINATOR_PROCESS_BOUNDARY_COUNT);
    let ids = selected
        .iter()
        .map(|boundary| boundary.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), selected.len(), "fault IDs are create-only");

    for boundary in selected {
        assert!(!boundary.category.is_empty());
        assert_eq!(
            boundary.coverage,
            ["in-process", "process-kill"],
            "{} must declare both T060 modes",
            boundary.id
        );
        assert_eq!(
            boundary.id,
            format!("PLAN005-FB-{:03}", boundary.ordinal),
            "fault ID and ordinal must remain byte-correlated"
        );
        let _ = expected_classification_v1(boundary.ordinal);
    }
}

#[test]
fn every_required_transaction_and_ambiguity_phase_is_represented() {
    let registry = registry_v1();
    let selected = coordinator_handoff_readback_boundaries_v1(&registry);
    let phases = selected
        .iter()
        .fold(BTreeMap::<&str, usize>::new(), |mut counts, boundary| {
            *counts.entry(boundary.phase.as_str()).or_default() += 1;
            counts
        });

    for required in [
        "lookup",
        "grant-signing",
        "guards",
        "dispatch-transaction",
        "delivery-handoff",
        "bounded-readback",
        "receipt-verify",
        "consumed-closure",
        "refused-definite-closure",
    ] {
        assert!(
            phases.contains_key(required),
            "T060 registry omits required phase {required}"
        );
    }

    assert!(
        selected
            .iter()
            .any(|boundary| boundary.owner == "helix-plan-dispatch"),
        "portable handoff/readback ownership must be represented"
    );
    assert!(
        selected
            .iter()
            .any(|boundary| boundary.owner == "helix-coordinator-sqlite"),
        "coordinator transaction ownership must be represented"
    );
}

#[test]
fn transaction_restart_states_distinguish_rollback_from_post_commit_durability() {
    let registry = registry_v1();
    for boundary in coordinator_handoff_readback_boundaries_v1(&registry) {
        let state = expected_restart_state_v1(boundary.ordinal);
        match boundary.ordinal {
            8..=16 => assert_eq!(
                state,
                CoordinatorRestartStateV1::PreparedWithoutDeliverableGrant,
                "{} is before the initial dispatch commit",
                boundary.id
            ),
            17 => assert_eq!(
                state,
                CoordinatorRestartStateV1::DispatchingWithExactGrant,
                "dispatch commit returned before {}",
                boundary.id
            ),
            44..=51 => assert_eq!(
                state,
                CoordinatorRestartStateV1::DispatchingWithRecoverableReceipt,
                "{} is before the consumed-closure commit",
                boundary.id
            ),
            52 => assert_eq!(
                state,
                CoordinatorRestartStateV1::ExecutingWithExactConsumedReceipt,
                "{} is after the consumed-closure commit",
                boundary.id
            ),
            53..=70 => assert_eq!(
                state,
                CoordinatorRestartStateV1::DispatchingWithRecoverableReceipt,
                "{} is before the all-or-none definite-refusal closure commit",
                boundary.id
            ),
            71 => assert_eq!(
                state,
                CoordinatorRestartStateV1::FailedWithOneReservationRelease,
                "{} is the only post-commit definite-refusal boundary",
                boundary.id
            ),
            _ => {}
        }
    }

    assert_eq!(
        (44..=51)
            .filter(|ordinal| matches!(
                expected_restart_state_v1(*ordinal),
                CoordinatorRestartStateV1::ExecutingWithExactConsumedReceipt
            ))
            .count(),
        0,
        "no pre-commit consumed-closure fault may report EXECUTING"
    );
    assert_eq!(
        (53..=70)
            .filter(|ordinal| matches!(
                expected_restart_state_v1(*ordinal),
                CoordinatorRestartStateV1::FailedWithOneReservationRelease
            ))
            .count(),
        0,
        "no pre-commit refusal fault may report release"
    );
}

#[test]
fn production_probe_selection_crosses_real_transactions_handoff_and_readback() {
    let coordinator = required_source_v1(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/dispatch_fault.rs"),
        "T063 coordinator dispatch fault driver",
    );
    let portable = required_source_v1(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../helix-plan-dispatch/src/test_fault.rs"),
        "T063 portable closed fault selector",
    );
    let combined = format!("{coordinator}\n{portable}");

    for required in [
        "PLAN005-FB-001",
        "PLAN005-FB-022",
        "PLAN005-FB-043",
        "PLAN005-FB-052",
        "PLAN005-FB-071",
        "FaultProbeV1",
        "select",
        "reach",
        "dispatch",
        "handoff",
        "readback",
    ] {
        assert!(
            combined.contains(required),
            "T060 RED: real coordinator fault path omits {required}"
        );
    }
    for forbidden in [
        "pub struct FaultProbe",
        "pub enum DispatchFault",
        "static mut",
    ] {
        assert!(
            !combined.contains(forbidden),
            "T060 test-only fault authority leaks through {forbidden}"
        );
    }
}

#[test]
fn every_selected_boundary_has_an_explicit_non_registry_checkpoint_call_site() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = [
        manifest.join("src/dispatch.rs"),
        manifest.join("src/dispatch_outbox.rs"),
        manifest.join("src/dispatch_readback.rs"),
        manifest.join("src/dispatch_receipt.rs"),
        manifest.join("src/dispatch_reconciliation.rs"),
        manifest.join("src/dispatch_fault.rs"),
        manifest.join("../helix-plan-dispatch/src/coordinator.rs"),
        manifest.join("../helix-plan-dispatch/src/transport.rs"),
        manifest.join("../helix-plan-dispatch/src/inbox.rs"),
        manifest.join("../helix-plan-dispatch/src/reconciliation.rs"),
    ]
    .into_iter()
    .map(|path| required_source_v1(path, "T060 explicit production fault checkpoint"))
    .collect::<Vec<_>>()
    .join("\n");

    let registry = registry_v1();
    let selected = coordinator_handoff_readback_boundaries_v1(&registry);
    assert_eq!(selected.len(), COORDINATOR_PROCESS_BOUNDARY_COUNT);
    for boundary in selected {
        let variant = format!("FaultBoundaryV1::Plan005Fb{:03}", boundary.ordinal);
        assert!(
            sources.contains(&variant),
            "T060 RED: {} lacks an explicit real-path checkpoint {variant}",
            boundary.id
        );
    }
}

#[test]
fn direct_acknowledged_receipt_faults_preserve_one_exact_append_only_history() {
    let registry = registry_v1();
    for boundary in coordinator_handoff_readback_boundaries_v1(&registry)
        .into_iter()
        .filter(|boundary| (44..=52).contains(&boundary.ordinal))
    {
        let case = ProcessCaseRootV1::new_v1();
        let protocol = ProcessCaseProtocolV1::for_boundary_v1(&case, boundary);
        let fixture = PreparedCoordinatorFixtureV1::prepare_v1(&protocol);
        let mut store = fixture.open_store_v1();
        dispatch_once_v1(&store, &fixture.bindings);
        let retained = load_retained_grant_v1(&fixture);
        assert!(matches!(
            store.handoff_pending_dispatch_v1(
                retained.grant_id,
                STORE_DEADLINE_MONOTONIC_MS,
                &PossibleHandoffTransportV1,
            ),
            CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
        ));
        let (lookup, canonical_receipt) = consumed_receipt_lookup_v1(&fixture, &retained);
        select_store_in_process_v1(&mut store, &boundary.id);
        let first = store.commit_execution_receipt_v1(
            lookup,
            &canonical_receipt,
            STORE_DEADLINE_MONOTONIC_MS,
            &CoordinatorReceiptKeysV1,
        );
        assert!(
            store.dispatch_fault_probe_injected_for_test_v1(),
            "{} must inject in the direct acknowledged closure",
            boundary.id
        );
        if boundary.ordinal == 52 {
            assert!(matches!(
                first,
                CoordinatorReceiptCommitOutcomeV1::Uncertain(_)
            ));
        } else {
            assert!(!matches!(
                first,
                CoordinatorReceiptCommitOutcomeV1::Committed(_)
                    | CoordinatorReceiptCommitOutcomeV1::PriorExact(_)
                    | CoordinatorReceiptCommitOutcomeV1::Uncertain(_)
            ));
        }
        drop(store);

        let reopened = fixture.open_store_v1();
        let before_retry = open_read_only_v1(&fixture.database);
        if boundary.ordinal <= 51 {
            assert_dispatching_authority_v1(&before_retry);
            assert_eq!(
                count_where_v1(
                    &before_retry,
                    "dispatch_outbox",
                    "delivery_state = 'HANDED_OFF' AND receipt_id IS NULL"
                ),
                1
            );
            assert_eq!(
                count_where_v1(
                    &before_retry,
                    "dispatch_delivery_attempts",
                    "attempt_number = 1 AND classification = 'POSSIBLE_HANDOFF' \
                     AND adapter_root_digest IS NULL AND adapter_epoch IS NULL \
                     AND readback_generation IS NULL"
                ),
                1
            );
            assert_eq!(
                count_where_v1(&before_retry, "dispatch_delivery_attempts", "1 = 1"),
                1
            );
        } else {
            assert_eq!(
                count_where_v1(
                    &before_retry,
                    "dispatch_records",
                    "effective_state = 'EXECUTING' AND receipt_decision = 'CONSUMED'"
                ),
                1
            );
        }
        drop(before_retry);

        let (retry_lookup, _) = consumed_receipt_lookup_v1(&fixture, &retained);
        let retry = reopened.commit_execution_receipt_v1(
            retry_lookup,
            &canonical_receipt,
            STORE_DEADLINE_MONOTONIC_MS,
            &CoordinatorReceiptKeysV1,
        );
        if boundary.ordinal <= 51 {
            assert!(matches!(
                retry,
                CoordinatorReceiptCommitOutcomeV1::Committed(_)
            ));
        } else {
            assert!(matches!(
                retry,
                CoordinatorReceiptCommitOutcomeV1::PriorExact(_)
            ));
        }
        drop(reopened);

        let final_projection = open_read_only_v1(&fixture.database);
        assert_eq!(
            count_where_v1(
                &final_projection,
                "dispatch_delivery_attempts",
                "attempt_number = 1 AND classification = 'POSSIBLE_HANDOFF' \
                 AND adapter_root_digest IS NULL AND adapter_epoch IS NULL \
                 AND readback_generation IS NULL"
            ),
            1
        );
        assert_eq!(
            count_where_v1(
                &final_projection,
                "dispatch_delivery_attempts",
                "attempt_number = 2 AND classification = 'ACKNOWLEDGED' \
                 AND adapter_root_digest IS NOT NULL AND adapter_epoch IS NOT NULL \
                 AND readback_generation IS NULL"
            ),
            1
        );
        assert_eq!(
            count_where_v1(&final_projection, "dispatch_delivery_attempts", "1 = 1"),
            2
        );
        assert_eq!(
            count_where_v1(
                &final_projection,
                "dispatch_outbox",
                "delivery_state = 'ACKNOWLEDGED' AND receipt_decision = 'CONSUMED'"
            ),
            1
        );
    }
}

#[test]
#[ignore = "release in-process gate: drive every selected fault through the real workflow and authoritative reopen"]
fn release_in_process_coordinator_handoff_and_readback_matrix() {
    let registry = registry_v1();
    let selected = coordinator_handoff_readback_boundaries_v1(&registry);
    assert_eq!(selected.len(), COORDINATOR_PROCESS_BOUNDARY_COUNT);
    assert!(selected.iter().all(|boundary| boundary.ordinal != 39));
    assert_eq!(
        selected
            .iter()
            .map(|boundary| boundary.id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        COORDINATOR_PROCESS_BOUNDARY_COUNT,
    );

    for boundary in selected {
        run_coordinator_in_process_case_v1(boundary);
    }
}

#[test]
#[ignore = "release process-kill gate: drive every selected fault through the real child workflow and authoritative reopen"]
fn release_process_kill_coordinator_handoff_and_readback_matrix() {
    let registry = registry_v1();
    let selected = coordinator_handoff_readback_boundaries_v1(&registry);
    assert_eq!(selected.len(), COORDINATOR_PROCESS_BOUNDARY_COUNT);
    assert!(selected.iter().all(|boundary| boundary.ordinal != 39));

    for boundary in selected {
        let case = ProcessCaseRootV1::new_v1();
        let environment = case.environment_v1(&boundary.id);
        let mut fault =
            SynchronizedProcessProbeV1::spawn_v1(PROCESS_CHILD_TEST_V1, 1, &environment)
                .expect("T070 production fault child spawns");
        assert_eq!(
            fault
                .execute_until_result_and_terminate_v1()
                .unwrap_or_else(|error| {
                    panic!(
                        "T070 production fault child {} failed before its exact boundary: {error:?}",
                        boundary.id
                    )
                }),
            [BOUNDARY_REACHED_TOKEN.to_vec()],
            "{} must publish only after its real production checkpoint",
            boundary.id,
        );

        let mut reopen =
            SynchronizedProcessProbeV1::spawn_v1(REOPEN_CHILD_TEST_V1, 1, &environment)
                .expect("T070 authoritative reopen child spawns");
        let expected = expected_restart_token_v1(boundary.ordinal);
        assert_eq!(
            reopen.execute_v1().unwrap_or_else(|error| {
                panic!(
                    "T070 authoritative reopen child {} failed: {error:?}",
                    boundary.id
                )
            }),
            [expected.to_vec()],
            "{} must satisfy its closed restart-state oracle",
            boundary.id,
        );
    }
}

fn required_source_v1(path: PathBuf, contract: &str) -> String {
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T060 RED: missing production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments_v1(&source)
}

fn source_without_comments_v1(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut block_depth = 0_u64;
    for line in source.lines() {
        let mut remaining = line;
        loop {
            if block_depth > 0 {
                let Some(end) = remaining.find("*/") else {
                    break;
                };
                block_depth -= 1;
                remaining = &remaining[end + 2..];
                continue;
            }
            let line_comment = remaining.find("//");
            let block_comment = remaining.find("/*");
            match (line_comment, block_comment) {
                (Some(line_start), Some(block_start)) if block_start < line_start => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (Some(line_start), _) => {
                    output.push_str(&remaining[..line_start]);
                    break;
                }
                (None, Some(block_start)) => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (None, None) => {
                    output.push_str(remaining);
                    break;
                }
            }
        }
        output.push('\n');
    }
    assert_eq!(block_depth, 0, "T060 source comments are balanced");
    output
}
