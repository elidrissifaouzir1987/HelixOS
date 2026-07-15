//! Feature-gated, no-effect SQLite dispatch corpus gate for PLAN-005 T080.
//!
//! The portable corpus executable owns fixture parsing and stable output. This module is
//! deliberately narrower: it drives the ordinary coordinator and adapter production paths
//! against independent SQLite roots, closes and strictly reopens both roots, and returns only
//! payload-free static failure labels.

use crate::dispatch_receipt::{
    CoordinatorReceiptCommitOutcomeV1, CoordinatorReceiptEffectiveStateV1,
    CoordinatorReceiptLookupV1,
};
use crate::dispatch_reconciliation::{
    CoordinatorReadbackExhaustionV1, CoordinatorReadbackSequenceClaimOutcomeV1,
    CoordinatorReadbackSequenceClaimV1, CoordinatorReconciliationLookupV1,
    CoordinatorReconciliationOutcomeV1, CoordinatorReconciliationStateV1,
};
use crate::dispatch_schema::{DispatchMigrationRequestV2, SqliteCoordinatorStoreV2};
use crate::{
    maintenance, CoordinatorClockUnavailableV1, CoordinatorDispatchHandoffOutcomeV1,
    CoordinatorMonotonicClockV1, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
    SqliteCoordinatorStoreV1, T080ProductionCorpusEvidenceV1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AtomicityV1, BudgetInputV1, ContractError,
    Ed25519KeyResolver, Ed25519Signer, FilePreconditionInputV1, Nonce128, PlanInputV1,
    RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, ResourceRefV1,
    Result as PlanContractResultV1, RiskLevelV1, Sha256Digest as PlanSha256Digest,
};
use helix_dispatch_contracts::{
    ContractError as DispatchContractErrorV1, Generation, GrantKeyResolver, GrantSigner,
    GrantVerificationKeyV1, Identifier, ReceiptKeyResolver, ReceiptSigner,
    ReceiptVerificationKeyV1, RecoveryModeV1, Result as DispatchContractResultV1, SafeU64,
    Sha256Digest,
};
use helix_dispatch_inbox_sqlite::{
    AdapterClockObservationV1, AdapterClockV1, AdapterConsumptionAdmissionObservationV1,
    AdapterConsumptionAdmissionObserverV1, AdapterInboxConsumeOutcomeV1,
    AdapterInboxInitializationV1, AdapterInboxProfileV1, AdapterInboxReadbackErrorV1,
    AdapterInboxReadbackOutcomeV1, AdapterInboxReceiveOutcomeV1, AdapterInboxRetainedStateV1,
    AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1, AdapterReceiptEntropyDomainV1,
    AdapterReceiptEntropyErrorV1, AdapterReceiptEntropyV1, AdapterReceiptSigningProfileV1,
    AdapterTimeSampleV1, EpochObservationV1, SqliteDispatchInboxStoreV1,
    SupervisorEpochObservationV1, SupervisorEpochObserverV1,
};
use helix_plan_dispatch::{
    dispatch_prepared_once_v1, run_automatic_readback_once_v1, DispatchAttemptIdV1,
    DispatchAuthorityCaptureOutcomeV1, DispatchAuthorityCapturePhaseV1,
    DispatchAuthorityProviderV1, DispatchAuthorityViewInputV1, DispatchAuthorityViewV1,
    DispatchAutomaticHandoffClassificationV1, DispatchAutomaticReadbackOutcomeV1,
    DispatchAutomaticReadbackScheduleV1, DispatchCommitPermitOutcomeV1, DispatchCommitPermitV1,
    DispatchCommitResolutionV1, DispatchEntropyDomainV1, DispatchEntropyErrorV1,
    DispatchEntropySourceV1, DispatchGuardAcquisitionV1, DispatchGuardClassV1,
    DispatchGuardOrderErrorV1, DispatchGuardProviderV1, DispatchGuardSetV1,
    DispatchGuardValidationV1, DispatchHandoffGuardV1, DispatchHandoffOutcomeV1,
    DispatchHandoffValidationV1, DispatchInboxReadbackOutcomeV1, DispatchInboxReadbackV1,
    DispatchLookupRequestInputV1, DispatchLookupRequestV1, DispatchReadbackWaitOutcomeV1,
    DispatchReconciliationReasonV1, DispatchRequestOutcomeV1, DispatchStoreCommitClassificationV1,
    DispatchTransportV1, DispatchUnknownReasonV1, DISPATCH_AUTHORITY_VIEW_VERSION_V1,
    DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
};
use helix_plan_preparation::{
    build_controlled_benchmark_case_v1, ControlledBenchmarkCaseV1, ControlledBenchmarkClockV1,
    CONTROLLED_BENCHMARK_BOOT_ID_V1, CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1,
    CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1, CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
    CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1, CONTROLLED_BENCHMARK_KEY_ID_V1,
    CONTROLLED_BENCHMARK_POLICY_VERSION_V1, CONTROLLED_BENCHMARK_WORKLOAD_ID_V1,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BUSY_WAIT_MS: u64 = 30_000;
const INITIALIZATION_WINDOW_MS: u64 = 60_000;
const PREPARATION_WINDOW_MS: u64 = 12 * 60 * 60 * 1_000;
const DISPATCH_LIFETIME_MS: u64 = 5_000;
const COORDINATOR_DATABASE_FILENAME: &str = "coordinator.sqlite3";
const ADAPTER_DATABASE_FILENAME: &str = "dispatch-inbox.sqlite3";
const DESTINATION_ADAPTER_ID: &str = "adapter:t080:no-effect-v1";
const DISPATCH_SIGNER_KEY_ID: &str = "dispatch-key:t080-v1";
const RECEIPT_SIGNER_KEY_ID: &str = "receipt-key:t080-v1";
const PLAN_SIGNING_KEY_BYTES: [u8; 32] = [0x42; 32];
const DISPATCH_SIGNING_KEY_BYTES: [u8; 32] = [0x80; 32];
const RECEIPT_SIGNING_KEY_BYTES: [u8; 32] = [0x81; 32];
const RECEIPT_SIGNER_PROFILE_DIGEST: [u8; 32] = [0x82; 32];
const ADAPTER_CAPABILITY_DIGEST: [u8; 32] = [0x83; 32];
const CONTROLLED_BASE_MONOTONIC_MS: u64 = 1_000_000;
const CONTROLLED_BASE_UTC_MS: u64 = CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 + 10_000;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

type CorpusStoreV1 = SqliteCoordinatorStoreV1<CorpusCoordinatorClockV1, CorpusPlanResolverV1>;
type CorpusStoreV2 = SqliteCoordinatorStoreV2<CorpusCoordinatorClockV1, CorpusPlanResolverV1>;

pub(crate) fn run_v1() -> Result<T080ProductionCorpusEvidenceV1, &'static str> {
    let roots = CorpusRootsV1::reserve_v1()?;
    let clock = ControlledBenchmarkClockV1::start_v1();
    let coordinator_clock = CorpusCoordinatorClockV1(clock.clone());
    let plan_signer = CorpusPlanSignerV1::new_v1();
    let plan_resolver = plan_signer.resolver_v1();
    let receipt_keys = ReceiptKeysV1::fixed_v1();
    let grant_resolver = DispatchGrantResolverV1::fixed_v1();
    let dispatch_keys = DispatchKeysV1::fixed_v1();
    let coordinator_receipt_keys = CoordinatorReceiptKeysV1 {
        grant: grant_resolver.clone(),
        receipt: receipt_keys.clone(),
    };
    let initialization_deadline = clock
        .deadline_after_ms_v1(INITIALIZATION_WINDOW_MS)
        .map_err(|_| "t080-initialization-deadline")?;
    let preparation_deadline = clock
        .deadline_after_ms_v1(PREPARATION_WINDOW_MS)
        .map_err(|_| "t080-preparation-deadline")?;

    let (coordinator_v1, coordinator_identity) = initialize_coordinator_v1(
        roots.coordinator(),
        coordinator_clock.clone(),
        plan_resolver.clone(),
        initialization_deadline,
    )?;
    let coordinator_database = fs::canonicalize(roots.coordinator())
        .map_err(|_| "t080-coordinator-canonicalize")?
        .join(COORDINATOR_DATABASE_FILENAME);
    let fixtures = vec![
        PreparationFixtureV1::try_new_v1(1, &plan_signer, clock.clone(), preparation_deadline)?,
        PreparationFixtureV1::try_new_v1(2, &plan_signer, clock.clone(), preparation_deadline)?,
    ];
    provision_scopes_v1(&coordinator_database, &fixtures)?;
    for fixture in fixtures {
        let committed = fixture
            .case
            .prepare_once_v1(&coordinator_v1, preparation_deadline)
            .map_err(|_| "t080-preparation-commit")?;
        if committed.recovery_provider_calls_v1() != 0 {
            return Err("t080-unexpected-recovery-provider");
        }
    }
    if coordinator_v1.operation_count() != 0 {
        // The open-time count is intentionally a snapshot; accepting a mutable cached count
        // here would make this gate depend on an implementation detail rather than reopen.
        return Err("t080-v1-open-count-drift");
    }
    drop(coordinator_v1);

    let coordinator_config = CoordinatorStoreConfigV1::try_new_existing_attested(
        roots.coordinator().to_path_buf(),
        coordinator_identity,
        BUSY_WAIT_MS,
    )
    .map_err(|_| "t080-coordinator-existing-attestation")?;
    migrate_dispatch_v2(
        &coordinator_config,
        coordinator_identity,
        &coordinator_clock,
        &plan_resolver,
        preparation_deadline,
        roots.backup().to_path_buf(),
    )?;
    let mut coordinator = Some(open_coordinator_v2(
        coordinator_config.clone(),
        coordinator_clock.clone(),
        plan_resolver.clone(),
        preparation_deadline,
    )?);
    if coordinator
        .as_ref()
        .ok_or("t080-coordinator-not-open")?
        .operation_count()
        != 2
    {
        return Err("t080-strict-migration-reopen-count");
    }
    let prepared = load_prepared_bindings_v1(&coordinator_database)?;
    if prepared.len() != 2 {
        return Err("t080-prepared-inventory");
    }

    let (adapter, adapter_identity, adapter_config, adapter_database) =
        initialize_adapter_v1(roots.adapter(), prepared[0].supervisor_epoch)?;
    drop(adapter);
    let mut adapter = Some(open_adapter_v1(adapter_config.clone())?);

    run_lost_ack_consumed_v1(
        &mut coordinator,
        &mut adapter,
        &coordinator_config,
        &adapter_config,
        &coordinator_clock,
        &plan_resolver,
        &coordinator_database,
        &adapter_database,
        adapter_identity,
        &prepared[0],
        &clock,
        &dispatch_keys,
        &grant_resolver,
        &receipt_keys,
        &coordinator_receipt_keys,
        preparation_deadline,
    )?;

    run_unknown_reconciliation_v1(
        &mut coordinator,
        adapter.as_ref().ok_or("t080-adapter-not-open")?,
        &coordinator_config,
        &coordinator_clock,
        &plan_resolver,
        &coordinator_database,
        adapter_identity,
        &prepared[1],
        &clock,
        &dispatch_keys,
        &grant_resolver,
        &receipt_keys,
        preparation_deadline,
    )?;

    let evidence = verify_final_sqlite_projection_v1(&coordinator_database, &adapter_database)?;
    drop(adapter.take());
    drop(coordinator.take());

    // These are the real T076/T077 production maintenance paths. T077 itself verifies that
    // both new roots reopen as PAUSED/RESTORE_PENDING, that its non-empty risky adapter grant
    // has exact quarantine evidence, and that automatic redelivery remains exactly zero.
    maintenance::run_t076_production_conformance_v1()?;
    maintenance::run_t077_production_conformance_v1()?;
    Ok(evidence.with_clean_restore_verified_v1())
}

/// Drives the five T096 lifecycle checkpoints through the ordinary production stores.
pub(crate) fn run_t096_restore_matrix_v1() -> Result<(), &'static str> {
    for lifecycle in maintenance::T096RestoreLifecycleV1::ALL {
        run_t096_restore_case_v1(lifecycle, None)?;
    }
    Ok(())
}

/// Materializes one strict production T096 source cut for T097 filesystem injection tests.
///
/// Both production stores are strictly reopened and closed before their dedicated roots are
/// copied. Destinations must not exist, so this helper cannot overwrite caller data.
pub(crate) fn materialize_t097_lifecycle_source_v1(
    lifecycle: crate::dispatch_quarantine::T097CoordinatorLifecycleForTestV1,
    coordinator_destination: &Path,
    adapter_destination: &Path,
) -> Result<(), &'static str> {
    let lifecycle = match lifecycle {
        crate::dispatch_quarantine::T097CoordinatorLifecycleForTestV1::Prepared => {
            maintenance::T096RestoreLifecycleV1::Prepared
        }
        crate::dispatch_quarantine::T097CoordinatorLifecycleForTestV1::Dispatching => {
            maintenance::T096RestoreLifecycleV1::Dispatching
        }
        crate::dispatch_quarantine::T097CoordinatorLifecycleForTestV1::AdapterReceived => {
            maintenance::T096RestoreLifecycleV1::AdapterReceived
        }
        crate::dispatch_quarantine::T097CoordinatorLifecycleForTestV1::Consumed => {
            maintenance::T096RestoreLifecycleV1::Consumed
        }
        crate::dispatch_quarantine::T097CoordinatorLifecycleForTestV1::Ambiguous => {
            maintenance::T096RestoreLifecycleV1::Ambiguous
        }
    };
    run_t096_restore_case_v1(
        lifecycle,
        Some((coordinator_destination, adapter_destination)),
    )
}

fn run_t096_restore_case_v1(
    lifecycle: maintenance::T096RestoreLifecycleV1,
    snapshot_destinations: Option<(&Path, &Path)>,
) -> Result<(), &'static str> {
    let roots = CorpusRootsV1::reserve_v1()?;
    let clock = ControlledBenchmarkClockV1::start_v1();
    let coordinator_clock = CorpusCoordinatorClockV1(clock.clone());
    let plan_signer = CorpusPlanSignerV1::new_v1();
    let plan_resolver = plan_signer.resolver_v1();
    let receipt_keys = ReceiptKeysV1::fixed_v1();
    let grant_resolver = DispatchGrantResolverV1::fixed_v1();
    let dispatch_keys = DispatchKeysV1::fixed_v1();
    let coordinator_receipt_keys = CoordinatorReceiptKeysV1 {
        grant: grant_resolver.clone(),
        receipt: receipt_keys.clone(),
    };
    let initialization_deadline = clock
        .deadline_after_ms_v1(INITIALIZATION_WINDOW_MS)
        .map_err(|_| "t096-initialization-deadline")?;
    let store_deadline = clock
        .deadline_after_ms_v1(PREPARATION_WINDOW_MS)
        .map_err(|_| "t096-store-deadline")?;

    let (coordinator_v1, coordinator_identity) = initialize_coordinator_v1(
        roots.coordinator(),
        coordinator_clock.clone(),
        plan_resolver.clone(),
        initialization_deadline,
    )?;
    let coordinator_database = fs::canonicalize(roots.coordinator())
        .map_err(|_| "t096-coordinator-canonicalize")?
        .join(COORDINATOR_DATABASE_FILENAME);
    let fixture = PreparationFixtureV1::try_new_v1(1, &plan_signer, clock.clone(), store_deadline)?;
    provision_scopes_v1(&coordinator_database, std::slice::from_ref(&fixture))?;
    let committed = fixture
        .case
        .prepare_once_v1(&coordinator_v1, store_deadline)
        .map_err(|_| match lifecycle {
            maintenance::T096RestoreLifecycleV1::Prepared => "t096-prepared-preparation-commit",
            maintenance::T096RestoreLifecycleV1::Dispatching => {
                "t096-dispatching-preparation-commit"
            }
            maintenance::T096RestoreLifecycleV1::AdapterReceived => {
                "t096-received-preparation-commit"
            }
            maintenance::T096RestoreLifecycleV1::Consumed => "t096-consumed-preparation-commit",
            maintenance::T096RestoreLifecycleV1::Ambiguous => "t096-ambiguous-preparation-commit",
        })?;
    if committed.recovery_provider_calls_v1() != 0 {
        return Err("t096-unexpected-recovery-provider");
    }
    drop(coordinator_v1);

    let coordinator_config = CoordinatorStoreConfigV1::try_new_existing_attested(
        roots.coordinator().to_path_buf(),
        coordinator_identity,
        BUSY_WAIT_MS,
    )
    .map_err(|_| "t096-coordinator-existing-attestation")?;
    migrate_dispatch_v2(
        &coordinator_config,
        coordinator_identity,
        &coordinator_clock,
        &plan_resolver,
        store_deadline,
        roots.backup().to_path_buf(),
    )?;
    let mut coordinator = Some(open_coordinator_v2(
        coordinator_config.clone(),
        coordinator_clock.clone(),
        plan_resolver.clone(),
        store_deadline,
    )?);
    let mut prepared = load_prepared_bindings_v1(&coordinator_database)?;
    if prepared.len() != 1 {
        return Err("t096-prepared-inventory");
    }
    let prepared = prepared.pop().ok_or("t096-prepared-missing")?;

    let (adapter_store, adapter_identity, adapter_config, adapter_database) =
        initialize_adapter_v1(roots.adapter(), prepared.supervisor_epoch)?;
    drop(adapter_store);
    let mut adapter = Some(open_adapter_v1(adapter_config.clone())?);

    match lifecycle {
        maintenance::T096RestoreLifecycleV1::Prepared => {}
        maintenance::T096RestoreLifecycleV1::Dispatching => {
            drive_t096_dispatch_v1(
                coordinator
                    .as_ref()
                    .ok_or("t096-dispatching-coordinator-not-open")?,
                &prepared,
                &clock,
                &dispatch_keys,
                &coordinator_database,
                t096_lifecycle_ordinal_v1(lifecycle),
            )?;
        }
        maintenance::T096RestoreLifecycleV1::AdapterReceived => {
            let (grant_id, dispatch_deadline, sampled_utc_ms, sampled_monotonic_ms) =
                drive_t096_dispatch_v1(
                    coordinator
                        .as_ref()
                        .ok_or("t096-received-coordinator-not-open")?,
                    &prepared,
                    &clock,
                    &dispatch_keys,
                    &coordinator_database,
                    t096_lifecycle_ordinal_v1(lifecycle),
                )?;
            let transport = ReceiveThenLoseAckTransportV1 {
                store: adapter.as_ref().ok_or("t096-received-adapter-not-open")?,
                database: adapter_database.clone(),
                boot_id: prepared.boot_id.clone(),
                supervisor_epoch: prepared.supervisor_epoch,
                sampled_utc_ms: sampled_utc_ms + 1,
                sampled_monotonic_ms: sampled_monotonic_ms + 1,
                grant_resolver: grant_resolver.clone(),
                receive_calls: AtomicU64::new(0),
            };
            if !matches!(
                coordinator
                    .as_ref()
                    .ok_or("t096-received-coordinator-not-open")?
                    .handoff_pending_dispatch_v1(grant_id, dispatch_deadline, &transport),
                CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
            ) || transport.receive_calls.load(Ordering::SeqCst) != 1
            {
                return Err("t096-received-handoff");
            }
        }
        maintenance::T096RestoreLifecycleV1::Consumed => {
            run_lost_ack_consumed_v1(
                &mut coordinator,
                &mut adapter,
                &coordinator_config,
                &adapter_config,
                &coordinator_clock,
                &plan_resolver,
                &coordinator_database,
                &adapter_database,
                adapter_identity,
                &prepared,
                &clock,
                &dispatch_keys,
                &grant_resolver,
                &receipt_keys,
                &coordinator_receipt_keys,
                store_deadline,
            )?;
        }
        maintenance::T096RestoreLifecycleV1::Ambiguous => {
            run_unknown_reconciliation_v1(
                &mut coordinator,
                adapter.as_ref().ok_or("t096-ambiguous-adapter-not-open")?,
                &coordinator_config,
                &coordinator_clock,
                &plan_resolver,
                &coordinator_database,
                adapter_identity,
                &prepared,
                &clock,
                &dispatch_keys,
                &grant_resolver,
                &receipt_keys,
                store_deadline,
            )?;
        }
    }

    if let Some((coordinator_destination, adapter_destination)) = snapshot_destinations {
        drop(coordinator.take().ok_or("t097-coordinator-not-open")?);
        drop(adapter.take().ok_or("t097-adapter-not-open")?);
        drop(open_coordinator_v2(
            coordinator_config.clone(),
            coordinator_clock.clone(),
            plan_resolver.clone(),
            store_deadline,
        )?);
        drop(open_adapter_v1(adapter_config.clone())?);
        checkpoint_t097_database_v1(&coordinator_database)?;
        checkpoint_t097_database_v1(&adapter_database)?;
        copy_t097_root_create_only_v1(roots.coordinator(), coordinator_destination)?;
        copy_t097_root_create_only_v1(roots.adapter(), adapter_destination)?;
        let copied_coordinator_config = CoordinatorStoreConfigV1::try_new_existing_attested(
            coordinator_destination.to_path_buf(),
            coordinator_identity,
            BUSY_WAIT_MS,
        )
        .map_err(|_| "t097-copied-coordinator-attestation")?;
        drop(open_coordinator_v2(
            copied_coordinator_config,
            coordinator_clock,
            plan_resolver,
            store_deadline,
        )?);
        let copied_adapter_config = AdapterInboxStoreConfigV1::try_new_existing_attested(
            adapter_destination.to_path_buf(),
            adapter_identity,
            BUSY_WAIT_MS,
        )
        .map_err(|_| "t097-copied-adapter-attestation")?;
        drop(open_adapter_v1(copied_adapter_config)?);
        return Ok(());
    }

    drop(coordinator.take().ok_or("t096-coordinator-not-open")?);
    maintenance::run_t096_restore_checkpoint_v1(
        lifecycle,
        &coordinator_config,
        coordinator_identity,
        &coordinator_clock,
        &plan_resolver,
        adapter.as_ref().ok_or("t096-adapter-not-open")?,
        prepared.instance_epoch,
        prepared.supervisor_epoch,
        store_deadline,
        DISPATCH_SIGNER_KEY_ID,
        grant_resolver.verifying_key,
        RECEIPT_SIGNER_KEY_ID,
        receipt_keys.signing_key.verifying_key().to_bytes(),
    )?;
    drop(adapter.take());
    Ok(())
}

fn checkpoint_t097_database_v1(database: &Path) -> Result<(), &'static str> {
    Connection::open(database)
        .map_err(|_| "t097-checkpoint-open")?
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|_| "t097-checkpoint-failed")
}

fn copy_t097_root_create_only_v1(source: &Path, destination: &Path) -> Result<(), &'static str> {
    if destination.exists() {
        return Err("t097-snapshot-destination-exists");
    }
    fs::create_dir(destination).map_err(|_| "t097-snapshot-destination-create")?;
    for entry in fs::read_dir(source).map_err(|_| "t097-snapshot-source-read")? {
        let entry = entry.map_err(|_| "t097-snapshot-entry-read")?;
        let target = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|_| "t097-snapshot-entry-type")?;
        if file_type.is_dir() {
            copy_t097_root_create_only_v1(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target).map_err(|_| "t097-snapshot-file-copy")?;
        } else {
            return Err("t097-snapshot-entry-invalid");
        }
    }
    Ok(())
}

fn t096_lifecycle_ordinal_v1(lifecycle: maintenance::T096RestoreLifecycleV1) -> u8 {
    match lifecycle {
        maintenance::T096RestoreLifecycleV1::Prepared => 1,
        maintenance::T096RestoreLifecycleV1::Dispatching => 2,
        maintenance::T096RestoreLifecycleV1::AdapterReceived => 3,
        maintenance::T096RestoreLifecycleV1::Consumed => 4,
        maintenance::T096RestoreLifecycleV1::Ambiguous => 5,
    }
}

fn drive_t096_dispatch_v1(
    coordinator: &CorpusStoreV2,
    prepared: &PreparedDispatchBindingsV1,
    clock: &ControlledBenchmarkClockV1,
    dispatch_keys: &DispatchKeysV1,
    coordinator_database: &Path,
    entropy_seed: u8,
) -> Result<([u8; 32], u64, u64, u64), &'static str> {
    let sampled_monotonic_ms = clock
        .now_absolute_monotonic_ms_v1()
        .map_err(|_| "t096-dispatch-monotonic")?;
    let sampled_utc_ms = controlled_utc_from_monotonic_v1(sampled_monotonic_ms)?;
    let dispatch_deadline = sampled_monotonic_ms
        .checked_add(DISPATCH_LIFETIME_MS)
        .ok_or("t096-dispatch-deadline")?;
    let authority = AuthorityFixtureV1 {
        prepared: prepared.clone(),
        sampled_monotonic_ms,
        sampled_utc_ms,
        deadline_monotonic_ms: dispatch_deadline,
    };
    require_new_dispatch_v1(
        coordinator,
        prepared,
        dispatch_deadline,
        &authority,
        &SeededDispatchEntropyV1(u64::from(entropy_seed)),
        dispatch_keys,
    )?;
    let (grant_id, _) = load_pending_grant_v1(coordinator_database, &prepared.operation_id)?;
    Ok((
        grant_id,
        dispatch_deadline,
        sampled_utc_ms,
        sampled_monotonic_ms,
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_lost_ack_consumed_v1(
    coordinator: &mut Option<CorpusStoreV2>,
    adapter: &mut Option<SqliteDispatchInboxStoreV1>,
    coordinator_config: &CoordinatorStoreConfigV1,
    adapter_config: &AdapterInboxStoreConfigV1,
    coordinator_clock: &CorpusCoordinatorClockV1,
    plan_resolver: &CorpusPlanResolverV1,
    coordinator_database: &Path,
    adapter_database: &Path,
    adapter_identity: AdapterInboxRootIdentityEvidenceV1,
    prepared: &PreparedDispatchBindingsV1,
    clock: &ControlledBenchmarkClockV1,
    dispatch_keys: &DispatchKeysV1,
    grant_resolver: &DispatchGrantResolverV1,
    receipt_keys: &ReceiptKeysV1,
    coordinator_receipt_keys: &CoordinatorReceiptKeysV1,
    store_deadline: u64,
) -> Result<(), &'static str> {
    let sampled_monotonic_ms = clock
        .now_absolute_monotonic_ms_v1()
        .map_err(|_| "t080-consumed-monotonic")?;
    let sampled_utc_ms = controlled_utc_from_monotonic_v1(sampled_monotonic_ms)?;
    let dispatch_deadline = sampled_monotonic_ms
        .checked_add(DISPATCH_LIFETIME_MS)
        .ok_or("t080-consumed-deadline")?;
    let authority = AuthorityFixtureV1 {
        prepared: prepared.clone(),
        sampled_monotonic_ms,
        sampled_utc_ms,
        deadline_monotonic_ms: dispatch_deadline,
    };
    require_new_dispatch_v1(
        coordinator
            .as_ref()
            .ok_or("t080-consumed-coordinator-not-open")?,
        prepared,
        dispatch_deadline,
        &authority,
        &SeededDispatchEntropyV1(1),
        dispatch_keys,
    )?;
    let (grant_id, canonical_grant) =
        load_pending_grant_v1(coordinator_database, &prepared.operation_id)?;
    let transport = ConsumeThenLoseAckTransportV1 {
        store: adapter.as_ref().ok_or("t080-consumed-adapter-not-open")?,
        database: adapter_database.to_path_buf(),
        boot_id: prepared.boot_id.clone(),
        supervisor_epoch: prepared.supervisor_epoch,
        sampled_utc_ms: sampled_utc_ms + 1,
        sampled_monotonic_ms: sampled_monotonic_ms + 1,
        grant_resolver: grant_resolver.clone(),
        receipt_keys: receipt_keys.clone(),
        canonical_receipt: Mutex::new(None),
        consume_calls: AtomicU64::new(0),
    };
    if !matches!(
        coordinator
            .as_ref()
            .ok_or("t080-consumed-coordinator-not-open")?
            .handoff_pending_dispatch_v1(grant_id, dispatch_deadline, &transport),
        CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
    ) {
        return Err("t080-lost-ack-not-possible-handoff");
    }
    let lost_receipt = transport.retained_receipt_v1()?;
    if transport.consume_calls.load(Ordering::SeqCst) != 1 || lost_receipt.is_empty() {
        return Err("t080-lost-ack-consume-count");
    }
    drop(transport);

    // Close both authority domains and admit only their strict existing-root constructors.
    drop(
        coordinator
            .take()
            .ok_or("t080-consumed-coordinator-not-open")?,
    );
    *coordinator = Some(open_coordinator_v2(
        coordinator_config.clone(),
        coordinator_clock.clone(),
        plan_resolver.clone(),
        store_deadline,
    )?);
    drop(adapter.take().ok_or("t080-consumed-adapter-not-open")?);
    *adapter = Some(open_adapter_v1(adapter_config.clone())?);
    let coordinator = coordinator
        .as_ref()
        .ok_or("t080-consumed-coordinator-reopen")?;
    let adapter = adapter.as_ref().ok_or("t080-consumed-adapter-reopen")?;

    let reconciliation_lookup =
        CoordinatorReconciliationLookupV1::try_new(prepared.operation_id.clone(), grant_id)
            .map_err(|_| "t080-consumed-reconciliation-lookup")?;
    let sequence_claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_identity.to_attested_bytes(),
        prepared.supervisor_epoch,
    )
    .map_err(|_| "t080-consumed-sequence-claim")?;
    let (claim_evidence, permit) = match coordinator.claim_or_resume_readback_sequence_v1(
        &reconciliation_lookup,
        &sequence_claim,
        dispatch_deadline,
    ) {
        CoordinatorReadbackSequenceClaimOutcomeV1::Claimed { evidence, permit } => {
            (evidence, permit)
        }
        _ => return Err("t080-consumed-sequence-not-claimed"),
    };
    let automatic_first_observation = sampled_monotonic_ms
        .checked_add(2)
        .ok_or("t080-consumed-readback-start")?;
    let inbox = CorpusAdapterReadbackV1::new_v1(adapter, grant_resolver, receipt_keys);
    let mut schedule = CorpusAutomaticReadbackScheduleV1::default();
    let first_receipt = match run_automatic_readback_once_v1(
        &inbox,
        &permit,
        &mut schedule,
        claim_evidence.source_handoff_generation(),
        DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
        &grant_id,
        automatic_first_observation,
        dispatch_deadline,
        dispatch_deadline,
    ) {
        DispatchAutomaticReadbackOutcomeV1::RetainedReceipt {
            receipt,
            evidence_only: false,
        } => receipt,
        _ => return Err("t080-lost-ack-automatic-readback"),
    };
    schedule.require_offsets_v1(automatic_first_observation, &[0])?;
    if inbox.call_count_v1() != 1 || first_receipt.canonical_receipt != lost_receipt {
        return Err("t080-lost-ack-receipt-drift");
    }
    let mut already_classified_schedule = CorpusAutomaticReadbackScheduleV1::default();
    if !matches!(
        run_automatic_readback_once_v1(
            &inbox,
            &permit,
            &mut already_classified_schedule,
            claim_evidence.source_handoff_generation(),
            DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
            &grant_id,
            automatic_first_observation,
            dispatch_deadline,
            dispatch_deadline,
        ),
        DispatchAutomaticReadbackOutcomeV1::AlreadyClassified
    ) || !already_classified_schedule.is_empty_v1()
        || inbox.call_count_v1() != 1
    {
        return Err("t080-lost-ack-permit-reused");
    }
    let repeated_claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_identity.to_attested_bytes(),
        prepared.supervisor_epoch,
    )
    .map_err(|_| "t080-consumed-repeated-claim")?;
    match coordinator.claim_or_resume_readback_sequence_v1(
        &reconciliation_lookup,
        &repeated_claim,
        dispatch_deadline,
    ) {
        CoordinatorReadbackSequenceClaimOutcomeV1::Resumed(evidence)
            if evidence.claim_attempt_generation() == claim_evidence.claim_attempt_generation()
                && evidence.source_handoff_generation()
                    == claim_evidence.source_handoff_generation() => {}
        _ => return Err("t080-consumed-claim-not-resumed"),
    }

    let duplicate_clock = FixedAdapterClockV1 {
        boot_id: prepared.boot_id.clone(),
        generation: 2,
        sampled_utc_ms: sampled_utc_ms + 2,
        sampled_monotonic_ms: sampled_monotonic_ms + 2,
    };
    let duplicate_observer = FreshAdapterEpochObserverV1 {
        database: adapter_database.to_path_buf(),
        boot_id: prepared.boot_id.clone(),
        supervisor_epoch: prepared.supervisor_epoch,
        sampled_utc_ms: sampled_utc_ms + 2,
        sampled_monotonic_ms: sampled_monotonic_ms + 2,
    };
    match adapter
        .receive_grant_v1(
            &canonical_grant,
            grant_resolver,
            &duplicate_clock,
            &duplicate_observer,
        )
        .map_err(|_| "t080-lost-ack-duplicate-receive")?
    {
        AdapterInboxReceiveOutcomeV1::ExactDuplicate(duplicate)
            if duplicate.state() == AdapterInboxRetainedStateV1::Consumed
                && duplicate.receipt_retained() => {}
        _ => return Err("t080-lost-ack-not-exact-duplicate"),
    }
    let second_readback = adapter
        .readback_grant_v1(
            Sha256Digest::from_bytes(grant_id),
            grant_resolver,
            receipt_keys,
        )
        .map_err(|_| "t080-lost-ack-second-readback")?;
    match second_readback {
        AdapterInboxReadbackOutcomeV1::RetainedReceipt(receipt)
            if receipt.receipt_generation() == first_receipt.receipt_generation
                && receipt.canonical_receipt() == first_receipt.canonical_receipt => {}
        _ => return Err("t080-lost-ack-reconsumed-or-resigned"),
    }
    let lookup = CoordinatorReceiptLookupV1::try_new(
        prepared.operation_id.clone(),
        grant_id,
        adapter_identity.to_attested_bytes(),
    )
    .map_err(|_| "t080-consumed-receipt-lookup")?;
    let committed = match coordinator.commit_execution_receipt_v1(
        lookup,
        &first_receipt.canonical_receipt,
        dispatch_deadline,
        coordinator_receipt_keys,
    ) {
        CoordinatorReceiptCommitOutcomeV1::Committed(evidence)
            if evidence.effective_state() == CoordinatorReceiptEffectiveStateV1::Executing =>
        {
            evidence
        }
        _ => return Err("t080-consumed-not-executing"),
    };
    let committed_generation = committed.state_generation();
    let retry_lookup = CoordinatorReceiptLookupV1::try_new(
        prepared.operation_id.clone(),
        grant_id,
        adapter_identity.to_attested_bytes(),
    )
    .map_err(|_| "t080-consumed-retry-lookup")?;
    match coordinator.commit_execution_receipt_v1(
        retry_lookup,
        &first_receipt.canonical_receipt,
        dispatch_deadline,
        coordinator_receipt_keys,
    ) {
        CoordinatorReceiptCommitOutcomeV1::PriorExact(evidence)
            if evidence.effective_state() == CoordinatorReceiptEffectiveStateV1::Executing
                && evidence.state_generation() == committed_generation => {}
        _ => return Err("t080-consumed-retry-not-exact"),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_unknown_reconciliation_v1(
    coordinator: &mut Option<CorpusStoreV2>,
    adapter: &SqliteDispatchInboxStoreV1,
    coordinator_config: &CoordinatorStoreConfigV1,
    coordinator_clock: &CorpusCoordinatorClockV1,
    plan_resolver: &CorpusPlanResolverV1,
    coordinator_database: &Path,
    adapter_identity: AdapterInboxRootIdentityEvidenceV1,
    prepared: &PreparedDispatchBindingsV1,
    clock: &ControlledBenchmarkClockV1,
    dispatch_keys: &DispatchKeysV1,
    grant_resolver: &DispatchGrantResolverV1,
    receipt_keys: &ReceiptKeysV1,
    store_deadline: u64,
) -> Result<(), &'static str> {
    let sampled_monotonic_ms = clock
        .now_absolute_monotonic_ms_v1()
        .map_err(|_| "t080-unknown-monotonic")?;
    let sampled_utc_ms = controlled_utc_from_monotonic_v1(sampled_monotonic_ms)?;
    let dispatch_deadline = sampled_monotonic_ms
        .checked_add(DISPATCH_LIFETIME_MS)
        .ok_or("t080-unknown-deadline")?;
    let authority = AuthorityFixtureV1 {
        prepared: prepared.clone(),
        sampled_monotonic_ms,
        sampled_utc_ms,
        deadline_monotonic_ms: dispatch_deadline,
    };
    require_new_dispatch_v1(
        coordinator
            .as_ref()
            .ok_or("t080-unknown-coordinator-not-open")?,
        prepared,
        dispatch_deadline,
        &authority,
        &SeededDispatchEntropyV1(2),
        dispatch_keys,
    )?;
    let (grant_id, _) = load_pending_grant_v1(coordinator_database, &prepared.operation_id)?;
    let transport = PossibleHandoffWithoutDeliveryV1;
    if !matches!(
        coordinator
            .as_ref()
            .ok_or("t080-unknown-coordinator-not-open")?
            .handoff_pending_dispatch_v1(grant_id, dispatch_deadline, &transport),
        CoordinatorDispatchHandoffOutcomeV1::PossibleHandoff
    ) {
        return Err("t080-unknown-not-possible-handoff");
    }

    strict_reopen_coordinator_v2(
        coordinator,
        coordinator_config,
        coordinator_clock,
        plan_resolver,
        store_deadline,
    )?;
    let lookup =
        CoordinatorReconciliationLookupV1::try_new(prepared.operation_id.clone(), grant_id)
            .map_err(|_| "t080-unknown-lookup")?;
    let claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_identity.to_attested_bytes(),
        prepared.supervisor_epoch,
    )
    .map_err(|_| "t080-unknown-claim")?;
    let (claim_evidence, permit) = match coordinator
        .as_ref()
        .ok_or("t080-unknown-coordinator-reopen")?
        .claim_or_resume_readback_sequence_v1(&lookup, &claim, dispatch_deadline)
    {
        CoordinatorReadbackSequenceClaimOutcomeV1::Claimed { evidence, permit } => {
            (evidence, permit)
        }
        _ => return Err("t080-unknown-claim-not-committed"),
    };
    let automatic_first_observation = sampled_monotonic_ms
        .checked_add(2)
        .ok_or("t080-unknown-readback-start")?;
    let inbox = CorpusAdapterReadbackV1::new_v1(adapter, grant_resolver, receipt_keys);
    let mut schedule = CorpusAutomaticReadbackScheduleV1::default();
    match run_automatic_readback_once_v1(
        &inbox,
        &permit,
        &mut schedule,
        claim_evidence.source_handoff_generation(),
        DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
        &grant_id,
        automatic_first_observation,
        dispatch_deadline,
        dispatch_deadline,
    ) {
        DispatchAutomaticReadbackOutcomeV1::OutcomeUnknownThenReconciliationRequired {
            unknown_reason: DispatchUnknownReasonV1::ReadbackExhausted,
            reconciliation_reason: DispatchReconciliationReasonV1::PossibleConsumption,
        } => {}
        _ => return Err("t080-unknown-automatic-readback"),
    }
    schedule.require_offsets_v1(automatic_first_observation, &[0, 25, 100, 275])?;
    if inbox.call_count_v1() != 4 {
        return Err("t080-unknown-readback-count");
    }
    let observation_digest = schedule.transcript_digest_v1(grant_id, inbox.call_count_v1());
    let exhaustion_latency_ms = schedule.exhaustion_latency_ms_v1(automatic_first_observation)?;
    let mut already_classified_schedule = CorpusAutomaticReadbackScheduleV1::default();
    if !matches!(
        run_automatic_readback_once_v1(
            &inbox,
            &permit,
            &mut already_classified_schedule,
            claim_evidence.source_handoff_generation(),
            DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
            &grant_id,
            automatic_first_observation,
            dispatch_deadline,
            dispatch_deadline,
        ),
        DispatchAutomaticReadbackOutcomeV1::AlreadyClassified
    ) || !already_classified_schedule.is_empty_v1()
        || inbox.call_count_v1() != 4
    {
        return Err("t080-unknown-permit-reused");
    }
    strict_reopen_coordinator_v2(
        coordinator,
        coordinator_config,
        coordinator_clock,
        plan_resolver,
        store_deadline,
    )?;
    let resumed_claim = CoordinatorReadbackSequenceClaimV1::try_new(
        adapter_identity.to_attested_bytes(),
        prepared.supervisor_epoch,
    )
    .map_err(|_| "t080-unknown-resumed-claim")?;
    match coordinator
        .as_ref()
        .ok_or("t080-unknown-coordinator-reopen")?
        .claim_or_resume_readback_sequence_v1(&lookup, &resumed_claim, dispatch_deadline)
    {
        CoordinatorReadbackSequenceClaimOutcomeV1::Resumed(evidence)
            if evidence.claim_attempt_generation() == claim_evidence.claim_attempt_generation()
                && evidence.source_handoff_generation()
                    == claim_evidence.source_handoff_generation() => {}
        _ => return Err("t080-unknown-claim-not-resumed"),
    }
    let exhaustion = CoordinatorReadbackExhaustionV1::try_new(
        observation_digest,
        "trace:t080-readback-exhausted".to_owned(),
        exhaustion_latency_ms,
    )
    .map_err(|_| "t080-unknown-exhaustion")?;
    let unknown = match coordinator
        .as_ref()
        .ok_or("t080-unknown-coordinator-reopen")?
        .commit_outcome_unknown_v1(&lookup, &exhaustion, dispatch_deadline)
    {
        CoordinatorReconciliationOutcomeV1::Committed(evidence)
            if evidence.state() == CoordinatorReconciliationStateV1::OutcomeUnknown =>
        {
            evidence
        }
        _ => return Err("t080-outcome-unknown-not-committed"),
    };
    let unknown_generation = unknown.state_generation();

    strict_reopen_coordinator_v2(
        coordinator,
        coordinator_config,
        coordinator_clock,
        plan_resolver,
        store_deadline,
    )?;
    match coordinator
        .as_ref()
        .ok_or("t080-outcome-unknown-coordinator-reopen")?
        .commit_outcome_unknown_v1(&lookup, &exhaustion, dispatch_deadline)
    {
        CoordinatorReconciliationOutcomeV1::Resumed(evidence)
            if evidence.state() == CoordinatorReconciliationStateV1::OutcomeUnknown
                && evidence.state_generation() == unknown_generation => {}
        _ => return Err("t080-outcome-unknown-reopen-drift"),
    }
    let required = match coordinator
        .as_ref()
        .ok_or("t080-outcome-unknown-coordinator-reopen")?
        .commit_reconciliation_required_unknown_v1(&lookup, dispatch_deadline)
    {
        CoordinatorReconciliationOutcomeV1::Committed(evidence)
            if evidence.state() == CoordinatorReconciliationStateV1::ReconciliationRequired =>
        {
            evidence
        }
        _ => return Err("t080-reconciliation-required-not-committed"),
    };
    if required.state_generation() <= unknown_generation {
        return Err("t080-reconciliation-generation-order");
    }
    let required_generation = required.state_generation();
    let required_id = required.reconciliation_id();

    strict_reopen_coordinator_v2(
        coordinator,
        coordinator_config,
        coordinator_clock,
        plan_resolver,
        store_deadline,
    )?;
    match coordinator
        .as_ref()
        .ok_or("t080-reconciliation-coordinator-reopen")?
        .commit_reconciliation_required_unknown_v1(&lookup, dispatch_deadline)
    {
        CoordinatorReconciliationOutcomeV1::Resumed(evidence)
            if evidence.state() == CoordinatorReconciliationStateV1::ReconciliationRequired
                && evidence.state_generation() == required_generation
                && evidence.reconciliation_id() == required_id => {}
        _ => return Err("t080-reconciliation-required-reopen-drift"),
    }
    Ok(())
}

fn require_new_dispatch_v1(
    coordinator: &CorpusStoreV2,
    prepared: &PreparedDispatchBindingsV1,
    deadline_monotonic_ms: u64,
    authority: &AuthorityFixtureV1,
    entropy: &SeededDispatchEntropyV1,
    dispatch_keys: &DispatchKeysV1,
) -> Result<(), &'static str> {
    match dispatch_prepared_once_v1(
        coordinator,
        prepared.lookup_request_v1(deadline_monotonic_ms)?,
        authority,
        entropy,
        dispatch_keys,
        authority,
    ) {
        DispatchRequestOutcomeV1::Dispatched(_) => Ok(()),
        _ => Err("t080-dispatch-not-committed"),
    }
}

fn migrate_dispatch_v2(
    config: &CoordinatorStoreConfigV1,
    expected_root_identity: CoordinatorRootIdentityEvidenceV1,
    clock: &CorpusCoordinatorClockV1,
    historical_plan_keys: &CorpusPlanResolverV1,
    deadline_monotonic_ms: u64,
    package_root: PathBuf,
) -> Result<(), &'static str> {
    let request = DispatchMigrationRequestV2::try_new(
        [0x80; 32],
        CONTROLLED_BASE_UTC_MS,
        CONTROLLED_BASE_MONOTONIC_MS,
        "helixos-t080-corpus-v1",
    )
    .map_err(|_| "t080-migration-request")?;
    maintenance::complete_t080_quiescent_backup_and_migrate_dispatch_v2(
        config,
        expected_root_identity,
        clock,
        historical_plan_keys,
        deadline_monotonic_ms,
        package_root,
        request,
    )
}

fn initialize_coordinator_v1(
    root: &Path,
    clock: CorpusCoordinatorClockV1,
    resolver: CorpusPlanResolverV1,
    deadline_monotonic_ms: u64,
) -> Result<(CorpusStoreV1, CoordinatorRootIdentityEvidenceV1), &'static str> {
    fs::create_dir(root).map_err(|_| "t080-coordinator-root-create")?;
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.to_path_buf(), BUSY_WAIT_MS)
        .map_err(|_| "t080-coordinator-root-attest")?;
    let store =
        SqliteCoordinatorStoreV1::open_or_create(config, clock, resolver, deadline_monotonic_ms)
            .map_err(|_| "t080-coordinator-v1-open")?;
    let identity = store.root_identity_evidence();
    Ok((store, identity))
}

fn open_coordinator_v2(
    config: CoordinatorStoreConfigV1,
    clock: CorpusCoordinatorClockV1,
    resolver: CorpusPlanResolverV1,
    deadline_monotonic_ms: u64,
) -> Result<CorpusStoreV2, &'static str> {
    SqliteCoordinatorStoreV2::open_existing(config, clock, resolver, deadline_monotonic_ms)
        .map_err(|_| "t080-coordinator-v2-strict-open")
}

fn strict_reopen_coordinator_v2(
    store: &mut Option<CorpusStoreV2>,
    config: &CoordinatorStoreConfigV1,
    clock: &CorpusCoordinatorClockV1,
    resolver: &CorpusPlanResolverV1,
    deadline_monotonic_ms: u64,
) -> Result<(), &'static str> {
    drop(store.take().ok_or("t080-coordinator-not-open")?);
    *store = Some(open_coordinator_v2(
        config.clone(),
        clock.clone(),
        resolver.clone(),
        deadline_monotonic_ms,
    )?);
    Ok(())
}

fn initialize_adapter_v1(
    root: &Path,
    supervisor_epoch: u64,
) -> Result<
    (
        SqliteDispatchInboxStoreV1,
        AdapterInboxRootIdentityEvidenceV1,
        AdapterInboxStoreConfigV1,
        PathBuf,
    ),
    &'static str,
> {
    fs::create_dir(root).map_err(|_| "t080-adapter-root-create")?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"HELIXOS\0T080-ADAPTER-ROOT\0V1\0");
    preimage.extend_from_slice(&std::process::id().to_be_bytes());
    preimage.extend_from_slice(
        &SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "t080-adapter-root-clock")?
            .as_nanos()
            .to_be_bytes(),
    );
    let identity =
        AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(Sha256::digest(&preimage).into());
    let empty_config = AdapterInboxStoreConfigV1::try_new_empty_attested(
        root.to_path_buf(),
        identity,
        BUSY_WAIT_MS,
    )
    .map_err(|_| "t080-adapter-root-attest")?;
    let initial =
        AdapterInboxInitializationV1::try_new(supervisor_epoch, 1, RECEIPT_SIGNER_PROFILE_DIGEST)
            .map_err(|_| "t080-adapter-initialization")?;
    let store = SqliteDispatchInboxStoreV1::initialize_empty_v1(
        empty_config,
        initial,
        adapter_profile_v1()?,
    )
    .map_err(|_| "t080-adapter-initialize")?;
    let database = fs::canonicalize(root)
        .map_err(|_| "t080-adapter-canonicalize")?
        .join(ADAPTER_DATABASE_FILENAME);
    let existing_config = AdapterInboxStoreConfigV1::try_new_existing_attested(
        root.to_path_buf(),
        identity,
        BUSY_WAIT_MS,
    )
    .map_err(|_| "t080-adapter-existing-attest")?;
    Ok((store, identity, existing_config, database))
}

fn open_adapter_v1(
    config: AdapterInboxStoreConfigV1,
) -> Result<SqliteDispatchInboxStoreV1, &'static str> {
    SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile_v1()?)
        .map_err(|_| "t080-adapter-strict-open")
}

fn adapter_profile_v1() -> Result<AdapterInboxProfileV1, &'static str> {
    AdapterInboxProfileV1::try_new(
        DESTINATION_ADAPTER_ID,
        1,
        Sha256Digest::from_bytes(ADAPTER_CAPABILITY_DIGEST),
    )
    .map_err(|_| "t080-adapter-profile")
}

fn receipt_signing_profile_v1(
    keys: &ReceiptKeysV1,
) -> Result<AdapterReceiptSigningProfileV1, &'static str> {
    AdapterReceiptSigningProfileV1::try_new(
        RECEIPT_SIGNER_KEY_ID,
        Sha256Digest::digest(&keys.signing_key.verifying_key().to_bytes()),
        Sha256Digest::from_bytes(RECEIPT_SIGNER_PROFILE_DIGEST),
    )
    .map_err(|_| "t080-receipt-signing-profile")
}

fn provision_scopes_v1(
    database: &Path,
    fixtures: &[PreparationFixtureV1],
) -> Result<(), &'static str> {
    let mut connection = open_write_connection_v1(database)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "t080-scope-begin")?;
    for fixture in fixtures {
        let scope = fixture.case.budget_scope_v1();
        let total = scope.total_v1();
        transaction
            .execute(
                "INSERT INTO budget_scopes (
                     scope_id, task_lease_digest, allowance_binding_digest, scope_generation,
                     currency_code, price_table_id, total_cost_micro_units, total_action_count,
                     total_egress_bytes, total_recovery_bytes, held_cost_micro_units,
                     held_action_count, held_egress_bytes, held_recovery_bytes,
                     provisioning_profile
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                           0, 0, 0, 0, 'TRUSTED_LEASE_V1')",
                params![
                    scope.scope_id_v1().as_bytes().as_slice(),
                    scope.task_lease_digest_v1().as_bytes().as_slice(),
                    scope.allowance_binding_digest_v1().as_bytes().as_slice(),
                    i64::try_from(scope.scope_generation_v1())
                        .map_err(|_| "t080-scope-generation")?,
                    scope.currency_code_v1(),
                    scope.price_table_id_v1(),
                    i64::try_from(total[0]).map_err(|_| "t080-scope-capacity")?,
                    i64::try_from(total[1]).map_err(|_| "t080-scope-capacity")?,
                    i64::try_from(total[2]).map_err(|_| "t080-scope-capacity")?,
                    i64::try_from(total[3]).map_err(|_| "t080-scope-capacity")?,
                ],
            )
            .map_err(|_| "t080-scope-insert")?;
    }
    let generation = i64::try_from(fixtures.len()).map_err(|_| "t080-scope-count")?;
    if transaction
        .execute(
            "UPDATE coordinator_store_meta
             SET store_generation=?1, budget_generation=?1
             WHERE singleton=1 AND root_lifecycle_state='ACTIVE'
               AND store_generation=0 AND budget_generation=0",
            [generation],
        )
        .map_err(|_| "t080-scope-metadata")?
        != 1
    {
        return Err("t080-scope-metadata-conflict");
    }
    transaction.commit().map_err(|_| "t080-scope-commit")
}

fn open_write_connection_v1(database: &Path) -> Result<Connection, &'static str> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "t080-scope-open")?;
    connection
        .busy_timeout(Duration::from_millis(BUSY_WAIT_MS))
        .map_err(|_| "t080-scope-timeout")?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA wal_autocheckpoint=0;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA cell_size_check=ON;
             PRAGMA recursive_triggers=ON;",
        )
        .map_err(|_| "t080-scope-profile")?;
    Ok(connection)
}

fn load_prepared_bindings_v1(
    database: &Path,
) -> Result<Vec<PreparedDispatchBindingsV1>, &'static str> {
    let connection = open_read_connection_v1(database)?;
    let mut statement = connection
        .prepare(
            "SELECT operation.operation_id, operation.attempt_id, operation.plan_id,
                    operation.state_generation, operation.task_id, operation.workload_id,
                    operation.boot_id, operation.instance_epoch, operation.fencing_epoch,
                    operation.reservation_id, reservation.task_lease_digest,
                    operation.recovery_mode, scope.scope_generation,
                    reservation.created_generation
             FROM prepared_operations AS operation
             JOIN budget_reservations AS reservation
               ON reservation.reservation_id = operation.reservation_id
              AND reservation.operation_id = operation.operation_id
              AND reservation.attempt_id = operation.attempt_id
              AND reservation.plan_id = operation.plan_id
              AND reservation.reservation_state = 'HELD'
              AND reservation.released_generation IS NULL
             JOIN preparation_comparisons AS comparison
               ON comparison.operation_id = operation.operation_id
             JOIN budget_scopes AS scope
               ON scope.scope_id = reservation.scope_id
              AND scope.scope_id = comparison.budget_scope_id
              AND scope.scope_generation = reservation.budget_generation
              AND scope.scope_generation = comparison.budget_scope_generation
             WHERE operation.operation_state = 'PREPARING'
             ORDER BY operation.operation_id",
        )
        .map_err(|_| "t080-prepared-query")?;
    let rows = statement
        .query_map([], |row| {
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
                row.get::<_, i64>(12)?,
                row.get::<_, i64>(13)?,
            ))
        })
        .map_err(|_| "t080-prepared-read")?;
    let mut bindings = Vec::with_capacity(2);
    for row in rows {
        let row = row.map_err(|_| "t080-prepared-row")?;
        bindings.push(PreparedDispatchBindingsV1 {
            operation_id: row.0,
            preparation_attempt_id: exact_array_v1(row.1)?,
            plan_id: exact_array_v1(row.2)?,
            preparation_transition_generation: u64::try_from(row.3)
                .map_err(|_| "t080-prepared-generation")?,
            task_id: row.4,
            workload_id: row.5,
            boot_id: row.6,
            instance_epoch: u64::try_from(row.7).map_err(|_| "t080-instance-epoch")?,
            supervisor_epoch: u64::try_from(row.8).map_err(|_| "t080-supervisor-epoch")?,
            reservation_id: row.9,
            task_lease_digest: exact_array_v1(row.10)?,
            recovery_mode: match row.11.as_str() {
                "COMPENSATION" => RecoveryModeV1::Compensation,
                "IRREVERSIBLE" => RecoveryModeV1::Irreversible,
                _ => return Err("t080-recovery-mode"),
            },
            budget_scope_generation: u64::try_from(row.12)
                .map_err(|_| "t080-budget-scope-generation")?,
            reservation_generation: u64::try_from(row.13)
                .map_err(|_| "t080-reservation-generation")?,
        });
    }
    Ok(bindings)
}

fn load_pending_grant_v1(
    database: &Path,
    operation_id: &str,
) -> Result<([u8; 32], Vec<u8>), &'static str> {
    let connection = open_read_connection_v1(database)?;
    let (grant_id, canonical_grant): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT grant.grant_id, grant.canonical_grant
             FROM dispatch_grants AS grant
             JOIN dispatch_records AS record
               ON record.operation_id = grant.operation_id
              AND record.grant_id = grant.grant_id
              AND record.effective_state = 'DISPATCHING'
             JOIN dispatch_outbox AS outbox
               ON outbox.grant_id = grant.grant_id
              AND outbox.operation_id = grant.operation_id
              AND outbox.delivery_state = 'PENDING'
              AND outbox.current_attempt_generation IS NULL
             WHERE grant.operation_id = ?1",
            [operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| "t080-pending-grant-query")?;
    if canonical_grant.is_empty() {
        return Err("t080-pending-grant-empty");
    }
    Ok((exact_array_v1(grant_id)?, canonical_grant))
}

fn verify_final_sqlite_projection_v1(
    coordinator_database: &Path,
    adapter_database: &Path,
) -> Result<T080ProductionCorpusEvidenceV1, &'static str> {
    let coordinator = open_read_connection_v1(coordinator_database)?;
    let coordinator_projection: (i64, i64, i64, i64, i64, i64, i64, i64) = coordinator
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM coordinator_v2_migrations),
                (SELECT COUNT(*) FROM dispatch_grants),
                (SELECT COUNT(*) FROM dispatch_records WHERE effective_state='EXECUTING'),
                (SELECT COUNT(*) FROM dispatch_records
                    WHERE effective_state='RECONCILIATION_REQUIRED'),
                (SELECT COUNT(*) FROM dispatch_receipts),
                ((SELECT COUNT(*) FROM dispatch_grants) -
                 (SELECT COUNT(DISTINCT operation_id) FROM dispatch_grants)),
                ((SELECT COUNT(*) FROM dispatch_delivery_attempts
                    WHERE classification = 'POSSIBLE_HANDOFF'
                      AND readback_generation IS NULL) -
                 (SELECT COUNT(DISTINCT grant_id) FROM dispatch_delivery_attempts
                    WHERE classification = 'POSSIBLE_HANDOFF'
                      AND readback_generation IS NULL)),
                (SELECT COUNT(*) FROM sqlite_master
                    WHERE lower(name) IN ('execution_tokens','host_effects'))",
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
                    row.get(7)?,
                ))
            },
        )
        .map_err(|_| "t080-final-coordinator-query")?;
    for (actual, expected, error) in [
        (coordinator_projection.0, 1, "t080-final-migration-count"),
        (coordinator_projection.1, 2, "t080-final-grant-count"),
        (coordinator_projection.2, 1, "t080-final-executing-count"),
        (
            coordinator_projection.3,
            1,
            "t080-final-reconciliation-count",
        ),
        (coordinator_projection.4, 1, "t080-final-receipt-count"),
        (
            coordinator_projection.5,
            0,
            "t080-final-replacement-grant-count",
        ),
        (
            coordinator_projection.6,
            0,
            "t080-final-automatic-redelivery-count",
        ),
        (
            coordinator_projection.7,
            0,
            "t080-final-execution-authority-count",
        ),
    ] {
        if actual != expected {
            return Err(error);
        }
    }
    let adapter = open_read_connection_v1(adapter_database)?;
    let adapter_projection: (i64, i64, i64, i64) = adapter
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM grant_inbox),
                (SELECT COUNT(*) FROM grant_inbox WHERE inbox_state='CONSUMED'),
                (SELECT COUNT(*) FROM execution_receipts WHERE decision='CONSUMED'),
                (SELECT COUNT(*) FROM inbox_transitions)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| "t080-final-adapter-query")?;
    if adapter_projection != (1, 1, 1, 2) {
        return Err("t080-final-adapter-projection");
    }
    Ok(T080ProductionCorpusEvidenceV1::new_v1(
        measured_count_v1(coordinator_projection.0)?,
        measured_count_v1(coordinator_projection.1)?,
        measured_count_v1(coordinator_projection.2)?,
        measured_count_v1(coordinator_projection.3)?,
        measured_count_v1(coordinator_projection.4)?,
        measured_count_v1(adapter_projection.0)?,
        measured_count_v1(adapter_projection.1)?,
        measured_count_v1(adapter_projection.2)?,
        measured_count_v1(adapter_projection.3)?,
        measured_count_v1(coordinator_projection.5)?,
        measured_count_v1(coordinator_projection.6)?,
        measured_count_v1(coordinator_projection.7)?,
    ))
}

fn measured_count_v1(value: i64) -> Result<u64, &'static str> {
    u64::try_from(value).map_err(|_| "t080-final-count-range")
}

fn open_read_connection_v1(database: &Path) -> Result<Connection, &'static str> {
    Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "t080-readonly-open")
}

struct PreparationFixtureV1 {
    case: ControlledBenchmarkCaseV1,
}

impl PreparationFixtureV1 {
    fn try_new_v1(
        sequence: u64,
        signer: &CorpusPlanSignerV1,
        clock: ControlledBenchmarkClockV1,
        deadline_monotonic_ms: u64,
    ) -> Result<Self, &'static str> {
        let signed =
            sign_plan_v1(plan_input_v1(sequence)?, signer).map_err(|_| "t080-plan-sign")?;
        let canonical = signed
            .to_canonical_json()
            .map_err(|_| "t080-plan-canonical")?;
        let authentic = decode_and_verify_plan(&canonical, &signer.resolver_v1())
            .map_err(|_| "t080-plan-verify")?;
        let case =
            build_controlled_benchmark_case_v1(authentic, clock, deadline_monotonic_ms, sequence)
                .map_err(|_| "t080-preparation-case")?;
        Ok(Self { case })
    }
}

fn plan_input_v1(sequence: u64) -> Result<PlanInputV1, &'static str> {
    let mut nonce = [0x80; 16];
    nonce[8..].copy_from_slice(&sequence.to_be_bytes());
    Ok(PlanInputV1 {
        operation_id: format!("operation:t080-{sequence:016x}"),
        task_id: format!("task:t080-{sequence:016x}"),
        workload_id: CONTROLLED_BENCHMARK_WORKLOAD_ID_V1.to_owned(),
        boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1.to_owned(),
        task_lease_digest: plan_digest_v1(b"task-lease", sequence),
        request_source_kind: RequestSourceKindV1::HumanRequestGrant,
        request_source_digest: plan_digest_v1(b"request-source", sequence),
        catalog_version: CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1.to_owned(),
        policy_version: CONTROLLED_BENCHMARK_POLICY_VERSION_V1.to_owned(),
        risk_level: RiskLevelV1::L2,
        target: ResourceRefV1::new(
            "vault-controlled-corpus",
            ["Public", "Controlled", "Corpus.md"],
        )
        .map_err(|_| "t080-plan-target")?,
        precondition: FilePreconditionInputV1 {
            volume_id: "volume:controlled-corpus".to_owned(),
            file_id: format!("file:t080-{sequence:016x}"),
            content_sha256: plan_digest_v1(b"precondition", sequence),
            byte_length: 7,
        },
        replacement_bytes: format!("after-{sequence:016x}\n").into_bytes(),
        replacement_media_type: "text/markdown".to_owned(),
        recovery: RecoveryInputV1 {
            class: RecoveryClassV1::Irreversible,
            atomicity: AtomicityV1::NonAtomic,
            reserved_bytes: 0,
        },
        capability_report_digest: plan_digest_v1(b"capability-report", sequence),
        capability_observed_at_unix_ms: CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1,
        required_capabilities: vec![
            "filesystem.verify-by-handle".to_owned(),
            "filesystem.atomic-replace".to_owned(),
        ],
        budget: BudgetInputV1 {
            reservation_id: format!("budget:t080-{sequence:016x}"),
            currency_code: "EUR".to_owned(),
            price_table_id: "price-table:controlled-corpus-v1".to_owned(),
            max_cost_micro_units: 0,
            action_limit: 1,
            egress_bytes_limit: 0,
        },
        issued_at_unix_ms: CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1,
        expires_at_unix_ms: CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
        nonce: Nonce128::from_bytes(nonce),
        instance_epoch: 1,
        fencing_epoch: 9,
    })
}

#[derive(Clone, Debug)]
struct CorpusCoordinatorClockV1(ControlledBenchmarkClockV1);

impl CoordinatorMonotonicClockV1 for CorpusCoordinatorClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        self.0
            .now_absolute_monotonic_ms_v1()
            .map_err(|_| CoordinatorClockUnavailableV1)
    }
}

struct CorpusPlanSignerV1 {
    key: SigningKey,
}

impl CorpusPlanSignerV1 {
    fn new_v1() -> Self {
        Self {
            key: SigningKey::from_bytes(&PLAN_SIGNING_KEY_BYTES),
        }
    }

    fn resolver_v1(&self) -> CorpusPlanResolverV1 {
        CorpusPlanResolverV1 {
            public_key: self.key.verifying_key().to_bytes(),
        }
    }
}

impl Ed25519Signer for CorpusPlanSignerV1 {
    fn key_id(&self) -> &str {
        CONTROLLED_BENCHMARK_KEY_ID_V1
    }

    fn sign_ed25519(&self, message: &[u8]) -> PlanContractResultV1<[u8; 64]> {
        Ok(self.key.sign(message).to_bytes())
    }
}

#[derive(Clone, Debug)]
struct CorpusPlanResolverV1 {
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for CorpusPlanResolverV1 {
    fn resolve_ed25519(&self, key_id: &str) -> Result<[u8; 32], ContractError> {
        if key_id == CONTROLLED_BENCHMARK_KEY_ID_V1 {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
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
    budget_scope_generation: u64,
    reservation_generation: u64,
}

impl fmt::Debug for PreparedDispatchBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDispatchBindingsV1")
            .finish_non_exhaustive()
    }
}

impl PreparedDispatchBindingsV1 {
    fn lookup_request_v1(
        &self,
        deadline_monotonic_ms: u64,
    ) -> Result<DispatchLookupRequestV1, &'static str> {
        DispatchLookupRequestV1::try_new(DispatchLookupRequestInputV1 {
            contract_version: DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
            operation_id: &self.operation_id,
            expected_plan_digest: self.plan_id,
            expected_preparation_attempt_digest: self.preparation_attempt_id,
            expected_preparation_transition_generation: self.preparation_transition_generation,
            caller_deadline_monotonic_ms: deadline_monotonic_ms,
        })
        .map_err(|_| "t080-dispatch-lookup")
    }
}

#[derive(Clone)]
struct AuthorityFixtureV1 {
    prepared: PreparedDispatchBindingsV1,
    sampled_monotonic_ms: u64,
    sampled_utc_ms: u64,
    deadline_monotonic_ms: u64,
}

impl AuthorityFixtureV1 {
    fn view_v1(&self, phase: DispatchAuthorityCapturePhaseV1) -> DispatchAuthorityViewV1 {
        DispatchAuthorityViewV1::try_new(DispatchAuthorityViewInputV1 {
            contract_version: DISPATCH_AUTHORITY_VIEW_VERSION_V1,
            phase,
            time: helix_plan_dispatch::DispatchTimeCaptureV1::new(
                identifier_v1(&self.prepared.boot_id),
                generation_v1(1),
                safe_v1(self.sampled_utc_ms),
                safe_v1(self.sampled_monotonic_ms),
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
            capability_observed_at_utc_ms: safe_v1(self.sampled_utc_ms),
            capability_max_age_ms: safe_v1(DISPATCH_LIFETIME_MS),
            adapter_capability_digest: Sha256Digest::from_bytes(ADAPTER_CAPABILITY_DIGEST),
            replay_claim_id: digest_byte_v1(11),
            replay_claimant_generation: generation_v1(1),
            replay_binding_digest: digest_byte_v1(12),
            budget_scope_id: identifier_v1("scope:t080-v1"),
            budget_scope_generation: generation_v1(self.prepared.budget_scope_generation),
            budget_scope_binding_digest: digest_byte_v1(13),
            reservation_id: identifier_v1(&self.prepared.reservation_id),
            reservation_generation: generation_v1(self.prepared.reservation_generation),
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
            earliest_authority_deadline_monotonic_ms: generation_v1(self.deadline_monotonic_ms),
        })
        .expect("T080 fixture is statically coherent")
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
        if now_monotonic_ms < self.authority.deadline_monotonic_ms {
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

struct SeededDispatchEntropyV1(u64);

impl DispatchEntropySourceV1 for SeededDispatchEntropyV1 {
    fn fill_entropy_v1(
        &self,
        domain: DispatchEntropyDomainV1,
        destination: &mut [u8],
    ) -> Result<(), DispatchEntropyErrorV1> {
        for (block, chunk) in destination.chunks_mut(32).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(b"HELIXOS\0T080-DISPATCH-ENTROPY\0V1\0");
            hasher.update(self.0.to_be_bytes());
            hasher.update([dispatch_entropy_domain_tag_v1(domain)]);
            hasher.update((block as u64).to_be_bytes());
            let digest = hasher.finalize();
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
        Ok(())
    }
}

struct CorpusRetainedReceiptV1 {
    canonical_receipt: Vec<u8>,
    receipt_generation: u64,
}

struct CorpusAdapterReadbackV1<'store> {
    store: &'store SqliteDispatchInboxStoreV1,
    grant_resolver: &'store DispatchGrantResolverV1,
    receipt_resolver: &'store ReceiptKeysV1,
    calls: AtomicU64,
}

impl<'store> CorpusAdapterReadbackV1<'store> {
    fn new_v1(
        store: &'store SqliteDispatchInboxStoreV1,
        grant_resolver: &'store DispatchGrantResolverV1,
        receipt_resolver: &'store ReceiptKeysV1,
    ) -> Self {
        Self {
            store,
            grant_resolver,
            receipt_resolver,
            calls: AtomicU64::new(0),
        }
    }

    fn call_count_v1(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl DispatchInboxReadbackV1 for CorpusAdapterReadbackV1<'_> {
    type RetainedState = ();
    type RetainedReceipt = CorpusRetainedReceiptV1;

    fn readback_grant_v1(
        &self,
        grant_binding: &[u8; 32],
    ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.store.readback_grant_v1(
            Sha256Digest::from_bytes(*grant_binding),
            self.grant_resolver,
            self.receipt_resolver,
        ) {
            Ok(AdapterInboxReadbackOutcomeV1::Absent) => DispatchInboxReadbackOutcomeV1::Absent,
            Ok(AdapterInboxReadbackOutcomeV1::Received(_)) => {
                DispatchInboxReadbackOutcomeV1::Received(())
            }
            Ok(AdapterInboxReadbackOutcomeV1::RetainedReceipt(receipt)) => {
                DispatchInboxReadbackOutcomeV1::RetainedReceipt(CorpusRetainedReceiptV1 {
                    canonical_receipt: receipt.canonical_receipt().to_vec(),
                    receipt_generation: receipt.receipt_generation(),
                })
            }
            Ok(AdapterInboxReadbackOutcomeV1::Conflict) => DispatchInboxReadbackOutcomeV1::Conflict,
            Ok(AdapterInboxReadbackOutcomeV1::Quarantined) => {
                DispatchInboxReadbackOutcomeV1::Quarantined
            }
            Err(AdapterInboxReadbackErrorV1::StoreBusy)
            | Err(AdapterInboxReadbackErrorV1::StoreUnavailable) => {
                DispatchInboxReadbackOutcomeV1::Unavailable
            }
            Err(AdapterInboxReadbackErrorV1::GrantUnverifiable)
            | Err(AdapterInboxReadbackErrorV1::ReceiptUnverifiable)
            | Err(AdapterInboxReadbackErrorV1::InvariantFailed) => {
                DispatchInboxReadbackOutcomeV1::Unhealthy
            }
        }
    }
}

#[derive(Default)]
struct CorpusAutomaticReadbackScheduleV1 {
    observations: Vec<(u64, u64)>,
}

impl CorpusAutomaticReadbackScheduleV1 {
    fn require_offsets_v1(
        &self,
        first_observation_monotonic_ms: u64,
        expected_offsets_ms: &[u64],
    ) -> Result<(), &'static str> {
        if self.observations.len() != expected_offsets_ms.len() {
            return Err("t080-readback-offset-count");
        }
        let expected_end = first_observation_monotonic_ms
            .checked_add(500)
            .ok_or("t080-readback-effective-end")?;
        for ((requested, effective_end), offset) in
            self.observations.iter().zip(expected_offsets_ms)
        {
            if *requested
                != first_observation_monotonic_ms
                    .checked_add(*offset)
                    .ok_or("t080-readback-offset")?
                || *effective_end != expected_end
            {
                return Err("t080-readback-offset-drift");
            }
        }
        Ok(())
    }

    fn transcript_digest_v1(&self, grant_binding: [u8; 32], readback_calls: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"HELIXOS\0T080-AUTOMATIC-READBACK-TRANSCRIPT\0V1\0");
        hasher.update(grant_binding);
        hasher.update(readback_calls.to_be_bytes());
        hasher.update((self.observations.len() as u64).to_be_bytes());
        for (requested, effective_end) in &self.observations {
            hasher.update(requested.to_be_bytes());
            hasher.update(effective_end.to_be_bytes());
            hasher.update(b"ABSENT");
        }
        hasher.finalize().into()
    }

    fn exhaustion_latency_ms_v1(
        &self,
        first_observation_monotonic_ms: u64,
    ) -> Result<u64, &'static str> {
        let (last_observation, _) = self
            .observations
            .last()
            .ok_or("t080-readback-transcript-empty")?;
        last_observation
            .checked_sub(first_observation_monotonic_ms)
            .ok_or("t080-readback-latency")
    }

    fn is_empty_v1(&self) -> bool {
        self.observations.is_empty()
    }
}

impl DispatchAutomaticReadbackScheduleV1 for CorpusAutomaticReadbackScheduleV1 {
    fn wait_until_readback_offset_v1(
        &mut self,
        requested_monotonic_ms: u64,
        effective_end_monotonic_ms: u64,
    ) -> DispatchReadbackWaitOutcomeV1 {
        self.observations
            .push((requested_monotonic_ms, effective_end_monotonic_ms));
        DispatchReadbackWaitOutcomeV1::ObservedAt(requested_monotonic_ms)
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

    fn sign_execution_grant(&self, message: &[u8]) -> DispatchContractResultV1<[u8; 64]> {
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

#[derive(Clone)]
struct DispatchGrantResolverV1 {
    verifying_key: [u8; 32],
}

impl DispatchGrantResolverV1 {
    fn fixed_v1() -> Self {
        Self {
            verifying_key: SigningKey::from_bytes(&DISPATCH_SIGNING_KEY_BYTES)
                .verifying_key()
                .to_bytes(),
        }
    }
}

impl GrantKeyResolver for DispatchGrantResolverV1 {
    fn resolve_grant_key(&self, key_id: &str) -> DispatchContractResultV1<GrantVerificationKeyV1> {
        if key_id == DISPATCH_SIGNER_KEY_ID {
            Ok(GrantVerificationKeyV1::current(self.verifying_key))
        } else {
            Err(DispatchContractErrorV1::UnknownKey)
        }
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

    fn sign_execution_receipt(&self, message: &[u8]) -> DispatchContractResultV1<[u8; 64]> {
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

impl ReceiptKeyResolver for ReceiptKeysV1 {
    fn resolve_receipt_key(
        &self,
        key_id: &str,
    ) -> DispatchContractResultV1<ReceiptVerificationKeyV1> {
        if key_id == RECEIPT_SIGNER_KEY_ID {
            Ok(ReceiptVerificationKeyV1::current(
                self.signing_key.verifying_key().to_bytes(),
            ))
        } else {
            Err(DispatchContractErrorV1::UnknownKey)
        }
    }
}

struct CoordinatorReceiptKeysV1 {
    grant: DispatchGrantResolverV1,
    receipt: ReceiptKeysV1,
}

impl GrantKeyResolver for CoordinatorReceiptKeysV1 {
    fn resolve_grant_key(&self, key_id: &str) -> DispatchContractResultV1<GrantVerificationKeyV1> {
        self.grant.resolve_grant_key(key_id)
    }
}

impl ReceiptKeyResolver for CoordinatorReceiptKeysV1 {
    fn resolve_receipt_key(
        &self,
        key_id: &str,
    ) -> DispatchContractResultV1<ReceiptVerificationKeyV1> {
        self.receipt.resolve_receipt_key(key_id)
    }
}

struct FixedAdapterClockV1 {
    boot_id: String,
    generation: u64,
    sampled_utc_ms: u64,
    sampled_monotonic_ms: u64,
}

impl FixedAdapterClockV1 {
    fn sample_v1(&self, generation: u64) -> AdapterTimeSampleV1 {
        AdapterTimeSampleV1::new(
            identifier_v1(&self.boot_id),
            generation_v1(generation),
            safe_v1(self.sampled_utc_ms),
            safe_v1(self.sampled_monotonic_ms),
        )
    }
}

impl AdapterClockV1 for FixedAdapterClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        AdapterClockObservationV1::Current(self.sample_v1(self.generation))
    }
}

struct FreshAdapterEpochObserverV1 {
    database: PathBuf,
    boot_id: String,
    supervisor_epoch: u64,
    sampled_utc_ms: u64,
    sampled_monotonic_ms: u64,
}

impl SupervisorEpochObserverV1 for FreshAdapterEpochObserverV1 {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
        let Ok(connection) = open_read_connection_v1(&self.database) else {
            return SupervisorEpochObservationV1::Unavailable;
        };
        let Ok(watermark) = connection.query_row(
            "SELECT epoch_observer_generation FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            return SupervisorEpochObservationV1::Unreadable;
        };
        let Some(next) = u64::try_from(watermark)
            .ok()
            .and_then(|value| value.checked_add(1))
        else {
            return SupervisorEpochObservationV1::Stale;
        };
        let sample = AdapterTimeSampleV1::new(
            identifier_v1(&self.boot_id),
            generation_v1(next),
            safe_v1(self.sampled_utc_ms),
            safe_v1(self.sampled_monotonic_ms),
        );
        SupervisorEpochObservationV1::Current(EpochObservationV1::new(
            safe_v1(self.supervisor_epoch),
            generation_v1(next),
            sample,
        ))
    }
}

struct RunningAdmissionV1;

impl AdapterConsumptionAdmissionObserverV1 for RunningAdmissionV1 {
    fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1 {
        AdapterConsumptionAdmissionObservationV1::Running
    }
}

struct SeededReceiptEntropyV1(u64);

impl AdapterReceiptEntropyV1 for SeededReceiptEntropyV1 {
    fn fill_receipt_entropy_v1(
        &self,
        domain: AdapterReceiptEntropyDomainV1,
        destination: &mut [u8; 32],
    ) -> Result<(), AdapterReceiptEntropyErrorV1> {
        if domain != AdapterReceiptEntropyDomainV1::ReceiptIdentity {
            return Err(AdapterReceiptEntropyErrorV1::Unsupported);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"HELIXOS\0T080-RECEIPT-ENTROPY\0V1\0");
        hasher.update(self.0.to_be_bytes());
        destination.copy_from_slice(&hasher.finalize());
        Ok(())
    }
}

struct LiveHandoffGuardV1 {
    binding: [u8; 32],
    deadline_monotonic_ms: u64,
}

impl DispatchHandoffGuardV1 for LiveHandoffGuardV1 {
    fn evidence_binding_v1(&self) -> [u8; 32] {
        self.binding
    }

    fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchHandoffValidationV1 {
        if now_monotonic_ms < self.deadline_monotonic_ms {
            DispatchHandoffValidationV1::Live
        } else {
            DispatchHandoffValidationV1::DeadlineReached
        }
    }

    fn release_v1(self) {}
}

struct ConsumeThenLoseAckTransportV1<'store> {
    store: &'store SqliteDispatchInboxStoreV1,
    database: PathBuf,
    boot_id: String,
    supervisor_epoch: u64,
    sampled_utc_ms: u64,
    sampled_monotonic_ms: u64,
    grant_resolver: DispatchGrantResolverV1,
    receipt_keys: ReceiptKeysV1,
    canonical_receipt: Mutex<Option<Vec<u8>>>,
    consume_calls: AtomicU64,
}

impl ConsumeThenLoseAckTransportV1<'_> {
    fn retained_receipt_v1(&self) -> Result<Vec<u8>, &'static str> {
        self.canonical_receipt
            .lock()
            .map_err(|_| "t080-lost-ack-receipt-lock")?
            .clone()
            .ok_or("t080-lost-ack-receipt-missing")
    }
}

impl DispatchTransportV1 for ConsumeThenLoseAckTransportV1<'_> {
    type Guard = LiveHandoffGuardV1;
    type Response = ();

    fn acquire_handoff_guard_v1(
        &self,
        grant_binding: &[u8; 32],
        deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
        Ok(LiveHandoffGuardV1 {
            binding: *grant_binding,
            deadline_monotonic_ms,
        })
    }

    fn deliver_exact_v1(
        &self,
        _guard: &mut Self::Guard,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response> {
        let clock = FixedAdapterClockV1 {
            boot_id: self.boot_id.clone(),
            generation: 1,
            sampled_utc_ms: self.sampled_utc_ms,
            sampled_monotonic_ms: self.sampled_monotonic_ms,
        };
        let observer = FreshAdapterEpochObserverV1 {
            database: self.database.clone(),
            boot_id: self.boot_id.clone(),
            supervisor_epoch: self.supervisor_epoch,
            sampled_utc_ms: self.sampled_utc_ms,
            sampled_monotonic_ms: self.sampled_monotonic_ms,
        };
        let Ok(AdapterInboxReceiveOutcomeV1::Received(received)) = self.store.receive_grant_v1(
            exact_signed_grant_bytes,
            &self.grant_resolver,
            &clock,
            &observer,
        ) else {
            return DispatchHandoffOutcomeV1::PossibleHandoff;
        };
        self.consume_calls.fetch_add(1, Ordering::SeqCst);
        let Ok(signing_profile) = receipt_signing_profile_v1(&self.receipt_keys) else {
            return DispatchHandoffOutcomeV1::PossibleHandoff;
        };
        let Ok(AdapterInboxConsumeOutcomeV1::Consumed(receipt)) = self.store.consume_received_v1(
            received,
            &self.grant_resolver,
            &clock,
            &observer,
            &RunningAdmissionV1,
            &SeededReceiptEntropyV1(1),
            &signing_profile,
            &self.receipt_keys,
            &self.receipt_keys,
        ) else {
            return DispatchHandoffOutcomeV1::PossibleHandoff;
        };
        if let Ok(mut retained) = self.canonical_receipt.lock() {
            *retained = Some(receipt.canonical_receipt().to_vec());
        }
        // The adapter durable commit happened, but its acknowledgement is intentionally lost.
        DispatchHandoffOutcomeV1::PossibleHandoff
    }
}

/// Commits the adapter receive, then deliberately loses the handoff acknowledgement.
struct ReceiveThenLoseAckTransportV1<'store> {
    store: &'store SqliteDispatchInboxStoreV1,
    database: PathBuf,
    boot_id: String,
    supervisor_epoch: u64,
    sampled_utc_ms: u64,
    sampled_monotonic_ms: u64,
    grant_resolver: DispatchGrantResolverV1,
    receive_calls: AtomicU64,
}

impl DispatchTransportV1 for ReceiveThenLoseAckTransportV1<'_> {
    type Guard = LiveHandoffGuardV1;
    type Response = ();

    fn acquire_handoff_guard_v1(
        &self,
        grant_binding: &[u8; 32],
        deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
        Ok(LiveHandoffGuardV1 {
            binding: *grant_binding,
            deadline_monotonic_ms,
        })
    }

    fn deliver_exact_v1(
        &self,
        _guard: &mut Self::Guard,
        exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response> {
        let clock = FixedAdapterClockV1 {
            boot_id: self.boot_id.clone(),
            generation: 1,
            sampled_utc_ms: self.sampled_utc_ms,
            sampled_monotonic_ms: self.sampled_monotonic_ms,
        };
        let observer = FreshAdapterEpochObserverV1 {
            database: self.database.clone(),
            boot_id: self.boot_id.clone(),
            supervisor_epoch: self.supervisor_epoch,
            sampled_utc_ms: self.sampled_utc_ms,
            sampled_monotonic_ms: self.sampled_monotonic_ms,
        };
        if matches!(
            self.store.receive_grant_v1(
                exact_signed_grant_bytes,
                &self.grant_resolver,
                &clock,
                &observer,
            ),
            Ok(AdapterInboxReceiveOutcomeV1::Received(_))
        ) {
            self.receive_calls.fetch_add(1, Ordering::SeqCst);
        }
        DispatchHandoffOutcomeV1::PossibleHandoff
    }
}

struct PossibleHandoffWithoutDeliveryV1;

impl DispatchTransportV1 for PossibleHandoffWithoutDeliveryV1 {
    type Guard = LiveHandoffGuardV1;
    type Response = ();

    fn acquire_handoff_guard_v1(
        &self,
        grant_binding: &[u8; 32],
        deadline_monotonic_ms: u64,
    ) -> Result<Self::Guard, DispatchHandoffValidationV1> {
        Ok(LiveHandoffGuardV1 {
            binding: *grant_binding,
            deadline_monotonic_ms,
        })
    }

    fn deliver_exact_v1(
        &self,
        _guard: &mut Self::Guard,
        _exact_signed_grant_bytes: &[u8],
    ) -> DispatchHandoffOutcomeV1<Self::Response> {
        DispatchHandoffOutcomeV1::PossibleHandoff
    }
}

struct CorpusRootsV1 {
    coordinator: PathBuf,
    adapter: PathBuf,
    backup: PathBuf,
}

impl CorpusRootsV1 {
    fn reserve_v1() -> Result<Self, &'static str> {
        for _ in 0..32 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "t080-temp-clock")?
                .as_nanos();
            let base = std::env::temp_dir().join(format!(
                "helixos-t080-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            let coordinator = base.with_extension("coordinator");
            let adapter = base.with_extension("adapter");
            let backup = base.with_extension("backup");
            if !coordinator.exists() && !adapter.exists() && !backup.exists() {
                return Ok(Self {
                    coordinator,
                    adapter,
                    backup,
                });
            }
        }
        Err("t080-temp-root-exhausted")
    }

    fn coordinator(&self) -> &Path {
        &self.coordinator
    }

    fn adapter(&self) -> &Path {
        &self.adapter
    }

    fn backup(&self) -> &Path {
        &self.backup
    }
}

impl Drop for CorpusRootsV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.coordinator);
        let _ = fs::remove_dir_all(&self.adapter);
        let _ = fs::remove_dir_all(&self.backup);
    }
}

fn controlled_utc_from_monotonic_v1(monotonic_ms: u64) -> Result<u64, &'static str> {
    let elapsed = monotonic_ms
        .checked_sub(CONTROLLED_BASE_MONOTONIC_MS)
        .ok_or("t080-controlled-monotonic-regressed")?;
    CONTROLLED_BASE_UTC_MS
        .checked_add(elapsed)
        .ok_or("t080-controlled-utc-overflow")
}

fn plan_digest_v1(domain: &[u8], sequence: u64) -> PlanSha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"HELIXOS\0T080-PLAN-FIXTURE\0V1\0");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(sequence.to_be_bytes());
    PlanSha256Digest::from_bytes(hasher.finalize().into())
}

fn dispatch_entropy_domain_tag_v1(domain: DispatchEntropyDomainV1) -> u8 {
    match domain {
        DispatchEntropyDomainV1::AttemptIdentity => 1,
        DispatchEntropyDomainV1::GrantIdentity => 2,
        DispatchEntropyDomainV1::OneShotNonce => 3,
        DispatchEntropyDomainV1::TraceIdentity => 4,
    }
}

fn exact_array_v1(bytes: Vec<u8>) -> Result<[u8; 32], &'static str> {
    bytes.try_into().map_err(|_| "t080-binding-length")
}

fn identifier_v1(value: &str) -> Identifier {
    Identifier::new(value).expect("T080 static identifier is valid")
}

fn generation_v1(value: u64) -> Generation {
    Generation::new(value).expect("T080 static generation is valid")
}

fn safe_v1(value: u64) -> SafeU64 {
    SafeU64::new(value).expect("T080 static safe integer is valid")
}

fn digest_byte_v1(value: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([value; 32])
}

fn dispatch_key_fingerprint_v1() -> Sha256Digest {
    Sha256Digest::digest(&DispatchGrantResolverV1::fixed_v1().verifying_key)
}
