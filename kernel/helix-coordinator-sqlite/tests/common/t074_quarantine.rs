//! Explicit T074 quarantine-and-retirement process workflow.

use crate::common::{
    SyntheticCoordinatorClockV1, SyntheticHistoricalPlanKeyResolverV1,
    SyntheticManifestLastRecoveryProviderV1, SyntheticRecoveryGuardOutcomeV1,
    SYNTHETIC_BUDGET_RECOVERY_BYTES,
};
use crate::failure::{
    fail_synthetic_before_dispatch_v1, SyntheticKnownFailureCaseV1, SyntheticNoDispatchGuardCaseV1,
};
use crate::prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use crate::quarantine::{
    authorize_orphan_retirement_with_fault_probe_v1, retain_synthetic_orphan_with_fault_probe_v1,
    OrphanRetirementAuthorizationInputV1, OrphanRetirementAuthorizationOutcomeV1,
    SyntheticOrphanInputV1,
};
use crate::retirement::{
    retire_synthetic_operation_bound_with_fault_probe_v1,
    retire_synthetic_orphan_with_fault_probe_v1, SyntheticOperationRetirementInputV1,
    SyntheticOrphanRetirementInputV1, SyntheticRetirementOutcomeV1, SyntheticRetirementStepV1,
};
use helix_contracts::Sha256Digest;
use helix_coordinator_sqlite::{
    CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1, SqliteCoordinatorStoreV1,
};
use helix_plan_preparation::{PreparationCommitOutcomeV1, PreparationFailureOutcomeV1};
use rusqlite::{Connection, OpenFlags};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const COORDINATOR_ROOT_DIRECTORY: &str = "coordinator-root-v1";
const COORDINATOR_IDENTITY_FILE: &str = "coordinator-root-identity-v1";
const COORDINATOR_DATABASE_FILE: &str = "coordinator.sqlite3";
const RECOVERY_PROVIDER_DIRECTORY: &str = "recovery-provider-v1";
const OPEN_NOW_MS: u64 = 1_000;
const OPEN_DEADLINE_MS: u64 = 10_000;
const FAILURE_REVOCATION_GENERATION: u64 = 17;
const FAILURE_GUARD_DEADLINE_MS: u64 = 10_000;
const RECOVERY_GUARD_DEADLINE_MS: u64 = 10_000;
const SYNTHETIC_MANIFEST_DOMAIN_V1: &[u8] = b"HELIXOS\0SYNTHETIC-RECOVERY-MANIFEST\0V1\0";
const SYNTHETIC_RETIREMENT_DOMAIN_V1: &[u8] = b"HELIXOS\0SYNTHETIC-RECOVERY-RETIREMENT\0V1\0";
const SYNTHETIC_MATERIAL_V1: &[u8] = b"before\n";

const ORPHAN_BOUNDARIES: [&str; 5] = [
    "quarantine_and_retirement_quarantine_inserted",
    "quarantine_and_retirement_quarantine_resolved",
    "quarantine_and_retirement_true_orphan_definitive_proof_returned",
    "quarantine_and_retirement_orphan_resolution_retirement_pending_tombstone_committed",
    "quarantine_and_retirement_orphan_retired_tombstone_committed",
];

const OPERATION_BOUNDARIES: [&str; 2] = [
    "quarantine_and_retirement_operation_bound_retirement_pending_committed",
    "quarantine_and_retirement_operation_bound_retired_tombstone_committed",
];

const PROVIDER_BOUNDARIES: [&str; 3] = [
    "quarantine_and_retirement_provider_retirement_invoked",
    "quarantine_and_retirement_provider_bytes_retired",
    "quarantine_and_retirement_retirement_manifest_published",
];

type ProcessBarrierV1 = Arc<dyn Fn() + Send + Sync>;

pub(crate) fn supports_boundary_v1(boundary_id: &str) -> bool {
    ORPHAN_BOUNDARIES.contains(&boundary_id)
        || OPERATION_BOUNDARIES.contains(&boundary_id)
        || PROVIDER_BOUNDARIES.contains(&boundary_id)
}

pub(crate) fn prepare_fixture_v1(protocol_root: &Path) -> Result<(), &'static str> {
    let protocol_root = canonical_protocol_root_v1(protocol_root)?;
    let coordinator_root = protocol_root.join(COORDINATOR_ROOT_DIRECTORY);
    create_exact_directory_v1(&coordinator_root)?;
    let recovery_root = protocol_root.join(RECOVERY_PROVIDER_DIRECTORY);
    create_exact_directory_v1(&recovery_root)?;

    let config = CoordinatorStoreConfigV1::try_new_empty_attested(coordinator_root, 50)
        .map_err(|_| "coordinator-config-invalid")?;
    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
        SyntheticHistoricalPlanKeyResolverV1::default(),
        OPEN_DEADLINE_MS,
    )
    .map_err(|_| "coordinator-initialize-failed")?;
    let identity = store.root_identity_evidence().to_attested_bytes();
    drop(store);
    write_create_new_synced_v1(&protocol_root.join(COORDINATOR_IDENTITY_FILE), &identity)
}

pub(crate) fn run_boundary_v1(
    protocol_root: &Path,
    boundary_id: &str,
    occurrence: u64,
    process_barrier: ProcessBarrierV1,
) -> Result<(), &'static str> {
    if !supports_boundary_v1(boundary_id) || occurrence != 1 {
        return Err("quarantine-boundary-unsupported");
    }
    let protocol_root = canonical_protocol_root_v1(protocol_root)?;
    let transaction_probe =
        selected_transaction_probe_v1(boundary_id, occurrence, Arc::clone(&process_barrier))?;
    let provider_probe = selected_provider_probe_v1(boundary_id, occurrence, process_barrier)?;
    let recovery_root = protocol_root.join(RECOVERY_PROVIDER_DIRECTORY);
    let provider = SyntheticManifestLastRecoveryProviderV1::open_v1(recovery_root)
        .map_err(|_| "recovery-provider-open-failed")?
        .with_fault_probe_v1(provider_probe);
    let database = protocol_root
        .join(COORDINATOR_ROOT_DIRECTORY)
        .join(COORDINATOR_DATABASE_FILE);

    if ORPHAN_BOUNDARIES.contains(&boundary_id) {
        run_orphan_branch_v1(&database, &provider, &transaction_probe)
    } else {
        run_operation_branch_v1(&database, &provider, &transaction_probe)
    }
}

pub(crate) fn reopen_state_v1(protocol_root: &Path) -> Result<&'static [u8], &'static str> {
    let protocol_root = canonical_protocol_root_v1(protocol_root)?;
    let identity_bytes = fs::read(protocol_root.join(COORDINATOR_IDENTITY_FILE))
        .map_err(|_| "coordinator-identity-read-failed")?;
    let identity_bytes: [u8; 32] = identity_bytes
        .try_into()
        .map_err(|_| "coordinator-identity-invalid")?;
    let coordinator_root = protocol_root.join(COORDINATOR_ROOT_DIRECTORY);
    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        coordinator_root.clone(),
        CoordinatorRootIdentityEvidenceV1::from_attested_bytes(identity_bytes),
        50,
    )
    .map_err(|_| "coordinator-reopen-config-invalid")?;
    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        SyntheticCoordinatorClockV1::new(OPEN_NOW_MS + 1),
        SyntheticHistoricalPlanKeyResolverV1::default(),
        OPEN_DEADLINE_MS,
    )
    .map_err(|_| "coordinator-full-reopen-failed")?;
    let verified_operation_count = store.operation_count();
    drop(store);
    let database = protocol_root
        .join(COORDINATOR_ROOT_DIRECTORY)
        .join(COORDINATOR_DATABASE_FILE);
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "coordinator-reopen-failed")?;
    let (total, preparing, failed, quarantines, orphan_retired, non_retired_recovery): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = connection
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM prepared_operations),
                 (SELECT COUNT(*) FROM prepared_operations WHERE operation_state = 'PREPARING'),
                 (SELECT COUNT(*) FROM prepared_operations WHERE operation_state = 'FAILED'),
                 (SELECT COUNT(*) FROM preparation_quarantines),
                 (SELECT COUNT(*) FROM preparation_quarantines
                    WHERE orphan_retirement_state = 'RETIRED_TOMBSTONE'),
                 (SELECT COUNT(*) FROM preparation_recovery_evidence
                    WHERE material_state <> 'RETIRED_TOMBSTONE')",
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
        .map_err(|_| "coordinator-reopen-classification-failed")?;
    if total < 0 || u64::try_from(total).ok() != Some(verified_operation_count) {
        return Err("coordinator-reopen-count-invalid");
    }
    let provider_artifacts = recovery_provider_has_artifacts_v1(&protocol_root)?;
    if quarantines > 0 {
        if quarantines == 1 && orphan_retired == 1 && total == 0 {
            return if retired_orphan_provider_is_exact_v1(&connection, &protocol_root)? {
                Ok(b"absent")
            } else {
                Err("retired-orphan-provider-invalid")
            };
        }
        return Ok(b"quarantine");
    }
    let retired_provider_exact =
        if quarantines == 0 && non_retired_recovery == 0 && total > 0 && total == failed {
            retired_provider_is_exact_v1(&connection, &protocol_root)?
        } else {
            false
        };
    match (
        non_retired_recovery,
        provider_artifacts,
        retired_provider_exact,
        total,
        preparing,
        failed,
    ) {
        (1.., _, _, _, _, _) => Ok(b"quarantine"),
        (0, true, false, 0, 0, 0) => Ok(b"quarantine"),
        (0, false, false, 0, 0, 0) => Ok(b"absent"),
        (0, _, false, total, preparing, 0) if total > 0 && total == preparing => Ok(b"preparing"),
        (0, true, true, total, 0, failed) if total > 0 && total == failed => Ok(b"failed"),
        _ => Err("coordinator-reopen-state-invalid"),
    }
}

fn recovery_provider_has_artifacts_v1(protocol_root: &Path) -> Result<bool, &'static str> {
    let provider_root = protocol_root.join(RECOVERY_PROVIDER_DIRECTORY);
    let metadata =
        fs::symlink_metadata(&provider_root).map_err(|_| "recovery-provider-reopen-failed")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("recovery-provider-root-invalid");
    }
    let package_root = provider_root.join("packages-v1");
    let metadata =
        fs::symlink_metadata(&package_root).map_err(|_| "recovery-provider-packages-missing")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("recovery-provider-packages-invalid");
    }
    let mut has_artifacts = false;
    for entry in fs::read_dir(package_root).map_err(|_| "recovery-provider-packages-unreadable")? {
        let entry = entry.map_err(|_| "recovery-provider-package-unreadable")?;
        let file_type = entry
            .file_type()
            .map_err(|_| "recovery-provider-package-unreadable")?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err("recovery-provider-package-invalid");
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "recovery-provider-package-invalid")?;
        if ![".material", ".manifest", ".retirement", ".staging"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        {
            return Err("recovery-provider-package-invalid");
        }
        has_artifacts = true;
    }
    Ok(has_artifacts)
}

fn retired_provider_is_exact_v1(
    connection: &Connection,
    protocol_root: &Path,
) -> Result<bool, &'static str> {
    let row: (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT manifest_digest, material_digest, material_length, reserved_capacity,
                    retirement_id, retirement_manifest_digest
               FROM preparation_recovery_evidence
              WHERE material_state = 'RETIRED_TOMBSTONE'",
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
        .map_err(|_| "retired-provider-binding-missing")?;
    let manifest_digest = digest_from_bytes_v1(row.0)?;
    let material_digest = digest_from_bytes_v1(row.1)?;
    let material_length = u64::try_from(row.2).map_err(|_| "retired-provider-binding-invalid")?;
    let reserved_capacity = u64::try_from(row.3).map_err(|_| "retired-provider-binding-invalid")?;
    let retirement_id = digest_from_bytes_v1(row.4)?;
    let retained_retirement_digest = digest_from_bytes_v1(row.5)?;

    let binding_hex = lowercase_hex_v1(manifest_digest.as_bytes());
    let package_root = protocol_root
        .join(RECOVERY_PROVIDER_DIRECTORY)
        .join("packages-v1");
    let manifest_path = package_root.join(format!("{binding_hex}.manifest"));
    let retirement_path = package_root.join(format!("{binding_hex}.retirement"));
    let material_path = package_root.join(format!("{binding_hex}.material"));
    if material_path.exists() {
        return Ok(false);
    }
    let manifest = fs::read(&manifest_path).map_err(|_| "retired-provider-manifest-missing")?;
    let mut expected_manifest = Vec::with_capacity(160);
    expected_manifest.extend_from_slice(SYNTHETIC_MANIFEST_DOMAIN_V1);
    expected_manifest.extend_from_slice(manifest_digest.as_bytes());
    expected_manifest.extend_from_slice(material_digest.as_bytes());
    expected_manifest.extend_from_slice(&material_length.to_be_bytes());
    expected_manifest.extend_from_slice(&reserved_capacity.to_be_bytes());
    if manifest != expected_manifest {
        return Ok(false);
    }
    let mut expected_retirement = Vec::with_capacity(128);
    expected_retirement.extend_from_slice(SYNTHETIC_RETIREMENT_DOMAIN_V1);
    expected_retirement.extend_from_slice(manifest_digest.as_bytes());
    expected_retirement.extend_from_slice(retirement_id.as_bytes());
    expected_retirement.extend_from_slice(Sha256Digest::digest(&manifest).as_bytes());
    let retirement =
        fs::read(&retirement_path).map_err(|_| "retired-provider-tombstone-missing")?;
    if retirement != expected_retirement
        || Sha256Digest::digest(&retirement) != retained_retirement_digest
    {
        return Ok(false);
    }
    let expected_names = [
        format!("{binding_hex}.manifest"),
        format!("{binding_hex}.retirement"),
    ];
    let mut observed_names = fs::read_dir(package_root)
        .map_err(|_| "retired-provider-packages-unreadable")?
        .map(|entry| {
            entry
                .map_err(|_| "retired-provider-package-unreadable")?
                .file_name()
                .into_string()
                .map_err(|_| "retired-provider-package-invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    observed_names.sort();
    let mut expected_names = expected_names;
    expected_names.sort();
    Ok(observed_names == expected_names)
}

fn retired_orphan_provider_is_exact_v1(
    connection: &Connection,
    protocol_root: &Path,
) -> Result<bool, &'static str> {
    let row: (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT recovery_manifest_digest, orphan_retirement_id,
                    orphan_retirement_manifest_digest
               FROM preparation_quarantines
              WHERE quarantine_status = 'RESOLVED_TOMBSTONE'
                AND quarantine_reason = 'ORPHAN_MATERIAL'
                AND orphan_retirement_state = 'RETIRED_TOMBSTONE'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| "retired-orphan-provider-binding-missing")?;
    let manifest_digest = digest_from_bytes_v1(row.0)?;
    let retirement_id = digest_from_bytes_v1(row.1)?;
    let retained_retirement_digest = digest_from_bytes_v1(row.2)?;

    let binding_hex = lowercase_hex_v1(manifest_digest.as_bytes());
    let package_root = protocol_root
        .join(RECOVERY_PROVIDER_DIRECTORY)
        .join("packages-v1");
    let manifest_path = package_root.join(format!("{binding_hex}.manifest"));
    let retirement_path = package_root.join(format!("{binding_hex}.retirement"));
    let material_path = package_root.join(format!("{binding_hex}.material"));
    if material_path.exists() {
        return Ok(false);
    }

    let material_digest = Sha256Digest::digest(SYNTHETIC_MATERIAL_V1);
    let mut expected_manifest = Vec::with_capacity(160);
    expected_manifest.extend_from_slice(SYNTHETIC_MANIFEST_DOMAIN_V1);
    expected_manifest.extend_from_slice(manifest_digest.as_bytes());
    expected_manifest.extend_from_slice(material_digest.as_bytes());
    expected_manifest.extend_from_slice(
        &u64::try_from(SYNTHETIC_MATERIAL_V1.len())
            .map_err(|_| "retired-orphan-provider-binding-invalid")?
            .to_be_bytes(),
    );
    expected_manifest.extend_from_slice(&SYNTHETIC_BUDGET_RECOVERY_BYTES.to_be_bytes());
    let manifest =
        fs::read(&manifest_path).map_err(|_| "retired-orphan-provider-manifest-missing")?;
    if manifest != expected_manifest {
        return Ok(false);
    }

    let mut expected_retirement = Vec::with_capacity(128);
    expected_retirement.extend_from_slice(SYNTHETIC_RETIREMENT_DOMAIN_V1);
    expected_retirement.extend_from_slice(manifest_digest.as_bytes());
    expected_retirement.extend_from_slice(retirement_id.as_bytes());
    expected_retirement.extend_from_slice(Sha256Digest::digest(&manifest).as_bytes());
    let retirement =
        fs::read(&retirement_path).map_err(|_| "retired-orphan-provider-tombstone-missing")?;
    if retirement != expected_retirement
        || Sha256Digest::digest(&retirement) != retained_retirement_digest
    {
        return Ok(false);
    }

    let expected_names = [
        format!("{binding_hex}.manifest"),
        format!("{binding_hex}.retirement"),
    ];
    let mut observed_names = fs::read_dir(package_root)
        .map_err(|_| "retired-orphan-provider-packages-unreadable")?
        .map(|entry| {
            entry
                .map_err(|_| "retired-orphan-provider-package-unreadable")?
                .file_name()
                .into_string()
                .map_err(|_| "retired-orphan-provider-package-invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    observed_names.sort();
    let mut expected_names = expected_names;
    expected_names.sort();
    Ok(observed_names == expected_names)
}

fn digest_from_bytes_v1(bytes: Vec<u8>) -> Result<Sha256Digest, &'static str> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "retired-provider-binding-invalid")?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn lowercase_hex_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn run_orphan_branch_v1(
    database: &Path,
    provider: &SyntheticManifestLastRecoveryProviderV1,
    fault_probe: &crate::test_fault::FaultProbeV1,
) -> Result<(), &'static str> {
    let attempt_id = digest_v1(0x41);
    let operation_binding_digest = digest_v1(0x42);
    let recovery_manifest_digest = digest_v1(0x43);
    let retirement_id = digest_v1(0x44);
    let no_reference_digest = digest_v1(0x45);
    provider
        .publish_public_synthetic_v1(recovery_manifest_digest)
        .map_err(|_| "orphan-material-publication-failed")?;
    let mut connection = open_write_connection_v1(database)?;
    let custody = retain_synthetic_orphan_with_fault_probe_v1(
        &mut connection,
        &SyntheticOrphanInputV1 {
            attempt_id,
            operation_binding_digest,
            recovery_manifest_digest,
        },
        fault_probe,
    )
    .map_err(|_| "orphan-quarantine-failed")?;
    let mut cleanup_guard = match provider
        .acquire_cleanup_guard_v1(recovery_manifest_digest, RECOVERY_GUARD_DEADLINE_MS)
    {
        SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
        _ => return Err("orphan-cleanup-guard-failed"),
    };
    let authorization = authorize_orphan_retirement_with_fault_probe_v1(
        &mut connection,
        &OrphanRetirementAuthorizationInputV1 {
            quarantine_id: custody.quarantine_id(),
            retirement_id,
            no_reference_digest,
        },
        fault_probe,
    )
    .map_err(|_| "orphan-authorization-failed")?;
    if authorization != OrphanRetirementAuthorizationOutcomeV1::AuthorizedPending {
        return Err("orphan-authorization-not-pending");
    }
    let retirement_manifest_digest = provider
        .publish_retirement_tombstone_v1(
            &mut cleanup_guard,
            recovery_manifest_digest,
            retirement_id,
        )
        .map_err(|_| "orphan-provider-retirement-failed")?;
    let retired = retire_synthetic_orphan_with_fault_probe_v1(
        &mut connection,
        &SyntheticOrphanRetirementInputV1 {
            quarantine_id: custody.quarantine_id(),
            retirement_id,
            retirement_manifest_digest,
        },
        SyntheticRetirementStepV1::FinishTombstone,
        &mut cleanup_guard,
        fault_probe,
    );
    if retired != SyntheticRetirementOutcomeV1::Retired {
        return Err("orphan-retirement-not-committed");
    }
    Ok(())
}

fn run_operation_branch_v1(
    database: &Path,
    provider: &SyntheticManifestLastRecoveryProviderV1,
    fault_probe: &crate::test_fault::FaultProbeV1,
) -> Result<(), &'static str> {
    let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
    provision_synthetic_budget_scope_v1(database, &case)
        .map_err(|_| "operation-budget-scope-failed")?;
    if !matches!(
        commit_synthetic_preparation_v1(database, &case, SyntheticCommitModeV1::Acknowledged),
        PreparationCommitOutcomeV1::Committed(_)
    ) {
        return Err("operation-preparation-failed");
    }
    let operation_id = only_operation_id_v1(database)?;
    let known = SyntheticKnownFailureCaseV1::load_preparing_v1(
        database,
        &operation_id,
        FAILURE_REVOCATION_GENERATION,
        FAILURE_GUARD_DEADLINE_MS,
    )
    .map_err(|_| "operation-failure-binding-invalid")?;
    if !matches!(
        fail_synthetic_before_dispatch_v1(
            database,
            &known,
            SyntheticNoDispatchGuardCaseV1::Exact,
            OPEN_NOW_MS,
        ),
        PreparationFailureOutcomeV1::Failed
    ) {
        return Err("operation-failure-transition-failed");
    }
    let manifest_digest = only_recovery_manifest_v1(database)?;
    let retirement_id = digest_v1(0x51);
    provider
        .publish_public_synthetic_v1(manifest_digest)
        .map_err(|_| "operation-material-publication-failed")?;
    let mut cleanup_guard =
        match provider.acquire_cleanup_guard_v1(manifest_digest, RECOVERY_GUARD_DEADLINE_MS) {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
            _ => return Err("operation-cleanup-guard-failed"),
        };
    let mut connection = open_write_connection_v1(database)?;
    let begin = retire_synthetic_operation_bound_with_fault_probe_v1(
        &mut connection,
        &SyntheticOperationRetirementInputV1 {
            operation_id: &operation_id,
            retirement_id,
            retirement_manifest_digest: None,
        },
        SyntheticRetirementStepV1::BeginPending,
        &mut cleanup_guard,
        fault_probe,
    );
    if begin != SyntheticRetirementOutcomeV1::Pending {
        return Err("operation-retirement-not-pending");
    }
    let retirement_manifest_digest = provider
        .publish_retirement_tombstone_v1(&mut cleanup_guard, manifest_digest, retirement_id)
        .map_err(|_| "operation-provider-retirement-failed")?;
    let retired = retire_synthetic_operation_bound_with_fault_probe_v1(
        &mut connection,
        &SyntheticOperationRetirementInputV1 {
            operation_id: &operation_id,
            retirement_id,
            retirement_manifest_digest: Some(retirement_manifest_digest),
        },
        SyntheticRetirementStepV1::FinishTombstone,
        &mut cleanup_guard,
        fault_probe,
    );
    if retired != SyntheticRetirementOutcomeV1::Retired {
        return Err("operation-retirement-not-committed");
    }
    Ok(())
}

fn selected_transaction_probe_v1(
    boundary_id: &str,
    occurrence: u64,
    process_barrier: ProcessBarrierV1,
) -> Result<crate::test_fault::FaultProbeV1, &'static str> {
    if PROVIDER_BOUNDARIES.contains(&boundary_id) {
        return Ok(crate::test_fault::FaultProbeV1::disabled_v1());
    }
    let boundary = crate::test_fault::FaultBoundaryV1::ALL
        .iter()
        .copied()
        .find(|candidate| candidate.id() == boundary_id)
        .ok_or("transaction-boundary-invalid")?;
    let selection = crate::test_fault::FaultSelectionV1::try_new(
        boundary,
        occurrence,
        crate::test_fault::FaultEffectV1::ProcessBarrier,
    )
    .map_err(|_| "transaction-occurrence-invalid")?;
    Ok(
        crate::test_fault::FaultProbeV1::selected_process_barrier_v1(
            selection,
            Box::new(move || process_barrier()),
        ),
    )
}

fn selected_provider_probe_v1(
    boundary_id: &str,
    occurrence: u64,
    process_barrier: ProcessBarrierV1,
) -> Result<crate::common::recovery_test_fault::FaultProbeV1, &'static str> {
    if !PROVIDER_BOUNDARIES.contains(&boundary_id) {
        return Ok(crate::common::recovery_test_fault::FaultProbeV1::disabled_v1());
    }
    let boundary = crate::common::recovery_test_fault::FaultBoundaryV1::ALL
        .iter()
        .copied()
        .find(|candidate| candidate.id() == boundary_id)
        .ok_or("provider-boundary-invalid")?;
    let selection = crate::common::recovery_test_fault::FaultSelectionV1::try_new(
        boundary,
        occurrence,
        crate::common::recovery_test_fault::FaultEffectV1::ProcessBarrier,
    )
    .map_err(|_| "provider-occurrence-invalid")?;
    Ok(
        crate::common::recovery_test_fault::FaultProbeV1::selected_process_barrier_v1(
            selection,
            Box::new(move || process_barrier()),
        ),
    )
}

fn create_exact_directory_v1(path: &Path) -> Result<(), &'static str> {
    fs::create_dir(path).map_err(|_| "fixture-directory-create-failed")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "fixture-directory-invalid")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("fixture-directory-invalid");
    }
    Ok(())
}

fn canonical_protocol_root_v1(path: &Path) -> Result<PathBuf, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "protocol-root-invalid")?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("protocol-root-invalid");
    }
    fs::canonicalize(path).map_err(|_| "protocol-root-invalid")
}

fn write_create_new_synced_v1(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "fixture-identity-create-failed")?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "fixture-identity-publish-failed")
}

fn open_write_connection_v1(database: &Path) -> Result<Connection, &'static str> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| "coordinator-database-open-failed")?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| "coordinator-foreign-keys-failed")?;
    Ok(connection)
}

fn only_operation_id_v1(database: &Path) -> Result<String, &'static str> {
    Connection::open(database)
        .map_err(|_| "operation-read-open-failed")?
        .query_row("SELECT operation_id FROM prepared_operations", [], |row| {
            row.get(0)
        })
        .map_err(|_| "operation-read-failed")
}

fn only_recovery_manifest_v1(database: &Path) -> Result<Sha256Digest, &'static str> {
    let bytes: Vec<u8> = Connection::open(database)
        .map_err(|_| "manifest-read-open-failed")?
        .query_row(
            "SELECT manifest_digest FROM preparation_recovery_evidence",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "manifest-read-failed")?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| "manifest-digest-invalid")?;
    Ok(Sha256Digest::from_bytes(bytes))
}

const fn digest_v1(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn frozen_quarantine_partition_is_exact() {
        let supported = crate::test_fault::FaultBoundaryV1::ALL
            .iter()
            .filter(|boundary| supports_boundary_v1(boundary.id()))
            .count();
        assert_eq!(supported, 10);
        assert!(ORPHAN_BOUNDARIES
            .iter()
            .all(|boundary| supports_boundary_v1(boundary)));
        assert!(OPERATION_BOUNDARIES
            .iter()
            .all(|boundary| supports_boundary_v1(boundary)));
        assert!(PROVIDER_BOUNDARIES
            .iter()
            .all(|boundary| supports_boundary_v1(boundary)));
    }

    #[test]
    fn every_selected_id_is_reached_by_the_real_quarantine_workflows() {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        for boundary_id in ORPHAN_BOUNDARIES
            .iter()
            .chain(OPERATION_BOUNDARIES.iter())
            .chain(PROVIDER_BOUNDARIES.iter())
        {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "helixos-t074-quarantine-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("T074 quarantine protocol root creates");
            prepare_fixture_v1(&root).expect("T074 quarantine fixture prepares");
            let reached = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
                let root = root.clone();
                let boundary_id = *boundary_id;
                move || {
                    run_boundary_v1(
                        &root,
                        boundary_id,
                        1,
                        Arc::new(|| panic!("T074_TEST_PROCESS_BARRIER")),
                    )
                    .expect("selected T074 quarantine workflow reaches its boundary")
                }
            }));
            assert!(reached.is_err(), "{boundary_id} must invoke the barrier");
            let state = reopen_state_v1(&root).expect("T074 quarantine state reopens");
            let expected_state = match *boundary_id {
                "quarantine_and_retirement_orphan_retired_tombstone_committed" => {
                    b"absent".as_slice()
                }
                "quarantine_and_retirement_operation_bound_retired_tombstone_committed" => {
                    b"failed".as_slice()
                }
                _ => b"quarantine".as_slice(),
            };
            assert_eq!(
                state, expected_state,
                "{boundary_id} must reopen to its single permitted state"
            );
            fs::remove_dir_all(root).expect("T074 quarantine protocol root removes");
        }
    }

    #[test]
    fn corrupt_final_retirement_tombstones_refuse_reopen() {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        for (boundary_id, expected_clean_state) in [
            (
                "quarantine_and_retirement_orphan_retired_tombstone_committed",
                b"absent".as_slice(),
            ),
            (
                "quarantine_and_retirement_operation_bound_retired_tombstone_committed",
                b"failed".as_slice(),
            ),
        ] {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "helixos-t074-retirement-corruption-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("T074 corruption protocol root creates");
            prepare_fixture_v1(&root).expect("T074 corruption fixture prepares");

            let reached = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
                let root = root.clone();
                move || {
                    run_boundary_v1(
                        &root,
                        boundary_id,
                        1,
                        Arc::new(|| panic!("T074_CORRUPTION_PROCESS_BARRIER")),
                    )
                    .expect("selected final retirement workflow reaches its boundary")
                }
            }));
            assert!(reached.is_err(), "{boundary_id} must invoke the barrier");
            assert_eq!(
                reopen_state_v1(&root).expect("uncorrupted final retirement reopens"),
                expected_clean_state,
                "{boundary_id} must be exact before corruption"
            );

            let package_root = root.join(RECOVERY_PROVIDER_DIRECTORY).join("packages-v1");
            let retirement_paths = fs::read_dir(&package_root)
                .expect("retirement package directory reads")
                .map(|entry| entry.expect("retirement package entry reads").path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|suffix| suffix == "retirement")
                })
                .collect::<Vec<_>>();
            let [retirement_path] = retirement_paths.as_slice() else {
                panic!("{boundary_id} must publish exactly one retirement tombstone");
            };
            fs::write(retirement_path, b"corrupt-retirement-tombstone")
                .expect("retirement tombstone corruption writes");

            assert!(
                reopen_state_v1(&root).is_err(),
                "{boundary_id} must refuse a corrupt retirement tombstone"
            );
            fs::remove_dir_all(root).expect("T074 corruption protocol root removes");
        }
    }
}
