//! Downstream harness root for coordinator SQLite integration tests.
//!
//! Native roots and process fixtures stop here. This module deliberately does not
//! source-include the upstream harness or depend directly on plan eligibility. Every
//! key and payload below is a fixed public-synthetic sentinel with no production claim.

#![allow(dead_code)]

pub(crate) mod process_probe;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use helix_contracts::{
    AtomicityV1, ContractError, Ed25519KeyResolver, Ed25519Signer, Identifier, RecoveryClassV1,
    Result as ContractResult, Sha256Digest,
};
use helix_coordinator_sqlite::{
    CoordinatorClockUnavailableV1, CoordinatorMonotonicClockV1, CoordinatorRootIdentityEvidenceV1,
    CoordinatorStoreConfigErrorV1, CoordinatorStoreConfigV1, CoordinatorStoreOpenErrorV1,
    SqliteCoordinatorStoreV1,
};
use helix_plan_preparation::{
    BudgetVectorInputV1, BudgetVectorV1, RecoveryBindingV1, RecoveryCleanupGuardOutcomeV1,
    RecoveryCleanupGuardV1, RecoveryEvidenceClassV1, RecoveryGuardOutcomeV1,
    RecoveryMaintenanceProviderV1, RecoveryMaterialReceiptInputV1, RecoveryMaterialReceiptV1,
    RecoveryMaterialStateV1, RecoveryPreparationInputV1, RecoveryPreparationOutcomeV1,
    RecoveryProviderProfileInputV1, RecoveryProviderProfileV1, RecoveryProviderV1,
    RecoveryPublicationGuardV1, RecoveryRetirementVerificationV1, RecoveryVerificationV1,
    RECOVERY_PROVIDER_CONTRACT_VERSION_V1, RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "test-fault-injection")]
#[allow(clippy::duplicate_mod)] // Some integration roots also source the closed taxonomy.
#[path = "../../src/test_fault.rs"]
pub(crate) mod recovery_test_fault;

#[cfg(feature = "test-fault-injection")]
type SyntheticRecoveryFaultProbeV1 = recovery_test_fault::FaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
#[derive(Clone, Copy, Default)]
struct SyntheticRecoveryFaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
impl SyntheticRecoveryFaultProbeV1 {
    const fn disabled_v1() -> Self {
        Self
    }
}

const SYNTHETIC_PROVENANCE_KEY_ID: &str = "provenance:synthetic-conformance-v1";
const SYNTHETIC_PROVENANCE_SIGNING_BYTES: [u8; 32] = [0x42; 32];
const SYNTHETIC_PROVENANCE_DOMAIN: &[u8] = b"HELIXOS\0SYNTHETIC-PROVENANCE-CONFORMANCE\0V1\0";
const SYNTHETIC_HISTORICAL_PLAN_KEY_ID: &str = "core-signing-key:fixture-1";
const SYNTHETIC_HISTORICAL_PLAN_SIGNING_BYTES: [u8; 32] = [7; 32];
pub(crate) const SYNTHETIC_BUDGET_MAX_COST_MICRO_UNITS: u64 = 0;
pub(crate) const SYNTHETIC_BUDGET_ACTION_LIMIT: u64 = 1;
pub(crate) const SYNTHETIC_BUDGET_EGRESS_BYTES_LIMIT: u64 = 0;
pub(crate) const SYNTHETIC_BUDGET_RECOVERY_BYTES: u64 = 4_096;
const SYNTHETIC_COORDINATOR_BUSY_WAIT_MS: u64 = 50;
const SYNTHETIC_RECOVERY_PROFILE_ID: &str = "recovery-profile:synthetic-conformance-v1";
const SYNTHETIC_RECOVERY_PROVIDER_ID: &str = "recovery-provider:synthetic-conformance-v1";
const SYNTHETIC_RECOVERY_AT_REST_PROFILE_ID: &str = "at-rest:synthetic-conformance-v1";
const SYNTHETIC_RECOVERY_PROVIDER_GENERATION: u64 = 1;
const SYNTHETIC_RECOVERY_MATERIAL: &[u8] = b"before\n";
const SYNTHETIC_RECOVERY_LOCK_DIRECTORY: &str = "locks-v1";
const SYNTHETIC_RECOVERY_PACKAGE_DIRECTORY: &str = "packages-v1";
const SYNTHETIC_RECOVERY_MATERIAL_SUFFIX: &str = ".material";
const SYNTHETIC_RECOVERY_MANIFEST_SUFFIX: &str = ".manifest";
const SYNTHETIC_RECOVERY_RETIREMENT_SUFFIX: &str = ".retirement";
const SYNTHETIC_RECOVERY_MANIFEST_DOMAIN: &[u8] = b"HELIXOS\0SYNTHETIC-RECOVERY-MANIFEST\0V1\0";
const SYNTHETIC_RECOVERY_RETIREMENT_DOMAIN: &[u8] = b"HELIXOS\0SYNTHETIC-RECOVERY-RETIREMENT\0V1\0";
const SYNTHETIC_RECOVERY_PUBLICATION_DOMAIN: &[u8] =
    b"HELIXOS\0SYNTHETIC-RECOVERY-PUBLICATION\0V1\0";
const SYNTHETIC_RECOVERY_MATERIAL_ID_DOMAIN: &[u8] = b"HELIXOS\0SYNTHETIC-RECOVERY-MATERIAL\0V1\0";
static SYNTHETIC_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyntheticHarnessErrorV1 {
    RootCreateFailed,
    CoordinatorConfig(CoordinatorStoreConfigErrorV1),
    CoordinatorOpen(CoordinatorStoreOpenErrorV1),
}

impl SyntheticHarnessErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::RootCreateFailed => "SYNTHETIC_ROOT_CREATE_FAILED",
            Self::CoordinatorConfig(error) => error.code(),
            Self::CoordinatorOpen(error) => error.code(),
        }
    }
}

impl fmt::Debug for SyntheticHarnessErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

pub(crate) struct SyntheticCoordinatorRootV1 {
    path: PathBuf,
}

impl SyntheticCoordinatorRootV1 {
    pub(crate) fn new() -> Result<Self, SyntheticHarnessErrorV1> {
        Ok(Self {
            path: create_synthetic_root_v1("helixos-t026-coordinator")?,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn empty_config_v1(
        &self,
    ) -> Result<CoordinatorStoreConfigV1, SyntheticHarnessErrorV1> {
        CoordinatorStoreConfigV1::try_new_empty_attested(
            self.path.clone(),
            SYNTHETIC_COORDINATOR_BUSY_WAIT_MS,
        )
        .map_err(SyntheticHarnessErrorV1::CoordinatorConfig)
    }

    pub(crate) fn existing_config_v1(
        &self,
        root_identity: CoordinatorRootIdentityEvidenceV1,
    ) -> Result<CoordinatorStoreConfigV1, SyntheticHarnessErrorV1> {
        CoordinatorStoreConfigV1::try_new_existing_attested(
            self.path.clone(),
            root_identity,
            SYNTHETIC_COORDINATOR_BUSY_WAIT_MS,
        )
        .map_err(SyntheticHarnessErrorV1::CoordinatorConfig)
    }

    pub(crate) fn open_empty_v1<C, R>(
        &self,
        clock: C,
        historical_plan_keys: R,
        deadline_monotonic_ms: u64,
    ) -> Result<SqliteCoordinatorStoreV1<C, R>, SyntheticHarnessErrorV1>
    where
        C: CoordinatorMonotonicClockV1,
        R: Ed25519KeyResolver,
    {
        SqliteCoordinatorStoreV1::open_or_create(
            self.empty_config_v1()?,
            clock,
            historical_plan_keys,
            deadline_monotonic_ms,
        )
        .map_err(SyntheticHarnessErrorV1::CoordinatorOpen)
    }

    pub(crate) fn open_existing_v1<C, R>(
        &self,
        root_identity: CoordinatorRootIdentityEvidenceV1,
        clock: C,
        historical_plan_keys: R,
        deadline_monotonic_ms: u64,
    ) -> Result<SqliteCoordinatorStoreV1<C, R>, SyntheticHarnessErrorV1>
    where
        C: CoordinatorMonotonicClockV1,
        R: Ed25519KeyResolver,
    {
        SqliteCoordinatorStoreV1::open_or_create(
            self.existing_config_v1(root_identity)?,
            clock,
            historical_plan_keys,
            deadline_monotonic_ms,
        )
        .map_err(SyntheticHarnessErrorV1::CoordinatorOpen)
    }
}

impl fmt::Debug for SyntheticCoordinatorRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticCoordinatorRootV1")
            .finish_non_exhaustive()
    }
}

impl Drop for SyntheticCoordinatorRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) struct SyntheticCrossProcessRecoveryRootV1 {
    path: PathBuf,
}

impl SyntheticCrossProcessRecoveryRootV1 {
    pub(crate) fn new() -> Result<Self, SyntheticHarnessErrorV1> {
        Ok(Self {
            path: create_synthetic_root_v1("helixos-t026-recovery")?,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Explicit process argument; the path never appears in `Debug` or error payloads.
    pub(crate) fn child_root_argument_v1(&self) -> OsString {
        self.path.clone().into_os_string()
    }
}

impl fmt::Debug for SyntheticCrossProcessRecoveryRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticCrossProcessRecoveryRootV1")
            .finish_non_exhaustive()
    }
}

impl Drop for SyntheticCrossProcessRecoveryRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) struct SyntheticCrossProcessRecoveryFixtureV1 {
    root: SyntheticCrossProcessRecoveryRootV1,
    expected_manifest_digest: Sha256Digest,
    reserved_bytes: u64,
}

impl SyntheticCrossProcessRecoveryFixtureV1 {
    pub(crate) fn new() -> Result<Self, SyntheticHarnessErrorV1> {
        let budget = synthetic_budget_vector_v1();
        Ok(Self {
            root: SyntheticCrossProcessRecoveryRootV1::new()?,
            expected_manifest_digest: Sha256Digest::digest(
                b"public-synthetic cross-process recovery manifest",
            ),
            reserved_bytes: budget.recovery_bytes(),
        })
    }

    pub(crate) fn root(&self) -> &SyntheticCrossProcessRecoveryRootV1 {
        &self.root
    }

    pub(crate) const fn expected_manifest_digest(&self) -> Sha256Digest {
        self.expected_manifest_digest
    }

    pub(crate) const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }
}

impl fmt::Debug for SyntheticCrossProcessRecoveryFixtureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticCrossProcessRecoveryFixtureV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyntheticRecoveryProviderErrorV1 {
    RootUnavailable,
    RootInvalid,
    BindingConflict,
    DeadlineReached,
    Contended,
    Unavailable,
    Unhealthy,
}

impl SyntheticRecoveryProviderErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::RootUnavailable => "SYNTHETIC_RECOVERY_ROOT_UNAVAILABLE",
            Self::RootInvalid => "SYNTHETIC_RECOVERY_ROOT_INVALID",
            Self::BindingConflict => "SYNTHETIC_RECOVERY_BINDING_CONFLICT",
            Self::DeadlineReached => "SYNTHETIC_RECOVERY_DEADLINE_REACHED",
            Self::Contended => "SYNTHETIC_RECOVERY_CONTENDED",
            Self::Unavailable => "SYNTHETIC_RECOVERY_UNAVAILABLE",
            Self::Unhealthy => "SYNTHETIC_RECOVERY_UNHEALTHY",
        }
    }
}

impl fmt::Debug for SyntheticRecoveryProviderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for SyntheticRecoveryProviderErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SyntheticRecoveryProviderErrorV1 {}

pub(crate) enum SyntheticRecoveryGuardOutcomeV1<G> {
    Acquired(G),
    Contended,
    Unavailable,
    DeadlineReached,
}

impl<G> fmt::Debug for SyntheticRecoveryGuardOutcomeV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::Acquired(_) => "ACQUIRED",
            Self::Contended => "CONTENDED",
            Self::Unavailable => "UNAVAILABLE",
            Self::DeadlineReached => "DEADLINE_REACHED",
        };
        formatter.write_str(code)
    }
}

struct SyntheticExpectedRecoveryReceiptV1 {
    provider_generation: u64,
    capability_binding_digest: Sha256Digest,
    plan_id: Sha256Digest,
    operation_id: String,
    attempt_id: Sha256Digest,
    target_reference_digest: Sha256Digest,
    precondition_identity_digest: Sha256Digest,
    precondition_digest: Sha256Digest,
    precondition_length: u64,
    recovery_class: RecoveryClassV1,
    atomicity: AtomicityV1,
    material_digest: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
    material_id: Sha256Digest,
    publication_attempt_id: Sha256Digest,
    manifest_digest: Sha256Digest,
    manifest_bytes: Vec<u8>,
    boot_binding_digest: Sha256Digest,
    instance_epoch: u64,
    fencing_epoch: u64,
}

pub(crate) struct SyntheticRecoveryNamespaceGuardV1 {
    _lock: File,
    binding_digest: Sha256Digest,
    deadline_monotonic_ms: u64,
    expected: Option<SyntheticExpectedRecoveryReceiptV1>,
}

impl fmt::Debug for SyntheticRecoveryNamespaceGuardV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticRecoveryNamespaceGuardV1")
            .finish_non_exhaustive()
    }
}

impl RecoveryPublicationGuardV1 for SyntheticRecoveryNamespaceGuardV1 {
    fn release(self) {
        drop(self);
    }
}

impl RecoveryCleanupGuardV1 for SyntheticRecoveryNamespaceGuardV1 {
    fn release(self) {
        drop(self);
    }
}

#[derive(Clone)]
pub(crate) struct SyntheticManifestLastRecoveryProviderV1 {
    root: PathBuf,
    fault_probe: SyntheticRecoveryFaultProbeV1,
}

impl fmt::Debug for SyntheticManifestLastRecoveryProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticManifestLastRecoveryProviderV1")
            .finish_non_exhaustive()
    }
}

impl SyntheticManifestLastRecoveryProviderV1 {
    pub(crate) fn open_v1(root: PathBuf) -> Result<Self, SyntheticRecoveryProviderErrorV1> {
        if !root.is_dir() {
            return Err(SyntheticRecoveryProviderErrorV1::RootInvalid);
        }
        let root = fs::canonicalize(root)
            .map_err(|_| SyntheticRecoveryProviderErrorV1::RootUnavailable)?;
        fs::create_dir_all(root.join(SYNTHETIC_RECOVERY_LOCK_DIRECTORY))
            .and_then(|()| fs::create_dir_all(root.join(SYNTHETIC_RECOVERY_PACKAGE_DIRECTORY)))
            .map_err(|_| SyntheticRecoveryProviderErrorV1::RootUnavailable)?;
        Ok(Self {
            root,
            fault_probe: SyntheticRecoveryFaultProbeV1::disabled_v1(),
        })
    }

    /// Replaces the disabled default with one explicit caller-owned selected probe.
    #[cfg(feature = "test-fault-injection")]
    pub(crate) fn with_fault_probe_v1(
        mut self,
        fault_probe: recovery_test_fault::FaultProbeV1,
    ) -> Self {
        self.fault_probe = fault_probe;
        self
    }

    pub(crate) fn profile_v1(
        &self,
    ) -> Result<RecoveryProviderProfileV1, SyntheticRecoveryProviderErrorV1> {
        RecoveryProviderProfileV1::try_new(RecoveryProviderProfileInputV1 {
            profile_id: synthetic_identifier_v1(SYNTHETIC_RECOVERY_PROFILE_ID)?,
            profile_version: RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
            provider_id: synthetic_identifier_v1(SYNTHETIC_RECOVERY_PROVIDER_ID)?,
            provider_generation: SYNTHETIC_RECOVERY_PROVIDER_GENERATION,
            evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
            capability_binding_digest: synthetic_capability_binding_v1(),
            at_rest_profile_id: synthetic_identifier_v1(SYNTHETIC_RECOVERY_AT_REST_PROFILE_ID)?,
            supports_create_only: true,
            supports_sync: true,
            supports_no_clobber_publication: true,
            maximum_material_bytes: SYNTHETIC_BUDGET_RECOVERY_BYTES,
            maximum_reserved_capacity: SYNTHETIC_BUDGET_RECOVERY_BYTES,
        })
        .map_err(|_| SyntheticRecoveryProviderErrorV1::Unhealthy)
    }

    pub(crate) fn acquire_publication_guard_v1(
        &self,
        binding_digest: Sha256Digest,
        deadline_monotonic_ms: u64,
    ) -> SyntheticRecoveryGuardOutcomeV1<SyntheticRecoveryNamespaceGuardV1> {
        let outcome = self.acquire_namespace_guard_v1(binding_digest, deadline_monotonic_ms, None);
        if matches!(outcome, SyntheticRecoveryGuardOutcomeV1::Acquired(_)) {
            reach_recovery_publication_guard_acquired_v1(&self.fault_probe);
        }
        outcome
    }

    pub(crate) fn acquire_cleanup_guard_v1(
        &self,
        binding_digest: Sha256Digest,
        deadline_monotonic_ms: u64,
    ) -> SyntheticRecoveryGuardOutcomeV1<SyntheticRecoveryNamespaceGuardV1> {
        self.acquire_namespace_guard_v1(binding_digest, deadline_monotonic_ms, None)
    }

    pub(crate) fn publish_public_synthetic_v1(
        &self,
        manifest_binding_digest: Sha256Digest,
    ) -> Result<(), SyntheticRecoveryProviderErrorV1> {
        let mut guard = match self.acquire_publication_guard_v1(manifest_binding_digest, u64::MAX) {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
            SyntheticRecoveryGuardOutcomeV1::Contended => {
                return Err(SyntheticRecoveryProviderErrorV1::Contended)
            }
            SyntheticRecoveryGuardOutcomeV1::Unavailable => {
                return Err(SyntheticRecoveryProviderErrorV1::Unavailable)
            }
            SyntheticRecoveryGuardOutcomeV1::DeadlineReached => {
                return Err(SyntheticRecoveryProviderErrorV1::DeadlineReached)
            }
        };
        let material_digest = Sha256Digest::digest(SYNTHETIC_RECOVERY_MATERIAL);
        let manifest_bytes = direct_manifest_bytes_v1(
            manifest_binding_digest,
            material_digest,
            SYNTHETIC_RECOVERY_MATERIAL.len() as u64,
            SYNTHETIC_BUDGET_RECOVERY_BYTES,
        );
        self.publish_package_v1(&mut guard, SYNTHETIC_RECOVERY_MATERIAL, &manifest_bytes)?;
        reach_recovery_receipt_returned_v1(&self.fault_probe);
        Ok(())
    }

    pub(crate) fn publish_retirement_tombstone_v1(
        &self,
        guard: &mut SyntheticRecoveryNamespaceGuardV1,
        manifest_digest: Sha256Digest,
        retirement_id: Sha256Digest,
    ) -> Result<Sha256Digest, SyntheticRecoveryProviderErrorV1> {
        self.publish_retirement_tombstone_internal_v1(guard, manifest_digest, retirement_id)
            .map(|(digest, _)| digest)
    }

    fn acquire_namespace_guard_v1(
        &self,
        binding_digest: Sha256Digest,
        deadline_monotonic_ms: u64,
        expected: Option<SyntheticExpectedRecoveryReceiptV1>,
    ) -> SyntheticRecoveryGuardOutcomeV1<SyntheticRecoveryNamespaceGuardV1> {
        if deadline_monotonic_ms == 0 {
            return SyntheticRecoveryGuardOutcomeV1::DeadlineReached;
        }
        let lock_path = self
            .root
            .join(SYNTHETIC_RECOVERY_LOCK_DIRECTORY)
            .join(format!(
                "{}.lock",
                lowercase_hex_v1(binding_digest.as_bytes())
            ));
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
        {
            Ok(lock) => lock,
            Err(_) => return SyntheticRecoveryGuardOutcomeV1::Unavailable,
        };
        match lock.try_lock() {
            Ok(()) => {
                SyntheticRecoveryGuardOutcomeV1::Acquired(SyntheticRecoveryNamespaceGuardV1 {
                    _lock: lock,
                    binding_digest,
                    deadline_monotonic_ms,
                    expected,
                })
            }
            Err(TryLockError::WouldBlock) => SyntheticRecoveryGuardOutcomeV1::Contended,
            Err(TryLockError::Error(_)) => SyntheticRecoveryGuardOutcomeV1::Unavailable,
        }
    }

    fn package_path_v1(&self, binding_digest: Sha256Digest, suffix: &str) -> PathBuf {
        self.root
            .join(SYNTHETIC_RECOVERY_PACKAGE_DIRECTORY)
            .join(format!(
                "{}{}",
                lowercase_hex_v1(binding_digest.as_bytes()),
                suffix
            ))
    }

    fn staging_path_v1(&self, binding_digest: Sha256Digest, label: &str) -> PathBuf {
        let sequence = SYNTHETIC_ROOT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        self.root
            .join(SYNTHETIC_RECOVERY_PACKAGE_DIRECTORY)
            .join(format!(
                "{}.{}.{}.{sequence}.staging",
                lowercase_hex_v1(binding_digest.as_bytes()),
                label,
                std::process::id(),
            ))
    }

    fn publish_package_v1(
        &self,
        guard: &mut SyntheticRecoveryNamespaceGuardV1,
        material: &[u8],
        manifest: &[u8],
    ) -> Result<(), SyntheticRecoveryProviderErrorV1> {
        match self.verify_package_files_v1(guard.binding_digest, material, manifest)? {
            SyntheticPackageStateV1::Exact => return Ok(()),
            SyntheticPackageStateV1::Absent => {}
            SyntheticPackageStateV1::Partial | SyntheticPackageStateV1::Retired => {
                return Err(SyntheticRecoveryProviderErrorV1::Unhealthy)
            }
        }

        let material_staging = self.staging_path_v1(guard.binding_digest, "material");
        let mut material_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&material_staging)
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        reach_recovery_staging_created_v1(&self.fault_probe);
        material_file
            .write_all(material)
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        reach_recovery_staging_written_v1(&self.fault_probe);
        material_file
            .sync_all()
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        reach_recovery_staging_synchronized_v1(&self.fault_probe);
        drop(material_file);
        reach_recovery_staging_closed_v1(&self.fault_probe);
        let reopened_material = read_exact_file_v1(&material_staging)?;
        reach_recovery_staging_reopened_v1(&self.fault_probe);
        if reopened_material != material
            || Sha256Digest::digest(&reopened_material) != Sha256Digest::digest(material)
        {
            let _ = fs::remove_file(&material_staging);
            return Err(SyntheticRecoveryProviderErrorV1::Unhealthy);
        }
        reach_recovery_material_verified_v1(&self.fault_probe);
        let material_final =
            self.package_path_v1(guard.binding_digest, SYNTHETIC_RECOVERY_MATERIAL_SUFFIX);
        publish_no_clobber_v1(&material_staging, &material_final)?;
        reach_recovery_material_published_v1(&self.fault_probe);

        let manifest_staging = self.staging_path_v1(guard.binding_digest, "manifest");
        let mut manifest_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&manifest_staging)
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        reach_recovery_manifest_staged_v1(&self.fault_probe);
        manifest_file
            .write_all(manifest)
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        manifest_file
            .sync_all()
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        reach_recovery_manifest_synchronized_v1(&self.fault_probe);
        drop(manifest_file);
        let manifest_final =
            self.package_path_v1(guard.binding_digest, SYNTHETIC_RECOVERY_MANIFEST_SUFFIX);
        publish_no_clobber_v1(&manifest_staging, &manifest_final)?;
        reach_recovery_manifest_published_v1(&self.fault_probe);
        let reopened_manifest = read_exact_file_v1(&manifest_final)?;
        reach_recovery_manifest_reopened_v1(&self.fault_probe);
        if reopened_manifest != manifest {
            return Err(SyntheticRecoveryProviderErrorV1::Unhealthy);
        }
        Ok(())
    }

    fn verify_package_files_v1(
        &self,
        binding_digest: Sha256Digest,
        expected_material: &[u8],
        expected_manifest: &[u8],
    ) -> Result<SyntheticPackageStateV1, SyntheticRecoveryProviderErrorV1> {
        let material = read_optional_file_v1(
            &self.package_path_v1(binding_digest, SYNTHETIC_RECOVERY_MATERIAL_SUFFIX),
        )?;
        let manifest = read_optional_file_v1(
            &self.package_path_v1(binding_digest, SYNTHETIC_RECOVERY_MANIFEST_SUFFIX),
        )?;
        let retirement = read_optional_file_v1(
            &self.package_path_v1(binding_digest, SYNTHETIC_RECOVERY_RETIREMENT_SUFFIX),
        )?;
        match (material, manifest, retirement) {
            (None, None, None) => Ok(SyntheticPackageStateV1::Absent),
            (Some(material), Some(manifest), None)
                if material == expected_material && manifest == expected_manifest =>
            {
                Ok(SyntheticPackageStateV1::Exact)
            }
            (None, Some(_), Some(_)) => Ok(SyntheticPackageStateV1::Retired),
            _ => Ok(SyntheticPackageStateV1::Partial),
        }
    }

    fn publish_retirement_tombstone_internal_v1(
        &self,
        guard: &mut SyntheticRecoveryNamespaceGuardV1,
        manifest_digest: Sha256Digest,
        retirement_id: Sha256Digest,
    ) -> Result<(Sha256Digest, bool), SyntheticRecoveryProviderErrorV1> {
        if guard.binding_digest != manifest_digest || guard.deadline_monotonic_ms == 0 {
            return Err(SyntheticRecoveryProviderErrorV1::BindingConflict);
        }
        reach_provider_retirement_invoked_v1(&self.fault_probe);
        let material_path =
            self.package_path_v1(manifest_digest, SYNTHETIC_RECOVERY_MATERIAL_SUFFIX);
        let manifest_path =
            self.package_path_v1(manifest_digest, SYNTHETIC_RECOVERY_MANIFEST_SUFFIX);
        let retirement_path =
            self.package_path_v1(manifest_digest, SYNTHETIC_RECOVERY_RETIREMENT_SUFFIX);
        let manifest = read_optional_file_v1(&manifest_path)?
            .ok_or(SyntheticRecoveryProviderErrorV1::BindingConflict)?;
        let retirement_bytes = retirement_manifest_bytes_v1(
            manifest_digest,
            retirement_id,
            Sha256Digest::digest(&manifest),
        );
        let retirement_digest = Sha256Digest::digest(&retirement_bytes);

        if let Some(existing) = read_optional_file_v1(&retirement_path)? {
            if existing == retirement_bytes && read_optional_file_v1(&material_path)?.is_none() {
                reach_provider_bytes_retired_v1(&self.fault_probe);
                reach_retirement_manifest_published_v1(&self.fault_probe);
                return Ok((retirement_digest, true));
            }
            return Err(SyntheticRecoveryProviderErrorV1::Unhealthy);
        }
        if read_optional_file_v1(&material_path)?.is_none() {
            return Err(SyntheticRecoveryProviderErrorV1::Unhealthy);
        }

        let retirement_staging = self.staging_path_v1(manifest_digest, "retirement");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&retirement_staging)
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        file.write_all(&retirement_bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        drop(file);
        fs::remove_file(&material_path)
            .map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)?;
        reach_provider_bytes_retired_v1(&self.fault_probe);
        publish_no_clobber_v1(&retirement_staging, &retirement_path)?;
        if read_exact_file_v1(&retirement_path)? != retirement_bytes {
            return Err(SyntheticRecoveryProviderErrorV1::Unhealthy);
        }
        reach_retirement_manifest_published_v1(&self.fault_probe);
        Ok((retirement_digest, false))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyntheticPackageStateV1 {
    Absent,
    Exact,
    Partial,
    Retired,
}

impl RecoveryProviderV1 for SyntheticManifestLastRecoveryProviderV1 {
    type PublicationGuard = SyntheticRecoveryNamespaceGuardV1;

    fn acquire_publication_guard(
        &self,
        input: &RecoveryBindingV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> RecoveryGuardOutcomeV1<Self::PublicationGuard> {
        if deadline_monotonic_ms != input.deadline_monotonic_ms()
            || input.context().sampled_monotonic_ms() >= deadline_monotonic_ms
        {
            return RecoveryGuardOutcomeV1::DeadlineReached;
        }
        let Some(expected) = expected_recovery_receipt_v1(input) else {
            return RecoveryGuardOutcomeV1::Unsupported;
        };
        let binding_digest = expected.manifest_digest;
        match self.acquire_namespace_guard_v1(binding_digest, deadline_monotonic_ms, Some(expected))
        {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => {
                reach_recovery_publication_guard_acquired_v1(&self.fault_probe);
                RecoveryGuardOutcomeV1::Acquired(guard)
            }
            SyntheticRecoveryGuardOutcomeV1::Contended => RecoveryGuardOutcomeV1::Conflict,
            SyntheticRecoveryGuardOutcomeV1::Unavailable => RecoveryGuardOutcomeV1::Unavailable,
            SyntheticRecoveryGuardOutcomeV1::DeadlineReached => {
                RecoveryGuardOutcomeV1::DeadlineReached
            }
        }
    }

    fn prepare_and_publish(
        &self,
        guard: &mut Self::PublicationGuard,
        input: &RecoveryPreparationInputV1<'_>,
    ) -> RecoveryPreparationOutcomeV1 {
        let Some(expected) = expected_recovery_receipt_v1(input.binding()) else {
            return RecoveryPreparationOutcomeV1::BindingConflict;
        };
        if guard.binding_digest != expected.manifest_digest
            || guard.deadline_monotonic_ms != input.binding().deadline_monotonic_ms()
            || guard
                .expected
                .as_ref()
                .is_none_or(|guard_expected| !expected_receipts_match_v1(guard_expected, &expected))
        {
            return RecoveryPreparationOutcomeV1::BindingConflict;
        }
        match self.publish_package_v1(guard, SYNTHETIC_RECOVERY_MATERIAL, &expected.manifest_bytes)
        {
            Ok(()) => {}
            Err(SyntheticRecoveryProviderErrorV1::BindingConflict) => {
                return RecoveryPreparationOutcomeV1::BindingConflict
            }
            Err(SyntheticRecoveryProviderErrorV1::Unhealthy) => {
                return RecoveryPreparationOutcomeV1::Unverified
            }
            Err(_) => return RecoveryPreparationOutcomeV1::ProviderFailed,
        }
        let Some(receipt) = receipt_from_expected_v1(&expected) else {
            return RecoveryPreparationOutcomeV1::ProviderFailed;
        };
        reach_recovery_receipt_returned_v1(&self.fault_probe);
        RecoveryPreparationOutcomeV1::Published(receipt)
    }

    fn verify_published(
        &self,
        guard: &mut Self::PublicationGuard,
        receipt: &RecoveryMaterialReceiptV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryVerificationV1 {
        if deadline_monotonic_ms == 0 || deadline_monotonic_ms != guard.deadline_monotonic_ms {
            return RecoveryVerificationV1::Unavailable;
        }
        let Some(expected) = guard.expected.as_ref() else {
            return RecoveryVerificationV1::Conflict;
        };
        if guard.binding_digest != expected.manifest_digest
            || !receipt_matches_expected_v1(receipt, expected)
        {
            return RecoveryVerificationV1::Conflict;
        }
        match self.verify_package_files_v1(
            guard.binding_digest,
            SYNTHETIC_RECOVERY_MATERIAL,
            &expected.manifest_bytes,
        ) {
            Ok(SyntheticPackageStateV1::Exact) => RecoveryVerificationV1::Exact,
            Ok(SyntheticPackageStateV1::Absent) => RecoveryVerificationV1::Missing,
            Ok(SyntheticPackageStateV1::Partial | SyntheticPackageStateV1::Retired) => {
                RecoveryVerificationV1::Conflict
            }
            Err(SyntheticRecoveryProviderErrorV1::Unavailable) => {
                RecoveryVerificationV1::Unavailable
            }
            Err(_) => RecoveryVerificationV1::Unhealthy,
        }
    }
}

impl RecoveryMaintenanceProviderV1 for SyntheticManifestLastRecoveryProviderV1 {
    type CleanupGuard = SyntheticRecoveryNamespaceGuardV1;

    fn acquire_cleanup_guard(
        &self,
        manifest_digest: Sha256Digest,
        deadline_monotonic_ms: u64,
    ) -> RecoveryCleanupGuardOutcomeV1<Self::CleanupGuard> {
        match self.acquire_cleanup_guard_v1(manifest_digest, deadline_monotonic_ms) {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => {
                RecoveryCleanupGuardOutcomeV1::Acquired(guard)
            }
            SyntheticRecoveryGuardOutcomeV1::Contended => RecoveryCleanupGuardOutcomeV1::Contended,
            SyntheticRecoveryGuardOutcomeV1::Unavailable => {
                RecoveryCleanupGuardOutcomeV1::Unavailable
            }
            SyntheticRecoveryGuardOutcomeV1::DeadlineReached => {
                RecoveryCleanupGuardOutcomeV1::DeadlineReached
            }
        }
    }

    fn retire_exact(
        &self,
        guard: &mut Self::CleanupGuard,
        manifest_digest: Sha256Digest,
        retirement_id: Sha256Digest,
        deadline_monotonic_ms: u64,
    ) -> RecoveryRetirementVerificationV1 {
        if deadline_monotonic_ms == 0 || deadline_monotonic_ms != guard.deadline_monotonic_ms {
            return RecoveryRetirementVerificationV1::Unavailable;
        }
        match self.publish_retirement_tombstone_internal_v1(guard, manifest_digest, retirement_id) {
            Ok((_, false)) => RecoveryRetirementVerificationV1::Retired,
            Ok((_, true)) => RecoveryRetirementVerificationV1::AlreadyRetired,
            Err(SyntheticRecoveryProviderErrorV1::BindingConflict) => {
                RecoveryRetirementVerificationV1::BindingConflict
            }
            Err(SyntheticRecoveryProviderErrorV1::Unhealthy) => {
                RecoveryRetirementVerificationV1::Unhealthy
            }
            Err(_) => RecoveryRetirementVerificationV1::Unavailable,
        }
    }
}

fn expected_recovery_receipt_v1(
    binding: &RecoveryBindingV1<'_>,
) -> Option<SyntheticExpectedRecoveryReceiptV1> {
    let context = binding.context();
    let provider = context.recovery_provider()?;
    if provider.profile_id() != SYNTHETIC_RECOVERY_PROFILE_ID
        || provider.profile_version() != RECOVERY_PROVIDER_CONTRACT_VERSION_V1
        || provider.provider_id() != SYNTHETIC_RECOVERY_PROVIDER_ID
        || provider.evidence_class() != "synthetic-conformance"
        || provider.provider_generation() != SYNTHETIC_RECOVERY_PROVIDER_GENERATION
        || provider.capability_binding_digest() != synthetic_capability_binding_v1()
        || provider.at_rest_profile_id() != SYNTHETIC_RECOVERY_AT_REST_PROFILE_ID
        || !provider.supports_create_only()
        || !provider.supports_sync()
        || !provider.supports_no_clobber_publication()
    {
        return None;
    }
    let claims = binding.claims();
    let material_digest = Sha256Digest::digest(SYNTHETIC_RECOVERY_MATERIAL);
    if claims.recovery_class() != RecoveryClassV1::Compensation
        || claims.preimage_sha256()? != material_digest
        || claims.precondition_content_sha256() != material_digest
        || claims.precondition_byte_length() != SYNTHETIC_RECOVERY_MATERIAL.len() as u64
        || claims.recovery_reserved_bytes() < SYNTHETIC_RECOVERY_MATERIAL.len() as u64
        || claims.recovery_reserved_bytes() > SYNTHETIC_BUDGET_RECOVERY_BYTES
    {
        return None;
    }
    let target_reference_digest = binding.target_reference_digest().ok()?;
    let precondition_identity_digest = binding.precondition_identity_digest().ok()?;
    let boot_binding_digest = binding.boot_binding_digest().ok()?;
    let publication_attempt_id = digest_parts_v1(
        SYNTHETIC_RECOVERY_PUBLICATION_DOMAIN,
        &[claims.plan_id().as_bytes(), binding.attempt().as_bytes()],
    );
    let material_id = digest_parts_v1(
        SYNTHETIC_RECOVERY_MATERIAL_ID_DOMAIN,
        &[
            claims.plan_id().as_bytes(),
            binding.attempt().as_bytes(),
            material_digest.as_bytes(),
        ],
    );
    let manifest_bytes = recovery_manifest_bytes_v1(
        material_id,
        publication_attempt_id,
        target_reference_digest,
        precondition_identity_digest,
        material_digest,
        claims.precondition_byte_length(),
        claims.recovery_reserved_bytes(),
        boot_binding_digest,
        context.instance_epoch(),
        context.fencing_epoch(),
    );
    let manifest_digest = Sha256Digest::digest(&manifest_bytes);
    Some(SyntheticExpectedRecoveryReceiptV1 {
        provider_generation: provider.provider_generation(),
        capability_binding_digest: provider.capability_binding_digest(),
        plan_id: claims.plan_id(),
        operation_id: claims.operation_id().to_owned(),
        attempt_id: binding.attempt().digest(),
        target_reference_digest,
        precondition_identity_digest,
        precondition_digest: claims.precondition_content_sha256(),
        precondition_length: claims.precondition_byte_length(),
        recovery_class: claims.recovery_class(),
        atomicity: claims.atomicity(),
        material_digest,
        material_length: claims.precondition_byte_length(),
        reserved_capacity: claims.recovery_reserved_bytes(),
        material_id,
        publication_attempt_id,
        manifest_digest,
        manifest_bytes,
        boot_binding_digest,
        instance_epoch: context.instance_epoch(),
        fencing_epoch: context.fencing_epoch(),
    })
}

fn receipt_from_expected_v1(
    expected: &SyntheticExpectedRecoveryReceiptV1,
) -> Option<RecoveryMaterialReceiptV1> {
    RecoveryMaterialReceiptV1::try_new(RecoveryMaterialReceiptInputV1 {
        contract_version: RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
        provider_profile_id: synthetic_identifier_v1(SYNTHETIC_RECOVERY_PROFILE_ID).ok()?,
        provider_profile_version: RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
        provider_id: synthetic_identifier_v1(SYNTHETIC_RECOVERY_PROVIDER_ID).ok()?,
        provider_generation: expected.provider_generation,
        evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
        at_rest_profile_id: synthetic_identifier_v1(SYNTHETIC_RECOVERY_AT_REST_PROFILE_ID).ok()?,
        capability_binding_digest: expected.capability_binding_digest,
        plan_id: expected.plan_id,
        operation_id: synthetic_identifier_v1(&expected.operation_id).ok()?,
        attempt_id: expected.attempt_id,
        target_reference_digest: expected.target_reference_digest,
        precondition_identity_digest: expected.precondition_identity_digest,
        precondition_digest: expected.precondition_digest,
        precondition_length: expected.precondition_length,
        recovery_class: expected.recovery_class,
        atomicity: expected.atomicity,
        material_digest: expected.material_digest,
        material_length: expected.material_length,
        reserved_capacity: expected.reserved_capacity,
        material_id: expected.material_id,
        publication_attempt_id: expected.publication_attempt_id,
        manifest_digest: expected.manifest_digest,
        state: RecoveryMaterialStateV1::Published,
        boot_binding_digest: expected.boot_binding_digest,
        instance_epoch: expected.instance_epoch,
        fencing_epoch: expected.fencing_epoch,
    })
    .ok()
}

fn receipt_matches_expected_v1(
    receipt: &RecoveryMaterialReceiptV1,
    expected: &SyntheticExpectedRecoveryReceiptV1,
) -> bool {
    receipt.contract_version() == RECOVERY_RECEIPT_CONTRACT_VERSION_V1
        && receipt.provider_profile_id() == SYNTHETIC_RECOVERY_PROFILE_ID
        && receipt.provider_profile_version() == RECOVERY_PROVIDER_CONTRACT_VERSION_V1
        && receipt.provider_id() == SYNTHETIC_RECOVERY_PROVIDER_ID
        && receipt.provider_generation() == expected.provider_generation
        && receipt.evidence_class() == &RecoveryEvidenceClassV1::SyntheticConformance
        && receipt.at_rest_profile_id() == SYNTHETIC_RECOVERY_AT_REST_PROFILE_ID
        && receipt.capability_binding_digest() == expected.capability_binding_digest
        && receipt.plan_id() == expected.plan_id
        && receipt.operation_id() == expected.operation_id
        && receipt.attempt_id() == expected.attempt_id
        && receipt.target_reference_digest() == expected.target_reference_digest
        && receipt.precondition_identity_digest() == expected.precondition_identity_digest
        && receipt.precondition_digest() == expected.precondition_digest
        && receipt.precondition_length() == expected.precondition_length
        && receipt.recovery_class() == expected.recovery_class
        && receipt.atomicity() == expected.atomicity
        && receipt.material_digest() == expected.material_digest
        && receipt.material_length() == expected.material_length
        && receipt.reserved_capacity() == expected.reserved_capacity
        && receipt.material_id() == expected.material_id
        && receipt.publication_attempt_id() == expected.publication_attempt_id
        && receipt.manifest_digest() == expected.manifest_digest
        && receipt.state() == &RecoveryMaterialStateV1::Published
        && receipt.boot_binding_digest() == expected.boot_binding_digest
        && receipt.instance_epoch() == expected.instance_epoch
        && receipt.fencing_epoch() == expected.fencing_epoch
}

fn expected_receipts_match_v1(
    left: &SyntheticExpectedRecoveryReceiptV1,
    right: &SyntheticExpectedRecoveryReceiptV1,
) -> bool {
    left.provider_generation == right.provider_generation
        && left.capability_binding_digest == right.capability_binding_digest
        && left.plan_id == right.plan_id
        && left.operation_id == right.operation_id
        && left.attempt_id == right.attempt_id
        && left.target_reference_digest == right.target_reference_digest
        && left.precondition_identity_digest == right.precondition_identity_digest
        && left.precondition_digest == right.precondition_digest
        && left.precondition_length == right.precondition_length
        && left.recovery_class == right.recovery_class
        && left.atomicity == right.atomicity
        && left.material_digest == right.material_digest
        && left.material_length == right.material_length
        && left.reserved_capacity == right.reserved_capacity
        && left.material_id == right.material_id
        && left.publication_attempt_id == right.publication_attempt_id
        && left.manifest_digest == right.manifest_digest
        && left.manifest_bytes == right.manifest_bytes
        && left.boot_binding_digest == right.boot_binding_digest
        && left.instance_epoch == right.instance_epoch
        && left.fencing_epoch == right.fencing_epoch
}

fn synthetic_identifier_v1(value: &str) -> Result<Identifier, SyntheticRecoveryProviderErrorV1> {
    Identifier::new(value, 128).map_err(|_| SyntheticRecoveryProviderErrorV1::Unhealthy)
}

fn synthetic_capability_binding_v1() -> Sha256Digest {
    let capability_report = Sha256Digest::digest(b"fixture capability report");
    let driver_context = Sha256Digest::digest(b"fixture host-driver context");
    digest_parts_v1(
        b"HELIXOS\0SYNTHETIC-RECOVERY-CAPABILITY\0V1\0",
        &[capability_report.as_bytes(), driver_context.as_bytes()],
    )
}

fn digest_parts_v1(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(domain);
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    Sha256Digest::digest(&encoded)
}

#[allow(clippy::too_many_arguments)]
fn recovery_manifest_bytes_v1(
    material_id: Sha256Digest,
    publication_attempt_id: Sha256Digest,
    target_reference_digest: Sha256Digest,
    precondition_identity_digest: Sha256Digest,
    material_digest: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
    boot_binding_digest: Sha256Digest,
    instance_epoch: u64,
    fencing_epoch: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(384);
    bytes.extend_from_slice(SYNTHETIC_RECOVERY_MANIFEST_DOMAIN);
    append_manifest_digest_v1(&mut bytes, material_id);
    append_manifest_digest_v1(&mut bytes, publication_attempt_id);
    append_manifest_digest_v1(&mut bytes, target_reference_digest);
    append_manifest_digest_v1(&mut bytes, precondition_identity_digest);
    append_manifest_digest_v1(&mut bytes, material_digest);
    bytes.extend_from_slice(&material_length.to_be_bytes());
    bytes.extend_from_slice(&reserved_capacity.to_be_bytes());
    append_manifest_digest_v1(&mut bytes, boot_binding_digest);
    bytes.extend_from_slice(&instance_epoch.to_be_bytes());
    bytes.extend_from_slice(&fencing_epoch.to_be_bytes());
    bytes
}

fn direct_manifest_bytes_v1(
    manifest_binding_digest: Sha256Digest,
    material_digest: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(SYNTHETIC_RECOVERY_MANIFEST_DOMAIN);
    append_manifest_digest_v1(&mut bytes, manifest_binding_digest);
    append_manifest_digest_v1(&mut bytes, material_digest);
    bytes.extend_from_slice(&material_length.to_be_bytes());
    bytes.extend_from_slice(&reserved_capacity.to_be_bytes());
    bytes
}

fn retirement_manifest_bytes_v1(
    original_manifest_digest: Sha256Digest,
    retirement_id: Sha256Digest,
    original_manifest_bytes_digest: Sha256Digest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(SYNTHETIC_RECOVERY_RETIREMENT_DOMAIN);
    append_manifest_digest_v1(&mut bytes, original_manifest_digest);
    append_manifest_digest_v1(&mut bytes, retirement_id);
    append_manifest_digest_v1(&mut bytes, original_manifest_bytes_digest);
    bytes
}

fn append_manifest_digest_v1(bytes: &mut Vec<u8>, digest: Sha256Digest) {
    bytes.extend_from_slice(digest.as_bytes());
}

fn publish_no_clobber_v1(
    staging: &Path,
    final_path: &Path,
) -> Result<(), SyntheticRecoveryProviderErrorV1> {
    match fs::hard_link(staging, final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(staging);
            return Err(SyntheticRecoveryProviderErrorV1::BindingConflict);
        }
        Err(_) => {
            let _ = fs::remove_file(staging);
            return Err(SyntheticRecoveryProviderErrorV1::Unavailable);
        }
    }
    fs::remove_file(staging).map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)
}

fn read_exact_file_v1(path: &Path) -> Result<Vec<u8>, SyntheticRecoveryProviderErrorV1> {
    fs::read(path).map_err(|_| SyntheticRecoveryProviderErrorV1::Unavailable)
}

fn read_optional_file_v1(path: &Path) -> Result<Option<Vec<u8>>, SyntheticRecoveryProviderErrorV1> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SyntheticRecoveryProviderErrorV1::Unavailable),
    }
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

#[inline]
fn reach_recovery_publication_guard_acquired_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryPublicationGuardAcquired);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_staging_created_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryStagingCreated);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_staging_written_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryStagingWritten);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_staging_synchronized_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryStagingSynchronized);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_staging_closed_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryStagingClosed);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_staging_reopened_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryStagingReopened);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_material_verified_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        recovery_test_fault::FaultBoundaryV1::RecoveryMaterialDigestLengthCapacityVerified,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_material_published_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryMaterialPublished);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_manifest_staged_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryManifestStaged);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_manifest_synchronized_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryManifestSynchronized);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_manifest_published_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryManifestPublished);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_manifest_reopened_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryManifestReopened);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_recovery_receipt_returned_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(recovery_test_fault::FaultBoundaryV1::RecoveryReceiptReturned);
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_provider_retirement_invoked_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        recovery_test_fault::FaultBoundaryV1::QuarantineAndRetirementProviderRetirementInvoked,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_provider_bytes_retired_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        recovery_test_fault::FaultBoundaryV1::QuarantineAndRetirementProviderBytesRetired,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

#[inline]
fn reach_retirement_manifest_published_v1(fault_probe: &SyntheticRecoveryFaultProbeV1) {
    #[cfg(feature = "test-fault-injection")]
    fault_probe.reach_v1(
        recovery_test_fault::FaultBoundaryV1::QuarantineAndRetirementRetirementManifestPublished,
    );
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = fault_probe;
}

fn create_synthetic_root_v1(prefix: &str) -> Result<PathBuf, SyntheticHarnessErrorV1> {
    for _ in 0..64 {
        let sequence = SYNTHETIC_ROOT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let candidate =
            std::env::temp_dir().join(format!("{prefix}-{}-{sequence}", std::process::id()));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(SyntheticHarnessErrorV1::RootCreateFailed),
        }
    }
    Err(SyntheticHarnessErrorV1::RootCreateFailed)
}

/// Exact signed request dimensions only; this is not reservation evidence.
pub(crate) fn synthetic_budget_vector_v1() -> BudgetVectorV1 {
    BudgetVectorV1::try_new(BudgetVectorInputV1 {
        max_cost_micro_units: SYNTHETIC_BUDGET_MAX_COST_MICRO_UNITS,
        action_limit: SYNTHETIC_BUDGET_ACTION_LIMIT,
        egress_bytes_limit: SYNTHETIC_BUDGET_EGRESS_BYTES_LIMIT,
        recovery_bytes: SYNTHETIC_BUDGET_RECOVERY_BYTES,
    })
    .expect("fixed public-synthetic budget is in range")
}

pub(crate) struct SyntheticProvenanceSignerV1 {
    key: SigningKey,
}

impl SyntheticProvenanceSignerV1 {
    pub(crate) fn fixed_public_synthetic() -> Self {
        Self {
            key: SigningKey::from_bytes(&SYNTHETIC_PROVENANCE_SIGNING_BYTES),
        }
    }

    pub(crate) fn verifier_v1(&self) -> SyntheticProvenanceVerifierV1 {
        SyntheticProvenanceVerifierV1 {
            public_key: self.key.verifying_key().to_bytes(),
        }
    }

    pub(crate) fn sign_detached_v1(&self, payload: &[u8]) -> [u8; 64] {
        self.key.sign(&provenance_preimage_v1(payload)).to_bytes()
    }
}

impl fmt::Debug for SyntheticProvenanceSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticProvenanceSignerV1")
            .finish_non_exhaustive()
    }
}

impl Ed25519Signer for SyntheticProvenanceSignerV1 {
    fn key_id(&self) -> &str {
        SYNTHETIC_PROVENANCE_KEY_ID
    }

    fn sign_ed25519(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        Ok(self.key.sign(message).to_bytes())
    }
}

pub(crate) struct SyntheticProvenanceVerifierV1 {
    public_key: [u8; 32],
}

impl SyntheticProvenanceVerifierV1 {
    pub(crate) fn verify_detached_v1(&self, payload: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.public_key) else {
            return false;
        };
        key.verify(
            &provenance_preimage_v1(payload),
            &Signature::from_bytes(signature),
        )
        .is_ok()
    }
}

impl fmt::Debug for SyntheticProvenanceVerifierV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticProvenanceVerifierV1")
            .finish_non_exhaustive()
    }
}

impl Ed25519KeyResolver for SyntheticProvenanceVerifierV1 {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == SYNTHETIC_PROVENANCE_KEY_ID {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

pub(crate) fn synthetic_provenance_pair_v1(
) -> (SyntheticProvenanceSignerV1, SyntheticProvenanceVerifierV1) {
    let signer = SyntheticProvenanceSignerV1::fixed_public_synthetic();
    let verifier = signer.verifier_v1();
    (signer, verifier)
}

fn provenance_preimage_v1(payload: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        SYNTHETIC_PROVENANCE_DOMAIN.len() + std::mem::size_of::<u64>() + payload.len(),
    );
    preimage.extend_from_slice(SYNTHETIC_PROVENANCE_DOMAIN);
    preimage.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    preimage.extend_from_slice(payload);
    preimage
}

pub(crate) struct SyntheticHistoricalPlanKeyResolverV1 {
    public_key: [u8; 32],
}

impl SyntheticHistoricalPlanKeyResolverV1 {
    pub(crate) fn fixed_public_synthetic() -> Self {
        Self {
            public_key: SigningKey::from_bytes(&SYNTHETIC_HISTORICAL_PLAN_SIGNING_BYTES)
                .verifying_key()
                .to_bytes(),
        }
    }
}

impl Default for SyntheticHistoricalPlanKeyResolverV1 {
    fn default() -> Self {
        Self::fixed_public_synthetic()
    }
}

impl fmt::Debug for SyntheticHistoricalPlanKeyResolverV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticHistoricalPlanKeyResolverV1")
            .finish_non_exhaustive()
    }
}

impl Ed25519KeyResolver for SyntheticHistoricalPlanKeyResolverV1 {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == SYNTHETIC_HISTORICAL_PLAN_KEY_ID {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SyntheticCoordinatorClockV1 {
    now_monotonic_ms: u64,
    unavailable: bool,
}

impl SyntheticCoordinatorClockV1 {
    pub(crate) const fn new(now_monotonic_ms: u64) -> Self {
        Self {
            now_monotonic_ms,
            unavailable: false,
        }
    }

    pub(crate) const fn unavailable() -> Self {
        Self {
            now_monotonic_ms: 0,
            unavailable: true,
        }
    }
}

impl fmt::Debug for SyntheticCoordinatorClockV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticCoordinatorClockV1")
            .finish_non_exhaustive()
    }
}

impl CoordinatorMonotonicClockV1 for SyntheticCoordinatorClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        if self.unavailable {
            Err(CoordinatorClockUnavailableV1::new())
        } else {
            Ok(self.now_monotonic_ms)
        }
    }
}

#[cfg(test)]
mod harness_contract_tests {
    use super::*;

    #[test]
    fn native_roots_redact_paths_from_diagnostics() {
        let coordinator = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root");
        let recovery = SyntheticCrossProcessRecoveryRootV1::new()
            .expect("synthetic cross-process recovery root");

        assert!(!format!("{coordinator:?}").contains(
            coordinator
                .path()
                .to_str()
                .expect("temporary path is UTF-8")
        ));
        assert!(!format!("{recovery:?}")
            .contains(recovery.path().to_str().expect("temporary path is UTF-8")));
    }

    #[test]
    fn coordinator_root_opens_and_reopens_with_opaque_identity_evidence() {
        let root = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root");
        let store = root
            .open_empty_v1(
                SyntheticCoordinatorClockV1::new(29),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                1_000,
            )
            .expect("synthetic empty coordinator opens");
        assert_eq!(store.operation_count(), 0);
        let identity = store.root_identity_evidence();
        drop(store);

        let reopened = root
            .open_existing_v1(
                identity,
                SyntheticCoordinatorClockV1::new(30),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                1_000,
            )
            .expect("synthetic existing coordinator reopens");
        assert_eq!(reopened.operation_count(), 0);
    }

    #[test]
    fn downstream_budget_uses_only_frozen_public_synthetic_values() {
        let budget = synthetic_budget_vector_v1();
        assert_eq!(
            budget.max_cost_micro_units(),
            SYNTHETIC_BUDGET_MAX_COST_MICRO_UNITS
        );
        assert_eq!(budget.action_limit(), SYNTHETIC_BUDGET_ACTION_LIMIT);
        assert_eq!(
            budget.egress_bytes_limit(),
            SYNTHETIC_BUDGET_EGRESS_BYTES_LIMIT
        );
        assert_eq!(budget.recovery_bytes(), SYNTHETIC_BUDGET_RECOVERY_BYTES);

        let recovery = SyntheticCrossProcessRecoveryFixtureV1::new()
            .expect("synthetic cross-process recovery fixture");
        assert_eq!(recovery.reserved_bytes(), budget.recovery_bytes());
        assert_eq!(
            recovery.root().child_root_argument_v1(),
            recovery.root().path().as_os_str()
        );
    }

    #[test]
    fn synthetic_provenance_pair_rejects_modified_payloads() {
        let (signer, verifier) = synthetic_provenance_pair_v1();
        let signature = signer.sign_detached_v1(b"public synthetic manifest");
        assert!(verifier.verify_detached_v1(b"public synthetic manifest", &signature));
        assert!(!verifier.verify_detached_v1(b"modified manifest", &signature));
    }

    #[test]
    fn manifest_last_provider_is_create_only_conformance_and_redacts_native_custody() {
        fn assert_provider_contracts_v1<P: RecoveryProviderV1 + RecoveryMaintenanceProviderV1>() {}
        fn assert_guard_contracts_v1<G: RecoveryPublicationGuardV1 + RecoveryCleanupGuardV1>() {}
        assert_provider_contracts_v1::<SyntheticManifestLastRecoveryProviderV1>();
        assert_guard_contracts_v1::<SyntheticRecoveryNamespaceGuardV1>();

        let fixture = SyntheticCrossProcessRecoveryFixtureV1::new()
            .expect("synthetic cross-process recovery fixture");
        let provider =
            SyntheticManifestLastRecoveryProviderV1::open_v1(fixture.root().path().to_path_buf())
                .expect("synthetic manifest-last provider opens");
        let profile = provider
            .profile_v1()
            .expect("synthetic profile is approved");
        assert_eq!(profile.profile_id(), SYNTHETIC_RECOVERY_PROFILE_ID);
        assert_eq!(profile.provider_id(), SYNTHETIC_RECOVERY_PROVIDER_ID);
        assert_eq!(
            profile.evidence_class(),
            RecoveryEvidenceClassV1::SyntheticConformance
        );
        assert!(!profile.can_establish_production_compensation());
        assert_eq!(
            profile.maximum_reserved_capacity(),
            SYNTHETIC_BUDGET_RECOVERY_BYTES
        );

        let binding = fixture.expected_manifest_digest();
        let publication = match provider.acquire_publication_guard_v1(binding, 10_000) {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
            other => panic!("publication guard must acquire, got {other:?}"),
        };
        assert!(matches!(
            provider.acquire_cleanup_guard_v1(binding, 10_000),
            SyntheticRecoveryGuardOutcomeV1::Contended
        ));
        assert_eq!(
            format!("{publication:?}"),
            "SyntheticRecoveryNamespaceGuardV1 { .. }"
        );
        drop(publication);

        let private_root = fixture.root().path().to_string_lossy();
        assert!(!format!("{provider:?}").contains(private_root.as_ref()));
        assert_eq!(
            format!("{:?}", SyntheticRecoveryProviderErrorV1::Unhealthy),
            "SYNTHETIC_RECOVERY_UNHEALTHY"
        );
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn manifest_last_provider_carries_one_explicit_shared_fault_probe() {
        let fixture = SyntheticCrossProcessRecoveryFixtureV1::new()
            .expect("synthetic cross-process recovery fixture");
        let boundary = recovery_test_fault::FaultBoundaryV1::ALL
            .iter()
            .copied()
            .find(|boundary| boundary.id() == "recovery_publication_guard_acquired")
            .expect("the selected provider boundary is frozen");
        let selection = recovery_test_fault::FaultSelectionV1::try_new(
            boundary,
            1,
            recovery_test_fault::FaultEffectV1::ProcessBarrier,
        )
        .expect("one selected provider occurrence is valid");
        let callback_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let callback_count_for_probe = std::sync::Arc::clone(&callback_count);
        let probe = recovery_test_fault::FaultProbeV1::selected_process_barrier_v1(
            selection,
            Box::new(move || {
                callback_count_for_probe.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let provider =
            SyntheticManifestLastRecoveryProviderV1::open_v1(fixture.root().path().to_path_buf())
                .expect("synthetic manifest-last provider opens")
                .with_fault_probe_v1(probe);
        let shared_provider = provider.clone();
        let binding = fixture.expected_manifest_digest();

        let selected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = provider.acquire_publication_guard_v1(binding, 10_000);
        }));
        assert!(
            selected.is_err(),
            "a returning process barrier fails closed"
        );
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);

        let guard = match shared_provider.acquire_publication_guard_v1(binding, 10_000) {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
            other => panic!("the shared one-shot probe must continue, got {other:?}"),
        };
        drop(guard);
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn manifest_publishes_last_and_retirement_tombstone_is_idempotent() {
        let fixture = SyntheticCrossProcessRecoveryFixtureV1::new()
            .expect("synthetic cross-process recovery fixture");
        let provider =
            SyntheticManifestLastRecoveryProviderV1::open_v1(fixture.root().path().to_path_buf())
                .expect("synthetic manifest-last provider opens");
        let binding = fixture.expected_manifest_digest();

        provider
            .publish_public_synthetic_v1(binding)
            .expect("public-synthetic package publishes");
        provider
            .publish_public_synthetic_v1(binding)
            .expect("exact publication repeat is idempotent");
        let material_path = provider.package_path_v1(binding, SYNTHETIC_RECOVERY_MATERIAL_SUFFIX);
        let manifest_path = provider.package_path_v1(binding, SYNTHETIC_RECOVERY_MANIFEST_SUFFIX);
        let retirement_path =
            provider.package_path_v1(binding, SYNTHETIC_RECOVERY_RETIREMENT_SUFFIX);
        assert_eq!(
            fs::read(&material_path).expect("published material reads"),
            SYNTHETIC_RECOVERY_MATERIAL
        );
        assert!(manifest_path.is_file(), "manifest is the publication point");
        assert!(!retirement_path.exists());
        assert!(
            fs::read_dir(provider.root.join(SYNTHETIC_RECOVERY_PACKAGE_DIRECTORY))
                .expect("package directory reads")
                .all(|entry| !entry
                    .expect("package entry reads")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".staging"))
        );

        let mut cleanup = match provider.acquire_cleanup_guard_v1(binding, 10_000) {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
            other => panic!("cleanup guard must acquire, got {other:?}"),
        };
        assert!(matches!(
            provider.acquire_publication_guard_v1(binding, 10_000),
            SyntheticRecoveryGuardOutcomeV1::Contended
        ));
        let retirement_id = Sha256Digest::from_bytes([0x77; 32]);
        let first = provider
            .publish_retirement_tombstone_v1(&mut cleanup, binding, retirement_id)
            .expect("provider publishes retirement tombstone");
        let repeat = provider
            .publish_retirement_tombstone_v1(&mut cleanup, binding, retirement_id)
            .expect("retirement repeat is exact and idempotent");
        assert_eq!(first, repeat);
        assert!(
            !material_path.exists(),
            "retirement removes only material bytes"
        );
        assert!(
            manifest_path.is_file(),
            "original immutable manifest remains"
        );
        assert!(retirement_path.is_file(), "retirement tombstone remains");
    }
}
