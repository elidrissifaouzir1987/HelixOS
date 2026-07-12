//! Portable recovery-provider contract boundary.
//!
//! This module describes receipt, publication-guard, and provider interactions without
//! implementing a provider. Native paths, material bytes, credentials, and production
//! durability claims remain outside the portable crate.

use crate::attempt::PreparationAttemptIdV1;
use crate::context::ReadyPreparationContextV1;
use helix_contracts::{
    AtomicityV1, Identifier, PlanPreparationClaimsV1, RecoveryClassV1, ResourceRefV1, RiskLevelV1,
    SafeU64, Sha256Digest,
};
use std::fmt;

const TARGET_REFERENCE_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-TARGET-REFERENCE\0V1\0";
const PRECONDITION_IDENTITY_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-PRECONDITION-IDENTITY\0V1\0";
const BOOT_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-BOOT-BINDING\0V1\0";

macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}

pub const RECOVERY_PROVIDER_CONTRACT_VERSION_V1: u16 = 1;
pub const RECOVERY_RECEIPT_CONTRACT_VERSION_V1: u16 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryContractBuildErrorV1 {
    VersionUnsupported,
    IntegerOutOfRange,
    InvalidIrreversibility,
    ProfileUnapproved,
    CapacityInvalid,
}

pub struct RecoveryBindingInputV1<'binding> {
    pub contract_version: u16,
    pub claims: PlanPreparationClaimsV1<'binding>,
    pub attempt: &'binding PreparationAttemptIdV1,
    pub context: &'binding ReadyPreparationContextV1,
    pub deadline_monotonic_ms: u64,
}

redacted_debug!(RecoveryBindingInputV1<'_>, "RecoveryBindingInputV1");

/// Borrowed exact provider binding assembled only from authenticated and captured facts.
pub struct RecoveryBindingV1<'binding> {
    contract_version: u16,
    claims: PlanPreparationClaimsV1<'binding>,
    attempt: &'binding PreparationAttemptIdV1,
    context: &'binding ReadyPreparationContextV1,
    deadline_monotonic_ms: SafeU64,
}

impl<'binding> RecoveryBindingV1<'binding> {
    pub fn try_new(
        input: RecoveryBindingInputV1<'binding>,
    ) -> Result<Self, RecoveryContractBuildErrorV1> {
        require_version(
            input.contract_version,
            RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
        )?;
        Ok(Self {
            contract_version: input.contract_version,
            claims: input.claims,
            attempt: input.attempt,
            context: input.context,
            deadline_monotonic_ms: safe(input.deadline_monotonic_ms)?,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }

    pub const fn claims(&self) -> PlanPreparationClaimsV1<'binding> {
        self.claims
    }

    pub const fn attempt(&self) -> &PreparationAttemptIdV1 {
        self.attempt
    }

    pub const fn context(&self) -> &ReadyPreparationContextV1 {
        self.context
    }

    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }

    pub fn target_reference_digest(&self) -> Result<Sha256Digest, RecoveryContractBuildErrorV1> {
        recovery_target_reference_digest_v1(self.claims.target())
    }

    pub fn precondition_identity_digest(
        &self,
    ) -> Result<Sha256Digest, RecoveryContractBuildErrorV1> {
        recovery_precondition_identity_digest_v1(
            self.claims.precondition_volume_id(),
            self.claims.precondition_file_id(),
        )
    }

    pub fn boot_binding_digest(&self) -> Result<Sha256Digest, RecoveryContractBuildErrorV1> {
        recovery_boot_binding_digest_v1(
            self.context.boot_id(),
            self.context.instance_epoch(),
            self.context.fencing_epoch(),
        )
    }
}

redacted_debug!(RecoveryBindingV1<'_>, "RecoveryBindingV1");

/// Restricted provider input containing no material bytes or native location.
pub struct RecoveryPreparationInputV1<'binding> {
    binding: &'binding RecoveryBindingV1<'binding>,
}

impl<'binding> RecoveryPreparationInputV1<'binding> {
    pub const fn new(binding: &'binding RecoveryBindingV1<'binding>) -> Self {
        Self { binding }
    }

    pub const fn binding(&self) -> &RecoveryBindingV1<'binding> {
        self.binding
    }
}

redacted_debug!(RecoveryPreparationInputV1<'_>, "RecoveryPreparationInputV1");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryEvidenceClassV1 {
    SyntheticConformance,
    ApprovedProduction,
}

pub struct RecoveryProviderProfileInputV1 {
    pub profile_id: Identifier,
    pub profile_version: u16,
    pub provider_id: Identifier,
    pub provider_generation: u64,
    pub evidence_class: RecoveryEvidenceClassV1,
    pub capability_binding_digest: Sha256Digest,
    pub at_rest_profile_id: Identifier,
    pub supports_create_only: bool,
    pub supports_sync: bool,
    pub supports_no_clobber_publication: bool,
    pub maximum_material_bytes: u64,
    pub maximum_reserved_capacity: u64,
}

redacted_debug!(
    RecoveryProviderProfileInputV1,
    "RecoveryProviderProfileInputV1"
);

/// Closed trusted provider profile captured outside agent-controlled input.
pub struct RecoveryProviderProfileV1 {
    profile_id: Identifier,
    profile_version: u16,
    provider_id: Identifier,
    provider_generation: SafeU64,
    evidence_class: RecoveryEvidenceClassV1,
    capability_binding_digest: Sha256Digest,
    at_rest_profile_id: Identifier,
    maximum_material_bytes: SafeU64,
    maximum_reserved_capacity: SafeU64,
}

impl RecoveryProviderProfileV1 {
    pub fn try_new(
        input: RecoveryProviderProfileInputV1,
    ) -> Result<Self, RecoveryContractBuildErrorV1> {
        require_version(input.profile_version, RECOVERY_PROVIDER_CONTRACT_VERSION_V1)?;
        if input.provider_generation == 0
            || !input.supports_create_only
            || !input.supports_sync
            || !input.supports_no_clobber_publication
        {
            return Err(RecoveryContractBuildErrorV1::ProfileUnapproved);
        }
        let maximum_material_bytes = safe(input.maximum_material_bytes)?;
        let maximum_reserved_capacity = safe(input.maximum_reserved_capacity)?;
        if maximum_material_bytes.get() > maximum_reserved_capacity.get() {
            return Err(RecoveryContractBuildErrorV1::CapacityInvalid);
        }
        Ok(Self {
            profile_id: input.profile_id,
            profile_version: input.profile_version,
            provider_id: input.provider_id,
            provider_generation: safe(input.provider_generation)?,
            evidence_class: input.evidence_class,
            capability_binding_digest: input.capability_binding_digest,
            at_rest_profile_id: input.at_rest_profile_id,
            maximum_material_bytes,
            maximum_reserved_capacity,
        })
    }

    pub fn profile_id(&self) -> &str {
        self.profile_id.as_str()
    }

    pub const fn profile_version(&self) -> u16 {
        self.profile_version
    }

    pub fn provider_id(&self) -> &str {
        self.provider_id.as_str()
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation.get()
    }

    pub const fn evidence_class(&self) -> RecoveryEvidenceClassV1 {
        self.evidence_class
    }

    pub const fn capability_binding_digest(&self) -> Sha256Digest {
        self.capability_binding_digest
    }

    pub fn at_rest_profile_id(&self) -> &str {
        self.at_rest_profile_id.as_str()
    }

    pub const fn maximum_material_bytes(&self) -> u64 {
        self.maximum_material_bytes.get()
    }

    pub const fn maximum_reserved_capacity(&self) -> u64 {
        self.maximum_reserved_capacity.get()
    }

    pub const fn can_establish_production_compensation(&self) -> bool {
        matches!(
            self.evidence_class,
            RecoveryEvidenceClassV1::ApprovedProduction
        )
    }
}

redacted_debug!(RecoveryProviderProfileV1, "RecoveryProviderProfileV1");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryMaterialStateV1 {
    Published,
}

pub struct RecoveryMaterialReceiptInputV1 {
    pub contract_version: u16,
    pub provider_profile_id: Identifier,
    pub provider_profile_version: u16,
    pub provider_id: Identifier,
    pub provider_generation: u64,
    pub evidence_class: RecoveryEvidenceClassV1,
    pub at_rest_profile_id: Identifier,
    pub capability_binding_digest: Sha256Digest,
    pub plan_id: Sha256Digest,
    pub operation_id: Identifier,
    pub attempt_id: Sha256Digest,
    pub target_reference_digest: Sha256Digest,
    pub precondition_identity_digest: Sha256Digest,
    pub precondition_digest: Sha256Digest,
    pub precondition_length: u64,
    pub recovery_class: RecoveryClassV1,
    pub atomicity: AtomicityV1,
    pub material_digest: Sha256Digest,
    pub material_length: u64,
    pub reserved_capacity: u64,
    pub material_id: Sha256Digest,
    pub publication_attempt_id: Sha256Digest,
    pub manifest_digest: Sha256Digest,
    pub state: RecoveryMaterialStateV1,
    pub boot_binding_digest: Sha256Digest,
    pub instance_epoch: u64,
    pub fencing_epoch: u64,
}

redacted_debug!(
    RecoveryMaterialReceiptInputV1,
    "RecoveryMaterialReceiptInputV1"
);

/// Immutable provider evidence. Construction alone never establishes preparation.
pub struct RecoveryMaterialReceiptV1 {
    contract_version: u16,
    provider_profile_id: Identifier,
    provider_profile_version: u16,
    provider_id: Identifier,
    provider_generation: SafeU64,
    evidence_class: RecoveryEvidenceClassV1,
    at_rest_profile_id: Identifier,
    capability_binding_digest: Sha256Digest,
    plan_id: Sha256Digest,
    operation_id: Identifier,
    attempt_id: Sha256Digest,
    target_reference_digest: Sha256Digest,
    precondition_identity_digest: Sha256Digest,
    precondition_digest: Sha256Digest,
    precondition_length: SafeU64,
    recovery_class: RecoveryClassV1,
    atomicity: AtomicityV1,
    material_digest: Sha256Digest,
    material_length: SafeU64,
    reserved_capacity: SafeU64,
    material_id: Sha256Digest,
    publication_attempt_id: Sha256Digest,
    manifest_digest: Sha256Digest,
    state: RecoveryMaterialStateV1,
    boot_binding_digest: Sha256Digest,
    instance_epoch: SafeU64,
    fencing_epoch: SafeU64,
}

impl RecoveryMaterialReceiptV1 {
    pub fn try_new(
        input: RecoveryMaterialReceiptInputV1,
    ) -> Result<Self, RecoveryContractBuildErrorV1> {
        require_version(input.contract_version, RECOVERY_RECEIPT_CONTRACT_VERSION_V1)?;
        require_version(
            input.provider_profile_version,
            RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
        )?;
        Ok(Self {
            contract_version: input.contract_version,
            provider_profile_id: input.provider_profile_id,
            provider_profile_version: input.provider_profile_version,
            provider_id: input.provider_id,
            provider_generation: safe(input.provider_generation)?,
            evidence_class: input.evidence_class,
            at_rest_profile_id: input.at_rest_profile_id,
            capability_binding_digest: input.capability_binding_digest,
            plan_id: input.plan_id,
            operation_id: input.operation_id,
            attempt_id: input.attempt_id,
            target_reference_digest: input.target_reference_digest,
            precondition_identity_digest: input.precondition_identity_digest,
            precondition_digest: input.precondition_digest,
            precondition_length: safe(input.precondition_length)?,
            recovery_class: input.recovery_class,
            atomicity: input.atomicity,
            material_digest: input.material_digest,
            material_length: safe(input.material_length)?,
            reserved_capacity: safe(input.reserved_capacity)?,
            material_id: input.material_id,
            publication_attempt_id: input.publication_attempt_id,
            manifest_digest: input.manifest_digest,
            state: input.state,
            boot_binding_digest: input.boot_binding_digest,
            instance_epoch: safe(input.instance_epoch)?,
            fencing_epoch: safe(input.fencing_epoch)?,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub fn provider_profile_id(&self) -> &str {
        self.provider_profile_id.as_str()
    }
    pub const fn provider_profile_version(&self) -> u16 {
        self.provider_profile_version
    }
    pub fn provider_id(&self) -> &str {
        self.provider_id.as_str()
    }
    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation.get()
    }
    pub const fn evidence_class(&self) -> &RecoveryEvidenceClassV1 {
        &self.evidence_class
    }
    pub fn at_rest_profile_id(&self) -> &str {
        self.at_rest_profile_id.as_str()
    }
    pub const fn capability_binding_digest(&self) -> Sha256Digest {
        self.capability_binding_digest
    }
    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }
    pub fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }
    pub const fn attempt_id(&self) -> Sha256Digest {
        self.attempt_id
    }
    pub const fn target_reference_digest(&self) -> Sha256Digest {
        self.target_reference_digest
    }
    pub const fn precondition_identity_digest(&self) -> Sha256Digest {
        self.precondition_identity_digest
    }
    pub const fn precondition_digest(&self) -> Sha256Digest {
        self.precondition_digest
    }
    pub const fn precondition_length(&self) -> u64 {
        self.precondition_length.get()
    }
    pub const fn recovery_class(&self) -> RecoveryClassV1 {
        self.recovery_class
    }
    pub const fn atomicity(&self) -> AtomicityV1 {
        self.atomicity
    }
    pub const fn material_digest(&self) -> Sha256Digest {
        self.material_digest
    }
    pub const fn material_length(&self) -> u64 {
        self.material_length.get()
    }
    pub const fn reserved_capacity(&self) -> u64 {
        self.reserved_capacity.get()
    }
    pub const fn material_id(&self) -> Sha256Digest {
        self.material_id
    }
    pub const fn publication_attempt_id(&self) -> Sha256Digest {
        self.publication_attempt_id
    }
    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }
    pub const fn state(&self) -> &RecoveryMaterialStateV1 {
        &self.state
    }
    pub const fn boot_binding_digest(&self) -> Sha256Digest {
        self.boot_binding_digest
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch.get()
    }
}

redacted_debug!(RecoveryMaterialReceiptV1, "RecoveryMaterialReceiptV1");

/// Fixed no-material evidence for an already-authenticated irreversible L2 plan.
pub struct IrreversibilityEvidenceV1 {
    contract_version: u16,
    risk_level: RiskLevelV1,
    recovery_class: RecoveryClassV1,
    atomicity: AtomicityV1,
    no_material: bool,
}

impl IrreversibilityEvidenceV1 {
    pub fn try_new(
        risk_level: RiskLevelV1,
        recovery_class: RecoveryClassV1,
        atomicity: AtomicityV1,
    ) -> Result<Self, RecoveryContractBuildErrorV1> {
        if risk_level != RiskLevelV1::L2 || recovery_class != RecoveryClassV1::Irreversible {
            return Err(RecoveryContractBuildErrorV1::InvalidIrreversibility);
        }
        Ok(Self {
            contract_version: RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
            risk_level,
            recovery_class,
            atomicity,
            no_material: true,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn risk_level(&self) -> RiskLevelV1 {
        self.risk_level
    }
    pub const fn recovery_class(&self) -> RecoveryClassV1 {
        self.recovery_class
    }
    pub const fn atomicity(&self) -> AtomicityV1 {
        self.atomicity
    }
    pub const fn no_material(&self) -> bool {
        self.no_material
    }
}

redacted_debug!(IrreversibilityEvidenceV1, "IrreversibilityEvidenceV1");

// Receipt custody stays inline so moving verified evidence cannot introduce another
// allocation boundary before coordinator commit.
#[allow(clippy::large_enum_variant)]
pub enum RecoveryEvidenceV1 {
    Material(RecoveryMaterialReceiptV1),
    Irreversible(IrreversibilityEvidenceV1),
}

impl fmt::Debug for RecoveryEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Material(_) => "Material(..)",
            Self::Irreversible(_) => "Irreversible(..)",
        };
        write!(formatter, "RecoveryEvidenceV1::{variant}")
    }
}

/// Opaque mutually exclusive publication custody supplied by a provider implementation.
pub trait RecoveryPublicationGuardV1: Send {
    fn release(self);
}

/// Opaque provider custody mutually exclusive with publication for one material binding.
pub trait RecoveryCleanupGuardV1: Send {
    fn release(self);
}

pub enum RecoveryCleanupGuardOutcomeV1<G> {
    Acquired(G),
    Contended,
    Unavailable,
    DeadlineReached,
    Unsupported,
}

impl<G> fmt::Debug for RecoveryCleanupGuardOutcomeV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Acquired(_) => "Acquired(..)",
            Self::Contended => "Contended",
            Self::Unavailable => "Unavailable",
            Self::DeadlineReached => "DeadlineReached",
            Self::Unsupported => "Unsupported",
        };
        write!(formatter, "RecoveryCleanupGuardOutcomeV1::{variant}")
    }
}

pub enum RecoveryGuardOutcomeV1<G> {
    Acquired(G),
    Unavailable,
    DeadlineReached,
    Conflict,
    Unsupported,
}

impl<G> fmt::Debug for RecoveryGuardOutcomeV1<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Acquired(_) => "Acquired(..)",
            Self::Unavailable => "Unavailable",
            Self::DeadlineReached => "DeadlineReached",
            Self::Conflict => "Conflict",
            Self::Unsupported => "Unsupported",
        };
        write!(formatter, "RecoveryGuardOutcomeV1::{variant}")
    }
}

// A published receipt is deliberately moved directly from provider to orchestration.
#[allow(clippy::large_enum_variant)]
pub enum RecoveryPreparationOutcomeV1 {
    Published(RecoveryMaterialReceiptV1),
    BindingConflict,
    Unverified,
    ProviderFailed,
    Ambiguous,
}

impl fmt::Debug for RecoveryPreparationOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Published(_) => "Published(..)",
            Self::BindingConflict => "BindingConflict",
            Self::Unverified => "Unverified",
            Self::ProviderFailed => "ProviderFailed",
            Self::Ambiguous => "Ambiguous",
        };
        write!(formatter, "RecoveryPreparationOutcomeV1::{variant}")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryVerificationV1 {
    Exact,
    Missing,
    Conflict,
    Unavailable,
    Unhealthy,
}

/// Replaceable synchronous recovery provider; no provider implementation lives here.
pub trait RecoveryProviderV1: Send + Sync {
    type PublicationGuard: RecoveryPublicationGuardV1;

    fn acquire_publication_guard(
        &self,
        input: &RecoveryBindingV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> RecoveryGuardOutcomeV1<Self::PublicationGuard>;

    fn prepare_and_publish(
        &self,
        guard: &mut Self::PublicationGuard,
        input: &RecoveryPreparationInputV1<'_>,
    ) -> RecoveryPreparationOutcomeV1;

    fn verify_published(
        &self,
        guard: &mut Self::PublicationGuard,
        receipt: &RecoveryMaterialReceiptV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryVerificationV1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryRetirementVerificationV1 {
    Retired,
    AlreadyRetired,
    BindingConflict,
    Unavailable,
    Unhealthy,
}

/// Provider maintenance surface required by guarded reconciliation and retirement.
///
/// Concrete backup/restore inventory types stay with the provider implementation; this
/// portable boundary freezes the mutually-exclusive cleanup and exact retirement
/// custody without accepting a native root or material bytes.
pub trait RecoveryMaintenanceProviderV1: Send + Sync {
    type CleanupGuard: RecoveryCleanupGuardV1;

    fn acquire_cleanup_guard(
        &self,
        manifest_digest: Sha256Digest,
        deadline_monotonic_ms: u64,
    ) -> RecoveryCleanupGuardOutcomeV1<Self::CleanupGuard>;

    fn retire_exact(
        &self,
        guard: &mut Self::CleanupGuard,
        manifest_digest: Sha256Digest,
        retirement_id: Sha256Digest,
        deadline_monotonic_ms: u64,
    ) -> RecoveryRetirementVerificationV1;
}

pub fn recovery_target_reference_digest_v1(
    target: &ResourceRefV1,
) -> Result<Sha256Digest, RecoveryContractBuildErrorV1> {
    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(TARGET_REFERENCE_DOMAIN_V1);
    extend_length_prefixed_v1(&mut preimage, target.root_id().as_bytes())?;
    preimage.extend_from_slice(
        &u64::try_from(target.components().len())
            .map_err(|_| RecoveryContractBuildErrorV1::IntegerOutOfRange)?
            .to_be_bytes(),
    );
    for component in target.components() {
        extend_length_prefixed_v1(&mut preimage, component.as_bytes())?;
    }
    Ok(Sha256Digest::digest(&preimage))
}

pub fn recovery_precondition_identity_digest_v1(
    volume_id: &str,
    file_id: &str,
) -> Result<Sha256Digest, RecoveryContractBuildErrorV1> {
    let mut preimage = Vec::with_capacity(
        PRECONDITION_IDENTITY_DOMAIN_V1.len() + volume_id.len() + file_id.len() + 16,
    );
    preimage.extend_from_slice(PRECONDITION_IDENTITY_DOMAIN_V1);
    extend_length_prefixed_v1(&mut preimage, volume_id.as_bytes())?;
    extend_length_prefixed_v1(&mut preimage, file_id.as_bytes())?;
    Ok(Sha256Digest::digest(&preimage))
}

pub fn recovery_boot_binding_digest_v1(
    boot_id: &str,
    instance_epoch: u64,
    fencing_epoch: u64,
) -> Result<Sha256Digest, RecoveryContractBuildErrorV1> {
    let mut preimage = Vec::with_capacity(BOOT_BINDING_DOMAIN_V1.len() + boot_id.len() + 24);
    preimage.extend_from_slice(BOOT_BINDING_DOMAIN_V1);
    extend_length_prefixed_v1(&mut preimage, boot_id.as_bytes())?;
    preimage.extend_from_slice(&instance_epoch.to_be_bytes());
    preimage.extend_from_slice(&fencing_epoch.to_be_bytes());
    Ok(Sha256Digest::digest(&preimage))
}

fn extend_length_prefixed_v1(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), RecoveryContractBuildErrorV1> {
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| RecoveryContractBuildErrorV1::IntegerOutOfRange)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn safe(value: u64) -> Result<SafeU64, RecoveryContractBuildErrorV1> {
    SafeU64::new(value).map_err(|_| RecoveryContractBuildErrorV1::IntegerOutOfRange)
}

fn require_version(value: u16, expected: u16) -> Result<(), RecoveryContractBuildErrorV1> {
    if value != expected {
        return Err(RecoveryContractBuildErrorV1::VersionUnsupported);
    }
    Ok(())
}
