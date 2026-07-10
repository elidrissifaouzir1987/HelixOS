use crate::EligibilityContextBuildErrorV1;
use helix_contracts::{Nonce128, RequestSourceKindV1, RiskLevelV1, SafeU64, Sha256Digest};
use std::fmt;

pub const MAX_ELIGIBILITY_IDENTIFIER_BYTES: usize = 128;
pub const MAX_AVAILABLE_CAPABILITIES: usize = 128;
pub const MAX_POLICY_MANDATORY_CAPABILITIES: usize = 64;
pub const MAX_CATALOGUE_MANDATORY_CAPABILITIES: usize = 64;

type BuildResult<T> = Result<T, EligibilityContextBuildErrorV1>;

macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WallClockViewV1 {
    Unavailable,
    RollbackSuspected,
    Healthy(SafeU64),
}

impl WallClockViewV1 {
    pub fn healthy(now_utc_unix_ms: u64) -> BuildResult<Self> {
        Ok(Self::Healthy(safe(now_utc_unix_ms)?))
    }

    pub const fn now_utc_unix_ms(&self) -> Option<u64> {
        match self {
            Self::Healthy(value) => Some(value.get()),
            Self::Unavailable | Self::RollbackSuspected => None,
        }
    }
}

impl fmt::Debug for WallClockViewV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::RollbackSuspected => "RollbackSuspected",
            Self::Healthy(_) => "Healthy",
        };
        write!(formatter, "WallClockViewV1::{variant}")
    }
}

pub struct MonotonicSampleV1<'ctx> {
    boot_id: &'ctx str,
    now_monotonic_ms: SafeU64,
}

impl<'ctx> MonotonicSampleV1<'ctx> {
    pub fn try_new(boot_id: &'ctx str, now_monotonic_ms: u64) -> BuildResult<Self> {
        validate_identifier(boot_id)?;
        Ok(Self {
            boot_id,
            now_monotonic_ms: safe(now_monotonic_ms)?,
        })
    }

    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }

    pub const fn now_monotonic_ms(&self) -> u64 {
        self.now_monotonic_ms.get()
    }
}

redacted_debug!(MonotonicSampleV1<'_>, "MonotonicSampleV1");

pub enum MonotonicClockViewV1<'ctx> {
    Unavailable,
    NotSuspendAware,
    Regressed,
    Healthy(MonotonicSampleV1<'ctx>),
}

impl fmt::Debug for MonotonicClockViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::NotSuspendAware => "NotSuspendAware",
            Self::Regressed => "Regressed",
            Self::Healthy(_) => "Healthy",
        };
        write!(formatter, "MonotonicClockViewV1::{variant}")
    }
}

pub struct TimeViewInputV1<'ctx> {
    pub clock_generation: u64,
    pub wall: WallClockViewV1,
    pub monotonic: MonotonicClockViewV1<'ctx>,
}

redacted_debug!(TimeViewInputV1<'_>, "TimeViewInputV1");

pub struct TimeViewV1<'ctx> {
    clock_generation: SafeU64,
    wall: WallClockViewV1,
    monotonic: MonotonicClockViewV1<'ctx>,
}

impl<'ctx> TimeViewV1<'ctx> {
    pub fn try_new(input: TimeViewInputV1<'ctx>) -> BuildResult<Self> {
        Ok(Self {
            clock_generation: safe(input.clock_generation)?,
            wall: input.wall,
            monotonic: input.monotonic,
        })
    }

    pub const fn clock_generation(&self) -> u64 {
        self.clock_generation.get()
    }

    pub const fn wall(&self) -> &WallClockViewV1 {
        &self.wall
    }

    pub const fn monotonic(&self) -> &MonotonicClockViewV1<'ctx> {
        &self.monotonic
    }
}

redacted_debug!(TimeViewV1<'_>, "TimeViewV1");

pub struct PlanDeadlineInputV1<'ctx> {
    pub plan_id: Sha256Digest,
    pub boot_id: &'ctx str,
    pub deadline_monotonic_ms: u64,
    pub deadline_generation: u64,
}

redacted_debug!(PlanDeadlineInputV1<'_>, "PlanDeadlineInputV1");

pub struct PlanDeadlineRecordV1<'ctx> {
    plan_id: Sha256Digest,
    boot_id: &'ctx str,
    deadline_monotonic_ms: SafeU64,
    deadline_generation: SafeU64,
}

impl<'ctx> PlanDeadlineRecordV1<'ctx> {
    pub fn try_new(input: PlanDeadlineInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.boot_id)?;
        Ok(Self {
            plan_id: input.plan_id,
            boot_id: input.boot_id,
            deadline_monotonic_ms: safe(input.deadline_monotonic_ms)?,
            deadline_generation: safe(input.deadline_generation)?,
        })
    }

    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }

    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }

    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }

    pub const fn deadline_generation(&self) -> u64 {
        self.deadline_generation.get()
    }
}

redacted_debug!(PlanDeadlineRecordV1<'_>, "PlanDeadlineRecordV1");

pub enum PlanDeadlineViewV1<'ctx> {
    Missing,
    Unavailable,
    Inconsistent,
    Current(PlanDeadlineRecordV1<'ctx>),
}

impl fmt::Debug for PlanDeadlineViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Missing => "Missing",
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Current(_) => "Current",
        };
        write!(formatter, "PlanDeadlineViewV1::{variant}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisorAdmissionStateV1 {
    Open,
    Paused,
    Aborting,
    Halted,
    Restoring,
}

pub struct SupervisorInputV1<'ctx> {
    pub admission_state: SupervisorAdmissionStateV1,
    pub boot_id: &'ctx str,
    pub instance_epoch: u64,
    pub fencing_epoch: u64,
    pub supervisor_generation: u64,
}

redacted_debug!(SupervisorInputV1<'_>, "SupervisorInputV1");

pub struct SupervisorRecordV1<'ctx> {
    admission_state: SupervisorAdmissionStateV1,
    boot_id: &'ctx str,
    instance_epoch: SafeU64,
    fencing_epoch: SafeU64,
    supervisor_generation: SafeU64,
}

impl<'ctx> SupervisorRecordV1<'ctx> {
    pub fn try_new(input: SupervisorInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.boot_id)?;
        Ok(Self {
            admission_state: input.admission_state,
            boot_id: input.boot_id,
            instance_epoch: safe(input.instance_epoch)?,
            fencing_epoch: safe(input.fencing_epoch)?,
            supervisor_generation: safe(input.supervisor_generation)?,
        })
    }

    pub const fn admission_state(&self) -> SupervisorAdmissionStateV1 {
        self.admission_state
    }

    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }

    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }

    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch.get()
    }

    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation.get()
    }
}

redacted_debug!(SupervisorRecordV1<'_>, "SupervisorRecordV1");

pub enum SupervisorViewV1<'ctx> {
    Unavailable,
    Inconsistent,
    Current(SupervisorRecordV1<'ctx>),
}

impl fmt::Debug for SupervisorViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Current(_) => "Current",
        };
        write!(formatter, "SupervisorViewV1::{variant}")
    }
}

pub struct SignerTrustInputV1<'ctx> {
    pub key_id: &'ctx str,
    pub public_key_fingerprint: Sha256Digest,
    pub trust_generation: u64,
    pub minimum_accepted_issued_at_unix_ms: u64,
}

redacted_debug!(SignerTrustInputV1<'_>, "SignerTrustInputV1");

pub struct SignerTrustRecordV1<'ctx> {
    key_id: &'ctx str,
    public_key_fingerprint: Sha256Digest,
    trust_generation: SafeU64,
    minimum_accepted_issued_at_unix_ms: SafeU64,
}

impl<'ctx> SignerTrustRecordV1<'ctx> {
    pub fn try_new(input: SignerTrustInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.key_id)?;
        Ok(Self {
            key_id: input.key_id,
            public_key_fingerprint: input.public_key_fingerprint,
            trust_generation: safe(input.trust_generation)?,
            minimum_accepted_issued_at_unix_ms: safe(input.minimum_accepted_issued_at_unix_ms)?,
        })
    }

    pub const fn key_id(&self) -> &str {
        self.key_id
    }

    pub const fn public_key_fingerprint(&self) -> Sha256Digest {
        self.public_key_fingerprint
    }

    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation.get()
    }

    pub const fn minimum_accepted_issued_at_unix_ms(&self) -> u64 {
        self.minimum_accepted_issued_at_unix_ms.get()
    }
}

redacted_debug!(SignerTrustRecordV1<'_>, "SignerTrustRecordV1");

pub enum SignerTrustViewV1<'ctx> {
    Unavailable,
    Inconsistent,
    Unknown,
    Revoked,
    Trusted(SignerTrustRecordV1<'ctx>),
}

impl fmt::Debug for SignerTrustViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Unknown => "Unknown",
            Self::Revoked => "Revoked",
            Self::Trusted(_) => "Trusted",
        };
        write!(formatter, "SignerTrustViewV1::{variant}")
    }
}

pub struct WorkloadIdentityInputV1<'ctx> {
    pub workload_id: &'ctx str,
    pub evidence_digest: Sha256Digest,
    pub identity_generation: u64,
    pub boot_id: &'ctx str,
    pub instance_epoch: u64,
    pub not_before_utc_unix_ms: u64,
    pub expires_at_utc_unix_ms: u64,
    pub deadline_monotonic_ms: u64,
}

redacted_debug!(WorkloadIdentityInputV1<'_>, "WorkloadIdentityInputV1");

pub struct WorkloadIdentityRecordV1<'ctx> {
    workload_id: &'ctx str,
    evidence_digest: Sha256Digest,
    identity_generation: SafeU64,
    boot_id: &'ctx str,
    instance_epoch: SafeU64,
    not_before_utc_unix_ms: SafeU64,
    expires_at_utc_unix_ms: SafeU64,
    deadline_monotonic_ms: SafeU64,
}

impl<'ctx> WorkloadIdentityRecordV1<'ctx> {
    pub fn try_new(input: WorkloadIdentityInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.workload_id)?;
        validate_identifier(input.boot_id)?;
        validate_interval(input.not_before_utc_unix_ms, input.expires_at_utc_unix_ms)?;
        Ok(Self {
            workload_id: input.workload_id,
            evidence_digest: input.evidence_digest,
            identity_generation: safe(input.identity_generation)?,
            boot_id: input.boot_id,
            instance_epoch: safe(input.instance_epoch)?,
            not_before_utc_unix_ms: safe(input.not_before_utc_unix_ms)?,
            expires_at_utc_unix_ms: safe(input.expires_at_utc_unix_ms)?,
            deadline_monotonic_ms: safe(input.deadline_monotonic_ms)?,
        })
    }

    pub const fn workload_id(&self) -> &str {
        self.workload_id
    }
    pub const fn evidence_digest(&self) -> Sha256Digest {
        self.evidence_digest
    }
    pub const fn identity_generation(&self) -> u64 {
        self.identity_generation.get()
    }
    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }
    pub const fn not_before_utc_unix_ms(&self) -> u64 {
        self.not_before_utc_unix_ms.get()
    }
    pub const fn expires_at_utc_unix_ms(&self) -> u64 {
        self.expires_at_utc_unix_ms.get()
    }
    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }
}

redacted_debug!(WorkloadIdentityRecordV1<'_>, "WorkloadIdentityRecordV1");

pub enum WorkloadIdentityViewV1<'ctx> {
    Unavailable,
    Inconsistent,
    Unknown,
    Revoked,
    Trusted(WorkloadIdentityRecordV1<'ctx>),
}

impl fmt::Debug for WorkloadIdentityViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Unknown => "Unknown",
            Self::Revoked => "Revoked",
            Self::Trusted(_) => "Trusted",
        };
        write!(formatter, "WorkloadIdentityViewV1::{variant}")
    }
}

pub struct LeaseAllowanceInputV1 {
    pub plan_id: Sha256Digest,
    pub decision_digest: Sha256Digest,
}

redacted_debug!(LeaseAllowanceInputV1, "LeaseAllowanceInputV1");

pub struct LeaseAllowanceV1 {
    plan_id: Sha256Digest,
    decision_digest: Sha256Digest,
}

impl LeaseAllowanceV1 {
    pub const fn new(input: LeaseAllowanceInputV1) -> Self {
        Self {
            plan_id: input.plan_id,
            decision_digest: input.decision_digest,
        }
    }

    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }
    pub const fn decision_digest(&self) -> Sha256Digest {
        self.decision_digest
    }
}

redacted_debug!(LeaseAllowanceV1, "LeaseAllowanceV1");

pub enum LeaseAuthorityDecisionV1 {
    Allows(LeaseAllowanceV1),
    PlanMismatch,
    IntentDenied,
    ScopeWidened,
    BudgetWidened,
    PriceTableMismatch,
    ReservationMismatch,
    Unavailable,
    Inconsistent,
}

impl fmt::Debug for LeaseAuthorityDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Allows(_) => "Allows",
            Self::PlanMismatch => "PlanMismatch",
            Self::IntentDenied => "IntentDenied",
            Self::ScopeWidened => "ScopeWidened",
            Self::BudgetWidened => "BudgetWidened",
            Self::PriceTableMismatch => "PriceTableMismatch",
            Self::ReservationMismatch => "ReservationMismatch",
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
        };
        write!(formatter, "LeaseAuthorityDecisionV1::{variant}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseStateV1 {
    Active,
    Revoked,
    Exhausted,
}

pub struct ActiveLeaseInputV1<'ctx> {
    pub lease_digest: Sha256Digest,
    pub lease_generation: u64,
    pub state: LeaseStateV1,
    pub task_id: &'ctx str,
    pub workload_id: &'ctx str,
    pub boot_id: &'ctx str,
    pub instance_epoch: u64,
    pub request_source_kind: RequestSourceKindV1,
    pub request_source_digest: Sha256Digest,
    pub not_before_utc_unix_ms: u64,
    pub expires_at_utc_unix_ms: u64,
    pub deadline_monotonic_ms: u64,
    pub decision: LeaseAuthorityDecisionV1,
}

redacted_debug!(ActiveLeaseInputV1<'_>, "ActiveLeaseInputV1");

pub struct ActiveLeaseRecordV1<'ctx> {
    lease_digest: Sha256Digest,
    lease_generation: SafeU64,
    state: LeaseStateV1,
    task_id: &'ctx str,
    workload_id: &'ctx str,
    boot_id: &'ctx str,
    instance_epoch: SafeU64,
    request_source_kind: RequestSourceKindV1,
    request_source_digest: Sha256Digest,
    not_before_utc_unix_ms: SafeU64,
    expires_at_utc_unix_ms: SafeU64,
    deadline_monotonic_ms: SafeU64,
    decision: LeaseAuthorityDecisionV1,
}

impl<'ctx> ActiveLeaseRecordV1<'ctx> {
    pub fn try_new(input: ActiveLeaseInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.task_id)?;
        validate_identifier(input.workload_id)?;
        validate_identifier(input.boot_id)?;
        validate_interval(input.not_before_utc_unix_ms, input.expires_at_utc_unix_ms)?;
        Ok(Self {
            lease_digest: input.lease_digest,
            lease_generation: safe(input.lease_generation)?,
            state: input.state,
            task_id: input.task_id,
            workload_id: input.workload_id,
            boot_id: input.boot_id,
            instance_epoch: safe(input.instance_epoch)?,
            request_source_kind: input.request_source_kind,
            request_source_digest: input.request_source_digest,
            not_before_utc_unix_ms: safe(input.not_before_utc_unix_ms)?,
            expires_at_utc_unix_ms: safe(input.expires_at_utc_unix_ms)?,
            deadline_monotonic_ms: safe(input.deadline_monotonic_ms)?,
            decision: input.decision,
        })
    }

    pub const fn lease_digest(&self) -> Sha256Digest {
        self.lease_digest
    }
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation.get()
    }
    pub const fn state(&self) -> LeaseStateV1 {
        self.state
    }
    pub const fn task_id(&self) -> &str {
        self.task_id
    }
    pub const fn workload_id(&self) -> &str {
        self.workload_id
    }
    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }
    pub const fn request_source_kind(&self) -> RequestSourceKindV1 {
        self.request_source_kind
    }
    pub const fn request_source_digest(&self) -> Sha256Digest {
        self.request_source_digest
    }
    pub const fn not_before_utc_unix_ms(&self) -> u64 {
        self.not_before_utc_unix_ms.get()
    }
    pub const fn expires_at_utc_unix_ms(&self) -> u64 {
        self.expires_at_utc_unix_ms.get()
    }
    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }
    pub const fn decision(&self) -> &LeaseAuthorityDecisionV1 {
        &self.decision
    }
}

redacted_debug!(ActiveLeaseRecordV1<'_>, "ActiveLeaseRecordV1");

// The owned record avoids self-referential core fixtures and heap allocation during evaluation.
#[allow(clippy::large_enum_variant)]
pub enum LeaseResolutionV1<'ctx> {
    Unavailable,
    Inconsistent,
    NotFound,
    Multiple,
    ExactlyOne(ActiveLeaseRecordV1<'ctx>),
}

impl fmt::Debug for LeaseResolutionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::NotFound => "NotFound",
            Self::Multiple => "Multiple",
            Self::ExactlyOne(_) => "ExactlyOne",
        };
        write!(formatter, "LeaseResolutionV1::{variant}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationStatusV1 {
    Granted,
    Denied,
    Revoked,
}

pub struct AuthorizationInputV1<'ctx> {
    pub status: AuthorizationStatusV1,
    pub plan_id: Sha256Digest,
    pub operation_id: &'ctx str,
    pub risk_level: RiskLevelV1,
    pub nonce: Nonce128,
    pub evidence_digest: Sha256Digest,
    pub authorization_generation: u64,
    pub boot_id: &'ctx str,
    pub not_before_utc_unix_ms: u64,
    pub expires_at_utc_unix_ms: u64,
    pub deadline_monotonic_ms: u64,
}

redacted_debug!(AuthorizationInputV1<'_>, "AuthorizationInputV1");

pub struct AuthorizationRecordV1<'ctx> {
    status: AuthorizationStatusV1,
    plan_id: Sha256Digest,
    operation_id: &'ctx str,
    risk_level: RiskLevelV1,
    nonce: Nonce128,
    evidence_digest: Sha256Digest,
    authorization_generation: SafeU64,
    boot_id: &'ctx str,
    not_before_utc_unix_ms: SafeU64,
    expires_at_utc_unix_ms: SafeU64,
    deadline_monotonic_ms: SafeU64,
}

impl<'ctx> AuthorizationRecordV1<'ctx> {
    pub fn try_new(input: AuthorizationInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.operation_id)?;
        validate_identifier(input.boot_id)?;
        validate_interval(input.not_before_utc_unix_ms, input.expires_at_utc_unix_ms)?;
        Ok(Self {
            status: input.status,
            plan_id: input.plan_id,
            operation_id: input.operation_id,
            risk_level: input.risk_level,
            nonce: input.nonce,
            evidence_digest: input.evidence_digest,
            authorization_generation: safe(input.authorization_generation)?,
            boot_id: input.boot_id,
            not_before_utc_unix_ms: safe(input.not_before_utc_unix_ms)?,
            expires_at_utc_unix_ms: safe(input.expires_at_utc_unix_ms)?,
            deadline_monotonic_ms: safe(input.deadline_monotonic_ms)?,
        })
    }

    pub const fn status(&self) -> AuthorizationStatusV1 {
        self.status
    }
    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }
    pub const fn operation_id(&self) -> &str {
        self.operation_id
    }
    pub const fn risk_level(&self) -> RiskLevelV1 {
        self.risk_level
    }
    pub const fn nonce(&self) -> Nonce128 {
        self.nonce
    }
    pub const fn evidence_digest(&self) -> Sha256Digest {
        self.evidence_digest
    }
    pub const fn authorization_generation(&self) -> u64 {
        self.authorization_generation.get()
    }
    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }
    pub const fn not_before_utc_unix_ms(&self) -> u64 {
        self.not_before_utc_unix_ms.get()
    }
    pub const fn expires_at_utc_unix_ms(&self) -> u64 {
        self.expires_at_utc_unix_ms.get()
    }
    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }
}

redacted_debug!(AuthorizationRecordV1<'_>, "AuthorizationRecordV1");

pub enum AuthorizationViewV1<'ctx> {
    Unavailable,
    Inconsistent,
    Current(AuthorizationRecordV1<'ctx>),
}

impl fmt::Debug for AuthorizationViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Current(_) => "Current",
        };
        write!(formatter, "AuthorizationViewV1::{variant}")
    }
}

pub struct PlanDecisionEvidenceInputV1 {
    pub plan_id: Sha256Digest,
    pub decision_digest: Sha256Digest,
}

redacted_debug!(PlanDecisionEvidenceInputV1, "PlanDecisionEvidenceInputV1");

pub struct PlanDecisionEvidenceV1 {
    plan_id: Sha256Digest,
    decision_digest: Sha256Digest,
}

impl PlanDecisionEvidenceV1 {
    pub const fn new(input: PlanDecisionEvidenceInputV1) -> Self {
        Self {
            plan_id: input.plan_id,
            decision_digest: input.decision_digest,
        }
    }
    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }
    pub const fn decision_digest(&self) -> Sha256Digest {
        self.decision_digest
    }
}

redacted_debug!(PlanDecisionEvidenceV1, "PlanDecisionEvidenceV1");

pub enum PolicyDecisionV1 {
    Allow(PlanDecisionEvidenceV1),
    Deny(PlanDecisionEvidenceV1),
}

impl fmt::Debug for PolicyDecisionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Allow(_) => "Allow",
            Self::Deny(_) => "Deny",
        };
        write!(formatter, "PolicyDecisionV1::{variant}")
    }
}

pub struct PolicyRecordInputV1<'ctx> {
    pub version: &'ctx str,
    pub resolved_content_digest: Sha256Digest,
    pub active_content_digest: Sha256Digest,
    pub policy_generation: u64,
    pub decision_policy_generation: u64,
    pub decision_generation: u64,
    pub decision: PolicyDecisionV1,
    pub max_capability_age_ms: u64,
    pub mandatory_capabilities: &'ctx [String],
}

redacted_debug!(PolicyRecordInputV1<'_>, "PolicyRecordInputV1");

pub struct PolicyRecordV1<'ctx> {
    version: &'ctx str,
    resolved_content_digest: Sha256Digest,
    active_content_digest: Sha256Digest,
    policy_generation: SafeU64,
    decision_policy_generation: SafeU64,
    decision_generation: SafeU64,
    decision: PolicyDecisionV1,
    max_capability_age_ms: SafeU64,
    mandatory_capabilities: &'ctx [String],
}

impl<'ctx> PolicyRecordV1<'ctx> {
    pub fn try_new(input: PolicyRecordInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.version)?;
        validate_capabilities(
            input.mandatory_capabilities,
            MAX_POLICY_MANDATORY_CAPABILITIES,
        )?;
        Ok(Self {
            version: input.version,
            resolved_content_digest: input.resolved_content_digest,
            active_content_digest: input.active_content_digest,
            policy_generation: safe(input.policy_generation)?,
            decision_policy_generation: safe(input.decision_policy_generation)?,
            decision_generation: safe(input.decision_generation)?,
            decision: input.decision,
            max_capability_age_ms: safe(input.max_capability_age_ms)?,
            mandatory_capabilities: input.mandatory_capabilities,
        })
    }

    pub const fn version(&self) -> &str {
        self.version
    }
    pub const fn resolved_content_digest(&self) -> Sha256Digest {
        self.resolved_content_digest
    }
    pub const fn active_content_digest(&self) -> Sha256Digest {
        self.active_content_digest
    }
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation.get()
    }
    pub const fn decision_policy_generation(&self) -> u64 {
        self.decision_policy_generation.get()
    }
    pub const fn decision_generation(&self) -> u64 {
        self.decision_generation.get()
    }
    pub const fn decision(&self) -> &PolicyDecisionV1 {
        &self.decision
    }
    pub const fn max_capability_age_ms(&self) -> u64 {
        self.max_capability_age_ms.get()
    }
    pub const fn mandatory_capabilities(&self) -> &[String] {
        self.mandatory_capabilities
    }
}

redacted_debug!(PolicyRecordV1<'_>, "PolicyRecordV1");

pub enum PolicyViewV1<'ctx> {
    Unavailable,
    Inconsistent,
    Unknown,
    IdentifierReused,
    Current(PolicyRecordV1<'ctx>),
}

impl fmt::Debug for PolicyViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Unknown => "Unknown",
            Self::IdentifierReused => "IdentifierReused",
            Self::Current(_) => "Current",
        };
        write!(formatter, "PolicyViewV1::{variant}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportStatusV1 {
    Supported,
    Unsupported,
}

pub struct CatalogueRecordInputV1<'ctx> {
    pub version: &'ctx str,
    pub resolved_content_digest: Sha256Digest,
    pub active_content_digest: Sha256Digest,
    pub catalogue_generation: u64,
    pub decision_catalogue_generation: u64,
    pub decision_generation: u64,
    pub decision: PlanDecisionEvidenceV1,
    pub schema_support: SupportStatusV1,
    pub intent_support: SupportStatusV1,
    pub mandatory_capabilities: &'ctx [String],
}

redacted_debug!(CatalogueRecordInputV1<'_>, "CatalogueRecordInputV1");

pub struct CatalogueRecordV1<'ctx> {
    version: &'ctx str,
    resolved_content_digest: Sha256Digest,
    active_content_digest: Sha256Digest,
    catalogue_generation: SafeU64,
    decision_catalogue_generation: SafeU64,
    decision_generation: SafeU64,
    decision: PlanDecisionEvidenceV1,
    schema_support: SupportStatusV1,
    intent_support: SupportStatusV1,
    mandatory_capabilities: &'ctx [String],
}

impl<'ctx> CatalogueRecordV1<'ctx> {
    pub fn try_new(input: CatalogueRecordInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.version)?;
        validate_capabilities(
            input.mandatory_capabilities,
            MAX_CATALOGUE_MANDATORY_CAPABILITIES,
        )?;
        Ok(Self {
            version: input.version,
            resolved_content_digest: input.resolved_content_digest,
            active_content_digest: input.active_content_digest,
            catalogue_generation: safe(input.catalogue_generation)?,
            decision_catalogue_generation: safe(input.decision_catalogue_generation)?,
            decision_generation: safe(input.decision_generation)?,
            decision: input.decision,
            schema_support: input.schema_support,
            intent_support: input.intent_support,
            mandatory_capabilities: input.mandatory_capabilities,
        })
    }

    pub const fn version(&self) -> &str {
        self.version
    }
    pub const fn resolved_content_digest(&self) -> Sha256Digest {
        self.resolved_content_digest
    }
    pub const fn active_content_digest(&self) -> Sha256Digest {
        self.active_content_digest
    }
    pub const fn catalogue_generation(&self) -> u64 {
        self.catalogue_generation.get()
    }
    pub const fn decision_catalogue_generation(&self) -> u64 {
        self.decision_catalogue_generation.get()
    }
    pub const fn decision_generation(&self) -> u64 {
        self.decision_generation.get()
    }
    pub const fn decision(&self) -> &PlanDecisionEvidenceV1 {
        &self.decision
    }
    pub const fn schema_support(&self) -> SupportStatusV1 {
        self.schema_support
    }
    pub const fn intent_support(&self) -> SupportStatusV1 {
        self.intent_support
    }
    pub const fn mandatory_capabilities(&self) -> &[String] {
        self.mandatory_capabilities
    }
}

redacted_debug!(CatalogueRecordV1<'_>, "CatalogueRecordV1");

pub enum CatalogueViewV1<'ctx> {
    Unavailable,
    Inconsistent,
    Unknown,
    IdentifierReused,
    Current(CatalogueRecordV1<'ctx>),
}

impl fmt::Debug for CatalogueViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Unknown => "Unknown",
            Self::IdentifierReused => "IdentifierReused",
            Self::Current(_) => "Current",
        };
        write!(formatter, "CatalogueViewV1::{variant}")
    }
}

pub struct CapabilityRecordInputV1<'ctx> {
    pub report_digest: Sha256Digest,
    pub observed_at_unix_ms: u64,
    pub boot_id: &'ctx str,
    pub instance_epoch: u64,
    pub report_generation: u64,
    pub report_host_driver_context_digest: Sha256Digest,
    pub current_host_driver_context_digest: Sha256Digest,
    pub available_capabilities: &'ctx [String],
}

redacted_debug!(CapabilityRecordInputV1<'_>, "CapabilityRecordInputV1");

pub struct CapabilityRecordV1<'ctx> {
    report_digest: Sha256Digest,
    observed_at_unix_ms: SafeU64,
    boot_id: &'ctx str,
    instance_epoch: SafeU64,
    report_generation: SafeU64,
    report_host_driver_context_digest: Sha256Digest,
    current_host_driver_context_digest: Sha256Digest,
    available_capabilities: &'ctx [String],
}

impl<'ctx> CapabilityRecordV1<'ctx> {
    pub fn try_new(input: CapabilityRecordInputV1<'ctx>) -> BuildResult<Self> {
        validate_identifier(input.boot_id)?;
        validate_capabilities(input.available_capabilities, MAX_AVAILABLE_CAPABILITIES)?;
        Ok(Self {
            report_digest: input.report_digest,
            observed_at_unix_ms: safe(input.observed_at_unix_ms)?,
            boot_id: input.boot_id,
            instance_epoch: safe(input.instance_epoch)?,
            report_generation: safe(input.report_generation)?,
            report_host_driver_context_digest: input.report_host_driver_context_digest,
            current_host_driver_context_digest: input.current_host_driver_context_digest,
            available_capabilities: input.available_capabilities,
        })
    }

    pub const fn report_digest(&self) -> Sha256Digest {
        self.report_digest
    }
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms.get()
    }
    pub const fn boot_id(&self) -> &str {
        self.boot_id
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }
    pub const fn report_generation(&self) -> u64 {
        self.report_generation.get()
    }
    pub const fn report_host_driver_context_digest(&self) -> Sha256Digest {
        self.report_host_driver_context_digest
    }
    pub const fn current_host_driver_context_digest(&self) -> Sha256Digest {
        self.current_host_driver_context_digest
    }
    pub const fn available_capabilities(&self) -> &[String] {
        self.available_capabilities
    }
}

redacted_debug!(CapabilityRecordV1<'_>, "CapabilityRecordV1");

pub enum CapabilityViewV1<'ctx> {
    Unavailable,
    Inconsistent,
    Unknown,
    Current(CapabilityRecordV1<'ctx>),
}

impl fmt::Debug for CapabilityViewV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Inconsistent => "Inconsistent",
            Self::Unknown => "Unknown",
            Self::Current(_) => "Current",
        };
        write!(formatter, "CapabilityViewV1::{variant}")
    }
}

/// Complete core-owned current-state snapshot input bound to one authentic plan.
///
/// Callers must obtain every field from sovereign providers under one coherent capture;
/// terminal provider states are represented explicitly rather than with dummy values.
pub struct ReadyEligibilityContextInputV1<'ctx> {
    pub bound_plan_id: Sha256Digest,
    pub capture_generation: u64,
    pub time: TimeViewV1<'ctx>,
    pub plan_deadline: PlanDeadlineViewV1<'ctx>,
    pub supervisor: SupervisorViewV1<'ctx>,
    pub signer: SignerTrustViewV1<'ctx>,
    pub workload: WorkloadIdentityViewV1<'ctx>,
    pub lease: LeaseResolutionV1<'ctx>,
    pub authorization: AuthorizationViewV1<'ctx>,
    pub policy: PolicyViewV1<'ctx>,
    pub catalogue: CatalogueViewV1<'ctx>,
    pub capabilities: CapabilityViewV1<'ctx>,
}

redacted_debug!(
    ReadyEligibilityContextInputV1<'_>,
    "ReadyEligibilityContextInputV1"
);

/// Checked, bounded and redacted current-state snapshot used by the evaluator.
pub struct ReadyEligibilityContextV1<'ctx> {
    bound_plan_id: Sha256Digest,
    capture_generation: SafeU64,
    time: TimeViewV1<'ctx>,
    plan_deadline: PlanDeadlineViewV1<'ctx>,
    supervisor: SupervisorViewV1<'ctx>,
    signer: SignerTrustViewV1<'ctx>,
    workload: WorkloadIdentityViewV1<'ctx>,
    lease: LeaseResolutionV1<'ctx>,
    authorization: AuthorizationViewV1<'ctx>,
    policy: PolicyViewV1<'ctx>,
    catalogue: CatalogueViewV1<'ctx>,
    capabilities: CapabilityViewV1<'ctx>,
}

impl<'ctx> ReadyEligibilityContextV1<'ctx> {
    pub fn try_new(input: ReadyEligibilityContextInputV1<'ctx>) -> BuildResult<Self> {
        Ok(Self {
            bound_plan_id: input.bound_plan_id,
            capture_generation: safe(input.capture_generation)?,
            time: input.time,
            plan_deadline: input.plan_deadline,
            supervisor: input.supervisor,
            signer: input.signer,
            workload: input.workload,
            lease: input.lease,
            authorization: input.authorization,
            policy: input.policy,
            catalogue: input.catalogue,
            capabilities: input.capabilities,
        })
    }

    pub const fn bound_plan_id(&self) -> Sha256Digest {
        self.bound_plan_id
    }
    pub const fn capture_generation(&self) -> u64 {
        self.capture_generation.get()
    }
    pub const fn time(&self) -> &TimeViewV1<'ctx> {
        &self.time
    }
    pub const fn plan_deadline(&self) -> &PlanDeadlineViewV1<'ctx> {
        &self.plan_deadline
    }
    pub const fn supervisor(&self) -> &SupervisorViewV1<'ctx> {
        &self.supervisor
    }
    pub const fn signer(&self) -> &SignerTrustViewV1<'ctx> {
        &self.signer
    }
    pub const fn workload(&self) -> &WorkloadIdentityViewV1<'ctx> {
        &self.workload
    }
    pub const fn lease(&self) -> &LeaseResolutionV1<'ctx> {
        &self.lease
    }
    pub const fn authorization(&self) -> &AuthorizationViewV1<'ctx> {
        &self.authorization
    }
    pub const fn policy(&self) -> &PolicyViewV1<'ctx> {
        &self.policy
    }
    pub const fn catalogue(&self) -> &CatalogueViewV1<'ctx> {
        &self.catalogue
    }
    pub const fn capabilities(&self) -> &CapabilityViewV1<'ctx> {
        &self.capabilities
    }
}

redacted_debug!(ReadyEligibilityContextV1<'_>, "ReadyEligibilityContextV1");

/// Terminal context acquisition result or one complete frozen snapshot.
///
/// `Unavailable`, `Incomplete`, and `Torn` fail closed before replay state is touched.
// Ready owns one frozen snapshot; its size is bounded and avoids indirection in the hot path.
#[allow(clippy::large_enum_variant)]
pub enum EligibilityContextV1<'ctx> {
    Unavailable,
    Incomplete,
    Torn,
    Ready(ReadyEligibilityContextV1<'ctx>),
}

impl fmt::Debug for EligibilityContextV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Unavailable => "Unavailable",
            Self::Incomplete => "Incomplete",
            Self::Torn => "Torn",
            Self::Ready(_) => "Ready",
        };
        write!(formatter, "EligibilityContextV1::{variant}")
    }
}

pub(crate) fn safe(value: u64) -> BuildResult<SafeU64> {
    SafeU64::new(value).map_err(|_| EligibilityContextBuildErrorV1::IntegerOutOfRange)
}

fn validate_interval(not_before: u64, expires_at: u64) -> BuildResult<()> {
    safe(not_before)?;
    safe(expires_at)?;
    if not_before >= expires_at {
        return Err(EligibilityContextBuildErrorV1::InvalidInterval);
    }
    Ok(())
}

pub(crate) fn validate_identifier(value: &str) -> BuildResult<()> {
    if value.is_empty() || value.len() > MAX_ELIGIBILITY_IDENTIFIER_BYTES {
        return Err(EligibilityContextBuildErrorV1::InvalidIdentifier);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(EligibilityContextBuildErrorV1::InvalidIdentifier);
    }
    Ok(())
}

fn validate_capabilities(values: &[String], maximum: usize) -> BuildResult<()> {
    if values.len() > maximum {
        return Err(EligibilityContextBuildErrorV1::LimitExceeded);
    }
    for value in values {
        validate_identifier(value)?;
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(EligibilityContextBuildErrorV1::InvalidCapabilitySet);
    }
    Ok(())
}
