//! Canonical signed TaskLease v1 contract and verifier boundary.

use crate::canonical::{decode_canonical_value, require_closed_object, to_jcs_vec};
use crate::crypto::{
    decode_signature, encode_signature, signature_message, verify_task_lease_signature,
    TaskLeaseKeyResolver, TaskLeaseSigner, VerificationKeyStatusV1,
};
use crate::validation::{require_at_most, require_lease_time_bounds};
use crate::{
    AuthenticHumanRequestGrantV1, ContractError, CurrencyCodeV1, DelegationDepthV1,
    DelegationModeV1, Generation, Identifier, LeaseSourceKindV1, MinimumAuthenticationProfileV1,
    ResourceRootV1, Result, RiskLevelV1, SafeU64, Sha256Digest, TaskIntentionV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::fmt;

const TASK_LEASE_SIGNATURE_DOMAIN_V1: &[u8] = b"HELIXOS\0TASK-LEASE\0V1\0";
const MAX_TASK_LEASE_WIRE_BYTES_V1: usize = 1_048_576;

const OUTER_FIELDS_V1: &[&str] = &["protected", "lease_digest", "signature"];
const PROTECTED_FIELDS_V1: &[&str] = &[
    "schema",
    "digest_algorithm",
    "signature_algorithm",
    "key_purpose",
    "key_id",
    "lease_id",
    "issuer_id",
    "task_id",
    "workload_id",
    "audience",
    "source_kind",
    "source_grant_id",
    "source_grant_digest",
    "source_principal_id",
    "allowed_intentions",
    "resource_roots",
    "budget",
    "counter_limits",
    "trust_bound",
    "catalogue_bound",
    "delegation_mode",
    "parent_lease_id",
    "parent_lease_digest",
    "parent_allocation_id",
    "delegation_depth",
    "clock_generation",
    "boot_id",
    "instance_epoch",
    "issued_at_utc_ms",
    "not_before_utc_ms",
    "expires_at_utc_ms",
    "issued_at_monotonic_ms",
    "deadline_monotonic_ms",
];
const RESOURCE_ROOT_FIELDS_V1: &[&str] = &["root_id", "components"];
const BUDGET_FIELDS_V1: &[&str] = &[
    "read_bytes_limit",
    "distinct_files_limit",
    "action_limit",
    "egress_bytes_limit",
    "currency_code",
    "max_cost_micro_units",
    "price_table_id",
];
const COUNTER_FIELDS_V1: &[&str] = &[
    "plan_limit",
    "approval_limit",
    "child_lease_limit",
    "max_delegation_depth",
];
const TRUST_FIELDS_V1: &[&str] = &[
    "maximum_risk_level",
    "minimum_authentication_profile",
    "policy_id",
    "policy_content_digest",
    "policy_generation",
];
const CATALOGUE_FIELDS_V1: &[&str] = &[
    "catalogue_id",
    "catalogue_content_digest",
    "catalogue_generation",
    "allowed_catalogue_entries",
];

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLeaseBudgetV1 {
    read_bytes_limit: SafeU64,
    distinct_files_limit: SafeU64,
    action_limit: SafeU64,
    egress_bytes_limit: SafeU64,
    currency_code: CurrencyCodeV1,
    max_cost_micro_units: SafeU64,
    price_table_id: Identifier,
}

impl TaskLeaseBudgetV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn from_validated_parts_v1(
        read_bytes_limit: SafeU64,
        distinct_files_limit: SafeU64,
        action_limit: SafeU64,
        egress_bytes_limit: SafeU64,
        currency_code: CurrencyCodeV1,
        max_cost_micro_units: SafeU64,
        price_table_id: Identifier,
    ) -> Self {
        Self {
            read_bytes_limit,
            distinct_files_limit,
            action_limit,
            egress_bytes_limit,
            currency_code,
            max_cost_micro_units,
            price_table_id,
        }
    }

    pub const fn read_bytes_limit_v1(&self) -> SafeU64 {
        self.read_bytes_limit
    }

    pub const fn distinct_files_limit_v1(&self) -> SafeU64 {
        self.distinct_files_limit
    }

    pub const fn action_limit_v1(&self) -> SafeU64 {
        self.action_limit
    }

    pub const fn egress_bytes_limit_v1(&self) -> SafeU64 {
        self.egress_bytes_limit
    }

    pub fn currency_code_v1(&self) -> &str {
        self.currency_code.as_str()
    }

    pub const fn max_cost_micro_units_v1(&self) -> SafeU64 {
        self.max_cost_micro_units
    }

    pub fn price_table_id_v1(&self) -> &str {
        self.price_table_id.as_str()
    }
}

impl fmt::Debug for TaskLeaseBudgetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLeaseBudgetV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLeaseCounterLimitsV1 {
    plan_limit: SafeU64,
    approval_limit: SafeU64,
    child_lease_limit: SafeU64,
    max_delegation_depth: DelegationDepthV1,
}

impl TaskLeaseCounterLimitsV1 {
    pub const fn from_validated_parts_v1(
        plan_limit: SafeU64,
        approval_limit: SafeU64,
        child_lease_limit: SafeU64,
        max_delegation_depth: DelegationDepthV1,
    ) -> Self {
        Self {
            plan_limit,
            approval_limit,
            child_lease_limit,
            max_delegation_depth,
        }
    }

    pub const fn plan_limit_v1(&self) -> SafeU64 {
        self.plan_limit
    }

    pub const fn approval_limit_v1(&self) -> SafeU64 {
        self.approval_limit
    }

    pub const fn child_lease_limit_v1(&self) -> SafeU64 {
        self.child_lease_limit
    }

    pub const fn max_delegation_depth_v1(&self) -> DelegationDepthV1 {
        self.max_delegation_depth
    }
}

impl fmt::Debug for TaskLeaseCounterLimitsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLeaseCounterLimitsV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLeaseTrustBoundV1 {
    maximum_risk_level: RiskLevelV1,
    minimum_authentication_profile: MinimumAuthenticationProfileV1,
    policy_id: Identifier,
    policy_content_digest: Sha256Digest,
    policy_generation: Generation,
}

impl TaskLeaseTrustBoundV1 {
    pub const fn from_validated_parts_v1(
        maximum_risk_level: RiskLevelV1,
        minimum_authentication_profile: MinimumAuthenticationProfileV1,
        policy_id: Identifier,
        policy_content_digest: Sha256Digest,
        policy_generation: Generation,
    ) -> Self {
        Self {
            maximum_risk_level,
            minimum_authentication_profile,
            policy_id,
            policy_content_digest,
            policy_generation,
        }
    }

    pub const fn maximum_risk_level_v1(&self) -> RiskLevelV1 {
        self.maximum_risk_level
    }

    pub const fn minimum_authentication_profile_v1(&self) -> MinimumAuthenticationProfileV1 {
        self.minimum_authentication_profile
    }

    pub fn policy_id_v1(&self) -> &str {
        self.policy_id.as_str()
    }

    pub const fn policy_content_digest_v1(&self) -> Sha256Digest {
        self.policy_content_digest
    }

    pub const fn policy_generation_v1(&self) -> Generation {
        self.policy_generation
    }
}

impl fmt::Debug for TaskLeaseTrustBoundV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLeaseTrustBoundV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLeaseCatalogueBoundV1 {
    catalogue_id: Identifier,
    catalogue_content_digest: Sha256Digest,
    catalogue_generation: Generation,
    allowed_catalogue_entries: Vec<Identifier>,
}

impl TaskLeaseCatalogueBoundV1 {
    pub fn try_new_v1(
        catalogue_id: Identifier,
        catalogue_content_digest: Sha256Digest,
        catalogue_generation: Generation,
        allowed_catalogue_entries: Vec<Identifier>,
    ) -> Result<Self> {
        crate::validation::require_sorted_unique_identifiers(&allowed_catalogue_entries, 1, 256)?;
        Ok(Self {
            catalogue_id,
            catalogue_content_digest,
            catalogue_generation,
            allowed_catalogue_entries,
        })
    }

    fn validate_v1(&self) -> Result<()> {
        crate::validation::require_sorted_unique_identifiers(
            &self.allowed_catalogue_entries,
            1,
            256,
        )
    }

    pub fn catalogue_id_v1(&self) -> &str {
        self.catalogue_id.as_str()
    }

    pub const fn catalogue_content_digest_v1(&self) -> Sha256Digest {
        self.catalogue_content_digest
    }

    pub const fn catalogue_generation_v1(&self) -> Generation {
        self.catalogue_generation
    }

    pub fn allowed_catalogue_entries_v1(&self) -> &[Identifier] {
        &self.allowed_catalogue_entries
    }
}

impl fmt::Debug for TaskLeaseCatalogueBoundV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLeaseCatalogueBoundV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RootTaskLeaseBoundsV1 {
    resource_roots: Vec<ResourceRootV1>,
    budget: TaskLeaseBudgetV1,
    counter_limits: TaskLeaseCounterLimitsV1,
    trust_bound: TaskLeaseTrustBoundV1,
    catalogue_bound: TaskLeaseCatalogueBoundV1,
    delegation_mode: DelegationModeV1,
}

impl RootTaskLeaseBoundsV1 {
    pub fn try_new_v1(
        resource_roots: Vec<ResourceRootV1>,
        budget: TaskLeaseBudgetV1,
        counter_limits: TaskLeaseCounterLimitsV1,
        trust_bound: TaskLeaseTrustBoundV1,
        catalogue_bound: TaskLeaseCatalogueBoundV1,
        delegation_mode: DelegationModeV1,
    ) -> Result<Self> {
        validate_resource_roots_v1(&resource_roots)?;
        catalogue_bound.validate_v1()?;
        Ok(Self {
            resource_roots,
            budget,
            counter_limits,
            trust_bound,
            catalogue_bound,
            delegation_mode,
        })
    }

    pub fn resource_roots_v1(&self) -> &[ResourceRootV1] {
        &self.resource_roots
    }

    pub const fn budget_v1(&self) -> &TaskLeaseBudgetV1 {
        &self.budget
    }

    pub const fn counter_limits_v1(&self) -> &TaskLeaseCounterLimitsV1 {
        &self.counter_limits
    }

    pub const fn trust_bound_v1(&self) -> &TaskLeaseTrustBoundV1 {
        &self.trust_bound
    }

    pub const fn catalogue_bound_v1(&self) -> &TaskLeaseCatalogueBoundV1 {
        &self.catalogue_bound
    }

    pub const fn delegation_mode_v1(&self) -> DelegationModeV1 {
        self.delegation_mode
    }

    /// Stable canonical binding used by the root-issuance idempotency preimage.
    pub fn canonical_digest_v1(&self) -> Result<Sha256Digest> {
        Ok(Sha256Digest::digest(&to_jcs_vec(self)?))
    }
}

impl fmt::Debug for RootTaskLeaseBoundsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootTaskLeaseBoundsV1")
            .finish_non_exhaustive()
    }
}

/// Core-owned, non-wire input for one root lease candidate.
pub struct RootTaskLeaseInputV1 {
    pub lease_id: Sha256Digest,
    pub issuer_id: Identifier,
    pub task_id: Identifier,
    pub workload_id: Identifier,
    pub audience: Identifier,
    pub bounds: RootTaskLeaseBoundsV1,
    pub clock_generation: Generation,
    pub boot_id: Identifier,
    pub instance_epoch: SafeU64,
    pub issued_at_utc_ms: SafeU64,
    pub not_before_utc_ms: SafeU64,
    pub expires_at_utc_ms: SafeU64,
    pub issued_at_monotonic_ms: SafeU64,
    pub deadline_monotonic_ms: SafeU64,
}

impl fmt::Debug for RootTaskLeaseInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootTaskLeaseInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskLeaseProtectedV1 {
    schema: String,
    digest_algorithm: String,
    signature_algorithm: String,
    key_purpose: String,
    key_id: Identifier,
    lease_id: Sha256Digest,
    issuer_id: Identifier,
    task_id: Identifier,
    workload_id: Identifier,
    audience: Identifier,
    source_kind: LeaseSourceKindV1,
    source_grant_id: Sha256Digest,
    source_grant_digest: Sha256Digest,
    source_principal_id: Identifier,
    allowed_intentions: Vec<TaskIntentionV1>,
    resource_roots: Vec<ResourceRootV1>,
    budget: TaskLeaseBudgetV1,
    counter_limits: TaskLeaseCounterLimitsV1,
    trust_bound: TaskLeaseTrustBoundV1,
    catalogue_bound: TaskLeaseCatalogueBoundV1,
    delegation_mode: DelegationModeV1,
    parent_lease_id: Option<Sha256Digest>,
    parent_lease_digest: Option<Sha256Digest>,
    parent_allocation_id: Option<Sha256Digest>,
    delegation_depth: DelegationDepthV1,
    clock_generation: Generation,
    boot_id: Identifier,
    instance_epoch: SafeU64,
    issued_at_utc_ms: SafeU64,
    not_before_utc_ms: SafeU64,
    expires_at_utc_ms: SafeU64,
    issued_at_monotonic_ms: SafeU64,
    deadline_monotonic_ms: SafeU64,
}

impl fmt::Debug for TaskLeaseProtectedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLeaseProtectedV1")
            .finish_non_exhaustive()
    }
}

impl TaskLeaseProtectedV1 {
    pub fn try_new_root_v1(
        input: RootTaskLeaseInputV1,
        source_grant: &AuthenticHumanRequestGrantV1,
        key_id: Identifier,
    ) -> Result<Self> {
        let grant = source_grant.claims();
        require_at_most(
            input.expires_at_utc_ms,
            SafeU64::new(grant.expires_at_utc_ms())?,
        )?;
        let value = Self {
            schema: "helixos.task-lease/1".to_owned(),
            digest_algorithm: "sha-256".to_owned(),
            signature_algorithm: "ed25519".to_owned(),
            key_purpose: "core-task-lease-signing".to_owned(),
            key_id,
            lease_id: input.lease_id,
            issuer_id: input.issuer_id,
            task_id: input.task_id,
            workload_id: input.workload_id,
            audience: input.audience,
            source_kind: LeaseSourceKindV1::HumanRequestGrant,
            source_grant_id: grant.grant_id(),
            source_grant_digest: grant.grant_digest(),
            source_principal_id: Identifier::new(grant.principal_id())?,
            allowed_intentions: vec![TaskIntentionV1::HostFilePatch],
            resource_roots: input.bounds.resource_roots,
            budget: input.bounds.budget,
            counter_limits: input.bounds.counter_limits,
            trust_bound: input.bounds.trust_bound,
            catalogue_bound: input.bounds.catalogue_bound,
            delegation_mode: input.bounds.delegation_mode,
            parent_lease_id: None,
            parent_lease_digest: None,
            parent_allocation_id: None,
            delegation_depth: DelegationDepthV1::new(0)?,
            clock_generation: input.clock_generation,
            boot_id: input.boot_id,
            instance_epoch: input.instance_epoch,
            issued_at_utc_ms: input.issued_at_utc_ms,
            not_before_utc_ms: input.not_before_utc_ms,
            expires_at_utc_ms: input.expires_at_utc_ms,
            issued_at_monotonic_ms: input.issued_at_monotonic_ms,
            deadline_monotonic_ms: input.deadline_monotonic_ms,
        };
        value.validate_v1()?;
        Ok(value)
    }

    fn validate_v1(&self) -> Result<()> {
        if self.schema != "helixos.task-lease/1" {
            return Err(ContractError::UnsupportedSchema);
        }
        if self.digest_algorithm != "sha-256" {
            return Err(ContractError::UnsupportedDigestAlgorithm);
        }
        if self.signature_algorithm != "ed25519" {
            return Err(ContractError::UnsupportedSignatureAlgorithm);
        }
        if self.key_purpose != "core-task-lease-signing" {
            return Err(ContractError::WrongKeyPurpose);
        }
        if self.source_kind != LeaseSourceKindV1::HumanRequestGrant
            || self.allowed_intentions != [TaskIntentionV1::HostFilePatch]
        {
            return Err(ContractError::InvalidField);
        }
        validate_resource_roots_v1(&self.resource_roots)?;
        self.catalogue_bound.validate_v1()?;
        require_lease_time_bounds(
            self.issued_at_utc_ms,
            self.not_before_utc_ms,
            self.expires_at_utc_ms,
            self.issued_at_monotonic_ms,
            self.deadline_monotonic_ms,
        )?;
        let parents = [
            self.parent_lease_id.is_some(),
            self.parent_lease_digest.is_some(),
            self.parent_allocation_id.is_some(),
        ];
        if parents.iter().all(|present| !present) {
            if self.delegation_depth.get() != 0 {
                return Err(ContractError::InvalidField);
            }
        } else {
            if !parents.iter().all(|present| *present)
                || self.delegation_depth.get() == 0
                || self.delegation_depth.get() > self.counter_limits.max_delegation_depth.get()
            {
                return Err(ContractError::InvalidField);
            }
        }
        Ok(())
    }

    pub fn key_id_v1(&self) -> &str {
        self.key_id.as_str()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTaskLeaseV1 {
    protected: TaskLeaseProtectedV1,
    lease_digest: Sha256Digest,
    signature: String,
}

impl fmt::Debug for SignedTaskLeaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedTaskLeaseV1")
            .finish_non_exhaustive()
    }
}

impl SignedTaskLeaseV1 {
    pub fn protected(&self) -> &TaskLeaseProtectedV1 {
        &self.protected
    }

    pub const fn lease_digest(&self) -> Sha256Digest {
        self.lease_digest
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.protected.validate_v1()?;
        to_jcs_vec(self)
    }
}

pub struct AuthenticTaskLeaseV1 {
    signed: SignedTaskLeaseV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

impl fmt::Debug for AuthenticTaskLeaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticTaskLeaseV1")
            .finish_non_exhaustive()
    }
}

impl AuthenticTaskLeaseV1 {
    pub fn protected(&self) -> &TaskLeaseProtectedV1 {
        &self.signed.protected
    }

    pub fn claims(&self) -> TaskLeaseClaimsV1<'_> {
        TaskLeaseClaimsV1 { lease: self }
    }

    pub const fn lease_digest(&self) -> Sha256Digest {
        self.signed.lease_digest
    }

    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.verified_key_fingerprint
    }

    pub const fn verification_key_status(&self) -> VerificationKeyStatusV1 {
        self.verification_key_status
    }

    pub fn canonical_signed_envelope_bytes(&self) -> Result<Vec<u8>> {
        self.signed.to_canonical_json()
    }
}

#[derive(Clone, Copy)]
pub struct TaskLeaseClaimsV1<'lease> {
    lease: &'lease AuthenticTaskLeaseV1,
}

impl fmt::Debug for TaskLeaseClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLeaseClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'lease> TaskLeaseClaimsV1<'lease> {
    fn protected(&self) -> &'lease TaskLeaseProtectedV1 {
        &self.lease.signed.protected
    }

    pub const fn schema(&self) -> &'static str {
        "helixos.task-lease/1"
    }
    pub const fn digest_algorithm(&self) -> &'static str {
        "sha-256"
    }
    pub const fn signature_algorithm(&self) -> &'static str {
        "ed25519"
    }
    pub const fn key_purpose(&self) -> &'static str {
        "core-task-lease-signing"
    }
    pub fn key_id(&self) -> &'lease str {
        self.protected().key_id.as_str()
    }
    pub const fn lease_id(&self) -> Sha256Digest {
        self.lease.signed.protected.lease_id
    }
    pub const fn lease_digest(&self) -> Sha256Digest {
        self.lease.signed.lease_digest
    }
    pub fn issuer_id(&self) -> &'lease str {
        self.protected().issuer_id.as_str()
    }
    pub fn task_id(&self) -> &'lease str {
        self.protected().task_id.as_str()
    }
    pub fn workload_id(&self) -> &'lease str {
        self.protected().workload_id.as_str()
    }
    pub fn audience(&self) -> &'lease str {
        self.protected().audience.as_str()
    }
    pub const fn source_kind(&self) -> LeaseSourceKindV1 {
        self.lease.signed.protected.source_kind
    }
    pub const fn source_grant_id(&self) -> Sha256Digest {
        self.lease.signed.protected.source_grant_id
    }
    pub const fn source_grant_digest(&self) -> Sha256Digest {
        self.lease.signed.protected.source_grant_digest
    }
    pub fn source_principal_id(&self) -> &'lease str {
        self.protected().source_principal_id.as_str()
    }
    pub fn allowed_intentions(&self) -> &'lease [TaskIntentionV1] {
        &self.protected().allowed_intentions
    }
    pub fn resource_roots(&self) -> &'lease [ResourceRootV1] {
        &self.protected().resource_roots
    }
    pub fn budget(&self) -> &'lease TaskLeaseBudgetV1 {
        &self.protected().budget
    }
    pub fn counter_limits(&self) -> &'lease TaskLeaseCounterLimitsV1 {
        &self.protected().counter_limits
    }
    pub fn trust_bound(&self) -> &'lease TaskLeaseTrustBoundV1 {
        &self.protected().trust_bound
    }
    pub fn catalogue_bound(&self) -> &'lease TaskLeaseCatalogueBoundV1 {
        &self.protected().catalogue_bound
    }
    pub const fn delegation_mode(&self) -> DelegationModeV1 {
        self.lease.signed.protected.delegation_mode
    }
    pub const fn parent_lease_id(&self) -> Option<Sha256Digest> {
        self.lease.signed.protected.parent_lease_id
    }
    pub const fn parent_lease_digest(&self) -> Option<Sha256Digest> {
        self.lease.signed.protected.parent_lease_digest
    }
    pub const fn parent_allocation_id(&self) -> Option<Sha256Digest> {
        self.lease.signed.protected.parent_allocation_id
    }
    pub const fn delegation_depth(&self) -> u8 {
        self.lease.signed.protected.delegation_depth.get()
    }
    pub const fn clock_generation(&self) -> u64 {
        self.lease.signed.protected.clock_generation.get()
    }
    pub fn boot_id(&self) -> &'lease str {
        self.protected().boot_id.as_str()
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.lease.signed.protected.instance_epoch.get()
    }
    pub const fn issued_at_utc_ms(&self) -> u64 {
        self.lease.signed.protected.issued_at_utc_ms.get()
    }
    pub const fn not_before_utc_ms(&self) -> u64 {
        self.lease.signed.protected.not_before_utc_ms.get()
    }
    pub const fn expires_at_utc_ms(&self) -> u64 {
        self.lease.signed.protected.expires_at_utc_ms.get()
    }
    pub const fn issued_at_monotonic_ms(&self) -> u64 {
        self.lease.signed.protected.issued_at_monotonic_ms.get()
    }
    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.lease.signed.protected.deadline_monotonic_ms.get()
    }
}

pub struct RetainedTaskLeaseEvidenceV1 {
    signed: SignedTaskLeaseV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

impl fmt::Debug for RetainedTaskLeaseEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedTaskLeaseEvidenceV1")
            .finish_non_exhaustive()
    }
}

impl RetainedTaskLeaseEvidenceV1 {
    pub fn claims(&self) -> RetainedTaskLeaseClaimsV1<'_> {
        RetainedTaskLeaseClaimsV1 { evidence: self }
    }

    pub const fn lease_digest(&self) -> Sha256Digest {
        self.signed.lease_digest
    }
    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.verified_key_fingerprint
    }
    pub const fn verification_key_status(&self) -> VerificationKeyStatusV1 {
        self.verification_key_status
    }
    pub fn canonical_signed_envelope_bytes(&self) -> Result<Vec<u8>> {
        self.signed.to_canonical_json()
    }
}

#[derive(Clone, Copy)]
pub struct RetainedTaskLeaseClaimsV1<'evidence> {
    evidence: &'evidence RetainedTaskLeaseEvidenceV1,
}

impl fmt::Debug for RetainedTaskLeaseClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedTaskLeaseClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'evidence> RetainedTaskLeaseClaimsV1<'evidence> {
    fn protected(&self) -> &'evidence TaskLeaseProtectedV1 {
        &self.evidence.signed.protected
    }
    pub const fn lease_id(&self) -> Sha256Digest {
        self.evidence.signed.protected.lease_id
    }
    pub const fn lease_digest(&self) -> Sha256Digest {
        self.evidence.signed.lease_digest
    }
    pub const fn source_grant_id(&self) -> Sha256Digest {
        self.evidence.signed.protected.source_grant_id
    }
    pub const fn source_grant_digest(&self) -> Sha256Digest {
        self.evidence.signed.protected.source_grant_digest
    }
    pub fn task_id(&self) -> &'evidence str {
        self.protected().task_id.as_str()
    }
    pub fn workload_id(&self) -> &'evidence str {
        self.protected().workload_id.as_str()
    }
    pub const fn expires_at_utc_ms(&self) -> u64 {
        self.evidence.signed.protected.expires_at_utc_ms.get()
    }
    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.evidence.signed.protected.deadline_monotonic_ms.get()
    }
}

pub fn sign_task_lease_v1<S: TaskLeaseSigner>(
    protected: TaskLeaseProtectedV1,
    signer: &S,
) -> Result<SignedTaskLeaseV1> {
    protected.validate_v1()?;
    if protected.key_id_v1() != signer.key_id() {
        return Err(ContractError::WrongKeyPurpose);
    }
    let protected_bytes = to_jcs_vec(&protected)?;
    let lease_digest = Sha256Digest::digest(&protected_bytes);
    let signature = signer
        .sign_task_lease(&signature_message(
            TASK_LEASE_SIGNATURE_DOMAIN_V1,
            &protected_bytes,
        ))
        .map_err(|_| ContractError::SigningFailed)?;
    Ok(SignedTaskLeaseV1 {
        protected,
        lease_digest,
        signature: encode_signature(signature),
    })
}

pub fn decode_and_verify_task_lease_v1<R: TaskLeaseKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<AuthenticTaskLeaseV1> {
    let verified = decode_verified_task_lease_v1(wire, resolver)?;
    if verified.verification_key_status != VerificationKeyStatusV1::Current {
        return Err(ContractError::HistoricalKeyNotAuthority);
    }
    Ok(AuthenticTaskLeaseV1 {
        signed: verified.signed,
        verified_key_fingerprint: verified.verified_key_fingerprint,
        verification_key_status: verified.verification_key_status,
    })
}

pub fn decode_and_verify_retained_task_lease_v1<R: TaskLeaseKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<RetainedTaskLeaseEvidenceV1> {
    let verified = decode_verified_task_lease_v1(wire, resolver)?;
    Ok(RetainedTaskLeaseEvidenceV1 {
        signed: verified.signed,
        verified_key_fingerprint: verified.verified_key_fingerprint,
        verification_key_status: verified.verification_key_status,
    })
}

struct VerifiedTaskLeaseV1 {
    signed: SignedTaskLeaseV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

fn decode_verified_task_lease_v1<R: TaskLeaseKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<VerifiedTaskLeaseV1> {
    let value = decode_canonical_value(wire, MAX_TASK_LEASE_WIRE_BYTES_V1)?;
    preflight_task_lease_v1(&value)?;
    let signed: SignedTaskLeaseV1 =
        serde_json::from_value(value).map_err(|_| ContractError::InvalidField)?;
    signed.protected.validate_v1()?;
    let protected_bytes = to_jcs_vec(&signed.protected)?;
    if Sha256Digest::digest(&protected_bytes) != signed.lease_digest {
        return Err(ContractError::DigestMismatch);
    }
    let signature = decode_signature(&signed.signature)?;
    let key = resolver.resolve_task_lease_key(signed.protected.key_id_v1())?;
    let evidence = verify_task_lease_signature(
        signature,
        &signature_message(TASK_LEASE_SIGNATURE_DOMAIN_V1, &protected_bytes),
        key,
    )?;
    Ok(VerifiedTaskLeaseV1 {
        signed,
        verified_key_fingerprint: evidence.fingerprint(),
        verification_key_status: evidence.status(),
    })
}

fn preflight_task_lease_v1(value: &Value) -> Result<()> {
    require_closed_object(value, OUTER_FIELDS_V1, true)?;
    let protected = value
        .get("protected")
        .ok_or(ContractError::MissingOuterField)?;
    require_closed_object(protected, PROTECTED_FIELDS_V1, false)?;
    preflight_exact_string_v1(
        protected,
        "schema",
        "helixos.task-lease/1",
        ContractError::UnsupportedSchema,
    )?;
    preflight_exact_string_v1(
        protected,
        "digest_algorithm",
        "sha-256",
        ContractError::UnsupportedDigestAlgorithm,
    )?;
    preflight_exact_string_v1(
        protected,
        "signature_algorithm",
        "ed25519",
        ContractError::UnsupportedSignatureAlgorithm,
    )?;
    preflight_exact_string_v1(
        protected,
        "key_purpose",
        "core-task-lease-signing",
        ContractError::WrongKeyPurpose,
    )?;
    for (name, fields) in [
        ("budget", BUDGET_FIELDS_V1),
        ("counter_limits", COUNTER_FIELDS_V1),
        ("trust_bound", TRUST_FIELDS_V1),
        ("catalogue_bound", CATALOGUE_FIELDS_V1),
    ] {
        require_closed_object(
            protected
                .get(name)
                .ok_or(ContractError::MissingRequiredField)?,
            fields,
            false,
        )?;
    }
    let roots = protected
        .get("resource_roots")
        .and_then(Value::as_array)
        .ok_or(ContractError::InvalidField)?;
    for root in roots {
        require_closed_object(root, RESOURCE_ROOT_FIELDS_V1, false)?;
    }
    Ok(())
}

fn preflight_exact_string_v1(
    protected: &Value,
    field: &str,
    expected: &str,
    mismatch: ContractError,
) -> Result<()> {
    match protected.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(mismatch),
        None => Err(ContractError::InvalidField),
    }
}

fn validate_resource_roots_v1(roots: &[ResourceRootV1]) -> Result<()> {
    if roots.is_empty() || roots.len() > 128 {
        return Err(ContractError::InvalidField);
    }
    for root in roots {
        root.validate()?;
    }
    if roots
        .windows(2)
        .any(|pair| compare_resource_roots_v1(&pair[0], &pair[1]) != Ordering::Less)
    {
        return Err(ContractError::InvalidField);
    }
    Ok(())
}

fn compare_resource_roots_v1(left: &ResourceRootV1, right: &ResourceRootV1) -> Ordering {
    left.root_id()
        .as_bytes()
        .cmp(right.root_id().as_bytes())
        .then_with(|| left.components().cmp(right.components()))
}
