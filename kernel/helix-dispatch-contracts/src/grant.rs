use crate::canonical::{decode_canonical_value, require_closed_object, to_jcs_vec};
use crate::crypto::{
    decode_signature, encode_signature, signature_message, verify_grant_signature,
    GrantKeyResolver, GrantSigner, VerificationKeyStatusV1,
};
use crate::validation::{valid_media_type, Generation, Identifier, ResourceRefV1, SafeU64};
use crate::{ContractError, Result, Sha256Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

const GRANT_SIGNATURE_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-GRANT\0V1\0";
const MAX_GRANT_WIRE_BYTES: usize = 1_048_576;
const MAX_GRANT_LIFETIME_MS: u64 = 5_000;

const OUTER_FIELDS: &[&str] = &["protected", "grant_digest", "signature"];
const PROTECTED_FIELDS: &[&str] = &[
    "schema",
    "digest_algorithm",
    "signature_algorithm",
    "key_purpose",
    "key_id",
    "grant_id",
    "dispatch_attempt_id",
    "one_shot_nonce",
    "operation_id",
    "operation_state_generation",
    "preparation_attempt_id",
    "preparation_transition_generation",
    "plan_id",
    "task_id",
    "workload_id",
    "intent",
    "target",
    "precondition_digest",
    "content_digest",
    "content_byte_length",
    "content_media_type",
    "trust_generation",
    "verified_key_fingerprint",
    "workload_generation",
    "workload_evidence_digest",
    "lease_generation",
    "lease_digest",
    "lease_decision_digest",
    "authorization_generation",
    "authorization_evidence_digest",
    "policy_generation",
    "policy_decision_generation",
    "policy_content_digest",
    "policy_decision_digest",
    "catalogue_generation",
    "catalogue_decision_generation",
    "catalogue_content_digest",
    "catalogue_decision_digest",
    "capability_report_generation",
    "capability_report_digest",
    "host_driver_context_digest",
    "capability_observed_at_utc_ms",
    "capability_max_age_ms",
    "adapter_capability_digest",
    "replay_claim_id",
    "replay_claimant_generation",
    "replay_binding_digest",
    "budget_scope_id",
    "budget_scope_generation",
    "budget_scope_binding_digest",
    "reservation_id",
    "reservation_generation",
    "reservation_binding_digest",
    "reservation_vector_digest",
    "recovery_reference_digest",
    "recovery_mode",
    "recovery_profile_digest",
    "recovery_binding_digest",
    "recovery_receipt_digest",
    "destination_adapter_id",
    "protocol_version",
    "boot_id",
    "instance_epoch",
    "supervisor_epoch",
    "supervisor_generation",
    "clock_generation",
    "issued_at_utc_ms",
    "issued_at_monotonic_ms",
    "deadline_monotonic_ms",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryModeV1 {
    Compensation,
    Irreversible,
}

/// Coordinator-owned, typed input for constructing one protected grant.
///
/// This value is deliberately not serializable and carries no signing authority.
pub struct ExecutionGrantInputV1 {
    pub grant_id: Sha256Digest,
    pub dispatch_attempt_id: Sha256Digest,
    pub one_shot_nonce: Sha256Digest,
    pub operation_id: Identifier,
    pub operation_state_generation: Generation,
    pub preparation_attempt_id: Sha256Digest,
    pub preparation_transition_generation: Generation,
    pub plan_id: Sha256Digest,
    pub task_id: Identifier,
    pub workload_id: Identifier,
    pub target: ResourceRefV1,
    pub precondition_digest: Sha256Digest,
    pub content_digest: Sha256Digest,
    pub content_byte_length: SafeU64,
    pub content_media_type: String,
    pub trust_generation: Generation,
    pub verified_key_fingerprint: Sha256Digest,
    pub workload_generation: Generation,
    pub workload_evidence_digest: Sha256Digest,
    pub lease_generation: Generation,
    pub lease_digest: Sha256Digest,
    pub lease_decision_digest: Sha256Digest,
    pub authorization_generation: Generation,
    pub authorization_evidence_digest: Sha256Digest,
    pub policy_generation: Generation,
    pub policy_decision_generation: Generation,
    pub policy_content_digest: Sha256Digest,
    pub policy_decision_digest: Sha256Digest,
    pub catalogue_generation: Generation,
    pub catalogue_decision_generation: Generation,
    pub catalogue_content_digest: Sha256Digest,
    pub catalogue_decision_digest: Sha256Digest,
    pub capability_report_generation: Generation,
    pub capability_report_digest: Sha256Digest,
    pub host_driver_context_digest: Sha256Digest,
    pub capability_observed_at_utc_ms: SafeU64,
    pub capability_max_age_ms: SafeU64,
    pub adapter_capability_digest: Sha256Digest,
    pub replay_claim_id: Sha256Digest,
    pub replay_claimant_generation: Generation,
    pub replay_binding_digest: Sha256Digest,
    pub budget_scope_id: Identifier,
    pub budget_scope_generation: Generation,
    pub budget_scope_binding_digest: Sha256Digest,
    pub reservation_id: Identifier,
    pub reservation_generation: Generation,
    pub reservation_binding_digest: Sha256Digest,
    pub reservation_vector_digest: Sha256Digest,
    pub recovery_reference_digest: Sha256Digest,
    pub recovery_mode: RecoveryModeV1,
    pub recovery_profile_digest: Sha256Digest,
    pub recovery_binding_digest: Sha256Digest,
    pub recovery_receipt_digest: Sha256Digest,
    pub destination_adapter_id: Identifier,
    pub boot_id: Identifier,
    pub instance_epoch: SafeU64,
    pub supervisor_epoch: SafeU64,
    pub supervisor_generation: Generation,
    pub clock_generation: Generation,
    pub issued_at_utc_ms: SafeU64,
    pub issued_at_monotonic_ms: SafeU64,
    pub deadline_monotonic_ms: Generation,
}

impl fmt::Debug for ExecutionGrantInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionGrantInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGrantProtectedV1 {
    schema: String,
    digest_algorithm: String,
    signature_algorithm: String,
    key_purpose: String,
    key_id: Identifier,
    grant_id: Sha256Digest,
    dispatch_attempt_id: Sha256Digest,
    one_shot_nonce: Sha256Digest,
    operation_id: Identifier,
    operation_state_generation: Generation,
    preparation_attempt_id: Sha256Digest,
    preparation_transition_generation: Generation,
    plan_id: Sha256Digest,
    task_id: Identifier,
    workload_id: Identifier,
    intent: String,
    target: ResourceRefV1,
    precondition_digest: Sha256Digest,
    content_digest: Sha256Digest,
    content_byte_length: SafeU64,
    content_media_type: String,
    trust_generation: Generation,
    verified_key_fingerprint: Sha256Digest,
    workload_generation: Generation,
    workload_evidence_digest: Sha256Digest,
    lease_generation: Generation,
    lease_digest: Sha256Digest,
    lease_decision_digest: Sha256Digest,
    authorization_generation: Generation,
    authorization_evidence_digest: Sha256Digest,
    policy_generation: Generation,
    policy_decision_generation: Generation,
    policy_content_digest: Sha256Digest,
    policy_decision_digest: Sha256Digest,
    catalogue_generation: Generation,
    catalogue_decision_generation: Generation,
    catalogue_content_digest: Sha256Digest,
    catalogue_decision_digest: Sha256Digest,
    capability_report_generation: Generation,
    capability_report_digest: Sha256Digest,
    host_driver_context_digest: Sha256Digest,
    capability_observed_at_utc_ms: SafeU64,
    capability_max_age_ms: SafeU64,
    adapter_capability_digest: Sha256Digest,
    replay_claim_id: Sha256Digest,
    replay_claimant_generation: Generation,
    replay_binding_digest: Sha256Digest,
    budget_scope_id: Identifier,
    budget_scope_generation: Generation,
    budget_scope_binding_digest: Sha256Digest,
    reservation_id: Identifier,
    reservation_generation: Generation,
    reservation_binding_digest: Sha256Digest,
    reservation_vector_digest: Sha256Digest,
    recovery_reference_digest: Sha256Digest,
    recovery_mode: RecoveryModeV1,
    recovery_profile_digest: Sha256Digest,
    recovery_binding_digest: Sha256Digest,
    recovery_receipt_digest: Sha256Digest,
    destination_adapter_id: Identifier,
    protocol_version: u8,
    boot_id: Identifier,
    instance_epoch: SafeU64,
    supervisor_epoch: SafeU64,
    supervisor_generation: Generation,
    clock_generation: Generation,
    issued_at_utc_ms: SafeU64,
    issued_at_monotonic_ms: SafeU64,
    deadline_monotonic_ms: Generation,
}

impl fmt::Debug for ExecutionGrantProtectedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionGrantProtectedV1")
            .finish_non_exhaustive()
    }
}

impl ExecutionGrantProtectedV1 {
    pub fn try_new(input: ExecutionGrantInputV1, key_id: Identifier) -> Result<Self> {
        let value = Self {
            schema: "helixos.execution-grant/1".to_owned(),
            digest_algorithm: "sha-256".to_owned(),
            signature_algorithm: "ed25519".to_owned(),
            key_purpose: "coordinator-dispatch-signing".to_owned(),
            key_id,
            grant_id: input.grant_id,
            dispatch_attempt_id: input.dispatch_attempt_id,
            one_shot_nonce: input.one_shot_nonce,
            operation_id: input.operation_id,
            operation_state_generation: input.operation_state_generation,
            preparation_attempt_id: input.preparation_attempt_id,
            preparation_transition_generation: input.preparation_transition_generation,
            plan_id: input.plan_id,
            task_id: input.task_id,
            workload_id: input.workload_id,
            intent: "host.file.patch".to_owned(),
            target: input.target,
            precondition_digest: input.precondition_digest,
            content_digest: input.content_digest,
            content_byte_length: input.content_byte_length,
            content_media_type: input.content_media_type,
            trust_generation: input.trust_generation,
            verified_key_fingerprint: input.verified_key_fingerprint,
            workload_generation: input.workload_generation,
            workload_evidence_digest: input.workload_evidence_digest,
            lease_generation: input.lease_generation,
            lease_digest: input.lease_digest,
            lease_decision_digest: input.lease_decision_digest,
            authorization_generation: input.authorization_generation,
            authorization_evidence_digest: input.authorization_evidence_digest,
            policy_generation: input.policy_generation,
            policy_decision_generation: input.policy_decision_generation,
            policy_content_digest: input.policy_content_digest,
            policy_decision_digest: input.policy_decision_digest,
            catalogue_generation: input.catalogue_generation,
            catalogue_decision_generation: input.catalogue_decision_generation,
            catalogue_content_digest: input.catalogue_content_digest,
            catalogue_decision_digest: input.catalogue_decision_digest,
            capability_report_generation: input.capability_report_generation,
            capability_report_digest: input.capability_report_digest,
            host_driver_context_digest: input.host_driver_context_digest,
            capability_observed_at_utc_ms: input.capability_observed_at_utc_ms,
            capability_max_age_ms: input.capability_max_age_ms,
            adapter_capability_digest: input.adapter_capability_digest,
            replay_claim_id: input.replay_claim_id,
            replay_claimant_generation: input.replay_claimant_generation,
            replay_binding_digest: input.replay_binding_digest,
            budget_scope_id: input.budget_scope_id,
            budget_scope_generation: input.budget_scope_generation,
            budget_scope_binding_digest: input.budget_scope_binding_digest,
            reservation_id: input.reservation_id,
            reservation_generation: input.reservation_generation,
            reservation_binding_digest: input.reservation_binding_digest,
            reservation_vector_digest: input.reservation_vector_digest,
            recovery_reference_digest: input.recovery_reference_digest,
            recovery_mode: input.recovery_mode,
            recovery_profile_digest: input.recovery_profile_digest,
            recovery_binding_digest: input.recovery_binding_digest,
            recovery_receipt_digest: input.recovery_receipt_digest,
            destination_adapter_id: input.destination_adapter_id,
            protocol_version: 1,
            boot_id: input.boot_id,
            instance_epoch: input.instance_epoch,
            supervisor_epoch: input.supervisor_epoch,
            supervisor_generation: input.supervisor_generation,
            clock_generation: input.clock_generation,
            issued_at_utc_ms: input.issued_at_utc_ms,
            issued_at_monotonic_ms: input.issued_at_monotonic_ms,
            deadline_monotonic_ms: input.deadline_monotonic_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate_exact_bindings(&self, expected: &Self) -> Result<()> {
        (self == expected)
            .then_some(())
            .ok_or(ContractError::GrantBindingMismatch)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "helixos.execution-grant/1" {
            return Err(ContractError::UnsupportedSchema);
        }
        if self.digest_algorithm != "sha-256" {
            return Err(ContractError::UnsupportedDigestAlgorithm);
        }
        if self.signature_algorithm != "ed25519" {
            return Err(ContractError::UnsupportedSignatureAlgorithm);
        }
        if self.key_purpose != "coordinator-dispatch-signing" {
            return Err(ContractError::WrongKeyPurpose);
        }
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocol);
        }
        if self.intent != "host.file.patch" || !valid_media_type(&self.content_media_type) {
            return Err(ContractError::InvalidField);
        }
        self.target.validate()?;
        if self.grant_id == self.dispatch_attempt_id
            || self.grant_id == self.one_shot_nonce
            || self.dispatch_attempt_id == self.one_shot_nonce
        {
            return Err(ContractError::InvalidField);
        }
        let issued = self.issued_at_monotonic_ms.get();
        let deadline = self.deadline_monotonic_ms.get();
        if issued >= deadline || deadline - issued > MAX_GRANT_LIFETIME_MS {
            return Err(ContractError::GrantLifetimeExceeded);
        }
        Ok(())
    }

    pub fn key_id(&self) -> &str {
        self.key_id.as_str()
    }

    pub const fn grant_id(&self) -> Sha256Digest {
        self.grant_id
    }

    pub fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }

    pub fn destination_adapter_id(&self) -> &str {
        self.destination_adapter_id.as_str()
    }

    pub const fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    pub fn boot_id(&self) -> &str {
        self.boot_id.as_str()
    }

    pub const fn supervisor_epoch(&self) -> u64 {
        self.supervisor_epoch.get()
    }

    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionGrantV1 {
    protected: ExecutionGrantProtectedV1,
    grant_digest: Sha256Digest,
    signature: String,
}

impl fmt::Debug for SignedExecutionGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedExecutionGrantV1")
            .finish_non_exhaustive()
    }
}

impl SignedExecutionGrantV1 {
    pub fn protected(&self) -> &ExecutionGrantProtectedV1 {
        &self.protected
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant_digest
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.protected.validate()?;
        to_jcs_vec(self)
    }
}

pub struct AuthenticExecutionGrantV1 {
    signed: SignedExecutionGrantV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

impl fmt::Debug for AuthenticExecutionGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticExecutionGrantV1")
            .finish_non_exhaustive()
    }
}

impl AuthenticExecutionGrantV1 {
    pub fn protected(&self) -> &ExecutionGrantProtectedV1 {
        &self.signed.protected
    }

    pub fn claims(&self) -> ExecutionGrantClaimsV1<'_> {
        ExecutionGrantClaimsV1 { grant: self }
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.signed.grant_digest
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

/// Read-only bindings projected only from a currently authentic grant.
#[derive(Clone, Copy)]
pub struct ExecutionGrantClaimsV1<'grant> {
    grant: &'grant AuthenticExecutionGrantV1,
}

impl fmt::Debug for ExecutionGrantClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionGrantClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'grant> ExecutionGrantClaimsV1<'grant> {
    fn protected(&self) -> &'grant ExecutionGrantProtectedV1 {
        &self.grant.signed.protected
    }

    pub const fn schema(&self) -> &'static str {
        "helixos.execution-grant/1"
    }

    pub const fn digest_algorithm(&self) -> &'static str {
        "sha-256"
    }

    pub const fn signature_algorithm(&self) -> &'static str {
        "ed25519"
    }

    pub const fn key_purpose(&self) -> &'static str {
        "coordinator-dispatch-signing"
    }

    pub fn key_id(&self) -> &'grant str {
        self.protected().key_id.as_str()
    }

    pub const fn grant_id(&self) -> Sha256Digest {
        self.grant.signed.protected.grant_id
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant.signed.grant_digest
    }

    pub const fn dispatch_attempt_id(&self) -> Sha256Digest {
        self.grant.signed.protected.dispatch_attempt_id
    }

    pub const fn one_shot_nonce(&self) -> Sha256Digest {
        self.grant.signed.protected.one_shot_nonce
    }

    pub fn operation_id(&self) -> &'grant str {
        self.protected().operation_id.as_str()
    }

    pub const fn operation_state_generation(&self) -> u64 {
        self.grant.signed.protected.operation_state_generation.get()
    }

    pub const fn preparation_attempt_id(&self) -> Sha256Digest {
        self.grant.signed.protected.preparation_attempt_id
    }

    pub const fn preparation_transition_generation(&self) -> u64 {
        self.grant
            .signed
            .protected
            .preparation_transition_generation
            .get()
    }

    pub const fn plan_id(&self) -> Sha256Digest {
        self.grant.signed.protected.plan_id
    }

    pub fn task_id(&self) -> &'grant str {
        self.protected().task_id.as_str()
    }

    pub fn workload_id(&self) -> &'grant str {
        self.protected().workload_id.as_str()
    }

    pub const fn intent(&self) -> &'static str {
        "host.file.patch"
    }

    pub fn target(&self) -> &'grant ResourceRefV1 {
        &self.protected().target
    }

    pub const fn precondition_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.precondition_digest
    }

    pub const fn content_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.content_digest
    }

    pub const fn content_byte_length(&self) -> u64 {
        self.grant.signed.protected.content_byte_length.get()
    }

    pub fn content_media_type(&self) -> &'grant str {
        &self.protected().content_media_type
    }

    pub const fn trust_generation(&self) -> u64 {
        self.grant.signed.protected.trust_generation.get()
    }

    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.grant.signed.protected.verified_key_fingerprint
    }

    pub const fn workload_generation(&self) -> u64 {
        self.grant.signed.protected.workload_generation.get()
    }

    pub const fn workload_evidence_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.workload_evidence_digest
    }

    pub const fn lease_generation(&self) -> u64 {
        self.grant.signed.protected.lease_generation.get()
    }

    pub const fn lease_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.lease_digest
    }

    pub const fn lease_decision_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.lease_decision_digest
    }

    pub const fn authorization_generation(&self) -> u64 {
        self.grant.signed.protected.authorization_generation.get()
    }

    pub const fn authorization_evidence_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.authorization_evidence_digest
    }

    pub const fn policy_generation(&self) -> u64 {
        self.grant.signed.protected.policy_generation.get()
    }

    pub const fn policy_decision_generation(&self) -> u64 {
        self.grant.signed.protected.policy_decision_generation.get()
    }

    pub const fn policy_content_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.policy_content_digest
    }

    pub const fn policy_decision_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.policy_decision_digest
    }

    pub const fn catalogue_generation(&self) -> u64 {
        self.grant.signed.protected.catalogue_generation.get()
    }

    pub const fn catalogue_decision_generation(&self) -> u64 {
        self.grant
            .signed
            .protected
            .catalogue_decision_generation
            .get()
    }

    pub const fn catalogue_content_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.catalogue_content_digest
    }

    pub const fn catalogue_decision_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.catalogue_decision_digest
    }

    pub const fn capability_report_generation(&self) -> u64 {
        self.grant
            .signed
            .protected
            .capability_report_generation
            .get()
    }

    pub const fn capability_report_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.capability_report_digest
    }

    pub const fn host_driver_context_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.host_driver_context_digest
    }

    pub const fn capability_observed_at_utc_ms(&self) -> u64 {
        self.grant
            .signed
            .protected
            .capability_observed_at_utc_ms
            .get()
    }

    pub const fn capability_max_age_ms(&self) -> u64 {
        self.grant.signed.protected.capability_max_age_ms.get()
    }

    pub const fn adapter_capability_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.adapter_capability_digest
    }

    pub const fn replay_claim_id(&self) -> Sha256Digest {
        self.grant.signed.protected.replay_claim_id
    }

    pub const fn replay_claimant_generation(&self) -> u64 {
        self.grant.signed.protected.replay_claimant_generation.get()
    }

    pub const fn replay_binding_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.replay_binding_digest
    }

    pub fn budget_scope_id(&self) -> &'grant str {
        self.protected().budget_scope_id.as_str()
    }

    pub const fn budget_scope_generation(&self) -> u64 {
        self.grant.signed.protected.budget_scope_generation.get()
    }

    pub const fn budget_scope_binding_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.budget_scope_binding_digest
    }

    pub fn reservation_id(&self) -> &'grant str {
        self.protected().reservation_id.as_str()
    }

    pub const fn reservation_generation(&self) -> u64 {
        self.grant.signed.protected.reservation_generation.get()
    }

    pub const fn reservation_binding_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.reservation_binding_digest
    }

    pub const fn reservation_vector_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.reservation_vector_digest
    }

    pub const fn recovery_reference_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.recovery_reference_digest
    }

    pub const fn recovery_mode(&self) -> RecoveryModeV1 {
        self.grant.signed.protected.recovery_mode
    }

    pub const fn recovery_profile_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.recovery_profile_digest
    }

    pub const fn recovery_binding_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.recovery_binding_digest
    }

    pub const fn recovery_receipt_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.recovery_receipt_digest
    }

    pub fn destination_adapter_id(&self) -> &'grant str {
        self.protected().destination_adapter_id.as_str()
    }

    pub const fn protocol_version(&self) -> u8 {
        self.grant.signed.protected.protocol_version
    }

    pub fn boot_id(&self) -> &'grant str {
        self.protected().boot_id.as_str()
    }

    pub const fn instance_epoch(&self) -> u64 {
        self.grant.signed.protected.instance_epoch.get()
    }

    pub const fn supervisor_epoch(&self) -> u64 {
        self.grant.signed.protected.supervisor_epoch.get()
    }

    pub const fn supervisor_generation(&self) -> u64 {
        self.grant.signed.protected.supervisor_generation.get()
    }

    pub const fn clock_generation(&self) -> u64 {
        self.grant.signed.protected.clock_generation.get()
    }

    pub const fn issued_at_utc_ms(&self) -> u64 {
        self.grant.signed.protected.issued_at_utc_ms.get()
    }

    pub const fn issued_at_monotonic_ms(&self) -> u64 {
        self.grant.signed.protected.issued_at_monotonic_ms.get()
    }

    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.grant.signed.protected.deadline_monotonic_ms.get()
    }
}

/// Signature-verified retained grant bytes with no current dispatch authority.
pub struct RetainedExecutionGrantEvidenceV1 {
    signed: SignedExecutionGrantV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

impl fmt::Debug for RetainedExecutionGrantEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedExecutionGrantEvidenceV1")
            .finish_non_exhaustive()
    }
}

impl RetainedExecutionGrantEvidenceV1 {
    pub fn claims(&self) -> RetainedExecutionGrantClaimsV1<'_> {
        RetainedExecutionGrantClaimsV1 { evidence: self }
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.signed.grant_digest
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

/// Read-only correlation claims from retained grant evidence after key rotation.
///
/// Unlike [`ExecutionGrantClaimsV1`], this projection cannot create current dispatch
/// authority and is intended only for historical receipt verification and audit.
#[derive(Clone, Copy)]
pub struct RetainedExecutionGrantClaimsV1<'evidence> {
    evidence: &'evidence RetainedExecutionGrantEvidenceV1,
}

impl fmt::Debug for RetainedExecutionGrantClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedExecutionGrantClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'evidence> RetainedExecutionGrantClaimsV1<'evidence> {
    fn protected(&self) -> &'evidence ExecutionGrantProtectedV1 {
        &self.evidence.signed.protected
    }

    pub const fn grant_id(&self) -> Sha256Digest {
        self.evidence.signed.protected.grant_id
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.evidence.signed.grant_digest
    }

    pub fn operation_id(&self) -> &'evidence str {
        self.protected().operation_id.as_str()
    }

    pub fn destination_adapter_id(&self) -> &'evidence str {
        self.protected().destination_adapter_id.as_str()
    }

    pub const fn protocol_version(&self) -> u8 {
        self.evidence.signed.protected.protocol_version
    }

    pub fn boot_id(&self) -> &'evidence str {
        self.protected().boot_id.as_str()
    }

    pub const fn supervisor_epoch(&self) -> u64 {
        self.evidence.signed.protected.supervisor_epoch.get()
    }

    pub const fn issued_at_monotonic_ms(&self) -> u64 {
        self.evidence.signed.protected.issued_at_monotonic_ms.get()
    }

    pub const fn deadline_monotonic_ms(&self) -> u64 {
        self.evidence.signed.protected.deadline_monotonic_ms.get()
    }
}

pub fn sign_execution_grant_v1<S: GrantSigner>(
    protected: ExecutionGrantProtectedV1,
    signer: &S,
) -> Result<SignedExecutionGrantV1> {
    protected.validate()?;
    if protected.key_id() != signer.key_id() {
        return Err(ContractError::WrongKeyPurpose);
    }
    let protected_bytes = to_jcs_vec(&protected)?;
    let grant_digest = Sha256Digest::digest(&protected_bytes);
    let signature = signer
        .sign_execution_grant(&signature_message(GRANT_SIGNATURE_DOMAIN, &protected_bytes))
        .map_err(|_| ContractError::SigningFailed)?;
    Ok(SignedExecutionGrantV1 {
        protected,
        grant_digest,
        signature: encode_signature(signature),
    })
}

pub fn decode_and_verify_execution_grant_v1<R: GrantKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<AuthenticExecutionGrantV1> {
    let verified = decode_verified_execution_grant_v1(wire, resolver)?;
    if verified.verification_key_status != VerificationKeyStatusV1::Current {
        return Err(ContractError::HistoricalKeyNotAuthority);
    }
    Ok(AuthenticExecutionGrantV1 {
        signed: verified.signed,
        verified_key_fingerprint: verified.verified_key_fingerprint,
        verification_key_status: verified.verification_key_status,
    })
}

pub fn decode_and_verify_retained_execution_grant_v1<R: GrantKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<RetainedExecutionGrantEvidenceV1> {
    let verified = decode_verified_execution_grant_v1(wire, resolver)?;
    Ok(RetainedExecutionGrantEvidenceV1 {
        signed: verified.signed,
        verified_key_fingerprint: verified.verified_key_fingerprint,
        verification_key_status: verified.verification_key_status,
    })
}

struct VerifiedExecutionGrantV1 {
    signed: SignedExecutionGrantV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

fn decode_verified_execution_grant_v1<R: GrantKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<VerifiedExecutionGrantV1> {
    let value = decode_canonical_value(wire, MAX_GRANT_WIRE_BYTES)?;
    preflight_grant(&value)?;
    let signed: SignedExecutionGrantV1 =
        serde_json::from_value(value).map_err(|_| ContractError::InvalidField)?;
    signed.protected.validate()?;
    let protected_bytes = to_jcs_vec(&signed.protected)?;
    if Sha256Digest::digest(&protected_bytes) != signed.grant_digest {
        return Err(ContractError::DigestMismatch);
    }
    decode_signature(&signed.signature)?;
    let key = resolver.resolve_grant_key(signed.protected.key_id())?;
    let (verified_key_fingerprint, verification_key_status) = verify_grant_signature(
        &signed.signature,
        &signature_message(GRANT_SIGNATURE_DOMAIN, &protected_bytes),
        key,
    )?;
    Ok(VerifiedExecutionGrantV1 {
        signed,
        verified_key_fingerprint,
        verification_key_status,
    })
}

fn preflight_grant(value: &Value) -> Result<()> {
    require_closed_object(value, OUTER_FIELDS, true)?;
    let protected = value
        .get("protected")
        .ok_or(ContractError::MissingOuterField)?;
    require_closed_object(protected, PROTECTED_FIELDS, false)?;
    match protected.get("schema").and_then(Value::as_str) {
        Some("helixos.execution-grant/1") => {}
        Some(_) => return Err(ContractError::UnsupportedSchema),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("digest_algorithm").and_then(Value::as_str) {
        Some("sha-256") => {}
        Some(_) => return Err(ContractError::UnsupportedDigestAlgorithm),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("signature_algorithm").and_then(Value::as_str) {
        Some("ed25519") => {}
        Some(_) => return Err(ContractError::UnsupportedSignatureAlgorithm),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("key_purpose").and_then(Value::as_str) {
        Some("coordinator-dispatch-signing") => {}
        Some(_) => return Err(ContractError::WrongKeyPurpose),
        None => return Err(ContractError::InvalidField),
    }
    if protected.get("protocol_version").and_then(Value::as_u64) != Some(1) {
        return Err(ContractError::UnsupportedProtocol);
    }
    Ok(())
}
