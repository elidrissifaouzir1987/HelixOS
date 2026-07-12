//! Explicit preliminary and final authority-snapshot boundary.
//!
//! Contexts contain only portable values supplied by trusted providers. This module
//! must not read ambient clocks or retain callbacks, native handles, paths, or guards.

#![allow(dead_code)]

use helix_contracts::{Identifier, SafeU64, Sha256Digest};
use helix_plan_eligibility::SupervisorAdmissionStateV1;
use std::fmt;

macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}

pub const PREPARATION_CONTEXT_VERSION_V1: u16 = 1;
pub const RECOVERY_PROVIDER_CONTEXT_VERSION_V1: u16 = 1;

type BuildResult<T> = Result<T, PreparationContextBuildErrorV1>;

#[derive(Debug, PartialEq, Eq)]
pub enum PreparationContextBuildErrorV1 {
    VersionUnsupported,
    IntegerOutOfRange,
    InvalidCurrencyCode,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PreparationClockReadErrorV1 {
    Unavailable,
}

/// Injected trusted UTC source; the portable crate provides no ambient fallback.
pub trait PreparationUtcClockV1: Send + Sync {
    fn now_utc_ms(&self) -> Result<u64, PreparationClockReadErrorV1>;
}

/// Injected suspend-aware boot-monotonic source; values are absolute milliseconds.
pub trait PreparationMonotonicClockV1: Send + Sync {
    fn now_monotonic_ms(&self) -> Result<u64, PreparationClockReadErrorV1>;
}

/// Marker for wiring that supplies both explicit preparation clock domains.
pub trait PreparationTimeSourceV1: PreparationUtcClockV1 + PreparationMonotonicClockV1 {}

impl<T> PreparationTimeSourceV1 for T where T: PreparationUtcClockV1 + PreparationMonotonicClockV1 {}

#[derive(Debug, PartialEq, Eq)]
pub enum PreparationCapturePhaseV1 {
    Preliminary,
    Final,
}

pub struct PreparationRequestedBudgetInputV1 {
    pub max_cost_micro_units: u64,
    pub action_limit: u64,
    pub egress_bytes_limit: u64,
    pub recovery_bytes: u64,
}

redacted_debug!(
    PreparationRequestedBudgetInputV1,
    "PreparationRequestedBudgetInputV1"
);

/// Exact four-dimensional request copied from authenticated preparation claims.
pub struct PreparationRequestedBudgetV1 {
    max_cost_micro_units: SafeU64,
    action_limit: SafeU64,
    egress_bytes_limit: SafeU64,
    recovery_bytes: SafeU64,
}

impl PreparationRequestedBudgetV1 {
    pub fn try_new(input: PreparationRequestedBudgetInputV1) -> BuildResult<Self> {
        Ok(Self {
            max_cost_micro_units: safe(input.max_cost_micro_units)?,
            action_limit: safe(input.action_limit)?,
            egress_bytes_limit: safe(input.egress_bytes_limit)?,
            recovery_bytes: safe(input.recovery_bytes)?,
        })
    }

    pub const fn max_cost_micro_units(&self) -> u64 {
        self.max_cost_micro_units.get()
    }

    pub const fn action_limit(&self) -> u64 {
        self.action_limit.get()
    }

    pub const fn egress_bytes_limit(&self) -> u64 {
        self.egress_bytes_limit.get()
    }

    pub const fn recovery_bytes(&self) -> u64 {
        self.recovery_bytes.get()
    }
}

redacted_debug!(PreparationRequestedBudgetV1, "PreparationRequestedBudgetV1");

pub struct RecoveryProviderContextInputV1 {
    pub profile_id: Identifier,
    pub profile_version: u16,
    pub provider_id: Identifier,
    pub evidence_class: Identifier,
    pub provider_generation: u64,
    pub capability_binding_digest: Sha256Digest,
    pub at_rest_profile_id: Identifier,
    pub supports_create_only: bool,
    pub supports_sync: bool,
    pub supports_no_clobber_publication: bool,
}

redacted_debug!(
    RecoveryProviderContextInputV1,
    "RecoveryProviderContextInputV1"
);

/// Explicit recovery-provider facts captured with the authority snapshot.
pub struct RecoveryProviderContextV1 {
    profile_id: Identifier,
    profile_version: u16,
    provider_id: Identifier,
    evidence_class: Identifier,
    provider_generation: SafeU64,
    capability_binding_digest: Sha256Digest,
    at_rest_profile_id: Identifier,
    supports_create_only: bool,
    supports_sync: bool,
    supports_no_clobber_publication: bool,
}

impl RecoveryProviderContextV1 {
    pub fn try_new(input: RecoveryProviderContextInputV1) -> BuildResult<Self> {
        if input.profile_version != RECOVERY_PROVIDER_CONTEXT_VERSION_V1 {
            return Err(PreparationContextBuildErrorV1::VersionUnsupported);
        }
        Ok(Self {
            profile_id: input.profile_id,
            profile_version: input.profile_version,
            provider_id: input.provider_id,
            evidence_class: input.evidence_class,
            provider_generation: safe(input.provider_generation)?,
            capability_binding_digest: input.capability_binding_digest,
            at_rest_profile_id: input.at_rest_profile_id,
            supports_create_only: input.supports_create_only,
            supports_sync: input.supports_sync,
            supports_no_clobber_publication: input.supports_no_clobber_publication,
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

    pub fn evidence_class(&self) -> &str {
        self.evidence_class.as_str()
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation.get()
    }

    pub const fn capability_binding_digest(&self) -> Sha256Digest {
        self.capability_binding_digest
    }

    pub fn at_rest_profile_id(&self) -> &str {
        self.at_rest_profile_id.as_str()
    }

    pub const fn supports_create_only(&self) -> bool {
        self.supports_create_only
    }

    pub const fn supports_sync(&self) -> bool {
        self.supports_sync
    }

    pub const fn supports_no_clobber_publication(&self) -> bool {
        self.supports_no_clobber_publication
    }
}

redacted_debug!(RecoveryProviderContextV1, "RecoveryProviderContextV1");

/// Complete structural input supplied by trusted context-provider wiring.
pub struct ReadyPreparationContextInputV1 {
    pub context_version: u16,
    pub phase: PreparationCapturePhaseV1,
    pub plan_id: Sha256Digest,
    pub operation_id: Identifier,
    pub task_id: Identifier,
    pub workload_id: Identifier,
    pub attempt_id: Sha256Digest,
    pub capture_generation: u64,
    pub clock_generation: u64,
    pub plan_deadline_generation: u64,
    pub sampled_utc_ms: u64,
    pub sampled_monotonic_ms: u64,
    pub effective_expires_at_utc_ms: u64,
    pub effective_deadline_monotonic_ms: u64,
    pub supervisor_admission_state: SupervisorAdmissionStateV1,
    pub supervisor_generation: u64,
    pub boot_id: Identifier,
    pub instance_epoch: u64,
    pub fencing_epoch: u64,
    pub trust_generation: u64,
    pub verified_key_fingerprint: Sha256Digest,
    pub workload_generation: u64,
    pub workload_evidence_digest: Sha256Digest,
    pub lease_generation: u64,
    pub lease_digest: Sha256Digest,
    pub lease_decision_digest: Sha256Digest,
    pub authorization_generation: u64,
    pub authorization_evidence_digest: Sha256Digest,
    pub policy_generation: u64,
    pub policy_decision_generation: u64,
    pub policy_content_digest: Sha256Digest,
    pub policy_decision_digest: Sha256Digest,
    pub catalogue_generation: u64,
    pub catalogue_decision_generation: u64,
    pub catalogue_content_digest: Sha256Digest,
    pub catalogue_decision_digest: Sha256Digest,
    pub capability_report_generation: u64,
    pub capability_report_digest: Sha256Digest,
    pub host_driver_context_digest: Sha256Digest,
    pub capability_observed_at_utc_ms: u64,
    pub capability_max_age_ms: u64,
    pub replay_claim_id: Sha256Digest,
    pub replay_claimant_generation: u64,
    pub replay_binding_digest: Sha256Digest,
    pub budget_scope_binding_digest: Sha256Digest,
    pub budget_scope_generation: u64,
    pub currency_code: Identifier,
    pub price_table_id: Identifier,
    pub requested_budget: PreparationRequestedBudgetV1,
    pub recovery_provider: Option<RecoveryProviderContextV1>,
}

redacted_debug!(
    ReadyPreparationContextInputV1,
    "ReadyPreparationContextInputV1"
);

/// One complete, internally coherent preliminary or final portable snapshot.
pub struct ReadyPreparationContextV1 {
    context_version: u16,
    phase: PreparationCapturePhaseV1,
    plan_id: Sha256Digest,
    operation_id: Identifier,
    task_id: Identifier,
    workload_id: Identifier,
    attempt_id: Sha256Digest,
    capture_generation: SafeU64,
    clock_generation: SafeU64,
    plan_deadline_generation: SafeU64,
    sampled_utc_ms: SafeU64,
    sampled_monotonic_ms: SafeU64,
    effective_expires_at_utc_ms: SafeU64,
    effective_deadline_monotonic_ms: SafeU64,
    supervisor_admission_state: SupervisorAdmissionStateV1,
    supervisor_generation: SafeU64,
    boot_id: Identifier,
    instance_epoch: SafeU64,
    fencing_epoch: SafeU64,
    trust_generation: SafeU64,
    verified_key_fingerprint: Sha256Digest,
    workload_generation: SafeU64,
    workload_evidence_digest: Sha256Digest,
    lease_generation: SafeU64,
    lease_digest: Sha256Digest,
    lease_decision_digest: Sha256Digest,
    authorization_generation: SafeU64,
    authorization_evidence_digest: Sha256Digest,
    policy_generation: SafeU64,
    policy_decision_generation: SafeU64,
    policy_content_digest: Sha256Digest,
    policy_decision_digest: Sha256Digest,
    catalogue_generation: SafeU64,
    catalogue_decision_generation: SafeU64,
    catalogue_content_digest: Sha256Digest,
    catalogue_decision_digest: Sha256Digest,
    capability_report_generation: SafeU64,
    capability_report_digest: Sha256Digest,
    host_driver_context_digest: Sha256Digest,
    capability_observed_at_utc_ms: SafeU64,
    capability_max_age_ms: SafeU64,
    replay_claim_id: Sha256Digest,
    replay_claimant_generation: SafeU64,
    replay_binding_digest: Sha256Digest,
    budget_scope_binding_digest: Sha256Digest,
    budget_scope_generation: SafeU64,
    currency_code: Identifier,
    price_table_id: Identifier,
    requested_budget: PreparationRequestedBudgetV1,
    recovery_provider: Option<RecoveryProviderContextV1>,
}

impl ReadyPreparationContextV1 {
    pub fn try_new(input: ReadyPreparationContextInputV1) -> BuildResult<Self> {
        if input.context_version != PREPARATION_CONTEXT_VERSION_V1 {
            return Err(PreparationContextBuildErrorV1::VersionUnsupported);
        }
        if !is_currency_code(input.currency_code.as_str()) {
            return Err(PreparationContextBuildErrorV1::InvalidCurrencyCode);
        }
        Ok(Self {
            context_version: input.context_version,
            phase: input.phase,
            plan_id: input.plan_id,
            operation_id: input.operation_id,
            task_id: input.task_id,
            workload_id: input.workload_id,
            attempt_id: input.attempt_id,
            capture_generation: safe(input.capture_generation)?,
            clock_generation: safe(input.clock_generation)?,
            plan_deadline_generation: safe(input.plan_deadline_generation)?,
            sampled_utc_ms: safe(input.sampled_utc_ms)?,
            sampled_monotonic_ms: safe(input.sampled_monotonic_ms)?,
            effective_expires_at_utc_ms: safe(input.effective_expires_at_utc_ms)?,
            effective_deadline_monotonic_ms: safe(input.effective_deadline_monotonic_ms)?,
            supervisor_admission_state: input.supervisor_admission_state,
            supervisor_generation: safe(input.supervisor_generation)?,
            boot_id: input.boot_id,
            instance_epoch: safe(input.instance_epoch)?,
            fencing_epoch: safe(input.fencing_epoch)?,
            trust_generation: safe(input.trust_generation)?,
            verified_key_fingerprint: input.verified_key_fingerprint,
            workload_generation: safe(input.workload_generation)?,
            workload_evidence_digest: input.workload_evidence_digest,
            lease_generation: safe(input.lease_generation)?,
            lease_digest: input.lease_digest,
            lease_decision_digest: input.lease_decision_digest,
            authorization_generation: safe(input.authorization_generation)?,
            authorization_evidence_digest: input.authorization_evidence_digest,
            policy_generation: safe(input.policy_generation)?,
            policy_decision_generation: safe(input.policy_decision_generation)?,
            policy_content_digest: input.policy_content_digest,
            policy_decision_digest: input.policy_decision_digest,
            catalogue_generation: safe(input.catalogue_generation)?,
            catalogue_decision_generation: safe(input.catalogue_decision_generation)?,
            catalogue_content_digest: input.catalogue_content_digest,
            catalogue_decision_digest: input.catalogue_decision_digest,
            capability_report_generation: safe(input.capability_report_generation)?,
            capability_report_digest: input.capability_report_digest,
            host_driver_context_digest: input.host_driver_context_digest,
            capability_observed_at_utc_ms: safe(input.capability_observed_at_utc_ms)?,
            capability_max_age_ms: safe(input.capability_max_age_ms)?,
            replay_claim_id: input.replay_claim_id,
            replay_claimant_generation: safe(input.replay_claimant_generation)?,
            replay_binding_digest: input.replay_binding_digest,
            budget_scope_binding_digest: input.budget_scope_binding_digest,
            budget_scope_generation: safe(input.budget_scope_generation)?,
            currency_code: input.currency_code,
            price_table_id: input.price_table_id,
            requested_budget: input.requested_budget,
            recovery_provider: input.recovery_provider,
        })
    }

    pub const fn context_version(&self) -> u16 {
        self.context_version
    }
    pub const fn phase(&self) -> &PreparationCapturePhaseV1 {
        &self.phase
    }
    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }
    pub fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }
    pub fn task_id(&self) -> &str {
        self.task_id.as_str()
    }
    pub fn workload_id(&self) -> &str {
        self.workload_id.as_str()
    }
    pub const fn attempt_id(&self) -> Sha256Digest {
        self.attempt_id
    }
    pub const fn capture_generation(&self) -> u64 {
        self.capture_generation.get()
    }
    pub const fn clock_generation(&self) -> u64 {
        self.clock_generation.get()
    }
    pub const fn plan_deadline_generation(&self) -> u64 {
        self.plan_deadline_generation.get()
    }
    pub const fn sampled_utc_ms(&self) -> u64 {
        self.sampled_utc_ms.get()
    }
    pub const fn sampled_monotonic_ms(&self) -> u64 {
        self.sampled_monotonic_ms.get()
    }
    pub const fn effective_expires_at_utc_ms(&self) -> u64 {
        self.effective_expires_at_utc_ms.get()
    }
    pub const fn effective_deadline_monotonic_ms(&self) -> u64 {
        self.effective_deadline_monotonic_ms.get()
    }
    pub const fn supervisor_admission_state(&self) -> SupervisorAdmissionStateV1 {
        self.supervisor_admission_state
    }
    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation.get()
    }
    pub fn boot_id(&self) -> &str {
        self.boot_id.as_str()
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch.get()
    }
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation.get()
    }
    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.verified_key_fingerprint
    }
    pub const fn workload_generation(&self) -> u64 {
        self.workload_generation.get()
    }
    pub const fn workload_evidence_digest(&self) -> Sha256Digest {
        self.workload_evidence_digest
    }
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation.get()
    }
    pub const fn lease_digest(&self) -> Sha256Digest {
        self.lease_digest
    }
    pub const fn lease_decision_digest(&self) -> Sha256Digest {
        self.lease_decision_digest
    }
    pub const fn authorization_generation(&self) -> u64 {
        self.authorization_generation.get()
    }
    pub const fn authorization_evidence_digest(&self) -> Sha256Digest {
        self.authorization_evidence_digest
    }
    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation.get()
    }
    pub const fn policy_decision_generation(&self) -> u64 {
        self.policy_decision_generation.get()
    }
    pub const fn policy_content_digest(&self) -> Sha256Digest {
        self.policy_content_digest
    }
    pub const fn policy_decision_digest(&self) -> Sha256Digest {
        self.policy_decision_digest
    }
    pub const fn catalogue_generation(&self) -> u64 {
        self.catalogue_generation.get()
    }
    pub const fn catalogue_decision_generation(&self) -> u64 {
        self.catalogue_decision_generation.get()
    }
    pub const fn catalogue_content_digest(&self) -> Sha256Digest {
        self.catalogue_content_digest
    }
    pub const fn catalogue_decision_digest(&self) -> Sha256Digest {
        self.catalogue_decision_digest
    }
    pub const fn capability_report_generation(&self) -> u64 {
        self.capability_report_generation.get()
    }
    pub const fn capability_report_digest(&self) -> Sha256Digest {
        self.capability_report_digest
    }
    pub const fn host_driver_context_digest(&self) -> Sha256Digest {
        self.host_driver_context_digest
    }
    pub const fn capability_observed_at_utc_ms(&self) -> u64 {
        self.capability_observed_at_utc_ms.get()
    }
    pub const fn capability_max_age_ms(&self) -> u64 {
        self.capability_max_age_ms.get()
    }
    /// Checked freshness classification; equality with the maximum age remains live.
    pub(crate) fn capability_is_fresh_v1(&self) -> bool {
        checked_capability_freshness_v1(
            self.sampled_utc_ms(),
            self.capability_observed_at_utc_ms(),
            self.capability_max_age_ms(),
        )
    }
    pub const fn replay_claim_id(&self) -> Sha256Digest {
        self.replay_claim_id
    }
    pub const fn replay_claimant_generation(&self) -> u64 {
        self.replay_claimant_generation.get()
    }
    pub const fn replay_binding_digest(&self) -> Sha256Digest {
        self.replay_binding_digest
    }
    pub const fn budget_scope_binding_digest(&self) -> Sha256Digest {
        self.budget_scope_binding_digest
    }
    pub const fn budget_scope_generation(&self) -> u64 {
        self.budget_scope_generation.get()
    }
    pub fn currency_code(&self) -> &str {
        self.currency_code.as_str()
    }
    pub fn price_table_id(&self) -> &str {
        self.price_table_id.as_str()
    }
    pub const fn requested_budget(&self) -> &PreparationRequestedBudgetV1 {
        &self.requested_budget
    }
    pub fn recovery_provider(&self) -> Option<&RecoveryProviderContextV1> {
        self.recovery_provider.as_ref()
    }
}

redacted_debug!(ReadyPreparationContextV1, "ReadyPreparationContextV1");

/// Closed result of one trusted preliminary or final context capture.
// Keep the ready snapshot inline: introducing allocation/indirection at this authority
// boundary would add a new failure mode after eligibility has already been consumed.
#[allow(clippy::large_enum_variant)]
pub enum PreparationContextV1 {
    Ready(ReadyPreparationContextV1),
    Unavailable,
    Incomplete,
    Torn,
    Unsupported,
}

impl fmt::Debug for PreparationContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(_) => formatter.write_str("PreparationContextV1::Ready(..)"),
            Self::Unavailable => formatter.write_str("PreparationContextV1::Unavailable"),
            Self::Incomplete => formatter.write_str("PreparationContextV1::Incomplete"),
            Self::Torn => formatter.write_str("PreparationContextV1::Torn"),
            Self::Unsupported => formatter.write_str("PreparationContextV1::Unsupported"),
        }
    }
}

fn safe(value: u64) -> BuildResult<SafeU64> {
    SafeU64::new(value).map_err(|_| PreparationContextBuildErrorV1::IntegerOutOfRange)
}

fn is_currency_code(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn checked_capability_freshness_v1(
    sampled_utc_ms: u64,
    observed_utc_ms: u64,
    max_age_ms: u64,
) -> bool {
    sampled_utc_ms
        .checked_sub(observed_utc_ms)
        .is_some_and(|age| age <= max_age_ms)
}

#[cfg(test)]
mod tests {
    use super::checked_capability_freshness_v1;

    #[test]
    fn capability_age_is_checked_and_max_age_is_inclusive() {
        assert!(checked_capability_freshness_v1(110, 100, 10));
        assert!(!checked_capability_freshness_v1(111, 100, 10));
        assert!(!checked_capability_freshness_v1(99, 100, 10));
    }
}
