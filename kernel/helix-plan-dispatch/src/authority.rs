//! Trusted authority capture boundary for dispatch comparison.

#![allow(dead_code)]

use crate::attempt::DispatchAttemptIdV1;
use crate::control::DispatchTimeCaptureV1;
use crate::request::DispatchLookupRequestV1;
use helix_dispatch_contracts::{Generation, Identifier, RecoveryModeV1, SafeU64, Sha256Digest};
use std::fmt;

pub const DISPATCH_AUTHORITY_VIEW_VERSION_V1: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchAuthorityCapturePhaseV1 {
    Preliminary,
    FinalGuarded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchAuthorityViewBuildErrorV1 {
    VersionUnsupported,
    ProtocolUnsupported,
    DeadlineReached,
}

/// Complete typed input returned by trusted authority providers in one capture phase.
pub struct DispatchAuthorityViewInputV1 {
    pub contract_version: u16,
    pub phase: DispatchAuthorityCapturePhaseV1,
    pub time: DispatchTimeCaptureV1,
    pub task_id: Identifier,
    pub workload_id: Identifier,
    pub instance_epoch: SafeU64,
    pub supervisor_epoch: SafeU64,
    pub supervisor_generation: Generation,
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
    pub protocol_version: u8,
    pub signer_key_id: Identifier,
    pub signer_generation: Generation,
    pub signer_profile_digest: Sha256Digest,
    pub earliest_authority_deadline_monotonic_ms: Generation,
}

impl fmt::Debug for DispatchAuthorityViewInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchAuthorityViewInputV1")
            .finish_non_exhaustive()
    }
}

/// One checked capture from injected trusted authority providers.
pub struct DispatchAuthorityViewV1 {
    contract_version: u16,
    phase: DispatchAuthorityCapturePhaseV1,
    time: DispatchTimeCaptureV1,
    task_id: Identifier,
    workload_id: Identifier,
    instance_epoch: SafeU64,
    supervisor_epoch: SafeU64,
    supervisor_generation: Generation,
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
    signer_key_id: Identifier,
    signer_generation: Generation,
    signer_profile_digest: Sha256Digest,
    earliest_authority_deadline_monotonic_ms: Generation,
}

/// Borrowed exhaustive projection used only by crate-owned grant construction.
pub(crate) struct DispatchGrantAuthorityProjectionV1<'view> {
    pub(crate) boot_id: &'view Identifier,
    pub(crate) clock_generation: Generation,
    pub(crate) issued_at_utc_ms: SafeU64,
    pub(crate) issued_at_monotonic_ms: SafeU64,
    pub(crate) task_id: &'view Identifier,
    pub(crate) workload_id: &'view Identifier,
    pub(crate) instance_epoch: SafeU64,
    pub(crate) supervisor_epoch: SafeU64,
    pub(crate) supervisor_generation: Generation,
    pub(crate) trust_generation: Generation,
    pub(crate) verified_key_fingerprint: Sha256Digest,
    pub(crate) workload_generation: Generation,
    pub(crate) workload_evidence_digest: Sha256Digest,
    pub(crate) lease_generation: Generation,
    pub(crate) lease_digest: Sha256Digest,
    pub(crate) lease_decision_digest: Sha256Digest,
    pub(crate) authorization_generation: Generation,
    pub(crate) authorization_evidence_digest: Sha256Digest,
    pub(crate) policy_generation: Generation,
    pub(crate) policy_decision_generation: Generation,
    pub(crate) policy_content_digest: Sha256Digest,
    pub(crate) policy_decision_digest: Sha256Digest,
    pub(crate) catalogue_generation: Generation,
    pub(crate) catalogue_decision_generation: Generation,
    pub(crate) catalogue_content_digest: Sha256Digest,
    pub(crate) catalogue_decision_digest: Sha256Digest,
    pub(crate) capability_report_generation: Generation,
    pub(crate) capability_report_digest: Sha256Digest,
    pub(crate) host_driver_context_digest: Sha256Digest,
    pub(crate) capability_observed_at_utc_ms: SafeU64,
    pub(crate) capability_max_age_ms: SafeU64,
    pub(crate) adapter_capability_digest: Sha256Digest,
    pub(crate) replay_claim_id: Sha256Digest,
    pub(crate) replay_claimant_generation: Generation,
    pub(crate) replay_binding_digest: Sha256Digest,
    pub(crate) budget_scope_id: &'view Identifier,
    pub(crate) budget_scope_generation: Generation,
    pub(crate) budget_scope_binding_digest: Sha256Digest,
    pub(crate) reservation_id: &'view Identifier,
    pub(crate) reservation_generation: Generation,
    pub(crate) reservation_binding_digest: Sha256Digest,
    pub(crate) reservation_vector_digest: Sha256Digest,
    pub(crate) recovery_reference_digest: Sha256Digest,
    pub(crate) recovery_mode: RecoveryModeV1,
    pub(crate) recovery_profile_digest: Sha256Digest,
    pub(crate) recovery_binding_digest: Sha256Digest,
    pub(crate) recovery_receipt_digest: Sha256Digest,
    pub(crate) destination_adapter_id: &'view Identifier,
    pub(crate) protocol_version: u8,
    pub(crate) signer_key_id: &'view Identifier,
    pub(crate) signer_generation: Generation,
    pub(crate) signer_profile_digest: Sha256Digest,
    pub(crate) earliest_authority_deadline_monotonic_ms: Generation,
}

impl fmt::Debug for DispatchGrantAuthorityProjectionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchGrantAuthorityProjectionV1")
            .finish_non_exhaustive()
    }
}

impl DispatchAuthorityViewV1 {
    pub fn try_new(
        input: DispatchAuthorityViewInputV1,
    ) -> Result<Self, DispatchAuthorityViewBuildErrorV1> {
        if input.contract_version != DISPATCH_AUTHORITY_VIEW_VERSION_V1 {
            return Err(DispatchAuthorityViewBuildErrorV1::VersionUnsupported);
        }
        if input.protocol_version != 1 {
            return Err(DispatchAuthorityViewBuildErrorV1::ProtocolUnsupported);
        }
        if input.time.sampled_monotonic_ms() >= input.earliest_authority_deadline_monotonic_ms.get()
        {
            return Err(DispatchAuthorityViewBuildErrorV1::DeadlineReached);
        }
        Ok(Self {
            contract_version: input.contract_version,
            phase: input.phase,
            time: input.time,
            task_id: input.task_id,
            workload_id: input.workload_id,
            instance_epoch: input.instance_epoch,
            supervisor_epoch: input.supervisor_epoch,
            supervisor_generation: input.supervisor_generation,
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
            protocol_version: input.protocol_version,
            signer_key_id: input.signer_key_id,
            signer_generation: input.signer_generation,
            signer_profile_digest: input.signer_profile_digest,
            earliest_authority_deadline_monotonic_ms: input
                .earliest_authority_deadline_monotonic_ms,
        })
    }

    pub const fn phase(&self) -> DispatchAuthorityCapturePhaseV1 {
        self.phase
    }

    pub const fn time(&self) -> &DispatchTimeCaptureV1 {
        &self.time
    }

    pub fn signer_key_id(&self) -> &str {
        self.signer_key_id.as_str()
    }

    pub const fn signer_generation(&self) -> u64 {
        self.signer_generation.get()
    }

    pub const fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    pub(crate) fn grant_projection(&self) -> DispatchGrantAuthorityProjectionV1<'_> {
        DispatchGrantAuthorityProjectionV1 {
            boot_id: self.time.boot_identifier(),
            clock_generation: self.time.clock_generation_value(),
            issued_at_utc_ms: self.time.sampled_utc_value(),
            issued_at_monotonic_ms: self.time.sampled_monotonic_value(),
            task_id: &self.task_id,
            workload_id: &self.workload_id,
            instance_epoch: self.instance_epoch,
            supervisor_epoch: self.supervisor_epoch,
            supervisor_generation: self.supervisor_generation,
            trust_generation: self.trust_generation,
            verified_key_fingerprint: self.verified_key_fingerprint,
            workload_generation: self.workload_generation,
            workload_evidence_digest: self.workload_evidence_digest,
            lease_generation: self.lease_generation,
            lease_digest: self.lease_digest,
            lease_decision_digest: self.lease_decision_digest,
            authorization_generation: self.authorization_generation,
            authorization_evidence_digest: self.authorization_evidence_digest,
            policy_generation: self.policy_generation,
            policy_decision_generation: self.policy_decision_generation,
            policy_content_digest: self.policy_content_digest,
            policy_decision_digest: self.policy_decision_digest,
            catalogue_generation: self.catalogue_generation,
            catalogue_decision_generation: self.catalogue_decision_generation,
            catalogue_content_digest: self.catalogue_content_digest,
            catalogue_decision_digest: self.catalogue_decision_digest,
            capability_report_generation: self.capability_report_generation,
            capability_report_digest: self.capability_report_digest,
            host_driver_context_digest: self.host_driver_context_digest,
            capability_observed_at_utc_ms: self.capability_observed_at_utc_ms,
            capability_max_age_ms: self.capability_max_age_ms,
            adapter_capability_digest: self.adapter_capability_digest,
            replay_claim_id: self.replay_claim_id,
            replay_claimant_generation: self.replay_claimant_generation,
            replay_binding_digest: self.replay_binding_digest,
            budget_scope_id: &self.budget_scope_id,
            budget_scope_generation: self.budget_scope_generation,
            budget_scope_binding_digest: self.budget_scope_binding_digest,
            reservation_id: &self.reservation_id,
            reservation_generation: self.reservation_generation,
            reservation_binding_digest: self.reservation_binding_digest,
            reservation_vector_digest: self.reservation_vector_digest,
            recovery_reference_digest: self.recovery_reference_digest,
            recovery_mode: self.recovery_mode,
            recovery_profile_digest: self.recovery_profile_digest,
            recovery_binding_digest: self.recovery_binding_digest,
            recovery_receipt_digest: self.recovery_receipt_digest,
            destination_adapter_id: &self.destination_adapter_id,
            protocol_version: self.protocol_version,
            signer_key_id: &self.signer_key_id,
            signer_generation: self.signer_generation,
            signer_profile_digest: self.signer_profile_digest,
            earliest_authority_deadline_monotonic_ms: self.earliest_authority_deadline_monotonic_ms,
        }
    }

    /// Compares every guarded grant binding; phase and fresh sample values may differ.
    pub fn guarded_bindings_match(&self, final_view: &Self) -> bool {
        self.contract_version == final_view.contract_version
            && self.time.boot_id() == final_view.time.boot_id()
            && self.time.clock_generation() == final_view.time.clock_generation()
            && self.task_id == final_view.task_id
            && self.workload_id == final_view.workload_id
            && self.instance_epoch == final_view.instance_epoch
            && self.supervisor_epoch == final_view.supervisor_epoch
            && self.supervisor_generation == final_view.supervisor_generation
            && self.trust_generation == final_view.trust_generation
            && self.verified_key_fingerprint == final_view.verified_key_fingerprint
            && self.workload_generation == final_view.workload_generation
            && self.workload_evidence_digest == final_view.workload_evidence_digest
            && self.lease_generation == final_view.lease_generation
            && self.lease_digest == final_view.lease_digest
            && self.lease_decision_digest == final_view.lease_decision_digest
            && self.authorization_generation == final_view.authorization_generation
            && self.authorization_evidence_digest == final_view.authorization_evidence_digest
            && self.policy_generation == final_view.policy_generation
            && self.policy_decision_generation == final_view.policy_decision_generation
            && self.policy_content_digest == final_view.policy_content_digest
            && self.policy_decision_digest == final_view.policy_decision_digest
            && self.catalogue_generation == final_view.catalogue_generation
            && self.catalogue_decision_generation == final_view.catalogue_decision_generation
            && self.catalogue_content_digest == final_view.catalogue_content_digest
            && self.catalogue_decision_digest == final_view.catalogue_decision_digest
            && self.capability_report_generation == final_view.capability_report_generation
            && self.capability_report_digest == final_view.capability_report_digest
            && self.host_driver_context_digest == final_view.host_driver_context_digest
            && self.capability_observed_at_utc_ms == final_view.capability_observed_at_utc_ms
            && self.capability_max_age_ms == final_view.capability_max_age_ms
            && self.adapter_capability_digest == final_view.adapter_capability_digest
            && self.replay_claim_id == final_view.replay_claim_id
            && self.replay_claimant_generation == final_view.replay_claimant_generation
            && self.replay_binding_digest == final_view.replay_binding_digest
            && self.budget_scope_id == final_view.budget_scope_id
            && self.budget_scope_generation == final_view.budget_scope_generation
            && self.budget_scope_binding_digest == final_view.budget_scope_binding_digest
            && self.reservation_id == final_view.reservation_id
            && self.reservation_generation == final_view.reservation_generation
            && self.reservation_binding_digest == final_view.reservation_binding_digest
            && self.reservation_vector_digest == final_view.reservation_vector_digest
            && self.recovery_reference_digest == final_view.recovery_reference_digest
            && self.recovery_mode == final_view.recovery_mode
            && self.recovery_profile_digest == final_view.recovery_profile_digest
            && self.recovery_binding_digest == final_view.recovery_binding_digest
            && self.recovery_receipt_digest == final_view.recovery_receipt_digest
            && self.destination_adapter_id == final_view.destination_adapter_id
            && self.protocol_version == final_view.protocol_version
            && self.signer_key_id == final_view.signer_key_id
            && self.signer_generation == final_view.signer_generation
            && self.signer_profile_digest == final_view.signer_profile_digest
            && self.earliest_authority_deadline_monotonic_ms
                == final_view.earliest_authority_deadline_monotonic_ms
    }
}

impl fmt::Debug for DispatchAuthorityViewV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchAuthorityViewV1")
            .finish_non_exhaustive()
    }
}

pub enum DispatchAuthorityCaptureOutcomeV1 {
    Captured(Box<DispatchAuthorityViewV1>),
    Unavailable,
    Inconsistent,
    Revoked,
    Unsupported,
}

impl fmt::Debug for DispatchAuthorityCaptureOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Captured(_) => {
                formatter.write_str("DispatchAuthorityCaptureOutcomeV1::Captured(..)")
            }
            Self::Unavailable => {
                formatter.write_str("DispatchAuthorityCaptureOutcomeV1::Unavailable")
            }
            Self::Inconsistent => {
                formatter.write_str("DispatchAuthorityCaptureOutcomeV1::Inconsistent")
            }
            Self::Revoked => formatter.write_str("DispatchAuthorityCaptureOutcomeV1::Revoked"),
            Self::Unsupported => {
                formatter.write_str("DispatchAuthorityCaptureOutcomeV1::Unsupported")
            }
        }
    }
}

pub trait DispatchAuthorityProviderV1: Send + Sync {
    fn capture_authority_v1(
        &self,
        phase: DispatchAuthorityCapturePhaseV1,
        request: &DispatchLookupRequestV1,
        attempt: &DispatchAttemptIdV1,
    ) -> DispatchAuthorityCaptureOutcomeV1;
}

/// Private non-wire projection; it cannot itself authorize a commit or delivery.
pub(crate) struct ReadyDispatchContextV1 {
    request: DispatchLookupRequestV1,
    attempt: DispatchAttemptIdV1,
    authority: DispatchAuthorityViewV1,
    preliminary_context_digest: Sha256Digest,
    final_context_digest: Sha256Digest,
}

impl ReadyDispatchContextV1 {
    pub(crate) fn from_verified_reload(
        request: DispatchLookupRequestV1,
        attempt: DispatchAttemptIdV1,
        authority: DispatchAuthorityViewV1,
        preliminary_context_digest: Sha256Digest,
        final_context_digest: Sha256Digest,
    ) -> Self {
        Self {
            request,
            attempt,
            authority,
            preliminary_context_digest,
            final_context_digest,
        }
    }

    pub(crate) const fn attempt(&self) -> &DispatchAttemptIdV1 {
        &self.attempt
    }

    pub(crate) const fn final_context_digest(&self) -> Sha256Digest {
        self.final_context_digest
    }

    pub(crate) const fn preliminary_context_digest(&self) -> Sha256Digest {
        self.preliminary_context_digest
    }

    pub(crate) const fn request(&self) -> &DispatchLookupRequestV1 {
        &self.request
    }

    pub(crate) const fn authority(&self) -> &DispatchAuthorityViewV1 {
        &self.authority
    }

    pub(crate) fn grant_authority_projection(&self) -> DispatchGrantAuthorityProjectionV1<'_> {
        self.authority.grant_projection()
    }

    pub(crate) fn operation_id(&self) -> &str {
        self.request.operation_id()
    }
}

impl fmt::Debug for ReadyDispatchContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadyDispatchContextV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("test generation is valid")
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).expect("test identifier is valid")
    }

    pub(crate) fn view(
        phase: DispatchAuthorityCapturePhaseV1,
        clock_generation: u64,
        signer_generation: u64,
        lease_decision: u8,
        adapter_capability: u8,
    ) -> DispatchAuthorityViewV1 {
        let sample = match phase {
            DispatchAuthorityCapturePhaseV1::Preliminary => 100,
            DispatchAuthorityCapturePhaseV1::FinalGuarded => 125,
        };
        view_with_sample(
            phase,
            clock_generation,
            signer_generation,
            lease_decision,
            adapter_capability,
            sample,
        )
    }

    pub(crate) fn view_with_sample(
        phase: DispatchAuthorityCapturePhaseV1,
        clock_generation: u64,
        signer_generation: u64,
        lease_decision: u8,
        adapter_capability: u8,
        sample: u64,
    ) -> DispatchAuthorityViewV1 {
        DispatchAuthorityViewV1::try_new(DispatchAuthorityViewInputV1 {
            contract_version: DISPATCH_AUTHORITY_VIEW_VERSION_V1,
            phase,
            time: DispatchTimeCaptureV1::new(
                identifier("boot-v1"),
                generation(clock_generation),
                SafeU64::new(1_000_000 + sample).unwrap(),
                SafeU64::new(sample).unwrap(),
            ),
            task_id: identifier("task-v1"),
            workload_id: identifier("workload-v1"),
            instance_epoch: SafeU64::new(14).unwrap(),
            supervisor_epoch: SafeU64::new(15).unwrap(),
            supervisor_generation: generation(16),
            trust_generation: generation(17),
            verified_key_fingerprint: digest(1),
            workload_generation: generation(18),
            workload_evidence_digest: digest(2),
            lease_generation: generation(19),
            lease_digest: digest(3),
            lease_decision_digest: digest(lease_decision),
            authorization_generation: generation(20),
            authorization_evidence_digest: digest(5),
            policy_generation: generation(21),
            policy_decision_generation: generation(22),
            policy_content_digest: digest(6),
            policy_decision_digest: digest(7),
            catalogue_generation: generation(23),
            catalogue_decision_generation: generation(24),
            catalogue_content_digest: digest(8),
            catalogue_decision_digest: digest(9),
            capability_report_generation: generation(25),
            capability_report_digest: digest(10),
            host_driver_context_digest: digest(11),
            capability_observed_at_utc_ms: SafeU64::new(999_900).unwrap(),
            capability_max_age_ms: SafeU64::new(500).unwrap(),
            adapter_capability_digest: digest(adapter_capability),
            replay_claim_id: digest(13),
            replay_claimant_generation: generation(26),
            replay_binding_digest: digest(14),
            budget_scope_id: identifier("budget-v1"),
            budget_scope_generation: generation(27),
            budget_scope_binding_digest: digest(15),
            reservation_id: identifier("reservation-v1"),
            reservation_generation: generation(28),
            reservation_binding_digest: digest(16),
            reservation_vector_digest: digest(17),
            recovery_reference_digest: digest(18),
            recovery_mode: RecoveryModeV1::Compensation,
            recovery_profile_digest: digest(19),
            recovery_binding_digest: digest(20),
            recovery_receipt_digest: digest(21),
            destination_adapter_id: identifier("adapter-v1"),
            protocol_version: 1,
            signer_key_id: identifier("dispatch-key-v1"),
            signer_generation: generation(signer_generation),
            signer_profile_digest: digest(22),
            earliest_authority_deadline_monotonic_ms: generation(5_000),
        })
        .expect("test authority view is valid")
    }

    #[test]
    fn critical_named_guarded_bindings_participate_in_mutation_detection() {
        let preliminary = view(DispatchAuthorityCapturePhaseV1::Preliminary, 30, 31, 4, 12);
        let exact_final = view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 30, 31, 4, 12);
        assert!(preliminary.guarded_bindings_match(&exact_final));

        let signer_changed = view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 30, 32, 4, 12);
        assert!(!preliminary.guarded_bindings_match(&signer_changed));

        let lease_decision_changed = view(
            DispatchAuthorityCapturePhaseV1::FinalGuarded,
            30,
            31,
            0x44,
            12,
        );
        assert!(!preliminary.guarded_bindings_match(&lease_decision_changed));

        let adapter_capability_changed = view(
            DispatchAuthorityCapturePhaseV1::FinalGuarded,
            30,
            31,
            4,
            0x55,
        );
        assert!(!preliminary.guarded_bindings_match(&adapter_capability_changed));

        let clock_generation_changed =
            view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 33, 31, 4, 12);
        assert!(!preliminary.guarded_bindings_match(&clock_generation_changed));
    }
}
