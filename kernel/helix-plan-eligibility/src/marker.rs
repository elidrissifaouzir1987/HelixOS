use crate::{EligibilityDenialV1, ReplayClaimReceiptV1};
use helix_contracts::{AuthenticPlanEnvelopeV1, SafeU64, Sha256Digest};
use std::fmt;

pub(crate) struct EffectiveEligibilityBoundsInputV1 {
    pub(crate) evaluated_at_utc_unix_ms: SafeU64,
    pub(crate) evaluated_at_monotonic_ms: SafeU64,
    pub(crate) effective_expires_at_utc_unix_ms: SafeU64,
    pub(crate) capability_observed_at_unix_ms: SafeU64,
    pub(crate) capability_max_age_ms: SafeU64,
    pub(crate) effective_deadline_monotonic_ms: SafeU64,
}

impl fmt::Debug for EffectiveEligibilityBoundsInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectiveEligibilityBoundsInputV1")
            .finish_non_exhaustive()
    }
}

pub struct EffectiveEligibilityBoundsV1 {
    evaluated_at_utc_unix_ms: SafeU64,
    evaluated_at_monotonic_ms: SafeU64,
    effective_expires_at_utc_unix_ms: SafeU64,
    capability_observed_at_unix_ms: SafeU64,
    capability_max_age_ms: SafeU64,
    effective_deadline_monotonic_ms: SafeU64,
}

impl EffectiveEligibilityBoundsV1 {
    pub(crate) fn new(input: EffectiveEligibilityBoundsInputV1) -> Self {
        Self {
            evaluated_at_utc_unix_ms: input.evaluated_at_utc_unix_ms,
            evaluated_at_monotonic_ms: input.evaluated_at_monotonic_ms,
            effective_expires_at_utc_unix_ms: input.effective_expires_at_utc_unix_ms,
            capability_observed_at_unix_ms: input.capability_observed_at_unix_ms,
            capability_max_age_ms: input.capability_max_age_ms,
            effective_deadline_monotonic_ms: input.effective_deadline_monotonic_ms,
        }
    }

    pub const fn evaluated_at_utc_unix_ms(&self) -> u64 {
        self.evaluated_at_utc_unix_ms.get()
    }

    pub const fn evaluated_at_monotonic_ms(&self) -> u64 {
        self.evaluated_at_monotonic_ms.get()
    }

    pub const fn effective_expires_at_utc_unix_ms(&self) -> u64 {
        self.effective_expires_at_utc_unix_ms.get()
    }

    pub const fn capability_observed_at_unix_ms(&self) -> u64 {
        self.capability_observed_at_unix_ms.get()
    }

    pub const fn capability_max_age_ms(&self) -> u64 {
        self.capability_max_age_ms.get()
    }

    pub const fn effective_deadline_monotonic_ms(&self) -> u64 {
        self.effective_deadline_monotonic_ms.get()
    }
}

impl fmt::Debug for EffectiveEligibilityBoundsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectiveEligibilityBoundsV1")
            .finish_non_exhaustive()
    }
}

pub(crate) struct EligibilityBindingsInputV1 {
    pub(crate) capture_generation: SafeU64,
    pub(crate) clock_generation: SafeU64,
    pub(crate) plan_deadline_generation: SafeU64,
    pub(crate) supervisor_generation: SafeU64,
    pub(crate) instance_epoch: SafeU64,
    pub(crate) fencing_epoch: SafeU64,
    pub(crate) trust_generation: SafeU64,
    pub(crate) verified_key_fingerprint: Sha256Digest,
    pub(crate) workload_identity_generation: SafeU64,
    pub(crate) workload_evidence_digest: Sha256Digest,
    pub(crate) lease_generation: SafeU64,
    pub(crate) lease_digest: Sha256Digest,
    pub(crate) lease_decision_digest: Sha256Digest,
    pub(crate) authorization_generation: SafeU64,
    pub(crate) authorization_evidence_digest: Sha256Digest,
    pub(crate) policy_generation: SafeU64,
    pub(crate) policy_decision_generation: SafeU64,
    pub(crate) policy_content_digest: Sha256Digest,
    pub(crate) policy_decision_digest: Sha256Digest,
    pub(crate) catalogue_generation: SafeU64,
    pub(crate) catalogue_decision_generation: SafeU64,
    pub(crate) catalogue_content_digest: Sha256Digest,
    pub(crate) catalogue_decision_digest: Sha256Digest,
    pub(crate) capability_report_generation: SafeU64,
    pub(crate) capability_report_digest: Sha256Digest,
    pub(crate) host_driver_context_digest: Sha256Digest,
}

impl fmt::Debug for EligibilityBindingsInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EligibilityBindingsInputV1")
            .finish_non_exhaustive()
    }
}

pub struct EligibilityBindingsV1 {
    capture_generation: SafeU64,
    clock_generation: SafeU64,
    plan_deadline_generation: SafeU64,
    supervisor_generation: SafeU64,
    instance_epoch: SafeU64,
    fencing_epoch: SafeU64,
    trust_generation: SafeU64,
    verified_key_fingerprint: Sha256Digest,
    workload_identity_generation: SafeU64,
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
    replay_claim_id: Sha256Digest,
    replay_claimant_generation: SafeU64,
    replay_binding_digest: Sha256Digest,
}

impl EligibilityBindingsV1 {
    pub(crate) fn new(input: EligibilityBindingsInputV1, receipt: &ReplayClaimReceiptV1) -> Self {
        Self {
            capture_generation: input.capture_generation,
            clock_generation: input.clock_generation,
            plan_deadline_generation: input.plan_deadline_generation,
            supervisor_generation: input.supervisor_generation,
            instance_epoch: input.instance_epoch,
            fencing_epoch: input.fencing_epoch,
            trust_generation: input.trust_generation,
            verified_key_fingerprint: input.verified_key_fingerprint,
            workload_identity_generation: input.workload_identity_generation,
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
            replay_claim_id: receipt.claim_id(),
            replay_claimant_generation: receipt.claimant_generation_safe(),
            replay_binding_digest: receipt.binding_digest(),
        }
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
    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation.get()
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
    pub const fn workload_identity_generation(&self) -> u64 {
        self.workload_identity_generation.get()
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
    pub const fn replay_claim_id(&self) -> Sha256Digest {
        self.replay_claim_id
    }
    pub const fn replay_claimant_generation(&self) -> u64 {
        self.replay_claimant_generation.get()
    }
    pub const fn replay_binding_digest(&self) -> Sha256Digest {
        self.replay_binding_digest
    }
}

impl fmt::Debug for EligibilityBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EligibilityBindingsV1")
            .finish_non_exhaustive()
    }
}

#[must_use = "eligibility is a point-in-time prerequisite that must be consumed deliberately"]
/// Opaque proof that current eligibility and one new replay claim just succeeded.
///
/// This non-`Clone`, non-Serde marker owns the authentic plan and its evaluated bounds.
/// It is not effect authority and must be revalidated by a future coordinator before
/// any separately specified prepare/grant transition.
pub struct EligiblePlanV1 {
    authentic: AuthenticPlanEnvelopeV1,
    bounds: EffectiveEligibilityBoundsV1,
    bindings: EligibilityBindingsV1,
    replay_claim: ReplayClaimReceiptV1,
}

impl EligiblePlanV1 {
    pub(crate) fn new(
        authentic: AuthenticPlanEnvelopeV1,
        bounds: EffectiveEligibilityBoundsV1,
        bindings: EligibilityBindingsInputV1,
        replay_claim: ReplayClaimReceiptV1,
    ) -> Self {
        let bindings = EligibilityBindingsV1::new(bindings, &replay_claim);
        Self {
            authentic,
            bounds,
            bindings,
            replay_claim,
        }
    }

    pub const fn authentic(&self) -> &AuthenticPlanEnvelopeV1 {
        &self.authentic
    }
    pub const fn bounds(&self) -> &EffectiveEligibilityBoundsV1 {
        &self.bounds
    }
    pub const fn bindings(&self) -> &EligibilityBindingsV1 {
        &self.bindings
    }
    pub const fn replay_claim(&self) -> &ReplayClaimReceiptV1 {
        &self.replay_claim
    }
}

impl fmt::Debug for EligiblePlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EligiblePlanV1")
            .finish_non_exhaustive()
    }
}

#[must_use = "the denial and authentic plan remain sovereign coordinator state"]
/// A typed denial that preserves caller custody of the authentic plan.
pub struct EligibilityFailureV1 {
    authentic: AuthenticPlanEnvelopeV1,
    denial: EligibilityDenialV1,
}

impl EligibilityFailureV1 {
    pub(crate) const fn new(
        authentic: AuthenticPlanEnvelopeV1,
        denial: EligibilityDenialV1,
    ) -> Self {
        Self { authentic, denial }
    }

    pub const fn denial(&self) -> EligibilityDenialV1 {
        self.denial
    }

    pub fn into_authentic(self) -> AuthenticPlanEnvelopeV1 {
        self.authentic
    }
}

impl fmt::Debug for EligibilityFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EligibilityFailureV1")
            .field("denial_code", &self.denial.code())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_contracts::{
        decode_and_verify_plan, ContractError, Ed25519KeyResolver, Result as ContractResult,
    };

    const FIXTURE_ENVELOPE: &[u8] =
        include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.envelope.jcs");
    const FIXTURE_PUBLIC_KEY: [u8; 32] = [
        0xEA, 0x4A, 0x6C, 0x63, 0xE2, 0x9C, 0x52, 0x0A, 0xBE, 0xF5, 0x50, 0x7B, 0x13, 0x2E, 0xC5,
        0xF9, 0x95, 0x47, 0x76, 0xAE, 0xBE, 0xBE, 0x7B, 0x92, 0x42, 0x1E, 0xEA, 0x69, 0x14, 0x46,
        0xD2, 0x2C,
    ];

    struct FixtureResolver;

    impl Ed25519KeyResolver for FixtureResolver {
        fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
            if key_id == "core-signing-key:fixture-1" {
                Ok(FIXTURE_PUBLIC_KEY)
            } else {
                Err(ContractError::UnknownKey)
            }
        }
    }

    #[test]
    fn marker_debug_surfaces_never_render_owned_plan_or_binding_values() {
        let eligible_authentic = authentic_fixture();
        let receipt = ReplayClaimReceiptV1::try_new(digest(b"claim"), 2, digest(b"binding"))
            .expect("fixture receipt");
        let eligible = EligiblePlanV1::new(
            eligible_authentic,
            EffectiveEligibilityBoundsV1::new(EffectiveEligibilityBoundsInputV1 {
                evaluated_at_utc_unix_ms: safe(10),
                evaluated_at_monotonic_ms: safe(20),
                effective_expires_at_utc_unix_ms: safe(30),
                capability_observed_at_unix_ms: safe(5),
                capability_max_age_ms: safe(25),
                effective_deadline_monotonic_ms: safe(40),
            }),
            bindings_fixture(),
            receipt,
        );
        let failure =
            EligibilityFailureV1::new(authentic_fixture(), EligibilityDenialV1::ReplayAmbiguous);

        let rendered = format!("{eligible:?}\n{failure:?}");
        assert!(rendered.contains("EligiblePlanV1"));
        assert!(rendered.contains("REPLAY_AMBIGUOUS"));
        for sentinel in [
            "core-signing-key:fixture-1",
            "task:fixture-1",
            "workload:agent-vm-1",
            "boot:fixture-1",
            "vault-main",
            "Decision.md",
        ] {
            assert!(!rendered.contains(sentinel), "marker leaked {sentinel}");
        }
    }

    fn authentic_fixture() -> AuthenticPlanEnvelopeV1 {
        decode_and_verify_plan(FIXTURE_ENVELOPE, &FixtureResolver)
            .expect("committed fixture must verify")
    }

    fn bindings_fixture() -> EligibilityBindingsInputV1 {
        EligibilityBindingsInputV1 {
            capture_generation: safe(1),
            clock_generation: safe(2),
            plan_deadline_generation: safe(3),
            supervisor_generation: safe(4),
            instance_epoch: safe(5),
            fencing_epoch: safe(6),
            trust_generation: safe(7),
            verified_key_fingerprint: digest(b"key"),
            workload_identity_generation: safe(8),
            workload_evidence_digest: digest(b"workload"),
            lease_generation: safe(9),
            lease_digest: digest(b"lease"),
            lease_decision_digest: digest(b"lease-decision"),
            authorization_generation: safe(10),
            authorization_evidence_digest: digest(b"authorization"),
            policy_generation: safe(11),
            policy_decision_generation: safe(12),
            policy_content_digest: digest(b"policy"),
            policy_decision_digest: digest(b"policy-decision"),
            catalogue_generation: safe(13),
            catalogue_decision_generation: safe(14),
            catalogue_content_digest: digest(b"catalogue"),
            catalogue_decision_digest: digest(b"catalogue-decision"),
            capability_report_generation: safe(15),
            capability_report_digest: digest(b"capability"),
            host_driver_context_digest: digest(b"context"),
        }
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("test fixture uses safe integers")
    }

    fn digest(value: &[u8]) -> Sha256Digest {
        Sha256Digest::digest(value)
    }
}
