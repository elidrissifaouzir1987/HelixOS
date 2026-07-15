use helix_dispatch_contracts::{Generation, Identifier, RecoveryModeV1, SafeU64, Sha256Digest};
use helix_plan_dispatch::{
    DispatchAuthorityCapturePhaseV1, DispatchAuthorityViewInputV1, DispatchAuthorityViewV1,
    DispatchTimeCaptureV1, DISPATCH_AUTHORITY_VIEW_VERSION_V1,
};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug)]
enum GuardedMutation {
    ClockGeneration,
    InstanceEpoch,
    SupervisorEpoch,
    SupervisorGeneration,
    TrustGeneration,
    WorkloadGeneration,
    LeaseGeneration,
    AuthorizationGeneration,
    PolicyGeneration,
    PolicyDecisionGeneration,
    CatalogueGeneration,
    CatalogueDecisionGeneration,
    CapabilityReportGeneration,
    ReplayClaimantGeneration,
    BudgetScopeGeneration,
    ReservationGeneration,
    SignerGeneration,
    VerifiedKeyFingerprint,
    WorkloadEvidenceDigest,
    LeaseDigest,
    LeaseDecisionDigest,
    AuthorizationEvidenceDigest,
    PolicyContentDigest,
    PolicyDecisionDigest,
    CatalogueContentDigest,
    CatalogueDecisionDigest,
    CapabilityReportDigest,
    HostDriverContextDigest,
    AdapterCapabilityDigest,
    ReplayClaimId,
    ReplayBindingDigest,
    BudgetScopeBindingDigest,
    ReservationBindingDigest,
    ReservationVectorDigest,
    RecoveryReferenceDigest,
    RecoveryProfileDigest,
    RecoveryBindingDigest,
    RecoveryReceiptDigest,
    EarliestAuthorityDeadline,
    DestinationAdapterId,
    SignerKeyId,
    SignerProfileDigest,
}

const GUARDED_MUTATIONS: &[GuardedMutation] = &[
    GuardedMutation::ClockGeneration,
    GuardedMutation::InstanceEpoch,
    GuardedMutation::SupervisorEpoch,
    GuardedMutation::SupervisorGeneration,
    GuardedMutation::TrustGeneration,
    GuardedMutation::WorkloadGeneration,
    GuardedMutation::LeaseGeneration,
    GuardedMutation::AuthorizationGeneration,
    GuardedMutation::PolicyGeneration,
    GuardedMutation::PolicyDecisionGeneration,
    GuardedMutation::CatalogueGeneration,
    GuardedMutation::CatalogueDecisionGeneration,
    GuardedMutation::CapabilityReportGeneration,
    GuardedMutation::ReplayClaimantGeneration,
    GuardedMutation::BudgetScopeGeneration,
    GuardedMutation::ReservationGeneration,
    GuardedMutation::SignerGeneration,
    GuardedMutation::VerifiedKeyFingerprint,
    GuardedMutation::WorkloadEvidenceDigest,
    GuardedMutation::LeaseDigest,
    GuardedMutation::LeaseDecisionDigest,
    GuardedMutation::AuthorizationEvidenceDigest,
    GuardedMutation::PolicyContentDigest,
    GuardedMutation::PolicyDecisionDigest,
    GuardedMutation::CatalogueContentDigest,
    GuardedMutation::CatalogueDecisionDigest,
    GuardedMutation::CapabilityReportDigest,
    GuardedMutation::HostDriverContextDigest,
    GuardedMutation::AdapterCapabilityDigest,
    GuardedMutation::ReplayClaimId,
    GuardedMutation::ReplayBindingDigest,
    GuardedMutation::BudgetScopeBindingDigest,
    GuardedMutation::ReservationBindingDigest,
    GuardedMutation::ReservationVectorDigest,
    GuardedMutation::RecoveryReferenceDigest,
    GuardedMutation::RecoveryProfileDigest,
    GuardedMutation::RecoveryBindingDigest,
    GuardedMutation::RecoveryReceiptDigest,
    GuardedMutation::EarliestAuthorityDeadline,
    GuardedMutation::DestinationAdapterId,
    GuardedMutation::SignerKeyId,
    GuardedMutation::SignerProfileDigest,
];

fn generation(value: u64) -> Generation {
    Generation::new(value).expect("test generation is within the safe range")
}

fn safe(value: u64) -> SafeU64 {
    SafeU64::new(value).expect("test integer is within the safe range")
}

fn identifier(value: &str) -> Identifier {
    Identifier::new(value).expect("test identifier is valid")
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn authority_view(
    phase: DispatchAuthorityCapturePhaseV1,
    mutation: Option<GuardedMutation>,
) -> DispatchAuthorityViewV1 {
    let sample = match phase {
        DispatchAuthorityCapturePhaseV1::Preliminary => 100,
        DispatchAuthorityCapturePhaseV1::FinalGuarded => 125,
    };
    let mut input = DispatchAuthorityViewInputV1 {
        contract_version: DISPATCH_AUTHORITY_VIEW_VERSION_V1,
        phase,
        time: DispatchTimeCaptureV1::new(
            identifier("boot-v1"),
            generation(30),
            safe(1_000_000 + sample),
            safe(sample),
        ),
        task_id: identifier("task-v1"),
        workload_id: identifier("workload-v1"),
        instance_epoch: safe(14),
        supervisor_epoch: safe(15),
        supervisor_generation: generation(16),
        trust_generation: generation(17),
        verified_key_fingerprint: digest(1),
        workload_generation: generation(18),
        workload_evidence_digest: digest(2),
        lease_generation: generation(19),
        lease_digest: digest(3),
        lease_decision_digest: digest(4),
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
        capability_observed_at_utc_ms: safe(999_900),
        capability_max_age_ms: safe(500),
        adapter_capability_digest: digest(12),
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
        signer_generation: generation(31),
        signer_profile_digest: digest(22),
        earliest_authority_deadline_monotonic_ms: generation(5_000),
    };

    if let Some(mutation) = mutation {
        match mutation {
            GuardedMutation::ClockGeneration => {
                input.time = DispatchTimeCaptureV1::new(
                    identifier("boot-v1"),
                    generation(130),
                    safe(1_000_000 + sample),
                    safe(sample),
                );
            }
            GuardedMutation::InstanceEpoch => input.instance_epoch = safe(114),
            GuardedMutation::SupervisorEpoch => input.supervisor_epoch = safe(115),
            GuardedMutation::SupervisorGeneration => {
                input.supervisor_generation = generation(116);
            }
            GuardedMutation::TrustGeneration => input.trust_generation = generation(117),
            GuardedMutation::WorkloadGeneration => input.workload_generation = generation(118),
            GuardedMutation::LeaseGeneration => input.lease_generation = generation(119),
            GuardedMutation::AuthorizationGeneration => {
                input.authorization_generation = generation(120);
            }
            GuardedMutation::PolicyGeneration => input.policy_generation = generation(121),
            GuardedMutation::PolicyDecisionGeneration => {
                input.policy_decision_generation = generation(122);
            }
            GuardedMutation::CatalogueGeneration => input.catalogue_generation = generation(123),
            GuardedMutation::CatalogueDecisionGeneration => {
                input.catalogue_decision_generation = generation(124);
            }
            GuardedMutation::CapabilityReportGeneration => {
                input.capability_report_generation = generation(125);
            }
            GuardedMutation::ReplayClaimantGeneration => {
                input.replay_claimant_generation = generation(126);
            }
            GuardedMutation::BudgetScopeGeneration => {
                input.budget_scope_generation = generation(127);
            }
            GuardedMutation::ReservationGeneration => {
                input.reservation_generation = generation(128);
            }
            GuardedMutation::SignerGeneration => input.signer_generation = generation(131),
            GuardedMutation::VerifiedKeyFingerprint => {
                input.verified_key_fingerprint = digest(101);
            }
            GuardedMutation::WorkloadEvidenceDigest => {
                input.workload_evidence_digest = digest(102);
            }
            GuardedMutation::LeaseDigest => input.lease_digest = digest(103),
            GuardedMutation::LeaseDecisionDigest => input.lease_decision_digest = digest(104),
            GuardedMutation::AuthorizationEvidenceDigest => {
                input.authorization_evidence_digest = digest(105);
            }
            GuardedMutation::PolicyContentDigest => input.policy_content_digest = digest(106),
            GuardedMutation::PolicyDecisionDigest => input.policy_decision_digest = digest(107),
            GuardedMutation::CatalogueContentDigest => {
                input.catalogue_content_digest = digest(108);
            }
            GuardedMutation::CatalogueDecisionDigest => {
                input.catalogue_decision_digest = digest(109);
            }
            GuardedMutation::CapabilityReportDigest => {
                input.capability_report_digest = digest(110);
            }
            GuardedMutation::HostDriverContextDigest => {
                input.host_driver_context_digest = digest(111);
            }
            GuardedMutation::AdapterCapabilityDigest => {
                input.adapter_capability_digest = digest(112);
            }
            GuardedMutation::ReplayClaimId => input.replay_claim_id = digest(113),
            GuardedMutation::ReplayBindingDigest => input.replay_binding_digest = digest(114),
            GuardedMutation::BudgetScopeBindingDigest => {
                input.budget_scope_binding_digest = digest(115);
            }
            GuardedMutation::ReservationBindingDigest => {
                input.reservation_binding_digest = digest(116);
            }
            GuardedMutation::ReservationVectorDigest => {
                input.reservation_vector_digest = digest(117);
            }
            GuardedMutation::RecoveryReferenceDigest => {
                input.recovery_reference_digest = digest(118);
            }
            GuardedMutation::RecoveryProfileDigest => {
                input.recovery_profile_digest = digest(119);
            }
            GuardedMutation::RecoveryBindingDigest => {
                input.recovery_binding_digest = digest(120);
            }
            GuardedMutation::RecoveryReceiptDigest => {
                input.recovery_receipt_digest = digest(121);
            }
            GuardedMutation::EarliestAuthorityDeadline => {
                input.earliest_authority_deadline_monotonic_ms = generation(4_999);
            }
            GuardedMutation::DestinationAdapterId => {
                input.destination_adapter_id = identifier("adapter-v2");
            }
            GuardedMutation::SignerKeyId => {
                input.signer_key_id = identifier("dispatch-key-v2");
            }
            GuardedMutation::SignerProfileDigest => input.signer_profile_digest = digest(122),
        }
    }

    DispatchAuthorityViewV1::try_new(input).expect("mutated authority remains structurally valid")
}

#[test]
fn every_listed_generation_digest_epoch_deadline_destination_and_signer_mutation_is_detected() {
    let preliminary = authority_view(DispatchAuthorityCapturePhaseV1::Preliminary, None);
    let unchanged_final = authority_view(DispatchAuthorityCapturePhaseV1::FinalGuarded, None);
    assert!(
        preliminary.guarded_bindings_match(&unchanged_final),
        "capture phase and fresh trusted time samples are not guarded-binding mutations"
    );

    for mutation in GUARDED_MUTATIONS {
        let final_view = authority_view(
            DispatchAuthorityCapturePhaseV1::FinalGuarded,
            Some(*mutation),
        );
        assert!(
            !preliminary.guarded_bindings_match(&final_view),
            "single-field mutation was accepted: {mutation:?}"
        );
    }
}

#[test]
fn t029_must_own_final_comparison_and_context_digesting() {
    // This source contract deliberately avoids importing a not-yet-existing API. Once T029
    // lands, direct coordinator-facing behavior tests should be added beside this ownership
    // check for the closed mismatch result and stable final-context digest.
    let compare_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/compare.rs");
    let source = fs::read_to_string(&compare_path).unwrap_or_else(|error| {
        panic!(
            "T029 RED: {} must implement preliminary/final authority comparison and context digesting: {error}",
            compare_path.display()
        )
    });
    let lib_source =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
            .expect("the crate root must remain readable");

    assert!(
        lib_source.contains("mod compare;"),
        "T029 compare.rs must be compiled into the crate rather than existing as dead source"
    );
    assert!(
        source.contains("guarded_bindings_match"),
        "T029 compare.rs must delegate the exhaustive single-field comparison to the typed authority view"
    );
    assert!(
        source.contains("final_context_digest"),
        "T029 compare.rs must produce the final context digest retained by the ready context"
    );
    assert!(
        source.contains("Sha256Digest") && source.contains("digest"),
        "T029 compare.rs must use the reviewed SHA-256 digest type rather than an ad-hoc value"
    );
}
