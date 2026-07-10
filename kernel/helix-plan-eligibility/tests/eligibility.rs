mod common;

use common::*;
use helix_contracts::Sha256Digest;
use helix_plan_eligibility::{
    EligibilityDenialV1, MonotonicClockViewV1, PlanDeadlineViewV1, SignerTrustViewV1,
    SupervisorAdmissionStateV1, SupervisorViewV1, WallClockViewV1,
};

#[test]
fn coherent_context_claims_once_last_and_carries_exact_marker_metadata() {
    let fixture = coherent_fixture();
    let plan_id = fixture.plan.plan_id();
    let fingerprint = fixture.plan.eligibility_claims().verified_key_fingerprint();
    let claimant = ClaimantProbe::default();

    let eligible = fixture
        .evaluate(&claimant)
        .expect("coherent fixture must become eligible");

    assert_eq!(claimant.calls(), 1);
    assert_eq!(
        claimant.observed_claim_deadline_monotonic_ms(),
        Some(PLAN_DEADLINE_MS)
    );
    assert_eq!(eligible.authentic().plan_id(), plan_id);
    let bounds = eligible.bounds();
    assert_eq!(bounds.evaluated_at_utc_unix_ms(), NOW_UTC_MS);
    assert_eq!(bounds.evaluated_at_monotonic_ms(), NOW_MONOTONIC_MS);
    assert_eq!(bounds.effective_expires_at_utc_unix_ms(), EXPIRES_AT_MS);
    assert_eq!(
        bounds.capability_observed_at_unix_ms(),
        ISSUED_AT_MS - 1_000
    );
    assert_eq!(bounds.capability_max_age_ms(), CAPABILITY_MAX_AGE_MS);
    assert_eq!(bounds.effective_deadline_monotonic_ms(), PLAN_DEADLINE_MS);

    let bindings = eligible.bindings();
    assert_eq!(bindings.capture_generation(), CAPTURE_GENERATION);
    assert_eq!(bindings.clock_generation(), CLOCK_GENERATION);
    assert_eq!(
        bindings.plan_deadline_generation(),
        PLAN_DEADLINE_GENERATION
    );
    assert_eq!(bindings.supervisor_generation(), SUPERVISOR_GENERATION);
    assert_eq!(bindings.instance_epoch(), INSTANCE_EPOCH);
    assert_eq!(bindings.fencing_epoch(), FENCING_EPOCH);
    assert_eq!(bindings.trust_generation(), TRUST_GENERATION);
    assert_eq!(bindings.verified_key_fingerprint(), fingerprint);
    assert_eq!(bindings.workload_identity_generation(), WORKLOAD_GENERATION);
    assert_eq!(
        bindings.workload_evidence_digest(),
        digest(b"fixture workload evidence")
    );
    assert_eq!(bindings.lease_generation(), LEASE_GENERATION);
    assert_eq!(bindings.lease_digest(), digest(b"fixture task lease"));
    assert_eq!(
        bindings.lease_decision_digest(),
        digest(b"fixture lease decision")
    );
    assert_eq!(
        bindings.authorization_generation(),
        AUTHORIZATION_GENERATION
    );
    assert_eq!(bindings.policy_generation(), POLICY_GENERATION);
    assert_eq!(
        bindings.policy_decision_generation(),
        POLICY_DECISION_GENERATION
    );
    assert_eq!(bindings.catalogue_generation(), CATALOGUE_GENERATION);
    assert_eq!(
        bindings.catalogue_decision_generation(),
        CATALOGUE_DECISION_GENERATION
    );
    assert_eq!(
        bindings.capability_report_generation(),
        CAPABILITY_REPORT_GENERATION
    );
    assert_eq!(
        bindings.capability_report_digest(),
        digest(b"fixture capability report")
    );
    assert_eq!(bindings.replay_claimant_generation(), CLAIMANT_GENERATION);
    assert_eq!(bindings.replay_claim_id(), digest(b"fixture replay claim"));
    assert_eq!(
        Some(bindings.replay_binding_digest()),
        claimant.observed_binding_digest()
    );
    assert_eq!(
        eligible.replay_claim().binding_digest(),
        bindings.replay_binding_digest()
    );
}

#[test]
fn multiple_faults_return_the_normative_first_denial_before_claiming() {
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.bound_plan_id = Sha256Digest::digest(b"another plan");
            input.supervisor = SupervisorViewV1::Unavailable;
        }),
        EligibilityDenialV1::ContextPlanMismatch,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.supervisor = SupervisorViewV1::Unavailable;
            input.time = time_view(
                WallClockViewV1::Unavailable,
                MonotonicClockViewV1::Unavailable,
            );
        }),
        EligibilityDenialV1::SupervisorUnavailable,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Paused,
                BOOT_ID,
                INSTANCE_EPOCH,
                FENCING_EPOCH,
            );
            input.time = time_view(
                WallClockViewV1::Unavailable,
                MonotonicClockViewV1::Unavailable,
            );
        }),
        EligibilityDenialV1::SupervisorNotOpen,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.time = healthy_time(ISSUED_AT_MS - 1, OTHER_BOOT_ID, NOW_MONOTONIC_MS);
        }),
        EligibilityDenialV1::PlanNotYetValid,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.time = time_view(
                WallClockViewV1::healthy(NOW_UTC_MS).expect("safe wall time"),
                MonotonicClockViewV1::Unavailable,
            );
            input.plan_deadline = PlanDeadlineViewV1::Inconsistent;
        }),
        EligibilityDenialV1::MonotonicClockUnavailable,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.plan_deadline = PlanDeadlineViewV1::Inconsistent;
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Open,
                BOOT_ID,
                INSTANCE_EPOCH + 1,
                FENCING_EPOCH + 1,
            );
        }),
        EligibilityDenialV1::PlanDeadlineInconsistent,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Open,
                BOOT_ID,
                INSTANCE_EPOCH + 1,
                FENCING_EPOCH + 1,
            );
            input.signer = SignerTrustViewV1::Unavailable;
        }),
        EligibilityDenialV1::InstanceEpochMismatch,
    );
}
