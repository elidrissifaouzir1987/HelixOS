mod common;

use common::{fixed_signer, sample_input, TestResolver, TestSigner, ISSUED_AT_MS};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, Nonce128, RequestSourceKindV1, RiskLevelV1, Sha256Digest,
};

const FIXTURE_ENVELOPE: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.envelope.jcs");

fn authentic_fixture() -> (helix_contracts::AuthenticPlanEnvelopeV1, common::TestSigner) {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).expect("fixture plan signs");
    let wire = signed
        .to_canonical_json()
        .expect("fixture plan canonicalizes");
    let authentic = decode_and_verify_plan(&wire, &resolver).expect("fixture plan verifies");
    (authentic, signer)
}

#[test]
fn authentic_marker_retains_the_exact_verified_key_fingerprint() {
    let (authentic, signer) = authentic_fixture();
    let claims = authentic.eligibility_claims();

    assert_eq!(
        claims.verified_key_fingerprint(),
        Sha256Digest::digest(&signer.verifying_key_bytes())
    );
    assert_ne!(
        claims.verified_key_fingerprint(),
        Sha256Digest::digest(claims.key_id().as_bytes()),
        "fingerprint must cover resolved key bytes, not the signed key identifier"
    );
}

#[test]
fn rotation_to_a_new_immutable_key_id_produces_new_verification_evidence() {
    let old_signer = TestSigner::new("core-signing-key:rotation-1", [0x21; 32]);
    let new_signer = TestSigner::new("core-signing-key:rotation-2", [0x22; 32]);

    let old_signed = sign_plan_v1(sample_input(), &old_signer).expect("old plan signs");
    let new_signed = sign_plan_v1(sample_input(), &new_signer).expect("new plan signs");
    let old_authentic = decode_and_verify_plan(
        &old_signed.to_canonical_json().unwrap(),
        &TestResolver::for_signer(&old_signer),
    )
    .expect("old plan verifies");
    let new_authentic = decode_and_verify_plan(
        &new_signed.to_canonical_json().unwrap(),
        &TestResolver::for_signer(&new_signer),
    )
    .expect("new plan verifies");

    assert_ne!(
        old_authentic.eligibility_claims().key_id(),
        new_authentic.eligibility_claims().key_id()
    );
    assert_ne!(
        old_authentic
            .eligibility_claims()
            .verified_key_fingerprint(),
        new_authentic
            .eligibility_claims()
            .verified_key_fingerprint()
    );
}

#[test]
fn eligibility_projection_borrows_every_required_protected_binding() {
    let (authentic, signer) = authentic_fixture();
    let claims = authentic.eligibility_claims();

    assert_eq!(claims.plan_id(), authentic.plan_id());
    assert_eq!(claims.schema(), "helixos.plan-envelope/1");
    assert_eq!(claims.key_id(), "core-signing-key:fixture-1");
    assert_eq!(
        claims.verified_key_fingerprint(),
        Sha256Digest::digest(&signer.verifying_key_bytes())
    );
    assert_eq!(
        claims.operation_id(),
        "operation:00000000-0000-4000-8000-000000000001"
    );
    assert_eq!(claims.task_id(), "task:fixture-1");
    assert_eq!(claims.workload_id(), "workload:agent-vm-1");
    assert_eq!(claims.boot_id(), "boot:fixture-1");
    assert_eq!(
        claims.task_lease_digest(),
        Sha256Digest::digest(b"fixture task lease")
    );
    assert_eq!(
        claims.request_source_kind(),
        RequestSourceKindV1::HumanRequestGrant
    );
    assert_eq!(
        claims.request_source_digest(),
        Sha256Digest::digest(b"fixture human request grant")
    );
    assert_eq!(claims.catalog_version(), "catalog:1");
    assert_eq!(claims.policy_version(), "policy:1");
    assert_eq!(claims.risk_level(), RiskLevelV1::L1);
    assert_eq!(claims.intent_kind(), "host.file.patch");
    assert_eq!(claims.target().root_id(), "vault-main");
    assert_eq!(
        claims.target().components(),
        &["Projects", "HelixOS", "Decision.md"]
    );
    assert_eq!(
        claims.capability_report_digest(),
        Sha256Digest::digest(b"fixture capability report")
    );
    assert_eq!(
        claims.capability_observed_at_unix_ms(),
        ISSUED_AT_MS - 1_000
    );
    assert_eq!(
        claims
            .required_capabilities()
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>(),
        vec!["filesystem.atomic-replace", "filesystem.verify-by-handle"]
    );

    let budget = claims.budget();
    assert_eq!(budget.reservation_id(), "budget:fixture-1");
    assert_eq!(budget.currency_code(), "EUR");
    assert_eq!(budget.price_table_id(), "price-table:fixture-1");
    assert_eq!(budget.max_cost_micro_units(), 0);
    assert_eq!(budget.action_limit(), 1);
    assert_eq!(budget.egress_bytes_limit(), 0);

    assert_eq!(claims.issued_at_unix_ms(), ISSUED_AT_MS);
    assert_eq!(claims.expires_at_unix_ms(), ISSUED_AT_MS + 120_000);
    assert_eq!(claims.nonce().as_bytes(), &[0x11; 16]);
    assert_eq!(claims.instance_epoch(), 1);
    assert_eq!(claims.fencing_epoch(), 9);
}

#[test]
fn claims_and_budget_debug_are_redacted() {
    let (authentic, _) = authentic_fixture();
    let claims = authentic.eligibility_claims();
    let claims_debug = format!("{claims:?}");
    let budget_debug = format!("{:?}", claims.budget());

    assert!(claims_debug.contains("PlanEligibilityClaimsV1"));
    assert!(claims_debug.contains("required_capability_count"));
    assert!(budget_debug.contains("PlanEligibilityBudgetClaimsV1"));
    for sentinel in [
        "operation:00000000-0000-4000-8000-000000000001",
        "task:fixture-1",
        "workload:agent-vm-1",
        "boot:fixture-1",
        "core-signing-key:fixture-1",
        "vault-main",
        "Decision.md",
        "filesystem.atomic-replace",
        "budget:fixture-1",
        "price-table:fixture-1",
        "11111111111111111111111111111111",
    ] {
        assert!(!claims_debug.contains(sentinel), "claims leaked {sentinel}");
        assert!(!budget_debug.contains(sentinel), "budget leaked {sentinel}");
    }
}

#[test]
fn verification_evidence_does_not_change_feature_one_wire() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let authentic =
        decode_and_verify_plan(FIXTURE_ENVELOPE, &resolver).expect("golden fixture verifies");

    assert_eq!(
        authentic
            .clone()
            .into_signed()
            .to_canonical_json()
            .expect("signed envelope remains canonical"),
        FIXTURE_ENVELOPE
    );
    assert_eq!(
        authentic.eligibility_claims().plan_id(),
        Sha256Digest::digest(
            authentic
                .protected()
                .canonical_bytes()
                .expect("protected plan canonicalizes")
                .as_slice()
        )
    );
}

#[test]
fn nonce_byte_view_is_fixed_and_non_allocating() {
    let nonce = Nonce128::from_bytes([0xA5; 16]);
    assert_eq!(nonce.as_bytes(), &[0xA5; 16]);
}
