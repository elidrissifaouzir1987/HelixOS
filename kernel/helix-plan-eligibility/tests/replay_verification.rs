mod common;

use common::{
    coherent_fixture, digest, ClaimantProbe, CLAIMANT_GENERATION, INSTANCE_EPOCH, OPERATION_ID,
    PLAN_DEADLINE_MS,
};
use helix_contracts::Nonce128;
use helix_plan_eligibility::{
    ReplayClaimVerificationV1, ReplayClaimVerificationViewV1, ReplayClaimVerifierV1,
};

const MARKER_SOURCE: &str = include_str!("../src/marker.rs");
const REPLAY_SOURCE: &str = include_str!("../src/replay.rs");

struct ExactVerifier;

impl ReplayClaimVerifierV1 for ExactVerifier {
    fn verify_exact_claim(
        &self,
        view: &ReplayClaimVerificationViewV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> ReplayClaimVerificationV1 {
        assert_eq!(deadline_monotonic_ms, PLAN_DEADLINE_MS);
        assert_eq!(view.instance_epoch(), INSTANCE_EPOCH);
        assert_eq!(view.nonce(), Nonce128::from_bytes([0x11; 16]));
        assert_eq!(
            view.nonce_key(),
            (INSTANCE_EPOCH, Nonce128::from_bytes([0x11; 16]))
        );
        assert_eq!(view.operation_id(), OPERATION_ID);
        assert_eq!(view.claim_id(), digest(b"fixture replay claim"));
        assert_eq!(view.claimant_generation(), CLAIMANT_GENERATION);
        ReplayClaimVerificationV1::Exact
    }
}

#[test]
fn eligible_plan_builds_one_opaque_exact_replay_view() {
    let claimant = ClaimantProbe::default();
    let eligible = coherent_fixture()
        .evaluate(&claimant)
        .expect("coherent fixture is eligible");
    let view = eligible.replay_verification_view();

    assert_eq!(
        view.binding_digest(),
        claimant.observed_binding_digest().unwrap()
    );
    assert_eq!(format!("{view:?}"), "ReplayClaimVerificationViewV1 { .. }");

    let verifier = ExactVerifier;
    assert_eq!(
        verifier.verify_exact_claim(&view, PLAN_DEADLINE_MS),
        ReplayClaimVerificationV1::Exact
    );
}

#[test]
fn verification_contract_has_exactly_five_closed_classifications() {
    let cases = [
        ReplayClaimVerificationV1::Exact,
        ReplayClaimVerificationV1::Missing,
        ReplayClaimVerificationV1::Conflict,
        ReplayClaimVerificationV1::Unavailable,
        ReplayClaimVerificationV1::Unhealthy,
    ];
    let names = cases.iter().map(classification_name).collect::<Vec<_>>();
    assert_eq!(
        names,
        ["EXACT", "MISSING", "CONFLICT", "UNAVAILABLE", "UNHEALTHY"]
    );
}

#[test]
fn verification_view_has_no_independent_public_constructor_or_binding_builder_surface() {
    let view_surface = REPLAY_SOURCE
        .split_once("pub struct ReplayClaimVerificationViewV1")
        .expect("verification view declaration exists")
        .1
        .split_once("pub enum ReplayClaimVerificationV1")
        .expect("closed verification outcome follows the view")
        .0;

    assert!(view_surface.contains("pub(crate)"));
    assert!(!view_surface.contains("pub fn new"));
    assert!(!view_surface.contains("ReplayBindingV1"));
    assert!(MARKER_SOURCE.contains("pub fn replay_verification_view"));
}

fn classification_name(value: &ReplayClaimVerificationV1) -> &'static str {
    match value {
        ReplayClaimVerificationV1::Exact => "EXACT",
        ReplayClaimVerificationV1::Missing => "MISSING",
        ReplayClaimVerificationV1::Conflict => "CONFLICT",
        ReplayClaimVerificationV1::Unavailable => "UNAVAILABLE",
        ReplayClaimVerificationV1::Unhealthy => "UNHEALTHY",
    }
}
