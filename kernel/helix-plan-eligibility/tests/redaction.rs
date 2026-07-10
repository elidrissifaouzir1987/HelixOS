mod common;

use common::{coherent_fixture, fixture_with_context};
use helix_contracts::Sha256Digest;
use helix_plan_eligibility::{
    EligibilityContextBuildErrorV1, EligibilityContextV1, EligibilityDenialV1, ReplayBindingV1,
    ReplayClaimOutcomeV1, ReplayClaimReceiptV1, ReplayClaimantV1, SignerTrustInputV1,
    SignerTrustRecordV1, SignerTrustViewV1,
};
use std::sync::Mutex;

const SENTINELS: &[&str] = &[
    "secret-key-identifier",
    "secret-workload",
    "secret-nonce",
    "secret-resource-component",
    "raw-provider-error",
    "core-signing-key:fixture-1",
    "operation:00000000-0000-4000-8000-000000000001",
    "task:fixture-1",
    "workload:agent-vm-1",
    "boot:fixture-1",
];

#[derive(Debug, Default)]
struct DebugCaptureClaimant {
    rendered_binding: Mutex<Option<String>>,
}

impl ReplayClaimantV1 for DebugCaptureClaimant {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1 {
        *self
            .rendered_binding
            .lock()
            .expect("debug capture mutex is not poisoned") = Some(format!("{binding:?}"));
        ReplayClaimOutcomeV1::Claimed(
            ReplayClaimReceiptV1::try_new(
                Sha256Digest::digest(b"public synthetic claim"),
                1,
                binding.binding_digest(),
            )
            .expect("valid public synthetic receipt"),
        )
    }
}

#[test]
fn public_debug_and_display_surfaces_are_redacted() {
    let signer = SignerTrustRecordV1::try_new(SignerTrustInputV1 {
        key_id: SENTINELS[0],
        public_key_fingerprint: Sha256Digest::digest(SENTINELS[1].as_bytes()),
        trust_generation: 3,
        minimum_accepted_issued_at_unix_ms: 1,
    })
    .expect("synthetic bounded signer view");
    let receipt = ReplayClaimReceiptV1::try_new(
        Sha256Digest::digest(SENTINELS[2].as_bytes()),
        9,
        Sha256Digest::digest(SENTINELS[3].as_bytes()),
    )
    .expect("synthetic bounded receipt");

    let rendered = [
        format!("{:?}", EligibilityContextV1::Unavailable),
        format!("{:?}", SignerTrustViewV1::Trusted(signer)),
        format!("{:?}", ReplayClaimOutcomeV1::Claimed(receipt)),
        format!("{:?}", EligibilityDenialV1::SignerFingerprintMismatch),
        EligibilityDenialV1::SignerFingerprintMismatch.to_string(),
        EligibilityContextBuildErrorV1::InvalidIdentifier.to_string(),
    ]
    .join("\n");

    for sentinel in SENTINELS {
        assert!(
            !rendered.contains(sentinel),
            "diagnostic leaked sentinel {sentinel}"
        );
    }
    assert!(!rendered.contains("expected"));
    assert!(!rendered.contains("actual"));
}

#[test]
fn errors_expose_stable_codes_without_wrapped_sources() {
    let denial = EligibilityDenialV1::ReplayReceiptBindingMismatch;
    assert_eq!(denial.code(), "REPLAY_RECEIPT_BINDING_MISMATCH");
    assert!(std::error::Error::source(&denial).is_none());

    let build = EligibilityContextBuildErrorV1::InvalidCapabilitySet;
    assert_eq!(build.code(), "CONTEXT_BUILD_INVALID_CAPABILITY_SET");
    assert!(std::error::Error::source(&build).is_none());
}

#[test]
fn claims_markers_failures_and_replay_bindings_never_render_trusted_values() {
    let fixture = coherent_fixture();
    let claims_rendered = format!(
        "{:?}\n{:?}",
        fixture.plan.eligibility_claims(),
        fixture.plan.eligibility_claims().budget()
    );
    let claimant = DebugCaptureClaimant::default();
    let eligible = fixture
        .evaluate(&claimant)
        .expect("coherent synthetic context is eligible");
    let binding_rendered = claimant
        .rendered_binding
        .lock()
        .expect("debug capture mutex is not poisoned")
        .clone()
        .expect("claimant captured binding debug");

    let failure = fixture_with_context(EligibilityContextV1::Unavailable)
        .evaluate(&claimant)
        .expect_err("unavailable context is denied");
    let rendered = format!(
        "{claims_rendered}\n{binding_rendered}\n{eligible:?}\n{:?}\n{:?}\n{:?}\n{failure:?}",
        eligible.bounds(),
        eligible.bindings(),
        eligible.replay_claim(),
    );

    for sentinel in SENTINELS {
        assert!(
            !rendered.contains(sentinel),
            "public diagnostic leaked trusted sentinel {sentinel}"
        );
    }
    for forbidden_label in ["expected", "actual", "provider", "signature", "nonce"] {
        assert!(
            !rendered.to_ascii_lowercase().contains(forbidden_label),
            "public diagnostic exposed forbidden label {forbidden_label}"
        );
    }
}

#[test]
fn every_closed_error_debug_display_and_source_surface_is_bounded() {
    for denial in EligibilityDenialV1::ALL {
        let debug = format!("{denial:?}");
        let display = denial.to_string();
        assert!(debug.len() < 96);
        assert_eq!(display, "plan eligibility was denied");
        assert!(std::error::Error::source(denial).is_none());
    }
    for build in EligibilityContextBuildErrorV1::ALL {
        let debug = format!("{build:?}");
        let display = build.to_string();
        assert!(debug.len() < 96);
        assert_eq!(display, "eligibility context construction was rejected");
        assert!(std::error::Error::source(build).is_none());
    }
}
