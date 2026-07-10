mod common;

#[path = "../test-support/replay_claimant.rs"]
mod replay_claimant;

use common::*;
use ed25519_dalek::{Signer as _, SigningKey};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AuthenticPlanEnvelopeV1, ContractError,
    Ed25519KeyResolver, Ed25519Signer, Nonce128, PlanInputV1, Result as ContractResult,
    RiskLevelV1,
};
use helix_plan_eligibility::{
    AuthorizationInputV1, AuthorizationRecordV1, AuthorizationStatusV1, AuthorizationViewV1,
    EligibilityContextV1, EligibilityDenialV1, ReadyEligibilityContextInputV1,
    ReadyEligibilityContextV1, SignerTrustInputV1, SignerTrustRecordV1, SignerTrustViewV1,
};
use replay_claimant::{DeterministicReplayClaimant, ForcedReplayOutcome};

const ROTATED_KEY_ID: &str = "core-signing-key:fixture-2";
const OTHER_OPERATION_ID: &str = "operation:00000000-0000-4000-8000-000000000002";
const OTHER_NONCE: Nonce128 = Nonce128::from_bytes([0x22; 16]);

#[test]
fn exact_repeat_is_already_claimed_and_returns_the_original_authentic_plan() {
    let claimant = DeterministicReplayClaimant::new();
    let first = coherent_fixture();
    let plan_id = first.plan.plan_id();
    let _first_eligible = first
        .evaluate(&claimant)
        .expect("first exact binding must claim");

    let failure = coherent_fixture()
        .evaluate(&claimant)
        .expect_err("an exact repeated binding must not yield a second marker");
    assert_eq!(failure.denial(), EligibilityDenialV1::ReplayAlreadyClaimed);
    assert_eq!(failure.into_authentic().plan_id(), plan_id);
    assert_eq!(claimant.call_count(), 2);
    assert_eq!(claimant.successful_claim_count(), 1);
    assert_eq!(claimant.claimant_generation(), 1);
}

#[test]
fn either_uniqueness_index_and_key_rotation_conflict_with_the_first_binding() {
    let mut other_operation_input = sample_plan_input();
    other_operation_input.operation_id = OTHER_OPERATION_ID.to_owned();
    let other_operation_plan = authenticate(other_operation_input, KEY_ID, [7; 32]);
    let other_operation_fixture = fixture_for_plan(other_operation_plan, |plan, input| {
        input.authorization =
            authorization_for(plan, OTHER_OPERATION_ID, Nonce128::from_bytes([0x11; 16]));
    });
    assert_binding_conflict(other_operation_fixture);

    let mut other_nonce_input = sample_plan_input();
    other_nonce_input.nonce = OTHER_NONCE;
    let other_nonce_plan = authenticate(other_nonce_input, KEY_ID, [7; 32]);
    let other_nonce_fixture = fixture_for_plan(other_nonce_plan, |plan, input| {
        input.authorization = authorization_for(plan, OPERATION_ID, OTHER_NONCE);
    });
    assert_binding_conflict(other_nonce_fixture);

    let rotated_plan = authenticate(sample_plan_input(), ROTATED_KEY_ID, [9; 32]);
    let baseline_fingerprint = authentic_plan()
        .eligibility_claims()
        .verified_key_fingerprint();
    let rotated_fingerprint = rotated_plan.eligibility_claims().verified_key_fingerprint();
    assert_ne!(rotated_fingerprint, baseline_fingerprint);
    let rotated_fixture = fixture_for_plan(rotated_plan, |plan, input| {
        input.signer = signer_for(plan, ROTATED_KEY_ID, TRUST_GENERATION + 1);
    });
    assert_binding_conflict(rotated_fixture);
}

#[test]
fn mismatched_receipt_digest_fails_closed_after_one_permanent_claim() {
    let claimant =
        DeterministicReplayClaimant::with_forced_outcome(ForcedReplayOutcome::WrongReceiptBinding);
    let fixture = coherent_fixture();
    let plan_id = fixture.plan.plan_id();

    let failure = fixture
        .evaluate(&claimant)
        .expect_err("a receipt for another replay binding must deny");
    assert_eq!(
        failure.denial(),
        EligibilityDenialV1::ReplayReceiptBindingMismatch
    );
    assert_eq!(failure.into_authentic().plan_id(), plan_id);
    assert_eq!(claimant.call_count(), 1);
    assert_eq!(claimant.successful_claim_count(), 1);
    assert_eq!(claimant.claimant_generation(), 1);

    let retry = coherent_fixture()
        .evaluate(&claimant)
        .expect_err("a rejected receipt never releases the committed claim");
    assert_eq!(retry.denial(), EligibilityDenialV1::ReplayAlreadyClaimed);
    assert_eq!(claimant.call_count(), 2);
    assert_eq!(claimant.successful_claim_count(), 1);
}

#[test]
fn claimant_is_last_called_once_and_replay_failures_return_authentic_custody() {
    let claimant = DeterministicReplayClaimant::new();
    let invalid = fixture_with_context(EligibilityContextV1::Unavailable);
    let invalid_plan_id = invalid.plan.plan_id();
    let failure = invalid
        .evaluate(&claimant)
        .expect_err("context failure must stop before replay");
    assert_eq!(failure.denial(), EligibilityDenialV1::ContextUnavailable);
    assert_eq!(failure.into_authentic().plan_id(), invalid_plan_id);
    assert_eq!(claimant.call_count(), 0);
    assert_eq!(claimant.successful_claim_count(), 0);

    let _eligible = coherent_fixture()
        .evaluate(&claimant)
        .expect("a later coherent plan must still claim exactly once");
    assert_eq!(claimant.call_count(), 1);
    assert_eq!(claimant.successful_claim_count(), 1);

    for (mode, expected) in [
        (
            ForcedReplayOutcome::AlreadyClaimed,
            EligibilityDenialV1::ReplayAlreadyClaimed,
        ),
        (
            ForcedReplayOutcome::BindingConflict,
            EligibilityDenialV1::ReplayBindingConflict,
        ),
        (
            ForcedReplayOutcome::Unavailable,
            EligibilityDenialV1::ReplayUnavailable,
        ),
        (
            ForcedReplayOutcome::Ambiguous,
            EligibilityDenialV1::ReplayAmbiguous,
        ),
    ] {
        let forced = DeterministicReplayClaimant::with_forced_outcome(mode);
        let fixture = coherent_fixture();
        let plan_id = fixture.plan.plan_id();
        let fingerprint = fixture.plan.eligibility_claims().verified_key_fingerprint();
        let failure = fixture
            .evaluate(&forced)
            .expect_err("a forced replay failure must deny");
        assert_eq!(failure.denial(), expected);
        let recovered = failure.into_authentic();
        assert_eq!(recovered.plan_id(), plan_id);
        assert_eq!(
            recovered.eligibility_claims().verified_key_fingerprint(),
            fingerprint
        );
        assert_eq!(forced.call_count(), 1, "replay outcome was retried");
        assert_eq!(forced.successful_claim_count(), 0);
    }
}

fn assert_binding_conflict(attempt: EligibilityFixture) {
    let claimant = DeterministicReplayClaimant::new();
    let _baseline_eligible = coherent_fixture()
        .evaluate(&claimant)
        .expect("baseline binding must claim");
    let attempted_plan_id = attempt.plan.plan_id();

    let failure = attempt
        .evaluate(&claimant)
        .expect_err("either occupied uniqueness index must conflict");
    assert_eq!(failure.denial(), EligibilityDenialV1::ReplayBindingConflict);
    assert_eq!(failure.into_authentic().plan_id(), attempted_plan_id);
    assert_eq!(claimant.call_count(), 2);
    assert_eq!(claimant.successful_claim_count(), 1);
    assert_eq!(claimant.claimant_generation(), 1);
}

fn fixture_for_plan(
    plan: AuthenticPlanEnvelopeV1,
    configure: impl FnOnce(&AuthenticPlanEnvelopeV1, &mut ReadyEligibilityContextInputV1<'static>),
) -> EligibilityFixture {
    let mut input = coherent_ready_input(&plan);
    configure(&plan, &mut input);
    let ready = ReadyEligibilityContextV1::try_new(input).expect("valid replay fixture");
    EligibilityFixture {
        plan,
        context: EligibilityContextV1::Ready(ready),
    }
}

fn authorization_for(
    plan: &AuthenticPlanEnvelopeV1,
    operation_id: &'static str,
    nonce: Nonce128,
) -> AuthorizationViewV1<'static> {
    AuthorizationViewV1::Current(
        AuthorizationRecordV1::try_new(AuthorizationInputV1 {
            status: AuthorizationStatusV1::Granted,
            plan_id: plan.plan_id(),
            operation_id,
            risk_level: RiskLevelV1::L1,
            nonce,
            evidence_digest: digest(b"fixture authorization evidence"),
            authorization_generation: AUTHORIZATION_GENERATION,
            boot_id: BOOT_ID,
            not_before_utc_unix_ms: ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: ISSUED_AT_MS + 190_000,
            deadline_monotonic_ms: 110_000,
        })
        .expect("valid replay authorization"),
    )
}

fn signer_for(
    plan: &AuthenticPlanEnvelopeV1,
    key_id: &'static str,
    trust_generation: u64,
) -> SignerTrustViewV1<'static> {
    SignerTrustViewV1::Trusted(
        SignerTrustRecordV1::try_new(SignerTrustInputV1 {
            key_id,
            public_key_fingerprint: plan.eligibility_claims().verified_key_fingerprint(),
            trust_generation,
            minimum_accepted_issued_at_unix_ms: ISSUED_AT_MS - 1,
        })
        .expect("valid rotated signer view"),
    )
}

fn authenticate(
    input: PlanInputV1,
    key_id: &'static str,
    secret: [u8; 32],
) -> AuthenticPlanEnvelopeV1 {
    let signer = LocalSigner {
        key_id,
        key: SigningKey::from_bytes(&secret),
    };
    let resolver = LocalResolver {
        key_id,
        public_key: signer.key.verifying_key().to_bytes(),
    };
    let signed = sign_plan_v1(input, &signer).expect("replay variant signs");
    let wire = signed
        .to_canonical_json()
        .expect("replay variant canonicalizes");
    decode_and_verify_plan(&wire, &resolver).expect("replay variant authenticates")
}

struct LocalSigner {
    key_id: &'static str,
    key: SigningKey,
}

impl Ed25519Signer for LocalSigner {
    fn key_id(&self) -> &str {
        self.key_id
    }

    fn sign_ed25519(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        Ok(self.key.sign(message).to_bytes())
    }
}

struct LocalResolver {
    key_id: &'static str,
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for LocalResolver {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == self.key_id {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}
