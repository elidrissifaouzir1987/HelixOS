use ed25519_dalek::{Signer as _, SigningKey};
use helix_task_authority::{evaluate_authority_currentness_v1, AuthorityCurrentnessV1};
use helix_task_authority_contracts::{
    decode_and_verify_human_request_grant_v1, decode_and_verify_retained_human_request_grant_v1,
    sign_human_request_grant_v1, ContractError, Generation, HumanRequestGrantInputV1,
    HumanRequestGrantKeyResolver, HumanRequestGrantProtectedV1, HumanRequestGrantSigner,
    HumanRequestGrantVerificationKeyV1, Identifier, SafeU64, Sha256Digest, VerificationKeyStatusV1,
};

struct SignerV1(SigningKey);

impl HumanRequestGrantSigner for SignerV1 {
    fn key_id(&self) -> &str {
        "request-key-v1"
    }

    fn sign_human_request_grant(
        &self,
        message: &[u8],
    ) -> helix_task_authority_contracts::Result<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
}

struct ResolverV1 {
    key: [u8; 32],
    current: bool,
}

impl HumanRequestGrantKeyResolver for ResolverV1 {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
        if key_id != "request-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(if self.current {
            HumanRequestGrantVerificationKeyV1::current(self.key)
        } else {
            HumanRequestGrantVerificationKeyV1::historical(self.key)
        })
    }
}

fn identifier(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn wire_v1(signer: &SignerV1) -> Vec<u8> {
    let protected = HumanRequestGrantProtectedV1::try_new(
        HumanRequestGrantInputV1 {
            grant_id: Sha256Digest::from_bytes([1; 32]),
            issuer_id: identifier("request-surface"),
            audience: identifier("helix-core"),
            principal_id: identifier("principal-a"),
            message_digest: Sha256Digest::from_bytes([2; 32]),
            channel_id: identifier("channel-a"),
            session_id: identifier("session-a"),
            scope_template_id: identifier("scope-a"),
            scope_template_digest: Sha256Digest::from_bytes([3; 32]),
            scope_template_generation: Generation::new(1).unwrap(),
            issued_at_utc_ms: SafeU64::new(1_000).unwrap(),
            expires_at_utc_ms: SafeU64::new(2_000).unwrap(),
        },
        identifier(signer.key_id()),
    )
    .unwrap();
    sign_human_request_grant_v1(protected, signer)
        .unwrap()
        .to_canonical_json()
        .unwrap()
}

#[test]
fn rotation_keeps_old_bytes_historical_without_revival() {
    let signer = SignerV1(SigningKey::from_bytes(&[31; 32]));
    let wire = wire_v1(&signer);
    let public_key = signer.0.verifying_key().to_bytes();

    decode_and_verify_human_request_grant_v1(
        &wire,
        &ResolverV1 {
            key: public_key,
            current: true,
        },
    )
    .expect("current key admits consumption evidence");

    assert_eq!(
        decode_and_verify_human_request_grant_v1(
            &wire,
            &ResolverV1 {
                key: public_key,
                current: false,
            },
        )
        .unwrap_err(),
        ContractError::HistoricalKeyNotAuthority
    );
    let retained = decode_and_verify_retained_human_request_grant_v1(
        &wire,
        &ResolverV1 {
            key: public_key,
            current: false,
        },
    )
    .expect("historical verifier retains exact evidence");
    assert_eq!(
        retained.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(retained.canonical_signed_envelope_bytes().unwrap(), wire);
}

#[test]
fn source_ancestor_and_decision_revocations_are_distinct_noncurrent_outcomes() {
    assert_eq!(
        evaluate_authority_currentness_v1(
            VerificationKeyStatusV1::Current,
            false,
            false,
            false,
            false,
        ),
        AuthorityCurrentnessV1::Current
    );
    assert_eq!(
        evaluate_authority_currentness_v1(
            VerificationKeyStatusV1::Historical,
            false,
            false,
            false,
            false,
        ),
        AuthorityCurrentnessV1::SignerHistorical
    );
    assert_eq!(
        evaluate_authority_currentness_v1(VerificationKeyStatusV1::Current, true, true, true, true,),
        AuthorityCurrentnessV1::SignerRevoked
    );
    assert_eq!(
        evaluate_authority_currentness_v1(
            VerificationKeyStatusV1::Current,
            false,
            true,
            true,
            true,
        ),
        AuthorityCurrentnessV1::SourceRevoked
    );
    assert_eq!(
        evaluate_authority_currentness_v1(
            VerificationKeyStatusV1::Current,
            false,
            false,
            true,
            true,
        ),
        AuthorityCurrentnessV1::AncestorRevoked
    );
    assert_eq!(
        evaluate_authority_currentness_v1(
            VerificationKeyStatusV1::Current,
            false,
            false,
            false,
            true,
        ),
        AuthorityCurrentnessV1::DecisionRevoked
    );
}
