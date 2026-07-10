mod common;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::{canonicalize_value, fixed_signer, sample_input, TestResolver, TestSigner};
use ed25519_dalek::{Signer as _, SigningKey};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, sign_protected_plan_v1, ContractError,
    Ed25519KeyResolver, Ed25519Signer, PlanProtectedV1, Result,
};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};

#[test]
fn rfc8032_test_vector_one_matches() {
    let seed: [u8; 32] =
        decode_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .try_into()
            .unwrap();
    let key = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex(&key.verifying_key().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        hex(&key.sign(b"").to_bytes()),
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
}

#[test]
fn signed_plan_verifies_and_is_deterministic() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let first = sign_plan_v1(sample_input(), &signer).unwrap();
    let second = sign_plan_v1(sample_input(), &signer).unwrap();
    assert_eq!(first, second);
    let wire = first.to_canonical_json().unwrap();
    let authentic = decode_and_verify_plan(&wire, &resolver).unwrap();
    assert_eq!(authentic.plan_id(), second.plan_id());
}

#[test]
fn wrong_or_revoked_key_is_denied() {
    let signer = fixed_signer();
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let wire = signed.to_canonical_json().unwrap();

    let wrong = TestSigner::new("core-signing-key:fixture-1", [8_u8; 32]);
    let wrong_resolver = TestResolver::for_signer(&wrong);
    assert!(matches!(
        decode_and_verify_plan(&wire, &wrong_resolver),
        Err(ContractError::SignatureInvalid)
    ));

    let mut revoked = TestResolver::for_signer(&signer);
    revoked.revoked = true;
    assert!(matches!(
        decode_and_verify_plan(&wire, &revoked),
        Err(ContractError::UnknownKey)
    ));
}

#[test]
fn signer_cannot_substitute_the_protected_key_id() {
    let protected = PlanProtectedV1::try_new(sample_input(), "key:a").unwrap();
    let signer = TestSigner::new("key:b", [7_u8; 32]);
    assert!(matches!(
        sign_protected_plan_v1(protected, &signer),
        Err(ContractError::SignerKeyMismatch)
    ));
}

#[derive(Debug)]
struct RecordingSigner {
    key: SigningKey,
    message: RefCell<Vec<u8>>,
}

impl Ed25519Signer for RecordingSigner {
    fn key_id(&self) -> &str {
        "key:domain-test"
    }

    fn sign_ed25519(&self, message: &[u8]) -> Result<[u8; 64]> {
        self.message.replace(message.to_vec());
        Ok(self.key.sign(message).to_bytes())
    }
}

#[test]
fn signature_message_has_exact_v1_domain_and_protected_suffix() {
    let signer = RecordingSigner {
        key: SigningKey::from_bytes(&[9_u8; 32]),
        message: RefCell::new(Vec::new()),
    };
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let protected = signed.protected().canonical_bytes().unwrap();
    let expected = [b"HELIXOS\0PLAN-ENVELOPE\0V1\0".as_slice(), &protected].concat();
    assert_eq!(*signer.message.borrow(), expected);
}

#[test]
fn truncated_padded_and_bit_flipped_signatures_are_denied() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let mut envelope: Value = serde_json::from_slice(&signed.to_canonical_json().unwrap()).unwrap();

    envelope["signature"] = json!(&signed.signature_base64url()[..85]);
    assert!(matches!(
        decode_and_verify_plan(&canonicalize_value(&envelope), &resolver),
        Err(ContractError::InvalidEncoding { kind: "signature" })
    ));

    envelope["signature"] = json!(format!("{}=", signed.signature_base64url()));
    assert!(matches!(
        decode_and_verify_plan(&canonicalize_value(&envelope), &resolver),
        Err(ContractError::InvalidEncoding { kind: "signature" })
    ));

    let mut signature = URL_SAFE_NO_PAD
        .decode(signed.signature_base64url())
        .unwrap();
    signature[0] ^= 0x01;
    envelope["signature"] = json!(URL_SAFE_NO_PAD.encode(signature));
    assert!(matches!(
        decode_and_verify_plan(&canonicalize_value(&envelope), &resolver),
        Err(ContractError::SignatureInvalid)
    ));
}

#[derive(Debug, Default)]
struct CountingResolver(Cell<usize>);

impl Ed25519KeyResolver for CountingResolver {
    fn resolve_ed25519(&self, _key_id: &str) -> Result<[u8; 32]> {
        self.0.set(self.0.get() + 1);
        Ok([0_u8; 32])
    }
}

#[test]
fn malformed_signature_never_reaches_key_resolution() {
    let signer = fixed_signer();
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let mut envelope: Value = serde_json::from_slice(&signed.to_canonical_json().unwrap()).unwrap();
    envelope["signature"] = json!("short");
    let resolver = CountingResolver::default();
    assert!(matches!(
        decode_and_verify_plan(&canonicalize_value(&envelope), &resolver),
        Err(ContractError::InvalidEncoding { kind: "signature" })
    ));
    assert_eq!(resolver.0.get(), 0);
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
