//! Exhaustive HumanRequestGrant v1 contract boundary tests (PLAN-006 T025).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use helix_task_authority_contracts::{
    decode_and_verify_human_request_grant_v1, decode_and_verify_retained_human_request_grant_v1,
    sign_human_request_grant_v1, ContractError, Generation, HumanRequestGrantInputV1,
    HumanRequestGrantKeyResolver, HumanRequestGrantProtectedV1, HumanRequestGrantSigner,
    HumanRequestGrantVerificationKeyV1, Identifier, SafeU64, Sha256Digest, VerificationKeyStatusV1,
};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};

const SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/human-request-grant-v1.schema.json"
);
const DOMAIN: &[u8] = b"HELIXOS\0HUMAN-REQUEST-GRANT\0V1\0";
const KEY_ID: &str = "request-key-v1";
const PROTECTED_FIELDS: &[&str] = &[
    "schema",
    "digest_algorithm",
    "signature_algorithm",
    "key_purpose",
    "key_id",
    "grant_id",
    "issuer_id",
    "audience",
    "principal_id",
    "message_digest",
    "channel_id",
    "session_id",
    "scope_template_id",
    "scope_template_digest",
    "scope_template_generation",
    "issued_at_utc_ms",
    "expires_at_utc_ms",
];

struct RecordingSigner {
    key: SigningKey,
    key_id: &'static str,
    calls: Cell<usize>,
    message: RefCell<Vec<u8>>,
    fail: bool,
}

impl RecordingSigner {
    fn working() -> Self {
        Self {
            key: SigningKey::from_bytes(&[7_u8; 32]),
            key_id: KEY_ID,
            calls: Cell::new(0),
            message: RefCell::new(Vec::new()),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::working()
        }
    }
}

impl HumanRequestGrantSigner for RecordingSigner {
    fn key_id(&self) -> &str {
        self.key_id
    }

    fn sign_human_request_grant(
        &self,
        message: &[u8],
    ) -> helix_task_authority_contracts::Result<[u8; 64]> {
        self.calls.set(self.calls.get() + 1);
        self.message.replace(message.to_vec());
        if self.fail {
            return Err(ContractError::SigningFailed);
        }
        Ok(self.key.sign(message).to_bytes())
    }
}

struct Resolver {
    public_key: [u8; 32],
    status: VerificationKeyStatusV1,
    calls: Cell<usize>,
    accept_any_id: bool,
}

impl Resolver {
    fn current(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            status: VerificationKeyStatusV1::Current,
            calls: Cell::new(0),
            accept_any_id: false,
        }
    }

    fn historical(public_key: [u8; 32]) -> Self {
        Self {
            status: VerificationKeyStatusV1::Historical,
            ..Self::current(public_key)
        }
    }

    fn permissive(public_key: [u8; 32]) -> Self {
        Self {
            accept_any_id: true,
            ..Self::current(public_key)
        }
    }
}

impl HumanRequestGrantKeyResolver for Resolver {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
        self.calls.set(self.calls.get() + 1);
        if !self.accept_any_id && key_id != KEY_ID {
            return Err(ContractError::UnknownKey);
        }
        Ok(match self.status {
            VerificationKeyStatusV1::Current => {
                HumanRequestGrantVerificationKeyV1::current(self.public_key)
            }
            VerificationKeyStatusV1::Historical => {
                HumanRequestGrantVerificationKeyV1::historical(self.public_key)
            }
        })
    }
}

fn input(issued: u64, expires: u64) -> HumanRequestGrantInputV1 {
    HumanRequestGrantInputV1 {
        grant_id: Sha256Digest::from_bytes([0x10; 32]),
        issuer_id: Identifier::new("request-surface-v1").unwrap(),
        audience: Identifier::new("helixos-core-v1").unwrap(),
        principal_id: Identifier::new("principal-v1").unwrap(),
        message_digest: Sha256Digest::from_bytes([0x20; 32]),
        channel_id: Identifier::new("channel-v1").unwrap(),
        session_id: Identifier::new("session-v1").unwrap(),
        scope_template_id: Identifier::new("scope-v1").unwrap(),
        scope_template_digest: Sha256Digest::from_bytes([0x30; 32]),
        scope_template_generation: Generation::new(7).unwrap(),
        issued_at_utc_ms: SafeU64::new(issued).unwrap(),
        expires_at_utc_ms: SafeU64::new(expires).unwrap(),
    }
}

fn protected() -> HumanRequestGrantProtectedV1 {
    HumanRequestGrantProtectedV1::try_new(input(1_000, 2_000), Identifier::new(KEY_ID).unwrap())
        .unwrap()
}

fn fixture() -> (Vec<u8>, Value, [u8; 32]) {
    let signer = RecordingSigner::working();
    let signed = sign_human_request_grant_v1(protected(), &signer).unwrap();
    let wire = signed.to_canonical_json().unwrap();
    let value = serde_json::from_slice(&wire).unwrap();
    (wire, value, signer.key.verifying_key().to_bytes())
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).unwrap()
}

fn mutation(field: &str) -> Value {
    match field {
        "schema" => json!("helixos.human-request-grant/2"),
        "digest_algorithm" => json!("sha-512"),
        "signature_algorithm" => json!("ed25519ph"),
        "key_purpose" => json!("core-task-lease-signing"),
        "key_id" => json!("request-key-v2"),
        "grant_id" => json!("11".repeat(32)),
        "issuer_id" => json!("request-surface-v2"),
        "audience" => json!("helixos-core-v2"),
        "principal_id" => json!("principal-v2"),
        "message_digest" => json!("21".repeat(32)),
        "channel_id" => json!("channel-v2"),
        "session_id" => json!("session-v2"),
        "scope_template_id" => json!("scope-v2"),
        "scope_template_digest" => json!("31".repeat(32)),
        "scope_template_generation" => json!(8),
        "issued_at_utc_ms" => json!(1_001),
        "expires_at_utc_ms" => json!(2_001),
        _ => unreachable!(),
    }
}

fn profile_error(field: &str) -> Option<ContractError> {
    match field {
        "schema" => Some(ContractError::UnsupportedSchema),
        "digest_algorithm" => Some(ContractError::UnsupportedDigestAlgorithm),
        "signature_algorithm" => Some(ContractError::UnsupportedSignatureAlgorithm),
        "key_purpose" => Some(ContractError::WrongKeyPurpose),
        _ => None,
    }
}

#[test]
fn schema_and_production_inventory_are_exact_closed_and_seventeen_leaf() {
    let schema: Value = serde_json::from_str(SCHEMA).unwrap();
    let required = schema["$defs"]["protectedGrant"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(required, PROTECTED_FIELDS);
    assert_eq!(
        schema["$defs"]["protectedGrant"]["additionalProperties"],
        false
    );

    let (_, value, _) = fixture();
    let actual = value["protected"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut expected = PROTECTED_FIELDS.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

#[test]
fn independent_domain_digest_and_signature_oracle_is_exact() {
    let signer = RecordingSigner::working();
    let signed = sign_human_request_grant_v1(protected(), &signer).unwrap();
    assert_eq!(signer.calls.get(), 1);

    let wire = signed.to_canonical_json().unwrap();
    let value: Value = serde_json::from_slice(&wire).unwrap();
    let protected_jcs = canonical(&value["protected"]);
    let mut expected_message = DOMAIN.to_vec();
    expected_message.extend_from_slice(&protected_jcs);
    assert_eq!(&*signer.message.borrow(), &expected_message);
    assert_eq!(
        value["grant_digest"],
        json!(Sha256Digest::digest(&protected_jcs).to_hex())
    );

    let signature = URL_SAFE_NO_PAD
        .decode(value["signature"].as_str().unwrap())
        .unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
    signer
        .key
        .verifying_key()
        .verify(&expected_message, &signature)
        .unwrap();
    for wrong_domain in [
        b"HELIXOS\0TASK-LEASE\0V1\0".as_slice(),
        b"HELIXOS\0APPROVAL-DECISION\0V1\0".as_slice(),
    ] {
        let mut wrong = wrong_domain.to_vec();
        wrong.extend_from_slice(&protected_jcs);
        assert!(signer
            .key
            .verifying_key()
            .verify(&wrong, &signature)
            .is_err());
    }
}

#[test]
fn every_protected_leaf_removal_denies_before_resolution() {
    let (_, base, public_key) = fixture();
    for field in PROTECTED_FIELDS {
        let mut candidate = base.clone();
        candidate["protected"]
            .as_object_mut()
            .unwrap()
            .remove(*field);
        let resolver = Resolver::current(public_key);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(&canonical(&candidate), &resolver)
                .expect_err("missing protected leaf must deny"),
            ContractError::MissingRequiredField,
            "{field}"
        );
        assert_eq!(resolver.calls.get(), 0, "{field}");
    }
}

#[test]
fn every_valid_leaf_mutation_changes_jcs_digest_and_fixed_order_outcome() {
    let (_, base, public_key) = fixture();
    let original_protected = canonical(&base["protected"]);
    let original_digest = Sha256Digest::digest(&original_protected);

    for field in PROTECTED_FIELDS {
        let mut stale = base.clone();
        stale["protected"][*field] = mutation(field);
        let mutated_protected = canonical(&stale["protected"]);
        assert_ne!(mutated_protected, original_protected, "{field}");
        assert_ne!(
            Sha256Digest::digest(&mutated_protected),
            original_digest,
            "{field}"
        );

        let stale_resolver = Resolver::permissive(public_key);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(&canonical(&stale), &stale_resolver)
                .expect_err("stale digest or profile mutation must deny"),
            profile_error(field).unwrap_or(ContractError::DigestMismatch),
            "{field}"
        );
        assert_eq!(stale_resolver.calls.get(), 0, "{field}");

        stale["grant_digest"] = json!(Sha256Digest::digest(&mutated_protected).to_hex());
        let signature_resolver = Resolver::permissive(public_key);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(&canonical(&stale), &signature_resolver,)
                .expect_err("rehashed mutation must still fail its old signature"),
            profile_error(field).unwrap_or(ContractError::SignatureInvalid),
            "{field}"
        );
        assert_eq!(
            signature_resolver.calls.get(),
            usize::from(profile_error(field).is_none()),
            "{field}"
        );
    }
}

#[test]
fn outer_duplicate_canonical_size_and_signature_encoding_are_closed() {
    let (wire, base, public_key) = fixture();
    for outer in ["protected", "grant_digest", "signature"] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(outer);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(
                &canonical(&missing),
                &Resolver::current(public_key),
            )
            .expect_err("outer field is required"),
            ContractError::MissingOuterField
        );
    }

    let mut unknown = base.clone();
    unknown["extra"] = json!(true);
    assert_eq!(
        decode_and_verify_human_request_grant_v1(
            &canonical(&unknown),
            &Resolver::current(public_key),
        )
        .unwrap_err(),
        ContractError::UnknownField
    );

    let duplicate =
        String::from_utf8(wire.clone())
            .unwrap()
            .replacen("{", "{\"signature\":\"duplicate\",", 1);
    assert_eq!(
        decode_and_verify_human_request_grant_v1(
            duplicate.as_bytes(),
            &Resolver::current(public_key),
        )
        .unwrap_err(),
        ContractError::DuplicateMember
    );

    let mut spaced = vec![b' '];
    spaced.extend_from_slice(&wire);
    assert_eq!(
        decode_and_verify_human_request_grant_v1(&spaced, &Resolver::current(public_key),)
            .unwrap_err(),
        ContractError::NonCanonicalWire
    );

    let oversized = serde_json::to_vec(&"a".repeat(65_535)).unwrap();
    assert_eq!(oversized.len(), 65_537);
    assert_eq!(
        decode_and_verify_human_request_grant_v1(&oversized, &Resolver::current(public_key),)
            .unwrap_err(),
        ContractError::WireTooLarge
    );

    let mut invalid_signature = base;
    invalid_signature["signature"] = json!("A".repeat(85));
    let resolver = Resolver::current(public_key);
    assert_eq!(
        decode_and_verify_human_request_grant_v1(&canonical(&invalid_signature), &resolver)
            .unwrap_err(),
        ContractError::InvalidEncoding
    );
    assert_eq!(resolver.calls.get(), 0);
}

#[test]
fn time_signer_and_current_historical_boundaries_are_explicit() {
    for (issued, expires) in [(1_000, 1_000), (1_001, 1_000)] {
        let invalid = HumanRequestGrantInputV1 {
            issued_at_utc_ms: SafeU64::new(issued).unwrap(),
            expires_at_utc_ms: SafeU64::new(expires).unwrap(),
            ..input(1_000, 2_000)
        };
        assert_eq!(
            HumanRequestGrantProtectedV1::try_new(invalid, Identifier::new(KEY_ID).unwrap()),
            Err(ContractError::InvalidField)
        );
    }

    let wrong_key = RecordingSigner {
        key_id: "other-purpose-key",
        ..RecordingSigner::working()
    };
    assert_eq!(
        sign_human_request_grant_v1(protected(), &wrong_key),
        Err(ContractError::WrongKeyPurpose)
    );
    assert_eq!(wrong_key.calls.get(), 0);
    assert_eq!(
        sign_human_request_grant_v1(protected(), &RecordingSigner::failing()),
        Err(ContractError::SigningFailed)
    );

    let (wire, _, public_key) = fixture();
    let historical = Resolver::historical(public_key);
    assert_eq!(
        decode_and_verify_human_request_grant_v1(&wire, &historical).unwrap_err(),
        ContractError::HistoricalKeyNotAuthority
    );
    let retained =
        decode_and_verify_retained_human_request_grant_v1(&wire, &Resolver::historical(public_key))
            .unwrap();
    assert_eq!(
        retained.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(retained.claims().principal_id(), "principal-v1");
}
