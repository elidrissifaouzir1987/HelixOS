use crate::{ContractError, Result, Sha256Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationKeyStatusV1 {
    Current,
    Historical,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HumanRequestGrantVerificationKeyV1 {
    public_key: [u8; 32],
    status: VerificationKeyStatusV1,
}

impl HumanRequestGrantVerificationKeyV1 {
    pub const fn current(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            status: VerificationKeyStatusV1::Current,
        }
    }

    pub const fn historical(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            status: VerificationKeyStatusV1::Historical,
        }
    }
}

impl fmt::Debug for HumanRequestGrantVerificationKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanRequestGrantVerificationKeyV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TaskLeaseVerificationKeyV1 {
    public_key: [u8; 32],
    status: VerificationKeyStatusV1,
}

impl TaskLeaseVerificationKeyV1 {
    pub const fn current(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            status: VerificationKeyStatusV1::Current,
        }
    }

    pub const fn historical(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            status: VerificationKeyStatusV1::Historical,
        }
    }
}

impl fmt::Debug for TaskLeaseVerificationKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLeaseVerificationKeyV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ApprovalDecisionVerificationKeyV1 {
    public_key: [u8; 32],
    status: VerificationKeyStatusV1,
}

impl ApprovalDecisionVerificationKeyV1 {
    pub const fn current(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            status: VerificationKeyStatusV1::Current,
        }
    }

    pub const fn historical(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            status: VerificationKeyStatusV1::Historical,
        }
    }
}

impl fmt::Debug for ApprovalDecisionVerificationKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalDecisionVerificationKeyV1")
            .finish_non_exhaustive()
    }
}

pub trait HumanRequestGrantSigner {
    fn key_id(&self) -> &str;
    fn sign_human_request_grant(&self, message: &[u8]) -> Result<[u8; 64]>;
}

pub trait HumanRequestGrantKeyResolver {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> Result<HumanRequestGrantVerificationKeyV1>;
}

pub trait TaskLeaseSigner {
    fn key_id(&self) -> &str;
    fn sign_task_lease(&self, message: &[u8]) -> Result<[u8; 64]>;
}

pub trait TaskLeaseKeyResolver {
    fn resolve_task_lease_key(&self, key_id: &str) -> Result<TaskLeaseVerificationKeyV1>;
}

pub trait ApprovalDecisionSigner {
    fn key_id(&self) -> &str;
    fn sign_approval_decision(&self, message: &[u8]) -> Result<[u8; 64]>;
}

pub trait ApprovalDecisionKeyResolver {
    fn resolve_approval_decision_key(
        &self,
        key_id: &str,
    ) -> Result<ApprovalDecisionVerificationKeyV1>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedKeyEvidenceV1 {
    fingerprint: Sha256Digest,
    status: VerificationKeyStatusV1,
}

impl VerifiedKeyEvidenceV1 {
    const fn new(fingerprint: Sha256Digest, status: VerificationKeyStatusV1) -> Self {
        Self {
            fingerprint,
            status,
        }
    }

    pub(crate) const fn fingerprint(&self) -> Sha256Digest {
        self.fingerprint
    }

    pub(crate) const fn status(&self) -> VerificationKeyStatusV1 {
        self.status
    }
}

impl fmt::Debug for VerifiedKeyEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedKeyEvidenceV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalEd25519SignatureV1([u8; 64]);

impl fmt::Debug for CanonicalEd25519SignatureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalEd25519SignatureV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn encode_signature(signature: [u8; 64]) -> String {
    URL_SAFE_NO_PAD.encode(signature)
}

pub(crate) fn decode_signature(encoded: &str) -> Result<CanonicalEd25519SignatureV1> {
    if encoded.len() != 86
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ContractError::InvalidEncoding);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ContractError::InvalidEncoding)?;
    if decoded.len() != 64 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(ContractError::InvalidEncoding);
    }
    let signature = decoded
        .try_into()
        .map_err(|_| ContractError::InvalidEncoding)?;
    Ok(CanonicalEd25519SignatureV1(signature))
}

pub(crate) fn verify_human_request_grant_signature(
    signature: CanonicalEd25519SignatureV1,
    message: &[u8],
    key: HumanRequestGrantVerificationKeyV1,
) -> Result<VerifiedKeyEvidenceV1> {
    let fingerprint = verify(signature, message, key.public_key)?;
    Ok(VerifiedKeyEvidenceV1::new(fingerprint, key.status))
}

pub(crate) fn verify_task_lease_signature(
    signature: CanonicalEd25519SignatureV1,
    message: &[u8],
    key: TaskLeaseVerificationKeyV1,
) -> Result<VerifiedKeyEvidenceV1> {
    let fingerprint = verify(signature, message, key.public_key)?;
    Ok(VerifiedKeyEvidenceV1::new(fingerprint, key.status))
}

pub(crate) fn verify_approval_decision_signature(
    signature: CanonicalEd25519SignatureV1,
    message: &[u8],
    key: ApprovalDecisionVerificationKeyV1,
) -> Result<VerifiedKeyEvidenceV1> {
    let fingerprint = verify(signature, message, key.public_key)?;
    Ok(VerifiedKeyEvidenceV1::new(fingerprint, key.status))
}

fn verify(
    signature: CanonicalEd25519SignatureV1,
    message: &[u8],
    public_key: [u8; 32],
) -> Result<Sha256Digest> {
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| ContractError::InvalidPublicKey)?;
    key.verify_strict(message, &Signature::from_bytes(&signature.0))
        .map_err(|_| ContractError::SignatureInvalid)?;
    Ok(Sha256Digest::digest(&public_key))
}

pub(crate) fn signature_message(domain: &[u8], protected: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + protected.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(protected);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
    use std::any::TypeId;

    const GRANT_DOMAIN: &[u8] = b"HELIXOS\0HUMAN-REQUEST-GRANT\0V1\0";
    const LEASE_DOMAIN: &[u8] = b"HELIXOS\0TASK-LEASE\0V1\0";
    const DECISION_DOMAIN: &[u8] = b"HELIXOS\0APPROVAL-DECISION\0V1\0";

    fn fixture_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn signed_message(domain: &[u8], protected: &[u8]) -> ([u8; 64], [u8; 32], Vec<u8>) {
        let signing_key = fixture_signing_key();
        let message = signature_message(domain, protected);
        let signature = signing_key.sign(&message).to_bytes();
        (signature, signing_key.verifying_key().to_bytes(), message)
    }

    fn canonical_signature(bytes: [u8; 64]) -> CanonicalEd25519SignatureV1 {
        decode_signature(&encode_signature(bytes)).unwrap()
    }

    #[test]
    fn canonical_signature_encoding_round_trips_exactly() {
        let mut q_tail = [0_u8; 64];
        q_tail[63] = 1;
        let mut g_tail = [0_u8; 64];
        g_tail[63] = 2;

        for (bytes, expected_tail) in [
            ([0_u8; 64], b'A'),
            (q_tail, b'Q'),
            (g_tail, b'g'),
            ([0xff_u8; 64], b'w'),
        ] {
            let encoded = encode_signature(bytes);

            assert_eq!(encoded.len(), 86);
            assert_eq!(encoded.as_bytes().last(), Some(&expected_tail));
            assert!(!encoded.contains(['=', '+', '/', ' ', '\n', '\r', '\t']));
            assert_eq!(
                decode_signature(&encoded).map(|signature| signature.0),
                Ok(bytes)
            );
        }
    }

    #[test]
    fn malformed_or_noncanonical_signature_text_is_rejected() {
        let valid = encode_signature([0_u8; 64]);
        let mut invalid = vec![
            valid[..85].to_owned(),
            format!("{valid}A"),
            format!("{valid}="),
            format!("+{}", &valid[1..]),
            format!("/{}", &valid[1..]),
            format!(" {}", &valid[1..]),
            format!("\n{}", &valid[1..]),
            format!("é{}", &valid[2..]),
        ];
        for noncanonical_last in ['B', 'R', 'h', 'x'] {
            let mut candidate = valid.clone();
            candidate.pop();
            candidate.push(noncanonical_last);
            invalid.push(candidate);
        }

        for encoded in invalid {
            assert_eq!(
                decode_signature(&encoded),
                Err(ContractError::InvalidEncoding),
                "accepted malformed signature {encoded:?}"
            );
        }
    }

    #[test]
    fn strict_verification_matches_rfc8032_vector_one() {
        let public_key: [u8; 32] =
            decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .try_into()
                .unwrap();
        let signature: [u8; 64] = decode_hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ))
        .try_into()
        .unwrap();

        assert_eq!(
            verify(canonical_signature(signature), b"", public_key),
            Ok(Sha256Digest::digest(&public_key))
        );
    }

    #[test]
    fn evidence_uses_only_the_verified_raw_public_key_and_preserves_status() {
        let protected = br#"{"grant_id":"fixture"}"#;
        let (signature, public_key, message) = signed_message(GRANT_DOMAIN, protected);
        let expected_fingerprint = Sha256Digest::digest(&public_key);

        let current = verify_human_request_grant_signature(
            canonical_signature(signature),
            &message,
            HumanRequestGrantVerificationKeyV1::current(public_key),
        )
        .unwrap();
        let historical = verify_human_request_grant_signature(
            canonical_signature(signature),
            &message,
            HumanRequestGrantVerificationKeyV1::historical(public_key),
        )
        .unwrap();

        assert_eq!(current.fingerprint(), expected_fingerprint);
        assert_eq!(historical.fingerprint(), expected_fingerprint);
        assert_eq!(current.status(), VerificationKeyStatusV1::Current);
        assert_eq!(historical.status(), VerificationKeyStatusV1::Historical);
    }

    #[test]
    fn each_purpose_specific_key_verifies_without_becoming_interchangeable() {
        let protected = br#"{"task_id":"fixture"}"#;
        let (signature, public_key, message) = signed_message(LEASE_DOMAIN, protected);

        let lease = verify_task_lease_signature(
            canonical_signature(signature),
            &message,
            TaskLeaseVerificationKeyV1::current(public_key),
        )
        .unwrap();
        let historical_lease = verify_task_lease_signature(
            canonical_signature(signature),
            &message,
            TaskLeaseVerificationKeyV1::historical(public_key),
        )
        .unwrap();
        assert_eq!(lease.fingerprint(), Sha256Digest::digest(&public_key));
        assert_eq!(
            historical_lease.status(),
            VerificationKeyStatusV1::Historical
        );

        let (signature, public_key, message) = signed_message(DECISION_DOMAIN, protected);
        let current_decision = verify_approval_decision_signature(
            canonical_signature(signature),
            &message,
            ApprovalDecisionVerificationKeyV1::current(public_key),
        )
        .unwrap();
        let historical_decision = verify_approval_decision_signature(
            canonical_signature(signature),
            &message,
            ApprovalDecisionVerificationKeyV1::historical(public_key),
        )
        .unwrap();
        assert_eq!(current_decision.status(), VerificationKeyStatusV1::Current);
        assert_eq!(
            historical_decision.status(),
            VerificationKeyStatusV1::Historical
        );

        assert_ne!(
            TypeId::of::<HumanRequestGrantVerificationKeyV1>(),
            TypeId::of::<TaskLeaseVerificationKeyV1>()
        );
        assert_ne!(
            TypeId::of::<TaskLeaseVerificationKeyV1>(),
            TypeId::of::<ApprovalDecisionVerificationKeyV1>()
        );
    }

    #[test]
    fn domains_prevent_cross_contract_signature_substitution() {
        let protected = br#"{"id":"same-protected-bytes"}"#;
        let domains = [GRANT_DOMAIN, LEASE_DOMAIN, DECISION_DOMAIN];

        for signed_domain in domains {
            let (signature, public_key, _) = signed_message(signed_domain, protected);
            for verification_domain in domains {
                let result = verify(
                    canonical_signature(signature),
                    &signature_message(verification_domain, protected),
                    public_key,
                );
                if signed_domain == verification_domain {
                    assert_eq!(result, Ok(Sha256Digest::digest(&public_key)));
                } else {
                    assert_eq!(result, Err(ContractError::SignatureInvalid));
                }
            }
        }
    }

    #[test]
    fn strict_verification_rejects_a_weak_key_universal_signature() {
        let mut identity_encoding = [0_u8; 32];
        identity_encoding[0] = 1;
        let mut universal_signature = [0_u8; 64];
        universal_signature[0] = 1;
        let signature = Signature::from_bytes(&universal_signature);
        let weak_key = VerifyingKey::from_bytes(&identity_encoding).unwrap();

        assert!(weak_key.verify(b"first message", &signature).is_ok());
        assert!(weak_key.verify(b"second message", &signature).is_ok());
        assert_eq!(
            verify(
                canonical_signature(universal_signature),
                b"first message",
                identity_encoding
            ),
            Err(ContractError::SignatureInvalid)
        );
        assert_eq!(
            verify(
                canonical_signature(universal_signature),
                b"second message",
                identity_encoding
            ),
            Err(ContractError::SignatureInvalid)
        );
    }

    #[test]
    fn tampering_wrong_keys_and_invalid_public_keys_produce_no_evidence() {
        let protected = br#"{"decision_id":"fixture"}"#;
        let (signature, public_key, message) = signed_message(DECISION_DOMAIN, protected);
        let wrong_key = SigningKey::from_bytes(&[8_u8; 32])
            .verifying_key()
            .to_bytes();
        let mut tampered_signature = signature;
        tampered_signature[0] ^= 1;

        assert_eq!(
            verify(
                canonical_signature(tampered_signature),
                &message,
                public_key
            ),
            Err(ContractError::SignatureInvalid)
        );
        assert_eq!(
            verify(canonical_signature(signature), b"tampered", public_key),
            Err(ContractError::SignatureInvalid)
        );
        assert_eq!(
            verify(canonical_signature(signature), &message, wrong_key),
            Err(ContractError::SignatureInvalid)
        );
        let invalid_public_key = (0_u8..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|candidate| VerifyingKey::from_bytes(candidate).is_err())
            .expect("the compressed Edwards-Y space contains invalid encodings");
        assert_eq!(
            verify(canonical_signature(signature), &message, invalid_public_key),
            Err(ContractError::InvalidPublicKey)
        );
    }

    #[test]
    fn signature_message_is_exact_domain_then_protected_bytes() {
        let protected = br#"{"a":1}"#;

        assert_eq!(
            signature_message(GRANT_DOMAIN, protected),
            [GRANT_DOMAIN, protected].concat()
        );
    }

    #[test]
    fn key_material_and_fingerprint_debug_are_strictly_opaque() {
        let public_key = fixture_signing_key().verifying_key().to_bytes();
        let fingerprint = Sha256Digest::digest(&public_key);
        let evidence = VerifiedKeyEvidenceV1::new(fingerprint, VerificationKeyStatusV1::Current);

        let grant = format!(
            "{:?}",
            HumanRequestGrantVerificationKeyV1::current(public_key)
        );
        let lease = format!("{:?}", TaskLeaseVerificationKeyV1::current(public_key));
        let decision = format!(
            "{:?}",
            ApprovalDecisionVerificationKeyV1::current(public_key)
        );
        let evidence_debug = format!("{evidence:?}");
        let signature_debug = format!("{:?}", canonical_signature([0xa5_u8; 64]));
        let key_hex = hex(&public_key);

        assert_eq!(grant, "HumanRequestGrantVerificationKeyV1 { .. }");
        assert_eq!(lease, "TaskLeaseVerificationKeyV1 { .. }");
        assert_eq!(decision, "ApprovalDecisionVerificationKeyV1 { .. }");
        assert_eq!(evidence_debug, "VerifiedKeyEvidenceV1 { .. }");
        assert_eq!(signature_debug, "CanonicalEd25519SignatureV1 { .. }");
        for rendered in [&grant, &lease, &decision, &evidence_debug, &signature_debug] {
            assert!(!rendered.contains(&key_hex));
            assert!(!rendered.contains(&fingerprint.to_hex()));
        }
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
}
