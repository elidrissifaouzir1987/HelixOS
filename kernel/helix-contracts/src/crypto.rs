use crate::canonical::to_jcs_vec;
use crate::plan::{
    AuthenticPlanEnvelopeV1, PlanInputV1, PlanProtectedV1, RawSignedPlanEnvelopeV1,
    SignedPlanEnvelopeV1,
};
use crate::{ContractError, Result, Sha256Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};

const SIGNATURE_DOMAIN: &[u8] = b"HELIXOS\0PLAN-ENVELOPE\0V1\0";
const MAX_WIRE_BYTES: usize = 1_048_576;

pub trait Ed25519Signer {
    fn key_id(&self) -> &str;

    fn sign_ed25519(&self, message: &[u8]) -> Result<[u8; 64]>;
}

pub trait Ed25519KeyResolver {
    fn resolve_ed25519(&self, key_id: &str) -> Result<[u8; 32]>;
}

pub fn sign_plan_v1<S: Ed25519Signer>(
    input: PlanInputV1,
    signer: &S,
) -> Result<SignedPlanEnvelopeV1> {
    let protected = PlanProtectedV1::try_new(input, signer.key_id())?;
    sign_validated_protected_plan_v1(protected, signer)
}

pub fn sign_protected_plan_v1<S: Ed25519Signer>(
    protected: PlanProtectedV1,
    signer: &S,
) -> Result<SignedPlanEnvelopeV1> {
    protected.validate()?;
    sign_validated_protected_plan_v1(protected, signer)
}

fn sign_validated_protected_plan_v1<S: Ed25519Signer>(
    protected: PlanProtectedV1,
    signer: &S,
) -> Result<SignedPlanEnvelopeV1> {
    if protected.key_id() != signer.key_id() {
        return Err(ContractError::SignerKeyMismatch);
    }
    let protected_jcs = protected.canonical_bytes_after_validation()?;
    let plan_id = Sha256Digest::digest(&protected_jcs);
    let message = signature_message(&protected_jcs);
    let signature = signer
        .sign_ed25519(&message)
        .map_err(|_| ContractError::SigningFailed)?;
    Ok(SignedPlanEnvelopeV1::new(
        protected,
        plan_id,
        URL_SAFE_NO_PAD.encode(signature),
    ))
}

pub fn decode_and_verify_plan<R: Ed25519KeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<AuthenticPlanEnvelopeV1> {
    if wire.len() > MAX_WIRE_BYTES {
        return Err(ContractError::WireTooLarge {
            maximum: MAX_WIRE_BYTES,
        });
    }
    let signed = serde_json::from_slice::<RawSignedPlanEnvelopeV1>(wire)
        .map_err(ContractError::from)?
        .into_signed();
    let canonical_wire = to_jcs_vec(&signed)?;
    if canonical_wire != wire {
        return Err(ContractError::NonCanonicalWire);
    }
    signed.protected().validate()?;
    let protected_jcs = signed.protected().canonical_bytes_after_validation()?;
    let recomputed_id = Sha256Digest::digest(&protected_jcs);
    if recomputed_id != signed.plan_id() {
        return Err(ContractError::PlanIdMismatch);
    }
    let signature_bytes = decode_signature(signed.signature())?;
    let public_key_bytes = resolver.resolve_ed25519(signed.protected().key_id())?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| ContractError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signature_message(&protected_jcs), &signature)
        .map_err(|_| ContractError::SignatureInvalid)?;
    let verified_key_fingerprint = Sha256Digest::digest(&public_key_bytes);
    Ok(AuthenticPlanEnvelopeV1::new(
        signed,
        verified_key_fingerprint,
    ))
}

fn decode_signature(encoded: &str) -> Result<[u8; 64]> {
    if encoded.len() != 86
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ContractError::InvalidEncoding { kind: "signature" });
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ContractError::InvalidEncoding { kind: "signature" })?;
    if bytes.len() != 64 || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(ContractError::InvalidEncoding { kind: "signature" });
    }
    bytes
        .try_into()
        .map_err(|_| ContractError::InvalidEncoding { kind: "signature" })
}

fn signature_message(protected_jcs: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + protected_jcs.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(protected_jcs);
    message
}
