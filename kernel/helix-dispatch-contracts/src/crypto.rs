use crate::{ContractError, Result, Sha256Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationKeyStatusV1 {
    Current,
    Historical,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GrantVerificationKeyV1 {
    public_key: [u8; 32],
    status: VerificationKeyStatusV1,
}

impl std::fmt::Debug for GrantVerificationKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrantVerificationKeyV1")
            .finish_non_exhaustive()
    }
}

impl GrantVerificationKeyV1 {
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReceiptVerificationKeyV1 {
    public_key: [u8; 32],
    status: VerificationKeyStatusV1,
}

impl std::fmt::Debug for ReceiptVerificationKeyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceiptVerificationKeyV1")
            .finish_non_exhaustive()
    }
}

impl ReceiptVerificationKeyV1 {
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

pub trait GrantSigner {
    fn key_id(&self) -> &str;
    fn sign_execution_grant(&self, message: &[u8]) -> Result<[u8; 64]>;
}

pub trait GrantKeyResolver {
    fn resolve_grant_key(&self, key_id: &str) -> Result<GrantVerificationKeyV1>;
}

pub trait ReceiptSigner {
    fn key_id(&self) -> &str;
    fn sign_execution_receipt(&self, message: &[u8]) -> Result<[u8; 64]>;
}

pub trait ReceiptKeyResolver {
    fn resolve_receipt_key(&self, key_id: &str) -> Result<ReceiptVerificationKeyV1>;
}

pub(crate) fn encode_signature(signature: [u8; 64]) -> String {
    URL_SAFE_NO_PAD.encode(signature)
}

pub(crate) fn verify_grant_signature(
    encoded: &str,
    message: &[u8],
    key: GrantVerificationKeyV1,
) -> Result<(Sha256Digest, VerificationKeyStatusV1)> {
    verify(encoded, message, key.public_key).map(|digest| (digest, key.status))
}

pub(crate) fn verify_receipt_signature(
    encoded: &str,
    message: &[u8],
    key: ReceiptVerificationKeyV1,
) -> Result<(Sha256Digest, VerificationKeyStatusV1)> {
    verify(encoded, message, key.public_key).map(|digest| (digest, key.status))
}

fn verify(encoded: &str, message: &[u8], public_key: [u8; 32]) -> Result<Sha256Digest> {
    let signature = decode_signature(encoded)?;
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| ContractError::InvalidPublicKey)?;
    key.verify_strict(message, &Signature::from_bytes(&signature))
        .map_err(|_| ContractError::SignatureInvalid)?;
    Ok(Sha256Digest::digest(&public_key))
}

pub(crate) fn decode_signature(encoded: &str) -> Result<[u8; 64]> {
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
    decoded
        .try_into()
        .map_err(|_| ContractError::InvalidEncoding)
}

pub(crate) fn signature_message(domain: &[u8], protected: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + protected.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(protected);
    message
}
