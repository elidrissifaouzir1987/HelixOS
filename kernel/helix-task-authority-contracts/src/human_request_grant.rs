use crate::canonical::{decode_canonical_value, require_closed_object, to_jcs_vec};
use crate::crypto::{
    decode_signature, encode_signature, signature_message, verify_human_request_grant_signature,
    HumanRequestGrantKeyResolver, HumanRequestGrantSigner, VerificationKeyStatusV1,
};
use crate::validation::{Generation, Identifier, SafeU64};
use crate::{ContractError, Result, Sha256Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

const HUMAN_REQUEST_GRANT_SIGNATURE_DOMAIN: &[u8] = b"HELIXOS\0HUMAN-REQUEST-GRANT\0V1\0";
const MAX_HUMAN_REQUEST_GRANT_WIRE_BYTES: usize = 65_536;

const OUTER_FIELDS: &[&str] = &["protected", "grant_digest", "signature"];
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

/// Request-surface-owned, typed input for one protected human-request grant.
///
/// This value is deliberately not serializable and carries no signing authority.
pub struct HumanRequestGrantInputV1 {
    pub grant_id: Sha256Digest,
    pub issuer_id: Identifier,
    pub audience: Identifier,
    pub principal_id: Identifier,
    pub message_digest: Sha256Digest,
    pub channel_id: Identifier,
    pub session_id: Identifier,
    pub scope_template_id: Identifier,
    pub scope_template_digest: Sha256Digest,
    pub scope_template_generation: Generation,
    pub issued_at_utc_ms: SafeU64,
    pub expires_at_utc_ms: SafeU64,
}

impl fmt::Debug for HumanRequestGrantInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanRequestGrantInputV1")
            .finish_non_exhaustive()
    }
}

/// Closed, typed protected content for `helixos.human-request-grant/1`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanRequestGrantProtectedV1 {
    schema: String,
    digest_algorithm: String,
    signature_algorithm: String,
    key_purpose: String,
    key_id: Identifier,
    grant_id: Sha256Digest,
    issuer_id: Identifier,
    audience: Identifier,
    principal_id: Identifier,
    message_digest: Sha256Digest,
    channel_id: Identifier,
    session_id: Identifier,
    scope_template_id: Identifier,
    scope_template_digest: Sha256Digest,
    scope_template_generation: Generation,
    issued_at_utc_ms: SafeU64,
    expires_at_utc_ms: SafeU64,
}

impl fmt::Debug for HumanRequestGrantProtectedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanRequestGrantProtectedV1")
            .finish_non_exhaustive()
    }
}

impl HumanRequestGrantProtectedV1 {
    pub fn try_new(input: HumanRequestGrantInputV1, key_id: Identifier) -> Result<Self> {
        let protected = Self {
            schema: "helixos.human-request-grant/1".to_owned(),
            digest_algorithm: "sha-256".to_owned(),
            signature_algorithm: "ed25519".to_owned(),
            key_purpose: "request-surface-grant-signing".to_owned(),
            key_id,
            grant_id: input.grant_id,
            issuer_id: input.issuer_id,
            audience: input.audience,
            principal_id: input.principal_id,
            message_digest: input.message_digest,
            channel_id: input.channel_id,
            session_id: input.session_id,
            scope_template_id: input.scope_template_id,
            scope_template_digest: input.scope_template_digest,
            scope_template_generation: input.scope_template_generation,
            issued_at_utc_ms: input.issued_at_utc_ms,
            expires_at_utc_ms: input.expires_at_utc_ms,
        };
        protected.validate()?;
        Ok(protected)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "helixos.human-request-grant/1" {
            return Err(ContractError::UnsupportedSchema);
        }
        if self.digest_algorithm != "sha-256" {
            return Err(ContractError::UnsupportedDigestAlgorithm);
        }
        if self.signature_algorithm != "ed25519" {
            return Err(ContractError::UnsupportedSignatureAlgorithm);
        }
        if self.key_purpose != "request-surface-grant-signing" {
            return Err(ContractError::WrongKeyPurpose);
        }
        if self.issued_at_utc_ms.get() >= self.expires_at_utc_ms.get() {
            return Err(ContractError::InvalidField);
        }
        Ok(())
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn digest_algorithm(&self) -> &str {
        &self.digest_algorithm
    }

    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    pub fn key_purpose(&self) -> &str {
        &self.key_purpose
    }

    pub fn key_id(&self) -> &str {
        self.key_id.as_str()
    }

    pub const fn grant_id(&self) -> Sha256Digest {
        self.grant_id
    }

    pub fn issuer_id(&self) -> &str {
        self.issuer_id.as_str()
    }

    pub fn audience(&self) -> &str {
        self.audience.as_str()
    }

    pub fn principal_id(&self) -> &str {
        self.principal_id.as_str()
    }

    pub const fn message_digest(&self) -> Sha256Digest {
        self.message_digest
    }

    pub fn channel_id(&self) -> &str {
        self.channel_id.as_str()
    }

    pub fn session_id(&self) -> &str {
        self.session_id.as_str()
    }

    pub fn scope_template_id(&self) -> &str {
        self.scope_template_id.as_str()
    }

    pub const fn scope_template_digest(&self) -> Sha256Digest {
        self.scope_template_digest
    }

    pub const fn scope_template_generation(&self) -> u64 {
        self.scope_template_generation.get()
    }

    pub const fn issued_at_utc_ms(&self) -> u64 {
        self.issued_at_utc_ms.get()
    }

    pub const fn expires_at_utc_ms(&self) -> u64 {
        self.expires_at_utc_ms.get()
    }
}

/// Opaque signed HumanRequestGrant v1 evidence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHumanRequestGrantV1 {
    protected: HumanRequestGrantProtectedV1,
    grant_digest: Sha256Digest,
    signature: String,
}

impl fmt::Debug for SignedHumanRequestGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedHumanRequestGrantV1")
            .finish_non_exhaustive()
    }
}

impl SignedHumanRequestGrantV1 {
    pub fn protected(&self) -> &HumanRequestGrantProtectedV1 {
        &self.protected
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant_digest
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.protected.validate()?;
        to_jcs_vec(self)
    }
}

/// Signature-verified grant whose verification key is currently trusted.
///
/// This linear verifier result is still not sufficient for consumption: the authority
/// core must separately recheck context, expiry, scope, revocation and one-shot state.
pub struct AuthenticHumanRequestGrantV1 {
    signed: SignedHumanRequestGrantV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

impl fmt::Debug for AuthenticHumanRequestGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticHumanRequestGrantV1")
            .finish_non_exhaustive()
    }
}

impl AuthenticHumanRequestGrantV1 {
    pub fn protected(&self) -> &HumanRequestGrantProtectedV1 {
        &self.signed.protected
    }

    pub fn claims(&self) -> HumanRequestGrantClaimsV1<'_> {
        HumanRequestGrantClaimsV1 { grant: self }
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.signed.grant_digest
    }

    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.verified_key_fingerprint
    }

    pub const fn verification_key_status(&self) -> VerificationKeyStatusV1 {
        self.verification_key_status
    }

    pub fn canonical_signed_envelope_bytes(&self) -> Result<Vec<u8>> {
        self.signed.to_canonical_json()
    }
}

/// Read-only protected bindings projected from a grant verified with a current key.
#[derive(Clone, Copy)]
pub struct HumanRequestGrantClaimsV1<'grant> {
    grant: &'grant AuthenticHumanRequestGrantV1,
}

impl fmt::Debug for HumanRequestGrantClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanRequestGrantClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'grant> HumanRequestGrantClaimsV1<'grant> {
    fn protected(&self) -> &'grant HumanRequestGrantProtectedV1 {
        &self.grant.signed.protected
    }

    pub fn schema(&self) -> &'grant str {
        self.protected().schema()
    }

    pub fn digest_algorithm(&self) -> &'grant str {
        self.protected().digest_algorithm()
    }

    pub fn signature_algorithm(&self) -> &'grant str {
        self.protected().signature_algorithm()
    }

    pub fn key_purpose(&self) -> &'grant str {
        self.protected().key_purpose()
    }

    pub fn key_id(&self) -> &'grant str {
        self.protected().key_id()
    }

    pub const fn grant_id(&self) -> Sha256Digest {
        self.grant.signed.protected.grant_id
    }

    pub fn issuer_id(&self) -> &'grant str {
        self.protected().issuer_id()
    }

    pub fn audience(&self) -> &'grant str {
        self.protected().audience()
    }

    pub fn principal_id(&self) -> &'grant str {
        self.protected().principal_id()
    }

    pub const fn message_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.message_digest
    }

    pub fn channel_id(&self) -> &'grant str {
        self.protected().channel_id()
    }

    pub fn session_id(&self) -> &'grant str {
        self.protected().session_id()
    }

    pub fn scope_template_id(&self) -> &'grant str {
        self.protected().scope_template_id()
    }

    pub const fn scope_template_digest(&self) -> Sha256Digest {
        self.grant.signed.protected.scope_template_digest
    }

    pub const fn scope_template_generation(&self) -> u64 {
        self.grant.signed.protected.scope_template_generation.get()
    }

    pub const fn issued_at_utc_ms(&self) -> u64 {
        self.grant.signed.protected.issued_at_utc_ms.get()
    }

    pub const fn expires_at_utc_ms(&self) -> u64 {
        self.grant.signed.protected.expires_at_utc_ms.get()
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.grant.signed.grant_digest
    }
}

/// Signature-verified retained grant bytes with no current-consumption authority.
pub struct RetainedHumanRequestGrantEvidenceV1 {
    signed: SignedHumanRequestGrantV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

impl fmt::Debug for RetainedHumanRequestGrantEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedHumanRequestGrantEvidenceV1")
            .finish_non_exhaustive()
    }
}

impl RetainedHumanRequestGrantEvidenceV1 {
    pub fn protected(&self) -> &HumanRequestGrantProtectedV1 {
        &self.signed.protected
    }

    pub fn claims(&self) -> RetainedHumanRequestGrantClaimsV1<'_> {
        RetainedHumanRequestGrantClaimsV1 { evidence: self }
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.signed.grant_digest
    }

    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.verified_key_fingerprint
    }

    pub const fn verification_key_status(&self) -> VerificationKeyStatusV1 {
        self.verification_key_status
    }

    pub fn canonical_signed_envelope_bytes(&self) -> Result<Vec<u8>> {
        self.signed.to_canonical_json()
    }
}

/// Read-only correlation claims from retained grant evidence.
///
/// This projection is intentionally a different type from [`HumanRequestGrantClaimsV1`]
/// and cannot create current grant authority after key rotation.
#[derive(Clone, Copy)]
pub struct RetainedHumanRequestGrantClaimsV1<'evidence> {
    evidence: &'evidence RetainedHumanRequestGrantEvidenceV1,
}

impl fmt::Debug for RetainedHumanRequestGrantClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedHumanRequestGrantClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'evidence> RetainedHumanRequestGrantClaimsV1<'evidence> {
    fn protected(&self) -> &'evidence HumanRequestGrantProtectedV1 {
        &self.evidence.signed.protected
    }

    pub fn schema(&self) -> &'evidence str {
        self.protected().schema()
    }

    pub fn digest_algorithm(&self) -> &'evidence str {
        self.protected().digest_algorithm()
    }

    pub fn signature_algorithm(&self) -> &'evidence str {
        self.protected().signature_algorithm()
    }

    pub fn key_purpose(&self) -> &'evidence str {
        self.protected().key_purpose()
    }

    pub fn key_id(&self) -> &'evidence str {
        self.protected().key_id()
    }

    pub const fn grant_id(&self) -> Sha256Digest {
        self.evidence.signed.protected.grant_id
    }

    pub fn issuer_id(&self) -> &'evidence str {
        self.protected().issuer_id()
    }

    pub fn audience(&self) -> &'evidence str {
        self.protected().audience()
    }

    pub fn principal_id(&self) -> &'evidence str {
        self.protected().principal_id()
    }

    pub const fn message_digest(&self) -> Sha256Digest {
        self.evidence.signed.protected.message_digest
    }

    pub fn channel_id(&self) -> &'evidence str {
        self.protected().channel_id()
    }

    pub fn session_id(&self) -> &'evidence str {
        self.protected().session_id()
    }

    pub fn scope_template_id(&self) -> &'evidence str {
        self.protected().scope_template_id()
    }

    pub const fn scope_template_digest(&self) -> Sha256Digest {
        self.evidence.signed.protected.scope_template_digest
    }

    pub const fn scope_template_generation(&self) -> u64 {
        self.evidence
            .signed
            .protected
            .scope_template_generation
            .get()
    }

    pub const fn issued_at_utc_ms(&self) -> u64 {
        self.evidence.signed.protected.issued_at_utc_ms.get()
    }

    pub const fn expires_at_utc_ms(&self) -> u64 {
        self.evidence.signed.protected.expires_at_utc_ms.get()
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.evidence.signed.grant_digest
    }
}

pub fn sign_human_request_grant_v1<S: HumanRequestGrantSigner>(
    protected: HumanRequestGrantProtectedV1,
    signer: &S,
) -> Result<SignedHumanRequestGrantV1> {
    protected.validate()?;
    if protected.key_id() != signer.key_id() {
        return Err(ContractError::WrongKeyPurpose);
    }
    let protected_bytes = to_jcs_vec(&protected)?;
    let grant_digest = Sha256Digest::digest(&protected_bytes);
    let signature = signer
        .sign_human_request_grant(&signature_message(
            HUMAN_REQUEST_GRANT_SIGNATURE_DOMAIN,
            &protected_bytes,
        ))
        .map_err(|_| ContractError::SigningFailed)?;
    Ok(SignedHumanRequestGrantV1 {
        protected,
        grant_digest,
        signature: encode_signature(signature),
    })
}

pub fn decode_and_verify_human_request_grant_v1<R: HumanRequestGrantKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<AuthenticHumanRequestGrantV1> {
    let verified = decode_verified_human_request_grant_v1(wire, resolver)?;
    if verified.verification_key_status != VerificationKeyStatusV1::Current {
        return Err(ContractError::HistoricalKeyNotAuthority);
    }
    Ok(AuthenticHumanRequestGrantV1 {
        signed: verified.signed,
        verified_key_fingerprint: verified.verified_key_fingerprint,
        verification_key_status: verified.verification_key_status,
    })
}

pub fn decode_and_verify_retained_human_request_grant_v1<R: HumanRequestGrantKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<RetainedHumanRequestGrantEvidenceV1> {
    let verified = decode_verified_human_request_grant_v1(wire, resolver)?;
    Ok(RetainedHumanRequestGrantEvidenceV1 {
        signed: verified.signed,
        verified_key_fingerprint: verified.verified_key_fingerprint,
        verification_key_status: verified.verification_key_status,
    })
}

struct VerifiedHumanRequestGrantV1 {
    signed: SignedHumanRequestGrantV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

fn decode_verified_human_request_grant_v1<R: HumanRequestGrantKeyResolver>(
    wire: &[u8],
    resolver: &R,
) -> Result<VerifiedHumanRequestGrantV1> {
    let value = decode_canonical_value(wire, MAX_HUMAN_REQUEST_GRANT_WIRE_BYTES)?;
    preflight_human_request_grant(&value)?;
    let signed: SignedHumanRequestGrantV1 =
        serde_json::from_value(value).map_err(|_| ContractError::InvalidField)?;
    signed.protected.validate()?;
    let protected_bytes = to_jcs_vec(&signed.protected)?;
    if Sha256Digest::digest(&protected_bytes) != signed.grant_digest {
        return Err(ContractError::DigestMismatch);
    }
    let signature = decode_signature(&signed.signature)?;
    let key = resolver.resolve_human_request_grant_key(signed.protected.key_id())?;
    let evidence = verify_human_request_grant_signature(
        signature,
        &signature_message(HUMAN_REQUEST_GRANT_SIGNATURE_DOMAIN, &protected_bytes),
        key,
    )?;
    Ok(VerifiedHumanRequestGrantV1 {
        signed,
        verified_key_fingerprint: evidence.fingerprint(),
        verification_key_status: evidence.status(),
    })
}

fn preflight_human_request_grant(value: &Value) -> Result<()> {
    require_closed_object(value, OUTER_FIELDS, true)?;
    let protected = value
        .get("protected")
        .ok_or(ContractError::MissingOuterField)?;
    require_closed_object(protected, PROTECTED_FIELDS, false)?;
    match protected.get("schema").and_then(Value::as_str) {
        Some("helixos.human-request-grant/1") => {}
        Some(_) => return Err(ContractError::UnsupportedSchema),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("digest_algorithm").and_then(Value::as_str) {
        Some("sha-256") => {}
        Some(_) => return Err(ContractError::UnsupportedDigestAlgorithm),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("signature_algorithm").and_then(Value::as_str) {
        Some("ed25519") => {}
        Some(_) => return Err(ContractError::UnsupportedSignatureAlgorithm),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("key_purpose").and_then(Value::as_str) {
        Some("request-surface-grant-signing") => {}
        Some(_) => return Err(ContractError::WrongKeyPurpose),
        None => return Err(ContractError::InvalidField),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::json;
    use std::cell::Cell;

    const KEY_ID: &str = "request-key-v1";

    struct FixtureSigner(SigningKey);

    impl HumanRequestGrantSigner for FixtureSigner {
        fn key_id(&self) -> &str {
            KEY_ID
        }

        fn sign_human_request_grant(&self, message: &[u8]) -> Result<[u8; 64]> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    struct FixtureResolver {
        public_key: [u8; 32],
        status: VerificationKeyStatusV1,
        calls: Cell<usize>,
    }

    impl HumanRequestGrantKeyResolver for FixtureResolver {
        fn resolve_human_request_grant_key(
            &self,
            key_id: &str,
        ) -> Result<crate::HumanRequestGrantVerificationKeyV1> {
            self.calls.set(self.calls.get() + 1);
            if key_id != KEY_ID {
                return Err(ContractError::UnknownKey);
            }
            Ok(match self.status {
                VerificationKeyStatusV1::Current => {
                    crate::HumanRequestGrantVerificationKeyV1::current(self.public_key)
                }
                VerificationKeyStatusV1::Historical => {
                    crate::HumanRequestGrantVerificationKeyV1::historical(self.public_key)
                }
            })
        }
    }

    fn signer() -> FixtureSigner {
        FixtureSigner(SigningKey::from_bytes(&[7_u8; 32]))
    }

    fn input(issued_at_utc_ms: u64, expires_at_utc_ms: u64) -> HumanRequestGrantInputV1 {
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
            issued_at_utc_ms: SafeU64::new(issued_at_utc_ms).unwrap(),
            expires_at_utc_ms: SafeU64::new(expires_at_utc_ms).unwrap(),
        }
    }

    fn signed_wire() -> (Vec<u8>, [u8; 32]) {
        let signer = signer();
        let protected = HumanRequestGrantProtectedV1::try_new(
            input(1_000, 2_000),
            Identifier::new(KEY_ID).unwrap(),
        )
        .unwrap();
        let signed = sign_human_request_grant_v1(protected, &signer).unwrap();
        (
            signed.to_canonical_json().unwrap(),
            signer.0.verifying_key().to_bytes(),
        )
    }

    fn resolver(public_key: [u8; 32], status: VerificationKeyStatusV1) -> FixtureResolver {
        FixtureResolver {
            public_key,
            status,
            calls: Cell::new(0),
        }
    }

    #[test]
    fn current_round_trip_projects_every_context_binding_and_exact_bytes() {
        let (wire, public_key) = signed_wire();
        let resolver = resolver(public_key, VerificationKeyStatusV1::Current);

        let grant = decode_and_verify_human_request_grant_v1(&wire, &resolver).unwrap();
        let claims = grant.claims();

        assert_eq!(resolver.calls.get(), 1);
        assert_eq!(claims.schema(), "helixos.human-request-grant/1");
        assert_eq!(claims.digest_algorithm(), "sha-256");
        assert_eq!(claims.signature_algorithm(), "ed25519");
        assert_eq!(claims.key_purpose(), "request-surface-grant-signing");
        assert_eq!(claims.key_id(), KEY_ID);
        assert_eq!(claims.grant_id(), Sha256Digest::from_bytes([0x10; 32]));
        assert_eq!(claims.issuer_id(), "request-surface-v1");
        assert_eq!(claims.audience(), "helixos-core-v1");
        assert_eq!(claims.principal_id(), "principal-v1");
        assert_eq!(
            claims.message_digest(),
            Sha256Digest::from_bytes([0x20; 32])
        );
        assert_eq!(claims.channel_id(), "channel-v1");
        assert_eq!(claims.session_id(), "session-v1");
        assert_eq!(claims.scope_template_id(), "scope-v1");
        assert_eq!(
            claims.scope_template_digest(),
            Sha256Digest::from_bytes([0x30; 32])
        );
        assert_eq!(claims.scope_template_generation(), 7);
        assert_eq!(claims.issued_at_utc_ms(), 1_000);
        assert_eq!(claims.expires_at_utc_ms(), 2_000);
        assert_eq!(claims.grant_digest(), grant.grant_digest());
        assert_eq!(
            grant.verification_key_status(),
            VerificationKeyStatusV1::Current
        );
        assert_eq!(grant.canonical_signed_envelope_bytes().unwrap(), wire);
    }

    #[test]
    fn historical_key_is_retained_evidence_but_not_current_authenticity() {
        let (wire, public_key) = signed_wire();
        let current_decoder = resolver(public_key, VerificationKeyStatusV1::Historical);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(&wire, &current_decoder)
                .expect_err("historical key cannot create current authenticity"),
            ContractError::HistoricalKeyNotAuthority
        );

        let retained_decoder = resolver(public_key, VerificationKeyStatusV1::Historical);
        let retained =
            decode_and_verify_retained_human_request_grant_v1(&wire, &retained_decoder).unwrap();
        assert_eq!(
            retained.verification_key_status(),
            VerificationKeyStatusV1::Historical
        );
        assert_eq!(
            retained.claims().grant_id(),
            Sha256Digest::from_bytes([0x10; 32])
        );
        assert_eq!(retained.canonical_signed_envelope_bytes().unwrap(), wire);
    }

    #[test]
    fn local_time_relation_is_strict_without_reading_ambient_time() {
        for (issued, expires) in [(1_000, 1_000), (1_001, 1_000)] {
            assert_eq!(
                HumanRequestGrantProtectedV1::try_new(
                    input(issued, expires),
                    Identifier::new(KEY_ID).unwrap(),
                ),
                Err(ContractError::InvalidField)
            );
        }
        HumanRequestGrantProtectedV1::try_new(input(0, 1), Identifier::new(KEY_ID).unwrap())
            .expect("zero issue time is valid when the exclusive expiry is later");
    }

    #[test]
    fn missing_digest_and_signature_encoding_fail_before_key_resolution() {
        let (wire, public_key) = signed_wire();
        let value: Value = serde_json::from_slice(&wire).unwrap();

        let mut missing = value.clone();
        missing["protected"]
            .as_object_mut()
            .unwrap()
            .remove("audience");
        let missing_resolver = resolver(public_key, VerificationKeyStatusV1::Current);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(
                &to_jcs_vec(&missing).unwrap(),
                &missing_resolver,
            )
            .expect_err("missing protected member must deny"),
            ContractError::MissingRequiredField
        );
        assert_eq!(missing_resolver.calls.get(), 0);

        let mut digest_mismatch = value.clone();
        digest_mismatch["protected"]["audience"] = json!("other-core-v1");
        let digest_resolver = resolver(public_key, VerificationKeyStatusV1::Current);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(
                &to_jcs_vec(&digest_mismatch).unwrap(),
                &digest_resolver,
            )
            .expect_err("protected mutation must change its digest"),
            ContractError::DigestMismatch
        );
        assert_eq!(digest_resolver.calls.get(), 0);

        let mut invalid_signature = value;
        invalid_signature["signature"] = json!("A".repeat(85));
        let signature_resolver = resolver(public_key, VerificationKeyStatusV1::Current);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(
                &to_jcs_vec(&invalid_signature).unwrap(),
                &signature_resolver,
            )
            .expect_err("signature encoding is checked before resolution"),
            ContractError::InvalidEncoding
        );
        assert_eq!(signature_resolver.calls.get(), 0);
    }

    #[test]
    fn all_seventeen_protected_members_are_required() {
        let (wire, public_key) = signed_wire();
        let base: Value = serde_json::from_slice(&wire).unwrap();

        assert_eq!(PROTECTED_FIELDS.len(), 17);
        for field in PROTECTED_FIELDS {
            let mut missing = base.clone();
            missing["protected"].as_object_mut().unwrap().remove(*field);
            let resolver = resolver(public_key, VerificationKeyStatusV1::Current);
            assert_eq!(
                decode_and_verify_human_request_grant_v1(
                    &to_jcs_vec(&missing).unwrap(),
                    &resolver,
                )
                .expect_err("every protected member is required"),
                ContractError::MissingRequiredField,
                "{field}"
            );
            assert_eq!(resolver.calls.get(), 0, "{field}");
        }
    }

    #[test]
    fn complete_wire_limit_is_checked_before_json_shape() {
        let at_limit =
            serde_json::to_vec(&"a".repeat(MAX_HUMAN_REQUEST_GRANT_WIRE_BYTES - 2)).unwrap();
        assert_eq!(at_limit.len(), MAX_HUMAN_REQUEST_GRANT_WIRE_BYTES);
        let resolver = resolver([0_u8; 32], VerificationKeyStatusV1::Current);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(&at_limit, &resolver)
                .expect_err("a scalar is not an envelope"),
            ContractError::InvalidField
        );

        let over_limit =
            serde_json::to_vec(&"a".repeat(MAX_HUMAN_REQUEST_GRANT_WIRE_BYTES - 1)).unwrap();
        assert_eq!(over_limit.len(), MAX_HUMAN_REQUEST_GRANT_WIRE_BYTES + 1);
        assert_eq!(
            decode_and_verify_human_request_grant_v1(&over_limit, &resolver)
                .expect_err("size must be the first rejection"),
            ContractError::WireTooLarge
        );
        assert_eq!(resolver.calls.get(), 0);
    }

    #[test]
    fn debug_surfaces_are_bounded_and_opaque() {
        let (wire, public_key) = signed_wire();
        let resolver = resolver(public_key, VerificationKeyStatusV1::Current);
        let authentic = decode_and_verify_human_request_grant_v1(&wire, &resolver).unwrap();

        assert_eq!(
            format!("{:?}", authentic.protected()),
            "HumanRequestGrantProtectedV1 { .. }"
        );
        assert_eq!(
            format!("{:?}", authentic.claims()),
            "HumanRequestGrantClaimsV1 { .. }"
        );
        assert_eq!(
            format!("{authentic:?}"),
            "AuthenticHumanRequestGrantV1 { .. }"
        );
    }
}
