//! Immutable verification-key history, current trust and append-only revocations.

#![allow(dead_code)] // Foundation consumed by T033/T036 mutation and projection paths.

use crate::event::{
    latest_generation_v1, map_insert_error_v1, sql_integer_v1, verify_related_event_v1,
    AuthorityEventKindV1, AuthorityEventReasonV1, AuthorityEventResultV1,
    AuthorityEventSubjectKindV1, AuthorityHistoryErrorV1,
};
use ed25519_dalek::VerifyingKey;
use helix_task_authority::{
    AuthorityKeyStatusReasonV1, AuthorityKeyStatusV1, AuthorityRevocationReasonV1,
    AuthorityRevocationSubjectKindV1, AuthoritySignerPurposeV1,
};
use helix_task_authority_contracts::{Generation, Identifier, SafeU64, Sha256Digest};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::fmt;

const KEY_EVENT_REFERENCE_DOMAIN_V1: &[u8] = b"HELIXOS\0TASK-AUTHORITY-KEY-EVENT-REFERENCE\0V1\0";
const REVOCATION_EVENT_REFERENCE_DOMAIN_V1: &[u8] =
    b"HELIXOS\0TASK-AUTHORITY-REVOCATION-EVENT-REFERENCE\0V1\0";

/// Immutable candidate public verification key.  Private signing material is never
/// accepted by this adapter.
pub(crate) struct AuthorityVerificationKeyCandidateV1 {
    purpose: AuthoritySignerPurposeV1,
    key_id: Identifier,
    issuer_id: Identifier,
    public_key: [u8; 32],
    public_key_fingerprint: Sha256Digest,
    provenance_digest: Sha256Digest,
    introduced_generation: Generation,
}

impl AuthorityVerificationKeyCandidateV1 {
    pub(crate) fn try_new(
        purpose: AuthoritySignerPurposeV1,
        key_id: Identifier,
        issuer_id: Identifier,
        public_key: [u8; 32],
        provenance_digest: Sha256Digest,
        introduced_generation: Generation,
    ) -> Result<Self, AuthorityHistoryErrorV1> {
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| AuthorityHistoryErrorV1::InvalidRecord)?;
        Ok(Self {
            purpose,
            key_id,
            issuer_id,
            public_key,
            public_key_fingerprint: Sha256Digest::digest(&public_key),
            provenance_digest,
            introduced_generation,
        })
    }

    pub(crate) fn event_subject_reference_digest_v1(&self) -> Sha256Digest {
        verification_key_event_reference_digest_v1(self.purpose, &self.key_id)
    }
}

impl fmt::Debug for AuthorityVerificationKeyCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityVerificationKeyCandidateV1(..)")
    }
}

/// Strictly decoded retained public-key history row.
pub(crate) struct AuthorityVerificationKeyRecordV1 {
    purpose: AuthoritySignerPurposeV1,
    key_id: Identifier,
    issuer_id: Identifier,
    public_key: [u8; 32],
    public_key_fingerprint: Sha256Digest,
    provenance_digest: Sha256Digest,
    introduced_generation: Generation,
}

impl AuthorityVerificationKeyRecordV1 {
    pub(crate) const fn purpose_v1(&self) -> AuthoritySignerPurposeV1 {
        self.purpose
    }

    pub(crate) fn key_id_v1(&self) -> &str {
        self.key_id.as_str()
    }

    pub(crate) fn issuer_id_v1(&self) -> &str {
        self.issuer_id.as_str()
    }

    pub(crate) const fn public_key_v1(&self) -> [u8; 32] {
        self.public_key
    }

    pub(crate) const fn public_key_fingerprint_v1(&self) -> Sha256Digest {
        self.public_key_fingerprint
    }

    pub(crate) const fn provenance_digest_v1(&self) -> Sha256Digest {
        self.provenance_digest
    }

    pub(crate) const fn introduced_generation_v1(&self) -> Generation {
        self.introduced_generation
    }

    fn exactly_matches_candidate_v1(
        &self,
        candidate: &AuthorityVerificationKeyCandidateV1,
    ) -> bool {
        self.purpose == candidate.purpose
            && self.key_id == candidate.key_id
            && self.issuer_id == candidate.issuer_id
            && self.public_key == candidate.public_key
            && self.public_key_fingerprint == candidate.public_key_fingerprint
            && self.provenance_digest == candidate.provenance_digest
            && self.introduced_generation == candidate.introduced_generation
    }
}

impl fmt::Debug for AuthorityVerificationKeyRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityVerificationKeyRecordV1(..)")
    }
}

/// Duplicate-aware result.  A key ID can never be rebound to another purpose or key.
pub(crate) enum AuthorityVerificationKeyRetentionV1 {
    Introduced(AuthorityVerificationKeyRecordV1),
    PriorExact(AuthorityVerificationKeyRecordV1),
    IdentityConflict,
}

impl fmt::Debug for AuthorityVerificationKeyRetentionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Introduced(_) => {
                formatter.write_str("AuthorityVerificationKeyRetentionV1::Introduced(..)")
            }
            Self::PriorExact(_) => {
                formatter.write_str("AuthorityVerificationKeyRetentionV1::PriorExact(..)")
            }
            Self::IdentityConflict => {
                formatter.write_str("AuthorityVerificationKeyRetentionV1::IdentityConflict")
            }
        }
    }
}

pub(crate) fn retain_verification_key_v1(
    transaction: &Transaction<'_>,
    candidate: AuthorityVerificationKeyCandidateV1,
) -> Result<AuthorityVerificationKeyRetentionV1, AuthorityHistoryErrorV1> {
    if let Some(existing) = read_verification_key_by_id_v1(transaction, candidate.key_id.as_str())?
    {
        return Ok(if existing.exactly_matches_candidate_v1(&candidate) {
            AuthorityVerificationKeyRetentionV1::PriorExact(existing)
        } else {
            AuthorityVerificationKeyRetentionV1::IdentityConflict
        });
    }

    let fingerprint = candidate.public_key_fingerprint.to_hex();
    let fingerprint_exists = transaction
        .query_row(
            "SELECT 1 FROM authority_verification_keys WHERE public_key_fingerprint = ?1",
            [&fingerprint],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?
        .is_some();
    if fingerprint_exists {
        return Ok(AuthorityVerificationKeyRetentionV1::IdentityConflict);
    }

    transaction
        .execute(
            "INSERT INTO authority_verification_keys (
                key_purpose, key_id, issuer_id, algorithm, public_key,
                public_key_fingerprint, provenance_digest, introduced_generation
             ) VALUES (?1, ?2, ?3, 'ed25519', ?4, ?5, ?6, ?7)",
            params![
                candidate.purpose.code_v1(),
                candidate.key_id.as_str(),
                candidate.issuer_id.as_str(),
                &candidate.public_key[..],
                fingerprint,
                candidate.provenance_digest.to_hex(),
                sql_integer_v1(candidate.introduced_generation.get())?,
            ],
        )
        .map_err(map_insert_error_v1)?;

    Ok(AuthorityVerificationKeyRetentionV1::Introduced(
        AuthorityVerificationKeyRecordV1 {
            purpose: candidate.purpose,
            key_id: candidate.key_id,
            issuer_id: candidate.issuer_id,
            public_key: candidate.public_key,
            public_key_fingerprint: candidate.public_key_fingerprint,
            provenance_digest: candidate.provenance_digest,
            introduced_generation: candidate.introduced_generation,
        },
    ))
}

/// One append-only status transition for an immutable public-key identity.
pub(crate) struct AuthorityKeyStatusCandidateV1 {
    key_status_event_id: Sha256Digest,
    purpose: AuthoritySignerPurposeV1,
    key_id: Identifier,
    status: AuthorityKeyStatusV1,
    effective_at_utc_ms: SafeU64,
    trust_generation: Generation,
    attempt_id: Sha256Digest,
    reason: AuthorityKeyStatusReasonV1,
    event_id: Sha256Digest,
}

impl AuthorityKeyStatusCandidateV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        key_status_event_id: Sha256Digest,
        purpose: AuthoritySignerPurposeV1,
        key_id: Identifier,
        status: AuthorityKeyStatusV1,
        effective_at_utc_ms: SafeU64,
        trust_generation: Generation,
        attempt_id: Sha256Digest,
        reason: AuthorityKeyStatusReasonV1,
        event_id: Sha256Digest,
    ) -> Self {
        Self {
            key_status_event_id,
            purpose,
            key_id,
            status,
            effective_at_utc_ms,
            trust_generation,
            attempt_id,
            reason,
            event_id,
        }
    }

    pub(crate) fn event_subject_reference_digest_v1(&self) -> Sha256Digest {
        verification_key_event_reference_digest_v1(self.purpose, &self.key_id)
    }
}

impl fmt::Debug for AuthorityKeyStatusCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityKeyStatusCandidateV1(..)")
    }
}

/// Current status derived exclusively from the newest valid append-only event.
pub(crate) struct AuthorityCurrentKeyStatusV1 {
    key: AuthorityVerificationKeyRecordV1,
    status: AuthorityKeyStatusV1,
    effective_at_utc_ms: SafeU64,
    trust_generation: Generation,
    reason: AuthorityKeyStatusReasonV1,
}

impl AuthorityCurrentKeyStatusV1 {
    pub(crate) const fn key_v1(&self) -> &AuthorityVerificationKeyRecordV1 {
        &self.key
    }

    pub(crate) const fn status_v1(&self) -> AuthorityKeyStatusV1 {
        self.status
    }

    pub(crate) const fn is_current_trusted_v1(&self) -> bool {
        matches!(self.status, AuthorityKeyStatusV1::Trusted)
    }

    pub(crate) const fn effective_at_utc_ms_v1(&self) -> SafeU64 {
        self.effective_at_utc_ms
    }

    pub(crate) const fn trust_generation_v1(&self) -> Generation {
        self.trust_generation
    }

    pub(crate) const fn reason_v1(&self) -> AuthorityKeyStatusReasonV1 {
        self.reason
    }
}

impl fmt::Debug for AuthorityCurrentKeyStatusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityCurrentKeyStatusV1(..)")
    }
}

pub(crate) fn append_key_status_v1(
    transaction: &Transaction<'_>,
    candidate: AuthorityKeyStatusCandidateV1,
) -> Result<AuthorityCurrentKeyStatusV1, AuthorityHistoryErrorV1> {
    let key = read_verification_key_by_id_v1(transaction, candidate.key_id.as_str())?
        .ok_or(AuthorityHistoryErrorV1::MissingKey)?;
    if key.purpose != candidate.purpose {
        return Err(AuthorityHistoryErrorV1::IdentityConflict);
    }
    validate_status_reason_v1(candidate.status, candidate.reason)?;

    let prior = read_latest_status_row_v1(transaction, candidate.purpose, &candidate.key_id)?;
    validate_key_status_transition_v1(prior.as_ref(), &candidate)?;
    if latest_generation_v1(
        transaction,
        "SELECT MAX(trust_generation) FROM authority_key_status_events",
    )?
    .is_some_and(|generation| candidate.trust_generation.get() <= generation)
    {
        return Err(AuthorityHistoryErrorV1::GenerationNotIncreasing);
    }

    let subject_reference = candidate.event_subject_reference_digest_v1();
    verify_related_event_v1(
        transaction,
        candidate.event_id,
        candidate.attempt_id,
        AuthorityEventKindV1::KeyStatusChanged,
        AuthorityEventSubjectKindV1::Key,
        subject_reference,
        AuthorityEventResultV1::CommittedRetained,
        AuthorityEventReasonV1::from_key_status_reason_v1(candidate.reason),
        candidate.trust_generation,
    )?;

    transaction
        .execute(
            "INSERT INTO authority_key_status_events (
                key_status_event_id, key_purpose, key_id, status,
                effective_at_utc_ms, trust_generation, attempt_id,
                reason_code, event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                candidate.key_status_event_id.to_hex(),
                candidate.purpose.code_v1(),
                candidate.key_id.as_str(),
                candidate.status.code_v1(),
                sql_integer_v1(candidate.effective_at_utc_ms.get())?,
                sql_integer_v1(candidate.trust_generation.get())?,
                candidate.attempt_id.to_hex(),
                candidate.reason.code_v1(),
                candidate.event_id.to_hex(),
            ],
        )
        .map_err(map_insert_error_v1)?;

    Ok(AuthorityCurrentKeyStatusV1 {
        key,
        status: candidate.status,
        effective_at_utc_ms: candidate.effective_at_utc_ms,
        trust_generation: candidate.trust_generation,
        reason: candidate.reason,
    })
}

pub(crate) fn current_key_status_v1(
    connection: &Connection,
    purpose: AuthoritySignerPurposeV1,
    key_id: &Identifier,
) -> Result<Option<AuthorityCurrentKeyStatusV1>, AuthorityHistoryErrorV1> {
    let Some(key) = read_verification_key_by_id_v1(connection, key_id.as_str())? else {
        return Ok(None);
    };
    if key.purpose != purpose {
        return Ok(None);
    }
    let status = read_latest_status_row_v1(connection, purpose, key_id)?
        .ok_or(AuthorityHistoryErrorV1::IncompleteGraph)?;
    verify_related_event_v1(
        connection,
        status.event_id,
        status.attempt_id,
        AuthorityEventKindV1::KeyStatusChanged,
        AuthorityEventSubjectKindV1::Key,
        verification_key_event_reference_digest_v1(purpose, key_id),
        AuthorityEventResultV1::CommittedRetained,
        AuthorityEventReasonV1::from_key_status_reason_v1(status.reason),
        status.trust_generation,
    )?;
    Ok(Some(AuthorityCurrentKeyStatusV1 {
        key,
        status: status.status,
        effective_at_utc_ms: status.effective_at_utc_ms,
        trust_generation: status.trust_generation,
        reason: status.reason,
    }))
}

struct KeyStatusRowV1 {
    status: AuthorityKeyStatusV1,
    effective_at_utc_ms: SafeU64,
    trust_generation: Generation,
    attempt_id: Sha256Digest,
    reason: AuthorityKeyStatusReasonV1,
    event_id: Sha256Digest,
}

fn read_latest_status_row_v1(
    connection: &Connection,
    purpose: AuthoritySignerPurposeV1,
    key_id: &Identifier,
) -> Result<Option<KeyStatusRowV1>, AuthorityHistoryErrorV1> {
    let row = connection
        .query_row(
            "SELECT status, effective_at_utc_ms, trust_generation,
                    attempt_id, reason_code, event_id
             FROM authority_key_status_events
             WHERE key_purpose = ?1 AND key_id = ?2
             ORDER BY trust_generation DESC LIMIT 1",
            params![purpose.code_v1(), key_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?;
    row.map(|row| {
        Ok(KeyStatusRowV1 {
            status: parse_key_status_v1(&row.0)?,
            effective_at_utc_ms: safe_from_sql_v1(row.1)?,
            trust_generation: generation_from_sql_v1(row.2)?,
            attempt_id: parse_digest_v1(&row.3)?,
            reason: parse_key_status_reason_v1(&row.4)?,
            event_id: parse_digest_v1(&row.5)?,
        })
    })
    .transpose()
}

fn validate_status_reason_v1(
    status: AuthorityKeyStatusV1,
    reason: AuthorityKeyStatusReasonV1,
) -> Result<(), AuthorityHistoryErrorV1> {
    let compatible = matches!(
        (status, reason),
        (
            AuthorityKeyStatusV1::Trusted,
            AuthorityKeyStatusReasonV1::KeyIntroduced
        ) | (
            AuthorityKeyStatusV1::Retired,
            AuthorityKeyStatusReasonV1::KeyRotated | AuthorityKeyStatusReasonV1::KeyRetired
        ) | (
            AuthorityKeyStatusV1::Revoked,
            AuthorityKeyStatusReasonV1::KeyCompromised | AuthorityKeyStatusReasonV1::AdminRevoked
        )
    );
    if compatible {
        Ok(())
    } else {
        Err(AuthorityHistoryErrorV1::InvalidTransition)
    }
}

fn validate_key_status_transition_v1(
    prior: Option<&KeyStatusRowV1>,
    candidate: &AuthorityKeyStatusCandidateV1,
) -> Result<(), AuthorityHistoryErrorV1> {
    match prior {
        None if candidate.status == AuthorityKeyStatusV1::Trusted
            && candidate.reason == AuthorityKeyStatusReasonV1::KeyIntroduced =>
        {
            Ok(())
        }
        Some(prior)
            if prior.status == AuthorityKeyStatusV1::Trusted
                && matches!(
                    candidate.status,
                    AuthorityKeyStatusV1::Retired | AuthorityKeyStatusV1::Revoked
                )
                && candidate.effective_at_utc_ms >= prior.effective_at_utc_ms =>
        {
            Ok(())
        }
        Some(prior)
            if prior.status == AuthorityKeyStatusV1::Retired
                && candidate.status == AuthorityKeyStatusV1::Revoked
                && candidate.effective_at_utc_ms >= prior.effective_at_utc_ms =>
        {
            Ok(())
        }
        _ => Err(AuthorityHistoryErrorV1::InvalidTransition),
    }
}

fn read_verification_key_by_id_v1(
    connection: &Connection,
    key_id: &str,
) -> Result<Option<AuthorityVerificationKeyRecordV1>, AuthorityHistoryErrorV1> {
    let row = connection
        .query_row(
            "SELECT key_purpose, key_id, issuer_id, algorithm, public_key,
                    public_key_fingerprint, provenance_digest, introduced_generation
             FROM authority_verification_keys WHERE key_id = ?1",
            [key_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?;
    row.map(|row| {
        let public_key: [u8; 32] = row
            .4
            .try_into()
            .map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
        VerifyingKey::from_bytes(&public_key).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
        let fingerprint = parse_digest_v1(&row.5)?;
        if row.3 != "ed25519" || fingerprint != Sha256Digest::digest(&public_key) {
            return Err(AuthorityHistoryErrorV1::Corrupt);
        }
        Ok(AuthorityVerificationKeyRecordV1 {
            purpose: parse_signer_purpose_v1(&row.0)?,
            key_id: Identifier::new(row.1).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?,
            issuer_id: Identifier::new(row.2).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?,
            public_key,
            public_key_fingerprint: fingerprint,
            provenance_digest: parse_digest_v1(&row.6)?,
            introduced_generation: generation_from_sql_v1(row.7)?,
        })
    })
    .transpose()
}

/// Immutable append-only revocation candidate.
pub(crate) struct AuthorityRevocationCandidateV1 {
    revocation_id: Sha256Digest,
    revocation_attempt_id: Sha256Digest,
    subject_kind: AuthorityRevocationSubjectKindV1,
    subject_id: Identifier,
    subject_digest: Option<Sha256Digest>,
    effective_at_utc_ms: SafeU64,
    effective_at_monotonic_ms: Option<SafeU64>,
    boot_id: Option<Identifier>,
    reason: AuthorityRevocationReasonV1,
    created_generation: Generation,
    event_id: Sha256Digest,
}

impl AuthorityRevocationCandidateV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        revocation_id: Sha256Digest,
        revocation_attempt_id: Sha256Digest,
        subject_kind: AuthorityRevocationSubjectKindV1,
        subject_id: Identifier,
        subject_digest: Option<Sha256Digest>,
        effective_at_utc_ms: SafeU64,
        effective_at_monotonic_ms: Option<SafeU64>,
        boot_id: Option<Identifier>,
        reason: AuthorityRevocationReasonV1,
        created_generation: Generation,
        event_id: Sha256Digest,
    ) -> Result<Self, AuthorityHistoryErrorV1> {
        if effective_at_monotonic_ms.is_some() != boot_id.is_some()
            || !revocation_reason_is_compatible_v1(subject_kind, reason)
        {
            return Err(AuthorityHistoryErrorV1::InvalidRecord);
        }
        Ok(Self {
            revocation_id,
            revocation_attempt_id,
            subject_kind,
            subject_id,
            subject_digest,
            effective_at_utc_ms,
            effective_at_monotonic_ms,
            boot_id,
            reason,
            created_generation,
            event_id,
        })
    }

    pub(crate) fn event_subject_reference_digest_v1(&self) -> Sha256Digest {
        revocation_event_reference_digest_v1(
            self.subject_kind,
            &self.subject_id,
            self.subject_digest,
        )
    }
}

impl fmt::Debug for AuthorityRevocationCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityRevocationCandidateV1(..)")
    }
}

pub(crate) struct AuthorityRevocationRecordV1 {
    revocation_id: Sha256Digest,
    subject_kind: AuthorityRevocationSubjectKindV1,
    subject_id: Identifier,
    subject_digest: Option<Sha256Digest>,
    effective_at_utc_ms: SafeU64,
    effective_at_monotonic_ms: Option<SafeU64>,
    boot_id: Option<Identifier>,
    reason: AuthorityRevocationReasonV1,
    created_generation: Generation,
}

impl AuthorityRevocationRecordV1 {
    pub(crate) const fn revocation_id_v1(&self) -> Sha256Digest {
        self.revocation_id
    }

    pub(crate) const fn subject_kind_v1(&self) -> AuthorityRevocationSubjectKindV1 {
        self.subject_kind
    }

    pub(crate) fn subject_id_v1(&self) -> &str {
        self.subject_id.as_str()
    }

    pub(crate) const fn subject_digest_v1(&self) -> Option<Sha256Digest> {
        self.subject_digest
    }

    pub(crate) const fn effective_at_utc_ms_v1(&self) -> SafeU64 {
        self.effective_at_utc_ms
    }

    pub(crate) const fn effective_at_monotonic_ms_v1(&self) -> Option<SafeU64> {
        self.effective_at_monotonic_ms
    }

    pub(crate) fn boot_id_v1(&self) -> Option<&str> {
        self.boot_id.as_ref().map(Identifier::as_str)
    }

    pub(crate) const fn reason_v1(&self) -> AuthorityRevocationReasonV1 {
        self.reason
    }

    pub(crate) const fn created_generation_v1(&self) -> Generation {
        self.created_generation
    }
}

impl fmt::Debug for AuthorityRevocationRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityRevocationRecordV1(..)")
    }
}

pub(crate) fn append_revocation_v1(
    transaction: &Transaction<'_>,
    candidate: AuthorityRevocationCandidateV1,
) -> Result<AuthorityRevocationRecordV1, AuthorityHistoryErrorV1> {
    if latest_generation_v1(
        transaction,
        "SELECT MAX(created_generation) FROM authority_revocations",
    )?
    .is_some_and(|generation| candidate.created_generation.get() <= generation)
    {
        return Err(AuthorityHistoryErrorV1::GenerationNotIncreasing);
    }
    let subject_reference = candidate.event_subject_reference_digest_v1();
    verify_related_event_v1(
        transaction,
        candidate.event_id,
        candidate.revocation_attempt_id,
        AuthorityEventKindV1::AuthorityRevoked,
        AuthorityEventSubjectKindV1::Revocation,
        subject_reference,
        AuthorityEventResultV1::CommittedRetained,
        AuthorityEventReasonV1::from_revocation_reason_v1(candidate.reason),
        candidate.created_generation,
    )?;

    let monotonic = candidate
        .effective_at_monotonic_ms
        .map(|value| sql_integer_v1(value.get()))
        .transpose()?;
    let boot_id = candidate.boot_id.as_ref().map(Identifier::as_str);
    transaction
        .execute(
            "INSERT INTO authority_revocations (
                revocation_id, revocation_attempt_id, subject_kind, subject_id,
                subject_digest, effective_at_utc_ms, effective_at_monotonic_ms,
                boot_id, reason_code, created_generation, event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                candidate.revocation_id.to_hex(),
                candidate.revocation_attempt_id.to_hex(),
                candidate.subject_kind.code_v1(),
                candidate.subject_id.as_str(),
                candidate.subject_digest.map(Sha256Digest::to_hex),
                sql_integer_v1(candidate.effective_at_utc_ms.get())?,
                monotonic,
                boot_id,
                candidate.reason.code_v1(),
                sql_integer_v1(candidate.created_generation.get())?,
                candidate.event_id.to_hex(),
            ],
        )
        .map_err(map_insert_error_v1)?;

    Ok(AuthorityRevocationRecordV1 {
        revocation_id: candidate.revocation_id,
        subject_kind: candidate.subject_kind,
        subject_id: candidate.subject_id,
        subject_digest: candidate.subject_digest,
        effective_at_utc_ms: candidate.effective_at_utc_ms,
        effective_at_monotonic_ms: candidate.effective_at_monotonic_ms,
        boot_id: candidate.boot_id,
        reason: candidate.reason,
        created_generation: candidate.created_generation,
    })
}

pub(crate) fn latest_revocation_for_subject_v1(
    connection: &Connection,
    subject_kind: AuthorityRevocationSubjectKindV1,
    subject_id: &Identifier,
) -> Result<Option<AuthorityRevocationRecordV1>, AuthorityHistoryErrorV1> {
    let row = connection
        .query_row(
            "SELECT revocation_id, revocation_attempt_id, subject_kind, subject_id,
                    subject_digest, effective_at_utc_ms, effective_at_monotonic_ms,
                    boot_id, reason_code, created_generation, event_id
             FROM authority_revocations
             WHERE subject_kind = ?1 AND subject_id = ?2
             ORDER BY created_generation DESC LIMIT 1",
            params![subject_kind.code_v1(), subject_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?;
    row.map(|row| {
        let parsed_subject_kind = parse_revocation_subject_kind_v1(&row.2)?;
        let parsed_subject_id =
            Identifier::new(row.3).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
        let subject_digest = row.4.as_deref().map(parse_digest_v1).transpose()?;
        let effective_at_monotonic_ms = row.6.map(safe_from_sql_v1).transpose()?;
        let boot_id = row
            .7
            .map(Identifier::new)
            .transpose()
            .map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
        if effective_at_monotonic_ms.is_some() != boot_id.is_some() {
            return Err(AuthorityHistoryErrorV1::Corrupt);
        }
        let reason = parse_revocation_reason_v1(&row.8)?;
        if !revocation_reason_is_compatible_v1(parsed_subject_kind, reason) {
            return Err(AuthorityHistoryErrorV1::Corrupt);
        }
        let generation = generation_from_sql_v1(row.9)?;
        let revocation_id = parse_digest_v1(&row.0)?;
        let attempt_id = parse_digest_v1(&row.1)?;
        let event_id = parse_digest_v1(&row.10)?;
        verify_related_event_v1(
            connection,
            event_id,
            attempt_id,
            AuthorityEventKindV1::AuthorityRevoked,
            AuthorityEventSubjectKindV1::Revocation,
            revocation_event_reference_digest_v1(
                parsed_subject_kind,
                &parsed_subject_id,
                subject_digest,
            ),
            AuthorityEventResultV1::CommittedRetained,
            AuthorityEventReasonV1::from_revocation_reason_v1(reason),
            generation,
        )?;
        Ok(AuthorityRevocationRecordV1 {
            revocation_id,
            subject_kind: parsed_subject_kind,
            subject_id: parsed_subject_id,
            subject_digest,
            effective_at_utc_ms: safe_from_sql_v1(row.5)?,
            effective_at_monotonic_ms,
            boot_id,
            reason,
            created_generation: generation,
        })
    })
    .transpose()
}

pub(crate) fn verification_key_event_reference_digest_v1(
    purpose: AuthoritySignerPurposeV1,
    key_id: &Identifier,
) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(KEY_EVENT_REFERENCE_DOMAIN_V1);
    push_reference_field_v1(&mut bytes, purpose.code_v1().as_bytes());
    push_reference_field_v1(&mut bytes, key_id.as_str().as_bytes());
    Sha256Digest::digest(&bytes)
}

fn revocation_event_reference_digest_v1(
    subject_kind: AuthorityRevocationSubjectKindV1,
    subject_id: &Identifier,
    subject_digest: Option<Sha256Digest>,
) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(REVOCATION_EVENT_REFERENCE_DOMAIN_V1);
    push_reference_field_v1(&mut bytes, subject_kind.code_v1().as_bytes());
    push_reference_field_v1(&mut bytes, subject_id.as_str().as_bytes());
    match subject_digest {
        Some(digest) => push_reference_field_v1(&mut bytes, digest.as_bytes()),
        None => push_reference_field_v1(&mut bytes, b""),
    }
    Sha256Digest::digest(&bytes)
}

fn push_reference_field_v1(destination: &mut Vec<u8>, field: &[u8]) {
    destination.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    destination.extend_from_slice(field);
}

fn revocation_reason_is_compatible_v1(
    subject: AuthorityRevocationSubjectKindV1,
    reason: AuthorityRevocationReasonV1,
) -> bool {
    match subject {
        AuthorityRevocationSubjectKindV1::Signer => matches!(
            reason,
            AuthorityRevocationReasonV1::AdminRevoked | AuthorityRevocationReasonV1::KeyCompromised
        ),
        AuthorityRevocationSubjectKindV1::Grant => matches!(
            reason,
            AuthorityRevocationReasonV1::AdminRevoked | AuthorityRevocationReasonV1::SourceRevoked
        ),
        AuthorityRevocationSubjectKindV1::Lease => matches!(
            reason,
            AuthorityRevocationReasonV1::AdminRevoked
                | AuthorityRevocationReasonV1::SourceRevoked
                | AuthorityRevocationReasonV1::AncestorRevoked
        ),
        AuthorityRevocationSubjectKindV1::Decision => matches!(
            reason,
            AuthorityRevocationReasonV1::AdminRevoked
                | AuthorityRevocationReasonV1::DecisionRevoked
        ),
        AuthorityRevocationSubjectKindV1::Boot => {
            reason == AuthorityRevocationReasonV1::BootReplaced
        }
        AuthorityRevocationSubjectKindV1::Instance => {
            reason == AuthorityRevocationReasonV1::InstanceReplaced
        }
        AuthorityRevocationSubjectKindV1::ScopeTemplate => {
            reason == AuthorityRevocationReasonV1::ScopeReplaced
        }
    }
}

fn parse_signer_purpose_v1(
    value: &str,
) -> Result<AuthoritySignerPurposeV1, AuthorityHistoryErrorV1> {
    match value {
        "request-surface-grant-signing" => Ok(AuthoritySignerPurposeV1::RequestSurfaceGrantSigning),
        "core-task-lease-signing" => Ok(AuthoritySignerPurposeV1::CoreTaskLeaseSigning),
        "core-approval-decision-signing" => {
            Ok(AuthoritySignerPurposeV1::CoreApprovalDecisionSigning)
        }
        _ => Err(AuthorityHistoryErrorV1::Corrupt),
    }
}

fn parse_key_status_v1(value: &str) -> Result<AuthorityKeyStatusV1, AuthorityHistoryErrorV1> {
    match value {
        "TRUSTED" => Ok(AuthorityKeyStatusV1::Trusted),
        "RETIRED" => Ok(AuthorityKeyStatusV1::Retired),
        "REVOKED" => Ok(AuthorityKeyStatusV1::Revoked),
        _ => Err(AuthorityHistoryErrorV1::Corrupt),
    }
}

fn parse_key_status_reason_v1(
    value: &str,
) -> Result<AuthorityKeyStatusReasonV1, AuthorityHistoryErrorV1> {
    match value {
        "KEY_INTRODUCED" => Ok(AuthorityKeyStatusReasonV1::KeyIntroduced),
        "KEY_ROTATED" => Ok(AuthorityKeyStatusReasonV1::KeyRotated),
        "KEY_RETIRED" => Ok(AuthorityKeyStatusReasonV1::KeyRetired),
        "KEY_COMPROMISED" => Ok(AuthorityKeyStatusReasonV1::KeyCompromised),
        "ADMIN_REVOKED" => Ok(AuthorityKeyStatusReasonV1::AdminRevoked),
        _ => Err(AuthorityHistoryErrorV1::Corrupt),
    }
}

fn parse_revocation_subject_kind_v1(
    value: &str,
) -> Result<AuthorityRevocationSubjectKindV1, AuthorityHistoryErrorV1> {
    match value {
        "SIGNER" => Ok(AuthorityRevocationSubjectKindV1::Signer),
        "GRANT" => Ok(AuthorityRevocationSubjectKindV1::Grant),
        "LEASE" => Ok(AuthorityRevocationSubjectKindV1::Lease),
        "DECISION" => Ok(AuthorityRevocationSubjectKindV1::Decision),
        "BOOT" => Ok(AuthorityRevocationSubjectKindV1::Boot),
        "INSTANCE" => Ok(AuthorityRevocationSubjectKindV1::Instance),
        "SCOPE_TEMPLATE" => Ok(AuthorityRevocationSubjectKindV1::ScopeTemplate),
        _ => Err(AuthorityHistoryErrorV1::Corrupt),
    }
}

fn parse_revocation_reason_v1(
    value: &str,
) -> Result<AuthorityRevocationReasonV1, AuthorityHistoryErrorV1> {
    match value {
        "ADMIN_REVOKED" => Ok(AuthorityRevocationReasonV1::AdminRevoked),
        "KEY_COMPROMISED" => Ok(AuthorityRevocationReasonV1::KeyCompromised),
        "SOURCE_REVOKED" => Ok(AuthorityRevocationReasonV1::SourceRevoked),
        "ANCESTOR_REVOKED" => Ok(AuthorityRevocationReasonV1::AncestorRevoked),
        "DECISION_REVOKED" => Ok(AuthorityRevocationReasonV1::DecisionRevoked),
        "BOOT_REPLACED" => Ok(AuthorityRevocationReasonV1::BootReplaced),
        "INSTANCE_REPLACED" => Ok(AuthorityRevocationReasonV1::InstanceReplaced),
        "SCOPE_REPLACED" => Ok(AuthorityRevocationReasonV1::ScopeReplaced),
        _ => Err(AuthorityHistoryErrorV1::Corrupt),
    }
}

fn parse_digest_v1(value: &str) -> Result<Sha256Digest, AuthorityHistoryErrorV1> {
    Sha256Digest::parse_hex(value).map_err(|_| AuthorityHistoryErrorV1::Corrupt)
}

fn safe_from_sql_v1(value: i64) -> Result<SafeU64, AuthorityHistoryErrorV1> {
    let value = u64::try_from(value).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
    SafeU64::new(value).map_err(|_| AuthorityHistoryErrorV1::Corrupt)
}

fn generation_from_sql_v1(value: i64) -> Result<Generation, AuthorityHistoryErrorV1> {
    let value = u64::try_from(value).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
    Generation::new(value).map_err(|_| AuthorityHistoryErrorV1::Corrupt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{retain_authority_event_v1, AuthorityEventCandidateV1};
    use crate::schema::TASK_AUTHORITY_STORE_SCHEMA_V1_SQL;
    use ed25519_dalek::SigningKey;

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).expect("history test identifier is valid")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("history test generation is valid")
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("history test safe integer is valid")
    }

    fn public_key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("history SQLite opens");
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("foreign keys enable");
        connection
            .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
            .expect("exact HLXA schema installs");
        connection
    }

    fn key_candidate(
        key_id: &str,
        purpose: AuthoritySignerPurposeV1,
        seed: u8,
    ) -> AuthorityVerificationKeyCandidateV1 {
        AuthorityVerificationKeyCandidateV1::try_new(
            purpose,
            identifier(key_id),
            identifier("issuer-history-v1"),
            public_key(seed),
            digest(90),
            generation(1),
        )
        .expect("public key candidate is valid")
    }

    fn retain_attempt(
        transaction: &Transaction<'_>,
        attempt: Sha256Digest,
        event: Sha256Digest,
        operation: &str,
        attempt_generation: u64,
    ) {
        transaction
            .execute(
                "INSERT INTO authority_attempts (
                    attempt_id, operation_kind, namespace_digest, input_graph_digest,
                    caller_deadline_monotonic_ms, outcome_code,
                    outcome_binding_digest, attempt_generation, event_id
                 ) VALUES (?1, ?2, ?3, ?4, 1000, 'COMMITTED_RETAINED', ?5, ?6, ?7)",
                params![
                    attempt.to_hex(),
                    operation,
                    digest(91).to_hex(),
                    digest(92).to_hex(),
                    digest(93).to_hex(),
                    sql_integer_v1(attempt_generation).expect("generation fits"),
                    event.to_hex(),
                ],
            )
            .expect("attempt retains before deferred event");
    }

    #[allow(clippy::too_many_arguments)]
    fn retain_event(
        transaction: &Transaction<'_>,
        event: Sha256Digest,
        attempt: Sha256Digest,
        generation_value: u64,
        kind: AuthorityEventKindV1,
        subject: AuthorityEventSubjectKindV1,
        reference: Sha256Digest,
        reason: AuthorityEventReasonV1,
    ) {
        retain_authority_event_v1(
            transaction,
            AuthorityEventCandidateV1::try_new(
                event,
                kind,
                subject,
                reference,
                attempt,
                AuthorityEventResultV1::CommittedRetained,
                reason,
                generation(generation_value),
                safe(10_000 + generation_value),
                Some(safe(100 + generation_value)),
                Some(identifier("boot-history-v1")),
            )
            .expect("event candidate is coherent"),
        )
        .expect("related event retains");
    }

    #[test]
    fn key_identity_is_immutable_and_exact_duplicate_is_read_only() {
        let mut connection = connection();
        let transaction = connection.transaction().expect("key writer starts");
        let first = retain_verification_key_v1(
            &transaction,
            key_candidate(
                "key-one-v1",
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                7,
            ),
        )
        .expect("key introduction succeeds");
        assert!(matches!(
            first,
            AuthorityVerificationKeyRetentionV1::Introduced(_)
        ));
        let exact = retain_verification_key_v1(
            &transaction,
            key_candidate(
                "key-one-v1",
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                7,
            ),
        )
        .expect("exact duplicate classifies");
        assert!(matches!(
            exact,
            AuthorityVerificationKeyRetentionV1::PriorExact(_)
        ));
        let changed_key = retain_verification_key_v1(
            &transaction,
            key_candidate(
                "key-one-v1",
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                8,
            ),
        )
        .expect("changed binding classifies");
        assert!(matches!(
            changed_key,
            AuthorityVerificationKeyRetentionV1::IdentityConflict
        ));
        let changed_id = retain_verification_key_v1(
            &transaction,
            key_candidate(
                "key-two-v1",
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                7,
            ),
        )
        .expect("fingerprint reuse classifies");
        assert!(matches!(
            changed_id,
            AuthorityVerificationKeyRetentionV1::IdentityConflict
        ));
        assert!(!format!("{first:?}").contains("key-one-v1"));
        transaction.commit().expect("key introduction commits");

        assert!(connection
            .execute(
                "UPDATE authority_verification_keys SET issuer_id = 'replacement'",
                [],
            )
            .is_err());
        assert!(connection
            .execute("DELETE FROM authority_verification_keys", [])
            .is_err());
    }

    #[test]
    fn latest_status_is_current_and_terminal_transitions_cannot_retrust() {
        let mut connection = connection();
        let key_id = identifier("key-status-v1");
        {
            let transaction = connection.transaction().expect("key introduction starts");
            retain_verification_key_v1(
                &transaction,
                key_candidate(
                    key_id.as_str(),
                    AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                    9,
                ),
            )
            .expect("key introduction succeeds");
            transaction.commit().expect("key introduction commits");
        }

        {
            let transaction = connection.transaction().expect("trusted status starts");
            let candidate = AuthorityKeyStatusCandidateV1::new(
                digest(10),
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                key_id.clone(),
                AuthorityKeyStatusV1::Trusted,
                safe(1_000),
                generation(1),
                digest(11),
                AuthorityKeyStatusReasonV1::KeyIntroduced,
                digest(12),
            );
            retain_attempt(&transaction, digest(11), digest(12), "KEY_STATUS_CHANGE", 1);
            retain_event(
                &transaction,
                digest(12),
                digest(11),
                1,
                AuthorityEventKindV1::KeyStatusChanged,
                AuthorityEventSubjectKindV1::Key,
                candidate.event_subject_reference_digest_v1(),
                AuthorityEventReasonV1::KeyIntroduced,
            );
            append_key_status_v1(&transaction, candidate).expect("trusted status appends");
            transaction.commit().expect("trusted status commits");
        }
        let current = current_key_status_v1(
            &connection,
            AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
            &key_id,
        )
        .expect("current status decodes")
        .expect("key status exists");
        assert!(current.is_current_trusted_v1());
        assert!(!format!("{current:?}").contains(key_id.as_str()));

        {
            let transaction = connection.transaction().expect("retirement starts");
            let candidate = AuthorityKeyStatusCandidateV1::new(
                digest(13),
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                key_id.clone(),
                AuthorityKeyStatusV1::Retired,
                safe(2_000),
                generation(2),
                digest(14),
                AuthorityKeyStatusReasonV1::KeyRotated,
                digest(15),
            );
            retain_attempt(&transaction, digest(14), digest(15), "KEY_STATUS_CHANGE", 2);
            retain_event(
                &transaction,
                digest(15),
                digest(14),
                2,
                AuthorityEventKindV1::KeyStatusChanged,
                AuthorityEventSubjectKindV1::Key,
                candidate.event_subject_reference_digest_v1(),
                AuthorityEventReasonV1::KeyRotated,
            );
            let retired = append_key_status_v1(&transaction, candidate)
                .expect("retirement appends monotonically");
            assert_eq!(retired.status_v1(), AuthorityKeyStatusV1::Retired);
            transaction.commit().expect("retirement commits");
        }

        let transaction = connection.transaction().expect("invalid retrust starts");
        let retrust = AuthorityKeyStatusCandidateV1::new(
            digest(16),
            AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
            key_id,
            AuthorityKeyStatusV1::Trusted,
            safe(3_000),
            generation(3),
            digest(17),
            AuthorityKeyStatusReasonV1::KeyIntroduced,
            digest(18),
        );
        assert_eq!(
            append_key_status_v1(&transaction, retrust).unwrap_err(),
            AuthorityHistoryErrorV1::InvalidTransition
        );
    }

    #[test]
    fn revocations_append_with_increasing_generation_and_exact_event_binding() {
        let mut connection = connection();
        let subject_id = identifier("lease-revoked-v1");
        let transaction = connection.transaction().expect("revocation writer starts");
        let candidate = AuthorityRevocationCandidateV1::try_new(
            digest(30),
            digest(31),
            AuthorityRevocationSubjectKindV1::Lease,
            subject_id.clone(),
            Some(digest(32)),
            safe(5_000),
            Some(safe(500)),
            Some(identifier("boot-revocation-v1")),
            AuthorityRevocationReasonV1::AncestorRevoked,
            generation(1),
            digest(33),
        )
        .expect("revocation candidate is coherent");
        retain_attempt(&transaction, digest(31), digest(33), "AUTHORITY_REVOKE", 1);
        retain_event(
            &transaction,
            digest(33),
            digest(31),
            1,
            AuthorityEventKindV1::AuthorityRevoked,
            AuthorityEventSubjectKindV1::Revocation,
            candidate.event_subject_reference_digest_v1(),
            AuthorityEventReasonV1::AncestorRevoked,
        );
        let retained =
            append_revocation_v1(&transaction, candidate).expect("first revocation appends");
        assert_eq!(retained.created_generation_v1().get(), 1);
        assert!(!format!("{retained:?}").contains(subject_id.as_str()));
        transaction.commit().expect("revocation graph commits");

        let current = latest_revocation_for_subject_v1(
            &connection,
            AuthorityRevocationSubjectKindV1::Lease,
            &subject_id,
        )
        .expect("revocation history decodes")
        .expect("revocation exists");
        assert_eq!(
            current.reason_v1(),
            AuthorityRevocationReasonV1::AncestorRevoked
        );

        assert!(connection
            .execute(
                "UPDATE authority_revocations SET reason_code = 'ADMIN_REVOKED'",
                [],
            )
            .is_err());
        assert!(connection
            .execute("DELETE FROM authority_revocations", [])
            .is_err());
    }

    #[test]
    fn invalid_key_status_and_revocation_reason_pairs_fail_before_sql() {
        assert_eq!(
            validate_status_reason_v1(
                AuthorityKeyStatusV1::Trusted,
                AuthorityKeyStatusReasonV1::AdminRevoked,
            )
            .unwrap_err(),
            AuthorityHistoryErrorV1::InvalidTransition
        );
        assert_eq!(
            AuthorityRevocationCandidateV1::try_new(
                digest(40),
                digest(41),
                AuthorityRevocationSubjectKindV1::Boot,
                identifier("boot-old-v1"),
                None,
                safe(10),
                None,
                None,
                AuthorityRevocationReasonV1::ScopeReplaced,
                generation(1),
                digest(42),
            )
            .unwrap_err(),
            AuthorityHistoryErrorV1::InvalidRecord
        );
    }
}
