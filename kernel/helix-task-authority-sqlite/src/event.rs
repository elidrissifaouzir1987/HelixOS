//! Append-only redacted transition events and retained conflict tombstones.
//!
//! Exact authority rows remain restricted.  This module stores only closed event
//! vocabulary plus pseudonymous digests and never formats identifiers, digests, native
//! SQLite errors, or provider text.

#![allow(dead_code)] // Foundation consumed by the story-specific atomic writers.

use helix_task_authority::{
    AuthorityKeyStatusReasonV1, AuthorityRetainedOutcomeCodeV1, AuthorityRevocationReasonV1,
};
use helix_task_authority_contracts::{Generation, Identifier, SafeU64, Sha256Digest};
use rusqlite::{params, Connection, ErrorCode, OptionalExtension, Transaction};
use std::error::Error;
use std::fmt;

const EVENT_DIGEST_DOMAIN_V1: &[u8] = b"HELIXOS\0TASK-AUTHORITY-EVENT\0V1\0";

/// Closed adapter-history failures.  Variants deliberately carry no SQLite payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityHistoryErrorV1 {
    InvalidRecord,
    MissingAttempt,
    MissingKey,
    IdentityConflict,
    GenerationNotIncreasing,
    InvalidTransition,
    IncompleteGraph,
    Corrupt,
    Unavailable,
}

impl AuthorityHistoryErrorV1 {
    pub(crate) const fn code_v1(self) -> &'static str {
        match self {
            Self::InvalidRecord => "AUTHORITY_HISTORY_INVALID_RECORD",
            Self::MissingAttempt => "AUTHORITY_HISTORY_MISSING_ATTEMPT",
            Self::MissingKey => "AUTHORITY_HISTORY_MISSING_KEY",
            Self::IdentityConflict => "AUTHORITY_HISTORY_IDENTITY_CONFLICT",
            Self::GenerationNotIncreasing => "AUTHORITY_HISTORY_GENERATION_NOT_INCREASING",
            Self::InvalidTransition => "AUTHORITY_HISTORY_INVALID_TRANSITION",
            Self::IncompleteGraph => "AUTHORITY_HISTORY_INCOMPLETE_GRAPH",
            Self::Corrupt => "AUTHORITY_HISTORY_CORRUPT",
            Self::Unavailable => "AUTHORITY_HISTORY_UNAVAILABLE",
        }
    }
}

impl fmt::Debug for AuthorityHistoryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityHistoryErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl Error for AuthorityHistoryErrorV1 {}

/// Exact closed inventory persisted in `authority_events.event_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityEventKindV1 {
    BootstrapCompleted,
    KeyStatusChanged,
    RootLeaseIssued,
    ChildLeaseIssued,
    CounterConsumed,
    DecisionRetained,
    AuthorityRevoked,
    ConflictRetained,
    BackupPublished,
    RestorePublished,
}

impl AuthorityEventKindV1 {
    pub(crate) const fn sql_code_v1(self) -> &'static str {
        match self {
            Self::BootstrapCompleted => "BOOTSTRAP_COMPLETED",
            Self::KeyStatusChanged => "KEY_STATUS_CHANGED",
            Self::RootLeaseIssued => "ROOT_LEASE_ISSUED",
            Self::ChildLeaseIssued => "CHILD_LEASE_ISSUED",
            Self::CounterConsumed => "COUNTER_CONSUMED",
            Self::DecisionRetained => "DECISION_RETAINED",
            Self::AuthorityRevoked => "AUTHORITY_REVOKED",
            Self::ConflictRetained => "CONFLICT_RETAINED",
            Self::BackupPublished => "BACKUP_PUBLISHED",
            Self::RestorePublished => "RESTORE_PUBLISHED",
        }
    }
}

/// Exact closed inventory persisted in `authority_events.subject_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityEventSubjectKindV1 {
    Root,
    Key,
    Grant,
    Lease,
    Decision,
    Revocation,
    Restore,
}

impl AuthorityEventSubjectKindV1 {
    pub(crate) const fn sql_code_v1(self) -> &'static str {
        match self {
            Self::Root => "ROOT",
            Self::Key => "KEY",
            Self::Grant => "GRANT",
            Self::Lease => "LEASE",
            Self::Decision => "DECISION",
            Self::Revocation => "REVOCATION",
            Self::Restore => "RESTORE",
        }
    }
}

/// Closed event reasons shared by the mutation-specific writers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityEventReasonV1 {
    BootstrapCompleted,
    KeyIntroduced,
    KeyRotated,
    KeyRetired,
    KeyCompromised,
    AdminRevoked,
    SourceRevoked,
    AncestorRevoked,
    DecisionRevoked,
    BootReplaced,
    InstanceReplaced,
    ScopeReplaced,
    RootLeaseIssued,
    ChildLeaseIssued,
    CounterConsumed,
    DecisionRetained,
    ConflictingIdentityReuse,
    BackupPublished,
    RestorePublished,
}

impl AuthorityEventReasonV1 {
    pub(crate) const fn sql_code_v1(self) -> &'static str {
        match self {
            Self::BootstrapCompleted => "BOOTSTRAP_COMPLETED",
            Self::KeyIntroduced => "KEY_INTRODUCED",
            Self::KeyRotated => "KEY_ROTATED",
            Self::KeyRetired => "KEY_RETIRED",
            Self::KeyCompromised => "KEY_COMPROMISED",
            Self::AdminRevoked => "ADMIN_REVOKED",
            Self::SourceRevoked => "SOURCE_REVOKED",
            Self::AncestorRevoked => "ANCESTOR_REVOKED",
            Self::DecisionRevoked => "DECISION_REVOKED",
            Self::BootReplaced => "BOOT_REPLACED",
            Self::InstanceReplaced => "INSTANCE_REPLACED",
            Self::ScopeReplaced => "SCOPE_REPLACED",
            Self::RootLeaseIssued => "ROOT_LEASE_ISSUED",
            Self::ChildLeaseIssued => "CHILD_LEASE_ISSUED",
            Self::CounterConsumed => "COUNTER_CONSUMED",
            Self::DecisionRetained => "DECISION_RETAINED",
            Self::ConflictingIdentityReuse => "CONFLICTING_IDENTITY_REUSE",
            Self::BackupPublished => "BACKUP_PUBLISHED",
            Self::RestorePublished => "RESTORE_PUBLISHED",
        }
    }

    pub(crate) const fn from_key_status_reason_v1(reason: AuthorityKeyStatusReasonV1) -> Self {
        match reason {
            AuthorityKeyStatusReasonV1::KeyIntroduced => Self::KeyIntroduced,
            AuthorityKeyStatusReasonV1::KeyRotated => Self::KeyRotated,
            AuthorityKeyStatusReasonV1::KeyRetired => Self::KeyRetired,
            AuthorityKeyStatusReasonV1::KeyCompromised => Self::KeyCompromised,
            AuthorityKeyStatusReasonV1::AdminRevoked => Self::AdminRevoked,
        }
    }

    pub(crate) const fn from_revocation_reason_v1(reason: AuthorityRevocationReasonV1) -> Self {
        match reason {
            AuthorityRevocationReasonV1::AdminRevoked => Self::AdminRevoked,
            AuthorityRevocationReasonV1::KeyCompromised => Self::KeyCompromised,
            AuthorityRevocationReasonV1::SourceRevoked => Self::SourceRevoked,
            AuthorityRevocationReasonV1::AncestorRevoked => Self::AncestorRevoked,
            AuthorityRevocationReasonV1::DecisionRevoked => Self::DecisionRevoked,
            AuthorityRevocationReasonV1::BootReplaced => Self::BootReplaced,
            AuthorityRevocationReasonV1::InstanceReplaced => Self::InstanceReplaced,
            AuthorityRevocationReasonV1::ScopeReplaced => Self::ScopeReplaced,
        }
    }
}

/// Closed result inventory mirrored from the core retained-attempt contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityEventResultV1 {
    CommittedRetained,
    ConflictRetained,
    RestorePending,
}

impl AuthorityEventResultV1 {
    pub(crate) const fn from_core_v1(value: &AuthorityRetainedOutcomeCodeV1) -> Self {
        match value {
            AuthorityRetainedOutcomeCodeV1::CommittedRetained => Self::CommittedRetained,
            AuthorityRetainedOutcomeCodeV1::ConflictRetained => Self::ConflictRetained,
            AuthorityRetainedOutcomeCodeV1::RestorePending => Self::RestorePending,
        }
    }

    pub(crate) const fn sql_code_v1(self) -> &'static str {
        match self {
            Self::CommittedRetained => "COMMITTED_RETAINED",
            Self::ConflictRetained => "CONFLICT_RETAINED",
            Self::RestorePending => "RESTORE_PENDING",
        }
    }
}

/// Immutable inputs for one redacted transition event.
pub(crate) struct AuthorityEventCandidateV1 {
    event_id: Sha256Digest,
    event_kind: AuthorityEventKindV1,
    subject_kind: AuthorityEventSubjectKindV1,
    subject_reference_digest: Sha256Digest,
    attempt_id: Sha256Digest,
    result: AuthorityEventResultV1,
    reason: AuthorityEventReasonV1,
    event_generation: Generation,
    observed_at_utc_ms: SafeU64,
    observed_at_monotonic_ms: Option<SafeU64>,
    boot_id: Option<Identifier>,
}

impl AuthorityEventCandidateV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new(
        event_id: Sha256Digest,
        event_kind: AuthorityEventKindV1,
        subject_kind: AuthorityEventSubjectKindV1,
        subject_reference_digest: Sha256Digest,
        attempt_id: Sha256Digest,
        result: AuthorityEventResultV1,
        reason: AuthorityEventReasonV1,
        event_generation: Generation,
        observed_at_utc_ms: SafeU64,
        observed_at_monotonic_ms: Option<SafeU64>,
        boot_id: Option<Identifier>,
    ) -> Result<Self, AuthorityHistoryErrorV1> {
        if observed_at_monotonic_ms.is_some() != boot_id.is_some() {
            return Err(AuthorityHistoryErrorV1::InvalidRecord);
        }
        Ok(Self {
            event_id,
            event_kind,
            subject_kind,
            subject_reference_digest,
            attempt_id,
            result,
            reason,
            event_generation,
            observed_at_utc_ms,
            observed_at_monotonic_ms,
            boot_id,
        })
    }
}

impl fmt::Debug for AuthorityEventCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityEventCandidateV1(..)")
    }
}

/// Restricted retained row.  Formatting exposes no correlation values.
pub(crate) struct AuthorityEventRecordV1 {
    event_id: Sha256Digest,
    attempt_id: Sha256Digest,
    event_kind: AuthorityEventKindV1,
    subject_kind: AuthorityEventSubjectKindV1,
    result: AuthorityEventResultV1,
    reason: AuthorityEventReasonV1,
    event_generation: Generation,
    previous_event_digest: Option<Sha256Digest>,
    event_digest: Sha256Digest,
}

impl AuthorityEventRecordV1 {
    pub(crate) const fn event_id_v1(&self) -> Sha256Digest {
        self.event_id
    }

    pub(crate) const fn attempt_id_v1(&self) -> Sha256Digest {
        self.attempt_id
    }

    pub(crate) const fn event_kind_v1(&self) -> AuthorityEventKindV1 {
        self.event_kind
    }

    pub(crate) const fn subject_kind_v1(&self) -> AuthorityEventSubjectKindV1 {
        self.subject_kind
    }

    pub(crate) const fn result_v1(&self) -> AuthorityEventResultV1 {
        self.result
    }

    pub(crate) const fn reason_v1(&self) -> AuthorityEventReasonV1 {
        self.reason
    }

    pub(crate) const fn event_generation_v1(&self) -> Generation {
        self.event_generation
    }

    pub(crate) const fn previous_event_digest_v1(&self) -> Option<Sha256Digest> {
        self.previous_event_digest
    }

    pub(crate) const fn event_digest_v1(&self) -> Sha256Digest {
        self.event_digest
    }
}

impl fmt::Debug for AuthorityEventRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityEventRecordV1(..)")
    }
}

/// Appends one event after proving its attempt points back to the same event ID.
pub(crate) fn retain_authority_event_v1(
    transaction: &Transaction<'_>,
    candidate: AuthorityEventCandidateV1,
) -> Result<AuthorityEventRecordV1, AuthorityHistoryErrorV1> {
    verify_attempt_event_binding_v1(transaction, candidate.attempt_id, candidate.event_id)?;

    let previous = latest_event_generation_and_digest_v1(transaction)?;
    if previous
        .as_ref()
        .is_some_and(|(generation, _)| candidate.event_generation.get() <= *generation)
    {
        return Err(AuthorityHistoryErrorV1::GenerationNotIncreasing);
    }
    let previous_event_digest = previous.map(|(_, digest)| digest);
    let event_digest = event_digest_v1(&candidate, previous_event_digest);

    let event_id = candidate.event_id.to_hex();
    let subject_reference_digest = candidate.subject_reference_digest.to_hex();
    let attempt_id = candidate.attempt_id.to_hex();
    let previous_event_digest_hex = previous_event_digest.map(Sha256Digest::to_hex);
    let event_digest_hex = event_digest.to_hex();
    let monotonic = candidate
        .observed_at_monotonic_ms
        .map(|value| sql_integer_v1(value.get()))
        .transpose()?;
    let boot_id = candidate.boot_id.as_ref().map(Identifier::as_str);

    transaction
        .execute(
            "INSERT INTO authority_events (
                event_id, event_kind, subject_kind, subject_reference_digest,
                attempt_id, result_code, reason_code, event_generation,
                observed_at_utc_ms, observed_at_monotonic_ms, boot_id,
                previous_event_digest, event_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                event_id,
                candidate.event_kind.sql_code_v1(),
                candidate.subject_kind.sql_code_v1(),
                subject_reference_digest,
                attempt_id,
                candidate.result.sql_code_v1(),
                candidate.reason.sql_code_v1(),
                sql_integer_v1(candidate.event_generation.get())?,
                sql_integer_v1(candidate.observed_at_utc_ms.get())?,
                monotonic,
                boot_id,
                previous_event_digest_hex,
                event_digest_hex,
            ],
        )
        .map_err(map_insert_error_v1)?;

    Ok(AuthorityEventRecordV1 {
        event_id: candidate.event_id,
        attempt_id: candidate.attempt_id,
        event_kind: candidate.event_kind,
        subject_kind: candidate.subject_kind,
        result: candidate.result,
        reason: candidate.reason,
        event_generation: candidate.event_generation,
        previous_event_digest,
        event_digest,
    })
}

/// Exact namespace inventory persisted by conflict tombstones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityConflictNamespaceKindV1 {
    Grant,
    Lease,
    Allocation,
    Consumption,
    Decision,
    Bootstrap,
}

impl AuthorityConflictNamespaceKindV1 {
    pub(crate) const fn sql_code_v1(self) -> &'static str {
        match self {
            Self::Grant => "GRANT",
            Self::Lease => "LEASE",
            Self::Allocation => "ALLOCATION",
            Self::Consumption => "CONSUMPTION",
            Self::Decision => "DECISION",
            Self::Bootstrap => "BOOTSTRAP",
        }
    }

    const fn event_subject_kind_v1(self) -> AuthorityEventSubjectKindV1 {
        match self {
            Self::Grant => AuthorityEventSubjectKindV1::Grant,
            Self::Lease | Self::Allocation | Self::Consumption => {
                AuthorityEventSubjectKindV1::Lease
            }
            Self::Decision => AuthorityEventSubjectKindV1::Decision,
            Self::Bootstrap => AuthorityEventSubjectKindV1::Root,
        }
    }
}

/// Immutable restricted inputs for one conflict proof.
pub(crate) struct AuthorityConflictCandidateV1 {
    conflict_id: Sha256Digest,
    namespace_kind: AuthorityConflictNamespaceKindV1,
    namespace_digest: Sha256Digest,
    expected_binding_digest: Sha256Digest,
    observed_binding_digest: Sha256Digest,
    attempt_id: Sha256Digest,
    created_generation: Generation,
    event_id: Sha256Digest,
}

impl AuthorityConflictCandidateV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        conflict_id: Sha256Digest,
        namespace_kind: AuthorityConflictNamespaceKindV1,
        namespace_digest: Sha256Digest,
        expected_binding_digest: Sha256Digest,
        observed_binding_digest: Sha256Digest,
        attempt_id: Sha256Digest,
        created_generation: Generation,
        event_id: Sha256Digest,
    ) -> Self {
        Self {
            conflict_id,
            namespace_kind,
            namespace_digest,
            expected_binding_digest,
            observed_binding_digest,
            attempt_id,
            created_generation,
            event_id,
        }
    }
}

impl fmt::Debug for AuthorityConflictCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityConflictCandidateV1(..)")
    }
}

pub(crate) struct AuthorityConflictRecordV1 {
    namespace_kind: AuthorityConflictNamespaceKindV1,
    created_generation: Generation,
}

impl AuthorityConflictRecordV1 {
    pub(crate) const fn namespace_kind_v1(&self) -> AuthorityConflictNamespaceKindV1 {
        self.namespace_kind
    }

    pub(crate) const fn created_generation_v1(&self) -> Generation {
        self.created_generation
    }
}

impl fmt::Debug for AuthorityConflictRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityConflictRecordV1(..)")
    }
}

pub(crate) fn retain_conflict_tombstone_v1(
    transaction: &Transaction<'_>,
    candidate: AuthorityConflictCandidateV1,
) -> Result<AuthorityConflictRecordV1, AuthorityHistoryErrorV1> {
    verify_related_event_v1(
        transaction,
        candidate.event_id,
        candidate.attempt_id,
        AuthorityEventKindV1::ConflictRetained,
        candidate.namespace_kind.event_subject_kind_v1(),
        candidate.namespace_digest,
        AuthorityEventResultV1::ConflictRetained,
        AuthorityEventReasonV1::ConflictingIdentityReuse,
        candidate.created_generation,
    )?;
    if latest_generation_v1(
        transaction,
        "SELECT MAX(created_generation) FROM authority_conflict_tombstones",
    )?
    .is_some_and(|generation| candidate.created_generation.get() <= generation)
    {
        return Err(AuthorityHistoryErrorV1::GenerationNotIncreasing);
    }

    transaction
        .execute(
            "INSERT INTO authority_conflict_tombstones (
                conflict_id, namespace_kind, namespace_digest,
                expected_binding_digest, observed_binding_digest, attempt_id,
                reason_code, created_generation, event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6,
                       'CONFLICTING_IDENTITY_REUSE', ?7, ?8)",
            params![
                candidate.conflict_id.to_hex(),
                candidate.namespace_kind.sql_code_v1(),
                candidate.namespace_digest.to_hex(),
                candidate.expected_binding_digest.to_hex(),
                candidate.observed_binding_digest.to_hex(),
                candidate.attempt_id.to_hex(),
                sql_integer_v1(candidate.created_generation.get())?,
                candidate.event_id.to_hex(),
            ],
        )
        .map_err(map_insert_error_v1)?;

    Ok(AuthorityConflictRecordV1 {
        namespace_kind: candidate.namespace_kind,
        created_generation: candidate.created_generation,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_related_event_v1(
    connection: &Connection,
    event_id: Sha256Digest,
    attempt_id: Sha256Digest,
    event_kind: AuthorityEventKindV1,
    subject_kind: AuthorityEventSubjectKindV1,
    subject_reference_digest: Sha256Digest,
    result: AuthorityEventResultV1,
    reason: AuthorityEventReasonV1,
    generation: Generation,
) -> Result<(), AuthorityHistoryErrorV1> {
    verify_attempt_event_binding_v1(connection, attempt_id, event_id)?;
    let event_id_hex = event_id.to_hex();
    let row = connection
        .query_row(
            "SELECT event_kind, subject_kind, subject_reference_digest, attempt_id,
                    result_code, reason_code, event_generation, event_digest
             FROM authority_events WHERE event_id = ?1",
            [&event_id_hex],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?
        .ok_or(AuthorityHistoryErrorV1::IncompleteGraph)?;

    if row.0 != event_kind.sql_code_v1()
        || row.1 != subject_kind.sql_code_v1()
        || row.2 != subject_reference_digest.to_hex()
        || row.3 != attempt_id.to_hex()
        || row.4 != result.sql_code_v1()
        || row.5 != reason.sql_code_v1()
        || row.6 != sql_integer_v1(generation.get())?
        || Sha256Digest::parse_hex(&row.7).is_err()
    {
        return Err(AuthorityHistoryErrorV1::IncompleteGraph);
    }
    Ok(())
}

fn verify_attempt_event_binding_v1(
    connection: &Connection,
    attempt_id: Sha256Digest,
    event_id: Sha256Digest,
) -> Result<(), AuthorityHistoryErrorV1> {
    let attempt_id_hex = attempt_id.to_hex();
    let retained_event_id = connection
        .query_row(
            "SELECT event_id FROM authority_attempts WHERE attempt_id = ?1",
            [&attempt_id_hex],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?
        .ok_or(AuthorityHistoryErrorV1::MissingAttempt)?;
    if retained_event_id != event_id.to_hex() {
        return Err(AuthorityHistoryErrorV1::IncompleteGraph);
    }
    Ok(())
}

fn latest_event_generation_and_digest_v1(
    connection: &Connection,
) -> Result<Option<(u64, Sha256Digest)>, AuthorityHistoryErrorV1> {
    let row = connection
        .query_row(
            "SELECT event_generation, event_digest
             FROM authority_events ORDER BY event_generation DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?;
    row.map(|(generation, digest)| {
        let generation = u64::try_from(generation).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
        let digest =
            Sha256Digest::parse_hex(&digest).map_err(|_| AuthorityHistoryErrorV1::Corrupt)?;
        Ok((generation, digest))
    })
    .transpose()
}

pub(crate) fn latest_generation_v1(
    connection: &Connection,
    statement: &str,
) -> Result<Option<u64>, AuthorityHistoryErrorV1> {
    let value = connection
        .query_row(statement, [], |row| row.get::<_, Option<i64>>(0))
        .map_err(|_| AuthorityHistoryErrorV1::Unavailable)?;
    value
        .map(|value| u64::try_from(value).map_err(|_| AuthorityHistoryErrorV1::Corrupt))
        .transpose()
}

fn event_digest_v1(
    candidate: &AuthorityEventCandidateV1,
    previous_event_digest: Option<Sha256Digest>,
) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(EVENT_DIGEST_DOMAIN_V1);
    push_digest_field_v1(&mut bytes, candidate.event_id);
    push_field_v1(&mut bytes, candidate.event_kind.sql_code_v1().as_bytes());
    push_field_v1(&mut bytes, candidate.subject_kind.sql_code_v1().as_bytes());
    push_digest_field_v1(&mut bytes, candidate.subject_reference_digest);
    push_digest_field_v1(&mut bytes, candidate.attempt_id);
    push_field_v1(&mut bytes, candidate.result.sql_code_v1().as_bytes());
    push_field_v1(&mut bytes, candidate.reason.sql_code_v1().as_bytes());
    push_field_v1(
        &mut bytes,
        candidate.event_generation.get().to_string().as_bytes(),
    );
    push_field_v1(
        &mut bytes,
        candidate.observed_at_utc_ms.get().to_string().as_bytes(),
    );
    push_field_v1(
        &mut bytes,
        candidate
            .observed_at_monotonic_ms
            .map(|value| value.get().to_string())
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    push_field_v1(
        &mut bytes,
        candidate
            .boot_id
            .as_ref()
            .map(Identifier::as_str)
            .unwrap_or("")
            .as_bytes(),
    );
    match previous_event_digest {
        Some(digest) => push_digest_field_v1(&mut bytes, digest),
        None => push_field_v1(&mut bytes, b""),
    }
    Sha256Digest::digest(&bytes)
}

fn push_digest_field_v1(destination: &mut Vec<u8>, digest: Sha256Digest) {
    push_field_v1(destination, digest.as_bytes());
}

fn push_field_v1(destination: &mut Vec<u8>, field: &[u8]) {
    let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(field);
}

pub(crate) fn sql_integer_v1(value: u64) -> Result<i64, AuthorityHistoryErrorV1> {
    i64::try_from(value).map_err(|_| AuthorityHistoryErrorV1::InvalidRecord)
}

pub(crate) fn map_insert_error_v1(error: rusqlite::Error) -> AuthorityHistoryErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            AuthorityHistoryErrorV1::IdentityConflict
        }
        _ => AuthorityHistoryErrorV1::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::TASK_AUTHORITY_STORE_SCHEMA_V1_SQL;

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("event test generation is valid")
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("event test safe integer is valid")
    }

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("event SQLite opens");
        connection
            .pragma_update(None, "foreign_keys", true)
            .expect("foreign keys enable");
        connection
            .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
            .expect("exact HLXA schema installs");
        connection
    }

    fn retain_attempt(
        transaction: &Transaction<'_>,
        attempt: Sha256Digest,
        event: Sha256Digest,
        attempt_generation: u64,
        outcome: AuthorityEventResultV1,
    ) {
        transaction
            .execute(
                "INSERT INTO authority_attempts (
                    attempt_id, operation_kind, namespace_digest, input_graph_digest,
                    caller_deadline_monotonic_ms, outcome_code,
                    outcome_binding_digest, attempt_generation, event_id
                 ) VALUES (?1, 'ROOT_LEASE_ISSUE', ?2, ?3, 1000, ?4, ?5, ?6, ?7)",
                params![
                    attempt.to_hex(),
                    digest(201).to_hex(),
                    digest(202).to_hex(),
                    outcome.sql_code_v1(),
                    digest(203).to_hex(),
                    sql_integer_v1(attempt_generation).expect("generation fits"),
                    event.to_hex(),
                ],
            )
            .expect("attempt retains before its deferred event");
    }

    #[allow(clippy::too_many_arguments)]
    fn event_candidate(
        event: Sha256Digest,
        attempt: Sha256Digest,
        generation_value: u64,
        subject_reference: Sha256Digest,
        kind: AuthorityEventKindV1,
        subject: AuthorityEventSubjectKindV1,
        result: AuthorityEventResultV1,
        reason: AuthorityEventReasonV1,
    ) -> AuthorityEventCandidateV1 {
        AuthorityEventCandidateV1::try_new(
            event,
            kind,
            subject,
            subject_reference,
            attempt,
            result,
            reason,
            generation(generation_value),
            safe(10_000 + generation_value),
            Some(safe(100 + generation_value)),
            Some(Identifier::new("boot-event-v1").expect("boot identifier is valid")),
        )
        .expect("event candidate is coherent")
    }

    #[test]
    fn event_chain_is_strictly_increasing_and_opaque() {
        let mut connection = connection();
        let first_digest = {
            let transaction = connection.transaction().expect("writer starts");
            retain_attempt(
                &transaction,
                digest(1),
                digest(2),
                1,
                AuthorityEventResultV1::CommittedRetained,
            );
            let record = retain_authority_event_v1(
                &transaction,
                event_candidate(
                    digest(2),
                    digest(1),
                    1,
                    digest(3),
                    AuthorityEventKindV1::RootLeaseIssued,
                    AuthorityEventSubjectKindV1::Lease,
                    AuthorityEventResultV1::CommittedRetained,
                    AuthorityEventReasonV1::RootLeaseIssued,
                ),
            )
            .expect("first event retains");
            assert_eq!(record.previous_event_digest_v1(), None);
            assert!(!format!("{record:?}").contains(&digest(1).to_hex()));
            transaction.commit().expect("first graph commits");
            record.event_digest_v1()
        };

        let transaction = connection.transaction().expect("second writer starts");
        retain_attempt(
            &transaction,
            digest(4),
            digest(5),
            2,
            AuthorityEventResultV1::CommittedRetained,
        );
        let second = retain_authority_event_v1(
            &transaction,
            event_candidate(
                digest(5),
                digest(4),
                2,
                digest(6),
                AuthorityEventKindV1::DecisionRetained,
                AuthorityEventSubjectKindV1::Decision,
                AuthorityEventResultV1::CommittedRetained,
                AuthorityEventReasonV1::DecisionRetained,
            ),
        )
        .expect("second event retains");
        assert_eq!(second.previous_event_digest_v1(), Some(first_digest));
        transaction.commit().expect("second graph commits");

        let transaction = connection.transaction().expect("stale writer starts");
        retain_attempt(
            &transaction,
            digest(7),
            digest(8),
            3,
            AuthorityEventResultV1::CommittedRetained,
        );
        assert_eq!(
            retain_authority_event_v1(
                &transaction,
                event_candidate(
                    digest(8),
                    digest(7),
                    2,
                    digest(9),
                    AuthorityEventKindV1::CounterConsumed,
                    AuthorityEventSubjectKindV1::Lease,
                    AuthorityEventResultV1::CommittedRetained,
                    AuthorityEventReasonV1::CounterConsumed,
                ),
            )
            .unwrap_err(),
            AuthorityHistoryErrorV1::GenerationNotIncreasing
        );
    }

    #[test]
    fn conflict_tombstone_requires_its_exact_redacted_event_and_is_immutable() {
        let mut connection = connection();
        let transaction = connection.transaction().expect("conflict writer starts");
        retain_attempt(
            &transaction,
            digest(20),
            digest(21),
            1,
            AuthorityEventResultV1::ConflictRetained,
        );
        retain_authority_event_v1(
            &transaction,
            event_candidate(
                digest(21),
                digest(20),
                1,
                digest(22),
                AuthorityEventKindV1::ConflictRetained,
                AuthorityEventSubjectKindV1::Grant,
                AuthorityEventResultV1::ConflictRetained,
                AuthorityEventReasonV1::ConflictingIdentityReuse,
            ),
        )
        .expect("conflict event retains");
        let conflict = retain_conflict_tombstone_v1(
            &transaction,
            AuthorityConflictCandidateV1::new(
                digest(23),
                AuthorityConflictNamespaceKindV1::Grant,
                digest(22),
                digest(24),
                digest(25),
                digest(20),
                generation(1),
                digest(21),
            ),
        )
        .expect("conflict tombstone retains");
        assert_eq!(
            conflict.namespace_kind_v1(),
            AuthorityConflictNamespaceKindV1::Grant
        );
        assert!(!format!("{conflict:?}").contains(&digest(24).to_hex()));
        transaction.commit().expect("conflict graph commits");

        assert!(connection
            .execute(
                "UPDATE authority_conflict_tombstones SET namespace_digest = ?1",
                [digest(26).to_hex()],
            )
            .is_err());
        assert!(connection
            .execute("DELETE FROM authority_conflict_tombstones", [])
            .is_err());
    }

    #[test]
    fn event_candidate_rejects_partial_boot_observations_and_errors_are_payload_free() {
        let invalid = AuthorityEventCandidateV1::try_new(
            digest(30),
            AuthorityEventKindV1::AuthorityRevoked,
            AuthorityEventSubjectKindV1::Revocation,
            digest(31),
            digest(32),
            AuthorityEventResultV1::CommittedRetained,
            AuthorityEventReasonV1::AdminRevoked,
            generation(1),
            safe(100),
            Some(safe(10)),
            None,
        )
        .unwrap_err();
        assert_eq!(invalid, AuthorityHistoryErrorV1::InvalidRecord);
        assert_eq!(format!("{invalid:?}"), "AUTHORITY_HISTORY_INVALID_RECORD");
    }

    #[test]
    fn event_result_codes_remain_exactly_aligned_with_core() {
        let values = [
            AuthorityRetainedOutcomeCodeV1::CommittedRetained,
            AuthorityRetainedOutcomeCodeV1::ConflictRetained,
            AuthorityRetainedOutcomeCodeV1::RestorePending,
        ];
        for value in values {
            assert_eq!(
                AuthorityEventResultV1::from_core_v1(&value).sql_code_v1(),
                value.sql_code_v1()
            );
        }
    }
}
