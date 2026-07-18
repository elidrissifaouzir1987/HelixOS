//! Create-only human-grant retention and exact root-claim lookup.

use helix_task_authority::{
    AuthorityAttemptBindingV1, AuthorityAttemptIdV1, AuthorityInputGraphDigestV1,
    AuthorityNamespaceDigestV1, AuthorityOperationKindV1, AuthorityOutcomeBindingDigestV1,
    AuthorityRetainedAttemptV1, AuthorityRetainedOutcomeCodeV1, RootLeaseCandidateV1,
};
use helix_task_authority_contracts::{Generation, SafeU64, Sha256Digest};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::fmt;

pub(crate) enum GrantNamespaceStateV1 {
    Vacant,
    Exact(Box<RootGraphReadbackV1>),
    Conflict {
        expected_input_graph_digest: Sha256Digest,
    },
}

impl fmt::Debug for GrantNamespaceStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Vacant => "GrantNamespaceStateV1::Vacant",
            Self::Exact(_) => "GrantNamespaceStateV1::Exact(..)",
            Self::Conflict { .. } => "GrantNamespaceStateV1::Conflict(..)",
        })
    }
}

pub(crate) struct RootGraphReadbackV1 {
    pub(crate) retained_attempt: AuthorityRetainedAttemptV1,
    pub(crate) source_grant_digest: Sha256Digest,
    pub(crate) root_lease_digest: Sha256Digest,
    pub(crate) source_grant_wire: Vec<u8>,
    pub(crate) root_lease_wire: Vec<u8>,
}

impl fmt::Debug for RootGraphReadbackV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootGraphReadbackV1(..)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantStoreErrorV1 {
    Corrupt,
    Unavailable,
}

pub(crate) fn classify_grant_namespace_v1(
    connection: &Connection,
    candidate: &RootLeaseCandidateV1,
) -> Result<GrantNamespaceStateV1, GrantStoreErrorV1> {
    let grant = candidate.source_grant_v1().claims();
    let row = connection
        .query_row(
            "SELECT
                 grant.grant_digest, grant.signed_wire, grant.signed_wire_sha256,
                 claim.root_lease_digest, lease.signed_wire, lease.signed_wire_sha256,
                 attempt.attempt_id, attempt.operation_kind, attempt.namespace_digest,
                 attempt.input_graph_digest, attempt.caller_deadline_monotonic_ms,
                 attempt.outcome_code, attempt.outcome_binding_digest,
                 attempt.attempt_generation, attempt.event_id,
                 event.event_kind, event.subject_kind, event.result_code, event.reason_code,
                 event.event_generation,
                 usage.allocated_read_bytes, usage.allocated_distinct_files,
                 usage.allocated_actions, usage.allocated_egress_bytes,
                 usage.allocated_cost_micro_units, usage.allocated_plans,
                 usage.allocated_approvals, usage.allocated_child_leases,
                 usage.consumed_read_bytes, usage.consumed_distinct_files,
                 usage.consumed_actions, usage.consumed_plans, usage.consumed_approvals,
                 usage.allocation_generation, usage.counter_generation,
                 claim.claim_generation, lease.created_generation,
                 grant.retained_generation, grant.verification_generation,
                 lease.source_grant_issuer_id, lease.source_grant_id,
                 lease.source_grant_digest, lease.delegation_depth,
                 lease.creation_attempt_id, claim.claim_attempt_id, claim.event_id
             FROM human_grant_claims AS claim
             JOIN human_request_grants AS grant
               ON grant.grant_issuer_id = claim.grant_issuer_id
              AND grant.grant_id = claim.grant_id
             JOIN task_leases AS lease
               ON lease.lease_issuer_id = claim.root_lease_issuer_id
              AND lease.lease_id = claim.root_lease_id
             JOIN task_lease_usage AS usage
               ON usage.lease_issuer_id = lease.lease_issuer_id
              AND usage.lease_id = lease.lease_id
             JOIN authority_attempts AS attempt
               ON attempt.attempt_id = claim.claim_attempt_id
             JOIN authority_events AS event ON event.event_id = claim.event_id
             WHERE claim.grant_issuer_id = ?1 AND claim.grant_id = ?2",
            params![grant.issuer_id(), grant.grant_id().to_hex()],
            |row| {
                let mut text = Vec::with_capacity(21);
                for index in [
                    0, 2, 3, 5, 6, 7, 8, 9, 11, 12, 14, 15, 16, 17, 18, 39, 40, 41, 43, 44, 45,
                ] {
                    text.push(row.get::<_, String>(index)?);
                }
                let grant_wire = row.get::<_, Vec<u8>>(1)?;
                let lease_wire = row.get::<_, Vec<u8>>(4)?;
                let mut integers = Vec::with_capacity(20);
                for index in 10..=13 {
                    if index != 11 && index != 12 {
                        integers.push(row.get::<_, i64>(index)?);
                    }
                }
                integers.push(row.get::<_, i64>(19)?);
                for index in 20..=38 {
                    integers.push(row.get::<_, i64>(index)?);
                }
                integers.push(row.get::<_, i64>(42)?);
                Ok((text, grant_wire, lease_wire, integers))
            },
        )
        .optional()
        .map_err(|_| GrantStoreErrorV1::Unavailable)?;

    let Some((text, grant_wire, lease_wire, integers)) = row else {
        let retained_grant = connection
            .query_row(
                "SELECT 1 FROM human_request_grants
                 WHERE grant_issuer_id = ?1 AND grant_id = ?2",
                params![grant.issuer_id(), grant.grant_id().to_hex()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|_| GrantStoreErrorV1::Unavailable)?;
        return if retained_grant.is_some() {
            Err(GrantStoreErrorV1::Corrupt)
        } else {
            Ok(GrantNamespaceStateV1::Vacant)
        };
    };

    decode_complete_root_graph_v1(candidate, text, grant_wire, lease_wire, integers)
}

fn decode_complete_root_graph_v1(
    candidate: &RootLeaseCandidateV1,
    text: Vec<String>,
    grant_wire: Vec<u8>,
    lease_wire: Vec<u8>,
    integers: Vec<i64>,
) -> Result<GrantNamespaceStateV1, GrantStoreErrorV1> {
    if text.len() != 21 || integers.len() != 23 {
        return Err(GrantStoreErrorV1::Corrupt);
    }
    let digest_at = |index: usize| {
        Sha256Digest::parse_hex(&text[index]).map_err(|_| GrantStoreErrorV1::Corrupt)
    };
    let nonnegative = |value: i64| u64::try_from(value).map_err(|_| GrantStoreErrorV1::Corrupt);
    let grant_digest = digest_at(0)?;
    let grant_wire_digest = digest_at(1)?;
    let root_lease_digest = digest_at(2)?;
    let lease_wire_digest = digest_at(3)?;
    let attempt_id = digest_at(4)?;
    let namespace_digest = digest_at(6)?;
    let input_graph_digest = digest_at(7)?;
    let outcome_binding_digest = digest_at(9)?;
    let event_id = digest_at(10)?;
    let event_generation = nonnegative(integers[2])?;
    let attempt_generation = nonnegative(integers[1])?;
    let deadline = nonnegative(integers[0])?;

    let all_usage_zero = integers[3..16].iter().all(|value| *value == 0);
    let graph_generation_values = &integers[16..21];
    let candidate_grant = candidate.source_grant_v1().claims();
    if grant_digest != candidate_grant.grant_digest()
        || Sha256Digest::digest(&grant_wire) != grant_wire_digest
        || Sha256Digest::digest(&lease_wire) != lease_wire_digest
        || grant_wire != candidate.source_grant_wire_v1()
        || text[5] != AuthorityOperationKindV1::RootLeaseIssue.sql_code_v1()
        || text[8] != AuthorityRetainedOutcomeCodeV1::CommittedRetained.sql_code_v1()
        || text[11] != "ROOT_LEASE_ISSUED"
        || text[12] != "LEASE"
        || text[13] != "COMMITTED_RETAINED"
        || text[14] != "ROOT_LEASE_ISSUED"
        || text[15] != candidate_grant.issuer_id()
        || text[16] != candidate_grant.grant_id().to_hex()
        || text[17] != candidate_grant.grant_digest().to_hex()
        || integers[22] != 0
        || text[18] != text[4]
        || text[19] != text[4]
        || text[20] != text[10]
        || event_generation != attempt_generation
        || !all_usage_zero
        || graph_generation_values
            .iter()
            .any(|value| nonnegative(*value).ok() != Some(attempt_generation))
    {
        return Err(GrantStoreErrorV1::Corrupt);
    }

    let candidate_attempt = candidate.attempt_v1();
    if namespace_digest != candidate_attempt.namespace_digest_v1().digest_v1() {
        return Err(GrantStoreErrorV1::Corrupt);
    }
    if input_graph_digest != candidate_attempt.input_graph_digest_v1().digest_v1() {
        return Ok(GrantNamespaceStateV1::Conflict {
            expected_input_graph_digest: input_graph_digest,
        });
    }

    let attempt = AuthorityAttemptBindingV1::from_verified_parts_v1(
        AuthorityAttemptIdV1::from_verified_digest_v1(attempt_id),
        AuthorityOperationKindV1::RootLeaseIssue,
        AuthorityNamespaceDigestV1::from_verified_digest_v1(namespace_digest),
        AuthorityInputGraphDigestV1::from_verified_digest_v1(input_graph_digest),
        SafeU64::new(deadline).map_err(|_| GrantStoreErrorV1::Corrupt)?,
    )
    .ok_or(GrantStoreErrorV1::Corrupt)?;
    let retained = AuthorityRetainedAttemptV1::from_verified_parts_v1(
        attempt,
        AuthorityRetainedOutcomeCodeV1::CommittedRetained,
        AuthorityOutcomeBindingDigestV1::from_verified_digest_v1(outcome_binding_digest),
        Generation::new(attempt_generation).map_err(|_| GrantStoreErrorV1::Corrupt)?,
        event_id,
    );
    Ok(GrantNamespaceStateV1::Exact(Box::new(
        RootGraphReadbackV1 {
            retained_attempt: retained,
            source_grant_digest: grant_digest,
            root_lease_digest,
            source_grant_wire: grant_wire,
            root_lease_wire: lease_wire,
        },
    )))
}

pub(crate) fn retain_human_request_grant_v1(
    transaction: &Transaction<'_>,
    candidate: &RootLeaseCandidateV1,
    generation: Generation,
    verification_generation: Generation,
) -> Result<(), GrantStoreErrorV1> {
    let claims = candidate.source_grant_v1().claims();
    let wire = candidate.source_grant_wire_v1();
    transaction
        .execute(
            "INSERT INTO human_request_grants (
                 grant_issuer_id, grant_id, grant_digest, signed_wire, signed_wire_sha256,
                 key_purpose, key_id, key_fingerprint, principal_id, channel_id, session_id,
                 audience, scope_template_id, scope_template_digest,
                 scope_template_generation, issued_at_utc_ms, expires_at_utc_ms,
                 verification_generation, retained_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'request-surface-grant-signing', ?6, ?7,
                       ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                claims.issuer_id(),
                claims.grant_id().to_hex(),
                claims.grant_digest().to_hex(),
                wire,
                Sha256Digest::digest(wire).to_hex(),
                claims.key_id(),
                candidate
                    .source_grant_v1()
                    .verified_key_fingerprint()
                    .to_hex(),
                claims.principal_id(),
                claims.channel_id(),
                claims.session_id(),
                claims.audience(),
                claims.scope_template_id(),
                claims.scope_template_digest().to_hex(),
                to_sql_v1(claims.scope_template_generation())?,
                to_sql_v1(claims.issued_at_utc_ms())?,
                to_sql_v1(claims.expires_at_utc_ms())?,
                to_sql_v1(verification_generation.get())?,
                to_sql_v1(generation.get())?,
            ],
        )
        .map_err(|_| GrantStoreErrorV1::Unavailable)?;
    Ok(())
}

pub(crate) fn read_root_graph_for_retained_attempt_v1(
    connection: &Connection,
    retained: AuthorityRetainedAttemptV1,
) -> Result<RootGraphReadbackV1, GrantStoreErrorV1> {
    let attempt_id = retained.attempt_v1().attempt_id_v1().digest_v1().to_hex();
    let row = connection
        .query_row(
            "SELECT grant.signed_wire, grant.signed_wire_sha256, grant.grant_digest,
                    lease.signed_wire, lease.signed_wire_sha256, lease.lease_digest,
                    lease.source_grant_issuer_id, lease.source_grant_id,
                    lease.source_grant_digest, lease.delegation_depth,
                    lease.creation_attempt_id, lease.created_generation,
                    grant.grant_issuer_id, grant.grant_id, grant.retained_generation,
                    claim.claim_attempt_id, claim.claim_generation, claim.event_id,
                    usage.allocated_read_bytes, usage.allocated_distinct_files,
                    usage.allocated_actions, usage.allocated_egress_bytes,
                    usage.allocated_cost_micro_units, usage.allocated_plans,
                    usage.allocated_approvals, usage.allocated_child_leases,
                    usage.consumed_read_bytes, usage.consumed_distinct_files,
                    usage.consumed_actions, usage.consumed_plans, usage.consumed_approvals,
                    usage.allocation_generation, usage.counter_generation
             FROM human_grant_claims AS claim
             JOIN human_request_grants AS grant
               ON grant.grant_issuer_id = claim.grant_issuer_id
              AND grant.grant_id = claim.grant_id
             JOIN task_leases AS lease
               ON lease.lease_issuer_id = claim.root_lease_issuer_id
              AND lease.lease_id = claim.root_lease_id
             JOIN task_lease_usage AS usage
               ON usage.lease_issuer_id = lease.lease_issuer_id
              AND usage.lease_id = lease.lease_id
             WHERE claim.claim_attempt_id = ?1",
            [&attempt_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, String>(17)?,
                    (18..=32)
                        .map(|index| row.get::<_, i64>(index))
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                ))
            },
        )
        .optional()
        .map_err(|_| GrantStoreErrorV1::Unavailable)?
        .ok_or(GrantStoreErrorV1::Corrupt)?;
    let generation = i64::try_from(retained.attempt_generation_v1().get())
        .map_err(|_| GrantStoreErrorV1::Corrupt)?;
    let zero_usage = row.18[..13].iter().all(|value| *value == 0);
    let usage_generations = &row.18[13..];
    let source_grant_digest =
        Sha256Digest::parse_hex(&row.2).map_err(|_| GrantStoreErrorV1::Corrupt)?;
    let root_lease_digest =
        Sha256Digest::parse_hex(&row.5).map_err(|_| GrantStoreErrorV1::Corrupt)?;
    if Sha256Digest::digest(&row.0).to_hex() != row.1
        || Sha256Digest::digest(&row.3).to_hex() != row.4
        || row.2 != row.8
        || row.6 != row.12
        || row.7 != row.13
        || row.9 != 0
        || row.10 != attempt_id
        || row.11 != generation
        || row.14 != generation
        || row.15 != attempt_id
        || row.16 != generation
        || row.17 != retained.event_id_v1().to_hex()
        || !zero_usage
        || usage_generations.iter().any(|value| *value != generation)
    {
        return Err(GrantStoreErrorV1::Corrupt);
    }
    Ok(RootGraphReadbackV1 {
        retained_attempt: retained,
        source_grant_digest,
        root_lease_digest,
        source_grant_wire: row.0,
        root_lease_wire: row.3,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn retain_human_grant_claim_v1(
    transaction: &Transaction<'_>,
    candidate: &RootLeaseCandidateV1,
    root_lease_issuer_id: &str,
    root_lease_id: Sha256Digest,
    root_lease_digest: Sha256Digest,
    generation: Generation,
    event_id: Sha256Digest,
) -> Result<(), GrantStoreErrorV1> {
    let grant = candidate.source_grant_v1().claims();
    transaction
        .execute(
            "INSERT INTO human_grant_claims (
                 grant_issuer_id, grant_id, grant_digest, claim_attempt_id,
                 root_lease_issuer_id, root_lease_id, root_lease_digest,
                 claim_generation, event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                grant.issuer_id(),
                grant.grant_id().to_hex(),
                grant.grant_digest().to_hex(),
                candidate.attempt_v1().attempt_id_v1().digest_v1().to_hex(),
                root_lease_issuer_id,
                root_lease_id.to_hex(),
                root_lease_digest.to_hex(),
                to_sql_v1(generation.get())?,
                event_id.to_hex(),
            ],
        )
        .map_err(|_| GrantStoreErrorV1::Unavailable)?;
    Ok(())
}

fn to_sql_v1(value: u64) -> Result<i64, GrantStoreErrorV1> {
    i64::try_from(value).map_err(|_| GrantStoreErrorV1::Corrupt)
}
