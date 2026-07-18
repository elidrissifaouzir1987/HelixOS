//! Atomic SQLite root-lease issuance graph.

use crate::connection::open_existing_v1;
use crate::event::{
    retain_authority_event_v1, retain_conflict_tombstone_v1, AuthorityConflictCandidateV1,
    AuthorityConflictNamespaceKindV1, AuthorityEventCandidateV1, AuthorityEventKindV1,
    AuthorityEventReasonV1, AuthorityEventResultV1, AuthorityEventSubjectKindV1,
};
use crate::grant::{
    classify_grant_namespace_v1, retain_human_grant_claim_v1, retain_human_request_grant_v1,
    GrantNamespaceStateV1, GrantStoreErrorV1, RootGraphReadbackV1,
};
use crate::readback::{
    abandon_uncertain_connection_v1, one_fresh_root_uncertain_readback_v1,
    RootLeaseReadbackExpectationV1,
};
use crate::AuthorityStoreConfigV1;
use helix_task_authority::{
    AuthorityAtomicMutationV1, AuthorityAtomicStoreV1, AuthorityAttemptBindingV1,
    AuthorityClockObservationV1, AuthorityClockProviderV1, AuthorityInputGraphDigestV1,
    AuthorityMutationOutcomeV1, AuthorityNamespaceDigestV1, AuthorityOperationKindV1,
    AuthorityOutcomeBindingDigestV1, AuthorityRetainedAttemptV1, AuthorityRetainedGraphV1,
    AuthorityRetainedOutcomeCodeV1, AuthorityUncertainReadbackV1, RootLeaseCandidateV1,
};
use helix_task_authority_contracts::{
    decode_and_verify_human_request_grant_v1, decode_and_verify_retained_human_request_grant_v1,
    decode_and_verify_retained_task_lease_v1, decode_and_verify_task_lease_v1,
    AuthenticHumanRequestGrantV1, AuthenticTaskLeaseV1, ContractError, Generation,
    HumanRequestGrantKeyResolver, HumanRequestGrantVerificationKeyV1, Identifier, SafeU64,
    Sha256Digest, TaskLeaseKeyResolver, TaskLeaseVerificationKeyV1,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::fmt;
use std::sync::Arc;

const ROOT_OUTCOME_DOMAIN_V1: &[u8] = b"HELIXOS\0ROOT-LEASE-OUTCOME\0V1\0";
const ROOT_EVENT_ID_DOMAIN_V1: &[u8] = b"HELIXOS\0ROOT-LEASE-EVENT-ID\0V1\0";
const ROOT_CONFLICT_ID_DOMAIN_V1: &[u8] = b"HELIXOS\0ROOT-LEASE-CONFLICT-ID\0V1\0";

/// Exact retained root wire plus immutable attempt evidence.
pub struct RetainedRootLeaseV1 {
    attempt: AuthorityRetainedAttemptV1,
    source_grant_wire: Vec<u8>,
    root_lease_wire: Vec<u8>,
}

impl RetainedRootLeaseV1 {
    pub fn source_grant_wire_v1(&self) -> &[u8] {
        &self.source_grant_wire
    }

    pub fn root_lease_wire_v1(&self) -> &[u8] {
        &self.root_lease_wire
    }
}

impl fmt::Debug for RetainedRootLeaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedRootLeaseV1(..)")
    }
}

impl AuthorityRetainedGraphV1 for RetainedRootLeaseV1 {
    fn operation_kind_v1(&self) -> AuthorityOperationKindV1 {
        self.attempt.operation_kind_v1()
    }

    fn attempt_id_v1(&self) -> &helix_task_authority::AuthorityAttemptIdV1 {
        self.attempt.attempt_id_v1()
    }

    fn namespace_digest_v1(&self) -> &AuthorityNamespaceDigestV1 {
        self.attempt.namespace_digest_v1()
    }

    fn input_graph_digest_v1(&self) -> &AuthorityInputGraphDigestV1 {
        self.attempt.input_graph_digest_v1()
    }

    fn caller_deadline_monotonic_ms_v1(&self) -> SafeU64 {
        self.attempt.caller_deadline_monotonic_ms_v1()
    }

    fn outcome_code_v1(&self) -> &AuthorityRetainedOutcomeCodeV1 {
        self.attempt.outcome_code_v1()
    }

    fn outcome_binding_digest_v1(&self) -> &AuthorityOutcomeBindingDigestV1 {
        self.attempt.outcome_binding_digest_v1()
    }

    fn attempt_generation_v1(&self) -> Generation {
        self.attempt.attempt_generation_v1()
    }

    fn event_id_v1(&self) -> Sha256Digest {
        self.attempt.event_id_v1()
    }
}

/// Thread-safe store handle. Every mutation opens and admits one fresh connection.
pub struct SqliteRootLeaseStoreV1 {
    config: AuthorityStoreConfigV1,
    clock: Arc<dyn AuthorityClockProviderV1>,
    root_id: Box<str>,
    #[cfg(test)]
    simulate_lost_ack: bool,
}

impl SqliteRootLeaseStoreV1 {
    pub fn new_v1(
        config: AuthorityStoreConfigV1,
        clock: Arc<dyn AuthorityClockProviderV1>,
        root_id: Identifier,
    ) -> Self {
        Self {
            config,
            clock,
            root_id: root_id.as_str().into(),
            #[cfg(test)]
            simulate_lost_ack: false,
        }
    }

    #[cfg(test)]
    fn with_simulated_lost_ack_v1(mut self) -> Self {
        self.simulate_lost_ack = true;
        self
    }
}

impl fmt::Debug for SqliteRootLeaseStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteRootLeaseStoreV1(..)")
    }
}

impl AuthorityAtomicStoreV1<RootLeaseCandidateV1> for SqliteRootLeaseStoreV1 {
    type Retained = RetainedRootLeaseV1;

    fn commit_atomic_once_v1(
        &self,
        candidate: RootLeaseCandidateV1,
    ) -> AuthorityMutationOutcomeV1<Self::Retained, AuthorityUncertainReadbackV1<Self::Retained>>
    {
        commit_root_graph_v1(self, candidate)
    }
}

#[derive(Clone, Copy)]
struct MetadataV1 {
    store_generation: Generation,
    trust_generation: Generation,
    grant_generation: Generation,
    lease_generation: Generation,
    allocation_generation: Generation,
    counter_generation: Generation,
    event_generation: Generation,
    boot_instance_epoch: Generation,
}

fn commit_root_graph_v1(
    store: &SqliteRootLeaseStoreV1,
    candidate: RootLeaseCandidateV1,
) -> AuthorityMutationOutcomeV1<
    RetainedRootLeaseV1,
    AuthorityUncertainReadbackV1<RetainedRootLeaseV1>,
> {
    let grant_claims = candidate.source_grant_v1().claims();
    let readback_expectation =
        RootLeaseReadbackExpectationV1::new(grant_claims.issuer_id(), grant_claims.grant_id());
    let mut opened = match open_existing_v1(
        store.config.clone(),
        store.clock.as_ref(),
        candidate.attempt_v1().caller_deadline_monotonic_ms_v1(),
        &store.root_id,
    ) {
        Ok(opened) => opened,
        Err(_) => return AuthorityMutationOutcomeV1::Unavailable,
    };
    let writer_clock = match store
        .clock
        .capture_v1(candidate.attempt_v1().caller_deadline_monotonic_ms_v1())
    {
        Ok(clock) => clock,
        Err(_) => return AuthorityMutationOutcomeV1::DeniedDefinite,
    };
    let transaction = match opened
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)
    {
        Ok(transaction) => transaction,
        Err(_) => return AuthorityMutationOutcomeV1::Unavailable,
    };

    let result = commit_root_transaction_v1(&transaction, &candidate, &writer_clock);
    match result {
        Ok(RootTransactionResultV1::Exact(readback)) => {
            let retained = match qualify_retained_readback_v1(&transaction, *readback) {
                Ok(retained) => retained,
                Err(_) => {
                    let _ = transaction.rollback();
                    return AuthorityMutationOutcomeV1::AmbiguousReconciliationRequired;
                }
            };
            if transaction.rollback().is_err() {
                AuthorityMutationOutcomeV1::AmbiguousReconciliationRequired
            } else {
                AuthorityMutationOutcomeV1::CommittedRetained(retained)
            }
        }
        Ok(RootTransactionResultV1::Committed {
            generation,
            event_id,
            outcome_binding_digest,
        }) => {
            let source_grant_wire = candidate.source_grant_wire_v1().to_vec();
            let root_lease_wire = candidate.root_lease_wire_v1().to_vec();
            let commit_failed = transaction.commit().is_err();
            #[cfg(test)]
            let simulate_lost_ack = store.simulate_lost_ack;
            #[cfg(not(test))]
            let simulate_lost_ack = false;
            if commit_failed || simulate_lost_ack {
                let attempt = candidate.into_attempt_binding_v1();
                let capacity = abandon_uncertain_connection_v1(opened.into_connection());
                return AuthorityMutationOutcomeV1::UncertainReadbackRequired(
                    one_fresh_root_uncertain_readback_v1(
                        attempt,
                        capacity,
                        store.config.clone(),
                        Arc::clone(&store.clock),
                        store.root_id.clone(),
                        readback_expectation,
                    ),
                );
            }
            let attempt = candidate.into_attempt_binding_v1();
            AuthorityMutationOutcomeV1::CommittedRetained(RetainedRootLeaseV1 {
                attempt: AuthorityRetainedAttemptV1::from_verified_parts_v1(
                    attempt,
                    AuthorityRetainedOutcomeCodeV1::CommittedRetained,
                    AuthorityOutcomeBindingDigestV1::from_verified_digest_v1(
                        outcome_binding_digest,
                    ),
                    generation,
                    event_id,
                ),
                source_grant_wire,
                root_lease_wire,
            })
        }
        Ok(RootTransactionResultV1::Conflict) => {
            if transaction.commit().is_err() {
                AuthorityMutationOutcomeV1::AmbiguousReconciliationRequired
            } else {
                AuthorityMutationOutcomeV1::ConflictRetained
            }
        }
        Err(RootStoreErrorV1::Denied) => {
            let _ = transaction.rollback();
            AuthorityMutationOutcomeV1::DeniedDefinite
        }
        Err(RootStoreErrorV1::Corrupt) => {
            let _ = transaction.rollback();
            AuthorityMutationOutcomeV1::AmbiguousReconciliationRequired
        }
        Err(RootStoreErrorV1::Unavailable) => {
            let _ = transaction.rollback();
            AuthorityMutationOutcomeV1::Unavailable
        }
    }
}

enum RootTransactionResultV1 {
    Exact(Box<RootGraphReadbackV1>),
    Committed {
        generation: Generation,
        event_id: Sha256Digest,
        outcome_binding_digest: Sha256Digest,
    },
    Conflict,
}

#[derive(Clone, Copy)]
pub(crate) enum RootStoreErrorV1 {
    Denied,
    Corrupt,
    Unavailable,
}

fn commit_root_transaction_v1(
    transaction: &Transaction<'_>,
    candidate: &RootLeaseCandidateV1,
    writer_clock: &AuthorityClockObservationV1,
) -> Result<RootTransactionResultV1, RootStoreErrorV1> {
    let metadata = read_metadata_v1(transaction)?;
    verify_writer_clock_v1(candidate, writer_clock, metadata)?;

    match classify_grant_namespace_v1(transaction, candidate).map_err(map_grant_error_v1)? {
        GrantNamespaceStateV1::Exact(readback) => {
            return Ok(RootTransactionResultV1::Exact(readback));
        }
        GrantNamespaceStateV1::Conflict {
            expected_input_graph_digest,
        } => {
            retain_root_conflict_v1(
                transaction,
                candidate,
                writer_clock,
                metadata,
                expected_input_graph_digest,
            )?;
            return Ok(RootTransactionResultV1::Conflict);
        }
        GrantNamespaceStateV1::Vacant => {}
    }

    let resolver = SqliteCurrentKeyResolverV1 {
        connection: transaction,
        observed_at_utc_ms: writer_clock.sampled_utc_ms_v1(),
    };
    let grant =
        decode_and_verify_human_request_grant_v1(candidate.source_grant_wire_v1(), &resolver)
            .map_err(map_contract_error_v1)?;
    let lease = decode_and_verify_task_lease_v1(candidate.root_lease_wire_v1(), &resolver)
        .map_err(map_contract_error_v1)?;
    verify_current_candidate_v1(
        transaction,
        candidate,
        &grant,
        &lease,
        metadata,
        writer_clock,
    )?;

    let generation = metadata
        .store_generation
        .checked_next()
        .map_err(|_| RootStoreErrorV1::Denied)?;
    let outcome_binding_digest = root_outcome_binding_v1(candidate, generation);
    let event_id = root_event_id_v1(candidate.attempt_v1(), outcome_binding_digest);
    insert_attempt_v1(
        transaction,
        candidate.attempt_v1(),
        AuthorityRetainedOutcomeCodeV1::CommittedRetained,
        outcome_binding_digest,
        generation,
        event_id,
    )?;
    retain_human_request_grant_v1(
        transaction,
        candidate,
        generation,
        metadata.trust_generation,
    )
    .map_err(map_grant_error_v1)?;
    retain_root_lease_v1(transaction, candidate, &lease, generation)?;
    retain_initial_usage_v1(transaction, &lease, generation)?;
    let lease_claims = lease.claims();
    retain_human_grant_claim_v1(
        transaction,
        candidate,
        lease_claims.issuer_id(),
        lease_claims.lease_id(),
        lease_claims.lease_digest(),
        generation,
        event_id,
    )
    .map_err(map_grant_error_v1)?;
    let event = AuthorityEventCandidateV1::try_new(
        event_id,
        AuthorityEventKindV1::RootLeaseIssued,
        AuthorityEventSubjectKindV1::Lease,
        lease_claims.lease_digest(),
        candidate.attempt_v1().attempt_id_v1().digest_v1(),
        AuthorityEventResultV1::CommittedRetained,
        AuthorityEventReasonV1::RootLeaseIssued,
        generation,
        writer_clock.sampled_utc_ms_v1(),
        Some(writer_clock.sampled_monotonic_ms_v1()),
        Some(Identifier::new(writer_clock.boot_id_v1()).map_err(|_| RootStoreErrorV1::Denied)?),
    )
    .map_err(|_| RootStoreErrorV1::Denied)?;
    retain_authority_event_v1(transaction, event).map_err(|_| RootStoreErrorV1::Unavailable)?;
    advance_root_metadata_v1(transaction, metadata, generation)?;
    Ok(RootTransactionResultV1::Committed {
        generation,
        event_id,
        outcome_binding_digest,
    })
}

fn read_metadata_v1(connection: &Connection) -> Result<MetadataV1, RootStoreErrorV1> {
    let values = connection
        .query_row(
            "SELECT store_generation, trust_generation, grant_generation, lease_generation,
                    allocation_generation, counter_generation, event_generation, instance_epoch
             FROM authority_store_metadata WHERE singleton_id = 1 AND lifecycle = 'ACTIVE'",
            [],
            |row| {
                Ok([
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ])
            },
        )
        .optional()
        .map_err(|_| RootStoreErrorV1::Unavailable)?
        .ok_or(RootStoreErrorV1::Corrupt)?;
    let generation = |value: i64| {
        u64::try_from(value)
            .ok()
            .and_then(|value| Generation::new(value).ok())
            .ok_or(RootStoreErrorV1::Corrupt)
    };
    Ok(MetadataV1 {
        store_generation: generation(values[0])?,
        trust_generation: generation(values[1])?,
        grant_generation: generation(values[2])?,
        lease_generation: generation(values[3])?,
        allocation_generation: generation(values[4])?,
        counter_generation: generation(values[5])?,
        event_generation: generation(values[6])?,
        boot_instance_epoch: generation(values[7])?,
    })
}

fn verify_writer_clock_v1(
    candidate: &RootLeaseCandidateV1,
    writer_clock: &AuthorityClockObservationV1,
    metadata: MetadataV1,
) -> Result<(), RootStoreErrorV1> {
    if writer_clock.boot_id_v1() != candidate.boot_id_v1()
        || writer_clock.clock_generation_v1() != candidate.clock_generation_v1()
        || writer_clock.instance_epoch_v1() != candidate.instance_epoch_v1()
        || writer_clock.instance_epoch_v1() != metadata.boot_instance_epoch
        || writer_clock.sampled_utc_ms_v1().get() < candidate.observed_utc_ms_v1().get()
        || writer_clock.sampled_monotonic_ms_v1().get() < candidate.observed_monotonic_ms_v1().get()
        || writer_clock.sampled_monotonic_ms_v1().get()
            >= candidate
                .attempt_v1()
                .caller_deadline_monotonic_ms_v1()
                .get()
    {
        return Err(RootStoreErrorV1::Denied);
    }
    Ok(())
}

fn verify_current_candidate_v1(
    connection: &Connection,
    candidate: &RootLeaseCandidateV1,
    grant: &AuthenticHumanRequestGrantV1,
    lease: &AuthenticTaskLeaseV1,
    metadata: MetadataV1,
    writer_clock: &AuthorityClockObservationV1,
) -> Result<(), RootStoreErrorV1> {
    let grant_claims = grant.claims();
    let lease_claims = lease.claims();
    if grant
        .canonical_signed_envelope_bytes()
        .map_err(map_contract_error_v1)?
        != candidate.source_grant_wire_v1()
        || lease
            .canonical_signed_envelope_bytes()
            .map_err(map_contract_error_v1)?
            != candidate.root_lease_wire_v1()
        || grant.verified_key_fingerprint()
            != candidate.source_grant_v1().verified_key_fingerprint()
        || lease_claims.source_grant_id() != grant_claims.grant_id()
        || lease_claims.source_grant_digest() != grant_claims.grant_digest()
        || lease_claims.delegation_depth() != 0
        || candidate.observations_v1().scope_v1().digest_v1()
            != grant_claims.scope_template_digest()
        || candidate.observations_v1().scope_v1().generation_v1().get()
            != grant_claims.scope_template_generation()
        || candidate.observations_v1().trust_v1().generation_v1() != metadata.trust_generation
        || writer_clock.sampled_utc_ms_v1().get() < grant_claims.issued_at_utc_ms()
        || writer_clock.sampled_utc_ms_v1().get() >= grant_claims.expires_at_utc_ms()
        || writer_clock.sampled_utc_ms_v1().get() >= lease_claims.expires_at_utc_ms()
        || writer_clock.sampled_monotonic_ms_v1().get() >= lease_claims.deadline_monotonic_ms()
        || is_effectively_revoked_v1(
            connection,
            "SIGNER",
            grant_claims.key_id(),
            None,
            writer_clock.sampled_utc_ms_v1(),
        )?
        || is_effectively_revoked_v1(
            connection,
            "SIGNER",
            lease_claims.key_id(),
            None,
            writer_clock.sampled_utc_ms_v1(),
        )?
        || is_effectively_revoked_v1(
            connection,
            "GRANT",
            &grant_claims.grant_id().to_hex(),
            Some(grant_claims.grant_digest()),
            writer_clock.sampled_utc_ms_v1(),
        )?
        || is_effectively_revoked_v1(
            connection,
            "SCOPE_TEMPLATE",
            grant_claims.scope_template_id(),
            Some(grant_claims.scope_template_digest()),
            writer_clock.sampled_utc_ms_v1(),
        )?
    {
        return Err(RootStoreErrorV1::Denied);
    }
    Ok(())
}

struct SqliteCurrentKeyResolverV1<'connection> {
    connection: &'connection Connection,
    observed_at_utc_ms: SafeU64,
}

impl HumanRequestGrantKeyResolver for SqliteCurrentKeyResolverV1<'_> {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
        let (key, current) = resolve_key_v1(
            self.connection,
            "request-surface-grant-signing",
            key_id,
            self.observed_at_utc_ms,
        )?;
        Ok(if current {
            HumanRequestGrantVerificationKeyV1::current(key)
        } else {
            HumanRequestGrantVerificationKeyV1::historical(key)
        })
    }
}

impl TaskLeaseKeyResolver for SqliteCurrentKeyResolverV1<'_> {
    fn resolve_task_lease_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<TaskLeaseVerificationKeyV1> {
        let (key, current) = resolve_key_v1(
            self.connection,
            "core-task-lease-signing",
            key_id,
            self.observed_at_utc_ms,
        )?;
        Ok(if current {
            TaskLeaseVerificationKeyV1::current(key)
        } else {
            TaskLeaseVerificationKeyV1::historical(key)
        })
    }
}

fn resolve_key_v1(
    connection: &Connection,
    purpose: &str,
    key_id: &str,
    observed_at_utc_ms: SafeU64,
) -> helix_task_authority_contracts::Result<([u8; 32], bool)> {
    let row = connection
        .query_row(
            "SELECT key.public_key, key.public_key_fingerprint,
                    (SELECT status.status FROM authority_key_status_events AS status
                     WHERE status.key_purpose = key.key_purpose
                       AND status.key_id = key.key_id
                       AND status.effective_at_utc_ms <= ?3
                     ORDER BY status.trust_generation DESC LIMIT 1)
             FROM authority_verification_keys AS key
             WHERE key.key_purpose = ?1 AND key.key_id = ?2",
            params![
                purpose,
                key_id,
                to_sql_contract_v1(observed_at_utc_ms.get())?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ContractError::UnknownKey)?
        .ok_or(ContractError::UnknownKey)?;
    let key: [u8; 32] = row
        .0
        .try_into()
        .map_err(|_| ContractError::InvalidPublicKey)?;
    if Sha256Digest::digest(&key).to_hex() != row.1 {
        return Err(ContractError::InvalidPublicKey);
    }
    let status = row.2.ok_or(ContractError::HistoricalKeyNotAuthority)?;
    Ok((key, status == "TRUSTED"))
}

fn is_effectively_revoked_v1(
    connection: &Connection,
    subject_kind: &str,
    subject_id: &str,
    subject_digest: Option<Sha256Digest>,
    observed_at_utc_ms: SafeU64,
) -> Result<bool, RootStoreErrorV1> {
    let digest = subject_digest.map(Sha256Digest::to_hex);
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM authority_revocations
                 WHERE subject_kind = ?1 AND subject_id = ?2
                   AND effective_at_utc_ms <= ?3
                   AND (subject_digest IS NULL OR subject_digest = ?4)
             )",
            params![
                subject_kind,
                subject_id,
                to_sql_v1(observed_at_utc_ms.get())?,
                digest
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| RootStoreErrorV1::Unavailable)
}

fn retain_root_lease_v1(
    transaction: &Transaction<'_>,
    candidate: &RootLeaseCandidateV1,
    lease: &AuthenticTaskLeaseV1,
    generation: Generation,
) -> Result<(), RootStoreErrorV1> {
    let claims = lease.claims();
    let grant = candidate.source_grant_v1().claims();
    transaction
        .execute(
            "INSERT INTO task_leases (
                 lease_issuer_id, lease_id, lease_digest, signed_wire, signed_wire_sha256,
                 key_purpose, key_id, key_fingerprint, source_grant_issuer_id,
                 source_grant_id, source_grant_digest, task_id, workload_id,
                 parent_lease_issuer_id, parent_lease_id, parent_lease_digest,
                 parent_allocation_id, delegation_depth, boot_id, instance_epoch,
                 expires_at_utc_ms, deadline_monotonic_ms, creation_attempt_id,
                 created_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'core-task-lease-signing', ?6, ?7,
                       ?8, ?9, ?10, ?11, ?12, NULL, NULL, NULL, NULL, 0, ?13, ?14,
                       ?15, ?16, ?17, ?18)",
            params![
                claims.issuer_id(),
                claims.lease_id().to_hex(),
                claims.lease_digest().to_hex(),
                candidate.root_lease_wire_v1(),
                Sha256Digest::digest(candidate.root_lease_wire_v1()).to_hex(),
                claims.key_id(),
                lease.verified_key_fingerprint().to_hex(),
                grant.issuer_id(),
                grant.grant_id().to_hex(),
                grant.grant_digest().to_hex(),
                claims.task_id(),
                claims.workload_id(),
                claims.boot_id(),
                to_sql_v1(claims.instance_epoch())?,
                to_sql_v1(claims.expires_at_utc_ms())?,
                to_sql_v1(claims.deadline_monotonic_ms())?,
                candidate.attempt_v1().attempt_id_v1().digest_v1().to_hex(),
                to_sql_v1(generation.get())?,
            ],
        )
        .map_err(|_| RootStoreErrorV1::Unavailable)?;
    Ok(())
}

fn retain_initial_usage_v1(
    transaction: &Transaction<'_>,
    lease: &AuthenticTaskLeaseV1,
    generation: Generation,
) -> Result<(), RootStoreErrorV1> {
    let claims = lease.claims();
    transaction
        .execute(
            "INSERT INTO task_lease_usage (
                 lease_issuer_id, lease_id, allocated_read_bytes,
                 allocated_distinct_files, allocated_actions, allocated_egress_bytes,
                 allocated_cost_micro_units, allocated_plans, allocated_approvals,
                 allocated_child_leases, consumed_read_bytes, consumed_distinct_files,
                 consumed_actions, consumed_plans, consumed_approvals,
                 allocation_generation, counter_generation
             ) VALUES (?1, ?2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?3, ?3)",
            params![
                claims.issuer_id(),
                claims.lease_id().to_hex(),
                to_sql_v1(generation.get())?,
            ],
        )
        .map_err(|_| RootStoreErrorV1::Unavailable)?;
    Ok(())
}

fn insert_attempt_v1(
    transaction: &Transaction<'_>,
    attempt: &AuthorityAttemptBindingV1,
    outcome: AuthorityRetainedOutcomeCodeV1,
    outcome_binding_digest: Sha256Digest,
    generation: Generation,
    event_id: Sha256Digest,
) -> Result<(), RootStoreErrorV1> {
    transaction
        .execute(
            "INSERT INTO authority_attempts (
                 attempt_id, operation_kind, namespace_digest, input_graph_digest,
                 caller_deadline_monotonic_ms, outcome_code, outcome_binding_digest,
                 attempt_generation, event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                attempt.attempt_id_v1().digest_v1().to_hex(),
                attempt.operation_kind_v1().sql_code_v1(),
                attempt.namespace_digest_v1().digest_v1().to_hex(),
                attempt.input_graph_digest_v1().digest_v1().to_hex(),
                to_sql_v1(attempt.caller_deadline_monotonic_ms_v1().get())?,
                outcome.sql_code_v1(),
                outcome_binding_digest.to_hex(),
                to_sql_v1(generation.get())?,
                event_id.to_hex(),
            ],
        )
        .map_err(|_| RootStoreErrorV1::Unavailable)?;
    Ok(())
}

fn advance_root_metadata_v1(
    transaction: &Transaction<'_>,
    metadata: MetadataV1,
    generation: Generation,
) -> Result<(), RootStoreErrorV1> {
    let changed = transaction
        .execute(
            "UPDATE authority_store_metadata SET
                 store_generation = ?1, grant_generation = ?1, lease_generation = ?1,
                 allocation_generation = ?1, counter_generation = ?1, event_generation = ?1
             WHERE singleton_id = 1 AND store_generation = ?2 AND trust_generation = ?3
               AND grant_generation = ?4 AND lease_generation = ?5
               AND allocation_generation = ?6 AND counter_generation = ?7
               AND event_generation = ?8 AND lifecycle = 'ACTIVE'",
            params![
                to_sql_v1(generation.get())?,
                to_sql_v1(metadata.store_generation.get())?,
                to_sql_v1(metadata.trust_generation.get())?,
                to_sql_v1(metadata.grant_generation.get())?,
                to_sql_v1(metadata.lease_generation.get())?,
                to_sql_v1(metadata.allocation_generation.get())?,
                to_sql_v1(metadata.counter_generation.get())?,
                to_sql_v1(metadata.event_generation.get())?,
            ],
        )
        .map_err(|_| RootStoreErrorV1::Unavailable)?;
    if changed != 1 {
        return Err(RootStoreErrorV1::Corrupt);
    }
    Ok(())
}

fn retain_root_conflict_v1(
    transaction: &Transaction<'_>,
    candidate: &RootLeaseCandidateV1,
    writer_clock: &AuthorityClockObservationV1,
    metadata: MetadataV1,
    expected_input_graph_digest: Sha256Digest,
) -> Result<(), RootStoreErrorV1> {
    let generation = metadata
        .store_generation
        .checked_next()
        .map_err(|_| RootStoreErrorV1::Denied)?;
    let observed = candidate.attempt_v1().input_graph_digest_v1().digest_v1();
    let outcome = conflict_binding_v1(expected_input_graph_digest, observed);
    let event_id = root_event_id_v1(candidate.attempt_v1(), outcome);
    insert_attempt_v1(
        transaction,
        candidate.attempt_v1(),
        AuthorityRetainedOutcomeCodeV1::ConflictRetained,
        outcome,
        generation,
        event_id,
    )?;
    let namespace = candidate.attempt_v1().namespace_digest_v1().digest_v1();
    let event = AuthorityEventCandidateV1::try_new(
        event_id,
        AuthorityEventKindV1::ConflictRetained,
        AuthorityEventSubjectKindV1::Grant,
        namespace,
        candidate.attempt_v1().attempt_id_v1().digest_v1(),
        AuthorityEventResultV1::ConflictRetained,
        AuthorityEventReasonV1::ConflictingIdentityReuse,
        generation,
        writer_clock.sampled_utc_ms_v1(),
        Some(writer_clock.sampled_monotonic_ms_v1()),
        Some(Identifier::new(writer_clock.boot_id_v1()).map_err(|_| RootStoreErrorV1::Denied)?),
    )
    .map_err(|_| RootStoreErrorV1::Denied)?;
    retain_authority_event_v1(transaction, event).map_err(|_| RootStoreErrorV1::Unavailable)?;
    let conflict_id = conflict_id_v1(candidate.attempt_v1(), outcome);
    retain_conflict_tombstone_v1(
        transaction,
        AuthorityConflictCandidateV1::new(
            conflict_id,
            AuthorityConflictNamespaceKindV1::Grant,
            namespace,
            expected_input_graph_digest,
            observed,
            candidate.attempt_v1().attempt_id_v1().digest_v1(),
            generation,
            event_id,
        ),
    )
    .map_err(|_| RootStoreErrorV1::Unavailable)?;
    let changed = transaction
        .execute(
            "UPDATE authority_store_metadata SET store_generation = ?1, event_generation = ?1
             WHERE singleton_id = 1 AND store_generation = ?2 AND event_generation = ?3",
            params![
                to_sql_v1(generation.get())?,
                to_sql_v1(metadata.store_generation.get())?,
                to_sql_v1(metadata.event_generation.get())?,
            ],
        )
        .map_err(|_| RootStoreErrorV1::Unavailable)?;
    if changed != 1 {
        return Err(RootStoreErrorV1::Corrupt);
    }
    Ok(())
}

pub(crate) fn qualify_retained_readback_v1(
    connection: &Connection,
    readback: RootGraphReadbackV1,
) -> Result<RetainedRootLeaseV1, RootStoreErrorV1> {
    let resolver = SqliteCurrentKeyResolverV1 {
        connection,
        observed_at_utc_ms: SafeU64::new(9_007_199_254_740_991)
            .map_err(|_| RootStoreErrorV1::Corrupt)?,
    };
    let grant =
        decode_and_verify_retained_human_request_grant_v1(&readback.source_grant_wire, &resolver)
            .map_err(map_contract_error_v1)?;
    let lease = decode_and_verify_retained_task_lease_v1(&readback.root_lease_wire, &resolver)
        .map_err(map_contract_error_v1)?;
    if grant.claims().grant_digest() != readback.source_grant_digest
        || lease.claims().lease_digest() != readback.root_lease_digest
        || lease.claims().source_grant_id() != grant.claims().grant_id()
        || lease.claims().source_grant_digest() != grant.claims().grant_digest()
    {
        return Err(RootStoreErrorV1::Corrupt);
    }
    Ok(RetainedRootLeaseV1 {
        attempt: readback.retained_attempt,
        source_grant_wire: readback.source_grant_wire,
        root_lease_wire: readback.root_lease_wire,
    })
}

fn root_outcome_binding_v1(
    candidate: &RootLeaseCandidateV1,
    generation: Generation,
) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(
        ROOT_OUTCOME_DOMAIN_V1.len()
            + candidate.source_grant_wire_v1().len()
            + candidate.root_lease_wire_v1().len()
            + 104,
    );
    bytes.extend_from_slice(ROOT_OUTCOME_DOMAIN_V1);
    push_digest_v1(
        &mut bytes,
        candidate.attempt_v1().namespace_digest_v1().digest_v1(),
    );
    push_digest_v1(
        &mut bytes,
        candidate.attempt_v1().input_graph_digest_v1().digest_v1(),
    );
    push_digest_v1(
        &mut bytes,
        Sha256Digest::digest(candidate.source_grant_wire_v1()),
    );
    push_digest_v1(
        &mut bytes,
        Sha256Digest::digest(candidate.root_lease_wire_v1()),
    );
    bytes.extend_from_slice(&generation.get().to_be_bytes());
    Sha256Digest::digest(&bytes)
}

fn root_event_id_v1(attempt: &AuthorityAttemptBindingV1, outcome: Sha256Digest) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(ROOT_EVENT_ID_DOMAIN_V1.len() + 64);
    bytes.extend_from_slice(ROOT_EVENT_ID_DOMAIN_V1);
    bytes.extend_from_slice(attempt.attempt_id_v1().digest_v1().as_bytes());
    bytes.extend_from_slice(outcome.as_bytes());
    Sha256Digest::digest(&bytes)
}

fn conflict_binding_v1(expected: Sha256Digest, observed: Sha256Digest) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(ROOT_OUTCOME_DOMAIN_V1.len() + 64);
    bytes.extend_from_slice(ROOT_OUTCOME_DOMAIN_V1);
    bytes.extend_from_slice(expected.as_bytes());
    bytes.extend_from_slice(observed.as_bytes());
    Sha256Digest::digest(&bytes)
}

fn conflict_id_v1(attempt: &AuthorityAttemptBindingV1, outcome: Sha256Digest) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(ROOT_CONFLICT_ID_DOMAIN_V1.len() + 64);
    bytes.extend_from_slice(ROOT_CONFLICT_ID_DOMAIN_V1);
    bytes.extend_from_slice(attempt.attempt_id_v1().digest_v1().as_bytes());
    bytes.extend_from_slice(outcome.as_bytes());
    Sha256Digest::digest(&bytes)
}

fn push_digest_v1(bytes: &mut Vec<u8>, digest: Sha256Digest) {
    bytes.extend_from_slice(digest.as_bytes());
}

fn map_contract_error_v1(error: ContractError) -> RootStoreErrorV1 {
    match error {
        ContractError::HistoricalKeyNotAuthority
        | ContractError::UnknownKey
        | ContractError::SignatureInvalid => RootStoreErrorV1::Denied,
        _ => RootStoreErrorV1::Corrupt,
    }
}

fn map_grant_error_v1(error: GrantStoreErrorV1) -> RootStoreErrorV1 {
    match error {
        GrantStoreErrorV1::Corrupt => RootStoreErrorV1::Corrupt,
        GrantStoreErrorV1::Unavailable => RootStoreErrorV1::Unavailable,
    }
}

fn to_sql_v1(value: u64) -> Result<i64, RootStoreErrorV1> {
    i64::try_from(value).map_err(|_| RootStoreErrorV1::Denied)
}

fn to_sql_contract_v1(value: u64) -> helix_task_authority_contracts::Result<i64> {
    i64::try_from(value).map_err(|_| ContractError::InvalidField)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{initialize_empty_with_v1, open_existing_v1};
    use crate::schema::{
        TASK_AUTHORITY_STORE_APPLICATION_ID_V1, TASK_AUTHORITY_STORE_DURABILITY_PROFILE_V1,
        TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
    };
    use crate::AuthorityRootIdentityEvidenceV1;
    use ed25519_dalek::{Signer as _, SigningKey};
    use helix_task_authority::{
        issue_root_lease_v1, AuthorityCurrentnessV1, CurrentHumanRequestContextV1,
        RootIssuanceObservationsV1, RootLeaseRequestOutcomeV1, RootLeaseRequestV1,
    };
    use helix_task_authority_contracts::{
        decode_and_verify_human_request_grant_v1, sign_human_request_grant_v1, CurrencyCodeV1,
        DelegationDepthV1, DelegationModeV1, HumanRequestGrantInputV1,
        HumanRequestGrantProtectedV1, HumanRequestGrantSigner, MinimumAuthenticationProfileV1,
        ResourceRootV1, RiskLevelV1, RootTaskLeaseBoundsV1, TaskLeaseBudgetV1,
        TaskLeaseCatalogueBoundV1, TaskLeaseCounterLimitsV1, TaskLeaseSigner,
        TaskLeaseTrustBoundV1,
    };
    use rusqlite::Transaction;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TemporaryRoot(PathBuf);

    impl TemporaryRoot {
        fn new() -> Self {
            loop {
                let nonce = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "helix-root-lease-store-{}-{nonce}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary root creates: {error}"),
                }
            }
        }
    }

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct FixedClock;

    impl AuthorityClockProviderV1 for FixedClock {
        fn capture_v1(
            &self,
            deadline: SafeU64,
        ) -> Result<AuthorityClockObservationV1, helix_task_authority::AuthorityControlErrorV1>
        {
            if deadline.get() <= 100 {
                return Err(helix_task_authority::AuthorityControlErrorV1::DeadlineReached);
            }
            Ok(AuthorityClockObservationV1::from_trusted_provider_parts_v1(
                identifier("boot-a"),
                generation(8),
                generation(1),
                safe(1_100),
                safe(100),
            ))
        }
    }

    struct GrantSignerV1(SigningKey);

    impl HumanRequestGrantSigner for GrantSignerV1 {
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

    impl HumanRequestGrantKeyResolver for GrantSignerV1 {
        fn resolve_human_request_grant_key(
            &self,
            key_id: &str,
        ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
            if key_id != self.key_id() {
                return Err(ContractError::UnknownKey);
            }
            Ok(HumanRequestGrantVerificationKeyV1::current(
                self.0.verifying_key().to_bytes(),
            ))
        }
    }

    struct LeaseSignerV1(SigningKey);

    impl TaskLeaseSigner for LeaseSignerV1 {
        fn key_id(&self) -> &str {
            "lease-key-v1"
        }

        fn sign_task_lease(
            &self,
            message: &[u8],
        ) -> helix_task_authority_contracts::Result<[u8; 64]> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn digest_hex(byte: u8) -> String {
        digest(byte).to_hex()
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).unwrap()
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).unwrap()
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).unwrap()
    }

    fn bounds(read_bytes: u64) -> RootTaskLeaseBoundsV1 {
        RootTaskLeaseBoundsV1::try_new_v1(
            vec![ResourceRootV1::try_new(
                "workspace",
                vec!["project".to_owned(), "src".to_owned()],
            )
            .unwrap()],
            TaskLeaseBudgetV1::from_validated_parts_v1(
                safe(read_bytes),
                safe(20),
                safe(10),
                safe(1_000),
                CurrencyCodeV1::new("USD").unwrap(),
                safe(500),
                identifier("prices-v1"),
            ),
            TaskLeaseCounterLimitsV1::from_validated_parts_v1(
                safe(4),
                safe(2),
                safe(2),
                DelegationDepthV1::new(2).unwrap(),
            ),
            TaskLeaseTrustBoundV1::from_validated_parts_v1(
                RiskLevelV1::L1,
                MinimumAuthenticationProfileV1::UserVerificationV1,
                identifier("policy-a"),
                digest(4),
                generation(4),
            ),
            TaskLeaseCatalogueBoundV1::try_new_v1(
                identifier("catalogue-a"),
                digest(5),
                generation(5),
                vec![identifier("entry-a"), identifier("entry-b")],
            )
            .unwrap(),
            DelegationModeV1::Delegable,
        )
        .unwrap()
    }

    fn request(read_bytes: u64, grant_signer: &GrantSignerV1) -> RootLeaseRequestV1 {
        let protected = HumanRequestGrantProtectedV1::try_new(
            HumanRequestGrantInputV1 {
                grant_id: digest(51),
                issuer_id: identifier("request-surface"),
                audience: identifier("helix-core"),
                principal_id: identifier("principal-a"),
                message_digest: digest(52),
                channel_id: identifier("channel-a"),
                session_id: identifier("session-a"),
                scope_template_id: identifier("scope-a"),
                scope_template_digest: digest(3),
                scope_template_generation: generation(3),
                issued_at_utc_ms: safe(1_000),
                expires_at_utc_ms: safe(2_000),
            },
            identifier(grant_signer.key_id()),
        )
        .unwrap();
        let grant_wire = sign_human_request_grant_v1(protected, grant_signer)
            .unwrap()
            .to_canonical_json()
            .unwrap();
        let grant = decode_and_verify_human_request_grant_v1(&grant_wire, grant_signer).unwrap();
        RootLeaseRequestV1 {
            grant,
            human_context: CurrentHumanRequestContextV1::from_authenticated_parts_v1(
                identifier("request-surface"),
                identifier("helix-core"),
                identifier("principal-a"),
                digest(52),
                identifier("channel-a"),
                identifier("session-a"),
                identifier("scope-a"),
                digest(3),
                generation(3),
            ),
            requested_bounds: bounds(read_bytes),
            current_ceiling: bounds(100),
            observations: RootIssuanceObservationsV1::from_current_parts_v1(
                digest(3),
                generation(3),
                digest(4),
                generation(4),
                digest(5),
                generation(5),
                digest(6),
                generation(6),
                digest(7),
                generation(3),
            ),
            source_currentness: AuthorityCurrentnessV1::Current,
            lease_issuer_id: identifier("core-lease-issuer"),
            task_id: identifier("task-a"),
            workload_id: identifier("workload-a"),
            audience: identifier("helix-core"),
            clock: FixedClock.capture_v1(safe(300)).unwrap(),
            not_before_utc_ms: safe(1_100),
            expires_at_utc_ms: safe(1_900),
            deadline_monotonic_ms: safe(500),
            caller_deadline_monotonic_ms: safe(300),
        }
    }

    fn stage_bootstrap_and_keys_v1(
        transaction: &Transaction<'_>,
        root_id: &str,
        grant_key: [u8; 32],
        lease_key: [u8; 32],
    ) {
        let bootstrap_attempt = digest_hex(1);
        let bootstrap_event = digest_hex(2);
        let receipt = digest_hex(3);
        transaction
            .execute(
                "INSERT INTO authority_attempts VALUES (?1, 'BOOTSTRAP', ?2, ?3, 1000,
             'COMMITTED_RETAINED', ?4, 1, ?5)",
                params![
                    bootstrap_attempt,
                    digest_hex(4),
                    digest_hex(5),
                    digest_hex(6),
                    bootstrap_event
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO authority_events VALUES (?1, 'BOOTSTRAP_COMPLETED', 'ROOT', ?2, ?3,
             'COMMITTED_RETAINED', 'BOOTSTRAP_COMPLETED', 1, 1, 1, 'boot-a', NULL, ?4)",
                params![
                    bootstrap_event,
                    digest_hex(7),
                    bootstrap_attempt,
                    digest_hex(8)
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO authority_bootstrap_receipts VALUES (
             ?1, ?2, ?3, ?4, 1212962883, 2, 'coordinator-root', ?5, ?6, ?7,
             ?8, ?9, 0, 0, 0, 1, 1, 'helixos-provision', ?10)",
                params![
                    receipt,
                    bootstrap_attempt,
                    "aa".repeat(20),
                    "bb".repeat(20),
                    digest_hex(9),
                    digest_hex(10),
                    digest_hex(11),
                    root_id,
                    TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                    digest_hex(12)
                ],
            )
            .unwrap();

        let keys = [
            (
                "request-surface-grant-signing",
                "request-key-v1",
                grant_key,
                2_u64,
                21_u8,
            ),
            (
                "core-task-lease-signing",
                "lease-key-v1",
                lease_key,
                3_u64,
                31_u8,
            ),
        ];
        for (purpose, key_id, public_key, generation, seed) in keys {
            let attempt = digest_hex(seed);
            let event = digest_hex(seed + 1);
            let fingerprint = Sha256Digest::digest(&public_key);
            transaction
                .execute(
                    "INSERT INTO authority_attempts VALUES (?1, 'KEY_STATUS_CHANGE', ?2, ?3, 1000,
                 'COMMITTED_RETAINED', ?4, ?5, ?6)",
                    params![
                        attempt,
                        digest_hex(seed + 2),
                        digest_hex(seed + 3),
                        digest_hex(seed + 4),
                        generation as i64,
                        event
                    ],
                )
                .unwrap();
            transaction
                .execute(
                    "INSERT INTO authority_verification_keys VALUES
                 (?1, ?2, 'authority-test-issuer', 'ed25519', ?3, ?4, ?5, ?6)",
                    params![
                        purpose,
                        key_id,
                        public_key.as_slice(),
                        fingerprint.to_hex(),
                        digest_hex(seed + 5),
                        generation as i64
                    ],
                )
                .unwrap();
            transaction
                .execute(
                    "INSERT INTO authority_key_status_events VALUES
                 (?1, ?2, ?3, 'TRUSTED', 0, ?4, ?5, 'KEY_INTRODUCED', ?6)",
                    params![
                        digest_hex(seed + 6),
                        purpose,
                        key_id,
                        generation as i64,
                        attempt,
                        event
                    ],
                )
                .unwrap();
            transaction
                .execute(
                    "INSERT INTO authority_events VALUES (?1, 'KEY_STATUS_CHANGED', 'KEY', ?2, ?3,
                 'COMMITTED_RETAINED', 'KEY_INTRODUCED', ?4, 1, 1, 'boot-a', ?5, ?6)",
                    params![
                        event,
                        fingerprint.to_hex(),
                        attempt,
                        generation as i64,
                        if generation == 2 {
                            digest_hex(8)
                        } else {
                            digest_hex(29)
                        },
                        digest_hex(seed + 8)
                    ],
                )
                .unwrap();
        }
        transaction
            .execute(
                "INSERT INTO authority_store_metadata VALUES (
             1, ?1, 1, ?2, ?3, 'ACTIVE', ?4, 'boot-a', 1, 1, 0, 1024, 32,
             3, 3, 1, 1, 1, 1, 1, 1, 3, 1, 0, 0, 1, ?5, NULL)",
                params![
                    TASK_AUTHORITY_STORE_APPLICATION_ID_V1,
                    TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                    root_id,
                    TASK_AUTHORITY_STORE_DURABILITY_PROFILE_V1,
                    receipt
                ],
            )
            .unwrap();
    }

    fn initialized_store_v1(
        root: &TemporaryRoot,
        grant_signer: &GrantSignerV1,
        lease_signer: &LeaseSignerV1,
    ) -> (SqliteRootLeaseStoreV1, AuthorityStoreConfigV1, String) {
        let identity = [0x61; 32];
        let root_id = "61".repeat(32);
        let empty = AuthorityStoreConfigV1::try_new_empty_attested(
            root.0.clone(),
            AuthorityRootIdentityEvidenceV1::from_attested_bytes(identity),
            500,
        )
        .unwrap();
        let opened = initialize_empty_with_v1(empty, &FixedClock, safe(900), &root_id, |tx, id| {
            stage_bootstrap_and_keys_v1(
                tx,
                id,
                grant_signer.0.verifying_key().to_bytes(),
                lease_signer.0.verifying_key().to_bytes(),
            );
            Ok(())
        })
        .unwrap();
        let config = opened.config().clone();
        drop(opened);
        let store = SqliteRootLeaseStoreV1::new_v1(
            config.clone(),
            Arc::new(FixedClock),
            identifier(&root_id),
        );
        (store, config, root_id)
    }

    #[test]
    fn root_graph_is_all_visible_exactly_once_and_conflicts_are_tombstoned() {
        let root = TemporaryRoot::new();
        let grant_signer = GrantSignerV1(SigningKey::from_bytes(&[17; 32]));
        let lease_signer = LeaseSignerV1(SigningKey::from_bytes(&[23; 32]));
        let (store, config, root_id) = initialized_store_v1(&root, &grant_signer, &lease_signer);

        let first = match issue_root_lease_v1(request(50, &grant_signer), &lease_signer, &store) {
            RootLeaseRequestOutcomeV1::CommittedRetained(retained) => retained,
            outcome => panic!("first issuance failed: {outcome:?}"),
        };
        let exact_wire = first.root_lease_wire_v1().to_vec();
        let retry = match issue_root_lease_v1(request(50, &grant_signer), &lease_signer, &store) {
            RootLeaseRequestOutcomeV1::CommittedRetained(retained) => retained,
            outcome => panic!("retry failed: {outcome:?}"),
        };
        assert_eq!(retry.root_lease_wire_v1(), exact_wire);
        assert!(matches!(
            issue_root_lease_v1(request(49, &grant_signer), &lease_signer, &store),
            RootLeaseRequestOutcomeV1::ConflictRetained
        ));

        let reopened = open_existing_v1(config, &FixedClock, safe(900), &root_id).unwrap();
        let connection = reopened.connection();
        for (table, expected) in [
            ("human_request_grants", 1_i64),
            ("human_grant_claims", 1),
            ("task_leases", 1),
            ("task_lease_usage", 1),
            ("authority_conflict_tombstones", 1),
            ("authority_attempts", 5),
            ("authority_events", 5),
        ] {
            let actual: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(actual, expected, "{table} cardinality");
        }
        let generations: (i64, i64, i64, i64, i64, i64) = connection
            .query_row(
                "SELECT store_generation, grant_generation, lease_generation,
                        allocation_generation, counter_generation, event_generation
                 FROM authority_store_metadata",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(generations, (5, 4, 4, 4, 4, 5));
    }

    #[test]
    fn lost_ack_transfers_one_fresh_readback_without_resigning() {
        let root = TemporaryRoot::new();
        let grant_signer = GrantSignerV1(SigningKey::from_bytes(&[17; 32]));
        let lease_signer = LeaseSignerV1(SigningKey::from_bytes(&[23; 32]));
        let (store, _config, _root_id) = initialized_store_v1(&root, &grant_signer, &lease_signer);
        let store = store.with_simulated_lost_ack_v1();
        let custody = match issue_root_lease_v1(request(50, &grant_signer), &lease_signer, &store) {
            RootLeaseRequestOutcomeV1::UncertainReadbackRequired(custody) => custody,
            outcome => panic!("lost ACK did not transfer custody: {outcome:?}"),
        };
        let retained = match store.readback_uncertain_once_v1(custody) {
            helix_task_authority::AuthorityReadbackOutcomeV1::CommittedRetained(retained) => {
                retained
            }
            outcome => panic!("fresh exact readback failed: {outcome:?}"),
        };
        assert!(!retained.root_lease_wire_v1().is_empty());
        assert_eq!(
            retained.operation_kind_v1(),
            AuthorityOperationKindV1::RootLeaseIssue
        );
    }
}
