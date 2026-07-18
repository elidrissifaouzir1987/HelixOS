//! One-shot uncertainty readback for the durable HLXA authority store.
//!
//! The writer connection whose commit acknowledgement became uncertain is consumed
//! and dropped before a resolver can exist.  The resolver then owns only immutable
//! attempt/configuration data and may consume exactly one newly opened, fully admitted
//! connection.  Every failure while opening, validating, decoding, or revalidating is
//! ambiguity; no classification grants mutation retry authority.

#![allow(dead_code)] // Foundation consumed by the story-specific lost-acknowledgement paths.

use crate::config::AuthorityStoreConfigV1;
use crate::connection::open_existing_v1;
use crate::grant::read_root_graph_for_retained_attempt_v1;
use crate::lease::{qualify_retained_readback_v1, RetainedRootLeaseV1};
use crate::schema;
use helix_task_authority::{
    AuthorityAttemptBindingV1, AuthorityAttemptIdV1, AuthorityClockProviderV1,
    AuthorityInputGraphDigestV1, AuthorityNamespaceDigestV1, AuthorityOperationKindV1,
    AuthorityOutcomeBindingDigestV1, AuthorityReadbackOutcomeV1, AuthorityRetainedAttemptV1,
    AuthorityRetainedOutcomeCodeV1, AuthorityUncertainReadbackResolverV1,
    AuthorityUncertainReadbackV1,
};
use helix_task_authority_contracts::{Generation, SafeU64, Sha256Digest};
use rusqlite::{params, Connection, TransactionBehavior};
use std::fmt;
use std::sync::Arc;

pub(crate) struct RootLeaseReadbackExpectationV1 {
    grant_issuer_id: Box<str>,
    grant_id: Sha256Digest,
}

impl RootLeaseReadbackExpectationV1 {
    pub(crate) fn new(grant_issuer_id: &str, grant_id: Sha256Digest) -> Self {
        Self {
            grant_issuer_id: grant_issuer_id.into(),
            grant_id,
        }
    }
}

impl fmt::Debug for RootLeaseReadbackExpectationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootLeaseReadbackExpectationV1(..)")
    }
}

/// Adapter-private proof that the uncertain writer was abandoned before readback.
///
/// The only production constructor takes the writer connection by value and drops it.
/// The token is non-`Clone`, non-Serde, and consumed before the fresh open is attempted.
pub(crate) struct FreshReadbackCapacityV1 {
    _private: (),
}

impl FreshReadbackCapacityV1 {
    fn after_abandon_v1(uncertain_connection: Connection) -> Self {
        drop(uncertain_connection);
        Self { _private: () }
    }

    fn consume_v1(self) {}
}

impl fmt::Debug for FreshReadbackCapacityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshReadbackCapacityV1(..)")
    }
}

/// Consumes and closes the connection whose commit result was uncertain.
///
/// Returning a linear capacity instead of a boolean makes the required ordering part
/// of the type flow: the SQLite resolver cannot be built before this call.
pub(crate) fn abandon_uncertain_connection_v1(
    uncertain_connection: Connection,
) -> FreshReadbackCapacityV1 {
    FreshReadbackCapacityV1::after_abandon_v1(uncertain_connection)
}

/// Builds the core-owned one-shot custody after the uncertain writer is gone.
///
/// `fresh_config` must describe the already-published root.  The resolver never opens
/// with `CREATE`, never runs schema SQL, and never loops or retries a failed open.
pub(crate) fn one_fresh_uncertain_readback_v1(
    attempt: AuthorityAttemptBindingV1,
    capacity: FreshReadbackCapacityV1,
    fresh_config: AuthorityStoreConfigV1,
    clock: Arc<dyn AuthorityClockProviderV1>,
    expected_root_id: Box<str>,
    graph_verifier: Box<dyn AuthorityFreshGraphVerifierV1>,
) -> AuthorityUncertainReadbackV1<AuthorityRetainedAttemptV1> {
    // The deadline comes only from the frozen attempt binding.  Accepting a caller-
    // supplied replacement here could renew the uncertainty window after commit.
    let absolute_deadline_monotonic_ms = frozen_readback_deadline_v1(&attempt);
    AuthorityUncertainReadbackV1::from_store_parts_v1(
        attempt,
        Box::new(SqliteAuthorityUncertainReadbackResolverV1 {
            capacity,
            fresh_config,
            clock,
            absolute_deadline_monotonic_ms,
            expected_root_id,
            graph_verifier,
        }),
    )
}

pub(crate) fn one_fresh_root_uncertain_readback_v1(
    attempt: AuthorityAttemptBindingV1,
    capacity: FreshReadbackCapacityV1,
    fresh_config: AuthorityStoreConfigV1,
    clock: Arc<dyn AuthorityClockProviderV1>,
    expected_root_id: Box<str>,
    expectation: RootLeaseReadbackExpectationV1,
) -> AuthorityUncertainReadbackV1<RetainedRootLeaseV1> {
    let absolute_deadline_monotonic_ms = frozen_readback_deadline_v1(&attempt);
    AuthorityUncertainReadbackV1::from_store_parts_v1(
        attempt,
        Box::new(SqliteRootLeaseUncertainReadbackResolverV1 {
            capacity,
            fresh_config,
            clock,
            absolute_deadline_monotonic_ms,
            expected_root_id,
            expectation,
        }),
    )
}

struct SqliteRootLeaseUncertainReadbackResolverV1 {
    capacity: FreshReadbackCapacityV1,
    fresh_config: AuthorityStoreConfigV1,
    clock: Arc<dyn AuthorityClockProviderV1>,
    absolute_deadline_monotonic_ms: SafeU64,
    expected_root_id: Box<str>,
    expectation: RootLeaseReadbackExpectationV1,
}

impl fmt::Debug for SqliteRootLeaseUncertainReadbackResolverV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteRootLeaseUncertainReadbackResolverV1(..)")
    }
}

impl AuthorityUncertainReadbackResolverV1<RetainedRootLeaseV1>
    for SqliteRootLeaseUncertainReadbackResolverV1
{
    fn readback_exact_once_v1(
        self: Box<Self>,
        attempt: &AuthorityAttemptBindingV1,
    ) -> AuthorityReadbackOutcomeV1<RetainedRootLeaseV1> {
        let Self {
            capacity,
            fresh_config,
            clock,
            absolute_deadline_monotonic_ms,
            expected_root_id,
            expectation,
        } = *self;
        capacity.consume_v1();
        resolve_root_on_one_fresh_connection_v1(
            fresh_config,
            clock,
            absolute_deadline_monotonic_ms,
            expected_root_id,
            expectation,
            attempt,
        )
    }
}

fn resolve_root_on_one_fresh_connection_v1(
    fresh_config: AuthorityStoreConfigV1,
    clock: Arc<dyn AuthorityClockProviderV1>,
    absolute_deadline_monotonic_ms: SafeU64,
    expected_root_id: Box<str>,
    expectation: RootLeaseReadbackExpectationV1,
    attempt: &AuthorityAttemptBindingV1,
) -> AuthorityReadbackOutcomeV1<RetainedRootLeaseV1> {
    let mut opened = match open_existing_v1(
        fresh_config,
        clock.as_ref(),
        absolute_deadline_monotonic_ms,
        &expected_root_id,
    ) {
        Ok(opened) => opened,
        Err(_) => return AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired,
    };
    if opened
        .connection()
        .pragma_update(None, "query_only", true)
        .is_err()
    {
        return AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired;
    }

    let outcome = {
        let transaction = match opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Deferred)
        {
            Ok(transaction) => transaction,
            Err(_) => return AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired,
        };
        if schema::verify_admission_v1(&transaction, &expected_root_id).is_err() {
            return AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired;
        }
        let classification = match classify_fresh_graph_v1(&transaction, attempt) {
            FreshGraphClassificationV1::Complete(retained) => {
                match read_root_graph_for_retained_attempt_v1(&transaction, retained).and_then(
                    |readback| {
                        qualify_retained_readback_v1(&transaction, readback)
                            .map_err(|_| crate::grant::GrantStoreErrorV1::Corrupt)
                    },
                ) {
                    Ok(retained) => AuthorityReadbackOutcomeV1::CommittedRetained(retained),
                    Err(_) => AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired,
                }
            }
            FreshGraphClassificationV1::Conflict => AuthorityReadbackOutcomeV1::ConflictRetained,
            FreshGraphClassificationV1::HealthyAbsence
                if all_root_candidate_keys_absent_v1(&transaction, attempt, &expectation) =>
            {
                AuthorityReadbackOutcomeV1::DeniedDefinite
            }
            FreshGraphClassificationV1::HealthyAbsence | FreshGraphClassificationV1::Ambiguous => {
                AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired
            }
        };
        if transaction.rollback().is_err() {
            return AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired;
        }
        classification
    };

    if opened
        .config()
        .existing_root()
        .is_none_or(|root| root.revalidate().is_err())
        || !deadline_is_still_live_v1(clock.as_ref(), absolute_deadline_monotonic_ms)
    {
        AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired
    } else {
        outcome
    }
}

fn all_root_candidate_keys_absent_v1(
    connection: &Connection,
    attempt: &AuthorityAttemptBindingV1,
    expectation: &RootLeaseReadbackExpectationV1,
) -> bool {
    connection
        .query_row(
            "SELECT
                 NOT EXISTS(SELECT 1 FROM authority_attempts WHERE attempt_id = ?1) AND
                 NOT EXISTS(SELECT 1 FROM authority_attempts WHERE namespace_digest = ?2) AND
                 NOT EXISTS(SELECT 1 FROM human_request_grants
                            WHERE grant_issuer_id = ?3 AND grant_id = ?4) AND
                 NOT EXISTS(SELECT 1 FROM human_grant_claims
                            WHERE grant_issuer_id = ?3 AND grant_id = ?4)",
            params![
                attempt.attempt_id_v1().digest_v1().to_hex(),
                attempt.namespace_digest_v1().digest_v1().to_hex(),
                expectation.grant_issuer_id.as_ref(),
                expectation.grant_id.to_hex(),
            ],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
}

fn frozen_readback_deadline_v1(attempt: &AuthorityAttemptBindingV1) -> SafeU64 {
    attempt.caller_deadline_monotonic_ms_v1()
}

struct SqliteAuthorityUncertainReadbackResolverV1 {
    capacity: FreshReadbackCapacityV1,
    fresh_config: AuthorityStoreConfigV1,
    clock: Arc<dyn AuthorityClockProviderV1>,
    absolute_deadline_monotonic_ms: SafeU64,
    expected_root_id: Box<str>,
    graph_verifier: Box<dyn AuthorityFreshGraphVerifierV1>,
}

impl fmt::Debug for SqliteAuthorityUncertainReadbackResolverV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SqliteAuthorityUncertainReadbackResolverV1(..)")
    }
}

impl AuthorityUncertainReadbackResolverV1<AuthorityRetainedAttemptV1>
    for SqliteAuthorityUncertainReadbackResolverV1
{
    fn readback_exact_once_v1(
        self: Box<Self>,
        attempt: &AuthorityAttemptBindingV1,
    ) -> AuthorityReadbackOutcomeV1<AuthorityRetainedAttemptV1> {
        let Self {
            capacity,
            fresh_config,
            clock,
            absolute_deadline_monotonic_ms,
            expected_root_id,
            graph_verifier,
        } = *self;

        // Consumption occurs before any fallible operation.  An unavailable root or
        // failed open therefore cannot preserve authority for a second auto-readback.
        capacity.consume_v1();
        resolve_on_one_fresh_connection_v1(
            fresh_config,
            clock,
            absolute_deadline_monotonic_ms,
            expected_root_id,
            graph_verifier,
            attempt,
        )
    }
}

/// Operation-specific proof required on top of the global T020 relational verifier.
///
/// Future mutation modules capture their generated graph keys in this non-public
/// verifier.  A positive complete result must revalidate exact signed wires/digests
/// and every operation member.  Definite absence must prove every candidate-specific
/// durable key absent.  Returning `false` is always ambiguity, never permission to
/// retry the mutation.
pub(crate) trait AuthorityFreshGraphVerifierV1: Send {
    fn complete_graph_matches_v1(
        &self,
        connection: &Connection,
        candidate: &AuthorityAttemptBindingV1,
        retained: &AuthorityRetainedAttemptV1,
    ) -> bool;

    fn all_candidate_graph_keys_absent_v1(
        &self,
        connection: &Connection,
        candidate: &AuthorityAttemptBindingV1,
    ) -> bool;
}

fn resolve_on_one_fresh_connection_v1(
    fresh_config: AuthorityStoreConfigV1,
    clock: Arc<dyn AuthorityClockProviderV1>,
    absolute_deadline_monotonic_ms: SafeU64,
    expected_root_id: Box<str>,
    graph_verifier: Box<dyn AuthorityFreshGraphVerifierV1>,
    attempt: &AuthorityAttemptBindingV1,
) -> AuthorityReadbackOutcomeV1<AuthorityRetainedAttemptV1> {
    let mut opened = match open_existing_v1(
        fresh_config,
        clock.as_ref(),
        absolute_deadline_monotonic_ms,
        &expected_root_id,
    ) {
        Ok(opened) => opened,
        Err(_) => return FreshGraphClassificationV1::Ambiguous.into_core_v1(),
    };

    // Readback is structurally non-mutating even if later code is accidentally added.
    if opened
        .connection()
        .pragma_update(None, "query_only", true)
        .is_err()
    {
        return FreshGraphClassificationV1::Ambiguous.into_core_v1();
    }

    let classification = {
        let transaction = match opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Deferred)
        {
            Ok(transaction) => transaction,
            Err(_) => return FreshGraphClassificationV1::Ambiguous.into_core_v1(),
        };

        // Re-run exact admission after the read transaction establishes its snapshot;
        // the pre-open verifier alone would not bind subsequent graph reads to it.
        if schema::verify_admission_v1(&transaction, &expected_root_id).is_err() {
            return FreshGraphClassificationV1::Ambiguous.into_core_v1();
        }
        let classification = qualify_operation_graph_v1(
            &transaction,
            attempt,
            classify_fresh_graph_v1(&transaction, attempt),
            graph_verifier.as_ref(),
        );
        if transaction.rollback().is_err() {
            return FreshGraphClassificationV1::Ambiguous.into_core_v1();
        }
        classification
    };

    let root_is_still_exact = opened
        .config()
        .existing_root()
        .is_some_and(|root| root.revalidate().is_ok());
    if !root_is_still_exact
        || !deadline_is_still_live_v1(clock.as_ref(), absolute_deadline_monotonic_ms)
    {
        return FreshGraphClassificationV1::Ambiguous.into_core_v1();
    }

    classification.into_core_v1()
}

fn qualify_operation_graph_v1(
    connection: &Connection,
    candidate: &AuthorityAttemptBindingV1,
    relational: FreshGraphClassificationV1,
    verifier: &dyn AuthorityFreshGraphVerifierV1,
) -> FreshGraphClassificationV1 {
    match relational {
        FreshGraphClassificationV1::Complete(retained)
            if verifier.complete_graph_matches_v1(connection, candidate, &retained) =>
        {
            FreshGraphClassificationV1::Complete(retained)
        }
        FreshGraphClassificationV1::HealthyAbsence
            if verifier.all_candidate_graph_keys_absent_v1(connection, candidate) =>
        {
            FreshGraphClassificationV1::HealthyAbsence
        }
        FreshGraphClassificationV1::Complete(_) | FreshGraphClassificationV1::HealthyAbsence => {
            FreshGraphClassificationV1::Ambiguous
        }
        FreshGraphClassificationV1::Conflict => FreshGraphClassificationV1::Conflict,
        FreshGraphClassificationV1::Ambiguous => FreshGraphClassificationV1::Ambiguous,
    }
}

fn deadline_is_still_live_v1(
    clock: &dyn AuthorityClockProviderV1,
    absolute_deadline_monotonic_ms: SafeU64,
) -> bool {
    if absolute_deadline_monotonic_ms.get() == 0 {
        return false;
    }
    clock
        .capture_v1(absolute_deadline_monotonic_ms)
        .is_ok_and(|observation| {
            observation.sampled_monotonic_ms_v1() < absolute_deadline_monotonic_ms
        })
}

/// Closed graph classification used internally before mapping to the portable core
/// readback vocabulary.
enum FreshGraphClassificationV1 {
    Complete(AuthorityRetainedAttemptV1),
    HealthyAbsence,
    Conflict,
    Ambiguous,
}

impl FreshGraphClassificationV1 {
    fn into_core_v1(self) -> AuthorityReadbackOutcomeV1<AuthorityRetainedAttemptV1> {
        match self {
            Self::Complete(retained) => AuthorityReadbackOutcomeV1::CommittedRetained(retained),
            Self::HealthyAbsence => AuthorityReadbackOutcomeV1::DeniedDefinite,
            Self::Conflict => AuthorityReadbackOutcomeV1::ConflictRetained,
            Self::Ambiguous => AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired,
        }
    }
}

impl fmt::Debug for FreshGraphClassificationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Complete(_) => "FreshGraphClassificationV1::Complete(..)",
            Self::HealthyAbsence => "FreshGraphClassificationV1::HealthyAbsence",
            Self::Conflict => "FreshGraphClassificationV1::Conflict",
            Self::Ambiguous => "FreshGraphClassificationV1::Ambiguous",
        })
    }
}

struct DurableAttemptRowV1 {
    attempt_id: String,
    operation_kind: String,
    namespace_digest: String,
    input_graph_digest: String,
    caller_deadline_monotonic_ms: i64,
    outcome_code: String,
    outcome_binding_digest: String,
    attempt_generation: i64,
    event_id: String,
}

impl fmt::Debug for DurableAttemptRowV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DurableAttemptRowV1(..)")
    }
}

impl DurableAttemptRowV1 {
    fn has_candidate_attempt_id_v1(&self, candidate: &AuthorityAttemptBindingV1) -> bool {
        self.attempt_id == candidate.attempt_id_v1().digest_v1().to_hex()
    }

    fn has_same_stable_input_v1(&self, candidate: &AuthorityAttemptBindingV1) -> bool {
        self.operation_kind == candidate.operation_kind_v1().sql_code_v1()
            && self.namespace_digest == candidate.namespace_digest_v1().digest_v1().to_hex()
            && self.input_graph_digest == candidate.input_graph_digest_v1().digest_v1().to_hex()
            && u64::try_from(self.caller_deadline_monotonic_ms)
                .is_ok_and(|value| value == candidate.caller_deadline_monotonic_ms_v1().get())
    }

    fn into_classification_v1(self) -> FreshGraphClassificationV1 {
        match self.outcome_code.as_str() {
            "CONFLICT_RETAINED" => FreshGraphClassificationV1::Conflict,
            "COMMITTED_RETAINED" | "RESTORE_PENDING" => self
                .into_retained_v1()
                .map(FreshGraphClassificationV1::Complete)
                .unwrap_or(FreshGraphClassificationV1::Ambiguous),
            _ => FreshGraphClassificationV1::Ambiguous,
        }
    }

    fn into_retained_v1(self) -> Option<AuthorityRetainedAttemptV1> {
        let attempt_id = Sha256Digest::parse_hex(&self.attempt_id).ok()?;
        let namespace_digest = Sha256Digest::parse_hex(&self.namespace_digest).ok()?;
        let input_graph_digest = Sha256Digest::parse_hex(&self.input_graph_digest).ok()?;
        let outcome_binding_digest = Sha256Digest::parse_hex(&self.outcome_binding_digest).ok()?;
        let event_id = Sha256Digest::parse_hex(&self.event_id).ok()?;
        let deadline = SafeU64::new(u64::try_from(self.caller_deadline_monotonic_ms).ok()?).ok()?;
        let generation = Generation::new(u64::try_from(self.attempt_generation).ok()?).ok()?;
        let operation_kind = parse_operation_kind_v1(&self.operation_kind)?;
        let outcome_code = parse_outcome_code_v1(&self.outcome_code)?;
        let attempt = AuthorityAttemptBindingV1::from_verified_parts_v1(
            AuthorityAttemptIdV1::from_verified_digest_v1(attempt_id),
            operation_kind,
            AuthorityNamespaceDigestV1::from_verified_digest_v1(namespace_digest),
            AuthorityInputGraphDigestV1::from_verified_digest_v1(input_graph_digest),
            deadline,
        )?;
        Some(AuthorityRetainedAttemptV1::from_verified_parts_v1(
            attempt,
            outcome_code,
            AuthorityOutcomeBindingDigestV1::from_verified_digest_v1(outcome_binding_digest),
            generation,
            event_id,
        ))
    }
}

fn classify_fresh_graph_v1(
    connection: &Connection,
    candidate: &AuthorityAttemptBindingV1,
) -> FreshGraphClassificationV1 {
    let candidate_attempt_id = candidate.attempt_id_v1().digest_v1().to_hex();
    let candidate_namespace = candidate.namespace_digest_v1().digest_v1().to_hex();
    let mut statement = match connection.prepare(
        "SELECT attempt_id, operation_kind, namespace_digest, input_graph_digest, \
                caller_deadline_monotonic_ms, outcome_code, outcome_binding_digest, \
                attempt_generation, event_id \
         FROM main.authority_attempts \
         WHERE attempt_id = ?1 OR namespace_digest = ?2 \
         ORDER BY CASE WHEN attempt_id = ?1 THEN 0 ELSE 1 END, attempt_generation \
         LIMIT 3",
    ) {
        Ok(statement) => statement,
        Err(_) => return FreshGraphClassificationV1::Ambiguous,
    };
    let mapped =
        match statement.query_map(params![candidate_attempt_id, candidate_namespace], |row| {
            Ok(DurableAttemptRowV1 {
                attempt_id: row.get(0)?,
                operation_kind: row.get(1)?,
                namespace_digest: row.get(2)?,
                input_graph_digest: row.get(3)?,
                caller_deadline_monotonic_ms: row.get(4)?,
                outcome_code: row.get(5)?,
                outcome_binding_digest: row.get(6)?,
                attempt_generation: row.get(7)?,
                event_id: row.get(8)?,
            })
        }) {
            Ok(mapped) => mapped,
            Err(_) => return FreshGraphClassificationV1::Ambiguous,
        };
    let mut rows = match mapped.collect::<rusqlite::Result<Vec<_>>>() {
        Ok(rows) => rows,
        Err(_) => return FreshGraphClassificationV1::Ambiguous,
    };

    // Three rows already prove that the supposedly one-shot namespace is not uniquely
    // classifiable.  The LIMIT keeps corruption from turning readback into an unbounded
    // scan while still detecting this condition.
    if rows.len() >= 3 {
        return FreshGraphClassificationV1::Ambiguous;
    }
    if rows.iter().any(|row| {
        row.has_candidate_attempt_id_v1(candidate) && !row.has_same_stable_input_v1(candidate)
    }) {
        return FreshGraphClassificationV1::Ambiguous;
    }

    let matching = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| row.has_same_stable_input_v1(candidate).then_some(index))
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [index] => rows.swap_remove(*index).into_classification_v1(),
        [_, _, ..] => FreshGraphClassificationV1::Ambiguous,
        [] if rows.is_empty() => FreshGraphClassificationV1::HealthyAbsence,
        [] if rows.len() == 1 => FreshGraphClassificationV1::Conflict,
        [] => FreshGraphClassificationV1::Ambiguous,
    }
}

fn parse_operation_kind_v1(value: &str) -> Option<AuthorityOperationKindV1> {
    AuthorityOperationKindV1::ALL
        .into_iter()
        .find(|kind| kind.sql_code_v1() == value)
}

fn parse_outcome_code_v1(value: &str) -> Option<AuthorityRetainedOutcomeCodeV1> {
    match value {
        "COMMITTED_RETAINED" => Some(AuthorityRetainedOutcomeCodeV1::CommittedRetained),
        "CONFLICT_RETAINED" => Some(AuthorityRetainedOutcomeCodeV1::ConflictRetained),
        "RESTORE_PENDING" => Some(AuthorityRetainedOutcomeCodeV1::RestorePending),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_task_authority::AuthorityRetainedGraphV1;
    use std::cell::Cell;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_READBACK_DATABASE: AtomicU64 = AtomicU64::new(1);

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("test value is safe")
    }

    fn candidate(attempt: u8, namespace: u8, input: u8) -> AuthorityAttemptBindingV1 {
        AuthorityAttemptBindingV1::from_verified_parts_v1(
            AuthorityAttemptIdV1::from_verified_digest_v1(digest(attempt)),
            AuthorityOperationKindV1::RootLeaseIssue,
            AuthorityNamespaceDigestV1::from_verified_digest_v1(digest(namespace)),
            AuthorityInputGraphDigestV1::from_verified_digest_v1(digest(input)),
            safe(500),
        )
        .expect("test attempt is valid")
    }

    #[test]
    fn readback_deadline_is_only_the_original_attempt_bound() {
        let attempt = candidate(1, 2, 3);
        assert_eq!(frozen_readback_deadline_v1(&attempt).get(), 500);
        // There is intentionally no supplied-deadline parameter on the resolver
        // constructor, so a later value cannot replace this frozen bound.
    }

    fn schema_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("SQLite opens");
        connection
            .execute_batch(schema::TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
            .expect("authority schema initializes");
        // These focused classifier fixtures intentionally omit the operation-specific
        // graph.  Production resolution admits the complete graph first through T020.
        connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .expect("focused fixture disables graph foreign keys");
        connection
    }

    fn insert_attempt(
        connection: &Connection,
        attempt: u8,
        namespace: u8,
        input: u8,
        outcome: &str,
        generation: u64,
    ) {
        connection
            .execute(
                "INSERT INTO authority_attempts (attempt_id, operation_kind, namespace_digest, \
                     input_graph_digest, caller_deadline_monotonic_ms, outcome_code, \
                     outcome_binding_digest, attempt_generation, event_id) \
                 VALUES (?1, 'ROOT_LEASE_ISSUE', ?2, ?3, 500, ?4, ?5, ?6, ?7)",
                params![
                    digest(attempt).to_hex(),
                    digest(namespace).to_hex(),
                    digest(input).to_hex(),
                    outcome,
                    digest(attempt.wrapping_add(80)).to_hex(),
                    i64::try_from(generation).expect("generation fits"),
                    digest(attempt.wrapping_add(120)).to_hex(),
                ],
            )
            .expect("attempt fixture inserts");
    }

    struct ScriptedGraphVerifierV1 {
        complete_matches: bool,
        all_keys_absent: bool,
        complete_calls: Cell<u64>,
        absence_calls: Cell<u64>,
    }

    impl ScriptedGraphVerifierV1 {
        fn returning_v1(complete_matches: bool, all_keys_absent: bool) -> Self {
            Self {
                complete_matches,
                all_keys_absent,
                complete_calls: Cell::new(0),
                absence_calls: Cell::new(0),
            }
        }
    }

    impl AuthorityFreshGraphVerifierV1 for ScriptedGraphVerifierV1 {
        fn complete_graph_matches_v1(
            &self,
            _connection: &Connection,
            _candidate: &AuthorityAttemptBindingV1,
            _retained: &AuthorityRetainedAttemptV1,
        ) -> bool {
            self.complete_calls.set(self.complete_calls.get() + 1);
            self.complete_matches
        }

        fn all_candidate_graph_keys_absent_v1(
            &self,
            _connection: &Connection,
            _candidate: &AuthorityAttemptBindingV1,
        ) -> bool {
            self.absence_calls.set(self.absence_calls.get() + 1);
            self.all_keys_absent
        }
    }

    #[test]
    fn exact_complete_graph_reconstructs_retained_evidence() {
        let connection = schema_connection();
        let candidate = candidate(1, 2, 3);
        insert_attempt(&connection, 1, 2, 3, "COMMITTED_RETAINED", 7);

        let retained = match classify_fresh_graph_v1(&connection, &candidate) {
            FreshGraphClassificationV1::Complete(retained) => retained,
            other => panic!("unexpected classification: {other:?}"),
        };
        assert_eq!(retained.attempt_id_v1().digest_v1(), digest(1));
        assert_eq!(retained.attempt_generation_v1().get(), 7);
        assert!(matches!(
            retained.outcome_code_v1(),
            AuthorityRetainedOutcomeCodeV1::CommittedRetained
        ));
    }

    #[test]
    fn relational_complete_requires_the_operation_specific_digest_and_wire_graph() {
        let connection = schema_connection();
        let candidate = candidate(1, 2, 3);
        insert_attempt(&connection, 1, 2, 3, "COMMITTED_RETAINED", 7);

        let verifier = ScriptedGraphVerifierV1::returning_v1(false, true);
        let classification = qualify_operation_graph_v1(
            &connection,
            &candidate,
            classify_fresh_graph_v1(&connection, &candidate),
            &verifier,
        );

        assert!(matches!(
            classification,
            FreshGraphClassificationV1::Ambiguous
        ));
        assert_eq!(verifier.complete_calls.get(), 1);
        assert_eq!(verifier.absence_calls.get(), 0);

        let verifier = ScriptedGraphVerifierV1::returning_v1(true, false);
        let classification = qualify_operation_graph_v1(
            &connection,
            &candidate,
            classify_fresh_graph_v1(&connection, &candidate),
            &verifier,
        );
        assert!(matches!(
            classification,
            FreshGraphClassificationV1::Complete(_)
        ));
        assert_eq!(verifier.complete_calls.get(), 1);
        assert_eq!(verifier.absence_calls.get(), 0);
    }

    #[test]
    fn relational_absence_requires_every_candidate_graph_key_to_be_absent() {
        let connection = schema_connection();
        let candidate = candidate(1, 2, 3);

        let verifier = ScriptedGraphVerifierV1::returning_v1(true, false);
        let classification = qualify_operation_graph_v1(
            &connection,
            &candidate,
            classify_fresh_graph_v1(&connection, &candidate),
            &verifier,
        );
        assert!(matches!(
            classification,
            FreshGraphClassificationV1::Ambiguous
        ));
        assert_eq!(verifier.complete_calls.get(), 0);
        assert_eq!(verifier.absence_calls.get(), 1);

        let verifier = ScriptedGraphVerifierV1::returning_v1(false, true);
        let classification = qualify_operation_graph_v1(
            &connection,
            &candidate,
            classify_fresh_graph_v1(&connection, &candidate),
            &verifier,
        );
        assert!(matches!(
            classification,
            FreshGraphClassificationV1::HealthyAbsence
        ));
        assert_eq!(verifier.complete_calls.get(), 0);
        assert_eq!(verifier.absence_calls.get(), 1);
    }

    #[test]
    fn conflict_and_relational_ambiguity_cannot_be_upgraded_by_the_verifier() {
        let candidate = candidate(1, 2, 3);
        let verifier = ScriptedGraphVerifierV1::returning_v1(true, true);

        let connection = schema_connection();
        insert_attempt(&connection, 9, 2, 4, "COMMITTED_RETAINED", 7);
        assert!(matches!(
            qualify_operation_graph_v1(
                &connection,
                &candidate,
                classify_fresh_graph_v1(&connection, &candidate),
                &verifier,
            ),
            FreshGraphClassificationV1::Conflict
        ));

        let connection = schema_connection();
        insert_attempt(&connection, 1, 2, 4, "COMMITTED_RETAINED", 7);
        assert!(matches!(
            qualify_operation_graph_v1(
                &connection,
                &candidate,
                classify_fresh_graph_v1(&connection, &candidate),
                &verifier,
            ),
            FreshGraphClassificationV1::Ambiguous
        ));
        assert_eq!(verifier.complete_calls.get(), 0);
        assert_eq!(verifier.absence_calls.get(), 0);
    }

    #[test]
    fn exact_retry_can_recover_the_preexisting_attempt_for_the_same_stable_input() {
        let connection = schema_connection();
        let later_candidate = candidate(9, 2, 3);
        insert_attempt(&connection, 1, 2, 3, "COMMITTED_RETAINED", 7);

        let retained = match classify_fresh_graph_v1(&connection, &later_candidate) {
            FreshGraphClassificationV1::Complete(retained) => retained,
            other => panic!("unexpected classification: {other:?}"),
        };
        assert_eq!(retained.attempt_id_v1().digest_v1(), digest(1));
    }

    #[test]
    fn healthy_absence_and_one_different_binding_are_closed() {
        let connection = schema_connection();
        let candidate = candidate(1, 2, 3);
        assert!(matches!(
            classify_fresh_graph_v1(&connection, &candidate),
            FreshGraphClassificationV1::HealthyAbsence
        ));

        insert_attempt(&connection, 9, 2, 4, "COMMITTED_RETAINED", 7);
        assert!(matches!(
            classify_fresh_graph_v1(&connection, &candidate),
            FreshGraphClassificationV1::Conflict
        ));
    }

    #[test]
    fn mismatched_attempt_or_multiple_different_bindings_are_ambiguous() {
        let connection = schema_connection();
        let candidate = candidate(1, 2, 3);
        insert_attempt(&connection, 1, 2, 4, "COMMITTED_RETAINED", 7);
        assert!(matches!(
            classify_fresh_graph_v1(&connection, &candidate),
            FreshGraphClassificationV1::Ambiguous
        ));

        let connection = schema_connection();
        insert_attempt(&connection, 8, 2, 4, "COMMITTED_RETAINED", 7);
        insert_attempt(&connection, 9, 2, 5, "CONFLICT_RETAINED", 8);
        assert!(matches!(
            classify_fresh_graph_v1(&connection, &candidate),
            FreshGraphClassificationV1::Ambiguous
        ));
    }

    #[test]
    fn unreadable_or_partial_schema_is_ambiguity_not_absence() {
        let connection = Connection::open_in_memory().expect("SQLite opens");
        assert!(matches!(
            classify_fresh_graph_v1(&connection, &candidate(1, 2, 3)),
            FreshGraphClassificationV1::Ambiguous
        ));
    }

    #[test]
    fn abandonment_drops_writer_before_capacity_exists() {
        let sequence = NEXT_READBACK_DATABASE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helix-task-authority-readback-{}-{sequence}.sqlite3",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let uncertain = Connection::open(&path).expect("uncertain connection opens");
        uncertain
            .execute_batch("CREATE TABLE held (id INTEGER); BEGIN IMMEDIATE;")
            .expect("uncertain writer holds its transaction");

        let capacity = abandon_uncertain_connection_v1(uncertain);
        let fresh = Connection::open(&path).expect("fresh connection opens");
        fresh
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
            .expect("writer lock was released before fresh capacity");
        assert_eq!(format!("{capacity:?}"), "FreshReadbackCapacityV1(..)");
        capacity.consume_v1();
        drop(fresh);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn closed_classifications_map_without_retry_outcome() {
        assert!(matches!(
            FreshGraphClassificationV1::HealthyAbsence.into_core_v1(),
            AuthorityReadbackOutcomeV1::DeniedDefinite
        ));
        assert!(matches!(
            FreshGraphClassificationV1::Conflict.into_core_v1(),
            AuthorityReadbackOutcomeV1::ConflictRetained
        ));
        assert!(matches!(
            FreshGraphClassificationV1::Ambiguous.into_core_v1(),
            AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired
        ));
    }
}
