//! Exact retained inbox and receipt readback without re-consumption or re-signing.

#![allow(dead_code)]

use crate::inbox::{AdapterInboxReceiveErrorV1, ReceivedInboxGrantV1, SqliteDispatchInboxStoreV1};
use crate::receipt::{AdapterRetainedReceiptDecisionV1, RetainedAdapterReceiptV1};
#[cfg(feature = "test-fault-injection")]
use crate::test_fault::FaultBoundaryV1;
use helix_dispatch_contracts::{
    decode_and_verify_execution_receipt_v1, decode_and_verify_retained_execution_grant_v1,
    ExecutionReceiptDecisionV1, ExecutionReceiptRefusalCodeV1, GrantKeyResolver,
    ReceiptKeyResolver, ReceiptVerificationBindingsV1, RetainedExecutionGrantEvidenceV1,
    Sha256Digest,
};
use rusqlite::{Connection, ErrorCode, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::error::Error;
use std::fmt;

/// Closed exact readback result for one grant identity.
pub enum AdapterInboxReadbackOutcomeV1 {
    Absent,
    Received(ReceivedInboxGrantV1),
    RetainedReceipt(RetainedAdapterReceiptV1),
    Conflict,
    Quarantined,
}

impl fmt::Debug for AdapterInboxReadbackOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => formatter.write_str("AdapterInboxReadbackOutcomeV1::Absent"),
            Self::Received(_) => formatter.write_str("AdapterInboxReadbackOutcomeV1::Received(..)"),
            Self::RetainedReceipt(_) => {
                formatter.write_str("AdapterInboxReadbackOutcomeV1::RetainedReceipt(..)")
            }
            Self::Conflict => formatter.write_str("AdapterInboxReadbackOutcomeV1::Conflict"),
            Self::Quarantined => formatter.write_str("AdapterInboxReadbackOutcomeV1::Quarantined"),
        }
    }
}

/// Payload-free failure to prove one exact retained graph.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterInboxReadbackErrorV1 {
    StoreBusy,
    StoreUnavailable,
    GrantUnverifiable,
    ReceiptUnverifiable,
    InvariantFailed,
}

impl AdapterInboxReadbackErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::StoreBusy => "STORE_BUSY",
            Self::StoreUnavailable => "STORE_UNAVAILABLE",
            Self::GrantUnverifiable => "GRANT_UNVERIFIABLE",
            Self::ReceiptUnverifiable => "RECEIPT_UNVERIFIABLE",
            Self::InvariantFailed => "INVARIANT_FAILED",
        }
    }
}

impl fmt::Debug for AdapterInboxReadbackErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AdapterInboxReadbackErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterInboxReadbackErrorV1 {}

impl SqliteDispatchInboxStoreV1 {
    /// Reads one exact retained state from SQLite after restart. Historical verification
    /// keys are accepted only to prove retained bytes; this path never consumes or signs.
    pub fn readback_grant_v1<G, R>(
        &self,
        grant_id: Sha256Digest,
        grant_resolver: &G,
        receipt_resolver: &R,
    ) -> Result<AdapterInboxReadbackOutcomeV1, AdapterInboxReadbackErrorV1>
    where
        G: GrantKeyResolver,
        R: ReceiptKeyResolver,
    {
        let mut opened = self.lock_store().map_err(map_lock_error)?;
        let root_identity =
            Sha256Digest::from_bytes(opened.summary().root_identity.to_attested_bytes());
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(map_sqlite_error)?;
        let Some(grant) = load_verified_grant_by_id_v1(&transaction, grant_id, grant_resolver)?
        else {
            let outcome = classify_missing_binding_v1(&transaction, grant_id)?;
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(outcome);
        };

        let outcome = match grant.state {
            RetainedInboxStateV1::Received => {
                if grant.receipt_id.is_some() || grant.receipt_decision.is_some() {
                    return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
                }
                AdapterInboxReadbackOutcomeV1::Received(grant.to_received_handle_v1()?)
            }
            RetainedInboxStateV1::Consumed | RetainedInboxStateV1::Refused => {
                let receipt = load_verified_receipt_v1(
                    &transaction,
                    &grant,
                    root_identity,
                    receipt_resolver,
                )?
                .ok_or(AdapterInboxReadbackErrorV1::InvariantFailed)?;
                #[cfg(feature = "test-fault-injection")]
                self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb039)
                    .map_err(|_| AdapterInboxReadbackErrorV1::StoreUnavailable)?;
                AdapterInboxReadbackOutcomeV1::RetainedReceipt(receipt)
            }
            RetainedInboxStateV1::Quarantined => {
                if grant.receipt_id.is_some() || grant.receipt_decision.is_some() {
                    return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
                }
                AdapterInboxReadbackOutcomeV1::Quarantined
            }
        };
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetainedInboxStateV1 {
    Received,
    Consumed,
    Refused,
    Quarantined,
}

pub(crate) struct VerifiedRetainedGrantRowV1 {
    pub(crate) evidence: RetainedExecutionGrantEvidenceV1,
    pub(crate) grant_id: Sha256Digest,
    pub(crate) operation_id: String,
    pub(crate) dispatch_attempt_id: Sha256Digest,
    pub(crate) plan_id: Sha256Digest,
    pub(crate) task_id: String,
    pub(crate) workload_id: String,
    pub(crate) task_lease_digest: Sha256Digest,
    pub(crate) grant_digest: Sha256Digest,
    pub(crate) destination_adapter_id: String,
    pub(crate) protocol_version: u8,
    pub(crate) observed_supervisor_epoch: u64,
    pub(crate) epoch_observer_generation: u64,
    pub(crate) state: RetainedInboxStateV1,
    pub(crate) received_generation: u64,
    pub(crate) current_generation: u64,
    pub(crate) receipt_id: Option<Sha256Digest>,
    pub(crate) receipt_decision: Option<AdapterRetainedReceiptDecisionV1>,
}

impl fmt::Debug for VerifiedRetainedGrantRowV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRetainedGrantRowV1")
            .finish_non_exhaustive()
    }
}

impl VerifiedRetainedGrantRowV1 {
    pub(crate) fn to_received_handle_v1(
        &self,
    ) -> Result<ReceivedInboxGrantV1, AdapterInboxReadbackErrorV1> {
        if self.state != RetainedInboxStateV1::Received
            || self.current_generation != self.received_generation
        {
            return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
        }
        let claims = self.evidence.claims();
        ReceivedInboxGrantV1::from_retained_parts_v1(
            self.grant_id,
            &self.operation_id,
            self.dispatch_attempt_id,
            self.received_generation,
            claims.boot_id(),
            self.observed_supervisor_epoch,
            self.epoch_observer_generation,
            claims.deadline_monotonic_ms(),
        )
        .map_err(|_| AdapterInboxReadbackErrorV1::InvariantFailed)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_verified_received_grant_v1<G: GrantKeyResolver>(
    connection: &Connection,
    received: &ReceivedInboxGrantV1,
    resolver: &G,
) -> Result<Option<VerifiedRetainedGrantRowV1>, AdapterInboxReadbackErrorV1> {
    let Some(grant) = load_verified_grant_by_id_v1(connection, received.grant_id(), resolver)?
    else {
        return Ok(None);
    };
    if grant.operation_id != received.operation_id()
        || grant.dispatch_attempt_id != received.dispatch_attempt_id()
        || grant.received_generation != received.received_generation()
    {
        return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
    }
    Ok(Some(grant))
}

pub(crate) fn load_verified_grant_by_id_v1<G: GrantKeyResolver>(
    connection: &Connection,
    grant_id: Sha256Digest,
    resolver: &G,
) -> Result<Option<VerifiedRetainedGrantRowV1>, AdapterInboxReadbackErrorV1> {
    let raw = connection
        .query_row(
            "SELECT operation_id, dispatch_attempt_id, plan_id, task_id, workload_id,
                    task_lease_digest, one_shot_nonce, grant_digest, canonical_grant,
                    canonical_grant_length, coordinator_key_fingerprint,
                    destination_adapter_id, protocol_version,
                    observed_supervisor_epoch, epoch_observer_generation, inbox_state,
                    received_generation, current_generation, receipt_id, receipt_decision
             FROM grant_inbox WHERE grant_id = ?1",
            [grant_id.as_bytes().as_slice()],
            |row| {
                Ok(RawGrantRowV1 {
                    operation_id: row.get(0)?,
                    dispatch_attempt_id: row.get(1)?,
                    plan_id: row.get(2)?,
                    task_id: row.get(3)?,
                    workload_id: row.get(4)?,
                    task_lease_digest: row.get(5)?,
                    one_shot_nonce: row.get(6)?,
                    grant_digest: row.get(7)?,
                    canonical_grant: row.get(8)?,
                    canonical_grant_length: row.get(9)?,
                    coordinator_key_fingerprint: row.get(10)?,
                    destination_adapter_id: row.get(11)?,
                    protocol_version: row.get(12)?,
                    observed_supervisor_epoch: row.get(13)?,
                    epoch_observer_generation: row.get(14)?,
                    state: row.get(15)?,
                    received_generation: row.get(16)?,
                    current_generation: row.get(17)?,
                    receipt_id: row.get(18)?,
                    receipt_decision: row.get(19)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?;
    raw.map(|raw| verify_raw_grant_v1(grant_id, raw, resolver))
        .transpose()
}

pub(crate) fn load_verified_receipt_v1<R: ReceiptKeyResolver>(
    connection: &Connection,
    grant: &VerifiedRetainedGrantRowV1,
    adapter_root_id: Sha256Digest,
    resolver: &R,
) -> Result<Option<RetainedAdapterReceiptV1>, AdapterInboxReadbackErrorV1> {
    let raw = connection
        .query_row(
            "SELECT receipt_id, operation_id, dispatch_attempt_id, receipt_digest,
                    canonical_receipt, canonical_receipt_length, adapter_key_id,
                    adapter_key_fingerprint, decision, refusal_code,
                    no_consumption_tombstone_digest, receipt_generation
             FROM execution_receipts WHERE grant_id = ?1",
            [grant.grant_id.as_bytes().as_slice()],
            |row| {
                Ok(RawReceiptRowV1 {
                    receipt_id: row.get(0)?,
                    operation_id: row.get(1)?,
                    dispatch_attempt_id: row.get(2)?,
                    receipt_digest: row.get(3)?,
                    canonical_receipt: row.get(4)?,
                    canonical_receipt_length: row.get(5)?,
                    adapter_key_id: row.get(6)?,
                    adapter_key_fingerprint: row.get(7)?,
                    decision: row.get(8)?,
                    refusal_code: row.get(9)?,
                    no_consumption_tombstone_digest: row.get(10)?,
                    receipt_generation: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(map_sqlite_error)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let receipt_id = exact_digest(&raw.receipt_id)?;
    let receipt_digest = exact_digest(&raw.receipt_digest)?;
    let adapter_key_fingerprint = exact_digest(&raw.adapter_key_fingerprint)?;
    let receipt_generation = strict_generation(raw.receipt_generation)?;
    if raw.operation_id != grant.operation_id
        || exact_digest(&raw.dispatch_attempt_id)? != grant.dispatch_attempt_id
        || strict_length(raw.canonical_receipt_length)? != raw.canonical_receipt.len()
        || raw.canonical_receipt.is_empty()
        || raw.canonical_receipt.len() > 65_536
        || grant.receipt_id != Some(receipt_id)
    {
        return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
    }

    let bindings = ReceiptVerificationBindingsV1::from_retained_grant_evidence(
        &grant.evidence,
        adapter_root_id,
    );
    let authentic =
        decode_and_verify_execution_receipt_v1(&raw.canonical_receipt, resolver, &bindings)
            .map_err(|_| AdapterInboxReadbackErrorV1::ReceiptUnverifiable)?;
    let claims = authentic.claims();
    let decision = decision_from_contract(claims.decision());
    let refusal = claims.refusal_code();
    if authentic
        .canonical_signed_envelope_bytes()
        .map_err(|_| AdapterInboxReadbackErrorV1::ReceiptUnverifiable)?
        != raw.canonical_receipt
        || claims.receipt_id() != receipt_id
        || claims.receipt_digest() != receipt_digest
        || claims.grant_id() != grant.grant_id
        || claims.operation_id() != grant.operation_id
        || claims.inbox_generation() != grant.received_generation
        || match decision {
            AdapterRetainedReceiptDecisionV1::Consumed => {
                claims.consumption_generation() != Some(grant.current_generation)
                    || claims.refusal_generation().is_some()
            }
            AdapterRetainedReceiptDecisionV1::RefusedDefinite => {
                claims.refusal_generation() != Some(grant.current_generation)
                    || claims.consumption_generation().is_some()
            }
        }
        || claims.receipt_generation() != receipt_generation
        || claims.key_id() != raw.adapter_key_id
        || authentic.verified_key_fingerprint() != adapter_key_fingerprint
        || decision.code() != raw.decision
        || refusal_code(refusal) != raw.refusal_code.as_deref()
        || optional_digest(&raw.no_consumption_tombstone_digest)?
            != claims.no_consumption_tombstone_digest()
        || grant.receipt_decision != Some(decision)
    {
        return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
    }
    match (grant.state, decision) {
        (RetainedInboxStateV1::Consumed, AdapterRetainedReceiptDecisionV1::Consumed)
        | (RetainedInboxStateV1::Refused, AdapterRetainedReceiptDecisionV1::RefusedDefinite) => {}
        _ => return Err(AdapterInboxReadbackErrorV1::InvariantFailed),
    }
    Ok(Some(RetainedAdapterReceiptV1::from_verified_parts_v1(
        raw.canonical_receipt,
        decision,
        refusal,
        claims.no_consumption_tombstone_digest(),
        receipt_generation,
    )))
}

struct RawGrantRowV1 {
    operation_id: String,
    dispatch_attempt_id: Vec<u8>,
    plan_id: Vec<u8>,
    task_id: String,
    workload_id: String,
    task_lease_digest: Vec<u8>,
    one_shot_nonce: Vec<u8>,
    grant_digest: Vec<u8>,
    canonical_grant: Vec<u8>,
    canonical_grant_length: i64,
    coordinator_key_fingerprint: Vec<u8>,
    destination_adapter_id: String,
    protocol_version: i64,
    observed_supervisor_epoch: i64,
    epoch_observer_generation: i64,
    state: String,
    received_generation: i64,
    current_generation: i64,
    receipt_id: Option<Vec<u8>>,
    receipt_decision: Option<String>,
}

struct RawReceiptRowV1 {
    receipt_id: Vec<u8>,
    operation_id: String,
    dispatch_attempt_id: Vec<u8>,
    receipt_digest: Vec<u8>,
    canonical_receipt: Vec<u8>,
    canonical_receipt_length: i64,
    adapter_key_id: String,
    adapter_key_fingerprint: Vec<u8>,
    decision: String,
    refusal_code: Option<String>,
    no_consumption_tombstone_digest: Option<Vec<u8>>,
    receipt_generation: i64,
}

fn verify_raw_grant_v1<G: GrantKeyResolver>(
    grant_id: Sha256Digest,
    raw: RawGrantRowV1,
    resolver: &G,
) -> Result<VerifiedRetainedGrantRowV1, AdapterInboxReadbackErrorV1> {
    if strict_length(raw.canonical_grant_length)? != raw.canonical_grant.len()
        || raw.canonical_grant.is_empty()
        || raw.canonical_grant.len() > 1_048_576
    {
        return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
    }
    let evidence = decode_and_verify_retained_execution_grant_v1(&raw.canonical_grant, resolver)
        .map_err(|_| AdapterInboxReadbackErrorV1::GrantUnverifiable)?;
    if evidence
        .canonical_signed_envelope_bytes()
        .map_err(|_| AdapterInboxReadbackErrorV1::GrantUnverifiable)?
        != raw.canonical_grant
    {
        return Err(AdapterInboxReadbackErrorV1::GrantUnverifiable);
    }
    let claims = evidence.claims();
    let document: Value = serde_json::from_slice(&raw.canonical_grant)
        .map_err(|_| AdapterInboxReadbackErrorV1::GrantUnverifiable)?;
    let protected = document
        .get("protected")
        .and_then(Value::as_object)
        .ok_or(AdapterInboxReadbackErrorV1::GrantUnverifiable)?;
    let dispatch_attempt_id = exact_digest(&raw.dispatch_attempt_id)?;
    let plan_id = exact_digest(&raw.plan_id)?;
    let task_lease_digest = exact_digest(&raw.task_lease_digest)?;
    let one_shot_nonce = exact_digest(&raw.one_shot_nonce)?;
    let grant_digest = exact_digest(&raw.grant_digest)?;
    if claims.grant_id() != grant_id
        || claims.grant_digest() != grant_digest
        || claims.operation_id() != raw.operation_id
        || claims.destination_adapter_id() != raw.destination_adapter_id
        || i64::from(claims.protocol_version()) != raw.protocol_version
        || claims.supervisor_epoch() != strict_safe_integer(raw.observed_supervisor_epoch)?
        || evidence.verified_key_fingerprint() != exact_digest(&raw.coordinator_key_fingerprint)?
        || protected_digest(protected, "dispatch_attempt_id")? != dispatch_attempt_id
        || protected_digest(protected, "plan_id")? != plan_id
        || protected_digest(protected, "lease_digest")? != task_lease_digest
        || protected_digest(protected, "one_shot_nonce")? != one_shot_nonce
        || protected_text(protected, "task_id")? != raw.task_id
        || protected_text(protected, "workload_id")? != raw.workload_id
    {
        return Err(AdapterInboxReadbackErrorV1::InvariantFailed);
    }
    let state = match raw.state.as_str() {
        "RECEIVED" => RetainedInboxStateV1::Received,
        "CONSUMED" => RetainedInboxStateV1::Consumed,
        "REFUSED" => RetainedInboxStateV1::Refused,
        "QUARANTINED" => RetainedInboxStateV1::Quarantined,
        _ => return Err(AdapterInboxReadbackErrorV1::InvariantFailed),
    };
    let receipt_id = optional_digest(&raw.receipt_id)?;
    let receipt_decision = raw
        .receipt_decision
        .as_deref()
        .map(decision_from_text)
        .transpose()?;
    Ok(VerifiedRetainedGrantRowV1 {
        evidence,
        grant_id,
        operation_id: raw.operation_id,
        dispatch_attempt_id,
        plan_id,
        task_id: raw.task_id,
        workload_id: raw.workload_id,
        task_lease_digest,
        grant_digest,
        destination_adapter_id: raw.destination_adapter_id,
        protocol_version: u8::try_from(raw.protocol_version)
            .map_err(|_| AdapterInboxReadbackErrorV1::InvariantFailed)?,
        observed_supervisor_epoch: strict_safe_integer(raw.observed_supervisor_epoch)?,
        epoch_observer_generation: strict_generation(raw.epoch_observer_generation)?,
        state,
        received_generation: strict_generation(raw.received_generation)?,
        current_generation: strict_generation(raw.current_generation)?,
        receipt_id,
        receipt_decision,
    })
}

fn classify_missing_binding_v1(
    connection: &Connection,
    grant_id: Sha256Digest,
) -> Result<AdapterInboxReadbackOutcomeV1, AdapterInboxReadbackErrorV1> {
    let conflict: i64 = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM inbox_conflicts WHERE observed_grant_id = ?1
             )",
            [grant_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    if conflict == 1 {
        return Ok(AdapterInboxReadbackOutcomeV1::Conflict);
    }
    let quarantined: i64 = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM inbox_quarantines WHERE grant_id = ?1
             )",
            [grant_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    match quarantined {
        0 => Ok(AdapterInboxReadbackOutcomeV1::Absent),
        1 => Ok(AdapterInboxReadbackOutcomeV1::Quarantined),
        _ => Err(AdapterInboxReadbackErrorV1::InvariantFailed),
    }
}

fn decision_from_contract(
    decision: ExecutionReceiptDecisionV1,
) -> AdapterRetainedReceiptDecisionV1 {
    match decision {
        ExecutionReceiptDecisionV1::Consumed => AdapterRetainedReceiptDecisionV1::Consumed,
        ExecutionReceiptDecisionV1::RefusedDefinite => {
            AdapterRetainedReceiptDecisionV1::RefusedDefinite
        }
    }
}

fn decision_from_text(
    decision: &str,
) -> Result<AdapterRetainedReceiptDecisionV1, AdapterInboxReadbackErrorV1> {
    match decision {
        "CONSUMED" => Ok(AdapterRetainedReceiptDecisionV1::Consumed),
        "REFUSED_DEFINITE" => Ok(AdapterRetainedReceiptDecisionV1::RefusedDefinite),
        _ => Err(AdapterInboxReadbackErrorV1::InvariantFailed),
    }
}

fn refusal_code(code: Option<ExecutionReceiptRefusalCodeV1>) -> Option<&'static str> {
    code.map(|code| match code {
        ExecutionReceiptRefusalCodeV1::GrantExpired => "GRANT_EXPIRED",
        ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch => "SUPERVISOR_EPOCH_MISMATCH",
        ExecutionReceiptRefusalCodeV1::AdapterPaused => "ADAPTER_PAUSED",
    })
}

fn protected_digest(
    protected: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Sha256Digest, AdapterInboxReadbackErrorV1> {
    let value = protected
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AdapterInboxReadbackErrorV1::GrantUnverifiable)?;
    Sha256Digest::parse_hex(value).map_err(|_| AdapterInboxReadbackErrorV1::GrantUnverifiable)
}

fn protected_text<'value>(
    protected: &'value serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'value str, AdapterInboxReadbackErrorV1> {
    protected
        .get(field)
        .and_then(Value::as_str)
        .ok_or(AdapterInboxReadbackErrorV1::GrantUnverifiable)
}

fn exact_digest(bytes: &[u8]) -> Result<Sha256Digest, AdapterInboxReadbackErrorV1> {
    let exact: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AdapterInboxReadbackErrorV1::InvariantFailed)?;
    Ok(Sha256Digest::from_bytes(exact))
}

fn optional_digest(
    bytes: &Option<Vec<u8>>,
) -> Result<Option<Sha256Digest>, AdapterInboxReadbackErrorV1> {
    bytes.as_deref().map(exact_digest).transpose()
}

fn strict_length(value: i64) -> Result<usize, AdapterInboxReadbackErrorV1> {
    usize::try_from(value).map_err(|_| AdapterInboxReadbackErrorV1::InvariantFailed)
}

fn strict_safe_integer(value: i64) -> Result<u64, AdapterInboxReadbackErrorV1> {
    let value = u64::try_from(value).map_err(|_| AdapterInboxReadbackErrorV1::InvariantFailed)?;
    (value <= helix_dispatch_contracts::MAX_SAFE_U64)
        .then_some(value)
        .ok_or(AdapterInboxReadbackErrorV1::InvariantFailed)
}

fn strict_generation(value: i64) -> Result<u64, AdapterInboxReadbackErrorV1> {
    let value = strict_safe_integer(value)?;
    (value > 0)
        .then_some(value)
        .ok_or(AdapterInboxReadbackErrorV1::InvariantFailed)
}

fn map_lock_error(_error: AdapterInboxReceiveErrorV1) -> AdapterInboxReadbackErrorV1 {
    AdapterInboxReadbackErrorV1::StoreUnavailable
}

fn map_sqlite_error(error: rusqlite::Error) -> AdapterInboxReadbackErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            AdapterInboxReadbackErrorV1::StoreBusy
        }
        rusqlite::Error::SqliteFailure(_, _) => AdapterInboxReadbackErrorV1::StoreUnavailable,
        _ => AdapterInboxReadbackErrorV1::InvariantFailed,
    }
}
