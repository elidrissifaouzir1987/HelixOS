//! Second fencing observation and atomic terminal receipt transaction.

#![allow(dead_code)]

use crate::clock::{AdapterClockObservationV1, AdapterClockV1};
use crate::epoch::{SupervisorEpochObservationV1, SupervisorEpochObserverV1};
use crate::events::{append_terminal_adapter_event_v1, TerminalAdapterEventV1};
use crate::inbox::{AdapterInboxReceiveErrorV1, ReceivedInboxGrantV1, SqliteDispatchInboxStoreV1};
use crate::quarantine::{
    ensure_no_active_global_adapter_corruption_quarantine_v1, QuarantineStoreErrorV1,
};
use crate::readback::{
    load_verified_receipt_v1, load_verified_received_grant_v1, AdapterInboxReadbackErrorV1,
    RetainedInboxStateV1,
};
#[cfg(feature = "test-fault-injection")]
use crate::test_fault::FaultBoundaryV1;
use helix_dispatch_contracts::{
    decode_and_verify_execution_receipt_v1, sign_execution_receipt_v1, ExecutionReceiptDecisionV1,
    ExecutionReceiptInputV1, ExecutionReceiptProtectedV1, ExecutionReceiptRefusalCodeV1,
    Generation, GrantKeyResolver, Identifier, ReceiptKeyResolver, ReceiptSigner,
    ReceiptVerificationBindingsV1, SafeU64, Sha256Digest, VerificationKeyStatusV1, MAX_SAFE_U64,
};
use rusqlite::{params, ErrorCode, Transaction, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;

const TERMINAL_EVENT_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_TERMINAL_EVENT_V1\0";
const TERMINAL_EVIDENCE_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_TERMINAL_EVIDENCE_V1\0";
const REFUSAL_TOMBSTONE_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_REFUSAL_TOMBSTONE_V1\0";
const RECEIPT_TRACE_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_RECEIPT_TRACE_V1\0";

const CONSUMED: &str = "CONSUMED";
const REFUSED: &str = "REFUSED";
const REFUSED_DEFINITE: &str = "REFUSED_DEFINITE";
const GRANT_EXPIRED: &str = "GRANT_EXPIRED";
const SUPERVISOR_EPOCH_MISMATCH: &str = "SUPERVISOR_EPOCH_MISMATCH";
const ADAPTER_PAUSED: &str = "ADAPTER_PAUSED";

/// Provisioner-attested public receipt-key binding. It carries no private signing key.
pub struct AdapterReceiptSigningProfileV1 {
    key_id: Identifier,
    key_fingerprint: Sha256Digest,
    profile_digest: Sha256Digest,
}

impl AdapterReceiptSigningProfileV1 {
    pub fn try_new(
        key_id: impl Into<String>,
        key_fingerprint: Sha256Digest,
        profile_digest: Sha256Digest,
    ) -> Result<Self, AdapterReceiptSigningProfileErrorV1> {
        let key_id = Identifier::new(key_id)
            .map_err(|_| AdapterReceiptSigningProfileErrorV1::InvalidKeyId)?;
        Ok(Self {
            key_id,
            key_fingerprint,
            profile_digest,
        })
    }

    fn key_id(&self) -> &str {
        self.key_id.as_str()
    }
}

impl fmt::Debug for AdapterReceiptSigningProfileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterReceiptSigningProfileV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterReceiptSigningProfileErrorV1 {
    InvalidKeyId,
}

impl AdapterReceiptSigningProfileErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidKeyId => "INVALID_KEY_ID",
        }
    }
}

impl fmt::Debug for AdapterReceiptSigningProfileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AdapterReceiptSigningProfileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterReceiptSigningProfileErrorV1 {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterReceiptEntropyDomainV1 {
    ReceiptIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterReceiptEntropyErrorV1 {
    Unavailable,
    Unsupported,
}

/// Adapter-owned entropy boundary used exactly once by the winning terminal writer.
pub trait AdapterReceiptEntropyV1: Send + Sync {
    fn fill_receipt_entropy_v1(
        &self,
        domain: AdapterReceiptEntropyDomainV1,
        destination: &mut [u8; 32],
    ) -> Result<(), AdapterReceiptEntropyErrorV1>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterConsumptionAdmissionObservationV1 {
    Running,
    Paused,
    Unavailable,
    Unreadable,
}

/// Independent PAUSE observation performed again while the terminal writer is held.
pub trait AdapterConsumptionAdmissionObserverV1: Send + Sync {
    fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterRetainedReceiptDecisionV1 {
    Consumed,
    RefusedDefinite,
}

impl AdapterRetainedReceiptDecisionV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Consumed => CONSUMED,
            Self::RefusedDefinite => REFUSED_DEFINITE,
        }
    }
}

/// Opaque exact signed receipt retained by the adapter store.
///
/// It is deliberately non-Clone and non-Serde. The canonical bytes are read-only
/// evidence and provide no execution, retry, or signing capability.
pub struct RetainedAdapterReceiptV1 {
    canonical_receipt: Box<[u8]>,
    decision: AdapterRetainedReceiptDecisionV1,
    refusal_code: Option<ExecutionReceiptRefusalCodeV1>,
    no_consumption_tombstone_digest: Option<Sha256Digest>,
    receipt_generation: u64,
}

impl RetainedAdapterReceiptV1 {
    pub fn canonical_receipt(&self) -> &[u8] {
        &self.canonical_receipt
    }

    pub const fn decision(&self) -> AdapterRetainedReceiptDecisionV1 {
        self.decision
    }

    pub const fn refusal_code(&self) -> Option<ExecutionReceiptRefusalCodeV1> {
        self.refusal_code
    }

    pub const fn receipt_generation(&self) -> u64 {
        self.receipt_generation
    }

    pub const fn no_consumption_tombstone_digest(&self) -> Option<Sha256Digest> {
        self.no_consumption_tombstone_digest
    }

    pub(crate) fn from_verified_parts_v1(
        canonical_receipt: Vec<u8>,
        decision: AdapterRetainedReceiptDecisionV1,
        refusal_code: Option<ExecutionReceiptRefusalCodeV1>,
        no_consumption_tombstone_digest: Option<Sha256Digest>,
        receipt_generation: u64,
    ) -> Self {
        Self {
            canonical_receipt: canonical_receipt.into_boxed_slice(),
            decision,
            refusal_code,
            no_consumption_tombstone_digest,
            receipt_generation,
        }
    }
}

impl fmt::Debug for RetainedAdapterReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedAdapterReceiptV1")
            .finish_non_exhaustive()
    }
}

/// Closed outcome of one terminalization attempt.
pub enum AdapterInboxConsumeOutcomeV1 {
    Consumed(RetainedAdapterReceiptV1),
    DefinitelyRefused(RetainedAdapterReceiptV1),
    RetainedReceipt(RetainedAdapterReceiptV1),
    Conflict,
    Quarantined,
}

impl fmt::Debug for AdapterInboxConsumeOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consumed(_) => formatter.write_str("AdapterInboxConsumeOutcomeV1::Consumed(..)"),
            Self::DefinitelyRefused(_) => {
                formatter.write_str("AdapterInboxConsumeOutcomeV1::DefinitelyRefused(..)")
            }
            Self::RetainedReceipt(_) => {
                formatter.write_str("AdapterInboxConsumeOutcomeV1::RetainedReceipt(..)")
            }
            Self::Conflict => formatter.write_str("AdapterInboxConsumeOutcomeV1::Conflict"),
            Self::Quarantined => formatter.write_str("AdapterInboxConsumeOutcomeV1::Quarantined"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterInboxConsumeErrorV1 {
    ClockUnavailable,
    ClockUnreadable,
    ClockStale,
    EpochObserverUnavailable,
    EpochObserverUnreadable,
    EpochObserverStale,
    AdmissionUnavailable,
    AdmissionUnreadable,
    EntropyUnavailable,
    SigningProfileMismatch,
    SigningFailed,
    ReceiptVerificationFailed,
    StoreBusy,
    StoreUnavailable,
    RestorePending,
    InvariantFailed,
}

impl AdapterInboxConsumeErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ClockUnavailable => "CLOCK_UNAVAILABLE",
            Self::ClockUnreadable => "CLOCK_UNREADABLE",
            Self::ClockStale => "CLOCK_STALE",
            Self::EpochObserverUnavailable => "EPOCH_OBSERVER_UNAVAILABLE",
            Self::EpochObserverUnreadable => "EPOCH_OBSERVER_UNREADABLE",
            Self::EpochObserverStale => "EPOCH_OBSERVER_STALE",
            Self::AdmissionUnavailable => "ADMISSION_UNAVAILABLE",
            Self::AdmissionUnreadable => "ADMISSION_UNREADABLE",
            Self::EntropyUnavailable => "ENTROPY_UNAVAILABLE",
            Self::SigningProfileMismatch => "SIGNING_PROFILE_MISMATCH",
            Self::SigningFailed => "SIGNING_FAILED",
            Self::ReceiptVerificationFailed => "RECEIPT_VERIFICATION_FAILED",
            Self::StoreBusy => "STORE_BUSY",
            Self::StoreUnavailable => "STORE_UNAVAILABLE",
            Self::RestorePending => "RESTORE_PENDING",
            Self::InvariantFailed => "INVARIANT_FAILED",
        }
    }
}

impl fmt::Debug for AdapterInboxConsumeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AdapterInboxConsumeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterInboxConsumeErrorV1 {}

impl SqliteDispatchInboxStoreV1 {
    /// Reloads the exact durable `RECEIVED` row, repeats deadline/epoch/PAUSE fencing,
    /// then signs and commits one terminal receipt graph under one immediate writer.
    #[allow(clippy::too_many_arguments)]
    pub fn consume_received_v1<G, C, O, A, E, S, R>(
        &self,
        received: ReceivedInboxGrantV1,
        grant_resolver: &G,
        clock: &C,
        epoch_observer: &O,
        admission_observer: &A,
        entropy: &E,
        signing_profile: &AdapterReceiptSigningProfileV1,
        signer: &S,
        receipt_resolver: &R,
    ) -> Result<AdapterInboxConsumeOutcomeV1, AdapterInboxConsumeErrorV1>
    where
        G: GrantKeyResolver,
        C: AdapterClockV1 + ?Sized,
        O: SupervisorEpochObserverV1 + ?Sized,
        A: AdapterConsumptionAdmissionObserverV1 + ?Sized,
        E: AdapterReceiptEntropyV1 + ?Sized,
        S: ReceiptSigner,
        R: ReceiptKeyResolver,
    {
        let mut opened = self.lock_store().map_err(map_lock_error)?;
        let root_identity =
            Sha256Digest::from_bytes(opened.summary().root_identity.to_attested_bytes());
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        ensure_no_active_global_adapter_corruption_quarantine_v1(&transaction)
            .map_err(map_global_corruption_fence_error_v1)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb034)
            .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;
        let grant = load_verified_received_grant_v1(&transaction, &received, grant_resolver)
            .map_err(map_readback_error)?
            .ok_or(AdapterInboxConsumeErrorV1::InvariantFailed)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb031)
            .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;

        // Terminal state is resolved before clock, epoch, PAUSE, entropy, or signer calls.
        match grant.state {
            RetainedInboxStateV1::Consumed | RetainedInboxStateV1::Refused => {
                let receipt =
                    load_verified_receipt_v1(&transaction, &grant, root_identity, receipt_resolver)
                        .map_err(map_readback_error)?
                        .ok_or(AdapterInboxConsumeErrorV1::InvariantFailed)?;
                transaction.commit().map_err(map_sqlite_error)?;
                return Ok(AdapterInboxConsumeOutcomeV1::RetainedReceipt(receipt));
            }
            RetainedInboxStateV1::Quarantined => {
                transaction.commit().map_err(map_sqlite_error)?;
                return Ok(AdapterInboxConsumeOutcomeV1::Quarantined);
            }
            RetainedInboxStateV1::Received => {}
        }

        let metadata = read_terminal_metadata_v1(&transaction)?;
        if metadata.lifecycle != "ACTIVE" {
            return Err(AdapterInboxConsumeErrorV1::RestorePending);
        }
        if metadata.root_identity != root_identity
            || metadata.receipt_signer_profile_digest != signing_profile.profile_digest
            || signer.key_id() != signing_profile.key_id()
        {
            return Err(AdapterInboxConsumeErrorV1::SigningProfileMismatch);
        }

        let clock_sample = match clock.observe_time_v1() {
            AdapterClockObservationV1::Current(sample) => sample,
            AdapterClockObservationV1::Unavailable => {
                return Err(AdapterInboxConsumeErrorV1::ClockUnavailable)
            }
            AdapterClockObservationV1::Unreadable => {
                return Err(AdapterInboxConsumeErrorV1::ClockUnreadable)
            }
            AdapterClockObservationV1::Stale => return Err(AdapterInboxConsumeErrorV1::ClockStale),
        };
        let claims = grant.evidence.claims();
        if clock_sample.boot_id() != claims.boot_id() {
            return Err(AdapterInboxConsumeErrorV1::ClockStale);
        }

        let epoch = match epoch_observer.observe_supervisor_epoch_v1() {
            SupervisorEpochObservationV1::Current(observation) => observation,
            SupervisorEpochObservationV1::Unavailable => {
                return Err(AdapterInboxConsumeErrorV1::EpochObserverUnavailable)
            }
            SupervisorEpochObservationV1::Unreadable => {
                return Err(AdapterInboxConsumeErrorV1::EpochObserverUnreadable)
            }
            SupervisorEpochObservationV1::Stale => {
                return Err(AdapterInboxConsumeErrorV1::EpochObserverStale)
            }
        };
        if epoch.boot_id() != claims.boot_id()
            || !epoch.time_sample().is_coherent_successor_of(&clock_sample)
            || epoch.observer_generation()
                <= grant
                    .epoch_observer_generation
                    .max(metadata.epoch_observer_generation)
            || epoch.supervisor_epoch() < metadata.supervisor_epoch
        {
            return Err(AdapterInboxConsumeErrorV1::EpochObserverStale);
        }
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb032)
            .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;

        let admission = match admission_observer.observe_consumption_admission_v1() {
            AdapterConsumptionAdmissionObservationV1::Running => TerminalAdmissionV1::Running,
            AdapterConsumptionAdmissionObservationV1::Paused => TerminalAdmissionV1::Paused,
            AdapterConsumptionAdmissionObservationV1::Unavailable => {
                return Err(AdapterInboxConsumeErrorV1::AdmissionUnavailable)
            }
            AdapterConsumptionAdmissionObservationV1::Unreadable => {
                return Err(AdapterInboxConsumeErrorV1::AdmissionUnreadable)
            }
        };
        let decision = if epoch.supervisor_epoch() != claims.supervisor_epoch() {
            TerminalDecisionV1::Refused(ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch)
        } else if epoch.observed_at_monotonic_ms() >= claims.deadline_monotonic_ms() {
            TerminalDecisionV1::Refused(ExecutionReceiptRefusalCodeV1::GrantExpired)
        } else if admission == TerminalAdmissionV1::Paused {
            TerminalDecisionV1::Refused(ExecutionReceiptRefusalCodeV1::AdapterPaused)
        } else {
            TerminalDecisionV1::Consumed
        };

        let decision_generation = next_generation(metadata.store_generation)?;
        let receipt_generation = next_generation(decision_generation)?;
        let event_generation = next_generation(receipt_generation)?;
        let mut receipt_identity = [0_u8; 32];
        entropy
            .fill_receipt_entropy_v1(
                AdapterReceiptEntropyDomainV1::ReceiptIdentity,
                &mut receipt_identity,
            )
            .map_err(|_| AdapterInboxConsumeErrorV1::EntropyUnavailable)?;
        let receipt_id = Sha256Digest::from_bytes(receipt_identity);
        if receipt_identity == [0; 32] || receipt_id == grant.grant_id {
            return Err(AdapterInboxConsumeErrorV1::EntropyUnavailable);
        }
        let event_id = domain_digest(&[
            TERMINAL_EVENT_DOMAIN_V1,
            grant.grant_id.as_bytes(),
            receipt_id.as_bytes(),
            &event_generation.to_be_bytes(),
        ]);
        let trace_id = domain_digest(&[
            RECEIPT_TRACE_DOMAIN_V1,
            receipt_id.as_bytes(),
            event_id.as_bytes(),
        ])
        .to_hex();
        let refusal_code = decision.refusal_code();
        let tombstone = refusal_code.map(|code| {
            domain_digest(&[
                REFUSAL_TOMBSTONE_DOMAIN_V1,
                root_identity.as_bytes(),
                grant.grant_id.as_bytes(),
                receipt_refusal_code(code).as_bytes(),
                &decision_generation.to_be_bytes(),
            ])
        });
        let input = ExecutionReceiptInputV1 {
            receipt_id,
            grant_id: grant.grant_id,
            grant_digest: grant.grant_digest,
            operation_id: Identifier::new(grant.operation_id.clone())
                .map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)?,
            destination_adapter_id: Identifier::new(grant.destination_adapter_id.clone())
                .map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)?,
            adapter_root_id: root_identity,
            inbox_generation: generation(grant.received_generation)?,
            consumption_generation: decision
                .is_consumed()
                .then(|| generation(decision_generation))
                .transpose()?,
            refusal_generation: (!decision.is_consumed())
                .then(|| generation(decision_generation))
                .transpose()?,
            receipt_generation: generation(receipt_generation)?,
            observed_boot_id: Identifier::new(epoch.boot_id())
                .map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)?,
            observed_supervisor_epoch: safe_u64(epoch.supervisor_epoch())?,
            epoch_observer_generation: generation(epoch.observer_generation())?,
            decision: decision.contract_decision(),
            refusal_code,
            no_consumption_tombstone_digest: tombstone,
            decided_at_utc_ms: safe_u64(epoch.observed_at_utc_ms())?,
            decided_at_monotonic_ms: safe_u64(epoch.observed_at_monotonic_ms())?,
            trace_id: Identifier::new(trace_id.clone())
                .map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)?,
        };
        let protected = ExecutionReceiptProtectedV1::try_new(
            input,
            Identifier::new(signing_profile.key_id())
                .map_err(|_| AdapterInboxConsumeErrorV1::SigningProfileMismatch)?,
        )
        .map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)?;
        let signed = sign_execution_receipt_v1(protected, signer)
            .map_err(|_| AdapterInboxConsumeErrorV1::SigningFailed)?;
        let receipt_digest = signed.receipt_digest();
        let canonical_receipt = signed
            .to_canonical_json()
            .map_err(|_| AdapterInboxConsumeErrorV1::SigningFailed)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb033)
            .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;
        let verification_bindings = ReceiptVerificationBindingsV1::from_retained_grant_evidence(
            &grant.evidence,
            root_identity,
        );
        let verified = decode_and_verify_execution_receipt_v1(
            &canonical_receipt,
            receipt_resolver,
            &verification_bindings,
        )
        .map_err(|_| AdapterInboxConsumeErrorV1::ReceiptVerificationFailed)?;
        if verified.verification_key_status() != VerificationKeyStatusV1::Current
            || verified.verified_key_fingerprint() != signing_profile.key_fingerprint
            || verified
                .canonical_signed_envelope_bytes()
                .map_err(|_| AdapterInboxConsumeErrorV1::ReceiptVerificationFailed)?
                != canonical_receipt
        {
            return Err(AdapterInboxConsumeErrorV1::ReceiptVerificationFailed);
        }

        persist_terminal_graph_v1(
            self,
            &transaction,
            &metadata,
            &grant,
            decision,
            decision_generation,
            receipt_generation,
            event_generation,
            receipt_id,
            receipt_digest,
            &canonical_receipt,
            signing_profile,
            epoch.supervisor_epoch(),
            epoch.observer_generation(),
            tombstone,
            event_id,
            &trace_id,
            epoch
                .observed_at_monotonic_ms()
                .checked_sub(claims.issued_at_monotonic_ms())
                .ok_or(AdapterInboxConsumeErrorV1::InvariantFailed)?,
        )?;
        transaction.commit().map_err(map_sqlite_error)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb038)
            .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;

        let retained = RetainedAdapterReceiptV1::from_verified_parts_v1(
            canonical_receipt,
            decision.retained_decision(),
            refusal_code,
            tombstone,
            receipt_generation,
        );
        Ok(if decision.is_consumed() {
            AdapterInboxConsumeOutcomeV1::Consumed(retained)
        } else {
            AdapterInboxConsumeOutcomeV1::DefinitelyRefused(retained)
        })
    }
}

fn map_global_corruption_fence_error_v1(
    error: QuarantineStoreErrorV1,
) -> AdapterInboxConsumeErrorV1 {
    match error {
        QuarantineStoreErrorV1::Busy => AdapterInboxConsumeErrorV1::StoreBusy,
        QuarantineStoreErrorV1::Unavailable => AdapterInboxConsumeErrorV1::StoreUnavailable,
        QuarantineStoreErrorV1::RestorePending => AdapterInboxConsumeErrorV1::RestorePending,
        QuarantineStoreErrorV1::InvariantFailed => AdapterInboxConsumeErrorV1::InvariantFailed,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalAdmissionV1 {
    Running,
    Paused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalDecisionV1 {
    Consumed,
    Refused(ExecutionReceiptRefusalCodeV1),
}

impl TerminalDecisionV1 {
    const fn is_consumed(self) -> bool {
        matches!(self, Self::Consumed)
    }

    const fn contract_decision(self) -> ExecutionReceiptDecisionV1 {
        match self {
            Self::Consumed => ExecutionReceiptDecisionV1::Consumed,
            Self::Refused(_) => ExecutionReceiptDecisionV1::RefusedDefinite,
        }
    }

    const fn retained_decision(self) -> AdapterRetainedReceiptDecisionV1 {
        match self {
            Self::Consumed => AdapterRetainedReceiptDecisionV1::Consumed,
            Self::Refused(_) => AdapterRetainedReceiptDecisionV1::RefusedDefinite,
        }
    }

    const fn refusal_code(self) -> Option<ExecutionReceiptRefusalCodeV1> {
        match self {
            Self::Consumed => None,
            Self::Refused(code) => Some(code),
        }
    }

    const fn state(self) -> &'static str {
        match self {
            Self::Consumed => CONSUMED,
            Self::Refused(_) => REFUSED,
        }
    }

    const fn receipt_decision(self) -> &'static str {
        match self {
            Self::Consumed => CONSUMED,
            Self::Refused(_) => REFUSED_DEFINITE,
        }
    }

    const fn event_kind(self) -> &'static str {
        match self {
            Self::Consumed => "GRANT_CONSUMED",
            Self::Refused(_) => "GRANT_REFUSED",
        }
    }
}

const fn receipt_refusal_code(code: ExecutionReceiptRefusalCodeV1) -> &'static str {
    match code {
        ExecutionReceiptRefusalCodeV1::GrantExpired => GRANT_EXPIRED,
        ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch => SUPERVISOR_EPOCH_MISMATCH,
        ExecutionReceiptRefusalCodeV1::AdapterPaused => ADAPTER_PAUSED,
    }
}

struct TerminalMetadataV1 {
    store_generation: u64,
    root_identity: Sha256Digest,
    lifecycle: String,
    supervisor_epoch: u64,
    epoch_observer_generation: u64,
    receipt_signer_profile_digest: Sha256Digest,
}

impl fmt::Debug for TerminalMetadataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalMetadataV1")
            .finish_non_exhaustive()
    }
}

fn read_terminal_metadata_v1(
    transaction: &Transaction<'_>,
) -> Result<TerminalMetadataV1, AdapterInboxConsumeErrorV1> {
    let raw: (i64, Vec<u8>, String, i64, i64, Vec<u8>) = transaction
        .query_row(
            "SELECT store_generation, root_identity, root_lifecycle_state,
                    supervisor_epoch, epoch_observer_generation,
                    receipt_signer_profile_digest
             FROM adapter_store_meta WHERE singleton = 1",
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
        .map_err(map_sqlite_error)?;
    Ok(TerminalMetadataV1 {
        store_generation: strict_safe_integer(raw.0)?,
        root_identity: exact_digest(&raw.1)?,
        lifecycle: raw.2,
        supervisor_epoch: strict_safe_integer(raw.3)?,
        epoch_observer_generation: strict_generation(raw.4)?,
        receipt_signer_profile_digest: exact_digest(&raw.5)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn persist_terminal_graph_v1(
    store: &SqliteDispatchInboxStoreV1,
    transaction: &Transaction<'_>,
    metadata: &TerminalMetadataV1,
    grant: &crate::readback::VerifiedRetainedGrantRowV1,
    decision: TerminalDecisionV1,
    decision_generation: u64,
    receipt_generation: u64,
    event_generation: u64,
    receipt_id: Sha256Digest,
    receipt_digest: Sha256Digest,
    canonical_receipt: &[u8],
    signing_profile: &AdapterReceiptSigningProfileV1,
    observed_supervisor_epoch: u64,
    epoch_observer_generation: u64,
    tombstone: Option<Sha256Digest>,
    event_id: Sha256Digest,
    trace_id: &str,
    latency_ms: u64,
) -> Result<(), AdapterInboxConsumeErrorV1> {
    #[cfg(not(feature = "test-fault-injection"))]
    let _ = store;

    let changed = transaction
        .execute(
            "UPDATE adapter_store_meta
             SET store_generation = ?1, consumption_generation = ?2,
                 receipt_generation = ?3, event_generation = ?1,
                 supervisor_epoch = ?4, epoch_observer_generation = ?5
             WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
               AND store_generation = ?6 AND root_identity = ?7
               AND receipt_signer_profile_digest = ?8",
            params![
                to_i64(event_generation)?,
                to_i64(decision_generation)?,
                to_i64(receipt_generation)?,
                to_i64(observed_supervisor_epoch)?,
                to_i64(epoch_observer_generation)?,
                to_i64(metadata.store_generation)?,
                metadata.root_identity.as_bytes().as_slice(),
                signing_profile.profile_digest.as_bytes().as_slice(),
            ],
        )
        .map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(AdapterInboxConsumeErrorV1::InvariantFailed);
    }

    transaction
        .execute(
            "INSERT INTO execution_receipts (
                receipt_id, grant_id, operation_id, dispatch_attempt_id,
                receipt_digest, canonical_receipt, canonical_receipt_length,
                adapter_key_id, adapter_key_fingerprint, decision, refusal_code,
                no_consumption_tombstone_digest, receipt_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                receipt_id.as_bytes().as_slice(),
                grant.grant_id.as_bytes().as_slice(),
                grant.operation_id,
                grant.dispatch_attempt_id.as_bytes().as_slice(),
                receipt_digest.as_bytes().as_slice(),
                canonical_receipt,
                to_i64(canonical_receipt.len() as u64)?,
                signing_profile.key_id(),
                signing_profile.key_fingerprint.as_bytes().as_slice(),
                decision.receipt_decision(),
                decision.refusal_code().map(receipt_refusal_code),
                tombstone.map(|digest| digest.as_bytes().to_vec()),
                to_i64(receipt_generation)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    #[cfg(feature = "test-fault-injection")]
    store
        .reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb036)
        .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;
    let updated = transaction
        .execute(
            "UPDATE grant_inbox
             SET inbox_state = ?1, current_generation = ?2,
                 receipt_id = ?3, receipt_decision = ?4, current_event_id = ?5
             WHERE grant_id = ?6 AND operation_id = ?7
               AND dispatch_attempt_id = ?8 AND inbox_state = 'RECEIVED'
               AND received_generation = ?9 AND current_generation = ?9
               AND receipt_id IS NULL AND receipt_decision IS NULL",
            params![
                decision.state(),
                to_i64(decision_generation)?,
                receipt_id.as_bytes().as_slice(),
                decision.receipt_decision(),
                event_id.as_bytes().as_slice(),
                grant.grant_id.as_bytes().as_slice(),
                grant.operation_id,
                grant.dispatch_attempt_id.as_bytes().as_slice(),
                to_i64(grant.received_generation)?,
            ],
        )
        .map_err(map_sqlite_error)?;
    if updated != 1 {
        return Err(AdapterInboxConsumeErrorV1::InvariantFailed);
    }
    let evidence_digest = domain_digest(&[
        TERMINAL_EVIDENCE_DOMAIN_V1,
        grant.grant_digest.as_bytes(),
        receipt_digest.as_bytes(),
        &decision_generation.to_be_bytes(),
    ]);
    transaction
        .execute(
            "INSERT INTO inbox_transitions (
                transition_generation, previous_transition_generation, grant_id,
                operation_id, previous_state, new_state, event_id,
                evidence_digest, receipt_id, receipt_decision
             ) VALUES (?1, ?2, ?3, ?4, 'RECEIVED', ?5, ?6, ?7, ?8, ?9)",
            params![
                to_i64(decision_generation)?,
                to_i64(grant.received_generation)?,
                grant.grant_id.as_bytes().as_slice(),
                grant.operation_id,
                decision.state(),
                event_id.as_bytes().as_slice(),
                evidence_digest.as_bytes().as_slice(),
                receipt_id.as_bytes().as_slice(),
                decision.receipt_decision(),
            ],
        )
        .map_err(map_sqlite_error)?;
    #[cfg(feature = "test-fault-injection")]
    store
        .reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb035)
        .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;
    append_terminal_adapter_event_v1(
        transaction,
        &TerminalAdapterEventV1 {
            event_id,
            event_generation,
            transition_generation: decision_generation,
            grant_id: grant.grant_id,
            operation_id: &grant.operation_id,
            dispatch_attempt_id: grant.dispatch_attempt_id,
            task_id: &grant.task_id,
            workload_id: &grant.workload_id,
            plan_id: grant.plan_id,
            task_lease_digest: grant.task_lease_digest,
            effective_state: decision.state(),
            decision: decision.receipt_decision(),
            latency_ms,
            event_kind: decision.event_kind(),
            public_reason_code: decision.refusal_code().map(receipt_refusal_code),
            public_trace_id: trace_id,
        },
    )
    .map_err(map_sqlite_error)?;
    #[cfg(feature = "test-fault-injection")]
    store
        .reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb037)
        .map_err(|_| AdapterInboxConsumeErrorV1::StoreUnavailable)?;
    Ok(())
}

fn generation(value: u64) -> Result<Generation, AdapterInboxConsumeErrorV1> {
    Generation::new(value).map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)
}

fn safe_u64(value: u64) -> Result<SafeU64, AdapterInboxConsumeErrorV1> {
    SafeU64::new(value).map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)
}

fn next_generation(value: u64) -> Result<u64, AdapterInboxConsumeErrorV1> {
    value
        .checked_add(1)
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(AdapterInboxConsumeErrorV1::InvariantFailed)
}

fn exact_digest(bytes: &[u8]) -> Result<Sha256Digest, AdapterInboxConsumeErrorV1> {
    let exact: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)?;
    Ok(Sha256Digest::from_bytes(exact))
}

fn strict_safe_integer(value: i64) -> Result<u64, AdapterInboxConsumeErrorV1> {
    let value = u64::try_from(value).map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)?;
    (value <= MAX_SAFE_U64)
        .then_some(value)
        .ok_or(AdapterInboxConsumeErrorV1::InvariantFailed)
}

fn strict_generation(value: i64) -> Result<u64, AdapterInboxConsumeErrorV1> {
    let value = strict_safe_integer(value)?;
    (value > 0)
        .then_some(value)
        .ok_or(AdapterInboxConsumeErrorV1::InvariantFailed)
}

fn to_i64(value: u64) -> Result<i64, AdapterInboxConsumeErrorV1> {
    i64::try_from(value).map_err(|_| AdapterInboxConsumeErrorV1::InvariantFailed)
}

fn domain_digest(parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn map_lock_error(_error: AdapterInboxReceiveErrorV1) -> AdapterInboxConsumeErrorV1 {
    AdapterInboxConsumeErrorV1::StoreUnavailable
}

fn map_readback_error(error: AdapterInboxReadbackErrorV1) -> AdapterInboxConsumeErrorV1 {
    match error {
        AdapterInboxReadbackErrorV1::StoreBusy => AdapterInboxConsumeErrorV1::StoreBusy,
        AdapterInboxReadbackErrorV1::StoreUnavailable => {
            AdapterInboxConsumeErrorV1::StoreUnavailable
        }
        AdapterInboxReadbackErrorV1::ReceiptUnverifiable => {
            AdapterInboxConsumeErrorV1::ReceiptVerificationFailed
        }
        AdapterInboxReadbackErrorV1::GrantUnverifiable
        | AdapterInboxReadbackErrorV1::InvariantFailed => {
            AdapterInboxConsumeErrorV1::InvariantFailed
        }
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> AdapterInboxConsumeErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked
            ) =>
        {
            AdapterInboxConsumeErrorV1::StoreBusy
        }
        rusqlite::Error::SqliteFailure(_, _) => AdapterInboxConsumeErrorV1::StoreUnavailable,
        _ => AdapterInboxConsumeErrorV1::InvariantFailed,
    }
}
