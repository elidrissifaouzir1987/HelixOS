//! Canonical current-grant validation and durable `ABSENT -> RECEIVED` custody.

#![allow(dead_code)]

use crate::clock::{
    observe_deadline_v1, AdapterClockV1, AdapterDeadlineOutcomeV1, AdapterDeadlineV1,
};
use crate::config::{AdapterInboxInitializationV1, AdapterInboxStoreConfigV1};
use crate::connection::{
    initialize_empty, open_existing, AdapterInboxStoreOpenErrorV1, OpenedAdapterInboxStoreV1,
};
use crate::epoch::{
    observe_expected_epoch_v1, EpochObservationV1, EpochValidationOutcomeV1,
    SupervisorEpochObserverV1,
};
use crate::quarantine::{
    ensure_no_active_global_adapter_corruption_quarantine_v1, retain_binding_conflict_v1,
    retain_pre_received_refusal_v1, ConflictEvidenceInputV1, QuarantineStoreErrorV1,
};
use crate::readback::{
    load_verified_grant_by_id_v1, AdapterInboxReadbackErrorV1, RetainedInboxStateV1,
};
#[cfg(feature = "test-fault-injection")]
use crate::test_fault::{
    AdapterDispatchFaultProbeV1, AdapterDispatchFaultReachedV1, FaultBoundaryV1,
};
use helix_dispatch_contracts::{
    decode_and_verify_execution_grant_v1, decode_and_verify_retained_execution_grant_v1,
    ContractError, Generation, GrantKeyResolver, Identifier, RetainedExecutionGrantEvidenceV1,
    SafeU64, Sha256Digest, VerificationKeyStatusV1, MAX_SAFE_U64,
};
#[cfg(feature = "test-fault-injection")]
use helix_plan_dispatch::{FaultInjectionModeV1, FaultSelectionErrorV1};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

pub const ADAPTER_ORDINARY_QUEUE_CAPACITY_V1: u64 = 1024;

const RECEIVE_EVENT_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_RECEIVE_EVENT_V1\0";
const RECEIVE_EVIDENCE_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_RECEIVE_EVIDENCE_V1\0";
const BINDING_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_INBOX_BINDING_V1\0";
const BINDING_SET_DOMAIN_V1: &[u8] = b"HELIXOS_ADAPTER_INBOX_BINDING_SET_V1\0";
const INVALID_GRANT_REASON_V1: &str = "INVALID_GRANT";
const HISTORICAL_NOT_RETAINED_REASON_V1: &str = "HISTORICAL_NOT_RETAINED";

/// Provisioner-owned adapter destination/protocol/capability profile.
///
/// It is bounded and redacted, carries no signing material, and is retained by one store
/// instance so individual deliveries cannot silently substitute a different profile.
pub struct AdapterInboxProfileV1 {
    destination_adapter_id: Identifier,
    protocol_version: u8,
    adapter_capability_digest: Sha256Digest,
}

impl AdapterInboxProfileV1 {
    pub fn try_new(
        destination_adapter_id: impl Into<String>,
        protocol_version: u8,
        adapter_capability_digest: Sha256Digest,
    ) -> Result<Self, AdapterInboxProfileErrorV1> {
        let destination_adapter_id = Identifier::new(destination_adapter_id)
            .map_err(|_| AdapterInboxProfileErrorV1::InvalidDestination)?;
        if protocol_version != 1 {
            return Err(AdapterInboxProfileErrorV1::InvalidProtocol);
        }
        Ok(Self {
            destination_adapter_id,
            protocol_version,
            adapter_capability_digest,
        })
    }
}

impl fmt::Debug for AdapterInboxProfileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInboxProfileV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterInboxProfileErrorV1 {
    InvalidDestination,
    InvalidProtocol,
}

impl AdapterInboxProfileErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidDestination => "INVALID_DESTINATION",
            Self::InvalidProtocol => "INVALID_PROTOCOL",
        }
    }
}

impl fmt::Debug for AdapterInboxProfileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AdapterInboxProfileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterInboxProfileErrorV1 {}

/// Independent SQLite adapter store. It contains no resolver, clock, observer, signer or
/// host-effect implementation; those trusted dependencies remain injected per operation.
pub struct SqliteDispatchInboxStoreV1 {
    opened: Mutex<OpenedAdapterInboxStoreV1>,
    profile: AdapterInboxProfileV1,
    #[cfg(feature = "test-fault-injection")]
    fault_probe: AdapterDispatchFaultProbeV1,
}

impl SqliteDispatchInboxStoreV1 {
    pub fn initialize_empty_v1(
        config: AdapterInboxStoreConfigV1,
        initial: AdapterInboxInitializationV1,
        profile: AdapterInboxProfileV1,
    ) -> Result<Self, AdapterInboxStoreOpenErrorV1> {
        Ok(Self {
            opened: Mutex::new(initialize_empty(config, initial)?),
            profile,
            #[cfg(feature = "test-fault-injection")]
            fault_probe: AdapterDispatchFaultProbeV1::disabled_v1(),
        })
    }

    pub fn open_existing_v1(
        config: AdapterInboxStoreConfigV1,
        profile: AdapterInboxProfileV1,
    ) -> Result<Self, AdapterInboxStoreOpenErrorV1> {
        Ok(Self {
            opened: Mutex::new(open_existing(config)?),
            profile,
            #[cfg(feature = "test-fault-injection")]
            fault_probe: AdapterDispatchFaultProbeV1::disabled_v1(),
        })
    }

    /// Selects one private adapter checkpoint on this explicit store instance.
    ///
    /// This non-default test seam owns no ambient selector. Both modes are installed
    /// through the same portable probe and reach the same production call sites.
    #[doc(hidden)]
    #[cfg(feature = "test-fault-injection")]
    pub fn select_fault_probe_for_test_v1<F>(
        &mut self,
        boundary_id: &str,
        occurrence: u64,
        mode: FaultInjectionModeV1,
        process_barrier: F,
    ) -> Result<(), FaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        self.fault_probe = AdapterDispatchFaultProbeV1::select_id_v1(
            boundary_id,
            occurrence,
            mode,
            process_barrier,
        )?;
        Ok(())
    }

    /// Reports only whether the explicit feature-gated store probe injected once.
    #[doc(hidden)]
    #[cfg(feature = "test-fault-injection")]
    pub fn fault_probe_injected_for_test_v1(&self) -> bool {
        self.fault_probe.injected_v1()
    }

    /// Validates current canonical authority, classifies exact duplicates/conflicts, then
    /// commits one all-or-none SQLite `ABSENT -> RECEIVED` transaction before returning.
    pub fn receive_grant_v1<R, C, O>(
        &self,
        canonical_grant: &[u8],
        resolver: &R,
        clock: &C,
        epoch_observer: &O,
    ) -> Result<AdapterInboxReceiveOutcomeV1, AdapterInboxReceiveErrorV1>
    where
        R: GrantKeyResolver,
        C: AdapterClockV1 + ?Sized,
        O: SupervisorEpochObserverV1 + ?Sized,
    {
        {
            let opened = self.lock_store()?;
            ensure_no_active_global_adapter_corruption_quarantine_v1(opened.connection())
                .map_err(map_quarantine_error)?;
        }
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb023)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;

        let authentic = match decode_and_verify_execution_grant_v1(canonical_grant, resolver) {
            Ok(authentic) => authentic,
            Err(ContractError::HistoricalKeyNotAuthority) => {
                // Historical authority can classify only exact evidence that this inbox already
                // retained. The current decoder has already rejected it as execution authority;
                // decode the evidence form only on this exceptional path instead of verifying
                // every current grant twice.
                let retained = match decode_and_verify_retained_execution_grant_v1(
                    canonical_grant,
                    resolver,
                ) {
                    Ok(retained)
                        if retained.verification_key_status()
                            == VerificationKeyStatusV1::Historical =>
                    {
                        retained
                    }
                    Ok(retained) => {
                        self.retain_wire_quarantine(
                            canonical_grant,
                            Some(retained.claims().grant_id()),
                            INVALID_GRANT_REASON_V1,
                        )?;
                        return Err(AdapterInboxReceiveErrorV1::InvalidGrant);
                    }
                    Err(_) => {
                        self.retain_wire_quarantine(
                            canonical_grant,
                            None,
                            INVALID_GRANT_REASON_V1,
                        )?;
                        return Err(AdapterInboxReceiveErrorV1::InvalidGrant);
                    }
                };
                let exact_wire = match retained.canonical_signed_envelope_bytes() {
                    Ok(exact_wire) if exact_wire.as_slice() == canonical_grant => exact_wire,
                    Ok(_) | Err(_) => {
                        self.retain_wire_quarantine(
                            canonical_grant,
                            Some(retained.claims().grant_id()),
                            INVALID_GRANT_REASON_V1,
                        )?;
                        return Err(AdapterInboxReceiveErrorV1::InvalidGrant);
                    }
                };
                if let Some(duplicate) =
                    self.preflight_exact_duplicate(&retained, &exact_wire, resolver)?
                {
                    return Ok(AdapterInboxReceiveOutcomeV1::ExactDuplicate(duplicate));
                }
                self.retain_wire_quarantine(
                    canonical_grant,
                    Some(retained.claims().grant_id()),
                    HISTORICAL_NOT_RETAINED_REASON_V1,
                )?;
                return Err(AdapterInboxReceiveErrorV1::InvalidGrant);
            }
            Err(ContractError::UnsupportedProtocol) => {
                return self.retain_wire_pre_received_refusal(
                    canonical_grant,
                    AdapterPreReceiveRefusalV1::ProtocolUnsupported,
                );
            }
            Err(_) => {
                self.retain_wire_quarantine(canonical_grant, None, INVALID_GRANT_REASON_V1)?;
                return Err(AdapterInboxReceiveErrorV1::InvalidGrant);
            }
        };
        let exact_wire = authentic
            .canonical_signed_envelope_bytes()
            .map_err(map_contract_error)?;
        if exact_wire.as_slice() != canonical_grant {
            self.retain_wire_quarantine(
                canonical_grant,
                Some(authentic.claims().grant_id()),
                INVALID_GRANT_REASON_V1,
            )?;
            return Err(AdapterInboxReceiveErrorV1::InvalidGrant);
        }
        let candidate = ReceiveCandidateV1::from_authentic(&authentic, exact_wire)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb024)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;

        let prior_metadata = {
            let mut opened = self.lock_store()?;
            let transaction = opened
                .connection_mut()
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_sqlite_error)?;
            ensure_no_active_global_adapter_corruption_quarantine_v1(&transaction)
                .map_err(map_quarantine_error)?;
            match classify_collision(&transaction, &candidate)? {
                CollisionClassV1::Exact(duplicate) => {
                    transaction.rollback().map_err(map_sqlite_error)?;
                    return Ok(AdapterInboxReceiveOutcomeV1::ExactDuplicate(duplicate));
                }
                CollisionClassV1::Conflict(retained_binding_digest) => {
                    let conflict =
                        retain_conflict(&transaction, &candidate, retained_binding_digest)?;
                    transaction.commit().map_err(map_sqlite_error)?;
                    return Ok(AdapterInboxReceiveOutcomeV1::Conflict(conflict));
                }
                CollisionClassV1::Absent => {
                    let metadata = read_metadata_snapshot(&transaction)?;
                    transaction.rollback().map_err(map_sqlite_error)?;
                    metadata
                }
            }
        };

        if candidate.destination_adapter_id != self.profile.destination_adapter_id.as_str() {
            return self.retain_pre_received_refusal(
                &candidate,
                AdapterPreReceiveRefusalV1::DestinationMismatch,
            );
        }
        if candidate.protocol_version != self.profile.protocol_version {
            return self.retain_pre_received_refusal(
                &candidate,
                AdapterPreReceiveRefusalV1::ProtocolUnsupported,
            );
        }
        if candidate.adapter_capability_digest != self.profile.adapter_capability_digest {
            return self.retain_pre_received_refusal(
                &candidate,
                AdapterPreReceiveRefusalV1::CapabilityMismatch,
            );
        }

        let deadline = AdapterDeadlineV1::new(
            Identifier::new(candidate.boot_id.clone())
                .map_err(|_| AdapterInboxReceiveErrorV1::InvalidGrant)?,
            Generation::new(candidate.deadline_monotonic_ms)
                .map_err(|_| AdapterInboxReceiveErrorV1::InvalidGrant)?,
        );
        let current_deadline = match observe_deadline_v1(clock, &deadline) {
            AdapterDeadlineOutcomeV1::Current(current) => current,
            AdapterDeadlineOutcomeV1::Reached => {
                return Err(AdapterInboxReceiveErrorV1::DeadlineReached)
            }
            AdapterDeadlineOutcomeV1::Unavailable => {
                return Err(AdapterInboxReceiveErrorV1::ClockUnavailable)
            }
            AdapterDeadlineOutcomeV1::Unreadable => {
                return Err(AdapterInboxReceiveErrorV1::ClockUnreadable)
            }
            AdapterDeadlineOutcomeV1::Stale => return Err(AdapterInboxReceiveErrorV1::ClockStale),
        };
        if !capability_is_current(&candidate, current_deadline.sample().sampled_at_utc_ms()) {
            return self.retain_pre_received_refusal(
                &candidate,
                AdapterPreReceiveRefusalV1::CapabilityMismatch,
            );
        }

        let expected_epoch = SafeU64::new(candidate.supervisor_epoch)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvalidGrant)?;
        let prior_observer_generation = Generation::new(prior_metadata.epoch_observer_generation)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        let epoch_observation = match observe_expected_epoch_v1(
            epoch_observer,
            &candidate.boot_id,
            expected_epoch,
            Some(prior_observer_generation),
        ) {
            EpochValidationOutcomeV1::Current(observation) => observation,
            EpochValidationOutcomeV1::Mismatch(_) => {
                return Err(AdapterInboxReceiveErrorV1::SupervisorEpochMismatch)
            }
            EpochValidationOutcomeV1::Unavailable => {
                return Err(AdapterInboxReceiveErrorV1::EpochObserverUnavailable)
            }
            EpochValidationOutcomeV1::Unreadable => {
                return Err(AdapterInboxReceiveErrorV1::EpochObserverUnreadable)
            }
            EpochValidationOutcomeV1::Stale => {
                return Err(AdapterInboxReceiveErrorV1::EpochObserverStale)
            }
        };
        if !epoch_observation
            .time_sample()
            .is_coherent_successor_of(current_deadline.sample())
            || epoch_observation.observed_at_monotonic_ms() >= candidate.deadline_monotonic_ms
        {
            return Err(AdapterInboxReceiveErrorV1::EpochObserverStale);
        }
        if !capability_is_current(&candidate, epoch_observation.observed_at_utc_ms()) {
            return self.retain_pre_received_refusal(
                &candidate,
                AdapterPreReceiveRefusalV1::CapabilityMismatch,
            );
        }

        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb025)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;

        self.commit_received(candidate, epoch_observation)
    }

    fn preflight_exact_duplicate<R: GrantKeyResolver>(
        &self,
        retained: &RetainedExecutionGrantEvidenceV1,
        exact_wire: &[u8],
        resolver: &R,
    ) -> Result<Option<AdapterInboxExactDuplicateV1>, AdapterInboxReceiveErrorV1> {
        let mut opened = self.lock_store()?;
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        ensure_no_active_global_adapter_corruption_quarantine_v1(&transaction)
            .map_err(map_quarantine_error)?;
        let duplicate = classify_retained_duplicate(&transaction, retained, exact_wire, resolver)?;
        transaction.rollback().map_err(map_sqlite_error)?;
        Ok(duplicate)
    }

    fn retain_wire_quarantine(
        &self,
        wire: &[u8],
        grant_id: Option<Sha256Digest>,
        public_reason_code: &str,
    ) -> Result<(), AdapterInboxReceiveErrorV1> {
        let mut opened = self.lock_store()?;
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        ensure_no_active_global_adapter_corruption_quarantine_v1(&transaction)
            .map_err(map_quarantine_error)?;
        retain_pre_received_refusal_v1(
            &transaction,
            grant_id,
            Sha256Digest::digest(wire),
            public_reason_code,
        )
        .map_err(map_quarantine_error)?;
        transaction.commit().map_err(map_sqlite_error)
    }

    fn retain_wire_pre_received_refusal(
        &self,
        wire: &[u8],
        reason: AdapterPreReceiveRefusalV1,
    ) -> Result<AdapterInboxReceiveOutcomeV1, AdapterInboxReceiveErrorV1> {
        let mut opened = self.lock_store()?;
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        ensure_no_active_global_adapter_corruption_quarantine_v1(&transaction)
            .map_err(map_quarantine_error)?;
        let retained = retain_pre_received_refusal_v1(
            &transaction,
            None,
            Sha256Digest::digest(wire),
            reason.code(),
        )
        .map_err(map_quarantine_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(AdapterInboxReceiveOutcomeV1::PreReceivedRefusal(
            AdapterPreReceivedRefusalEvidenceV1 {
                reason,
                quarantine_generation: retained.generation,
            },
        ))
    }

    fn retain_pre_received_refusal(
        &self,
        candidate: &ReceiveCandidateV1,
        reason: AdapterPreReceiveRefusalV1,
    ) -> Result<AdapterInboxReceiveOutcomeV1, AdapterInboxReceiveErrorV1> {
        let mut opened = self.lock_store()?;
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        ensure_no_active_global_adapter_corruption_quarantine_v1(&transaction)
            .map_err(map_quarantine_error)?;
        let retained = retain_pre_received_refusal_v1(
            &transaction,
            Some(candidate.grant_id),
            candidate.grant_digest,
            reason.code(),
        )
        .map_err(map_quarantine_error)?;
        transaction.commit().map_err(map_sqlite_error)?;
        Ok(AdapterInboxReceiveOutcomeV1::PreReceivedRefusal(
            AdapterPreReceivedRefusalEvidenceV1 {
                reason,
                quarantine_generation: retained.generation,
            },
        ))
    }

    fn commit_received(
        &self,
        candidate: ReceiveCandidateV1,
        epoch_observation: EpochObservationV1,
    ) -> Result<AdapterInboxReceiveOutcomeV1, AdapterInboxReceiveErrorV1> {
        let mut opened = self.lock_store()?;
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sqlite_error)?;
        ensure_no_active_global_adapter_corruption_quarantine_v1(&transaction)
            .map_err(map_quarantine_error)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb026)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;
        match classify_collision(&transaction, &candidate)? {
            CollisionClassV1::Exact(duplicate) => {
                transaction.rollback().map_err(map_sqlite_error)?;
                return Ok(AdapterInboxReceiveOutcomeV1::ExactDuplicate(duplicate));
            }
            CollisionClassV1::Conflict(retained_binding_digest) => {
                let conflict = retain_conflict(&transaction, &candidate, retained_binding_digest)?;
                transaction.commit().map_err(map_sqlite_error)?;
                return Ok(AdapterInboxReceiveOutcomeV1::Conflict(conflict));
            }
            CollisionClassV1::Absent => {}
        }

        let metadata = read_metadata_snapshot(&transaction)?;
        if metadata.lifecycle != "ACTIVE" {
            return Err(AdapterInboxReceiveErrorV1::RestorePending);
        }
        if epoch_observation.observer_generation() <= metadata.epoch_observer_generation
            || epoch_observation.supervisor_epoch() < metadata.supervisor_epoch
        {
            return Err(AdapterInboxReceiveErrorV1::EpochObserverStale);
        }
        let pending_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM grant_inbox WHERE inbox_state = 'RECEIVED'",
                [],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)?;
        if pending_count < 0 {
            return Err(AdapterInboxReceiveErrorV1::InvariantFailed);
        }
        if pending_count as u64 >= ADAPTER_ORDINARY_QUEUE_CAPACITY_V1 {
            let retained = retain_pre_received_refusal_v1(
                &transaction,
                Some(candidate.grant_id),
                candidate.grant_digest,
                AdapterPreReceiveRefusalV1::InboxCapacityExhausted.code(),
            )
            .map_err(map_quarantine_error)?;
            transaction.commit().map_err(map_sqlite_error)?;
            return Ok(AdapterInboxReceiveOutcomeV1::PreReceivedRefusal(
                AdapterPreReceivedRefusalEvidenceV1 {
                    reason: AdapterPreReceiveRefusalV1::InboxCapacityExhausted,
                    quarantine_generation: retained.generation,
                },
            ));
        }

        let generation = metadata
            .store_generation
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(AdapterInboxReceiveErrorV1::InvariantFailed)?;
        let event_id = domain_digest(&[
            RECEIVE_EVENT_DOMAIN_V1,
            candidate.grant_id.as_bytes(),
            &generation.to_be_bytes(),
        ]);
        let evidence_digest = domain_digest(&[
            RECEIVE_EVIDENCE_DOMAIN_V1,
            candidate.grant_digest.as_bytes(),
            &epoch_observation.supervisor_epoch().to_be_bytes(),
            &epoch_observation.observer_generation().to_be_bytes(),
        ]);
        let changed = transaction
            .execute(
                "UPDATE adapter_store_meta
                 SET store_generation = ?1, inbox_generation = ?1,
                     event_generation = ?1, supervisor_epoch = ?2,
                     epoch_observer_generation = ?3
                 WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
                   AND store_generation = ?4",
                params![
                    to_i64(generation)?,
                    to_i64(epoch_observation.supervisor_epoch())?,
                    to_i64(epoch_observation.observer_generation())?,
                    to_i64(metadata.store_generation)?,
                ],
            )
            .map_err(map_sqlite_error)?;
        if changed != 1 {
            return Err(AdapterInboxReceiveErrorV1::InvariantFailed);
        }

        transaction
            .execute(
                "INSERT INTO grant_inbox (
                    grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                    workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                    canonical_grant, canonical_grant_length,
                    coordinator_key_fingerprint, destination_adapter_id,
                    protocol_version, observed_supervisor_epoch,
                    epoch_observer_generation, inbox_state, received_generation,
                    current_generation, receipt_id, receipt_decision, current_event_id
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16, 'RECEIVED', ?17, ?17, NULL, NULL, ?18
                 )",
                params![
                    candidate.grant_id.as_bytes().as_slice(),
                    candidate.operation_id,
                    candidate.dispatch_attempt_id.as_bytes().as_slice(),
                    candidate.plan_id.as_bytes().as_slice(),
                    candidate.task_id,
                    candidate.workload_id,
                    candidate.task_lease_digest.as_bytes().as_slice(),
                    candidate.one_shot_nonce.as_bytes().as_slice(),
                    candidate.grant_digest.as_bytes().as_slice(),
                    candidate.canonical_grant,
                    to_i64(candidate.canonical_grant_length)?,
                    candidate.coordinator_key_fingerprint.as_bytes().as_slice(),
                    candidate.destination_adapter_id,
                    i64::from(candidate.protocol_version),
                    to_i64(epoch_observation.supervisor_epoch())?,
                    to_i64(epoch_observation.observer_generation())?,
                    to_i64(generation)?,
                    event_id.as_bytes().as_slice(),
                ],
            )
            .map_err(map_sqlite_error)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb027)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;
        transaction
            .execute(
                "INSERT INTO inbox_transitions (
                    transition_generation, previous_transition_generation, grant_id,
                    operation_id, previous_state, new_state, event_id,
                    evidence_digest, receipt_id, receipt_decision
                 ) VALUES (?1, NULL, ?2, ?3, 'ABSENT', 'RECEIVED', ?4, ?5, NULL, NULL)",
                params![
                    to_i64(generation)?,
                    candidate.grant_id.as_bytes().as_slice(),
                    candidate.operation_id,
                    event_id.as_bytes().as_slice(),
                    evidence_digest.as_bytes().as_slice(),
                ],
            )
            .map_err(map_sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO adapter_events (
                    event_id, event_generation, transition_generation, grant_id,
                    operation_id, dispatch_attempt_id, task_id, workload_id, plan_id,
                    task_lease_digest, event_contract_version, grant_contract_version,
                    receipt_contract_version, effective_state, decision, latency_ms,
                    event_kind, public_reason_code, public_trace_id, delivery_state,
                    delivered_generation
                 ) VALUES (
                    ?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    1, 1, 0, 'RECEIVED', 'RECEIVED', 0,
                    'GRANT_RECEIVED', NULL, ?10, 'PENDING', NULL
                 )",
                params![
                    event_id.as_bytes().as_slice(),
                    to_i64(generation)?,
                    candidate.grant_id.as_bytes().as_slice(),
                    candidate.operation_id,
                    candidate.dispatch_attempt_id.as_bytes().as_slice(),
                    candidate.task_id,
                    candidate.workload_id,
                    candidate.plan_id.as_bytes().as_slice(),
                    candidate.task_lease_digest.as_bytes().as_slice(),
                    event_id.to_hex(),
                ],
            )
            .map_err(map_sqlite_error)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb028)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb029)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;
        transaction.commit().map_err(map_sqlite_error)?;
        #[cfg(feature = "test-fault-injection")]
        self.reach_adapter_fault_v1(FaultBoundaryV1::Plan005Fb030)
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)?;

        let operation_id = Identifier::new(candidate.operation_id)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        let expected_boot_id = Identifier::new(candidate.boot_id)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        Ok(AdapterInboxReceiveOutcomeV1::Received(
            ReceivedInboxGrantV1 {
                grant_id: candidate.grant_id,
                operation_id,
                dispatch_attempt_id: candidate.dispatch_attempt_id,
                received_generation: generation,
                expected_boot_id,
                observed_supervisor_epoch: epoch_observation.supervisor_epoch(),
                epoch_observer_generation: epoch_observation.observer_generation(),
                deadline_monotonic_ms: candidate.deadline_monotonic_ms,
            },
        ))
    }

    pub(crate) fn lock_store(
        &self,
    ) -> Result<MutexGuard<'_, OpenedAdapterInboxStoreV1>, AdapterInboxReceiveErrorV1> {
        self.opened
            .lock()
            .map_err(|_| AdapterInboxReceiveErrorV1::StoreUnavailable)
    }

    #[cfg(feature = "test-fault-injection")]
    pub(crate) fn reach_adapter_fault_v1(
        &self,
        boundary: FaultBoundaryV1,
    ) -> Result<(), AdapterDispatchFaultReachedV1> {
        self.fault_probe.checkpoint_v1(boundary)
    }
}

impl fmt::Debug for SqliteDispatchInboxStoreV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteDispatchInboxStoreV1")
            .finish_non_exhaustive()
    }
}

/// Opaque durable receive evidence. It is intentionally non-Clone and non-Serde, and it
/// contains no execution/effect handle.
pub struct ReceivedInboxGrantV1 {
    grant_id: Sha256Digest,
    operation_id: Identifier,
    dispatch_attempt_id: Sha256Digest,
    received_generation: u64,
    expected_boot_id: Identifier,
    observed_supervisor_epoch: u64,
    epoch_observer_generation: u64,
    deadline_monotonic_ms: u64,
}

impl ReceivedInboxGrantV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_retained_parts_v1(
        grant_id: Sha256Digest,
        operation_id: &str,
        dispatch_attempt_id: Sha256Digest,
        received_generation: u64,
        expected_boot_id: &str,
        observed_supervisor_epoch: u64,
        epoch_observer_generation: u64,
        deadline_monotonic_ms: u64,
    ) -> Result<Self, AdapterInboxReceiveErrorV1> {
        let operation_id = Identifier::new(operation_id)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        let expected_boot_id = Identifier::new(expected_boot_id)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        Generation::new(received_generation)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        SafeU64::new(observed_supervisor_epoch)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        Generation::new(epoch_observer_generation)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        Generation::new(deadline_monotonic_ms)
            .map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
        Ok(Self {
            grant_id,
            operation_id,
            dispatch_attempt_id,
            received_generation,
            expected_boot_id,
            observed_supervisor_epoch,
            epoch_observer_generation,
            deadline_monotonic_ms,
        })
    }

    pub(crate) const fn grant_id(&self) -> Sha256Digest {
        self.grant_id
    }

    pub(crate) fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }

    pub(crate) const fn dispatch_attempt_id(&self) -> Sha256Digest {
        self.dispatch_attempt_id
    }

    pub(crate) const fn received_generation(&self) -> u64 {
        self.received_generation
    }

    pub(crate) fn expected_boot_id(&self) -> &str {
        self.expected_boot_id.as_str()
    }

    pub(crate) const fn observed_supervisor_epoch(&self) -> u64 {
        self.observed_supervisor_epoch
    }

    pub(crate) const fn epoch_observer_generation(&self) -> u64 {
        self.epoch_observer_generation
    }

    pub(crate) const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms
    }
}

impl fmt::Debug for ReceivedInboxGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedInboxGrantV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterInboxRetainedStateV1 {
    Received,
    Consumed,
    Refused,
    Quarantined,
}

/// Digest-only exact duplicate evidence.
///
/// Terminal receipt bytes remain available only through the independently verified T050
/// readback boundary; this fast path never promotes raw SQLite bytes into receipt evidence.
pub struct AdapterInboxExactDuplicateV1 {
    grant_id: Sha256Digest,
    state: AdapterInboxRetainedStateV1,
    receipt_retained: bool,
}

impl AdapterInboxExactDuplicateV1 {
    pub(crate) const fn grant_id(&self) -> Sha256Digest {
        self.grant_id
    }

    pub const fn state(&self) -> AdapterInboxRetainedStateV1 {
        self.state
    }

    pub const fn receipt_retained(&self) -> bool {
        self.receipt_retained
    }
}

impl fmt::Debug for AdapterInboxExactDuplicateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInboxExactDuplicateV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterPreReceiveRefusalV1 {
    DestinationMismatch,
    ProtocolUnsupported,
    CapabilityMismatch,
    InboxCapacityExhausted,
}

impl AdapterPreReceiveRefusalV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::DestinationMismatch => "DESTINATION_MISMATCH",
            Self::ProtocolUnsupported => "PROTOCOL_UNSUPPORTED",
            Self::CapabilityMismatch => "CAPABILITY_MISMATCH",
            Self::InboxCapacityExhausted => "INBOX_CAPACITY_EXHAUSTED",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterPreReceivedRefusalEvidenceV1 {
    reason: AdapterPreReceiveRefusalV1,
    quarantine_generation: u64,
}

impl AdapterPreReceivedRefusalEvidenceV1 {
    pub const fn reason(&self) -> AdapterPreReceiveRefusalV1 {
        self.reason
    }

    pub const fn quarantine_generation(&self) -> u64 {
        self.quarantine_generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterInboxConflictEvidenceV1 {
    conflict_generation: u64,
}

impl AdapterInboxConflictEvidenceV1 {
    pub const fn conflict_generation(&self) -> u64 {
        self.conflict_generation
    }
}

pub enum AdapterInboxReceiveOutcomeV1 {
    Received(ReceivedInboxGrantV1),
    ExactDuplicate(AdapterInboxExactDuplicateV1),
    PreReceivedRefusal(AdapterPreReceivedRefusalEvidenceV1),
    Conflict(AdapterInboxConflictEvidenceV1),
}

impl fmt::Debug for AdapterInboxReceiveOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Received(_) => formatter.write_str("AdapterInboxReceiveOutcomeV1::Received(..)"),
            Self::ExactDuplicate(_) => {
                formatter.write_str("AdapterInboxReceiveOutcomeV1::ExactDuplicate(..)")
            }
            Self::PreReceivedRefusal(_) => {
                formatter.write_str("AdapterInboxReceiveOutcomeV1::PreReceivedRefusal(..)")
            }
            Self::Conflict(_) => formatter.write_str("AdapterInboxReceiveOutcomeV1::Conflict(..)"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdapterInboxReceiveErrorV1 {
    InvalidGrant,
    ClockUnavailable,
    ClockUnreadable,
    ClockStale,
    DeadlineReached,
    EpochObserverUnavailable,
    EpochObserverUnreadable,
    EpochObserverStale,
    SupervisorEpochMismatch,
    StoreBusy,
    StoreUnavailable,
    RestorePending,
    InvariantFailed,
}

impl AdapterInboxReceiveErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidGrant => "INVALID_GRANT",
            Self::ClockUnavailable => "CLOCK_UNAVAILABLE",
            Self::ClockUnreadable => "CLOCK_UNREADABLE",
            Self::ClockStale => "CLOCK_STALE",
            Self::DeadlineReached => "DEADLINE_REACHED",
            Self::EpochObserverUnavailable => "EPOCH_OBSERVER_UNAVAILABLE",
            Self::EpochObserverUnreadable => "EPOCH_OBSERVER_UNREADABLE",
            Self::EpochObserverStale => "EPOCH_OBSERVER_STALE",
            Self::SupervisorEpochMismatch => "SUPERVISOR_EPOCH_MISMATCH",
            Self::StoreBusy => "STORE_BUSY",
            Self::StoreUnavailable => "STORE_UNAVAILABLE",
            Self::RestorePending => "RESTORE_PENDING",
            Self::InvariantFailed => "INVARIANT_FAILED",
        }
    }
}

impl fmt::Debug for AdapterInboxReceiveErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AdapterInboxReceiveErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterInboxReceiveErrorV1 {}

struct ReceiveCandidateV1 {
    grant_id: Sha256Digest,
    operation_id: String,
    dispatch_attempt_id: Sha256Digest,
    plan_id: Sha256Digest,
    task_id: String,
    workload_id: String,
    task_lease_digest: Sha256Digest,
    one_shot_nonce: Sha256Digest,
    grant_digest: Sha256Digest,
    canonical_grant: Vec<u8>,
    canonical_grant_length: u64,
    coordinator_key_fingerprint: Sha256Digest,
    destination_adapter_id: String,
    protocol_version: u8,
    supervisor_epoch: u64,
    boot_id: String,
    deadline_monotonic_ms: u64,
    capability_observed_at_utc_ms: u64,
    capability_max_age_ms: u64,
    adapter_capability_digest: Sha256Digest,
}

impl ReceiveCandidateV1 {
    fn from_authentic(
        authentic: &helix_dispatch_contracts::AuthenticExecutionGrantV1,
        canonical_grant: Vec<u8>,
    ) -> Result<Self, AdapterInboxReceiveErrorV1> {
        let claims = authentic.claims();
        let canonical_grant_length = u64::try_from(canonical_grant.len())
            .ok()
            .filter(|length| (1..=1_048_576).contains(length))
            .ok_or(AdapterInboxReceiveErrorV1::InvalidGrant)?;
        Ok(Self {
            grant_id: claims.grant_id(),
            operation_id: claims.operation_id().to_owned(),
            dispatch_attempt_id: claims.dispatch_attempt_id(),
            plan_id: claims.plan_id(),
            task_id: claims.task_id().to_owned(),
            workload_id: claims.workload_id().to_owned(),
            task_lease_digest: claims.lease_digest(),
            one_shot_nonce: claims.one_shot_nonce(),
            grant_digest: claims.grant_digest(),
            canonical_grant,
            canonical_grant_length,
            coordinator_key_fingerprint: authentic.verified_key_fingerprint(),
            destination_adapter_id: claims.destination_adapter_id().to_owned(),
            protocol_version: claims.protocol_version(),
            supervisor_epoch: claims.supervisor_epoch(),
            boot_id: claims.boot_id().to_owned(),
            deadline_monotonic_ms: claims.deadline_monotonic_ms(),
            capability_observed_at_utc_ms: claims.capability_observed_at_utc_ms(),
            capability_max_age_ms: claims.capability_max_age_ms(),
            adapter_capability_digest: claims.adapter_capability_digest(),
        })
    }

    fn binding_digest(&self) -> Sha256Digest {
        domain_digest(&[
            BINDING_DOMAIN_V1,
            self.grant_id.as_bytes(),
            self.operation_id.as_bytes(),
            self.dispatch_attempt_id.as_bytes(),
            self.one_shot_nonce.as_bytes(),
            self.grant_digest.as_bytes(),
            self.coordinator_key_fingerprint.as_bytes(),
            &self.canonical_grant,
        ])
    }
}

struct RetainedGrantRowV1 {
    grant_id: Vec<u8>,
    operation_id: String,
    dispatch_attempt_id: Vec<u8>,
    plan_id: Vec<u8>,
    task_id: String,
    workload_id: String,
    task_lease_digest: Vec<u8>,
    one_shot_nonce: Vec<u8>,
    grant_digest: Vec<u8>,
    canonical_grant: Vec<u8>,
    coordinator_key_fingerprint: Vec<u8>,
    destination_adapter_id: String,
    protocol_version: i64,
    inbox_state: String,
    receipt_id: Option<Vec<u8>>,
}

impl RetainedGrantRowV1 {
    fn exactly_matches(&self, candidate: &ReceiveCandidateV1) -> bool {
        self.grant_id.as_slice() == candidate.grant_id.as_bytes()
            && self.operation_id == candidate.operation_id
            && self.dispatch_attempt_id.as_slice() == candidate.dispatch_attempt_id.as_bytes()
            && self.plan_id.as_slice() == candidate.plan_id.as_bytes()
            && self.task_id == candidate.task_id
            && self.workload_id == candidate.workload_id
            && self.task_lease_digest.as_slice() == candidate.task_lease_digest.as_bytes()
            && self.one_shot_nonce.as_slice() == candidate.one_shot_nonce.as_bytes()
            && self.grant_digest.as_slice() == candidate.grant_digest.as_bytes()
            && self.canonical_grant == candidate.canonical_grant
            && self.coordinator_key_fingerprint.as_slice()
                == candidate.coordinator_key_fingerprint.as_bytes()
            && self.destination_adapter_id == candidate.destination_adapter_id
            && self.protocol_version == i64::from(candidate.protocol_version)
    }

    fn binding_digest(&self) -> Sha256Digest {
        domain_digest(&[
            BINDING_DOMAIN_V1,
            &self.grant_id,
            self.operation_id.as_bytes(),
            &self.dispatch_attempt_id,
            &self.one_shot_nonce,
            &self.grant_digest,
            &self.coordinator_key_fingerprint,
            &self.canonical_grant,
        ])
    }
}

enum CollisionClassV1 {
    Absent,
    Exact(AdapterInboxExactDuplicateV1),
    Conflict(Sha256Digest),
}

struct MetadataSnapshotV1 {
    store_generation: u64,
    supervisor_epoch: u64,
    epoch_observer_generation: u64,
    lifecycle: String,
}

fn classify_retained_duplicate<R: GrantKeyResolver>(
    transaction: &Transaction<'_>,
    retained: &RetainedExecutionGrantEvidenceV1,
    exact_wire: &[u8],
    resolver: &R,
) -> Result<Option<AdapterInboxExactDuplicateV1>, AdapterInboxReceiveErrorV1> {
    let claims = retained.claims();
    let Some(row) = load_verified_grant_by_id_v1(transaction, claims.grant_id(), resolver)
        .map_err(map_readback_error)?
    else {
        return Ok(None);
    };
    let verified_wire = row
        .evidence
        .canonical_signed_envelope_bytes()
        .map_err(map_contract_error)?;
    if verified_wire != exact_wire
        || row.evidence.verified_key_fingerprint() != retained.verified_key_fingerprint()
    {
        return Ok(None);
    }
    let inbox_state = match row.state {
        RetainedInboxStateV1::Received => "RECEIVED",
        RetainedInboxStateV1::Consumed => "CONSUMED",
        RetainedInboxStateV1::Refused => "REFUSED",
        RetainedInboxStateV1::Quarantined => "QUARANTINED",
    };
    let receipt_id = row.receipt_id.map(|value| *value.as_bytes());
    read_exact_duplicate(
        transaction,
        claims.grant_id(),
        inbox_state,
        receipt_id.as_ref().map(<[u8; 32]>::as_slice),
    )
    .map(Some)
}

fn read_exact_duplicate(
    transaction: &Transaction<'_>,
    grant_id: Sha256Digest,
    inbox_state: &str,
    receipt_id: Option<&[u8]>,
) -> Result<AdapterInboxExactDuplicateV1, AdapterInboxReceiveErrorV1> {
    let state = match inbox_state {
        "RECEIVED" => AdapterInboxRetainedStateV1::Received,
        "CONSUMED" => AdapterInboxRetainedStateV1::Consumed,
        "REFUSED" => AdapterInboxRetainedStateV1::Refused,
        "QUARANTINED" => AdapterInboxRetainedStateV1::Quarantined,
        _ => return Err(AdapterInboxReceiveErrorV1::InvariantFailed),
    };
    let receipt_decision = match receipt_id {
        Some(receipt_id) => transaction
            .query_row(
                "SELECT decision FROM execution_receipts
                 WHERE receipt_id = ?1 AND grant_id = ?2",
                params![receipt_id, grant_id.as_bytes().as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_sqlite_error)?
            .ok_or(AdapterInboxReceiveErrorV1::InvariantFailed)
            .map(Some)?,
        None => None,
    };
    let receipt_matches_state = matches!(
        (state, receipt_decision.as_deref()),
        (AdapterInboxRetainedStateV1::Consumed, Some("CONSUMED"))
            | (
                AdapterInboxRetainedStateV1::Refused,
                Some("REFUSED_DEFINITE")
            )
            | (AdapterInboxRetainedStateV1::Received, None)
            | (AdapterInboxRetainedStateV1::Quarantined, None)
    );
    if !receipt_matches_state {
        return Err(AdapterInboxReceiveErrorV1::InvariantFailed);
    }
    Ok(AdapterInboxExactDuplicateV1 {
        grant_id,
        state,
        receipt_retained: receipt_decision.is_some(),
    })
}

fn classify_collision(
    transaction: &Transaction<'_>,
    candidate: &ReceiveCandidateV1,
) -> Result<CollisionClassV1, AdapterInboxReceiveErrorV1> {
    let mut statement = transaction
        .prepare(
            "SELECT grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                    workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                    canonical_grant, coordinator_key_fingerprint,
                    destination_adapter_id, protocol_version, inbox_state, receipt_id
             FROM grant_inbox
             WHERE grant_id = ?1 OR operation_id = ?2 OR one_shot_nonce = ?3
                OR grant_digest = ?4 OR dispatch_attempt_id = ?5
             ORDER BY received_generation",
        )
        .map_err(map_sqlite_error)?;
    let retained = statement
        .query_map(
            params![
                candidate.grant_id.as_bytes().as_slice(),
                candidate.operation_id,
                candidate.one_shot_nonce.as_bytes().as_slice(),
                candidate.grant_digest.as_bytes().as_slice(),
                candidate.dispatch_attempt_id.as_bytes().as_slice(),
            ],
            |row| {
                Ok(RetainedGrantRowV1 {
                    grant_id: row.get(0)?,
                    operation_id: row.get(1)?,
                    dispatch_attempt_id: row.get(2)?,
                    plan_id: row.get(3)?,
                    task_id: row.get(4)?,
                    workload_id: row.get(5)?,
                    task_lease_digest: row.get(6)?,
                    one_shot_nonce: row.get(7)?,
                    grant_digest: row.get(8)?,
                    canonical_grant: row.get(9)?,
                    coordinator_key_fingerprint: row.get(10)?,
                    destination_adapter_id: row.get(11)?,
                    protocol_version: row.get(12)?,
                    inbox_state: row.get(13)?,
                    receipt_id: row.get(14)?,
                })
            },
        )
        .map_err(map_sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sqlite_error)?;
    if retained.is_empty() {
        return Ok(CollisionClassV1::Absent);
    }
    if retained.len() == 1 && retained[0].exactly_matches(candidate) {
        return read_exact_duplicate(
            transaction,
            candidate.grant_id,
            &retained[0].inbox_state,
            retained[0].receipt_id.as_deref(),
        )
        .map(CollisionClassV1::Exact);
    }
    Ok(CollisionClassV1::Conflict(
        aggregate_retained_binding_digest(&retained)?,
    ))
}

fn aggregate_retained_binding_digest(
    retained: &[RetainedGrantRowV1],
) -> Result<Sha256Digest, AdapterInboxReceiveErrorV1> {
    let retained_count =
        u64::try_from(retained.len()).map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)?;
    let mut hasher = Sha256::new();
    hasher.update(BINDING_SET_DOMAIN_V1);
    hasher.update(retained_count.to_be_bytes());
    for row in retained {
        hasher.update(row.binding_digest().as_bytes());
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn retain_conflict(
    transaction: &Transaction<'_>,
    candidate: &ReceiveCandidateV1,
    retained_binding_digest: Sha256Digest,
) -> Result<AdapterInboxConflictEvidenceV1, AdapterInboxReceiveErrorV1> {
    let retained = retain_binding_conflict_v1(
        transaction,
        &ConflictEvidenceInputV1 {
            observed_grant_id: candidate.grant_id,
            operation_id: &candidate.operation_id,
            one_shot_nonce: candidate.one_shot_nonce,
            retained_binding_digest,
            conflicting_binding_digest: candidate.binding_digest(),
        },
    )
    .map_err(map_quarantine_error)?;
    Ok(AdapterInboxConflictEvidenceV1 {
        conflict_generation: retained.generation,
    })
}

fn read_metadata_snapshot(
    transaction: &Transaction<'_>,
) -> Result<MetadataSnapshotV1, AdapterInboxReceiveErrorV1> {
    let (store_generation, supervisor_epoch, epoch_observer_generation, lifecycle): (
        i64,
        i64,
        i64,
        String,
    ) = transaction
        .query_row(
            "SELECT store_generation, supervisor_epoch, epoch_observer_generation,
                    root_lifecycle_state
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(map_sqlite_error)?;
    Ok(MetadataSnapshotV1 {
        store_generation: strict_safe_integer(store_generation)?,
        supervisor_epoch: strict_safe_integer(supervisor_epoch)?,
        epoch_observer_generation: strict_generation(epoch_observer_generation)?,
        lifecycle,
    })
}

fn capability_is_current(candidate: &ReceiveCandidateV1, observed_utc_ms: u64) -> bool {
    observed_utc_ms
        .checked_sub(candidate.capability_observed_at_utc_ms)
        .is_some_and(|age| age <= candidate.capability_max_age_ms)
}

fn map_contract_error(_error: ContractError) -> AdapterInboxReceiveErrorV1 {
    AdapterInboxReceiveErrorV1::InvalidGrant
}

fn map_readback_error(error: AdapterInboxReadbackErrorV1) -> AdapterInboxReceiveErrorV1 {
    match error {
        AdapterInboxReadbackErrorV1::StoreBusy => AdapterInboxReceiveErrorV1::StoreBusy,
        AdapterInboxReadbackErrorV1::StoreUnavailable => {
            AdapterInboxReceiveErrorV1::StoreUnavailable
        }
        AdapterInboxReadbackErrorV1::GrantUnverifiable
        | AdapterInboxReadbackErrorV1::ReceiptUnverifiable
        | AdapterInboxReadbackErrorV1::InvariantFailed => {
            AdapterInboxReceiveErrorV1::InvariantFailed
        }
    }
}

fn map_quarantine_error(error: QuarantineStoreErrorV1) -> AdapterInboxReceiveErrorV1 {
    match error {
        QuarantineStoreErrorV1::Busy => AdapterInboxReceiveErrorV1::StoreBusy,
        QuarantineStoreErrorV1::Unavailable => AdapterInboxReceiveErrorV1::StoreUnavailable,
        QuarantineStoreErrorV1::RestorePending => AdapterInboxReceiveErrorV1::RestorePending,
        QuarantineStoreErrorV1::InvariantFailed => AdapterInboxReceiveErrorV1::InvariantFailed,
    }
}

fn map_sqlite_error(error: rusqlite::Error) -> AdapterInboxReceiveErrorV1 {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy
                    | rusqlite::ErrorCode::DatabaseLocked
                    | rusqlite::ErrorCode::SchemaChanged
                    | rusqlite::ErrorCode::FileLockingProtocolFailed
            ) =>
        {
            AdapterInboxReceiveErrorV1::StoreBusy
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            AdapterInboxReceiveErrorV1::InvariantFailed
        }
        _ => AdapterInboxReceiveErrorV1::StoreUnavailable,
    }
}

fn strict_safe_integer(value: i64) -> Result<u64, AdapterInboxReceiveErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(AdapterInboxReceiveErrorV1::InvariantFailed)
}

fn strict_generation(value: i64) -> Result<u64, AdapterInboxReceiveErrorV1> {
    strict_safe_integer(value).and_then(|value| {
        (value > 0)
            .then_some(value)
            .ok_or(AdapterInboxReceiveErrorV1::InvariantFailed)
    })
}

fn to_i64(value: u64) -> Result<i64, AdapterInboxReceiveErrorV1> {
    i64::try_from(value).map_err(|_| AdapterInboxReceiveErrorV1::InvariantFailed)
}

fn domain_digest(parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{AdapterClockObservationV1, AdapterTimeSampleV1};
    use crate::config::AdapterInboxRootIdentityEvidenceV1;
    use crate::epoch::SupervisorEpochObservationV1;
    use ed25519_dalek::{Signer as _, SigningKey};
    use helix_dispatch_contracts::{
        sign_execution_grant_v1, ContractError, ExecutionGrantProtectedV1, GrantSigner,
        GrantVerificationKeyV1, Result as ContractResult,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
    const FIXTURE_GRANT_KEY: [u8; 32] = [
        167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246,
        103, 165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
    ];
    const FIXTURE_CAPABILITY_DIGEST: &str =
        "7bd116b849df045678b6521d504056fe77119b19a0eadb84d661878e6d5f667b";
    const COLLISION_TEST_KEY_ID: &str = "collision-test-grant-key-v1";
    static NEXT_TEMPORARY_ROOT: AtomicU64 = AtomicU64::new(1);

    struct FixtureGrantResolverV1;

    impl GrantKeyResolver for FixtureGrantResolverV1 {
        fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
            if key_id == "fixture-grant-key-v1" {
                Ok(GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY))
            } else {
                Err(ContractError::UnknownKey)
            }
        }
    }

    struct CountingCurrentGrantResolverV1(AtomicU64);

    impl CountingCurrentGrantResolverV1 {
        const fn new() -> Self {
            Self(AtomicU64::new(0))
        }

        fn calls(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl GrantKeyResolver for CountingCurrentGrantResolverV1 {
        fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if key_id == "fixture-grant-key-v1" {
                Ok(GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY))
            } else {
                Err(ContractError::UnknownKey)
            }
        }
    }

    struct HistoricalFixtureGrantResolverV1;

    impl GrantKeyResolver for HistoricalFixtureGrantResolverV1 {
        fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
            if key_id == "fixture-grant-key-v1" {
                Ok(GrantVerificationKeyV1::historical(FIXTURE_GRANT_KEY))
            } else {
                Err(ContractError::UnknownKey)
            }
        }
    }

    struct CollisionGrantAuthorityV1(SigningKey);

    impl CollisionGrantAuthorityV1 {
        fn new() -> Self {
            Self(SigningKey::from_bytes(&[0x47; 32]))
        }
    }

    impl GrantSigner for CollisionGrantAuthorityV1 {
        fn key_id(&self) -> &str {
            COLLISION_TEST_KEY_ID
        }

        fn sign_execution_grant(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
            Ok(self.0.sign(message).to_bytes())
        }
    }

    impl GrantKeyResolver for CollisionGrantAuthorityV1 {
        fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
            match key_id {
                "fixture-grant-key-v1" => Ok(GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY)),
                COLLISION_TEST_KEY_ID => Ok(GrantVerificationKeyV1::current(
                    self.0.verifying_key().to_bytes(),
                )),
                _ => Err(ContractError::UnknownKey),
            }
        }
    }

    struct FixedClockV1 {
        clock_generation: u64,
        sampled_at_utc_ms: u64,
        sampled_at_monotonic_ms: u64,
    }

    impl AdapterClockV1 for FixedClockV1 {
        fn observe_time_v1(&self) -> AdapterClockObservationV1 {
            AdapterClockObservationV1::Current(time_sample(
                self.clock_generation,
                self.sampled_at_utc_ms,
                self.sampled_at_monotonic_ms,
            ))
        }
    }

    struct FixedEpochObserverV1 {
        supervisor_epoch: u64,
        observer_generation: u64,
        time_sample: AdapterTimeSampleV1,
    }

    impl SupervisorEpochObserverV1 for FixedEpochObserverV1 {
        fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
            SupervisorEpochObservationV1::Current(EpochObservationV1::new(
                SafeU64::new(self.supervisor_epoch).expect("fixture epoch is bounded"),
                Generation::new(self.observer_generation)
                    .expect("fixture observer generation is positive"),
                time_sample(
                    self.time_sample.clock_generation(),
                    self.time_sample.sampled_at_utc_ms(),
                    self.time_sample.sampled_at_monotonic_ms(),
                ),
            ))
        }
    }

    struct UnavailableClockV1;

    impl AdapterClockV1 for UnavailableClockV1 {
        fn observe_time_v1(&self) -> AdapterClockObservationV1 {
            AdapterClockObservationV1::Unavailable
        }
    }

    struct UnavailableEpochObserverV1;

    impl SupervisorEpochObserverV1 for UnavailableEpochObserverV1 {
        fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
            SupervisorEpochObservationV1::Unavailable
        }
    }

    struct TemporaryRootV1(PathBuf);

    impl TemporaryRootV1 {
        fn new(label: &str) -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock follows epoch")
                .as_nanos();
            let sequence = NEXT_TEMPORARY_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "helix-dispatch-inbox-{label}-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("temporary adapter root creates");
            Self(path)
        }
    }

    impl Drop for TemporaryRootV1 {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn canonical_fixture_grant() -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(CASES).expect("reviewed fixture corpus decodes");
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"])
            .expect("reviewed grant fixture canonicalizes")
    }

    fn sign_synthetic_fixture_protected(mut protected: serde_json::Value) -> Vec<u8> {
        protected["key_id"] = serde_json::Value::String(COLLISION_TEST_KEY_ID.to_owned());
        let protected: ExecutionGrantProtectedV1 =
            serde_json::from_value(protected).expect("synthetic protected grant decodes");
        sign_execution_grant_v1(protected, &CollisionGrantAuthorityV1::new())
            .expect("synthetic grant signs")
            .to_canonical_json()
            .expect("synthetic grant canonicalizes")
    }

    fn signed_destination_collision_grant() -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(CASES).expect("reviewed fixture corpus decodes");
        let mut protected = corpus["base_envelopes"]["grant.valid"]["protected"].clone();
        protected["destination_adapter_id"] =
            serde_json::Value::String("different-adapter-v1".to_owned());
        sign_synthetic_fixture_protected(protected)
    }

    fn signed_capability_boundary_grant() -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(CASES).expect("reviewed fixture corpus decodes");
        let mut protected = corpus["base_envelopes"]["grant.valid"]["protected"].clone();
        protected["capability_observed_at_utc_ms"] = serde_json::Value::from(1_000_100_u64);
        protected["capability_max_age_ms"] = serde_json::Value::from(0_u64);
        sign_synthetic_fixture_protected(protected)
    }

    fn fixture_capability_digest() -> Sha256Digest {
        Sha256Digest::parse_hex(FIXTURE_CAPABILITY_DIGEST)
            .expect("reviewed capability digest parses")
    }

    fn fixture_profile() -> AdapterInboxProfileV1 {
        AdapterInboxProfileV1::try_new("adapter-v1", 1, fixture_capability_digest())
            .expect("fixture profile validates")
    }

    fn time_sample(
        clock_generation: u64,
        sampled_at_utc_ms: u64,
        sampled_at_monotonic_ms: u64,
    ) -> AdapterTimeSampleV1 {
        AdapterTimeSampleV1::new(
            Identifier::new("boot-v1").expect("fixture boot id validates"),
            Generation::new(clock_generation).expect("clock generation is positive"),
            SafeU64::new(sampled_at_utc_ms).expect("UTC sample is bounded"),
            SafeU64::new(sampled_at_monotonic_ms).expect("monotonic sample is bounded"),
        )
    }

    fn current_clock() -> FixedClockV1 {
        FixedClockV1 {
            clock_generation: 2,
            sampled_at_utc_ms: 1_000_100,
            sampled_at_monotonic_ms: 1_100,
        }
    }

    fn current_epoch(observer_generation: u64) -> FixedEpochObserverV1 {
        FixedEpochObserverV1 {
            supervisor_epoch: 15,
            observer_generation,
            time_sample: time_sample(3, 1_000_101, 1_101),
        }
    }

    fn initialize_fixture_store(
        root: &TemporaryRootV1,
        identity: AdapterInboxRootIdentityEvidenceV1,
        profile: AdapterInboxProfileV1,
    ) -> SqliteDispatchInboxStoreV1 {
        let config =
            AdapterInboxStoreConfigV1::try_new_empty_attested(root.0.clone(), identity, 25)
                .expect("empty adapter root is provisioner-attested");
        SqliteDispatchInboxStoreV1::initialize_empty_v1(
            config,
            AdapterInboxInitializationV1::try_new(15, 1, [0x52; 32])
                .expect("fixture initialization validates"),
            profile,
        )
        .expect("fixture store initializes")
    }

    fn reopen_fixture_store(
        root: &TemporaryRootV1,
        identity: AdapterInboxRootIdentityEvidenceV1,
        profile: AdapterInboxProfileV1,
    ) -> SqliteDispatchInboxStoreV1 {
        let config =
            AdapterInboxStoreConfigV1::try_new_existing_attested(root.0.clone(), identity, 25)
                .expect("existing adapter root is provisioner-attested");
        SqliteDispatchInboxStoreV1::open_existing_v1(config, profile)
            .expect("fixture store reopens with full verification")
    }

    fn table_count(store: &SqliteDispatchInboxStoreV1, table: &str) -> i64 {
        let opened = store.opened.lock().expect("test store lock is healthy");
        opened
            .connection()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("test table count reads")
    }

    fn bound_quarantine_count(store: &SqliteDispatchInboxStoreV1, grant_id: Sha256Digest) -> i64 {
        let opened = store.opened.lock().expect("test store lock is healthy");
        opened
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM inbox_quarantines WHERE grant_id = ?1",
                [grant_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("bound quarantine count reads")
    }

    fn fixture_candidate() -> ReceiveCandidateV1 {
        let wire = canonical_fixture_grant();
        let authentic = decode_and_verify_execution_grant_v1(&wire, &FixtureGrantResolverV1)
            .expect("fixture grant authenticates as current");
        ReceiveCandidateV1::from_authentic(&authentic, wire)
            .expect("authentic fixture projects into a receive candidate")
    }

    fn epoch_observation(observer_generation: u64) -> EpochObservationV1 {
        EpochObservationV1::new(
            SafeU64::new(15).expect("fixture epoch is bounded"),
            Generation::new(observer_generation).expect("observer generation is positive"),
            time_sample(3, 1_000_101, 1_101),
        )
    }

    #[derive(Clone, Copy)]
    enum CollisionDimensionV1 {
        Grant,
        Operation,
        Nonce,
        Digest,
        DispatchAttempt,
    }

    fn conflicting_candidate(dimension: CollisionDimensionV1) -> ReceiveCandidateV1 {
        let mut candidate = fixture_candidate();
        let label = match dimension {
            CollisionDimensionV1::Grant => "grant",
            CollisionDimensionV1::Operation => "operation",
            CollisionDimensionV1::Nonce => "nonce",
            CollisionDimensionV1::Digest => "digest",
            CollisionDimensionV1::DispatchAttempt => "dispatch-attempt",
        };
        candidate.grant_id = Sha256Digest::digest(format!("conflict-grant-{label}").as_bytes());
        candidate.operation_id = format!("operation-conflict-{label}");
        candidate.dispatch_attempt_id =
            Sha256Digest::digest(format!("conflict-dispatch-{label}").as_bytes());
        candidate.one_shot_nonce =
            Sha256Digest::digest(format!("conflict-nonce-{label}").as_bytes());
        candidate.grant_digest =
            Sha256Digest::digest(format!("conflict-digest-{label}").as_bytes());
        candidate.canonical_grant.push(label.len() as u8);
        candidate.canonical_grant_length = candidate.canonical_grant.len() as u64;
        match dimension {
            CollisionDimensionV1::Grant => {
                candidate.grant_id = fixture_candidate().grant_id;
            }
            CollisionDimensionV1::Operation => {
                candidate.operation_id = fixture_candidate().operation_id;
            }
            CollisionDimensionV1::Nonce => {
                candidate.one_shot_nonce = fixture_candidate().one_shot_nonce;
            }
            CollisionDimensionV1::Digest => {
                candidate.grant_digest = fixture_candidate().grant_digest;
            }
            CollisionDimensionV1::DispatchAttempt => {
                candidate.dispatch_attempt_id = fixture_candidate().dispatch_attempt_id;
            }
        }
        candidate
    }

    fn refusal_profile(reason: AdapterPreReceiveRefusalV1) -> AdapterInboxProfileV1 {
        match reason {
            AdapterPreReceiveRefusalV1::DestinationMismatch => AdapterInboxProfileV1::try_new(
                "different-adapter-v1",
                1,
                fixture_capability_digest(),
            )
            .expect("mismatching destination profile validates"),
            AdapterPreReceiveRefusalV1::CapabilityMismatch => AdapterInboxProfileV1::try_new(
                "adapter-v1",
                1,
                Sha256Digest::digest(b"different-capability-profile"),
            )
            .expect("mismatching capability profile validates"),
            AdapterPreReceiveRefusalV1::ProtocolUnsupported
            | AdapterPreReceiveRefusalV1::InboxCapacityExhausted => fixture_profile(),
        }
    }

    fn wire_for_refusal(reason: AdapterPreReceiveRefusalV1) -> Vec<u8> {
        let canonical = canonical_fixture_grant();
        if reason != AdapterPreReceiveRefusalV1::ProtocolUnsupported {
            return canonical;
        }
        let mut unsupported: serde_json::Value =
            serde_json::from_slice(&canonical).expect("fixture JSON decodes");
        unsupported["protected"]["protocol_version"] = serde_json::Value::from(2);
        serde_json_canonicalizer::to_vec(&unsupported)
            .expect("unsupported protocol wire canonicalizes")
    }

    fn expect_pre_received_refusal(
        outcome: AdapterInboxReceiveOutcomeV1,
        expected: AdapterPreReceiveRefusalV1,
    ) -> u64 {
        let AdapterInboxReceiveOutcomeV1::PreReceivedRefusal(evidence) = outcome else {
            panic!("validation must stop before RECEIVED");
        };
        assert_eq!(evidence.reason(), expected);
        evidence.quarantine_generation()
    }

    fn fixed_blob(value: u64) -> Vec<u8> {
        format!("{value:032x}").into_bytes()
    }

    fn seed_full_ordinary_lane(store: &SqliteDispatchInboxStoreV1) {
        let mut opened = store.lock_store().expect("test store lock is healthy");
        let transaction = opened
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("capacity seed transaction begins");
        assert_eq!(
            transaction
                .execute(
                    "UPDATE adapter_store_meta
                     SET store_generation = 1024, inbox_generation = 1024,
                         event_generation = 1024, epoch_observer_generation = 1025
                     WHERE singleton = 1 AND store_generation = 0
                       AND root_lifecycle_state = 'ACTIVE'",
                    [],
                )
                .expect("capacity metadata advances"),
            1
        );
        for generation in 1_i64..=1_024 {
            let ordinal = generation as u64;
            let grant_id = fixed_blob(ordinal);
            let dispatch_attempt_id = fixed_blob(ordinal + 2_000);
            let one_shot_nonce = fixed_blob(ordinal + 4_000);
            let grant_digest = fixed_blob(ordinal + 6_000);
            let event_id = fixed_blob(ordinal + 8_000);
            let evidence_digest = fixed_blob(ordinal + 10_000);
            let operation_id = format!("operation:capacity:{ordinal}");
            transaction
                .execute(
                    "INSERT INTO grant_inbox (
                        grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                        workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                        canonical_grant, canonical_grant_length,
                        coordinator_key_fingerprint, destination_adapter_id,
                        protocol_version, observed_supervisor_epoch,
                        epoch_observer_generation, inbox_state, received_generation,
                        current_generation, receipt_id, receipt_decision, current_event_id
                     ) VALUES (
                        ?1, ?2, ?3, ?4, 'task:capacity', 'workload:capacity', ?5,
                        ?6, ?7, x'01', 1, ?8, 'adapter-v1', 1, 15, 1025,
                        'RECEIVED', ?9, ?9, NULL, NULL, ?10
                     )",
                    params![
                        grant_id,
                        operation_id,
                        dispatch_attempt_id,
                        [0x31_u8; 32].as_slice(),
                        [0x32_u8; 32].as_slice(),
                        one_shot_nonce,
                        grant_digest,
                        [0x33_u8; 32].as_slice(),
                        generation,
                        event_id,
                    ],
                )
                .expect("capacity grant row inserts");
            transaction
                .execute(
                    "INSERT INTO inbox_transitions (
                        transition_generation, previous_transition_generation, grant_id,
                        operation_id, previous_state, new_state, event_id,
                        evidence_digest, receipt_id, receipt_decision
                     ) VALUES (?1, NULL, ?2, ?3, 'ABSENT', 'RECEIVED', ?4, ?5, NULL, NULL)",
                    params![
                        generation,
                        grant_id,
                        operation_id,
                        event_id,
                        evidence_digest,
                    ],
                )
                .expect("capacity transition inserts");
            transaction
                .execute(
                    "INSERT INTO adapter_events (
                        event_id, event_generation, transition_generation, grant_id,
                        operation_id, dispatch_attempt_id, task_id, workload_id, plan_id,
                        task_lease_digest, event_contract_version, grant_contract_version,
                        receipt_contract_version, effective_state, decision, latency_ms,
                        event_kind, public_reason_code, public_trace_id, delivery_state,
                        delivered_generation
                     ) VALUES (
                        ?1, ?2, ?2, ?3, ?4, ?5, 'task:capacity', 'workload:capacity',
                        ?6, ?7, 1, 1, 0, 'RECEIVED', 'RECEIVED', 0,
                        'GRANT_RECEIVED', NULL, ?8, 'PENDING', NULL
                     )",
                    params![
                        event_id,
                        generation,
                        grant_id,
                        operation_id,
                        dispatch_attempt_id,
                        [0x31_u8; 32].as_slice(),
                        [0x32_u8; 32].as_slice(),
                        format!("capacity-event-{ordinal}"),
                    ],
                )
                .expect("capacity event inserts");
        }
        transaction
            .commit()
            .expect("capacity seed commits atomically");
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn explicit_store_probe_fails_closed_and_process_mode_uses_the_same_real_reach() {
        for mode in [
            FaultInjectionModeV1::InProcess,
            FaultInjectionModeV1::ProcessKill,
        ] {
            let root = TemporaryRootV1::new("receive-fault-probe");
            let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x60; 32]);
            let mut store = initialize_fixture_store(&root, identity, fixture_profile());
            let callback_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let callback_observation = std::sync::Arc::clone(&callback_count);
            store
                .select_fault_probe_for_test_v1("PLAN005-FB-023", 1, mode, move || {
                    callback_observation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                })
                .expect("explicit adapter boundary selects on the real store");

            let error = store
                .receive_grant_v1(
                    &canonical_fixture_grant(),
                    &FixtureGrantResolverV1,
                    &current_clock(),
                    &current_epoch(2),
                )
                .expect_err("selected real receive checkpoint fails closed");
            assert_eq!(error, AdapterInboxReceiveErrorV1::StoreUnavailable);
            assert!(store.fault_probe_injected_for_test_v1());
            assert_eq!(table_count(&store, "grant_inbox"), 0);
            assert_eq!(
                callback_count.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(mode == FaultInjectionModeV1::ProcessKill)
            );
        }
    }

    #[test]
    fn current_receive_verifies_the_grant_once() {
        let root = TemporaryRootV1::new("single-current-grant-verification");
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x5f; 32]);
        let store = initialize_fixture_store(&root, identity, fixture_profile());
        let resolver = CountingCurrentGrantResolverV1::new();

        let outcome = store
            .receive_grant_v1(
                &canonical_fixture_grant(),
                &resolver,
                &current_clock(),
                &current_epoch(2),
            )
            .expect("one current verification retains the authentic grant");

        assert!(matches!(outcome, AdapterInboxReceiveOutcomeV1::Received(_)));
        assert_eq!(resolver.calls(), 1);
    }

    #[test]
    fn received_projection_survives_reopen_and_exact_retry_does_not_reobserve() {
        let root = TemporaryRootV1::new("receive-reopen");
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x61; 32]);
        let grant = canonical_fixture_grant();
        let store = initialize_fixture_store(&root, identity, fixture_profile());

        let received = store
            .receive_grant_v1(
                &grant,
                &FixtureGrantResolverV1,
                &current_clock(),
                &current_epoch(2),
            )
            .expect("current authentic grant reaches durable inbox");
        let AdapterInboxReceiveOutcomeV1::Received(received) = received else {
            panic!("first authentic delivery must be newly received");
        };
        assert_eq!(received.operation_id(), "operation-v1");
        assert_eq!(received.received_generation(), 1);
        assert_eq!(received.expected_boot_id(), "boot-v1");
        assert_eq!(received.observed_supervisor_epoch(), 15);
        assert_eq!(received.epoch_observer_generation(), 2);
        assert_eq!(received.deadline_monotonic_ms(), 6_000);
        assert_eq!(table_count(&store, "grant_inbox"), 1);
        assert_eq!(table_count(&store, "inbox_transitions"), 1);
        assert_eq!(table_count(&store, "adapter_events"), 1);
        assert_eq!(table_count(&store, "execution_receipts"), 0);

        let current_duplicate = store
            .receive_grant_v1(
                &grant,
                &FixtureGrantResolverV1,
                &UnavailableClockV1,
                &UnavailableEpochObserverV1,
            )
            .expect("current exact retry is classified before renewed authority observation");
        let AdapterInboxReceiveOutcomeV1::ExactDuplicate(current_duplicate) = current_duplicate
        else {
            panic!("current replayed exact bytes must return retained result");
        };
        assert_eq!(
            current_duplicate.state(),
            AdapterInboxRetainedStateV1::Received
        );
        assert_eq!(current_duplicate.grant_id(), received.grant_id());
        assert!(!current_duplicate.receipt_retained());
        assert_eq!(table_count(&store, "grant_inbox"), 1);
        assert_eq!(table_count(&store, "inbox_transitions"), 1);
        assert_eq!(table_count(&store, "adapter_events"), 1);
        assert_eq!(table_count(&store, "execution_receipts"), 0);
        drop(store);

        let reopened = reopen_fixture_store(&root, identity, fixture_profile());
        let duplicate = reopened
            .receive_grant_v1(
                &grant,
                &HistoricalFixtureGrantResolverV1,
                &UnavailableClockV1,
                &UnavailableEpochObserverV1,
            )
            .expect("historical exact retry reads retained state without renewing authority");
        let AdapterInboxReceiveOutcomeV1::ExactDuplicate(duplicate) = duplicate else {
            panic!("replayed exact bytes must return retained result");
        };
        assert_eq!(duplicate.state(), AdapterInboxRetainedStateV1::Received);
        assert_eq!(duplicate.grant_id(), received.grant_id());
        assert!(!duplicate.receipt_retained());
        assert_eq!(table_count(&reopened, "grant_inbox"), 1);
        assert_eq!(table_count(&reopened, "inbox_transitions"), 1);
        assert_eq!(table_count(&reopened, "adapter_events"), 1);
        assert_eq!(table_count(&reopened, "execution_receipts"), 0);
    }

    #[test]
    fn invalid_and_unretained_historical_wires_are_durably_quarantined() {
        assert_eq!(
            AdapterInboxProfileV1::try_new("adapter-v1", 2, fixture_capability_digest())
                .expect_err("only frozen protocol v1 is provisionable"),
            AdapterInboxProfileErrorV1::InvalidProtocol
        );
        let root = TemporaryRootV1::new("invalid-wire-quarantine");
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x63; 32]);
        let store = initialize_fixture_store(&root, identity, fixture_profile());
        let canonical = canonical_fixture_grant();

        let mut unsupported: serde_json::Value =
            serde_json::from_slice(&canonical).expect("fixture JSON decodes");
        unsupported["protected"]["schema"] =
            serde_json::Value::String("helixos.execution-grant/2".to_owned());
        let unsupported =
            serde_json_canonicalizer::to_vec(&unsupported).expect("unsupported wire canonicalizes");

        let mut unverifiable: serde_json::Value =
            serde_json::from_slice(&canonical).expect("fixture JSON decodes");
        unverifiable["signature"] = serde_json::Value::String("A".repeat(86));
        let unverifiable = serde_json_canonicalizer::to_vec(&unverifiable)
            .expect("unverifiable wire canonicalizes");

        for invalid in [
            b"{".as_slice(),
            unsupported.as_slice(),
            unverifiable.as_slice(),
        ] {
            assert!(matches!(
                store.receive_grant_v1(
                    invalid,
                    &FixtureGrantResolverV1,
                    &UnavailableClockV1,
                    &UnavailableEpochObserverV1,
                ),
                Err(AdapterInboxReceiveErrorV1::InvalidGrant)
            ));
        }
        assert!(matches!(
            store.receive_grant_v1(
                b"{",
                &FixtureGrantResolverV1,
                &UnavailableClockV1,
                &UnavailableEpochObserverV1,
            ),
            Err(AdapterInboxReceiveErrorV1::InvalidGrant)
        ));
        assert!(matches!(
            store.receive_grant_v1(
                &canonical,
                &HistoricalFixtureGrantResolverV1,
                &UnavailableClockV1,
                &UnavailableEpochObserverV1,
            ),
            Err(AdapterInboxReceiveErrorV1::InvalidGrant)
        ));
        assert_eq!(table_count(&store, "inbox_quarantines"), 4);
        assert_eq!(
            bound_quarantine_count(&store, fixture_candidate().grant_id),
            1
        );
        assert_eq!(table_count(&store, "grant_inbox"), 0);
        assert_eq!(table_count(&store, "inbox_transitions"), 0);
        assert_eq!(table_count(&store, "adapter_events"), 0);
        assert_eq!(table_count(&store, "execution_receipts"), 0);
        drop(store);

        let reopened = reopen_fixture_store(&root, identity, fixture_profile());
        assert_eq!(table_count(&reopened, "inbox_quarantines"), 4);
        assert_eq!(table_count(&reopened, "grant_inbox"), 0);
        assert_eq!(table_count(&reopened, "execution_receipts"), 0);
    }

    #[test]
    fn all_four_pre_received_refusals_are_durable_and_receipt_free() {
        for (index, reason) in [
            AdapterPreReceiveRefusalV1::DestinationMismatch,
            AdapterPreReceiveRefusalV1::ProtocolUnsupported,
            AdapterPreReceiveRefusalV1::CapabilityMismatch,
        ]
        .into_iter()
        .enumerate()
        {
            let root = TemporaryRootV1::new(reason.code());
            let identity =
                AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x70 + index as u8; 32]);
            let wire = wire_for_refusal(reason);
            let store = initialize_fixture_store(&root, identity, refusal_profile(reason));
            let generation = expect_pre_received_refusal(
                store
                    .receive_grant_v1(
                        &wire,
                        &FixtureGrantResolverV1,
                        &UnavailableClockV1,
                        &UnavailableEpochObserverV1,
                    )
                    .expect("pre-receive refusal persists"),
                reason,
            );
            assert_eq!(generation, 1);
            assert_eq!(table_count(&store, "inbox_quarantines"), 1);
            assert_eq!(
                bound_quarantine_count(&store, fixture_candidate().grant_id),
                i64::from(reason != AdapterPreReceiveRefusalV1::ProtocolUnsupported)
            );
            assert_eq!(table_count(&store, "grant_inbox"), 0);
            assert_eq!(table_count(&store, "inbox_transitions"), 0);
            assert_eq!(table_count(&store, "adapter_events"), 0);
            assert_eq!(table_count(&store, "execution_receipts"), 0);
            drop(store);

            let reopened = reopen_fixture_store(&root, identity, refusal_profile(reason));
            let repeated_generation = expect_pre_received_refusal(
                reopened
                    .receive_grant_v1(
                        &wire,
                        &FixtureGrantResolverV1,
                        &UnavailableClockV1,
                        &UnavailableEpochObserverV1,
                    )
                    .expect("identical refusal reads retained quarantine"),
                reason,
            );
            assert_eq!(repeated_generation, generation);
            assert_eq!(table_count(&reopened, "inbox_quarantines"), 1);
            assert_eq!(table_count(&reopened, "grant_inbox"), 0);
            assert_eq!(table_count(&reopened, "execution_receipts"), 0);
        }

        let reason = AdapterPreReceiveRefusalV1::InboxCapacityExhausted;
        let root = TemporaryRootV1::new(reason.code());
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x73; 32]);
        let wire = canonical_fixture_grant();
        let store = initialize_fixture_store(&root, identity, fixture_profile());
        seed_full_ordinary_lane(&store);
        let generation = expect_pre_received_refusal(
            store
                .receive_grant_v1(
                    &wire,
                    &FixtureGrantResolverV1,
                    &current_clock(),
                    &current_epoch(1_026),
                )
                .expect("over-capacity delivery retains diagnostic"),
            reason,
        );
        assert_eq!(generation, 1_025);
        assert_eq!(
            bound_quarantine_count(&store, fixture_candidate().grant_id),
            1
        );
        assert_eq!(table_count(&store, "grant_inbox"), 1_024);
        assert_eq!(table_count(&store, "inbox_transitions"), 1_024);
        assert_eq!(table_count(&store, "adapter_events"), 1_024);
        assert_eq!(table_count(&store, "inbox_quarantines"), 1);
        assert_eq!(
            bound_quarantine_count(&store, fixture_candidate().grant_id),
            1
        );
        assert_eq!(table_count(&store, "execution_receipts"), 0);
        drop(store);

        let reopened = reopen_fixture_store(&root, identity, fixture_profile());
        let repeated_generation = expect_pre_received_refusal(
            reopened
                .receive_grant_v1(
                    &wire,
                    &FixtureGrantResolverV1,
                    &current_clock(),
                    &current_epoch(1_026),
                )
                .expect("capacity refusal survives full-store reopen"),
            reason,
        );
        assert_eq!(repeated_generation, generation);
        assert_eq!(table_count(&reopened, "grant_inbox"), 1_024);
        assert_eq!(table_count(&reopened, "inbox_quarantines"), 1);
        assert_eq!(table_count(&reopened, "execution_receipts"), 0);
    }

    #[test]
    fn retained_identity_collision_precedes_destination_profile_refusal() {
        let root = TemporaryRootV1::new("collision-before-profile");
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x74; 32]);
        let authority = CollisionGrantAuthorityV1::new();
        let store = initialize_fixture_store(&root, identity, fixture_profile());
        assert!(matches!(
            store
                .receive_grant_v1(
                    &canonical_fixture_grant(),
                    &authority,
                    &current_clock(),
                    &current_epoch(2),
                )
                .expect("first exact grant is admitted"),
            AdapterInboxReceiveOutcomeV1::Received(_)
        ));

        let outcome = store
            .receive_grant_v1(
                &signed_destination_collision_grant(),
                &authority,
                &UnavailableClockV1,
                &UnavailableEpochObserverV1,
            )
            .expect("authentic identity reuse retains conflict before profile refusal");
        assert!(matches!(outcome, AdapterInboxReceiveOutcomeV1::Conflict(_)));
        assert_eq!(table_count(&store, "grant_inbox"), 1);
        assert_eq!(table_count(&store, "inbox_conflicts"), 1);
        assert_eq!(table_count(&store, "inbox_quarantines"), 0);
        assert_eq!(table_count(&store, "adapter_events"), 2);
        assert_eq!(table_count(&store, "execution_receipts"), 0);
    }

    #[test]
    fn capability_freshness_is_revalidated_at_the_second_epoch_sample() {
        let root = TemporaryRootV1::new("capability-second-sample");
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x75; 32]);
        let store = initialize_fixture_store(&root, identity, fixture_profile());
        let outcome = store
            .receive_grant_v1(
                &signed_capability_boundary_grant(),
                &CollisionGrantAuthorityV1::new(),
                &current_clock(),
                &current_epoch(2),
            )
            .expect("capability expiry retains a closed pre-receive refusal");
        let AdapterInboxReceiveOutcomeV1::PreReceivedRefusal(refusal) = outcome else {
            panic!("second-sample capability expiry must stop before RECEIVED");
        };
        assert_eq!(
            refusal.reason(),
            AdapterPreReceiveRefusalV1::CapabilityMismatch
        );
        assert_eq!(table_count(&store, "grant_inbox"), 0);
        assert_eq!(table_count(&store, "inbox_quarantines"), 1);
        assert_eq!(
            bound_quarantine_count(&store, fixture_candidate().grant_id),
            1
        );
        assert_eq!(table_count(&store, "adapter_events"), 0);
        assert_eq!(table_count(&store, "execution_receipts"), 0);
    }

    #[test]
    fn all_binding_collisions_are_permanent_and_never_admitted() {
        let root = TemporaryRootV1::new("binding-conflicts");
        let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x62; 32]);
        let grant = canonical_fixture_grant();
        let store = initialize_fixture_store(&root, identity, fixture_profile());
        assert!(matches!(
            store
                .receive_grant_v1(
                    &grant,
                    &FixtureGrantResolverV1,
                    &current_clock(),
                    &current_epoch(2),
                )
                .expect("first grant is admitted"),
            AdapterInboxReceiveOutcomeV1::Received(_)
        ));

        let dimensions = [
            CollisionDimensionV1::Grant,
            CollisionDimensionV1::Operation,
            CollisionDimensionV1::Nonce,
            CollisionDimensionV1::Digest,
            CollisionDimensionV1::DispatchAttempt,
        ];
        for (offset, dimension) in dimensions.into_iter().enumerate() {
            let conflict = store
                .commit_received(conflicting_candidate(dimension), epoch_observation(3))
                .expect("colliding binding retains permanent evidence");
            let AdapterInboxReceiveOutcomeV1::Conflict(conflict) = conflict else {
                panic!("a colliding binding must not enter RECEIVED");
            };
            assert_eq!(conflict.conflict_generation(), offset as u64 + 2);
        }
        assert_eq!(table_count(&store, "grant_inbox"), 1);
        assert_eq!(table_count(&store, "inbox_transitions"), 1);
        assert_eq!(table_count(&store, "inbox_conflicts"), 5);
        assert_eq!(table_count(&store, "adapter_events"), 6);
        assert_eq!(table_count(&store, "execution_receipts"), 0);

        let repeated = store
            .commit_received(
                conflicting_candidate(CollisionDimensionV1::Grant),
                epoch_observation(3),
            )
            .expect("identical conflict reads retained evidence");
        let AdapterInboxReceiveOutcomeV1::Conflict(repeated) = repeated else {
            panic!("repeated conflict remains a conflict");
        };
        assert_eq!(repeated.conflict_generation(), 2);
        assert_eq!(table_count(&store, "inbox_conflicts"), 5);
        assert_eq!(table_count(&store, "adapter_events"), 6);
        drop(store);

        let reopened = reopen_fixture_store(&root, identity, fixture_profile());
        assert_eq!(table_count(&reopened, "grant_inbox"), 1);
        assert_eq!(table_count(&reopened, "inbox_conflicts"), 5);
        assert_eq!(table_count(&reopened, "adapter_events"), 6);
        assert_eq!(table_count(&reopened, "execution_receipts"), 0);
    }
}
