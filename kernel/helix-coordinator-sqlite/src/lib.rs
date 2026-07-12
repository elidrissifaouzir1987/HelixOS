#![forbid(unsafe_code)]

//! SQLite-backed durable-preparation coordinator state for HelixOS.
//!
//! This crate neither dispatches effects nor mutates the replay store.

// Gives private test seams one identical path in the real crate and source-included tests.
extern crate self as helix_coordinator_sqlite;

mod budget;
mod clock;
mod comparison_digest;
mod config;
mod connection;
mod error;
mod failure;
mod maintenance;
#[allow(dead_code)] // T025 codecs are consumed by the T070-T072 backup/restore path.
mod manifest;
mod outbox;
mod preflight;
mod prepare;
mod quarantine;
mod readback;
mod retirement;
mod root_safety;
mod schema;
mod transition;

#[cfg(feature = "test-fault-injection")]
mod test_fault;

/// Opaque store-owned fault probe used only by non-default conformance wiring.
///
/// Its ordinary public constructor is disabled. A selected value can be constructed or
/// installed only by the hidden T074 feature-gated test seams.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct CoordinatorFaultProbeV1 {
    #[cfg(feature = "test-fault-injection")]
    inner: test_fault::FaultProbeV1,
}

impl CoordinatorFaultProbeV1 {
    #[doc(hidden)]
    pub fn disabled_v1() -> Self {
        Self::default()
    }

    #[doc(hidden)]
    pub fn reach_id_v1(&self, boundary_id: &str) {
        #[cfg(feature = "test-fault-injection")]
        if let Some(boundary) = test_fault::FaultBoundaryV1::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.id() == boundary_id)
        {
            self.inner.reach_v1(boundary);
        }
        #[cfg(not(feature = "test-fault-injection"))]
        let _ = boundary_id;
    }

    #[cfg(feature = "test-fault-injection")]
    fn selected_process_barrier_v1(
        selection: test_fault::FaultSelectionV1,
        process_barrier: Box<dyn FnMut() + Send>,
    ) -> Self {
        Self {
            inner: test_fault::FaultProbeV1::selected_process_barrier_v1(
                selection,
                process_barrier,
            ),
        }
    }

    /// Selects one exact transactional coordinator boundary for a private process driver.
    ///
    /// The closed boundary enum remains private; string IDs outside the 26 transaction
    /// boundaries are rejected before any callback custody is created.
    #[doc(hidden)]
    #[cfg(feature = "test-fault-injection")]
    pub fn selected_process_barrier_for_test_v1<F>(
        boundary_id: &str,
        occurrence: u64,
        process_barrier: F,
    ) -> Result<Self, &'static str>
    where
        F: FnMut() + Send + 'static,
    {
        let boundary = test_fault::FaultBoundaryV1::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.id() == boundary_id)
            .filter(|boundary| boundary.is_transactional_coordinator_v1())
            .ok_or("fault-boundary-workflow-unsupported")?;
        let selection = test_fault::FaultSelectionV1::try_new(
            boundary,
            occurrence,
            test_fault::FaultEffectV1::ProcessBarrier,
        )
        .map_err(|_| "fault-occurrence-invalid")?;
        Ok(Self::selected_process_barrier_v1(
            selection,
            Box::new(process_barrier),
        ))
    }
}

pub use clock::CoordinatorMonotonicClockV1;
pub use config::{
    CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigErrorV1, CoordinatorStoreConfigV1,
};
pub use connection::CoordinatorStoreOpenErrorV1;
pub use error::CoordinatorClockUnavailableV1;
pub use maintenance::{RestoredPreparationMaintenanceEvidenceV1, VerifiedPreparationRestoreV1};
pub use schema::{
    embedded_schema_v1_sha256, COORDINATOR_STORE_APPLICATION_ID_V1,
    COORDINATOR_STORE_FORMAT_VERSION_V1, COORDINATOR_STORE_SCHEMA_V1_SQL,
    COORDINATOR_STORE_SCHEMA_VERSION_V1,
};

/// Runs the exact production T071 backup path for the external conformance harness.
///
/// This facade exists only in the non-default fault-test build and returns static,
/// payload-free phase labels. It is not a backup API and carries no production
/// authority.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub fn run_t071_production_conformance_for_test_v1() -> Result<(), &'static str> {
    maintenance::run_t071_production_conformance_v1()
}

/// Runs the exact production T072 clean-root restore path for the external harness.
///
/// This hidden facade is feature-gated test evidence only. It returns no root identity,
/// native path, restore binding or activation authority.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub fn run_t072_production_conformance_for_test_v1() -> Result<(), &'static str> {
    maintenance::run_t072_production_conformance_v1()
}

/// Runs one explicitly selected process barrier through a production workflow.
///
/// This hidden, non-default test facade transfers the callback into a caller-owned
/// fault probe. It never consults environment, global or thread-local selection state.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub fn run_t074_production_fault_probe_for_test_v1<F>(
    boundary_id: &str,
    occurrence: u64,
    probe_root: std::path::PathBuf,
    process_barrier: F,
) -> Result<(), &'static str>
where
    F: FnMut() + Send + 'static,
{
    maintenance::run_t074_production_fault_probe_v1(
        boundary_id,
        occurrence,
        probe_root,
        Box::new(process_barrier),
    )
}

/// Selects one coordinator transaction boundary on an explicitly supplied store.
///
/// This hidden non-default facade is the only route that can replace the store's
/// disabled probe. It carries no operation, root, digest, or activation authority.
#[doc(hidden)]
#[cfg(all(feature = "test-fault-injection", not(test)))]
pub fn select_t074_coordinator_fault_probe_for_test_v1<C, R, F>(
    store: &mut SqliteCoordinatorStoreV1<C, R>,
    boundary_id: &str,
    occurrence: u64,
    process_barrier: F,
) -> Result<(), &'static str>
where
    C: CoordinatorMonotonicClockV1,
    R: Ed25519KeyResolver,
    F: FnMut() + Send + 'static,
{
    store.fault_probe = CoordinatorFaultProbeV1::selected_process_barrier_for_test_v1(
        boundary_id,
        occurrence,
        process_barrier,
    )?;
    Ok(())
}

use crate::connection::{initialize_or_verify_store, open_bound_existing_connection};
use crate::error::InternalCoordinatorError;
use crate::failure::fail_before_dispatch_transaction_with_probe_v1;
use crate::preflight::{
    classify_preflight_budget_v1, classify_preflight_operation_v1, CoordinatorOperationPreflightV1,
    CoordinatorPreflightInputV1,
};
use crate::prepare::production::{
    commit_preparing_transaction_v1, CoordinatorCommitBindingsV1, CoordinatorCommitOutcomeV1,
    CoordinatorCommitVerificationErrorV1, CoordinatorUncertainCommitCustodyV1,
};
use crate::readback::{
    readback_with_fault_probe_v1, record_uncertain_connection_closed_with_probe_v1,
    CoordinatorReadbackInputV1,
};
use helix_contracts::{Ed25519KeyResolver, ResourceRefV1, Sha256Digest};
use helix_plan_preparation::{
    FinalCommitGateV1, FinalCommitInFlightV1, FinalCommitPermitV1, FinalCommitReadbackResolutionV1,
    NoDispatchAuthorityGuardV1, PreparationCommitInputV1, PreparationCommitOutcomeV1,
    PreparationFailureInputV1, PreparationFailureOutcomeV1, PreparationPreflightInputV1,
    PreparationPreflightOutcomeV1, PreparationReadbackInputV1, PreparationReadbackOutcomeV1,
    PreparationStoreV1, RecoveryEvidenceV1, PREPARATION_STORE_CONTRACT_VERSION_V1,
};
use rusqlite::TransactionBehavior;
use sha2::{Digest as _, Sha256};
use std::collections::{hash_map::Entry, HashMap};
use std::fmt;
use std::sync::{Mutex, MutexGuard};

const PREPARED_EVENT_ID_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-EVENT-ID\0V1\0";
const TARGET_REFERENCE_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-TARGET-REFERENCE\0V1\0";
const PRECONDITION_IDENTITY_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-PRECONDITION-IDENTITY\0V1\0";
const BOOT_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0PREPARATION-BOOT-BINDING\0V1\0";

/// SQLite-backed owner of the durable preparation coordinator state.
///
/// The injected resolver must retain historical PLAN-001 verification keys. Healthy
/// open reparses and verifies every retained canonical signed plan with that resolver.
#[allow(dead_code)] // Retained for the staged coordinator operations that follow T024.
pub struct SqliteCoordinatorStoreV1<C, R> {
    pub(crate) config: CoordinatorStoreConfigV1,
    pub(crate) clock: C,
    pub(crate) historical_plan_keys: R,
    pub(crate) schema_cookie: i64,
    pub(crate) operation_count: u64,
    root_identity: CoordinatorRootIdentityEvidenceV1,
    uncertain_custody: Mutex<HashMap<Sha256Digest, CoordinatorUncertainCommitCustodyV1>>,
    fault_probe: CoordinatorFaultProbeV1,
}

impl<C, R> SqliteCoordinatorStoreV1<C, R>
where
    C: CoordinatorMonotonicClockV1,
    R: Ed25519KeyResolver,
{
    /// Initializes an attested empty root or verifies an attested existing root.
    pub fn open_or_create(
        config: CoordinatorStoreConfigV1,
        clock: C,
        historical_plan_keys: R,
        deadline_monotonic_ms: u64,
    ) -> Result<Self, CoordinatorStoreOpenErrorV1> {
        let (config, summary) = initialize_or_verify_store(
            config,
            &clock,
            &historical_plan_keys,
            deadline_monotonic_ms,
        )
        .map_err(CoordinatorStoreOpenErrorV1::from_internal)?;
        Ok(Self {
            config,
            clock,
            historical_plan_keys,
            schema_cookie: summary.schema_cookie,
            operation_count: summary.operation_count,
            root_identity: CoordinatorRootIdentityEvidenceV1::from_internal(summary.root_identity),
            uncertain_custody: Mutex::new(HashMap::new()),
            fault_probe: CoordinatorFaultProbeV1::disabled_v1(),
        })
    }

    /// Number of canonical operation records revalidated during this open.
    pub const fn operation_count(&self) -> u64 {
        self.operation_count
    }

    /// Returns the opaque identity evidence the provisioner must retain for reopen.
    pub const fn root_identity_evidence(&self) -> CoordinatorRootIdentityEvidenceV1 {
        self.root_identity
    }
}

impl<C, R> PreparationStoreV1 for SqliteCoordinatorStoreV1<C, R>
where
    C: CoordinatorMonotonicClockV1,
    R: Ed25519KeyResolver + Send + Sync,
{
    fn preflight_operation_and_budget(
        &self,
        input: &PreparationPreflightInputV1<'_>,
    ) -> PreparationPreflightOutcomeV1 {
        if input.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1 {
            return PreparationPreflightOutcomeV1::OperationAuthorityUnavailable;
        }
        let deadline = input.context().effective_deadline_monotonic_ms();
        let mut bound = match open_bound_existing_connection(&self.config, &self.clock, deadline) {
            Ok(bound) => bound,
            Err(_) => return PreparationPreflightOutcomeV1::OperationAuthorityUnavailable,
        };
        let expected_root_identity = bound.expected_root_identity();
        let transaction = match bound
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Deferred)
        {
            Ok(transaction) => transaction,
            Err(_) => return PreparationPreflightOutcomeV1::OperationAuthorityUnavailable,
        };
        let coordinator_input = coordinator_preflight_input_v1(input);
        let operation = classify_preflight_operation_v1(&transaction, &coordinator_input);
        let outcome = match operation {
            CoordinatorOperationPreflightV1::Absent => {
                if schema::verify_full(
                    &transaction,
                    expected_root_identity,
                    &self.historical_plan_keys,
                )
                .is_ok()
                {
                    classify_preflight_budget_v1(&transaction, &coordinator_input)
                } else {
                    PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable
                }
            }
            CoordinatorOperationPreflightV1::OperationConflict => {
                PreparationPreflightOutcomeV1::OperationConflict
            }
            CoordinatorOperationPreflightV1::AlreadyPrepared => {
                PreparationPreflightOutcomeV1::AlreadyPrepared
            }
            CoordinatorOperationPreflightV1::Unavailable => {
                PreparationPreflightOutcomeV1::OperationAuthorityUnavailable
            }
        };
        if transaction.rollback().is_err() || bound.revalidate(&self.clock, deadline).is_err() {
            return match operation {
                CoordinatorOperationPreflightV1::Absent => {
                    PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable
                }
                _ => PreparationPreflightOutcomeV1::OperationAuthorityUnavailable,
            };
        }
        outcome
    }

    fn commit_preparing<G: FinalCommitGateV1>(
        &self,
        input: &PreparationCommitInputV1<'_>,
        final_gate: &mut G,
    ) -> PreparationCommitOutcomeV1<<G::Permit as FinalCommitPermitV1>::InFlight> {
        let derived = match derive_commit_bindings_v1(input) {
            Ok(derived) => derived,
            Err(()) => return PreparationCommitOutcomeV1::Unhealthy,
        };
        let deadline = input.final_context().effective_deadline_monotonic_ms();
        let mut bound = match open_bound_existing_connection(&self.config, &self.clock, deadline) {
            Ok(bound) => bound,
            Err(error) => return map_commit_connection_error_v1(error),
        };
        if let Err(error) = bound.arm_next_writer_wait_v1(&self.clock, deadline) {
            return map_commit_connection_error_v1(error);
        }
        let expected_root_identity = bound.expected_root_identity();
        let bindings = CoordinatorCommitBindingsV1 {
            commit: input,
            event_id: derived.event_id,
            target_reference_digest: derived.target_reference_digest,
            precondition_identity_digest: derived.precondition_identity_digest,
            boot_binding_digest: derived.boot_binding_digest,
            caller_deadline_monotonic_ms: deadline,
        };
        let internal = commit_preparing_transaction_v1(
            bound.connection_mut(),
            &bindings,
            final_gate,
            &self.fault_probe,
            || self.clock.now_monotonic_ms().map_err(|_| ()),
            |connection| {
                schema::verify_full(
                    connection,
                    expected_root_identity,
                    &self.historical_plan_keys,
                )
                .map(|_| ())
                .map_err(map_commit_verification_error_v1)
            },
        );
        let binding_revalidation_failed = bound.revalidate(&self.clock, deadline).is_err();
        if binding_revalidation_failed
            && !matches!(&internal, CoordinatorCommitOutcomeV1::Uncertain(_))
        {
            return PreparationCommitOutcomeV1::Unclassified;
        }
        map_commit_outcome_v1(&self.uncertain_custody, internal)
    }

    fn readback_attempt(
        &self,
        input: &PreparationReadbackInputV1<'_>,
    ) -> PreparationReadbackOutcomeV1 {
        if input.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1
            || input.uncertain().contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1
            || input.uncertain().attempt_id() != input.attempt().digest()
        {
            return PreparationReadbackOutcomeV1::Ambiguous;
        }
        let Some(custody) =
            take_uncertain_custody_v1(&self.uncertain_custody, input.uncertain().attempt_id())
        else {
            return PreparationReadbackOutcomeV1::Ambiguous;
        };
        record_uncertain_connection_closed_with_probe_v1(&self.fault_probe);

        let eligible = input.eligible();
        let claims = eligible.authentic().preparation_claims();
        let requested = [
            claims.budget().max_cost_micro_units(),
            claims.budget().action_limit(),
            claims.budget().egress_bytes_limit(),
            claims.recovery_reserved_bytes(),
        ];
        let coordinator_input = CoordinatorReadbackInputV1 {
            operation_id: claims.operation_id(),
            attempt_id: input.attempt().digest(),
            plan_id: claims.plan_id(),
            task_id: claims.task_id(),
            workload_id: claims.workload_id(),
            reservation_id: claims.budget().reservation_id(),
            replay_claim_id: custody.replay_claim_id,
            replay_claimant_generation: custody.replay_claimant_generation,
            replay_binding_digest: custody.replay_binding_digest,
            task_lease_digest: claims.task_lease_digest(),
            allowance_binding_digest: custody.budget_scope_binding_digest,
            scope_generation: custody.budget_scope_generation,
            currency_code: claims.budget().currency_code(),
            price_table_id: claims.budget().price_table_id(),
            requested,
            recovery_mode: claims.recovery_class(),
            precondition_digest: claims.precondition_content_sha256(),
            precondition_length: claims.precondition_byte_length(),
            effective_expires_at_utc_ms: eligible.bounds().effective_expires_at_utc_unix_ms(),
            effective_deadline_monotonic_ms: eligible.bounds().effective_deadline_monotonic_ms(),
            exact_custody: Some(&custody),
            #[cfg(test)]
            full_store_verified: false,
            #[cfg(test)]
            definite_absence_writer_exclusion: false,
        };
        let deadline = coordinator_input.effective_deadline_monotonic_ms;
        let mut bound = match open_bound_existing_connection(&self.config, &self.clock, deadline) {
            Ok(bound) => bound,
            Err(error) => return map_readback_connection_error_v1(error),
        };
        if let Err(error) = bound.arm_next_writer_wait_v1(&self.clock, deadline) {
            return map_readback_connection_error_v1(error);
        }
        let expected_root_identity = bound.expected_root_identity();
        let mut full_verify_failed = false;
        let outcome = readback_with_fault_probe_v1(
            bound.connection_mut(),
            &coordinator_input,
            &self.fault_probe,
            |snapshot| {
                let verified = schema::verify_full(
                    snapshot,
                    expected_root_identity,
                    &self.historical_plan_keys,
                )
                .is_ok();
                full_verify_failed = !verified;
                verified
            },
        );
        if full_verify_failed || bound.revalidate(&self.clock, deadline).is_err() {
            return PreparationReadbackOutcomeV1::Unhealthy;
        }
        outcome
    }

    fn fail_before_dispatch<G: NoDispatchAuthorityGuardV1>(
        &self,
        input: &PreparationFailureInputV1<'_>,
        no_dispatch_guard: &mut G,
    ) -> PreparationFailureOutcomeV1 {
        if input.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1 {
            return PreparationFailureOutcomeV1::Mismatch;
        }
        let deadline = input.binding().deadline_monotonic_ms();
        let mut bound = match open_bound_existing_connection(&self.config, &self.clock, deadline) {
            Ok(bound) => bound,
            Err(error) => return map_failure_connection_error_v1(error),
        };
        if let Err(error) = bound.arm_next_writer_wait_v1(&self.clock, deadline) {
            return map_failure_connection_error_v1(error);
        }
        let expected_root_identity = bound.expected_root_identity();
        let outcome = fail_before_dispatch_transaction_with_probe_v1(
            bound.connection_mut(),
            input,
            no_dispatch_guard,
            &self.fault_probe,
            || self.clock.now_monotonic_ms().map_err(|_| ()),
            |connection| {
                schema::verify_full(
                    connection,
                    expected_root_identity,
                    &self.historical_plan_keys,
                )
                .is_ok()
            },
        );
        if bound.revalidate(&self.clock, deadline).is_err() {
            return PreparationFailureOutcomeV1::Unhealthy;
        }
        outcome
    }
}

fn coordinator_preflight_input_v1<'input>(
    input: &'input PreparationPreflightInputV1<'input>,
) -> CoordinatorPreflightInputV1<'input> {
    let claims = input.eligible().authentic().preparation_claims();
    let context = input.context();
    CoordinatorPreflightInputV1 {
        operation_id: claims.operation_id(),
        attempt_id: input.attempt().digest(),
        plan_id: claims.plan_id(),
        task_id: claims.task_id(),
        workload_id: claims.workload_id(),
        reservation_id: claims.budget().reservation_id(),
        task_lease_digest: claims.task_lease_digest(),
        allowance_binding_digest: context.budget_scope_binding_digest(),
        scope_generation: context.budget_scope_generation(),
        currency_code: context.currency_code(),
        price_table_id: context.price_table_id(),
        requested: [
            input.requested_budget().max_cost_micro_units(),
            input.requested_budget().action_limit(),
            input.requested_budget().egress_bytes_limit(),
            input.requested_budget().recovery_bytes(),
        ],
    }
}

struct DerivedCommitBindingsV1 {
    event_id: Sha256Digest,
    target_reference_digest: Sha256Digest,
    precondition_identity_digest: Sha256Digest,
    boot_binding_digest: Sha256Digest,
}

/// Material receipts already carry the provider's exact verified bindings and are the
/// sole source for those three digests. Authenticated irreversible L2 plans have no
/// material receipt by design; for that branch only, the adapter derives restricted
/// persistence bindings from the authentic target/precondition and final boot epochs.
/// This does not create recovery evidence or weaken the fixed `no_material` statement.
fn derive_commit_bindings_v1(
    input: &PreparationCommitInputV1<'_>,
) -> Result<DerivedCommitBindingsV1, ()> {
    let claims = input.eligible().authentic().preparation_claims();
    let event_id = derive_prepared_event_id_v1(
        input.attempt().digest(),
        claims.plan_id(),
        claims.operation_id(),
        claims.budget().reservation_id(),
    )?;
    let (target_reference_digest, precondition_identity_digest, boot_binding_digest) =
        match input.recovery_evidence() {
            RecoveryEvidenceV1::Material(receipt) => (
                receipt.target_reference_digest(),
                receipt.precondition_identity_digest(),
                receipt.boot_binding_digest(),
            ),
            RecoveryEvidenceV1::Irreversible(_) => (
                derive_target_reference_digest_v1(claims.target())?,
                derive_precondition_identity_digest_v1(
                    claims.precondition_volume_id(),
                    claims.precondition_file_id(),
                )?,
                derive_boot_binding_digest_v1(
                    input.final_context().boot_id(),
                    input.final_context().instance_epoch(),
                    input.final_context().fencing_epoch(),
                )?,
            ),
        };
    Ok(DerivedCommitBindingsV1 {
        event_id,
        target_reference_digest,
        precondition_identity_digest,
        boot_binding_digest,
    })
}

fn derive_prepared_event_id_v1(
    attempt_id: Sha256Digest,
    plan_id: Sha256Digest,
    operation_id: &str,
    reservation_id: &str,
) -> Result<Sha256Digest, ()> {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_EVENT_ID_DOMAIN_V1);
    hasher.update(attempt_id.as_bytes());
    hasher.update(plan_id.as_bytes());
    update_length_prefixed_v1(&mut hasher, operation_id.as_bytes())?;
    update_length_prefixed_v1(&mut hasher, reservation_id.as_bytes())?;
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn derive_target_reference_digest_v1(target: &ResourceRefV1) -> Result<Sha256Digest, ()> {
    let mut hasher = Sha256::new();
    hasher.update(TARGET_REFERENCE_DOMAIN_V1);
    update_length_prefixed_v1(&mut hasher, target.root_id().as_bytes())?;
    hasher.update(
        u64::try_from(target.components().len())
            .map_err(|_| ())?
            .to_be_bytes(),
    );
    for component in target.components() {
        update_length_prefixed_v1(&mut hasher, component.as_bytes())?;
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn derive_precondition_identity_digest_v1(
    volume_id: &str,
    file_id: &str,
) -> Result<Sha256Digest, ()> {
    let mut hasher = Sha256::new();
    hasher.update(PRECONDITION_IDENTITY_DOMAIN_V1);
    update_length_prefixed_v1(&mut hasher, volume_id.as_bytes())?;
    update_length_prefixed_v1(&mut hasher, file_id.as_bytes())?;
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn derive_boot_binding_digest_v1(
    boot_id: &str,
    instance_epoch: u64,
    fencing_epoch: u64,
) -> Result<Sha256Digest, ()> {
    let mut hasher = Sha256::new();
    hasher.update(BOOT_BINDING_DOMAIN_V1);
    update_length_prefixed_v1(&mut hasher, boot_id.as_bytes())?;
    hasher.update(instance_epoch.to_be_bytes());
    hasher.update(fencing_epoch.to_be_bytes());
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn update_length_prefixed_v1(hasher: &mut Sha256, value: &[u8]) -> Result<(), ()> {
    hasher.update(u64::try_from(value.len()).map_err(|_| ())?.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn map_commit_connection_error_v1<I>(
    error: InternalCoordinatorError,
) -> PreparationCommitOutcomeV1<I> {
    match error {
        InternalCoordinatorError::DeadlineReached => {
            PreparationCommitOutcomeV1::PermitDeadlineReached
        }
        InternalCoordinatorError::RootBusy => PreparationCommitOutcomeV1::Busy,
        InternalCoordinatorError::ClockUnavailable | InternalCoordinatorError::RootUnavailable => {
            PreparationCommitOutcomeV1::Unavailable
        }
        _ => PreparationCommitOutcomeV1::Unhealthy,
    }
}

fn map_commit_verification_error_v1(
    error: InternalCoordinatorError,
) -> CoordinatorCommitVerificationErrorV1 {
    match error {
        InternalCoordinatorError::RootBusy => CoordinatorCommitVerificationErrorV1::Busy,
        InternalCoordinatorError::ClockUnavailable
        | InternalCoordinatorError::DeadlineReached
        | InternalCoordinatorError::RootUnavailable => {
            CoordinatorCommitVerificationErrorV1::Unavailable
        }
        _ => CoordinatorCommitVerificationErrorV1::Unhealthy,
    }
}

fn map_commit_outcome_v1<I: FinalCommitInFlightV1>(
    uncertain_custody: &Mutex<HashMap<Sha256Digest, CoordinatorUncertainCommitCustodyV1>>,
    outcome: CoordinatorCommitOutcomeV1<I>,
) -> PreparationCommitOutcomeV1<I> {
    match outcome {
        CoordinatorCommitOutcomeV1::Committed(receipt) => {
            PreparationCommitOutcomeV1::Committed(receipt)
        }
        CoordinatorCommitOutcomeV1::ConfirmedRollback => {
            PreparationCommitOutcomeV1::ConfirmedRollback
        }
        CoordinatorCommitOutcomeV1::Uncertain(uncertain) => {
            if !insert_uncertain_custody_v1(uncertain_custody, uncertain.custody) {
                let _ = uncertain.in_flight.resolve_readback_instrumented_v1(
                    FinalCommitReadbackResolutionV1::Inconclusive,
                );
                return PreparationCommitOutcomeV1::Unclassified;
            }
            PreparationCommitOutcomeV1::Uncertain {
                token: uncertain.portable,
                in_flight: uncertain.in_flight,
            }
        }
        CoordinatorCommitOutcomeV1::Unclassified => PreparationCommitOutcomeV1::Unclassified,
        CoordinatorCommitOutcomeV1::PermitRevoked => PreparationCommitOutcomeV1::PermitRevoked,
        CoordinatorCommitOutcomeV1::PermitUnavailable => {
            PreparationCommitOutcomeV1::PermitUnavailable
        }
        CoordinatorCommitOutcomeV1::PermitDeadlineReached => {
            PreparationCommitOutcomeV1::PermitDeadlineReached
        }
        CoordinatorCommitOutcomeV1::PermitUnsupported => {
            PreparationCommitOutcomeV1::PermitUnsupported
        }
        CoordinatorCommitOutcomeV1::StoreUnavailable => PreparationCommitOutcomeV1::Unavailable,
        CoordinatorCommitOutcomeV1::StoreBusy => PreparationCommitOutcomeV1::Busy,
        CoordinatorCommitOutcomeV1::StoreUnhealthy => PreparationCommitOutcomeV1::Unhealthy,
        CoordinatorCommitOutcomeV1::OperationConflict => {
            PreparationCommitOutcomeV1::OperationConflict
        }
        CoordinatorCommitOutcomeV1::AlreadyPrepared => PreparationCommitOutcomeV1::AlreadyPrepared,
        CoordinatorCommitOutcomeV1::Conflict => PreparationCommitOutcomeV1::Conflict,
        CoordinatorCommitOutcomeV1::BudgetScopeMissing => {
            PreparationCommitOutcomeV1::BudgetScopeMissing
        }
        CoordinatorCommitOutcomeV1::BudgetBindingConflict => {
            PreparationCommitOutcomeV1::BudgetBindingConflict
        }
        CoordinatorCommitOutcomeV1::BudgetArithmeticInvalid => {
            PreparationCommitOutcomeV1::BudgetArithmeticInvalid
        }
        CoordinatorCommitOutcomeV1::BudgetExhausted => PreparationCommitOutcomeV1::BudgetExhausted,
    }
}

fn insert_uncertain_custody_v1(
    custody_by_attempt: &Mutex<HashMap<Sha256Digest, CoordinatorUncertainCommitCustodyV1>>,
    custody: CoordinatorUncertainCommitCustodyV1,
) -> bool {
    let mut entries = lock_custody_v1(custody_by_attempt);
    match entries.entry(custody.attempt_id) {
        Entry::Vacant(entry) => {
            entry.insert(custody);
            true
        }
        Entry::Occupied(_) => false,
    }
}

fn take_uncertain_custody_v1(
    custody_by_attempt: &Mutex<HashMap<Sha256Digest, CoordinatorUncertainCommitCustodyV1>>,
    attempt_id: Sha256Digest,
) -> Option<CoordinatorUncertainCommitCustodyV1> {
    lock_custody_v1(custody_by_attempt).remove(&attempt_id)
}

fn lock_custody_v1(
    custody_by_attempt: &Mutex<HashMap<Sha256Digest, CoordinatorUncertainCommitCustodyV1>>,
) -> MutexGuard<'_, HashMap<Sha256Digest, CoordinatorUncertainCommitCustodyV1>> {
    custody_by_attempt
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn map_readback_connection_error_v1(
    error: InternalCoordinatorError,
) -> PreparationReadbackOutcomeV1 {
    match error {
        InternalCoordinatorError::ClockUnavailable
        | InternalCoordinatorError::DeadlineReached
        | InternalCoordinatorError::RootBusy
        | InternalCoordinatorError::RootUnavailable => PreparationReadbackOutcomeV1::Unavailable,
        _ => PreparationReadbackOutcomeV1::Unhealthy,
    }
}

fn map_failure_connection_error_v1(error: InternalCoordinatorError) -> PreparationFailureOutcomeV1 {
    match error {
        InternalCoordinatorError::DeadlineReached => PreparationFailureOutcomeV1::DeadlineReached,
        InternalCoordinatorError::RootBusy => PreparationFailureOutcomeV1::Conflict,
        InternalCoordinatorError::ClockUnavailable | InternalCoordinatorError::RootUnavailable => {
            PreparationFailureOutcomeV1::Unavailable
        }
        _ => PreparationFailureOutcomeV1::Unhealthy,
    }
}

impl<C, R> fmt::Debug for SqliteCoordinatorStoreV1<C, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteCoordinatorStoreV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    use helix_contracts::{ContractError, Result as ContractResult};
    use helix_plan_preparation::{
        FinalCommitTerminalResolutionV1, PreparationCommitOutcomeV1 as PortableCommitOutcomeV1,
    };

    struct TestClock;

    impl CoordinatorMonotonicClockV1 for TestClock {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            Ok(1)
        }
    }

    struct TestKeys;

    impl Ed25519KeyResolver for TestKeys {
        fn resolve_ed25519(&self, _key_id: &str) -> ContractResult<[u8; 32]> {
            Err(ContractError::UnknownKey)
        }
    }

    struct TestInFlight;

    impl FinalCommitInFlightV1 for TestInFlight {
        fn permit_deadline_monotonic_ms(&self) -> u64 {
            250
        }

        fn resolve_readback(
            self,
            _resolution: FinalCommitReadbackResolutionV1,
        ) -> FinalCommitTerminalResolutionV1 {
            FinalCommitTerminalResolutionV1::Ambiguous
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn custody(attempt_id: Sha256Digest) -> CoordinatorUncertainCommitCustodyV1 {
        CoordinatorUncertainCommitCustodyV1 {
            operation_id: "operation:t037".to_owned(),
            attempt_id,
            plan_id: digest(2),
            reservation_id: "reservation:t037".to_owned(),
            event_id: digest(3),
            scope_id: digest(4),
            budget_scope_binding_digest: digest(5),
            comparison_digest: digest(6),
            replay_claim_id: digest(7),
            replay_claimant_generation: 1,
            replay_binding_digest: digest(8),
            target_reference_digest: digest(9),
            precondition_identity_digest: digest(10),
            boot_binding_digest: digest(11),
            budget_scope_generation: 1,
            store_generation: 1,
            operation_generation: 1,
            event_generation: 1,
            reservation_created_generation: 1,
            supervisor_generation: 1,
            instance_epoch: 1,
            fencing_epoch: 1,
        }
    }

    #[test]
    fn sqlite_store_satisfies_the_portable_adapter_boundary() {
        fn require_store<T: PreparationStoreV1>() {}
        require_store::<SqliteCoordinatorStoreV1<TestClock, TestKeys>>();
    }

    #[test]
    fn uncertain_custody_is_attempt_keyed_and_consumed_once() {
        let entries = Mutex::new(HashMap::new());
        let attempt = digest(1);
        assert!(insert_uncertain_custody_v1(&entries, custody(attempt)));
        assert!(!insert_uncertain_custody_v1(&entries, custody(attempt)));
        assert_eq!(
            take_uncertain_custody_v1(&entries, attempt).map(|value| value.attempt_id),
            Some(attempt)
        );
        assert!(take_uncertain_custody_v1(&entries, attempt).is_none());
    }

    #[test]
    fn all_four_transactional_budget_classes_map_without_collapse() {
        let entries = Mutex::new(HashMap::new());
        assert!(matches!(
            map_commit_outcome_v1::<TestInFlight>(
                &entries,
                CoordinatorCommitOutcomeV1::BudgetScopeMissing,
            ),
            PortableCommitOutcomeV1::BudgetScopeMissing
        ));
        assert!(matches!(
            map_commit_outcome_v1::<TestInFlight>(
                &entries,
                CoordinatorCommitOutcomeV1::BudgetBindingConflict,
            ),
            PortableCommitOutcomeV1::BudgetBindingConflict
        ));
        assert!(matches!(
            map_commit_outcome_v1::<TestInFlight>(
                &entries,
                CoordinatorCommitOutcomeV1::BudgetArithmeticInvalid,
            ),
            PortableCommitOutcomeV1::BudgetArithmeticInvalid
        ));
        assert!(matches!(
            map_commit_outcome_v1::<TestInFlight>(
                &entries,
                CoordinatorCommitOutcomeV1::BudgetExhausted,
            ),
            PortableCommitOutcomeV1::BudgetExhausted
        ));
    }

    #[test]
    fn transactional_operation_classes_map_without_collapse() {
        let entries = Mutex::new(HashMap::new());
        assert!(matches!(
            map_commit_outcome_v1::<TestInFlight>(
                &entries,
                CoordinatorCommitOutcomeV1::OperationConflict,
            ),
            PortableCommitOutcomeV1::OperationConflict
        ));
        assert!(matches!(
            map_commit_outcome_v1::<TestInFlight>(
                &entries,
                CoordinatorCommitOutcomeV1::AlreadyPrepared,
            ),
            PortableCommitOutcomeV1::AlreadyPrepared
        ));
        assert!(matches!(
            map_commit_outcome_v1::<TestInFlight>(&entries, CoordinatorCommitOutcomeV1::Conflict,),
            PortableCommitOutcomeV1::Conflict
        ));
    }

    #[test]
    fn full_verification_errors_keep_store_availability_classes() {
        assert_eq!(
            map_commit_verification_error_v1(InternalCoordinatorError::RootBusy),
            CoordinatorCommitVerificationErrorV1::Busy
        );
        assert_eq!(
            map_commit_verification_error_v1(InternalCoordinatorError::RootUnavailable),
            CoordinatorCommitVerificationErrorV1::Unavailable
        );
        assert_eq!(
            map_commit_verification_error_v1(InternalCoordinatorError::SchemaInvalid),
            CoordinatorCommitVerificationErrorV1::Unhealthy
        );
    }

    #[test]
    fn pre_permit_deadline_is_not_collapsed_into_writer_busy() {
        assert!(matches!(
            map_commit_connection_error_v1::<TestInFlight>(
                InternalCoordinatorError::DeadlineReached
            ),
            PortableCommitOutcomeV1::PermitDeadlineReached
        ));
        assert!(matches!(
            map_commit_connection_error_v1::<TestInFlight>(InternalCoordinatorError::RootBusy),
            PortableCommitOutcomeV1::Busy
        ));
    }

    #[test]
    fn restricted_adapter_digests_are_deterministic_and_domain_separated() {
        let target = ResourceRefV1::new("root", ["leaf"]).expect("synthetic target is valid");
        let target_digest =
            derive_target_reference_digest_v1(&target).expect("target digest derives");
        let target_repeat =
            derive_target_reference_digest_v1(&target).expect("target digest repeats");
        let precondition = derive_precondition_identity_digest_v1("root", "leaf")
            .expect("precondition digest derives");
        let boot =
            derive_boot_binding_digest_v1("root", 1, 2).expect("boot binding digest derives");
        let event = derive_prepared_event_id_v1(
            digest(12),
            digest(13),
            "operation:t037",
            "reservation:t037",
        )
        .expect("event id derives");

        assert_eq!(target_digest, target_repeat);
        assert_ne!(target_digest, precondition);
        assert_ne!(precondition, boot);
        assert_ne!(boot, event);
    }
}
