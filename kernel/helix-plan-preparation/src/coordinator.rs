//! Ordered synchronous preparation-orchestration boundary.
//!
//! Orchestration stops at durable, non-dispatchable preparation. It owns no async
//! runtime, network client, ambient clock, effect adapter, target resolver, or host
//! mutation path.

#![allow(dead_code)] // Exported by the public one-shot seam in T037.

use crate::attempt::PreparationAttemptIdV1;
use crate::budget::{BudgetReservationStateV1, BudgetVectorInputV1, BudgetVectorV1};
#[cfg(feature = "test-fault-injection")]
use crate::commit_gate::{
    reach_fault_probed_commit_permit_returned_v1, FaultProbedFinalCommitPermitV1,
};
use crate::commit_gate::{
    FinalCommitGateV1, FinalCommitInFlightV1, FinalCommitPermitOutcomeV1,
    FinalCommitPermitRequestV1, FinalCommitReadbackResolutionV1, FinalCommitTerminalResolutionV1,
};
use crate::compare::{
    compare_context_replay_binding_v1, compare_final_budget_v1,
    compare_final_context_authority_after_guards_instrumented_v1,
    compare_final_context_before_guards_instrumented_v1, compare_final_recovery_profile_v1,
    compare_preliminary_budget_v1, compare_preliminary_context_before_replay_instrumented_v1,
    compare_preliminary_recovery_profile_v1,
};
use crate::context::{
    PreparationMonotonicClockV1, PreparationTimeSourceV1, PreparationUtcClockV1,
    ReadyPreparationContextV1,
};
use crate::guard::{
    acquire_final_guards_observed_v1, classify_authority_guard_acquisition_v1,
    classify_authority_guard_validation_v1, record_recovery_publication_guard_v1,
    AuthorityGuardRefusalV1, AuthorityGuardSetV1, PreparationAuthoritySourceV1,
    RecoveryPublicationGuardSlotV1,
};
use crate::outcome::{
    AmbiguousPreparationV1, PreparationDenialV1, PreparationFailureV1, PreparationOutcomeV1,
    PreparedOperationV1,
};
use crate::recovery::{
    recovery_boot_binding_digest_v1, recovery_precondition_identity_digest_v1,
    recovery_target_reference_digest_v1, IrreversibilityEvidenceV1, RecoveryBindingInputV1,
    RecoveryBindingV1, RecoveryEvidenceClassV1, RecoveryEvidenceV1, RecoveryGuardOutcomeV1,
    RecoveryMaterialReceiptV1, RecoveryMaterialStateV1, RecoveryPreparationInputV1,
    RecoveryPreparationOutcomeV1, RecoveryProviderV1, RecoveryPublicationGuardV1,
    RecoveryVerificationV1, RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
    RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
};
use crate::store::{
    BudgetPreflightV1, PreparationCommitInputV1, PreparationCommitOutcomeV1,
    PreparationCommitReceiptV1, PreparationPreflightInputV1, PreparationPreflightOutcomeV1,
    PreparationReadbackInputV1, PreparationReadbackOutcomeV1, PreparationStoreV1,
    PREPARATION_STORE_CONTRACT_VERSION_V1,
};
use helix_contracts::{RecoveryClassV1, MAX_SAFE_U64};
use helix_plan_eligibility::{EligiblePlanV1, ReplayClaimVerificationV1, ReplayClaimVerifierV1};

#[cfg(feature = "test-fault-injection")]
type PreparationFaultProbeV1 = crate::test_fault::FaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
#[derive(Clone, Copy, Debug, Default)]
struct PreparationFaultProbeV1;

#[cfg(not(feature = "test-fault-injection"))]
impl PreparationFaultProbeV1 {
    const fn disabled_v1() -> Self {
        Self
    }
}

macro_rules! reach {
    ($boundary:ident) => {
        |fault_probe: &PreparationFaultProbeV1| {
            #[cfg(feature = "test-fault-injection")]
            fault_probe.reach_v1(crate::test_fault::FaultBoundaryV1::$boundary);
            #[cfg(not(feature = "test-fault-injection"))]
            let _ = fault_probe;
        }
    };
}

#[derive(Clone, Copy)]
enum PreparationRefusalV1 {
    Denied(PreparationDenialV1),
    Failed(PreparationFailureV1),
    Ambiguous(AmbiguousPreparationV1),
}

enum UncertainReadbackDecisionV1 {
    Committed(PreparationCommitReceiptV1),
    Aborted(PreparationRefusalV1),
    Ambiguous(PreparationRefusalV1),
}

impl From<PreparationRefusalV1> for PreparationOutcomeV1 {
    fn from(refusal: PreparationRefusalV1) -> Self {
        match refusal {
            PreparationRefusalV1::Denied(reason) => Self::Denied(reason),
            PreparationRefusalV1::Failed(reason) => Self::Failed(reason),
            PreparationRefusalV1::Ambiguous(reason) => Self::Ambiguous(reason),
        }
    }
}

type PreparationResultV1<T> = Result<T, PreparationRefusalV1>;

/// Consumes one eligibility marker and runs the synchronous Phase A-E protocol.
pub fn prepare_plan_v1<A, R, S, P, T>(
    eligible: EligiblePlanV1,
    authority: &A,
    replay_verifier: &R,
    store: &S,
    recovery_provider: &P,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
) -> PreparationOutcomeV1
where
    A: PreparationAuthoritySourceV1,
    R: ReplayClaimVerifierV1,
    S: PreparationStoreV1,
    P: RecoveryProviderV1,
    T: PreparationTimeSourceV1,
{
    prepare_plan_with_probe_inner_v1(
        eligible,
        authority,
        replay_verifier,
        store,
        recovery_provider,
        time_source,
        caller_deadline_monotonic_ms,
        PreparationFaultProbeV1::disabled_v1(),
    )
}

/// Feature-only entry used by the external process-kill harness.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)]
pub fn prepare_plan_with_fault_probe_v1<A, R, S, P, T>(
    eligible: EligiblePlanV1,
    authority: &A,
    replay_verifier: &R,
    store: &S,
    recovery_provider: &P,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
    fault_probe: crate::test_fault::FaultProbeV1,
) -> PreparationOutcomeV1
where
    A: PreparationAuthoritySourceV1,
    R: ReplayClaimVerifierV1,
    S: PreparationStoreV1,
    P: RecoveryProviderV1,
    T: PreparationTimeSourceV1,
{
    prepare_plan_with_probe_inner_v1(
        eligible,
        authority,
        replay_verifier,
        store,
        recovery_provider,
        time_source,
        caller_deadline_monotonic_ms,
        fault_probe,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_plan_with_probe_inner_v1<A, R, S, P, T>(
    eligible: EligiblePlanV1,
    authority: &A,
    replay_verifier: &R,
    store: &S,
    recovery_provider: &P,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
    fault_probe: PreparationFaultProbeV1,
) -> PreparationOutcomeV1
where
    A: PreparationAuthoritySourceV1,
    R: ReplayClaimVerifierV1,
    S: PreparationStoreV1,
    P: RecoveryProviderV1,
    T: PreparationTimeSourceV1,
{
    let outcome = prepare_plan_inner_v1(
        eligible,
        authority,
        replay_verifier,
        store,
        recovery_provider,
        time_source,
        caller_deadline_monotonic_ms,
        &fault_probe,
    );
    reach!(AcknowledgementResultReturned)(&fault_probe);
    outcome
}

#[allow(clippy::too_many_arguments)]
fn prepare_plan_inner_v1<A, R, S, P, T>(
    eligible: EligiblePlanV1,
    authority: &A,
    replay_verifier: &R,
    store: &S,
    recovery_provider: &P,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
    fault_probe: &PreparationFaultProbeV1,
) -> PreparationOutcomeV1
where
    A: PreparationAuthoritySourceV1,
    R: ReplayClaimVerifierV1,
    S: PreparationStoreV1,
    P: RecoveryProviderV1,
    T: PreparationTimeSourceV1,
{
    if caller_deadline_monotonic_ms > MAX_SAFE_U64 {
        return denied(PreparationDenialV1::VersionUnsupported).into();
    }
    let attempt = match PreparationAttemptIdV1::generate() {
        Ok(attempt) => attempt,
        Err(_) => return denied(PreparationDenialV1::ContextUnavailable).into(),
    };
    reach!(PreliminaryAttemptIdentityGenerated)(fault_probe);

    let preliminary_capture =
        authority.capture_preliminary(&eligible, &attempt, caller_deadline_monotonic_ms);
    reach!(PreliminaryContextReturned)(fault_probe);
    let preliminary = match compare_preliminary_context_before_replay_instrumented_v1(
        &eligible,
        &attempt,
        preliminary_capture,
        caller_deadline_monotonic_ms,
        || {
            reach!(PreliminaryFirstFailureGroupClassified)(fault_probe);
        },
    ) {
        Ok(context) => context,
        Err(reason) => return denied(reason).into(),
    };

    if let Err(reason) = verify_replay_v1(
        replay_verifier,
        &eligible,
        &preliminary,
        preliminary.effective_deadline_monotonic_ms(),
        false,
        fault_probe,
        || Ok(()),
    ) {
        return denied(reason).into();
    }

    let requested_budget = match requested_budget_v1(&eligible) {
        Ok(requested) => requested,
        Err(reason) => return denied(reason).into(),
    };
    let preliminary_preflight = run_preflight_v1(
        store,
        &eligible,
        &attempt,
        &preliminary,
        &requested_budget,
        false,
        fault_probe,
        || compare_preliminary_budget_v1(&eligible, &preliminary),
        || Ok(()),
    );
    if let Err(reason) = preliminary_preflight {
        return denied(reason).into();
    }
    if let Err(reason) = compare_preliminary_recovery_profile_v1(&eligible, &preliminary) {
        return denied(reason).into();
    }

    let mut recovery = match prepare_recovery_v1(
        recovery_provider,
        &eligible,
        &attempt,
        &preliminary,
        fault_probe,
    ) {
        Ok(recovery) => recovery,
        Err(refusal) => return refusal.into(),
    };

    let _recovery_slot = recovery.slot();
    let acquisition = acquire_final_guards_observed_v1(
        authority,
        &eligible,
        &attempt,
        preliminary.effective_deadline_monotonic_ms(),
        || reach!(FinalComparisonGuardAcquired)(fault_probe),
    );
    let mut guards = match classify_authority_guard_acquisition_v1(acquisition) {
        Ok(guards) => guards,
        Err(refusal) => {
            recovery.release();
            return guard_refusal_outcome_v1(refusal).into();
        }
    };

    let completion = run_guarded_v1(
        &eligible,
        &attempt,
        &preliminary,
        &requested_budget,
        &mut recovery,
        &mut guards,
        replay_verifier,
        store,
        recovery_provider,
        time_source,
        caller_deadline_monotonic_ms,
        fault_probe,
    );

    let outcome = match completion {
        Ok(receipt) => {
            reach!(AcknowledgementPositiveMarkerConstructed)(fault_probe);
            PreparationOutcomeV1::Prepared(PreparedOperationV1::new(eligible, receipt))
        }
        Err(refusal) => refusal.into(),
    };
    guards.release_reverse();
    recovery.release();
    reach!(AcknowledgementAllFinalGuardsReleased)(fault_probe);
    outcome
}

#[allow(clippy::too_many_arguments)]
fn run_guarded_v1<R, S, P, T, G>(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    preliminary: &ReadyPreparationContextV1,
    requested_budget: &BudgetVectorV1,
    recovery: &mut RecoveryCustodyV1<P::PublicationGuard>,
    guards: &mut G,
    replay_verifier: &R,
    store: &S,
    recovery_provider: &P,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
    fault_probe: &PreparationFaultProbeV1,
) -> PreparationResultV1<PreparationCommitReceiptV1>
where
    R: ReplayClaimVerifierV1,
    S: PreparationStoreV1,
    P: RecoveryProviderV1,
    T: PreparationTimeSourceV1,
    G: AuthorityGuardSetV1,
{
    let deadline = preliminary.effective_deadline_monotonic_ms();
    let final_capture = guards.capture_final(eligible, attempt, deadline);
    reach!(FinalComparisonContextReturned)(fault_probe);
    let final_context = compare_final_context_before_guards_instrumented_v1(
        eligible,
        attempt,
        preliminary,
        final_capture,
        caller_deadline_monotonic_ms,
        || {
            reach!(FinalComparisonFirstFailureGroupClassified)(fault_probe);
        },
    )
    .map_err(denied)?;

    classify_authority_guard_validation_v1(
        guards.validate_all(final_context.sampled_monotonic_ms(), deadline),
    )
    .map_err(guard_refusal_outcome_v1)?;
    compare_final_context_authority_after_guards_instrumented_v1(eligible, &final_context, || {
        reach!(FinalComparisonFirstFailureGroupClassified)(fault_probe);
    })
    .map_err(denied)?;

    verify_replay_v1(
        replay_verifier,
        eligible,
        &final_context,
        deadline,
        true,
        fault_probe,
        || {
            classify_final_liveness_v1(
                &final_context,
                guards,
                time_source,
                caller_deadline_monotonic_ms,
                fault_probe,
            )
        },
    )
    .map_err(denied)?;
    let final_preflight = run_preflight_v1(
        store,
        eligible,
        attempt,
        &final_context,
        requested_budget,
        true,
        fault_probe,
        || compare_final_budget_v1(eligible, preliminary, &final_context),
        || {
            classify_final_liveness_v1(
                &final_context,
                guards,
                time_source,
                caller_deadline_monotonic_ms,
                fault_probe,
            )
        },
    )
    .map_err(denied)?;
    if let Err(reason) = compare_final_recovery_profile_v1(eligible, preliminary, &final_context) {
        classify_final_liveness_v1(
            &final_context,
            guards,
            time_source,
            caller_deadline_monotonic_ms,
            fault_probe,
        )
        .map_err(denied)?;
        return Err(denied(reason));
    }

    if let Err(refusal) = recovery.revalidate(
        recovery_provider,
        eligible,
        attempt,
        &final_context,
        deadline,
        fault_probe,
        true,
    ) {
        classify_final_liveness_v1(
            &final_context,
            guards,
            time_source,
            caller_deadline_monotonic_ms,
            fault_probe,
        )
        .map_err(denied)?;
        return Err(refusal);
    }

    classify_final_liveness_v1(
        &final_context,
        guards,
        time_source,
        caller_deadline_monotonic_ms,
        fault_probe,
    )
    .map_err(denied)?;

    let commit_input = PreparationCommitInputV1::new(
        eligible,
        attempt,
        &final_context,
        requested_budget,
        &final_preflight,
        recovery.evidence(),
    );
    let commit_outcome = {
        let mut final_gate = CombinedFinalCommitGateV1 {
            authority_guards: guards,
            recovery_slot: recovery.slot(),
            attempt,
            deadline_monotonic_ms: deadline,
            fault_probe,
        };
        store.commit_preparing(&commit_input, &mut final_gate)
    };
    match commit_outcome {
        PreparationCommitOutcomeV1::Committed(receipt) => {
            validate_commit_receipt_v1(attempt, &receipt)
                .map_err(|_| ambiguous(AmbiguousPreparationV1::CommitClassificationMissing))?;
            post_commit_all_guards_v1(
                &final_context,
                guards,
                recovery,
                recovery_provider,
                eligible,
                attempt,
                time_source,
                caller_deadline_monotonic_ms,
                fault_probe,
            )?;
            Ok(receipt)
        }
        PreparationCommitOutcomeV1::ConfirmedRollback => {
            Err(failed(PreparationFailureV1::CommitAborted))
        }
        PreparationCommitOutcomeV1::Uncertain { token, in_flight } => {
            if token.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1
                || token.attempt_id() != attempt.digest()
            {
                let _ = in_flight.resolve_readback_instrumented_v1(
                    FinalCommitReadbackResolutionV1::Inconclusive,
                );
                return Err(ambiguous(
                    AmbiguousPreparationV1::CommitClassificationMissing,
                ));
            }
            let readback_input = PreparationReadbackInputV1::new(eligible, attempt, &token);
            let readback = store.readback_attempt(&readback_input);
            let mut timely = || {
                post_commit_all_guards_v1(
                    &final_context,
                    guards,
                    recovery,
                    recovery_provider,
                    eligible,
                    attempt,
                    time_source,
                    caller_deadline_monotonic_ms,
                    fault_probe,
                )
            };
            let (readback_resolution, decision) = match readback {
                PreparationReadbackOutcomeV1::ThisAttempt(receipt) => {
                    if validate_commit_receipt_v1(attempt, &receipt).is_err() {
                        (
                            FinalCommitReadbackResolutionV1::Inconclusive,
                            UncertainReadbackDecisionV1::Ambiguous(ambiguous(
                                AmbiguousPreparationV1::ReadbackInconsistent,
                            )),
                        )
                    } else if let Err(refusal) = timely() {
                        (
                            FinalCommitReadbackResolutionV1::LateOrRevoked,
                            UncertainReadbackDecisionV1::Ambiguous(refusal),
                        )
                    } else {
                        (
                            FinalCommitReadbackResolutionV1::ThisAttemptCommitted,
                            UncertainReadbackDecisionV1::Committed(receipt),
                        )
                    }
                }
                PreparationReadbackOutcomeV1::PriorExactAttempt => {
                    if let Err(refusal) = timely() {
                        (
                            FinalCommitReadbackResolutionV1::LateOrRevoked,
                            UncertainReadbackDecisionV1::Ambiguous(refusal),
                        )
                    } else {
                        (
                            FinalCommitReadbackResolutionV1::PriorExactAttempt,
                            UncertainReadbackDecisionV1::Aborted(denied(
                                PreparationDenialV1::AlreadyPrepared,
                            )),
                        )
                    }
                }
                PreparationReadbackOutcomeV1::Conflict => {
                    if let Err(refusal) = timely() {
                        (
                            FinalCommitReadbackResolutionV1::LateOrRevoked,
                            UncertainReadbackDecisionV1::Ambiguous(refusal),
                        )
                    } else {
                        (
                            FinalCommitReadbackResolutionV1::Conflict,
                            UncertainReadbackDecisionV1::Aborted(denied(
                                PreparationDenialV1::OperationConflict,
                            )),
                        )
                    }
                }
                PreparationReadbackOutcomeV1::DefiniteAbsence => {
                    if let Err(refusal) = timely() {
                        (
                            FinalCommitReadbackResolutionV1::LateOrRevoked,
                            UncertainReadbackDecisionV1::Ambiguous(refusal),
                        )
                    } else {
                        (
                            FinalCommitReadbackResolutionV1::DefinitelyAbsent,
                            UncertainReadbackDecisionV1::Aborted(failed(
                                PreparationFailureV1::DefiniteAbsence,
                            )),
                        )
                    }
                }
                PreparationReadbackOutcomeV1::Unavailable => (
                    FinalCommitReadbackResolutionV1::Inconclusive,
                    UncertainReadbackDecisionV1::Ambiguous(ambiguous(
                        AmbiguousPreparationV1::ReadbackUnavailable,
                    )),
                ),
                PreparationReadbackOutcomeV1::Ambiguous
                | PreparationReadbackOutcomeV1::Unhealthy => (
                    FinalCommitReadbackResolutionV1::Inconclusive,
                    UncertainReadbackDecisionV1::Ambiguous(ambiguous(
                        AmbiguousPreparationV1::ReadbackInconsistent,
                    )),
                ),
            };
            let terminal = in_flight.resolve_readback_instrumented_v1(readback_resolution);
            match (decision, terminal) {
                (
                    UncertainReadbackDecisionV1::Committed(receipt),
                    FinalCommitTerminalResolutionV1::Committed,
                ) => Ok(receipt),
                (
                    UncertainReadbackDecisionV1::Aborted(refusal),
                    FinalCommitTerminalResolutionV1::Aborted,
                ) => Err(refusal),
                (UncertainReadbackDecisionV1::Ambiguous(refusal), _) => Err(refusal),
                _ => Err(ambiguous(AmbiguousPreparationV1::ReadbackLateOrRevoked)),
            }
        }
        PreparationCommitOutcomeV1::PermitRevoked
        | PreparationCommitOutcomeV1::PermitUnavailable => {
            Err(denied(PreparationDenialV1::GuardRevoked))
        }
        PreparationCommitOutcomeV1::PermitDeadlineReached => {
            Err(denied(PreparationDenialV1::DeadlineReached))
        }
        PreparationCommitOutcomeV1::PermitUnsupported => {
            Err(denied(PreparationDenialV1::ContextUnsupported))
        }
        PreparationCommitOutcomeV1::Unclassified => Err(ambiguous(
            AmbiguousPreparationV1::CommitClassificationMissing,
        )),
        PreparationCommitOutcomeV1::Unavailable => {
            Err(failed(PreparationFailureV1::StoreUnavailable))
        }
        PreparationCommitOutcomeV1::Busy => Err(failed(PreparationFailureV1::StoreBusy)),
        PreparationCommitOutcomeV1::Unhealthy => Err(failed(PreparationFailureV1::StoreUnhealthy)),
        PreparationCommitOutcomeV1::OperationConflict => {
            Err(denied(PreparationDenialV1::OperationConflict))
        }
        PreparationCommitOutcomeV1::AlreadyPrepared => {
            Err(denied(PreparationDenialV1::AlreadyPrepared))
        }
        PreparationCommitOutcomeV1::Conflict => Err(failed(PreparationFailureV1::StoreConflict)),
        PreparationCommitOutcomeV1::BudgetScopeMissing => {
            Err(denied(PreparationDenialV1::BudgetScopeMissing))
        }
        PreparationCommitOutcomeV1::BudgetBindingConflict => {
            Err(denied(PreparationDenialV1::BudgetBindingConflict))
        }
        PreparationCommitOutcomeV1::BudgetArithmeticInvalid => {
            Err(denied(PreparationDenialV1::BudgetArithmeticInvalid))
        }
        PreparationCommitOutcomeV1::BudgetExhausted => {
            Err(denied(PreparationDenialV1::BudgetExhausted))
        }
    }
}

fn verify_replay_v1<R, L>(
    replay_verifier: &R,
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
    deadline_monotonic_ms: u64,
    final_phase: bool,
    fault_probe: &PreparationFaultProbeV1,
    classify_liveness_before_failure: L,
) -> Result<(), PreparationDenialV1>
where
    R: ReplayClaimVerifierV1,
    L: FnOnce() -> Result<(), PreparationDenialV1>,
{
    if final_phase {
        reach!(FinalComparisonReplaySnapshotOpened)(fault_probe);
    } else {
        reach!(PreliminaryReplaySnapshotOpened)(fault_probe);
    }
    let outcome = replay_verifier
        .verify_exact_claim(&eligible.replay_verification_view(), deadline_monotonic_ms);
    if final_phase {
        reach!(FinalComparisonReplaySnapshotClassified)(fault_probe);
    } else {
        reach!(PreliminaryReplaySnapshotClassified)(fault_probe);
    }
    let context_binding = compare_context_replay_binding_v1(eligible, context);
    let classified = match outcome {
        ReplayClaimVerificationV1::Exact => Ok(()),
        ReplayClaimVerificationV1::Missing => Err(PreparationDenialV1::ReplayMissing),
        ReplayClaimVerificationV1::Conflict => Err(PreparationDenialV1::ReplayConflict),
        ReplayClaimVerificationV1::Unavailable => Err(PreparationDenialV1::ReplayUnavailable),
        ReplayClaimVerificationV1::Unhealthy => Err(PreparationDenialV1::ReplayUnhealthy),
    };
    let result = match classified {
        Err(PreparationDenialV1::ReplayMissing) => Err(PreparationDenialV1::ReplayMissing),
        other => context_binding.and(other),
    };
    if result.is_err() {
        classify_liveness_before_failure()?;
    }
    result
}

fn requested_budget_v1(eligible: &EligiblePlanV1) -> Result<BudgetVectorV1, PreparationDenialV1> {
    let claims = eligible.authentic().preparation_claims();
    let budget = claims.budget();
    BudgetVectorV1::try_new(BudgetVectorInputV1 {
        max_cost_micro_units: budget.max_cost_micro_units(),
        action_limit: budget.action_limit(),
        egress_bytes_limit: budget.egress_bytes_limit(),
        recovery_bytes: claims.recovery_reserved_bytes(),
    })
    .map_err(|_| PreparationDenialV1::BudgetArithmeticInvalid)
}

#[allow(clippy::too_many_arguments)]
fn run_preflight_v1<'input, S, B, L>(
    store: &S,
    eligible: &'input EligiblePlanV1,
    attempt: &'input PreparationAttemptIdV1,
    context: &'input ReadyPreparationContextV1,
    requested_budget: &'input BudgetVectorV1,
    final_phase: bool,
    fault_probe: &PreparationFaultProbeV1,
    compare_context_budget: B,
    classify_liveness_before_failure: L,
) -> Result<BudgetPreflightV1, PreparationDenialV1>
where
    S: PreparationStoreV1,
    B: FnOnce() -> Result<(), PreparationDenialV1>,
    L: FnOnce() -> Result<(), PreparationDenialV1>,
{
    if final_phase {
        reach!(FinalComparisonPreflightSnapshotOpened)(fault_probe);
    } else {
        reach!(PreliminaryPreflightSnapshotOpened)(fault_probe);
    }
    let input = PreparationPreflightInputV1::new(eligible, attempt, context, requested_budget);
    let outcome = store.preflight_operation_and_budget(&input);
    if final_phase {
        reach!(FinalComparisonOperationIdentityClassified)(fault_probe);
    } else {
        reach!(PreliminaryOperationIdentityClassified)(fault_probe);
    }
    let result = (|| -> Result<BudgetPreflightV1, PreparationDenialV1> {
        match outcome {
            PreparationPreflightOutcomeV1::Ready(preflight) => {
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Binding,
                    fault_probe,
                    compare_context_budget()
                        .and_then(|()| validate_budget_preflight_binding_v1(context, &preflight)),
                )?;
                // `Ready` is the store's positive checked-arithmetic classification.
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Arithmetic,
                    fault_probe,
                    Ok(()),
                )?;
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Capacity,
                    fault_probe,
                    validate_budget_preflight_capacity_v1(requested_budget, &preflight),
                )?;
                Ok(preflight)
            }
            PreparationPreflightOutcomeV1::OperationAuthorityUnavailable => {
                Err(PreparationDenialV1::OperationAuthorityUnavailable)
            }
            PreparationPreflightOutcomeV1::OperationConflict => {
                Err(PreparationDenialV1::OperationConflict)
            }
            PreparationPreflightOutcomeV1::AlreadyPrepared => {
                Err(PreparationDenialV1::AlreadyPrepared)
            }
            PreparationPreflightOutcomeV1::BudgetScopeMissing => observe_budget_preflight_group_v1(
                final_phase,
                BudgetPreflightGroupV1::Binding,
                fault_probe,
                Err(PreparationDenialV1::BudgetScopeMissing),
            ),
            PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable => {
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Binding,
                    fault_probe,
                    Err(PreparationDenialV1::BudgetAuthorityUnavailable),
                )
            }
            PreparationPreflightOutcomeV1::BudgetBindingConflict => {
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Binding,
                    fault_probe,
                    compare_context_budget().and(Err(PreparationDenialV1::BudgetBindingConflict)),
                )
            }
            PreparationPreflightOutcomeV1::BudgetArithmeticInvalid => {
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Binding,
                    fault_probe,
                    compare_context_budget(),
                )?;
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Arithmetic,
                    fault_probe,
                    Err(PreparationDenialV1::BudgetArithmeticInvalid),
                )
            }
            PreparationPreflightOutcomeV1::BudgetExhausted => {
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Binding,
                    fault_probe,
                    compare_context_budget(),
                )?;
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Arithmetic,
                    fault_probe,
                    Ok(()),
                )?;
                observe_budget_preflight_group_v1(
                    final_phase,
                    BudgetPreflightGroupV1::Capacity,
                    fault_probe,
                    Err(PreparationDenialV1::BudgetExhausted),
                )
            }
        }
    })();
    if result.is_err() {
        classify_liveness_before_failure()?;
    }
    result
}

#[derive(Clone, Copy)]
enum BudgetPreflightGroupV1 {
    Binding,
    Arithmetic,
    Capacity,
}

fn observe_budget_preflight_group_v1<T>(
    final_phase: bool,
    group: BudgetPreflightGroupV1,
    fault_probe: &PreparationFaultProbeV1,
    classified: Result<T, PreparationDenialV1>,
) -> Result<T, PreparationDenialV1> {
    match (final_phase, group) {
        (true, BudgetPreflightGroupV1::Binding) => {
            reach!(FinalComparisonBudgetBindingClassified)(fault_probe);
        }
        (true, BudgetPreflightGroupV1::Arithmetic) => {
            reach!(FinalComparisonBudgetArithmeticClassified)(fault_probe);
        }
        (true, BudgetPreflightGroupV1::Capacity) => {
            reach!(FinalComparisonBudgetCapacityClassified)(fault_probe);
        }
        (false, BudgetPreflightGroupV1::Binding) => {
            reach!(PreliminaryBudgetBindingClassified)(fault_probe);
        }
        (false, BudgetPreflightGroupV1::Arithmetic) => {
            reach!(PreliminaryBudgetArithmeticClassified)(fault_probe);
        }
        (false, BudgetPreflightGroupV1::Capacity) => {
            reach!(PreliminaryBudgetCapacityClassified)(fault_probe);
        }
    }
    classified
}

fn validate_budget_preflight_binding_v1(
    context: &ReadyPreparationContextV1,
    preflight: &BudgetPreflightV1,
) -> Result<(), PreparationDenialV1> {
    if preflight.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1 {
        return Err(PreparationDenialV1::VersionUnsupported);
    }
    if preflight.observed_scope_generation() != context.budget_scope_generation()
        || preflight.observed_scope_binding_digest() != context.budget_scope_binding_digest()
    {
        return Err(PreparationDenialV1::BudgetBindingConflict);
    }
    Ok(())
}

fn validate_budget_preflight_capacity_v1(
    requested: &BudgetVectorV1,
    preflight: &BudgetPreflightV1,
) -> Result<(), PreparationDenialV1> {
    let remaining = preflight.observed_remaining();
    if requested.max_cost_micro_units() > remaining.max_cost_micro_units()
        || requested.action_limit() > remaining.action_limit()
        || requested.egress_bytes_limit() > remaining.egress_bytes_limit()
        || requested.recovery_bytes() > remaining.recovery_bytes()
    {
        return Err(PreparationDenialV1::BudgetExhausted);
    }
    Ok(())
}

enum RecoveryCustodyV1<G> {
    Material {
        guard: G,
        evidence: RecoveryEvidenceV1,
        slot: RecoveryPublicationGuardSlotV1,
    },
    Irreversible {
        evidence: RecoveryEvidenceV1,
        slot: RecoveryPublicationGuardSlotV1,
    },
}

impl<G: RecoveryPublicationGuardV1> RecoveryCustodyV1<G> {
    fn evidence(&self) -> &RecoveryEvidenceV1 {
        match self {
            Self::Material { evidence, .. } | Self::Irreversible { evidence, .. } => evidence,
        }
    }

    fn slot(&self) -> &RecoveryPublicationGuardSlotV1 {
        match self {
            Self::Material { slot, .. } | Self::Irreversible { slot, .. } => slot,
        }
    }

    #[allow(clippy::too_many_arguments)] // Keeps one exact custody/probe path for both checks.
    fn revalidate<P: RecoveryProviderV1<PublicationGuard = G>>(
        &mut self,
        provider: &P,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        final_context: &ReadyPreparationContextV1,
        deadline_monotonic_ms: u64,
        fault_probe: &PreparationFaultProbeV1,
        observe_final_comparison_boundaries: bool,
    ) -> PreparationResultV1<()> {
        match self {
            Self::Material {
                guard, evidence, ..
            } => {
                let RecoveryEvidenceV1::Material(receipt) = evidence else {
                    return Err(ambiguous(AmbiguousPreparationV1::ReadbackInconsistent));
                };
                validate_material_binding_v1(eligible, attempt, final_context, receipt)
                    .map_err(denied)?;
                if observe_final_comparison_boundaries {
                    reach!(FinalComparisonRecoveryReceiptReopened)(fault_probe);
                }
                let verification = provider.verify_published(guard, receipt, deadline_monotonic_ms);
                if observe_final_comparison_boundaries {
                    reach!(FinalComparisonRecoveryReceiptRevalidated)(fault_probe);
                }
                classify_recovery_verification_v1(verification)
            }
            Self::Irreversible { evidence, .. } => {
                if observe_final_comparison_boundaries {
                    reach!(FinalComparisonRecoveryReceiptReopened)(fault_probe);
                }
                let RecoveryEvidenceV1::Irreversible(irreversible) = evidence else {
                    if observe_final_comparison_boundaries {
                        reach!(FinalComparisonRecoveryReceiptRevalidated)(fault_probe);
                    }
                    return Err(ambiguous(AmbiguousPreparationV1::ReadbackInconsistent));
                };
                if irreversible.contract_version() != RECOVERY_RECEIPT_CONTRACT_VERSION_V1 {
                    if observe_final_comparison_boundaries {
                        reach!(FinalComparisonRecoveryReceiptRevalidated)(fault_probe);
                    }
                    return Err(denied(PreparationDenialV1::VersionUnsupported));
                }
                let claims = eligible.authentic().preparation_claims();
                if irreversible.recovery_class() != claims.recovery_class()
                    || irreversible.atomicity() != claims.atomicity()
                    || !irreversible.no_material()
                    || final_context.recovery_provider().is_some()
                {
                    if observe_final_comparison_boundaries {
                        reach!(FinalComparisonRecoveryReceiptRevalidated)(fault_probe);
                    }
                    return Err(denied(PreparationDenialV1::RecoveryBindingConflict));
                }
                if observe_final_comparison_boundaries {
                    reach!(FinalComparisonRecoveryReceiptRevalidated)(fault_probe);
                }
                Ok(())
            }
        }
    }

    fn release(self) {
        if let Self::Material { guard, .. } = self {
            guard.release();
        }
    }
}

/// Commit gate composed from the already-held recovery-publication slot and the nine
/// remaining authority guards. It borrows both through permit entry, so Phase D cannot
/// reacquire the non-reentrant publication lock or omit its final revalidation.
struct CombinedFinalCommitGateV1<'guard, G> {
    authority_guards: &'guard mut G,
    recovery_slot: &'guard RecoveryPublicationGuardSlotV1,
    attempt: &'guard PreparationAttemptIdV1,
    deadline_monotonic_ms: u64,
    fault_probe: &'guard PreparationFaultProbeV1,
}

#[cfg(not(feature = "test-fault-injection"))]
impl<G> FinalCommitGateV1 for CombinedFinalCommitGateV1<'_, G>
where
    G: AuthorityGuardSetV1,
{
    type Permit = G::Permit;

    fn enter_commit_permit(
        &mut self,
        request: &FinalCommitPermitRequestV1<'_>,
    ) -> FinalCommitPermitOutcomeV1<Self::Permit> {
        if request.attempt().digest() != self.attempt.digest()
            || request.caller_deadline_monotonic_ms() > self.deadline_monotonic_ms
        {
            return FinalCommitPermitOutcomeV1::Revoked;
        }
        // This borrow proves that the exact Phase-B custody remains live through permit
        // entry. Its receipt was reopened/revalidated immediately before this boundary;
        // the exclusive provider guard prevents a second publication mutation.
        let _held_recovery_slot = self.recovery_slot;
        self.authority_guards.enter_commit_permit(request)
    }
}

#[cfg(feature = "test-fault-injection")]
impl<G> FinalCommitGateV1 for CombinedFinalCommitGateV1<'_, G>
where
    G: AuthorityGuardSetV1,
{
    type Permit = FaultProbedFinalCommitPermitV1<G::Permit>;

    fn enter_commit_permit(
        &mut self,
        request: &FinalCommitPermitRequestV1<'_>,
    ) -> FinalCommitPermitOutcomeV1<Self::Permit> {
        if request.attempt().digest() != self.attempt.digest()
            || request.caller_deadline_monotonic_ms() > self.deadline_monotonic_ms
        {
            return FinalCommitPermitOutcomeV1::Revoked;
        }
        let _held_recovery_slot = self.recovery_slot;
        let outcome = self.authority_guards.enter_commit_permit(request);
        reach_fault_probed_commit_permit_returned_v1(self.fault_probe);
        match outcome {
            FinalCommitPermitOutcomeV1::Permitted(permit) => FinalCommitPermitOutcomeV1::Permitted(
                FaultProbedFinalCommitPermitV1::new(permit, self.fault_probe.clone()),
            ),
            FinalCommitPermitOutcomeV1::Revoked => FinalCommitPermitOutcomeV1::Revoked,
            FinalCommitPermitOutcomeV1::Unavailable => FinalCommitPermitOutcomeV1::Unavailable,
            FinalCommitPermitOutcomeV1::DeadlineReached => {
                FinalCommitPermitOutcomeV1::DeadlineReached
            }
            FinalCommitPermitOutcomeV1::Unsupported => FinalCommitPermitOutcomeV1::Unsupported,
        }
    }
}

fn prepare_recovery_v1<P: RecoveryProviderV1>(
    provider: &P,
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    preliminary: &ReadyPreparationContextV1,
    fault_probe: &PreparationFaultProbeV1,
) -> PreparationResultV1<RecoveryCustodyV1<P::PublicationGuard>> {
    let claims = eligible.authentic().preparation_claims();
    if claims.recovery_class() == RecoveryClassV1::Irreversible {
        let evidence = IrreversibilityEvidenceV1::try_new(
            eligible.authentic().eligibility_claims().risk_level(),
            claims.recovery_class(),
            claims.atomicity(),
        )
        .map_err(|_| denied(PreparationDenialV1::RecoveryBindingConflict))?;
        let slot = record_recovery_publication_guard_v1();
        reach!(FinalComparisonGuardAcquired)(fault_probe);
        return Ok(RecoveryCustodyV1::Irreversible {
            evidence: RecoveryEvidenceV1::Irreversible(evidence),
            slot,
        });
    }

    let binding = RecoveryBindingV1::try_new(RecoveryBindingInputV1 {
        contract_version: RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
        claims,
        attempt,
        context: preliminary,
        deadline_monotonic_ms: preliminary.effective_deadline_monotonic_ms(),
    })
    .map_err(|_| denied(PreparationDenialV1::VersionUnsupported))?;
    let mut guard = match provider
        .acquire_publication_guard(&binding, preliminary.effective_deadline_monotonic_ms())
    {
        RecoveryGuardOutcomeV1::Acquired(guard) => guard,
        RecoveryGuardOutcomeV1::Unavailable => {
            return Err(failed(PreparationFailureV1::RecoveryProviderFailed))
        }
        RecoveryGuardOutcomeV1::DeadlineReached => {
            return Err(denied(PreparationDenialV1::DeadlineReached))
        }
        RecoveryGuardOutcomeV1::Conflict => {
            return Err(denied(PreparationDenialV1::RecoveryBindingConflict))
        }
        RecoveryGuardOutcomeV1::Unsupported => {
            return Err(denied(PreparationDenialV1::RecoveryProfileUnapproved))
        }
    };
    let slot = record_recovery_publication_guard_v1();
    reach!(FinalComparisonGuardAcquired)(fault_probe);
    let preparation_input = RecoveryPreparationInputV1::new(&binding);
    let receipt = match provider.prepare_and_publish(&mut guard, &preparation_input) {
        RecoveryPreparationOutcomeV1::Published(receipt) => receipt,
        RecoveryPreparationOutcomeV1::BindingConflict => {
            guard.release();
            return Err(denied(PreparationDenialV1::RecoveryBindingConflict));
        }
        RecoveryPreparationOutcomeV1::Unverified => {
            guard.release();
            return Err(denied(PreparationDenialV1::RecoveryUnverified));
        }
        RecoveryPreparationOutcomeV1::ProviderFailed => {
            guard.release();
            return Err(failed(PreparationFailureV1::RecoveryProviderFailed));
        }
        RecoveryPreparationOutcomeV1::Ambiguous => {
            guard.release();
            return Err(ambiguous(
                AmbiguousPreparationV1::RecoveryPublicationUnclassified,
            ));
        }
    };
    if let Err(reason) = validate_material_binding_v1(eligible, attempt, preliminary, &receipt) {
        guard.release();
        return Err(denied(reason));
    }
    if let Err(outcome) = classify_recovery_verification_v1(provider.verify_published(
        &mut guard,
        &receipt,
        preliminary.effective_deadline_monotonic_ms(),
    )) {
        guard.release();
        return Err(outcome);
    }
    Ok(RecoveryCustodyV1::Material {
        guard,
        evidence: RecoveryEvidenceV1::Material(receipt),
        slot,
    })
}

fn validate_material_binding_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    context: &ReadyPreparationContextV1,
    receipt: &RecoveryMaterialReceiptV1,
) -> Result<(), PreparationDenialV1> {
    if receipt.contract_version() != RECOVERY_RECEIPT_CONTRACT_VERSION_V1
        || receipt.provider_profile_version() != RECOVERY_PROVIDER_CONTRACT_VERSION_V1
    {
        return Err(PreparationDenialV1::VersionUnsupported);
    }
    let Some(expected_provider) = context.recovery_provider() else {
        return Err(PreparationDenialV1::RecoveryProfileUnapproved);
    };
    let evidence_class_matches = match receipt.evidence_class() {
        RecoveryEvidenceClassV1::SyntheticConformance => matches!(
            expected_provider.evidence_class(),
            "synthetic-conformance" | "SYNTHETIC_CONFORMANCE"
        ),
        RecoveryEvidenceClassV1::ApprovedProduction => !matches!(
            expected_provider.evidence_class(),
            "synthetic-conformance" | "SYNTHETIC_CONFORMANCE"
        ),
    };
    if receipt.provider_profile_id() != expected_provider.profile_id()
        || !evidence_class_matches
        || receipt.at_rest_profile_id() != expected_provider.at_rest_profile_id()
    {
        return Err(PreparationDenialV1::RecoveryProfileUnapproved);
    }
    let claims = eligible.authentic().preparation_claims();
    let target_reference_digest = recovery_target_reference_digest_v1(claims.target())
        .map_err(|_| PreparationDenialV1::RecoveryBindingConflict)?;
    let precondition_identity_digest = recovery_precondition_identity_digest_v1(
        claims.precondition_volume_id(),
        claims.precondition_file_id(),
    )
    .map_err(|_| PreparationDenialV1::RecoveryBindingConflict)?;
    let boot_binding_digest = recovery_boot_binding_digest_v1(
        context.boot_id(),
        context.instance_epoch(),
        context.fencing_epoch(),
    )
    .map_err(|_| PreparationDenialV1::RecoveryBindingConflict)?;
    if receipt.provider_id() != expected_provider.provider_id()
        || receipt.provider_generation() != expected_provider.provider_generation()
        || receipt.capability_binding_digest() != expected_provider.capability_binding_digest()
        || receipt.plan_id() != claims.plan_id()
        || receipt.operation_id() != claims.operation_id()
        || receipt.attempt_id() != attempt.digest()
        || receipt.target_reference_digest() != target_reference_digest
        || receipt.precondition_identity_digest() != precondition_identity_digest
        || receipt.precondition_digest() != claims.precondition_content_sha256()
        || receipt.precondition_length() != claims.precondition_byte_length()
        || receipt.recovery_class() != claims.recovery_class()
        || receipt.atomicity() != claims.atomicity()
        || receipt.boot_binding_digest() != boot_binding_digest
        || receipt.instance_epoch() != context.instance_epoch()
        || receipt.fencing_epoch() != context.fencing_epoch()
    {
        return Err(PreparationDenialV1::RecoveryBindingConflict);
    }
    if receipt.material_digest() != claims.precondition_content_sha256()
        || claims.preimage_sha256() != Some(receipt.material_digest())
        || receipt.material_length() != claims.precondition_byte_length()
        || receipt.reserved_capacity() != claims.recovery_reserved_bytes()
        || receipt.reserved_capacity() < receipt.material_length()
        || receipt.state() != &RecoveryMaterialStateV1::Published
    {
        return Err(PreparationDenialV1::RecoveryUnverified);
    }
    Ok(())
}

fn classify_recovery_verification_v1(
    verification: RecoveryVerificationV1,
) -> PreparationResultV1<()> {
    match verification {
        RecoveryVerificationV1::Exact => Ok(()),
        RecoveryVerificationV1::Missing => Err(denied(PreparationDenialV1::RecoveryUnverified)),
        RecoveryVerificationV1::Conflict => {
            Err(denied(PreparationDenialV1::RecoveryBindingConflict))
        }
        RecoveryVerificationV1::Unavailable | RecoveryVerificationV1::Unhealthy => Err(ambiguous(
            AmbiguousPreparationV1::RecoveryPublicationUnclassified,
        )),
    }
}

fn classify_final_time_v1(
    context: &ReadyPreparationContextV1,
    utc_ms: u64,
    monotonic_ms: u64,
    caller_deadline_monotonic_ms: u64,
) -> Result<(), PreparationDenialV1> {
    if utc_ms < context.sampled_utc_ms() || monotonic_ms < context.sampled_monotonic_ms() {
        return Err(PreparationDenialV1::ClockMismatch);
    }
    if utc_ms >= context.effective_expires_at_utc_ms() {
        return Err(PreparationDenialV1::TimeExpired);
    }
    if monotonic_ms
        >= context
            .effective_deadline_monotonic_ms()
            .min(caller_deadline_monotonic_ms)
    {
        return Err(PreparationDenialV1::DeadlineReached);
    }
    Ok(())
}

fn classify_final_liveness_v1<T: PreparationTimeSourceV1, G: AuthorityGuardSetV1>(
    context: &ReadyPreparationContextV1,
    guards: &mut G,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
    fault_probe: &PreparationFaultProbeV1,
) -> Result<(), PreparationDenialV1> {
    let utc_ms = PreparationUtcClockV1::now_utc_ms(time_source)
        .map_err(|_| PreparationDenialV1::ClockMismatch)?;
    reach!(FinalComparisonUtcSampleReturned)(fault_probe);
    let monotonic_ms = PreparationMonotonicClockV1::now_monotonic_ms(time_source)
        .map_err(|_| PreparationDenialV1::ClockMismatch)?;
    reach!(FinalComparisonMonotonicSampleReturned)(fault_probe);
    classify_final_time_v1(context, utc_ms, monotonic_ms, caller_deadline_monotonic_ms)?;
    classify_authority_guard_validation_v1(guards.validate_all(
        monotonic_ms,
        caller_deadline_monotonic_ms.min(context.effective_deadline_monotonic_ms()),
    ))
    .map_err(|refusal| match refusal {
        AuthorityGuardRefusalV1::DeadlineReached => PreparationDenialV1::DeadlineReached,
        AuthorityGuardRefusalV1::Unsupported => PreparationDenialV1::ContextUnsupported,
        AuthorityGuardRefusalV1::Revoked | AuthorityGuardRefusalV1::Unavailable => {
            PreparationDenialV1::GuardRevoked
        }
    })
}

#[allow(clippy::question_mark, clippy::too_many_arguments)] // Error-path hook must run before return.
fn post_commit_all_guards_v1<T, G, P>(
    context: &ReadyPreparationContextV1,
    guards: &mut G,
    recovery: &mut RecoveryCustodyV1<P::PublicationGuard>,
    recovery_provider: &P,
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
    fault_probe: &PreparationFaultProbeV1,
) -> PreparationResultV1<()>
where
    T: PreparationTimeSourceV1,
    G: AuthorityGuardSetV1,
    P: RecoveryProviderV1,
{
    if let Err(refusal) = post_commit_checks_v1(
        context,
        guards,
        time_source,
        caller_deadline_monotonic_ms,
        fault_probe,
    ) {
        reach!(AcknowledgementPostCommitGuardsClassified)(fault_probe);
        return Err(refusal);
    }
    if recovery
        .revalidate(
            recovery_provider,
            eligible,
            attempt,
            context,
            context
                .effective_deadline_monotonic_ms()
                .min(caller_deadline_monotonic_ms),
            fault_probe,
            false,
        )
        .is_err()
    {
        reach!(AcknowledgementPostCommitGuardsClassified)(fault_probe);
        return Err(ambiguous(AmbiguousPreparationV1::ReadbackLateOrRevoked));
    }
    reach!(AcknowledgementPostCommitGuardsClassified)(fault_probe);
    Ok(())
}

fn post_commit_checks_v1<T: PreparationTimeSourceV1, G: AuthorityGuardSetV1>(
    context: &ReadyPreparationContextV1,
    guards: &mut G,
    time_source: &T,
    caller_deadline_monotonic_ms: u64,
    fault_probe: &PreparationFaultProbeV1,
) -> PreparationResultV1<()> {
    let utc_ms = PreparationUtcClockV1::now_utc_ms(time_source)
        .map_err(|_| ambiguous(AmbiguousPreparationV1::ReadbackLateOrRevoked))?;
    let monotonic_ms = PreparationMonotonicClockV1::now_monotonic_ms(time_source)
        .map_err(|_| ambiguous(AmbiguousPreparationV1::ReadbackLateOrRevoked))?;
    let time_is_live =
        classify_final_time_v1(context, utc_ms, monotonic_ms, caller_deadline_monotonic_ms).is_ok();
    reach!(AcknowledgementPostCommitTimeClassified)(fault_probe);
    if !time_is_live {
        return Err(ambiguous(AmbiguousPreparationV1::ReadbackLateOrRevoked));
    }
    let guards_are_live = classify_authority_guard_validation_v1(guards.validate_all(
        monotonic_ms,
        caller_deadline_monotonic_ms.min(context.effective_deadline_monotonic_ms()),
    ))
    .is_ok();
    if !guards_are_live {
        return Err(ambiguous(AmbiguousPreparationV1::ReadbackLateOrRevoked));
    }
    Ok(())
}

fn validate_commit_receipt_v1(
    attempt: &PreparationAttemptIdV1,
    receipt: &PreparationCommitReceiptV1,
) -> Result<(), ()> {
    if receipt.contract_version() != PREPARATION_STORE_CONTRACT_VERSION_V1
        || receipt.attempt_id() != attempt.digest()
        || receipt.store_generation() == 0
        || receipt.operation_state_generation() == 0
        || receipt.transition_generation() == 0
        || receipt.event_generation() == 0
        || receipt.budget_reservation().state() != &BudgetReservationStateV1::Held
        || receipt.budget_reservation().reservation_generation() == 0
    {
        return Err(());
    }
    Ok(())
}

fn guard_refusal_outcome_v1(refusal: AuthorityGuardRefusalV1) -> PreparationRefusalV1 {
    match refusal {
        AuthorityGuardRefusalV1::Revoked | AuthorityGuardRefusalV1::Unavailable => {
            denied(PreparationDenialV1::GuardRevoked)
        }
        AuthorityGuardRefusalV1::DeadlineReached => denied(PreparationDenialV1::DeadlineReached),
        AuthorityGuardRefusalV1::Unsupported => denied(PreparationDenialV1::ContextUnsupported),
    }
}

const fn denied(reason: PreparationDenialV1) -> PreparationRefusalV1 {
    PreparationRefusalV1::Denied(reason)
}

const fn failed(reason: PreparationFailureV1) -> PreparationRefusalV1 {
    PreparationRefusalV1::Failed(reason)
}

const fn ambiguous(reason: AmbiguousPreparationV1) -> PreparationRefusalV1 {
    PreparationRefusalV1::Ambiguous(reason)
}
