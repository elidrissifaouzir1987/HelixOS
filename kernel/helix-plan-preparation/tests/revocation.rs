mod common;

use common::{
    feature002, synthetic_eligible_plan_v1, DeterministicPreparationClockV1,
    SyntheticAuthorityGuardControlV1, SyntheticConformanceRecoveryProviderV1,
    SyntheticPermitDeadmanV1, SyntheticPermitStateV1, SyntheticPreparationAuthorityV1,
    SyntheticSupervisorPermitControlV1,
};
use helix_plan_eligibility::{
    ReplayClaimVerificationV1, ReplayClaimVerificationViewV1, ReplayClaimVerifierV1,
};
use helix_plan_preparation::{
    compute_final_commit_permit_deadline_v1, prepare_plan_v1, AmbiguousPreparationV1,
    BudgetPreflightInputV1, BudgetPreflightV1, BudgetReservationReceiptInputV1,
    BudgetReservationReceiptV1, BudgetReservationStateV1, BudgetVectorInputV1, BudgetVectorV1,
    FinalCommitGateV1, FinalCommitPermitOutcomeV1, FinalCommitPermitRequestInputV1,
    FinalCommitPermitRequestV1, FinalCommitPermitV1, FinalCommitResolutionV1,
    FinalCommitStoreClassificationV1, NoDispatchAuthorityGuardV1, PreparationCommitInputV1,
    PreparationCommitOutcomeV1, PreparationCommitReceiptInputV1, PreparationCommitReceiptV1,
    PreparationCommitUncertainV1, PreparationDenialV1, PreparationFailureInputV1,
    PreparationFailureOutcomeV1, PreparationFailureV1, PreparationMonotonicClockV1,
    PreparationOutcomeV1, PreparationPreflightInputV1, PreparationPreflightOutcomeV1,
    PreparationReadbackInputV1, PreparationReadbackOutcomeV1, PreparationStoreV1,
    PREPARATION_BUDGET_CONTRACT_VERSION_V1, PREPARATION_STORE_CONTRACT_VERSION_V1,
};
use std::sync::atomic::{AtomicUsize, Ordering};

const CALLER_DEADLINE: u64 = 60_000;

#[derive(Clone, Copy)]
enum ControlAction {
    Pause,
    Halt,
}

#[derive(Clone, Copy)]
enum CommitScript {
    AcknowledgedCommit,
    ControlBeforePermit(ControlAction),
    ControlAfterPermit(ControlAction),
    ConfirmedRollback,
    ExplicitUncertainty(UncertainReadbackScript),
    MissingClassification,
}

#[derive(Clone, Copy)]
enum UncertainReadbackScript {
    ThisAttempt,
    PriorExactAttempt,
    Conflict,
    DefiniteAbsence,
    Unavailable,
    Unhealthy,
    Ambiguous,
    Late,
    Revoked,
}

struct ExactReplayVerifier;

impl ReplayClaimVerifierV1 for ExactReplayVerifier {
    fn verify_exact_claim(
        &self,
        _view: &ReplayClaimVerificationViewV1<'_>,
        _deadline_monotonic_ms: u64,
    ) -> ReplayClaimVerificationV1 {
        ReplayClaimVerificationV1::Exact
    }
}

struct ScriptedStore {
    script: CommitScript,
    clock: DeterministicPreparationClockV1,
    supervisor: SyntheticSupervisorPermitControlV1,
    commit_calls: AtomicUsize,
    commit_invocations: AtomicUsize,
    readback_calls: AtomicUsize,
}

impl ScriptedStore {
    fn new(
        script: CommitScript,
        clock: DeterministicPreparationClockV1,
        supervisor: SyntheticSupervisorPermitControlV1,
    ) -> Self {
        Self {
            script,
            clock,
            supervisor,
            commit_calls: AtomicUsize::new(0),
            commit_invocations: AtomicUsize::new(0),
            readback_calls: AtomicUsize::new(0),
        }
    }

    fn activate_control(&self, action: ControlAction) {
        match action {
            ControlAction::Pause => self.supervisor.pause_test_only(),
            ControlAction::Halt => self.supervisor.halt_test_only(),
        }
    }

    fn committed_receipt(input: &PreparationCommitInputV1<'_>) -> PreparationCommitReceiptV1 {
        Self::committed_receipt_for(input.attempt().digest())
    }

    fn committed_receipt_for(
        attempt_id: helix_contracts::Sha256Digest,
    ) -> PreparationCommitReceiptV1 {
        let reservation = BudgetReservationReceiptV1::try_new(BudgetReservationReceiptInputV1 {
            contract_version: PREPARATION_BUDGET_CONTRACT_VERSION_V1,
            state: BudgetReservationStateV1::Held,
            reservation_generation: 1,
        })
        .expect("synthetic held reservation is valid");
        PreparationCommitReceiptV1::try_new(PreparationCommitReceiptInputV1 {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            attempt_id,
            store_generation: 1,
            operation_state_generation: 1,
            transition_generation: 1,
            event_generation: 1,
            budget_reservation: reservation,
        })
        .expect("synthetic commit receipt is valid")
    }
}

impl PreparationStoreV1 for ScriptedStore {
    fn preflight_operation_and_budget(
        &self,
        input: &PreparationPreflightInputV1<'_>,
    ) -> PreparationPreflightOutcomeV1 {
        let requested = input.requested_budget();
        let remaining = BudgetVectorV1::try_new(BudgetVectorInputV1 {
            max_cost_micro_units: requested.max_cost_micro_units(),
            action_limit: requested.action_limit(),
            egress_bytes_limit: requested.egress_bytes_limit(),
            recovery_bytes: requested.recovery_bytes(),
        })
        .expect("synthetic remaining budget is valid");
        PreparationPreflightOutcomeV1::Ready(
            BudgetPreflightV1::try_new(BudgetPreflightInputV1 {
                contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
                observed_scope_generation: input.context().budget_scope_generation(),
                observed_scope_binding_digest: input.context().budget_scope_binding_digest(),
                observed_remaining: remaining,
            })
            .expect("synthetic preflight is valid"),
        )
    }

    fn commit_preparing<G: FinalCommitGateV1>(
        &self,
        input: &PreparationCommitInputV1<'_>,
        final_gate: &mut G,
    ) -> PreparationCommitOutcomeV1<<G::Permit as FinalCommitPermitV1>::InFlight> {
        self.commit_calls.fetch_add(1, Ordering::SeqCst);
        if let CommitScript::ControlBeforePermit(action) = self.script {
            self.activate_control(action);
        }

        let entry = PreparationMonotonicClockV1::now_monotonic_ms(&self.clock)
            .expect("scripted monotonic clock is available");
        let request = FinalCommitPermitRequestV1::try_new(FinalCommitPermitRequestInputV1 {
            attempt: input.attempt(),
            expected_supervisor_generation: input.final_context().supervisor_generation(),
            caller_deadline_monotonic_ms: CALLER_DEADLINE,
            permit_entry_monotonic_ms: entry,
        })
        .expect("scripted permit request is valid");
        let permit = match final_gate.enter_commit_permit_instrumented_v1(&request) {
            FinalCommitPermitOutcomeV1::Permitted(permit) => permit,
            FinalCommitPermitOutcomeV1::Revoked => {
                return PreparationCommitOutcomeV1::PermitRevoked
            }
            FinalCommitPermitOutcomeV1::Unavailable => {
                return PreparationCommitOutcomeV1::PermitUnavailable
            }
            FinalCommitPermitOutcomeV1::DeadlineReached => {
                return PreparationCommitOutcomeV1::PermitDeadlineReached
            }
            FinalCommitPermitOutcomeV1::Unsupported => {
                return PreparationCommitOutcomeV1::PermitUnsupported
            }
        };

        let store_classification = match self.script {
            CommitScript::ConfirmedRollback => FinalCommitStoreClassificationV1::ConfirmedRollback,
            CommitScript::ExplicitUncertainty(_) => FinalCommitStoreClassificationV1::Uncertain,
            CommitScript::MissingClassification => FinalCommitStoreClassificationV1::Unclassified,
            CommitScript::AcknowledgedCommit
            | CommitScript::ControlBeforePermit(_)
            | CommitScript::ControlAfterPermit(_) => FinalCommitStoreClassificationV1::Committed,
        };
        let resolution = permit.commit_once_instrumented_v1(|| {
            self.commit_invocations.fetch_add(1, Ordering::SeqCst);
            if let CommitScript::ControlAfterPermit(action) = self.script {
                self.activate_control(action);
            }
            store_classification
        });
        match (self.script, resolution) {
            (CommitScript::ConfirmedRollback, FinalCommitResolutionV1::Aborted) => {
                PreparationCommitOutcomeV1::ConfirmedRollback
            }
            (
                CommitScript::ExplicitUncertainty(_),
                FinalCommitResolutionV1::Uncertain(in_flight),
            ) => PreparationCommitOutcomeV1::Uncertain {
                token: PreparationCommitUncertainV1::try_new(
                    PREPARATION_STORE_CONTRACT_VERSION_V1,
                    input.attempt().digest(),
                )
                .expect("synthetic uncertainty is valid"),
                in_flight,
            },
            (CommitScript::MissingClassification, FinalCommitResolutionV1::Ambiguous) => {
                PreparationCommitOutcomeV1::Unclassified
            }
            (CommitScript::ControlAfterPermit(_), FinalCommitResolutionV1::Committed) => {
                PreparationCommitOutcomeV1::Committed(Self::committed_receipt(input))
            }
            (CommitScript::AcknowledgedCommit, FinalCommitResolutionV1::Committed) => {
                PreparationCommitOutcomeV1::Committed(Self::committed_receipt(input))
            }
            _ => PreparationCommitOutcomeV1::Unclassified,
        }
    }

    fn readback_attempt(
        &self,
        input: &PreparationReadbackInputV1<'_>,
    ) -> PreparationReadbackOutcomeV1 {
        self.readback_calls.fetch_add(1, Ordering::SeqCst);
        match self.script {
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::ThisAttempt) => {
                PreparationReadbackOutcomeV1::ThisAttempt(Self::committed_receipt_for(
                    input.attempt().digest(),
                ))
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::PriorExactAttempt) => {
                PreparationReadbackOutcomeV1::PriorExactAttempt
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::Conflict) => {
                PreparationReadbackOutcomeV1::Conflict
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::DefiniteAbsence) => {
                PreparationReadbackOutcomeV1::DefiniteAbsence
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::Unavailable) => {
                PreparationReadbackOutcomeV1::Unavailable
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::Unhealthy) => {
                PreparationReadbackOutcomeV1::Unhealthy
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::Ambiguous) => {
                PreparationReadbackOutcomeV1::Ambiguous
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::Late) => {
                self.clock.set_monotonic_ms(CALLER_DEADLINE);
                PreparationReadbackOutcomeV1::ThisAttempt(Self::committed_receipt_for(
                    input.attempt().digest(),
                ))
            }
            CommitScript::ExplicitUncertainty(UncertainReadbackScript::Revoked) => {
                self.supervisor.pause_test_only();
                PreparationReadbackOutcomeV1::ThisAttempt(Self::committed_receipt_for(
                    input.attempt().digest(),
                ))
            }
            CommitScript::AcknowledgedCommit
            | CommitScript::ControlBeforePermit(_)
            | CommitScript::ControlAfterPermit(_)
            | CommitScript::ConfirmedRollback
            | CommitScript::MissingClassification => PreparationReadbackOutcomeV1::Ambiguous,
        }
    }

    fn fail_before_dispatch<G: NoDispatchAuthorityGuardV1>(
        &self,
        _input: &PreparationFailureInputV1<'_>,
        _no_dispatch_guard: &mut G,
    ) -> PreparationFailureOutcomeV1 {
        PreparationFailureOutcomeV1::Unavailable
    }
}

#[test]
fn acknowledged_commit_returns_the_one_shot_positive_marker_without_readback() {
    let result = run(CommitScript::AcknowledgedCommit);
    let PreparationOutcomeV1::Prepared(marker) = &result.outcome else {
        panic!("unexpected outcome: {:?}", result.outcome);
    };
    assert_eq!(format!("{marker:?}"), "PreparedOperationV1 { .. }");
    assert_eq!(
        format!("{:?}", result.outcome),
        "PreparationOutcomeV1::Prepared(..)"
    );
    assert!(
        matches!(&result.outcome, PreparationOutcomeV1::Prepared(_)),
        "unexpected outcome: {:?}",
        result.outcome
    );
    assert_eq!(result.commit_calls, 1);
    assert_eq!(result.commit_invocations, 1);
    assert_eq!(result.readback_calls, 0);
    assert_eq!(
        result.permit_state,
        SyntheticPermitStateV1::ResolvedCommitted
    );
    assert!(!result.paused);
    let remaining = helix_plan_preparation::AuthorityGuardKindV1::acquisition_order()[1..].to_vec();
    assert_eq!(result.acquisition_order, remaining);
    assert_eq!(
        result.release_order,
        remaining.iter().rev().copied().collect::<Vec<_>>()
    );
    assert_eq!(result.recovery_guard_releases, 1);
}

struct RunResult {
    outcome: PreparationOutcomeV1,
    commit_calls: usize,
    commit_invocations: usize,
    readback_calls: usize,
    permit_state: SyntheticPermitStateV1,
    paused: bool,
    acquisition_order: Vec<helix_plan_preparation::AuthorityGuardKindV1>,
    release_order: Vec<helix_plan_preparation::AuthorityGuardKindV1>,
    recovery_guard_releases: usize,
}

fn run(script: CommitScript) -> RunResult {
    let clock = DeterministicPreparationClockV1::coherent();
    let supervisor =
        SyntheticSupervisorPermitControlV1::new_test_only(feature002::SUPERVISOR_GENERATION);
    let deadman = supervisor.deadman_test_only();
    let guard_control = SyntheticAuthorityGuardControlV1::new_test_only();
    let authority = SyntheticPreparationAuthorityV1::new_test_only(
        clock.clone(),
        guard_control.clone(),
        supervisor.clone(),
    );
    let store = ScriptedStore::new(script, clock.clone(), supervisor.clone());
    let recovery_provider = SyntheticConformanceRecoveryProviderV1::default();
    let outcome = prepare_plan_v1(
        synthetic_eligible_plan_v1(),
        &authority,
        &ExactReplayVerifier,
        &store,
        &recovery_provider,
        &clock,
        CALLER_DEADLINE,
    );
    RunResult {
        outcome,
        commit_calls: store.commit_calls.load(Ordering::SeqCst),
        commit_invocations: store.commit_invocations.load(Ordering::SeqCst),
        readback_calls: store.readback_calls.load(Ordering::SeqCst),
        permit_state: supervisor.state_test_only(),
        paused: deadman.is_paused_test_only(),
        acquisition_order: guard_control.acquisition_order_test_only(),
        release_order: guard_control.release_order_test_only(),
        recovery_guard_releases: recovery_provider.released_guard_count_test_only(),
    }
}

#[test]
fn caller_deadline_first_is_the_exclusive_deadman_bound() {
    let deadline = compute_final_commit_permit_deadline_v1(50_100, 50_000).unwrap();
    assert_eq!(deadline, 50_100);
    let deadman = SyntheticPermitDeadmanV1::new_test_only();
    deadman.arm_test_only(deadline);
    assert!(!deadman.expire_if_due_test_only(deadline - 1));
    assert!(deadman.expire_if_due_test_only(deadline));
    assert!(deadman.is_paused_test_only());
}

#[test]
fn fixed_250_ms_ceiling_first_is_the_exclusive_deadman_bound() {
    let deadline = compute_final_commit_permit_deadline_v1(60_000, 50_000).unwrap();
    assert_eq!(deadline, 50_250);
    let deadman = SyntheticPermitDeadmanV1::new_test_only();
    deadman.arm_test_only(deadline);
    assert!(!deadman.expire_if_due_test_only(deadline - 1));
    assert!(deadman.expire_if_due_test_only(deadline));
}

#[test]
fn equality_resolves_once_to_ambiguous_pause_and_never_reuses_the_permit() {
    let deadman = SyntheticPermitDeadmanV1::new_test_only();
    deadman.arm_test_only(250);
    assert!(deadman.expire_if_due_test_only(250));
    assert!(!deadman.expire_if_due_test_only(251));
    assert!(deadman.is_paused_test_only());
}

#[test]
fn pause_or_halt_winning_before_permit_denies_without_invoking_commit() {
    for action in [ControlAction::Pause, ControlAction::Halt] {
        let result = run(CommitScript::ControlBeforePermit(action));
        assert!(
            matches!(
                &result.outcome,
                PreparationOutcomeV1::Denied(PreparationDenialV1::GuardRevoked)
            ),
            "unexpected outcome: {:?}",
            result.outcome
        );
        assert_eq!(result.commit_calls, 1);
        assert_eq!(result.commit_invocations, 0);
        assert_eq!(result.readback_calls, 0);
    }
}

#[test]
fn permit_winning_before_pause_or_halt_resolves_current_commit_then_returns_no_marker() {
    for action in [ControlAction::Pause, ControlAction::Halt] {
        let result = run(CommitScript::ControlAfterPermit(action));
        assert!(
            matches!(&result.outcome, PreparationOutcomeV1::Ambiguous(_)),
            "unexpected outcome: {:?}",
            result.outcome
        );
        assert_eq!(result.commit_invocations, 1);
        assert_eq!(
            result.permit_state,
            SyntheticPermitStateV1::ResolvedCommitted
        );
        assert!(result.paused);
    }
}

#[test]
fn confirmed_rollback_fails_immediately_and_performs_zero_readback() {
    let result = run(CommitScript::ConfirmedRollback);
    assert!(
        matches!(
            &result.outcome,
            PreparationOutcomeV1::Failed(PreparationFailureV1::CommitAborted)
        ),
        "unexpected outcome: {:?}",
        result.outcome
    );
    assert_eq!(result.readback_calls, 0);
    assert_eq!(result.permit_state, SyntheticPermitStateV1::ResolvedAborted);
}

#[test]
fn explicit_uncertainty_opens_one_fresh_readback_and_resolves_every_closed_class() {
    let cases = [
        UncertainReadbackScript::ThisAttempt,
        UncertainReadbackScript::PriorExactAttempt,
        UncertainReadbackScript::Conflict,
        UncertainReadbackScript::DefiniteAbsence,
        UncertainReadbackScript::Unavailable,
        UncertainReadbackScript::Unhealthy,
        UncertainReadbackScript::Ambiguous,
        UncertainReadbackScript::Late,
        UncertainReadbackScript::Revoked,
    ];

    for readback in cases {
        let result = run(CommitScript::ExplicitUncertainty(readback));
        let outcome_is_exact = match readback {
            UncertainReadbackScript::ThisAttempt => {
                matches!(&result.outcome, PreparationOutcomeV1::Prepared(_))
            }
            UncertainReadbackScript::PriorExactAttempt => matches!(
                &result.outcome,
                PreparationOutcomeV1::Denied(PreparationDenialV1::AlreadyPrepared)
            ),
            UncertainReadbackScript::Conflict => matches!(
                &result.outcome,
                PreparationOutcomeV1::Denied(PreparationDenialV1::OperationConflict)
            ),
            UncertainReadbackScript::DefiniteAbsence => matches!(
                &result.outcome,
                PreparationOutcomeV1::Failed(PreparationFailureV1::DefiniteAbsence)
            ),
            UncertainReadbackScript::Unavailable => matches!(
                &result.outcome,
                PreparationOutcomeV1::Ambiguous(AmbiguousPreparationV1::ReadbackUnavailable)
            ),
            UncertainReadbackScript::Unhealthy | UncertainReadbackScript::Ambiguous => matches!(
                &result.outcome,
                PreparationOutcomeV1::Ambiguous(AmbiguousPreparationV1::ReadbackInconsistent)
            ),
            UncertainReadbackScript::Late | UncertainReadbackScript::Revoked => matches!(
                &result.outcome,
                PreparationOutcomeV1::Ambiguous(AmbiguousPreparationV1::ReadbackLateOrRevoked)
            ),
        };
        assert!(outcome_is_exact, "unexpected outcome: {:?}", result.outcome);
        assert_eq!(result.commit_invocations, 1);
        assert_eq!(result.readback_calls, 1);
        let expected_terminal = match readback {
            UncertainReadbackScript::ThisAttempt => SyntheticPermitStateV1::ResolvedCommitted,
            UncertainReadbackScript::PriorExactAttempt
            | UncertainReadbackScript::Conflict
            | UncertainReadbackScript::DefiniteAbsence => SyntheticPermitStateV1::ResolvedAborted,
            UncertainReadbackScript::Unavailable
            | UncertainReadbackScript::Unhealthy
            | UncertainReadbackScript::Ambiguous
            | UncertainReadbackScript::Late
            | UncertainReadbackScript::Revoked => SyntheticPermitStateV1::ResolvedAmbiguous,
        };
        assert_eq!(result.permit_state, expected_terminal);
    }
}

#[test]
fn missing_classification_is_ambiguous_pause_with_zero_worker_readback() {
    let result = run(CommitScript::MissingClassification);
    assert!(
        matches!(
            &result.outcome,
            PreparationOutcomeV1::Ambiguous(AmbiguousPreparationV1::CommitClassificationMissing)
        ),
        "unexpected outcome: {:?}",
        result.outcome
    );
    assert_eq!(result.readback_calls, 0);
    assert!(result.paused);
}

#[test]
fn deterministic_deadman_resolves_owner_loss_once_and_blocks_reuse() {
    let deadman = SyntheticPermitDeadmanV1::new_test_only();
    deadman.arm_test_only(500);
    assert!(deadman.owner_lost_test_only());
    assert!(!deadman.owner_lost_test_only());
    assert!(!deadman.expire_if_due_test_only(500));
    assert!(deadman.is_paused_test_only());
}
