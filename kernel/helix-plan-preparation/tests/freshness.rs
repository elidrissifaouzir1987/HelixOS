//! Executable, table-driven specification for the frozen authority-comparison order.
//!
//! The cases drive the public orchestration seam through injected context, replay,
//! preflight, recovery, commit and readback boundaries and assert phase call counts.

mod common;

use common::{
    feature002, synthetic_eligible_plan_v1, DeterministicPreparationClockV1,
    SyntheticAuthorityGuardControlV1, SyntheticConformanceRecoveryProviderV1,
    SyntheticContextFaultV1, SyntheticGuardStateV1, SyntheticPermitStateV1,
    SyntheticPreparationAuthorityV1, SyntheticRecoveryGuardFaultV1,
    SyntheticRecoveryPreparationFaultV1, SyntheticRecoveryVerificationFaultV1,
    SyntheticSupervisorPermitControlV1,
};
use helix_plan_eligibility::{
    EligiblePlanV1, ReplayClaimVerificationV1, ReplayClaimVerificationViewV1, ReplayClaimVerifierV1,
};
use helix_plan_preparation::{
    prepare_plan_v1, AmbiguousPreparationV1, AuthorityGuardKindV1, BudgetPreflightInputV1,
    BudgetPreflightV1, BudgetReservationReceiptInputV1, BudgetReservationReceiptV1,
    BudgetReservationStateV1, BudgetVectorInputV1, BudgetVectorV1, FinalCommitGateV1,
    FinalCommitPermitOutcomeV1, FinalCommitPermitRequestInputV1, FinalCommitPermitRequestV1,
    FinalCommitPermitV1, FinalCommitResolutionV1, FinalCommitStoreClassificationV1,
    NoDispatchAuthorityGuardV1, PreparationAuthoritySourceV1, PreparationCommitInputV1,
    PreparationCommitOutcomeV1, PreparationCommitReceiptInputV1, PreparationCommitReceiptV1,
    PreparationCommitUncertainV1, PreparationDenialV1, PreparationFailureInputV1,
    PreparationFailureOutcomeV1, PreparationFailureV1, PreparationOutcomeV1,
    PreparationPreflightInputV1, PreparationPreflightOutcomeV1, PreparationReadbackInputV1,
    PreparationReadbackOutcomeV1, PreparationStoreV1, PreparationTimeSourceV1, RecoveryProviderV1,
    PREPARATION_BUDGET_CONTRACT_VERSION_V1, PREPARATION_STORE_CONTRACT_VERSION_V1,
};
#[cfg(feature = "test-fault-injection")]
use helix_plan_preparation::{prepare_plan_with_fault_probe_v1, FaultProbeV1};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const CALLER_DEADLINE: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreflightScript {
    Ready,
    OperationAuthorityUnavailable,
    OperationConflict,
    AlreadyPrepared,
    BudgetScopeMissing,
    BudgetAuthorityUnavailable,
    BudgetBindingConflict,
    BudgetArithmeticInvalid,
    BudgetExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitScript {
    Committed,
    Unavailable,
    Busy,
    Unhealthy,
    Conflict,
    ConfirmedRollback,
    Uncertain,
    Unclassified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadbackScript {
    DefiniteAbsence,
    ThisAttempt,
    PriorExactAttempt,
    Conflict,
    Unavailable,
    Unhealthy,
}

struct ScriptedReplayVerifier {
    expected: ReplayViewSnapshot,
    preliminary: ReplayClaimVerificationV1,
    final_result: ReplayClaimVerificationV1,
    calls: AtomicUsize,
    unrelated_global_generation: AtomicU64,
}

#[derive(Debug, PartialEq, Eq)]
struct ReplayViewSnapshot {
    instance_epoch: u64,
    nonce: helix_contracts::Nonce128,
    operation_id: String,
    claim_id: helix_contracts::Sha256Digest,
    claimant_generation: u64,
    binding_digest: helix_contracts::Sha256Digest,
}

impl ReplayViewSnapshot {
    fn capture(view: &ReplayClaimVerificationViewV1<'_>) -> Self {
        Self {
            instance_epoch: view.instance_epoch(),
            nonce: view.nonce(),
            operation_id: view.operation_id().to_owned(),
            claim_id: view.claim_id(),
            claimant_generation: view.claimant_generation(),
            binding_digest: view.binding_digest(),
        }
    }
}

impl ScriptedReplayVerifier {
    fn new(
        expected: ReplayViewSnapshot,
        preliminary: ReplayClaimVerificationV1,
        final_result: ReplayClaimVerificationV1,
    ) -> Self {
        Self {
            expected,
            preliminary,
            final_result,
            calls: AtomicUsize::new(0),
            unrelated_global_generation: AtomicU64::new(1),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn unrelated_global_generation(&self) -> u64 {
        self.unrelated_global_generation.load(Ordering::SeqCst)
    }
}

impl ReplayClaimVerifierV1 for ScriptedReplayVerifier {
    fn verify_exact_claim(
        &self,
        view: &ReplayClaimVerificationViewV1<'_>,
        _deadline_monotonic_ms: u64,
    ) -> ReplayClaimVerificationV1 {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            ReplayViewSnapshot::capture(view),
            self.expected,
            "both replay checks must carry the same exact permanent row"
        );
        if call == 0 {
            assert_eq!(self.unrelated_global_generation(), 1);
            self.unrelated_global_generation
                .fetch_add(1, Ordering::SeqCst);
            self.preliminary
        } else {
            assert_eq!(self.unrelated_global_generation(), 2);
            self.final_result
        }
    }
}

struct ScriptedPreparationStore {
    preliminary_preflight: PreflightScript,
    final_preflight: PreflightScript,
    commit: CommitScript,
    readback: ReadbackScript,
    preflight_calls: AtomicUsize,
    commit_calls: AtomicUsize,
    commit_invocations: AtomicUsize,
    readback_calls: AtomicUsize,
    operation_generation_delta: AtomicU64,
    reservation_generation_delta: AtomicU64,
    event_generation_delta: AtomicU64,
}

impl ScriptedPreparationStore {
    fn new(
        preliminary_preflight: PreflightScript,
        final_preflight: PreflightScript,
        commit: CommitScript,
        readback: ReadbackScript,
    ) -> Self {
        Self {
            preliminary_preflight,
            final_preflight,
            commit,
            readback,
            preflight_calls: AtomicUsize::new(0),
            commit_calls: AtomicUsize::new(0),
            commit_invocations: AtomicUsize::new(0),
            readback_calls: AtomicUsize::new(0),
            operation_generation_delta: AtomicU64::new(0),
            reservation_generation_delta: AtomicU64::new(0),
            event_generation_delta: AtomicU64::new(0),
        }
    }

    fn preflight_calls(&self) -> usize {
        self.preflight_calls.load(Ordering::SeqCst)
    }

    fn commit_calls(&self) -> usize {
        self.commit_calls.load(Ordering::SeqCst)
    }

    fn commit_invocations(&self) -> usize {
        self.commit_invocations.load(Ordering::SeqCst)
    }

    fn readback_calls(&self) -> usize {
        self.readback_calls.load(Ordering::SeqCst)
    }

    fn generation_deltas(&self) -> (u64, u64, u64) {
        (
            self.operation_generation_delta.load(Ordering::SeqCst),
            self.reservation_generation_delta.load(Ordering::SeqCst),
            self.event_generation_delta.load(Ordering::SeqCst),
        )
    }

    fn record_this_attempt_commit(&self) {
        self.operation_generation_delta.store(1, Ordering::SeqCst);
        self.reservation_generation_delta.store(1, Ordering::SeqCst);
        self.event_generation_delta.store(1, Ordering::SeqCst);
    }

    fn ready_preflight(input: &PreparationPreflightInputV1<'_>) -> BudgetPreflightV1 {
        let requested = input.requested_budget();
        let remaining = BudgetVectorV1::try_new(BudgetVectorInputV1 {
            max_cost_micro_units: requested.max_cost_micro_units(),
            action_limit: requested.action_limit(),
            egress_bytes_limit: requested.egress_bytes_limit(),
            recovery_bytes: requested.recovery_bytes(),
        })
        .expect("synthetic remaining vector is valid");
        BudgetPreflightV1::try_new(BudgetPreflightInputV1 {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            observed_scope_generation: input.context().budget_scope_generation(),
            observed_scope_binding_digest: input.context().budget_scope_binding_digest(),
            observed_remaining: remaining,
        })
        .expect("synthetic preflight is valid")
    }

    fn receipt(attempt_id: helix_contracts::Sha256Digest) -> PreparationCommitReceiptV1 {
        let reservation = BudgetReservationReceiptV1::try_new(BudgetReservationReceiptInputV1 {
            contract_version: PREPARATION_BUDGET_CONTRACT_VERSION_V1,
            state: BudgetReservationStateV1::Held,
            reservation_generation: 1,
        })
        .expect("synthetic reservation is valid");
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

impl PreparationStoreV1 for ScriptedPreparationStore {
    fn preflight_operation_and_budget(
        &self,
        input: &PreparationPreflightInputV1<'_>,
    ) -> PreparationPreflightOutcomeV1 {
        let call = self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        let script = if call == 0 {
            self.preliminary_preflight
        } else {
            self.final_preflight
        };
        match script {
            PreflightScript::Ready => {
                PreparationPreflightOutcomeV1::Ready(Self::ready_preflight(input))
            }
            PreflightScript::OperationAuthorityUnavailable => {
                PreparationPreflightOutcomeV1::OperationAuthorityUnavailable
            }
            PreflightScript::OperationConflict => PreparationPreflightOutcomeV1::OperationConflict,
            PreflightScript::AlreadyPrepared => PreparationPreflightOutcomeV1::AlreadyPrepared,
            PreflightScript::BudgetScopeMissing => {
                PreparationPreflightOutcomeV1::BudgetScopeMissing
            }
            PreflightScript::BudgetAuthorityUnavailable => {
                PreparationPreflightOutcomeV1::BudgetAuthorityUnavailable
            }
            PreflightScript::BudgetBindingConflict => {
                PreparationPreflightOutcomeV1::BudgetBindingConflict
            }
            PreflightScript::BudgetArithmeticInvalid => {
                PreparationPreflightOutcomeV1::BudgetArithmeticInvalid
            }
            PreflightScript::BudgetExhausted => PreparationPreflightOutcomeV1::BudgetExhausted,
        }
    }

    fn commit_preparing<G: FinalCommitGateV1>(
        &self,
        input: &PreparationCommitInputV1<'_>,
        final_gate: &mut G,
    ) -> PreparationCommitOutcomeV1<<G::Permit as FinalCommitPermitV1>::InFlight> {
        self.commit_calls.fetch_add(1, Ordering::SeqCst);
        match self.commit {
            CommitScript::Unavailable => return PreparationCommitOutcomeV1::Unavailable,
            CommitScript::Busy => return PreparationCommitOutcomeV1::Busy,
            CommitScript::Unhealthy => return PreparationCommitOutcomeV1::Unhealthy,
            CommitScript::Conflict => return PreparationCommitOutcomeV1::Conflict,
            CommitScript::Committed
            | CommitScript::ConfirmedRollback
            | CommitScript::Uncertain
            | CommitScript::Unclassified => {}
        }

        let request = FinalCommitPermitRequestV1::try_new(FinalCommitPermitRequestInputV1 {
            attempt: input.attempt(),
            expected_supervisor_generation: input.final_context().supervisor_generation(),
            caller_deadline_monotonic_ms: input.final_context().effective_deadline_monotonic_ms(),
            permit_entry_monotonic_ms: input.final_context().sampled_monotonic_ms(),
        })
        .expect("synthetic permit request is valid");
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
        let classification = match self.commit {
            CommitScript::Committed => FinalCommitStoreClassificationV1::Committed,
            CommitScript::ConfirmedRollback => FinalCommitStoreClassificationV1::ConfirmedRollback,
            CommitScript::Uncertain => FinalCommitStoreClassificationV1::Uncertain,
            CommitScript::Unclassified => FinalCommitStoreClassificationV1::Unclassified,
            CommitScript::Unavailable
            | CommitScript::Busy
            | CommitScript::Unhealthy
            | CommitScript::Conflict => unreachable!("early store failures already returned"),
        };
        let resolution = permit.commit_once_instrumented_v1(|| {
            self.commit_invocations.fetch_add(1, Ordering::SeqCst);
            if classification == FinalCommitStoreClassificationV1::Committed {
                self.record_this_attempt_commit();
            }
            classification
        });
        match resolution {
            FinalCommitResolutionV1::Committed => {
                PreparationCommitOutcomeV1::Committed(Self::receipt(input.attempt().digest()))
            }
            FinalCommitResolutionV1::Aborted => PreparationCommitOutcomeV1::ConfirmedRollback,
            FinalCommitResolutionV1::Uncertain(in_flight) => {
                let token = PreparationCommitUncertainV1::try_new(
                    PREPARATION_STORE_CONTRACT_VERSION_V1,
                    input.attempt().digest(),
                )
                .expect("synthetic uncertainty token is valid");
                PreparationCommitOutcomeV1::Uncertain { token, in_flight }
            }
            FinalCommitResolutionV1::Ambiguous => PreparationCommitOutcomeV1::Unclassified,
        }
    }

    fn readback_attempt(
        &self,
        input: &PreparationReadbackInputV1<'_>,
    ) -> PreparationReadbackOutcomeV1 {
        self.readback_calls.fetch_add(1, Ordering::SeqCst);
        match self.readback {
            ReadbackScript::DefiniteAbsence => PreparationReadbackOutcomeV1::DefiniteAbsence,
            ReadbackScript::ThisAttempt => {
                self.record_this_attempt_commit();
                PreparationReadbackOutcomeV1::ThisAttempt(Self::receipt(input.attempt().digest()))
            }
            ReadbackScript::PriorExactAttempt => PreparationReadbackOutcomeV1::PriorExactAttempt,
            ReadbackScript::Conflict => PreparationReadbackOutcomeV1::Conflict,
            ReadbackScript::Unavailable => PreparationReadbackOutcomeV1::Unavailable,
            ReadbackScript::Unhealthy => PreparationReadbackOutcomeV1::Unhealthy,
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

#[derive(Clone, Copy)]
struct CaseConfig {
    caller_deadline: u64,
    clock_utc_ms: u64,
    clock_monotonic_ms: u64,
    preliminary_context: SyntheticContextFaultV1,
    preliminary_context_secondary: SyntheticContextFaultV1,
    final_context: SyntheticContextFaultV1,
    final_context_secondary: SyntheticContextFaultV1,
    guard_fault: Option<(AuthorityGuardKindV1, SyntheticGuardStateV1)>,
    post_final_capture_guard_fault: Option<(AuthorityGuardKindV1, SyntheticGuardStateV1)>,
    preliminary_replay: ReplayClaimVerificationV1,
    final_replay: ReplayClaimVerificationV1,
    preliminary_preflight: PreflightScript,
    final_preflight: PreflightScript,
    recovery_guard: SyntheticRecoveryGuardFaultV1,
    recovery_preparation: SyntheticRecoveryPreparationFaultV1,
    recovery_verifications: [SyntheticRecoveryVerificationFaultV1; 3],
    commit: CommitScript,
    readback: ReadbackScript,
}

impl CaseConfig {
    const fn coherent() -> Self {
        Self {
            caller_deadline: CALLER_DEADLINE,
            clock_utc_ms: feature002::NOW_UTC_MS,
            clock_monotonic_ms: feature002::NOW_MONOTONIC_MS,
            preliminary_context: SyntheticContextFaultV1::None,
            preliminary_context_secondary: SyntheticContextFaultV1::None,
            final_context: SyntheticContextFaultV1::None,
            final_context_secondary: SyntheticContextFaultV1::None,
            guard_fault: None,
            post_final_capture_guard_fault: None,
            preliminary_replay: ReplayClaimVerificationV1::Exact,
            final_replay: ReplayClaimVerificationV1::Exact,
            preliminary_preflight: PreflightScript::Ready,
            final_preflight: PreflightScript::Ready,
            recovery_guard: SyntheticRecoveryGuardFaultV1::Exact,
            recovery_preparation: SyntheticRecoveryPreparationFaultV1::Exact,
            recovery_verifications: [SyntheticRecoveryVerificationFaultV1::Exact; 3],
            commit: CommitScript::Committed,
            readback: ReadbackScript::DefiniteAbsence,
        }
    }
}

struct CaseObservation {
    outcome: PreparationOutcomeV1,
    replay_calls: usize,
    replay_global_generation: u64,
    preflight_calls: usize,
    commit_calls: usize,
    commit_invocations: usize,
    readback_calls: usize,
    generation_deltas: (u64, u64, u64),
    recovery_acquire_calls: usize,
    recovery_prepare_calls: usize,
    recovery_verify_calls: usize,
    recovery_published_count: usize,
    recovery_release_calls: usize,
    permit_state: SyntheticPermitStateV1,
}

fn run_case(config: CaseConfig) -> CaseObservation {
    run_case_with_optional_fault_probe(config, CaseFaultProbeV1::Disabled)
}

enum CaseFaultProbeV1 {
    Disabled,
    #[cfg(feature = "test-fault-injection")]
    Selected(FaultProbeV1),
}

#[cfg(feature = "test-fault-injection")]
fn run_case_with_fault_probe(config: CaseConfig, fault_probe: FaultProbeV1) -> CaseObservation {
    run_case_with_optional_fault_probe(config, CaseFaultProbeV1::Selected(fault_probe))
}

fn run_case_with_optional_fault_probe(
    config: CaseConfig,
    fault_probe: CaseFaultProbeV1,
) -> CaseObservation {
    let clock =
        DeterministicPreparationClockV1::new(config.clock_utc_ms, config.clock_monotonic_ms);
    let guard_control = SyntheticAuthorityGuardControlV1::new_test_only();
    if let Some((kind, state)) = config.guard_fault {
        guard_control.set_state_test_only(kind, state);
    }
    let supervisor =
        SyntheticSupervisorPermitControlV1::new_test_only(feature002::SUPERVISOR_GENERATION);
    let authority = SyntheticPreparationAuthorityV1::with_context_fault_sets_test_only(
        clock.clone(),
        guard_control,
        supervisor.clone(),
        [
            config.preliminary_context,
            config.preliminary_context_secondary,
        ],
        [config.final_context, config.final_context_secondary],
        config.post_final_capture_guard_fault,
    );
    let eligible = synthetic_eligible_plan_v1();
    let expected_replay = ReplayViewSnapshot::capture(&eligible.replay_verification_view());
    let replay = ScriptedReplayVerifier::new(
        expected_replay,
        config.preliminary_replay,
        config.final_replay,
    );
    let store = ScriptedPreparationStore::new(
        config.preliminary_preflight,
        config.final_preflight,
        config.commit,
        config.readback,
    );
    let recovery = SyntheticConformanceRecoveryProviderV1::with_faults_test_only(
        config.recovery_guard,
        config.recovery_preparation,
        config.recovery_verifications.to_vec(),
    );
    let outcome = match fault_probe {
        CaseFaultProbeV1::Disabled => prepare_plan_v1(
            eligible,
            &authority,
            &replay,
            &store,
            &recovery,
            &clock,
            config.caller_deadline,
        ),
        #[cfg(feature = "test-fault-injection")]
        CaseFaultProbeV1::Selected(fault_probe) => prepare_plan_with_fault_probe_v1(
            eligible,
            &authority,
            &replay,
            &store,
            &recovery,
            &clock,
            config.caller_deadline,
            fault_probe,
        ),
    };
    CaseObservation {
        outcome,
        replay_calls: replay.calls(),
        replay_global_generation: replay.unrelated_global_generation(),
        preflight_calls: store.preflight_calls(),
        commit_calls: store.commit_calls(),
        commit_invocations: store.commit_invocations(),
        readback_calls: store.readback_calls(),
        generation_deltas: store.generation_deltas(),
        recovery_acquire_calls: recovery.acquire_count_test_only(),
        recovery_prepare_calls: recovery.prepare_count_test_only(),
        recovery_verify_calls: recovery.verify_count_test_only(),
        recovery_published_count: recovery.published_count_test_only(),
        recovery_release_calls: recovery.released_guard_count_test_only(),
        permit_state: supervisor.state_test_only(),
    }
}

#[derive(Clone, Copy, Debug)]
enum ExpectedOutcome {
    Denied(PreparationDenialV1),
    Failed(PreparationFailureV1),
    Ambiguous(AmbiguousPreparationV1),
    Prepared,
}

fn assert_outcome(actual: &PreparationOutcomeV1, expected: ExpectedOutcome, label: &str) {
    let matches = match (actual, expected) {
        (PreparationOutcomeV1::Denied(actual), ExpectedOutcome::Denied(expected)) => {
            actual == &expected
        }
        (PreparationOutcomeV1::Failed(actual), ExpectedOutcome::Failed(expected)) => {
            actual == &expected
        }
        (PreparationOutcomeV1::Ambiguous(actual), ExpectedOutcome::Ambiguous(expected)) => {
            actual == &expected
        }
        (PreparationOutcomeV1::Prepared(_), ExpectedOutcome::Prepared) => true,
        _ => false,
    };
    assert!(matches, "{label}: unexpected outcome {actual:?}");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutcomeClass {
    Denied,
    Failed,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NormativeRow {
    order: u8,
    class: OutcomeClass,
    code: &'static str,
}

const NORMATIVE_ROWS: [NormativeRow; 45] = [
    denied(1, "PREPARATION_VERSION_UNSUPPORTED"),
    denied(2, "PREPARATION_CONTEXT_UNAVAILABLE"),
    denied(3, "PREPARATION_CONTEXT_INCOMPLETE"),
    denied(4, "PREPARATION_CONTEXT_UNSUPPORTED"),
    denied(5, "PREPARATION_CONTEXT_TORN"),
    denied(6, "PREPARATION_CONTEXT_MISMATCH"),
    denied(7, "PREPARATION_CLOCK_MISMATCH"),
    denied(8, "PREPARATION_TIME_EXPIRED"),
    denied(9, "PREPARATION_DEADLINE_MISMATCH"),
    denied(10, "PREPARATION_DEADLINE_REACHED"),
    denied(11, "PREPARATION_BOOT_MISMATCH"),
    denied(12, "PREPARATION_SUPERVISOR_DENIED"),
    denied(13, "PREPARATION_SUPERVISOR_MISMATCH"),
    denied(14, "PREPARATION_GUARD_REVOKED"),
    denied(15, "PREPARATION_TRUST_MISMATCH"),
    denied(16, "PREPARATION_WORKLOAD_MISMATCH"),
    denied(17, "PREPARATION_LEASE_MISMATCH"),
    denied(18, "PREPARATION_AUTHORIZATION_MISMATCH"),
    denied(19, "PREPARATION_POLICY_MISMATCH"),
    denied(20, "PREPARATION_CATALOGUE_MISMATCH"),
    denied(21, "PREPARATION_CAPABILITY_MISMATCH"),
    denied(22, "PREPARATION_REPLAY_MISSING"),
    denied(23, "PREPARATION_REPLAY_CONFLICT"),
    denied(24, "PREPARATION_REPLAY_UNAVAILABLE"),
    denied(25, "PREPARATION_REPLAY_UNHEALTHY"),
    denied(26, "PREPARATION_OPERATION_AUTHORITY_UNAVAILABLE"),
    denied(27, "PREPARATION_OPERATION_CONFLICT"),
    denied(28, "PREPARATION_ALREADY_PREPARED"),
    denied(29, "PREPARATION_BUDGET_SCOPE_MISSING"),
    denied(30, "PREPARATION_BUDGET_AUTHORITY_UNAVAILABLE"),
    denied(31, "PREPARATION_BUDGET_BINDING_CONFLICT"),
    denied(32, "PREPARATION_BUDGET_ARITHMETIC_INVALID"),
    denied(33, "PREPARATION_BUDGET_EXHAUSTED"),
    denied(34, "PREPARATION_RECOVERY_PROFILE_UNAPPROVED"),
    failed(35, "PREPARATION_RECOVERY_UNAVAILABLE"),
    denied(36, "PREPARATION_RECOVERY_BINDING_CONFLICT"),
    denied(37, "PREPARATION_RECOVERY_UNVERIFIED"),
    ambiguous(38, "PREPARATION_AMBIGUOUS"),
    failed(39, "PREPARATION_STORE_UNAVAILABLE"),
    failed(40, "PREPARATION_STORE_BUSY"),
    failed(41, "PREPARATION_STORE_UNHEALTHY"),
    failed(42, "PREPARATION_STORE_CONFLICT"),
    failed(43, "PREPARATION_STORE_COMMIT_ABORTED"),
    failed(44, "PREPARATION_STORE_DEFINITE_ABSENCE"),
    ambiguous(45, "PREPARATION_AMBIGUOUS"),
];

const fn denied(order: u8, code: &'static str) -> NormativeRow {
    NormativeRow {
        order,
        class: OutcomeClass::Denied,
        code,
    }
}

const fn failed(order: u8, code: &'static str) -> NormativeRow {
    NormativeRow {
        order,
        class: OutcomeClass::Failed,
        code,
    }
}

const fn ambiguous(order: u8, code: &'static str) -> NormativeRow {
    NormativeRow {
        order,
        class: OutcomeClass::Ambiguous,
        code,
    }
}

#[test]
fn section_6_1_rows_are_closed_contiguous_and_in_normative_order() {
    assert_eq!(NORMATIVE_ROWS.len(), 45);
    for (index, row) in NORMATIVE_ROWS.iter().enumerate() {
        assert_eq!(usize::from(row.order), index + 1);
        assert!(row.code.starts_with("PREPARATION_"));
    }
}

#[test]
fn public_codes_are_unique_except_for_the_two_closed_ambiguous_rows() {
    let mut occurrences = BTreeMap::<&str, usize>::new();
    for row in NORMATIVE_ROWS {
        *occurrences.entry(row.code).or_default() += 1;
    }

    let duplicate_codes = occurrences
        .iter()
        .filter_map(|(code, count)| (*count > 1).then_some((*code, *count)))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        duplicate_codes,
        BTreeSet::from([("PREPARATION_AMBIGUOUS", 2)])
    );
    assert_eq!(occurrences.len(), 44);
}

#[test]
fn coherent_exact_replay_reaches_one_positive_commit_and_releases_every_guard() {
    let observation = run_case(CaseConfig::coherent());
    assert_outcome(&observation.outcome, ExpectedOutcome::Prepared, "coherent");
    assert_eq!(observation.replay_calls, 2);
    assert_eq!(observation.preflight_calls, 2);
    assert_eq!(observation.commit_calls, 1);
    assert_eq!(observation.commit_invocations, 1);
    assert_eq!(observation.readback_calls, 0);
    assert_eq!(observation.generation_deltas, (1, 1, 1));
    assert_eq!(observation.recovery_acquire_calls, 1);
    assert_eq!(observation.recovery_prepare_calls, 1);
    assert_eq!(observation.recovery_verify_calls, 3);
    assert_eq!(observation.recovery_published_count, 1);
    assert_eq!(observation.recovery_release_calls, 1);
    assert_eq!(
        observation.permit_state,
        SyntheticPermitStateV1::ResolvedCommitted
    );
}

#[test]
fn preliminary_context_single_leaf_rows_stop_before_commit_and_recovery() {
    let cases = [
        (
            2,
            SyntheticContextFaultV1::Unavailable,
            PreparationDenialV1::ContextUnavailable,
        ),
        (
            3,
            SyntheticContextFaultV1::Incomplete,
            PreparationDenialV1::ContextIncomplete,
        ),
        (
            4,
            SyntheticContextFaultV1::Unsupported,
            PreparationDenialV1::ContextUnsupported,
        ),
        (
            5,
            SyntheticContextFaultV1::Torn,
            PreparationDenialV1::ContextTorn,
        ),
        (
            6,
            SyntheticContextFaultV1::CaptureGeneration,
            PreparationDenialV1::ContextMismatch,
        ),
        (
            7,
            SyntheticContextFaultV1::ClockGeneration,
            PreparationDenialV1::ClockMismatch,
        ),
        (
            8,
            SyntheticContextFaultV1::UtcExpired,
            PreparationDenialV1::TimeExpired,
        ),
        (
            9,
            SyntheticContextFaultV1::DeadlineGeneration,
            PreparationDenialV1::DeadlineMismatch,
        ),
        (
            10,
            SyntheticContextFaultV1::MonotonicDeadlineReached,
            PreparationDenialV1::DeadlineReached,
        ),
        (
            11,
            SyntheticContextFaultV1::Boot,
            PreparationDenialV1::BootMismatch,
        ),
        (
            12,
            SyntheticContextFaultV1::SupervisorDenied,
            PreparationDenialV1::SupervisorDenied,
        ),
        (
            13,
            SyntheticContextFaultV1::SupervisorGeneration,
            PreparationDenialV1::SupervisorMismatch,
        ),
        (
            15,
            SyntheticContextFaultV1::Trust,
            PreparationDenialV1::TrustMismatch,
        ),
        (
            16,
            SyntheticContextFaultV1::Workload,
            PreparationDenialV1::WorkloadMismatch,
        ),
        (
            17,
            SyntheticContextFaultV1::Lease,
            PreparationDenialV1::LeaseMismatch,
        ),
        (
            18,
            SyntheticContextFaultV1::Authorization,
            PreparationDenialV1::AuthorizationMismatch,
        ),
        (
            19,
            SyntheticContextFaultV1::Policy,
            PreparationDenialV1::PolicyMismatch,
        ),
        (
            20,
            SyntheticContextFaultV1::Catalogue,
            PreparationDenialV1::CatalogueMismatch,
        ),
        (
            21,
            SyntheticContextFaultV1::Capability,
            PreparationDenialV1::CapabilityMismatch,
        ),
        (
            23,
            SyntheticContextFaultV1::ReplayBinding,
            PreparationDenialV1::ReplayConflict,
        ),
        (
            31,
            SyntheticContextFaultV1::BudgetBinding,
            PreparationDenialV1::BudgetBindingConflict,
        ),
        (
            34,
            SyntheticContextFaultV1::RecoveryProfile,
            PreparationDenialV1::RecoveryProfileUnapproved,
        ),
    ];
    for (row, fault, denial) in cases {
        let mut config = CaseConfig::coherent();
        config.preliminary_context = fault;
        let observation = run_case(config);
        assert_outcome(
            &observation.outcome,
            ExpectedOutcome::Denied(denial),
            &format!("preliminary row {row}"),
        );
        assert_eq!(observation.commit_calls, 0, "row {row}");
        assert_eq!(observation.commit_invocations, 0, "row {row}");
        assert_eq!(observation.readback_calls, 0, "row {row}");
        assert_eq!(observation.generation_deltas, (0, 0, 0), "row {row}");
        assert_eq!(observation.recovery_acquire_calls, 0, "row {row}");
        assert_eq!(observation.recovery_prepare_calls, 0, "row {row}");
        assert_eq!(observation.recovery_verify_calls, 0, "row {row}");
        assert_eq!(observation.recovery_published_count, 0, "row {row}");
        assert_eq!(observation.recovery_release_calls, 0, "row {row}");
    }
}

#[test]
fn final_context_single_leaf_rows_retain_then_release_recovery_without_mutation() {
    let cases = [
        (
            2,
            SyntheticContextFaultV1::Unavailable,
            PreparationDenialV1::ContextUnavailable,
        ),
        (
            3,
            SyntheticContextFaultV1::Incomplete,
            PreparationDenialV1::ContextIncomplete,
        ),
        (
            4,
            SyntheticContextFaultV1::Unsupported,
            PreparationDenialV1::ContextUnsupported,
        ),
        (
            5,
            SyntheticContextFaultV1::Torn,
            PreparationDenialV1::ContextTorn,
        ),
        (
            6,
            SyntheticContextFaultV1::CaptureGeneration,
            PreparationDenialV1::ContextMismatch,
        ),
        (
            7,
            SyntheticContextFaultV1::ClockGeneration,
            PreparationDenialV1::ClockMismatch,
        ),
        (
            8,
            SyntheticContextFaultV1::UtcExpired,
            PreparationDenialV1::TimeExpired,
        ),
        (
            9,
            SyntheticContextFaultV1::DeadlineGeneration,
            PreparationDenialV1::DeadlineMismatch,
        ),
        (
            10,
            SyntheticContextFaultV1::MonotonicDeadlineReached,
            PreparationDenialV1::DeadlineReached,
        ),
        (
            11,
            SyntheticContextFaultV1::Boot,
            PreparationDenialV1::BootMismatch,
        ),
        (
            12,
            SyntheticContextFaultV1::SupervisorDenied,
            PreparationDenialV1::SupervisorDenied,
        ),
        (
            13,
            SyntheticContextFaultV1::SupervisorGeneration,
            PreparationDenialV1::SupervisorMismatch,
        ),
        (
            15,
            SyntheticContextFaultV1::Trust,
            PreparationDenialV1::TrustMismatch,
        ),
        (
            16,
            SyntheticContextFaultV1::Workload,
            PreparationDenialV1::WorkloadMismatch,
        ),
        (
            17,
            SyntheticContextFaultV1::Lease,
            PreparationDenialV1::LeaseMismatch,
        ),
        (
            18,
            SyntheticContextFaultV1::Authorization,
            PreparationDenialV1::AuthorizationMismatch,
        ),
        (
            19,
            SyntheticContextFaultV1::Policy,
            PreparationDenialV1::PolicyMismatch,
        ),
        (
            20,
            SyntheticContextFaultV1::Catalogue,
            PreparationDenialV1::CatalogueMismatch,
        ),
        (
            21,
            SyntheticContextFaultV1::Capability,
            PreparationDenialV1::CapabilityMismatch,
        ),
        (
            23,
            SyntheticContextFaultV1::ReplayBinding,
            PreparationDenialV1::ReplayConflict,
        ),
        (
            31,
            SyntheticContextFaultV1::BudgetBinding,
            PreparationDenialV1::BudgetBindingConflict,
        ),
        (
            34,
            SyntheticContextFaultV1::RecoveryProfile,
            PreparationDenialV1::RecoveryProfileUnapproved,
        ),
        (
            36,
            SyntheticContextFaultV1::RecoveryBinding,
            PreparationDenialV1::RecoveryBindingConflict,
        ),
    ];
    for (row, fault, denial) in cases {
        let mut config = CaseConfig::coherent();
        config.final_context = fault;
        let observation = run_case(config);
        assert_outcome(
            &observation.outcome,
            ExpectedOutcome::Denied(denial),
            &format!("final row {row}"),
        );
        assert_eq!(observation.commit_calls, 0, "row {row}");
        assert_eq!(observation.commit_invocations, 0, "row {row}");
        assert_eq!(observation.readback_calls, 0, "row {row}");
        assert_eq!(observation.generation_deltas, (0, 0, 0), "row {row}");
        assert_eq!(observation.recovery_acquire_calls, 1, "row {row}");
        assert_eq!(observation.recovery_prepare_calls, 1, "row {row}");
        assert_eq!(observation.recovery_verify_calls, 1, "row {row}");
        assert_eq!(observation.recovery_published_count, 1, "row {row}");
        assert_eq!(observation.recovery_release_calls, 1, "row {row}");
        assert_eq!(observation.permit_state, SyntheticPermitStateV1::Open);
    }
}

#[test]
fn row_1_and_guard_row_14_are_fail_closed_with_zero_commit_invocation() {
    let mut version = CaseConfig::coherent();
    version.caller_deadline = helix_contracts::MAX_SAFE_U64 + 1;
    let observation = run_case(version);
    assert_outcome(
        &observation.outcome,
        ExpectedOutcome::Denied(PreparationDenialV1::VersionUnsupported),
        "row 1",
    );
    assert_eq!(observation.replay_calls, 0);
    assert_eq!(observation.preflight_calls, 0);
    assert_eq!(observation.recovery_acquire_calls, 0);
    assert_eq!(observation.commit_calls, 0);
    assert_eq!(observation.generation_deltas, (0, 0, 0));
    assert_eq!(observation.recovery_published_count, 0);

    let mut guard = CaseConfig::coherent();
    guard.post_final_capture_guard_fault = Some((
        AuthorityGuardKindV1::SignerTrust,
        SyntheticGuardStateV1::Revoked,
    ));
    let observation = run_case(guard);
    assert_outcome(
        &observation.outcome,
        ExpectedOutcome::Denied(PreparationDenialV1::GuardRevoked),
        "row 14",
    );
    assert_eq!(observation.commit_calls, 0);
    assert_eq!(observation.commit_invocations, 0);
    assert_eq!(observation.recovery_acquire_calls, 1);
    assert_eq!(observation.recovery_published_count, 1);
    assert_eq!(observation.recovery_release_calls, 1);
    assert_eq!(observation.generation_deltas, (0, 0, 0));
}

#[test]
fn replay_rows_22_to_25_are_exercised_in_both_captures() {
    let cases = [
        (
            22,
            ReplayClaimVerificationV1::Missing,
            PreparationDenialV1::ReplayMissing,
        ),
        (
            23,
            ReplayClaimVerificationV1::Conflict,
            PreparationDenialV1::ReplayConflict,
        ),
        (
            24,
            ReplayClaimVerificationV1::Unavailable,
            PreparationDenialV1::ReplayUnavailable,
        ),
        (
            25,
            ReplayClaimVerificationV1::Unhealthy,
            PreparationDenialV1::ReplayUnhealthy,
        ),
    ];
    for (row, replay, denial) in cases {
        let mut preliminary = CaseConfig::coherent();
        preliminary.preliminary_replay = replay;
        let observation = run_case(preliminary);
        assert_outcome(
            &observation.outcome,
            ExpectedOutcome::Denied(denial),
            &format!("preliminary replay row {row}"),
        );
        assert_eq!(observation.replay_calls, 1);
        assert_eq!(observation.preflight_calls, 0);
        assert_eq!(observation.recovery_acquire_calls, 0);
        assert_eq!(observation.commit_calls, 0);
        assert_eq!(observation.generation_deltas, (0, 0, 0));
        assert_eq!(observation.recovery_published_count, 0);

        let mut final_case = CaseConfig::coherent();
        final_case.final_replay = replay;
        let observation = run_case(final_case);
        assert_outcome(
            &observation.outcome,
            ExpectedOutcome::Denied(denial),
            &format!("final replay row {row}"),
        );
        assert_eq!(observation.replay_calls, 2);
        assert_eq!(observation.preflight_calls, 1);
        assert_eq!(observation.recovery_acquire_calls, 1);
        assert_eq!(observation.recovery_published_count, 1);
        assert_eq!(observation.recovery_release_calls, 1);
        assert_eq!(observation.commit_calls, 0);
        assert_eq!(observation.generation_deltas, (0, 0, 0));
    }
}

#[test]
fn preflight_rows_26_to_33_are_exercised_preliminary_and_final() {
    let cases = [
        (
            26,
            PreflightScript::OperationAuthorityUnavailable,
            PreparationDenialV1::OperationAuthorityUnavailable,
        ),
        (
            27,
            PreflightScript::OperationConflict,
            PreparationDenialV1::OperationConflict,
        ),
        (
            28,
            PreflightScript::AlreadyPrepared,
            PreparationDenialV1::AlreadyPrepared,
        ),
        (
            29,
            PreflightScript::BudgetScopeMissing,
            PreparationDenialV1::BudgetScopeMissing,
        ),
        (
            30,
            PreflightScript::BudgetAuthorityUnavailable,
            PreparationDenialV1::BudgetAuthorityUnavailable,
        ),
        (
            31,
            PreflightScript::BudgetBindingConflict,
            PreparationDenialV1::BudgetBindingConflict,
        ),
        (
            32,
            PreflightScript::BudgetArithmeticInvalid,
            PreparationDenialV1::BudgetArithmeticInvalid,
        ),
        (
            33,
            PreflightScript::BudgetExhausted,
            PreparationDenialV1::BudgetExhausted,
        ),
    ];
    for (row, preflight, denial) in cases {
        let mut preliminary = CaseConfig::coherent();
        preliminary.preliminary_preflight = preflight;
        let observation = run_case(preliminary);
        assert_outcome(
            &observation.outcome,
            ExpectedOutcome::Denied(denial),
            &format!("preliminary preflight row {row}"),
        );
        assert_eq!(observation.preflight_calls, 1);
        assert_eq!(observation.recovery_acquire_calls, 0);
        assert_eq!(observation.commit_calls, 0);
        assert_eq!(observation.generation_deltas, (0, 0, 0));
        assert_eq!(observation.recovery_published_count, 0);

        let mut final_case = CaseConfig::coherent();
        final_case.final_preflight = preflight;
        let observation = run_case(final_case);
        assert_outcome(
            &observation.outcome,
            ExpectedOutcome::Denied(denial),
            &format!("final preflight row {row}"),
        );
        assert_eq!(observation.preflight_calls, 2);
        assert_eq!(observation.recovery_acquire_calls, 1);
        assert_eq!(observation.recovery_published_count, 1);
        assert_eq!(observation.recovery_release_calls, 1);
        assert_eq!(observation.commit_calls, 0);
        assert_eq!(observation.generation_deltas, (0, 0, 0));
    }
}

#[test]
fn recovery_rows_35_to_38_cover_publication_and_final_revalidation() {
    let preliminary_cases = [
        (
            35,
            SyntheticRecoveryGuardFaultV1::Unavailable,
            SyntheticRecoveryPreparationFaultV1::Exact,
            SyntheticRecoveryVerificationFaultV1::Exact,
            ExpectedOutcome::Failed(PreparationFailureV1::RecoveryProviderFailed),
        ),
        (
            36,
            SyntheticRecoveryGuardFaultV1::Exact,
            SyntheticRecoveryPreparationFaultV1::BindingConflict,
            SyntheticRecoveryVerificationFaultV1::Exact,
            ExpectedOutcome::Denied(PreparationDenialV1::RecoveryBindingConflict),
        ),
        (
            37,
            SyntheticRecoveryGuardFaultV1::Exact,
            SyntheticRecoveryPreparationFaultV1::Unverified,
            SyntheticRecoveryVerificationFaultV1::Exact,
            ExpectedOutcome::Denied(PreparationDenialV1::RecoveryUnverified),
        ),
        (
            38,
            SyntheticRecoveryGuardFaultV1::Exact,
            SyntheticRecoveryPreparationFaultV1::Ambiguous,
            SyntheticRecoveryVerificationFaultV1::Exact,
            ExpectedOutcome::Ambiguous(AmbiguousPreparationV1::RecoveryPublicationUnclassified),
        ),
    ];
    for (row, guard, preparation, verification, expected) in preliminary_cases {
        let mut config = CaseConfig::coherent();
        config.recovery_guard = guard;
        config.recovery_preparation = preparation;
        config.recovery_verifications[0] = verification;
        let observation = run_case(config);
        assert_outcome(
            &observation.outcome,
            expected,
            &format!("recovery row {row}"),
        );
        assert_eq!(observation.commit_calls, 0);
        assert_eq!(observation.commit_invocations, 0);
        assert_eq!(observation.generation_deltas, (0, 0, 0));
        assert_eq!(observation.recovery_acquire_calls, 1);
        assert_eq!(observation.recovery_verify_calls, 0);
        assert_eq!(observation.recovery_published_count, 0);
        if row == 35 {
            assert_eq!(observation.recovery_prepare_calls, 0);
            assert_eq!(observation.recovery_release_calls, 0);
        } else {
            assert_eq!(observation.recovery_prepare_calls, 1);
            assert_eq!(observation.recovery_release_calls, 1);
        }
        assert_eq!(observation.permit_state, SyntheticPermitStateV1::Open);
    }

    let final_cases = [
        (
            36,
            SyntheticRecoveryVerificationFaultV1::Conflict,
            ExpectedOutcome::Denied(PreparationDenialV1::RecoveryBindingConflict),
        ),
        (
            37,
            SyntheticRecoveryVerificationFaultV1::Missing,
            ExpectedOutcome::Denied(PreparationDenialV1::RecoveryUnverified),
        ),
        (
            38,
            SyntheticRecoveryVerificationFaultV1::Unavailable,
            ExpectedOutcome::Ambiguous(AmbiguousPreparationV1::RecoveryPublicationUnclassified),
        ),
        (
            38,
            SyntheticRecoveryVerificationFaultV1::Unhealthy,
            ExpectedOutcome::Ambiguous(AmbiguousPreparationV1::RecoveryPublicationUnclassified),
        ),
    ];
    for (row, verification, expected) in final_cases {
        let mut config = CaseConfig::coherent();
        config.recovery_verifications[1] = verification;
        let observation = run_case(config);
        assert_outcome(
            &observation.outcome,
            expected,
            &format!("final recovery row {row}"),
        );
        assert_eq!(observation.recovery_acquire_calls, 1);
        assert_eq!(observation.recovery_prepare_calls, 1);
        assert_eq!(observation.recovery_verify_calls, 2);
        assert_eq!(observation.recovery_published_count, 1);
        assert_eq!(observation.recovery_release_calls, 1);
        assert_eq!(observation.commit_calls, 0);
        assert_eq!(observation.generation_deltas, (0, 0, 0));
        assert_eq!(observation.permit_state, SyntheticPermitStateV1::Open);
    }
}

#[test]
fn store_rows_39_to_45_and_readback_are_closed_and_non_retrying() {
    let cases = [
        (
            39,
            CommitScript::Unavailable,
            ReadbackScript::DefiniteAbsence,
            ExpectedOutcome::Failed(PreparationFailureV1::StoreUnavailable),
            0,
            0,
        ),
        (
            40,
            CommitScript::Busy,
            ReadbackScript::DefiniteAbsence,
            ExpectedOutcome::Failed(PreparationFailureV1::StoreBusy),
            0,
            0,
        ),
        (
            41,
            CommitScript::Unhealthy,
            ReadbackScript::DefiniteAbsence,
            ExpectedOutcome::Failed(PreparationFailureV1::StoreUnhealthy),
            0,
            0,
        ),
        (
            42,
            CommitScript::Conflict,
            ReadbackScript::DefiniteAbsence,
            ExpectedOutcome::Failed(PreparationFailureV1::StoreConflict),
            0,
            0,
        ),
        (
            43,
            CommitScript::ConfirmedRollback,
            ReadbackScript::DefiniteAbsence,
            ExpectedOutcome::Failed(PreparationFailureV1::CommitAborted),
            1,
            0,
        ),
        (
            44,
            CommitScript::Uncertain,
            ReadbackScript::DefiniteAbsence,
            ExpectedOutcome::Failed(PreparationFailureV1::DefiniteAbsence),
            1,
            1,
        ),
        (
            45,
            CommitScript::Unclassified,
            ReadbackScript::DefiniteAbsence,
            ExpectedOutcome::Ambiguous(AmbiguousPreparationV1::CommitClassificationMissing),
            1,
            0,
        ),
        (
            45,
            CommitScript::Uncertain,
            ReadbackScript::Unavailable,
            ExpectedOutcome::Ambiguous(AmbiguousPreparationV1::ReadbackUnavailable),
            1,
            1,
        ),
        (
            45,
            CommitScript::Uncertain,
            ReadbackScript::Unhealthy,
            ExpectedOutcome::Ambiguous(AmbiguousPreparationV1::ReadbackInconsistent),
            1,
            1,
        ),
    ];
    for (row, commit, readback, expected, invocations, readbacks) in cases {
        let mut config = CaseConfig::coherent();
        config.commit = commit;
        config.readback = readback;
        let observation = run_case(config);
        assert_outcome(&observation.outcome, expected, &format!("store row {row}"));
        assert_eq!(observation.commit_calls, 1, "row {row}");
        assert_eq!(observation.commit_invocations, invocations, "row {row}");
        assert_eq!(observation.readback_calls, readbacks, "row {row}");
        assert_eq!(observation.generation_deltas, (0, 0, 0), "row {row}");
        assert_eq!(observation.recovery_published_count, 1, "row {row}");
        assert_eq!(observation.recovery_release_calls, 1, "row {row}");
        let expected_permit_state = match commit {
            CommitScript::Unavailable
            | CommitScript::Busy
            | CommitScript::Unhealthy
            | CommitScript::Conflict => SyntheticPermitStateV1::Open,
            CommitScript::ConfirmedRollback => SyntheticPermitStateV1::ResolvedAborted,
            CommitScript::Uncertain if readback == ReadbackScript::DefiniteAbsence => {
                SyntheticPermitStateV1::ResolvedAborted
            }
            CommitScript::Uncertain | CommitScript::Unclassified => {
                SyntheticPermitStateV1::ResolvedAmbiguous
            }
            CommitScript::Committed => unreachable!("the failure table has no committed row"),
        };
        assert_eq!(observation.permit_state, expected_permit_state, "row {row}");
    }
}

#[test]
fn exact_uncertain_readback_variants_resolve_without_a_second_commit() {
    let cases = [
        (
            ReadbackScript::ThisAttempt,
            ExpectedOutcome::Prepared,
            (1, 1, 1),
            SyntheticPermitStateV1::ResolvedCommitted,
        ),
        (
            ReadbackScript::PriorExactAttempt,
            ExpectedOutcome::Denied(PreparationDenialV1::AlreadyPrepared),
            (0, 0, 0),
            SyntheticPermitStateV1::ResolvedAborted,
        ),
        (
            ReadbackScript::Conflict,
            ExpectedOutcome::Denied(PreparationDenialV1::OperationConflict),
            (0, 0, 0),
            SyntheticPermitStateV1::ResolvedAborted,
        ),
    ];
    for (readback, expected, deltas, permit_state) in cases {
        let mut config = CaseConfig::coherent();
        config.commit = CommitScript::Uncertain;
        config.readback = readback;
        let observation = run_case(config);
        assert_outcome(&observation.outcome, expected, "uncertain exact readback");
        assert_eq!(observation.commit_calls, 1);
        assert_eq!(observation.commit_invocations, 1);
        assert_eq!(observation.readback_calls, 1);
        assert_eq!(observation.generation_deltas, deltas);
        assert_eq!(observation.recovery_published_count, 1);
        assert_eq!(observation.recovery_release_calls, 1);
        assert_eq!(observation.permit_state, permit_state);
    }
}

#[test]
fn injectable_adjacent_dual_faults_select_the_earlier_normative_row() {
    let mut cases = Vec::new();

    let final_pair = |first, second| {
        let mut config = CaseConfig::coherent();
        config.final_context = first;
        config.final_context_secondary = second;
        config
    };

    cases.push((
        "6+7",
        final_pair(
            SyntheticContextFaultV1::CaptureGeneration,
            SyntheticContextFaultV1::ClockGeneration,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::ContextMismatch),
    ));
    cases.push((
        "7+8",
        final_pair(
            SyntheticContextFaultV1::ClockGeneration,
            SyntheticContextFaultV1::UtcExpired,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::ClockMismatch),
    ));
    cases.push((
        "8+9",
        final_pair(
            SyntheticContextFaultV1::UtcExpired,
            SyntheticContextFaultV1::DeadlineGeneration,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::TimeExpired),
    ));
    cases.push((
        "9+10",
        final_pair(
            SyntheticContextFaultV1::DeadlineGeneration,
            SyntheticContextFaultV1::MonotonicDeadlineReached,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::DeadlineMismatch),
    ));
    cases.push((
        "10+11",
        final_pair(
            SyntheticContextFaultV1::MonotonicDeadlineReached,
            SyntheticContextFaultV1::Boot,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::DeadlineReached),
    ));
    cases.push((
        "11+12",
        final_pair(
            SyntheticContextFaultV1::Boot,
            SyntheticContextFaultV1::SupervisorDenied,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::BootMismatch),
    ));
    cases.push((
        "12+13",
        final_pair(
            SyntheticContextFaultV1::SupervisorDenied,
            SyntheticContextFaultV1::SupervisorGeneration,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::SupervisorDenied),
    ));

    let mut row_13_14 = CaseConfig::coherent();
    row_13_14.final_context = SyntheticContextFaultV1::SupervisorGeneration;
    row_13_14.post_final_capture_guard_fault = Some((
        AuthorityGuardKindV1::SignerTrust,
        SyntheticGuardStateV1::Revoked,
    ));
    cases.push((
        "13+14",
        row_13_14,
        ExpectedOutcome::Denied(PreparationDenialV1::SupervisorMismatch),
    ));

    let mut row_14_15 = CaseConfig::coherent();
    row_14_15.final_context = SyntheticContextFaultV1::Trust;
    row_14_15.post_final_capture_guard_fault = Some((
        AuthorityGuardKindV1::SignerTrust,
        SyntheticGuardStateV1::Revoked,
    ));
    cases.push((
        "14+15",
        row_14_15,
        ExpectedOutcome::Denied(PreparationDenialV1::GuardRevoked),
    ));

    cases.push((
        "15+16",
        final_pair(
            SyntheticContextFaultV1::Trust,
            SyntheticContextFaultV1::Workload,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::TrustMismatch),
    ));
    cases.push((
        "16+17",
        final_pair(
            SyntheticContextFaultV1::Workload,
            SyntheticContextFaultV1::Lease,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::WorkloadMismatch),
    ));
    cases.push((
        "17+18",
        final_pair(
            SyntheticContextFaultV1::Lease,
            SyntheticContextFaultV1::Authorization,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::LeaseMismatch),
    ));
    cases.push((
        "18+19",
        final_pair(
            SyntheticContextFaultV1::Authorization,
            SyntheticContextFaultV1::Policy,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::AuthorizationMismatch),
    ));
    cases.push((
        "19+20",
        final_pair(
            SyntheticContextFaultV1::Policy,
            SyntheticContextFaultV1::Catalogue,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::PolicyMismatch),
    ));
    cases.push((
        "20+21",
        final_pair(
            SyntheticContextFaultV1::Catalogue,
            SyntheticContextFaultV1::Capability,
        ),
        ExpectedOutcome::Denied(PreparationDenialV1::CatalogueMismatch),
    ));

    let mut row_21_22 = CaseConfig::coherent();
    row_21_22.preliminary_context = SyntheticContextFaultV1::Capability;
    row_21_22.preliminary_replay = ReplayClaimVerificationV1::Missing;
    cases.push((
        "21+22",
        row_21_22,
        ExpectedOutcome::Denied(PreparationDenialV1::CapabilityMismatch),
    ));

    let mut row_22_23 = CaseConfig::coherent();
    row_22_23.preliminary_context = SyntheticContextFaultV1::ReplayBinding;
    row_22_23.preliminary_replay = ReplayClaimVerificationV1::Missing;
    cases.push((
        "22+23",
        row_22_23,
        ExpectedOutcome::Denied(PreparationDenialV1::ReplayMissing),
    ));

    let mut row_23_24 = CaseConfig::coherent();
    row_23_24.preliminary_context = SyntheticContextFaultV1::ReplayBinding;
    row_23_24.preliminary_replay = ReplayClaimVerificationV1::Unavailable;
    cases.push((
        "23+24",
        row_23_24,
        ExpectedOutcome::Denied(PreparationDenialV1::ReplayConflict),
    ));

    let mut row_30_31 = CaseConfig::coherent();
    row_30_31.preliminary_context = SyntheticContextFaultV1::BudgetBinding;
    row_30_31.preliminary_preflight = PreflightScript::BudgetAuthorityUnavailable;
    cases.push((
        "30+31",
        row_30_31,
        ExpectedOutcome::Denied(PreparationDenialV1::BudgetAuthorityUnavailable),
    ));

    let mut row_31_32 = CaseConfig::coherent();
    row_31_32.preliminary_context = SyntheticContextFaultV1::BudgetBinding;
    row_31_32.preliminary_preflight = PreflightScript::BudgetArithmeticInvalid;
    cases.push((
        "31+32",
        row_31_32,
        ExpectedOutcome::Denied(PreparationDenialV1::BudgetBindingConflict),
    ));

    let mut row_33_34 = CaseConfig::coherent();
    row_33_34.preliminary_preflight = PreflightScript::BudgetExhausted;
    row_33_34.preliminary_context = SyntheticContextFaultV1::RecoveryProfile;
    cases.push((
        "33+34",
        row_33_34,
        ExpectedOutcome::Denied(PreparationDenialV1::BudgetExhausted),
    ));

    let mut row_34_35 = CaseConfig::coherent();
    row_34_35.preliminary_context = SyntheticContextFaultV1::RecoveryProfile;
    row_34_35.recovery_guard = SyntheticRecoveryGuardFaultV1::Unavailable;
    cases.push((
        "34+35",
        row_34_35,
        ExpectedOutcome::Denied(PreparationDenialV1::RecoveryProfileUnapproved),
    ));

    let mut row_36_37 = CaseConfig::coherent();
    row_36_37.final_context = SyntheticContextFaultV1::RecoveryBinding;
    row_36_37.recovery_verifications[1] = SyntheticRecoveryVerificationFaultV1::Missing;
    cases.push((
        "36+37",
        row_36_37,
        ExpectedOutcome::Denied(PreparationDenialV1::RecoveryBindingConflict),
    ));

    assert_eq!(
        cases.len(),
        23,
        "only independently injectable adjacent pairs belong in this table"
    );
    for (label, config, expected) in cases {
        let observation = run_case(config);
        assert_outcome(&observation.outcome, expected, label);
        assert_eq!(observation.commit_calls, 0, "{label}");
        assert_eq!(observation.commit_invocations, 0, "{label}");
        assert_eq!(observation.generation_deltas, (0, 0, 0), "{label}");
    }
}

#[test]
fn exact_replay_ignores_unrelated_global_generation_and_bounds_are_exclusive() {
    let observation = run_case(CaseConfig::coherent());
    assert_outcome(
        &observation.outcome,
        ExpectedOutcome::Prepared,
        "unrelated replay generation",
    );
    assert_eq!(observation.replay_calls, 2);
    assert_eq!(observation.replay_global_generation, 2);
    assert_eq!(observation.generation_deltas, (1, 1, 1));

    for (fault, denial) in [
        (
            SyntheticContextFaultV1::UtcExpired,
            PreparationDenialV1::TimeExpired,
        ),
        (
            SyntheticContextFaultV1::MonotonicDeadlineReached,
            PreparationDenialV1::DeadlineReached,
        ),
    ] {
        let mut config = CaseConfig::coherent();
        config.preliminary_context = fault;
        let observation = run_case(config);
        assert_outcome(
            &observation.outcome,
            ExpectedOutcome::Denied(denial),
            "exclusive equality",
        );
        assert_eq!(observation.commit_invocations, 0);
    }

    let mut utc_one_before = CaseConfig::coherent();
    utc_one_before.clock_utc_ms = feature002::EXPIRES_AT_MS - 1;
    let observation = run_case(utc_one_before);
    assert_outcome(
        &observation.outcome,
        ExpectedOutcome::Prepared,
        "UTC bound minus one",
    );
    assert_eq!(observation.generation_deltas, (1, 1, 1));
    assert_eq!(observation.recovery_published_count, 1);
    assert_eq!(
        observation.permit_state,
        SyntheticPermitStateV1::ResolvedCommitted
    );

    let mut monotonic_one_before = CaseConfig::coherent();
    monotonic_one_before.clock_monotonic_ms = CALLER_DEADLINE - 1;
    let observation = run_case(monotonic_one_before);
    assert_outcome(
        &observation.outcome,
        ExpectedOutcome::Prepared,
        "monotonic bound minus one",
    );
    assert_eq!(observation.generation_deltas, (1, 1, 1));
    assert_eq!(observation.recovery_published_count, 1);
    assert_eq!(
        observation.permit_state,
        SyntheticPermitStateV1::ResolvedCommitted
    );
}

#[cfg(feature = "test-fault-injection")]
const PREPARE_SUCCESS_BOUNDARY_OCCURRENCES_V1: [(&str, u64); 34] = [
    ("preliminary_attempt_identity_generated", 1),
    ("preliminary_context_returned", 1),
    ("preliminary_first_failure_group_classified", 12),
    ("preliminary_replay_snapshot_opened", 1),
    ("preliminary_replay_snapshot_classified", 1),
    ("preliminary_preflight_snapshot_opened", 1),
    ("preliminary_operation_identity_classified", 1),
    ("preliminary_budget_binding_classified", 1),
    ("preliminary_budget_arithmetic_classified", 1),
    ("preliminary_budget_capacity_classified", 1),
    ("final_comparison_guard_acquired", 10),
    ("final_comparison_context_returned", 1),
    ("final_comparison_first_failure_group_classified", 12),
    ("final_comparison_replay_snapshot_opened", 1),
    ("final_comparison_replay_snapshot_classified", 1),
    ("final_comparison_preflight_snapshot_opened", 1),
    ("final_comparison_operation_identity_classified", 1),
    ("final_comparison_budget_binding_classified", 1),
    ("final_comparison_budget_arithmetic_classified", 1),
    ("final_comparison_budget_capacity_classified", 1),
    ("final_comparison_recovery_receipt_reopened", 1),
    ("final_comparison_recovery_receipt_revalidated", 1),
    ("final_comparison_utc_sample_returned", 1),
    ("final_comparison_monotonic_sample_returned", 1),
    (
        "positive_coordinator_commit_enter_commit_permit_returned",
        1,
    ),
    (
        "positive_coordinator_commit_permit_moved_to_commit_in_flight",
        1,
    ),
    ("positive_coordinator_commit_permit_resolved_committed", 1),
    ("positive_coordinator_commit_permit_resolved_aborted", 0),
    ("positive_coordinator_commit_permit_resolved_ambiguous", 0),
    ("acknowledgement_post_commit_time_classified", 1),
    ("acknowledgement_post_commit_guards_classified", 1),
    ("acknowledgement_positive_marker_constructed", 1),
    ("acknowledgement_result_returned", 1),
    ("acknowledgement_all_final_guards_released", 1),
];

#[cfg(feature = "test-fault-injection")]
fn run_selected_boundary(
    config: CaseConfig,
    boundary_id: &'static str,
    occurrence: u64,
) -> (CaseObservation, std::sync::Arc<AtomicUsize>) {
    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let fault_probe =
        FaultProbeV1::selected_process_barrier_v1(boundary_id, occurrence, move || {
            callback_calls.fetch_add(1, Ordering::SeqCst);
        })
        .expect("the frozen boundary and occurrence are valid");
    (run_case_with_fault_probe(config, fault_probe), calls)
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn explicit_probe_reaches_real_prepare_path_with_exact_success_multiplicities() {
    assert_eq!(
        PREPARE_SUCCESS_BOUNDARY_OCCURRENCES_V1[..10]
            .iter()
            .map(|(_, count)| count)
            .sum::<u64>(),
        21,
        "the preliminary action has exactly 21 expanded occurrences"
    );
    assert_eq!(
        PREPARE_SUCCESS_BOUNDARY_OCCURRENCES_V1[10..24]
            .iter()
            .map(|(_, count)| count)
            .sum::<u64>(),
        34,
        "the final-comparison action has exactly 34 expanded occurrences"
    );
    assert_eq!(
        PREPARE_SUCCESS_BOUNDARY_OCCURRENCES_V1[24..29]
            .iter()
            .map(|(_, count)| count)
            .sum::<u64>(),
        3,
        "the committed positive action has exactly three expanded occurrences"
    );
    assert_eq!(
        PREPARE_SUCCESS_BOUNDARY_OCCURRENCES_V1[29..]
            .iter()
            .map(|(_, count)| count)
            .sum::<u64>(),
        5,
        "acknowledgement has exactly five expanded occurrences"
    );

    for (boundary_id, expected_occurrences) in PREPARE_SUCCESS_BOUNDARY_OCCURRENCES_V1 {
        if expected_occurrences > 0 {
            let (observation, calls) =
                run_selected_boundary(CaseConfig::coherent(), boundary_id, expected_occurrences);
            assert_outcome(&observation.outcome, ExpectedOutcome::Prepared, boundary_id);
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{boundary_id}");
        }

        let (observation, calls) = run_selected_boundary(
            CaseConfig::coherent(),
            boundary_id,
            expected_occurrences + 1,
        );
        assert_outcome(&observation.outcome, ExpectedOutcome::Prepared, boundary_id);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "{boundary_id}: no hidden extra occurrence may be reached"
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn explicit_probe_reaches_aborted_ambiguous_and_known_failure_branches() {
    let mut aborted = CaseConfig::coherent();
    aborted.commit = CommitScript::ConfirmedRollback;
    let (observation, calls) = run_selected_boundary(
        aborted,
        "positive_coordinator_commit_permit_resolved_aborted",
        1,
    );
    assert_outcome(
        &observation.outcome,
        ExpectedOutcome::Failed(PreparationFailureV1::CommitAborted),
        "permit resolved aborted",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut unclassified = CaseConfig::coherent();
    unclassified.commit = CommitScript::Unclassified;
    let (observation, calls) = run_selected_boundary(
        unclassified,
        "positive_coordinator_commit_permit_resolved_ambiguous",
        1,
    );
    assert_outcome(
        &observation.outcome,
        ExpectedOutcome::Ambiguous(AmbiguousPreparationV1::CommitClassificationMissing),
        "permit resolved ambiguous",
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    for (boundary_id, reach) in [
        (
            "known_failure_no_dispatch_guard_acquired",
            helix_plan_preparation::note_known_failure_guard_acquired_with_fault_probe_v1
                as fn(&FaultProbeV1),
        ),
        (
            "known_failure_no_dispatch_guard_finally_revalidated",
            helix_plan_preparation::note_known_failure_guard_finally_revalidated_with_fault_probe_v1
                as fn(&FaultProbeV1),
        ),
    ] {
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let callback_calls = std::sync::Arc::clone(&calls);
        let fault_probe = FaultProbeV1::selected_process_barrier_v1(boundary_id, 1, move || {
            callback_calls.fetch_add(1, Ordering::SeqCst);
        })
        .expect("known-failure boundary selects");
        reach(&fault_probe);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{boundary_id}");
    }

    struct ReleasableGuard(std::sync::Arc<AtomicUsize>);
    impl NoDispatchAuthorityGuardV1 for ReleasableGuard {
        fn validate(
            &mut self,
            _expected: &helix_plan_preparation::NoDispatchAuthorityBindingV1<'_>,
            _now_monotonic_ms: u64,
        ) -> helix_plan_preparation::NoDispatchAuthorityValidationV1 {
            helix_plan_preparation::NoDispatchAuthorityValidationV1::Valid
        }

        fn release(self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let callback_calls = std::sync::Arc::clone(&calls);
    let releases = std::sync::Arc::new(AtomicUsize::new(0));
    let fault_probe = FaultProbeV1::selected_process_barrier_v1(
        "known_failure_no_dispatch_guard_released",
        1,
        move || {
            callback_calls.fetch_add(1, Ordering::SeqCst);
        },
    )
    .expect("known-failure release boundary selects");
    helix_plan_preparation::release_known_failure_guard_with_fault_probe_v1(
        ReleasableGuard(std::sync::Arc::clone(&releases)),
        &fault_probe,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
}

/// Compile-time contract for the public T036/T037 orchestration seam.
///
/// Attempt generation remains internal; callers provide only the consumed eligibility
/// marker and injected sovereign dependencies.
#[allow(dead_code)]
fn agreed_prepare_seam<A, R, S, P, T>(
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
    prepare_plan_v1(
        eligible,
        authority,
        replay_verifier,
        store,
        recovery_provider,
        time_source,
        caller_deadline_monotonic_ms,
    )
}
