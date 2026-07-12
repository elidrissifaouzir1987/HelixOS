//! T050 executable recovery contract for PLAN-004 user story 3.
//!
//! The provider below is deliberately public-synthetic and in-memory. It proves only
//! protocol ordering through the portable provider trait; it is not production
//! durability evidence and never receives material bytes, a native path, or a handle.

mod common;

use common::{
    feature002, synthetic_eligible_plan_v1, DeterministicPreparationClockV1,
    SyntheticAuthorityGuardControlV1, SyntheticConformanceRecoveryProviderV1,
    SyntheticContextFaultV1, SyntheticPreparationAuthorityV1, SyntheticRecoveryGuardFaultV1,
    SyntheticRecoveryPreparationFaultV1, SyntheticRecoveryPublicationGuardV1,
    SyntheticRecoveryVerificationFaultV1, SyntheticSupervisorPermitControlV1,
    SYNTHETIC_AT_REST_PROFILE_ID, SYNTHETIC_RECOVERY_EVIDENCE_CLASS_ID,
    SYNTHETIC_RECOVERY_PROFILE_ID, SYNTHETIC_RECOVERY_PROVIDER_ID,
};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AtomicityV1, ContractError, Ed25519KeyResolver,
    Ed25519Signer, Identifier, Nonce128, RecoveryClassV1, Result as ContractResult, RiskLevelV1,
    Sha256Digest,
};
use helix_plan_eligibility::{
    AuthorizationInputV1, AuthorizationRecordV1, AuthorizationStatusV1, AuthorizationViewV1,
    EligibilityContextV1, EligiblePlanV1, ReadyEligibilityContextV1, ReplayClaimVerificationV1,
    ReplayClaimVerificationViewV1, ReplayClaimVerifierV1,
};
use helix_plan_preparation::{
    prepare_plan_v1, AmbiguousPreparationV1, BudgetPreflightInputV1, BudgetPreflightV1,
    BudgetReservationReceiptInputV1, BudgetReservationReceiptV1, BudgetReservationStateV1,
    BudgetVectorInputV1, BudgetVectorV1, FinalCommitGateV1, FinalCommitPermitOutcomeV1,
    FinalCommitPermitRequestInputV1, FinalCommitPermitRequestV1, FinalCommitPermitV1,
    FinalCommitResolutionV1, FinalCommitStoreClassificationV1, NoDispatchAuthorityGuardV1,
    PreparationCommitInputV1, PreparationCommitOutcomeV1, PreparationCommitReceiptInputV1,
    PreparationCommitReceiptV1, PreparationDenialV1, PreparationFailureInputV1,
    PreparationFailureOutcomeV1, PreparationFailureV1, PreparationOutcomeV1,
    PreparationPreflightInputV1, PreparationPreflightOutcomeV1, PreparationReadbackInputV1,
    PreparationReadbackOutcomeV1, PreparationStoreV1, RecoveryEvidenceClassV1, RecoveryEvidenceV1,
    RecoveryGuardOutcomeV1, RecoveryMaterialReceiptInputV1, RecoveryMaterialReceiptV1,
    RecoveryMaterialStateV1, RecoveryPreparationInputV1, RecoveryPreparationOutcomeV1,
    RecoveryProviderV1, RecoveryPublicationGuardV1, RecoveryVerificationV1,
    PREPARATION_BUDGET_CONTRACT_VERSION_V1, PREPARATION_STORE_CONTRACT_VERSION_V1,
};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const CALLER_DEADLINE_MONOTONIC_MS: u64 = 60_000;
const RECOVERY_SOURCE: &str = include_str!("../src/recovery.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationBoundaryV1 {
    GuardAcquired,
    StagingCreated,
    MaterialWritten,
    MaterialSynchronized,
    MaterialClosed,
    MaterialReopened,
    MaterialDigestLengthCapacityVerified,
    MaterialPublished,
    ManifestStaged,
    ManifestSynchronized,
    ManifestPublished,
    ManifestReopened,
    ReceiptReturned,
    ReceiptRevalidated,
    CommitEntered,
    ReadbackEntered,
    ReadbackReturned,
    GuardReleased,
}

const MANIFEST_LAST_BOUNDARIES: [PublicationBoundaryV1; 11] = [
    PublicationBoundaryV1::StagingCreated,
    PublicationBoundaryV1::MaterialWritten,
    PublicationBoundaryV1::MaterialSynchronized,
    PublicationBoundaryV1::MaterialClosed,
    PublicationBoundaryV1::MaterialReopened,
    PublicationBoundaryV1::MaterialDigestLengthCapacityVerified,
    PublicationBoundaryV1::MaterialPublished,
    PublicationBoundaryV1::ManifestStaged,
    PublicationBoundaryV1::ManifestSynchronized,
    PublicationBoundaryV1::ManifestPublished,
    PublicationBoundaryV1::ManifestReopened,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptFaultV1 {
    ProviderGeneration,
    TargetReference,
    PreconditionIdentity,
    BootBinding,
    MaterialDigest,
    MaterialLengthMinusOne,
    MaterialLengthPlusOne,
    ReservedCapacityMinusOne,
    ReservedCapacityPlusOne,
}

struct ManifestLastGuardV1 {
    inner: SyntheticRecoveryPublicationGuardV1,
    trace: Arc<Mutex<Vec<PublicationBoundaryV1>>>,
}

impl fmt::Debug for ManifestLastGuardV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestLastGuardV1")
            .finish_non_exhaustive()
    }
}

impl RecoveryPublicationGuardV1 for ManifestLastGuardV1 {
    fn release(self) {
        self.trace
            .lock()
            .expect("publication trace mutex is not poisoned")
            .push(PublicationBoundaryV1::GuardReleased);
        self.inner.release();
    }
}

#[derive(Clone)]
struct ManifestLastProviderV1 {
    inner: SyntheticConformanceRecoveryProviderV1,
    trace: Arc<Mutex<Vec<PublicationBoundaryV1>>>,
    stop_after: Option<PublicationBoundaryV1>,
    receipt_faults: Vec<ReceiptFaultV1>,
}

impl ManifestLastProviderV1 {
    fn exact() -> Self {
        Self::with_faults(
            SyntheticRecoveryGuardFaultV1::Exact,
            SyntheticRecoveryPreparationFaultV1::Exact,
            vec![SyntheticRecoveryVerificationFaultV1::Exact; 3],
            None,
            Vec::new(),
        )
    }

    fn with_faults(
        guard_fault: SyntheticRecoveryGuardFaultV1,
        preparation_fault: SyntheticRecoveryPreparationFaultV1,
        verification_faults: Vec<SyntheticRecoveryVerificationFaultV1>,
        stop_after: Option<PublicationBoundaryV1>,
        receipt_faults: Vec<ReceiptFaultV1>,
    ) -> Self {
        Self {
            inner: SyntheticConformanceRecoveryProviderV1::with_faults_test_only(
                guard_fault,
                preparation_fault,
                verification_faults,
            ),
            trace: Arc::new(Mutex::new(Vec::new())),
            stop_after,
            receipt_faults,
        }
    }

    fn trace(&self) -> Vec<PublicationBoundaryV1> {
        self.trace
            .lock()
            .expect("publication trace mutex is not poisoned")
            .clone()
    }

    fn trace_handle(&self) -> Arc<Mutex<Vec<PublicationBoundaryV1>>> {
        Arc::clone(&self.trace)
    }

    fn push(&self, boundary: PublicationBoundaryV1) -> bool {
        self.trace
            .lock()
            .expect("publication trace mutex is not poisoned")
            .push(boundary);
        self.stop_after == Some(boundary)
    }

    fn acquire_calls(&self) -> usize {
        self.inner.acquire_count_test_only()
    }

    fn prepare_calls(&self) -> usize {
        self.inner.prepare_count_test_only()
    }

    fn verify_calls(&self) -> usize {
        self.inner.verify_count_test_only()
    }

    fn release_calls(&self) -> usize {
        self.inner.released_guard_count_test_only()
    }
}

impl fmt::Debug for ManifestLastProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestLastProviderV1")
            .finish_non_exhaustive()
    }
}

impl RecoveryProviderV1 for ManifestLastProviderV1 {
    type PublicationGuard = ManifestLastGuardV1;

    fn acquire_publication_guard(
        &self,
        input: &helix_plan_preparation::RecoveryBindingV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> RecoveryGuardOutcomeV1<Self::PublicationGuard> {
        match self
            .inner
            .acquire_publication_guard(input, deadline_monotonic_ms)
        {
            RecoveryGuardOutcomeV1::Acquired(inner) => {
                self.push(PublicationBoundaryV1::GuardAcquired);
                RecoveryGuardOutcomeV1::Acquired(ManifestLastGuardV1 {
                    inner,
                    trace: Arc::clone(&self.trace),
                })
            }
            RecoveryGuardOutcomeV1::Unavailable => RecoveryGuardOutcomeV1::Unavailable,
            RecoveryGuardOutcomeV1::DeadlineReached => RecoveryGuardOutcomeV1::DeadlineReached,
            RecoveryGuardOutcomeV1::Conflict => RecoveryGuardOutcomeV1::Conflict,
            RecoveryGuardOutcomeV1::Unsupported => RecoveryGuardOutcomeV1::Unsupported,
        }
    }

    fn prepare_and_publish(
        &self,
        guard: &mut Self::PublicationGuard,
        input: &RecoveryPreparationInputV1<'_>,
    ) -> RecoveryPreparationOutcomeV1 {
        for boundary in MANIFEST_LAST_BOUNDARIES {
            if self.push(boundary) {
                return RecoveryPreparationOutcomeV1::ProviderFailed;
            }
        }
        match self.inner.prepare_and_publish(&mut guard.inner, input) {
            RecoveryPreparationOutcomeV1::Published(receipt) => {
                let receipt = rebuild_receipt_with_faults_v1(&receipt, &self.receipt_faults)
                    .expect("synthetic receipt mutation remains structurally valid");
                self.push(PublicationBoundaryV1::ReceiptReturned);
                RecoveryPreparationOutcomeV1::Published(receipt)
            }
            RecoveryPreparationOutcomeV1::BindingConflict => {
                RecoveryPreparationOutcomeV1::BindingConflict
            }
            RecoveryPreparationOutcomeV1::Unverified => RecoveryPreparationOutcomeV1::Unverified,
            RecoveryPreparationOutcomeV1::ProviderFailed => {
                RecoveryPreparationOutcomeV1::ProviderFailed
            }
            RecoveryPreparationOutcomeV1::Ambiguous => RecoveryPreparationOutcomeV1::Ambiguous,
        }
    }

    fn verify_published(
        &self,
        guard: &mut Self::PublicationGuard,
        receipt: &RecoveryMaterialReceiptV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryVerificationV1 {
        let result = self
            .inner
            .verify_published(&mut guard.inner, receipt, deadline_monotonic_ms);
        self.push(PublicationBoundaryV1::ReceiptRevalidated);
        result
    }
}

#[derive(Default)]
struct ExactReplayV1 {
    calls: AtomicUsize,
}

impl ExactReplayV1 {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ReplayClaimVerifierV1 for ExactReplayV1 {
    fn verify_exact_claim(
        &self,
        _view: &ReplayClaimVerificationViewV1<'_>,
        _deadline_monotonic_ms: u64,
    ) -> ReplayClaimVerificationV1 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ReplayClaimVerificationV1::Exact
    }
}

#[derive(Clone, Copy)]
enum ExactCommitScriptV1 {
    Committed,
    Uncertain,
}

#[derive(Clone, Copy)]
enum ExactReadbackScriptV1 {
    DefiniteAbsence,
    ThisAttempt,
    Unavailable,
}

struct ExactStoreV1 {
    trace: Arc<Mutex<Vec<PublicationBoundaryV1>>>,
    commit: ExactCommitScriptV1,
    readback: ExactReadbackScriptV1,
    preflight_calls: AtomicUsize,
    commit_calls: AtomicUsize,
    material_commits: AtomicUsize,
    irreversible_commits: AtomicUsize,
}

impl ExactStoreV1 {
    fn new(
        trace: Arc<Mutex<Vec<PublicationBoundaryV1>>>,
        commit: ExactCommitScriptV1,
        readback: ExactReadbackScriptV1,
    ) -> Self {
        Self {
            trace,
            commit,
            readback,
            preflight_calls: AtomicUsize::new(0),
            commit_calls: AtomicUsize::new(0),
            material_commits: AtomicUsize::new(0),
            irreversible_commits: AtomicUsize::new(0),
        }
    }

    fn push(&self, boundary: PublicationBoundaryV1) {
        self.trace
            .lock()
            .expect("publication trace mutex is not poisoned")
            .push(boundary);
    }

    fn assert_material_guard_held(&self, boundary: PublicationBoundaryV1) {
        let trace = self
            .trace
            .lock()
            .expect("publication trace mutex is not poisoned");
        assert!(
            trace.contains(&PublicationBoundaryV1::GuardAcquired),
            "publication guard was never acquired before {boundary:?}"
        );
        assert!(
            !trace.contains(&PublicationBoundaryV1::GuardReleased),
            "publication guard was released before {boundary:?}"
        );
    }

    fn ready_preflight(input: &PreparationPreflightInputV1<'_>) -> BudgetPreflightV1 {
        let requested = input.requested_budget();
        let remaining = BudgetVectorV1::try_new(BudgetVectorInputV1 {
            max_cost_micro_units: requested.max_cost_micro_units(),
            action_limit: requested.action_limit(),
            egress_bytes_limit: requested.egress_bytes_limit(),
            recovery_bytes: requested.recovery_bytes(),
        })
        .expect("synthetic exact remaining vector is valid");
        BudgetPreflightV1::try_new(BudgetPreflightInputV1 {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            observed_scope_generation: input.context().budget_scope_generation(),
            observed_scope_binding_digest: input.context().budget_scope_binding_digest(),
            observed_remaining: remaining,
        })
        .expect("synthetic exact preflight is valid")
    }

    fn commit_receipt(attempt_id: Sha256Digest) -> PreparationCommitReceiptV1 {
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
        .expect("synthetic exact commit receipt is valid")
    }
}

impl PreparationStoreV1 for ExactStoreV1 {
    fn preflight_operation_and_budget(
        &self,
        input: &PreparationPreflightInputV1<'_>,
    ) -> PreparationPreflightOutcomeV1 {
        self.preflight_calls.fetch_add(1, Ordering::SeqCst);
        PreparationPreflightOutcomeV1::Ready(Self::ready_preflight(input))
    }

    fn commit_preparing<G: FinalCommitGateV1>(
        &self,
        input: &PreparationCommitInputV1<'_>,
        final_gate: &mut G,
    ) -> PreparationCommitOutcomeV1<<G::Permit as FinalCommitPermitV1>::InFlight> {
        self.commit_calls.fetch_add(1, Ordering::SeqCst);
        match input.recovery_evidence() {
            RecoveryEvidenceV1::Material(_) => {
                self.assert_material_guard_held(PublicationBoundaryV1::CommitEntered);
                self.push(PublicationBoundaryV1::CommitEntered);
                self.material_commits.fetch_add(1, Ordering::SeqCst);
            }
            RecoveryEvidenceV1::Irreversible(evidence) => {
                assert_eq!(evidence.risk_level(), RiskLevelV1::L2);
                assert_eq!(evidence.recovery_class(), RecoveryClassV1::Irreversible);
                assert!(evidence.no_material());
                self.irreversible_commits.fetch_add(1, Ordering::SeqCst);
            }
        }
        let request = FinalCommitPermitRequestV1::try_new(FinalCommitPermitRequestInputV1 {
            attempt: input.attempt(),
            expected_supervisor_generation: input.final_context().supervisor_generation(),
            caller_deadline_monotonic_ms: input.final_context().effective_deadline_monotonic_ms(),
            permit_entry_monotonic_ms: input.final_context().sampled_monotonic_ms(),
        })
        .expect("synthetic commit permit request is valid");
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
            ExactCommitScriptV1::Committed => FinalCommitStoreClassificationV1::Committed,
            ExactCommitScriptV1::Uncertain => FinalCommitStoreClassificationV1::Uncertain,
        };
        match permit.commit_once_instrumented_v1(|| classification) {
            FinalCommitResolutionV1::Committed => PreparationCommitOutcomeV1::Committed(
                Self::commit_receipt(input.attempt().digest()),
            ),
            FinalCommitResolutionV1::Aborted => PreparationCommitOutcomeV1::ConfirmedRollback,
            FinalCommitResolutionV1::Uncertain(in_flight) => {
                let token = helix_plan_preparation::PreparationCommitUncertainV1::try_new(
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
        self.assert_material_guard_held(PublicationBoundaryV1::ReadbackEntered);
        self.push(PublicationBoundaryV1::ReadbackEntered);
        let outcome = match self.readback {
            ExactReadbackScriptV1::DefiniteAbsence => PreparationReadbackOutcomeV1::DefiniteAbsence,
            ExactReadbackScriptV1::ThisAttempt => PreparationReadbackOutcomeV1::ThisAttempt(
                Self::commit_receipt(input.attempt().digest()),
            ),
            ExactReadbackScriptV1::Unavailable => PreparationReadbackOutcomeV1::Unavailable,
        };
        self.push(PublicationBoundaryV1::ReadbackReturned);
        outcome
    }

    fn fail_before_dispatch<G: NoDispatchAuthorityGuardV1>(
        &self,
        _input: &PreparationFailureInputV1<'_>,
        _no_dispatch_guard: &mut G,
    ) -> PreparationFailureOutcomeV1 {
        PreparationFailureOutcomeV1::Unavailable
    }
}

struct CaseObservationV1 {
    outcome: PreparationOutcomeV1,
    replay_calls: usize,
    preflight_calls: usize,
    commit_calls: usize,
    material_commits: usize,
    irreversible_commits: usize,
}

fn run_case_v1(
    eligible: EligiblePlanV1,
    preliminary_fault: SyntheticContextFaultV1,
    provider: &ManifestLastProviderV1,
) -> CaseObservationV1 {
    run_case_with_store_script_v1(
        eligible,
        preliminary_fault,
        provider,
        ExactCommitScriptV1::Committed,
        ExactReadbackScriptV1::DefiniteAbsence,
    )
}

fn run_case_with_store_script_v1(
    eligible: EligiblePlanV1,
    preliminary_fault: SyntheticContextFaultV1,
    provider: &ManifestLastProviderV1,
    commit: ExactCommitScriptV1,
    readback: ExactReadbackScriptV1,
) -> CaseObservationV1 {
    let clock = DeterministicPreparationClockV1::coherent();
    let authority = SyntheticPreparationAuthorityV1::with_context_faults_test_only(
        clock.clone(),
        SyntheticAuthorityGuardControlV1::new_test_only(),
        SyntheticSupervisorPermitControlV1::new_test_only(feature002::SUPERVISOR_GENERATION),
        preliminary_fault,
        SyntheticContextFaultV1::None,
    );
    let replay = ExactReplayV1::default();
    let store = ExactStoreV1::new(provider.trace_handle(), commit, readback);
    let outcome = prepare_plan_v1(
        eligible,
        &authority,
        &replay,
        &store,
        provider,
        &clock,
        CALLER_DEADLINE_MONOTONIC_MS,
    );
    CaseObservationV1 {
        outcome,
        replay_calls: replay.calls(),
        preflight_calls: store.preflight_calls.load(Ordering::SeqCst),
        commit_calls: store.commit_calls.load(Ordering::SeqCst),
        material_commits: store.material_commits.load(Ordering::SeqCst),
        irreversible_commits: store.irreversible_commits.load(Ordering::SeqCst),
    }
}

#[derive(Debug)]
struct FixedResolverV1 {
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for FixedResolverV1 {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == feature002::KEY_ID {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

fn synthetic_irreversible_eligible_plan_v1() -> EligiblePlanV1 {
    let mut input = feature002::sample_plan_input();
    input.risk_level = RiskLevelV1::L2;
    input.recovery.class = RecoveryClassV1::Irreversible;
    input.recovery.reserved_bytes = 0;

    let signer = feature002::TestSigner::fixed();
    assert_eq!(signer.key_id(), feature002::KEY_ID);
    let resolver = FixedResolverV1 {
        public_key: signer.verifying_key_bytes(),
    };
    let signed = sign_plan_v1(input, &signer).expect("synthetic L2 plan signs");
    let wire = signed
        .to_canonical_json()
        .expect("synthetic L2 plan canonicalizes");
    let plan = decode_and_verify_plan(&wire, &resolver).expect("synthetic L2 plan authenticates");
    let plan_id = plan.plan_id();
    let mut ready = feature002::coherent_ready_input(&plan);
    ready.authorization = AuthorizationViewV1::Current(
        AuthorizationRecordV1::try_new(AuthorizationInputV1 {
            status: AuthorizationStatusV1::Granted,
            plan_id,
            operation_id: feature002::OPERATION_ID,
            risk_level: RiskLevelV1::L2,
            nonce: Nonce128::from_bytes([0x11; 16]),
            evidence_digest: feature002::digest(b"fixture L2 authorization evidence"),
            authorization_generation: feature002::AUTHORIZATION_GENERATION,
            boot_id: feature002::BOOT_ID,
            not_before_utc_unix_ms: feature002::ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: feature002::ISSUED_AT_MS + 190_000,
            deadline_monotonic_ms: 110_000,
        })
        .expect("synthetic L2 authorization is valid"),
    );
    feature002::EligibilityFixture {
        plan,
        context: EligibilityContextV1::Ready(
            ReadyEligibilityContextV1::try_new(ready)
                .expect("synthetic L2 eligibility context is coherent"),
        ),
    }
    .evaluate(&feature002::ClaimantProbe::default())
    .expect("synthetic L2 plan is eligible")
}

fn rebuild_receipt_with_faults_v1(
    receipt: &RecoveryMaterialReceiptV1,
    faults: &[ReceiptFaultV1],
) -> Option<RecoveryMaterialReceiptV1> {
    let mut input = RecoveryMaterialReceiptInputV1 {
        contract_version: receipt.contract_version(),
        provider_profile_id: identifier_v1(receipt.provider_profile_id())?,
        provider_profile_version: receipt.provider_profile_version(),
        provider_id: identifier_v1(receipt.provider_id())?,
        provider_generation: receipt.provider_generation(),
        evidence_class: match receipt.evidence_class() {
            RecoveryEvidenceClassV1::SyntheticConformance => {
                RecoveryEvidenceClassV1::SyntheticConformance
            }
            RecoveryEvidenceClassV1::ApprovedProduction => {
                RecoveryEvidenceClassV1::ApprovedProduction
            }
        },
        at_rest_profile_id: identifier_v1(receipt.at_rest_profile_id())?,
        capability_binding_digest: receipt.capability_binding_digest(),
        plan_id: receipt.plan_id(),
        operation_id: identifier_v1(receipt.operation_id())?,
        attempt_id: receipt.attempt_id(),
        target_reference_digest: receipt.target_reference_digest(),
        precondition_identity_digest: receipt.precondition_identity_digest(),
        precondition_digest: receipt.precondition_digest(),
        precondition_length: receipt.precondition_length(),
        recovery_class: receipt.recovery_class(),
        atomicity: receipt.atomicity(),
        material_digest: receipt.material_digest(),
        material_length: receipt.material_length(),
        reserved_capacity: receipt.reserved_capacity(),
        material_id: receipt.material_id(),
        publication_attempt_id: receipt.publication_attempt_id(),
        manifest_digest: receipt.manifest_digest(),
        state: RecoveryMaterialStateV1::Published,
        boot_binding_digest: receipt.boot_binding_digest(),
        instance_epoch: receipt.instance_epoch(),
        fencing_epoch: receipt.fencing_epoch(),
    };
    for fault in faults {
        match fault {
            ReceiptFaultV1::ProviderGeneration => {
                input.provider_generation = input.provider_generation.checked_add(1)?;
            }
            ReceiptFaultV1::TargetReference => {
                input.target_reference_digest = different_digest_v1(input.target_reference_digest);
            }
            ReceiptFaultV1::PreconditionIdentity => {
                input.precondition_identity_digest =
                    different_digest_v1(input.precondition_identity_digest);
            }
            ReceiptFaultV1::BootBinding => {
                input.boot_binding_digest = different_digest_v1(input.boot_binding_digest);
            }
            ReceiptFaultV1::MaterialDigest => {
                input.material_digest = different_digest_v1(input.material_digest);
            }
            ReceiptFaultV1::MaterialLengthMinusOne => {
                input.material_length = input.material_length.checked_sub(1)?;
            }
            ReceiptFaultV1::MaterialLengthPlusOne => {
                input.material_length = input.material_length.checked_add(1)?;
            }
            ReceiptFaultV1::ReservedCapacityMinusOne => {
                input.reserved_capacity = input.reserved_capacity.checked_sub(1)?;
            }
            ReceiptFaultV1::ReservedCapacityPlusOne => {
                input.reserved_capacity = input.reserved_capacity.checked_add(1)?;
            }
        }
    }
    RecoveryMaterialReceiptV1::try_new(input).ok()
}

fn identifier_v1(value: &str) -> Option<Identifier> {
    Identifier::new(value, 128).ok()
}

fn different_digest_v1(value: Sha256Digest) -> Sha256Digest {
    let mut bytes = *value.as_bytes();
    bytes[0] ^= 1;
    Sha256Digest::from_bytes(bytes)
}

fn assert_denied_v1(outcome: &PreparationOutcomeV1, expected: PreparationDenialV1) {
    assert!(
        matches!(outcome, PreparationOutcomeV1::Denied(actual) if actual == &expected),
        "expected denial {expected:?}, got {outcome:?}"
    );
}

fn assert_failed_v1(outcome: &PreparationOutcomeV1, expected: PreparationFailureV1) {
    assert!(
        matches!(outcome, PreparationOutcomeV1::Failed(actual) if actual == &expected),
        "expected failure {expected:?}, got {outcome:?}"
    );
}

#[test]
fn approved_provider_profile_is_a_typed_closed_v1_contract() {
    assert!(
        RECOVERY_SOURCE.contains("pub struct RecoveryProviderProfileInputV1"),
        "T053 must expose the trusted profile input named by PLAN-004"
    );
    assert!(
        RECOVERY_SOURCE.contains("pub struct RecoveryProviderProfileV1"),
        "T053 must expose the trusted provider profile named by PLAN-004"
    );
    for field in [
        "profile_id",
        "profile_version",
        "provider_id",
        "provider_generation",
        "evidence_class",
        "capability_binding_digest",
        "at_rest_profile_id",
        "supports_create_only",
        "supports_sync",
        "supports_no_clobber_publication",
    ] {
        assert!(
            RECOVERY_SOURCE.contains(field),
            "missing profile field {field}"
        );
    }
}

#[test]
fn exact_compensation_publishes_manifest_last_and_revalidates_before_release() {
    let provider = ManifestLastProviderV1::exact();
    let observation = run_case_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &provider,
    );
    assert!(matches!(
        observation.outcome,
        PreparationOutcomeV1::Prepared(_)
    ));
    assert_eq!(observation.replay_calls, 2);
    assert_eq!(observation.preflight_calls, 2);
    assert_eq!(observation.commit_calls, 1);
    assert_eq!(observation.material_commits, 1);
    assert_eq!(observation.irreversible_commits, 0);
    assert_eq!(provider.acquire_calls(), 1);
    assert_eq!(provider.prepare_calls(), 1);
    assert_eq!(provider.verify_calls(), 3);
    assert_eq!(provider.release_calls(), 1);

    let trace = provider.trace();
    let material_publish = trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::MaterialPublished)
        .expect("material publication is observed");
    let manifest_publish = trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::ManifestPublished)
        .expect("manifest publication is observed");
    let manifest_reopen = trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::ManifestReopened)
        .expect("manifest reopen is observed");
    let receipt = trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::ReceiptReturned)
        .expect("receipt return is observed");
    let release = trace
        .iter()
        .rposition(|value| *value == PublicationBoundaryV1::GuardReleased)
        .expect("guard release is observed");
    assert!(material_publish < manifest_publish);
    assert!(manifest_publish < manifest_reopen);
    assert!(manifest_reopen < receipt);
    assert!(receipt < release);
    assert_eq!(
        trace
            .iter()
            .filter(|value| **value == PublicationBoundaryV1::ReceiptRevalidated)
            .count(),
        3
    );

    let revalidations = trace
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            (*value == PublicationBoundaryV1::ReceiptRevalidated).then_some(index)
        })
        .collect::<Vec<_>>();
    let commit = trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::CommitEntered)
        .expect("commit entry is observed while publication custody is live");
    assert!(revalidations[1] < commit);
    assert!(commit < revalidations[2]);
    assert!(revalidations[2] < release);

    let uncertain_provider = ManifestLastProviderV1::exact();
    let uncertain = run_case_with_store_script_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &uncertain_provider,
        ExactCommitScriptV1::Uncertain,
        ExactReadbackScriptV1::ThisAttempt,
    );
    assert!(matches!(
        uncertain.outcome,
        PreparationOutcomeV1::Prepared(_)
    ));
    assert_eq!(uncertain.commit_calls, 1);
    assert_eq!(uncertain_provider.verify_calls(), 3);
    assert_eq!(uncertain_provider.release_calls(), 1);
    let uncertain_trace = uncertain_provider.trace();
    let uncertain_commit = uncertain_trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::CommitEntered)
        .expect("uncertain commit entry is observed");
    let readback_entered = uncertain_trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::ReadbackEntered)
        .expect("exact readback entry is observed");
    let readback_returned = uncertain_trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::ReadbackReturned)
        .expect("exact readback completion is observed");
    let uncertain_release = uncertain_trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::GuardReleased)
        .expect("uncertain-path publication custody is released");
    assert!(uncertain_commit < readback_entered);
    assert!(readback_entered < readback_returned);
    assert!(readback_returned < uncertain_release);

    let ambiguous_provider = ManifestLastProviderV1::exact();
    let ambiguous_outcome = run_case_with_store_script_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &ambiguous_provider,
        ExactCommitScriptV1::Uncertain,
        ExactReadbackScriptV1::Unavailable,
    );
    assert!(matches!(
        ambiguous_outcome.outcome,
        PreparationOutcomeV1::Ambiguous(AmbiguousPreparationV1::ReadbackUnavailable)
    ));
    assert_eq!(ambiguous_provider.verify_calls(), 2);
    assert_eq!(ambiguous_provider.release_calls(), 1);
    let ambiguous_trace = ambiguous_provider.trace();
    let ambiguous_readback_returned = ambiguous_trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::ReadbackReturned)
        .expect("ambiguous readback completion is observed");
    let ambiguous_release = ambiguous_trace
        .iter()
        .position(|value| *value == PublicationBoundaryV1::GuardReleased)
        .expect("ambiguous-path publication custody is released before public return");
    assert!(ambiguous_readback_returned < ambiguous_release);
}

#[test]
fn no_interrupted_publication_boundary_can_return_a_receipt_or_commit() {
    for boundary in MANIFEST_LAST_BOUNDARIES {
        let provider = ManifestLastProviderV1::with_faults(
            SyntheticRecoveryGuardFaultV1::Exact,
            SyntheticRecoveryPreparationFaultV1::Exact,
            Vec::new(),
            Some(boundary),
            Vec::new(),
        );
        let observation = run_case_v1(
            synthetic_eligible_plan_v1(),
            SyntheticContextFaultV1::None,
            &provider,
        );
        assert_failed_v1(
            &observation.outcome,
            PreparationFailureV1::RecoveryProviderFailed,
        );
        assert_eq!(observation.commit_calls, 0, "boundary {boundary:?}");
        assert_eq!(observation.material_commits, 0, "boundary {boundary:?}");
        assert!(
            provider.trace().contains(&boundary),
            "boundary {boundary:?}"
        );
        assert!(
            !provider
                .trace()
                .contains(&PublicationBoundaryV1::ReceiptReturned),
            "boundary {boundary:?} fabricated a receipt"
        );
        assert_eq!(provider.release_calls(), 1, "boundary {boundary:?}");
    }
}

#[test]
fn every_receipt_binding_is_exact_and_capacity_is_neither_reduced_nor_widened() {
    for (fault, expected) in [
        (
            ReceiptFaultV1::ProviderGeneration,
            PreparationDenialV1::RecoveryBindingConflict,
        ),
        (
            ReceiptFaultV1::TargetReference,
            PreparationDenialV1::RecoveryBindingConflict,
        ),
        (
            ReceiptFaultV1::PreconditionIdentity,
            PreparationDenialV1::RecoveryBindingConflict,
        ),
        (
            ReceiptFaultV1::BootBinding,
            PreparationDenialV1::RecoveryBindingConflict,
        ),
        (
            ReceiptFaultV1::MaterialDigest,
            PreparationDenialV1::RecoveryUnverified,
        ),
        (
            ReceiptFaultV1::MaterialLengthMinusOne,
            PreparationDenialV1::RecoveryUnverified,
        ),
        (
            ReceiptFaultV1::MaterialLengthPlusOne,
            PreparationDenialV1::RecoveryUnverified,
        ),
        (
            ReceiptFaultV1::ReservedCapacityMinusOne,
            PreparationDenialV1::RecoveryUnverified,
        ),
        (
            ReceiptFaultV1::ReservedCapacityPlusOne,
            PreparationDenialV1::RecoveryUnverified,
        ),
    ] {
        let provider = ManifestLastProviderV1::with_faults(
            SyntheticRecoveryGuardFaultV1::Exact,
            SyntheticRecoveryPreparationFaultV1::Exact,
            vec![SyntheticRecoveryVerificationFaultV1::Exact; 3],
            None,
            vec![fault],
        );
        let observation = run_case_v1(
            synthetic_eligible_plan_v1(),
            SyntheticContextFaultV1::None,
            &provider,
        );
        assert_denied_v1(&observation.outcome, expected);
        assert_eq!(observation.commit_calls, 0, "fault {fault:?}");
        assert_eq!(provider.release_calls(), 1, "fault {fault:?}");
    }
}

#[test]
fn authenticated_l2_irreversibility_records_no_material_and_never_calls_provider() {
    let provider = ManifestLastProviderV1::exact();
    let observation = run_case_v1(
        synthetic_irreversible_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &provider,
    );
    assert!(matches!(
        observation.outcome,
        PreparationOutcomeV1::Prepared(_)
    ));
    assert_eq!(observation.material_commits, 0);
    assert_eq!(observation.irreversible_commits, 1);
    assert_eq!(provider.acquire_calls(), 0);
    assert_eq!(provider.prepare_calls(), 0);
    assert_eq!(provider.verify_calls(), 0);
    assert_eq!(provider.release_calls(), 0);
    assert!(provider.trace().is_empty());
}

#[test]
fn invalid_irreversibility_combinations_are_closed() {
    for (risk, class) in [
        (RiskLevelV1::L1, RecoveryClassV1::Irreversible),
        (RiskLevelV1::L2, RecoveryClassV1::Compensation),
    ] {
        assert!(matches!(
            helix_plan_preparation::IrreversibilityEvidenceV1::try_new(
                risk,
                class,
                AtomicityV1::AtomicReplace,
            ),
            Err(helix_plan_preparation::RecoveryContractBuildErrorV1::InvalidIrreversibility)
        ));
    }
}

#[test]
fn recovery_first_failure_order_is_profile_availability_binding_verification_ambiguity() {
    let profile_before_availability = ManifestLastProviderV1::with_faults(
        SyntheticRecoveryGuardFaultV1::Unavailable,
        SyntheticRecoveryPreparationFaultV1::Exact,
        Vec::new(),
        None,
        Vec::new(),
    );
    let observation = run_case_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::RecoveryProfile,
        &profile_before_availability,
    );
    assert_denied_v1(
        &observation.outcome,
        PreparationDenialV1::RecoveryProfileUnapproved,
    );
    assert_eq!(profile_before_availability.acquire_calls(), 0);

    let availability_before_binding = ManifestLastProviderV1::with_faults(
        SyntheticRecoveryGuardFaultV1::Unavailable,
        SyntheticRecoveryPreparationFaultV1::Exact,
        Vec::new(),
        None,
        vec![ReceiptFaultV1::TargetReference],
    );
    let observation = run_case_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &availability_before_binding,
    );
    assert_failed_v1(
        &observation.outcome,
        PreparationFailureV1::RecoveryProviderFailed,
    );
    assert_eq!(availability_before_binding.prepare_calls(), 0);

    let binding_before_verification = ManifestLastProviderV1::with_faults(
        SyntheticRecoveryGuardFaultV1::Exact,
        SyntheticRecoveryPreparationFaultV1::Exact,
        vec![SyntheticRecoveryVerificationFaultV1::Missing; 3],
        None,
        vec![
            ReceiptFaultV1::TargetReference,
            ReceiptFaultV1::MaterialLengthMinusOne,
        ],
    );
    let observation = run_case_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &binding_before_verification,
    );
    assert_denied_v1(
        &observation.outcome,
        PreparationDenialV1::RecoveryBindingConflict,
    );
    assert_eq!(binding_before_verification.verify_calls(), 0);

    let verification_before_ambiguity = ManifestLastProviderV1::with_faults(
        SyntheticRecoveryGuardFaultV1::Exact,
        SyntheticRecoveryPreparationFaultV1::Exact,
        vec![SyntheticRecoveryVerificationFaultV1::Unavailable; 3],
        None,
        vec![ReceiptFaultV1::MaterialLengthMinusOne],
    );
    let observation = run_case_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &verification_before_ambiguity,
    );
    assert_denied_v1(
        &observation.outcome,
        PreparationDenialV1::RecoveryUnverified,
    );
    assert_eq!(verification_before_ambiguity.verify_calls(), 0);

    let ambiguity = ManifestLastProviderV1::with_faults(
        SyntheticRecoveryGuardFaultV1::Exact,
        SyntheticRecoveryPreparationFaultV1::Ambiguous,
        Vec::new(),
        None,
        Vec::new(),
    );
    let observation = run_case_v1(
        synthetic_eligible_plan_v1(),
        SyntheticContextFaultV1::None,
        &ambiguity,
    );
    assert!(matches!(
        observation.outcome,
        PreparationOutcomeV1::Ambiguous(AmbiguousPreparationV1::RecoveryPublicationUnclassified)
    ));
}

#[test]
fn synthetic_provider_never_claims_production_recovery_evidence() {
    let provider = ManifestLastProviderV1::exact();
    assert_eq!(
        provider.inner.evidence_class_id(),
        SYNTHETIC_RECOVERY_EVIDENCE_CLASS_ID
    );
    assert!(!provider.inner.claims_production_evidence());
    assert_eq!(SYNTHETIC_RECOVERY_PROFILE_ID, provider_profile_id_v1());
    assert_eq!(SYNTHETIC_RECOVERY_PROVIDER_ID, provider_id_v1());
    assert_eq!(SYNTHETIC_AT_REST_PROFILE_ID, at_rest_profile_id_v1());
}

const fn provider_profile_id_v1() -> &'static str {
    SYNTHETIC_RECOVERY_PROFILE_ID
}

const fn provider_id_v1() -> &'static str {
    SYNTHETIC_RECOVERY_PROVIDER_ID
}

const fn at_rest_profile_id_v1() -> &'static str {
    SYNTHETIC_AT_REST_PROFILE_ID
}
