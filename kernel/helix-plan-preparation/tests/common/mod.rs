//! Portable, public-synthetic harness root for durable-preparation tests.
//!
//! Every positive value in this module is test-only and is obtained through the same
//! public contracts as production wiring. Native paths, SQLite, process control,
//! credentials and claims of production recovery evidence belong downstream.

#![allow(dead_code)]

#[path = "../../../helix-plan-eligibility/tests/common/mod.rs"]
pub(crate) mod feature002;

use helix_contracts::{
    AtomicityV1, AuthenticPlanEnvelopeV1, Identifier, RecoveryClassV1, Sha256Digest,
};
use helix_plan_eligibility::{EligiblePlanV1, SupervisorAdmissionStateV1};
use helix_plan_preparation::{
    AuthorityGuardAcquisitionOrderErrorV1, AuthorityGuardAcquisitionV1, AuthorityGuardKindV1,
    AuthorityGuardSetV1, AuthorityGuardV1, AuthorityGuardValidationV1, FinalCommitGateV1,
    FinalCommitInFlightV1, FinalCommitPermitOutcomeV1, FinalCommitPermitRequestV1,
    FinalCommitPermitV1, FinalCommitReadbackResolutionV1, FinalCommitResolutionV1,
    FinalCommitStoreClassificationV1, FinalCommitTerminalResolutionV1, PreparationAttemptIdV1,
    PreparationAuthoritySourceV1, PreparationCapturePhaseV1, PreparationClockReadErrorV1,
    PreparationContextV1, PreparationMonotonicClockV1, PreparationRequestedBudgetInputV1,
    PreparationRequestedBudgetV1, PreparationUtcClockV1, ReadyPreparationContextInputV1,
    ReadyPreparationContextV1, RecoveryBindingV1, RecoveryEvidenceClassV1, RecoveryGuardOutcomeV1,
    RecoveryMaterialReceiptInputV1, RecoveryMaterialReceiptV1, RecoveryMaterialStateV1,
    RecoveryPreparationInputV1, RecoveryPreparationOutcomeV1, RecoveryProviderContextInputV1,
    RecoveryProviderContextV1, RecoveryProviderV1, RecoveryPublicationGuardV1,
    RecoveryVerificationV1, PREPARATION_CONTEXT_VERSION_V1, RECOVERY_PROVIDER_CONTEXT_VERSION_V1,
    RECOVERY_PROVIDER_CONTRACT_VERSION_V1, RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) const SYNTHETIC_RECOVERY_PROFILE_ID: &str = "recovery-profile:synthetic-conformance-v1";
pub(crate) const SYNTHETIC_RECOVERY_PROVIDER_ID: &str =
    "recovery-provider:synthetic-conformance-v1";
pub(crate) const SYNTHETIC_RECOVERY_EVIDENCE_CLASS_ID: &str = "synthetic-conformance";
pub(crate) const SYNTHETIC_AT_REST_PROFILE_ID: &str = "at-rest:synthetic-conformance-v1";
pub(crate) const SYNTHETIC_RECOVERY_PROVIDER_GENERATION: u64 = 1;
pub(crate) const SYNTHETIC_BUDGET_SCOPE_GENERATION: u64 = 1;

pub(crate) fn synthetic_authentic_plan_v1() -> AuthenticPlanEnvelopeV1 {
    feature002::authentic_plan()
}

/// Creates eligibility only through the injected claimant contract.
pub(crate) fn synthetic_eligible_plan_v1() -> EligiblePlanV1 {
    feature002::coherent_fixture()
        .evaluate(&feature002::ClaimantProbe::default())
        .expect("public-synthetic eligibility fixture is coherent")
}

#[derive(Clone)]
pub(crate) struct DeterministicPreparationClockV1 {
    inner: Arc<DeterministicPreparationClockInnerV1>,
}

struct DeterministicPreparationClockInnerV1 {
    utc_ms: AtomicU64,
    monotonic_ms: AtomicU64,
    unavailable: AtomicBool,
}

impl DeterministicPreparationClockV1 {
    pub(crate) fn new(utc_ms: u64, monotonic_ms: u64) -> Self {
        Self {
            inner: Arc::new(DeterministicPreparationClockInnerV1 {
                utc_ms: AtomicU64::new(utc_ms),
                monotonic_ms: AtomicU64::new(monotonic_ms),
                unavailable: AtomicBool::new(false),
            }),
        }
    }

    pub(crate) fn coherent() -> Self {
        Self::new(feature002::NOW_UTC_MS, feature002::NOW_MONOTONIC_MS)
    }

    pub(crate) fn set_utc_ms(&self, value: u64) {
        self.inner.utc_ms.store(value, Ordering::SeqCst);
    }

    pub(crate) fn set_monotonic_ms(&self, value: u64) {
        self.inner.monotonic_ms.store(value, Ordering::SeqCst);
    }

    pub(crate) fn set_unavailable(&self, value: bool) {
        self.inner.unavailable.store(value, Ordering::SeqCst);
    }
}

impl fmt::Debug for DeterministicPreparationClockV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicPreparationClockV1")
            .finish_non_exhaustive()
    }
}

impl PreparationUtcClockV1 for DeterministicPreparationClockV1 {
    fn now_utc_ms(&self) -> Result<u64, PreparationClockReadErrorV1> {
        if self.inner.unavailable.load(Ordering::SeqCst) {
            return Err(PreparationClockReadErrorV1::Unavailable);
        }
        Ok(self.inner.utc_ms.load(Ordering::SeqCst))
    }
}

impl PreparationMonotonicClockV1 for DeterministicPreparationClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, PreparationClockReadErrorV1> {
        if self.inner.unavailable.load(Ordering::SeqCst) {
            return Err(PreparationClockReadErrorV1::Unavailable);
        }
        Ok(self.inner.monotonic_ms.load(Ordering::SeqCst))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticGuardStateV1 {
    Valid,
    Revoked,
    Unavailable,
    Mismatch,
}

/// Deterministic context mutations injected at either capture boundary.
///
/// A capture script can combine two ready-context mutations so the production
/// comparator, rather than the harness, selects the normative first failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticContextFaultV1 {
    None,
    Unavailable,
    Incomplete,
    Unsupported,
    Torn,
    CaptureGeneration,
    ClockGeneration,
    UtcExpired,
    DeadlineGeneration,
    MonotonicDeadlineReached,
    Boot,
    SupervisorDenied,
    SupervisorGeneration,
    Trust,
    Workload,
    Lease,
    Authorization,
    Policy,
    Catalogue,
    Capability,
    ReplayBinding,
    BudgetBinding,
    RecoveryProfile,
    RecoveryBinding,
}

#[derive(Clone)]
pub(crate) struct SyntheticAuthorityGuardControlV1 {
    states: Arc<Mutex<[SyntheticGuardStateV1; AuthorityGuardKindV1::COUNT]>>,
    acquisition_order: Arc<Mutex<Vec<usize>>>,
    release_order: Arc<Mutex<Vec<usize>>>,
    acquired_boundary_count: Arc<AtomicUsize>,
}

impl SyntheticAuthorityGuardControlV1 {
    pub(crate) fn new_test_only() -> Self {
        Self {
            states: Arc::new(Mutex::new(
                [SyntheticGuardStateV1::Valid; AuthorityGuardKindV1::COUNT],
            )),
            acquisition_order: Arc::new(Mutex::new(Vec::new())),
            release_order: Arc::new(Mutex::new(Vec::new())),
            acquired_boundary_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn set_state_test_only(
        &self,
        kind: AuthorityGuardKindV1,
        state: SyntheticGuardStateV1,
    ) {
        self.states
            .lock()
            .expect("synthetic guard-state mutex is not poisoned")[guard_kind_ordinal_v1(&kind)] =
            state;
    }

    pub(crate) fn release_order_test_only(&self) -> Vec<AuthorityGuardKindV1> {
        self.release_order
            .lock()
            .expect("synthetic guard-release mutex is not poisoned")
            .iter()
            .copied()
            .map(guard_kind_from_ordinal_v1)
            .collect()
    }

    pub(crate) fn acquisition_order_test_only(&self) -> Vec<AuthorityGuardKindV1> {
        self.acquisition_order
            .lock()
            .expect("synthetic guard-acquisition mutex is not poisoned")
            .iter()
            .copied()
            .map(guard_kind_from_ordinal_v1)
            .collect()
    }

    pub(crate) fn acquired_boundary_count_test_only(&self) -> usize {
        self.acquired_boundary_count.load(Ordering::SeqCst)
    }

    pub(crate) fn acquire_and_release_test_only(&self) -> Result<(), SyntheticGuardStateV1> {
        let guards = acquire_synthetic_guards_v1(self)?;
        release_synthetic_guards_reverse_v1(guards);
        Ok(())
    }
}

impl Default for SyntheticAuthorityGuardControlV1 {
    fn default() -> Self {
        Self::new_test_only()
    }
}

impl fmt::Debug for SyntheticAuthorityGuardControlV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticAuthorityGuardControlV1")
            .finish_non_exhaustive()
    }
}

struct SyntheticAuthorityGuardV1 {
    ordinal: usize,
    control: SyntheticAuthorityGuardControlV1,
}

impl SyntheticAuthorityGuardV1 {
    fn acquired(ordinal: usize, control: SyntheticAuthorityGuardControlV1) -> Self {
        control
            .acquisition_order
            .lock()
            .expect("synthetic guard-acquisition mutex is not poisoned")
            .push(ordinal);
        control
            .acquired_boundary_count
            .fetch_add(1, Ordering::SeqCst);
        Self { ordinal, control }
    }

    fn release(self) {
        self.control
            .release_order
            .lock()
            .expect("synthetic guard-release mutex is not poisoned")
            .push(self.ordinal);
    }
}

fn acquire_synthetic_guards_v1(
    control: &SyntheticAuthorityGuardControlV1,
) -> Result<Vec<SyntheticAuthorityGuardV1>, SyntheticGuardStateV1> {
    let mut unobserved = |_| Ok(());
    match acquire_synthetic_guards_observed_v1(control, 0, &mut unobserved) {
        Ok(guards) => Ok(guards),
        Err(SyntheticGuardAcquisitionErrorV1::State(state)) => Err(state),
        Err(SyntheticGuardAcquisitionErrorV1::Order) => {
            unreachable!("the no-op acquisition observer accepts every guard")
        }
    }
}

enum SyntheticGuardAcquisitionErrorV1 {
    State(SyntheticGuardStateV1),
    Order,
}

fn acquire_synthetic_guards_observed_v1(
    control: &SyntheticAuthorityGuardControlV1,
    start_ordinal: usize,
    after_acquisition: &mut dyn FnMut(
        AuthorityGuardKindV1,
    ) -> Result<(), AuthorityGuardAcquisitionOrderErrorV1>,
) -> Result<Vec<SyntheticAuthorityGuardV1>, SyntheticGuardAcquisitionErrorV1> {
    let mut guards = Vec::with_capacity(AuthorityGuardKindV1::COUNT - start_ordinal);
    for (ordinal, kind) in AuthorityGuardKindV1::acquisition_order()
        .into_iter()
        .enumerate()
        .skip(start_ordinal)
    {
        let state = control
            .states
            .lock()
            .expect("synthetic guard-state mutex is not poisoned")[ordinal];
        if state != SyntheticGuardStateV1::Valid {
            release_synthetic_guards_reverse_v1(guards);
            return Err(SyntheticGuardAcquisitionErrorV1::State(state));
        }
        guards.push(SyntheticAuthorityGuardV1::acquired(
            ordinal,
            control.clone(),
        ));
        if after_acquisition(kind).is_err() {
            release_synthetic_guards_reverse_v1(guards);
            return Err(SyntheticGuardAcquisitionErrorV1::Order);
        }
    }
    Ok(guards)
}

fn release_synthetic_guards_reverse_v1(mut guards: Vec<SyntheticAuthorityGuardV1>) {
    while let Some(guard) = guards.pop() {
        guard.release();
    }
}

impl fmt::Debug for SyntheticAuthorityGuardV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticAuthorityGuardV1")
            .finish_non_exhaustive()
    }
}

impl AuthorityGuardV1 for SyntheticAuthorityGuardV1 {
    fn kind(&self) -> AuthorityGuardKindV1 {
        guard_kind_from_ordinal_v1(self.ordinal)
    }

    fn validate(
        &mut self,
        now_monotonic_ms: u64,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardValidationV1 {
        if now_monotonic_ms >= deadline_monotonic_ms {
            return AuthorityGuardValidationV1::DeadlineReached;
        }
        match self
            .control
            .states
            .lock()
            .expect("synthetic guard-state mutex is not poisoned")[self.ordinal]
        {
            SyntheticGuardStateV1::Valid => AuthorityGuardValidationV1::Valid,
            SyntheticGuardStateV1::Revoked => AuthorityGuardValidationV1::Revoked,
            SyntheticGuardStateV1::Unavailable => AuthorityGuardValidationV1::Unavailable,
            SyntheticGuardStateV1::Mismatch => AuthorityGuardValidationV1::Mismatch,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticPermitStateV1 {
    Open,
    Permitted,
    CommitInFlight,
    ResolvedCommitted,
    ResolvedAborted,
    ResolvedAmbiguous,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticControlActionV1 {
    Pause,
    Halt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticPermitBoundaryV1 {
    EnterPermitReturned,
    MovedToCommitInFlight,
    ResolvedCommitted,
    ResolvedAborted,
    ResolvedAmbiguous,
}

struct SyntheticSupervisorPermitInnerV1 {
    state: SyntheticPermitStateV1,
    supervisor_generation: u64,
    permit_deadline_monotonic_ms: Option<u64>,
    owner_token: u64,
    paused: bool,
    pending_control: Option<SyntheticControlActionV1>,
    active_control: Option<SyntheticControlActionV1>,
    boundary_events: Vec<SyntheticPermitBoundaryV1>,
}

#[derive(Clone)]
pub(crate) struct SyntheticSupervisorPermitControlV1 {
    inner: Arc<Mutex<SyntheticSupervisorPermitInnerV1>>,
}

impl SyntheticSupervisorPermitControlV1 {
    pub(crate) fn new_test_only(supervisor_generation: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SyntheticSupervisorPermitInnerV1 {
                state: SyntheticPermitStateV1::Open,
                supervisor_generation,
                permit_deadline_monotonic_ms: None,
                owner_token: 0,
                paused: false,
                pending_control: None,
                active_control: None,
                boundary_events: Vec::new(),
            })),
        }
    }

    pub(crate) fn deadman_test_only(&self) -> SyntheticPermitDeadmanV1 {
        SyntheticPermitDeadmanV1 {
            inner: Arc::clone(&self.inner),
        }
    }

    pub(crate) fn pause_test_only(&self) {
        self.request_control_test_only(SyntheticControlActionV1::Pause);
    }

    pub(crate) fn halt_test_only(&self) {
        self.request_control_test_only(SyntheticControlActionV1::Halt);
    }

    pub(crate) fn revoke_test_only(&self) {
        self.pause_test_only();
    }

    fn request_control_test_only(&self, action: SyntheticControlActionV1) {
        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        inner.paused = true;
        match inner.state {
            SyntheticPermitStateV1::Permitted | SyntheticPermitStateV1::CommitInFlight => {
                inner.pending_control = Some(action);
            }
            SyntheticPermitStateV1::Open => {
                inner.state = SyntheticPermitStateV1::Revoked;
                inner.active_control = Some(action);
            }
            SyntheticPermitStateV1::ResolvedCommitted
            | SyntheticPermitStateV1::ResolvedAborted
            | SyntheticPermitStateV1::ResolvedAmbiguous
            | SyntheticPermitStateV1::Revoked => {
                inner.active_control = Some(action);
            }
        }
    }

    pub(crate) fn state_test_only(&self) -> SyntheticPermitStateV1 {
        self.inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned")
            .state
    }

    pub(crate) fn boundary_events_test_only(&self) -> Vec<SyntheticPermitBoundaryV1> {
        self.inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned")
            .boundary_events
            .clone()
    }

    pub(crate) fn issue_permit_test_only(
        &self,
        clock: DeterministicPreparationClockV1,
        permit_deadline_monotonic_ms: u64,
    ) -> SyntheticFinalCommitPermitV1 {
        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        inner.owner_token = inner.owner_token.wrapping_add(1);
        let owner_token = inner.owner_token;
        inner.permit_deadline_monotonic_ms = Some(permit_deadline_monotonic_ms);
        inner.state = SyntheticPermitStateV1::Permitted;
        inner.paused = false;
        inner.pending_control = None;
        inner.active_control = None;
        inner
            .boundary_events
            .push(SyntheticPermitBoundaryV1::EnterPermitReturned);
        SyntheticFinalCommitPermitV1 {
            inner: Arc::clone(&self.inner),
            clock,
            owner_token,
            permit_deadline_monotonic_ms,
        }
    }

    fn supervisor_generation(&self) -> u64 {
        self.inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned")
            .supervisor_generation
    }

    fn admission_state(&self) -> SupervisorAdmissionStateV1 {
        let inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        if inner.paused {
            SupervisorAdmissionStateV1::Paused
        } else {
            SupervisorAdmissionStateV1::Open
        }
    }

    fn enter_permit(
        &self,
        clock: DeterministicPreparationClockV1,
        request: &FinalCommitPermitRequestV1<'_>,
        now_monotonic_ms: u64,
    ) -> FinalCommitPermitOutcomeV1<SyntheticFinalCommitPermitV1> {
        if !request.is_live_at(now_monotonic_ms) {
            return FinalCommitPermitOutcomeV1::DeadlineReached;
        }

        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        if inner.paused || inner.state == SyntheticPermitStateV1::Revoked {
            return FinalCommitPermitOutcomeV1::Revoked;
        }
        if request.expected_supervisor_generation() != inner.supervisor_generation {
            inner.state = SyntheticPermitStateV1::Revoked;
            inner.paused = true;
            return FinalCommitPermitOutcomeV1::Revoked;
        }
        if inner.state != SyntheticPermitStateV1::Open {
            return FinalCommitPermitOutcomeV1::Unavailable;
        }

        inner.owner_token = inner.owner_token.wrapping_add(1);
        let owner_token = inner.owner_token;
        let permit_deadline_monotonic_ms = request.permit_deadline_monotonic_ms();
        inner.permit_deadline_monotonic_ms = Some(permit_deadline_monotonic_ms);
        inner.state = SyntheticPermitStateV1::Permitted;
        inner
            .boundary_events
            .push(SyntheticPermitBoundaryV1::EnterPermitReturned);
        FinalCommitPermitOutcomeV1::Permitted(SyntheticFinalCommitPermitV1 {
            inner: Arc::clone(&self.inner),
            clock,
            owner_token,
            permit_deadline_monotonic_ms,
        })
    }
}

impl fmt::Debug for SyntheticSupervisorPermitControlV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticSupervisorPermitControlV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct SyntheticPermitDeadmanV1 {
    inner: Arc<Mutex<SyntheticSupervisorPermitInnerV1>>,
}

impl SyntheticPermitDeadmanV1 {
    pub(crate) fn new_test_only() -> Self {
        SyntheticSupervisorPermitControlV1::new_test_only(feature002::SUPERVISOR_GENERATION)
            .deadman_test_only()
    }

    pub(crate) fn arm_test_only(&self, permit_deadline_monotonic_ms: u64) {
        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        inner.owner_token = inner.owner_token.wrapping_add(1);
        inner.permit_deadline_monotonic_ms = Some(permit_deadline_monotonic_ms);
        inner.state = SyntheticPermitStateV1::Permitted;
        inner.paused = false;
        inner.pending_control = None;
        inner.active_control = None;
        inner
            .boundary_events
            .push(SyntheticPermitBoundaryV1::EnterPermitReturned);
    }

    pub(crate) fn expire_if_due_test_only(&self, now_monotonic_ms: u64) -> bool {
        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        let active = matches!(
            inner.state,
            SyntheticPermitStateV1::Permitted | SyntheticPermitStateV1::CommitInFlight
        );
        let due = inner
            .permit_deadline_monotonic_ms
            .is_some_and(|deadline| now_monotonic_ms >= deadline);
        if !active || !due {
            return false;
        }
        resolve_ambiguous_v1(&mut inner);
        true
    }

    pub(crate) fn owner_lost_test_only(&self) -> bool {
        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        if !matches!(
            inner.state,
            SyntheticPermitStateV1::Permitted | SyntheticPermitStateV1::CommitInFlight
        ) {
            return false;
        }
        resolve_ambiguous_v1(&mut inner);
        true
    }

    pub(crate) fn is_paused_test_only(&self) -> bool {
        self.inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned")
            .paused
    }

    pub(crate) fn state_test_only(&self) -> SyntheticPermitStateV1 {
        self.inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned")
            .state
    }

    pub(crate) fn boundary_events_test_only(&self) -> Vec<SyntheticPermitBoundaryV1> {
        self.inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned")
            .boundary_events
            .clone()
    }
}

impl fmt::Debug for SyntheticPermitDeadmanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticPermitDeadmanV1")
            .finish_non_exhaustive()
    }
}

pub(crate) struct SyntheticFinalCommitPermitV1 {
    inner: Arc<Mutex<SyntheticSupervisorPermitInnerV1>>,
    clock: DeterministicPreparationClockV1,
    owner_token: u64,
    permit_deadline_monotonic_ms: u64,
}

impl fmt::Debug for SyntheticFinalCommitPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticFinalCommitPermitV1")
            .finish_non_exhaustive()
    }
}

impl FinalCommitPermitV1 for SyntheticFinalCommitPermitV1 {
    type InFlight = SyntheticFinalCommitInFlightV1;

    fn permit_deadline_monotonic_ms(&self) -> u64 {
        self.permit_deadline_monotonic_ms
    }

    fn commit_once<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
    where
        C: FnOnce() -> FinalCommitStoreClassificationV1,
    {
        let now = match PreparationMonotonicClockV1::now_monotonic_ms(&self.clock) {
            Ok(now) => now,
            Err(_) => {
                resolve_shared_ambiguous_v1(&self.inner);
                return FinalCommitResolutionV1::Ambiguous;
            }
        };
        {
            let mut inner = self
                .inner
                .lock()
                .expect("synthetic supervisor mutex is not poisoned");
            if inner.owner_token != self.owner_token
                || inner.state != SyntheticPermitStateV1::Permitted
                || now >= self.permit_deadline_monotonic_ms
            {
                resolve_ambiguous_v1(&mut inner);
                return FinalCommitResolutionV1::Ambiguous;
            }
            inner.state = SyntheticPermitStateV1::CommitInFlight;
            inner
                .boundary_events
                .push(SyntheticPermitBoundaryV1::MovedToCommitInFlight);
        }

        let classification = commit();
        let now_after = PreparationMonotonicClockV1::now_monotonic_ms(&self.clock);
        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        if inner.owner_token != self.owner_token
            || inner.state != SyntheticPermitStateV1::CommitInFlight
            || now_after
                .ok()
                .is_none_or(|now| now >= self.permit_deadline_monotonic_ms)
        {
            resolve_ambiguous_v1(&mut inner);
            return FinalCommitResolutionV1::Ambiguous;
        }

        match classification {
            FinalCommitStoreClassificationV1::Committed => {
                resolve_terminal_v1(
                    &mut inner,
                    SyntheticPermitStateV1::ResolvedCommitted,
                    SyntheticPermitBoundaryV1::ResolvedCommitted,
                );
                FinalCommitResolutionV1::Committed
            }
            FinalCommitStoreClassificationV1::ConfirmedRollback => {
                resolve_terminal_v1(
                    &mut inner,
                    SyntheticPermitStateV1::ResolvedAborted,
                    SyntheticPermitBoundaryV1::ResolvedAborted,
                );
                FinalCommitResolutionV1::Aborted
            }
            FinalCommitStoreClassificationV1::Uncertain => {
                drop(inner);
                FinalCommitResolutionV1::Uncertain(SyntheticFinalCommitInFlightV1 {
                    inner: Arc::clone(&self.inner),
                    clock: self.clock,
                    owner_token: self.owner_token,
                    permit_deadline_monotonic_ms: self.permit_deadline_monotonic_ms,
                })
            }
            FinalCommitStoreClassificationV1::Unclassified => {
                resolve_ambiguous_v1(&mut inner);
                FinalCommitResolutionV1::Ambiguous
            }
        }
    }
}

pub(crate) struct SyntheticFinalCommitInFlightV1 {
    inner: Arc<Mutex<SyntheticSupervisorPermitInnerV1>>,
    clock: DeterministicPreparationClockV1,
    owner_token: u64,
    permit_deadline_monotonic_ms: u64,
}

impl fmt::Debug for SyntheticFinalCommitInFlightV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticFinalCommitInFlightV1")
            .finish_non_exhaustive()
    }
}

impl FinalCommitInFlightV1 for SyntheticFinalCommitInFlightV1 {
    fn permit_deadline_monotonic_ms(&self) -> u64 {
        self.permit_deadline_monotonic_ms
    }

    fn resolve_readback(
        self,
        resolution: FinalCommitReadbackResolutionV1,
    ) -> FinalCommitTerminalResolutionV1 {
        let now = PreparationMonotonicClockV1::now_monotonic_ms(&self.clock);
        let mut inner = self
            .inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned");
        if inner.owner_token != self.owner_token
            || inner.state != SyntheticPermitStateV1::CommitInFlight
            || now
                .ok()
                .is_none_or(|value| value >= self.permit_deadline_monotonic_ms)
        {
            resolve_ambiguous_v1(&mut inner);
            return FinalCommitTerminalResolutionV1::Ambiguous;
        }

        match resolution {
            FinalCommitReadbackResolutionV1::ThisAttemptCommitted => {
                resolve_terminal_v1(
                    &mut inner,
                    SyntheticPermitStateV1::ResolvedCommitted,
                    SyntheticPermitBoundaryV1::ResolvedCommitted,
                );
                FinalCommitTerminalResolutionV1::Committed
            }
            FinalCommitReadbackResolutionV1::PriorExactAttempt
            | FinalCommitReadbackResolutionV1::Conflict
            | FinalCommitReadbackResolutionV1::DefinitelyAbsent => {
                resolve_terminal_v1(
                    &mut inner,
                    SyntheticPermitStateV1::ResolvedAborted,
                    SyntheticPermitBoundaryV1::ResolvedAborted,
                );
                FinalCommitTerminalResolutionV1::Aborted
            }
            FinalCommitReadbackResolutionV1::Inconclusive
            | FinalCommitReadbackResolutionV1::LateOrRevoked => {
                resolve_ambiguous_v1(&mut inner);
                FinalCommitTerminalResolutionV1::Ambiguous
            }
        }
    }
}

fn resolve_shared_ambiguous_v1(inner: &Arc<Mutex<SyntheticSupervisorPermitInnerV1>>) {
    resolve_ambiguous_v1(
        &mut inner
            .lock()
            .expect("synthetic supervisor mutex is not poisoned"),
    );
}

fn resolve_ambiguous_v1(inner: &mut SyntheticSupervisorPermitInnerV1) {
    if !matches!(
        inner.state,
        SyntheticPermitStateV1::Permitted | SyntheticPermitStateV1::CommitInFlight
    ) {
        return;
    }
    inner.state = SyntheticPermitStateV1::ResolvedAmbiguous;
    inner
        .boundary_events
        .push(SyntheticPermitBoundaryV1::ResolvedAmbiguous);
    inner.paused = true;
    if let Some(action) = inner.pending_control.take() {
        inner.active_control = Some(action);
    } else if inner.active_control.is_none() {
        inner.active_control = Some(SyntheticControlActionV1::Pause);
    }
}

fn resolve_terminal_v1(
    inner: &mut SyntheticSupervisorPermitInnerV1,
    state: SyntheticPermitStateV1,
    boundary: SyntheticPermitBoundaryV1,
) {
    inner.state = state;
    inner.boundary_events.push(boundary);
    if let Some(action) = inner.pending_control.take() {
        inner.active_control = Some(action);
        inner.paused = true;
    }
}

pub(crate) struct SyntheticAuthorityGuardSetV1 {
    guards: Vec<SyntheticAuthorityGuardV1>,
    control: SyntheticAuthorityGuardControlV1,
    clock: DeterministicPreparationClockV1,
    supervisor: SyntheticSupervisorPermitControlV1,
    supervisor_generation: u64,
    final_context_faults: [SyntheticContextFaultV1; 2],
    post_final_capture_guard_fault: Option<(AuthorityGuardKindV1, SyntheticGuardStateV1)>,
    plan_id: Sha256Digest,
    attempt_id: Sha256Digest,
}

impl fmt::Debug for SyntheticAuthorityGuardSetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticAuthorityGuardSetV1")
            .finish_non_exhaustive()
    }
}

impl AuthorityGuardSetV1 for SyntheticAuthorityGuardSetV1 {
    fn capture_final(
        &mut self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> PreparationContextV1 {
        if eligible.authentic().plan_id() != self.plan_id || attempt.digest() != self.attempt_id {
            return PreparationContextV1::Torn;
        }
        let context = capture_context_v1(
            eligible,
            attempt,
            PreparationCapturePhaseV1::Final,
            deadline_monotonic_ms,
            &self.clock,
            &self.supervisor,
            &self.final_context_faults,
        );
        if let Some((kind, state)) = self.post_final_capture_guard_fault {
            self.control.set_state_test_only(kind, state);
        }
        context
    }

    fn validate_all(
        &mut self,
        now_monotonic_ms: u64,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardValidationV1 {
        for guard in &mut self.guards {
            let outcome = guard.validate(now_monotonic_ms, deadline_monotonic_ms);
            if outcome != AuthorityGuardValidationV1::Valid {
                return outcome;
            }
            if guard.kind() == AuthorityGuardKindV1::Supervisor {
                if self.supervisor.supervisor_generation() != self.supervisor_generation {
                    return AuthorityGuardValidationV1::Mismatch;
                }
                if self.supervisor.admission_state() != SupervisorAdmissionStateV1::Open {
                    return AuthorityGuardValidationV1::Revoked;
                }
            }
        }
        AuthorityGuardValidationV1::Valid
    }

    fn release_reverse(mut self) {
        release_synthetic_guards_reverse_v1(std::mem::take(&mut self.guards));
    }
}

impl FinalCommitGateV1 for SyntheticAuthorityGuardSetV1 {
    type Permit = SyntheticFinalCommitPermitV1;

    fn enter_commit_permit(
        &mut self,
        request: &FinalCommitPermitRequestV1<'_>,
    ) -> FinalCommitPermitOutcomeV1<Self::Permit> {
        if request.attempt().digest() != self.attempt_id {
            return FinalCommitPermitOutcomeV1::Revoked;
        }
        let now = match PreparationMonotonicClockV1::now_monotonic_ms(&self.clock) {
            Ok(now) => now,
            Err(_) => return FinalCommitPermitOutcomeV1::Unavailable,
        };
        match self.validate_all(now, request.caller_deadline_monotonic_ms()) {
            AuthorityGuardValidationV1::Valid => {}
            AuthorityGuardValidationV1::DeadlineReached => {
                return FinalCommitPermitOutcomeV1::DeadlineReached;
            }
            AuthorityGuardValidationV1::Revoked | AuthorityGuardValidationV1::Mismatch => {
                return FinalCommitPermitOutcomeV1::Revoked;
            }
            AuthorityGuardValidationV1::Unavailable => {
                return FinalCommitPermitOutcomeV1::Unavailable;
            }
        }
        self.supervisor
            .enter_permit(self.clock.clone(), request, now)
    }
}

#[derive(Clone)]
pub(crate) struct SyntheticPreparationAuthorityV1 {
    clock: DeterministicPreparationClockV1,
    guards: SyntheticAuthorityGuardControlV1,
    supervisor: SyntheticSupervisorPermitControlV1,
    preliminary_context_faults: [SyntheticContextFaultV1; 2],
    final_context_faults: [SyntheticContextFaultV1; 2],
    post_final_capture_guard_fault: Option<(AuthorityGuardKindV1, SyntheticGuardStateV1)>,
}

impl SyntheticPreparationAuthorityV1 {
    pub(crate) fn new_test_only(
        clock: DeterministicPreparationClockV1,
        guards: SyntheticAuthorityGuardControlV1,
        supervisor: SyntheticSupervisorPermitControlV1,
    ) -> Self {
        Self {
            clock,
            guards,
            supervisor,
            preliminary_context_faults: [SyntheticContextFaultV1::None; 2],
            final_context_faults: [SyntheticContextFaultV1::None; 2],
            post_final_capture_guard_fault: None,
        }
    }

    pub(crate) fn with_context_faults_test_only(
        clock: DeterministicPreparationClockV1,
        guards: SyntheticAuthorityGuardControlV1,
        supervisor: SyntheticSupervisorPermitControlV1,
        preliminary_context_fault: SyntheticContextFaultV1,
        final_context_fault: SyntheticContextFaultV1,
    ) -> Self {
        Self::with_context_fault_sets_test_only(
            clock,
            guards,
            supervisor,
            [preliminary_context_fault, SyntheticContextFaultV1::None],
            [final_context_fault, SyntheticContextFaultV1::None],
            None,
        )
    }

    pub(crate) fn with_context_fault_sets_test_only(
        clock: DeterministicPreparationClockV1,
        guards: SyntheticAuthorityGuardControlV1,
        supervisor: SyntheticSupervisorPermitControlV1,
        preliminary_context_faults: [SyntheticContextFaultV1; 2],
        final_context_faults: [SyntheticContextFaultV1; 2],
        post_final_capture_guard_fault: Option<(AuthorityGuardKindV1, SyntheticGuardStateV1)>,
    ) -> Self {
        Self {
            clock,
            guards,
            supervisor,
            preliminary_context_faults,
            final_context_faults,
            post_final_capture_guard_fault,
        }
    }

    pub(crate) fn coherent_test_only() -> Self {
        Self::new_test_only(
            DeterministicPreparationClockV1::coherent(),
            SyntheticAuthorityGuardControlV1::new_test_only(),
            SyntheticSupervisorPermitControlV1::new_test_only(feature002::SUPERVISOR_GENERATION),
        )
    }

    pub(crate) fn clock_test_only(&self) -> DeterministicPreparationClockV1 {
        self.clock.clone()
    }

    pub(crate) fn guard_control_test_only(&self) -> SyntheticAuthorityGuardControlV1 {
        self.guards.clone()
    }

    pub(crate) fn supervisor_control_test_only(&self) -> SyntheticSupervisorPermitControlV1 {
        self.supervisor.clone()
    }

    pub(crate) fn deadman_test_only(&self) -> SyntheticPermitDeadmanV1 {
        self.supervisor.deadman_test_only()
    }

    fn acquire_final_guards_observed_v1(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
        start_ordinal: usize,
        after_acquisition: &mut dyn FnMut(
            AuthorityGuardKindV1,
        )
            -> Result<(), AuthorityGuardAcquisitionOrderErrorV1>,
    ) -> AuthorityGuardAcquisitionV1<SyntheticAuthorityGuardSetV1> {
        let now = match PreparationMonotonicClockV1::now_monotonic_ms(&self.clock) {
            Ok(now) => now,
            Err(_) => return AuthorityGuardAcquisitionV1::Unavailable,
        };
        if now >= deadline_monotonic_ms {
            return AuthorityGuardAcquisitionV1::DeadlineReached;
        }
        if self.supervisor.admission_state() != SupervisorAdmissionStateV1::Open {
            return AuthorityGuardAcquisitionV1::Revoked;
        }

        let guards = match acquire_synthetic_guards_observed_v1(
            &self.guards,
            start_ordinal,
            after_acquisition,
        ) {
            Ok(guards) => guards,
            Err(SyntheticGuardAcquisitionErrorV1::State(
                SyntheticGuardStateV1::Revoked | SyntheticGuardStateV1::Mismatch,
            )) => return AuthorityGuardAcquisitionV1::Revoked,
            Err(SyntheticGuardAcquisitionErrorV1::State(SyntheticGuardStateV1::Unavailable)) => {
                return AuthorityGuardAcquisitionV1::Unavailable
            }
            Err(SyntheticGuardAcquisitionErrorV1::State(SyntheticGuardStateV1::Valid)) => {
                unreachable!("valid guards are acquired")
            }
            Err(SyntheticGuardAcquisitionErrorV1::Order) => {
                return AuthorityGuardAcquisitionV1::Unsupported;
            }
        };
        AuthorityGuardAcquisitionV1::Acquired(SyntheticAuthorityGuardSetV1 {
            guards,
            control: self.guards.clone(),
            clock: self.clock.clone(),
            supervisor: self.supervisor.clone(),
            supervisor_generation: self.supervisor.supervisor_generation(),
            final_context_faults: self.final_context_faults,
            post_final_capture_guard_fault: self.post_final_capture_guard_fault,
            plan_id: eligible.authentic().plan_id(),
            attempt_id: attempt.digest(),
        })
    }
}

impl fmt::Debug for SyntheticPreparationAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticPreparationAuthorityV1")
            .finish_non_exhaustive()
    }
}

impl PreparationAuthoritySourceV1 for SyntheticPreparationAuthorityV1 {
    type GuardSet = SyntheticAuthorityGuardSetV1;

    fn capture_preliminary(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> PreparationContextV1 {
        capture_context_v1(
            eligible,
            attempt,
            PreparationCapturePhaseV1::Preliminary,
            deadline_monotonic_ms,
            &self.clock,
            &self.supervisor,
            &self.preliminary_context_faults,
        )
    }

    fn acquire_final_guards(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardAcquisitionV1<Self::GuardSet> {
        self.acquire_final_guards_observed_v1(
            eligible,
            attempt,
            deadline_monotonic_ms,
            0,
            &mut |_| Ok(()),
        )
    }

    fn acquire_final_guards_ordered_v1(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
        after_acquisition: &mut dyn FnMut(
            AuthorityGuardKindV1,
        )
            -> Result<(), AuthorityGuardAcquisitionOrderErrorV1>,
    ) -> AuthorityGuardAcquisitionV1<Self::GuardSet> {
        self.acquire_final_guards_observed_v1(
            eligible,
            attempt,
            deadline_monotonic_ms,
            1,
            after_acquisition,
        )
    }
}

fn capture_context_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    phase: PreparationCapturePhaseV1,
    caller_deadline_monotonic_ms: u64,
    clock: &DeterministicPreparationClockV1,
    supervisor: &SyntheticSupervisorPermitControlV1,
    faults: &[SyntheticContextFaultV1],
) -> PreparationContextV1 {
    for fault in faults {
        match fault {
            SyntheticContextFaultV1::Unavailable => return PreparationContextV1::Unavailable,
            SyntheticContextFaultV1::Incomplete => return PreparationContextV1::Incomplete,
            SyntheticContextFaultV1::Unsupported => return PreparationContextV1::Unsupported,
            SyntheticContextFaultV1::Torn => return PreparationContextV1::Torn,
            SyntheticContextFaultV1::None
            | SyntheticContextFaultV1::CaptureGeneration
            | SyntheticContextFaultV1::ClockGeneration
            | SyntheticContextFaultV1::UtcExpired
            | SyntheticContextFaultV1::DeadlineGeneration
            | SyntheticContextFaultV1::MonotonicDeadlineReached
            | SyntheticContextFaultV1::Boot
            | SyntheticContextFaultV1::SupervisorDenied
            | SyntheticContextFaultV1::SupervisorGeneration
            | SyntheticContextFaultV1::Trust
            | SyntheticContextFaultV1::Workload
            | SyntheticContextFaultV1::Lease
            | SyntheticContextFaultV1::Authorization
            | SyntheticContextFaultV1::Policy
            | SyntheticContextFaultV1::Catalogue
            | SyntheticContextFaultV1::Capability
            | SyntheticContextFaultV1::ReplayBinding
            | SyntheticContextFaultV1::BudgetBinding
            | SyntheticContextFaultV1::RecoveryProfile
            | SyntheticContextFaultV1::RecoveryBinding => {}
        }
    }
    build_ready_context_v1(
        eligible,
        attempt,
        phase,
        caller_deadline_monotonic_ms,
        clock,
        supervisor,
        faults,
    )
    .map(PreparationContextV1::Ready)
    .unwrap_or(PreparationContextV1::Unavailable)
}

fn build_ready_context_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    phase: PreparationCapturePhaseV1,
    caller_deadline_monotonic_ms: u64,
    clock: &DeterministicPreparationClockV1,
    supervisor: &SyntheticSupervisorPermitControlV1,
    faults: &[SyntheticContextFaultV1],
) -> Option<ReadyPreparationContextV1> {
    let sampled_utc_ms = PreparationUtcClockV1::now_utc_ms(clock).ok()?;
    let sampled_monotonic_ms = PreparationMonotonicClockV1::now_monotonic_ms(clock).ok()?;
    let bounds = eligible.bounds();
    let effective_deadline_monotonic_ms = bounds
        .effective_deadline_monotonic_ms()
        .min(caller_deadline_monotonic_ms);
    if sampled_utc_ms >= bounds.effective_expires_at_utc_unix_ms()
        || sampled_monotonic_ms >= effective_deadline_monotonic_ms
    {
        return None;
    }

    let authentic = eligible.authentic();
    let claims = authentic.preparation_claims();
    let eligibility_claims = authentic.eligibility_claims();
    let bindings = eligible.bindings();
    let budget = claims.budget();
    let budget_scope_binding_digest = synthetic_digest_parts_v1(
        b"HELIXOS\0SYNTHETIC-BUDGET-SCOPE\0V1\0",
        &[
            budget.reservation_id().as_bytes(),
            budget.currency_code().as_bytes(),
            budget.price_table_id().as_bytes(),
            claims.workload_id().as_bytes(),
        ],
    );
    let capability_binding_digest = synthetic_digest_parts_v1(
        b"HELIXOS\0SYNTHETIC-RECOVERY-CAPABILITY\0V1\0",
        &[
            bindings.capability_report_digest().as_bytes(),
            bindings.host_driver_context_digest().as_bytes(),
        ],
    );

    let requested_budget =
        PreparationRequestedBudgetV1::try_new(PreparationRequestedBudgetInputV1 {
            max_cost_micro_units: budget.max_cost_micro_units(),
            action_limit: budget.action_limit(),
            egress_bytes_limit: budget.egress_bytes_limit(),
            recovery_bytes: claims.recovery_reserved_bytes(),
        })
        .ok()?;
    let recovery_provider = match claims.recovery_class() {
        RecoveryClassV1::Compensation => Some(
            RecoveryProviderContextV1::try_new(RecoveryProviderContextInputV1 {
                profile_id: identifier_v1(SYNTHETIC_RECOVERY_PROFILE_ID)?,
                profile_version: RECOVERY_PROVIDER_CONTEXT_VERSION_V1,
                provider_id: identifier_v1(SYNTHETIC_RECOVERY_PROVIDER_ID)?,
                evidence_class: identifier_v1(SYNTHETIC_RECOVERY_EVIDENCE_CLASS_ID)?,
                provider_generation: SYNTHETIC_RECOVERY_PROVIDER_GENERATION,
                capability_binding_digest,
                at_rest_profile_id: identifier_v1(SYNTHETIC_AT_REST_PROFILE_ID)?,
                supports_create_only: true,
                supports_sync: true,
                supports_no_clobber_publication: true,
            })
            .ok()?,
        ),
        RecoveryClassV1::Irreversible => None,
    };

    let mut input = ReadyPreparationContextInputV1 {
        context_version: PREPARATION_CONTEXT_VERSION_V1,
        phase,
        plan_id: claims.plan_id(),
        operation_id: identifier_v1(claims.operation_id())?,
        task_id: identifier_v1(claims.task_id())?,
        workload_id: identifier_v1(claims.workload_id())?,
        attempt_id: attempt.digest(),
        capture_generation: bindings.capture_generation(),
        clock_generation: bindings.clock_generation(),
        plan_deadline_generation: bindings.plan_deadline_generation(),
        sampled_utc_ms,
        sampled_monotonic_ms,
        effective_expires_at_utc_ms: bounds.effective_expires_at_utc_unix_ms(),
        effective_deadline_monotonic_ms,
        supervisor_admission_state: supervisor.admission_state(),
        supervisor_generation: supervisor.supervisor_generation(),
        boot_id: identifier_v1(eligibility_claims.boot_id())?,
        instance_epoch: bindings.instance_epoch(),
        fencing_epoch: bindings.fencing_epoch(),
        trust_generation: bindings.trust_generation(),
        verified_key_fingerprint: bindings.verified_key_fingerprint(),
        workload_generation: bindings.workload_identity_generation(),
        workload_evidence_digest: bindings.workload_evidence_digest(),
        lease_generation: bindings.lease_generation(),
        lease_digest: bindings.lease_digest(),
        lease_decision_digest: bindings.lease_decision_digest(),
        authorization_generation: bindings.authorization_generation(),
        authorization_evidence_digest: bindings.authorization_evidence_digest(),
        policy_generation: bindings.policy_generation(),
        policy_decision_generation: bindings.policy_decision_generation(),
        policy_content_digest: bindings.policy_content_digest(),
        policy_decision_digest: bindings.policy_decision_digest(),
        catalogue_generation: bindings.catalogue_generation(),
        catalogue_decision_generation: bindings.catalogue_decision_generation(),
        catalogue_content_digest: bindings.catalogue_content_digest(),
        catalogue_decision_digest: bindings.catalogue_decision_digest(),
        capability_report_generation: bindings.capability_report_generation(),
        capability_report_digest: bindings.capability_report_digest(),
        host_driver_context_digest: bindings.host_driver_context_digest(),
        capability_observed_at_utc_ms: bounds.capability_observed_at_unix_ms(),
        capability_max_age_ms: bounds.capability_max_age_ms(),
        replay_claim_id: bindings.replay_claim_id(),
        replay_claimant_generation: bindings.replay_claimant_generation(),
        replay_binding_digest: bindings.replay_binding_digest(),
        budget_scope_binding_digest,
        budget_scope_generation: SYNTHETIC_BUDGET_SCOPE_GENERATION,
        currency_code: identifier_v1(budget.currency_code())?,
        price_table_id: identifier_v1(budget.price_table_id())?,
        requested_budget,
        recovery_provider,
    };
    for fault in faults {
        apply_context_fault_v1(&mut input, *fault)?;
    }
    ReadyPreparationContextV1::try_new(input).ok()
}

fn apply_context_fault_v1(
    input: &mut ReadyPreparationContextInputV1,
    fault: SyntheticContextFaultV1,
) -> Option<()> {
    match fault {
        SyntheticContextFaultV1::None
        | SyntheticContextFaultV1::Unavailable
        | SyntheticContextFaultV1::Incomplete
        | SyntheticContextFaultV1::Unsupported
        | SyntheticContextFaultV1::Torn => {}
        SyntheticContextFaultV1::CaptureGeneration => {
            input.capture_generation = input.capture_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::ClockGeneration => {
            input.clock_generation = input.clock_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::UtcExpired => {
            input.sampled_utc_ms = input.effective_expires_at_utc_ms;
        }
        SyntheticContextFaultV1::DeadlineGeneration => {
            input.plan_deadline_generation = input.plan_deadline_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::MonotonicDeadlineReached => {
            input.sampled_monotonic_ms = input.effective_deadline_monotonic_ms;
        }
        SyntheticContextFaultV1::Boot => {
            input.boot_id = identifier_v1("boot:freshness-fault")?;
        }
        SyntheticContextFaultV1::SupervisorDenied => {
            input.supervisor_admission_state = SupervisorAdmissionStateV1::Paused;
        }
        SyntheticContextFaultV1::SupervisorGeneration => {
            input.supervisor_generation = input.supervisor_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::Trust => {
            input.trust_generation = input.trust_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::Workload => {
            input.workload_generation = input.workload_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::Lease => {
            input.lease_generation = input.lease_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::Authorization => {
            input.authorization_generation = input.authorization_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::Policy => {
            input.policy_generation = input.policy_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::Catalogue => {
            input.catalogue_generation = input.catalogue_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::Capability => {
            input.capability_report_generation =
                input.capability_report_generation.checked_add(1)?;
        }
        SyntheticContextFaultV1::ReplayBinding => {
            input.replay_binding_digest = different_digest_v1(input.replay_binding_digest);
        }
        SyntheticContextFaultV1::BudgetBinding => {
            input.price_table_id = identifier_v1("prices:freshness-fault")?;
        }
        SyntheticContextFaultV1::RecoveryProfile => {
            let provider = input.recovery_provider.take()?;
            input.recovery_provider = Some(rebuild_recovery_provider_v1(provider, false, false)?);
        }
        SyntheticContextFaultV1::RecoveryBinding => {
            let provider = input.recovery_provider.take()?;
            input.recovery_provider = Some(rebuild_recovery_provider_v1(provider, true, true)?);
        }
    }
    Some(())
}

fn different_digest_v1(value: Sha256Digest) -> Sha256Digest {
    let mut bytes = *value.as_bytes();
    bytes[0] ^= 1;
    Sha256Digest::from_bytes(bytes)
}

fn rebuild_recovery_provider_v1(
    provider: RecoveryProviderContextV1,
    supports_sync: bool,
    advance_generation: bool,
) -> Option<RecoveryProviderContextV1> {
    let provider_generation = if advance_generation {
        provider.provider_generation().checked_add(1)?
    } else {
        provider.provider_generation()
    };
    RecoveryProviderContextV1::try_new(RecoveryProviderContextInputV1 {
        profile_id: identifier_v1(provider.profile_id())?,
        profile_version: provider.profile_version(),
        provider_id: identifier_v1(provider.provider_id())?,
        evidence_class: identifier_v1(provider.evidence_class())?,
        provider_generation,
        capability_binding_digest: provider.capability_binding_digest(),
        at_rest_profile_id: identifier_v1(provider.at_rest_profile_id())?,
        supports_create_only: provider.supports_create_only(),
        supports_sync,
        supports_no_clobber_publication: provider.supports_no_clobber_publication(),
    })
    .ok()
}

fn identifier_v1(value: &str) -> Option<Identifier> {
    Identifier::new(value, 128).ok()
}

fn guard_kind_ordinal_v1(kind: &AuthorityGuardKindV1) -> usize {
    match kind {
        AuthorityGuardKindV1::RecoveryPublication => 0,
        AuthorityGuardKindV1::ExternalClockDeadline => 1,
        AuthorityGuardKindV1::Supervisor => 2,
        AuthorityGuardKindV1::SignerTrust => 3,
        AuthorityGuardKindV1::Workload => 4,
        AuthorityGuardKindV1::Lease => 5,
        AuthorityGuardKindV1::Authorization => 6,
        AuthorityGuardKindV1::Policy => 7,
        AuthorityGuardKindV1::Catalogue => 8,
        AuthorityGuardKindV1::Capabilities => 9,
    }
}

fn guard_kind_from_ordinal_v1(ordinal: usize) -> AuthorityGuardKindV1 {
    match ordinal {
        0 => AuthorityGuardKindV1::RecoveryPublication,
        1 => AuthorityGuardKindV1::ExternalClockDeadline,
        2 => AuthorityGuardKindV1::Supervisor,
        3 => AuthorityGuardKindV1::SignerTrust,
        4 => AuthorityGuardKindV1::Workload,
        5 => AuthorityGuardKindV1::Lease,
        6 => AuthorityGuardKindV1::Authorization,
        7 => AuthorityGuardKindV1::Policy,
        8 => AuthorityGuardKindV1::Catalogue,
        9 => AuthorityGuardKindV1::Capabilities,
        _ => unreachable!("fixed synthetic guard ordinal"),
    }
}

#[derive(Clone)]
struct SyntheticExpectedRecoveryReceiptV1 {
    provider_generation: u64,
    capability_binding_digest: Sha256Digest,
    plan_id: Sha256Digest,
    operation_id: String,
    attempt_id: Sha256Digest,
    target_reference_digest: Sha256Digest,
    precondition_identity_digest: Sha256Digest,
    precondition_digest: Sha256Digest,
    precondition_length: u64,
    recovery_class: RecoveryClassV1,
    atomicity: AtomicityV1,
    material_digest: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
    material_id: Sha256Digest,
    publication_attempt_id: Sha256Digest,
    manifest_digest: Sha256Digest,
    boot_binding_digest: Sha256Digest,
    instance_epoch: u64,
    fencing_epoch: u64,
}

pub(crate) struct SyntheticRecoveryPublicationGuardV1 {
    binding_digest: Sha256Digest,
    deadline_monotonic_ms: u64,
    expected: SyntheticExpectedRecoveryReceiptV1,
    release_count: Arc<AtomicUsize>,
}

impl fmt::Debug for SyntheticRecoveryPublicationGuardV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticRecoveryPublicationGuardV1")
            .finish_non_exhaustive()
    }
}

impl RecoveryPublicationGuardV1 for SyntheticRecoveryPublicationGuardV1 {
    fn release(self) {
        self.release_count.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub(crate) struct SyntheticConformanceRecoveryProviderV1 {
    release_count: Arc<AtomicUsize>,
    acquire_count: Arc<AtomicUsize>,
    prepare_count: Arc<AtomicUsize>,
    verify_count: Arc<AtomicUsize>,
    published_count: Arc<AtomicUsize>,
    guard_fault: SyntheticRecoveryGuardFaultV1,
    preparation_fault: SyntheticRecoveryPreparationFaultV1,
    verification_faults: Arc<Mutex<Vec<SyntheticRecoveryVerificationFaultV1>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticRecoveryGuardFaultV1 {
    Exact,
    Unavailable,
    DeadlineReached,
    Conflict,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticRecoveryPreparationFaultV1 {
    Exact,
    BindingConflict,
    Unverified,
    ProviderFailed,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SyntheticRecoveryVerificationFaultV1 {
    Exact,
    Missing,
    Conflict,
    Unavailable,
    Unhealthy,
}

impl SyntheticConformanceRecoveryProviderV1 {
    pub(crate) const fn evidence_class_id(&self) -> &'static str {
        SYNTHETIC_RECOVERY_EVIDENCE_CLASS_ID
    }

    pub(crate) const fn claims_production_evidence(&self) -> bool {
        false
    }

    pub(crate) fn released_guard_count_test_only(&self) -> usize {
        self.release_count.load(Ordering::SeqCst)
    }

    pub(crate) fn acquire_count_test_only(&self) -> usize {
        self.acquire_count.load(Ordering::SeqCst)
    }

    pub(crate) fn prepare_count_test_only(&self) -> usize {
        self.prepare_count.load(Ordering::SeqCst)
    }

    pub(crate) fn verify_count_test_only(&self) -> usize {
        self.verify_count.load(Ordering::SeqCst)
    }

    pub(crate) fn published_count_test_only(&self) -> usize {
        self.published_count.load(Ordering::SeqCst)
    }

    pub(crate) fn with_faults_test_only(
        guard_fault: SyntheticRecoveryGuardFaultV1,
        preparation_fault: SyntheticRecoveryPreparationFaultV1,
        verification_faults: Vec<SyntheticRecoveryVerificationFaultV1>,
    ) -> Self {
        Self {
            release_count: Arc::new(AtomicUsize::new(0)),
            acquire_count: Arc::new(AtomicUsize::new(0)),
            prepare_count: Arc::new(AtomicUsize::new(0)),
            verify_count: Arc::new(AtomicUsize::new(0)),
            published_count: Arc::new(AtomicUsize::new(0)),
            guard_fault,
            preparation_fault,
            verification_faults: Arc::new(Mutex::new(verification_faults)),
        }
    }
}

impl Default for SyntheticConformanceRecoveryProviderV1 {
    fn default() -> Self {
        Self {
            release_count: Arc::new(AtomicUsize::new(0)),
            acquire_count: Arc::new(AtomicUsize::new(0)),
            prepare_count: Arc::new(AtomicUsize::new(0)),
            verify_count: Arc::new(AtomicUsize::new(0)),
            published_count: Arc::new(AtomicUsize::new(0)),
            guard_fault: SyntheticRecoveryGuardFaultV1::Exact,
            preparation_fault: SyntheticRecoveryPreparationFaultV1::Exact,
            verification_faults: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl fmt::Debug for SyntheticConformanceRecoveryProviderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticConformanceRecoveryProviderV1")
            .finish_non_exhaustive()
    }
}

impl RecoveryProviderV1 for SyntheticConformanceRecoveryProviderV1 {
    type PublicationGuard = SyntheticRecoveryPublicationGuardV1;

    fn acquire_publication_guard(
        &self,
        input: &RecoveryBindingV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> RecoveryGuardOutcomeV1<Self::PublicationGuard> {
        self.acquire_count.fetch_add(1, Ordering::SeqCst);
        match self.guard_fault {
            SyntheticRecoveryGuardFaultV1::Exact => {}
            SyntheticRecoveryGuardFaultV1::Unavailable => {
                return RecoveryGuardOutcomeV1::Unavailable
            }
            SyntheticRecoveryGuardFaultV1::DeadlineReached => {
                return RecoveryGuardOutcomeV1::DeadlineReached
            }
            SyntheticRecoveryGuardFaultV1::Conflict => return RecoveryGuardOutcomeV1::Conflict,
            SyntheticRecoveryGuardFaultV1::Unsupported => {
                return RecoveryGuardOutcomeV1::Unsupported
            }
        }
        if deadline_monotonic_ms != input.deadline_monotonic_ms()
            || input.context().sampled_monotonic_ms() >= deadline_monotonic_ms
        {
            return RecoveryGuardOutcomeV1::DeadlineReached;
        }
        let Some(expected) = expected_recovery_receipt_v1(input) else {
            return RecoveryGuardOutcomeV1::Unsupported;
        };
        RecoveryGuardOutcomeV1::Acquired(SyntheticRecoveryPublicationGuardV1 {
            binding_digest: recovery_binding_digest_v1(input),
            deadline_monotonic_ms,
            expected,
            release_count: Arc::clone(&self.release_count),
        })
    }

    fn prepare_and_publish(
        &self,
        guard: &mut Self::PublicationGuard,
        input: &RecoveryPreparationInputV1<'_>,
    ) -> RecoveryPreparationOutcomeV1 {
        self.prepare_count.fetch_add(1, Ordering::SeqCst);
        match self.preparation_fault {
            SyntheticRecoveryPreparationFaultV1::Exact => {}
            SyntheticRecoveryPreparationFaultV1::BindingConflict => {
                return RecoveryPreparationOutcomeV1::BindingConflict
            }
            SyntheticRecoveryPreparationFaultV1::Unverified => {
                return RecoveryPreparationOutcomeV1::Unverified
            }
            SyntheticRecoveryPreparationFaultV1::ProviderFailed => {
                return RecoveryPreparationOutcomeV1::ProviderFailed
            }
            SyntheticRecoveryPreparationFaultV1::Ambiguous => {
                return RecoveryPreparationOutcomeV1::Ambiguous
            }
        }
        if guard.binding_digest != recovery_binding_digest_v1(input.binding()) {
            return RecoveryPreparationOutcomeV1::BindingConflict;
        }
        match receipt_from_expected_v1(&guard.expected) {
            Some(receipt) => {
                self.published_count.fetch_add(1, Ordering::SeqCst);
                RecoveryPreparationOutcomeV1::Published(receipt)
            }
            None => RecoveryPreparationOutcomeV1::ProviderFailed,
        }
    }

    fn verify_published(
        &self,
        guard: &mut Self::PublicationGuard,
        receipt: &RecoveryMaterialReceiptV1,
        deadline_monotonic_ms: u64,
    ) -> RecoveryVerificationV1 {
        self.verify_count.fetch_add(1, Ordering::SeqCst);
        let fault = {
            let mut faults = self
                .verification_faults
                .lock()
                .expect("synthetic recovery verification mutex is not poisoned");
            if faults.is_empty() {
                SyntheticRecoveryVerificationFaultV1::Exact
            } else {
                faults.remove(0)
            }
        };
        match fault {
            SyntheticRecoveryVerificationFaultV1::Exact => {}
            SyntheticRecoveryVerificationFaultV1::Missing => {
                return RecoveryVerificationV1::Missing
            }
            SyntheticRecoveryVerificationFaultV1::Conflict => {
                return RecoveryVerificationV1::Conflict
            }
            SyntheticRecoveryVerificationFaultV1::Unavailable => {
                return RecoveryVerificationV1::Unavailable
            }
            SyntheticRecoveryVerificationFaultV1::Unhealthy => {
                return RecoveryVerificationV1::Unhealthy
            }
        }
        if deadline_monotonic_ms != guard.deadline_monotonic_ms {
            return RecoveryVerificationV1::Unavailable;
        }
        if receipt_matches_expected_v1(receipt, &guard.expected) {
            RecoveryVerificationV1::Exact
        } else {
            RecoveryVerificationV1::Conflict
        }
    }
}

fn expected_recovery_receipt_v1(
    binding: &RecoveryBindingV1<'_>,
) -> Option<SyntheticExpectedRecoveryReceiptV1> {
    let context = binding.context();
    let provider = context.recovery_provider()?;
    if provider.profile_id() != SYNTHETIC_RECOVERY_PROFILE_ID
        || provider.profile_version() != RECOVERY_PROVIDER_CONTEXT_VERSION_V1
        || provider.provider_id() != SYNTHETIC_RECOVERY_PROVIDER_ID
        || provider.evidence_class() != SYNTHETIC_RECOVERY_EVIDENCE_CLASS_ID
        || provider.at_rest_profile_id() != SYNTHETIC_AT_REST_PROFILE_ID
        || !provider.supports_create_only()
        || !provider.supports_sync()
        || !provider.supports_no_clobber_publication()
    {
        return None;
    }
    let claims = binding.claims();
    let material_digest = claims.preimage_sha256()?;
    let target_reference_digest = binding.target_reference_digest().ok()?;
    let precondition_identity_digest = binding.precondition_identity_digest().ok()?;
    let publication_attempt_id = synthetic_digest_parts_v1(
        b"HELIXOS\0SYNTHETIC-RECOVERY-PUBLICATION\0V1\0",
        &[claims.plan_id().as_bytes(), binding.attempt().as_bytes()],
    );
    let material_id = synthetic_digest_parts_v1(
        b"HELIXOS\0SYNTHETIC-RECOVERY-MATERIAL\0V1\0",
        &[
            claims.plan_id().as_bytes(),
            binding.attempt().as_bytes(),
            material_digest.as_bytes(),
        ],
    );
    let boot_binding_digest = binding.boot_binding_digest().ok()?;
    let manifest_digest = synthetic_digest_parts_v1(
        b"HELIXOS\0SYNTHETIC-RECOVERY-MANIFEST\0V1\0",
        &[
            material_id.as_bytes(),
            publication_attempt_id.as_bytes(),
            target_reference_digest.as_bytes(),
            precondition_identity_digest.as_bytes(),
        ],
    );

    Some(SyntheticExpectedRecoveryReceiptV1 {
        provider_generation: provider.provider_generation(),
        capability_binding_digest: provider.capability_binding_digest(),
        plan_id: claims.plan_id(),
        operation_id: claims.operation_id().to_owned(),
        attempt_id: binding.attempt().digest(),
        target_reference_digest,
        precondition_identity_digest,
        precondition_digest: claims.precondition_content_sha256(),
        precondition_length: claims.precondition_byte_length(),
        recovery_class: claims.recovery_class(),
        atomicity: claims.atomicity(),
        material_digest,
        material_length: claims.precondition_byte_length(),
        reserved_capacity: claims.recovery_reserved_bytes(),
        material_id,
        publication_attempt_id,
        manifest_digest,
        boot_binding_digest,
        instance_epoch: context.instance_epoch(),
        fencing_epoch: context.fencing_epoch(),
    })
}

fn receipt_from_expected_v1(
    expected: &SyntheticExpectedRecoveryReceiptV1,
) -> Option<RecoveryMaterialReceiptV1> {
    RecoveryMaterialReceiptV1::try_new(RecoveryMaterialReceiptInputV1 {
        contract_version: RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
        provider_profile_id: identifier_v1(SYNTHETIC_RECOVERY_PROFILE_ID)?,
        provider_profile_version: RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
        provider_id: identifier_v1(SYNTHETIC_RECOVERY_PROVIDER_ID)?,
        provider_generation: expected.provider_generation,
        evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
        at_rest_profile_id: identifier_v1(SYNTHETIC_AT_REST_PROFILE_ID)?,
        capability_binding_digest: expected.capability_binding_digest,
        plan_id: expected.plan_id,
        operation_id: identifier_v1(&expected.operation_id)?,
        attempt_id: expected.attempt_id,
        target_reference_digest: expected.target_reference_digest,
        precondition_identity_digest: expected.precondition_identity_digest,
        precondition_digest: expected.precondition_digest,
        precondition_length: expected.precondition_length,
        recovery_class: expected.recovery_class,
        atomicity: expected.atomicity,
        material_digest: expected.material_digest,
        material_length: expected.material_length,
        reserved_capacity: expected.reserved_capacity,
        material_id: expected.material_id,
        publication_attempt_id: expected.publication_attempt_id,
        manifest_digest: expected.manifest_digest,
        state: RecoveryMaterialStateV1::Published,
        boot_binding_digest: expected.boot_binding_digest,
        instance_epoch: expected.instance_epoch,
        fencing_epoch: expected.fencing_epoch,
    })
    .ok()
}

fn receipt_matches_expected_v1(
    receipt: &RecoveryMaterialReceiptV1,
    expected: &SyntheticExpectedRecoveryReceiptV1,
) -> bool {
    receipt.contract_version() == RECOVERY_RECEIPT_CONTRACT_VERSION_V1
        && receipt.provider_profile_id() == SYNTHETIC_RECOVERY_PROFILE_ID
        && receipt.provider_profile_version() == RECOVERY_PROVIDER_CONTRACT_VERSION_V1
        && receipt.provider_id() == SYNTHETIC_RECOVERY_PROVIDER_ID
        && receipt.provider_generation() == expected.provider_generation
        && receipt.evidence_class() == &RecoveryEvidenceClassV1::SyntheticConformance
        && receipt.at_rest_profile_id() == SYNTHETIC_AT_REST_PROFILE_ID
        && receipt.capability_binding_digest() == expected.capability_binding_digest
        && receipt.plan_id() == expected.plan_id
        && receipt.operation_id() == expected.operation_id
        && receipt.attempt_id() == expected.attempt_id
        && receipt.target_reference_digest() == expected.target_reference_digest
        && receipt.precondition_identity_digest() == expected.precondition_identity_digest
        && receipt.precondition_digest() == expected.precondition_digest
        && receipt.precondition_length() == expected.precondition_length
        && receipt.recovery_class() == expected.recovery_class
        && receipt.atomicity() == expected.atomicity
        && receipt.material_digest() == expected.material_digest
        && receipt.material_length() == expected.material_length
        && receipt.reserved_capacity() == expected.reserved_capacity
        && receipt.material_id() == expected.material_id
        && receipt.publication_attempt_id() == expected.publication_attempt_id
        && receipt.manifest_digest() == expected.manifest_digest
        && receipt.state() == &RecoveryMaterialStateV1::Published
        && receipt.boot_binding_digest() == expected.boot_binding_digest
        && receipt.instance_epoch() == expected.instance_epoch
        && receipt.fencing_epoch() == expected.fencing_epoch
}

fn recovery_binding_digest_v1(binding: &RecoveryBindingV1<'_>) -> Sha256Digest {
    let claims = binding.claims();
    synthetic_digest_parts_v1(
        b"HELIXOS\0SYNTHETIC-RECOVERY-BINDING\0V1\0",
        &[
            claims.plan_id().as_bytes(),
            claims.operation_id().as_bytes(),
            binding.attempt().as_bytes(),
            binding.context().capability_report_digest().as_bytes(),
            &binding.deadline_monotonic_ms().to_be_bytes(),
        ],
    )
}

fn synthetic_digest_parts_v1(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(
        domain.len()
            + parts
                .iter()
                .map(|part| std::mem::size_of::<u64>() + part.len())
                .sum::<usize>(),
    );
    bytes.extend_from_slice(domain);
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    Sha256Digest::digest(&bytes)
}

#[cfg(test)]
mod harness_contract_tests {
    use super::*;
    use helix_plan_preparation::{
        PreparationClockReadErrorV1, PreparationMonotonicClockV1, PreparationUtcClockV1,
    };

    #[test]
    fn public_synthetic_plan_and_eligibility_are_deterministic() {
        let first = synthetic_authentic_plan_v1();
        let second = synthetic_authentic_plan_v1();
        assert_eq!(first.plan_id(), second.plan_id());

        let eligible = synthetic_eligible_plan_v1();
        assert_eq!(eligible.authentic().plan_id(), first.plan_id());
    }

    #[test]
    fn preparation_clock_has_no_ambient_fallback() {
        let clock = DeterministicPreparationClockV1::new(17, 29);
        assert_eq!(PreparationUtcClockV1::now_utc_ms(&clock), Ok(17));
        assert_eq!(
            PreparationMonotonicClockV1::now_monotonic_ms(&clock),
            Ok(29)
        );

        clock.set_unavailable(true);
        assert_eq!(
            PreparationUtcClockV1::now_utc_ms(&clock),
            Err(PreparationClockReadErrorV1::Unavailable)
        );
        assert_eq!(
            PreparationMonotonicClockV1::now_monotonic_ms(&clock),
            Err(PreparationClockReadErrorV1::Unavailable)
        );
    }

    #[test]
    fn test_only_deadman_expires_at_equality_and_pauses() {
        let deadman = SyntheticPermitDeadmanV1::new_test_only();
        deadman.arm_test_only(250);
        assert!(!deadman.expire_if_due_test_only(249));
        assert!(deadman.expire_if_due_test_only(250));
        assert!(deadman.is_paused_test_only());
    }

    #[test]
    fn guards_acquire_in_fixed_order_and_partial_failure_unwinds_reverse() {
        let complete = SyntheticAuthorityGuardControlV1::new_test_only();
        complete
            .acquire_and_release_test_only()
            .expect("coherent guards acquire");
        let expected = AuthorityGuardKindV1::acquisition_order().to_vec();
        assert_eq!(complete.acquisition_order_test_only(), expected);
        assert_eq!(
            complete.release_order_test_only(),
            expected.iter().rev().copied().collect::<Vec<_>>()
        );
        assert_eq!(
            complete.acquired_boundary_count_test_only(),
            AuthorityGuardKindV1::COUNT
        );

        let partial = SyntheticAuthorityGuardControlV1::new_test_only();
        partial.set_state_test_only(
            AuthorityGuardKindV1::Lease,
            SyntheticGuardStateV1::Unavailable,
        );
        assert_eq!(
            partial.acquire_and_release_test_only(),
            Err(SyntheticGuardStateV1::Unavailable)
        );
        let acquired = AuthorityGuardKindV1::acquisition_order()[..5].to_vec();
        assert_eq!(partial.acquisition_order_test_only(), acquired);
        assert_eq!(
            partial.release_order_test_only(),
            acquired.iter().rev().copied().collect::<Vec<_>>()
        );
        assert_eq!(partial.acquired_boundary_count_test_only(), acquired.len());
    }

    #[test]
    fn deferred_pause_or_halt_never_overwrites_the_active_permit() {
        for action in [
            SyntheticControlActionV1::Pause,
            SyntheticControlActionV1::Halt,
        ] {
            let clock = DeterministicPreparationClockV1::new(0, 100);
            let supervisor = SyntheticSupervisorPermitControlV1::new_test_only(
                feature002::SUPERVISOR_GENERATION,
            );
            let permit = supervisor.issue_permit_test_only(clock, 350);
            let resolution = permit.commit_once(|| {
                match action {
                    SyntheticControlActionV1::Pause => supervisor.pause_test_only(),
                    SyntheticControlActionV1::Halt => supervisor.halt_test_only(),
                }
                FinalCommitStoreClassificationV1::Committed
            });
            assert!(matches!(resolution, FinalCommitResolutionV1::Committed));
            assert_eq!(
                supervisor.state_test_only(),
                SyntheticPermitStateV1::ResolvedCommitted
            );
            assert!(supervisor.deadman_test_only().is_paused_test_only());
            assert_eq!(
                supervisor.boundary_events_test_only(),
                vec![
                    SyntheticPermitBoundaryV1::EnterPermitReturned,
                    SyntheticPermitBoundaryV1::MovedToCommitInFlight,
                    SyntheticPermitBoundaryV1::ResolvedCommitted,
                ]
            );
        }
    }

    #[test]
    fn confirmed_rollback_resolves_aborted_before_deferred_control_activates() {
        let clock = DeterministicPreparationClockV1::new(0, 100);
        let supervisor =
            SyntheticSupervisorPermitControlV1::new_test_only(feature002::SUPERVISOR_GENERATION);
        let permit = supervisor.issue_permit_test_only(clock, 350);
        let resolution = permit.commit_once(|| {
            supervisor.halt_test_only();
            FinalCommitStoreClassificationV1::ConfirmedRollback
        });
        assert!(matches!(resolution, FinalCommitResolutionV1::Aborted));
        assert_eq!(
            supervisor.state_test_only(),
            SyntheticPermitStateV1::ResolvedAborted
        );
        assert!(supervisor.deadman_test_only().is_paused_test_only());
    }

    #[test]
    fn deadman_resolves_permitted_owner_loss_and_equality_without_late_commit() {
        for owner_loss in [true, false] {
            let clock = DeterministicPreparationClockV1::new(0, 100);
            let supervisor = SyntheticSupervisorPermitControlV1::new_test_only(
                feature002::SUPERVISOR_GENERATION,
            );
            let permit = supervisor.issue_permit_test_only(clock.clone(), 250);
            let deadman = supervisor.deadman_test_only();
            if owner_loss {
                assert!(deadman.owner_lost_test_only());
            } else {
                clock.set_monotonic_ms(250);
                assert!(deadman.expire_if_due_test_only(250));
            }
            let commit_calls = AtomicUsize::new(0);
            let resolution = permit.commit_once(|| {
                commit_calls.fetch_add(1, Ordering::SeqCst);
                FinalCommitStoreClassificationV1::Committed
            });
            assert!(matches!(resolution, FinalCommitResolutionV1::Ambiguous));
            assert_eq!(commit_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                deadman.state_test_only(),
                SyntheticPermitStateV1::ResolvedAmbiguous
            );
            assert_eq!(
                deadman
                    .boundary_events_test_only()
                    .iter()
                    .filter(|event| **event == SyntheticPermitBoundaryV1::ResolvedAmbiguous)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn deadman_resolves_commit_in_flight_owner_loss_and_equality_once() {
        for owner_loss in [true, false] {
            let clock = DeterministicPreparationClockV1::new(0, 100);
            let supervisor = SyntheticSupervisorPermitControlV1::new_test_only(
                feature002::SUPERVISOR_GENERATION,
            );
            let permit = supervisor.issue_permit_test_only(clock.clone(), 250);
            let deadman = supervisor.deadman_test_only();
            let resolution = permit.commit_once(|| {
                if owner_loss {
                    assert!(deadman.owner_lost_test_only());
                } else {
                    clock.set_monotonic_ms(250);
                    assert!(deadman.expire_if_due_test_only(250));
                }
                FinalCommitStoreClassificationV1::Committed
            });
            assert!(matches!(resolution, FinalCommitResolutionV1::Ambiguous));
            assert!(!deadman.owner_lost_test_only());
            assert_eq!(
                deadman.state_test_only(),
                SyntheticPermitStateV1::ResolvedAmbiguous
            );
            assert_eq!(
                deadman
                    .boundary_events_test_only()
                    .iter()
                    .filter(|event| **event == SyntheticPermitBoundaryV1::ResolvedAmbiguous)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn recovery_provider_is_explicitly_synthetic_conformance_only() {
        let provider = SyntheticConformanceRecoveryProviderV1::default();
        assert_eq!(
            provider.evidence_class_id(),
            SYNTHETIC_RECOVERY_EVIDENCE_CLASS_ID
        );
        assert!(!provider.claims_production_evidence());
    }
}
