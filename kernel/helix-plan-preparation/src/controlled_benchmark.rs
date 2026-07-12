//! Feature-only controlled benchmark wiring.
//!
//! This module deliberately uses public synthetic authority facts to drive the real
//! eligibility, preparation orchestration, final comparison, commit-permit and store
//! adapter path. It is not compiled by default and returns no eligibility marker,
//! prepared marker, permit, grant or adapter authority.

use crate::{
    prepare_plan_v1, AuthorityGuardAcquisitionOrderErrorV1, AuthorityGuardAcquisitionV1,
    AuthorityGuardKindV1, AuthorityGuardSetV1, AuthorityGuardValidationV1, FinalCommitGateV1,
    FinalCommitInFlightV1, FinalCommitPermitOutcomeV1, FinalCommitPermitRequestV1,
    FinalCommitPermitV1, FinalCommitReadbackResolutionV1, FinalCommitResolutionV1,
    FinalCommitStoreClassificationV1, FinalCommitTerminalResolutionV1, PreparationAttemptIdV1,
    PreparationAuthoritySourceV1, PreparationCapturePhaseV1, PreparationClockReadErrorV1,
    PreparationContextV1, PreparationMonotonicClockV1, PreparationOutcomeV1,
    PreparationRequestedBudgetInputV1, PreparationRequestedBudgetV1, PreparationStoreV1,
    PreparationUtcClockV1, ReadyPreparationContextInputV1, ReadyPreparationContextV1,
    RecoveryBindingV1, RecoveryGuardOutcomeV1, RecoveryMaterialReceiptV1,
    RecoveryPreparationInputV1, RecoveryPreparationOutcomeV1, RecoveryProviderV1,
    RecoveryPublicationGuardV1, RecoveryVerificationV1, PREPARATION_CONTEXT_VERSION_V1,
};
#[cfg(feature = "test-fault-injection")]
use crate::{prepare_plan_with_fault_probe_v1, FaultProbeV1};
use helix_contracts::{
    AtomicityV1, AuthenticPlanEnvelopeV1, Identifier, RecoveryClassV1, RequestSourceKindV1,
    RiskLevelV1, Sha256Digest, MAX_SAFE_U64,
};
use helix_plan_eligibility::{
    evaluate_and_claim_plan_v1, ActiveLeaseInputV1, ActiveLeaseRecordV1, AuthorizationInputV1,
    AuthorizationRecordV1, AuthorizationStatusV1, AuthorizationViewV1, CapabilityRecordInputV1,
    CapabilityRecordV1, CapabilityViewV1, CatalogueRecordInputV1, CatalogueRecordV1,
    CatalogueViewV1, EligibilityContextV1, EligiblePlanV1, LeaseAllowanceInputV1, LeaseAllowanceV1,
    LeaseAuthorityDecisionV1, LeaseResolutionV1, LeaseStateV1, MonotonicClockViewV1,
    MonotonicSampleV1, PlanDeadlineInputV1, PlanDeadlineRecordV1, PlanDeadlineViewV1,
    PlanDecisionEvidenceInputV1, PlanDecisionEvidenceV1, PolicyDecisionV1, PolicyRecordInputV1,
    PolicyRecordV1, PolicyViewV1, ReadyEligibilityContextInputV1, ReadyEligibilityContextV1,
    ReplayBindingV1, ReplayClaimOutcomeV1, ReplayClaimReceiptV1, ReplayClaimVerificationV1,
    ReplayClaimVerificationViewV1, ReplayClaimVerifierV1, ReplayClaimantV1, SignerTrustInputV1,
    SignerTrustRecordV1, SignerTrustViewV1, SupervisorAdmissionStateV1, SupervisorInputV1,
    SupervisorRecordV1, SupervisorViewV1, SupportStatusV1, TimeViewInputV1, TimeViewV1,
    WallClockViewV1, WorkloadIdentityInputV1, WorkloadIdentityRecordV1, WorkloadIdentityViewV1,
};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1: u64 = 1_750_000_000_000;
#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1: u64 =
    CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 + 86_400_000;
#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1: u64 =
    CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 - 1_000;
#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_KEY_ID_V1: &str = "core-signing-key:controlled-benchmark-v1";
#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_BOOT_ID_V1: &str = "boot:controlled-benchmark-v1";
#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_WORKLOAD_ID_V1: &str = "workload:controlled-benchmark-v1";
#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_POLICY_VERSION_V1: &str = "policy:controlled-benchmark-v1";
#[doc(hidden)]
pub const CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1: &str = "catalog:controlled-benchmark-v1";

const BASE_MONOTONIC_MS: u64 = 1_000_000;
const BASE_UTC_MS: u64 = CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 + 10_000;
const CAPABILITY_MAX_AGE_MS: u64 = 200_000;
const INSTANCE_EPOCH: u64 = 1;
const FENCING_EPOCH: u64 = 9;
const CAPTURE_GENERATION: u64 = 10;
const CLOCK_GENERATION: u64 = 11;
const PLAN_DEADLINE_GENERATION: u64 = 12;
const SUPERVISOR_GENERATION: u64 = 13;
const TRUST_GENERATION: u64 = 14;
const WORKLOAD_GENERATION: u64 = 15;
const LEASE_GENERATION: u64 = 16;
const AUTHORIZATION_GENERATION: u64 = 17;
const POLICY_GENERATION: u64 = 18;
const POLICY_DECISION_GENERATION: u64 = 19;
const CATALOGUE_GENERATION: u64 = 20;
const CATALOGUE_DECISION_GENERATION: u64 = 21;
const CAPABILITY_REPORT_GENERATION: u64 = 22;
const CLAIMANT_GENERATION: u64 = 23;
const BUDGET_SCOPE_DOMAIN_V1: &[u8] = b"HELIXOS\0CONTROLLED-BENCHMARK-BUDGET-SCOPE\0V1\0";
const BUDGET_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0SYNTHETIC-BUDGET-SCOPE\0V1\0";
const REPLAY_CLAIM_DOMAIN_V1: &[u8] = b"HELIXOS\0CONTROLLED-BENCHMARK-REPLAY-CLAIM\0V1\0";

/// Stable, redacted refusal from the feature-only benchmark facade.
#[derive(Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ControlledBenchmarkErrorV1 {
    InvalidFixture,
    DeadlineReached,
    EligibilityDenied,
    PreparationRefused,
    RecoveryProviderCalled,
}

impl ControlledBenchmarkErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidFixture => "CONTROLLED_BENCHMARK_INVALID_FIXTURE",
            Self::DeadlineReached => "CONTROLLED_BENCHMARK_DEADLINE_REACHED",
            Self::EligibilityDenied => "CONTROLLED_BENCHMARK_ELIGIBILITY_DENIED",
            Self::PreparationRefused => "CONTROLLED_BENCHMARK_PREPARATION_REFUSED",
            Self::RecoveryProviderCalled => "CONTROLLED_BENCHMARK_RECOVERY_PROVIDER_CALLED",
        }
    }
}

impl fmt::Debug for ControlledBenchmarkErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for ControlledBenchmarkErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled benchmark refused")
    }
}

impl Error for ControlledBenchmarkErrorV1 {}

/// Shared real monotonic source for the benchmark facade and coordinator adapter.
#[derive(Clone)]
#[doc(hidden)]
pub struct ControlledBenchmarkClockV1 {
    started: Arc<Instant>,
}

impl ControlledBenchmarkClockV1 {
    pub fn start_v1() -> Self {
        Self {
            started: Arc::new(Instant::now()),
        }
    }

    pub fn now_absolute_monotonic_ms_v1(&self) -> Result<u64, ControlledBenchmarkErrorV1> {
        let elapsed = u64::try_from(self.started.elapsed().as_millis())
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?;
        BASE_MONOTONIC_MS
            .checked_add(elapsed)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(ControlledBenchmarkErrorV1::InvalidFixture)
    }

    pub fn deadline_after_ms_v1(
        &self,
        remaining_ms: u64,
    ) -> Result<u64, ControlledBenchmarkErrorV1> {
        self.now_absolute_monotonic_ms_v1()?
            .checked_add(remaining_ms)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(ControlledBenchmarkErrorV1::InvalidFixture)
    }
}

impl fmt::Debug for ControlledBenchmarkClockV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlledBenchmarkClockV1")
            .finish_non_exhaustive()
    }
}

impl PreparationUtcClockV1 for ControlledBenchmarkClockV1 {
    fn now_utc_ms(&self) -> Result<u64, PreparationClockReadErrorV1> {
        let elapsed = u64::try_from(self.started.elapsed().as_millis())
            .map_err(|_| PreparationClockReadErrorV1::Unavailable)?;
        BASE_UTC_MS
            .checked_add(elapsed)
            .filter(|value| *value <= MAX_SAFE_U64)
            .ok_or(PreparationClockReadErrorV1::Unavailable)
    }
}

impl PreparationMonotonicClockV1 for ControlledBenchmarkClockV1 {
    fn now_monotonic_ms(&self) -> Result<u64, PreparationClockReadErrorV1> {
        self.now_absolute_monotonic_ms_v1()
            .map_err(|_| PreparationClockReadErrorV1::Unavailable)
    }
}

/// Exact scope fixture that the caller provisions before starting the timer.
#[doc(hidden)]
pub struct ControlledBenchmarkBudgetScopeV1 {
    scope_id: Sha256Digest,
    task_lease_digest: Sha256Digest,
    allowance_binding_digest: Sha256Digest,
    scope_generation: u64,
    currency_code: String,
    price_table_id: String,
    total: [u64; 4],
}

impl ControlledBenchmarkBudgetScopeV1 {
    pub const fn scope_id_v1(&self) -> Sha256Digest {
        self.scope_id
    }

    pub const fn task_lease_digest_v1(&self) -> Sha256Digest {
        self.task_lease_digest
    }

    pub const fn allowance_binding_digest_v1(&self) -> Sha256Digest {
        self.allowance_binding_digest
    }

    pub const fn scope_generation_v1(&self) -> u64 {
        self.scope_generation
    }

    pub fn currency_code_v1(&self) -> &str {
        &self.currency_code
    }

    pub fn price_table_id_v1(&self) -> &str {
        &self.price_table_id
    }

    pub const fn total_v1(&self) -> [u64; 4] {
        self.total
    }
}

impl fmt::Debug for ControlledBenchmarkBudgetScopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlledBenchmarkBudgetScopeV1")
            .finish_non_exhaustive()
    }
}

/// One consumed, already-authenticated and already-eligible benchmark sample.
#[doc(hidden)]
pub struct ControlledBenchmarkCaseV1 {
    eligible: EligiblePlanV1,
    authority: ControlledAuthorityV1,
    replay: ControlledReplayV1,
    recovery: RefusingRecoveryProviderV1,
    clock: ControlledBenchmarkClockV1,
    scope: ControlledBenchmarkBudgetScopeV1,
}

impl ControlledBenchmarkCaseV1 {
    pub const fn budget_scope_v1(&self) -> &ControlledBenchmarkBudgetScopeV1 {
        &self.scope
    }

    /// Runs the real Phase A-E orchestrator and consumes the positive marker internally.
    pub fn prepare_once_v1<S: PreparationStoreV1>(
        self,
        store: &S,
        caller_deadline_monotonic_ms: u64,
    ) -> Result<ControlledBenchmarkCommitV1, ControlledBenchmarkErrorV1> {
        if self.clock.now_absolute_monotonic_ms_v1()? >= caller_deadline_monotonic_ms {
            return Err(ControlledBenchmarkErrorV1::DeadlineReached);
        }
        let outcome = prepare_plan_v1(
            self.eligible,
            &self.authority,
            &self.replay,
            store,
            &self.recovery,
            &self.clock,
            caller_deadline_monotonic_ms,
        );
        Self::classify_outcome_v1(outcome, self.recovery.calls.load(Ordering::SeqCst))
    }

    /// Runs the same real Phase A-E action with one explicit portable process probe.
    #[doc(hidden)]
    #[cfg(feature = "test-fault-injection")]
    pub fn prepare_once_with_fault_probe_v1<S: PreparationStoreV1>(
        self,
        store: &S,
        caller_deadline_monotonic_ms: u64,
        fault_probe: FaultProbeV1,
    ) -> Result<ControlledBenchmarkCommitV1, ControlledBenchmarkErrorV1> {
        if self.clock.now_absolute_monotonic_ms_v1()? >= caller_deadline_monotonic_ms {
            return Err(ControlledBenchmarkErrorV1::DeadlineReached);
        }
        let outcome = prepare_plan_with_fault_probe_v1(
            self.eligible,
            &self.authority,
            &self.replay,
            store,
            &self.recovery,
            &self.clock,
            caller_deadline_monotonic_ms,
            fault_probe,
        );
        Self::classify_outcome_v1(outcome, self.recovery.calls.load(Ordering::SeqCst))
    }

    fn classify_outcome_v1(
        outcome: PreparationOutcomeV1,
        provider_calls: usize,
    ) -> Result<ControlledBenchmarkCommitV1, ControlledBenchmarkErrorV1> {
        if provider_calls != 0 {
            return Err(ControlledBenchmarkErrorV1::RecoveryProviderCalled);
        }
        match outcome {
            PreparationOutcomeV1::Prepared(marker) => {
                drop(marker);
                Ok(ControlledBenchmarkCommitV1 {
                    recovery_provider_calls: provider_calls,
                })
            }
            PreparationOutcomeV1::Denied(_)
            | PreparationOutcomeV1::Failed(_)
            | PreparationOutcomeV1::Ambiguous(_) => {
                Err(ControlledBenchmarkErrorV1::PreparationRefused)
            }
        }
    }
}

impl fmt::Debug for ControlledBenchmarkCaseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlledBenchmarkCaseV1")
            .finish_non_exhaustive()
    }
}

/// Redacted confirmation that the production preparation path committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ControlledBenchmarkCommitV1 {
    recovery_provider_calls: usize,
}

impl ControlledBenchmarkCommitV1 {
    pub const fn recovery_provider_calls_v1(self) -> usize {
        self.recovery_provider_calls
    }
}

/// Evaluates one authentic unique plan before measurement and freezes its exact scope.
#[doc(hidden)]
pub fn build_controlled_benchmark_case_v1(
    plan: AuthenticPlanEnvelopeV1,
    clock: ControlledBenchmarkClockV1,
    plan_deadline_monotonic_ms: u64,
    scope_generation: u64,
) -> Result<ControlledBenchmarkCaseV1, ControlledBenchmarkErrorV1> {
    if scope_generation == 0
        || scope_generation > MAX_SAFE_U64
        || clock.now_absolute_monotonic_ms_v1()? >= plan_deadline_monotonic_ms
    {
        return Err(ControlledBenchmarkErrorV1::InvalidFixture);
    }
    validate_plan_profile_v1(&plan)?;
    let replay = ControlledReplayV1::new(plan.plan_id(), clock.clone());
    let operation_id = plan.eligibility_claims().operation_id().to_owned();
    let task_id = plan.eligibility_claims().task_id().to_owned();
    let context = build_eligibility_context_v1(
        &plan,
        &clock,
        plan_deadline_monotonic_ms,
        &operation_id,
        &task_id,
    )?;
    let eligible = evaluate_and_claim_plan_v1(plan, context, &replay)
        .map_err(|_| ControlledBenchmarkErrorV1::EligibilityDenied)?;
    let scope = budget_scope_v1(&eligible, scope_generation)?;
    let authority = ControlledAuthorityV1 {
        clock: clock.clone(),
        plan_id: eligible.authentic().plan_id(),
        scope_generation,
    };
    Ok(ControlledBenchmarkCaseV1 {
        eligible,
        authority,
        replay,
        recovery: RefusingRecoveryProviderV1::default(),
        clock,
        scope,
    })
}

fn validate_plan_profile_v1(
    plan: &AuthenticPlanEnvelopeV1,
) -> Result<(), ControlledBenchmarkErrorV1> {
    let eligibility = plan.eligibility_claims();
    let preparation = plan.preparation_claims();
    if eligibility.key_id() != CONTROLLED_BENCHMARK_KEY_ID_V1
        || eligibility.boot_id() != CONTROLLED_BENCHMARK_BOOT_ID_V1
        || eligibility.workload_id() != CONTROLLED_BENCHMARK_WORKLOAD_ID_V1
        || eligibility.policy_version() != CONTROLLED_BENCHMARK_POLICY_VERSION_V1
        || eligibility.catalog_version() != CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1
        || eligibility.risk_level() != RiskLevelV1::L2
        || preparation.recovery_class() != RecoveryClassV1::Irreversible
        || preparation.atomicity() != AtomicityV1::NonAtomic
        || preparation.recovery_reserved_bytes() != 0
        || eligibility.issued_at_unix_ms() != CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1
        || eligibility.expires_at_unix_ms() != CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1
        || eligibility.capability_observed_at_unix_ms()
            != CONTROLLED_BENCHMARK_CAPABILITY_OBSERVED_AT_UTC_MS_V1
    {
        return Err(ControlledBenchmarkErrorV1::InvalidFixture);
    }
    Ok(())
}

fn build_eligibility_context_v1<'context>(
    plan: &AuthenticPlanEnvelopeV1,
    clock: &ControlledBenchmarkClockV1,
    deadline_monotonic_ms: u64,
    operation_id: &'context str,
    task_id: &'context str,
) -> Result<EligibilityContextV1<'context>, ControlledBenchmarkErrorV1> {
    let claims = plan.eligibility_claims();
    let plan_id = claims.plan_id();
    let now_utc_ms = PreparationUtcClockV1::now_utc_ms(clock)
        .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?;
    let now_monotonic_ms = PreparationMonotonicClockV1::now_monotonic_ms(clock)
        .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?;
    let policy_content_digest = Sha256Digest::digest(b"controlled benchmark policy content");
    let catalogue_content_digest = Sha256Digest::digest(b"controlled benchmark catalogue content");
    let host_driver_context_digest =
        Sha256Digest::digest(b"controlled benchmark host-driver context");
    let lease_decision_digest = Sha256Digest::digest(b"controlled benchmark lease decision");
    let policy_decision_digest = Sha256Digest::digest(b"controlled benchmark policy decision");
    let catalogue_decision_digest =
        Sha256Digest::digest(b"controlled benchmark catalogue decision");
    let input = ReadyEligibilityContextInputV1 {
        bound_plan_id: plan_id,
        capture_generation: CAPTURE_GENERATION,
        time: TimeViewV1::try_new(TimeViewInputV1 {
            clock_generation: CLOCK_GENERATION,
            wall: WallClockViewV1::healthy(now_utc_ms)
                .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
            monotonic: MonotonicClockViewV1::Healthy(
                MonotonicSampleV1::try_new(CONTROLLED_BENCHMARK_BOOT_ID_V1, now_monotonic_ms)
                    .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
            ),
        })
        .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        plan_deadline: PlanDeadlineViewV1::Current(
            PlanDeadlineRecordV1::try_new(PlanDeadlineInputV1 {
                plan_id,
                boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1,
                deadline_monotonic_ms,
                deadline_generation: PLAN_DEADLINE_GENERATION,
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        supervisor: SupervisorViewV1::Current(
            SupervisorRecordV1::try_new(SupervisorInputV1 {
                admission_state: SupervisorAdmissionStateV1::Open,
                boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1,
                instance_epoch: INSTANCE_EPOCH,
                fencing_epoch: FENCING_EPOCH,
                supervisor_generation: SUPERVISOR_GENERATION,
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        signer: SignerTrustViewV1::Trusted(
            SignerTrustRecordV1::try_new(SignerTrustInputV1 {
                key_id: CONTROLLED_BENCHMARK_KEY_ID_V1,
                public_key_fingerprint: claims.verified_key_fingerprint(),
                trust_generation: TRUST_GENERATION,
                minimum_accepted_issued_at_unix_ms: CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 - 1,
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        workload: WorkloadIdentityViewV1::Trusted(
            WorkloadIdentityRecordV1::try_new(WorkloadIdentityInputV1 {
                workload_id: CONTROLLED_BENCHMARK_WORKLOAD_ID_V1,
                evidence_digest: Sha256Digest::digest(b"controlled benchmark workload evidence"),
                identity_generation: WORKLOAD_GENERATION,
                boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1,
                instance_epoch: INSTANCE_EPOCH,
                not_before_utc_unix_ms: CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 - 1,
                expires_at_utc_unix_ms: CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
                deadline_monotonic_ms,
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        lease: LeaseResolutionV1::ExactlyOne(
            ActiveLeaseRecordV1::try_new(ActiveLeaseInputV1 {
                lease_digest: claims.task_lease_digest(),
                lease_generation: LEASE_GENERATION,
                state: LeaseStateV1::Active,
                task_id,
                workload_id: CONTROLLED_BENCHMARK_WORKLOAD_ID_V1,
                boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1,
                instance_epoch: INSTANCE_EPOCH,
                request_source_kind: RequestSourceKindV1::HumanRequestGrant,
                request_source_digest: claims.request_source_digest(),
                not_before_utc_unix_ms: CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 - 1,
                expires_at_utc_unix_ms: CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
                deadline_monotonic_ms,
                decision: LeaseAuthorityDecisionV1::Allows(LeaseAllowanceV1::new(
                    LeaseAllowanceInputV1 {
                        plan_id,
                        decision_digest: lease_decision_digest,
                    },
                )),
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        authorization: AuthorizationViewV1::Current(
            AuthorizationRecordV1::try_new(AuthorizationInputV1 {
                status: AuthorizationStatusV1::Granted,
                plan_id,
                operation_id,
                risk_level: RiskLevelV1::L2,
                nonce: claims.nonce(),
                evidence_digest: Sha256Digest::digest(
                    b"controlled benchmark authorization evidence",
                ),
                authorization_generation: AUTHORIZATION_GENERATION,
                boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1,
                not_before_utc_unix_ms: CONTROLLED_BENCHMARK_ISSUED_AT_UTC_MS_V1 - 1,
                expires_at_utc_unix_ms: CONTROLLED_BENCHMARK_EXPIRES_AT_UTC_MS_V1,
                deadline_monotonic_ms,
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        policy: PolicyViewV1::Current(
            PolicyRecordV1::try_new(PolicyRecordInputV1 {
                version: CONTROLLED_BENCHMARK_POLICY_VERSION_V1,
                resolved_content_digest: policy_content_digest,
                active_content_digest: policy_content_digest,
                policy_generation: POLICY_GENERATION,
                decision_policy_generation: POLICY_GENERATION,
                decision_generation: POLICY_DECISION_GENERATION,
                decision: PolicyDecisionV1::Allow(PlanDecisionEvidenceV1::new(
                    PlanDecisionEvidenceInputV1 {
                        plan_id,
                        decision_digest: policy_decision_digest,
                    },
                )),
                max_capability_age_ms: CAPABILITY_MAX_AGE_MS,
                mandatory_capabilities: policy_capabilities_v1(),
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        catalogue: CatalogueViewV1::Current(
            CatalogueRecordV1::try_new(CatalogueRecordInputV1 {
                version: CONTROLLED_BENCHMARK_CATALOGUE_VERSION_V1,
                resolved_content_digest: catalogue_content_digest,
                active_content_digest: catalogue_content_digest,
                catalogue_generation: CATALOGUE_GENERATION,
                decision_catalogue_generation: CATALOGUE_GENERATION,
                decision_generation: CATALOGUE_DECISION_GENERATION,
                decision: PlanDecisionEvidenceV1::new(PlanDecisionEvidenceInputV1 {
                    plan_id,
                    decision_digest: catalogue_decision_digest,
                }),
                schema_support: SupportStatusV1::Supported,
                intent_support: SupportStatusV1::Supported,
                mandatory_capabilities: catalogue_capabilities_v1(),
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
        capabilities: CapabilityViewV1::Current(
            CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
                report_digest: claims.capability_report_digest(),
                observed_at_unix_ms: claims.capability_observed_at_unix_ms(),
                boot_id: CONTROLLED_BENCHMARK_BOOT_ID_V1,
                instance_epoch: INSTANCE_EPOCH,
                report_generation: CAPABILITY_REPORT_GENERATION,
                report_host_driver_context_digest: host_driver_context_digest,
                current_host_driver_context_digest: host_driver_context_digest,
                available_capabilities: available_capabilities_v1(),
            })
            .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?,
        ),
    };
    let ready = ReadyEligibilityContextV1::try_new(input)
        .map_err(|_| ControlledBenchmarkErrorV1::InvalidFixture)?;
    Ok(EligibilityContextV1::Ready(ready))
}

fn policy_capabilities_v1() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES
        .get_or_init(|| vec!["filesystem.atomic-replace".to_owned()])
        .as_slice()
}

fn catalogue_capabilities_v1() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES
        .get_or_init(|| vec!["filesystem.verify-by-handle".to_owned()])
        .as_slice()
}

fn available_capabilities_v1() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES
        .get_or_init(|| {
            vec![
                "filesystem.atomic-replace".to_owned(),
                "filesystem.durable-flush".to_owned(),
                "filesystem.verify-by-handle".to_owned(),
            ]
        })
        .as_slice()
}

struct ExactReplayRowV1 {
    instance_epoch: u64,
    nonce: helix_contracts::Nonce128,
    operation_id: String,
    claim_id: Sha256Digest,
    claimant_generation: u64,
    binding_digest: Sha256Digest,
}

struct ControlledReplayV1 {
    plan_id: Sha256Digest,
    clock: ControlledBenchmarkClockV1,
    exact: Mutex<Option<ExactReplayRowV1>>,
}

impl ControlledReplayV1 {
    fn new(plan_id: Sha256Digest, clock: ControlledBenchmarkClockV1) -> Self {
        Self {
            plan_id,
            clock,
            exact: Mutex::new(None),
        }
    }
}

impl ReplayClaimantV1 for ControlledReplayV1 {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1 {
        let now = match self.clock.now_absolute_monotonic_ms_v1() {
            Ok(now) => now,
            Err(_) => return ReplayClaimOutcomeV1::Unavailable,
        };
        if binding.plan_id() != self.plan_id || now >= binding.claim_deadline_monotonic_ms() {
            return ReplayClaimOutcomeV1::BindingConflict;
        }
        let claim_id = digest_joined_v1(REPLAY_CLAIM_DOMAIN_V1, &[self.plan_id.as_bytes()]);
        let receipt = match ReplayClaimReceiptV1::try_new(
            claim_id,
            CLAIMANT_GENERATION,
            binding.binding_digest(),
        ) {
            Ok(receipt) => receipt,
            Err(_) => return ReplayClaimOutcomeV1::Unavailable,
        };
        let mut exact = match self.exact.lock() {
            Ok(exact) => exact,
            Err(_) => return ReplayClaimOutcomeV1::Unavailable,
        };
        if exact.is_some() {
            return ReplayClaimOutcomeV1::AlreadyClaimed;
        }
        *exact = Some(ExactReplayRowV1 {
            instance_epoch: binding.instance_epoch(),
            nonce: binding.nonce(),
            operation_id: binding.operation_id().to_owned(),
            claim_id,
            claimant_generation: CLAIMANT_GENERATION,
            binding_digest: binding.binding_digest(),
        });
        ReplayClaimOutcomeV1::Claimed(receipt)
    }
}

impl ReplayClaimVerifierV1 for ControlledReplayV1 {
    fn verify_exact_claim(
        &self,
        view: &ReplayClaimVerificationViewV1<'_>,
        deadline_monotonic_ms: u64,
    ) -> ReplayClaimVerificationV1 {
        let now = match self.clock.now_absolute_monotonic_ms_v1() {
            Ok(now) if now < deadline_monotonic_ms => now,
            Ok(_) => return ReplayClaimVerificationV1::Unavailable,
            Err(_) => return ReplayClaimVerificationV1::Unhealthy,
        };
        let _ = now;
        let exact = match self.exact.lock() {
            Ok(exact) => exact,
            Err(_) => return ReplayClaimVerificationV1::Unhealthy,
        };
        let Some(exact) = exact.as_ref() else {
            return ReplayClaimVerificationV1::Missing;
        };
        if view.instance_epoch() == exact.instance_epoch
            && view.nonce() == exact.nonce
            && view.operation_id() == exact.operation_id
            && view.claim_id() == exact.claim_id
            && view.claimant_generation() == exact.claimant_generation
            && view.binding_digest() == exact.binding_digest
        {
            ReplayClaimVerificationV1::Exact
        } else {
            ReplayClaimVerificationV1::Conflict
        }
    }
}

struct ControlledAuthorityV1 {
    clock: ControlledBenchmarkClockV1,
    plan_id: Sha256Digest,
    scope_generation: u64,
}

impl PreparationAuthoritySourceV1 for ControlledAuthorityV1 {
    type GuardSet = ControlledGuardSetV1;

    fn capture_preliminary(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> PreparationContextV1 {
        build_preparation_context_v1(
            eligible,
            attempt,
            PreparationCapturePhaseV1::Preliminary,
            &self.clock,
            deadline_monotonic_ms,
            self.scope_generation,
        )
    }

    fn acquire_final_guards(
        &self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardAcquisitionV1<Self::GuardSet> {
        self.acquire_final_guards_ordered_v1(eligible, attempt, deadline_monotonic_ms, &mut |_| {
            Ok(())
        })
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
        let now = match self.clock.now_absolute_monotonic_ms_v1() {
            Ok(now) => now,
            Err(_) => return AuthorityGuardAcquisitionV1::Unavailable,
        };
        if eligible.authentic().plan_id() != self.plan_id {
            return AuthorityGuardAcquisitionV1::Revoked;
        }
        if now >= deadline_monotonic_ms {
            return AuthorityGuardAcquisitionV1::DeadlineReached;
        }
        for kind in AuthorityGuardKindV1::acquisition_order()
            .into_iter()
            .skip(1)
        {
            if after_acquisition(kind).is_err() {
                return AuthorityGuardAcquisitionV1::Unsupported;
            }
        }
        AuthorityGuardAcquisitionV1::Acquired(ControlledGuardSetV1 {
            clock: self.clock.clone(),
            plan_id: self.plan_id,
            attempt_id: attempt.digest(),
            scope_generation: self.scope_generation,
        })
    }
}

struct ControlledGuardSetV1 {
    clock: ControlledBenchmarkClockV1,
    plan_id: Sha256Digest,
    attempt_id: Sha256Digest,
    scope_generation: u64,
}

impl AuthorityGuardSetV1 for ControlledGuardSetV1 {
    fn capture_final(
        &mut self,
        eligible: &EligiblePlanV1,
        attempt: &PreparationAttemptIdV1,
        deadline_monotonic_ms: u64,
    ) -> PreparationContextV1 {
        if eligible.authentic().plan_id() != self.plan_id || attempt.digest() != self.attempt_id {
            return PreparationContextV1::Torn;
        }
        build_preparation_context_v1(
            eligible,
            attempt,
            PreparationCapturePhaseV1::Final,
            &self.clock,
            deadline_monotonic_ms,
            self.scope_generation,
        )
    }

    fn validate_all(
        &mut self,
        now_monotonic_ms: u64,
        deadline_monotonic_ms: u64,
    ) -> AuthorityGuardValidationV1 {
        match self.clock.now_absolute_monotonic_ms_v1() {
            Ok(now)
                if now >= now_monotonic_ms
                    && now_monotonic_ms < deadline_monotonic_ms
                    && now < deadline_monotonic_ms =>
            {
                AuthorityGuardValidationV1::Valid
            }
            Ok(now) if now >= deadline_monotonic_ms => AuthorityGuardValidationV1::DeadlineReached,
            Ok(_) => AuthorityGuardValidationV1::Mismatch,
            Err(_) => AuthorityGuardValidationV1::Unavailable,
        }
    }

    fn release_reverse(self) {}
}

impl FinalCommitGateV1 for ControlledGuardSetV1 {
    type Permit = ControlledPermitV1;

    fn enter_commit_permit(
        &mut self,
        request: &FinalCommitPermitRequestV1<'_>,
    ) -> FinalCommitPermitOutcomeV1<Self::Permit> {
        let now = match self.clock.now_absolute_monotonic_ms_v1() {
            Ok(now) => now,
            Err(_) => return FinalCommitPermitOutcomeV1::Unavailable,
        };
        if request.attempt().digest() != self.attempt_id
            || request.expected_supervisor_generation() != SUPERVISOR_GENERATION
        {
            return FinalCommitPermitOutcomeV1::Revoked;
        }
        if now >= request.permit_deadline_monotonic_ms() {
            return FinalCommitPermitOutcomeV1::DeadlineReached;
        }
        FinalCommitPermitOutcomeV1::Permitted(ControlledPermitV1 {
            clock: self.clock.clone(),
            deadline_monotonic_ms: request.permit_deadline_monotonic_ms(),
        })
    }
}

struct ControlledPermitV1 {
    clock: ControlledBenchmarkClockV1,
    deadline_monotonic_ms: u64,
}

impl FinalCommitPermitV1 for ControlledPermitV1 {
    type InFlight = ControlledInFlightV1;

    fn permit_deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms
    }

    fn commit_once<C>(self, commit: C) -> FinalCommitResolutionV1<Self::InFlight>
    where
        C: FnOnce() -> FinalCommitStoreClassificationV1,
    {
        let before = self.clock.now_absolute_monotonic_ms_v1();
        if !matches!(before, Ok(now) if now < self.deadline_monotonic_ms) {
            return FinalCommitResolutionV1::Aborted;
        }
        let classification = commit();
        let live_after = matches!(
            self.clock.now_absolute_monotonic_ms_v1(),
            Ok(now) if now < self.deadline_monotonic_ms
        );
        match (classification, live_after) {
            (FinalCommitStoreClassificationV1::Committed, true) => {
                FinalCommitResolutionV1::Committed
            }
            (FinalCommitStoreClassificationV1::ConfirmedRollback, _) => {
                FinalCommitResolutionV1::Aborted
            }
            (FinalCommitStoreClassificationV1::Uncertain, _) => {
                FinalCommitResolutionV1::Uncertain(ControlledInFlightV1 {
                    deadline_monotonic_ms: self.deadline_monotonic_ms,
                })
            }
            (FinalCommitStoreClassificationV1::Committed, false)
            | (FinalCommitStoreClassificationV1::Unclassified, _) => {
                FinalCommitResolutionV1::Ambiguous
            }
        }
    }
}

struct ControlledInFlightV1 {
    deadline_monotonic_ms: u64,
}

impl FinalCommitInFlightV1 for ControlledInFlightV1 {
    fn permit_deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms
    }

    fn resolve_readback(
        self,
        resolution: FinalCommitReadbackResolutionV1,
    ) -> FinalCommitTerminalResolutionV1 {
        match resolution {
            FinalCommitReadbackResolutionV1::ThisAttemptCommitted => {
                FinalCommitTerminalResolutionV1::Committed
            }
            FinalCommitReadbackResolutionV1::DefinitelyAbsent => {
                FinalCommitTerminalResolutionV1::Aborted
            }
            FinalCommitReadbackResolutionV1::PriorExactAttempt
            | FinalCommitReadbackResolutionV1::Conflict
            | FinalCommitReadbackResolutionV1::Inconclusive
            | FinalCommitReadbackResolutionV1::LateOrRevoked => {
                FinalCommitTerminalResolutionV1::Ambiguous
            }
        }
    }
}

fn build_preparation_context_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    phase: PreparationCapturePhaseV1,
    clock: &ControlledBenchmarkClockV1,
    caller_deadline_monotonic_ms: u64,
    scope_generation: u64,
) -> PreparationContextV1 {
    let ready = (|| {
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
        let eligibility = authentic.eligibility_claims();
        let bindings = eligible.bindings();
        let budget = claims.budget();
        let budget_scope_binding_digest = budget_binding_digest_v1(eligible).ok()?;
        let requested_budget =
            PreparationRequestedBudgetV1::try_new(PreparationRequestedBudgetInputV1 {
                max_cost_micro_units: budget.max_cost_micro_units(),
                action_limit: budget.action_limit(),
                egress_bytes_limit: budget.egress_bytes_limit(),
                recovery_bytes: claims.recovery_reserved_bytes(),
            })
            .ok()?;
        ReadyPreparationContextV1::try_new(ReadyPreparationContextInputV1 {
            context_version: PREPARATION_CONTEXT_VERSION_V1,
            phase,
            plan_id: claims.plan_id(),
            operation_id: Identifier::new(claims.operation_id().to_owned(), 128).ok()?,
            task_id: Identifier::new(claims.task_id().to_owned(), 128).ok()?,
            workload_id: Identifier::new(claims.workload_id().to_owned(), 128).ok()?,
            attempt_id: attempt.digest(),
            capture_generation: bindings.capture_generation(),
            clock_generation: bindings.clock_generation(),
            plan_deadline_generation: bindings.plan_deadline_generation(),
            sampled_utc_ms,
            sampled_monotonic_ms,
            effective_expires_at_utc_ms: bounds.effective_expires_at_utc_unix_ms(),
            effective_deadline_monotonic_ms,
            supervisor_admission_state: SupervisorAdmissionStateV1::Open,
            supervisor_generation: SUPERVISOR_GENERATION,
            boot_id: Identifier::new(eligibility.boot_id().to_owned(), 128).ok()?,
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
            budget_scope_generation: scope_generation,
            currency_code: Identifier::new(budget.currency_code().to_owned(), 3).ok()?,
            price_table_id: Identifier::new(budget.price_table_id().to_owned(), 128).ok()?,
            requested_budget,
            recovery_provider: None,
        })
        .ok()
    })();
    ready
        .map(PreparationContextV1::Ready)
        .unwrap_or(PreparationContextV1::Unavailable)
}

fn budget_scope_v1(
    eligible: &EligiblePlanV1,
    scope_generation: u64,
) -> Result<ControlledBenchmarkBudgetScopeV1, ControlledBenchmarkErrorV1> {
    let claims = eligible.authentic().preparation_claims();
    let budget = claims.budget();
    Ok(ControlledBenchmarkBudgetScopeV1 {
        scope_id: digest_joined_v1(
            BUDGET_SCOPE_DOMAIN_V1,
            &[eligible.authentic().plan_id().as_bytes()],
        ),
        task_lease_digest: claims.task_lease_digest(),
        allowance_binding_digest: budget_binding_digest_v1(eligible)?,
        scope_generation,
        currency_code: budget.currency_code().to_owned(),
        price_table_id: budget.price_table_id().to_owned(),
        total: [
            budget.max_cost_micro_units(),
            budget.action_limit(),
            budget.egress_bytes_limit(),
            claims.recovery_reserved_bytes(),
        ],
    })
}

fn budget_binding_digest_v1(
    eligible: &EligiblePlanV1,
) -> Result<Sha256Digest, ControlledBenchmarkErrorV1> {
    let claims = eligible.authentic().preparation_claims();
    let budget = claims.budget();
    Ok(digest_joined_v1(
        BUDGET_BINDING_DOMAIN_V1,
        &[
            budget.reservation_id().as_bytes(),
            budget.currency_code().as_bytes(),
            budget.price_table_id().as_bytes(),
            claims.workload_id().as_bytes(),
        ],
    ))
}

fn digest_joined_v1(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let additional = parts.iter().fold(0_usize, |total, part| {
        total.saturating_add(8).saturating_add(part.len())
    });
    let mut preimage = Vec::with_capacity(domain.len().saturating_add(additional));
    preimage.extend_from_slice(domain);
    for part in parts {
        preimage.extend_from_slice(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        preimage.extend_from_slice(part);
    }
    Sha256Digest::digest(&preimage)
}

#[derive(Default)]
struct RefusingRecoveryProviderV1 {
    calls: AtomicUsize,
}

struct RefusingRecoveryGuardV1;

impl RecoveryPublicationGuardV1 for RefusingRecoveryGuardV1 {
    fn release(self) {}
}

impl RecoveryProviderV1 for RefusingRecoveryProviderV1 {
    type PublicationGuard = RefusingRecoveryGuardV1;

    fn acquire_publication_guard(
        &self,
        _input: &RecoveryBindingV1<'_>,
        _deadline_monotonic_ms: u64,
    ) -> RecoveryGuardOutcomeV1<Self::PublicationGuard> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        RecoveryGuardOutcomeV1::Unsupported
    }

    fn prepare_and_publish(
        &self,
        _guard: &mut Self::PublicationGuard,
        _input: &RecoveryPreparationInputV1<'_>,
    ) -> RecoveryPreparationOutcomeV1 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        RecoveryPreparationOutcomeV1::ProviderFailed
    }

    fn verify_published(
        &self,
        _guard: &mut Self::PublicationGuard,
        _receipt: &RecoveryMaterialReceiptV1,
        _deadline_monotonic_ms: u64,
    ) -> RecoveryVerificationV1 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        RecoveryVerificationV1::Unhealthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_deadlines_are_absolute_and_advance() {
        let clock = ControlledBenchmarkClockV1::start_v1();
        let now = clock.now_absolute_monotonic_ms_v1().unwrap();
        let deadline = clock.deadline_after_ms_v1(60_000).unwrap();
        assert!(deadline > now);
        assert!(deadline >= BASE_MONOTONIC_MS + 60_000);
    }

    #[test]
    fn stable_errors_and_profile_constants_are_bounded() {
        assert_eq!(
            ControlledBenchmarkErrorV1::PreparationRefused.code(),
            "CONTROLLED_BENCHMARK_PREPARATION_REFUSED"
        );
        assert!(CONTROLLED_BENCHMARK_KEY_ID_V1.len() <= 128);
        assert!(CONTROLLED_BENCHMARK_BOOT_ID_V1.len() <= 128);
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn process_probe_facade_uses_the_real_orchestrator_without_changing_default_entry() {
        let source = include_str!("controlled_benchmark.rs").replace("\r\n", "\n");
        let default_start = source
            .find("pub fn prepare_once_v1")
            .expect("default facade remains present");
        let selected_start = source
            .find("pub fn prepare_once_with_fault_probe_v1")
            .expect("feature-only probe facade remains present");
        let classifier_start = source
            .find("fn classify_outcome_v1")
            .expect("shared classifier remains present");
        let default_body = &source[default_start..selected_start];
        let selected_body = &source[selected_start..classifier_start];

        assert!(default_body.contains("prepare_plan_v1("));
        assert!(!default_body.contains("prepare_plan_with_fault_probe_v1("));
        assert!(selected_body.contains("prepare_plan_with_fault_probe_v1("));
        assert!(selected_body.contains("fault_probe,"));
    }
}
