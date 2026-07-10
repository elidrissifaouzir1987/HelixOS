//! Deterministic, project-owned registry and executor for the public v1 corpus.
//!
//! This module is test support, not production authority. Both the integration test
//! and the generator example include it so one exhaustive registry defines fixture
//! generation and execution.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use crate::common::*;
use crate::replay_claimant::{DeterministicReplayClaimant, ForcedReplayOutcome};
use helix_contracts::{
    AuthenticPlanEnvelopeV1, Nonce128, RequestSourceKindV1, RiskLevelV1, Sha256Digest, MAX_SAFE_U64,
};
use helix_plan_eligibility::{
    ActiveLeaseInputV1, ActiveLeaseRecordV1, AuthorizationInputV1, AuthorizationRecordV1,
    AuthorizationStatusV1, AuthorizationViewV1, CapabilityRecordInputV1, CapabilityRecordV1,
    CapabilityViewV1, CatalogueRecordInputV1, CatalogueRecordV1, CatalogueViewV1,
    EligibilityContextBuildErrorV1, EligibilityContextV1, EligibilityDenialV1,
    LeaseAllowanceInputV1, LeaseAllowanceV1, LeaseAuthorityDecisionV1, LeaseResolutionV1,
    LeaseStateV1, MonotonicClockViewV1, PlanDeadlineViewV1, PlanDecisionEvidenceInputV1,
    PlanDecisionEvidenceV1, PolicyDecisionV1, PolicyRecordInputV1, PolicyRecordV1, PolicyViewV1,
    ReadyEligibilityContextV1, SignerTrustInputV1, SignerTrustRecordV1, SignerTrustViewV1,
    SupervisorAdmissionStateV1, SupervisorViewV1, SupportStatusV1, WallClockViewV1,
    WorkloadIdentityInputV1, WorkloadIdentityRecordV1, WorkloadIdentityViewV1,
};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

pub const CASES_SCHEMA_V1: &str = "helixos.plan-eligibility-cases/1";
pub const SUMMARY_SCHEMA_V1: &str = "helixos.plan-eligibility-summary/1";

const OTHER_KEY_ID: &str = "core-signing-key:fixture-2";
const OTHER_TASK_ID: &str = "task:fixture-2";
const OTHER_WORKLOAD_ID: &str = "workload:agent-vm-2";
const OTHER_OPERATION_ID: &str = "operation:00000000-0000-4000-8000-000000000002";
const OTHER_POLICY_VERSION: &str = "policy:2";
const OTHER_CATALOGUE_VERSION: &str = "catalog:2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CasesManifestV1 {
    pub schema: String,
    pub cases: Vec<CaseV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseV1 {
    pub case_id: String,
    pub stage: CaseStageV1,
    pub profile: CorpusProfileV1,
    pub fault: String,
    pub claimant: ClaimantProfileV1,
    pub expected_outcome: OutcomeV1,
    pub expected_code: String,
    pub expected_claimant_reached: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeSummaryV1 {
    pub schema: String,
    pub cases: Vec<OutcomeCaseV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeCaseV1 {
    pub case_id: String,
    pub claimant_reached: bool,
    pub code: String,
    pub outcome: OutcomeV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStageV1 {
    ContextBuild,
    Runtime,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CorpusProfileV1 {
    #[serde(rename = "coherent-v1")]
    CoherentV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimantProfileV1 {
    NotReached,
    ClaimedMatching,
    ClaimedWrongBinding,
    AlreadyClaimed,
    BindingConflict,
    Unavailable,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeV1 {
    Eligible,
    Denied,
    ContextBuildDenied,
}

/// Builds the complete manifest directly from both frozen public taxonomies.
pub fn generated_manifest() -> CasesManifestV1 {
    let mut cases = Vec::with_capacity(
        1 + EligibilityContextBuildErrorV1::ALL.len() + EligibilityDenialV1::ALL.len(),
    );
    cases.push(CaseV1 {
        case_id: "eligible-coherent".to_owned(),
        stage: CaseStageV1::Runtime,
        profile: CorpusProfileV1::CoherentV1,
        fault: "none".to_owned(),
        claimant: ClaimantProfileV1::ClaimedMatching,
        expected_outcome: OutcomeV1::Eligible,
        expected_code: "NONE".to_owned(),
        expected_claimant_reached: true,
    });

    for error in EligibilityContextBuildErrorV1::ALL.iter().copied() {
        let fault = build_fault_token(error);
        cases.push(CaseV1 {
            case_id: format!("build-{fault}"),
            stage: CaseStageV1::ContextBuild,
            profile: CorpusProfileV1::CoherentV1,
            fault,
            claimant: ClaimantProfileV1::NotReached,
            expected_outcome: OutcomeV1::ContextBuildDenied,
            expected_code: error.code().to_owned(),
            expected_claimant_reached: false,
        });
    }

    for denial in EligibilityDenialV1::ALL.iter().copied() {
        let fault = runtime_fault_token(denial);
        cases.push(CaseV1 {
            case_id: format!("deny-{fault}"),
            stage: CaseStageV1::Runtime,
            profile: CorpusProfileV1::CoherentV1,
            fault,
            claimant: claimant_profile(denial),
            expected_outcome: OutcomeV1::Denied,
            expected_code: denial.code().to_owned(),
            expected_claimant_reached: is_replay_denial(denial),
        });
    }

    cases.sort_unstable_by(|left, right| left.case_id.cmp(&right.case_id));
    CasesManifestV1 {
        schema: CASES_SCHEMA_V1.to_owned(),
        cases,
    }
}

/// Executes every registered fault rather than projecting manifest expectations.
pub fn execute_manifest(manifest: &CasesManifestV1) -> OutcomeSummaryV1 {
    let mut cases = manifest.cases.iter().map(execute_case).collect::<Vec<_>>();
    cases.sort_unstable_by(|left, right| left.case_id.cmp(&right.case_id));
    OutcomeSummaryV1 {
        schema: SUMMARY_SCHEMA_V1.to_owned(),
        cases,
    }
}

/// RFC 8785 JCS bytes with no BOM, whitespace, or trailing newline.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("corpus value must canonicalize")
}

fn execute_case(case: &CaseV1) -> OutcomeCaseV1 {
    let actual = match case.stage {
        CaseStageV1::ContextBuild => execute_build_case(&case.fault),
        CaseStageV1::Runtime if case.fault == "none" => execute_runtime_case(None),
        CaseStageV1::Runtime => {
            let denial = EligibilityDenialV1::ALL
                .iter()
                .copied()
                .find(|candidate| runtime_fault_token(*candidate) == case.fault)
                .unwrap_or_else(|| panic!("unregistered runtime fault token"));
            execute_runtime_case(Some(denial))
        }
    };
    assert_eq!(
        actual.outcome, case.expected_outcome,
        "registered outcome drift for {}",
        case.case_id
    );
    assert_eq!(
        actual.code, case.expected_code,
        "registered first-code drift for {}",
        case.case_id
    );
    assert_eq!(
        actual.claimant_reached, case.expected_claimant_reached,
        "registered claimant probe drift for {}",
        case.case_id
    );
    OutcomeCaseV1 {
        case_id: case.case_id.clone(),
        claimant_reached: actual.claimant_reached,
        code: actual.code,
        outcome: actual.outcome,
    }
}

struct ActualOutcome {
    claimant_reached: bool,
    code: String,
    outcome: OutcomeV1,
}

fn execute_build_case(fault: &str) -> ActualOutcome {
    let expected = EligibilityContextBuildErrorV1::ALL
        .iter()
        .copied()
        .find(|candidate| build_fault_token(*candidate) == fault)
        .unwrap_or_else(|| panic!("unregistered context-build fault token"));
    let actual = trigger_build_error(expected);
    ActualOutcome {
        claimant_reached: false,
        code: actual.code().to_owned(),
        outcome: OutcomeV1::ContextBuildDenied,
    }
}

fn execute_runtime_case(denial: Option<EligibilityDenialV1>) -> ActualOutcome {
    let (result, claimant_reached) = match denial {
        Some(EligibilityDenialV1::ReplayAlreadyClaimed) => {
            let claimant = DeterministicReplayClaimant::new();
            let _ = coherent_fixture()
                .evaluate(&claimant)
                .expect("replay repeat setup must claim the coherent binding");
            let before = claimant.call_count();
            let result = coherent_fixture().evaluate(&claimant);
            let call_delta = claimant.call_count() - before;
            assert_eq!(
                call_delta, 1,
                "the replay repeat case must call exactly once"
            );
            (result, true)
        }
        Some(EligibilityDenialV1::ReplayBindingConflict) => {
            execute_with_forced_claimant(ForcedReplayOutcome::BindingConflict, coherent_fixture())
        }
        Some(EligibilityDenialV1::ReplayUnavailable) => {
            execute_with_forced_claimant(ForcedReplayOutcome::Unavailable, coherent_fixture())
        }
        Some(EligibilityDenialV1::ReplayAmbiguous) => {
            execute_with_forced_claimant(ForcedReplayOutcome::Ambiguous, coherent_fixture())
        }
        Some(EligibilityDenialV1::ReplayReceiptBindingMismatch) => execute_with_forced_claimant(
            ForcedReplayOutcome::WrongReceiptBinding,
            coherent_fixture(),
        ),
        Some(expected) => {
            let claimant = DeterministicReplayClaimant::new();
            let before = claimant.call_count();
            let result = fixture_for_denial(expected).evaluate(&claimant);
            let call_delta = claimant.call_count() - before;
            assert!(call_delta <= 1, "the evaluator retried the replay claimant");
            (result, call_delta == 1)
        }
        None => {
            let claimant = DeterministicReplayClaimant::new();
            let before = claimant.call_count();
            let result = coherent_fixture().evaluate(&claimant);
            let call_delta = claimant.call_count() - before;
            assert_eq!(call_delta, 1, "the coherent case must call exactly once");
            (result, true)
        }
    };

    match result {
        Ok(_) => ActualOutcome {
            claimant_reached,
            code: "NONE".to_owned(),
            outcome: OutcomeV1::Eligible,
        },
        Err(failure) => ActualOutcome {
            claimant_reached,
            code: failure.denial().code().to_owned(),
            outcome: OutcomeV1::Denied,
        },
    }
}

fn execute_with_forced_claimant(
    forced: ForcedReplayOutcome,
    fixture: EligibilityFixture,
) -> (
    Result<helix_plan_eligibility::EligiblePlanV1, helix_plan_eligibility::EligibilityFailureV1>,
    bool,
) {
    let claimant = DeterministicReplayClaimant::with_forced_outcome(forced);
    let before = claimant.call_count();
    let result = fixture.evaluate(&claimant);
    let call_delta = claimant.call_count() - before;
    assert_eq!(call_delta, 1, "a replay case must call exactly once");
    (result, true)
}

fn build_fault_token(error: EligibilityContextBuildErrorV1) -> String {
    code_token(
        error
            .code()
            .strip_prefix("CONTEXT_BUILD_")
            .expect("context-build code prefix is frozen"),
    )
}

fn runtime_fault_token(denial: EligibilityDenialV1) -> String {
    code_token(denial.code())
}

fn code_token(code: &str) -> String {
    code.to_ascii_lowercase().replace('_', "-")
}

fn claimant_profile(denial: EligibilityDenialV1) -> ClaimantProfileV1 {
    match denial {
        EligibilityDenialV1::ReplayAlreadyClaimed => ClaimantProfileV1::AlreadyClaimed,
        EligibilityDenialV1::ReplayBindingConflict => ClaimantProfileV1::BindingConflict,
        EligibilityDenialV1::ReplayUnavailable => ClaimantProfileV1::Unavailable,
        EligibilityDenialV1::ReplayAmbiguous => ClaimantProfileV1::Ambiguous,
        EligibilityDenialV1::ReplayReceiptBindingMismatch => ClaimantProfileV1::ClaimedWrongBinding,
        _ => ClaimantProfileV1::NotReached,
    }
}

fn is_replay_denial(denial: EligibilityDenialV1) -> bool {
    matches!(
        denial,
        EligibilityDenialV1::ReplayAlreadyClaimed
            | EligibilityDenialV1::ReplayBindingConflict
            | EligibilityDenialV1::ReplayUnavailable
            | EligibilityDenialV1::ReplayAmbiguous
            | EligibilityDenialV1::ReplayReceiptBindingMismatch
    )
}

fn trigger_build_error(expected: EligibilityContextBuildErrorV1) -> EligibilityContextBuildErrorV1 {
    match expected {
        EligibilityContextBuildErrorV1::IntegerOutOfRange => {
            let plan = authentic_plan();
            let mut input = coherent_ready_input(&plan);
            input.capture_generation = MAX_SAFE_U64 + 1;
            ReadyEligibilityContextV1::try_new(input)
                .expect_err("an unsafe capture generation must fail construction")
        }
        EligibilityContextBuildErrorV1::InvalidInterval => {
            WorkloadIdentityRecordV1::try_new(WorkloadIdentityInputV1 {
                workload_id: WORKLOAD_ID,
                evidence_digest: digest(b"fixture workload evidence"),
                identity_generation: WORKLOAD_GENERATION,
                boot_id: BOOT_ID,
                instance_epoch: INSTANCE_EPOCH,
                not_before_utc_unix_ms: ISSUED_AT_MS - 10_000,
                expires_at_utc_unix_ms: ISSUED_AT_MS - 10_000,
                deadline_monotonic_ms: 130_000,
            })
            .expect_err("an empty half-open interval must fail construction")
        }
        EligibilityContextBuildErrorV1::InvalidIdentifier => {
            let plan = authentic_plan();
            SignerTrustRecordV1::try_new(SignerTrustInputV1 {
                key_id: "invalid key id",
                public_key_fingerprint: plan.eligibility_claims().verified_key_fingerprint(),
                trust_generation: TRUST_GENERATION,
                minimum_accepted_issued_at_unix_ms: ISSUED_AT_MS - 1,
            })
            .expect_err("an identifier containing spaces must fail construction")
        }
        EligibilityContextBuildErrorV1::InvalidCapabilitySet => {
            let values = vec![
                "filesystem.verify-by-handle".to_owned(),
                "filesystem.atomic-replace".to_owned(),
            ];
            CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
                report_digest: digest(b"fixture capability report"),
                observed_at_unix_ms: ISSUED_AT_MS - 1_000,
                boot_id: BOOT_ID,
                instance_epoch: INSTANCE_EPOCH,
                report_generation: CAPABILITY_REPORT_GENERATION,
                report_host_driver_context_digest: digest(b"fixture host-driver context"),
                current_host_driver_context_digest: digest(b"fixture host-driver context"),
                available_capabilities: &values,
            })
            .expect_err("an unsorted capability set must fail construction")
        }
        EligibilityContextBuildErrorV1::LimitExceeded => {
            let values = (0..129)
                .map(|index| format!("capability-{index:03}"))
                .collect::<Vec<_>>();
            CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
                report_digest: digest(b"fixture capability report"),
                observed_at_unix_ms: ISSUED_AT_MS - 1_000,
                boot_id: BOOT_ID,
                instance_epoch: INSTANCE_EPOCH,
                report_generation: CAPABILITY_REPORT_GENERATION,
                report_host_driver_context_digest: digest(b"fixture host-driver context"),
                current_host_driver_context_digest: digest(b"fixture host-driver context"),
                available_capabilities: &values,
            })
            .expect_err("a capability set above the frozen limit must fail construction")
        }
    }
}

#[derive(Clone, Copy)]
struct SignerFacts {
    key_id: &'static str,
    public_key_fingerprint: Sha256Digest,
    trust_generation: u64,
    minimum_accepted_issued_at_unix_ms: u64,
}

impl SignerFacts {
    fn coherent(plan: &AuthenticPlanEnvelopeV1) -> Self {
        Self {
            key_id: KEY_ID,
            public_key_fingerprint: plan.eligibility_claims().verified_key_fingerprint(),
            trust_generation: TRUST_GENERATION,
            minimum_accepted_issued_at_unix_ms: ISSUED_AT_MS - 1,
        }
    }

    fn into_view(self) -> SignerTrustViewV1<'static> {
        SignerTrustViewV1::Trusted(
            SignerTrustRecordV1::try_new(SignerTrustInputV1 {
                key_id: self.key_id,
                public_key_fingerprint: self.public_key_fingerprint,
                trust_generation: self.trust_generation,
                minimum_accepted_issued_at_unix_ms: self.minimum_accepted_issued_at_unix_ms,
            })
            .expect("valid signer facts"),
        )
    }
}

fn signer_fixture_with(change: impl FnOnce(&mut SignerFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        let mut facts = SignerFacts::coherent(plan);
        change(&mut facts);
        input.signer = facts.into_view();
    })
}

#[derive(Clone, Copy)]
struct WorkloadFacts {
    workload_id: &'static str,
    evidence_digest: Sha256Digest,
    identity_generation: u64,
    boot_id: &'static str,
    instance_epoch: u64,
    not_before_utc_unix_ms: u64,
    expires_at_utc_unix_ms: u64,
    deadline_monotonic_ms: u64,
}

impl WorkloadFacts {
    fn coherent() -> Self {
        Self {
            workload_id: WORKLOAD_ID,
            evidence_digest: digest(b"fixture workload evidence"),
            identity_generation: WORKLOAD_GENERATION,
            boot_id: BOOT_ID,
            instance_epoch: INSTANCE_EPOCH,
            not_before_utc_unix_ms: ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: ISSUED_AT_MS + 210_000,
            deadline_monotonic_ms: 130_000,
        }
    }

    fn into_view(self) -> WorkloadIdentityViewV1<'static> {
        WorkloadIdentityViewV1::Trusted(
            WorkloadIdentityRecordV1::try_new(WorkloadIdentityInputV1 {
                workload_id: self.workload_id,
                evidence_digest: self.evidence_digest,
                identity_generation: self.identity_generation,
                boot_id: self.boot_id,
                instance_epoch: self.instance_epoch,
                not_before_utc_unix_ms: self.not_before_utc_unix_ms,
                expires_at_utc_unix_ms: self.expires_at_utc_unix_ms,
                deadline_monotonic_ms: self.deadline_monotonic_ms,
            })
            .expect("valid workload facts"),
        )
    }
}

fn workload_fixture_with(change: impl FnOnce(&mut WorkloadFacts)) -> EligibilityFixture {
    ready_fixture_with(move |_, input| {
        let mut facts = WorkloadFacts::coherent();
        change(&mut facts);
        input.workload = facts.into_view();
    })
}

#[derive(Clone, Copy)]
enum LeaseDecisionFixture {
    Allows(Sha256Digest),
    Unavailable,
    Inconsistent,
    PlanMismatch,
    IntentDenied,
    ScopeWidened,
    BudgetWidened,
    PriceTableMismatch,
    ReservationMismatch,
}

impl LeaseDecisionFixture {
    fn into_decision(self) -> LeaseAuthorityDecisionV1 {
        match self {
            Self::Allows(plan_id) => {
                LeaseAuthorityDecisionV1::Allows(LeaseAllowanceV1::new(LeaseAllowanceInputV1 {
                    plan_id,
                    decision_digest: digest(b"fixture lease decision"),
                }))
            }
            Self::Unavailable => LeaseAuthorityDecisionV1::Unavailable,
            Self::Inconsistent => LeaseAuthorityDecisionV1::Inconsistent,
            Self::PlanMismatch => LeaseAuthorityDecisionV1::PlanMismatch,
            Self::IntentDenied => LeaseAuthorityDecisionV1::IntentDenied,
            Self::ScopeWidened => LeaseAuthorityDecisionV1::ScopeWidened,
            Self::BudgetWidened => LeaseAuthorityDecisionV1::BudgetWidened,
            Self::PriceTableMismatch => LeaseAuthorityDecisionV1::PriceTableMismatch,
            Self::ReservationMismatch => LeaseAuthorityDecisionV1::ReservationMismatch,
        }
    }
}

#[derive(Clone, Copy)]
struct LeaseFacts {
    lease_digest: Sha256Digest,
    lease_generation: u64,
    state: LeaseStateV1,
    task_id: &'static str,
    workload_id: &'static str,
    boot_id: &'static str,
    instance_epoch: u64,
    request_source_kind: RequestSourceKindV1,
    request_source_digest: Sha256Digest,
    not_before_utc_unix_ms: u64,
    expires_at_utc_unix_ms: u64,
    deadline_monotonic_ms: u64,
    decision: LeaseDecisionFixture,
}

impl LeaseFacts {
    fn coherent(plan: &AuthenticPlanEnvelopeV1) -> Self {
        let claims = plan.eligibility_claims();
        Self {
            lease_digest: claims.task_lease_digest(),
            lease_generation: LEASE_GENERATION,
            state: LeaseStateV1::Active,
            task_id: TASK_ID,
            workload_id: WORKLOAD_ID,
            boot_id: BOOT_ID,
            instance_epoch: INSTANCE_EPOCH,
            request_source_kind: RequestSourceKindV1::HumanRequestGrant,
            request_source_digest: claims.request_source_digest(),
            not_before_utc_unix_ms: ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: ISSUED_AT_MS + 200_000,
            deadline_monotonic_ms: 120_000,
            decision: LeaseDecisionFixture::Allows(claims.plan_id()),
        }
    }

    fn into_view(self) -> LeaseResolutionV1<'static> {
        LeaseResolutionV1::ExactlyOne(
            ActiveLeaseRecordV1::try_new(ActiveLeaseInputV1 {
                lease_digest: self.lease_digest,
                lease_generation: self.lease_generation,
                state: self.state,
                task_id: self.task_id,
                workload_id: self.workload_id,
                boot_id: self.boot_id,
                instance_epoch: self.instance_epoch,
                request_source_kind: self.request_source_kind,
                request_source_digest: self.request_source_digest,
                not_before_utc_unix_ms: self.not_before_utc_unix_ms,
                expires_at_utc_unix_ms: self.expires_at_utc_unix_ms,
                deadline_monotonic_ms: self.deadline_monotonic_ms,
                decision: self.decision.into_decision(),
            })
            .expect("valid lease facts"),
        )
    }
}

fn lease_fixture_with(change: impl FnOnce(&mut LeaseFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        let mut facts = LeaseFacts::coherent(plan);
        change(&mut facts);
        input.lease = facts.into_view();
    })
}

#[derive(Clone, Copy)]
struct AuthorizationFacts {
    status: AuthorizationStatusV1,
    plan_id: Sha256Digest,
    operation_id: &'static str,
    risk_level: RiskLevelV1,
    nonce: Nonce128,
    evidence_digest: Sha256Digest,
    authorization_generation: u64,
    boot_id: &'static str,
    not_before_utc_unix_ms: u64,
    expires_at_utc_unix_ms: u64,
    deadline_monotonic_ms: u64,
}

impl AuthorizationFacts {
    fn coherent(plan: &AuthenticPlanEnvelopeV1) -> Self {
        Self {
            status: AuthorizationStatusV1::Granted,
            plan_id: plan.plan_id(),
            operation_id: OPERATION_ID,
            risk_level: RiskLevelV1::L1,
            nonce: Nonce128::from_bytes([0x11; 16]),
            evidence_digest: digest(b"fixture authorization evidence"),
            authorization_generation: AUTHORIZATION_GENERATION,
            boot_id: BOOT_ID,
            not_before_utc_unix_ms: ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: ISSUED_AT_MS + 190_000,
            deadline_monotonic_ms: 110_000,
        }
    }

    fn into_view(self) -> AuthorizationViewV1<'static> {
        AuthorizationViewV1::Current(
            AuthorizationRecordV1::try_new(AuthorizationInputV1 {
                status: self.status,
                plan_id: self.plan_id,
                operation_id: self.operation_id,
                risk_level: self.risk_level,
                nonce: self.nonce,
                evidence_digest: self.evidence_digest,
                authorization_generation: self.authorization_generation,
                boot_id: self.boot_id,
                not_before_utc_unix_ms: self.not_before_utc_unix_ms,
                expires_at_utc_unix_ms: self.expires_at_utc_unix_ms,
                deadline_monotonic_ms: self.deadline_monotonic_ms,
            })
            .expect("valid authorization facts"),
        )
    }
}

fn authorization_fixture_with(change: impl FnOnce(&mut AuthorizationFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        let mut facts = AuthorizationFacts::coherent(plan);
        change(&mut facts);
        input.authorization = facts.into_view();
    })
}

fn strings<const N: usize>(
    lock: &'static OnceLock<Vec<String>>,
    values: [&str; N],
) -> &'static [String] {
    lock.get_or_init(|| values.into_iter().map(str::to_owned).collect())
        .as_slice()
}

fn policy_mandatory() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(&VALUES, ["filesystem.atomic-replace"])
}

fn catalogue_mandatory() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(&VALUES, ["filesystem.verify-by-handle"])
}

fn extra_policy_mandatory() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(&VALUES, ["filesystem.policy-extra"])
}

fn available_all() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(
        &VALUES,
        [
            "filesystem.atomic-replace",
            "filesystem.durable-flush",
            "filesystem.verify-by-handle",
        ],
    )
}

fn available_without_atomic_replace() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(
        &VALUES,
        ["filesystem.durable-flush", "filesystem.verify-by-handle"],
    )
}

#[derive(Clone, Copy)]
enum PolicyDecisionFixture {
    Allow(Sha256Digest),
    Deny(Sha256Digest),
}

impl PolicyDecisionFixture {
    fn into_decision(self) -> PolicyDecisionV1 {
        let evidence = match self {
            Self::Allow(plan_id) | Self::Deny(plan_id) => {
                PlanDecisionEvidenceV1::new(PlanDecisionEvidenceInputV1 {
                    plan_id,
                    decision_digest: digest(b"fixture policy decision"),
                })
            }
        };
        match self {
            Self::Allow(_) => PolicyDecisionV1::Allow(evidence),
            Self::Deny(_) => PolicyDecisionV1::Deny(evidence),
        }
    }
}

#[derive(Clone, Copy)]
struct PolicyFacts {
    version: &'static str,
    resolved_content_digest: Sha256Digest,
    active_content_digest: Sha256Digest,
    policy_generation: u64,
    decision_policy_generation: u64,
    decision_generation: u64,
    decision: PolicyDecisionFixture,
    max_capability_age_ms: u64,
    mandatory_capabilities: &'static [String],
}

impl PolicyFacts {
    fn coherent(plan: &AuthenticPlanEnvelopeV1) -> Self {
        let content_digest = digest(b"fixture policy content");
        Self {
            version: POLICY_VERSION,
            resolved_content_digest: content_digest,
            active_content_digest: content_digest,
            policy_generation: POLICY_GENERATION,
            decision_policy_generation: POLICY_GENERATION,
            decision_generation: POLICY_DECISION_GENERATION,
            decision: PolicyDecisionFixture::Allow(plan.plan_id()),
            max_capability_age_ms: CAPABILITY_MAX_AGE_MS,
            mandatory_capabilities: policy_mandatory(),
        }
    }

    fn into_view(self) -> PolicyViewV1<'static> {
        PolicyViewV1::Current(
            PolicyRecordV1::try_new(PolicyRecordInputV1 {
                version: self.version,
                resolved_content_digest: self.resolved_content_digest,
                active_content_digest: self.active_content_digest,
                policy_generation: self.policy_generation,
                decision_policy_generation: self.decision_policy_generation,
                decision_generation: self.decision_generation,
                decision: self.decision.into_decision(),
                max_capability_age_ms: self.max_capability_age_ms,
                mandatory_capabilities: self.mandatory_capabilities,
            })
            .expect("valid policy facts"),
        )
    }
}

fn policy_view_with(
    plan: &AuthenticPlanEnvelopeV1,
    change: impl FnOnce(&mut PolicyFacts),
) -> PolicyViewV1<'static> {
    let mut facts = PolicyFacts::coherent(plan);
    change(&mut facts);
    facts.into_view()
}

fn policy_fixture_with(change: impl FnOnce(&mut PolicyFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        input.policy = policy_view_with(plan, change);
    })
}

#[derive(Clone, Copy)]
struct CatalogueFacts {
    version: &'static str,
    resolved_content_digest: Sha256Digest,
    active_content_digest: Sha256Digest,
    catalogue_generation: u64,
    decision_catalogue_generation: u64,
    decision_generation: u64,
    decision_plan_id: Sha256Digest,
    schema_support: SupportStatusV1,
    intent_support: SupportStatusV1,
    mandatory_capabilities: &'static [String],
}

impl CatalogueFacts {
    fn coherent(plan: &AuthenticPlanEnvelopeV1) -> Self {
        let content_digest = digest(b"fixture catalogue content");
        Self {
            version: CATALOGUE_VERSION,
            resolved_content_digest: content_digest,
            active_content_digest: content_digest,
            catalogue_generation: CATALOGUE_GENERATION,
            decision_catalogue_generation: CATALOGUE_GENERATION,
            decision_generation: CATALOGUE_DECISION_GENERATION,
            decision_plan_id: plan.plan_id(),
            schema_support: SupportStatusV1::Supported,
            intent_support: SupportStatusV1::Supported,
            mandatory_capabilities: catalogue_mandatory(),
        }
    }

    fn into_view(self) -> CatalogueViewV1<'static> {
        CatalogueViewV1::Current(
            CatalogueRecordV1::try_new(CatalogueRecordInputV1 {
                version: self.version,
                resolved_content_digest: self.resolved_content_digest,
                active_content_digest: self.active_content_digest,
                catalogue_generation: self.catalogue_generation,
                decision_catalogue_generation: self.decision_catalogue_generation,
                decision_generation: self.decision_generation,
                decision: PlanDecisionEvidenceV1::new(PlanDecisionEvidenceInputV1 {
                    plan_id: self.decision_plan_id,
                    decision_digest: digest(b"fixture catalogue decision"),
                }),
                schema_support: self.schema_support,
                intent_support: self.intent_support,
                mandatory_capabilities: self.mandatory_capabilities,
            })
            .expect("valid catalogue facts"),
        )
    }
}

fn catalogue_fixture_with(change: impl FnOnce(&mut CatalogueFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        let mut facts = CatalogueFacts::coherent(plan);
        change(&mut facts);
        input.catalogue = facts.into_view();
    })
}

#[derive(Clone, Copy)]
struct CapabilityFacts {
    report_digest: Sha256Digest,
    observed_at_unix_ms: u64,
    boot_id: &'static str,
    instance_epoch: u64,
    report_generation: u64,
    report_host_driver_context_digest: Sha256Digest,
    current_host_driver_context_digest: Sha256Digest,
    available_capabilities: &'static [String],
}

impl CapabilityFacts {
    fn coherent(plan: &AuthenticPlanEnvelopeV1) -> Self {
        let claims = plan.eligibility_claims();
        let context_digest = digest(b"fixture host-driver context");
        Self {
            report_digest: claims.capability_report_digest(),
            observed_at_unix_ms: claims.capability_observed_at_unix_ms(),
            boot_id: BOOT_ID,
            instance_epoch: INSTANCE_EPOCH,
            report_generation: CAPABILITY_REPORT_GENERATION,
            report_host_driver_context_digest: context_digest,
            current_host_driver_context_digest: context_digest,
            available_capabilities: available_all(),
        }
    }

    fn into_view(self) -> CapabilityViewV1<'static> {
        CapabilityViewV1::Current(
            CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
                report_digest: self.report_digest,
                observed_at_unix_ms: self.observed_at_unix_ms,
                boot_id: self.boot_id,
                instance_epoch: self.instance_epoch,
                report_generation: self.report_generation,
                report_host_driver_context_digest: self.report_host_driver_context_digest,
                current_host_driver_context_digest: self.current_host_driver_context_digest,
                available_capabilities: self.available_capabilities,
            })
            .expect("valid capability facts"),
        )
    }
}

fn capability_fixture_with(change: impl FnOnce(&mut CapabilityFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        let mut facts = CapabilityFacts::coherent(plan);
        change(&mut facts);
        input.capabilities = facts.into_view();
    })
}

#[allow(clippy::too_many_lines)]
fn fixture_for_denial(denial: EligibilityDenialV1) -> EligibilityFixture {
    match denial {
        EligibilityDenialV1::ContextUnavailable => {
            fixture_with_context(EligibilityContextV1::Unavailable)
        }
        EligibilityDenialV1::ContextIncomplete => {
            fixture_with_context(EligibilityContextV1::Incomplete)
        }
        EligibilityDenialV1::ContextTorn => fixture_with_context(EligibilityContextV1::Torn),
        EligibilityDenialV1::ContextPlanMismatch => ready_fixture_with(|_, input| {
            input.bound_plan_id = digest(b"another plan");
        }),
        EligibilityDenialV1::SupervisorUnavailable => ready_fixture_with(|_, input| {
            input.supervisor = SupervisorViewV1::Unavailable;
        }),
        EligibilityDenialV1::SupervisorInconsistent => ready_fixture_with(|_, input| {
            input.supervisor = SupervisorViewV1::Inconsistent;
        }),
        EligibilityDenialV1::SupervisorNotOpen => ready_fixture_with(|_, input| {
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Paused,
                BOOT_ID,
                INSTANCE_EPOCH,
                FENCING_EPOCH,
            );
        }),
        EligibilityDenialV1::WallClockUnavailable => ready_fixture_with(|_, input| {
            input.time = time_view(
                WallClockViewV1::Unavailable,
                monotonic_sample(BOOT_ID, NOW_MONOTONIC_MS),
            );
        }),
        EligibilityDenialV1::WallClockRollbackSuspected => ready_fixture_with(|_, input| {
            input.time = time_view(
                WallClockViewV1::RollbackSuspected,
                monotonic_sample(BOOT_ID, NOW_MONOTONIC_MS),
            );
        }),
        EligibilityDenialV1::PlanNotYetValid => ready_fixture_with(|_, input| {
            input.time = healthy_time(ISSUED_AT_MS - 1, BOOT_ID, NOW_MONOTONIC_MS);
        }),
        EligibilityDenialV1::PlanExpired => ready_fixture_with(|_, input| {
            input.time = healthy_time(EXPIRES_AT_MS, BOOT_ID, NOW_MONOTONIC_MS);
        }),
        EligibilityDenialV1::BootMismatch => ready_fixture_with(|_, input| {
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Open,
                OTHER_BOOT_ID,
                INSTANCE_EPOCH,
                FENCING_EPOCH,
            );
        }),
        EligibilityDenialV1::MonotonicClockUnavailable => ready_fixture_with(|_, input| {
            input.time = time_view(
                WallClockViewV1::healthy(NOW_UTC_MS).expect("safe wall time"),
                MonotonicClockViewV1::Unavailable,
            );
        }),
        EligibilityDenialV1::MonotonicClockUnsuitable => ready_fixture_with(|_, input| {
            input.time = time_view(
                WallClockViewV1::healthy(NOW_UTC_MS).expect("safe wall time"),
                MonotonicClockViewV1::NotSuspendAware,
            );
        }),
        EligibilityDenialV1::MonotonicClockRegressed => ready_fixture_with(|_, input| {
            input.time = time_view(
                WallClockViewV1::healthy(NOW_UTC_MS).expect("safe wall time"),
                MonotonicClockViewV1::Regressed,
            );
        }),
        EligibilityDenialV1::PlanDeadlineUnavailable => ready_fixture_with(|_, input| {
            input.plan_deadline = PlanDeadlineViewV1::Unavailable;
        }),
        EligibilityDenialV1::PlanDeadlineInconsistent => ready_fixture_with(|_, input| {
            input.plan_deadline = PlanDeadlineViewV1::Inconsistent;
        }),
        EligibilityDenialV1::PlanDeadlineMismatch => ready_fixture_with(|_, input| {
            input.plan_deadline = plan_deadline(digest(b"another plan"), BOOT_ID, PLAN_DEADLINE_MS);
        }),
        EligibilityDenialV1::MonotonicDeadlineReached => ready_fixture_with(|_, input| {
            input.time = healthy_time(NOW_UTC_MS, BOOT_ID, PLAN_DEADLINE_MS);
        }),
        EligibilityDenialV1::InstanceEpochMismatch => ready_fixture_with(|_, input| {
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Open,
                BOOT_ID,
                INSTANCE_EPOCH + 1,
                FENCING_EPOCH,
            );
        }),
        EligibilityDenialV1::FencingEpochMismatch => ready_fixture_with(|_, input| {
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Open,
                BOOT_ID,
                INSTANCE_EPOCH,
                FENCING_EPOCH + 1,
            );
        }),

        EligibilityDenialV1::SignerTrustUnavailable => ready_fixture_with(|_, input| {
            input.signer = SignerTrustViewV1::Unavailable;
        }),
        EligibilityDenialV1::SignerTrustInconsistent => ready_fixture_with(|_, input| {
            input.signer = SignerTrustViewV1::Inconsistent;
        }),
        EligibilityDenialV1::SignerKeyMismatch => {
            signer_fixture_with(|facts| facts.key_id = OTHER_KEY_ID)
        }
        EligibilityDenialV1::SignerFingerprintMismatch => signer_fixture_with(|facts| {
            facts.public_key_fingerprint = digest(b"replacement key bytes");
        }),
        EligibilityDenialV1::SignerNotTrusted => ready_fixture_with(|_, input| {
            input.signer = SignerTrustViewV1::Unknown;
        }),
        EligibilityDenialV1::SignerGenerationRejectsPlan => signer_fixture_with(|facts| {
            facts.minimum_accepted_issued_at_unix_ms = ISSUED_AT_MS + 1;
        }),

        EligibilityDenialV1::WorkloadUnavailable => ready_fixture_with(|_, input| {
            input.workload = WorkloadIdentityViewV1::Unavailable;
        }),
        EligibilityDenialV1::WorkloadInconsistent => ready_fixture_with(|_, input| {
            input.workload = WorkloadIdentityViewV1::Inconsistent;
        }),
        EligibilityDenialV1::WorkloadIdMismatch => {
            workload_fixture_with(|facts| facts.workload_id = OTHER_WORKLOAD_ID)
        }
        EligibilityDenialV1::WorkloadNotTrusted => ready_fixture_with(|_, input| {
            input.workload = WorkloadIdentityViewV1::Unknown;
        }),
        EligibilityDenialV1::WorkloadBootMismatch => {
            workload_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID)
        }
        EligibilityDenialV1::WorkloadInstanceEpochMismatch => {
            workload_fixture_with(|facts| facts.instance_epoch = INSTANCE_EPOCH + 1)
        }
        EligibilityDenialV1::WorkloadNotYetValid => {
            workload_fixture_with(|facts| facts.not_before_utc_unix_ms = NOW_UTC_MS + 1)
        }
        EligibilityDenialV1::WorkloadExpired => {
            workload_fixture_with(|facts| facts.expires_at_utc_unix_ms = NOW_UTC_MS)
        }
        EligibilityDenialV1::WorkloadMonotonicExpired => {
            workload_fixture_with(|facts| facts.deadline_monotonic_ms = NOW_MONOTONIC_MS)
        }

        EligibilityDenialV1::LeaseUnavailable => ready_fixture_with(|_, input| {
            input.lease = LeaseResolutionV1::Unavailable;
        }),
        EligibilityDenialV1::LeaseInconsistent => ready_fixture_with(|_, input| {
            input.lease = LeaseResolutionV1::Inconsistent;
        }),
        EligibilityDenialV1::LeaseNotFound => ready_fixture_with(|_, input| {
            input.lease = LeaseResolutionV1::NotFound;
        }),
        EligibilityDenialV1::LeaseAmbiguous => ready_fixture_with(|_, input| {
            input.lease = LeaseResolutionV1::Multiple;
        }),
        EligibilityDenialV1::LeaseDigestMismatch => {
            lease_fixture_with(|facts| facts.lease_digest = digest(b"another lease"))
        }
        EligibilityDenialV1::LeaseNotActive => {
            lease_fixture_with(|facts| facts.state = LeaseStateV1::Revoked)
        }
        EligibilityDenialV1::LeaseTaskMismatch => {
            lease_fixture_with(|facts| facts.task_id = OTHER_TASK_ID)
        }
        EligibilityDenialV1::LeaseWorkloadMismatch => {
            lease_fixture_with(|facts| facts.workload_id = OTHER_WORKLOAD_ID)
        }
        EligibilityDenialV1::LeaseBootMismatch => {
            lease_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID)
        }
        EligibilityDenialV1::LeaseInstanceEpochMismatch => {
            lease_fixture_with(|facts| facts.instance_epoch = INSTANCE_EPOCH + 1)
        }
        EligibilityDenialV1::LeaseSourceMismatch => lease_fixture_with(|facts| {
            facts.request_source_kind = RequestSourceKindV1::RegisteredTrigger;
        }),
        EligibilityDenialV1::LeaseNotYetValid => {
            lease_fixture_with(|facts| facts.not_before_utc_unix_ms = NOW_UTC_MS + 1)
        }
        EligibilityDenialV1::LeaseExpired => {
            lease_fixture_with(|facts| facts.expires_at_utc_unix_ms = NOW_UTC_MS)
        }
        EligibilityDenialV1::LeaseMonotonicExpired => {
            lease_fixture_with(|facts| facts.deadline_monotonic_ms = NOW_MONOTONIC_MS)
        }
        EligibilityDenialV1::LeaseDecisionUnavailable => {
            lease_fixture_with(|facts| facts.decision = LeaseDecisionFixture::Unavailable)
        }
        EligibilityDenialV1::LeaseDecisionInconsistent => {
            lease_fixture_with(|facts| facts.decision = LeaseDecisionFixture::Inconsistent)
        }
        EligibilityDenialV1::LeaseDecisionPlanMismatch => {
            lease_fixture_with(|facts| facts.decision = LeaseDecisionFixture::PlanMismatch)
        }
        EligibilityDenialV1::LeaseIntentDenied => {
            lease_fixture_with(|facts| facts.decision = LeaseDecisionFixture::IntentDenied)
        }
        EligibilityDenialV1::LeaseScopeWidened => {
            lease_fixture_with(|facts| facts.decision = LeaseDecisionFixture::ScopeWidened)
        }
        EligibilityDenialV1::LeaseBudgetWidened => {
            lease_fixture_with(|facts| facts.decision = LeaseDecisionFixture::BudgetWidened)
        }
        EligibilityDenialV1::LeasePriceTableMismatch => lease_fixture_with(|facts| {
            facts.decision = LeaseDecisionFixture::PriceTableMismatch;
        }),
        EligibilityDenialV1::LeaseReservationMismatch => lease_fixture_with(|facts| {
            facts.decision = LeaseDecisionFixture::ReservationMismatch;
        }),

        EligibilityDenialV1::AuthorizationUnavailable => ready_fixture_with(|_, input| {
            input.authorization = AuthorizationViewV1::Unavailable;
        }),
        EligibilityDenialV1::AuthorizationInconsistent => ready_fixture_with(|_, input| {
            input.authorization = AuthorizationViewV1::Inconsistent;
        }),
        EligibilityDenialV1::AuthorizationNotGranted => {
            authorization_fixture_with(|facts| facts.status = AuthorizationStatusV1::Denied)
        }
        EligibilityDenialV1::AuthorizationPlanMismatch => {
            authorization_fixture_with(|facts| facts.plan_id = digest(b"another plan"))
        }
        EligibilityDenialV1::AuthorizationOperationMismatch => {
            authorization_fixture_with(|facts| facts.operation_id = OTHER_OPERATION_ID)
        }
        EligibilityDenialV1::AuthorizationRiskMismatch => {
            authorization_fixture_with(|facts| facts.risk_level = RiskLevelV1::L2)
        }
        EligibilityDenialV1::AuthorizationNonceMismatch => authorization_fixture_with(|facts| {
            facts.nonce = Nonce128::from_bytes([0x22; 16]);
        }),
        EligibilityDenialV1::AuthorizationBootMismatch => {
            authorization_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID)
        }
        EligibilityDenialV1::AuthorizationNotYetValid => {
            authorization_fixture_with(|facts| facts.not_before_utc_unix_ms = NOW_UTC_MS + 1)
        }
        EligibilityDenialV1::AuthorizationExpired => {
            authorization_fixture_with(|facts| facts.expires_at_utc_unix_ms = NOW_UTC_MS)
        }
        EligibilityDenialV1::AuthorizationMonotonicExpired => {
            authorization_fixture_with(|facts| facts.deadline_monotonic_ms = NOW_MONOTONIC_MS)
        }

        EligibilityDenialV1::PolicyUnavailable => ready_fixture_with(|_, input| {
            input.policy = PolicyViewV1::Unavailable;
        }),
        EligibilityDenialV1::PolicyInconsistent => ready_fixture_with(|_, input| {
            input.policy = PolicyViewV1::Inconsistent;
        }),
        EligibilityDenialV1::PolicyIdentityMismatch => ready_fixture_with(|_, input| {
            input.policy = PolicyViewV1::Unknown;
        }),
        EligibilityDenialV1::PolicyContentMismatch => ready_fixture_with(|_, input| {
            input.policy = PolicyViewV1::IdentifierReused;
        }),
        EligibilityDenialV1::PolicyGenerationMismatch => policy_fixture_with(|facts| {
            facts.decision_policy_generation = POLICY_GENERATION + 1;
        }),
        EligibilityDenialV1::PolicyDecisionPlanMismatch => policy_fixture_with(|facts| {
            facts.decision = PolicyDecisionFixture::Allow(digest(b"another plan"));
        }),
        EligibilityDenialV1::PolicyDenied => policy_fixture_with(|facts| {
            let plan_id = match facts.decision {
                PolicyDecisionFixture::Allow(plan_id) | PolicyDecisionFixture::Deny(plan_id) => {
                    plan_id
                }
            };
            facts.decision = PolicyDecisionFixture::Deny(plan_id);
        }),

        EligibilityDenialV1::CatalogueUnavailable => ready_fixture_with(|_, input| {
            input.catalogue = CatalogueViewV1::Unavailable;
        }),
        EligibilityDenialV1::CatalogueInconsistent => ready_fixture_with(|_, input| {
            input.catalogue = CatalogueViewV1::Inconsistent;
        }),
        EligibilityDenialV1::CatalogueIdentityMismatch => ready_fixture_with(|_, input| {
            input.catalogue = CatalogueViewV1::Unknown;
        }),
        EligibilityDenialV1::CatalogueContentMismatch => ready_fixture_with(|_, input| {
            input.catalogue = CatalogueViewV1::IdentifierReused;
        }),
        EligibilityDenialV1::CatalogueGenerationMismatch => catalogue_fixture_with(|facts| {
            facts.decision_catalogue_generation = CATALOGUE_GENERATION + 1;
        }),
        EligibilityDenialV1::CatalogueDecisionPlanMismatch => catalogue_fixture_with(|facts| {
            facts.decision_plan_id = digest(b"another plan");
        }),
        EligibilityDenialV1::CatalogueSchemaUnsupported => catalogue_fixture_with(|facts| {
            facts.schema_support = SupportStatusV1::Unsupported;
        }),
        EligibilityDenialV1::CatalogueIntentUnsupported => catalogue_fixture_with(|facts| {
            facts.intent_support = SupportStatusV1::Unsupported;
        }),

        EligibilityDenialV1::CapabilityUnavailable => ready_fixture_with(|_, input| {
            input.capabilities = CapabilityViewV1::Unavailable;
        }),
        EligibilityDenialV1::CapabilityInconsistent => ready_fixture_with(|_, input| {
            input.capabilities = CapabilityViewV1::Inconsistent;
        }),
        EligibilityDenialV1::CapabilityNotFound => ready_fixture_with(|_, input| {
            input.capabilities = CapabilityViewV1::Unknown;
        }),
        EligibilityDenialV1::CapabilityDigestMismatch => capability_fixture_with(|facts| {
            facts.report_digest = digest(b"another capability report");
        }),
        EligibilityDenialV1::CapabilityObservationMismatch => {
            capability_fixture_with(|facts| facts.observed_at_unix_ms += 1)
        }
        EligibilityDenialV1::CapabilityBootMismatch => {
            capability_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID)
        }
        EligibilityDenialV1::CapabilityInstanceEpochMismatch => {
            capability_fixture_with(|facts| facts.instance_epoch = INSTANCE_EPOCH + 1)
        }
        EligibilityDenialV1::CapabilityContextMismatch => capability_fixture_with(|facts| {
            facts.current_host_driver_context_digest = digest(b"new host-driver context");
        }),
        EligibilityDenialV1::CapabilityStale => policy_fixture_with(|facts| {
            let exact_age = NOW_UTC_MS - (ISSUED_AT_MS - 1_000);
            facts.max_capability_age_ms = exact_age - 1;
        }),
        EligibilityDenialV1::RequiredCapabilityMissing => capability_fixture_with(|facts| {
            facts.available_capabilities = available_without_atomic_replace();
        }),
        EligibilityDenialV1::MandatoryCapabilityMissing => policy_fixture_with(|facts| {
            facts.mandatory_capabilities = extra_policy_mandatory();
        }),

        EligibilityDenialV1::ReplayAlreadyClaimed
        | EligibilityDenialV1::ReplayBindingConflict
        | EligibilityDenialV1::ReplayUnavailable
        | EligibilityDenialV1::ReplayAmbiguous
        | EligibilityDenialV1::ReplayReceiptBindingMismatch => {
            panic!("replay denials are claimant scenarios, not context fixtures")
        }
    }
}
