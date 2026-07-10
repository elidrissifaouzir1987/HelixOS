#![allow(dead_code)]
// The public contract deliberately returns ownership of the authentic plan on failure.
#![allow(clippy::result_large_err)]

use ed25519_dalek::{Signer as _, SigningKey};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AtomicityV1, AuthenticPlanEnvelopeV1, BudgetInputV1,
    ContractError, Ed25519KeyResolver, Ed25519Signer, FilePreconditionInputV1, Nonce128,
    PlanInputV1, RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, ResourceRefV1,
    Result as ContractResult, RiskLevelV1, Sha256Digest,
};
use helix_plan_eligibility::{
    evaluate_and_claim_plan_v1, ActiveLeaseInputV1, ActiveLeaseRecordV1, AuthorizationInputV1,
    AuthorizationRecordV1, AuthorizationStatusV1, AuthorizationViewV1, CapabilityRecordInputV1,
    CapabilityRecordV1, CapabilityViewV1, CatalogueRecordInputV1, CatalogueRecordV1,
    CatalogueViewV1, EligibilityContextV1, EligibilityDenialV1, EligibilityFailureV1,
    EligiblePlanV1, LeaseAllowanceInputV1, LeaseAllowanceV1, LeaseAuthorityDecisionV1,
    LeaseResolutionV1, LeaseStateV1, MonotonicClockViewV1, MonotonicSampleV1, PlanDeadlineInputV1,
    PlanDeadlineRecordV1, PlanDeadlineViewV1, PlanDecisionEvidenceInputV1, PlanDecisionEvidenceV1,
    PolicyDecisionV1, PolicyRecordInputV1, PolicyRecordV1, PolicyViewV1,
    ReadyEligibilityContextInputV1, ReadyEligibilityContextV1, ReplayBindingV1,
    ReplayClaimOutcomeV1, ReplayClaimReceiptV1, ReplayClaimantV1, SignerTrustInputV1,
    SignerTrustRecordV1, SignerTrustViewV1, SupervisorAdmissionStateV1, SupervisorInputV1,
    SupervisorRecordV1, SupervisorViewV1, SupportStatusV1, TimeViewInputV1, TimeViewV1,
    WallClockViewV1, WorkloadIdentityInputV1, WorkloadIdentityRecordV1, WorkloadIdentityViewV1,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

pub const ISSUED_AT_MS: u64 = 1_750_000_000_000;
pub const EXPIRES_AT_MS: u64 = ISSUED_AT_MS + 120_000;
pub const NOW_UTC_MS: u64 = ISSUED_AT_MS + 10_000;
pub const NOW_MONOTONIC_MS: u64 = 50_000;
pub const PLAN_DEADLINE_MS: u64 = 100_000;
pub const CAPABILITY_MAX_AGE_MS: u64 = 200_000;

pub const KEY_ID: &str = "core-signing-key:fixture-1";
pub const OPERATION_ID: &str = "operation:00000000-0000-4000-8000-000000000001";
pub const TASK_ID: &str = "task:fixture-1";
pub const WORKLOAD_ID: &str = "workload:agent-vm-1";
pub const BOOT_ID: &str = "boot:fixture-1";
pub const OTHER_BOOT_ID: &str = "boot:fixture-2";
pub const POLICY_VERSION: &str = "policy:1";
pub const CATALOGUE_VERSION: &str = "catalog:1";

pub const INSTANCE_EPOCH: u64 = 1;
pub const FENCING_EPOCH: u64 = 9;
pub const CAPTURE_GENERATION: u64 = 10;
pub const CLOCK_GENERATION: u64 = 11;
pub const PLAN_DEADLINE_GENERATION: u64 = 12;
pub const SUPERVISOR_GENERATION: u64 = 13;
pub const TRUST_GENERATION: u64 = 14;
pub const WORKLOAD_GENERATION: u64 = 15;
pub const LEASE_GENERATION: u64 = 16;
pub const AUTHORIZATION_GENERATION: u64 = 17;
pub const POLICY_GENERATION: u64 = 18;
pub const POLICY_DECISION_GENERATION: u64 = 19;
pub const CATALOGUE_GENERATION: u64 = 20;
pub const CATALOGUE_DECISION_GENERATION: u64 = 21;
pub const CAPABILITY_REPORT_GENERATION: u64 = 22;
pub const CLAIMANT_GENERATION: u64 = 23;

#[derive(Debug)]
pub struct TestSigner {
    key_id: &'static str,
    key: SigningKey,
}

impl TestSigner {
    pub fn fixed() -> Self {
        Self {
            key_id: KEY_ID,
            key: SigningKey::from_bytes(&[7_u8; 32]),
        }
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl Ed25519Signer for TestSigner {
    fn key_id(&self) -> &str {
        self.key_id
    }

    fn sign_ed25519(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        Ok(self.key.sign(message).to_bytes())
    }
}

#[derive(Debug)]
pub struct TestResolver {
    key_id: &'static str,
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for TestResolver {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == self.key_id {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

pub fn digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::digest(value)
}

pub fn authentic_plan() -> AuthenticPlanEnvelopeV1 {
    let signer = TestSigner::fixed();
    let resolver = TestResolver {
        key_id: KEY_ID,
        public_key: signer.verifying_key_bytes(),
    };
    let signed = sign_plan_v1(sample_plan_input(), &signer).expect("fixture plan signs");
    let wire = signed
        .to_canonical_json()
        .expect("fixture plan canonicalizes");
    decode_and_verify_plan(&wire, &resolver).expect("fixture plan authenticates")
}

pub fn sample_plan_input() -> PlanInputV1 {
    PlanInputV1 {
        operation_id: OPERATION_ID.to_owned(),
        task_id: TASK_ID.to_owned(),
        workload_id: WORKLOAD_ID.to_owned(),
        boot_id: BOOT_ID.to_owned(),
        task_lease_digest: digest(b"fixture task lease"),
        request_source_kind: RequestSourceKindV1::HumanRequestGrant,
        request_source_digest: digest(b"fixture human request grant"),
        catalog_version: CATALOGUE_VERSION.to_owned(),
        policy_version: POLICY_VERSION.to_owned(),
        risk_level: RiskLevelV1::L1,
        target: ResourceRefV1::new("vault-main", ["Projects", "HelixOS", "Decision.md"])
            .expect("valid fixture resource"),
        precondition: FilePreconditionInputV1 {
            volume_id: "volume:fixture-apfs".to_owned(),
            file_id: "file:00000042".to_owned(),
            content_sha256: digest(b"before\n"),
            byte_length: 7,
        },
        replacement_bytes: b"after\n".to_vec(),
        replacement_media_type: "text/markdown;charset=utf-8".to_owned(),
        recovery: RecoveryInputV1 {
            class: RecoveryClassV1::Compensation,
            atomicity: AtomicityV1::AtomicReplace,
            reserved_bytes: 4096,
        },
        capability_report_digest: digest(b"fixture capability report"),
        capability_observed_at_unix_ms: ISSUED_AT_MS - 1_000,
        required_capabilities: vec![
            "filesystem.verify-by-handle".to_owned(),
            "filesystem.atomic-replace".to_owned(),
        ],
        budget: BudgetInputV1 {
            reservation_id: "budget:fixture-1".to_owned(),
            currency_code: "EUR".to_owned(),
            price_table_id: "price-table:fixture-1".to_owned(),
            max_cost_micro_units: 0,
            action_limit: 1,
            egress_bytes_limit: 0,
        },
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
        nonce: Nonce128::from_bytes([0x11; 16]),
        instance_epoch: INSTANCE_EPOCH,
        fencing_epoch: FENCING_EPOCH,
    }
}

fn policy_capabilities() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES
        .get_or_init(|| vec!["filesystem.atomic-replace".to_owned()])
        .as_slice()
}

fn catalogue_capabilities() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES
        .get_or_init(|| vec!["filesystem.verify-by-handle".to_owned()])
        .as_slice()
}

fn available_capabilities() -> &'static [String] {
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

pub fn monotonic_sample(boot_id: &'static str, now_ms: u64) -> MonotonicClockViewV1<'static> {
    MonotonicClockViewV1::Healthy(
        MonotonicSampleV1::try_new(boot_id, now_ms).expect("valid monotonic fixture"),
    )
}

pub fn time_view(
    wall: WallClockViewV1,
    monotonic: MonotonicClockViewV1<'static>,
) -> TimeViewV1<'static> {
    TimeViewV1::try_new(TimeViewInputV1 {
        clock_generation: CLOCK_GENERATION,
        wall,
        monotonic,
    })
    .expect("valid time fixture")
}

pub fn healthy_time(
    now_utc_ms: u64,
    boot_id: &'static str,
    now_monotonic_ms: u64,
) -> TimeViewV1<'static> {
    time_view(
        WallClockViewV1::healthy(now_utc_ms).expect("safe wall time"),
        monotonic_sample(boot_id, now_monotonic_ms),
    )
}

pub fn plan_deadline(
    plan_id: Sha256Digest,
    boot_id: &'static str,
    deadline_monotonic_ms: u64,
) -> PlanDeadlineViewV1<'static> {
    PlanDeadlineViewV1::Current(
        PlanDeadlineRecordV1::try_new(PlanDeadlineInputV1 {
            plan_id,
            boot_id,
            deadline_monotonic_ms,
            deadline_generation: PLAN_DEADLINE_GENERATION,
        })
        .expect("valid plan-deadline fixture"),
    )
}

pub fn supervisor(
    state: SupervisorAdmissionStateV1,
    boot_id: &'static str,
    instance_epoch: u64,
    fencing_epoch: u64,
) -> SupervisorViewV1<'static> {
    SupervisorViewV1::Current(
        SupervisorRecordV1::try_new(SupervisorInputV1 {
            admission_state: state,
            boot_id,
            instance_epoch,
            fencing_epoch,
            supervisor_generation: SUPERVISOR_GENERATION,
        })
        .expect("valid supervisor fixture"),
    )
}

pub fn coherent_ready_input(
    plan: &AuthenticPlanEnvelopeV1,
) -> ReadyEligibilityContextInputV1<'static> {
    let claims = plan.eligibility_claims();
    let plan_id = claims.plan_id();
    let policy_content_digest = digest(b"fixture policy content");
    let catalogue_content_digest = digest(b"fixture catalogue content");
    let host_driver_context_digest = digest(b"fixture host-driver context");
    let lease_decision_digest = digest(b"fixture lease decision");
    let policy_decision_digest = digest(b"fixture policy decision");
    let catalogue_decision_digest = digest(b"fixture catalogue decision");

    ReadyEligibilityContextInputV1 {
        bound_plan_id: plan_id,
        capture_generation: CAPTURE_GENERATION,
        time: healthy_time(NOW_UTC_MS, BOOT_ID, NOW_MONOTONIC_MS),
        plan_deadline: plan_deadline(plan_id, BOOT_ID, PLAN_DEADLINE_MS),
        supervisor: supervisor(
            SupervisorAdmissionStateV1::Open,
            BOOT_ID,
            INSTANCE_EPOCH,
            FENCING_EPOCH,
        ),
        signer: SignerTrustViewV1::Trusted(
            SignerTrustRecordV1::try_new(SignerTrustInputV1 {
                key_id: KEY_ID,
                public_key_fingerprint: claims.verified_key_fingerprint(),
                trust_generation: TRUST_GENERATION,
                minimum_accepted_issued_at_unix_ms: ISSUED_AT_MS - 1,
            })
            .expect("valid signer fixture"),
        ),
        workload: WorkloadIdentityViewV1::Trusted(
            WorkloadIdentityRecordV1::try_new(WorkloadIdentityInputV1 {
                workload_id: WORKLOAD_ID,
                evidence_digest: digest(b"fixture workload evidence"),
                identity_generation: WORKLOAD_GENERATION,
                boot_id: BOOT_ID,
                instance_epoch: INSTANCE_EPOCH,
                not_before_utc_unix_ms: ISSUED_AT_MS - 10_000,
                expires_at_utc_unix_ms: ISSUED_AT_MS + 210_000,
                deadline_monotonic_ms: 130_000,
            })
            .expect("valid workload fixture"),
        ),
        lease: LeaseResolutionV1::ExactlyOne(
            ActiveLeaseRecordV1::try_new(ActiveLeaseInputV1 {
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
                decision: LeaseAuthorityDecisionV1::Allows(LeaseAllowanceV1::new(
                    LeaseAllowanceInputV1 {
                        plan_id,
                        decision_digest: lease_decision_digest,
                    },
                )),
            })
            .expect("valid lease fixture"),
        ),
        authorization: AuthorizationViewV1::Current(
            AuthorizationRecordV1::try_new(AuthorizationInputV1 {
                status: AuthorizationStatusV1::Granted,
                plan_id,
                operation_id: OPERATION_ID,
                risk_level: RiskLevelV1::L1,
                nonce: Nonce128::from_bytes([0x11; 16]),
                evidence_digest: digest(b"fixture authorization evidence"),
                authorization_generation: AUTHORIZATION_GENERATION,
                boot_id: BOOT_ID,
                not_before_utc_unix_ms: ISSUED_AT_MS - 10_000,
                expires_at_utc_unix_ms: ISSUED_AT_MS + 190_000,
                deadline_monotonic_ms: 110_000,
            })
            .expect("valid authorization fixture"),
        ),
        policy: PolicyViewV1::Current(
            PolicyRecordV1::try_new(PolicyRecordInputV1 {
                version: POLICY_VERSION,
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
                mandatory_capabilities: policy_capabilities(),
            })
            .expect("valid policy fixture"),
        ),
        catalogue: CatalogueViewV1::Current(
            CatalogueRecordV1::try_new(CatalogueRecordInputV1 {
                version: CATALOGUE_VERSION,
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
                mandatory_capabilities: catalogue_capabilities(),
            })
            .expect("valid catalogue fixture"),
        ),
        capabilities: CapabilityViewV1::Current(
            CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
                report_digest: claims.capability_report_digest(),
                observed_at_unix_ms: claims.capability_observed_at_unix_ms(),
                boot_id: BOOT_ID,
                instance_epoch: INSTANCE_EPOCH,
                report_generation: CAPABILITY_REPORT_GENERATION,
                report_host_driver_context_digest: host_driver_context_digest,
                current_host_driver_context_digest: host_driver_context_digest,
                available_capabilities: available_capabilities(),
            })
            .expect("valid capability fixture"),
        ),
    }
}

pub struct EligibilityFixture {
    pub plan: AuthenticPlanEnvelopeV1,
    pub context: EligibilityContextV1<'static>,
}

impl EligibilityFixture {
    pub fn evaluate<C: ReplayClaimantV1 + ?Sized>(
        self,
        claimant: &C,
    ) -> Result<EligiblePlanV1, EligibilityFailureV1> {
        evaluate_and_claim_plan_v1(self.plan, self.context, claimant)
    }
}

pub fn coherent_fixture() -> EligibilityFixture {
    ready_fixture_with(|_, _| {})
}

pub fn ready_fixture_with(
    override_input: impl FnOnce(&AuthenticPlanEnvelopeV1, &mut ReadyEligibilityContextInputV1<'static>),
) -> EligibilityFixture {
    let plan = authentic_plan();
    let mut input = coherent_ready_input(&plan);
    override_input(&plan, &mut input);
    let ready = ReadyEligibilityContextV1::try_new(input).expect("valid ready fixture");
    EligibilityFixture {
        plan,
        context: EligibilityContextV1::Ready(ready),
    }
}

pub fn fixture_with_context(context: EligibilityContextV1<'static>) -> EligibilityFixture {
    EligibilityFixture {
        plan: authentic_plan(),
        context,
    }
}

#[derive(Debug, Default)]
pub struct ClaimantProbe {
    calls: AtomicUsize,
    observed_binding_digest: Mutex<Option<Sha256Digest>>,
    observed_claim_deadline_monotonic_ms: Mutex<Option<u64>>,
}

impl ClaimantProbe {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn observed_binding_digest(&self) -> Option<Sha256Digest> {
        *self
            .observed_binding_digest
            .lock()
            .expect("claimant probe mutex is not poisoned")
    }

    pub fn observed_claim_deadline_monotonic_ms(&self) -> Option<u64> {
        *self
            .observed_claim_deadline_monotonic_ms
            .lock()
            .expect("claimant probe mutex is not poisoned")
    }
}

impl ReplayClaimantV1 for ClaimantProbe {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1 {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self
            .observed_binding_digest
            .lock()
            .expect("claimant probe mutex is not poisoned") = Some(binding.binding_digest());
        *self
            .observed_claim_deadline_monotonic_ms
            .lock()
            .expect("claimant probe mutex is not poisoned") =
            Some(binding.claim_deadline_monotonic_ms());
        ReplayClaimOutcomeV1::Claimed(
            ReplayClaimReceiptV1::try_new(
                digest(b"fixture replay claim"),
                CLAIMANT_GENERATION,
                binding.binding_digest(),
            )
            .expect("valid matching replay receipt"),
        )
    }
}

pub fn assert_preclaim_denial(fixture: EligibilityFixture, expected: EligibilityDenialV1) {
    let claimant = ClaimantProbe::default();
    let failure = fixture
        .evaluate(&claimant)
        .expect_err("single-fault fixture must be denied");
    assert_eq!(failure.denial(), expected);
    assert_eq!(failure.denial().code(), expected.code());
    assert_eq!(claimant.calls(), 0, "pre-claim denial reached claimant");
    assert_eq!(claimant.observed_binding_digest(), None);
    assert_eq!(claimant.observed_claim_deadline_monotonic_ms(), None);
}
