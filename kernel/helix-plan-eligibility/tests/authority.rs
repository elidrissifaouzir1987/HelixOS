mod common;

use common::*;
use helix_contracts::{
    AuthenticPlanEnvelopeV1, Nonce128, RequestSourceKindV1, RiskLevelV1, Sha256Digest,
};
use helix_plan_eligibility::{
    ActiveLeaseInputV1, ActiveLeaseRecordV1, AuthorizationInputV1, AuthorizationRecordV1,
    AuthorizationStatusV1, AuthorizationViewV1, EligibilityDenialV1, LeaseAllowanceInputV1,
    LeaseAllowanceV1, LeaseAuthorityDecisionV1, LeaseResolutionV1, LeaseStateV1, PolicyViewV1,
    SignerTrustInputV1, SignerTrustRecordV1, SignerTrustViewV1, WorkloadIdentityInputV1,
    WorkloadIdentityRecordV1, WorkloadIdentityViewV1,
};

const OTHER_KEY_ID: &str = "core-signing-key:fixture-2";
const OTHER_TASK_ID: &str = "task:fixture-2";
const OTHER_WORKLOAD_ID: &str = "workload:agent-vm-2";
const OTHER_OPERATION_ID: &str = "operation:00000000-0000-4000-8000-000000000002";

fn assert_denied(fixture: EligibilityFixture, expected: EligibilityDenialV1) {
    let claimant = ClaimantProbe::default();
    let failure = fixture
        .evaluate(&claimant)
        .expect_err("single-fault authority fixture must be denied");
    assert_eq!(claimant.calls(), 0, "pre-claim denial reached claimant");
    assert_eq!(claimant.observed_binding_digest(), None);
    assert_eq!(failure.denial(), expected);
    assert_eq!(failure.denial().code(), expected.code());
}

fn assert_eligible(fixture: EligibilityFixture) {
    let claimant = ClaimantProbe::default();
    let _eligible = fixture
        .evaluate(&claimant)
        .expect("exact valid boundary must remain eligible");
    assert_eq!(claimant.calls(), 1);
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

#[test]
fn signer_status_key_fingerprint_and_generation_are_exact() {
    for (view, expected) in [
        (
            SignerTrustViewV1::Unavailable,
            EligibilityDenialV1::SignerTrustUnavailable,
        ),
        (
            SignerTrustViewV1::Inconsistent,
            EligibilityDenialV1::SignerTrustInconsistent,
        ),
        (
            SignerTrustViewV1::Unknown,
            EligibilityDenialV1::SignerNotTrusted,
        ),
        (
            SignerTrustViewV1::Revoked,
            EligibilityDenialV1::SignerNotTrusted,
        ),
    ] {
        assert_denied(ready_fixture_with(|_, input| input.signer = view), expected);
    }

    assert_denied(
        signer_fixture_with(|facts| {
            facts.key_id = OTHER_KEY_ID;
            facts.public_key_fingerprint = digest(b"also wrong");
        }),
        EligibilityDenialV1::SignerKeyMismatch,
    );
    assert_denied(
        signer_fixture_with(|facts| {
            facts.public_key_fingerprint = digest(b"replacement key bytes");
            facts.minimum_accepted_issued_at_unix_ms = ISSUED_AT_MS + 1;
        }),
        EligibilityDenialV1::SignerFingerprintMismatch,
    );
    assert_denied(
        signer_fixture_with(|facts| {
            facts.minimum_accepted_issued_at_unix_ms = ISSUED_AT_MS + 1;
        }),
        EligibilityDenialV1::SignerGenerationRejectsPlan,
    );
    assert_eligible(signer_fixture_with(|facts| {
        facts.minimum_accepted_issued_at_unix_ms = ISSUED_AT_MS;
    }));
}

#[test]
fn workload_status_bindings_and_half_open_windows_are_exact() {
    for (view, expected) in [
        (
            WorkloadIdentityViewV1::Unavailable,
            EligibilityDenialV1::WorkloadUnavailable,
        ),
        (
            WorkloadIdentityViewV1::Inconsistent,
            EligibilityDenialV1::WorkloadInconsistent,
        ),
        (
            WorkloadIdentityViewV1::Unknown,
            EligibilityDenialV1::WorkloadNotTrusted,
        ),
        (
            WorkloadIdentityViewV1::Revoked,
            EligibilityDenialV1::WorkloadNotTrusted,
        ),
    ] {
        assert_denied(
            ready_fixture_with(|_, input| input.workload = view),
            expected,
        );
    }

    for (fixture, expected) in [
        (
            workload_fixture_with(|facts| facts.workload_id = OTHER_WORKLOAD_ID),
            EligibilityDenialV1::WorkloadIdMismatch,
        ),
        (
            workload_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID),
            EligibilityDenialV1::WorkloadBootMismatch,
        ),
        (
            workload_fixture_with(|facts| facts.instance_epoch = INSTANCE_EPOCH + 1),
            EligibilityDenialV1::WorkloadInstanceEpochMismatch,
        ),
        (
            workload_fixture_with(|facts| {
                facts.not_before_utc_unix_ms = NOW_UTC_MS + 1;
                facts.expires_at_utc_unix_ms = NOW_UTC_MS + 2;
            }),
            EligibilityDenialV1::WorkloadNotYetValid,
        ),
        (
            workload_fixture_with(|facts| {
                facts.not_before_utc_unix_ms = NOW_UTC_MS - 1;
                facts.expires_at_utc_unix_ms = NOW_UTC_MS;
            }),
            EligibilityDenialV1::WorkloadExpired,
        ),
        (
            workload_fixture_with(|facts| {
                facts.deadline_monotonic_ms = NOW_MONOTONIC_MS;
            }),
            EligibilityDenialV1::WorkloadMonotonicExpired,
        ),
    ] {
        assert_denied(fixture, expected);
    }

    assert_eligible(workload_fixture_with(|facts| {
        facts.not_before_utc_unix_ms = NOW_UTC_MS;
        facts.expires_at_utc_unix_ms = NOW_UTC_MS + 1;
        facts.deadline_monotonic_ms = NOW_MONOTONIC_MS + 1;
    }));
}

#[test]
fn lease_resolution_identity_source_and_windows_are_exact() {
    for (view, expected) in [
        (
            LeaseResolutionV1::Unavailable,
            EligibilityDenialV1::LeaseUnavailable,
        ),
        (
            LeaseResolutionV1::Inconsistent,
            EligibilityDenialV1::LeaseInconsistent,
        ),
        (
            LeaseResolutionV1::NotFound,
            EligibilityDenialV1::LeaseNotFound,
        ),
        (
            LeaseResolutionV1::Multiple,
            EligibilityDenialV1::LeaseAmbiguous,
        ),
    ] {
        assert_denied(ready_fixture_with(|_, input| input.lease = view), expected);
    }

    for (fixture, expected) in [
        (
            lease_fixture_with(|facts| facts.lease_digest = digest(b"another lease")),
            EligibilityDenialV1::LeaseDigestMismatch,
        ),
        (
            lease_fixture_with(|facts| facts.state = LeaseStateV1::Revoked),
            EligibilityDenialV1::LeaseNotActive,
        ),
        (
            lease_fixture_with(|facts| facts.state = LeaseStateV1::Exhausted),
            EligibilityDenialV1::LeaseNotActive,
        ),
        (
            lease_fixture_with(|facts| facts.task_id = OTHER_TASK_ID),
            EligibilityDenialV1::LeaseTaskMismatch,
        ),
        (
            lease_fixture_with(|facts| facts.workload_id = OTHER_WORKLOAD_ID),
            EligibilityDenialV1::LeaseWorkloadMismatch,
        ),
        (
            lease_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID),
            EligibilityDenialV1::LeaseBootMismatch,
        ),
        (
            lease_fixture_with(|facts| facts.instance_epoch = INSTANCE_EPOCH + 1),
            EligibilityDenialV1::LeaseInstanceEpochMismatch,
        ),
        (
            lease_fixture_with(|facts| {
                facts.request_source_kind = RequestSourceKindV1::RegisteredTrigger;
            }),
            EligibilityDenialV1::LeaseSourceMismatch,
        ),
        (
            lease_fixture_with(|facts| {
                facts.request_source_digest = digest(b"another request source");
            }),
            EligibilityDenialV1::LeaseSourceMismatch,
        ),
        (
            lease_fixture_with(|facts| {
                facts.not_before_utc_unix_ms = NOW_UTC_MS + 1;
                facts.expires_at_utc_unix_ms = NOW_UTC_MS + 2;
            }),
            EligibilityDenialV1::LeaseNotYetValid,
        ),
        (
            lease_fixture_with(|facts| {
                facts.not_before_utc_unix_ms = NOW_UTC_MS - 1;
                facts.expires_at_utc_unix_ms = NOW_UTC_MS;
            }),
            EligibilityDenialV1::LeaseExpired,
        ),
        (
            lease_fixture_with(|facts| facts.deadline_monotonic_ms = NOW_MONOTONIC_MS),
            EligibilityDenialV1::LeaseMonotonicExpired,
        ),
    ] {
        assert_denied(fixture, expected);
    }

    assert_eligible(lease_fixture_with(|facts| {
        facts.not_before_utc_unix_ms = NOW_UTC_MS;
        facts.expires_at_utc_unix_ms = NOW_UTC_MS + 1;
        facts.deadline_monotonic_ms = NOW_MONOTONIC_MS + 1;
    }));
}

#[test]
fn lease_decision_scope_and_budget_outcomes_are_closed() {
    for (decision, expected) in [
        (
            LeaseDecisionFixture::Unavailable,
            EligibilityDenialV1::LeaseDecisionUnavailable,
        ),
        (
            LeaseDecisionFixture::Inconsistent,
            EligibilityDenialV1::LeaseDecisionInconsistent,
        ),
        (
            LeaseDecisionFixture::PlanMismatch,
            EligibilityDenialV1::LeaseDecisionPlanMismatch,
        ),
        (
            LeaseDecisionFixture::IntentDenied,
            EligibilityDenialV1::LeaseIntentDenied,
        ),
        (
            LeaseDecisionFixture::ScopeWidened,
            EligibilityDenialV1::LeaseScopeWidened,
        ),
        (
            LeaseDecisionFixture::BudgetWidened,
            EligibilityDenialV1::LeaseBudgetWidened,
        ),
        (
            LeaseDecisionFixture::PriceTableMismatch,
            EligibilityDenialV1::LeasePriceTableMismatch,
        ),
        (
            LeaseDecisionFixture::ReservationMismatch,
            EligibilityDenialV1::LeaseReservationMismatch,
        ),
    ] {
        assert_denied(
            lease_fixture_with(|facts| facts.decision = decision),
            expected,
        );
    }
    assert_denied(
        lease_fixture_with(|facts| {
            facts.decision = LeaseDecisionFixture::Allows(digest(b"another plan"));
        }),
        EligibilityDenialV1::LeaseDecisionPlanMismatch,
    );
}

#[test]
fn authorization_status_bindings_and_half_open_windows_are_exact() {
    for (view, expected) in [
        (
            AuthorizationViewV1::Unavailable,
            EligibilityDenialV1::AuthorizationUnavailable,
        ),
        (
            AuthorizationViewV1::Inconsistent,
            EligibilityDenialV1::AuthorizationInconsistent,
        ),
    ] {
        assert_denied(
            ready_fixture_with(|_, input| input.authorization = view),
            expected,
        );
    }

    for status in [
        AuthorizationStatusV1::Denied,
        AuthorizationStatusV1::Revoked,
    ] {
        assert_denied(
            authorization_fixture_with(|facts| facts.status = status),
            EligibilityDenialV1::AuthorizationNotGranted,
        );
    }
    for (fixture, expected) in [
        (
            authorization_fixture_with(|facts| facts.plan_id = digest(b"another plan")),
            EligibilityDenialV1::AuthorizationPlanMismatch,
        ),
        (
            authorization_fixture_with(|facts| facts.operation_id = OTHER_OPERATION_ID),
            EligibilityDenialV1::AuthorizationOperationMismatch,
        ),
        (
            authorization_fixture_with(|facts| facts.risk_level = RiskLevelV1::L2),
            EligibilityDenialV1::AuthorizationRiskMismatch,
        ),
        (
            authorization_fixture_with(|facts| {
                facts.nonce = Nonce128::from_bytes([0x22; 16]);
            }),
            EligibilityDenialV1::AuthorizationNonceMismatch,
        ),
        (
            authorization_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID),
            EligibilityDenialV1::AuthorizationBootMismatch,
        ),
        (
            authorization_fixture_with(|facts| {
                facts.not_before_utc_unix_ms = NOW_UTC_MS + 1;
                facts.expires_at_utc_unix_ms = NOW_UTC_MS + 2;
            }),
            EligibilityDenialV1::AuthorizationNotYetValid,
        ),
        (
            authorization_fixture_with(|facts| {
                facts.not_before_utc_unix_ms = NOW_UTC_MS - 1;
                facts.expires_at_utc_unix_ms = NOW_UTC_MS;
            }),
            EligibilityDenialV1::AuthorizationExpired,
        ),
        (
            authorization_fixture_with(|facts| {
                facts.deadline_monotonic_ms = NOW_MONOTONIC_MS;
            }),
            EligibilityDenialV1::AuthorizationMonotonicExpired,
        ),
    ] {
        assert_denied(fixture, expected);
    }

    assert_eligible(authorization_fixture_with(|facts| {
        facts.not_before_utc_unix_ms = NOW_UTC_MS;
        facts.expires_at_utc_unix_ms = NOW_UTC_MS + 1;
        facts.deadline_monotonic_ms = NOW_MONOTONIC_MS + 1;
    }));
}

#[test]
fn authority_groups_preserve_normative_first_failure_precedence() {
    assert_denied(
        ready_fixture_with(|plan, input| {
            let mut signer = SignerFacts::coherent(plan);
            signer.key_id = OTHER_KEY_ID;
            input.signer = signer.into_view();
            input.workload = WorkloadIdentityViewV1::Unavailable;
        }),
        EligibilityDenialV1::SignerKeyMismatch,
    );
    assert_denied(
        ready_fixture_with(|_, input| {
            let mut workload = WorkloadFacts::coherent();
            workload.workload_id = OTHER_WORKLOAD_ID;
            input.workload = workload.into_view();
            input.lease = LeaseResolutionV1::Unavailable;
        }),
        EligibilityDenialV1::WorkloadIdMismatch,
    );
    assert_denied(
        ready_fixture_with(|plan, input| {
            let mut lease = LeaseFacts::coherent(plan);
            lease.lease_digest = digest(b"another lease");
            input.lease = lease.into_view();
            input.authorization = AuthorizationViewV1::Unavailable;
        }),
        EligibilityDenialV1::LeaseDigestMismatch,
    );
    assert_denied(
        ready_fixture_with(|plan, input| {
            let mut authorization = AuthorizationFacts::coherent(plan);
            authorization.plan_id = digest(b"another plan");
            input.authorization = authorization.into_view();
            input.policy = PolicyViewV1::Unavailable;
        }),
        EligibilityDenialV1::AuthorizationPlanMismatch,
    );
}
