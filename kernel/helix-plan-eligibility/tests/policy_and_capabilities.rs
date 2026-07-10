mod common;

use common::*;
use helix_contracts::{sign_plan_v1, AuthenticPlanEnvelopeV1, ContractError, Sha256Digest};
use helix_plan_eligibility::{
    CapabilityRecordInputV1, CapabilityRecordV1, CapabilityViewV1, CatalogueRecordInputV1,
    CatalogueRecordV1, CatalogueViewV1, EligibilityDenialV1, PlanDecisionEvidenceInputV1,
    PlanDecisionEvidenceV1, PolicyDecisionV1, PolicyRecordInputV1, PolicyRecordV1, PolicyViewV1,
    SupportStatusV1,
};
use std::sync::OnceLock;

const OTHER_POLICY_VERSION: &str = "policy:2";
const OTHER_CATALOGUE_VERSION: &str = "catalog:2";

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

fn durable_flush_mandatory() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(&VALUES, ["filesystem.durable-flush"])
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

fn available_required_only() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(
        &VALUES,
        ["filesystem.atomic-replace", "filesystem.verify-by-handle"],
    )
}

fn available_verify_only() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    strings(&VALUES, ["filesystem.verify-by-handle"])
}

fn assert_denied(fixture: EligibilityFixture, expected: EligibilityDenialV1) {
    let claimant = ClaimantProbe::default();
    let failure = fixture
        .evaluate(&claimant)
        .expect_err("single-fault policy/capability fixture must be denied");
    assert_eq!(claimant.calls(), 0, "pre-claim denial reached claimant");
    assert_eq!(claimant.observed_binding_digest(), None);
    assert_eq!(failure.denial(), expected);
    assert_eq!(failure.denial().code(), expected.code());
}

fn assert_eligible(fixture: EligibilityFixture) {
    let claimant = ClaimantProbe::default();
    let _eligible = fixture
        .evaluate(&claimant)
        .expect("exact freshness boundary must remain eligible");
    assert_eq!(claimant.calls(), 1);
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

fn catalogue_view_with(
    plan: &AuthenticPlanEnvelopeV1,
    change: impl FnOnce(&mut CatalogueFacts),
) -> CatalogueViewV1<'static> {
    let mut facts = CatalogueFacts::coherent(plan);
    change(&mut facts);
    facts.into_view()
}

fn catalogue_fixture_with(change: impl FnOnce(&mut CatalogueFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        input.catalogue = catalogue_view_with(plan, change);
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

fn capability_view_with(
    plan: &AuthenticPlanEnvelopeV1,
    change: impl FnOnce(&mut CapabilityFacts),
) -> CapabilityViewV1<'static> {
    let mut facts = CapabilityFacts::coherent(plan);
    change(&mut facts);
    facts.into_view()
}

fn capability_fixture_with(change: impl FnOnce(&mut CapabilityFacts)) -> EligibilityFixture {
    ready_fixture_with(move |plan, input| {
        input.capabilities = capability_view_with(plan, change);
    })
}

#[test]
fn policy_resolution_identity_content_generation_and_decision_are_exact() {
    for (view, expected) in [
        (
            PolicyViewV1::Unavailable,
            EligibilityDenialV1::PolicyUnavailable,
        ),
        (
            PolicyViewV1::Inconsistent,
            EligibilityDenialV1::PolicyInconsistent,
        ),
        (
            PolicyViewV1::Unknown,
            EligibilityDenialV1::PolicyIdentityMismatch,
        ),
        (
            PolicyViewV1::IdentifierReused,
            EligibilityDenialV1::PolicyContentMismatch,
        ),
    ] {
        assert_denied(ready_fixture_with(|_, input| input.policy = view), expected);
    }

    for (fixture, expected) in [
        (
            policy_fixture_with(|facts| {
                facts.version = OTHER_POLICY_VERSION;
                facts.active_content_digest = digest(b"also changed");
            }),
            EligibilityDenialV1::PolicyIdentityMismatch,
        ),
        (
            policy_fixture_with(|facts| {
                facts.active_content_digest = digest(b"replacement policy content");
            }),
            EligibilityDenialV1::PolicyContentMismatch,
        ),
        (
            policy_fixture_with(|facts| {
                facts.decision_policy_generation = POLICY_GENERATION + 1;
            }),
            EligibilityDenialV1::PolicyGenerationMismatch,
        ),
        (
            policy_fixture_with(|facts| {
                facts.decision = PolicyDecisionFixture::Allow(digest(b"another plan"));
            }),
            EligibilityDenialV1::PolicyDecisionPlanMismatch,
        ),
        (
            policy_fixture_with(|facts| {
                facts.decision = PolicyDecisionFixture::Deny(digest(b"another plan"));
            }),
            EligibilityDenialV1::PolicyDecisionPlanMismatch,
        ),
        (
            policy_fixture_with(|facts| {
                let plan_id = match facts.decision {
                    PolicyDecisionFixture::Allow(plan_id)
                    | PolicyDecisionFixture::Deny(plan_id) => plan_id,
                };
                facts.decision = PolicyDecisionFixture::Deny(plan_id);
            }),
            EligibilityDenialV1::PolicyDenied,
        ),
    ] {
        assert_denied(fixture, expected);
    }
}

#[test]
fn catalogue_resolution_identity_content_generation_and_support_are_exact() {
    for (view, expected) in [
        (
            CatalogueViewV1::Unavailable,
            EligibilityDenialV1::CatalogueUnavailable,
        ),
        (
            CatalogueViewV1::Inconsistent,
            EligibilityDenialV1::CatalogueInconsistent,
        ),
        (
            CatalogueViewV1::Unknown,
            EligibilityDenialV1::CatalogueIdentityMismatch,
        ),
        (
            CatalogueViewV1::IdentifierReused,
            EligibilityDenialV1::CatalogueContentMismatch,
        ),
    ] {
        assert_denied(
            ready_fixture_with(|_, input| input.catalogue = view),
            expected,
        );
    }

    for (fixture, expected) in [
        (
            catalogue_fixture_with(|facts| {
                facts.version = OTHER_CATALOGUE_VERSION;
                facts.active_content_digest = digest(b"also changed");
            }),
            EligibilityDenialV1::CatalogueIdentityMismatch,
        ),
        (
            catalogue_fixture_with(|facts| {
                facts.active_content_digest = digest(b"replacement catalogue content");
            }),
            EligibilityDenialV1::CatalogueContentMismatch,
        ),
        (
            catalogue_fixture_with(|facts| {
                facts.decision_catalogue_generation = CATALOGUE_GENERATION + 1;
            }),
            EligibilityDenialV1::CatalogueGenerationMismatch,
        ),
        (
            catalogue_fixture_with(|facts| {
                facts.decision_plan_id = digest(b"another plan");
            }),
            EligibilityDenialV1::CatalogueDecisionPlanMismatch,
        ),
        (
            catalogue_fixture_with(|facts| {
                facts.schema_support = SupportStatusV1::Unsupported;
                facts.intent_support = SupportStatusV1::Unsupported;
            }),
            EligibilityDenialV1::CatalogueSchemaUnsupported,
        ),
        (
            catalogue_fixture_with(|facts| {
                facts.intent_support = SupportStatusV1::Unsupported;
            }),
            EligibilityDenialV1::CatalogueIntentUnsupported,
        ),
    ] {
        assert_denied(fixture, expected);
    }
}

#[test]
fn capability_resolution_and_exact_report_bindings_are_closed() {
    for (view, expected) in [
        (
            CapabilityViewV1::Unavailable,
            EligibilityDenialV1::CapabilityUnavailable,
        ),
        (
            CapabilityViewV1::Inconsistent,
            EligibilityDenialV1::CapabilityInconsistent,
        ),
        (
            CapabilityViewV1::Unknown,
            EligibilityDenialV1::CapabilityNotFound,
        ),
    ] {
        assert_denied(
            ready_fixture_with(|_, input| input.capabilities = view),
            expected,
        );
    }

    for (fixture, expected) in [
        (
            capability_fixture_with(|facts| {
                facts.report_digest = digest(b"another report");
                facts.observed_at_unix_ms += 1;
            }),
            EligibilityDenialV1::CapabilityDigestMismatch,
        ),
        (
            capability_fixture_with(|facts| facts.observed_at_unix_ms += 1),
            EligibilityDenialV1::CapabilityObservationMismatch,
        ),
        (
            capability_fixture_with(|facts| facts.boot_id = OTHER_BOOT_ID),
            EligibilityDenialV1::CapabilityBootMismatch,
        ),
        (
            capability_fixture_with(|facts| facts.instance_epoch = INSTANCE_EPOCH + 1),
            EligibilityDenialV1::CapabilityInstanceEpochMismatch,
        ),
        (
            capability_fixture_with(|facts| {
                facts.current_host_driver_context_digest = digest(b"new host-driver context");
            }),
            EligibilityDenialV1::CapabilityContextMismatch,
        ),
    ] {
        assert_denied(fixture, expected);
    }
}

#[test]
fn capability_freshness_accepts_max_age_and_rejects_one_millisecond_older() {
    let exact_age = NOW_UTC_MS - (ISSUED_AT_MS - 1_000);
    assert_eligible(policy_fixture_with(|facts| {
        facts.max_capability_age_ms = exact_age;
    }));
    assert_denied(
        policy_fixture_with(|facts| {
            facts.max_capability_age_ms = exact_age - 1;
        }),
        EligibilityDenialV1::CapabilityStale,
    );
}

#[test]
fn required_and_both_sources_of_mandatory_capabilities_are_distinct() {
    assert_denied(
        capability_fixture_with(|facts| {
            facts.available_capabilities = available_verify_only();
        }),
        EligibilityDenialV1::RequiredCapabilityMissing,
    );
    assert_denied(
        ready_fixture_with(|plan, input| {
            input.policy = policy_view_with(plan, |facts| {
                facts.mandatory_capabilities = durable_flush_mandatory();
            });
            input.capabilities = capability_view_with(plan, |facts| {
                facts.available_capabilities = available_required_only();
            });
        }),
        EligibilityDenialV1::MandatoryCapabilityMissing,
    );
    assert_denied(
        ready_fixture_with(|plan, input| {
            input.catalogue = catalogue_view_with(plan, |facts| {
                facts.mandatory_capabilities = durable_flush_mandatory();
            });
            input.capabilities = capability_view_with(plan, |facts| {
                facts.available_capabilities = available_required_only();
            });
        }),
        EligibilityDenialV1::MandatoryCapabilityMissing,
    );
    assert_denied(
        ready_fixture_with(|plan, input| {
            input.policy = policy_view_with(plan, |facts| {
                facts.mandatory_capabilities = durable_flush_mandatory();
            });
            input.capabilities = capability_view_with(plan, |facts| {
                facts.available_capabilities = available_verify_only();
            });
        }),
        EligibilityDenialV1::RequiredCapabilityMissing,
    );
}

#[test]
fn policy_catalogue_and_capability_groups_preserve_first_failure_precedence() {
    assert_denied(
        ready_fixture_with(|_, input| {
            input.policy = PolicyViewV1::Unavailable;
            input.catalogue = CatalogueViewV1::Unavailable;
            input.capabilities = CapabilityViewV1::Unavailable;
        }),
        EligibilityDenialV1::PolicyUnavailable,
    );
    assert_denied(
        ready_fixture_with(|_, input| {
            input.catalogue = CatalogueViewV1::Unavailable;
            input.capabilities = CapabilityViewV1::Unavailable;
        }),
        EligibilityDenialV1::CatalogueUnavailable,
    );
}

#[test]
fn feature_one_invariant_rejects_future_observations_without_a_dead_denial_code() {
    let mut input = sample_plan_input();
    input.capability_observed_at_unix_ms = input.issued_at_unix_ms + 1;
    let error = sign_plan_v1(input, &TestSigner::fixed())
        .expect_err("feature one rejects an observation after plan issuance");
    assert!(matches!(
        error,
        ContractError::InvalidField {
            field: "capability_observed_at_unix_ms",
            ..
        }
    ));

    assert_denied(
        capability_fixture_with(|facts| {
            facts.observed_at_unix_ms = NOW_UTC_MS + 1;
        }),
        EligibilityDenialV1::CapabilityObservationMismatch,
    );
    assert!(!EligibilityDenialV1::ALL
        .iter()
        .any(|denial| denial.code() == "CAPABILITY_FUTURE_DATED"));
}
