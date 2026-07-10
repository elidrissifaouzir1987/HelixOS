use crate::marker::{
    EffectiveEligibilityBoundsInputV1, EffectiveEligibilityBoundsV1, EligibilityBindingsInputV1,
};
use crate::replay::{ReplayBindingInputV1, ReplayBindingV1};
use crate::{
    AuthorizationStatusV1, AuthorizationViewV1, CapabilityViewV1, CatalogueViewV1,
    EligibilityContextV1, EligibilityDenialV1, EligibilityFailureV1, EligiblePlanV1,
    LeaseAuthorityDecisionV1, LeaseResolutionV1, LeaseStateV1, MonotonicClockViewV1,
    PlanDeadlineViewV1, PolicyDecisionV1, PolicyViewV1, ReadyEligibilityContextV1,
    ReplayClaimOutcomeV1, ReplayClaimantV1, SignerTrustViewV1, SupervisorAdmissionStateV1,
    SupervisorViewV1, SupportStatusV1, WallClockViewV1, WorkloadIdentityViewV1,
};
use helix_contracts::{AuthenticPlanEnvelopeV1, Identifier, PlanEligibilityClaimsV1, SafeU64};

/// Evaluates all read-only current-state gates in frozen order, then attempts one claim.
///
/// No claimant call occurs for a read-only denial. Once the claimant is reached it is
/// called exactly once, is never retried, and its matching receipt is required before an
/// [`EligiblePlanV1`] can be constructed. The returned marker remains non-authoritative.
pub fn evaluate_and_claim_plan_v1<C: ReplayClaimantV1 + ?Sized>(
    plan: AuthenticPlanEnvelopeV1,
    context: EligibilityContextV1<'_>,
    claimant: &C,
) -> Result<EligiblePlanV1, EligibilityFailureV1> {
    let ready = match context {
        EligibilityContextV1::Unavailable => {
            return denied(plan, EligibilityDenialV1::ContextUnavailable)
        }
        EligibilityContextV1::Incomplete => {
            return denied(plan, EligibilityDenialV1::ContextIncomplete)
        }
        EligibilityContextV1::Torn => return denied(plan, EligibilityDenialV1::ContextTorn),
        EligibilityContextV1::Ready(ready) => ready,
    };

    let validated = match validate_read_only(plan.eligibility_claims(), &ready) {
        Ok(validated) => validated,
        Err(denial) => return denied(plan, denial),
    };
    let ValidatedEligibilityV1 {
        replay_binding,
        bounds,
        bindings,
    } = validated;
    let (expected_binding_digest, outcome) = {
        let expected_binding_digest = replay_binding.binding_digest();
        let outcome = claimant.claim_once(&replay_binding);
        (expected_binding_digest, outcome)
    };

    match outcome {
        ReplayClaimOutcomeV1::Claimed(receipt) => {
            if receipt.binding_digest() != expected_binding_digest {
                return denied(plan, EligibilityDenialV1::ReplayReceiptBindingMismatch);
            }
            Ok(EligiblePlanV1::new(
                plan,
                EffectiveEligibilityBoundsV1::new(bounds),
                bindings,
                receipt,
            ))
        }
        ReplayClaimOutcomeV1::AlreadyClaimed => {
            denied(plan, EligibilityDenialV1::ReplayAlreadyClaimed)
        }
        ReplayClaimOutcomeV1::BindingConflict => {
            denied(plan, EligibilityDenialV1::ReplayBindingConflict)
        }
        ReplayClaimOutcomeV1::Unavailable => denied(plan, EligibilityDenialV1::ReplayUnavailable),
        ReplayClaimOutcomeV1::Ambiguous => denied(plan, EligibilityDenialV1::ReplayAmbiguous),
    }
}

struct ValidatedEligibilityV1<'plan> {
    replay_binding: ReplayBindingV1<'plan>,
    bounds: EffectiveEligibilityBoundsInputV1,
    bindings: EligibilityBindingsInputV1,
}

fn validate_read_only<'plan>(
    claims: PlanEligibilityClaimsV1<'plan>,
    ready: &ReadyEligibilityContextV1<'_>,
) -> Result<ValidatedEligibilityV1<'plan>, EligibilityDenialV1> {
    if ready.bound_plan_id() != claims.plan_id() {
        return Err(EligibilityDenialV1::ContextPlanMismatch);
    }

    let supervisor = match ready.supervisor() {
        SupervisorViewV1::Unavailable => return Err(EligibilityDenialV1::SupervisorUnavailable),
        SupervisorViewV1::Inconsistent => return Err(EligibilityDenialV1::SupervisorInconsistent),
        SupervisorViewV1::Current(supervisor) => supervisor,
    };
    if supervisor.admission_state() != SupervisorAdmissionStateV1::Open {
        return Err(EligibilityDenialV1::SupervisorNotOpen);
    }

    let now_utc = match ready.time().wall() {
        WallClockViewV1::Unavailable => return Err(EligibilityDenialV1::WallClockUnavailable),
        WallClockViewV1::RollbackSuspected => {
            return Err(EligibilityDenialV1::WallClockRollbackSuspected)
        }
        WallClockViewV1::Healthy(now) => now.get(),
    };
    if now_utc < claims.issued_at_unix_ms() {
        return Err(EligibilityDenialV1::PlanNotYetValid);
    }
    if now_utc >= claims.expires_at_unix_ms() {
        return Err(EligibilityDenialV1::PlanExpired);
    }
    if supervisor.boot_id() != claims.boot_id() {
        return Err(EligibilityDenialV1::BootMismatch);
    }

    let monotonic = match ready.time().monotonic() {
        MonotonicClockViewV1::Unavailable => {
            return Err(EligibilityDenialV1::MonotonicClockUnavailable)
        }
        MonotonicClockViewV1::NotSuspendAware => {
            return Err(EligibilityDenialV1::MonotonicClockUnsuitable)
        }
        MonotonicClockViewV1::Regressed => {
            return Err(EligibilityDenialV1::MonotonicClockRegressed)
        }
        MonotonicClockViewV1::Healthy(sample) => sample,
    };
    if monotonic.boot_id() != claims.boot_id() {
        return Err(EligibilityDenialV1::BootMismatch);
    }
    let now_monotonic = monotonic.now_monotonic_ms();

    let plan_deadline = match ready.plan_deadline() {
        PlanDeadlineViewV1::Missing | PlanDeadlineViewV1::Unavailable => {
            return Err(EligibilityDenialV1::PlanDeadlineUnavailable)
        }
        PlanDeadlineViewV1::Inconsistent => {
            return Err(EligibilityDenialV1::PlanDeadlineInconsistent)
        }
        PlanDeadlineViewV1::Current(deadline) => deadline,
    };
    if plan_deadline.plan_id() != claims.plan_id() || plan_deadline.boot_id() != claims.boot_id() {
        return Err(EligibilityDenialV1::PlanDeadlineMismatch);
    }
    if now_monotonic >= plan_deadline.deadline_monotonic_ms() {
        return Err(EligibilityDenialV1::MonotonicDeadlineReached);
    }
    if supervisor.instance_epoch() != claims.instance_epoch() {
        return Err(EligibilityDenialV1::InstanceEpochMismatch);
    }
    if supervisor.fencing_epoch() != claims.fencing_epoch() {
        return Err(EligibilityDenialV1::FencingEpochMismatch);
    }

    let signer = match ready.signer() {
        SignerTrustViewV1::Unavailable => return Err(EligibilityDenialV1::SignerTrustUnavailable),
        SignerTrustViewV1::Inconsistent => {
            return Err(EligibilityDenialV1::SignerTrustInconsistent)
        }
        SignerTrustViewV1::Unknown | SignerTrustViewV1::Revoked => {
            return Err(EligibilityDenialV1::SignerNotTrusted)
        }
        SignerTrustViewV1::Trusted(signer) => signer,
    };
    if signer.key_id() != claims.key_id() {
        return Err(EligibilityDenialV1::SignerKeyMismatch);
    }
    if signer.public_key_fingerprint() != claims.verified_key_fingerprint() {
        return Err(EligibilityDenialV1::SignerFingerprintMismatch);
    }
    if claims.issued_at_unix_ms() < signer.minimum_accepted_issued_at_unix_ms() {
        return Err(EligibilityDenialV1::SignerGenerationRejectsPlan);
    }

    let workload = match ready.workload() {
        WorkloadIdentityViewV1::Unavailable => {
            return Err(EligibilityDenialV1::WorkloadUnavailable)
        }
        WorkloadIdentityViewV1::Inconsistent => {
            return Err(EligibilityDenialV1::WorkloadInconsistent)
        }
        WorkloadIdentityViewV1::Unknown | WorkloadIdentityViewV1::Revoked => {
            return Err(EligibilityDenialV1::WorkloadNotTrusted)
        }
        WorkloadIdentityViewV1::Trusted(workload) => workload,
    };
    if workload.workload_id() != claims.workload_id() {
        return Err(EligibilityDenialV1::WorkloadIdMismatch);
    }
    if workload.boot_id() != claims.boot_id() {
        return Err(EligibilityDenialV1::WorkloadBootMismatch);
    }
    if workload.instance_epoch() != claims.instance_epoch() {
        return Err(EligibilityDenialV1::WorkloadInstanceEpochMismatch);
    }
    if now_utc < workload.not_before_utc_unix_ms() {
        return Err(EligibilityDenialV1::WorkloadNotYetValid);
    }
    if now_utc >= workload.expires_at_utc_unix_ms() {
        return Err(EligibilityDenialV1::WorkloadExpired);
    }
    if now_monotonic >= workload.deadline_monotonic_ms() {
        return Err(EligibilityDenialV1::WorkloadMonotonicExpired);
    }

    let lease = match ready.lease() {
        LeaseResolutionV1::Unavailable => return Err(EligibilityDenialV1::LeaseUnavailable),
        LeaseResolutionV1::Inconsistent => return Err(EligibilityDenialV1::LeaseInconsistent),
        LeaseResolutionV1::NotFound => return Err(EligibilityDenialV1::LeaseNotFound),
        LeaseResolutionV1::Multiple => return Err(EligibilityDenialV1::LeaseAmbiguous),
        LeaseResolutionV1::ExactlyOne(lease) => lease,
    };
    if lease.lease_digest() != claims.task_lease_digest() {
        return Err(EligibilityDenialV1::LeaseDigestMismatch);
    }
    if lease.state() != LeaseStateV1::Active {
        return Err(EligibilityDenialV1::LeaseNotActive);
    }
    if lease.task_id() != claims.task_id() {
        return Err(EligibilityDenialV1::LeaseTaskMismatch);
    }
    if lease.workload_id() != claims.workload_id() {
        return Err(EligibilityDenialV1::LeaseWorkloadMismatch);
    }
    if lease.boot_id() != claims.boot_id() {
        return Err(EligibilityDenialV1::LeaseBootMismatch);
    }
    if lease.instance_epoch() != claims.instance_epoch() {
        return Err(EligibilityDenialV1::LeaseInstanceEpochMismatch);
    }
    if lease.request_source_kind() != claims.request_source_kind()
        || lease.request_source_digest() != claims.request_source_digest()
    {
        return Err(EligibilityDenialV1::LeaseSourceMismatch);
    }
    if now_utc < lease.not_before_utc_unix_ms() {
        return Err(EligibilityDenialV1::LeaseNotYetValid);
    }
    if now_utc >= lease.expires_at_utc_unix_ms() {
        return Err(EligibilityDenialV1::LeaseExpired);
    }
    if now_monotonic >= lease.deadline_monotonic_ms() {
        return Err(EligibilityDenialV1::LeaseMonotonicExpired);
    }
    let lease_decision = match lease.decision() {
        LeaseAuthorityDecisionV1::Unavailable => {
            return Err(EligibilityDenialV1::LeaseDecisionUnavailable)
        }
        LeaseAuthorityDecisionV1::Inconsistent => {
            return Err(EligibilityDenialV1::LeaseDecisionInconsistent)
        }
        LeaseAuthorityDecisionV1::PlanMismatch => {
            return Err(EligibilityDenialV1::LeaseDecisionPlanMismatch)
        }
        LeaseAuthorityDecisionV1::IntentDenied => {
            return Err(EligibilityDenialV1::LeaseIntentDenied)
        }
        LeaseAuthorityDecisionV1::ScopeWidened => {
            return Err(EligibilityDenialV1::LeaseScopeWidened)
        }
        LeaseAuthorityDecisionV1::BudgetWidened => {
            return Err(EligibilityDenialV1::LeaseBudgetWidened)
        }
        LeaseAuthorityDecisionV1::PriceTableMismatch => {
            return Err(EligibilityDenialV1::LeasePriceTableMismatch)
        }
        LeaseAuthorityDecisionV1::ReservationMismatch => {
            return Err(EligibilityDenialV1::LeaseReservationMismatch)
        }
        LeaseAuthorityDecisionV1::Allows(decision) => decision,
    };
    if lease_decision.plan_id() != claims.plan_id() {
        return Err(EligibilityDenialV1::LeaseDecisionPlanMismatch);
    }

    let authorization = match ready.authorization() {
        AuthorizationViewV1::Unavailable => {
            return Err(EligibilityDenialV1::AuthorizationUnavailable)
        }
        AuthorizationViewV1::Inconsistent => {
            return Err(EligibilityDenialV1::AuthorizationInconsistent)
        }
        AuthorizationViewV1::Current(authorization) => authorization,
    };
    if authorization.status() != AuthorizationStatusV1::Granted {
        return Err(EligibilityDenialV1::AuthorizationNotGranted);
    }
    if authorization.plan_id() != claims.plan_id() {
        return Err(EligibilityDenialV1::AuthorizationPlanMismatch);
    }
    if authorization.operation_id() != claims.operation_id() {
        return Err(EligibilityDenialV1::AuthorizationOperationMismatch);
    }
    if authorization.risk_level() != claims.risk_level() {
        return Err(EligibilityDenialV1::AuthorizationRiskMismatch);
    }
    if authorization.nonce() != claims.nonce() {
        return Err(EligibilityDenialV1::AuthorizationNonceMismatch);
    }
    if authorization.boot_id() != claims.boot_id() {
        return Err(EligibilityDenialV1::AuthorizationBootMismatch);
    }
    if now_utc < authorization.not_before_utc_unix_ms() {
        return Err(EligibilityDenialV1::AuthorizationNotYetValid);
    }
    if now_utc >= authorization.expires_at_utc_unix_ms() {
        return Err(EligibilityDenialV1::AuthorizationExpired);
    }
    if now_monotonic >= authorization.deadline_monotonic_ms() {
        return Err(EligibilityDenialV1::AuthorizationMonotonicExpired);
    }

    let policy = match ready.policy() {
        PolicyViewV1::Unavailable => return Err(EligibilityDenialV1::PolicyUnavailable),
        PolicyViewV1::Inconsistent => return Err(EligibilityDenialV1::PolicyInconsistent),
        PolicyViewV1::Unknown => return Err(EligibilityDenialV1::PolicyIdentityMismatch),
        PolicyViewV1::IdentifierReused => return Err(EligibilityDenialV1::PolicyContentMismatch),
        PolicyViewV1::Current(policy) => policy,
    };
    if policy.version() != claims.policy_version() {
        return Err(EligibilityDenialV1::PolicyIdentityMismatch);
    }
    if policy.resolved_content_digest() != policy.active_content_digest() {
        return Err(EligibilityDenialV1::PolicyContentMismatch);
    }
    if policy.policy_generation() != policy.decision_policy_generation() {
        return Err(EligibilityDenialV1::PolicyGenerationMismatch);
    }
    let (policy_decision, policy_allowed) = match policy.decision() {
        PolicyDecisionV1::Allow(decision) => (decision, true),
        PolicyDecisionV1::Deny(decision) => (decision, false),
    };
    if policy_decision.plan_id() != claims.plan_id() {
        return Err(EligibilityDenialV1::PolicyDecisionPlanMismatch);
    }
    if !policy_allowed {
        return Err(EligibilityDenialV1::PolicyDenied);
    }

    let catalogue = match ready.catalogue() {
        CatalogueViewV1::Unavailable => return Err(EligibilityDenialV1::CatalogueUnavailable),
        CatalogueViewV1::Inconsistent => return Err(EligibilityDenialV1::CatalogueInconsistent),
        CatalogueViewV1::Unknown => return Err(EligibilityDenialV1::CatalogueIdentityMismatch),
        CatalogueViewV1::IdentifierReused => {
            return Err(EligibilityDenialV1::CatalogueContentMismatch)
        }
        CatalogueViewV1::Current(catalogue) => catalogue,
    };
    if catalogue.version() != claims.catalog_version() {
        return Err(EligibilityDenialV1::CatalogueIdentityMismatch);
    }
    if catalogue.resolved_content_digest() != catalogue.active_content_digest() {
        return Err(EligibilityDenialV1::CatalogueContentMismatch);
    }
    if catalogue.catalogue_generation() != catalogue.decision_catalogue_generation() {
        return Err(EligibilityDenialV1::CatalogueGenerationMismatch);
    }
    if catalogue.decision().plan_id() != claims.plan_id() {
        return Err(EligibilityDenialV1::CatalogueDecisionPlanMismatch);
    }
    if catalogue.schema_support() != SupportStatusV1::Supported {
        return Err(EligibilityDenialV1::CatalogueSchemaUnsupported);
    }
    if catalogue.intent_support() != SupportStatusV1::Supported {
        return Err(EligibilityDenialV1::CatalogueIntentUnsupported);
    }

    let capabilities = match ready.capabilities() {
        CapabilityViewV1::Unavailable => return Err(EligibilityDenialV1::CapabilityUnavailable),
        CapabilityViewV1::Inconsistent => return Err(EligibilityDenialV1::CapabilityInconsistent),
        CapabilityViewV1::Unknown => return Err(EligibilityDenialV1::CapabilityNotFound),
        CapabilityViewV1::Current(capabilities) => capabilities,
    };
    if capabilities.report_digest() != claims.capability_report_digest() {
        return Err(EligibilityDenialV1::CapabilityDigestMismatch);
    }
    if capabilities.observed_at_unix_ms() != claims.capability_observed_at_unix_ms() {
        return Err(EligibilityDenialV1::CapabilityObservationMismatch);
    }
    if capabilities.boot_id() != claims.boot_id() {
        return Err(EligibilityDenialV1::CapabilityBootMismatch);
    }
    if capabilities.instance_epoch() != claims.instance_epoch() {
        return Err(EligibilityDenialV1::CapabilityInstanceEpochMismatch);
    }
    if capabilities.report_host_driver_context_digest()
        != capabilities.current_host_driver_context_digest()
    {
        return Err(EligibilityDenialV1::CapabilityContextMismatch);
    }
    // Feature 001 proves observed_at <= issued_at, and the time gate above proves
    // issued_at <= now. Keep the subtraction checked and fail closed if that upstream
    // invariant is ever broken without inventing an unreachable public denial code.
    let capability_age = now_utc
        .checked_sub(capabilities.observed_at_unix_ms())
        .ok_or(EligibilityDenialV1::CapabilityObservationMismatch)?;
    if capability_age > policy.max_capability_age_ms() {
        return Err(EligibilityDenialV1::CapabilityStale);
    }
    if !contains_all_identifiers(
        capabilities.available_capabilities(),
        claims.required_capabilities(),
    ) {
        return Err(EligibilityDenialV1::RequiredCapabilityMissing);
    }
    if !contains_all_strings(
        capabilities.available_capabilities(),
        policy.mandatory_capabilities(),
    ) || !contains_all_strings(
        capabilities.available_capabilities(),
        catalogue.mandatory_capabilities(),
    ) {
        return Err(EligibilityDenialV1::MandatoryCapabilityMissing);
    }

    let effective_expiry = claims
        .expires_at_unix_ms()
        .min(workload.expires_at_utc_unix_ms())
        .min(lease.expires_at_utc_unix_ms())
        .min(authorization.expires_at_utc_unix_ms());
    let effective_monotonic_deadline = plan_deadline
        .deadline_monotonic_ms()
        .min(workload.deadline_monotonic_ms())
        .min(lease.deadline_monotonic_ms())
        .min(authorization.deadline_monotonic_ms());

    let bounds = EffectiveEligibilityBoundsInputV1 {
        evaluated_at_utc_unix_ms: checked_safe(now_utc)?,
        evaluated_at_monotonic_ms: checked_safe(now_monotonic)?,
        effective_expires_at_utc_unix_ms: checked_safe(effective_expiry)?,
        capability_observed_at_unix_ms: checked_safe(capabilities.observed_at_unix_ms())?,
        capability_max_age_ms: checked_safe(policy.max_capability_age_ms())?,
        effective_deadline_monotonic_ms: checked_safe(effective_monotonic_deadline)?,
    };
    let bindings = EligibilityBindingsInputV1 {
        capture_generation: checked_safe(ready.capture_generation())?,
        clock_generation: checked_safe(ready.time().clock_generation())?,
        plan_deadline_generation: checked_safe(plan_deadline.deadline_generation())?,
        supervisor_generation: checked_safe(supervisor.supervisor_generation())?,
        instance_epoch: checked_safe(supervisor.instance_epoch())?,
        fencing_epoch: checked_safe(supervisor.fencing_epoch())?,
        trust_generation: checked_safe(signer.trust_generation())?,
        verified_key_fingerprint: claims.verified_key_fingerprint(),
        workload_identity_generation: checked_safe(workload.identity_generation())?,
        workload_evidence_digest: workload.evidence_digest(),
        lease_generation: checked_safe(lease.lease_generation())?,
        lease_digest: lease.lease_digest(),
        lease_decision_digest: lease_decision.decision_digest(),
        authorization_generation: checked_safe(authorization.authorization_generation())?,
        authorization_evidence_digest: authorization.evidence_digest(),
        policy_generation: checked_safe(policy.policy_generation())?,
        policy_decision_generation: checked_safe(policy.decision_generation())?,
        policy_content_digest: policy.resolved_content_digest(),
        policy_decision_digest: policy_decision.decision_digest(),
        catalogue_generation: checked_safe(catalogue.catalogue_generation())?,
        catalogue_decision_generation: checked_safe(catalogue.decision_generation())?,
        catalogue_content_digest: catalogue.resolved_content_digest(),
        catalogue_decision_digest: catalogue.decision().decision_digest(),
        capability_report_generation: checked_safe(capabilities.report_generation())?,
        capability_report_digest: capabilities.report_digest(),
        host_driver_context_digest: capabilities.current_host_driver_context_digest(),
    };
    let replay_binding = ReplayBindingV1::try_new(ReplayBindingInputV1 {
        instance_epoch: claims.instance_epoch(),
        nonce: claims.nonce(),
        key_id: claims.key_id(),
        verified_key_fingerprint: claims.verified_key_fingerprint(),
        plan_id: claims.plan_id(),
        operation_id: claims.operation_id(),
        task_id: claims.task_id(),
        workload_id: claims.workload_id(),
        task_lease_digest: claims.task_lease_digest(),
        trust_generation: signer.trust_generation(),
        fencing_epoch: claims.fencing_epoch(),
        claim_deadline_monotonic_ms: effective_monotonic_deadline,
    })
    .map_err(|_| EligibilityDenialV1::ContextIncomplete)?;

    Ok(ValidatedEligibilityV1 {
        replay_binding,
        bounds,
        bindings,
    })
}

fn checked_safe(value: u64) -> Result<SafeU64, EligibilityDenialV1> {
    SafeU64::new(value).map_err(|_| EligibilityDenialV1::ContextIncomplete)
}

fn contains_all_identifiers(available: &[String], required: &[Identifier]) -> bool {
    let mut available_index = 0;
    for required_value in required {
        while available_index < available.len()
            && available[available_index].as_str() < required_value.as_str()
        {
            available_index += 1;
        }
        if available_index == available.len()
            || available[available_index].as_str() != required_value.as_str()
        {
            return false;
        }
    }
    true
}

fn contains_all_strings(available: &[String], required: &[String]) -> bool {
    let mut available_index = 0;
    for required_value in required {
        while available_index < available.len() && available[available_index] < *required_value {
            available_index += 1;
        }
        if available_index == available.len() || available[available_index] != *required_value {
            return false;
        }
    }
    true
}

fn denied(
    plan: AuthenticPlanEnvelopeV1,
    denial: EligibilityDenialV1,
) -> Result<EligiblePlanV1, EligibilityFailureV1> {
    Err(EligibilityFailureV1::new(plan, denial))
}
