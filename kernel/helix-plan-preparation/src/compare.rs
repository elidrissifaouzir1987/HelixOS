//! Deterministic authority-comparison boundary.
//!
//! Comparison is pure, field-by-field, and follows the frozen first-failure order. It
//! performs no I/O and must not select public outcomes from provider diagnostics or
//! iteration order.

#![allow(dead_code)] // Called by the ordered orchestration introduced in T036.

use crate::attempt::PreparationAttemptIdV1;
use crate::context::{
    PreparationCapturePhaseV1, PreparationContextV1, ReadyPreparationContextV1,
    PREPARATION_CONTEXT_VERSION_V1,
};
use crate::outcome::PreparationDenialV1;
use helix_contracts::RecoveryClassV1;
use helix_plan_eligibility::{EligiblePlanV1, SupervisorAdmissionStateV1};

type ComparisonResult = Result<ReadyPreparationContextV1, PreparationDenialV1>;

/// Classifies and compares one preliminary snapshot without performing I/O.
pub(crate) fn compare_preliminary_context_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    context: PreparationContextV1,
    caller_deadline_monotonic_ms: u64,
) -> ComparisonResult {
    let ready = compare_preliminary_context_before_replay_v1(
        eligible,
        attempt,
        context,
        caller_deadline_monotonic_ms,
    )?;
    compare_context_replay_binding_v1(eligible, &ready)?;
    compare_preliminary_budget_v1(eligible, &ready)?;
    compare_preliminary_recovery_profile_v1(eligible, &ready)?;
    Ok(ready)
}

/// Compares preliminary rows 1-21, stopping before live replay classification.
pub(crate) fn compare_preliminary_context_before_replay_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    context: PreparationContextV1,
    caller_deadline_monotonic_ms: u64,
) -> ComparisonResult {
    compare_preliminary_context_before_replay_instrumented_v1(
        eligible,
        attempt,
        context,
        caller_deadline_monotonic_ms,
        || {},
    )
}

/// Compares preliminary rows 1-21 and observes each of the twelve context groups
/// immediately after it is classified, including the first failing group.
pub(crate) fn compare_preliminary_context_before_replay_instrumented_v1<O>(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    context: PreparationContextV1,
    caller_deadline_monotonic_ms: u64,
    mut observe_group: O,
) -> ComparisonResult
where
    O: FnMut(),
{
    let ready = compare_context_before_guard_groups_instrumented_v1(
        eligible,
        attempt,
        context,
        PreparationCapturePhaseV1::Preliminary,
        caller_deadline_monotonic_ms,
        None,
        &mut observe_group,
    )?;
    compare_authority_after_guard_fields_instrumented_v1(eligible, &ready, &mut observe_group)?;
    Ok(ready)
}

/// Classifies a fresh final snapshot and compares preparation-local authority to the
/// independently accepted preliminary snapshot.
pub(crate) fn compare_final_context_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    preliminary: &ReadyPreparationContextV1,
    context: PreparationContextV1,
    caller_deadline_monotonic_ms: u64,
) -> ComparisonResult {
    let ready = compare_final_context_before_guards_v1(
        eligible,
        attempt,
        preliminary,
        context,
        caller_deadline_monotonic_ms,
    )?;
    compare_final_context_after_guards_v1(eligible, preliminary, &ready)?;
    Ok(ready)
}

/// Compares final rows 1-13. Ordered orchestration must validate the live guard set
/// immediately after this function and before calling
/// [`compare_final_context_after_guards_v1`], placing guard refusal at normative row 14.
pub(crate) fn compare_final_context_before_guards_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    preliminary: &ReadyPreparationContextV1,
    context: PreparationContextV1,
    caller_deadline_monotonic_ms: u64,
) -> ComparisonResult {
    compare_final_context_before_guards_instrumented_v1(
        eligible,
        attempt,
        preliminary,
        context,
        caller_deadline_monotonic_ms,
        || {},
    )
}

/// Compares final rows 1-13 and observes groups 1-5 before live guard validation.
pub(crate) fn compare_final_context_before_guards_instrumented_v1<O>(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    preliminary: &ReadyPreparationContextV1,
    context: PreparationContextV1,
    caller_deadline_monotonic_ms: u64,
    mut observe_group: O,
) -> ComparisonResult
where
    O: FnMut(),
{
    compare_context_before_guard_groups_instrumented_v1(
        eligible,
        attempt,
        context,
        PreparationCapturePhaseV1::Final,
        caller_deadline_monotonic_ms,
        Some(preliminary),
        &mut observe_group,
    )
}

/// Compares final rows 15 onward after ordered orchestration has proved row 14.
pub(crate) fn compare_final_context_after_guards_v1(
    eligible: &EligiblePlanV1,
    preliminary: &ReadyPreparationContextV1,
    ready: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    compare_final_context_authority_after_guards_v1(eligible, ready)?;
    compare_context_replay_binding_v1(eligible, ready)?;
    compare_final_budget_v1(eligible, preliminary, ready)?;
    compare_final_recovery_profile_v1(eligible, preliminary, ready)?;
    Ok(())
}

/// Compares rows 15-21 after row 14 has been proved by live guard validation.
pub(crate) fn compare_final_context_authority_after_guards_v1(
    eligible: &EligiblePlanV1,
    ready: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    compare_final_context_authority_after_guards_instrumented_v1(eligible, ready, || {})
}

/// Compares final rows 15-21 and observes groups 6-12 only after row 14 has been
/// classified successfully by the live guard set.
pub(crate) fn compare_final_context_authority_after_guards_instrumented_v1<O>(
    eligible: &EligiblePlanV1,
    ready: &ReadyPreparationContextV1,
    mut observe_group: O,
) -> Result<(), PreparationDenialV1>
where
    O: FnMut(),
{
    compare_authority_after_guard_fields_instrumented_v1(eligible, ready, &mut observe_group)
}

/// Compares the carried replay identity at row 23. Ordered orchestration evaluates a
/// live `Missing` result (row 22) before calling this helper, then maps the remaining
/// verifier classifications at rows 23-25.
pub(crate) fn compare_context_replay_binding_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    if context.replay_claim_id() != bindings.replay_claim_id()
        || context.replay_claimant_generation() != bindings.replay_claimant_generation()
        || context.replay_binding_digest() != bindings.replay_binding_digest()
    {
        return Err(PreparationDenialV1::ReplayConflict);
    }
    Ok(())
}

pub(crate) fn compare_preliminary_budget_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    compare_signed_budget_v1(eligible, context)
}

pub(crate) fn compare_final_budget_v1(
    eligible: &EligiblePlanV1,
    preliminary: &ReadyPreparationContextV1,
    final_context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    compare_signed_budget_v1(eligible, final_context)?;
    compare_preparation_budget_authority_v1(preliminary, final_context)
}

pub(crate) fn compare_preliminary_recovery_profile_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    compare_recovery_shape_v1(eligible, context)
}

pub(crate) fn compare_final_recovery_profile_v1(
    eligible: &EligiblePlanV1,
    preliminary: &ReadyPreparationContextV1,
    final_context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    compare_recovery_shape_v1(eligible, final_context)?;
    compare_preparation_recovery_authority_v1(preliminary, final_context)
}

fn compare_context_completeness_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let recovery_class = eligible.authentic().preparation_claims().recovery_class();
    if !recovery_group_is_complete_v1(recovery_class, context.recovery_provider().is_some()) {
        return Err(PreparationDenialV1::ContextIncomplete);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compare_context_before_guard_groups_instrumented_v1<O>(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    context: PreparationContextV1,
    expected_phase: PreparationCapturePhaseV1,
    caller_deadline_monotonic_ms: u64,
    preliminary: Option<&ReadyPreparationContextV1>,
    observe_group: &mut O,
) -> ComparisonResult
where
    O: FnMut(),
{
    // Group 1 owns rows 1-5, including internal identity/capture coherence.
    let ready = classify_context_v1(context).and_then(|ready| {
        compare_context_completeness_v1(eligible, &ready)?;
        compare_context_identity_coherence_v1(eligible, attempt, &ready, expected_phase)?;
        Ok(ready)
    });
    let ready = observe_comparison_group_v1(ready, observe_group)?;

    // Groups 2-5 own rows 6-13. Row 14 belongs to live guard validation.
    observe_comparison_group_v1(
        compare_capture_generation_v1(eligible, &ready),
        observe_group,
    )?;
    observe_comparison_group_v1(
        compare_clock_and_utc_v1(eligible, &ready, preliminary),
        observe_group,
    )?;
    observe_comparison_group_v1(
        compare_deadline_v1(eligible, &ready, caller_deadline_monotonic_ms),
        observe_group,
    )?;
    observe_comparison_group_v1(
        compare_boot_and_supervisor_v1(eligible, &ready),
        observe_group,
    )?;
    Ok(ready)
}

fn observe_comparison_group_v1<T, O>(
    classified: Result<T, PreparationDenialV1>,
    observe_group: &mut O,
) -> Result<T, PreparationDenialV1>
where
    O: FnMut(),
{
    observe_group();
    classified
}

fn classify_context_v1(context: PreparationContextV1) -> ComparisonResult {
    match context {
        PreparationContextV1::Ready(ready) => {
            if ready.context_version() != PREPARATION_CONTEXT_VERSION_V1 {
                Err(PreparationDenialV1::VersionUnsupported)
            } else {
                Ok(ready)
            }
        }
        PreparationContextV1::Unavailable => Err(PreparationDenialV1::ContextUnavailable),
        PreparationContextV1::Incomplete => Err(PreparationDenialV1::ContextIncomplete),
        PreparationContextV1::Unsupported => Err(PreparationDenialV1::ContextUnsupported),
        PreparationContextV1::Torn => Err(PreparationDenialV1::ContextTorn),
    }
}

fn compare_context_identity_coherence_v1(
    eligible: &EligiblePlanV1,
    attempt: &PreparationAttemptIdV1,
    context: &ReadyPreparationContextV1,
    expected_phase: PreparationCapturePhaseV1,
) -> Result<(), PreparationDenialV1> {
    let claims = eligible.authentic().preparation_claims();
    if context.phase() != &expected_phase
        || context.plan_id() != claims.plan_id()
        || context.operation_id() != claims.operation_id()
        || context.task_id() != claims.task_id()
        || context.workload_id() != claims.workload_id()
        || context.attempt_id() != attempt.digest()
    {
        return Err(PreparationDenialV1::ContextTorn);
    }
    Ok(())
}

fn compare_capture_generation_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    if context.capture_generation() != eligible.bindings().capture_generation() {
        return Err(PreparationDenialV1::ContextMismatch);
    }
    Ok(())
}

fn compare_clock_and_utc_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
    preliminary: Option<&ReadyPreparationContextV1>,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    let bounds = eligible.bounds();
    if context.clock_generation() != bindings.clock_generation() {
        return Err(PreparationDenialV1::ClockMismatch);
    }
    if context.sampled_utc_ms() < bounds.evaluated_at_utc_unix_ms()
        || context.sampled_monotonic_ms() < bounds.evaluated_at_monotonic_ms()
        || preliminary.is_some_and(|earlier| {
            context.sampled_utc_ms() < earlier.sampled_utc_ms()
                || context.sampled_monotonic_ms() < earlier.sampled_monotonic_ms()
        })
    {
        return Err(PreparationDenialV1::ClockMismatch);
    }
    if !exclusive_bound_is_live_v1(
        context.sampled_utc_ms(),
        context.effective_expires_at_utc_ms(),
        bounds.effective_expires_at_utc_unix_ms(),
    ) {
        return Err(PreparationDenialV1::TimeExpired);
    }
    Ok(())
}

fn compare_deadline_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
    caller_deadline_monotonic_ms: u64,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    let bounds = eligible.bounds();
    if context.plan_deadline_generation() != bindings.plan_deadline_generation() {
        return Err(PreparationDenialV1::DeadlineMismatch);
    }
    let expected_deadline = bounds
        .effective_deadline_monotonic_ms()
        .min(caller_deadline_monotonic_ms);
    if !exclusive_bound_is_live_v1(
        context.sampled_monotonic_ms(),
        context.effective_deadline_monotonic_ms(),
        expected_deadline,
    ) {
        return Err(PreparationDenialV1::DeadlineReached);
    }
    Ok(())
}

fn compare_boot_and_supervisor_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let authentic = eligible.authentic();
    let eligibility_claims = authentic.eligibility_claims();
    let bindings = eligible.bindings();
    if context.boot_id() != eligibility_claims.boot_id() {
        return Err(PreparationDenialV1::BootMismatch);
    }
    if context.supervisor_admission_state() != SupervisorAdmissionStateV1::Open {
        return Err(PreparationDenialV1::SupervisorDenied);
    }
    if context.supervisor_generation() != bindings.supervisor_generation()
        || context.instance_epoch() != bindings.instance_epoch()
        || context.fencing_epoch() != bindings.fencing_epoch()
    {
        return Err(PreparationDenialV1::SupervisorMismatch);
    }
    Ok(())
}

fn compare_authority_after_guard_fields_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    compare_authority_after_guard_fields_instrumented_v1(eligible, context, &mut || {})
}

fn compare_authority_after_guard_fields_instrumented_v1<O>(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
    observe_group: &mut O,
) -> Result<(), PreparationDenialV1>
where
    O: FnMut(),
{
    observe_comparison_group_v1(compare_trust_v1(eligible, context), observe_group)?;
    observe_comparison_group_v1(compare_workload_v1(eligible, context), observe_group)?;
    observe_comparison_group_v1(compare_lease_v1(eligible, context), observe_group)?;
    observe_comparison_group_v1(compare_authorization_v1(eligible, context), observe_group)?;
    observe_comparison_group_v1(compare_policy_v1(eligible, context), observe_group)?;
    observe_comparison_group_v1(compare_catalogue_v1(eligible, context), observe_group)?;
    observe_comparison_group_v1(compare_capability_v1(eligible, context), observe_group)
}

fn compare_trust_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    if context.trust_generation() != bindings.trust_generation()
        || context.verified_key_fingerprint() != bindings.verified_key_fingerprint()
    {
        return Err(PreparationDenialV1::TrustMismatch);
    }
    Ok(())
}

fn compare_workload_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    if context.workload_generation() != bindings.workload_identity_generation()
        || context.workload_evidence_digest() != bindings.workload_evidence_digest()
    {
        return Err(PreparationDenialV1::WorkloadMismatch);
    }
    Ok(())
}

fn compare_lease_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    if context.lease_generation() != bindings.lease_generation()
        || context.lease_digest() != bindings.lease_digest()
        || context.lease_decision_digest() != bindings.lease_decision_digest()
    {
        return Err(PreparationDenialV1::LeaseMismatch);
    }
    Ok(())
}

fn compare_authorization_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    if context.authorization_generation() != bindings.authorization_generation()
        || context.authorization_evidence_digest() != bindings.authorization_evidence_digest()
    {
        return Err(PreparationDenialV1::AuthorizationMismatch);
    }
    Ok(())
}

fn compare_policy_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    if context.policy_generation() != bindings.policy_generation()
        || context.policy_decision_generation() != bindings.policy_decision_generation()
        || context.policy_content_digest() != bindings.policy_content_digest()
        || context.policy_decision_digest() != bindings.policy_decision_digest()
    {
        return Err(PreparationDenialV1::PolicyMismatch);
    }
    Ok(())
}

fn compare_catalogue_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    if context.catalogue_generation() != bindings.catalogue_generation()
        || context.catalogue_decision_generation() != bindings.catalogue_decision_generation()
        || context.catalogue_content_digest() != bindings.catalogue_content_digest()
        || context.catalogue_decision_digest() != bindings.catalogue_decision_digest()
    {
        return Err(PreparationDenialV1::CatalogueMismatch);
    }
    Ok(())
}

fn compare_capability_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let bindings = eligible.bindings();
    let bounds = eligible.bounds();
    if context.capability_report_generation() != bindings.capability_report_generation()
        || context.capability_report_digest() != bindings.capability_report_digest()
        || context.host_driver_context_digest() != bindings.host_driver_context_digest()
        || context.capability_observed_at_utc_ms() != bounds.capability_observed_at_unix_ms()
        || context.capability_max_age_ms() != bounds.capability_max_age_ms()
        || !context.capability_is_fresh_v1()
    {
        return Err(PreparationDenialV1::CapabilityMismatch);
    }
    Ok(())
}

fn recovery_group_is_complete_v1(recovery_class: RecoveryClassV1, provider_present: bool) -> bool {
    recovery_class != RecoveryClassV1::Compensation || provider_present
}

fn exclusive_bound_is_live_v1(sampled: u64, captured_bound: u64, expected_bound: u64) -> bool {
    captured_bound == expected_bound && sampled < expected_bound
}

fn compare_signed_budget_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let claims = eligible.authentic().preparation_claims();
    let signed = claims.budget();
    let requested = context.requested_budget();
    if context.budget_scope_generation() == 0
        || context.currency_code() != signed.currency_code()
        || context.price_table_id() != signed.price_table_id()
        || requested.max_cost_micro_units() != signed.max_cost_micro_units()
        || requested.action_limit() != signed.action_limit()
        || requested.egress_bytes_limit() != signed.egress_bytes_limit()
        || requested.recovery_bytes() != claims.recovery_reserved_bytes()
    {
        return Err(PreparationDenialV1::BudgetBindingConflict);
    }
    Ok(())
}

fn compare_recovery_shape_v1(
    eligible: &EligiblePlanV1,
    context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let recovery_class = eligible.authentic().preparation_claims().recovery_class();
    match (recovery_class, context.recovery_provider()) {
        (RecoveryClassV1::Compensation, Some(provider))
            if !provider.supports_create_only()
                || !provider.supports_sync()
                || !provider.supports_no_clobber_publication() =>
        {
            Err(PreparationDenialV1::RecoveryProfileUnapproved)
        }
        (RecoveryClassV1::Compensation, Some(provider)) if provider.provider_generation() == 0 => {
            Err(PreparationDenialV1::RecoveryBindingConflict)
        }
        (RecoveryClassV1::Irreversible, Some(_)) => {
            Err(PreparationDenialV1::RecoveryProfileUnapproved)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
fn compare_budget_before_recovery_v1<B, R>(
    compare_budget: B,
    compare_recovery: R,
) -> Result<(), PreparationDenialV1>
where
    B: FnOnce() -> Result<(), PreparationDenialV1>,
    R: FnOnce() -> Result<(), PreparationDenialV1>,
{
    compare_budget()?;
    compare_recovery()
}

fn compare_preparation_budget_authority_v1(
    preliminary: &ReadyPreparationContextV1,
    final_context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    let preliminary_budget = preliminary.requested_budget();
    let final_budget = final_context.requested_budget();
    if final_context.budget_scope_binding_digest() != preliminary.budget_scope_binding_digest()
        || final_context.budget_scope_generation() != preliminary.budget_scope_generation()
        || final_context.currency_code() != preliminary.currency_code()
        || final_context.price_table_id() != preliminary.price_table_id()
        || final_budget.max_cost_micro_units() != preliminary_budget.max_cost_micro_units()
        || final_budget.action_limit() != preliminary_budget.action_limit()
        || final_budget.egress_bytes_limit() != preliminary_budget.egress_bytes_limit()
        || final_budget.recovery_bytes() != preliminary_budget.recovery_bytes()
    {
        return Err(PreparationDenialV1::BudgetBindingConflict);
    }
    Ok(())
}

fn compare_preparation_recovery_authority_v1(
    preliminary: &ReadyPreparationContextV1,
    final_context: &ReadyPreparationContextV1,
) -> Result<(), PreparationDenialV1> {
    match (
        preliminary.recovery_provider(),
        final_context.recovery_provider(),
    ) {
        (None, None) => Ok(()),
        (Some(expected), Some(actual)) => {
            if actual.profile_id() != expected.profile_id()
                || actual.profile_version() != expected.profile_version()
                || actual.evidence_class() != expected.evidence_class()
                || actual.at_rest_profile_id() != expected.at_rest_profile_id()
                || actual.supports_create_only() != expected.supports_create_only()
                || actual.supports_sync() != expected.supports_sync()
                || actual.supports_no_clobber_publication()
                    != expected.supports_no_clobber_publication()
            {
                return Err(PreparationDenialV1::RecoveryProfileUnapproved);
            }
            if actual.provider_id() != expected.provider_id()
                || actual.provider_generation() != expected.provider_generation()
                || actual.capability_binding_digest() != expected.capability_binding_digest()
            {
                return Err(PreparationDenialV1::RecoveryBindingConflict);
            }
            Ok(())
        }
        _ => Err(PreparationDenialV1::RecoveryProfileUnapproved),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_context_v1, compare_budget_before_recovery_v1, exclusive_bound_is_live_v1,
        recovery_group_is_complete_v1,
    };
    use crate::context::PreparationContextV1;
    use crate::outcome::PreparationDenialV1;
    use helix_contracts::RecoveryClassV1;
    use std::cell::Cell;

    #[test]
    fn closed_negative_contexts_keep_their_distinct_early_codes() {
        for (context, expected) in [
            (
                PreparationContextV1::Unavailable,
                PreparationDenialV1::ContextUnavailable,
            ),
            (
                PreparationContextV1::Incomplete,
                PreparationDenialV1::ContextIncomplete,
            ),
            (
                PreparationContextV1::Unsupported,
                PreparationDenialV1::ContextUnsupported,
            ),
            (PreparationContextV1::Torn, PreparationDenialV1::ContextTorn),
        ] {
            assert_eq!(classify_context_v1(context).unwrap_err(), expected);
        }
    }

    #[test]
    fn exclusive_bounds_reject_equality_and_captured_bound_substitution() {
        assert!(exclusive_bound_is_live_v1(99, 100, 100));
        assert!(!exclusive_bound_is_live_v1(100, 100, 100));
        assert!(!exclusive_bound_is_live_v1(99, 101, 100));
    }

    #[test]
    fn missing_compensation_provider_wins_before_any_later_fault() {
        assert!(!recovery_group_is_complete_v1(
            RecoveryClassV1::Compensation,
            false,
        ));
        assert!(recovery_group_is_complete_v1(
            RecoveryClassV1::Irreversible,
            false,
        ));
    }

    #[test]
    fn final_budget_scope_fault_wins_without_evaluating_simultaneous_recovery_fault() {
        let recovery_was_evaluated = Cell::new(false);
        let outcome = compare_budget_before_recovery_v1(
            || Err(PreparationDenialV1::BudgetBindingConflict),
            || {
                recovery_was_evaluated.set(true);
                Err(PreparationDenialV1::RecoveryProfileUnapproved)
            },
        );

        assert_eq!(outcome, Err(PreparationDenialV1::BudgetBindingConflict));
        assert!(!recovery_was_evaluated.get());
    }
}
