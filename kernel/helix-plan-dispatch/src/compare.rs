//! Exact preliminary/final dispatch-authority comparison.

#![allow(dead_code)]

use crate::authority::{
    DispatchAuthorityCaptureOutcomeV1, DispatchAuthorityCapturePhaseV1,
    DispatchAuthorityProviderV1, DispatchAuthorityViewV1, ReadyDispatchContextV1,
    DISPATCH_AUTHORITY_VIEW_VERSION_V1,
};
use crate::guard::DispatchGuardSetV1;
use crate::{DispatchAttemptIdV1, DispatchLookupRequestV1};
use helix_dispatch_contracts::{Sha256Digest, MAX_SAFE_U64};
use std::fmt;

pub const EXECUTION_GRANT_MAX_LIFETIME_MS_V1: u64 = 5_000;
const DISPATCH_CONTEXT_DIGEST_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-CONTEXT\0V1\0";
const DISPATCH_AUTHORITY_DIGEST_FIELD_COUNT_V1: usize = 55;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchAuthorityComparisonErrorV1 {
    AuthorityUnavailable,
    AuthorityInconsistent,
    AuthorityRevoked,
    AuthorityUnsupported,
    PreliminaryPhaseRequired,
    FinalPhaseRequired,
    GuardedBindingMismatch,
    TimeRegression,
    CapacityExceeded,
    CapacityChanged,
    DeadlineInvalid,
    DeadlineReached,
    DeadlineArithmeticInvalid,
}

/// The exact four PLAN-004 signed budget dimensions retained by dispatch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DispatchCapacityVectorV1 {
    max_cost_micro_units: u64,
    action_limit: u64,
    egress_bytes_limit: u64,
    recovery_bytes: u64,
}

impl DispatchCapacityVectorV1 {
    pub fn try_new(
        max_cost_micro_units: u64,
        action_limit: u64,
        egress_bytes_limit: u64,
        recovery_bytes: u64,
    ) -> Result<Self, DispatchAuthorityComparisonErrorV1> {
        let values = [
            max_cost_micro_units,
            action_limit,
            egress_bytes_limit,
            recovery_bytes,
        ];
        if values.iter().any(|value| *value > MAX_SAFE_U64) {
            return Err(DispatchAuthorityComparisonErrorV1::CapacityExceeded);
        }
        Ok(Self {
            max_cost_micro_units,
            action_limit,
            egress_bytes_limit,
            recovery_bytes,
        })
    }

    pub(crate) const fn components_v1(self) -> [u64; 4] {
        [
            self.max_cost_micro_units,
            self.action_limit,
            self.egress_bytes_limit,
            self.recovery_bytes,
        ]
    }

    pub(crate) fn fits_within_v1(self, held: Self) -> bool {
        self.components_v1()
            .into_iter()
            .zip(held.components_v1())
            .all(|(required, retained)| required <= retained)
    }
}

impl fmt::Debug for DispatchCapacityVectorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchCapacityVectorV1")
            .finish_non_exhaustive()
    }
}

/// Preliminary authority retained with its exact digest and immutable grant deadline.
pub(crate) struct PreliminaryDispatchAuthorityV1 {
    view: DispatchAuthorityViewV1,
    preliminary_context_digest: Sha256Digest,
    grant_deadline_monotonic_ms: u64,
    required_capacity: DispatchCapacityVectorV1,
    held_capacity: DispatchCapacityVectorV1,
}

impl PreliminaryDispatchAuthorityV1 {
    pub(crate) const fn view(&self) -> &DispatchAuthorityViewV1 {
        &self.view
    }

    pub(crate) const fn preliminary_context_digest(&self) -> Sha256Digest {
        self.preliminary_context_digest
    }

    pub(crate) const fn grant_deadline_monotonic_ms(&self) -> u64 {
        self.grant_deadline_monotonic_ms
    }
}

impl fmt::Debug for PreliminaryDispatchAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreliminaryDispatchAuthorityV1")
            .finish_non_exhaustive()
    }
}

/// Final authority that passed exact mutation, capacity and exclusive-deadline checks.
pub(crate) struct VerifiedDispatchAuthorityV1 {
    final_view: DispatchAuthorityViewV1,
    preliminary_context_digest: Sha256Digest,
    final_context_digest: Sha256Digest,
    grant_deadline_monotonic_ms: u64,
}

impl VerifiedDispatchAuthorityV1 {
    pub(crate) const fn preliminary_context_digest(&self) -> Sha256Digest {
        self.preliminary_context_digest
    }

    pub(crate) const fn final_context_digest(&self) -> Sha256Digest {
        self.final_context_digest
    }

    pub(crate) const fn grant_deadline_monotonic_ms(&self) -> u64 {
        self.grant_deadline_monotonic_ms
    }

    pub(crate) fn into_ready_context_v1(
        self,
        request: DispatchLookupRequestV1,
        attempt: DispatchAttemptIdV1,
    ) -> ReadyDispatchContextV1 {
        ReadyDispatchContextV1::from_verified_reload(
            request,
            attempt,
            self.final_view,
            self.preliminary_context_digest,
            self.final_context_digest,
        )
    }
}

impl fmt::Debug for VerifiedDispatchAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDispatchAuthorityV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn capture_preliminary_authority_v1(
    provider: &dyn DispatchAuthorityProviderV1,
    request: &DispatchLookupRequestV1,
    attempt: &DispatchAttemptIdV1,
) -> Result<DispatchAuthorityViewV1, DispatchAuthorityComparisonErrorV1> {
    classify_capture_v1(provider.capture_authority_v1(
        DispatchAuthorityCapturePhaseV1::Preliminary,
        request,
        attempt,
    ))
}

pub(crate) fn capture_final_authority_v1<G: DispatchGuardSetV1>(
    guards: &mut G,
) -> Result<DispatchAuthorityViewV1, DispatchAuthorityComparisonErrorV1> {
    classify_capture_v1(guards.capture_final_authority_v1())
}

pub(crate) fn prepare_preliminary_authority_v1(
    view: DispatchAuthorityViewV1,
    caller_deadline_monotonic_ms: u64,
    required_capacity: DispatchCapacityVectorV1,
    held_capacity: DispatchCapacityVectorV1,
) -> Result<PreliminaryDispatchAuthorityV1, DispatchAuthorityComparisonErrorV1> {
    if view.phase() != DispatchAuthorityCapturePhaseV1::Preliminary {
        return Err(DispatchAuthorityComparisonErrorV1::PreliminaryPhaseRequired);
    }
    require_capacity_v1(required_capacity, held_capacity)?;
    let grant_deadline_monotonic_ms = effective_grant_deadline_v1(
        view.time().sampled_monotonic_ms(),
        earliest_authority_deadline_v1(&view),
        caller_deadline_monotonic_ms,
    )?;
    let preliminary_context_digest = authority_context_digest_v1(&view);
    Ok(PreliminaryDispatchAuthorityV1 {
        view,
        preliminary_context_digest,
        grant_deadline_monotonic_ms,
        required_capacity,
        held_capacity,
    })
}

pub(crate) fn compare_preliminary_and_final_authority_v1(
    preliminary: PreliminaryDispatchAuthorityV1,
    final_view: DispatchAuthorityViewV1,
    final_required_capacity: DispatchCapacityVectorV1,
    final_held_capacity: DispatchCapacityVectorV1,
    permit_deadline_monotonic_ms: u64,
) -> Result<VerifiedDispatchAuthorityV1, DispatchAuthorityComparisonErrorV1> {
    if final_view.phase() != DispatchAuthorityCapturePhaseV1::FinalGuarded {
        return Err(DispatchAuthorityComparisonErrorV1::FinalPhaseRequired);
    }
    if !preliminary.view.guarded_bindings_match(&final_view) {
        return Err(DispatchAuthorityComparisonErrorV1::GuardedBindingMismatch);
    }
    if final_view.time().sampled_monotonic_ms() < preliminary.view.time().sampled_monotonic_ms()
        || final_view.time().sampled_utc_ms() < preliminary.view.time().sampled_utc_ms()
    {
        return Err(DispatchAuthorityComparisonErrorV1::TimeRegression);
    }
    if final_required_capacity != preliminary.required_capacity
        || final_held_capacity != preliminary.held_capacity
    {
        return Err(DispatchAuthorityComparisonErrorV1::CapacityChanged);
    }
    require_capacity_v1(final_required_capacity, final_held_capacity)?;
    require_live_deadline_v1(
        final_view.time().sampled_monotonic_ms(),
        preliminary.grant_deadline_monotonic_ms,
    )?;
    require_live_deadline_v1(
        final_view.time().sampled_monotonic_ms(),
        permit_deadline_monotonic_ms,
    )?;
    let final_context_digest = authority_context_digest_v1(&final_view);
    Ok(VerifiedDispatchAuthorityV1 {
        final_view,
        preliminary_context_digest: preliminary.preliminary_context_digest,
        final_context_digest,
        grant_deadline_monotonic_ms: preliminary.grant_deadline_monotonic_ms,
    })
}

pub(crate) fn effective_grant_deadline_v1(
    issued_at_monotonic_ms: u64,
    earliest_authority_deadline_monotonic_ms: u64,
    caller_deadline_monotonic_ms: u64,
) -> Result<u64, DispatchAuthorityComparisonErrorV1> {
    if issued_at_monotonic_ms > MAX_SAFE_U64
        || earliest_authority_deadline_monotonic_ms == 0
        || earliest_authority_deadline_monotonic_ms > MAX_SAFE_U64
        || caller_deadline_monotonic_ms == 0
        || caller_deadline_monotonic_ms > MAX_SAFE_U64
    {
        return Err(DispatchAuthorityComparisonErrorV1::DeadlineInvalid);
    }
    let lifetime_ceiling = issued_at_monotonic_ms
        .checked_add(EXECUTION_GRANT_MAX_LIFETIME_MS_V1)
        .filter(|deadline| *deadline <= MAX_SAFE_U64)
        .ok_or(DispatchAuthorityComparisonErrorV1::DeadlineArithmeticInvalid)?;
    let deadline = lifetime_ceiling
        .min(earliest_authority_deadline_monotonic_ms)
        .min(caller_deadline_monotonic_ms);
    require_live_deadline_v1(issued_at_monotonic_ms, deadline)?;
    Ok(deadline)
}

fn classify_capture_v1(
    capture: DispatchAuthorityCaptureOutcomeV1,
) -> Result<DispatchAuthorityViewV1, DispatchAuthorityComparisonErrorV1> {
    match capture {
        DispatchAuthorityCaptureOutcomeV1::Captured(view) => Ok(*view),
        DispatchAuthorityCaptureOutcomeV1::Unavailable => {
            Err(DispatchAuthorityComparisonErrorV1::AuthorityUnavailable)
        }
        DispatchAuthorityCaptureOutcomeV1::Inconsistent => {
            Err(DispatchAuthorityComparisonErrorV1::AuthorityInconsistent)
        }
        DispatchAuthorityCaptureOutcomeV1::Revoked => {
            Err(DispatchAuthorityComparisonErrorV1::AuthorityRevoked)
        }
        DispatchAuthorityCaptureOutcomeV1::Unsupported => {
            Err(DispatchAuthorityComparisonErrorV1::AuthorityUnsupported)
        }
    }
}

fn require_capacity_v1(
    required: DispatchCapacityVectorV1,
    held: DispatchCapacityVectorV1,
) -> Result<(), DispatchAuthorityComparisonErrorV1> {
    required
        .fits_within_v1(held)
        .then_some(())
        .ok_or(DispatchAuthorityComparisonErrorV1::CapacityExceeded)
}

fn require_live_deadline_v1(
    sampled_monotonic_ms: u64,
    deadline_monotonic_ms: u64,
) -> Result<(), DispatchAuthorityComparisonErrorV1> {
    if deadline_monotonic_ms == 0 || deadline_monotonic_ms > MAX_SAFE_U64 {
        return Err(DispatchAuthorityComparisonErrorV1::DeadlineInvalid);
    }
    (sampled_monotonic_ms < deadline_monotonic_ms)
        .then_some(())
        .ok_or(DispatchAuthorityComparisonErrorV1::DeadlineReached)
}

fn earliest_authority_deadline_v1(view: &DispatchAuthorityViewV1) -> u64 {
    view.grant_projection()
        .earliest_authority_deadline_monotonic_ms
        .get()
}

fn authority_context_digest_v1(view: &DispatchAuthorityViewV1) -> Sha256Digest {
    let projection = view.grant_projection();
    let mut preimage = Vec::with_capacity(1_024);
    preimage.extend_from_slice(DISPATCH_CONTEXT_DIGEST_DOMAIN_V1);
    let mut field_count = 0_usize;

    macro_rules! append_bytes {
        ($value:expr) => {{
            let value: &[u8] = $value;
            preimage.extend_from_slice(&(value.len() as u32).to_be_bytes());
            preimage.extend_from_slice(value);
            field_count += 1;
        }};
    }
    macro_rules! append_u64 {
        ($value:expr) => {{
            preimage.extend_from_slice(&$value.to_be_bytes());
            field_count += 1;
        }};
    }
    macro_rules! append_digest {
        ($value:expr) => {{
            preimage.extend_from_slice($value.as_bytes());
            field_count += 1;
        }};
    }

    append_u64!(u64::from(DISPATCH_AUTHORITY_VIEW_VERSION_V1));
    append_u64!(match view.phase() {
        DispatchAuthorityCapturePhaseV1::Preliminary => 0_u64,
        DispatchAuthorityCapturePhaseV1::FinalGuarded => 1_u64,
    });
    append_bytes!(projection.boot_id.as_str().as_bytes());
    append_u64!(projection.clock_generation.get());
    append_u64!(projection.issued_at_utc_ms.get());
    append_u64!(projection.issued_at_monotonic_ms.get());
    append_bytes!(projection.task_id.as_str().as_bytes());
    append_bytes!(projection.workload_id.as_str().as_bytes());
    append_u64!(projection.instance_epoch.get());
    append_u64!(projection.supervisor_epoch.get());
    append_u64!(projection.supervisor_generation.get());
    append_u64!(projection.trust_generation.get());
    append_digest!(projection.verified_key_fingerprint);
    append_u64!(projection.workload_generation.get());
    append_digest!(projection.workload_evidence_digest);
    append_u64!(projection.lease_generation.get());
    append_digest!(projection.lease_digest);
    append_digest!(projection.lease_decision_digest);
    append_u64!(projection.authorization_generation.get());
    append_digest!(projection.authorization_evidence_digest);
    append_u64!(projection.policy_generation.get());
    append_u64!(projection.policy_decision_generation.get());
    append_digest!(projection.policy_content_digest);
    append_digest!(projection.policy_decision_digest);
    append_u64!(projection.catalogue_generation.get());
    append_u64!(projection.catalogue_decision_generation.get());
    append_digest!(projection.catalogue_content_digest);
    append_digest!(projection.catalogue_decision_digest);
    append_u64!(projection.capability_report_generation.get());
    append_digest!(projection.capability_report_digest);
    append_digest!(projection.host_driver_context_digest);
    append_u64!(projection.capability_observed_at_utc_ms.get());
    append_u64!(projection.capability_max_age_ms.get());
    append_digest!(projection.adapter_capability_digest);
    append_digest!(projection.replay_claim_id);
    append_u64!(projection.replay_claimant_generation.get());
    append_digest!(projection.replay_binding_digest);
    append_bytes!(projection.budget_scope_id.as_str().as_bytes());
    append_u64!(projection.budget_scope_generation.get());
    append_digest!(projection.budget_scope_binding_digest);
    append_bytes!(projection.reservation_id.as_str().as_bytes());
    append_u64!(projection.reservation_generation.get());
    append_digest!(projection.reservation_binding_digest);
    append_digest!(projection.reservation_vector_digest);
    append_digest!(projection.recovery_reference_digest);
    append_u64!(match projection.recovery_mode {
        helix_dispatch_contracts::RecoveryModeV1::Compensation => 0_u64,
        helix_dispatch_contracts::RecoveryModeV1::Irreversible => 1_u64,
    });
    append_digest!(projection.recovery_profile_digest);
    append_digest!(projection.recovery_binding_digest);
    append_digest!(projection.recovery_receipt_digest);
    append_bytes!(projection.destination_adapter_id.as_str().as_bytes());
    append_u64!(u64::from(projection.protocol_version));
    append_bytes!(projection.signer_key_id.as_str().as_bytes());
    append_u64!(projection.signer_generation.get());
    append_digest!(projection.signer_profile_digest);
    append_u64!(projection.earliest_authority_deadline_monotonic_ms.get());

    debug_assert_eq!(field_count, DISPATCH_AUTHORITY_DIGEST_FIELD_COUNT_V1);
    Sha256Digest::digest(&preimage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::tests::{view, view_with_sample};

    fn capacity(values: [u64; 4]) -> DispatchCapacityVectorV1 {
        DispatchCapacityVectorV1::try_new(values[0], values[1], values[2], values[3]).unwrap()
    }

    #[test]
    fn exact_capacity_deadline_equality_ceiling_and_overflow_are_closed() {
        let held = capacity([10, 20, 30, 40]);
        assert!(require_capacity_v1(held, held).is_ok());
        for index in 0..4 {
            let mut values = held.components_v1();
            values[index] += 1;
            assert_eq!(
                require_capacity_v1(capacity(values), held),
                Err(DispatchAuthorityComparisonErrorV1::CapacityExceeded)
            );
        }

        assert_eq!(effective_grant_deadline_v1(100, 8_000, 9_000), Ok(5_100));
        assert_eq!(effective_grant_deadline_v1(100, 4_000, 9_000), Ok(4_000));
        assert_eq!(effective_grant_deadline_v1(100, 8_000, 3_000), Ok(3_000));
        assert_eq!(
            effective_grant_deadline_v1(MAX_SAFE_U64 - 4_999, MAX_SAFE_U64, MAX_SAFE_U64),
            Err(DispatchAuthorityComparisonErrorV1::DeadlineArithmeticInvalid)
        );
        assert_eq!(
            require_live_deadline_v1(250, 250),
            Err(DispatchAuthorityComparisonErrorV1::DeadlineReached)
        );
    }

    #[test]
    fn final_digest_changes_with_fresh_samples_but_guarded_bindings_stay_exact() {
        let held = capacity([10, 20, 30, 40]);
        let preliminary = prepare_preliminary_authority_v1(
            view(DispatchAuthorityCapturePhaseV1::Preliminary, 30, 31, 4, 12),
            4_000,
            held,
            held,
        )
        .unwrap();
        let preliminary_digest = preliminary.preliminary_context_digest();
        let final_authority = compare_preliminary_and_final_authority_v1(
            preliminary,
            view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 30, 31, 4, 12),
            held,
            held,
            375,
        )
        .unwrap();
        assert_ne!(
            preliminary_digest,
            final_authority.final_context_digest(),
            "phase and fresh time samples are included in exact context digests"
        );
        assert_eq!(final_authority.grant_deadline_monotonic_ms(), 4_000);
    }

    #[test]
    fn final_mutation_and_changed_capacity_fail_closed() {
        let held = capacity([10, 20, 30, 40]);
        let preliminary = prepare_preliminary_authority_v1(
            view(DispatchAuthorityCapturePhaseV1::Preliminary, 30, 31, 4, 12),
            4_000,
            held,
            held,
        )
        .unwrap();
        assert!(matches!(
            compare_preliminary_and_final_authority_v1(
                preliminary,
                view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 30, 32, 4, 12),
                held,
                held,
                375,
            ),
            Err(DispatchAuthorityComparisonErrorV1::GuardedBindingMismatch)
        ));

        let preliminary = prepare_preliminary_authority_v1(
            view(DispatchAuthorityCapturePhaseV1::Preliminary, 30, 31, 4, 12),
            4_000,
            held,
            held,
        )
        .unwrap();
        assert!(matches!(
            compare_preliminary_and_final_authority_v1(
                preliminary,
                view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 30, 31, 4, 12),
                capacity([9, 20, 30, 40]),
                held,
                375,
            ),
            Err(DispatchAuthorityComparisonErrorV1::CapacityChanged)
        ));
    }

    #[test]
    fn final_atomic_time_capture_cannot_move_backward() {
        let held = capacity([10, 20, 30, 40]);
        let preliminary = prepare_preliminary_authority_v1(
            view(DispatchAuthorityCapturePhaseV1::Preliminary, 30, 31, 4, 12),
            4_000,
            held,
            held,
        )
        .unwrap();
        assert!(matches!(
            compare_preliminary_and_final_authority_v1(
                preliminary,
                view_with_sample(
                    DispatchAuthorityCapturePhaseV1::FinalGuarded,
                    30,
                    31,
                    4,
                    12,
                    99,
                ),
                held,
                held,
                375,
            ),
            Err(DispatchAuthorityComparisonErrorV1::TimeRegression)
        ));
    }
}
