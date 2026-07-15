//! Coordinator-owned dispatch identity, effect projection and exact grant construction.

#![allow(dead_code)]

use crate::authority::{DispatchAuthorityProviderV1, DispatchGrantAuthorityProjectionV1};
use crate::compare::{
    capture_final_authority_v1, capture_preliminary_authority_v1,
    compare_preliminary_and_final_authority_v1, prepare_preliminary_authority_v1,
    DispatchAuthorityComparisonErrorV1, DispatchCapacityVectorV1, PreliminaryDispatchAuthorityV1,
};
use crate::guard::{DispatchGuardSetV1, DispatchGuardValidationV1};
use crate::inbox::{
    DispatchInboxAdapterOutcomeV1, DispatchInboxConsumeOutcomeV1, DispatchInboxConsumerV1,
    DispatchInboxReadbackOutcomeV1, DispatchInboxReadbackV1, DispatchInboxReceiveOutcomeV1,
    DispatchInboxV1,
};
#[cfg(feature = "test-fault-injection")]
use crate::test_fault::FaultBoundaryV1;
use crate::{
    AmbiguousDispatchV1, DeniedDispatchV1, DispatchAmbiguityReasonV1, DispatchAttemptIdV1,
    DispatchCommitCandidateV1, DispatchCommitEvidenceV1, DispatchCommitPermitOutcomeV1,
    DispatchCommitPermitV1, DispatchCommitResolutionV1, DispatchCoordinatorStoreV1,
    DispatchDenialReasonV1, DispatchEntropyDomainV1, DispatchEntropySourceV1,
    DispatchFailureReasonV1, DispatchGrantSignerV1, DispatchGuardAcquisitionV1,
    DispatchGuardClassV1, DispatchGuardProviderV1, DispatchLookupRequestV1,
    DispatchReloadOutcomeV1, DispatchRequestOutcomeV1, DispatchStoreProjectionV1,
    DispatchStoreReadbackOutcomeV1, ExactSignedGrantV1, FailedDispatchV1, RetainedDispatchV1,
};
#[cfg(feature = "test-fault-injection")]
use crate::{DispatchFaultProbeV1, FaultInjectionDecisionV1};
use helix_dispatch_contracts::{
    ContractError, ExecutionGrantInputV1, ExecutionGrantProtectedV1, Generation, Identifier,
    ResourceRefV1, SafeU64, Sha256Digest,
};
use std::fmt;

const GRANT_ID_DERIVATION_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-GRANT-ID\0V1\0";
const NONCE_DERIVATION_DOMAIN_V1: &[u8] = b"HELIXOS\0DISPATCH-NONCE\0V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchCandidateBuildErrorV1 {
    EntropyUnavailable,
    EffectDescriptorInvalid,
    Authority(DispatchAuthorityComparisonErrorV1),
    GuardRevoked,
    GuardUnavailable,
    GuardDeadlineReached,
    GuardMismatch,
    SignerProfileMismatch,
    GrantContract(ContractError),
}

/// Effect-only projection loaded from durable PLAN-004 state. It contains no host handle.
pub struct DispatchEffectDescriptorInputV1 {
    pub operation_state_generation: u64,
    pub target: ResourceRefV1,
    pub precondition_digest: Sha256Digest,
    pub content_digest: Sha256Digest,
    pub content_byte_length: u64,
    pub content_media_type: String,
}

impl fmt::Debug for DispatchEffectDescriptorInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchEffectDescriptorInputV1")
            .finish_non_exhaustive()
    }
}

/// Checked descriptor used only to populate the closed execution-grant contract.
pub struct DispatchEffectDescriptorV1 {
    operation_state_generation: Generation,
    target: ResourceRefV1,
    precondition_digest: Sha256Digest,
    content_digest: Sha256Digest,
    content_byte_length: SafeU64,
    content_media_type: String,
}

impl DispatchEffectDescriptorV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_portable_parts(
        operation_state_generation: u64,
        target_root_id: &str,
        target_components: Vec<String>,
        precondition_digest: [u8; 32],
        content_digest: [u8; 32],
        content_byte_length: u64,
        content_media_type: String,
    ) -> Result<Self, DispatchCandidateBuildErrorV1> {
        let target = ResourceRefV1::try_new(target_root_id, target_components)
            .map_err(DispatchCandidateBuildErrorV1::GrantContract)?;
        Self::try_new(DispatchEffectDescriptorInputV1 {
            operation_state_generation,
            target,
            precondition_digest: Sha256Digest::from_bytes(precondition_digest),
            content_digest: Sha256Digest::from_bytes(content_digest),
            content_byte_length,
            content_media_type,
        })
    }

    pub fn try_new(
        input: DispatchEffectDescriptorInputV1,
    ) -> Result<Self, DispatchCandidateBuildErrorV1> {
        let operation_state_generation = Generation::new(input.operation_state_generation)
            .map_err(|_| DispatchCandidateBuildErrorV1::EffectDescriptorInvalid)?;
        let content_byte_length = SafeU64::new(input.content_byte_length)
            .map_err(|_| DispatchCandidateBuildErrorV1::EffectDescriptorInvalid)?;
        if input.content_media_type.is_empty() || input.content_media_type.len() > 127 {
            return Err(DispatchCandidateBuildErrorV1::EffectDescriptorInvalid);
        }
        Ok(Self {
            operation_state_generation,
            target: input.target,
            precondition_digest: input.precondition_digest,
            content_digest: input.content_digest,
            content_byte_length,
            content_media_type: input.content_media_type,
        })
    }
}

impl fmt::Debug for DispatchEffectDescriptorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchEffectDescriptorV1")
            .finish_non_exhaustive()
    }
}

/// Store-proved retained identity used only to classify an idempotent lookup.
#[derive(Clone, Copy)]
pub struct DispatchRetainedProjectionV1 {
    grant_id: [u8; 32],
    grant_digest: [u8; 32],
    state_generation: u64,
}

impl DispatchRetainedProjectionV1 {
    pub fn try_new(
        grant_id: [u8; 32],
        grant_digest: [u8; 32],
        state_generation: u64,
    ) -> Option<Self> {
        (grant_id != [0; 32]
            && grant_digest != [0; 32]
            && (1..=helix_dispatch_contracts::MAX_SAFE_U64).contains(&state_generation))
        .then_some(Self {
            grant_id,
            grant_digest,
            state_generation,
        })
    }
}

impl fmt::Debug for DispatchRetainedProjectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchRetainedProjectionV1")
            .finish_non_exhaustive()
    }
}

/// Trusted projection supplied only by the coordinator store after full durable reload.
///
/// The untrusted dispatch request never contains these values. Implementations must
/// derive them from the same verified snapshot represented by `self`.
pub trait DispatchReloadedCandidateV1: Send {
    fn effect_descriptor_v1(&self) -> Option<DispatchEffectDescriptorV1>;

    fn required_capacity_v1(&self) -> Option<DispatchCapacityVectorV1>;

    fn held_capacity_v1(&self) -> Option<DispatchCapacityVectorV1>;

    fn prior_dispatch_projection_v1(&self) -> Option<DispatchRetainedProjectionV1>;
}

struct CoordinatorDispatchIdentitiesV1 {
    attempt: DispatchAttemptIdV1,
    grant_id: Sha256Digest,
    one_shot_nonce: Sha256Digest,
}

impl CoordinatorDispatchIdentitiesV1 {
    fn generate_v1(
        entropy: &dyn DispatchEntropySourceV1,
    ) -> Result<Self, DispatchCandidateBuildErrorV1> {
        let attempt = DispatchAttemptIdV1::generate(entropy)
            .map_err(|_| DispatchCandidateBuildErrorV1::EntropyUnavailable)?;
        let grant_id = derive_entropy_digest_v1(
            entropy,
            DispatchEntropyDomainV1::GrantIdentity,
            GRANT_ID_DERIVATION_DOMAIN_V1,
            &attempt,
        )?;
        let one_shot_nonce = derive_entropy_digest_v1(
            entropy,
            DispatchEntropyDomainV1::OneShotNonce,
            NONCE_DERIVATION_DOMAIN_V1,
            &attempt,
        )?;
        Ok(Self {
            attempt,
            grant_id,
            one_shot_nonce,
        })
    }
}

impl fmt::Debug for CoordinatorDispatchIdentitiesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDispatchIdentitiesV1")
            .finish_non_exhaustive()
    }
}

/// Signed preliminary candidate that cannot enter the store until final guarded comparison.
pub(crate) struct PendingDispatchCandidateV1<R> {
    reloaded_state: R,
    request: DispatchLookupRequestV1,
    identities: CoordinatorDispatchIdentitiesV1,
    preliminary_authority: PreliminaryDispatchAuthorityV1,
    issued_at_monotonic_ms: u64,
    expected_protected_grant: ExecutionGrantProtectedV1,
    exact_grant: ExactSignedGrantV1,
}

impl<R> PendingDispatchCandidateV1<R> {
    pub(crate) const fn attempt(&self) -> &DispatchAttemptIdV1 {
        &self.identities.attempt
    }

    pub(crate) const fn preliminary_context_digest(&self) -> Sha256Digest {
        self.preliminary_authority.preliminary_context_digest()
    }

    pub(crate) const fn grant_deadline_monotonic_ms(&self) -> u64 {
        self.preliminary_authority.grant_deadline_monotonic_ms()
    }

    pub(crate) const fn exact_grant(&self) -> &ExactSignedGrantV1 {
        &self.exact_grant
    }

    pub(crate) fn finalize_with_guards_v1<G: DispatchGuardSetV1>(
        self,
        guards: &mut G,
        final_required_capacity: DispatchCapacityVectorV1,
        final_held_capacity: DispatchCapacityVectorV1,
        permit_deadline_monotonic_ms: u64,
    ) -> Result<DispatchCommitCandidateV1<R>, DispatchCandidateBuildErrorV1> {
        let final_view =
            capture_final_authority_v1(guards).map_err(DispatchCandidateBuildErrorV1::Authority)?;
        match guards.validate_all_v1(final_view.time().sampled_monotonic_ms()) {
            DispatchGuardValidationV1::Valid => {}
            DispatchGuardValidationV1::Revoked => {
                return Err(DispatchCandidateBuildErrorV1::GuardRevoked);
            }
            DispatchGuardValidationV1::Unavailable => {
                return Err(DispatchCandidateBuildErrorV1::GuardUnavailable);
            }
            DispatchGuardValidationV1::DeadlineReached => {
                return Err(DispatchCandidateBuildErrorV1::GuardDeadlineReached);
            }
            DispatchGuardValidationV1::Mismatch => {
                return Err(DispatchCandidateBuildErrorV1::GuardMismatch);
            }
        }
        self.finalize_v1(
            final_view,
            final_required_capacity,
            final_held_capacity,
            permit_deadline_monotonic_ms,
        )
    }

    pub(crate) fn finalize_v1(
        self,
        final_view: crate::DispatchAuthorityViewV1,
        final_required_capacity: DispatchCapacityVectorV1,
        final_held_capacity: DispatchCapacityVectorV1,
        permit_deadline_monotonic_ms: u64,
    ) -> Result<DispatchCommitCandidateV1<R>, DispatchCandidateBuildErrorV1> {
        let Self {
            reloaded_state,
            request,
            identities,
            preliminary_authority,
            issued_at_monotonic_ms,
            expected_protected_grant,
            exact_grant,
        } = self;
        let effective_deadline_monotonic_ms = preliminary_authority.grant_deadline_monotonic_ms();
        exact_grant
            .signed()
            .protected()
            .validate_exact_bindings(&expected_protected_grant)
            .map_err(DispatchCandidateBuildErrorV1::GrantContract)?;
        let verified = compare_preliminary_and_final_authority_v1(
            preliminary_authority,
            final_view,
            final_required_capacity,
            final_held_capacity,
            permit_deadline_monotonic_ms,
        )
        .map_err(DispatchCandidateBuildErrorV1::Authority)?;
        let context = verified.into_ready_context_v1(request, identities.attempt);
        let authority = context.grant_authority_projection();
        let destination_binding_digest = destination_binding_digest_v1(
            authority.destination_adapter_id.as_str(),
            authority.protocol_version,
            authority.adapter_capability_digest,
        );
        let store_projection = DispatchStoreProjectionV1 {
            preparation_attempt_id: *context.request().expected_preparation_attempt_digest(),
            preparation_transition_generation: context
                .request()
                .expected_preparation_transition_generation(),
            plan_id: *context.request().expected_plan_digest(),
            task_id: authority.task_id.as_str().into(),
            workload_id: authority.workload_id.as_str().into(),
            task_lease_digest: *authority.lease_digest.as_bytes(),
            reservation_id: authority.reservation_id.as_str().into(),
            boot_id: authority.boot_id.as_str().into(),
            instance_epoch: authority.instance_epoch.get(),
            supervisor_epoch: authority.supervisor_epoch.get(),
            one_shot_nonce: *identities.one_shot_nonce.as_bytes(),
            preliminary_context_digest: *context.preliminary_context_digest().as_bytes(),
            final_context_digest: *context.final_context_digest().as_bytes(),
            authority_vector_digest: *context.final_context_digest().as_bytes(),
            destination_binding_digest: *destination_binding_digest.as_bytes(),
            signer_profile_digest: *authority.signer_profile_digest.as_bytes(),
            signer_key_id: authority.signer_key_id.as_str().into(),
            signer_key_fingerprint: *authority.signer_profile_digest.as_bytes(),
            destination_adapter_id: authority.destination_adapter_id.as_str().into(),
            protocol_version: authority.protocol_version,
            sampled_utc_ms: authority.issued_at_utc_ms.get(),
            sampled_monotonic_ms: authority.issued_at_monotonic_ms.get(),
            issued_at_monotonic_ms,
            effective_deadline_monotonic_ms,
        };
        Ok(DispatchCommitCandidateV1::from_verified_parts(
            reloaded_state,
            context,
            store_projection,
            exact_grant,
        ))
    }
}

impl<R> fmt::Debug for PendingDispatchCandidateV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingDispatchCandidateV1")
            .finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments, clippy::needless_return)]
pub(crate) fn build_preliminary_dispatch_candidate_v1<R, S>(
    reloaded_state: R,
    request: DispatchLookupRequestV1,
    authority_provider: &dyn DispatchAuthorityProviderV1,
    entropy: &dyn DispatchEntropySourceV1,
    signer: &S,
    effect: DispatchEffectDescriptorV1,
    required_capacity: DispatchCapacityVectorV1,
    held_capacity: DispatchCapacityVectorV1,
) -> Result<PendingDispatchCandidateV1<R>, DispatchCandidateBuildErrorV1>
where
    S: DispatchGrantSignerV1,
{
    #[cfg(feature = "test-fault-injection")]
    {
        let fault_probe = DispatchFaultProbeV1::disabled_v1();
        return build_preliminary_dispatch_candidate_inner_v1(
            reloaded_state,
            request,
            authority_provider,
            entropy,
            signer,
            effect,
            required_capacity,
            held_capacity,
            &fault_probe,
        );
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        return build_preliminary_dispatch_candidate_inner_v1(
            reloaded_state,
            request,
            authority_provider,
            entropy,
            signer,
            effect,
            required_capacity,
            held_capacity,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn build_preliminary_dispatch_candidate_inner_v1<R, S>(
    reloaded_state: R,
    request: DispatchLookupRequestV1,
    authority_provider: &dyn DispatchAuthorityProviderV1,
    entropy: &dyn DispatchEntropySourceV1,
    signer: &S,
    effect: DispatchEffectDescriptorV1,
    required_capacity: DispatchCapacityVectorV1,
    held_capacity: DispatchCapacityVectorV1,
    #[cfg(feature = "test-fault-injection")] fault_probe: &DispatchFaultProbeV1,
) -> Result<PendingDispatchCandidateV1<R>, DispatchCandidateBuildErrorV1>
where
    S: DispatchGrantSignerV1,
{
    let identities = CoordinatorDispatchIdentitiesV1::generate_v1(entropy)?;
    let preliminary_view =
        capture_preliminary_authority_v1(authority_provider, &request, &identities.attempt)
            .map_err(DispatchCandidateBuildErrorV1::Authority)?;
    #[cfg(feature = "test-fault-injection")]
    if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb002)
        || portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb003)
    {
        return Err(DispatchCandidateBuildErrorV1::GuardUnavailable);
    }
    let preliminary_authority = prepare_preliminary_authority_v1(
        preliminary_view,
        request.caller_deadline_monotonic_ms(),
        required_capacity,
        held_capacity,
    )
    .map_err(DispatchCandidateBuildErrorV1::Authority)?;
    if signer.key_id() != preliminary_authority.view().signer_key_id() {
        return Err(DispatchCandidateBuildErrorV1::SignerProfileMismatch);
    }
    let protected = build_protected_grant_v1(
        &request,
        &identities,
        preliminary_authority.view().grant_projection(),
        preliminary_authority.grant_deadline_monotonic_ms(),
        effect,
    )?;
    #[cfg(feature = "test-fault-injection")]
    if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb004) {
        return Err(DispatchCandidateBuildErrorV1::GuardUnavailable);
    }
    let issued_at_monotonic_ms = preliminary_authority.view().time().sampled_monotonic_ms();
    let expected_protected_grant = protected.clone();
    let exact_grant = signer
        .sign_grant_v1(protected)
        .map_err(DispatchCandidateBuildErrorV1::GrantContract)?;
    #[cfg(feature = "test-fault-injection")]
    if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb005) {
        return Err(DispatchCandidateBuildErrorV1::GuardUnavailable);
    }
    Ok(PendingDispatchCandidateV1 {
        reloaded_state,
        request,
        identities,
        preliminary_authority,
        issued_at_monotonic_ms,
        expected_protected_grant,
        exact_grant,
    })
}

/// Executes one complete no-delivery dispatch request through trusted injected seams.
///
/// The only caller input is `DispatchLookupRequestV1`. Positive effect, capacity and
/// prior-dispatch projections come from the store's fully reloaded state. Exact signed
/// bytes commit under a consuming permit; uncertainty is resolved once by exact store
/// readback and never causes signing or commit retry.
#[allow(clippy::too_many_arguments, clippy::needless_return)]
pub fn dispatch_prepared_once_v1<S, A, E, K, G>(
    store: &S,
    request: DispatchLookupRequestV1,
    authority_provider: &A,
    entropy: &E,
    signer: &K,
    guard_provider: &G,
) -> DispatchRequestOutcomeV1
where
    S: DispatchCoordinatorStoreV1,
    S::ReloadedState: DispatchReloadedCandidateV1,
    A: DispatchAuthorityProviderV1,
    E: DispatchEntropySourceV1,
    K: DispatchGrantSignerV1,
    G: DispatchGuardProviderV1,
{
    #[cfg(feature = "test-fault-injection")]
    {
        let fault_probe = DispatchFaultProbeV1::disabled_v1();
        return dispatch_prepared_once_inner_v1(
            store,
            request,
            authority_provider,
            entropy,
            signer,
            guard_provider,
            &fault_probe,
        );
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        return dispatch_prepared_once_inner_v1(
            store,
            request,
            authority_provider,
            entropy,
            signer,
            guard_provider,
        );
    }
}

/// Runs the production dispatch path with one caller-owned non-default fault selection.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_prepared_once_with_fault_probe_v1<S, A, E, K, G>(
    store: &S,
    request: DispatchLookupRequestV1,
    authority_provider: &A,
    entropy: &E,
    signer: &K,
    guard_provider: &G,
    fault_probe: &DispatchFaultProbeV1,
) -> DispatchRequestOutcomeV1
where
    S: DispatchCoordinatorStoreV1,
    S::ReloadedState: DispatchReloadedCandidateV1,
    A: DispatchAuthorityProviderV1,
    E: DispatchEntropySourceV1,
    K: DispatchGrantSignerV1,
    G: DispatchGuardProviderV1,
{
    dispatch_prepared_once_inner_v1(
        store,
        request,
        authority_provider,
        entropy,
        signer,
        guard_provider,
        fault_probe,
    )
}

#[allow(clippy::too_many_arguments)]
fn dispatch_prepared_once_inner_v1<S, A, E, K, G>(
    store: &S,
    request: DispatchLookupRequestV1,
    authority_provider: &A,
    entropy: &E,
    signer: &K,
    guard_provider: &G,
    #[cfg(feature = "test-fault-injection")] fault_probe: &DispatchFaultProbeV1,
) -> DispatchRequestOutcomeV1
where
    S: DispatchCoordinatorStoreV1,
    S::ReloadedState: DispatchReloadedCandidateV1,
    A: DispatchAuthorityProviderV1,
    E: DispatchEntropySourceV1,
    K: DispatchGrantSignerV1,
    G: DispatchGuardProviderV1,
{
    let reloaded = match store.reload_authoritative_v1(&request) {
        DispatchReloadOutcomeV1::Ready(reloaded) => reloaded,
        DispatchReloadOutcomeV1::PriorExactDispatch(reloaded) => {
            return reloaded.prior_dispatch_projection_v1().map_or_else(
                || ambiguous_outcome_v1(DispatchAmbiguityReasonV1::ReadbackInconsistent, [0; 32]),
                |prior| {
                    DispatchRequestOutcomeV1::AlreadyDispatched(retained_from_projection_v1(prior))
                },
            );
        }
        DispatchReloadOutcomeV1::Missing => {
            return denied_outcome_v1(DispatchDenialReasonV1::OperationMissing);
        }
        DispatchReloadOutcomeV1::Restored
        | DispatchReloadOutcomeV1::Quarantined
        | DispatchReloadOutcomeV1::Failed => {
            return denied_outcome_v1(DispatchDenialReasonV1::OperationNotCurrent);
        }
        DispatchReloadOutcomeV1::Conflict => {
            return denied_outcome_v1(DispatchDenialReasonV1::ExpectedBindingMismatch);
        }
        DispatchReloadOutcomeV1::Unavailable => {
            return failed_outcome_v1(DispatchFailureReasonV1::StoreUnavailable);
        }
        DispatchReloadOutcomeV1::Unhealthy => {
            return failed_outcome_v1(DispatchFailureReasonV1::StoreUnhealthy);
        }
        DispatchReloadOutcomeV1::UnsupportedVersion => {
            return denied_outcome_v1(DispatchDenialReasonV1::VersionUnsupported);
        }
    };
    let effect = match reloaded.effect_descriptor_v1() {
        Some(effect) => effect,
        None => return denied_outcome_v1(DispatchDenialReasonV1::AuthorityMismatch),
    };
    let required_capacity = match reloaded.required_capacity_v1() {
        Some(capacity) => capacity,
        None => return denied_outcome_v1(DispatchDenialReasonV1::CapacityExceeded),
    };
    let held_capacity = match reloaded.held_capacity_v1() {
        Some(capacity) => capacity,
        None => return denied_outcome_v1(DispatchDenialReasonV1::CapacityExceeded),
    };
    let pending = match build_preliminary_dispatch_candidate_inner_v1(
        reloaded,
        request,
        authority_provider,
        entropy,
        signer,
        effect,
        required_capacity,
        held_capacity,
        #[cfg(feature = "test-fault-injection")]
        fault_probe,
    ) {
        Ok(pending) => pending,
        Err(error) => return map_candidate_error_v1(error),
    };
    let attempt_id = *pending.attempt().as_bytes();
    let ordered = DispatchGuardClassV1::acquisition_order();
    let mut observed = 0_usize;
    let mut observe_order = |guard_class| {
        if ordered.get(observed).copied() != Some(guard_class) {
            return Err(crate::DispatchGuardOrderErrorV1::UnexpectedClass);
        }
        observed += 1;
        Ok(())
    };
    let mut guards = match guard_provider.acquire_in_fixed_order_v1(
        &pending.request,
        pending.attempt(),
        &mut observe_order,
    ) {
        DispatchGuardAcquisitionV1::Acquired(guards) => guards,
        DispatchGuardAcquisitionV1::Unavailable => {
            return denied_outcome_v1(DispatchDenialReasonV1::AuthorityUnavailable);
        }
        DispatchGuardAcquisitionV1::DeadlineReached => {
            return denied_outcome_v1(DispatchDenialReasonV1::DeadlineReached);
        }
        DispatchGuardAcquisitionV1::Revoked | DispatchGuardAcquisitionV1::OrderViolated => {
            return denied_outcome_v1(DispatchDenialReasonV1::GuardRevoked);
        }
        DispatchGuardAcquisitionV1::Unsupported => {
            return denied_outcome_v1(DispatchDenialReasonV1::AuthorityMismatch);
        }
    };
    if observed != DispatchGuardClassV1::COUNT {
        guards.release_reverse_v1();
        return denied_outcome_v1(DispatchDenialReasonV1::GuardRevoked);
    }
    let permit = match guards
        .acquire_commit_permit_v1(pending.attempt(), pending.grant_deadline_monotonic_ms())
    {
        DispatchCommitPermitOutcomeV1::Permitted(permit) => permit,
        DispatchCommitPermitOutcomeV1::Unavailable => {
            guards.release_reverse_v1();
            return denied_outcome_v1(DispatchDenialReasonV1::AuthorityUnavailable);
        }
        DispatchCommitPermitOutcomeV1::DeadlineReached => {
            guards.release_reverse_v1();
            return denied_outcome_v1(DispatchDenialReasonV1::DeadlineReached);
        }
        DispatchCommitPermitOutcomeV1::Revoked => {
            guards.release_reverse_v1();
            return denied_outcome_v1(DispatchDenialReasonV1::GuardRevoked);
        }
        DispatchCommitPermitOutcomeV1::Unsupported => {
            guards.release_reverse_v1();
            return denied_outcome_v1(DispatchDenialReasonV1::AuthorityMismatch);
        }
    };
    #[cfg(feature = "test-fault-injection")]
    if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb006) {
        permit.abandon_v1();
        guards.release_reverse_v1();
        return failed_outcome_v1(DispatchFailureReasonV1::StoreUnavailable);
    }
    let permit_deadline = permit.deadline_monotonic_ms();
    let candidate = match pending.finalize_with_guards_v1(
        &mut guards,
        required_capacity,
        held_capacity,
        permit_deadline,
    ) {
        Ok(candidate) => candidate,
        Err(error) => {
            permit.abandon_v1();
            guards.release_reverse_v1();
            return map_candidate_error_v1(error);
        }
    };
    #[cfg(feature = "test-fault-injection")]
    if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb007) {
        permit.abandon_v1();
        guards.release_reverse_v1();
        return failed_outcome_v1(DispatchFailureReasonV1::StoreUnavailable);
    }
    let resolution = permit.commit_once(|| store.commit_candidate_once_v1(candidate));
    guards.release_reverse_v1();
    match resolution {
        DispatchCommitResolutionV1::Committed(receipt) => {
            DispatchRequestOutcomeV1::Dispatched(retained_from_evidence_v1(&receipt))
        }
        DispatchCommitResolutionV1::PriorExactDispatch(receipt) => {
            DispatchRequestOutcomeV1::AlreadyDispatched(retained_from_evidence_v1(&receipt))
        }
        DispatchCommitResolutionV1::ConfirmedRollback => {
            failed_outcome_v1(DispatchFailureReasonV1::CommitAborted)
        }
        DispatchCommitResolutionV1::Uncertain(custody) => {
            match store.readback_uncertain_v1(custody) {
                DispatchStoreReadbackOutcomeV1::ThisAttemptCommitted(evidence) => {
                    DispatchRequestOutcomeV1::Dispatched(retained_from_evidence_v1(&evidence))
                }
                DispatchStoreReadbackOutcomeV1::PriorExactDispatch(evidence) => {
                    DispatchRequestOutcomeV1::AlreadyDispatched(retained_from_evidence_v1(
                        &evidence,
                    ))
                }
                DispatchStoreReadbackOutcomeV1::DefinitelyAbsent => {
                    failed_outcome_v1(DispatchFailureReasonV1::CommitAborted)
                }
                DispatchStoreReadbackOutcomeV1::Conflict
                | DispatchStoreReadbackOutcomeV1::Unhealthy => ambiguous_outcome_v1(
                    DispatchAmbiguityReasonV1::ReadbackInconsistent,
                    attempt_id,
                ),
                DispatchStoreReadbackOutcomeV1::Unavailable => {
                    ambiguous_outcome_v1(DispatchAmbiguityReasonV1::ReadbackUnavailable, attempt_id)
                }
            }
        }
        DispatchCommitResolutionV1::Conflict => {
            ambiguous_outcome_v1(DispatchAmbiguityReasonV1::ReadbackInconsistent, attempt_id)
        }
        DispatchCommitResolutionV1::Revoked => {
            denied_outcome_v1(DispatchDenialReasonV1::GuardRevoked)
        }
        DispatchCommitResolutionV1::Unavailable => {
            failed_outcome_v1(DispatchFailureReasonV1::StoreUnavailable)
        }
        DispatchCommitResolutionV1::DeadlineReached => {
            denied_outcome_v1(DispatchDenialReasonV1::DeadlineReached)
        }
        DispatchCommitResolutionV1::Ambiguous => {
            ambiguous_outcome_v1(DispatchAmbiguityReasonV1::PermitOwnerLost, attempt_id)
        }
        DispatchCommitResolutionV1::Unclassified => {
            ambiguous_outcome_v1(DispatchAmbiguityReasonV1::ReadbackInconsistent, attempt_id)
        }
    }
}

fn retained_from_projection_v1(projection: DispatchRetainedProjectionV1) -> RetainedDispatchV1 {
    RetainedDispatchV1::from_verified_store_v1(
        projection.grant_id,
        projection.grant_digest,
        projection.state_generation,
    )
}

fn retained_from_evidence_v1(evidence: &impl DispatchCommitEvidenceV1) -> RetainedDispatchV1 {
    RetainedDispatchV1::from_verified_store_v1(
        evidence.grant_id_v1(),
        evidence.grant_digest_v1(),
        evidence.state_generation_v1(),
    )
}

fn denied_outcome_v1(reason: DispatchDenialReasonV1) -> DispatchRequestOutcomeV1 {
    DispatchRequestOutcomeV1::Denied(DeniedDispatchV1::from_reason_v1(reason))
}

fn failed_outcome_v1(reason: DispatchFailureReasonV1) -> DispatchRequestOutcomeV1 {
    DispatchRequestOutcomeV1::Failed(FailedDispatchV1::from_reason_v1(reason))
}

fn ambiguous_outcome_v1(
    reason: DispatchAmbiguityReasonV1,
    attempt_id: [u8; 32],
) -> DispatchRequestOutcomeV1 {
    DispatchRequestOutcomeV1::Ambiguous(AmbiguousDispatchV1::from_reason_v1(reason, attempt_id))
}

fn map_candidate_error_v1(error: DispatchCandidateBuildErrorV1) -> DispatchRequestOutcomeV1 {
    match error {
        DispatchCandidateBuildErrorV1::EntropyUnavailable
        | DispatchCandidateBuildErrorV1::GrantContract(_)
        | DispatchCandidateBuildErrorV1::SignerProfileMismatch => {
            failed_outcome_v1(DispatchFailureReasonV1::SigningFailed)
        }
        DispatchCandidateBuildErrorV1::EffectDescriptorInvalid
        | DispatchCandidateBuildErrorV1::Authority(
            DispatchAuthorityComparisonErrorV1::GuardedBindingMismatch
            | DispatchAuthorityComparisonErrorV1::CapacityChanged,
        )
        | DispatchCandidateBuildErrorV1::GuardMismatch => {
            denied_outcome_v1(DispatchDenialReasonV1::AuthorityMismatch)
        }
        DispatchCandidateBuildErrorV1::Authority(
            DispatchAuthorityComparisonErrorV1::CapacityExceeded,
        ) => denied_outcome_v1(DispatchDenialReasonV1::CapacityExceeded),
        DispatchCandidateBuildErrorV1::Authority(
            DispatchAuthorityComparisonErrorV1::DeadlineReached
            | DispatchAuthorityComparisonErrorV1::DeadlineInvalid
            | DispatchAuthorityComparisonErrorV1::DeadlineArithmeticInvalid
            | DispatchAuthorityComparisonErrorV1::TimeRegression,
        )
        | DispatchCandidateBuildErrorV1::GuardDeadlineReached => {
            denied_outcome_v1(DispatchDenialReasonV1::DeadlineReached)
        }
        DispatchCandidateBuildErrorV1::Authority(
            DispatchAuthorityComparisonErrorV1::AuthorityUnavailable,
        )
        | DispatchCandidateBuildErrorV1::GuardUnavailable => {
            denied_outcome_v1(DispatchDenialReasonV1::AuthorityUnavailable)
        }
        DispatchCandidateBuildErrorV1::Authority(
            DispatchAuthorityComparisonErrorV1::AuthorityInconsistent
            | DispatchAuthorityComparisonErrorV1::AuthorityRevoked
            | DispatchAuthorityComparisonErrorV1::AuthorityUnsupported
            | DispatchAuthorityComparisonErrorV1::PreliminaryPhaseRequired
            | DispatchAuthorityComparisonErrorV1::FinalPhaseRequired,
        )
        | DispatchCandidateBuildErrorV1::GuardRevoked => {
            denied_outcome_v1(DispatchDenialReasonV1::GuardRevoked)
        }
    }
}

fn build_protected_grant_v1(
    request: &DispatchLookupRequestV1,
    identities: &CoordinatorDispatchIdentitiesV1,
    authority: DispatchGrantAuthorityProjectionV1<'_>,
    grant_deadline_monotonic_ms: u64,
    effect: DispatchEffectDescriptorV1,
) -> Result<ExecutionGrantProtectedV1, DispatchCandidateBuildErrorV1> {
    let operation_id = Identifier::new(request.operation_id())
        .map_err(DispatchCandidateBuildErrorV1::GrantContract)?;
    let preparation_transition_generation =
        Generation::new(request.expected_preparation_transition_generation())
            .map_err(DispatchCandidateBuildErrorV1::GrantContract)?;
    let deadline_monotonic_ms = Generation::new(grant_deadline_monotonic_ms)
        .map_err(DispatchCandidateBuildErrorV1::GrantContract)?;
    let input = ExecutionGrantInputV1 {
        grant_id: identities.grant_id,
        dispatch_attempt_id: identities.attempt.digest(),
        one_shot_nonce: identities.one_shot_nonce,
        operation_id,
        operation_state_generation: effect.operation_state_generation,
        preparation_attempt_id: Sha256Digest::from_bytes(
            *request.expected_preparation_attempt_digest(),
        ),
        preparation_transition_generation,
        plan_id: Sha256Digest::from_bytes(*request.expected_plan_digest()),
        task_id: authority.task_id.clone(),
        workload_id: authority.workload_id.clone(),
        target: effect.target,
        precondition_digest: effect.precondition_digest,
        content_digest: effect.content_digest,
        content_byte_length: effect.content_byte_length,
        content_media_type: effect.content_media_type,
        trust_generation: authority.trust_generation,
        verified_key_fingerprint: authority.verified_key_fingerprint,
        workload_generation: authority.workload_generation,
        workload_evidence_digest: authority.workload_evidence_digest,
        lease_generation: authority.lease_generation,
        lease_digest: authority.lease_digest,
        lease_decision_digest: authority.lease_decision_digest,
        authorization_generation: authority.authorization_generation,
        authorization_evidence_digest: authority.authorization_evidence_digest,
        policy_generation: authority.policy_generation,
        policy_decision_generation: authority.policy_decision_generation,
        policy_content_digest: authority.policy_content_digest,
        policy_decision_digest: authority.policy_decision_digest,
        catalogue_generation: authority.catalogue_generation,
        catalogue_decision_generation: authority.catalogue_decision_generation,
        catalogue_content_digest: authority.catalogue_content_digest,
        catalogue_decision_digest: authority.catalogue_decision_digest,
        capability_report_generation: authority.capability_report_generation,
        capability_report_digest: authority.capability_report_digest,
        host_driver_context_digest: authority.host_driver_context_digest,
        capability_observed_at_utc_ms: authority.capability_observed_at_utc_ms,
        capability_max_age_ms: authority.capability_max_age_ms,
        adapter_capability_digest: authority.adapter_capability_digest,
        replay_claim_id: authority.replay_claim_id,
        replay_claimant_generation: authority.replay_claimant_generation,
        replay_binding_digest: authority.replay_binding_digest,
        budget_scope_id: authority.budget_scope_id.clone(),
        budget_scope_generation: authority.budget_scope_generation,
        budget_scope_binding_digest: authority.budget_scope_binding_digest,
        reservation_id: authority.reservation_id.clone(),
        reservation_generation: authority.reservation_generation,
        reservation_binding_digest: authority.reservation_binding_digest,
        reservation_vector_digest: authority.reservation_vector_digest,
        recovery_reference_digest: authority.recovery_reference_digest,
        recovery_mode: authority.recovery_mode,
        recovery_profile_digest: authority.recovery_profile_digest,
        recovery_binding_digest: authority.recovery_binding_digest,
        recovery_receipt_digest: authority.recovery_receipt_digest,
        destination_adapter_id: authority.destination_adapter_id.clone(),
        boot_id: authority.boot_id.clone(),
        instance_epoch: authority.instance_epoch,
        supervisor_epoch: authority.supervisor_epoch,
        supervisor_generation: authority.supervisor_generation,
        clock_generation: authority.clock_generation,
        issued_at_utc_ms: authority.issued_at_utc_ms,
        issued_at_monotonic_ms: authority.issued_at_monotonic_ms,
        deadline_monotonic_ms,
    };
    ExecutionGrantProtectedV1::try_new(input, authority.signer_key_id.clone())
        .map_err(DispatchCandidateBuildErrorV1::GrantContract)
}

fn derive_entropy_digest_v1(
    entropy: &dyn DispatchEntropySourceV1,
    entropy_domain: DispatchEntropyDomainV1,
    derivation_domain: &[u8],
    attempt: &DispatchAttemptIdV1,
) -> Result<Sha256Digest, DispatchCandidateBuildErrorV1> {
    let mut random = [0_u8; 32];
    entropy
        .fill_entropy_v1(entropy_domain, &mut random)
        .map_err(|_| DispatchCandidateBuildErrorV1::EntropyUnavailable)?;
    let mut preimage = Vec::with_capacity(derivation_domain.len() + 64);
    preimage.extend_from_slice(derivation_domain);
    preimage.extend_from_slice(attempt.as_bytes());
    preimage.extend_from_slice(&random);
    Ok(Sha256Digest::digest(&preimage))
}

fn destination_binding_digest_v1(
    destination_adapter_id: &str,
    protocol_version: u8,
    adapter_capability_digest: Sha256Digest,
) -> Sha256Digest {
    let mut preimage = Vec::with_capacity(destination_adapter_id.len() + 64);
    preimage.extend_from_slice(b"HELIXOS\0DISPATCH-DESTINATION-BINDING\0V1\0");
    preimage.extend_from_slice(&(destination_adapter_id.len() as u32).to_be_bytes());
    preimage.extend_from_slice(destination_adapter_id.as_bytes());
    preimage.push(protocol_version);
    preimage.extend_from_slice(adapter_capability_digest.as_bytes());
    Sha256Digest::digest(&preimage)
}

/// Sends byte-identical retained grant bytes through the adapter's two durable steps.
///
/// The first call must durably establish `RECEIVED`. Only a returned durable or
/// retained state is passed to the one-shot consume boundary. A pre-receive refusal
/// or retained receipt returns immediately, so neither path can accidentally invoke
/// consumption. The adapter keeps exclusive ownership of persistence and receipt
/// signing; this orchestration receives no such authority.
pub fn receive_and_consume_exact_grant_v1<I>(
    inbox: &I,
    exact_signed_grant_bytes: &[u8],
) -> DispatchInboxAdapterOutcomeV1<I::RetainedReceipt>
where
    I: DispatchInboxConsumerV1,
{
    let retained_state = match inbox.receive_exact_grant_v1(exact_signed_grant_bytes) {
        DispatchInboxReceiveOutcomeV1::DurablyReceived(state)
        | DispatchInboxReceiveOutcomeV1::RetainedState(state) => state,
        DispatchInboxReceiveOutcomeV1::RetainedReceipt(receipt) => {
            return DispatchInboxAdapterOutcomeV1::RetainedReceipt(receipt);
        }
        DispatchInboxReceiveOutcomeV1::RefusedBeforeReceive(reason) => {
            return DispatchInboxAdapterOutcomeV1::RefusedBeforeReceive(reason);
        }
        DispatchInboxReceiveOutcomeV1::Conflict => {
            return DispatchInboxAdapterOutcomeV1::Conflict;
        }
        DispatchInboxReceiveOutcomeV1::Quarantined => {
            return DispatchInboxAdapterOutcomeV1::Quarantined;
        }
        DispatchInboxReceiveOutcomeV1::Unavailable => {
            return DispatchInboxAdapterOutcomeV1::ReceiveUnavailable;
        }
        DispatchInboxReceiveOutcomeV1::Unhealthy => {
            return DispatchInboxAdapterOutcomeV1::ReceiveUnhealthy;
        }
    };

    match inbox.consume_received_once_v1(retained_state) {
        DispatchInboxConsumeOutcomeV1::Consumed(receipt) => {
            DispatchInboxAdapterOutcomeV1::Consumed(receipt)
        }
        DispatchInboxConsumeOutcomeV1::DefinitelyRefused(receipt) => {
            DispatchInboxAdapterOutcomeV1::DefinitelyRefused(receipt)
        }
        DispatchInboxConsumeOutcomeV1::RetainedReceipt(receipt) => {
            DispatchInboxAdapterOutcomeV1::RetainedReceipt(receipt)
        }
        DispatchInboxConsumeOutcomeV1::Conflict => DispatchInboxAdapterOutcomeV1::Conflict,
        DispatchInboxConsumeOutcomeV1::Quarantined => DispatchInboxAdapterOutcomeV1::Quarantined,
        DispatchInboxConsumeOutcomeV1::Unavailable => {
            DispatchInboxAdapterOutcomeV1::ConsumeUnavailable
        }
        DispatchInboxConsumeOutcomeV1::Unhealthy => DispatchInboxAdapterOutcomeV1::ConsumeUnhealthy,
    }
}

pub const AUTOMATIC_READBACK_BACKOFFS_MS_V1: [u64; 4] = [0, 25, 75, 175];
pub const AUTOMATIC_READBACK_OFFSETS_MS_V1: [u64; 4] = [0, 25, 100, 275];
pub const AUTOMATIC_READBACK_MAX_OBSERVATIONS_V1: usize = 4;
pub const AUTOMATIC_READBACK_BUDGET_MS_V1: u64 = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchAutomaticHandoffClassificationV1 {
    ConfirmedNoSend,
    PossibleHandoff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchReadbackWaitOutcomeV1 {
    ObservedAt(u64),
    Unavailable,
}

/// Injected scheduler for a bounded sequence. Implementations may wait, advance a
/// deterministic clock, or refuse; the portable crate never reads ambient time.
pub trait DispatchAutomaticReadbackScheduleV1 {
    fn wait_until_readback_offset_v1(
        &mut self,
        requested_monotonic_ms: u64,
        effective_end_monotonic_ms: u64,
    ) -> DispatchReadbackWaitOutcomeV1;
}

/// Durable per-attempt gate. Returning `false` means that the automatic sequence was
/// already claimed or terminally classified and must not be restarted.
pub trait DispatchAutomaticReadbackGateV1 {
    fn try_begin_automatic_readback_once_v1(&self, delivery_attempt_generation: u64) -> bool;
}

pub enum DispatchLostAcknowledgementRecoveryV1<'grant, S, R> {
    ResumeReceived {
        retained_state: S,
        exact_signed_grant_bytes: &'grant [u8],
        original_exclusive_deadline_monotonic_ms: u64,
    },
    RetainedReceipt {
        receipt: R,
        evidence_only: bool,
    },
    OutcomeUnknownThenReconciliationRequired {
        unknown_reason: crate::DispatchUnknownReasonV1,
        reconciliation_reason: crate::DispatchReconciliationReasonV1,
    },
    Conflict,
    Quarantined,
}

impl<S, R> fmt::Debug for DispatchLostAcknowledgementRecoveryV1<'_, S, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ResumeReceived { .. } => {
                "DispatchLostAcknowledgementRecoveryV1::ResumeReceived(..)"
            }
            Self::RetainedReceipt { .. } => {
                "DispatchLostAcknowledgementRecoveryV1::RetainedReceipt(..)"
            }
            Self::OutcomeUnknownThenReconciliationRequired { .. } => {
                "DispatchLostAcknowledgementRecoveryV1::OutcomeUnknownThenReconciliationRequired(..)"
            }
            Self::Conflict => "DispatchLostAcknowledgementRecoveryV1::Conflict",
            Self::Quarantined => "DispatchLostAcknowledgementRecoveryV1::Quarantined",
        })
    }
}

/// Resolves one lost receive/consume acknowledgement through exact adapter readback.
///
/// If no row is present while the original authority remains live, only the caller's
/// byte-identical retained envelope is offered again. A retained receipt is returned as
/// historical evidence even after expiry; no signing, renewal, or consumption occurs here.
/// An absent row at or after expiry, or a pre-receive refusal observed during live
/// redelivery, never proves that the original possible handoff was absent: those paths
/// retain unknown/reconciliation custody instead.
#[allow(clippy::needless_return)]
pub fn recover_lost_acknowledgement_v1<'grant, I>(
    inbox: &I,
    grant_binding: &[u8; 32],
    exact_signed_grant_bytes: &'grant [u8],
    original_exclusive_deadline_monotonic_ms: u64,
    recovered_at_monotonic_ms: u64,
) -> DispatchLostAcknowledgementRecoveryV1<
    'grant,
    <I as DispatchInboxReadbackV1>::RetainedState,
    <I as DispatchInboxReadbackV1>::RetainedReceipt,
>
where
    I: DispatchInboxReadbackV1
        + DispatchInboxV1<
            RetainedState = <I as DispatchInboxReadbackV1>::RetainedState,
            RetainedReceipt = <I as DispatchInboxReadbackV1>::RetainedReceipt,
        >,
{
    #[cfg(feature = "test-fault-injection")]
    {
        let fault_probe = DispatchFaultProbeV1::disabled_v1();
        return recover_lost_acknowledgement_inner_v1(
            inbox,
            grant_binding,
            exact_signed_grant_bytes,
            original_exclusive_deadline_monotonic_ms,
            recovered_at_monotonic_ms,
            &fault_probe,
        );
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        return recover_lost_acknowledgement_inner_v1(
            inbox,
            grant_binding,
            exact_signed_grant_bytes,
            original_exclusive_deadline_monotonic_ms,
            recovered_at_monotonic_ms,
        );
    }
}

/// Runs lost-ack recovery with one caller-owned non-default fault selection.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
pub fn recover_lost_acknowledgement_with_fault_probe_v1<'grant, I>(
    inbox: &I,
    grant_binding: &[u8; 32],
    exact_signed_grant_bytes: &'grant [u8],
    original_exclusive_deadline_monotonic_ms: u64,
    recovered_at_monotonic_ms: u64,
    fault_probe: &DispatchFaultProbeV1,
) -> DispatchLostAcknowledgementRecoveryV1<
    'grant,
    <I as DispatchInboxReadbackV1>::RetainedState,
    <I as DispatchInboxReadbackV1>::RetainedReceipt,
>
where
    I: DispatchInboxReadbackV1
        + DispatchInboxV1<
            RetainedState = <I as DispatchInboxReadbackV1>::RetainedState,
            RetainedReceipt = <I as DispatchInboxReadbackV1>::RetainedReceipt,
        >,
{
    recover_lost_acknowledgement_inner_v1(
        inbox,
        grant_binding,
        exact_signed_grant_bytes,
        original_exclusive_deadline_monotonic_ms,
        recovered_at_monotonic_ms,
        fault_probe,
    )
}

fn recover_lost_acknowledgement_inner_v1<'grant, I>(
    inbox: &I,
    grant_binding: &[u8; 32],
    exact_signed_grant_bytes: &'grant [u8],
    original_exclusive_deadline_monotonic_ms: u64,
    recovered_at_monotonic_ms: u64,
    #[cfg(feature = "test-fault-injection")] fault_probe: &DispatchFaultProbeV1,
) -> DispatchLostAcknowledgementRecoveryV1<
    'grant,
    <I as DispatchInboxReadbackV1>::RetainedState,
    <I as DispatchInboxReadbackV1>::RetainedReceipt,
>
where
    I: DispatchInboxReadbackV1
        + DispatchInboxV1<
            RetainedState = <I as DispatchInboxReadbackV1>::RetainedState,
            RetainedReceipt = <I as DispatchInboxReadbackV1>::RetainedReceipt,
        >,
{
    let readback = inbox.readback_grant_v1(grant_binding);
    match readback {
        DispatchInboxReadbackOutcomeV1::Received(retained_state) => {
            DispatchLostAcknowledgementRecoveryV1::ResumeReceived {
                retained_state,
                exact_signed_grant_bytes,
                original_exclusive_deadline_monotonic_ms,
            }
        }
        DispatchInboxReadbackOutcomeV1::RetainedReceipt(receipt) => {
            DispatchLostAcknowledgementRecoveryV1::RetainedReceipt {
                receipt,
                evidence_only: recovered_at_monotonic_ms
                    >= original_exclusive_deadline_monotonic_ms,
            }
        }
        DispatchInboxReadbackOutcomeV1::Absent => {
            if recovered_at_monotonic_ms >= original_exclusive_deadline_monotonic_ms {
                return lost_acknowledgement_unknown_v1(
                    crate::DispatchUnknownReasonV1::PossibleHandoff,
                );
            }
            let receive = inbox.receive_exact_grant_v1(exact_signed_grant_bytes);
            #[cfg(feature = "test-fault-injection")]
            if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb040) {
                return lost_acknowledgement_unknown_v1(
                    crate::DispatchUnknownReasonV1::PossibleHandoff,
                );
            }
            match receive {
                DispatchInboxReceiveOutcomeV1::DurablyReceived(retained_state)
                | DispatchInboxReceiveOutcomeV1::RetainedState(retained_state) => {
                    DispatchLostAcknowledgementRecoveryV1::ResumeReceived {
                        retained_state,
                        exact_signed_grant_bytes,
                        original_exclusive_deadline_monotonic_ms,
                    }
                }
                DispatchInboxReceiveOutcomeV1::RetainedReceipt(receipt) => {
                    DispatchLostAcknowledgementRecoveryV1::RetainedReceipt {
                        receipt,
                        evidence_only: false,
                    }
                }
                DispatchInboxReceiveOutcomeV1::RefusedBeforeReceive(_) => {
                    lost_acknowledgement_unknown_v1(crate::DispatchUnknownReasonV1::PossibleHandoff)
                }
                DispatchInboxReceiveOutcomeV1::Conflict => {
                    DispatchLostAcknowledgementRecoveryV1::Conflict
                }
                DispatchInboxReceiveOutcomeV1::Quarantined => {
                    DispatchLostAcknowledgementRecoveryV1::Quarantined
                }
                DispatchInboxReceiveOutcomeV1::Unavailable => lost_acknowledgement_unknown_v1(
                    crate::DispatchUnknownReasonV1::ReadbackUnavailable,
                ),
                DispatchInboxReceiveOutcomeV1::Unhealthy => lost_acknowledgement_unknown_v1(
                    crate::DispatchUnknownReasonV1::ReadbackUnavailable,
                ),
            }
        }
        DispatchInboxReadbackOutcomeV1::Conflict => DispatchLostAcknowledgementRecoveryV1::Conflict,
        DispatchInboxReadbackOutcomeV1::Quarantined => {
            DispatchLostAcknowledgementRecoveryV1::Quarantined
        }
        DispatchInboxReadbackOutcomeV1::Unavailable => {
            lost_acknowledgement_unknown_v1(crate::DispatchUnknownReasonV1::ReadbackUnavailable)
        }
        DispatchInboxReadbackOutcomeV1::Unhealthy => {
            lost_acknowledgement_unknown_v1(crate::DispatchUnknownReasonV1::ReadbackUnavailable)
        }
    }
}

fn lost_acknowledgement_unknown_v1<'grant, S, R>(
    unknown_reason: crate::DispatchUnknownReasonV1,
) -> DispatchLostAcknowledgementRecoveryV1<'grant, S, R> {
    DispatchLostAcknowledgementRecoveryV1::OutcomeUnknownThenReconciliationRequired {
        unknown_reason,
        reconciliation_reason: crate::DispatchReconciliationReasonV1::PossibleConsumption,
    }
}

pub enum DispatchAutomaticReadbackOutcomeV1<S, R> {
    PendingExactGrant,
    Received(S),
    RetainedReceipt {
        receipt: R,
        evidence_only: bool,
    },
    RefusedBeforeReceive(crate::DispatchPreReceiveRefusalV1),
    Conflict,
    Quarantined,
    OutcomeUnknownThenReconciliationRequired {
        unknown_reason: crate::DispatchUnknownReasonV1,
        reconciliation_reason: crate::DispatchReconciliationReasonV1,
    },
    AlreadyClassified,
}

impl<S, R> fmt::Debug for DispatchAutomaticReadbackOutcomeV1<S, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PendingExactGrant => "DispatchAutomaticReadbackOutcomeV1::PendingExactGrant",
            Self::Received(_) => "DispatchAutomaticReadbackOutcomeV1::Received(..)",
            Self::RetainedReceipt { .. } => {
                "DispatchAutomaticReadbackOutcomeV1::RetainedReceipt(..)"
            }
            Self::RefusedBeforeReceive(_) => {
                "DispatchAutomaticReadbackOutcomeV1::RefusedBeforeReceive(..)"
            }
            Self::Conflict => "DispatchAutomaticReadbackOutcomeV1::Conflict",
            Self::Quarantined => "DispatchAutomaticReadbackOutcomeV1::Quarantined",
            Self::OutcomeUnknownThenReconciliationRequired { .. } => {
                "DispatchAutomaticReadbackOutcomeV1::OutcomeUnknownThenReconciliationRequired(..)"
            }
            Self::AlreadyClassified => "DispatchAutomaticReadbackOutcomeV1::AlreadyClassified",
        })
    }
}

/// Runs the single bounded automatic readback sequence for one possible-handoff attempt.
#[allow(clippy::too_many_arguments, clippy::needless_return)]
pub fn run_automatic_readback_once_v1<I, G, W>(
    inbox: &I,
    sequence_gate: &G,
    schedule: &mut W,
    delivery_attempt_generation: u64,
    handoff: DispatchAutomaticHandoffClassificationV1,
    grant_binding: &[u8; 32],
    first_observation_monotonic_ms: u64,
    caller_deadline_monotonic_ms: u64,
    grant_deadline_monotonic_ms: u64,
) -> DispatchAutomaticReadbackOutcomeV1<I::RetainedState, I::RetainedReceipt>
where
    I: DispatchInboxReadbackV1,
    G: DispatchAutomaticReadbackGateV1,
    W: DispatchAutomaticReadbackScheduleV1,
{
    #[cfg(feature = "test-fault-injection")]
    {
        let fault_probe = DispatchFaultProbeV1::disabled_v1();
        return run_automatic_readback_once_inner_v1(
            inbox,
            sequence_gate,
            schedule,
            delivery_attempt_generation,
            handoff,
            grant_binding,
            first_observation_monotonic_ms,
            caller_deadline_monotonic_ms,
            grant_deadline_monotonic_ms,
            &fault_probe,
        );
    }
    #[cfg(not(feature = "test-fault-injection"))]
    {
        return run_automatic_readback_once_inner_v1(
            inbox,
            sequence_gate,
            schedule,
            delivery_attempt_generation,
            handoff,
            grant_binding,
            first_observation_monotonic_ms,
            caller_deadline_monotonic_ms,
            grant_deadline_monotonic_ms,
        );
    }
}

/// Runs the bounded production readback path with one non-default fault selection.
#[doc(hidden)]
#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)]
pub fn run_automatic_readback_once_with_fault_probe_v1<I, G, W>(
    inbox: &I,
    sequence_gate: &G,
    schedule: &mut W,
    delivery_attempt_generation: u64,
    handoff: DispatchAutomaticHandoffClassificationV1,
    grant_binding: &[u8; 32],
    first_observation_monotonic_ms: u64,
    caller_deadline_monotonic_ms: u64,
    grant_deadline_monotonic_ms: u64,
    fault_probe: &DispatchFaultProbeV1,
) -> DispatchAutomaticReadbackOutcomeV1<I::RetainedState, I::RetainedReceipt>
where
    I: DispatchInboxReadbackV1,
    G: DispatchAutomaticReadbackGateV1,
    W: DispatchAutomaticReadbackScheduleV1,
{
    run_automatic_readback_once_inner_v1(
        inbox,
        sequence_gate,
        schedule,
        delivery_attempt_generation,
        handoff,
        grant_binding,
        first_observation_monotonic_ms,
        caller_deadline_monotonic_ms,
        grant_deadline_monotonic_ms,
        fault_probe,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_automatic_readback_once_inner_v1<I, G, W>(
    inbox: &I,
    sequence_gate: &G,
    schedule: &mut W,
    delivery_attempt_generation: u64,
    handoff: DispatchAutomaticHandoffClassificationV1,
    grant_binding: &[u8; 32],
    first_observation_monotonic_ms: u64,
    caller_deadline_monotonic_ms: u64,
    grant_deadline_monotonic_ms: u64,
    #[cfg(feature = "test-fault-injection")] fault_probe: &DispatchFaultProbeV1,
) -> DispatchAutomaticReadbackOutcomeV1<I::RetainedState, I::RetainedReceipt>
where
    I: DispatchInboxReadbackV1,
    G: DispatchAutomaticReadbackGateV1,
    W: DispatchAutomaticReadbackScheduleV1,
{
    if handoff == DispatchAutomaticHandoffClassificationV1::ConfirmedNoSend {
        return DispatchAutomaticReadbackOutcomeV1::PendingExactGrant;
    }
    if !sequence_gate.try_begin_automatic_readback_once_v1(delivery_attempt_generation) {
        return DispatchAutomaticReadbackOutcomeV1::AlreadyClassified;
    }
    let hard_end_monotonic_ms = match first_observation_monotonic_ms
        .checked_add(AUTOMATIC_READBACK_BUDGET_MS_V1)
    {
        Some(value) => value,
        None => {
            return unknown_readback_outcome_v1(crate::DispatchUnknownReasonV1::ReadbackExhausted)
        }
    };
    let effective_end_monotonic_ms = hard_end_monotonic_ms
        .min(caller_deadline_monotonic_ms)
        .min(grant_deadline_monotonic_ms);
    #[cfg(feature = "test-fault-injection")]
    if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb041) {
        return unknown_readback_outcome_v1(crate::DispatchUnknownReasonV1::ReadbackUnavailable);
    }
    let mut offset = 0_u64;
    for (index, backoff) in AUTOMATIC_READBACK_BACKOFFS_MS_V1
        .iter()
        .copied()
        .enumerate()
    {
        if index >= AUTOMATIC_READBACK_MAX_OBSERVATIONS_V1 {
            break;
        }
        offset = match offset.checked_add(backoff) {
            Some(value) => value,
            None => break,
        };
        debug_assert_eq!(AUTOMATIC_READBACK_OFFSETS_MS_V1[index], offset);
        let requested_monotonic_ms = match first_observation_monotonic_ms.checked_add(offset) {
            Some(value) if value < effective_end_monotonic_ms => value,
            _ => break,
        };
        let observed_at = match schedule
            .wait_until_readback_offset_v1(requested_monotonic_ms, effective_end_monotonic_ms)
        {
            DispatchReadbackWaitOutcomeV1::ObservedAt(observed_at)
                if observed_at >= requested_monotonic_ms
                    && observed_at < effective_end_monotonic_ms =>
            {
                observed_at
            }
            DispatchReadbackWaitOutcomeV1::ObservedAt(_)
            | DispatchReadbackWaitOutcomeV1::Unavailable => {
                return unknown_readback_outcome_v1(
                    crate::DispatchUnknownReasonV1::ReadbackUnavailable,
                )
            }
        };
        let readback = inbox.readback_grant_v1(grant_binding);
        #[cfg(feature = "test-fault-injection")]
        if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb042) {
            return unknown_readback_outcome_v1(
                crate::DispatchUnknownReasonV1::ReadbackUnavailable,
            );
        }
        match readback {
            DispatchInboxReadbackOutcomeV1::Absent => {}
            DispatchInboxReadbackOutcomeV1::Received(state) => {
                return DispatchAutomaticReadbackOutcomeV1::Received(state)
            }
            DispatchInboxReadbackOutcomeV1::RetainedReceipt(receipt) => {
                #[cfg(feature = "test-fault-injection")]
                if portable_dispatch_fault_injected_v1(fault_probe, FaultBoundaryV1::Plan005Fb043) {
                    return unknown_readback_outcome_v1(
                        crate::DispatchUnknownReasonV1::ReadbackUnavailable,
                    );
                }
                return DispatchAutomaticReadbackOutcomeV1::RetainedReceipt {
                    receipt,
                    evidence_only: observed_at >= grant_deadline_monotonic_ms,
                };
            }
            DispatchInboxReadbackOutcomeV1::Conflict => {
                return DispatchAutomaticReadbackOutcomeV1::Conflict
            }
            DispatchInboxReadbackOutcomeV1::Quarantined => {
                return DispatchAutomaticReadbackOutcomeV1::Quarantined
            }
            DispatchInboxReadbackOutcomeV1::Unavailable => {
                return unknown_readback_outcome_v1(
                    crate::DispatchUnknownReasonV1::ReadbackUnavailable,
                )
            }
            DispatchInboxReadbackOutcomeV1::Unhealthy => {
                return unknown_readback_outcome_v1(
                    crate::DispatchUnknownReasonV1::ReadbackUnavailable,
                )
            }
        }
    }
    unknown_readback_outcome_v1(crate::DispatchUnknownReasonV1::ReadbackExhausted)
}

fn unknown_readback_outcome_v1<S, R>(
    unknown_reason: crate::DispatchUnknownReasonV1,
) -> DispatchAutomaticReadbackOutcomeV1<S, R> {
    DispatchAutomaticReadbackOutcomeV1::OutcomeUnknownThenReconciliationRequired {
        unknown_reason,
        reconciliation_reason: crate::DispatchReconciliationReasonV1::PossibleConsumption,
    }
}

#[cfg(feature = "test-fault-injection")]
fn portable_dispatch_fault_injected_v1(
    fault_probe: &DispatchFaultProbeV1,
    boundary: FaultBoundaryV1,
) -> bool {
    !matches!(
        fault_probe.reach_id_v1(boundary.id()),
        Ok(FaultInjectionDecisionV1::Continue)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{tests::view, DispatchAuthorityCaptureOutcomeV1};
    use crate::{
        DispatchAuthorityCapturePhaseV1, DispatchCommitPermitOutcomeV1, DispatchEntropyErrorV1,
        DispatchGuardAcquisitionV1, DispatchGuardClassV1, DispatchGuardOrderErrorV1,
        DispatchLookupRequestInputV1, DispatchStoreCommitClassificationV1,
    };
    use helix_dispatch_contracts::{GrantSigner, RecoveryModeV1};
    use std::{collections::VecDeque, sync::Mutex};

    struct ScriptAuthority;

    impl DispatchAuthorityProviderV1 for ScriptAuthority {
        fn capture_authority_v1(
            &self,
            phase: DispatchAuthorityCapturePhaseV1,
            _request: &DispatchLookupRequestV1,
            _attempt: &DispatchAttemptIdV1,
        ) -> DispatchAuthorityCaptureOutcomeV1 {
            DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(view(phase, 30, 31, 4, 12)))
        }
    }

    struct RecordingEntropy {
        calls: Mutex<Vec<DispatchEntropyDomainV1>>,
    }

    impl DispatchEntropySourceV1 for RecordingEntropy {
        fn fill_entropy_v1(
            &self,
            domain: DispatchEntropyDomainV1,
            destination: &mut [u8],
        ) -> Result<(), DispatchEntropyErrorV1> {
            self.calls.lock().unwrap().push(domain);
            destination.fill(0x44);
            Ok(())
        }
    }

    struct DomainCheckingSigner;

    impl GrantSigner for DomainCheckingSigner {
        fn key_id(&self) -> &str {
            "dispatch-key-v1"
        }

        fn sign_execution_grant(&self, message: &[u8]) -> Result<[u8; 64], ContractError> {
            assert!(message.starts_with(b"HELIXOS\0EXECUTION-GRANT\0V1\0"));
            Ok([0x55; 64])
        }
    }

    struct Reloaded;

    impl DispatchReloadedCandidateV1 for Reloaded {
        fn effect_descriptor_v1(&self) -> Option<DispatchEffectDescriptorV1> {
            Some(effect())
        }

        fn required_capacity_v1(&self) -> Option<DispatchCapacityVectorV1> {
            DispatchCapacityVectorV1::try_new(10, 20, 30, 40).ok()
        }

        fn held_capacity_v1(&self) -> Option<DispatchCapacityVectorV1> {
            DispatchCapacityVectorV1::try_new(10, 20, 30, 40).ok()
        }

        fn prior_dispatch_projection_v1(&self) -> Option<DispatchRetainedProjectionV1> {
            None
        }
    }

    struct Evidence;

    impl DispatchCommitEvidenceV1 for Evidence {
        fn grant_id_v1(&self) -> [u8; 32] {
            [0x61; 32]
        }

        fn grant_digest_v1(&self) -> [u8; 32] {
            [0x62; 32]
        }

        fn state_generation_v1(&self) -> u64 {
            7
        }
    }

    struct Store;

    impl DispatchCoordinatorStoreV1 for Store {
        type ReloadedState = Reloaded;
        type CommitReceipt = Evidence;
        type UncertainCommitCustody = ();
        type ReadbackEvidence = Evidence;

        fn reload_authoritative_v1(
            &self,
            _request: &DispatchLookupRequestV1,
        ) -> DispatchReloadOutcomeV1<Self::ReloadedState> {
            DispatchReloadOutcomeV1::Ready(Reloaded)
        }

        fn commit_candidate_once_v1(
            &self,
            candidate: DispatchCommitCandidateV1<Self::ReloadedState>,
        ) -> DispatchStoreCommitClassificationV1<Self::CommitReceipt, Self::UncertainCommitCustody>
        {
            assert_eq!(candidate.operation_id(), "operation-v1");
            assert!(!candidate.exact_grant().exact_bytes().is_empty());
            DispatchStoreCommitClassificationV1::Committed(Evidence)
        }

        fn readback_uncertain_v1(
            &self,
            _custody: Self::UncertainCommitCustody,
        ) -> DispatchStoreReadbackOutcomeV1<Self::ReadbackEvidence> {
            panic!("committed synthetic store never enters readback")
        }
    }

    struct Permit;

    impl DispatchCommitPermitV1 for Permit {
        fn deadline_monotonic_ms(&self) -> u64 {
            375
        }

        fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
            if now_monotonic_ms < 375 {
                DispatchGuardValidationV1::Valid
            } else {
                DispatchGuardValidationV1::DeadlineReached
            }
        }

        fn commit_once<C, U, F>(self, commit: F) -> DispatchCommitResolutionV1<C, U>
        where
            C: Send,
            U: Send,
            F: FnOnce() -> DispatchStoreCommitClassificationV1<C, U>,
        {
            match commit() {
                DispatchStoreCommitClassificationV1::Committed(value) => {
                    DispatchCommitResolutionV1::Committed(value)
                }
                DispatchStoreCommitClassificationV1::PriorExactDispatch(value) => {
                    DispatchCommitResolutionV1::PriorExactDispatch(value)
                }
                DispatchStoreCommitClassificationV1::ConfirmedRollback => {
                    DispatchCommitResolutionV1::ConfirmedRollback
                }
                DispatchStoreCommitClassificationV1::Uncertain(value) => {
                    DispatchCommitResolutionV1::Uncertain(value)
                }
                DispatchStoreCommitClassificationV1::Conflict => {
                    DispatchCommitResolutionV1::Conflict
                }
                DispatchStoreCommitClassificationV1::Unavailable => {
                    DispatchCommitResolutionV1::Unavailable
                }
                DispatchStoreCommitClassificationV1::Unhealthy
                | DispatchStoreCommitClassificationV1::Unclassified => {
                    DispatchCommitResolutionV1::Unclassified
                }
            }
        }

        fn abandon_v1(self) {}
    }

    struct Guards;

    impl DispatchGuardSetV1 for Guards {
        type Permit = Permit;

        fn capture_final_authority_v1(&mut self) -> DispatchAuthorityCaptureOutcomeV1 {
            DispatchAuthorityCaptureOutcomeV1::Captured(Box::new(view(
                DispatchAuthorityCapturePhaseV1::FinalGuarded,
                30,
                31,
                4,
                12,
            )))
        }

        fn validate_all_v1(&mut self, _now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
            DispatchGuardValidationV1::Valid
        }

        fn acquire_commit_permit_v1(
            &mut self,
            _attempt: &DispatchAttemptIdV1,
            _deadline_monotonic_ms: u64,
        ) -> DispatchCommitPermitOutcomeV1<Self::Permit> {
            DispatchCommitPermitOutcomeV1::Permitted(Permit)
        }

        fn release_reverse_v1(self) {}
    }

    struct GuardProvider;

    impl DispatchGuardProviderV1 for GuardProvider {
        type GuardSet = Guards;

        fn acquire_in_fixed_order_v1(
            &self,
            _request: &DispatchLookupRequestV1,
            _attempt: &DispatchAttemptIdV1,
            after_acquisition: &mut dyn FnMut(
                DispatchGuardClassV1,
            ) -> Result<(), DispatchGuardOrderErrorV1>,
        ) -> DispatchGuardAcquisitionV1<Self::GuardSet> {
            for guard_class in DispatchGuardClassV1::acquisition_order() {
                if after_acquisition(guard_class).is_err() {
                    return DispatchGuardAcquisitionV1::OrderViolated;
                }
            }
            DispatchGuardAcquisitionV1::Acquired(Guards)
        }
    }

    fn request() -> DispatchLookupRequestV1 {
        DispatchLookupRequestV1::try_new(DispatchLookupRequestInputV1 {
            contract_version: 1,
            operation_id: "operation-v1",
            expected_plan_digest: [1; 32],
            expected_preparation_attempt_digest: [2; 32],
            expected_preparation_transition_generation: 3,
            caller_deadline_monotonic_ms: 4_000,
        })
        .unwrap()
    }

    fn effect() -> DispatchEffectDescriptorV1 {
        DispatchEffectDescriptorV1::try_new(DispatchEffectDescriptorInputV1 {
            operation_state_generation: 9,
            target: ResourceRefV1::try_new("workspace", vec!["file.txt".to_owned()]).unwrap(),
            precondition_digest: Sha256Digest::from_bytes([3; 32]),
            content_digest: Sha256Digest::from_bytes([4; 32]),
            content_byte_length: 16,
            content_media_type: "text/plain".to_owned(),
        })
        .unwrap()
    }

    #[test]
    fn identities_use_three_domains_and_exact_signed_bytes_bind_the_projection() {
        let entropy = RecordingEntropy {
            calls: Mutex::new(Vec::new()),
        };
        let capacity = DispatchCapacityVectorV1::try_new(10, 20, 30, 40).unwrap();
        let pending = build_preliminary_dispatch_candidate_v1(
            (),
            request(),
            &ScriptAuthority,
            &entropy,
            &DomainCheckingSigner,
            effect(),
            capacity,
            capacity,
        )
        .unwrap();
        assert_eq!(
            *entropy.calls.lock().unwrap(),
            vec![
                DispatchEntropyDomainV1::AttemptIdentity,
                DispatchEntropyDomainV1::GrantIdentity,
                DispatchEntropyDomainV1::OneShotNonce,
            ]
        );
        let signed = pending.exact_grant().signed();
        assert_eq!(signed.protected().operation_id(), "operation-v1");
        assert_eq!(signed.protected().destination_adapter_id(), "adapter-v1");
        assert_eq!(signed.protected().deadline_monotonic_ms(), 4_000);
        assert_eq!(signed.protected().supervisor_epoch(), 15);
        assert!(!pending.exact_grant().exact_bytes().is_empty());
        assert_ne!(pending.preliminary_context_digest(), signed.grant_digest());
        let preliminary_digest = pending.preliminary_context_digest();
        let candidate = pending
            .finalize_v1(
                view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 30, 31, 4, 12),
                capacity,
                capacity,
                375,
            )
            .unwrap();
        assert_eq!(candidate.operation_id(), "operation-v1");
        assert_ne!(candidate.final_context_digest(), preliminary_digest);
        assert!(!candidate.exact_grant().exact_bytes().is_empty());
    }

    #[test]
    fn signer_profile_mismatch_fails_before_signing() {
        struct WrongSigner;
        impl GrantSigner for WrongSigner {
            fn key_id(&self) -> &str {
                "wrong-key"
            }
            fn sign_execution_grant(&self, _message: &[u8]) -> Result<[u8; 64], ContractError> {
                panic!("signing must not be called")
            }
        }

        let entropy = RecordingEntropy {
            calls: Mutex::new(Vec::new()),
        };
        let capacity = DispatchCapacityVectorV1::try_new(10, 20, 30, 40).unwrap();
        assert!(matches!(
            build_preliminary_dispatch_candidate_v1(
                (),
                request(),
                &ScriptAuthority,
                &entropy,
                &WrongSigner,
                effect(),
                capacity,
                capacity,
            ),
            Err(DispatchCandidateBuildErrorV1::SignerProfileMismatch)
        ));
    }

    #[test]
    fn recovery_mode_remains_authority_owned_not_effect_input() {
        let authority = view(DispatchAuthorityCapturePhaseV1::Preliminary, 30, 31, 4, 12);
        assert_eq!(
            authority.grant_projection().recovery_mode,
            RecoveryModeV1::Compensation
        );
    }

    #[test]
    fn public_lookup_only_orchestrator_reaches_one_store_commit_under_permit() {
        let entropy = RecordingEntropy {
            calls: Mutex::new(Vec::new()),
        };
        let outcome = dispatch_prepared_once_v1(
            &Store,
            request(),
            &ScriptAuthority,
            &entropy,
            &DomainCheckingSigner,
            &GuardProvider,
        );
        assert!(matches!(outcome, DispatchRequestOutcomeV1::Dispatched(_)));
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AdapterCall {
        Receive,
        Consume,
    }

    struct ReceivedState;

    struct AdapterReceipt {
        marker: u8,
    }

    #[derive(Default)]
    struct DuplicateScriptState {
        calls: Vec<AdapterCall>,
        received_bytes: Vec<Vec<u8>>,
        receive_count: usize,
        consume_count: usize,
    }

    #[derive(Default)]
    struct DuplicateScriptInbox {
        state: Mutex<DuplicateScriptState>,
    }

    impl crate::DispatchInboxV1 for DuplicateScriptInbox {
        type RetainedState = ReceivedState;
        type RetainedReceipt = AdapterReceipt;

        fn receive_exact_grant_v1(
            &self,
            exact_signed_grant_bytes: &[u8],
        ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(AdapterCall::Receive);
            state.received_bytes.push(exact_signed_grant_bytes.to_vec());
            state.receive_count += 1;
            if state.receive_count == 1 {
                DispatchInboxReceiveOutcomeV1::DurablyReceived(ReceivedState)
            } else {
                DispatchInboxReceiveOutcomeV1::RetainedReceipt(AdapterReceipt { marker: 0x5a })
            }
        }
    }

    impl DispatchInboxConsumerV1 for DuplicateScriptInbox {
        fn consume_received_once_v1(
            &self,
            _retained_state: Self::RetainedState,
        ) -> DispatchInboxConsumeOutcomeV1<Self::RetainedReceipt> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(AdapterCall::Consume);
            state.consume_count += 1;
            assert_eq!(state.consume_count, 1, "duplicate consumption attempted");
            DispatchInboxConsumeOutcomeV1::Consumed(AdapterReceipt { marker: 0x5a })
        }
    }

    struct RefusalInbox {
        reason: crate::DispatchPreReceiveRefusalV1,
        calls: Mutex<Vec<AdapterCall>>,
    }

    impl crate::DispatchInboxV1 for RefusalInbox {
        type RetainedState = ReceivedState;
        type RetainedReceipt = AdapterReceipt;

        fn receive_exact_grant_v1(
            &self,
            _exact_signed_grant_bytes: &[u8],
        ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
            self.calls.lock().unwrap().push(AdapterCall::Receive);
            DispatchInboxReceiveOutcomeV1::RefusedBeforeReceive(self.reason)
        }
    }

    impl DispatchInboxConsumerV1 for RefusalInbox {
        fn consume_received_once_v1(
            &self,
            _retained_state: Self::RetainedState,
        ) -> DispatchInboxConsumeOutcomeV1<Self::RetainedReceipt> {
            self.calls.lock().unwrap().push(AdapterCall::Consume);
            panic!("pre-RECEIVED refusal must not enter consumption")
        }
    }

    struct RetainedStateInbox {
        calls: Mutex<Vec<AdapterCall>>,
    }

    impl crate::DispatchInboxV1 for RetainedStateInbox {
        type RetainedState = ReceivedState;
        type RetainedReceipt = AdapterReceipt;

        fn receive_exact_grant_v1(
            &self,
            _exact_signed_grant_bytes: &[u8],
        ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
            self.calls.lock().unwrap().push(AdapterCall::Receive);
            DispatchInboxReceiveOutcomeV1::RetainedState(ReceivedState)
        }
    }

    impl DispatchInboxConsumerV1 for RetainedStateInbox {
        fn consume_received_once_v1(
            &self,
            _retained_state: Self::RetainedState,
        ) -> DispatchInboxConsumeOutcomeV1<Self::RetainedReceipt> {
            self.calls.lock().unwrap().push(AdapterCall::Consume);
            DispatchInboxConsumeOutcomeV1::DefinitelyRefused(AdapterReceipt { marker: 0x33 })
        }
    }

    #[test]
    fn adapter_orchestration_forwards_exact_bytes_after_durable_receive_then_consumes() {
        let inbox = DuplicateScriptInbox::default();
        let exact_bytes = b"\x00exact-signed-grant\xff";

        let outcome = receive_and_consume_exact_grant_v1(&inbox, exact_bytes);

        assert!(matches!(
            outcome,
            DispatchInboxAdapterOutcomeV1::Consumed(AdapterReceipt { marker: 0x5a })
        ));
        let state = inbox.state.lock().unwrap();
        assert_eq!(
            state.calls,
            vec![AdapterCall::Receive, AdapterCall::Consume]
        );
        assert_eq!(state.received_bytes, vec![exact_bytes.to_vec()]);
        assert_eq!(state.consume_count, 1);
    }

    #[test]
    fn exact_duplicate_returns_retained_receipt_without_reconsumption() {
        let inbox = DuplicateScriptInbox::default();
        let exact_bytes = b"same-exact-signed-grant";

        assert!(matches!(
            receive_and_consume_exact_grant_v1(&inbox, exact_bytes),
            DispatchInboxAdapterOutcomeV1::Consumed(AdapterReceipt { marker: 0x5a })
        ));
        assert!(matches!(
            receive_and_consume_exact_grant_v1(&inbox, exact_bytes),
            DispatchInboxAdapterOutcomeV1::RetainedReceipt(AdapterReceipt { marker: 0x5a })
        ));

        let state = inbox.state.lock().unwrap();
        assert_eq!(
            state.calls,
            vec![
                AdapterCall::Receive,
                AdapterCall::Consume,
                AdapterCall::Receive,
            ]
        );
        assert_eq!(state.received_bytes, vec![exact_bytes.to_vec(); 2]);
        assert_eq!(state.receive_count, 2);
        assert_eq!(state.consume_count, 1);
    }

    #[test]
    fn all_closed_pre_received_refusals_return_without_consumption() {
        use crate::DispatchPreReceiveRefusalV1::{
            CapabilityMismatch, DestinationMismatch, InboxCapacityExhausted, ProtocolUnsupported,
        };

        for reason in [
            DestinationMismatch,
            ProtocolUnsupported,
            CapabilityMismatch,
            InboxCapacityExhausted,
        ] {
            let inbox = RefusalInbox {
                reason,
                calls: Mutex::new(Vec::new()),
            };
            let outcome = receive_and_consume_exact_grant_v1(&inbox, b"unaccepted-grant");
            assert!(matches!(
                outcome,
                DispatchInboxAdapterOutcomeV1::RefusedBeforeReceive(observed)
                    if observed == reason
            ));
            assert_eq!(*inbox.calls.lock().unwrap(), vec![AdapterCall::Receive]);
        }
    }

    #[test]
    fn retained_received_state_resumes_once_and_closed_outcomes_are_redacted() {
        let inbox = RetainedStateInbox {
            calls: Mutex::new(Vec::new()),
        };
        let outcome = receive_and_consume_exact_grant_v1(&inbox, b"retained-grant");

        assert_eq!(
            format!("{outcome:?}"),
            "DispatchInboxAdapterOutcomeV1::DefinitelyRefused(..)"
        );
        assert!(matches!(
            outcome,
            DispatchInboxAdapterOutcomeV1::DefinitelyRefused(AdapterReceipt { marker: 0x33 })
        ));
        assert_eq!(
            *inbox.calls.lock().unwrap(),
            vec![AdapterCall::Receive, AdapterCall::Consume]
        );
    }

    struct AbsentRecoveryInbox {
        received_bytes: Mutex<Vec<Vec<u8>>>,
        refuse_redelivery: bool,
    }

    impl crate::DispatchInboxReadbackV1 for AbsentRecoveryInbox {
        type RetainedState = ();
        type RetainedReceipt = ();

        fn readback_grant_v1(
            &self,
            _grant_binding: &[u8; 32],
        ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
            DispatchInboxReadbackOutcomeV1::Absent
        }
    }

    impl crate::DispatchInboxV1 for AbsentRecoveryInbox {
        type RetainedState = ();
        type RetainedReceipt = ();

        fn receive_exact_grant_v1(
            &self,
            exact_signed_grant_bytes: &[u8],
        ) -> DispatchInboxReceiveOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
            self.received_bytes
                .lock()
                .unwrap()
                .push(exact_signed_grant_bytes.to_vec());
            if self.refuse_redelivery {
                DispatchInboxReceiveOutcomeV1::RefusedBeforeReceive(
                    crate::DispatchPreReceiveRefusalV1::InboxCapacityExhausted,
                )
            } else {
                DispatchInboxReceiveOutcomeV1::DurablyReceived(())
            }
        }
    }

    #[test]
    fn expired_absence_never_redelivers_or_claims_definite_absence() {
        for recovered_at in [5_000, 5_001] {
            let inbox = AbsentRecoveryInbox {
                received_bytes: Mutex::new(Vec::new()),
                refuse_redelivery: false,
            };
            let outcome = recover_lost_acknowledgement_v1(
                &inbox,
                &[0x41; 32],
                b"exact-retained-signed-grant",
                5_000,
                recovered_at,
            );

            assert!(matches!(
                outcome,
                DispatchLostAcknowledgementRecoveryV1::OutcomeUnknownThenReconciliationRequired {
                    unknown_reason: crate::DispatchUnknownReasonV1::PossibleHandoff,
                    reconciliation_reason:
                        crate::DispatchReconciliationReasonV1::PossibleConsumption,
                }
            ));
            assert!(inbox.received_bytes.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn live_exact_redelivery_refusal_preserves_possible_handoff_custody() {
        let inbox = AbsentRecoveryInbox {
            received_bytes: Mutex::new(Vec::new()),
            refuse_redelivery: true,
        };
        let exact_bytes = b"\x00exact-retained-signed-grant\xff";
        let outcome =
            recover_lost_acknowledgement_v1(&inbox, &[0x41; 32], exact_bytes, 5_000, 4_999);

        assert!(matches!(
            outcome,
            DispatchLostAcknowledgementRecoveryV1::OutcomeUnknownThenReconciliationRequired {
                unknown_reason: crate::DispatchUnknownReasonV1::PossibleHandoff,
                reconciliation_reason: crate::DispatchReconciliationReasonV1::PossibleConsumption,
            }
        ));
        assert_eq!(
            *inbox.received_bytes.lock().unwrap(),
            vec![exact_bytes.to_vec()]
        );
    }

    const AUTOMATIC_READBACK_GRANT_BINDING_V1: [u8; 32] = [0x91; 32];
    const AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1: u64 = 37;

    #[derive(Default)]
    struct InstrumentedAutomaticReadbackGateV1 {
        state: Mutex<InstrumentedAutomaticReadbackGateStateV1>,
    }

    #[derive(Default)]
    struct InstrumentedAutomaticReadbackGateStateV1 {
        claimed: bool,
        calls: Vec<u64>,
    }

    impl InstrumentedAutomaticReadbackGateV1 {
        fn calls_v1(&self) -> Vec<u64> {
            self.state.lock().unwrap().calls.clone()
        }
    }

    impl DispatchAutomaticReadbackGateV1 for InstrumentedAutomaticReadbackGateV1 {
        fn try_begin_automatic_readback_once_v1(&self, delivery_attempt_generation: u64) -> bool {
            let mut state = self.state.lock().unwrap();
            state.calls.push(delivery_attempt_generation);
            let acquired = !state.claimed;
            state.claimed = true;
            acquired
        }
    }

    #[derive(Clone, Copy)]
    enum InstrumentedAutomaticReadbackStepV1 {
        Absent,
        Received(u8),
        RetainedReceipt(u8),
        Unavailable,
    }

    struct InstrumentedAutomaticReadbackInboxV1 {
        steps: Mutex<VecDeque<InstrumentedAutomaticReadbackStepV1>>,
        bindings: Mutex<Vec<[u8; 32]>>,
    }

    impl InstrumentedAutomaticReadbackInboxV1 {
        fn new_v1(steps: impl IntoIterator<Item = InstrumentedAutomaticReadbackStepV1>) -> Self {
            Self {
                steps: Mutex::new(steps.into_iter().collect()),
                bindings: Mutex::new(Vec::new()),
            }
        }

        fn bindings_v1(&self) -> Vec<[u8; 32]> {
            self.bindings.lock().unwrap().clone()
        }
    }

    impl DispatchInboxReadbackV1 for InstrumentedAutomaticReadbackInboxV1 {
        type RetainedState = u8;
        type RetainedReceipt = u8;

        fn readback_grant_v1(
            &self,
            grant_binding: &[u8; 32],
        ) -> DispatchInboxReadbackOutcomeV1<Self::RetainedState, Self::RetainedReceipt> {
            self.bindings.lock().unwrap().push(*grant_binding);
            match self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(InstrumentedAutomaticReadbackStepV1::Absent)
            {
                InstrumentedAutomaticReadbackStepV1::Absent => {
                    DispatchInboxReadbackOutcomeV1::Absent
                }
                InstrumentedAutomaticReadbackStepV1::Received(state) => {
                    DispatchInboxReadbackOutcomeV1::Received(state)
                }
                InstrumentedAutomaticReadbackStepV1::RetainedReceipt(receipt) => {
                    DispatchInboxReadbackOutcomeV1::RetainedReceipt(receipt)
                }
                InstrumentedAutomaticReadbackStepV1::Unavailable => {
                    DispatchInboxReadbackOutcomeV1::Unavailable
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum InstrumentedAutomaticReadbackScheduleStepV1 {
        ObserveRequested,
        ObserveEffectiveEnd,
        Unavailable,
    }

    struct InstrumentedAutomaticReadbackScheduleV1 {
        steps: VecDeque<InstrumentedAutomaticReadbackScheduleStepV1>,
        calls: Vec<(u64, u64)>,
    }

    impl InstrumentedAutomaticReadbackScheduleV1 {
        fn new_v1(
            steps: impl IntoIterator<Item = InstrumentedAutomaticReadbackScheduleStepV1>,
        ) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                calls: Vec::new(),
            }
        }

        fn observe_requested_v1() -> Self {
            Self::new_v1([])
        }
    }

    impl DispatchAutomaticReadbackScheduleV1 for InstrumentedAutomaticReadbackScheduleV1 {
        fn wait_until_readback_offset_v1(
            &mut self,
            requested_monotonic_ms: u64,
            effective_end_monotonic_ms: u64,
        ) -> DispatchReadbackWaitOutcomeV1 {
            self.calls
                .push((requested_monotonic_ms, effective_end_monotonic_ms));
            match self
                .steps
                .pop_front()
                .unwrap_or(InstrumentedAutomaticReadbackScheduleStepV1::ObserveRequested)
            {
                InstrumentedAutomaticReadbackScheduleStepV1::ObserveRequested => {
                    DispatchReadbackWaitOutcomeV1::ObservedAt(requested_monotonic_ms)
                }
                InstrumentedAutomaticReadbackScheduleStepV1::ObserveEffectiveEnd => {
                    DispatchReadbackWaitOutcomeV1::ObservedAt(effective_end_monotonic_ms)
                }
                InstrumentedAutomaticReadbackScheduleStepV1::Unavailable => {
                    DispatchReadbackWaitOutcomeV1::Unavailable
                }
            }
        }
    }

    fn assert_automatic_readback_unknown_v1(
        outcome: DispatchAutomaticReadbackOutcomeV1<u8, u8>,
        expected_unknown_reason: crate::DispatchUnknownReasonV1,
    ) {
        match outcome {
            DispatchAutomaticReadbackOutcomeV1::OutcomeUnknownThenReconciliationRequired {
                unknown_reason,
                reconciliation_reason,
            } => {
                assert_eq!(unknown_reason, expected_unknown_reason);
                assert_eq!(
                    reconciliation_reason,
                    crate::DispatchReconciliationReasonV1::PossibleConsumption
                );
            }
            other => panic!("expected one unknown/reconciliation custody, got {other:?}"),
        }
    }

    #[test]
    fn automatic_readback_uses_exact_offsets_at_most_four_times_and_gate_classifies_once() {
        let inbox = InstrumentedAutomaticReadbackInboxV1::new_v1([]);
        let gate = InstrumentedAutomaticReadbackGateV1::default();
        let mut schedule = InstrumentedAutomaticReadbackScheduleV1::observe_requested_v1();

        let outcome = run_automatic_readback_once_v1(
            &inbox,
            &gate,
            &mut schedule,
            AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
            DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
            &AUTOMATIC_READBACK_GRANT_BINDING_V1,
            1_000,
            2_000,
            2_000,
        );

        assert_automatic_readback_unknown_v1(
            outcome,
            crate::DispatchUnknownReasonV1::ReadbackExhausted,
        );
        assert_eq!(
            schedule.calls,
            vec![
                (1_000, 1_500),
                (1_025, 1_500),
                (1_100, 1_500),
                (1_275, 1_500)
            ]
        );
        assert_eq!(
            inbox.bindings_v1(),
            vec![AUTOMATIC_READBACK_GRANT_BINDING_V1; 4]
        );
        assert_eq!(
            gate.calls_v1(),
            vec![AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1]
        );

        let mut second_schedule = InstrumentedAutomaticReadbackScheduleV1::observe_requested_v1();
        let second = run_automatic_readback_once_v1(
            &inbox,
            &gate,
            &mut second_schedule,
            AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
            DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
            &AUTOMATIC_READBACK_GRANT_BINDING_V1,
            1_000,
            2_000,
            2_000,
        );
        assert!(matches!(
            second,
            DispatchAutomaticReadbackOutcomeV1::AlreadyClassified
        ));
        assert!(second_schedule.calls.is_empty());
        assert_eq!(
            inbox.bindings_v1(),
            vec![AUTOMATIC_READBACK_GRANT_BINDING_V1; 4]
        );
        assert_eq!(
            gate.calls_v1(),
            vec![AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1; 2]
        );
    }

    #[test]
    fn automatic_readback_budget_caller_and_grant_ends_are_all_exclusive() {
        for (label, caller_deadline, grant_deadline, expected_end) in [
            ("500-ms-budget", 2_000, 3_000, 1_500),
            ("caller-deadline", 1_100, 3_000, 1_100),
            ("grant-deadline", 3_000, 1_100, 1_100),
        ] {
            let inbox = InstrumentedAutomaticReadbackInboxV1::new_v1([]);
            let gate = InstrumentedAutomaticReadbackGateV1::default();
            let mut schedule = InstrumentedAutomaticReadbackScheduleV1::new_v1([
                InstrumentedAutomaticReadbackScheduleStepV1::ObserveEffectiveEnd,
            ]);

            let outcome = run_automatic_readback_once_v1(
                &inbox,
                &gate,
                &mut schedule,
                AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
                DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
                &AUTOMATIC_READBACK_GRANT_BINDING_V1,
                1_000,
                caller_deadline,
                grant_deadline,
            );

            assert_automatic_readback_unknown_v1(
                outcome,
                crate::DispatchUnknownReasonV1::ReadbackUnavailable,
            );
            assert_eq!(schedule.calls, vec![(1_000, expected_end)], "{label}");
            assert!(inbox.bindings_v1().is_empty(), "{label}");
            assert_eq!(
                gate.calls_v1(),
                vec![AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1],
                "{label}"
            );
        }
    }

    #[test]
    fn automatic_readback_unavailability_creates_one_custody_then_already_classified() {
        let scheduler_inbox = InstrumentedAutomaticReadbackInboxV1::new_v1([]);
        let scheduler_gate = InstrumentedAutomaticReadbackGateV1::default();
        let mut unavailable_schedule = InstrumentedAutomaticReadbackScheduleV1::new_v1([
            InstrumentedAutomaticReadbackScheduleStepV1::Unavailable,
        ]);
        let scheduler_outcome = run_automatic_readback_once_v1(
            &scheduler_inbox,
            &scheduler_gate,
            &mut unavailable_schedule,
            AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
            DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
            &AUTOMATIC_READBACK_GRANT_BINDING_V1,
            1_000,
            2_000,
            2_000,
        );
        assert_automatic_readback_unknown_v1(
            scheduler_outcome,
            crate::DispatchUnknownReasonV1::ReadbackUnavailable,
        );
        assert!(scheduler_inbox.bindings_v1().is_empty());

        let mut scheduler_retry = InstrumentedAutomaticReadbackScheduleV1::observe_requested_v1();
        assert!(matches!(
            run_automatic_readback_once_v1(
                &scheduler_inbox,
                &scheduler_gate,
                &mut scheduler_retry,
                AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
                DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
                &AUTOMATIC_READBACK_GRANT_BINDING_V1,
                1_000,
                2_000,
                2_000,
            ),
            DispatchAutomaticReadbackOutcomeV1::AlreadyClassified
        ));
        assert!(scheduler_retry.calls.is_empty());
        assert_eq!(
            scheduler_gate.calls_v1(),
            vec![AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1; 2]
        );

        let readback_inbox = InstrumentedAutomaticReadbackInboxV1::new_v1([
            InstrumentedAutomaticReadbackStepV1::Unavailable,
        ]);
        let readback_gate = InstrumentedAutomaticReadbackGateV1::default();
        let mut readback_schedule = InstrumentedAutomaticReadbackScheduleV1::observe_requested_v1();
        let readback_outcome = run_automatic_readback_once_v1(
            &readback_inbox,
            &readback_gate,
            &mut readback_schedule,
            AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
            DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
            &AUTOMATIC_READBACK_GRANT_BINDING_V1,
            1_000,
            2_000,
            2_000,
        );
        assert_automatic_readback_unknown_v1(
            readback_outcome,
            crate::DispatchUnknownReasonV1::ReadbackUnavailable,
        );
        assert_eq!(
            readback_inbox.bindings_v1(),
            vec![AUTOMATIC_READBACK_GRANT_BINDING_V1]
        );

        let mut readback_retry = InstrumentedAutomaticReadbackScheduleV1::observe_requested_v1();
        assert!(matches!(
            run_automatic_readback_once_v1(
                &readback_inbox,
                &readback_gate,
                &mut readback_retry,
                AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
                DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
                &AUTOMATIC_READBACK_GRANT_BINDING_V1,
                1_000,
                2_000,
                2_000,
            ),
            DispatchAutomaticReadbackOutcomeV1::AlreadyClassified
        ));
        assert!(readback_retry.calls.is_empty());
        assert_eq!(
            readback_inbox.bindings_v1(),
            vec![AUTOMATIC_READBACK_GRANT_BINDING_V1]
        );
        assert_eq!(
            readback_gate.calls_v1(),
            vec![AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1; 2]
        );
    }

    #[cfg(feature = "test-fault-injection")]
    #[test]
    fn automatic_readback_fb041_fb042_and_fb043_use_fault_seam_and_fail_closed() {
        for (boundary_id, readback_step, expected_schedule_calls, expected_readback_calls) in [
            (
                "PLAN005-FB-041",
                InstrumentedAutomaticReadbackStepV1::Absent,
                0,
                0,
            ),
            (
                "PLAN005-FB-042",
                InstrumentedAutomaticReadbackStepV1::Received(0x42),
                1,
                1,
            ),
            (
                "PLAN005-FB-043",
                InstrumentedAutomaticReadbackStepV1::RetainedReceipt(0x43),
                1,
                1,
            ),
        ] {
            let inbox = InstrumentedAutomaticReadbackInboxV1::new_v1([readback_step]);
            let gate = InstrumentedAutomaticReadbackGateV1::default();
            let mut schedule = InstrumentedAutomaticReadbackScheduleV1::observe_requested_v1();
            let probe = DispatchFaultProbeV1::selected_v1(
                boundary_id,
                1,
                crate::FaultInjectionModeV1::InProcess,
                || {},
            )
            .unwrap();

            let outcome = run_automatic_readback_once_with_fault_probe_v1(
                &inbox,
                &gate,
                &mut schedule,
                AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
                DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
                &AUTOMATIC_READBACK_GRANT_BINDING_V1,
                1_000,
                2_000,
                2_000,
                &probe,
            );

            assert_automatic_readback_unknown_v1(
                outcome,
                crate::DispatchUnknownReasonV1::ReadbackUnavailable,
            );
            assert!(probe.injected_v1(), "{boundary_id}");
            assert_eq!(
                schedule.calls.len(),
                expected_schedule_calls,
                "{boundary_id}"
            );
            assert_eq!(
                inbox.bindings_v1().len(),
                expected_readback_calls,
                "{boundary_id}"
            );
            assert_eq!(
                gate.calls_v1(),
                vec![AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1],
                "{boundary_id}"
            );

            let mut second_schedule =
                InstrumentedAutomaticReadbackScheduleV1::observe_requested_v1();
            assert!(matches!(
                run_automatic_readback_once_v1(
                    &inbox,
                    &gate,
                    &mut second_schedule,
                    AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1,
                    DispatchAutomaticHandoffClassificationV1::PossibleHandoff,
                    &AUTOMATIC_READBACK_GRANT_BINDING_V1,
                    1_000,
                    2_000,
                    2_000,
                ),
                DispatchAutomaticReadbackOutcomeV1::AlreadyClassified
            ));
            assert!(second_schedule.calls.is_empty(), "{boundary_id}");
            assert_eq!(
                gate.calls_v1(),
                vec![AUTOMATIC_READBACK_ATTEMPT_GENERATION_V1; 2],
                "{boundary_id}"
            );
        }
    }
}
