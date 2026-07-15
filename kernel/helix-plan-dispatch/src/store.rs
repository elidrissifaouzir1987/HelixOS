//! Portable coordinator store seam for reload, one commit, and exact readback.

#![allow(dead_code)]

use crate::authority::ReadyDispatchContextV1;
use crate::{DispatchAttemptIdV1, DispatchLookupRequestV1, ExactSignedGrantV1};
use helix_dispatch_contracts::Sha256Digest;
use std::fmt;

/// Read-only projection of one store-proved initial dispatch commit.
///
/// Implementations may expose these bindings only after their complete durable graph
/// has been verified. The projection is status evidence; it is never a grant, permit,
/// or delivery authority.
pub trait DispatchCommitEvidenceV1: Send {
    fn grant_id_v1(&self) -> [u8; 32];

    fn grant_digest_v1(&self) -> [u8; 32];

    fn state_generation_v1(&self) -> u64;
}

pub enum DispatchReloadOutcomeV1<R> {
    Ready(R),
    PriorExactDispatch(R),
    Missing,
    Restored,
    Quarantined,
    Failed,
    Conflict,
    Unavailable,
    Unhealthy,
    UnsupportedVersion,
}

impl<R> fmt::Debug for DispatchReloadOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready(_) => formatter.write_str("DispatchReloadOutcomeV1::Ready(..)"),
            Self::PriorExactDispatch(_) => {
                formatter.write_str("DispatchReloadOutcomeV1::PriorExactDispatch(..)")
            }
            Self::Missing => formatter.write_str("DispatchReloadOutcomeV1::Missing"),
            Self::Restored => formatter.write_str("DispatchReloadOutcomeV1::Restored"),
            Self::Quarantined => formatter.write_str("DispatchReloadOutcomeV1::Quarantined"),
            Self::Failed => formatter.write_str("DispatchReloadOutcomeV1::Failed"),
            Self::Conflict => formatter.write_str("DispatchReloadOutcomeV1::Conflict"),
            Self::Unavailable => formatter.write_str("DispatchReloadOutcomeV1::Unavailable"),
            Self::Unhealthy => formatter.write_str("DispatchReloadOutcomeV1::Unhealthy"),
            Self::UnsupportedVersion => {
                formatter.write_str("DispatchReloadOutcomeV1::UnsupportedVersion")
            }
        }
    }
}

/// Store classification returned to the consumed supervisor permit.
pub enum DispatchStoreCommitClassificationV1<C, U> {
    Committed(C),
    PriorExactDispatch(C),
    ConfirmedRollback,
    Uncertain(U),
    Conflict,
    Unavailable,
    Unhealthy,
    Unclassified,
}

impl<C, U> fmt::Debug for DispatchStoreCommitClassificationV1<C, U> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Committed(_) => {
                formatter.write_str("DispatchStoreCommitClassificationV1::Committed(..)")
            }
            Self::PriorExactDispatch(_) => {
                formatter.write_str("DispatchStoreCommitClassificationV1::PriorExactDispatch(..)")
            }
            Self::ConfirmedRollback => {
                formatter.write_str("DispatchStoreCommitClassificationV1::ConfirmedRollback")
            }
            Self::Uncertain(_) => {
                formatter.write_str("DispatchStoreCommitClassificationV1::Uncertain(..)")
            }
            Self::Conflict => formatter.write_str("DispatchStoreCommitClassificationV1::Conflict"),
            Self::Unavailable => {
                formatter.write_str("DispatchStoreCommitClassificationV1::Unavailable")
            }
            Self::Unhealthy => {
                formatter.write_str("DispatchStoreCommitClassificationV1::Unhealthy")
            }
            Self::Unclassified => {
                formatter.write_str("DispatchStoreCommitClassificationV1::Unclassified")
            }
        }
    }
}

pub enum DispatchStoreReadbackOutcomeV1<R> {
    ThisAttemptCommitted(R),
    PriorExactDispatch(R),
    DefinitelyAbsent,
    Conflict,
    Unavailable,
    Unhealthy,
}

/// Exact, read-only persistence projection derived inside portable orchestration.
///
/// It contains no permit, signer, canonical envelope ownership, or delivery authority.
/// Store implementations use it only while persisting the matching candidate.
pub struct DispatchStoreProjectionV1 {
    pub(crate) preparation_attempt_id: [u8; 32],
    pub(crate) preparation_transition_generation: u64,
    pub(crate) plan_id: [u8; 32],
    pub(crate) task_id: Box<str>,
    pub(crate) workload_id: Box<str>,
    pub(crate) task_lease_digest: [u8; 32],
    pub(crate) reservation_id: Box<str>,
    pub(crate) boot_id: Box<str>,
    pub(crate) instance_epoch: u64,
    pub(crate) supervisor_epoch: u64,
    pub(crate) one_shot_nonce: [u8; 32],
    pub(crate) preliminary_context_digest: [u8; 32],
    pub(crate) final_context_digest: [u8; 32],
    pub(crate) authority_vector_digest: [u8; 32],
    pub(crate) destination_binding_digest: [u8; 32],
    pub(crate) signer_profile_digest: [u8; 32],
    pub(crate) signer_key_id: Box<str>,
    pub(crate) signer_key_fingerprint: [u8; 32],
    pub(crate) destination_adapter_id: Box<str>,
    pub(crate) protocol_version: u8,
    pub(crate) sampled_utc_ms: u64,
    pub(crate) sampled_monotonic_ms: u64,
    pub(crate) issued_at_monotonic_ms: u64,
    pub(crate) effective_deadline_monotonic_ms: u64,
}

impl fmt::Debug for DispatchStoreProjectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchStoreProjectionV1")
            .finish_non_exhaustive()
    }
}

macro_rules! projection_copy_getter {
    ($name:ident, $field:ident, $type:ty) => {
        pub const fn $name(&self) -> $type {
            self.$field
        }
    };
}

impl DispatchStoreProjectionV1 {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn signer_key_id(&self) -> &str {
        &self.signer_key_id
    }

    pub fn destination_adapter_id(&self) -> &str {
        &self.destination_adapter_id
    }

    projection_copy_getter!(preparation_attempt_id, preparation_attempt_id, [u8; 32]);
    projection_copy_getter!(
        preparation_transition_generation,
        preparation_transition_generation,
        u64
    );
    projection_copy_getter!(plan_id, plan_id, [u8; 32]);
    projection_copy_getter!(task_lease_digest, task_lease_digest, [u8; 32]);
    projection_copy_getter!(instance_epoch, instance_epoch, u64);
    projection_copy_getter!(supervisor_epoch, supervisor_epoch, u64);
    projection_copy_getter!(one_shot_nonce, one_shot_nonce, [u8; 32]);
    projection_copy_getter!(
        preliminary_context_digest,
        preliminary_context_digest,
        [u8; 32]
    );
    projection_copy_getter!(final_context_digest, final_context_digest, [u8; 32]);
    projection_copy_getter!(authority_vector_digest, authority_vector_digest, [u8; 32]);
    projection_copy_getter!(
        destination_binding_digest,
        destination_binding_digest,
        [u8; 32]
    );
    projection_copy_getter!(signer_profile_digest, signer_profile_digest, [u8; 32]);
    projection_copy_getter!(signer_key_fingerprint, signer_key_fingerprint, [u8; 32]);
    projection_copy_getter!(protocol_version, protocol_version, u8);
    projection_copy_getter!(sampled_utc_ms, sampled_utc_ms, u64);
    projection_copy_getter!(sampled_monotonic_ms, sampled_monotonic_ms, u64);
    projection_copy_getter!(issued_at_monotonic_ms, issued_at_monotonic_ms, u64);
    projection_copy_getter!(
        effective_deadline_monotonic_ms,
        effective_deadline_monotonic_ms,
        u64
    );
}

impl<R> fmt::Debug for DispatchStoreReadbackOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThisAttemptCommitted(_) => {
                formatter.write_str("DispatchStoreReadbackOutcomeV1::ThisAttemptCommitted(..)")
            }
            Self::PriorExactDispatch(_) => {
                formatter.write_str("DispatchStoreReadbackOutcomeV1::PriorExactDispatch(..)")
            }
            Self::DefinitelyAbsent => {
                formatter.write_str("DispatchStoreReadbackOutcomeV1::DefinitelyAbsent")
            }
            Self::Conflict => formatter.write_str("DispatchStoreReadbackOutcomeV1::Conflict"),
            Self::Unavailable => formatter.write_str("DispatchStoreReadbackOutcomeV1::Unavailable"),
            Self::Unhealthy => formatter.write_str("DispatchStoreReadbackOutcomeV1::Unhealthy"),
        }
    }
}

/// Opaque positive candidate. Only verified reload/context/grant orchestration constructs it.
pub struct DispatchCommitCandidateV1<R> {
    reloaded_state: R,
    context: ReadyDispatchContextV1,
    store_projection: DispatchStoreProjectionV1,
    exact_grant: ExactSignedGrantV1,
}

impl<R> DispatchCommitCandidateV1<R> {
    pub(crate) const fn from_verified_parts(
        reloaded_state: R,
        context: ReadyDispatchContextV1,
        store_projection: DispatchStoreProjectionV1,
        exact_grant: ExactSignedGrantV1,
    ) -> Self {
        Self {
            reloaded_state,
            context,
            store_projection,
            exact_grant,
        }
    }

    pub const fn reloaded_state(&self) -> &R {
        &self.reloaded_state
    }

    pub const fn attempt_id(&self) -> &DispatchAttemptIdV1 {
        self.context.attempt()
    }

    pub fn operation_id(&self) -> &str {
        self.context.operation_id()
    }

    pub const fn final_context_digest(&self) -> Sha256Digest {
        self.context.final_context_digest()
    }

    pub const fn preliminary_context_digest(&self) -> Sha256Digest {
        self.context.preliminary_context_digest()
    }

    pub fn signer_profile_digest(&self) -> Sha256Digest {
        self.context
            .grant_authority_projection()
            .signer_profile_digest
    }

    pub const fn store_projection_v1(&self) -> &DispatchStoreProjectionV1 {
        &self.store_projection
    }

    pub const fn exact_grant(&self) -> &ExactSignedGrantV1 {
        &self.exact_grant
    }
}

impl<R> fmt::Debug for DispatchCommitCandidateV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchCommitCandidateV1")
            .finish_non_exhaustive()
    }
}

/// Coordinator durability boundary. Implementations own schema and transaction details.
pub trait DispatchCoordinatorStoreV1: Send + Sync {
    type ReloadedState: Send;
    type CommitReceipt: DispatchCommitEvidenceV1;
    type UncertainCommitCustody: Send;
    type ReadbackEvidence: DispatchCommitEvidenceV1;

    fn reload_authoritative_v1(
        &self,
        request: &DispatchLookupRequestV1,
    ) -> DispatchReloadOutcomeV1<Self::ReloadedState>;

    fn commit_candidate_once_v1(
        &self,
        candidate: DispatchCommitCandidateV1<Self::ReloadedState>,
    ) -> DispatchStoreCommitClassificationV1<Self::CommitReceipt, Self::UncertainCommitCustody>;

    fn readback_uncertain_v1(
        &self,
        custody: Self::UncertainCommitCustody,
    ) -> DispatchStoreReadbackOutcomeV1<Self::ReadbackEvidence>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{tests::view, DispatchAuthorityCapturePhaseV1};
    use crate::control::{
        DispatchEntropyDomainV1, DispatchEntropyErrorV1, DispatchEntropySourceV1,
        DispatchGrantSignerV1,
    };
    use crate::guard::{
        DispatchCommitPermitV1, DispatchCommitResolutionV1, DispatchGuardValidationV1,
    };
    use crate::{DispatchLookupRequestInputV1, DispatchLookupRequestV1};
    use helix_dispatch_contracts::{
        ContractError, ExecutionGrantInputV1, ExecutionGrantProtectedV1, Generation, GrantSigner,
        Identifier, RecoveryModeV1, ResourceRefV1, SafeU64,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).unwrap()
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).unwrap()
    }

    struct FixedEntropy;

    impl DispatchEntropySourceV1 for FixedEntropy {
        fn fill_entropy_v1(
            &self,
            domain: DispatchEntropyDomainV1,
            destination: &mut [u8],
        ) -> Result<(), DispatchEntropyErrorV1> {
            assert_eq!(domain, DispatchEntropyDomainV1::AttemptIdentity);
            destination.fill(0x31);
            Ok(())
        }
    }

    struct FakeSigner;

    impl GrantSigner for FakeSigner {
        fn key_id(&self) -> &str {
            "dispatch-key-v1"
        }

        fn sign_execution_grant(&self, message: &[u8]) -> Result<[u8; 64], ContractError> {
            assert!(message.starts_with(b"HELIXOS\0EXECUTION-GRANT\0V1\0"));
            Ok([0x5a; 64])
        }
    }

    struct ReloadedStateV1;

    struct UncertainCustodyV1 {
        attempt: Sha256Digest,
        exact_grant_bytes: Box<[u8]>,
    }

    struct ReadbackEvidenceV1 {
        attempt: Sha256Digest,
    }

    impl DispatchCommitEvidenceV1 for () {
        fn grant_id_v1(&self) -> [u8; 32] {
            [0x41; 32]
        }

        fn grant_digest_v1(&self) -> [u8; 32] {
            [0x42; 32]
        }

        fn state_generation_v1(&self) -> u64 {
            1
        }
    }

    impl DispatchCommitEvidenceV1 for ReadbackEvidenceV1 {
        fn grant_id_v1(&self) -> [u8; 32] {
            *self.attempt.as_bytes()
        }

        fn grant_digest_v1(&self) -> [u8; 32] {
            *self.attempt.as_bytes()
        }

        fn state_generation_v1(&self) -> u64 {
            1
        }
    }

    struct FakeStore {
        commits: Arc<AtomicUsize>,
        readbacks: Arc<AtomicUsize>,
    }

    impl DispatchCoordinatorStoreV1 for FakeStore {
        type ReloadedState = ReloadedStateV1;
        type CommitReceipt = ();
        type UncertainCommitCustody = UncertainCustodyV1;
        type ReadbackEvidence = ReadbackEvidenceV1;

        fn reload_authoritative_v1(
            &self,
            request: &DispatchLookupRequestV1,
        ) -> DispatchReloadOutcomeV1<Self::ReloadedState> {
            assert_eq!(request.operation_id(), "operation-v1");
            DispatchReloadOutcomeV1::Ready(ReloadedStateV1)
        }

        fn commit_candidate_once_v1(
            &self,
            candidate: DispatchCommitCandidateV1<Self::ReloadedState>,
        ) -> DispatchStoreCommitClassificationV1<Self::CommitReceipt, Self::UncertainCommitCustody>
        {
            self.commits.fetch_add(1, Ordering::SeqCst);
            assert_eq!(candidate.operation_id(), "operation-v1");
            assert!(!candidate.exact_grant().exact_bytes().is_empty());
            DispatchStoreCommitClassificationV1::Uncertain(UncertainCustodyV1 {
                attempt: candidate.attempt_id().digest(),
                exact_grant_bytes: candidate
                    .exact_grant()
                    .exact_bytes()
                    .to_vec()
                    .into_boxed_slice(),
            })
        }

        fn readback_uncertain_v1(
            &self,
            custody: Self::UncertainCommitCustody,
        ) -> DispatchStoreReadbackOutcomeV1<Self::ReadbackEvidence> {
            self.readbacks.fetch_add(1, Ordering::SeqCst);
            assert!(!custody.exact_grant_bytes.is_empty());
            DispatchStoreReadbackOutcomeV1::ThisAttemptCommitted(ReadbackEvidenceV1 {
                attempt: custody.attempt,
            })
        }
    }

    struct SingleUsePermit {
        closure_calls: Arc<AtomicUsize>,
    }

    impl DispatchCommitPermitV1 for SingleUsePermit {
        fn deadline_monotonic_ms(&self) -> u64 {
            6_000
        }

        fn validate_at_v1(&mut self, now_monotonic_ms: u64) -> DispatchGuardValidationV1 {
            if now_monotonic_ms < self.deadline_monotonic_ms() {
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
            self.closure_calls.fetch_add(1, Ordering::SeqCst);
            match commit() {
                DispatchStoreCommitClassificationV1::Committed(receipt) => {
                    DispatchCommitResolutionV1::Committed(receipt)
                }
                DispatchStoreCommitClassificationV1::PriorExactDispatch(receipt) => {
                    DispatchCommitResolutionV1::PriorExactDispatch(receipt)
                }
                DispatchStoreCommitClassificationV1::ConfirmedRollback => {
                    DispatchCommitResolutionV1::ConfirmedRollback
                }
                DispatchStoreCommitClassificationV1::Uncertain(custody) => {
                    DispatchCommitResolutionV1::Uncertain(custody)
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

    fn protected_grant() -> ExecutionGrantProtectedV1 {
        ExecutionGrantProtectedV1::try_new(
            ExecutionGrantInputV1 {
                grant_id: digest(1),
                dispatch_attempt_id: digest(2),
                one_shot_nonce: digest(3),
                operation_id: identifier("operation-v1"),
                operation_state_generation: generation(1),
                preparation_attempt_id: digest(4),
                preparation_transition_generation: generation(2),
                plan_id: digest(5),
                task_id: identifier("task-v1"),
                workload_id: identifier("workload-v1"),
                target: ResourceRefV1::try_new("workspace", vec!["file.txt".to_owned()]).unwrap(),
                precondition_digest: digest(6),
                content_digest: digest(7),
                content_byte_length: SafeU64::new(16).unwrap(),
                content_media_type: "text/plain".to_owned(),
                trust_generation: generation(3),
                verified_key_fingerprint: digest(8),
                workload_generation: generation(4),
                workload_evidence_digest: digest(9),
                lease_generation: generation(5),
                lease_digest: digest(10),
                lease_decision_digest: digest(11),
                authorization_generation: generation(6),
                authorization_evidence_digest: digest(12),
                policy_generation: generation(7),
                policy_decision_generation: generation(8),
                policy_content_digest: digest(13),
                policy_decision_digest: digest(14),
                catalogue_generation: generation(9),
                catalogue_decision_generation: generation(10),
                catalogue_content_digest: digest(15),
                catalogue_decision_digest: digest(16),
                capability_report_generation: generation(11),
                capability_report_digest: digest(17),
                host_driver_context_digest: digest(18),
                capability_observed_at_utc_ms: SafeU64::new(999_900).unwrap(),
                capability_max_age_ms: SafeU64::new(500).unwrap(),
                adapter_capability_digest: digest(19),
                replay_claim_id: digest(20),
                replay_claimant_generation: generation(12),
                replay_binding_digest: digest(21),
                budget_scope_id: identifier("budget-v1"),
                budget_scope_generation: generation(13),
                budget_scope_binding_digest: digest(22),
                reservation_id: identifier("reservation-v1"),
                reservation_generation: generation(14),
                reservation_binding_digest: digest(23),
                reservation_vector_digest: digest(24),
                recovery_reference_digest: digest(25),
                recovery_mode: RecoveryModeV1::Compensation,
                recovery_profile_digest: digest(26),
                recovery_binding_digest: digest(27),
                recovery_receipt_digest: digest(28),
                destination_adapter_id: identifier("adapter-v1"),
                boot_id: identifier("boot-v1"),
                instance_epoch: SafeU64::new(14).unwrap(),
                supervisor_epoch: SafeU64::new(15).unwrap(),
                supervisor_generation: generation(15),
                clock_generation: generation(16),
                issued_at_utc_ms: SafeU64::new(1_000_000).unwrap(),
                issued_at_monotonic_ms: SafeU64::new(1_000).unwrap(),
                deadline_monotonic_ms: generation(6_000),
            },
            identifier("dispatch-key-v1"),
        )
        .unwrap()
    }

    #[test]
    fn fake_consumer_moves_reload_sign_commit_and_uncertain_readback_custody_once() {
        let commits = Arc::new(AtomicUsize::new(0));
        let readbacks = Arc::new(AtomicUsize::new(0));
        let closure_calls = Arc::new(AtomicUsize::new(0));
        let store = FakeStore {
            commits: Arc::clone(&commits),
            readbacks: Arc::clone(&readbacks),
        };
        let request = DispatchLookupRequestV1::try_new(DispatchLookupRequestInputV1 {
            contract_version: 1,
            operation_id: "operation-v1",
            expected_plan_digest: [5; 32],
            expected_preparation_attempt_digest: [4; 32],
            expected_preparation_transition_generation: 2,
            caller_deadline_monotonic_ms: 6_000,
        })
        .unwrap();
        let reloaded = match store.reload_authoritative_v1(&request) {
            DispatchReloadOutcomeV1::Ready(reloaded) => reloaded,
            other => panic!("unexpected reload result: {other:?}"),
        };
        let attempt = DispatchAttemptIdV1::generate(&FixedEntropy).unwrap();
        let authority = view(DispatchAuthorityCapturePhaseV1::FinalGuarded, 30, 31, 4, 12);
        let context = ReadyDispatchContextV1::from_verified_reload(
            request,
            attempt,
            authority,
            digest(28),
            digest(29),
        );
        assert_eq!(context.request().operation_id(), "operation-v1");
        assert_eq!(context.authority().signer_generation(), 31);
        let grant_authority = context.grant_authority_projection();
        assert_eq!(grant_authority.protocol_version, 1);
        assert_eq!(grant_authority.signer_generation.get(), 31);
        assert_eq!(grant_authority.clock_generation.get(), 30);
        let exact_grant = FakeSigner.sign_grant_v1(protected_grant()).unwrap();
        let projection = DispatchStoreProjectionV1 {
            preparation_attempt_id: [4; 32],
            preparation_transition_generation: 2,
            plan_id: [5; 32],
            task_id: "task-v1".into(),
            workload_id: "workload-v1".into(),
            task_lease_digest: [6; 32],
            reservation_id: "reservation-v1".into(),
            boot_id: "boot-v1".into(),
            instance_epoch: 4,
            supervisor_epoch: 12,
            one_shot_nonce: [7; 32],
            preliminary_context_digest: [28; 32],
            final_context_digest: [29; 32],
            authority_vector_digest: [29; 32],
            destination_binding_digest: [8; 32],
            signer_profile_digest: [9; 32],
            signer_key_id: "dispatch-key-v1".into(),
            signer_key_fingerprint: [9; 32],
            destination_adapter_id: "adapter-v1".into(),
            protocol_version: 1,
            sampled_utc_ms: 1_000,
            sampled_monotonic_ms: 100,
            issued_at_monotonic_ms: 100,
            effective_deadline_monotonic_ms: 6_000,
        };
        let candidate = DispatchCommitCandidateV1::from_verified_parts(
            reloaded,
            context,
            projection,
            exact_grant,
        );
        let permit = SingleUsePermit {
            closure_calls: Arc::clone(&closure_calls),
        };

        let custody = match permit.commit_once(|| store.commit_candidate_once_v1(candidate)) {
            DispatchCommitResolutionV1::Uncertain(custody) => custody,
            other => panic!("unexpected commit resolution: {other:?}"),
        };
        let expected_attempt = custody.attempt;
        let evidence = match store.readback_uncertain_v1(custody) {
            DispatchStoreReadbackOutcomeV1::ThisAttemptCommitted(evidence) => evidence,
            other => panic!("unexpected readback result: {other:?}"),
        };

        assert_eq!(evidence.attempt, expected_attempt);
        assert_eq!(closure_calls.load(Ordering::SeqCst), 1);
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        assert_eq!(readbacks.load(Ordering::SeqCst), 1);
    }
}
