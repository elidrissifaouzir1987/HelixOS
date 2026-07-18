use ed25519_dalek::{Signer as _, SigningKey};
use helix_task_authority::{
    issue_root_lease_v1, prepare_root_lease_candidate_v1, AuthorityAtomicStoreV1,
    AuthorityClockObservationV1, AuthorityCurrentnessV1, AuthorityMutationOutcomeV1,
    AuthorityOperationKindV1, AuthorityRetainedGraphV1, AuthorityRetainedOutcomeCodeV1,
    AuthorityUncertainReadbackV1, CurrentHumanRequestContextV1, RootIssuanceObservationsV1,
    RootLeaseCandidateV1, RootLeaseRequestOutcomeV1, RootLeaseRequestRefusalV1, RootLeaseRequestV1,
};
use helix_task_authority_contracts::{
    decode_and_verify_human_request_grant_v1, sign_human_request_grant_v1, ContractError,
    CurrencyCodeV1, DelegationDepthV1, DelegationModeV1, Generation, HumanRequestGrantInputV1,
    HumanRequestGrantKeyResolver, HumanRequestGrantProtectedV1, HumanRequestGrantSigner,
    HumanRequestGrantVerificationKeyV1, Identifier, MinimumAuthenticationProfileV1, ResourceRootV1,
    RiskLevelV1, RootTaskLeaseBoundsV1, SafeU64, Sha256Digest, TaskLeaseBudgetV1,
    TaskLeaseCatalogueBoundV1, TaskLeaseCounterLimitsV1, TaskLeaseSigner, TaskLeaseTrustBoundV1,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn identifier(value: &str) -> Identifier {
    Identifier::new(value).expect("test identifier is valid")
}

fn safe(value: u64) -> SafeU64 {
    SafeU64::new(value).expect("test integer is safe")
}

fn generation(value: u64) -> Generation {
    Generation::new(value).expect("test generation is positive")
}

struct GrantSigner {
    key: SigningKey,
}

impl GrantSigner {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&[17; 32]),
        }
    }
}

impl HumanRequestGrantSigner for GrantSigner {
    fn key_id(&self) -> &str {
        "request-key-v1"
    }

    fn sign_human_request_grant(
        &self,
        message: &[u8],
    ) -> helix_task_authority_contracts::Result<[u8; 64]> {
        Ok(self.key.sign(message).to_bytes())
    }
}

struct GrantResolver {
    public_key: [u8; 32],
}

impl HumanRequestGrantKeyResolver for GrantResolver {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
        if key_id != "request-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(HumanRequestGrantVerificationKeyV1::current(self.public_key))
    }
}

struct LeaseSigner {
    key: SigningKey,
    calls: AtomicUsize,
    fail: bool,
}

impl LeaseSigner {
    fn working() -> Self {
        Self {
            key: SigningKey::from_bytes(&[23; 32]),
            calls: AtomicUsize::new(0),
            fail: false,
        }
    }

    fn failing() -> Self {
        Self {
            key: SigningKey::from_bytes(&[23; 32]),
            calls: AtomicUsize::new(0),
            fail: true,
        }
    }
}

impl TaskLeaseSigner for LeaseSigner {
    fn key_id(&self) -> &str {
        "lease-key-v1"
    }

    fn sign_task_lease(&self, message: &[u8]) -> helix_task_authority_contracts::Result<[u8; 64]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            Err(ContractError::SigningFailed)
        } else {
            Ok(self.key.sign(message).to_bytes())
        }
    }
}

fn authentic_grant(expiry: u64) -> helix_task_authority_contracts::AuthenticHumanRequestGrantV1 {
    let signer = GrantSigner::new();
    let protected = HumanRequestGrantProtectedV1::try_new(
        HumanRequestGrantInputV1 {
            grant_id: digest(1),
            issuer_id: identifier("request-surface"),
            audience: identifier("helix-core"),
            principal_id: identifier("principal-a"),
            message_digest: digest(2),
            channel_id: identifier("channel-a"),
            session_id: identifier("session-a"),
            scope_template_id: identifier("scope-a"),
            scope_template_digest: digest(3),
            scope_template_generation: generation(3),
            issued_at_utc_ms: safe(1_000),
            expires_at_utc_ms: safe(expiry),
        },
        identifier(signer.key_id()),
    )
    .expect("grant protected value is valid");
    let signed = sign_human_request_grant_v1(protected, &signer).expect("grant signs");
    let wire = signed.to_canonical_json().expect("grant canonicalizes");
    decode_and_verify_human_request_grant_v1(
        &wire,
        &GrantResolver {
            public_key: signer.key.verifying_key().to_bytes(),
        },
    )
    .expect("grant verifies as current")
}

fn bounds(read_bytes: u64) -> RootTaskLeaseBoundsV1 {
    RootTaskLeaseBoundsV1::try_new_v1(
        vec![
            ResourceRootV1::try_new("workspace", vec!["project".to_owned(), "src".to_owned()])
                .expect("resource is portable"),
        ],
        TaskLeaseBudgetV1::from_validated_parts_v1(
            safe(read_bytes),
            safe(20),
            safe(10),
            safe(1_000),
            CurrencyCodeV1::new("USD").expect("currency is valid"),
            safe(500),
            identifier("prices-v1"),
        ),
        TaskLeaseCounterLimitsV1::from_validated_parts_v1(
            safe(4),
            safe(2),
            safe(2),
            DelegationDepthV1::new(2).expect("depth is valid"),
        ),
        TaskLeaseTrustBoundV1::from_validated_parts_v1(
            RiskLevelV1::L1,
            MinimumAuthenticationProfileV1::UserVerificationV1,
            identifier("policy-a"),
            digest(4),
            generation(4),
        ),
        TaskLeaseCatalogueBoundV1::try_new_v1(
            identifier("catalogue-a"),
            digest(5),
            generation(5),
            vec![identifier("entry-a"), identifier("entry-b")],
        )
        .expect("catalogue is canonical"),
        DelegationModeV1::Delegable,
    )
    .expect("bounds are valid")
}

fn request_with(read_bytes: u64, ceiling: u64) -> RootLeaseRequestV1 {
    RootLeaseRequestV1 {
        grant: authentic_grant(2_000),
        human_context: CurrentHumanRequestContextV1::from_authenticated_parts_v1(
            identifier("request-surface"),
            identifier("helix-core"),
            identifier("principal-a"),
            digest(2),
            identifier("channel-a"),
            identifier("session-a"),
            identifier("scope-a"),
            digest(3),
            generation(3),
        ),
        requested_bounds: bounds(read_bytes),
        current_ceiling: bounds(ceiling),
        observations: RootIssuanceObservationsV1::from_current_parts_v1(
            digest(3),
            generation(3),
            digest(4),
            generation(4),
            digest(5),
            generation(5),
            digest(6),
            generation(6),
            digest(7),
            generation(7),
        ),
        source_currentness: AuthorityCurrentnessV1::Current,
        lease_issuer_id: identifier("core-lease-issuer"),
        task_id: identifier("task-a"),
        workload_id: identifier("workload-a"),
        audience: identifier("helix-core"),
        clock: AuthorityClockObservationV1::from_trusted_provider_parts_v1(
            identifier("boot-a"),
            generation(8),
            generation(9),
            safe(1_100),
            safe(100),
        ),
        not_before_utc_ms: safe(1_100),
        expires_at_utc_ms: safe(1_900),
        deadline_monotonic_ms: safe(500),
        caller_deadline_monotonic_ms: safe(300),
    }
}

struct NeverRetained;

impl AuthorityRetainedGraphV1 for NeverRetained {
    fn operation_kind_v1(&self) -> AuthorityOperationKindV1 {
        unreachable!()
    }
    fn attempt_id_v1(&self) -> &helix_task_authority::AuthorityAttemptIdV1 {
        unreachable!()
    }
    fn namespace_digest_v1(&self) -> &helix_task_authority::AuthorityNamespaceDigestV1 {
        unreachable!()
    }
    fn input_graph_digest_v1(&self) -> &helix_task_authority::AuthorityInputGraphDigestV1 {
        unreachable!()
    }
    fn caller_deadline_monotonic_ms_v1(&self) -> SafeU64 {
        unreachable!()
    }
    fn outcome_code_v1(&self) -> &AuthorityRetainedOutcomeCodeV1 {
        unreachable!()
    }
    fn outcome_binding_digest_v1(&self) -> &helix_task_authority::AuthorityOutcomeBindingDigestV1 {
        unreachable!()
    }
    fn attempt_generation_v1(&self) -> Generation {
        unreachable!()
    }
    fn event_id_v1(&self) -> Sha256Digest {
        unreachable!()
    }
}

struct RejectingStore {
    calls: AtomicUsize,
}

impl AuthorityAtomicStoreV1<RootLeaseCandidateV1> for RejectingStore {
    type Retained = NeverRetained;

    fn commit_atomic_once_v1(
        &self,
        _candidate: RootLeaseCandidateV1,
    ) -> AuthorityMutationOutcomeV1<Self::Retained, AuthorityUncertainReadbackV1<Self::Retained>>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        AuthorityMutationOutcomeV1::DeniedDefinite
    }
}

#[test]
fn signing_failure_happens_before_writer_and_creates_no_claim_attempt() {
    let signer = LeaseSigner::failing();
    let store = RejectingStore {
        calls: AtomicUsize::new(0),
    };
    let outcome = issue_root_lease_v1(request_with(50, 100), &signer, &store);
    assert!(matches!(
        outcome,
        RootLeaseRequestOutcomeV1::Refused(RootLeaseRequestRefusalV1::SigningFailed)
    ));
    assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.calls.load(Ordering::SeqCst), 0);

    let working = LeaseSigner::working();
    let outcome = issue_root_lease_v1(request_with(50, 100), &working, &store);
    assert!(matches!(outcome, RootLeaseRequestOutcomeV1::DeniedDefinite));
    assert_eq!(store.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn forged_wire_and_every_wrong_authenticated_context_fail_closed() {
    let grant_signer = GrantSigner::new();
    let protected = HumanRequestGrantProtectedV1::try_new(
        HumanRequestGrantInputV1 {
            grant_id: digest(1),
            issuer_id: identifier("request-surface"),
            audience: identifier("helix-core"),
            principal_id: identifier("principal-a"),
            message_digest: digest(2),
            channel_id: identifier("channel-a"),
            session_id: identifier("session-a"),
            scope_template_id: identifier("scope-a"),
            scope_template_digest: digest(3),
            scope_template_generation: generation(3),
            issued_at_utc_ms: safe(1_000),
            expires_at_utc_ms: safe(2_000),
        },
        identifier(grant_signer.key_id()),
    )
    .unwrap();
    let mut wire = sign_human_request_grant_v1(protected, &grant_signer)
        .unwrap()
        .to_canonical_json()
        .unwrap();
    let position = wire.iter().position(|byte| *byte == b'a').unwrap();
    wire[position] = b'b';
    assert!(decode_and_verify_human_request_grant_v1(
        &wire,
        &GrantResolver {
            public_key: grant_signer.key.verifying_key().to_bytes(),
        }
    )
    .is_err());

    let signer = LeaseSigner::working();
    let mut wrong = request_with(50, 100);
    wrong.human_context = CurrentHumanRequestContextV1::from_authenticated_parts_v1(
        identifier("request-surface"),
        identifier("helix-core"),
        identifier("principal-a"),
        digest(99),
        identifier("channel-a"),
        identifier("session-a"),
        identifier("scope-a"),
        digest(3),
        generation(3),
    );
    assert_eq!(
        prepare_root_lease_candidate_v1(wrong, &signer).unwrap_err(),
        RootLeaseRequestRefusalV1::InvalidGrantContext
    );
}

#[test]
fn stale_scope_revocation_expiry_and_widening_refuse_before_signing() {
    let signer = LeaseSigner::working();

    let mut stale = request_with(50, 100);
    stale.observations = RootIssuanceObservationsV1::from_current_parts_v1(
        digest(33),
        generation(3),
        digest(4),
        generation(4),
        digest(5),
        generation(5),
        digest(6),
        generation(6),
        digest(7),
        generation(7),
    );
    assert_eq!(
        prepare_root_lease_candidate_v1(stale, &signer).unwrap_err(),
        RootLeaseRequestRefusalV1::ObservationMismatch
    );

    let mut revoked = request_with(50, 100);
    revoked.source_currentness = AuthorityCurrentnessV1::SourceRevoked;
    assert_eq!(
        prepare_root_lease_candidate_v1(revoked, &signer).unwrap_err(),
        RootLeaseRequestRefusalV1::GrantNotCurrent
    );

    let mut expired = request_with(50, 100);
    expired.clock = AuthorityClockObservationV1::from_trusted_provider_parts_v1(
        identifier("boot-a"),
        generation(8),
        generation(9),
        safe(2_000),
        safe(100),
    );
    assert_eq!(
        prepare_root_lease_candidate_v1(expired, &signer).unwrap_err(),
        RootLeaseRequestRefusalV1::GrantNotCurrent
    );

    assert_eq!(
        prepare_root_lease_candidate_v1(request_with(101, 100), &signer).unwrap_err(),
        RootLeaseRequestRefusalV1::AuthorityWidening
    );
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_retry_has_same_stable_input_but_new_attempt_and_candidate_bytes() {
    let signer = LeaseSigner::working();
    let first = prepare_root_lease_candidate_v1(request_with(50, 100), &signer).unwrap();
    let retry = prepare_root_lease_candidate_v1(request_with(50, 100), &signer).unwrap();
    assert!(first
        .attempt_v1()
        .has_same_stable_input_v1(retry.attempt_v1()));
    assert_ne!(
        first.attempt_v1().attempt_id_v1().digest_v1(),
        retry.attempt_v1().attempt_id_v1().digest_v1()
    );
    assert_ne!(first.root_lease_wire_v1(), retry.root_lease_wire_v1());

    let conflict = prepare_root_lease_candidate_v1(request_with(49, 100), &signer).unwrap();
    assert!(first.attempt_v1().conflicts_with_v1(conflict.attempt_v1()));
}
