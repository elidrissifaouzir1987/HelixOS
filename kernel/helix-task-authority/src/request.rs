//! Portable root-lease request orchestration.
//!
//! All provider observations are captured before this boundary. The operation checks
//! their exact bindings, creates and signs a candidate, and only then invokes the
//! atomic writer. A signer failure therefore cannot consume a grant.

use crate::lease::root_bounds_are_within_v1;
use crate::{
    AuthorityAtomicMutationV1, AuthorityAtomicStoreV1, AuthorityAttemptBindingV1,
    AuthorityClockObservationV1, AuthorityCurrentnessV1, AuthorityIdempotencyPreimageV1,
    AuthorityMutationOutcomeV1, AuthorityNamespaceDigestV1, AuthorityObservationBindingV1,
    AuthorityRetainedGraphV1, AuthorityUncertainReadbackV1, RootLeaseIssuePreimageV1,
};
use helix_task_authority_contracts::{
    sign_task_lease_v1, AuthenticHumanRequestGrantV1, ContractError, Generation, Identifier,
    RootTaskLeaseBoundsV1, RootTaskLeaseInputV1, SafeU64, Sha256Digest, SignedTaskLeaseV1,
    TaskLeaseSigner,
};
use std::fmt;

const GRANT_NAMESPACE_DOMAIN_V1: &[u8] = b"HELIXOS\0HUMAN-GRANT-NAMESPACE\0V1\0";
const ROOT_LEASE_ID_DOMAIN_V1: &[u8] = b"HELIXOS\0ROOT-TASK-LEASE-ID\0V1\0";

/// Independently authenticated ingress context that must exactly match the grant.
pub struct CurrentHumanRequestContextV1 {
    issuer_id: Identifier,
    audience: Identifier,
    principal_id: Identifier,
    message_digest: Sha256Digest,
    channel_id: Identifier,
    session_id: Identifier,
    scope_template_id: Identifier,
    scope_template_digest: Sha256Digest,
    scope_template_generation: Generation,
}

impl CurrentHumanRequestContextV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn from_authenticated_parts_v1(
        issuer_id: Identifier,
        audience: Identifier,
        principal_id: Identifier,
        message_digest: Sha256Digest,
        channel_id: Identifier,
        session_id: Identifier,
        scope_template_id: Identifier,
        scope_template_digest: Sha256Digest,
        scope_template_generation: Generation,
    ) -> Self {
        Self {
            issuer_id,
            audience,
            principal_id,
            message_digest,
            channel_id,
            session_id,
            scope_template_id,
            scope_template_digest,
            scope_template_generation,
        }
    }

    fn exactly_matches_v1(&self, grant: &AuthenticHumanRequestGrantV1) -> bool {
        let claims = grant.claims();
        self.issuer_id.as_str() == claims.issuer_id()
            && self.audience.as_str() == claims.audience()
            && self.principal_id.as_str() == claims.principal_id()
            && self.message_digest == claims.message_digest()
            && self.channel_id.as_str() == claims.channel_id()
            && self.session_id.as_str() == claims.session_id()
            && self.scope_template_id.as_str() == claims.scope_template_id()
            && self.scope_template_digest == claims.scope_template_digest()
            && self.scope_template_generation.get() == claims.scope_template_generation()
    }
}

impl fmt::Debug for CurrentHumanRequestContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CurrentHumanRequestContextV1(..)")
    }
}

/// Immutable current-provider bindings carried into the atomic writer.
pub struct RootIssuanceObservationsV1 {
    scope: AuthorityObservationBindingV1,
    policy: AuthorityObservationBindingV1,
    catalogue: AuthorityObservationBindingV1,
    workload: AuthorityObservationBindingV1,
    trust: AuthorityObservationBindingV1,
}

impl RootIssuanceObservationsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_current_parts_v1(
        scope_digest: Sha256Digest,
        scope_generation: Generation,
        policy_digest: Sha256Digest,
        policy_generation: Generation,
        catalogue_digest: Sha256Digest,
        catalogue_generation: Generation,
        workload_digest: Sha256Digest,
        workload_generation: Generation,
        trust_digest: Sha256Digest,
        trust_generation: Generation,
    ) -> Self {
        Self {
            scope: AuthorityObservationBindingV1::new(scope_digest, scope_generation),
            policy: AuthorityObservationBindingV1::new(policy_digest, policy_generation),
            catalogue: AuthorityObservationBindingV1::new(catalogue_digest, catalogue_generation),
            workload: AuthorityObservationBindingV1::new(workload_digest, workload_generation),
            trust: AuthorityObservationBindingV1::new(trust_digest, trust_generation),
        }
    }

    pub const fn scope_v1(&self) -> &AuthorityObservationBindingV1 {
        &self.scope
    }

    pub const fn policy_v1(&self) -> &AuthorityObservationBindingV1 {
        &self.policy
    }

    pub const fn catalogue_v1(&self) -> &AuthorityObservationBindingV1 {
        &self.catalogue
    }

    pub const fn workload_v1(&self) -> &AuthorityObservationBindingV1 {
        &self.workload
    }

    pub const fn trust_v1(&self) -> &AuthorityObservationBindingV1 {
        &self.trust
    }
}

impl fmt::Debug for RootIssuanceObservationsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootIssuanceObservationsV1(..)")
    }
}

/// Complete non-wire input for one root-lease request.
pub struct RootLeaseRequestV1 {
    pub grant: AuthenticHumanRequestGrantV1,
    pub human_context: CurrentHumanRequestContextV1,
    pub requested_bounds: RootTaskLeaseBoundsV1,
    pub current_ceiling: RootTaskLeaseBoundsV1,
    pub observations: RootIssuanceObservationsV1,
    pub source_currentness: AuthorityCurrentnessV1,
    pub lease_issuer_id: Identifier,
    pub task_id: Identifier,
    pub workload_id: Identifier,
    pub audience: Identifier,
    pub clock: AuthorityClockObservationV1,
    pub not_before_utc_ms: SafeU64,
    pub expires_at_utc_ms: SafeU64,
    pub deadline_monotonic_ms: SafeU64,
    pub caller_deadline_monotonic_ms: SafeU64,
}

impl fmt::Debug for RootLeaseRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootLeaseRequestV1(..)")
    }
}

/// Payload-free refusal before the atomic writer is invoked.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootLeaseRequestRefusalV1 {
    InvalidGrantContext,
    GrantNotCurrent,
    ObservationMismatch,
    AuthorityWidening,
    InvalidTime,
    InvalidInput,
    SigningFailed,
    AttemptUnavailable,
}

impl RootLeaseRequestRefusalV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::InvalidGrantContext => "ROOT_LEASE_INVALID_GRANT_CONTEXT",
            Self::GrantNotCurrent => "ROOT_LEASE_GRANT_NOT_CURRENT",
            Self::ObservationMismatch => "ROOT_LEASE_OBSERVATION_MISMATCH",
            Self::AuthorityWidening => "ROOT_LEASE_AUTHORITY_WIDENING",
            Self::InvalidTime => "ROOT_LEASE_INVALID_TIME",
            Self::InvalidInput => "ROOT_LEASE_INVALID_INPUT",
            Self::SigningFailed => "ROOT_LEASE_SIGNING_FAILED",
            Self::AttemptUnavailable => "ROOT_LEASE_ATTEMPT_UNAVAILABLE",
        }
    }
}

impl fmt::Debug for RootLeaseRequestRefusalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for RootLeaseRequestRefusalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl std::error::Error for RootLeaseRequestRefusalV1 {}

/// Signed, immutable root graph candidate. This value grants no current authority.
pub struct RootLeaseCandidateV1 {
    attempt: AuthorityAttemptBindingV1,
    source_grant: AuthenticHumanRequestGrantV1,
    source_grant_wire: Vec<u8>,
    signed_root_lease: SignedTaskLeaseV1,
    root_lease_wire: Vec<u8>,
    observations: RootIssuanceObservationsV1,
    observed_utc_ms: SafeU64,
    observed_monotonic_ms: SafeU64,
    clock_generation: Generation,
    boot_id: Identifier,
    instance_epoch: Generation,
}

impl RootLeaseCandidateV1 {
    pub const fn attempt_v1(&self) -> &AuthorityAttemptBindingV1 {
        &self.attempt
    }

    pub const fn source_grant_v1(&self) -> &AuthenticHumanRequestGrantV1 {
        &self.source_grant
    }

    pub fn source_grant_wire_v1(&self) -> &[u8] {
        &self.source_grant_wire
    }

    pub const fn signed_root_lease_v1(&self) -> &SignedTaskLeaseV1 {
        &self.signed_root_lease
    }

    pub fn root_lease_wire_v1(&self) -> &[u8] {
        &self.root_lease_wire
    }

    pub const fn observations_v1(&self) -> &RootIssuanceObservationsV1 {
        &self.observations
    }

    pub const fn observed_utc_ms_v1(&self) -> SafeU64 {
        self.observed_utc_ms
    }

    pub const fn observed_monotonic_ms_v1(&self) -> SafeU64 {
        self.observed_monotonic_ms
    }

    pub const fn clock_generation_v1(&self) -> Generation {
        self.clock_generation
    }

    pub fn boot_id_v1(&self) -> &str {
        self.boot_id.as_str()
    }

    pub const fn instance_epoch_v1(&self) -> Generation {
        self.instance_epoch
    }
}

impl fmt::Debug for RootLeaseCandidateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootLeaseCandidateV1(..)")
    }
}

impl AuthorityAtomicMutationV1 for RootLeaseCandidateV1 {
    fn attempt_binding_v1(&self) -> &AuthorityAttemptBindingV1 {
        &self.attempt
    }

    fn into_attempt_binding_v1(self) -> AuthorityAttemptBindingV1 {
        self.attempt
    }
}

/// Closed user-facing root request outcome.
pub enum RootLeaseRequestOutcomeV1<R>
where
    R: AuthorityRetainedGraphV1,
{
    CommittedRetained(R),
    Refused(RootLeaseRequestRefusalV1),
    DeniedDefinite,
    ConflictRetained,
    UncertainReadbackRequired(AuthorityUncertainReadbackV1<R>),
    AmbiguousReconciliationRequired,
    Unavailable,
}

impl<R> fmt::Debug for RootLeaseRequestOutcomeV1<R>
where
    R: AuthorityRetainedGraphV1,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CommittedRetained(_) => "RootLeaseRequestOutcomeV1::CommittedRetained(..)",
            Self::Refused(_) => "RootLeaseRequestOutcomeV1::Refused(..)",
            Self::DeniedDefinite => "RootLeaseRequestOutcomeV1::DeniedDefinite",
            Self::ConflictRetained => "RootLeaseRequestOutcomeV1::ConflictRetained",
            Self::UncertainReadbackRequired(_) => {
                "RootLeaseRequestOutcomeV1::UncertainReadbackRequired(..)"
            }
            Self::AmbiguousReconciliationRequired => {
                "RootLeaseRequestOutcomeV1::AmbiguousReconciliationRequired"
            }
            Self::Unavailable => "RootLeaseRequestOutcomeV1::Unavailable",
        })
    }
}

/// Verifies and signs one candidate without invoking a writer.
pub fn prepare_root_lease_candidate_v1<S: TaskLeaseSigner>(
    request: RootLeaseRequestV1,
    signer: &S,
) -> Result<RootLeaseCandidateV1, RootLeaseRequestRefusalV1> {
    if !request.human_context.exactly_matches_v1(&request.grant)
        || request.audience.as_str() != request.grant.claims().audience()
    {
        return Err(RootLeaseRequestRefusalV1::InvalidGrantContext);
    }
    if !request.source_currentness.is_current_v1() {
        return Err(RootLeaseRequestRefusalV1::GrantNotCurrent);
    }

    let observed_utc_ms = request.clock.sampled_utc_ms_v1();
    let observed_monotonic_ms = request.clock.sampled_monotonic_ms_v1();
    let grant_claims = request.grant.claims();
    if observed_utc_ms.get() < grant_claims.issued_at_utc_ms()
        || observed_utc_ms.get() >= grant_claims.expires_at_utc_ms()
    {
        return Err(RootLeaseRequestRefusalV1::GrantNotCurrent);
    }
    if observed_monotonic_ms.get() >= request.caller_deadline_monotonic_ms.get()
        || observed_monotonic_ms.get() >= request.deadline_monotonic_ms.get()
        || observed_utc_ms.get() > request.not_before_utc_ms.get()
        || request.not_before_utc_ms.get() >= request.expires_at_utc_ms.get()
    {
        return Err(RootLeaseRequestRefusalV1::InvalidTime);
    }

    let observations = &request.observations;
    let ceiling_trust = request.current_ceiling.trust_bound_v1();
    let ceiling_catalogue = request.current_ceiling.catalogue_bound_v1();
    if observations.scope.digest_v1() != grant_claims.scope_template_digest()
        || observations.scope.generation_v1().get() != grant_claims.scope_template_generation()
        || observations.policy.digest_v1() != ceiling_trust.policy_content_digest_v1()
        || observations.policy.generation_v1() != ceiling_trust.policy_generation_v1()
        || observations.catalogue.digest_v1() != ceiling_catalogue.catalogue_content_digest_v1()
        || observations.catalogue.generation_v1() != ceiling_catalogue.catalogue_generation_v1()
    {
        return Err(RootLeaseRequestRefusalV1::ObservationMismatch);
    }
    if !root_bounds_are_within_v1(&request.requested_bounds, &request.current_ceiling) {
        return Err(RootLeaseRequestRefusalV1::AuthorityWidening);
    }

    let requested_bounds_digest = request
        .requested_bounds
        .canonical_digest_v1()
        .map_err(map_contract_error_v1)?;
    let source_grant_wire = request
        .grant
        .canonical_signed_envelope_bytes()
        .map_err(map_contract_error_v1)?;
    let namespace_digest = grant_namespace_digest_v1(&request.grant);
    let observation_parts = [
        (
            request.observations.scope.digest_v1(),
            request.observations.scope.generation_v1(),
        ),
        (
            request.observations.policy.digest_v1(),
            request.observations.policy.generation_v1(),
        ),
        (
            request.observations.catalogue.digest_v1(),
            request.observations.catalogue.generation_v1(),
        ),
        (
            request.observations.workload.digest_v1(),
            request.observations.workload.generation_v1(),
        ),
        (
            request.observations.trust.digest_v1(),
            request.observations.trust.generation_v1(),
        ),
    ];
    let preimage = AuthorityIdempotencyPreimageV1::RootLeaseIssue(RootLeaseIssuePreimageV1::new(
        Sha256Digest::digest(&source_grant_wire),
        &request.task_id,
        &request.workload_id,
        &request.audience,
        requested_bounds_digest,
        request.observations.scope,
        request.observations.policy,
        request.observations.catalogue,
        request.observations.workload,
        request.observations.trust,
        request.caller_deadline_monotonic_ms,
    ));
    let attempt = AuthorityAttemptBindingV1::begin_v1(namespace_digest, &preimage)
        .ok_or(RootLeaseRequestRefusalV1::AttemptUnavailable)?;

    let lease_id = random_root_lease_id_v1()?;
    let boot_id = Identifier::new(request.clock.boot_id_v1())
        .map_err(|_| RootLeaseRequestRefusalV1::InvalidInput)?;
    let instance_epoch = request.clock.instance_epoch_v1();
    let protected = helix_task_authority_contracts::TaskLeaseProtectedV1::try_new_root_v1(
        RootTaskLeaseInputV1 {
            lease_id,
            issuer_id: request.lease_issuer_id,
            task_id: request.task_id,
            workload_id: request.workload_id,
            audience: request.audience,
            bounds: request.requested_bounds,
            clock_generation: request.clock.clock_generation_v1(),
            boot_id: Identifier::new(request.clock.boot_id_v1())
                .map_err(|_| RootLeaseRequestRefusalV1::InvalidInput)?,
            instance_epoch: SafeU64::new(instance_epoch.get())
                .map_err(|_| RootLeaseRequestRefusalV1::InvalidInput)?,
            issued_at_utc_ms: observed_utc_ms,
            not_before_utc_ms: request.not_before_utc_ms,
            expires_at_utc_ms: request.expires_at_utc_ms,
            issued_at_monotonic_ms: observed_monotonic_ms,
            deadline_monotonic_ms: request.deadline_monotonic_ms,
        },
        &request.grant,
        Identifier::new(signer.key_id()).map_err(|_| RootLeaseRequestRefusalV1::SigningFailed)?,
    )
    .map_err(map_contract_error_v1)?;
    let signed_root_lease = sign_task_lease_v1(protected, signer).map_err(map_contract_error_v1)?;
    let root_lease_wire = signed_root_lease
        .to_canonical_json()
        .map_err(map_contract_error_v1)?;

    Ok(RootLeaseCandidateV1 {
        attempt,
        source_grant: request.grant,
        source_grant_wire,
        signed_root_lease,
        root_lease_wire,
        observations: RootIssuanceObservationsV1::from_current_parts_v1(
            observation_parts[0].0,
            observation_parts[0].1,
            observation_parts[1].0,
            observation_parts[1].1,
            observation_parts[2].0,
            observation_parts[2].1,
            observation_parts[3].0,
            observation_parts[3].1,
            observation_parts[4].0,
            observation_parts[4].1,
        ),
        observed_utc_ms,
        observed_monotonic_ms,
        clock_generation: request.clock.clock_generation_v1(),
        boot_id,
        instance_epoch,
    })
}

/// Performs preparation and invokes the writer only after signing succeeds.
pub fn issue_root_lease_v1<S, W>(
    request: RootLeaseRequestV1,
    signer: &S,
    writer: &W,
) -> RootLeaseRequestOutcomeV1<W::Retained>
where
    S: TaskLeaseSigner,
    W: AuthorityAtomicStoreV1<RootLeaseCandidateV1>,
{
    let candidate = match prepare_root_lease_candidate_v1(request, signer) {
        Ok(candidate) => candidate,
        Err(refusal) => return RootLeaseRequestOutcomeV1::Refused(refusal),
    };
    match writer.commit_atomic_once_v1(candidate) {
        AuthorityMutationOutcomeV1::CommittedRetained(retained) => {
            RootLeaseRequestOutcomeV1::CommittedRetained(retained)
        }
        AuthorityMutationOutcomeV1::DeniedDefinite => RootLeaseRequestOutcomeV1::DeniedDefinite,
        AuthorityMutationOutcomeV1::ConflictRetained => RootLeaseRequestOutcomeV1::ConflictRetained,
        AuthorityMutationOutcomeV1::UncertainReadbackRequired(custody) => {
            RootLeaseRequestOutcomeV1::UncertainReadbackRequired(custody)
        }
        AuthorityMutationOutcomeV1::AmbiguousReconciliationRequired => {
            RootLeaseRequestOutcomeV1::AmbiguousReconciliationRequired
        }
        AuthorityMutationOutcomeV1::Unavailable => RootLeaseRequestOutcomeV1::Unavailable,
    }
}

fn map_contract_error_v1(error: ContractError) -> RootLeaseRequestRefusalV1 {
    match error {
        ContractError::SigningFailed | ContractError::WrongKeyPurpose => {
            RootLeaseRequestRefusalV1::SigningFailed
        }
        ContractError::InvalidField => RootLeaseRequestRefusalV1::InvalidTime,
        _ => RootLeaseRequestRefusalV1::InvalidInput,
    }
}

fn grant_namespace_digest_v1(grant: &AuthenticHumanRequestGrantV1) -> AuthorityNamespaceDigestV1 {
    let claims = grant.claims();
    let issuer = claims.issuer_id().as_bytes();
    let mut bytes = Vec::with_capacity(GRANT_NAMESPACE_DOMAIN_V1.len() + 4 + issuer.len() + 32);
    bytes.extend_from_slice(GRANT_NAMESPACE_DOMAIN_V1);
    bytes.extend_from_slice(&(issuer.len() as u32).to_be_bytes());
    bytes.extend_from_slice(issuer);
    bytes.extend_from_slice(claims.grant_id().as_bytes());
    AuthorityNamespaceDigestV1::from_verified_digest_v1(Sha256Digest::digest(&bytes))
}

fn random_root_lease_id_v1() -> Result<Sha256Digest, RootLeaseRequestRefusalV1> {
    let mut entropy = [0_u8; 32];
    getrandom::fill(&mut entropy).map_err(|_| RootLeaseRequestRefusalV1::AttemptUnavailable)?;
    let mut bytes = Vec::with_capacity(ROOT_LEASE_ID_DOMAIN_V1.len() + entropy.len());
    bytes.extend_from_slice(ROOT_LEASE_ID_DOMAIN_V1);
    bytes.extend_from_slice(&entropy);
    Ok(Sha256Digest::digest(&bytes))
}
