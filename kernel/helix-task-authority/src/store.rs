//! Portable atomic persistence contract for durable task-authority mutations.
//!
//! Stable idempotency inputs are typed and domain-selected by this module. Generated
//! candidate values never enter their preimages, and an attempt is correlation
//! evidence only: it never grants authority to retry a mutation.

#![allow(dead_code)]

use crate::{
    AuthorityMutationOutcomeV1, AuthorityReadbackOutcomeV1, AuthorityRetainedOutcomeCodeV1,
};
use helix_task_authority_contracts::{
    ApprovalDecisionValueV1, AuthenticationProfileV1, Generation, Identifier, SafeU64, Sha256Digest,
};
use std::fmt;

const ATTEMPT_ID_DOMAIN: &[u8] = b"HELIXOS\0TASK-AUTHORITY-ATTEMPT\0V1\0";

/// Closed durable operation inventory shared with the strict HLXA v1 schema.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityOperationKindV1 {
    Bootstrap,
    KeyStatusChange,
    RootLeaseIssue,
    ChildLeaseIssue,
    CounterConsume,
    DecisionRetain,
    AuthorityRevoke,
    BackupPublish,
    RestorePublish,
}

impl AuthorityOperationKindV1 {
    pub const ALL: [Self; 9] = [
        Self::Bootstrap,
        Self::KeyStatusChange,
        Self::RootLeaseIssue,
        Self::ChildLeaseIssue,
        Self::CounterConsume,
        Self::DecisionRetain,
        Self::AuthorityRevoke,
        Self::BackupPublish,
        Self::RestorePublish,
    ];

    /// Exact value retained in `authority_attempts.operation_kind`.
    pub const fn sql_code_v1(self) -> &'static str {
        match self {
            Self::Bootstrap => "BOOTSTRAP",
            Self::KeyStatusChange => "KEY_STATUS_CHANGE",
            Self::RootLeaseIssue => "ROOT_LEASE_ISSUE",
            Self::ChildLeaseIssue => "CHILD_LEASE_ISSUE",
            Self::CounterConsume => "COUNTER_CONSUME",
            Self::DecisionRetain => "DECISION_RETAIN",
            Self::AuthorityRevoke => "AUTHORITY_REVOKE",
            Self::BackupPublish => "BACKUP_PUBLISH",
            Self::RestorePublish => "RESTORE_PUBLISH",
        }
    }

    /// Exact bytes prepended to the operation's canonical stable preimage.
    pub const fn idempotency_domain_v1(self) -> &'static [u8] {
        match self {
            Self::Bootstrap => b"HELIXOS\0TASK-AUTHORITY-BOOTSTRAP\0V1\0",
            Self::KeyStatusChange => b"HELIXOS\0TASK-AUTHORITY-KEY-STATUS\0V1\0",
            Self::RootLeaseIssue => b"HELIXOS\0TASK-AUTHORITY-ROOT-ISSUE\0V1\0",
            Self::ChildLeaseIssue => b"HELIXOS\0TASK-AUTHORITY-CHILD-DELEGATION\0V1\0",
            Self::CounterConsume => b"HELIXOS\0TASK-AUTHORITY-COUNTER-CONSUMPTION\0V1\0",
            Self::DecisionRetain => b"HELIXOS\0TASK-AUTHORITY-TERMINAL-DECISION\0V1\0",
            Self::AuthorityRevoke => b"HELIXOS\0TASK-AUTHORITY-REVOCATION\0V1\0",
            Self::BackupPublish => b"HELIXOS\0TASK-AUTHORITY-BACKUP\0V1\0",
            Self::RestorePublish => b"HELIXOS\0TASK-AUTHORITY-RESTORE\0V1\0",
        }
    }
}

impl fmt::Debug for AuthorityOperationKindV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bootstrap => "AuthorityOperationKindV1::Bootstrap",
            Self::KeyStatusChange => "AuthorityOperationKindV1::KeyStatusChange",
            Self::RootLeaseIssue => "AuthorityOperationKindV1::RootLeaseIssue",
            Self::ChildLeaseIssue => "AuthorityOperationKindV1::ChildLeaseIssue",
            Self::CounterConsume => "AuthorityOperationKindV1::CounterConsume",
            Self::DecisionRetain => "AuthorityOperationKindV1::DecisionRetain",
            Self::AuthorityRevoke => "AuthorityOperationKindV1::AuthorityRevoke",
            Self::BackupPublish => "AuthorityOperationKindV1::BackupPublish",
            Self::RestorePublish => "AuthorityOperationKindV1::RestorePublish",
        })
    }
}

/// Closed counter families accepted by the durable counter-consumption graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityCounterKindV1 {
    ReadBytes,
    DistinctFiles,
    Actions,
    Plans,
    Approvals,
}

impl AuthorityCounterKindV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::ReadBytes => "READ_BYTES",
            Self::DistinctFiles => "DISTINCT_FILES",
            Self::Actions => "ACTIONS",
            Self::Plans => "PLANS",
            Self::Approvals => "APPROVALS",
        }
    }
}

/// Closed signing purposes for durable key-status transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthoritySignerPurposeV1 {
    RequestSurfaceGrantSigning,
    CoreTaskLeaseSigning,
    CoreApprovalDecisionSigning,
}

impl AuthoritySignerPurposeV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::RequestSurfaceGrantSigning => "request-surface-grant-signing",
            Self::CoreTaskLeaseSigning => "core-task-lease-signing",
            Self::CoreApprovalDecisionSigning => "core-approval-decision-signing",
        }
    }
}

/// Requested durable verification-key status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityKeyStatusV1 {
    Trusted,
    Retired,
    Revoked,
}

impl AuthorityKeyStatusV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Retired => "RETIRED",
            Self::Revoked => "REVOKED",
        }
    }
}

/// Closed reason inventory for verification-key status changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityKeyStatusReasonV1 {
    KeyIntroduced,
    KeyRotated,
    KeyRetired,
    KeyCompromised,
    AdminRevoked,
}

impl AuthorityKeyStatusReasonV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::KeyIntroduced => "KEY_INTRODUCED",
            Self::KeyRotated => "KEY_ROTATED",
            Self::KeyRetired => "KEY_RETIRED",
            Self::KeyCompromised => "KEY_COMPROMISED",
            Self::AdminRevoked => "ADMIN_REVOKED",
        }
    }
}

/// Closed revocation subject inventory retained by HLXA v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityRevocationSubjectKindV1 {
    Signer,
    Grant,
    Lease,
    Decision,
    Boot,
    Instance,
    ScopeTemplate,
}

impl AuthorityRevocationSubjectKindV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Signer => "SIGNER",
            Self::Grant => "GRANT",
            Self::Lease => "LEASE",
            Self::Decision => "DECISION",
            Self::Boot => "BOOT",
            Self::Instance => "INSTANCE",
            Self::ScopeTemplate => "SCOPE_TEMPLATE",
        }
    }
}

/// Closed reason inventory for durable authority revocations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityRevocationReasonV1 {
    AdminRevoked,
    KeyCompromised,
    SourceRevoked,
    AncestorRevoked,
    DecisionRevoked,
    BootReplaced,
    InstanceReplaced,
    ScopeReplaced,
}

impl AuthorityRevocationReasonV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::AdminRevoked => "ADMIN_REVOKED",
            Self::KeyCompromised => "KEY_COMPROMISED",
            Self::SourceRevoked => "SOURCE_REVOKED",
            Self::AncestorRevoked => "ANCESTOR_REVOKED",
            Self::DecisionRevoked => "DECISION_REVOKED",
            Self::BootReplaced => "BOOT_REPLACED",
            Self::InstanceReplaced => "INSTANCE_REPLACED",
            Self::ScopeReplaced => "SCOPE_REPLACED",
        }
    }
}

/// Closed root-lifecycle targets used by bootstrap, backup and restore preimages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityLifecycleV1 {
    Absent,
    Active,
    RestorePending,
}

impl AuthorityLifecycleV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Absent => "ABSENT",
            Self::Active => "ACTIVE",
            Self::RestorePending => "RESTORE_PENDING",
        }
    }
}

/// Exact digest and current generation of one authoritative observation.
pub struct AuthorityObservationBindingV1 {
    digest: Sha256Digest,
    generation: Generation,
}

impl AuthorityObservationBindingV1 {
    pub(crate) const fn new(digest: Sha256Digest, generation: Generation) -> Self {
        Self { digest, generation }
    }

    pub const fn digest_v1(&self) -> Sha256Digest {
        self.digest
    }

    pub const fn generation_v1(&self) -> Generation {
        self.generation
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            "{{\"digest\":\"{}\",\"generation\":{}}}",
            self.digest.to_hex(),
            self.generation.get()
        )
    }
}

impl fmt::Debug for AuthorityObservationBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityObservationBindingV1")
            .finish_non_exhaustive()
    }
}

/// Stable root-lease issuance input frozen before candidate signing.
pub struct RootLeaseIssuePreimageV1 {
    request_grant_wire_digest: Sha256Digest,
    task_id: Box<str>,
    workload_id: Box<str>,
    audience: Box<str>,
    requested_authority_bounds_digest: Sha256Digest,
    scope_observation: AuthorityObservationBindingV1,
    policy_observation: AuthorityObservationBindingV1,
    catalogue_observation: AuthorityObservationBindingV1,
    workload_observation: AuthorityObservationBindingV1,
    trust_observation: AuthorityObservationBindingV1,
    caller_deadline_monotonic_ms: SafeU64,
}

impl RootLeaseIssuePreimageV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_grant_wire_digest: Sha256Digest,
        task_id: &Identifier,
        workload_id: &Identifier,
        audience: &Identifier,
        requested_authority_bounds_digest: Sha256Digest,
        scope_observation: AuthorityObservationBindingV1,
        policy_observation: AuthorityObservationBindingV1,
        catalogue_observation: AuthorityObservationBindingV1,
        workload_observation: AuthorityObservationBindingV1,
        trust_observation: AuthorityObservationBindingV1,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            request_grant_wire_digest,
            task_id: task_id.as_str().into(),
            workload_id: workload_id.as_str().into(),
            audience: audience.as_str().into(),
            requested_authority_bounds_digest,
            scope_observation,
            policy_observation,
            catalogue_observation,
            workload_observation,
            trust_observation,
            caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            concat!(
                "{{\"audience\":\"{}\",",
                "\"caller_deadline_monotonic_ms\":{},",
                "\"catalogue_observation\":{},",
                "\"policy_observation\":{},",
                "\"request_grant_wire_digest\":\"{}\",",
                "\"requested_authority_bounds_digest\":\"{}\",",
                "\"scope_observation\":{},",
                "\"task_id\":\"{}\",",
                "\"trust_observation\":{},",
                "\"workload_id\":\"{}\",",
                "\"workload_observation\":{}}}"
            ),
            self.audience,
            self.caller_deadline_monotonic_ms.get(),
            self.catalogue_observation.canonical_jcs_v1(),
            self.policy_observation.canonical_jcs_v1(),
            self.request_grant_wire_digest.to_hex(),
            self.requested_authority_bounds_digest.to_hex(),
            self.scope_observation.canonical_jcs_v1(),
            self.task_id,
            self.trust_observation.canonical_jcs_v1(),
            self.workload_id,
            self.workload_observation.canonical_jcs_v1(),
        )
    }
}

impl fmt::Debug for RootLeaseIssuePreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RootLeaseIssuePreimageV1")
            .finish_non_exhaustive()
    }
}

/// Stable restrictive child-delegation input frozen before candidate signing.
pub struct ChildLeaseIssuePreimageV1 {
    source_grant_digest: Sha256Digest,
    parent_lease_digest: Sha256Digest,
    task_id: Box<str>,
    workload_id: Box<str>,
    audience: Box<str>,
    requested_restrictive_authority_digest: Sha256Digest,
    ancestor_observation: AuthorityObservationBindingV1,
    allocation_observation: AuthorityObservationBindingV1,
    counter_observation: AuthorityObservationBindingV1,
    trust_observation: AuthorityObservationBindingV1,
    caller_deadline_monotonic_ms: SafeU64,
}

impl ChildLeaseIssuePreimageV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        source_grant_digest: Sha256Digest,
        parent_lease_digest: Sha256Digest,
        task_id: &Identifier,
        workload_id: &Identifier,
        audience: &Identifier,
        requested_restrictive_authority_digest: Sha256Digest,
        ancestor_observation: AuthorityObservationBindingV1,
        allocation_observation: AuthorityObservationBindingV1,
        counter_observation: AuthorityObservationBindingV1,
        trust_observation: AuthorityObservationBindingV1,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            source_grant_digest,
            parent_lease_digest,
            task_id: task_id.as_str().into(),
            workload_id: workload_id.as_str().into(),
            audience: audience.as_str().into(),
            requested_restrictive_authority_digest,
            ancestor_observation,
            allocation_observation,
            counter_observation,
            trust_observation,
            caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            concat!(
                "{{\"allocation_observation\":{},",
                "\"ancestor_observation\":{},",
                "\"audience\":\"{}\",",
                "\"caller_deadline_monotonic_ms\":{},",
                "\"counter_observation\":{},",
                "\"parent_lease_digest\":\"{}\",",
                "\"requested_restrictive_authority_digest\":\"{}\",",
                "\"source_grant_digest\":\"{}\",",
                "\"task_id\":\"{}\",",
                "\"trust_observation\":{},",
                "\"workload_id\":\"{}\"}}"
            ),
            self.allocation_observation.canonical_jcs_v1(),
            self.ancestor_observation.canonical_jcs_v1(),
            self.audience,
            self.caller_deadline_monotonic_ms.get(),
            self.counter_observation.canonical_jcs_v1(),
            self.parent_lease_digest.to_hex(),
            self.requested_restrictive_authority_digest.to_hex(),
            self.source_grant_digest.to_hex(),
            self.task_id,
            self.trust_observation.canonical_jcs_v1(),
            self.workload_id,
        )
    }
}

impl fmt::Debug for ChildLeaseIssuePreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChildLeaseIssuePreimageV1")
            .finish_non_exhaustive()
    }
}

/// Stable monotonic counter-consumption input.
pub struct CounterConsumePreimageV1 {
    lease_digest: Sha256Digest,
    ancestor_projection_digest: Sha256Digest,
    counter_kind: AuthorityCounterKindV1,
    amount: SafeU64,
    context_digest: Sha256Digest,
    current_counter_generation: Generation,
    caller_deadline_monotonic_ms: SafeU64,
}

impl CounterConsumePreimageV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        lease_digest: Sha256Digest,
        ancestor_projection_digest: Sha256Digest,
        counter_kind: AuthorityCounterKindV1,
        amount: SafeU64,
        context_digest: Sha256Digest,
        current_counter_generation: Generation,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            lease_digest,
            ancestor_projection_digest,
            counter_kind,
            amount,
            context_digest,
            current_counter_generation,
            caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            concat!(
                "{{\"amount\":{},",
                "\"ancestor_projection_digest\":\"{}\",",
                "\"caller_deadline_monotonic_ms\":{},",
                "\"context_digest\":\"{}\",",
                "\"counter_kind\":\"{}\",",
                "\"current_counter_generation\":{},",
                "\"lease_digest\":\"{}\"}}"
            ),
            self.amount.get(),
            self.ancestor_projection_digest.to_hex(),
            self.caller_deadline_monotonic_ms.get(),
            self.context_digest.to_hex(),
            self.counter_kind.code_v1(),
            self.current_counter_generation.get(),
            self.lease_digest.to_hex(),
        )
    }
}

impl fmt::Debug for CounterConsumePreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CounterConsumePreimageV1")
            .finish_non_exhaustive()
    }
}

/// Stable one-terminal-decision input frozen before candidate signing.
pub struct DecisionRetainPreimageV1 {
    plan_envelope_digest: Sha256Digest,
    grant_projection_digest: Sha256Digest,
    ancestor_projection_digest: Sha256Digest,
    lease_projection_digest: Sha256Digest,
    requested_terminal_value: ApprovalDecisionValueV1,
    authentication_profile: AuthenticationProfileV1,
    authentication_evidence_digest: Sha256Digest,
    policy_observation: AuthorityObservationBindingV1,
    catalogue_observation: AuthorityObservationBindingV1,
    trust_observation: AuthorityObservationBindingV1,
    caller_deadline_monotonic_ms: SafeU64,
}

impl DecisionRetainPreimageV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        plan_envelope_digest: Sha256Digest,
        grant_projection_digest: Sha256Digest,
        ancestor_projection_digest: Sha256Digest,
        lease_projection_digest: Sha256Digest,
        requested_terminal_value: ApprovalDecisionValueV1,
        authentication_profile: AuthenticationProfileV1,
        authentication_evidence_digest: Sha256Digest,
        policy_observation: AuthorityObservationBindingV1,
        catalogue_observation: AuthorityObservationBindingV1,
        trust_observation: AuthorityObservationBindingV1,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            plan_envelope_digest,
            grant_projection_digest,
            ancestor_projection_digest,
            lease_projection_digest,
            requested_terminal_value,
            authentication_profile,
            authentication_evidence_digest,
            policy_observation,
            catalogue_observation,
            trust_observation,
            caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            concat!(
                "{{\"ancestor_projection_digest\":\"{}\",",
                "\"authentication_evidence_digest\":\"{}\",",
                "\"authentication_profile\":\"{}\",",
                "\"caller_deadline_monotonic_ms\":{},",
                "\"catalogue_observation\":{},",
                "\"grant_projection_digest\":\"{}\",",
                "\"lease_projection_digest\":\"{}\",",
                "\"plan_envelope_digest\":\"{}\",",
                "\"policy_observation\":{},",
                "\"requested_terminal_value\":\"{}\",",
                "\"trust_observation\":{}}}"
            ),
            self.ancestor_projection_digest.to_hex(),
            self.authentication_evidence_digest.to_hex(),
            authentication_profile_code_v1(self.authentication_profile),
            self.caller_deadline_monotonic_ms.get(),
            self.catalogue_observation.canonical_jcs_v1(),
            self.grant_projection_digest.to_hex(),
            self.lease_projection_digest.to_hex(),
            self.plan_envelope_digest.to_hex(),
            self.policy_observation.canonical_jcs_v1(),
            approval_decision_code_v1(self.requested_terminal_value),
            self.trust_observation.canonical_jcs_v1(),
        )
    }
}

impl fmt::Debug for DecisionRetainPreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionRetainPreimageV1")
            .finish_non_exhaustive()
    }
}

const fn authentication_profile_code_v1(value: AuthenticationProfileV1) -> &'static str {
    match value {
        AuthenticationProfileV1::SessionAuthenticatedV1 => "SESSION_AUTHENTICATED_V1",
        AuthenticationProfileV1::UserVerificationV1 => "USER_VERIFICATION_V1",
        AuthenticationProfileV1::SyntheticConformanceV1 => "SYNTHETIC_CONFORMANCE_V1",
    }
}

const fn approval_decision_code_v1(value: ApprovalDecisionValueV1) -> &'static str {
    match value {
        ApprovalDecisionValueV1::Approved => "APPROVED",
        ApprovalDecisionValueV1::Denied => "DENIED",
    }
}

/// Stable verification-key status transition input.
pub struct KeyStatusChangePreimageV1 {
    subject_binding_digest: Sha256Digest,
    signer_purpose: AuthoritySignerPurposeV1,
    current_trust_generation: Generation,
    requested_status: AuthorityKeyStatusV1,
    reason: AuthorityKeyStatusReasonV1,
    effective_at_utc_ms: SafeU64,
    caller_deadline_monotonic_ms: SafeU64,
}

impl KeyStatusChangePreimageV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        subject_binding_digest: Sha256Digest,
        signer_purpose: AuthoritySignerPurposeV1,
        current_trust_generation: Generation,
        requested_status: AuthorityKeyStatusV1,
        reason: AuthorityKeyStatusReasonV1,
        effective_at_utc_ms: SafeU64,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            subject_binding_digest,
            signer_purpose,
            current_trust_generation,
            requested_status,
            reason,
            effective_at_utc_ms,
            caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            concat!(
                "{{\"caller_deadline_monotonic_ms\":{},",
                "\"current_trust_generation\":{},",
                "\"effective_at_utc_ms\":{},",
                "\"reason\":\"{}\",",
                "\"requested_status\":\"{}\",",
                "\"signer_purpose\":\"{}\",",
                "\"subject_binding_digest\":\"{}\"}}"
            ),
            self.caller_deadline_monotonic_ms.get(),
            self.current_trust_generation.get(),
            self.effective_at_utc_ms.get(),
            self.reason.code_v1(),
            self.requested_status.code_v1(),
            self.signer_purpose.code_v1(),
            self.subject_binding_digest.to_hex(),
        )
    }
}

impl fmt::Debug for KeyStatusChangePreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyStatusChangePreimageV1")
            .finish_non_exhaustive()
    }
}

/// Stable append-only authority-revocation input.
pub struct AuthorityRevokePreimageV1 {
    subject_binding_digest: Sha256Digest,
    subject_kind: AuthorityRevocationSubjectKindV1,
    current_subject_generation: Generation,
    reason: AuthorityRevocationReasonV1,
    effective_time_binding_digest: Sha256Digest,
    caller_deadline_monotonic_ms: SafeU64,
}

impl AuthorityRevokePreimageV1 {
    pub(crate) const fn new(
        subject_binding_digest: Sha256Digest,
        subject_kind: AuthorityRevocationSubjectKindV1,
        current_subject_generation: Generation,
        reason: AuthorityRevocationReasonV1,
        effective_time_binding_digest: Sha256Digest,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            subject_binding_digest,
            subject_kind,
            current_subject_generation,
            reason,
            effective_time_binding_digest,
            caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            concat!(
                "{{\"caller_deadline_monotonic_ms\":{},",
                "\"current_subject_generation\":{},",
                "\"effective_time_binding_digest\":\"{}\",",
                "\"reason\":\"{}\",",
                "\"subject_binding_digest\":\"{}\",",
                "\"subject_kind\":\"{}\"}}"
            ),
            self.caller_deadline_monotonic_ms.get(),
            self.current_subject_generation.get(),
            self.effective_time_binding_digest.to_hex(),
            self.reason.code_v1(),
            self.subject_binding_digest.to_hex(),
            self.subject_kind.code_v1(),
        )
    }
}

impl fmt::Debug for AuthorityRevokePreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRevokePreimageV1")
            .finish_non_exhaustive()
    }
}

/// Common stable leaves for bootstrap, backup and restore publication.
pub struct AuthorityLifecyclePreimageV1 {
    source_digest: Sha256Digest,
    root_digest: Sha256Digest,
    schema_digest: Sha256Digest,
    package_digest: Sha256Digest,
    configuration_digest: Sha256Digest,
    requested_lifecycle: AuthorityLifecycleV1,
    epoch_transition_digest: Sha256Digest,
    caller_deadline_monotonic_ms: SafeU64,
}

impl AuthorityLifecyclePreimageV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        source_digest: Sha256Digest,
        root_digest: Sha256Digest,
        schema_digest: Sha256Digest,
        package_digest: Sha256Digest,
        configuration_digest: Sha256Digest,
        requested_lifecycle: AuthorityLifecycleV1,
        epoch_transition_digest: Sha256Digest,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            source_digest,
            root_digest,
            schema_digest,
            package_digest,
            configuration_digest,
            requested_lifecycle,
            epoch_transition_digest,
            caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        format!(
            concat!(
                "{{\"caller_deadline_monotonic_ms\":{},",
                "\"configuration_digest\":\"{}\",",
                "\"epoch_transition_digest\":\"{}\",",
                "\"package_digest\":\"{}\",",
                "\"requested_lifecycle\":\"{}\",",
                "\"root_digest\":\"{}\",",
                "\"schema_digest\":\"{}\",",
                "\"source_digest\":\"{}\"}}"
            ),
            self.caller_deadline_monotonic_ms.get(),
            self.configuration_digest.to_hex(),
            self.epoch_transition_digest.to_hex(),
            self.package_digest.to_hex(),
            self.requested_lifecycle.code_v1(),
            self.root_digest.to_hex(),
            self.schema_digest.to_hex(),
            self.source_digest.to_hex(),
        )
    }
}

impl fmt::Debug for AuthorityLifecyclePreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityLifecyclePreimageV1")
            .finish_non_exhaustive()
    }
}

/// Stable bootstrap publication input.
pub struct BootstrapPreimageV1 {
    lifecycle: AuthorityLifecyclePreimageV1,
}

impl BootstrapPreimageV1 {
    pub(crate) const fn new(lifecycle: AuthorityLifecyclePreimageV1) -> Self {
        Self { lifecycle }
    }
}

impl fmt::Debug for BootstrapPreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapPreimageV1")
            .finish_non_exhaustive()
    }
}

/// Stable manifest-last backup publication input.
pub struct BackupPublishPreimageV1 {
    lifecycle: AuthorityLifecyclePreimageV1,
}

impl BackupPublishPreimageV1 {
    pub(crate) const fn new(lifecycle: AuthorityLifecyclePreimageV1) -> Self {
        Self { lifecycle }
    }
}

impl fmt::Debug for BackupPublishPreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupPublishPreimageV1")
            .finish_non_exhaustive()
    }
}

/// Stable restore publication input whose retained lifecycle remains non-active.
pub struct RestorePublishPreimageV1 {
    lifecycle: AuthorityLifecyclePreimageV1,
}

impl RestorePublishPreimageV1 {
    pub(crate) const fn new(lifecycle: AuthorityLifecyclePreimageV1) -> Self {
        Self { lifecycle }
    }
}

impl fmt::Debug for RestorePublishPreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestorePublishPreimageV1")
            .finish_non_exhaustive()
    }
}

/// Exactly one of the nine closed stable idempotency preimages.
pub enum AuthorityIdempotencyPreimageV1 {
    Bootstrap(BootstrapPreimageV1),
    KeyStatusChange(KeyStatusChangePreimageV1),
    RootLeaseIssue(RootLeaseIssuePreimageV1),
    ChildLeaseIssue(ChildLeaseIssuePreimageV1),
    CounterConsume(CounterConsumePreimageV1),
    DecisionRetain(DecisionRetainPreimageV1),
    AuthorityRevoke(AuthorityRevokePreimageV1),
    BackupPublish(BackupPublishPreimageV1),
    RestorePublish(RestorePublishPreimageV1),
}

impl AuthorityIdempotencyPreimageV1 {
    pub const fn operation_kind_v1(&self) -> AuthorityOperationKindV1 {
        match self {
            Self::Bootstrap(_) => AuthorityOperationKindV1::Bootstrap,
            Self::KeyStatusChange(_) => AuthorityOperationKindV1::KeyStatusChange,
            Self::RootLeaseIssue(_) => AuthorityOperationKindV1::RootLeaseIssue,
            Self::ChildLeaseIssue(_) => AuthorityOperationKindV1::ChildLeaseIssue,
            Self::CounterConsume(_) => AuthorityOperationKindV1::CounterConsume,
            Self::DecisionRetain(_) => AuthorityOperationKindV1::DecisionRetain,
            Self::AuthorityRevoke(_) => AuthorityOperationKindV1::AuthorityRevoke,
            Self::BackupPublish(_) => AuthorityOperationKindV1::BackupPublish,
            Self::RestorePublish(_) => AuthorityOperationKindV1::RestorePublish,
        }
    }

    pub fn input_graph_digest_v1(&self) -> Sha256Digest {
        let operation_kind = self.operation_kind_v1();
        let canonical_jcs = self.canonical_jcs_v1();
        let mut digest_input =
            Vec::with_capacity(operation_kind.idempotency_domain_v1().len() + canonical_jcs.len());
        digest_input.extend_from_slice(operation_kind.idempotency_domain_v1());
        digest_input.extend_from_slice(canonical_jcs.as_bytes());
        Sha256Digest::digest(&digest_input)
    }

    pub const fn caller_deadline_monotonic_ms_v1(&self) -> SafeU64 {
        match self {
            Self::Bootstrap(value) => value.lifecycle.caller_deadline_monotonic_ms,
            Self::KeyStatusChange(value) => value.caller_deadline_monotonic_ms,
            Self::RootLeaseIssue(value) => value.caller_deadline_monotonic_ms,
            Self::ChildLeaseIssue(value) => value.caller_deadline_monotonic_ms,
            Self::CounterConsume(value) => value.caller_deadline_monotonic_ms,
            Self::DecisionRetain(value) => value.caller_deadline_monotonic_ms,
            Self::AuthorityRevoke(value) => value.caller_deadline_monotonic_ms,
            Self::BackupPublish(value) => value.lifecycle.caller_deadline_monotonic_ms,
            Self::RestorePublish(value) => value.lifecycle.caller_deadline_monotonic_ms,
        }
    }

    fn canonical_jcs_v1(&self) -> String {
        match self {
            Self::Bootstrap(value) => value.lifecycle.canonical_jcs_v1(),
            Self::KeyStatusChange(value) => value.canonical_jcs_v1(),
            Self::RootLeaseIssue(value) => value.canonical_jcs_v1(),
            Self::ChildLeaseIssue(value) => value.canonical_jcs_v1(),
            Self::CounterConsume(value) => value.canonical_jcs_v1(),
            Self::DecisionRetain(value) => value.canonical_jcs_v1(),
            Self::AuthorityRevoke(value) => value.canonical_jcs_v1(),
            Self::BackupPublish(value) => value.lifecycle.canonical_jcs_v1(),
            Self::RestorePublish(value) => value.lifecycle.canonical_jcs_v1(),
        }
    }
}

impl fmt::Debug for AuthorityIdempotencyPreimageV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bootstrap(_) => "AuthorityIdempotencyPreimageV1::Bootstrap(..)",
            Self::KeyStatusChange(_) => "AuthorityIdempotencyPreimageV1::KeyStatusChange(..)",
            Self::RootLeaseIssue(_) => "AuthorityIdempotencyPreimageV1::RootLeaseIssue(..)",
            Self::ChildLeaseIssue(_) => "AuthorityIdempotencyPreimageV1::ChildLeaseIssue(..)",
            Self::CounterConsume(_) => "AuthorityIdempotencyPreimageV1::CounterConsume(..)",
            Self::DecisionRetain(_) => "AuthorityIdempotencyPreimageV1::DecisionRetain(..)",
            Self::AuthorityRevoke(_) => "AuthorityIdempotencyPreimageV1::AuthorityRevoke(..)",
            Self::BackupPublish(_) => "AuthorityIdempotencyPreimageV1::BackupPublish(..)",
            Self::RestorePublish(_) => "AuthorityIdempotencyPreimageV1::RestorePublish(..)",
        })
    }
}

/// Random, domain-separated correlation identity for one mutation attempt.
pub struct AuthorityAttemptIdV1 {
    digest: Sha256Digest,
}

impl AuthorityAttemptIdV1 {
    /// Reconstructs an opaque attempt identity after strict durable-row verification.
    ///
    /// An attempt identity is correlation evidence and never authorizes a retry.
    pub const fn from_verified_digest_v1(digest: Sha256Digest) -> Self {
        Self { digest }
    }

    fn from_entropy_v1(operation_kind: AuthorityOperationKindV1, entropy: [u8; 32]) -> Self {
        let mut input = Vec::with_capacity(
            ATTEMPT_ID_DOMAIN.len() + operation_kind.idempotency_domain_v1().len() + entropy.len(),
        );
        input.extend_from_slice(ATTEMPT_ID_DOMAIN);
        input.extend_from_slice(operation_kind.idempotency_domain_v1());
        input.extend_from_slice(&entropy);
        Self {
            digest: Sha256Digest::digest(&input),
        }
    }

    pub const fn digest_v1(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for AuthorityAttemptIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityAttemptIdV1")
            .finish_non_exhaustive()
    }
}

/// Canonical one-shot namespace digest, distinct from attempt and input identity.
pub struct AuthorityNamespaceDigestV1 {
    digest: Sha256Digest,
}

impl AuthorityNamespaceDigestV1 {
    /// Reconstructs a canonical namespace binding after exact verification.
    pub const fn from_verified_digest_v1(digest: Sha256Digest) -> Self {
        Self { digest }
    }

    pub const fn digest_v1(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for AuthorityNamespaceDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityNamespaceDigestV1")
            .finish_non_exhaustive()
    }
}

/// Domain-separated digest of one typed closed stable preimage.
pub struct AuthorityInputGraphDigestV1 {
    digest: Sha256Digest,
}

impl AuthorityInputGraphDigestV1 {
    /// Reconstructs a stable input binding after exact preimage or row verification.
    pub const fn from_verified_digest_v1(digest: Sha256Digest) -> Self {
        Self { digest }
    }

    fn from_preimage_v1(preimage: &AuthorityIdempotencyPreimageV1) -> Self {
        Self {
            digest: preimage.input_graph_digest_v1(),
        }
    }

    pub const fn digest_v1(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for AuthorityInputGraphDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityInputGraphDigestV1")
            .finish_non_exhaustive()
    }
}

/// Digest binding the complete retained outcome graph.
pub struct AuthorityOutcomeBindingDigestV1 {
    digest: Sha256Digest,
}

impl AuthorityOutcomeBindingDigestV1 {
    /// Reconstructs an exact complete-graph outcome binding after verification.
    pub const fn from_verified_digest_v1(digest: Sha256Digest) -> Self {
        Self { digest }
    }

    pub const fn digest_v1(&self) -> Sha256Digest {
        self.digest
    }
}

impl fmt::Debug for AuthorityOutcomeBindingDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityOutcomeBindingDigestV1")
            .finish_non_exhaustive()
    }
}

/// Immutable pre-commit attempt binding carried by a core-created candidate.
pub struct AuthorityAttemptBindingV1 {
    attempt_id: AuthorityAttemptIdV1,
    operation_kind: AuthorityOperationKindV1,
    namespace_digest: AuthorityNamespaceDigestV1,
    input_graph_digest: AuthorityInputGraphDigestV1,
    caller_deadline_monotonic_ms: SafeU64,
}

impl AuthorityAttemptBindingV1 {
    /// Reconstructs an immutable attempt binding from a strictly verified durable row.
    ///
    /// This evidence remains non-authoritative: current authority requires a later
    /// complete-graph snapshot and guard.
    pub fn from_verified_parts_v1(
        attempt_id: AuthorityAttemptIdV1,
        operation_kind: AuthorityOperationKindV1,
        namespace_digest: AuthorityNamespaceDigestV1,
        input_graph_digest: AuthorityInputGraphDigestV1,
        caller_deadline_monotonic_ms: SafeU64,
    ) -> Option<Self> {
        if caller_deadline_monotonic_ms.get() == 0 {
            return None;
        }
        Some(Self {
            attempt_id,
            operation_kind,
            namespace_digest,
            input_graph_digest,
            caller_deadline_monotonic_ms,
        })
    }

    pub(crate) fn begin_v1(
        namespace_digest: AuthorityNamespaceDigestV1,
        preimage: &AuthorityIdempotencyPreimageV1,
    ) -> Option<Self> {
        if preimage.caller_deadline_monotonic_ms_v1().get() == 0 {
            return None;
        }
        let mut entropy = [0_u8; 32];
        getrandom::fill(&mut entropy).ok()?;
        Some(Self::from_entropy_v1(namespace_digest, preimage, entropy))
    }

    fn from_entropy_v1(
        namespace_digest: AuthorityNamespaceDigestV1,
        preimage: &AuthorityIdempotencyPreimageV1,
        entropy: [u8; 32],
    ) -> Self {
        let operation_kind = preimage.operation_kind_v1();
        Self {
            attempt_id: AuthorityAttemptIdV1::from_entropy_v1(operation_kind, entropy),
            operation_kind,
            namespace_digest,
            input_graph_digest: AuthorityInputGraphDigestV1::from_preimage_v1(preimage),
            caller_deadline_monotonic_ms: preimage.caller_deadline_monotonic_ms_v1(),
        }
    }

    pub const fn attempt_id_v1(&self) -> &AuthorityAttemptIdV1 {
        &self.attempt_id
    }

    pub const fn operation_kind_v1(&self) -> AuthorityOperationKindV1 {
        self.operation_kind
    }

    pub const fn namespace_digest_v1(&self) -> &AuthorityNamespaceDigestV1 {
        &self.namespace_digest
    }

    pub const fn input_graph_digest_v1(&self) -> &AuthorityInputGraphDigestV1 {
        &self.input_graph_digest
    }

    pub const fn caller_deadline_monotonic_ms_v1(&self) -> SafeU64 {
        self.caller_deadline_monotonic_ms
    }

    /// Stable retry equality deliberately excludes the random attempt identity.
    pub fn has_same_stable_input_v1(&self, other: &Self) -> bool {
        self.namespace_digest.digest == other.namespace_digest.digest
            && self.input_graph_digest.digest == other.input_graph_digest.digest
    }

    /// A reused namespace with a changed stable input is a retained conflict.
    pub fn conflicts_with_v1(&self, other: &Self) -> bool {
        self.namespace_digest.digest == other.namespace_digest.digest
            && self.input_graph_digest.digest != other.input_graph_digest.digest
    }
}

impl fmt::Debug for AuthorityAttemptBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityAttemptBindingV1")
            .finish_non_exhaustive()
    }
}

/// Immutable durable binding retained with one complete atomic event graph.
pub struct AuthorityRetainedAttemptV1 {
    attempt: AuthorityAttemptBindingV1,
    outcome_code: AuthorityRetainedOutcomeCodeV1,
    outcome_binding_digest: AuthorityOutcomeBindingDigestV1,
    attempt_generation: Generation,
    event_id: Sha256Digest,
}

impl AuthorityRetainedAttemptV1 {
    /// Reconstructs immutable retained evidence after complete-graph verification.
    ///
    /// Retained evidence is not a current-authority projection.
    pub const fn from_verified_parts_v1(
        attempt: AuthorityAttemptBindingV1,
        outcome_code: AuthorityRetainedOutcomeCodeV1,
        outcome_binding_digest: AuthorityOutcomeBindingDigestV1,
        attempt_generation: Generation,
        event_id: Sha256Digest,
    ) -> Self {
        Self {
            attempt,
            outcome_code,
            outcome_binding_digest,
            attempt_generation,
            event_id,
        }
    }

    pub const fn attempt_v1(&self) -> &AuthorityAttemptBindingV1 {
        &self.attempt
    }

    pub const fn outcome_code_v1(&self) -> &AuthorityRetainedOutcomeCodeV1 {
        &self.outcome_code
    }

    pub const fn outcome_binding_digest_v1(&self) -> &AuthorityOutcomeBindingDigestV1 {
        &self.outcome_binding_digest
    }

    pub const fn attempt_generation_v1(&self) -> Generation {
        self.attempt_generation
    }

    pub const fn event_id_v1(&self) -> Sha256Digest {
        self.event_id
    }
}

impl fmt::Debug for AuthorityRetainedAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRetainedAttemptV1")
            .finish_non_exhaustive()
    }
}

/// Core-created candidate accepted by the shared atomic store seam.
pub trait AuthorityAtomicMutationV1: Send {
    fn attempt_binding_v1(&self) -> &AuthorityAttemptBindingV1;

    /// Transfers the exact binding into uncertainty custody after commit ambiguity.
    fn into_attempt_binding_v1(self) -> AuthorityAttemptBindingV1
    where
        Self: Sized;
}

/// Read-only evidence that a complete atomic graph was retained.
///
/// Implementing this trait never creates current task authority. Current projections
/// require a later verified snapshot and retained authority guard.
pub trait AuthorityRetainedGraphV1: Send {
    fn operation_kind_v1(&self) -> AuthorityOperationKindV1;
    fn attempt_id_v1(&self) -> &AuthorityAttemptIdV1;
    fn namespace_digest_v1(&self) -> &AuthorityNamespaceDigestV1;
    fn input_graph_digest_v1(&self) -> &AuthorityInputGraphDigestV1;
    fn caller_deadline_monotonic_ms_v1(&self) -> SafeU64;
    fn outcome_code_v1(&self) -> &AuthorityRetainedOutcomeCodeV1;
    fn outcome_binding_digest_v1(&self) -> &AuthorityOutcomeBindingDigestV1;
    fn attempt_generation_v1(&self) -> Generation;
    fn event_id_v1(&self) -> Sha256Digest;
}

impl AuthorityRetainedGraphV1 for AuthorityRetainedAttemptV1 {
    fn operation_kind_v1(&self) -> AuthorityOperationKindV1 {
        self.attempt.operation_kind
    }

    fn attempt_id_v1(&self) -> &AuthorityAttemptIdV1 {
        &self.attempt.attempt_id
    }

    fn namespace_digest_v1(&self) -> &AuthorityNamespaceDigestV1 {
        &self.attempt.namespace_digest
    }

    fn input_graph_digest_v1(&self) -> &AuthorityInputGraphDigestV1 {
        &self.attempt.input_graph_digest
    }

    fn caller_deadline_monotonic_ms_v1(&self) -> SafeU64 {
        self.attempt.caller_deadline_monotonic_ms
    }

    fn outcome_code_v1(&self) -> &AuthorityRetainedOutcomeCodeV1 {
        &self.outcome_code
    }

    fn outcome_binding_digest_v1(&self) -> &AuthorityOutcomeBindingDigestV1 {
        &self.outcome_binding_digest
    }

    fn attempt_generation_v1(&self) -> Generation {
        self.attempt_generation
    }

    fn event_id_v1(&self) -> Sha256Digest {
        self.event_id
    }
}

/// Store-owned exact readback implementation captured behind one core-owned token.
pub trait AuthorityUncertainReadbackResolverV1<R>: Send {
    fn readback_exact_once_v1(
        self: Box<Self>,
        attempt: &AuthorityAttemptBindingV1,
    ) -> AuthorityReadbackOutcomeV1<R>;
}

/// Opaque, non-cloneable custody for exactly one fresh uncertainty readback.
///
/// The resolver captures adapter-private graph keys. Callers can inspect only the
/// immutable attempt binding and can consume the resolver exactly once.
///
/// ```compile_fail
/// use helix_task_authority::AuthorityUncertainReadbackV1;
///
/// fn duplicate<R>(custody: AuthorityUncertainReadbackV1<R>) {
///     let _second = custody.clone();
/// }
/// ```
pub struct AuthorityUncertainReadbackV1<R> {
    attempt: AuthorityAttemptBindingV1,
    resolver: Box<dyn AuthorityUncertainReadbackResolverV1<R>>,
}

impl<R> AuthorityUncertainReadbackV1<R> {
    /// Captures adapter-private readback state after an uncertain commit result.
    pub fn from_store_parts_v1(
        attempt: AuthorityAttemptBindingV1,
        resolver: Box<dyn AuthorityUncertainReadbackResolverV1<R>>,
    ) -> Self {
        Self { attempt, resolver }
    }

    pub const fn attempt_binding_v1(&self) -> &AuthorityAttemptBindingV1 {
        &self.attempt
    }

    pub fn resolve_once_v1(self) -> AuthorityReadbackOutcomeV1<R> {
        self.resolver.readback_exact_once_v1(&self.attempt)
    }
}

impl<R> fmt::Debug for AuthorityUncertainReadbackV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityUncertainReadbackV1")
            .finish_non_exhaustive()
    }
}

/// One portable atomic mutation plus at most one consuming uncertainty readback.
pub trait AuthorityAtomicStoreV1<C>: Send + Sync
where
    C: AuthorityAtomicMutationV1,
{
    type Retained: AuthorityRetainedGraphV1;

    fn commit_atomic_once_v1(
        &self,
        candidate: C,
    ) -> AuthorityMutationOutcomeV1<Self::Retained, AuthorityUncertainReadbackV1<Self::Retained>>;

    /// Consumes uncertainty custody so the same automatic readback cannot repeat.
    fn readback_uncertain_once_v1(
        &self,
        custody: AuthorityUncertainReadbackV1<Self::Retained>,
    ) -> AuthorityReadbackOutcomeV1<Self::Retained> {
        custody.resolve_once_v1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("test generation must be valid")
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("test integer must be valid")
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).expect("test identifier must be valid")
    }

    fn observation(byte: u8, value: u64) -> AuthorityObservationBindingV1 {
        AuthorityObservationBindingV1::new(digest(byte), generation(value))
    }

    fn lifecycle(byte: u8, requested: AuthorityLifecycleV1) -> AuthorityLifecyclePreimageV1 {
        AuthorityLifecyclePreimageV1::new(
            digest(byte),
            digest(byte.wrapping_add(1)),
            digest(byte.wrapping_add(2)),
            digest(byte.wrapping_add(3)),
            digest(byte.wrapping_add(4)),
            requested,
            digest(byte.wrapping_add(5)),
            safe(99),
        )
    }

    fn hex(byte: u8) -> String {
        digest(byte).to_hex()
    }

    fn observation_json(byte: u8, value: u64) -> serde_json::Value {
        serde_json::json!({
            "digest": hex(byte),
            "generation": value,
        })
    }

    fn lifecycle_json(byte: u8, requested: &str) -> serde_json::Value {
        serde_json::json!({
            "caller_deadline_monotonic_ms": 99,
            "configuration_digest": hex(byte.wrapping_add(4)),
            "epoch_transition_digest": hex(byte.wrapping_add(5)),
            "package_digest": hex(byte.wrapping_add(3)),
            "requested_lifecycle": requested,
            "root_digest": hex(byte.wrapping_add(1)),
            "schema_digest": hex(byte.wrapping_add(2)),
            "source_digest": hex(byte),
        })
    }

    fn leaf_paths(value: &serde_json::Value) -> Vec<Vec<String>> {
        fn visit(
            value: &serde_json::Value,
            prefix: &mut Vec<String>,
            output: &mut Vec<Vec<String>>,
        ) {
            match value {
                serde_json::Value::Object(object) => {
                    for (key, child) in object {
                        prefix.push(key.clone());
                        visit(child, prefix, output);
                        prefix.pop();
                    }
                }
                _ => output.push(prefix.clone()),
            }
        }

        let mut output = Vec::new();
        visit(value, &mut Vec::new(), &mut output);
        output
    }

    fn mutate_leaf(value: &mut serde_json::Value, path: &[String]) {
        let mut current = value;
        for key in &path[..path.len() - 1] {
            current = current
                .get_mut(key)
                .expect("test leaf path must remain present");
        }
        let leaf = current
            .get_mut(path.last().expect("leaf path must not be empty"))
            .expect("test leaf must remain present");
        match leaf {
            serde_json::Value::String(text) => text.push_str("-changed"),
            serde_json::Value::Number(number) => {
                let changed = number
                    .as_u64()
                    .expect("stable numeric leaves are non-negative")
                    + 1;
                *leaf = serde_json::Value::Number(changed.into());
            }
            _ => panic!("stable leaf must be a string or safe integer"),
        }
    }

    fn sample_root() -> RootLeaseIssuePreimageV1 {
        RootLeaseIssuePreimageV1::new(
            digest(1),
            &identifier("task-1"),
            &identifier("workload-1"),
            &identifier("audience-1"),
            digest(2),
            observation(3, 3),
            observation(4, 4),
            observation(5, 5),
            observation(6, 6),
            observation(7, 7),
            safe(99),
        )
    }

    fn root_preimage(request_digest: u8) -> AuthorityIdempotencyPreimageV1 {
        let mut value = sample_root();
        value.request_grant_wire_digest = digest(request_digest);
        AuthorityIdempotencyPreimageV1::RootLeaseIssue(value)
    }

    fn sample_child() -> ChildLeaseIssuePreimageV1 {
        ChildLeaseIssuePreimageV1::new(
            digest(1),
            digest(2),
            &identifier("task-1"),
            &identifier("workload-1"),
            &identifier("audience-1"),
            digest(3),
            observation(4, 4),
            observation(5, 5),
            observation(6, 6),
            observation(7, 7),
            safe(99),
        )
    }

    fn sample_counter() -> CounterConsumePreimageV1 {
        CounterConsumePreimageV1::new(
            digest(1),
            digest(2),
            AuthorityCounterKindV1::Plans,
            safe(1),
            digest(3),
            generation(4),
            safe(99),
        )
    }

    fn sample_decision() -> DecisionRetainPreimageV1 {
        DecisionRetainPreimageV1::new(
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            ApprovalDecisionValueV1::Approved,
            AuthenticationProfileV1::UserVerificationV1,
            digest(5),
            observation(6, 6),
            observation(7, 7),
            observation(8, 8),
            safe(99),
        )
    }

    fn sample_key_status() -> KeyStatusChangePreimageV1 {
        KeyStatusChangePreimageV1::new(
            digest(1),
            AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
            generation(1),
            AuthorityKeyStatusV1::Retired,
            AuthorityKeyStatusReasonV1::KeyRetired,
            safe(10),
            safe(99),
        )
    }

    fn sample_revocation() -> AuthorityRevokePreimageV1 {
        AuthorityRevokePreimageV1::new(
            digest(1),
            AuthorityRevocationSubjectKindV1::Lease,
            generation(2),
            AuthorityRevocationReasonV1::AdminRevoked,
            digest(3),
            safe(99),
        )
    }

    fn sample_lifecycle() -> AuthorityLifecyclePreimageV1 {
        lifecycle(1, AuthorityLifecycleV1::Active)
    }

    fn assert_typed_leaf_mutations<T>(
        build: fn() -> T,
        wrap: fn(T) -> AuthorityIdempotencyPreimageV1,
        leaf_count: usize,
        mutate: fn(&mut T, usize),
    ) {
        let baseline = wrap(build()).input_graph_digest_v1();
        for index in 0..leaf_count {
            let mut changed = build();
            mutate(&mut changed, index);
            assert_ne!(
                wrap(changed).input_graph_digest_v1(),
                baseline,
                "typed stable leaf {index} must affect the production digest"
            );
        }
    }

    fn mutate_root(value: &mut RootLeaseIssuePreimageV1, index: usize) {
        match index {
            0 => value.request_grant_wire_digest = digest(101),
            1 => value.task_id = "task-2".into(),
            2 => value.workload_id = "workload-2".into(),
            3 => value.audience = "audience-2".into(),
            4 => value.requested_authority_bounds_digest = digest(102),
            5 => value.scope_observation.digest = digest(103),
            6 => value.scope_observation.generation = generation(103),
            7 => value.policy_observation.digest = digest(104),
            8 => value.policy_observation.generation = generation(104),
            9 => value.catalogue_observation.digest = digest(105),
            10 => value.catalogue_observation.generation = generation(105),
            11 => value.workload_observation.digest = digest(106),
            12 => value.workload_observation.generation = generation(106),
            13 => value.trust_observation.digest = digest(107),
            14 => value.trust_observation.generation = generation(107),
            15 => value.caller_deadline_monotonic_ms = safe(199),
            _ => panic!("root leaf index outside closed inventory"),
        }
    }

    fn mutate_child(value: &mut ChildLeaseIssuePreimageV1, index: usize) {
        match index {
            0 => value.source_grant_digest = digest(101),
            1 => value.parent_lease_digest = digest(102),
            2 => value.task_id = "task-2".into(),
            3 => value.workload_id = "workload-2".into(),
            4 => value.audience = "audience-2".into(),
            5 => value.requested_restrictive_authority_digest = digest(103),
            6 => value.ancestor_observation.digest = digest(104),
            7 => value.ancestor_observation.generation = generation(104),
            8 => value.allocation_observation.digest = digest(105),
            9 => value.allocation_observation.generation = generation(105),
            10 => value.counter_observation.digest = digest(106),
            11 => value.counter_observation.generation = generation(106),
            12 => value.trust_observation.digest = digest(107),
            13 => value.trust_observation.generation = generation(107),
            14 => value.caller_deadline_monotonic_ms = safe(199),
            _ => panic!("child leaf index outside closed inventory"),
        }
    }

    fn mutate_counter(value: &mut CounterConsumePreimageV1, index: usize) {
        match index {
            0 => value.lease_digest = digest(101),
            1 => value.ancestor_projection_digest = digest(102),
            2 => value.counter_kind = AuthorityCounterKindV1::Approvals,
            3 => value.amount = safe(2),
            4 => value.context_digest = digest(103),
            5 => value.current_counter_generation = generation(104),
            6 => value.caller_deadline_monotonic_ms = safe(199),
            _ => panic!("counter leaf index outside closed inventory"),
        }
    }

    fn mutate_decision(value: &mut DecisionRetainPreimageV1, index: usize) {
        match index {
            0 => value.plan_envelope_digest = digest(101),
            1 => value.grant_projection_digest = digest(102),
            2 => value.ancestor_projection_digest = digest(103),
            3 => value.lease_projection_digest = digest(104),
            4 => value.requested_terminal_value = ApprovalDecisionValueV1::Denied,
            5 => value.authentication_profile = AuthenticationProfileV1::SessionAuthenticatedV1,
            6 => value.authentication_evidence_digest = digest(105),
            7 => value.policy_observation.digest = digest(106),
            8 => value.policy_observation.generation = generation(106),
            9 => value.catalogue_observation.digest = digest(107),
            10 => value.catalogue_observation.generation = generation(107),
            11 => value.trust_observation.digest = digest(108),
            12 => value.trust_observation.generation = generation(108),
            13 => value.caller_deadline_monotonic_ms = safe(199),
            _ => panic!("decision leaf index outside closed inventory"),
        }
    }

    fn mutate_key_status(value: &mut KeyStatusChangePreimageV1, index: usize) {
        match index {
            0 => value.subject_binding_digest = digest(101),
            1 => value.signer_purpose = AuthoritySignerPurposeV1::RequestSurfaceGrantSigning,
            2 => value.current_trust_generation = generation(101),
            3 => value.requested_status = AuthorityKeyStatusV1::Revoked,
            4 => value.reason = AuthorityKeyStatusReasonV1::AdminRevoked,
            5 => value.effective_at_utc_ms = safe(11),
            6 => value.caller_deadline_monotonic_ms = safe(199),
            _ => panic!("key-status leaf index outside closed inventory"),
        }
    }

    fn mutate_revocation(value: &mut AuthorityRevokePreimageV1, index: usize) {
        match index {
            0 => value.subject_binding_digest = digest(101),
            1 => value.subject_kind = AuthorityRevocationSubjectKindV1::Decision,
            2 => value.current_subject_generation = generation(102),
            3 => value.reason = AuthorityRevocationReasonV1::DecisionRevoked,
            4 => value.effective_time_binding_digest = digest(103),
            5 => value.caller_deadline_monotonic_ms = safe(199),
            _ => panic!("revocation leaf index outside closed inventory"),
        }
    }

    fn mutate_lifecycle(value: &mut AuthorityLifecyclePreimageV1, index: usize) {
        match index {
            0 => value.source_digest = digest(101),
            1 => value.root_digest = digest(102),
            2 => value.schema_digest = digest(103),
            3 => value.package_digest = digest(104),
            4 => value.configuration_digest = digest(105),
            5 => value.requested_lifecycle = AuthorityLifecycleV1::Absent,
            6 => value.epoch_transition_digest = digest(106),
            7 => value.caller_deadline_monotonic_ms = safe(199),
            _ => panic!("lifecycle leaf index outside closed inventory"),
        }
    }

    #[test]
    fn exact_domain_and_schema_operation_inventory_is_closed() {
        let expected = [
            (
                "BOOTSTRAP",
                b"HELIXOS\0TASK-AUTHORITY-BOOTSTRAP\0V1\0".as_slice(),
            ),
            (
                "KEY_STATUS_CHANGE",
                b"HELIXOS\0TASK-AUTHORITY-KEY-STATUS\0V1\0".as_slice(),
            ),
            (
                "ROOT_LEASE_ISSUE",
                b"HELIXOS\0TASK-AUTHORITY-ROOT-ISSUE\0V1\0".as_slice(),
            ),
            (
                "CHILD_LEASE_ISSUE",
                b"HELIXOS\0TASK-AUTHORITY-CHILD-DELEGATION\0V1\0".as_slice(),
            ),
            (
                "COUNTER_CONSUME",
                b"HELIXOS\0TASK-AUTHORITY-COUNTER-CONSUMPTION\0V1\0".as_slice(),
            ),
            (
                "DECISION_RETAIN",
                b"HELIXOS\0TASK-AUTHORITY-TERMINAL-DECISION\0V1\0".as_slice(),
            ),
            (
                "AUTHORITY_REVOKE",
                b"HELIXOS\0TASK-AUTHORITY-REVOCATION\0V1\0".as_slice(),
            ),
            (
                "BACKUP_PUBLISH",
                b"HELIXOS\0TASK-AUTHORITY-BACKUP\0V1\0".as_slice(),
            ),
            (
                "RESTORE_PUBLISH",
                b"HELIXOS\0TASK-AUTHORITY-RESTORE\0V1\0".as_slice(),
            ),
        ];

        assert_eq!(AuthorityOperationKindV1::ALL.len(), 9);
        for (operation, (sql_code, domain)) in
            AuthorityOperationKindV1::ALL.iter().copied().zip(expected)
        {
            assert_eq!(operation.sql_code_v1(), sql_code);
            assert_eq!(operation.idempotency_domain_v1(), domain);
        }

        assert_eq!(
            AuthorityOperationKindV1::ALL
                .iter()
                .map(|operation| operation.sql_code_v1())
                .collect::<HashSet<_>>()
                .len(),
            9
        );
        assert_eq!(
            AuthorityOperationKindV1::ALL
                .iter()
                .map(|operation| operation.idempotency_domain_v1())
                .collect::<HashSet<_>>()
                .len(),
            9
        );
    }

    #[test]
    fn every_closed_stable_leaf_code_matches_the_authoritative_vocabulary() {
        assert_eq!(
            [
                AuthorityCounterKindV1::ReadBytes,
                AuthorityCounterKindV1::DistinctFiles,
                AuthorityCounterKindV1::Actions,
                AuthorityCounterKindV1::Plans,
                AuthorityCounterKindV1::Approvals,
            ]
            .map(AuthorityCounterKindV1::code_v1),
            [
                "READ_BYTES",
                "DISTINCT_FILES",
                "ACTIONS",
                "PLANS",
                "APPROVALS",
            ]
        );
        assert_eq!(
            [
                AuthoritySignerPurposeV1::RequestSurfaceGrantSigning,
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                AuthoritySignerPurposeV1::CoreApprovalDecisionSigning,
            ]
            .map(AuthoritySignerPurposeV1::code_v1),
            [
                "request-surface-grant-signing",
                "core-task-lease-signing",
                "core-approval-decision-signing",
            ]
        );
        assert_eq!(
            [
                AuthorityKeyStatusV1::Trusted,
                AuthorityKeyStatusV1::Retired,
                AuthorityKeyStatusV1::Revoked,
            ]
            .map(AuthorityKeyStatusV1::code_v1),
            ["TRUSTED", "RETIRED", "REVOKED"]
        );
        assert_eq!(
            [
                AuthorityKeyStatusReasonV1::KeyIntroduced,
                AuthorityKeyStatusReasonV1::KeyRotated,
                AuthorityKeyStatusReasonV1::KeyRetired,
                AuthorityKeyStatusReasonV1::KeyCompromised,
                AuthorityKeyStatusReasonV1::AdminRevoked,
            ]
            .map(AuthorityKeyStatusReasonV1::code_v1),
            [
                "KEY_INTRODUCED",
                "KEY_ROTATED",
                "KEY_RETIRED",
                "KEY_COMPROMISED",
                "ADMIN_REVOKED",
            ]
        );
        assert_eq!(
            [
                AuthorityRevocationSubjectKindV1::Signer,
                AuthorityRevocationSubjectKindV1::Grant,
                AuthorityRevocationSubjectKindV1::Lease,
                AuthorityRevocationSubjectKindV1::Decision,
                AuthorityRevocationSubjectKindV1::Boot,
                AuthorityRevocationSubjectKindV1::Instance,
                AuthorityRevocationSubjectKindV1::ScopeTemplate,
            ]
            .map(AuthorityRevocationSubjectKindV1::code_v1),
            [
                "SIGNER",
                "GRANT",
                "LEASE",
                "DECISION",
                "BOOT",
                "INSTANCE",
                "SCOPE_TEMPLATE",
            ]
        );
        assert_eq!(
            [
                AuthorityRevocationReasonV1::AdminRevoked,
                AuthorityRevocationReasonV1::KeyCompromised,
                AuthorityRevocationReasonV1::SourceRevoked,
                AuthorityRevocationReasonV1::AncestorRevoked,
                AuthorityRevocationReasonV1::DecisionRevoked,
                AuthorityRevocationReasonV1::BootReplaced,
                AuthorityRevocationReasonV1::InstanceReplaced,
                AuthorityRevocationReasonV1::ScopeReplaced,
            ]
            .map(AuthorityRevocationReasonV1::code_v1),
            [
                "ADMIN_REVOKED",
                "KEY_COMPROMISED",
                "SOURCE_REVOKED",
                "ANCESTOR_REVOKED",
                "DECISION_REVOKED",
                "BOOT_REPLACED",
                "INSTANCE_REPLACED",
                "SCOPE_REPLACED",
            ]
        );
        assert_eq!(
            [
                AuthorityLifecycleV1::Absent,
                AuthorityLifecycleV1::Active,
                AuthorityLifecycleV1::RestorePending,
            ]
            .map(AuthorityLifecycleV1::code_v1),
            ["ABSENT", "ACTIVE", "RESTORE_PENDING"]
        );
        assert_eq!(
            [
                ApprovalDecisionValueV1::Approved,
                ApprovalDecisionValueV1::Denied,
            ]
            .map(approval_decision_code_v1),
            ["APPROVED", "DENIED"]
        );
        assert_eq!(
            [
                AuthenticationProfileV1::SessionAuthenticatedV1,
                AuthenticationProfileV1::UserVerificationV1,
                AuthenticationProfileV1::SyntheticConformanceV1,
            ]
            .map(authentication_profile_code_v1),
            [
                "SESSION_AUTHENTICATED_V1",
                "USER_VERIFICATION_V1",
                "SYNTHETIC_CONFORMANCE_V1",
            ]
        );
    }

    #[test]
    fn all_nine_typed_preimages_select_their_own_domain() {
        let preimages = [
            AuthorityIdempotencyPreimageV1::Bootstrap(BootstrapPreimageV1::new(lifecycle(
                1,
                AuthorityLifecycleV1::Active,
            ))),
            AuthorityIdempotencyPreimageV1::KeyStatusChange(KeyStatusChangePreimageV1::new(
                digest(1),
                AuthoritySignerPurposeV1::CoreTaskLeaseSigning,
                generation(1),
                AuthorityKeyStatusV1::Retired,
                AuthorityKeyStatusReasonV1::KeyRetired,
                safe(10),
                safe(99),
            )),
            root_preimage(1),
            AuthorityIdempotencyPreimageV1::ChildLeaseIssue(ChildLeaseIssuePreimageV1::new(
                digest(1),
                digest(2),
                &identifier("task-1"),
                &identifier("workload-1"),
                &identifier("audience-1"),
                digest(3),
                observation(4, 4),
                observation(5, 5),
                observation(6, 6),
                observation(7, 7),
                safe(99),
            )),
            AuthorityIdempotencyPreimageV1::CounterConsume(CounterConsumePreimageV1::new(
                digest(1),
                digest(2),
                AuthorityCounterKindV1::Plans,
                safe(1),
                digest(3),
                generation(4),
                safe(99),
            )),
            AuthorityIdempotencyPreimageV1::DecisionRetain(DecisionRetainPreimageV1::new(
                digest(1),
                digest(2),
                digest(3),
                digest(4),
                ApprovalDecisionValueV1::Approved,
                AuthenticationProfileV1::UserVerificationV1,
                digest(5),
                observation(6, 6),
                observation(7, 7),
                observation(8, 8),
                safe(99),
            )),
            AuthorityIdempotencyPreimageV1::AuthorityRevoke(AuthorityRevokePreimageV1::new(
                digest(1),
                AuthorityRevocationSubjectKindV1::Lease,
                generation(2),
                AuthorityRevocationReasonV1::AdminRevoked,
                digest(3),
                safe(99),
            )),
            AuthorityIdempotencyPreimageV1::BackupPublish(BackupPublishPreimageV1::new(lifecycle(
                1,
                AuthorityLifecycleV1::Active,
            ))),
            AuthorityIdempotencyPreimageV1::RestorePublish(RestorePublishPreimageV1::new(
                lifecycle(1, AuthorityLifecycleV1::RestorePending),
            )),
        ];

        let expected = [
            lifecycle_json(1, "ACTIVE"),
            serde_json::json!({
                "caller_deadline_monotonic_ms": 99,
                "current_trust_generation": 1,
                "effective_at_utc_ms": 10,
                "reason": "KEY_RETIRED",
                "requested_status": "RETIRED",
                "signer_purpose": "core-task-lease-signing",
                "subject_binding_digest": hex(1),
            }),
            serde_json::json!({
                "audience": "audience-1",
                "caller_deadline_monotonic_ms": 99,
                "catalogue_observation": observation_json(5, 5),
                "policy_observation": observation_json(4, 4),
                "request_grant_wire_digest": hex(1),
                "requested_authority_bounds_digest": hex(2),
                "scope_observation": observation_json(3, 3),
                "task_id": "task-1",
                "trust_observation": observation_json(7, 7),
                "workload_id": "workload-1",
                "workload_observation": observation_json(6, 6),
            }),
            serde_json::json!({
                "allocation_observation": observation_json(5, 5),
                "ancestor_observation": observation_json(4, 4),
                "audience": "audience-1",
                "caller_deadline_monotonic_ms": 99,
                "counter_observation": observation_json(6, 6),
                "parent_lease_digest": hex(2),
                "requested_restrictive_authority_digest": hex(3),
                "source_grant_digest": hex(1),
                "task_id": "task-1",
                "trust_observation": observation_json(7, 7),
                "workload_id": "workload-1",
            }),
            serde_json::json!({
                "amount": 1,
                "ancestor_projection_digest": hex(2),
                "caller_deadline_monotonic_ms": 99,
                "context_digest": hex(3),
                "counter_kind": "PLANS",
                "current_counter_generation": 4,
                "lease_digest": hex(1),
            }),
            serde_json::json!({
                "ancestor_projection_digest": hex(3),
                "authentication_evidence_digest": hex(5),
                "authentication_profile": "USER_VERIFICATION_V1",
                "caller_deadline_monotonic_ms": 99,
                "catalogue_observation": observation_json(7, 7),
                "grant_projection_digest": hex(2),
                "lease_projection_digest": hex(4),
                "plan_envelope_digest": hex(1),
                "policy_observation": observation_json(6, 6),
                "requested_terminal_value": "APPROVED",
                "trust_observation": observation_json(8, 8),
            }),
            serde_json::json!({
                "caller_deadline_monotonic_ms": 99,
                "current_subject_generation": 2,
                "effective_time_binding_digest": hex(3),
                "reason": "ADMIN_REVOKED",
                "subject_binding_digest": hex(1),
                "subject_kind": "LEASE",
            }),
            lifecycle_json(1, "ACTIVE"),
            lifecycle_json(1, "RESTORE_PENDING"),
        ];

        for ((preimage, operation), expected_value) in preimages
            .iter()
            .zip(AuthorityOperationKindV1::ALL.iter())
            .zip(expected.iter())
        {
            assert_eq!(preimage.operation_kind_v1(), *operation);
            let encoded = preimage.canonical_jcs_v1();
            let parsed: serde_json::Value =
                serde_json::from_str(&encoded).expect("typed preimage must be valid JSON");
            assert_eq!(&parsed, expected_value);
            assert_eq!(
                encoded,
                serde_json_canonicalizer::to_string(expected_value)
                    .expect("typed preimage must canonicalize")
            );

            let mut digest_input = operation.idempotency_domain_v1().to_vec();
            digest_input.extend_from_slice(encoded.as_bytes());
            let expected_digest = Sha256Digest::digest(&digest_input);
            assert_eq!(preimage.input_graph_digest_v1(), expected_digest);

            for path in leaf_paths(expected_value) {
                let mut mutated = expected_value.clone();
                mutate_leaf(&mut mutated, &path);
                let mutated_jcs = serde_json_canonicalizer::to_vec(&mutated)
                    .expect("mutated stable preimage must canonicalize");
                let mut mutated_input = operation.idempotency_domain_v1().to_vec();
                mutated_input.extend_from_slice(&mutated_jcs);
                assert_ne!(
                    Sha256Digest::digest(&mutated_input),
                    expected_digest,
                    "stable leaf {path:?} must affect the input graph digest"
                );
            }
        }
        assert_eq!(
            preimages
                .iter()
                .map(AuthorityIdempotencyPreimageV1::input_graph_digest_v1)
                .collect::<HashSet<_>>()
                .len(),
            9
        );
    }

    #[test]
    fn identical_canonical_preimage_is_separated_by_all_nine_domains() {
        let digests = AuthorityOperationKindV1::ALL
            .iter()
            .map(|operation| {
                let mut bytes = operation.idempotency_domain_v1().to_vec();
                bytes.extend_from_slice(b"{}");
                Sha256Digest::digest(&bytes)
            })
            .collect::<HashSet<_>>();

        assert_eq!(digests.len(), 9);
    }

    #[test]
    fn every_typed_stable_leaf_changes_the_production_input_digest() {
        assert_typed_leaf_mutations(
            sample_root,
            AuthorityIdempotencyPreimageV1::RootLeaseIssue,
            16,
            mutate_root,
        );
        assert_typed_leaf_mutations(
            sample_child,
            AuthorityIdempotencyPreimageV1::ChildLeaseIssue,
            15,
            mutate_child,
        );
        assert_typed_leaf_mutations(
            sample_counter,
            AuthorityIdempotencyPreimageV1::CounterConsume,
            7,
            mutate_counter,
        );
        assert_typed_leaf_mutations(
            sample_decision,
            AuthorityIdempotencyPreimageV1::DecisionRetain,
            14,
            mutate_decision,
        );
        assert_typed_leaf_mutations(
            sample_key_status,
            AuthorityIdempotencyPreimageV1::KeyStatusChange,
            7,
            mutate_key_status,
        );
        assert_typed_leaf_mutations(
            sample_revocation,
            AuthorityIdempotencyPreimageV1::AuthorityRevoke,
            6,
            mutate_revocation,
        );
        assert_typed_leaf_mutations(
            sample_lifecycle,
            |value| AuthorityIdempotencyPreimageV1::Bootstrap(BootstrapPreimageV1::new(value)),
            8,
            mutate_lifecycle,
        );
        assert_typed_leaf_mutations(
            sample_lifecycle,
            |value| {
                AuthorityIdempotencyPreimageV1::BackupPublish(BackupPublishPreimageV1::new(value))
            },
            8,
            mutate_lifecycle,
        );
        assert_typed_leaf_mutations(
            sample_lifecycle,
            |value| {
                AuthorityIdempotencyPreimageV1::RestorePublish(RestorePublishPreimageV1::new(value))
            },
            8,
            mutate_lifecycle,
        );
    }

    #[test]
    fn identical_entropy_is_separated_across_all_nine_attempt_domains() {
        let attempts = AuthorityOperationKindV1::ALL
            .iter()
            .copied()
            .map(|operation| AuthorityAttemptIdV1::from_entropy_v1(operation, [7; 32]).digest_v1())
            .collect::<HashSet<_>>();

        assert_eq!(attempts.len(), 9);
    }

    #[test]
    fn canonical_preimage_is_frozen_and_each_stable_change_changes_the_digest() {
        let original = root_preimage(1);
        let changed = root_preimage(9);

        assert_eq!(
            original.canonical_jcs_v1(),
            concat!(
                "{\"audience\":\"audience-1\",",
                "\"caller_deadline_monotonic_ms\":99,",
                "\"catalogue_observation\":{\"digest\":\"0505050505050505050505050505050505050505050505050505050505050505\",\"generation\":5},",
                "\"policy_observation\":{\"digest\":\"0404040404040404040404040404040404040404040404040404040404040404\",\"generation\":4},",
                "\"request_grant_wire_digest\":\"0101010101010101010101010101010101010101010101010101010101010101\",",
                "\"requested_authority_bounds_digest\":\"0202020202020202020202020202020202020202020202020202020202020202\",",
                "\"scope_observation\":{\"digest\":\"0303030303030303030303030303030303030303030303030303030303030303\",\"generation\":3},",
                "\"task_id\":\"task-1\",",
                "\"trust_observation\":{\"digest\":\"0707070707070707070707070707070707070707070707070707070707070707\",\"generation\":7},",
                "\"workload_id\":\"workload-1\",",
                "\"workload_observation\":{\"digest\":\"0606060606060606060606060606060606060606060606060606060606060606\",\"generation\":6}}"
            )
        );
        assert_ne!(
            original.input_graph_digest_v1(),
            changed.input_graph_digest_v1()
        );
    }

    #[test]
    fn stable_retry_ignores_attempt_entropy_and_changed_input_conflicts() {
        let namespace = digest(40);
        let exact_preimage = root_preimage(1);
        let changed_preimage = root_preimage(2);
        let first = AuthorityAttemptBindingV1::from_entropy_v1(
            AuthorityNamespaceDigestV1::from_verified_digest_v1(namespace),
            &exact_preimage,
            [1; 32],
        );
        let retry = AuthorityAttemptBindingV1::from_entropy_v1(
            AuthorityNamespaceDigestV1::from_verified_digest_v1(namespace),
            &exact_preimage,
            [2; 32],
        );
        let conflict = AuthorityAttemptBindingV1::from_entropy_v1(
            AuthorityNamespaceDigestV1::from_verified_digest_v1(namespace),
            &changed_preimage,
            [3; 32],
        );

        assert_ne!(first.attempt_id.digest, retry.attempt_id.digest);
        assert!(first.has_same_stable_input_v1(&retry));
        assert!(!first.conflicts_with_v1(&retry));
        assert!(first.conflicts_with_v1(&conflict));
    }

    struct CandidateV1 {
        attempt: AuthorityAttemptBindingV1,
    }

    impl AuthorityAtomicMutationV1 for CandidateV1 {
        fn attempt_binding_v1(&self) -> &AuthorityAttemptBindingV1 {
            &self.attempt
        }

        fn into_attempt_binding_v1(self) -> AuthorityAttemptBindingV1 {
            self.attempt
        }
    }

    struct RetainedV1(AuthorityRetainedAttemptV1);

    impl AuthorityRetainedGraphV1 for RetainedV1 {
        fn operation_kind_v1(&self) -> AuthorityOperationKindV1 {
            self.0.operation_kind_v1()
        }

        fn attempt_id_v1(&self) -> &AuthorityAttemptIdV1 {
            self.0.attempt_id_v1()
        }

        fn namespace_digest_v1(&self) -> &AuthorityNamespaceDigestV1 {
            self.0.namespace_digest_v1()
        }

        fn input_graph_digest_v1(&self) -> &AuthorityInputGraphDigestV1 {
            self.0.input_graph_digest_v1()
        }

        fn caller_deadline_monotonic_ms_v1(&self) -> SafeU64 {
            AuthorityRetainedGraphV1::caller_deadline_monotonic_ms_v1(&self.0)
        }

        fn outcome_code_v1(&self) -> &AuthorityRetainedOutcomeCodeV1 {
            AuthorityRetainedGraphV1::outcome_code_v1(&self.0)
        }

        fn outcome_binding_digest_v1(&self) -> &AuthorityOutcomeBindingDigestV1 {
            AuthorityRetainedGraphV1::outcome_binding_digest_v1(&self.0)
        }

        fn attempt_generation_v1(&self) -> Generation {
            AuthorityRetainedGraphV1::attempt_generation_v1(&self.0)
        }

        fn event_id_v1(&self) -> Sha256Digest {
            AuthorityRetainedGraphV1::event_id_v1(&self.0)
        }
    }

    struct ReadbackResolverV1 {
        retained: RetainedV1,
    }

    impl AuthorityUncertainReadbackResolverV1<RetainedV1> for ReadbackResolverV1 {
        fn readback_exact_once_v1(
            self: Box<Self>,
            _attempt: &AuthorityAttemptBindingV1,
        ) -> AuthorityReadbackOutcomeV1<RetainedV1> {
            AuthorityReadbackOutcomeV1::CommittedRetained(self.retained)
        }
    }

    struct FakeStoreV1 {
        commits: AtomicUsize,
        readbacks: AtomicUsize,
    }

    impl AuthorityAtomicStoreV1<CandidateV1> for FakeStoreV1 {
        type Retained = RetainedV1;

        fn commit_atomic_once_v1(
            &self,
            candidate: CandidateV1,
        ) -> AuthorityMutationOutcomeV1<Self::Retained, AuthorityUncertainReadbackV1<Self::Retained>>
        {
            self.commits.fetch_add(1, Ordering::SeqCst);
            let source = candidate.attempt_binding_v1();
            let retained_attempt = AuthorityAttemptBindingV1::from_verified_parts_v1(
                AuthorityAttemptIdV1::from_verified_digest_v1(source.attempt_id_v1().digest_v1()),
                source.operation_kind_v1(),
                AuthorityNamespaceDigestV1::from_verified_digest_v1(
                    source.namespace_digest_v1().digest_v1(),
                ),
                AuthorityInputGraphDigestV1::from_verified_digest_v1(
                    source.input_graph_digest_v1().digest_v1(),
                ),
                source.caller_deadline_monotonic_ms_v1(),
            )
            .expect("test retained binding must be valid");
            let retained = AuthorityRetainedAttemptV1::from_verified_parts_v1(
                retained_attempt,
                AuthorityRetainedOutcomeCodeV1::CommittedRetained,
                AuthorityOutcomeBindingDigestV1::from_verified_digest_v1(digest(55)),
                generation(56),
                digest(57),
            );
            let custody = AuthorityUncertainReadbackV1::from_store_parts_v1(
                candidate.into_attempt_binding_v1(),
                Box::new(ReadbackResolverV1 {
                    retained: RetainedV1(retained),
                }),
            );
            AuthorityMutationOutcomeV1::UncertainReadbackRequired(custody)
        }

        fn readback_uncertain_once_v1(
            &self,
            custody: AuthorityUncertainReadbackV1<Self::Retained>,
        ) -> AuthorityReadbackOutcomeV1<Self::Retained> {
            self.readbacks.fetch_add(1, Ordering::SeqCst);
            custody.resolve_once_v1()
        }
    }

    #[test]
    fn store_contract_consumes_one_uncertain_readback_custody() {
        let preimage = root_preimage(1);
        let candidate = CandidateV1 {
            attempt: AuthorityAttemptBindingV1::from_entropy_v1(
                AuthorityNamespaceDigestV1::from_verified_digest_v1(digest(40)),
                &preimage,
                [1; 32],
            ),
        };
        let store = FakeStoreV1 {
            commits: AtomicUsize::new(0),
            readbacks: AtomicUsize::new(0),
        };

        let custody = match store.commit_atomic_once_v1(candidate) {
            AuthorityMutationOutcomeV1::UncertainReadbackRequired(custody) => custody,
            other => panic!("unexpected mutation classification: {other:?}"),
        };
        assert!(matches!(
            store.readback_uncertain_once_v1(custody),
            AuthorityReadbackOutcomeV1::CommittedRetained(_)
        ));
        assert_eq!(store.commits.load(Ordering::SeqCst), 1);
        assert_eq!(store.readbacks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn all_public_binding_debug_is_payload_free() {
        struct AmbiguousResolverV1 {
            _native_path: Box<str>,
            _provider_error: Box<str>,
        }

        impl AuthorityUncertainReadbackResolverV1<()> for AmbiguousResolverV1 {
            fn readback_exact_once_v1(
                self: Box<Self>,
                _attempt: &AuthorityAttemptBindingV1,
            ) -> AuthorityReadbackOutcomeV1<()> {
                AuthorityReadbackOutcomeV1::AmbiguousReconciliationRequired
            }
        }

        let mut sentinel_root = sample_root();
        sentinel_root.task_id = "bearer-secret".into();
        let mut rendered = vec![
            format!("{:?}", observation(1, 1)),
            format!("{sentinel_root:?}"),
            format!("{:?}", sample_child()),
            format!("{:?}", sample_counter()),
            format!("{:?}", sample_decision()),
            format!("{:?}", sample_key_status()),
            format!("{:?}", sample_revocation()),
            format!("{:?}", sample_lifecycle()),
            format!("{:?}", BootstrapPreimageV1::new(sample_lifecycle())),
            format!("{:?}", BackupPublishPreimageV1::new(sample_lifecycle())),
            format!("{:?}", RestorePublishPreimageV1::new(sample_lifecycle())),
            format!(
                "{:?}",
                AuthorityAttemptIdV1::from_verified_digest_v1(digest(40))
            ),
            format!(
                "{:?}",
                AuthorityNamespaceDigestV1::from_verified_digest_v1(digest(40))
            ),
            format!(
                "{:?}",
                AuthorityInputGraphDigestV1::from_verified_digest_v1(digest(40))
            ),
            format!(
                "{:?}",
                AuthorityOutcomeBindingDigestV1::from_verified_digest_v1(digest(40))
            ),
        ];
        for preimage in [
            AuthorityIdempotencyPreimageV1::Bootstrap(BootstrapPreimageV1::new(sample_lifecycle())),
            AuthorityIdempotencyPreimageV1::KeyStatusChange(sample_key_status()),
            AuthorityIdempotencyPreimageV1::RootLeaseIssue(sample_root()),
            AuthorityIdempotencyPreimageV1::ChildLeaseIssue(sample_child()),
            AuthorityIdempotencyPreimageV1::CounterConsume(sample_counter()),
            AuthorityIdempotencyPreimageV1::DecisionRetain(sample_decision()),
            AuthorityIdempotencyPreimageV1::AuthorityRevoke(sample_revocation()),
            AuthorityIdempotencyPreimageV1::BackupPublish(BackupPublishPreimageV1::new(
                sample_lifecycle(),
            )),
            AuthorityIdempotencyPreimageV1::RestorePublish(RestorePublishPreimageV1::new(
                sample_lifecycle(),
            )),
        ] {
            rendered.push(format!("{preimage:?}"));
        }

        let preimage = root_preimage(1);
        let attempt = AuthorityAttemptBindingV1::from_entropy_v1(
            AuthorityNamespaceDigestV1::from_verified_digest_v1(digest(40)),
            &preimage,
            [1; 32],
        );
        rendered.push(format!("{attempt:?}"));
        let retained = AuthorityRetainedAttemptV1::from_verified_parts_v1(
            attempt,
            AuthorityRetainedOutcomeCodeV1::CommittedRetained,
            AuthorityOutcomeBindingDigestV1::from_verified_digest_v1(digest(55)),
            generation(56),
            digest(57),
        );
        rendered.push(format!("{retained:?}"));

        let token_attempt = AuthorityAttemptBindingV1::from_entropy_v1(
            AuthorityNamespaceDigestV1::from_verified_digest_v1(digest(40)),
            &root_preimage(1),
            [2; 32],
        );
        let custody = AuthorityUncertainReadbackV1::from_store_parts_v1(
            token_attempt,
            Box::new(AmbiguousResolverV1 {
                _native_path: "/Users/private".into(),
                _provider_error: "provider-native-error".into(),
            }),
        );
        rendered.push(format!("{custody:?}"));

        let joined = rendered.join(" ");
        for forbidden in [
            "task-1",
            "workload-1",
            "audience-1",
            &digest(1).to_hex(),
            &digest(40).to_hex(),
            &digest(55).to_hex(),
            &digest(57).to_hex(),
            "bearer-secret",
            "/Users/private",
            "provider-native-error",
        ] {
            assert!(!joined.contains(forbidden), "Debug leaked {forbidden}");
        }
    }

    #[test]
    fn begin_refuses_zero_deadline_before_entropy_or_mutation() {
        let preimage =
            AuthorityIdempotencyPreimageV1::CounterConsume(CounterConsumePreimageV1::new(
                digest(1),
                digest(2),
                AuthorityCounterKindV1::Plans,
                safe(1),
                digest(3),
                generation(4),
                safe(0),
            ));

        assert!(AuthorityAttemptBindingV1::begin_v1(
            AuthorityNamespaceDigestV1::from_verified_digest_v1(digest(40)),
            &preimage,
        )
        .is_none());
    }

    #[test]
    fn canonical_writes_to_string_are_infallible() {
        let mut output = String::new();
        write!(&mut output, "{}", root_preimage(1).canonical_jcs_v1())
            .expect("String formatting is infallible");
        assert!(output.starts_with('{'));
        assert!(output.ends_with('}'));
    }
}
