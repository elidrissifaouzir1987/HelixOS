use std::error::Error;
use std::fmt;

macro_rules! closed_codes {
    ($visibility:vis enum $name:ident { $($variant:ident => $code:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        $visibility enum $name {
            $($variant),+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),+
                }
            }
        }
    };
}

closed_codes! {
    pub enum EligibilityContextBuildErrorV1 {
        IntegerOutOfRange => "CONTEXT_BUILD_INTEGER_OUT_OF_RANGE",
        InvalidInterval => "CONTEXT_BUILD_INVALID_INTERVAL",
        InvalidIdentifier => "CONTEXT_BUILD_INVALID_IDENTIFIER",
        InvalidCapabilitySet => "CONTEXT_BUILD_INVALID_CAPABILITY_SET",
        LimitExceeded => "CONTEXT_BUILD_LIMIT_EXCEEDED",
    }
}

impl fmt::Display for EligibilityContextBuildErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("eligibility context construction was rejected")
    }
}

impl Error for EligibilityContextBuildErrorV1 {}

closed_codes! {
    pub enum EligibilityDenialV1 {
        ContextUnavailable => "CONTEXT_UNAVAILABLE",
        ContextIncomplete => "CONTEXT_INCOMPLETE",
        ContextTorn => "CONTEXT_TORN",
        ContextPlanMismatch => "CONTEXT_PLAN_MISMATCH",
        SupervisorUnavailable => "SUPERVISOR_UNAVAILABLE",
        SupervisorInconsistent => "SUPERVISOR_INCONSISTENT",
        SupervisorNotOpen => "SUPERVISOR_NOT_OPEN",
        WallClockUnavailable => "WALL_CLOCK_UNAVAILABLE",
        WallClockRollbackSuspected => "WALL_CLOCK_ROLLBACK_SUSPECTED",
        PlanNotYetValid => "PLAN_NOT_YET_VALID",
        PlanExpired => "PLAN_EXPIRED",
        BootMismatch => "BOOT_MISMATCH",
        MonotonicClockUnavailable => "MONOTONIC_CLOCK_UNAVAILABLE",
        MonotonicClockUnsuitable => "MONOTONIC_CLOCK_UNSUITABLE",
        MonotonicClockRegressed => "MONOTONIC_CLOCK_REGRESSED",
        PlanDeadlineUnavailable => "PLAN_DEADLINE_UNAVAILABLE",
        PlanDeadlineInconsistent => "PLAN_DEADLINE_INCONSISTENT",
        PlanDeadlineMismatch => "PLAN_DEADLINE_MISMATCH",
        MonotonicDeadlineReached => "MONOTONIC_DEADLINE_REACHED",
        InstanceEpochMismatch => "INSTANCE_EPOCH_MISMATCH",
        FencingEpochMismatch => "FENCING_EPOCH_MISMATCH",
        SignerTrustUnavailable => "SIGNER_TRUST_UNAVAILABLE",
        SignerTrustInconsistent => "SIGNER_TRUST_INCONSISTENT",
        SignerKeyMismatch => "SIGNER_KEY_MISMATCH",
        SignerFingerprintMismatch => "SIGNER_FINGERPRINT_MISMATCH",
        SignerNotTrusted => "SIGNER_NOT_TRUSTED",
        SignerGenerationRejectsPlan => "SIGNER_GENERATION_REJECTS_PLAN",
        WorkloadUnavailable => "WORKLOAD_UNAVAILABLE",
        WorkloadInconsistent => "WORKLOAD_INCONSISTENT",
        WorkloadIdMismatch => "WORKLOAD_ID_MISMATCH",
        WorkloadNotTrusted => "WORKLOAD_NOT_TRUSTED",
        WorkloadBootMismatch => "WORKLOAD_BOOT_MISMATCH",
        WorkloadInstanceEpochMismatch => "WORKLOAD_INSTANCE_EPOCH_MISMATCH",
        WorkloadNotYetValid => "WORKLOAD_NOT_YET_VALID",
        WorkloadExpired => "WORKLOAD_EXPIRED",
        WorkloadMonotonicExpired => "WORKLOAD_MONOTONIC_EXPIRED",
        LeaseUnavailable => "LEASE_UNAVAILABLE",
        LeaseInconsistent => "LEASE_INCONSISTENT",
        LeaseNotFound => "LEASE_NOT_FOUND",
        LeaseAmbiguous => "LEASE_AMBIGUOUS",
        LeaseDigestMismatch => "LEASE_DIGEST_MISMATCH",
        LeaseNotActive => "LEASE_NOT_ACTIVE",
        LeaseTaskMismatch => "LEASE_TASK_MISMATCH",
        LeaseWorkloadMismatch => "LEASE_WORKLOAD_MISMATCH",
        LeaseBootMismatch => "LEASE_BOOT_MISMATCH",
        LeaseInstanceEpochMismatch => "LEASE_INSTANCE_EPOCH_MISMATCH",
        LeaseSourceMismatch => "LEASE_SOURCE_MISMATCH",
        LeaseNotYetValid => "LEASE_NOT_YET_VALID",
        LeaseExpired => "LEASE_EXPIRED",
        LeaseMonotonicExpired => "LEASE_MONOTONIC_EXPIRED",
        LeaseDecisionUnavailable => "LEASE_DECISION_UNAVAILABLE",
        LeaseDecisionInconsistent => "LEASE_DECISION_INCONSISTENT",
        LeaseDecisionPlanMismatch => "LEASE_DECISION_PLAN_MISMATCH",
        LeaseIntentDenied => "LEASE_INTENT_DENIED",
        LeaseScopeWidened => "LEASE_SCOPE_WIDENED",
        LeaseBudgetWidened => "LEASE_BUDGET_WIDENED",
        LeasePriceTableMismatch => "LEASE_PRICE_TABLE_MISMATCH",
        LeaseReservationMismatch => "LEASE_RESERVATION_MISMATCH",
        AuthorizationUnavailable => "AUTHORIZATION_UNAVAILABLE",
        AuthorizationInconsistent => "AUTHORIZATION_INCONSISTENT",
        AuthorizationNotGranted => "AUTHORIZATION_NOT_GRANTED",
        AuthorizationPlanMismatch => "AUTHORIZATION_PLAN_MISMATCH",
        AuthorizationOperationMismatch => "AUTHORIZATION_OPERATION_MISMATCH",
        AuthorizationRiskMismatch => "AUTHORIZATION_RISK_MISMATCH",
        AuthorizationNonceMismatch => "AUTHORIZATION_NONCE_MISMATCH",
        AuthorizationBootMismatch => "AUTHORIZATION_BOOT_MISMATCH",
        AuthorizationNotYetValid => "AUTHORIZATION_NOT_YET_VALID",
        AuthorizationExpired => "AUTHORIZATION_EXPIRED",
        AuthorizationMonotonicExpired => "AUTHORIZATION_MONOTONIC_EXPIRED",
        PolicyUnavailable => "POLICY_UNAVAILABLE",
        PolicyInconsistent => "POLICY_INCONSISTENT",
        PolicyIdentityMismatch => "POLICY_IDENTITY_MISMATCH",
        PolicyContentMismatch => "POLICY_CONTENT_MISMATCH",
        PolicyGenerationMismatch => "POLICY_GENERATION_MISMATCH",
        PolicyDecisionPlanMismatch => "POLICY_DECISION_PLAN_MISMATCH",
        PolicyDenied => "POLICY_DENIED",
        CatalogueUnavailable => "CATALOGUE_UNAVAILABLE",
        CatalogueInconsistent => "CATALOGUE_INCONSISTENT",
        CatalogueIdentityMismatch => "CATALOGUE_IDENTITY_MISMATCH",
        CatalogueContentMismatch => "CATALOGUE_CONTENT_MISMATCH",
        CatalogueGenerationMismatch => "CATALOGUE_GENERATION_MISMATCH",
        CatalogueDecisionPlanMismatch => "CATALOGUE_DECISION_PLAN_MISMATCH",
        CatalogueSchemaUnsupported => "CATALOGUE_SCHEMA_UNSUPPORTED",
        CatalogueIntentUnsupported => "CATALOGUE_INTENT_UNSUPPORTED",
        CapabilityUnavailable => "CAPABILITY_UNAVAILABLE",
        CapabilityInconsistent => "CAPABILITY_INCONSISTENT",
        CapabilityNotFound => "CAPABILITY_NOT_FOUND",
        CapabilityDigestMismatch => "CAPABILITY_DIGEST_MISMATCH",
        CapabilityObservationMismatch => "CAPABILITY_OBSERVATION_MISMATCH",
        CapabilityBootMismatch => "CAPABILITY_BOOT_MISMATCH",
        CapabilityInstanceEpochMismatch => "CAPABILITY_INSTANCE_EPOCH_MISMATCH",
        CapabilityContextMismatch => "CAPABILITY_CONTEXT_MISMATCH",
        CapabilityStale => "CAPABILITY_STALE",
        RequiredCapabilityMissing => "REQUIRED_CAPABILITY_MISSING",
        MandatoryCapabilityMissing => "MANDATORY_CAPABILITY_MISSING",
        ReplayAlreadyClaimed => "REPLAY_ALREADY_CLAIMED",
        ReplayBindingConflict => "REPLAY_BINDING_CONFLICT",
        ReplayUnavailable => "REPLAY_UNAVAILABLE",
        ReplayAmbiguous => "REPLAY_AMBIGUOUS",
        ReplayReceiptBindingMismatch => "REPLAY_RECEIPT_BINDING_MISMATCH",
    }
}

impl fmt::Display for EligibilityDenialV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plan eligibility was denied")
    }
}

impl Error for EligibilityDenialV1 {}
