//! Closed and redacted preparation-outcome boundary.
//!
//! Outcomes may eventually carry an opaque non-dispatchable prepared marker, but never
//! an execution grant, adapter conversion, native diagnostic, or effect authority.

use crate::store::PreparationCommitReceiptV1;
use helix_plan_eligibility::EligiblePlanV1;
use std::error::Error;
use std::fmt;

macro_rules! closed_code_enum {
    (
        $visibility:vis enum $name:ident,
        $display:literal,
        { $($variant:ident => $code:literal),+ $(,)? }
    ) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
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

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.code())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($display)
            }
        }

        impl Error for $name {}
    };
}

closed_code_enum! {
    pub enum PreparationDenialV1,
    "plan preparation was denied",
    {
        ContextUnavailable => "PREPARATION_CONTEXT_UNAVAILABLE",
        ContextIncomplete => "PREPARATION_CONTEXT_INCOMPLETE",
        ContextTorn => "PREPARATION_CONTEXT_TORN",
        ContextUnsupported => "PREPARATION_CONTEXT_UNSUPPORTED",
        ContextMismatch => "PREPARATION_CONTEXT_MISMATCH",
        VersionUnsupported => "PREPARATION_VERSION_UNSUPPORTED",
        ClockMismatch => "PREPARATION_CLOCK_MISMATCH",
        TimeExpired => "PREPARATION_TIME_EXPIRED",
        DeadlineMismatch => "PREPARATION_DEADLINE_MISMATCH",
        DeadlineReached => "PREPARATION_DEADLINE_REACHED",
        BootMismatch => "PREPARATION_BOOT_MISMATCH",
        SupervisorMismatch => "PREPARATION_SUPERVISOR_MISMATCH",
        SupervisorDenied => "PREPARATION_SUPERVISOR_DENIED",
        GuardRevoked => "PREPARATION_GUARD_REVOKED",
        TrustMismatch => "PREPARATION_TRUST_MISMATCH",
        WorkloadMismatch => "PREPARATION_WORKLOAD_MISMATCH",
        LeaseMismatch => "PREPARATION_LEASE_MISMATCH",
        AuthorizationMismatch => "PREPARATION_AUTHORIZATION_MISMATCH",
        PolicyMismatch => "PREPARATION_POLICY_MISMATCH",
        CatalogueMismatch => "PREPARATION_CATALOGUE_MISMATCH",
        CapabilityMismatch => "PREPARATION_CAPABILITY_MISMATCH",
        ReplayMissing => "PREPARATION_REPLAY_MISSING",
        ReplayConflict => "PREPARATION_REPLAY_CONFLICT",
        ReplayUnavailable => "PREPARATION_REPLAY_UNAVAILABLE",
        ReplayUnhealthy => "PREPARATION_REPLAY_UNHEALTHY",
        OperationConflict => "PREPARATION_OPERATION_CONFLICT",
        AlreadyPrepared => "PREPARATION_ALREADY_PREPARED",
        OperationAuthorityUnavailable => "PREPARATION_OPERATION_AUTHORITY_UNAVAILABLE",
        BudgetScopeMissing => "PREPARATION_BUDGET_SCOPE_MISSING",
        BudgetAuthorityUnavailable => "PREPARATION_BUDGET_AUTHORITY_UNAVAILABLE",
        BudgetBindingConflict => "PREPARATION_BUDGET_BINDING_CONFLICT",
        BudgetExhausted => "PREPARATION_BUDGET_EXHAUSTED",
        BudgetArithmeticInvalid => "PREPARATION_BUDGET_ARITHMETIC_INVALID",
        RecoveryBindingConflict => "PREPARATION_RECOVERY_BINDING_CONFLICT",
        RecoveryUnverified => "PREPARATION_RECOVERY_UNVERIFIED",
        RecoveryProfileUnapproved => "PREPARATION_RECOVERY_PROFILE_UNAPPROVED"
    }
}

closed_code_enum! {
    pub enum PreparationFailureV1,
    "plan preparation failed",
    {
        RecoveryProviderFailed => "PREPARATION_RECOVERY_UNAVAILABLE",
        StoreUnavailable => "PREPARATION_STORE_UNAVAILABLE",
        StoreBusy => "PREPARATION_STORE_BUSY",
        StoreUnhealthy => "PREPARATION_STORE_UNHEALTHY",
        StoreConflict => "PREPARATION_STORE_CONFLICT",
        CommitAborted => "PREPARATION_STORE_COMMIT_ABORTED",
        DefiniteAbsence => "PREPARATION_STORE_DEFINITE_ABSENCE"
    }
}

const AMBIGUOUS_PUBLIC_CODE_V1: &str = "PREPARATION_AMBIGUOUS";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmbiguousPreparationV1 {
    RecoveryPublicationUnclassified,
    CommitClassificationMissing,
    PermitOwnerOrProcessLost,
    PermitDeadlineReached,
    ReadbackUnavailable,
    ReadbackInconsistent,
    ReadbackLateOrRevoked,
}

impl AmbiguousPreparationV1 {
    pub const ALL: &'static [Self] = &[
        Self::RecoveryPublicationUnclassified,
        Self::CommitClassificationMissing,
        Self::PermitOwnerOrProcessLost,
        Self::PermitDeadlineReached,
        Self::ReadbackUnavailable,
        Self::ReadbackInconsistent,
        Self::ReadbackLateOrRevoked,
    ];

    pub const fn code(self) -> &'static str {
        AMBIGUOUS_PUBLIC_CODE_V1
    }
}

impl fmt::Debug for AmbiguousPreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for AmbiguousPreparationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("plan preparation is ambiguous")
    }
}

impl Error for AmbiguousPreparationV1 {}

#[must_use = "prepared custody must be consumed deliberately by a later core transition"]
/// Opaque, non-transferable proof of this call's exact durable preparation.
///
/// It is neither approval, an execution grant, adapter input, nor effect authority.
///
/// ```compile_fail,E0277
/// use helix_plan_preparation::PreparedOperationV1;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<PreparedOperationV1>();
/// ```
///
/// ```compile_fail,E0277
/// use helix_plan_preparation::PreparedOperationV1;
/// use serde::Serialize;
///
/// fn require_serialize<T: Serialize>() {}
/// require_serialize::<PreparedOperationV1>();
/// ```
///
/// ```compile_fail,E0277
/// use helix_plan_preparation::PreparedOperationV1;
/// use serde::Deserialize;
///
/// fn require_deserialize<T: for<'de> Deserialize<'de>>() {}
/// require_deserialize::<PreparedOperationV1>();
/// ```
///
/// ```compile_fail,E0624
/// use helix_plan_preparation::PreparedOperationV1;
///
/// let _ = PreparedOperationV1::new(todo!(), todo!());
/// ```
///
/// ```compile_fail,E0451
/// use helix_plan_preparation::PreparedOperationV1;
///
/// let _ = PreparedOperationV1 {
///     eligible: todo!(),
///     commit: todo!(),
/// };
/// ```
///
/// ```compile_fail,E0624
/// use helix_plan_preparation::PreparedOperationV1;
///
/// fn unpack(marker: PreparedOperationV1) {
///     let _ = marker.into_parts();
/// }
/// ```
#[allow(dead_code)] // Constructed and consumed only by the later one-shot orchestration task.
pub struct PreparedOperationV1 {
    eligible: EligiblePlanV1,
    commit: PreparationCommitReceiptV1,
}

#[allow(dead_code)]
impl PreparedOperationV1 {
    pub(crate) const fn new(eligible: EligiblePlanV1, commit: PreparationCommitReceiptV1) -> Self {
        Self { eligible, commit }
    }

    pub(crate) fn into_parts(self) -> (EligiblePlanV1, PreparationCommitReceiptV1) {
        (self.eligible, self.commit)
    }
}

impl fmt::Debug for PreparedOperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedOperationV1")
            .finish_non_exhaustive()
    }
}

#[must_use = "preparation outcomes carry sovereign custody or a closed refusal"]
// Keep the one-shot positive custody inline rather than introducing a fresh allocation
// after the durable commit has already been classified.
#[allow(clippy::large_enum_variant)]
pub enum PreparationOutcomeV1 {
    Prepared(PreparedOperationV1),
    Denied(PreparationDenialV1),
    Failed(PreparationFailureV1),
    Ambiguous(AmbiguousPreparationV1),
}

impl fmt::Debug for PreparationOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepared(_) => formatter.write_str("PreparationOutcomeV1::Prepared(..)"),
            Self::Denied(value) => write!(formatter, "PreparationOutcomeV1::Denied({value:?})"),
            Self::Failed(value) => write!(formatter, "PreparationOutcomeV1::Failed({value:?})"),
            Self::Ambiguous(value) => {
                write!(formatter, "PreparationOutcomeV1::Ambiguous({value:?})")
            }
        }
    }
}
