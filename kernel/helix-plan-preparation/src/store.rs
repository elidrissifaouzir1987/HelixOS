//! Portable coordinator-store contract boundary.
//!
//! Store contracts separate read-only preflight, guarded commit, exact readback, and
//! known-failure reconciliation. SQLite, roots, native errors, and durable schema
//! details belong to the host storage adapter.

use crate::attempt::PreparationAttemptIdV1;
use crate::budget::{BudgetReservationReceiptV1, BudgetVectorV1};
use crate::commit_gate::{FinalCommitGateV1, FinalCommitPermitV1};
use crate::context::ReadyPreparationContextV1;
use crate::guard::{NoDispatchAuthorityBindingV1, NoDispatchAuthorityGuardV1};
use crate::outcome::PreparationFailureV1;
use crate::recovery::RecoveryEvidenceV1;
use helix_contracts::{SafeU64, Sha256Digest};
use helix_plan_eligibility::EligiblePlanV1;
use std::fmt;

macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}

pub const PREPARATION_STORE_CONTRACT_VERSION_V1: u16 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum PreparationStoreContractBuildErrorV1 {
    VersionUnsupported,
    IntegerOutOfRange,
}

pub struct PreparationPreflightInputV1<'input> {
    contract_version: u16,
    eligible: &'input EligiblePlanV1,
    attempt: &'input PreparationAttemptIdV1,
    context: &'input ReadyPreparationContextV1,
    requested_budget: &'input BudgetVectorV1,
}

impl<'input> PreparationPreflightInputV1<'input> {
    #[allow(dead_code)] // Wired by the later ordered orchestration task.
    pub(crate) fn new(
        eligible: &'input EligiblePlanV1,
        attempt: &'input PreparationAttemptIdV1,
        context: &'input ReadyPreparationContextV1,
        requested_budget: &'input BudgetVectorV1,
    ) -> Self {
        Self {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            eligible,
            attempt,
            context,
            requested_budget,
        }
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn eligible(&self) -> &EligiblePlanV1 {
        self.eligible
    }
    pub const fn attempt(&self) -> &PreparationAttemptIdV1 {
        self.attempt
    }
    pub const fn context(&self) -> &ReadyPreparationContextV1 {
        self.context
    }
    pub const fn requested_budget(&self) -> &BudgetVectorV1 {
        self.requested_budget
    }
}

redacted_debug!(
    PreparationPreflightInputV1<'_>,
    "PreparationPreflightInputV1"
);

pub struct BudgetPreflightInputV1 {
    pub contract_version: u16,
    pub observed_scope_generation: u64,
    pub observed_scope_binding_digest: Sha256Digest,
    pub observed_remaining: BudgetVectorV1,
}

redacted_debug!(BudgetPreflightInputV1, "BudgetPreflightInputV1");

/// Opaque, read-only snapshot evidence that reserves no capacity.
pub struct BudgetPreflightV1 {
    contract_version: u16,
    observed_scope_generation: SafeU64,
    observed_scope_binding_digest: Sha256Digest,
    observed_remaining: BudgetVectorV1,
}

impl BudgetPreflightV1 {
    pub fn try_new(
        input: BudgetPreflightInputV1,
    ) -> Result<Self, PreparationStoreContractBuildErrorV1> {
        require_version(input.contract_version)?;
        Ok(Self {
            contract_version: input.contract_version,
            observed_scope_generation: safe(input.observed_scope_generation)?,
            observed_scope_binding_digest: input.observed_scope_binding_digest,
            observed_remaining: input.observed_remaining,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn observed_scope_generation(&self) -> u64 {
        self.observed_scope_generation.get()
    }
    pub const fn observed_scope_binding_digest(&self) -> Sha256Digest {
        self.observed_scope_binding_digest
    }
    pub const fn observed_remaining(&self) -> &BudgetVectorV1 {
        &self.observed_remaining
    }
}

redacted_debug!(BudgetPreflightV1, "BudgetPreflightV1");

pub enum PreparationPreflightOutcomeV1 {
    Ready(BudgetPreflightV1),
    OperationAuthorityUnavailable,
    OperationConflict,
    AlreadyPrepared,
    BudgetScopeMissing,
    BudgetAuthorityUnavailable,
    BudgetBindingConflict,
    BudgetArithmeticInvalid,
    BudgetExhausted,
}

impl fmt::Debug for PreparationPreflightOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Ready(_) => "Ready(..)",
            Self::OperationAuthorityUnavailable => "OperationAuthorityUnavailable",
            Self::OperationConflict => "OperationConflict",
            Self::AlreadyPrepared => "AlreadyPrepared",
            Self::BudgetScopeMissing => "BudgetScopeMissing",
            Self::BudgetAuthorityUnavailable => "BudgetAuthorityUnavailable",
            Self::BudgetBindingConflict => "BudgetBindingConflict",
            Self::BudgetArithmeticInvalid => "BudgetArithmeticInvalid",
            Self::BudgetExhausted => "BudgetExhausted",
        };
        write!(formatter, "PreparationPreflightOutcomeV1::{variant}")
    }
}

pub struct PreparationCommitInputV1<'input> {
    contract_version: u16,
    eligible: &'input EligiblePlanV1,
    attempt: &'input PreparationAttemptIdV1,
    final_context: &'input ReadyPreparationContextV1,
    requested_budget: &'input BudgetVectorV1,
    preflight: &'input BudgetPreflightV1,
    recovery_evidence: &'input RecoveryEvidenceV1,
}

impl<'input> PreparationCommitInputV1<'input> {
    #[allow(dead_code)] // Wired by the later ordered orchestration task.
    pub(crate) fn new(
        eligible: &'input EligiblePlanV1,
        attempt: &'input PreparationAttemptIdV1,
        final_context: &'input ReadyPreparationContextV1,
        requested_budget: &'input BudgetVectorV1,
        preflight: &'input BudgetPreflightV1,
        recovery_evidence: &'input RecoveryEvidenceV1,
    ) -> Self {
        Self {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            eligible,
            attempt,
            final_context,
            requested_budget,
            preflight,
            recovery_evidence,
        }
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn eligible(&self) -> &EligiblePlanV1 {
        self.eligible
    }
    pub const fn attempt(&self) -> &PreparationAttemptIdV1 {
        self.attempt
    }
    pub const fn final_context(&self) -> &ReadyPreparationContextV1 {
        self.final_context
    }
    pub const fn requested_budget(&self) -> &BudgetVectorV1 {
        self.requested_budget
    }
    pub const fn preflight(&self) -> &BudgetPreflightV1 {
        self.preflight
    }
    pub const fn recovery_evidence(&self) -> &RecoveryEvidenceV1 {
        self.recovery_evidence
    }
}

redacted_debug!(PreparationCommitInputV1<'_>, "PreparationCommitInputV1");

pub struct PreparationCommitReceiptInputV1 {
    pub contract_version: u16,
    pub attempt_id: Sha256Digest,
    pub store_generation: u64,
    pub operation_state_generation: u64,
    pub transition_generation: u64,
    pub event_generation: u64,
    pub budget_reservation: BudgetReservationReceiptV1,
}

redacted_debug!(
    PreparationCommitReceiptInputV1,
    "PreparationCommitReceiptInputV1"
);

/// Opaque exact-commit custody. It is not a status lookup or adapter authority.
pub struct PreparationCommitReceiptV1 {
    contract_version: u16,
    attempt_id: Sha256Digest,
    store_generation: SafeU64,
    operation_state_generation: SafeU64,
    transition_generation: SafeU64,
    event_generation: SafeU64,
    budget_reservation: BudgetReservationReceiptV1,
}

impl PreparationCommitReceiptV1 {
    pub fn try_new(
        input: PreparationCommitReceiptInputV1,
    ) -> Result<Self, PreparationStoreContractBuildErrorV1> {
        require_version(input.contract_version)?;
        Ok(Self {
            contract_version: input.contract_version,
            attempt_id: input.attempt_id,
            store_generation: safe(input.store_generation)?,
            operation_state_generation: safe(input.operation_state_generation)?,
            transition_generation: safe(input.transition_generation)?,
            event_generation: safe(input.event_generation)?,
            budget_reservation: input.budget_reservation,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn attempt_id(&self) -> Sha256Digest {
        self.attempt_id
    }
    pub const fn store_generation(&self) -> u64 {
        self.store_generation.get()
    }
    pub const fn operation_state_generation(&self) -> u64 {
        self.operation_state_generation.get()
    }
    pub const fn transition_generation(&self) -> u64 {
        self.transition_generation.get()
    }
    pub const fn event_generation(&self) -> u64 {
        self.event_generation.get()
    }
    pub const fn budget_reservation(&self) -> &BudgetReservationReceiptV1 {
        &self.budget_reservation
    }
}

redacted_debug!(PreparationCommitReceiptV1, "PreparationCommitReceiptV1");

pub struct PreparationCommitUncertainV1 {
    contract_version: u16,
    attempt_id: Sha256Digest,
}

impl PreparationCommitUncertainV1 {
    pub fn try_new(
        contract_version: u16,
        attempt_id: Sha256Digest,
    ) -> Result<Self, PreparationStoreContractBuildErrorV1> {
        require_version(contract_version)?;
        Ok(Self {
            contract_version,
            attempt_id,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn attempt_id(&self) -> Sha256Digest {
        self.attempt_id
    }
}

redacted_debug!(PreparationCommitUncertainV1, "PreparationCommitUncertainV1");

pub enum PreparationCommitOutcomeV1<I = ()> {
    Committed(PreparationCommitReceiptV1),
    ConfirmedRollback,
    Uncertain {
        token: PreparationCommitUncertainV1,
        in_flight: I,
    },
    /// The live final gate refused before the one-shot store commit was invoked.
    PermitRevoked,
    PermitUnavailable,
    PermitDeadlineReached,
    PermitUnsupported,
    /// The permit was entered but the actual commit result lacked trusted classification.
    Unclassified,
    Unavailable,
    Busy,
    Unhealthy,
    /// A serialized operation/attempt/plan identity is occupied incompatibly.
    OperationConflict,
    /// One coherent prior preparation already permanently occupies the operation.
    AlreadyPrepared,
    /// A residual serialized constraint not attributable to a known operation/budget row.
    Conflict,
    BudgetScopeMissing,
    BudgetBindingConflict,
    BudgetArithmeticInvalid,
    BudgetExhausted,
}

impl<I> fmt::Debug for PreparationCommitOutcomeV1<I> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Committed(_) => "Committed(..)",
            Self::ConfirmedRollback => "ConfirmedRollback",
            Self::Uncertain { .. } => "Uncertain(..)",
            Self::PermitRevoked => "PermitRevoked",
            Self::PermitUnavailable => "PermitUnavailable",
            Self::PermitDeadlineReached => "PermitDeadlineReached",
            Self::PermitUnsupported => "PermitUnsupported",
            Self::Unclassified => "Unclassified",
            Self::Unavailable => "Unavailable",
            Self::Busy => "Busy",
            Self::Unhealthy => "Unhealthy",
            Self::OperationConflict => "OperationConflict",
            Self::AlreadyPrepared => "AlreadyPrepared",
            Self::Conflict => "Conflict",
            Self::BudgetScopeMissing => "BudgetScopeMissing",
            Self::BudgetBindingConflict => "BudgetBindingConflict",
            Self::BudgetArithmeticInvalid => "BudgetArithmeticInvalid",
            Self::BudgetExhausted => "BudgetExhausted",
        };
        write!(formatter, "PreparationCommitOutcomeV1::{variant}")
    }
}

pub struct PreparationReadbackInputV1<'input> {
    contract_version: u16,
    eligible: &'input EligiblePlanV1,
    attempt: &'input PreparationAttemptIdV1,
    uncertain: &'input PreparationCommitUncertainV1,
}

impl<'input> PreparationReadbackInputV1<'input> {
    #[allow(dead_code)] // Wired by the later ordered orchestration task.
    pub(crate) fn new(
        eligible: &'input EligiblePlanV1,
        attempt: &'input PreparationAttemptIdV1,
        uncertain: &'input PreparationCommitUncertainV1,
    ) -> Self {
        Self {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            eligible,
            attempt,
            uncertain,
        }
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn eligible(&self) -> &EligiblePlanV1 {
        self.eligible
    }
    pub const fn attempt(&self) -> &PreparationAttemptIdV1 {
        self.attempt
    }
    pub const fn uncertain(&self) -> &PreparationCommitUncertainV1 {
        self.uncertain
    }
}

redacted_debug!(PreparationReadbackInputV1<'_>, "PreparationReadbackInputV1");

pub enum PreparationReadbackOutcomeV1 {
    ThisAttempt(PreparationCommitReceiptV1),
    PriorExactAttempt,
    Conflict,
    DefiniteAbsence,
    Ambiguous,
    Unavailable,
    Unhealthy,
}

impl fmt::Debug for PreparationReadbackOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::ThisAttempt(_) => "ThisAttempt(..)",
            Self::PriorExactAttempt => "PriorExactAttempt",
            Self::Conflict => "Conflict",
            Self::DefiniteAbsence => "DefiniteAbsence",
            Self::Ambiguous => "Ambiguous",
            Self::Unavailable => "Unavailable",
            Self::Unhealthy => "Unhealthy",
        };
        write!(formatter, "PreparationReadbackOutcomeV1::{variant}")
    }
}

pub struct PreparationFailureInputV1<'input> {
    contract_version: u16,
    binding: &'input NoDispatchAuthorityBindingV1<'input>,
    reason: PreparationFailureV1,
}

impl<'input> PreparationFailureInputV1<'input> {
    #[allow(dead_code)] // Wired by the later known-failure orchestration task.
    pub(crate) fn new(
        binding: &'input NoDispatchAuthorityBindingV1<'input>,
        reason: PreparationFailureV1,
    ) -> Self {
        Self {
            contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
            binding,
            reason,
        }
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }
    pub const fn binding(&self) -> &NoDispatchAuthorityBindingV1<'input> {
        self.binding
    }
    pub const fn reason(&self) -> PreparationFailureV1 {
        self.reason
    }
}

redacted_debug!(PreparationFailureInputV1<'_>, "PreparationFailureInputV1");

pub enum PreparationFailureOutcomeV1 {
    Failed,
    AlreadyFailed,
    Mismatch,
    DeadlineReached,
    Unavailable,
    Unhealthy,
    Conflict,
}

impl fmt::Debug for PreparationFailureOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Failed => "Failed",
            Self::AlreadyFailed => "AlreadyFailed",
            Self::Mismatch => "Mismatch",
            Self::DeadlineReached => "DeadlineReached",
            Self::Unavailable => "Unavailable",
            Self::Unhealthy => "Unhealthy",
            Self::Conflict => "Conflict",
        };
        write!(formatter, "PreparationFailureOutcomeV1::{variant}")
    }
}

/// Replaceable synchronous authoritative store boundary.
pub trait PreparationStoreV1: Send + Sync {
    fn preflight_operation_and_budget(
        &self,
        input: &PreparationPreflightInputV1<'_>,
    ) -> PreparationPreflightOutcomeV1;

    fn commit_preparing<G: FinalCommitGateV1>(
        &self,
        input: &PreparationCommitInputV1<'_>,
        final_gate: &mut G,
    ) -> PreparationCommitOutcomeV1<<G::Permit as FinalCommitPermitV1>::InFlight>;

    fn readback_attempt(
        &self,
        input: &PreparationReadbackInputV1<'_>,
    ) -> PreparationReadbackOutcomeV1;

    fn fail_before_dispatch<G: NoDispatchAuthorityGuardV1>(
        &self,
        input: &PreparationFailureInputV1<'_>,
        no_dispatch_guard: &mut G,
    ) -> PreparationFailureOutcomeV1;
}

fn safe(value: u64) -> Result<SafeU64, PreparationStoreContractBuildErrorV1> {
    SafeU64::new(value).map_err(|_| PreparationStoreContractBuildErrorV1::IntegerOutOfRange)
}

fn require_version(value: u16) -> Result<(), PreparationStoreContractBuildErrorV1> {
    if value != PREPARATION_STORE_CONTRACT_VERSION_V1 {
        return Err(PreparationStoreContractBuildErrorV1::VersionUnsupported);
    }
    Ok(())
}
