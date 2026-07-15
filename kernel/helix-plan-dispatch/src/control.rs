//! Injected atomic time, entropy, signer, and reserved control-lane boundaries.

#![allow(dead_code)]

use helix_dispatch_contracts::{
    sign_execution_grant_v1, ContractError, ExecutionGrantProtectedV1, Generation, GrantSigner,
    Identifier, SafeU64, SignedExecutionGrantV1,
};
use std::fmt;

pub const DISPATCH_ORDINARY_PENDING_CAPACITY_V1: usize = 1_024;
pub const DISPATCH_CONTROL_CAPACITY_V1: usize = 32;

/// One boot-bound time sample returned atomically by trusted clock wiring.
#[derive(PartialEq, Eq)]
pub struct DispatchTimeCaptureV1 {
    boot_id: Identifier,
    clock_generation: Generation,
    sampled_utc_ms: SafeU64,
    sampled_monotonic_ms: SafeU64,
}

impl DispatchTimeCaptureV1 {
    pub const fn new(
        boot_id: Identifier,
        clock_generation: Generation,
        sampled_utc_ms: SafeU64,
        sampled_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            boot_id,
            clock_generation,
            sampled_utc_ms,
            sampled_monotonic_ms,
        }
    }

    pub fn boot_id(&self) -> &str {
        self.boot_id.as_str()
    }

    pub(crate) const fn boot_identifier(&self) -> &Identifier {
        &self.boot_id
    }

    pub const fn clock_generation(&self) -> u64 {
        self.clock_generation.get()
    }

    pub const fn sampled_utc_ms(&self) -> u64 {
        self.sampled_utc_ms.get()
    }

    pub const fn sampled_monotonic_ms(&self) -> u64 {
        self.sampled_monotonic_ms.get()
    }

    pub(crate) const fn clock_generation_value(&self) -> Generation {
        self.clock_generation
    }

    pub(crate) const fn sampled_utc_value(&self) -> SafeU64 {
        self.sampled_utc_ms
    }

    pub(crate) const fn sampled_monotonic_value(&self) -> SafeU64 {
        self.sampled_monotonic_ms
    }
}

impl fmt::Debug for DispatchTimeCaptureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchTimeCaptureV1")
            .finish_non_exhaustive()
    }
}

pub enum DispatchTimeCaptureOutcomeV1 {
    Captured(DispatchTimeCaptureV1),
    Unavailable,
    Inconsistent,
}

impl fmt::Debug for DispatchTimeCaptureOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Captured(_) => formatter.write_str("DispatchTimeCaptureOutcomeV1::Captured(..)"),
            Self::Unavailable => formatter.write_str("DispatchTimeCaptureOutcomeV1::Unavailable"),
            Self::Inconsistent => formatter.write_str("DispatchTimeCaptureOutcomeV1::Inconsistent"),
        }
    }
}

/// Trusted clock seam. Boot, clock generation, UTC, and monotonic values share one call.
pub trait DispatchClockV1: Send + Sync {
    fn capture_time_v1(&self) -> DispatchTimeCaptureOutcomeV1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchEntropyDomainV1 {
    AttemptIdentity,
    GrantIdentity,
    OneShotNonce,
    TraceIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchEntropyErrorV1 {
    Unavailable,
    Unsupported,
}

/// Coordinator-owned randomness with an explicit domain for every generated value.
pub trait DispatchEntropySourceV1: Send + Sync {
    fn fill_entropy_v1(
        &self,
        domain: DispatchEntropyDomainV1,
        destination: &mut [u8],
    ) -> Result<(), DispatchEntropyErrorV1>;
}

/// Signed grant plus the exact canonical envelope bytes that stores and transports retain.
pub struct ExactSignedGrantV1 {
    signed: SignedExecutionGrantV1,
    exact_bytes: Box<[u8]>,
}

impl ExactSignedGrantV1 {
    fn from_signed(signed: SignedExecutionGrantV1) -> Result<Self, ContractError> {
        let exact_bytes = signed.to_canonical_json()?.into_boxed_slice();
        Ok(Self {
            signed,
            exact_bytes,
        })
    }

    pub const fn signed(&self) -> &SignedExecutionGrantV1 {
        &self.signed
    }

    pub const fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

impl fmt::Debug for ExactSignedGrantV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSignedGrantV1")
            .finish_non_exhaustive()
    }
}

/// Dedicated coordinator signer with the contract crate's purpose-specific boundary.
pub trait DispatchGrantSignerV1: GrantSigner + Send + Sync {
    fn sign_grant_v1(
        &self,
        protected: ExecutionGrantProtectedV1,
    ) -> Result<ExactSignedGrantV1, ContractError>
    where
        Self: Sized,
    {
        ExactSignedGrantV1::from_signed(sign_execution_grant_v1(protected, self)?)
    }
}

impl<T> DispatchGrantSignerV1 for T where T: GrantSigner + Send + Sync {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchAdmissionStateV1 {
    Running,
    Paused,
    Halted,
    Unavailable,
}

/// Linearization point of a delivery-control observation.
///
/// `BeforeHandoff` is still after the durable dispatch/grant transaction: control may
/// prevent transport admission, but it never rewrites that committed history as a
/// pre-dispatch failure. `PossibleHandoff` means adapter acceptance can no longer be
/// excluded and therefore requires readback or reconciliation custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchDeliveryControlPhaseV1 {
    BeforeHandoff,
    PossibleHandoff,
}

/// Closed control/audit observations that can race one committed delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchDeliveryControlSignalV1 {
    CancellationRequested,
    PauseRequested,
    HaltRequested,
    AuditUnavailable,
}

/// Closed, authority-preserving response to a delivery control race.
///
/// Every variant retains the committed grant and the PLAN-004 hold. There is no
/// cancellation/deletion, replacement-grant, safe-retry, or hold-release variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchDeliveryControlOutcomeV1 {
    PreventNewDeliveryRetainGrant,
    PreventNewDeliveryAuditBlockedRetainGrant,
    PreserveGrantAndRequireReadback,
    PreserveGrantAuditPendingUnknown,
}

impl DispatchDeliveryControlOutcomeV1 {
    pub const fn blocks_new_delivery(self) -> bool {
        true
    }

    pub const fn retains_committed_grant(self) -> bool {
        true
    }

    pub const fn retains_held_authority(self) -> bool {
        true
    }

    pub const fn requires_readback_or_reconciliation(self) -> bool {
        matches!(
            self,
            Self::PreserveGrantAndRequireReadback | Self::PreserveGrantAuditPendingUnknown
        )
    }

    pub const fn audit_pending(self) -> bool {
        matches!(self, Self::PreserveGrantAuditPendingUnknown)
    }

    pub const fn permits_evidence_deletion(self) -> bool {
        false
    }

    pub const fn permits_replacement_grant(self) -> bool {
        false
    }

    pub const fn permits_held_authority_release(self) -> bool {
        false
    }

    pub const fn claims_pre_dispatch_failure(self) -> bool {
        false
    }
}

/// Classifies cancellation/PAUSE/HALT/audit races without mutating authority.
pub const fn classify_delivery_control_v1(
    phase: DispatchDeliveryControlPhaseV1,
    signal: DispatchDeliveryControlSignalV1,
) -> DispatchDeliveryControlOutcomeV1 {
    match (phase, signal) {
        (
            DispatchDeliveryControlPhaseV1::BeforeHandoff,
            DispatchDeliveryControlSignalV1::CancellationRequested
            | DispatchDeliveryControlSignalV1::PauseRequested
            | DispatchDeliveryControlSignalV1::HaltRequested,
        ) => DispatchDeliveryControlOutcomeV1::PreventNewDeliveryRetainGrant,
        (
            DispatchDeliveryControlPhaseV1::BeforeHandoff,
            DispatchDeliveryControlSignalV1::AuditUnavailable,
        ) => DispatchDeliveryControlOutcomeV1::PreventNewDeliveryAuditBlockedRetainGrant,
        (
            DispatchDeliveryControlPhaseV1::PossibleHandoff,
            DispatchDeliveryControlSignalV1::CancellationRequested
            | DispatchDeliveryControlSignalV1::PauseRequested
            | DispatchDeliveryControlSignalV1::HaltRequested,
        ) => DispatchDeliveryControlOutcomeV1::PreserveGrantAndRequireReadback,
        (
            DispatchDeliveryControlPhaseV1::PossibleHandoff,
            DispatchDeliveryControlSignalV1::AuditUnavailable,
        ) => DispatchDeliveryControlOutcomeV1::PreserveGrantAuditPendingUnknown,
    }
}

pub enum DispatchControlLaneOutcomeV1<R> {
    Completed(R),
    Saturated,
    Unavailable,
    Denied,
}

impl<R> fmt::Debug for DispatchControlLaneOutcomeV1<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed(_) => {
                formatter.write_str("DispatchControlLaneOutcomeV1::Completed(..)")
            }
            Self::Saturated => formatter.write_str("DispatchControlLaneOutcomeV1::Saturated"),
            Self::Unavailable => formatter.write_str("DispatchControlLaneOutcomeV1::Unavailable"),
            Self::Denied => formatter.write_str("DispatchControlLaneOutcomeV1::Denied"),
        }
    }
}

/// Reserved lane for pause, status, and explicit reconciliation under ordinary load.
pub trait DispatchControlLaneV1: Send + Sync {
    type Status: Send;
    type PauseReceipt: Send;
    type ReconciliationReceipt: Send;

    fn admission_state_v1(&self) -> DispatchAdmissionStateV1;

    fn request_pause_v1(&self) -> DispatchControlLaneOutcomeV1<Self::PauseReceipt>;

    fn request_status_v1(&self) -> DispatchControlLaneOutcomeV1<Self::Status>;

    fn open_reconciliation_v1(
        &self,
        operation_binding: &[u8; 32],
    ) -> DispatchControlLaneOutcomeV1<Self::ReconciliationReceipt>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_control_matrix_is_closed_and_phase_aware() {
        for signal in [
            DispatchDeliveryControlSignalV1::CancellationRequested,
            DispatchDeliveryControlSignalV1::PauseRequested,
            DispatchDeliveryControlSignalV1::HaltRequested,
        ] {
            assert_eq!(
                classify_delivery_control_v1(DispatchDeliveryControlPhaseV1::BeforeHandoff, signal,),
                DispatchDeliveryControlOutcomeV1::PreventNewDeliveryRetainGrant
            );
            assert_eq!(
                classify_delivery_control_v1(
                    DispatchDeliveryControlPhaseV1::PossibleHandoff,
                    signal,
                ),
                DispatchDeliveryControlOutcomeV1::PreserveGrantAndRequireReadback
            );
        }

        assert_eq!(
            classify_delivery_control_v1(
                DispatchDeliveryControlPhaseV1::BeforeHandoff,
                DispatchDeliveryControlSignalV1::AuditUnavailable,
            ),
            DispatchDeliveryControlOutcomeV1::PreventNewDeliveryAuditBlockedRetainGrant
        );
        assert_eq!(
            classify_delivery_control_v1(
                DispatchDeliveryControlPhaseV1::PossibleHandoff,
                DispatchDeliveryControlSignalV1::AuditUnavailable,
            ),
            DispatchDeliveryControlOutcomeV1::PreserveGrantAuditPendingUnknown
        );
    }

    #[test]
    fn every_control_outcome_retains_grant_and_hold_without_false_failure() {
        for phase in [
            DispatchDeliveryControlPhaseV1::BeforeHandoff,
            DispatchDeliveryControlPhaseV1::PossibleHandoff,
        ] {
            for signal in [
                DispatchDeliveryControlSignalV1::CancellationRequested,
                DispatchDeliveryControlSignalV1::PauseRequested,
                DispatchDeliveryControlSignalV1::HaltRequested,
                DispatchDeliveryControlSignalV1::AuditUnavailable,
            ] {
                let outcome = classify_delivery_control_v1(phase, signal);
                assert!(outcome.blocks_new_delivery());
                assert!(outcome.retains_committed_grant());
                assert!(outcome.retains_held_authority());
                assert!(!outcome.permits_evidence_deletion());
                assert!(!outcome.permits_replacement_grant());
                assert!(!outcome.permits_held_authority_release());
                assert!(!outcome.claims_pre_dispatch_failure());
                assert_eq!(
                    outcome.requires_readback_or_reconciliation(),
                    phase == DispatchDeliveryControlPhaseV1::PossibleHandoff
                );
                assert_eq!(
                    outcome.audit_pending(),
                    phase == DispatchDeliveryControlPhaseV1::PossibleHandoff
                        && signal == DispatchDeliveryControlSignalV1::AuditUnavailable
                );
            }
        }
    }
}
