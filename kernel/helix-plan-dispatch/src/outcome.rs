//! Closed, versioned, and publicly redacted dispatch outcomes.

#![allow(dead_code)]

use std::fmt;

pub const DISPATCH_OUTCOME_CONTRACT_VERSION_V1: u16 = 1;

macro_rules! closed_reason_enum {
    (
        $visibility:vis enum $name:ident,
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
    };
}

closed_reason_enum! {
    pub enum DispatchDenialReasonV1,
    {
        InvalidRequest => "DISPATCH_INVALID_REQUEST",
        VersionUnsupported => "DISPATCH_VERSION_UNSUPPORTED",
        OperationMissing => "DISPATCH_OPERATION_MISSING",
        OperationNotCurrent => "DISPATCH_OPERATION_NOT_CURRENT",
        ExpectedBindingMismatch => "DISPATCH_EXPECTED_BINDING_MISMATCH",
        AuthorityUnavailable => "DISPATCH_AUTHORITY_UNAVAILABLE",
        AuthorityMismatch => "DISPATCH_AUTHORITY_MISMATCH",
        DeadlineReached => "DISPATCH_DEADLINE_REACHED",
        CapacityExceeded => "DISPATCH_CAPACITY_EXCEEDED",
        GuardRevoked => "DISPATCH_GUARD_REVOKED",
        DestinationMismatch => "DISPATCH_DESTINATION_MISMATCH",
        SignerUnavailable => "DISPATCH_SIGNER_UNAVAILABLE"
    }
}

closed_reason_enum! {
    pub enum DispatchFailureReasonV1,
    {
        StoreUnavailable => "DISPATCH_STORE_UNAVAILABLE",
        StoreUnhealthy => "DISPATCH_STORE_UNHEALTHY",
        SigningFailed => "DISPATCH_SIGNING_FAILED",
        CommitAborted => "DISPATCH_COMMIT_ABORTED"
    }
}

closed_reason_enum! {
    pub enum DispatchAmbiguityReasonV1,
    {
        CommitUncertain => "DISPATCH_COMMIT_UNCERTAIN",
        ReadbackUnavailable => "DISPATCH_READBACK_UNAVAILABLE",
        ReadbackInconsistent => "DISPATCH_READBACK_INCONSISTENT",
        PermitOwnerLost => "DISPATCH_PERMIT_OWNER_LOST"
    }
}

closed_reason_enum! {
    pub enum DispatchConflictReasonV1,
    {
        GrantBindingConflict => "DISPATCH_GRANT_BINDING_CONFLICT",
        ReceiptBindingConflict => "DISPATCH_RECEIPT_BINDING_CONFLICT",
        EvidenceConflict => "DISPATCH_EVIDENCE_CONFLICT"
    }
}

closed_reason_enum! {
    pub enum DispatchUnknownReasonV1,
    {
        PossibleHandoff => "DISPATCH_POSSIBLE_HANDOFF",
        ReadbackExhausted => "DISPATCH_READBACK_EXHAUSTED",
        ReadbackUnavailable => "DISPATCH_OUTCOME_READBACK_UNAVAILABLE"
    }
}

closed_reason_enum! {
    pub enum DispatchReconciliationReasonV1,
    {
        PossibleConsumption => "DISPATCH_POSSIBLE_CONSUMPTION",
        LateConsumedReceipt => "DISPATCH_LATE_CONSUMED_RECEIPT",
        RestoreCustody => "DISPATCH_RESTORE_CUSTODY",
        OrphanEvidence => "DISPATCH_ORPHAN_EVIDENCE"
    }
}

closed_reason_enum! {
    pub enum DispatchReconciliationFailureReasonV1,
    {
        DefiniteNoConsumption => "DISPATCH_DEFINITE_NO_CONSUMPTION",
        DefiniteRefusal => "DISPATCH_DEFINITE_REFUSAL"
    }
}

macro_rules! opaque_projection {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}

pub struct RetainedDispatchV1 {
    grant_id: [u8; 32],
    grant_digest: [u8; 32],
    state_generation: u64,
}

opaque_projection!(RetainedDispatchV1, "RetainedDispatchV1");

impl RetainedDispatchV1 {
    /// Returns the verified durable grant identifier carried by the committed projection.
    ///
    /// This restricted correlation lookup is not a grant, permit, or effect authority and
    /// must not be logged or serialized as public diagnostics.
    pub const fn grant_id(&self) -> [u8; 32] {
        self.grant_id
    }

    pub(crate) const fn from_verified_store_v1(
        grant_id: [u8; 32],
        grant_digest: [u8; 32],
        state_generation: u64,
    ) -> Self {
        Self {
            grant_id,
            grant_digest,
            state_generation,
        }
    }
}

pub struct DeniedDispatchV1 {
    reason: DispatchDenialReasonV1,
}

opaque_projection!(DeniedDispatchV1, "DeniedDispatchV1");

impl DeniedDispatchV1 {
    pub(crate) const fn from_reason_v1(reason: DispatchDenialReasonV1) -> Self {
        Self { reason }
    }

    pub const fn reason(&self) -> DispatchDenialReasonV1 {
        self.reason
    }
}

pub struct FailedDispatchV1 {
    reason: DispatchFailureReasonV1,
}

opaque_projection!(FailedDispatchV1, "FailedDispatchV1");

impl FailedDispatchV1 {
    pub(crate) const fn from_reason_v1(reason: DispatchFailureReasonV1) -> Self {
        Self { reason }
    }

    pub const fn reason(&self) -> DispatchFailureReasonV1 {
        self.reason
    }
}

pub struct AmbiguousDispatchV1 {
    reason: DispatchAmbiguityReasonV1,
    attempt_id: [u8; 32],
}

opaque_projection!(AmbiguousDispatchV1, "AmbiguousDispatchV1");

impl AmbiguousDispatchV1 {
    pub(crate) const fn from_reason_v1(
        reason: DispatchAmbiguityReasonV1,
        attempt_id: [u8; 32],
    ) -> Self {
        Self { reason, attempt_id }
    }

    pub const fn reason(&self) -> DispatchAmbiguityReasonV1 {
        self.reason
    }
}

pub struct ConsumedDispatchV1 {
    receipt_digest: [u8; 32],
    state_generation: u64,
}

opaque_projection!(ConsumedDispatchV1, "ConsumedDispatchV1");

pub struct DefinitelyRefusedDispatchV1 {
    receipt_digest: [u8; 32],
    state_generation: u64,
}

opaque_projection!(DefinitelyRefusedDispatchV1, "DefinitelyRefusedDispatchV1");

pub struct PendingDispatchV1 {
    grant_id: [u8; 32],
    grant_digest: [u8; 32],
    exclusive_deadline_monotonic_ms: u64,
}

opaque_projection!(PendingDispatchV1, "PendingDispatchV1");

pub struct ConflictDispatchV1 {
    reason: DispatchConflictReasonV1,
    incident_generation: u64,
}

opaque_projection!(ConflictDispatchV1, "ConflictDispatchV1");

impl ConflictDispatchV1 {
    pub const fn reason(&self) -> DispatchConflictReasonV1 {
        self.reason
    }
}

pub struct OutcomeUnknownDispatchV1 {
    reason: DispatchUnknownReasonV1,
    custody_generation: u64,
}

opaque_projection!(OutcomeUnknownDispatchV1, "OutcomeUnknownDispatchV1");

impl OutcomeUnknownDispatchV1 {
    pub const fn reason(&self) -> DispatchUnknownReasonV1 {
        self.reason
    }
}

pub struct ReconciliationRequiredDispatchV1 {
    reason: DispatchReconciliationReasonV1,
    reconciliation_generation: u64,
}

opaque_projection!(
    ReconciliationRequiredDispatchV1,
    "ReconciliationRequiredDispatchV1"
);

impl ReconciliationRequiredDispatchV1 {
    pub const fn reason(&self) -> DispatchReconciliationReasonV1 {
        self.reason
    }
}

pub struct FailedReconciliationV1 {
    reason: DispatchReconciliationFailureReasonV1,
    reconciliation_generation: u64,
}

opaque_projection!(FailedReconciliationV1, "FailedReconciliationV1");

impl FailedReconciliationV1 {
    pub const fn reason(&self) -> DispatchReconciliationFailureReasonV1 {
        self.reason
    }
}

pub enum DispatchRequestOutcomeV1 {
    Dispatched(RetainedDispatchV1),
    AlreadyDispatched(RetainedDispatchV1),
    Denied(DeniedDispatchV1),
    Failed(FailedDispatchV1),
    Ambiguous(AmbiguousDispatchV1),
}

impl fmt::Debug for DispatchRequestOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dispatched(_) => formatter.write_str("DispatchRequestOutcomeV1::Dispatched(..)"),
            Self::AlreadyDispatched(_) => {
                formatter.write_str("DispatchRequestOutcomeV1::AlreadyDispatched(..)")
            }
            Self::Denied(_) => formatter.write_str("DispatchRequestOutcomeV1::Denied(..)"),
            Self::Failed(_) => formatter.write_str("DispatchRequestOutcomeV1::Failed(..)"),
            Self::Ambiguous(_) => formatter.write_str("DispatchRequestOutcomeV1::Ambiguous(..)"),
        }
    }
}

pub enum DispatchDeliveryOutcomeV1 {
    Consumed(ConsumedDispatchV1),
    DefinitelyRefused(DefinitelyRefusedDispatchV1),
    Pending(PendingDispatchV1),
    Conflict(ConflictDispatchV1),
    OutcomeUnknown(OutcomeUnknownDispatchV1),
    ReconciliationRequired(ReconciliationRequiredDispatchV1),
}

impl fmt::Debug for DispatchDeliveryOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consumed(_) => formatter.write_str("DispatchDeliveryOutcomeV1::Consumed(..)"),
            Self::DefinitelyRefused(_) => {
                formatter.write_str("DispatchDeliveryOutcomeV1::DefinitelyRefused(..)")
            }
            Self::Pending(_) => formatter.write_str("DispatchDeliveryOutcomeV1::Pending(..)"),
            Self::Conflict(_) => formatter.write_str("DispatchDeliveryOutcomeV1::Conflict(..)"),
            Self::OutcomeUnknown(_) => {
                formatter.write_str("DispatchDeliveryOutcomeV1::OutcomeUnknown(..)")
            }
            Self::ReconciliationRequired(_) => {
                formatter.write_str("DispatchDeliveryOutcomeV1::ReconciliationRequired(..)")
            }
        }
    }
}

pub enum DispatchReconciliationOutcomeV1 {
    ReconciliationRequired(ReconciliationRequiredDispatchV1),
    Failed(FailedReconciliationV1),
}

impl fmt::Debug for DispatchReconciliationOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReconciliationRequired(_) => {
                formatter.write_str("DispatchReconciliationOutcomeV1::ReconciliationRequired(..)")
            }
            Self::Failed(_) => formatter.write_str("DispatchReconciliationOutcomeV1::Failed(..)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_codes {
        ($reason:ty) => {
            for value in <$reason>::ALL {
                let code = value.code();
                assert!(!code.is_empty());
                assert!(code.bytes().all(|byte| {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                }));
            }
        };
    }

    #[test]
    fn every_public_reason_code_is_closed_uppercase_ascii() {
        assert_codes!(DispatchDenialReasonV1);
        assert_codes!(DispatchFailureReasonV1);
        assert_codes!(DispatchAmbiguityReasonV1);
        assert_codes!(DispatchConflictReasonV1);
        assert_codes!(DispatchUnknownReasonV1);
        assert_codes!(DispatchReconciliationReasonV1);
        assert_codes!(DispatchReconciliationFailureReasonV1);
    }

    #[test]
    fn retained_dispatch_exposes_only_its_exact_correlation_id_and_keeps_debug_opaque() {
        let retained = RetainedDispatchV1::from_verified_store_v1([0x61; 32], [0x62; 32], 7);
        assert_eq!(retained.grant_id(), [0x61; 32]);
        assert_eq!(format!("{retained:?}"), "RetainedDispatchV1 { .. }");
    }
}
