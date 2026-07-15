//! Fenced definite-absence and signed no-consumption evidence classification.

use crate::DispatchPreReceiveRefusalV1;
use helix_dispatch_contracts::{
    AuthenticExecutionReceiptV1, ExecutionReceiptDecisionV1, ExecutionReceiptRefusalCodeV1,
};
use std::fmt;

const MAX_SAFE_U64_V1: u64 = 9_007_199_254_740_991;

pub struct DispatchDefiniteAbsenceEvidenceInputV1 {
    pub transport_fenced: bool,
    pub transport_quiesced: bool,
    pub adapter_healthy: bool,
    pub expected_adapter_root: [u8; 32],
    pub observed_adapter_root: [u8; 32],
    pub expected_supervisor_epoch: u64,
    pub observed_supervisor_epoch: u64,
    pub expected_delivery_attempt_id: [u8; 32],
    pub observed_delivery_attempt_id: [u8; 32],
    pub authoritative_handoff_generation: u64,
    pub observed_readback_generation: u64,
    pub exclusive_deadline_monotonic_ms: u64,
    pub observed_monotonic_ms: u64,
}

impl fmt::Debug for DispatchDefiniteAbsenceEvidenceInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchDefiniteAbsenceEvidenceInputV1")
            .finish_non_exhaustive()
    }
}

/// Checked evidence bundle. Construction validates only shape and safe-integer bounds;
/// the classifier below still requires every independent equality and fence.
pub struct DispatchDefiniteAbsenceEvidenceV1 {
    transport_fenced: bool,
    transport_quiesced: bool,
    adapter_healthy: bool,
    expected_adapter_root: [u8; 32],
    observed_adapter_root: [u8; 32],
    expected_supervisor_epoch: u64,
    observed_supervisor_epoch: u64,
    expected_delivery_attempt_id: [u8; 32],
    observed_delivery_attempt_id: [u8; 32],
    authoritative_handoff_generation: u64,
    observed_readback_generation: u64,
    exclusive_deadline_monotonic_ms: u64,
    observed_monotonic_ms: u64,
}

impl DispatchDefiniteAbsenceEvidenceV1 {
    pub fn try_new(input: DispatchDefiniteAbsenceEvidenceInputV1) -> Option<Self> {
        if input.expected_adapter_root == [0; 32]
            || input.observed_adapter_root == [0; 32]
            || input.expected_delivery_attempt_id == [0; 32]
            || input.observed_delivery_attempt_id == [0; 32]
            || input.expected_supervisor_epoch > MAX_SAFE_U64_V1
            || input.observed_supervisor_epoch > MAX_SAFE_U64_V1
            || !(1..=MAX_SAFE_U64_V1).contains(&input.authoritative_handoff_generation)
            || !(1..=MAX_SAFE_U64_V1).contains(&input.observed_readback_generation)
            || !(1..=MAX_SAFE_U64_V1).contains(&input.exclusive_deadline_monotonic_ms)
            || input.observed_monotonic_ms > MAX_SAFE_U64_V1
        {
            return None;
        }
        Some(Self {
            transport_fenced: input.transport_fenced,
            transport_quiesced: input.transport_quiesced,
            adapter_healthy: input.adapter_healthy,
            expected_adapter_root: input.expected_adapter_root,
            observed_adapter_root: input.observed_adapter_root,
            expected_supervisor_epoch: input.expected_supervisor_epoch,
            observed_supervisor_epoch: input.observed_supervisor_epoch,
            expected_delivery_attempt_id: input.expected_delivery_attempt_id,
            observed_delivery_attempt_id: input.observed_delivery_attempt_id,
            authoritative_handoff_generation: input.authoritative_handoff_generation,
            observed_readback_generation: input.observed_readback_generation,
            exclusive_deadline_monotonic_ms: input.exclusive_deadline_monotonic_ms,
            observed_monotonic_ms: input.observed_monotonic_ms,
        })
    }
}

impl fmt::Debug for DispatchDefiniteAbsenceEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchDefiniteAbsenceEvidenceV1")
            .finish_non_exhaustive()
    }
}

pub struct DispatchDefiniteAbsenceProofV1 {
    adapter_root: [u8; 32],
    supervisor_epoch: u64,
    delivery_attempt_id: [u8; 32],
    readback_generation: u64,
    exclusive_deadline_monotonic_ms: u64,
}

impl DispatchDefiniteAbsenceProofV1 {
    pub const fn adapter_root(&self) -> [u8; 32] {
        self.adapter_root
    }

    pub const fn supervisor_epoch(&self) -> u64 {
        self.supervisor_epoch
    }

    pub const fn delivery_attempt_id(&self) -> [u8; 32] {
        self.delivery_attempt_id
    }

    pub const fn readback_generation(&self) -> u64 {
        self.readback_generation
    }

    pub const fn exclusive_deadline_monotonic_ms(&self) -> u64 {
        self.exclusive_deadline_monotonic_ms
    }
}

impl fmt::Debug for DispatchDefiniteAbsenceProofV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchDefiniteAbsenceProofV1")
            .finish_non_exhaustive()
    }
}

pub enum DispatchDefiniteAbsenceClassificationV1 {
    DefiniteAbsence(DispatchDefiniteAbsenceProofV1),
    PossibleConsumption,
}

impl fmt::Debug for DispatchDefiniteAbsenceClassificationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DefiniteAbsence(_) => {
                "DispatchDefiniteAbsenceClassificationV1::DefiniteAbsence(..)"
            }
            Self::PossibleConsumption => {
                "DispatchDefiniteAbsenceClassificationV1::PossibleConsumption"
            }
        })
    }
}

pub fn classify_definite_absence_v1(
    evidence: DispatchDefiniteAbsenceEvidenceV1,
) -> DispatchDefiniteAbsenceClassificationV1 {
    if evidence.transport_fenced
        && evidence.transport_quiesced
        && evidence.adapter_healthy
        && evidence.observed_adapter_root == evidence.expected_adapter_root
        && evidence.observed_supervisor_epoch == evidence.expected_supervisor_epoch
        && evidence.observed_delivery_attempt_id == evidence.expected_delivery_attempt_id
        && evidence.observed_readback_generation == evidence.authoritative_handoff_generation
        && evidence.observed_monotonic_ms >= evidence.exclusive_deadline_monotonic_ms
    {
        DispatchDefiniteAbsenceClassificationV1::DefiniteAbsence(DispatchDefiniteAbsenceProofV1 {
            adapter_root: evidence.expected_adapter_root,
            supervisor_epoch: evidence.expected_supervisor_epoch,
            delivery_attempt_id: evidence.expected_delivery_attempt_id,
            readback_generation: evidence.authoritative_handoff_generation,
            exclusive_deadline_monotonic_ms: evidence.exclusive_deadline_monotonic_ms,
        })
    } else {
        DispatchDefiniteAbsenceClassificationV1::PossibleConsumption
    }
}

/// Opaque custody extracted only from an already-authentic signed refusal receipt.
pub struct DispatchNoConsumptionTombstoneCustodyV1 {
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
    refusal_code: ExecutionReceiptRefusalCodeV1,
    no_consumption_tombstone_digest: [u8; 32],
}

impl DispatchNoConsumptionTombstoneCustodyV1 {
    pub const fn receipt_id(&self) -> [u8; 32] {
        self.receipt_id
    }

    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    pub const fn refusal_code(&self) -> ExecutionReceiptRefusalCodeV1 {
        self.refusal_code
    }

    pub const fn no_consumption_tombstone_digest(&self) -> [u8; 32] {
        self.no_consumption_tombstone_digest
    }
}

impl fmt::Debug for DispatchNoConsumptionTombstoneCustodyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchNoConsumptionTombstoneCustodyV1")
            .finish_non_exhaustive()
    }
}

pub fn classify_no_consumption_receipt_v1(
    authentic_receipt: &AuthenticExecutionReceiptV1,
) -> Option<DispatchNoConsumptionTombstoneCustodyV1> {
    let claims = authentic_receipt.claims();
    if claims.decision() != ExecutionReceiptDecisionV1::RefusedDefinite {
        return None;
    }
    let refusal_code = claims.refusal_code()?;
    if !matches!(
        refusal_code,
        ExecutionReceiptRefusalCodeV1::GrantExpired
            | ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch
            | ExecutionReceiptRefusalCodeV1::AdapterPaused
    ) {
        return None;
    }
    let tombstone = claims.no_consumption_tombstone_digest()?;
    Some(DispatchNoConsumptionTombstoneCustodyV1 {
        receipt_id: *claims.receipt_id().as_bytes(),
        receipt_digest: *claims.receipt_digest().as_bytes(),
        refusal_code,
        no_consumption_tombstone_digest: *tombstone.as_bytes(),
    })
}

/// Pre-`RECEIVED` failures remain diagnostics and can never be promoted to a receipt,
/// tombstone, definite absence, or reservation-release proof.
pub const fn pre_receive_diagnostic_requires_reconciliation_v1(
    _diagnostic: DispatchPreReceiveRefusalV1,
) -> DispatchDefiniteAbsenceClassificationV1 {
    DispatchDefiniteAbsenceClassificationV1::PossibleConsumption
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_input() -> DispatchDefiniteAbsenceEvidenceInputV1 {
        DispatchDefiniteAbsenceEvidenceInputV1 {
            transport_fenced: true,
            transport_quiesced: true,
            adapter_healthy: true,
            expected_adapter_root: [1; 32],
            observed_adapter_root: [1; 32],
            expected_supervisor_epoch: 7,
            observed_supervisor_epoch: 7,
            expected_delivery_attempt_id: [2; 32],
            observed_delivery_attempt_id: [2; 32],
            authoritative_handoff_generation: 11,
            observed_readback_generation: 11,
            exclusive_deadline_monotonic_ms: 5_000,
            observed_monotonic_ms: 5_000,
        }
    }

    fn exact() -> DispatchDefiniteAbsenceEvidenceV1 {
        DispatchDefiniteAbsenceEvidenceV1::try_new(exact_input()).unwrap()
    }

    #[test]
    fn exact_fenced_evidence_closes_only_at_or_after_the_exclusive_deadline() {
        let DispatchDefiniteAbsenceClassificationV1::DefiniteAbsence(proof) =
            classify_definite_absence_v1(exact())
        else {
            panic!("exact evidence must prove definite absence");
        };
        assert_eq!(proof.adapter_root(), [1; 32]);
        assert_eq!(proof.supervisor_epoch(), 7);
        assert_eq!(proof.delivery_attempt_id(), [2; 32]);
        assert_eq!(proof.readback_generation(), 11);
        assert_eq!(proof.exclusive_deadline_monotonic_ms(), 5_000);

        let early =
            DispatchDefiniteAbsenceEvidenceV1::try_new(DispatchDefiniteAbsenceEvidenceInputV1 {
                observed_monotonic_ms: 4_999,
                ..exact_input()
            })
            .unwrap();
        assert!(matches!(
            classify_definite_absence_v1(early),
            DispatchDefiniteAbsenceClassificationV1::PossibleConsumption
        ));
    }

    #[test]
    fn removing_any_required_binding_from_the_production_classifier_fails_closed() {
        let mutations = [
            DispatchDefiniteAbsenceEvidenceInputV1 {
                transport_fenced: false,
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                transport_quiesced: false,
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                adapter_healthy: false,
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                observed_adapter_root: [3; 32],
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                observed_supervisor_epoch: 8,
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                observed_delivery_attempt_id: [4; 32],
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                observed_readback_generation: 10,
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                observed_readback_generation: 12,
                ..exact_input()
            },
            DispatchDefiniteAbsenceEvidenceInputV1 {
                observed_monotonic_ms: 4_999,
                ..exact_input()
            },
        ];

        for (index, mutation) in mutations.into_iter().enumerate() {
            let evidence = DispatchDefiniteAbsenceEvidenceV1::try_new(mutation).unwrap();
            assert!(
                matches!(
                    classify_definite_absence_v1(evidence),
                    DispatchDefiniteAbsenceClassificationV1::PossibleConsumption
                ),
                "absence mutation {index} must remain possible consumption"
            );
        }
    }

    #[test]
    fn every_pre_receive_diagnostic_retains_possible_consumption_custody() {
        for diagnostic in [
            DispatchPreReceiveRefusalV1::DestinationMismatch,
            DispatchPreReceiveRefusalV1::ProtocolUnsupported,
            DispatchPreReceiveRefusalV1::CapabilityMismatch,
            DispatchPreReceiveRefusalV1::InboxCapacityExhausted,
        ] {
            assert!(matches!(
                pre_receive_diagnostic_requires_reconciliation_v1(diagnostic),
                DispatchDefiniteAbsenceClassificationV1::PossibleConsumption
            ));
        }
    }
}
