//! Deterministic replay claimant shared by integration tests and examples.
//!
//! Include this file from either directory with:
//! `#[path = "../test-support/replay_claimant.rs"] mod replay_claimant;`.
//! It is deliberately outside `src/` and is not part of the production crate.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use helix_contracts::Sha256Digest;
use helix_plan_eligibility::{
    ReplayBindingV1, ReplayClaimOutcomeV1, ReplayClaimReceiptV1, ReplayClaimantV1,
};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

const CLAIM_ID_DOMAIN: &[u8] = b"HELIXOS\0PLAN-ELIGIBILITY-TEST-CLAIM\0V1\0";
const MAX_SAFE_GENERATION: u64 = 9_007_199_254_740_991;

type NonceKey = (u64, [u8; 16]);

/// Closed fault modes for replay-outcome and receipt-validation tests.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ForcedReplayOutcome {
    AlreadyClaimed,
    BindingConflict,
    Unavailable,
    Ambiguous,
    WrongReceiptBinding,
}

impl fmt::Debug for ForcedReplayOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::AlreadyClaimed => "AlreadyClaimed",
            Self::BindingConflict => "BindingConflict",
            Self::Unavailable => "Unavailable",
            Self::Ambiguous => "Ambiguous",
            Self::WrongReceiptBinding => "WrongReceiptBinding",
        };
        write!(formatter, "ForcedReplayOutcome::{variant}")
    }
}

/// A process-local linearizable model. It is never a production durability claim.
pub struct DeterministicReplayClaimant {
    state: Mutex<ClaimantState>,
    forced_outcome: Option<ForcedReplayOutcome>,
}

struct ClaimantState {
    nonce_bindings: BTreeMap<NonceKey, Sha256Digest>,
    operation_bindings: BTreeMap<String, Sha256Digest>,
    generation: u64,
    call_count: u64,
}

impl DeterministicReplayClaimant {
    /// Constructs the normal deterministic claimant.
    pub fn new() -> Self {
        Self::with_optional_forced_outcome(None)
    }

    /// Constructs a claimant that returns one closed forced outcome mode.
    pub fn with_forced_outcome(outcome: ForcedReplayOutcome) -> Self {
        Self::with_optional_forced_outcome(Some(outcome))
    }

    fn with_optional_forced_outcome(forced_outcome: Option<ForcedReplayOutcome>) -> Self {
        Self {
            state: Mutex::new(ClaimantState {
                nonce_bindings: BTreeMap::new(),
                operation_bindings: BTreeMap::new(),
                generation: 0,
                call_count: 0,
            }),
            forced_outcome,
        }
    }

    /// Returns the number of times `claim_once` was called.
    pub fn call_count(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.call_count,
            Err(poisoned) => poisoned.into_inner().call_count,
        }
    }

    /// Returns the number of bindings that reached a new committed claim.
    pub fn successful_claim_count(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.nonce_bindings.len(),
            Err(poisoned) => poisoned.into_inner().nonce_bindings.len(),
        }
    }

    /// Returns the safe generation assigned to the latest successful claim.
    pub fn claimant_generation(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.generation,
            Err(poisoned) => poisoned.into_inner().generation,
        }
    }
}

impl Default for DeterministicReplayClaimant {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DeterministicReplayClaimant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeterministicReplayClaimant")
            .field("forced_outcome", &self.forced_outcome)
            .finish_non_exhaustive()
    }
}

impl ReplayClaimantV1 for DeterministicReplayClaimant {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1 {
        let Ok(mut state) = self.state.lock() else {
            return ReplayClaimOutcomeV1::Unavailable;
        };
        state.call_count = state.call_count.saturating_add(1);

        if let Some(forced) = terminal_forced_outcome(self.forced_outcome) {
            return forced;
        }

        let nonce_key = (binding.instance_epoch(), *binding.nonce().as_bytes());
        let operation_id = binding.operation_id();
        let binding_digest = binding.binding_digest();
        let nonce_binding = state.nonce_bindings.get(&nonce_key);
        let operation_binding = state.operation_bindings.get(operation_id);

        match (nonce_binding, operation_binding) {
            (None, None) => {}
            (Some(nonce_digest), Some(operation_digest))
                if *nonce_digest == binding_digest && *operation_digest == binding_digest =>
            {
                return ReplayClaimOutcomeV1::AlreadyClaimed;
            }
            _ => return ReplayClaimOutcomeV1::BindingConflict,
        }

        let Some(next_generation) = state.generation.checked_add(1) else {
            return ReplayClaimOutcomeV1::Unavailable;
        };
        if next_generation > MAX_SAFE_GENERATION {
            return ReplayClaimOutcomeV1::Unavailable;
        }

        let receipt_binding_digest =
            if self.forced_outcome == Some(ForcedReplayOutcome::WrongReceiptBinding) {
                different_digest(binding_digest)
            } else {
                binding_digest
            };
        let claim_id = deterministic_claim_id(binding_digest, next_generation);
        let Ok(receipt) =
            ReplayClaimReceiptV1::try_new(claim_id, next_generation, receipt_binding_digest)
        else {
            return ReplayClaimOutcomeV1::Unavailable;
        };

        state.nonce_bindings.insert(nonce_key, binding_digest);
        state
            .operation_bindings
            .insert(operation_id.to_owned(), binding_digest);
        state.generation = next_generation;

        ReplayClaimOutcomeV1::Claimed(receipt)
    }
}

fn terminal_forced_outcome(
    forced_outcome: Option<ForcedReplayOutcome>,
) -> Option<ReplayClaimOutcomeV1> {
    match forced_outcome {
        Some(ForcedReplayOutcome::AlreadyClaimed) => Some(ReplayClaimOutcomeV1::AlreadyClaimed),
        Some(ForcedReplayOutcome::BindingConflict) => Some(ReplayClaimOutcomeV1::BindingConflict),
        Some(ForcedReplayOutcome::Unavailable) => Some(ReplayClaimOutcomeV1::Unavailable),
        Some(ForcedReplayOutcome::Ambiguous) => Some(ReplayClaimOutcomeV1::Ambiguous),
        Some(ForcedReplayOutcome::WrongReceiptBinding) | None => None,
    }
}

fn deterministic_claim_id(binding_digest: Sha256Digest, generation: u64) -> Sha256Digest {
    let mut material = [0_u8; 96];
    let domain_end = CLAIM_ID_DOMAIN.len();
    material[..domain_end].copy_from_slice(CLAIM_ID_DOMAIN);
    let digest_end = domain_end + Sha256Digest::BYTE_LEN;
    material[domain_end..digest_end].copy_from_slice(binding_digest.as_bytes());
    let generation_end = digest_end + std::mem::size_of::<u64>();
    material[digest_end..generation_end].copy_from_slice(&generation.to_be_bytes());
    Sha256Digest::digest(&material[..generation_end])
}

fn different_digest(binding_digest: Sha256Digest) -> Sha256Digest {
    let mut bytes = *binding_digest.as_bytes();
    bytes[0] ^= 0x80;
    Sha256Digest::from_bytes(bytes)
}
