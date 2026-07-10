use crate::context::{safe, validate_identifier};
use crate::EligibilityContextBuildErrorV1;
use helix_contracts::{Nonce128, SafeU64, Sha256Digest};
use std::fmt;

const REPLAY_BINDING_DOMAIN: &[u8] = b"HELIXOS\0PLAN-ELIGIBILITY-REPLAY-BINDING\0V1\0";
const MAX_BINDING_BYTES: usize = 768;

pub(crate) struct ReplayBindingInputV1<'plan> {
    pub(crate) instance_epoch: u64,
    pub(crate) nonce: Nonce128,
    pub(crate) key_id: &'plan str,
    pub(crate) verified_key_fingerprint: Sha256Digest,
    pub(crate) plan_id: Sha256Digest,
    pub(crate) operation_id: &'plan str,
    pub(crate) task_id: &'plan str,
    pub(crate) workload_id: &'plan str,
    pub(crate) task_lease_digest: Sha256Digest,
    pub(crate) trust_generation: u64,
    pub(crate) fencing_epoch: u64,
    pub(crate) claim_deadline_monotonic_ms: u64,
}

impl fmt::Debug for ReplayBindingInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayBindingInputV1")
            .finish_non_exhaustive()
    }
}

/// Borrowed, redacted request for the permanent replay linearization point.
///
/// Uniqueness is keyed by `(instance_epoch, nonce)` plus an operation index. All other
/// fields are compared evidence and contribute to the domain-separated binding digest.
pub struct ReplayBindingV1<'plan> {
    instance_epoch: SafeU64,
    nonce: Nonce128,
    key_id: &'plan str,
    verified_key_fingerprint: Sha256Digest,
    plan_id: Sha256Digest,
    operation_id: &'plan str,
    task_id: &'plan str,
    workload_id: &'plan str,
    task_lease_digest: Sha256Digest,
    trust_generation: SafeU64,
    fencing_epoch: SafeU64,
    claim_deadline_monotonic_ms: SafeU64,
    binding_digest: Sha256Digest,
}

impl<'plan> ReplayBindingV1<'plan> {
    pub(crate) fn try_new(
        input: ReplayBindingInputV1<'plan>,
    ) -> Result<Self, EligibilityContextBuildErrorV1> {
        validate_identifier(input.key_id)?;
        validate_identifier(input.operation_id)?;
        validate_identifier(input.task_id)?;
        validate_identifier(input.workload_id)?;

        let instance_epoch = safe(input.instance_epoch)?;
        let trust_generation = safe(input.trust_generation)?;
        let fencing_epoch = safe(input.fencing_epoch)?;
        let claim_deadline_monotonic_ms = safe(input.claim_deadline_monotonic_ms)?;

        let mut binding = Self {
            instance_epoch,
            nonce: input.nonce,
            key_id: input.key_id,
            verified_key_fingerprint: input.verified_key_fingerprint,
            plan_id: input.plan_id,
            operation_id: input.operation_id,
            task_id: input.task_id,
            workload_id: input.workload_id,
            task_lease_digest: input.task_lease_digest,
            trust_generation,
            fencing_epoch,
            claim_deadline_monotonic_ms,
            binding_digest: Sha256Digest::from_bytes([0; 32]),
        };
        binding.binding_digest = binding.compute_binding_digest();
        Ok(binding)
    }

    pub const fn nonce_key(&self) -> (u64, Nonce128) {
        (self.instance_epoch.get(), self.nonce)
    }

    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch.get()
    }
    pub const fn nonce(&self) -> Nonce128 {
        self.nonce
    }
    pub const fn key_id(&self) -> &str {
        self.key_id
    }
    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.verified_key_fingerprint
    }
    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }
    pub const fn operation_id(&self) -> &str {
        self.operation_id
    }
    pub const fn task_id(&self) -> &str {
        self.task_id
    }
    pub const fn workload_id(&self) -> &str {
        self.workload_id
    }
    pub const fn task_lease_digest(&self) -> Sha256Digest {
        self.task_lease_digest
    }
    pub const fn trust_generation(&self) -> u64 {
        self.trust_generation.get()
    }
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch.get()
    }
    /// Exclusive absolute deadline in the caller's trusted suspend-aware boot clock.
    ///
    /// This scalar is not a duration and must be interpreted in the same clock domain
    /// that produced the eligibility context. See [`ReplayClaimantV1`] for the bounded
    /// wait, commit and late-result requirements.
    pub const fn claim_deadline_monotonic_ms(&self) -> u64 {
        self.claim_deadline_monotonic_ms.get()
    }
    pub const fn binding_digest(&self) -> Sha256Digest {
        self.binding_digest
    }

    fn compute_binding_digest(&self) -> Sha256Digest {
        let mut bytes = [0_u8; MAX_BINDING_BYTES];
        let mut length = 0_usize;
        append(&mut bytes, &mut length, REPLAY_BINDING_DOMAIN);
        append_u64(&mut bytes, &mut length, self.instance_epoch.get());
        append(&mut bytes, &mut length, self.nonce.as_bytes());
        append_string(&mut bytes, &mut length, self.key_id);
        append(
            &mut bytes,
            &mut length,
            self.verified_key_fingerprint.as_bytes(),
        );
        append(&mut bytes, &mut length, self.plan_id.as_bytes());
        append_string(&mut bytes, &mut length, self.operation_id);
        append_string(&mut bytes, &mut length, self.task_id);
        append_string(&mut bytes, &mut length, self.workload_id);
        append(&mut bytes, &mut length, self.task_lease_digest.as_bytes());
        append_u64(&mut bytes, &mut length, self.trust_generation.get());
        append_u64(&mut bytes, &mut length, self.fencing_epoch.get());
        append_u64(
            &mut bytes,
            &mut length,
            self.claim_deadline_monotonic_ms.get(),
        );
        Sha256Digest::digest(&bytes[..length])
    }
}

impl fmt::Debug for ReplayBindingV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayBindingV1")
            .finish_non_exhaustive()
    }
}

/// Opaque receipt returned for a newly committed replay claim.
pub struct ReplayClaimReceiptV1 {
    claim_id: Sha256Digest,
    claimant_generation: SafeU64,
    binding_digest: Sha256Digest,
}

impl ReplayClaimReceiptV1 {
    pub fn try_new(
        claim_id: Sha256Digest,
        claimant_generation: u64,
        binding_digest: Sha256Digest,
    ) -> Result<Self, EligibilityContextBuildErrorV1> {
        Ok(Self {
            claim_id,
            claimant_generation: safe(claimant_generation)?,
            binding_digest,
        })
    }

    pub const fn claim_id(&self) -> Sha256Digest {
        self.claim_id
    }
    pub const fn claimant_generation(&self) -> u64 {
        self.claimant_generation.get()
    }
    pub(crate) const fn claimant_generation_safe(&self) -> SafeU64 {
        self.claimant_generation
    }
    pub const fn binding_digest(&self) -> Sha256Digest {
        self.binding_digest
    }
}

impl fmt::Debug for ReplayClaimReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayClaimReceiptV1")
            .finish_non_exhaustive()
    }
}

/// Closed outcome of one replay claim attempt; ambiguous outcomes are never retried.
pub enum ReplayClaimOutcomeV1 {
    Claimed(ReplayClaimReceiptV1),
    AlreadyClaimed,
    BindingConflict,
    Unavailable,
    Ambiguous,
}

impl fmt::Debug for ReplayClaimOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Claimed(_) => "Claimed",
            Self::AlreadyClaimed => "AlreadyClaimed",
            Self::BindingConflict => "BindingConflict",
            Self::Unavailable => "Unavailable",
            Self::Ambiguous => "Ambiguous",
        };
        write!(formatter, "ReplayClaimOutcomeV1::{variant}")
    }
}

/// Caller-owned atomic replay claimant.
///
/// A production implementation must durably and atomically maintain both uniqueness
/// indexes and permanently retain successful claims. It must interpret the binding's
/// exclusive deadline in the same trusted suspend-aware boot-clock domain used by the
/// caller, perform no mutation when that deadline is already reached, bound intentional
/// lock/wait time by the remaining budget, and recheck after acquiring mutation authority
/// and immediately before and after commit or definitive readback. It must return no
/// positive outcome at or after the deadline and leave no detached retry after return.
///
/// The synchronous trait does not promise portable hard cancellation of an operating-
/// system storage flush already in progress. If a mutation may have committed and the
/// call completes late or cannot obtain a timely definitive readback, the outcome is
/// [`ReplayClaimOutcomeV1::Ambiguous`], not `Unavailable`; only a definite pre-mutation
/// failure or confirmed rollback is unavailable. The in-repository claimant is test-only
/// and does not establish those production durability or timing properties.
pub trait ReplayClaimantV1: Send + Sync {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1;
}

fn append(destination: &mut [u8; MAX_BINDING_BYTES], length: &mut usize, value: &[u8]) {
    let end = *length + value.len();
    debug_assert!(end <= destination.len());
    destination[*length..end].copy_from_slice(value);
    *length = end;
}

fn append_u64(destination: &mut [u8; MAX_BINDING_BYTES], length: &mut usize, value: u64) {
    append(destination, length, &value.to_be_bytes());
}

fn append_string(destination: &mut [u8; MAX_BINDING_BYTES], length: &mut usize, value: &str) {
    let string_length = u16::try_from(value.len()).expect("validated v1 identifiers fit u16");
    append(destination, length, &string_length.to_be_bytes());
    append(destination, length, value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_uses_instance_nonce_namespace_and_all_compared_evidence() {
        let input = ReplayBindingInputV1 {
            instance_epoch: 7,
            nonce: Nonce128::from_bytes([0x11; 16]),
            key_id: "key-1",
            verified_key_fingerprint: Sha256Digest::digest(b"key"),
            plan_id: Sha256Digest::digest(b"plan"),
            operation_id: "operation-1",
            task_id: "task-1",
            workload_id: "workload-1",
            task_lease_digest: Sha256Digest::digest(b"lease"),
            trust_generation: 8,
            fencing_epoch: 9,
            claim_deadline_monotonic_ms: 10,
        };
        let binding = ReplayBindingV1::try_new(input).expect("valid binding");
        assert_eq!(binding.nonce_key(), (7, Nonce128::from_bytes([0x11; 16])));
        assert_ne!(binding.binding_digest(), Sha256Digest::from_bytes([0; 32]));
        assert_eq!(format!("{binding:?}"), "ReplayBindingV1 { .. }");
    }
}
