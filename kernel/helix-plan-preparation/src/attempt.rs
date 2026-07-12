//! Fresh preparation-attempt identity boundary.
//!
//! Attempt identities are portable, opaque, domain-separated values created before
//! recovery publication. They are neither credentials nor retry permissions, and this
//! module must not expose their restricted bytes through diagnostics.

#![allow(dead_code)]

use helix_contracts::Sha256Digest;
use std::fmt;

const ATTEMPT_ID_DOMAIN: &[u8] = b"HELIXOS\0PLAN-PREPARATION-ATTEMPT\0V1\0";
const ATTEMPT_ID_PREIMAGE_CAPACITY: usize = 96;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PreparationAttemptIdGenerationErrorV1 {
    RandomUnavailable,
}

/// Fresh opaque identity for exactly one preparation attempt.
///
/// Construction remains crate-private so callers cannot select an idempotency key or
/// retry identity. The value is not a credential, but its bytes are restricted and its
/// diagnostic surface is always redacted.
#[derive(PartialEq, Eq, Hash)]
pub struct PreparationAttemptIdV1 {
    digest: Sha256Digest,
}

impl PreparationAttemptIdV1 {
    pub(crate) fn generate() -> Result<Self, PreparationAttemptIdGenerationErrorV1> {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random)
            .map_err(|_| PreparationAttemptIdGenerationErrorV1::RandomUnavailable)?;

        let mut preimage = [0_u8; ATTEMPT_ID_PREIMAGE_CAPACITY];
        let random_start = ATTEMPT_ID_DOMAIN.len();
        let preimage_len = random_start + random.len();
        debug_assert!(preimage_len <= preimage.len());
        preimage[..random_start].copy_from_slice(ATTEMPT_ID_DOMAIN);
        preimage[random_start..preimage_len].copy_from_slice(&random);
        let digest = Sha256Digest::digest(&preimage[..preimage_len]);

        random.fill(0);
        preimage.fill(0);
        Ok(Self { digest })
    }

    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }
}

impl fmt::Debug for PreparationAttemptIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparationAttemptIdV1")
            .finish_non_exhaustive()
    }
}
