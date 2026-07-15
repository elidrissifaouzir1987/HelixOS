//! Opaque identity for one coordinator-owned dispatch attempt.

#![allow(dead_code)]

use crate::control::{DispatchEntropyDomainV1, DispatchEntropySourceV1};
use helix_dispatch_contracts::Sha256Digest;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchAttemptIdGenerationErrorV1 {
    EntropyUnavailable,
}

#[derive(PartialEq, Eq, Hash)]
pub struct DispatchAttemptIdV1 {
    bytes: [u8; 32],
}

impl DispatchAttemptIdV1 {
    pub(crate) fn generate(
        entropy: &dyn DispatchEntropySourceV1,
    ) -> Result<Self, DispatchAttemptIdGenerationErrorV1> {
        let mut bytes = [0_u8; 32];
        entropy
            .fill_entropy_v1(DispatchEntropyDomainV1::AttemptIdentity, &mut bytes)
            .map_err(|_| DispatchAttemptIdGenerationErrorV1::EntropyUnavailable)?;
        Ok(Self { bytes })
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub const fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(self.bytes)
    }
}

impl fmt::Debug for DispatchAttemptIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchAttemptIdV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DispatchEntropyErrorV1;

    struct FixedEntropy;

    impl DispatchEntropySourceV1 for FixedEntropy {
        fn fill_entropy_v1(
            &self,
            domain: DispatchEntropyDomainV1,
            destination: &mut [u8],
        ) -> Result<(), DispatchEntropyErrorV1> {
            assert_eq!(domain, DispatchEntropyDomainV1::AttemptIdentity);
            destination.fill(0xa5);
            Ok(())
        }
    }

    #[test]
    fn attempt_identity_requests_only_its_domain_separated_entropy() {
        let attempt = DispatchAttemptIdV1::generate(&FixedEntropy).expect("fixed entropy works");
        assert_eq!(attempt.as_bytes(), &[0xa5; 32]);
    }
}
