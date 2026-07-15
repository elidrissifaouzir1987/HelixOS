//! Bounded untrusted dispatch lookup input.

use std::fmt;

pub const DISPATCH_LOOKUP_CONTRACT_VERSION_V1: u16 = 1;
pub(crate) const DISPATCH_MAX_SAFE_INTEGER_V1: u64 = 9_007_199_254_740_991;
const MAX_OPERATION_ID_BYTES_V1: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchLookupRequestBuildErrorV1 {
    VersionUnsupported,
    OperationIdInvalid,
    IntegerOutOfRange,
    TransitionGenerationZero,
    DeadlineZero,
}

pub struct DispatchLookupRequestInputV1<'input> {
    pub contract_version: u16,
    pub operation_id: &'input str,
    pub expected_plan_digest: [u8; 32],
    pub expected_preparation_attempt_digest: [u8; 32],
    pub expected_preparation_transition_generation: u64,
    pub caller_deadline_monotonic_ms: u64,
}

impl fmt::Debug for DispatchLookupRequestInputV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchLookupRequestInputV1")
            .finish_non_exhaustive()
    }
}

/// Lookup-only input. Validation establishes syntax, never positive authority.
pub struct DispatchLookupRequestV1 {
    contract_version: u16,
    operation_id: Box<str>,
    expected_plan_digest: [u8; 32],
    expected_preparation_attempt_digest: [u8; 32],
    expected_preparation_transition_generation: u64,
    caller_deadline_monotonic_ms: u64,
}

impl DispatchLookupRequestV1 {
    pub fn try_new(
        input: DispatchLookupRequestInputV1<'_>,
    ) -> Result<Self, DispatchLookupRequestBuildErrorV1> {
        if input.contract_version != DISPATCH_LOOKUP_CONTRACT_VERSION_V1 {
            return Err(DispatchLookupRequestBuildErrorV1::VersionUnsupported);
        }
        if !valid_identifier(input.operation_id) {
            return Err(DispatchLookupRequestBuildErrorV1::OperationIdInvalid);
        }
        require_safe(input.expected_preparation_transition_generation)?;
        require_safe(input.caller_deadline_monotonic_ms)?;
        if input.expected_preparation_transition_generation == 0 {
            return Err(DispatchLookupRequestBuildErrorV1::TransitionGenerationZero);
        }
        if input.caller_deadline_monotonic_ms == 0 {
            return Err(DispatchLookupRequestBuildErrorV1::DeadlineZero);
        }
        Ok(Self {
            contract_version: input.contract_version,
            operation_id: Box::from(input.operation_id),
            expected_plan_digest: input.expected_plan_digest,
            expected_preparation_attempt_digest: input.expected_preparation_attempt_digest,
            expected_preparation_transition_generation: input
                .expected_preparation_transition_generation,
            caller_deadline_monotonic_ms: input.caller_deadline_monotonic_ms,
        })
    }

    pub const fn contract_version(&self) -> u16 {
        self.contract_version
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn expected_plan_digest(&self) -> &[u8; 32] {
        &self.expected_plan_digest
    }

    pub const fn expected_preparation_attempt_digest(&self) -> &[u8; 32] {
        &self.expected_preparation_attempt_digest
    }

    pub const fn expected_preparation_transition_generation(&self) -> u64 {
        self.expected_preparation_transition_generation
    }

    pub const fn caller_deadline_monotonic_ms(&self) -> u64 {
        self.caller_deadline_monotonic_ms
    }
}

impl fmt::Debug for DispatchLookupRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchLookupRequestV1")
            .finish_non_exhaustive()
    }
}

pub(crate) fn require_safe(value: u64) -> Result<(), DispatchLookupRequestBuildErrorV1> {
    if value > DISPATCH_MAX_SAFE_INTEGER_V1 {
        return Err(DispatchLookupRequestBuildErrorV1::IntegerOutOfRange);
    }
    Ok(())
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES_V1
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> DispatchLookupRequestInputV1<'static> {
        DispatchLookupRequestInputV1 {
            contract_version: DISPATCH_LOOKUP_CONTRACT_VERSION_V1,
            operation_id: "operation:one",
            expected_plan_digest: [1; 32],
            expected_preparation_attempt_digest: [2; 32],
            expected_preparation_transition_generation: 1,
            caller_deadline_monotonic_ms: 2,
        }
    }

    #[test]
    fn lookup_accepts_only_bounded_non_authoritative_bindings() {
        let request = DispatchLookupRequestV1::try_new(valid_input()).expect("valid lookup");
        assert_eq!(request.contract_version(), 1);
        assert_eq!(request.operation_id(), "operation:one");
        assert_eq!(request.expected_plan_digest(), &[1; 32]);
        assert_eq!(request.expected_preparation_attempt_digest(), &[2; 32]);
        assert_eq!(request.expected_preparation_transition_generation(), 1);
        assert_eq!(request.caller_deadline_monotonic_ms(), 2);
    }

    #[test]
    fn lookup_rejects_invalid_version_identifier_generation_and_deadline() {
        let mut input = valid_input();
        input.contract_version = 2;
        assert_eq!(
            DispatchLookupRequestV1::try_new(input).expect_err("v2 is closed"),
            DispatchLookupRequestBuildErrorV1::VersionUnsupported
        );

        let mut input = valid_input();
        input.operation_id = "native/path";
        assert_eq!(
            DispatchLookupRequestV1::try_new(input).expect_err("identifier is portable"),
            DispatchLookupRequestBuildErrorV1::OperationIdInvalid
        );

        let mut input = valid_input();
        input.expected_preparation_transition_generation = 0;
        assert_eq!(
            DispatchLookupRequestV1::try_new(input).expect_err("generation is nonzero"),
            DispatchLookupRequestBuildErrorV1::TransitionGenerationZero
        );

        let mut input = valid_input();
        input.caller_deadline_monotonic_ms = 0;
        assert_eq!(
            DispatchLookupRequestV1::try_new(input).expect_err("deadline is nonzero"),
            DispatchLookupRequestBuildErrorV1::DeadlineZero
        );

        let mut input = valid_input();
        input.caller_deadline_monotonic_ms = DISPATCH_MAX_SAFE_INTEGER_V1 + 1;
        assert_eq!(
            DispatchLookupRequestV1::try_new(input).expect_err("deadline is I-JSON safe"),
            DispatchLookupRequestBuildErrorV1::IntegerOutOfRange
        );
    }
}
