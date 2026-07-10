use crate::error::{InternalStoreError, ReplayClockUnavailableV1};
use helix_contracts::MAX_SAFE_U64;

/// Caller-owned suspend-aware boot-monotonic clock used by feature 002 deadlines.
///
/// Implementations must use the same scalar origin as the eligibility context that
/// created `claim_deadline_monotonic_ms`; this crate intentionally provides no ambient
/// `Instant` or UTC fallback.
pub trait ReplayMonotonicClockV1: Send + Sync {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1>;
}

pub(crate) fn read_safe_now<C: ReplayMonotonicClockV1>(
    clock: &C,
) -> Result<u64, InternalStoreError> {
    let now = clock
        .now_monotonic_ms()
        .map_err(|_| InternalStoreError::ClockUnavailable)?;
    if now > MAX_SAFE_U64 {
        return Err(InternalStoreError::ClockUnavailable);
    }
    Ok(now)
}

pub(crate) fn remaining_monotonic_ms<C: ReplayMonotonicClockV1>(
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<u64, InternalStoreError> {
    if deadline_monotonic_ms > MAX_SAFE_U64 {
        return Err(InternalStoreError::DeadlineReached);
    }
    let now = read_safe_now(clock)?;
    deadline_monotonic_ms
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(InternalStoreError::DeadlineReached)
}
