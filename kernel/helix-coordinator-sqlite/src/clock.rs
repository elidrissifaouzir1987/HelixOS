//! Private injected-clock adapter boundary.

#![allow(dead_code)]

use crate::error::{CoordinatorClockUnavailableV1, InternalCoordinatorError};
use helix_contracts::MAX_SAFE_U64;

/// Caller-owned suspend-aware boot-monotonic clock.
///
/// Implementations must share the scalar origin of the caller's absolute deadline.
/// This module intentionally provides no ambient time fallback.
pub trait CoordinatorMonotonicClockV1: Send + Sync {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1>;
}

pub(crate) fn read_safe_now<C: CoordinatorMonotonicClockV1 + ?Sized>(
    clock: &C,
) -> Result<u64, InternalCoordinatorError> {
    let now = clock
        .now_monotonic_ms()
        .map_err(|_| InternalCoordinatorError::ClockUnavailable)?;
    if now > MAX_SAFE_U64 {
        return Err(InternalCoordinatorError::ClockUnavailable);
    }
    Ok(now)
}

pub(crate) fn remaining_monotonic_ms<C: CoordinatorMonotonicClockV1 + ?Sized>(
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<u64, InternalCoordinatorError> {
    if deadline_monotonic_ms > MAX_SAFE_U64 {
        return Err(InternalCoordinatorError::DeadlineReached);
    }
    deadline_monotonic_ms
        .checked_sub(read_safe_now(clock)?)
        .filter(|remaining| *remaining > 0)
        .ok_or(InternalCoordinatorError::DeadlineReached)
}
