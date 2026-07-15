//! Injected adapter clock and exclusive-deadline boundary.
//!
//! Implementations must capture UTC and boot-monotonic values in one synchronous
//! call. This module deliberately provides no ambient clock implementation.

#![allow(dead_code)]

use helix_dispatch_contracts::{Generation, Identifier, SafeU64};
use std::fmt;

/// One coherent, boot-bound time observation supplied by trusted adapter wiring.
#[derive(PartialEq, Eq)]
pub struct AdapterTimeSampleV1 {
    boot_id: Identifier,
    clock_generation: Generation,
    sampled_at_utc_ms: SafeU64,
    sampled_at_monotonic_ms: SafeU64,
}

impl AdapterTimeSampleV1 {
    pub const fn new(
        boot_id: Identifier,
        clock_generation: Generation,
        sampled_at_utc_ms: SafeU64,
        sampled_at_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            boot_id,
            clock_generation,
            sampled_at_utc_ms,
            sampled_at_monotonic_ms,
        }
    }

    pub fn boot_id(&self) -> &str {
        self.boot_id.as_str()
    }

    pub const fn clock_generation(&self) -> u64 {
        self.clock_generation.get()
    }

    pub const fn sampled_at_utc_ms(&self) -> u64 {
        self.sampled_at_utc_ms.get()
    }

    pub const fn sampled_at_monotonic_ms(&self) -> u64 {
        self.sampled_at_monotonic_ms.get()
    }

    pub(crate) const fn clock_generation_value(&self) -> Generation {
        self.clock_generation
    }

    pub(crate) const fn sampled_at_utc_value(&self) -> SafeU64 {
        self.sampled_at_utc_ms
    }

    pub(crate) const fn sampled_at_monotonic_value(&self) -> SafeU64 {
        self.sampled_at_monotonic_ms
    }

    /// Both values must remain non-regressing inside one boot domain.
    pub(crate) fn is_coherent_successor_of(&self, prior: &Self) -> bool {
        self.boot_id == prior.boot_id
            && self.clock_generation.get() >= prior.clock_generation.get()
            && self.sampled_at_utc_ms.get() >= prior.sampled_at_utc_ms.get()
            && self.sampled_at_monotonic_ms.get() >= prior.sampled_at_monotonic_ms.get()
    }
}

impl fmt::Debug for AdapterTimeSampleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterTimeSampleV1")
            .finish_non_exhaustive()
    }
}

/// Closed result of one injected, atomic clock observation.
pub enum AdapterClockObservationV1 {
    Current(AdapterTimeSampleV1),
    Unavailable,
    Unreadable,
    Stale,
}

impl fmt::Debug for AdapterClockObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current(_) => formatter.write_str("AdapterClockObservationV1::Current(..)"),
            Self::Unavailable => formatter.write_str("AdapterClockObservationV1::Unavailable"),
            Self::Unreadable => formatter.write_str("AdapterClockObservationV1::Unreadable"),
            Self::Stale => formatter.write_str("AdapterClockObservationV1::Stale"),
        }
    }
}

/// Trusted synchronous clock seam; no system clock is consulted by this crate.
pub trait AdapterClockV1: Send + Sync {
    fn observe_time_v1(&self) -> AdapterClockObservationV1;
}

/// Positive safe-integer exclusive deadline bound to one monotonic boot domain.
#[derive(PartialEq, Eq)]
pub(crate) struct AdapterDeadlineV1 {
    boot_id: Identifier,
    deadline_monotonic_ms: Generation,
}

impl AdapterDeadlineV1 {
    pub(crate) const fn new(boot_id: Identifier, deadline_monotonic_ms: Generation) -> Self {
        Self {
            boot_id,
            deadline_monotonic_ms,
        }
    }

    pub(crate) fn boot_id(&self) -> &str {
        self.boot_id.as_str()
    }

    pub(crate) const fn deadline_monotonic_ms(&self) -> u64 {
        self.deadline_monotonic_ms.get()
    }
}

impl fmt::Debug for AdapterDeadlineV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterDeadlineV1")
            .finish_non_exhaustive()
    }
}

/// A current time sample with a strictly positive remaining duration.
pub(crate) struct CurrentAdapterDeadlineV1 {
    sample: AdapterTimeSampleV1,
    remaining_monotonic_ms: u64,
}

impl CurrentAdapterDeadlineV1 {
    pub(crate) const fn sample(&self) -> &AdapterTimeSampleV1 {
        &self.sample
    }

    pub(crate) const fn remaining_monotonic_ms(&self) -> u64 {
        self.remaining_monotonic_ms
    }
}

impl fmt::Debug for CurrentAdapterDeadlineV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CurrentAdapterDeadlineV1")
            .finish_non_exhaustive()
    }
}

/// Closed deadline result. Equality is `Reached` because v1 deadlines are exclusive.
pub(crate) enum AdapterDeadlineOutcomeV1 {
    Current(CurrentAdapterDeadlineV1),
    Reached,
    Unavailable,
    Unreadable,
    Stale,
}

impl fmt::Debug for AdapterDeadlineOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current(_) => formatter.write_str("AdapterDeadlineOutcomeV1::Current(..)"),
            Self::Reached => formatter.write_str("AdapterDeadlineOutcomeV1::Reached"),
            Self::Unavailable => formatter.write_str("AdapterDeadlineOutcomeV1::Unavailable"),
            Self::Unreadable => formatter.write_str("AdapterDeadlineOutcomeV1::Unreadable"),
            Self::Stale => formatter.write_str("AdapterDeadlineOutcomeV1::Stale"),
        }
    }
}

pub(crate) fn observe_deadline_v1<C: AdapterClockV1 + ?Sized>(
    clock: &C,
    deadline: &AdapterDeadlineV1,
) -> AdapterDeadlineOutcomeV1 {
    match clock.observe_time_v1() {
        AdapterClockObservationV1::Unavailable => AdapterDeadlineOutcomeV1::Unavailable,
        AdapterClockObservationV1::Unreadable => AdapterDeadlineOutcomeV1::Unreadable,
        AdapterClockObservationV1::Stale => AdapterDeadlineOutcomeV1::Stale,
        AdapterClockObservationV1::Current(sample) if sample.boot_id() != deadline.boot_id() => {
            AdapterDeadlineOutcomeV1::Stale
        }
        AdapterClockObservationV1::Current(sample) => {
            let Some(remaining_monotonic_ms) = deadline
                .deadline_monotonic_ms()
                .checked_sub(sample.sampled_at_monotonic_ms())
                .filter(|remaining| *remaining > 0)
            else {
                return AdapterDeadlineOutcomeV1::Reached;
            };
            AdapterDeadlineOutcomeV1::Current(CurrentAdapterDeadlineV1 {
                sample,
                remaining_monotonic_ms,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct ScriptedClockV1(Mutex<VecDeque<AdapterClockObservationV1>>);

    impl ScriptedClockV1 {
        fn new(observations: impl IntoIterator<Item = AdapterClockObservationV1>) -> Self {
            Self(Mutex::new(observations.into_iter().collect()))
        }
    }

    impl AdapterClockV1 for ScriptedClockV1 {
        fn observe_time_v1(&self) -> AdapterClockObservationV1 {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .expect("scripted T046 clock observation exists")
        }
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).expect("T046 identifier is valid")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("T046 generation is valid")
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("T046 safe integer is valid")
    }

    fn sample(boot_id: &str, utc_ms: u64, monotonic_ms: u64) -> AdapterTimeSampleV1 {
        AdapterTimeSampleV1::new(
            identifier(boot_id),
            generation(7),
            safe(utc_ms),
            safe(monotonic_ms),
        )
    }

    fn deadline() -> AdapterDeadlineV1 {
        AdapterDeadlineV1::new(identifier("boot-t046"), generation(1_250))
    }

    #[test]
    fn exclusive_deadline_accepts_before_and_refuses_equality_or_later() {
        let before = ScriptedClockV1::new([AdapterClockObservationV1::Current(sample(
            "boot-t046",
            10_000,
            1_249,
        ))]);
        let AdapterDeadlineOutcomeV1::Current(current) = observe_deadline_v1(&before, &deadline())
        else {
            panic!("T046 one millisecond before deadline must remain current");
        };
        assert_eq!(current.remaining_monotonic_ms(), 1);

        for now in [1_250, 1_251] {
            let clock = ScriptedClockV1::new([AdapterClockObservationV1::Current(sample(
                "boot-t046",
                10_000,
                now,
            ))]);
            assert!(matches!(
                observe_deadline_v1(&clock, &deadline()),
                AdapterDeadlineOutcomeV1::Reached
            ));
        }
    }

    #[test]
    fn unavailable_unreadable_stale_and_wrong_boot_fail_closed() {
        let cases = [
            AdapterClockObservationV1::Unavailable,
            AdapterClockObservationV1::Unreadable,
            AdapterClockObservationV1::Stale,
        ];
        for case in cases {
            let clock = ScriptedClockV1::new([case]);
            assert!(!matches!(
                observe_deadline_v1(&clock, &deadline()),
                AdapterDeadlineOutcomeV1::Current(_)
            ));
        }

        let wrong_boot = ScriptedClockV1::new([AdapterClockObservationV1::Current(sample(
            "boot-other",
            10_000,
            1_000,
        ))]);
        assert!(matches!(
            observe_deadline_v1(&wrong_boot, &deadline()),
            AdapterDeadlineOutcomeV1::Stale
        ));
    }

    #[test]
    fn coherent_successor_requires_nonregression_in_one_boot() {
        let first = sample("boot-t046", 10_000, 1_000);
        let later = sample("boot-t046", 10_001, 1_001);
        let utc_regression = sample("boot-t046", 9_999, 1_001);
        let monotonic_regression = sample("boot-t046", 10_001, 999);
        let new_boot = sample("boot-other", 10_001, 1_001);

        assert!(later.is_coherent_successor_of(&first));
        assert!(!utc_regression.is_coherent_successor_of(&first));
        assert!(!monotonic_regression.is_coherent_successor_of(&first));
        assert!(!new_boot.is_coherent_successor_of(&first));
    }
}
