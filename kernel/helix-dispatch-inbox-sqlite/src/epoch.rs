//! Independent supervisor-epoch observation and matching boundary.
//!
//! The observer is injected by trusted adapter wiring. Grant-carried fields never
//! implement or substitute for this boundary.

#![allow(dead_code)]

use crate::clock::AdapterTimeSampleV1;
use helix_dispatch_contracts::{Generation, SafeU64};
use std::fmt;

/// One current independent supervisor epoch plus its coherent observation time.
#[derive(PartialEq, Eq)]
pub struct EpochObservationV1 {
    supervisor_epoch: SafeU64,
    observer_generation: Generation,
    time_sample: AdapterTimeSampleV1,
}

impl EpochObservationV1 {
    pub const fn new(
        supervisor_epoch: SafeU64,
        observer_generation: Generation,
        time_sample: AdapterTimeSampleV1,
    ) -> Self {
        Self {
            supervisor_epoch,
            observer_generation,
            time_sample,
        }
    }

    pub fn boot_id(&self) -> &str {
        self.time_sample.boot_id()
    }

    pub const fn supervisor_epoch(&self) -> u64 {
        self.supervisor_epoch.get()
    }

    pub const fn observer_generation(&self) -> u64 {
        self.observer_generation.get()
    }

    pub const fn observed_at_utc_ms(&self) -> u64 {
        self.time_sample.sampled_at_utc_ms()
    }

    pub const fn observed_at_monotonic_ms(&self) -> u64 {
        self.time_sample.sampled_at_monotonic_ms()
    }

    pub const fn clock_generation(&self) -> u64 {
        self.time_sample.clock_generation()
    }

    pub const fn time_sample(&self) -> &AdapterTimeSampleV1 {
        &self.time_sample
    }

    pub(crate) const fn observer_generation_value(&self) -> Generation {
        self.observer_generation
    }
}

impl fmt::Debug for EpochObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpochObservationV1")
            .finish_non_exhaustive()
    }
}

/// Closed result of one independent supervisor-owned observation.
pub enum SupervisorEpochObservationV1 {
    Current(EpochObservationV1),
    Unavailable,
    Unreadable,
    Stale,
}

impl fmt::Debug for SupervisorEpochObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current(_) => formatter.write_str("SupervisorEpochObservationV1::Current(..)"),
            Self::Unavailable => formatter.write_str("SupervisorEpochObservationV1::Unavailable"),
            Self::Unreadable => formatter.write_str("SupervisorEpochObservationV1::Unreadable"),
            Self::Stale => formatter.write_str("SupervisorEpochObservationV1::Stale"),
        }
    }
}

/// Trusted synchronous observer. It is independent of grant and transport input.
pub trait SupervisorEpochObserverV1: Send + Sync {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1;
}

pub(crate) enum EpochValidationOutcomeV1 {
    Current(EpochObservationV1),
    Mismatch(EpochObservationV1),
    Unavailable,
    Unreadable,
    Stale,
}

impl fmt::Debug for EpochValidationOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current(_) => formatter.write_str("EpochValidationOutcomeV1::Current(..)"),
            Self::Mismatch(_) => formatter.write_str("EpochValidationOutcomeV1::Mismatch(..)"),
            Self::Unavailable => formatter.write_str("EpochValidationOutcomeV1::Unavailable"),
            Self::Unreadable => formatter.write_str("EpochValidationOutcomeV1::Unreadable"),
            Self::Stale => formatter.write_str("EpochValidationOutcomeV1::Stale"),
        }
    }
}

pub(crate) fn observe_expected_epoch_v1<O: SupervisorEpochObserverV1 + ?Sized>(
    observer: &O,
    expected_boot_id: &str,
    expected_supervisor_epoch: SafeU64,
    minimum_prior_generation: Option<Generation>,
) -> EpochValidationOutcomeV1 {
    match observer.observe_supervisor_epoch_v1() {
        SupervisorEpochObservationV1::Unavailable => EpochValidationOutcomeV1::Unavailable,
        SupervisorEpochObservationV1::Unreadable => EpochValidationOutcomeV1::Unreadable,
        SupervisorEpochObservationV1::Stale => EpochValidationOutcomeV1::Stale,
        SupervisorEpochObservationV1::Current(observation)
            if minimum_prior_generation
                .is_some_and(|minimum| observation.observer_generation() <= minimum.get()) =>
        {
            EpochValidationOutcomeV1::Stale
        }
        SupervisorEpochObservationV1::Current(observation)
            if observation.boot_id() != expected_boot_id
                || observation.supervisor_epoch() != expected_supervisor_epoch.get() =>
        {
            EpochValidationOutcomeV1::Mismatch(observation)
        }
        SupervisorEpochObservationV1::Current(observation) => {
            EpochValidationOutcomeV1::Current(observation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::AdapterTimeSampleV1;
    use helix_dispatch_contracts::Identifier;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct ScriptedEpochObserverV1(Mutex<VecDeque<SupervisorEpochObservationV1>>);

    impl ScriptedEpochObserverV1 {
        fn new(observations: impl IntoIterator<Item = SupervisorEpochObservationV1>) -> Self {
            Self(Mutex::new(observations.into_iter().collect()))
        }
    }

    impl SupervisorEpochObserverV1 for ScriptedEpochObserverV1 {
        fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .expect("scripted T046 epoch observation exists")
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

    fn current(epoch: u64, observer_generation: u64) -> SupervisorEpochObservationV1 {
        SupervisorEpochObservationV1::Current(EpochObservationV1::new(
            safe(epoch),
            generation(observer_generation),
            AdapterTimeSampleV1::new(
                identifier("boot-t046"),
                generation(3),
                safe(10_000 + observer_generation),
                safe(1_000 + observer_generation),
            ),
        ))
    }

    #[test]
    fn current_requires_exact_boot_epoch_and_a_fresh_generation() {
        let exact = ScriptedEpochObserverV1::new([current(41, 8)]);
        assert!(matches!(
            observe_expected_epoch_v1(&exact, "boot-t046", safe(41), Some(generation(7))),
            EpochValidationOutcomeV1::Current(_)
        ));

        let wrong_epoch = ScriptedEpochObserverV1::new([current(42, 8)]);
        assert!(matches!(
            observe_expected_epoch_v1(&wrong_epoch, "boot-t046", safe(41), Some(generation(7))),
            EpochValidationOutcomeV1::Mismatch(_)
        ));

        let same_generation = ScriptedEpochObserverV1::new([current(41, 7)]);
        assert!(matches!(
            observe_expected_epoch_v1(&same_generation, "boot-t046", safe(41), Some(generation(7))),
            EpochValidationOutcomeV1::Stale
        ));
    }

    #[test]
    fn closed_observer_failures_never_become_current() {
        for outcome in [
            SupervisorEpochObservationV1::Unavailable,
            SupervisorEpochObservationV1::Unreadable,
            SupervisorEpochObservationV1::Stale,
        ] {
            let observer = ScriptedEpochObserverV1::new([outcome]);
            assert!(!matches!(
                observe_expected_epoch_v1(&observer, "boot-t046", safe(41), None),
                EpochValidationOutcomeV1::Current(_)
            ));
        }
    }

    #[test]
    fn observations_are_safe_integer_typed_and_debug_redacted() {
        let observer = ScriptedEpochObserverV1::new([current(41, 8)]);
        let EpochValidationOutcomeV1::Current(observation) =
            observe_expected_epoch_v1(&observer, "boot-t046", safe(41), None)
        else {
            panic!("T046 exact epoch observation must be current");
        };
        assert_eq!(observation.supervisor_epoch(), 41);
        assert_eq!(observation.observer_generation(), 8);
        assert_eq!(format!("{observation:?}"), "EpochObservationV1 { .. }");
        assert!(!format!("{observation:?}").contains("boot-t046"));
    }
}
