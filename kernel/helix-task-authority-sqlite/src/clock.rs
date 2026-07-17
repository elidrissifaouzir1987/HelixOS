//! Injected trusted-clock adapter for HLXA operations.
//!
//! This module intentionally contains no ambient clock implementation.  Host wiring
//! supplies each coherent UTC/suspend-aware-monotonic/boot observation synchronously;
//! the wrapper maps only closed outcomes into the portable authority control contract.

use helix_task_authority::{
    AuthorityClockObservationV1, AuthorityClockProviderV1, AuthorityControlErrorV1,
};
use helix_task_authority_contracts::{Generation, Identifier, SafeU64};
use std::fmt;
use std::sync::Mutex;

/// One coherent trusted observation supplied by host adapter wiring.
pub struct AuthorityTrustedClockSampleV1 {
    boot_id: Identifier,
    clock_generation: Generation,
    instance_epoch: Generation,
    sampled_utc_ms: SafeU64,
    sampled_monotonic_ms: SafeU64,
}

impl AuthorityTrustedClockSampleV1 {
    pub const fn new(
        boot_id: Identifier,
        clock_generation: Generation,
        instance_epoch: Generation,
        sampled_utc_ms: SafeU64,
        sampled_monotonic_ms: SafeU64,
    ) -> Self {
        Self {
            boot_id,
            clock_generation,
            instance_epoch,
            sampled_utc_ms,
            sampled_monotonic_ms,
        }
    }

    pub fn boot_id_v1(&self) -> &str {
        self.boot_id.as_str()
    }

    pub const fn clock_generation_v1(&self) -> Generation {
        self.clock_generation
    }

    pub const fn instance_epoch_v1(&self) -> Generation {
        self.instance_epoch
    }

    pub const fn sampled_utc_ms_v1(&self) -> SafeU64 {
        self.sampled_utc_ms
    }

    pub const fn sampled_monotonic_ms_v1(&self) -> SafeU64 {
        self.sampled_monotonic_ms
    }

    fn into_core_observation(self) -> AuthorityClockObservationV1 {
        AuthorityClockObservationV1::from_trusted_provider_parts_v1(
            self.boot_id,
            self.clock_generation,
            self.instance_epoch,
            self.sampled_utc_ms,
            self.sampled_monotonic_ms,
        )
    }
}

impl fmt::Debug for AuthorityTrustedClockSampleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityTrustedClockSampleV1(..)")
    }
}

/// Closed result of one injected atomic clock observation.
pub enum AuthorityTrustedClockOutcomeV1 {
    Current(AuthorityTrustedClockSampleV1),
    Unavailable,
    Unreadable,
    OutOfRange,
    UtcRollback,
    MonotonicRollback,
    RollbackSuspected,
    BootMismatch,
    ClockGenerationMismatch,
    InstanceEpochMismatch,
    SuspendResumeInconsistent,
    UnexpectedLongSleep,
    Unsupported,
}

impl fmt::Debug for AuthorityTrustedClockOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Current(_) => formatter.write_str("AuthorityTrustedClockOutcomeV1::Current(..)"),
            Self::Unavailable => formatter.write_str("AuthorityTrustedClockOutcomeV1::Unavailable"),
            Self::Unreadable => formatter.write_str("AuthorityTrustedClockOutcomeV1::Unreadable"),
            Self::OutOfRange => formatter.write_str("AuthorityTrustedClockOutcomeV1::OutOfRange"),
            Self::UtcRollback => formatter.write_str("AuthorityTrustedClockOutcomeV1::UtcRollback"),
            Self::MonotonicRollback => {
                formatter.write_str("AuthorityTrustedClockOutcomeV1::MonotonicRollback")
            }
            Self::RollbackSuspected => {
                formatter.write_str("AuthorityTrustedClockOutcomeV1::RollbackSuspected")
            }
            Self::BootMismatch => {
                formatter.write_str("AuthorityTrustedClockOutcomeV1::BootMismatch")
            }
            Self::ClockGenerationMismatch => {
                formatter.write_str("AuthorityTrustedClockOutcomeV1::ClockGenerationMismatch")
            }
            Self::InstanceEpochMismatch => {
                formatter.write_str("AuthorityTrustedClockOutcomeV1::InstanceEpochMismatch")
            }
            Self::SuspendResumeInconsistent => {
                formatter.write_str("AuthorityTrustedClockOutcomeV1::SuspendResumeInconsistent")
            }
            Self::UnexpectedLongSleep => {
                formatter.write_str("AuthorityTrustedClockOutcomeV1::UnexpectedLongSleep")
            }
            Self::Unsupported => formatter.write_str("AuthorityTrustedClockOutcomeV1::Unsupported"),
        }
    }
}

/// Trusted synchronous clock seam.  Implementations must not renew the supplied absolute
/// deadline and must return one coherent sample or one closed failure.
pub trait AuthorityTrustedClockSourceV1: Send + Sync {
    fn capture_trusted_v1(
        &self,
        absolute_deadline_monotonic_ms: SafeU64,
    ) -> AuthorityTrustedClockOutcomeV1;
}

struct PreviousTrustedClockSampleV1 {
    boot_id: String,
    clock_generation: Generation,
    instance_epoch: Generation,
    sampled_utc_ms: SafeU64,
    sampled_monotonic_ms: SafeU64,
}

impl PreviousTrustedClockSampleV1 {
    fn from_sample(sample: &AuthorityTrustedClockSampleV1) -> Self {
        Self {
            boot_id: sample.boot_id_v1().to_owned(),
            clock_generation: sample.clock_generation,
            instance_epoch: sample.instance_epoch,
            sampled_utc_ms: sample.sampled_utc_ms,
            sampled_monotonic_ms: sample.sampled_monotonic_ms,
        }
    }
}

/// Core clock provider backed exclusively by an injected trusted source.
pub struct InjectedAuthorityClockProviderV1<S> {
    source: S,
    previous: Mutex<Option<PreviousTrustedClockSampleV1>>,
}

impl<S> InjectedAuthorityClockProviderV1<S> {
    pub const fn new(source: S) -> Self {
        Self {
            source,
            previous: Mutex::new(None),
        }
    }

    pub const fn source_v1(&self) -> &S {
        &self.source
    }
}

impl<S> fmt::Debug for InjectedAuthorityClockProviderV1<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InjectedAuthorityClockProviderV1(..)")
    }
}

impl<S: AuthorityTrustedClockSourceV1> AuthorityClockProviderV1
    for InjectedAuthorityClockProviderV1<S>
{
    fn capture_v1(
        &self,
        absolute_deadline_monotonic_ms: SafeU64,
    ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1> {
        if absolute_deadline_monotonic_ms.get() == 0 {
            return Err(AuthorityControlErrorV1::InvalidAbsoluteDeadline);
        }

        let sample = match self
            .source
            .capture_trusted_v1(absolute_deadline_monotonic_ms)
        {
            AuthorityTrustedClockOutcomeV1::Current(sample) => sample,
            AuthorityTrustedClockOutcomeV1::Unavailable => {
                return Err(AuthorityControlErrorV1::ClockUnavailable)
            }
            AuthorityTrustedClockOutcomeV1::Unreadable => {
                return Err(AuthorityControlErrorV1::ClockUnreadable)
            }
            AuthorityTrustedClockOutcomeV1::OutOfRange => {
                return Err(AuthorityControlErrorV1::ClockOutOfRange)
            }
            AuthorityTrustedClockOutcomeV1::UtcRollback => {
                return Err(AuthorityControlErrorV1::UtcRollback)
            }
            AuthorityTrustedClockOutcomeV1::MonotonicRollback => {
                return Err(AuthorityControlErrorV1::MonotonicRollback)
            }
            AuthorityTrustedClockOutcomeV1::RollbackSuspected => {
                return Err(AuthorityControlErrorV1::RollbackSuspected)
            }
            AuthorityTrustedClockOutcomeV1::BootMismatch => {
                return Err(AuthorityControlErrorV1::BootMismatch)
            }
            AuthorityTrustedClockOutcomeV1::ClockGenerationMismatch => {
                return Err(AuthorityControlErrorV1::ClockGenerationMismatch)
            }
            AuthorityTrustedClockOutcomeV1::InstanceEpochMismatch => {
                return Err(AuthorityControlErrorV1::InstanceEpochMismatch)
            }
            AuthorityTrustedClockOutcomeV1::SuspendResumeInconsistent => {
                return Err(AuthorityControlErrorV1::SuspendResumeInconsistent)
            }
            AuthorityTrustedClockOutcomeV1::UnexpectedLongSleep => {
                return Err(AuthorityControlErrorV1::UnexpectedLongSleep)
            }
            AuthorityTrustedClockOutcomeV1::Unsupported => {
                return Err(AuthorityControlErrorV1::Unsupported)
            }
        };

        if sample.sampled_monotonic_ms.get() >= absolute_deadline_monotonic_ms.get() {
            return Err(AuthorityControlErrorV1::DeadlineReached);
        }

        let mut previous = self
            .previous
            .lock()
            .map_err(|_| AuthorityControlErrorV1::ClockUnreadable)?;
        if let Some(prior) = previous.as_ref() {
            if prior.boot_id != sample.boot_id_v1() {
                return Err(AuthorityControlErrorV1::BootMismatch);
            }
            if prior.clock_generation != sample.clock_generation {
                return Err(AuthorityControlErrorV1::ClockGenerationMismatch);
            }
            if prior.instance_epoch != sample.instance_epoch {
                return Err(AuthorityControlErrorV1::InstanceEpochMismatch);
            }
            if sample.sampled_utc_ms < prior.sampled_utc_ms {
                return Err(AuthorityControlErrorV1::UtcRollback);
            }
            if sample.sampled_monotonic_ms < prior.sampled_monotonic_ms {
                return Err(AuthorityControlErrorV1::MonotonicRollback);
            }
        }
        *previous = Some(PreviousTrustedClockSampleV1::from_sample(&sample));
        Ok(sample.into_core_observation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScriptedClockSourceV1(Mutex<VecDeque<AuthorityTrustedClockOutcomeV1>>);

    impl ScriptedClockSourceV1 {
        fn new(outcomes: impl IntoIterator<Item = AuthorityTrustedClockOutcomeV1>) -> Self {
            Self(Mutex::new(outcomes.into_iter().collect()))
        }
    }

    impl fmt::Debug for ScriptedClockSourceV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ScriptedClockSourceV1(..)")
        }
    }

    impl AuthorityTrustedClockSourceV1 for ScriptedClockSourceV1 {
        fn capture_trusted_v1(
            &self,
            _absolute_deadline_monotonic_ms: SafeU64,
        ) -> AuthorityTrustedClockOutcomeV1 {
            self.0
                .lock()
                .expect("scripted trusted clock lock remains healthy")
                .pop_front()
                .expect("scripted trusted clock sample exists")
        }
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value).expect("test clock identifier is valid")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("test clock generation is valid")
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("test clock safe integer is valid")
    }

    fn sample(
        boot: &str,
        clock_generation: u64,
        instance_epoch: u64,
        utc: u64,
        monotonic: u64,
    ) -> AuthorityTrustedClockSampleV1 {
        AuthorityTrustedClockSampleV1::new(
            identifier(boot),
            generation(clock_generation),
            generation(instance_epoch),
            safe(utc),
            safe(monotonic),
        )
    }

    #[test]
    fn injected_provider_captures_without_ambient_time_and_enforces_exclusive_deadline() {
        let provider = InjectedAuthorityClockProviderV1::new(ScriptedClockSourceV1::new([
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_000, 99)),
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_001, 100)),
        ]));
        let observation = provider.capture_v1(safe(100)).expect("sample before bound");
        assert_eq!(observation.boot_id_v1(), "boot-a");
        assert_eq!(observation.sampled_monotonic_ms_v1().get(), 99);
        assert_eq!(
            provider.capture_v1(safe(100)).unwrap_err(),
            AuthorityControlErrorV1::DeadlineReached
        );
    }

    #[test]
    fn same_domain_utc_and_monotonic_regressions_fail_closed() {
        let utc_provider = InjectedAuthorityClockProviderV1::new(ScriptedClockSourceV1::new([
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_000, 100)),
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 9_999, 101)),
        ]));
        utc_provider
            .capture_v1(safe(1_000))
            .expect("baseline captures");
        assert_eq!(
            utc_provider.capture_v1(safe(1_000)).unwrap_err(),
            AuthorityControlErrorV1::UtcRollback
        );

        let monotonic_provider =
            InjectedAuthorityClockProviderV1::new(ScriptedClockSourceV1::new([
                AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_000, 100)),
                AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_001, 99)),
            ]));
        monotonic_provider
            .capture_v1(safe(1_000))
            .expect("baseline captures");
        assert_eq!(
            monotonic_provider.capture_v1(safe(1_000)).unwrap_err(),
            AuthorityControlErrorV1::MonotonicRollback
        );
    }

    #[test]
    fn changed_clock_domain_and_closed_source_errors_fail_closed() {
        let provider = InjectedAuthorityClockProviderV1::new(ScriptedClockSourceV1::new([
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_000, 100)),
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-b", 3, 4, 10_001, 1)),
        ]));
        provider.capture_v1(safe(1_000)).expect("old boot captures");
        assert_eq!(
            provider.capture_v1(safe(1_000)).unwrap_err(),
            AuthorityControlErrorV1::BootMismatch
        );

        let generation_provider =
            InjectedAuthorityClockProviderV1::new(ScriptedClockSourceV1::new([
                AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_000, 100)),
                AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 3, 3, 10_001, 101)),
            ]));
        generation_provider
            .capture_v1(safe(1_000))
            .expect("clock generation baseline captures");
        assert_eq!(
            generation_provider.capture_v1(safe(1_000)).unwrap_err(),
            AuthorityControlErrorV1::ClockGenerationMismatch
        );

        let epoch_provider = InjectedAuthorityClockProviderV1::new(ScriptedClockSourceV1::new([
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 3, 10_000, 100)),
            AuthorityTrustedClockOutcomeV1::Current(sample("boot-a", 2, 4, 10_001, 101)),
        ]));
        epoch_provider
            .capture_v1(safe(1_000))
            .expect("instance epoch baseline captures");
        assert_eq!(
            epoch_provider.capture_v1(safe(1_000)).unwrap_err(),
            AuthorityControlErrorV1::InstanceEpochMismatch
        );

        let failure_provider = InjectedAuthorityClockProviderV1::new(ScriptedClockSourceV1::new([
            AuthorityTrustedClockOutcomeV1::SuspendResumeInconsistent,
        ]));
        assert_eq!(
            failure_provider.capture_v1(safe(1_000)).unwrap_err(),
            AuthorityControlErrorV1::SuspendResumeInconsistent
        );
    }

    #[test]
    fn clock_debug_is_opaque() {
        let sample = sample("boot-secret-sentinel", 2, 3, 10_000, 100);
        assert!(!format!("{sample:?}").contains("secret-sentinel"));
        let outcome = AuthorityTrustedClockOutcomeV1::Current(sample);
        assert!(!format!("{outcome:?}").contains("secret-sentinel"));
    }
}
