//! Trusted portable time, absolute-deadline and admission-capacity contracts.
//!
//! This module never reads an ambient clock. A configured provider supplies one
//! coherent UTC/suspend-aware-monotonic observation. Captured deadlines retain their
//! original absolute bounds and are tied to one exact clock, boot and instance domain.

use helix_task_authority_contracts::{Generation, Identifier, SafeU64};
use std::fmt;

/// Fixed ordinary admission capacity for HLXA v1.
pub const AUTHORITY_ORDINARY_CAPACITY_V1: usize = 1_024;

/// Fixed capacity reserved exclusively for revocation and status control work.
pub const AUTHORITY_RESERVED_CONTROL_CAPACITY_V1: usize = 32;

/// The two physically independent authority admission lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityAdmissionLaneV1 {
    Ordinary,
    ReservedControl,
}

/// Closed operation classes admitted by the two capacity lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthorityAdmissionClassV1 {
    RootLeaseIssue,
    ChildLeaseIssue,
    CounterConsume,
    DecisionRetain,
    KeyStatusChange,
    Revocation,
    StatusLookup,
}

impl AuthorityAdmissionClassV1 {
    pub const ALL: [Self; 7] = [
        Self::RootLeaseIssue,
        Self::ChildLeaseIssue,
        Self::CounterConsume,
        Self::DecisionRetain,
        Self::KeyStatusChange,
        Self::Revocation,
        Self::StatusLookup,
    ];

    /// Ordinary work cannot borrow the reserved lane and control work cannot consume
    /// ordinary slots.
    pub const fn lane_v1(self) -> AuthorityAdmissionLaneV1 {
        match self {
            Self::RootLeaseIssue
            | Self::ChildLeaseIssue
            | Self::CounterConsume
            | Self::DecisionRetain => AuthorityAdmissionLaneV1::Ordinary,
            Self::KeyStatusChange | Self::Revocation | Self::StatusLookup => {
                AuthorityAdmissionLaneV1::ReservedControl
            }
        }
    }
}

/// Non-configurable v1 capacity profile.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorityCapacityProfileV1 {
    _private: (),
}

impl AuthorityCapacityProfileV1 {
    pub const FIXED: Self = Self { _private: () };

    pub const fn ordinary_capacity_v1(self) -> usize {
        AUTHORITY_ORDINARY_CAPACITY_V1
    }

    pub const fn reserved_control_capacity_v1(self) -> usize {
        AUTHORITY_RESERVED_CONTROL_CAPACITY_V1
    }

    pub const fn capacity_for_v1(self, lane: AuthorityAdmissionLaneV1) -> usize {
        match lane {
            AuthorityAdmissionLaneV1::Ordinary => AUTHORITY_ORDINARY_CAPACITY_V1,
            AuthorityAdmissionLaneV1::ReservedControl => AUTHORITY_RESERVED_CONTROL_CAPACITY_V1,
        }
    }
}

impl fmt::Debug for AuthorityCapacityProfileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityCapacityProfileV1(..)")
    }
}

/// Closed, payload-free failures for trusted time and deadline capture.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityControlErrorV1 {
    InvalidAbsoluteDeadline,
    ClockUnavailable,
    ClockUnreadable,
    ClockOutOfRange,
    UtcRollback,
    MonotonicRollback,
    RollbackSuspected,
    BootMismatch,
    ClockGenerationMismatch,
    InstanceEpochMismatch,
    SuspendResumeInconsistent,
    UnexpectedLongSleep,
    DeadlineReached,
    ArithmeticOverflow,
    Unsupported,
}

impl AuthorityControlErrorV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::InvalidAbsoluteDeadline => "AUTHORITY_INVALID_ABSOLUTE_DEADLINE",
            Self::ClockUnavailable => "AUTHORITY_CLOCK_UNAVAILABLE",
            Self::ClockUnreadable => "AUTHORITY_CLOCK_UNREADABLE",
            Self::ClockOutOfRange => "AUTHORITY_CLOCK_OUT_OF_RANGE",
            Self::UtcRollback => "AUTHORITY_UTC_ROLLBACK",
            Self::MonotonicRollback => "AUTHORITY_MONOTONIC_ROLLBACK",
            Self::RollbackSuspected => "AUTHORITY_ROLLBACK_SUSPECTED",
            Self::BootMismatch => "AUTHORITY_BOOT_MISMATCH",
            Self::ClockGenerationMismatch => "AUTHORITY_CLOCK_GENERATION_MISMATCH",
            Self::InstanceEpochMismatch => "AUTHORITY_INSTANCE_EPOCH_MISMATCH",
            Self::SuspendResumeInconsistent => "AUTHORITY_SUSPEND_RESUME_INCONSISTENT",
            Self::UnexpectedLongSleep => "AUTHORITY_UNEXPECTED_LONG_SLEEP",
            Self::DeadlineReached => "AUTHORITY_DEADLINE_REACHED",
            Self::ArithmeticOverflow => "AUTHORITY_ARITHMETIC_OVERFLOW",
            Self::Unsupported => "AUTHORITY_CLOCK_UNSUPPORTED",
        }
    }
}

impl fmt::Debug for AuthorityControlErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityControlErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl std::error::Error for AuthorityControlErrorV1 {}

/// One coherent observation returned by the configured trusted clock.
///
/// This adapter-boundary value is evidence, never standalone authority. Positive
/// authority additionally requires the configured provider, verified durable graph
/// and live unified guard custody.
pub struct AuthorityClockObservationV1 {
    boot_id: Identifier,
    clock_generation: Generation,
    instance_epoch: Generation,
    sampled_utc_ms: SafeU64,
    sampled_monotonic_ms: SafeU64,
}

impl AuthorityClockObservationV1 {
    pub fn from_trusted_provider_parts_v1(
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
}

impl fmt::Debug for AuthorityClockObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityClockObservationV1(..)")
    }
}

/// Configured trusted UTC/suspend-aware-monotonic observation source.
///
/// Implementations obtain one coherent sample per call and classify native rollback,
/// suspend/resume and long-sleep failures into [`AuthorityControlErrorV1`]. The
/// absolute monotonic deadline bounds provider work; it is never a relative timeout.
pub trait AuthorityClockProviderV1: Send + Sync {
    fn capture_v1(
        &self,
        absolute_deadline_monotonic_ms: SafeU64,
    ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1>;
}

/// Closed validation result for a later coherent observation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityDeadlineValidationV1 {
    Current,
    UtcRollback,
    MonotonicRollback,
    BootMismatch,
    ClockGenerationMismatch,
    InstanceEpochMismatch,
    DeadlineReached,
}

impl AuthorityDeadlineValidationV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Current => "AUTHORITY_DEADLINE_CURRENT",
            Self::UtcRollback => "AUTHORITY_UTC_ROLLBACK",
            Self::MonotonicRollback => "AUTHORITY_MONOTONIC_ROLLBACK",
            Self::BootMismatch => "AUTHORITY_BOOT_MISMATCH",
            Self::ClockGenerationMismatch => "AUTHORITY_CLOCK_GENERATION_MISMATCH",
            Self::InstanceEpochMismatch => "AUTHORITY_INSTANCE_EPOCH_MISMATCH",
            Self::DeadlineReached => "AUTHORITY_DEADLINE_REACHED",
        }
    }
}

impl fmt::Debug for AuthorityDeadlineValidationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

/// One linear absolute authority deadline tied to an exact trusted domain.
///
/// The type is deliberately non-`Clone`. A recapture consumes the prior value and
/// preserves both original absolute bounds, so retry cannot renew authority.
///
/// ```compile_fail
/// use helix_task_authority::AuthorityDeadlineV1;
///
/// fn duplicate(deadline: AuthorityDeadlineV1) {
///     let _copy = deadline.clone();
/// }
/// ```
pub struct AuthorityDeadlineV1 {
    observation: AuthorityClockObservationV1,
    earliest_expires_at_utc_ms: SafeU64,
    earliest_deadline_monotonic_ms: SafeU64,
}

impl AuthorityDeadlineV1 {
    /// Freezes the minimum caller/authority monotonic bound around one trusted sample.
    pub(crate) fn try_capture_v1(
        observation: AuthorityClockObservationV1,
        caller_deadline_monotonic_ms: SafeU64,
        earliest_expires_at_utc_ms: SafeU64,
        earliest_authority_deadline_monotonic_ms: SafeU64,
    ) -> Result<Self, AuthorityControlErrorV1> {
        if caller_deadline_monotonic_ms.get() == 0
            || earliest_expires_at_utc_ms.get() == 0
            || earliest_authority_deadline_monotonic_ms.get() == 0
        {
            return Err(AuthorityControlErrorV1::InvalidAbsoluteDeadline);
        }

        let earliest_deadline_monotonic_ms = SafeU64::new(
            caller_deadline_monotonic_ms
                .get()
                .min(earliest_authority_deadline_monotonic_ms.get()),
        )
        .map_err(|_| AuthorityControlErrorV1::ClockOutOfRange)?;

        if observation.sampled_utc_ms >= earliest_expires_at_utc_ms
            || observation.sampled_monotonic_ms >= earliest_deadline_monotonic_ms
        {
            return Err(AuthorityControlErrorV1::DeadlineReached);
        }

        Ok(Self {
            observation,
            earliest_expires_at_utc_ms,
            earliest_deadline_monotonic_ms,
        })
    }

    pub fn boot_id_v1(&self) -> &str {
        self.observation.boot_id.as_str()
    }

    pub const fn clock_generation_v1(&self) -> Generation {
        self.observation.clock_generation
    }

    pub const fn instance_epoch_v1(&self) -> Generation {
        self.observation.instance_epoch
    }

    pub const fn captured_utc_ms_v1(&self) -> SafeU64 {
        self.observation.sampled_utc_ms
    }

    pub const fn captured_monotonic_ms_v1(&self) -> SafeU64 {
        self.observation.sampled_monotonic_ms
    }

    pub const fn earliest_expires_at_utc_ms_v1(&self) -> SafeU64 {
        self.earliest_expires_at_utc_ms
    }

    pub const fn earliest_deadline_monotonic_ms_v1(&self) -> SafeU64 {
        self.earliest_deadline_monotonic_ms
    }

    /// Validates one later coherent observation without refreshing either bound.
    pub fn validate_observation_v1(
        &self,
        current: &AuthorityClockObservationV1,
    ) -> AuthorityDeadlineValidationV1 {
        // A reboot can reset monotonic time, so boot identity is deliberately checked
        // before rollback classification.
        if current.boot_id != self.observation.boot_id {
            return AuthorityDeadlineValidationV1::BootMismatch;
        }
        if current.clock_generation != self.observation.clock_generation {
            return AuthorityDeadlineValidationV1::ClockGenerationMismatch;
        }
        if current.instance_epoch != self.observation.instance_epoch {
            return AuthorityDeadlineValidationV1::InstanceEpochMismatch;
        }
        if current.sampled_utc_ms < self.observation.sampled_utc_ms {
            return AuthorityDeadlineValidationV1::UtcRollback;
        }
        if current.sampled_monotonic_ms < self.observation.sampled_monotonic_ms {
            return AuthorityDeadlineValidationV1::MonotonicRollback;
        }
        if current.sampled_utc_ms >= self.earliest_expires_at_utc_ms
            || current.sampled_monotonic_ms >= self.earliest_deadline_monotonic_ms
        {
            return AuthorityDeadlineValidationV1::DeadlineReached;
        }
        AuthorityDeadlineValidationV1::Current
    }

    /// Consumes this capture and validates one new trusted sample while preserving
    /// both original absolute deadline values.
    pub fn recapture_v1<P: AuthorityClockProviderV1 + ?Sized>(
        self,
        provider: &P,
    ) -> Result<Self, AuthorityControlErrorV1> {
        let current = provider.capture_v1(self.earliest_deadline_monotonic_ms)?;
        match self.validate_observation_v1(&current) {
            AuthorityDeadlineValidationV1::Current => Ok(Self {
                observation: current,
                earliest_expires_at_utc_ms: self.earliest_expires_at_utc_ms,
                earliest_deadline_monotonic_ms: self.earliest_deadline_monotonic_ms,
            }),
            AuthorityDeadlineValidationV1::UtcRollback => Err(AuthorityControlErrorV1::UtcRollback),
            AuthorityDeadlineValidationV1::MonotonicRollback => {
                Err(AuthorityControlErrorV1::MonotonicRollback)
            }
            AuthorityDeadlineValidationV1::BootMismatch => {
                Err(AuthorityControlErrorV1::BootMismatch)
            }
            AuthorityDeadlineValidationV1::ClockGenerationMismatch => {
                Err(AuthorityControlErrorV1::ClockGenerationMismatch)
            }
            AuthorityDeadlineValidationV1::InstanceEpochMismatch => {
                Err(AuthorityControlErrorV1::InstanceEpochMismatch)
            }
            AuthorityDeadlineValidationV1::DeadlineReached => {
                Err(AuthorityControlErrorV1::DeadlineReached)
            }
        }
    }
}

impl fmt::Debug for AuthorityDeadlineV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityDeadlineV1(..)")
    }
}

/// Captures a trusted observation exactly once and freezes the earliest absolute bounds.
pub fn capture_authority_deadline_v1<P: AuthorityClockProviderV1 + ?Sized>(
    provider: &P,
    caller_deadline_monotonic_ms: SafeU64,
    earliest_expires_at_utc_ms: SafeU64,
    earliest_authority_deadline_monotonic_ms: SafeU64,
) -> Result<AuthorityDeadlineV1, AuthorityControlErrorV1> {
    if caller_deadline_monotonic_ms.get() == 0
        || earliest_expires_at_utc_ms.get() == 0
        || earliest_authority_deadline_monotonic_ms.get() == 0
    {
        return Err(AuthorityControlErrorV1::InvalidAbsoluteDeadline);
    }
    let effective_deadline_monotonic_ms = SafeU64::new(
        caller_deadline_monotonic_ms
            .get()
            .min(earliest_authority_deadline_monotonic_ms.get()),
    )
    .map_err(|_| AuthorityControlErrorV1::ClockOutOfRange)?;
    let observation = provider.capture_v1(effective_deadline_monotonic_ms)?;
    AuthorityDeadlineV1::try_capture_v1(
        observation,
        caller_deadline_monotonic_ms,
        earliest_expires_at_utc_ms,
        earliest_authority_deadline_monotonic_ms,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("valid generation")
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("valid safe integer")
    }

    fn observation(
        clock_generation: u64,
        instance_epoch: u64,
        boot: &str,
        utc: u64,
        monotonic: u64,
    ) -> AuthorityClockObservationV1 {
        AuthorityClockObservationV1::from_trusted_provider_parts_v1(
            Identifier::new(boot).expect("valid boot id"),
            generation(clock_generation),
            generation(instance_epoch),
            safe(utc),
            safe(monotonic),
        )
    }

    struct OneShotClock {
        calls: AtomicUsize,
        deadline: AtomicU64,
        observation: std::sync::Mutex<Option<AuthorityClockObservationV1>>,
    }

    impl AuthorityClockProviderV1 for OneShotClock {
        fn capture_v1(
            &self,
            absolute_deadline_monotonic_ms: SafeU64,
        ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.deadline
                .store(absolute_deadline_monotonic_ms.get(), Ordering::SeqCst);
            self.observation
                .lock()
                .expect("clock mutex")
                .take()
                .ok_or(AuthorityControlErrorV1::ClockUnavailable)
        }
    }

    #[test]
    fn capacity_is_exact_and_only_revocation_status_are_reserved() {
        let profile = AuthorityCapacityProfileV1::FIXED;
        assert_eq!(profile.ordinary_capacity_v1(), 1_024);
        assert_eq!(profile.reserved_control_capacity_v1(), 32);

        for class in AuthorityAdmissionClassV1::ALL {
            let expected = match class {
                AuthorityAdmissionClassV1::KeyStatusChange
                | AuthorityAdmissionClassV1::Revocation
                | AuthorityAdmissionClassV1::StatusLookup => {
                    AuthorityAdmissionLaneV1::ReservedControl
                }
                _ => AuthorityAdmissionLaneV1::Ordinary,
            };
            assert_eq!(class.lane_v1(), expected);
        }
    }

    #[test]
    fn capture_calls_provider_once_and_freezes_earliest_bounds() {
        let clock = OneShotClock {
            calls: AtomicUsize::new(0),
            deadline: AtomicU64::new(0),
            observation: std::sync::Mutex::new(Some(observation(7, 3, "boot-a", 100, 200))),
        };
        let deadline = capture_authority_deadline_v1(&clock, safe(900), safe(500), safe(800))
            .expect("live capture");

        assert_eq!(clock.calls.load(Ordering::SeqCst), 1);
        assert_eq!(clock.deadline.load(Ordering::SeqCst), 800);
        assert_eq!(deadline.earliest_deadline_monotonic_ms_v1().get(), 800);
        assert_eq!(deadline.earliest_expires_at_utc_ms_v1().get(), 500);
        assert_eq!(
            deadline.validate_observation_v1(&observation(7, 3, "boot-a", 499, 799)),
            AuthorityDeadlineValidationV1::Current
        );
    }

    #[test]
    fn recapture_consumes_prior_capture_without_extending_bounds() {
        let first = OneShotClock {
            calls: AtomicUsize::new(0),
            deadline: AtomicU64::new(0),
            observation: std::sync::Mutex::new(Some(observation(7, 3, "boot-a", 100, 200))),
        };
        let second = OneShotClock {
            calls: AtomicUsize::new(0),
            deadline: AtomicU64::new(0),
            observation: std::sync::Mutex::new(Some(observation(7, 3, "boot-a", 150, 300))),
        };
        let deadline = capture_authority_deadline_v1(&first, safe(900), safe(500), safe(800))
            .expect("initial capture")
            .recapture_v1(&second)
            .expect("current recapture");

        assert_eq!(second.calls.load(Ordering::SeqCst), 1);
        assert_eq!(second.deadline.load(Ordering::SeqCst), 800);
        assert_eq!(deadline.earliest_expires_at_utc_ms_v1().get(), 500);
        assert_eq!(deadline.earliest_deadline_monotonic_ms_v1().get(), 800);
        assert_eq!(deadline.captured_utc_ms_v1().get(), 150);
        assert_eq!(deadline.captured_monotonic_ms_v1().get(), 300);
    }

    #[test]
    fn provider_failures_remain_closed_and_payload_free() {
        struct FailingClock;

        impl AuthorityClockProviderV1 for FailingClock {
            fn capture_v1(
                &self,
                _absolute_deadline_monotonic_ms: SafeU64,
            ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1> {
                Err(AuthorityControlErrorV1::SuspendResumeInconsistent)
            }
        }

        assert_eq!(
            capture_authority_deadline_v1(&FailingClock, safe(900), safe(500), safe(800))
                .expect_err("provider failure must propagate"),
            AuthorityControlErrorV1::SuspendResumeInconsistent
        );
    }

    #[test]
    fn equality_with_either_exclusive_bound_denies() {
        let deadline = AuthorityDeadlineV1::try_capture_v1(
            observation(7, 3, "boot-a", 100, 200),
            safe(900),
            safe(500),
            safe(800),
        )
        .expect("live capture");

        assert_eq!(
            deadline.validate_observation_v1(&observation(7, 3, "boot-a", 500, 799)),
            AuthorityDeadlineValidationV1::DeadlineReached
        );
        assert_eq!(
            deadline.validate_observation_v1(&observation(7, 3, "boot-a", 499, 800)),
            AuthorityDeadlineValidationV1::DeadlineReached
        );
    }

    #[test]
    fn rollback_and_every_domain_change_fail_closed() {
        let deadline = AuthorityDeadlineV1::try_capture_v1(
            observation(7, 3, "boot-a", 100, 200),
            safe(900),
            safe(500),
            safe(800),
        )
        .expect("live capture");

        assert_eq!(
            deadline.validate_observation_v1(&observation(7, 3, "boot-a", 99, 201)),
            AuthorityDeadlineValidationV1::UtcRollback
        );
        assert_eq!(
            deadline.validate_observation_v1(&observation(7, 3, "boot-a", 101, 199)),
            AuthorityDeadlineValidationV1::MonotonicRollback
        );
        assert_eq!(
            deadline.validate_observation_v1(&observation(8, 3, "boot-a", 101, 201)),
            AuthorityDeadlineValidationV1::ClockGenerationMismatch
        );
        assert_eq!(
            deadline.validate_observation_v1(&observation(7, 4, "boot-a", 101, 201)),
            AuthorityDeadlineValidationV1::InstanceEpochMismatch
        );
        assert_eq!(
            deadline.validate_observation_v1(&observation(7, 3, "boot-b", 101, 1)),
            AuthorityDeadlineValidationV1::BootMismatch
        );
    }

    #[test]
    fn zero_bounds_and_initial_equality_are_rejected() {
        for (caller, utc, authority) in [(0, 500, 800), (900, 0, 800), (900, 500, 0)] {
            assert_eq!(
                AuthorityDeadlineV1::try_capture_v1(
                    observation(7, 3, "boot-a", 100, 200),
                    safe(caller),
                    safe(utc),
                    safe(authority),
                )
                .expect_err("zero bound must fail"),
                AuthorityControlErrorV1::InvalidAbsoluteDeadline
            );
        }
        assert_eq!(
            AuthorityDeadlineV1::try_capture_v1(
                observation(7, 3, "boot-a", 500, 200),
                safe(900),
                safe(500),
                safe(800),
            )
            .expect_err("UTC equality must fail"),
            AuthorityControlErrorV1::DeadlineReached
        );
    }

    #[test]
    fn public_debug_and_errors_are_payload_free() {
        let secret = "native-path-private-sentinel";
        let captured = observation(7, 3, secret, 100, 200);
        let rendered = format!("{captured:?} {:?}", AuthorityControlErrorV1::UtcRollback);

        assert!(!rendered.contains(secret));
        assert_eq!(
            AuthorityControlErrorV1::UtcRollback.to_string(),
            "AUTHORITY_UTC_ROLLBACK"
        );
    }
}
