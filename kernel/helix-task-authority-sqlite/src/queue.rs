//! Concurrent bounded admission and exact duplicate coalescing for HLXA work.
//!
//! The queue retains only opaque stable digests and payload-free completion classes.
//! It never reads an ambient clock: admission and coalesced waits consume a core
//! [`AuthorityDeadlineV1`] and recapture it through the injected trusted provider.

#![allow(dead_code)]

use helix_task_authority::{
    AuthorityAdmissionClassV1, AuthorityAdmissionLaneV1, AuthorityAttemptBindingV1,
    AuthorityCapacityProfileV1, AuthorityClockProviderV1, AuthorityControlErrorV1,
    AuthorityDeadlineV1, AuthorityOperationKindV1,
};
use helix_task_authority_contracts::Sha256Digest;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

/// Opaque stable identity for a non-mutating status lookup.
///
/// Constructing this value does not grant authority. The digest must bind the exact
/// verified lookup subject and observation inputs selected by the caller.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorityStatusLookupBindingV1 {
    digest: Sha256Digest,
}

impl AuthorityStatusLookupBindingV1 {
    pub const fn from_verified_digest_v1(digest: Sha256Digest) -> Self {
        Self { digest }
    }
}

impl fmt::Debug for AuthorityStatusLookupBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityStatusLookupBindingV1(..)")
    }
}

/// Payload-free result shared with exact concurrent duplicates.
///
/// A coalesced caller uses this classification only to select the exact durable
/// readback path. It never receives candidate bytes from another caller and this
/// value never authorizes blind signing, reissuance or mutation retry.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityQueueCompletionV1 {
    CommittedRetained,
    DeniedDefinite,
    ConflictRetained,
    UncertainReadbackRequired,
    AmbiguousReconciliationRequired,
    Unavailable,
}

impl AuthorityQueueCompletionV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::CommittedRetained => "COMMITTED_RETAINED",
            Self::DeniedDefinite => "DENIED_DEFINITE",
            Self::ConflictRetained => "CONFLICT_RETAINED",
            Self::UncertainReadbackRequired => "UNCERTAIN_READBACK_REQUIRED",
            Self::AmbiguousReconciliationRequired => "AMBIGUOUS_RECONCILIATION_REQUIRED",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

impl fmt::Debug for AuthorityQueueCompletionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

/// Closed queue or deadline failure.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityQueueErrorV1 {
    Deadline(AuthorityControlErrorV1),
    UnsupportedOperation,
    Unavailable,
}

impl AuthorityQueueErrorV1 {
    pub const fn code_v1(self) -> &'static str {
        match self {
            Self::Deadline(_) => "AUTHORITY_QUEUE_DEADLINE_FAILURE",
            Self::UnsupportedOperation => "AUTHORITY_QUEUE_UNSUPPORTED_OPERATION",
            Self::Unavailable => "AUTHORITY_QUEUE_UNAVAILABLE",
        }
    }

    pub const fn deadline_error_v1(self) -> Option<AuthorityControlErrorV1> {
        match self {
            Self::Deadline(error) => Some(error),
            Self::UnsupportedOperation | Self::Unavailable => None,
        }
    }
}

impl fmt::Debug for AuthorityQueueErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl fmt::Display for AuthorityQueueErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code_v1())
    }
}

impl std::error::Error for AuthorityQueueErrorV1 {}

impl From<AuthorityControlErrorV1> for AuthorityQueueErrorV1 {
    fn from(error: AuthorityControlErrorV1) -> Self {
        Self::Deadline(error)
    }
}

/// Redacted immutable snapshot of queue accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityQueueSnapshotV1 {
    ordinary_active: usize,
    reserved_control_active: usize,
    admitted_count: u64,
    coalesced_count: u64,
    refused_at_capacity_count: u64,
}

impl AuthorityQueueSnapshotV1 {
    pub const fn ordinary_active_v1(self) -> usize {
        self.ordinary_active
    }

    pub const fn reserved_control_active_v1(self) -> usize {
        self.reserved_control_active
    }

    pub const fn admitted_count_v1(self) -> u64 {
        self.admitted_count
    }

    pub const fn coalesced_count_v1(self) -> u64 {
        self.coalesced_count
    }

    pub const fn refused_at_capacity_count_v1(self) -> u64 {
        self.refused_at_capacity_count
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct AuthorityQueueIdentityV1 {
    class: AuthorityAdmissionClassV1,
    namespace_digest: Sha256Digest,
    input_graph_digest: Sha256Digest,
}

impl AuthorityQueueIdentityV1 {
    fn from_attempt_v1(
        class: AuthorityAdmissionClassV1,
        attempt: &AuthorityAttemptBindingV1,
    ) -> Self {
        Self {
            class,
            namespace_digest: attempt.namespace_digest_v1().digest_v1(),
            input_graph_digest: attempt.input_graph_digest_v1().digest_v1(),
        }
    }

    const fn from_status_lookup_v1(binding: AuthorityStatusLookupBindingV1) -> Self {
        Self {
            class: AuthorityAdmissionClassV1::StatusLookup,
            namespace_digest: binding.digest,
            input_graph_digest: binding.digest,
        }
    }

    const fn lane_v1(self) -> AuthorityAdmissionLaneV1 {
        self.class.lane_v1()
    }
}

impl fmt::Debug for AuthorityQueueIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityQueueIdentityV1")
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

struct AuthorityQueueEntryV1 {
    completion: Mutex<Option<AuthorityQueueCompletionV1>>,
    completed: Condvar,
}

impl AuthorityQueueEntryV1 {
    fn new_v1() -> Self {
        Self {
            completion: Mutex::new(None),
            completed: Condvar::new(),
        }
    }
}

impl fmt::Debug for AuthorityQueueEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityQueueEntryV1(..)")
    }
}

struct AuthorityQueueStateV1 {
    active: HashMap<AuthorityQueueIdentityV1, Arc<AuthorityQueueEntryV1>>,
    ordinary_active: usize,
    reserved_control_active: usize,
    admitted_count: u64,
    coalesced_count: u64,
    refused_at_capacity_count: u64,
}

impl AuthorityQueueStateV1 {
    fn new_v1() -> Self {
        Self {
            active: HashMap::new(),
            ordinary_active: 0,
            reserved_control_active: 0,
            admitted_count: 0,
            coalesced_count: 0,
            refused_at_capacity_count: 0,
        }
    }

    const fn active_for_v1(&self, lane: AuthorityAdmissionLaneV1) -> usize {
        match lane {
            AuthorityAdmissionLaneV1::Ordinary => self.ordinary_active,
            AuthorityAdmissionLaneV1::ReservedControl => self.reserved_control_active,
        }
    }

    fn increment_lane_v1(&mut self, lane: AuthorityAdmissionLaneV1) {
        match lane {
            AuthorityAdmissionLaneV1::Ordinary => self.ordinary_active += 1,
            AuthorityAdmissionLaneV1::ReservedControl => self.reserved_control_active += 1,
        }
    }

    fn decrement_lane_v1(&mut self, lane: AuthorityAdmissionLaneV1) {
        let active = match lane {
            AuthorityAdmissionLaneV1::Ordinary => &mut self.ordinary_active,
            AuthorityAdmissionLaneV1::ReservedControl => &mut self.reserved_control_active,
        };
        debug_assert!(*active > 0, "an admitted leader owns exactly one lane slot");
        *active = active.saturating_sub(1);
    }

    fn snapshot_v1(&self) -> AuthorityQueueSnapshotV1 {
        AuthorityQueueSnapshotV1 {
            ordinary_active: self.ordinary_active,
            reserved_control_active: self.reserved_control_active,
            admitted_count: self.admitted_count,
            coalesced_count: self.coalesced_count,
            refused_at_capacity_count: self.refused_at_capacity_count,
        }
    }
}

impl fmt::Debug for AuthorityQueueStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityQueueStateV1(..)")
    }
}

struct AuthorityQueueInnerV1 {
    capacity: AuthorityCapacityProfileV1,
    state: Mutex<AuthorityQueueStateV1>,
}

impl AuthorityQueueInnerV1 {
    fn finish_v1(
        &self,
        identity: AuthorityQueueIdentityV1,
        entry: &Arc<AuthorityQueueEntryV1>,
        outcome: AuthorityQueueCompletionV1,
    ) -> Result<(), AuthorityQueueErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthorityQueueErrorV1::Unavailable)?;
        let Some(current) = state.active.get(&identity) else {
            return Ok(());
        };
        if !Arc::ptr_eq(current, entry) {
            return Ok(());
        }

        let mut completion = entry
            .completion
            .lock()
            .map_err(|_| AuthorityQueueErrorV1::Unavailable)?;
        if completion.is_some() {
            return Ok(());
        }
        *completion = Some(outcome);
        let removed = state.active.remove(&identity);
        debug_assert!(
            removed
                .as_ref()
                .is_some_and(|value| Arc::ptr_eq(value, entry)),
            "the exact active leader is removed"
        );
        state.decrement_lane_v1(identity.lane_v1());

        drop(completion);
        drop(state);
        entry.completed.notify_all();
        Ok(())
    }
}

impl fmt::Debug for AuthorityQueueInnerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityQueueInnerV1(..)")
    }
}

/// One admitted leader. Dropping it publishes `UNAVAILABLE` and releases its slot.
pub struct AuthorityQueuePermitV1 {
    inner: Arc<AuthorityQueueInnerV1>,
    identity: AuthorityQueueIdentityV1,
    entry: Arc<AuthorityQueueEntryV1>,
    finished: bool,
}

impl AuthorityQueuePermitV1 {
    pub const fn class_v1(&self) -> AuthorityAdmissionClassV1 {
        self.identity.class
    }

    pub const fn lane_v1(&self) -> AuthorityAdmissionLaneV1 {
        self.identity.lane_v1()
    }

    /// Publishes one payload-free terminal classification and releases exactly the
    /// lane slot held by this leader.
    pub fn complete_v1(
        mut self,
        outcome: AuthorityQueueCompletionV1,
    ) -> Result<(), AuthorityQueueErrorV1> {
        self.finished = true;
        self.inner.finish_v1(self.identity, &self.entry, outcome)
    }
}

impl fmt::Debug for AuthorityQueuePermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityQueuePermitV1")
            .field("class", &self.identity.class)
            .field("lane", &self.identity.lane_v1())
            .finish_non_exhaustive()
    }
}

impl Drop for AuthorityQueuePermitV1 {
    fn drop(&mut self) {
        if !self.finished {
            self.finished = true;
            let _ = self.inner.finish_v1(
                self.identity,
                &self.entry,
                AuthorityQueueCompletionV1::Unavailable,
            );
        }
    }
}

/// A duplicate follower that owns no admission slot and can only observe the leader's
/// payload-free completion classification.
pub struct AuthorityQueueFollowerV1 {
    class: AuthorityAdmissionClassV1,
    entry: Arc<AuthorityQueueEntryV1>,
}

impl AuthorityQueueFollowerV1 {
    pub const fn class_v1(&self) -> AuthorityAdmissionClassV1 {
        self.class
    }

    pub const fn lane_v1(&self) -> AuthorityAdmissionLaneV1 {
        self.class.lane_v1()
    }

    /// Waits only for the remaining interval derived from the injected trusted
    /// observation. Every wakeup consumes and recaptures the original absolute
    /// deadline, so a retry can never extend either bound.
    pub fn wait_v1<P: AuthorityClockProviderV1 + ?Sized>(
        self,
        mut deadline: AuthorityDeadlineV1,
        provider: &P,
    ) -> Result<AuthorityQueueCompletionV1, AuthorityQueueErrorV1> {
        loop {
            let (mut completion, recaptured) =
                lock_before_deadline_v1(&self.entry.completion, deadline, provider)?;
            deadline = recaptured;
            if let Some(outcome) = *completion {
                return Ok(outcome);
            }

            let remaining_monotonic_ms = deadline
                .earliest_deadline_monotonic_ms_v1()
                .get()
                .saturating_sub(deadline.captured_monotonic_ms_v1().get());
            let remaining_utc_ms = deadline
                .earliest_expires_at_utc_ms_v1()
                .get()
                .saturating_sub(deadline.captured_utc_ms_v1().get());
            let remaining_ms = remaining_monotonic_ms.min(remaining_utc_ms);
            if remaining_ms == 0 {
                return Err(AuthorityQueueErrorV1::Deadline(
                    AuthorityControlErrorV1::DeadlineReached,
                ));
            }

            let (next, _) = self
                .entry
                .completed
                .wait_timeout(completion, Duration::from_millis(remaining_ms))
                .map_err(|_| AuthorityQueueErrorV1::Unavailable)?;
            completion = next;
            if let Some(outcome) = *completion {
                drop(completion);
                // Completion cannot bypass expiry: validate one final trusted sample.
                deadline = deadline.recapture_v1(provider)?;
                let _ = deadline;
                return Ok(outcome);
            }
        }
    }
}

impl fmt::Debug for AuthorityQueueFollowerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityQueueFollowerV1")
            .field("class", &self.class)
            .field("lane", &self.class.lane_v1())
            .finish_non_exhaustive()
    }
}

/// Immediate closed result of one admission attempt.
pub enum AuthorityQueueAdmissionV1 {
    Leader {
        permit: AuthorityQueuePermitV1,
        deadline: AuthorityDeadlineV1,
    },
    Coalesced {
        follower: AuthorityQueueFollowerV1,
        deadline: AuthorityDeadlineV1,
    },
    RefusedAtCapacity {
        lane: AuthorityAdmissionLaneV1,
    },
}

impl AuthorityQueueAdmissionV1 {
    pub const fn lane_v1(&self) -> AuthorityAdmissionLaneV1 {
        match self {
            Self::Leader { permit, .. } => permit.lane_v1(),
            Self::Coalesced { follower, .. } => follower.lane_v1(),
            Self::RefusedAtCapacity { lane } => *lane,
        }
    }
}

impl fmt::Debug for AuthorityQueueAdmissionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Leader { permit, .. } => formatter
                .debug_struct("AuthorityQueueAdmissionV1::Leader")
                .field("class", &permit.class_v1())
                .field("lane", &permit.lane_v1())
                .finish_non_exhaustive(),
            Self::Coalesced { follower, .. } => formatter
                .debug_struct("AuthorityQueueAdmissionV1::Coalesced")
                .field("class", &follower.class_v1())
                .field("lane", &follower.lane_v1())
                .finish_non_exhaustive(),
            Self::RefusedAtCapacity { lane } => formatter
                .debug_struct("AuthorityQueueAdmissionV1::RefusedAtCapacity")
                .field("lane", lane)
                .finish(),
        }
    }
}

/// Process-local HLXA admission controller with two physically independent capacities.
#[derive(Clone)]
pub struct AuthorityAdmissionQueueV1 {
    inner: Arc<AuthorityQueueInnerV1>,
}

impl AuthorityAdmissionQueueV1 {
    pub fn new_v1() -> Self {
        Self {
            inner: Arc::new(AuthorityQueueInnerV1 {
                capacity: AuthorityCapacityProfileV1::FIXED,
                state: Mutex::new(AuthorityQueueStateV1::new_v1()),
            }),
        }
    }

    /// Admits a mutation using the class implied by its closed core operation kind.
    /// Bootstrap, backup and restore use their separately serialized maintenance paths.
    pub fn admit_attempt_v1<P: AuthorityClockProviderV1 + ?Sized>(
        &self,
        attempt: &AuthorityAttemptBindingV1,
        deadline: AuthorityDeadlineV1,
        provider: &P,
    ) -> Result<AuthorityQueueAdmissionV1, AuthorityQueueErrorV1> {
        let class = admission_class_for_operation_v1(attempt.operation_kind_v1())
            .ok_or(AuthorityQueueErrorV1::UnsupportedOperation)?;
        if deadline.earliest_deadline_monotonic_ms_v1().get()
            > attempt.caller_deadline_monotonic_ms_v1().get()
        {
            return Err(AuthorityQueueErrorV1::Deadline(
                AuthorityControlErrorV1::InvalidAbsoluteDeadline,
            ));
        }
        self.admit_identity_v1(
            AuthorityQueueIdentityV1::from_attempt_v1(class, attempt),
            deadline,
            provider,
        )
    }

    /// Admits an exact non-mutating lookup only to the reserved status lane.
    pub fn admit_status_lookup_v1<P: AuthorityClockProviderV1 + ?Sized>(
        &self,
        binding: AuthorityStatusLookupBindingV1,
        deadline: AuthorityDeadlineV1,
        provider: &P,
    ) -> Result<AuthorityQueueAdmissionV1, AuthorityQueueErrorV1> {
        self.admit_identity_v1(
            AuthorityQueueIdentityV1::from_status_lookup_v1(binding),
            deadline,
            provider,
        )
    }

    pub fn snapshot_v1(&self) -> Result<AuthorityQueueSnapshotV1, AuthorityQueueErrorV1> {
        self.inner
            .state
            .lock()
            .map(|state| state.snapshot_v1())
            .map_err(|_| AuthorityQueueErrorV1::Unavailable)
    }

    fn admit_identity_v1<P: AuthorityClockProviderV1 + ?Sized>(
        &self,
        identity: AuthorityQueueIdentityV1,
        deadline: AuthorityDeadlineV1,
        provider: &P,
    ) -> Result<AuthorityQueueAdmissionV1, AuthorityQueueErrorV1> {
        // A blocking `Mutex::lock` could retain a pre-wait clock sample past the
        // exclusive deadline. Recapture before every non-blocking acquisition so
        // provider code never runs under queue custody and stale work mutates no state.
        let (mut state, deadline) = lock_before_deadline_v1(&self.inner.state, deadline, provider)?;

        if let Some(entry) = state.active.get(&identity).cloned() {
            state.coalesced_count = state.coalesced_count.saturating_add(1);
            return Ok(AuthorityQueueAdmissionV1::Coalesced {
                follower: AuthorityQueueFollowerV1 {
                    class: identity.class,
                    entry,
                },
                deadline,
            });
        }

        let lane = identity.lane_v1();
        if state.active_for_v1(lane) >= self.inner.capacity.capacity_for_v1(lane) {
            state.refused_at_capacity_count = state.refused_at_capacity_count.saturating_add(1);
            return Ok(AuthorityQueueAdmissionV1::RefusedAtCapacity { lane });
        }

        let entry = Arc::new(AuthorityQueueEntryV1::new_v1());
        let replaced = state.active.insert(identity, Arc::clone(&entry));
        debug_assert!(replaced.is_none(), "duplicate check and insert stay atomic");
        state.increment_lane_v1(lane);
        state.admitted_count = state.admitted_count.saturating_add(1);
        drop(state);

        Ok(AuthorityQueueAdmissionV1::Leader {
            permit: AuthorityQueuePermitV1 {
                inner: Arc::clone(&self.inner),
                identity,
                entry,
                finished: false,
            },
            deadline,
        })
    }
}

fn lock_before_deadline_v1<'a, T, P: AuthorityClockProviderV1 + ?Sized>(
    mutex: &'a Mutex<T>,
    mut deadline: AuthorityDeadlineV1,
    provider: &P,
) -> Result<(MutexGuard<'a, T>, AuthorityDeadlineV1), AuthorityQueueErrorV1> {
    loop {
        deadline = deadline.recapture_v1(provider)?;
        match mutex.try_lock() {
            Ok(guard) => return Ok((guard, deadline)),
            Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            Err(TryLockError::Poisoned(_)) => return Err(AuthorityQueueErrorV1::Unavailable),
        }
    }
}

impl Default for AuthorityAdmissionQueueV1 {
    fn default() -> Self {
        Self::new_v1()
    }
}

impl fmt::Debug for AuthorityAdmissionQueueV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityAdmissionQueueV1(..)")
    }
}

const fn admission_class_for_operation_v1(
    operation: AuthorityOperationKindV1,
) -> Option<AuthorityAdmissionClassV1> {
    match operation {
        AuthorityOperationKindV1::KeyStatusChange => {
            Some(AuthorityAdmissionClassV1::KeyStatusChange)
        }
        AuthorityOperationKindV1::RootLeaseIssue => Some(AuthorityAdmissionClassV1::RootLeaseIssue),
        AuthorityOperationKindV1::ChildLeaseIssue => {
            Some(AuthorityAdmissionClassV1::ChildLeaseIssue)
        }
        AuthorityOperationKindV1::CounterConsume => Some(AuthorityAdmissionClassV1::CounterConsume),
        AuthorityOperationKindV1::DecisionRetain => Some(AuthorityAdmissionClassV1::DecisionRetain),
        AuthorityOperationKindV1::AuthorityRevoke => Some(AuthorityAdmissionClassV1::Revocation),
        AuthorityOperationKindV1::Bootstrap
        | AuthorityOperationKindV1::BackupPublish
        | AuthorityOperationKindV1::RestorePublish => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helix_task_authority::{
        capture_authority_deadline_v1, AuthorityAttemptIdV1, AuthorityClockObservationV1,
        AuthorityInputGraphDigestV1, AuthorityNamespaceDigestV1,
    };
    use helix_task_authority_contracts::{Generation, Identifier, SafeU64};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    const DEADLINE_MS: u64 = 1_000_000;

    struct ControlledClockV1 {
        now_ms: AtomicU64,
        capture_count: AtomicUsize,
    }

    impl ControlledClockV1 {
        const fn new_v1(now_ms: u64) -> Self {
            Self {
                now_ms: AtomicU64::new(now_ms),
                capture_count: AtomicUsize::new(0),
            }
        }

        fn set_v1(&self, now_ms: u64) {
            self.now_ms.store(now_ms, Ordering::SeqCst);
        }

        fn capture_count_v1(&self) -> usize {
            self.capture_count.load(Ordering::SeqCst)
        }
    }

    impl AuthorityClockProviderV1 for ControlledClockV1 {
        fn capture_v1(
            &self,
            _absolute_deadline_monotonic_ms: SafeU64,
        ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1> {
            self.capture_count.fetch_add(1, Ordering::SeqCst);
            let now_ms = safe(self.now_ms.load(Ordering::SeqCst));
            Ok(AuthorityClockObservationV1::from_trusted_provider_parts_v1(
                Identifier::new("queue-test-boot").expect("test boot identifier"),
                generation(1),
                generation(1),
                now_ms,
                now_ms,
            ))
        }
    }

    fn safe(value: u64) -> SafeU64 {
        SafeU64::new(value).expect("test value is a safe integer")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("test generation is positive")
    }

    fn deadline_v1(clock: &ControlledClockV1) -> AuthorityDeadlineV1 {
        capture_authority_deadline_v1(
            clock,
            safe(DEADLINE_MS),
            safe(DEADLINE_MS),
            safe(DEADLINE_MS),
        )
        .expect("test deadline is current")
    }

    fn wait_for_capture_after_v1(clock: &ControlledClockV1, prior_count: usize) {
        for _ in 0..1_000_000 {
            if clock.capture_count_v1() > prior_count {
                return;
            }
            thread::yield_now();
        }
        panic!("clock provider was not recaptured while the test mutex remained held");
    }

    fn identity_v1(class: AuthorityAdmissionClassV1, ordinal: usize) -> AuthorityQueueIdentityV1 {
        let namespace_digest = Sha256Digest::digest(format!("namespace-{ordinal}").as_bytes());
        let input_graph_digest = Sha256Digest::digest(format!("input-{ordinal}").as_bytes());
        AuthorityQueueIdentityV1 {
            class,
            namespace_digest,
            input_graph_digest,
        }
    }

    fn attempt_v1(
        operation: AuthorityOperationKindV1,
        ordinal: usize,
        caller_deadline_ms: u64,
    ) -> AuthorityAttemptBindingV1 {
        AuthorityAttemptBindingV1::from_verified_parts_v1(
            AuthorityAttemptIdV1::from_verified_digest_v1(Sha256Digest::digest(
                format!("attempt-{ordinal}").as_bytes(),
            )),
            operation,
            AuthorityNamespaceDigestV1::from_verified_digest_v1(Sha256Digest::digest(
                format!("attempt-namespace-{ordinal}").as_bytes(),
            )),
            AuthorityInputGraphDigestV1::from_verified_digest_v1(Sha256Digest::digest(
                format!("attempt-input-{ordinal}").as_bytes(),
            )),
            safe(caller_deadline_ms),
        )
        .expect("test attempt binding is valid")
    }

    fn take_leader_v1(admission: AuthorityQueueAdmissionV1) -> AuthorityQueuePermitV1 {
        match admission {
            AuthorityQueueAdmissionV1::Leader { permit, .. } => permit,
            other => panic!("expected leader, got {other:?}"),
        }
    }

    #[test]
    fn supported_mutations_derive_their_lane_and_maintenance_cannot_borrow_one() {
        let expected = [
            (
                AuthorityOperationKindV1::RootLeaseIssue,
                AuthorityAdmissionClassV1::RootLeaseIssue,
                AuthorityAdmissionLaneV1::Ordinary,
            ),
            (
                AuthorityOperationKindV1::ChildLeaseIssue,
                AuthorityAdmissionClassV1::ChildLeaseIssue,
                AuthorityAdmissionLaneV1::Ordinary,
            ),
            (
                AuthorityOperationKindV1::CounterConsume,
                AuthorityAdmissionClassV1::CounterConsume,
                AuthorityAdmissionLaneV1::Ordinary,
            ),
            (
                AuthorityOperationKindV1::DecisionRetain,
                AuthorityAdmissionClassV1::DecisionRetain,
                AuthorityAdmissionLaneV1::Ordinary,
            ),
            (
                AuthorityOperationKindV1::KeyStatusChange,
                AuthorityAdmissionClassV1::KeyStatusChange,
                AuthorityAdmissionLaneV1::ReservedControl,
            ),
            (
                AuthorityOperationKindV1::AuthorityRevoke,
                AuthorityAdmissionClassV1::Revocation,
                AuthorityAdmissionLaneV1::ReservedControl,
            ),
        ];
        for (operation, class, lane) in expected {
            let actual = admission_class_for_operation_v1(operation).expect("supported operation");
            assert_eq!(actual, class);
            assert_eq!(actual.lane_v1(), lane);
        }
        for operation in [
            AuthorityOperationKindV1::Bootstrap,
            AuthorityOperationKindV1::BackupPublish,
            AuthorityOperationKindV1::RestorePublish,
        ] {
            assert_eq!(admission_class_for_operation_v1(operation), None);
        }
    }

    #[test]
    fn exact_fixed_capacities_are_physically_independent() {
        let queue = AuthorityAdmissionQueueV1::new_v1();
        let clock = ControlledClockV1::new_v1(10);
        let profile = AuthorityCapacityProfileV1::FIXED;
        let mut ordinary = Vec::with_capacity(profile.ordinary_capacity_v1());
        for ordinal in 0..profile.ordinary_capacity_v1() {
            ordinary.push(take_leader_v1(
                queue
                    .admit_identity_v1(
                        identity_v1(AuthorityAdmissionClassV1::RootLeaseIssue, ordinal),
                        deadline_v1(&clock),
                        &clock,
                    )
                    .expect("ordinary admission remains available"),
            ));
        }
        assert!(matches!(
            queue
                .admit_identity_v1(
                    identity_v1(AuthorityAdmissionClassV1::RootLeaseIssue, 0),
                    deadline_v1(&clock),
                    &clock,
                )
                .expect("an exact duplicate coalesces even when its lane is full"),
            AuthorityQueueAdmissionV1::Coalesced { .. }
        ));
        assert!(matches!(
            queue
                .admit_identity_v1(
                    identity_v1(AuthorityAdmissionClassV1::DecisionRetain, 10_000),
                    deadline_v1(&clock),
                    &clock,
                )
                .expect("bounded refusal is a closed result"),
            AuthorityQueueAdmissionV1::RefusedAtCapacity {
                lane: AuthorityAdmissionLaneV1::Ordinary
            }
        ));

        let mut control = Vec::with_capacity(profile.reserved_control_capacity_v1());
        for ordinal in 0..profile.reserved_control_capacity_v1() {
            control.push(take_leader_v1(
                queue
                    .admit_identity_v1(
                        identity_v1(AuthorityAdmissionClassV1::Revocation, 20_000 + ordinal),
                        deadline_v1(&clock),
                        &clock,
                    )
                    .expect("ordinary saturation cannot consume control capacity"),
            ));
        }
        assert!(matches!(
            queue
                .admit_status_lookup_v1(
                    AuthorityStatusLookupBindingV1::from_verified_digest_v1(Sha256Digest::digest(
                        b"control-full"
                    ),),
                    deadline_v1(&clock),
                    &clock,
                )
                .expect("bounded refusal is a closed result"),
            AuthorityQueueAdmissionV1::RefusedAtCapacity {
                lane: AuthorityAdmissionLaneV1::ReservedControl
            }
        ));

        let snapshot = queue.snapshot_v1().expect("queue mutex is healthy");
        assert_eq!(
            snapshot.ordinary_active_v1(),
            profile.ordinary_capacity_v1()
        );
        assert_eq!(
            snapshot.reserved_control_active_v1(),
            profile.reserved_control_capacity_v1()
        );

        drop(ordinary.pop());
        let replacement = queue
            .admit_identity_v1(
                identity_v1(AuthorityAdmissionClassV1::CounterConsume, 30_000),
                deadline_v1(&clock),
                &clock,
            )
            .expect("control saturation cannot consume ordinary capacity");
        assert!(matches!(
            replacement,
            AuthorityQueueAdmissionV1::Leader { .. }
        ));
        drop(replacement);
        drop(control);
        drop(ordinary);
    }

    #[test]
    fn exact_duplicates_coalesce_before_capacity_and_share_only_closed_outcome() {
        let queue = AuthorityAdmissionQueueV1::new_v1();
        let clock = ControlledClockV1::new_v1(10);
        let identity = identity_v1(AuthorityAdmissionClassV1::RootLeaseIssue, 7);
        let leader = take_leader_v1(
            queue
                .admit_identity_v1(identity, deadline_v1(&clock), &clock)
                .expect("first exact identity leads"),
        );

        let mut followers = Vec::new();
        for _ in 0..512 {
            match queue
                .admit_identity_v1(identity, deadline_v1(&clock), &clock)
                .expect("exact duplicate admission is closed")
            {
                AuthorityQueueAdmissionV1::Coalesced { follower, deadline } => {
                    followers.push((follower, deadline));
                }
                other => panic!("expected coalesced duplicate, got {other:?}"),
            }
        }
        let snapshot = queue.snapshot_v1().expect("queue mutex is healthy");
        assert_eq!(snapshot.ordinary_active_v1(), 1);
        assert_eq!(snapshot.admitted_count_v1(), 1);
        assert_eq!(snapshot.coalesced_count_v1(), 512);

        leader
            .complete_v1(AuthorityQueueCompletionV1::CommittedRetained)
            .expect("leader publishes completion");
        for (follower, deadline) in followers {
            assert_eq!(
                follower
                    .wait_v1(deadline, &clock)
                    .expect("completed follower remains before deadline"),
                AuthorityQueueCompletionV1::CommittedRetained
            );
        }
        assert_eq!(
            queue
                .snapshot_v1()
                .expect("queue mutex is healthy")
                .ordinary_active_v1(),
            0
        );
        assert_eq!(
            format!("{:?}", AuthorityQueueCompletionV1::CommittedRetained),
            "COMMITTED_RETAINED"
        );
    }

    #[test]
    fn concurrent_exact_duplicates_have_one_leader_and_no_extra_slots() {
        const CONCURRENCY: usize = 32;
        let queue = Arc::new(AuthorityAdmissionQueueV1::new_v1());
        let clock = Arc::new(ControlledClockV1::new_v1(10));
        let barrier = Arc::new(Barrier::new(CONCURRENCY));
        let leader_count = Arc::new(AtomicUsize::new(0));
        let identity = identity_v1(AuthorityAdmissionClassV1::DecisionRetain, 99);

        let handles: Vec<_> = (0..CONCURRENCY)
            .map(|_| {
                let queue = Arc::clone(&queue);
                let clock = Arc::clone(&clock);
                let barrier = Arc::clone(&barrier);
                let leader_count = Arc::clone(&leader_count);
                thread::spawn(move || {
                    let admission = queue
                        .admit_identity_v1(identity, deadline_v1(&clock), clock.as_ref())
                        .expect("concurrent admission remains healthy");
                    barrier.wait();
                    match admission {
                        AuthorityQueueAdmissionV1::Leader { permit, .. } => {
                            leader_count.fetch_add(1, Ordering::SeqCst);
                            permit
                                .complete_v1(AuthorityQueueCompletionV1::DeniedDefinite)
                                .expect("leader completes");
                            AuthorityQueueCompletionV1::DeniedDefinite
                        }
                        AuthorityQueueAdmissionV1::Coalesced { follower, deadline } => follower
                            .wait_v1(deadline, clock.as_ref())
                            .expect("follower observes leader"),
                        AuthorityQueueAdmissionV1::RefusedAtCapacity { .. } => {
                            panic!("duplicates never consume extra capacity")
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            assert_eq!(
                handle.join().expect("queue worker does not panic"),
                AuthorityQueueCompletionV1::DeniedDefinite
            );
        }
        assert_eq!(leader_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            queue
                .snapshot_v1()
                .expect("queue mutex is healthy")
                .ordinary_active_v1(),
            0
        );
    }

    #[test]
    fn expired_deadlines_never_admit_or_escape_a_coalesced_wait() {
        let queue = AuthorityAdmissionQueueV1::new_v1();
        let clock = ControlledClockV1::new_v1(100);
        let identity = identity_v1(AuthorityAdmissionClassV1::RootLeaseIssue, 1);
        let stale = capture_authority_deadline_v1(&clock, safe(200), safe(200), safe(200))
            .expect("deadline starts current");
        clock.set_v1(200);
        assert_eq!(
            queue
                .admit_identity_v1(identity, stale, &clock)
                .expect_err("equality with the exclusive deadline denies")
                .deadline_error_v1(),
            Some(AuthorityControlErrorV1::DeadlineReached)
        );
        assert_eq!(
            queue
                .snapshot_v1()
                .expect("queue mutex is healthy")
                .ordinary_active_v1(),
            0
        );

        clock.set_v1(100);
        let leader = take_leader_v1(
            queue
                .admit_identity_v1(identity, deadline_v1(&clock), &clock)
                .expect("leader is admitted before deadline"),
        );
        let (follower, follower_deadline) = match queue
            .admit_identity_v1(identity, deadline_v1(&clock), &clock)
            .expect("duplicate coalesces before deadline")
        {
            AuthorityQueueAdmissionV1::Coalesced { follower, deadline } => (follower, deadline),
            other => panic!("expected follower, got {other:?}"),
        };
        clock.set_v1(DEADLINE_MS);
        assert_eq!(
            follower
                .wait_v1(follower_deadline, &clock)
                .expect_err("coalesced waits preserve the original exclusive bound")
                .deadline_error_v1(),
            Some(AuthorityControlErrorV1::DeadlineReached)
        );
        drop(leader);
    }

    #[test]
    fn admission_mutex_wait_cannot_reuse_a_pre_deadline_sample() {
        let queue = Arc::new(AuthorityAdmissionQueueV1::new_v1());
        let clock = Arc::new(ControlledClockV1::new_v1(100));
        let deadline = capture_authority_deadline_v1(&*clock, safe(200), safe(200), safe(200))
            .expect("deadline starts current");
        let captures_before_wait = clock.capture_count_v1();
        let state_guard = queue
            .inner
            .state
            .lock()
            .expect("queue mutex starts healthy");

        let worker_queue = Arc::clone(&queue);
        let worker_clock = Arc::clone(&clock);
        let worker = thread::spawn(move || {
            worker_queue.admit_identity_v1(
                identity_v1(AuthorityAdmissionClassV1::RootLeaseIssue, 40_001),
                deadline,
                worker_clock.as_ref(),
            )
        });

        wait_for_capture_after_v1(&clock, captures_before_wait);
        let captures_before_expiry = clock.capture_count_v1();
        clock.set_v1(200);
        wait_for_capture_after_v1(&clock, captures_before_expiry);
        drop(state_guard);

        assert_eq!(
            worker
                .join()
                .expect("admission worker does not panic")
                .expect_err("a mutex wait cannot preserve stale deadline authority")
                .deadline_error_v1(),
            Some(AuthorityControlErrorV1::DeadlineReached)
        );
        assert_eq!(
            queue
                .snapshot_v1()
                .expect("queue mutex remains healthy")
                .ordinary_active_v1(),
            0
        );
    }

    #[test]
    fn completed_follower_mutex_wait_cannot_escape_after_deadline() {
        let queue = AuthorityAdmissionQueueV1::new_v1();
        let clock = Arc::new(ControlledClockV1::new_v1(100));
        let identity = identity_v1(AuthorityAdmissionClassV1::RootLeaseIssue, 40_002);
        let leader = take_leader_v1(
            queue
                .admit_identity_v1(identity, deadline_v1(&clock), clock.as_ref())
                .expect("leader is admitted before deadline"),
        );
        let follower_deadline =
            capture_authority_deadline_v1(&*clock, safe(200), safe(200), safe(200))
                .expect("follower deadline starts current");
        let follower = match queue
            .admit_identity_v1(identity, deadline_v1(&clock), clock.as_ref())
            .expect("duplicate coalesces before deadline")
        {
            AuthorityQueueAdmissionV1::Coalesced { follower, .. } => follower,
            other => panic!("expected follower, got {other:?}"),
        };
        leader
            .complete_v1(AuthorityQueueCompletionV1::CommittedRetained)
            .expect("leader publishes a closed completion");

        let entry = Arc::clone(&follower.entry);
        let completion_guard = entry
            .completion
            .lock()
            .expect("completion mutex starts healthy");
        let captures_before_wait = clock.capture_count_v1();
        let worker_clock = Arc::clone(&clock);
        let worker =
            thread::spawn(move || follower.wait_v1(follower_deadline, worker_clock.as_ref()));

        wait_for_capture_after_v1(&clock, captures_before_wait);
        let captures_before_expiry = clock.capture_count_v1();
        clock.set_v1(200);
        wait_for_capture_after_v1(&clock, captures_before_expiry);
        drop(completion_guard);

        assert_eq!(
            worker
                .join()
                .expect("follower worker does not panic")
                .expect_err("a completion mutex wait cannot escape after deadline")
                .deadline_error_v1(),
            Some(AuthorityControlErrorV1::DeadlineReached)
        );
    }

    #[test]
    fn attempt_deadline_cannot_be_renewed_and_control_kinds_are_reserved() {
        let queue = AuthorityAdmissionQueueV1::new_v1();
        let clock = ControlledClockV1::new_v1(10);
        let attempt = attempt_v1(AuthorityOperationKindV1::AuthorityRevoke, 1, 500);
        let renewed = capture_authority_deadline_v1(&clock, safe(600), safe(600), safe(600))
            .expect("later deadline is otherwise current");
        assert_eq!(
            queue
                .admit_attempt_v1(&attempt, renewed, &clock)
                .expect_err("queue rejects deadline renewal")
                .deadline_error_v1(),
            Some(AuthorityControlErrorV1::InvalidAbsoluteDeadline)
        );

        let exact = capture_authority_deadline_v1(&clock, safe(500), safe(500), safe(500))
            .expect("attempt deadline is current");
        let admission = queue
            .admit_attempt_v1(&attempt, exact, &clock)
            .expect("revocation uses reserved control capacity");
        assert_eq!(
            admission.lane_v1(),
            AuthorityAdmissionLaneV1::ReservedControl
        );
        drop(admission);

        let unsupported = attempt_v1(AuthorityOperationKindV1::BackupPublish, 2, 500);
        assert_eq!(
            queue
                .admit_attempt_v1(&unsupported, deadline_v1(&clock), &clock)
                .expect_err("maintenance cannot borrow either runtime lane"),
            AuthorityQueueErrorV1::UnsupportedOperation
        );
    }
}
