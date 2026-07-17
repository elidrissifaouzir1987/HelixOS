//! SQLite-owned projection of the explicit PLAN-006 fault phase carrier.
//!
//! This entire module is absent from default builds. It delegates to the portable
//! feature-only probe and accepts only phases owned by the HLXA adapter.

#![allow(dead_code)] // Concrete checkpoints land with their owning transaction tasks.

use helix_task_authority::{
    AuthorityFaultDecisionV1, AuthorityFaultModeV1, AuthorityFaultProbeV1,
    AuthorityFaultSelectionErrorV1,
};
use std::fmt;

const SQLITE_FAULT_PHASE_IDS_V1: [&str; 9] = [
    "P01-ROOT-ISSUE",
    "P02-DELEGATION",
    "P03-COUNTER",
    "P04-DECISION",
    "P05-TRUST-REVOCATION",
    "P07-BOOTSTRAP",
    "P08-BACKUP",
    "P09-RESTORE",
    "P10-CORRUPTION-READBACK",
];

/// Closed signal forcing the selected adapter operation to stop at its checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SqliteAuthorityFaultReachedV1;

/// Explicit feature-only carrier for HLXA-owned phases.
#[derive(Clone, Default)]
pub(crate) struct SqliteAuthorityFaultProbeV1 {
    inner: AuthorityFaultProbeV1,
}

impl SqliteAuthorityFaultProbeV1 {
    pub(crate) fn disabled_v1() -> Self {
        Self::default()
    }

    pub(crate) fn selected_phase_v1<F>(
        phase_id: &str,
        occurrence: u64,
        mode: AuthorityFaultModeV1,
        process_barrier: F,
    ) -> Result<Self, AuthorityFaultSelectionErrorV1>
    where
        F: FnMut() + Send + 'static,
    {
        if !SQLITE_FAULT_PHASE_IDS_V1.contains(&phase_id) {
            return Err(AuthorityFaultSelectionErrorV1::UnknownPhase);
        }
        AuthorityFaultProbeV1::selected_phase_v1(phase_id, occurrence, mode, process_barrier)
            .map(|inner| Self { inner })
    }

    /// Uses the same reach path for both models and fails closed if a kill callback returns.
    pub(crate) fn checkpoint_phase_v1(
        &self,
        phase_id: &str,
    ) -> Result<(), SqliteAuthorityFaultReachedV1> {
        if !SQLITE_FAULT_PHASE_IDS_V1.contains(&phase_id) {
            return Err(SqliteAuthorityFaultReachedV1);
        }
        match self.inner.reach_phase_id_v1(phase_id) {
            Ok(AuthorityFaultDecisionV1::Continue) => Ok(()),
            Ok(
                AuthorityFaultDecisionV1::InjectInProcess
                | AuthorityFaultDecisionV1::ProcessBarrierReached,
            )
            | Err(_) => Err(SqliteAuthorityFaultReachedV1),
        }
    }

    pub(crate) fn injected_v1(&self) -> Result<bool, SqliteAuthorityFaultReachedV1> {
        self.inner
            .injected_v1()
            .map_err(|_| SqliteAuthorityFaultReachedV1)
    }
}

impl fmt::Debug for SqliteAuthorityFaultProbeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteAuthorityFaultProbeV1")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn projection_accepts_only_sqlite_owned_phases() {
        assert_eq!(SQLITE_FAULT_PHASE_IDS_V1.len(), 9);
        for rejected in ["P00-CONTRACT", "P06-PROJECTION-GUARD", "unknown"] {
            assert_eq!(
                SqliteAuthorityFaultProbeV1::selected_phase_v1(
                    rejected,
                    1,
                    AuthorityFaultModeV1::InProcess,
                    || {},
                )
                .unwrap_err(),
                AuthorityFaultSelectionErrorV1::UnknownPhase
            );
        }
        assert_eq!(
            SqliteAuthorityFaultProbeV1::selected_phase_v1(
                "P10-CORRUPTION-READBACK",
                1,
                AuthorityFaultModeV1::ProcessKill,
                || {},
            )
            .unwrap_err(),
            AuthorityFaultSelectionErrorV1::UnsupportedFaultModel
        );
    }

    #[test]
    fn both_models_stop_through_one_checkpoint_path() {
        let in_process = SqliteAuthorityFaultProbeV1::selected_phase_v1(
            "P05-TRUST-REVOCATION",
            1,
            AuthorityFaultModeV1::InProcess,
            || {},
        )
        .expect("SQLite phase selects");
        assert_eq!(
            in_process.checkpoint_phase_v1("P05-TRUST-REVOCATION"),
            Err(SqliteAuthorityFaultReachedV1)
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let process = SqliteAuthorityFaultProbeV1::selected_phase_v1(
            "P07-BOOTSTRAP",
            1,
            AuthorityFaultModeV1::ProcessKill,
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("SQLite process phase selects");
        assert_eq!(
            process.checkpoint_phase_v1("P07-BOOTSTRAP"),
            Err(SqliteAuthorityFaultReachedV1)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(process.injected_v1(), Ok(true));
    }

    #[test]
    fn disabled_probe_is_inert() {
        let probe = SqliteAuthorityFaultProbeV1::disabled_v1();
        assert_eq!(probe.checkpoint_phase_v1("P03-COUNTER"), Ok(()));
        assert_eq!(probe.injected_v1(), Ok(false));
    }
}
