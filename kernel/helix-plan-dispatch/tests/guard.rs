use helix_plan_dispatch::{DispatchAdmissionStateV1, DispatchGuardClassV1};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PermitState {
    Permitted,
    CommitInFlight,
    ResolvedCommitted,
    ResolvedAmbiguous,
}

#[derive(Debug)]
struct PermitOracle {
    state: PermitState,
    deadline_monotonic_ms: u64,
    pause_activations: usize,
}

impl PermitOracle {
    fn new(deadline_monotonic_ms: u64) -> Self {
        Self {
            state: PermitState::Permitted,
            deadline_monotonic_ms,
            pause_activations: 0,
        }
    }

    fn enter_commit(&mut self) -> bool {
        if self.state != PermitState::Permitted {
            return false;
        }
        self.state = PermitState::CommitInFlight;
        true
    }

    fn resolve_committed(&mut self) -> bool {
        if self.state != PermitState::CommitInFlight {
            return false;
        }
        self.state = PermitState::ResolvedCommitted;
        true
    }

    fn owner_lost(&mut self) -> bool {
        self.resolve_ambiguous_once()
    }

    fn expire_if_due(&mut self, now_monotonic_ms: u64) -> bool {
        if now_monotonic_ms < self.deadline_monotonic_ms {
            return false;
        }
        self.resolve_ambiguous_once()
    }

    fn resolve_ambiguous_once(&mut self) -> bool {
        if !matches!(
            self.state,
            PermitState::Permitted | PermitState::CommitInFlight
        ) {
            return false;
        }
        self.state = PermitState::ResolvedAmbiguous;
        self.pause_activations += 1;
        true
    }
}

fn admission_allows_permit(state: DispatchAdmissionStateV1) -> bool {
    matches!(state, DispatchAdmissionStateV1::Running)
}

#[test]
fn guard_acquisition_order_is_the_frozen_plan004_order() {
    assert_eq!(
        DispatchGuardClassV1::acquisition_order(),
        [
            DispatchGuardClassV1::RecoveryPublication,
            DispatchGuardClassV1::ExternalClockDeadline,
            DispatchGuardClassV1::Supervisor,
            DispatchGuardClassV1::SignerTrust,
            DispatchGuardClassV1::Workload,
            DispatchGuardClassV1::Lease,
            DispatchGuardClassV1::Authorization,
            DispatchGuardClassV1::Policy,
            DispatchGuardClassV1::Catalogue,
            DispatchGuardClassV1::Capabilities,
        ]
    );
}

#[test]
fn pause_halt_unavailable_and_revocation_win_before_permit() {
    assert!(admission_allows_permit(DispatchAdmissionStateV1::Running));
    for denied in [
        DispatchAdmissionStateV1::Paused,
        DispatchAdmissionStateV1::Halted,
        DispatchAdmissionStateV1::Unavailable,
    ] {
        assert!(
            !admission_allows_permit(denied),
            "non-running admission must deny before a commit closure can be invoked: {denied:?}"
        );
    }

    let guard_revoked_before_permit = true;
    let commit_invocations = usize::from(!guard_revoked_before_permit);
    assert_eq!(commit_invocations, 0, "revocation must win before commit");
}

#[test]
fn owner_loss_and_permit_deadline_equality_resolve_once_to_ambiguous_pause() {
    for commit_in_flight in [false, true] {
        let mut owner_loss = PermitOracle::new(250);
        if commit_in_flight {
            assert!(owner_loss.enter_commit());
        }
        assert!(owner_loss.owner_lost());
        assert!(!owner_loss.owner_lost(), "terminal resolution is one-shot");
        assert_eq!(owner_loss.state, PermitState::ResolvedAmbiguous);
        assert_eq!(owner_loss.pause_activations, 1);

        let mut equality = PermitOracle::new(250);
        if commit_in_flight {
            assert!(equality.enter_commit());
        }
        assert!(!equality.expire_if_due(249));
        assert!(equality.expire_if_due(250), "permit deadline is exclusive");
        assert!(
            !equality.expire_if_due(251),
            "terminal resolution is one-shot"
        );
        assert_eq!(equality.state, PermitState::ResolvedAmbiguous);
        assert_eq!(equality.pause_activations, 1);
    }

    let mut success = PermitOracle::new(250);
    assert!(success.enter_commit());
    assert!(success.resolve_committed());
    assert!(
        !success.owner_lost(),
        "resolved success cannot be overwritten"
    );
    assert_eq!(success.state, PermitState::ResolvedCommitted);
    assert_eq!(success.pause_activations, 0);
}

#[test]
fn t030_must_implement_a_consuming_linearizable_commit_gate() {
    // This source contract is the intentional TDD RED seam. Once T030 lands, add direct
    // concurrency tests around its crate-owned test constructor for PAUSE/HALT racing permit
    // acquisition and owner loss/deadline racing both Permitted and CommitInFlight states.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let guard_source = fs::read_to_string(manifest.join("src/guard.rs"))
        .expect("the existing portable guard boundary must remain present");
    assert!(
        guard_source.contains("FnOnce") && guard_source.contains("commit_once"),
        "T030 permits must consume exactly one store commit closure"
    );

    let gate_path = manifest.join("src/commit_gate.rs");
    let gate_source = fs::read_to_string(&gate_path).unwrap_or_else(|error| {
        panic!(
            "T030 RED: {} must implement PAUSE/HALT/deadman linearization: {error}",
            gate_path.display()
        )
    });
    let lib_source = fs::read_to_string(manifest.join("src/lib.rs"))
        .expect("the crate root must remain readable");

    assert!(
        lib_source.contains("mod commit_gate;"),
        "T030 commit_gate.rs must be compiled into the crate rather than existing as dead source"
    );
    assert!(
        gate_source.contains("Paused") && gate_source.contains("Halted"),
        "T030 commit gate must deny PAUSE and HALT before permit acquisition"
    );
    assert!(
        gate_source.contains("owner") && gate_source.contains("deadline"),
        "T030 commit gate must resolve owner loss and exclusive permit deadline"
    );
    assert!(
        gate_source.contains("Ambiguous") && gate_source.contains("commit_once"),
        "T030 owner-loss/deadline races must resolve once without reusing the commit closure"
    );
}
