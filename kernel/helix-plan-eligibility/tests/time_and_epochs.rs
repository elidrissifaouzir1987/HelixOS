mod common;

use common::*;
use helix_contracts::Sha256Digest;
use helix_plan_eligibility::{
    EligibilityContextV1, EligibilityDenialV1, MonotonicClockViewV1, PlanDeadlineViewV1,
    SupervisorAdmissionStateV1, SupervisorViewV1, WallClockViewV1,
};

fn assert_eligible(fixture: EligibilityFixture) {
    let claimant = ClaimantProbe::default();
    let _eligible = fixture
        .evaluate(&claimant)
        .expect("boundary fixture must be eligible");
    assert_eq!(claimant.calls(), 1);
}

#[test]
fn context_health_and_supervisor_statuses_fail_closed_before_claim() {
    for (context, expected) in [
        (
            EligibilityContextV1::Unavailable,
            EligibilityDenialV1::ContextUnavailable,
        ),
        (
            EligibilityContextV1::Incomplete,
            EligibilityDenialV1::ContextIncomplete,
        ),
        (EligibilityContextV1::Torn, EligibilityDenialV1::ContextTorn),
    ] {
        assert_preclaim_denial(fixture_with_context(context), expected);
    }

    for (view, expected) in [
        (
            SupervisorViewV1::Unavailable,
            EligibilityDenialV1::SupervisorUnavailable,
        ),
        (
            SupervisorViewV1::Inconsistent,
            EligibilityDenialV1::SupervisorInconsistent,
        ),
    ] {
        assert_preclaim_denial(
            ready_fixture_with(|_, input| input.supervisor = view),
            expected,
        );
    }

    for state in [
        SupervisorAdmissionStateV1::Paused,
        SupervisorAdmissionStateV1::Aborting,
        SupervisorAdmissionStateV1::Halted,
        SupervisorAdmissionStateV1::Restoring,
    ] {
        assert_preclaim_denial(
            ready_fixture_with(|_, input| {
                input.supervisor = supervisor(state, BOOT_ID, INSTANCE_EPOCH, FENCING_EPOCH);
            }),
            EligibilityDenialV1::SupervisorNotOpen,
        );
    }
}

#[test]
fn wall_and_utc_half_open_boundaries_are_exact() {
    for (wall, expected) in [
        (
            WallClockViewV1::Unavailable,
            EligibilityDenialV1::WallClockUnavailable,
        ),
        (
            WallClockViewV1::RollbackSuspected,
            EligibilityDenialV1::WallClockRollbackSuspected,
        ),
    ] {
        assert_preclaim_denial(
            ready_fixture_with(|_, input| {
                input.time = time_view(wall, monotonic_sample(BOOT_ID, NOW_MONOTONIC_MS));
            }),
            expected,
        );
    }

    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.time = healthy_time(ISSUED_AT_MS - 1, BOOT_ID, NOW_MONOTONIC_MS);
        }),
        EligibilityDenialV1::PlanNotYetValid,
    );
    assert_eligible(ready_fixture_with(|_, input| {
        input.time = healthy_time(ISSUED_AT_MS, BOOT_ID, NOW_MONOTONIC_MS);
    }));
    assert_eligible(ready_fixture_with(|_, input| {
        input.time = healthy_time(EXPIRES_AT_MS - 1, BOOT_ID, NOW_MONOTONIC_MS);
    }));
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.time = healthy_time(EXPIRES_AT_MS, BOOT_ID, NOW_MONOTONIC_MS);
        }),
        EligibilityDenialV1::PlanExpired,
    );
}

#[test]
fn reboot_monotonic_health_and_deadline_statuses_are_exact() {
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.time = healthy_time(NOW_UTC_MS, OTHER_BOOT_ID, NOW_MONOTONIC_MS);
        }),
        EligibilityDenialV1::BootMismatch,
    );
    for (monotonic, expected) in [
        (
            MonotonicClockViewV1::Unavailable,
            EligibilityDenialV1::MonotonicClockUnavailable,
        ),
        (
            MonotonicClockViewV1::NotSuspendAware,
            EligibilityDenialV1::MonotonicClockUnsuitable,
        ),
        (
            MonotonicClockViewV1::Regressed,
            EligibilityDenialV1::MonotonicClockRegressed,
        ),
    ] {
        assert_preclaim_denial(
            ready_fixture_with(|_, input| {
                input.time = time_view(
                    WallClockViewV1::healthy(NOW_UTC_MS).expect("safe wall time"),
                    monotonic,
                );
            }),
            expected,
        );
    }
    for deadline in [PlanDeadlineViewV1::Missing, PlanDeadlineViewV1::Unavailable] {
        assert_preclaim_denial(
            ready_fixture_with(|_, input| input.plan_deadline = deadline),
            EligibilityDenialV1::PlanDeadlineUnavailable,
        );
    }
    assert_preclaim_denial(
        ready_fixture_with(|_, input| input.plan_deadline = PlanDeadlineViewV1::Inconsistent),
        EligibilityDenialV1::PlanDeadlineInconsistent,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.plan_deadline = plan_deadline(
                Sha256Digest::digest(b"another plan"),
                BOOT_ID,
                PLAN_DEADLINE_MS,
            );
        }),
        EligibilityDenialV1::PlanDeadlineMismatch,
    );
    assert_preclaim_denial(
        ready_fixture_with(|plan, input| {
            input.plan_deadline = plan_deadline(plan.plan_id(), OTHER_BOOT_ID, PLAN_DEADLINE_MS);
        }),
        EligibilityDenialV1::PlanDeadlineMismatch,
    );
    assert_preclaim_denial(
        ready_fixture_with(|_, input| {
            input.time = healthy_time(NOW_UTC_MS, BOOT_ID, PLAN_DEADLINE_MS);
        }),
        EligibilityDenialV1::MonotonicDeadlineReached,
    );
}

#[test]
fn instance_and_fencing_epochs_reject_stale_and_ahead_values() {
    for instance_epoch in [INSTANCE_EPOCH - 1, INSTANCE_EPOCH + 1] {
        assert_preclaim_denial(
            ready_fixture_with(|_, input| {
                input.supervisor = supervisor(
                    SupervisorAdmissionStateV1::Open,
                    BOOT_ID,
                    instance_epoch,
                    FENCING_EPOCH,
                );
            }),
            EligibilityDenialV1::InstanceEpochMismatch,
        );
    }
    for fencing_epoch in [FENCING_EPOCH - 1, FENCING_EPOCH + 1] {
        assert_preclaim_denial(
            ready_fixture_with(|_, input| {
                input.supervisor = supervisor(
                    SupervisorAdmissionStateV1::Open,
                    BOOT_ID,
                    INSTANCE_EPOCH,
                    fencing_epoch,
                );
            }),
            EligibilityDenialV1::FencingEpochMismatch,
        );
    }
    assert_eligible(coherent_fixture());
}
