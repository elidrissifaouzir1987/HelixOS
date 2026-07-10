mod common;

use common::*;
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use helix_plan_eligibility::{
    CapabilityRecordInputV1, CapabilityRecordV1, CapabilityViewV1, EligibilityContextBuildErrorV1,
    EligibilityDenialV1, MonotonicClockViewV1, PlanDeadlineViewV1, PlanDecisionEvidenceInputV1,
    PlanDecisionEvidenceV1, PolicyDecisionV1, PolicyRecordInputV1, PolicyRecordV1, PolicyViewV1,
    SignerTrustViewV1, SupervisorAdmissionStateV1, SupervisorViewV1, WallClockViewV1,
    WorkloadIdentityViewV1,
};
use proptest::prelude::*;
use std::sync::OnceLock;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn utc_half_open_interval_classifies_every_safe_sample(
        now_utc_ms in prop_oneof![
            0..ISSUED_AT_MS,
            ISSUED_AT_MS..EXPIRES_AT_MS,
            EXPIRES_AT_MS..=MAX_SAFE_U64,
        ],
    ) {
        let fixture = ready_fixture_with(|_, input| {
            input.time = healthy_time(now_utc_ms, BOOT_ID, NOW_MONOTONIC_MS);
        });
        let (outcome, calls) = evaluate_outcome(fixture);

        if now_utc_ms < ISSUED_AT_MS {
            prop_assert_eq!(outcome, Err(EligibilityDenialV1::PlanNotYetValid));
            prop_assert_eq!(calls, 0);
        } else if now_utc_ms >= EXPIRES_AT_MS {
            prop_assert_eq!(outcome, Err(EligibilityDenialV1::PlanExpired));
            prop_assert_eq!(calls, 0);
        } else {
            prop_assert_eq!(outcome, Ok(()));
            prop_assert_eq!(calls, 1);
        }
    }

    #[test]
    fn monotonic_deadline_is_exclusive_for_every_safe_sample(
        now_monotonic_ms in prop_oneof![
            0..PLAN_DEADLINE_MS,
            PLAN_DEADLINE_MS..=MAX_SAFE_U64,
        ],
    ) {
        let fixture = ready_fixture_with(|_, input| {
            input.time = healthy_time(NOW_UTC_MS, BOOT_ID, now_monotonic_ms);
        });
        let (outcome, calls) = evaluate_outcome(fixture);

        if now_monotonic_ms < PLAN_DEADLINE_MS {
            prop_assert_eq!(outcome, Ok(()));
            prop_assert_eq!(calls, 1);
        } else {
            prop_assert_eq!(outcome, Err(EligibilityDenialV1::MonotonicDeadlineReached));
            prop_assert_eq!(calls, 0);
        }
    }

    #[test]
    fn clock_terminal_state_has_exact_first_code_and_never_claims(tag in 0_u8..5) {
        let (fixture, expected) = match tag {
            0 => (
                ready_fixture_with(|_, input| {
                    input.time = time_view(
                        WallClockViewV1::Unavailable,
                        monotonic_sample(BOOT_ID, NOW_MONOTONIC_MS),
                    );
                }),
                EligibilityDenialV1::WallClockUnavailable,
            ),
            1 => (
                ready_fixture_with(|_, input| {
                    input.time = time_view(
                        WallClockViewV1::RollbackSuspected,
                        monotonic_sample(BOOT_ID, NOW_MONOTONIC_MS),
                    );
                }),
                EligibilityDenialV1::WallClockRollbackSuspected,
            ),
            2 => (
                ready_fixture_with(|_, input| {
                    input.time = time_view(
                        WallClockViewV1::healthy(NOW_UTC_MS).expect("safe fixture time"),
                        MonotonicClockViewV1::Unavailable,
                    );
                }),
                EligibilityDenialV1::MonotonicClockUnavailable,
            ),
            3 => (
                ready_fixture_with(|_, input| {
                    input.time = time_view(
                        WallClockViewV1::healthy(NOW_UTC_MS).expect("safe fixture time"),
                        MonotonicClockViewV1::NotSuspendAware,
                    );
                }),
                EligibilityDenialV1::MonotonicClockUnsuitable,
            ),
            _ => (
                ready_fixture_with(|_, input| {
                    input.time = time_view(
                        WallClockViewV1::healthy(NOW_UTC_MS).expect("safe fixture time"),
                        MonotonicClockViewV1::Regressed,
                    );
                }),
                EligibilityDenialV1::MonotonicClockRegressed,
            ),
        };

        let (outcome, calls) = evaluate_outcome(fixture);
        prop_assert_eq!(outcome, Err(expected));
        prop_assert_eq!(calls, 0);
    }

    #[test]
    fn stale_or_ahead_epoch_never_claims(
        (mutate_instance, epoch) in (any::<bool>(), 0_u64..=MAX_SAFE_U64).prop_filter(
            "epoch must differ from its coherent value",
            |(mutate_instance, value)| if *mutate_instance {
                *value != INSTANCE_EPOCH
            } else {
                *value != FENCING_EPOCH
            },
        ),
    ) {
        let fixture = ready_fixture_with(|_, input| {
            let (instance, fencing) = if mutate_instance {
                (epoch, FENCING_EPOCH)
            } else {
                (INSTANCE_EPOCH, epoch)
            };
            input.supervisor = supervisor(
                SupervisorAdmissionStateV1::Open,
                BOOT_ID,
                instance,
                fencing,
            );
        });
        let expected = if mutate_instance {
            EligibilityDenialV1::InstanceEpochMismatch
        } else {
            EligibilityDenialV1::FencingEpochMismatch
        };
        let (outcome, calls) = evaluate_outcome(fixture);
        prop_assert_eq!(outcome, Err(expected));
        prop_assert_eq!(calls, 0);
    }

    #[test]
    fn capability_subset_obeys_required_then_mandatory_precedence(mask in 0_u8..8) {
        let available = available_subset(mask);
        let fixture = ready_fixture_with(|plan, input| {
            input.policy = policy_view(plan.plan_id(), CAPABILITY_MAX_AGE_MS, durable_mandatory());
            input.capabilities = capability_view(plan, available);
        });
        let has_atomic = mask & 0b001 != 0;
        let has_durable = mask & 0b010 != 0;
        let has_verify = mask & 0b100 != 0;
        let (outcome, calls) = evaluate_outcome(fixture);

        if !has_atomic || !has_verify {
            prop_assert_eq!(outcome, Err(EligibilityDenialV1::RequiredCapabilityMissing));
            prop_assert_eq!(calls, 0);
        } else if !has_durable {
            prop_assert_eq!(outcome, Err(EligibilityDenialV1::MandatoryCapabilityMissing));
            prop_assert_eq!(calls, 0);
        } else {
            prop_assert_eq!(outcome, Ok(()));
            prop_assert_eq!(calls, 1);
        }
    }

    #[test]
    fn capability_freshness_accepts_exact_maximum_and_denies_one_older(
        max_age_ms in 0_u64..=CAPABILITY_MAX_AGE_MS,
    ) {
        let actual_age = NOW_UTC_MS - (ISSUED_AT_MS - 1_000);
        let fixture = ready_fixture_with(|plan, input| {
            input.policy = policy_view(plan.plan_id(), max_age_ms, atomic_mandatory());
        });
        let (outcome, calls) = evaluate_outcome(fixture);

        if actual_age <= max_age_ms {
            prop_assert_eq!(outcome, Ok(()));
            prop_assert_eq!(calls, 1);
        } else {
            prop_assert_eq!(outcome, Err(EligibilityDenialV1::CapabilityStale));
            prop_assert_eq!(calls, 0);
        }
    }

    #[test]
    fn generated_multi_faults_always_return_normative_first_code(mask in 1_u8..128) {
        let fixture = ready_fixture_with(|_, input| {
            if mask & 0b000_0001 != 0 {
                input.bound_plan_id = Sha256Digest::digest(b"precedence-other-plan");
            }
            if mask & 0b000_0010 != 0 {
                input.supervisor = SupervisorViewV1::Unavailable;
            } else if mask & 0b010_0000 != 0 {
                input.supervisor = supervisor(
                    SupervisorAdmissionStateV1::Open,
                    BOOT_ID,
                    INSTANCE_EPOCH + 1,
                    FENCING_EPOCH,
                );
            }
            if mask & 0b000_0100 != 0 {
                input.time = time_view(
                    WallClockViewV1::Unavailable,
                    MonotonicClockViewV1::Unavailable,
                );
            } else if mask & 0b000_1000 != 0 {
                input.time = time_view(
                    WallClockViewV1::healthy(NOW_UTC_MS).expect("safe fixture time"),
                    MonotonicClockViewV1::Unavailable,
                );
            }
            if mask & 0b001_0000 != 0 {
                input.plan_deadline = PlanDeadlineViewV1::Inconsistent;
            }
            if mask & 0b100_0000 != 0 {
                input.capabilities = CapabilityViewV1::Unavailable;
            }
        });

        let expected = if mask & 0b000_0001 != 0 {
            EligibilityDenialV1::ContextPlanMismatch
        } else if mask & 0b000_0010 != 0 {
            EligibilityDenialV1::SupervisorUnavailable
        } else if mask & 0b000_0100 != 0 {
            EligibilityDenialV1::WallClockUnavailable
        } else if mask & 0b000_1000 != 0 {
            EligibilityDenialV1::MonotonicClockUnavailable
        } else if mask & 0b001_0000 != 0 {
            EligibilityDenialV1::PlanDeadlineInconsistent
        } else if mask & 0b010_0000 != 0 {
            EligibilityDenialV1::InstanceEpochMismatch
        } else {
            EligibilityDenialV1::CapabilityUnavailable
        };
        let (outcome, calls) = evaluate_outcome(fixture);
        prop_assert_eq!(outcome, Err(expected));
        prop_assert_eq!(calls, 0);
    }

    #[test]
    fn unsafe_integer_inputs_fail_checked_construction_without_claiming(
        value in (MAX_SAFE_U64 + 1)..=u64::MAX,
    ) {
        let claimant = ClaimantProbe::default();
        let error = WallClockViewV1::healthy(value)
            .expect_err("outside-safe-range wall input must fail construction");
        prop_assert_eq!(error, EligibilityContextBuildErrorV1::IntegerOutOfRange);
        prop_assert_eq!(claimant.calls(), 0);
    }
}

#[test]
fn each_major_binding_mutation_has_a_stable_preclaim_oracle() {
    for fault in 0_u8..14 {
        let fixture = ready_fixture_with(|_, input| match fault {
            0 => input.bound_plan_id = digest(b"mutation-other-plan"),
            1 => input.supervisor = SupervisorViewV1::Unavailable,
            2 => {
                input.time = time_view(
                    WallClockViewV1::RollbackSuspected,
                    monotonic_sample(BOOT_ID, NOW_MONOTONIC_MS),
                );
            }
            3 => {
                input.time = time_view(
                    WallClockViewV1::healthy(NOW_UTC_MS).expect("safe fixture time"),
                    MonotonicClockViewV1::Regressed,
                );
            }
            4 => input.plan_deadline = PlanDeadlineViewV1::Inconsistent,
            5 => {
                input.supervisor = supervisor(
                    SupervisorAdmissionStateV1::Open,
                    BOOT_ID,
                    INSTANCE_EPOCH + 1,
                    FENCING_EPOCH,
                );
            }
            6 => {
                input.supervisor = supervisor(
                    SupervisorAdmissionStateV1::Open,
                    BOOT_ID,
                    INSTANCE_EPOCH,
                    FENCING_EPOCH + 1,
                );
            }
            7 => input.signer = SignerTrustViewV1::Unavailable,
            8 => input.workload = WorkloadIdentityViewV1::Unavailable,
            9 => input.lease = helix_plan_eligibility::LeaseResolutionV1::Unavailable,
            10 => input.authorization = helix_plan_eligibility::AuthorizationViewV1::Unavailable,
            11 => input.policy = PolicyViewV1::Unavailable,
            12 => input.catalogue = helix_plan_eligibility::CatalogueViewV1::Unavailable,
            _ => input.capabilities = CapabilityViewV1::Unavailable,
        });
        let expected = [
            EligibilityDenialV1::ContextPlanMismatch,
            EligibilityDenialV1::SupervisorUnavailable,
            EligibilityDenialV1::WallClockRollbackSuspected,
            EligibilityDenialV1::MonotonicClockRegressed,
            EligibilityDenialV1::PlanDeadlineInconsistent,
            EligibilityDenialV1::InstanceEpochMismatch,
            EligibilityDenialV1::FencingEpochMismatch,
            EligibilityDenialV1::SignerTrustUnavailable,
            EligibilityDenialV1::WorkloadUnavailable,
            EligibilityDenialV1::LeaseUnavailable,
            EligibilityDenialV1::AuthorizationUnavailable,
            EligibilityDenialV1::PolicyUnavailable,
            EligibilityDenialV1::CatalogueUnavailable,
            EligibilityDenialV1::CapabilityUnavailable,
        ][usize::from(fault)];
        assert_preclaim_denial(fixture, expected);
    }
}

fn evaluate_outcome(fixture: EligibilityFixture) -> (Result<(), EligibilityDenialV1>, usize) {
    let claimant = ClaimantProbe::default();
    let outcome = fixture
        .evaluate(&claimant)
        .map(|_| ())
        .map_err(|failure| failure.denial());
    (outcome, claimant.calls())
}

fn available_subset(mask: u8) -> &'static [String] {
    static SETS: OnceLock<Vec<Vec<String>>> = OnceLock::new();
    SETS.get_or_init(|| {
        (0_u8..8)
            .map(|candidate| {
                let mut values = Vec::new();
                if candidate & 0b001 != 0 {
                    values.push("filesystem.atomic-replace".to_owned());
                }
                if candidate & 0b010 != 0 {
                    values.push("filesystem.durable-flush".to_owned());
                }
                if candidate & 0b100 != 0 {
                    values.push("filesystem.verify-by-handle".to_owned());
                }
                values
            })
            .collect()
    })[usize::from(mask)]
    .as_slice()
}

fn atomic_mandatory() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES
        .get_or_init(|| vec!["filesystem.atomic-replace".to_owned()])
        .as_slice()
}

fn durable_mandatory() -> &'static [String] {
    static VALUES: OnceLock<Vec<String>> = OnceLock::new();
    VALUES
        .get_or_init(|| vec!["filesystem.durable-flush".to_owned()])
        .as_slice()
}

fn policy_view(
    plan_id: Sha256Digest,
    max_capability_age_ms: u64,
    mandatory_capabilities: &'static [String],
) -> PolicyViewV1<'static> {
    let content_digest = digest(b"fixture policy content");
    PolicyViewV1::Current(
        PolicyRecordV1::try_new(PolicyRecordInputV1 {
            version: POLICY_VERSION,
            resolved_content_digest: content_digest,
            active_content_digest: content_digest,
            policy_generation: POLICY_GENERATION,
            decision_policy_generation: POLICY_GENERATION,
            decision_generation: POLICY_DECISION_GENERATION,
            decision: PolicyDecisionV1::Allow(PlanDecisionEvidenceV1::new(
                PlanDecisionEvidenceInputV1 {
                    plan_id,
                    decision_digest: digest(b"fixture policy decision"),
                },
            )),
            max_capability_age_ms,
            mandatory_capabilities,
        })
        .expect("valid generated policy view"),
    )
}

fn capability_view(
    plan: &helix_contracts::AuthenticPlanEnvelopeV1,
    available_capabilities: &'static [String],
) -> CapabilityViewV1<'static> {
    let claims = plan.eligibility_claims();
    let host_driver_context_digest = digest(b"fixture host-driver context");
    CapabilityViewV1::Current(
        CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
            report_digest: claims.capability_report_digest(),
            observed_at_unix_ms: claims.capability_observed_at_unix_ms(),
            boot_id: BOOT_ID,
            instance_epoch: INSTANCE_EPOCH,
            report_generation: CAPABILITY_REPORT_GENERATION,
            report_host_driver_context_digest: host_driver_context_digest,
            current_host_driver_context_digest: host_driver_context_digest,
            available_capabilities,
        })
        .expect("valid generated capability view"),
    )
}
