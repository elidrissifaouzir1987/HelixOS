mod common;

use common::{
    authentic_plan, coherent_ready_input, digest, healthy_time, ClaimantProbe, EligibilityFixture,
    BOOT_ID, EXPIRES_AT_MS, NOW_MONOTONIC_MS,
};
use helix_plan_eligibility::{
    CapabilityViewV1, EligibilityContextV1, EligibilityDenialV1, LeaseResolutionV1, PolicyViewV1,
    ReadyEligibilityContextV1, SignerTrustViewV1, SupervisorViewV1,
};

const SOAK_SEED: u64 = 0x48_45_4c_49_58_4f_53_02;
const SOAK_ITERATIONS: usize = 100_000;

#[test]
#[ignore = "deterministic 100,000-context release evidence run"]
fn deterministic_acceptance_oracle_soak() {
    let started = std::time::Instant::now();
    let base_plan = authentic_plan();
    let claimant = ClaimantProbe::default();
    let mut random = XorShift64::new(SOAK_SEED);
    let mut eligible_count = 0_usize;
    let mut denied_counts = [0_usize; 7];

    for iteration in 0..SOAK_ITERATIONS {
        let plan = base_plan.clone();
        let mut input = coherent_ready_input(&plan);
        let scenario = (random.next() % 8) as usize;
        let expected = match scenario {
            0 => None,
            1 => {
                input.bound_plan_id = digest(b"soak other plan");
                Some(EligibilityDenialV1::ContextPlanMismatch)
            }
            2 => {
                input.supervisor = SupervisorViewV1::Unavailable;
                Some(EligibilityDenialV1::SupervisorUnavailable)
            }
            3 => {
                input.time = healthy_time(EXPIRES_AT_MS, BOOT_ID, NOW_MONOTONIC_MS);
                Some(EligibilityDenialV1::PlanExpired)
            }
            4 => {
                input.signer = SignerTrustViewV1::Unavailable;
                Some(EligibilityDenialV1::SignerTrustUnavailable)
            }
            5 => {
                input.lease = LeaseResolutionV1::NotFound;
                Some(EligibilityDenialV1::LeaseNotFound)
            }
            6 => {
                input.policy = PolicyViewV1::Unavailable;
                Some(EligibilityDenialV1::PolicyUnavailable)
            }
            7 => {
                input.capabilities = CapabilityViewV1::Unavailable;
                Some(EligibilityDenialV1::CapabilityUnavailable)
            }
            _ => unreachable!("scenario is reduced modulo eight"),
        };
        let context = EligibilityContextV1::Ready(
            ReadyEligibilityContextV1::try_new(input).expect("soak context remains well formed"),
        );
        let calls_before = claimant.calls();
        let outcome = (EligibilityFixture { plan, context }).evaluate(&claimant);

        match expected {
            None => {
                let eligible = outcome.unwrap_or_else(|failure| {
                    panic!(
                        "eligible soak scenario denied at iteration {iteration}: {}",
                        failure.denial().code()
                    )
                });
                assert_eq!(
                    eligible.bounds().evaluated_at_utc_unix_ms(),
                    common::NOW_UTC_MS
                );
                eligible_count += 1;
                assert_eq!(claimant.calls(), calls_before + 1);
            }
            Some(expected_denial) => {
                let failure = outcome.expect_err("faulted soak scenario must be denied");
                assert_eq!(failure.denial(), expected_denial, "iteration {iteration}");
                assert_eq!(claimant.calls(), calls_before, "iteration {iteration}");
                denied_counts[scenario - 1] += 1;
            }
        }
    }

    assert_eq!(
        eligible_count + denied_counts.iter().sum::<usize>(),
        SOAK_ITERATIONS
    );
    assert_eq!(claimant.calls(), eligible_count);
    let elapsed_ms = started.elapsed().as_millis();
    eprintln!(
        "plan-eligibility-soak schema=1 corpus=helixos.plan-eligibility-cases/1 seed={SOAK_SEED:#018x} iterations={SOAK_ITERATIONS} eligible={eligible_count} denied={denied_counts:?} elapsed_ms={elapsed_ms} status=pass"
    );
}

struct XorShift64(u64);

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
}
