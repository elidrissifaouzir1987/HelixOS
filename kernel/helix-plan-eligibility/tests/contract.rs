use helix_contracts::{Nonce128, Sha256Digest, MAX_SAFE_U64};
use helix_plan_eligibility::{
    CapabilityRecordInputV1, CapabilityRecordV1, EligibilityContextBuildErrorV1,
    EligibilityContextV1, EligibilityDenialV1, MonotonicClockViewV1, ReplayBindingV1,
    ReplayClaimOutcomeV1, ReplayClaimReceiptV1, ReplayClaimantV1, SignerTrustViewV1,
    TimeViewInputV1, TimeViewV1, WallClockViewV1, WorkloadIdentityInputV1,
    WorkloadIdentityRecordV1,
};
use std::collections::BTreeSet;

#[test]
fn context_health_and_provider_failures_need_no_dummy_records() {
    let contexts = [
        EligibilityContextV1::Unavailable,
        EligibilityContextV1::Incomplete,
        EligibilityContextV1::Torn,
    ];
    assert_eq!(
        format!("{:?}", contexts[0]),
        "EligibilityContextV1::Unavailable"
    );
    assert_eq!(
        format!("{:?}", contexts[1]),
        "EligibilityContextV1::Incomplete"
    );
    assert_eq!(format!("{:?}", contexts[2]), "EligibilityContextV1::Torn");

    assert!(matches!(
        SignerTrustViewV1::Unavailable,
        SignerTrustViewV1::Unavailable
    ));
    assert!(matches!(
        SignerTrustViewV1::Inconsistent,
        SignerTrustViewV1::Inconsistent
    ));
    assert!(matches!(
        SignerTrustViewV1::Unknown,
        SignerTrustViewV1::Unknown
    ));
    assert!(matches!(
        SignerTrustViewV1::Revoked,
        SignerTrustViewV1::Revoked
    ));
}

#[test]
fn checked_build_errors_have_closed_stable_codes() {
    let expected = [
        "CONTEXT_BUILD_INTEGER_OUT_OF_RANGE",
        "CONTEXT_BUILD_INVALID_INTERVAL",
        "CONTEXT_BUILD_INVALID_IDENTIFIER",
        "CONTEXT_BUILD_INVALID_CAPABILITY_SET",
        "CONTEXT_BUILD_LIMIT_EXCEEDED",
    ];
    let actual = EligibilityContextBuildErrorV1::ALL
        .iter()
        .map(|error| error.code())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert_eq!(
        actual.iter().copied().collect::<BTreeSet<_>>().len(),
        actual.len()
    );

    let overflow = TimeViewV1::try_new(TimeViewInputV1 {
        clock_generation: MAX_SAFE_U64 + 1,
        wall: WallClockViewV1::Unavailable,
        monotonic: MonotonicClockViewV1::Unavailable,
    })
    .expect_err("an out-of-range generation must fail construction");
    assert_eq!(overflow, EligibilityContextBuildErrorV1::IntegerOutOfRange);

    let invalid_interval = WorkloadIdentityRecordV1::try_new(WorkloadIdentityInputV1 {
        workload_id: "workload-1",
        evidence_digest: digest(b"identity"),
        identity_generation: 1,
        boot_id: "boot-1",
        instance_epoch: 1,
        not_before_utc_unix_ms: 10,
        expires_at_utc_unix_ms: 10,
        deadline_monotonic_ms: 20,
    })
    .expect_err("a half-open interval must be nonempty");
    assert_eq!(
        invalid_interval,
        EligibilityContextBuildErrorV1::InvalidInterval
    );
}

#[test]
fn capability_sets_are_bounded_sorted_unique_portable_tokens() {
    let unsorted = vec!["zeta".to_owned(), "alpha".to_owned()];
    let error = CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
        report_digest: digest(b"report"),
        observed_at_unix_ms: 1,
        boot_id: "boot-1",
        instance_epoch: 1,
        report_generation: 1,
        report_host_driver_context_digest: digest(b"report-context"),
        current_host_driver_context_digest: digest(b"current-context"),
        available_capabilities: &unsorted,
    })
    .expect_err("an unsorted capability set is not canonical");
    assert_eq!(error, EligibilityContextBuildErrorV1::InvalidCapabilitySet);

    let too_many = (0..129)
        .map(|index| format!("capability-{index:03}"))
        .collect::<Vec<_>>();
    let error = CapabilityRecordV1::try_new(CapabilityRecordInputV1 {
        report_digest: digest(b"report"),
        observed_at_unix_ms: 1,
        boot_id: "boot-1",
        instance_epoch: 1,
        report_generation: 1,
        report_host_driver_context_digest: digest(b"report-context"),
        current_host_driver_context_digest: digest(b"current-context"),
        available_capabilities: &too_many,
    })
    .expect_err("the available capability set has a frozen v1 maximum");
    assert_eq!(error, EligibilityContextBuildErrorV1::LimitExceeded);
}

#[test]
fn denial_taxonomy_is_exhaustive_unique_and_contains_remediated_codes() {
    assert_eq!(EligibilityDenialV1::ALL.len(), 100);
    let codes = EligibilityDenialV1::ALL
        .iter()
        .map(|denial| denial.code())
        .collect::<Vec<_>>();
    assert_eq!(
        codes.iter().copied().collect::<BTreeSet<_>>().len(),
        codes.len()
    );
    assert!(codes.contains(&"CAPABILITY_NOT_FOUND"));
    assert!(codes.contains(&"REPLAY_RECEIPT_BINDING_MISMATCH"));
    assert_eq!(
        EligibilityDenialV1::ContextUnavailable.code(),
        "CONTEXT_UNAVAILABLE"
    );
    assert_eq!(
        EligibilityDenialV1::ReplayAmbiguous.code(),
        "REPLAY_AMBIGUOUS"
    );
}

#[test]
fn external_claimants_can_return_checked_receipts_but_not_construct_markers() {
    struct UnavailableClaimant;

    impl ReplayClaimantV1 for UnavailableClaimant {
        fn claim_once(&self, _binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1 {
            ReplayClaimOutcomeV1::Unavailable
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<UnavailableClaimant>();

    let claim_id = digest(b"claim-id");
    let binding_digest = digest(b"binding");
    let receipt = ReplayClaimReceiptV1::try_new(claim_id, 7, binding_digest)
        .expect("safe integer receipt generation");
    assert_eq!(receipt.claim_id(), claim_id);
    assert_eq!(receipt.claimant_generation(), 7);
    assert_eq!(receipt.binding_digest(), binding_digest);

    let error = ReplayClaimReceiptV1::try_new(claim_id, MAX_SAFE_U64 + 1, binding_digest)
        .expect_err("receipt generation uses the frozen safe-integer profile");
    assert_eq!(error, EligibilityContextBuildErrorV1::IntegerOutOfRange);
}

fn digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::digest(value)
}

#[allow(dead_code)]
fn nonce_fixture() -> Nonce128 {
    Nonce128::from_bytes([0x11; 16])
}
