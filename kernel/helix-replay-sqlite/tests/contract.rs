//! Ownership: T006 and T015 public construction, diagnostics and claimant contract.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use helix_plan_eligibility::{ReplayClaimOutcomeV1, ReplayClaimReceiptV1, ReplayClaimantV1};
use helix_replay_sqlite::{
    ReplayStoreConfigErrorV1, ReplayStoreConfigV1, ReplayStoreLocationErrorV1,
    SqliteReplayClaimantV1, TrustedLocalStoreRootV1,
};

fn assert_send_sync<T: Send + Sync>() {}

fn config_error(
    result: Result<ReplayStoreConfigV1, ReplayStoreConfigErrorV1>,
) -> ReplayStoreConfigErrorV1 {
    result
        .err()
        .unwrap_or_else(|| panic!("invalid replay configuration was accepted"))
}

fn location_error(
    result: Result<TrustedLocalStoreRootV1, ReplayStoreLocationErrorV1>,
) -> ReplayStoreLocationErrorV1 {
    result
        .err()
        .unwrap_or_else(|| panic!("invalid replay location was accepted"))
}

fn assert_redacted_error<E>(error: &E, expected_code: &str)
where
    E: std::error::Error,
{
    assert_eq!(error.to_string(), expected_code);
    assert_eq!(format!("{error:?}"), expected_code);
    assert!(error.source().is_none());
}

#[test]
fn provisioned_root_requires_an_existing_absolute_dedicated_directory() {
    let relative = location_error(TrustedLocalStoreRootV1::try_from_provisioned(
        "relative-replay-root".into(),
    ));
    assert_eq!(relative.code(), "LOCATION_INVALID");
    assert_redacted_error(&relative, "LOCATION_INVALID");

    let root = SyntheticTempRoot::new("location-file");
    root.create_foreign_file();
    let foreign = location_error(TrustedLocalStoreRootV1::try_from_provisioned(
        root.path().to_path_buf(),
    ));
    assert_eq!(foreign.code(), "LOCATION_NOT_DEDICATED");
    assert_redacted_error(&foreign, "LOCATION_NOT_DEDICATED");
}

#[test]
fn configuration_bounds_have_frozen_payload_free_codes() {
    let busy_root = SyntheticTempRoot::new("invalid-busy");
    let busy = config_error(ReplayStoreConfigV1::try_new(
        busy_root.trusted_root(),
        0,
        16,
        1,
    ));
    assert_eq!(busy.code(), "INVALID_BUSY_BOUND");
    assert_redacted_error(&busy, "INVALID_BUSY_BOUND");

    let busy_large_root = SyntheticTempRoot::new("invalid-busy-large");
    let busy_large = config_error(ReplayStoreConfigV1::try_new(
        busy_large_root.trusted_root(),
        MAX_SAFE_U64 + 1,
        16,
        1,
    ));
    assert_eq!(busy_large.code(), "INVALID_BUSY_BOUND");

    for (label, pages) in [("invalid-pages-zero", 0), ("invalid-pages-large", 4097)] {
        let root = SyntheticTempRoot::new(label);
        let error = config_error(ReplayStoreConfigV1::try_new(
            root.trusted_root(),
            50,
            pages,
            1,
        ));
        assert_eq!(error.code(), "INVALID_BACKUP_STEP");
        assert_redacted_error(&error, "INVALID_BACKUP_STEP");
    }

    let wait_root = SyntheticTempRoot::new("invalid-backup-wait");
    let wait = config_error(ReplayStoreConfigV1::try_new(
        wait_root.trusted_root(),
        50,
        16,
        1001,
    ));
    assert_eq!(wait.code(), "INVALID_BACKUP_WAIT");
    assert_redacted_error(&wait, "INVALID_BACKUP_WAIT");
}

#[test]
fn path_bearing_public_types_are_debug_redacted() {
    const PATH_SENTINEL: &str = "DO-NOT-DISCLOSE-ROOT";
    let root = SyntheticTempRoot::new(PATH_SENTINEL);
    let trusted = root.trusted_root();
    let rendered = format!("{trusted:?}");
    assert_eq!(rendered, "TrustedLocalStoreRootV1 { .. }");
    assert!(!rendered.contains(PATH_SENTINEL));

    let config = ReplayStoreConfigV1::try_new(trusted, 50, 16, 1)
        .unwrap_or_else(|_| panic!("valid redaction configuration was rejected"));
    let rendered = format!("{config:?}");
    assert_eq!(rendered, "ReplayStoreConfigV1 { .. }");
    assert!(!rendered.contains(PATH_SENTINEL));

    let claimant = SqliteReplayClaimantV1::open_or_create(
        config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("valid redaction store open failed"));
    let rendered = format!("{claimant:?}");
    assert_eq!(rendered, "SqliteReplayClaimantV1 { .. }");
    assert!(!rendered.contains(PATH_SENTINEL));
}

#[test]
fn opening_after_the_supplied_deadline_fails_with_a_closed_code() {
    let root = SyntheticTempRoot::new("expired-open");
    let clock = InjectedClock::new(OPEN_DEADLINE_MONOTONIC_MS);
    let error =
        SqliteReplayClaimantV1::open_or_create(root.config(), clock, OPEN_DEADLINE_MONOTONIC_MS)
            .err()
            .unwrap_or_else(|| panic!("deadline-reached store open was accepted"));
    assert_eq!(error.code(), "DEADLINE_REACHED");
    assert_redacted_error(&error, "DEADLINE_REACHED");
}

#[test]
fn sqlite_claimant_is_a_send_sync_feature002_claimant() {
    assert_send_sync::<SqliteReplayClaimantV1<InjectedClock>>();
    fn assert_replay_claimant<T: ReplayClaimantV1 + Send + Sync>() {}
    assert_replay_claimant::<SqliteReplayClaimantV1<InjectedClock>>();
}

fn outcome_code(outcome: ReplayClaimOutcomeV1) -> &'static str {
    match outcome {
        ReplayClaimOutcomeV1::Claimed(_) => "CLAIMED",
        ReplayClaimOutcomeV1::AlreadyClaimed => "ALREADY_CLAIMED",
        ReplayClaimOutcomeV1::BindingConflict => "BINDING_CONFLICT",
        ReplayClaimOutcomeV1::Unavailable => "UNAVAILABLE",
        ReplayClaimOutcomeV1::Ambiguous => "AMBIGUOUS",
    }
}

#[test]
fn replay_outcome_mapping_is_exhaustive_and_receipts_are_redacted() {
    let binding_digest = Sha256Digest::digest(b"public synthetic binding");
    let receipt = ReplayClaimReceiptV1::try_new(
        Sha256Digest::digest(b"public synthetic claim"),
        1,
        binding_digest,
    )
    .unwrap_or_else(|_| panic!("valid synthetic receipt was rejected"));
    assert_eq!(format!("{receipt:?}"), "ReplayClaimReceiptV1 { .. }");
    assert_eq!(
        outcome_code(ReplayClaimOutcomeV1::Claimed(receipt)),
        "CLAIMED"
    );
    assert_eq!(
        outcome_code(ReplayClaimOutcomeV1::AlreadyClaimed),
        "ALREADY_CLAIMED"
    );
    assert_eq!(
        outcome_code(ReplayClaimOutcomeV1::BindingConflict),
        "BINDING_CONFLICT"
    );
    assert_eq!(
        outcome_code(ReplayClaimOutcomeV1::Unavailable),
        "UNAVAILABLE"
    );
    assert_eq!(outcome_code(ReplayClaimOutcomeV1::Ambiguous), "AMBIGUOUS");
}

#[test]
fn production_receipt_matches_the_feature002_binding_and_is_not_reissued() {
    let root = SyntheticTempRoot::new("receipt-contract");
    let claimant = open_store(&root, InjectedClock::coherent());
    let (first, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    let eligible = first.unwrap_or_else(|_| panic!("fresh coherent plan was denied"));
    assert_eq!(
        observed,
        ObservedReplayOutcome::Claimed {
            claimant_generation: 1,
            receipt_matches_binding: true,
            claim_id_is_nonzero: true,
        }
    );
    assert_eq!(
        eligible.replay_claim().binding_digest(),
        eligible.bindings().replay_binding_digest()
    );

    let (repeat, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    assert!(repeat.is_err());
    assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);
}

#[test]
fn authority_types_are_not_given_explicit_serde_implementations() {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let public_types = [
        "SqliteReplayClaimantV1",
        "ReplayStoreVerificationV1",
        "ReplayBackupEvidenceV1",
        "VerifiedRestoreEvidenceV1",
    ];
    let entries = std::fs::read_dir(source_root)
        .unwrap_or_else(|_| panic!("crate source enumeration failed"));
    let mut source = String::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|_| panic!("crate source entry was unreadable"));
        if entry.path().extension().and_then(|value| value.to_str()) == Some("rs") {
            source.push_str(
                &std::fs::read_to_string(entry.path())
                    .unwrap_or_else(|_| panic!("crate source file was unreadable")),
            );
        }
    }
    for public_type in public_types {
        assert!(
            !source.contains(&format!("Serialize for {public_type}")),
            "authority type has an explicit serialization implementation"
        );
    }
}
