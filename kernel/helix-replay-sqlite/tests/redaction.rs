//! Path, identity, nonce, digest and provider redaction on public diagnostics.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    SyntheticTempRoot, MAINTENANCE_DEADLINE_MONOTONIC_MS,
};
use helix_replay_sqlite::{
    BackupManifestV1, ReplayClockUnavailableV1, ReplayStoreConfigErrorV1,
    ReplayStoreLocationErrorV1, ReplayStoreMaintenanceErrorV1, ReplayStoreOpenErrorV1,
    TrustedEmptyLocalRootV1, REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1,
};
use std::error::Error;
use std::fmt::{Debug, Display};

const PATH_SENTINEL: &str = "redaction-surface";
const PROVIDER_SENTINEL: &str = "sqlite-provider-sentinel-0123456789abcdef0123456789abcdef";
const NONCE_SENTINEL: &str = "11111111111111111111111111111111";
const DIGEST_SENTINEL: &str = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

fn assert_opaque(diagnostic: &str, forbidden: &[&str]) {
    assert!(diagnostic.is_ascii());
    assert!(diagnostic.len() <= 160);
    for sentinel in forbidden {
        assert!(!diagnostic.contains(sentinel));
    }
}

fn assert_closed_error<E>(error: E, code: &str)
where
    E: Error + Debug + Display,
{
    assert_eq!(format!("{error:?}"), code);
    assert_eq!(error.to_string(), code);
    assert!(error.source().is_none());
}

#[test]
fn roots_configuration_claimant_and_evidence_have_opaque_debug_surfaces() {
    let empty_root = SyntheticTempRoot::new("redaction-empty");
    let empty = TrustedEmptyLocalRootV1::try_from_provisioned(empty_root.path().to_path_buf())
        .unwrap_or_else(|_| panic!("synthetic empty root was rejected"));
    assert_opaque(
        &format!("{empty:?}"),
        &["redaction-empty", &empty_root.path().to_string_lossy()],
    );

    let root = SyntheticTempRoot::new(PATH_SENTINEL);
    let native_path = root.path().to_string_lossy().into_owned();
    let trusted = root.trusted_root();
    let config = root.config();
    let clock = InjectedClock::coherent();
    let claimant = open_store(&root, clock);

    for diagnostic in [
        format!("{root:?}"),
        format!("{trusted:?}"),
        format!("{config:?}"),
        format!("{claimant:?}"),
    ] {
        assert_opaque(&diagnostic, &[PATH_SENTINEL, &native_path]);
    }

    let (eligible, _) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    let eligible = eligible.unwrap_or_else(|_| panic!("coherent fixture was denied"));
    assert_opaque(
        &format!("{eligible:?}"),
        &[
            common::feature002::OPERATION_ID,
            common::feature002::TASK_ID,
            common::feature002::WORKLOAD_ID,
            common::feature002::BOOT_ID,
            NONCE_SENTINEL,
            PATH_SENTINEL,
            &native_path,
        ],
    );

    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("healthy store verification failed"));
    assert_opaque(&format!("{verification:?}"), &[PATH_SENTINEL, &native_path]);
}

#[test]
fn backup_manifest_debug_hides_digest_and_sqlite_provider() {
    let manifest_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "helixos.replay-store-backup/1",
        "application_id": REPLAY_STORE_APPLICATION_ID_V1,
        "store_schema_version": REPLAY_STORE_SCHEMA_VERSION_V1,
        "claimant_generation": 1,
        "claim_count": 1,
        "database_sha256": DIGEST_SENTINEL,
        "sqlite_version": "3.51.2",
        "sqlite_source_id": PROVIDER_SENTINEL,
        "integrity_check": "ok",
        "requires_paused_activation": true,
        "requires_instance_epoch_rotation": true,
        "requires_fencing_epoch_rotation": true,
        "may_omit_claims_after_generation": true
    }))
    .unwrap();
    let manifest = BackupManifestV1::decode_v1(&manifest_bytes)
        .unwrap_or_else(|_| panic!("valid synthetic manifest was rejected"));

    assert_opaque(
        &format!("{manifest:?}"),
        &[DIGEST_SENTINEL, PROVIDER_SENTINEL],
    );

    let hostile = format!(
        "{{\"schema\":\"{PATH_SENTINEL}\",\"nonce\":\"{NONCE_SENTINEL}\",\"provider\":\"{PROVIDER_SENTINEL}\"}}"
    );
    let error = BackupManifestV1::decode_v1(hostile.as_bytes())
        .err()
        .unwrap_or_else(|| panic!("hostile manifest was accepted"));
    assert_closed_error(error, "MANIFEST_INVALID");
}

#[test]
fn every_closed_public_error_is_payload_free() {
    assert_closed_error(ReplayClockUnavailableV1::new(), "CLOCK_UNAVAILABLE");

    for (error, code) in [
        (
            ReplayStoreLocationErrorV1::LocationInvalid,
            "LOCATION_INVALID",
        ),
        (
            ReplayStoreLocationErrorV1::LocationNotDedicated,
            "LOCATION_NOT_DEDICATED",
        ),
    ] {
        assert_closed_error(error, code);
    }

    for (error, code) in [
        (
            ReplayStoreConfigErrorV1::InvalidBusyBound,
            "INVALID_BUSY_BOUND",
        ),
        (
            ReplayStoreConfigErrorV1::InvalidBackupStep,
            "INVALID_BACKUP_STEP",
        ),
        (
            ReplayStoreConfigErrorV1::InvalidBackupWait,
            "INVALID_BACKUP_WAIT",
        ),
    ] {
        assert_closed_error(error, code);
    }

    for (error, code) in [
        (
            ReplayStoreOpenErrorV1::ClockUnavailable,
            "CLOCK_UNAVAILABLE",
        ),
        (ReplayStoreOpenErrorV1::DeadlineReached, "DEADLINE_REACHED"),
        (ReplayStoreOpenErrorV1::LocationInvalid, "LOCATION_INVALID"),
        (
            ReplayStoreOpenErrorV1::LocationNotDedicated,
            "LOCATION_NOT_DEDICATED",
        ),
        (
            ReplayStoreOpenErrorV1::StoreUnavailable,
            "STORE_UNAVAILABLE",
        ),
        (ReplayStoreOpenErrorV1::StoreBusy, "STORE_BUSY"),
        (
            ReplayStoreOpenErrorV1::ApplicationIdMismatch,
            "APPLICATION_ID_MISMATCH",
        ),
        (
            ReplayStoreOpenErrorV1::SchemaUnsupported,
            "SCHEMA_UNSUPPORTED",
        ),
        (ReplayStoreOpenErrorV1::SchemaInvalid, "SCHEMA_INVALID"),
        (
            ReplayStoreOpenErrorV1::DurabilityProfileUnavailable,
            "DURABILITY_PROFILE_UNAVAILABLE",
        ),
        (ReplayStoreOpenErrorV1::IntegrityFailed, "INTEGRITY_FAILED"),
        (ReplayStoreOpenErrorV1::InvariantFailed, "INVARIANT_FAILED"),
    ] {
        assert_closed_error(error, code);
    }

    for (error, code) in [
        (
            ReplayStoreMaintenanceErrorV1::ClockUnavailable,
            "CLOCK_UNAVAILABLE",
        ),
        (
            ReplayStoreMaintenanceErrorV1::DeadlineReached,
            "DEADLINE_REACHED",
        ),
        (
            ReplayStoreMaintenanceErrorV1::LocationInvalid,
            "LOCATION_INVALID",
        ),
        (
            ReplayStoreMaintenanceErrorV1::LocationNotDedicated,
            "LOCATION_NOT_DEDICATED",
        ),
        (
            ReplayStoreMaintenanceErrorV1::StoreUnavailable,
            "STORE_UNAVAILABLE",
        ),
        (ReplayStoreMaintenanceErrorV1::StoreBusy, "STORE_BUSY"),
        (
            ReplayStoreMaintenanceErrorV1::ApplicationIdMismatch,
            "APPLICATION_ID_MISMATCH",
        ),
        (
            ReplayStoreMaintenanceErrorV1::SchemaUnsupported,
            "SCHEMA_UNSUPPORTED",
        ),
        (
            ReplayStoreMaintenanceErrorV1::SchemaInvalid,
            "SCHEMA_INVALID",
        ),
        (
            ReplayStoreMaintenanceErrorV1::DurabilityProfileUnavailable,
            "DURABILITY_PROFILE_UNAVAILABLE",
        ),
        (
            ReplayStoreMaintenanceErrorV1::IntegrityFailed,
            "INTEGRITY_FAILED",
        ),
        (
            ReplayStoreMaintenanceErrorV1::InvariantFailed,
            "INVARIANT_FAILED",
        ),
        (
            ReplayStoreMaintenanceErrorV1::DestinationNotEmpty,
            "DESTINATION_NOT_EMPTY",
        ),
        (
            ReplayStoreMaintenanceErrorV1::SourceDestinationConflict,
            "SOURCE_DESTINATION_CONFLICT",
        ),
        (
            ReplayStoreMaintenanceErrorV1::ManifestMissing,
            "MANIFEST_MISSING",
        ),
        (
            ReplayStoreMaintenanceErrorV1::ManifestInvalid,
            "MANIFEST_INVALID",
        ),
        (
            ReplayStoreMaintenanceErrorV1::DatabaseDigestMismatch,
            "DATABASE_DIGEST_MISMATCH",
        ),
        (
            ReplayStoreMaintenanceErrorV1::BackupIncomplete,
            "BACKUP_INCOMPLETE",
        ),
        (
            ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
            "RESTORE_INCOMPLETE",
        ),
        (
            ReplayStoreMaintenanceErrorV1::MaintenanceDeadlineReached,
            "MAINTENANCE_DEADLINE_REACHED",
        ),
    ] {
        assert_closed_error(error, code);
    }
}
