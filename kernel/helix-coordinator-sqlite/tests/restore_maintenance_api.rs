//! T075 public evidence surface and source-order contracts for internal maintenance.

use helix_coordinator_sqlite::{
    RestoredPreparationMaintenanceEvidenceV1, VerifiedPreparationRestoreV1,
};

const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MAINTENANCE_SOURCE: &str = include_str!("../src/maintenance.rs");
const FAILURE_SOURCE: &str = include_str!("../src/failure.rs");
const QUARANTINE_SOURCE: &str = include_str!("../src/quarantine.rs");

fn source_with_lf_newlines(source: &str) -> String {
    source.replace("\r\n", "\n")
}

#[test]
fn public_restore_surface_is_evidence_only_and_has_no_producer() {
    fn assert_public_type<T>() {}
    assert_public_type::<VerifiedPreparationRestoreV1>();
    assert_public_type::<RestoredPreparationMaintenanceEvidenceV1>();

    let public_maintenance_exports = LIB_SOURCE
        .split_once("pub use maintenance::{")
        .expect("maintenance evidence export block exists")
        .1
        .split_once("};")
        .expect("maintenance evidence export block is closed")
        .0;
    for required_export in [
        "RestoredPreparationMaintenanceEvidenceV1",
        "VerifiedPreparationRestoreV1",
    ] {
        assert!(
            public_maintenance_exports.contains(required_export),
            "missing T075 export {required_export}"
        );
    }
    for forbidden_export in [
        "PreparationRestoreErrorV1",
        "RestoreMaintenanceErrorV1",
        "RestoreMaintenanceLimitErrorV1",
        "RestoreMaintenanceLimitsV1",
        "PausedRotatedRestoreAuthorityV1",
        "RestoredAuthorityRotationV1",
        "RestorePauseRotationCustodyV1",
        "CoordinatorPendingRootCustodyV1",
        "RecoveryRestorePendingCustodyV1",
    ] {
        assert!(
            !public_maintenance_exports.contains(forbidden_export),
            "maintenance input/error/authority must remain private: {forbidden_export}"
        );
    }
    for forbidden_producer in [
        "pub fn accept_preparation_restore_package_v1",
        "pub fn restore_preparation_to_pending_v1",
        "pub fn reconcile_restored_old_authority_v1",
        "pub fn quarantine_existing_restore_attempt_v1",
    ] {
        assert!(!LIB_SOURCE.contains(forbidden_producer));
    }
}

#[test]
fn windows_refusal_precedes_package_handle_trust_and_every_mutation() {
    let maintenance_source = source_with_lf_newlines(MAINTENANCE_SOURCE);
    let accept_start = maintenance_source
        .find(
            "#[cfg(all(not(test), windows))]\npub(crate) fn accept_preparation_restore_package_v1",
        )
        .expect("Windows acceptance gate exists");
    let supported_start = maintenance_source[accept_start..]
        .find("#[cfg(all(not(test), not(windows)))]\npub(crate) fn accept_preparation_restore_package_v1")
        .map(|offset| accept_start + offset)
        .expect("non-Windows acceptance implementation follows");
    let windows_accept = &maintenance_source[accept_start..supported_start];
    assert!(windows_accept.contains("PreparationRestoreErrorV1::PlatformUnsupported"));
    for forbidden in [
        "attested_directory_binding_sha256_v1",
        "capture_immutable_members_v1",
        "acquire_restore_trust_custody_v1",
        "persist_restore_package_quarantine_v1",
        "persist_restore_quarantine_v1",
    ] {
        assert!(
            !windows_accept.contains(forbidden),
            "Windows acceptance performed forbidden work: {forbidden}"
        );
    }

    let restore_start = maintenance_source
        .find("#[cfg(all(not(test), windows))]\n#[allow(clippy::too_many_arguments)]\npub(crate) fn restore_preparation_to_pending_v1")
        .expect("Windows defensive restore gate exists");
    let restore_supported = maintenance_source[restore_start..]
        .find("#[cfg(all(not(test), not(windows)))]")
        .map(|offset| restore_start + offset)
        .expect("non-Windows restore implementation follows");
    let windows_restore = &maintenance_source[restore_start..restore_supported];
    assert!(windows_restore.contains("PreparationRestoreErrorV1::PlatformUnsupported"));
    for forbidden in [
        "persist_pause_and_rotate_for_restore_v1",
        "begin_empty_restore_root_custody_v1",
        "begin_or_resume_restore_root_v1",
        "persist_root_quarantine_v1",
    ] {
        assert!(!windows_restore.contains(forbidden));
    }
}

#[test]
fn t073_rotation_is_typed_from_live_pause_and_maintenance_has_no_activation_path() {
    let maintenance_source = source_with_lf_newlines(MAINTENANCE_SOURCE);
    assert!(maintenance_source.contains(
        "pub(crate) const fn old_authority_rotation_v1(self) -> RestoredAuthorityRotationV1"
    ));
    assert!(maintenance_source.contains(
        "serialize both\n    /// provisioner-owned physical destination-binding namespaces"
    ));
    for (source, start, end) in [
        (
            FAILURE_SOURCE,
            "pub(crate) struct RestoredOldAuthorityFailureInputV1",
            "impl std::fmt::Debug for RestoredOldAuthorityFailureInputV1",
        ),
        (
            QUARANTINE_SOURCE,
            "pub(crate) struct RestoredOldAuthorityQuarantineInputV1",
            "impl fmt::Debug for RestoredOldAuthorityQuarantineInputV1",
        ),
    ] {
        let input = source
            .split_once(start)
            .expect("T073 input exists")
            .1
            .split_once(end)
            .expect("T073 input has a closed definition")
            .0;
        assert!(input.contains("rotation: RestoredAuthorityRotationV1"));
        assert!(!input.contains("rotated_boot_id:"));
        assert!(!input.contains("rotated_instance_epoch:"));
        assert!(!input.contains("rotated_fencing_epoch:"));
    }

    let reconcile_start = maintenance_source
        .find("pub(crate) fn reconcile_restored_old_authority_v1")
        .expect("bounded reconciliation exists");
    let reconcile_end = maintenance_source[reconcile_start..]
        .find("fn verify_recovery_pending_metadata_for_maintenance_v1")
        .map(|offset| reconcile_start + offset)
        .expect("bounded reconciliation has a closed helper boundary");
    let reconcile = &maintenance_source[reconcile_start..reconcile_end];
    for required in [
        "inspect_existing_restore_attempt_v1",
        "reopen_restore_pending_root_custody_v1",
        "reopen_restore_pending_root_v1",
        "fail_restored_old_authority_transaction_v1",
        "retain_restored_old_authority_quarantine_v1",
        "old_authority_rotation_v1",
    ] {
        assert!(
            reconcile.contains(required),
            "missing custody step {required}"
        );
    }
    for forbidden in [
        "root_lifecycle_state = 'ACTIVE'",
        "root_lifecycle_state='ACTIVE'",
        "DISPATCHING",
        "dispatch_outbox",
        "activate_restore",
        "activation_permit",
    ] {
        assert!(
            !reconcile.contains(forbidden),
            "T075 reconciliation contains activation/dispatch path {forbidden}"
        );
    }
}
