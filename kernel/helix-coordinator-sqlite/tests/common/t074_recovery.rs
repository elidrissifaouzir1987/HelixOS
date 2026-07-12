//! Explicit T074 recovery-publication process workflow.
//!
//! This drives the real public-synthetic manifest-last provider used by downstream
//! conformance. It is process-crash evidence for that provider only: it neither creates
//! a coordinator operation nor claims a production compensable recovery path.

#![allow(dead_code)] // Wired by the private process child after the workflow lands.

use crate::common::{recovery_test_fault, SyntheticManifestLastRecoveryProviderV1};
use helix_contracts::Sha256Digest;
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const PROVIDER_ROOT_DIRECTORY_V1: &str = "recovery-provider-v1";
const LOCK_DIRECTORY_V1: &str = "locks-v1";
const PACKAGE_DIRECTORY_V1: &str = "packages-v1";
const MATERIAL_SUFFIX_V1: &str = ".material";
const MANIFEST_SUFFIX_V1: &str = ".manifest";
const LOCK_SUFFIX_V1: &str = ".lock";
const STAGING_SUFFIX_V1: &str = ".staging";
const RECOVERY_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0T074\0RECOVERY-PROVIDER-WORKFLOW\0V1\0";
const SYNTHETIC_MANIFEST_DOMAIN_V1: &[u8] = b"HELIXOS\0SYNTHETIC-RECOVERY-MANIFEST\0V1\0";
const SYNTHETIC_MATERIAL_V1: &[u8] = b"before\n";

const RECOVERY_BOUNDARY_IDS_V1: [&str; 13] = [
    "recovery_publication_guard_acquired",
    "recovery_staging_created",
    "recovery_staging_written",
    "recovery_staging_synchronized",
    "recovery_staging_closed",
    "recovery_staging_reopened",
    "recovery_material_digest_length_capacity_verified",
    "recovery_material_published",
    "recovery_manifest_staged",
    "recovery_manifest_synchronized",
    "recovery_manifest_published",
    "recovery_manifest_reopened",
    "recovery_receipt_returned",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum T074RecoveryWorkflowErrorV1 {
    UnsupportedBoundary,
    InvalidOccurrence,
    RootUnavailable,
    RootInvalid,
    ProviderRefused,
    StateUnreadable,
    StateInvalid,
}

impl T074RecoveryWorkflowErrorV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedBoundary => "T074_RECOVERY_UNSUPPORTED_BOUNDARY",
            Self::InvalidOccurrence => "T074_RECOVERY_INVALID_OCCURRENCE",
            Self::RootUnavailable => "T074_RECOVERY_ROOT_UNAVAILABLE",
            Self::RootInvalid => "T074_RECOVERY_ROOT_INVALID",
            Self::ProviderRefused => "T074_RECOVERY_PROVIDER_REFUSED",
            Self::StateUnreadable => "T074_RECOVERY_STATE_UNREADABLE",
            Self::StateInvalid => "T074_RECOVERY_STATE_INVALID",
        }
    }
}

impl std::fmt::Debug for T074RecoveryWorkflowErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

pub(crate) fn supports_boundary_v1(boundary_id: &str) -> bool {
    RECOVERY_BOUNDARY_IDS_V1.contains(&boundary_id)
}

pub(crate) fn prepare_fixture_v1(protocol_root: &Path) -> Result<(), T074RecoveryWorkflowErrorV1> {
    ensure_directory_v1(protocol_root, true)?;
    let provider_root = provider_root_v1(protocol_root);
    match fs::create_dir(&provider_root) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            ensure_directory_v1(&provider_root, false)?;
        }
        Err(_) => return Err(T074RecoveryWorkflowErrorV1::RootUnavailable),
    }
    SyntheticManifestLastRecoveryProviderV1::open_v1(provider_root.clone())
        .map_err(|_| T074RecoveryWorkflowErrorV1::RootInvalid)?;
    validate_provider_tree_v1(&provider_root, false).map(|_| ())
}

pub(crate) fn run_boundary_v1(
    protocol_root: &Path,
    boundary_id: &str,
    occurrence: u64,
    process_barrier: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), T074RecoveryWorkflowErrorV1> {
    if !supports_boundary_v1(boundary_id) {
        return Err(T074RecoveryWorkflowErrorV1::UnsupportedBoundary);
    }
    if occurrence == 0 {
        return Err(T074RecoveryWorkflowErrorV1::InvalidOccurrence);
    }
    let boundary = recovery_test_fault::FaultBoundaryV1::ALL
        .iter()
        .copied()
        .find(|candidate| candidate.id() == boundary_id)
        .ok_or(T074RecoveryWorkflowErrorV1::UnsupportedBoundary)?;
    let selection = recovery_test_fault::FaultSelectionV1::try_new(
        boundary,
        occurrence,
        recovery_test_fault::FaultEffectV1::ProcessBarrier,
    )
    .map_err(|_| T074RecoveryWorkflowErrorV1::InvalidOccurrence)?;
    let callback = Arc::clone(&process_barrier);
    let fault_probe = recovery_test_fault::FaultProbeV1::selected_process_barrier_v1(
        selection,
        Box::new(move || callback()),
    );
    let provider =
        SyntheticManifestLastRecoveryProviderV1::open_v1(provider_root_v1(protocol_root))
            .map_err(|_| T074RecoveryWorkflowErrorV1::RootInvalid)?
            .with_fault_probe_v1(fault_probe);
    provider
        .publish_public_synthetic_v1(recovery_binding_v1())
        .map_err(|_| T074RecoveryWorkflowErrorV1::ProviderRefused)
}

pub(crate) fn reopen_state_v1(
    protocol_root: &Path,
) -> Result<&'static [u8], T074RecoveryWorkflowErrorV1> {
    ensure_directory_v1(protocol_root, false)?;
    let provider_root = provider_root_v1(protocol_root);
    match fs::symlink_metadata(&provider_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(T074RecoveryWorkflowErrorV1::RootInvalid)
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(b"absent"),
        Err(_) => return Err(T074RecoveryWorkflowErrorV1::StateUnreadable),
    }
    let has_artifacts = validate_provider_tree_v1(&provider_root, true)?;
    Ok(if has_artifacts {
        // Recovery bytes, including a complete manifest-last package, are never
        // operation authority. This workflow intentionally owns no coordinator row.
        b"quarantine"
    } else {
        b"absent"
    })
}

fn provider_root_v1(protocol_root: &Path) -> PathBuf {
    protocol_root.join(PROVIDER_ROOT_DIRECTORY_V1)
}

fn recovery_binding_v1() -> Sha256Digest {
    Sha256Digest::digest(RECOVERY_BINDING_DOMAIN_V1)
}

fn ensure_directory_v1(
    path: &Path,
    create_if_missing: bool,
) -> Result<(), T074RecoveryWorkflowErrorV1> {
    if create_if_missing {
        fs::create_dir_all(path).map_err(|_| T074RecoveryWorkflowErrorV1::RootUnavailable)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        ErrorKind::NotFound => T074RecoveryWorkflowErrorV1::RootUnavailable,
        _ => T074RecoveryWorkflowErrorV1::StateUnreadable,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(T074RecoveryWorkflowErrorV1::RootInvalid);
    }
    Ok(())
}

fn validate_provider_tree_v1(
    provider_root: &Path,
    inspect_artifacts: bool,
) -> Result<bool, T074RecoveryWorkflowErrorV1> {
    let mut saw_locks = false;
    let mut saw_packages = false;
    for entry in read_directory_v1(provider_root)? {
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .map_err(|_| T074RecoveryWorkflowErrorV1::StateUnreadable)?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
        }
        match name.to_str() {
            Some(LOCK_DIRECTORY_V1) if !saw_locks => saw_locks = true,
            Some(PACKAGE_DIRECTORY_V1) if !saw_packages => saw_packages = true,
            _ => return Err(T074RecoveryWorkflowErrorV1::StateInvalid),
        }
    }
    if !saw_locks || !saw_packages {
        return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
    }

    validate_lock_directory_v1(&provider_root.join(LOCK_DIRECTORY_V1))?;
    let has_artifacts = inspect_package_directory_v1(&provider_root.join(PACKAGE_DIRECTORY_V1))?;
    if !inspect_artifacts && has_artifacts {
        return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
    }
    Ok(has_artifacts)
}

fn validate_lock_directory_v1(path: &Path) -> Result<(), T074RecoveryWorkflowErrorV1> {
    ensure_directory_v1(path, false)?;
    let expected_name = format!("{}{}", recovery_binding_hex_v1(), LOCK_SUFFIX_V1);
    for entry in read_directory_v1(path)? {
        let file_type = entry
            .file_type()
            .map_err(|_| T074RecoveryWorkflowErrorV1::StateUnreadable)?;
        if file_type.is_symlink()
            || !file_type.is_file()
            || entry.file_name() != OsStr::new(&expected_name)
        {
            return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
        }
        if !fs::read(entry.path())
            .map_err(|_| T074RecoveryWorkflowErrorV1::StateUnreadable)?
            .is_empty()
        {
            return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
        }
    }
    Ok(())
}

fn inspect_package_directory_v1(path: &Path) -> Result<bool, T074RecoveryWorkflowErrorV1> {
    ensure_directory_v1(path, false)?;
    let binding_hex = recovery_binding_hex_v1();
    let material_name = format!("{binding_hex}{MATERIAL_SUFFIX_V1}");
    let manifest_name = format!("{binding_hex}{MANIFEST_SUFFIX_V1}");
    let material_staging_prefix = format!("{binding_hex}.material.");
    let manifest_staging_prefix = format!("{binding_hex}.manifest.");
    let expected_material = SYNTHETIC_MATERIAL_V1;
    let expected_manifest = expected_manifest_bytes_v1(
        recovery_binding_v1(),
        Sha256Digest::digest(expected_material),
        u64::try_from(expected_material.len())
            .map_err(|_| T074RecoveryWorkflowErrorV1::StateInvalid)?,
        crate::common::SYNTHETIC_BUDGET_RECOVERY_BYTES,
    );

    let mut material_final = false;
    let mut manifest_final = false;
    let mut material_staging = false;
    let mut manifest_staging = false;
    for entry in read_directory_v1(path)? {
        let file_type = entry
            .file_type()
            .map_err(|_| T074RecoveryWorkflowErrorV1::StateUnreadable)?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| T074RecoveryWorkflowErrorV1::StateInvalid)?;
        let bytes =
            fs::read(entry.path()).map_err(|_| T074RecoveryWorkflowErrorV1::StateUnreadable)?;
        if name == material_name && !material_final {
            if bytes != expected_material {
                return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
            }
            material_final = true;
        } else if name == manifest_name && !manifest_final {
            if bytes != expected_manifest {
                return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
            }
            manifest_final = true;
        } else if valid_staging_name_v1(&name, &material_staging_prefix) && !material_staging {
            if !expected_material.starts_with(&bytes) {
                return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
            }
            material_staging = true;
        } else if valid_staging_name_v1(&name, &manifest_staging_prefix) && !manifest_staging {
            if !expected_manifest.starts_with(&bytes) {
                return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
            }
            manifest_staging = true;
        } else {
            return Err(T074RecoveryWorkflowErrorV1::StateInvalid);
        }
    }

    match (
        material_staging,
        material_final,
        manifest_staging,
        manifest_final,
    ) {
        (false, false, false, false) => Ok(false),
        (true, false, false, false)
        | (false, true, false, false)
        | (false, true, true, false)
        | (false, true, false, true) => Ok(true),
        _ => Err(T074RecoveryWorkflowErrorV1::StateInvalid),
    }
}

fn valid_staging_name_v1(name: &str, prefix: &str) -> bool {
    let Some(middle) = name
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(STAGING_SUFFIX_V1))
    else {
        return false;
    };
    let mut pieces = middle.split('.');
    matches!(
        (pieces.next(), pieces.next(), pieces.next()),
        (Some(process), Some(sequence), None)
            if !process.is_empty()
                && !sequence.is_empty()
                && process.bytes().all(|byte| byte.is_ascii_digit())
                && sequence.bytes().all(|byte| byte.is_ascii_digit())
    )
}

fn expected_manifest_bytes_v1(
    binding_digest: Sha256Digest,
    material_digest: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(SYNTHETIC_MANIFEST_DOMAIN_V1);
    bytes.extend_from_slice(binding_digest.as_bytes());
    bytes.extend_from_slice(material_digest.as_bytes());
    bytes.extend_from_slice(&material_length.to_be_bytes());
    bytes.extend_from_slice(&reserved_capacity.to_be_bytes());
    bytes
}

fn recovery_binding_hex_v1() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = recovery_binding_v1();
    let mut value = String::with_capacity(64);
    for byte in bytes.as_bytes() {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn read_directory_v1(path: &Path) -> Result<Vec<fs::DirEntry>, T074RecoveryWorkflowErrorV1> {
    fs::read_dir(path)
        .map_err(|_| T074RecoveryWorkflowErrorV1::StateUnreadable)?
        .map(|entry| entry.map_err(|_| T074RecoveryWorkflowErrorV1::StateUnreadable))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new_v1() -> Self {
            let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "helixos-t074-recovery-workflow-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("unique test root creates");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn supports_exactly_the_thirteen_recovery_boundaries() {
        assert_eq!(RECOVERY_BOUNDARY_IDS_V1.len(), 13);
        for boundary_id in RECOVERY_BOUNDARY_IDS_V1 {
            assert!(supports_boundary_v1(boundary_id), "{boundary_id}");
        }
        assert!(!supports_boundary_v1("recovery_not_in_the_closed_taxonomy"));
        assert!(!supports_boundary_v1(
            "quarantine_and_retirement_provider_retirement_invoked"
        ));
        let source = include_str!("t074_recovery.rs");
        assert!(!source.contains(&["probe.", "reach_v1"].concat()));
    }

    #[test]
    fn every_selected_id_is_reached_by_the_real_manifest_last_provider() {
        for boundary_id in RECOVERY_BOUNDARY_IDS_V1 {
            let root = TestRoot::new_v1();
            prepare_fixture_v1(&root.0).expect("fixture prepares");
            let calls = Arc::new(AtomicU64::new(0));
            let callback_calls = Arc::clone(&calls);
            let callback: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                callback_calls.fetch_add(1, Ordering::SeqCst);
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_boundary_v1(&root.0, boundary_id, 1, callback)
            }));
            assert!(
                result.is_err(),
                "{boundary_id}: returning test barrier must fail closed at the selected hook"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{boundary_id}");
            let expected = if boundary_id == "recovery_publication_guard_acquired" {
                b"absent".as_slice()
            } else {
                b"quarantine".as_slice()
            };
            assert_eq!(reopen_state_v1(&root.0), Ok(expected), "{boundary_id}");
        }
    }

    #[test]
    fn prepared_empty_fixture_reopens_absent_and_complete_provider_package_quarantines() {
        let root = TestRoot::new_v1();
        prepare_fixture_v1(&root.0).expect("fixture prepares");
        assert_eq!(reopen_state_v1(&root.0), Ok(b"absent".as_slice()));

        let provider = SyntheticManifestLastRecoveryProviderV1::open_v1(provider_root_v1(&root.0))
            .expect("real synthetic manifest-last provider opens");
        provider
            .publish_public_synthetic_v1(recovery_binding_v1())
            .expect("real public-synthetic package publishes");
        assert_eq!(reopen_state_v1(&root.0), Ok(b"quarantine".as_slice()));
    }

    #[test]
    fn partial_staging_is_quarantined_but_unknown_or_corrupt_members_are_refused() {
        let root = TestRoot::new_v1();
        prepare_fixture_v1(&root.0).expect("fixture prepares");
        let package_root = provider_root_v1(&root.0).join(PACKAGE_DIRECTORY_V1);
        fs::write(
            package_root.join(format!(
                "{}.material.1.1.staging",
                recovery_binding_hex_v1()
            )),
            &SYNTHETIC_MATERIAL_V1[..3],
        )
        .expect("partial staging writes");
        assert_eq!(reopen_state_v1(&root.0), Ok(b"quarantine".as_slice()));

        fs::write(package_root.join("unexpected"), b"x").expect("unknown member writes");
        assert_eq!(
            reopen_state_v1(&root.0),
            Err(T074RecoveryWorkflowErrorV1::StateInvalid)
        );
    }
}
