//! Native coordinator diagnostics redact paths, identities, provider text and key data.

use helix_contracts::{ContractError, Ed25519KeyResolver, Result as ContractResult};
use helix_coordinator_sqlite::{
    CoordinatorClockUnavailableV1, CoordinatorMonotonicClockV1, CoordinatorRootIdentityEvidenceV1,
    CoordinatorStoreConfigErrorV1, CoordinatorStoreConfigV1, CoordinatorStoreOpenErrorV1,
    SqliteCoordinatorStoreV1,
};
use std::error::Error;
use std::fmt::{Debug, Display};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const PATH_SENTINEL: &str = "native-private-path-sentinel";
const IDENTIFIER_SENTINEL: &str = "operation-private-identifier-seed";
const CONTENT_SENTINEL: &str = "canonical-content-private-seed";
const PROVIDER_SENTINEL: &str = "sqlite-provider-raw-diagnostic-private-seed";
const KEY_SENTINEL: &str = "provisioner-key-private-seed";
const DIGEST_SENTINEL: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const BUDGET_SENTINEL: &str = "7654321098765";

const ALL_SENTINELS: [&str; 7] = [
    PATH_SENTINEL,
    IDENTIFIER_SENTINEL,
    CONTENT_SENTINEL,
    PROVIDER_SENTINEL,
    KEY_SENTINEL,
    DIGEST_SENTINEL,
    BUDGET_SENTINEL,
];

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new() -> Self {
        let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-{PATH_SENTINEL}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("seeded test root must be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct SeededClock(&'static str);

impl CoordinatorMonotonicClockV1 for SeededClock {
    fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
        let _private_provider_diagnostic = self.0;
        Ok(1)
    }
}

struct SeededKeys(&'static str);

impl Ed25519KeyResolver for SeededKeys {
    fn resolve_ed25519(&self, _key_id: &str) -> ContractResult<[u8; 32]> {
        let _private_key_id = self.0;
        Err(ContractError::UnknownKey)
    }
}

fn assert_opaque(diagnostic: &str, native_path: Option<&str>) {
    assert!(diagnostic.is_ascii());
    assert!(diagnostic.len() <= 192, "diagnostic is unexpectedly large");
    for sentinel in ALL_SENTINELS {
        assert!(
            !diagnostic.contains(sentinel),
            "diagnostic exposed seeded private data"
        );
    }
    if let Some(native_path) = native_path {
        assert!(!diagnostic.contains(native_path));
    }
}

fn assert_closed_error<E>(error: E, code: &str)
where
    E: Error + Debug + Display,
{
    assert_eq!(format!("{error:?}"), code);
    assert_eq!(error.to_string(), code);
    assert!(error.source().is_none());
    assert_opaque(&format!("{error:?}"), None);
    assert_opaque(&error.to_string(), None);
}

#[test]
fn root_configuration_and_store_hide_native_injected_custody() {
    let root = TestRoot::new();
    let native_path = root.path().to_string_lossy().into_owned();
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 50)
        .expect("seeded empty root must be accepted");
    assert_opaque(&format!("{config:?}"), Some(&native_path));

    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        SeededClock(PROVIDER_SENTINEL),
        SeededKeys(KEY_SENTINEL),
        10_000,
    )
    .expect("seeded empty store must initialize");
    assert_opaque(&format!("{store:?}"), Some(&native_path));

    let identity = store.root_identity_evidence();
    assert_opaque(&format!("{identity:?}"), Some(&native_path));
}

#[test]
fn hostile_root_member_and_content_map_to_payload_free_error() {
    let root = TestRoot::new();
    let hostile_name = format!("{IDENTIFIER_SENTINEL}-{CONTENT_SENTINEL}");
    fs::write(root.path().join(hostile_name), PROVIDER_SENTINEL)
        .expect("seeded hostile member must be written");
    let native_path = root.path().to_string_lossy().into_owned();
    let error = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 50)
        .expect_err("unknown member must be rejected");
    assert_closed_error(error, "UNKNOWN_ROOT_MEMBER");
    assert_opaque(&format!("{error:?}"), Some(&native_path));
}

#[test]
fn root_identity_and_clock_debug_are_opaque() {
    let identity = CoordinatorRootIdentityEvidenceV1::from_attested_bytes([0xcd; 32]);
    assert_opaque(&format!("{identity:?}"), None);
    assert_closed_error(CoordinatorClockUnavailableV1::new(), "CLOCK_UNAVAILABLE");
}

#[test]
fn every_public_coordinator_error_is_a_closed_code() {
    for (error, code) in [
        (
            CoordinatorStoreConfigErrorV1::InvalidBusyBound,
            "INVALID_BUSY_BOUND",
        ),
        (CoordinatorStoreConfigErrorV1::RootInvalid, "ROOT_INVALID"),
        (
            CoordinatorStoreConfigErrorV1::RootNotDedicated,
            "ROOT_NOT_DEDICATED",
        ),
        (
            CoordinatorStoreConfigErrorV1::RootRoleMismatch,
            "ROOT_ROLE_MISMATCH",
        ),
        (
            CoordinatorStoreConfigErrorV1::UnknownRootMember,
            "UNKNOWN_ROOT_MEMBER",
        ),
    ] {
        assert_closed_error(error, code);
    }

    for (error, code) in [
        (
            CoordinatorStoreOpenErrorV1::ClockUnavailable,
            "CLOCK_UNAVAILABLE",
        ),
        (
            CoordinatorStoreOpenErrorV1::DeadlineReached,
            "DEADLINE_REACHED",
        ),
        (CoordinatorStoreOpenErrorV1::RootInvalid, "ROOT_INVALID"),
        (
            CoordinatorStoreOpenErrorV1::RootNotDedicated,
            "ROOT_NOT_DEDICATED",
        ),
        (
            CoordinatorStoreOpenErrorV1::RootRoleMismatch,
            "ROOT_ROLE_MISMATCH",
        ),
        (
            CoordinatorStoreOpenErrorV1::RootIdentityMismatch,
            "ROOT_IDENTITY_MISMATCH",
        ),
        (CoordinatorStoreOpenErrorV1::RootBusy, "ROOT_BUSY"),
        (
            CoordinatorStoreOpenErrorV1::RootUnavailable,
            "ROOT_UNAVAILABLE",
        ),
        (
            CoordinatorStoreOpenErrorV1::UnknownRootMember,
            "UNKNOWN_ROOT_MEMBER",
        ),
        (
            CoordinatorStoreOpenErrorV1::ApplicationIdMismatch,
            "APPLICATION_ID_MISMATCH",
        ),
        (
            CoordinatorStoreOpenErrorV1::SchemaUnsupported,
            "SCHEMA_UNSUPPORTED",
        ),
        (CoordinatorStoreOpenErrorV1::SchemaInvalid, "SCHEMA_INVALID"),
        (
            CoordinatorStoreOpenErrorV1::DurabilityProfileUnavailable,
            "DURABILITY_PROFILE_UNAVAILABLE",
        ),
        (
            CoordinatorStoreOpenErrorV1::IntegrityFailed,
            "INTEGRITY_FAILED",
        ),
        (
            CoordinatorStoreOpenErrorV1::InvariantFailed,
            "INVARIANT_FAILED",
        ),
        (
            CoordinatorStoreOpenErrorV1::RestorePending,
            "RESTORE_PENDING",
        ),
    ] {
        assert_closed_error(error, code);
    }
}
