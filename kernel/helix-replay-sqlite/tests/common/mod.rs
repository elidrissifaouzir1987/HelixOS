//! Shared synthetic fixtures for the durable replay integration tests.
//!
//! This module deliberately keeps native paths and provider diagnostics out of panic
//! and assertion messages. The directories it creates contain synthetic data only.

#![allow(dead_code)]
#![allow(clippy::result_large_err)]

#[path = "../../../helix-plan-eligibility/tests/common/mod.rs"]
pub mod feature002;

use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AuthenticPlanEnvelopeV1, ContractError,
    Ed25519KeyResolver, Nonce128, PlanInputV1, Result as ContractResult, RiskLevelV1, Sha256Digest,
};
use helix_plan_eligibility::{
    AuthorizationInputV1, AuthorizationRecordV1, AuthorizationStatusV1, AuthorizationViewV1,
    EligibilityContextV1, EligibilityFailureV1, EligiblePlanV1, ReadyEligibilityContextV1,
    ReplayBindingV1, ReplayClaimOutcomeV1, ReplayClaimantV1,
};
use helix_replay_sqlite::{
    ReplayClockUnavailableV1, ReplayMonotonicClockV1, ReplayStoreConfigV1, SqliteReplayClaimantV1,
    TrustedLocalStoreRootV1,
};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub const OPEN_DEADLINE_MONOTONIC_MS: u64 = 90_000;
pub const MAINTENANCE_DEADLINE_MONOTONIC_MS: u64 = 95_000;
pub const DEFAULT_BUSY_WAIT_MS: u64 = 50;
pub const DEFAULT_BACKUP_STEP_PAGES: u32 = 16;
pub const DEFAULT_BACKUP_RETRY_WAIT_MS: u64 = 1;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const VARIANT_OPERATION_2: &str = "operation:00000000-0000-4000-8000-000000000002";
const VARIANT_OPERATION_3: &str = "operation:00000000-0000-4000-8000-000000000003";
const VARIANT_NONCE_1: [u8; 16] = [0x11; 16];
const VARIANT_NONCE_2: [u8; 16] = [0x22; 16];
const VARIANT_NONCE_3: [u8; 16] = [0x33; 16];
const ZERO_DIGEST: Sha256Digest = Sha256Digest::from_bytes([0; 32]);

static NEXT_TEMP_ROOT: AtomicU64 = AtomicU64::new(1);

/// Owned temporary root with path-redacted diagnostics and best-effort cleanup.
pub struct SyntheticTempRoot {
    path: PathBuf,
}

impl SyntheticTempRoot {
    pub fn new(label: &str) -> Self {
        assert!(
            !label.is_empty()
                && label.len() <= 48
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "synthetic root label must be bounded ASCII"
        );

        let temp = std::env::temp_dir();
        for _ in 0..128 {
            let sequence = NEXT_TEMP_ROOT.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                "helix-replay-test-{}-{sequence}-{label}",
                std::process::id()
            );
            let path = temp.join(name);
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("synthetic replay root creation failed"),
            }
        }
        panic!("synthetic replay root allocation exhausted")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn trusted_root(&self) -> TrustedLocalStoreRootV1 {
        TrustedLocalStoreRootV1::try_from_provisioned(self.path.clone())
            .unwrap_or_else(|_| panic!("synthetic provisioned root was rejected"))
    }

    pub fn config(&self) -> ReplayStoreConfigV1 {
        ReplayStoreConfigV1::try_new(
            self.trusted_root(),
            DEFAULT_BUSY_WAIT_MS,
            DEFAULT_BACKUP_STEP_PAGES,
            DEFAULT_BACKUP_RETRY_WAIT_MS,
        )
        .unwrap_or_else(|_| panic!("synthetic replay configuration was rejected"))
    }

    pub fn create_foreign_file(&self) {
        let foreign = self.path.join("foreign-sentinel.txt");
        fs::write(foreign, b"synthetic foreign file")
            .unwrap_or_else(|_| panic!("synthetic foreign file creation failed"));
    }

    /// Finds the closed SQLite database by its header without exposing its private name.
    pub fn closed_database_path(&self) -> PathBuf {
        self.closed_database_path_if_present()
            .unwrap_or_else(|| panic!("closed synthetic SQLite database was not found"))
    }

    pub fn closed_database_path_if_present(&self) -> Option<PathBuf> {
        let entries = fs::read_dir(&self.path)
            .unwrap_or_else(|_| panic!("synthetic replay root enumeration failed"));
        for entry in entries {
            let entry = entry.unwrap_or_else(|_| panic!("synthetic root entry was unreadable"));
            let file_type = entry
                .file_type()
                .unwrap_or_else(|_| panic!("synthetic root entry type was unreadable"));
            if !file_type.is_file() {
                continue;
            }
            let bytes = fs::read(entry.path())
                .unwrap_or_else(|_| panic!("synthetic root entry was unreadable"));
            if bytes.get(..SQLITE_HEADER.len()) == Some(SQLITE_HEADER.as_slice()) {
                return Some(entry.path());
            }
        }
        None
    }
}

impl fmt::Debug for SyntheticTempRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticTempRoot")
            .finish_non_exhaustive()
    }
}

impl Drop for SyntheticTempRoot {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.path);
    }
}

/// Cloneable injected clock sharing one atomic monotonic sample across reopen calls.
#[derive(Clone)]
pub struct InjectedClock {
    now_monotonic_ms: Arc<AtomicU64>,
}

impl InjectedClock {
    pub fn new(now_monotonic_ms: u64) -> Self {
        Self {
            now_monotonic_ms: Arc::new(AtomicU64::new(now_monotonic_ms)),
        }
    }

    pub fn coherent() -> Self {
        Self::new(feature002::NOW_MONOTONIC_MS)
    }

    pub fn set(&self, now_monotonic_ms: u64) {
        self.now_monotonic_ms
            .store(now_monotonic_ms, Ordering::SeqCst);
    }

    pub fn now(&self) -> u64 {
        self.now_monotonic_ms.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for InjectedClock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InjectedClock")
            .finish_non_exhaustive()
    }
}

impl ReplayMonotonicClockV1 for InjectedClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        Ok(self.now())
    }
}

pub fn open_store(
    root: &SyntheticTempRoot,
    clock: InjectedClock,
) -> SqliteReplayClaimantV1<InjectedClock> {
    SqliteReplayClaimantV1::open_or_create(root.config(), clock, OPEN_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("synthetic replay store open failed"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature002Variant {
    Coherent,
    SameNonceDifferentOperation,
    SameOperationDifferentNonce,
    Independent,
}

impl Feature002Variant {
    fn operation_id(self) -> &'static str {
        match self {
            Self::Coherent | Self::SameOperationDifferentNonce => feature002::OPERATION_ID,
            Self::SameNonceDifferentOperation => VARIANT_OPERATION_2,
            Self::Independent => VARIANT_OPERATION_3,
        }
    }

    fn nonce(self) -> Nonce128 {
        let bytes = match self {
            Self::Coherent | Self::SameNonceDifferentOperation => VARIANT_NONCE_1,
            Self::SameOperationDifferentNonce => VARIANT_NONCE_2,
            Self::Independent => VARIANT_NONCE_3,
        };
        Nonce128::from_bytes(bytes)
    }
}

struct FixtureResolver {
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for FixtureResolver {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == feature002::KEY_ID {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

fn authenticate_plan(input: PlanInputV1) -> AuthenticPlanEnvelopeV1 {
    let signer = feature002::TestSigner::fixed();
    let resolver = FixtureResolver {
        public_key: signer.verifying_key_bytes(),
    };
    let signed =
        sign_plan_v1(input, &signer).unwrap_or_else(|_| panic!("synthetic plan signing failed"));
    let wire = signed
        .to_canonical_json()
        .unwrap_or_else(|_| panic!("synthetic plan canonicalization failed"));
    decode_and_verify_plan(&wire, &resolver)
        .unwrap_or_else(|_| panic!("synthetic plan authentication failed"))
}

pub fn feature002_fixture(variant: Feature002Variant) -> feature002::EligibilityFixture {
    let mut input = feature002::sample_plan_input();
    input.operation_id = variant.operation_id().to_owned();
    input.nonce = variant.nonce();
    let plan = authenticate_plan(input);
    let plan_id = plan.eligibility_claims().plan_id();
    let mut ready_input = feature002::coherent_ready_input(&plan);
    ready_input.authorization = AuthorizationViewV1::Current(
        AuthorizationRecordV1::try_new(AuthorizationInputV1 {
            status: AuthorizationStatusV1::Granted,
            plan_id,
            operation_id: variant.operation_id(),
            risk_level: RiskLevelV1::L1,
            nonce: variant.nonce(),
            evidence_digest: feature002::digest(b"fixture authorization evidence"),
            authorization_generation: feature002::AUTHORIZATION_GENERATION,
            boot_id: feature002::BOOT_ID,
            not_before_utc_unix_ms: feature002::ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: feature002::ISSUED_AT_MS + 190_000,
            deadline_monotonic_ms: 110_000,
        })
        .unwrap_or_else(|_| panic!("synthetic authorization construction failed")),
    );
    let ready = ReadyEligibilityContextV1::try_new(ready_input)
        .unwrap_or_else(|_| panic!("synthetic eligibility context construction failed"));
    feature002::EligibilityFixture {
        plan,
        context: EligibilityContextV1::Ready(ready),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedReplayOutcome {
    Claimed {
        claimant_generation: u64,
        receipt_matches_binding: bool,
        claim_id_is_nonzero: bool,
    },
    AlreadyClaimed,
    BindingConflict,
    Unavailable,
    Ambiguous,
}

pub struct ObservingClaimant<'claimant, C: ?Sized> {
    inner: &'claimant C,
    observed: Mutex<Option<ObservedReplayOutcome>>,
}

impl<'claimant, C: ?Sized> ObservingClaimant<'claimant, C> {
    pub fn new(inner: &'claimant C) -> Self {
        Self {
            inner,
            observed: Mutex::new(None),
        }
    }

    pub fn observed(&self) -> ObservedReplayOutcome {
        self.observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .unwrap_or_else(|| panic!("replay claimant was not reached"))
    }
}

impl<C: ReplayClaimantV1 + ?Sized> ReplayClaimantV1 for ObservingClaimant<'_, C> {
    fn claim_once(&self, binding: &ReplayBindingV1<'_>) -> ReplayClaimOutcomeV1 {
        let outcome = self.inner.claim_once(binding);
        let observed = match &outcome {
            ReplayClaimOutcomeV1::Claimed(receipt) => ObservedReplayOutcome::Claimed {
                claimant_generation: receipt.claimant_generation(),
                receipt_matches_binding: receipt.binding_digest() == binding.binding_digest(),
                claim_id_is_nonzero: receipt.claim_id() != ZERO_DIGEST,
            },
            ReplayClaimOutcomeV1::AlreadyClaimed => ObservedReplayOutcome::AlreadyClaimed,
            ReplayClaimOutcomeV1::BindingConflict => ObservedReplayOutcome::BindingConflict,
            ReplayClaimOutcomeV1::Unavailable => ObservedReplayOutcome::Unavailable,
            ReplayClaimOutcomeV1::Ambiguous => ObservedReplayOutcome::Ambiguous,
        };
        *self
            .observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(observed);
        outcome
    }
}

pub fn evaluate_with_observation<C: ReplayClaimantV1 + ?Sized>(
    fixture: feature002::EligibilityFixture,
    claimant: &C,
) -> (
    Result<EligiblePlanV1, EligibilityFailureV1>,
    ObservedReplayOutcome,
) {
    let observer = ObservingClaimant::new(claimant);
    let result = fixture.evaluate(&observer);
    let observed = observer.observed();
    (result, observed)
}
