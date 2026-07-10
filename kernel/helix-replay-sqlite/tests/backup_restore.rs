//! Ownership: T035-T042 backup, manifest-last publication, and clean restore.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, open_store, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, DEFAULT_BACKUP_RETRY_WAIT_MS,
    DEFAULT_BACKUP_STEP_PAGES, MAINTENANCE_DEADLINE_MONOTONIC_MS, OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AuthenticPlanEnvelopeV1, ContractError,
    Ed25519KeyResolver, Nonce128, PlanInputV1, Result as ContractResult, RiskLevelV1,
};
use helix_plan_eligibility::{
    AuthorizationInputV1, AuthorizationRecordV1, AuthorizationStatusV1, AuthorizationViewV1,
    EligibilityContextV1, ReadyEligibilityContextV1,
};
use helix_replay_sqlite::{
    restore_replay_store_v1, verify_replay_backup_v1, BackupManifestV1, ReplayClockUnavailableV1,
    ReplayMonotonicClockV1, ReplayStoreConfigV1, ReplayStoreMaintenanceErrorV1,
    SqliteReplayClaimantV1, TrustedLocalStoreRootV1,
};
use rusqlite::Connection;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
#[cfg(feature = "test-fault-injection")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const TEST_NOW_MONOTONIC_MS: u64 = 10_000;
const TEST_DEADLINE_MONOTONIC_MS: u64 = 20_000;
const ROOT_LOCK_FILENAME: &str = ".helix-replay-root-v1.lock";
const ACTIVATION_MARKER_FILENAME: &str = ".helix-replay-restored-activation-required-v1";
const LIVE_READY_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=LIVE_READY\n";
const BACKUP_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=BACKUP_PACKAGE\n";
#[cfg(feature = "test-fault-injection")]
const RESTORE_PENDING_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=RESTORE_PENDING\n";
const COLLISION_SENTINEL: &[u8] = b"HELIXOS-DO-NOT-OVERWRITE";
const BACKUP_STAGING_DATABASE_FILENAME: &str = ".replay-backup.sqlite3.staging";
#[cfg(feature = "test-fault-injection")]
const RESTORE_RETURN_ERROR_WORKER_ENV: &str = "HELIX_REPLAY_RESTORE_RETURN_ERROR_WORKER";
#[cfg(feature = "test-fault-injection")]
const RESTORE_RETURN_ERROR_PACKAGE_ENV: &str = "HELIX_REPLAY_RESTORE_RETURN_ERROR_PACKAGE";
#[cfg(feature = "test-fault-injection")]
const RESTORE_RETURN_ERROR_DESTINATION_ENV: &str = "HELIX_REPLAY_RESTORE_RETURN_ERROR_DESTINATION";
#[cfg(feature = "test-fault-injection")]
const RETURN_ERROR_ENV: &str = "HELIX_REPLAY_TEST_RETURN_ERROR";
#[cfg(feature = "test-fault-injection")]
const RESTORE_BEFORE_COPY: &str = "restore_before_copy";
const INDEPENDENT_OPERATION_ID: &str = "operation:00000000-0000-4000-8000-000000000003";
const INDEPENDENT_NONCE_CONFLICT_OPERATION_ID: &str =
    "operation:00000000-0000-4000-8000-000000000004";
const INDEPENDENT_NONCE: [u8; 16] = [0x33; 16];
const INDEPENDENT_OPERATION_CONFLICT_NONCE: [u8; 16] = [0x44; 16];

fn config_with_step_pages(root: &SyntheticTempRoot, step_pages: u32) -> ReplayStoreConfigV1 {
    ReplayStoreConfigV1::try_new(
        root.trusted_root(),
        common::DEFAULT_BUSY_WAIT_MS,
        step_pages,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("synthetic incremental backup configuration was rejected"))
}

fn progress_barrier_config(root: &SyntheticTempRoot) -> ReplayStoreConfigV1 {
    ReplayStoreConfigV1::try_new(root.trusted_root(), common::DEFAULT_BUSY_WAIT_MS, 1, 0)
        .unwrap_or_else(|_| panic!("online backup progress configuration was rejected"))
}

struct BackupFixtureResolver {
    public_key: [u8; 32],
}

impl Ed25519KeyResolver for BackupFixtureResolver {
    fn resolve_ed25519(&self, key_id: &str) -> ContractResult<[u8; 32]> {
        if key_id == common::feature002::KEY_ID {
            Ok(self.public_key)
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

fn authenticate_backup_fixture(input: PlanInputV1) -> AuthenticPlanEnvelopeV1 {
    let signer = common::feature002::TestSigner::fixed();
    let resolver = BackupFixtureResolver {
        public_key: signer.verifying_key_bytes(),
    };
    let signed = sign_plan_v1(input, &signer)
        .unwrap_or_else(|_| panic!("backup conflict fixture signing failed"));
    let wire = signed
        .to_canonical_json()
        .unwrap_or_else(|_| panic!("backup conflict fixture canonicalization failed"));
    decode_and_verify_plan(&wire, &resolver)
        .unwrap_or_else(|_| panic!("backup conflict fixture authentication failed"))
}

fn fixture_for_replay_keys(
    operation_id: &'static str,
    nonce_bytes: [u8; 16],
) -> common::feature002::EligibilityFixture {
    let nonce = Nonce128::from_bytes(nonce_bytes);
    let mut input = common::feature002::sample_plan_input();
    input.operation_id = operation_id.to_owned();
    input.nonce = nonce;
    let plan = authenticate_backup_fixture(input);
    let plan_id = plan.eligibility_claims().plan_id();
    let mut ready_input = common::feature002::coherent_ready_input(&plan);
    ready_input.authorization = AuthorizationViewV1::Current(
        AuthorizationRecordV1::try_new(AuthorizationInputV1 {
            status: AuthorizationStatusV1::Granted,
            plan_id,
            operation_id,
            risk_level: RiskLevelV1::L1,
            nonce,
            evidence_digest: common::feature002::digest(b"fixture authorization evidence"),
            authorization_generation: common::feature002::AUTHORIZATION_GENERATION,
            boot_id: common::feature002::BOOT_ID,
            not_before_utc_unix_ms: common::feature002::ISSUED_AT_MS - 10_000,
            expires_at_utc_unix_ms: common::feature002::ISSUED_AT_MS + 190_000,
            deadline_monotonic_ms: 110_000,
        })
        .unwrap_or_else(|_| panic!("backup conflict authorization construction failed")),
    );
    let ready = ReadyEligibilityContextV1::try_new(ready_input)
        .unwrap_or_else(|_| panic!("backup conflict context construction failed"));
    common::feature002::EligibilityFixture {
        plan,
        context: EligibilityContextV1::Ready(ready),
    }
}

fn assert_fresh_claim<C>(claimant: &SqliteReplayClaimantV1<C>, variant: Feature002Variant)
where
    C: ReplayMonotonicClockV1,
{
    let (result, observed) = evaluate_with_observation(feature002_fixture(variant), claimant);
    assert!(result.is_ok());
    assert!(matches!(observed, ObservedReplayOutcome::Claimed { .. }));
}

fn assert_repeat<C>(claimant: &SqliteReplayClaimantV1<C>, variant: Feature002Variant)
where
    C: ReplayMonotonicClockV1,
{
    let (result, observed) = evaluate_with_observation(feature002_fixture(variant), claimant);
    assert!(result.is_err());
    assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);
}

fn assert_fixture_conflict<C>(
    claimant: &SqliteReplayClaimantV1<C>,
    fixture: common::feature002::EligibilityFixture,
) where
    C: ReplayMonotonicClockV1,
{
    let (result, observed) = evaluate_with_observation(fixture, claimant);
    assert!(result.is_err());
    assert_eq!(observed, ObservedReplayOutcome::BindingConflict);
}

fn assert_conflict<C>(claimant: &SqliteReplayClaimantV1<C>, variant: Feature002Variant)
where
    C: ReplayMonotonicClockV1,
{
    assert_fixture_conflict(claimant, feature002_fixture(variant));
}

fn assert_independent_conflicts<C>(claimant: &SqliteReplayClaimantV1<C>)
where
    C: ReplayMonotonicClockV1,
{
    assert_fixture_conflict(
        claimant,
        fixture_for_replay_keys(INDEPENDENT_NONCE_CONFLICT_OPERATION_ID, INDEPENDENT_NONCE),
    );
    assert_fixture_conflict(
        claimant,
        fixture_for_replay_keys(
            INDEPENDENT_OPERATION_ID,
            INDEPENDENT_OPERATION_CONFLICT_NONCE,
        ),
    );
}

fn package_files(root: &SyntheticTempRoot) -> (PathBuf, PathBuf, BackupManifestV1) {
    let entries: Vec<PathBuf> = fs::read_dir(root.path())
        .unwrap_or_else(|_| panic!("backup package enumeration failed"))
        .map(|entry| {
            entry
                .unwrap_or_else(|_| panic!("backup package entry was unreadable"))
                .path()
        })
        .collect();
    assert_eq!(entries.len(), 3);

    let mut database = None;
    let mut manifest = None;
    for path in entries {
        let bytes =
            fs::read(&path).unwrap_or_else(|_| panic!("backup package member was unreadable"));
        if path
            .file_name()
            .is_some_and(|name| name == ROOT_LOCK_FILENAME)
        {
            assert_eq!(bytes, BACKUP_LOCK_CONTENT);
        } else if bytes.get(..SQLITE_HEADER.len()) == Some(SQLITE_HEADER.as_slice()) {
            assert!(database.replace(path).is_none());
        } else if let Ok(decoded) = BackupManifestV1::decode_v1(&bytes) {
            assert!(manifest.replace((path, decoded)).is_none());
        } else {
            panic!("backup package contained an unknown member")
        }
    }

    let database = database.unwrap_or_else(|| panic!("backup database was absent"));
    let (manifest_path, manifest) =
        manifest.unwrap_or_else(|| panic!("backup manifest was absent"));
    (database, manifest_path, manifest)
}

fn simulate_supervisor_activation(root: &SyntheticTempRoot) {
    let lock_path = root.path().join(ROOT_LOCK_FILENAME);
    let mut lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap_or_else(|_| panic!("restore-state simulation could not open root lock"));
    lock.try_lock()
        .unwrap_or_else(|_| panic!("restore-state simulation could not acquire root lock"));
    lock.set_len(0)
        .and_then(|()| lock.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| lock.write_all(LIVE_READY_LOCK_CONTENT))
        .and_then(|()| lock.sync_all())
        .unwrap_or_else(|_| panic!("restore-state simulation could not publish LIVE_READY"));
    fs::remove_file(root.path().join(ACTIVATION_MARKER_FILENAME))
        .unwrap_or_else(|_| panic!("restore-state simulation could not clear activation marker"));
}

fn successful_backup(source: &SyntheticTempRoot, backup: &SyntheticTempRoot) {
    let claimant = open_store(source, InjectedClock::coherent());
    claimant
        .backup_v1(backup.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("synthetic online backup failed"));
}

#[derive(Clone)]
struct CountWhileDestinationNonEmptyClock {
    destination: Arc<PathBuf>,
    observed_nonempty_reads: Arc<AtomicU64>,
}

impl CountWhileDestinationNonEmptyClock {
    fn new(destination: &SyntheticTempRoot) -> Self {
        Self {
            destination: Arc::new(destination.path().to_path_buf()),
            observed_nonempty_reads: Arc::new(AtomicU64::new(0)),
        }
    }

    fn observed_nonempty_reads(&self) -> u64 {
        self.observed_nonempty_reads.load(Ordering::SeqCst)
    }
}

impl ReplayMonotonicClockV1 for CountWhileDestinationNonEmptyClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        if fs::read_dir(self.destination.as_ref())
            .ok()
            .and_then(|mut entries| entries.next())
            .is_some()
        {
            self.observed_nonempty_reads.fetch_add(1, Ordering::SeqCst);
        }
        Ok(TEST_NOW_MONOTONIC_MS)
    }
}

#[derive(Clone)]
struct PauseAfterFirstBackupStepClock {
    destination: Arc<PathBuf>,
    staging_clock_reads: Arc<AtomicU64>,
    progress_sender: Arc<Mutex<Option<SyncSender<()>>>>,
    release_receiver: Arc<Mutex<Receiver<()>>>,
}

impl PauseAfterFirstBackupStepClock {
    fn new(destination: &SyntheticTempRoot) -> (Self, Receiver<()>, SyncSender<()>) {
        let (progress_sender, progress_receiver) = sync_channel(0);
        let (release_sender, release_receiver) = sync_channel(0);
        (
            Self {
                destination: Arc::new(destination.path().to_path_buf()),
                staging_clock_reads: Arc::new(AtomicU64::new(0)),
                progress_sender: Arc::new(Mutex::new(Some(progress_sender))),
                release_receiver: Arc::new(Mutex::new(release_receiver)),
            },
            progress_receiver,
            release_sender,
        )
    }

    fn staging_path(&self) -> PathBuf {
        self.destination.join(BACKUP_STAGING_DATABASE_FILENAME)
    }

    fn staging_clock_reads(&self) -> u64 {
        self.staging_clock_reads.load(Ordering::SeqCst)
    }
}

impl ReplayMonotonicClockV1 for PauseAfterFirstBackupStepClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        let staging_path = self.staging_path();
        if staging_path.exists() {
            let read = self.staging_clock_reads.fetch_add(1, Ordering::SeqCst) + 1;
            if read == 2 {
                let sender = self
                    .progress_sender
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                    .ok_or_else(ReplayClockUnavailableV1::new)?;
                sender
                    .send(())
                    .map_err(|_| ReplayClockUnavailableV1::new())?;
                self.release_receiver
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .recv()
                    .map_err(|_| ReplayClockUnavailableV1::new())?;
            }
        }
        Ok(TEST_NOW_MONOTONIC_MS)
    }
}

#[derive(Clone)]
struct ExpireAfterDatabaseRenameClock {
    destination: Arc<PathBuf>,
    observed_database_name: Arc<Mutex<Option<OsString>>>,
}

impl ExpireAfterDatabaseRenameClock {
    fn new(destination: &SyntheticTempRoot) -> Self {
        Self {
            destination: Arc::new(destination.path().to_path_buf()),
            observed_database_name: Arc::new(Mutex::new(None)),
        }
    }

    fn sqlite_database_name(&self) -> Option<OsString> {
        let entries = fs::read_dir(self.destination.as_ref()).ok()?;
        for entry in entries.flatten() {
            if !entry.file_type().ok()?.is_file() {
                continue;
            }
            let mut header = [0_u8; SQLITE_HEADER.len()];
            let mut file = fs::File::open(entry.path()).ok()?;
            if file.read_exact(&mut header).is_ok() && &header == SQLITE_HEADER {
                return Some(entry.file_name());
            }
        }
        None
    }
}

impl ReplayMonotonicClockV1 for ExpireAfterDatabaseRenameClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        let Some(current_name) = self.sqlite_database_name() else {
            return Ok(TEST_NOW_MONOTONIC_MS);
        };
        let mut observed = self
            .observed_database_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match observed.as_ref() {
            None => {
                *observed = Some(current_name);
                Ok(TEST_NOW_MONOTONIC_MS)
            }
            Some(initial_name) if initial_name == &current_name => Ok(TEST_NOW_MONOTONIC_MS),
            Some(_) => Ok(TEST_DEADLINE_MONOTONIC_MS),
        }
    }
}

#[derive(Clone)]
struct ExpireWhenDestinationChangesClock {
    destination: Arc<PathBuf>,
}

impl ExpireWhenDestinationChangesClock {
    fn new(destination: &SyntheticTempRoot) -> Self {
        Self {
            destination: Arc::new(destination.path().to_path_buf()),
        }
    }
}

impl ReplayMonotonicClockV1 for ExpireWhenDestinationChangesClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        let is_empty = fs::read_dir(self.destination.as_ref())
            .ok()
            .is_some_and(|mut entries| entries.next().is_none());
        if is_empty {
            Ok(TEST_NOW_MONOTONIC_MS)
        } else {
            Ok(TEST_DEADLINE_MONOTONIC_MS)
        }
    }
}

#[derive(Clone)]
struct PublishCollisionClock {
    destination: Arc<PathBuf>,
    staging_filename: &'static str,
    final_filename: &'static str,
    injected: Arc<AtomicBool>,
}

impl PublishCollisionClock {
    fn new(
        destination: &SyntheticTempRoot,
        staging_filename: &'static str,
        final_filename: &'static str,
    ) -> Self {
        Self {
            destination: Arc::new(destination.path().to_path_buf()),
            staging_filename,
            final_filename,
            injected: Arc::new(AtomicBool::new(false)),
        }
    }

    fn final_path(&self) -> PathBuf {
        self.destination.join(self.final_filename)
    }
}

impl ReplayMonotonicClockV1 for PublishCollisionClock {
    fn now_monotonic_ms(&self) -> Result<u64, ReplayClockUnavailableV1> {
        if self.destination.join(self.staging_filename).exists()
            && !self.injected.swap(true, Ordering::SeqCst)
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.final_path())
                .map_err(|_| ReplayClockUnavailableV1::new())?;
            file.write_all(COLLISION_SENTINEL)
                .and_then(|()| file.sync_all())
                .map_err(|_| ReplayClockUnavailableV1::new())?;
        }
        Ok(TEST_NOW_MONOTONIC_MS)
    }
}

#[test]
fn zero_claim_backup_restores_to_a_clean_empty_root_and_reopens() {
    let source = SyntheticTempRoot::new("backup-zero-source");
    let backup = SyntheticTempRoot::new("backup-zero-package");
    let destination = SyntheticTempRoot::new("backup-zero-restore");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&source, clock.clone());

    let backup_evidence = claimant
        .backup_v1(backup.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("zero-claim online backup failed"));
    assert_eq!(backup_evidence.claim_count(), 0);
    assert_eq!(backup_evidence.claimant_generation(), 0);
    let (_, _, manifest) = package_files(&backup);
    assert_eq!(manifest.claim_count(), 0);
    assert_eq!(manifest.claimant_generation(), 0);

    let destination_config = destination.config();
    let restore_evidence = restore_replay_store_v1(
        backup.trusted_root(),
        destination_config.clone(),
        &clock,
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("zero-claim clean restore failed"));
    assert_eq!(restore_evidence.claim_count(), 0);
    assert_eq!(restore_evidence.claimant_generation(), 0);
    assert!(restore_evidence.restored_activation_marker_present());

    let blocked = SqliteReplayClaimantV1::open_or_create(
        destination_config.clone(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    );
    assert!(blocked.is_err());
    simulate_supervisor_activation(&destination);

    let reopened = SqliteReplayClaimantV1::open_or_create(
        destination_config,
        clock,
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("zero-claim restored store did not reopen"));
    let verification = reopened
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("zero-claim restored store failed verification"));
    assert_eq!(verification.claim_count(), 0);
    assert_eq!(verification.claimant_generation(), 0);
}

#[test]
fn multiple_claim_backup_restores_exact_replay_history_after_reopen() {
    let source = SyntheticTempRoot::new("backup-multiple-source");
    let backup = SyntheticTempRoot::new("backup-multiple-package");
    let destination = SyntheticTempRoot::new("backup-multiple-restore");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&source, clock.clone());
    assert_fresh_claim(&claimant, Feature002Variant::Coherent);
    assert_fresh_claim(&claimant, Feature002Variant::Independent);

    let backup_evidence = claimant
        .backup_v1(backup.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("multiple-claim online backup failed"));
    assert_eq!(backup_evidence.claim_count(), 2);
    assert_eq!(backup_evidence.claimant_generation(), 2);
    let (_, _, manifest) = package_files(&backup);
    assert_eq!(manifest.claim_count(), 2);
    assert_eq!(manifest.claimant_generation(), 2);

    let destination_config = destination.config();
    let restored = restore_replay_store_v1(
        backup.trusted_root(),
        destination_config.clone(),
        &clock,
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("multiple-claim clean restore failed"));
    assert_eq!(restored.claim_count(), 2);
    assert_eq!(restored.claimant_generation(), 2);
    assert!(restored.restored_activation_marker_present());

    let blocked = SqliteReplayClaimantV1::open_or_create(
        destination_config.clone(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    );
    assert!(blocked.is_err());
    simulate_supervisor_activation(&destination);

    let reopened = SqliteReplayClaimantV1::open_or_create(
        destination_config,
        clock,
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("multiple-claim restored store did not reopen"));
    let verification = reopened
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("multiple-claim restored store failed verification"));
    assert_eq!(verification.claim_count(), 2);
    assert_eq!(verification.claimant_generation(), 2);
    assert_repeat(&reopened, Feature002Variant::Coherent);
    assert_repeat(&reopened, Feature002Variant::Independent);
    assert_conflict(&reopened, Feature002Variant::SameNonceDifferentOperation);
    assert_conflict(&reopened, Feature002Variant::SameOperationDifferentNonce);
}

#[test]
fn one_page_batches_observe_multiple_online_backup_steps() {
    let source = SyntheticTempRoot::new("backup-incremental-source");
    let backup = SyntheticTempRoot::new("backup-incremental-package");
    let clock = CountWhileDestinationNonEmptyClock::new(&backup);
    let claimant = SqliteReplayClaimantV1::open_or_create(
        config_with_step_pages(&source, 1),
        clock.clone(),
        TEST_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("incremental backup source open failed"));
    assert_fresh_claim(&claimant, Feature002Variant::Coherent);
    assert_fresh_claim(&claimant, Feature002Variant::Independent);

    let source_database = source.closed_database_path();
    let source_connection = Connection::open(source_database)
        .unwrap_or_else(|_| panic!("incremental source inspection failed"));
    let page_count: i64 = source_connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap_or_else(|_| panic!("incremental source page count failed"));
    drop(source_connection);
    assert!(page_count > 1);

    claimant
        .backup_v1(backup.trusted_root(), TEST_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("incremental one-page backup failed"));
    assert!(clock.observed_nonempty_reads() >= page_count as u64);
    package_files(&backup);
}

#[test]
fn online_backup_with_concurrent_claim_restores_one_coherent_generation() {
    let source = SyntheticTempRoot::new("backup-concurrent-source");
    let package = SyntheticTempRoot::new("backup-concurrent-package");
    let destination = SyntheticTempRoot::new("backup-concurrent-restore");
    let (clock, progress_receiver, release_sender) = PauseAfterFirstBackupStepClock::new(&package);
    let claimant = Arc::new(
        SqliteReplayClaimantV1::open_or_create(
            progress_barrier_config(&source),
            clock.clone(),
            TEST_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("concurrent backup source open failed")),
    );
    assert_fresh_claim(&claimant, Feature002Variant::Coherent);

    let source_connection = Connection::open(source.closed_database_path())
        .unwrap_or_else(|_| panic!("concurrent backup source inspection failed"));
    let page_count: i64 = source_connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap_or_else(|_| panic!("concurrent backup source page count failed"));
    drop(source_connection);
    assert!(page_count > 1);

    let backup_claimant = Arc::clone(&claimant);
    let package_root = package.trusted_root();
    let backup_handle =
        thread::spawn(move || backup_claimant.backup_v1(package_root, TEST_DEADLINE_MONOTONIC_MS));

    progress_receiver
        .recv()
        .unwrap_or_else(|_| panic!("online backup did not reach its first completed page step"));
    let staging_clock_reads_at_barrier = clock.staging_clock_reads();
    let (concurrent_result, concurrent_observed) = evaluate_with_observation(
        feature002_fixture(Feature002Variant::Independent),
        claimant.as_ref(),
    );
    release_sender
        .send(())
        .unwrap_or_else(|_| panic!("online backup progress barrier could not be released"));
    let backup_evidence = backup_handle
        .join()
        .unwrap_or_else(|_| panic!("online backup worker panicked"))
        .unwrap_or_else(|_| panic!("online backup with concurrent claim failed"));

    assert_eq!(staging_clock_reads_at_barrier, 2);
    assert!(concurrent_result.is_ok());
    assert_eq!(
        concurrent_observed,
        ObservedReplayOutcome::Claimed {
            claimant_generation: 2,
            receipt_matches_binding: true,
            claim_id_is_nonzero: true,
        }
    );
    let source_verification = claimant
        .verify_integrity_v1(TEST_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("concurrent backup source verification failed"));
    assert_eq!(source_verification.claim_count(), 2);
    assert_eq!(source_verification.claimant_generation(), 2);

    let (_, _, manifest) = package_files(&package);
    let snapshot_generation = manifest.claimant_generation();
    assert!(matches!(snapshot_generation, 1 | 2));
    assert_eq!(manifest.claim_count(), snapshot_generation);
    assert_eq!(backup_evidence.claimant_generation(), snapshot_generation);
    assert_eq!(backup_evidence.claim_count(), snapshot_generation);

    let destination_config = destination.config();
    let restore_evidence = restore_replay_store_v1(
        package.trusted_root(),
        destination_config.clone(),
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("concurrent backup snapshot restore failed"));
    assert_eq!(restore_evidence.claim_count(), snapshot_generation);
    assert_eq!(restore_evidence.claimant_generation(), snapshot_generation);
    assert!(restore_evidence.restored_activation_marker_present());
    assert!(SqliteReplayClaimantV1::open_or_create(
        destination_config.clone(),
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .is_err());
    simulate_supervisor_activation(&destination);

    let restored = SqliteReplayClaimantV1::open_or_create(
        destination_config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("activated concurrent backup snapshot did not reopen"));
    let restored_verification = restored
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("concurrent backup snapshot verification failed"));
    assert_eq!(restored_verification.claim_count(), snapshot_generation);
    assert_eq!(
        restored_verification.claimant_generation(),
        snapshot_generation
    );

    assert_repeat(&restored, Feature002Variant::Coherent);
    assert_conflict(&restored, Feature002Variant::SameNonceDifferentOperation);
    assert_conflict(&restored, Feature002Variant::SameOperationDifferentNonce);
    if snapshot_generation == 2 {
        assert_repeat(&restored, Feature002Variant::Independent);
        assert_independent_conflicts(&restored);
    }
}

#[test]
fn successful_package_publishes_role_database_and_valid_manifest() {
    let source = SyntheticTempRoot::new("backup-publish-source");
    let backup = SyntheticTempRoot::new("backup-publish-package");
    successful_backup(&source, &backup);

    let (_, _, manifest) = package_files(&backup);
    assert!(manifest.requires_paused_activation());
    assert!(manifest.requires_instance_epoch_rotation());
    assert!(manifest.requires_fencing_epoch_rotation());
    assert!(manifest.may_omit_claims_after_generation());
}

#[test]
fn public_backup_verifier_checks_complete_package_and_rejects_incomplete_staging() {
    let source = SyntheticTempRoot::new("backup-verify-source");
    let package = SyntheticTempRoot::new("backup-verify-package");
    let claimant = open_store(&source, InjectedClock::coherent());
    assert_fresh_claim(&claimant, Feature002Variant::Coherent);
    claimant
        .backup_v1(package.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("backup verification fixture failed"));

    let evidence = verify_replay_backup_v1(
        package.trusted_root(),
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("complete backup package did not verify"));
    assert_eq!(evidence.claim_count(), 1);
    assert_eq!(evidence.claimant_generation(), 1);

    let incomplete = SyntheticTempRoot::new("backup-verify-incomplete");
    let incomplete_root = incomplete.trusted_root();
    fs::write(
        incomplete.path().join(ROOT_LOCK_FILENAME),
        BACKUP_LOCK_CONTENT,
    )
    .and_then(|()| {
        fs::write(
            incomplete.path().join(BACKUP_STAGING_DATABASE_FILENAME),
            SQLITE_HEADER,
        )
    })
    .unwrap_or_else(|_| panic!("incomplete staging fixture could not be published"));
    let error = verify_replay_backup_v1(
        incomplete_root,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("incomplete staging package verified");
    assert_eq!(error, ReplayStoreMaintenanceErrorV1::BackupIncomplete);
}

#[test]
fn public_backup_verifier_rejects_extra_members_and_digest_mutation() {
    let extra_source = SyntheticTempRoot::new("backup-verify-extra-source");
    let extra_package = SyntheticTempRoot::new("backup-verify-extra-package");
    successful_backup(&extra_source, &extra_package);
    let extra_root = extra_package.trusted_root();
    fs::write(extra_package.path().join("foreign-member"), b"foreign")
        .unwrap_or_else(|_| panic!("extra backup member fixture failed"));
    let extra_error = verify_replay_backup_v1(
        extra_root,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("backup package with an extra member verified");
    assert_eq!(extra_error, ReplayStoreMaintenanceErrorV1::BackupIncomplete);

    let digest_source = SyntheticTempRoot::new("backup-verify-digest-source");
    let digest_package = SyntheticTempRoot::new("backup-verify-digest-package");
    successful_backup(&digest_source, &digest_package);
    let digest_root = digest_package.trusted_root();
    let (database, _, _) = package_files(&digest_package);
    OpenOptions::new()
        .append(true)
        .open(database)
        .and_then(|mut file| file.write_all(b"digest-mismatch"))
        .unwrap_or_else(|_| panic!("backup digest mutation failed"));
    let digest_error = verify_replay_backup_v1(
        digest_root,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("digest-mutated backup package verified");
    assert_eq!(
        digest_error,
        ReplayStoreMaintenanceErrorV1::DatabaseDigestMismatch
    );
}

#[test]
fn deadline_between_database_and_manifest_publish_leaves_no_restorable_package() {
    let source = SyntheticTempRoot::new("backup-manifest-last-source");
    let backup = SyntheticTempRoot::new("backup-manifest-last-package");
    let restore_destination = SyntheticTempRoot::new("backup-manifest-last-restore");
    let clock = ExpireAfterDatabaseRenameClock::new(&backup);
    let claimant =
        SqliteReplayClaimantV1::open_or_create(source.config(), clock, TEST_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("manifest-last source open failed"));
    let backup_root = backup.trusted_root();

    let error = claimant
        .backup_v1(backup_root.clone(), TEST_DEADLINE_MONOTONIC_MS)
        .err()
        .unwrap_or_else(|| panic!("manifest-last interruption unexpectedly succeeded"));
    assert_eq!(
        error,
        ReplayStoreMaintenanceErrorV1::MaintenanceDeadlineReached
    );
    assert!(fs::read_dir(backup.path())
        .unwrap_or_else(|_| panic!("interrupted package enumeration failed"))
        .next()
        .is_some());
    assert!(TrustedLocalStoreRootV1::try_from_provisioned(backup.path().to_path_buf()).is_err());

    let restore_error = restore_replay_store_v1(
        backup_root,
        restore_destination.config(),
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("interrupted package unexpectedly restored"));
    assert_eq!(
        restore_error,
        ReplayStoreMaintenanceErrorV1::BackupIncomplete
    );
}

#[test]
fn backup_and_restore_reject_same_root_and_nonempty_destinations() {
    let source = SyntheticTempRoot::new("backup-boundary-source");
    let package = SyntheticTempRoot::new("backup-boundary-package");
    let backup_nonempty = SyntheticTempRoot::new("backup-nonempty-destination");
    let restore_nonempty = SyntheticTempRoot::new("restore-nonempty-destination");
    let claimant = open_store(&source, InjectedClock::coherent());

    let same_root_error = claimant
        .backup_v1(source.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .err()
        .unwrap_or_else(|| panic!("same-root backup unexpectedly succeeded"));
    assert_eq!(
        same_root_error,
        ReplayStoreMaintenanceErrorV1::SourceDestinationConflict
    );

    let backup_nonempty_root = backup_nonempty.trusted_root();
    backup_nonempty.create_foreign_file();
    let nonempty_backup_error = claimant
        .backup_v1(backup_nonempty_root, MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .err()
        .unwrap_or_else(|| panic!("nonempty backup destination unexpectedly succeeded"));
    assert_eq!(
        nonempty_backup_error,
        ReplayStoreMaintenanceErrorV1::DestinationNotEmpty
    );

    claimant
        .backup_v1(package.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("boundary package backup failed"));
    let package_root = package.trusted_root();
    let same_root_config = ReplayStoreConfigV1::try_new(
        package_root.clone(),
        common::DEFAULT_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("same-root restore configuration was rejected"));
    let same_restore_error = restore_replay_store_v1(
        package_root.clone(),
        same_root_config,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("same-root restore unexpectedly succeeded"));
    assert_eq!(
        same_restore_error,
        ReplayStoreMaintenanceErrorV1::SourceDestinationConflict
    );

    let nonempty_restore_config = restore_nonempty.config();
    restore_nonempty.create_foreign_file();
    let nonempty_restore_error = restore_replay_store_v1(
        package_root,
        nonempty_restore_config,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("nonempty restore destination unexpectedly succeeded"));
    assert_eq!(
        nonempty_restore_error,
        ReplayStoreMaintenanceErrorV1::DestinationNotEmpty
    );
}

#[test]
fn concurrent_backup_and_restore_destinations_have_one_reservation_winner() {
    let source = SyntheticTempRoot::new("reservation-source");
    let package = SyntheticTempRoot::new("reservation-package");
    let backup_destination = SyntheticTempRoot::new("reservation-backup-destination");
    let claimant = Arc::new(open_store(&source, InjectedClock::coherent()));
    let backup_root = backup_destination.trusted_root();
    let barrier = Arc::new(Barrier::new(2));
    let mut backup_handles = Vec::new();
    for _ in 0..2 {
        let claimant = Arc::clone(&claimant);
        let destination = backup_root.clone();
        let barrier = Arc::clone(&barrier);
        backup_handles.push(thread::spawn(move || {
            barrier.wait();
            claimant.backup_v1(destination, MAINTENANCE_DEADLINE_MONOTONIC_MS)
        }));
    }
    let backup_results = backup_handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .unwrap_or_else(|_| panic!("backup reserver panicked"))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        backup_results
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1
    );
    assert_eq!(
        backup_results
            .iter()
            .filter(|result| {
                result.as_ref().err() == Some(&ReplayStoreMaintenanceErrorV1::DestinationNotEmpty)
            })
            .count(),
        1
    );

    successful_backup(&source, &package);
    let alternate_package = SyntheticTempRoot::new("reservation-alternate-package");
    successful_backup(&source, &alternate_package);
    let restore_destination = SyntheticTempRoot::new("reservation-restore-destination");
    let destination_config = restore_destination.config();
    let package_roots = [package.trusted_root(), alternate_package.trusted_root()];
    let barrier = Arc::new(Barrier::new(2));
    let mut restore_handles = Vec::new();
    for package in package_roots {
        let destination = destination_config.clone();
        let barrier = Arc::clone(&barrier);
        restore_handles.push(thread::spawn(move || {
            barrier.wait();
            restore_replay_store_v1(
                package,
                destination,
                &InjectedClock::coherent(),
                MAINTENANCE_DEADLINE_MONOTONIC_MS,
            )
        }));
    }
    let restore_results = restore_handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .unwrap_or_else(|_| panic!("restore reserver panicked"))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        restore_results
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1
    );
    assert_eq!(
        restore_results
            .iter()
            .filter(|result| {
                result.as_ref().err() == Some(&ReplayStoreMaintenanceErrorV1::DestinationNotEmpty)
            })
            .count(),
        1
    );
}

#[test]
fn stale_staging_and_late_final_collisions_are_never_reused_or_overwritten() {
    let source = SyntheticTempRoot::new("no-clobber-source");
    let stale_destination = SyntheticTempRoot::new("no-clobber-stale-destination");
    let stale_root = stale_destination.trusted_root();
    let stale_path = stale_destination
        .path()
        .join(".replay-backup.sqlite3.staging");
    fs::write(&stale_path, COLLISION_SENTINEL)
        .unwrap_or_else(|_| panic!("stale staging fixture write failed"));
    let claimant = open_store(&source, InjectedClock::coherent());
    let stale_error = claimant
        .backup_v1(stale_root, MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .err()
        .unwrap_or_else(|| panic!("stale staging destination was reused"));
    assert_eq!(
        stale_error,
        ReplayStoreMaintenanceErrorV1::DestinationNotEmpty
    );
    assert_eq!(
        fs::read(&stale_path).unwrap_or_else(|_| panic!("stale staging fixture disappeared")),
        COLLISION_SENTINEL
    );

    let backup_collision = SyntheticTempRoot::new("no-clobber-backup-final");
    let backup_clock = PublishCollisionClock::new(
        &backup_collision,
        ".replay-backup.sqlite3.staging",
        "replay-backup.sqlite3",
    );
    let collision_claimant = SqliteReplayClaimantV1::open_or_create(
        source.config(),
        backup_clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("backup collision claimant open failed"));
    let backup_error = collision_claimant
        .backup_v1(
            backup_collision.trusted_root(),
            MAINTENANCE_DEADLINE_MONOTONIC_MS,
        )
        .err()
        .unwrap_or_else(|| panic!("backup final collision was overwritten"));
    assert_eq!(
        backup_error,
        ReplayStoreMaintenanceErrorV1::BackupIncomplete
    );
    assert_eq!(
        fs::read(backup_clock.final_path())
            .unwrap_or_else(|_| panic!("backup collision sentinel disappeared")),
        COLLISION_SENTINEL
    );

    let package = SyntheticTempRoot::new("no-clobber-restore-package");
    successful_backup(&source, &package);
    let restore_collision = SyntheticTempRoot::new("no-clobber-restore-final");
    let restore_clock = PublishCollisionClock::new(
        &restore_collision,
        ".replay.sqlite3.restore-staging",
        "replay.sqlite3",
    );
    let restore_config = restore_collision.config();
    let restore_error = restore_replay_store_v1(
        package.trusted_root(),
        restore_config.clone(),
        &restore_clock,
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("restore final collision was overwritten"));
    assert_eq!(
        restore_error,
        ReplayStoreMaintenanceErrorV1::RestoreIncomplete
    );
    assert_eq!(
        fs::read(restore_clock.final_path())
            .unwrap_or_else(|_| panic!("restore collision sentinel disappeared")),
        COLLISION_SENTINEL
    );
    assert!(SqliteReplayClaimantV1::open_or_create(
        restore_config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .is_err());
}

#[test]
fn restore_rejects_missing_invalid_and_digest_mismatched_manifests() {
    let missing_source = SyntheticTempRoot::new("restore-missing-source");
    let missing_package = SyntheticTempRoot::new("restore-missing-package");
    let missing_destination = SyntheticTempRoot::new("restore-missing-destination");
    successful_backup(&missing_source, &missing_package);
    let missing_root = missing_package.trusted_root();
    let (_, missing_manifest, _) = package_files(&missing_package);
    fs::remove_file(missing_manifest)
        .unwrap_or_else(|_| panic!("missing-manifest fixture mutation failed"));
    let missing_error = restore_replay_store_v1(
        missing_root,
        missing_destination.config(),
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("missing-manifest package unexpectedly restored"));
    assert_eq!(
        missing_error,
        ReplayStoreMaintenanceErrorV1::ManifestMissing
    );

    let invalid_source = SyntheticTempRoot::new("restore-invalid-source");
    let invalid_package = SyntheticTempRoot::new("restore-invalid-package");
    let invalid_destination = SyntheticTempRoot::new("restore-invalid-destination");
    successful_backup(&invalid_source, &invalid_package);
    let invalid_root = invalid_package.trusted_root();
    let (_, invalid_manifest, _) = package_files(&invalid_package);
    fs::write(invalid_manifest, br#"{"schema":"unsupported"}"#)
        .unwrap_or_else(|_| panic!("invalid-manifest fixture mutation failed"));
    let invalid_error = restore_replay_store_v1(
        invalid_root,
        invalid_destination.config(),
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("invalid-manifest package unexpectedly restored"));
    assert_eq!(
        invalid_error,
        ReplayStoreMaintenanceErrorV1::ManifestInvalid
    );

    let digest_source = SyntheticTempRoot::new("restore-digest-source");
    let digest_package = SyntheticTempRoot::new("restore-digest-package");
    let digest_destination = SyntheticTempRoot::new("restore-digest-destination");
    successful_backup(&digest_source, &digest_package);
    let digest_root = digest_package.trusted_root();
    let (database, _, _) = package_files(&digest_package);
    OpenOptions::new()
        .append(true)
        .open(database)
        .and_then(|mut file| file.write_all(b"digest-mismatch"))
        .unwrap_or_else(|_| panic!("digest-mismatch fixture mutation failed"));
    let digest_error = restore_replay_store_v1(
        digest_root,
        digest_destination.config(),
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("digest-mismatched package unexpectedly restored"));
    assert_eq!(
        digest_error,
        ReplayStoreMaintenanceErrorV1::DatabaseDigestMismatch
    );
}

#[test]
fn restore_deadline_after_staging_begins_never_activates_partial_destination() {
    let source = SyntheticTempRoot::new("restore-deadline-source");
    let package = SyntheticTempRoot::new("restore-deadline-package");
    let destination = SyntheticTempRoot::new("restore-deadline-destination");
    successful_backup(&source, &package);
    let destination_config = destination.config();
    let clock = ExpireWhenDestinationChangesClock::new(&destination);

    let error = restore_replay_store_v1(
        package.trusted_root(),
        destination_config.clone(),
        &clock,
        TEST_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("deadline-interrupted restore unexpectedly succeeded"));
    assert_eq!(
        error,
        ReplayStoreMaintenanceErrorV1::MaintenanceDeadlineReached
    );
    assert!(fs::read_dir(destination.path())
        .unwrap_or_else(|_| panic!("partial restore destination enumeration failed"))
        .next()
        .is_some());

    let activation_error = SqliteReplayClaimantV1::open_or_create(
        destination_config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("partial restore destination unexpectedly activated"));
    assert_eq!(activation_error.code(), "LOCATION_NOT_DEDICATED");
}

#[test]
fn verified_restore_evidence_requires_paused_activation_and_epoch_rotation() {
    let source = SyntheticTempRoot::new("restore-evidence-source");
    let package = SyntheticTempRoot::new("restore-evidence-package");
    let destination = SyntheticTempRoot::new("restore-evidence-destination");
    let clock = InjectedClock::coherent();
    let claimant = open_store(&source, clock.clone());
    assert_fresh_claim(&claimant, Feature002Variant::Coherent);
    claimant
        .backup_v1(package.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("restore-evidence backup failed"));

    let evidence = restore_replay_store_v1(
        package.trusted_root(),
        destination.config(),
        &clock,
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("restore-evidence clean restore failed"));
    assert_eq!(evidence.claim_count(), 1);
    assert_eq!(evidence.claimant_generation(), 1);
    assert!(evidence.requires_paused_activation());
    assert!(evidence.requires_instance_epoch_rotation());
    assert!(evidence.requires_fencing_epoch_rotation());
    assert!(evidence.may_omit_claims_after_generation());
    assert!(evidence.restored_activation_marker_present());
}

#[cfg(feature = "test-fault-injection")]
#[test]
#[ignore = "private return-error child entry point"]
fn restore_return_error_worker() {
    if std::env::var(RESTORE_RETURN_ERROR_WORKER_ENV)
        .ok()
        .as_deref()
        != Some("1")
    {
        return;
    }
    let package = std::env::var_os(RESTORE_RETURN_ERROR_PACKAGE_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("return-error worker package was not supplied"));
    let destination = std::env::var_os(RESTORE_RETURN_ERROR_DESTINATION_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("return-error worker destination was not supplied"));
    let package = TrustedLocalStoreRootV1::try_from_provisioned(package)
        .unwrap_or_else(|_| panic!("return-error worker package was rejected"));
    let destination = TrustedLocalStoreRootV1::try_from_provisioned(destination)
        .unwrap_or_else(|_| panic!("return-error worker destination was rejected"));
    let destination = ReplayStoreConfigV1::try_new(
        destination,
        common::DEFAULT_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("return-error worker configuration was rejected"));
    let error = restore_replay_store_v1(
        package,
        destination,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("injected restore unexpectedly completed");
    assert_eq!(error, ReplayStoreMaintenanceErrorV1::RestoreIncomplete);
    println!("HELIX_RESTORE_RETURN_ERROR_OK");
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn restore_return_error_leaves_pending_nonclaimable_destination() {
    let source = SyntheticTempRoot::new("restore-return-error-source");
    let package = SyntheticTempRoot::new("restore-return-error-package");
    let destination = SyntheticTempRoot::new("restore-return-error-destination");
    successful_backup(&source, &package);
    let destination_config = destination.config();

    let executable = std::env::current_exe()
        .unwrap_or_else(|_| panic!("return-error test executable was unavailable"));
    let output = Command::new(executable)
        .args([
            "--exact",
            "restore_return_error_worker",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RESTORE_RETURN_ERROR_WORKER_ENV, "1")
        .env(RESTORE_RETURN_ERROR_PACKAGE_ENV, package.path())
        .env(RESTORE_RETURN_ERROR_DESTINATION_ENV, destination.path())
        .env(RETURN_ERROR_ENV, RESTORE_BEFORE_COPY)
        .output()
        .unwrap_or_else(|_| panic!("return-error worker could not be launched"));
    assert!(
        output.status.success(),
        "return-error worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("HELIX_RESTORE_RETURN_ERROR_OK"),
        "return-error worker did not report completion"
    );

    assert_eq!(
        fs::read(destination.path().join(ROOT_LOCK_FILENAME))
            .unwrap_or_else(|_| panic!("pending restore lock was unreadable")),
        RESTORE_PENDING_LOCK_CONTENT
    );
    assert!(destination
        .path()
        .join(ACTIVATION_MARKER_FILENAME)
        .is_file());
    assert!(!destination.path().join("replay.sqlite3").exists());
    assert!(!destination
        .path()
        .join(".replay.sqlite3.restore-staging")
        .exists());
    let open_error = SqliteReplayClaimantV1::open_or_create(
        destination_config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("pending restore became claimable");
    assert_eq!(open_error.code(), "LOCATION_NOT_DEDICATED");
}
