//! Process-kill all-or-none matrix; this is never power-loss evidence.

mod common;

use common::{
    evaluate_with_observation, feature002_fixture, Feature002Variant, InjectedClock,
    ObservedReplayOutcome, SyntheticTempRoot, DEFAULT_BACKUP_RETRY_WAIT_MS,
    DEFAULT_BACKUP_STEP_PAGES, DEFAULT_BUSY_WAIT_MS, MAINTENANCE_DEADLINE_MONOTONIC_MS,
    OPEN_DEADLINE_MONOTONIC_MS,
};
use helix_plan_eligibility::EligibilityDenialV1;
use helix_replay_sqlite::{
    restore_replay_store_v1, ReplayCheckpointModeV1, ReplayStoreConfigV1,
    ReplayStoreMaintenanceErrorV1, SqliteReplayClaimantV1, TrustedLocalStoreRootV1,
};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, Read as _, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const WORKER_ENV: &str = "HELIX_REPLAY_PROCESS_WORKER";
const ROOT_ENV: &str = "HELIX_REPLAY_PROCESS_ROOT";
const BACKUP_ROOT_ENV: &str = "HELIX_REPLAY_PROCESS_BACKUP_ROOT";
const RESTORE_ROOT_ENV: &str = "HELIX_REPLAY_PROCESS_RESTORE_ROOT";
const FAULT_ENV: &str = "HELIX_REPLAY_TEST_FAULT_POINT";
const READY_PREFIX: &str = "READY:";
const GO_BYTE: u8 = b'G';
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(15);
const REAP_POLL: Duration = Duration::from_millis(5);
const ROOT_LOCK_FILENAME: &str = ".helix-replay-root-v1.lock";
const ACTIVATION_MARKER_FILENAME: &str = ".helix-replay-restored-activation-required-v1";
const LIVE_READY_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=LIVE_READY\n";
const RESTORE_PENDING_LOCK_CONTENT: &[u8] = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=RESTORE_PENDING\n";
const RESTORED_ACTIVATION_MARKER_CONTENT: &[u8] =
    b"HELIXOS_REPLAY_RESTORED_ACTIVATION_REQUIRED_V1\n";

#[test]
#[ignore = "private child entry point"]
fn fault_worker_process() {
    if std::env::var(WORKER_ENV).ok().as_deref() != Some("1") {
        return;
    }
    let fault_point =
        std::env::var(FAULT_ENV).unwrap_or_else(|_| panic!("fault worker point was not supplied"));
    announce_ready_and_wait_for_go(&fault_point);

    if fault_point.starts_with("restore_") {
        run_restore_fault_worker();
        return;
    }

    let root = std::env::var_os(ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("fault worker root was not supplied"));
    let trusted = TrustedLocalStoreRootV1::try_from_provisioned(root)
        .unwrap_or_else(|_| panic!("fault worker root was rejected"));
    let config = ReplayStoreConfigV1::try_new(
        trusted,
        DEFAULT_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("fault worker configuration was rejected"));
    let claimant = SqliteReplayClaimantV1::open_or_create(
        config,
        InjectedClock::coherent(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("fault worker store open failed"));
    if fault_point.starts_with("initialization_") {
        return;
    }

    let _eligible = feature002_fixture(Feature002Variant::Coherent)
        .evaluate(&claimant)
        .unwrap_or_else(|_| panic!("fault worker initial claim failed"));

    if fault_point.starts_with("backup_") {
        let backup_root = std::env::var_os(BACKUP_ROOT_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("fault worker backup root was not supplied"));
        let trusted_backup = TrustedLocalStoreRootV1::try_from_provisioned(backup_root)
            .unwrap_or_else(|_| panic!("fault worker backup root was rejected"));
        claimant
            .backup_v1(trusted_backup, MAINTENANCE_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("fault worker backup failed"));
    } else if fault_point.starts_with("checkpoint_") {
        claimant
            .checkpoint_v1(
                ReplayCheckpointModeV1::QuiescentTruncate,
                MAINTENANCE_DEADLINE_MONOTONIC_MS,
            )
            .unwrap_or_else(|_| panic!("fault worker checkpoint failed"));
    }
}

fn announce_ready_and_wait_for_go(fault_point: &str) {
    println!("{READY_PREFIX}{fault_point}");
    std::io::stdout()
        .flush()
        .unwrap_or_else(|_| panic!("fault worker readiness flush failed"));
    let mut go = [0_u8; 1];
    std::io::stdin()
        .lock()
        .read_exact(&mut go)
        .unwrap_or_else(|_| panic!("fault worker start signal was unavailable"));
    assert_eq!(go[0], GO_BYTE, "fault worker start signal was invalid");
}

fn run_restore_fault_worker() {
    let backup_root = std::env::var_os(BACKUP_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("restore fault worker backup root was not supplied"));
    let trusted_backup = TrustedLocalStoreRootV1::try_from_provisioned(backup_root)
        .unwrap_or_else(|_| panic!("restore fault worker backup root was rejected"));
    let destination_root = std::env::var_os(RESTORE_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("restore fault worker destination root was not supplied"));
    let trusted_destination = TrustedLocalStoreRootV1::try_from_provisioned(destination_root)
        .unwrap_or_else(|_| panic!("restore fault worker destination root was rejected"));
    let destination_config = ReplayStoreConfigV1::try_new(
        trusted_destination,
        DEFAULT_BUSY_WAIT_MS,
        DEFAULT_BACKUP_STEP_PAGES,
        DEFAULT_BACKUP_RETRY_WAIT_MS,
    )
    .unwrap_or_else(|_| panic!("restore fault worker configuration was rejected"));
    restore_replay_store_v1(
        trusted_backup,
        destination_config,
        &InjectedClock::coherent(),
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("restore fault worker restore failed"));
}

#[test]
#[ignore = "release process-kill evidence matrix"]
fn every_frozen_claim_boundary_reopens_all_or_none() {
    let phases = [
        ("opened", false),
        ("begin_acquired", false),
        ("generation_updated", false),
        ("row_inserted", false),
        ("before_commit", false),
        ("commit_returned", true),
        ("before_result_ack", true),
    ];

    for (phase, committed) in phases {
        run_killed_phase(phase, committed);
    }
}

#[test]
#[ignore = "release initialization process-kill evidence matrix"]
fn initialization_boundaries_fresh_reopen_to_valid_empty_store() {
    for phase in ["initialization_schema_staged", "initialization_committed"] {
        let root = SyntheticTempRoot::new(phase.replace('_', "-").as_str());
        let retained_config = root.config();
        kill_worker_at_phase(&root, None, None, phase);

        let clock = InjectedClock::coherent();
        let claimant = SqliteReplayClaimantV1::open_or_create(
            retained_config,
            clock,
            OPEN_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("initialization process-kill store failed fresh reopen"));
        let before = claimant
            .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("reopened initialized store failed verification"));
        assert_eq!(before.claim_count(), 0);
        assert_eq!(before.claimant_generation(), 0);

        let (result, observed) =
            evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
        assert!(
            result.is_ok(),
            "reopened initialized store refused a fresh claim"
        );
        assert!(matches!(observed, ObservedReplayOutcome::Claimed { .. }));
        let after = claimant
            .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| {
                panic!("reopened initialized store failed post-claim verification")
            });
        assert_eq!(after.claim_count(), 1);
        assert_eq!(after.claimant_generation(), 1);
    }
}

#[test]
#[ignore = "release checkpoint process-kill evidence matrix"]
fn checkpoint_boundaries_fresh_reopen_without_losing_claims() {
    for phase in ["checkpoint_before_mutation", "checkpoint_returned"] {
        let root = SyntheticTempRoot::new(phase.replace('_', "-").as_str());
        let retained_config = root.config();
        kill_worker_at_phase(&root, None, None, phase);

        let clock = InjectedClock::coherent();
        let claimant = SqliteReplayClaimantV1::open_or_create(
            retained_config,
            clock,
            OPEN_DEADLINE_MONOTONIC_MS,
        )
        .unwrap_or_else(|_| panic!("checkpoint process-kill store failed fresh reopen"));
        let (result, observed) =
            evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
        let failure = result
            .err()
            .unwrap_or_else(|| panic!("checkpoint process-kill lost a committed claim"));
        assert_eq!(failure.denial(), EligibilityDenialV1::ReplayAlreadyClaimed);
        assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);
        let verification = claimant
            .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("checkpoint process-kill store failed verification"));
        assert_eq!(verification.claim_count(), 1);
        assert_eq!(verification.claimant_generation(), 1);
    }
}

#[test]
#[ignore = "release backup publication process-kill evidence matrix"]
fn backup_publication_boundaries_reject_incomplete_and_restore_published() {
    let phases = [
        ("backup_database_complete", false),
        ("backup_manifest_staged", false),
        ("backup_published", true),
    ];

    for (phase, published) in phases {
        run_killed_backup_phase(phase, published);
    }
}

#[test]
#[ignore = "release restore process-kill evidence matrix"]
fn restore_boundaries_remain_pending_inactive_and_no_clobber() {
    for phase in [
        "restore_reserved",
        "restore_database_staged",
        "restore_published",
        "restore_profile_verified",
    ] {
        run_killed_restore_phase(phase);
    }
}

fn run_killed_phase(phase: &str, committed: bool) {
    let root = SyntheticTempRoot::new(phase.replace('_', "-").as_str());
    kill_worker_at_phase(&root, None, None, phase);

    let clock = InjectedClock::coherent();
    let claimant =
        SqliteReplayClaimantV1::open_or_create(root.config(), clock, OPEN_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("process-kill store failed fresh reopen"));
    let (result, observed) =
        evaluate_with_observation(feature002_fixture(Feature002Variant::Coherent), &claimant);
    if committed {
        let failure = result
            .err()
            .unwrap_or_else(|| panic!("post-commit killed claim was admitted again"));
        assert_eq!(failure.denial(), EligibilityDenialV1::ReplayAlreadyClaimed);
        assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);
    } else {
        assert!(result.is_ok(), "pre-commit killed claim was not fresh");
        assert!(matches!(observed, ObservedReplayOutcome::Claimed { .. }));
    }

    let verification = claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("process-kill reopened store failed verification"));
    assert_eq!(verification.claim_count(), 1);
    assert_eq!(verification.claimant_generation(), 1);
}

fn run_killed_backup_phase(phase: &str, published: bool) {
    let source = SyntheticTempRoot::new(format!("{phase}-source").replace('_', "-").as_str());
    let backup = SyntheticTempRoot::new(format!("{phase}-backup").replace('_', "-").as_str());
    let restore = SyntheticTempRoot::new(format!("{phase}-restore").replace('_', "-").as_str());
    let retained_backup_root = backup.trusted_root();

    kill_worker_at_phase(&source, Some(&backup), None, phase);

    let clock = InjectedClock::coherent();
    let source_claimant = SqliteReplayClaimantV1::open_or_create(
        source.config(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("backup process-kill source failed fresh reopen"));
    let source_verification = source_claimant
        .verify_integrity_v1(MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("backup process-kill source failed verification"));
    assert_eq!(source_verification.claim_count(), 1);
    assert_eq!(source_verification.claimant_generation(), 1);

    let restored = restore_replay_store_v1(
        retained_backup_root,
        restore.config(),
        &clock,
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    );
    if !published {
        assert_eq!(
            restored.expect_err("incomplete backup was accepted for restore"),
            ReplayStoreMaintenanceErrorV1::BackupIncomplete
        );
        return;
    }

    let evidence = restored.unwrap_or_else(|_| panic!("published backup failed clean restore"));
    assert_eq!(evidence.claim_count(), 1);
    assert_eq!(evidence.claimant_generation(), 1);
    assert!(evidence.requires_paused_activation());
    assert!(evidence.requires_instance_epoch_rotation());
    assert!(evidence.requires_fencing_epoch_rotation());
    assert!(evidence.may_omit_claims_after_generation());

    let pending_error = SqliteReplayClaimantV1::open_or_create(
        restore.config(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("RESTORE_PENDING destination reopened before activation"));
    assert_eq!(pending_error.code(), "LOCATION_NOT_DEDICATED");

    simulate_supervisor_activation(&restore);
    let restored_claimant =
        SqliteReplayClaimantV1::open_or_create(restore.config(), clock, OPEN_DEADLINE_MONOTONIC_MS)
            .unwrap_or_else(|_| panic!("restored backup failed fresh reopen"));
    let (result, observed) = evaluate_with_observation(
        feature002_fixture(Feature002Variant::Coherent),
        &restored_claimant,
    );
    let failure = result
        .err()
        .unwrap_or_else(|| panic!("restored backup admitted an already claimed binding"));
    assert_eq!(failure.denial(), EligibilityDenialV1::ReplayAlreadyClaimed);
    assert_eq!(observed, ObservedReplayOutcome::AlreadyClaimed);
}

fn run_killed_restore_phase(phase: &str) {
    let source = SyntheticTempRoot::new(format!("{phase}-source").replace('_', "-").as_str());
    let backup = SyntheticTempRoot::new(format!("{phase}-backup").replace('_', "-").as_str());
    let destination =
        SyntheticTempRoot::new(format!("{phase}-destination").replace('_', "-").as_str());
    let destination_config = destination.config();

    let clock = InjectedClock::coherent();
    let source_claimant = SqliteReplayClaimantV1::open_or_create(
        source.config(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .unwrap_or_else(|_| panic!("restore process-kill source open failed"));
    let _eligible = feature002_fixture(Feature002Variant::Coherent)
        .evaluate(&source_claimant)
        .unwrap_or_else(|_| panic!("restore process-kill source claim failed"));
    source_claimant
        .backup_v1(backup.trusted_root(), MAINTENANCE_DEADLINE_MONOTONIC_MS)
        .unwrap_or_else(|_| panic!("restore process-kill backup preparation failed"));
    drop(source_claimant);

    kill_worker_at_phase(&source, Some(&backup), Some(&destination), phase);

    assert_exact_file(
        destination.path().join(ROOT_LOCK_FILENAME),
        RESTORE_PENDING_LOCK_CONTENT,
        "restore process-kill root was not RESTORE_PENDING",
    );
    assert_exact_file(
        destination.path().join(ACTIVATION_MARKER_FILENAME),
        RESTORED_ACTIVATION_MARKER_CONTENT,
        "restore process-kill activation marker was absent or invalid",
    );

    let pending_error = SqliteReplayClaimantV1::open_or_create(
        destination_config.clone(),
        clock.clone(),
        OPEN_DEADLINE_MONOTONIC_MS,
    )
    .err()
    .unwrap_or_else(|| panic!("restore process-kill destination activated as a live store"));
    assert_eq!(pending_error.code(), "LOCATION_NOT_DEDICATED");

    let before_retry = snapshot_directory(&destination);
    let retry_error = restore_replay_store_v1(
        backup.trusted_root(),
        destination_config,
        &clock,
        MAINTENANCE_DEADLINE_MONOTONIC_MS,
    )
    .expect_err("restore process-kill destination was overwritten on retry");
    assert_eq!(
        retry_error,
        ReplayStoreMaintenanceErrorV1::DestinationNotEmpty
    );
    let after_retry = snapshot_directory(&destination);
    assert!(
        before_retry == after_retry,
        "rejected restore retry changed the pending destination"
    );
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

fn kill_worker_at_phase(
    source: &SyntheticTempRoot,
    backup: Option<&SyntheticTempRoot>,
    restore: Option<&SyntheticTempRoot>,
    phase: &str,
) {
    let executable = std::env::current_exe()
        .unwrap_or_else(|_| panic!("process-kill test executable was unavailable"));
    let mut command = Command::new(executable);
    command
        .args([
            "--exact",
            "fault_worker_process",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(WORKER_ENV, "1")
        .env(ROOT_ENV, source.path())
        .env(FAULT_ENV, phase)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(backup) = backup {
        command.env(BACKUP_ROOT_ENV, backup.path());
    }
    if let Some(restore) = restore {
        command.env(RESTORE_ROOT_ENV, restore.path());
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|_| panic!("process-kill worker failed to spawn"));
    let mut stdin = child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("process-kill worker stdin was unavailable"));

    let stdout = child
        .stdout
        .take()
        .unwrap_or_else(|| panic!("process-kill worker stdout was unavailable"));
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    let ready = format!("{READY_PREFIX}{phase}");
    if !wait_for_protocol_line(&receiver, &ready) {
        terminate_and_reap(&mut child);
        drop(stdin);
        let _ = reader.join();
        panic!("process-kill worker did not become ready for {phase}");
    }
    stdin
        .write_all(&[GO_BYTE])
        .and_then(|()| stdin.flush())
        .unwrap_or_else(|_| panic!("process-kill worker start signal failed"));

    let expected = format!("AT:{phase}");
    if !wait_for_protocol_line(&receiver, &expected) {
        terminate_and_reap(&mut child);
        drop(stdin);
        let _ = reader.join();
        panic!("process-kill worker did not reach bounded fault point {phase}");
    }

    terminate_and_reap(&mut child);
    drop(stdin);
    reader
        .join()
        .unwrap_or_else(|_| panic!("process-kill reader thread failed"));
}

fn wait_for_protocol_line(receiver: &Receiver<String>, expected: &str) -> bool {
    let deadline = Instant::now() + PROTOCOL_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(line) if line.contains(expected) => return true,
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

fn terminate_and_reap(child: &mut Child) {
    let _ignored = child.kill();
    let deadline = Instant::now() + PROTOCOL_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(REAP_POLL),
            Ok(None) => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                panic!("process-kill worker reap watchdog expired");
            }
            Err(_) => panic!("process-kill worker reap failed"),
        }
    }
}

fn assert_exact_file(path: PathBuf, expected: &[u8], failure: &str) {
    let actual = fs::read(path).unwrap_or_else(|_| panic!("{failure}"));
    assert!(actual == expected, "{failure}");
}

fn snapshot_directory(root: &SyntheticTempRoot) -> Vec<(OsString, Vec<u8>)> {
    let entries = fs::read_dir(root.path())
        .unwrap_or_else(|_| panic!("pending restore destination was unreadable"));
    let mut snapshot = entries
        .map(|entry| {
            let entry = entry
                .unwrap_or_else(|_| panic!("pending restore destination entry was unreadable"));
            let file_type = entry.file_type().unwrap_or_else(|_| {
                panic!("pending restore destination entry type was unreadable")
            });
            assert!(
                file_type.is_file(),
                "pending restore destination contained a non-file entry"
            );
            let contents = fs::read(entry.path())
                .unwrap_or_else(|_| panic!("pending restore destination file was unreadable"));
            (entry.file_name(), contents)
        })
        .collect::<Vec<_>>();
    snapshot.sort_by(|left, right| left.0.cmp(&right.0));
    snapshot
}
