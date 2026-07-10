use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestRootGuard {
    path: PathBuf,
}

impl TestRootGuard {
    fn new(label: &str) -> (Self, TrustedLocalStoreRootV1) {
        let sequence = TEST_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helix-replay-root-safety-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap_or_else(|_| panic!("test root creation failed"));
        let trusted = TrustedLocalStoreRootV1::try_from_provisioned(path.clone())
            .unwrap_or_else(|_| panic!("test root validation failed"));
        (Self { path }, trusted)
    }
}

impl Drop for TestRootGuard {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn creator_accepts_waiter_publication_before_finalization() {
    let (_guard, root) = TestRootGuard::new("waiter-published");
    let lock_path = root.path().join(ROOT_LOCK_FILENAME);
    prepare_live_initialization_intent(&root, &lock_path)
        .unwrap_or_else(|_| panic!("live intent preparation failed"));

    // The creator owns the create-new handle but has not acquired its lock.
    let mut creator = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .unwrap_or_else(|_| panic!("creator reservation failed"));

    // Deterministically give the waiter the lock first, matching the failing
    // inter-process ordering without relying on scheduler timing.
    let mut waiter = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap_or_else(|_| panic!("waiter role open failed"));
    waiter
        .try_lock()
        .unwrap_or_else(|_| panic!("waiter lock acquisition failed"));
    write_and_sync_exact(&mut waiter, LIVE_ROOT_LOCK_CONTENT)
        .unwrap_or_else(|_| panic!("waiter role publication failed"));
    consume_live_initialization_intent(&root)
        .unwrap_or_else(|_| panic!("waiter intent consumption failed"));
    drop(waiter);

    creator
        .try_lock()
        .unwrap_or_else(|_| panic!("creator lock acquisition failed"));
    verify_or_repair_locked_root_role(&root, RootStateV1::LiveReady, &mut creator)
        .unwrap_or_else(|_| panic!("creator rejected the exact waiter publication"));
    verify_exact_file(&mut creator, LIVE_ROOT_LOCK_CONTENT)
        .unwrap_or_else(|_| panic!("published live role changed"));
    assert!(!root
        .path()
        .join(LIVE_INITIALIZATION_INTENT_FILENAME)
        .exists());
}

#[test]
fn creator_does_not_overwrite_unknown_reserved_role() {
    let (_guard, root) = TestRootGuard::new("unknown-role");
    let lock_path = root.path().join(ROOT_LOCK_FILENAME);
    prepare_live_initialization_intent(&root, &lock_path)
        .unwrap_or_else(|_| panic!("live intent preparation failed"));
    let unknown = b"HELIXOS_REPLAY_ROOT_LOCK_V1\nSTATE=UNKNOWN\n";
    let mut creator = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .unwrap_or_else(|_| panic!("creator reservation failed"));
    creator
        .try_lock()
        .unwrap_or_else(|_| panic!("creator lock acquisition failed"));
    creator
        .write_all(unknown)
        .and_then(|()| creator.sync_all())
        .unwrap_or_else(|_| panic!("unknown role fixture publication failed"));

    let error = verify_or_repair_locked_root_role(&root, RootStateV1::LiveReady, &mut creator)
        .err()
        .unwrap_or_else(|| panic!("unknown role was promoted"));
    assert_eq!(error, InternalStoreError::LocationNotDedicated);
    creator
        .seek(SeekFrom::Start(0))
        .unwrap_or_else(|_| panic!("unknown role rewind failed"));
    let mut actual = Vec::new();
    creator
        .read_to_end(&mut actual)
        .unwrap_or_else(|_| panic!("unknown role readback failed"));
    assert_eq!(actual, unknown);
}
