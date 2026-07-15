use helix_dispatch_contracts::{
    ContractError, Generation, GrantKeyResolver, GrantVerificationKeyV1, Identifier,
    Result as ContractResult, SafeU64, Sha256Digest,
};
use helix_dispatch_inbox_sqlite::{
    commit_adapter_dispatch_restore_to_pending_v1, inspect_adapter_dispatch_restore_destination_v1,
    prepare_adapter_dispatch_restore_v1, AdapterBackupPauseAuthorityV1,
    AdapterBackupPauseCustodyOutcomeV1, AdapterBackupPauseCustodyV1,
    AdapterBackupPauseValidationV1, AdapterClockObservationV1, AdapterClockV1,
    AdapterDispatchBackupErrorV1, AdapterDispatchRestoreCountsV1, AdapterDispatchRestoreErrorV1,
    AdapterDispatchRestoreGenerationsV1, AdapterDispatchRestoreInventoriesV1,
    AdapterDispatchRestorePauseCustodyV1, AdapterDispatchRestorePauseValidationV1,
    AdapterDispatchRestoreSourceBindingsV1, AdapterInboxInitializationV1, AdapterInboxProfileV1,
    AdapterInboxReceiveOutcomeV1, AdapterInboxRootIdentityEvidenceV1, AdapterInboxStoreConfigV1,
    AdapterPausedDispatchRestoreV1, AdapterPausedQuiescenceV1, AdapterTimeSampleV1,
    EpochObservationV1, ProvisionedAdapterDispatchBackupDestinationV1,
    ProvisionedAdapterDispatchRestoreSourceV1, SqliteDispatchInboxStoreV1,
    SupervisorEpochObservationV1, SupervisorEpochObserverV1,
};
#[cfg(feature = "test-fault-injection")]
use helix_plan_dispatch::FaultInjectionModeV1;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const ADAPTER_APPLICATION_ID_V1: i64 = 1_212_962_889;
const ADAPTER_ROOT_IDENTITY_V1: [u8; 32] = [0x76; 32];
const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const FIXTURE_GRANT_KEY: [u8; 32] = [
    167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246, 103,
    165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
];
const FIXTURE_CAPABILITY_DIGEST: &str =
    "7bd116b849df045678b6521d504056fe77119b19a0eadb84d661878e6d5f667b";

struct FixtureGrantResolverV1;

impl GrantKeyResolver for FixtureGrantResolverV1 {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        if key_id != "fixture-grant-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY))
    }
}

struct FixtureClockV1;

impl AdapterClockV1 for FixtureClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        AdapterClockObservationV1::Current(fixture_time_sample_v1(10, 1_000_100, 1_100))
    }
}

struct FixtureEpochObserverV1;

impl SupervisorEpochObserverV1 for FixtureEpochObserverV1 {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
        SupervisorEpochObservationV1::Current(EpochObservationV1::new(
            SafeU64::new(15).expect("T077 fixture epoch is safe"),
            Generation::new(2).expect("T077 fixture observer generation is non-zero"),
            fixture_time_sample_v1(20, 1_000_101, 1_101),
        ))
    }
}

struct TestRootV1 {
    store_root: PathBuf,
    success_root: PathBuf,
    changed_root: PathBuf,
    #[cfg(feature = "test-fault-injection")]
    fault_root: PathBuf,
}

impl TestRootV1 {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "helixos-t076-adapter-maintenance-{}-{sequence}",
            std::process::id()
        ));
        let store_root = base.join("store");
        fs::create_dir_all(&store_root).expect("T076 adapter source root creates");
        Self {
            store_root,
            success_root: base.join("success-component"),
            changed_root: base.join("changed-component"),
            #[cfg(feature = "test-fault-injection")]
            fault_root: base.join("fault-component"),
        }
    }
}

impl Drop for TestRootV1 {
    fn drop(&mut self) {
        if let Some(base) = self.store_root.parent() {
            let _ = fs::remove_dir_all(base);
        }
    }
}

#[derive(Clone)]
struct PauseAuthorityV1 {
    revoke_at_recheck: Option<u64>,
    rechecks: Arc<AtomicU64>,
    releases: Arc<AtomicU64>,
}

struct PauseCustodyV1 {
    paused: AdapterPausedQuiescenceV1,
    revoke_at_recheck: Option<u64>,
    rechecks: Arc<AtomicU64>,
    releases: Arc<AtomicU64>,
}

struct RestorePauseCustodyV1 {
    paused: AdapterPausedDispatchRestoreV1,
    rechecks: u64,
}

impl AdapterBackupPauseAuthorityV1 for PauseAuthorityV1 {
    type Custody = PauseCustodyV1;

    fn persist_pause_fence_and_drain_v1(
        &self,
        _deadline_monotonic_ms: u64,
    ) -> AdapterBackupPauseCustodyOutcomeV1<Self::Custody> {
        AdapterBackupPauseCustodyOutcomeV1::Acquired(PauseCustodyV1 {
            paused: AdapterPausedQuiescenceV1::try_new(15, 7, 9, 0)
                .expect("T076 fixed PAUSE evidence is bounded"),
            revoke_at_recheck: self.revoke_at_recheck,
            rechecks: Arc::clone(&self.rechecks),
            releases: Arc::clone(&self.releases),
        })
    }
}

impl AdapterBackupPauseCustodyV1 for PauseCustodyV1 {
    fn capture_paused_quiescence_v1(
        &mut self,
    ) -> Result<AdapterPausedQuiescenceV1, AdapterBackupPauseValidationV1> {
        Ok(self.paused)
    }

    fn recheck_paused_quiescence_v1(
        &mut self,
        expected: &AdapterPausedQuiescenceV1,
    ) -> AdapterBackupPauseValidationV1 {
        let occurrence = self.rechecks.fetch_add(1, Ordering::SeqCst) + 1;
        if self
            .revoke_at_recheck
            .is_some_and(|selected| occurrence >= selected)
        {
            AdapterBackupPauseValidationV1::Revoked
        } else if *expected == self.paused {
            AdapterBackupPauseValidationV1::Exact
        } else {
            AdapterBackupPauseValidationV1::Unhealthy
        }
    }

    fn release(self) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

impl AdapterDispatchRestorePauseCustodyV1 for RestorePauseCustodyV1 {
    fn recheck_paused_dispatch_restore_v1(
        &mut self,
        expected: &AdapterPausedDispatchRestoreV1,
    ) -> AdapterDispatchRestorePauseValidationV1 {
        self.rechecks += 1;
        if *expected == self.paused {
            AdapterDispatchRestorePauseValidationV1::Exact
        } else {
            AdapterDispatchRestorePauseValidationV1::Unhealthy
        }
    }

    fn release(self) {}
}

fn pause_authority_v1(revoke_at_recheck: Option<u64>) -> PauseAuthorityV1 {
    PauseAuthorityV1 {
        revoke_at_recheck,
        rechecks: Arc::new(AtomicU64::new(0)),
        releases: Arc::new(AtomicU64::new(0)),
    }
}

fn initialize_store_v1(root: &Path) -> SqliteDispatchInboxStoreV1 {
    let identity =
        AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(ADAPTER_ROOT_IDENTITY_V1);
    let config =
        AdapterInboxStoreConfigV1::try_new_empty_attested(root.to_path_buf(), identity, 25)
            .expect("T076 source root is provisioner-attested and empty");
    let initialization = AdapterInboxInitializationV1::try_new(15, 1, [0x77; 32])
        .expect("T076 initialization is bounded");
    let profile = AdapterInboxProfileV1::try_new(
        "adapter-t076-maintenance-v1",
        1,
        Sha256Digest::from_bytes([0x78; 32]),
    )
    .expect("T076 adapter profile is closed");
    SqliteDispatchInboxStoreV1::initialize_empty_v1(config, initialization, profile)
        .expect("T076 real adapter store initializes")
}

fn initialize_fixture_store_v1(root: &Path) -> SqliteDispatchInboxStoreV1 {
    let identity =
        AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(ADAPTER_ROOT_IDENTITY_V1);
    let config =
        AdapterInboxStoreConfigV1::try_new_empty_attested(root.to_path_buf(), identity, 25)
            .expect("T077 non-empty source root is provisioner-attested and empty");
    let initialization = AdapterInboxInitializationV1::try_new(15, 1, [0x77; 32])
        .expect("T077 non-empty source initialization is bounded");
    SqliteDispatchInboxStoreV1::initialize_empty_v1(config, initialization, fixture_profile_v1())
        .expect("T077 non-empty real adapter store initializes")
}

fn reopen_fixture_store_v1(root: &Path) -> SqliteDispatchInboxStoreV1 {
    let identity =
        AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(ADAPTER_ROOT_IDENTITY_V1);
    let config =
        AdapterInboxStoreConfigV1::try_new_existing_attested(root.to_path_buf(), identity, 25)
            .expect("T077 non-empty source root remains provisioner-attested");
    SqliteDispatchInboxStoreV1::open_existing_v1(config, fixture_profile_v1())
        .expect("T077 non-empty source strictly reopens")
}

fn fixture_profile_v1() -> AdapterInboxProfileV1 {
    AdapterInboxProfileV1::try_new(
        "adapter-v1",
        1,
        Sha256Digest::parse_hex(FIXTURE_CAPABILITY_DIGEST)
            .expect("T077 fixture capability digest parses"),
    )
    .expect("T077 fixture adapter profile is closed")
}

fn receive_fixture_grant_v1(store: &SqliteDispatchInboxStoreV1) {
    let corpus: serde_json::Value = serde_json::from_str(CASES).expect("T077 corpus parses");
    let canonical_grant =
        serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"])
            .expect("T077 canonical source grant encodes");
    assert!(matches!(
        store
            .receive_grant_v1(
                &canonical_grant,
                &FixtureGrantResolverV1,
                &FixtureClockV1,
                &FixtureEpochObserverV1,
            )
            .expect("T077 canonical grant commits through the production receive API"),
        AdapterInboxReceiveOutcomeV1::Received(_)
    ));
}

fn fixture_time_sample_v1(
    clock_generation: u64,
    utc_ms: u64,
    monotonic_ms: u64,
) -> AdapterTimeSampleV1 {
    AdapterTimeSampleV1::new(
        Identifier::new("boot-v1").expect("T077 fixture boot id is valid"),
        Generation::new(clock_generation).expect("T077 fixture clock generation is non-zero"),
        SafeU64::new(utc_ms).expect("T077 fixture UTC sample is safe"),
        SafeU64::new(monotonic_ms).expect("T077 fixture monotonic sample is safe"),
    )
}

fn sha256_file_v1(path: &Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).expect("T076 published member reads")).into()
}

fn lower_hex_v1(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn manifest_u64_v1(manifest: &serde_json::Value, path: &[&str]) -> u64 {
    let mut value = manifest;
    for segment in path {
        value = &value[*segment];
    }
    value
        .as_u64()
        .unwrap_or_else(|| panic!("T077 manifest field {path:?} must be an unsigned integer"))
}

fn manifest_digest_v1(manifest: &serde_json::Value, path: &[&str]) -> [u8; 32] {
    let mut value = manifest;
    for segment in path {
        value = &value[*segment];
    }
    let encoded = value
        .as_str()
        .unwrap_or_else(|| panic!("T077 manifest field {path:?} must be a digest"));
    assert_eq!(encoded.len(), 64, "T077 manifest digest length is exact");
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .expect("T077 manifest digest is lower hexadecimal");
    }
    digest
}

fn restore_source_bindings_v1(
    manifest: &serde_json::Value,
    source_root_identity: AdapterInboxRootIdentityEvidenceV1,
) -> AdapterDispatchRestoreSourceBindingsV1 {
    let generations = AdapterDispatchRestoreGenerationsV1::try_new(
        manifest_u64_v1(manifest, &["generations", "store"]),
        manifest_u64_v1(manifest, &["generations", "inbox"]),
        manifest_u64_v1(manifest, &["generations", "consumption"]),
        manifest_u64_v1(manifest, &["generations", "receipt"]),
        manifest_u64_v1(manifest, &["generations", "conflict"]),
        manifest_u64_v1(manifest, &["generations", "quarantine"]),
        manifest_u64_v1(manifest, &["generations", "event"]),
        manifest_u64_v1(manifest, &["generations", "epoch_observer"]),
        manifest_u64_v1(manifest, &["generations", "restore_state"]),
    )
    .expect("T077 signed adapter generation projection is exact");
    let counts = AdapterDispatchRestoreCountsV1::try_new(
        manifest_u64_v1(manifest, &["counts", "inbox_entries"]),
        manifest_u64_v1(manifest, &["counts", "transitions"]),
        manifest_u64_v1(manifest, &["counts", "receipts"]),
        manifest_u64_v1(manifest, &["counts", "conflicts"]),
        manifest_u64_v1(manifest, &["counts", "quarantines"]),
        manifest_u64_v1(manifest, &["counts", "events"]),
    )
    .expect("T077 signed adapter count projection is exact");
    let inventories = AdapterDispatchRestoreInventoriesV1::new(
        manifest_digest_v1(manifest, &["inventory_digests", "inbox_entries"]),
        manifest_digest_v1(manifest, &["inventory_digests", "transitions"]),
        manifest_digest_v1(manifest, &["inventory_digests", "receipts"]),
        manifest_digest_v1(manifest, &["inventory_digests", "conflicts"]),
        manifest_digest_v1(manifest, &["inventory_digests", "quarantines"]),
        manifest_digest_v1(manifest, &["inventory_digests", "events"]),
        manifest_digest_v1(manifest, &["inventory_digests", "complete_store"]),
    );
    AdapterDispatchRestoreSourceBindingsV1::try_new(
        source_root_identity,
        manifest_digest_v1(manifest, &["root_identity_digest"]),
        manifest_u64_v1(manifest, &["supervisor_epoch"]),
        generations,
        counts,
        inventories,
    )
    .expect("T077 signed adapter source bindings are exact")
}

#[test]
fn paused_restore_authority_rejects_zero_identities_and_index() {
    let source_root = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([1; 32]);
    let new_root = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([2; 32]);
    let zero_root = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0; 32]);
    let validate =
        |source_root, new_root, source_supervisor_identity, new_supervisor_identity, index| {
            AdapterPausedDispatchRestoreV1::try_new(
                source_root,
                new_root,
                source_supervisor_identity,
                new_supervisor_identity,
                7,
                8,
                1,
                2,
                index,
                3,
                4,
            )
        };
    for result in [
        validate(zero_root, new_root, [3; 32], [4; 32], [5; 32]),
        validate(source_root, zero_root, [3; 32], [4; 32], [5; 32]),
        validate(source_root, new_root, [0; 32], [4; 32], [5; 32]),
        validate(source_root, new_root, [3; 32], [0; 32], [5; 32]),
        validate(source_root, new_root, [3; 32], [4; 32], [0; 32]),
    ] {
        assert_eq!(result, Err(AdapterDispatchRestoreErrorV1::AuthorityInvalid));
    }
}

#[test]
fn real_paused_online_backup_reopens_and_pause_mutation_cannot_publish_completion() {
    let roots = TestRootV1::new();
    let store = initialize_store_v1(&roots.store_root);
    #[cfg(feature = "test-fault-injection")]
    let mut store = store;

    let success_pause = pause_authority_v1(None);
    let success_destination =
        ProvisionedAdapterDispatchBackupDestinationV1::try_reserve_create_only(
            roots.success_root.clone(),
        )
        .expect("T076 success destination reserves create-only");
    let verified = store
        .backup_paused_dispatch_inbox_v1(
            &success_pause,
            success_destination,
            1_900_000_000_076,
            10_000,
        )
        .expect("T076 real paused online backup succeeds");

    assert_eq!(success_pause.rechecks.load(Ordering::SeqCst), 4);
    assert_eq!(success_pause.releases.load(Ordering::SeqCst), 1);
    let published = roots.success_root.join("published");
    let staging = roots.success_root.join("staging");
    let database = published.join("adapter-inbox.sqlite3");
    let manifest = published.join("adapter-inbox-manifest.json");
    let marker = published.join("adapter-inbox-component.complete");
    assert_eq!(sha256_file_v1(&database), verified.database_sha256());
    assert_eq!(sha256_file_v1(&manifest), verified.manifest_digest());
    assert_eq!(
        Sha256::digest(verified.manifest_package_bytes()).as_slice(),
        verified.manifest_package_sha256()
    );
    let body: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).expect("T076 published manifest body reads"))
            .expect("T076 published manifest body is JSON");
    assert!(body.get("manifest_digest").is_none());
    let expected_marker = format!(
        "HELIXOS_DISPATCH_ADAPTER_BACKUP_COMPONENT_V1\nDATABASE_SHA256={}\nMANIFEST_DIGEST={}\n",
        lower_hex_v1(verified.database_sha256()),
        lower_hex_v1(verified.manifest_digest())
    );
    assert_eq!(
        fs::read(&marker).expect("T076 completion marker reads"),
        expected_marker.as_bytes()
    );
    assert!(
        fs::read_dir(&staging)
            .expect("T076 staging directory reads")
            .next()
            .is_none(),
        "successful publication removes every hard-link staging alias"
    );
    let names = fs::read_dir(&published)
        .expect("T076 published directory reads")
        .map(|entry| {
            entry
                .expect("T076 published entry reads")
                .file_name()
                .into_string()
                .expect("T076 published member name is UTF-8")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "adapter-inbox-component.complete".to_owned(),
            "adapter-inbox-manifest.json".to_owned(),
            "adapter-inbox.sqlite3".to_owned(),
        ])
    );

    let reopened = Connection::open_with_flags(
        &database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("T076 component DB strictly reopens read-only");
    assert_eq!(
        reopened
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .expect("T076 integrity_check reads"),
        "ok"
    );
    assert_eq!(
        reopened
            .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
            .expect("T076 journal mode reads")
            .to_ascii_lowercase(),
        "delete"
    );
    assert_eq!(
        reopened
            .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
            .expect("T076 application id reads"),
        ADAPTER_APPLICATION_ID_V1
    );
    assert_eq!(
        reopened
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .expect("T076 user version reads"),
        1
    );
    let (root_identity, supervisor_epoch): (Vec<u8>, i64) = reopened
        .query_row(
            "SELECT root_identity, supervisor_epoch FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("T076 exact root metadata reads");
    assert_eq!(root_identity, ADAPTER_ROOT_IDENTITY_V1);
    assert_eq!(supervisor_epoch, 15);
    drop(reopened);
    assert!(!PathBuf::from(format!("{}-wal", database.display())).exists());
    assert!(!PathBuf::from(format!("{}-shm", database.display())).exists());

    let changed_pause = pause_authority_v1(Some(4));
    let changed_destination =
        ProvisionedAdapterDispatchBackupDestinationV1::try_reserve_create_only(
            roots.changed_root.clone(),
        )
        .expect("T076 changed-PAUSE destination reserves create-only");
    assert!(matches!(
        store.backup_paused_dispatch_inbox_v1(
            &changed_pause,
            changed_destination,
            1_900_000_000_077,
            10_000,
        ),
        Err(AdapterDispatchBackupErrorV1::PauseChanged)
    ));
    assert_eq!(changed_pause.rechecks.load(Ordering::SeqCst), 4);
    assert_eq!(changed_pause.releases.load(Ordering::SeqCst), 1);
    let changed_published = roots.changed_root.join("published");
    assert!(changed_published.join("adapter-inbox.sqlite3").is_file());
    assert!(changed_published
        .join("adapter-inbox-manifest.json")
        .is_file());
    assert!(
        !changed_published
            .join("adapter-inbox-component.complete")
            .exists(),
        "PAUSE mutation must leave no consumable component completion marker"
    );

    #[cfg(feature = "test-fault-injection")]
    {
        store
            .select_fault_probe_for_test_v1(
                "PLAN005-FB-079",
                1,
                FaultInjectionModeV1::InProcess,
                || {},
            )
            .expect("T076 adapter marker checkpoint selects");
        let fault_pause = pause_authority_v1(None);
        let fault_destination =
            ProvisionedAdapterDispatchBackupDestinationV1::try_reserve_create_only(
                roots.fault_root.clone(),
            )
            .expect("T076 FB079 destination reserves create-only");
        assert!(matches!(
            store.backup_paused_dispatch_inbox_v1(
                &fault_pause,
                fault_destination,
                1_900_000_000_078,
                10_000,
            ),
            Err(AdapterDispatchBackupErrorV1::PublicationFailed)
        ));
        assert!(store.fault_probe_injected_for_test_v1());
        assert_eq!(fault_pause.releases.load(Ordering::SeqCst), 1);
        assert!(roots
            .fault_root
            .join("published")
            .join("adapter-inbox-component.complete")
            .is_file());
        assert!(
            !roots
                .fault_root
                .join("published")
                .join("dispatch-backup-index.json")
                .exists(),
            "FB079 must propagate before any top-level index can follow"
        );
    }
}

#[test]
fn clean_adapter_restore_is_pending_paused_exact_and_idempotent() {
    let roots = TestRootV1::new();
    let store = initialize_fixture_store_v1(&roots.store_root);
    receive_fixture_grant_v1(&store);
    drop(store);
    let store = reopen_fixture_store_v1(&roots.store_root);
    let backup_pause = pause_authority_v1(None);
    let backup_destination =
        ProvisionedAdapterDispatchBackupDestinationV1::try_reserve_create_only(
            roots.success_root.clone(),
        )
        .expect("T077 source component destination reserves create-only");
    let backup = store
        .backup_paused_dispatch_inbox_v1(
            &backup_pause,
            backup_destination,
            1_900_000_000_177,
            10_000,
        )
        .expect("T077 exact source backup succeeds");
    let manifest: serde_json::Value = serde_json::from_slice(backup.manifest_package_bytes())
        .expect("T077 adapter manifest package parses");
    let source_database = roots
        .success_root
        .join("published")
        .join("adapter-inbox.sqlite3");
    let source_identity_connection = Connection::open_with_flags(
        &source_database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("T077 retained adapter member opens for root projection");
    let source_root_identity: Vec<u8> = source_identity_connection
        .query_row(
            "SELECT root_identity FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("T077 retained adapter root projection reads");
    let source_grant_id: Vec<u8> = source_identity_connection
        .query_row("SELECT grant_id FROM grant_inbox", [], |row| row.get(0))
        .expect("T077 retained non-empty grant id reads");
    drop(source_identity_connection);
    let source_root_identity: [u8; 32] = source_root_identity
        .try_into()
        .expect("T077 retained adapter root projection is exact");
    let source_bindings = restore_source_bindings_v1(
        &manifest,
        AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(source_root_identity),
    );
    assert_eq!(
        manifest_digest_v1(&manifest, &["database_digest"]),
        backup.database_sha256()
    );
    assert_eq!(manifest_u64_v1(&manifest, &["counts", "inbox_entries"]), 1);

    let source_length = fs::metadata(&source_database)
        .expect("T077 source database metadata reads")
        .len();
    let restored_root = roots
        .store_root
        .parent()
        .expect("T077 test base exists")
        .join("restored-adapter");
    fs::create_dir(&restored_root).expect("T077 clean adapter root creates");
    let new_root_identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x86; 32]);
    let destination = AdapterInboxStoreConfigV1::try_new_empty_attested(
        restored_root.clone(),
        new_root_identity,
        25,
    )
    .expect("T077 clean adapter root is provisioner-attested");
    let initial_destination = inspect_adapter_dispatch_restore_destination_v1(&destination)
        .expect("T077 clean adapter root rescans");
    assert!(initial_destination.is_fresh());
    assert_eq!(initial_destination.entry_count(), 0);

    let restore_index_digest = [0x91; 32];
    let paused = AdapterPausedDispatchRestoreV1::try_new(
        AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(ADAPTER_ROOT_IDENTITY_V1),
        new_root_identity,
        [0x41; 32],
        [0x42; 32],
        15,
        16,
        2,
        3,
        restore_index_digest,
        17,
        19,
    )
    .expect("T077 rotated PAUSE authority is exact");
    let source = ProvisionedAdapterDispatchRestoreSourceV1::try_new(
        fs::File::open(&source_database).expect("T077 source member opens read-only"),
        source_length,
        backup.database_sha256(),
        source_bindings,
    )
    .expect("T077 source member is bounded and hash-bound");
    let mut custody = RestorePauseCustodyV1 {
        paused,
        rechecks: 0,
    };
    let prepared = prepare_adapter_dispatch_restore_v1(&mut custody, paused, source, destination)
        .expect("T077 adapter copy prepares without authority publication");
    let restored = commit_adapter_dispatch_restore_to_pending_v1(&mut custody, prepared)
        .expect("T077 adapter restore commits pending and reopens exactly");
    assert_eq!(custody.rechecks, 6);
    assert_eq!(restored.root_identity(), new_root_identity);
    assert_eq!(restored.root_lifecycle_code(), "RESTORE_PENDING");
    assert_eq!(restored.control_state_code(), "PAUSED");
    assert_eq!(restored.restore_index_digest(), restore_index_digest);
    assert_eq!(restored.automatic_consumption_count(), 0);
    assert_eq!(restored.automatic_redelivery_count(), 0);
    assert_eq!(restored.possible_consumption_quarantine_count(), 1);
    assert_eq!(restored.reconciliation_required_count(), 1);
    let source_grant_id_array =
        <[u8; 32]>::try_from(source_grant_id.as_slice()).expect("T077 retained grant id is exact");
    assert_eq!(
        restored.reconciliation_grant_ids(),
        &[source_grant_id_array]
    );
    assert_ne!(
        restored.source_inventory_digest(),
        restored.restored_inventory_digest(),
        "T077 restore-only quarantine proof changes only the restored inventory"
    );
    assert_eq!(restored.initial_destination_entry_count(), 0);

    let raw = Connection::open_with_flags(
        restored_root.join("dispatch-inbox.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("T077 restored adapter database opens read-only");
    let metadata: (Vec<u8>, String, i64, i64, Vec<u8>, i64, i64, i64) = raw
        .query_row(
            "SELECT root_identity, root_lifecycle_state, supervisor_epoch,
                    epoch_observer_generation, restore_index_digest,
                    restore_state_generation, store_generation, quarantine_generation
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .expect("T077 pending adapter metadata reads exactly");
    assert_eq!(metadata.0.as_slice(), [0x86; 32].as_slice());
    assert_eq!(metadata.1, "RESTORE_PENDING");
    assert_eq!(metadata.2, 16);
    assert_eq!(metadata.3, 3);
    assert_eq!(metadata.4.as_slice(), restore_index_digest.as_slice());
    assert_eq!(metadata.5, metadata.6);
    assert_eq!(metadata.6, 3);
    assert_eq!(metadata.7, 2);
    let retained_state: String = raw
        .query_row("SELECT inbox_state FROM grant_inbox", [], |row| row.get(0))
        .expect("T077 source grant state reads after restore");
    assert_eq!(retained_state, "RECEIVED");
    let proof: (Vec<u8>, Vec<u8>, Vec<u8>, String, i64, Option<i64>) = raw
        .query_row(
            "SELECT quarantine_id, grant_id, evidence_digest, public_reason_code,
                    quarantine_generation, resolved_generation
             FROM inbox_quarantines",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .expect("T077 restore reconciliation proof reads exactly");
    assert_eq!(proof.1, source_grant_id);
    assert_eq!(proof.0.len(), 32);
    assert_eq!(proof.2.len(), 32);
    assert_eq!(proof.3, "RESTORE_RECONCILIATION_REQUIRED");
    assert_eq!(proof.4, 2);
    assert_eq!(proof.5, None);
    let reconciliation_set_digest = restored.reconciliation_grant_set_digest();
    drop(raw);

    let retry_database = restored_root.join("dispatch-inbox.sqlite3");
    let retry_destination =
        AdapterInboxStoreConfigV1::try_new_existing_attested(restored_root, new_root_identity, 25)
            .expect("T077 published pending root is provisioner-attested");
    let retry_observation = inspect_adapter_dispatch_restore_destination_v1(&retry_destination)
        .expect("T077 published pending root rescans");
    assert!(retry_observation.is_retry());
    assert!(retry_observation.entry_count() >= 2);
    let retry_source = ProvisionedAdapterDispatchRestoreSourceV1::try_new(
        fs::File::open(source_database).expect("T077 retry source opens read-only"),
        source_length,
        backup.database_sha256(),
        source_bindings,
    )
    .expect("T077 retry source remains exactly bound");
    let mut retry_custody = RestorePauseCustodyV1 {
        paused,
        rechecks: 0,
    };
    let retry_prepared = prepare_adapter_dispatch_restore_v1(
        &mut retry_custody,
        paused,
        retry_source,
        retry_destination,
    )
    .expect("T077 exact published retry prepares without mutation");
    let retried = commit_adapter_dispatch_restore_to_pending_v1(&mut retry_custody, retry_prepared)
        .expect("T077 exact published retry reopens idempotently");
    assert_eq!(retried.root_lifecycle_code(), "RESTORE_PENDING");
    assert_eq!(retried.restore_index_digest(), restore_index_digest);
    assert_eq!(retried.possible_consumption_quarantine_count(), 1);
    assert_eq!(retried.reconciliation_required_count(), 1);
    assert_eq!(
        retried.reconciliation_grant_set_digest(),
        reconciliation_set_digest
    );
    assert_eq!(
        retried.reconciliation_grant_ids(),
        restored.reconciliation_grant_ids()
    );
    assert_eq!(
        retried.initial_destination_entry_count(),
        retry_observation.entry_count()
    );
    assert_eq!(retried.automatic_redelivery_count(), 0);
    let retry_raw = Connection::open_with_flags(
        retry_database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("T077 retried adapter database opens read-only");
    let retry_proof_count: i64 = retry_raw
        .query_row(
            "SELECT COUNT(*) FROM inbox_quarantines
             WHERE public_reason_code = 'RESTORE_RECONCILIATION_REQUIRED'",
            [],
            |row| row.get(0),
        )
        .expect("T077 retry proof count reads");
    assert_eq!(retry_proof_count, 1, "retry never duplicates durable proof");
}
