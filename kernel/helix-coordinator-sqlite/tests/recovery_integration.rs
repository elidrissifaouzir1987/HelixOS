//! T051 red integration tests for recovery publication, quarantine, and retirement.
//!
//! These tests deliberately use only public-synthetic material. The provider fixture
//! remains downstream test wiring, while coordinator lifecycle mutations stay behind
//! crate-private source-included seams. No test constructs preparation authority.

mod common;

#[path = "../src/budget.rs"]
mod budget;
#[path = "../src/comparison_digest.rs"]
mod comparison_digest;
#[path = "../src/failure.rs"]
mod failure;
#[path = "../src/maintenance.rs"]
mod maintenance;
#[path = "../src/outbox.rs"]
mod outbox;
#[path = "../src/prepare.rs"]
mod prepare;
#[path = "../src/quarantine.rs"]
mod quarantine;
#[path = "../src/readback.rs"]
mod readback;
#[path = "../src/retirement.rs"]
mod retirement;
#[cfg(feature = "test-fault-injection")]
#[path = "../src/test_fault.rs"]
mod test_fault;
#[path = "../src/transition.rs"]
mod transition;

use common::process_probe::{
    private_process_argument_v1, ProcessProbeChildV1, ProcessProbeEnvironmentV1,
    SynchronizedProcessProbeV1,
};
use common::{
    SyntheticCoordinatorClockV1, SyntheticCoordinatorRootV1,
    SyntheticCrossProcessRecoveryFixtureV1, SyntheticHistoricalPlanKeyResolverV1,
    SyntheticManifestLastRecoveryProviderV1, SyntheticRecoveryGuardOutcomeV1,
};
use failure::{
    fail_synthetic_before_dispatch_v1, SyntheticKnownFailureCaseV1, SyntheticNoDispatchGuardCaseV1,
};
use helix_contracts::Sha256Digest;
use helix_coordinator_sqlite::{CoordinatorRootIdentityEvidenceV1, CoordinatorStoreOpenErrorV1};
use helix_plan_preparation::{PreparationCommitOutcomeV1, PreparationFailureOutcomeV1};
use maintenance::{
    authorize_synthetic_orphan_retirement_v1, SyntheticNoReferenceCaseV1,
    SyntheticOrphanAuthorizationInputV1, SyntheticOrphanAuthorizationOutcomeV1,
};
use prepare::{
    commit_synthetic_preparation_v1, provision_synthetic_budget_scope_v1, SyntheticCommitModeV1,
    SyntheticPreparationCaseV1, SyntheticRecoveryModeV1,
};
use quarantine::{retain_synthetic_orphan_v1, SyntheticOrphanInputV1};
use retirement::{
    retire_synthetic_operation_bound_v1, retire_synthetic_orphan_v1,
    SyntheticOperationRetirementInputV1, SyntheticOrphanRetirementInputV1,
    SyntheticRetirementOutcomeV1, SyntheticRetirementStepV1,
};
use rusqlite::Connection;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

const OPEN_NOW_MS: u64 = 100;
const OPEN_DEADLINE_MS: u64 = 10_000;
const FAILURE_NOW_MS: u64 = 1_000;
const FAILURE_GUARD_DEADLINE_MS: u64 = 10_000;
const FAILURE_REVOCATION_GENERATION: u64 = 17;
const RECOVERY_GUARD_DEADLINE_MS: u64 = 10_000;
const RECOVERY_GUARD_BINDING: [u8; 32] = [0x91; 32];
const RECOVERY_PROBE_ROOT_ENV: &str = "HELIXOS_RECOVERY_GUARD_PROBE_ROOT";
const RECOVERY_PROBE_MODE_ENV: &str = "HELIXOS_RECOVERY_GUARD_PROBE_MODE";
const RECOVERY_PROBE_PUBLICATION: &str = "publication";
const RECOVERY_PROBE_CLEANUP: &str = "cleanup";

struct PreparedCompensationRootV1 {
    root: SyntheticCoordinatorRootV1,
    identity: CoordinatorRootIdentityEvidenceV1,
    database: PathBuf,
    operation_id: String,
}

impl PreparedCompensationRootV1 {
    fn new() -> Self {
        let root = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root");
        let store = root
            .open_empty_v1(
                SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                OPEN_DEADLINE_MS,
            )
            .expect("empty coordinator initializes");
        let identity = store.root_identity_evidence();
        drop(store);

        let database = coordinator_database_v1(root.path());
        let case = SyntheticPreparationCaseV1::coherent_v1(SyntheticRecoveryModeV1::Compensation);
        provision_synthetic_budget_scope_v1(&database, &case)
            .expect("trusted synthetic scope provisions");
        assert!(matches!(
            commit_synthetic_preparation_v1(&database, &case, SyntheticCommitModeV1::Acknowledged,),
            PreparationCommitOutcomeV1::Committed(_)
        ));
        let operation_id = only_operation_id_v1(&database);
        Self {
            root,
            identity,
            database,
            operation_id,
        }
    }

    fn fail_before_dispatch_v1(&self) {
        let known = SyntheticKnownFailureCaseV1::load_preparing_v1(
            &self.database,
            &self.operation_id,
            FAILURE_REVOCATION_GENERATION,
            FAILURE_GUARD_DEADLINE_MS,
        )
        .expect("coherent PREPARING row loads");
        assert!(matches!(
            fail_synthetic_before_dispatch_v1(
                &self.database,
                &known,
                SyntheticNoDispatchGuardCaseV1::Exact,
                FAILURE_NOW_MS,
            ),
            PreparationFailureOutcomeV1::Failed
        ));
    }

    fn reopen_v1(&self) -> Result<(), CoordinatorStoreOpenErrorV1> {
        self.root
            .open_existing_v1(
                self.identity,
                SyntheticCoordinatorClockV1::new(OPEN_NOW_MS + 1),
                SyntheticHistoricalPlanKeyResolverV1::default(),
                OPEN_DEADLINE_MS,
            )
            .map(|_| ())
            .map_err(|error| match error {
                common::SyntheticHarnessErrorV1::CoordinatorOpen(error) => error,
                _ => panic!("unexpected synthetic harness error class"),
            })
    }
}

fn coordinator_database_v1(root: &Path) -> PathBuf {
    std::fs::canonicalize(root)
        .expect("synthetic coordinator root canonicalizes")
        .join("coordinator.sqlite3")
}

fn only_operation_id_v1(database: &Path) -> String {
    Connection::open(database)
        .expect("coordinator database opens")
        .query_row("SELECT operation_id FROM prepared_operations", [], |row| {
            row.get(0)
        })
        .expect("one operation reads")
}

fn only_recovery_manifest_v1(database: &Path) -> Sha256Digest {
    let value: Vec<u8> = Connection::open(database)
        .expect("coordinator database opens")
        .query_row(
            "SELECT manifest_digest FROM preparation_recovery_evidence",
            [],
            |row| row.get(0),
        )
        .expect("one recovery manifest reads");
    Sha256Digest::from_bytes(value.try_into().expect("manifest digest has 32 bytes"))
}

fn required_private_environment_v1(name: &str) -> OsString {
    private_process_argument_v1(name).unwrap_or_else(|| panic!("missing private probe input"))
}

#[test]
#[ignore = "private child entry used only by recovery guard contention"]
fn recovery_guard_probe_child_v1() {
    let Some(child) =
        ProcessProbeChildV1::from_environment_v1().expect("private child input validates")
    else {
        return;
    };
    let root = PathBuf::from(required_private_environment_v1(RECOVERY_PROBE_ROOT_ENV));
    let mode = required_private_environment_v1(RECOVERY_PROBE_MODE_ENV);
    let provider = SyntheticManifestLastRecoveryProviderV1::open_v1(root)
        .expect("existing synthetic provider opens");
    child
        .publish_ready_and_wait_for_go_v1()
        .expect("READY/GO protocol completes");
    let outcome = if mode == RECOVERY_PROBE_PUBLICATION {
        provider.acquire_publication_guard_v1(
            Sha256Digest::from_bytes(RECOVERY_GUARD_BINDING),
            RECOVERY_GUARD_DEADLINE_MS,
        )
    } else if mode == RECOVERY_PROBE_CLEANUP {
        provider.acquire_cleanup_guard_v1(
            Sha256Digest::from_bytes(RECOVERY_GUARD_BINDING),
            RECOVERY_GUARD_DEADLINE_MS,
        )
    } else {
        panic!("unknown private recovery probe mode")
    };
    let result = match outcome {
        SyntheticRecoveryGuardOutcomeV1::Acquired(_) => b"acquired".as_slice(),
        SyntheticRecoveryGuardOutcomeV1::Contended => b"contended".as_slice(),
        SyntheticRecoveryGuardOutcomeV1::Unavailable => b"unavailable".as_slice(),
        SyntheticRecoveryGuardOutcomeV1::DeadlineReached => b"deadline".as_slice(),
    };
    child
        .publish_result_v1(result)
        .expect("private child result publishes");
}

fn assert_opposite_process_contends_v1(
    provider: &SyntheticManifestLastRecoveryProviderV1,
    root: &Path,
    parent_holds_publication: bool,
) {
    let binding = Sha256Digest::from_bytes(RECOVERY_GUARD_BINDING);
    let held = if parent_holds_publication {
        provider.acquire_publication_guard_v1(binding, RECOVERY_GUARD_DEADLINE_MS)
    } else {
        provider.acquire_cleanup_guard_v1(binding, RECOVERY_GUARD_DEADLINE_MS)
    };
    let held = match held {
        SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
        other => panic!("parent guard must acquire, got {other:?}"),
    };
    let child_mode = if parent_holds_publication {
        RECOVERY_PROBE_CLEANUP
    } else {
        RECOVERY_PROBE_PUBLICATION
    };
    let environment = [
        ProcessProbeEnvironmentV1::new(RECOVERY_PROBE_ROOT_ENV, root.as_os_str()),
        ProcessProbeEnvironmentV1::new(RECOVERY_PROBE_MODE_ENV, child_mode),
    ];
    let mut probe =
        SynchronizedProcessProbeV1::spawn_v1("recovery_guard_probe_child_v1", 1, &environment)
            .expect("recovery guard probe spawns");
    let results = probe.execute_v1().expect("recovery guard probe completes");
    assert_eq!(results, vec![b"contended".to_vec()]);
    drop(held);
}

#[test]
fn publication_and_cleanup_guards_are_cross_process_mutually_exclusive() {
    let fixture =
        SyntheticCrossProcessRecoveryFixtureV1::new().expect("synthetic recovery root creates");
    let provider =
        SyntheticManifestLastRecoveryProviderV1::open_v1(fixture.root().path().to_path_buf())
            .expect("synthetic provider opens");

    assert_opposite_process_contends_v1(&provider, fixture.root().path(), true);
    assert_opposite_process_contends_v1(&provider, fixture.root().path(), false);

    let binding = Sha256Digest::from_bytes(RECOVERY_GUARD_BINDING);
    assert!(matches!(
        provider.acquire_publication_guard_v1(binding, RECOVERY_GUARD_DEADLINE_MS),
        SyntheticRecoveryGuardOutcomeV1::Acquired(_)
    ));
    assert!(matches!(
        provider.acquire_cleanup_guard_v1(binding, RECOVERY_GUARD_DEADLINE_MS),
        SyntheticRecoveryGuardOutcomeV1::Acquired(_)
    ));
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveryEvidenceObservationV1 {
    mode: String,
    profile: String,
    provider: String,
    provider_generation: i64,
    evidence_class: String,
    at_rest_profile: String,
    precondition_digest: Vec<u8>,
    precondition_length: i64,
    reserved_capacity: i64,
    material_id: Vec<u8>,
    publication_attempt_id: Vec<u8>,
    manifest_digest: Vec<u8>,
    material_digest: Vec<u8>,
    material_length: i64,
    material_state: String,
    retirement_id: Option<Vec<u8>>,
    retirement_manifest_digest: Option<Vec<u8>>,
    retirement_generation: Option<i64>,
}

impl RecoveryEvidenceObservationV1 {
    fn read(database: &Path) -> Self {
        Connection::open(database)
            .expect("coordinator database opens")
            .query_row(
                "SELECT recovery_mode, provider_profile_id, provider_id, provider_generation, \
                        evidence_class, at_rest_profile_id, precondition_digest, \
                        precondition_length, reserved_capacity, material_id, \
                        publication_attempt_id, manifest_digest, material_digest, \
                        material_length, material_state, retirement_id, \
                        retirement_manifest_digest, retirement_generation \
                 FROM preparation_recovery_evidence",
                [],
                |row| {
                    Ok(Self {
                        mode: row.get(0)?,
                        profile: row.get(1)?,
                        provider: row.get(2)?,
                        provider_generation: row.get(3)?,
                        evidence_class: row.get(4)?,
                        at_rest_profile: row.get(5)?,
                        precondition_digest: row.get(6)?,
                        precondition_length: row.get(7)?,
                        reserved_capacity: row.get(8)?,
                        material_id: row.get(9)?,
                        publication_attempt_id: row.get(10)?,
                        manifest_digest: row.get(11)?,
                        material_digest: row.get(12)?,
                        material_length: row.get(13)?,
                        material_state: row.get(14)?,
                        retirement_id: row.get(15)?,
                        retirement_manifest_digest: row.get(16)?,
                        retirement_generation: row.get(17)?,
                    })
                },
            )
            .expect("one recovery evidence row reads")
    }
}

#[test]
fn immutable_recovery_evidence_persists_exactly_and_every_binding_corruption_fails_reopen() {
    let fixture = PreparedCompensationRootV1::new();
    let before = RecoveryEvidenceObservationV1::read(&fixture.database);
    assert_eq!(before.mode, "COMPENSATION");
    assert_eq!(before.profile, "recovery-profile:synthetic-v1");
    assert_eq!(before.provider, "recovery-provider:synthetic-v1");
    assert_eq!(before.provider_generation, 1);
    assert_eq!(before.evidence_class, "SYNTHETIC_CONFORMANCE");
    assert_eq!(before.at_rest_profile, "at-rest:synthetic-v1");
    assert_eq!(before.precondition_digest, before.material_digest);
    assert_eq!(before.precondition_length, before.material_length);
    assert!(before.reserved_capacity >= before.material_length);
    for digest in [
        &before.precondition_digest,
        &before.material_id,
        &before.publication_attempt_id,
        &before.manifest_digest,
        &before.material_digest,
    ] {
        assert_eq!(digest.len(), 32);
    }
    assert_eq!(before.material_state, "PUBLISHED");
    assert_eq!(before.retirement_id, None);
    assert_eq!(before.retirement_manifest_digest, None);
    assert_eq!(before.retirement_generation, None);
    fixture.reopen_v1().expect("exact evidence survives reopen");
    assert_eq!(
        RecoveryEvidenceObservationV1::read(&fixture.database),
        before
    );

    for mutation in [
        "UPDATE preparation_recovery_evidence SET provider_generation = 2",
        "UPDATE preparation_recovery_evidence SET provider_id = 'recovery-provider:other-v1'",
        "UPDATE preparation_recovery_evidence SET at_rest_profile_id = 'at-rest:other-v1'",
        "UPDATE preparation_recovery_evidence SET capability_binding_digest = zeroblob(32)",
        "UPDATE preparation_recovery_evidence SET publication_attempt_id = zeroblob(32)",
        "UPDATE preparation_recovery_evidence SET manifest_digest = zeroblob(32)",
        "UPDATE preparation_recovery_evidence SET reserved_capacity = reserved_capacity + 1",
        "UPDATE preparation_recovery_evidence SET instance_epoch = instance_epoch + 1",
    ] {
        let corrupted = PreparedCompensationRootV1::new();
        Connection::open(&corrupted.database)
            .expect("coordinator database opens")
            .execute(mutation, [])
            .expect("schema-valid single-field corruption applies");
        assert_eq!(
            corrupted.reopen_v1(),
            Err(CoordinatorStoreOpenErrorV1::InvariantFailed),
            "immutable recovery corruption must fail closed: {mutation}",
        );
    }
}

fn open_provider_for_database_v1(
    fixture: &SyntheticCrossProcessRecoveryFixtureV1,
) -> SyntheticManifestLastRecoveryProviderV1 {
    SyntheticManifestLastRecoveryProviderV1::open_v1(fixture.root().path().to_path_buf())
        .expect("synthetic recovery provider opens")
}

#[test]
fn true_orphan_requires_quarantine_then_definitive_proof_then_permanent_retirement() {
    let root = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root");
    let store = root
        .open_empty_v1(
            SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            OPEN_DEADLINE_MS,
        )
        .expect("empty coordinator initializes");
    drop(store);
    let database = coordinator_database_v1(root.path());
    let recovery =
        SyntheticCrossProcessRecoveryFixtureV1::new().expect("synthetic recovery fixture creates");
    let provider = open_provider_for_database_v1(&recovery);
    let attempt_id = Sha256Digest::from_bytes([0x41; 32]);
    let operation_binding_digest = Sha256Digest::from_bytes([0x42; 32]);
    let recovery_manifest_digest = Sha256Digest::from_bytes([0x43; 32]);
    let retirement_id = Sha256Digest::from_bytes([0x44; 32]);
    let no_reference_digest = Sha256Digest::from_bytes([0x45; 32]);
    let mut connection = Connection::open(&database).expect("coordinator database opens");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys enable");

    let orphan = SyntheticOrphanInputV1 {
        attempt_id,
        operation_binding_digest,
        recovery_manifest_digest,
    };
    let first = retain_synthetic_orphan_v1(&mut connection, &orphan)
        .expect("published material enters active orphan quarantine");
    let repeat = retain_synthetic_orphan_v1(&mut connection, &orphan)
        .expect("orphan quarantine repeat is exact");
    assert_eq!(first.quarantine_id(), repeat.quarantine_id());
    assert_eq!(first.created_generation(), repeat.created_generation());
    provider
        .publish_public_synthetic_v1(recovery_manifest_digest)
        .expect("public-synthetic orphan material publishes manifest-last");

    let mut cleanup_guard = match provider
        .acquire_cleanup_guard_v1(recovery_manifest_digest, RECOVERY_GUARD_DEADLINE_MS)
    {
        SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
        other => panic!("cleanup guard must acquire, got {other:?}"),
    };
    let authorization = SyntheticOrphanAuthorizationInputV1 {
        quarantine_id: first.quarantine_id(),
        retirement_id,
        no_reference_digest,
    };
    assert_eq!(
        authorize_synthetic_orphan_retirement_v1(
            &mut connection,
            &authorization,
            SyntheticNoReferenceCaseV1::TemporaryAbsence,
            &mut cleanup_guard,
        ),
        SyntheticOrphanAuthorizationOutcomeV1::RetainedActive,
        "one absence observation is never retirement authority",
    );
    assert_orphan_state_v1(&connection, "ACTIVE", None);
    assert_eq!(count_rows_v1(&connection, "prepared_operations"), 0);
    assert_eq!(count_rows_v1(&connection, "budget_reservations"), 0);
    assert_eq!(count_rows_v1(&connection, "preparation_events"), 0);

    assert_eq!(
        authorize_synthetic_orphan_retirement_v1(
            &mut connection,
            &authorization,
            SyntheticNoReferenceCaseV1::Definitive,
            &mut cleanup_guard,
        ),
        SyntheticOrphanAuthorizationOutcomeV1::AuthorizedPending,
    );
    assert_orphan_state_v1(
        &connection,
        "RESOLVED_TOMBSTONE",
        Some("RETIREMENT_PENDING"),
    );
    assert_eq!(count_rows_v1(&connection, "prepared_operations"), 0);

    let retirement_manifest_digest = provider
        .publish_retirement_tombstone_v1(
            &mut cleanup_guard,
            recovery_manifest_digest,
            retirement_id,
        )
        .expect("provider bytes retire and immutable tombstone publishes");
    let retirement = SyntheticOrphanRetirementInputV1 {
        quarantine_id: first.quarantine_id(),
        retirement_id,
        retirement_manifest_digest,
    };
    assert_eq!(
        retire_synthetic_orphan_v1(
            &mut connection,
            &retirement,
            SyntheticRetirementStepV1::FinishTombstone,
            &mut cleanup_guard,
        ),
        SyntheticRetirementOutcomeV1::Retired,
    );
    assert_eq!(
        retire_synthetic_orphan_v1(
            &mut connection,
            &retirement,
            SyntheticRetirementStepV1::FinishTombstone,
            &mut cleanup_guard,
        ),
        SyntheticRetirementOutcomeV1::AlreadyRetired,
    );
    assert_orphan_state_v1(&connection, "RESOLVED_TOMBSTONE", Some("RETIRED_TOMBSTONE"));
    assert_eq!(count_rows_v1(&connection, "prepared_operations"), 0);
    assert_eq!(count_rows_v1(&connection, "operation_transitions"), 0);
    assert_eq!(count_rows_v1(&connection, "budget_reservations"), 0);
    assert_eq!(count_rows_v1(&connection, "preparation_events"), 0);
}

fn assert_orphan_state_v1(connection: &Connection, status: &str, retirement: Option<&str>) {
    let observed: (String, Option<String>) = connection
        .query_row(
            "SELECT quarantine_status, orphan_retirement_state \
             FROM preparation_quarantines",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("one orphan quarantine reads");
    assert_eq!(observed, (status.to_owned(), retirement.map(str::to_owned)));
}

#[test]
fn failed_operation_retirement_preserves_evidence_and_reconciled_budget_tombstones() {
    let fixture = PreparedCompensationRootV1::new();
    let recovery =
        SyntheticCrossProcessRecoveryFixtureV1::new().expect("synthetic recovery fixture creates");
    let provider = open_provider_for_database_v1(&recovery);
    let manifest_digest = only_recovery_manifest_v1(&fixture.database);
    let retirement_id = Sha256Digest::from_bytes([0x51; 32]);
    let original = RecoveryEvidenceObservationV1::read(&fixture.database);
    provider
        .publish_public_synthetic_v1(manifest_digest)
        .expect("matching public-synthetic material publishes manifest-last");

    let mut cleanup_guard =
        match provider.acquire_cleanup_guard_v1(manifest_digest, RECOVERY_GUARD_DEADLINE_MS) {
            SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
            other => panic!("cleanup guard must acquire, got {other:?}"),
        };
    let begin = SyntheticOperationRetirementInputV1 {
        operation_id: &fixture.operation_id,
        retirement_id,
        retirement_manifest_digest: None,
    };
    let mut connection = Connection::open(&fixture.database).expect("coordinator database opens");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys enable");
    assert_eq!(
        retire_synthetic_operation_bound_v1(
            &mut connection,
            &begin,
            SyntheticRetirementStepV1::BeginPending,
            &mut cleanup_guard,
        ),
        SyntheticRetirementOutcomeV1::NotEligible,
        "PREPARING material can never enter retirement",
    );

    drop(connection);
    fixture.fail_before_dispatch_v1();
    let mut connection = Connection::open(&fixture.database).expect("coordinator database opens");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("foreign keys enable");
    assert_eq!(
        retire_synthetic_operation_bound_v1(
            &mut connection,
            &begin,
            SyntheticRetirementStepV1::BeginPending,
            &mut cleanup_guard,
        ),
        SyntheticRetirementOutcomeV1::Pending,
    );
    assert_operation_recovery_state_v1(&connection, &fixture.operation_id, "RETIREMENT_PENDING");
    let retirement_manifest_digest = provider
        .publish_retirement_tombstone_v1(&mut cleanup_guard, manifest_digest, retirement_id)
        .expect("provider bytes retire and immutable tombstone publishes");
    let finish = SyntheticOperationRetirementInputV1 {
        operation_id: &fixture.operation_id,
        retirement_id,
        retirement_manifest_digest: Some(retirement_manifest_digest),
    };
    assert_eq!(
        retire_synthetic_operation_bound_v1(
            &mut connection,
            &finish,
            SyntheticRetirementStepV1::FinishTombstone,
            &mut cleanup_guard,
        ),
        SyntheticRetirementOutcomeV1::Retired,
    );
    assert_eq!(
        retire_synthetic_operation_bound_v1(
            &mut connection,
            &finish,
            SyntheticRetirementStepV1::FinishTombstone,
            &mut cleanup_guard,
        ),
        SyntheticRetirementOutcomeV1::AlreadyRetired,
    );
    assert_operation_recovery_state_v1(&connection, &fixture.operation_id, "RETIRED_TOMBSTONE");
    drop(connection);

    let retired = RecoveryEvidenceObservationV1::read(&fixture.database);
    assert_eq!(retired.material_digest, original.material_digest);
    assert_eq!(retired.material_length, original.material_length);
    assert_eq!(retired.reserved_capacity, original.reserved_capacity);
    assert_eq!(retired.manifest_digest, original.manifest_digest);
    assert_eq!(
        retired.retirement_id,
        Some(retirement_id.as_bytes().to_vec())
    );
    assert_eq!(
        retired.retirement_manifest_digest,
        Some(retirement_manifest_digest.as_bytes().to_vec())
    );
    let connection = Connection::open(&fixture.database).expect("coordinator database opens");
    let lifecycle: (String, String, i64) = connection
        .query_row(
            "SELECT operation.operation_state, reservation.reservation_state, \
                    scope.held_recovery_bytes \
             FROM prepared_operations AS operation \
             JOIN budget_reservations AS reservation USING (operation_id) \
             JOIN budget_scopes AS scope ON scope.scope_id = reservation.scope_id \
             WHERE operation.operation_id = ?1",
            [&fixture.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("failed operation lifecycle reads");
    assert_eq!(lifecycle, ("FAILED".to_owned(), "RELEASED".to_owned(), 0));
    fixture
        .reopen_v1()
        .expect("retired tombstone retains invariant-valid evidence");
}

fn assert_operation_recovery_state_v1(connection: &Connection, operation_id: &str, expected: &str) {
    let observed: String = connection
        .query_row(
            "SELECT material_state FROM preparation_recovery_evidence \
             WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .expect("operation-bound recovery state reads");
    assert_eq!(observed, expected);
}

fn count_rows_v1(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("table count reads")
}

#[test]
fn orphan_authorization_refuses_live_or_ambiguous_references_without_mutation() {
    let root = SyntheticCoordinatorRootV1::new().expect("synthetic coordinator root");
    let store = root
        .open_empty_v1(
            SyntheticCoordinatorClockV1::new(OPEN_NOW_MS),
            SyntheticHistoricalPlanKeyResolverV1::default(),
            OPEN_DEADLINE_MS,
        )
        .expect("empty coordinator initializes");
    drop(store);
    let database = coordinator_database_v1(root.path());
    let recovery =
        SyntheticCrossProcessRecoveryFixtureV1::new().expect("synthetic recovery fixture creates");
    let provider = open_provider_for_database_v1(&recovery);
    let input = SyntheticOrphanInputV1 {
        attempt_id: Sha256Digest::from_bytes([0x61; 32]),
        operation_binding_digest: Sha256Digest::from_bytes([0x62; 32]),
        recovery_manifest_digest: Sha256Digest::from_bytes([0x63; 32]),
    };
    let mut connection = Connection::open(&database).expect("coordinator database opens");
    let custody =
        retain_synthetic_orphan_v1(&mut connection, &input).expect("orphan quarantine inserts");
    let before: (i64, i64) = connection
        .query_row(
            "SELECT store_generation, quarantine_generation \
             FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("metadata reads");
    let authorization = SyntheticOrphanAuthorizationInputV1 {
        quarantine_id: custody.quarantine_id(),
        retirement_id: Sha256Digest::from_bytes([0x64; 32]),
        no_reference_digest: Sha256Digest::from_bytes([0x65; 32]),
    };
    let mut cleanup_guard = match provider
        .acquire_cleanup_guard_v1(input.recovery_manifest_digest, RECOVERY_GUARD_DEADLINE_MS)
    {
        SyntheticRecoveryGuardOutcomeV1::Acquired(guard) => guard,
        other => panic!("cleanup guard must acquire, got {other:?}"),
    };
    for case in [
        SyntheticNoReferenceCaseV1::CommittedOperation,
        SyntheticNoReferenceCaseV1::InFlightPermit,
        SyntheticNoReferenceCaseV1::AmbiguousReference,
        SyntheticNoReferenceCaseV1::StoreUnavailable,
    ] {
        assert_eq!(
            authorize_synthetic_orphan_retirement_v1(
                &mut connection,
                &authorization,
                case,
                &mut cleanup_guard,
            ),
            SyntheticOrphanAuthorizationOutcomeV1::RetainedActive,
        );
        assert_orphan_state_v1(&connection, "ACTIVE", None);
        assert_eq!(
            connection
                .query_row(
                    "SELECT store_generation, quarantine_generation \
                     FROM coordinator_store_meta WHERE singleton = 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .expect("metadata rereads"),
            before,
        );
    }
}
