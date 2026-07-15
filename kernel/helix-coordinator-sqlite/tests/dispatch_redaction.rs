//! Seeded PLAN-005 coordinator redaction, public-event and metrics contracts.

#![forbid(unsafe_code)]

#[path = "../src/dispatch_events.rs"]
mod production_dispatch_events;

use helix_contracts::{
    ContractError, Ed25519KeyResolver, Result as PlanContractResult, MAX_SAFE_U64,
};
use helix_coordinator_sqlite::{
    embedded_schema_v1_sha256, CoordinatorMonotonicClockV1, CoordinatorReceiptCommitOutcomeV1,
    CoordinatorReceiptLookupV1, CoordinatorRootIdentityEvidenceV1, CoordinatorStoreConfigV1,
    SqliteCoordinatorStoreV1, SqliteCoordinatorStoreV2,
};
use helix_dispatch_contracts::{
    ContractError as DispatchContractError, GrantKeyResolver, GrantVerificationKeyV1,
    ReceiptKeyResolver, ReceiptVerificationKeyV1,
};
use production_dispatch_events::{
    stage_pending_dispatch_event_v1, DispatchEventRowV1, DispatchMetricsV1,
};
use rusqlite::{params, Connection};
use sha2::{Digest as _, Sha256};
use std::cell::Cell;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);

const DETERMINISTIC_SEED: u64 = 0x54d1_5a7c_91e3_2b6f;
const PATH_CANARY: &str = "native-private-path-canary-t054";
const GRANT_BYTES_CANARY: &str = "canonical-grant-private-bytes-canary-t054";
const RECEIPT_BYTES_CANARY: &str = "canonical-receipt-private-bytes-canary-t054";
const KEY_CANARY: &str = "receipt-signing-key-private-canary-t054";
const OPERATION_CANARY: &str = "operation-private-canary-t054";
const TASK_CANARY: &str = "task-private-canary-t054";
const WORKLOAD_CANARY: &str = "workload-private-canary-t054";
const TRACE_CANARY: &str = "trace-private-canary-t054";

type ClosedPublicEventProjectionV1 = (
    i64,
    i64,
    i64,
    String,
    String,
    i64,
    String,
    Option<String>,
    String,
    Option<i64>,
);

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl CoordinatorMonotonicClockV1 for FixedClock {
    fn now_monotonic_ms(
        &self,
    ) -> Result<u64, helix_coordinator_sqlite::CoordinatorClockUnavailableV1> {
        Ok(self.0)
    }
}

struct HistoricalPlanKeys;

impl Ed25519KeyResolver for HistoricalPlanKeys {
    fn resolve_ed25519(&self, _: &str) -> PlanContractResult<[u8; 32]> {
        Err(ContractError::UnknownKey)
    }
}

struct SeededDispatchKeys {
    private_key_canary: &'static str,
    grant_resolutions: Cell<u64>,
    receipt_resolutions: Cell<u64>,
}

impl SeededDispatchKeys {
    fn new() -> Self {
        Self {
            private_key_canary: KEY_CANARY,
            grant_resolutions: Cell::new(0),
            receipt_resolutions: Cell::new(0),
        }
    }
}

impl GrantKeyResolver for SeededDispatchKeys {
    fn resolve_grant_key(
        &self,
        key_id: &str,
    ) -> helix_dispatch_contracts::Result<GrantVerificationKeyV1> {
        let _private_inputs = (self.private_key_canary, key_id);
        self.grant_resolutions
            .set(self.grant_resolutions.get().saturating_add(1));
        Err(DispatchContractError::UnknownKey)
    }
}

impl ReceiptKeyResolver for SeededDispatchKeys {
    fn resolve_receipt_key(
        &self,
        key_id: &str,
    ) -> helix_dispatch_contracts::Result<ReceiptVerificationKeyV1> {
        let _private_inputs = (self.private_key_canary, key_id);
        self.receipt_resolutions
            .set(self.receipt_resolutions.get().saturating_add(1));
        Err(DispatchContractError::UnknownKey)
    }
}

struct DispatchRoot {
    path: PathBuf,
}

impl DispatchRoot {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-{PATH_CANARY}-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("seeded coordinator root creates");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn database(&self) -> PathBuf {
        self.path.join("coordinator.sqlite3")
    }
}

impl Drop for DispatchRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn initialize_v1(root: &DispatchRoot) -> CoordinatorRootIdentityEvidenceV1 {
    let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), 25)
        .expect("empty seeded root validates");
    let store = SqliteCoordinatorStoreV1::open_or_create(
        config,
        FixedClock(1_000),
        HistoricalPlanKeys,
        10_000,
    )
    .expect("exact V1 root initializes");
    let identity = store.root_identity_evidence();
    drop(store);
    identity
}

fn install_exact_empty_v2(root: &DispatchRoot) {
    let connection = Connection::open(root.database()).expect("V1 database opens for overlay");
    let root_identity: Vec<u8> = connection
        .query_row(
            "SELECT root_identity FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("root identity reads");
    connection
        .execute_batch(V2_OVERLAY)
        .expect("reviewed V2 overlay installs");
    connection
        .execute(
            "INSERT INTO dispatch_store_meta (
                singleton, extension_format_version, dispatch_store_generation,
                dispatch_generation, delivery_generation, receipt_generation,
                reconciliation_generation, event_generation, migration_generation,
                ordinary_queue_capacity, control_queue_capacity, root_lifecycle_state,
                restore_index_digest, restore_state_generation
             ) VALUES (1, 1, 1, 0, 0, 0, 0, 0, 1, 1024, 32, 'ACTIVE', NULL, 0)",
            [],
        )
        .expect("dispatch metadata installs");
    connection
        .execute(
            "INSERT INTO coordinator_v2_migrations (
                migration_attempt_id, source_schema_digest, source_root_identity,
                source_summary_digest, verified_backup_digest, overlay_schema_digest,
                migration_generation, migrated_at_utc_ms, migrated_at_monotonic_ms,
                tool_identity
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1000, 1000, 'helixos-test-v1')",
            params![
                seeded_bytes(1).as_slice(),
                embedded_schema_v1_sha256().as_slice(),
                root_identity,
                seeded_bytes(2).as_slice(),
                seeded_bytes(3).as_slice(),
                <[u8; 32]>::from(Sha256::digest(V2_OVERLAY.as_bytes())).as_slice(),
            ],
        )
        .expect("migration evidence installs");
}

fn open_empty_v2(
    root: &DispatchRoot,
    identity: CoordinatorRootIdentityEvidenceV1,
) -> SqliteCoordinatorStoreV2<FixedClock, HistoricalPlanKeys> {
    let config = CoordinatorStoreConfigV1::try_new_existing_attested(
        root.path().to_path_buf(),
        identity,
        25,
    )
    .expect("existing seeded root validates");
    SqliteCoordinatorStoreV2::open_existing(config, FixedClock(1_002), HistoricalPlanKeys, 10_000)
        .expect("exact empty V2 root opens")
}

fn seeded_bytes(domain: u64) -> [u8; 32] {
    let mut state = DETERMINISTIC_SEED ^ domain.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut output = [0_u8; 32];
    for byte in &mut output {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state.to_le_bytes()[0];
    }
    output
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn sensitive_canaries(root: Option<&Path>, binary_values: &[[u8; 32]]) -> Vec<String> {
    let mut canaries = [
        PATH_CANARY,
        GRANT_BYTES_CANARY,
        RECEIPT_BYTES_CANARY,
        KEY_CANARY,
        OPERATION_CANARY,
        TASK_CANARY,
        WORKLOAD_CANARY,
        TRACE_CANARY,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    if let Some(root) = root {
        canaries.push(root.to_string_lossy().into_owned());
    }
    for value in binary_values {
        canaries.push(lowercase_hex(value));
        canaries.push(format!("{value:?}"));
    }
    canaries
}

fn assert_sensitive_free(diagnostic: &str, canaries: &[String]) {
    assert!(
        diagnostic.is_ascii(),
        "outward diagnostic must remain ASCII"
    );
    assert!(
        diagnostic.len() <= 512,
        "outward diagnostic must remain bounded"
    );
    for canary in canaries {
        assert!(
            !diagnostic.contains(canary),
            "outward diagnostic exposed a seeded private canary"
        );
    }
}

#[test]
fn real_t052_lookup_receipt_and_v2_root_return_only_a_closed_redacted_outcome() {
    let root = DispatchRoot::new("receipt-api");
    let identity = initialize_v1(&root);
    install_exact_empty_v2(&root);
    let store = open_empty_v2(&root, identity);

    let grant_id = seeded_bytes(10);
    let adapter_root_id = seeded_bytes(11);
    let canaries = sensitive_canaries(Some(root.path()), &[grant_id, adapter_root_id]);
    let lookup =
        CoordinatorReceiptLookupV1::try_new(OPERATION_CANARY.to_owned(), grant_id, adapter_root_id)
            .expect("seeded lookup validates");
    assert_eq!(format!("{lookup:?}"), "CoordinatorReceiptLookupV1 { .. }");
    assert_sensitive_free(&format!("{lookup:?}"), &canaries);
    assert_eq!(format!("{store:?}"), "SqliteCoordinatorStoreV2 { .. }");
    assert_sensitive_free(&format!("{store:?}"), &canaries);

    let canonical_receipt =
        format!("{{\"grant\":\"{GRANT_BYTES_CANARY}\",\"receipt\":\"{RECEIPT_BYTES_CANARY}\"}}");
    let keys = SeededDispatchKeys::new();
    let outcome =
        store.commit_execution_receipt_v1(lookup, canonical_receipt.as_bytes(), 10_000, &keys);
    assert!(matches!(
        &outcome,
        CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance
    ));
    assert_eq!(
        format!("{outcome:?}"),
        "CoordinatorReceiptCommitOutcomeV1::RejectedNoAdvance"
    );
    assert_sensitive_free(&format!("{outcome:?}"), &canaries);
    assert_eq!(keys.grant_resolutions.get(), 0);
    assert_eq!(keys.receipt_resolutions.get(), 0);

    for (outcome, expected) in [
        (
            CoordinatorReceiptCommitOutcomeV1::Conflict,
            "CoordinatorReceiptCommitOutcomeV1::Conflict",
        ),
        (
            CoordinatorReceiptCommitOutcomeV1::Unavailable,
            "CoordinatorReceiptCommitOutcomeV1::Unavailable",
        ),
        (
            CoordinatorReceiptCommitOutcomeV1::Unhealthy,
            "CoordinatorReceiptCommitOutcomeV1::Unhealthy",
        ),
    ] {
        let diagnostic = format!("{outcome:?}");
        assert_eq!(diagnostic, expected);
        assert_sensitive_free(&diagnostic, &canaries);
    }

    let invalid = CoordinatorReceiptLookupV1::try_new(
        format!("{OPERATION_CANARY}/private"),
        grant_id,
        adapter_root_id,
    )
    .expect_err("non-portable lookup must be rejected");
    assert_eq!(format!("{invalid:?}"), "InvalidLookup");
    assert_sensitive_free(&format!("{invalid:?}"), &canaries);

    drop(store);
    let connection = Connection::open(root.database()).expect("V2 database reopens read-only");
    for table in ["dispatch_receipts", "dispatch_events"] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("retained row count reads");
        assert_eq!(count, 0, "rejected receipt must retain no public row");
    }
}

#[test]
fn production_event_writer_keeps_seeded_graph_values_out_of_the_closed_public_projection() {
    let root = DispatchRoot::new("event-projection");
    initialize_v1(&root);
    install_exact_empty_v2(&root);

    let event_id = seeded_bytes(20);
    let grant_id = seeded_bytes(21);
    let dispatch_attempt_id = seeded_bytes(22);
    let plan_id = seeded_bytes(23);
    let task_lease_digest = seeded_bytes(24);
    let canaries = sensitive_canaries(
        Some(root.path()),
        &[
            event_id,
            grant_id,
            dispatch_attempt_id,
            plan_id,
            task_lease_digest,
        ],
    );
    let event = DispatchEventRowV1 {
        event_id: &event_id,
        event_generation: 2,
        transition_generation: 2,
        operation_id: OPERATION_CANARY,
        grant_id: &grant_id,
        dispatch_attempt_id: &dispatch_attempt_id,
        task_id: TASK_CANARY,
        workload_id: WORKLOAD_CANARY,
        plan_id: &plan_id,
        task_lease_digest: &task_lease_digest,
        latency_ms: 17,
        public_trace_id: TRACE_CANARY,
    };
    assert_eq!(format!("{event:?}"), "DispatchEventRowV1 { .. }");
    assert_sensitive_free(&format!("{event:?}"), &canaries);

    let mut connection = Connection::open(root.database()).expect("V2 event database opens");
    connection
        .pragma_update(None, "foreign_keys", false)
        .expect("synthetic event fixture disables cross-graph foreign keys");
    let transaction = connection.transaction().expect("event transaction begins");
    stage_pending_dispatch_event_v1(&transaction, event)
        .expect("production event writer accepts the seeded contract row");

    let internal_match: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM dispatch_events
             WHERE operation_id = ?1 AND grant_id = ?2 AND task_id = ?3
               AND workload_id = ?4 AND public_trace_id = ?5",
            params![
                OPERATION_CANARY,
                grant_id.as_slice(),
                TASK_CANARY,
                WORKLOAD_CANARY,
                TRACE_CANARY,
            ],
            |row| row.get(0),
        )
        .expect("internal exact event binding reads");
    assert_eq!(internal_match, 1, "seeded private graph was not exercised");

    let public_projection: ClosedPublicEventProjectionV1 = transaction
        .query_row(
            "SELECT event_contract_version, grant_contract_version,
                    receipt_contract_version, effective_state, decision, latency_ms,
                    event_kind, public_reason_code, delivery_state, delivered_generation
             FROM dispatch_events WHERE event_id = ?1",
            [event_id.as_slice()],
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
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .expect("closed public event projection reads");
    assert_eq!(
        public_projection,
        (
            1,
            1,
            0,
            "DISPATCHING".to_owned(),
            "DISPATCHED".to_owned(),
            17,
            "DISPATCHED".to_owned(),
            None,
            "PENDING".to_owned(),
            None,
        )
    );
    assert_sensitive_free(&format!("{public_projection:?}"), &canaries);
    transaction
        .rollback()
        .expect("seeded graph remains test-local");

    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM dispatch_events", [], |row| row.get(0))
        .expect("rolled-back event count reads");
    assert_eq!(count, 0);
}

#[test]
fn production_metrics_are_label_free_closed_and_bounded() {
    let binary_canary = seeded_bytes(30);
    let canaries = sensitive_canaries(None, &[binary_canary]);
    let metrics = DispatchMetricsV1::default();
    for _ in 0..3 {
        metrics.observe_committed_v1();
    }
    metrics.observe_prior_exact_v1();
    metrics.observe_confirmed_rollback_v1();
    metrics.observe_uncertain_v1();
    metrics.observe_conflict_v1();
    metrics.observe_unavailable_v1();
    metrics.observe_unhealthy_v1();

    let metrics_debug = format!("{metrics:?}");
    assert_eq!(metrics_debug, "DispatchMetricsV1 { .. }");
    assert_sensitive_free(&metrics_debug, &canaries);

    let snapshot = metrics.snapshot_v1();
    assert_eq!(snapshot.committed, 3);
    for counter in [
        snapshot.prior_exact,
        snapshot.confirmed_rollback,
        snapshot.uncertain,
        snapshot.conflict,
        snapshot.unavailable,
        snapshot.unhealthy,
    ] {
        assert_eq!(counter, 1);
    }
    for counter in [
        snapshot.committed,
        snapshot.prior_exact,
        snapshot.confirmed_rollback,
        snapshot.uncertain,
        snapshot.conflict,
        snapshot.unavailable,
        snapshot.unhealthy,
    ] {
        assert!(counter <= MAX_SAFE_U64);
    }
    let snapshot_debug = format!("{snapshot:?}");
    assert_eq!(
        snapshot_debug,
        "DispatchMetricsSnapshotV1 { committed: 3, prior_exact: 1, confirmed_rollback: 1, uncertain: 1, conflict: 1, unavailable: 1, unhealthy: 1 }"
    );
    assert_sensitive_free(&snapshot_debug, &canaries);
}

#[test]
fn t052_payload_carrying_debug_implementations_remain_structurally_opaque() {
    let source = include_str!("../src/dispatch_receipt.rs");
    for required in [
        "debug_struct(\"CoordinatorReceiptLookupV1\")",
        "debug_struct(\"CoordinatorReceiptCommitEvidenceV1\")",
        "debug_struct(\"CoordinatorReceiptUncertainCustodyV1\")",
        "Self::Committed(_) => \"CoordinatorReceiptCommitOutcomeV1::Committed(..)\"",
        "Self::PriorExact(_) => \"CoordinatorReceiptCommitOutcomeV1::PriorExact(..)\"",
        "Self::Uncertain(_) => \"CoordinatorReceiptCommitOutcomeV1::Uncertain(..)\"",
    ] {
        assert!(
            source.contains(required),
            "opaque Debug contract omits {required}"
        );
    }
    assert!(
        !source.contains(".field("),
        "T052 Debug must not project receipt, custody, identity or digest fields"
    );
}
