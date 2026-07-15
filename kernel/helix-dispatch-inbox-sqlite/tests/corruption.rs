//! PLAN-005 T097 adapter/cross-store corruption custody.
//!
//! These tests retain the adapter's production strict-open boundary as the first oracle:
//! structurally orphan inbox or receipt rows return no store handle. The complete cross-store
//! final T097 matrix is added only through production classification over real store projections;
//! the test never provides its own verifier or any activation path.

use helix_dispatch_contracts::Sha256Digest;
#[cfg(feature = "test-fault-injection")]
use helix_dispatch_inbox_sqlite::{
    audit_and_retain_adapter_projection_v1, classify_and_retain_adapter_connections_for_test_v1,
    AdapterCorruptionAuditErrorV1, AdapterCorruptionAuditLifecycleV1,
    AdapterCorruptionAuditOutcomeV1, AdapterCorruptionAuditPauseEvidenceV1,
    AdapterCorruptionAuditPauseV1, AdapterCorruptionAuditSelectionV1,
    AdapterCrossStoreIdsForTestV1, AdapterHistoryCustodyForTestV1,
    AdapterLifecycleRelationshipForTestV1,
};
use helix_dispatch_inbox_sqlite::{
    AdapterInboxInitializationV1, AdapterInboxProfileV1, AdapterInboxRootIdentityEvidenceV1,
    AdapterInboxStoreConfigV1, AdapterInboxStoreOpenErrorV1, SqliteDispatchInboxStoreV1,
};
#[cfg(feature = "test-fault-injection")]
use rusqlite::OptionalExtension;
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ADAPTER_DATABASE_FILENAME: &str = "dispatch-inbox.sqlite3";
#[cfg(feature = "test-fault-injection")]
const PATH_CANARY_V1: &str = "PATH_CANARY_T097_MUST_NOT_ESCAPE";
#[cfg(feature = "test-fault-injection")]
const WIRE_CANARY_V1: &[u8] = b"WIRE_CANARY_T097_MUST_NOT_ESCAPE";
#[cfg(feature = "test-fault-injection")]
const EVIDENCE_CANARY_V1: [u8; 32] = *b"T097-EVIDENCE-CANARY-DO-NOT-LOG!";

#[cfg(feature = "test-fault-injection")]
struct AdapterAuditPauseFixtureV1 {
    evidence: AdapterCorruptionAuditPauseEvidenceV1,
    capture_count: u64,
    recheck_count: u64,
    fail_on_recheck: Option<u64>,
}

#[cfg(feature = "test-fault-injection")]
impl AdapterAuditPauseFixtureV1 {
    fn stable() -> Self {
        Self::failing_on_recheck(None)
    }

    fn failing_on_recheck(fail_on_recheck: Option<u64>) -> Self {
        Self {
            evidence: AdapterCorruptionAuditPauseEvidenceV1::try_new(7, [0x97; 32])
                .expect("T097 PAUSE evidence is bounded and non-zero"),
            capture_count: 0,
            recheck_count: 0,
            fail_on_recheck,
        }
    }
}

#[cfg(feature = "test-fault-injection")]
impl AdapterCorruptionAuditPauseV1 for AdapterAuditPauseFixtureV1 {
    fn capture_adapter_corruption_audit_pause_v1(
        &mut self,
    ) -> Result<AdapterCorruptionAuditPauseEvidenceV1, AdapterCorruptionAuditErrorV1> {
        self.capture_count += 1;
        Ok(self.evidence)
    }

    fn recheck_adapter_corruption_audit_pause_v1(
        &mut self,
        expected: &AdapterCorruptionAuditPauseEvidenceV1,
    ) -> Result<(), AdapterCorruptionAuditErrorV1> {
        self.recheck_count += 1;
        if *expected != self.evidence || self.fail_on_recheck == Some(self.recheck_count) {
            return Err(AdapterCorruptionAuditErrorV1::Unavailable);
        }
        Ok(())
    }
}

struct StrictAdapterRootV1 {
    path: PathBuf,
    identity: AdapterInboxRootIdentityEvidenceV1,
}

impl StrictAdapterRootV1 {
    fn new(label: &str) -> Self {
        Self::new_with_identity(
            label,
            AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x41; 32]),
        )
    }

    fn new_with_identity(label: &str, identity: AdapterInboxRootIdentityEvidenceV1) -> Self {
        let path = Self::unique_path(label);
        fs::create_dir(&path).expect("T073 adapter root creates");
        let config = AdapterInboxStoreConfigV1::try_new_empty_attested(path.clone(), identity, 25)
            .expect("T073 empty adapter root is provisioner-attested");
        let store = SqliteDispatchInboxStoreV1::initialize_empty_v1(
            config,
            AdapterInboxInitializationV1::try_new(15, 1, [0x52; 32])
                .expect("T073 initial adapter observation is bounded"),
            adapter_profile(),
        )
        .expect("T073 exact adapter store initializes");
        drop(store);

        let fixture = Self { path, identity };
        drop(
            fixture
                .reopen()
                .expect("T073 exact empty adapter store passes strict open"),
        );
        fixture
    }

    #[cfg(feature = "test-fault-injection")]
    fn branch_from(source: &Self, label: &str) -> Self {
        let path = Self::unique_path(label);
        fs::create_dir(&path).expect("T097 adapter branch root creates");
        for entry in fs::read_dir(&source.path).expect("T097 source root is readable") {
            let entry = entry.expect("T097 source entry is readable");
            let source_path = entry.path();
            if source_path.is_file() {
                fs::copy(&source_path, path.join(entry.file_name()))
                    .expect("T097 closed adapter root file copies exactly");
            }
        }
        let branch = Self {
            path,
            identity: source.identity,
        };
        drop(
            branch
                .reopen()
                .expect("T097 physical adapter branch passes strict open"),
        );
        branch
    }

    fn unique_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "helixos-t073-adapter-{}-{sequence}-{label}",
            std::process::id()
        ))
    }

    fn database(&self) -> PathBuf {
        self.path.join(ADAPTER_DATABASE_FILENAME)
    }

    fn reopen(&self) -> Result<SqliteDispatchInboxStoreV1, AdapterInboxStoreOpenErrorV1> {
        let config = AdapterInboxStoreConfigV1::try_new_existing_attested(
            self.path.clone(),
            self.identity,
            25,
        )
        .expect("T073 existing adapter root remains provisioner-attested");
        SqliteDispatchInboxStoreV1::open_existing_v1(config, adapter_profile())
    }
}

impl Drop for StrictAdapterRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn adapter_profile() -> AdapterInboxProfileV1 {
    AdapterInboxProfileV1::try_new("adapter-t073-v1", 1, Sha256Digest::from_bytes([0x53; 32]))
        .expect("T073 adapter profile is exact")
}

fn inject_orphan_adapter_inbox(database: &Path) {
    let connection = Connection::open(database).expect("T073 adapter database opens raw");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T073 out-of-band fixture disables foreign keys");
    connection
        .execute(
            "UPDATE adapter_store_meta
             SET store_generation = 1, inbox_generation = 1
             WHERE singleton = 1",
            [],
        )
        .expect("T073 orphan adapter inbox high-water projection seeds");
    connection
        .execute(
            "INSERT INTO grant_inbox (
                grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                canonical_grant, canonical_grant_length, coordinator_key_fingerprint,
                destination_adapter_id, protocol_version, observed_supervisor_epoch,
                epoch_observer_generation, inbox_state, received_generation,
                current_generation, receipt_id, receipt_decision, current_event_id
             ) VALUES (
                ?1, 'operation:t073-orphan-inbox', ?2, ?3, 'task:t073',
                'workload:t073', ?4, ?5, ?6, ?7, 1, ?8,
                'adapter-t073-v1', 1, 15, 1, 'RECEIVED', 1, 1, NULL, NULL, ?9
             )",
            params![
                [0x61_u8; 32].as_slice(),
                [0x62_u8; 32].as_slice(),
                [0x63_u8; 32].as_slice(),
                [0x64_u8; 32].as_slice(),
                [0x65_u8; 32].as_slice(),
                [0x66_u8; 32].as_slice(),
                [0x67_u8].as_slice(),
                [0x68_u8; 32].as_slice(),
                [0x69_u8; 32].as_slice(),
            ],
        )
        .expect("T073 structurally orphan adapter inbox injects");
}

fn inject_orphan_adapter_receipt(database: &Path) {
    let connection = Connection::open(database).expect("T073 adapter database opens raw");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T073 out-of-band fixture disables foreign keys");
    connection
        .execute(
            "UPDATE adapter_store_meta
             SET store_generation = 1, receipt_generation = 1
             WHERE singleton = 1",
            [],
        )
        .expect("T073 orphan adapter receipt high-water projection seeds");
    connection
        .execute(
            "INSERT INTO execution_receipts (
                receipt_id, grant_id, operation_id, dispatch_attempt_id,
                receipt_digest, canonical_receipt, canonical_receipt_length,
                adapter_key_id, adapter_key_fingerprint, decision, refusal_code,
                no_consumption_tombstone_digest, receipt_generation
             ) VALUES (
                ?1, ?2, 'operation:t073-orphan-receipt', ?3,
                ?4, ?5, 1, 'receipt-key:t073', ?6,
                'CONSUMED', NULL, NULL, 1
             )",
            params![
                [0x71_u8; 32].as_slice(),
                [0x72_u8; 32].as_slice(),
                [0x73_u8; 32].as_slice(),
                [0x74_u8; 32].as_slice(),
                [0x75_u8].as_slice(),
                [0x76_u8; 32].as_slice(),
            ],
        )
        .expect("T073 structurally orphan adapter receipt injects");
}

#[cfg(feature = "test-fault-injection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterFixtureTerminalV1 {
    Received,
    Quarantined {
        transition_generation: u64,
        event_generation: u64,
    },
    Consumed {
        transition_generation: u64,
        receipt_generation: u64,
        event_generation: u64,
    },
}

#[cfg(feature = "test-fault-injection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdapterFixtureRecordV1 {
    identity_tag: u8,
    grant_digest_tag: u8,
    receipt_digest_tag: u8,
    wire_tag: u8,
    redaction_canaries: bool,
    received_generation: u64,
    received_event_generation: u64,
    terminal: AdapterFixtureTerminalV1,
}

#[cfg(feature = "test-fault-injection")]
impl AdapterFixtureRecordV1 {
    const fn received(identity_tag: u8, generation: u64) -> Self {
        Self {
            identity_tag,
            grant_digest_tag: identity_tag.wrapping_add(1),
            receipt_digest_tag: identity_tag.wrapping_add(2),
            wire_tag: identity_tag.wrapping_add(3),
            redaction_canaries: false,
            received_generation: generation,
            received_event_generation: generation,
            terminal: AdapterFixtureTerminalV1::Received,
        }
    }

    const fn consumed(identity_tag: u8) -> Self {
        Self::consumed_at(identity_tag, 1, 2, 3, 4)
    }

    const fn consumed_at(
        identity_tag: u8,
        received_generation: u64,
        transition_generation: u64,
        receipt_generation: u64,
        event_generation: u64,
    ) -> Self {
        Self {
            identity_tag,
            grant_digest_tag: identity_tag.wrapping_add(1),
            receipt_digest_tag: identity_tag.wrapping_add(2),
            wire_tag: identity_tag.wrapping_add(3),
            redaction_canaries: false,
            received_generation,
            received_event_generation: received_generation,
            terminal: AdapterFixtureTerminalV1::Consumed {
                transition_generation,
                receipt_generation,
                event_generation,
            },
        }
    }

    const fn quarantined(identity_tag: u8) -> Self {
        Self {
            identity_tag,
            grant_digest_tag: identity_tag.wrapping_add(1),
            receipt_digest_tag: identity_tag.wrapping_add(2),
            wire_tag: identity_tag.wrapping_add(3),
            redaction_canaries: false,
            received_generation: 1,
            received_event_generation: 1,
            terminal: AdapterFixtureTerminalV1::Quarantined {
                transition_generation: 2,
                event_generation: 3,
            },
        }
    }

    const fn with_grant_digest_tag(mut self, tag: u8) -> Self {
        self.grant_digest_tag = tag;
        self
    }

    const fn with_redaction_canaries(mut self) -> Self {
        self.redaction_canaries = true;
        self
    }
}

#[cfg(feature = "test-fault-injection")]
fn exact_blob(tag: u8) -> [u8; 32] {
    [tag; 32]
}

#[cfg(feature = "test-fault-injection")]
fn fixture_grant_id(record: AdapterFixtureRecordV1) -> [u8; 32] {
    exact_blob(record.identity_tag)
}

#[cfg(feature = "test-fault-injection")]
fn strict_i64(value: u64) -> i64 {
    i64::try_from(value).expect("T097 fixture generation fits signed SQLite integer")
}

#[cfg(feature = "test-fault-injection")]
fn seed_adapter_history_v1(
    root: &StrictAdapterRootV1,
    records: &[AdapterFixtureRecordV1],
    store_generation_floor: u64,
) {
    assert!(!records.is_empty(), "T097 seeded history is non-empty");
    let mut inbox_generation = 0_u64;
    let mut consumption_generation = 0_u64;
    let mut receipt_generation = 0_u64;
    let mut event_generation = 0_u64;
    for record in records {
        inbox_generation = inbox_generation.max(record.received_generation);
        event_generation = event_generation.max(record.received_event_generation);
        match record.terminal {
            AdapterFixtureTerminalV1::Received => {}
            AdapterFixtureTerminalV1::Quarantined {
                transition_generation,
                event_generation: terminal_event_generation,
            } => {
                consumption_generation = consumption_generation.max(transition_generation);
                event_generation = event_generation.max(terminal_event_generation);
            }
            AdapterFixtureTerminalV1::Consumed {
                transition_generation,
                receipt_generation: terminal_receipt_generation,
                event_generation: terminal_event_generation,
            } => {
                consumption_generation = consumption_generation.max(transition_generation);
                receipt_generation = receipt_generation.max(terminal_receipt_generation);
                event_generation = event_generation.max(terminal_event_generation);
            }
        }
    }
    let store_generation = store_generation_floor
        .max(inbox_generation)
        .max(consumption_generation)
        .max(receipt_generation)
        .max(event_generation);
    assert!(store_generation > 0, "T097 seeded store advances");

    let mut connection = Connection::open(root.database()).expect("T097 seed database opens");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("T097 seed enforces foreign keys");
    let transaction = connection
        .transaction()
        .expect("T097 seed transaction begins");
    transaction
        .execute_batch("PRAGMA defer_foreign_keys = ON")
        .expect("T097 cyclic fixture foreign keys are deferred");
    transaction
        .execute(
            "UPDATE adapter_store_meta
             SET store_generation = ?1, inbox_generation = ?2,
                 consumption_generation = ?3, receipt_generation = ?4,
                 event_generation = ?5
             WHERE singleton = 1",
            params![
                strict_i64(store_generation),
                strict_i64(inbox_generation),
                strict_i64(consumption_generation),
                strict_i64(receipt_generation),
                strict_i64(event_generation),
            ],
        )
        .expect("T097 fixture metadata advances monotonically");

    for record in records {
        insert_received_fixture_v1(&transaction, *record);
        match record.terminal {
            AdapterFixtureTerminalV1::Received => {}
            AdapterFixtureTerminalV1::Quarantined {
                transition_generation,
                event_generation,
            } => insert_terminal_fixture_v1(
                &transaction,
                *record,
                transition_generation,
                None,
                event_generation,
            ),
            AdapterFixtureTerminalV1::Consumed {
                transition_generation,
                receipt_generation,
                event_generation,
            } => insert_terminal_fixture_v1(
                &transaction,
                *record,
                transition_generation,
                Some(receipt_generation),
                event_generation,
            ),
        }
    }
    transaction.commit().expect("T097 fixture history commits");
    drop(connection);
    drop(
        root.reopen()
            .expect("T097 seeded adapter history passes strict open"),
    );
}

#[cfg(feature = "test-fault-injection")]
fn insert_received_fixture_v1(
    transaction: &rusqlite::Transaction<'_>,
    record: AdapterFixtureRecordV1,
) {
    let grant_id = fixture_grant_id(record);
    let dispatch_attempt_id = exact_blob(record.identity_tag.wrapping_add(10));
    let plan_id = exact_blob(record.identity_tag.wrapping_add(11));
    let lease_digest = exact_blob(record.identity_tag.wrapping_add(12));
    let nonce = exact_blob(record.identity_tag.wrapping_add(13));
    let grant_digest = exact_blob(record.grant_digest_tag);
    let coordinator_fingerprint = exact_blob(record.identity_tag.wrapping_add(14));
    let event_id = exact_blob(record.identity_tag.wrapping_add(20));
    let operation_id = format!("operation:t097-{:02x}", record.identity_tag);
    let task_id = format!("task:t097-{:02x}", record.identity_tag);
    let workload_id = format!("workload:t097-{:02x}", record.identity_tag);
    let trace_id = format!("trace:t097-received-{:02x}", record.identity_tag);
    let one_byte_wire = [record.wire_tag];
    let canonical_grant = if record.redaction_canaries {
        WIRE_CANARY_V1
    } else {
        one_byte_wire.as_slice()
    };
    let evidence_digest = if record.redaction_canaries {
        EVIDENCE_CANARY_V1
    } else {
        exact_blob(record.identity_tag.wrapping_add(21))
    };
    transaction
        .execute(
            "INSERT INTO grant_inbox (
                grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                canonical_grant, canonical_grant_length, coordinator_key_fingerprint,
                destination_adapter_id, protocol_version, observed_supervisor_epoch,
                epoch_observer_generation, inbox_state, received_generation,
                current_generation, receipt_id, receipt_decision, current_event_id
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, 'adapter-t073-v1', 1, 15, 1,
                'RECEIVED', ?13, ?13, NULL, NULL, ?14
             )",
            params![
                grant_id.as_slice(),
                operation_id,
                dispatch_attempt_id.as_slice(),
                plan_id.as_slice(),
                task_id,
                workload_id,
                lease_digest.as_slice(),
                nonce.as_slice(),
                grant_digest.as_slice(),
                canonical_grant,
                strict_i64(canonical_grant.len() as u64),
                coordinator_fingerprint.as_slice(),
                strict_i64(record.received_generation),
                event_id.as_slice(),
            ],
        )
        .expect("T097 fixture grant inserts as RECEIVED");
    transaction
        .execute(
            "INSERT INTO inbox_transitions (
                transition_generation, previous_transition_generation, grant_id,
                operation_id, previous_state, new_state, event_id, evidence_digest,
                receipt_id, receipt_decision
             ) VALUES (?1, NULL, ?2, ?3, 'ABSENT', 'RECEIVED', ?4, ?5, NULL, NULL)",
            params![
                strict_i64(record.received_generation),
                grant_id.as_slice(),
                operation_id,
                event_id.as_slice(),
                evidence_digest.as_slice(),
            ],
        )
        .expect("T097 fixture receive transition inserts");
    insert_adapter_event_v1(
        transaction,
        record,
        record.received_generation,
        record.received_event_generation,
        event_id,
        "RECEIVED",
        "RECEIVED",
        "GRANT_RECEIVED",
        0,
        None,
        &trace_id,
    );
}

#[cfg(feature = "test-fault-injection")]
fn insert_terminal_fixture_v1(
    transaction: &rusqlite::Transaction<'_>,
    record: AdapterFixtureRecordV1,
    transition_generation: u64,
    receipt_generation: Option<u64>,
    event_generation: u64,
) {
    let grant_id = fixture_grant_id(record);
    let operation_id = format!("operation:t097-{:02x}", record.identity_tag);
    let terminal_event_id = exact_blob(record.identity_tag.wrapping_add(22));
    let receipt_id = receipt_generation.map(|_| exact_blob(record.identity_tag.wrapping_add(23)));
    let evidence_digest = if record.redaction_canaries {
        EVIDENCE_CANARY_V1
    } else {
        exact_blob(record.identity_tag.wrapping_add(24))
    };
    let (state, decision, event_kind, receipt_version, public_reason) = if receipt_id.is_some() {
        ("CONSUMED", "CONSUMED", "GRANT_CONSUMED", 1_i64, None)
    } else {
        (
            "QUARANTINED",
            "QUARANTINED",
            "GRANT_QUARANTINED",
            0_i64,
            Some("CORRUPTION_FIXTURE"),
        )
    };
    transaction
        .execute(
            "UPDATE grant_inbox
             SET inbox_state = ?1, current_generation = ?2,
                 receipt_id = ?3, receipt_decision = ?4, current_event_id = ?5
             WHERE grant_id = ?6",
            params![
                state,
                strict_i64(transition_generation),
                receipt_id.as_ref().map(|value| value.as_slice()),
                receipt_id.map(|_| decision),
                terminal_event_id.as_slice(),
                grant_id.as_slice(),
            ],
        )
        .expect("T097 fixture grant advances once to terminal");
    transaction
        .execute(
            "INSERT INTO inbox_transitions (
                transition_generation, previous_transition_generation, grant_id,
                operation_id, previous_state, new_state, event_id, evidence_digest,
                receipt_id, receipt_decision
             ) VALUES (?1, ?2, ?3, ?4, 'RECEIVED', ?5, ?6, ?7, ?8, ?9)",
            params![
                strict_i64(transition_generation),
                strict_i64(record.received_generation),
                grant_id.as_slice(),
                operation_id,
                state,
                terminal_event_id.as_slice(),
                evidence_digest.as_slice(),
                receipt_id.as_ref().map(|value| value.as_slice()),
                receipt_id.map(|_| decision),
            ],
        )
        .expect("T097 fixture terminal transition inserts");
    if let (Some(receipt_generation), Some(receipt_id)) = (receipt_generation, receipt_id) {
        transaction
            .execute(
                "INSERT INTO execution_receipts (
                    receipt_id, grant_id, operation_id, dispatch_attempt_id,
                    receipt_digest, canonical_receipt, canonical_receipt_length,
                    adapter_key_id, adapter_key_fingerprint, decision, refusal_code,
                    no_consumption_tombstone_digest, receipt_generation
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, 1, 'receipt-key:t097', ?7,
                    'CONSUMED', NULL, NULL, ?8
                 )",
                params![
                    receipt_id.as_slice(),
                    grant_id.as_slice(),
                    operation_id,
                    exact_blob(record.identity_tag.wrapping_add(10)).as_slice(),
                    exact_blob(record.receipt_digest_tag).as_slice(),
                    [record.wire_tag.wrapping_add(1)].as_slice(),
                    exact_blob(record.identity_tag.wrapping_add(25)).as_slice(),
                    strict_i64(receipt_generation),
                ],
            )
            .expect("T097 fixture consumed receipt inserts");
    }
    let trace_id = format!("trace:t097-terminal-{:02x}", record.identity_tag);
    insert_adapter_event_v1(
        transaction,
        record,
        transition_generation,
        event_generation,
        terminal_event_id,
        state,
        decision,
        event_kind,
        receipt_version,
        public_reason,
        &trace_id,
    );
}

#[cfg(feature = "test-fault-injection")]
#[allow(clippy::too_many_arguments)]
fn insert_adapter_event_v1(
    transaction: &rusqlite::Transaction<'_>,
    record: AdapterFixtureRecordV1,
    transition_generation: u64,
    event_generation: u64,
    event_id: [u8; 32],
    effective_state: &str,
    decision: &str,
    event_kind: &str,
    receipt_contract_version: i64,
    public_reason_code: Option<&str>,
    trace_id: &str,
) {
    transaction
        .execute(
            "INSERT INTO adapter_events (
                event_id, event_generation, transition_generation, grant_id,
                operation_id, dispatch_attempt_id, task_id, workload_id, plan_id,
                task_lease_digest, event_contract_version, grant_contract_version,
                receipt_contract_version, effective_state, decision, latency_ms,
                event_kind, public_reason_code, public_trace_id, delivery_state,
                delivered_generation
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                1, 1, ?11, ?12, ?13, 0, ?14, ?15, ?16, 'PENDING', NULL
             )",
            params![
                event_id.as_slice(),
                strict_i64(event_generation),
                strict_i64(transition_generation),
                fixture_grant_id(record).as_slice(),
                format!("operation:t097-{:02x}", record.identity_tag),
                exact_blob(record.identity_tag.wrapping_add(10)).as_slice(),
                format!("task:t097-{:02x}", record.identity_tag),
                format!("workload:t097-{:02x}", record.identity_tag),
                exact_blob(record.identity_tag.wrapping_add(11)).as_slice(),
                exact_blob(record.identity_tag.wrapping_add(12)).as_slice(),
                receipt_contract_version,
                effective_state,
                decision,
                event_kind,
                public_reason_code,
                trace_id,
            ],
        )
        .expect("T097 fixture adapter event inserts");
}

#[cfg(feature = "test-fault-injection")]
fn remove_received_record_preserving_schema_v1(root: &StrictAdapterRootV1, grant_id: [u8; 32]) {
    let mut connection = Connection::open(root.database()).expect("T097 branch database opens");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T097 out-of-band branch mutation disables foreign keys");
    let trigger_names = [
        "adapter_events_no_delete",
        "inbox_transitions_no_delete",
        "grant_inbox_no_delete",
    ];
    let trigger_sql = trigger_names.map(|name| {
        connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .expect("T097 permanent-history trigger SQL is present")
    });
    let transaction = connection
        .transaction()
        .expect("T097 out-of-band branch transaction begins");
    for name in trigger_names {
        transaction
            .execute_batch(&format!("DROP TRIGGER {name}"))
            .expect("T097 fixture temporarily removes reviewed delete guard");
    }
    transaction
        .execute(
            "DELETE FROM adapter_events WHERE grant_id = ?1",
            [grant_id.as_slice()],
        )
        .expect("T097 branch removes selected adapter event history");
    transaction
        .execute(
            "DELETE FROM inbox_transitions WHERE grant_id = ?1",
            [grant_id.as_slice()],
        )
        .expect("T097 branch removes selected transition history");
    transaction
        .execute(
            "DELETE FROM grant_inbox WHERE grant_id = ?1",
            [grant_id.as_slice()],
        )
        .expect("T097 branch removes selected grant history");
    for sql in trigger_sql {
        transaction
            .execute_batch(&sql)
            .expect("T097 fixture restores exact reviewed delete guard");
    }
    transaction
        .commit()
        .expect("T097 out-of-band branch mutation commits");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("T097 branch re-enables foreign keys");
    let foreign_key_violation: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("T097 branch foreign-key check executes");
    assert_eq!(
        foreign_key_violation, None,
        "T097 retained branch is closed"
    );
    drop(connection);
    drop(
        root.reopen()
            .expect("T097 truncated physical branch remains internally strict-openable"),
    );
}

#[cfg(feature = "test-fault-injection")]
fn inject_duplicate_adapter_generation_v1(root: &StrictAdapterRootV1, duplicate_tag: u8) {
    let connection = Connection::open(root.database()).expect("T097 duplicate database opens");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("T097 duplicate fixture disables foreign keys");
    connection
        .execute_batch(
            "DROP INDEX grant_inbox_received_generation_uq;
             DROP INDEX grant_inbox_current_generation_uq;",
        )
        .expect("T097 duplicate fixture removes only generation uniqueness guards");
    connection
        .execute(
            "INSERT INTO grant_inbox (
                grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                canonical_grant, canonical_grant_length, coordinator_key_fingerprint,
                destination_adapter_id, protocol_version, observed_supervisor_epoch,
                epoch_observer_generation, inbox_state, received_generation,
                current_generation, receipt_id, receipt_decision, current_event_id
             )
             SELECT ?1, ?2, ?3, plan_id, task_id, workload_id, task_lease_digest,
                    ?4, ?5, canonical_grant, canonical_grant_length,
                    coordinator_key_fingerprint, destination_adapter_id,
                    protocol_version, observed_supervisor_epoch,
                    epoch_observer_generation, inbox_state, received_generation,
                    current_generation, NULL, NULL, ?6
             FROM grant_inbox
             ORDER BY grant_id
             LIMIT 1",
            params![
                exact_blob(duplicate_tag).as_slice(),
                format!("operation:t097-{duplicate_tag:02x}"),
                exact_blob(duplicate_tag.wrapping_add(10)).as_slice(),
                exact_blob(duplicate_tag.wrapping_add(13)).as_slice(),
                exact_blob(duplicate_tag.wrapping_add(1)).as_slice(),
                exact_blob(duplicate_tag.wrapping_add(20)).as_slice(),
            ],
        )
        .expect("T097 real duplicate generation row inserts after index loss");
    let duplicates: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM (
                 SELECT received_generation FROM grant_inbox
                 GROUP BY received_generation HAVING COUNT(*) > 1
             )",
            [],
            |row| row.get(0),
        )
        .expect("T097 duplicate generation evidence reads from SQLite");
    assert_eq!(
        duplicates, 1,
        "T097 fixture contains one real reused generation"
    );
}

#[cfg(feature = "test-fault-injection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CounterpartFixtureRecordV1 {
    identity_tag: u8,
    operation_identity_tag: u8,
    dispatch_attempt_tag: u8,
    grant_digest_tag: u8,
    receipt_digest_tag: u8,
    created_generation: u64,
    preparation_transition_generation: u64,
    receipt_generation: u64,
    include_receipt: bool,
}

#[cfg(feature = "test-fault-injection")]
impl CounterpartFixtureRecordV1 {
    const fn matching(record: AdapterFixtureRecordV1, include_receipt: bool) -> Self {
        let receipt_generation = match record.terminal {
            AdapterFixtureTerminalV1::Consumed {
                receipt_generation, ..
            } => receipt_generation,
            AdapterFixtureTerminalV1::Received | AdapterFixtureTerminalV1::Quarantined { .. } => {
                record.received_generation
            }
        };
        Self {
            identity_tag: record.identity_tag,
            operation_identity_tag: record.identity_tag,
            dispatch_attempt_tag: record.identity_tag.wrapping_add(10),
            grant_digest_tag: record.grant_digest_tag,
            receipt_digest_tag: record.receipt_digest_tag,
            created_generation: record.received_generation,
            preparation_transition_generation: record.received_generation,
            receipt_generation,
            include_receipt,
        }
    }

    const fn with_grant_digest_tag(mut self, tag: u8) -> Self {
        self.grant_digest_tag = tag;
        self
    }

    const fn with_receipt_digest_tag(mut self, tag: u8) -> Self {
        self.receipt_digest_tag = tag;
        self
    }

    const fn with_dispatch_attempt_tag(mut self, tag: u8) -> Self {
        self.dispatch_attempt_tag = tag;
        self
    }

    const fn with_created_generation(mut self, generation: u64) -> Self {
        self.created_generation = generation;
        self
    }
}

#[cfg(feature = "test-fault-injection")]
struct CounterpartRootV1 {
    path: PathBuf,
}

#[cfg(feature = "test-fault-injection")]
impl CounterpartRootV1 {
    fn new(label: &str, records: &[CounterpartFixtureRecordV1]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-t097-counterpart-{}-{sequence}-{label}.sqlite3",
            std::process::id()
        ));
        let mut connection = Connection::open(&path).expect("T097 counterpart file creates");
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE dispatch_grants (
                    grant_id BLOB NOT NULL,
                    operation_id TEXT COLLATE BINARY NOT NULL,
                    dispatch_attempt_id BLOB NOT NULL,
                    grant_digest BLOB NOT NULL,
                    created_generation INTEGER NOT NULL DEFAULT 1,
                    preparation_transition_generation INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (grant_id),
                    UNIQUE (grant_id, operation_id, dispatch_attempt_id),
                    CHECK (typeof(grant_id) = 'blob' AND length(grant_id) = 32),
                    CHECK (typeof(dispatch_attempt_id) = 'blob'
                           AND length(dispatch_attempt_id) = 32),
                    CHECK (typeof(grant_digest) = 'blob' AND length(grant_digest) = 32)
                 ) STRICT, WITHOUT ROWID;
                 CREATE TABLE dispatch_receipts (
                    receipt_id BLOB NOT NULL,
                    grant_id BLOB NOT NULL,
                    operation_id TEXT COLLATE BINARY NOT NULL,
                    dispatch_attempt_id BLOB NOT NULL,
                    receipt_digest BLOB NOT NULL,
                    receipt_generation INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (receipt_id),
                    FOREIGN KEY (grant_id, operation_id, dispatch_attempt_id)
                        REFERENCES dispatch_grants (
                            grant_id, operation_id, dispatch_attempt_id
                        ),
                    CHECK (typeof(receipt_id) = 'blob' AND length(receipt_id) = 32),
                    CHECK (typeof(grant_id) = 'blob' AND length(grant_id) = 32),
                    CHECK (typeof(dispatch_attempt_id) = 'blob'
                           AND length(dispatch_attempt_id) = 32),
                    CHECK (typeof(receipt_digest) = 'blob' AND length(receipt_digest) = 32)
                 ) STRICT, WITHOUT ROWID;",
            )
            .expect("T097 counterpart projection schema initializes");
        let transaction = connection
            .transaction()
            .expect("T097 counterpart transaction begins");
        for record in records {
            let operation_id = format!("operation:t097-{:02x}", record.operation_identity_tag);
            transaction
                .execute(
                    "INSERT INTO dispatch_grants (
                        grant_id, operation_id, dispatch_attempt_id, grant_digest,
                        created_generation, preparation_transition_generation
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        exact_blob(record.identity_tag).as_slice(),
                        operation_id,
                        exact_blob(record.dispatch_attempt_tag).as_slice(),
                        exact_blob(record.grant_digest_tag).as_slice(),
                        strict_i64(record.created_generation),
                        strict_i64(record.preparation_transition_generation),
                    ],
                )
                .expect("T097 counterpart grant inserts");
            if record.include_receipt {
                transaction
                    .execute(
                        "INSERT INTO dispatch_receipts (
                            receipt_id, grant_id, operation_id,
                            dispatch_attempt_id, receipt_digest, receipt_generation
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            exact_blob(record.identity_tag.wrapping_add(23)).as_slice(),
                            exact_blob(record.identity_tag).as_slice(),
                            operation_id,
                            exact_blob(record.dispatch_attempt_tag).as_slice(),
                            exact_blob(record.receipt_digest_tag).as_slice(),
                            strict_i64(record.receipt_generation),
                        ],
                    )
                    .expect("T097 counterpart receipt inserts");
            }
        }
        transaction
            .commit()
            .expect("T097 counterpart projection commits");
        drop(connection);
        let root = Self { path };
        root.assert_readable();
        root
    }

    fn branch_from(source: &Self, label: &str) -> Self {
        let branch = Self::new(label, &[]);
        fs::remove_file(&branch.path).expect("T097 empty counterpart branch file removes");
        fs::copy(&source.path, &branch.path).expect("T097 counterpart file copies physically");
        branch.assert_readable();
        branch
    }

    fn open(&self) -> Connection {
        let connection = Connection::open(&self.path).expect("T097 counterpart opens");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("T097 counterpart enforces foreign keys");
        connection
    }

    fn assert_readable(&self) {
        let connection = self.open();
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("T097 counterpart integrity check runs");
        assert_eq!(
            integrity, "ok",
            "T097 counterpart file is structurally valid"
        );
        let violation: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .expect("T097 counterpart foreign-key check runs");
        assert_eq!(violation, None, "T097 counterpart relationships are exact");
    }
}

#[cfg(feature = "test-fault-injection")]
impl Drop for CounterpartRootV1 {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(format!("{}-wal", self.path.display()));
        let _ = fs::remove_file(format!("{}-shm", self.path.display()));
    }
}

#[cfg(feature = "test-fault-injection")]
fn adapter_root_with_history_v1(
    label: &str,
    records: &[AdapterFixtureRecordV1],
    store_generation_floor: u64,
) -> StrictAdapterRootV1 {
    let root = StrictAdapterRootV1::new(label);
    seed_adapter_history_v1(&root, records, store_generation_floor);
    root
}

#[cfg(feature = "test-fault-injection")]
fn fixture_ids_v1(
    record: AdapterFixtureRecordV1,
    include_receipt: bool,
) -> AdapterCrossStoreIdsForTestV1 {
    AdapterCrossStoreIdsForTestV1::try_new(
        fixture_grant_id(record),
        format!("operation:t097-{:02x}", record.identity_tag),
        exact_blob(record.identity_tag.wrapping_add(10)),
        include_receipt.then(|| exact_blob(record.identity_tag.wrapping_add(23))),
    )
    .expect("T097 cross-store identities are bounded")
}

#[cfg(feature = "test-fault-injection")]
fn audit_selection_v1(
    record: AdapterFixtureRecordV1,
    include_receipt: bool,
) -> AdapterCorruptionAuditSelectionV1 {
    AdapterCorruptionAuditSelectionV1::try_new(
        fixture_grant_id(record),
        format!("operation:t097-{:02x}", record.identity_tag),
        exact_blob(record.identity_tag.wrapping_add(10)),
        include_receipt.then(|| exact_blob(record.identity_tag.wrapping_add(23))),
    )
    .expect("T097 production audit selection is bounded")
}

#[cfg(feature = "test-fault-injection")]
fn missing_fixture_ids_v1(tag: u8) -> AdapterCrossStoreIdsForTestV1 {
    AdapterCrossStoreIdsForTestV1::try_new(
        exact_blob(tag),
        format!("operation:t097-missing-{tag:02x}"),
        exact_blob(tag.wrapping_add(1)),
        None,
    )
    .expect("T097 missing selection identities are bounded")
}

#[cfg(feature = "test-fault-injection")]
fn open_adapter_connection_v1(root: &StrictAdapterRootV1) -> Connection {
    let connection = Connection::open(root.database()).expect("T097 adapter SQLite file opens");
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("T097 adapter raw connection enforces foreign keys");
    connection
}

#[cfg(feature = "test-fault-injection")]
fn existing_adapter_config_v1(root: &StrictAdapterRootV1) -> AdapterInboxStoreConfigV1 {
    AdapterInboxStoreConfigV1::try_new_existing_attested(root.path.clone(), root.identity, 25)
        .expect("T097 adapter root remains provisioner-attested")
}

#[cfg(feature = "test-fault-injection")]
fn lowercase_hex_v1(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing hexadecimal to String succeeds");
    }
    encoded
}

#[cfg(feature = "test-fault-injection")]
fn file_contains_v1(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(feature = "test-fault-injection")]
fn assert_custody_files_redacted_v1(root: &StrictAdapterRootV1, forbidden: &[&[u8]]) {
    for entry in fs::read_dir(&root.path).expect("T097 custody root is readable") {
        let path = entry.expect("T097 custody entry is readable").path();
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).expect("T097 custody file is readable");
        for needle in forbidden {
            assert!(
                !file_contains_v1(&bytes, needle),
                "T097 custody file {} disclosed redacted evidence",
                path.display()
            );
        }
    }
}

#[cfg(feature = "test-fault-injection")]
struct PersistedGlobalCustodyRowV1 {
    quarantine_id: Vec<u8>,
    evidence_digest: Vec<u8>,
    reason: String,
    generation: i64,
    grant_id: Option<Vec<u8>>,
    resolved_generation: Option<i64>,
}

#[cfg(feature = "test-fault-injection")]
fn assert_real_corruption_case_v1(
    label: &str,
    expected_reason: &str,
    trusted: &StrictAdapterRootV1,
    observed: &StrictAdapterRootV1,
    counterparts: (&CounterpartRootV1, &CounterpartRootV1),
    ids: &AdapterCrossStoreIdsForTestV1,
    lifecycle: AdapterLifecycleRelationshipForTestV1,
) {
    let (trusted_counterpart, observed_counterpart) = counterparts;
    let custody = StrictAdapterRootV1::new(&format!("{PATH_CANARY_V1}-{label}-custody"));
    let trusted_connection = open_adapter_connection_v1(trusted);
    let mut observed_connection = open_adapter_connection_v1(observed);
    let trusted_counterpart_connection = trusted_counterpart.open();
    let mut observed_counterpart_connection = observed_counterpart.open();
    let mut custody_connection = open_adapter_connection_v1(&custody);

    let first = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        ids,
        lifecycle,
    )
    .unwrap_or_else(|error| panic!("T097 real corruption {label} classifies: {error:?}"));
    let repeat = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        ids,
        lifecycle,
    )
    .expect("T097 exact retry reads original custody before close");
    let first_debug = format!("{first:?}");
    let repeat_debug = format!("{repeat:?}");
    let (first_reason, first_generation) = match &first {
        AdapterHistoryCustodyForTestV1::NoCorruptionObserved => {
            panic!("T097 {label} must not classify clean")
        }
        AdapterHistoryCustodyForTestV1::Quarantined(retained) => {
            (retained.reason_code(), retained.quarantine_generation())
        }
    };
    let (repeat_reason, repeat_generation) = match &repeat {
        AdapterHistoryCustodyForTestV1::NoCorruptionObserved => {
            panic!("T097 {label} retry must remain corrupt")
        }
        AdapterHistoryCustodyForTestV1::Quarantined(retained) => {
            (retained.reason_code(), retained.quarantine_generation())
        }
    };
    assert_eq!(
        first_reason, expected_reason,
        "T097 exact class for {label}"
    );
    assert_eq!(
        repeat_reason, expected_reason,
        "T097 retry class for {label}"
    );
    assert_eq!(
        repeat_generation, first_generation,
        "T097 retry is idempotent"
    );

    let persisted = custody_connection
        .query_row(
            "SELECT quarantine_id, evidence_digest, public_reason_code,
                    quarantine_generation, grant_id, resolved_generation
             FROM inbox_quarantines",
            [],
            |row| {
                Ok(PersistedGlobalCustodyRowV1 {
                    quarantine_id: row.get(0)?,
                    evidence_digest: row.get(1)?,
                    reason: row.get(2)?,
                    generation: row.get(3)?,
                    grant_id: row.get(4)?,
                    resolved_generation: row.get(5)?,
                })
            },
        )
        .expect("T097 exact custody row reads");
    let observed_persisted = observed_connection
        .query_row(
            "SELECT quarantine_id, evidence_digest, public_reason_code,
                    quarantine_generation, grant_id, resolved_generation
             FROM inbox_quarantines
             WHERE grant_id IS NULL",
            [],
            |row| {
                Ok(PersistedGlobalCustodyRowV1 {
                    quarantine_id: row.get(0)?,
                    evidence_digest: row.get(1)?,
                    reason: row.get(2)?,
                    generation: row.get(3)?,
                    grant_id: row.get(4)?,
                    resolved_generation: row.get(5)?,
                })
            },
        )
        .expect("T097 observed-branch fence row reads");
    assert_eq!(
        custody_connection
            .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| row
                .get::<_, i64>(0))
            .expect("T097 custody count reads"),
        1,
        "T097 retains one row for {label}"
    );
    assert_eq!(persisted.quarantine_id.len(), 32);
    assert_eq!(persisted.evidence_digest.len(), 32);
    assert_eq!(persisted.reason, expected_reason);
    assert_eq!(observed_persisted.quarantine_id, persisted.quarantine_id);
    assert_eq!(
        observed_persisted.evidence_digest,
        persisted.evidence_digest
    );
    assert_eq!(observed_persisted.reason, persisted.reason);
    assert_eq!(observed_persisted.grant_id, None);
    assert_eq!(observed_persisted.resolved_generation, None);
    assert_eq!(
        u64::try_from(persisted.generation).expect("positive generation"),
        first_generation
    );
    assert_eq!(
        persisted.grant_id, None,
        "T097 cross-store custody is global"
    );
    assert_eq!(
        persisted.resolved_generation, None,
        "T097 corruption custody remains active"
    );

    let evidence_hex = lowercase_hex_v1(&persisted.evidence_digest);
    let quarantine_hex = lowercase_hex_v1(&persisted.quarantine_id);
    let ids_debug = format!("{ids:?}");
    for rendered in [&first_debug, &repeat_debug, &ids_debug] {
        for forbidden in [
            std::str::from_utf8(WIRE_CANARY_V1).expect("wire canary is UTF-8"),
            std::str::from_utf8(&EVIDENCE_CANARY_V1).expect("evidence canary is UTF-8"),
            PATH_CANARY_V1,
            evidence_hex.as_str(),
            quarantine_hex.as_str(),
            "ReadyDispatchContextV1",
            "VerifiedDispatchAuthorityV1",
            "ExecutionPermit",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "T097 Debug leaked `{forbidden}`"
            );
        }
    }
    assert!(
        custody_connection
            .execute(
                "DELETE FROM inbox_quarantines WHERE quarantine_id = ?1",
                [persisted.quarantine_id.as_slice()],
            )
            .is_err(),
        "T097 custody denies delete for {label}"
    );
    assert!(
        custody_connection
            .execute(
                "UPDATE inbox_quarantines SET public_reason_code = 'MUTATED_REASON'
                 WHERE quarantine_id = ?1",
                [persisted.quarantine_id.as_slice()],
            )
            .is_err(),
        "T097 custody denies evidence mutation for {label}"
    );
    assert!(
        observed_connection
            .execute(
                "DELETE FROM inbox_quarantines WHERE quarantine_id = ?1",
                [observed_persisted.quarantine_id.as_slice()],
            )
            .is_err(),
        "T097 observed-branch fence denies delete for {label}"
    );
    assert!(
        observed_connection
            .execute(
                "UPDATE inbox_quarantines SET public_reason_code = 'MUTATED_REASON'
                 WHERE quarantine_id = ?1",
                [observed_persisted.quarantine_id.as_slice()],
            )
            .is_err(),
        "T097 observed-branch fence denies evidence mutation for {label}"
    );
    assert_eq!(
        custody_connection
            .execute(
                "UPDATE inbox_quarantines
                 SET resolved_generation = quarantine_generation + 1
                 WHERE quarantine_id = ?1",
                [persisted.quarantine_id.as_slice()],
            )
            .expect("T097 unresolved-to-resolved projection is the sole allowed update"),
        1,
        "T097 exact custody row resolves once for {label}"
    );
    assert_eq!(
        custody_connection
            .query_row(
                "SELECT resolved_generation FROM inbox_quarantines
                 WHERE quarantine_id = ?1",
                [persisted.quarantine_id.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .expect("T097 resolved generation reads"),
        persisted.generation + 1,
        "T097 resolution remains monotonic for {label}"
    );
    let evidence_hex_upper = evidence_hex.to_ascii_uppercase();
    let quarantine_hex_upper = quarantine_hex.to_ascii_uppercase();
    let forbidden_files = [
        WIRE_CANARY_V1,
        EVIDENCE_CANARY_V1.as_slice(),
        PATH_CANARY_V1.as_bytes(),
        evidence_hex.as_bytes(),
        evidence_hex_upper.as_bytes(),
        quarantine_hex.as_bytes(),
        quarantine_hex_upper.as_bytes(),
    ];
    assert_custody_files_redacted_v1(&custody, &forbidden_files);
    drop(custody_connection);
    drop(observed_counterpart_connection);
    drop(trusted_counterpart_connection);
    drop(observed_connection);
    drop(trusted_connection);
    assert_custody_files_redacted_v1(&custody, &forbidden_files);
    assert_eq!(
        custody.reopen().unwrap_err(),
        AdapterInboxStoreOpenErrorV1::InvariantFailed,
        "T097 separate global custody fences strict reopen for {label}"
    );
    let observed_reopen_error = observed.reopen().unwrap_err();
    let expected_observed_error = if label == "generation-reused" {
        AdapterInboxStoreOpenErrorV1::SchemaInvalid
    } else {
        AdapterInboxStoreOpenErrorV1::InvariantFailed
    };
    assert_eq!(
        observed_reopen_error, expected_observed_error,
        "T097 observed branch itself remains permanently fenced for {label}"
    );
}

#[cfg(feature = "test-fault-injection")]
fn assert_clean_relationship_v1(
    label: &str,
    trusted: &StrictAdapterRootV1,
    observed: &StrictAdapterRootV1,
    trusted_counterpart: &CounterpartRootV1,
    observed_counterpart: &CounterpartRootV1,
    ids: &AdapterCrossStoreIdsForTestV1,
    lifecycle: AdapterLifecycleRelationshipForTestV1,
) {
    let custody = StrictAdapterRootV1::new(&format!("clean-{label}-custody"));
    let trusted_connection = open_adapter_connection_v1(trusted);
    let mut observed_connection = open_adapter_connection_v1(observed);
    let trusted_counterpart_connection = trusted_counterpart.open();
    let mut observed_counterpart_connection = observed_counterpart.open();
    let mut custody_connection = open_adapter_connection_v1(&custody);
    let outcome = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        ids,
        lifecycle,
    )
    .expect("T097 clean real relationship classifies");
    assert!(
        matches!(
            outcome,
            AdapterHistoryCustodyForTestV1::NoCorruptionObserved
        ),
        "T097 clean {label} relationship must not be a false positive: {outcome:?}"
    );
    assert_eq!(
        custody_connection
            .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| row
                .get::<_, i64>(0))
            .expect("T097 clean custody count reads"),
        0,
        "T097 clean {label} retains no quarantine"
    );
    drop(custody_connection);
    drop(
        custody
            .reopen()
            .expect("T097 clean custody remains strict-openable"),
    );
}

#[cfg(feature = "test-fault-injection")]
fn assert_checkpoint_mismatch_v1(
    label: &str,
    trusted: &StrictAdapterRootV1,
    observed: &StrictAdapterRootV1,
    trusted_counterpart: &CounterpartRootV1,
    observed_counterpart: &CounterpartRootV1,
    selection: &AdapterCorruptionAuditSelectionV1,
    lifecycle: AdapterCorruptionAuditLifecycleV1,
) {
    let custody = StrictAdapterRootV1::new(&format!("checkpoint-{label}-custody"));
    let trusted_store = trusted
        .reopen()
        .expect("T097 checkpoint trusted store strict-opens");
    let trusted_counterpart_connection = trusted_counterpart.open();
    let mut observed_counterpart_connection = observed_counterpart.open();
    let mut pause = AdapterAuditPauseFixtureV1::stable();
    let error = audit_and_retain_adapter_projection_v1(
        &trusted_store,
        &mut pause,
        existing_adapter_config_v1(observed),
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        existing_adapter_config_v1(&custody),
        selection,
        lifecycle,
    )
    .expect_err("T097 distinct strict checkpoints are not a successful audit");
    assert_eq!(error.code(), "CHECKPOINT_MISMATCH");
    assert_eq!(pause.capture_count, 1);
    assert_eq!(pause.recheck_count, 2);
    let observed_connection = open_adapter_connection_v1(observed);
    let custody_connection = open_adapter_connection_v1(&custody);
    for (root_label, connection) in [
        ("observed", &observed_connection),
        ("custody", &custody_connection),
    ] {
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("T097 checkpoint quarantine count reads"),
            0,
            "T097 checkpoint mismatch must not fence or retain in {root_label}"
        );
    }
    drop(custody_connection);
    drop(observed_counterpart_connection);
    drop(trusted_counterpart_connection);
    drop(observed_connection);
    drop(trusted_store);
    drop(
        observed
            .reopen()
            .expect("T097 mismatched observed checkpoint remains strict-openable"),
    );
    drop(
        custody
            .reopen()
            .expect("T097 mismatch custody remains strict-openable"),
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn real_adapter_history_roots_and_physical_branches_are_strict_openable() {
    let received = StrictAdapterRootV1::new("t097-real-received");
    seed_adapter_history_v1(&received, &[AdapterFixtureRecordV1::received(0x11, 1)], 1);
    let received_branch = StrictAdapterRootV1::branch_from(&received, "t097-received-branch");
    drop(
        received_branch
            .reopen()
            .expect("T097 received copy is a real strict branch"),
    );

    let consumed = StrictAdapterRootV1::new("t097-real-consumed");
    seed_adapter_history_v1(&consumed, &[AdapterFixtureRecordV1::consumed(0x21)], 4);

    let quarantined = StrictAdapterRootV1::new("t097-real-quarantined");
    seed_adapter_history_v1(
        &quarantined,
        &[AdapterFixtureRecordV1::quarantined(0x31)],
        3,
    );

    let trusted_history = StrictAdapterRootV1::new("t097-real-two-record-history");
    let first = AdapterFixtureRecordV1::received(0x41, 1);
    let second = AdapterFixtureRecordV1::received(0x61, 2);
    seed_adapter_history_v1(&trusted_history, &[first, second], 2);
    let truncated_branch =
        StrictAdapterRootV1::branch_from(&trusted_history, "t097-truncated-branch");
    remove_received_record_preserving_schema_v1(&truncated_branch, fixture_grant_id(first));
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn real_filesystem_cross_store_corruption_matrix_retains_exact_global_custody() {
    use AdapterLifecycleRelationshipForTestV1::{AdapterReceived, Consumed, Prepared};

    {
        let record = AdapterFixtureRecordV1::received(0x11, 1).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("matrix-orphan-inbox-trusted", &[record], 1);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "matrix-orphan-inbox-observed");
        let trusted_peer = CounterpartRootV1::new(
            "matrix-orphan-inbox-peer-trusted",
            &[CounterpartFixtureRecordV1::matching(record, false)],
        );
        let observed_peer = CounterpartRootV1::new("matrix-orphan-inbox-peer-observed", &[]);
        assert_real_corruption_case_v1(
            "orphan-inbox",
            "ORPHAN_ADAPTER_INBOX",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(record, false),
            AdapterReceived,
        );
    }
    {
        let record = AdapterFixtureRecordV1::consumed(0x21).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("matrix-orphan-receipt-trusted", &[record], 4);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "matrix-orphan-receipt-observed");
        let trusted_peer = CounterpartRootV1::new(
            "matrix-orphan-receipt-peer-trusted",
            &[CounterpartFixtureRecordV1::matching(record, true)],
        );
        let observed_peer = CounterpartRootV1::new(
            "matrix-orphan-receipt-peer-observed",
            &[CounterpartFixtureRecordV1::matching(record, false)],
        );
        assert_real_corruption_case_v1(
            "orphan-receipt",
            "ORPHAN_ADAPTER_RECEIPT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(record, true),
            Consumed,
        );
    }
    {
        let record = AdapterFixtureRecordV1::received(0x31, 1).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("matrix-grant-conflict-trusted", &[record], 1);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "matrix-grant-conflict-observed");
        let trusted_peer = CounterpartRootV1::new(
            "matrix-grant-conflict-peer-trusted",
            &[CounterpartFixtureRecordV1::matching(record, false)],
        );
        let observed_peer = CounterpartRootV1::new(
            "matrix-grant-conflict-peer-observed",
            &[CounterpartFixtureRecordV1::matching(record, false).with_grant_digest_tag(0xd1)],
        );
        assert_real_corruption_case_v1(
            "grant-digest-conflict",
            "GRANT_DIGEST_CONFLICT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(record, false),
            AdapterReceived,
        );
    }
    {
        let record = AdapterFixtureRecordV1::consumed(0x41).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("matrix-receipt-conflict-trusted", &[record], 4);
        let observed =
            StrictAdapterRootV1::branch_from(&trusted, "matrix-receipt-conflict-observed");
        let trusted_peer = CounterpartRootV1::new(
            "matrix-receipt-conflict-peer-trusted",
            &[CounterpartFixtureRecordV1::matching(record, true)],
        );
        let observed_peer = CounterpartRootV1::new(
            "matrix-receipt-conflict-peer-observed",
            &[CounterpartFixtureRecordV1::matching(record, true).with_receipt_digest_tag(0xd2)],
        );
        assert_real_corruption_case_v1(
            "receipt-digest-conflict",
            "RECEIPT_DIGEST_CONFLICT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(record, true),
            Consumed,
        );
    }
    {
        let record = AdapterFixtureRecordV1::received(0x51, 1).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("matrix-cross-generation-trusted", &[record], 1);
        let observed =
            StrictAdapterRootV1::branch_from(&trusted, "matrix-cross-generation-observed");
        let trusted_peer = CounterpartRootV1::new(
            "matrix-cross-generation-peer-trusted",
            &[CounterpartFixtureRecordV1::matching(record, false)],
        );
        let observed_peer = CounterpartRootV1::new(
            "matrix-cross-generation-peer-observed",
            &[CounterpartFixtureRecordV1::matching(record, false).with_dispatch_attempt_tag(0xe1)],
        );
        assert_real_corruption_case_v1(
            "cross-generation",
            "CROSS_GENERATION_CONFLICT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(record, false),
            AdapterReceived,
        );
    }
    {
        let record = AdapterFixtureRecordV1::consumed(0x61).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("matrix-store-rollback-trusted", &[record], 4);
        let observed_record = AdapterFixtureRecordV1::received(0x61, 1)
            .with_grant_digest_tag(record.grant_digest_tag)
            .with_redaction_canaries();
        let observed =
            adapter_root_with_history_v1("matrix-store-rollback-observed", &[observed_record], 1);
        let trusted_peer = CounterpartRootV1::new("matrix-store-rollback-peer-trusted", &[]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "matrix-store-rollback-peer-observed");
        assert_real_corruption_case_v1(
            "store-rollback",
            "ADAPTER_STORE_ROLLBACK",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &missing_fixture_ids_v1(0xf1),
            Prepared,
        );
    }
    {
        let record = AdapterFixtureRecordV1::received(0x71, 1).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("matrix-root-rollback-trusted", &[record], 1);
        let observed = StrictAdapterRootV1::new_with_identity(
            "matrix-root-rollback-observed",
            AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0x42; 32]),
        );
        seed_adapter_history_v1(&observed, &[record], 1);
        let trusted_peer = CounterpartRootV1::new("matrix-root-rollback-peer-trusted", &[]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "matrix-root-rollback-peer-observed");
        assert_real_corruption_case_v1(
            "root-rollback",
            "ADAPTER_ROOT_ROLLBACK",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &missing_fixture_ids_v1(0xf2),
            Prepared,
        );
    }
    {
        let record = AdapterFixtureRecordV1::consumed(0x81).with_redaction_canaries();
        let trusted =
            adapter_root_with_history_v1("matrix-generation-rollback-trusted", &[record], 4);
        let observed_record = AdapterFixtureRecordV1::received(0x81, 1)
            .with_grant_digest_tag(record.grant_digest_tag)
            .with_redaction_canaries();
        let observed = adapter_root_with_history_v1(
            "matrix-generation-rollback-observed",
            &[observed_record],
            4,
        );
        let trusted_peer = CounterpartRootV1::new("matrix-generation-rollback-peer-trusted", &[]);
        let observed_peer = CounterpartRootV1::branch_from(
            &trusted_peer,
            "matrix-generation-rollback-peer-observed",
        );
        assert_real_corruption_case_v1(
            "generation-rollback",
            "ADAPTER_GENERATION_ROLLBACK",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &missing_fixture_ids_v1(0xf3),
            Prepared,
        );
    }
    {
        let first = AdapterFixtureRecordV1::received(0x91, 1).with_redaction_canaries();
        let second = AdapterFixtureRecordV1::received(0xb1, 2).with_redaction_canaries();
        let trusted =
            adapter_root_with_history_v1("matrix-history-truncated-trusted", &[first, second], 2);
        let observed =
            StrictAdapterRootV1::branch_from(&trusted, "matrix-history-truncated-observed");
        remove_received_record_preserving_schema_v1(&observed, fixture_grant_id(first));
        let trusted_peer = CounterpartRootV1::new("matrix-history-truncated-peer-trusted", &[]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "matrix-history-truncated-peer-observed");
        assert_real_corruption_case_v1(
            "history-truncated",
            "ADAPTER_HISTORY_TRUNCATED",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &missing_fixture_ids_v1(0xf4),
            Prepared,
        );
    }
    {
        let trusted_record = AdapterFixtureRecordV1::received(0xa1, 1).with_redaction_canaries();
        let trusted =
            adapter_root_with_history_v1("matrix-generation-reused-trusted", &[trusted_record], 1);
        let observed =
            StrictAdapterRootV1::branch_from(&trusted, "matrix-generation-reused-observed");
        inject_duplicate_adapter_generation_v1(&observed, 0xc1);
        let trusted_peer = CounterpartRootV1::new("matrix-generation-reused-peer-trusted", &[]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "matrix-generation-reused-peer-observed");
        assert_real_corruption_case_v1(
            "generation-reused",
            "ADAPTER_GENERATION_REUSED",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &missing_fixture_ids_v1(0xf5),
            Prepared,
        );
    }
    {
        let trusted = StrictAdapterRootV1::new("matrix-cross-store-trusted");
        let observed = StrictAdapterRootV1::branch_from(&trusted, "matrix-cross-store-observed");
        let trusted_peer = CounterpartRootV1::new("matrix-cross-store-peer-trusted", &[]);
        // A coordinator-only grant is a valid PREPARED -> DISPATCHING checkpoint advance and
        // must not be quarantined. A coordinator receipt without the corresponding adapter
        // receipt is impossible in every valid lifecycle and remains a real disagreement.
        let extra =
            CounterpartFixtureRecordV1::matching(AdapterFixtureRecordV1::consumed(0xd1), true);
        let observed_peer = CounterpartRootV1::new("matrix-cross-store-peer-observed", &[extra]);
        assert_real_corruption_case_v1(
            "cross-store-disagreement",
            "CROSS_STORE_DISAGREEMENT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &missing_fixture_ids_v1(0xf6),
            Prepared,
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn exhaustive_inventories_classify_late_grants_receipts_and_real_generation_mutation() {
    use AdapterLifecycleRelationshipForTestV1::{AdapterReceived, Consumed};

    {
        let anchor = AdapterFixtureRecordV1::received(0x12, 1);
        let late = AdapterFixtureRecordV1::received(0x32, 2);
        let trusted = adapter_root_with_history_v1("late-orphan-trusted", &[anchor], 1);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "late-orphan-observed");
        seed_adapter_history_v1(&observed, &[late], 2);
        let trusted_peer = CounterpartRootV1::new(
            "late-orphan-peer-trusted",
            &[CounterpartFixtureRecordV1::matching(anchor, false)],
        );
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "late-orphan-peer-observed");
        assert_real_corruption_case_v1(
            "late-orphan-inventory",
            "ORPHAN_ADAPTER_INBOX",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(anchor, false),
            AdapterReceived,
        );
    }

    {
        let anchor = AdapterFixtureRecordV1::received(0x13, 1);
        let late = AdapterFixtureRecordV1::received(0x33, 2);
        let trusted = adapter_root_with_history_v1("late-digest-trusted", &[anchor], 1);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "late-digest-observed");
        seed_adapter_history_v1(&observed, &[late], 2);
        let trusted_peer = CounterpartRootV1::new(
            "late-digest-peer-trusted",
            &[CounterpartFixtureRecordV1::matching(anchor, false)],
        );
        let observed_peer = CounterpartRootV1::new(
            "late-digest-peer-observed",
            &[
                CounterpartFixtureRecordV1::matching(anchor, false),
                CounterpartFixtureRecordV1::matching(late, false).with_grant_digest_tag(0xe3),
            ],
        );
        assert_real_corruption_case_v1(
            "late-grant-digest-inventory",
            "GRANT_DIGEST_CONFLICT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(anchor, false),
            AdapterReceived,
        );
    }

    {
        let anchor = AdapterFixtureRecordV1::consumed_at(0x14, 1, 2, 3, 4);
        let late = AdapterFixtureRecordV1::consumed_at(0x34, 5, 6, 7, 8);
        let trusted = adapter_root_with_history_v1("late-receipt-trusted", &[anchor, late], 8);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "late-receipt-observed");
        let trusted_peer = CounterpartRootV1::new(
            "late-receipt-peer-trusted",
            &[
                CounterpartFixtureRecordV1::matching(anchor, true),
                CounterpartFixtureRecordV1::matching(late, true),
            ],
        );
        let observed_peer = CounterpartRootV1::new(
            "late-receipt-peer-observed",
            &[
                CounterpartFixtureRecordV1::matching(anchor, true),
                CounterpartFixtureRecordV1::matching(late, true).with_receipt_digest_tag(0xe4),
            ],
        );
        assert_real_corruption_case_v1(
            "late-receipt-digest-inventory",
            "RECEIPT_DIGEST_CONFLICT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(anchor, true),
            Consumed,
        );
    }

    {
        let anchor = AdapterFixtureRecordV1::received(0x15, 1);
        let late = AdapterFixtureRecordV1::received(0x35, 2);
        let trusted = adapter_root_with_history_v1("late-generation-trusted", &[anchor, late], 2);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "late-generation-observed");
        let trusted_peer = CounterpartRootV1::new(
            "late-generation-peer-trusted",
            &[
                CounterpartFixtureRecordV1::matching(anchor, false),
                CounterpartFixtureRecordV1::matching(late, false),
            ],
        );
        let observed_peer = CounterpartRootV1::new(
            "late-generation-peer-observed",
            &[
                CounterpartFixtureRecordV1::matching(anchor, false),
                CounterpartFixtureRecordV1::matching(late, false).with_created_generation(9),
            ],
        );
        assert_real_corruption_case_v1(
            "late-real-generation-inventory",
            "CROSS_GENERATION_CONFLICT",
            &trusted,
            &observed,
            (&trusted_peer, &observed_peer),
            &fixture_ids_v1(anchor, false),
            AdapterReceived,
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn external_custody_failure_leaves_local_fence_and_exact_retry_copies_same_incident() {
    let record = AdapterFixtureRecordV1::received(0x46, 1);
    let trusted = adapter_root_with_history_v1("custody-fail-trusted", &[record], 1);
    let observed = StrictAdapterRootV1::branch_from(&trusted, "custody-fail-observed");
    let trusted_peer = CounterpartRootV1::new(
        "custody-fail-peer-trusted",
        &[CounterpartFixtureRecordV1::matching(record, false)],
    );
    let observed_peer = CounterpartRootV1::new("custody-fail-peer-observed", &[]);
    let custody = StrictAdapterRootV1::new("custody-fail-external");

    let trusted_connection = open_adapter_connection_v1(&trusted);
    let mut observed_connection = open_adapter_connection_v1(&observed);
    let trusted_counterpart_connection = trusted_peer.open();
    let mut observed_counterpart_connection = observed_peer.open();
    let mut custody_connection = open_adapter_connection_v1(&custody);
    custody_connection
        .busy_timeout(std::time::Duration::ZERO)
        .expect("T097 custody scanner never waits behind the fault lock");
    let custody_blocker = open_adapter_connection_v1(&custody);
    custody_blocker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("T097 independent custody writer fault begins");

    let ids = fixture_ids_v1(record, false);
    let first_error = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        &ids,
        AdapterLifecycleRelationshipForTestV1::AdapterReceived,
    )
    .expect_err("T097 external custody writer fault interrupts only the mirror");
    assert_eq!(first_error.code(), "BUSY");
    assert_eq!(
        custody_connection
            .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| row
                .get::<_, i64>(0))
            .expect("T097 failed custody mirror remains readable"),
        0
    );
    let local_incident: (Vec<u8>, Vec<u8>, String, i64) = observed_connection
        .query_row(
            "SELECT quarantine_id, evidence_digest, public_reason_code, quarantine_generation
             FROM inbox_quarantines WHERE grant_id IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("T097 local source fence committed before external custody failed");
    assert_eq!(local_incident.2, "ORPHAN_ADAPTER_INBOX");

    custody_blocker
        .execute_batch("ROLLBACK")
        .expect("T097 independent custody writer fault releases");
    drop(custody_blocker);
    drop(custody_connection);
    drop(observed_counterpart_connection);
    drop(trusted_counterpart_connection);
    drop(observed_connection);
    drop(trusted_connection);

    let trusted_connection = open_adapter_connection_v1(&trusted);
    let mut observed_connection = open_adapter_connection_v1(&observed);
    let trusted_counterpart_connection = trusted_peer.open();
    let mut observed_counterpart_connection = observed_peer.open();
    let mut custody_connection = open_adapter_connection_v1(&custody);
    let retry = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        &ids,
        AdapterLifecycleRelationshipForTestV1::AdapterReceived,
    )
    .expect("T097 retry copies the already-retained local incident");
    let AdapterHistoryCustodyForTestV1::Quarantined(retry) = retry else {
        panic!("T097 retry must remain quarantined");
    };
    assert_eq!(retry.reason_code(), "ORPHAN_ADAPTER_INBOX");
    let custody_incident: (Vec<u8>, Vec<u8>, String, i64) = custody_connection
        .query_row(
            "SELECT quarantine_id, evidence_digest, public_reason_code, quarantine_generation
             FROM inbox_quarantines WHERE grant_id IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("T097 retry retains exact external custody");
    assert_eq!(custody_incident.0, local_incident.0);
    assert_eq!(custody_incident.1, local_incident.1);
    assert_eq!(custody_incident.2, local_incident.2);
    assert_eq!(
        retry.quarantine_generation(),
        u64::try_from(custody_incident.3).expect("T097 custody generation is safe")
    );

    let retry_generation = retry.quarantine_generation();
    drop(custody_connection);
    drop(observed_counterpart_connection);
    drop(trusted_counterpart_connection);
    drop(observed_connection);
    drop(trusted_connection);
    assert_eq!(
        custody.reopen().unwrap_err(),
        AdapterInboxStoreOpenErrorV1::InvariantFailed,
        "T097 successful external custody correctly denies ordinary restart open"
    );

    let trusted_connection = open_adapter_connection_v1(&trusted);
    let mut observed_connection = open_adapter_connection_v1(&observed);
    let trusted_counterpart_connection = trusted_peer.open();
    let mut observed_counterpart_connection = observed_peer.open();
    let mut custody_connection = open_adapter_connection_v1(&custody);
    let exact_retry = classify_and_retain_adapter_connections_for_test_v1(
        &trusted_connection,
        &mut observed_connection,
        &trusted_counterpart_connection,
        &mut observed_counterpart_connection,
        &mut custody_connection,
        &ids,
        AdapterLifecycleRelationshipForTestV1::AdapterReceived,
    )
    .expect("T097 repeated retry reuses exact external custody");
    let AdapterHistoryCustodyForTestV1::Quarantined(exact_retry) = exact_retry else {
        panic!("T097 repeated retry must remain quarantined");
    };
    assert_eq!(exact_retry.quarantine_generation(), retry_generation);
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn default_compiled_config_bound_audit_reopens_fenced_custody_idempotently() {
    let record = AdapterFixtureRecordV1::received(0x47, 1);
    let trusted = adapter_root_with_history_v1("default-audit-trusted", &[record], 1);
    let observed = StrictAdapterRootV1::branch_from(&trusted, "default-audit-observed");
    let trusted_peer = CounterpartRootV1::new(
        "default-audit-peer-trusted",
        &[CounterpartFixtureRecordV1::matching(record, false)],
    );
    let observed_peer = CounterpartRootV1::new("default-audit-peer-observed", &[]);
    let custody = StrictAdapterRootV1::new("default-audit-custody");
    let trusted_store = trusted
        .reopen()
        .expect("T097 trusted adapter store strict-opens once");
    let selection = AdapterCorruptionAuditSelectionV1::try_new(
        fixture_grant_id(record),
        format!("operation:t097-{:02x}", record.identity_tag),
        exact_blob(record.identity_tag.wrapping_add(10)),
        None,
    )
    .expect("T097 production audit selection is bounded");
    let mut pause = AdapterAuditPauseFixtureV1::stable();

    let trusted_counterpart = trusted_peer.open();
    let mut observed_counterpart = observed_peer.open();
    let first = audit_and_retain_adapter_projection_v1(
        &trusted_store,
        &mut pause,
        existing_adapter_config_v1(&observed),
        &trusted_counterpart,
        &mut observed_counterpart,
        existing_adapter_config_v1(&custody),
        &selection,
        AdapterCorruptionAuditLifecycleV1::AdapterReceived,
    )
    .expect("T097 default config-bound audit fences and retains");
    let AdapterCorruptionAuditOutcomeV1::Quarantined(first) = first else {
        panic!("T097 default audit must retain corruption");
    };
    assert_eq!(first.reason_code(), "ORPHAN_ADAPTER_INBOX");
    let generation = first.quarantine_generation();
    drop(observed_counterpart);
    drop(trusted_counterpart);

    assert_eq!(
        custody.reopen().unwrap_err(),
        AdapterInboxStoreOpenErrorV1::InvariantFailed,
        "T097 ordinary custody open remains fail-closed"
    );
    let trusted_counterpart = trusted_peer.open();
    let mut observed_counterpart = observed_peer.open();
    let retry = audit_and_retain_adapter_projection_v1(
        &trusted_store,
        &mut pause,
        existing_adapter_config_v1(&observed),
        &trusted_counterpart,
        &mut observed_counterpart,
        existing_adapter_config_v1(&custody),
        &selection,
        AdapterCorruptionAuditLifecycleV1::AdapterReceived,
    )
    .expect("T097 default config-bound restart reads exact fenced custody");
    let AdapterCorruptionAuditOutcomeV1::Quarantined(retry) = retry else {
        panic!("T097 default audit retry must remain retained");
    };
    assert_eq!(retry.reason_code(), "ORPHAN_ADAPTER_INBOX");
    assert_eq!(retry.quarantine_generation(), generation);
    assert_eq!(pause.capture_count, 2);
    assert_eq!(pause.recheck_count, 4);
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn default_compiled_audit_refuses_success_when_final_pause_recheck_fails() {
    let record = AdapterFixtureRecordV1::received(0x57, 1);
    let trusted = adapter_root_with_history_v1("pause-recheck-trusted", &[record], 1);
    let observed = StrictAdapterRootV1::branch_from(&trusted, "pause-recheck-observed");
    let trusted_peer = CounterpartRootV1::new(
        "pause-recheck-peer-trusted",
        &[CounterpartFixtureRecordV1::matching(record, false)],
    );
    let observed_peer =
        CounterpartRootV1::branch_from(&trusted_peer, "pause-recheck-peer-observed");
    let custody = StrictAdapterRootV1::new("pause-recheck-custody");
    let trusted_store = trusted
        .reopen()
        .expect("T097 PAUSE trusted adapter store strict-opens");
    let selection = AdapterCorruptionAuditSelectionV1::try_new(
        fixture_grant_id(record),
        format!("operation:t097-{:02x}", record.identity_tag),
        exact_blob(record.identity_tag.wrapping_add(10)),
        None,
    )
    .expect("T097 PAUSE selection is bounded");
    let mut pause = AdapterAuditPauseFixtureV1::failing_on_recheck(Some(2));
    let trusted_counterpart = trusted_peer.open();
    let mut observed_counterpart = observed_peer.open();

    let error = audit_and_retain_adapter_projection_v1(
        &trusted_store,
        &mut pause,
        existing_adapter_config_v1(&observed),
        &trusted_counterpart,
        &mut observed_counterpart,
        existing_adapter_config_v1(&custody),
        &selection,
        AdapterCorruptionAuditLifecycleV1::AdapterReceived,
    )
    .expect_err("T097 failed final PAUSE recheck cannot report clean success");
    assert_eq!(error, AdapterCorruptionAuditErrorV1::Unavailable);
    assert_eq!(pause.capture_count, 1);
    assert_eq!(pause.recheck_count, 2);

    for (label, root) in [("observed", &observed), ("custody", &custody)] {
        let connection = open_adapter_connection_v1(root);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("T097 PAUSE quarantine count reads"),
            0,
            "T097 PAUSE failure must not synthesize a fence in {label}"
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn real_scanner_refuses_custody_aliases_before_mutating_any_adapter_root() {
    let record = AdapterFixtureRecordV1::received(0xd1, 1);
    let trusted = adapter_root_with_history_v1("alias-trusted", &[record], 1);
    let observed = StrictAdapterRootV1::branch_from(&trusted, "alias-observed");
    let trusted_peer = CounterpartRootV1::new(
        "alias-peer-trusted",
        &[CounterpartFixtureRecordV1::matching(record, false)],
    );
    let observed_peer = CounterpartRootV1::new("alias-peer-observed", &[]);
    let ids = fixture_ids_v1(record, false);

    for alias in ["trusted", "observed"] {
        let trusted_connection = open_adapter_connection_v1(&trusted);
        let mut observed_connection = open_adapter_connection_v1(&observed);
        let trusted_counterpart_connection = trusted_peer.open();
        let mut observed_counterpart_connection = observed_peer.open();
        let mut aliased_custody = if alias == "trusted" {
            open_adapter_connection_v1(&trusted)
        } else {
            open_adapter_connection_v1(&observed)
        };
        let before = [
            trusted_connection
                .query_row(
                    "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("T097 trusted generation reads"),
            observed_connection
                .query_row(
                    "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("T097 observed generation reads"),
        ];

        assert_eq!(
            classify_and_retain_adapter_connections_for_test_v1(
                &trusted_connection,
                &mut observed_connection,
                &trusted_counterpart_connection,
                &mut observed_counterpart_connection,
                &mut aliased_custody,
                &ids,
                AdapterLifecycleRelationshipForTestV1::AdapterReceived,
            )
            .unwrap_err()
            .code(),
            "INVARIANT_FAILED",
            "T097 custody alias with {alias} must fail closed"
        );
        assert_eq!(
            trusted_connection
                .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| row
                    .get::<_, i64>(0))
                .expect("T097 trusted quarantine count reads"),
            0,
            "T097 alias rejection must not mutate trusted"
        );
        assert_eq!(
            observed_connection
                .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| row
                    .get::<_, i64>(0))
                .expect("T097 observed quarantine count reads"),
            0,
            "T097 alias rejection must not mutate observed"
        );
        assert_eq!(
            [
                trusted_connection
                    .query_row(
                        "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("T097 trusted generation rereads"),
                observed_connection
                    .query_row(
                        "SELECT store_generation FROM adapter_store_meta WHERE singleton = 1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("T097 observed generation rereads"),
            ],
            before,
            "T097 alias rejection leaves both generations unchanged"
        );
    }

    static HARDLINK_NEXT: AtomicU64 = AtomicU64::new(0);
    let hardlink_path = std::env::temp_dir().join(format!(
        "helixos-t097-custody-hardlink-{}-{}.sqlite3",
        std::process::id(),
        HARDLINK_NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::hard_link(observed.database(), &hardlink_path)
        .expect("T097 filesystem supports a database hardlink alias fixture");
    let trusted_connection = open_adapter_connection_v1(&trusted);
    let mut observed_connection = open_adapter_connection_v1(&observed);
    let trusted_counterpart_connection = trusted_peer.open();
    let mut observed_counterpart_connection = observed_peer.open();
    let mut hardlinked_custody =
        Connection::open(&hardlink_path).expect("T097 hardlinked custody alias opens");
    assert_eq!(
        classify_and_retain_adapter_connections_for_test_v1(
            &trusted_connection,
            &mut observed_connection,
            &trusted_counterpart_connection,
            &mut observed_counterpart_connection,
            &mut hardlinked_custody,
            &ids,
            AdapterLifecycleRelationshipForTestV1::AdapterReceived,
        )
        .unwrap_err()
        .code(),
        "INVARIANT_FAILED",
        "T097 custody hardlink alias must fail closed by filesystem identity"
    );
    assert_eq!(
        observed_connection
            .query_row("SELECT COUNT(*) FROM inbox_quarantines", [], |row| row
                .get::<_, i64>(0))
            .expect("T097 observed quarantine count reads after hardlink rejection"),
        0,
        "T097 hardlink rejection must precede observed mutation"
    );
    drop(hardlinked_custody);
    fs::remove_file(&hardlink_path).expect("T097 hardlink fixture removes");

    drop(
        trusted
            .reopen()
            .expect("T097 alias rejection leaves trusted strict-openable"),
    );
    drop(
        observed
            .reopen()
            .expect("T097 alias rejection leaves observed strict-openable"),
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn real_t096_lifecycle_relationships_are_clean_negative_controls() {
    use AdapterLifecycleRelationshipForTestV1::{
        AdapterReceived, Ambiguous, Consumed, Dispatching, Prepared,
    };

    {
        let trusted = StrictAdapterRootV1::new("clean-prepared-trusted");
        let observed = StrictAdapterRootV1::branch_from(&trusted, "clean-prepared-observed");
        let trusted_peer = CounterpartRootV1::new("clean-prepared-peer-trusted", &[]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "clean-prepared-peer-observed");
        assert_clean_relationship_v1(
            "prepared",
            &trusted,
            &observed,
            &trusted_peer,
            &observed_peer,
            &missing_fixture_ids_v1(0xe1),
            Prepared,
        );
    }
    for (label, lifecycle, identity_tag) in [
        ("dispatching", Dispatching, 0x21_u8),
        ("ambiguous", Ambiguous, 0x31_u8),
    ] {
        let record = AdapterFixtureRecordV1::received(identity_tag, 1);
        let trusted = StrictAdapterRootV1::new(&format!("clean-{label}-trusted"));
        let observed =
            StrictAdapterRootV1::branch_from(&trusted, &format!("clean-{label}-observed"));
        let peer_record = CounterpartFixtureRecordV1::matching(record, false);
        let trusted_peer =
            CounterpartRootV1::new(&format!("clean-{label}-peer-trusted"), &[peer_record]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, &format!("clean-{label}-peer-observed"));
        assert_clean_relationship_v1(
            label,
            &trusted,
            &observed,
            &trusted_peer,
            &observed_peer,
            &fixture_ids_v1(record, false),
            lifecycle,
        );
    }
    {
        let record = AdapterFixtureRecordV1::received(0x41, 1).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("clean-received-trusted", &[record], 1);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "clean-received-observed");
        let peer_record = CounterpartFixtureRecordV1::matching(record, false);
        let trusted_peer = CounterpartRootV1::new("clean-received-peer-trusted", &[peer_record]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "clean-received-peer-observed");
        assert_clean_relationship_v1(
            "adapter-received",
            &trusted,
            &observed,
            &trusted_peer,
            &observed_peer,
            &fixture_ids_v1(record, false),
            AdapterReceived,
        );
    }
    {
        let record = AdapterFixtureRecordV1::consumed(0x51).with_redaction_canaries();
        let trusted = adapter_root_with_history_v1("clean-consumed-trusted", &[record], 4);
        let observed = StrictAdapterRootV1::branch_from(&trusted, "clean-consumed-observed");
        let peer_record = CounterpartFixtureRecordV1::matching(record, true);
        let trusted_peer = CounterpartRootV1::new("clean-consumed-peer-trusted", &[peer_record]);
        let observed_peer =
            CounterpartRootV1::branch_from(&trusted_peer, "clean-consumed-peer-observed");
        assert_clean_relationship_v1(
            "consumed",
            &trusted,
            &observed,
            &trusted_peer,
            &observed_peer,
            &fixture_ids_v1(record, true),
            Consumed,
        );
    }
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn strict_append_whose_key_sorts_before_retained_checkpoint_is_mismatch() {
    let trusted_record = AdapterFixtureRecordV1::received(0xc1, 1);
    let appended_record = AdapterFixtureRecordV1::received(0x11, 2);
    let trusted =
        adapter_root_with_history_v1("exact-checkpoint-append-trusted", &[trusted_record], 1);
    let observed = StrictAdapterRootV1::branch_from(&trusted, "exact-checkpoint-append-observed");
    seed_adapter_history_v1(&observed, &[appended_record], 2);
    let trusted_peer = CounterpartRootV1::new(
        "exact-checkpoint-append-peer-trusted",
        &[CounterpartFixtureRecordV1::matching(trusted_record, false)],
    );
    let observed_peer = CounterpartRootV1::new(
        "exact-checkpoint-append-peer-observed",
        &[
            CounterpartFixtureRecordV1::matching(trusted_record, false),
            CounterpartFixtureRecordV1::matching(appended_record, false),
        ],
    );
    assert_checkpoint_mismatch_v1(
        "append-before-retained-checkpoint",
        &trusted,
        &observed,
        &trusted_peer,
        &observed_peer,
        &audit_selection_v1(trusted_record, false),
        AdapterCorruptionAuditLifecycleV1::AdapterReceived,
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn strict_lifecycle_advance_is_checkpoint_mismatch_without_fence() {
    let advanced_record = AdapterFixtureRecordV1::received(0xa7, 1);
    let trusted = StrictAdapterRootV1::new("lifecycle-checkpoint-trusted");
    let observed = StrictAdapterRootV1::branch_from(&trusted, "lifecycle-checkpoint-observed");
    let trusted_peer = CounterpartRootV1::new("lifecycle-checkpoint-peer-trusted", &[]);
    let observed_peer = CounterpartRootV1::new(
        "lifecycle-checkpoint-peer-observed",
        &[CounterpartFixtureRecordV1::matching(advanced_record, false)],
    );
    assert_checkpoint_mismatch_v1(
        "prepared-to-dispatching-advance",
        &trusted,
        &observed,
        &trusted_peer,
        &observed_peer,
        &audit_selection_v1(advanced_record, false),
        AdapterCorruptionAuditLifecycleV1::Prepared,
    );
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn strict_legitimate_mutable_advance_is_checkpoint_mismatch_without_fence() {
    let trusted_record = AdapterFixtureRecordV1::received(0xb1, 1);
    let observed_record = AdapterFixtureRecordV1::consumed_at(0xb1, 1, 2, 3, 4);
    let trusted = adapter_root_with_history_v1("mutable-checkpoint-trusted", &[trusted_record], 1);
    let observed =
        adapter_root_with_history_v1("mutable-checkpoint-observed", &[observed_record], 4);
    let trusted_peer = CounterpartRootV1::new(
        "mutable-checkpoint-peer-trusted",
        &[CounterpartFixtureRecordV1::matching(trusted_record, false)],
    );
    let observed_peer = CounterpartRootV1::new(
        "mutable-checkpoint-peer-observed",
        &[CounterpartFixtureRecordV1::matching(observed_record, true)],
    );
    assert_checkpoint_mismatch_v1(
        "legitimate-mutable-advance",
        &trusted,
        &observed,
        &trusted_peer,
        &observed_peer,
        &audit_selection_v1(trusted_record, false),
        AdapterCorruptionAuditLifecycleV1::AdapterReceived,
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterCorruptionSeedV1 {
    OrphanAdapterInbox,
    OrphanAdapterReceipt,
    GrantDigestConflict,
    ReceiptDigestConflict,
    CrossGenerationConflict,
    StoreRollback,
    RootRollback,
    GenerationRollback,
    HistoryTruncation,
    GenerationReuse,
    CrossStoreDisagreement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CustodyOracleV1 {
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionOracleV1 {
    Refused,
}

fn adapter_oracle(
    seed: AdapterCorruptionSeedV1,
) -> (&'static str, CustodyOracleV1, ExecutionOracleV1) {
    use AdapterCorruptionSeedV1::*;
    let reason = match seed {
        OrphanAdapterInbox => "ORPHAN_ADAPTER_INBOX",
        OrphanAdapterReceipt => "ORPHAN_ADAPTER_RECEIPT",
        GrantDigestConflict => "GRANT_DIGEST_CONFLICT",
        ReceiptDigestConflict => "RECEIPT_DIGEST_CONFLICT",
        CrossGenerationConflict => "CROSS_GENERATION_CONFLICT",
        StoreRollback => "ADAPTER_STORE_ROLLBACK",
        RootRollback => "ADAPTER_ROOT_ROLLBACK",
        GenerationRollback => "ADAPTER_GENERATION_ROLLBACK",
        HistoryTruncation => "ADAPTER_HISTORY_TRUNCATED",
        GenerationReuse => "ADAPTER_GENERATION_REUSED",
        CrossStoreDisagreement => "CROSS_STORE_DISAGREEMENT",
    };
    (
        reason,
        CustodyOracleV1::Quarantined,
        ExecutionOracleV1::Refused,
    )
}

#[test]
fn strict_adapter_open_returns_no_store_for_structural_orphan_inbox_or_receipt() {
    let inbox = StrictAdapterRootV1::new("orphan-inbox");
    inject_orphan_adapter_inbox(&inbox.database());
    assert_eq!(
        inbox.reopen().unwrap_err(),
        AdapterInboxStoreOpenErrorV1::InvariantFailed,
        "a structurally orphan adapter inbox must fail before any store handle exists"
    );

    let receipt = StrictAdapterRootV1::new("orphan-receipt");
    inject_orphan_adapter_receipt(&receipt.database());
    assert_eq!(
        receipt.reopen().unwrap_err(),
        AdapterInboxStoreOpenErrorV1::InvariantFailed,
        "a structurally orphan adapter receipt must fail before any store handle exists"
    );
}

#[test]
fn adapter_corruption_oracles_are_closed_quarantine_plus_refusal() {
    use AdapterCorruptionSeedV1::*;
    let seeds = [
        OrphanAdapterInbox,
        OrphanAdapterReceipt,
        GrantDigestConflict,
        ReceiptDigestConflict,
        CrossGenerationConflict,
        StoreRollback,
        RootRollback,
        GenerationRollback,
        HistoryTruncation,
        GenerationReuse,
        CrossStoreDisagreement,
    ];
    let expected_reasons = [
        "ORPHAN_ADAPTER_INBOX",
        "ORPHAN_ADAPTER_RECEIPT",
        "GRANT_DIGEST_CONFLICT",
        "RECEIPT_DIGEST_CONFLICT",
        "CROSS_GENERATION_CONFLICT",
        "ADAPTER_STORE_ROLLBACK",
        "ADAPTER_ROOT_ROLLBACK",
        "ADAPTER_GENERATION_ROLLBACK",
        "ADAPTER_HISTORY_TRUNCATED",
        "ADAPTER_GENERATION_REUSED",
        "CROSS_STORE_DISAGREEMENT",
    ];
    for (seed, expected_reason) in seeds.into_iter().zip(expected_reasons) {
        assert_eq!(
            adapter_oracle(seed),
            (
                expected_reason,
                CustodyOracleV1::Quarantined,
                ExecutionOracleV1::Refused,
            ),
            "T073 corruption oracles must never contain an activation outcome"
        );
    }
}

#[test]
fn production_adapter_cross_store_verifier_must_be_non_authoritative() {
    let quarantine = required_production_source(
        "quarantine.rs",
        "T097 adapter cross-store verifier and quarantine custody",
    );
    for required in [
        "AdapterCrossStoreCorruptionV1",
        "AdapterCorruptionDispositionV1",
        "verify_adapter_cross_store_history_v1",
        "retain_adapter_corruption_quarantine_v1",
        "Quarantined",
        "Refused",
        "ORPHAN_ADAPTER_INBOX",
        "ORPHAN_ADAPTER_RECEIPT",
        "GRANT_DIGEST_CONFLICT",
        "RECEIPT_DIGEST_CONFLICT",
        "CROSS_GENERATION_CONFLICT",
        "ADAPTER_STORE_ROLLBACK",
        "ADAPTER_ROOT_ROLLBACK",
        "ADAPTER_GENERATION_ROLLBACK",
        "ADAPTER_HISTORY_TRUNCATED",
        "ADAPTER_GENERATION_REUSED",
        "CROSS_STORE_DISAGREEMENT",
    ] {
        assert!(
            quarantine.contains(required),
            "T073 RED: adapter corruption custody omits `{required}`"
        );
    }
    for forbidden in [
        "ReadyDispatchContextV1",
        "VerifiedDispatchAuthorityV1",
        "DispatchGrantPermitV1",
        "ExecutionPermit",
        "activate_v1",
        "redeliver_v1",
    ] {
        assert!(
            !quarantine.contains(forbidden),
            "T073: corruption/quarantine code must not expose activation authority `{forbidden}`"
        );
    }
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T073 RED: missing production extension {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut cursor = 0_usize;
    let mut block_depth = 0_u64;
    while cursor < bytes.len() {
        if block_depth > 0 {
            if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                block_depth += 1;
                cursor += 2;
            } else if bytes.get(cursor..cursor + 2) == Some(b"*/") {
                block_depth -= 1;
                cursor += 2;
            } else {
                if bytes[cursor] == b'\n' {
                    output.push('\n');
                }
                cursor += 1;
            }
        } else if bytes.get(cursor..cursor + 2) == Some(b"//") {
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
        } else if bytes.get(cursor..cursor + 2) == Some(b"/*") {
            block_depth = 1;
            cursor += 2;
        } else {
            output.push(char::from(bytes[cursor]));
            cursor += 1;
        }
    }
    assert_eq!(block_depth, 0, "T073 production comments are balanced");
    output
}
