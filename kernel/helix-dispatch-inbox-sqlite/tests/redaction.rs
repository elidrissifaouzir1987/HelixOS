//! Seeded redaction checks for the independent adapter inbox.
//!
//! These tests deliberately put restricted canaries in the authoritative adapter
//! schema, then exercise only the reviewed public event/metric columns. This proves
//! that an observability projection does not need to copy authority-bearing rows.

use helix_dispatch_contracts::{Generation, Identifier, SafeU64, MAX_SAFE_U64};
use helix_dispatch_inbox_sqlite::{
    AdapterClockObservationV1, AdapterInboxInitializationV1, AdapterInboxRootIdentityEvidenceV1,
    AdapterInboxStoreConfigErrorV1, AdapterInboxStoreConfigV1, AdapterInboxStoreOpenErrorV1,
    AdapterTimeSampleV1, EpochObservationV1, SupervisorEpochObservationV1,
};
use rusqlite::{params, Connection};
use std::error::Error;
use std::fmt::{Debug, Display};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ADAPTER_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/adapter-inbox-schema-v1.sql");

const CANARY_SEED: u64 = 0x5eed_d15c_a7c4_0054;
const PRIVATE_PATH: &str = "/Users/private-operator/adapter-authority.sqlite";
const PRIVATE_OPERATION: &str = "operation-private-canary";
const PRIVATE_TASK: &str = "task-private-canary";
const PRIVATE_WORKLOAD: &str = "workload-private-canary";
const PRIVATE_ADAPTER: &str = "adapter-private-canary";
const PRIVATE_TRACE: &str = "trace-private-canary";
const PRIVATE_BOOT: &str = "boot-private-canary";
const PRIVATE_KEY_ID: &str = "adapter-key-private-canary";
const PRIVATE_PROVIDER_TEXT: &str = "sqlite-provider-private-diagnostic";
const PRIVATE_CANONICAL_GRANT: &[u8] =
    b"canonical-grant-private-canary:/Users/private-operator/grant.json";
const PRIVATE_CANONICAL_RECEIPT: &[u8] =
    b"canonical-receipt-private-canary:/Users/private-operator/receipt.json";

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new() -> Self {
        let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-adapter-native-private-path-canary-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("seeded adapter root must be created");
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

#[derive(Clone)]
struct SeededEvidence {
    root_identity: [u8; 32],
    signer_profile: [u8; 32],
    grant_id: [u8; 32],
    dispatch_attempt_id: [u8; 32],
    plan_id: [u8; 32],
    task_lease_digest: [u8; 32],
    one_shot_nonce: [u8; 32],
    grant_digest: [u8; 32],
    coordinator_key_fingerprint: [u8; 32],
    receipt_id: [u8; 32],
    receipt_digest: [u8; 32],
    adapter_key_fingerprint: [u8; 32],
    received_event_id: [u8; 32],
    consumed_event_id: [u8; 32],
    conflict_event_id: [u8; 32],
    conflict_id: [u8; 32],
    observed_operation_digest: [u8; 32],
    observed_nonce_digest: [u8; 32],
    retained_binding_digest: [u8; 32],
    conflicting_binding_digest: [u8; 32],
}

impl SeededEvidence {
    fn new() -> Self {
        let mut generator = DeterministicCanaryGenerator(CANARY_SEED);
        Self {
            root_identity: generator.next_digest(),
            signer_profile: generator.next_digest(),
            grant_id: generator.next_digest(),
            dispatch_attempt_id: generator.next_digest(),
            plan_id: generator.next_digest(),
            task_lease_digest: generator.next_digest(),
            one_shot_nonce: generator.next_digest(),
            grant_digest: generator.next_digest(),
            coordinator_key_fingerprint: generator.next_digest(),
            receipt_id: generator.next_digest(),
            receipt_digest: generator.next_digest(),
            adapter_key_fingerprint: generator.next_digest(),
            received_event_id: generator.next_digest(),
            consumed_event_id: generator.next_digest(),
            conflict_event_id: generator.next_digest(),
            conflict_id: generator.next_digest(),
            observed_operation_digest: generator.next_digest(),
            observed_nonce_digest: generator.next_digest(),
            retained_binding_digest: generator.next_digest(),
            conflicting_binding_digest: generator.next_digest(),
        }
    }

    fn digests(&self) -> [[u8; 32]; 20] {
        [
            self.root_identity,
            self.signer_profile,
            self.grant_id,
            self.dispatch_attempt_id,
            self.plan_id,
            self.task_lease_digest,
            self.one_shot_nonce,
            self.grant_digest,
            self.coordinator_key_fingerprint,
            self.receipt_id,
            self.receipt_digest,
            self.adapter_key_fingerprint,
            self.received_event_id,
            self.consumed_event_id,
            self.conflict_event_id,
            self.conflict_id,
            self.observed_operation_digest,
            self.observed_nonce_digest,
            self.retained_binding_digest,
            self.conflicting_binding_digest,
        ]
    }
}

struct DeterministicCanaryGenerator(u64);

impl DeterministicCanaryGenerator {
    fn next_digest(&mut self) -> [u8; 32] {
        let mut digest = [0_u8; 32];
        for chunk in digest.chunks_exact_mut(8) {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            chunk.copy_from_slice(&self.0.to_be_bytes());
        }
        digest
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PublicEventProjectionV1 {
    event_contract_version: u64,
    grant_contract_version: u64,
    receipt_contract_version: u64,
    effective_state: Option<String>,
    decision: String,
    latency_ms: u64,
    event_kind: String,
    public_reason_code: Option<String>,
    delivery_state: String,
}

#[derive(Debug, PartialEq, Eq)]
struct PublicMetricsProjectionV1 {
    events: u64,
    received: u64,
    consumed: u64,
    refused: u64,
    quarantined: u64,
    conflicts: u64,
    restore_pending: u64,
}

#[test]
fn public_debug_and_error_surfaces_hide_seeded_native_custody() {
    let evidence = SeededEvidence::new();
    let root = TestRoot::new();
    let native_path = root.path().to_string_lossy().into_owned();
    let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(evidence.root_identity);
    let initialization = AdapterInboxInitializationV1::try_new(41, 7, evidence.signer_profile)
        .expect("seeded initialization is in range");
    let config =
        AdapterInboxStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), identity, 50)
            .expect("seeded empty adapter root is dedicated");

    let sample = AdapterTimeSampleV1::new(
        identifier(PRIVATE_BOOT),
        generation(11),
        safe(10_001),
        safe(2_001),
    );
    let epoch = EpochObservationV1::new(safe(41), generation(12), sample);

    for diagnostic in [
        format!("{identity:?}"),
        format!("{initialization:?}"),
        format!("{config:?}"),
        format!("{epoch:?}"),
        format!("{:?}", SupervisorEpochObservationV1::Current(epoch)),
        format!(
            "{:?}",
            AdapterClockObservationV1::Current(AdapterTimeSampleV1::new(
                identifier(PRIVATE_BOOT),
                generation(13),
                safe(10_002),
                safe(2_002),
            ))
        ),
    ] {
        assert_redacted(&diagnostic, &evidence, Some(&native_path));
    }

    fs::write(
        root.path().join("unknown-private-key-canary"),
        PRIVATE_PROVIDER_TEXT,
    )
    .expect("seeded hostile root member is written");
    let error =
        AdapterInboxStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), identity, 50)
            .expect_err("unknown root member is refused");
    assert_closed_error(error, "UNKNOWN_ROOT_MEMBER", &evidence, Some(&native_path));

    for (error, code) in [
        (
            AdapterInboxStoreConfigErrorV1::InvalidBusyBound,
            "INVALID_BUSY_BOUND",
        ),
        (
            AdapterInboxStoreConfigErrorV1::InvalidInitialObservation,
            "INVALID_INITIAL_OBSERVATION",
        ),
        (AdapterInboxStoreConfigErrorV1::RootInvalid, "ROOT_INVALID"),
        (
            AdapterInboxStoreConfigErrorV1::RootNotDedicated,
            "ROOT_NOT_DEDICATED",
        ),
        (
            AdapterInboxStoreConfigErrorV1::RootRoleMismatch,
            "ROOT_ROLE_MISMATCH",
        ),
        (
            AdapterInboxStoreConfigErrorV1::RootIdentityMismatch,
            "ROOT_IDENTITY_MISMATCH",
        ),
        (
            AdapterInboxStoreConfigErrorV1::UnknownRootMember,
            "UNKNOWN_ROOT_MEMBER",
        ),
    ] {
        assert_closed_error(error, code, &evidence, None);
    }

    for (error, code) in [
        (AdapterInboxStoreOpenErrorV1::RootInvalid, "ROOT_INVALID"),
        (
            AdapterInboxStoreOpenErrorV1::RootNotDedicated,
            "ROOT_NOT_DEDICATED",
        ),
        (
            AdapterInboxStoreOpenErrorV1::RootRoleMismatch,
            "ROOT_ROLE_MISMATCH",
        ),
        (
            AdapterInboxStoreOpenErrorV1::RootIdentityMismatch,
            "ROOT_IDENTITY_MISMATCH",
        ),
        (AdapterInboxStoreOpenErrorV1::RootBusy, "ROOT_BUSY"),
        (
            AdapterInboxStoreOpenErrorV1::RootUnavailable,
            "ROOT_UNAVAILABLE",
        ),
        (
            AdapterInboxStoreOpenErrorV1::UnknownRootMember,
            "UNKNOWN_ROOT_MEMBER",
        ),
        (
            AdapterInboxStoreOpenErrorV1::ApplicationIdMismatch,
            "APPLICATION_ID_MISMATCH",
        ),
        (
            AdapterInboxStoreOpenErrorV1::SchemaUnsupported,
            "SCHEMA_UNSUPPORTED",
        ),
        (
            AdapterInboxStoreOpenErrorV1::SchemaInvalid,
            "SCHEMA_INVALID",
        ),
        (
            AdapterInboxStoreOpenErrorV1::DurabilityProfileUnavailable,
            "DURABILITY_PROFILE_UNAVAILABLE",
        ),
        (
            AdapterInboxStoreOpenErrorV1::IntegrityFailed,
            "INTEGRITY_FAILED",
        ),
        (
            AdapterInboxStoreOpenErrorV1::InvariantFailed,
            "INVARIANT_FAILED",
        ),
    ] {
        assert_closed_error(error, code, &evidence, None);
    }
}

#[test]
fn real_schema_retains_restricted_evidence_but_public_events_and_metrics_are_payload_free() {
    let evidence = SeededEvidence::new();
    let connection = seeded_adapter_connection(&evidence);

    assert_restricted_evidence_is_really_stored(&connection, &evidence);

    let events = public_event_projection(&connection);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_kind, "GRANT_RECEIVED");
    assert_eq!(events[1].event_kind, "GRANT_CONSUMED");
    assert_eq!(events[2].event_kind, "GRANT_CONFLICT");
    for event in &events {
        assert!(matches!(event.event_contract_version, 1));
        assert!(matches!(event.grant_contract_version, 0 | 1));
        assert!(matches!(event.receipt_contract_version, 0 | 1));
        assert!(matches!(
            event.effective_state.as_deref(),
            Some("RECEIVED") | Some("CONSUMED") | None
        ));
        assert!(matches!(
            event.decision.as_str(),
            "RECEIVED" | "CONSUMED" | "CONFLICT"
        ));
        assert!(matches!(
            event.event_kind.as_str(),
            "GRANT_RECEIVED" | "GRANT_CONSUMED" | "GRANT_CONFLICT"
        ));
        assert!(matches!(
            event.public_reason_code.as_deref(),
            None | Some("BINDING_CONFLICT")
        ));
        assert_eq!(event.delivery_state, "PENDING");
        assert!(event.latency_ms <= MAX_SAFE_U64);
    }

    let metrics = public_metrics_projection(&connection);
    assert_eq!(
        metrics,
        PublicMetricsProjectionV1 {
            events: 3,
            received: 1,
            consumed: 1,
            refused: 0,
            quarantined: 0,
            conflicts: 1,
            restore_pending: 0,
        }
    );
    for count in [
        metrics.events,
        metrics.received,
        metrics.consumed,
        metrics.refused,
        metrics.quarantined,
        metrics.conflicts,
        metrics.restore_pending,
    ] {
        assert!(count <= MAX_SAFE_U64, "public counter exceeds safe bound");
    }

    assert_redacted(&format!("{events:?}"), &evidence, None);
    assert_redacted(&format!("{metrics:?}"), &evidence, None);
}

#[test]
fn real_schema_refuses_free_form_public_diagnostics() {
    let evidence = SeededEvidence::new();
    let connection = reviewed_connection();

    for (index, reason) in [
        "lowercase-private-diagnostic".to_owned(),
        PRIVATE_PATH.to_owned(),
        "HAS SPACE".to_owned(),
        "A".repeat(65),
    ]
    .into_iter()
    .enumerate()
    {
        let mut conflict_id = evidence.conflict_id;
        conflict_id[0] ^= u8::try_from(index + 1).expect("small seeded case index");
        let result = connection.execute(
            "INSERT INTO inbox_conflicts (
                conflict_id, observed_grant_id, observed_operation_digest,
                observed_nonce_digest, retained_binding_digest,
                conflicting_binding_digest, public_reason_code, conflict_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                conflict_id.as_slice(),
                evidence.grant_id.as_slice(),
                evidence.observed_operation_digest.as_slice(),
                evidence.observed_nonce_digest.as_slice(),
                evidence.retained_binding_digest.as_slice(),
                evidence.conflicting_binding_digest.as_slice(),
                reason,
                i64::try_from(index + 1).expect("small seeded generation"),
            ],
        );
        assert!(
            result.is_err(),
            "free-form public reason entered the schema"
        );
    }

    let result = connection.execute(
        "INSERT INTO adapter_events (
            event_id, event_generation, transition_generation, grant_id,
            operation_id, dispatch_attempt_id, task_id, workload_id, plan_id,
            task_lease_digest, event_contract_version, grant_contract_version,
            receipt_contract_version, effective_state, decision, latency_ms,
            event_kind, public_reason_code, public_trace_id, delivery_state,
            delivered_generation
         ) VALUES (
            ?1, 1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            1, 0, 0, NULL, 'CONFLICT', 0, 'GRANT_CONFLICT',
            'BINDING_CONFLICT', ?2, 'PENDING', NULL
         )",
        params![evidence.conflict_event_id.as_slice(), PRIVATE_PATH],
    );
    assert!(
        result.is_err(),
        "native path entered the bounded public trace column"
    );
}

fn seeded_adapter_connection(evidence: &SeededEvidence) -> Connection {
    let mut connection = reviewed_connection();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .expect("adapter foreign keys enable");
    connection
        .execute(
            "INSERT INTO adapter_store_meta (
                singleton, format_version, store_generation, inbox_generation,
                consumption_generation, receipt_generation, conflict_generation,
                quarantine_generation, event_generation, root_identity,
                root_lifecycle_state, supervisor_epoch, epoch_observer_generation,
                ordinary_queue_capacity, control_queue_capacity,
                receipt_signer_profile_digest, restore_index_digest,
                restore_state_generation
             ) VALUES (
                1, 1, 1, 1, 0, 0, 0, 0, 1, ?1,
                'ACTIVE', 41, 7, 1024, 32, ?2, NULL, 0
             )",
            params![
                evidence.root_identity.as_slice(),
                evidence.signer_profile.as_slice(),
            ],
        )
        .expect("seeded adapter metadata inserts");

    {
        let transaction = connection
            .transaction()
            .expect("receive transaction begins");
        transaction
            .execute(
                "INSERT INTO grant_inbox (
                    grant_id, operation_id, dispatch_attempt_id, plan_id, task_id,
                    workload_id, task_lease_digest, one_shot_nonce, grant_digest,
                    canonical_grant, canonical_grant_length,
                    coordinator_key_fingerprint, destination_adapter_id,
                    protocol_version, observed_supervisor_epoch,
                    epoch_observer_generation, inbox_state, received_generation,
                    current_generation, receipt_id, receipt_decision, current_event_id
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, 1, 41, 7, 'RECEIVED', 1, 1, NULL, NULL, ?14
                 )",
                params![
                    evidence.grant_id.as_slice(),
                    PRIVATE_OPERATION,
                    evidence.dispatch_attempt_id.as_slice(),
                    evidence.plan_id.as_slice(),
                    PRIVATE_TASK,
                    PRIVATE_WORKLOAD,
                    evidence.task_lease_digest.as_slice(),
                    evidence.one_shot_nonce.as_slice(),
                    evidence.grant_digest.as_slice(),
                    PRIVATE_CANONICAL_GRANT,
                    i64::try_from(PRIVATE_CANONICAL_GRANT.len()).expect("small grant canary"),
                    evidence.coordinator_key_fingerprint.as_slice(),
                    PRIVATE_ADAPTER,
                    evidence.received_event_id.as_slice(),
                ],
            )
            .expect("seeded RECEIVED grant inserts");
        insert_bound_event(
            &transaction,
            evidence.received_event_id,
            1,
            evidence,
            "RECEIVED",
            "RECEIVED",
            "GRANT_RECEIVED",
            0,
        );
        transaction
            .execute(
                "INSERT INTO inbox_transitions (
                    transition_generation, previous_transition_generation, grant_id,
                    operation_id, previous_state, new_state, event_id,
                    evidence_digest, receipt_id, receipt_decision
                 ) VALUES (1, NULL, ?1, ?2, 'ABSENT', 'RECEIVED', ?3, ?4, NULL, NULL)",
                params![
                    evidence.grant_id.as_slice(),
                    PRIVATE_OPERATION,
                    evidence.received_event_id.as_slice(),
                    evidence.grant_digest.as_slice(),
                ],
            )
            .expect("seeded RECEIVED transition inserts");
        transaction.commit().expect("receive transaction commits");
    }

    {
        let transaction = connection
            .transaction()
            .expect("consume transaction begins");
        transaction
            .execute(
                "UPDATE adapter_store_meta
                 SET store_generation = 2, consumption_generation = 2,
                     receipt_generation = 2, event_generation = 2
                 WHERE singleton = 1",
                [],
            )
            .expect("seeded consume metadata advances");
        transaction
            .execute(
                "INSERT INTO execution_receipts (
                    receipt_id, grant_id, operation_id, dispatch_attempt_id,
                    receipt_digest, canonical_receipt, canonical_receipt_length,
                    adapter_key_id, adapter_key_fingerprint, decision, refusal_code,
                    no_consumption_tombstone_digest, receipt_generation
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    'CONSUMED', NULL, NULL, 2
                 )",
                params![
                    evidence.receipt_id.as_slice(),
                    evidence.grant_id.as_slice(),
                    PRIVATE_OPERATION,
                    evidence.dispatch_attempt_id.as_slice(),
                    evidence.receipt_digest.as_slice(),
                    PRIVATE_CANONICAL_RECEIPT,
                    i64::try_from(PRIVATE_CANONICAL_RECEIPT.len()).expect("small receipt canary"),
                    PRIVATE_KEY_ID,
                    evidence.adapter_key_fingerprint.as_slice(),
                ],
            )
            .expect("seeded receipt inserts");
        transaction
            .execute(
                "UPDATE grant_inbox
                 SET inbox_state = 'CONSUMED', current_generation = 2,
                     receipt_id = ?1, receipt_decision = 'CONSUMED',
                     current_event_id = ?2
                 WHERE grant_id = ?3",
                params![
                    evidence.receipt_id.as_slice(),
                    evidence.consumed_event_id.as_slice(),
                    evidence.grant_id.as_slice(),
                ],
            )
            .expect("seeded grant advances to CONSUMED");
        insert_bound_event(
            &transaction,
            evidence.consumed_event_id,
            2,
            evidence,
            "CONSUMED",
            "CONSUMED",
            "GRANT_CONSUMED",
            1,
        );
        transaction
            .execute(
                "INSERT INTO inbox_transitions (
                    transition_generation, previous_transition_generation, grant_id,
                    operation_id, previous_state, new_state, event_id,
                    evidence_digest, receipt_id, receipt_decision
                 ) VALUES (2, 1, ?1, ?2, 'RECEIVED', 'CONSUMED', ?3, ?4, ?5, 'CONSUMED')",
                params![
                    evidence.grant_id.as_slice(),
                    PRIVATE_OPERATION,
                    evidence.consumed_event_id.as_slice(),
                    evidence.receipt_digest.as_slice(),
                    evidence.receipt_id.as_slice(),
                ],
            )
            .expect("seeded CONSUMED transition inserts");
        transaction.commit().expect("consume transaction commits");
    }

    {
        let transaction = connection
            .transaction()
            .expect("conflict transaction begins");
        transaction
            .execute(
                "UPDATE adapter_store_meta
                 SET store_generation = 3, conflict_generation = 3,
                     event_generation = 3
                 WHERE singleton = 1",
                [],
            )
            .expect("seeded conflict metadata advances");
        transaction
            .execute(
                "INSERT INTO inbox_conflicts (
                    conflict_id, observed_grant_id, observed_operation_digest,
                    observed_nonce_digest, retained_binding_digest,
                    conflicting_binding_digest, public_reason_code,
                    conflict_generation
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'BINDING_CONFLICT', 3)",
                params![
                    evidence.conflict_id.as_slice(),
                    evidence.grant_id.as_slice(),
                    evidence.observed_operation_digest.as_slice(),
                    evidence.observed_nonce_digest.as_slice(),
                    evidence.retained_binding_digest.as_slice(),
                    evidence.conflicting_binding_digest.as_slice(),
                ],
            )
            .expect("seeded conflict evidence inserts");
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
                    ?1, 3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                    1, 0, 0, NULL, 'CONFLICT', 2, 'GRANT_CONFLICT',
                    'BINDING_CONFLICT', ?2, 'PENDING', NULL
                 )",
                params![evidence.conflict_event_id.as_slice(), PRIVATE_TRACE],
            )
            .expect("seeded redacted conflict event inserts");
        transaction.commit().expect("conflict transaction commits");
    }

    connection
}

#[allow(clippy::too_many_arguments)]
fn insert_bound_event(
    transaction: &rusqlite::Transaction<'_>,
    event_id: [u8; 32],
    generation: i64,
    evidence: &SeededEvidence,
    effective_state: &str,
    decision: &str,
    event_kind: &str,
    latency_ms: i64,
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
                ?1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                1, 1, ?10, ?11, ?12, ?13, ?14, NULL, ?15, 'PENDING', NULL
             )",
            params![
                event_id.as_slice(),
                generation,
                evidence.grant_id.as_slice(),
                PRIVATE_OPERATION,
                evidence.dispatch_attempt_id.as_slice(),
                PRIVATE_TASK,
                PRIVATE_WORKLOAD,
                evidence.plan_id.as_slice(),
                evidence.task_lease_digest.as_slice(),
                if event_kind == "GRANT_RECEIVED" { 0 } else { 1 },
                effective_state,
                decision,
                latency_ms,
                event_kind,
                PRIVATE_TRACE,
            ],
        )
        .expect("seeded bound adapter event inserts");
}

fn assert_restricted_evidence_is_really_stored(connection: &Connection, evidence: &SeededEvidence) {
    let (root_identity, signer_profile): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT root_identity, receipt_signer_profile_digest
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("seeded metadata reads");
    assert_eq!(root_identity, evidence.root_identity);
    assert_eq!(signer_profile, evidence.signer_profile);

    let (operation, task, workload, canonical_grant): (String, String, String, Vec<u8>) =
        connection
            .query_row(
                "SELECT operation_id, task_id, workload_id, canonical_grant
                 FROM grant_inbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("seeded grant authority reads");
    assert_eq!(operation, PRIVATE_OPERATION);
    assert_eq!(task, PRIVATE_TASK);
    assert_eq!(workload, PRIVATE_WORKLOAD);
    assert_eq!(canonical_grant, PRIVATE_CANONICAL_GRANT);

    let (key_id, canonical_receipt): (String, Vec<u8>) = connection
        .query_row(
            "SELECT adapter_key_id, canonical_receipt FROM execution_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("seeded receipt authority reads");
    assert_eq!(key_id, PRIVATE_KEY_ID);
    assert_eq!(canonical_receipt, PRIVATE_CANONICAL_RECEIPT);

    let traces = connection
        .prepare("SELECT public_trace_id FROM adapter_events ORDER BY event_generation")
        .expect("seeded trace query prepares")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("seeded traces query")
        .collect::<Result<Vec<_>, _>>()
        .expect("seeded traces decode");
    assert_eq!(traces, vec![PRIVATE_TRACE; 3]);
}

fn public_event_projection(connection: &Connection) -> Vec<PublicEventProjectionV1> {
    connection
        .prepare(
            "SELECT event_contract_version, grant_contract_version,
                    receipt_contract_version, effective_state, decision, latency_ms,
                    event_kind, public_reason_code, delivery_state
             FROM adapter_events ORDER BY event_generation",
        )
        .expect("payload-free public event projection prepares")
        .query_map([], |row| {
            Ok(PublicEventProjectionV1 {
                event_contract_version: bounded_u64(row.get(0)?),
                grant_contract_version: bounded_u64(row.get(1)?),
                receipt_contract_version: bounded_u64(row.get(2)?),
                effective_state: row.get(3)?,
                decision: row.get(4)?,
                latency_ms: bounded_u64(row.get(5)?),
                event_kind: row.get(6)?,
                public_reason_code: row.get(7)?,
                delivery_state: row.get(8)?,
            })
        })
        .expect("payload-free public events query")
        .collect::<Result<Vec<_>, _>>()
        .expect("payload-free public events decode")
}

fn public_metrics_projection(connection: &Connection) -> PublicMetricsProjectionV1 {
    connection
        .query_row(
            "SELECT COUNT(*),
                    SUM(event_kind = 'GRANT_RECEIVED'),
                    SUM(event_kind = 'GRANT_CONSUMED'),
                    SUM(event_kind = 'GRANT_REFUSED'),
                    SUM(event_kind = 'GRANT_QUARANTINED'),
                    SUM(event_kind = 'GRANT_CONFLICT'),
                    SUM(event_kind = 'RESTORE_PENDING')
             FROM adapter_events",
            [],
            |row| {
                Ok(PublicMetricsProjectionV1 {
                    events: bounded_u64(row.get(0)?),
                    received: bounded_u64(row.get(1)?),
                    consumed: bounded_u64(row.get(2)?),
                    refused: bounded_u64(row.get(3)?),
                    quarantined: bounded_u64(row.get(4)?),
                    conflicts: bounded_u64(row.get(5)?),
                    restore_pending: bounded_u64(row.get(6)?),
                })
            },
        )
        .expect("payload-free public metrics query")
}

fn reviewed_connection() -> Connection {
    let connection = Connection::open_in_memory().expect("reviewed adapter schema opens");
    connection
        .execute_batch(ADAPTER_SCHEMA)
        .expect("reviewed adapter schema executes");
    connection
}

fn bounded_u64(value: i64) -> u64 {
    u64::try_from(value)
        .expect("public count/generation is non-negative")
        .min(MAX_SAFE_U64)
}

fn identifier(value: &str) -> Identifier {
    Identifier::new(value).expect("seeded identifier is contract-valid")
}

fn generation(value: u64) -> Generation {
    Generation::new(value).expect("seeded generation is contract-valid")
}

fn safe(value: u64) -> SafeU64 {
    SafeU64::new(value).expect("seeded integer is contract-valid")
}

fn assert_closed_error<E>(
    error: E,
    expected_code: &str,
    evidence: &SeededEvidence,
    native_path: Option<&str>,
) where
    E: Error + Debug + Display,
{
    let debug = format!("{error:?}");
    let display = error.to_string();
    assert_eq!(debug, expected_code);
    assert_eq!(display, expected_code);
    assert!(error.source().is_none());
    assert_redacted(&debug, evidence, native_path);
    assert_redacted(&display, evidence, native_path);
}

fn assert_redacted(text: &str, evidence: &SeededEvidence, native_path: Option<&str>) {
    assert!(text.is_ascii(), "public diagnostic is not ASCII");
    assert!(text.len() <= 1_024, "public diagnostic is not bounded");
    for forbidden in [
        PRIVATE_PATH,
        PRIVATE_OPERATION,
        PRIVATE_TASK,
        PRIVATE_WORKLOAD,
        PRIVATE_ADAPTER,
        PRIVATE_TRACE,
        PRIVATE_BOOT,
        PRIVATE_KEY_ID,
        PRIVATE_PROVIDER_TEXT,
        std::str::from_utf8(PRIVATE_CANONICAL_GRANT).expect("grant canary is UTF-8"),
        std::str::from_utf8(PRIVATE_CANONICAL_RECEIPT).expect("receipt canary is UTF-8"),
    ] {
        assert!(
            !text.contains(forbidden),
            "public output leaked {forbidden}"
        );
    }
    if let Some(path) = native_path {
        assert!(!text.contains(path), "public output leaked the native root");
    }
    for digest in evidence.digests() {
        let hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!text.to_ascii_lowercase().contains(&hex));
        assert!(!text.contains(&format!("{digest:?}")));
    }
}
