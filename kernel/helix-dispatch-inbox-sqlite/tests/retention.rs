//! PLAN-005 T074 RED contracts for permanent adapter-inbox v1 retention.
//!
//! The executable SQLite checks exercise the reviewed schema directly. The final
//! production-source gate is a compile-safe runtime RED until T079 adds the explicit
//! retention/nonclaim contract to `src/schema.rs`.

use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ADAPTER_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/adapter-inbox-schema-v1.sql");
const HISTORY_TABLES: [&str; 6] = [
    "grant_inbox",
    "inbox_transitions",
    "execution_receipts",
    "inbox_conflicts",
    "inbox_quarantines",
    "adapter_events",
];

struct RetentionFixtureV1 {
    directory: PathBuf,
    database: PathBuf,
}

impl RetentionFixtureV1 {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "helixos-t074-adapter-retention-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("T074 adapter retention root creates");
        let database = directory.join("dispatch-inbox.sqlite3");
        let connection = Connection::open(&database).expect("T074 adapter database creates");
        connection
            .execute_batch(ADAPTER_SCHEMA)
            .expect("reviewed adapter v1 schema installs");
        seed_history(&connection);
        Self {
            directory,
            database,
        }
    }

    fn open(&self) -> Connection {
        let connection =
            Connection::open(&self.database).expect("T074 adapter retention database reopens");
        connection
            .pragma_update(None, "recursive_triggers", "ON")
            .expect("replacement delete triggers enable");
        connection
    }
}

impl Drop for RetentionFixtureV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn seed_history(connection: &Connection) {
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("out-of-band retention fixture disables relationship checks while seeding");
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
                1, 1, 4, 1, 0, 2, 3, 4, 1, ?1,
                'ACTIVE', 15, 1, 1024, 32, ?2, NULL, 0
             )",
            params![[0x10_u8; 32].as_slice(), [0x11_u8; 32].as_slice()],
        )
        .expect("adapter metadata seeds");
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
                ?1, 'operation:t074', ?2, ?3, 'task:t074', 'workload:t074',
                ?4, ?5, ?6, ?7, 1, ?8, 'adapter:t074', 1, 15, 1,
                'RECEIVED', 1, 1, NULL, NULL, ?9
             )",
            params![
                [0x20_u8; 32].as_slice(),
                [0x21_u8; 32].as_slice(),
                [0x22_u8; 32].as_slice(),
                [0x23_u8; 32].as_slice(),
                [0x24_u8; 32].as_slice(),
                [0x25_u8; 32].as_slice(),
                [0x26_u8].as_slice(),
                [0x27_u8; 32].as_slice(),
                [0x28_u8; 32].as_slice(),
            ],
        )
        .expect("retained grant seeds");
    connection
        .execute(
            "INSERT INTO adapter_events (
                event_id, event_generation, transition_generation, grant_id,
                operation_id, dispatch_attempt_id, task_id, workload_id, plan_id,
                task_lease_digest, event_contract_version, grant_contract_version,
                receipt_contract_version, effective_state, decision, latency_ms,
                event_kind, public_reason_code, public_trace_id, delivery_state,
                delivered_generation
             ) VALUES (
                ?1, 1, 1, ?2, 'operation:t074', ?3, 'task:t074',
                'workload:t074', ?4, ?5, 1, 1, 0, 'RECEIVED', 'RECEIVED', 0,
                'GRANT_RECEIVED', NULL, 'trace:t074', 'PENDING', NULL
             )",
            params![
                [0x28_u8; 32].as_slice(),
                [0x20_u8; 32].as_slice(),
                [0x21_u8; 32].as_slice(),
                [0x22_u8; 32].as_slice(),
                [0x23_u8; 32].as_slice(),
            ],
        )
        .expect("retained adapter event seeds");
    connection
        .execute(
            "INSERT INTO inbox_transitions (
                transition_generation, previous_transition_generation, grant_id,
                operation_id, previous_state, new_state, event_id, evidence_digest,
                receipt_id, receipt_decision
             ) VALUES (
                1, NULL, ?1, 'operation:t074', 'ABSENT', 'RECEIVED', ?2, ?3,
                NULL, NULL
             )",
            params![
                [0x20_u8; 32].as_slice(),
                [0x28_u8; 32].as_slice(),
                [0x29_u8; 32].as_slice(),
            ],
        )
        .expect("retained adapter transition seeds");
    connection
        .execute(
            "INSERT INTO execution_receipts (
                receipt_id, grant_id, operation_id, dispatch_attempt_id,
                receipt_digest, canonical_receipt, canonical_receipt_length,
                adapter_key_id, adapter_key_fingerprint, decision, refusal_code,
                no_consumption_tombstone_digest, receipt_generation
             ) VALUES (
                ?1, ?2, 'operation:t074', ?3, ?4, ?5, 1,
                'receipt-key:t074', ?6, 'REFUSED_DEFINITE', 'ADAPTER_PAUSED', ?7, 2
             )",
            params![
                [0x30_u8; 32].as_slice(),
                [0x20_u8; 32].as_slice(),
                [0x21_u8; 32].as_slice(),
                [0x31_u8; 32].as_slice(),
                [0x32_u8].as_slice(),
                [0x33_u8; 32].as_slice(),
                [0x34_u8; 32].as_slice(),
            ],
        )
        .expect("retained definite-refusal receipt and tombstone seed");
    connection
        .execute(
            "INSERT INTO inbox_conflicts (
                conflict_id, observed_grant_id, observed_operation_digest,
                observed_nonce_digest, retained_binding_digest,
                conflicting_binding_digest, public_reason_code, conflict_generation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'BINDING_CONFLICT', 3)",
            params![
                [0x40_u8; 32].as_slice(),
                [0x41_u8; 32].as_slice(),
                [0x42_u8; 32].as_slice(),
                [0x43_u8; 32].as_slice(),
                [0x44_u8; 32].as_slice(),
                [0x45_u8; 32].as_slice(),
            ],
        )
        .expect("retained conflict seeds");
    connection
        .execute(
            "INSERT INTO inbox_quarantines (
                quarantine_id, grant_id, evidence_digest, public_reason_code,
                quarantine_generation, resolved_generation
             ) VALUES (?1, NULL, ?2, 'ORPHAN_RECEIPT', 4, NULL)",
            params![[0x50_u8; 32].as_slice(), [0x51_u8; 32].as_slice()],
        )
        .expect("retained quarantine seeds");
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|_| panic!("retained row count reads for {table}"))
}

fn adapter_rust_sources() -> Vec<(PathBuf, String)> {
    fn visit(directory: &Path, sources: &mut Vec<(PathBuf, String)>) {
        let mut entries = fs::read_dir(directory)
            .expect("adapter source directory reads")
            .map(|entry| entry.expect("adapter source entry reads").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(&path, sources);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let source = fs::read_to_string(&path).expect("adapter Rust source is UTF-8");
                sources.push((path, source));
            }
        }
    }

    let mut sources = Vec::new();
    visit(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    sources
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
    assert_eq!(block_depth, 0, "T074 production comments are balanced");
    output
}

fn production_source_without_comments(source: &str) -> String {
    let source = source_without_comments(source);
    let test_start = ["#[cfg(test)]", "#[cfg(all(test"]
        .into_iter()
        .filter_map(|marker| source.find(marker))
        .min()
        .unwrap_or(source.len());
    source[..test_start].to_owned()
}

#[test]
fn every_authoritative_adapter_v1_table_has_a_permanent_delete_guard() {
    let connection = Connection::open_in_memory().expect("T074 schema oracle opens");
    connection
        .execute_batch(ADAPTER_SCHEMA)
        .expect("reviewed adapter schema installs in oracle");
    for table in HISTORY_TABLES {
        let guards: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'trigger' AND tbl_name = ?1
                   AND sql LIKE '%BEFORE DELETE ON%'
                   AND sql LIKE '%RAISE(ABORT,%'",
                [table],
                |row| row.get(0),
            )
            .expect("delete-guard inventory reads");
        assert_eq!(guards, 1, "{table} must have one permanent delete guard");
    }
}

#[test]
fn delete_replace_and_whole_history_prune_are_rejected_without_mutation() {
    let fixture = RetentionFixtureV1::new("delete-replace");
    let connection = fixture.open();
    let before = HISTORY_TABLES.map(|table| count(&connection, table));

    for table in HISTORY_TABLES {
        for statement in [
            format!("DELETE FROM {table}"),
            format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
        ] {
            assert!(
                connection.execute_batch(&statement).is_err(),
                "permanent adapter history must reject `{statement}`"
            );
        }
    }
    assert!(
        connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 PRAGMA defer_foreign_keys = ON;
                 DELETE FROM adapter_events;
                 DELETE FROM inbox_transitions;
                 DELETE FROM execution_receipts;
                 DELETE FROM inbox_conflicts;
                 DELETE FROM inbox_quarantines;
                 DELETE FROM grant_inbox;
                 COMMIT;",
            )
            .is_err(),
        "whole-history pruning must fail even when foreign keys are deferred"
    );
    let _ = connection.execute_batch("ROLLBACK");
    assert_eq!(
        HISTORY_TABLES.map(|table| count(&connection, table)),
        before
    );
}

#[test]
fn tombstones_cannot_reverse_and_history_generations_cannot_be_reused() {
    let fixture = RetentionFixtureV1::new("tombstone-reuse");
    let connection = fixture.open();
    assert!(
        connection
            .execute(
                "UPDATE execution_receipts
                 SET no_consumption_tombstone_digest = NULL
                 WHERE receipt_id = ?1",
                [[0x30_u8; 32].as_slice()],
            )
            .is_err(),
        "definite-refusal tombstone must never be cleared"
    );
    connection
        .execute(
            "UPDATE inbox_quarantines SET resolved_generation = 5
             WHERE quarantine_id = ?1",
            [[0x50_u8; 32].as_slice()],
        )
        .expect("unresolved quarantine may append its one terminal projection");
    assert!(
        connection
            .execute(
                "UPDATE inbox_quarantines SET resolved_generation = NULL
                 WHERE quarantine_id = ?1",
                [[0x50_u8; 32].as_slice()],
            )
            .is_err(),
        "resolved quarantine tombstone must never reverse"
    );
    assert!(
        connection
            .execute(
                "INSERT INTO inbox_conflicts (
                    conflict_id, observed_grant_id, observed_operation_digest,
                    observed_nonce_digest, retained_binding_digest,
                    conflicting_binding_digest, public_reason_code, conflict_generation
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'SECOND_CONFLICT', 3)",
                params![
                    [0x60_u8; 32].as_slice(),
                    [0x61_u8; 32].as_slice(),
                    [0x62_u8; 32].as_slice(),
                    [0x63_u8; 32].as_slice(),
                    [0x64_u8; 32].as_slice(),
                    [0x65_u8; 32].as_slice(),
                ],
            )
            .is_err(),
        "conflict_generation must be create-only and globally unreusable"
    );
    assert_eq!(count(&connection, "execution_receipts"), 1);
    assert_eq!(count(&connection, "inbox_quarantines"), 1);
    assert_eq!(count(&connection, "inbox_conflicts"), 1);
}

#[test]
fn production_exposes_no_adapter_prune_compact_delete_or_reuse_surface() {
    let forbidden_identifiers = [
        "pub fn prune",
        "pub(crate) fn prune",
        "pub fn compact_history",
        "pub(crate) fn compact_history",
        "pub fn delete_inbox_history",
        "pub(crate) fn delete_inbox_history",
        "pub fn reuse_inbox_generation",
        "pub(crate) fn reuse_inbox_generation",
    ];
    for (path, source) in adapter_rust_sources() {
        let source = production_source_without_comments(&source);
        for forbidden in forbidden_identifiers {
            assert!(
                !source.contains(forbidden),
                "{} exposes forbidden adapter retention shortcut `{forbidden}`",
                path.display()
            );
        }
        for table in HISTORY_TABLES {
            for forbidden in [
                format!("DELETE FROM {table}"),
                format!("INSERT OR REPLACE INTO {table}"),
            ] {
                assert!(
                    !source.contains(&forbidden),
                    "{} mutates permanent adapter history with `{forbidden}`",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn production_t079_adapter_retention_contract_is_explicit_and_closed() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/schema.rs");
    let source = source_without_comments(
        &fs::read_to_string(&path).expect("adapter schema production source reads"),
    );
    let required = [
        "AdapterInboxRetentionPolicyV1",
        "adapter_inbox_retention_policy_v1",
        "verify_permanent_adapter_history_v1",
        "requires_approved_encrypted_at_rest_profile",
        "automatic_pruning_enabled",
        "physical_secure_erasure_claimed",
    ];
    let missing = required
        .iter()
        .copied()
        .filter(|member| !source.contains(member))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "T074 RED: future T079 adapter retention contract is absent or incomplete; missing={missing:?}"
    );
}
