//! PLAN-005 T040 receive-before-acknowledgement and terminal atomicity contracts.

use helix_dispatch_contracts::ExecutionReceiptRefusalCodeV1;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const REVIEWED_ADAPTER_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/adapter-inbox-schema-v1.sql");

const ORACLE_SCHEMA: &str = r#"
CREATE TABLE oracle_inbox (
    grant_id TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('RECEIVED', 'CONSUMED', 'REFUSED')),
    current_generation INTEGER NOT NULL,
    receipt_id TEXT
) STRICT;
CREATE TABLE oracle_transitions (
    generation INTEGER PRIMARY KEY NOT NULL,
    grant_id TEXT NOT NULL,
    previous_state TEXT NOT NULL,
    new_state TEXT NOT NULL,
    receipt_id TEXT,
    UNIQUE (grant_id, previous_state)
) STRICT;
CREATE TABLE oracle_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    grant_id TEXT UNIQUE NOT NULL,
    decision TEXT NOT NULL,
    refusal_code TEXT,
    CHECK (
        (decision = 'CONSUMED' AND refusal_code IS NULL)
        OR
        (decision = 'REFUSED_DEFINITE' AND refusal_code IN (
            'GRANT_EXPIRED',
            'SUPERVISOR_EPOCH_MISMATCH',
            'ADAPTER_PAUSED'
        ))
    )
) STRICT;
CREATE TABLE oracle_events (
    generation INTEGER PRIMARY KEY NOT NULL,
    grant_id TEXT,
    kind TEXT NOT NULL,
    reason TEXT
) STRICT;
CREATE TABLE oracle_diagnostics (
    generation INTEGER PRIMARY KEY NOT NULL,
    reason TEXT NOT NULL UNIQUE
) STRICT;
"#;

const PRE_RECEIVED_REFUSALS: [&str; 4] = [
    "DESTINATION_MISMATCH",
    "PROTOCOL_UNSUPPORTED",
    "CAPABILITY_MISMATCH",
    "INBOX_CAPACITY_EXHAUSTED",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalDecisionV1 {
    Consumed,
    Refused(ExecutionReceiptRefusalCodeV1),
}

impl TerminalDecisionV1 {
    fn state(self) -> &'static str {
        match self {
            Self::Consumed => "CONSUMED",
            Self::Refused(_) => "REFUSED",
        }
    }

    fn receipt_decision(self) -> &'static str {
        match self {
            Self::Consumed => "CONSUMED",
            Self::Refused(_) => "REFUSED_DEFINITE",
        }
    }

    fn refusal_code(self) -> Option<&'static str> {
        match self {
            Self::Consumed => None,
            Self::Refused(code) => Some(refusal_code(code)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalFaultV1 {
    Receipt,
    Event,
    Transition,
    Projection,
}

fn refusal_code(code: ExecutionReceiptRefusalCodeV1) -> &'static str {
    match code {
        ExecutionReceiptRefusalCodeV1::GrantExpired => "GRANT_EXPIRED",
        ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch => "SUPERVISOR_EPOCH_MISMATCH",
        ExecutionReceiptRefusalCodeV1::AdapterPaused => "ADAPTER_PAUSED",
    }
}

fn terminal_decisions() -> [TerminalDecisionV1; 4] {
    [
        TerminalDecisionV1::Consumed,
        TerminalDecisionV1::Refused(ExecutionReceiptRefusalCodeV1::GrantExpired),
        TerminalDecisionV1::Refused(ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch),
        TerminalDecisionV1::Refused(ExecutionReceiptRefusalCodeV1::AdapterPaused),
    ]
}

fn open_oracle() -> Connection {
    let connection = Connection::open_in_memory().expect("T040 oracle opens");
    connection
        .execute_batch(ORACLE_SCHEMA)
        .expect("T040 oracle schema creates");
    connection
}

fn commit_received_before_acknowledgement(
    connection: &mut Connection,
    grant_id: &str,
    acknowledge: impl FnOnce(&Connection),
) {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("T040 receive transaction begins");
    transaction
        .execute(
            "INSERT INTO oracle_inbox (grant_id, state, current_generation, receipt_id)
             VALUES (?1, 'RECEIVED', 1, NULL)",
            [grant_id],
        )
        .expect("T040 inbox receive stages");
    transaction
        .execute(
            "INSERT INTO oracle_transitions
             (generation, grant_id, previous_state, new_state, receipt_id)
             VALUES (1, ?1, 'ABSENT', 'RECEIVED', NULL)",
            [grant_id],
        )
        .expect("T040 receive transition stages");
    transaction
        .execute(
            "INSERT INTO oracle_events (generation, grant_id, kind, reason)
             VALUES (1, ?1, 'GRANT_RECEIVED', NULL)",
            [grant_id],
        )
        .expect("T040 receive event stages");
    transaction.commit().expect("T040 receive commits");
    acknowledge(connection);
}

fn commit_terminal_decision(
    connection: &mut Connection,
    grant_id: &str,
    decision: TerminalDecisionV1,
    fault: Option<TerminalFaultV1>,
) -> rusqlite::Result<()> {
    let receipt_id = format!("receipt-{}", decision.state().to_ascii_lowercase());
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO oracle_receipts
         (receipt_id, grant_id, decision, refusal_code) VALUES (?1, ?2, ?3, ?4)",
        params![
            receipt_id,
            grant_id,
            decision.receipt_decision(),
            decision.refusal_code()
        ],
    )?;
    inject_terminal_fault(fault, TerminalFaultV1::Receipt)?;

    transaction.execute(
        "INSERT INTO oracle_events (generation, grant_id, kind, reason)
         VALUES (2, ?1, ?2, ?3)",
        params![
            grant_id,
            if decision == TerminalDecisionV1::Consumed {
                "GRANT_CONSUMED"
            } else {
                "GRANT_REFUSED"
            },
            decision.refusal_code()
        ],
    )?;
    inject_terminal_fault(fault, TerminalFaultV1::Event)?;

    transaction.execute(
        "INSERT INTO oracle_transitions
         (generation, grant_id, previous_state, new_state, receipt_id)
         VALUES (2, ?1, 'RECEIVED', ?2, ?3)",
        params![grant_id, decision.state(), receipt_id],
    )?;
    inject_terminal_fault(fault, TerminalFaultV1::Transition)?;

    let updated = transaction.execute(
        "UPDATE oracle_inbox
         SET state = ?1, current_generation = 2, receipt_id = ?2
         WHERE grant_id = ?3 AND state = 'RECEIVED' AND current_generation = 1",
        params![decision.state(), receipt_id, grant_id],
    )?;
    assert_eq!(updated, 1, "T040 terminal projection requires RECEIVED");
    inject_terminal_fault(fault, TerminalFaultV1::Projection)?;

    transaction.commit()
}

fn inject_terminal_fault(
    selected: Option<TerminalFaultV1>,
    current: TerminalFaultV1,
) -> rusqlite::Result<()> {
    if selected == Some(current) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn record_pre_received_refusal(connection: &mut Connection, generation: i64, reason: &str) {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("T040 pre-receive diagnostic transaction begins");
    transaction
        .execute(
            "INSERT INTO oracle_diagnostics (generation, reason) VALUES (?1, ?2)",
            (generation, reason),
        )
        .expect("T040 pre-receive diagnostic stages");
    transaction
        .commit()
        .expect("T040 pre-receive diagnostic commits");
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .expect("T040 oracle count reads")
}

#[test]
fn reviewed_schema_closes_receive_consume_and_refusal_shapes() {
    for required in [
        "previous_state = 'ABSENT' AND new_state = 'RECEIVED'",
        "previous_state = 'RECEIVED'",
        "new_state = 'CONSUMED'",
        "new_state = 'REFUSED'",
        "receipt_decision = 'CONSUMED'",
        "receipt_decision = 'REFUSED_DEFINITE'",
        "adapter transitions are append-only",
        "adapter receipt history is permanent",
    ] {
        assert!(
            REVIEWED_ADAPTER_SCHEMA.contains(required),
            "T040 reviewed adapter schema omits {required}"
        );
    }

    let post_received = terminal_decisions()
        .into_iter()
        .filter_map(TerminalDecisionV1::refusal_code)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        post_received,
        BTreeSet::from([
            "ADAPTER_PAUSED",
            "GRANT_EXPIRED",
            "SUPERVISOR_EPOCH_MISMATCH",
        ])
    );
    assert_eq!(
        PRE_RECEIVED_REFUSALS.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "CAPABILITY_MISMATCH",
            "DESTINATION_MISMATCH",
            "INBOX_CAPACITY_EXHAUSTED",
            "PROTOCOL_UNSUPPORTED",
        ])
    );
}

#[test]
fn receive_commits_before_acknowledgement_in_a_distinct_transaction() {
    let mut connection = open_oracle();
    let mut acknowledgement_count = 0_u64;
    commit_received_before_acknowledgement(&mut connection, "grant-a", |committed| {
        let state: String = committed
            .query_row(
                "SELECT state FROM oracle_inbox WHERE grant_id = 'grant-a'",
                [],
                |row| row.get(0),
            )
            .expect("T040 acknowledgement observes durable receive");
        assert_eq!(state, "RECEIVED");
        assert_eq!(count(committed, "oracle_receipts"), 0);
        acknowledgement_count += 1;
    });

    assert_eq!(acknowledgement_count, 1);
    assert_eq!(count(&connection, "oracle_transitions"), 1);
    assert_eq!(count(&connection, "oracle_events"), 1);
    assert_eq!(count(&connection, "oracle_receipts"), 0);

    commit_terminal_decision(
        &mut connection,
        "grant-a",
        TerminalDecisionV1::Consumed,
        None,
    )
    .expect("T040 distinct terminal transaction commits");
    assert_eq!(count(&connection, "oracle_transitions"), 2);
    assert_eq!(count(&connection, "oracle_events"), 2);
    assert_eq!(count(&connection, "oracle_receipts"), 1);
}

#[test]
fn consumed_and_exactly_three_post_received_refusals_commit_atomically() {
    for (case, decision) in terminal_decisions().into_iter().enumerate() {
        let mut connection = open_oracle();
        let grant_id = format!("grant-terminal-{case}");
        commit_received_before_acknowledgement(&mut connection, &grant_id, |_| {});
        commit_terminal_decision(&mut connection, &grant_id, decision, None)
            .expect("T040 terminal decision commits");

        let retained: (String, String, Option<String>) = connection
            .query_row(
                "SELECT i.state, r.decision, r.refusal_code
                 FROM oracle_inbox AS i
                 JOIN oracle_receipts AS r ON r.receipt_id = i.receipt_id
                 WHERE i.grant_id = ?1",
                [&grant_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("T040 terminal graph reads");
        assert_eq!(retained.0, decision.state());
        assert_eq!(retained.1, decision.receipt_decision());
        assert_eq!(retained.2.as_deref(), decision.refusal_code());
        assert_eq!(count(&connection, "oracle_transitions"), 2);
        assert_eq!(count(&connection, "oracle_events"), 2);
        assert_eq!(count(&connection, "oracle_receipts"), 1);
    }
}

#[test]
fn terminal_faults_leave_received_with_no_partial_receipt_transition_or_event() {
    for decision in terminal_decisions() {
        for fault in [
            TerminalFaultV1::Receipt,
            TerminalFaultV1::Event,
            TerminalFaultV1::Transition,
            TerminalFaultV1::Projection,
        ] {
            let mut connection = open_oracle();
            commit_received_before_acknowledgement(&mut connection, "grant-fault", |_| {});
            assert!(
                commit_terminal_decision(&mut connection, "grant-fault", decision, Some(fault),)
                    .is_err(),
                "T040 selected terminal fault must abort"
            );

            let retained_state: String = connection
                .query_row(
                    "SELECT state FROM oracle_inbox WHERE grant_id = 'grant-fault'",
                    [],
                    |row| row.get(0),
                )
                .expect("T040 retained receive reads");
            assert_eq!(retained_state, "RECEIVED");
            assert_eq!(count(&connection, "oracle_transitions"), 1);
            assert_eq!(count(&connection, "oracle_events"), 1);
            assert_eq!(count(&connection, "oracle_receipts"), 0);
        }
    }
}

#[test]
fn exactly_four_pre_received_refusals_remain_durable_without_receipt() {
    let root = TemporaryOracleRoot::new("t040-pre-received");
    {
        let mut connection = Connection::open(root.path()).expect("T040 file oracle opens");
        connection
            .execute_batch(ORACLE_SCHEMA)
            .expect("T040 file oracle schema creates");
        for (index, reason) in PRE_RECEIVED_REFUSALS.into_iter().enumerate() {
            record_pre_received_refusal(
                &mut connection,
                i64::try_from(index + 1).expect("T040 diagnostic generation fits"),
                reason,
            );
        }
    }

    let reopened = Connection::open(root.path()).expect("T040 file oracle reopens");
    assert_eq!(count(&reopened, "oracle_diagnostics"), 4);
    assert_eq!(count(&reopened, "oracle_inbox"), 0);
    assert_eq!(count(&reopened, "oracle_transitions"), 0);
    assert_eq!(count(&reopened, "oracle_receipts"), 0);
    assert_eq!(count(&reopened, "oracle_events"), 0);
    for reason in PRE_RECEIVED_REFUSALS {
        let retained: Option<String> = reopened
            .query_row(
                "SELECT reason FROM oracle_diagnostics WHERE reason = ?1",
                [reason],
                |row| row.get(0),
            )
            .optional()
            .expect("T040 diagnostic readback succeeds");
        assert_eq!(retained.as_deref(), Some(reason));
    }
}

#[test]
fn production_receive_and_terminal_paths_own_the_two_durable_boundaries() {
    let inbox = required_production_source(
        "inbox.rs",
        "T040/T047 durable ABSENT-to-RECEIVED before acknowledgement",
    );
    let receipt = required_production_source(
        "receipt.rs",
        "T040/T049 atomic post-RECEIVED terminal receipt",
    );
    let events =
        required_production_source("events.rs", "T040/T049 receive and terminal event custody");
    let crate_root = required_production_source("lib.rs", "T040 compiled module wiring");

    for module in ["mod inbox;", "mod receipt;", "mod events;"] {
        assert!(
            crate_root.contains(module),
            "T040 RED: production crate root must compile {module}"
        );
    }
    for required in [
        "TransactionBehavior::Immediate",
        "grant_inbox",
        "inbox_transitions",
        "adapter_events",
        "ABSENT",
        "RECEIVED",
        "canonical_grant",
        "grant_digest",
        "DESTINATION_MISMATCH",
        "PROTOCOL_UNSUPPORTED",
        "CAPABILITY_MISMATCH",
        "INBOX_CAPACITY_EXHAUSTED",
    ] {
        assert!(
            inbox.contains(required),
            "T040 RED: T047 receive path omits {required}"
        );
    }
    for required in [
        "TransactionBehavior::Immediate",
        "sign_execution_receipt_v1",
        "execution_receipts",
        "inbox_transitions",
        "adapter_events",
        "RECEIVED",
        "CONSUMED",
        "REFUSED",
        "REFUSED_DEFINITE",
        "GRANT_EXPIRED",
        "SUPERVISOR_EPOCH_MISMATCH",
        "ADAPTER_PAUSED",
        "no_consumption_tombstone",
    ] {
        assert!(
            receipt.contains(required) || events.contains(required),
            "T040 RED: T049 terminal path omits {required}"
        );
    }
    for forbidden in PRE_RECEIVED_REFUSALS {
        assert!(
            !receipt.contains(forbidden),
            "T040: pre-RECEIVED refusal {forbidden} must never enter receipt signing"
        );
    }
    for forbidden in [
        "ExecutionToken",
        "execution_token",
        "execute_effect",
        "host_effect",
        "release_reservation",
    ] {
        assert!(
            !format!("{inbox}\n{receipt}\n{events}").contains(forbidden),
            "T040: adapter crosses the no-effect/no-release boundary through {forbidden}"
        );
    }
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T040 RED: missing future production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut block_depth = 0_u64;
    for line in source.lines() {
        let mut remaining = line;
        loop {
            if block_depth > 0 {
                let Some(end) = remaining.find("*/") else {
                    break;
                };
                block_depth -= 1;
                remaining = &remaining[end + 2..];
                continue;
            }
            let line_comment = remaining.find("//");
            let block_comment = remaining.find("/*");
            match (line_comment, block_comment) {
                (Some(line_start), Some(block_start)) if block_start < line_start => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (Some(line_start), _) => {
                    output.push_str(&remaining[..line_start]);
                    break;
                }
                (None, Some(block_start)) => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (None, None) => {
                    output.push_str(remaining);
                    break;
                }
            }
        }
        output.push('\n');
    }
    assert_eq!(block_depth, 0, "T040 source comments are balanced");
    output
}

#[derive(Debug)]
struct TemporaryOracleRoot {
    path: PathBuf,
}

impl TemporaryOracleRoot {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helix-dispatch-inbox-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryOracleRoot {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(self.path.with_extension("sqlite3-shm"));
    }
}
