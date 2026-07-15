//! PLAN-005 T026 canonical dispatch transaction and exact readback contracts.

use rusqlite::Connection;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const V2_OVERLAY: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/coordinator-dispatch-schema-v2.sql"
);

const CANONICAL_INITIAL_MEMBERS: [&str; 7] = [
    "dispatch_comparisons",
    "dispatch_grants",
    "dispatch_records",
    "dispatch_transitions",
    "dispatch_outbox",
    "dispatch_events",
    "dispatch_store_meta",
];

#[test]
fn reviewed_overlay_contains_the_complete_initial_commit_graph() {
    let unique = CANONICAL_INITIAL_MEMBERS
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), CANONICAL_INITIAL_MEMBERS.len());
    for member in CANONICAL_INITIAL_MEMBERS {
        assert!(
            V2_OVERLAY.contains(&format!("CREATE TABLE {member}")),
            "reviewed overlay omits canonical member {member}"
        );
    }
    for required in [
        "DEFERRABLE INITIALLY DEFERRED",
        "dispatch_grants_no_update",
        "dispatch_transitions_current_projection_guard",
        "dispatch_outbox_no_delete",
        "dispatch_events_one_per_transition_uq",
    ] {
        assert!(V2_OVERLAY.contains(required), "overlay omits {required}");
    }
}

#[test]
fn sqlite_rollback_oracle_leaks_no_partial_canonical_member() {
    let mut connection = Connection::open_in_memory().expect("rollback oracle opens");
    connection
        .execute_batch(
            "CREATE TABLE staged_dispatch_member (
                member TEXT PRIMARY KEY NOT NULL,
                ordinal INTEGER UNIQUE NOT NULL
            ) STRICT;",
        )
        .expect("rollback oracle schema creates");

    for failure_after in 1..=CANONICAL_INITIAL_MEMBERS.len() {
        let transaction = connection.transaction().expect("oracle transaction begins");
        for (ordinal, member) in CANONICAL_INITIAL_MEMBERS
            .iter()
            .copied()
            .enumerate()
            .take(failure_after)
        {
            transaction
                .execute(
                    "INSERT INTO staged_dispatch_member (member, ordinal) VALUES (?1, ?2)",
                    (member, i64::try_from(ordinal).unwrap()),
                )
                .expect("oracle member stages");
        }
        transaction.rollback().expect("oracle rollback succeeds");
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM staged_dispatch_member", [], |row| {
                row.get(0)
            })
            .expect("oracle count reads");
        assert_eq!(count, 0, "member {failure_after} leaked after rollback");
    }
}

#[test]
fn production_commit_stages_every_member_once_under_one_immediate_transaction() {
    let dispatch = required_production_source(
        "dispatch.rs",
        "T026/T032-T033 canonical all-or-none dispatch commit",
    );
    let outbox = required_production_source(
        "dispatch_outbox.rs",
        "T026/T033 exact retained outbox member",
    );
    let staging_boundary = "pub(crate) fn stage_pending_dispatch_outbox_v1";
    let handoff_boundary = "pub enum CoordinatorDispatchHandoffOutcomeV1<R>";
    let staging_start = outbox
        .find(staging_boundary)
        .expect("T026 production source retains the canonical outbox staging helper");
    let handoff_start = outbox
        .find(handoff_boundary)
        .expect("T064 production source retains a distinct post-commit handoff boundary");
    assert!(staging_start < handoff_start);
    let canonical_outbox = &outbox[staging_start..handoff_start];
    let combined = format!("{dispatch}\n{canonical_outbox}");

    assert!(
        combined.contains("TransactionBehavior::Immediate") || combined.contains("BEGIN IMMEDIATE"),
        "T026 RED: canonical dispatch commit must own one immediate writer transaction"
    );
    for member in CANONICAL_INITIAL_MEMBERS {
        assert!(
            combined.contains(member),
            "T026 RED: canonical commit omits {member}"
        );
    }
    for required in [
        "DispatchCommitCandidateV1",
        "ConfirmedRollback",
        "Uncertain",
        "canonical_grant",
        "grant_digest",
        "dispatch_attempt_id",
        "one_shot_nonce",
    ] {
        assert!(
            combined.contains(required),
            "T026 RED: canonical commit source omits {required}"
        );
    }
    for forbidden in [
        "deliver_exact_v1",
        "DispatchTransportV1",
        "sign_execution_grant_v1",
        "sign_grant_v1",
    ] {
        assert!(
            !combined.contains(forbidden),
            "T026: writer transaction crosses forbidden transport/signing boundary {forbidden}"
        );
    }
}

#[test]
fn uncertain_commit_readback_consumes_exact_attempt_custody_without_retry() {
    let source = required_production_source(
        "dispatch_readback.rs",
        "T026/T034 exact uncertain dispatch-attempt readback",
    );

    for required in [
        "DispatchAttemptIdV1",
        "UncertainCommitCustody",
        "ThisAttemptCommitted",
        "PriorExactDispatch",
        "DefinitelyAbsent",
        "Conflict",
        "Unavailable",
        "Unhealthy",
        "dispatch_attempt_id",
        "grant_id",
        "grant_digest",
        "one_shot_nonce",
    ] {
        assert!(
            source.contains(required),
            "T026 RED: exact uncertain readback omits {required}"
        );
    }
    for forbidden in [
        "sign_execution_grant_v1",
        "sign_grant_v1",
        "new_grant",
        "replacement_grant",
        "commit_candidate_once_v1",
    ] {
        assert!(
            !source.contains(forbidden),
            "T026: readback retries or remints authority through {forbidden}"
        );
    }
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T026 RED: missing production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}
