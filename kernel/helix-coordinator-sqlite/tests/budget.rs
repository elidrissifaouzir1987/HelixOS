//! T039 red tests for trusted create-only budget-scope provisioning.
//!
//! The production seam stays crate-private. These tests source-include it so trusted
//! maintenance fixtures can exercise the storage contract without widening the public
//! coordinator API or constructing plan authority.

#[path = "../src/budget.rs"]
mod budget;

use budget::{
    checked_budget_reservation_v1, provision_trusted_budget_scope_v1,
    BudgetScopeProvisionOutcomeV1, BudgetVectorCheckErrorV1, TrustedBudgetScopeInputV1,
};
use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use rusqlite::Connection;

const STORE_SCHEMA: &str = include_str!(
    "../../../specs/004-durable-preparation/contracts/preparation-store-schema-v1.sql"
);

#[derive(Debug, PartialEq, Eq)]
struct StoredScope {
    scope_id: Vec<u8>,
    task_lease_digest: Vec<u8>,
    allowance_binding_digest: Vec<u8>,
    scope_generation: i64,
    currency_code: String,
    price_table_id: String,
    total: [i64; 4],
    held: [i64; 4],
    provisioning_profile: String,
}

#[derive(Clone, Copy, Debug)]
enum BindingField {
    ScopeId,
    TaskLeaseDigest,
    AllowanceBindingDigest,
    ScopeGeneration,
    CurrencyCode,
    PriceTableId,
    Total(usize),
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn exact_input(total: [u64; 4]) -> TrustedBudgetScopeInputV1<'static> {
    TrustedBudgetScopeInputV1 {
        scope_id: digest(1),
        task_lease_digest: digest(2),
        allowance_binding_digest: digest(3),
        scope_generation: 1,
        currency_code: "EUR",
        price_table_id: "price-table:t039-v1",
        total,
    }
}

fn conflicting_input(field: BindingField) -> TrustedBudgetScopeInputV1<'static> {
    let mut input = exact_input([10, 20, 30, 40]);
    match field {
        BindingField::ScopeId => input.scope_id = digest(11),
        BindingField::TaskLeaseDigest => input.task_lease_digest = digest(12),
        BindingField::AllowanceBindingDigest => input.allowance_binding_digest = digest(13),
        BindingField::ScopeGeneration => input.scope_generation = 2,
        BindingField::CurrencyCode => input.currency_code = "USD",
        BindingField::PriceTableId => input.price_table_id = "price-table:t039-v2",
        BindingField::Total(dimension) => input.total[dimension] += 1,
    }
    input
}

fn database() -> Connection {
    let connection = Connection::open_in_memory().expect("in-memory coordinator opens");
    connection
        .execute_batch(STORE_SCHEMA)
        .expect("reviewed coordinator schema installs");
    connection
        .execute(
            "INSERT INTO coordinator_store_meta (
                 singleton, format_version, store_generation, operation_generation,
                 budget_generation, event_generation, quarantine_generation, root_identity,
                 root_lifecycle_state, restore_identity_digest, restore_attestation_digest,
                 restore_state_generation
             ) VALUES (1, 1, 0, 0, 0, 0, 0, zeroblob(32), 'ACTIVE', NULL, NULL, 0)",
            [],
        )
        .expect("trusted empty coordinator metadata initializes");
    connection
}

fn read_only_scope(connection: &Connection) -> StoredScope {
    connection
        .query_row(
            "SELECT scope_id, task_lease_digest, allowance_binding_digest, scope_generation,
                    currency_code, price_table_id, total_cost_micro_units,
                    total_action_count, total_egress_bytes, total_recovery_bytes,
                    held_cost_micro_units, held_action_count, held_egress_bytes,
                    held_recovery_bytes, provisioning_profile
             FROM budget_scopes",
            [],
            |row| {
                Ok(StoredScope {
                    scope_id: row.get(0)?,
                    task_lease_digest: row.get(1)?,
                    allowance_binding_digest: row.get(2)?,
                    scope_generation: row.get(3)?,
                    currency_code: row.get(4)?,
                    price_table_id: row.get(5)?,
                    total: [row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?],
                    held: [row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?],
                    provisioning_profile: row.get(14)?,
                })
            },
        )
        .expect("exactly one scope reads")
}

fn assert_exact_scope(connection: &Connection, input: &TrustedBudgetScopeInputV1<'_>) {
    let expected_total = input.total.map(|value| value as i64);
    assert_eq!(
        read_only_scope(connection),
        StoredScope {
            scope_id: input.scope_id.as_bytes().to_vec(),
            task_lease_digest: input.task_lease_digest.as_bytes().to_vec(),
            allowance_binding_digest: input.allowance_binding_digest.as_bytes().to_vec(),
            scope_generation: input.scope_generation as i64,
            currency_code: input.currency_code.to_owned(),
            price_table_id: input.price_table_id.to_owned(),
            total: expected_total,
            held: [0; 4],
            provisioning_profile: "TRUSTED_LEASE_V1".to_owned(),
        }
    );
}

fn scope_count(connection: &Connection) -> i64 {
    connection
        .query_row("SELECT COUNT(*) FROM budget_scopes", [], |row| row.get(0))
        .expect("scope count reads")
}

fn store_and_budget_generations(connection: &Connection) -> (i64, i64) {
    connection
        .query_row(
            "SELECT store_generation, budget_generation
             FROM coordinator_store_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("budget metadata generations read")
}

#[test]
fn trusted_scope_provisioning_is_create_only_exact_and_repeat_exact_idempotent() {
    let mut connection = database();
    let input = exact_input([10, 20, 30, 40]);

    assert_eq!(
        provision_trusted_budget_scope_v1(&mut connection, &input),
        BudgetScopeProvisionOutcomeV1::Created
    );
    assert_exact_scope(&connection, &input);
    assert_eq!(store_and_budget_generations(&connection), (1, 1));

    assert_eq!(
        provision_trusted_budget_scope_v1(&mut connection, &input),
        BudgetScopeProvisionOutcomeV1::AlreadyExact
    );
    assert_eq!(scope_count(&connection), 1);
    assert_exact_scope(&connection, &input);
    assert_eq!(store_and_budget_generations(&connection), (1, 1));
}

#[test]
fn every_scope_field_is_a_permanent_binding_and_conflicts_never_rewrite() {
    let mut connection = database();
    let exact = exact_input([10, 20, 30, 40]);
    assert_eq!(
        provision_trusted_budget_scope_v1(&mut connection, &exact),
        BudgetScopeProvisionOutcomeV1::Created
    );

    let fields = [
        BindingField::ScopeId,
        BindingField::TaskLeaseDigest,
        BindingField::AllowanceBindingDigest,
        BindingField::ScopeGeneration,
        BindingField::CurrencyCode,
        BindingField::PriceTableId,
        BindingField::Total(0),
        BindingField::Total(1),
        BindingField::Total(2),
        BindingField::Total(3),
    ];
    for field in fields {
        let conflict = conflicting_input(field);
        assert_eq!(
            provision_trusted_budget_scope_v1(&mut connection, &conflict),
            BudgetScopeProvisionOutcomeV1::BindingConflict,
            "field {field:?} must conflict"
        );
        assert_eq!(scope_count(&connection), 1, "field {field:?}");
        assert_exact_scope(&connection, &exact);
        assert_eq!(store_and_budget_generations(&connection), (1, 1));
    }

    assert_eq!(
        provision_trusted_budget_scope_v1(&mut connection, &exact),
        BudgetScopeProvisionOutcomeV1::AlreadyExact
    );
}

#[test]
fn exact_minus_one_and_plus_one_are_classified_for_each_dimension() {
    for dimension in 0..4 {
        let mut total = [0; 4];
        let mut held = [0; 4];
        total[dimension] = 10;
        held[dimension] = 3;

        let mut exact = [0; 4];
        exact[dimension] = 7;
        assert_eq!(
            checked_budget_reservation_v1(total, held, exact),
            Ok(total),
            "dimension {dimension} exact limit"
        );

        let mut minus_one = [0; 4];
        minus_one[dimension] = 6;
        let mut expected = held;
        expected[dimension] = 9;
        assert_eq!(
            checked_budget_reservation_v1(total, held, minus_one),
            Ok(expected),
            "dimension {dimension} minus one"
        );

        let mut plus_one = [0; 4];
        plus_one[dimension] = 8;
        assert_eq!(
            checked_budget_reservation_v1(total, held, plus_one),
            Err(BudgetVectorCheckErrorV1::Exhausted),
            "dimension {dimension} plus one"
        );
    }
}

#[test]
fn zero_and_maximum_safe_vectors_remain_exact_and_out_of_range_is_closed() {
    for total in [[0; 4], [MAX_SAFE_U64; 4]] {
        let mut connection = database();
        let input = exact_input(total);
        assert_eq!(
            provision_trusted_budget_scope_v1(&mut connection, &input),
            BudgetScopeProvisionOutcomeV1::Created
        );
        assert_exact_scope(&connection, &input);
        assert_eq!(
            checked_budget_reservation_v1(total, [0; 4], total),
            Ok(total)
        );
    }

    let mut outside_safe_range = [0; 4];
    outside_safe_range[2] = MAX_SAFE_U64 + 1;
    assert_eq!(
        checked_budget_reservation_v1([MAX_SAFE_U64; 4], [0; 4], outside_safe_range),
        Err(BudgetVectorCheckErrorV1::ArithmeticInvalid)
    );
}
