//! Portable root-lease restriction checks.
//!
//! This module compares already validated contract values only. It performs no I/O,
//! reads no ambient state and never treats a caller-provided bound as current state.

use helix_task_authority_contracts::{ResourceRootV1, RootTaskLeaseBoundsV1};

pub(crate) fn root_bounds_are_within_v1(
    requested: &RootTaskLeaseBoundsV1,
    ceiling: &RootTaskLeaseBoundsV1,
) -> bool {
    let requested_budget = requested.budget_v1();
    let ceiling_budget = ceiling.budget_v1();
    if requested_budget.read_bytes_limit_v1().get() > ceiling_budget.read_bytes_limit_v1().get()
        || requested_budget.distinct_files_limit_v1().get()
            > ceiling_budget.distinct_files_limit_v1().get()
        || requested_budget.action_limit_v1().get() > ceiling_budget.action_limit_v1().get()
        || requested_budget.egress_bytes_limit_v1().get()
            > ceiling_budget.egress_bytes_limit_v1().get()
        || requested_budget.max_cost_micro_units_v1().get()
            > ceiling_budget.max_cost_micro_units_v1().get()
        || requested_budget.currency_code_v1() != ceiling_budget.currency_code_v1()
        || requested_budget.price_table_id_v1() != ceiling_budget.price_table_id_v1()
    {
        return false;
    }

    let requested_counters = requested.counter_limits_v1();
    let ceiling_counters = ceiling.counter_limits_v1();
    if requested_counters.plan_limit_v1().get() > ceiling_counters.plan_limit_v1().get()
        || requested_counters.approval_limit_v1().get() > ceiling_counters.approval_limit_v1().get()
        || requested_counters.child_lease_limit_v1().get()
            > ceiling_counters.child_lease_limit_v1().get()
        || requested_counters.max_delegation_depth_v1().get()
            > ceiling_counters.max_delegation_depth_v1().get()
    {
        return false;
    }

    let requested_trust = requested.trust_bound_v1();
    let ceiling_trust = ceiling.trust_bound_v1();
    if !ceiling_trust
        .maximum_risk_level_v1()
        .permits(requested_trust.maximum_risk_level_v1())
        || !ceiling_trust
            .minimum_authentication_profile_v1()
            .permits(requested_trust.minimum_authentication_profile_v1())
        || requested_trust.policy_id_v1() != ceiling_trust.policy_id_v1()
        || requested_trust.policy_content_digest_v1() != ceiling_trust.policy_content_digest_v1()
        || requested_trust.policy_generation_v1() != ceiling_trust.policy_generation_v1()
    {
        return false;
    }

    let requested_catalogue = requested.catalogue_bound_v1();
    let ceiling_catalogue = ceiling.catalogue_bound_v1();
    if requested_catalogue.catalogue_id_v1() != ceiling_catalogue.catalogue_id_v1()
        || requested_catalogue.catalogue_content_digest_v1()
            != ceiling_catalogue.catalogue_content_digest_v1()
        || requested_catalogue.catalogue_generation_v1()
            != ceiling_catalogue.catalogue_generation_v1()
        || !is_identifier_subset_v1(
            requested_catalogue.allowed_catalogue_entries_v1(),
            ceiling_catalogue.allowed_catalogue_entries_v1(),
        )
        || (!ceiling.delegation_mode_v1().is_delegable()
            && requested.delegation_mode_v1().is_delegable())
    {
        return false;
    }

    requested.resource_roots_v1().iter().all(|root| {
        ceiling
            .resource_roots_v1()
            .iter()
            .any(|bound| resource_is_within_v1(root, bound))
    })
}

fn is_identifier_subset_v1(
    requested: &[helix_task_authority_contracts::Identifier],
    ceiling: &[helix_task_authority_contracts::Identifier],
) -> bool {
    requested.iter().all(|candidate| {
        ceiling
            .binary_search_by(|bound| bound.as_str().cmp(candidate.as_str()))
            .is_ok()
    })
}

fn resource_is_within_v1(requested: &ResourceRootV1, ceiling: &ResourceRootV1) -> bool {
    requested.root_id() == ceiling.root_id()
        && requested.components().len() >= ceiling.components().len()
        && requested.components().iter().zip(ceiling.components()).all(
            |(requested_component, ceiling_component)| requested_component == ceiling_component,
        )
}
