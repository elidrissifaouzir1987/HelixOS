-- HelixOS coordinator preparation store schema v1.
--
-- The implementation executes these statements inside an empty-to-v1 initialization
-- writer transaction after establishing and verifying WAL + synchronous FULL on a
-- dedicated, provisioner-attested local coordinator root. Application code additionally
-- verifies exact schema/index SQL and all cross-table invariants on open/maintenance.
-- In the same empty-to-v1 transaction, application code generates a fresh root identity
-- with the pinned OS-randomness provider and inserts the sole coordinator_store_meta row
-- as ACTIVE with null restore digests and restore_state_generation = 0. The value cannot
-- be represented as a static literal in this reviewed DDL contract.

PRAGMA application_id = 1212962883; -- 0x484c5843, "HLXC"
PRAGMA user_version = 1;
PRAGMA recursive_triggers = ON;

CREATE TABLE coordinator_store_meta (
    singleton INTEGER NOT NULL,
    format_version INTEGER NOT NULL,
    store_generation INTEGER NOT NULL,
    operation_generation INTEGER NOT NULL,
    budget_generation INTEGER NOT NULL,
    event_generation INTEGER NOT NULL,
    quarantine_generation INTEGER NOT NULL,
    root_identity BLOB NOT NULL,
    root_lifecycle_state TEXT COLLATE BINARY NOT NULL,
    restore_identity_digest BLOB,
    restore_attestation_digest BLOB,
    restore_state_generation INTEGER NOT NULL,
    CONSTRAINT coordinator_store_meta_pk PRIMARY KEY (singleton),
    CONSTRAINT coordinator_store_meta_singleton_ck CHECK (singleton = 1),
    CONSTRAINT coordinator_store_meta_format_ck CHECK (format_version = 1),
    CONSTRAINT coordinator_store_meta_store_generation_ck CHECK (
        store_generation BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT coordinator_store_meta_operation_generation_ck CHECK (
        operation_generation BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT coordinator_store_meta_budget_generation_ck CHECK (
        budget_generation BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT coordinator_store_meta_event_generation_ck CHECK (
        event_generation BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT coordinator_store_meta_quarantine_generation_ck CHECK (
        quarantine_generation BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT coordinator_store_meta_root_identity_ck CHECK (
        typeof(root_identity) = 'blob' AND length(root_identity) = 32
    ),
    CONSTRAINT coordinator_store_meta_root_lifecycle_ck CHECK (
        (root_lifecycle_state = 'ACTIVE'
         AND restore_identity_digest IS NULL
         AND restore_attestation_digest IS NULL
         AND restore_state_generation = 0)
        OR
        (root_lifecycle_state = 'RESTORE_PENDING'
         AND typeof(restore_identity_digest) = 'blob'
         AND length(restore_identity_digest) = 32
         AND typeof(restore_attestation_digest) = 'blob'
         AND length(restore_attestation_digest) = 32
         AND restore_state_generation BETWEEN 1 AND 9007199254740991
         AND restore_state_generation <= store_generation)
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER coordinator_store_meta_initial_insert_guard
BEFORE INSERT ON coordinator_store_meta
WHEN NEW.root_lifecycle_state <> 'ACTIVE'
     OR NEW.restore_identity_digest IS NOT NULL
     OR NEW.restore_attestation_digest IS NOT NULL
     OR NEW.restore_state_generation <> 0
BEGIN
    SELECT RAISE(ABORT, 'coordinator root must initialize ACTIVE');
END;

CREATE TRIGGER coordinator_store_meta_single_row_guard
BEFORE INSERT ON coordinator_store_meta
WHEN EXISTS (SELECT 1 FROM coordinator_store_meta)
BEGIN
    SELECT RAISE(ABORT, 'coordinator metadata row already exists');
END;

CREATE TRIGGER coordinator_store_meta_no_delete
BEFORE DELETE ON coordinator_store_meta
BEGIN
    SELECT RAISE(ABORT, 'coordinator metadata is permanent');
END;

CREATE TRIGGER coordinator_store_meta_root_transition_guard
BEFORE UPDATE OF
    root_identity,
    root_lifecycle_state,
    restore_identity_digest,
    restore_attestation_digest,
    restore_state_generation
ON coordinator_store_meta
WHEN NOT (
    (NEW.root_identity IS OLD.root_identity
     AND NEW.root_lifecycle_state IS OLD.root_lifecycle_state
     AND NEW.restore_identity_digest IS OLD.restore_identity_digest
     AND NEW.restore_attestation_digest IS OLD.restore_attestation_digest
     AND NEW.restore_state_generation IS OLD.restore_state_generation)
    OR
    (OLD.root_lifecycle_state = 'ACTIVE'
     AND NEW.root_lifecycle_state = 'RESTORE_PENDING'
     AND NEW.root_identity IS NOT OLD.root_identity
     AND NEW.store_generation > OLD.store_generation
     AND NEW.restore_state_generation = NEW.store_generation)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid coordinator root lifecycle transition');
END;

CREATE TABLE budget_scopes (
    scope_id BLOB NOT NULL,
    task_lease_digest BLOB NOT NULL,
    allowance_binding_digest BLOB NOT NULL,
    scope_generation INTEGER NOT NULL,
    currency_code TEXT COLLATE BINARY NOT NULL,
    price_table_id TEXT COLLATE BINARY NOT NULL,
    total_cost_micro_units INTEGER NOT NULL,
    total_action_count INTEGER NOT NULL,
    total_egress_bytes INTEGER NOT NULL,
    total_recovery_bytes INTEGER NOT NULL,
    held_cost_micro_units INTEGER NOT NULL,
    held_action_count INTEGER NOT NULL,
    held_egress_bytes INTEGER NOT NULL,
    held_recovery_bytes INTEGER NOT NULL,
    provisioning_profile TEXT COLLATE BINARY NOT NULL,
    CONSTRAINT budget_scopes_pk PRIMARY KEY (scope_id),
    CONSTRAINT budget_scopes_scope_id_ck CHECK (
        typeof(scope_id) = 'blob' AND length(scope_id) = 32
    ),
    CONSTRAINT budget_scopes_lease_digest_ck CHECK (
        typeof(task_lease_digest) = 'blob' AND length(task_lease_digest) = 32
    ),
    CONSTRAINT budget_scopes_allowance_digest_ck CHECK (
        typeof(allowance_binding_digest) = 'blob'
        AND length(allowance_binding_digest) = 32
    ),
    CONSTRAINT budget_scopes_generation_ck CHECK (
        scope_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT budget_scopes_currency_ck CHECK (
        typeof(currency_code) = 'text'
        AND length(CAST(currency_code AS BLOB)) = 3
        AND currency_code NOT GLOB '*[^A-Z]*'
    ),
    CONSTRAINT budget_scopes_price_table_ck CHECK (
        typeof(price_table_id) = 'text'
        AND length(CAST(price_table_id AS BLOB)) BETWEEN 1 AND 128
        AND price_table_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT budget_scopes_totals_ck CHECK (
        total_cost_micro_units BETWEEN 0 AND 9007199254740991
        AND total_action_count BETWEEN 0 AND 9007199254740991
        AND total_egress_bytes BETWEEN 0 AND 9007199254740991
        AND total_recovery_bytes BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT budget_scopes_held_ck CHECK (
        held_cost_micro_units BETWEEN 0 AND total_cost_micro_units
        AND held_action_count BETWEEN 0 AND total_action_count
        AND held_egress_bytes BETWEEN 0 AND total_egress_bytes
        AND held_recovery_bytes BETWEEN 0 AND total_recovery_bytes
    ),
    CONSTRAINT budget_scopes_profile_ck CHECK (
        provisioning_profile = 'TRUSTED_LEASE_V1'
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX budget_scopes_binding_uq
    ON budget_scopes (
        task_lease_digest,
        allowance_binding_digest,
        scope_generation,
        currency_code,
        price_table_id
    );

CREATE UNIQUE INDEX budget_scopes_generation_uq
    ON budget_scopes (scope_generation);

CREATE TRIGGER budget_scopes_no_delete
BEFORE DELETE ON budget_scopes
BEGIN
    SELECT RAISE(ABORT, 'budget scope history is permanent');
END;

CREATE TABLE prepared_operations (
    operation_id TEXT COLLATE BINARY NOT NULL,
    attempt_id BLOB NOT NULL,
    plan_id BLOB NOT NULL,
    task_id TEXT COLLATE BINARY NOT NULL,
    workload_id TEXT COLLATE BINARY NOT NULL,
    canonical_plan BLOB NOT NULL,
    canonical_plan_length INTEGER NOT NULL,
    operation_state TEXT COLLATE BINARY NOT NULL,
    state_generation INTEGER NOT NULL,
    created_generation INTEGER NOT NULL,
    failed_generation INTEGER,
    failed_reason_code TEXT COLLATE BINARY,
    boot_id TEXT COLLATE BINARY NOT NULL,
    instance_epoch INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    effective_expires_at_utc_ms INTEGER NOT NULL,
    effective_deadline_monotonic_ms INTEGER NOT NULL,
    reservation_id TEXT COLLATE BINARY NOT NULL,
    recovery_mode TEXT COLLATE BINARY NOT NULL,
    current_event_id BLOB NOT NULL,
    restored_source_generation INTEGER,
    CONSTRAINT prepared_operations_pk PRIMARY KEY (operation_id),
    CONSTRAINT prepared_operations_current_transition_fk FOREIGN KEY (
        operation_id,
        state_generation,
        current_event_id,
        operation_state
    ) REFERENCES operation_transitions (
        operation_id,
        state_generation,
        event_id,
        new_state
    )
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT prepared_operations_operation_id_ck CHECK (
        typeof(operation_id) = 'text'
        AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128
        AND operation_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT prepared_operations_attempt_id_ck CHECK (
        typeof(attempt_id) = 'blob' AND length(attempt_id) = 32
    ),
    CONSTRAINT prepared_operations_plan_id_ck CHECK (
        typeof(plan_id) = 'blob' AND length(plan_id) = 32
    ),
    CONSTRAINT prepared_operations_task_id_ck CHECK (
        typeof(task_id) = 'text'
        AND length(CAST(task_id AS BLOB)) BETWEEN 1 AND 128
        AND task_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT prepared_operations_workload_id_ck CHECK (
        typeof(workload_id) = 'text'
        AND length(CAST(workload_id AS BLOB)) BETWEEN 1 AND 128
        AND workload_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT prepared_operations_canonical_plan_ck CHECK (
        typeof(canonical_plan) = 'blob'
        AND canonical_plan_length = length(canonical_plan)
        AND canonical_plan_length BETWEEN 1 AND 1048576
    ),
    CONSTRAINT prepared_operations_state_ck CHECK (
        operation_state IN ('PREPARING', 'FAILED')
    ),
    CONSTRAINT prepared_operations_generations_ck CHECK (
        state_generation BETWEEN 1 AND 9007199254740991
        AND created_generation BETWEEN 1 AND 9007199254740991
        AND (failed_generation IS NULL
             OR failed_generation BETWEEN 1 AND 9007199254740991)
    ),
    CONSTRAINT prepared_operations_failure_ck CHECK (
        (operation_state = 'PREPARING'
         AND failed_generation IS NULL
         AND failed_reason_code IS NULL)
        OR
        (operation_state = 'FAILED'
         AND failed_generation IS NOT NULL
         AND failed_reason_code IS NOT NULL
         AND length(CAST(failed_reason_code AS BLOB)) BETWEEN 1 AND 64
         AND failed_reason_code NOT GLOB '*[^A-Z0-9_]*')
    ),
    CONSTRAINT prepared_operations_boot_id_ck CHECK (
        typeof(boot_id) = 'text'
        AND length(CAST(boot_id AS BLOB)) BETWEEN 1 AND 128
        AND boot_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT prepared_operations_epochs_ck CHECK (
        instance_epoch BETWEEN 0 AND 9007199254740991
        AND fencing_epoch BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT prepared_operations_bounds_ck CHECK (
        effective_expires_at_utc_ms BETWEEN 0 AND 9007199254740991
        AND effective_deadline_monotonic_ms BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT prepared_operations_reservation_id_ck CHECK (
        typeof(reservation_id) = 'text'
        AND length(CAST(reservation_id AS BLOB)) BETWEEN 1 AND 128
        AND reservation_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT prepared_operations_recovery_mode_ck CHECK (
        recovery_mode IN ('COMPENSATION', 'IRREVERSIBLE')
    ),
    CONSTRAINT prepared_operations_event_id_ck CHECK (
        typeof(current_event_id) = 'blob' AND length(current_event_id) = 32
    ),
    CONSTRAINT prepared_operations_restore_generation_ck CHECK (
        restored_source_generation IS NULL
        OR restored_source_generation BETWEEN 0 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX prepared_operations_attempt_id_uq
    ON prepared_operations (attempt_id);

CREATE UNIQUE INDEX prepared_operations_plan_id_uq
    ON prepared_operations (plan_id);

CREATE UNIQUE INDEX prepared_operations_reservation_id_uq
    ON prepared_operations (reservation_id);

CREATE UNIQUE INDEX prepared_operations_state_generation_uq
    ON prepared_operations (state_generation);

CREATE TRIGGER prepared_operations_no_delete
BEFORE DELETE ON prepared_operations
BEGIN
    SELECT RAISE(ABORT, 'prepared operation history is permanent');
END;

CREATE TABLE operation_transitions (
    state_generation INTEGER NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    previous_state TEXT COLLATE BINARY,
    new_state TEXT COLLATE BINARY NOT NULL,
    event_id BLOB NOT NULL,
    CONSTRAINT operation_transitions_pk PRIMARY KEY (state_generation),
    CONSTRAINT operation_transitions_operation_fk FOREIGN KEY (operation_id)
        REFERENCES prepared_operations (operation_id) ON DELETE RESTRICT,
    CONSTRAINT operation_transitions_event_fk FOREIGN KEY (event_id)
        REFERENCES preparation_events (event_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT operation_transitions_generation_ck CHECK (
        state_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT operation_transitions_event_id_ck CHECK (
        typeof(event_id) = 'blob' AND length(event_id) = 32
    ),
    CONSTRAINT operation_transitions_state_ck CHECK (
        (previous_state IS NULL AND new_state = 'PREPARING')
        OR (previous_state = 'PREPARING' AND new_state = 'FAILED')
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX operation_transitions_event_uq
    ON operation_transitions (event_id);

CREATE UNIQUE INDEX operation_transitions_operation_state_uq
    ON operation_transitions (operation_id, new_state);

CREATE UNIQUE INDEX operation_transitions_complete_identity_uq
    ON operation_transitions (
        operation_id,
        state_generation,
        event_id,
        new_state
    );

CREATE TRIGGER operation_transitions_no_delete
BEFORE DELETE ON operation_transitions
BEGIN
    SELECT RAISE(ABORT, 'operation transition history is permanent');
END;

CREATE TABLE preparation_comparisons (
    operation_id TEXT COLLATE BINARY NOT NULL,
    comparison_version INTEGER NOT NULL,
    capture_generation INTEGER NOT NULL,
    clock_generation INTEGER NOT NULL,
    plan_deadline_generation INTEGER NOT NULL,
    supervisor_generation INTEGER NOT NULL,
    admission_state TEXT COLLATE BINARY NOT NULL,
    instance_epoch INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    trust_generation INTEGER NOT NULL,
    verified_key_fingerprint BLOB NOT NULL,
    workload_generation INTEGER NOT NULL,
    workload_evidence_digest BLOB NOT NULL,
    lease_generation INTEGER NOT NULL,
    lease_digest BLOB NOT NULL,
    lease_decision_digest BLOB NOT NULL,
    authorization_generation INTEGER NOT NULL,
    authorization_evidence_digest BLOB NOT NULL,
    policy_generation INTEGER NOT NULL,
    policy_decision_generation INTEGER NOT NULL,
    policy_content_digest BLOB NOT NULL,
    policy_decision_digest BLOB NOT NULL,
    catalogue_generation INTEGER NOT NULL,
    catalogue_decision_generation INTEGER NOT NULL,
    catalogue_content_digest BLOB NOT NULL,
    catalogue_decision_digest BLOB NOT NULL,
    capability_generation INTEGER NOT NULL,
    capability_report_digest BLOB NOT NULL,
    host_driver_context_digest BLOB NOT NULL,
    eligible_evaluated_at_utc_ms INTEGER NOT NULL,
    eligible_evaluated_at_monotonic_ms INTEGER NOT NULL,
    final_sample_utc_ms INTEGER NOT NULL,
    final_sample_monotonic_ms INTEGER NOT NULL,
    capability_observed_at_utc_ms INTEGER NOT NULL,
    capability_max_age_ms INTEGER NOT NULL,
    replay_claim_id BLOB NOT NULL,
    replay_claimant_generation INTEGER NOT NULL,
    replay_binding_digest BLOB NOT NULL,
    budget_scope_id BLOB NOT NULL,
    budget_scope_generation INTEGER NOT NULL,
    recovery_provider_generation INTEGER,
    comparison_digest BLOB NOT NULL,
    CONSTRAINT preparation_comparisons_pk PRIMARY KEY (operation_id),
    CONSTRAINT preparation_comparisons_operation_fk FOREIGN KEY (operation_id)
        REFERENCES prepared_operations (operation_id) ON DELETE RESTRICT,
    CONSTRAINT preparation_comparisons_version_ck CHECK (comparison_version = 1),
    CONSTRAINT preparation_comparisons_admission_ck CHECK (admission_state = 'OPEN'),
    CONSTRAINT preparation_comparisons_generations_ck CHECK (
        capture_generation BETWEEN 0 AND 9007199254740991
        AND clock_generation BETWEEN 0 AND 9007199254740991
        AND plan_deadline_generation BETWEEN 0 AND 9007199254740991
        AND supervisor_generation BETWEEN 0 AND 9007199254740991
        AND instance_epoch BETWEEN 0 AND 9007199254740991
        AND fencing_epoch BETWEEN 0 AND 9007199254740991
        AND trust_generation BETWEEN 0 AND 9007199254740991
        AND workload_generation BETWEEN 0 AND 9007199254740991
        AND lease_generation BETWEEN 0 AND 9007199254740991
        AND authorization_generation BETWEEN 0 AND 9007199254740991
        AND policy_generation BETWEEN 0 AND 9007199254740991
        AND policy_decision_generation BETWEEN 0 AND 9007199254740991
        AND catalogue_generation BETWEEN 0 AND 9007199254740991
        AND catalogue_decision_generation BETWEEN 0 AND 9007199254740991
        AND capability_generation BETWEEN 0 AND 9007199254740991
        AND replay_claimant_generation BETWEEN 1 AND 9007199254740991
        AND budget_scope_generation BETWEEN 1 AND 9007199254740991
        AND (recovery_provider_generation IS NULL
             OR recovery_provider_generation BETWEEN 1 AND 9007199254740991)
    ),
    CONSTRAINT preparation_comparisons_time_ck CHECK (
        eligible_evaluated_at_utc_ms BETWEEN 0 AND 9007199254740991
        AND eligible_evaluated_at_monotonic_ms BETWEEN 0 AND 9007199254740991
        AND final_sample_utc_ms BETWEEN 0 AND 9007199254740991
        AND final_sample_monotonic_ms BETWEEN 0 AND 9007199254740991
        AND capability_observed_at_utc_ms BETWEEN 0 AND 9007199254740991
        AND capability_max_age_ms BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT preparation_comparisons_digests_ck CHECK (
        typeof(verified_key_fingerprint) = 'blob' AND length(verified_key_fingerprint) = 32
        AND typeof(workload_evidence_digest) = 'blob' AND length(workload_evidence_digest) = 32
        AND typeof(lease_digest) = 'blob' AND length(lease_digest) = 32
        AND typeof(lease_decision_digest) = 'blob' AND length(lease_decision_digest) = 32
        AND typeof(authorization_evidence_digest) = 'blob' AND length(authorization_evidence_digest) = 32
        AND typeof(policy_content_digest) = 'blob' AND length(policy_content_digest) = 32
        AND typeof(policy_decision_digest) = 'blob' AND length(policy_decision_digest) = 32
        AND typeof(catalogue_content_digest) = 'blob' AND length(catalogue_content_digest) = 32
        AND typeof(catalogue_decision_digest) = 'blob' AND length(catalogue_decision_digest) = 32
        AND typeof(capability_report_digest) = 'blob' AND length(capability_report_digest) = 32
        AND typeof(host_driver_context_digest) = 'blob' AND length(host_driver_context_digest) = 32
        AND typeof(replay_claim_id) = 'blob' AND length(replay_claim_id) = 32
        AND typeof(replay_binding_digest) = 'blob' AND length(replay_binding_digest) = 32
        AND typeof(budget_scope_id) = 'blob' AND length(budget_scope_id) = 32
        AND typeof(comparison_digest) = 'blob' AND length(comparison_digest) = 32
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX preparation_comparisons_digest_uq
    ON preparation_comparisons (comparison_digest);

CREATE TRIGGER preparation_comparisons_no_delete
BEFORE DELETE ON preparation_comparisons
BEGIN
    SELECT RAISE(ABORT, 'preparation comparison history is permanent');
END;

CREATE TABLE budget_reservations (
    reservation_id TEXT COLLATE BINARY NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    attempt_id BLOB NOT NULL,
    plan_id BLOB NOT NULL,
    scope_id BLOB NOT NULL,
    task_lease_digest BLOB NOT NULL,
    budget_generation INTEGER NOT NULL,
    currency_code TEXT COLLATE BINARY NOT NULL,
    price_table_id TEXT COLLATE BINARY NOT NULL,
    reserved_cost_micro_units INTEGER NOT NULL,
    reserved_action_count INTEGER NOT NULL,
    reserved_egress_bytes INTEGER NOT NULL,
    reserved_recovery_bytes INTEGER NOT NULL,
    reservation_state TEXT COLLATE BINARY NOT NULL,
    created_generation INTEGER NOT NULL,
    released_generation INTEGER,
    CONSTRAINT budget_reservations_pk PRIMARY KEY (reservation_id),
    CONSTRAINT budget_reservations_operation_fk FOREIGN KEY (operation_id)
        REFERENCES prepared_operations (operation_id) ON DELETE RESTRICT,
    CONSTRAINT budget_reservations_scope_fk FOREIGN KEY (scope_id)
        REFERENCES budget_scopes (scope_id) ON DELETE RESTRICT,
    CONSTRAINT budget_reservations_reservation_id_ck CHECK (
        typeof(reservation_id) = 'text'
        AND length(CAST(reservation_id AS BLOB)) BETWEEN 1 AND 128
        AND reservation_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT budget_reservations_attempt_id_ck CHECK (
        typeof(attempt_id) = 'blob' AND length(attempt_id) = 32
    ),
    CONSTRAINT budget_reservations_plan_id_ck CHECK (
        typeof(plan_id) = 'blob' AND length(plan_id) = 32
    ),
    CONSTRAINT budget_reservations_lease_digest_ck CHECK (
        typeof(task_lease_digest) = 'blob' AND length(task_lease_digest) = 32
    ),
    CONSTRAINT budget_reservations_generation_ck CHECK (
        budget_generation BETWEEN 1 AND 9007199254740991
        AND created_generation BETWEEN 1 AND 9007199254740991
        AND (released_generation IS NULL
             OR released_generation BETWEEN 1 AND 9007199254740991)
    ),
    CONSTRAINT budget_reservations_currency_ck CHECK (
        typeof(currency_code) = 'text'
        AND length(CAST(currency_code AS BLOB)) = 3
        AND currency_code NOT GLOB '*[^A-Z]*'
    ),
    CONSTRAINT budget_reservations_price_table_ck CHECK (
        typeof(price_table_id) = 'text'
        AND length(CAST(price_table_id AS BLOB)) BETWEEN 1 AND 128
        AND price_table_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT budget_reservations_vector_ck CHECK (
        reserved_cost_micro_units BETWEEN 0 AND 9007199254740991
        AND reserved_action_count BETWEEN 0 AND 9007199254740991
        AND reserved_egress_bytes BETWEEN 0 AND 9007199254740991
        AND reserved_recovery_bytes BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT budget_reservations_state_ck CHECK (
        (reservation_state = 'HELD' AND released_generation IS NULL)
        OR (reservation_state = 'RELEASED' AND released_generation IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX budget_reservations_operation_uq
    ON budget_reservations (operation_id);

CREATE UNIQUE INDEX budget_reservations_attempt_uq
    ON budget_reservations (attempt_id);

CREATE TRIGGER budget_reservations_no_delete
BEFORE DELETE ON budget_reservations
BEGIN
    SELECT RAISE(ABORT, 'budget reservation history is permanent');
END;

CREATE TABLE preparation_recovery_evidence (
    operation_id TEXT COLLATE BINARY NOT NULL,
    evidence_version INTEGER NOT NULL,
    recovery_mode TEXT COLLATE BINARY NOT NULL,
    recovery_class TEXT COLLATE BINARY NOT NULL,
    atomicity TEXT COLLATE BINARY NOT NULL,
    risk_level TEXT COLLATE BINARY NOT NULL,
    target_reference_digest BLOB NOT NULL,
    precondition_identity_digest BLOB NOT NULL,
    precondition_digest BLOB NOT NULL,
    precondition_length INTEGER NOT NULL,
    reserved_capacity INTEGER NOT NULL,
    provider_profile_id TEXT COLLATE BINARY,
    provider_profile_version INTEGER,
    provider_id TEXT COLLATE BINARY,
    provider_generation INTEGER,
    evidence_class TEXT COLLATE BINARY,
    at_rest_profile_id TEXT COLLATE BINARY,
    capability_binding_digest BLOB,
    material_id BLOB,
    publication_attempt_id BLOB,
    manifest_digest BLOB,
    material_digest BLOB,
    material_length INTEGER,
    material_state TEXT COLLATE BINARY,
    retirement_id BLOB,
    retirement_manifest_digest BLOB,
    retirement_generation INTEGER,
    boot_binding_digest BLOB NOT NULL,
    instance_epoch INTEGER NOT NULL,
    fencing_epoch INTEGER NOT NULL,
    CONSTRAINT preparation_recovery_evidence_pk PRIMARY KEY (operation_id),
    CONSTRAINT preparation_recovery_evidence_operation_fk FOREIGN KEY (operation_id)
        REFERENCES prepared_operations (operation_id) ON DELETE RESTRICT,
    CONSTRAINT preparation_recovery_evidence_version_ck CHECK (evidence_version = 1),
    CONSTRAINT preparation_recovery_evidence_mode_ck CHECK (
        recovery_mode IN ('COMPENSATION', 'IRREVERSIBLE')
        AND recovery_class = recovery_mode
    ),
    CONSTRAINT preparation_recovery_evidence_atomicity_ck CHECK (
        atomicity IN ('ATOMIC_REPLACE', 'NON_ATOMIC')
    ),
    CONSTRAINT preparation_recovery_evidence_risk_ck CHECK (
        risk_level IN ('L0', 'L1', 'L2')
        AND (recovery_mode <> 'IRREVERSIBLE' OR risk_level = 'L2')
    ),
    CONSTRAINT preparation_recovery_evidence_target_ck CHECK (
        typeof(target_reference_digest) = 'blob' AND length(target_reference_digest) = 32
        AND typeof(precondition_identity_digest) = 'blob'
        AND length(precondition_identity_digest) = 32
        AND typeof(precondition_digest) = 'blob' AND length(precondition_digest) = 32
        AND typeof(boot_binding_digest) = 'blob' AND length(boot_binding_digest) = 32
    ),
    CONSTRAINT preparation_recovery_evidence_bounds_ck CHECK (
        precondition_length BETWEEN 0 AND 9007199254740991
        AND reserved_capacity BETWEEN 0 AND 9007199254740991
        AND instance_epoch BETWEEN 0 AND 9007199254740991
        AND fencing_epoch BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT preparation_recovery_evidence_compensation_ck CHECK (
        (recovery_mode = 'COMPENSATION'
         AND provider_profile_id IS NOT NULL
         AND length(CAST(provider_profile_id AS BLOB)) BETWEEN 1 AND 128
         AND provider_profile_id NOT GLOB '*[^-A-Za-z0-9._:]*'
         AND provider_profile_version IS NOT NULL
         AND provider_profile_version = 1
         AND provider_id IS NOT NULL
         AND length(CAST(provider_id AS BLOB)) BETWEEN 1 AND 128
         AND provider_id NOT GLOB '*[^-A-Za-z0-9._:]*'
         AND provider_generation IS NOT NULL
         AND provider_generation BETWEEN 1 AND 9007199254740991
         AND evidence_class IS NOT NULL
         AND length(CAST(evidence_class AS BLOB)) BETWEEN 1 AND 64
         AND evidence_class NOT GLOB '*[^A-Z0-9_]*'
         AND at_rest_profile_id IS NOT NULL
         AND length(CAST(at_rest_profile_id AS BLOB)) BETWEEN 1 AND 128
         AND at_rest_profile_id NOT GLOB '*[^-A-Za-z0-9._:]*'
         AND typeof(capability_binding_digest) = 'blob' AND length(capability_binding_digest) = 32
         AND typeof(material_id) = 'blob' AND length(material_id) = 32
         AND typeof(publication_attempt_id) = 'blob' AND length(publication_attempt_id) = 32
         AND typeof(manifest_digest) = 'blob' AND length(manifest_digest) = 32
         AND typeof(material_digest) = 'blob' AND length(material_digest) = 32
         AND material_digest = precondition_digest
         AND material_length IS NOT NULL
         AND material_length = precondition_length
         AND material_length BETWEEN 0 AND 9007199254740991
         AND reserved_capacity >= material_length
         AND material_state IS NOT NULL
         AND (
             (material_state = 'PUBLISHED'
              AND retirement_id IS NULL
              AND retirement_manifest_digest IS NULL
              AND retirement_generation IS NULL)
             OR
             (material_state = 'RETIREMENT_PENDING'
              AND typeof(retirement_id) = 'blob' AND length(retirement_id) = 32
              AND retirement_manifest_digest IS NULL
              AND retirement_generation BETWEEN 1 AND 9007199254740991)
             OR
             (material_state = 'RETIRED_TOMBSTONE'
              AND typeof(retirement_id) = 'blob' AND length(retirement_id) = 32
              AND typeof(retirement_manifest_digest) = 'blob'
              AND length(retirement_manifest_digest) = 32
              AND retirement_generation BETWEEN 1 AND 9007199254740991)
         ))
        OR
        (recovery_mode = 'IRREVERSIBLE'
         AND provider_profile_id IS NULL
         AND provider_profile_version IS NULL
         AND provider_id IS NULL
         AND provider_generation IS NULL
         AND evidence_class IS NULL
         AND at_rest_profile_id IS NULL
         AND capability_binding_digest IS NULL
         AND material_id IS NULL
         AND publication_attempt_id IS NULL
         AND manifest_digest IS NULL
         AND material_digest IS NULL
         AND material_length IS NULL
         AND material_state IS NULL
         AND retirement_id IS NULL
         AND retirement_manifest_digest IS NULL
         AND retirement_generation IS NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX preparation_recovery_material_uq
    ON preparation_recovery_evidence (material_id)
    WHERE material_id IS NOT NULL;

CREATE UNIQUE INDEX preparation_recovery_manifest_uq
    ON preparation_recovery_evidence (manifest_digest)
    WHERE manifest_digest IS NOT NULL;

CREATE UNIQUE INDEX preparation_recovery_retirement_uq
    ON preparation_recovery_evidence (retirement_id)
    WHERE retirement_id IS NOT NULL;

CREATE UNIQUE INDEX preparation_recovery_retirement_manifest_uq
    ON preparation_recovery_evidence (retirement_manifest_digest)
    WHERE retirement_manifest_digest IS NOT NULL;

CREATE TRIGGER preparation_recovery_evidence_no_delete
BEFORE DELETE ON preparation_recovery_evidence
BEGIN
    SELECT RAISE(ABORT, 'recovery evidence history is permanent');
END;

CREATE TABLE preparation_events (
    event_id BLOB NOT NULL,
    event_generation INTEGER NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    operation_state_generation INTEGER NOT NULL,
    operation_state TEXT COLLATE BINARY NOT NULL,
    event_kind TEXT COLLATE BINARY NOT NULL,
    reason_code TEXT COLLATE BINARY,
    delivery_state TEXT COLLATE BINARY NOT NULL,
    delivered_generation INTEGER,
    CONSTRAINT preparation_events_pk PRIMARY KEY (event_id),
    CONSTRAINT preparation_events_transition_fk FOREIGN KEY (
        operation_id,
        operation_state_generation,
        event_id,
        operation_state
    ) REFERENCES operation_transitions (
        operation_id,
        state_generation,
        event_id,
        new_state
    ) ON DELETE RESTRICT,
    CONSTRAINT preparation_events_event_id_ck CHECK (
        typeof(event_id) = 'blob' AND length(event_id) = 32
    ),
    CONSTRAINT preparation_events_generation_ck CHECK (
        event_generation BETWEEN 1 AND 9007199254740991
        AND operation_state_generation BETWEEN 1 AND 9007199254740991
        AND (delivered_generation IS NULL
             OR delivered_generation BETWEEN 1 AND 9007199254740991)
    ),
    CONSTRAINT preparation_events_kind_ck CHECK (
        (event_kind = 'PREPARED'
         AND operation_state = 'PREPARING'
         AND reason_code IS NULL)
        OR
        (event_kind = 'PREPARATION_FAILED'
         AND operation_state = 'FAILED'
         AND reason_code IS NOT NULL
         AND length(CAST(reason_code AS BLOB)) BETWEEN 1 AND 64
         AND reason_code NOT GLOB '*[^A-Z0-9_]*')
    ),
    CONSTRAINT preparation_events_delivery_ck CHECK (
        (delivery_state = 'PENDING' AND delivered_generation IS NULL)
        OR (delivery_state = 'DELIVERED' AND delivered_generation IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX preparation_events_generation_uq
    ON preparation_events (event_generation);

CREATE UNIQUE INDEX preparation_events_transition_uq
    ON preparation_events (operation_id, operation_state_generation);

CREATE TRIGGER preparation_events_no_delete
BEFORE DELETE ON preparation_events
BEGIN
    SELECT RAISE(ABORT, 'preparation event history is permanent');
END;

CREATE TABLE preparation_quarantines (
    quarantine_id BLOB NOT NULL,
    attempt_id BLOB,
    operation_binding_digest BLOB NOT NULL,
    quarantine_reason TEXT COLLATE BINARY NOT NULL,
    quarantine_status TEXT COLLATE BINARY NOT NULL,
    created_generation INTEGER NOT NULL,
    resolved_generation INTEGER,
    recovery_manifest_digest BLOB,
    orphan_resolution_evidence_digest BLOB,
    orphan_retirement_id BLOB,
    orphan_retirement_state TEXT COLLATE BINARY,
    orphan_retired_generation INTEGER,
    orphan_retirement_manifest_digest BLOB,
    CONSTRAINT preparation_quarantines_pk PRIMARY KEY (quarantine_id),
    CONSTRAINT preparation_quarantines_id_ck CHECK (
        typeof(quarantine_id) = 'blob' AND length(quarantine_id) = 32
    ),
    CONSTRAINT preparation_quarantines_attempt_ck CHECK (
        attempt_id IS NULL OR (typeof(attempt_id) = 'blob' AND length(attempt_id) = 32)
    ),
    CONSTRAINT preparation_quarantines_binding_ck CHECK (
        typeof(operation_binding_digest) = 'blob'
        AND length(operation_binding_digest) = 32
    ),
    CONSTRAINT preparation_quarantines_reason_ck CHECK (
        quarantine_reason IN (
            'AMBIGUOUS_COMMIT',
            'ORPHAN_MATERIAL',
            'RESTORED_OLD_AUTHORITY',
            'INVARIANT_CONFLICT',
            'STORE_UNHEALTHY'
        )
    ),
    CONSTRAINT preparation_quarantines_generation_ck CHECK (
        created_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT preparation_quarantines_manifest_ck CHECK (
        recovery_manifest_digest IS NULL
        OR (typeof(recovery_manifest_digest) = 'blob'
            AND length(recovery_manifest_digest) = 32)
    ),
    CONSTRAINT preparation_quarantines_orphan_identity_ck CHECK (
        quarantine_reason <> 'ORPHAN_MATERIAL'
        OR (attempt_id IS NOT NULL AND recovery_manifest_digest IS NOT NULL)
    ),
    CONSTRAINT preparation_quarantines_lifecycle_ck CHECK (
        (quarantine_status = 'ACTIVE'
         AND resolved_generation IS NULL
         AND orphan_resolution_evidence_digest IS NULL
         AND orphan_retirement_id IS NULL
         AND orphan_retirement_state IS NULL
         AND orphan_retired_generation IS NULL
         AND orphan_retirement_manifest_digest IS NULL)
        OR
        (quarantine_status = 'RESOLVED_TOMBSTONE'
         AND resolved_generation BETWEEN 1 AND 9007199254740991
         AND created_generation < resolved_generation
         AND quarantine_reason <> 'ORPHAN_MATERIAL'
         AND orphan_resolution_evidence_digest IS NULL
         AND orphan_retirement_id IS NULL
         AND orphan_retirement_state IS NULL
         AND orphan_retired_generation IS NULL
         AND orphan_retirement_manifest_digest IS NULL)
        OR
        (quarantine_status = 'RESOLVED_TOMBSTONE'
         AND resolved_generation BETWEEN 1 AND 9007199254740991
         AND created_generation < resolved_generation
         AND quarantine_reason = 'ORPHAN_MATERIAL'
         AND typeof(orphan_resolution_evidence_digest) = 'blob'
         AND length(orphan_resolution_evidence_digest) = 32
         AND typeof(orphan_retirement_id) = 'blob'
         AND length(orphan_retirement_id) = 32
         AND orphan_retirement_state = 'RETIREMENT_PENDING'
         AND orphan_retired_generation IS NULL
         AND orphan_retirement_manifest_digest IS NULL)
        OR
        (quarantine_status = 'RESOLVED_TOMBSTONE'
         AND resolved_generation BETWEEN 1 AND 9007199254740991
         AND created_generation < resolved_generation
         AND quarantine_reason = 'ORPHAN_MATERIAL'
         AND typeof(orphan_resolution_evidence_digest) = 'blob'
         AND length(orphan_resolution_evidence_digest) = 32
         AND typeof(orphan_retirement_id) = 'blob'
         AND length(orphan_retirement_id) = 32
         AND orphan_retirement_state = 'RETIRED_TOMBSTONE'
         AND orphan_retired_generation BETWEEN 1 AND 9007199254740991
         AND resolved_generation < orphan_retired_generation
         AND typeof(orphan_retirement_manifest_digest) = 'blob'
         AND length(orphan_retirement_manifest_digest) = 32)
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER preparation_quarantines_initial_state_guard
BEFORE INSERT ON preparation_quarantines
WHEN NEW.quarantine_status <> 'ACTIVE'
BEGIN
    SELECT RAISE(ABORT, 'quarantine must initialize ACTIVE');
END;

CREATE TRIGGER preparation_quarantines_insert_conflict_guard
BEFORE INSERT ON preparation_quarantines
WHEN EXISTS (
    SELECT 1
    FROM preparation_quarantines AS existing
    WHERE existing.quarantine_id = NEW.quarantine_id
       OR existing.created_generation = NEW.created_generation
       OR (NEW.attempt_id IS NOT NULL
           AND NEW.quarantine_status = 'ACTIVE'
           AND existing.attempt_id = NEW.attempt_id
           AND existing.quarantine_status = 'ACTIVE')
       OR (NEW.quarantine_reason = 'ORPHAN_MATERIAL'
           AND existing.quarantine_reason = 'ORPHAN_MATERIAL'
           AND existing.recovery_manifest_digest = NEW.recovery_manifest_digest)
       OR (NEW.orphan_retirement_id IS NOT NULL
           AND existing.orphan_retirement_id = NEW.orphan_retirement_id)
       OR (NEW.orphan_retirement_manifest_digest IS NOT NULL
           AND existing.orphan_retirement_manifest_digest
               = NEW.orphan_retirement_manifest_digest)
)
BEGIN
    SELECT RAISE(ABORT, 'quarantine key is permanently reserved');
END;

CREATE TRIGGER preparation_quarantines_no_delete
BEFORE DELETE ON preparation_quarantines
BEGIN
    SELECT RAISE(ABORT, 'quarantine evidence is permanent');
END;

CREATE TRIGGER preparation_quarantines_identity_guard
BEFORE UPDATE OF
    quarantine_id,
    attempt_id,
    operation_binding_digest,
    quarantine_reason,
    created_generation,
    recovery_manifest_digest
ON preparation_quarantines
WHEN NEW.quarantine_id IS NOT OLD.quarantine_id
     OR NEW.attempt_id IS NOT OLD.attempt_id
     OR NEW.operation_binding_digest IS NOT OLD.operation_binding_digest
     OR NEW.quarantine_reason IS NOT OLD.quarantine_reason
     OR NEW.created_generation IS NOT OLD.created_generation
     OR NEW.recovery_manifest_digest IS NOT OLD.recovery_manifest_digest
BEGIN
    SELECT RAISE(ABORT, 'quarantine identity is immutable');
END;

CREATE TRIGGER preparation_quarantines_update_conflict_guard
BEFORE UPDATE ON preparation_quarantines
WHEN EXISTS (
    SELECT 1
    FROM preparation_quarantines AS existing
    WHERE existing.quarantine_id <> OLD.quarantine_id
      AND (
          existing.quarantine_id = NEW.quarantine_id
          OR existing.created_generation = NEW.created_generation
          OR (NEW.attempt_id IS NOT NULL
              AND NEW.quarantine_status = 'ACTIVE'
              AND existing.attempt_id = NEW.attempt_id
              AND existing.quarantine_status = 'ACTIVE')
          OR (NEW.quarantine_reason = 'ORPHAN_MATERIAL'
              AND existing.quarantine_reason = 'ORPHAN_MATERIAL'
              AND existing.recovery_manifest_digest = NEW.recovery_manifest_digest)
          OR (NEW.orphan_retirement_id IS NOT NULL
              AND existing.orphan_retirement_id = NEW.orphan_retirement_id)
          OR (NEW.orphan_retirement_manifest_digest IS NOT NULL
              AND existing.orphan_retirement_manifest_digest
                  = NEW.orphan_retirement_manifest_digest)
      )
)
BEGIN
    SELECT RAISE(ABORT, 'quarantine key conflict cannot replace history');
END;

CREATE TRIGGER preparation_quarantines_transition_guard
BEFORE UPDATE OF
    quarantine_status,
    resolved_generation,
    orphan_resolution_evidence_digest,
    orphan_retirement_id,
    orphan_retirement_state,
    orphan_retired_generation,
    orphan_retirement_manifest_digest
ON preparation_quarantines
WHEN NOT (
    (NEW.quarantine_status IS OLD.quarantine_status
     AND NEW.resolved_generation IS OLD.resolved_generation
     AND NEW.orphan_resolution_evidence_digest
         IS OLD.orphan_resolution_evidence_digest
     AND NEW.orphan_retirement_id IS OLD.orphan_retirement_id
     AND NEW.orphan_retirement_state IS OLD.orphan_retirement_state
     AND NEW.orphan_retired_generation IS OLD.orphan_retired_generation
     AND NEW.orphan_retirement_manifest_digest
         IS OLD.orphan_retirement_manifest_digest)
    OR
    (OLD.quarantine_status = 'ACTIVE'
     AND NEW.quarantine_status = 'RESOLVED_TOMBSTONE'
     AND (
         (OLD.quarantine_reason <> 'ORPHAN_MATERIAL'
          AND NEW.orphan_retirement_state IS NULL)
         OR
         (OLD.quarantine_reason = 'ORPHAN_MATERIAL'
          AND NEW.orphan_retirement_state = 'RETIREMENT_PENDING')
     ))
    OR
    (OLD.quarantine_status = 'RESOLVED_TOMBSTONE'
     AND OLD.quarantine_reason = 'ORPHAN_MATERIAL'
     AND OLD.orphan_retirement_state = 'RETIREMENT_PENDING'
     AND NEW.quarantine_status = 'RESOLVED_TOMBSTONE'
     AND NEW.resolved_generation IS OLD.resolved_generation
     AND NEW.orphan_resolution_evidence_digest
         IS OLD.orphan_resolution_evidence_digest
     AND NEW.orphan_retirement_id IS OLD.orphan_retirement_id
     AND NEW.orphan_retirement_state = 'RETIRED_TOMBSTONE')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid quarantine lifecycle transition');
END;

CREATE UNIQUE INDEX preparation_quarantines_generation_uq
    ON preparation_quarantines (created_generation);

CREATE UNIQUE INDEX preparation_quarantines_attempt_active_uq
    ON preparation_quarantines (attempt_id)
    WHERE attempt_id IS NOT NULL AND quarantine_status = 'ACTIVE';

CREATE UNIQUE INDEX preparation_quarantines_orphan_manifest_uq
    ON preparation_quarantines (recovery_manifest_digest)
    WHERE quarantine_reason = 'ORPHAN_MATERIAL';

CREATE UNIQUE INDEX preparation_quarantines_orphan_retirement_uq
    ON preparation_quarantines (orphan_retirement_id)
    WHERE orphan_retirement_id IS NOT NULL;

CREATE UNIQUE INDEX preparation_quarantines_orphan_retirement_manifest_uq
    ON preparation_quarantines (orphan_retirement_manifest_digest)
    WHERE orphan_retirement_manifest_digest IS NOT NULL;
