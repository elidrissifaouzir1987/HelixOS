-- HelixOS coordinator dispatch overlay schema v2.
--
-- This reviewed additive script is executed only by the explicit paused V1->V2
-- maintenance workflow after exact PLAN-004 schema/root verification and a verified
-- backup. All PLAN-004 V1 objects and rows remain unchanged. The implementation creates
-- the migration receipt in the same BEGIN IMMEDIATE transaction and executes
-- `PRAGMA user_version = 2` as the final statement before COMMIT. Ordinary open never
-- executes this script. Application code additionally verifies normalized object SQL,
-- the V1 schema digest, this overlay digest and all cross-record invariants.

PRAGMA application_id = 1212962883; -- 0x484c5843, unchanged coordinator root
PRAGMA recursive_triggers = ON;

-- Additive composite identities used by the V2 deferred graph. They do not rewrite
-- PLAN-004 rows: they make the immutable V1 operation identity and the terminal
-- refusal projection addressable by exact foreign keys.
CREATE UNIQUE INDEX prepared_operations_dispatch_identity_uq
    ON prepared_operations (
        operation_id,
        attempt_id,
        plan_id,
        task_id,
        workload_id,
        reservation_id
    );

CREATE UNIQUE INDEX prepared_operations_dispatch_attempt_uq
    ON prepared_operations (operation_id, attempt_id);

CREATE UNIQUE INDEX prepared_operations_dispatch_grant_uq
    ON prepared_operations (
        operation_id,
        attempt_id,
        plan_id,
        task_id,
        workload_id
    );

CREATE UNIQUE INDEX prepared_operations_dispatch_terminal_uq
    ON prepared_operations (
        operation_id,
        attempt_id,
        reservation_id,
        state_generation,
        current_event_id,
        operation_state
    );

CREATE UNIQUE INDEX operation_transitions_dispatch_state_uq
    ON operation_transitions (operation_id, state_generation, new_state);

CREATE UNIQUE INDEX operation_transitions_dispatch_generation_uq
    ON operation_transitions (operation_id, state_generation);

CREATE UNIQUE INDEX budget_reservations_dispatch_terminal_uq
    ON budget_reservations (
        reservation_id,
        operation_id,
        attempt_id,
        plan_id,
        task_lease_digest,
        reservation_state,
        released_generation
    );

CREATE UNIQUE INDEX budget_reservations_dispatch_binding_uq
    ON budget_reservations (
        reservation_id,
        operation_id,
        attempt_id,
        plan_id,
        task_lease_digest
    );

CREATE TABLE dispatch_store_meta (
    singleton INTEGER NOT NULL,
    extension_format_version INTEGER NOT NULL,
    dispatch_store_generation INTEGER NOT NULL,
    dispatch_generation INTEGER NOT NULL,
    delivery_generation INTEGER NOT NULL,
    receipt_generation INTEGER NOT NULL,
    reconciliation_generation INTEGER NOT NULL,
    event_generation INTEGER NOT NULL,
    migration_generation INTEGER NOT NULL,
    ordinary_queue_capacity INTEGER NOT NULL,
    control_queue_capacity INTEGER NOT NULL,
    root_lifecycle_state TEXT COLLATE BINARY NOT NULL,
    restore_index_digest BLOB,
    restore_state_generation INTEGER NOT NULL,
    CONSTRAINT dispatch_store_meta_pk PRIMARY KEY (singleton),
    CONSTRAINT dispatch_store_meta_singleton_ck CHECK (singleton = 1),
    CONSTRAINT dispatch_store_meta_version_ck CHECK (extension_format_version = 1),
    CONSTRAINT dispatch_store_meta_generations_ck CHECK (
        dispatch_store_generation BETWEEN 0 AND 9007199254740991
        AND dispatch_generation BETWEEN 0 AND dispatch_store_generation
        AND delivery_generation BETWEEN 0 AND dispatch_store_generation
        AND receipt_generation BETWEEN 0 AND dispatch_store_generation
        AND reconciliation_generation BETWEEN 0 AND dispatch_store_generation
        AND event_generation BETWEEN 0 AND dispatch_store_generation
        AND migration_generation BETWEEN 0 AND dispatch_store_generation
    ),
    CONSTRAINT dispatch_store_meta_capacity_ck CHECK (
        ordinary_queue_capacity = 1024 AND control_queue_capacity = 32
    ),
    CONSTRAINT dispatch_store_meta_lifecycle_ck CHECK (
        (root_lifecycle_state = 'ACTIVE'
         AND restore_index_digest IS NULL
         AND restore_state_generation = 0)
        OR
        (root_lifecycle_state = 'RESTORE_PENDING'
         AND typeof(restore_index_digest) = 'blob'
         AND length(restore_index_digest) = 32
         AND restore_state_generation BETWEEN 1 AND dispatch_store_generation)
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER dispatch_store_meta_single_row_guard
BEFORE INSERT ON dispatch_store_meta
WHEN EXISTS (SELECT 1 FROM dispatch_store_meta)
BEGIN
    SELECT RAISE(ABORT, 'dispatch metadata row already exists');
END;

CREATE TRIGGER dispatch_store_meta_no_delete
BEFORE DELETE ON dispatch_store_meta
BEGIN
    SELECT RAISE(ABORT, 'dispatch metadata is permanent');
END;

CREATE TRIGGER dispatch_store_meta_update_guard
BEFORE UPDATE ON dispatch_store_meta
WHEN NOT (
    NEW.singleton = OLD.singleton
    AND NEW.extension_format_version = OLD.extension_format_version
    AND NEW.ordinary_queue_capacity = OLD.ordinary_queue_capacity
    AND NEW.control_queue_capacity = OLD.control_queue_capacity
    AND NEW.dispatch_store_generation > OLD.dispatch_store_generation
    AND NEW.dispatch_generation BETWEEN OLD.dispatch_generation
        AND NEW.dispatch_store_generation
    AND NEW.delivery_generation BETWEEN OLD.delivery_generation
        AND NEW.dispatch_store_generation
    AND NEW.receipt_generation BETWEEN OLD.receipt_generation
        AND NEW.dispatch_store_generation
    AND NEW.reconciliation_generation BETWEEN OLD.reconciliation_generation
        AND NEW.dispatch_store_generation
    AND NEW.event_generation BETWEEN OLD.event_generation
        AND NEW.dispatch_store_generation
    AND NEW.migration_generation BETWEEN OLD.migration_generation
        AND NEW.dispatch_store_generation
    AND (
        (OLD.root_lifecycle_state = 'ACTIVE'
         AND NEW.root_lifecycle_state = 'ACTIVE'
         AND NEW.restore_index_digest IS NULL
         AND NEW.restore_state_generation = 0)
        OR
        (OLD.root_lifecycle_state = 'ACTIVE'
         AND NEW.root_lifecycle_state = 'RESTORE_PENDING'
         AND typeof(NEW.restore_index_digest) = 'blob'
         AND length(NEW.restore_index_digest) = 32
         AND NEW.restore_state_generation = NEW.dispatch_store_generation)
        OR
        (OLD.root_lifecycle_state = 'RESTORE_PENDING'
         AND NEW.root_lifecycle_state = 'RESTORE_PENDING'
         AND NEW.restore_index_digest IS OLD.restore_index_digest
         AND NEW.restore_state_generation = OLD.restore_state_generation)
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid dispatch metadata projection update');
END;

CREATE TABLE coordinator_v2_migrations (
    migration_attempt_id BLOB NOT NULL,
    source_schema_digest BLOB NOT NULL,
    source_root_identity BLOB NOT NULL,
    source_summary_digest BLOB NOT NULL,
    verified_backup_digest BLOB NOT NULL,
    overlay_schema_digest BLOB NOT NULL,
    migration_generation INTEGER NOT NULL,
    migrated_at_utc_ms INTEGER NOT NULL,
    migrated_at_monotonic_ms INTEGER NOT NULL,
    tool_identity TEXT COLLATE BINARY NOT NULL,
    CONSTRAINT coordinator_v2_migrations_pk PRIMARY KEY (migration_attempt_id),
    CONSTRAINT coordinator_v2_migrations_digest_ck CHECK (
        typeof(migration_attempt_id) = 'blob' AND length(migration_attempt_id) = 32
        AND typeof(source_schema_digest) = 'blob' AND length(source_schema_digest) = 32
        AND typeof(source_root_identity) = 'blob' AND length(source_root_identity) = 32
        AND typeof(source_summary_digest) = 'blob' AND length(source_summary_digest) = 32
        AND typeof(verified_backup_digest) = 'blob' AND length(verified_backup_digest) = 32
        AND typeof(overlay_schema_digest) = 'blob' AND length(overlay_schema_digest) = 32
    ),
    CONSTRAINT coordinator_v2_migrations_generation_ck CHECK (
        migration_generation BETWEEN 1 AND 9007199254740991
        AND migrated_at_utc_ms BETWEEN 0 AND 9007199254740991
        AND migrated_at_monotonic_ms BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT coordinator_v2_migrations_tool_ck CHECK (
        length(CAST(tool_identity AS BLOB)) BETWEEN 1 AND 128
        AND tool_identity NOT GLOB '*[^-A-Za-z0-9._:]*'
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX coordinator_v2_migrations_generation_uq
    ON coordinator_v2_migrations (migration_generation);

CREATE TRIGGER coordinator_v2_migrations_no_update
BEFORE UPDATE ON coordinator_v2_migrations
BEGIN SELECT RAISE(ABORT, 'coordinator migration history is append-only'); END;

CREATE TRIGGER coordinator_v2_migrations_no_delete
BEFORE DELETE ON coordinator_v2_migrations
BEGIN SELECT RAISE(ABORT, 'coordinator migration history is permanent'); END;

CREATE TABLE dispatch_comparisons (
    dispatch_attempt_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    operation_state_generation INTEGER NOT NULL,
    preparation_attempt_id BLOB NOT NULL,
    preparation_transition_generation INTEGER NOT NULL,
    preparation_state TEXT COLLATE BINARY NOT NULL,
    preliminary_context_digest BLOB NOT NULL,
    final_context_digest BLOB NOT NULL,
    authority_vector_digest BLOB NOT NULL,
    destination_binding_digest BLOB NOT NULL,
    signer_profile_digest BLOB NOT NULL,
    sampled_utc_ms INTEGER NOT NULL,
    sampled_monotonic_ms INTEGER NOT NULL,
    effective_deadline_monotonic_ms INTEGER NOT NULL,
    comparison_generation INTEGER NOT NULL,
    CONSTRAINT dispatch_comparisons_pk PRIMARY KEY (dispatch_attempt_id),
    CONSTRAINT dispatch_comparisons_operation_fk FOREIGN KEY (operation_id)
        REFERENCES prepared_operations (operation_id),
    CONSTRAINT dispatch_comparisons_preparation_fk FOREIGN KEY (
        operation_id,
        preparation_attempt_id
    ) REFERENCES prepared_operations (operation_id, attempt_id),
    CONSTRAINT dispatch_comparisons_transition_fk FOREIGN KEY (
        operation_id,
        preparation_transition_generation,
        preparation_state
    ) REFERENCES operation_transitions (
        operation_id,
        state_generation,
        new_state
    ),
    CONSTRAINT dispatch_comparisons_digest_ck CHECK (
        typeof(dispatch_attempt_id) = 'blob' AND length(dispatch_attempt_id) = 32
        AND typeof(preparation_attempt_id) = 'blob' AND length(preparation_attempt_id) = 32
        AND typeof(preliminary_context_digest) = 'blob' AND length(preliminary_context_digest) = 32
        AND typeof(final_context_digest) = 'blob' AND length(final_context_digest) = 32
        AND typeof(authority_vector_digest) = 'blob' AND length(authority_vector_digest) = 32
        AND typeof(destination_binding_digest) = 'blob' AND length(destination_binding_digest) = 32
        AND typeof(signer_profile_digest) = 'blob' AND length(signer_profile_digest) = 32
    ),
    CONSTRAINT dispatch_comparisons_generations_ck CHECK (
        operation_state_generation BETWEEN 1 AND 9007199254740991
        AND preparation_transition_generation BETWEEN 1 AND 9007199254740991
        AND operation_state_generation = preparation_transition_generation
        AND preparation_state = 'PREPARING'
        AND comparison_generation BETWEEN 1 AND 9007199254740991
        AND sampled_utc_ms BETWEEN 0 AND 9007199254740991
        AND sampled_monotonic_ms BETWEEN 0 AND 9007199254740991
        AND effective_deadline_monotonic_ms BETWEEN 0 AND 9007199254740991
        AND sampled_monotonic_ms < effective_deadline_monotonic_ms
        AND effective_deadline_monotonic_ms - sampled_monotonic_ms <= 5000
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_comparisons_operation_attempt_uq
    ON dispatch_comparisons (dispatch_attempt_id, operation_id);
CREATE UNIQUE INDEX dispatch_comparisons_generation_uq
    ON dispatch_comparisons (comparison_generation);

CREATE TRIGGER dispatch_comparisons_no_update BEFORE UPDATE ON dispatch_comparisons
BEGIN SELECT RAISE(ABORT, 'dispatch comparisons are append-only'); END;
CREATE TRIGGER dispatch_comparisons_no_delete BEFORE DELETE ON dispatch_comparisons
BEGIN SELECT RAISE(ABORT, 'dispatch comparisons are permanent'); END;

CREATE TABLE dispatch_grants (
    grant_id BLOB NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    preparation_attempt_id BLOB NOT NULL,
    preparation_transition_generation INTEGER NOT NULL,
    plan_id BLOB NOT NULL,
    task_id TEXT COLLATE BINARY NOT NULL,
    workload_id TEXT COLLATE BINARY NOT NULL,
    task_lease_digest BLOB NOT NULL,
    reservation_id TEXT COLLATE BINARY NOT NULL,
    one_shot_nonce BLOB NOT NULL,
    grant_digest BLOB NOT NULL,
    canonical_grant BLOB NOT NULL,
    canonical_grant_length INTEGER NOT NULL,
    signer_key_id TEXT COLLATE BINARY NOT NULL,
    signer_key_fingerprint BLOB NOT NULL,
    destination_adapter_id TEXT COLLATE BINARY NOT NULL,
    protocol_version INTEGER NOT NULL,
    issued_at_monotonic_ms INTEGER NOT NULL,
    deadline_monotonic_ms INTEGER NOT NULL,
    created_generation INTEGER NOT NULL,
    CONSTRAINT dispatch_grants_pk PRIMARY KEY (grant_id),
    CONSTRAINT dispatch_grants_comparison_fk FOREIGN KEY (
        dispatch_attempt_id,
        operation_id
    ) REFERENCES dispatch_comparisons (dispatch_attempt_id, operation_id),
    CONSTRAINT dispatch_grants_operation_fk FOREIGN KEY (
        operation_id,
        preparation_attempt_id,
        plan_id,
        task_id,
        workload_id
    ) REFERENCES prepared_operations (
        operation_id,
        attempt_id,
        plan_id,
        task_id,
        workload_id
    ),
    CONSTRAINT dispatch_grants_preparation_transition_fk FOREIGN KEY (
        operation_id,
        preparation_transition_generation
    ) REFERENCES operation_transitions (operation_id, state_generation),
    CONSTRAINT dispatch_grants_reservation_fk FOREIGN KEY (
        reservation_id,
        operation_id,
        preparation_attempt_id,
        plan_id,
        task_lease_digest
    ) REFERENCES budget_reservations (
        reservation_id,
        operation_id,
        attempt_id,
        plan_id,
        task_lease_digest
    ),
    CONSTRAINT dispatch_grants_digest_ck CHECK (
        typeof(grant_id) = 'blob' AND length(grant_id) = 32
        AND typeof(preparation_attempt_id) = 'blob' AND length(preparation_attempt_id) = 32
        AND typeof(plan_id) = 'blob' AND length(plan_id) = 32
        AND typeof(task_lease_digest) = 'blob' AND length(task_lease_digest) = 32
        AND typeof(one_shot_nonce) = 'blob' AND length(one_shot_nonce) = 32
        AND typeof(grant_digest) = 'blob' AND length(grant_digest) = 32
        AND typeof(signer_key_fingerprint) = 'blob' AND length(signer_key_fingerprint) = 32
    ),
    CONSTRAINT dispatch_grants_wire_ck CHECK (
        typeof(canonical_grant) = 'blob'
        AND canonical_grant_length = length(canonical_grant)
        AND canonical_grant_length BETWEEN 1 AND 1048576
    ),
    CONSTRAINT dispatch_grants_identifier_ck CHECK (
        length(CAST(signer_key_id AS BLOB)) BETWEEN 1 AND 128
        AND signer_key_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(task_id AS BLOB)) BETWEEN 1 AND 128
        AND task_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(workload_id AS BLOB)) BETWEEN 1 AND 128
        AND workload_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(reservation_id AS BLOB)) BETWEEN 1 AND 128
        AND reservation_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(destination_adapter_id AS BLOB)) BETWEEN 1 AND 128
        AND destination_adapter_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT dispatch_grants_bounds_ck CHECK (
        protocol_version = 1
        AND issued_at_monotonic_ms BETWEEN 0 AND 9007199254740991
        AND deadline_monotonic_ms BETWEEN 1 AND 9007199254740991
        AND issued_at_monotonic_ms < deadline_monotonic_ms
        AND deadline_monotonic_ms - issued_at_monotonic_ms <= 5000
        AND preparation_transition_generation BETWEEN 1 AND 9007199254740991
        AND created_generation BETWEEN 1 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_grants_attempt_uq ON dispatch_grants (dispatch_attempt_id);
CREATE UNIQUE INDEX dispatch_grants_operation_uq ON dispatch_grants (operation_id);
CREATE UNIQUE INDEX dispatch_grants_nonce_uq ON dispatch_grants (one_shot_nonce);
CREATE UNIQUE INDEX dispatch_grants_digest_uq ON dispatch_grants (grant_digest);
CREATE UNIQUE INDEX dispatch_grants_generation_uq ON dispatch_grants (created_generation);
CREATE UNIQUE INDEX dispatch_grants_complete_identity_uq
    ON dispatch_grants (grant_id, operation_id, dispatch_attempt_id);
CREATE UNIQUE INDEX dispatch_grants_event_identity_uq
    ON dispatch_grants (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        task_id,
        workload_id,
        plan_id,
        task_lease_digest
    );

CREATE TRIGGER dispatch_grants_active_root_guard
BEFORE INSERT ON dispatch_grants
WHEN NOT EXISTS (
    SELECT 1
    FROM dispatch_store_meta AS dispatch_meta
    JOIN coordinator_store_meta AS base_meta ON base_meta.singleton = 1
    WHERE dispatch_meta.singleton = 1
      AND dispatch_meta.root_lifecycle_state = 'ACTIVE'
      AND base_meta.root_lifecycle_state = 'ACTIVE'
)
BEGIN SELECT RAISE(ABORT, 'RESTORE_PENDING denies new dispatch authority'); END;

CREATE TRIGGER dispatch_grants_no_update BEFORE UPDATE ON dispatch_grants
BEGIN SELECT RAISE(ABORT, 'dispatch grants are append-only'); END;

CREATE TABLE dispatch_records (
    operation_id TEXT COLLATE BINARY NOT NULL,
    grant_id BLOB NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    initial_delivery_generation INTEGER NOT NULL,
    effective_state TEXT COLLATE BINARY NOT NULL,
    state_generation INTEGER NOT NULL,
    receipt_id BLOB,
    receipt_decision TEXT COLLATE BINARY,
    reconciliation_id BLOB,
    reconciliation_result TEXT COLLATE BINARY,
    current_event_id BLOB NOT NULL,
    CONSTRAINT dispatch_records_pk PRIMARY KEY (operation_id),
    CONSTRAINT dispatch_records_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_grants (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT dispatch_records_outbox_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        initial_delivery_generation
    ) REFERENCES dispatch_outbox (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        initial_delivery_generation
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_records_current_transition_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        current_event_id,
        effective_state
    ) REFERENCES dispatch_transitions (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        event_id,
        new_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_records_receipt_fk FOREIGN KEY (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        receipt_decision
    ) REFERENCES dispatch_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_records_reconciliation_fk FOREIGN KEY (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        reconciliation_result
    ) REFERENCES dispatch_reconciliations (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        result
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_records_state_ck CHECK (
        effective_state IN (
            'DISPATCHING',
            'EXECUTING',
            'OUTCOME_UNKNOWN',
            'RECONCILIATION_REQUIRED',
            'FAILED'
        )
    ),
    CONSTRAINT dispatch_records_generation_ck CHECK (
        state_generation BETWEEN 1 AND 9007199254740991
        AND initial_delivery_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT dispatch_records_receipt_ck CHECK (
        (effective_state = 'DISPATCHING'
         AND receipt_id IS NULL AND receipt_decision IS NULL
         AND reconciliation_id IS NULL AND reconciliation_result IS NULL)
        OR
        (effective_state = 'EXECUTING'
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'CONSUMED'
         AND reconciliation_id IS NULL AND reconciliation_result IS NULL)
        OR
        (effective_state = 'OUTCOME_UNKNOWN'
         AND receipt_id IS NULL AND receipt_decision IS NULL
         AND typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
         AND reconciliation_result = 'OUTCOME_UNKNOWN')
        OR
        (effective_state = 'RECONCILIATION_REQUIRED'
         AND typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
         AND (
             (reconciliation_result = 'OUTCOME_UNKNOWN'
              AND receipt_id IS NULL AND receipt_decision IS NULL)
             OR
             (reconciliation_result IN ('CONSUMED', 'REFUSED_DEFINITE')
              AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
              AND receipt_decision = reconciliation_result)
         ))
        OR
        (effective_state = 'FAILED'
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'REFUSED_DEFINITE'
         AND typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
         AND reconciliation_result = 'REFUSED_DEFINITE')
    ),
    CONSTRAINT dispatch_records_reconciliation_ck CHECK (
        reconciliation_id IS NULL
        OR (typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32)
    ),
    CONSTRAINT dispatch_records_event_ck CHECK (
        typeof(current_event_id) = 'blob' AND length(current_event_id) = 32
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_records_grant_uq ON dispatch_records (grant_id);
CREATE UNIQUE INDEX dispatch_records_attempt_uq ON dispatch_records (dispatch_attempt_id);
CREATE UNIQUE INDEX dispatch_records_state_generation_uq ON dispatch_records (state_generation);
CREATE UNIQUE INDEX dispatch_records_complete_identity_uq
    ON dispatch_records (operation_id, grant_id, dispatch_attempt_id);
CREATE UNIQUE INDEX dispatch_records_terminal_identity_uq
    ON dispatch_records (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        receipt_id,
        reconciliation_id,
        state_generation,
        current_event_id,
        effective_state
    );

CREATE TRIGGER dispatch_records_update_guard
BEFORE UPDATE ON dispatch_records
WHEN NOT (
    NEW.operation_id = OLD.operation_id
    AND NEW.grant_id = OLD.grant_id
    AND NEW.dispatch_attempt_id = OLD.dispatch_attempt_id
    AND NEW.initial_delivery_generation = OLD.initial_delivery_generation
    AND NEW.state_generation > OLD.state_generation
    AND (
        NEW.effective_state <> 'EXECUTING'
        OR EXISTS (
            SELECT 1 FROM dispatch_store_meta
            WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
        )
    )
    AND (
        (OLD.effective_state = 'DISPATCHING'
         AND NEW.effective_state IN ('EXECUTING', 'OUTCOME_UNKNOWN'))
        OR
        (OLD.effective_state = 'OUTCOME_UNKNOWN'
         AND NEW.effective_state = 'RECONCILIATION_REQUIRED')
        OR
        (OLD.effective_state = 'RECONCILIATION_REQUIRED'
         AND NEW.effective_state = 'FAILED')
    )
)
BEGIN SELECT RAISE(ABORT, 'invalid dispatch current-state transition'); END;

CREATE TABLE dispatch_transitions (
    state_generation INTEGER NOT NULL,
    previous_transition_generation INTEGER,
    operation_id TEXT COLLATE BINARY NOT NULL,
    grant_id BLOB NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    previous_state TEXT COLLATE BINARY NOT NULL,
    new_state TEXT COLLATE BINARY NOT NULL,
    event_id BLOB NOT NULL,
    evidence_digest BLOB NOT NULL,
    receipt_id BLOB,
    receipt_decision TEXT COLLATE BINARY,
    reconciliation_id BLOB,
    reconciliation_result TEXT COLLATE BINARY,
    definite_refusal_guard_id BLOB,
    CONSTRAINT dispatch_transitions_pk PRIMARY KEY (state_generation),
    CONSTRAINT dispatch_transitions_record_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_records (
        operation_id,
        grant_id,
        dispatch_attempt_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_transitions_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_grants (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT dispatch_transitions_previous_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        previous_transition_generation,
        previous_state
    ) REFERENCES dispatch_transitions (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        new_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_transitions_event_fk FOREIGN KEY (
        event_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        new_state
    ) REFERENCES dispatch_events (
        event_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        transition_generation,
        effective_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_transitions_receipt_fk FOREIGN KEY (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        receipt_decision
    ) REFERENCES dispatch_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_transitions_reconciliation_fk FOREIGN KEY (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        reconciliation_result
    ) REFERENCES dispatch_reconciliations (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        result
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_transitions_refusal_guard_fk FOREIGN KEY (
        definite_refusal_guard_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        event_id
    ) REFERENCES dispatch_definite_refusal_guards (
        guard_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        refusal_transition_generation,
        refusal_event_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_transitions_state_ck CHECK (
        (previous_state = 'PREPARING' AND new_state = 'DISPATCHING'
         AND previous_transition_generation IS NULL
         AND receipt_id IS NULL AND receipt_decision IS NULL
         AND reconciliation_id IS NULL AND reconciliation_result IS NULL
         AND definite_refusal_guard_id IS NULL)
        OR
        (previous_state = 'DISPATCHING' AND new_state = 'EXECUTING'
         AND previous_transition_generation BETWEEN 1 AND state_generation - 1
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'CONSUMED'
         AND reconciliation_id IS NULL AND reconciliation_result IS NULL
         AND definite_refusal_guard_id IS NULL)
        OR
        (previous_state = 'DISPATCHING' AND new_state = 'OUTCOME_UNKNOWN'
         AND previous_transition_generation BETWEEN 1 AND state_generation - 1
         AND receipt_id IS NULL AND receipt_decision IS NULL
         AND typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
         AND reconciliation_result = 'OUTCOME_UNKNOWN'
         AND definite_refusal_guard_id IS NULL)
        OR
        (previous_state = 'OUTCOME_UNKNOWN'
         AND new_state = 'RECONCILIATION_REQUIRED'
         AND previous_transition_generation BETWEEN 1 AND state_generation - 1
         AND typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
         AND (
             (reconciliation_result = 'OUTCOME_UNKNOWN'
              AND receipt_id IS NULL AND receipt_decision IS NULL)
             OR
             (reconciliation_result IN ('CONSUMED', 'REFUSED_DEFINITE')
              AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
              AND receipt_decision = reconciliation_result)
         )
         AND definite_refusal_guard_id IS NULL)
        OR
        (previous_state = 'RECONCILIATION_REQUIRED' AND new_state = 'FAILED'
         AND previous_transition_generation BETWEEN 1 AND state_generation - 1
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'REFUSED_DEFINITE'
         AND typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
         AND reconciliation_result = 'REFUSED_DEFINITE'
         AND typeof(definite_refusal_guard_id) = 'blob'
         AND length(definite_refusal_guard_id) = 32)
    ),
    CONSTRAINT dispatch_transitions_digest_ck CHECK (
        typeof(event_id) = 'blob' AND length(event_id) = 32
        AND typeof(evidence_digest) = 'blob' AND length(evidence_digest) = 32
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_transitions_complete_identity_uq
    ON dispatch_transitions (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        event_id,
        new_state
    );
CREATE UNIQUE INDEX dispatch_transitions_state_identity_uq
    ON dispatch_transitions (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        new_state
    );
CREATE UNIQUE INDEX dispatch_transitions_single_successor_uq
    ON dispatch_transitions (operation_id, grant_id, previous_state);

CREATE UNIQUE INDEX dispatch_transitions_guard_identity_uq
    ON dispatch_transitions (
        definite_refusal_guard_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        event_id
    );

CREATE TRIGGER dispatch_transitions_current_projection_guard
AFTER INSERT ON dispatch_transitions
WHEN NOT EXISTS (
    SELECT 1 FROM dispatch_records
    WHERE dispatch_records.operation_id = NEW.operation_id
      AND dispatch_records.grant_id = NEW.grant_id
      AND dispatch_records.dispatch_attempt_id = NEW.dispatch_attempt_id
      AND dispatch_records.state_generation = NEW.state_generation
      AND dispatch_records.current_event_id = NEW.event_id
      AND dispatch_records.effective_state = NEW.new_state
)
BEGIN SELECT RAISE(ABORT, 'dispatch transition must be the current projection when appended'); END;

CREATE TABLE dispatch_outbox (
    grant_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    initial_delivery_generation INTEGER NOT NULL,
    delivery_state TEXT COLLATE BINARY NOT NULL,
    delivery_generation INTEGER NOT NULL,
    current_attempt_generation INTEGER,
    receipt_id BLOB,
    receipt_decision TEXT COLLATE BINARY,
    deadline_monotonic_ms INTEGER NOT NULL,
    CONSTRAINT dispatch_outbox_pk PRIMARY KEY (grant_id),
    CONSTRAINT dispatch_outbox_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_grants (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT dispatch_outbox_operation_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_records (operation_id, grant_id, dispatch_attempt_id),
    CONSTRAINT dispatch_outbox_receipt_fk FOREIGN KEY (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        receipt_decision
    ) REFERENCES dispatch_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_outbox_attempt_fk FOREIGN KEY (
        current_attempt_generation,
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_delivery_attempts (
        attempt_generation,
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_outbox_state_ck CHECK (
        delivery_state IN ('PENDING', 'HANDED_OFF', 'ACKNOWLEDGED', 'QUIESCED', 'UNKNOWN')
    ),
    CONSTRAINT dispatch_outbox_generation_ck CHECK (
        delivery_generation BETWEEN 1 AND 9007199254740991
        AND initial_delivery_generation BETWEEN 1 AND delivery_generation
        AND (current_attempt_generation IS NULL
             OR current_attempt_generation BETWEEN 1 AND 9007199254740991)
        AND deadline_monotonic_ms BETWEEN 1 AND 9007199254740991
        AND (delivery_state = 'PENDING' OR current_attempt_generation IS NOT NULL)
    ),
    CONSTRAINT dispatch_outbox_receipt_ck CHECK (
        (receipt_id IS NULL AND receipt_decision IS NULL
         AND delivery_state IN ('PENDING', 'HANDED_OFF', 'UNKNOWN'))
        OR
        (typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision IN ('CONSUMED', 'REFUSED_DEFINITE')
         AND delivery_state IN ('ACKNOWLEDGED', 'QUIESCED'))
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_outbox_delivery_generation_uq
    ON dispatch_outbox (delivery_generation);
CREATE UNIQUE INDEX dispatch_outbox_initial_identity_uq
    ON dispatch_outbox (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        initial_delivery_generation
    );

CREATE TRIGGER dispatch_outbox_update_guard
BEFORE UPDATE ON dispatch_outbox
WHEN NOT (
    NEW.grant_id = OLD.grant_id
    AND NEW.operation_id = OLD.operation_id
    AND NEW.dispatch_attempt_id = OLD.dispatch_attempt_id
    AND NEW.initial_delivery_generation = OLD.initial_delivery_generation
    AND NEW.deadline_monotonic_ms = OLD.deadline_monotonic_ms
    AND NEW.delivery_generation > OLD.delivery_generation
    AND (
        (OLD.current_attempt_generation IS NULL
         AND NEW.current_attempt_generation IS NOT NULL)
        OR
        (OLD.current_attempt_generation IS NOT NULL
         AND NEW.current_attempt_generation >= OLD.current_attempt_generation)
    )
    AND (
        NEW.delivery_state <> 'HANDED_OFF'
        OR EXISTS (
            SELECT 1 FROM dispatch_store_meta
            WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
        )
    )
    AND (
        (OLD.delivery_state = 'PENDING'
         AND NEW.delivery_state IN ('HANDED_OFF', 'QUIESCED', 'UNKNOWN'))
        OR
        (OLD.delivery_state = 'HANDED_OFF'
         AND NEW.delivery_state IN ('ACKNOWLEDGED', 'QUIESCED', 'UNKNOWN'))
        OR
        (OLD.delivery_state = 'UNKNOWN'
         AND NEW.delivery_state IN ('ACKNOWLEDGED', 'QUIESCED'))
    )
)
BEGIN SELECT RAISE(ABORT, 'invalid dispatch outbox projection update'); END;

CREATE TRIGGER dispatch_outbox_no_delete BEFORE DELETE ON dispatch_outbox
BEGIN SELECT RAISE(ABORT, 'dispatch outbox is permanent'); END;

CREATE TABLE dispatch_delivery_attempts (
    attempt_generation INTEGER NOT NULL,
    grant_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    attempt_number INTEGER NOT NULL,
    handoff_guard_digest BLOB NOT NULL,
    classification TEXT COLLATE BINARY NOT NULL,
    adapter_root_digest BLOB,
    adapter_epoch INTEGER,
    readback_generation INTEGER,
    CONSTRAINT dispatch_delivery_attempts_pk PRIMARY KEY (attempt_generation),
    CONSTRAINT dispatch_delivery_attempts_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_grants (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT dispatch_delivery_attempts_attempt_uq UNIQUE (grant_id, attempt_number),
    CONSTRAINT dispatch_delivery_attempts_digest_ck CHECK (
        typeof(handoff_guard_digest) = 'blob' AND length(handoff_guard_digest) = 32
        AND (adapter_root_digest IS NULL
             OR (typeof(adapter_root_digest) = 'blob' AND length(adapter_root_digest) = 32))
    ),
    CONSTRAINT dispatch_delivery_attempts_class_ck CHECK (
        classification IN ('CONFIRMED_NO_SEND', 'POSSIBLE_HANDOFF', 'ACKNOWLEDGED', 'QUIESCED')
    ),
    CONSTRAINT dispatch_delivery_attempts_bounds_ck CHECK (
        attempt_generation BETWEEN 1 AND 9007199254740991
        AND attempt_number BETWEEN 1 AND 9007199254740991
        AND (adapter_epoch IS NULL OR adapter_epoch BETWEEN 0 AND 9007199254740991)
        AND (readback_generation IS NULL OR readback_generation BETWEEN 1 AND 9007199254740991)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_delivery_attempts_complete_identity_uq
    ON dispatch_delivery_attempts (
        attempt_generation,
        grant_id,
        operation_id,
        dispatch_attempt_id
    );

CREATE TRIGGER dispatch_delivery_attempts_active_root_guard
BEFORE INSERT ON dispatch_delivery_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM dispatch_store_meta
    WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
)
BEGIN SELECT RAISE(ABORT, 'RESTORE_PENDING denies new delivery attempts'); END;

CREATE TRIGGER dispatch_delivery_attempts_no_update BEFORE UPDATE ON dispatch_delivery_attempts
BEGIN SELECT RAISE(ABORT, 'dispatch delivery attempts are append-only'); END;
CREATE TRIGGER dispatch_delivery_attempts_no_delete BEFORE DELETE ON dispatch_delivery_attempts
BEGIN SELECT RAISE(ABORT, 'dispatch delivery attempts are permanent'); END;

CREATE TABLE dispatch_receipts (
    receipt_id BLOB NOT NULL,
    grant_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    receipt_digest BLOB NOT NULL,
    canonical_receipt BLOB NOT NULL,
    canonical_receipt_length INTEGER NOT NULL,
    adapter_key_fingerprint BLOB NOT NULL,
    decision TEXT COLLATE BINARY NOT NULL,
    refusal_code TEXT COLLATE BINARY,
    no_consumption_tombstone_digest BLOB,
    receipt_generation INTEGER NOT NULL,
    CONSTRAINT dispatch_receipts_pk PRIMARY KEY (receipt_id),
    CONSTRAINT dispatch_receipts_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_grants (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT dispatch_receipts_operation_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_records (operation_id, grant_id, dispatch_attempt_id),
    CONSTRAINT dispatch_receipts_digest_ck CHECK (
        typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
        AND typeof(receipt_digest) = 'blob' AND length(receipt_digest) = 32
        AND typeof(adapter_key_fingerprint) = 'blob' AND length(adapter_key_fingerprint) = 32
    ),
    CONSTRAINT dispatch_receipts_wire_ck CHECK (
        typeof(canonical_receipt) = 'blob'
        AND canonical_receipt_length = length(canonical_receipt)
        AND canonical_receipt_length BETWEEN 1 AND 65536
    ),
    CONSTRAINT dispatch_receipts_decision_ck CHECK (
        (decision = 'CONSUMED'
         AND refusal_code IS NULL
         AND no_consumption_tombstone_digest IS NULL)
        OR
        (decision = 'REFUSED_DEFINITE'
         AND refusal_code IN (
             'GRANT_EXPIRED',
             'SUPERVISOR_EPOCH_MISMATCH',
             'ADAPTER_PAUSED'
         )
         AND typeof(no_consumption_tombstone_digest) = 'blob'
         AND length(no_consumption_tombstone_digest) = 32)
    ),
    CONSTRAINT dispatch_receipts_generation_ck CHECK (
        receipt_generation BETWEEN 1 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_receipts_grant_uq ON dispatch_receipts (grant_id);
CREATE UNIQUE INDEX dispatch_receipts_operation_uq ON dispatch_receipts (operation_id);
CREATE UNIQUE INDEX dispatch_receipts_digest_uq ON dispatch_receipts (receipt_digest);
CREATE UNIQUE INDEX dispatch_receipts_generation_uq ON dispatch_receipts (receipt_generation);
CREATE UNIQUE INDEX dispatch_receipts_complete_identity_uq
    ON dispatch_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision,
        receipt_digest
    );
CREATE UNIQUE INDEX dispatch_receipts_binding_identity_uq
    ON dispatch_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision
    );

CREATE TRIGGER dispatch_receipts_no_update BEFORE UPDATE ON dispatch_receipts
BEGIN SELECT RAISE(ABORT, 'dispatch receipts are append-only'); END;

CREATE TABLE dispatch_reconciliations (
    reconciliation_id BLOB NOT NULL,
    grant_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    evidence_digest BLOB NOT NULL,
    transport_quiescence_digest BLOB NOT NULL,
    no_inflight_proof_digest BLOB,
    result TEXT COLLATE BINARY NOT NULL,
    receipt_id BLOB,
    receipt_decision TEXT COLLATE BINARY,
    reconciliation_generation INTEGER NOT NULL,
    CONSTRAINT dispatch_reconciliations_pk PRIMARY KEY (reconciliation_id),
    CONSTRAINT dispatch_reconciliations_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_grants (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT dispatch_reconciliations_operation_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_records (operation_id, grant_id, dispatch_attempt_id),
    CONSTRAINT dispatch_reconciliations_receipt_fk FOREIGN KEY (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        receipt_decision
    ) REFERENCES dispatch_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_reconciliations_digest_ck CHECK (
        typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
        AND typeof(evidence_digest) = 'blob' AND length(evidence_digest) = 32
        AND typeof(transport_quiescence_digest) = 'blob'
        AND length(transport_quiescence_digest) = 32
        AND (no_inflight_proof_digest IS NULL
             OR (typeof(no_inflight_proof_digest) = 'blob'
                 AND length(no_inflight_proof_digest) = 32))
    ),
    CONSTRAINT dispatch_reconciliations_result_ck CHECK (
        result IN ('CONSUMED', 'REFUSED_DEFINITE', 'OUTCOME_UNKNOWN')
    ),
    CONSTRAINT dispatch_reconciliations_receipt_ck CHECK (
        (result = 'OUTCOME_UNKNOWN'
         AND receipt_id IS NULL AND receipt_decision IS NULL
         AND no_inflight_proof_digest IS NULL)
        OR
        (result = 'CONSUMED'
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'CONSUMED'
         AND no_inflight_proof_digest IS NULL)
        OR
        (result = 'REFUSED_DEFINITE'
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'REFUSED_DEFINITE'
         AND typeof(no_inflight_proof_digest) = 'blob'
         AND length(no_inflight_proof_digest) = 32)
    ),
    CONSTRAINT dispatch_reconciliations_generation_ck CHECK (
        reconciliation_generation BETWEEN 1 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_reconciliations_generation_uq
    ON dispatch_reconciliations (reconciliation_generation);
CREATE UNIQUE INDEX dispatch_reconciliations_complete_identity_uq
    ON dispatch_reconciliations (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        result,
        receipt_id,
        transport_quiescence_digest,
        no_inflight_proof_digest
    );
CREATE UNIQUE INDEX dispatch_reconciliations_binding_identity_uq
    ON dispatch_reconciliations (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        result
    );

CREATE TRIGGER dispatch_reconciliations_no_update BEFORE UPDATE ON dispatch_reconciliations
BEGIN SELECT RAISE(ABORT, 'dispatch reconciliations are append-only'); END;

CREATE TABLE dispatch_events (
    event_id BLOB NOT NULL,
    event_generation INTEGER NOT NULL,
    transition_generation INTEGER NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    grant_id BLOB NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    task_id TEXT COLLATE BINARY NOT NULL,
    workload_id TEXT COLLATE BINARY NOT NULL,
    plan_id BLOB NOT NULL,
    task_lease_digest BLOB NOT NULL,
    event_contract_version INTEGER NOT NULL,
    grant_contract_version INTEGER NOT NULL,
    receipt_contract_version INTEGER NOT NULL,
    effective_state TEXT COLLATE BINARY NOT NULL,
    decision TEXT COLLATE BINARY NOT NULL,
    latency_ms INTEGER NOT NULL,
    event_kind TEXT COLLATE BINARY NOT NULL,
    public_reason_code TEXT COLLATE BINARY,
    public_trace_id TEXT COLLATE BINARY NOT NULL,
    delivery_state TEXT COLLATE BINARY NOT NULL,
    delivered_generation INTEGER,
    CONSTRAINT dispatch_events_pk PRIMARY KEY (event_id),
    CONSTRAINT dispatch_events_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        task_id,
        workload_id,
        plan_id,
        task_lease_digest
    ) REFERENCES dispatch_grants (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        task_id,
        workload_id,
        plan_id,
        task_lease_digest
    ),
    CONSTRAINT dispatch_events_transition_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        transition_generation,
        event_id,
        effective_state
    ) REFERENCES dispatch_transitions (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        event_id,
        new_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_events_event_id_ck CHECK (
        typeof(event_id) = 'blob' AND length(event_id) = 32
        AND typeof(plan_id) = 'blob' AND length(plan_id) = 32
        AND typeof(task_lease_digest) = 'blob' AND length(task_lease_digest) = 32
    ),
    CONSTRAINT dispatch_events_generation_ck CHECK (
        event_generation BETWEEN 1 AND 9007199254740991
        AND transition_generation BETWEEN 1 AND 9007199254740991
        AND latency_ms BETWEEN 0 AND 9007199254740991
        AND (delivered_generation IS NULL
             OR delivered_generation BETWEEN event_generation AND 9007199254740991)
    ),
    CONSTRAINT dispatch_events_kind_ck CHECK (
        event_contract_version = 1
        AND grant_contract_version = 1
        AND receipt_contract_version IN (0, 1)
        AND (
            (event_kind = 'DISPATCHED'
             AND effective_state = 'DISPATCHING'
             AND decision = 'DISPATCHED'
             AND receipt_contract_version = 0)
            OR
            (event_kind = 'GRANT_CONSUMED'
             AND effective_state = 'EXECUTING'
             AND decision = 'CONSUMED'
             AND receipt_contract_version = 1)
            OR
            (event_kind = 'DISPATCH_UNKNOWN'
             AND effective_state = 'OUTCOME_UNKNOWN'
             AND decision = 'OUTCOME_UNKNOWN'
             AND receipt_contract_version = 0)
            OR
            (event_kind = 'DISPATCH_RECONCILED'
             AND effective_state = 'RECONCILIATION_REQUIRED'
             AND decision IN ('CONSUMED', 'REFUSED_DEFINITE', 'OUTCOME_UNKNOWN')
             AND receipt_contract_version = CASE
                 WHEN decision = 'OUTCOME_UNKNOWN' THEN 0 ELSE 1 END)
            OR
            (event_kind = 'DISPATCH_REFUSED'
             AND effective_state = 'FAILED'
             AND decision = 'REFUSED_DEFINITE'
             AND receipt_contract_version = 1)
        )
    ),
    CONSTRAINT dispatch_events_public_ck CHECK (
        (public_reason_code IS NULL
         OR (length(CAST(public_reason_code AS BLOB)) BETWEEN 1 AND 64
             AND public_reason_code NOT GLOB '*[^A-Z0-9_]*'))
        AND length(CAST(public_trace_id AS BLOB)) BETWEEN 1 AND 128
        AND public_trace_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(task_id AS BLOB)) BETWEEN 1 AND 128
        AND task_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(workload_id AS BLOB)) BETWEEN 1 AND 128
        AND workload_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT dispatch_events_delivery_ck CHECK (
        (delivery_state = 'PENDING' AND delivered_generation IS NULL)
        OR (delivery_state = 'DELIVERED' AND delivered_generation IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_events_generation_uq ON dispatch_events (event_generation);
CREATE UNIQUE INDEX dispatch_events_transition_uq
    ON dispatch_events (
        event_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        transition_generation,
        effective_state
    );
CREATE UNIQUE INDEX dispatch_events_one_per_transition_uq
    ON dispatch_events (operation_id, grant_id, transition_generation);

CREATE TRIGGER dispatch_events_update_guard
BEFORE UPDATE ON dispatch_events
WHEN NOT (
    NEW.event_id = OLD.event_id
    AND NEW.event_generation = OLD.event_generation
    AND NEW.transition_generation = OLD.transition_generation
    AND NEW.operation_id = OLD.operation_id
    AND NEW.grant_id = OLD.grant_id
    AND NEW.dispatch_attempt_id = OLD.dispatch_attempt_id
    AND NEW.task_id = OLD.task_id
    AND NEW.workload_id = OLD.workload_id
    AND NEW.plan_id = OLD.plan_id
    AND NEW.task_lease_digest = OLD.task_lease_digest
    AND NEW.event_contract_version = OLD.event_contract_version
    AND NEW.grant_contract_version = OLD.grant_contract_version
    AND NEW.receipt_contract_version = OLD.receipt_contract_version
    AND NEW.effective_state = OLD.effective_state
    AND NEW.decision = OLD.decision
    AND NEW.latency_ms = OLD.latency_ms
    AND NEW.event_kind = OLD.event_kind
    AND NEW.public_reason_code IS OLD.public_reason_code
    AND NEW.public_trace_id = OLD.public_trace_id
    AND OLD.delivery_state = 'PENDING'
    AND OLD.delivered_generation IS NULL
    AND NEW.delivery_state = 'DELIVERED'
    AND NEW.delivered_generation >= OLD.event_generation
)
BEGIN SELECT RAISE(ABORT, 'only pending-to-delivered event projection is mutable'); END;

-- A definite refusal is not a transport error. This append-only guard makes the
-- signed REFUSED_DEFINITE receipt, exact no-in-flight proof, V2 terminal transition,
-- PLAN-004 PREPARING->FAILED transition/event, and HELD->RELEASED reservation one
-- deferred all-or-none graph. Inserting a guard without completing every edge cannot
-- commit with foreign_keys enabled.
CREATE TABLE dispatch_definite_refusal_guards (
    guard_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    grant_id BLOB NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    preparation_attempt_id BLOB NOT NULL,
    plan_id BLOB NOT NULL,
    task_lease_digest BLOB NOT NULL,
    receipt_id BLOB NOT NULL,
    receipt_digest BLOB NOT NULL,
    reconciliation_id BLOB NOT NULL,
    transport_quiescence_digest BLOB NOT NULL,
    no_inflight_proof_digest BLOB NOT NULL,
    refusal_transition_generation INTEGER NOT NULL,
    refusal_event_id BLOB NOT NULL,
    base_failure_transition_generation INTEGER NOT NULL,
    base_failure_event_id BLOB NOT NULL,
    reservation_id TEXT COLLATE BINARY NOT NULL,
    reservation_released_generation INTEGER NOT NULL,
    guard_generation INTEGER NOT NULL,
    receipt_decision TEXT COLLATE BINARY NOT NULL,
    reconciliation_result TEXT COLLATE BINARY NOT NULL,
    final_dispatch_state TEXT COLLATE BINARY NOT NULL,
    base_operation_state TEXT COLLATE BINARY NOT NULL,
    reservation_state TEXT COLLATE BINARY NOT NULL,
    CONSTRAINT dispatch_definite_refusal_guards_pk PRIMARY KEY (guard_id),
    CONSTRAINT dispatch_refusal_guard_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES dispatch_grants (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT dispatch_refusal_guard_receipt_fk FOREIGN KEY (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        receipt_decision,
        receipt_digest
    ) REFERENCES dispatch_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision,
        receipt_digest
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_refusal_guard_reconciliation_fk FOREIGN KEY (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        reconciliation_result,
        receipt_id,
        transport_quiescence_digest,
        no_inflight_proof_digest
    ) REFERENCES dispatch_reconciliations (
        reconciliation_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        result,
        receipt_id,
        transport_quiescence_digest,
        no_inflight_proof_digest
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_refusal_guard_transition_fk FOREIGN KEY (
        guard_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        refusal_transition_generation,
        refusal_event_id
    ) REFERENCES dispatch_transitions (
        definite_refusal_guard_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        state_generation,
        event_id
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_refusal_guard_current_fk FOREIGN KEY (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        receipt_id,
        reconciliation_id,
        refusal_transition_generation,
        refusal_event_id,
        final_dispatch_state
    ) REFERENCES dispatch_records (
        operation_id,
        grant_id,
        dispatch_attempt_id,
        receipt_id,
        reconciliation_id,
        state_generation,
        current_event_id,
        effective_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_refusal_guard_base_operation_fk FOREIGN KEY (
        operation_id,
        preparation_attempt_id,
        reservation_id,
        base_failure_transition_generation,
        base_failure_event_id,
        base_operation_state
    ) REFERENCES prepared_operations (
        operation_id,
        attempt_id,
        reservation_id,
        state_generation,
        current_event_id,
        operation_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_refusal_guard_base_transition_fk FOREIGN KEY (
        operation_id,
        base_failure_transition_generation,
        base_failure_event_id,
        base_operation_state
    ) REFERENCES operation_transitions (
        operation_id,
        state_generation,
        event_id,
        new_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_refusal_guard_reservation_fk FOREIGN KEY (
        reservation_id,
        operation_id,
        preparation_attempt_id,
        plan_id,
        task_lease_digest,
        reservation_state,
        reservation_released_generation
    ) REFERENCES budget_reservations (
        reservation_id,
        operation_id,
        attempt_id,
        plan_id,
        task_lease_digest,
        reservation_state,
        released_generation
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT dispatch_refusal_guard_digest_ck CHECK (
        typeof(guard_id) = 'blob' AND length(guard_id) = 32
        AND typeof(preparation_attempt_id) = 'blob' AND length(preparation_attempt_id) = 32
        AND typeof(plan_id) = 'blob' AND length(plan_id) = 32
        AND typeof(task_lease_digest) = 'blob' AND length(task_lease_digest) = 32
        AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
        AND typeof(receipt_digest) = 'blob' AND length(receipt_digest) = 32
        AND typeof(reconciliation_id) = 'blob' AND length(reconciliation_id) = 32
        AND typeof(transport_quiescence_digest) = 'blob'
        AND length(transport_quiescence_digest) = 32
        AND typeof(no_inflight_proof_digest) = 'blob'
        AND length(no_inflight_proof_digest) = 32
        AND typeof(refusal_event_id) = 'blob' AND length(refusal_event_id) = 32
        AND typeof(base_failure_event_id) = 'blob' AND length(base_failure_event_id) = 32
    ),
    CONSTRAINT dispatch_refusal_guard_state_ck CHECK (
        receipt_decision = 'REFUSED_DEFINITE'
        AND reconciliation_result = 'REFUSED_DEFINITE'
        AND final_dispatch_state = 'FAILED'
        AND base_operation_state = 'FAILED'
        AND reservation_state = 'RELEASED'
    ),
    CONSTRAINT dispatch_refusal_guard_generation_ck CHECK (
        refusal_transition_generation BETWEEN 1 AND 9007199254740991
        AND base_failure_transition_generation BETWEEN 1 AND 9007199254740991
        AND reservation_released_generation BETWEEN 1 AND 9007199254740991
        AND guard_generation BETWEEN 1 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX dispatch_definite_refusal_guards_generation_uq
    ON dispatch_definite_refusal_guards (guard_generation);
CREATE UNIQUE INDEX dispatch_definite_refusal_guards_transition_uq
    ON dispatch_definite_refusal_guards (
        guard_id,
        operation_id,
        grant_id,
        dispatch_attempt_id,
        refusal_transition_generation,
        refusal_event_id
    );

CREATE TRIGGER dispatch_definite_refusal_guards_no_update
BEFORE UPDATE ON dispatch_definite_refusal_guards
BEGIN SELECT RAISE(ABORT, 'definite refusal guards are append-only'); END;
CREATE TRIGGER dispatch_definite_refusal_guards_no_delete
BEFORE DELETE ON dispatch_definite_refusal_guards
BEGIN SELECT RAISE(ABORT, 'definite refusal guards are permanent'); END;

CREATE TRIGGER dispatch_overlay_guards_v1_operation
BEFORE UPDATE ON prepared_operations
WHEN EXISTS (
    SELECT 1 FROM dispatch_records
    WHERE dispatch_records.operation_id = OLD.operation_id
)
AND NOT (
    (
        OLD.operation_state = 'PREPARING'
        AND NEW.operation_state = 'FAILED'
        AND NEW.operation_id = OLD.operation_id
        AND NEW.attempt_id = OLD.attempt_id
        AND NEW.plan_id = OLD.plan_id
        AND NEW.task_id = OLD.task_id
        AND NEW.workload_id = OLD.workload_id
        AND NEW.canonical_plan = OLD.canonical_plan
        AND NEW.canonical_plan_length = OLD.canonical_plan_length
        AND NEW.created_generation = OLD.created_generation
        AND NEW.boot_id = OLD.boot_id
        AND NEW.instance_epoch = OLD.instance_epoch
        AND NEW.fencing_epoch = OLD.fencing_epoch
        AND NEW.effective_expires_at_utc_ms = OLD.effective_expires_at_utc_ms
        AND NEW.effective_deadline_monotonic_ms = OLD.effective_deadline_monotonic_ms
        AND NEW.reservation_id = OLD.reservation_id
        AND NEW.recovery_mode = OLD.recovery_mode
        AND NEW.restored_source_generation IS OLD.restored_source_generation
        AND NEW.failed_generation = NEW.state_generation
        AND EXISTS (
            SELECT 1
            FROM dispatch_definite_refusal_guards AS refusal
            WHERE refusal.operation_id = NEW.operation_id
              AND refusal.preparation_attempt_id = NEW.attempt_id
              AND refusal.reservation_id = NEW.reservation_id
              AND refusal.base_failure_transition_generation = NEW.state_generation
              AND refusal.base_failure_event_id = NEW.current_event_id
              AND refusal.base_operation_state = NEW.operation_state
        )
    )
    OR (
        OLD.restored_source_generation IS NULL
        AND NEW.operation_id = OLD.operation_id
        AND NEW.attempt_id = OLD.attempt_id
        AND NEW.plan_id = OLD.plan_id
        AND NEW.task_id = OLD.task_id
        AND NEW.workload_id = OLD.workload_id
        AND NEW.canonical_plan = OLD.canonical_plan
        AND NEW.canonical_plan_length = OLD.canonical_plan_length
        AND NEW.operation_state = OLD.operation_state
        AND NEW.state_generation = OLD.state_generation
        AND NEW.created_generation = OLD.created_generation
        AND NEW.failed_generation IS OLD.failed_generation
        AND NEW.failed_reason_code IS OLD.failed_reason_code
        AND NEW.boot_id = OLD.boot_id
        AND NEW.instance_epoch = OLD.instance_epoch
        AND NEW.fencing_epoch = OLD.fencing_epoch
        AND NEW.effective_expires_at_utc_ms = OLD.effective_expires_at_utc_ms
        AND NEW.effective_deadline_monotonic_ms = OLD.effective_deadline_monotonic_ms
        AND NEW.reservation_id = OLD.reservation_id
        AND NEW.recovery_mode = OLD.recovery_mode
        AND NEW.current_event_id = OLD.current_event_id
        AND EXISTS (
            SELECT 1
            FROM coordinator_store_meta AS base
            JOIN dispatch_store_meta AS dispatch
              ON dispatch.singleton = base.singleton
            WHERE base.singleton = 1
              AND base.root_lifecycle_state = 'ACTIVE'
              AND base.restore_identity_digest IS NULL
              AND base.restore_attestation_digest IS NULL
              AND base.restore_state_generation = 0
              AND dispatch.root_lifecycle_state = 'RESTORE_PENDING'
              AND dispatch.restore_index_digest IS NOT NULL
              AND dispatch.restore_state_generation = dispatch.dispatch_store_generation
              AND NEW.restored_source_generation = base.store_generation
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'dispatch overlay permits only guarded definite-refusal failure');
END;

CREATE TRIGGER dispatch_overlay_guards_v1_reservation
BEFORE UPDATE ON budget_reservations
WHEN EXISTS (
    SELECT 1 FROM dispatch_records
    WHERE dispatch_records.operation_id = OLD.operation_id
)
AND NOT (
    OLD.reservation_state = 'HELD'
    AND OLD.released_generation IS NULL
    AND NEW.reservation_state = 'RELEASED'
    AND NEW.released_generation IS NOT NULL
    AND NEW.reservation_id = OLD.reservation_id
    AND NEW.operation_id = OLD.operation_id
    AND NEW.attempt_id = OLD.attempt_id
    AND NEW.plan_id = OLD.plan_id
    AND NEW.scope_id = OLD.scope_id
    AND NEW.task_lease_digest = OLD.task_lease_digest
    AND NEW.currency_code = OLD.currency_code
    AND NEW.price_table_id = OLD.price_table_id
    AND NEW.reserved_cost_micro_units = OLD.reserved_cost_micro_units
    AND NEW.reserved_action_count = OLD.reserved_action_count
    AND NEW.reserved_egress_bytes = OLD.reserved_egress_bytes
    AND NEW.reserved_recovery_bytes = OLD.reserved_recovery_bytes
    AND NEW.created_generation = OLD.created_generation
    AND EXISTS (
        SELECT 1
        FROM dispatch_definite_refusal_guards AS refusal
        WHERE refusal.reservation_id = NEW.reservation_id
          AND refusal.operation_id = NEW.operation_id
          AND refusal.preparation_attempt_id = NEW.attempt_id
          AND refusal.plan_id = NEW.plan_id
          AND refusal.task_lease_digest = NEW.task_lease_digest
          AND refusal.reservation_state = NEW.reservation_state
          AND refusal.reservation_released_generation = NEW.released_generation
    )
)
BEGIN
    SELECT RAISE(ABORT, 'dispatch reservation release requires definite-refusal guard');
END;

CREATE TRIGGER dispatch_records_active_insert_guard
BEFORE INSERT ON dispatch_records
WHEN NOT EXISTS (
    SELECT 1 FROM dispatch_store_meta
    WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
)
BEGIN SELECT RAISE(ABORT, 'RESTORE_PENDING denies new dispatch authority'); END;

CREATE TRIGGER dispatch_grants_no_delete BEFORE DELETE ON dispatch_grants
BEGIN SELECT RAISE(ABORT, 'dispatch grants are permanent'); END;
CREATE TRIGGER dispatch_records_no_delete BEFORE DELETE ON dispatch_records
BEGIN SELECT RAISE(ABORT, 'dispatch records are permanent'); END;
CREATE TRIGGER dispatch_transitions_no_update BEFORE UPDATE ON dispatch_transitions
BEGIN SELECT RAISE(ABORT, 'dispatch transitions are append-only'); END;
CREATE TRIGGER dispatch_transitions_no_delete BEFORE DELETE ON dispatch_transitions
BEGIN SELECT RAISE(ABORT, 'dispatch transitions are permanent'); END;
CREATE TRIGGER dispatch_receipts_no_delete BEFORE DELETE ON dispatch_receipts
BEGIN SELECT RAISE(ABORT, 'dispatch receipts are permanent'); END;
CREATE TRIGGER dispatch_reconciliations_no_delete BEFORE DELETE ON dispatch_reconciliations
BEGIN SELECT RAISE(ABORT, 'dispatch reconciliation is permanent'); END;
CREATE TRIGGER dispatch_events_no_delete BEFORE DELETE ON dispatch_events
BEGIN SELECT RAISE(ABORT, 'dispatch events are permanent'); END;

-- The migration implementation inserts the singleton metadata and migration receipt,
-- verifies all objects/invariants, and performs this as its final statement before
-- COMMIT. A standalone schema test must execute the V1 DDL first.
PRAGMA user_version = 2;
