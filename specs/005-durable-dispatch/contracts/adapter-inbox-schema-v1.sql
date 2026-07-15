-- HelixOS independent adapter dispatch inbox schema v1.
--
-- Initialized only in an empty provisioner-attested local adapter root. Application
-- code supplies a fresh root identity, trusted initial supervisor epoch observation and
-- receipt signer profile when inserting the singleton metadata row. Ordinary open
-- verifies exact object SQL, PRAGMAs and cross-record invariants.

PRAGMA application_id = 1212962889; -- 0x484c5849, "HLXI"
PRAGMA user_version = 1;
PRAGMA recursive_triggers = ON;

CREATE TABLE adapter_store_meta (
    singleton INTEGER NOT NULL,
    format_version INTEGER NOT NULL,
    store_generation INTEGER NOT NULL,
    inbox_generation INTEGER NOT NULL,
    consumption_generation INTEGER NOT NULL,
    receipt_generation INTEGER NOT NULL,
    conflict_generation INTEGER NOT NULL,
    quarantine_generation INTEGER NOT NULL,
    event_generation INTEGER NOT NULL,
    root_identity BLOB NOT NULL,
    root_lifecycle_state TEXT COLLATE BINARY NOT NULL,
    supervisor_epoch INTEGER NOT NULL,
    epoch_observer_generation INTEGER NOT NULL,
    ordinary_queue_capacity INTEGER NOT NULL,
    control_queue_capacity INTEGER NOT NULL,
    receipt_signer_profile_digest BLOB NOT NULL,
    restore_index_digest BLOB,
    restore_state_generation INTEGER NOT NULL,
    CONSTRAINT adapter_store_meta_pk PRIMARY KEY (singleton),
    CONSTRAINT adapter_store_meta_singleton_ck CHECK (singleton = 1),
    CONSTRAINT adapter_store_meta_version_ck CHECK (format_version = 1),
    CONSTRAINT adapter_store_meta_generations_ck CHECK (
        store_generation BETWEEN 0 AND 9007199254740991
        AND inbox_generation BETWEEN 0 AND store_generation
        AND consumption_generation BETWEEN 0 AND store_generation
        AND receipt_generation BETWEEN 0 AND store_generation
        AND conflict_generation BETWEEN 0 AND store_generation
        AND quarantine_generation BETWEEN 0 AND store_generation
        AND event_generation BETWEEN 0 AND store_generation
        AND supervisor_epoch BETWEEN 0 AND 9007199254740991
        AND epoch_observer_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT adapter_store_meta_identity_ck CHECK (
        typeof(root_identity) = 'blob' AND length(root_identity) = 32
        AND typeof(receipt_signer_profile_digest) = 'blob'
        AND length(receipt_signer_profile_digest) = 32
    ),
    CONSTRAINT adapter_store_meta_capacity_ck CHECK (
        ordinary_queue_capacity = 1024 AND control_queue_capacity = 32
    ),
    CONSTRAINT adapter_store_meta_lifecycle_ck CHECK (
        (root_lifecycle_state = 'ACTIVE'
         AND restore_index_digest IS NULL
         AND restore_state_generation = 0)
        OR
        (root_lifecycle_state = 'RESTORE_PENDING'
         AND typeof(restore_index_digest) = 'blob'
         AND length(restore_index_digest) = 32
         AND restore_state_generation BETWEEN 1 AND store_generation)
    )
) STRICT, WITHOUT ROWID;

CREATE TRIGGER adapter_store_meta_single_row_guard
BEFORE INSERT ON adapter_store_meta
WHEN EXISTS (SELECT 1 FROM adapter_store_meta)
BEGIN SELECT RAISE(ABORT, 'adapter metadata row already exists'); END;

CREATE TRIGGER adapter_store_meta_no_delete
BEFORE DELETE ON adapter_store_meta
BEGIN SELECT RAISE(ABORT, 'adapter metadata is permanent'); END;

CREATE TRIGGER adapter_store_meta_update_guard
BEFORE UPDATE ON adapter_store_meta
WHEN NOT (
    NEW.singleton = OLD.singleton
    AND NEW.format_version = OLD.format_version
    AND NEW.ordinary_queue_capacity = OLD.ordinary_queue_capacity
    AND NEW.control_queue_capacity = OLD.control_queue_capacity
    AND NEW.store_generation > OLD.store_generation
    AND NEW.inbox_generation BETWEEN OLD.inbox_generation AND NEW.store_generation
    AND NEW.consumption_generation BETWEEN OLD.consumption_generation AND NEW.store_generation
    AND NEW.receipt_generation BETWEEN OLD.receipt_generation AND NEW.store_generation
    AND NEW.conflict_generation BETWEEN OLD.conflict_generation AND NEW.store_generation
    AND NEW.quarantine_generation BETWEEN OLD.quarantine_generation AND NEW.store_generation
    AND NEW.event_generation BETWEEN OLD.event_generation AND NEW.store_generation
    AND NEW.supervisor_epoch >= OLD.supervisor_epoch
    AND NEW.epoch_observer_generation >= OLD.epoch_observer_generation
    AND (
        (OLD.root_lifecycle_state = 'ACTIVE'
         AND NEW.root_lifecycle_state = 'ACTIVE'
         AND NEW.root_identity = OLD.root_identity
         AND NEW.receipt_signer_profile_digest = OLD.receipt_signer_profile_digest
         AND NEW.restore_index_digest IS NULL
         AND NEW.restore_state_generation = 0)
        OR
        (OLD.root_lifecycle_state = 'ACTIVE'
         AND NEW.root_lifecycle_state = 'RESTORE_PENDING'
         AND NEW.root_identity <> OLD.root_identity
         AND NEW.supervisor_epoch > OLD.supervisor_epoch
         AND typeof(NEW.restore_index_digest) = 'blob'
         AND length(NEW.restore_index_digest) = 32
         AND NEW.restore_state_generation = NEW.store_generation)
        OR
        (OLD.root_lifecycle_state = 'RESTORE_PENDING'
         AND NEW.root_lifecycle_state = 'RESTORE_PENDING'
         AND NEW.root_identity = OLD.root_identity
         AND NEW.receipt_signer_profile_digest = OLD.receipt_signer_profile_digest
         AND NEW.restore_index_digest = OLD.restore_index_digest
         AND NEW.restore_state_generation = OLD.restore_state_generation)
    )
)
BEGIN SELECT RAISE(ABORT, 'invalid adapter metadata projection update'); END;

CREATE TABLE grant_inbox (
    grant_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    plan_id BLOB NOT NULL,
    task_id TEXT COLLATE BINARY NOT NULL,
    workload_id TEXT COLLATE BINARY NOT NULL,
    task_lease_digest BLOB NOT NULL,
    one_shot_nonce BLOB NOT NULL,
    grant_digest BLOB NOT NULL,
    canonical_grant BLOB NOT NULL,
    canonical_grant_length INTEGER NOT NULL,
    coordinator_key_fingerprint BLOB NOT NULL,
    destination_adapter_id TEXT COLLATE BINARY NOT NULL,
    protocol_version INTEGER NOT NULL,
    observed_supervisor_epoch INTEGER NOT NULL,
    epoch_observer_generation INTEGER NOT NULL,
    inbox_state TEXT COLLATE BINARY NOT NULL,
    received_generation INTEGER NOT NULL,
    current_generation INTEGER NOT NULL,
    receipt_id BLOB,
    receipt_decision TEXT COLLATE BINARY,
    current_event_id BLOB NOT NULL,
    CONSTRAINT grant_inbox_pk PRIMARY KEY (grant_id),
    CONSTRAINT grant_inbox_current_transition_fk FOREIGN KEY (
        grant_id,
        operation_id,
        current_generation,
        current_event_id,
        inbox_state
    ) REFERENCES inbox_transitions (
        grant_id,
        operation_id,
        transition_generation,
        event_id,
        new_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT grant_inbox_receipt_fk FOREIGN KEY (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        receipt_decision
    ) REFERENCES execution_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT grant_inbox_digest_ck CHECK (
        typeof(grant_id) = 'blob' AND length(grant_id) = 32
        AND typeof(dispatch_attempt_id) = 'blob' AND length(dispatch_attempt_id) = 32
        AND typeof(plan_id) = 'blob' AND length(plan_id) = 32
        AND typeof(task_lease_digest) = 'blob' AND length(task_lease_digest) = 32
        AND typeof(one_shot_nonce) = 'blob' AND length(one_shot_nonce) = 32
        AND typeof(grant_digest) = 'blob' AND length(grant_digest) = 32
        AND typeof(coordinator_key_fingerprint) = 'blob'
        AND length(coordinator_key_fingerprint) = 32
    ),
    CONSTRAINT grant_inbox_wire_ck CHECK (
        typeof(canonical_grant) = 'blob'
        AND canonical_grant_length = length(canonical_grant)
        AND canonical_grant_length BETWEEN 1 AND 1048576
    ),
    CONSTRAINT grant_inbox_identifier_ck CHECK (
        length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128
        AND operation_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(task_id AS BLOB)) BETWEEN 1 AND 128
        AND task_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(workload_id AS BLOB)) BETWEEN 1 AND 128
        AND workload_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND length(CAST(destination_adapter_id AS BLOB)) BETWEEN 1 AND 128
        AND destination_adapter_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT grant_inbox_epoch_ck CHECK (
        protocol_version = 1
        AND observed_supervisor_epoch BETWEEN 0 AND 9007199254740991
        AND epoch_observer_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT grant_inbox_state_ck CHECK (
        inbox_state IN ('RECEIVED', 'CONSUMED', 'REFUSED', 'QUARANTINED')
    ),
    CONSTRAINT grant_inbox_generation_ck CHECK (
        received_generation BETWEEN 1 AND 9007199254740991
        AND current_generation BETWEEN received_generation AND 9007199254740991
    ),
    CONSTRAINT grant_inbox_receipt_ck CHECK (
        (inbox_state = 'CONSUMED'
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'CONSUMED')
        OR
        (inbox_state = 'REFUSED'
         AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
         AND receipt_decision = 'REFUSED_DEFINITE')
        OR
        (inbox_state IN ('RECEIVED', 'QUARANTINED')
         AND receipt_id IS NULL AND receipt_decision IS NULL)
    ),
    CONSTRAINT grant_inbox_event_ck CHECK (
        typeof(current_event_id) = 'blob' AND length(current_event_id) = 32
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX grant_inbox_operation_uq ON grant_inbox (operation_id);
CREATE UNIQUE INDEX grant_inbox_nonce_uq ON grant_inbox (one_shot_nonce);
CREATE UNIQUE INDEX grant_inbox_digest_uq ON grant_inbox (grant_digest);
CREATE UNIQUE INDEX grant_inbox_received_generation_uq ON grant_inbox (received_generation);
CREATE UNIQUE INDEX grant_inbox_current_generation_uq ON grant_inbox (current_generation);
CREATE UNIQUE INDEX grant_inbox_complete_identity_uq
    ON grant_inbox (grant_id, operation_id, dispatch_attempt_id);
CREATE UNIQUE INDEX grant_inbox_binding_identity_uq
    ON grant_inbox (grant_id, operation_id);
CREATE UNIQUE INDEX grant_inbox_event_identity_uq
    ON grant_inbox (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        task_id,
        workload_id,
        plan_id,
        task_lease_digest
    );

CREATE TRIGGER grant_inbox_active_root_guard
BEFORE INSERT ON grant_inbox
WHEN NOT EXISTS (
    SELECT 1 FROM adapter_store_meta
    WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
)
BEGIN SELECT RAISE(ABORT, 'RESTORE_PENDING denies new adapter authority'); END;

CREATE TRIGGER grant_inbox_update_guard
BEFORE UPDATE ON grant_inbox
WHEN NOT (
    NEW.grant_id = OLD.grant_id
    AND NEW.operation_id = OLD.operation_id
    AND NEW.dispatch_attempt_id = OLD.dispatch_attempt_id
    AND NEW.plan_id = OLD.plan_id
    AND NEW.task_id = OLD.task_id
    AND NEW.workload_id = OLD.workload_id
    AND NEW.task_lease_digest = OLD.task_lease_digest
    AND NEW.one_shot_nonce = OLD.one_shot_nonce
    AND NEW.grant_digest = OLD.grant_digest
    AND NEW.canonical_grant = OLD.canonical_grant
    AND NEW.canonical_grant_length = OLD.canonical_grant_length
    AND NEW.coordinator_key_fingerprint = OLD.coordinator_key_fingerprint
    AND NEW.destination_adapter_id = OLD.destination_adapter_id
    AND NEW.protocol_version = OLD.protocol_version
    AND NEW.observed_supervisor_epoch = OLD.observed_supervisor_epoch
    AND NEW.epoch_observer_generation = OLD.epoch_observer_generation
    AND NEW.received_generation = OLD.received_generation
    AND NEW.current_generation > OLD.current_generation
    AND OLD.inbox_state = 'RECEIVED'
    AND NEW.inbox_state IN ('CONSUMED', 'REFUSED', 'QUARANTINED')
    AND (
        EXISTS (
            SELECT 1 FROM adapter_store_meta
            WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
        )
        OR NEW.inbox_state = 'QUARANTINED'
    )
)
BEGIN SELECT RAISE(ABORT, 'invalid adapter inbox projection update'); END;

CREATE TABLE inbox_transitions (
    transition_generation INTEGER NOT NULL,
    previous_transition_generation INTEGER,
    grant_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    previous_state TEXT COLLATE BINARY NOT NULL,
    new_state TEXT COLLATE BINARY NOT NULL,
    event_id BLOB NOT NULL,
    evidence_digest BLOB NOT NULL,
    receipt_id BLOB,
    receipt_decision TEXT COLLATE BINARY,
    CONSTRAINT inbox_transitions_pk PRIMARY KEY (transition_generation),
    CONSTRAINT inbox_transitions_grant_fk FOREIGN KEY (grant_id, operation_id)
        REFERENCES grant_inbox (grant_id, operation_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inbox_transitions_previous_fk FOREIGN KEY (
        grant_id,
        operation_id,
        previous_transition_generation,
        previous_state
    ) REFERENCES inbox_transitions (
        grant_id,
        operation_id,
        transition_generation,
        new_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inbox_transitions_event_fk FOREIGN KEY (
        event_id,
        grant_id,
        operation_id,
        transition_generation,
        new_state
    ) REFERENCES adapter_events (
        event_id,
        grant_id,
        operation_id,
        transition_generation,
        effective_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inbox_transitions_receipt_fk FOREIGN KEY (
        receipt_id,
        grant_id,
        operation_id,
        receipt_decision
    ) REFERENCES execution_receipts (
        receipt_id,
        grant_id,
        operation_id,
        decision
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT inbox_transitions_state_ck CHECK (
        (previous_state = 'ABSENT' AND new_state = 'RECEIVED'
         AND previous_transition_generation IS NULL
         AND receipt_id IS NULL AND receipt_decision IS NULL)
        OR (previous_state = 'RECEIVED'
            AND new_state = 'CONSUMED'
            AND previous_transition_generation BETWEEN 1 AND transition_generation - 1
            AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
            AND receipt_decision = 'CONSUMED')
        OR (previous_state = 'RECEIVED'
            AND new_state = 'REFUSED'
            AND previous_transition_generation BETWEEN 1 AND transition_generation - 1
            AND typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
            AND receipt_decision = 'REFUSED_DEFINITE')
        OR (previous_state = 'RECEIVED'
            AND new_state = 'QUARANTINED'
            AND previous_transition_generation BETWEEN 1 AND transition_generation - 1
            AND receipt_id IS NULL AND receipt_decision IS NULL)
    ),
    CONSTRAINT inbox_transitions_digest_ck CHECK (
        typeof(event_id) = 'blob' AND length(event_id) = 32
        AND typeof(evidence_digest) = 'blob' AND length(evidence_digest) = 32
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX inbox_transitions_complete_identity_uq
    ON inbox_transitions (
        grant_id,
        operation_id,
        transition_generation,
        event_id,
        new_state
    );
CREATE UNIQUE INDEX inbox_transitions_state_identity_uq
    ON inbox_transitions (grant_id, operation_id, transition_generation, new_state);
CREATE UNIQUE INDEX inbox_transitions_single_successor_uq
    ON inbox_transitions (grant_id, operation_id, previous_state);

CREATE TRIGGER inbox_transitions_current_projection_guard
AFTER INSERT ON inbox_transitions
WHEN NOT EXISTS (
    SELECT 1 FROM grant_inbox
    WHERE grant_inbox.grant_id = NEW.grant_id
      AND grant_inbox.operation_id = NEW.operation_id
      AND grant_inbox.current_generation = NEW.transition_generation
      AND grant_inbox.current_event_id = NEW.event_id
      AND grant_inbox.inbox_state = NEW.new_state
)
BEGIN SELECT RAISE(ABORT, 'inbox transition must be the current projection when appended'); END;

CREATE TRIGGER inbox_transitions_no_update BEFORE UPDATE ON inbox_transitions
BEGIN SELECT RAISE(ABORT, 'adapter transitions are append-only'); END;

CREATE TABLE execution_receipts (
    receipt_id BLOB NOT NULL,
    grant_id BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    dispatch_attempt_id BLOB NOT NULL,
    receipt_digest BLOB NOT NULL,
    canonical_receipt BLOB NOT NULL,
    canonical_receipt_length INTEGER NOT NULL,
    adapter_key_id TEXT COLLATE BINARY NOT NULL,
    adapter_key_fingerprint BLOB NOT NULL,
    decision TEXT COLLATE BINARY NOT NULL,
    refusal_code TEXT COLLATE BINARY,
    no_consumption_tombstone_digest BLOB,
    receipt_generation INTEGER NOT NULL,
    CONSTRAINT execution_receipts_pk PRIMARY KEY (receipt_id),
    CONSTRAINT execution_receipts_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id
    ) REFERENCES grant_inbox (grant_id, operation_id, dispatch_attempt_id),
    CONSTRAINT execution_receipts_digest_ck CHECK (
        typeof(receipt_id) = 'blob' AND length(receipt_id) = 32
        AND typeof(dispatch_attempt_id) = 'blob' AND length(dispatch_attempt_id) = 32
        AND typeof(receipt_digest) = 'blob' AND length(receipt_digest) = 32
        AND typeof(adapter_key_fingerprint) = 'blob' AND length(adapter_key_fingerprint) = 32
    ),
    CONSTRAINT execution_receipts_wire_ck CHECK (
        typeof(canonical_receipt) = 'blob'
        AND canonical_receipt_length = length(canonical_receipt)
        AND canonical_receipt_length BETWEEN 1 AND 65536
    ),
    CONSTRAINT execution_receipts_key_ck CHECK (
        length(CAST(adapter_key_id AS BLOB)) BETWEEN 1 AND 128
        AND adapter_key_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT execution_receipts_decision_ck CHECK (
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
    CONSTRAINT execution_receipts_generation_ck CHECK (
        receipt_generation BETWEEN 1 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX execution_receipts_grant_uq ON execution_receipts (grant_id);
CREATE UNIQUE INDEX execution_receipts_operation_uq ON execution_receipts (operation_id);
CREATE UNIQUE INDEX execution_receipts_digest_uq ON execution_receipts (receipt_digest);
CREATE UNIQUE INDEX execution_receipts_generation_uq ON execution_receipts (receipt_generation);
CREATE UNIQUE INDEX execution_receipts_complete_identity_uq
    ON execution_receipts (
        receipt_id,
        grant_id,
        operation_id,
        dispatch_attempt_id,
        decision
    );
CREATE UNIQUE INDEX execution_receipts_transition_identity_uq
    ON execution_receipts (receipt_id, grant_id, operation_id, decision);

CREATE TRIGGER execution_receipts_no_update BEFORE UPDATE ON execution_receipts
BEGIN SELECT RAISE(ABORT, 'adapter receipts are append-only'); END;

CREATE TABLE inbox_conflicts (
    conflict_id BLOB NOT NULL,
    observed_grant_id BLOB NOT NULL,
    observed_operation_digest BLOB NOT NULL,
    observed_nonce_digest BLOB NOT NULL,
    retained_binding_digest BLOB NOT NULL,
    conflicting_binding_digest BLOB NOT NULL,
    public_reason_code TEXT COLLATE BINARY NOT NULL,
    conflict_generation INTEGER NOT NULL,
    CONSTRAINT inbox_conflicts_pk PRIMARY KEY (conflict_id),
    CONSTRAINT inbox_conflicts_digest_ck CHECK (
        typeof(conflict_id) = 'blob' AND length(conflict_id) = 32
        AND typeof(observed_grant_id) = 'blob' AND length(observed_grant_id) = 32
        AND typeof(observed_operation_digest) = 'blob' AND length(observed_operation_digest) = 32
        AND typeof(observed_nonce_digest) = 'blob' AND length(observed_nonce_digest) = 32
        AND typeof(retained_binding_digest) = 'blob' AND length(retained_binding_digest) = 32
        AND typeof(conflicting_binding_digest) = 'blob'
        AND length(conflicting_binding_digest) = 32
    ),
    CONSTRAINT inbox_conflicts_reason_ck CHECK (
        length(CAST(public_reason_code AS BLOB)) BETWEEN 1 AND 64
        AND public_reason_code NOT GLOB '*[^A-Z0-9_]*'
    ),
    CONSTRAINT inbox_conflicts_generation_ck CHECK (
        conflict_generation BETWEEN 1 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX inbox_conflicts_generation_uq ON inbox_conflicts (conflict_generation);

CREATE TABLE inbox_quarantines (
    quarantine_id BLOB NOT NULL,
    grant_id BLOB,
    evidence_digest BLOB NOT NULL,
    public_reason_code TEXT COLLATE BINARY NOT NULL,
    quarantine_generation INTEGER NOT NULL,
    resolved_generation INTEGER,
    CONSTRAINT inbox_quarantines_pk PRIMARY KEY (quarantine_id),
    CONSTRAINT inbox_quarantines_digest_ck CHECK (
        typeof(quarantine_id) = 'blob' AND length(quarantine_id) = 32
        AND (grant_id IS NULL OR (typeof(grant_id) = 'blob' AND length(grant_id) = 32))
        AND typeof(evidence_digest) = 'blob' AND length(evidence_digest) = 32
    ),
    CONSTRAINT inbox_quarantines_reason_ck CHECK (
        length(CAST(public_reason_code AS BLOB)) BETWEEN 1 AND 64
        AND public_reason_code NOT GLOB '*[^A-Z0-9_]*'
    ),
    CONSTRAINT inbox_quarantines_generation_ck CHECK (
        quarantine_generation BETWEEN 1 AND 9007199254740991
        AND (resolved_generation IS NULL
             OR resolved_generation BETWEEN quarantine_generation + 1 AND 9007199254740991)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX inbox_quarantines_generation_uq
    ON inbox_quarantines (quarantine_generation);

CREATE TABLE adapter_events (
    event_id BLOB NOT NULL,
    event_generation INTEGER NOT NULL,
    transition_generation INTEGER,
    grant_id BLOB,
    operation_id TEXT COLLATE BINARY,
    dispatch_attempt_id BLOB,
    task_id TEXT COLLATE BINARY,
    workload_id TEXT COLLATE BINARY,
    plan_id BLOB,
    task_lease_digest BLOB,
    event_contract_version INTEGER NOT NULL,
    grant_contract_version INTEGER NOT NULL,
    receipt_contract_version INTEGER NOT NULL,
    effective_state TEXT COLLATE BINARY,
    decision TEXT COLLATE BINARY NOT NULL,
    latency_ms INTEGER NOT NULL,
    event_kind TEXT COLLATE BINARY NOT NULL,
    public_reason_code TEXT COLLATE BINARY,
    public_trace_id TEXT COLLATE BINARY NOT NULL,
    delivery_state TEXT COLLATE BINARY NOT NULL,
    delivered_generation INTEGER,
    CONSTRAINT adapter_events_pk PRIMARY KEY (event_id),
    CONSTRAINT adapter_events_grant_fk FOREIGN KEY (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        task_id,
        workload_id,
        plan_id,
        task_lease_digest
    ) REFERENCES grant_inbox (
        grant_id,
        operation_id,
        dispatch_attempt_id,
        task_id,
        workload_id,
        plan_id,
        task_lease_digest
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT adapter_events_transition_fk FOREIGN KEY (
        grant_id,
        operation_id,
        transition_generation,
        event_id,
        effective_state
    ) REFERENCES inbox_transitions (
        grant_id,
        operation_id,
        transition_generation,
        event_id,
        new_state
    ) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT adapter_events_event_id_ck CHECK (
        typeof(event_id) = 'blob' AND length(event_id) = 32
        AND (grant_id IS NULL OR (typeof(grant_id) = 'blob' AND length(grant_id) = 32))
        AND (dispatch_attempt_id IS NULL
             OR (typeof(dispatch_attempt_id) = 'blob' AND length(dispatch_attempt_id) = 32))
        AND (plan_id IS NULL OR (typeof(plan_id) = 'blob' AND length(plan_id) = 32))
        AND (task_lease_digest IS NULL
             OR (typeof(task_lease_digest) = 'blob' AND length(task_lease_digest) = 32))
    ),
    CONSTRAINT adapter_events_generation_ck CHECK (
        event_generation BETWEEN 1 AND 9007199254740991
        AND (transition_generation IS NULL
             OR transition_generation BETWEEN 1 AND 9007199254740991)
        AND latency_ms BETWEEN 0 AND 9007199254740991
        AND (delivered_generation IS NULL
             OR delivered_generation BETWEEN event_generation AND 9007199254740991)
    ),
    CONSTRAINT adapter_events_kind_ck CHECK (
        event_contract_version = 1
        AND grant_contract_version IN (0, 1)
        AND receipt_contract_version IN (0, 1)
        AND (
            (event_kind = 'GRANT_RECEIVED'
             AND effective_state = 'RECEIVED'
             AND decision = 'RECEIVED'
             AND grant_contract_version = 1
             AND receipt_contract_version = 0)
            OR
            (event_kind = 'GRANT_CONSUMED'
             AND effective_state = 'CONSUMED'
             AND decision = 'CONSUMED'
             AND grant_contract_version = 1
             AND receipt_contract_version = 1)
            OR
            (event_kind = 'GRANT_REFUSED'
             AND effective_state = 'REFUSED'
             AND decision = 'REFUSED_DEFINITE'
             AND grant_contract_version = 1
             AND receipt_contract_version = 1)
            OR
            (event_kind = 'GRANT_QUARANTINED'
             AND effective_state = 'QUARANTINED'
             AND decision = 'QUARANTINED'
             AND grant_contract_version = 1
             AND receipt_contract_version = 0)
            OR
            (event_kind = 'GRANT_CONFLICT'
             AND effective_state IS NULL
             AND decision = 'CONFLICT'
             AND grant_contract_version = 0
             AND receipt_contract_version = 0)
            OR
            (event_kind = 'RESTORE_PENDING'
             AND effective_state IS NULL
             AND decision = 'RESTORE_PENDING'
             AND grant_contract_version = 0
             AND receipt_contract_version = 0)
        )
        AND (
            event_kind IN (
                'GRANT_RECEIVED',
                'GRANT_CONSUMED',
                'GRANT_REFUSED',
                'GRANT_QUARANTINED'
            )
            AND transition_generation IS NOT NULL
            AND grant_id IS NOT NULL
            AND operation_id IS NOT NULL
            AND dispatch_attempt_id IS NOT NULL
            AND task_id IS NOT NULL
            AND workload_id IS NOT NULL
            AND plan_id IS NOT NULL
            AND task_lease_digest IS NOT NULL
            OR event_kind IN ('GRANT_CONFLICT', 'RESTORE_PENDING')
            AND transition_generation IS NULL
            AND grant_id IS NULL
            AND operation_id IS NULL
            AND dispatch_attempt_id IS NULL
            AND task_id IS NULL
            AND workload_id IS NULL
            AND plan_id IS NULL
            AND task_lease_digest IS NULL
        )
    ),
    CONSTRAINT adapter_events_public_ck CHECK (
        (public_reason_code IS NULL
         OR (length(CAST(public_reason_code AS BLOB)) BETWEEN 1 AND 64
             AND public_reason_code NOT GLOB '*[^A-Z0-9_]*'))
        AND length(CAST(public_trace_id AS BLOB)) BETWEEN 1 AND 128
        AND public_trace_id NOT GLOB '*[^-A-Za-z0-9._:]*'
        AND (task_id IS NULL
             OR (length(CAST(task_id AS BLOB)) BETWEEN 1 AND 128
                 AND task_id NOT GLOB '*[^-A-Za-z0-9._:]*'))
        AND (workload_id IS NULL
             OR (length(CAST(workload_id AS BLOB)) BETWEEN 1 AND 128
                 AND workload_id NOT GLOB '*[^-A-Za-z0-9._:]*'))
    ),
    CONSTRAINT adapter_events_delivery_ck CHECK (
        (delivery_state = 'PENDING' AND delivered_generation IS NULL)
        OR (delivery_state = 'DELIVERED' AND delivered_generation IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX adapter_events_generation_uq ON adapter_events (event_generation);
CREATE UNIQUE INDEX adapter_events_transition_uq
    ON adapter_events (
        event_id,
        grant_id,
        operation_id,
        transition_generation,
        effective_state
    );
CREATE UNIQUE INDEX adapter_events_one_per_transition_uq
    ON adapter_events (grant_id, operation_id, transition_generation)
    WHERE transition_generation IS NOT NULL;

CREATE TRIGGER adapter_events_update_guard
BEFORE UPDATE ON adapter_events
WHEN NOT (
    NEW.event_id = OLD.event_id
    AND NEW.event_generation = OLD.event_generation
    AND NEW.transition_generation IS OLD.transition_generation
    AND NEW.grant_id IS OLD.grant_id
    AND NEW.operation_id IS OLD.operation_id
    AND NEW.dispatch_attempt_id IS OLD.dispatch_attempt_id
    AND NEW.task_id IS OLD.task_id
    AND NEW.workload_id IS OLD.workload_id
    AND NEW.plan_id IS OLD.plan_id
    AND NEW.task_lease_digest IS OLD.task_lease_digest
    AND NEW.event_contract_version = OLD.event_contract_version
    AND NEW.grant_contract_version = OLD.grant_contract_version
    AND NEW.receipt_contract_version = OLD.receipt_contract_version
    AND NEW.effective_state IS OLD.effective_state
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

CREATE TRIGGER execution_receipts_active_root_guard
BEFORE INSERT ON execution_receipts
WHEN NOT EXISTS (
    SELECT 1 FROM adapter_store_meta
    WHERE singleton = 1 AND root_lifecycle_state = 'ACTIVE'
)
BEGIN SELECT RAISE(ABORT, 'RESTORE_PENDING denies new adapter receipts'); END;

CREATE TRIGGER grant_inbox_no_delete BEFORE DELETE ON grant_inbox
BEGIN SELECT RAISE(ABORT, 'adapter inbox history is permanent'); END;
CREATE TRIGGER inbox_transitions_no_delete BEFORE DELETE ON inbox_transitions
BEGIN SELECT RAISE(ABORT, 'adapter transition history is permanent'); END;
CREATE TRIGGER execution_receipts_no_delete BEFORE DELETE ON execution_receipts
BEGIN SELECT RAISE(ABORT, 'adapter receipt history is permanent'); END;
CREATE TRIGGER inbox_conflicts_no_update BEFORE UPDATE ON inbox_conflicts
BEGIN SELECT RAISE(ABORT, 'adapter conflicts are append-only'); END;
CREATE TRIGGER inbox_conflicts_no_delete BEFORE DELETE ON inbox_conflicts
BEGIN SELECT RAISE(ABORT, 'adapter conflict history is permanent'); END;
CREATE TRIGGER inbox_quarantines_update_guard
BEFORE UPDATE ON inbox_quarantines
WHEN NOT (
    NEW.quarantine_id = OLD.quarantine_id
    AND NEW.grant_id IS OLD.grant_id
    AND NEW.evidence_digest = OLD.evidence_digest
    AND NEW.public_reason_code = OLD.public_reason_code
    AND NEW.quarantine_generation = OLD.quarantine_generation
    AND OLD.resolved_generation IS NULL
    AND NEW.resolved_generation > OLD.quarantine_generation
)
BEGIN SELECT RAISE(ABORT, 'only unresolved-to-resolved quarantine projection is mutable'); END;
CREATE TRIGGER inbox_quarantines_no_delete BEFORE DELETE ON inbox_quarantines
BEGIN SELECT RAISE(ABORT, 'adapter quarantine history is permanent'); END;
CREATE TRIGGER adapter_events_no_delete BEFORE DELETE ON adapter_events
BEGIN SELECT RAISE(ABORT, 'adapter event history is permanent'); END;
