-- HelixOS PLAN-006 independent durable task-authority schema v1.
--
-- Normative identity:
--   application_id = 1212962881 = 0x484c5841 = "HLXA"
--   user_version   = 1
--
-- This file defines the reviewed logical schema. Production initialization MUST run
-- it only in an approved empty staging root under the explicit PAUSED bootstrap
-- protocol, inside one transaction, and publish the completed root last. Ordinary
-- open MUST NOT execute this file, migrate, repair, synthesize, or backfill authority.
-- All digests are 64 lowercase hexadecimal characters. All signed_wire values are
-- exact RFC 8785 UTF-8 bytes. Cross-wire cryptography and relational invariants that
-- SQLite cannot prove are revalidated by the typed implementation on open/readback.

PRAGMA application_id = 1212962881;

CREATE TABLE authority_store_metadata (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    application_id INTEGER NOT NULL CHECK (application_id = 1212962881),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    schema_digest TEXT NOT NULL CHECK (
        length(schema_digest) = 64 AND
        schema_digest NOT GLOB '*[^0-9a-f]*'
    ),
    root_id TEXT NOT NULL UNIQUE CHECK (length(root_id) BETWEEN 1 AND 128),
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('ACTIVE', 'RESTORE_PENDING')),
    durability_profile TEXT NOT NULL CHECK (
        durability_profile = 'WAL_FULL_CONTROLLED_CHECKPOINT_V1'
    ),
    boot_id TEXT NOT NULL CHECK (length(boot_id) BETWEEN 1 AND 128),
    instance_epoch INTEGER NOT NULL CHECK (instance_epoch BETWEEN 1 AND 9007199254740991),
    fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch BETWEEN 1 AND 9007199254740991),
    restore_epoch INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9007199254740991),
    ordinary_capacity INTEGER NOT NULL CHECK (ordinary_capacity = 1024),
    control_capacity INTEGER NOT NULL CHECK (control_capacity = 32),
    store_generation INTEGER NOT NULL CHECK (store_generation BETWEEN 1 AND 9007199254740991),
    trust_generation INTEGER NOT NULL CHECK (trust_generation BETWEEN 1 AND store_generation),
    grant_generation INTEGER NOT NULL CHECK (grant_generation BETWEEN 1 AND store_generation),
    lease_generation INTEGER NOT NULL CHECK (lease_generation BETWEEN 1 AND store_generation),
    allocation_generation INTEGER NOT NULL CHECK (allocation_generation BETWEEN 1 AND store_generation),
    counter_generation INTEGER NOT NULL CHECK (counter_generation BETWEEN 1 AND store_generation),
    decision_generation INTEGER NOT NULL CHECK (decision_generation BETWEEN 1 AND store_generation),
    revocation_generation INTEGER NOT NULL CHECK (revocation_generation BETWEEN 1 AND store_generation),
    event_generation INTEGER NOT NULL CHECK (event_generation BETWEEN 1 AND store_generation),
    migration_generation INTEGER NOT NULL CHECK (migration_generation BETWEEN 1 AND store_generation),
    backup_generation INTEGER NOT NULL CHECK (backup_generation BETWEEN 0 AND store_generation),
    restore_generation INTEGER NOT NULL CHECK (restore_generation BETWEEN 0 AND store_generation),
    created_at_utc_ms INTEGER NOT NULL CHECK (created_at_utc_ms BETWEEN 0 AND 9007199254740991),
    bootstrap_receipt_id TEXT NOT NULL UNIQUE CHECK (length(bootstrap_receipt_id) = 64),
    restore_receipt_id TEXT CHECK (restore_receipt_id IS NULL OR length(restore_receipt_id) = 64)
) STRICT;

CREATE TABLE authority_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 64 AND attempt_id NOT GLOB '*[^0-9a-f]*'
    ),
    operation_kind TEXT NOT NULL CHECK (operation_kind IN (
        'BOOTSTRAP', 'KEY_STATUS_CHANGE', 'ROOT_LEASE_ISSUE',
        'CHILD_LEASE_ISSUE', 'COUNTER_CONSUME', 'DECISION_RETAIN',
        'AUTHORITY_REVOKE', 'BACKUP_PUBLISH', 'RESTORE_PUBLISH'
    )),
    namespace_digest TEXT NOT NULL CHECK (
        length(namespace_digest) = 64 AND
        namespace_digest NOT GLOB '*[^0-9a-f]*'
    ),
    input_graph_digest TEXT NOT NULL CHECK (
        length(input_graph_digest) = 64 AND
        input_graph_digest NOT GLOB '*[^0-9a-f]*'
    ),
    caller_deadline_monotonic_ms INTEGER NOT NULL CHECK (
        caller_deadline_monotonic_ms BETWEEN 1 AND 9007199254740991
    ),
    outcome_code TEXT NOT NULL CHECK (outcome_code IN (
        'COMMITTED_RETAINED', 'CONFLICT_RETAINED', 'RESTORE_PENDING'
    )),
    outcome_binding_digest TEXT NOT NULL CHECK (
        length(outcome_binding_digest) = 64 AND
        outcome_binding_digest NOT GLOB '*[^0-9a-f]*'
    ),
    attempt_generation INTEGER NOT NULL UNIQUE CHECK (
        attempt_generation BETWEEN 1 AND 9007199254740991
    ),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    FOREIGN KEY (event_id) REFERENCES authority_events (event_id)
        DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE authority_bootstrap_receipts (
    bootstrap_receipt_id TEXT PRIMARY KEY CHECK (
        length(bootstrap_receipt_id) = 64 AND
        bootstrap_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    bootstrap_attempt_id TEXT NOT NULL UNIQUE CHECK (length(bootstrap_attempt_id) = 64),
    source_commit TEXT NOT NULL CHECK (
        length(source_commit) = 40 AND source_commit NOT GLOB '*[^0-9a-f]*'
    ),
    source_tree TEXT NOT NULL CHECK (
        length(source_tree) = 40 AND source_tree NOT GLOB '*[^0-9a-f]*'
    ),
    source_application_id INTEGER NOT NULL CHECK (source_application_id = 1212962883),
    source_user_version INTEGER NOT NULL CHECK (source_user_version = 2),
    source_root_id TEXT NOT NULL CHECK (length(source_root_id) BETWEEN 1 AND 128),
    source_schema_digest TEXT NOT NULL CHECK (length(source_schema_digest) = 64),
    source_backup_digest TEXT NOT NULL CHECK (length(source_backup_digest) = 64),
    source_summary_digest TEXT NOT NULL CHECK (length(source_summary_digest) = 64),
    target_root_id TEXT NOT NULL UNIQUE CHECK (length(target_root_id) BETWEEN 1 AND 128),
    target_schema_digest TEXT NOT NULL CHECK (length(target_schema_digest) = 64),
    imported_grant_count INTEGER NOT NULL CHECK (imported_grant_count = 0),
    imported_lease_count INTEGER NOT NULL CHECK (imported_lease_count = 0),
    imported_decision_count INTEGER NOT NULL CHECK (imported_decision_count = 0),
    migration_generation INTEGER NOT NULL UNIQUE CHECK (
        migration_generation BETWEEN 1 AND 9007199254740991
    ),
    created_at_utc_ms INTEGER NOT NULL CHECK (created_at_utc_ms BETWEEN 0 AND 9007199254740991),
    tool_identity TEXT NOT NULL CHECK (length(tool_identity) BETWEEN 1 AND 128),
    tool_digest TEXT NOT NULL CHECK (length(tool_digest) = 64),
    FOREIGN KEY (bootstrap_attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE authority_verification_keys (
    key_purpose TEXT NOT NULL CHECK (key_purpose IN (
        'request-surface-grant-signing',
        'core-task-lease-signing',
        'core-approval-decision-signing'
    )),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
    issuer_id TEXT NOT NULL CHECK (length(issuer_id) BETWEEN 1 AND 128),
    algorithm TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    public_key_fingerprint TEXT NOT NULL UNIQUE CHECK (length(public_key_fingerprint) = 64),
    provenance_digest TEXT NOT NULL CHECK (length(provenance_digest) = 64),
    introduced_generation INTEGER NOT NULL CHECK (
        introduced_generation BETWEEN 1 AND 9007199254740991
    ),
    PRIMARY KEY (key_purpose, key_id),
    UNIQUE (key_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE authority_key_status_events (
    key_status_event_id TEXT PRIMARY KEY CHECK (length(key_status_event_id) = 64),
    key_purpose TEXT NOT NULL,
    key_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('TRUSTED', 'RETIRED', 'REVOKED')),
    effective_at_utc_ms INTEGER NOT NULL CHECK (effective_at_utc_ms BETWEEN 0 AND 9007199254740991),
    trust_generation INTEGER NOT NULL UNIQUE CHECK (trust_generation BETWEEN 1 AND 9007199254740991),
    attempt_id TEXT NOT NULL CHECK (length(attempt_id) = 64),
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'KEY_INTRODUCED', 'KEY_ROTATED', 'KEY_RETIRED', 'KEY_COMPROMISED', 'ADMIN_REVOKED'
    )),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    FOREIGN KEY (key_purpose, key_id)
        REFERENCES authority_verification_keys (key_purpose, key_id),
    FOREIGN KEY (attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX authority_key_status_by_key_generation
    ON authority_key_status_events (key_purpose, key_id, trust_generation DESC);

CREATE TABLE human_request_grants (
    grant_issuer_id TEXT NOT NULL CHECK (length(grant_issuer_id) BETWEEN 1 AND 128),
    grant_id TEXT NOT NULL CHECK (length(grant_id) = 64),
    grant_digest TEXT NOT NULL UNIQUE CHECK (length(grant_digest) = 64),
    signed_wire BLOB NOT NULL CHECK (length(signed_wire) BETWEEN 1 AND 65536),
    signed_wire_sha256 TEXT NOT NULL UNIQUE CHECK (length(signed_wire_sha256) = 64),
    key_purpose TEXT NOT NULL CHECK (key_purpose = 'request-surface-grant-signing'),
    key_id TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL CHECK (length(key_fingerprint) = 64),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 128),
    channel_id TEXT NOT NULL CHECK (length(channel_id) BETWEEN 1 AND 128),
    session_id TEXT NOT NULL CHECK (length(session_id) BETWEEN 1 AND 128),
    audience TEXT NOT NULL CHECK (length(audience) BETWEEN 1 AND 128),
    scope_template_id TEXT NOT NULL CHECK (length(scope_template_id) BETWEEN 1 AND 128),
    scope_template_digest TEXT NOT NULL CHECK (length(scope_template_digest) = 64),
    scope_template_generation INTEGER NOT NULL CHECK (
        scope_template_generation BETWEEN 1 AND 9007199254740991
    ),
    issued_at_utc_ms INTEGER NOT NULL CHECK (issued_at_utc_ms BETWEEN 0 AND 9007199254740991),
    expires_at_utc_ms INTEGER NOT NULL CHECK (
        expires_at_utc_ms BETWEEN 1 AND 9007199254740991 AND issued_at_utc_ms < expires_at_utc_ms
    ),
    verification_generation INTEGER NOT NULL CHECK (
        verification_generation BETWEEN 1 AND 9007199254740991
    ),
    retained_generation INTEGER NOT NULL UNIQUE CHECK (
        retained_generation BETWEEN 1 AND 9007199254740991
    ),
    PRIMARY KEY (grant_issuer_id, grant_id),
    FOREIGN KEY (key_purpose, key_id)
        REFERENCES authority_verification_keys (key_purpose, key_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE task_leases (
    lease_issuer_id TEXT NOT NULL CHECK (length(lease_issuer_id) BETWEEN 1 AND 128),
    lease_id TEXT NOT NULL CHECK (length(lease_id) = 64),
    lease_digest TEXT NOT NULL UNIQUE CHECK (length(lease_digest) = 64),
    signed_wire BLOB NOT NULL CHECK (length(signed_wire) BETWEEN 1 AND 1048576),
    signed_wire_sha256 TEXT NOT NULL UNIQUE CHECK (length(signed_wire_sha256) = 64),
    key_purpose TEXT NOT NULL CHECK (key_purpose = 'core-task-lease-signing'),
    key_id TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL CHECK (length(key_fingerprint) = 64),
    source_grant_issuer_id TEXT NOT NULL,
    source_grant_id TEXT NOT NULL CHECK (length(source_grant_id) = 64),
    source_grant_digest TEXT NOT NULL CHECK (length(source_grant_digest) = 64),
    task_id TEXT NOT NULL CHECK (length(task_id) BETWEEN 1 AND 128),
    workload_id TEXT NOT NULL CHECK (length(workload_id) BETWEEN 1 AND 128),
    parent_lease_issuer_id TEXT,
    parent_lease_id TEXT,
    parent_lease_digest TEXT,
    parent_allocation_id TEXT,
    delegation_depth INTEGER NOT NULL CHECK (delegation_depth BETWEEN 0 AND 32),
    boot_id TEXT NOT NULL CHECK (length(boot_id) BETWEEN 1 AND 128),
    instance_epoch INTEGER NOT NULL CHECK (instance_epoch BETWEEN 0 AND 9007199254740991),
    expires_at_utc_ms INTEGER NOT NULL CHECK (expires_at_utc_ms BETWEEN 1 AND 9007199254740991),
    deadline_monotonic_ms INTEGER NOT NULL CHECK (
        deadline_monotonic_ms BETWEEN 1 AND 9007199254740991
    ),
    creation_attempt_id TEXT NOT NULL UNIQUE CHECK (length(creation_attempt_id) = 64),
    created_generation INTEGER NOT NULL UNIQUE CHECK (
        created_generation BETWEEN 1 AND 9007199254740991
    ),
    PRIMARY KEY (lease_issuer_id, lease_id),
    FOREIGN KEY (key_purpose, key_id)
        REFERENCES authority_verification_keys (key_purpose, key_id),
    FOREIGN KEY (creation_attempt_id) REFERENCES authority_attempts (attempt_id),
    FOREIGN KEY (source_grant_issuer_id, source_grant_id)
        REFERENCES human_request_grants (grant_issuer_id, grant_id),
    FOREIGN KEY (parent_lease_issuer_id, parent_lease_id)
        REFERENCES task_leases (lease_issuer_id, lease_id),
    CHECK (
        (delegation_depth = 0 AND parent_lease_issuer_id IS NULL AND
         parent_lease_id IS NULL AND parent_lease_digest IS NULL AND
         parent_allocation_id IS NULL) OR
        (delegation_depth > 0 AND parent_lease_issuer_id IS NOT NULL AND
         length(parent_lease_id) = 64 AND length(parent_lease_digest) = 64 AND
         length(parent_allocation_id) = 64)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX task_leases_by_source
    ON task_leases (source_grant_issuer_id, source_grant_id, delegation_depth);
CREATE INDEX task_leases_by_parent
    ON task_leases (parent_lease_issuer_id, parent_lease_id);

CREATE TABLE human_grant_claims (
    grant_issuer_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    grant_digest TEXT NOT NULL CHECK (length(grant_digest) = 64),
    claim_attempt_id TEXT NOT NULL UNIQUE CHECK (length(claim_attempt_id) = 64),
    root_lease_issuer_id TEXT NOT NULL,
    root_lease_id TEXT NOT NULL CHECK (length(root_lease_id) = 64),
    root_lease_digest TEXT NOT NULL UNIQUE CHECK (length(root_lease_digest) = 64),
    claim_generation INTEGER NOT NULL UNIQUE CHECK (
        claim_generation BETWEEN 1 AND 9007199254740991
    ),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    PRIMARY KEY (grant_issuer_id, grant_id),
    FOREIGN KEY (grant_issuer_id, grant_id)
        REFERENCES human_request_grants (grant_issuer_id, grant_id),
    FOREIGN KEY (root_lease_issuer_id, root_lease_id)
        REFERENCES task_leases (lease_issuer_id, lease_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (claim_attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE task_lease_usage (
    lease_issuer_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    allocated_read_bytes INTEGER NOT NULL CHECK (allocated_read_bytes BETWEEN 0 AND 9007199254740991),
    allocated_distinct_files INTEGER NOT NULL CHECK (allocated_distinct_files BETWEEN 0 AND 9007199254740991),
    allocated_actions INTEGER NOT NULL CHECK (allocated_actions BETWEEN 0 AND 9007199254740991),
    allocated_egress_bytes INTEGER NOT NULL CHECK (allocated_egress_bytes BETWEEN 0 AND 9007199254740991),
    allocated_cost_micro_units INTEGER NOT NULL CHECK (allocated_cost_micro_units BETWEEN 0 AND 9007199254740991),
    allocated_plans INTEGER NOT NULL CHECK (allocated_plans BETWEEN 0 AND 9007199254740991),
    allocated_approvals INTEGER NOT NULL CHECK (allocated_approvals BETWEEN 0 AND 9007199254740991),
    allocated_child_leases INTEGER NOT NULL CHECK (allocated_child_leases BETWEEN 0 AND 9007199254740991),
    consumed_read_bytes INTEGER NOT NULL CHECK (consumed_read_bytes BETWEEN 0 AND 9007199254740991),
    consumed_distinct_files INTEGER NOT NULL CHECK (consumed_distinct_files BETWEEN 0 AND 9007199254740991),
    consumed_actions INTEGER NOT NULL CHECK (consumed_actions BETWEEN 0 AND 9007199254740991),
    consumed_plans INTEGER NOT NULL CHECK (consumed_plans BETWEEN 0 AND 9007199254740991),
    consumed_approvals INTEGER NOT NULL CHECK (consumed_approvals BETWEEN 0 AND 9007199254740991),
    allocation_generation INTEGER NOT NULL CHECK (allocation_generation BETWEEN 1 AND 9007199254740991),
    counter_generation INTEGER NOT NULL CHECK (counter_generation BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (lease_issuer_id, lease_id),
    FOREIGN KEY (lease_issuer_id, lease_id)
        REFERENCES task_leases (lease_issuer_id, lease_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE task_lease_allocations (
    allocation_id TEXT PRIMARY KEY CHECK (length(allocation_id) = 64),
    allocation_attempt_id TEXT NOT NULL UNIQUE CHECK (length(allocation_attempt_id) = 64),
    parent_lease_issuer_id TEXT NOT NULL,
    parent_lease_id TEXT NOT NULL,
    parent_lease_digest TEXT NOT NULL CHECK (length(parent_lease_digest) = 64),
    child_lease_issuer_id TEXT NOT NULL,
    child_lease_id TEXT NOT NULL,
    child_lease_digest TEXT NOT NULL UNIQUE CHECK (length(child_lease_digest) = 64),
    allocation_vector_digest TEXT NOT NULL CHECK (length(allocation_vector_digest) = 64),
    allocated_read_bytes INTEGER NOT NULL CHECK (allocated_read_bytes BETWEEN 0 AND 9007199254740991),
    allocated_distinct_files INTEGER NOT NULL CHECK (allocated_distinct_files BETWEEN 0 AND 9007199254740991),
    allocated_actions INTEGER NOT NULL CHECK (allocated_actions BETWEEN 0 AND 9007199254740991),
    allocated_egress_bytes INTEGER NOT NULL CHECK (allocated_egress_bytes BETWEEN 0 AND 9007199254740991),
    allocated_cost_micro_units INTEGER NOT NULL CHECK (allocated_cost_micro_units BETWEEN 0 AND 9007199254740991),
    allocated_plans INTEGER NOT NULL CHECK (allocated_plans BETWEEN 0 AND 9007199254740991),
    allocated_approvals INTEGER NOT NULL CHECK (allocated_approvals BETWEEN 0 AND 9007199254740991),
    allocated_child_leases INTEGER NOT NULL CHECK (allocated_child_leases BETWEEN 0 AND 9007199254740991),
    created_generation INTEGER NOT NULL UNIQUE CHECK (created_generation BETWEEN 1 AND 9007199254740991),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    UNIQUE (parent_lease_issuer_id, parent_lease_id, child_lease_issuer_id, child_lease_id),
    FOREIGN KEY (parent_lease_issuer_id, parent_lease_id)
        REFERENCES task_leases (lease_issuer_id, lease_id),
    FOREIGN KEY (child_lease_issuer_id, child_lease_id)
        REFERENCES task_leases (lease_issuer_id, lease_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (allocation_attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE task_lease_counter_consumptions (
    consumption_id TEXT PRIMARY KEY CHECK (length(consumption_id) = 64),
    consumption_attempt_id TEXT NOT NULL UNIQUE CHECK (length(consumption_attempt_id) = 64),
    lease_issuer_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    lease_digest TEXT NOT NULL CHECK (length(lease_digest) = 64),
    counter_kind TEXT NOT NULL CHECK (counter_kind IN (
        'READ_BYTES', 'DISTINCT_FILES', 'ACTIONS', 'PLANS', 'APPROVALS'
    )),
    amount INTEGER NOT NULL CHECK (amount BETWEEN 1 AND 9007199254740991),
    context_digest TEXT NOT NULL CHECK (length(context_digest) = 64),
    created_generation INTEGER NOT NULL UNIQUE CHECK (created_generation BETWEEN 1 AND 9007199254740991),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    FOREIGN KEY (lease_issuer_id, lease_id)
        REFERENCES task_leases (lease_issuer_id, lease_id),
    FOREIGN KEY (consumption_attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE approval_plan_bindings (
    plan_id TEXT PRIMARY KEY CHECK (length(plan_id) = 64),
    plan_envelope_digest TEXT NOT NULL UNIQUE CHECK (length(plan_envelope_digest) = 64),
    plan_envelope_wire BLOB NOT NULL CHECK (length(plan_envelope_wire) BETWEEN 1 AND 1048576),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    plan_nonce TEXT NOT NULL CHECK (length(plan_nonce) = 32),
    task_id TEXT NOT NULL CHECK (length(task_id) BETWEEN 1 AND 128),
    workload_id TEXT NOT NULL CHECK (length(workload_id) BETWEEN 1 AND 128),
    grant_issuer_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    grant_digest TEXT NOT NULL CHECK (length(grant_digest) = 64),
    leaf_lease_issuer_id TEXT NOT NULL,
    leaf_lease_id TEXT NOT NULL,
    leaf_lease_digest TEXT NOT NULL CHECK (length(leaf_lease_digest) = 64),
    ancestor_vector_digest TEXT NOT NULL CHECK (length(ancestor_vector_digest) = 64),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('L0', 'L1', 'L2')),
    expires_at_utc_ms INTEGER NOT NULL CHECK (expires_at_utc_ms BETWEEN 1 AND 9007199254740991),
    deadline_monotonic_ms INTEGER NOT NULL CHECK (deadline_monotonic_ms BETWEEN 1 AND 9007199254740991),
    verification_generation INTEGER NOT NULL CHECK (verification_generation BETWEEN 1 AND 9007199254740991),
    FOREIGN KEY (grant_issuer_id, grant_id)
        REFERENCES human_request_grants (grant_issuer_id, grant_id),
    FOREIGN KEY (leaf_lease_issuer_id, leaf_lease_id)
        REFERENCES task_leases (lease_issuer_id, lease_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE approval_decisions (
    decision_issuer_id TEXT NOT NULL CHECK (length(decision_issuer_id) BETWEEN 1 AND 128),
    decision_id TEXT NOT NULL CHECK (length(decision_id) = 64),
    decision_digest TEXT NOT NULL UNIQUE CHECK (length(decision_digest) = 64),
    signed_wire BLOB NOT NULL CHECK (length(signed_wire) BETWEEN 1 AND 65536),
    signed_wire_sha256 TEXT NOT NULL UNIQUE CHECK (length(signed_wire_sha256) = 64),
    key_purpose TEXT NOT NULL CHECK (key_purpose = 'core-approval-decision-signing'),
    key_id TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL CHECK (length(key_fingerprint) = 64),
    plan_id TEXT NOT NULL UNIQUE,
    plan_envelope_digest TEXT NOT NULL UNIQUE CHECK (length(plan_envelope_digest) = 64),
    decision TEXT NOT NULL CHECK (decision IN ('APPROVED', 'DENIED')),
    authentication_profile TEXT NOT NULL CHECK (authentication_profile IN (
        'SESSION_AUTHENTICATED_V1', 'USER_VERIFICATION_V1', 'SYNTHETIC_CONFORMANCE_V1'
    )),
    authentication_evidence_digest TEXT NOT NULL CHECK (length(authentication_evidence_digest) = 64),
    issued_at_utc_ms INTEGER NOT NULL CHECK (issued_at_utc_ms BETWEEN 0 AND 9007199254740991),
    expires_at_utc_ms INTEGER NOT NULL CHECK (
        expires_at_utc_ms BETWEEN 1 AND 9007199254740991 AND issued_at_utc_ms < expires_at_utc_ms
    ),
    creation_attempt_id TEXT NOT NULL UNIQUE CHECK (length(creation_attempt_id) = 64),
    created_generation INTEGER NOT NULL UNIQUE CHECK (created_generation BETWEEN 1 AND 9007199254740991),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    PRIMARY KEY (decision_issuer_id, decision_id),
    FOREIGN KEY (key_purpose, key_id)
        REFERENCES authority_verification_keys (key_purpose, key_id),
    FOREIGN KEY (creation_attempt_id) REFERENCES authority_attempts (attempt_id),
    FOREIGN KEY (plan_id)
        REFERENCES approval_plan_bindings (plan_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE authority_revocations (
    revocation_id TEXT PRIMARY KEY CHECK (length(revocation_id) = 64),
    revocation_attempt_id TEXT NOT NULL UNIQUE CHECK (length(revocation_attempt_id) = 64),
    subject_kind TEXT NOT NULL CHECK (subject_kind IN (
        'SIGNER', 'GRANT', 'LEASE', 'DECISION', 'BOOT', 'INSTANCE', 'SCOPE_TEMPLATE'
    )),
    subject_id TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 128),
    subject_digest TEXT CHECK (subject_digest IS NULL OR length(subject_digest) = 64),
    effective_at_utc_ms INTEGER NOT NULL CHECK (effective_at_utc_ms BETWEEN 0 AND 9007199254740991),
    effective_at_monotonic_ms INTEGER CHECK (
        effective_at_monotonic_ms IS NULL OR
        effective_at_monotonic_ms BETWEEN 0 AND 9007199254740991
    ),
    boot_id TEXT CHECK (boot_id IS NULL OR length(boot_id) BETWEEN 1 AND 128),
    reason_code TEXT NOT NULL CHECK (reason_code IN (
        'ADMIN_REVOKED', 'KEY_COMPROMISED', 'SOURCE_REVOKED', 'ANCESTOR_REVOKED',
        'DECISION_REVOKED', 'BOOT_REPLACED', 'INSTANCE_REPLACED', 'SCOPE_REPLACED'
    )),
    created_generation INTEGER NOT NULL UNIQUE CHECK (created_generation BETWEEN 1 AND 9007199254740991),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    FOREIGN KEY (revocation_attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX authority_revocations_by_subject
    ON authority_revocations (subject_kind, subject_id, created_generation DESC);

CREATE TABLE authority_events (
    event_id TEXT PRIMARY KEY CHECK (length(event_id) = 64),
    event_kind TEXT NOT NULL CHECK (event_kind IN (
        'BOOTSTRAP_COMPLETED', 'KEY_STATUS_CHANGED', 'ROOT_LEASE_ISSUED',
        'CHILD_LEASE_ISSUED', 'COUNTER_CONSUMED', 'DECISION_RETAINED',
        'AUTHORITY_REVOKED', 'CONFLICT_RETAINED', 'BACKUP_PUBLISHED',
        'RESTORE_PUBLISHED'
    )),
    subject_kind TEXT NOT NULL CHECK (subject_kind IN (
        'ROOT', 'KEY', 'GRANT', 'LEASE', 'DECISION', 'REVOCATION', 'RESTORE'
    )),
    subject_reference_digest TEXT NOT NULL CHECK (length(subject_reference_digest) = 64),
    attempt_id TEXT NOT NULL CHECK (length(attempt_id) = 64),
    result_code TEXT NOT NULL CHECK (result_code IN (
        'COMMITTED_RETAINED', 'CONFLICT_RETAINED', 'RESTORE_PENDING'
    )),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 64),
    event_generation INTEGER NOT NULL UNIQUE CHECK (event_generation BETWEEN 1 AND 9007199254740991),
    observed_at_utc_ms INTEGER NOT NULL CHECK (observed_at_utc_ms BETWEEN 0 AND 9007199254740991),
    observed_at_monotonic_ms INTEGER CHECK (
        observed_at_monotonic_ms IS NULL OR
        observed_at_monotonic_ms BETWEEN 0 AND 9007199254740991
    ),
    boot_id TEXT CHECK (boot_id IS NULL OR length(boot_id) BETWEEN 1 AND 128),
    previous_event_digest TEXT CHECK (
        previous_event_digest IS NULL OR length(previous_event_digest) = 64
    ),
    event_digest TEXT NOT NULL UNIQUE CHECK (length(event_digest) = 64),
    FOREIGN KEY (attempt_id) REFERENCES authority_attempts (attempt_id)
        DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE authority_conflict_tombstones (
    conflict_id TEXT PRIMARY KEY CHECK (length(conflict_id) = 64),
    namespace_kind TEXT NOT NULL CHECK (namespace_kind IN (
        'GRANT', 'LEASE', 'ALLOCATION', 'CONSUMPTION', 'DECISION', 'BOOTSTRAP'
    )),
    namespace_digest TEXT NOT NULL CHECK (length(namespace_digest) = 64),
    expected_binding_digest TEXT NOT NULL CHECK (length(expected_binding_digest) = 64),
    observed_binding_digest TEXT NOT NULL CHECK (length(observed_binding_digest) = 64),
    attempt_id TEXT NOT NULL UNIQUE CHECK (length(attempt_id) = 64),
    reason_code TEXT NOT NULL CHECK (reason_code = 'CONFLICTING_IDENTITY_REUSE'),
    created_generation INTEGER NOT NULL UNIQUE CHECK (created_generation BETWEEN 1 AND 9007199254740991),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    FOREIGN KEY (attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE authority_restore_receipts (
    restore_receipt_id TEXT PRIMARY KEY CHECK (length(restore_receipt_id) = 64),
    restore_attempt_id TEXT NOT NULL UNIQUE CHECK (length(restore_attempt_id) = 64),
    package_manifest_digest TEXT NOT NULL UNIQUE CHECK (length(package_manifest_digest) = 64),
    source_root_id TEXT NOT NULL CHECK (length(source_root_id) BETWEEN 1 AND 128),
    target_root_id TEXT NOT NULL UNIQUE CHECK (length(target_root_id) BETWEEN 1 AND 128),
    source_checkpoint_digest TEXT NOT NULL CHECK (length(source_checkpoint_digest) = 64),
    rotated_boot_id TEXT NOT NULL CHECK (length(rotated_boot_id) BETWEEN 1 AND 128),
    rotated_instance_epoch INTEGER NOT NULL CHECK (rotated_instance_epoch BETWEEN 1 AND 9007199254740991),
    rotated_fencing_epoch INTEGER NOT NULL CHECK (rotated_fencing_epoch BETWEEN 1 AND 9007199254740991),
    restore_epoch INTEGER NOT NULL UNIQUE CHECK (restore_epoch BETWEEN 1 AND 9007199254740991),
    lifecycle TEXT NOT NULL CHECK (lifecycle = 'RESTORE_PENDING'),
    reactivated_lease_count INTEGER NOT NULL CHECK (reactivated_lease_count = 0),
    reactivated_approval_count INTEGER NOT NULL CHECK (reactivated_approval_count = 0),
    published_generation INTEGER NOT NULL UNIQUE CHECK (published_generation BETWEEN 1 AND 9007199254740991),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 64),
    FOREIGN KEY (restore_attempt_id) REFERENCES authority_attempts (attempt_id)
) STRICT, WITHOUT ROWID;

-- Mutable metadata may only move generations forward and may never restore old
-- root/boot/instance/fencing authority. RESTORE_PENDING has no v1 return to ACTIVE.
CREATE TRIGGER authority_metadata_monotonic_update
BEFORE UPDATE ON authority_store_metadata
BEGIN
    SELECT CASE WHEN
        NEW.application_id <> OLD.application_id OR
        NEW.schema_version <> OLD.schema_version OR
        NEW.schema_digest <> OLD.schema_digest OR
        NEW.root_id <> OLD.root_id OR
        NEW.durability_profile <> OLD.durability_profile OR
        NEW.created_at_utc_ms <> OLD.created_at_utc_ms OR
        NEW.bootstrap_receipt_id <> OLD.bootstrap_receipt_id OR
        NEW.store_generation <= OLD.store_generation OR
        NEW.trust_generation < OLD.trust_generation OR
        NEW.grant_generation < OLD.grant_generation OR
        NEW.lease_generation < OLD.lease_generation OR
        NEW.allocation_generation < OLD.allocation_generation OR
        NEW.counter_generation < OLD.counter_generation OR
        NEW.decision_generation < OLD.decision_generation OR
        NEW.revocation_generation < OLD.revocation_generation OR
        NEW.event_generation < OLD.event_generation OR
        NEW.migration_generation < OLD.migration_generation OR
        NEW.backup_generation < OLD.backup_generation OR
        NEW.restore_generation < OLD.restore_generation OR
        (OLD.lifecycle = 'RESTORE_PENDING' AND NEW.lifecycle <> 'RESTORE_PENDING') OR
        (NEW.boot_id = OLD.boot_id AND NEW.instance_epoch <> OLD.instance_epoch) OR
        NEW.instance_epoch < OLD.instance_epoch OR
        NEW.fencing_epoch < OLD.fencing_epoch OR
        NEW.restore_epoch < OLD.restore_epoch
    THEN RAISE(ABORT, 'AUTHORITY_METADATA_NON_MONOTONIC') END;
END;

CREATE TRIGGER authority_metadata_no_delete
BEFORE DELETE ON authority_store_metadata
BEGIN
    SELECT RAISE(ABORT, 'AUTHORITY_METADATA_DELETE_FORBIDDEN');
END;

CREATE TRIGGER task_lease_usage_monotonic_update
BEFORE UPDATE ON task_lease_usage
BEGIN
    SELECT CASE WHEN
        NEW.lease_issuer_id <> OLD.lease_issuer_id OR
        NEW.lease_id <> OLD.lease_id OR
        NEW.allocated_read_bytes < OLD.allocated_read_bytes OR
        NEW.allocated_distinct_files < OLD.allocated_distinct_files OR
        NEW.allocated_actions < OLD.allocated_actions OR
        NEW.allocated_egress_bytes < OLD.allocated_egress_bytes OR
        NEW.allocated_cost_micro_units < OLD.allocated_cost_micro_units OR
        NEW.allocated_plans < OLD.allocated_plans OR
        NEW.allocated_approvals < OLD.allocated_approvals OR
        NEW.allocated_child_leases < OLD.allocated_child_leases OR
        NEW.consumed_read_bytes < OLD.consumed_read_bytes OR
        NEW.consumed_distinct_files < OLD.consumed_distinct_files OR
        NEW.consumed_actions < OLD.consumed_actions OR
        NEW.consumed_plans < OLD.consumed_plans OR
        NEW.consumed_approvals < OLD.consumed_approvals OR
        NEW.allocation_generation < OLD.allocation_generation OR
        NEW.counter_generation < OLD.counter_generation OR
        (
            (NEW.allocated_read_bytes <> OLD.allocated_read_bytes OR
             NEW.allocated_distinct_files <> OLD.allocated_distinct_files OR
             NEW.allocated_actions <> OLD.allocated_actions OR
             NEW.allocated_egress_bytes <> OLD.allocated_egress_bytes OR
             NEW.allocated_cost_micro_units <> OLD.allocated_cost_micro_units OR
             NEW.allocated_plans <> OLD.allocated_plans OR
             NEW.allocated_approvals <> OLD.allocated_approvals OR
             NEW.allocated_child_leases <> OLD.allocated_child_leases) AND
            (NEW.allocation_generation <= OLD.allocation_generation OR
             NEW.allocation_generation <> (
                 SELECT allocation_generation FROM authority_store_metadata
                 WHERE singleton_id = 1
             ))
        ) OR
        (
            NEW.allocated_read_bytes = OLD.allocated_read_bytes AND
            NEW.allocated_distinct_files = OLD.allocated_distinct_files AND
            NEW.allocated_actions = OLD.allocated_actions AND
            NEW.allocated_egress_bytes = OLD.allocated_egress_bytes AND
            NEW.allocated_cost_micro_units = OLD.allocated_cost_micro_units AND
            NEW.allocated_plans = OLD.allocated_plans AND
            NEW.allocated_approvals = OLD.allocated_approvals AND
            NEW.allocated_child_leases = OLD.allocated_child_leases AND
            NEW.allocation_generation <> OLD.allocation_generation
        ) OR
        (
            (NEW.consumed_read_bytes <> OLD.consumed_read_bytes OR
             NEW.consumed_distinct_files <> OLD.consumed_distinct_files OR
             NEW.consumed_actions <> OLD.consumed_actions OR
             NEW.consumed_plans <> OLD.consumed_plans OR
             NEW.consumed_approvals <> OLD.consumed_approvals) AND
            (NEW.counter_generation <= OLD.counter_generation OR
             NEW.counter_generation <> (
                 SELECT counter_generation FROM authority_store_metadata
                 WHERE singleton_id = 1
             ))
        ) OR
        (
            NEW.consumed_read_bytes = OLD.consumed_read_bytes AND
            NEW.consumed_distinct_files = OLD.consumed_distinct_files AND
            NEW.consumed_actions = OLD.consumed_actions AND
            NEW.consumed_plans = OLD.consumed_plans AND
            NEW.consumed_approvals = OLD.consumed_approvals AND
            NEW.counter_generation <> OLD.counter_generation
        )
    THEN RAISE(ABORT, 'LEASE_USAGE_NON_MONOTONIC') END;
END;

CREATE TRIGGER task_lease_usage_no_delete
BEFORE DELETE ON task_lease_usage
BEGIN
    SELECT RAISE(ABORT, 'LEASE_USAGE_DELETE_FORBIDDEN');
END;

-- Every table below is immutable after insert. Exact retry is a read; a conflicting
-- retry inserts a conflict tombstone in the same writer transaction.
CREATE TRIGGER attempts_no_update BEFORE UPDATE ON authority_attempts
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_ATTEMPT_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER attempts_no_delete BEFORE DELETE ON authority_attempts
BEGIN SELECT RAISE(ABORT, 'AUTHORITY_ATTEMPT_DELETE_FORBIDDEN'); END;
CREATE TRIGGER bootstrap_receipts_no_update BEFORE UPDATE ON authority_bootstrap_receipts
BEGIN SELECT RAISE(ABORT, 'BOOTSTRAP_RECEIPT_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER bootstrap_receipts_no_delete BEFORE DELETE ON authority_bootstrap_receipts
BEGIN SELECT RAISE(ABORT, 'BOOTSTRAP_RECEIPT_DELETE_FORBIDDEN'); END;
CREATE TRIGGER verification_keys_no_update BEFORE UPDATE ON authority_verification_keys
BEGIN SELECT RAISE(ABORT, 'VERIFICATION_KEY_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER verification_keys_no_delete BEFORE DELETE ON authority_verification_keys
BEGIN SELECT RAISE(ABORT, 'VERIFICATION_KEY_DELETE_FORBIDDEN'); END;
CREATE TRIGGER key_status_no_update BEFORE UPDATE ON authority_key_status_events
BEGIN SELECT RAISE(ABORT, 'KEY_STATUS_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER key_status_no_delete BEFORE DELETE ON authority_key_status_events
BEGIN SELECT RAISE(ABORT, 'KEY_STATUS_DELETE_FORBIDDEN'); END;
CREATE TRIGGER grants_no_update BEFORE UPDATE ON human_request_grants
BEGIN SELECT RAISE(ABORT, 'GRANT_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER grants_no_delete BEFORE DELETE ON human_request_grants
BEGIN SELECT RAISE(ABORT, 'GRANT_DELETE_FORBIDDEN'); END;
CREATE TRIGGER claims_no_update BEFORE UPDATE ON human_grant_claims
BEGIN SELECT RAISE(ABORT, 'GRANT_CLAIM_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER claims_no_delete BEFORE DELETE ON human_grant_claims
BEGIN SELECT RAISE(ABORT, 'GRANT_CLAIM_DELETE_FORBIDDEN'); END;
CREATE TRIGGER leases_no_update BEFORE UPDATE ON task_leases
BEGIN SELECT RAISE(ABORT, 'LEASE_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER leases_no_delete BEFORE DELETE ON task_leases
BEGIN SELECT RAISE(ABORT, 'LEASE_DELETE_FORBIDDEN'); END;
CREATE TRIGGER allocations_no_update BEFORE UPDATE ON task_lease_allocations
BEGIN SELECT RAISE(ABORT, 'ALLOCATION_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER allocations_no_delete BEFORE DELETE ON task_lease_allocations
BEGIN SELECT RAISE(ABORT, 'ALLOCATION_DELETE_FORBIDDEN'); END;
CREATE TRIGGER consumptions_no_update BEFORE UPDATE ON task_lease_counter_consumptions
BEGIN SELECT RAISE(ABORT, 'CONSUMPTION_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER consumptions_no_delete BEFORE DELETE ON task_lease_counter_consumptions
BEGIN SELECT RAISE(ABORT, 'CONSUMPTION_DELETE_FORBIDDEN'); END;
CREATE TRIGGER plans_no_update BEFORE UPDATE ON approval_plan_bindings
BEGIN SELECT RAISE(ABORT, 'PLAN_BINDING_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER plans_no_delete BEFORE DELETE ON approval_plan_bindings
BEGIN SELECT RAISE(ABORT, 'PLAN_BINDING_DELETE_FORBIDDEN'); END;
CREATE TRIGGER decisions_no_update BEFORE UPDATE ON approval_decisions
BEGIN SELECT RAISE(ABORT, 'DECISION_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER decisions_no_delete BEFORE DELETE ON approval_decisions
BEGIN SELECT RAISE(ABORT, 'DECISION_DELETE_FORBIDDEN'); END;
CREATE TRIGGER revocations_no_update BEFORE UPDATE ON authority_revocations
BEGIN SELECT RAISE(ABORT, 'REVOCATION_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER revocations_no_delete BEFORE DELETE ON authority_revocations
BEGIN SELECT RAISE(ABORT, 'REVOCATION_DELETE_FORBIDDEN'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON authority_events
BEGIN SELECT RAISE(ABORT, 'EVENT_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON authority_events
BEGIN SELECT RAISE(ABORT, 'EVENT_DELETE_FORBIDDEN'); END;
CREATE TRIGGER conflicts_no_update BEFORE UPDATE ON authority_conflict_tombstones
BEGIN SELECT RAISE(ABORT, 'CONFLICT_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER conflicts_no_delete BEFORE DELETE ON authority_conflict_tombstones
BEGIN SELECT RAISE(ABORT, 'CONFLICT_DELETE_FORBIDDEN'); END;
CREATE TRIGGER restores_no_update BEFORE UPDATE ON authority_restore_receipts
BEGIN SELECT RAISE(ABORT, 'RESTORE_RECEIPT_UPDATE_FORBIDDEN'); END;
CREATE TRIGGER restores_no_delete BEFORE DELETE ON authority_restore_receipts
BEGIN SELECT RAISE(ABORT, 'RESTORE_RECEIPT_DELETE_FORBIDDEN'); END;

-- Typed open/readback additionally requires:
-- * exact RFC 8785/signature verification for every retained wire;
-- * indexed fields equal their signed leaves;
-- * one claim/root pair per grant and one allocation/child pair;
-- * acyclic, depth-bounded, task/workload/source-coherent ancestry;
-- * usage summaries equal append-only allocations/consumptions with checked sums;
-- * exact one terminal decision per plan target;
-- * each operation row/event references one immutable attempt whose operation kind,
--   namespace digest, stable input-graph digest, deadline, outcome binding and
--   generation exactly match the complete atomic graph; exact retry creates no new
--   attempt;
-- * current trust/revocation/time/epoch resolution before any projection; and
-- * zero admission while lifecycle is RESTORE_PENDING.

-- Schema version publication is the final schema mutation. A partial staging root
-- therefore never advertises the complete v1 schema to a strict ordinary opener.
PRAGMA user_version = 1;
