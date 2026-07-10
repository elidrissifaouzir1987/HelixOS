-- HelixOS durable replay store schema v1.
-- The implementation executes these statements inside the initialization writer
-- transaction after establishing WAL + FULL on an empty, dedicated local database.

PRAGMA application_id = 1212962898;
PRAGMA user_version = 1;

CREATE TABLE replay_store_meta (
    singleton INTEGER NOT NULL,
    format_version INTEGER NOT NULL,
    claimant_generation INTEGER NOT NULL,
    CONSTRAINT replay_store_meta_pk PRIMARY KEY (singleton),
    CONSTRAINT replay_store_meta_singleton_ck CHECK (singleton = 1),
    CONSTRAINT replay_store_meta_format_ck CHECK (format_version = 1),
    CONSTRAINT replay_store_meta_generation_ck CHECK (
        claimant_generation BETWEEN 0 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

INSERT INTO replay_store_meta (
    singleton,
    format_version,
    claimant_generation
) VALUES (1, 1, 0);

CREATE TABLE replay_claims (
    instance_epoch INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    operation_id TEXT COLLATE BINARY NOT NULL,
    binding_digest BLOB NOT NULL,
    claim_id BLOB NOT NULL,
    claimant_generation INTEGER NOT NULL,
    CONSTRAINT replay_claims_pk PRIMARY KEY (instance_epoch, nonce),
    CONSTRAINT replay_claims_instance_epoch_ck CHECK (
        instance_epoch BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT replay_claims_nonce_ck CHECK (
        typeof(nonce) = 'blob' AND length(nonce) = 16
    ),
    CONSTRAINT replay_claims_operation_id_ck CHECK (
        typeof(operation_id) = 'text'
        AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128
        AND operation_id NOT GLOB '*[^-A-Za-z0-9._:]*'
    ),
    CONSTRAINT replay_claims_binding_digest_ck CHECK (
        typeof(binding_digest) = 'blob' AND length(binding_digest) = 32
    ),
    CONSTRAINT replay_claims_claim_id_ck CHECK (
        typeof(claim_id) = 'blob' AND length(claim_id) = 32
    ),
    CONSTRAINT replay_claims_generation_ck CHECK (
        claimant_generation BETWEEN 1 AND 9007199254740991
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX replay_claims_operation_id_uq
    ON replay_claims (operation_id);

CREATE UNIQUE INDEX replay_claims_claim_id_uq
    ON replay_claims (claim_id);

CREATE UNIQUE INDEX replay_claims_generation_uq
    ON replay_claims (claimant_generation);
