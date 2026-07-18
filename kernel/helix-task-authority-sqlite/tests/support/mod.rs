#![allow(dead_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use helix_task_authority::{
    AuthorityClockObservationV1, AuthorityClockProviderV1, AuthorityControlErrorV1,
    AuthorityCurrentnessV1, CurrentHumanRequestContextV1, RootIssuanceObservationsV1,
    RootLeaseRequestV1,
};
use helix_task_authority_contracts::{
    decode_and_verify_human_request_grant_v1, sign_human_request_grant_v1, ContractError,
    CurrencyCodeV1, DelegationDepthV1, DelegationModeV1, Generation, HumanRequestGrantInputV1,
    HumanRequestGrantKeyResolver, HumanRequestGrantProtectedV1, HumanRequestGrantSigner,
    HumanRequestGrantVerificationKeyV1, Identifier, MinimumAuthenticationProfileV1, ResourceRootV1,
    RiskLevelV1, RootTaskLeaseBoundsV1, SafeU64, Sha256Digest, TaskLeaseBudgetV1,
    TaskLeaseCatalogueBoundV1, TaskLeaseCounterLimitsV1, TaskLeaseSigner, TaskLeaseTrustBoundV1,
};
use helix_task_authority_sqlite::{
    AuthorityRootIdentityEvidenceV1, AuthorityStoreConfigV1, SqliteRootLeaseStoreV1,
    TASK_AUTHORITY_STORE_APPLICATION_ID_V1, TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
    TASK_AUTHORITY_STORE_SCHEMA_V1_SQL,
};
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const DURABILITY_PROFILE: &str = "WAL_FULL_CONTROLLED_CHECKPOINT_V1";
static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

pub fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn digest_hex(byte: u8) -> String {
    digest(byte).to_hex()
}

pub fn identifier(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

pub fn safe(value: u64) -> SafeU64 {
    SafeU64::new(value).unwrap()
}

pub fn generation(value: u64) -> Generation {
    Generation::new(value).unwrap()
}

#[derive(Clone, Copy)]
pub struct FixedClock;

impl AuthorityClockProviderV1 for FixedClock {
    fn capture_v1(
        &self,
        deadline: SafeU64,
    ) -> Result<AuthorityClockObservationV1, AuthorityControlErrorV1> {
        if deadline.get() <= 100 {
            return Err(AuthorityControlErrorV1::DeadlineReached);
        }
        Ok(AuthorityClockObservationV1::from_trusted_provider_parts_v1(
            identifier("boot-a"),
            generation(8),
            generation(1),
            safe(1_100),
            safe(100),
        ))
    }
}

pub struct GrantSignerV1(pub SigningKey);

impl GrantSignerV1 {
    pub fn fixed() -> Self {
        Self(SigningKey::from_bytes(&[17; 32]))
    }
}

impl HumanRequestGrantSigner for GrantSignerV1 {
    fn key_id(&self) -> &str {
        "request-key-v1"
    }

    fn sign_human_request_grant(
        &self,
        message: &[u8],
    ) -> helix_task_authority_contracts::Result<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
}

impl HumanRequestGrantKeyResolver for GrantSignerV1 {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
        if key_id != self.key_id() {
            return Err(ContractError::UnknownKey);
        }
        Ok(HumanRequestGrantVerificationKeyV1::current(
            self.0.verifying_key().to_bytes(),
        ))
    }
}

pub struct LeaseSignerV1(pub SigningKey);

impl LeaseSignerV1 {
    pub fn fixed() -> Self {
        Self(SigningKey::from_bytes(&[23; 32]))
    }
}

impl TaskLeaseSigner for LeaseSignerV1 {
    fn key_id(&self) -> &str {
        "lease-key-v1"
    }

    fn sign_task_lease(&self, message: &[u8]) -> helix_task_authority_contracts::Result<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
}

pub struct TestRoot {
    path: PathBuf,
    root_id: String,
}

impl TestRoot {
    pub fn provision() -> Self {
        let nonce = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helix-root-contract-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        let root_id = "61".repeat(32);
        let grant_signer = GrantSignerV1::fixed();
        let lease_signer = LeaseSignerV1::fixed();
        create_database_v1(
            &path,
            &root_id,
            grant_signer.0.verifying_key().to_bytes(),
            lease_signer.0.verifying_key().to_bytes(),
        );
        fs::write(
            path.join(".helix-task-authority-root-v1"),
            format!("HELIXOS_TASK_AUTHORITY_ROOT_V1\nROOT_IDENTITY={root_id}\nSTATE=EXISTING\n"),
        )
        .unwrap();
        Self { path, root_id }
    }

    pub fn store(&self) -> SqliteRootLeaseStoreV1 {
        SqliteRootLeaseStoreV1::new_v1(
            self.config(),
            Arc::new(FixedClock),
            identifier(&self.root_id),
        )
    }

    pub fn config(&self) -> AuthorityStoreConfigV1 {
        AuthorityStoreConfigV1::try_new_existing_attested(
            self.path.clone(),
            AuthorityRootIdentityEvidenceV1::from_attested_bytes([0x61; 32]),
            10_000,
        )
        .unwrap()
    }

    pub fn connection(&self) -> Connection {
        Connection::open(self.path.join("task-authority.sqlite3")).unwrap()
    }

    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    pub fn revoke_request_signer(&self) {
        let mut connection = self.connection();
        connection
            .pragma_update(None, "foreign_keys", true)
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let attempt = digest_hex(71);
        let event = digest_hex(72);
        let fingerprint: String = transaction
            .query_row(
                "SELECT public_key_fingerprint FROM authority_verification_keys
                 WHERE key_id = 'request-key-v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO authority_attempts VALUES (?1, 'KEY_STATUS_CHANGE', ?2, ?3, 1000,
                 'COMMITTED_RETAINED', ?4, 4, ?5)",
                params![
                    attempt,
                    digest_hex(73),
                    digest_hex(74),
                    digest_hex(75),
                    event
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO authority_key_status_events VALUES
                 (?1, 'request-surface-grant-signing', 'request-key-v1', 'REVOKED', 1050,
                  4, ?2, 'ADMIN_REVOKED', ?3)",
                params![digest_hex(76), attempt, event],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO authority_events VALUES
                 (?1, 'KEY_STATUS_CHANGED', 'KEY', ?2, ?3, 'COMMITTED_RETAINED',
                  'ADMIN_REVOKED', 4, 1050, 50, 'boot-a', ?4, ?5)",
                params![event, fingerprint, attempt, digest_hex(39), digest_hex(77)],
            )
            .unwrap();
        transaction
            .execute(
                "UPDATE authority_store_metadata
                 SET store_generation = 4, trust_generation = 4, event_generation = 4
                 WHERE singleton_id = 1 AND store_generation = 3",
                [],
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn store_for_existing_path(path: PathBuf, root_id: &str) -> SqliteRootLeaseStoreV1 {
    let config = AuthorityStoreConfigV1::try_new_existing_attested(
        path,
        AuthorityRootIdentityEvidenceV1::from_attested_bytes([0x61; 32]),
        10_000,
    )
    .unwrap();
    SqliteRootLeaseStoreV1::new_v1(config, Arc::new(FixedClock), identifier(root_id))
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn bounds(read_bytes: u64) -> RootTaskLeaseBoundsV1 {
    RootTaskLeaseBoundsV1::try_new_v1(
        vec![
            ResourceRootV1::try_new("workspace", vec!["project".to_owned(), "src".to_owned()])
                .unwrap(),
        ],
        TaskLeaseBudgetV1::from_validated_parts_v1(
            safe(read_bytes),
            safe(20),
            safe(10),
            safe(1_000),
            CurrencyCodeV1::new("USD").unwrap(),
            safe(500),
            identifier("prices-v1"),
        ),
        TaskLeaseCounterLimitsV1::from_validated_parts_v1(
            safe(4),
            safe(2),
            safe(2),
            DelegationDepthV1::new(2).unwrap(),
        ),
        TaskLeaseTrustBoundV1::from_validated_parts_v1(
            RiskLevelV1::L1,
            MinimumAuthenticationProfileV1::UserVerificationV1,
            identifier("policy-a"),
            digest(4),
            generation(4),
        ),
        TaskLeaseCatalogueBoundV1::try_new_v1(
            identifier("catalogue-a"),
            digest(5),
            generation(5),
            vec![identifier("entry-a"), identifier("entry-b")],
        )
        .unwrap(),
        DelegationModeV1::Delegable,
    )
    .unwrap()
}

pub fn request(read_bytes: u64, trust_generation: u64) -> RootLeaseRequestV1 {
    let signer = GrantSignerV1::fixed();
    let protected = HumanRequestGrantProtectedV1::try_new(
        HumanRequestGrantInputV1 {
            grant_id: digest(51),
            issuer_id: identifier("request-surface"),
            audience: identifier("helix-core"),
            principal_id: identifier("principal-a"),
            message_digest: digest(52),
            channel_id: identifier("channel-a"),
            session_id: identifier("session-a"),
            scope_template_id: identifier("scope-a"),
            scope_template_digest: digest(3),
            scope_template_generation: generation(3),
            issued_at_utc_ms: safe(1_000),
            expires_at_utc_ms: safe(2_000),
        },
        identifier(signer.key_id()),
    )
    .unwrap();
    let wire = sign_human_request_grant_v1(protected, &signer)
        .unwrap()
        .to_canonical_json()
        .unwrap();
    let grant = decode_and_verify_human_request_grant_v1(&wire, &signer).unwrap();
    RootLeaseRequestV1 {
        grant,
        human_context: CurrentHumanRequestContextV1::from_authenticated_parts_v1(
            identifier("request-surface"),
            identifier("helix-core"),
            identifier("principal-a"),
            digest(52),
            identifier("channel-a"),
            identifier("session-a"),
            identifier("scope-a"),
            digest(3),
            generation(3),
        ),
        requested_bounds: bounds(read_bytes),
        current_ceiling: bounds(100),
        observations: RootIssuanceObservationsV1::from_current_parts_v1(
            digest(3),
            generation(3),
            digest(4),
            generation(4),
            digest(5),
            generation(5),
            digest(6),
            generation(6),
            digest(7),
            generation(trust_generation),
        ),
        source_currentness: AuthorityCurrentnessV1::Current,
        lease_issuer_id: identifier("core-lease-issuer"),
        task_id: identifier("task-a"),
        workload_id: identifier("workload-a"),
        audience: identifier("helix-core"),
        clock: FixedClock.capture_v1(safe(60_000)).unwrap(),
        not_before_utc_ms: safe(1_100),
        expires_at_utc_ms: safe(1_900),
        deadline_monotonic_ms: safe(500),
        caller_deadline_monotonic_ms: safe(60_000),
    }
}

fn create_database_v1(root: &Path, root_id: &str, grant_key: [u8; 32], lease_key: [u8; 32]) {
    let path = root.join("task-authority.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    connection
        .pragma_update(None, "synchronous", "FULL")
        .unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .pragma_update(None, "recursive_triggers", true)
        .unwrap();
    connection
        .execute_batch(TASK_AUTHORITY_STORE_SCHEMA_V1_SQL)
        .unwrap();
    let transaction = connection.unchecked_transaction().unwrap();
    stage_bootstrap_and_keys_v1(&transaction, root_id, grant_key, lease_key);
    transaction.commit().unwrap();
    connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
}

fn stage_bootstrap_and_keys_v1(
    connection: &Connection,
    root_id: &str,
    grant_key: [u8; 32],
    lease_key: [u8; 32],
) {
    let bootstrap_attempt = digest_hex(1);
    let bootstrap_event = digest_hex(2);
    let receipt = digest_hex(3);
    connection
        .execute(
            "INSERT INTO authority_attempts VALUES (?1, 'BOOTSTRAP', ?2, ?3, 1000,
             'COMMITTED_RETAINED', ?4, 1, ?5)",
            params![
                bootstrap_attempt,
                digest_hex(4),
                digest_hex(5),
                digest_hex(6),
                bootstrap_event
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO authority_events VALUES (?1, 'BOOTSTRAP_COMPLETED', 'ROOT', ?2, ?3,
             'COMMITTED_RETAINED', 'BOOTSTRAP_COMPLETED', 1, 1, 1, 'boot-a', NULL, ?4)",
            params![
                bootstrap_event,
                digest_hex(7),
                bootstrap_attempt,
                digest_hex(8)
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO authority_bootstrap_receipts VALUES (
             ?1, ?2, ?3, ?4, 1212962883, 2, 'coordinator-root', ?5, ?6, ?7,
             ?8, ?9, 0, 0, 0, 1, 1, 'helixos-provision', ?10)",
            params![
                receipt,
                bootstrap_attempt,
                "aa".repeat(20),
                "bb".repeat(20),
                digest_hex(9),
                digest_hex(10),
                digest_hex(11),
                root_id,
                TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                digest_hex(12)
            ],
        )
        .unwrap();

    for (purpose, key_id, public_key, generation, seed) in [
        (
            "request-surface-grant-signing",
            "request-key-v1",
            grant_key,
            2_u64,
            21_u8,
        ),
        (
            "core-task-lease-signing",
            "lease-key-v1",
            lease_key,
            3_u64,
            31_u8,
        ),
    ] {
        let attempt = digest_hex(seed);
        let event = digest_hex(seed + 1);
        let fingerprint = Sha256Digest::digest(&public_key);
        connection
            .execute(
                "INSERT INTO authority_attempts VALUES (?1, 'KEY_STATUS_CHANGE', ?2, ?3, 1000,
                 'COMMITTED_RETAINED', ?4, ?5, ?6)",
                params![
                    attempt,
                    digest_hex(seed + 2),
                    digest_hex(seed + 3),
                    digest_hex(seed + 4),
                    generation as i64,
                    event
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO authority_verification_keys VALUES
                 (?1, ?2, 'authority-test-issuer', 'ed25519', ?3, ?4, ?5, ?6)",
                params![
                    purpose,
                    key_id,
                    public_key.as_slice(),
                    fingerprint.to_hex(),
                    digest_hex(seed + 5),
                    generation as i64
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO authority_key_status_events VALUES
                 (?1, ?2, ?3, 'TRUSTED', 0, ?4, ?5, 'KEY_INTRODUCED', ?6)",
                params![
                    digest_hex(seed + 6),
                    purpose,
                    key_id,
                    generation as i64,
                    attempt,
                    event
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO authority_events VALUES (?1, 'KEY_STATUS_CHANGED', 'KEY', ?2, ?3,
                 'COMMITTED_RETAINED', 'KEY_INTRODUCED', ?4, 1, 1, 'boot-a', ?5, ?6)",
                params![
                    event,
                    fingerprint.to_hex(),
                    attempt,
                    generation as i64,
                    if generation == 2 {
                        digest_hex(8)
                    } else {
                        digest_hex(29)
                    },
                    digest_hex(seed + 8)
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO authority_store_metadata VALUES (
             1, ?1, 1, ?2, ?3, 'ACTIVE', ?4, 'boot-a', 1, 1, 0, 1024, 32,
             3, 3, 1, 1, 1, 1, 1, 1, 3, 1, 0, 0, 1, ?5, NULL)",
            params![
                TASK_AUTHORITY_STORE_APPLICATION_ID_V1,
                TASK_AUTHORITY_STORE_SCHEMA_V1_SHA256_HEX,
                root_id,
                DURABILITY_PROFILE,
                receipt
            ],
        )
        .unwrap();
}
