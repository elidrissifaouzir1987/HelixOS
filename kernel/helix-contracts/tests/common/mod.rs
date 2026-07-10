#![allow(dead_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use helix_contracts::{
    AtomicityV1, BudgetInputV1, ContractError, Ed25519KeyResolver, Ed25519Signer,
    FilePreconditionInputV1, Nonce128, PlanInputV1, RecoveryClassV1, RecoveryInputV1,
    RequestSourceKindV1, ResourceRefV1, Result, RiskLevelV1, Sha256Digest,
};

pub const ISSUED_AT_MS: u64 = 1_750_000_000_000;

#[derive(Debug)]
pub struct TestSigner {
    key_id: String,
    key: SigningKey,
}

impl TestSigner {
    pub fn new(key_id: &str, seed: [u8; 32]) -> Self {
        Self {
            key_id: key_id.to_owned(),
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl Ed25519Signer for TestSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_ed25519(&self, message: &[u8]) -> Result<[u8; 64]> {
        Ok(self.key.sign(message).to_bytes())
    }
}

#[derive(Debug)]
pub struct TestResolver {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub revoked: bool,
}

impl TestResolver {
    pub fn for_signer(signer: &TestSigner) -> Self {
        Self {
            key_id: signer.key_id.clone(),
            public_key: signer.verifying_key_bytes(),
            revoked: false,
        }
    }
}

impl Ed25519KeyResolver for TestResolver {
    fn resolve_ed25519(&self, key_id: &str) -> Result<[u8; 32]> {
        if self.revoked || self.key_id != key_id {
            return Err(ContractError::UnknownKey);
        }
        Ok(self.public_key)
    }
}

pub fn fixed_signer() -> TestSigner {
    TestSigner::new("core-signing-key:fixture-1", [7_u8; 32])
}

pub fn sample_input() -> PlanInputV1 {
    PlanInputV1 {
        operation_id: "operation:00000000-0000-4000-8000-000000000001".to_owned(),
        task_id: "task:fixture-1".to_owned(),
        workload_id: "workload:agent-vm-1".to_owned(),
        boot_id: "boot:fixture-1".to_owned(),
        task_lease_digest: Sha256Digest::digest(b"fixture task lease"),
        request_source_kind: RequestSourceKindV1::HumanRequestGrant,
        request_source_digest: Sha256Digest::digest(b"fixture human request grant"),
        catalog_version: "catalog:1".to_owned(),
        policy_version: "policy:1".to_owned(),
        risk_level: RiskLevelV1::L1,
        target: ResourceRefV1::new("vault-main", ["Projects", "HelixOS", "Decision.md"])
            .expect("valid resource"),
        precondition: FilePreconditionInputV1 {
            volume_id: "volume:fixture-apfs".to_owned(),
            file_id: "file:00000042".to_owned(),
            content_sha256: Sha256Digest::digest(b"before\n"),
            byte_length: 7,
        },
        replacement_bytes: b"after\n".to_vec(),
        replacement_media_type: "text/markdown;charset=utf-8".to_owned(),
        recovery: RecoveryInputV1 {
            class: RecoveryClassV1::Compensation,
            atomicity: AtomicityV1::AtomicReplace,
            reserved_bytes: 4096,
        },
        capability_report_digest: Sha256Digest::digest(b"fixture capability report"),
        capability_observed_at_unix_ms: ISSUED_AT_MS - 1_000,
        required_capabilities: vec![
            "filesystem.verify-by-handle".to_owned(),
            "filesystem.atomic-replace".to_owned(),
        ],
        budget: BudgetInputV1 {
            reservation_id: "budget:fixture-1".to_owned(),
            currency_code: "EUR".to_owned(),
            price_table_id: "price-table:fixture-1".to_owned(),
            max_cost_micro_units: 0,
            action_limit: 1,
            egress_bytes_limit: 0,
        },
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: ISSUED_AT_MS + 120_000,
        nonce: Nonce128::from_bytes([0x11; 16]),
        instance_epoch: 1,
        fencing_epoch: 9,
    }
}

pub fn canonicalize_value(value: &serde_json::Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("test JSON must canonicalize")
}
