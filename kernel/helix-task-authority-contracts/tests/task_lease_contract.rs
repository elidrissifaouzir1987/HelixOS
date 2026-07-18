//! Root TaskLease v1 contract tests (PLAN-006 T026).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use helix_task_authority_contracts::{
    decode_and_verify_human_request_grant_v1, decode_and_verify_retained_task_lease_v1,
    decode_and_verify_task_lease_v1, sign_human_request_grant_v1, sign_task_lease_v1,
    AuthenticHumanRequestGrantV1, ContractError, CurrencyCodeV1, DelegationDepthV1,
    DelegationModeV1, Generation, HumanRequestGrantInputV1, HumanRequestGrantKeyResolver,
    HumanRequestGrantProtectedV1, HumanRequestGrantSigner, HumanRequestGrantVerificationKeyV1,
    Identifier, MinimumAuthenticationProfileV1, ResourceRootV1, RiskLevelV1, RootTaskLeaseBoundsV1,
    RootTaskLeaseInputV1, SafeU64, Sha256Digest, TaskLeaseBudgetV1, TaskLeaseCatalogueBoundV1,
    TaskLeaseCounterLimitsV1, TaskLeaseKeyResolver, TaskLeaseProtectedV1, TaskLeaseSigner,
    TaskLeaseTrustBoundV1, TaskLeaseVerificationKeyV1, VerificationKeyStatusV1,
};
use serde_json::{json, Value};
use std::cell::Cell;

const SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/task-lease-v1.schema.json"
);
const LEASE_DOMAIN: &[u8] = b"HELIXOS\0TASK-LEASE\0V1\0";
const GRANT_KEY_ID: &str = "request-key-v1";
const LEASE_KEY_ID: &str = "lease-key-v1";

struct GrantSigner(SigningKey);

impl HumanRequestGrantSigner for GrantSigner {
    fn key_id(&self) -> &str {
        GRANT_KEY_ID
    }

    fn sign_human_request_grant(
        &self,
        message: &[u8],
    ) -> helix_task_authority_contracts::Result<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
}

struct GrantResolver([u8; 32]);

impl HumanRequestGrantKeyResolver for GrantResolver {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
        if key_id != GRANT_KEY_ID {
            return Err(ContractError::UnknownKey);
        }
        Ok(HumanRequestGrantVerificationKeyV1::current(self.0))
    }
}

struct LeaseSigner(SigningKey);

impl TaskLeaseSigner for LeaseSigner {
    fn key_id(&self) -> &str {
        LEASE_KEY_ID
    }

    fn sign_task_lease(&self, message: &[u8]) -> helix_task_authority_contracts::Result<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
}

struct LeaseResolver {
    key: [u8; 32],
    status: VerificationKeyStatusV1,
    calls: Cell<usize>,
}

impl LeaseResolver {
    fn current(key: [u8; 32]) -> Self {
        Self {
            key,
            status: VerificationKeyStatusV1::Current,
            calls: Cell::new(0),
        }
    }

    fn historical(key: [u8; 32]) -> Self {
        Self {
            status: VerificationKeyStatusV1::Historical,
            ..Self::current(key)
        }
    }
}

impl TaskLeaseKeyResolver for LeaseResolver {
    fn resolve_task_lease_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<TaskLeaseVerificationKeyV1> {
        self.calls.set(self.calls.get() + 1);
        if key_id != LEASE_KEY_ID {
            return Err(ContractError::UnknownKey);
        }
        Ok(match self.status {
            VerificationKeyStatusV1::Current => TaskLeaseVerificationKeyV1::current(self.key),
            VerificationKeyStatusV1::Historical => TaskLeaseVerificationKeyV1::historical(self.key),
        })
    }
}

fn safe(value: u64) -> SafeU64 {
    SafeU64::new(value).unwrap()
}

fn generation(value: u64) -> Generation {
    Generation::new(value).unwrap()
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).unwrap()
}

fn authentic_grant() -> AuthenticHumanRequestGrantV1 {
    let signer = GrantSigner(SigningKey::from_bytes(&[7_u8; 32]));
    let protected = HumanRequestGrantProtectedV1::try_new(
        HumanRequestGrantInputV1 {
            grant_id: Sha256Digest::from_bytes([0x10; 32]),
            issuer_id: Identifier::new("request-surface-v1").unwrap(),
            audience: Identifier::new("helixos-core-v1").unwrap(),
            principal_id: Identifier::new("principal-v1").unwrap(),
            message_digest: Sha256Digest::from_bytes([0x20; 32]),
            channel_id: Identifier::new("channel-v1").unwrap(),
            session_id: Identifier::new("session-v1").unwrap(),
            scope_template_id: Identifier::new("scope-v1").unwrap(),
            scope_template_digest: Sha256Digest::from_bytes([0x30; 32]),
            scope_template_generation: generation(7),
            issued_at_utc_ms: safe(1_000),
            expires_at_utc_ms: safe(2_000),
        },
        Identifier::new(GRANT_KEY_ID).unwrap(),
    )
    .unwrap();
    let signed = sign_human_request_grant_v1(protected, &signer).unwrap();
    decode_and_verify_human_request_grant_v1(
        &signed.to_canonical_json().unwrap(),
        &GrantResolver(signer.0.verifying_key().to_bytes()),
    )
    .unwrap()
}

fn budget() -> TaskLeaseBudgetV1 {
    TaskLeaseBudgetV1::from_validated_parts_v1(
        safe(10_000),
        safe(20),
        safe(30),
        safe(40_000),
        CurrencyCodeV1::new("EUR").unwrap(),
        safe(50_000),
        Identifier::new("price-v1").unwrap(),
    )
}

fn counters() -> TaskLeaseCounterLimitsV1 {
    TaskLeaseCounterLimitsV1::from_validated_parts_v1(
        safe(3),
        safe(2),
        safe(1),
        DelegationDepthV1::new(2).unwrap(),
    )
}

fn trust() -> TaskLeaseTrustBoundV1 {
    TaskLeaseTrustBoundV1::from_validated_parts_v1(
        RiskLevelV1::L2,
        MinimumAuthenticationProfileV1::UserVerificationV1,
        Identifier::new("policy-v1").unwrap(),
        Sha256Digest::from_bytes([0x40; 32]),
        generation(8),
    )
}

fn catalogue(
    entries: &[&str],
) -> helix_task_authority_contracts::Result<TaskLeaseCatalogueBoundV1> {
    TaskLeaseCatalogueBoundV1::try_new_v1(
        Identifier::new("catalogue-v1").unwrap(),
        Sha256Digest::from_bytes([0x50; 32]),
        generation(9),
        entries
            .iter()
            .map(|entry| Identifier::new(*entry).unwrap())
            .collect(),
    )
}

fn roots() -> Vec<ResourceRootV1> {
    vec![
        ResourceRootV1::try_new("root-a", vec!["docs".to_owned()]).unwrap(),
        ResourceRootV1::try_new("root-b", Vec::new()).unwrap(),
    ]
}

fn bounds() -> RootTaskLeaseBoundsV1 {
    RootTaskLeaseBoundsV1::try_new_v1(
        roots(),
        budget(),
        counters(),
        trust(),
        catalogue(&["entry-a", "entry-b"]).unwrap(),
        DelegationModeV1::Delegable,
    )
    .unwrap()
}

fn input(expires_utc: u64, issued_mono: u64, deadline_mono: u64) -> RootTaskLeaseInputV1 {
    RootTaskLeaseInputV1 {
        lease_id: Sha256Digest::from_bytes([0x60; 32]),
        issuer_id: Identifier::new("core-lease-issuer-v1").unwrap(),
        task_id: Identifier::new("task-v1").unwrap(),
        workload_id: Identifier::new("workload-v1").unwrap(),
        audience: Identifier::new("plan-authority-v1").unwrap(),
        bounds: bounds(),
        clock_generation: generation(10),
        boot_id: Identifier::new("boot-v1").unwrap(),
        instance_epoch: safe(11),
        issued_at_utc_ms: safe(1_100),
        not_before_utc_ms: safe(1_100),
        expires_at_utc_ms: safe(expires_utc),
        issued_at_monotonic_ms: safe(issued_mono),
        deadline_monotonic_ms: safe(deadline_mono),
    }
}

fn fixture() -> (Vec<u8>, [u8; 32], Sha256Digest, Sha256Digest) {
    let grant = authentic_grant();
    let source_id = grant.claims().grant_id();
    let source_digest = grant.grant_digest();
    let protected = TaskLeaseProtectedV1::try_new_root_v1(
        input(1_900, 100, 200),
        &grant,
        Identifier::new(LEASE_KEY_ID).unwrap(),
    )
    .unwrap();
    let signer = LeaseSigner(SigningKey::from_bytes(&[9_u8; 32]));
    let signed = sign_task_lease_v1(protected, &signer).unwrap();
    (
        signed.to_canonical_json().unwrap(),
        signer.0.verifying_key().to_bytes(),
        source_id,
        source_digest,
    )
}

#[test]
fn root_shape_source_scope_digest_and_claims_are_exact() {
    let (wire, public_key, source_id, source_digest) = fixture();
    let lease =
        decode_and_verify_task_lease_v1(&wire, &LeaseResolver::current(public_key)).unwrap();
    let claims = lease.claims();

    assert_eq!(claims.schema(), "helixos.task-lease/1");
    assert_eq!(claims.digest_algorithm(), "sha-256");
    assert_eq!(claims.signature_algorithm(), "ed25519");
    assert_eq!(claims.key_purpose(), "core-task-lease-signing");
    assert_eq!(claims.key_id(), LEASE_KEY_ID);
    assert_eq!(claims.lease_id(), Sha256Digest::from_bytes([0x60; 32]));
    assert_eq!(claims.source_grant_id(), source_id);
    assert_eq!(claims.source_grant_digest(), source_digest);
    assert_eq!(claims.source_principal_id(), "principal-v1");
    assert_eq!(claims.allowed_intentions().len(), 1);
    assert_eq!(claims.resource_roots(), roots());
    assert_eq!(claims.budget().read_bytes_limit_v1().get(), 10_000);
    assert_eq!(claims.counter_limits().max_delegation_depth_v1().get(), 2);
    assert_eq!(claims.trust_bound().policy_generation_v1().get(), 8);
    assert_eq!(claims.catalogue_bound().catalogue_generation_v1().get(), 9);
    assert_eq!(claims.parent_lease_id(), None);
    assert_eq!(claims.parent_lease_digest(), None);
    assert_eq!(claims.parent_allocation_id(), None);
    assert_eq!(claims.delegation_depth(), 0);
    assert_eq!(claims.issued_at_utc_ms(), claims.not_before_utc_ms());
    assert_eq!(claims.expires_at_utc_ms(), 1_900);
    assert_eq!(claims.issued_at_monotonic_ms(), 100);
    assert_eq!(claims.deadline_monotonic_ms(), 200);
    assert_eq!(lease.canonical_signed_envelope_bytes().unwrap(), wire);
}

#[test]
fn schema_and_wire_have_three_outer_and_thirty_three_protected_fields() {
    let schema: Value = serde_json::from_str(SCHEMA).unwrap();
    assert_eq!(schema["required"].as_array().unwrap().len(), 3);
    assert_eq!(
        schema["$defs"]["protectedLease"]["required"]
            .as_array()
            .unwrap()
            .len(),
        33
    );
    let (wire, _, _, _) = fixture();
    let value: Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert_eq!(value["protected"].as_object().unwrap().len(), 33);
    for parent in [
        "parent_lease_id",
        "parent_lease_digest",
        "parent_allocation_id",
    ] {
        assert!(value["protected"][parent].is_null());
    }
    assert_eq!(value["protected"]["delegation_depth"], 0);
    assert_eq!(value["protected"]["budget"].as_object().unwrap().len(), 7);
    assert_eq!(
        value["protected"]["counter_limits"]
            .as_object()
            .unwrap()
            .len(),
        4
    );
    assert_eq!(
        value["protected"]["trust_bound"].as_object().unwrap().len(),
        5
    );
    assert_eq!(
        value["protected"]["catalogue_bound"]
            .as_object()
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn independent_digest_domain_and_signature_are_exact() {
    let (wire, public_key, _, _) = fixture();
    let value: Value = serde_json::from_slice(&wire).unwrap();
    let protected_jcs = canonical(&value["protected"]);
    assert_eq!(
        value["lease_digest"],
        json!(Sha256Digest::digest(&protected_jcs).to_hex())
    );
    let signature = URL_SAFE_NO_PAD
        .decode(value["signature"].as_str().unwrap())
        .unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&signature).unwrap();
    let mut message = LEASE_DOMAIN.to_vec();
    message.extend_from_slice(&protected_jcs);
    ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .unwrap()
        .verify(&message, &signature)
        .unwrap();
    let mut wrong = b"HELIXOS\0HUMAN-REQUEST-GRANT\0V1\0".to_vec();
    wrong.extend_from_slice(&protected_jcs);
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .unwrap()
        .verify(&wrong, &signature)
        .is_err());
}

#[test]
fn source_expiry_parent_shape_and_exclusive_time_relations_deny() {
    let grant = authentic_grant();
    for candidate in [input(2_001, 100, 200), input(1_900, 200, 200)] {
        assert_eq!(
            TaskLeaseProtectedV1::try_new_root_v1(
                candidate,
                &grant,
                Identifier::new(LEASE_KEY_ID).unwrap(),
            ),
            Err(ContractError::InvalidField)
        );
    }

    let (wire, public_key, _, _) = fixture();
    let base: Value = serde_json::from_slice(&wire).unwrap();
    for mutation in [
        ("parent_lease_id", json!("70".repeat(32))),
        ("delegation_depth", json!(1)),
        ("expires_at_utc_ms", json!(1_100)),
    ] {
        let mut candidate = base.clone();
        candidate["protected"][mutation.0] = mutation.1;
        candidate["lease_digest"] =
            json!(Sha256Digest::digest(&canonical(&candidate["protected"])).to_hex());
        assert_eq!(
            decode_and_verify_task_lease_v1(
                &canonical(&candidate),
                &LeaseResolver::current(public_key),
            )
            .unwrap_err(),
            ContractError::InvalidField,
            "{}",
            mutation.0
        );
    }

    let mut omitted = base;
    omitted["protected"]
        .as_object_mut()
        .unwrap()
        .remove("parent_lease_id");
    assert_eq!(
        decode_and_verify_task_lease_v1(&canonical(&omitted), &LeaseResolver::current(public_key),)
            .unwrap_err(),
        ContractError::MissingRequiredField
    );
}

#[test]
fn resource_and_catalogue_sets_are_canonical_sorted_unique() {
    assert!(catalogue(&["entry-a", "entry-b"]).is_ok());
    assert_eq!(
        catalogue(&["entry-b", "entry-a"]),
        Err(ContractError::InvalidField)
    );
    assert_eq!(
        catalogue(&["entry-a", "entry-a"]),
        Err(ContractError::InvalidField)
    );

    let reversed = roots().into_iter().rev().collect();
    assert!(RootTaskLeaseBoundsV1::try_new_v1(
        reversed,
        budget(),
        counters(),
        trust(),
        catalogue(&["entry-a"]).unwrap(),
        DelegationModeV1::Delegable,
    )
    .is_err());
    let duplicate = vec![roots()[0].clone(), roots()[0].clone()];
    assert!(RootTaskLeaseBoundsV1::try_new_v1(
        duplicate,
        budget(),
        counters(),
        trust(),
        catalogue(&["entry-a"]).unwrap(),
        DelegationModeV1::Delegable,
    )
    .is_err());
}

#[test]
fn digest_signature_canonical_size_and_historical_status_fail_closed() {
    let (wire, public_key, _, _) = fixture();
    let mut value: Value = serde_json::from_slice(&wire).unwrap();
    value["lease_digest"] = json!("00".repeat(32));
    let resolver = LeaseResolver::current(public_key);
    assert_eq!(
        decode_and_verify_task_lease_v1(&canonical(&value), &resolver).unwrap_err(),
        ContractError::DigestMismatch
    );
    assert_eq!(resolver.calls.get(), 0);

    let mut resign_required: Value = serde_json::from_slice(&wire).unwrap();
    resign_required["protected"]["audience"] = json!("other-audience-v1");
    resign_required["lease_digest"] =
        json!(Sha256Digest::digest(&canonical(&resign_required["protected"])).to_hex());
    let resolver = LeaseResolver::current(public_key);
    assert_eq!(
        decode_and_verify_task_lease_v1(&canonical(&resign_required), &resolver).unwrap_err(),
        ContractError::SignatureInvalid
    );
    assert_eq!(resolver.calls.get(), 1);

    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&wire);
    assert_eq!(
        decode_and_verify_task_lease_v1(&noncanonical, &LeaseResolver::current(public_key))
            .unwrap_err(),
        ContractError::NonCanonicalWire
    );
    let oversized = serde_json::to_vec(&"a".repeat(1_048_575)).unwrap();
    assert_eq!(oversized.len(), 1_048_577);
    assert_eq!(
        decode_and_verify_task_lease_v1(&oversized, &LeaseResolver::current(public_key))
            .unwrap_err(),
        ContractError::WireTooLarge
    );

    assert_eq!(
        decode_and_verify_task_lease_v1(&wire, &LeaseResolver::historical(public_key)).unwrap_err(),
        ContractError::HistoricalKeyNotAuthority
    );
    let retained =
        decode_and_verify_retained_task_lease_v1(&wire, &LeaseResolver::historical(public_key))
            .unwrap();
    assert_eq!(
        retained.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(retained.canonical_signed_envelope_bytes().unwrap(), wire);
}
