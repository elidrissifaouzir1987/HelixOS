use helix_task_authority_contracts::{
    decode_and_verify_human_request_grant_v1, decode_and_verify_task_lease_v1, ContractError,
    HumanRequestGrantKeyResolver, HumanRequestGrantVerificationKeyV1, Sha256Digest,
    TaskLeaseKeyResolver, TaskLeaseVerificationKeyV1,
};
use serde_json::Value;
use std::collections::BTreeSet;

const GRANT_PROTECTED: &[u8] = include_bytes!(
    "../../../contracts/fixtures/durable-signed-task-authority-v1/golden/human-request-grant.protected.jcs"
);
const GRANT_ENVELOPE: &[u8] = include_bytes!(
    "../../../contracts/fixtures/durable-signed-task-authority-v1/golden/human-request-grant.envelope.jcs"
);
const LEASE_PROTECTED: &[u8] = include_bytes!(
    "../../../contracts/fixtures/durable-signed-task-authority-v1/golden/root-task-lease.protected.jcs"
);
const LEASE_ENVELOPE: &[u8] = include_bytes!(
    "../../../contracts/fixtures/durable-signed-task-authority-v1/golden/root-task-lease.envelope.jcs"
);
const PUBLIC_KEYS: &str =
    include_str!("../../../contracts/fixtures/durable-signed-task-authority-v1/public-keys.json");
const CASES: &str =
    include_str!("../../../contracts/fixtures/durable-signed-task-authority-v1/cases.json");
const OUTCOMES: &str = include_str!(
    "../../../contracts/fixtures/durable-signed-task-authority-v1/expected-outcomes.json"
);

struct FixtureKeys {
    grant: [u8; 32],
    lease: [u8; 32],
}

impl HumanRequestGrantKeyResolver for FixtureKeys {
    fn resolve_human_request_grant_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<HumanRequestGrantVerificationKeyV1> {
        if key_id != "request-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(HumanRequestGrantVerificationKeyV1::current(self.grant))
    }
}

impl TaskLeaseKeyResolver for FixtureKeys {
    fn resolve_task_lease_key(
        &self,
        key_id: &str,
    ) -> helix_task_authority_contracts::Result<TaskLeaseVerificationKeyV1> {
        if key_id != "lease-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(TaskLeaseVerificationKeyV1::current(self.lease))
    }
}

#[test]
fn golden_us1_bytes_are_exact_canonical_and_cryptographically_current() {
    for wire in [
        GRANT_PROTECTED,
        GRANT_ENVELOPE,
        LEASE_PROTECTED,
        LEASE_ENVELOPE,
    ] {
        assert!(!wire.ends_with(b"\n"));
        let value: Value = serde_json::from_slice(wire).unwrap();
        assert_eq!(serde_json_canonicalizer::to_vec(&value).unwrap(), wire);
    }

    let public_keys: Value = serde_json::from_str(PUBLIC_KEYS).unwrap();
    let keys = public_keys["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    let decode_key = |purpose: &str| {
        let entry = keys
            .iter()
            .find(|entry| entry["key_purpose"] == purpose)
            .unwrap();
        let public_key =
            Sha256Digest::parse_hex(entry["public_key_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            Sha256Digest::digest(public_key.as_bytes()).to_hex(),
            entry["public_key_fingerprint"].as_str().unwrap()
        );
        *public_key.as_bytes()
    };
    let resolver = FixtureKeys {
        grant: decode_key("request-surface-grant-signing"),
        lease: decode_key("core-task-lease-signing"),
    };

    let grant_value: Value = serde_json::from_slice(GRANT_ENVELOPE).unwrap();
    let lease_value: Value = serde_json::from_slice(LEASE_ENVELOPE).unwrap();
    assert_eq!(
        serde_json_canonicalizer::to_vec(&grant_value["protected"]).unwrap(),
        GRANT_PROTECTED
    );
    assert_eq!(
        serde_json_canonicalizer::to_vec(&lease_value["protected"]).unwrap(),
        LEASE_PROTECTED
    );
    assert_eq!(
        Sha256Digest::digest(GRANT_PROTECTED).to_hex(),
        grant_value["grant_digest"]
    );
    assert_eq!(
        Sha256Digest::digest(LEASE_PROTECTED).to_hex(),
        lease_value["lease_digest"]
    );

    let grant = decode_and_verify_human_request_grant_v1(GRANT_ENVELOPE, &resolver).unwrap();
    let lease = decode_and_verify_task_lease_v1(LEASE_ENVELOPE, &resolver).unwrap();
    assert_eq!(lease.claims().source_grant_id(), grant.claims().grant_id());
    assert_eq!(
        lease.claims().source_grant_digest(),
        grant.claims().grant_digest()
    );
    assert_eq!(lease.claims().delegation_depth(), 0);
    assert!(lease.claims().parent_lease_id().is_none());
    assert!(lease.claims().parent_lease_digest().is_none());
    assert!(lease.claims().parent_allocation_id().is_none());
}

#[test]
fn cases_and_expected_outcomes_are_one_to_one_closed_and_secret_free() {
    let cases: Value = serde_json::from_str(CASES).unwrap();
    let outcomes: Value = serde_json::from_str(OUTCOMES).unwrap();
    let case_ids = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["case_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let outcome_ids = outcomes["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|outcome| outcome["case_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(case_ids.len(), 9);
    assert_eq!(case_ids, outcome_ids);

    for forbidden in [
        "private_key",
        "private-key",
        "secret_key",
        "signing_seed",
        "bearer",
        "cookie",
        "native_path",
    ] {
        assert!(!PUBLIC_KEYS.contains(forbidden));
        assert!(!CASES.contains(forbidden));
        assert!(!OUTCOMES.contains(forbidden));
    }
    for outcome in outcomes["outcomes"].as_array().unwrap() {
        let delta = outcome["durable_delta"].as_object().unwrap();
        assert_eq!(delta.len(), 7);
        assert!(outcome["code"].as_str().is_some());
        assert!(outcome["current_authority_marker_returned"]
            .as_bool()
            .is_some());
    }
}
