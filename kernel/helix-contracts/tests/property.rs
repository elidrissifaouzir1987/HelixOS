mod common;

use common::{fixed_signer, sample_input, TestResolver};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, AtomicityV1, Nonce128, PlanInputV1, PlanProtectedV1,
    RecoveryClassV1, RequestSourceKindV1, ResourceRefV1, RiskLevelV1, Sha256Digest,
};
use proptest::prelude::*;

type InputMutation = (&'static str, fn(&mut PlanInputV1));

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn signed_roundtrip_is_canonical_and_stable(content in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let signer = fixed_signer();
        let resolver = TestResolver::for_signer(&signer);
        let mut input = sample_input();
        input.replacement_bytes = content;
        let signed = sign_plan_v1(input, &signer).unwrap();
        let first = signed.to_canonical_json().unwrap();
        let authentic = decode_and_verify_plan(&first, &resolver).unwrap();
        let second = authentic.into_signed().to_canonical_json().unwrap();
        prop_assert_eq!(first, second);
    }

    #[test]
    fn every_replacement_mutation_changes_plan_id(a in proptest::collection::vec(any::<u8>(), 0..512), suffix in any::<u8>()) {
        let mut first_input = sample_input();
        first_input.replacement_bytes = a.clone();
        let mut second_input = sample_input();
        let mut changed = a;
        changed.push(suffix);
        second_input.replacement_bytes = changed;
        let first = PlanProtectedV1::try_new(first_input, "key:property").unwrap();
        let second = PlanProtectedV1::try_new(second_input, "key:property").unwrap();
        prop_assert_ne!(first.plan_id().unwrap(), second.plan_id().unwrap());
    }

    #[test]
    fn portable_ascii_components_roundtrip(component in "[A-Za-z0-9_-]{1,32}") {
        prop_assume!(!matches!(component.to_ascii_uppercase().as_str(), "CON" | "PRN" | "AUX" | "NUL"));
        let reference = ResourceRefV1::new("vault", [component.clone()]).unwrap();
        let json = serde_json::to_vec(&reference).unwrap();
        let decoded: ResourceRefV1 = serde_json::from_slice(&json).unwrap();
        prop_assert_eq!(reference, decoded);
    }

    #[test]
    fn arbitrary_wire_never_panics_or_authenticates(wire in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let signer = fixed_signer();
        let resolver = TestResolver::for_signer(&signer);
        prop_assert!(decode_and_verify_plan(&wire, &resolver).is_err());
    }
}

#[test]
fn every_independent_valid_input_mutation_changes_plan_identity() {
    let baseline = PlanProtectedV1::try_new(sample_input(), "key:property")
        .unwrap()
        .plan_id()
        .unwrap();
    let mutations: &[InputMutation] = &[
        ("operation_id", |input| {
            input.operation_id.push_str("-changed")
        }),
        ("task_id", |input| input.task_id.push_str("-changed")),
        ("workload_id", |input| {
            input.workload_id.push_str("-changed")
        }),
        ("boot_id", |input| input.boot_id.push_str("-changed")),
        ("task_lease_digest", |input| {
            input.task_lease_digest = Sha256Digest::digest(b"changed lease")
        }),
        ("request_source_kind", |input| {
            input.request_source_kind = RequestSourceKindV1::RegisteredTrigger
        }),
        ("request_source_digest", |input| {
            input.request_source_digest = Sha256Digest::digest(b"changed source")
        }),
        ("catalog_version", |input| {
            input.catalog_version.push_str(".2")
        }),
        ("policy_version", |input| {
            input.policy_version.push_str(".2")
        }),
        ("risk_level", |input| input.risk_level = RiskLevelV1::L2),
        ("target_root", |input| {
            input.target =
                ResourceRefV1::new("vault-secondary", ["Projects", "HelixOS", "Decision.md"])
                    .unwrap()
        }),
        ("target_component", |input| {
            input.target =
                ResourceRefV1::new("vault-main", ["Projects", "HelixOS", "Other.md"]).unwrap()
        }),
        ("precondition_volume", |input| {
            input.precondition.volume_id.push_str("-changed")
        }),
        ("precondition_file", |input| {
            input.precondition.file_id.push_str("-changed")
        }),
        ("precondition_digest", |input| {
            input.precondition.content_sha256 = Sha256Digest::digest(b"changed preimage")
        }),
        ("precondition_length", |input| {
            input.precondition.byte_length += 1
        }),
        ("replacement_bytes", |input| {
            input.replacement_bytes.push(b'!')
        }),
        ("replacement_media_type", |input| {
            input.replacement_media_type = "application/octet-stream".to_owned()
        }),
        ("recovery_atomicity", |input| {
            input.recovery.atomicity = AtomicityV1::NonAtomic
        }),
        ("recovery_class", |input| {
            input.recovery.class = RecoveryClassV1::Irreversible;
            input.risk_level = RiskLevelV1::L2;
        }),
        ("recovery_reserved_bytes", |input| {
            input.recovery.reserved_bytes += 1
        }),
        ("capability_report_digest", |input| {
            input.capability_report_digest = Sha256Digest::digest(b"changed capabilities")
        }),
        ("capability_observed_at", |input| {
            input.capability_observed_at_unix_ms += 1
        }),
        ("required_capabilities", |input| {
            input
                .required_capabilities
                .push("filesystem.durable-flush".to_owned())
        }),
        ("budget_reservation", |input| {
            input.budget.reservation_id.push_str("-changed")
        }),
        ("budget_currency", |input| {
            input.budget.currency_code = "USD".to_owned()
        }),
        ("budget_price_table", |input| {
            input.budget.price_table_id.push_str("-changed")
        }),
        ("budget_cost", |input| {
            input.budget.max_cost_micro_units += 1
        }),
        ("budget_actions", |input| input.budget.action_limit += 1),
        ("budget_egress", |input| {
            input.budget.egress_bytes_limit += 1
        }),
        ("issued_at", |input| input.issued_at_unix_ms += 1),
        ("expires_at", |input| input.expires_at_unix_ms += 1),
        ("nonce", |input| {
            input.nonce = Nonce128::from_bytes([0x22; 16])
        }),
        ("instance_epoch", |input| input.instance_epoch += 1),
        ("fencing_epoch", |input| input.fencing_epoch += 1),
    ];

    for (name, mutate) in mutations {
        let mut input = sample_input();
        mutate(&mut input);
        let changed = PlanProtectedV1::try_new(input, "key:property")
            .unwrap_or_else(|error| panic!("valid mutation {name} was rejected: {error}"))
            .plan_id()
            .unwrap();
        assert_ne!(baseline, changed, "mutation did not affect plan ID: {name}");
    }

    let changed_key = PlanProtectedV1::try_new(sample_input(), "key:property-changed")
        .unwrap()
        .plan_id()
        .unwrap();
    assert_ne!(baseline, changed_key, "key_id did not affect plan ID");
}

#[test]
fn capability_source_order_and_duplicates_do_not_change_identity() {
    let baseline = PlanProtectedV1::try_new(sample_input(), "key:property")
        .unwrap()
        .plan_id()
        .unwrap();
    let mut reordered = sample_input();
    reordered.required_capabilities.reverse();
    reordered
        .required_capabilities
        .push("filesystem.atomic-replace".to_owned());
    let normalized = PlanProtectedV1::try_new(reordered, "key:property")
        .unwrap()
        .plan_id()
        .unwrap();
    assert_eq!(baseline, normalized);
}
