//! Seeded diagnostics prove that portable preparation surfaces remain payload-free.

use helix_contracts::{AtomicityV1, Identifier, Nonce128, RecoveryClassV1, Sha256Digest};
use helix_plan_preparation::{
    AmbiguousPreparationV1, BudgetPreflightInputV1, BudgetPreflightV1,
    BudgetReservationReceiptInputV1, BudgetReservationReceiptV1, BudgetReservationStateV1,
    BudgetVectorInputV1, BudgetVectorV1, PreparationCommitReceiptInputV1,
    PreparationCommitReceiptV1, PreparationCommitUncertainV1, PreparationDenialV1,
    PreparationFailureV1, RecoveryEvidenceClassV1, RecoveryMaterialReceiptInputV1,
    RecoveryMaterialReceiptV1, RecoveryMaterialStateV1, RecoveryProviderProfileInputV1,
    RecoveryProviderProfileV1, PREPARATION_BUDGET_CONTRACT_VERSION_V1,
    PREPARATION_STORE_CONTRACT_VERSION_V1, RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
    RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
};
use std::error::Error;
use std::fmt::{Debug, Display};

const PATH_SENTINEL: &str = "/Users/private-operator/secret-plan.json";
const IDENTIFIER_SENTINEL: &str = "operation-private-identifier-seed";
const CONTENT_SENTINEL: &str = "canonical-content-private-seed";
const PROVIDER_SENTINEL: &str = "provider-raw-diagnostic-private-seed";
const KEY_SENTINEL: &str = "provisioner-key-private-seed";
const DIGEST_SENTINEL: &str = "abababababababababababababababababababababababababababababababab";
const NONCE_SENTINEL: &str = "11111111111111111111111111111111";
const BUDGET_SENTINEL: u64 = 7_654_321_098_765;
const BUDGET_SENTINEL_TEXT: &str = "7654321098765";

const ALL_SENTINELS: [&str; 8] = [
    PATH_SENTINEL,
    IDENTIFIER_SENTINEL,
    CONTENT_SENTINEL,
    PROVIDER_SENTINEL,
    KEY_SENTINEL,
    DIGEST_SENTINEL,
    NONCE_SENTINEL,
    BUDGET_SENTINEL_TEXT,
];

fn identifier(value: &str) -> Identifier {
    Identifier::new(value, 128).expect("seeded identifier must satisfy the portable grammar")
}

fn digest() -> Sha256Digest {
    Sha256Digest::parse_hex(DIGEST_SENTINEL).expect("seeded digest must be valid")
}

fn assert_opaque(diagnostic: &str) {
    assert!(diagnostic.is_ascii());
    assert!(diagnostic.len() <= 192, "diagnostic is unexpectedly large");
    for sentinel in ALL_SENTINELS {
        assert!(
            !diagnostic.contains(sentinel),
            "diagnostic exposed seeded private data"
        );
    }
}

fn assert_closed_error<E>(error: E, debug: &str, display: &str)
where
    E: Error + Debug + Display,
{
    assert_eq!(format!("{error:?}"), debug);
    assert_eq!(error.to_string(), display);
    assert!(error.source().is_none());
    assert_opaque(&format!("{error:?}"));
    assert_opaque(&error.to_string());
}

#[test]
fn provider_material_and_budget_receipts_hide_every_seeded_field() {
    let profile_input = RecoveryProviderProfileInputV1 {
        profile_id: identifier(CONTENT_SENTINEL),
        profile_version: RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
        provider_id: identifier(PROVIDER_SENTINEL),
        provider_generation: 1,
        evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
        capability_binding_digest: digest(),
        at_rest_profile_id: identifier(KEY_SENTINEL),
        supports_create_only: true,
        supports_sync: true,
        supports_no_clobber_publication: true,
        maximum_material_bytes: BUDGET_SENTINEL,
        maximum_reserved_capacity: BUDGET_SENTINEL,
    };
    assert_opaque(&format!("{profile_input:?}"));
    let profile = RecoveryProviderProfileV1::try_new(profile_input)
        .expect("seeded provider profile must be valid");
    assert_opaque(&format!("{profile:?}"));

    let receipt_input = RecoveryMaterialReceiptInputV1 {
        contract_version: RECOVERY_RECEIPT_CONTRACT_VERSION_V1,
        provider_profile_id: identifier(CONTENT_SENTINEL),
        provider_profile_version: RECOVERY_PROVIDER_CONTRACT_VERSION_V1,
        provider_id: identifier(PROVIDER_SENTINEL),
        provider_generation: 1,
        evidence_class: RecoveryEvidenceClassV1::SyntheticConformance,
        at_rest_profile_id: identifier(KEY_SENTINEL),
        capability_binding_digest: digest(),
        plan_id: digest(),
        operation_id: identifier(IDENTIFIER_SENTINEL),
        attempt_id: digest(),
        target_reference_digest: digest(),
        precondition_identity_digest: digest(),
        precondition_digest: digest(),
        precondition_length: BUDGET_SENTINEL,
        recovery_class: RecoveryClassV1::Compensation,
        atomicity: AtomicityV1::AtomicReplace,
        material_digest: digest(),
        material_length: BUDGET_SENTINEL,
        reserved_capacity: BUDGET_SENTINEL,
        material_id: digest(),
        publication_attempt_id: digest(),
        manifest_digest: digest(),
        state: RecoveryMaterialStateV1::Published,
        boot_binding_digest: digest(),
        instance_epoch: BUDGET_SENTINEL,
        fencing_epoch: BUDGET_SENTINEL,
    };
    assert_opaque(&format!("{receipt_input:?}"));
    let receipt = RecoveryMaterialReceiptV1::try_new(receipt_input)
        .expect("seeded recovery receipt must be valid");
    assert_opaque(&format!("{receipt:?}"));

    let budget_input = BudgetVectorInputV1 {
        max_cost_micro_units: BUDGET_SENTINEL,
        action_limit: BUDGET_SENTINEL,
        egress_bytes_limit: BUDGET_SENTINEL,
        recovery_bytes: BUDGET_SENTINEL,
    };
    assert_opaque(&format!("{budget_input:?}"));
    let budget = BudgetVectorV1::try_new(budget_input).expect("seeded budget must be valid");
    assert_opaque(&format!("{budget:?}"));

    let preflight_input = BudgetPreflightInputV1 {
        contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
        observed_scope_generation: BUDGET_SENTINEL,
        observed_scope_binding_digest: digest(),
        observed_remaining: budget,
    };
    assert_opaque(&format!("{preflight_input:?}"));
    let preflight =
        BudgetPreflightV1::try_new(preflight_input).expect("seeded preflight must be valid");
    assert_opaque(&format!("{preflight:?}"));
}

#[test]
fn commit_nonce_and_user_budget_custody_have_bounded_debug() {
    let reservation_input = BudgetReservationReceiptInputV1 {
        contract_version: PREPARATION_BUDGET_CONTRACT_VERSION_V1,
        state: BudgetReservationStateV1::Held,
        reservation_generation: BUDGET_SENTINEL,
    };
    assert_opaque(&format!("{reservation_input:?}"));
    let reservation = BudgetReservationReceiptV1::try_new(reservation_input)
        .expect("seeded reservation receipt must be valid");
    assert_opaque(&format!("{reservation:?}"));

    let commit_input = PreparationCommitReceiptInputV1 {
        contract_version: PREPARATION_STORE_CONTRACT_VERSION_V1,
        attempt_id: digest(),
        store_generation: BUDGET_SENTINEL,
        operation_state_generation: BUDGET_SENTINEL,
        transition_generation: BUDGET_SENTINEL,
        event_generation: BUDGET_SENTINEL,
        budget_reservation: reservation,
    };
    assert_opaque(&format!("{commit_input:?}"));
    let commit = PreparationCommitReceiptV1::try_new(commit_input)
        .expect("seeded commit receipt must be valid");
    assert_opaque(&format!("{commit:?}"));

    let uncertain =
        PreparationCommitUncertainV1::try_new(PREPARATION_STORE_CONTRACT_VERSION_V1, digest())
            .expect("seeded uncertain receipt must be valid");
    assert_opaque(&format!("{uncertain:?}"));

    let nonce = Nonce128::parse_hex(NONCE_SENTINEL).expect("seeded nonce must be valid");
    assert_eq!(format!("{nonce:?}"), "Nonce128(<redacted>)");
    assert_opaque(&format!("{nonce:?}"));
}

#[test]
fn invalid_native_path_and_content_are_never_echoed() {
    for hostile in [PATH_SENTINEL, "raw canonical plan content with spaces"] {
        let error = Identifier::new(hostile, 128)
            .expect_err("hostile private content must not become a portable identifier");
        assert_opaque(&format!("{error:?}"));
        assert_opaque(&error.to_string());
    }

    let hostile_digest = format!("{PROVIDER_SENTINEL}{DIGEST_SENTINEL}");
    let error =
        Sha256Digest::parse_hex(&hostile_digest).expect_err("hostile digest must be rejected");
    assert_opaque(&format!("{error:?}"));
    assert_opaque(&error.to_string());
}

#[test]
fn all_public_preparation_errors_are_closed_and_payload_free() {
    for error in PreparationDenialV1::ALL {
        assert_closed_error(*error, error.code(), "plan preparation was denied");
    }
    for error in PreparationFailureV1::ALL {
        assert_closed_error(*error, error.code(), "plan preparation failed");
    }
    for error in AmbiguousPreparationV1::ALL {
        assert_closed_error(
            *error,
            "PREPARATION_AMBIGUOUS",
            "plan preparation is ambiguous",
        );
    }
}
