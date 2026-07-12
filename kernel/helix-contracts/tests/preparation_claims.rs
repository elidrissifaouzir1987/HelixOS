mod common;

use common::{fixed_signer, TestResolver};
use helix_contracts::{
    decode_and_verify_plan, AtomicityV1, AuthenticPlanEnvelopeV1, PlanPreparationClaimsV1,
    RecoveryClassV1, Sha256Digest,
};

const FIXTURE_ENVELOPE: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.envelope.jcs");
const EXPECTED_PLAN_ID: &str = "50a31bfe3789f058e8498fa2a019ae24304243af6f1f239b550da8bfdfdfafd6";
const EXPECTED_SIGNATURE: &str =
    "ysUKcm-ZHfJU63AJ1uVxWRMncpBxsGFclz6johP90AlF3aTjVE8aaKfk0bYfIG_KFcTWvMPoDZkcJ3tJPdQ9Aw";
const EXPECTED_ENVELOPE_SHA256: &str =
    "3ba21bfc76208492fd8269def345ad2d25eb8fa79e792aea37794d24ce935de7";
const PLAN_SOURCE: &str = include_str!("../src/plan.rs");

fn authentic_fixture() -> AuthenticPlanEnvelopeV1 {
    let signer = fixed_signer();
    decode_and_verify_plan(FIXTURE_ENVELOPE, &TestResolver::for_signer(&signer))
        .expect("reviewed PLAN-001 fixture verifies")
}

#[test]
fn preparation_projection_borrows_every_required_authenticated_field() {
    let authentic = authentic_fixture();
    let claims = authentic.preparation_claims();

    assert_eq!(claims.plan_id(), authentic.plan_id());
    assert_eq!(
        claims.operation_id(),
        "operation:00000000-0000-4000-8000-000000000001"
    );
    assert_eq!(claims.task_id(), "task:fixture-1");
    assert_eq!(claims.workload_id(), "workload:agent-vm-1");
    assert_eq!(
        claims.task_lease_digest(),
        Sha256Digest::digest(b"fixture task lease")
    );
    assert!(std::ptr::eq(
        claims.target(),
        authentic.protected().target()
    ));
    assert_eq!(claims.target().root_id(), "vault-main");
    assert_eq!(
        claims.target().components(),
        &["Projects", "HelixOS", "Decision.md"]
    );

    assert_eq!(claims.precondition_volume_id(), "volume:fixture-apfs");
    assert_eq!(claims.precondition_file_id(), "file:00000042");
    assert_eq!(
        claims.precondition_content_sha256(),
        Sha256Digest::digest(b"before\n")
    );
    assert_eq!(claims.precondition_byte_length(), 7);

    assert_eq!(
        claims.replacement_sha256(),
        Sha256Digest::digest(b"after\n")
    );
    assert_eq!(claims.replacement_byte_length(), 6);
    assert_eq!(
        claims.replacement_media_type(),
        "text/markdown;charset=utf-8"
    );

    assert_eq!(claims.recovery_class(), RecoveryClassV1::Compensation);
    assert_eq!(claims.atomicity(), AtomicityV1::AtomicReplace);
    assert_eq!(
        claims.preimage_sha256(),
        Some(Sha256Digest::digest(b"before\n"))
    );
    assert_eq!(claims.recovery_reserved_bytes(), 4096);
    assert_eq!(
        claims.verification_sha256(),
        Sha256Digest::digest(b"after\n")
    );
    assert_eq!(claims.verification_byte_length(), 6);

    let budget = claims.budget();
    assert_eq!(budget.reservation_id(), "budget:fixture-1");
    assert_eq!(budget.currency_code(), "EUR");
    assert_eq!(budget.price_table_id(), "price-table:fixture-1");
    assert_eq!(budget.max_cost_micro_units(), 0);
    assert_eq!(budget.action_limit(), 1);
    assert_eq!(budget.egress_bytes_limit(), 0);
}

#[test]
fn preparation_projection_is_only_a_copyable_borrowed_view() {
    fn assert_copy<T: Copy>() {}

    assert_copy::<PlanPreparationClaimsV1<'static>>();
    assert_eq!(
        std::mem::size_of::<PlanPreparationClaimsV1<'static>>(),
        std::mem::size_of::<&AuthenticPlanEnvelopeV1>()
    );

    let authentic = authentic_fixture();
    let first = authentic.preparation_claims();
    let copied = first;
    assert_eq!(first.plan_id(), copied.plan_id());
}

#[test]
fn preparation_projection_has_no_wire_constructor_or_replacement_byte_surface() {
    let start = PLAN_SOURCE
        .find("#[derive(Clone, Copy)]\npub struct PlanPreparationClaimsV1<'plan>")
        .expect("preparation projection declaration");
    let tail = &PLAN_SOURCE[start..];
    let end = tail
        .find("/// Borrowed, read-only eligibility bindings from an authenticated plan.")
        .expect("next projection declaration");
    let projection_source = &tail[..end];

    assert!(projection_source.contains("envelope: &'plan AuthenticPlanEnvelopeV1"));
    assert!(!projection_source.contains("pub envelope:"));
    assert!(!projection_source.contains("Serialize"));
    assert!(!projection_source.contains("Deserialize"));
    assert!(!projection_source.contains("pub fn new("));
    assert!(!projection_source.contains("pub const fn new("));
    assert!(!projection_source.contains("pub fn replacement_bytes("));
    assert!(!projection_source.contains("pub fn replacement_content_base64url("));
}

#[test]
fn authentic_canonical_custody_preserves_plan_v1_bytes_identity_and_signature() {
    let authentic = authentic_fixture();
    let canonical = authentic
        .canonical_signed_envelope_bytes()
        .expect("authenticated envelope canonicalizes");

    assert_eq!(canonical, FIXTURE_ENVELOPE);
    assert_eq!(authentic.plan_id().to_string(), EXPECTED_PLAN_ID);
    assert_eq!(
        Sha256Digest::digest(FIXTURE_ENVELOPE).to_string(),
        EXPECTED_ENVELOPE_SHA256
    );

    let signed = authentic.into_signed();
    assert_eq!(signed.plan_id().to_string(), EXPECTED_PLAN_ID);
    assert_eq!(signed.signature_base64url(), EXPECTED_SIGNATURE);
    assert_eq!(signed.to_canonical_json().unwrap(), FIXTURE_ENVELOPE);
}

#[test]
fn preparation_projection_debug_is_bounded_and_redacted() {
    let authentic = authentic_fixture();
    let debug = format!("{:?}", authentic.preparation_claims());

    assert!(debug.contains("PlanPreparationClaimsV1"));
    for sentinel in [
        "operation:00000000-0000-4000-8000-000000000001",
        "task:fixture-1",
        "workload:agent-vm-1",
        "vault-main",
        "Decision.md",
        "volume:fixture-apfs",
        "file:00000042",
        "text/markdown;charset=utf-8",
        "budget:fixture-1",
        EXPECTED_PLAN_ID,
        EXPECTED_SIGNATURE,
        "9160d4be34c8695bd172a76c7c7966587ea5a4d991ad22c87b2b91af54aa9ebb",
        "7b9a72466d3960eb2aacccfc848939453490db0678bd4725def3f789b891c919",
        "YWZ0ZXIK",
    ] {
        assert!(
            !debug.contains(sentinel),
            "preparation claims leaked {sentinel}"
        );
    }
}
