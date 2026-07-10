mod common;

use common::{fixed_signer, sample_input, TestResolver};
use helix_contracts::{decode_and_verify_plan, sign_plan_v1};

#[test]
#[ignore = "deterministic 100,000-envelope release soak"]
fn one_hundred_thousand_envelopes_sign_and_verify() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    for index in 0_u64..100_000 {
        let mut input = sample_input();
        input.operation_id = format!("operation:soak-{index:06}");
        input.replacement_bytes = index.to_le_bytes().to_vec();
        let signed = sign_plan_v1(input, &signer).expect("sign");
        let wire = signed.to_canonical_json().expect("canonical wire");
        let authentic = decode_and_verify_plan(&wire, &resolver).expect("verify");
        assert_eq!(authentic.plan_id(), signed.plan_id());
    }
}
