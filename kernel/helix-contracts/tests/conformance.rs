mod common;

use common::{canonicalize_value, fixed_signer, sample_input, TestResolver, TestSigner};
use helix_contracts::{
    decode_and_verify_plan, sign_plan_v1, ContractError, Ed25519KeyResolver, PlanProtectedV1,
    RecoveryClassV1, Result, RiskLevelV1, Sha256Digest,
};
use serde_json::{json, Value};

const FIXTURE_INPUT: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.json");
const FIXTURE_PROTECTED: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.protected.jcs");
const FIXTURE_ENVELOPE: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.envelope.jcs");
const FIXTURE_PLAN_ID: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.plan-id");
const FIXTURE_PUBLIC_KEY: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.public-key");
const FIXTURE_SIGNATURE: &[u8] =
    include_bytes!("../../../contracts/fixtures/plan-envelope-v1/valid-plan.signature");

#[test]
fn reviewed_golden_fixture_is_exact_and_authentic() {
    for fixture in [
        FIXTURE_INPUT,
        FIXTURE_PROTECTED,
        FIXTURE_ENVELOPE,
        FIXTURE_PLAN_ID,
        FIXTURE_PUBLIC_KEY,
        FIXTURE_SIGNATURE,
    ] {
        assert!(!fixture.starts_with(&[0xef, 0xbb, 0xbf]));
        assert!(!fixture.ends_with(b"\n"));
    }
    let input: Value = serde_json::from_slice(FIXTURE_INPUT).unwrap();
    assert_eq!(input["fixture_format"], "helixos.plan-input-fixture/1");

    let signer = fixed_signer();
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let expected_plan_id = std::str::from_utf8(FIXTURE_PLAN_ID).unwrap();
    assert_eq!(
        signed.protected().canonical_bytes().unwrap(),
        FIXTURE_PROTECTED
    );
    assert_eq!(signed.to_canonical_json().unwrap(), FIXTURE_ENVELOPE);
    assert_eq!(signed.plan_id().to_string(), expected_plan_id);
    assert_eq!(
        Sha256Digest::digest(FIXTURE_PROTECTED).to_string(),
        expected_plan_id
    );
    assert_eq!(signed.signature_base64url().as_bytes(), FIXTURE_SIGNATURE);

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    assert_eq!(
        URL_SAFE_NO_PAD
            .encode(signer.verifying_key_bytes())
            .as_bytes(),
        FIXTURE_PUBLIC_KEY
    );
    let resolver = TestResolver::for_signer(&signer);
    let authentic = decode_and_verify_plan(FIXTURE_ENVELOPE, &resolver).unwrap();
    assert_eq!(authentic.plan_id().to_string(), expected_plan_id);
}

#[test]
fn reusable_negative_manifest_produces_declared_typed_denials() {
    use std::collections::BTreeSet;
    use std::path::{Component, Path};

    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures/plan-envelope-v1");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("negative-cases.json")).expect("negative manifest"),
    )
    .expect("manifest JSON");
    assert_eq!(manifest["schema"], "helixos.negative-contract-corpus/1");
    let cases = manifest["cases"].as_array().expect("manifest cases");
    assert!(cases.len() >= 20);

    let signer = fixed_signer();
    let trusted = TestResolver::for_signer(&signer);
    let wrong_signer = TestSigner::new("core-signing-key:fixture-1", [8_u8; 32]);
    let wrong_key = TestResolver::for_signer(&wrong_signer);
    let mut unknown_key = TestResolver::for_signer(&signer);
    unknown_key.revoked = true;
    let mut ids = BTreeSet::new();
    let mut coverage = BTreeSet::new();

    for case in cases {
        let id = case["id"].as_str().expect("case id");
        assert!(ids.insert(id), "duplicate negative case id: {id}");
        assert_eq!(case["dispatch_reached"], false, "case {id}");
        for tag in case["coverage"].as_array().expect("coverage") {
            coverage.insert(tag.as_str().expect("coverage tag"));
        }

        let wire = if let Some(relative) = case.get("wire").and_then(Value::as_str) {
            let relative_path = Path::new(relative);
            assert!(
                relative_path
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
                "non-portable fixture path: {relative}"
            );
            std::fs::read(root.join(relative_path)).expect("negative wire fixture")
        } else {
            let generated = &case["generator"];
            assert_eq!(generated["kind"], "ascii_repeat");
            let byte = u8::try_from(generated["byte"].as_u64().expect("generator byte"))
                .expect("byte range");
            let count = usize::try_from(generated["count"].as_u64().expect("generator count"))
                .expect("count range");
            vec![byte; count]
        };

        let result = match case["resolver"].as_str().expect("resolver profile") {
            "trusted" => decode_and_verify_plan(&wire, &trusted),
            "wrong_key" => decode_and_verify_plan(&wire, &wrong_key),
            "unknown_key" => decode_and_verify_plan(&wire, &unknown_key),
            profile => panic!("unknown resolver profile: {profile}"),
        };
        let error = result.unwrap_err();
        assert_eq!(
            error.code(),
            case["expected_error"].as_str().expect("error code"),
            "negative case {id}: {error}"
        );
    }

    for required in [
        "ordering",
        "unicode",
        "numeric",
        "resource",
        "version",
        "tampering",
        "key",
        "signature",
        "shape",
        "size",
        "recovery",
    ] {
        assert!(
            coverage.contains(required),
            "missing coverage tag: {required}"
        );
    }
}

#[test]
fn canonical_wire_roundtrips_strictly() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let wire = signed.to_canonical_json().unwrap();
    let authentic = decode_and_verify_plan(&wire, &resolver).unwrap();
    assert_eq!(authentic.plan_id(), signed.plan_id());

    let mut noncanonical = wire.clone();
    noncanonical.push(b'\n');
    assert!(matches!(
        decode_and_verify_plan(&noncanonical, &resolver),
        Err(ContractError::NonCanonicalWire)
    ));
}

#[test]
fn unknown_and_duplicate_fields_are_denied() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let wire = signed.to_canonical_json().unwrap();
    let mut value: Value = serde_json::from_slice(&wire).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), Value::Bool(true));
    let unknown = canonicalize_value(&value);
    assert!(matches!(
        decode_and_verify_plan(&unknown, &resolver),
        Err(ContractError::MalformedJson { .. })
    ));

    let text = String::from_utf8(wire).unwrap();
    let duplicate = format!("{{\"plan_id\":\"{}\",{}", signed.plan_id(), &text[1..]);
    assert!(matches!(
        decode_and_verify_plan(duplicate.as_bytes(), &resolver),
        Err(ContractError::MalformedJson { .. })
    ));
}

#[test]
fn explicit_null_never_aliases_an_omitted_v1_field() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let mut value: Value = serde_json::from_slice(&signed.to_canonical_json().unwrap()).unwrap();
    value["protected"]["intent"]["recovery"]["class"] = json!("irreversible");
    value["protected"]["intent"]["recovery"]["preimage_sha256"] = Value::Null;
    let wire = canonicalize_value(&value);
    assert!(matches!(
        decode_and_verify_plan(&wire, &resolver),
        Err(ContractError::MalformedJson { .. })
    ));
}

#[test]
fn missing_null_and_wrong_type_fields_are_denied() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let original: Value = serde_json::from_slice(&signed.to_canonical_json().unwrap()).unwrap();

    let mut missing = original.clone();
    missing["protected"]
        .as_object_mut()
        .unwrap()
        .remove("task_id");
    assert!(matches!(
        decode_and_verify_plan(&canonicalize_value(&missing), &resolver),
        Err(ContractError::MalformedJson { .. })
    ));

    let mut unexpected_null = original.clone();
    unexpected_null["protected"]["task_id"] = Value::Null;
    assert!(matches!(
        decode_and_verify_plan(&canonicalize_value(&unexpected_null), &resolver),
        Err(ContractError::MalformedJson { .. })
    ));

    let mut wrong_type = original;
    wrong_type["protected"]["issued_at_unix_ms"] = json!("1750000000000");
    assert!(matches!(
        decode_and_verify_plan(&canonicalize_value(&wrong_type), &resolver),
        Err(ContractError::MalformedJson { .. })
    ));
}

#[test]
fn file_patch_risk_cannot_be_downgraded() {
    let mut l0_write = sample_input();
    l0_write.risk_level = RiskLevelV1::L0;
    assert!(matches!(
        PlanProtectedV1::try_new(l0_write, "key:risk-test"),
        Err(ContractError::InvalidField {
            field: "risk_level",
            ..
        })
    ));

    let mut irreversible_l1 = sample_input();
    irreversible_l1.recovery.class = RecoveryClassV1::Irreversible;
    assert!(matches!(
        PlanProtectedV1::try_new(irreversible_l1, "key:risk-test"),
        Err(ContractError::InvalidField {
            field: "risk_level",
            ..
        })
    ));

    let mut irreversible_l2 = sample_input();
    irreversible_l2.recovery.class = RecoveryClassV1::Irreversible;
    irreversible_l2.risk_level = RiskLevelV1::L2;
    assert!(PlanProtectedV1::try_new(irreversible_l2, "key:risk-test").is_ok());
}

#[test]
fn compensation_requires_enough_reserved_preimage_space() {
    let mut insufficient = sample_input();
    insufficient.recovery.reserved_bytes = insufficient.precondition.byte_length - 1;
    assert!(matches!(
        PlanProtectedV1::try_new(insufficient, "key:recovery-test"),
        Err(ContractError::InvalidField {
            field: "intent.recovery",
            ..
        })
    ));
}

#[test]
fn public_debug_output_redacts_plan_content_paths_ids_and_signatures() {
    const MARKER: &str = "SECRET-MARKER";
    let mut input = sample_input();
    input.operation_id = format!("operation:{MARKER}");
    input.task_id = format!("task:{MARKER}");
    input.precondition.file_id = format!("file:{MARKER}");
    input.replacement_bytes = MARKER.as_bytes().to_vec();
    input.target = helix_contracts::ResourceRefV1::new("vault", [MARKER]).unwrap();

    assert!(!format!("{input:?}").contains(MARKER));
    assert!(!format!("{:?}", input.precondition).contains(MARKER));
    assert!(!format!("{:?}", input.budget).contains(MARKER));
    assert!(!format!("{:?}", input.target).contains(MARKER));

    let signer = fixed_signer();
    let signed = sign_plan_v1(input, &signer).unwrap();
    let signature = signed.signature_base64url().to_owned();
    let signed_debug = format!("{signed:?}");
    assert!(!signed_debug.contains(MARKER));
    assert!(!signed_debug.contains(&signature));

    let resolver = TestResolver::for_signer(&signer);
    let wire = signed.to_canonical_json().unwrap();
    let authentic = decode_and_verify_plan(&wire, &resolver).unwrap();
    assert!(!format!("{authentic:?}").contains(MARKER));
}

#[test]
fn unsupported_schema_algorithm_and_intent_are_typed_denials() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();

    for (path, replacement, expected) in [
        (
            &["protected", "schema"][..],
            json!("helixos.plan-envelope/2"),
            "schema",
        ),
        (
            &["protected", "digest_algorithm"][..],
            json!("sha-512"),
            "digest",
        ),
        (
            &["protected", "signature_algorithm"][..],
            json!("ed448"),
            "signature",
        ),
        (
            &["protected", "intent", "kind"][..],
            json!("host.shell"),
            "intent",
        ),
    ] {
        let wire = mutate(&signed, path, replacement);
        let error = decode_and_verify_plan(&wire, &resolver).unwrap_err();
        match expected {
            "schema" => assert!(matches!(error, ContractError::UnsupportedSchema)),
            "digest" => assert!(matches!(
                error,
                ContractError::UnsupportedAlgorithm { kind: "digest" }
            )),
            "signature" => assert!(matches!(
                error,
                ContractError::UnsupportedAlgorithm { kind: "signature" }
            )),
            "intent" => assert!(matches!(error, ContractError::UnsupportedIntent)),
            _ => unreachable!(),
        }
    }
}

#[test]
fn digest_signature_and_effect_tampering_are_denied() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();

    let wrong_id = mutate(&signed, &["plan_id"], json!("00".repeat(32)));
    assert!(matches!(
        decode_and_verify_plan(&wrong_id, &resolver),
        Err(ContractError::PlanIdMismatch)
    ));

    let wrong_signature = mutate(&signed, &["signature"], json!("A".repeat(86)));
    assert!(matches!(
        decode_and_verify_plan(&wrong_signature, &resolver),
        Err(ContractError::SignatureInvalid | ContractError::InvalidEncoding { .. })
    ));

    let changed_effect = mutate(
        &signed,
        &["protected", "intent", "replacement", "content_base64url"],
        json!("eA"),
    );
    assert!(matches!(
        decode_and_verify_plan(&changed_effect, &resolver),
        Err(ContractError::InvalidField { .. })
    ));
}

#[derive(Clone, Debug)]
enum JsonPathSegment {
    Key(String),
    Index(usize),
}

#[test]
fn every_protected_leaf_changes_identity_and_denies_the_original_signature() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let mut envelope: Value = serde_json::from_slice(&signed.to_canonical_json().unwrap()).unwrap();
    let protected = envelope["protected"].clone();
    let mut paths = Vec::new();
    collect_leaf_paths(&protected, &mut Vec::new(), &mut paths);
    assert!(
        paths.len() >= 40,
        "fixture unexpectedly lost protected leaves"
    );

    for path in paths {
        let mut changed = protected.clone();
        mutate_leaf(&mut changed, &path);
        let changed_jcs = canonicalize_value(&changed);
        let changed_id = Sha256Digest::digest(&changed_jcs);
        assert_ne!(
            changed_id,
            signed.plan_id(),
            "leaf mutation did not change identity: {path:?}"
        );

        envelope["protected"] = changed;
        envelope["plan_id"] = json!(changed_id.to_string());
        let wire = canonicalize_value(&envelope);
        assert!(
            decode_and_verify_plan(&wire, &resolver).is_err(),
            "original signature survived protected mutation: {path:?}"
        );
        envelope["protected"] = protected.clone();
    }
}

#[test]
fn numeric_alternate_forms_and_oversized_wire_are_denied() {
    let signer = fixed_signer();
    let resolver = TestResolver::for_signer(&signer);
    let signed = sign_plan_v1(sample_input(), &signer).unwrap();
    let text = String::from_utf8(signed.to_canonical_json().unwrap()).unwrap();

    let float = text.replace(
        "\"issued_at_unix_ms\":1750000000000",
        "\"issued_at_unix_ms\":1.0",
    );
    assert!(matches!(
        decode_and_verify_plan(float.as_bytes(), &resolver),
        Err(ContractError::MalformedJson { .. })
    ));

    let negative_zero = text.replace("\"instance_epoch\":1", "\"instance_epoch\":-0");
    assert!(matches!(
        decode_and_verify_plan(negative_zero.as_bytes(), &resolver),
        Err(ContractError::MalformedJson { .. }) | Err(ContractError::NonCanonicalWire)
    ));

    let oversized = vec![b' '; 1_048_577];
    assert!(matches!(
        decode_and_verify_plan(&oversized, &resolver),
        Err(ContractError::WireTooLarge { .. })
    ));
}

#[test]
fn unknown_key_is_denied_before_signature_trust() {
    #[derive(Debug)]
    struct EmptyResolver;
    impl Ed25519KeyResolver for EmptyResolver {
        fn resolve_ed25519(&self, _key_id: &str) -> Result<[u8; 32]> {
            Err(ContractError::UnknownKey)
        }
    }

    let signer = fixed_signer();
    let wire = sign_plan_v1(sample_input(), &signer)
        .unwrap()
        .to_canonical_json()
        .unwrap();
    assert!(matches!(
        decode_and_verify_plan(&wire, &EmptyResolver),
        Err(ContractError::UnknownKey)
    ));
}

fn mutate(
    signed: &helix_contracts::SignedPlanEnvelopeV1,
    path: &[&str],
    replacement: Value,
) -> Vec<u8> {
    let wire = signed.to_canonical_json().unwrap();
    let mut value: Value = serde_json::from_slice(&wire).unwrap();
    let mut cursor = &mut value;
    for segment in &path[..path.len() - 1] {
        cursor = cursor.get_mut(*segment).expect("test path");
    }
    cursor
        .as_object_mut()
        .expect("object")
        .insert(path[path.len() - 1].to_owned(), replacement);
    canonicalize_value(&value)
}

fn collect_leaf_paths(
    value: &Value,
    prefix: &mut Vec<JsonPathSegment>,
    output: &mut Vec<Vec<JsonPathSegment>>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                prefix.push(JsonPathSegment::Key(key.clone()));
                collect_leaf_paths(child, prefix, output);
                prefix.pop();
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                prefix.push(JsonPathSegment::Index(index));
                collect_leaf_paths(child, prefix, output);
                prefix.pop();
            }
        }
        _ => output.push(prefix.clone()),
    }
}

fn mutate_leaf(value: &mut Value, path: &[JsonPathSegment]) {
    let mut cursor = value;
    for segment in path {
        cursor = match segment {
            JsonPathSegment::Key(key) => cursor.get_mut(key).expect("fixture key"),
            JsonPathSegment::Index(index) => cursor.get_mut(*index).expect("fixture index"),
        };
    }
    match cursor {
        Value::String(text) => text.push('~'),
        Value::Number(number) => {
            *number = serde_json::Number::from(number.as_u64().expect("unsigned fixture") + 1);
        }
        Value::Bool(boolean) => *boolean = !*boolean,
        Value::Null => *cursor = json!("was-null"),
        Value::Array(_) | Value::Object(_) => unreachable!("path must end at a leaf"),
    }
}
