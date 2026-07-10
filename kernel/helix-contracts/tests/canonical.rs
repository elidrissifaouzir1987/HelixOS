use helix_contracts::{ContractError, Identifier, Nonce128, SafeU64, Sha256Digest, MAX_SAFE_U64};

#[test]
fn sha256_known_vector_and_strict_hex() {
    let digest = Sha256Digest::digest(b"abc");
    assert_eq!(
        digest.to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(Sha256Digest::parse_hex(&digest.to_hex()).unwrap(), digest);
    assert!(Sha256Digest::parse_hex(&digest.to_hex().to_uppercase()).is_err());
    assert!(Sha256Digest::parse_hex("00").is_err());
}

#[test]
fn safe_integer_enforces_ijson_bound_and_rejects_float_forms() {
    let maximum = SafeU64::new(MAX_SAFE_U64).unwrap();
    assert_eq!(maximum.get(), MAX_SAFE_U64);
    assert!(SafeU64::new(MAX_SAFE_U64 + 1).is_err());
    assert!(serde_json::from_str::<SafeU64>("1.0").is_err());
    assert!(serde_json::from_str::<SafeU64>("1e0").is_err());
    assert!(serde_json::from_str::<SafeU64>("-1").is_err());
}

#[test]
fn identifiers_and_nonces_are_closed_and_canonical() {
    let identifier = Identifier::new("task:abc-123", 32).unwrap();
    assert!(!format!("{identifier:?}").contains("task:abc-123"));
    assert!(Identifier::new("", 32).is_err());
    assert!(Identifier::new("contains space", 32).is_err());
    assert!(Identifier::new("x".repeat(33), 32).is_err());

    let nonce = Nonce128::from_bytes([0xab; 16]);
    assert_eq!(nonce.to_hex(), "abababababababababababababababab");
    assert!(!format!("{nonce:?}").contains(&nonce.to_hex()));
    assert!(Nonce128::parse_hex(&nonce.to_hex()).is_ok());
    assert!(Nonce128::parse_hex("ABABABABABABABABABABABABABABABAB").is_err());
}

#[test]
fn public_errors_do_not_echo_untrusted_json() {
    let marker = "SECRET-MARKER";
    let error =
        serde_json::from_str::<Sha256Digest>(&format!("\"{marker}\"")).expect_err("invalid digest");
    let public = ContractError::from(error);
    assert!(!public.to_string().contains(marker));
    assert!(!format!("{public:?}").contains(marker));
    assert!(std::error::Error::source(&public).is_none());
}

#[test]
fn source_member_order_does_not_change_jcs() {
    let first: serde_json::Value =
        serde_json::from_str(r#"{"z":0,"nested":{"b":"two","a":"one"},"a":1}"#).unwrap();
    let second: serde_json::Value =
        serde_json::from_str(r#"{"a":1,"nested":{"a":"one","b":"two"},"z":0}"#).unwrap();
    assert_eq!(
        serde_json_canonicalizer::to_vec(&first).unwrap(),
        serde_json_canonicalizer::to_vec(&second).unwrap()
    );
}
