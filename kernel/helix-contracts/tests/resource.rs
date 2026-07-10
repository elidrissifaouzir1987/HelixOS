use helix_contracts::ResourceRefV1;

#[test]
fn valid_resource_has_one_portable_uri_spelling() {
    let resource = ResourceRefV1::new("vault-main", ["Projects", "Café notes", "😀.md"]).unwrap();
    assert_eq!(
        resource.canonical_uri(),
        "helixfs://vault-main/Projects/Caf%C3%A9%20notes/%F0%9F%98%80.md"
    );
}

#[test]
fn rejects_traversal_separators_ads_controls_and_non_nfc() {
    let invalid = [
        ".",
        "..",
        "a/b",
        "a\\b",
        "C:",
        "note.md:secret",
        "trailing.",
        "trailing ",
        "bad\0name",
        "bad\u{061c}name",
        "bad\u{200e}name",
        "bad\u{200f}name",
        "bad\u{202e}name",
        "zero\u{200b}width",
        "soft\u{00ad}hyphen",
        "variation\u{fe0f}",
        "tag\u{e0061}",
        "e\u{301}",
    ];
    for component in invalid {
        assert!(
            ResourceRefV1::new("vault-main", [component]).is_err(),
            "accepted {component:?}"
        );
    }
}

#[test]
fn rejects_windows_devices_case_insensitively() {
    for component in [
        "CON",
        "nul.txt",
        "Com1.log",
        "LPT9",
        "aux.md",
        "prn",
        "COM¹",
        "com².txt",
        "LPT³",
        "CONIN$",
        "conout$.txt",
        "CLOCK$",
    ] {
        assert!(ResourceRefV1::new("vault-main", [component]).is_err());
    }
    assert!(ResourceRefV1::new("vault-main", ["console.md"]).is_ok());
    assert!(ResourceRefV1::new("vault-main", ["COM10.txt"]).is_ok());
}

#[test]
fn root_and_component_limits_are_enforced() {
    assert!(ResourceRefV1::new("Vault", ["ok"]).is_err());
    assert!(ResourceRefV1::new("-vault", ["ok"]).is_err());
    assert!(ResourceRefV1::new("v".repeat(65), ["ok"]).is_err());
    assert!(ResourceRefV1::new("vault", ["x".repeat(256)]).is_err());
    assert!(ResourceRefV1::new("vault", std::iter::repeat_n("x", 129)).is_err());
}

#[test]
fn deserialization_denies_unknown_fields_and_invalid_components() {
    let unknown = r#"{"root_id":"vault","components":["a"],"extra":true}"#;
    assert!(serde_json::from_str::<ResourceRefV1>(unknown).is_err());
    let invalid = r#"{"root_id":"vault","components":[".."]}"#;
    assert!(serde_json::from_str::<ResourceRefV1>(invalid).is_err());
}
