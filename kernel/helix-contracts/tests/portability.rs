#[test]
fn sovereign_contract_source_contains_no_native_or_unsafe_primitives() {
    let sources = [
        include_str!("../src/lib.rs"),
        include_str!("../src/canonical.rs"),
        include_str!("../src/crypto.rs"),
        include_str!("../src/digest.rs"),
        include_str!("../src/error.rs"),
        include_str!("../src/plan.rs"),
        include_str!("../src/resource.rs"),
        include_str!("../src/validation.rs"),
    ];
    let forbidden = [
        "std::path",
        "PathBuf",
        "OsStr",
        "cfg(target_os",
        "SystemTime",
        "rand::",
        "unsafe {",
        "unsafe fn",
        "f32",
        "f64",
    ];
    for token in forbidden {
        assert!(
            sources.iter().all(|source| !source.contains(token)),
            "forbidden contract primitive found: {token}"
        );
    }
}
