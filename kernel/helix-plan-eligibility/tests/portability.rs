const CONTEXT: &str = include_str!("../src/context.rs");
const DENIAL: &str = include_str!("../src/denial.rs");
const EVALUATOR: &str = include_str!("../src/evaluator.rs");
const MARKER: &str = include_str!("../src/marker.rs");
const REPLAY: &str = include_str!("../src/replay.rs");
const LIB: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");
const TEST_CLAIMANT: &str = include_str!("../test-support/replay_claimant.rs");

#[test]
fn production_foundation_has_no_native_or_ambient_api() {
    let source = [CONTEXT, DENIAL, EVALUATOR, MARKER, REPLAY, LIB].join("\n");
    let forbidden = [
        "use std::fs",
        "std::fs::",
        "use std::net",
        "std::net::",
        "std::os::",
        "std::path::",
        "std::process::",
        "std::thread::",
        "std::time::Instant",
        "std::time::SystemTime",
        "std::env::",
        "cfg(target_os",
        "cfg!(target_os",
        "cfg(target_arch",
        "cfg!(target_arch",
        "RawFd",
        "OwnedFd",
        "RawHandle",
        "OwnedHandle",
        "RawSocket",
        "OwnedSocket",
        "libc::",
        "windows_sys::",
        "core_foundation::",
        "serde::",
        "HashMap",
        "BTreeMap",
        "f32",
        "f64",
    ];
    for token in forbidden {
        assert!(
            !source.contains(token),
            "production source contains forbidden token {token}"
        );
    }
    assert!(LIB.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn only_the_reviewed_replay_adapter_depends_on_the_eligibility_contract() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("eligibility crate is directly below the kernel workspace");
    let mut reviewed_consumers = 0_u8;

    for entry in std::fs::read_dir(workspace).expect("kernel workspace is readable") {
        let entry = entry.expect("workspace directory entry is readable");
        if !entry.file_type().expect("entry type is readable").is_dir()
            || entry.path() == std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        {
            continue;
        }
        let manifest = entry.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let contents = std::fs::read_to_string(&manifest).expect("package manifest is UTF-8");
        if contents.contains("helix-plan-eligibility") {
            assert_eq!(
                entry.file_name(),
                "helix-replay-sqlite",
                "unreviewed workspace dependency found in {}",
                manifest.display()
            );
            reviewed_consumers += 1;
        }
    }
    assert_eq!(reviewed_consumers, 1);
}

#[test]
fn replay_contract_has_no_release_reset_or_idempotent_success_surface() {
    let public_surface = [REPLAY, TEST_CLAIMANT].join("\n");
    for forbidden in [
        "pub fn release",
        "pub fn reset",
        "pub fn unclaim",
        "pub fn reuse",
        "pub fn get_or_claim",
        "pub fn claim_or_get",
    ] {
        assert!(
            !public_surface.contains(forbidden),
            "replay surface contains forbidden API {forbidden}"
        );
    }

    let trait_body = REPLAY
        .split_once("pub trait ReplayClaimantV1")
        .expect("replay claimant trait exists")
        .1
        .split_once('}')
        .expect("replay claimant trait is closed")
        .0;
    assert_eq!(trait_body.matches("fn ").count(), 1);
    assert!(trait_body.contains("fn claim_once"));
}

#[test]
fn markers_are_not_cloneable_or_serializable_by_derive() {
    let production = MARKER
        .split_once("#[cfg(test)]")
        .map_or(MARKER, |parts| parts.0);
    assert_no_derive_before(production, "pub struct EligiblePlanV1", "Clone");
    assert_no_derive_before(production, "pub struct EligiblePlanV1", "Serialize");
    assert_no_derive_before(production, "pub struct EligibilityFailureV1", "Clone");
    assert_no_derive_before(production, "pub struct EligibilityFailureV1", "Serialize");
    assert!(!production.contains("impl Clone for EligiblePlanV1"));
    assert!(!production.contains("impl Clone for EligibilityFailureV1"));
    assert!(!production.contains(".to_owned()"));
    assert!(!production.contains("Box<"));
    assert!(!production.contains(".expect("));
    assert!(production.contains("capability_observed_at_unix_ms"));
    assert!(production.contains("capability_max_age_ms"));
    assert!(production.contains("policy_decision_generation"));
    assert!(production.contains("catalogue_decision_generation"));
}

#[test]
fn production_dependency_section_contains_only_contracts() {
    let dependencies = MANIFEST
        .split_once("[dependencies]")
        .expect("dependencies section")
        .1
        .split_once("[dev-dependencies]")
        .expect("dev dependencies section")
        .0;
    let entries = dependencies
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].starts_with("helix-contracts ="));
}

fn assert_no_derive_before(source: &str, declaration: &str, forbidden: &str) {
    let before = source
        .split_once(declaration)
        .unwrap_or_else(|| panic!("missing declaration {declaration}"))
        .0;
    let attribute = before
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    assert!(
        !(attribute.contains("derive") && attribute.contains(forbidden)),
        "{declaration} derives forbidden trait {forbidden}"
    );
}
