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
fn only_reviewed_consumers_depend_on_the_eligibility_contract() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("eligibility crate is directly below the kernel workspace");
    let mut reviewed_consumers = Vec::new();

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
            reviewed_consumers.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    reviewed_consumers.sort();
    assert_eq!(
        reviewed_consumers,
        vec![
            "helix-plan-preparation".to_owned(),
            "helix-replay-sqlite".to_owned(),
            "helix-task-authority-projections".to_owned(),
        ],
        "only the reviewed replay, preparation and signed-authority projection leaves may depend on eligibility"
    );
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
fn exact_replay_verification_is_read_only_opaque_and_separate_from_claiming() {
    let view_surface = REPLAY
        .split_once("pub struct ReplayClaimVerificationViewV1")
        .expect("verification view exists")
        .1
        .split_once("pub enum ReplayClaimVerificationV1")
        .expect("closed verification outcome follows the view")
        .0;
    assert!(view_surface.contains("pub(crate) fn new"));
    assert!(!view_surface.contains("pub fn new"));
    assert!(!view_surface.contains("ReplayBindingV1"));

    let verifier_body = REPLAY
        .split_once("pub trait ReplayClaimVerifierV1")
        .expect("read-only verifier trait exists")
        .1
        .split_once('}')
        .expect("read-only verifier trait is closed")
        .0;
    assert_eq!(verifier_body.matches("fn ").count(), 1);
    assert!(verifier_body.contains("fn verify_exact_claim"));
    for forbidden in ["claim_once", "&mut self", "release", "reset", "unclaim"] {
        assert!(
            !verifier_body.contains(forbidden),
            "verification trait contains forbidden surface {forbidden}"
        );
    }

    let factory = MARKER
        .split_once("pub fn replay_verification_view")
        .expect("eligible marker owns the verification-view factory")
        .1
        .split_once("\n    }")
        .expect("verification-view factory is closed")
        .0;
    assert!(!factory.contains("ReplayBindingV1"));
    assert_eq!(MARKER.matches("pub fn replay_verification_view").count(), 1);

    for variant in ["Exact", "Missing", "Conflict", "Unavailable", "Unhealthy"] {
        assert!(REPLAY.contains(&format!("    {variant},")));
    }
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
