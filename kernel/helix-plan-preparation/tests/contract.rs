const ATTEMPT: &str = include_str!("../src/attempt.rs");
const BUDGET: &str = include_str!("../src/budget.rs");
const COMMIT_GATE: &str = include_str!("../src/commit_gate.rs");
const CONTEXT: &str = include_str!("../src/context.rs");
const GUARD: &str = include_str!("../src/guard.rs");
const LIB: &str = include_str!("../src/lib.rs");
const OUTCOME: &str = include_str!("../src/outcome.rs");
const RECOVERY: &str = include_str!("../src/recovery.rs");
const STORE: &str = include_str!("../src/store.rs");

use helix_contracts::MAX_SAFE_U64;
use helix_plan_preparation::{
    AmbiguousPreparationV1, BudgetVectorBuildErrorV1, BudgetVectorInputV1, BudgetVectorV1,
    PreparationDenialV1, PreparationFailureV1,
};
use std::collections::BTreeSet;
use std::error::Error as _;
use std::path::Path;

#[test]
fn attempt_identity_is_checked_domain_separated_and_opaque() {
    assert!(ATTEMPT.contains("pub struct PreparationAttemptIdV1"));
    assert!(ATTEMPT.contains("const ATTEMPT_ID_DOMAIN"));
    assert!(ATTEMPT.contains("getrandom::fill"));
    assert!(ATTEMPT.contains("Sha256Digest::digest"));
    assert!(ATTEMPT.contains("pub(crate) fn generate"));
    assert!(!ATTEMPT.contains("pub fn from_bytes"));
    assert_no_derive_before(ATTEMPT, "pub struct PreparationAttemptIdV1", "Clone");
    assert_no_derive_before(ATTEMPT, "pub struct PreparationAttemptIdV1", "Serialize");
}

#[test]
fn contexts_are_closed_complete_and_use_only_injected_time() {
    for variant in ["Ready", "Unavailable", "Incomplete", "Torn", "Unsupported"] {
        assert!(CONTEXT.contains(&format!("    {variant}")));
    }
    for phase in ["Preliminary", "Final"] {
        assert!(CONTEXT.contains(&format!("    {phase},")));
    }
    for field in [
        "context_version",
        "plan_id",
        "operation_id",
        "task_id",
        "workload_id",
        "attempt_id",
        "capture_generation",
        "clock_generation",
        "plan_deadline_generation",
        "sampled_utc_ms",
        "sampled_monotonic_ms",
        "effective_expires_at_utc_ms",
        "effective_deadline_monotonic_ms",
        "supervisor_generation",
        "boot_id",
        "instance_epoch",
        "fencing_epoch",
        "trust_generation",
        "verified_key_fingerprint",
        "workload_generation",
        "workload_evidence_digest",
        "lease_generation",
        "lease_digest",
        "lease_decision_digest",
        "authorization_generation",
        "authorization_evidence_digest",
        "policy_generation",
        "policy_decision_generation",
        "policy_content_digest",
        "policy_decision_digest",
        "catalogue_generation",
        "catalogue_decision_generation",
        "catalogue_content_digest",
        "catalogue_decision_digest",
        "capability_report_generation",
        "capability_report_digest",
        "host_driver_context_digest",
        "capability_observed_at_utc_ms",
        "capability_max_age_ms",
        "replay_claim_id",
        "replay_claimant_generation",
        "replay_binding_digest",
        "budget_scope_binding_digest",
        "budget_scope_generation",
        "currency_code",
        "price_table_id",
        "requested_budget",
        "recovery_provider",
    ] {
        assert!(CONTEXT.contains(field), "missing context field {field}");
    }
    assert!(CONTEXT.contains("pub trait PreparationUtcClockV1"));
    assert!(CONTEXT.contains("pub trait PreparationMonotonicClockV1"));
    assert!(CONTEXT.contains("pub struct ReadyPreparationContextInputV1"));
    assert!(CONTEXT.contains("pub struct ReadyPreparationContextV1"));
    assert_no_derive_before(CONTEXT, "pub struct ReadyPreparationContextV1", "Serialize");
    assert_no_derive_before(CONTEXT, "pub struct ReadyPreparationContextV1", "Clone");
    assert_no_ambient_runtime(&production_lines(CONTEXT));
}

#[test]
fn authority_guards_permits_and_no_dispatch_custody_are_injected_and_opaque() {
    for contract in [
        "pub trait PreparationAuthoritySourceV1",
        "pub trait AuthorityGuardV1",
        "pub trait AuthorityGuardSetV1",
        "pub enum AuthorityGuardAcquisitionV1",
        "pub trait NoDispatchAuthoritySourceV1",
        "pub trait NoDispatchAuthorityGuardV1",
        "pub struct NoDispatchAuthorityBindingV1",
    ] {
        assert!(
            GUARD.contains(contract),
            "missing guard contract {contract}"
        );
    }
    for contract in [
        "pub const FINAL_COMMIT_PERMIT_CEILING_MS: u64 = 250",
        "pub trait FinalCommitGateV1",
        "pub trait FinalCommitPermitV1",
        "pub trait FinalCommitInFlightV1",
        "pub enum FinalCommitPermitOutcomeV1",
        "pub enum FinalCommitStoreClassificationV1",
        "pub enum FinalCommitResolutionV1",
    ] {
        assert!(
            COMMIT_GATE.contains(contract),
            "missing commit-gate contract {contract}"
        );
    }
    assert!(COMMIT_GATE.contains("now_monotonic_ms < self.permit_deadline_monotonic_ms"));
    assert_no_derive_before(GUARD, "pub struct RecoveryPublicationGuardSlotV1", "Clone");
    assert_no_derive_before(GUARD, "pub struct NoDispatchAuthorityBindingV1", "Clone");
    assert!(!production_lines(COMMIT_GATE).contains("derive(Clone"));
    assert_no_ambient_runtime(&production_lines(GUARD));
    assert_no_ambient_runtime(&production_lines(COMMIT_GATE));
}

#[test]
fn portable_foundation_has_no_adapter_or_native_dependency_surface() {
    let production = production_source_tree();
    for forbidden in [
        "ExecutionGrant",
        "helixos_kernel",
        "helixos_mcp",
        "rusqlite",
        "std::fs",
        "std::net",
        "std::path",
        "std::process",
        "std::thread",
        "serde::",
        "tokio",
    ] {
        assert!(
            !production.contains(forbidden),
            "portable production source contains forbidden token {forbidden}"
        );
    }
}

#[test]
fn only_the_reviewed_sqlite_coordinator_depends_on_preparation() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("preparation crate is directly below the kernel workspace");
    let mut preparation_consumers = Vec::new();
    let mut coordinator_consumers = Vec::new();
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
        let package_name = entry.file_name().to_string_lossy().into_owned();
        if contents.contains("helix-plan-preparation") {
            preparation_consumers.push(package_name.clone());
        }
        if package_name != "helix-coordinator-sqlite"
            && contents.contains("helix-coordinator-sqlite")
        {
            coordinator_consumers.push(package_name);
        }
    }
    preparation_consumers.sort();
    coordinator_consumers.sort();
    assert_eq!(
        preparation_consumers,
        vec![
            "helix-coordinator-sqlite".to_owned(),
            "helix-task-authority-projections".to_owned(),
        ],
        "only the reviewed coordinator and signed-authority projection leaves may reach preparation"
    );
    assert!(
        coordinator_consumers.is_empty(),
        "no legacy, MCP, dispatch, grant or effect-adapter crate may consume coordinator state"
    );
}

#[test]
fn t019_provider_and_store_surfaces_remain_a_separate_required_contract() {
    assert!(BUDGET.contains("pub struct BudgetVectorV1"));
    assert!(RECOVERY.contains("pub trait RecoveryProviderV1"));
    assert!(STORE.contains("pub trait PreparationStoreV1"));
}

#[test]
fn budget_vector_is_exact_checked_four_dimensional_and_redacted() {
    let vector = BudgetVectorV1::try_new(BudgetVectorInputV1 {
        max_cost_micro_units: MAX_SAFE_U64,
        action_limit: 2,
        egress_bytes_limit: 3,
        recovery_bytes: 4,
    })
    .expect("all four safe dimensions construct");
    assert_eq!(vector.max_cost_micro_units(), MAX_SAFE_U64);
    assert_eq!(vector.action_limit(), 2);
    assert_eq!(vector.egress_bytes_limit(), 3);
    assert_eq!(vector.recovery_bytes(), 4);
    assert_eq!(format!("{vector:?}"), "BudgetVectorV1 { .. }");

    let error = BudgetVectorV1::try_new(BudgetVectorInputV1 {
        max_cost_micro_units: MAX_SAFE_U64 + 1,
        action_limit: 0,
        egress_bytes_limit: 0,
        recovery_bytes: 0,
    })
    .expect_err("unsafe integer is rejected");
    assert_eq!(error, BudgetVectorBuildErrorV1::IntegerOutOfRange);
}

#[test]
fn provider_store_and_receipt_contracts_are_closed_borrowed_and_non_authoritative() {
    let provider = RECOVERY
        .split_once("pub trait RecoveryProviderV1")
        .expect("recovery provider trait exists")
        .1
        .split_once("\n}")
        .expect("recovery provider trait is closed")
        .0;
    assert_eq!(provider.matches("fn ").count(), 3);
    for method in [
        "acquire_publication_guard",
        "prepare_and_publish",
        "verify_published",
    ] {
        assert!(provider.contains(method));
    }

    let store = STORE
        .split_once("pub trait PreparationStoreV1")
        .expect("preparation store trait exists")
        .1
        .split_once("\n}")
        .expect("preparation store trait is closed")
        .0;
    assert_eq!(store.matches("fn ").count(), 4);
    for method in [
        "preflight_operation_and_budget",
        "commit_preparing",
        "readback_attempt",
        "fail_before_dispatch",
    ] {
        assert!(store.contains(method));
    }

    for (source, declaration) in [
        (RECOVERY, "pub struct RecoveryMaterialReceiptV1"),
        (STORE, "pub struct BudgetPreflightV1"),
        (STORE, "pub struct PreparationCommitReceiptV1"),
    ] {
        assert_no_derive_before(source, declaration, "Clone");
        assert_no_derive_before(source, declaration, "Serialize");
    }
}

#[test]
fn t020_owns_closed_outcomes_exclusive_codes_and_public_exports() {
    for contract in [
        "pub enum PreparationDenialV1",
        "pub enum PreparationFailureV1",
        "pub enum AmbiguousPreparationV1",
        "pub struct PreparedOperationV1",
        "pub enum PreparationOutcomeV1",
    ] {
        assert!(
            OUTCOME.contains(contract),
            "missing outcome contract {contract}"
        );
    }
    for code in [
        "PREPARATION_CONTEXT_UNAVAILABLE",
        "PREPARATION_RECOVERY_UNAVAILABLE",
        "PREPARATION_STORE_UNAVAILABLE",
        "PREPARATION_AMBIGUOUS",
    ] {
        assert_eq!(
            OUTCOME.matches(code).count(),
            1,
            "code {code} is not exclusive"
        );
    }
    assert!(LIB.contains("pub use outcome"));
    assert_no_derive_before(OUTCOME, "pub struct PreparedOperationV1", "Clone");
    assert_no_derive_before(OUTCOME, "pub struct PreparedOperationV1", "Serialize");
    let marker_surface = OUTCOME
        .split_once("pub struct PreparedOperationV1")
        .expect("prepared marker exists")
        .1
        .split_once("pub enum PreparationOutcomeV1")
        .expect("outcome follows marker")
        .0;
    let marker_fields = marker_surface
        .split_once('{')
        .expect("prepared marker fields begin")
        .1
        .split_once('}')
        .expect("prepared marker fields end")
        .0;
    assert!(marker_fields
        .lines()
        .all(|line| !line.trim_start().starts_with("pub ")));
    assert!(marker_surface.contains("pub(crate) const fn new"));
    assert!(marker_surface.lines().all(|line| {
        let line = line.trim_start();
        !line.starts_with("pub fn ")
            && !line.starts_with("pub const fn ")
            && !line.starts_with("pub async fn ")
    }));
    let mut marker_occurrences = rust_source_tree()
        .into_iter()
        .flat_map(|(path, source)| {
            source
                .lines()
                .filter_map(move |line| {
                    let line = line.trim();
                    (!line.starts_with("//") && line.contains("PreparedOperationV1"))
                        .then(|| (path.clone(), line.to_owned()))
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    marker_occurrences.sort();
    assert_eq!(
        marker_occurrences,
        vec![
            (
                "coordinator.rs".to_owned(),
                "PreparationOutcomeV1::Prepared(PreparedOperationV1::new(eligible, receipt))"
                    .to_owned(),
            ),
            (
                "coordinator.rs".to_owned(),
                "PreparedOperationV1,".to_owned(),
            ),
            (
                "outcome.rs".to_owned(),
                ".debug_struct(\"PreparedOperationV1\")".to_owned(),
            ),
            (
                "outcome.rs".to_owned(),
                "Prepared(PreparedOperationV1),".to_owned(),
            ),
            (
                "outcome.rs".to_owned(),
                "impl PreparedOperationV1 {".to_owned(),
            ),
            (
                "outcome.rs".to_owned(),
                "impl fmt::Debug for PreparedOperationV1 {".to_owned(),
            ),
            (
                "outcome.rs".to_owned(),
                "pub struct PreparedOperationV1 {".to_owned(),
            ),
        ],
        "every production occurrence of the one-shot marker is reviewed"
    );
    assert!(OUTCOME.matches("```compile_fail").count() >= 6);
}

#[test]
fn outcome_families_are_closed_code_exclusive_and_redacted() {
    assert_eq!(PreparationDenialV1::ALL.len(), 36);
    assert_eq!(PreparationFailureV1::ALL.len(), 7);
    assert_eq!(AmbiguousPreparationV1::ALL.len(), 7);

    let denial_codes = PreparationDenialV1::ALL
        .iter()
        .map(|value| value.code())
        .collect::<BTreeSet<_>>();
    let failure_codes = PreparationFailureV1::ALL
        .iter()
        .map(|value| value.code())
        .collect::<BTreeSet<_>>();
    let ambiguous_codes = AmbiguousPreparationV1::ALL
        .iter()
        .map(|value| value.code())
        .collect::<BTreeSet<_>>();
    assert_eq!(denial_codes.len(), PreparationDenialV1::ALL.len());
    assert_eq!(failure_codes.len(), PreparationFailureV1::ALL.len());
    assert!(denial_codes.is_disjoint(&failure_codes));
    assert_eq!(ambiguous_codes, BTreeSet::from(["PREPARATION_AMBIGUOUS"]));
    assert!(denial_codes.is_disjoint(&ambiguous_codes));
    assert!(failure_codes.is_disjoint(&ambiguous_codes));

    assert_eq!(
        PreparationDenialV1::ContextUnavailable.code(),
        "PREPARATION_CONTEXT_UNAVAILABLE"
    );
    assert_eq!(
        PreparationFailureV1::RecoveryProviderFailed.code(),
        "PREPARATION_RECOVERY_UNAVAILABLE"
    );
    assert_eq!(
        format!("{:?}", AmbiguousPreparationV1::ReadbackInconsistent),
        "PREPARATION_AMBIGUOUS"
    );

    for &value in PreparationDenialV1::ALL {
        assert_eq!(format!("{value:?}"), value.code());
        assert_eq!(value.to_string(), "plan preparation was denied");
        assert!(value.source().is_none());
        assert_eq!(
            format!(
                "{:?}",
                helix_plan_preparation::PreparationOutcomeV1::Denied(value)
            ),
            format!("PreparationOutcomeV1::Denied({})", value.code())
        );
    }
    for &value in PreparationFailureV1::ALL {
        assert_eq!(format!("{value:?}"), value.code());
        assert_eq!(value.to_string(), "plan preparation failed");
        assert!(value.source().is_none());
        assert_eq!(
            format!(
                "{:?}",
                helix_plan_preparation::PreparationOutcomeV1::Failed(value)
            ),
            format!("PreparationOutcomeV1::Failed({})", value.code())
        );
    }
    for &value in AmbiguousPreparationV1::ALL {
        assert_eq!(format!("{value:?}"), "PREPARATION_AMBIGUOUS");
        assert_eq!(value.to_string(), "plan preparation is ambiguous");
        assert!(value.source().is_none());
        assert_eq!(
            format!(
                "{:?}",
                helix_plan_preparation::PreparationOutcomeV1::Ambiguous(value)
            ),
            "PreparationOutcomeV1::Ambiguous(PREPARATION_AMBIGUOUS)"
        );
    }
}

fn rust_source_tree() -> Vec<(String, String)> {
    fn visit(root: &Path, directory: &Path, sources: &mut Vec<(String, String)>) {
        let mut entries = std::fs::read_dir(directory)
            .expect("source directory is readable")
            .map(|entry| entry.expect("source entry is readable").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(root, &path, sources);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let relative = path
                    .strip_prefix(root)
                    .expect("source remains below root")
                    .to_string_lossy()
                    .into_owned();
                let source = std::fs::read_to_string(&path).expect("Rust source is UTF-8");
                sources.push((relative, source));
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    visit(&root, &root, &mut sources);
    sources
}

fn production_source_tree() -> String {
    rust_source_tree()
        .into_iter()
        .map(|(_, source)| production_lines(&source))
        .collect::<Vec<_>>()
        .join("\n")
}

fn production_lines(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_no_ambient_runtime(source: &str) {
    for forbidden in [
        "std::time::Instant",
        "std::time::SystemTime",
        "std::thread",
        "std::env",
        "cfg(target_os",
        "cfg!(target_os",
    ] {
        assert!(
            !source.contains(forbidden),
            "portable source contains ambient/runtime token {forbidden}"
        );
    }
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
