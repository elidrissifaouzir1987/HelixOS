//! PLAN-005 T071 RED contract for the paused cross-store dispatch backup index.
//!
//! The frozen JSON schema is checked directly so drift fails independently of the future
//! implementation. The final test is a compile-safe runtime RED until T075 adds the closed
//! coordinator manifest/index codecs; it deliberately does not provide a test-only codec.

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const DISPATCH_BACKUP_SCHEMA: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/dispatch-backup-manifest-v1.schema.json"
);

const GRANT_KEY_PURPOSE: &str = "coordinator-dispatch-signing";
const RECEIPT_KEY_PURPOSE: &str = "adapter-receipt-signing";
const BACKUP_KEY_PURPOSE: &str = "dispatch-backup-provisioner";
const GRANT_SIGNATURE_DOMAIN: &str = "HELIXOS\0EXECUTION-GRANT\0V1\0";
const RECEIPT_SIGNATURE_DOMAIN: &str = "HELIXOS\0EXECUTION-RECEIPT\0V1\0";
const BACKUP_SIGNATURE_DOMAIN: &str = "HELIXOS\0DISPATCH-BACKUP-INDEX\0V1\0";

fn schema() -> Value {
    serde_json::from_str(DISPATCH_BACKUP_SCHEMA)
        .unwrap_or_else(|error| panic!("frozen dispatch backup schema must parse: {error}"))
}

fn definition<'a>(schema: &'a Value, name: &str) -> &'a Value {
    schema["$defs"]
        .get(name)
        .unwrap_or_else(|| panic!("frozen dispatch backup schema omits $defs/{name}"))
}

fn strings(value: &Value, context: &str) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{context} must be an array"))
        .iter()
        .map(|member| {
            member
                .as_str()
                .unwrap_or_else(|| panic!("{context} must contain only strings"))
                .to_owned()
        })
        .collect()
}

fn expected(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn assert_exact_closed_object(schema: &Value, name: &str, fields: &[&str]) {
    let object = definition(schema, name);
    assert_eq!(object["type"].as_str(), Some("object"));
    assert_eq!(object["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        strings(&object["required"], &format!("$defs/{name}/required")),
        expected(fields),
        "$defs/{name} required members drifted"
    );
    assert_eq!(
        object["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("$defs/{name}/properties must be an object"))
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected(fields),
        "$defs/{name} property inventory drifted"
    );
}

fn assert_property_refs(schema: &Value, name: &str, fields: &[&str], expected_ref: &str) {
    let properties = &definition(schema, name)["properties"];
    for field in fields {
        assert_eq!(
            properties[*field]["$ref"].as_str(),
            Some(expected_ref),
            "$defs/{name}/properties/{field} has the wrong scalar contract"
        );
    }
}

fn key_profile<'a>(schema: &'a Value, name: &str) -> (&'a str, &'a str) {
    let properties = &definition(schema, name)["allOf"][1]["properties"];
    (
        properties["key_purpose"]["const"]
            .as_str()
            .unwrap_or_else(|| panic!("$defs/{name} lacks a constant key purpose")),
        properties["signature_domain"]["const"]
            .as_str()
            .unwrap_or_else(|| panic!("$defs/{name} lacks a constant signature domain")),
    )
}

#[test]
fn frozen_index_and_coordinator_v2_package_are_exact_and_closed() {
    let schema = schema();
    assert_eq!(
        schema["$schema"].as_str(),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    assert_eq!(schema["additionalProperties"].as_bool(), Some(false));
    assert_eq!(
        strings(&schema["required"], "top-level required members"),
        expected(&["protected", "protected_digest", "signature"])
    );

    let protected_fields = [
        "schema",
        "backup_id",
        "restore_identity_digest",
        "created_at_utc_ms",
        "source",
        "supervisor_epoch",
        "pause_evidence_digest",
        "quiescence_evidence_digest",
        "backup_order",
        "coordinator",
        "adapter_inbox",
        "cross_store_inventory",
        "verification_keys",
        "signature_profile",
    ];
    assert_exact_closed_object(&schema, "protectedIndex", &protected_fields);
    assert_eq!(
        definition(&schema, "protectedIndex")["properties"]["schema"]["const"].as_str(),
        Some("helixos.dispatch-backup-index/1")
    );

    let coordinator_fields = [
        "root_identity_digest",
        "application_id",
        "user_version",
        "base_schema_digest",
        "overlay_schema_digest",
        "database_digest",
        "manifest_digest",
        "migration_receipt_digest",
        "root_lifecycle_state",
        "generations",
        "counts",
        "inventory_digests",
    ];
    assert_exact_closed_object(&schema, "coordinatorPackage", &coordinator_fields);
    let coordinator = &definition(&schema, "coordinatorPackage")["properties"];
    assert_eq!(
        coordinator["application_id"]["const"].as_u64(),
        Some(1_212_962_883)
    );
    assert_eq!(coordinator["user_version"]["const"].as_u64(), Some(2));
    assert_eq!(
        strings(
            &coordinator["root_lifecycle_state"]["enum"],
            "coordinator lifecycle"
        ),
        expected(&["ACTIVE", "RESTORE_PENDING"])
    );
    for (member, target) in [
        ("generations", "#/$defs/coordinatorGenerations"),
        ("counts", "#/$defs/coordinatorCounts"),
        ("inventory_digests", "#/$defs/coordinatorInventories"),
    ] {
        assert_eq!(coordinator[member]["$ref"].as_str(), Some(target));
    }
    for member in [
        "root_identity_digest",
        "base_schema_digest",
        "overlay_schema_digest",
        "database_digest",
        "manifest_digest",
        "migration_receipt_digest",
    ] {
        assert_eq!(coordinator[member]["$ref"].as_str(), Some("#/$defs/digest"));
    }
}

#[test]
fn coordinator_v2_generation_count_and_inventory_sets_are_exhaustive() {
    let schema = schema();
    let generation_fields = [
        "dispatch_store",
        "dispatch",
        "delivery",
        "receipt",
        "reconciliation",
        "event",
        "migration",
        "restore_state",
    ];
    assert_exact_closed_object(&schema, "coordinatorGenerations", &generation_fields);
    assert_property_refs(
        &schema,
        "coordinatorGenerations",
        &generation_fields,
        "#/$defs/safeInteger",
    );
    let count_fields = [
        "migrations",
        "comparisons",
        "grants",
        "dispatch_records",
        "transitions",
        "outbox_members",
        "delivery_attempts",
        "receipts",
        "reconciliations",
        "events",
    ];
    assert_exact_closed_object(&schema, "coordinatorCounts", &count_fields);
    assert_property_refs(
        &schema,
        "coordinatorCounts",
        &count_fields,
        "#/$defs/safeInteger",
    );
    let inventory_fields = [
        "migrations",
        "comparisons",
        "grants",
        "dispatch_records",
        "transitions",
        "outbox_members",
        "delivery_attempts",
        "receipts",
        "reconciliations",
        "events",
        "complete_store",
    ];
    assert_exact_closed_object(&schema, "coordinatorInventories", &inventory_fields);
    assert_property_refs(
        &schema,
        "coordinatorInventories",
        &inventory_fields,
        "#/$defs/digest",
    );
}

#[test]
fn backup_cut_is_coordinator_then_adapter_then_signed_index_last() {
    let schema = schema();
    let order = definition(&schema, "backupOrder");
    assert_eq!(order["type"].as_str(), Some("array"));
    assert_eq!(order["minItems"].as_u64(), Some(3));
    assert_eq!(order["maxItems"].as_u64(), Some(3));
    assert_eq!(order["uniqueItems"].as_bool(), Some(true));
    assert_eq!(order["items"].as_bool(), Some(false));
    let prefix = order["prefixItems"]
        .as_array()
        .unwrap_or_else(|| panic!("backup order must use a closed prefix"));
    assert_eq!(
        prefix
            .iter()
            .map(|step| step["$ref"].as_str().expect("backup step must be a $ref"))
            .collect::<Vec<_>>(),
        vec![
            "#/$defs/coordinatorBackupStep",
            "#/$defs/adapterBackupStep",
            "#/$defs/indexPublishStep",
        ]
    );

    for (name, ordinal, component, time_member) in [
        (
            "coordinatorBackupStep",
            1,
            "coordinator-v2",
            "completed_at_utc_ms",
        ),
        (
            "adapterBackupStep",
            2,
            "adapter-inbox-v1",
            "completed_at_utc_ms",
        ),
        (
            "indexPublishStep",
            3,
            "signed-dispatch-backup-index-v1",
            "published_at_utc_ms",
        ),
    ] {
        let step = definition(&schema, name);
        assert_eq!(
            step["properties"]["ordinal"]["const"].as_u64(),
            Some(ordinal)
        );
        assert_eq!(
            step["properties"]["component"]["const"].as_str(),
            Some(component)
        );
        assert_eq!(
            step["properties"][time_member]["$ref"].as_str(),
            Some("#/$defs/safeInteger")
        );
    }
}

#[test]
fn three_verifier_purposes_and_domains_are_unique_and_non_substitutable() {
    let schema = schema();
    let profiles = [
        (
            "grantVerificationKey",
            GRANT_KEY_PURPOSE,
            GRANT_SIGNATURE_DOMAIN,
        ),
        (
            "receiptVerificationKey",
            RECEIPT_KEY_PURPOSE,
            RECEIPT_SIGNATURE_DOMAIN,
        ),
        (
            "backupVerificationKey",
            BACKUP_KEY_PURPOSE,
            BACKUP_SIGNATURE_DOMAIN,
        ),
    ];
    for (name, purpose, domain) in profiles {
        assert_eq!(key_profile(&schema, name), (purpose, domain));
        assert_eq!(
            definition(&schema, name)["unevaluatedProperties"].as_bool(),
            Some(false)
        );
    }

    assert_eq!(
        profiles
            .iter()
            .map(|(_, purpose, _)| *purpose)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    assert_eq!(
        profiles
            .iter()
            .map(|(_, _, domain)| *domain)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    for (name, expected_purpose, expected_domain) in profiles {
        for (_, candidate_purpose, candidate_domain) in profiles {
            assert_eq!(
                key_profile(&schema, name) == (candidate_purpose, candidate_domain),
                candidate_purpose == expected_purpose && candidate_domain == expected_domain,
                "{name} accepted a substituted purpose/domain pair"
            );
        }
    }

    assert_exact_closed_object(
        &schema,
        "verificationKeySets",
        &[
            "grant_signing_history",
            "receipt_signing_history",
            "backup_provisioner_history",
        ],
    );
    let sets = &definition(&schema, "verificationKeySets")["properties"];
    for (member, target) in [
        ("grant_signing_history", "#/$defs/grantVerificationKey"),
        ("receipt_signing_history", "#/$defs/receiptVerificationKey"),
        (
            "backup_provisioner_history",
            "#/$defs/backupVerificationKey",
        ),
    ] {
        assert_eq!(sets[member]["minItems"].as_u64(), Some(1));
        assert_eq!(sets[member]["maxItems"].as_u64(), Some(64));
        assert_eq!(sets[member]["uniqueItems"].as_bool(), Some(true));
        assert_eq!(sets[member]["items"]["$ref"].as_str(), Some(target));
    }
}

#[test]
fn signature_profile_is_canonical_digest_bound_and_contains_no_secret_member() {
    let schema = schema();
    assert_exact_closed_object(
        &schema,
        "indexSignatureProfile",
        &[
            "canonicalization",
            "protected_digest_algorithm",
            "signature_algorithm",
            "signature_domain",
            "signature_input_profile",
            "key_purpose",
            "key_id",
        ],
    );
    let profile = &definition(&schema, "indexSignatureProfile")["properties"];
    for (member, expected) in [
        ("canonicalization", "rfc8785-jcs"),
        ("protected_digest_algorithm", "sha-256"),
        ("signature_algorithm", "ed25519"),
        ("signature_domain", BACKUP_SIGNATURE_DOMAIN),
        (
            "signature_input_profile",
            "signature-domain || protected-digest-raw-32",
        ),
        ("key_purpose", BACKUP_KEY_PURPOSE),
    ] {
        assert_eq!(profile[member]["const"].as_str(), Some(expected));
    }

    let mut property_names = BTreeSet::new();
    collect_property_names(&schema, &mut property_names);
    for forbidden in [
        "private_key",
        "secret",
        "secret_key",
        "signing_key",
        "seed",
        "key_material",
        "key_bytes",
        "mnemonic",
    ] {
        assert!(
            !property_names
                .iter()
                .any(|name| name.to_ascii_lowercase().contains(forbidden)),
            "backup schema exposes forbidden key/secret member containing {forbidden}"
        );
    }
    assert!(property_names.contains("public_key_fingerprint"));
}

#[test]
fn production_dispatch_manifest_module_must_supply_closed_canonical_codecs() {
    let manifest = required_production_source(
        "dispatch_manifest.rs",
        "T075 coordinator V2 manifest and signed-index codecs",
    );
    let crate_root = required_production_source("lib.rs", "T075 coordinator module wiring");
    assert!(
        crate_root.contains("mod dispatch_manifest;"),
        "T071 RED: coordinator crate root must compile src/dispatch_manifest.rs"
    );

    for required in [
        "CoordinatorDispatchBackupManifestV1",
        "DispatchBackupIndexV1",
        "decode_coordinator_dispatch_backup_manifest_v1",
        "finalize_coordinator_dispatch_backup_manifest_v1",
        "decode_dispatch_backup_index_v1",
        "finalize_dispatch_backup_index_v1",
        "validate_sequential_backup_cut_v1",
        "serde_json_canonicalizer",
        "deny_unknown_fields",
        "coordinator-v2",
        "adapter-inbox-v1",
        "signed-dispatch-backup-index-v1",
        GRANT_KEY_PURPOSE,
        RECEIPT_KEY_PURPOSE,
        BACKUP_KEY_PURPOSE,
        "grant_signing_history",
        "receipt_signing_history",
        "backup_provisioner_history",
    ] {
        assert!(
            manifest.contains(required),
            "T071 RED: coordinator dispatch manifest codec omits `{required}`"
        );
    }
}

fn collect_property_names(value: &Value, output: &mut BTreeSet<String>) {
    if let Some(properties) = value.get("properties").and_then(Value::as_object) {
        output.extend(properties.keys().cloned());
    }
    match value {
        Value::Array(values) => {
            for value in values {
                collect_property_names(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_property_names(value, output);
            }
        }
        _ => {}
    }
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T071 RED: missing future production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut block_depth = 0_u64;
    for line in source.lines() {
        let mut remaining = line;
        loop {
            if block_depth > 0 {
                let Some(end) = remaining.find("*/") else {
                    break;
                };
                block_depth -= 1;
                remaining = &remaining[end + 2..];
                continue;
            }
            let line_comment = remaining.find("//");
            let block_comment = remaining.find("/*");
            match (line_comment, block_comment) {
                (Some(line_start), Some(block_start)) if block_start < line_start => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (Some(line_start), _) => {
                    output.push_str(&remaining[..line_start]);
                    break;
                }
                (None, Some(block_start)) => {
                    output.push_str(&remaining[..block_start]);
                    block_depth += 1;
                    remaining = &remaining[block_start + 2..];
                }
                (None, None) => {
                    output.push_str(remaining);
                    break;
                }
            }
        }
        output.push('\n');
    }
    assert_eq!(block_depth, 0, "T071 production comments are balanced");
    output
}

// T072 freezes the clean-restore result independently of the future T077 maintenance
// API. These values are deliberately test-only oracles: they do not decode a manifest,
// mutate either store, or provide a substitute restore implementation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CleanRestoreAuthorityOracleV1 {
    source_coordinator_root: [u8; 32],
    source_adapter_root: [u8; 32],
    restored_coordinator_root: [u8; 32],
    restored_adapter_root: [u8; 32],
    source_instance_identity: [u8; 32],
    restored_instance_identity: [u8; 32],
    source_supervisor_identity: [u8; 32],
    restored_supervisor_identity: [u8; 32],
    source_instance_epoch: u64,
    restored_instance_epoch: u64,
    source_supervisor_epoch: u64,
    restored_supervisor_epoch: u64,
    coordinator_destination_entry_count: u64,
    adapter_destination_entry_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanRestoreAuthorityErrorV1 {
    DestinationNotEmpty,
    RootIdentityNotFresh,
    InstanceIdentityNotFresh,
    SupervisorIdentityNotFresh,
    InstanceEpochNotFresh,
    SupervisorEpochNotFresh,
}

fn exact_clean_restore_authority_oracle_v1() -> CleanRestoreAuthorityOracleV1 {
    CleanRestoreAuthorityOracleV1 {
        source_coordinator_root: [0x11; 32],
        source_adapter_root: [0x12; 32],
        restored_coordinator_root: [0x21; 32],
        restored_adapter_root: [0x22; 32],
        source_instance_identity: [0x31; 32],
        restored_instance_identity: [0x32; 32],
        source_supervisor_identity: [0x41; 32],
        restored_supervisor_identity: [0x42; 32],
        source_instance_epoch: 7,
        restored_instance_epoch: 8,
        source_supervisor_epoch: 11,
        restored_supervisor_epoch: 12,
        coordinator_destination_entry_count: 0,
        adapter_destination_entry_count: 0,
    }
}

fn validate_clean_restore_authority_oracle_v1(
    authority: CleanRestoreAuthorityOracleV1,
) -> Result<(), CleanRestoreAuthorityErrorV1> {
    if authority.coordinator_destination_entry_count != 0
        || authority.adapter_destination_entry_count != 0
    {
        return Err(CleanRestoreAuthorityErrorV1::DestinationNotEmpty);
    }
    let source_roots = [
        authority.source_coordinator_root,
        authority.source_adapter_root,
    ];
    if source_roots.contains(&authority.restored_coordinator_root)
        || source_roots.contains(&authority.restored_adapter_root)
        || authority.restored_coordinator_root == authority.restored_adapter_root
    {
        return Err(CleanRestoreAuthorityErrorV1::RootIdentityNotFresh);
    }
    if authority.restored_instance_identity == authority.source_instance_identity {
        return Err(CleanRestoreAuthorityErrorV1::InstanceIdentityNotFresh);
    }
    if authority.restored_supervisor_identity == authority.source_supervisor_identity {
        return Err(CleanRestoreAuthorityErrorV1::SupervisorIdentityNotFresh);
    }
    if authority.restored_instance_epoch == 0
        || authority.restored_instance_epoch == authority.source_instance_epoch
    {
        return Err(CleanRestoreAuthorityErrorV1::InstanceEpochNotFresh);
    }
    if authority.restored_supervisor_epoch == 0
        || authority.restored_supervisor_epoch == authority.source_supervisor_epoch
    {
        return Err(CleanRestoreAuthorityErrorV1::SupervisorEpochNotFresh);
    }
    Ok(())
}

#[test]
fn clean_restore_requires_empty_new_roots_and_rotated_authority() {
    let exact = exact_clean_restore_authority_oracle_v1();
    assert_eq!(validate_clean_restore_authority_oracle_v1(exact), Ok(()));

    let mut coordinator_not_empty = exact;
    coordinator_not_empty.coordinator_destination_entry_count = 1;
    let mut adapter_not_empty = exact;
    adapter_not_empty.adapter_destination_entry_count = 1;
    let mut reused_coordinator_root = exact;
    reused_coordinator_root.restored_coordinator_root = exact.source_coordinator_root;
    let mut reused_adapter_root = exact;
    reused_adapter_root.restored_adapter_root = exact.source_adapter_root;
    let mut colliding_new_roots = exact;
    colliding_new_roots.restored_adapter_root = exact.restored_coordinator_root;
    let mut reused_instance_identity = exact;
    reused_instance_identity.restored_instance_identity = exact.source_instance_identity;
    let mut reused_supervisor_identity = exact;
    reused_supervisor_identity.restored_supervisor_identity = exact.source_supervisor_identity;
    let mut reused_instance_epoch = exact;
    reused_instance_epoch.restored_instance_epoch = exact.source_instance_epoch;
    let mut reused_supervisor_epoch = exact;
    reused_supervisor_epoch.restored_supervisor_epoch = exact.source_supervisor_epoch;

    for (candidate, error) in [
        (
            coordinator_not_empty,
            CleanRestoreAuthorityErrorV1::DestinationNotEmpty,
        ),
        (
            adapter_not_empty,
            CleanRestoreAuthorityErrorV1::DestinationNotEmpty,
        ),
        (
            reused_coordinator_root,
            CleanRestoreAuthorityErrorV1::RootIdentityNotFresh,
        ),
        (
            reused_adapter_root,
            CleanRestoreAuthorityErrorV1::RootIdentityNotFresh,
        ),
        (
            colliding_new_roots,
            CleanRestoreAuthorityErrorV1::RootIdentityNotFresh,
        ),
        (
            reused_instance_identity,
            CleanRestoreAuthorityErrorV1::InstanceIdentityNotFresh,
        ),
        (
            reused_supervisor_identity,
            CleanRestoreAuthorityErrorV1::SupervisorIdentityNotFresh,
        ),
        (
            reused_instance_epoch,
            CleanRestoreAuthorityErrorV1::InstanceEpochNotFresh,
        ),
        (
            reused_supervisor_epoch,
            CleanRestoreAuthorityErrorV1::SupervisorEpochNotFresh,
        ),
    ] {
        assert_eq!(
            validate_clean_restore_authority_oracle_v1(candidate),
            Err(error)
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoreLifecycleOracleV1 {
    Active,
    RestorePending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoreControlOracleV1 {
    Running,
    Paused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoredGrantAuthorityOracleV1 {
    Live,
    IrrevocablyExpired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CleanRestoreOutcomeOracleV1 {
    coordinator_lifecycle: RestoreLifecycleOracleV1,
    adapter_lifecycle: RestoreLifecycleOracleV1,
    control: RestoreControlOracleV1,
    old_grant_authority: RestoredGrantAuthorityOracleV1,
    automatic_redelivery_count: u64,
}

fn exact_clean_restore_outcome_oracle_v1() -> CleanRestoreOutcomeOracleV1 {
    CleanRestoreOutcomeOracleV1 {
        coordinator_lifecycle: RestoreLifecycleOracleV1::RestorePending,
        adapter_lifecycle: RestoreLifecycleOracleV1::RestorePending,
        control: RestoreControlOracleV1::Paused,
        old_grant_authority: RestoredGrantAuthorityOracleV1::IrrevocablyExpired,
        automatic_redelivery_count: 0,
    }
}

fn validate_clean_restore_outcome_oracle_v1(outcome: CleanRestoreOutcomeOracleV1) -> bool {
    outcome.coordinator_lifecycle == RestoreLifecycleOracleV1::RestorePending
        && outcome.adapter_lifecycle == RestoreLifecycleOracleV1::RestorePending
        && outcome.control == RestoreControlOracleV1::Paused
        && outcome.old_grant_authority == RestoredGrantAuthorityOracleV1::IrrevocablyExpired
        && outcome.automatic_redelivery_count == 0
}

#[test]
fn clean_restore_is_pending_paused_and_cannot_revive_or_redeliver_old_grants() {
    let expected = exact_clean_restore_outcome_oracle_v1();
    assert!(validate_clean_restore_outcome_oracle_v1(expected));

    for forbidden in [
        CleanRestoreOutcomeOracleV1 {
            coordinator_lifecycle: RestoreLifecycleOracleV1::Active,
            ..expected
        },
        CleanRestoreOutcomeOracleV1 {
            adapter_lifecycle: RestoreLifecycleOracleV1::Active,
            ..expected
        },
        CleanRestoreOutcomeOracleV1 {
            control: RestoreControlOracleV1::Running,
            ..expected
        },
        CleanRestoreOutcomeOracleV1 {
            old_grant_authority: RestoredGrantAuthorityOracleV1::Live,
            ..expected
        },
        CleanRestoreOutcomeOracleV1 {
            automatic_redelivery_count: 1,
            ..expected
        },
    ] {
        assert!(!validate_clean_restore_outcome_oracle_v1(forbidden));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestoredDispatchEvidenceOracleV1 {
    DefiniteNoHandoff,
    PossibleHandoff,
    AdapterReceived,
    AdapterConsumed,
    CoordinatorExecuting,
    OutcomeUnknown,
}

impl RestoredDispatchEvidenceOracleV1 {
    const fn requires_quarantine_and_reconciliation(self) -> bool {
        !matches!(self, Self::DefiniteNoHandoff)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestoreCustodyOracleV1 {
    quarantined: bool,
    reconciliation_required: bool,
    automatic_redelivery_count: u64,
}

fn validate_restore_custody_oracle_v1(
    evidence: RestoredDispatchEvidenceOracleV1,
    custody: RestoreCustodyOracleV1,
) -> bool {
    custody.automatic_redelivery_count == 0
        && (!evidence.requires_quarantine_and_reconciliation()
            || (custody.quarantined && custody.reconciliation_required))
}

#[test]
fn every_possible_acceptance_or_consumption_is_quarantined_for_reconciliation() {
    let required = [
        RestoredDispatchEvidenceOracleV1::PossibleHandoff,
        RestoredDispatchEvidenceOracleV1::AdapterReceived,
        RestoredDispatchEvidenceOracleV1::AdapterConsumed,
        RestoredDispatchEvidenceOracleV1::CoordinatorExecuting,
        RestoredDispatchEvidenceOracleV1::OutcomeUnknown,
    ];
    for evidence in required {
        assert!(validate_restore_custody_oracle_v1(
            evidence,
            RestoreCustodyOracleV1 {
                quarantined: true,
                reconciliation_required: true,
                automatic_redelivery_count: 0,
            }
        ));
        for invalid in [
            RestoreCustodyOracleV1 {
                quarantined: false,
                reconciliation_required: true,
                automatic_redelivery_count: 0,
            },
            RestoreCustodyOracleV1 {
                quarantined: true,
                reconciliation_required: false,
                automatic_redelivery_count: 0,
            },
            RestoreCustodyOracleV1 {
                quarantined: true,
                reconciliation_required: true,
                automatic_redelivery_count: 1,
            },
        ] {
            assert!(!validate_restore_custody_oracle_v1(evidence, invalid));
        }
    }

    assert!(validate_restore_custody_oracle_v1(
        RestoredDispatchEvidenceOracleV1::DefiniteNoHandoff,
        RestoreCustodyOracleV1 {
            quarantined: false,
            reconciliation_required: false,
            automatic_redelivery_count: 0,
        }
    ));
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t076_backup_path_is_index_last_and_fail_closed() {
    helix_coordinator_sqlite::run_t076_production_conformance_for_test_v1()
        .expect("T076 production backup conformance must pass");
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t077_restore_path_is_pending_paused_and_exactly_retryable() {
    helix_coordinator_sqlite::run_t077_production_conformance_for_test_v1()
        .expect("T077 production restore conformance must pass");
}

#[cfg(feature = "test-fault-injection")]
#[test]
fn production_t096_restore_matrix_covers_every_declared_lifecycle_phase() {
    helix_coordinator_sqlite::run_t096_production_restore_matrix_for_test_v1()
        .expect("T096 production lifecycle restore matrix must pass");
}

#[test]
fn production_t077_clean_restore_maintenance_api_enforces_the_frozen_oracles() {
    let maintenance = required_production_source(
        "maintenance.rs",
        "T077 dispatch clean-root restore maintenance API",
    );
    let required = [
        "VerifiedDispatchRestoreV1",
        "restore_dispatch_backup_to_pending_v1",
        "CleanDispatchRestoreRootsV1",
        "PausedRotatedDispatchRestoreAuthorityV1",
        "IrrevocablyExpiredRestoredGrantV1",
        "RestoredPossibleConsumptionQuarantineV1",
        "coordinator_destination_entry_count",
        "adapter_destination_entry_count",
        "new_coordinator_root_identity",
        "new_adapter_root_identity",
        "new_instance_identity",
        "new_supervisor_identity",
        "new_instance_epoch",
        "new_supervisor_epoch",
        "RESTORE_PENDING",
        "PAUSED",
        "automatic_redelivery_count",
        "reconciliation_required_count",
    ];
    let missing = required
        .iter()
        .copied()
        .filter(|member| !maintenance.contains(member))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "T072 RED: future T077 clean-root maintenance API is absent or incomplete; missing={missing:?}"
    );
    for forbidden in [
        "activate_restored_dispatch_v1",
        "redeliver_restored_grant_v1",
        "resume_restored_execution_v1",
    ] {
        assert!(
            !maintenance.contains(forbidden),
            "T072 RED: clean restore must expose no activation/redelivery path `{forbidden}`"
        );
    }
}
