//! T064 tests for the quiescent preparation backup and dual-root pending restore.
//!
//! The closed manifest codecs are exercised directly. The two orchestration tests remain
//! deliberate runtime REDs until T069-T072 place their production call sites; they compile so
//! the missing protocol is reported as a bounded contract gap rather than a missing symbol.

#[path = "../src/error.rs"]
mod error;
#[path = "../src/manifest.rs"]
mod manifest;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use manifest::{
    cross_validate_backup_retirement_v1, decode_backup_provenance_attestation_v1,
    decode_preparation_backup_manifest_v1, decode_recovery_root_metadata_v1,
    decode_recovery_snapshot_manifest_v1, verify_backup_provenance_v1, ManifestCodecErrorV1,
    PendingRetirementEvidenceV1, PinnedEd25519KeyV1, ProvisionerTrustCustodyOutcomeV1,
    ProvisionerTrustCustodyV1, ProvisionerTrustDecisionV1, ProvisionerTrustResolverV1,
    ProvisionerTrustViewV1, ATTESTATION_SIGNATURE_DOMAIN_V1,
};
use rusqlite::backup::Backup;
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const MAINTENANCE_SOURCE: &str = include_str!("../src/maintenance.rs");
const ROOT_SAFETY_SOURCE: &str = include_str!("../src/root_safety.rs");
const FAULT_SOURCE: &str = include_str!("../src/test_fault.rs");
const CORPUS_CASES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/cases.json");

const ATTESTATION_PROFILE_ID: &str = "provisioner-backup";
const KEY_ID: &str = "provisioner-key-1";

fn digest_hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("public-synthetic JSON canonicalizes")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_lower_sha256(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "test digest must be SHA-256 hex");
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("test digest must be lowercase hex"),
        };
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

struct PackageBindingInputV1<'a> {
    provider_profile_id: &'a str,
    provider_profile_version: u64,
    provider_id: &'a str,
    provider_generation: u64,
    evidence_class: &'a str,
    at_rest_profile_id: &'a str,
    custody: &'a str,
    state: &'a str,
    manifest_sha256: &'a str,
    material_sha256: &'a str,
    material_length: u64,
    reserved_capacity: u64,
    retirement_manifest_sha256: Option<&'a str>,
}

fn package_binding_preimage(input: &PackageBindingInputV1<'_>) -> Vec<u8> {
    let mut bytes = b"HELIXOS\0RECOVERY-BACKUP-PACKAGE-BINDING\0V1\0".to_vec();
    let append_string = |bytes: &mut Vec<u8>, value: &str| {
        let length = u16::try_from(value.len()).expect("synthetic identifier fits u16");
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    };
    append_string(&mut bytes, input.provider_profile_id);
    bytes.extend_from_slice(&input.provider_profile_version.to_be_bytes());
    append_string(&mut bytes, input.provider_id);
    bytes.extend_from_slice(&input.provider_generation.to_be_bytes());
    append_string(&mut bytes, input.evidence_class);
    append_string(&mut bytes, input.at_rest_profile_id);
    append_string(&mut bytes, input.custody);
    append_string(&mut bytes, input.state);
    bytes.extend_from_slice(&decode_lower_sha256(input.manifest_sha256));
    bytes.extend_from_slice(&decode_lower_sha256(input.material_sha256));
    bytes.extend_from_slice(&input.material_length.to_be_bytes());
    bytes.extend_from_slice(&input.reserved_capacity.to_be_bytes());
    match input.retirement_manifest_sha256 {
        None => bytes.push(0),
        Some(retirement) => {
            bytes.push(1);
            bytes.extend_from_slice(&decode_lower_sha256(retirement));
        }
    }
    bytes
}

fn package_binding_sha256(input: &PackageBindingInputV1<'_>) -> String {
    sha256_hex(&package_binding_preimage(input))
}

struct InventoryEntryInputV1<'a> {
    provider_profile_id: &'a str,
    provider_id: &'a str,
    provider_generation: u64,
    manifest_byte: u8,
    material_byte: u8,
    custody: &'a str,
    state: &'a str,
    material_length: u64,
    reserved_capacity: u64,
    retirement_byte: Option<u8>,
}

fn inventory_entry(input: InventoryEntryInputV1<'_>) -> Value {
    let manifest = digest_hex(input.manifest_byte);
    let material = digest_hex(input.material_byte);
    let retirement = input.retirement_byte.map(digest_hex);
    let binding = package_binding_sha256(&PackageBindingInputV1 {
        provider_profile_id: input.provider_profile_id,
        provider_profile_version: 1,
        provider_id: input.provider_id,
        provider_generation: input.provider_generation,
        evidence_class: "SYNTHETIC_CONFORMANCE",
        at_rest_profile_id: "at-rest.synthetic-v1",
        custody: input.custody,
        state: input.state,
        manifest_sha256: &manifest,
        material_sha256: &material,
        material_length: input.material_length,
        reserved_capacity: input.reserved_capacity,
        retirement_manifest_sha256: retirement.as_deref(),
    });
    let mut entry = json!({
        "package_binding_sha256": binding,
        "manifest_sha256": manifest,
        "material_sha256": material,
        "material_length": input.material_length,
        "reserved_capacity": input.reserved_capacity,
        "custody": input.custody,
        "state": input.state
    });
    if let Some(retirement) = retirement {
        entry["retirement_manifest_sha256"] = Value::String(retirement);
    }
    entry
}

fn multi_provider_inventory_value(variant: u8) -> Value {
    let first = inventory_entry(InventoryEntryInputV1 {
        provider_profile_id: "profile.alpha",
        provider_id: "provider.alpha",
        provider_generation: 1,
        manifest_byte: 0x11_u8.wrapping_add(variant),
        material_byte: 0x21,
        custody: "OPERATION_BOUND",
        state: "MATERIAL_PRESENT",
        material_length: 3,
        reserved_capacity: 4,
        retirement_byte: None,
    });
    let second = inventory_entry(InventoryEntryInputV1 {
        provider_profile_id: "profile.beta",
        provider_id: "provider.beta",
        provider_generation: 7,
        manifest_byte: 0x13,
        material_byte: 0x22,
        custody: "ORPHAN_RESOLUTION_TOMBSTONE",
        state: "RETIRED_TOMBSTONE",
        material_length: 5,
        reserved_capacity: 8,
        retirement_byte: Some(0x33),
    });
    json!({
        "schema": "helixos.recovery-snapshot/1",
        "provider_set_count": 2,
        "entry_count": 2,
        "provider_sets": [
            {
                "provider_profile_id": "profile.alpha",
                "provider_profile_version": 1,
                "provider_id": "provider.alpha",
                "provider_generation": 1,
                "evidence_class": "SYNTHETIC_CONFORMANCE",
                "at_rest_profile_id": "at-rest.synthetic-v1",
                "entry_count": 1,
                "entries": [first]
            },
            {
                "provider_profile_id": "profile.beta",
                "provider_profile_version": 1,
                "provider_id": "provider.beta",
                "provider_generation": 7,
                "evidence_class": "SYNTHETIC_CONFORMANCE",
                "at_rest_profile_id": "at-rest.synthetic-v1",
                "entry_count": 1,
                "entries": [second]
            }
        ],
        "complete_reference_set": true,
        "no_retirement_pending": true,
        "requires_paused_restore": true
    })
}

fn backup_value(inventory_sha256: &str, variant: u8) -> Value {
    json!({
        "schema": "helixos.preparation-backup/1",
        "application_id": 1212962883,
        "store_schema_version": 1,
        "source_coordinator_root_identity_sha256": digest_hex(0x01_u8.wrapping_add(variant)),
        "source_recovery_root_identity_sha256": digest_hex(0x02_u8.wrapping_add(variant)),
        "source_instance_identity_sha256": digest_hex(0x03_u8.wrapping_add(variant)),
        "source_root_lifecycle_state": "ACTIVE",
        "coordinator_schema_sha256": digest_hex(0x04),
        "coordinator_database_sha256": digest_hex(0x05_u8.wrapping_add(variant)),
        "sqlite": {
            "rusqlite_version": "0.40.1",
            "libsqlite3_sys_version": "0.38.1",
            "bundled_sqlite_version": "3.53.2",
            "bundled_sqlite_source_id": "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24",
            "link_profile": "rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static"
        },
        "durability_profile": {
            "journal_mode": "WAL",
            "synchronous": "FULL",
            "wal_autocheckpoint_pages": 0,
            "foreign_keys": true,
            "recursive_triggers": true,
            "trusted_schema": false,
            "cell_size_check": true
        },
        "at_rest_profile_id": "at-rest.synthetic-v1",
        "generations": {
            "store": 11,
            "operation": 7,
            "budget": 9,
            "event": 8,
            "quarantine": 4
        },
        "counts": {
            "budget_scopes": 2,
            "operations": 2,
            "operation_transitions": 3,
            "held_reservations": 1,
            "released_reservations": 1,
            "pending_events": 2,
            "delivered_events": 1,
            "active_quarantines": 0,
            "resolved_quarantines": 1,
            "operation_retirement_pending": 0,
            "orphan_retirement_pending": 0
        },
        "recovery_snapshot": {
            "schema": "helixos.recovery-snapshot-summary/1",
            "inventory_sha256": inventory_sha256,
            "provider_set_count": 2,
            "entry_count": 2,
            "all_required_entries_verified": true
        },
        "recovery_root_metadata_schema": "helixos.recovery-root-metadata/1",
        "provenance_attestation_schema": "helixos.preparation-backup-provenance-attestation/1",
        "requires_detached_provenance_attestation": true,
        "required_restore_root_lifecycle_state": "RESTORE_PENDING",
        "requires_paused_restore": true,
        "requires_boot_epoch_rotation": true,
        "requires_instance_epoch_rotation": true,
        "requires_fencing_epoch_rotation": true,
        "nonterminal_preparations_not_reactivatable": true,
        "may_omit_work_after_generation": true
    })
}

fn attestation_value(
    signing_key: &SigningKey,
    backup: &Value,
    backup_sha256: &str,
    inventory: &Value,
    inventory_sha256: &str,
) -> Value {
    let generations = inventory["provider_sets"]
        .as_array()
        .expect("synthetic provider sets exist")
        .iter()
        .map(|provider| {
            json!({
                "provider_profile_id": provider["provider_profile_id"],
                "provider_profile_version": provider["provider_profile_version"],
                "provider_id": provider["provider_id"],
                "provider_generation": provider["provider_generation"]
            })
        })
        .collect::<Vec<_>>();
    let protected = json!({
        "schema": "helixos.preparation-backup-provenance-protected/1",
        "top_level_manifest_sha256": backup_sha256,
        "source_coordinator_root_identity_sha256": backup["source_coordinator_root_identity_sha256"],
        "source_recovery_root_identity_sha256": backup["source_recovery_root_identity_sha256"],
        "source_instance_identity_sha256": backup["source_instance_identity_sha256"],
        "coordinator_generations": backup["generations"],
        "recovery_inventory_sha256": inventory_sha256,
        "recovery_provider_set_count": inventory["provider_set_count"],
        "recovery_entry_count": inventory["entry_count"],
        "recovery_provider_generations": generations,
        "at_rest_profile_id": backup["at_rest_profile_id"],
        "attestation_profile_id": ATTESTATION_PROFILE_ID,
        "attestation_profile_version": 1,
        "key_id": KEY_ID,
        "digest_algorithm": "sha-256"
    });
    let mut message = ATTESTATION_SIGNATURE_DOMAIN_V1.to_vec();
    message.extend_from_slice(&canonical(&protected));
    let signature = signing_key.sign(&message).to_bytes();
    json!({
        "schema": "helixos.preparation-backup-provenance-attestation/1",
        "protected": protected,
        "signature_algorithm": "ed25519",
        "signature_base64url": URL_SAFE_NO_PAD.encode(signature)
    })
}

struct FixedProvisionerTrustV1 {
    pinned: PinnedEd25519KeyV1,
}

#[allow(dead_code)]
struct FixedProvisionerTrustCustodyV1 {
    pinned: PinnedEd25519KeyV1,
}

impl ProvisionerTrustViewV1 for FixedProvisionerTrustCustodyV1 {
    fn resolve_ed25519(
        &self,
        profile_id: &str,
        profile_version: u64,
        key_id: &str,
    ) -> ProvisionerTrustDecisionV1 {
        if profile_id == ATTESTATION_PROFILE_ID && profile_version == 1 && key_id == KEY_ID {
            ProvisionerTrustDecisionV1::Trusted(self.pinned)
        } else {
            ProvisionerTrustDecisionV1::Unknown
        }
    }
}

impl ProvisionerTrustCustodyV1 for FixedProvisionerTrustCustodyV1 {}

impl ProvisionerTrustResolverV1 for FixedProvisionerTrustV1 {
    fn acquire_restore_trust_custody_v1(&self) -> ProvisionerTrustCustodyOutcomeV1 {
        ProvisionerTrustCustodyOutcomeV1::Acquired(Box::new(FixedProvisionerTrustCustodyV1 {
            pinned: self.pinned,
        }))
    }

    fn resolve_ed25519(
        &self,
        profile_id: &str,
        profile_version: u64,
        key_id: &str,
    ) -> ProvisionerTrustDecisionV1 {
        if profile_id == ATTESTATION_PROFILE_ID && profile_version == 1 && key_id == KEY_ID {
            ProvisionerTrustDecisionV1::Trusted(self.pinned)
        } else {
            ProvisionerTrustDecisionV1::Unknown
        }
    }
}

struct TemporaryDirectoryV1(PathBuf);

impl TemporaryDirectoryV1 {
    fn new(label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-t064-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("T064 temporary directory creates");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectoryV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn t061_package_binding_known_answer_vectors_are_byte_exact() {
    let corpus: Value = serde_json::from_slice(CORPUS_CASES).expect("T061 corpus parses");
    let kats = corpus["package_binding_kats"]
        .as_array()
        .expect("T061 KAT array exists");
    assert_eq!(kats.len(), 2);
    for kat in kats {
        let input = PackageBindingInputV1 {
            provider_profile_id: kat["provider_profile_id"].as_str().unwrap(),
            provider_profile_version: kat["provider_profile_version"].as_u64().unwrap(),
            provider_id: kat["provider_id"].as_str().unwrap(),
            provider_generation: kat["provider_generation"].as_u64().unwrap(),
            evidence_class: kat["evidence_class"].as_str().unwrap(),
            at_rest_profile_id: kat["at_rest_profile_id"].as_str().unwrap(),
            custody: kat["custody"].as_str().unwrap(),
            state: kat["state"].as_str().unwrap(),
            manifest_sha256: kat["manifest_sha256"].as_str().unwrap(),
            material_sha256: kat["material_sha256"].as_str().unwrap(),
            material_length: kat["material_length"].as_u64().unwrap(),
            reserved_capacity: kat["reserved_capacity"].as_u64().unwrap(),
            retirement_manifest_sha256: kat
                .get("retirement_manifest_sha256")
                .and_then(Value::as_str),
        };
        let preimage = package_binding_preimage(&input);
        assert_eq!(preimage.len() as u64, kat["expected_preimage_length"]);
        assert_eq!(lowercase_hex(&preimage), kat["expected_preimage_hex"]);
        assert_eq!(
            package_binding_sha256(&input),
            kat["expected_package_binding_sha256"]
        );
    }
}

#[test]
fn multi_provider_inventory_and_both_pending_retirement_domains_are_closed() {
    let inventory_value = multi_provider_inventory_value(0);
    let inventory_bytes = canonical(&inventory_value);
    let inventory = decode_recovery_snapshot_manifest_v1(&inventory_bytes)
        .expect("sorted complete multi-provider inventory decodes");
    let backup_json = backup_value(&inventory.sha256_hex(), 0);
    let backup_bytes = canonical(&backup_json);
    let backup = decode_preparation_backup_manifest_v1(&backup_bytes)
        .expect("fixed-zero top-level backup decodes");

    let zero = PendingRetirementEvidenceV1::try_new(0, 0, 0, 0).unwrap();
    cross_validate_backup_retirement_v1(&backup, &inventory, zero)
        .expect("all four authoritative pending counts agree at zero");
    for pending in [
        PendingRetirementEvidenceV1::try_new(1, 0, 0, 0).unwrap(),
        PendingRetirementEvidenceV1::try_new(0, 1, 0, 0).unwrap(),
        PendingRetirementEvidenceV1::try_new(0, 0, 1, 0).unwrap(),
        PendingRetirementEvidenceV1::try_new(0, 0, 0, 1).unwrap(),
    ] {
        assert_eq!(
            cross_validate_backup_retirement_v1(&backup, &inventory, pending),
            Err(ManifestCodecErrorV1::JsonContractInvalid),
            "either coordinator or provider pending domain must block backup",
        );
    }

    for field in ["operation_retirement_pending", "orphan_retirement_pending"] {
        let mut nonzero = backup_json.clone();
        nonzero["counts"][field] = json!(1);
        assert_eq!(
            decode_preparation_backup_manifest_v1(&canonical(&nonzero)).unwrap_err(),
            ManifestCodecErrorV1::JsonContractInvalid,
        );
    }

    let mut reordered = inventory_value.clone();
    reordered["provider_sets"]
        .as_array_mut()
        .expect("provider sets are mutable")
        .reverse();
    assert!(decode_recovery_snapshot_manifest_v1(&canonical(&reordered)).is_err());
    let mut duplicate = inventory_value;
    duplicate["provider_sets"][1] = duplicate["provider_sets"][0].clone();
    assert!(decode_recovery_snapshot_manifest_v1(&canonical(&duplicate)).is_err());
}

#[test]
fn jcs_detached_attestation_and_coherent_substitution_are_byte_exact() {
    let inventory_value = multi_provider_inventory_value(0);
    let inventory_bytes = canonical(&inventory_value);
    let inventory = decode_recovery_snapshot_manifest_v1(&inventory_bytes).unwrap();
    let backup_json = backup_value(&inventory.sha256_hex(), 0);
    let backup_bytes = canonical(&backup_json);
    let backup = decode_preparation_backup_manifest_v1(&backup_bytes).unwrap();

    let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
    let verifying_key = signing_key.verifying_key().to_bytes();
    let pin: [u8; 32] = Sha256::digest(verifying_key).into();
    let trust = FixedProvisionerTrustV1 {
        pinned: PinnedEd25519KeyV1::try_new(verifying_key, pin).unwrap(),
    };
    let attestation_json = attestation_value(
        &signing_key,
        &backup_json,
        &backup.sha256_hex(),
        &inventory_value,
        &inventory.sha256_hex(),
    );
    let attestation_bytes = canonical(&attestation_json);
    let attestation = decode_backup_provenance_attestation_v1(&attestation_bytes).unwrap();
    verify_backup_provenance_v1(&attestation, &backup, &inventory, &trust)
        .expect("exact detached attestation verifies");

    assert!(!inventory_bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
    assert!(!backup_bytes.ends_with(b"\n"));
    assert!(!attestation_bytes.ends_with(b"\n"));
    assert_eq!(inventory.sha256_hex(), sha256_hex(&inventory_bytes));
    assert_eq!(backup.sha256_hex(), sha256_hex(&backup_bytes));
    for mut noncanonical in [inventory_bytes.clone(), backup_bytes.clone()] {
        noncanonical.push(b'\n');
        assert!(
            decode_recovery_snapshot_manifest_v1(&noncanonical).is_err()
                || decode_preparation_backup_manifest_v1(&noncanonical).is_err()
        );
    }
    let mut attestation_newline = attestation_bytes.clone();
    attestation_newline.push(b'\n');
    assert!(decode_backup_provenance_attestation_v1(&attestation_newline).is_err());

    // A second package is internally coherent and correctly signed, but cannot replace the
    // first package because its source identities, inventory and top-level digest differ.
    let substituted_inventory_value = multi_provider_inventory_value(1);
    let substituted_inventory_bytes = canonical(&substituted_inventory_value);
    let substituted_inventory =
        decode_recovery_snapshot_manifest_v1(&substituted_inventory_bytes).unwrap();
    let substituted_backup_value = backup_value(&substituted_inventory.sha256_hex(), 1);
    let substituted_backup_bytes = canonical(&substituted_backup_value);
    let substituted_backup =
        decode_preparation_backup_manifest_v1(&substituted_backup_bytes).unwrap();
    let substituted_attestation =
        decode_backup_provenance_attestation_v1(&canonical(&attestation_value(
            &signing_key,
            &substituted_backup_value,
            &substituted_backup.sha256_hex(),
            &substituted_inventory_value,
            &substituted_inventory.sha256_hex(),
        )))
        .unwrap();
    verify_backup_provenance_v1(
        &substituted_attestation,
        &substituted_backup,
        &substituted_inventory,
        &trust,
    )
    .expect("substitute package is self-consistent");
    assert_eq!(
        verify_backup_provenance_v1(&substituted_attestation, &backup, &inventory, &trust),
        Err(ManifestCodecErrorV1::ProvenanceInvalid),
        "coherent substitution must not inherit the original package provenance",
    );
}

#[test]
fn sqlite_online_backup_reference_captures_committed_wal_state() {
    let root = TemporaryDirectoryV1::new("online-backup-reference");
    let source_path = root.path().join("source.sqlite3");
    let destination_path = root.path().join("destination.sqlite3");
    let source = Connection::open(&source_path).expect("WAL source opens");
    let journal: String = source
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .expect("WAL establishes");
    assert_eq!(journal.to_ascii_lowercase(), "wal");
    source
        .execute_batch(
            "PRAGMA synchronous = FULL; PRAGMA wal_autocheckpoint = 0; \
             CREATE TABLE durable_cut (generation INTEGER PRIMARY KEY, value TEXT) STRICT; \
             INSERT INTO durable_cut VALUES (1, 'before-cut'); \
             INSERT INTO durable_cut VALUES (2, 'at-cut');",
        )
        .expect("committed WAL fixture writes");
    let mut destination = Connection::open(&destination_path).expect("backup destination opens");
    let backup = Backup::new(&source, &mut destination).expect("online backup starts");
    backup
        .run_to_completion(1, Duration::from_millis(1), None)
        .expect("online backup completes");
    drop(backup);
    let copied: Vec<(i64, String)> = destination
        .prepare("SELECT generation, value FROM durable_cut ORDER BY generation")
        .expect("backup table prepares")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("backup rows query")
        .collect::<Result<_, _>>()
        .expect("backup rows decode");
    assert_eq!(copied, vec![(1, "before-cut".into()), (2, "at-cut".into())]);
}

#[test]
fn matching_dual_root_restore_pending_metadata_is_closed_and_irreversible() {
    let restore_identity = digest_hex(0x81);
    let attestation = digest_hex(0x82);
    let inventory = digest_hex(0x83);
    let exact = canonical(&json!({
        "schema": "helixos.recovery-root-metadata/1",
        "root_identity_sha256": digest_hex(0x84),
        "root_lifecycle_state": "RESTORE_PENDING",
        "state_generation": 1,
        "at_rest_profile_id": "at-rest.synthetic-v1",
        "restore_identity_sha256": restore_identity,
        "provenance_attestation_sha256": attestation,
        "source_inventory_sha256": inventory
    }));
    decode_recovery_root_metadata_v1(&exact)
        .expect("complete independently durable recovery pending metadata decodes");

    for field in [
        "restore_identity_sha256",
        "provenance_attestation_sha256",
        "source_inventory_sha256",
    ] {
        let mut missing: Value = serde_json::from_slice(&exact).unwrap();
        missing.as_object_mut().unwrap().remove(field);
        assert!(decode_recovery_root_metadata_v1(&canonical(&missing)).is_err());
    }
    let active_with_pending_fields = canonical(&json!({
        "schema": "helixos.recovery-root-metadata/1",
        "root_identity_sha256": digest_hex(0x84),
        "root_lifecycle_state": "ACTIVE",
        "state_generation": 0,
        "at_rest_profile_id": "at-rest.synthetic-v1",
        "restore_identity_sha256": digest_hex(0x81),
        "provenance_attestation_sha256": digest_hex(0x82),
        "source_inventory_sha256": digest_hex(0x83)
    }));
    assert!(decode_recovery_root_metadata_v1(&active_with_pending_fields).is_err());
}

#[test]
fn production_quiescent_backup_pipeline_covers_every_required_cut_boundary() {
    let required = [
        "BackupPausePersisted",
        "BackupProviderMaintenanceGuardAcquired",
        "BackupCoordinatorMaintenanceGuardAcquired",
        "BackupSourceProfilesVerified",
        "BackupSourceInvariantsVerified",
        "BackupSourceGenerationsCaptured",
        "BackupSqliteOnlineBackupCompleted",
        "BackupSqliteOnlineBackupClosed",
        "BackupSqliteOnlineBackupIntegrityChecked",
        "BackupSqliteOnlineBackupHashed",
        "BackupProviderEnumerationReconciled",
        "BackupMaterialPresentPackageExported",
        "BackupRetirementTombstoneExported",
        "BackupInventoryJcsFinalized",
        "BackupSourceGenerationsRechecked",
        "BackupTopLevelManifestStaged",
        "BackupTopLevelManifestPublished",
        "BackupAttestationProtectedJcsFinalized",
        "BackupAttestationSigned",
        "BackupAttestationStaged",
        "BackupAttestationPublished",
        "BackupAttestationReopened",
        "BackupAttestationVerified",
    ];
    assert!(required
        .iter()
        .all(|boundary| FAULT_SOURCE.contains(boundary)));
    let missing = required
        .iter()
        .copied()
        .filter(|boundary| !MAINTENANCE_SOURCE.contains(boundary))
        .collect::<Vec<_>>();
    let has_online_backup = MAINTENANCE_SOURCE.contains("rusqlite::backup")
        && MAINTENANCE_SOURCE.contains("Backup::new");
    assert!(
        missing.is_empty() && has_online_backup,
        "T069/T071 RED: quiescent production backup is not wired through SQLite online backup and all 23 cut boundaries; missing={missing:?}",
    );
}

#[test]
fn production_restore_publishes_matching_pending_metadata_to_both_empty_roots() {
    let required = [
        "RestorePackageAndPinnedProvenanceAccepted",
        "RestoreEmptyCoordinatorRootReserved",
        "RestoreEmptyRecoveryRootReserved",
        "RestoreCoordinatorDatabaseImported",
        "RestoreWalFullProfileEstablished",
        "RestoreRecoveryPackageImported",
        "RestoreCoordinatorRestorePendingCommitted",
        "RestoreRecoveryRestorePendingMetadataPublished",
        "RestoreBothRootsClosed",
        "RestoreBothRootsReopened",
        "RestoreBothRootsAgreementClassified",
        "RestoreVerifiedPreparationRestoreReturned",
        "RestoreQuarantinePersisted",
    ];
    assert!(required
        .iter()
        .all(|boundary| FAULT_SOURCE.contains(boundary)));
    let missing = required
        .iter()
        .copied()
        .filter(|boundary| !MAINTENANCE_SOURCE.contains(boundary))
        .collect::<Vec<_>>();
    let has_pending_root_protocol = MAINTENANCE_SOURCE.contains("RESTORE_PENDING")
        && MAINTENANCE_SOURCE.contains("restore_identity")
        && MAINTENANCE_SOURCE.contains("restore_attestation")
        && ROOT_SAFETY_SOURCE.contains("ProvisionedEmptyCoordinatorRootV1");
    assert!(
        missing.is_empty() && has_pending_root_protocol,
        "T072 RED: authenticated clean-root restore has not published/reopened/classified matching independently durable RESTORE_PENDING metadata; missing={missing:?}",
    );
}
