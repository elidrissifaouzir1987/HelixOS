//! PLAN-005 adapter-inbox backup manifest and production clean-restore coverage.
//!
//! These tests pin the adapter-v1 package, exact inventories and cross-store comparison
//! fields from the frozen schema. They also exercise empty, received and consumed lifecycle
//! cuts through the production backup and restore APIs without adding executable authority.

use ed25519_dalek::{Signer as _, SigningKey};
use helix_dispatch_contracts::{
    ContractError, Generation, GrantKeyResolver, GrantVerificationKeyV1, Identifier,
    ReceiptKeyResolver, ReceiptSigner, ReceiptVerificationKeyV1, Result as ContractResult, SafeU64,
    Sha256Digest,
};
use helix_dispatch_inbox_sqlite::{
    commit_adapter_dispatch_restore_to_pending_v1, inspect_adapter_dispatch_restore_destination_v1,
    prepare_adapter_dispatch_restore_v1, AdapterBackupPauseAuthorityV1,
    AdapterBackupPauseCustodyOutcomeV1, AdapterBackupPauseCustodyV1,
    AdapterBackupPauseValidationV1, AdapterClockObservationV1, AdapterClockV1,
    AdapterConsumptionAdmissionObservationV1, AdapterConsumptionAdmissionObserverV1,
    AdapterDispatchRestoreCountsV1, AdapterDispatchRestoreGenerationsV1,
    AdapterDispatchRestoreInventoriesV1, AdapterDispatchRestorePauseCustodyV1,
    AdapterDispatchRestorePauseValidationV1, AdapterDispatchRestoreSourceBindingsV1,
    AdapterInboxConsumeErrorV1, AdapterInboxConsumeOutcomeV1, AdapterInboxInitializationV1,
    AdapterInboxProfileV1, AdapterInboxReadbackOutcomeV1, AdapterInboxReceiveErrorV1,
    AdapterInboxReceiveOutcomeV1, AdapterInboxRetainedStateV1, AdapterInboxRootIdentityEvidenceV1,
    AdapterInboxStoreConfigV1, AdapterPausedDispatchRestoreV1, AdapterPausedQuiescenceV1,
    AdapterReceiptEntropyDomainV1, AdapterReceiptEntropyErrorV1, AdapterReceiptEntropyV1,
    AdapterReceiptSigningProfileV1, AdapterTimeSampleV1, EpochObservationV1,
    ProvisionedAdapterDispatchBackupDestinationV1, ProvisionedAdapterDispatchRestoreSourceV1,
    SqliteDispatchInboxStoreV1, SupervisorEpochObservationV1, SupervisorEpochObserverV1,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

const DISPATCH_BACKUP_SCHEMA: &str = include_str!(
    "../../../specs/005-durable-dispatch/contracts/dispatch-backup-manifest-v1.schema.json"
);
const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const FIXTURE_GRANT_KEY: [u8; 32] = [
    167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246, 103,
    165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
];
const FIXTURE_GRANT_ID: &str = "e11c10ad33af1f082a3b2028bdfa66d9a9413f430105d6d1b3c9c7e975d32dbd";
const FIXTURE_CAPABILITY_DIGEST: &str =
    "7bd116b849df045678b6521d504056fe77119b19a0eadb84d661878e6d5f667b";
const RECEIPT_KEY_ID: &str = "t096-adapter-receipt-key-v1";
const RECEIPT_PROFILE_DIGEST: [u8; 32] = [0x52; 32];
const RECONCILIATION_GRANT_SET_DOMAIN: &[u8] =
    b"HELIXOS\0DISPATCH-RESTORE\0ADAPTER-RECONCILIATION-GRANT-SET\0V1\0";
static NEXT_DYNAMIC_ROOT: AtomicU64 = AtomicU64::new(0);

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

#[test]
fn frozen_adapter_inbox_v1_package_is_exact_and_closed() {
    let schema = schema();
    let fields = [
        "root_identity_digest",
        "application_id",
        "user_version",
        "format_version",
        "schema_digest",
        "database_digest",
        "manifest_digest",
        "root_lifecycle_state",
        "supervisor_epoch",
        "generations",
        "counts",
        "inventory_digests",
    ];
    assert_exact_closed_object(&schema, "adapterPackage", &fields);
    let adapter = &definition(&schema, "adapterPackage")["properties"];
    assert_eq!(
        adapter["application_id"]["const"].as_u64(),
        Some(1_212_962_889)
    );
    assert_eq!(adapter["user_version"]["const"].as_u64(), Some(1));
    assert_eq!(adapter["format_version"]["const"].as_u64(), Some(1));
    assert_eq!(
        strings(
            &adapter["root_lifecycle_state"]["enum"],
            "adapter lifecycle"
        ),
        expected(&["ACTIVE", "RESTORE_PENDING"])
    );
    for (member, target) in [
        ("generations", "#/$defs/adapterGenerations"),
        ("counts", "#/$defs/adapterCounts"),
        ("inventory_digests", "#/$defs/adapterInventories"),
    ] {
        assert_eq!(adapter[member]["$ref"].as_str(), Some(target));
    }
    for member in [
        "root_identity_digest",
        "schema_digest",
        "database_digest",
        "manifest_digest",
    ] {
        assert_eq!(adapter[member]["$ref"].as_str(), Some("#/$defs/digest"));
    }
}

#[test]
fn adapter_generation_count_and_inventory_sets_are_exhaustive() {
    let schema = schema();
    let generation_fields = [
        "store",
        "inbox",
        "consumption",
        "receipt",
        "conflict",
        "quarantine",
        "event",
        "epoch_observer",
        "restore_state",
    ];
    assert_exact_closed_object(&schema, "adapterGenerations", &generation_fields);
    assert_property_refs(
        &schema,
        "adapterGenerations",
        &[
            "store",
            "inbox",
            "consumption",
            "receipt",
            "conflict",
            "quarantine",
            "event",
            "restore_state",
        ],
        "#/$defs/safeInteger",
    );
    assert_eq!(
        definition(&schema, "adapterGenerations")["properties"]["epoch_observer"]["$ref"].as_str(),
        Some("#/$defs/positiveSafeInteger")
    );
    let count_fields = [
        "inbox_entries",
        "transitions",
        "receipts",
        "conflicts",
        "quarantines",
        "events",
    ];
    assert_exact_closed_object(&schema, "adapterCounts", &count_fields);
    assert_property_refs(
        &schema,
        "adapterCounts",
        &count_fields,
        "#/$defs/safeInteger",
    );
    let inventory_fields = [
        "inbox_entries",
        "transitions",
        "receipts",
        "conflicts",
        "quarantines",
        "events",
        "complete_store",
    ];
    assert_exact_closed_object(&schema, "adapterInventories", &inventory_fields);
    assert_property_refs(
        &schema,
        "adapterInventories",
        &inventory_fields,
        "#/$defs/digest",
    );
}

#[test]
fn cross_store_inventory_is_complete_canonical_and_orphan_explicit() {
    let schema = schema();
    let fields = [
        "canonicalization_profile",
        "coordinator_grant_count",
        "adapter_grant_count",
        "coordinator_receipt_count",
        "adapter_receipt_count",
        "matched_grant_count",
        "matched_receipt_count",
        "orphan_coordinator_grant_count",
        "orphan_adapter_grant_count",
        "orphan_coordinator_receipt_count",
        "orphan_adapter_receipt_count",
        "coordinator_grants_digest",
        "adapter_grants_digest",
        "coordinator_receipts_digest",
        "adapter_receipts_digest",
        "grant_relationships_digest",
        "receipt_relationships_digest",
        "complete_inventory_digest",
    ];
    assert_exact_closed_object(&schema, "crossStoreInventory", &fields);
    let inventory = &definition(&schema, "crossStoreInventory")["properties"];
    assert_eq!(
        inventory["canonicalization_profile"]["const"].as_str(),
        Some("helixos.dispatch-backup-inventory/rfc8785-sorted-v1")
    );
    for field in fields {
        if field == "canonicalization_profile" {
            continue;
        }
        let expected_ref = if field.ends_with("_count") {
            "#/$defs/safeInteger"
        } else {
            "#/$defs/digest"
        };
        assert_eq!(
            inventory[field]["$ref"].as_str(),
            Some(expected_ref),
            "cross-store field {field} has the wrong closed scalar contract"
        );
    }
}

#[test]
fn adapter_cannot_substitute_itself_for_other_backup_steps_or_signer_profiles() {
    let schema = schema();
    let order = definition(&schema, "backupOrder")["prefixItems"]
        .as_array()
        .unwrap_or_else(|| panic!("backup order must be a closed prefix"));
    assert_eq!(
        order[0]["$ref"].as_str(),
        Some("#/$defs/coordinatorBackupStep")
    );
    assert_eq!(order[1]["$ref"].as_str(), Some("#/$defs/adapterBackupStep"));
    assert_eq!(order[2]["$ref"].as_str(), Some("#/$defs/indexPublishStep"));
    assert_eq!(
        definition(&schema, "adapterBackupStep")["properties"]["component"]["const"].as_str(),
        Some("adapter-inbox-v1")
    );

    let key_sets = &definition(&schema, "verificationKeySets")["properties"];
    let targets = [
        key_sets["grant_signing_history"]["items"]["$ref"]
            .as_str()
            .expect("grant history ref"),
        key_sets["receipt_signing_history"]["items"]["$ref"]
            .as_str()
            .expect("receipt history ref"),
        key_sets["backup_provisioner_history"]["items"]["$ref"]
            .as_str()
            .expect("backup history ref"),
    ];
    assert_eq!(targets.into_iter().collect::<BTreeSet<_>>().len(), 3);
    assert_eq!(
        definition(&schema, "indexSignatureProfile")["properties"]["key_purpose"]["const"].as_str(),
        Some("dispatch-backup-provisioner")
    );
    assert_eq!(
        definition(&schema, "indexSignatureProfile")["properties"]["signature_domain"]["const"]
            .as_str(),
        Some("HELIXOS\0DISPATCH-BACKUP-INDEX\0V1\0")
    );
}

#[test]
fn production_adapter_manifest_module_must_supply_closed_canonical_codecs() {
    let manifest = required_production_source(
        "manifest.rs",
        "T075 adapter inbox V1 manifest and inventory codecs",
    );
    let crate_root = required_production_source("lib.rs", "T075 adapter module wiring");
    assert!(
        crate_root.contains("mod manifest;"),
        "T071 RED: adapter crate root must compile src/manifest.rs"
    );
    for required in [
        "AdapterInboxBackupManifestV1",
        "decode_adapter_inbox_backup_manifest_v1",
        "finalize_adapter_inbox_backup_manifest_v1",
        "serde_json_canonicalizer",
        "deny_unknown_fields",
        "adapter-inbox-v1",
        "root_identity_digest",
        "supervisor_epoch",
        "epoch_observer",
        "inventory_digests",
        "complete_store",
    ] {
        assert!(
            manifest.contains(required),
            "T071 RED: adapter backup manifest codec omits `{required}`"
        );
    }
}

#[test]
fn production_adapter_backup_restore_matrix_is_fresh_pending_paused_and_idempotent() {
    for cut in [
        AdapterLifecycleCutV1::Empty,
        AdapterLifecycleCutV1::Received,
        AdapterLifecycleCutV1::Consumed,
    ] {
        run_production_adapter_restore_case_v1(cut);
    }
}

fn run_production_adapter_restore_case_v1(cut: AdapterLifecycleCutV1) {
    let roots = DynamicRestoreRootsV1::new(cut.label());
    let source_root_identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(
        [0x41_u8.wrapping_add(cut.ordinal()); 32],
    );
    let new_root_identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes(
        [0x81_u8.wrapping_add(cut.ordinal()); 32],
    );
    let store = initialize_dynamic_store_v1(&roots.source, source_root_identity);
    let canonical_grant = canonical_fixture_grant_v1();
    let current_grant = FixtureGrantResolverV1::current();
    let receipt_authority = ReceiptAuthorityV1::new();
    let signing_profile = receipt_signing_profile_v1(&receipt_authority);

    match cut {
        AdapterLifecycleCutV1::Empty => {}
        AdapterLifecycleCutV1::Received => {
            drop(receive_fixture_grant_v1(
                &store,
                &canonical_grant,
                &current_grant,
            ));
        }
        AdapterLifecycleCutV1::Consumed => {
            let received = receive_fixture_grant_v1(&store, &canonical_grant, &current_grant);
            let clock = FixedClockV1::new(1_000_200, 1_200);
            let epoch = FixedEpochObserverV1::new(15, 3, 1_000_201, 1_201);
            let admission = FixedAdmissionV1;
            let entropy = FixedEntropyV1;
            assert!(matches!(
                store
                    .consume_received_v1(
                        received,
                        &current_grant,
                        &clock,
                        &epoch,
                        &admission,
                        &entropy,
                        &signing_profile,
                        &receipt_authority,
                        &receipt_authority,
                    )
                    .expect("T096 production consumption commits before backup"),
                AdapterInboxConsumeOutcomeV1::Consumed(_)
            ));
            assert_eq!(receipt_authority.signer_calls(), 1);
        }
    }

    let source_before_backup = read_dynamic_snapshot_v1(&roots.source_database());
    assert_eq!(
        source_before_backup.meta.root_identity,
        source_root_identity.to_attested_bytes()
    );
    assert_eq!(source_before_backup.meta.root_lifecycle_state, "ACTIVE");
    assert_eq!(source_before_backup.inbox_count, cut.inbox_count());
    assert_eq!(source_before_backup.receipt_count, cut.receipt_count());
    assert_eq!(
        source_before_backup
            .grant
            .as_ref()
            .map(|grant| grant.inbox_state.as_str()),
        cut.source_inbox_state()
    );

    let backup_pause = BackupPauseAuthorityV1::new(15);
    let backup_destination =
        ProvisionedAdapterDispatchBackupDestinationV1::try_reserve_create_only(
            roots.backup.clone(),
        )
        .expect("T096 create-only adapter backup destination reserves");
    let backup = store
        .backup_paused_dispatch_inbox_v1(
            &backup_pause,
            backup_destination,
            1_900_000_000_096_u64 + u64::from(cut.ordinal()),
            10_000,
        )
        .expect("T096 production paused adapter backup succeeds");
    assert_eq!(backup_pause.rechecks(), 4);
    assert_eq!(backup_pause.releases(), 1);
    drop(store);
    assert_eq!(
        read_dynamic_snapshot_v1(&roots.source_database()),
        source_before_backup,
        "{cut:?}: backup must not mutate the source graph"
    );
    let reopened_source = reopen_dynamic_store_v1(&roots.source, source_root_identity);
    assert_eq!(
        read_dynamic_snapshot_v1(&roots.source_database()),
        source_before_backup,
        "{cut:?}: strict reopen after live-store backup must preserve the source graph"
    );
    drop(reopened_source);
    assert_eq!(backup.grants().len(), cut.inbox_count() as usize);
    assert_eq!(backup.receipts().len(), cut.receipt_count() as usize);

    let manifest: Value = serde_json::from_slice(backup.manifest_package_bytes())
        .expect("T096 canonical adapter manifest package parses");
    assert_eq!(
        manifest_u64_v1(&manifest, &["counts", "inbox_entries"]),
        cut.inbox_count()
    );
    assert_eq!(
        manifest_u64_v1(&manifest, &["counts", "receipts"]),
        cut.receipt_count()
    );
    assert_eq!(
        manifest_digest_v1(&manifest, &["database_digest"]),
        backup.database_sha256()
    );
    let source_bindings = restore_source_bindings_v1(&manifest, source_root_identity);
    let source_database = roots.backup.join("published").join("adapter-inbox.sqlite3");
    let source_length = fs::metadata(&source_database)
        .expect("T096 retained adapter member metadata reads")
        .len();

    let destination = AdapterInboxStoreConfigV1::try_new_empty_attested(
        roots.restored.clone(),
        new_root_identity,
        25,
    )
    .expect("T096 independently provisioned restore root is attested");
    let initial_destination = inspect_adapter_dispatch_restore_destination_v1(&destination)
        .expect("T096 clean destination rescans before copy");
    assert!(initial_destination.is_fresh());
    assert_eq!(initial_destination.entry_count(), 0);

    let source_supervisor_epoch = manifest_u64_v1(&manifest, &["supervisor_epoch"]);
    let source_epoch_observer_generation =
        manifest_u64_v1(&manifest, &["generations", "epoch_observer"]);
    let new_supervisor_epoch = source_supervisor_epoch + 1;
    let new_epoch_observer_generation = source_epoch_observer_generation + 1;
    let restore_index_digest = [0x91_u8.wrapping_add(cut.ordinal()); 32];
    let paused = AdapterPausedDispatchRestoreV1::try_new(
        source_root_identity,
        new_root_identity,
        [0x61_u8.wrapping_add(cut.ordinal()); 32],
        [0x71_u8.wrapping_add(cut.ordinal()); 32],
        source_supervisor_epoch,
        new_supervisor_epoch,
        source_epoch_observer_generation,
        new_epoch_observer_generation,
        restore_index_digest,
        17,
        19,
    )
    .expect("T096 fresh root and rotated supervisor PAUSE authority validates");
    assert_ne!(paused.source_root_identity(), paused.new_root_identity());
    assert_ne!(
        paused.source_supervisor_identity(),
        paused.new_supervisor_identity()
    );
    assert!(paused.new_supervisor_epoch() > paused.source_supervisor_epoch());
    assert!(paused.new_epoch_observer_generation() > paused.source_epoch_observer_generation());
    let source = ProvisionedAdapterDispatchRestoreSourceV1::try_new(
        fs::File::open(&source_database).expect("T096 retained source opens read-only"),
        source_length,
        backup.database_sha256(),
        source_bindings,
    )
    .expect("T096 retained source is length, digest and manifest bound");
    let (mut custody, restore_rechecks, restore_releases) = RestorePauseCustodyV1::new(paused);
    let prepared = prepare_adapter_dispatch_restore_v1(&mut custody, paused, source, destination)
        .expect("T096 production adapter restore copy prepares");
    let restored = commit_adapter_dispatch_restore_to_pending_v1(&mut custody, prepared)
        .expect("T096 production adapter restore commits pending and strictly reopens");
    assert_eq!(restore_rechecks.load(Ordering::SeqCst), 6);
    custody.release();
    assert_eq!(restore_releases.load(Ordering::SeqCst), 1);

    let expected_grant_ids = cut
        .has_reconciliation_candidate()
        .then(|| *fixture_grant_id_v1().as_bytes())
        .into_iter()
        .collect::<Vec<_>>();
    let expected_proof_count = expected_grant_ids.len() as u64;
    assert_eq!(restored.root_identity(), new_root_identity);
    assert_eq!(restored.root_lifecycle_code(), "RESTORE_PENDING");
    assert_eq!(restored.control_state_code(), "PAUSED");
    assert_eq!(restored.restore_index_digest(), restore_index_digest);
    assert_eq!(
        restored.pause_evidence_digest(),
        paused.pause_evidence_digest()
    );
    assert_eq!(restored.initial_destination_entry_count(), 0);
    assert_eq!(restored.automatic_consumption_count(), 0);
    assert_eq!(restored.automatic_redelivery_count(), 0);
    assert_eq!(
        restored.possible_consumption_quarantine_count(),
        expected_proof_count
    );
    assert_eq!(
        restored.reconciliation_required_count(),
        expected_proof_count
    );
    assert_eq!(
        restored.reconciliation_grant_ids(),
        expected_grant_ids.as_slice()
    );
    assert_eq!(
        restored.reconciliation_grant_set_digest(),
        reconciliation_grant_set_digest_v1(&expected_grant_ids)
    );
    assert_eq!(
        restored.source_inventory_digest(),
        manifest_digest_v1(&manifest, &["inventory_digests", "complete_store"])
    );
    if expected_proof_count == 0 {
        assert_eq!(
            restored.source_inventory_digest(),
            restored.restored_inventory_digest()
        );
    } else {
        assert_ne!(
            restored.source_inventory_digest(),
            restored.restored_inventory_digest()
        );
    }

    let restored_database = roots.restored_database();
    let restored_snapshot = read_dynamic_snapshot_v1(&restored_database);
    assert_eq!(
        restored_snapshot.meta.root_identity,
        new_root_identity.to_attested_bytes()
    );
    assert_eq!(
        restored_snapshot.meta.root_lifecycle_state,
        "RESTORE_PENDING"
    );
    assert_eq!(
        restored_snapshot.meta.supervisor_epoch,
        new_supervisor_epoch as i64
    );
    assert_eq!(
        restored_snapshot.meta.epoch_observer_generation,
        new_epoch_observer_generation as i64
    );
    assert_eq!(
        restored_snapshot.meta.restore_index_digest,
        Some(restore_index_digest.to_vec())
    );
    assert_eq!(
        restored_snapshot.meta.restore_state_generation,
        restored_snapshot.meta.store_generation
    );
    assert_eq!(
        restored_snapshot.meta.store_generation,
        source_before_backup.meta.store_generation + expected_proof_count as i64 + 1
    );
    assert_eq!(
        restored_snapshot.meta.inbox_generation,
        source_before_backup.meta.inbox_generation
    );
    assert_eq!(
        restored_snapshot.meta.consumption_generation,
        source_before_backup.meta.consumption_generation
    );
    assert_eq!(
        restored_snapshot.meta.receipt_generation,
        source_before_backup.meta.receipt_generation
    );
    assert_eq!(
        restored_snapshot.meta.conflict_generation,
        source_before_backup.meta.conflict_generation
    );
    assert_eq!(
        restored_snapshot.meta.event_generation,
        source_before_backup.meta.event_generation
    );
    let expected_quarantine_generation = if expected_proof_count == 0 {
        source_before_backup.meta.quarantine_generation
    } else {
        source_before_backup.meta.store_generation + expected_proof_count as i64
    };
    assert_eq!(
        restored_snapshot.meta.quarantine_generation,
        expected_quarantine_generation
    );
    assert_eq!(restored_snapshot.grant, source_before_backup.grant);
    assert_eq!(restored_snapshot.receipt, source_before_backup.receipt);
    assert_eq!(
        restored_snapshot.transition_count,
        source_before_backup.transition_count
    );
    assert_eq!(
        restored_snapshot.conflict_count,
        source_before_backup.conflict_count
    );
    assert_eq!(
        restored_snapshot.event_count,
        source_before_backup.event_count
    );
    assert_eq!(
        restored_snapshot.quarantine_count,
        source_before_backup.quarantine_count + expected_proof_count
    );

    let proofs = read_restore_reconciliation_proofs_v1(
        &restored_database,
        source_before_backup.meta.quarantine_generation,
    );
    assert_eq!(proofs.len(), expected_grant_ids.len());
    for (index, (proof, grant_id)) in proofs.iter().zip(&expected_grant_ids).enumerate() {
        assert_eq!(proof.quarantine_id.len(), 32);
        assert_eq!(proof.grant_id.as_slice(), grant_id.as_slice());
        assert_eq!(proof.evidence_digest.len(), 32);
        assert_eq!(proof.public_reason_code, "RESTORE_RECONCILIATION_REQUIRED");
        assert_eq!(proof.resolved_generation, None);
        assert_eq!(
            proof.quarantine_generation,
            source_before_backup.meta.store_generation + index as i64 + 1
        );
    }

    let before_authority_probes = restored_snapshot.clone();
    let pending_config = AdapterInboxStoreConfigV1::try_new_existing_attested(
        roots.restored.clone(),
        new_root_identity,
        25,
    )
    .expect("T096 pending root remains provisioner-attested");
    let pending_store =
        SqliteDispatchInboxStoreV1::open_existing_v1(pending_config, dynamic_adapter_profile_v1())
            .expect("T096 RESTORE_PENDING root strictly reopens");
    if cut == AdapterLifecycleCutV1::Empty {
        let clock = FixedClockV1::new(1_000_100, 1_100);
        let epoch = FixedEpochObserverV1::new(15, 20, 1_000_101, 1_101);
        assert_eq!(
            pending_store
                .receive_grant_v1(&canonical_grant, &current_grant, &clock, &epoch)
                .expect_err("T096 pending empty root must deny new adapter authority"),
            AdapterInboxReceiveErrorV1::RestorePending
        );
    } else {
        let historical_grant = FixtureGrantResolverV1::historical();
        let unavailable_clock = UnavailableClockV1::new();
        let unavailable_epoch = UnavailableEpochObserverV1::new();
        let duplicate = pending_store
            .receive_grant_v1(
                &canonical_grant,
                &historical_grant,
                &unavailable_clock,
                &unavailable_epoch,
            )
            .expect("T096 historical exact bytes return retained evidence only");
        let AdapterInboxReceiveOutcomeV1::ExactDuplicate(duplicate) = duplicate else {
            panic!("{cut:?}: old exact bytes must not become new receive authority");
        };
        assert_eq!(
            duplicate.state(),
            cut.retained_state().expect("nonempty cut")
        );
        assert_eq!(duplicate.receipt_retained(), cut.receipt_count() == 1);
        assert_eq!(unavailable_clock.calls(), 0);
        assert_eq!(unavailable_epoch.calls(), 0);

        if cut == AdapterLifecycleCutV1::Received {
            let AdapterInboxReadbackOutcomeV1::Received(received) = pending_store
                .readback_grant_v1(fixture_grant_id_v1(), &historical_grant, &receipt_authority)
                .expect("T096 retained RECEIVED evidence reads without renewal")
            else {
                panic!("T096 retained RECEIVED evidence must remain exact");
            };
            let clock = UnavailableClockV1::new();
            let epoch = UnavailableEpochObserverV1::new();
            let admission = UnavailableAdmissionV1::new();
            let entropy = UnavailableEntropyV1::new();
            let signer_calls = receipt_authority.signer_calls();
            assert_eq!(
                pending_store
                    .consume_received_v1(
                        received,
                        &historical_grant,
                        &clock,
                        &epoch,
                        &admission,
                        &entropy,
                        &signing_profile,
                        &receipt_authority,
                        &receipt_authority,
                    )
                    .expect_err("T096 pending root must deny re-consumption"),
                AdapterInboxConsumeErrorV1::RestorePending
            );
            assert_eq!(clock.calls(), 0);
            assert_eq!(epoch.calls(), 0);
            assert_eq!(admission.calls(), 0);
            assert_eq!(entropy.calls(), 0);
            assert_eq!(receipt_authority.signer_calls(), signer_calls);
        }
    }
    drop(pending_store);
    assert_eq!(
        read_dynamic_snapshot_v1(&restored_database),
        before_authority_probes,
        "{cut:?}: old-authority probes must mutate no generation or history"
    );

    let retry_destination = AdapterInboxStoreConfigV1::try_new_existing_attested(
        roots.restored.clone(),
        new_root_identity,
        25,
    )
    .expect("T096 exact pending destination reattests for retry");
    let retry_observation = inspect_adapter_dispatch_restore_destination_v1(&retry_destination)
        .expect("T096 retry destination rescans");
    assert!(retry_observation.is_retry());
    let retry_source = ProvisionedAdapterDispatchRestoreSourceV1::try_new(
        fs::File::open(&source_database).expect("T096 retry source reopens read-only"),
        source_length,
        backup.database_sha256(),
        source_bindings,
    )
    .expect("T096 retry source remains exactly bound");
    let (mut retry_custody, retry_rechecks, retry_releases) = RestorePauseCustodyV1::new(paused);
    let retry_prepared = prepare_adapter_dispatch_restore_v1(
        &mut retry_custody,
        paused,
        retry_source,
        retry_destination,
    )
    .expect("T096 exact retry prepares without mutation");
    let retried = commit_adapter_dispatch_restore_to_pending_v1(&mut retry_custody, retry_prepared)
        .expect("T096 exact retry reopens pending idempotently");
    assert!(retry_rechecks.load(Ordering::SeqCst) >= 5);
    retry_custody.release();
    assert_eq!(retry_releases.load(Ordering::SeqCst), 1);
    assert_eq!(retried.root_identity(), restored.root_identity());
    assert_eq!(retried.store_generation(), restored.store_generation());
    assert_eq!(retried.inbox_count(), restored.inbox_count());
    assert_eq!(retried.receipt_count(), restored.receipt_count());
    assert_eq!(
        retried.source_inventory_digest(),
        restored.source_inventory_digest()
    );
    assert_eq!(
        retried.restored_inventory_digest(),
        restored.restored_inventory_digest()
    );
    assert_eq!(
        retried.reconciliation_required_count(),
        restored.reconciliation_required_count()
    );
    assert_eq!(
        retried.reconciliation_grant_set_digest(),
        restored.reconciliation_grant_set_digest()
    );
    assert_eq!(
        retried.reconciliation_grant_ids(),
        restored.reconciliation_grant_ids()
    );
    assert_eq!(retried.automatic_consumption_count(), 0);
    assert_eq!(retried.automatic_redelivery_count(), 0);
    assert_eq!(
        read_dynamic_snapshot_v1(&restored_database),
        before_authority_probes,
        "{cut:?}: exact retry must append no second quarantine or generation"
    );
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterLifecycleCutV1 {
    Empty,
    Received,
    Consumed,
}

impl AdapterLifecycleCutV1 {
    const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Received => "received",
            Self::Consumed => "consumed",
        }
    }

    const fn ordinal(self) -> u8 {
        match self {
            Self::Empty => 0,
            Self::Received => 1,
            Self::Consumed => 2,
        }
    }

    const fn inbox_count(self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::Received | Self::Consumed => 1,
        }
    }

    const fn receipt_count(self) -> u64 {
        match self {
            Self::Consumed => 1,
            Self::Empty | Self::Received => 0,
        }
    }

    const fn source_inbox_state(self) -> Option<&'static str> {
        match self {
            Self::Empty => None,
            Self::Received => Some("RECEIVED"),
            Self::Consumed => Some("CONSUMED"),
        }
    }

    const fn retained_state(self) -> Option<AdapterInboxRetainedStateV1> {
        match self {
            Self::Empty => None,
            Self::Received => Some(AdapterInboxRetainedStateV1::Received),
            Self::Consumed => Some(AdapterInboxRetainedStateV1::Consumed),
        }
    }

    const fn has_reconciliation_candidate(self) -> bool {
        !matches!(self, Self::Empty)
    }
}

struct DynamicRestoreRootsV1 {
    base: PathBuf,
    source: PathBuf,
    backup: PathBuf,
    restored: PathBuf,
}

impl DynamicRestoreRootsV1 {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DYNAMIC_ROOT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "helixos-t096-adapter-{label}-{}-{sequence}",
            std::process::id()
        ));
        let source = base.join("source");
        let restored = base.join("restored");
        fs::create_dir_all(&source).expect("T096 source root creates");
        fs::create_dir(&restored).expect("T096 clean restore root creates");
        Self {
            backup: base.join("backup"),
            base,
            source,
            restored,
        }
    }

    fn source_database(&self) -> PathBuf {
        self.source.join("dispatch-inbox.sqlite3")
    }

    fn restored_database(&self) -> PathBuf {
        self.restored.join("dispatch-inbox.sqlite3")
    }
}

impl Drop for DynamicRestoreRootsV1 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[derive(Clone, Copy)]
enum FixtureGrantTrustV1 {
    Current,
    Historical,
}

struct FixtureGrantResolverV1(FixtureGrantTrustV1);

impl FixtureGrantResolverV1 {
    const fn current() -> Self {
        Self(FixtureGrantTrustV1::Current)
    }

    const fn historical() -> Self {
        Self(FixtureGrantTrustV1::Historical)
    }
}

impl GrantKeyResolver for FixtureGrantResolverV1 {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        if key_id != "fixture-grant-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(match self.0 {
            FixtureGrantTrustV1::Current => GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY),
            FixtureGrantTrustV1::Historical => {
                GrantVerificationKeyV1::historical(FIXTURE_GRANT_KEY)
            }
        })
    }
}

struct ReceiptAuthorityV1 {
    signing_key: SigningKey,
    signer_calls: AtomicUsize,
}

impl ReceiptAuthorityV1 {
    fn new() -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&[0x74; 32]),
            signer_calls: AtomicUsize::new(0),
        }
    }

    fn fingerprint(&self) -> Sha256Digest {
        Sha256Digest::digest(self.signing_key.verifying_key().as_bytes())
    }

    fn signer_calls(&self) -> usize {
        self.signer_calls.load(Ordering::Relaxed)
    }
}

impl ReceiptSigner for ReceiptAuthorityV1 {
    fn key_id(&self) -> &str {
        RECEIPT_KEY_ID
    }

    fn sign_execution_receipt(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        self.signer_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.signing_key.sign(message).to_bytes())
    }
}

impl ReceiptKeyResolver for ReceiptAuthorityV1 {
    fn resolve_receipt_key(&self, key_id: &str) -> ContractResult<ReceiptVerificationKeyV1> {
        if key_id != RECEIPT_KEY_ID {
            return Err(ContractError::UnknownKey);
        }
        Ok(ReceiptVerificationKeyV1::current(
            self.signing_key.verifying_key().to_bytes(),
        ))
    }
}

struct FixedClockV1 {
    utc_ms: u64,
    monotonic_ms: u64,
}

impl FixedClockV1 {
    const fn new(utc_ms: u64, monotonic_ms: u64) -> Self {
        Self {
            utc_ms,
            monotonic_ms,
        }
    }
}

impl AdapterClockV1 for FixedClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        AdapterClockObservationV1::Current(time_sample_v1(10, self.utc_ms, self.monotonic_ms))
    }
}

struct FixedEpochObserverV1 {
    supervisor_epoch: u64,
    observer_generation: u64,
    utc_ms: u64,
    monotonic_ms: u64,
}

impl FixedEpochObserverV1 {
    const fn new(
        supervisor_epoch: u64,
        observer_generation: u64,
        utc_ms: u64,
        monotonic_ms: u64,
    ) -> Self {
        Self {
            supervisor_epoch,
            observer_generation,
            utc_ms,
            monotonic_ms,
        }
    }
}

impl SupervisorEpochObserverV1 for FixedEpochObserverV1 {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
        SupervisorEpochObservationV1::Current(EpochObservationV1::new(
            SafeU64::new(self.supervisor_epoch).expect("T096 supervisor epoch is safe"),
            Generation::new(self.observer_generation)
                .expect("T096 epoch observer generation is non-zero"),
            time_sample_v1(20, self.utc_ms, self.monotonic_ms),
        ))
    }
}

struct FixedAdmissionV1;

impl AdapterConsumptionAdmissionObserverV1 for FixedAdmissionV1 {
    fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1 {
        AdapterConsumptionAdmissionObservationV1::Running
    }
}

struct FixedEntropyV1;

impl AdapterReceiptEntropyV1 for FixedEntropyV1 {
    fn fill_receipt_entropy_v1(
        &self,
        domain: AdapterReceiptEntropyDomainV1,
        destination: &mut [u8; 32],
    ) -> Result<(), AdapterReceiptEntropyErrorV1> {
        assert_eq!(domain, AdapterReceiptEntropyDomainV1::ReceiptIdentity);
        destination.fill(0xa6);
        Ok(())
    }
}

struct UnavailableClockV1(AtomicUsize);

impl UnavailableClockV1 {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn calls(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl AdapterClockV1 for UnavailableClockV1 {
    fn observe_time_v1(&self) -> AdapterClockObservationV1 {
        self.0.fetch_add(1, Ordering::Relaxed);
        AdapterClockObservationV1::Unavailable
    }
}

struct UnavailableEpochObserverV1(AtomicUsize);

impl UnavailableEpochObserverV1 {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn calls(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl SupervisorEpochObserverV1 for UnavailableEpochObserverV1 {
    fn observe_supervisor_epoch_v1(&self) -> SupervisorEpochObservationV1 {
        self.0.fetch_add(1, Ordering::Relaxed);
        SupervisorEpochObservationV1::Unavailable
    }
}

struct UnavailableAdmissionV1(AtomicUsize);

impl UnavailableAdmissionV1 {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn calls(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl AdapterConsumptionAdmissionObserverV1 for UnavailableAdmissionV1 {
    fn observe_consumption_admission_v1(&self) -> AdapterConsumptionAdmissionObservationV1 {
        self.0.fetch_add(1, Ordering::Relaxed);
        AdapterConsumptionAdmissionObservationV1::Unavailable
    }
}

struct UnavailableEntropyV1(AtomicUsize);

impl UnavailableEntropyV1 {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn calls(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl AdapterReceiptEntropyV1 for UnavailableEntropyV1 {
    fn fill_receipt_entropy_v1(
        &self,
        _domain: AdapterReceiptEntropyDomainV1,
        _destination: &mut [u8; 32],
    ) -> Result<(), AdapterReceiptEntropyErrorV1> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(AdapterReceiptEntropyErrorV1::Unavailable)
    }
}

struct BackupPauseAuthorityV1 {
    supervisor_epoch: u64,
    rechecks: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
}

impl BackupPauseAuthorityV1 {
    fn new(supervisor_epoch: u64) -> Self {
        Self {
            supervisor_epoch,
            rechecks: Arc::new(AtomicUsize::new(0)),
            releases: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn rechecks(&self) -> usize {
        self.rechecks.load(Ordering::SeqCst)
    }

    fn releases(&self) -> usize {
        self.releases.load(Ordering::SeqCst)
    }
}

struct BackupPauseCustodyV1 {
    paused: AdapterPausedQuiescenceV1,
    rechecks: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
}

impl AdapterBackupPauseAuthorityV1 for BackupPauseAuthorityV1 {
    type Custody = BackupPauseCustodyV1;

    fn persist_pause_fence_and_drain_v1(
        &self,
        _deadline_monotonic_ms: u64,
    ) -> AdapterBackupPauseCustodyOutcomeV1<Self::Custody> {
        AdapterBackupPauseCustodyOutcomeV1::Acquired(BackupPauseCustodyV1 {
            paused: AdapterPausedQuiescenceV1::try_new(self.supervisor_epoch, 7, 9, 0)
                .expect("T096 PAUSE/quiescence evidence is bounded"),
            rechecks: Arc::clone(&self.rechecks),
            releases: Arc::clone(&self.releases),
        })
    }
}

impl AdapterBackupPauseCustodyV1 for BackupPauseCustodyV1 {
    fn capture_paused_quiescence_v1(
        &mut self,
    ) -> Result<AdapterPausedQuiescenceV1, AdapterBackupPauseValidationV1> {
        Ok(self.paused)
    }

    fn recheck_paused_quiescence_v1(
        &mut self,
        expected: &AdapterPausedQuiescenceV1,
    ) -> AdapterBackupPauseValidationV1 {
        self.rechecks.fetch_add(1, Ordering::SeqCst);
        if expected == &self.paused {
            AdapterBackupPauseValidationV1::Exact
        } else {
            AdapterBackupPauseValidationV1::Unhealthy
        }
    }

    fn release(self) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

struct RestorePauseCustodyV1 {
    paused: AdapterPausedDispatchRestoreV1,
    rechecks: Arc<AtomicUsize>,
    releases: Arc<AtomicUsize>,
}

impl RestorePauseCustodyV1 {
    fn new(paused: AdapterPausedDispatchRestoreV1) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let rechecks = Arc::new(AtomicUsize::new(0));
        let releases = Arc::new(AtomicUsize::new(0));
        (
            Self {
                paused,
                rechecks: Arc::clone(&rechecks),
                releases: Arc::clone(&releases),
            },
            rechecks,
            releases,
        )
    }
}

impl AdapterDispatchRestorePauseCustodyV1 for RestorePauseCustodyV1 {
    fn recheck_paused_dispatch_restore_v1(
        &mut self,
        expected: &AdapterPausedDispatchRestoreV1,
    ) -> AdapterDispatchRestorePauseValidationV1 {
        self.rechecks.fetch_add(1, Ordering::SeqCst);
        if expected == &self.paused {
            AdapterDispatchRestorePauseValidationV1::Exact
        } else {
            AdapterDispatchRestorePauseValidationV1::Unhealthy
        }
    }

    fn release(self) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

fn initialize_dynamic_store_v1(
    root: &Path,
    identity: AdapterInboxRootIdentityEvidenceV1,
) -> SqliteDispatchInboxStoreV1 {
    let config =
        AdapterInboxStoreConfigV1::try_new_empty_attested(root.to_path_buf(), identity, 25)
            .expect("T096 source root is provisioner-attested and empty");
    SqliteDispatchInboxStoreV1::initialize_empty_v1(
        config,
        AdapterInboxInitializationV1::try_new(15, 1, RECEIPT_PROFILE_DIGEST)
            .expect("T096 source metadata is bounded"),
        dynamic_adapter_profile_v1(),
    )
    .expect("T096 production adapter source initializes")
}

fn reopen_dynamic_store_v1(
    root: &Path,
    identity: AdapterInboxRootIdentityEvidenceV1,
) -> SqliteDispatchInboxStoreV1 {
    let config =
        AdapterInboxStoreConfigV1::try_new_existing_attested(root.to_path_buf(), identity, 25)
            .expect("T096 existing source remains provisioner-attested");
    SqliteDispatchInboxStoreV1::open_existing_v1(config, dynamic_adapter_profile_v1())
        .expect("T096 source graph strictly reopens")
}

fn dynamic_adapter_profile_v1() -> AdapterInboxProfileV1 {
    AdapterInboxProfileV1::try_new(
        "adapter-v1",
        1,
        Sha256Digest::parse_hex(FIXTURE_CAPABILITY_DIGEST)
            .expect("T096 fixture capability digest parses"),
    )
    .expect("T096 adapter profile is closed")
}

fn receipt_signing_profile_v1(authority: &ReceiptAuthorityV1) -> AdapterReceiptSigningProfileV1 {
    AdapterReceiptSigningProfileV1::try_new(
        RECEIPT_KEY_ID,
        authority.fingerprint(),
        Sha256Digest::from_bytes(RECEIPT_PROFILE_DIGEST),
    )
    .expect("T096 receipt signing profile is exact")
}

fn receive_fixture_grant_v1(
    store: &SqliteDispatchInboxStoreV1,
    canonical_grant: &[u8],
    resolver: &FixtureGrantResolverV1,
) -> helix_dispatch_inbox_sqlite::ReceivedInboxGrantV1 {
    let clock = FixedClockV1::new(1_000_100, 1_100);
    let epoch = FixedEpochObserverV1::new(15, 2, 1_000_101, 1_101);
    let AdapterInboxReceiveOutcomeV1::Received(received) = store
        .receive_grant_v1(canonical_grant, resolver, &clock, &epoch)
        .expect("T096 fixture grant reaches production RECEIVED")
    else {
        panic!("T096 fixture grant must be one first durable receive");
    };
    received
}

fn canonical_fixture_grant_v1() -> Vec<u8> {
    let corpus: Value = serde_json::from_str(CASES).expect("T096 fixture corpus parses");
    serde_json_canonicalizer::to_vec(&corpus["base_envelopes"]["grant.valid"])
        .expect("T096 fixture grant canonicalizes")
}

fn fixture_grant_id_v1() -> Sha256Digest {
    Sha256Digest::parse_hex(FIXTURE_GRANT_ID).expect("T096 fixture grant id parses")
}

fn time_sample_v1(clock_generation: u64, utc_ms: u64, monotonic_ms: u64) -> AdapterTimeSampleV1 {
    AdapterTimeSampleV1::new(
        Identifier::new("boot-v1").expect("T096 boot identity is valid"),
        Generation::new(clock_generation).expect("T096 clock generation is non-zero"),
        SafeU64::new(utc_ms).expect("T096 UTC sample is safe"),
        SafeU64::new(monotonic_ms).expect("T096 monotonic sample is safe"),
    )
}

fn manifest_u64_v1(manifest: &Value, path: &[&str]) -> u64 {
    let mut value = manifest;
    for segment in path {
        value = &value[*segment];
    }
    value
        .as_u64()
        .unwrap_or_else(|| panic!("T096 manifest field {path:?} must be an unsigned integer"))
}

fn manifest_digest_v1(manifest: &Value, path: &[&str]) -> [u8; 32] {
    let mut value = manifest;
    for segment in path {
        value = &value[*segment];
    }
    let encoded = value
        .as_str()
        .unwrap_or_else(|| panic!("T096 manifest field {path:?} must be a digest"));
    assert_eq!(encoded.len(), 64, "T096 manifest digest length is exact");
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .expect("T096 manifest digest is lower hexadecimal");
    }
    digest
}

fn restore_source_bindings_v1(
    manifest: &Value,
    source_root_identity: AdapterInboxRootIdentityEvidenceV1,
) -> AdapterDispatchRestoreSourceBindingsV1 {
    let generations = AdapterDispatchRestoreGenerationsV1::try_new(
        manifest_u64_v1(manifest, &["generations", "store"]),
        manifest_u64_v1(manifest, &["generations", "inbox"]),
        manifest_u64_v1(manifest, &["generations", "consumption"]),
        manifest_u64_v1(manifest, &["generations", "receipt"]),
        manifest_u64_v1(manifest, &["generations", "conflict"]),
        manifest_u64_v1(manifest, &["generations", "quarantine"]),
        manifest_u64_v1(manifest, &["generations", "event"]),
        manifest_u64_v1(manifest, &["generations", "epoch_observer"]),
        manifest_u64_v1(manifest, &["generations", "restore_state"]),
    )
    .expect("T096 signed adapter generation projection is exact");
    let counts = AdapterDispatchRestoreCountsV1::try_new(
        manifest_u64_v1(manifest, &["counts", "inbox_entries"]),
        manifest_u64_v1(manifest, &["counts", "transitions"]),
        manifest_u64_v1(manifest, &["counts", "receipts"]),
        manifest_u64_v1(manifest, &["counts", "conflicts"]),
        manifest_u64_v1(manifest, &["counts", "quarantines"]),
        manifest_u64_v1(manifest, &["counts", "events"]),
    )
    .expect("T096 signed adapter count projection is exact");
    let inventories = AdapterDispatchRestoreInventoriesV1::new(
        manifest_digest_v1(manifest, &["inventory_digests", "inbox_entries"]),
        manifest_digest_v1(manifest, &["inventory_digests", "transitions"]),
        manifest_digest_v1(manifest, &["inventory_digests", "receipts"]),
        manifest_digest_v1(manifest, &["inventory_digests", "conflicts"]),
        manifest_digest_v1(manifest, &["inventory_digests", "quarantines"]),
        manifest_digest_v1(manifest, &["inventory_digests", "events"]),
        manifest_digest_v1(manifest, &["inventory_digests", "complete_store"]),
    );
    AdapterDispatchRestoreSourceBindingsV1::try_new(
        source_root_identity,
        manifest_digest_v1(manifest, &["root_identity_digest"]),
        manifest_u64_v1(manifest, &["supervisor_epoch"]),
        generations,
        counts,
        inventories,
    )
    .expect("T096 signed adapter source bindings are exact")
}

fn reconciliation_grant_set_digest_v1(grant_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECONCILIATION_GRANT_SET_DOMAIN);
    hasher.update((grant_ids.len() as u64).to_be_bytes());
    for grant_id in grant_ids {
        hasher.update(grant_id);
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdapterMetadataSnapshotV1 {
    store_generation: i64,
    inbox_generation: i64,
    consumption_generation: i64,
    receipt_generation: i64,
    conflict_generation: i64,
    quarantine_generation: i64,
    event_generation: i64,
    root_identity: Vec<u8>,
    root_lifecycle_state: String,
    supervisor_epoch: i64,
    epoch_observer_generation: i64,
    restore_state_generation: i64,
    restore_index_digest: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdapterGrantSnapshotV1 {
    grant_id: Vec<u8>,
    canonical_grant: Vec<u8>,
    inbox_state: String,
    current_generation: i64,
    receipt_id: Option<Vec<u8>>,
    receipt_decision: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdapterReceiptSnapshotV1 {
    receipt_id: Vec<u8>,
    receipt_digest: Vec<u8>,
    canonical_receipt: Vec<u8>,
    decision: String,
    receipt_generation: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdapterDynamicSnapshotV1 {
    meta: AdapterMetadataSnapshotV1,
    inbox_count: u64,
    transition_count: u64,
    receipt_count: u64,
    conflict_count: u64,
    quarantine_count: u64,
    event_count: u64,
    grant: Option<AdapterGrantSnapshotV1>,
    receipt: Option<AdapterReceiptSnapshotV1>,
}

fn read_dynamic_snapshot_v1(database: &Path) -> AdapterDynamicSnapshotV1 {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("T096 adapter database opens read-only for exact snapshot");
    let meta = connection
        .query_row(
            "SELECT store_generation, inbox_generation, consumption_generation,
                    receipt_generation, conflict_generation, quarantine_generation,
                    event_generation, root_identity, root_lifecycle_state, supervisor_epoch,
                    epoch_observer_generation, restore_state_generation, restore_index_digest
             FROM adapter_store_meta WHERE singleton = 1",
            [],
            |row| {
                Ok(AdapterMetadataSnapshotV1 {
                    store_generation: row.get(0)?,
                    inbox_generation: row.get(1)?,
                    consumption_generation: row.get(2)?,
                    receipt_generation: row.get(3)?,
                    conflict_generation: row.get(4)?,
                    quarantine_generation: row.get(5)?,
                    event_generation: row.get(6)?,
                    root_identity: row.get(7)?,
                    root_lifecycle_state: row.get(8)?,
                    supervisor_epoch: row.get(9)?,
                    epoch_observer_generation: row.get(10)?,
                    restore_state_generation: row.get(11)?,
                    restore_index_digest: row.get(12)?,
                })
            },
        )
        .expect("T096 exact adapter metadata reads");
    let grant = connection
        .query_row(
            "SELECT grant_id, canonical_grant, inbox_state, current_generation,
                    receipt_id, receipt_decision
             FROM grant_inbox ORDER BY grant_id LIMIT 1",
            [],
            |row| {
                Ok(AdapterGrantSnapshotV1 {
                    grant_id: row.get(0)?,
                    canonical_grant: row.get(1)?,
                    inbox_state: row.get(2)?,
                    current_generation: row.get(3)?,
                    receipt_id: row.get(4)?,
                    receipt_decision: row.get(5)?,
                })
            },
        )
        .optional()
        .expect("T096 retained adapter grant snapshot reads");
    let receipt = connection
        .query_row(
            "SELECT receipt_id, receipt_digest, canonical_receipt, decision,
                    receipt_generation
             FROM execution_receipts ORDER BY receipt_id LIMIT 1",
            [],
            |row| {
                Ok(AdapterReceiptSnapshotV1 {
                    receipt_id: row.get(0)?,
                    receipt_digest: row.get(1)?,
                    canonical_receipt: row.get(2)?,
                    decision: row.get(3)?,
                    receipt_generation: row.get(4)?,
                })
            },
        )
        .optional()
        .expect("T096 retained adapter receipt snapshot reads");
    AdapterDynamicSnapshotV1 {
        meta,
        inbox_count: table_count_v1(&connection, "grant_inbox"),
        transition_count: table_count_v1(&connection, "inbox_transitions"),
        receipt_count: table_count_v1(&connection, "execution_receipts"),
        conflict_count: table_count_v1(&connection, "inbox_conflicts"),
        quarantine_count: table_count_v1(&connection, "inbox_quarantines"),
        event_count: table_count_v1(&connection, "adapter_events"),
        grant,
        receipt,
    }
}

fn table_count_v1(connection: &Connection, table: &str) -> u64 {
    let count: i64 = connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap_or_else(|error| panic!("T096 {table} count reads: {error}"));
    u64::try_from(count).unwrap_or_else(|_| panic!("T096 {table} count is non-negative"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RestoreReconciliationProofSnapshotV1 {
    quarantine_id: Vec<u8>,
    grant_id: Vec<u8>,
    evidence_digest: Vec<u8>,
    public_reason_code: String,
    quarantine_generation: i64,
    resolved_generation: Option<i64>,
}

fn read_restore_reconciliation_proofs_v1(
    database: &Path,
    source_quarantine_generation: i64,
) -> Vec<RestoreReconciliationProofSnapshotV1> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("T096 restored adapter database opens for quarantine readback");
    let mut statement = connection
        .prepare(
            "SELECT quarantine_id, grant_id, evidence_digest, public_reason_code,
                    quarantine_generation, resolved_generation
             FROM inbox_quarantines WHERE quarantine_generation > ?1
             ORDER BY quarantine_generation, quarantine_id",
        )
        .expect("T096 restore reconciliation query prepares");
    statement
        .query_map([source_quarantine_generation], |row| {
            Ok(RestoreReconciliationProofSnapshotV1 {
                quarantine_id: row.get(0)?,
                grant_id: row.get(1)?,
                evidence_digest: row.get(2)?,
                public_reason_code: row.get(3)?,
                quarantine_generation: row.get(4)?,
                resolved_generation: row.get(5)?,
            })
        })
        .expect("T096 restore reconciliation rows query")
        .collect::<Result<Vec<_>, _>>()
        .expect("T096 restore reconciliation rows decode")
}
