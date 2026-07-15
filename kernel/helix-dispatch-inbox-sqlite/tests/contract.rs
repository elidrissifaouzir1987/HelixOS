//! PLAN-005 T039 adapter inbox storage-boundary contracts.
//!
//! The reviewed SQL oracles are permanently executable. The production source guard is
//! deliberately compile-safe before T045/T051 exist: RED is reported as one precise missing
//! module or contract instead of preventing this integration-test binary from compiling.

use helix_dispatch_contracts::Sha256Digest;
use helix_dispatch_inbox_sqlite::{
    AdapterInboxInitializationV1, AdapterInboxProfileV1, AdapterInboxRootIdentityEvidenceV1,
    AdapterInboxStoreConfigV1, SqliteDispatchInboxStoreV1,
};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ADAPTER_SCHEMA: &str =
    include_str!("../../../specs/005-durable-dispatch/contracts/adapter-inbox-schema-v1.sql");
const ADAPTER_APPLICATION_ID_V1: i64 = 1_212_962_889;
const ADAPTER_SCHEMA_VERSION_V1: i64 = 1;

static T051_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

const TABLES: [&str; 7] = [
    "adapter_events",
    "adapter_store_meta",
    "execution_receipts",
    "grant_inbox",
    "inbox_conflicts",
    "inbox_quarantines",
    "inbox_transitions",
];

const INDEXES: [&str; 22] = [
    "adapter_events_generation_uq",
    "adapter_events_one_per_transition_uq",
    "adapter_events_transition_uq",
    "execution_receipts_complete_identity_uq",
    "execution_receipts_digest_uq",
    "execution_receipts_generation_uq",
    "execution_receipts_grant_uq",
    "execution_receipts_operation_uq",
    "execution_receipts_transition_identity_uq",
    "grant_inbox_binding_identity_uq",
    "grant_inbox_complete_identity_uq",
    "grant_inbox_current_generation_uq",
    "grant_inbox_digest_uq",
    "grant_inbox_event_identity_uq",
    "grant_inbox_nonce_uq",
    "grant_inbox_operation_uq",
    "grant_inbox_received_generation_uq",
    "inbox_conflicts_generation_uq",
    "inbox_quarantines_generation_uq",
    "inbox_transitions_complete_identity_uq",
    "inbox_transitions_single_successor_uq",
    "inbox_transitions_state_identity_uq",
];

const TRIGGERS: [&str; 18] = [
    "adapter_events_no_delete",
    "adapter_events_update_guard",
    "adapter_store_meta_no_delete",
    "adapter_store_meta_single_row_guard",
    "adapter_store_meta_update_guard",
    "execution_receipts_active_root_guard",
    "execution_receipts_no_delete",
    "execution_receipts_no_update",
    "grant_inbox_active_root_guard",
    "grant_inbox_no_delete",
    "grant_inbox_update_guard",
    "inbox_conflicts_no_delete",
    "inbox_conflicts_no_update",
    "inbox_quarantines_no_delete",
    "inbox_quarantines_update_guard",
    "inbox_transitions_current_projection_guard",
    "inbox_transitions_no_delete",
    "inbox_transitions_no_update",
];

#[test]
fn reviewed_application_version_objects_and_strict_table_shapes_are_exact() {
    assert_eq!(ADAPTER_APPLICATION_ID_V1, 0x484c_5849, "HLXI");
    assert!(ADAPTER_SCHEMA.contains("PRAGMA application_id = 1212962889;"));
    assert!(ADAPTER_SCHEMA.contains("PRAGMA user_version = 1;"));
    assert!(ADAPTER_SCHEMA.contains("PRAGMA recursive_triggers = ON;"));

    let connection = reviewed_connection();
    assert_eq!(
        pragma_i64(&connection, "application_id"),
        ADAPTER_APPLICATION_ID_V1
    );
    assert_eq!(
        pragma_i64(&connection, "user_version"),
        ADAPTER_SCHEMA_VERSION_V1
    );
    assert_eq!(pragma_i64(&connection, "recursive_triggers"), 1);

    assert_eq!(schema_names(&connection, "table"), expected_set(TABLES));
    assert_eq!(schema_names(&connection, "index"), expected_set(INDEXES));
    assert_eq!(schema_names(&connection, "trigger"), expected_set(TRIGGERS));

    let mut statement = connection
        .prepare(
            "SELECT name, sql FROM sqlite_schema \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .expect("reviewed table inventory prepares");
    let tables = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("reviewed table inventory queries")
        .collect::<Result<Vec<_>, _>>()
        .expect("reviewed table inventory decodes");
    assert_eq!(tables.len(), TABLES.len());
    for (name, sql) in tables {
        assert!(
            sql.contains("STRICT, WITHOUT ROWID"),
            "reviewed table {name} is not STRICT WITHOUT ROWID: {sql}"
        );
    }
}

#[test]
fn reviewed_root_is_provisioner_bound_singleton_and_lifecycle_fenced() {
    for required in [
        "empty provisioner-attested local adapter root",
        "root_identity BLOB NOT NULL",
        "typeof(root_identity) = 'blob' AND length(root_identity) = 32",
        "root_lifecycle_state = 'ACTIVE'",
        "root_lifecycle_state = 'RESTORE_PENDING'",
        "adapter_store_meta_single_row_guard",
        "adapter_store_meta_no_delete",
        "adapter_store_meta_update_guard",
        "grant_inbox_active_root_guard",
        "execution_receipts_active_root_guard",
    ] {
        assert!(
            ADAPTER_SCHEMA.contains(required),
            "reviewed adapter-root contract omits {required}"
        );
    }

    let connection = reviewed_connection();
    insert_active_metadata(&connection);
    assert!(
        connection
            .execute(
                "INSERT INTO adapter_store_meta (
                    singleton, format_version, store_generation, inbox_generation,
                    consumption_generation, receipt_generation, conflict_generation,
                    quarantine_generation, event_generation, root_identity,
                    root_lifecycle_state, supervisor_epoch, epoch_observer_generation,
                    ordinary_queue_capacity, control_queue_capacity,
                    receipt_signer_profile_digest, restore_index_digest,
                    restore_state_generation
                 ) SELECT 1, format_version, store_generation, inbox_generation,
                    consumption_generation, receipt_generation, conflict_generation,
                    quarantine_generation, event_generation, root_identity,
                    root_lifecycle_state, supervisor_epoch, epoch_observer_generation,
                    ordinary_queue_capacity, control_queue_capacity,
                    receipt_signer_profile_digest, restore_index_digest,
                    restore_state_generation FROM adapter_store_meta",
                [],
            )
            .is_err(),
        "adapter metadata must remain a singleton"
    );
    assert!(
        connection
            .execute("DELETE FROM adapter_store_meta", [])
            .is_err(),
        "adapter root metadata must be permanent"
    );
    assert!(
        connection
            .execute(
                "UPDATE adapter_store_meta
                 SET store_generation = 1, root_identity = zeroblob(32)
                 WHERE singleton = 1",
                [],
            )
            .is_err(),
        "an ACTIVE root identity cannot be replaced"
    );
}

#[test]
fn reviewed_uniqueness_invariants_and_history_guards_are_append_only() {
    for required in [
        "CREATE UNIQUE INDEX grant_inbox_operation_uq",
        "CREATE UNIQUE INDEX grant_inbox_nonce_uq",
        "CREATE UNIQUE INDEX grant_inbox_digest_uq",
        "DEFERRABLE INITIALLY DEFERRED",
        "ABSENT' AND new_state = 'RECEIVED",
        "RECEIVED'\n            AND new_state = 'CONSUMED",
        "RECEIVED'\n            AND new_state = 'REFUSED",
        "RECEIVED'\n            AND new_state = 'QUARANTINED",
        "grant_inbox_no_delete",
        "inbox_transitions_no_update",
        "inbox_transitions_no_delete",
        "execution_receipts_no_update",
        "execution_receipts_no_delete",
        "inbox_conflicts_no_update",
        "inbox_conflicts_no_delete",
        "inbox_quarantines_no_delete",
        "adapter_events_no_delete",
    ] {
        assert!(
            ADAPTER_SCHEMA.contains(required),
            "reviewed invariant/retention contract omits {required}"
        );
    }
    for forbidden in ["ALTER TABLE", "DROP TABLE", "DROP INDEX"] {
        assert!(
            !ADAPTER_SCHEMA.contains(forbidden),
            "adapter schema v1 must be initialization DDL, not migration/repair: {forbidden}"
        );
    }

    let connection = reviewed_connection();
    connection
        .execute(
            "INSERT INTO inbox_conflicts (
                conflict_id, observed_grant_id, observed_operation_digest,
                observed_nonce_digest, retained_binding_digest,
                conflicting_binding_digest, public_reason_code, conflict_generation
             ) VALUES (
                zeroblob(32), zeroblob(32), zeroblob(32), zeroblob(32),
                zeroblob(32), zeroblob(32), 'BINDING_CONFLICT', 1
             )",
            [],
        )
        .expect("valid synthetic conflict evidence inserts");
    assert!(
        connection
            .execute(
                "UPDATE inbox_conflicts SET public_reason_code = 'CHANGED'",
                [],
            )
            .is_err(),
        "conflict evidence must be append-only"
    );
    assert!(
        connection
            .execute("DELETE FROM inbox_conflicts", [])
            .is_err(),
        "conflict evidence must be permanent"
    );
}

#[test]
fn production_open_is_strict_provisioner_bound_and_never_auto_mutates() {
    let config = required_production_source(
        "config.rs",
        "T045 provisioner-bound empty/existing adapter configuration",
    );
    let root = required_production_source(
        "root_safety.rs",
        "T045 provisioner-bound dedicated-root identity custody",
    );
    let connection = required_production_source(
        "connection.rs",
        "T045 strict existing/open versus explicit initialization boundary",
    );
    let schema = required_production_source(
        "schema.rs",
        "T045 exact adapter schema/version/invariant verification",
    );
    let lib = required_production_source("lib.rs", "T045/T051 compiled public boundary");

    let config_lower = config.to_ascii_lowercase();
    assert!(
        config_lower.contains("provision") && config_lower.contains("root"),
        "T039 RED: config.rs must accept only provisioner-bound adapter roots"
    );
    let root_lower = root.to_ascii_lowercase();
    for required in ["root_identity", "dedicated", "provision"] {
        assert!(
            root_lower.contains(required),
            "T039 RED: root_safety.rs omits {required} custody"
        );
    }

    for declaration in [
        "mod config;",
        "mod connection;",
        "mod root_safety;",
        "mod schema;",
    ] {
        assert!(
            lib.contains(declaration),
            "T039 RED: lib.rs must compile the T045 boundary {declaration}"
        );
    }

    for required in [
        "fn initialize_empty",
        "fn open_existing",
        "SQLITE_OPEN_READ_WRITE",
        "journal_mode",
        "WAL",
        "synchronous",
        "FULL",
        "foreign_keys",
        "trusted_schema",
        "cell_size_check",
        "recursive_triggers",
        "wal_autocheckpoint",
        "busy_timeout",
    ] {
        assert!(
            connection.contains(required),
            "T039 RED: connection.rs omits strict open/profile step {required}"
        );
    }

    let local_profile = connection
        .split_once("fn configure_connection_local_profile(")
        .expect("adapter local profile configurator must exist")
        .1
        .split_once("fn configure_busy_timeout(")
        .expect("adapter local profile configurator must remain bounded")
        .0;
    for required in [
        "PRAGMA synchronous = FULL;",
        "PRAGMA foreign_keys = ON;",
        "PRAGMA trusted_schema = OFF;",
        "PRAGMA cell_size_check = ON;",
        "PRAGMA recursive_triggers = ON;",
        "PRAGMA wal_autocheckpoint = 0;",
    ] {
        assert!(
            local_profile.contains(required),
            "T095: adapter connection omits exact batched profile step {required}"
        );
    }

    let profile_verifier = connection
        .split_once("fn verify_profile(")
        .expect("adapter profile verifier must exist")
        .1
        .split_once("fn profile_pragma_i64(")
        .expect("adapter profile verifier must remain bounded")
        .0;
    for required in [
        "(SELECT journal_mode FROM temp.pragma_journal_mode())",
        "(SELECT synchronous FROM temp.pragma_synchronous())",
        "(SELECT foreign_keys FROM temp.pragma_foreign_keys())",
        "(SELECT trusted_schema FROM temp.pragma_trusted_schema())",
        "(SELECT cell_size_check FROM temp.pragma_cell_size_check())",
        "(SELECT recursive_triggers FROM temp.pragma_recursive_triggers())",
        "(SELECT timeout FROM temp.pragma_busy_timeout())",
        "profile.1 != 2",
        "profile.2 != 1",
        "profile.3 != 0",
        "profile.4 != 1",
        "profile.5 != 1",
        "profile.6 != expected_busy_timeout",
        "profile_pragma_i64(connection, \"wal_autocheckpoint\")? != 0",
    ] {
        assert!(
            profile_verifier.contains(required),
            "T095: adapter connection omits exact profile verification {required}"
        );
    }

    for required in [
        "adapter-inbox-schema-v1.sql",
        "1212962889",
        "application_id",
        "user_version",
        "sqlite_schema",
        "integrity_check",
        "foreign_key_check",
        "invariant",
        "unsupported",
    ] {
        assert!(
            schema
                .to_ascii_lowercase()
                .contains(&required.to_ascii_lowercase()),
            "T039 RED: schema.rs omits exact/refusing verifier step {required}"
        );
    }

    let existing_open = braced_block(&connection, "fn open_existing");
    assert!(
        existing_open.contains("verify"),
        "T039 RED: ordinary existing open must invoke exact verification"
    );
    for forbidden in [
        "SQLITE_OPEN_CREATE",
        "execute_batch",
        "initialize_empty",
        "migrat",
        "repair",
        "journal_mode = WAL",
    ] {
        assert!(
            !existing_open.contains(forbidden),
            "T039: ordinary existing open must not create, migrate or repair through {forbidden}"
        );
    }
}

#[test]
fn public_receive_and_consume_handles_are_linear_non_wire_and_manually_redacted() {
    let mut reviewed_handles = BTreeSet::new();
    for module in ["inbox.rs", "receipt.rs", "readback.rs"] {
        let Some(source) = optional_production_structure(module) else {
            continue;
        };
        for type_name in public_concrete_type_names(&source) {
            let item = public_type_item(&source, &type_name);
            if is_authority_bearing_adapter_handle(&type_name, item) {
                assert_linear_non_wire_handle(&source, &type_name);
                reviewed_handles.insert(type_name);
            }
        }
    }

    for required in [
        "SqliteDispatchInboxStoreV1",
        "ReceivedInboxGrantV1",
        "AdapterInboxExactDuplicateV1",
        "AdapterInboxReceiveOutcomeV1",
    ] {
        assert!(
            reviewed_handles.contains(required),
            "T051: public authority-bearing adapter handle {required} escaped review"
        );
    }
}

#[test]
fn public_lib_exports_no_sqlite_connection_or_signing_authority() {
    let lib = required_production_structure("lib.rs", "T051 compiled adapter export boundary");
    for module in ["connection", "quarantine", "root_safety", "schema"] {
        assert!(
            !lib.contains(&format!("pub mod {module}")),
            "T051: internal custody module {module} became publicly reachable"
        );
    }

    let exports = public_use_statements(&lib);
    let export_tokens = identifier_tokens(&exports);
    for forbidden in [
        "Connection",
        "Transaction",
        "TransactionBehavior",
        "OpenFlags",
        "OpenedAdapterInboxStoreV1",
        "AdapterInboxStoreSummaryV1",
        "AdapterRootIdentityV1",
        "ProvisionedEmptyAdapterRootV1",
        "ProvisionedExistingAdapterRootV1",
        "GrantSigner",
        "ReceiptSigner",
        "SigningKey",
        "SecretKey",
        "PrivateKey",
        "Keypair",
    ] {
        assert!(
            !export_tokens.iter().any(|token| token == forbidden),
            "T051: lib.rs re-exports forbidden connection/signing authority {forbidden}"
        );
    }
    for token in export_tokens {
        let normalized = normalize_identifier(&token);
        assert!(
            !normalized.ends_with("signer")
                && !normalized.contains("signingkey")
                && !normalized.contains("privatekey")
                && !normalized.contains("secretkey"),
            "T051: lib.rs exposes signing authority through {token}"
        );
    }
}

#[test]
fn public_adapter_surface_contains_no_execution_token_or_effect_handoff_api() {
    let production = production_rust_structure();
    for token in identifier_tokens(&production) {
        let normalized = normalize_identifier(&token);
        let forbidden = [
            "executiontoken",
            "executionpermit",
            "effecttoken",
            "effecthandoff",
            "effectauthority",
            "hosteffect",
            "hosteffecthandle",
            "intoexecution",
            "executehost",
            "performeffect",
            "takeeffect",
        ];
        assert!(
            !forbidden.iter().any(|candidate| normalized == *candidate),
            "T039/T051: adapter exposes forbidden execution authority identifier {token}"
        );
    }
}

#[test]
fn constructible_store_and_profile_debug_are_opaque() {
    let root = T051Root::new();
    let native_path = root.path().to_string_lossy().into_owned();
    let identity = AdapterInboxRootIdentityEvidenceV1::from_attested_bytes([0xa5; 32]);
    let config =
        AdapterInboxStoreConfigV1::try_new_empty_attested(root.path().to_path_buf(), identity, 50)
            .expect("T051 seeded adapter root is dedicated");
    let initialization = AdapterInboxInitializationV1::try_new(41, 7, [0xb6; 32])
        .expect("T051 initialization is bounded");
    let profile = AdapterInboxProfileV1::try_new(
        "adapter-private-t051-canary",
        1,
        Sha256Digest::from_bytes([0xc7; 32]),
    )
    .expect("T051 profile is valid");
    assert_eq!(format!("{profile:?}"), "AdapterInboxProfileV1 { .. }");

    let store = SqliteDispatchInboxStoreV1::initialize_empty_v1(config, initialization, profile)
        .expect("T051 seeded adapter store initializes");
    let debug = format!("{store:?}");
    assert_eq!(debug, "SqliteDispatchInboxStoreV1 { .. }");
    for private in [
        native_path.as_str(),
        "adapter-private-t051-canary",
        "a5a5a5a5a5a5a5a5",
        "b6b6b6b6b6b6b6b6",
        "c7c7c7c7c7c7c7c7",
    ] {
        assert!(
            !debug.to_ascii_lowercase().contains(private),
            "T051: store Debug leaked seeded custody {private}"
        );
    }
}

struct T051Root {
    path: PathBuf,
}

impl T051Root {
    fn new() -> Self {
        let sequence = T051_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "helixos-adapter-private-t051-root-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("T051 adapter root is created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for T051Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn assert_linear_non_wire_handle(source: &str, type_name: &str) {
    let declaration = public_type_declaration(source, type_name);
    let attributes = attributes_before(source, declaration.start);
    let attribute_tokens = identifier_tokens(attributes);
    for forbidden in ["Clone", "Copy", "Serialize", "Deserialize", "serde"] {
        assert!(
            !attribute_tokens.iter().any(|token| token == forbidden),
            "T051: authority-bearing handle {type_name} derives forbidden {forbidden}"
        );
    }
    for forbidden in ["Clone", "Copy", "Serialize", "Deserialize"] {
        assert!(
            !has_trait_impl(source, type_name, forbidden),
            "T051: authority-bearing handle {type_name} implements forbidden {forbidden}"
        );
    }
    assert!(
        has_trait_impl(source, type_name, "Debug"),
        "T051: authority-bearing handle {type_name} needs explicit redacted Debug"
    );

    if declaration.kind == "struct" {
        let body = &source[declaration.start..declaration.end];
        assert!(
            body.lines()
                .skip(1)
                .all(|line| !line.trim_start().starts_with("pub ")),
            "T051: authority-bearing handle {type_name} exposes a public field"
        );
    }
}

fn is_authority_bearing_adapter_handle(type_name: &str, item: &str) -> bool {
    if type_name == "SqliteDispatchInboxStoreV1"
        || type_name.contains("Outcome")
        || type_name.contains("ExactDuplicate")
    {
        return true;
    }
    let fields = identifier_tokens(item);
    fields.iter().any(|field| {
        matches!(
            field.as_str(),
            "canonical_grant"
                | "canonical_receipt"
                | "grant_id"
                | "receipt_id"
                | "operation_id"
                | "dispatch_attempt_id"
                | "one_shot_nonce"
                | "effect_authority"
                | "execution_token"
        )
    })
}

struct TypeDeclaration {
    start: usize,
    end: usize,
    kind: &'static str,
}

fn public_type_item<'source>(source: &'source str, type_name: &str) -> &'source str {
    let declaration = public_type_declaration(source, type_name);
    &source[declaration.start..declaration.end]
}

fn public_type_declaration(source: &str, type_name: &str) -> TypeDeclaration {
    let (anchor, kind) = [
        (format!("pub struct {type_name}"), "struct"),
        (format!("pub enum {type_name}"), "enum"),
    ]
    .into_iter()
    .find(|(anchor, _)| source.contains(anchor))
    .unwrap_or_else(|| panic!("T051: missing public concrete type {type_name}"));
    let start = source
        .find(&anchor)
        .expect("located T051 declaration remains present");
    let relative_open = source[start..]
        .find('{')
        .unwrap_or_else(|| panic!("T051: {type_name} must use a reviewed braced declaration"));
    let open = start + relative_open;
    let mut depth = 0_u32;
    for (relative, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .expect("T051 declaration braces are balanced");
                if depth == 0 {
                    return TypeDeclaration {
                        start,
                        end: open + relative + character.len_utf8(),
                        kind,
                    };
                }
            }
            _ => {}
        }
    }
    panic!("T051: public type {type_name} has an unterminated declaration")
}

fn attributes_before(source: &str, declaration_start: usize) -> &str {
    let mut cursor = source[..declaration_start].trim_end().len();
    let mut first_attribute = declaration_start;
    loop {
        let prefix = &source[..cursor];
        if !prefix.ends_with(']') {
            break;
        }
        let Some(attribute_start) = prefix.rfind("#[") else {
            break;
        };
        first_attribute = attribute_start;
        cursor = source[..attribute_start].trim_end().len();
    }
    &source[first_attribute..declaration_start]
}

fn has_trait_impl(source: &str, type_name: &str, trait_name: &str) -> bool {
    let tokens = identifier_tokens(source);
    tokens.iter().enumerate().any(|(index, token)| {
        if token != "for" || tokens.get(index + 1).map(String::as_str) != Some(type_name) {
            return false;
        }
        let search_start = index.saturating_sub(20);
        let Some(relative_impl) = tokens[search_start..index]
            .iter()
            .rposition(|candidate| candidate == "impl")
        else {
            return false;
        };
        tokens[search_start + relative_impl + 1..index]
            .iter()
            .any(|candidate| candidate == trait_name)
    })
}

fn public_concrete_type_names(source: &str) -> Vec<String> {
    let tokens = identifier_tokens(source);
    let mut names = tokens
        .windows(3)
        .filter(|window| window[0] == "pub" && matches!(window[1].as_str(), "struct" | "enum"))
        .map(|window| window[2].clone())
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn public_use_statements(source: &str) -> String {
    let mut statements = Vec::new();
    let mut remainder = source;
    while let Some(start) = remainder.find("pub use ") {
        let statement = &remainder[start..];
        let Some(end) = statement.find(';') else {
            panic!("T051: unterminated pub use declaration in lib.rs");
        };
        statements.push(&statement[..=end]);
        remainder = &statement[end + 1..];
    }
    statements.join("\n")
}

fn identifier_tokens(source: &str) -> Vec<String> {
    source
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

fn normalize_identifier(identifier: &str) -> String {
    identifier
        .chars()
        .filter(|character| *character != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn required_production_structure(file: &str, contract: &str) -> String {
    optional_production_structure(file).unwrap_or_else(|| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
        panic!(
            "T051: missing production module {} required for {contract}",
            path.display()
        )
    })
}

fn optional_production_structure(file: &str) -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let raw = fs::read_to_string(path).ok()?;
    let structure = rust_structure(&raw);
    Some(
        structure
            .split("#[cfg(test)]")
            .next()
            .expect("production prefix always exists")
            .to_owned(),
    )
}

fn production_rust_structure() -> String {
    fn visit(directory: &Path, structures: &mut Vec<(PathBuf, String)>) {
        let mut entries = fs::read_dir(directory)
            .expect("adapter source directory is readable")
            .map(|entry| entry.expect("adapter source entry is readable").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(&path, structures);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                let raw = fs::read_to_string(&path).expect("adapter Rust source is UTF-8");
                let structure = rust_structure(&raw);
                let production = structure
                    .split("#[cfg(test)]")
                    .next()
                    .expect("production prefix always exists")
                    .to_owned();
                structures.push((path, production));
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut structures = Vec::new();
    visit(&root, &mut structures);
    structures
        .into_iter()
        .map(|(_, structure)| structure)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Removes Rust comments and string contents while preserving byte offsets, braces,
/// attributes and identifiers. This keeps source-contract checks structural and avoids
/// matching SQL, diagnostics or documentation as if they were public Rust APIs.
fn rust_structure(source: &str) -> String {
    let input = source.as_bytes();
    let mut output = input.to_vec();
    let mut index = 0_usize;
    while index < input.len() {
        if input[index..].starts_with(b"//") {
            let start = index;
            index += 2;
            while index < input.len() && input[index] != b'\n' {
                index += 1;
            }
            blank_preserving_newlines(&mut output, start, index);
            continue;
        }
        if input[index..].starts_with(b"/*") {
            let start = index;
            let mut depth = 1_u32;
            index += 2;
            while index < input.len() && depth > 0 {
                if input[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if input[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            blank_preserving_newlines(&mut output, start, index);
            continue;
        }
        if input[index] == b'r' {
            let mut opening = index + 1;
            while opening < input.len() && input[opening] == b'#' {
                opening += 1;
            }
            if opening < input.len() && input[opening] == b'"' {
                let hashes = opening - index - 1;
                let start = index;
                index = opening + 1;
                while index < input.len() {
                    if input[index] == b'"'
                        && input
                            .get(index + 1..index + 1 + hashes)
                            .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                    {
                        index += 1 + hashes;
                        break;
                    }
                    index += 1;
                }
                blank_preserving_newlines(&mut output, start, index);
                continue;
            }
        }
        if input[index] == b'"' {
            let start = index;
            index += 1;
            while index < input.len() {
                match input[index] {
                    b'\\' => index = (index + 2).min(input.len()),
                    b'"' => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            blank_preserving_newlines(&mut output, start, index);
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("blanked Rust source remains UTF-8")
}

fn blank_preserving_newlines(output: &mut [u8], start: usize, end: usize) {
    for byte in &mut output[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

fn reviewed_connection() -> Connection {
    let connection = Connection::open_in_memory().expect("reviewed adapter schema opens");
    connection
        .execute_batch(ADAPTER_SCHEMA)
        .expect("reviewed adapter schema executes");
    connection
}

fn insert_active_metadata(connection: &Connection) {
    connection
        .execute(
            "INSERT INTO adapter_store_meta (
                singleton, format_version, store_generation, inbox_generation,
                consumption_generation, receipt_generation, conflict_generation,
                quarantine_generation, event_generation, root_identity,
                root_lifecycle_state, supervisor_epoch, epoch_observer_generation,
                ordinary_queue_capacity, control_queue_capacity,
                receipt_signer_profile_digest, restore_index_digest,
                restore_state_generation
             ) VALUES (
                1, 1, 0, 0, 0, 0, 0, 0, 0,
                X'1111111111111111111111111111111111111111111111111111111111111111',
                'ACTIVE', 0, 1, 1024, 32,
                X'2222222222222222222222222222222222222222222222222222222222222222',
                NULL, 0
             )",
            [],
        )
        .expect("valid ACTIVE adapter metadata inserts");
}

fn pragma_i64(connection: &Connection, pragma: &str) -> i64 {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .unwrap_or_else(|_| panic!("PRAGMA {pragma} reads"))
}

fn schema_names(connection: &Connection, kind: &str) -> BTreeSet<String> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_schema \
             WHERE type = ?1 AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .expect("schema-name inventory prepares");
    statement
        .query_map([kind], |row| row.get(0))
        .expect("schema-name inventory queries")
        .collect::<Result<BTreeSet<_>, _>>()
        .expect("schema-name inventory decodes")
}

fn expected_set<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

fn required_production_source(file: &str, contract: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let source = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "T039 RED: missing production module {} required for {contract}: {error}",
            path.display()
        )
    });
    source_without_comments(&source)
}

fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn braced_block<'a>(source: &'a str, anchor: &str) -> &'a str {
    let start = source
        .find(anchor)
        .unwrap_or_else(|| panic!("T039 RED: missing required source contract {anchor}"));
    let relative_open = source[start..]
        .find('{')
        .unwrap_or_else(|| panic!("T039: contract {anchor} has no body"));
    let open = start + relative_open;
    let mut depth = 0_u32;
    for (relative, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1).expect("balanced Rust source braces");
                if depth == 0 {
                    return &source[start..open + relative + character.len_utf8()];
                }
            }
            _ => {}
        }
    }
    panic!("T039: contract {anchor} has an unterminated body");
}
