//! Generated protected-leaf coverage for the three PLAN-006 v1 schemas.
//!
//! The generator is schema-driven and deliberately does not depend on the still-empty
//! Phase 1 fixture corpus. Contract-specific signed fixtures arrive in later user-story
//! tasks; T009 freezes the common leaf and canonical-digest oracle first.

use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

const GRANT_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/human-request-grant-v1.schema.json"
);
const LEASE_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/task-lease-v1.schema.json"
);
const DECISION_SCHEMA: &str = include_str!(
    "../../../specs/006-durable-signed-task-authority/contracts/approval-decision-v1.schema.json"
);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PathSegment {
    Key(String),
    AnyIndex,
}

#[derive(Clone, Copy, Debug)]
struct SchemaCase {
    name: &'static str,
    protected_definition: &'static str,
    text: &'static str,
    expected_leaf_count: usize,
}

const SCHEMAS: [SchemaCase; 3] = [
    SchemaCase {
        name: "human-request-grant",
        protected_definition: "protectedGrant",
        text: GRANT_SCHEMA,
        expected_leaf_count: 17,
    },
    SchemaCase {
        name: "task-lease",
        protected_definition: "protectedLease",
        text: LEASE_SCHEMA,
        expected_leaf_count: 50,
    },
    SchemaCase {
        name: "approval-decision",
        protected_definition: "protectedDecision",
        text: DECISION_SCHEMA,
        expected_leaf_count: 40,
    },
];

fn parse_schema(text: &str) -> Value {
    serde_json::from_str(text).expect("reviewed PLAN-006 schema must decode")
}

fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> &'a Value {
    assert!(
        reference.starts_with("#/"),
        "PLAN-006 schemas may use local references only: {reference}"
    );
    root.pointer(&reference[1..])
        .unwrap_or_else(|| panic!("missing local schema reference {reference}"))
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("required inventory must be an array")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("required member must be a string")
                .to_owned()
        })
        .collect()
}

fn collect_schema_leaf_paths(
    root: &Value,
    schema: &Value,
    prefix: &mut Vec<PathSegment>,
    output: &mut BTreeSet<Vec<PathSegment>>,
) {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        collect_schema_leaf_paths(root, resolve_local_ref(root, reference), prefix, output);
        return;
    }

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        assert_eq!(
            schema["additionalProperties"], false,
            "every authority object must be closed at {prefix:?}"
        );
        assert_eq!(
            string_set(&schema["required"]),
            properties.keys().cloned().collect(),
            "required/properties drift at {prefix:?}"
        );
        for (name, child) in properties {
            prefix.push(PathSegment::Key(name.clone()));
            collect_schema_leaf_paths(root, child, prefix, output);
            prefix.pop();
        }
        return;
    }

    if schema.get("type").and_then(Value::as_str) == Some("array") {
        prefix.push(PathSegment::AnyIndex);
        collect_schema_leaf_paths(root, &schema["items"], prefix, output);
        prefix.pop();
        return;
    }

    assert!(
        output.insert(prefix.clone()),
        "duplicate generated leaf path {prefix:?}"
    );
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(key) || object.values().any(|child| contains_key(child, key))
        }
        Value::Array(array) => array.iter().any(|child| contains_key(child, key)),
        _ => false,
    }
}

fn representative_value(root: &Value, schema: &Value) -> Value {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return representative_value(root, resolve_local_ref(root, reference));
    }
    if let Some(constant) = schema.get("const") {
        return constant.clone();
    }
    if let Some(first) = schema
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return first.clone();
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        let mut object = Map::new();
        for name in string_set(&schema["required"]) {
            object.insert(name.clone(), representative_value(root, &properties[&name]));
        }
        return Value::Object(object);
    }
    if schema.get("type").and_then(Value::as_str) == Some("array") {
        // Even zero-minimum component arrays receive one synthetic element so the
        // generated leaf oracle covers the wildcard component path.
        return Value::Array(vec![representative_value(root, &schema["items"])]);
    }
    if let Some(first) = schema
        .get("oneOf")
        .and_then(Value::as_array)
        .and_then(|variants| variants.first())
    {
        return representative_value(root, first);
    }

    match schema.get("type").and_then(Value::as_str) {
        Some("integer") => {
            let minimum = schema.get("minimum").and_then(Value::as_u64).unwrap_or(0);
            Value::Number(Number::from(minimum))
        }
        Some("string") | None => {
            let pattern = schema.get("pattern").and_then(Value::as_str).unwrap_or("");
            let value = match pattern {
                "^[0-9a-f]{64}$" => "0".repeat(64),
                "^[0-9a-f]{32}$" => "0".repeat(32),
                "^[A-Za-z0-9_-]{85}[AQgw]$" => "A".repeat(86),
                "^[A-Z]{3}$" => "USD".to_owned(),
                "^[a-z0-9][a-z0-9._-]{0,63}$" => "root".to_owned(),
                value if value.contains("A-Za-z0-9") => "id".to_owned(),
                _ => "component".to_owned(),
            };
            Value::String(value)
        }
        Some("null") => Value::Null,
        Some(other) => panic!("unsupported reviewed schema type {other}"),
    }
}

fn cursor_mut<'value>(value: &'value mut Value, path: &[PathSegment]) -> &'value mut Value {
    let mut cursor = value;
    for segment in path {
        cursor = match segment {
            PathSegment::Key(name) => cursor
                .get_mut(name)
                .unwrap_or_else(|| panic!("representative value omitted {name}")),
            PathSegment::AnyIndex => cursor
                .get_mut(0)
                .expect("representative arrays must contain one coverage element"),
        };
    }
    cursor
}

fn mutate_leaf(value: &mut Value, path: &[PathSegment]) {
    let leaf = cursor_mut(value, path);
    match leaf {
        Value::String(text) => text.push('~'),
        Value::Number(number) => {
            let changed = number.as_u64().expect("authority integer is unsigned") + 1;
            *number = Number::from(changed);
        }
        Value::Bool(boolean) => *boolean = !*boolean,
        Value::Null => *leaf = Value::String("0".repeat(64)),
        Value::Array(_) | Value::Object(_) => {
            panic!("generated path must end at a scalar or explicit null")
        }
    }
}

fn canonical_and_digest(value: &Value) -> (Vec<u8>, [u8; 32]) {
    let canonical = serde_json_canonicalizer::to_vec(value).expect("test value canonicalizes");
    let digest = Sha256::digest(&canonical).into();
    (canonical, digest)
}

#[test]
fn generated_schema_leaf_inventory_is_exact_closed_and_nondefaulted() {
    let mut total = 0;
    for case in SCHEMAS {
        let root = parse_schema(case.text);
        assert!(
            !contains_key(&root, "default"),
            "{} unexpectedly introduced a default",
            case.name
        );
        let protected = &root["$defs"][case.protected_definition];
        let mut paths = BTreeSet::new();
        collect_schema_leaf_paths(&root, protected, &mut Vec::new(), &mut paths);
        assert_eq!(
            paths.len(),
            case.expected_leaf_count,
            "{} protected-leaf inventory drift",
            case.name
        );
        total += paths.len();
    }
    assert_eq!(total, 107, "PLAN-006 protected-leaf total changed");
}

#[test]
fn every_generated_leaf_mutation_changes_canonical_bytes_and_protected_digest() {
    let mut mutated = 0;
    for case in SCHEMAS {
        let root = parse_schema(case.text);
        let protected_schema = &root["$defs"][case.protected_definition];
        let mut base = representative_value(&root, protected_schema);
        if case.name == "task-lease" {
            base["parent_lease_id"] = Value::Null;
            base["parent_lease_digest"] = Value::Null;
            base["parent_allocation_id"] = Value::Null;
            base["delegation_depth"] = Value::Number(Number::from(0));
        }

        let mut paths = BTreeSet::new();
        collect_schema_leaf_paths(&root, protected_schema, &mut Vec::new(), &mut paths);
        let (base_jcs, base_digest) = canonical_and_digest(&base);
        for path in paths {
            let mut changed = base.clone();
            mutate_leaf(&mut changed, &path);
            let (changed_jcs, changed_digest) = canonical_and_digest(&changed);
            assert_ne!(
                changed_jcs, base_jcs,
                "{} mutation left canonical bytes unchanged at {path:?}",
                case.name
            );
            assert_ne!(
                changed_digest, base_digest,
                "{} mutation left protected digest unchanged at {path:?}",
                case.name
            );
            mutated += 1;
        }
    }
    assert_eq!(mutated, 107);
}

fn production_source(name: &str) -> Option<String> {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(name),
    )
    .ok()
}

#[test]
fn production_foundation_exposes_the_generated_leaf_validation_seam() {
    let required = ["canonical.rs", "digest.rs", "error.rs", "validation.rs"];
    let missing = required
        .iter()
        .copied()
        .filter(|name| production_source(name).is_none())
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "T009 RED: T011--T014 must connect generated leaves to common validation; missing {missing:?}"
    );

    let sources = required
        .iter()
        .map(|name| production_source(name).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    for token in [
        "serde_json_canonicalizer",
        "Sha256",
        "Sha256Digest",
        "SafeU64",
        "Generation",
        "Identifier",
        "MissingRequiredField",
        "UnknownField",
        "UnsupportedSchema",
    ] {
        assert!(
            sources.contains(token),
            "T011--T014 generated-leaf foundation omits {token}"
        );
    }
}
