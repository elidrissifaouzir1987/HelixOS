use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer as _, SigningKey};
use helix_contracts::{
    sign_plan_v1, AtomicityV1, BudgetInputV1, Ed25519Signer, FilePreconditionInputV1, Nonce128,
    PlanInputV1, RecoveryClassV1, RecoveryInputV1, RequestSourceKindV1, ResourceRefV1, Result,
    RiskLevelV1, Sha256Digest,
};
use serde_json::{json, Value};
use std::path::Path;
use std::time::Instant;

#[derive(Debug)]
struct FixtureSigner(SigningKey);

impl Ed25519Signer for FixtureSigner {
    fn key_id(&self) -> &str {
        "core-signing-key:fixture-1"
    }

    fn sign_ed25519(&self, message: &[u8]) -> Result<[u8; 64]> {
        Ok(self.0.sign(message).to_bytes())
    }
}

fn main() {
    let signer = FixtureSigner(SigningKey::from_bytes(&[7_u8; 32]));
    let signed = sign_plan_v1(sample_input(), &signer).expect("fixture plan");
    let arguments = std::env::args().collect::<Vec<_>>();
    if let Some(position) = arguments
        .iter()
        .position(|argument| argument == "--write-fixtures")
    {
        let output = arguments
            .get(position + 1)
            .expect("--write-fixtures requires an output directory");
        write_fixtures(Path::new(output), &signed, &signer);
        println!("wrote fixture corpus to {output}");
        return;
    }
    if arguments.iter().any(|argument| argument == "--fixture") {
        println!(
            "PUBLIC_KEY={}",
            URL_SAFE_NO_PAD.encode(signer.0.verifying_key().to_bytes())
        );
        println!(
            "PROTECTED_JCS={}",
            String::from_utf8(signed.protected().canonical_bytes().expect("protected JCS"))
                .expect("UTF-8")
        );
        println!("PLAN_ID={}", signed.plan_id());
        println!("SIGNATURE={}", signed.signature_base64url());
        println!(
            "ENVELOPE={}",
            String::from_utf8(signed.to_canonical_json().expect("envelope JCS")).expect("UTF-8")
        );
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!("benchmark must run with --release");
        std::process::exit(2);
    }

    const ITERATIONS: usize = 10_000;
    let protected = signed.protected();
    let mut samples = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let started = Instant::now();
        let canonical = protected.canonical_bytes().expect("canonicalize");
        let _plan_id = Sha256Digest::digest(&canonical);
        samples.push(started.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let percentile = |numerator: usize| samples[(ITERATIONS * numerator / 100).min(ITERATIONS - 1)];
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let hardware_label = std::env::var("HELIX_BENCH_HARDWARE")
        .or_else(|_| std::env::var("PROCESSOR_IDENTIFIER"))
        .unwrap_or_else(|_| "unreported-set-HELIX_BENCH_HARDWARE".to_owned());
    let rustc_version = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .unwrap_or_else(|| "unreported".to_owned());
    let available_parallelism = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(0);
    let p50 = percentile(50);
    let p95 = percentile(95);
    let p99 = percentile(99);
    let maximum = samples[ITERATIONS - 1];

    println!("platform={platform}");
    println!("hardware={hardware_label}");
    println!("available_parallelism={available_parallelism}");
    println!("toolchain={rustc_version}");
    println!("corpus=valid-plan plan_id={}", signed.plan_id());
    println!("profile=release iterations={ITERATIONS}");
    println!("p50_ns={p50} p95_ns={p95} p99_ns={p99} max_ns={maximum}");

    if let Some(position) = arguments
        .iter()
        .position(|argument| argument == "--evidence")
    {
        let evidence_path = arguments
            .get(position + 1)
            .expect("--evidence requires an output file");
        let evidence = json!({
            "schema": "helixos.contract-benchmark-evidence/1",
            "platform": platform,
            "hardware_label": hardware_label,
            "available_parallelism": available_parallelism,
            "toolchain": rustc_version,
            "profile": "release",
            "corpus": "valid-plan",
            "plan_id": signed.plan_id().to_string(),
            "protected_jcs_bytes": protected.canonical_bytes().expect("protected JCS").len(),
            "iterations": ITERATIONS,
            "p50_ns": p50,
            "p95_ns": p95,
            "p99_ns": p99,
            "max_ns": maximum,
            "samples_ns_sorted": samples
        });
        let evidence_path = Path::new(evidence_path);
        if let Some(parent) = evidence_path.parent() {
            std::fs::create_dir_all(parent).expect("create evidence directory");
        }
        std::fs::write(evidence_path, canonical_value(&evidence)).expect("write evidence");
        println!("evidence={}", evidence_path.display());
    }

    if p95 > 1_000_000 {
        eprintln!("p95 exceeds the provisional 1 ms gate");
        std::process::exit(2);
    }
}

fn write_fixtures(
    output: &Path,
    signed: &helix_contracts::SignedPlanEnvelopeV1,
    signer: &FixtureSigner,
) {
    std::fs::create_dir_all(output).expect("create fixture directory");
    let input = json!({
        "fixture_format": "helixos.plan-input-fixture/1",
        "operation_id": "operation:00000000-0000-4000-8000-000000000001",
        "task_id": "task:fixture-1",
        "workload_id": "workload:agent-vm-1",
        "boot_id": "boot:fixture-1",
        "task_lease_utf8": "fixture task lease",
        "request_source": {
            "kind": "human_request_grant",
            "grant_utf8": "fixture human request grant"
        },
        "catalog_version": "catalog:1",
        "policy_version": "policy:1",
        "risk_level": "l1",
        "target": {
            "root_id": "vault-main",
            "components": ["Projects", "HelixOS", "Decision.md"]
        },
        "precondition": {
            "volume_id": "volume:fixture-apfs",
            "file_id": "file:00000042",
            "content_utf8": "before\n"
        },
        "replacement": {
            "content_utf8": "after\n",
            "media_type": "text/markdown;charset=utf-8"
        },
        "recovery": {
            "class": "compensation",
            "atomicity": "atomic_replace",
            "reserved_bytes": 4096
        },
        "capability_report_utf8": "fixture capability report",
        "capability_observed_at_unix_ms": 1749999999000_u64,
        "required_capabilities": [
            "filesystem.verify-by-handle",
            "filesystem.atomic-replace"
        ],
        "budget": {
            "reservation_id": "budget:fixture-1",
            "currency_code": "EUR",
            "price_table_id": "price-table:fixture-1",
            "max_cost_micro_units": 0,
            "action_limit": 1,
            "egress_bytes_limit": 0
        },
        "issued_at_unix_ms": 1750000000000_u64,
        "expires_at_unix_ms": 1750000120000_u64,
        "nonce_hex": "11111111111111111111111111111111",
        "instance_epoch": 1,
        "fencing_epoch": 9,
        "fixture_signing_key_id": "core-signing-key:fixture-1"
    });
    let protected = signed.protected().canonical_bytes().expect("protected JCS");
    let envelope = signed.to_canonical_json().expect("envelope JCS");
    let public_key = URL_SAFE_NO_PAD.encode(signer.0.verifying_key().to_bytes());

    for (name, bytes) in [
        (
            "valid-plan.json",
            serde_json_canonicalizer::to_vec(&input).expect("fixture input JCS"),
        ),
        ("valid-plan.protected.jcs", protected),
        ("valid-plan.envelope.jcs", envelope),
        (
            "valid-plan.plan-id",
            signed.plan_id().to_string().into_bytes(),
        ),
        ("valid-plan.public-key", public_key.into_bytes()),
        (
            "valid-plan.signature",
            signed.signature_base64url().as_bytes().to_vec(),
        ),
    ] {
        std::fs::write(output.join(name), bytes).expect("write fixture");
    }
    write_negative_fixtures(output, signed);
}

fn write_negative_fixtures(output: &Path, signed: &helix_contracts::SignedPlanEnvelopeV1) {
    let negative_root = output.join("negative");
    std::fs::create_dir_all(&negative_root).expect("create negative fixture directory");
    let envelope = signed.to_canonical_json().expect("envelope JCS");
    let original: Value = serde_json::from_slice(&envelope).expect("fixture envelope JSON");
    let mut cases = Vec::new();

    macro_rules! wire_case {
        ($id:expr, $wire:expr, $error:expr, [$($coverage:expr),+]) => {{
            let relative = format!("negative/{}.json", $id);
            std::fs::write(output.join(&relative), $wire).expect("write negative fixture");
            cases.push(json!({
                "id": $id,
                "wire": relative,
                "resolver": "trusted",
                "expected_error": $error,
                "dispatch_reached": false,
                "coverage": [$($coverage),+]
            }));
        }};
    }

    let mut trailing_newline = envelope.clone();
    trailing_newline.push(b'\n');
    wire_case!(
        "noncanonical-trailing-newline",
        trailing_newline,
        "NON_CANONICAL_WIRE",
        ["ordering"]
    );

    let signature =
        serde_json_canonicalizer::to_string(&original["signature"]).expect("canonical signature");
    let protected =
        serde_json_canonicalizer::to_string(&original["protected"]).expect("canonical protected");
    let plan_id =
        serde_json_canonicalizer::to_string(&original["plan_id"]).expect("canonical plan id");
    let reordered =
        format!("{{\"signature\":{signature},\"protected\":{protected},\"plan_id\":{plan_id}}}")
            .into_bytes();
    wire_case!(
        "noncanonical-member-order",
        reordered,
        "NON_CANONICAL_WIRE",
        ["ordering"]
    );

    let text = String::from_utf8(envelope.clone()).expect("fixture UTF-8");
    let duplicate = format!("{{\"plan_id\":{plan_id},{}", &text[1..]).into_bytes();
    wire_case!(
        "duplicate-top-level-member",
        duplicate,
        "MALFORMED_JSON",
        ["shape"]
    );

    let mut unknown = original.clone();
    unknown["unexpected"] = json!(true);
    wire_case!(
        "unknown-top-level-field",
        canonical_value(&unknown),
        "MALFORMED_JSON",
        ["shape"]
    );

    let mut missing = original.clone();
    missing["protected"]
        .as_object_mut()
        .expect("protected object")
        .remove("task_id");
    wire_case!(
        "missing-required-field",
        canonical_value(&missing),
        "MALFORMED_JSON",
        ["shape"]
    );

    let mut explicit_null = original.clone();
    explicit_null["protected"]["risk_level"] = json!("l2");
    explicit_null["protected"]["intent"]["recovery"]["class"] = json!("irreversible");
    explicit_null["protected"]["intent"]["recovery"]["preimage_sha256"] = Value::Null;
    wire_case!(
        "explicit-null-optional-field",
        canonical_value(&explicit_null),
        "MALFORMED_JSON",
        ["shape", "recovery"]
    );

    for (id, path, replacement, error) in [
        (
            "unsupported-schema",
            &["protected", "schema"][..],
            json!("helixos.plan-envelope/2"),
            "UNSUPPORTED_SCHEMA",
        ),
        (
            "unsupported-digest",
            &["protected", "digest_algorithm"][..],
            json!("sha-512"),
            "UNSUPPORTED_ALGORITHM",
        ),
        (
            "unsupported-signature-profile",
            &["protected", "signature_algorithm"][..],
            json!("ed448"),
            "UNSUPPORTED_ALGORITHM",
        ),
        (
            "unsupported-intent",
            &["protected", "intent", "kind"][..],
            json!("host.shell"),
            "UNSUPPORTED_INTENT",
        ),
    ] {
        wire_case!(
            id,
            canonical_replacement(&original, path, replacement, false),
            error,
            ["version"]
        );
    }

    for (id, component, coverage) in [
        ("resource-traversal", "..", "resource"),
        ("resource-default-ignorable", "zero\u{200b}width", "unicode"),
        ("resource-windows-device", "CONIN$", "resource"),
    ] {
        wire_case!(
            id,
            canonical_replacement(
                &original,
                &["protected", "intent", "target", "components", "0",],
                json!(component),
                false,
            ),
            "MALFORMED_JSON",
            [coverage]
        );
    }

    let fraction = text
        .replace(
            "\"issued_at_unix_ms\":1750000000000",
            "\"issued_at_unix_ms\":1.0",
        )
        .into_bytes();
    wire_case!(
        "fractional-integer",
        fraction,
        "MALFORMED_JSON",
        ["numeric"]
    );
    wire_case!(
        "unsafe-integer",
        canonical_replacement(
            &original,
            &["protected", "issued_at_unix_ms"],
            json!(9_007_199_254_740_992_u64),
            false,
        ),
        "MALFORMED_JSON",
        ["numeric"]
    );

    wire_case!(
        "replacement-tamper",
        canonical_replacement(
            &original,
            &["protected", "intent", "replacement", "content_base64url",],
            json!("eA"),
            false,
        ),
        "INVALID_FIELD",
        ["tampering"]
    );
    wire_case!(
        "plan-id-mismatch",
        canonical_replacement(&original, &["plan_id"], json!("00".repeat(32)), false,),
        "PLAN_ID_MISMATCH",
        ["tampering"]
    );
    wire_case!(
        "valid-protected-mutation-original-signature",
        canonical_replacement(
            &original,
            &["protected", "task_id"],
            json!("task:fixture-2"),
            true,
        ),
        "SIGNATURE_INVALID",
        ["tampering", "signature"]
    );
    wire_case!(
        "truncated-signature",
        canonical_replacement(
            &original,
            &["signature"],
            json!(&signed.signature_base64url()[..85]),
            false,
        ),
        "INVALID_ENCODING",
        ["signature"]
    );
    let mut signature_bytes = URL_SAFE_NO_PAD
        .decode(signed.signature_base64url())
        .expect("fixture signature");
    signature_bytes[0] ^= 0x01;
    wire_case!(
        "bit-flipped-signature",
        canonical_replacement(
            &original,
            &["signature"],
            json!(URL_SAFE_NO_PAD.encode(signature_bytes)),
            false,
        ),
        "SIGNATURE_INVALID",
        ["signature", "tampering"]
    );

    for (id, resolver, expected) in [
        ("wrong-verification-key", "wrong_key", "SIGNATURE_INVALID"),
        ("unknown-verification-key", "unknown_key", "UNKNOWN_KEY"),
    ] {
        cases.push(json!({
            "id": id,
            "wire": "valid-plan.envelope.jcs",
            "resolver": resolver,
            "expected_error": expected,
            "dispatch_reached": false,
            "coverage": ["key"]
        }));
    }
    cases.push(json!({
        "id": "wire-size-limit",
        "generator": {
            "kind": "ascii_repeat",
            "byte": 32,
            "count": 1_048_577
        },
        "resolver": "trusted",
        "expected_error": "WIRE_TOO_LARGE",
        "dispatch_reached": false,
        "coverage": ["size"]
    }));

    let manifest = json!({
        "schema": "helixos.negative-contract-corpus/1",
        "base_fixture": "valid-plan.envelope.jcs",
        "cases": cases
    });
    std::fs::write(
        output.join("negative-cases.json"),
        canonical_value(&manifest),
    )
    .expect("write negative manifest");
}

fn canonical_replacement(
    original: &Value,
    path: &[&str],
    replacement: Value,
    recompute_plan_id: bool,
) -> Vec<u8> {
    let mut value = original.clone();
    let mut cursor = &mut value;
    for segment in &path[..path.len() - 1] {
        cursor = if let Ok(index) = segment.parse::<usize>() {
            cursor.get_mut(index).expect("fixture array index")
        } else {
            cursor.get_mut(*segment).expect("fixture object key")
        };
    }
    let final_segment = path[path.len() - 1];
    if let Ok(index) = final_segment.parse::<usize>() {
        cursor[index] = replacement;
    } else {
        cursor
            .as_object_mut()
            .expect("fixture object")
            .insert(final_segment.to_owned(), replacement);
    }
    if recompute_plan_id {
        let protected = canonical_value(&value["protected"]);
        value["plan_id"] = json!(Sha256Digest::digest(&protected).to_string());
    }
    canonical_value(&value)
}

fn canonical_value(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("fixture JCS")
}

fn sample_input() -> PlanInputV1 {
    const ISSUED: u64 = 1_750_000_000_000;
    PlanInputV1 {
        operation_id: "operation:00000000-0000-4000-8000-000000000001".to_owned(),
        task_id: "task:fixture-1".to_owned(),
        workload_id: "workload:agent-vm-1".to_owned(),
        boot_id: "boot:fixture-1".to_owned(),
        task_lease_digest: Sha256Digest::digest(b"fixture task lease"),
        request_source_kind: RequestSourceKindV1::HumanRequestGrant,
        request_source_digest: Sha256Digest::digest(b"fixture human request grant"),
        catalog_version: "catalog:1".to_owned(),
        policy_version: "policy:1".to_owned(),
        risk_level: RiskLevelV1::L1,
        target: ResourceRefV1::new("vault-main", ["Projects", "HelixOS", "Decision.md"])
            .expect("resource"),
        precondition: FilePreconditionInputV1 {
            volume_id: "volume:fixture-apfs".to_owned(),
            file_id: "file:00000042".to_owned(),
            content_sha256: Sha256Digest::digest(b"before\n"),
            byte_length: 7,
        },
        replacement_bytes: b"after\n".to_vec(),
        replacement_media_type: "text/markdown;charset=utf-8".to_owned(),
        recovery: RecoveryInputV1 {
            class: RecoveryClassV1::Compensation,
            atomicity: AtomicityV1::AtomicReplace,
            reserved_bytes: 4096,
        },
        capability_report_digest: Sha256Digest::digest(b"fixture capability report"),
        capability_observed_at_unix_ms: ISSUED - 1000,
        required_capabilities: vec![
            "filesystem.verify-by-handle".to_owned(),
            "filesystem.atomic-replace".to_owned(),
        ],
        budget: BudgetInputV1 {
            reservation_id: "budget:fixture-1".to_owned(),
            currency_code: "EUR".to_owned(),
            price_table_id: "price-table:fixture-1".to_owned(),
            max_cost_micro_units: 0,
            action_limit: 1,
            egress_bytes_limit: 0,
        },
        issued_at_unix_ms: ISSUED,
        expires_at_unix_ms: ISSUED + 120_000,
        nonce: Nonce128::from_bytes([0x11; 16]),
        instance_epoch: 1,
        fencing_epoch: 9,
    }
}
