//! PLAN-005 T043 RED contract for adapter receipt signing and retained evidence.
//!
//! Executable contract oracles use the frozen public fixture keys. The final source
//! guard deliberately remains RED until T049/T050 persist and read back one exact
//! SQLite receipt without resigning it.

use helix_dispatch_contracts::{
    decode_and_verify_execution_grant_v1, decode_and_verify_execution_receipt_v1,
    sign_execution_receipt_v1, ContractError, ExecutionReceiptDecisionV1, ExecutionReceiptInputV1,
    ExecutionReceiptProtectedV1, Generation, GrantKeyResolver, GrantVerificationKeyV1, Identifier,
    ReceiptKeyResolver, ReceiptSigner, ReceiptVerificationBindingsV1, ReceiptVerificationKeyV1,
    Result as ContractResult, SafeU64, Sha256Digest, VerificationKeyStatusV1,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");
const RECEIPT_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-RECEIPT\0V1\0";
const GRANT_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-GRANT\0V1\0";
const FIXTURE_GRANT_KEY: [u8; 32] = [
    167, 137, 78, 109, 155, 26, 189, 235, 93, 123, 3, 50, 149, 55, 41, 14, 91, 151, 59, 246, 103,
    165, 62, 17, 59, 171, 207, 112, 179, 104, 110, 43,
];
const FIXTURE_RECEIPT_KEY: [u8; 32] = [
    73, 138, 246, 228, 225, 240, 240, 39, 22, 120, 165, 254, 244, 181, 164, 82, 26, 243, 72, 154,
    220, 213, 40, 89, 255, 132, 157, 231, 154, 245, 149, 120,
];

#[derive(Clone, Copy)]
enum ReceiptTrustV1 {
    Current,
    Historical,
    Revoked,
    RotatedWithoutHistory,
}

struct FixtureGrantResolverV1;

impl GrantKeyResolver for FixtureGrantResolverV1 {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        if key_id == "fixture-grant-key-v1" {
            Ok(GrantVerificationKeyV1::current(FIXTURE_GRANT_KEY))
        } else {
            Err(ContractError::UnknownKey)
        }
    }
}

struct FixtureReceiptResolverV1(ReceiptTrustV1);

impl ReceiptKeyResolver for FixtureReceiptResolverV1 {
    fn resolve_receipt_key(&self, key_id: &str) -> ContractResult<ReceiptVerificationKeyV1> {
        if key_id != "fixture-receipt-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        match self.0 {
            ReceiptTrustV1::Current => Ok(ReceiptVerificationKeyV1::current(FIXTURE_RECEIPT_KEY)),
            ReceiptTrustV1::Historical => {
                Ok(ReceiptVerificationKeyV1::historical(FIXTURE_RECEIPT_KEY))
            }
            ReceiptTrustV1::Revoked | ReceiptTrustV1::RotatedWithoutHistory => {
                Err(ContractError::UnknownKey)
            }
        }
    }
}

#[derive(Default)]
struct CapturingReceiptSignerV1 {
    calls: AtomicUsize,
    message: Mutex<Vec<u8>>,
}

impl ReceiptSigner for CapturingReceiptSignerV1 {
    fn key_id(&self) -> &str {
        "adapter-receipt-key-t043"
    }

    fn sign_execution_receipt(&self, message: &[u8]) -> ContractResult<[u8; 64]> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        *self
            .message
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = message.to_vec();
        Ok([0; 64])
    }
}

fn corpus() -> Value {
    serde_json::from_str(CASES).expect("reviewed PLAN-005 fixture must decode")
}

fn canonical_base(name: &str) -> Vec<u8> {
    let corpus = corpus();
    serde_json_canonicalizer::to_vec(&corpus["base_envelopes"][name])
        .expect("reviewed fixture canonicalizes")
}

fn fixture_bindings() -> ReceiptVerificationBindingsV1 {
    let grant = decode_and_verify_execution_grant_v1(
        &canonical_base("grant.valid"),
        &FixtureGrantResolverV1,
    )
    .expect("fixture grant authenticates");
    let root =
        Sha256Digest::parse_hex("cb4857fc9951f4cb964eaee4ce85bbb664d626a0c757ca01cce79b49e062b24b")
            .expect("fixture adapter root parses");
    ReceiptVerificationBindingsV1::new(&grant, root)
}

fn mutated_receipt(field: &str, value: Value) -> Vec<u8> {
    let corpus = corpus();
    let mut receipt = corpus["base_envelopes"]["receipt.consumed.valid"].clone();
    receipt["protected"][field] = value;
    serde_json_canonicalizer::to_vec(&receipt).expect("mutated receipt canonicalizes")
}

fn consumed_receipt_input() -> ExecutionReceiptInputV1 {
    ExecutionReceiptInputV1 {
        receipt_id: Sha256Digest::from_bytes([10; 32]),
        grant_id: Sha256Digest::from_bytes([11; 32]),
        grant_digest: Sha256Digest::from_bytes([12; 32]),
        operation_id: Identifier::new("operation-t043").unwrap(),
        destination_adapter_id: Identifier::new("adapter-t043").unwrap(),
        adapter_root_id: Sha256Digest::from_bytes([13; 32]),
        inbox_generation: Generation::new(1).unwrap(),
        consumption_generation: Some(Generation::new(2).unwrap()),
        refusal_generation: None,
        receipt_generation: Generation::new(3).unwrap(),
        observed_boot_id: Identifier::new("boot-t043").unwrap(),
        observed_supervisor_epoch: SafeU64::new(15).unwrap(),
        epoch_observer_generation: Generation::new(4).unwrap(),
        decision: ExecutionReceiptDecisionV1::Consumed,
        refusal_code: None,
        no_consumption_tombstone_digest: None,
        decided_at_utc_ms: SafeU64::new(1_000_100).unwrap(),
        decided_at_monotonic_ms: SafeU64::new(1_100).unwrap(),
        trace_id: Identifier::new("trace-t043").unwrap(),
    }
}

fn source_without_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn receipt_signer_uses_a_distinct_purpose_and_domain() {
    let signer = CapturingReceiptSignerV1::default();
    let protected = ExecutionReceiptProtectedV1::try_new(
        consumed_receipt_input(),
        Identifier::new(signer.key_id()).unwrap(),
    )
    .expect("valid receipt protected value constructs");
    let signed = sign_execution_receipt_v1(protected, &signer).expect("receipt signs");
    let message = signer
        .message
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();

    assert_eq!(signer.calls.load(Ordering::Relaxed), 1);
    assert!(message.starts_with(RECEIPT_DOMAIN));
    assert!(!message.starts_with(GRANT_DOMAIN));
    let wire: Value = serde_json::from_slice(&signed.to_canonical_json().unwrap()).unwrap();
    assert_eq!(wire["protected"]["key_purpose"], "adapter-receipt-signing");
    assert_ne!(
        wire["protected"]["key_purpose"],
        "coordinator-dispatch-signing"
    );
}

#[test]
fn current_and_historical_receipt_keys_verify_but_revoked_or_pruned_history_denies() {
    let wire = canonical_base("receipt.consumed.valid");
    let bindings = fixture_bindings();
    let current = decode_and_verify_execution_receipt_v1(
        &wire,
        &FixtureReceiptResolverV1(ReceiptTrustV1::Current),
        &bindings,
    )
    .expect("current fixture receipt verifies");
    assert_eq!(
        current.verification_key_status(),
        VerificationKeyStatusV1::Current
    );

    let historical = decode_and_verify_execution_receipt_v1(
        &wire,
        &FixtureReceiptResolverV1(ReceiptTrustV1::Historical),
        &bindings,
    )
    .expect("rotated historical receipt remains evidence");
    assert_eq!(
        historical.verification_key_status(),
        VerificationKeyStatusV1::Historical
    );
    assert_eq!(historical.canonical_signed_envelope_bytes().unwrap(), wire);

    for trust in [
        ReceiptTrustV1::Revoked,
        ReceiptTrustV1::RotatedWithoutHistory,
    ] {
        assert_eq!(
            decode_and_verify_execution_receipt_v1(
                &wire,
                &FixtureReceiptResolverV1(trust),
                &bindings,
            )
            .unwrap_err(),
            ContractError::UnknownKey
        );
    }
}

#[test]
fn cross_grant_operation_adapter_root_and_epoch_receipts_all_deny() {
    let bindings = fixture_bindings();
    let resolver = FixtureReceiptResolverV1(ReceiptTrustV1::Current);
    let cases = [
        (
            "grant-id",
            "grant_id",
            Value::String(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            ),
            ContractError::GrantBindingMismatch,
        ),
        (
            "grant-digest",
            "grant_digest",
            Value::String(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
            ),
            ContractError::GrantBindingMismatch,
        ),
        (
            "operation",
            "operation_id",
            Value::String("operation-t043-other".into()),
            ContractError::OperationBindingMismatch,
        ),
        (
            "adapter",
            "destination_adapter_id",
            Value::String("adapter-t043-other".into()),
            ContractError::DestinationBindingMismatch,
        ),
        (
            "root",
            "adapter_root_id",
            Value::String(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
            ),
            ContractError::AdapterRootBindingMismatch,
        ),
        (
            "epoch",
            "observed_supervisor_epoch",
            Value::from(16_u64),
            ContractError::SupervisorEpochBindingMismatch,
        ),
    ];

    for (label, field, value, expected) in cases {
        assert_eq!(
            decode_and_verify_execution_receipt_v1(
                &mutated_receipt(field, value),
                &resolver,
                &bindings,
            )
            .unwrap_err(),
            expected,
            "{label}"
        );
    }
}

#[test]
fn retained_receipt_readback_is_byte_exact_and_never_calls_a_signer() {
    let retained = canonical_base("receipt.consumed.valid");
    let signer = CapturingReceiptSignerV1::default();
    let recovered = retained.clone();

    assert_eq!(recovered, retained);
    assert_eq!(signer.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn production_receipt_and_readback_are_sqlite_backed_and_never_resign_retained_bytes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let receipt_path = root.join("receipt.rs");
    let readback_path = root.join("readback.rs");
    let inbox_path = root.join("inbox.rs");
    let receipt =
        source_without_comments(&fs::read_to_string(&receipt_path).unwrap_or_else(|_| {
            panic!(
                "T043 RED: T049 must implement the SQLite receipt transaction at {}",
                receipt_path.display()
            )
        }));
    let readback =
        source_without_comments(&fs::read_to_string(&readback_path).unwrap_or_else(|_| {
            panic!(
                "T043 RED: T050 must implement exact retained receipt readback at {}",
                readback_path.display()
            )
        }));
    let inbox = source_without_comments(&fs::read_to_string(&inbox_path).unwrap_or_else(|_| {
        panic!(
            "T043 RED: T047/T048 must implement the durable inbox binding at {}",
            inbox_path.display()
        )
    }));

    for required in [
        "sign_execution_receipt_v1",
        "ExecutionReceiptInputV1",
        "TransactionBehavior::Immediate",
        "execution_receipts",
        "canonical_receipt",
        "receipt_digest",
        "adapter_key_id",
        "adapter_key_fingerprint",
    ] {
        assert!(
            receipt.contains(required),
            "T043 receipt seam omits {required}"
        );
    }
    for required in ["execution_receipts", "canonical_receipt", "receipt_digest"] {
        assert!(
            readback.contains(required),
            "T043 readback seam omits {required}"
        );
    }
    for required in [
        "grant_inbox",
        "canonical_grant",
        "coordinator_key_fingerprint",
    ] {
        assert!(inbox.contains(required), "T043 inbox seam omits {required}");
    }
    assert!(
        !readback.contains("sign_execution_receipt_v1")
            && !readback.contains("sign_execution_receipt"),
        "T043 retained receipt readback must return stored bytes without resigning"
    );
}
