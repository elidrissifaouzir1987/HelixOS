//! Deterministic generated mutation gate for the PLAN-005 wire contracts.
//!
//! The permanent test freezes the seed, distribution, public fixture goldens and exact
//! 100,000-case release configuration. The ignored release test drives every generated
//! case through the production grant or receipt decoder/verifier and requires one exact
//! member of the closed [`ContractError`] oracle. No signing material is present here:
//! all positive inputs and public verification keys come from the reviewed fixture.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use helix_dispatch_contracts::{
    decode_and_verify_execution_grant_v1, decode_and_verify_execution_receipt_v1, ContractError,
    GrantKeyResolver, GrantVerificationKeyV1, ReceiptKeyResolver, ReceiptVerificationBindingsV1,
    ReceiptVerificationKeyV1, Result as ContractResult, Sha256Digest,
};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const CASES: &str = include_str!("../../../contracts/fixtures/durable-dispatch-v1/cases.json");

const PROPERTY_SEED: u64 = 0x504c_414e_3030_3583;
const FAST_FAMILY_CASES: usize = 4_540;
const BOUNDED_RAW_FAMILY_CASES: usize = 30;
const EXPECTED_TOTAL_CASES: usize = 100_000;
const EXPECTED_CASES_PER_CONTRACT: usize = 50_000;
const MAX_GRANT_WIRE_BYTES: usize = 1_048_576;
const MAX_RECEIPT_WIRE_BYTES: usize = 65_536;

const GRANT_GOLDEN_SHA256: &str =
    "a3b3a5e6af6c6aca1fc0d440d90f5f25071bd9d61af538080563a444cac67052";
const RECEIPT_CONSUMED_GOLDEN_SHA256: &str =
    "5b6e7466898957f97a876dade64fa95fc3cdbda3321dbeee2221c731bc72872e";
const RECEIPT_ADAPTER_PAUSED_GOLDEN_SHA256: &str =
    "9e205753336494357469e17bf2edc15c30631fbefe0bbf7d97ec524d1db289d0";
const RECEIPT_GRANT_EXPIRED_GOLDEN_SHA256: &str =
    "be63549cec431287d00c5e6892488e6d1d4d111509bd7dd680c7aebce69f586b";
const RECEIPT_EPOCH_MISMATCH_GOLDEN_SHA256: &str =
    "234a6658ee424fb2c8260de5b08b813033f6893d125d3aef32ca49ad8e914440";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContractKind {
    Grant,
    Receipt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MutationKind {
    GrantNonCanonical,
    GrantDuplicateMember,
    GrantUnknownField,
    GrantSignature,
    GrantCrossDomainSignature,
    GrantWrongPublicKey,
    GrantProtocolVersion,
    GrantDigest,
    GrantNonceCollision,
    GrantIdentity,
    GrantUnknownKeyId,
    GrantInvalidUtf8,
    GrantOversize,
    ReceiptNonCanonical,
    ReceiptDuplicateMember,
    ReceiptUnknownField,
    ReceiptSignature,
    ReceiptCrossDomainSignature,
    ReceiptWrongPublicKey,
    ReceiptProtocolVersion,
    ReceiptDigest,
    ReceiptIdentity,
    ReceiptGrantBindings,
    ReceiptAdapterBindings,
    ReceiptInvalidUtf8,
    ReceiptOversize,
}

#[derive(Clone, Copy, Debug)]
struct MutationFamily {
    name: &'static str,
    contract: ContractKind,
    kind: MutationKind,
    cases: usize,
}

const fn fast_family(
    name: &'static str,
    contract: ContractKind,
    kind: MutationKind,
) -> MutationFamily {
    MutationFamily {
        name,
        contract,
        kind,
        cases: FAST_FAMILY_CASES,
    }
}

const fn bounded_raw_family(
    name: &'static str,
    contract: ContractKind,
    kind: MutationKind,
) -> MutationFamily {
    MutationFamily {
        name,
        contract,
        kind,
        cases: BOUNDED_RAW_FAMILY_CASES,
    }
}

const MUTATION_FAMILIES: [MutationFamily; 26] = [
    fast_family(
        "grant-rfc8785-canonical-framing",
        ContractKind::Grant,
        MutationKind::GrantNonCanonical,
    ),
    fast_family(
        "grant-duplicate-member",
        ContractKind::Grant,
        MutationKind::GrantDuplicateMember,
    ),
    fast_family(
        "grant-unknown-field",
        ContractKind::Grant,
        MutationKind::GrantUnknownField,
    ),
    fast_family(
        "grant-signature",
        ContractKind::Grant,
        MutationKind::GrantSignature,
    ),
    fast_family(
        "grant-cross-domain-signature",
        ContractKind::Grant,
        MutationKind::GrantCrossDomainSignature,
    ),
    fast_family(
        "grant-wrong-public-key",
        ContractKind::Grant,
        MutationKind::GrantWrongPublicKey,
    ),
    fast_family(
        "grant-protocol-version",
        ContractKind::Grant,
        MutationKind::GrantProtocolVersion,
    ),
    fast_family(
        "grant-protected-digest",
        ContractKind::Grant,
        MutationKind::GrantDigest,
    ),
    fast_family(
        "grant-one-shot-nonce-collision",
        ContractKind::Grant,
        MutationKind::GrantNonceCollision,
    ),
    fast_family(
        "grant-identity-binding",
        ContractKind::Grant,
        MutationKind::GrantIdentity,
    ),
    fast_family(
        "grant-key-id-resolution",
        ContractKind::Grant,
        MutationKind::GrantUnknownKeyId,
    ),
    bounded_raw_family(
        "grant-invalid-utf8",
        ContractKind::Grant,
        MutationKind::GrantInvalidUtf8,
    ),
    bounded_raw_family(
        "grant-wire-size",
        ContractKind::Grant,
        MutationKind::GrantOversize,
    ),
    fast_family(
        "receipt-rfc8785-canonical-framing",
        ContractKind::Receipt,
        MutationKind::ReceiptNonCanonical,
    ),
    fast_family(
        "receipt-duplicate-member",
        ContractKind::Receipt,
        MutationKind::ReceiptDuplicateMember,
    ),
    fast_family(
        "receipt-unknown-field",
        ContractKind::Receipt,
        MutationKind::ReceiptUnknownField,
    ),
    fast_family(
        "receipt-signature",
        ContractKind::Receipt,
        MutationKind::ReceiptSignature,
    ),
    fast_family(
        "receipt-cross-domain-signature",
        ContractKind::Receipt,
        MutationKind::ReceiptCrossDomainSignature,
    ),
    fast_family(
        "receipt-wrong-public-key",
        ContractKind::Receipt,
        MutationKind::ReceiptWrongPublicKey,
    ),
    fast_family(
        "receipt-protocol-version",
        ContractKind::Receipt,
        MutationKind::ReceiptProtocolVersion,
    ),
    fast_family(
        "receipt-protected-digest",
        ContractKind::Receipt,
        MutationKind::ReceiptDigest,
    ),
    fast_family(
        "receipt-identity-binding",
        ContractKind::Receipt,
        MutationKind::ReceiptIdentity,
    ),
    fast_family(
        "receipt-grant-operation-destination-bindings",
        ContractKind::Receipt,
        MutationKind::ReceiptGrantBindings,
    ),
    fast_family(
        "receipt-root-boot-epoch-bindings",
        ContractKind::Receipt,
        MutationKind::ReceiptAdapterBindings,
    ),
    bounded_raw_family(
        "receipt-invalid-utf8",
        ContractKind::Receipt,
        MutationKind::ReceiptInvalidUtf8,
    ),
    bounded_raw_family(
        "receipt-wire-size",
        ContractKind::Receipt,
        MutationKind::ReceiptOversize,
    ),
];

#[derive(Clone, Copy, Debug)]
struct PublicGrantResolver {
    public_key: [u8; 32],
}

impl GrantKeyResolver for PublicGrantResolver {
    fn resolve_grant_key(&self, key_id: &str) -> ContractResult<GrantVerificationKeyV1> {
        if key_id != "fixture-grant-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(GrantVerificationKeyV1::current(self.public_key))
    }
}

#[derive(Clone, Copy, Debug)]
struct PublicReceiptResolver {
    public_key: [u8; 32],
}

impl ReceiptKeyResolver for PublicReceiptResolver {
    fn resolve_receipt_key(&self, key_id: &str) -> ContractResult<ReceiptVerificationKeyV1> {
        if key_id != "fixture-receipt-key-v1" {
            return Err(ContractError::UnknownKey);
        }
        Ok(ReceiptVerificationKeyV1::current(self.public_key))
    }
}

#[derive(Debug)]
struct PropertyCorpus {
    fixture: Value,
    grant_wire: Vec<u8>,
    receipt_wire: Vec<u8>,
    grant_public_key: [u8; 32],
    receipt_public_key: [u8; 32],
    receipt_bindings: ReceiptVerificationBindingsV1,
}

impl PropertyCorpus {
    fn load() -> Self {
        let fixture: Value =
            serde_json::from_str(CASES).expect("reviewed durable-dispatch fixture must decode");
        let grant_public_key = decode_public_key(
            fixture["verification_keys"]["grant"]["public_key_base64url"]
                .as_str()
                .expect("fixture grant public key exists"),
        );
        let receipt_public_key = decode_public_key(
            fixture["verification_keys"]["receipt"]["public_key_base64url"]
                .as_str()
                .expect("fixture receipt public key exists"),
        );
        let grant_wire = canonical_wire(&fixture["base_envelopes"]["grant.valid"]);
        let grant = decode_and_verify_execution_grant_v1(
            &grant_wire,
            &PublicGrantResolver {
                public_key: grant_public_key,
            },
        )
        .expect("reviewed grant golden must verify");
        let receipt_base = &fixture["base_envelopes"]["receipt.consumed.valid"];
        let receipt_wire = canonical_wire(receipt_base);
        let adapter_root_id = Sha256Digest::parse_hex(
            receipt_base["protected"]["adapter_root_id"]
                .as_str()
                .expect("fixture adapter root exists"),
        )
        .expect("fixture adapter root is a digest");
        let receipt_bindings = ReceiptVerificationBindingsV1::new(&grant, adapter_root_id);

        Self {
            fixture,
            grant_wire,
            receipt_wire,
            grant_public_key,
            receipt_public_key,
            receipt_bindings,
        }
    }

    fn grant_base(&self) -> &Value {
        &self.fixture["base_envelopes"]["grant.valid"]
    }

    fn receipt_base(&self) -> &Value {
        &self.fixture["base_envelopes"]["receipt.consumed.valid"]
    }

    const fn grant_resolver(&self) -> PublicGrantResolver {
        PublicGrantResolver {
            public_key: self.grant_public_key,
        }
    }

    const fn receipt_resolver(&self) -> PublicReceiptResolver {
        PublicReceiptResolver {
            public_key: self.receipt_public_key,
        }
    }
}

fn decode_public_key(encoded: &str) -> [u8; 32] {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("fixture public key must be base64url")
        .try_into()
        .expect("fixture public key must contain 32 bytes")
}

fn canonical_wire(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("generated JSON must canonicalize")
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn deterministic_bytes(family: &str, ordinal: usize, attempt: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROPERTY_SEED.to_be_bytes());
    hash.update((family.len() as u64).to_be_bytes());
    hash.update(family.as_bytes());
    hash.update((ordinal as u64).to_be_bytes());
    hash.update(attempt.to_be_bytes());
    hash.finalize().into()
}

fn deterministic_u64(family: &str, ordinal: usize) -> u64 {
    let bytes = deterministic_bytes(family, ordinal, 0);
    u64::from_be_bytes(bytes[..8].try_into().expect("eight-byte prefix exists"))
}

fn deterministic_digest(family: &str, ordinal: usize) -> String {
    lowercase_hex(&deterministic_bytes(family, ordinal, 0))
}

fn deterministic_identifier(prefix: &str, ordinal: usize) -> String {
    format!("property-{prefix}-{ordinal:04}")
}

fn wrong_valid_public_key(family: &str, ordinal: usize, forbidden: [u8; 32]) -> [u8; 32] {
    for attempt in 0_u64..1_000 {
        let candidate = deterministic_bytes(family, ordinal, attempt);
        if candidate != forbidden && VerifyingKey::from_bytes(&candidate).is_ok() {
            return candidate;
        }
    }
    panic!("deterministic public-key search did not converge for {family}/{ordinal}")
}

fn protected_object(envelope: &mut Value) -> &mut Map<String, Value> {
    envelope["protected"]
        .as_object_mut()
        .expect("fixture protected member is an object")
}

fn refresh_protected_digest(envelope: &mut Value, digest_name: &str) {
    let protected_bytes = canonical_wire(&envelope["protected"]);
    envelope[digest_name] = Value::String(lowercase_hex(&Sha256::digest(protected_bytes)));
}

fn mutate_signature(signature: &str, family: &str, ordinal: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = signature.as_bytes().to_vec();
    let random = deterministic_u64(family, ordinal) as usize;
    let position = (ordinal.wrapping_add(random)) % 85;
    let mut replacement = ALPHABET[(ordinal / 85 + random / 85) % ALPHABET.len()];
    if replacement == bytes[position] {
        replacement = ALPHABET[(usize::from(replacement) + 1) % ALPHABET.len()];
    }
    bytes[position] = replacement;
    String::from_utf8(bytes).expect("base64url mutation remains ASCII")
}

fn noncanonical_wire(value: &Value, digest_name: &str, family: &str, ordinal: usize) -> Vec<u8> {
    let canonical = canonical_wire(value);
    match deterministic_u64(family, ordinal) % 4 {
        0 => [b" ".as_slice(), canonical.as_slice()].concat(),
        1 => [canonical.as_slice(), b"\n".as_slice()].concat(),
        2 => [[0xef, 0xbb, 0xbf].as_slice(), canonical.as_slice()].concat(),
        3 => format!(
            "{{\"signature\":{},\"protected\":{},\"{digest_name}\":{}}}",
            serde_json::to_string(&value["signature"]).expect("signature serializes"),
            serde_json_canonicalizer::to_string(&value["protected"])
                .expect("protected member canonicalizes"),
            serde_json::to_string(&value[digest_name]).expect("digest serializes"),
        )
        .into_bytes(),
        _ => unreachable!("modulo four is closed"),
    }
}

fn duplicate_member_wire(base_wire: &[u8], family: &str, ordinal: usize) -> Vec<u8> {
    let tag = deterministic_digest(family, ordinal);
    format!(
        "{{\"property_duplicate\":\"{tag}\",\"property_duplicate\":\"{tag}\",{}",
        std::str::from_utf8(&base_wire[1..]).expect("fixture wire is UTF-8")
    )
    .into_bytes()
}

fn invalid_utf8_wire(base_wire: &[u8], family: &str, ordinal: usize) -> Vec<u8> {
    let mut wire = base_wire.to_vec();
    let interior = wire.len() - 2;
    let position = 1 + deterministic_u64(family, ordinal) as usize % interior;
    wire[position] = 0xff;
    wire
}

fn assert_grant_denial(
    _corpus: &PropertyCorpus,
    family: &MutationFamily,
    ordinal: usize,
    wire: &[u8],
    resolver: &PublicGrantResolver,
    expected: ContractError,
) -> ContractError {
    let actual = decode_and_verify_execution_grant_v1(wire, resolver)
        .expect_err("generated grant mutation must not authenticate");
    assert_eq!(
        actual, expected,
        "grant property mismatch seed={PROPERTY_SEED:#018x} family={} ordinal={ordinal}",
        family.name
    );
    actual
}

fn assert_receipt_denial(
    corpus: &PropertyCorpus,
    family: &MutationFamily,
    ordinal: usize,
    wire: &[u8],
    resolver: &PublicReceiptResolver,
    expected: ContractError,
) -> ContractError {
    let actual = decode_and_verify_execution_receipt_v1(wire, resolver, &corpus.receipt_bindings)
        .expect_err("generated receipt mutation must not authenticate");
    assert_eq!(
        actual, expected,
        "receipt property mismatch seed={PROPERTY_SEED:#018x} family={} ordinal={ordinal}",
        family.name
    );
    actual
}

fn execute_grant_case(
    corpus: &PropertyCorpus,
    family: &MutationFamily,
    ordinal: usize,
) -> ContractError {
    let resolver = corpus.grant_resolver();
    match family.kind {
        MutationKind::GrantNonCanonical => {
            let mut value = corpus.grant_base().clone();
            value["protected"]["task_id"] =
                Value::String(deterministic_identifier("grant-canonical", ordinal));
            let wire = noncanonical_wire(&value, "grant_digest", family.name, ordinal);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::NonCanonicalWire,
            )
        }
        MutationKind::GrantDuplicateMember => {
            let wire = duplicate_member_wire(&corpus.grant_wire, family.name, ordinal);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::DuplicateMember,
            )
        }
        MutationKind::GrantUnknownField => {
            let mut value = corpus.grant_base().clone();
            let generated = Value::String(deterministic_digest(family.name, ordinal));
            if ordinal.is_multiple_of(2) {
                value
                    .as_object_mut()
                    .expect("grant envelope is an object")
                    .insert("property_unknown".to_owned(), generated);
            } else {
                protected_object(&mut value).insert("property_unknown".to_owned(), generated);
            }
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::UnknownField,
            )
        }
        MutationKind::GrantSignature => {
            let mut value = corpus.grant_base().clone();
            value["signature"] = Value::String(mutate_signature(
                value["signature"].as_str().expect("grant signature exists"),
                family.name,
                ordinal,
            ));
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::SignatureInvalid,
            )
        }
        MutationKind::GrantCrossDomainSignature => {
            let mut value = corpus.grant_base().clone();
            value["protected"]["task_id"] =
                Value::String(deterministic_identifier("grant-domain", ordinal));
            refresh_protected_digest(&mut value, "grant_digest");
            value["signature"] = corpus.receipt_base()["signature"].clone();
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::SignatureInvalid,
            )
        }
        MutationKind::GrantWrongPublicKey => {
            let wrong_resolver = PublicGrantResolver {
                public_key: wrong_valid_public_key(family.name, ordinal, corpus.grant_public_key),
            };
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &corpus.grant_wire,
                &wrong_resolver,
                ContractError::SignatureInvalid,
            )
        }
        MutationKind::GrantProtocolVersion => {
            let mut value = corpus.grant_base().clone();
            value["protected"]["protocol_version"] =
                json!(2 + deterministic_u64(family.name, ordinal) % 250);
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::UnsupportedProtocol,
            )
        }
        MutationKind::GrantDigest => {
            let mut value = corpus.grant_base().clone();
            value["grant_digest"] = Value::String(deterministic_digest(family.name, ordinal));
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::DigestMismatch,
            )
        }
        MutationKind::GrantNonceCollision => {
            let mut value = corpus.grant_base().clone();
            let collision = Value::String(deterministic_digest(family.name, ordinal));
            value["protected"]["grant_id"] = collision.clone();
            value["protected"]["dispatch_attempt_id"] = collision.clone();
            value["protected"]["one_shot_nonce"] = collision;
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::InvalidField,
            )
        }
        MutationKind::GrantIdentity => {
            const IDENTITIES: [&str; 5] = [
                "grant_id",
                "dispatch_attempt_id",
                "preparation_attempt_id",
                "plan_id",
                "replay_claim_id",
            ];
            let mut value = corpus.grant_base().clone();
            let field = IDENTITIES[ordinal % IDENTITIES.len()];
            value["protected"][field] = Value::String(deterministic_digest(family.name, ordinal));
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::DigestMismatch,
            )
        }
        MutationKind::GrantUnknownKeyId => {
            let mut value = corpus.grant_base().clone();
            value["protected"]["key_id"] =
                Value::String(deterministic_identifier("grant-key", ordinal));
            refresh_protected_digest(&mut value, "grant_digest");
            let wire = canonical_wire(&value);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::UnknownKey,
            )
        }
        MutationKind::GrantInvalidUtf8 => {
            let wire = invalid_utf8_wire(&corpus.grant_wire, family.name, ordinal);
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::MalformedJson,
            )
        }
        MutationKind::GrantOversize => {
            let wire = vec![b' '; MAX_GRANT_WIRE_BYTES + 1 + ordinal];
            assert_grant_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::WireTooLarge,
            )
        }
        _ => unreachable!("receipt mutation routed through grant executor"),
    }
}

fn execute_receipt_case(
    corpus: &PropertyCorpus,
    family: &MutationFamily,
    ordinal: usize,
) -> ContractError {
    let resolver = corpus.receipt_resolver();
    match family.kind {
        MutationKind::ReceiptNonCanonical => {
            let mut value = corpus.receipt_base().clone();
            value["protected"]["trace_id"] =
                Value::String(deterministic_identifier("receipt-canonical", ordinal));
            let wire = noncanonical_wire(&value, "receipt_digest", family.name, ordinal);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::NonCanonicalWire,
            )
        }
        MutationKind::ReceiptDuplicateMember => {
            let wire = duplicate_member_wire(&corpus.receipt_wire, family.name, ordinal);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::DuplicateMember,
            )
        }
        MutationKind::ReceiptUnknownField => {
            let mut value = corpus.receipt_base().clone();
            let generated = Value::String(deterministic_digest(family.name, ordinal));
            if ordinal.is_multiple_of(2) {
                value
                    .as_object_mut()
                    .expect("receipt envelope is an object")
                    .insert("property_unknown".to_owned(), generated);
            } else {
                protected_object(&mut value).insert("property_unknown".to_owned(), generated);
            }
            let wire = canonical_wire(&value);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::UnknownField,
            )
        }
        MutationKind::ReceiptSignature => {
            let mut value = corpus.receipt_base().clone();
            value["signature"] = Value::String(mutate_signature(
                value["signature"]
                    .as_str()
                    .expect("receipt signature exists"),
                family.name,
                ordinal,
            ));
            let wire = canonical_wire(&value);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::SignatureInvalid,
            )
        }
        MutationKind::ReceiptCrossDomainSignature => {
            let mut value = corpus.receipt_base().clone();
            value["protected"]["trace_id"] =
                Value::String(deterministic_identifier("receipt-domain", ordinal));
            refresh_protected_digest(&mut value, "receipt_digest");
            value["signature"] = corpus.grant_base()["signature"].clone();
            let wire = canonical_wire(&value);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::SignatureInvalid,
            )
        }
        MutationKind::ReceiptWrongPublicKey => {
            let wrong_resolver = PublicReceiptResolver {
                public_key: wrong_valid_public_key(family.name, ordinal, corpus.receipt_public_key),
            };
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &corpus.receipt_wire,
                &wrong_resolver,
                ContractError::SignatureInvalid,
            )
        }
        MutationKind::ReceiptProtocolVersion => {
            let mut value = corpus.receipt_base().clone();
            value["protected"]["protocol_version"] =
                json!(2 + deterministic_u64(family.name, ordinal) % 250);
            let wire = canonical_wire(&value);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::UnsupportedProtocol,
            )
        }
        MutationKind::ReceiptDigest => {
            let mut value = corpus.receipt_base().clone();
            value["receipt_digest"] = Value::String(deterministic_digest(family.name, ordinal));
            let wire = canonical_wire(&value);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::DigestMismatch,
            )
        }
        MutationKind::ReceiptIdentity => {
            let mut value = corpus.receipt_base().clone();
            value["protected"]["receipt_id"] =
                Value::String(deterministic_digest(family.name, ordinal));
            let wire = canonical_wire(&value);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::DigestMismatch,
            )
        }
        MutationKind::ReceiptGrantBindings => {
            let mut value = corpus.receipt_base().clone();
            let expected = match ordinal % 4 {
                0 => {
                    value["protected"]["grant_id"] =
                        Value::String(deterministic_digest(family.name, ordinal));
                    ContractError::GrantBindingMismatch
                }
                1 => {
                    value["protected"]["grant_digest"] =
                        Value::String(deterministic_digest(family.name, ordinal));
                    ContractError::GrantBindingMismatch
                }
                2 => {
                    value["protected"]["operation_id"] =
                        Value::String(deterministic_identifier("receipt-operation", ordinal));
                    ContractError::OperationBindingMismatch
                }
                3 => {
                    value["protected"]["destination_adapter_id"] =
                        Value::String(deterministic_identifier("receipt-destination", ordinal));
                    ContractError::DestinationBindingMismatch
                }
                _ => unreachable!("modulo four is closed"),
            };
            let wire = canonical_wire(&value);
            assert_receipt_denial(corpus, family, ordinal, &wire, &resolver, expected)
        }
        MutationKind::ReceiptAdapterBindings => {
            let mut value = corpus.receipt_base().clone();
            let expected = match ordinal % 3 {
                0 => {
                    value["protected"]["adapter_root_id"] =
                        Value::String(deterministic_digest(family.name, ordinal));
                    ContractError::AdapterRootBindingMismatch
                }
                1 => {
                    value["protected"]["observed_boot_id"] =
                        Value::String(deterministic_identifier("receipt-boot", ordinal));
                    ContractError::SupervisorEpochBindingMismatch
                }
                2 => {
                    value["protected"]["observed_supervisor_epoch"] = json!(16 + ordinal as u64);
                    ContractError::SupervisorEpochBindingMismatch
                }
                _ => unreachable!("modulo three is closed"),
            };
            let wire = canonical_wire(&value);
            assert_receipt_denial(corpus, family, ordinal, &wire, &resolver, expected)
        }
        MutationKind::ReceiptInvalidUtf8 => {
            let wire = invalid_utf8_wire(&corpus.receipt_wire, family.name, ordinal);
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::MalformedJson,
            )
        }
        MutationKind::ReceiptOversize => {
            let wire = vec![b' '; MAX_RECEIPT_WIRE_BYTES + 1 + ordinal];
            assert_receipt_denial(
                corpus,
                family,
                ordinal,
                &wire,
                &resolver,
                ContractError::WireTooLarge,
            )
        }
        _ => unreachable!("grant mutation routed through receipt executor"),
    }
}

fn golden_hash(wire: &[u8]) -> String {
    lowercase_hex(&Sha256::digest(wire))
}

fn assert_valid_goldens_unchanged(corpus: &PropertyCorpus) {
    let grant = decode_and_verify_execution_grant_v1(&corpus.grant_wire, &corpus.grant_resolver())
        .expect("grant golden remains valid");
    assert_eq!(golden_hash(&corpus.grant_wire), GRANT_GOLDEN_SHA256);
    assert_eq!(
        grant
            .canonical_signed_envelope_bytes()
            .expect("authentic grant reserializes"),
        corpus.grant_wire
    );

    for (name, expected_hash) in [
        ("receipt.consumed.valid", RECEIPT_CONSUMED_GOLDEN_SHA256),
        (
            "receipt.refused.adapter-paused.valid",
            RECEIPT_ADAPTER_PAUSED_GOLDEN_SHA256,
        ),
        (
            "receipt.refused.grant-expired.valid",
            RECEIPT_GRANT_EXPIRED_GOLDEN_SHA256,
        ),
        (
            "receipt.refused.supervisor-epoch-mismatch.valid",
            RECEIPT_EPOCH_MISMATCH_GOLDEN_SHA256,
        ),
    ] {
        let base = &corpus.fixture["base_envelopes"][name];
        let wire = canonical_wire(base);
        let adapter_root_id = Sha256Digest::parse_hex(
            base["protected"]["adapter_root_id"]
                .as_str()
                .expect("golden adapter root exists"),
        )
        .expect("golden adapter root is a digest");
        let bindings = ReceiptVerificationBindingsV1::new(&grant, adapter_root_id);
        let receipt =
            decode_and_verify_execution_receipt_v1(&wire, &corpus.receipt_resolver(), &bindings)
                .unwrap_or_else(|error| panic!("receipt golden {name} failed: {error}"));
        assert_eq!(golden_hash(&wire), expected_hash, "{name}");
        assert_eq!(
            receipt
                .canonical_signed_envelope_bytes()
                .expect("authentic receipt reserializes"),
            wire,
            "{name}"
        );
    }
}

fn expected_error_histogram() -> BTreeMap<&'static str, usize> {
    BTreeMap::from([
        ("ADAPTER_ROOT_BINDING_MISMATCH", 1_514),
        ("DESTINATION_BINDING_MISMATCH", 1_135),
        ("DIGEST_MISMATCH", 18_160),
        ("DUPLICATE_MEMBER", 9_080),
        ("GRANT_BINDING_MISMATCH", 2_270),
        ("INVALID_FIELD", 4_540),
        ("MALFORMED_JSON", 60),
        ("NON_CANONICAL_WIRE", 9_080),
        ("OPERATION_BINDING_MISMATCH", 1_135),
        ("SIGNATURE_INVALID", 27_240),
        ("SUPERVISOR_EPOCH_BINDING_MISMATCH", 3_026),
        ("UNKNOWN_FIELD", 9_080),
        ("UNKNOWN_KEY", 4_540),
        ("UNSUPPORTED_PROTOCOL", 9_080),
        ("WIRE_TOO_LARGE", 60),
    ])
}

#[test]
fn property_gate_configuration_and_goldens_are_frozen() {
    assert_eq!(PROPERTY_SEED, 0x504c_414e_3030_3583);
    assert_eq!(FAST_FAMILY_CASES, 4_540);
    assert_eq!(BOUNDED_RAW_FAMILY_CASES, 30);
    assert_eq!(MUTATION_FAMILIES.len(), 26);

    let names = MUTATION_FAMILIES
        .iter()
        .map(|family| family.name)
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), MUTATION_FAMILIES.len());

    let total = MUTATION_FAMILIES
        .iter()
        .map(|family| family.cases)
        .sum::<usize>();
    let grant_total = MUTATION_FAMILIES
        .iter()
        .filter(|family| family.contract == ContractKind::Grant)
        .map(|family| family.cases)
        .sum::<usize>();
    let receipt_total = MUTATION_FAMILIES
        .iter()
        .filter(|family| family.contract == ContractKind::Receipt)
        .map(|family| family.cases)
        .sum::<usize>();
    assert_eq!(total, EXPECTED_TOTAL_CASES);
    assert_eq!(grant_total, EXPECTED_CASES_PER_CONTRACT);
    assert_eq!(receipt_total, EXPECTED_CASES_PER_CONTRACT);
    assert_eq!(expected_error_histogram().values().sum::<usize>(), total);

    assert_valid_goldens_unchanged(&PropertyCorpus::load());
}

#[test]
#[ignore = "release PLAN-005 gate: exactly 100,000 deterministic grant/receipt mutations"]
fn release_100_000_generated_mutations_follow_closed_oracle() {
    let started = Instant::now();
    let corpus = PropertyCorpus::load();
    assert_valid_goldens_unchanged(&corpus);

    let mut executed = 0_usize;
    let mut grant_executed = 0_usize;
    let mut receipt_executed = 0_usize;
    let mut observed_errors = BTreeMap::<&'static str, usize>::new();
    let mut observed_families = BTreeMap::<&'static str, usize>::new();

    for family in &MUTATION_FAMILIES {
        for ordinal in 0..family.cases {
            let error = match family.contract {
                ContractKind::Grant => {
                    grant_executed += 1;
                    execute_grant_case(&corpus, family, ordinal)
                }
                ContractKind::Receipt => {
                    receipt_executed += 1;
                    execute_receipt_case(&corpus, family, ordinal)
                }
            };
            *observed_errors.entry(error.code()).or_default() += 1;
            *observed_families.entry(family.name).or_default() += 1;
            executed += 1;
        }
    }

    assert_eq!(executed, EXPECTED_TOTAL_CASES);
    assert_eq!(grant_executed, EXPECTED_CASES_PER_CONTRACT);
    assert_eq!(receipt_executed, EXPECTED_CASES_PER_CONTRACT);
    assert_eq!(observed_errors, expected_error_histogram());
    assert_eq!(observed_families.len(), MUTATION_FAMILIES.len());
    for family in &MUTATION_FAMILIES {
        assert_eq!(observed_families.get(family.name), Some(&family.cases));
    }

    assert_valid_goldens_unchanged(&corpus);
    let elapsed_ms = started.elapsed().as_millis();
    eprintln!(
        "plan005-contract-property schema=1 seed={PROPERTY_SEED:#018x} total={executed} grant={grant_executed} receipt={receipt_executed} families={} fast_family_cases={FAST_FAMILY_CASES} bounded_raw_family_cases={BOUNDED_RAW_FAMILY_CASES} elapsed_ms={elapsed_ms} status=pass errors={observed_errors:?}",
        MUTATION_FAMILIES.len()
    );
}
