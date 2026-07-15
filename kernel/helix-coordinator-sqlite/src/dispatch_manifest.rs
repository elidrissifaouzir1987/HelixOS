//! Closed canonical codecs for paused dispatch backups and their signed index.
//!
//! The index carries public-key fingerprints and trust history, never signing keys or
//! other secret material. Signature production and trust-store lookup stay outside this
//! serialization boundary.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

const DISPATCH_BACKUP_INDEX_SCHEMA_V1: &str = "helixos.dispatch-backup-index/1";
const COORDINATOR_APPLICATION_ID_V2: u64 = 1_212_962_883;
const COORDINATOR_USER_VERSION_V2: u64 = 2;
const ADAPTER_APPLICATION_ID_V1: u64 = 1_212_962_889;
const ADAPTER_USER_VERSION_V1: u64 = 1;
const ADAPTER_FORMAT_VERSION_V1: u64 = 1;
const MAX_SAFE_U64_V1: u64 = 9_007_199_254_740_991;
const MAX_KEY_HISTORY_V1: usize = 64;
const MAX_DISPATCH_MANIFEST_BYTES_V1: usize = 1_048_576;

const COORDINATOR_BACKUP_COMPONENT_V1: &str = "coordinator-v2";
const ADAPTER_BACKUP_COMPONENT_V1: &str = "adapter-inbox-v1";
const INDEX_PUBLISH_COMPONENT_V1: &str = "signed-dispatch-backup-index-v1";
const INVENTORY_CANONICALIZATION_V1: &str = "helixos.dispatch-backup-inventory/rfc8785-sorted-v1";

const GRANT_KEY_PURPOSE_V1: &str = "coordinator-dispatch-signing";
const RECEIPT_KEY_PURPOSE_V1: &str = "adapter-receipt-signing";
const BACKUP_KEY_PURPOSE_V1: &str = "dispatch-backup-provisioner";
const GRANT_SIGNATURE_DOMAIN_V1: &str = "HELIXOS\0EXECUTION-GRANT\0V1\0";
const RECEIPT_SIGNATURE_DOMAIN_V1: &str = "HELIXOS\0EXECUTION-RECEIPT\0V1\0";
const BACKUP_SIGNATURE_DOMAIN_V1: &str = "HELIXOS\0DISPATCH-BACKUP-INDEX\0V1\0";
const COMPLETE_INVENTORY_DIGEST_DOMAIN_V1: &[u8] =
    b"HELIXOS\0DISPATCH-BACKUP-COMPLETE-INVENTORY\0V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchManifestCodecErrorV1 {
    JsonContractInvalid,
}

impl DispatchManifestCodecErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::JsonContractInvalid => "JSON_CONTRACT_INVALID",
        }
    }
}

impl fmt::Display for DispatchManifestCodecErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for DispatchManifestCodecErrorV1 {}

pub(crate) struct DecodedDispatchManifestV1<T> {
    value: T,
    sha256: [u8; 32],
}

impl<T> DecodedDispatchManifestV1<T> {
    pub(crate) const fn value(&self) -> &T {
        &self.value
    }

    pub(crate) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(crate) fn sha256_hex(&self) -> String {
        encode_sha256(self.sha256)
    }

    pub(crate) fn into_value(self) -> T {
        self.value
    }
}

impl<T> fmt::Debug for DecodedDispatchManifestV1<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedDispatchManifestV1")
            .finish_non_exhaustive()
    }
}

pub(crate) struct FinalizedDispatchManifestV1<T> {
    value: T,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

pub(crate) struct FinalizedCoordinatorDispatchBackupManifestV1 {
    value: CoordinatorDispatchBackupManifestV1,
    body_bytes: Vec<u8>,
    manifest_digest: [u8; 32],
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl FinalizedCoordinatorDispatchBackupManifestV1 {
    pub(crate) const fn value(&self) -> &CoordinatorDispatchBackupManifestV1 {
        &self.value
    }

    /// Exact standalone JCS body bytes. The package binding is SHA-256 of these
    /// published bytes; the full package digest remains available through `sha256()`.
    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    pub(crate) const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CoordinatorDispatchBackupManifestV1,
        Vec<u8>,
        [u8; 32],
        Vec<u8>,
        [u8; 32],
    ) {
        (
            self.value,
            self.body_bytes,
            self.manifest_digest,
            self.bytes,
            self.sha256,
        )
    }
}

impl fmt::Debug for FinalizedCoordinatorDispatchBackupManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedCoordinatorDispatchBackupManifestV1")
            .finish_non_exhaustive()
    }
}

impl<T> FinalizedDispatchManifestV1<T> {
    pub(crate) const fn value(&self) -> &T {
        &self.value
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(crate) fn sha256_hex(&self) -> String {
        encode_sha256(self.sha256)
    }

    pub(crate) fn into_parts(self) -> (T, Vec<u8>, [u8; 32]) {
        (self.value, self.bytes, self.sha256)
    }
}

impl<T> fmt::Debug for FinalizedDispatchManifestV1<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedDispatchManifestV1")
            .finish_non_exhaustive()
    }
}

trait ValidateDispatchManifestV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1>;
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            values.insert(key, object.next_value::<UniqueJsonValue>()?.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn decode_canonical_json_v1<T>(
    bytes: &[u8],
) -> Result<DecodedDispatchManifestV1<T>, DispatchManifestCodecErrorV1>
where
    T: DeserializeOwned + ValidateDispatchManifestV1,
{
    if bytes.is_empty()
        || bytes.len() > MAX_DISPATCH_MANIFEST_BYTES_V1
        || bytes.starts_with(&[0xEF, 0xBB, 0xBF])
    {
        return json_invalid();
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    deserializer
        .end()
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let canonical = serde_json_canonicalizer::to_vec(&raw.0)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    if canonical != bytes {
        return json_invalid();
    }
    let value: T = serde_json::from_value(raw.0)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    value.validate()?;
    Ok(DecodedDispatchManifestV1 {
        value,
        sha256: Sha256::digest(bytes).into(),
    })
}

fn finalize_canonical_json_v1<T>(
    value: T,
) -> Result<FinalizedDispatchManifestV1<T>, DispatchManifestCodecErrorV1>
where
    T: Serialize + ValidateDispatchManifestV1,
{
    value.validate()?;
    let bytes = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let sha256 = Sha256::digest(&bytes).into();
    Ok(FinalizedDispatchManifestV1 {
        value,
        bytes,
        sha256,
    })
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BackupRootLifecycleStateV1 {
    Active,
    RestorePending,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoordinatorDispatchBackupManifestV1 {
    root_identity_digest: String,
    application_id: u64,
    user_version: u64,
    base_schema_digest: String,
    overlay_schema_digest: String,
    database_digest: String,
    manifest_digest: String,
    migration_receipt_digest: String,
    root_lifecycle_state: BackupRootLifecycleStateV1,
    generations: CoordinatorGenerationsV1,
    counts: CoordinatorCountsV1,
    inventory_digests: CoordinatorInventoriesV1,
}

/// Canonical standalone coordinator manifest body. Its JCS bytes are published and
/// hashed before the frozen package object adds `manifest_digest`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinatorDispatchBackupManifestBodyV1 {
    root_identity_digest: String,
    application_id: u64,
    user_version: u64,
    base_schema_digest: String,
    overlay_schema_digest: String,
    database_digest: String,
    migration_receipt_digest: String,
    root_lifecycle_state: BackupRootLifecycleStateV1,
    generations: CoordinatorGenerationsV1,
    counts: CoordinatorCountsV1,
    inventory_digests: CoordinatorInventoriesV1,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinatorGenerationsV1 {
    dispatch_store: u64,
    dispatch: u64,
    delivery: u64,
    receipt: u64,
    reconciliation: u64,
    event: u64,
    migration: u64,
    restore_state: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinatorCountsV1 {
    migrations: u64,
    comparisons: u64,
    grants: u64,
    dispatch_records: u64,
    transitions: u64,
    outbox_members: u64,
    delivery_attempts: u64,
    receipts: u64,
    reconciliations: u64,
    events: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinatorInventoriesV1 {
    migrations: String,
    comparisons: String,
    grants: String,
    dispatch_records: String,
    transitions: String,
    outbox_members: String,
    delivery_attempts: String,
    receipts: String,
    reconciliations: String,
    events: String,
    complete_store: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterInboxBackupManifestV1 {
    root_identity_digest: String,
    application_id: u64,
    user_version: u64,
    format_version: u64,
    schema_digest: String,
    database_digest: String,
    manifest_digest: String,
    root_lifecycle_state: BackupRootLifecycleStateV1,
    supervisor_epoch: u64,
    generations: AdapterGenerationsV1,
    counts: AdapterCountsV1,
    inventory_digests: AdapterInventoriesV1,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdapterInboxBackupManifestBodyV1 {
    root_identity_digest: String,
    application_id: u64,
    user_version: u64,
    format_version: u64,
    schema_digest: String,
    database_digest: String,
    root_lifecycle_state: BackupRootLifecycleStateV1,
    supervisor_epoch: u64,
    generations: AdapterGenerationsV1,
    counts: AdapterCountsV1,
    inventory_digests: AdapterInventoriesV1,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdapterGenerationsV1 {
    store: u64,
    inbox: u64,
    consumption: u64,
    receipt: u64,
    conflict: u64,
    quarantine: u64,
    event: u64,
    epoch_observer: u64,
    restore_state: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdapterCountsV1 {
    inbox_entries: u64,
    transitions: u64,
    receipts: u64,
    conflicts: u64,
    quarantines: u64,
    events: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdapterInventoriesV1 {
    inbox_entries: String,
    transitions: String,
    receipts: String,
    conflicts: String,
    quarantines: String,
    events: String,
    complete_store: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatchBackupIndexV1 {
    protected: DispatchBackupProtectedV1,
    protected_digest: String,
    signature: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DispatchBackupProtectedV1 {
    schema: String,
    backup_id: String,
    restore_identity_digest: String,
    created_at_utc_ms: u64,
    source: DispatchBackupSourceIdentityV1,
    supervisor_epoch: u64,
    pause_evidence_digest: String,
    quiescence_evidence_digest: String,
    backup_order: Vec<DispatchBackupStepV1>,
    coordinator: CoordinatorDispatchBackupManifestV1,
    adapter_inbox: AdapterInboxBackupManifestV1,
    cross_store_inventory: CrossStoreInventoryV1,
    verification_keys: VerificationKeySetsV1,
    signature_profile: IndexSignatureProfileV1,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DispatchBackupSourceIdentityV1 {
    source_commit: String,
    tool_identity: String,
    tool_digest: String,
    artifact_set_digest: String,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
enum DispatchBackupStepV1 {
    Coordinator(CoordinatorBackupStepV1),
    Adapter(AdapterBackupStepV1),
    Index(IndexPublishStepV1),
}

impl<'de> Deserialize<'de> for DispatchBackupStepV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let component = value
            .get("component")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::custom("backup step omits component"))?;
        match component {
            COORDINATOR_BACKUP_COMPONENT_V1 => serde_json::from_value(value)
                .map(Self::Coordinator)
                .map_err(de::Error::custom),
            ADAPTER_BACKUP_COMPONENT_V1 => serde_json::from_value(value)
                .map(Self::Adapter)
                .map_err(de::Error::custom),
            INDEX_PUBLISH_COMPONENT_V1 => serde_json::from_value(value)
                .map(Self::Index)
                .map_err(de::Error::custom),
            _ => Err(de::Error::custom("unknown backup step component")),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinatorBackupStepV1 {
    ordinal: u64,
    component: String,
    completed_at_utc_ms: u64,
    database_digest: String,
    manifest_digest: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdapterBackupStepV1 {
    ordinal: u64,
    component: String,
    completed_at_utc_ms: u64,
    database_digest: String,
    manifest_digest: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IndexPublishStepV1 {
    ordinal: u64,
    component: String,
    published_at_utc_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CrossStoreInventoryV1 {
    canonicalization_profile: String,
    coordinator_grant_count: u64,
    adapter_grant_count: u64,
    coordinator_receipt_count: u64,
    adapter_receipt_count: u64,
    matched_grant_count: u64,
    matched_receipt_count: u64,
    orphan_coordinator_grant_count: u64,
    orphan_adapter_grant_count: u64,
    orphan_coordinator_receipt_count: u64,
    orphan_adapter_receipt_count: u64,
    coordinator_grants_digest: String,
    adapter_grants_digest: String,
    coordinator_receipts_digest: String,
    adapter_receipts_digest: String,
    grant_relationships_digest: String,
    receipt_relationships_digest: String,
    complete_inventory_digest: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct VerificationKeySetsV1 {
    grant_signing_history: Vec<VerificationKeyV1>,
    receipt_signing_history: Vec<VerificationKeyV1>,
    backup_provisioner_history: Vec<VerificationKeyV1>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct VerificationKeyV1 {
    key_id: String,
    key_purpose: String,
    algorithm: String,
    signature_domain: String,
    public_key_fingerprint: String,
    trust_profile_digest: String,
    introduced_generation: u64,
    revocation_generation: u64,
    status: VerificationKeyStatusV1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum VerificationKeyStatusV1 {
    Active,
    Retired,
    Revoked,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct IndexSignatureProfileV1 {
    canonicalization: String,
    protected_digest_algorithm: String,
    signature_algorithm: String,
    signature_domain: String,
    signature_input_profile: String,
    key_purpose: String,
    key_id: String,
}

impl fmt::Debug for CoordinatorDispatchBackupManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoordinatorDispatchBackupManifestV1")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AdapterInboxBackupManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInboxBackupManifestV1")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DispatchBackupIndexV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DispatchBackupIndexV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoordinatorGenerationsInputV1 {
    pub(crate) dispatch_store: u64,
    pub(crate) dispatch: u64,
    pub(crate) delivery: u64,
    pub(crate) receipt: u64,
    pub(crate) reconciliation: u64,
    pub(crate) event: u64,
    pub(crate) migration: u64,
    pub(crate) restore_state: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoordinatorCountsInputV1 {
    pub(crate) migrations: u64,
    pub(crate) comparisons: u64,
    pub(crate) grants: u64,
    pub(crate) dispatch_records: u64,
    pub(crate) transitions: u64,
    pub(crate) outbox_members: u64,
    pub(crate) delivery_attempts: u64,
    pub(crate) receipts: u64,
    pub(crate) reconciliations: u64,
    pub(crate) events: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CoordinatorInventoriesInputV1 {
    pub(crate) migrations: [u8; 32],
    pub(crate) comparisons: [u8; 32],
    pub(crate) grants: [u8; 32],
    pub(crate) dispatch_records: [u8; 32],
    pub(crate) transitions: [u8; 32],
    pub(crate) outbox_members: [u8; 32],
    pub(crate) delivery_attempts: [u8; 32],
    pub(crate) receipts: [u8; 32],
    pub(crate) reconciliations: [u8; 32],
    pub(crate) events: [u8; 32],
    pub(crate) complete_store: [u8; 32],
}

pub(crate) struct CoordinatorDispatchBackupManifestInputV1 {
    pub(crate) root_identity_digest: [u8; 32],
    pub(crate) base_schema_digest: [u8; 32],
    pub(crate) overlay_schema_digest: [u8; 32],
    pub(crate) database_digest: [u8; 32],
    pub(crate) migration_receipt_digest: [u8; 32],
    pub(crate) root_lifecycle_state: BackupRootLifecycleStateV1,
    pub(crate) generations: CoordinatorGenerationsInputV1,
    pub(crate) counts: CoordinatorCountsInputV1,
    pub(crate) inventory_digests: CoordinatorInventoriesInputV1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CrossStoreInventoryInputV1 {
    pub(crate) coordinator_grant_count: u64,
    pub(crate) adapter_grant_count: u64,
    pub(crate) coordinator_receipt_count: u64,
    pub(crate) adapter_receipt_count: u64,
    pub(crate) matched_grant_count: u64,
    pub(crate) matched_receipt_count: u64,
    pub(crate) orphan_coordinator_grant_count: u64,
    pub(crate) orphan_adapter_grant_count: u64,
    pub(crate) orphan_coordinator_receipt_count: u64,
    pub(crate) orphan_adapter_receipt_count: u64,
    pub(crate) coordinator_grants_digest: [u8; 32],
    pub(crate) adapter_grants_digest: [u8; 32],
    pub(crate) coordinator_receipts_digest: [u8; 32],
    pub(crate) adapter_receipts_digest: [u8; 32],
    pub(crate) grant_relationships_digest: [u8; 32],
    pub(crate) receipt_relationships_digest: [u8; 32],
}

pub(crate) struct DispatchBackupSourceIdentityInputV1 {
    pub(crate) source_commit: String,
    pub(crate) tool_identity: String,
    pub(crate) tool_digest: [u8; 32],
    pub(crate) artifact_set_digest: [u8; 32],
}

pub(crate) struct VerificationKeyHistoryInputV1 {
    pub(crate) key_id: String,
    pub(crate) public_key_fingerprint: [u8; 32],
    pub(crate) trust_profile_digest: [u8; 32],
    pub(crate) introduced_generation: u64,
    pub(crate) revocation_generation: u64,
    pub(crate) status: VerificationKeyStatusV1,
}

pub(crate) struct VerificationKeySetsInputV1 {
    pub(crate) grant_signing_history: Vec<VerificationKeyHistoryInputV1>,
    pub(crate) receipt_signing_history: Vec<VerificationKeyHistoryInputV1>,
    pub(crate) backup_provisioner_history: Vec<VerificationKeyHistoryInputV1>,
}

pub(crate) struct DispatchBackupIndexInputV1 {
    pub(crate) backup_id: String,
    pub(crate) restore_identity_digest: [u8; 32],
    pub(crate) created_at_utc_ms: u64,
    pub(crate) source: DispatchBackupSourceIdentityInputV1,
    pub(crate) supervisor_epoch: u64,
    pub(crate) pause_evidence_digest: [u8; 32],
    pub(crate) quiescence_evidence_digest: [u8; 32],
    pub(crate) coordinator_completed_at_utc_ms: u64,
    pub(crate) adapter_completed_at_utc_ms: u64,
    pub(crate) index_published_at_utc_ms: u64,
    pub(crate) coordinator: CoordinatorDispatchBackupManifestV1,
    pub(crate) adapter_inbox: AdapterInboxBackupManifestV1,
    pub(crate) cross_store_inventory: CrossStoreInventoryInputV1,
    pub(crate) verification_keys: VerificationKeySetsInputV1,
    pub(crate) provisioner_key_id: String,
}

/// Unsigned index state. Its private fields ensure callers can only obtain it through
/// `prepare_dispatch_backup_index_v1`, after every package and inventory binding passes.
pub(crate) struct PreparedDispatchBackupIndexV1 {
    protected: DispatchBackupProtectedV1,
    protected_digest: [u8; 32],
    signing_input: Vec<u8>,
}

impl PreparedDispatchBackupIndexV1 {
    pub(crate) const fn protected_digest(&self) -> [u8; 32] {
        self.protected_digest
    }

    /// Exact bytes to sign: the frozen signature domain followed by the raw 32-byte
    /// SHA-256 digest of the protected JCS object.
    pub(crate) fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }
}

impl fmt::Debug for PreparedDispatchBackupIndexV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDispatchBackupIndexV1")
            .finish_non_exhaustive()
    }
}

/// Externally trusted verification material. The fingerprint is deliberately derived
/// from `public_key`; it cannot be supplied independently and drift from the key bytes.
#[derive(Clone)]
pub(crate) struct TrustedBackupProvisionerKeyV1 {
    public_key: [u8; 32],
    trust_profile_digest: [u8; 32],
}

impl TrustedBackupProvisionerKeyV1 {
    pub(crate) fn new(
        public_key: [u8; 32],
        trust_profile_digest: [u8; 32],
    ) -> Result<Self, DispatchManifestCodecErrorV1> {
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
        Ok(Self {
            public_key,
            trust_profile_digest,
        })
    }
}

impl fmt::Debug for TrustedBackupProvisionerKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedBackupProvisionerKeyV1")
            .finish_non_exhaustive()
    }
}

pub(crate) trait DispatchBackupTrustResolverV1 {
    fn resolve_backup_provisioner_key_v1(
        &self,
        key_id: &str,
    ) -> Option<TrustedBackupProvisionerKeyV1>;
}

/// Non-forgeable result of canonical decode, external trust binding, and strict Ed25519
/// verification. There is no constructor other than `decode_and_verify_dispatch_backup_index_v1`.
pub(crate) struct VerifiedDispatchBackupIndexV1 {
    decoded: DecodedDispatchManifestV1<DispatchBackupIndexV1>,
}

impl VerifiedDispatchBackupIndexV1 {
    pub(crate) const fn value(&self) -> &DispatchBackupIndexV1 {
        self.decoded.value()
    }

    pub(crate) const fn sha256(&self) -> [u8; 32] {
        self.decoded.sha256()
    }
}

impl fmt::Debug for VerifiedDispatchBackupIndexV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDispatchBackupIndexV1")
            .finish_non_exhaustive()
    }
}

macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter
                        .debug_struct(stringify!($type))
                        .finish_non_exhaustive()
                }
            }
        )+
    };
}

redacted_debug!(
    CoordinatorGenerationsInputV1,
    CoordinatorCountsInputV1,
    CoordinatorInventoriesInputV1,
    CoordinatorDispatchBackupManifestInputV1,
    CrossStoreInventoryInputV1,
    DispatchBackupSourceIdentityInputV1,
    VerificationKeyHistoryInputV1,
    VerificationKeySetsInputV1,
    DispatchBackupIndexInputV1,
);

pub(crate) fn decode_coordinator_dispatch_backup_manifest_v1(
    bytes: &[u8],
) -> Result<
    DecodedDispatchManifestV1<CoordinatorDispatchBackupManifestV1>,
    DispatchManifestCodecErrorV1,
> {
    decode_canonical_json_v1(bytes)
}

pub(crate) fn finalize_coordinator_dispatch_backup_manifest_v1(
    input: CoordinatorDispatchBackupManifestInputV1,
) -> Result<FinalizedCoordinatorDispatchBackupManifestV1, DispatchManifestCodecErrorV1> {
    let body = CoordinatorDispatchBackupManifestBodyV1 {
        root_identity_digest: encode_sha256(input.root_identity_digest),
        application_id: COORDINATOR_APPLICATION_ID_V2,
        user_version: COORDINATOR_USER_VERSION_V2,
        base_schema_digest: encode_sha256(input.base_schema_digest),
        overlay_schema_digest: encode_sha256(input.overlay_schema_digest),
        database_digest: encode_sha256(input.database_digest),
        migration_receipt_digest: encode_sha256(input.migration_receipt_digest),
        root_lifecycle_state: input.root_lifecycle_state,
        generations: CoordinatorGenerationsV1 {
            dispatch_store: input.generations.dispatch_store,
            dispatch: input.generations.dispatch,
            delivery: input.generations.delivery,
            receipt: input.generations.receipt,
            reconciliation: input.generations.reconciliation,
            event: input.generations.event,
            migration: input.generations.migration,
            restore_state: input.generations.restore_state,
        },
        counts: CoordinatorCountsV1 {
            migrations: input.counts.migrations,
            comparisons: input.counts.comparisons,
            grants: input.counts.grants,
            dispatch_records: input.counts.dispatch_records,
            transitions: input.counts.transitions,
            outbox_members: input.counts.outbox_members,
            delivery_attempts: input.counts.delivery_attempts,
            receipts: input.counts.receipts,
            reconciliations: input.counts.reconciliations,
            events: input.counts.events,
        },
        inventory_digests: CoordinatorInventoriesV1 {
            migrations: encode_sha256(input.inventory_digests.migrations),
            comparisons: encode_sha256(input.inventory_digests.comparisons),
            grants: encode_sha256(input.inventory_digests.grants),
            dispatch_records: encode_sha256(input.inventory_digests.dispatch_records),
            transitions: encode_sha256(input.inventory_digests.transitions),
            outbox_members: encode_sha256(input.inventory_digests.outbox_members),
            delivery_attempts: encode_sha256(input.inventory_digests.delivery_attempts),
            receipts: encode_sha256(input.inventory_digests.receipts),
            reconciliations: encode_sha256(input.inventory_digests.reconciliations),
            events: encode_sha256(input.inventory_digests.events),
            complete_store: encode_sha256(input.inventory_digests.complete_store),
        },
    };
    body.validate()?;
    let body_bytes = serde_json_canonicalizer::to_vec(&body)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let manifest_digest: [u8; 32] = Sha256::digest(&body_bytes).into();
    let value = CoordinatorDispatchBackupManifestV1::from_body(body, manifest_digest);
    let finalized = finalize_canonical_json_v1(value)?;
    let (value, bytes, sha256) = finalized.into_parts();
    Ok(FinalizedCoordinatorDispatchBackupManifestV1 {
        value,
        body_bytes,
        manifest_digest,
        bytes,
        sha256,
    })
}

pub(crate) fn decode_adapter_inbox_backup_manifest_v1(
    bytes: &[u8],
) -> Result<DecodedDispatchManifestV1<AdapterInboxBackupManifestV1>, DispatchManifestCodecErrorV1> {
    decode_canonical_json_v1(bytes)
}

pub(crate) fn decode_dispatch_backup_index_v1(
    bytes: &[u8],
) -> Result<DecodedDispatchManifestV1<DispatchBackupIndexV1>, DispatchManifestCodecErrorV1> {
    decode_canonical_json_v1(bytes)
}

pub(crate) fn prepare_dispatch_backup_index_v1(
    input: DispatchBackupIndexInputV1,
) -> Result<PreparedDispatchBackupIndexV1, DispatchManifestCodecErrorV1> {
    let coordinator_database_digest = input.coordinator.database_digest.clone();
    let coordinator_manifest_digest = input.coordinator.manifest_digest.clone();
    let adapter_database_digest = input.adapter_inbox.database_digest.clone();
    let adapter_manifest_digest = input.adapter_inbox.manifest_digest.clone();
    let protected = DispatchBackupProtectedV1 {
        schema: DISPATCH_BACKUP_INDEX_SCHEMA_V1.to_owned(),
        backup_id: input.backup_id,
        restore_identity_digest: encode_sha256(input.restore_identity_digest),
        created_at_utc_ms: input.created_at_utc_ms,
        source: DispatchBackupSourceIdentityV1 {
            source_commit: input.source.source_commit,
            tool_identity: input.source.tool_identity,
            tool_digest: encode_sha256(input.source.tool_digest),
            artifact_set_digest: encode_sha256(input.source.artifact_set_digest),
        },
        supervisor_epoch: input.supervisor_epoch,
        pause_evidence_digest: encode_sha256(input.pause_evidence_digest),
        quiescence_evidence_digest: encode_sha256(input.quiescence_evidence_digest),
        backup_order: vec![
            DispatchBackupStepV1::Coordinator(CoordinatorBackupStepV1 {
                ordinal: 1,
                component: COORDINATOR_BACKUP_COMPONENT_V1.to_owned(),
                completed_at_utc_ms: input.coordinator_completed_at_utc_ms,
                database_digest: coordinator_database_digest,
                manifest_digest: coordinator_manifest_digest,
            }),
            DispatchBackupStepV1::Adapter(AdapterBackupStepV1 {
                ordinal: 2,
                component: ADAPTER_BACKUP_COMPONENT_V1.to_owned(),
                completed_at_utc_ms: input.adapter_completed_at_utc_ms,
                database_digest: adapter_database_digest,
                manifest_digest: adapter_manifest_digest,
            }),
            DispatchBackupStepV1::Index(IndexPublishStepV1 {
                ordinal: 3,
                component: INDEX_PUBLISH_COMPONENT_V1.to_owned(),
                published_at_utc_ms: input.index_published_at_utc_ms,
            }),
        ],
        coordinator: input.coordinator,
        adapter_inbox: input.adapter_inbox,
        cross_store_inventory: cross_store_inventory(input.cross_store_inventory)?,
        verification_keys: VerificationKeySetsV1 {
            grant_signing_history: verification_history(
                input.verification_keys.grant_signing_history,
                GRANT_KEY_PURPOSE_V1,
                GRANT_SIGNATURE_DOMAIN_V1,
            ),
            receipt_signing_history: verification_history(
                input.verification_keys.receipt_signing_history,
                RECEIPT_KEY_PURPOSE_V1,
                RECEIPT_SIGNATURE_DOMAIN_V1,
            ),
            backup_provisioner_history: verification_history(
                input.verification_keys.backup_provisioner_history,
                BACKUP_KEY_PURPOSE_V1,
                BACKUP_SIGNATURE_DOMAIN_V1,
            ),
        },
        signature_profile: IndexSignatureProfileV1 {
            canonicalization: "rfc8785-jcs".to_owned(),
            protected_digest_algorithm: "sha-256".to_owned(),
            signature_algorithm: "ed25519".to_owned(),
            signature_domain: BACKUP_SIGNATURE_DOMAIN_V1.to_owned(),
            signature_input_profile: "signature-domain || protected-digest-raw-32".to_owned(),
            key_purpose: BACKUP_KEY_PURPOSE_V1.to_owned(),
            key_id: input.provisioner_key_id,
        },
    };
    protected.validate()?;
    validate_sequential_backup_cut_protected_v1(&protected)?;
    let protected_bytes = serde_json_canonicalizer::to_vec(&protected)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let protected_digest: [u8; 32] = Sha256::digest(protected_bytes).into();
    let mut signing_input = Vec::with_capacity(BACKUP_SIGNATURE_DOMAIN_V1.len() + 32);
    signing_input.extend_from_slice(BACKUP_SIGNATURE_DOMAIN_V1.as_bytes());
    signing_input.extend_from_slice(&protected_digest);
    Ok(PreparedDispatchBackupIndexV1 {
        protected,
        protected_digest,
        signing_input,
    })
}

pub(crate) fn finalize_dispatch_backup_index_v1(
    prepared: PreparedDispatchBackupIndexV1,
    signature: [u8; 64],
) -> Result<FinalizedDispatchManifestV1<DispatchBackupIndexV1>, DispatchManifestCodecErrorV1> {
    if signature.iter().all(|byte| *byte == 0) {
        return json_invalid();
    }
    finalize_canonical_json_v1(DispatchBackupIndexV1 {
        protected: prepared.protected,
        protected_digest: encode_sha256(prepared.protected_digest),
        signature: URL_SAFE_NO_PAD.encode(signature),
    })
}

pub(crate) fn decode_and_verify_dispatch_backup_index_v1<R: DispatchBackupTrustResolverV1>(
    bytes: &[u8],
    resolver: &R,
) -> Result<VerifiedDispatchBackupIndexV1, DispatchManifestCodecErrorV1> {
    let decoded = decode_dispatch_backup_index_v1(bytes)?;
    let index = decoded.value();
    let signer = index
        .protected
        .verification_keys
        .backup_provisioner_history
        .iter()
        .find(|key| key.key_id == index.protected.signature_profile.key_id)
        .ok_or(DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    if signer.status != VerificationKeyStatusV1::Active {
        return json_invalid();
    }
    let trusted = resolver
        .resolve_backup_provisioner_key_v1(&signer.key_id)
        .ok_or(DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let trusted_fingerprint: [u8; 32] = Sha256::digest(trusted.public_key).into();
    if signer.public_key_fingerprint != encode_sha256(trusted_fingerprint)
        || signer.trust_profile_digest != encode_sha256(trusted.trust_profile_digest)
    {
        return json_invalid();
    }
    let protected_bytes = serde_json_canonicalizer::to_vec(&index.protected)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let protected_digest: [u8; 32] = Sha256::digest(protected_bytes).into();
    let mut signing_input = Vec::with_capacity(BACKUP_SIGNATURE_DOMAIN_V1.len() + 32);
    signing_input.extend_from_slice(BACKUP_SIGNATURE_DOMAIN_V1.as_bytes());
    signing_input.extend_from_slice(&protected_digest);
    let signature = Signature::from_bytes(&decode_signature(&index.signature)?);
    let verifying_key = VerifyingKey::from_bytes(&trusted.public_key)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    verifying_key
        .verify_strict(&signing_input, &signature)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    Ok(VerifiedDispatchBackupIndexV1 { decoded })
}

fn cross_store_inventory(
    input: CrossStoreInventoryInputV1,
) -> Result<CrossStoreInventoryV1, DispatchManifestCodecErrorV1> {
    let mut inventory = CrossStoreInventoryV1 {
        canonicalization_profile: INVENTORY_CANONICALIZATION_V1.to_owned(),
        coordinator_grant_count: input.coordinator_grant_count,
        adapter_grant_count: input.adapter_grant_count,
        coordinator_receipt_count: input.coordinator_receipt_count,
        adapter_receipt_count: input.adapter_receipt_count,
        matched_grant_count: input.matched_grant_count,
        matched_receipt_count: input.matched_receipt_count,
        orphan_coordinator_grant_count: input.orphan_coordinator_grant_count,
        orphan_adapter_grant_count: input.orphan_adapter_grant_count,
        orphan_coordinator_receipt_count: input.orphan_coordinator_receipt_count,
        orphan_adapter_receipt_count: input.orphan_adapter_receipt_count,
        coordinator_grants_digest: encode_sha256(input.coordinator_grants_digest),
        adapter_grants_digest: encode_sha256(input.adapter_grants_digest),
        coordinator_receipts_digest: encode_sha256(input.coordinator_receipts_digest),
        adapter_receipts_digest: encode_sha256(input.adapter_receipts_digest),
        grant_relationships_digest: encode_sha256(input.grant_relationships_digest),
        receipt_relationships_digest: encode_sha256(input.receipt_relationships_digest),
        complete_inventory_digest: String::new(),
    };
    inventory.complete_inventory_digest = encode_sha256(complete_inventory_digest_v1(&inventory)?);
    Ok(inventory)
}

/// The complete inventory digest binds a domain-separated JCS projection containing every
/// cross-store count and component digest except the digest field itself.
fn complete_inventory_digest_v1(
    inventory: &CrossStoreInventoryV1,
) -> Result<[u8; 32], DispatchManifestCodecErrorV1> {
    let mut projection = serde_json::to_value(inventory)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    projection
        .as_object_mut()
        .ok_or(DispatchManifestCodecErrorV1::JsonContractInvalid)?
        .remove("complete_inventory_digest");
    let canonical = serde_json_canonicalizer::to_vec(&projection)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let mut hasher = Sha256::new();
    hasher.update(COMPLETE_INVENTORY_DIGEST_DOMAIN_V1);
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

fn verification_history(
    inputs: Vec<VerificationKeyHistoryInputV1>,
    purpose: &str,
    domain: &str,
) -> Vec<VerificationKeyV1> {
    let mut history = inputs
        .into_iter()
        .map(|input| VerificationKeyV1 {
            key_id: input.key_id,
            key_purpose: purpose.to_owned(),
            algorithm: "ed25519".to_owned(),
            signature_domain: domain.to_owned(),
            public_key_fingerprint: encode_sha256(input.public_key_fingerprint),
            trust_profile_digest: encode_sha256(input.trust_profile_digest),
            introduced_generation: input.introduced_generation,
            revocation_generation: input.revocation_generation,
            status: input.status,
        })
        .collect::<Vec<_>>();
    history.sort_by(|left, right| {
        (left.introduced_generation, left.key_id.as_str())
            .cmp(&(right.introduced_generation, right.key_id.as_str()))
    });
    history
}

impl CoordinatorDispatchBackupManifestV1 {
    fn from_body(body: CoordinatorDispatchBackupManifestBodyV1, digest: [u8; 32]) -> Self {
        Self {
            root_identity_digest: body.root_identity_digest,
            application_id: body.application_id,
            user_version: body.user_version,
            base_schema_digest: body.base_schema_digest,
            overlay_schema_digest: body.overlay_schema_digest,
            database_digest: body.database_digest,
            manifest_digest: encode_sha256(digest),
            migration_receipt_digest: body.migration_receipt_digest,
            root_lifecycle_state: body.root_lifecycle_state,
            generations: body.generations,
            counts: body.counts,
            inventory_digests: body.inventory_digests,
        }
    }

    fn body(&self) -> CoordinatorDispatchBackupManifestBodyV1 {
        CoordinatorDispatchBackupManifestBodyV1 {
            root_identity_digest: self.root_identity_digest.clone(),
            application_id: self.application_id,
            user_version: self.user_version,
            base_schema_digest: self.base_schema_digest.clone(),
            overlay_schema_digest: self.overlay_schema_digest.clone(),
            database_digest: self.database_digest.clone(),
            migration_receipt_digest: self.migration_receipt_digest.clone(),
            root_lifecycle_state: self.root_lifecycle_state,
            generations: self.generations.clone(),
            counts: self.counts.clone(),
            inventory_digests: self.inventory_digests.clone(),
        }
    }
}

impl AdapterInboxBackupManifestV1 {
    fn from_body(body: AdapterInboxBackupManifestBodyV1, digest: [u8; 32]) -> Self {
        Self {
            root_identity_digest: body.root_identity_digest,
            application_id: body.application_id,
            user_version: body.user_version,
            format_version: body.format_version,
            schema_digest: body.schema_digest,
            database_digest: body.database_digest,
            manifest_digest: encode_sha256(digest),
            root_lifecycle_state: body.root_lifecycle_state,
            supervisor_epoch: body.supervisor_epoch,
            generations: body.generations,
            counts: body.counts,
            inventory_digests: body.inventory_digests,
        }
    }

    fn body(&self) -> AdapterInboxBackupManifestBodyV1 {
        AdapterInboxBackupManifestBodyV1 {
            root_identity_digest: self.root_identity_digest.clone(),
            application_id: self.application_id,
            user_version: self.user_version,
            format_version: self.format_version,
            schema_digest: self.schema_digest.clone(),
            database_digest: self.database_digest.clone(),
            root_lifecycle_state: self.root_lifecycle_state,
            supervisor_epoch: self.supervisor_epoch,
            generations: self.generations.clone(),
            counts: self.counts.clone(),
            inventory_digests: self.inventory_digests.clone(),
        }
    }
}

impl ValidateDispatchManifestV1 for CoordinatorDispatchBackupManifestV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        let body = self.body();
        body.validate()?;
        let body_bytes = serde_json_canonicalizer::to_vec(&body)
            .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
        let expected: [u8; 32] = Sha256::digest(body_bytes).into();
        if self.manifest_digest != encode_sha256(expected) {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for CoordinatorDispatchBackupManifestBodyV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if self.application_id != COORDINATOR_APPLICATION_ID_V2
            || self.user_version != COORDINATOR_USER_VERSION_V2
            || [
                &self.root_identity_digest,
                &self.base_schema_digest,
                &self.overlay_schema_digest,
                &self.database_digest,
                &self.migration_receipt_digest,
            ]
            .into_iter()
            .any(|digest| !is_lower_sha256(digest))
        {
            return json_invalid();
        }
        self.generations.validate()?;
        self.counts.validate()?;
        self.inventory_digests.validate()
    }
}

impl ValidateDispatchManifestV1 for CoordinatorGenerationsV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        require_safe_integers(&[
            self.dispatch_store,
            self.dispatch,
            self.delivery,
            self.receipt,
            self.reconciliation,
            self.event,
            self.migration,
            self.restore_state,
        ])
    }
}

impl ValidateDispatchManifestV1 for CoordinatorCountsV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        require_safe_integers(&[
            self.migrations,
            self.comparisons,
            self.grants,
            self.dispatch_records,
            self.transitions,
            self.outbox_members,
            self.delivery_attempts,
            self.receipts,
            self.reconciliations,
            self.events,
        ])
    }
}

impl ValidateDispatchManifestV1 for CoordinatorInventoriesV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if [
            &self.migrations,
            &self.comparisons,
            &self.grants,
            &self.dispatch_records,
            &self.transitions,
            &self.outbox_members,
            &self.delivery_attempts,
            &self.receipts,
            &self.reconciliations,
            &self.events,
            &self.complete_store,
        ]
        .into_iter()
        .any(|digest| !is_lower_sha256(digest))
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for AdapterInboxBackupManifestV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        let body = self.body();
        body.validate()?;
        let body_bytes = serde_json_canonicalizer::to_vec(&body)
            .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
        let expected: [u8; 32] = Sha256::digest(body_bytes).into();
        if self.manifest_digest != encode_sha256(expected) {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for AdapterInboxBackupManifestBodyV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if self.application_id != ADAPTER_APPLICATION_ID_V1
            || self.user_version != ADAPTER_USER_VERSION_V1
            || self.format_version != ADAPTER_FORMAT_VERSION_V1
            || [
                &self.root_identity_digest,
                &self.schema_digest,
                &self.database_digest,
            ]
            .into_iter()
            .any(|digest| !is_lower_sha256(digest))
            || self.supervisor_epoch > MAX_SAFE_U64_V1
        {
            return json_invalid();
        }
        self.generations.validate()?;
        self.counts.validate()?;
        self.inventory_digests.validate()
    }
}

impl ValidateDispatchManifestV1 for AdapterGenerationsV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        require_safe_integers(&[
            self.store,
            self.inbox,
            self.consumption,
            self.receipt,
            self.conflict,
            self.quarantine,
            self.event,
            self.restore_state,
        ])?;
        if !(1..=MAX_SAFE_U64_V1).contains(&self.epoch_observer) {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for AdapterCountsV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        require_safe_integers(&[
            self.inbox_entries,
            self.transitions,
            self.receipts,
            self.conflicts,
            self.quarantines,
            self.events,
        ])
    }
}

impl ValidateDispatchManifestV1 for AdapterInventoriesV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if [
            &self.inbox_entries,
            &self.transitions,
            &self.receipts,
            &self.conflicts,
            &self.quarantines,
            &self.events,
            &self.complete_store,
        ]
        .into_iter()
        .any(|digest| !is_lower_sha256(digest))
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for DispatchBackupIndexV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if !is_lower_sha256(&self.protected_digest) || decode_signature(&self.signature).is_err() {
            return json_invalid();
        }
        self.protected.validate()?;
        let protected_bytes = serde_json_canonicalizer::to_vec(&self.protected)
            .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
        if encode_sha256(Sha256::digest(protected_bytes).into()) != self.protected_digest {
            return json_invalid();
        }
        validate_sequential_backup_cut_v1(self)
    }
}

impl ValidateDispatchManifestV1 for DispatchBackupProtectedV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if self.schema != DISPATCH_BACKUP_INDEX_SCHEMA_V1
            || !is_identifier(&self.backup_id)
            || !is_lower_sha256(&self.restore_identity_digest)
            || self.created_at_utc_ms > MAX_SAFE_U64_V1
            || self.supervisor_epoch > MAX_SAFE_U64_V1
            || !is_lower_sha256(&self.pause_evidence_digest)
            || !is_lower_sha256(&self.quiescence_evidence_digest)
        {
            return json_invalid();
        }
        self.source.validate()?;
        self.coordinator.validate()?;
        self.adapter_inbox.validate()?;
        self.cross_store_inventory.validate()?;
        self.validate_cross_store_package_bindings()?;
        self.verification_keys.validate()?;
        self.signature_profile.validate()?;
        let matching_provisioner_keys = self
            .verification_keys
            .backup_provisioner_history
            .iter()
            .filter(|key| key.key_id == self.signature_profile.key_id)
            .count();
        let signer_is_active = self
            .verification_keys
            .backup_provisioner_history
            .iter()
            .any(|key| {
                key.key_id == self.signature_profile.key_id
                    && key.status == VerificationKeyStatusV1::Active
            });
        if matching_provisioner_keys != 1 || !signer_is_active {
            return json_invalid();
        }
        Ok(())
    }
}

impl DispatchBackupProtectedV1 {
    fn validate_cross_store_package_bindings(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        let inventory = &self.cross_store_inventory;
        if inventory.coordinator_grant_count != self.coordinator.counts.grants
            || inventory.coordinator_receipt_count != self.coordinator.counts.receipts
            || inventory.adapter_grant_count != self.adapter_inbox.counts.inbox_entries
            || inventory.adapter_receipt_count != self.adapter_inbox.counts.receipts
            || inventory.coordinator_grants_digest != self.coordinator.inventory_digests.grants
            || inventory.coordinator_receipts_digest != self.coordinator.inventory_digests.receipts
            || inventory.adapter_grants_digest != self.adapter_inbox.inventory_digests.inbox_entries
            || inventory.adapter_receipts_digest != self.adapter_inbox.inventory_digests.receipts
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for DispatchBackupSourceIdentityV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if !is_lower_hex(&self.source_commit, 40)
            || !is_identifier(&self.tool_identity)
            || !is_lower_sha256(&self.tool_digest)
            || !is_lower_sha256(&self.artifact_set_digest)
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for CrossStoreInventoryV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        require_safe_integers(&[
            self.coordinator_grant_count,
            self.adapter_grant_count,
            self.coordinator_receipt_count,
            self.adapter_receipt_count,
            self.matched_grant_count,
            self.matched_receipt_count,
            self.orphan_coordinator_grant_count,
            self.orphan_adapter_grant_count,
            self.orphan_coordinator_receipt_count,
            self.orphan_adapter_receipt_count,
        ])?;
        if self.canonicalization_profile != INVENTORY_CANONICALIZATION_V1
            || [
                &self.coordinator_grants_digest,
                &self.adapter_grants_digest,
                &self.coordinator_receipts_digest,
                &self.adapter_receipts_digest,
                &self.grant_relationships_digest,
                &self.receipt_relationships_digest,
                &self.complete_inventory_digest,
            ]
            .into_iter()
            .any(|digest| !is_lower_sha256(digest))
            || self
                .coordinator_grant_count
                .checked_sub(self.matched_grant_count)
                != Some(self.orphan_coordinator_grant_count)
            || self
                .adapter_grant_count
                .checked_sub(self.matched_grant_count)
                != Some(self.orphan_adapter_grant_count)
            || self
                .coordinator_receipt_count
                .checked_sub(self.matched_receipt_count)
                != Some(self.orphan_coordinator_receipt_count)
            || self
                .adapter_receipt_count
                .checked_sub(self.matched_receipt_count)
                != Some(self.orphan_adapter_receipt_count)
            || self.complete_inventory_digest != encode_sha256(complete_inventory_digest_v1(self)?)
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for VerificationKeySetsV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        validate_key_history(
            &self.grant_signing_history,
            GRANT_KEY_PURPOSE_V1,
            GRANT_SIGNATURE_DOMAIN_V1,
        )?;
        validate_key_history(
            &self.receipt_signing_history,
            RECEIPT_KEY_PURPOSE_V1,
            RECEIPT_SIGNATURE_DOMAIN_V1,
        )?;
        validate_key_history(
            &self.backup_provisioner_history,
            BACKUP_KEY_PURPOSE_V1,
            BACKUP_SIGNATURE_DOMAIN_V1,
        )?;
        let mut key_ids = BTreeSet::new();
        let mut fingerprints = BTreeSet::new();
        for key in self
            .grant_signing_history
            .iter()
            .chain(self.receipt_signing_history.iter())
            .chain(self.backup_provisioner_history.iter())
        {
            if !key_ids.insert(key.key_id.as_str())
                || !fingerprints.insert(key.public_key_fingerprint.as_str())
            {
                return json_invalid();
            }
        }
        Ok(())
    }
}

impl ValidateDispatchManifestV1 for VerificationKeyV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if !is_identifier(&self.key_id)
            || self.algorithm != "ed25519"
            || !is_lower_sha256(&self.public_key_fingerprint)
            || !is_lower_sha256(&self.trust_profile_digest)
            || self.introduced_generation == 0
            // `revocation_generation` records cryptographic revocation only. ACTIVE and
            // RETIRED keys therefore keep zero (retirement is non-revocation lifecycle
            // state); REVOKED must name a strictly later generation than introduction.
            || match self.status {
                VerificationKeyStatusV1::Active | VerificationKeyStatusV1::Retired => {
                    self.revocation_generation != 0
                }
                VerificationKeyStatusV1::Revoked => {
                    self.revocation_generation <= self.introduced_generation
                }
            }
        {
            return json_invalid();
        }
        require_safe_integers(&[self.introduced_generation, self.revocation_generation])
    }
}

impl ValidateDispatchManifestV1 for IndexSignatureProfileV1 {
    fn validate(&self) -> Result<(), DispatchManifestCodecErrorV1> {
        if self.canonicalization != "rfc8785-jcs"
            || self.protected_digest_algorithm != "sha-256"
            || self.signature_algorithm != "ed25519"
            || self.signature_domain != BACKUP_SIGNATURE_DOMAIN_V1
            || self.signature_input_profile != "signature-domain || protected-digest-raw-32"
            || self.key_purpose != BACKUP_KEY_PURPOSE_V1
            || !is_identifier(&self.key_id)
        {
            return json_invalid();
        }
        Ok(())
    }
}

/// Validates the closed coordinator -> adapter -> signed-index-last cut and all digest
/// bindings that make the independent backups one coherent paused evidence package.
pub(crate) fn validate_sequential_backup_cut_v1(
    index: &DispatchBackupIndexV1,
) -> Result<(), DispatchManifestCodecErrorV1> {
    validate_sequential_backup_cut_protected_v1(&index.protected)
}

fn validate_sequential_backup_cut_protected_v1(
    protected: &DispatchBackupProtectedV1,
) -> Result<(), DispatchManifestCodecErrorV1> {
    let [DispatchBackupStepV1::Coordinator(coordinator), DispatchBackupStepV1::Adapter(adapter), DispatchBackupStepV1::Index(published)] =
        protected.backup_order.as_slice()
    else {
        return json_invalid();
    };
    require_safe_integers(&[
        coordinator.completed_at_utc_ms,
        adapter.completed_at_utc_ms,
        published.published_at_utc_ms,
    ])?;
    if coordinator.ordinal != 1
        || coordinator.component != COORDINATOR_BACKUP_COMPONENT_V1
        || adapter.ordinal != 2
        || adapter.component != ADAPTER_BACKUP_COMPONENT_V1
        || published.ordinal != 3
        || published.component != INDEX_PUBLISH_COMPONENT_V1
        || coordinator.completed_at_utc_ms > adapter.completed_at_utc_ms
        || adapter.completed_at_utc_ms > published.published_at_utc_ms
        || coordinator.database_digest != protected.coordinator.database_digest
        || coordinator.manifest_digest != protected.coordinator.manifest_digest
        || adapter.database_digest != protected.adapter_inbox.database_digest
        || adapter.manifest_digest != protected.adapter_inbox.manifest_digest
        || protected.supervisor_epoch != protected.adapter_inbox.supervisor_epoch
    {
        return json_invalid();
    }
    Ok(())
}

fn validate_key_history(
    history: &[VerificationKeyV1],
    expected_purpose: &str,
    expected_domain: &str,
) -> Result<(), DispatchManifestCodecErrorV1> {
    if history.is_empty() || history.len() > MAX_KEY_HISTORY_V1 {
        return json_invalid();
    }
    let mut key_ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    let mut prior_order: Option<(u64, &str)> = None;
    for key in history {
        key.validate()?;
        let order = (key.introduced_generation, key.key_id.as_str());
        if key.key_purpose != expected_purpose
            || key.signature_domain != expected_domain
            || !key_ids.insert(key.key_id.as_str())
            || !fingerprints.insert(key.public_key_fingerprint.as_str())
            || prior_order.is_some_and(|prior| prior >= order)
        {
            return json_invalid();
        }
        prior_order = Some(order);
    }
    Ok(())
}

fn require_safe_integers(values: &[u64]) -> Result<(), DispatchManifestCodecErrorV1> {
    if values.iter().any(|value| *value > MAX_SAFE_U64_V1) {
        return json_invalid();
    }
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b':'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_lower_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn encode_sha256(value: [u8; 32]) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_signature(value: &str) -> Result<[u8; 64], DispatchManifestCodecErrorV1> {
    if value.len() != 86
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
    {
        return json_invalid();
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    let decoded: [u8; 64] = decoded
        .try_into()
        .map_err(|_| DispatchManifestCodecErrorV1::JsonContractInvalid)?;
    if URL_SAFE_NO_PAD.encode(decoded) != value {
        return json_invalid();
    }
    Ok(decoded)
}

fn json_invalid<T>() -> Result<T, DispatchManifestCodecErrorV1> {
    Err(DispatchManifestCodecErrorV1::JsonContractInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    const PROVISIONER_KEY_ID: &str = "backup-key:fixture-1";
    const PROVISIONER_SEED: [u8; 32] = [91; 32];
    const PROVISIONER_TRUST_PROFILE: [u8; 32] = [92; 32];

    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn coordinator_input() -> CoordinatorDispatchBackupManifestInputV1 {
        CoordinatorDispatchBackupManifestInputV1 {
            root_identity_digest: digest(1),
            base_schema_digest: digest(2),
            overlay_schema_digest: digest(3),
            database_digest: digest(4),
            migration_receipt_digest: digest(6),
            root_lifecycle_state: BackupRootLifecycleStateV1::Active,
            generations: CoordinatorGenerationsInputV1 {
                dispatch_store: 10,
                dispatch: 11,
                delivery: 12,
                receipt: 13,
                reconciliation: 14,
                event: 15,
                migration: 16,
                restore_state: 17,
            },
            counts: CoordinatorCountsInputV1 {
                migrations: 1,
                comparisons: 3,
                grants: 3,
                dispatch_records: 3,
                transitions: 6,
                outbox_members: 3,
                delivery_attempts: 3,
                receipts: 2,
                reconciliations: 0,
                events: 8,
            },
            inventory_digests: CoordinatorInventoriesInputV1 {
                migrations: digest(7),
                comparisons: digest(8),
                grants: digest(9),
                dispatch_records: digest(10),
                transitions: digest(11),
                outbox_members: digest(12),
                delivery_attempts: digest(13),
                receipts: digest(14),
                reconciliations: digest(15),
                events: digest(16),
                complete_store: digest(17),
            },
        }
    }

    fn adapter_manifest() -> AdapterInboxBackupManifestV1 {
        let body = AdapterInboxBackupManifestBodyV1 {
            root_identity_digest: encode_sha256(digest(20)),
            application_id: ADAPTER_APPLICATION_ID_V1,
            user_version: ADAPTER_USER_VERSION_V1,
            format_version: ADAPTER_FORMAT_VERSION_V1,
            schema_digest: encode_sha256(digest(21)),
            database_digest: encode_sha256(digest(22)),
            root_lifecycle_state: BackupRootLifecycleStateV1::Active,
            supervisor_epoch: 7,
            generations: AdapterGenerationsV1 {
                store: 30,
                inbox: 31,
                consumption: 32,
                receipt: 33,
                conflict: 34,
                quarantine: 35,
                event: 36,
                epoch_observer: 7,
                restore_state: 37,
            },
            counts: AdapterCountsV1 {
                inbox_entries: 2,
                transitions: 4,
                receipts: 2,
                conflicts: 0,
                quarantines: 0,
                events: 6,
            },
            inventory_digests: AdapterInventoriesV1 {
                inbox_entries: encode_sha256(digest(24)),
                transitions: encode_sha256(digest(25)),
                receipts: encode_sha256(digest(26)),
                conflicts: encode_sha256(digest(27)),
                quarantines: encode_sha256(digest(28)),
                events: encode_sha256(digest(29)),
                complete_store: encode_sha256(digest(30)),
            },
        };
        let body_bytes = canonical(&serde_json::to_value(&body).unwrap());
        AdapterInboxBackupManifestV1::from_body(body, Sha256::digest(body_bytes).into())
    }

    fn key(
        key_id: &str,
        value: u8,
        status: VerificationKeyStatusV1,
    ) -> VerificationKeyHistoryInputV1 {
        VerificationKeyHistoryInputV1 {
            key_id: key_id.to_owned(),
            public_key_fingerprint: digest(value),
            trust_profile_digest: digest(value.wrapping_add(1)),
            introduced_generation: 1,
            revocation_generation: 0,
            status,
        }
    }

    fn index_input() -> DispatchBackupIndexInputV1 {
        let coordinator = finalize_coordinator_dispatch_backup_manifest_v1(coordinator_input())
            .unwrap()
            .value()
            .clone();
        DispatchBackupIndexInputV1 {
            backup_id: "dispatch-backup:fixture-1".to_owned(),
            restore_identity_digest: digest(31),
            created_at_utc_ms: 400,
            source: DispatchBackupSourceIdentityInputV1 {
                source_commit: "a".repeat(40),
                tool_identity: "helixos-backup:fixture-1".to_owned(),
                tool_digest: digest(32),
                artifact_set_digest: digest(33),
            },
            supervisor_epoch: 7,
            pause_evidence_digest: digest(34),
            quiescence_evidence_digest: digest(35),
            coordinator_completed_at_utc_ms: 100,
            adapter_completed_at_utc_ms: 200,
            index_published_at_utc_ms: 300,
            coordinator,
            adapter_inbox: adapter_manifest(),
            cross_store_inventory: CrossStoreInventoryInputV1 {
                coordinator_grant_count: 3,
                adapter_grant_count: 2,
                coordinator_receipt_count: 2,
                adapter_receipt_count: 2,
                matched_grant_count: 2,
                matched_receipt_count: 2,
                orphan_coordinator_grant_count: 1,
                orphan_adapter_grant_count: 0,
                orphan_coordinator_receipt_count: 0,
                orphan_adapter_receipt_count: 0,
                coordinator_grants_digest: digest(9),
                adapter_grants_digest: digest(24),
                coordinator_receipts_digest: digest(14),
                adapter_receipts_digest: digest(26),
                grant_relationships_digest: digest(40),
                receipt_relationships_digest: digest(41),
            },
            verification_keys: VerificationKeySetsInputV1 {
                grant_signing_history: vec![key(
                    "grant-key:fixture-1",
                    43,
                    VerificationKeyStatusV1::Retired,
                )],
                receipt_signing_history: vec![key(
                    "receipt-key:fixture-1",
                    45,
                    VerificationKeyStatusV1::Active,
                )],
                backup_provisioner_history: vec![key(
                    PROVISIONER_KEY_ID,
                    47,
                    VerificationKeyStatusV1::Active,
                )],
            },
            provisioner_key_id: PROVISIONER_KEY_ID.to_owned(),
        }
    }

    fn trusted_index_input() -> DispatchBackupIndexInputV1 {
        let mut input = index_input();
        let public_key = SigningKey::from_bytes(&PROVISIONER_SEED)
            .verifying_key()
            .to_bytes();
        input.verification_keys.backup_provisioner_history[0].public_key_fingerprint =
            Sha256::digest(public_key).into();
        input.verification_keys.backup_provisioner_history[0].trust_profile_digest =
            PROVISIONER_TRUST_PROFILE;
        input
    }

    fn finalized_index() -> FinalizedDispatchManifestV1<DispatchBackupIndexV1> {
        let prepared = prepare_dispatch_backup_index_v1(trusted_index_input()).unwrap();
        let signature = SigningKey::from_bytes(&PROVISIONER_SEED)
            .sign(prepared.signing_input())
            .to_bytes();
        finalize_dispatch_backup_index_v1(prepared, signature).unwrap()
    }

    struct Resolver {
        public_key: [u8; 32],
        trust_profile: [u8; 32],
    }

    impl DispatchBackupTrustResolverV1 for Resolver {
        fn resolve_backup_provisioner_key_v1(
            &self,
            key_id: &str,
        ) -> Option<TrustedBackupProvisionerKeyV1> {
            (key_id == PROVISIONER_KEY_ID).then(|| {
                TrustedBackupProvisionerKeyV1::new(self.public_key, self.trust_profile).unwrap()
            })
        }
    }

    fn resolver() -> Resolver {
        Resolver {
            public_key: SigningKey::from_bytes(&PROVISIONER_SEED)
                .verifying_key()
                .to_bytes(),
            trust_profile: PROVISIONER_TRUST_PROFILE,
        }
    }

    fn canonical(value: &Value) -> Vec<u8> {
        serde_json_canonicalizer::to_vec(value).unwrap()
    }

    fn refresh_protected_digest(value: &mut Value) {
        let protected = canonical(&value["protected"]);
        value["protected_digest"] = Value::String(encode_sha256(Sha256::digest(protected).into()));
    }

    #[test]
    fn coordinator_manifest_round_trips_and_rejects_closed_contract_drift() {
        let finalized =
            finalize_coordinator_dispatch_backup_manifest_v1(coordinator_input()).unwrap();
        let decoded = decode_coordinator_dispatch_backup_manifest_v1(finalized.bytes()).unwrap();
        assert_eq!(decoded.sha256(), finalized.sha256());
        assert_eq!(decoded.value(), finalized.value());
        let expected_manifest_digest: [u8; 32] = Sha256::digest(finalized.body_bytes()).into();
        assert_eq!(finalized.manifest_digest(), expected_manifest_digest);
        assert_ne!(finalized.manifest_digest(), finalized.sha256());

        let source = std::str::from_utf8(finalized.bytes()).unwrap();
        let duplicate = format!("{{\"application_id\":1212962883,{}", &source[1..]);
        let mut unknown: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        unknown.as_object_mut().unwrap().insert(
            "secret_key".to_owned(),
            Value::String("forbidden".to_owned()),
        );
        let mut tampered: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        tampered["user_version"] = Value::from(1_u64);
        let mut body_tamper: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        body_tamper["counts"]["grants"] = Value::from(4_u64);
        let mut arbitrary_binding: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        arbitrary_binding["manifest_digest"] = Value::String(encode_sha256(digest(5)));
        let mut newline = finalized.bytes().to_vec();
        newline.push(b'\n');

        for invalid in [
            duplicate.into_bytes(),
            canonical(&unknown),
            canonical(&tampered),
            canonical(&body_tamper),
            canonical(&arbitrary_binding),
            newline,
        ] {
            assert_eq!(
                decode_coordinator_dispatch_backup_manifest_v1(&invalid).unwrap_err(),
                DispatchManifestCodecErrorV1::JsonContractInvalid
            );
        }
    }

    #[test]
    fn signed_index_round_trips_digest_bound_canonical_bytes_without_secret_members() {
        let prepared = prepare_dispatch_backup_index_v1(trusted_index_input()).unwrap();
        let expected_digest: [u8; 32] =
            Sha256::digest(serde_json_canonicalizer::to_vec(&prepared.protected).unwrap()).into();
        assert_eq!(prepared.protected_digest(), expected_digest);
        let mut expected_input = BACKUP_SIGNATURE_DOMAIN_V1.as_bytes().to_vec();
        expected_input.extend_from_slice(&expected_digest);
        assert_eq!(prepared.signing_input(), expected_input);
        let signature = SigningKey::from_bytes(&PROVISIONER_SEED)
            .sign(prepared.signing_input())
            .to_bytes();
        let finalized = finalize_dispatch_backup_index_v1(prepared, signature).unwrap();
        assert_eq!(
            finalized.bytes(),
            canonical(&serde_json::to_value(finalized.value()).unwrap())
        );
        let decoded = decode_dispatch_backup_index_v1(finalized.bytes()).unwrap();
        assert_eq!(decoded.sha256(), finalized.sha256());
        assert_eq!(decoded.value(), finalized.value());
        let verified =
            decode_and_verify_dispatch_backup_index_v1(finalized.bytes(), &resolver()).unwrap();
        assert_eq!(verified.sha256(), finalized.sha256());
        assert_eq!(verified.value(), finalized.value());

        let value: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        let protected = canonical(&value["protected"]);
        assert_eq!(
            value["protected_digest"],
            Value::String(encode_sha256(Sha256::digest(protected).into()))
        );
        let serialized = std::str::from_utf8(finalized.bytes()).unwrap();
        for forbidden in [
            "private_key",
            "secret_key",
            "signing_key",
            "key_material",
            "mnemonic",
            "seed",
        ] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn decoder_rejects_digest_tamper_substitution_duplicate_and_order_drift() {
        let finalized = finalized_index();
        let source = std::str::from_utf8(finalized.bytes()).unwrap();
        let duplicate = format!(
            "{{\"protected_digest\":\"{}\",{}",
            "0".repeat(64),
            &source[1..]
        );

        let mut digest_tamper: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        digest_tamper["protected_digest"] = Value::String("0".repeat(64));

        let mut purpose_substitution: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        purpose_substitution["protected"]["verification_keys"]["grant_signing_history"][0]
            ["key_purpose"] = Value::String(RECEIPT_KEY_PURPOSE_V1.to_owned());
        refresh_protected_digest(&mut purpose_substitution);

        let mut provisioner_substitution: Value =
            serde_json::from_slice(finalized.bytes()).unwrap();
        provisioner_substitution["protected"]["signature_profile"]["key_id"] =
            Value::String("receipt-key:fixture-1".to_owned());
        refresh_protected_digest(&mut provisioner_substitution);

        let mut order_drift: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        order_drift["protected"]["backup_order"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        refresh_protected_digest(&mut order_drift);

        let mut digest_binding_drift: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        digest_binding_drift["protected"]["coordinator"]["database_digest"] =
            Value::String("f".repeat(64));
        refresh_protected_digest(&mut digest_binding_drift);

        for invalid in [
            duplicate.into_bytes(),
            canonical(&digest_tamper),
            canonical(&purpose_substitution),
            canonical(&provisioner_substitution),
            canonical(&order_drift),
            canonical(&digest_binding_drift),
        ] {
            assert_eq!(
                decode_dispatch_backup_index_v1(&invalid).unwrap_err(),
                DispatchManifestCodecErrorV1::JsonContractInvalid
            );
        }
    }

    #[test]
    fn finalizer_rejects_nonsequential_cut_or_nonunique_provisioner_binding() {
        let mut reversed = index_input();
        reversed.coordinator_completed_at_utc_ms = 201;
        assert_eq!(
            prepare_dispatch_backup_index_v1(reversed).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut missing_key = index_input();
        missing_key.provisioner_key_id = "unknown-backup-key".to_owned();
        assert_eq!(
            prepare_dispatch_backup_index_v1(missing_key).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut inconsistent_inventory = index_input();
        inconsistent_inventory
            .cross_store_inventory
            .orphan_coordinator_grant_count = 0;
        assert_eq!(
            prepare_dispatch_backup_index_v1(inconsistent_inventory).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );
    }

    #[test]
    fn verifier_rejects_invalid_signature_fingerprint_trust_and_revoked_signer() {
        let zero_prepared = prepare_dispatch_backup_index_v1(trusted_index_input()).unwrap();
        assert_eq!(
            finalize_dispatch_backup_index_v1(zero_prepared, [0; 64]).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let prepared = prepare_dispatch_backup_index_v1(trusted_index_input()).unwrap();
        let invalid = finalize_dispatch_backup_index_v1(prepared, [7; 64]).unwrap();
        assert_eq!(
            decode_and_verify_dispatch_backup_index_v1(invalid.bytes(), &resolver()).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut wrong_fingerprint = trusted_index_input();
        wrong_fingerprint
            .verification_keys
            .backup_provisioner_history[0]
            .public_key_fingerprint = digest(47);
        let prepared = prepare_dispatch_backup_index_v1(wrong_fingerprint).unwrap();
        let signature = SigningKey::from_bytes(&PROVISIONER_SEED)
            .sign(prepared.signing_input())
            .to_bytes();
        let finalized = finalize_dispatch_backup_index_v1(prepared, signature).unwrap();
        assert_eq!(
            decode_and_verify_dispatch_backup_index_v1(finalized.bytes(), &resolver()).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let finalized = finalized_index();
        let wrong_trust = Resolver {
            trust_profile: digest(93),
            ..resolver()
        };
        assert_eq!(
            decode_and_verify_dispatch_backup_index_v1(finalized.bytes(), &wrong_trust)
                .unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut revoked = trusted_index_input();
        let signer = &mut revoked.verification_keys.backup_provisioner_history[0];
        signer.status = VerificationKeyStatusV1::Revoked;
        signer.revocation_generation = signer.introduced_generation;
        assert_eq!(
            prepare_dispatch_backup_index_v1(revoked).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );
    }

    #[test]
    fn key_histories_reject_ambiguous_identity_order_and_generation_state() {
        let mut duplicate_id = trusted_index_input();
        duplicate_id
            .verification_keys
            .backup_provisioner_history
            .push(key(
                PROVISIONER_KEY_ID,
                60,
                VerificationKeyStatusV1::Retired,
            ));
        assert_eq!(
            prepare_dispatch_backup_index_v1(duplicate_id).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut cross_purpose_id = trusted_index_input();
        cross_purpose_id.verification_keys.receipt_signing_history[0].key_id =
            "grant-key:fixture-1".to_owned();
        assert_eq!(
            prepare_dispatch_backup_index_v1(cross_purpose_id).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut duplicate_fingerprint = trusted_index_input();
        duplicate_fingerprint
            .verification_keys
            .receipt_signing_history[0]
            .public_key_fingerprint = duplicate_fingerprint
            .verification_keys
            .grant_signing_history[0]
            .public_key_fingerprint;
        assert_eq!(
            prepare_dispatch_backup_index_v1(duplicate_fingerprint).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut invalid_generation = trusted_index_input();
        invalid_generation.verification_keys.grant_signing_history[0].revocation_generation = 2;
        assert_eq!(
            prepare_dispatch_backup_index_v1(invalid_generation).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut equal_revocation = trusted_index_input();
        let revoked = &mut equal_revocation.verification_keys.grant_signing_history[0];
        revoked.status = VerificationKeyStatusV1::Revoked;
        revoked.introduced_generation = 3;
        revoked.revocation_generation = 3;
        assert_eq!(
            prepare_dispatch_backup_index_v1(equal_revocation).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let finalized = finalized_index();
        let mut out_of_order: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        let history = out_of_order["protected"]["verification_keys"]["grant_signing_history"]
            .as_array_mut()
            .unwrap();
        let mut second = history[0].clone();
        second["key_id"] = Value::String("grant-key:fixture-0".to_owned());
        second["public_key_fingerprint"] = Value::String(encode_sha256(digest(61)));
        history.push(second);
        refresh_protected_digest(&mut out_of_order);
        assert_eq!(
            decode_dispatch_backup_index_v1(&canonical(&out_of_order)).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );
    }

    #[test]
    fn cross_store_inventory_rejects_package_mismatch_and_complete_digest_tamper() {
        let mut count_mismatch = trusted_index_input();
        count_mismatch.cross_store_inventory.coordinator_grant_count = 4;
        count_mismatch
            .cross_store_inventory
            .orphan_coordinator_grant_count = 2;
        assert_eq!(
            prepare_dispatch_backup_index_v1(count_mismatch).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let mut digest_mismatch = trusted_index_input();
        digest_mismatch
            .cross_store_inventory
            .adapter_receipts_digest = digest(62);
        assert_eq!(
            prepare_dispatch_backup_index_v1(digest_mismatch).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );

        let finalized = finalized_index();
        let mut complete_tamper: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        complete_tamper["protected"]["cross_store_inventory"]["complete_inventory_digest"] =
            Value::String(encode_sha256(digest(63)));
        refresh_protected_digest(&mut complete_tamper);
        assert_eq!(
            decode_dispatch_backup_index_v1(&canonical(&complete_tamper)).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );
    }

    #[test]
    fn decoder_rejects_oversized_input_before_json_parsing() {
        let oversized = vec![b' '; MAX_DISPATCH_MANIFEST_BYTES_V1 + 1];
        assert_eq!(
            decode_dispatch_backup_index_v1(&oversized).unwrap_err(),
            DispatchManifestCodecErrorV1::JsonContractInvalid
        );
    }
}
