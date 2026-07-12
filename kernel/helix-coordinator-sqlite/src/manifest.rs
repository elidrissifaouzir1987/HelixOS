//! Private canonical manifest and provenance-codec boundary.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use helix_contracts::{Identifier, Sha256Digest, MAX_SAFE_U64};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

#[cfg(not(test))]
use crate::maintenance;
#[cfg(not(test))]
use helix_plan_preparation::RecoveryEvidenceClassV1;
#[cfg(not(test))]
use std::collections::BTreeMap;

pub(crate) const PREPARATION_BACKUP_MANIFEST_V1_JSON_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/004-durable-preparation/contracts/preparation-backup-manifest-v1.schema.json"
));
pub(crate) const BACKUP_PROVENANCE_ATTESTATION_V1_JSON_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/004-durable-preparation/contracts/preparation-backup-provenance-attestation-v1.schema.json"
));
pub(crate) const RECOVERY_ROOT_METADATA_V1_JSON_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/004-durable-preparation/contracts/recovery-root-metadata-v1.schema.json"
));
pub(crate) const RECOVERY_SNAPSHOT_MANIFEST_V1_JSON_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/004-durable-preparation/contracts/recovery-snapshot-manifest-v1.schema.json"
));

const PREPARATION_BACKUP_SCHEMA_V1: &str = "helixos.preparation-backup/1";
const PROVENANCE_ATTESTATION_SCHEMA_V1: &str =
    "helixos.preparation-backup-provenance-attestation/1";
const PROVENANCE_PROTECTED_SCHEMA_V1: &str = "helixos.preparation-backup-provenance-protected/1";
const RECOVERY_ROOT_METADATA_SCHEMA_V1: &str = "helixos.recovery-root-metadata/1";
const RECOVERY_SNAPSHOT_SCHEMA_V1: &str = "helixos.recovery-snapshot/1";
const RECOVERY_SNAPSHOT_SUMMARY_SCHEMA_V1: &str = "helixos.recovery-snapshot-summary/1";
const MAX_INVENTORY_ITEMS_V1: usize = 1_000_000;
const APPLICATION_ID_V1: i64 = 1_212_962_883;
const STORE_SCHEMA_VERSION_V1: i64 = 1;

pub(crate) const ATTESTATION_SIGNATURE_DOMAIN_V1: &[u8] =
    b"HELIXOS\0PREPARATION-BACKUP-ATTESTATION\0V1\0";
const PACKAGE_BINDING_DOMAIN_V1: &[u8] = b"HELIXOS\0RECOVERY-BACKUP-PACKAGE-BINDING\0V1\0";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestCodecErrorV1 {
    JsonContractInvalid,
    ProvenanceInvalid,
}

impl ManifestCodecErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::JsonContractInvalid => "JSON_CONTRACT_INVALID",
            Self::ProvenanceInvalid => "PROVENANCE_INVALID",
        }
    }
}

impl fmt::Debug for ManifestCodecErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for ManifestCodecErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ManifestCodecErrorV1 {}

impl From<ManifestCodecErrorV1> for crate::error::InternalCoordinatorError {
    fn from(error: ManifestCodecErrorV1) -> Self {
        match error {
            ManifestCodecErrorV1::JsonContractInvalid => Self::JsonContractInvalid,
            ManifestCodecErrorV1::ProvenanceInvalid => Self::ProvenanceInvalid,
        }
    }
}

pub(crate) struct DecodedCanonicalJsonV1<T> {
    value: T,
    sha256: [u8; 32],
}

/// Exact RFC 8785 bytes produced from one validated closed manifest value.
///
/// The digest is over `bytes` exactly.  Keeping the typed value beside the bytes lets
/// the backup pipeline cross-bind subsequent package members without reparsing or
/// constructing a second, potentially different JSON object.
pub(crate) struct FinalizedCanonicalJsonV1<T> {
    value: T,
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl<T> FinalizedCanonicalJsonV1<T> {
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

impl<T> fmt::Debug for FinalizedCanonicalJsonV1<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedCanonicalJsonV1")
            .finish_non_exhaustive()
    }
}

impl<T> DecodedCanonicalJsonV1<T> {
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

impl<T> fmt::Debug for DecodedCanonicalJsonV1<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedCanonicalJsonV1")
            .finish_non_exhaustive()
    }
}

trait ValidateManifestV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1>;
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
            let value = object.next_value::<UniqueJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn decode_canonical_json_v1<T>(
    bytes: &[u8],
) -> Result<DecodedCanonicalJsonV1<T>, ManifestCodecErrorV1>
where
    T: DeserializeOwned + ValidateManifestV1,
{
    if bytes.is_empty() || bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(ManifestCodecErrorV1::JsonContractInvalid);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    deserializer
        .end()
        .map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    let canonical = serde_json_canonicalizer::to_vec(&raw.0)
        .map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    if canonical != bytes {
        return Err(ManifestCodecErrorV1::JsonContractInvalid);
    }
    let value: T =
        serde_json::from_value(raw.0).map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    value.validate()?;
    Ok(DecodedCanonicalJsonV1 {
        value,
        sha256: Sha256::digest(bytes).into(),
    })
}

fn finalize_canonical_json_v1<T>(
    value: T,
) -> Result<FinalizedCanonicalJsonV1<T>, ManifestCodecErrorV1>
where
    T: Serialize + ValidateManifestV1,
{
    value.validate()?;
    let bytes = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    let sha256 = Sha256::digest(&bytes).into();
    Ok(FinalizedCanonicalJsonV1 {
        value,
        bytes,
        sha256,
    })
}

fn deserialize_present_value<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparationBackupManifestV1 {
    schema: String,
    application_id: i64,
    store_schema_version: i64,
    source_coordinator_root_identity_sha256: String,
    source_recovery_root_identity_sha256: String,
    source_instance_identity_sha256: String,
    source_root_lifecycle_state: String,
    coordinator_schema_sha256: String,
    coordinator_database_sha256: String,
    sqlite: SqliteSupplyChainV1,
    durability_profile: DurabilityProfileV1,
    at_rest_profile_id: String,
    generations: CoordinatorGenerationsV1,
    counts: PreparationBackupCountsV1,
    recovery_snapshot: RecoverySnapshotSummaryV1,
    recovery_root_metadata_schema: String,
    provenance_attestation_schema: String,
    requires_detached_provenance_attestation: bool,
    required_restore_root_lifecycle_state: String,
    requires_paused_restore: bool,
    requires_boot_epoch_rotation: bool,
    requires_instance_epoch_rotation: bool,
    requires_fencing_epoch_rotation: bool,
    nonterminal_preparations_not_reactivatable: bool,
    may_omit_work_after_generation: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SqliteSupplyChainV1 {
    rusqlite_version: String,
    libsqlite3_sys_version: String,
    bundled_sqlite_version: String,
    bundled_sqlite_source_id: String,
    link_profile: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DurabilityProfileV1 {
    journal_mode: String,
    synchronous: String,
    wal_autocheckpoint_pages: u64,
    foreign_keys: bool,
    recursive_triggers: bool,
    trusted_schema: bool,
    cell_size_check: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CoordinatorGenerationsV1 {
    store: u64,
    operation: u64,
    budget: u64,
    event: u64,
    quarantine: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreparationBackupCountsV1 {
    budget_scopes: u64,
    operations: u64,
    operation_transitions: u64,
    held_reservations: u64,
    released_reservations: u64,
    pending_events: u64,
    delivered_events: u64,
    active_quarantines: u64,
    resolved_quarantines: u64,
    operation_retirement_pending: u64,
    orphan_retirement_pending: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecoverySnapshotSummaryV1 {
    schema: String,
    inventory_sha256: String,
    provider_set_count: u64,
    entry_count: u64,
    all_required_entries_verified: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryRootMetadataV1 {
    schema: String,
    root_identity_sha256: String,
    root_lifecycle_state: RecoveryRootLifecycleStateV1,
    state_generation: u64,
    at_rest_profile_id: String,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    restore_identity_sha256: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    provenance_attestation_sha256: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    source_inventory_sha256: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RecoveryRootLifecycleStateV1 {
    Active,
    RestorePending,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoverySnapshotManifestV1 {
    schema: String,
    provider_set_count: u64,
    entry_count: u64,
    provider_sets: Vec<RecoveryProviderSetV1>,
    complete_reference_set: bool,
    no_retirement_pending: bool,
    requires_paused_restore: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecoveryProviderSetV1 {
    provider_profile_id: String,
    provider_profile_version: u64,
    provider_id: String,
    provider_generation: u64,
    evidence_class: String,
    at_rest_profile_id: String,
    entry_count: u64,
    entries: Vec<RecoverySnapshotEntryV1>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecoverySnapshotEntryV1 {
    package_binding_sha256: String,
    manifest_sha256: String,
    material_sha256: String,
    material_length: u64,
    reserved_capacity: u64,
    custody: RecoveryCustodyV1,
    state: RecoverySnapshotStateV1,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    retirement_manifest_sha256: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum RecoveryCustodyV1 {
    OperationBound,
    QuarantinedOrphan,
    OrphanResolutionTombstone,
}

impl RecoveryCustodyV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OperationBound => "OPERATION_BOUND",
            Self::QuarantinedOrphan => "QUARANTINED_ORPHAN",
            Self::OrphanResolutionTombstone => "ORPHAN_RESOLUTION_TOMBSTONE",
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum RecoverySnapshotStateV1 {
    MaterialPresent,
    RetiredTombstone,
}

impl RecoverySnapshotStateV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MaterialPresent => "MATERIAL_PRESENT",
            Self::RetiredTombstone => "RETIRED_TOMBSTONE",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupProvenanceAttestationV1 {
    schema: String,
    protected: BackupProvenanceProtectedV1,
    signature_algorithm: String,
    signature_base64url: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupProvenanceProtectedV1 {
    schema: String,
    top_level_manifest_sha256: String,
    source_coordinator_root_identity_sha256: String,
    source_recovery_root_identity_sha256: String,
    source_instance_identity_sha256: String,
    coordinator_generations: CoordinatorGenerationsV1,
    recovery_inventory_sha256: String,
    recovery_provider_set_count: u64,
    recovery_entry_count: u64,
    recovery_provider_generations: Vec<RecoveryProviderGenerationV1>,
    at_rest_profile_id: String,
    attestation_profile_id: String,
    attestation_profile_version: u64,
    key_id: String,
    digest_algorithm: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RecoveryProviderGenerationV1 {
    provider_profile_id: String,
    provider_profile_version: u64,
    provider_id: String,
    provider_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CoordinatorGenerationsInputV1 {
    pub(crate) store: u64,
    pub(crate) operation: u64,
    pub(crate) budget: u64,
    pub(crate) event: u64,
    pub(crate) quarantine: u64,
}

pub(crate) struct PreparationBackupCountsInputV1 {
    pub(crate) budget_scopes: u64,
    pub(crate) operations: u64,
    pub(crate) operation_transitions: u64,
    pub(crate) held_reservations: u64,
    pub(crate) released_reservations: u64,
    pub(crate) pending_events: u64,
    pub(crate) delivered_events: u64,
    pub(crate) active_quarantines: u64,
    pub(crate) resolved_quarantines: u64,
}

pub(crate) struct PreparationBackupManifestInputV1 {
    pub(crate) source_coordinator_root_identity_sha256: Sha256Digest,
    pub(crate) source_recovery_root_identity_sha256: Sha256Digest,
    pub(crate) source_instance_identity_sha256: Sha256Digest,
    pub(crate) coordinator_schema_sha256: Sha256Digest,
    pub(crate) coordinator_database_sha256: Sha256Digest,
    pub(crate) at_rest_profile_id: Identifier,
    pub(crate) generations: CoordinatorGenerationsInputV1,
    pub(crate) counts: PreparationBackupCountsInputV1,
    pub(crate) recovery_inventory_sha256: Sha256Digest,
    pub(crate) recovery_provider_set_count: u64,
    pub(crate) recovery_entry_count: u64,
}

pub(crate) enum RecoveryRootMetadataInputV1 {
    Active {
        root_identity_sha256: Sha256Digest,
        at_rest_profile_id: Identifier,
    },
    RestorePending {
        root_identity_sha256: Sha256Digest,
        state_generation: u64,
        at_rest_profile_id: Identifier,
        restore_identity_sha256: Sha256Digest,
        provenance_attestation_sha256: Sha256Digest,
        source_inventory_sha256: Sha256Digest,
    },
}

pub(crate) struct RecoverySnapshotEntryInputV1 {
    pub(crate) manifest_sha256: Sha256Digest,
    pub(crate) material_sha256: Sha256Digest,
    pub(crate) material_length: u64,
    pub(crate) reserved_capacity: u64,
    pub(crate) custody: RecoveryCustodyV1,
    pub(crate) state: RecoverySnapshotStateV1,
    pub(crate) retirement_manifest_sha256: Option<Sha256Digest>,
}

pub(crate) struct RecoveryProviderSetInputV1 {
    pub(crate) provider_profile_id: Identifier,
    pub(crate) provider_profile_version: u16,
    pub(crate) provider_id: Identifier,
    pub(crate) provider_generation: u64,
    pub(crate) evidence_class: String,
    pub(crate) at_rest_profile_id: Identifier,
    pub(crate) entries: Vec<RecoverySnapshotEntryInputV1>,
}

pub(crate) struct RecoveryProviderGenerationInputV1 {
    pub(crate) provider_profile_id: Identifier,
    pub(crate) provider_profile_version: u16,
    pub(crate) provider_id: Identifier,
    pub(crate) provider_generation: u64,
}

pub(crate) struct BackupProvenanceProtectedInputV1 {
    pub(crate) top_level_manifest_sha256: Sha256Digest,
    pub(crate) source_coordinator_root_identity_sha256: Sha256Digest,
    pub(crate) source_recovery_root_identity_sha256: Sha256Digest,
    pub(crate) source_instance_identity_sha256: Sha256Digest,
    pub(crate) coordinator_generations: CoordinatorGenerationsInputV1,
    pub(crate) recovery_inventory_sha256: Sha256Digest,
    pub(crate) recovery_entry_count: u64,
    pub(crate) recovery_provider_generations: Vec<RecoveryProviderGenerationInputV1>,
    pub(crate) at_rest_profile_id: Identifier,
    pub(crate) attestation_profile_id: Identifier,
    pub(crate) attestation_profile_version: u16,
    pub(crate) key_id: Identifier,
}

macro_rules! redacted_input_debug {
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

redacted_input_debug!(
    PreparationBackupCountsInputV1,
    PreparationBackupManifestInputV1,
    RecoveryRootMetadataInputV1,
    RecoverySnapshotEntryInputV1,
    RecoveryProviderSetInputV1,
    RecoveryProviderGenerationInputV1,
    BackupProvenanceProtectedInputV1,
);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinnedEd25519KeyV1 {
    verifying_key: [u8; 32],
    pinned_sha256: [u8; 32],
}

impl PinnedEd25519KeyV1 {
    pub(crate) fn try_new(
        verifying_key: [u8; 32],
        pinned_sha256: [u8; 32],
    ) -> Result<Self, ManifestCodecErrorV1> {
        if <[u8; 32]>::from(Sha256::digest(verifying_key)) != pinned_sha256
            || VerifyingKey::from_bytes(&verifying_key).is_err()
        {
            return Err(ManifestCodecErrorV1::ProvenanceInvalid);
        }
        Ok(Self {
            verifying_key,
            pinned_sha256,
        })
    }
}

impl fmt::Debug for PinnedEd25519KeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedEd25519KeyV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvisionerTrustDecisionV1 {
    Trusted(PinnedEd25519KeyV1),
    Unknown,
    Revoked,
    Unavailable,
}

/// Read-only view of one provisioner trust generation.
pub(crate) trait ProvisionerTrustViewV1 {
    fn resolve_ed25519(
        &self,
        attestation_profile_id: &str,
        attestation_profile_version: u64,
        key_id: &str,
    ) -> ProvisionerTrustDecisionV1;
}

/// Linear custody of one provisioner trust generation.
///
/// Acquisition MUST atomically retain the generation exposed by
/// [`ProvisionerTrustViewV1`] and a serialization permit. Every revocation, key rotation,
/// profile update, or other trust-store mutation MUST wait until this value is dropped.
/// A periodically sampled recheck is not a conforming substitute: it leaves a TOCTOU
/// window between the sample and a destination mutation.
#[cfg_attr(test, allow(dead_code))]
pub(crate) trait ProvisionerTrustCustodyV1: ProvisionerTrustViewV1 + Send {}

#[cfg_attr(test, allow(dead_code))]
pub(crate) enum ProvisionerTrustCustodyOutcomeV1 {
    Acquired(Box<dyn ProvisionerTrustCustodyV1>),
    Revoked,
    Unavailable,
}

impl fmt::Debug for ProvisionerTrustCustodyOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquired(_) => "ProvisionerTrustCustodyOutcomeV1::Acquired(..)",
            Self::Revoked => "ProvisionerTrustCustodyOutcomeV1::Revoked",
            Self::Unavailable => "ProvisionerTrustCustodyOutcomeV1::Unavailable",
        })
    }
}

pub(crate) trait ProvisionerTrustResolverV1: Send + Sync {
    #[cfg_attr(test, allow(dead_code))]
    fn acquire_restore_trust_custody_v1(&self) -> ProvisionerTrustCustodyOutcomeV1;

    fn resolve_ed25519(
        &self,
        attestation_profile_id: &str,
        attestation_profile_version: u64,
        key_id: &str,
    ) -> ProvisionerTrustDecisionV1;
}

impl<T: ProvisionerTrustResolverV1 + ?Sized> ProvisionerTrustViewV1 for T {
    fn resolve_ed25519(
        &self,
        attestation_profile_id: &str,
        attestation_profile_version: u64,
        key_id: &str,
    ) -> ProvisionerTrustDecisionV1 {
        ProvisionerTrustResolverV1::resolve_ed25519(
            self,
            attestation_profile_id,
            attestation_profile_version,
            key_id,
        )
    }
}

/// Authenticated coordinator generation vector projected from one restore package.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedRestoreCoordinatorGenerationsV1 {
    store: u64,
    operation: u64,
    budget: u64,
    event: u64,
    quarantine: u64,
}

impl VerifiedRestoreCoordinatorGenerationsV1 {
    pub(crate) const fn store(self) -> u64 {
        self.store
    }

    pub(crate) const fn operation(self) -> u64 {
        self.operation
    }

    pub(crate) const fn budget(self) -> u64 {
        self.budget
    }

    pub(crate) const fn event(self) -> u64 {
        self.event
    }

    pub(crate) const fn quarantine(self) -> u64 {
        self.quarantine
    }
}

/// Authenticated, bounded coordinator counts projected from one restore package.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedRestoreCoordinatorCountsV1 {
    budget_scopes: u64,
    operations: u64,
    operation_transitions: u64,
    held_reservations: u64,
    released_reservations: u64,
    pending_events: u64,
    delivered_events: u64,
    active_quarantines: u64,
    resolved_quarantines: u64,
    operation_retirement_pending: u64,
    orphan_retirement_pending: u64,
}

impl VerifiedRestoreCoordinatorCountsV1 {
    pub(crate) const fn budget_scopes(self) -> u64 {
        self.budget_scopes
    }

    pub(crate) const fn operations(self) -> u64 {
        self.operations
    }

    pub(crate) const fn operation_transitions(self) -> u64 {
        self.operation_transitions
    }

    pub(crate) const fn held_reservations(self) -> u64 {
        self.held_reservations
    }

    pub(crate) const fn released_reservations(self) -> u64 {
        self.released_reservations
    }

    pub(crate) const fn pending_events(self) -> u64 {
        self.pending_events
    }

    pub(crate) const fn delivered_events(self) -> u64 {
        self.delivered_events
    }

    pub(crate) const fn active_quarantines(self) -> u64 {
        self.active_quarantines
    }

    pub(crate) const fn resolved_quarantines(self) -> u64 {
        self.resolved_quarantines
    }

    pub(crate) const fn operation_retirement_pending(self) -> u64 {
        self.operation_retirement_pending
    }

    pub(crate) const fn orphan_retirement_pending(self) -> u64 {
        self.orphan_retirement_pending
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestorePackageRootLifecycleV1 {
    Active,
    RestorePending,
}

/// Closed lifecycle requirements authenticated by the top-level manifest and inventory.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedRestoreLifecycleRequirementsV1 {
    source_root_lifecycle: RestorePackageRootLifecycleV1,
    required_restore_root_lifecycle: RestorePackageRootLifecycleV1,
    requires_paused_restore: bool,
    requires_boot_epoch_rotation: bool,
    requires_instance_epoch_rotation: bool,
    requires_fencing_epoch_rotation: bool,
    nonterminal_preparations_not_reactivatable: bool,
    may_omit_work_after_generation: bool,
    complete_reference_set: bool,
    no_retirement_pending: bool,
    all_required_entries_verified: bool,
}

impl VerifiedRestoreLifecycleRequirementsV1 {
    pub(crate) const fn source_root_lifecycle(self) -> RestorePackageRootLifecycleV1 {
        self.source_root_lifecycle
    }

    pub(crate) const fn required_restore_root_lifecycle(self) -> RestorePackageRootLifecycleV1 {
        self.required_restore_root_lifecycle
    }

    pub(crate) const fn requires_paused_restore(self) -> bool {
        self.requires_paused_restore
    }

    pub(crate) const fn requires_boot_epoch_rotation(self) -> bool {
        self.requires_boot_epoch_rotation
    }

    pub(crate) const fn requires_instance_epoch_rotation(self) -> bool {
        self.requires_instance_epoch_rotation
    }

    pub(crate) const fn requires_fencing_epoch_rotation(self) -> bool {
        self.requires_fencing_epoch_rotation
    }

    pub(crate) const fn nonterminal_preparations_not_reactivatable(self) -> bool {
        self.nonterminal_preparations_not_reactivatable
    }

    pub(crate) const fn may_omit_work_after_generation(self) -> bool {
        self.may_omit_work_after_generation
    }

    pub(crate) const fn complete_reference_set(self) -> bool {
        self.complete_reference_set
    }

    pub(crate) const fn no_retirement_pending(self) -> bool {
        self.no_retirement_pending
    }

    pub(crate) const fn all_required_entries_verified(self) -> bool {
        self.all_required_entries_verified
    }
}

/// One canonical recovery-package entry after closed-manifest and provenance verification.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedRestoreProviderEntryV1 {
    package_binding_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    material_sha256: Sha256Digest,
    material_length: u64,
    reserved_capacity: u64,
    custody: RecoveryCustodyV1,
    state: RecoverySnapshotStateV1,
    retirement_manifest_sha256: Option<Sha256Digest>,
}

impl VerifiedRestoreProviderEntryV1 {
    pub(crate) const fn package_binding_sha256(&self) -> Sha256Digest {
        self.package_binding_sha256
    }

    pub(crate) const fn manifest_sha256(&self) -> Sha256Digest {
        self.manifest_sha256
    }

    pub(crate) const fn material_sha256(&self) -> Sha256Digest {
        self.material_sha256
    }

    pub(crate) const fn material_length(&self) -> u64 {
        self.material_length
    }

    pub(crate) const fn reserved_capacity(&self) -> u64 {
        self.reserved_capacity
    }

    pub(crate) const fn custody(&self) -> RecoveryCustodyV1 {
        self.custody
    }

    pub(crate) const fn state(&self) -> RecoverySnapshotStateV1 {
        self.state
    }

    pub(crate) const fn retirement_manifest_sha256(&self) -> Option<Sha256Digest> {
        self.retirement_manifest_sha256
    }
}

/// One canonical provider-generation set after closed-manifest and provenance verification.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedRestoreProviderSetV1 {
    provider_profile_id: Identifier,
    provider_profile_version: u64,
    provider_id: Identifier,
    provider_generation: u64,
    evidence_class: Identifier,
    at_rest_profile_id: Identifier,
    entry_count: u64,
    entries: Vec<VerifiedRestoreProviderEntryV1>,
}

impl VerifiedRestoreProviderSetV1 {
    pub(crate) const fn provider_profile_id(&self) -> &Identifier {
        &self.provider_profile_id
    }

    pub(crate) const fn provider_profile_version(&self) -> u64 {
        self.provider_profile_version
    }

    pub(crate) const fn provider_id(&self) -> &Identifier {
        &self.provider_id
    }

    pub(crate) const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub(crate) const fn evidence_class(&self) -> &Identifier {
        &self.evidence_class
    }

    pub(crate) const fn at_rest_profile_id(&self) -> &Identifier {
        &self.at_rest_profile_id
    }

    pub(crate) fn entries(&self) -> &[VerifiedRestoreProviderEntryV1] {
        &self.entries
    }

    pub(crate) const fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// Non-wire proof that all three restore-package manifests were canonical, mutually
/// consistent and signed by the currently pinned, non-revoked provisioner key.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedRestorePackageBindingsV1 {
    attestation_sha256: Sha256Digest,
    top_level_manifest_sha256: Sha256Digest,
    inventory_sha256: Sha256Digest,
    source_coordinator_root_identity_sha256: Sha256Digest,
    source_recovery_root_identity_sha256: Sha256Digest,
    source_instance_identity_sha256: Sha256Digest,
    coordinator_schema_sha256: Sha256Digest,
    coordinator_database_sha256: Sha256Digest,
    at_rest_profile_id: Identifier,
    attestation_profile_id: Identifier,
    attestation_profile_version: u64,
    key_id: Identifier,
    generations: VerifiedRestoreCoordinatorGenerationsV1,
    counts: VerifiedRestoreCoordinatorCountsV1,
    lifecycle: VerifiedRestoreLifecycleRequirementsV1,
    provider_set_count: u64,
    entry_count: u64,
    provider_sets: Vec<VerifiedRestoreProviderSetV1>,
}

impl VerifiedRestorePackageBindingsV1 {
    pub(crate) const fn attestation_sha256(&self) -> Sha256Digest {
        self.attestation_sha256
    }

    pub(crate) const fn top_level_manifest_sha256(&self) -> Sha256Digest {
        self.top_level_manifest_sha256
    }

    pub(crate) const fn inventory_sha256(&self) -> Sha256Digest {
        self.inventory_sha256
    }

    pub(crate) const fn source_coordinator_root_identity_sha256(&self) -> Sha256Digest {
        self.source_coordinator_root_identity_sha256
    }

    pub(crate) const fn source_recovery_root_identity_sha256(&self) -> Sha256Digest {
        self.source_recovery_root_identity_sha256
    }

    pub(crate) const fn source_instance_identity_sha256(&self) -> Sha256Digest {
        self.source_instance_identity_sha256
    }

    pub(crate) const fn coordinator_schema_sha256(&self) -> Sha256Digest {
        self.coordinator_schema_sha256
    }

    pub(crate) const fn coordinator_database_sha256(&self) -> Sha256Digest {
        self.coordinator_database_sha256
    }

    pub(crate) const fn at_rest_profile_id(&self) -> &Identifier {
        &self.at_rest_profile_id
    }

    pub(crate) const fn attestation_profile_id(&self) -> &Identifier {
        &self.attestation_profile_id
    }

    pub(crate) const fn attestation_profile_version(&self) -> u64 {
        self.attestation_profile_version
    }

    pub(crate) const fn key_id(&self) -> &Identifier {
        &self.key_id
    }

    pub(crate) const fn generations(&self) -> VerifiedRestoreCoordinatorGenerationsV1 {
        self.generations
    }

    pub(crate) const fn counts(&self) -> VerifiedRestoreCoordinatorCountsV1 {
        self.counts
    }

    pub(crate) const fn lifecycle(&self) -> VerifiedRestoreLifecycleRequirementsV1 {
        self.lifecycle
    }

    pub(crate) const fn provider_set_count(&self) -> u64 {
        self.provider_set_count
    }

    pub(crate) const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub(crate) fn provider_sets(&self) -> &[VerifiedRestoreProviderSetV1] {
        &self.provider_sets
    }
}

/// Typed proof obtained only from exact canonical `RESTORE_PENDING` recovery metadata.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedRecoveryRootPendingBindingsV1 {
    metadata_sha256: Sha256Digest,
    root_identity_sha256: Sha256Digest,
    state_generation: u64,
    at_rest_profile_id: Identifier,
    restore_identity_sha256: Sha256Digest,
    provenance_attestation_sha256: Sha256Digest,
    source_inventory_sha256: Sha256Digest,
}

impl VerifiedRecoveryRootPendingBindingsV1 {
    pub(crate) const fn metadata_sha256(&self) -> Sha256Digest {
        self.metadata_sha256
    }

    pub(crate) const fn root_identity_sha256(&self) -> Sha256Digest {
        self.root_identity_sha256
    }

    pub(crate) const fn state_generation(&self) -> u64 {
        self.state_generation
    }

    pub(crate) const fn at_rest_profile_id(&self) -> &Identifier {
        &self.at_rest_profile_id
    }

    pub(crate) const fn restore_identity_sha256(&self) -> Sha256Digest {
        self.restore_identity_sha256
    }

    pub(crate) const fn provenance_attestation_sha256(&self) -> Sha256Digest {
        self.provenance_attestation_sha256
    }

    pub(crate) const fn source_inventory_sha256(&self) -> Sha256Digest {
        self.source_inventory_sha256
    }
}

redacted_input_debug!(
    VerifiedRestoreCoordinatorGenerationsV1,
    VerifiedRestoreCoordinatorCountsV1,
    VerifiedRestoreLifecycleRequirementsV1,
    VerifiedRestoreProviderEntryV1,
    VerifiedRestoreProviderSetV1,
    VerifiedRestorePackageBindingsV1,
    VerifiedRecoveryRootPendingBindingsV1,
);

impl fmt::Debug for RestorePackageRootLifecycleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RestorePackageRootLifecycleV1(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingRetirementEvidenceV1 {
    coordinator_operation_pending: u64,
    coordinator_orphan_pending: u64,
    provider_operation_pending: u64,
    provider_orphan_pending: u64,
}

impl PendingRetirementEvidenceV1 {
    pub(crate) fn try_new(
        coordinator_operation_pending: u64,
        coordinator_orphan_pending: u64,
        provider_operation_pending: u64,
        provider_orphan_pending: u64,
    ) -> Result<Self, ManifestCodecErrorV1> {
        if [
            coordinator_operation_pending,
            coordinator_orphan_pending,
            provider_operation_pending,
            provider_orphan_pending,
        ]
        .iter()
        .any(|value| *value > MAX_SAFE_U64)
        {
            return Err(ManifestCodecErrorV1::JsonContractInvalid);
        }
        Ok(Self {
            coordinator_operation_pending,
            coordinator_orphan_pending,
            provider_operation_pending,
            provider_orphan_pending,
        })
    }

    const fn all_zero(self) -> bool {
        self.coordinator_operation_pending == 0
            && self.coordinator_orphan_pending == 0
            && self.provider_operation_pending == 0
            && self.provider_orphan_pending == 0
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
    PreparationBackupManifestV1,
    RecoveryRootMetadataV1,
    RecoverySnapshotManifestV1,
    BackupProvenanceAttestationV1,
);

pub(crate) fn embedded_preparation_backup_manifest_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(PREPARATION_BACKUP_MANIFEST_V1_JSON_SCHEMA.as_bytes()).into()
}

pub(crate) fn embedded_backup_provenance_attestation_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(BACKUP_PROVENANCE_ATTESTATION_V1_JSON_SCHEMA.as_bytes()).into()
}

pub(crate) fn embedded_recovery_root_metadata_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(RECOVERY_ROOT_METADATA_V1_JSON_SCHEMA.as_bytes()).into()
}

pub(crate) fn embedded_recovery_snapshot_manifest_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(RECOVERY_SNAPSHOT_MANIFEST_V1_JSON_SCHEMA.as_bytes()).into()
}

pub(crate) fn decode_preparation_backup_manifest_v1(
    bytes: &[u8],
) -> Result<DecodedCanonicalJsonV1<PreparationBackupManifestV1>, ManifestCodecErrorV1> {
    decode_canonical_json_v1(bytes)
}

pub(crate) fn decode_backup_provenance_attestation_v1(
    bytes: &[u8],
) -> Result<DecodedCanonicalJsonV1<BackupProvenanceAttestationV1>, ManifestCodecErrorV1> {
    decode_canonical_json_v1(bytes)
}

pub(crate) fn decode_recovery_root_metadata_v1(
    bytes: &[u8],
) -> Result<DecodedCanonicalJsonV1<RecoveryRootMetadataV1>, ManifestCodecErrorV1> {
    decode_canonical_json_v1(bytes)
}

pub(crate) fn decode_recovery_snapshot_manifest_v1(
    bytes: &[u8],
) -> Result<DecodedCanonicalJsonV1<RecoverySnapshotManifestV1>, ManifestCodecErrorV1> {
    decode_canonical_json_v1(bytes)
}

/// Finalizes the closed top-level backup object. Both authoritative retirement
/// domains are accepted only as observed zero and are encoded as literal zero.
pub(crate) fn finalize_preparation_backup_manifest_v1(
    input: PreparationBackupManifestInputV1,
    pending: PendingRetirementEvidenceV1,
) -> Result<FinalizedCanonicalJsonV1<PreparationBackupManifestV1>, ManifestCodecErrorV1> {
    if !pending.all_zero() {
        return json_invalid();
    }
    let counts = PreparationBackupCountsV1 {
        budget_scopes: input.counts.budget_scopes,
        operations: input.counts.operations,
        operation_transitions: input.counts.operation_transitions,
        held_reservations: input.counts.held_reservations,
        released_reservations: input.counts.released_reservations,
        pending_events: input.counts.pending_events,
        delivered_events: input.counts.delivered_events,
        active_quarantines: input.counts.active_quarantines,
        resolved_quarantines: input.counts.resolved_quarantines,
        operation_retirement_pending: 0,
        orphan_retirement_pending: 0,
    };
    let value = PreparationBackupManifestV1 {
        schema: PREPARATION_BACKUP_SCHEMA_V1.to_owned(),
        application_id: APPLICATION_ID_V1,
        store_schema_version: STORE_SCHEMA_VERSION_V1,
        source_coordinator_root_identity_sha256: input
            .source_coordinator_root_identity_sha256
            .to_hex(),
        source_recovery_root_identity_sha256: input
            .source_recovery_root_identity_sha256
            .to_hex(),
        source_instance_identity_sha256: input.source_instance_identity_sha256.to_hex(),
        source_root_lifecycle_state: "ACTIVE".to_owned(),
        coordinator_schema_sha256: input.coordinator_schema_sha256.to_hex(),
        coordinator_database_sha256: input.coordinator_database_sha256.to_hex(),
        sqlite: SqliteSupplyChainV1 {
            rusqlite_version: "0.40.1".to_owned(),
            libsqlite3_sys_version: "0.38.1".to_owned(),
            bundled_sqlite_version: "3.53.2".to_owned(),
            bundled_sqlite_source_id:
                "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24"
                    .to_owned(),
            link_profile: "rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static".to_owned(),
        },
        durability_profile: DurabilityProfileV1 {
            journal_mode: "WAL".to_owned(),
            synchronous: "FULL".to_owned(),
            wal_autocheckpoint_pages: 0,
            foreign_keys: true,
            recursive_triggers: true,
            trusted_schema: false,
            cell_size_check: true,
        },
        at_rest_profile_id: input.at_rest_profile_id.as_str().to_owned(),
        generations: coordinator_generations(input.generations),
        counts,
        recovery_snapshot: RecoverySnapshotSummaryV1 {
            schema: RECOVERY_SNAPSHOT_SUMMARY_SCHEMA_V1.to_owned(),
            inventory_sha256: input.recovery_inventory_sha256.to_hex(),
            provider_set_count: input.recovery_provider_set_count,
            entry_count: input.recovery_entry_count,
            all_required_entries_verified: true,
        },
        recovery_root_metadata_schema: RECOVERY_ROOT_METADATA_SCHEMA_V1.to_owned(),
        provenance_attestation_schema: PROVENANCE_ATTESTATION_SCHEMA_V1.to_owned(),
        requires_detached_provenance_attestation: true,
        required_restore_root_lifecycle_state: "RESTORE_PENDING".to_owned(),
        requires_paused_restore: true,
        requires_boot_epoch_rotation: true,
        requires_instance_epoch_rotation: true,
        requires_fencing_epoch_rotation: true,
        nonterminal_preparations_not_reactivatable: true,
        may_omit_work_after_generation: true,
    };
    finalize_canonical_json_v1(value)
}

pub(crate) fn finalize_recovery_root_metadata_v1(
    input: RecoveryRootMetadataInputV1,
) -> Result<FinalizedCanonicalJsonV1<RecoveryRootMetadataV1>, ManifestCodecErrorV1> {
    let value = match input {
        RecoveryRootMetadataInputV1::Active {
            root_identity_sha256,
            at_rest_profile_id,
        } => RecoveryRootMetadataV1 {
            schema: RECOVERY_ROOT_METADATA_SCHEMA_V1.to_owned(),
            root_identity_sha256: root_identity_sha256.to_hex(),
            root_lifecycle_state: RecoveryRootLifecycleStateV1::Active,
            state_generation: 0,
            at_rest_profile_id: at_rest_profile_id.as_str().to_owned(),
            restore_identity_sha256: None,
            provenance_attestation_sha256: None,
            source_inventory_sha256: None,
        },
        RecoveryRootMetadataInputV1::RestorePending {
            root_identity_sha256,
            state_generation,
            at_rest_profile_id,
            restore_identity_sha256,
            provenance_attestation_sha256,
            source_inventory_sha256,
        } => RecoveryRootMetadataV1 {
            schema: RECOVERY_ROOT_METADATA_SCHEMA_V1.to_owned(),
            root_identity_sha256: root_identity_sha256.to_hex(),
            root_lifecycle_state: RecoveryRootLifecycleStateV1::RestorePending,
            state_generation,
            at_rest_profile_id: at_rest_profile_id.as_str().to_owned(),
            restore_identity_sha256: Some(restore_identity_sha256.to_hex()),
            provenance_attestation_sha256: Some(provenance_attestation_sha256.to_hex()),
            source_inventory_sha256: Some(source_inventory_sha256.to_hex()),
        },
    };
    finalize_canonical_json_v1(value)
}

/// Calculates package bindings, sorts both inventory levels, rejects duplicate
/// provider generations/bindings, and emits the one standalone canonical inventory.
pub(crate) fn finalize_recovery_snapshot_manifest_v1(
    provider_inputs: Vec<RecoveryProviderSetInputV1>,
    pending: PendingRetirementEvidenceV1,
) -> Result<FinalizedCanonicalJsonV1<RecoverySnapshotManifestV1>, ManifestCodecErrorV1> {
    if !pending.all_zero() || provider_inputs.len() > MAX_INVENTORY_ITEMS_V1 {
        return json_invalid();
    }
    let mut provider_sets = Vec::with_capacity(provider_inputs.len());
    let mut total_entry_count = 0_u64;
    for provider_input in provider_inputs {
        if provider_input.entries.len() > MAX_INVENTORY_ITEMS_V1 {
            return json_invalid();
        }
        let entry_count = usize_to_safe_u64(provider_input.entries.len())?;
        total_entry_count = total_entry_count
            .checked_add(entry_count)
            .filter(|count| *count <= MAX_SAFE_U64)
            .ok_or(ManifestCodecErrorV1::JsonContractInvalid)?;
        let mut provider = RecoveryProviderSetV1 {
            provider_profile_id: provider_input.provider_profile_id.as_str().to_owned(),
            provider_profile_version: u64::from(provider_input.provider_profile_version),
            provider_id: provider_input.provider_id.as_str().to_owned(),
            provider_generation: provider_input.provider_generation,
            evidence_class: provider_input.evidence_class,
            at_rest_profile_id: provider_input.at_rest_profile_id.as_str().to_owned(),
            entry_count,
            entries: provider_input
                .entries
                .into_iter()
                .map(|entry| RecoverySnapshotEntryV1 {
                    package_binding_sha256: String::new(),
                    manifest_sha256: entry.manifest_sha256.to_hex(),
                    material_sha256: entry.material_sha256.to_hex(),
                    material_length: entry.material_length,
                    reserved_capacity: entry.reserved_capacity,
                    custody: entry.custody,
                    state: entry.state,
                    retirement_manifest_sha256: entry
                        .retirement_manifest_sha256
                        .map(Sha256Digest::to_hex),
                })
                .collect(),
        };
        for index in 0..provider.entries.len() {
            provider.entries[index].package_binding_sha256 =
                compute_package_binding_sha256(&provider, &provider.entries[index])?;
        }
        provider.entries.sort_by(|left, right| {
            left.package_binding_sha256
                .cmp(&right.package_binding_sha256)
        });
        if provider
            .entries
            .windows(2)
            .any(|pair| pair[0].package_binding_sha256 == pair[1].package_binding_sha256)
        {
            return json_invalid();
        }
        provider_sets.push(provider);
    }
    provider_sets.sort_by(|left, right| provider_set_key(left).cmp(&provider_set_key(right)));
    if provider_sets
        .windows(2)
        .any(|pair| provider_set_key(&pair[0]) == provider_set_key(&pair[1]))
    {
        return json_invalid();
    }
    let value = RecoverySnapshotManifestV1 {
        schema: RECOVERY_SNAPSHOT_SCHEMA_V1.to_owned(),
        provider_set_count: usize_to_safe_u64(provider_sets.len())?,
        entry_count: total_entry_count,
        provider_sets,
        complete_reference_set: true,
        no_retirement_pending: true,
        requires_paused_restore: true,
    };
    finalize_canonical_json_v1(value)
}

pub(crate) fn finalize_backup_provenance_protected_v1(
    input: BackupProvenanceProtectedInputV1,
) -> Result<FinalizedCanonicalJsonV1<BackupProvenanceProtectedV1>, ManifestCodecErrorV1> {
    if input.recovery_provider_generations.len() > MAX_INVENTORY_ITEMS_V1 {
        return json_invalid();
    }
    let mut recovery_provider_generations = input
        .recovery_provider_generations
        .into_iter()
        .map(|provider| RecoveryProviderGenerationV1 {
            provider_profile_id: provider.provider_profile_id.as_str().to_owned(),
            provider_profile_version: u64::from(provider.provider_profile_version),
            provider_id: provider.provider_id.as_str().to_owned(),
            provider_generation: provider.provider_generation,
        })
        .collect::<Vec<_>>();
    recovery_provider_generations
        .sort_by(|left, right| provider_generation_key(left).cmp(&provider_generation_key(right)));
    if recovery_provider_generations
        .windows(2)
        .any(|pair| provider_generation_key(&pair[0]) == provider_generation_key(&pair[1]))
    {
        return json_invalid();
    }
    let value = BackupProvenanceProtectedV1 {
        schema: PROVENANCE_PROTECTED_SCHEMA_V1.to_owned(),
        top_level_manifest_sha256: input.top_level_manifest_sha256.to_hex(),
        source_coordinator_root_identity_sha256: input
            .source_coordinator_root_identity_sha256
            .to_hex(),
        source_recovery_root_identity_sha256: input.source_recovery_root_identity_sha256.to_hex(),
        source_instance_identity_sha256: input.source_instance_identity_sha256.to_hex(),
        coordinator_generations: coordinator_generations(input.coordinator_generations),
        recovery_inventory_sha256: input.recovery_inventory_sha256.to_hex(),
        recovery_provider_set_count: usize_to_safe_u64(recovery_provider_generations.len())?,
        recovery_entry_count: input.recovery_entry_count,
        recovery_provider_generations,
        at_rest_profile_id: input.at_rest_profile_id.as_str().to_owned(),
        attestation_profile_id: input.attestation_profile_id.as_str().to_owned(),
        attestation_profile_version: u64::from(input.attestation_profile_version),
        key_id: input.key_id.as_str().to_owned(),
        digest_algorithm: "sha-256".to_owned(),
    };
    finalize_canonical_json_v1(value)
}

pub(crate) fn finalize_backup_provenance_attestation_v1(
    protected: BackupProvenanceProtectedV1,
    signature: [u8; 64],
) -> Result<FinalizedCanonicalJsonV1<BackupProvenanceAttestationV1>, ManifestCodecErrorV1> {
    finalize_canonical_json_v1(BackupProvenanceAttestationV1 {
        schema: PROVENANCE_ATTESTATION_SCHEMA_V1.to_owned(),
        protected,
        signature_algorithm: "ed25519".to_owned(),
        signature_base64url: URL_SAFE_NO_PAD.encode(signature),
    })
}

const fn coordinator_generations(input: CoordinatorGenerationsInputV1) -> CoordinatorGenerationsV1 {
    CoordinatorGenerationsV1 {
        store: input.store,
        operation: input.operation,
        budget: input.budget,
        event: input.event,
        quarantine: input.quarantine,
    }
}

impl ValidateManifestV1 for PreparationBackupManifestV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.schema != PREPARATION_BACKUP_SCHEMA_V1
            || self.application_id != APPLICATION_ID_V1
            || self.store_schema_version != STORE_SCHEMA_VERSION_V1
            || !is_lower_sha256(&self.source_coordinator_root_identity_sha256)
            || !is_lower_sha256(&self.source_recovery_root_identity_sha256)
            || !is_lower_sha256(&self.source_instance_identity_sha256)
            || self.source_root_lifecycle_state != "ACTIVE"
            || !is_lower_sha256(&self.coordinator_schema_sha256)
            || !is_lower_sha256(&self.coordinator_database_sha256)
            || !is_identifier(&self.at_rest_profile_id)
            || self.recovery_root_metadata_schema != RECOVERY_ROOT_METADATA_SCHEMA_V1
            || self.provenance_attestation_schema != PROVENANCE_ATTESTATION_SCHEMA_V1
            || !self.requires_detached_provenance_attestation
            || self.required_restore_root_lifecycle_state != "RESTORE_PENDING"
            || !self.requires_paused_restore
            || !self.requires_boot_epoch_rotation
            || !self.requires_instance_epoch_rotation
            || !self.requires_fencing_epoch_rotation
            || !self.nonterminal_preparations_not_reactivatable
            || !self.may_omit_work_after_generation
        {
            return json_invalid();
        }
        self.sqlite.validate()?;
        self.durability_profile.validate()?;
        self.generations.validate()?;
        self.counts.validate()?;
        self.recovery_snapshot.validate()
    }
}

impl SqliteSupplyChainV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.rusqlite_version != "0.40.1"
            || self.libsqlite3_sys_version != "0.38.1"
            || self.bundled_sqlite_version != "3.53.2"
            || self.bundled_sqlite_source_id
                != "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24"
            || self.link_profile != "rusqlite-0.40.1/libsqlite3-sys-0.38.1/bundled-static"
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl DurabilityProfileV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.journal_mode != "WAL"
            || self.synchronous != "FULL"
            || self.wal_autocheckpoint_pages != 0
            || !self.foreign_keys
            || !self.recursive_triggers
            || self.trusted_schema
            || !self.cell_size_check
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl CoordinatorGenerationsV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if [
            self.store,
            self.operation,
            self.budget,
            self.event,
            self.quarantine,
        ]
        .iter()
        .any(|value| *value > MAX_SAFE_U64)
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl PreparationBackupCountsV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if [
            self.budget_scopes,
            self.operations,
            self.operation_transitions,
            self.held_reservations,
            self.released_reservations,
            self.pending_events,
            self.delivered_events,
            self.active_quarantines,
            self.resolved_quarantines,
            self.operation_retirement_pending,
            self.orphan_retirement_pending,
        ]
        .iter()
        .any(|value| *value > MAX_SAFE_U64)
            || self.operation_retirement_pending != 0
            || self.orphan_retirement_pending != 0
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl RecoverySnapshotSummaryV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.schema != RECOVERY_SNAPSHOT_SUMMARY_SCHEMA_V1
            || !is_lower_sha256(&self.inventory_sha256)
            || self.provider_set_count > MAX_SAFE_U64
            || self.entry_count > MAX_SAFE_U64
            || !self.all_required_entries_verified
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateManifestV1 for RecoveryRootMetadataV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.schema != RECOVERY_ROOT_METADATA_SCHEMA_V1
            || !is_lower_sha256(&self.root_identity_sha256)
            || self.state_generation > MAX_SAFE_U64
            || !is_identifier(&self.at_rest_profile_id)
        {
            return json_invalid();
        }
        match self.root_lifecycle_state {
            RecoveryRootLifecycleStateV1::Active
                if self.state_generation == 0
                    && self.restore_identity_sha256.is_none()
                    && self.provenance_attestation_sha256.is_none()
                    && self.source_inventory_sha256.is_none() =>
            {
                Ok(())
            }
            RecoveryRootLifecycleStateV1::RestorePending
                if self.state_generation > 0
                    && self
                        .restore_identity_sha256
                        .as_deref()
                        .is_some_and(is_lower_sha256)
                    && self
                        .provenance_attestation_sha256
                        .as_deref()
                        .is_some_and(is_lower_sha256)
                    && self
                        .source_inventory_sha256
                        .as_deref()
                        .is_some_and(is_lower_sha256) =>
            {
                Ok(())
            }
            _ => json_invalid(),
        }
    }
}

impl ValidateManifestV1 for RecoverySnapshotManifestV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.schema != RECOVERY_SNAPSHOT_SCHEMA_V1
            || self.provider_set_count > MAX_SAFE_U64
            || self.entry_count > MAX_SAFE_U64
            || self.provider_sets.len() > MAX_INVENTORY_ITEMS_V1
            || self.provider_set_count != usize_to_safe_u64(self.provider_sets.len())?
            || !self.complete_reference_set
            || !self.no_retirement_pending
            || !self.requires_paused_restore
        {
            return json_invalid();
        }
        for pair in self.provider_sets.windows(2) {
            if provider_set_key(&pair[0]) >= provider_set_key(&pair[1]) {
                return json_invalid();
            }
        }
        let mut total = 0_u64;
        let mut manifest_digests = BTreeSet::new();
        for provider_set in &self.provider_sets {
            provider_set.validate()?;
            for entry in &provider_set.entries {
                if !manifest_digests.insert(entry.manifest_sha256.as_str()) {
                    return json_invalid();
                }
            }
            total = total
                .checked_add(provider_set.entry_count)
                .filter(|value| *value <= MAX_SAFE_U64)
                .ok_or(ManifestCodecErrorV1::JsonContractInvalid)?;
        }
        if total != self.entry_count {
            return json_invalid();
        }
        Ok(())
    }
}

impl RecoveryProviderSetV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if !is_identifier(&self.provider_profile_id)
            || self.provider_profile_version != 1
            || !is_identifier(&self.provider_id)
            || !(1..=MAX_SAFE_U64).contains(&self.provider_generation)
            || !is_evidence_class(&self.evidence_class)
            || !is_identifier(&self.at_rest_profile_id)
            || self.entry_count > MAX_SAFE_U64
            || self.entries.len() > MAX_INVENTORY_ITEMS_V1
            || self.entry_count != usize_to_safe_u64(self.entries.len())?
        {
            return json_invalid();
        }
        for pair in self.entries.windows(2) {
            if pair[0].package_binding_sha256 >= pair[1].package_binding_sha256 {
                return json_invalid();
            }
        }
        for entry in &self.entries {
            entry.validate(self)?;
        }
        Ok(())
    }
}

impl RecoverySnapshotEntryV1 {
    fn validate(&self, provider: &RecoveryProviderSetV1) -> Result<(), ManifestCodecErrorV1> {
        if !is_lower_sha256(&self.package_binding_sha256)
            || !is_lower_sha256(&self.manifest_sha256)
            || !is_lower_sha256(&self.material_sha256)
            || self.material_length > MAX_SAFE_U64
            || self.reserved_capacity > MAX_SAFE_U64
            || self.reserved_capacity < self.material_length
        {
            return json_invalid();
        }
        match (self.state, self.custody, &self.retirement_manifest_sha256) {
            (
                RecoverySnapshotStateV1::MaterialPresent,
                RecoveryCustodyV1::OperationBound | RecoveryCustodyV1::QuarantinedOrphan,
                None,
            ) => {}
            (
                RecoverySnapshotStateV1::RetiredTombstone,
                RecoveryCustodyV1::OperationBound | RecoveryCustodyV1::OrphanResolutionTombstone,
                Some(retirement),
            ) if is_lower_sha256(retirement) => {}
            _ => return json_invalid(),
        }
        if compute_package_binding_sha256(provider, self)? != self.package_binding_sha256 {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateManifestV1 for BackupProvenanceAttestationV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.schema != PROVENANCE_ATTESTATION_SCHEMA_V1
            || self.signature_algorithm != "ed25519"
            || decode_signature(&self.signature_base64url).is_err()
        {
            return json_invalid();
        }
        self.protected.validate()
    }
}

impl ValidateManifestV1 for BackupProvenanceProtectedV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if self.schema != PROVENANCE_PROTECTED_SCHEMA_V1
            || !is_lower_sha256(&self.top_level_manifest_sha256)
            || !is_lower_sha256(&self.source_coordinator_root_identity_sha256)
            || !is_lower_sha256(&self.source_recovery_root_identity_sha256)
            || !is_lower_sha256(&self.source_instance_identity_sha256)
            || !is_lower_sha256(&self.recovery_inventory_sha256)
            || self.recovery_provider_set_count > MAX_SAFE_U64
            || self.recovery_entry_count > MAX_SAFE_U64
            || self.recovery_provider_generations.len() > MAX_INVENTORY_ITEMS_V1
            || self.recovery_provider_set_count
                != usize_to_safe_u64(self.recovery_provider_generations.len())?
            || !is_identifier(&self.at_rest_profile_id)
            || !is_identifier(&self.attestation_profile_id)
            || self.attestation_profile_version != 1
            || !is_identifier(&self.key_id)
            || self.digest_algorithm != "sha-256"
        {
            return json_invalid();
        }
        self.coordinator_generations.validate()?;
        for generation in &self.recovery_provider_generations {
            generation.validate()?;
        }
        for pair in self.recovery_provider_generations.windows(2) {
            if provider_generation_key(&pair[0]) >= provider_generation_key(&pair[1]) {
                return json_invalid();
            }
        }
        Ok(())
    }
}

impl RecoveryProviderGenerationV1 {
    fn validate(&self) -> Result<(), ManifestCodecErrorV1> {
        if !is_identifier(&self.provider_profile_id)
            || self.provider_profile_version != 1
            || !is_identifier(&self.provider_id)
            || !(1..=MAX_SAFE_U64).contains(&self.provider_generation)
        {
            return json_invalid();
        }
        Ok(())
    }
}

pub(crate) fn cross_validate_backup_retirement_v1(
    backup: &DecodedCanonicalJsonV1<PreparationBackupManifestV1>,
    inventory: &DecodedCanonicalJsonV1<RecoverySnapshotManifestV1>,
    pending: PendingRetirementEvidenceV1,
) -> Result<(), ManifestCodecErrorV1> {
    let backup = backup.value();
    let inventory_value = inventory.value();
    if !pending.all_zero()
        || backup.counts.operation_retirement_pending != 0
        || backup.counts.orphan_retirement_pending != 0
        || !inventory_value.no_retirement_pending
        || backup.recovery_snapshot.inventory_sha256 != inventory.sha256_hex()
        || backup.recovery_snapshot.provider_set_count != inventory_value.provider_set_count
        || backup.recovery_snapshot.entry_count != inventory_value.entry_count
    {
        return json_invalid();
    }
    Ok(())
}

pub(crate) fn verify_backup_provenance_v1<R: ProvisionerTrustViewV1 + ?Sized>(
    attestation: &DecodedCanonicalJsonV1<BackupProvenanceAttestationV1>,
    backup: &DecodedCanonicalJsonV1<PreparationBackupManifestV1>,
    inventory: &DecodedCanonicalJsonV1<RecoverySnapshotManifestV1>,
    trust: &R,
) -> Result<(), ManifestCodecErrorV1> {
    let attestation = attestation.value();
    let protected = &attestation.protected;
    let backup_value = backup.value();
    let inventory_value = inventory.value();
    let expected_provider_generations = inventory_value
        .provider_sets
        .iter()
        .map(|provider| RecoveryProviderGenerationV1 {
            provider_profile_id: provider.provider_profile_id.clone(),
            provider_profile_version: provider.provider_profile_version,
            provider_id: provider.provider_id.clone(),
            provider_generation: provider.provider_generation,
        })
        .collect::<Vec<_>>();

    if protected.top_level_manifest_sha256 != backup.sha256_hex()
        || protected.source_coordinator_root_identity_sha256
            != backup_value.source_coordinator_root_identity_sha256
        || protected.source_recovery_root_identity_sha256
            != backup_value.source_recovery_root_identity_sha256
        || protected.source_instance_identity_sha256 != backup_value.source_instance_identity_sha256
        || protected.coordinator_generations != backup_value.generations
        || protected.recovery_inventory_sha256 != inventory.sha256_hex()
        || backup_value.recovery_snapshot.inventory_sha256 != inventory.sha256_hex()
        || protected.recovery_provider_set_count != inventory_value.provider_set_count
        || protected.recovery_provider_set_count
            != backup_value.recovery_snapshot.provider_set_count
        || protected.recovery_entry_count != inventory_value.entry_count
        || protected.recovery_entry_count != backup_value.recovery_snapshot.entry_count
        || protected.recovery_provider_generations != expected_provider_generations
        || protected.at_rest_profile_id != backup_value.at_rest_profile_id
    {
        return Err(ManifestCodecErrorV1::ProvenanceInvalid);
    }

    let pinned = match trust.resolve_ed25519(
        &protected.attestation_profile_id,
        protected.attestation_profile_version,
        &protected.key_id,
    ) {
        ProvisionerTrustDecisionV1::Trusted(pinned) => pinned,
        ProvisionerTrustDecisionV1::Unknown
        | ProvisionerTrustDecisionV1::Revoked
        | ProvisionerTrustDecisionV1::Unavailable => {
            return Err(ManifestCodecErrorV1::ProvenanceInvalid)
        }
    };
    if <[u8; 32]>::from(Sha256::digest(pinned.verifying_key)) != pinned.pinned_sha256 {
        return Err(ManifestCodecErrorV1::ProvenanceInvalid);
    }
    let verifying_key = VerifyingKey::from_bytes(&pinned.verifying_key)
        .map_err(|_| ManifestCodecErrorV1::ProvenanceInvalid)?;
    let signature = decode_signature(&attestation.signature_base64url)
        .map_err(|_| ManifestCodecErrorV1::ProvenanceInvalid)?;
    let protected_bytes = serde_json_canonicalizer::to_vec(protected)
        .map_err(|_| ManifestCodecErrorV1::ProvenanceInvalid)?;
    let mut message =
        Vec::with_capacity(ATTESTATION_SIGNATURE_DOMAIN_V1.len() + protected_bytes.len());
    message.extend_from_slice(ATTESTATION_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(&protected_bytes);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| ManifestCodecErrorV1::ProvenanceInvalid)
}

/// Verifies and projects the three canonical package members before restore code is
/// allowed to inspect any package binding. This function performs no I/O and confers
/// neither destination-root publication nor activation authority.
pub(crate) fn verify_restore_package_manifests_v1<R: ProvisionerTrustViewV1 + ?Sized>(
    attestation_bytes: &[u8],
    top_level_bytes: &[u8],
    inventory_bytes: &[u8],
    trust: &R,
) -> Result<VerifiedRestorePackageBindingsV1, ManifestCodecErrorV1> {
    let attestation = decode_backup_provenance_attestation_v1(attestation_bytes)?;
    let top_level = decode_preparation_backup_manifest_v1(top_level_bytes)?;
    let inventory = decode_recovery_snapshot_manifest_v1(inventory_bytes)?;

    let zero_pending = PendingRetirementEvidenceV1::try_new(0, 0, 0, 0)?;
    cross_validate_backup_retirement_v1(&top_level, &inventory, zero_pending)?;
    verify_backup_provenance_v1(&attestation, &top_level, &inventory, trust)?;

    project_verified_restore_package_bindings_v1(&attestation, &top_level, &inventory)
}

/// Decodes exact canonical recovery-root metadata and projects it only when its closed
/// lifecycle state is `RESTORE_PENDING` with every mandatory binding present.
pub(crate) fn verify_recovery_root_pending_bindings_v1(
    metadata_bytes: &[u8],
) -> Result<VerifiedRecoveryRootPendingBindingsV1, ManifestCodecErrorV1> {
    let metadata = decode_recovery_root_metadata_v1(metadata_bytes)?;
    let value = metadata.value();
    if value.root_lifecycle_state != RecoveryRootLifecycleStateV1::RestorePending {
        return json_invalid();
    }
    let restore_identity_sha256 = value
        .restore_identity_sha256
        .as_deref()
        .ok_or(ManifestCodecErrorV1::JsonContractInvalid)
        .and_then(parse_typed_sha256_v1)?;
    let provenance_attestation_sha256 = value
        .provenance_attestation_sha256
        .as_deref()
        .ok_or(ManifestCodecErrorV1::JsonContractInvalid)
        .and_then(parse_typed_sha256_v1)?;
    let source_inventory_sha256 = value
        .source_inventory_sha256
        .as_deref()
        .ok_or(ManifestCodecErrorV1::JsonContractInvalid)
        .and_then(parse_typed_sha256_v1)?;

    Ok(VerifiedRecoveryRootPendingBindingsV1 {
        metadata_sha256: Sha256Digest::from_bytes(metadata.sha256()),
        root_identity_sha256: parse_typed_sha256_v1(&value.root_identity_sha256)?,
        state_generation: value.state_generation,
        at_rest_profile_id: parse_typed_identifier_v1(&value.at_rest_profile_id)?,
        restore_identity_sha256,
        provenance_attestation_sha256,
        source_inventory_sha256,
    })
}

fn project_verified_restore_package_bindings_v1(
    attestation: &DecodedCanonicalJsonV1<BackupProvenanceAttestationV1>,
    top_level: &DecodedCanonicalJsonV1<PreparationBackupManifestV1>,
    inventory: &DecodedCanonicalJsonV1<RecoverySnapshotManifestV1>,
) -> Result<VerifiedRestorePackageBindingsV1, ManifestCodecErrorV1> {
    let backup = top_level.value();
    let protected = &attestation.value().protected;
    let snapshot = inventory.value();
    let provider_sets = snapshot
        .provider_sets
        .iter()
        .map(project_verified_restore_provider_set_v1)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(VerifiedRestorePackageBindingsV1 {
        attestation_sha256: Sha256Digest::from_bytes(attestation.sha256()),
        top_level_manifest_sha256: Sha256Digest::from_bytes(top_level.sha256()),
        inventory_sha256: Sha256Digest::from_bytes(inventory.sha256()),
        source_coordinator_root_identity_sha256: parse_typed_sha256_v1(
            &backup.source_coordinator_root_identity_sha256,
        )?,
        source_recovery_root_identity_sha256: parse_typed_sha256_v1(
            &backup.source_recovery_root_identity_sha256,
        )?,
        source_instance_identity_sha256: parse_typed_sha256_v1(
            &backup.source_instance_identity_sha256,
        )?,
        coordinator_schema_sha256: parse_typed_sha256_v1(&backup.coordinator_schema_sha256)?,
        coordinator_database_sha256: parse_typed_sha256_v1(&backup.coordinator_database_sha256)?,
        at_rest_profile_id: parse_typed_identifier_v1(&backup.at_rest_profile_id)?,
        attestation_profile_id: parse_typed_identifier_v1(&protected.attestation_profile_id)?,
        attestation_profile_version: protected.attestation_profile_version,
        key_id: parse_typed_identifier_v1(&protected.key_id)?,
        generations: VerifiedRestoreCoordinatorGenerationsV1 {
            store: backup.generations.store,
            operation: backup.generations.operation,
            budget: backup.generations.budget,
            event: backup.generations.event,
            quarantine: backup.generations.quarantine,
        },
        counts: VerifiedRestoreCoordinatorCountsV1 {
            budget_scopes: backup.counts.budget_scopes,
            operations: backup.counts.operations,
            operation_transitions: backup.counts.operation_transitions,
            held_reservations: backup.counts.held_reservations,
            released_reservations: backup.counts.released_reservations,
            pending_events: backup.counts.pending_events,
            delivered_events: backup.counts.delivered_events,
            active_quarantines: backup.counts.active_quarantines,
            resolved_quarantines: backup.counts.resolved_quarantines,
            operation_retirement_pending: backup.counts.operation_retirement_pending,
            orphan_retirement_pending: backup.counts.orphan_retirement_pending,
        },
        lifecycle: VerifiedRestoreLifecycleRequirementsV1 {
            source_root_lifecycle: RestorePackageRootLifecycleV1::Active,
            required_restore_root_lifecycle: RestorePackageRootLifecycleV1::RestorePending,
            requires_paused_restore: backup.requires_paused_restore
                && snapshot.requires_paused_restore,
            requires_boot_epoch_rotation: backup.requires_boot_epoch_rotation,
            requires_instance_epoch_rotation: backup.requires_instance_epoch_rotation,
            requires_fencing_epoch_rotation: backup.requires_fencing_epoch_rotation,
            nonterminal_preparations_not_reactivatable: backup
                .nonterminal_preparations_not_reactivatable,
            may_omit_work_after_generation: backup.may_omit_work_after_generation,
            complete_reference_set: snapshot.complete_reference_set,
            no_retirement_pending: snapshot.no_retirement_pending,
            all_required_entries_verified: backup.recovery_snapshot.all_required_entries_verified,
        },
        provider_set_count: snapshot.provider_set_count,
        entry_count: snapshot.entry_count,
        provider_sets,
    })
}

fn project_verified_restore_provider_set_v1(
    provider: &RecoveryProviderSetV1,
) -> Result<VerifiedRestoreProviderSetV1, ManifestCodecErrorV1> {
    let entries = provider
        .entries
        .iter()
        .map(project_verified_restore_provider_entry_v1)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifiedRestoreProviderSetV1 {
        provider_profile_id: parse_typed_identifier_v1(&provider.provider_profile_id)?,
        provider_profile_version: provider.provider_profile_version,
        provider_id: parse_typed_identifier_v1(&provider.provider_id)?,
        provider_generation: provider.provider_generation,
        evidence_class: parse_typed_identifier_v1(&provider.evidence_class)?,
        at_rest_profile_id: parse_typed_identifier_v1(&provider.at_rest_profile_id)?,
        entry_count: provider.entry_count,
        entries,
    })
}

fn project_verified_restore_provider_entry_v1(
    entry: &RecoverySnapshotEntryV1,
) -> Result<VerifiedRestoreProviderEntryV1, ManifestCodecErrorV1> {
    Ok(VerifiedRestoreProviderEntryV1 {
        package_binding_sha256: parse_typed_sha256_v1(&entry.package_binding_sha256)?,
        manifest_sha256: parse_typed_sha256_v1(&entry.manifest_sha256)?,
        material_sha256: parse_typed_sha256_v1(&entry.material_sha256)?,
        material_length: entry.material_length,
        reserved_capacity: entry.reserved_capacity,
        custody: entry.custody,
        state: entry.state,
        retirement_manifest_sha256: entry
            .retirement_manifest_sha256
            .as_deref()
            .map(parse_typed_sha256_v1)
            .transpose()?,
    })
}

fn parse_typed_sha256_v1(value: &str) -> Result<Sha256Digest, ManifestCodecErrorV1> {
    Sha256Digest::parse_hex(value).map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)
}

fn parse_typed_identifier_v1(value: &str) -> Result<Identifier, ManifestCodecErrorV1> {
    Identifier::new(value.to_owned(), 128).map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)
}

fn compute_package_binding_sha256(
    provider: &RecoveryProviderSetV1,
    entry: &RecoverySnapshotEntryV1,
) -> Result<String, ManifestCodecErrorV1> {
    let preimage = package_binding_preimage_v1(provider, entry)?;
    Ok(encode_sha256(Sha256::digest(preimage).into()))
}

fn package_binding_preimage_v1(
    provider: &RecoveryProviderSetV1,
    entry: &RecoverySnapshotEntryV1,
) -> Result<Vec<u8>, ManifestCodecErrorV1> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(PACKAGE_BINDING_DOMAIN_V1);
    update_string(&mut bytes, &provider.provider_profile_id)?;
    bytes.extend_from_slice(&provider.provider_profile_version.to_be_bytes());
    update_string(&mut bytes, &provider.provider_id)?;
    bytes.extend_from_slice(&provider.provider_generation.to_be_bytes());
    update_string(&mut bytes, &provider.evidence_class)?;
    update_string(&mut bytes, &provider.at_rest_profile_id)?;
    update_string(&mut bytes, entry.custody.as_str())?;
    update_string(&mut bytes, entry.state.as_str())?;
    bytes.extend_from_slice(&decode_sha256(&entry.manifest_sha256)?);
    bytes.extend_from_slice(&decode_sha256(&entry.material_sha256)?);
    bytes.extend_from_slice(&entry.material_length.to_be_bytes());
    bytes.extend_from_slice(&entry.reserved_capacity.to_be_bytes());
    match &entry.retirement_manifest_sha256 {
        None => bytes.push(0_u8),
        Some(retirement) => {
            bytes.push(1_u8);
            bytes.extend_from_slice(&decode_sha256(retirement)?);
        }
    }
    Ok(bytes)
}

fn update_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ManifestCodecErrorV1> {
    let length =
        u16::try_from(value.len()).map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_signature(value: &str) -> Result<Signature, ManifestCodecErrorV1> {
    if value.len() != 86
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(ManifestCodecErrorV1::JsonContractInvalid);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| ManifestCodecErrorV1::JsonContractInvalid)?;
    if URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(ManifestCodecErrorV1::JsonContractInvalid);
    }
    Ok(Signature::from_bytes(&bytes))
}

fn provider_set_key(provider: &RecoveryProviderSetV1) -> (&str, &str, u64) {
    (
        provider.provider_profile_id.as_str(),
        provider.provider_id.as_str(),
        provider.provider_generation,
    )
}

fn provider_generation_key(provider: &RecoveryProviderGenerationV1) -> (&str, &str, u64) {
    (
        provider.provider_profile_id.as_str(),
        provider.provider_id.as_str(),
        provider.provider_generation,
    )
}

fn usize_to_safe_u64(value: usize) -> Result<u64, ManifestCodecErrorV1> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= MAX_SAFE_U64)
        .ok_or(ManifestCodecErrorV1::JsonContractInvalid)
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:".contains(&byte))
}

fn is_evidence_class(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ManifestCodecErrorV1> {
    if !is_lower_sha256(value) {
        return json_invalid();
    }
    let mut decoded = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
    }
    Ok(decoded)
}

fn decode_hex_nibble(value: u8) -> Result<u8, ManifestCodecErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => json_invalid(),
    }
}

fn encode_sha256(value: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(64);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn json_invalid<T>() -> Result<T, ManifestCodecErrorV1> {
    Err(ManifestCodecErrorV1::JsonContractInvalid)
}

/// Production bridge from the T071 orchestration seam to the exact T070 codecs.
/// The pinned verifier is borrowed; neither signing nor verification key bytes are
/// exposed through the maintenance API.
#[cfg(not(test))]
pub(crate) struct ProductionBackupManifestCodecV1<'trust, R: ?Sized> {
    trust: &'trust R,
}

#[cfg(not(test))]
impl<'trust, R: ?Sized> ProductionBackupManifestCodecV1<'trust, R> {
    pub(crate) const fn new(trust: &'trust R) -> Self {
        Self { trust }
    }
}

#[cfg(not(test))]
impl<R: ?Sized> fmt::Debug for ProductionBackupManifestCodecV1<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionBackupManifestCodecV1")
            .finish_non_exhaustive()
    }
}

#[cfg(not(test))]
impl<R> maintenance::QuiescentBackupManifestCodecV1 for ProductionBackupManifestCodecV1<'_, R>
where
    R: ProvisionerTrustResolverV1 + ?Sized,
{
    fn finalize_inventory_v1(
        &mut self,
        entries: &[maintenance::ProviderRecoveryInventoryEntryV1],
        pending: maintenance::BackupPendingRetirementCountsV1,
    ) -> Result<maintenance::FinalizedRecoveryInventoryV1, maintenance::QuiescentBackupErrorV1>
    {
        type ProviderKey = (String, u16, String, u64, String, String);
        let mut grouped: BTreeMap<ProviderKey, Vec<RecoverySnapshotEntryInputV1>> = BTreeMap::new();
        for entry in entries {
            let evidence_class = match entry.evidence_class() {
                RecoveryEvidenceClassV1::SyntheticConformance => "SYNTHETIC_CONFORMANCE",
                RecoveryEvidenceClassV1::ApprovedProduction => "APPROVED_PRODUCTION",
            };
            let custody = match entry.custody() {
                maintenance::ProviderRecoveryCustodyV1::OperationBound => {
                    RecoveryCustodyV1::OperationBound
                }
                maintenance::ProviderRecoveryCustodyV1::QuarantinedOrphan => {
                    RecoveryCustodyV1::QuarantinedOrphan
                }
                maintenance::ProviderRecoveryCustodyV1::OrphanResolutionTombstone => {
                    RecoveryCustodyV1::OrphanResolutionTombstone
                }
            };
            let state = match entry.state() {
                maintenance::ProviderRecoveryStateV1::Published => {
                    RecoverySnapshotStateV1::MaterialPresent
                }
                maintenance::ProviderRecoveryStateV1::RetiredTombstone => {
                    RecoverySnapshotStateV1::RetiredTombstone
                }
            };
            grouped
                .entry((
                    entry.provider_profile_id().as_str().to_owned(),
                    entry.provider_profile_version(),
                    entry.provider_id().as_str().to_owned(),
                    entry.provider_generation(),
                    evidence_class.to_owned(),
                    entry.at_rest_profile_id().as_str().to_owned(),
                ))
                .or_default()
                .push(RecoverySnapshotEntryInputV1 {
                    manifest_sha256: entry.manifest_digest(),
                    material_sha256: entry.material_digest(),
                    material_length: entry.material_length(),
                    reserved_capacity: entry.reserved_capacity(),
                    custody,
                    state,
                    retirement_manifest_sha256: entry.retirement_manifest_digest(),
                });
        }
        let provider_set_count = u64::try_from(grouped.len())
            .ok()
            .filter(|count| *count <= MAX_SAFE_U64)
            .ok_or(maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
        let mut provider_generations = Vec::with_capacity(grouped.len());
        let mut provider_inputs = Vec::with_capacity(grouped.len());
        for ((profile, version, provider, generation, evidence, at_rest), group_entries) in grouped
        {
            let profile = Identifier::new(profile, 128)
                .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
            let provider = Identifier::new(provider, 128)
                .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
            let at_rest = Identifier::new(at_rest, 128)
                .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
            provider_generations.push(maintenance::BackupProviderGenerationV1 {
                provider_profile_id: profile.clone(),
                provider_profile_version: version,
                provider_id: provider.clone(),
                provider_generation: generation,
            });
            provider_inputs.push(RecoveryProviderSetInputV1 {
                provider_profile_id: profile,
                provider_profile_version: version,
                provider_id: provider,
                provider_generation: generation,
                evidence_class: evidence,
                at_rest_profile_id: at_rest,
                entries: group_entries,
            });
        }
        let entry_count = u64::try_from(entries.len())
            .ok()
            .filter(|count| *count <= MAX_SAFE_U64)
            .ok_or(maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
        let finalized = finalize_recovery_snapshot_manifest_v1(
            provider_inputs,
            production_pending_counts_v1(pending)?,
        )
        .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
        let expected_sha256 = Sha256Digest::from_bytes(finalized.sha256());
        let member = maintenance::CanonicalBackupMemberV1::try_new(finalized.bytes().to_vec())?;
        if member.sha256() != expected_sha256 {
            return Err(maintenance::QuiescentBackupErrorV1::ManifestInvalid);
        }
        Ok(maintenance::FinalizedRecoveryInventoryV1 {
            member,
            provider_set_count,
            entry_count,
            provider_generations,
        })
    }

    fn finalize_top_level_v1(
        &mut self,
        input: maintenance::BackupTopLevelCodecInputV1,
        pending: maintenance::BackupPendingRetirementCountsV1,
    ) -> Result<maintenance::CanonicalBackupMemberV1, maintenance::QuiescentBackupErrorV1> {
        let generations = input.generations;
        let counts = input.counts;
        let finalized = finalize_preparation_backup_manifest_v1(
            PreparationBackupManifestInputV1 {
                source_coordinator_root_identity_sha256: input
                    .source_coordinator_root_identity_sha256,
                source_recovery_root_identity_sha256: input.source_recovery_root_identity_sha256,
                source_instance_identity_sha256: input.source_instance_identity_sha256,
                coordinator_schema_sha256: input.coordinator_schema_sha256,
                coordinator_database_sha256: input.coordinator_database_sha256,
                at_rest_profile_id: input.at_rest_profile_id,
                generations: CoordinatorGenerationsInputV1 {
                    store: generations.store(),
                    operation: generations.operation(),
                    budget: generations.budget(),
                    event: generations.event(),
                    quarantine: generations.quarantine(),
                },
                counts: PreparationBackupCountsInputV1 {
                    budget_scopes: counts.budget_scopes(),
                    operations: counts.operations(),
                    operation_transitions: counts.operation_transitions(),
                    held_reservations: counts.held_reservations(),
                    released_reservations: counts.released_reservations(),
                    pending_events: counts.pending_events(),
                    delivered_events: counts.delivered_events(),
                    active_quarantines: counts.active_quarantines(),
                    resolved_quarantines: counts.resolved_quarantines(),
                },
                recovery_inventory_sha256: input.recovery_inventory_sha256,
                recovery_provider_set_count: input.recovery_provider_set_count,
                recovery_entry_count: input.recovery_entry_count,
            },
            production_pending_counts_v1(pending)?,
        )
        .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
        maintenance::CanonicalBackupMemberV1::try_new(finalized.bytes().to_vec())
    }

    fn finalize_protected_v1(
        &mut self,
        input: &maintenance::BackupProtectedCodecInputV1,
    ) -> Result<maintenance::CanonicalBackupMemberV1, maintenance::QuiescentBackupErrorV1> {
        let finalized =
            finalize_backup_provenance_protected_v1(production_protected_input_v1(input))
                .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
        maintenance::CanonicalBackupMemberV1::try_new(finalized.bytes().to_vec())
    }

    fn finalize_attestation_v1(
        &mut self,
        input: &maintenance::BackupProtectedCodecInputV1,
        signature: [u8; 64],
    ) -> Result<maintenance::CanonicalBackupMemberV1, maintenance::QuiescentBackupErrorV1> {
        let protected =
            finalize_backup_provenance_protected_v1(production_protected_input_v1(input))
                .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
        let (protected, _, _) = protected.into_parts();
        let attestation = finalize_backup_provenance_attestation_v1(protected, signature)
            .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)?;
        maintenance::CanonicalBackupMemberV1::try_new(attestation.bytes().to_vec())
    }

    fn verify_reopened_package_v1(
        &mut self,
        attestation: &[u8],
        top_level: &[u8],
        inventory: &[u8],
        pending: maintenance::BackupPendingRetirementCountsV1,
    ) -> Result<(), maintenance::QuiescentBackupErrorV1> {
        let attestation = decode_backup_provenance_attestation_v1(attestation)
            .map_err(|_| maintenance::QuiescentBackupErrorV1::ProvenanceInvalid)?;
        let top_level = decode_preparation_backup_manifest_v1(top_level)
            .map_err(|_| maintenance::QuiescentBackupErrorV1::ProvenanceInvalid)?;
        let inventory = decode_recovery_snapshot_manifest_v1(inventory)
            .map_err(|_| maintenance::QuiescentBackupErrorV1::ProvenanceInvalid)?;
        cross_validate_backup_retirement_v1(
            &top_level,
            &inventory,
            production_pending_counts_v1(pending)?,
        )
        .map_err(|_| maintenance::QuiescentBackupErrorV1::ProvenanceInvalid)?;
        verify_backup_provenance_v1(&attestation, &top_level, &inventory, self.trust)
            .map_err(|_| maintenance::QuiescentBackupErrorV1::ProvenanceInvalid)
    }
}

#[cfg(not(test))]
fn production_pending_counts_v1(
    pending: maintenance::BackupPendingRetirementCountsV1,
) -> Result<PendingRetirementEvidenceV1, maintenance::QuiescentBackupErrorV1> {
    PendingRetirementEvidenceV1::try_new(
        pending.coordinator_operation_pending,
        pending.coordinator_orphan_pending,
        pending.provider_operation_pending,
        pending.provider_orphan_pending,
    )
    .map_err(|_| maintenance::QuiescentBackupErrorV1::ManifestInvalid)
}

#[cfg(not(test))]
fn production_protected_input_v1(
    input: &maintenance::BackupProtectedCodecInputV1,
) -> BackupProvenanceProtectedInputV1 {
    let generations = input.coordinator_generations;
    BackupProvenanceProtectedInputV1 {
        top_level_manifest_sha256: input.top_level_manifest_sha256,
        source_coordinator_root_identity_sha256: input.source_coordinator_root_identity_sha256,
        source_recovery_root_identity_sha256: input.source_recovery_root_identity_sha256,
        source_instance_identity_sha256: input.source_instance_identity_sha256,
        coordinator_generations: CoordinatorGenerationsInputV1 {
            store: generations.store(),
            operation: generations.operation(),
            budget: generations.budget(),
            event: generations.event(),
            quarantine: generations.quarantine(),
        },
        recovery_inventory_sha256: input.recovery_inventory_sha256,
        recovery_entry_count: input.recovery_entry_count,
        recovery_provider_generations: input
            .recovery_provider_generations
            .iter()
            .map(|provider| RecoveryProviderGenerationInputV1 {
                provider_profile_id: provider.provider_profile_id.clone(),
                provider_profile_version: provider.provider_profile_version,
                provider_id: provider.provider_id.clone(),
                provider_generation: provider.provider_generation,
            })
            .collect(),
        at_rest_profile_id: input.at_rest_profile_id.clone(),
        attestation_profile_id: input.attestation_profile_id.clone(),
        attestation_profile_version: input.attestation_profile_version,
        key_id: input.key_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::{json, Value};

    const ATTESTATION_PROFILE_ID: &str = "provisioner-backup";
    const KEY_ID: &str = "provisioner-key-1";

    fn digest_hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn canonical(value: &Value) -> Vec<u8> {
        serde_json_canonicalizer::to_vec(value).expect("public synthetic JSON canonicalizes")
    }

    fn digest_to_hex(digest: [u8; 32]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn identifier(value: &str) -> Identifier {
        Identifier::new(value, 128).expect("public synthetic identifier is valid")
    }

    const fn typed_digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn no_pending() -> PendingRetirementEvidenceV1 {
        PendingRetirementEvidenceV1::try_new(0, 0, 0, 0).unwrap()
    }

    fn material_entry_input(byte: u8) -> RecoverySnapshotEntryInputV1 {
        RecoverySnapshotEntryInputV1 {
            manifest_sha256: typed_digest(byte),
            material_sha256: typed_digest(byte.wrapping_add(0x10)),
            material_length: 3,
            reserved_capacity: 4,
            custody: RecoveryCustodyV1::OperationBound,
            state: RecoverySnapshotStateV1::MaterialPresent,
            retirement_manifest_sha256: None,
        }
    }

    fn provider_input(
        profile: &str,
        provider: &str,
        generation: u64,
        entries: Vec<RecoverySnapshotEntryInputV1>,
    ) -> RecoveryProviderSetInputV1 {
        RecoveryProviderSetInputV1 {
            provider_profile_id: identifier(profile),
            provider_profile_version: 1,
            provider_id: identifier(provider),
            provider_generation: generation,
            evidence_class: "SYNTHETIC_CONFORMANCE".to_owned(),
            at_rest_profile_id: identifier("at-rest.synthetic-v1"),
            entries,
        }
    }

    fn valid_recovery_root_value() -> Value {
        json!({
            "schema": "helixos.recovery-root-metadata/1",
            "root_identity_sha256": digest_hex(0x41),
            "root_lifecycle_state": "ACTIVE",
            "state_generation": 0,
            "at_rest_profile_id": "a"
        })
    }

    fn valid_inventory_value() -> Value {
        json!({
            "schema": "helixos.recovery-snapshot/1",
            "provider_set_count": 1,
            "entry_count": 1,
            "provider_sets": [{
                "provider_profile_id": "p",
                "provider_profile_version": 1,
                "provider_id": "r",
                "provider_generation": 1,
                "evidence_class": "SYNTHETIC_CONFORMANCE",
                "at_rest_profile_id": "a",
                "entry_count": 1,
                "entries": [{
                    "package_binding_sha256": "85e7d004e1847040a09dcd23c04ce08e6c823adaf6661e38cfde4a7fd0e58e10",
                    "manifest_sha256": digest_hex(0x11),
                    "material_sha256": digest_hex(0x22),
                    "material_length": 3,
                    "reserved_capacity": 3,
                    "custody": "OPERATION_BOUND",
                    "state": "MATERIAL_PRESENT"
                }]
            }],
            "complete_reference_set": true,
            "no_retirement_pending": true,
            "requires_paused_restore": true
        })
    }

    fn valid_backup_value(inventory_sha256: &str) -> Value {
        json!({
            "schema": "helixos.preparation-backup/1",
            "application_id": 1212962883,
            "store_schema_version": 1,
            "source_coordinator_root_identity_sha256": digest_hex(0x01),
            "source_recovery_root_identity_sha256": digest_hex(0x02),
            "source_instance_identity_sha256": digest_hex(0x03),
            "source_root_lifecycle_state": "ACTIVE",
            "coordinator_schema_sha256": digest_hex(0x04),
            "coordinator_database_sha256": digest_hex(0x05),
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
            "at_rest_profile_id": "a",
            "generations": {
                "store": 1,
                "operation": 2,
                "budget": 3,
                "event": 4,
                "quarantine": 5
            },
            "counts": {
                "budget_scopes": 1,
                "operations": 1,
                "operation_transitions": 1,
                "held_reservations": 1,
                "released_reservations": 0,
                "pending_events": 1,
                "delivered_events": 0,
                "active_quarantines": 0,
                "resolved_quarantines": 0,
                "operation_retirement_pending": 0,
                "orphan_retirement_pending": 0
            },
            "recovery_snapshot": {
                "schema": "helixos.recovery-snapshot-summary/1",
                "inventory_sha256": inventory_sha256,
                "provider_set_count": 1,
                "entry_count": 1,
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

    fn valid_attestation_value(
        signing_key: &SigningKey,
        backup_sha256: &str,
        inventory_sha256: &str,
    ) -> Value {
        let protected = json!({
            "schema": "helixos.preparation-backup-provenance-protected/1",
            "top_level_manifest_sha256": backup_sha256,
            "source_coordinator_root_identity_sha256": digest_hex(0x01),
            "source_recovery_root_identity_sha256": digest_hex(0x02),
            "source_instance_identity_sha256": digest_hex(0x03),
            "coordinator_generations": {
                "store": 1,
                "operation": 2,
                "budget": 3,
                "event": 4,
                "quarantine": 5
            },
            "recovery_inventory_sha256": inventory_sha256,
            "recovery_provider_set_count": 1,
            "recovery_entry_count": 1,
            "recovery_provider_generations": [{
                "provider_profile_id": "p",
                "provider_profile_version": 1,
                "provider_id": "r",
                "provider_generation": 1
            }],
            "at_rest_profile_id": "a",
            "attestation_profile_id": ATTESTATION_PROFILE_ID,
            "attestation_profile_version": 1,
            "key_id": KEY_ID,
            "digest_algorithm": "sha-256"
        });
        let protected_bytes = canonical(&protected);
        let mut message = ATTESTATION_SIGNATURE_DOMAIN_V1.to_vec();
        message.extend_from_slice(&protected_bytes);
        let signature = signing_key.sign(&message).to_bytes();
        json!({
            "schema": "helixos.preparation-backup-provenance-attestation/1",
            "protected": protected,
            "signature_algorithm": "ed25519",
            "signature_base64url": URL_SAFE_NO_PAD.encode(signature)
        })
    }

    #[derive(Clone, Copy)]
    enum TrustMode {
        Trusted,
        Unknown,
        Revoked,
        Unavailable,
    }

    struct FixedTrust {
        mode: TrustMode,
        key: PinnedEd25519KeyV1,
    }

    #[allow(dead_code)]
    struct FixedTrustCustody {
        key: PinnedEd25519KeyV1,
    }

    impl ProvisionerTrustViewV1 for FixedTrustCustody {
        fn resolve_ed25519(
            &self,
            profile_id: &str,
            profile_version: u64,
            key_id: &str,
        ) -> ProvisionerTrustDecisionV1 {
            if profile_id == ATTESTATION_PROFILE_ID && profile_version == 1 && key_id == KEY_ID {
                ProvisionerTrustDecisionV1::Trusted(self.key)
            } else {
                ProvisionerTrustDecisionV1::Unknown
            }
        }
    }

    impl ProvisionerTrustCustodyV1 for FixedTrustCustody {}

    impl ProvisionerTrustResolverV1 for FixedTrust {
        fn acquire_restore_trust_custody_v1(&self) -> ProvisionerTrustCustodyOutcomeV1 {
            match self.mode {
                TrustMode::Trusted => {
                    ProvisionerTrustCustodyOutcomeV1::Acquired(Box::new(FixedTrustCustody {
                        key: self.key,
                    }))
                }
                TrustMode::Revoked => ProvisionerTrustCustodyOutcomeV1::Revoked,
                TrustMode::Unknown | TrustMode::Unavailable => {
                    ProvisionerTrustCustodyOutcomeV1::Unavailable
                }
            }
        }

        fn resolve_ed25519(
            &self,
            profile_id: &str,
            profile_version: u64,
            key_id: &str,
        ) -> ProvisionerTrustDecisionV1 {
            if profile_id != ATTESTATION_PROFILE_ID || profile_version != 1 || key_id != KEY_ID {
                return ProvisionerTrustDecisionV1::Unknown;
            }
            match self.mode {
                TrustMode::Trusted => ProvisionerTrustDecisionV1::Trusted(self.key),
                TrustMode::Unknown => ProvisionerTrustDecisionV1::Unknown,
                TrustMode::Revoked => ProvisionerTrustDecisionV1::Revoked,
                TrustMode::Unavailable => ProvisionerTrustDecisionV1::Unavailable,
            }
        }
    }

    fn fixed_trust(signing_key: &SigningKey, mode: TrustMode) -> FixedTrust {
        let verifying_key = signing_key.verifying_key().to_bytes();
        let pinned_sha256 = Sha256::digest(verifying_key).into();
        FixedTrust {
            mode,
            key: PinnedEd25519KeyV1::try_new(verifying_key, pinned_sha256).unwrap(),
        }
    }

    fn valid_restore_package_bytes(signing_key: &SigningKey) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let inventory = canonical(&valid_inventory_value());
        let inventory_sha256 = encode_sha256(Sha256::digest(&inventory).into());
        let top_level = canonical(&valid_backup_value(&inventory_sha256));
        let top_level_sha256 = encode_sha256(Sha256::digest(&top_level).into());
        let attestation = canonical(&valid_attestation_value(
            signing_key,
            &top_level_sha256,
            &inventory_sha256,
        ));
        (attestation, top_level, inventory)
    }

    #[test]
    fn all_four_embedded_schema_digests_are_exact() {
        assert_eq!(
            digest_to_hex(embedded_preparation_backup_manifest_schema_v1_sha256()),
            "163cfd72f54983f993b2d5f6ad3fcd00df84a1b8cbc7eb971fcc8c1d0019199e"
        );
        assert_eq!(
            digest_to_hex(embedded_backup_provenance_attestation_schema_v1_sha256()),
            "6b752fc1a8f0c92fd69a03ce418d07087e615eaf55f3b2e1959668e15237728f"
        );
        assert_eq!(
            digest_to_hex(embedded_recovery_root_metadata_schema_v1_sha256()),
            "0fb080c12df1b1e99ef7d0a19ca53ded97d8d170e0c2825e93fd3d57c53bf25f"
        );
        assert_eq!(
            digest_to_hex(embedded_recovery_snapshot_manifest_schema_v1_sha256()),
            "371e94fbf5c52d462e8363c9b3237a57288c4b0ae1c766e12c2c904d5f6cf646"
        );
    }

    #[test]
    fn both_t061_package_binding_known_answer_preimages_and_digests_are_exact() {
        let corpus: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/durable-preparation-v1/cases.json"
        )))
        .expect("T061 corpus parses");
        let vectors = corpus["package_binding_kats"]
            .as_array()
            .expect("T061 package-binding vectors exist");
        assert_eq!(vectors.len(), 2);

        for vector in vectors {
            let state = match vector["state"].as_str().unwrap() {
                "MATERIAL_PRESENT" => RecoverySnapshotStateV1::MaterialPresent,
                "RETIRED_TOMBSTONE" => RecoverySnapshotStateV1::RetiredTombstone,
                _ => panic!("T061 state is closed"),
            };
            let provider = RecoveryProviderSetV1 {
                provider_profile_id: vector["provider_profile_id"].as_str().unwrap().to_owned(),
                provider_profile_version: vector["provider_profile_version"].as_u64().unwrap(),
                provider_id: vector["provider_id"].as_str().unwrap().to_owned(),
                provider_generation: vector["provider_generation"].as_u64().unwrap(),
                evidence_class: vector["evidence_class"].as_str().unwrap().to_owned(),
                at_rest_profile_id: vector["at_rest_profile_id"].as_str().unwrap().to_owned(),
                entry_count: 1,
                entries: Vec::new(),
            };
            let entry = RecoverySnapshotEntryV1 {
                package_binding_sha256: vector["expected_package_binding_sha256"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                manifest_sha256: vector["manifest_sha256"].as_str().unwrap().to_owned(),
                material_sha256: vector["material_sha256"].as_str().unwrap().to_owned(),
                material_length: vector["material_length"].as_u64().unwrap(),
                reserved_capacity: vector["reserved_capacity"].as_u64().unwrap(),
                custody: RecoveryCustodyV1::OperationBound,
                state,
                retirement_manifest_sha256: vector
                    .get("retirement_manifest_sha256")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            };
            let preimage = package_binding_preimage_v1(&provider, &entry).unwrap();
            assert_eq!(
                u64::try_from(preimage.len()).unwrap(),
                vector["expected_preimage_length"].as_u64().unwrap()
            );
            assert_eq!(
                bytes_to_hex(&preimage),
                vector["expected_preimage_hex"].as_str().unwrap()
            );
            assert_eq!(
                compute_package_binding_sha256(&provider, &entry).unwrap(),
                vector["expected_package_binding_sha256"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn inventory_finalizer_sorts_both_levels_and_rejects_duplicate_or_pending_inputs() {
        let finalized = finalize_recovery_snapshot_manifest_v1(
            vec![
                provider_input(
                    "profile.z",
                    "provider.z",
                    9,
                    vec![material_entry_input(0x22)],
                ),
                provider_input(
                    "profile.a",
                    "provider.a",
                    1,
                    vec![material_entry_input(0x12), material_entry_input(0x11)],
                ),
            ],
            no_pending(),
        )
        .expect("valid inventory finalizes");
        let inventory = finalized.value();
        assert_eq!(inventory.provider_set_count, 2);
        assert_eq!(inventory.entry_count, 3);
        assert_eq!(inventory.provider_sets[0].provider_profile_id, "profile.a");
        assert!(
            inventory.provider_sets[0].entries[0].package_binding_sha256
                < inventory.provider_sets[0].entries[1].package_binding_sha256
        );
        assert_eq!(
            finalized.sha256(),
            <[u8; 32]>::from(Sha256::digest(finalized.bytes()))
        );
        assert!(!finalized.bytes().starts_with(&[0xEF, 0xBB, 0xBF]));
        assert!(!finalized.bytes().ends_with(b"\n"));
        decode_recovery_snapshot_manifest_v1(finalized.bytes())
            .expect("finalized inventory round trips through the strict decoder");

        let duplicate_groups = vec![
            provider_input("profile.a", "provider.a", 1, Vec::new()),
            provider_input("profile.a", "provider.a", 1, Vec::new()),
        ];
        assert_eq!(
            finalize_recovery_snapshot_manifest_v1(duplicate_groups, no_pending()).unwrap_err(),
            ManifestCodecErrorV1::JsonContractInvalid
        );
        assert_eq!(
            finalize_recovery_snapshot_manifest_v1(
                vec![provider_input(
                    "profile.a",
                    "provider.a",
                    1,
                    vec![material_entry_input(0x11), material_entry_input(0x11)],
                )],
                no_pending(),
            )
            .unwrap_err(),
            ManifestCodecErrorV1::JsonContractInvalid
        );
        let first = material_entry_input(0x31);
        let mut same_manifest_distinct_binding = material_entry_input(0x32);
        same_manifest_distinct_binding.manifest_sha256 = first.manifest_sha256;
        assert_ne!(
            first.material_sha256,
            same_manifest_distinct_binding.material_sha256
        );
        assert_eq!(
            finalize_recovery_snapshot_manifest_v1(
                vec![provider_input(
                    "profile.a",
                    "provider.a",
                    1,
                    vec![first, same_manifest_distinct_binding],
                )],
                no_pending(),
            )
            .unwrap_err(),
            ManifestCodecErrorV1::JsonContractInvalid
        );
        let cross_provider_first = material_entry_input(0x41);
        let mut cross_provider_second = material_entry_input(0x42);
        cross_provider_second.manifest_sha256 = cross_provider_first.manifest_sha256;
        assert_eq!(
            finalize_recovery_snapshot_manifest_v1(
                vec![
                    provider_input("profile.a", "provider.a", 1, vec![cross_provider_first]),
                    provider_input("profile.b", "provider.b", 1, vec![cross_provider_second]),
                ],
                no_pending(),
            )
            .unwrap_err(),
            ManifestCodecErrorV1::JsonContractInvalid
        );
        assert_eq!(
            finalize_recovery_snapshot_manifest_v1(
                Vec::new(),
                PendingRetirementEvidenceV1::try_new(0, 0, 0, 1).unwrap(),
            )
            .unwrap_err(),
            ManifestCodecErrorV1::JsonContractInvalid
        );
    }

    #[test]
    fn four_closed_schema_finalizers_round_trip_exact_canonical_bytes() {
        let inventory = finalize_recovery_snapshot_manifest_v1(
            vec![provider_input(
                "profile.a",
                "provider.a",
                1,
                vec![material_entry_input(0x11)],
            )],
            no_pending(),
        )
        .unwrap();
        let inventory_digest = Sha256Digest::from_bytes(inventory.sha256());
        let generations = CoordinatorGenerationsInputV1 {
            store: 11,
            operation: 7,
            budget: 9,
            event: 8,
            quarantine: 4,
        };
        let backup = finalize_preparation_backup_manifest_v1(
            PreparationBackupManifestInputV1 {
                source_coordinator_root_identity_sha256: typed_digest(0x01),
                source_recovery_root_identity_sha256: typed_digest(0x02),
                source_instance_identity_sha256: typed_digest(0x03),
                coordinator_schema_sha256: typed_digest(0x04),
                coordinator_database_sha256: typed_digest(0x05),
                at_rest_profile_id: identifier("at-rest.synthetic-v1"),
                generations,
                counts: PreparationBackupCountsInputV1 {
                    budget_scopes: 1,
                    operations: 1,
                    operation_transitions: 1,
                    held_reservations: 1,
                    released_reservations: 0,
                    pending_events: 1,
                    delivered_events: 0,
                    active_quarantines: 0,
                    resolved_quarantines: 0,
                },
                recovery_inventory_sha256: inventory_digest,
                recovery_provider_set_count: 1,
                recovery_entry_count: 1,
            },
            no_pending(),
        )
        .unwrap();
        let decoded_backup = decode_preparation_backup_manifest_v1(backup.bytes()).unwrap();
        assert_eq!(decoded_backup.sha256(), backup.sha256());
        assert_eq!(backup.sha256_hex(), encode_sha256(backup.sha256()));

        let active_root = finalize_recovery_root_metadata_v1(RecoveryRootMetadataInputV1::Active {
            root_identity_sha256: typed_digest(0x40),
            at_rest_profile_id: identifier("at-rest.synthetic-v1"),
        })
        .unwrap();
        decode_recovery_root_metadata_v1(active_root.bytes())
            .expect("ACTIVE recovery-root metadata finalizes canonically");

        let root =
            finalize_recovery_root_metadata_v1(RecoveryRootMetadataInputV1::RestorePending {
                root_identity_sha256: typed_digest(0x41),
                state_generation: 1,
                at_rest_profile_id: identifier("at-rest.synthetic-v1"),
                restore_identity_sha256: typed_digest(0x42),
                provenance_attestation_sha256: typed_digest(0x43),
                source_inventory_sha256: inventory_digest,
            })
            .unwrap();
        assert_eq!(
            decode_recovery_root_metadata_v1(root.bytes())
                .unwrap()
                .sha256(),
            root.sha256()
        );

        let protected = finalize_backup_provenance_protected_v1(BackupProvenanceProtectedInputV1 {
            top_level_manifest_sha256: Sha256Digest::from_bytes(backup.sha256()),
            source_coordinator_root_identity_sha256: typed_digest(0x01),
            source_recovery_root_identity_sha256: typed_digest(0x02),
            source_instance_identity_sha256: typed_digest(0x03),
            coordinator_generations: generations,
            recovery_inventory_sha256: inventory_digest,
            recovery_entry_count: 1,
            recovery_provider_generations: vec![RecoveryProviderGenerationInputV1 {
                provider_profile_id: identifier("profile.a"),
                provider_profile_version: 1,
                provider_id: identifier("provider.a"),
                provider_generation: 1,
            }],
            at_rest_profile_id: identifier("at-rest.synthetic-v1"),
            attestation_profile_id: identifier(ATTESTATION_PROFILE_ID),
            attestation_profile_version: 1,
            key_id: identifier(KEY_ID),
        })
        .unwrap();
        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let mut message = ATTESTATION_SIGNATURE_DOMAIN_V1.to_vec();
        message.extend_from_slice(protected.bytes());
        let signature = signing_key.sign(&message).to_bytes();
        let (protected_value, _, _) = protected.into_parts();
        let attestation =
            finalize_backup_provenance_attestation_v1(protected_value, signature).unwrap();
        assert_eq!(
            decode_backup_provenance_attestation_v1(attestation.bytes())
                .unwrap()
                .sha256(),
            attestation.sha256()
        );

        for bytes in [
            inventory.bytes(),
            backup.bytes(),
            root.bytes(),
            attestation.bytes(),
        ] {
            assert!(!bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
            assert!(!bytes.ends_with(b"\n"));
        }
    }

    #[test]
    fn manifest_errors_map_exhaustively_to_payload_free_internal_classifications() {
        assert_eq!(
            crate::error::InternalCoordinatorError::from(ManifestCodecErrorV1::JsonContractInvalid),
            crate::error::InternalCoordinatorError::JsonContractInvalid
        );
        assert_eq!(
            crate::error::InternalCoordinatorError::from(ManifestCodecErrorV1::ProvenanceInvalid),
            crate::error::InternalCoordinatorError::ProvenanceInvalid
        );
    }

    #[test]
    fn closed_decoder_rejects_duplicate_unknown_bom_newline_and_explicit_null() {
        let canonical_root = canonical(&valid_recovery_root_value());
        let decoded = decode_recovery_root_metadata_v1(&canonical_root).unwrap();
        let expected_sha256: [u8; 32] = Sha256::digest(&canonical_root).into();
        assert_eq!(decoded.sha256(), expected_sha256);
        assert_eq!(decoded.into_value().state_generation, 0);

        let duplicate = format!(
            "{{\"at_rest_profile_id\":\"a\",\"root_identity_sha256\":\"{}\",\"root_lifecycle_state\":\"ACTIVE\",\"schema\":\"helixos.recovery-root-metadata/1\",\"schema\":\"helixos.recovery-root-metadata/1\",\"state_generation\":0}}",
            digest_hex(0x41)
        );
        let unknown = format!(
            "{{\"at_rest_profile_id\":\"a\",\"extra\":true,\"root_identity_sha256\":\"{}\",\"root_lifecycle_state\":\"ACTIVE\",\"schema\":\"helixos.recovery-root-metadata/1\",\"state_generation\":0}}",
            digest_hex(0x41)
        );
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(&canonical_root);
        let mut newline = canonical_root.clone();
        newline.push(b'\n');
        let explicit_null = canonical(&json!({
            "schema": "helixos.recovery-root-metadata/1",
            "root_identity_sha256": digest_hex(0x41),
            "root_lifecycle_state": "ACTIVE",
            "state_generation": 0,
            "at_rest_profile_id": "a",
            "restore_identity_sha256": null
        }));

        for bytes in [
            duplicate.as_bytes(),
            unknown.as_bytes(),
            bom.as_slice(),
            newline.as_slice(),
            explicit_null.as_slice(),
        ] {
            assert_eq!(
                decode_recovery_root_metadata_v1(bytes).unwrap_err(),
                ManifestCodecErrorV1::JsonContractInvalid
            );
        }
    }

    #[test]
    fn recovery_root_lifecycle_fields_are_closed_and_exact() {
        let pending = canonical(&json!({
            "schema": "helixos.recovery-root-metadata/1",
            "root_identity_sha256": digest_hex(0x41),
            "root_lifecycle_state": "RESTORE_PENDING",
            "state_generation": 1,
            "at_rest_profile_id": "a",
            "restore_identity_sha256": digest_hex(0x42),
            "provenance_attestation_sha256": digest_hex(0x43),
            "source_inventory_sha256": digest_hex(0x44)
        }));
        assert!(decode_recovery_root_metadata_v1(&pending).is_ok());

        let missing_pending_binding = canonical(&json!({
            "schema": "helixos.recovery-root-metadata/1",
            "root_identity_sha256": digest_hex(0x41),
            "root_lifecycle_state": "RESTORE_PENDING",
            "state_generation": 1,
            "at_rest_profile_id": "a"
        }));
        assert!(decode_recovery_root_metadata_v1(&missing_pending_binding).is_err());
    }

    #[test]
    fn inventory_decoder_checks_counts_order_capacity_state_and_package_binding() {
        let valid = canonical(&valid_inventory_value());
        let decoded = decode_recovery_snapshot_manifest_v1(&valid).unwrap();
        assert_eq!(decoded.value().provider_set_count, 1);
        assert_eq!(decoded.value().entry_count, 1);

        for mutate in [
            |value: &mut Value| value["provider_set_count"] = json!(2),
            |value: &mut Value| {
                value["provider_sets"][0]["entries"][0]["reserved_capacity"] = json!(2)
            },
            |value: &mut Value| {
                value["provider_sets"][0]["entries"][0]["package_binding_sha256"] =
                    Value::String(digest_hex(0x99))
            },
        ] {
            let mut invalid = valid_inventory_value();
            mutate(&mut invalid);
            assert!(decode_recovery_snapshot_manifest_v1(&canonical(&invalid)).is_err());
        }
    }

    #[test]
    fn backup_pending_retirement_counts_are_fixed_zero_and_cross_validated() {
        let inventory =
            decode_recovery_snapshot_manifest_v1(&canonical(&valid_inventory_value())).unwrap();
        let backup = decode_preparation_backup_manifest_v1(&canonical(&valid_backup_value(
            &inventory.sha256_hex(),
        )))
        .unwrap();
        let clear = PendingRetirementEvidenceV1::try_new(0, 0, 0, 0).unwrap();
        assert!(cross_validate_backup_retirement_v1(&backup, &inventory, clear).is_ok());

        let pending = PendingRetirementEvidenceV1::try_new(1, 0, 0, 0).unwrap();
        assert_eq!(
            cross_validate_backup_retirement_v1(&backup, &inventory, pending),
            Err(ManifestCodecErrorV1::JsonContractInvalid)
        );

        let mut invalid = valid_backup_value(&inventory.sha256_hex());
        invalid["counts"]["orphan_retirement_pending"] = json!(1);
        assert!(decode_preparation_backup_manifest_v1(&canonical(&invalid)).is_err());
    }

    #[test]
    fn pinned_ed25519_provenance_accepts_exact_and_rejects_unknown_revoked_or_wrong_key() {
        let inventory =
            decode_recovery_snapshot_manifest_v1(&canonical(&valid_inventory_value())).unwrap();
        let backup = decode_preparation_backup_manifest_v1(&canonical(&valid_backup_value(
            &inventory.sha256_hex(),
        )))
        .unwrap();

        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let pin: [u8; 32] = Sha256::digest(verifying_key).into();
        let pinned = PinnedEd25519KeyV1::try_new(verifying_key, pin).unwrap();
        assert_eq!(
            PinnedEd25519KeyV1::try_new(verifying_key, [0; 32]),
            Err(ManifestCodecErrorV1::ProvenanceInvalid)
        );

        let attestation = decode_backup_provenance_attestation_v1(&canonical(
            &valid_attestation_value(&signing_key, &backup.sha256_hex(), &inventory.sha256_hex()),
        ))
        .unwrap();
        let trusted = FixedTrust {
            mode: TrustMode::Trusted,
            key: pinned,
        };
        assert!(verify_backup_provenance_v1(&attestation, &backup, &inventory, &trusted).is_ok());

        for mode in [
            TrustMode::Unknown,
            TrustMode::Revoked,
            TrustMode::Unavailable,
        ] {
            let trust = FixedTrust { mode, key: pinned };
            assert_eq!(
                verify_backup_provenance_v1(&attestation, &backup, &inventory, &trust),
                Err(ManifestCodecErrorV1::ProvenanceInvalid)
            );
        }

        let wrong_signing_key = SigningKey::from_bytes(&[0x6B; 32]);
        let wrong_verifying_key = wrong_signing_key.verifying_key().to_bytes();
        let wrong_pin: [u8; 32] = Sha256::digest(wrong_verifying_key).into();
        let wrong_trust = FixedTrust {
            mode: TrustMode::Trusted,
            key: PinnedEd25519KeyV1::try_new(wrong_verifying_key, wrong_pin).unwrap(),
        };
        assert_eq!(
            verify_backup_provenance_v1(&attestation, &backup, &inventory, &wrong_trust),
            Err(ManifestCodecErrorV1::ProvenanceInvalid)
        );
    }

    #[test]
    fn restore_package_acceptance_requires_exact_canonical_signed_members() {
        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let trust = fixed_trust(&signing_key, TrustMode::Trusted);
        let (attestation, top_level, inventory) = valid_restore_package_bytes(&signing_key);

        let verified =
            verify_restore_package_manifests_v1(&attestation, &top_level, &inventory, &trust)
                .expect("the exact canonical signed package verifies");
        assert_eq!(
            verified.attestation_sha256(),
            Sha256Digest::digest(&attestation)
        );
        assert_eq!(
            verified.top_level_manifest_sha256(),
            Sha256Digest::digest(&top_level)
        );
        assert_eq!(
            verified.inventory_sha256(),
            Sha256Digest::digest(&inventory)
        );
    }

    #[test]
    fn restore_package_acceptance_rejects_currently_revoked_trust() {
        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let revoked = fixed_trust(&signing_key, TrustMode::Revoked);
        let (attestation, top_level, inventory) = valid_restore_package_bytes(&signing_key);

        assert_eq!(
            verify_restore_package_manifests_v1(&attestation, &top_level, &inventory, &revoked,),
            Err(ManifestCodecErrorV1::ProvenanceInvalid)
        );
    }

    #[test]
    fn restore_package_acceptance_rejects_canonical_top_level_substitution() {
        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let trust = fixed_trust(&signing_key, TrustMode::Trusted);
        let (attestation, top_level, inventory) = valid_restore_package_bytes(&signing_key);
        let mut substituted: Value = serde_json::from_slice(&top_level).unwrap();
        substituted["coordinator_database_sha256"] = Value::String(digest_hex(0x99));
        let substituted = canonical(&substituted);

        assert_eq!(
            verify_restore_package_manifests_v1(&attestation, &substituted, &inventory, &trust,),
            Err(ManifestCodecErrorV1::ProvenanceInvalid)
        );
    }

    #[test]
    fn restore_package_projection_is_typed_ordered_and_redacted() {
        let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
        let trust = fixed_trust(&signing_key, TrustMode::Trusted);
        let (attestation, top_level, inventory) = valid_restore_package_bytes(&signing_key);
        let verified =
            verify_restore_package_manifests_v1(&attestation, &top_level, &inventory, &trust)
                .unwrap();

        assert_eq!(
            verified.source_coordinator_root_identity_sha256(),
            typed_digest(0x01)
        );
        assert_eq!(
            verified.source_recovery_root_identity_sha256(),
            typed_digest(0x02)
        );
        assert_eq!(
            verified.source_instance_identity_sha256(),
            typed_digest(0x03)
        );
        assert_eq!(verified.coordinator_schema_sha256(), typed_digest(0x04));
        assert_eq!(verified.coordinator_database_sha256(), typed_digest(0x05));
        assert_eq!(verified.at_rest_profile_id().as_str(), "a");
        assert_eq!(
            verified.attestation_profile_id().as_str(),
            ATTESTATION_PROFILE_ID
        );
        assert_eq!(verified.attestation_profile_version(), 1);
        assert_eq!(verified.key_id().as_str(), KEY_ID);

        let generations = verified.generations();
        assert_eq!(
            [
                generations.store(),
                generations.operation(),
                generations.budget(),
                generations.event(),
                generations.quarantine(),
            ],
            [1, 2, 3, 4, 5]
        );
        let counts = verified.counts();
        assert_eq!(counts.budget_scopes(), 1);
        assert_eq!(counts.operations(), 1);
        assert_eq!(counts.operation_transitions(), 1);
        assert_eq!(counts.held_reservations(), 1);
        assert_eq!(counts.released_reservations(), 0);
        assert_eq!(counts.pending_events(), 1);
        assert_eq!(counts.delivered_events(), 0);
        assert_eq!(counts.active_quarantines(), 0);
        assert_eq!(counts.resolved_quarantines(), 0);
        assert_eq!(counts.operation_retirement_pending(), 0);
        assert_eq!(counts.orphan_retirement_pending(), 0);

        let lifecycle = verified.lifecycle();
        assert!(matches!(
            lifecycle.source_root_lifecycle(),
            RestorePackageRootLifecycleV1::Active
        ));
        assert!(matches!(
            lifecycle.required_restore_root_lifecycle(),
            RestorePackageRootLifecycleV1::RestorePending
        ));
        assert!(lifecycle.requires_paused_restore());
        assert!(lifecycle.requires_boot_epoch_rotation());
        assert!(lifecycle.requires_instance_epoch_rotation());
        assert!(lifecycle.requires_fencing_epoch_rotation());
        assert!(lifecycle.nonterminal_preparations_not_reactivatable());
        assert!(lifecycle.may_omit_work_after_generation());
        assert!(lifecycle.complete_reference_set());
        assert!(lifecycle.no_retirement_pending());
        assert!(lifecycle.all_required_entries_verified());

        assert_eq!(verified.provider_set_count(), 1);
        assert_eq!(verified.entry_count(), 1);
        let providers = verified.provider_sets();
        assert_eq!(providers.len(), 1);
        let provider = &providers[0];
        assert_eq!(provider.provider_profile_id().as_str(), "p");
        assert_eq!(provider.provider_profile_version(), 1);
        assert_eq!(provider.provider_id().as_str(), "r");
        assert_eq!(provider.provider_generation(), 1);
        assert_eq!(provider.evidence_class().as_str(), "SYNTHETIC_CONFORMANCE");
        assert_eq!(provider.at_rest_profile_id().as_str(), "a");
        assert_eq!(provider.entry_count(), 1);
        let entry = &provider.entries()[0];
        assert_eq!(
            entry.package_binding_sha256(),
            Sha256Digest::parse_hex(
                "85e7d004e1847040a09dcd23c04ce08e6c823adaf6661e38cfde4a7fd0e58e10"
            )
            .unwrap()
        );
        assert_eq!(entry.manifest_sha256(), typed_digest(0x11));
        assert_eq!(entry.material_sha256(), typed_digest(0x22));
        assert_eq!(entry.material_length(), 3);
        assert_eq!(entry.reserved_capacity(), 3);
        assert!(matches!(entry.custody(), RecoveryCustodyV1::OperationBound));
        assert!(matches!(
            entry.state(),
            RecoverySnapshotStateV1::MaterialPresent
        ));
        assert!(entry.retirement_manifest_sha256().is_none());

        let debug = format!("{verified:?}");
        assert!(debug.contains("VerifiedRestorePackageBindingsV1"));
        assert!(!debug.contains(ATTESTATION_PROFILE_ID));
        assert!(!debug.contains(&digest_hex(0x01)));
    }

    #[test]
    fn recovery_root_pending_projection_rejects_active_and_projects_exact_bindings() {
        let pending_bytes = canonical(&json!({
            "schema": "helixos.recovery-root-metadata/1",
            "root_identity_sha256": digest_hex(0x41),
            "root_lifecycle_state": "RESTORE_PENDING",
            "state_generation": 7,
            "at_rest_profile_id": "at-rest.synthetic-v1",
            "restore_identity_sha256": digest_hex(0x42),
            "provenance_attestation_sha256": digest_hex(0x43),
            "source_inventory_sha256": digest_hex(0x44)
        }));
        let pending = verify_recovery_root_pending_bindings_v1(&pending_bytes).unwrap();
        assert_eq!(
            pending.metadata_sha256(),
            Sha256Digest::digest(&pending_bytes)
        );
        assert_eq!(pending.root_identity_sha256(), typed_digest(0x41));
        assert_eq!(pending.state_generation(), 7);
        assert_eq!(
            pending.at_rest_profile_id().as_str(),
            "at-rest.synthetic-v1"
        );
        assert_eq!(pending.restore_identity_sha256(), typed_digest(0x42));
        assert_eq!(pending.provenance_attestation_sha256(), typed_digest(0x43));
        assert_eq!(pending.source_inventory_sha256(), typed_digest(0x44));
        let debug = format!("{pending:?}");
        assert!(!debug.contains("at-rest.synthetic-v1"));
        assert!(!debug.contains(&digest_hex(0x41)));

        assert_eq!(
            verify_recovery_root_pending_bindings_v1(&canonical(&valid_recovery_root_value())),
            Err(ManifestCodecErrorV1::JsonContractInvalid)
        );
    }
}
