//! Closed canonical backup-manifest codec for the adapter inbox.
//!
//! This module owns public verification metadata only. It never accepts, stores, or
//! returns signing-key custody.

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;

const ADAPTER_APPLICATION_ID_V1: u64 = 1_212_962_889;
const ADAPTER_USER_VERSION_V1: u64 = 1;
const ADAPTER_FORMAT_VERSION_V1: u64 = 1;
const ADAPTER_BACKUP_COMPONENT_V1: &str = "adapter-inbox-v1";
const MAX_SAFE_U64_V1: u64 = 9_007_199_254_740_991;
const MAX_ADAPTER_MANIFEST_BYTES_V1: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdapterManifestCodecErrorV1 {
    JsonContractInvalid,
}

impl AdapterManifestCodecErrorV1 {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::JsonContractInvalid => "JSON_CONTRACT_INVALID",
        }
    }
}

impl fmt::Display for AdapterManifestCodecErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterManifestCodecErrorV1 {}

pub(crate) struct DecodedAdapterInboxBackupManifestV1 {
    value: AdapterInboxBackupManifestV1,
    sha256: [u8; 32],
}

impl DecodedAdapterInboxBackupManifestV1 {
    pub(crate) const fn value(&self) -> &AdapterInboxBackupManifestV1 {
        &self.value
    }

    pub(crate) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(crate) fn sha256_hex(&self) -> String {
        encode_sha256(self.sha256)
    }

    pub(crate) fn into_value(self) -> AdapterInboxBackupManifestV1 {
        self.value
    }
}

impl fmt::Debug for DecodedAdapterInboxBackupManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedAdapterInboxBackupManifestV1")
            .finish_non_exhaustive()
    }
}

pub(crate) struct FinalizedAdapterInboxBackupManifestV1 {
    value: AdapterInboxBackupManifestV1,
    body_bytes: Vec<u8>,
    manifest_digest: [u8; 32],
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl FinalizedAdapterInboxBackupManifestV1 {
    pub(crate) const fn value(&self) -> &AdapterInboxBackupManifestV1 {
        &self.value
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Exact standalone JCS body bytes that T076 must publish. The package's
    /// `manifest_digest` is SHA-256 of these bytes, not a caller-provided value and not
    /// a self-referential hash of the package that contains the digest.
    pub(crate) fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    pub(crate) const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub(crate) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(crate) fn sha256_hex(&self) -> String {
        encode_sha256(self.sha256)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        AdapterInboxBackupManifestV1,
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

impl fmt::Debug for FinalizedAdapterInboxBackupManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedAdapterInboxBackupManifestV1")
            .finish_non_exhaustive()
    }
}

trait ValidateAdapterManifestV1 {
    fn validate(&self) -> Result<(), AdapterManifestCodecErrorV1>;
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

fn decode_canonical_json_v1<T>(bytes: &[u8]) -> Result<(T, [u8; 32]), AdapterManifestCodecErrorV1>
where
    T: DeserializeOwned + ValidateAdapterManifestV1,
{
    if bytes.is_empty()
        || bytes.len() > MAX_ADAPTER_MANIFEST_BYTES_V1
        || bytes.starts_with(&[0xEF, 0xBB, 0xBF])
    {
        return json_invalid();
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let raw = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| AdapterManifestCodecErrorV1::JsonContractInvalid)?;
    deserializer
        .end()
        .map_err(|_| AdapterManifestCodecErrorV1::JsonContractInvalid)?;
    let canonical = serde_json_canonicalizer::to_vec(&raw.0)
        .map_err(|_| AdapterManifestCodecErrorV1::JsonContractInvalid)?;
    if canonical != bytes {
        return json_invalid();
    }
    let value: T = serde_json::from_value(raw.0)
        .map_err(|_| AdapterManifestCodecErrorV1::JsonContractInvalid)?;
    value.validate()?;
    Ok((value, Sha256::digest(bytes).into()))
}

fn finalize_canonical_json_v1<T>(
    value: &T,
) -> Result<(Vec<u8>, [u8; 32]), AdapterManifestCodecErrorV1>
where
    T: Serialize + ValidateAdapterManifestV1,
{
    value.validate()?;
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|_| AdapterManifestCodecErrorV1::JsonContractInvalid)?;
    let sha256 = Sha256::digest(&bytes).into();
    Ok((bytes, sha256))
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

/// Published independently from the package. Its exact JCS bytes are the preimage for
/// `AdapterInboxBackupManifestV1::manifest_digest`.
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

impl fmt::Debug for AdapterInboxBackupManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdapterInboxBackupManifestV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BackupRootLifecycleStateV1 {
    Active,
    RestorePending,
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdapterGenerationsInputV1 {
    pub(crate) store: u64,
    pub(crate) inbox: u64,
    pub(crate) consumption: u64,
    pub(crate) receipt: u64,
    pub(crate) conflict: u64,
    pub(crate) quarantine: u64,
    pub(crate) event: u64,
    pub(crate) epoch_observer: u64,
    pub(crate) restore_state: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdapterCountsInputV1 {
    pub(crate) inbox_entries: u64,
    pub(crate) transitions: u64,
    pub(crate) receipts: u64,
    pub(crate) conflicts: u64,
    pub(crate) quarantines: u64,
    pub(crate) events: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdapterInventoriesInputV1 {
    pub(crate) inbox_entries: [u8; 32],
    pub(crate) transitions: [u8; 32],
    pub(crate) receipts: [u8; 32],
    pub(crate) conflicts: [u8; 32],
    pub(crate) quarantines: [u8; 32],
    pub(crate) events: [u8; 32],
    pub(crate) complete_store: [u8; 32],
}

pub(crate) struct AdapterInboxBackupManifestInputV1 {
    pub(crate) root_identity_digest: [u8; 32],
    pub(crate) schema_digest: [u8; 32],
    pub(crate) database_digest: [u8; 32],
    pub(crate) root_lifecycle_state: BackupRootLifecycleStateV1,
    pub(crate) supervisor_epoch: u64,
    pub(crate) generations: AdapterGenerationsInputV1,
    pub(crate) counts: AdapterCountsInputV1,
    pub(crate) inventory_digests: AdapterInventoriesInputV1,
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
    AdapterGenerationsInputV1,
    AdapterCountsInputV1,
    AdapterInventoriesInputV1,
    AdapterInboxBackupManifestInputV1,
);

pub(crate) fn decode_adapter_inbox_backup_manifest_v1(
    bytes: &[u8],
) -> Result<DecodedAdapterInboxBackupManifestV1, AdapterManifestCodecErrorV1> {
    let (value, sha256) = decode_canonical_json_v1(bytes)?;
    Ok(DecodedAdapterInboxBackupManifestV1 { value, sha256 })
}

pub(crate) fn finalize_adapter_inbox_backup_manifest_v1(
    input: AdapterInboxBackupManifestInputV1,
) -> Result<FinalizedAdapterInboxBackupManifestV1, AdapterManifestCodecErrorV1> {
    let body = AdapterInboxBackupManifestBodyV1 {
        root_identity_digest: encode_sha256(input.root_identity_digest),
        application_id: ADAPTER_APPLICATION_ID_V1,
        user_version: ADAPTER_USER_VERSION_V1,
        format_version: ADAPTER_FORMAT_VERSION_V1,
        schema_digest: encode_sha256(input.schema_digest),
        database_digest: encode_sha256(input.database_digest),
        root_lifecycle_state: input.root_lifecycle_state,
        supervisor_epoch: input.supervisor_epoch,
        generations: AdapterGenerationsV1 {
            store: input.generations.store,
            inbox: input.generations.inbox,
            consumption: input.generations.consumption,
            receipt: input.generations.receipt,
            conflict: input.generations.conflict,
            quarantine: input.generations.quarantine,
            event: input.generations.event,
            epoch_observer: input.generations.epoch_observer,
            restore_state: input.generations.restore_state,
        },
        counts: AdapterCountsV1 {
            inbox_entries: input.counts.inbox_entries,
            transitions: input.counts.transitions,
            receipts: input.counts.receipts,
            conflicts: input.counts.conflicts,
            quarantines: input.counts.quarantines,
            events: input.counts.events,
        },
        inventory_digests: AdapterInventoriesV1 {
            inbox_entries: encode_sha256(input.inventory_digests.inbox_entries),
            transitions: encode_sha256(input.inventory_digests.transitions),
            receipts: encode_sha256(input.inventory_digests.receipts),
            conflicts: encode_sha256(input.inventory_digests.conflicts),
            quarantines: encode_sha256(input.inventory_digests.quarantines),
            events: encode_sha256(input.inventory_digests.events),
            complete_store: encode_sha256(input.inventory_digests.complete_store),
        },
    };
    body.validate()?;
    let body_bytes = serde_json_canonicalizer::to_vec(&body)
        .map_err(|_| AdapterManifestCodecErrorV1::JsonContractInvalid)?;
    let manifest_digest: [u8; 32] = Sha256::digest(&body_bytes).into();
    let value = AdapterInboxBackupManifestV1::from_body(body, manifest_digest);
    let (bytes, sha256) = finalize_canonical_json_v1(&value)?;
    Ok(FinalizedAdapterInboxBackupManifestV1 {
        value,
        body_bytes,
        manifest_digest,
        bytes,
        sha256,
    })
}

impl AdapterInboxBackupManifestV1 {
    fn from_body(body: AdapterInboxBackupManifestBodyV1, manifest_digest: [u8; 32]) -> Self {
        Self {
            root_identity_digest: body.root_identity_digest,
            application_id: body.application_id,
            user_version: body.user_version,
            format_version: body.format_version,
            schema_digest: body.schema_digest,
            database_digest: body.database_digest,
            manifest_digest: encode_sha256(manifest_digest),
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

impl ValidateAdapterManifestV1 for AdapterInboxBackupManifestV1 {
    fn validate(&self) -> Result<(), AdapterManifestCodecErrorV1> {
        let body = self.body();
        body.validate()?;
        let body_bytes = serde_json_canonicalizer::to_vec(&body)
            .map_err(|_| AdapterManifestCodecErrorV1::JsonContractInvalid)?;
        let expected: [u8; 32] = Sha256::digest(body_bytes).into();
        if self.manifest_digest != encode_sha256(expected) {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateAdapterManifestV1 for AdapterInboxBackupManifestBodyV1 {
    fn validate(&self) -> Result<(), AdapterManifestCodecErrorV1> {
        if self.application_id != ADAPTER_APPLICATION_ID_V1
            || self.user_version != ADAPTER_USER_VERSION_V1
            || self.format_version != ADAPTER_FORMAT_VERSION_V1
            || !is_lower_sha256(&self.root_identity_digest)
            || !is_lower_sha256(&self.schema_digest)
            || !is_lower_sha256(&self.database_digest)
            || self.supervisor_epoch > MAX_SAFE_U64_V1
        {
            return json_invalid();
        }
        self.generations.validate()?;
        self.counts.validate()?;
        self.inventory_digests.validate()
    }
}

impl ValidateAdapterManifestV1 for AdapterGenerationsV1 {
    fn validate(&self) -> Result<(), AdapterManifestCodecErrorV1> {
        if [
            self.store,
            self.inbox,
            self.consumption,
            self.receipt,
            self.conflict,
            self.quarantine,
            self.event,
            self.restore_state,
        ]
        .into_iter()
        .any(|value| value > MAX_SAFE_U64_V1)
            || !(1..=MAX_SAFE_U64_V1).contains(&self.epoch_observer)
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateAdapterManifestV1 for AdapterCountsV1 {
    fn validate(&self) -> Result<(), AdapterManifestCodecErrorV1> {
        if [
            self.inbox_entries,
            self.transitions,
            self.receipts,
            self.conflicts,
            self.quarantines,
            self.events,
        ]
        .into_iter()
        .any(|value| value > MAX_SAFE_U64_V1)
        {
            return json_invalid();
        }
        Ok(())
    }
}

impl ValidateAdapterManifestV1 for AdapterInventoriesV1 {
    fn validate(&self) -> Result<(), AdapterManifestCodecErrorV1> {
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

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
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

fn json_invalid<T>() -> Result<T, AdapterManifestCodecErrorV1> {
    Err(AdapterManifestCodecErrorV1::JsonContractInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn input() -> AdapterInboxBackupManifestInputV1 {
        AdapterInboxBackupManifestInputV1 {
            root_identity_digest: digest(1),
            schema_digest: digest(2),
            database_digest: digest(3),
            root_lifecycle_state: BackupRootLifecycleStateV1::Active,
            supervisor_epoch: 9,
            generations: AdapterGenerationsInputV1 {
                store: 10,
                inbox: 11,
                consumption: 12,
                receipt: 13,
                conflict: 14,
                quarantine: 15,
                event: 16,
                epoch_observer: 9,
                restore_state: 17,
            },
            counts: AdapterCountsInputV1 {
                inbox_entries: 2,
                transitions: 3,
                receipts: 1,
                conflicts: 0,
                quarantines: 0,
                events: 4,
            },
            inventory_digests: AdapterInventoriesInputV1 {
                inbox_entries: digest(5),
                transitions: digest(6),
                receipts: digest(7),
                conflicts: digest(8),
                quarantines: digest(9),
                events: digest(10),
                complete_store: digest(11),
            },
        }
    }

    #[test]
    fn adapter_manifest_round_trips_exact_canonical_bytes_and_digest() {
        let finalized = finalize_adapter_inbox_backup_manifest_v1(input()).unwrap();
        assert_eq!(
            finalized.bytes(),
            serde_json_canonicalizer::to_vec(finalized.value()).unwrap()
        );
        let decoded = decode_adapter_inbox_backup_manifest_v1(finalized.bytes()).unwrap();
        assert_eq!(decoded.sha256(), finalized.sha256());
        assert_eq!(decoded.value(), finalized.value());
        let expected_manifest_digest: [u8; 32] = Sha256::digest(finalized.body_bytes()).into();
        assert_eq!(finalized.manifest_digest(), expected_manifest_digest);
        assert_ne!(finalized.manifest_digest(), finalized.sha256());
    }

    #[test]
    fn adapter_decoder_rejects_duplicate_unknown_noncanonical_and_tampered_input() {
        let finalized = finalize_adapter_inbox_backup_manifest_v1(input()).unwrap();
        let canonical = std::str::from_utf8(finalized.bytes()).unwrap();
        let duplicate = format!("{{\"application_id\":1212962889,{}", &canonical[1..]);

        let mut unknown: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        unknown.as_object_mut().unwrap().insert(
            "private_key".to_owned(),
            Value::String("forbidden".to_owned()),
        );

        let mut tampered: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        tampered["application_id"] = Value::from(1_212_962_883_u64);

        let mut zero_epoch: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        zero_epoch["generations"]["epoch_observer"] = Value::from(0_u64);

        let mut body_tamper: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        body_tamper["counts"]["receipts"] = Value::from(2_u64);

        let mut arbitrary_binding: Value = serde_json::from_slice(finalized.bytes()).unwrap();
        arbitrary_binding["manifest_digest"] = Value::String(encode_sha256(digest(4)));

        let mut newline = finalized.bytes().to_vec();
        newline.push(b'\n');
        for invalid in [
            duplicate.into_bytes(),
            serde_json_canonicalizer::to_vec(&unknown).unwrap(),
            serde_json_canonicalizer::to_vec(&tampered).unwrap(),
            serde_json_canonicalizer::to_vec(&zero_epoch).unwrap(),
            serde_json_canonicalizer::to_vec(&body_tamper).unwrap(),
            serde_json_canonicalizer::to_vec(&arbitrary_binding).unwrap(),
            newline,
        ] {
            assert_eq!(
                decode_adapter_inbox_backup_manifest_v1(&invalid).unwrap_err(),
                AdapterManifestCodecErrorV1::JsonContractInvalid
            );
        }
    }

    #[test]
    fn adapter_decoder_rejects_oversized_input_before_json_parsing() {
        let oversized = vec![b' '; MAX_ADAPTER_MANIFEST_BYTES_V1 + 1];
        assert_eq!(
            decode_adapter_inbox_backup_manifest_v1(&oversized).unwrap_err(),
            AdapterManifestCodecErrorV1::JsonContractInvalid
        );
    }
}
