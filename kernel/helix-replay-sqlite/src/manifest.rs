use crate::error::{InternalStoreError, ReplayStoreMaintenanceErrorV1};
use crate::schema::{REPLAY_STORE_APPLICATION_ID_V1, REPLAY_STORE_SCHEMA_VERSION_V1};
use helix_contracts::MAX_SAFE_U64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

pub const BACKUP_MANIFEST_SCHEMA_V1: &str = "helixos.replay-store-backup/1";
pub const BACKUP_MANIFEST_V1_JSON_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/003-durable-replay-store/contracts/backup-manifest-v1.schema.json"
));

const MAX_MANIFEST_BYTES: usize = 4096;

/// Strict, non-secret consistency evidence for one completed SQLite online backup.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupManifestV1 {
    schema: String,
    application_id: i64,
    store_schema_version: i64,
    claimant_generation: u64,
    claim_count: u64,
    database_sha256: String,
    sqlite_version: String,
    sqlite_source_id: String,
    integrity_check: String,
    requires_paused_activation: bool,
    requires_instance_epoch_rotation: bool,
    requires_fencing_epoch_rotation: bool,
    may_omit_claims_after_generation: bool,
}

impl BackupManifestV1 {
    pub(crate) fn from_verified_snapshot(
        claimant_generation: u64,
        claim_count: u64,
        database_sha256: String,
        sqlite_version: String,
        sqlite_source_id: String,
    ) -> Result<Self, ReplayStoreMaintenanceErrorV1> {
        let manifest = Self {
            schema: BACKUP_MANIFEST_SCHEMA_V1.to_owned(),
            application_id: REPLAY_STORE_APPLICATION_ID_V1,
            store_schema_version: REPLAY_STORE_SCHEMA_VERSION_V1,
            claimant_generation,
            claim_count,
            database_sha256,
            sqlite_version,
            sqlite_source_id,
            integrity_check: "ok".to_owned(),
            requires_paused_activation: true,
            requires_instance_epoch_rotation: true,
            requires_fencing_epoch_rotation: true,
            may_omit_claims_after_generation: true,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn decode_v1(bytes: &[u8]) -> Result<Self, ReplayStoreMaintenanceErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ReplayStoreMaintenanceErrorV1::ManifestInvalid);
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|_| ReplayStoreMaintenanceErrorV1::ManifestInvalid)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn encode_v1(&self) -> Result<Vec<u8>, ReplayStoreMaintenanceErrorV1> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| ReplayStoreMaintenanceErrorV1::ManifestInvalid)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ReplayStoreMaintenanceErrorV1::ManifestInvalid);
        }
        Ok(bytes)
    }

    pub const fn claimant_generation(&self) -> u64 {
        self.claimant_generation
    }

    pub const fn claim_count(&self) -> u64 {
        self.claim_count
    }

    pub fn database_sha256(&self) -> &str {
        &self.database_sha256
    }

    pub fn sqlite_version(&self) -> &str {
        &self.sqlite_version
    }

    pub fn sqlite_source_id(&self) -> &str {
        &self.sqlite_source_id
    }

    pub const fn requires_paused_activation(&self) -> bool {
        self.requires_paused_activation
    }

    pub const fn requires_instance_epoch_rotation(&self) -> bool {
        self.requires_instance_epoch_rotation
    }

    pub const fn requires_fencing_epoch_rotation(&self) -> bool {
        self.requires_fencing_epoch_rotation
    }

    pub const fn may_omit_claims_after_generation(&self) -> bool {
        self.may_omit_claims_after_generation
    }

    fn validate(&self) -> Result<(), ReplayStoreMaintenanceErrorV1> {
        if self.schema != BACKUP_MANIFEST_SCHEMA_V1
            || self.application_id != REPLAY_STORE_APPLICATION_ID_V1
            || self.store_schema_version != REPLAY_STORE_SCHEMA_VERSION_V1
            || self.claimant_generation > MAX_SAFE_U64
            || self.claim_count > MAX_SAFE_U64
            || self.claim_count != self.claimant_generation
            || !is_lower_sha256(&self.database_sha256)
            || !is_three_part_numeric_version(&self.sqlite_version)
            || !(40..=160).contains(&self.sqlite_source_id.len())
            || !self
                .sqlite_source_id
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
            || self.integrity_check != "ok"
            || !self.requires_paused_activation
            || !self.requires_instance_epoch_rotation
            || !self.requires_fencing_epoch_rotation
            || !self.may_omit_claims_after_generation
        {
            return Err(ReplayStoreMaintenanceErrorV1::ManifestInvalid);
        }
        Ok(())
    }
}

impl fmt::Debug for BackupManifestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupManifestV1")
            .finish_non_exhaustive()
    }
}

pub fn embedded_backup_manifest_schema_v1_sha256() -> [u8; 32] {
    Sha256::digest(BACKUP_MANIFEST_V1_JSON_SCHEMA.as_bytes()).into()
}

pub(crate) fn read_manifest_v1_file(path: &Path) -> Result<BackupManifestV1, InternalStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(InternalStoreError::ManifestMissing)
        }
        Err(_) => return Err(InternalStoreError::ManifestInvalid),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES as u64
    {
        return Err(InternalStoreError::ManifestInvalid);
    }
    let bytes = fs::read(path).map_err(|_| InternalStoreError::ManifestInvalid)?;
    BackupManifestV1::decode_v1(&bytes).map_err(|_| InternalStoreError::ManifestInvalid)
}

pub(crate) fn sha256_file_hex(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(encoded)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_three_part_numeric_version(value: &str) -> bool {
    let mut parts = value.split('.');
    (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none()
        && (5..=32).contains(&value.len())
}
