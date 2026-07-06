#![forbid(unsafe_code)]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RollbackHandle { pub id: String, pub staged_original: PathBuf, pub target: PathBuf }

pub trait DriverHost {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, DriverError>;
    fn search_files(&self, query: &str, roots: &[PathBuf]) -> Result<Vec<PathBuf>, DriverError>;
    /// Copie-aside (compensation) puis remplace atomiquement le contenu cible.
    fn stage_and_apply(&self, target: &Path, new_content: &[u8]) -> Result<RollbackHandle, DriverError>;
    fn rollback(&self, handle: &RollbackHandle) -> Result<(), DriverError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("not found: {0}")] NotFound(String),
}
