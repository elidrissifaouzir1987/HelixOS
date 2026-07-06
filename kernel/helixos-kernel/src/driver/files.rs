#![forbid(unsafe_code)]
use std::path::{Path, PathBuf};
use crate::driver::{DriverHost, DriverError, RollbackHandle};

pub struct FileDriver { staging: PathBuf }
impl FileDriver { pub fn new(staging: PathBuf) -> Self { Self { staging } } }

impl DriverHost for FileDriver {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, DriverError> {
        Ok(std::fs::read(path)?)
    }
    fn search_files(&self, query: &str, roots: &[PathBuf]) -> Result<Vec<PathBuf>, DriverError> {
        crate::driver::search::walk_by_name(query, roots)
    }
    fn stage_and_apply(&self, target: &Path, new_content: &[u8]) -> Result<RollbackHandle, DriverError> {
        // 1. Copie-aside de l'original (compensation garantie).
        std::fs::create_dir_all(&self.staging)?;
        let id = uuid::Uuid::new_v4().to_string();
        let staged = self.staging.join(format!("{id}.orig"));
        std::fs::copy(target, &staged)?;
        // 2. Écrire le nouveau contenu dans un temp puis rename atomique (remplace l'existant sous Windows).
        let tmp = target.with_extension("helix.tmp");
        std::fs::write(&tmp, new_content)?;
        std::fs::rename(&tmp, target)?;   // MoveFileEx(REPLACE_EXISTING) — atomique même volume
        Ok(RollbackHandle { id, staged_original: staged, target: target.to_path_buf() })
    }
    fn rollback(&self, h: &RollbackHandle) -> Result<(), DriverError> {
        let tmp = h.target.with_extension("helix.rb.tmp");
        std::fs::copy(&h.staged_original, &tmp)?;
        std::fs::rename(&tmp, &h.target)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*; use crate::driver::DriverHost;
    #[test] fn apply_then_rollback_restores_original() {
        let dir = std::env::temp_dir().join(format!("helix-fd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("note.md");
        std::fs::write(&target, b"ORIGINAL").unwrap();
        let d = FileDriver::new(dir.clone());
        let h = d.stage_and_apply(&target, b"PATCHED").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"PATCHED");
        d.rollback(&h).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL");
    }
}
