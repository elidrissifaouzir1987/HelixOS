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
        if let Err(e) = std::fs::rename(&tmp, target) {
            // Le rename a échoué après l'écriture : nettoie le `.tmp` pour ne pas fuir un
            // fichier orphelin dans le répertoire cible avant de propager l'erreur.
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(RollbackHandle { id, staged_original: staged, target: target.to_path_buf() })
    }
    fn rollback(&self, h: &RollbackHandle) -> Result<(), DriverError> {
        let tmp = h.target.with_extension("helix.rb.tmp");
        std::fs::copy(&h.staged_original, &tmp)?;
        if let Err(e) = std::fs::rename(&tmp, &h.target) {
            // Même nettoyage que dans `stage_and_apply` : le rename a échoué après la copie,
            // on ne laisse pas de `.rb.tmp` orphelin derrière nous.
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
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

    /// Anti-fuite : si `rename(tmp, target)` échoue après que `tmp` a été écrit, le `.tmp` ne
    /// doit pas rester orphelin dans le répertoire cible. On force l'échec du rename SEUL (pas
    /// de l'étape 1) en gardant `target` ouvert avec `FILE_SHARE_READ` uniquement : la lecture
    /// partagée de `fs::copy` (étape 1, copie-aside) réussit toujours, mais Windows refuse de
    /// renommer un autre fichier par-dessus une cible qui n'autorise pas le partage en écriture
    /// (ERROR_SHARING_VIOLATION, os error 5) — isolant précisément le chemin d'erreur du rename
    /// après une écriture réussie du `.tmp`, exactement le scénario visé par le correctif.
    /// (Vérifié : avec `share_mode(0)` — verrou total — `fs::copy` lui-même échouerait déjà à
    /// l'étape 1, avant toute création de `.tmp`, ce qui rendrait le test trivialement vrai
    /// sans exercer le nettoyage ajouté par le correctif.)
    #[test]
    fn stage_and_apply_cleans_up_tmp_file_when_rename_fails() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        let dir = std::env::temp_dir().join(format!("helix-fd-leak-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("note.md");
        std::fs::write(&target, b"ORIGINAL").unwrap();
        let d = FileDriver::new(dir.join(".staging"));

        let _lock = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(&target).unwrap();

        let result = d.stage_and_apply(&target, b"PATCHED");
        assert!(result.is_err(), "rename vers une cible verrouillée en écriture doit échouer");

        let tmp = target.with_extension("helix.tmp");
        assert!(!tmp.exists(), "le fichier .tmp ne doit pas fuir après un rename en échec");
    }
}
