#![forbid(unsafe_code)]
use std::path::Path;
use crate::intention::Intention;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RiskLevel { L0, L1, L2 }

const SECRET_GLOBS: &[&str] = &[".env", ".key", ".pem", ".kdbx"];
const SECRET_DIRS: &[&str] = &[".ssh", ".hermes"];

/// NTFS est insensible à la casse : `.ENV`, `ID_RSA`, `deploy.KEY`, `.SSH/config` doivent être
/// traités comme leurs équivalents minuscules, sous peine de faux négatifs sur le deny-list de
/// secrets. On compare donc systématiquement en minuscules (nom de fichier ET chaque composant
/// de chemin), sans jamais modifier `SECRET_GLOBS`/`SECRET_DIRS` eux-mêmes (déjà en minuscules).
pub fn is_secret(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
    if name.starts_with("id_") { return true; }
    if SECRET_GLOBS.iter().any(|g| name.ends_with(g)) { return true; }
    path.components().any(|c| {
        let comp = c.as_os_str().to_str().unwrap_or("").to_ascii_lowercase();
        SECRET_DIRS.contains(&comp.as_str())
    })
}

fn base(intention: &Intention) -> RiskLevel {
    match intention {
        Intention::SearchFiles { .. } => RiskLevel::L0,
        Intention::ReadFile { path } => if is_secret(path) { RiskLevel::L2 } else { RiskLevel::L0 },
        Intention::ProposeFilePatch { .. } => RiskLevel::L1,
        Intention::ApplyFilePatch { .. } => RiskLevel::L1,
    }
}

/// Taint : +1 cran (L0→L1, L1→L2, L2 reste L2), jamais de descente.
pub fn classify(intention: &Intention, tainted: bool) -> RiskLevel {
    let b = base(intention);
    if !tainted { return b; }
    match b { RiskLevel::L0 => RiskLevel::L1, _ => RiskLevel::L2 }
}

#[cfg(test)]
mod tests {
    use super::*; use crate::intention::Intention; use std::path::PathBuf;
    #[test] fn read_of_secret_forces_l2() {                        // test 19
        let i = Intention::ReadFile { path: PathBuf::from("C:/vault/.env") };
        assert_eq!(classify(&i, false), RiskLevel::L2);
    }
    #[test] fn plain_read_is_l0() {
        let i = Intention::ReadFile { path: PathBuf::from("C:/vault/note.md") };
        assert_eq!(classify(&i, false), RiskLevel::L0);
    }
    #[test] fn tainted_read_escalates_one_notch() {
        let i = Intention::ReadFile { path: PathBuf::from("C:/vault/note.md") };
        assert_eq!(classify(&i, true), RiskLevel::L1);
    }
    #[test] fn apply_patch_is_l1() {
        let i = Intention::ApplyFilePatch { plan_id: "p".into() };
        assert_eq!(classify(&i, false), RiskLevel::L1);
    }
    #[test] fn is_secret_is_case_insensitive_for_globs_and_prefix() {
        assert!(is_secret(&PathBuf::from("C:/vault/.ENV")), ".ENV doit être détecté comme secret (NTFS insensible à la casse)");
        assert!(is_secret(&PathBuf::from("C:/vault/ID_RSA")), "ID_RSA doit être détecté comme secret");
        assert!(is_secret(&PathBuf::from("C:/vault/deploy.KEY")), "deploy.KEY doit être détecté comme secret");
    }
    #[test] fn is_secret_is_case_insensitive_for_dir_components() {
        assert!(is_secret(&PathBuf::from("C:/Users/elidr/.SSH/config")), "un chemin traversant .SSH/ doit être détecté comme secret");
    }
}
