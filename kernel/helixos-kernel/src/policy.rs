#![forbid(unsafe_code)]
use std::path::Path;
use crate::intention::Intention;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RiskLevel { L0, L1, L2 }

const SECRET_GLOBS: &[&str] = &[".env", ".key", ".pem", ".kdbx"];
const SECRET_DIRS: &[&str] = &[".ssh", ".hermes"];

pub fn is_secret(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.starts_with("id_") { return true; }
    if SECRET_GLOBS.iter().any(|g| name.ends_with(g)) { return true; }
    path.components().any(|c| SECRET_DIRS.contains(&c.as_os_str().to_str().unwrap_or("")))
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
}
