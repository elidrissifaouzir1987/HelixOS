#![forbid(unsafe_code)]
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ScopeLease { pub task_id: String, pub roots: Vec<PathBuf> }

fn normalize(p: &Path) -> PathBuf {
    // Rejette le traversal en résolvant `.`/`..` de façon purement lexicale (sans toucher le FS).
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => { out.pop(); }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

impl ScopeLease {
    /// Contrôle PRIMAIRE : le chemin normalisé doit être sous une racine louée.
    pub fn permits(&self, path: &Path) -> bool {
        let np = normalize(path);
        self.roots.iter().any(|r| np.starts_with(&normalize(r)))
    }
}

#[cfg(test)]
mod tests {
    use super::*; use std::path::PathBuf;
    fn lease(root: &str) -> ScopeLease {
        ScopeLease { task_id: "t1".into(), roots: vec![PathBuf::from(root)] }
    }
    #[test]
    fn permits_path_inside_leased_root() {
        assert!(lease("C:/vault").permits(&PathBuf::from("C:/vault/note.md")));
    }
    #[test]
    fn refuses_path_outside_lease() {           // test 20
        assert!(!lease("C:/vault").permits(&PathBuf::from("C:/Users/elidr/.ssh/id_rsa")));
    }
    #[test]
    fn refuses_parent_traversal() {
        assert!(!lease("C:/vault").permits(&PathBuf::from("C:/vault/../secrets/x")));
    }
}
