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

/// Chemin canonique effectif : si `p` existe, `std::fs::canonicalize(p)` directement (résout
/// les liens symboliques/jonctions réellement, via le FS). Sinon — la cible d'un `apply` peut
/// ne pas encore exister — canonicalise l'ancêtre existant le plus proche puis rattache le
/// reste lexical (déjà purgé des `..` par `normalize`). Ainsi un lien-dir ancêtre pointant hors
/// du vault fait toujours atterrir le résultat hors racine, même quand la feuille n'existe pas
/// encore.
fn effective_canonical(p: &Path) -> Option<PathBuf> {
    let np = normalize(p);
    if let Ok(c) = std::fs::canonicalize(&np) {
        return Some(c);
    }
    // Remonte jusqu'au premier ancêtre existant, en gardant la queue lexicale à rattacher.
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur: &Path = &np;
    loop {
        match cur.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                if let Some(name) = cur.file_name() { tail.push(name); }
                if let Ok(c) = std::fs::canonicalize(parent) {
                    let mut out = c;
                    for seg in tail.iter().rev() { out.push(seg); }
                    return Some(out);
                }
                cur = parent;
            }
            _ => return None, // aucun ancêtre existant (ex. racine louée elle-même absente)
        }
    }
}

impl ScopeLease {
    /// Contrôle PRIMAIRE : le chemin canonique effectif doit être sous une racine canonique.
    /// Canonicalise réellement le FS (`std::fs::canonicalize`) des deux côtés — racine ET
    /// cible — avec la même fonction, pour que le `starts_with` reste cohérent même si Windows
    /// préfixe les chemins canonicalisés en `\\?\`. `canonicalize` résout les liens
    /// symboliques/jonctions : un ancêtre-lien de la racine louée pointant hors du vault fait
    /// donc atterrir le chemin canonique hors de la racine canonique → refus. Si la racine
    /// louée elle-même ne peut pas être canonicalisée (inexistante), elle ne permet rien.
    pub fn permits(&self, path: &Path) -> bool {
        let Some(target_canon) = effective_canonical(path) else { return false; };
        self.roots.iter().any(|r| {
            match std::fs::canonicalize(r) {
                Ok(root_canon) => target_canon.starts_with(&root_canon),
                Err(_) => false, // racine louée inexistante -> ne permet rien
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `canonicalize` exige que la racine existe réellement sur le FS : ces tests créent donc
    /// un vrai répertoire temporaire ("tempdir" maison, sans dépendance externe) au lieu de
    /// chemins fictifs comme avant la canonicalisation.
    fn temp_vault() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("helix-scope-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn lease_at(root: PathBuf) -> ScopeLease {
        ScopeLease { task_id: "t1".into(), roots: vec![root] }
    }

    #[test]
    fn permits_path_inside_leased_root() {
        let vault = temp_vault();
        assert!(lease_at(vault.clone()).permits(&vault.join("note.md")));
    }
    #[test]
    fn refuses_path_outside_lease() {           // test 20
        let vault = temp_vault();
        let outside = std::env::temp_dir().join(format!("helix-outside-{}", uuid::Uuid::new_v4())).join(".ssh").join("id_rsa");
        assert!(!lease_at(vault).permits(&outside));
    }
    #[test]
    fn refuses_parent_traversal() {
        let vault = temp_vault();
        // `vault/../secrets/x` : le traversal lexical sort du vault avant même la canonicalisation.
        let escaping = vault.join("..").join("secrets").join("x");
        assert!(!lease_at(vault).permits(&escaping));
    }

    /// Best-effort : prouve que `permits` refuse une cible atteinte via un lien-dir ancêtre
    /// placé DANS le vault et pointant VERS L'EXTÉRIEUR (contournement lexical historique :
    /// `C:\vault\link\x` restait lexicalement sous `C:\vault` alors que `link` menait ailleurs).
    /// La création de jonctions/symlinks sous Windows exige un privilège (SeCreateSymbolicLink)
    /// ou le mode développeur ; si la création échoue par manque de droits (os error 1314),
    /// on saute proprement au lieu de faire échouer le test dans un environnement CI restreint.
    #[test]
    fn refuses_target_reached_through_outward_symlink_best_effort() {
        let vault = temp_vault();
        let outside = std::env::temp_dir().join(format!("helix-outside-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("x"), b"SECRET").unwrap();
        let link = vault.join("link");
        match std::os::windows::fs::symlink_dir(&outside, &link) {
            Ok(()) => {
                assert!(!lease_at(vault).permits(&link.join("x")),
                    "un lien-dir dans le vault pointant hors-vault doit faire refuser la cible");
            }
            Err(e) if e.raw_os_error() == Some(1314) => {
                eprintln!("skip refuses_target_reached_through_outward_symlink_best_effort: \
                           privilège insuffisant pour créer un lien symbolique (os error 1314)");
            }
            Err(e) => panic!("échec inattendu de création du lien symbolique : {e}"),
        }
    }
}
