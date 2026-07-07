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

    /// Crée un répertoire "reparse" (lien symbolique-dir, ou à défaut une jonction NTFS) menant
    /// de `link` vers `target`. Les deux formes sont des reparse points : `canonicalize` les
    /// résout et `entry.file_type().is_symlink()` renvoie `true` pour elles, donc les deux
    /// exercent le même contrôle. Un vrai lien symbolique exige un privilège
    /// (SeCreateSymbolicLink) ou le mode développeur (échoue en os error 1314 sinon) ; une
    /// jonction (`mklink /J`) ne demande aucun privilège particulier. On tente donc le
    /// symlink d'abord, puis on retombe sur la jonction. Retourne `false` si aucune des deux
    /// formes n'a pu être créée (cas rare, ex. FS non-NTFS).
    fn make_reparse_dir(link: &Path, target: &Path) -> bool {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return true;
        }
        // Repli jonction NTFS : `mklink /J` exige que `link` n'existe pas encore et que
        // `target` soit un répertoire existant. Pas de privilège requis.
        let link_str = link.to_string_lossy().replace('/', "\\");
        let target_str = target.to_string_lossy().replace('/', "\\");
        match std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J", &link_str, &target_str])
            .status()
        {
            Ok(status) => status.success(),
            Err(_) => false,
        }
    }

    /// Prouve que `permits` refuse une cible atteinte via un lien-dir ancêtre placé DANS le
    /// vault et pointant VERS L'EXTÉRIEUR (contournement lexical historique : `C:\vault\link\x`
    /// restait lexicalement sous `C:\vault` alors que `link` menait ailleurs). Exercé via
    /// `make_reparse_dir` (symlink si privilège dispo, sinon jonction NTFS sans privilège) :
    /// le skip ne subsiste que si NI l'une NI l'autre forme n'a pu être créée.
    #[test]
    fn refuses_target_reached_through_outward_symlink_best_effort() {
        let vault = temp_vault();
        let outside = std::env::temp_dir().join(format!("helix-outside-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("x"), b"SECRET").unwrap();
        let link = vault.join("link");
        if !make_reparse_dir(&link, &outside) {
            eprintln!("skip refuses_target_reached_through_outward_symlink_best_effort: \
                       ni symlink ni jonction créables");
            return;
        }
        let lease = lease_at(vault);
        assert!(!lease.permits(&link.join("x")),
            "un lien-dir dans le vault pointant hors-vault doit faire refuser une feuille existante");
        assert!(!lease.permits(&link.join("does-not-exist")),
            "un lien-dir dans le vault pointant hors-vault doit aussi faire refuser une feuille inexistante");
    }
}
