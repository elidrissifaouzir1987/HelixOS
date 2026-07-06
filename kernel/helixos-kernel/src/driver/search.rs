#![forbid(unsafe_code)]
use std::path::PathBuf;
use crate::driver::DriverError;
/// Recherche par nom, bornée aux racines (MVP-0 : parcours simple, pas d'index).
///
/// Sécurité : `p.is_dir()` (ancienne implémentation) DÉRÉFÉRENCE les liens symboliques/jonctions
/// avant de tester le type — un lien-dir dans une racine louée aurait donc été suivi et le
/// parcours aurait débordé hors scope. `entry.file_type()` ne déréférence pas (c'est le type de
/// l'entrée elle-même telle que lue par `read_dir`, pas celui de sa cible) : on ne descend donc
/// QUE dans de vrais répertoires (`is_dir() && !is_symlink()`), et toute entrée symlink (fichier
/// ou dossier) est simplement ignorée plutôt que suivie.
pub fn walk_by_name(query: &str, roots: &[PathBuf]) -> Result<Vec<PathBuf>, DriverError> {
    let mut out = Vec::new();
    for root in roots {
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)?.flatten() {
                let ft = match entry.file_type() { Ok(ft) => ft, Err(_) => continue };
                if ft.is_symlink() { continue; } // n'entre jamais dans un lien, ne le rapporte pas non plus
                let p = entry.path();
                if ft.is_dir() { stack.push(p); }
                else if p.file_name().and_then(|s| s.to_str()).map_or(false, |n| n.contains(query)) { out.push(p); }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Test déterministe (aucun privilège requis) : un parcours normal reste borné aux racines
    /// données et retrouve bien les fichiers correspondant à la requête, imbriqués ou non.
    #[test]
    fn walk_by_name_stays_within_roots_and_finds_nested_matches() {
        let root = temp_dir("helix-search-root");
        std::fs::write(root.join("keep.md"), b"x").unwrap();
        let nested = root.join("sub");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("keep-nested.md"), b"x").unwrap();
        std::fs::write(nested.join("other.txt"), b"x").unwrap();

        let hits = walk_by_name("keep", std::slice::from_ref(&root)).unwrap();
        assert_eq!(hits.len(), 2, "doit trouver les deux fichiers matching, imbriqués ou non");
        assert!(hits.iter().all(|p| p.starts_with(&root)), "tous les résultats doivent rester sous la racine");
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

    /// Prouve qu'un lien-dir placé DANS une racine et pointant VERS L'EXTÉRIEUR n'est pas suivi
    /// par `walk_by_name` (ancienne implémentation : `p.is_dir()` déréférence le lien et l'aurait
    /// suivi, débordant hors scope). Exercé via `make_reparse_dir` (symlink si privilège
    /// disponible, sinon jonction NTFS sans privilège) : le skip ne subsiste que si NI l'une NI
    /// l'autre forme n'a pu être créée.
    #[test]
    fn walk_by_name_does_not_follow_outward_symlink_best_effort() {
        let root = temp_dir("helix-search-root");
        let outside = temp_dir("helix-search-outside");
        std::fs::write(outside.join("secret-match.md"), b"SECRET").unwrap();
        let link = root.join("link");
        if !make_reparse_dir(&link, &outside) {
            eprintln!("skip walk_by_name_does_not_follow_outward_symlink_best_effort: \
                       ni symlink ni jonction créables");
            return;
        }
        let hits = walk_by_name("secret-match", std::slice::from_ref(&root)).unwrap();
        assert!(hits.is_empty(), "un lien-dir sortant ne doit jamais être suivi ni rapporté");
        assert!(hits.iter().all(|p| !p.starts_with(&link)),
            "aucun résultat ne doit se trouver sous le lien sortant");
    }
}
