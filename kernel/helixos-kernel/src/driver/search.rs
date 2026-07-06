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

    /// Best-effort : prouve qu'un lien-dir placé DANS une racine et pointant VERS L'EXTÉRIEUR
    /// n'est pas suivi par `walk_by_name` (ancienne implémentation : `p.is_dir()` déréférence le
    /// lien et l'aurait suivi, débordant hors scope). La création de liens symboliques sous
    /// Windows exige un privilège (SeCreateSymbolicLink) ou le mode développeur ; si la création
    /// échoue par manque de droits (os error 1314), on saute proprement.
    #[test]
    fn walk_by_name_does_not_follow_outward_symlink_best_effort() {
        let root = temp_dir("helix-search-root");
        let outside = temp_dir("helix-search-outside");
        std::fs::write(outside.join("secret-match.md"), b"SECRET").unwrap();
        let link = root.join("link");
        match std::os::windows::fs::symlink_dir(&outside, &link) {
            Ok(()) => {
                let hits = walk_by_name("secret-match", std::slice::from_ref(&root)).unwrap();
                assert!(hits.is_empty(), "un lien-dir sortant ne doit jamais être suivi ni rapporté");
            }
            Err(e) if e.raw_os_error() == Some(1314) => {
                eprintln!("skip walk_by_name_does_not_follow_outward_symlink_best_effort: \
                           privilège insuffisant pour créer un lien symbolique (os error 1314)");
            }
            Err(e) => panic!("échec inattendu de création du lien symbolique : {e}"),
        }
    }
}
