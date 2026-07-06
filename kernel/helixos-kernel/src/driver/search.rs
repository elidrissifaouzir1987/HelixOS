#![forbid(unsafe_code)]
use std::path::PathBuf;
use crate::driver::DriverError;
/// Recherche par nom, bornée aux racines (MVP-0 : parcours simple, pas d'index).
pub fn walk_by_name(query: &str, roots: &[PathBuf]) -> Result<Vec<PathBuf>, DriverError> {
    let mut out = Vec::new();
    for root in roots {
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)?.flatten() {
                let p = entry.path();
                if p.is_dir() { stack.push(p); }
                else if p.file_name().and_then(|s| s.to_str()).map_or(false, |n| n.contains(query)) { out.push(p); }
            }
        }
    }
    Ok(out)
}
