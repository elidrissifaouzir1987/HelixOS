#![forbid(unsafe_code)]
use std::path::PathBuf;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Intention {
    SearchFiles { query: String },
    ReadFile { path: PathBuf },
    ProposeFilePatch { path: PathBuf, patch: String },   // patch = nouveau contenu (MVP-0 : remplacement intégral)
    ApplyFilePatch { plan_id: String },
}
