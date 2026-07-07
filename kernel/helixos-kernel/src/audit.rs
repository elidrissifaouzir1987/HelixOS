#![forbid(unsafe_code)]
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRecord {
    pub operation_id: String,
    pub caller: String,
    pub subagent_id_hint: Option<String>,   // hint déclaratif — SANS valeur de sécurité
    pub tool: String,
    pub target: String,
    pub plan_hash: String,
    pub target_hash_at_diff: String,
    pub risk: String,
    pub rollback: Option<String>,
    pub result: String,
    pub trace_id: String,
}

impl AuditRecord {
    #[cfg(test)]
    pub fn sample(op: &str) -> Self {
        Self { operation_id: op.into(), caller: "hermes".into(), subagent_id_hint: None,
               tool: "apply_file_patch".into(), target: "C:/vault/n.md".into(),
               plan_hash: "h".into(), target_hash_at_diff: "th".into(), risk: "L1".into(),
               rollback: Some("rb1".into()), result: "success".into(), trace_id: "tr".into() }
    }
}

pub struct AppendOnlyStore { path: PathBuf }
impl AppendOnlyStore {
    pub fn new(path: PathBuf) -> Self { Self { path } }
    pub fn append(&self, rec: &AuditRecord) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(rec)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn append_writes_one_jsonl_line_per_record() {
        let dir = std::env::temp_dir().join(format!("helix-audit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = AppendOnlyStore::new(dir.join("audit.jsonl"));
        store.append(&AuditRecord::sample("op1")).unwrap();
        store.append(&AuditRecord::sample("op2")).unwrap();
        let content = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("op1") && content.contains("op2"));
    }
}
