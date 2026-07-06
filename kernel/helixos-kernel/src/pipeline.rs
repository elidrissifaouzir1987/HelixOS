#![forbid(unsafe_code)]
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use sha2::{Digest, Sha256};
use crate::{audit::*, driver::{files::FileDriver, DriverHost}, intention::Intention,
            plan::*, policy, scope::ScopeLease};

pub struct Outcome { pub rollback_id: String }

/// Une ligne du journal JSONL des plans consommés (append-only, disjoint de `audit.jsonl`).
#[derive(serde::Serialize, serde::Deserialize)]
struct ConsumedRecord { plan_hash: String }

pub struct Kernel {
    lease: ScopeLease,
    driver: FileDriver,
    audit: AppendOnlyStore,
    plans: HashMap<String, Plan>,           // plan_hash -> Plan (état des ops en vol, en mémoire)
    consumed_path: PathBuf,                 // journal JSONL persistant des plan_hash consommés
    consumed_hashes: HashSet<String>,       // reflet en mémoire du journal, pour un refus rapide
}

impl Kernel {
    /// Démarre un noyau neuf sur `state_dir` : journal des plans consommés vide (créé au
    /// premier `apply`), aucun plan en vol.
    pub fn new(state_dir: PathBuf, lease: ScopeLease) -> std::io::Result<Self> {
        std::fs::create_dir_all(&state_dir)?;
        Ok(Self {
            lease,
            driver: FileDriver::new(state_dir.join(".staging")),
            audit: AppendOnlyStore::new(state_dir.join("audit.jsonl")),
            plans: HashMap::new(),
            consumed_path: state_dir.join("consumed.jsonl"),
            consumed_hashes: HashSet::new(),
        })
    }

    /// Recharge un noyau depuis un `state_dir` existant : relit le journal des plans
    /// consommés pour qu'un plan déjà appliqué avant redémarrage reste refusé au rejeu.
    /// Un `state_dir` sans journal préexistant (première utilisation) charge un ensemble vide.
    pub fn load(state_dir: PathBuf, lease: ScopeLease) -> std::io::Result<Self> {
        let mut kernel = Self::new(state_dir, lease)?;
        if let Ok(f) = std::fs::File::open(&kernel.consumed_path) {
            for line in std::io::BufReader::new(f).lines() {
                let line = line?;
                if line.trim().is_empty() { continue; }
                let rec: ConsumedRecord = serde_json::from_str(&line)?;
                kernel.consumed_hashes.insert(rec.plan_hash);
            }
        }
        Ok(kernel)
    }

    #[cfg(test)]
    pub fn new_for_test(dir: PathBuf, lease: ScopeLease) -> Self {
        Self::new(dir, lease).expect("new_for_test: échec création state_dir")
    }

    fn hash_target(&self, path: &std::path::Path) -> String {
        match std::fs::read(path) { Ok(b) => hex(&Sha256::digest(&b)), Err(_) => "<absent>".into() }
    }

    /// Ajoute `plan_hash` au journal append-only des plans consommés (persistance E2).
    fn persist_consumed(&mut self, plan_hash: &str) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.consumed_path)?;
        writeln!(f, "{}", serde_json::to_string(&ConsumedRecord { plan_hash: plan_hash.to_string() })?)?;
        // `sync_all` force la durabilité de la ligne `consumed` sur le disque physique avant de
        // retourner : sans ça, l'OS peut garder la ligne en cache page tampon et un crash dur
        // (coupure de courant, kill -9 du process hôte) juste après `apply` pourrait la perdre,
        // rouvrant la fenêtre de rejeu qu'E2 est censé fermer (« survit au redémarrage »).
        f.sync_all()?;
        self.consumed_hashes.insert(plan_hash.to_string());
        Ok(())
    }

    /// request → scope → policy → plan → diff. Refuse hors bail.
    pub fn plan_intention(&mut self, task_id: &str, _caller: &str,
                          intention: Intention, tainted: bool) -> Result<Plan, String> {
        let target = match &intention {
            Intention::ProposeFilePatch { path, .. } | Intention::ReadFile { path } => path.clone(),
            _ => return Err("MVP-0: seul propose_file_patch est planifiable".into()),
        };
        if !self.lease.permits(&target) { return Err("hors bail de portée (refus)".into()); }  // contrôle primaire
        let risk = policy::classify(&intention, tainted);
        let th = self.hash_target(&target);
        // Le contenu approuvé (celui qu'`apply` écrira verbatim) fait partie du plan signé —
        // jamais reconstruit en parsant `diff` (fragile, cf. modification-contrôleur B7).
        let (diff, proposed_content) = match &intention {
            Intention::ProposeFilePatch { patch, .. } =>
                (format!("--- {}\n+++ (proposé)\n{patch}", target.display()), patch.clone().into_bytes()),
            _ => (String::new(), Vec::new()),
        };
        let plan = new_plan(task_id.into(), format!("{intention:?}"), target, th, diff, proposed_content,
                            risk, RollbackClass::Compensation);
        self.plans.insert(plan.plan_hash.clone(), plan.clone());
        Ok(plan)
    }

    /// apply : usage unique + anti-TOCTOU + exécute + audit + verify.
    /// Le refus de rejeu (usage unique) est vérifié contre le journal PERSISTÉ des plans
    /// consommés (`consumed_hashes`) avant même de regarder l'état en mémoire, afin qu'un
    /// noyau rechargé (`load`) refuse un plan déjà consommé par une instance antérieure,
    /// même s'il n'a jamais vu ce plan lui-même via `plan_intention` (E2).
    pub fn apply(&mut self, plan_hash: &str) -> Result<Outcome, String> {
        if self.consumed_hashes.contains(plan_hash) {
            return Err("plan déjà consommé (rejeu refusé, y compris après redémarrage)".into());
        }
        let mut plan = self.plans.get(plan_hash).cloned().ok_or("plan inconnu")?;
        if plan.consumed { return Err("plan déjà consommé (rejeu refusé)".into()); }
        if plan.is_expired(time::OffsetDateTime::now_utc()) { return Err("plan expiré".into()); }
        let current = self.hash_target(&plan.target);
        plan.verify_target_unchanged(&current).map_err(|e| e.to_string())?;   // TOCTOU
        // Écrit le contenu approuvé du plan signé, verbatim — jamais une valeur reconstruite
        // depuis `diff` (voir modification-contrôleur : plus de `diff.rsplit(...)` ici).
        let handle = self.driver.stage_and_apply(&plan.target, &plan.proposed_content).map_err(|e| e.to_string())?;
        plan.consumed = true;
        self.plans.insert(plan_hash.to_string(), plan.clone());
        // Ordre délibéré, fail-safe : `consumed` est persisté AVANT l'écriture de l'audit, pas
        // l'inverse. Si le process meurt entre les deux lignes suivantes, l'état résultant est
        // « consommé mais non audité » — un trou dans le journal humain-lisible, visible et
        // investiguable après coup. L'ordre inverse produirait « audité mais rejouable » : un
        // plan qui a modifié le fichier cible pourrait être appliqué une seconde fois après
        // redémarrage (le journal `consumed.jsonl` ne le connaîtrait pas encore), ce qui est un
        // trou de sécurité, pas juste un trou d'observabilité. Ne pas inverser cet ordre.
        self.persist_consumed(plan_hash).map_err(|e| e.to_string())?;
        self.audit.append(&AuditRecord {
            operation_id: plan.plan_id.to_string(), caller: plan.task_id.clone(), subagent_id_hint: None,
            tool: "apply_file_patch".into(), target: plan.target.display().to_string(),
            plan_hash: plan.plan_hash.clone(), target_hash_at_diff: plan.target_hash_at_diff.clone(),
            risk: format!("{:?}", plan.risk), rollback: Some(handle.id.clone()),
            result: "success".into(), trace_id: uuid::Uuid::new_v4().to_string(),
        }).map_err(|e| e.to_string())?;
        Ok(Outcome { rollback_id: handle.id })
    }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*; use crate::intention::Intention; use crate::scope::ScopeLease;
    use std::path::PathBuf;
    fn kernel_with_note(content: &[u8]) -> (Kernel, PathBuf) {
        let dir = std::env::temp_dir().join(format!("helix-pl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("note.md"); std::fs::write(&target, content).unwrap();
        let k = Kernel::new_for_test(dir.clone(),
            ScopeLease { task_id: "t1".into(), roots: vec![dir] });
        (k, target)
    }
    #[test] fn apply_patch_end_to_end_then_idempotent() {   // test 9
        let (mut k, target) = kernel_with_note(b"OLD");
        let plan = k.plan_intention("t1", "hermes",
            Intention::ProposeFilePatch { path: target.clone(), patch: "NEW".into() }, false).unwrap();
        let hash = plan.plan_hash.clone();
        assert!(k.apply(&hash).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW");
        assert!(k.apply(&hash).is_err(), "rejeu doit être refusé (usage unique)");   // idempotence
    }
    #[test] fn intention_outside_lease_is_refused() {       // test 20 (bout en bout)
        let (mut k, _t) = kernel_with_note(b"X");
        let outside = PathBuf::from("C:/Windows/system32/drivers/etc/hosts");
        let r = k.plan_intention("t1", "hermes",
            Intention::ProposeFilePatch { path: outside, patch: "P".into() }, false);
        assert!(r.is_err());
    }
    #[test] fn applied_content_matches_proposed_content_not_diff_string() {
        // Garde-fou anti-régression pour la modification-contrôleur : `apply` doit écrire
        // `plan.proposed_content` tel quel, jamais une valeur reconstruite en parsant `diff`.
        // On choisit un patch dont le texte apparaîtrait autrement dans le diff avant la
        // marque `+++ (proposé)\n` pour détecter tout retour à un rsplit sur la chaîne diff.
        let (mut k, target) = kernel_with_note(b"OLD");
        let tricky_patch = "+++ (proposé)\nCECI-NE-DOIT-PAS-ETRE-LE-RESULTAT";
        let plan = k.plan_intention("t1", "hermes",
            Intention::ProposeFilePatch { path: target.clone(), patch: tricky_patch.into() }, false).unwrap();
        assert_eq!(plan.proposed_content, tricky_patch.as_bytes());
        let hash = plan.plan_hash.clone();
        k.apply(&hash).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), tricky_patch.as_bytes());
    }
}
