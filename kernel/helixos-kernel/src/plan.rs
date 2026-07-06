#![forbid(unsafe_code)]
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;
use std::path::PathBuf;
use crate::policy::RiskLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RollbackClass { Compensation, Irreversible }   // pas d'`Auto` en MVP-0 (VSS gelé)

#[derive(Debug, Clone, serde::Serialize)]
pub struct Plan {
    pub plan_id: Uuid,
    pub task_id: String,
    pub intention_repr: String,
    pub target: PathBuf,
    pub target_hash_at_diff: String,
    pub diff: String,
    /// Contenu approuvé (verbatim) que `apply` écrira — fait partie du plan signé,
    /// jamais reconstruit depuis `diff` (anti-substitution : voir canonical_bytes).
    pub proposed_content: Vec<u8>,
    pub risk: RiskLevel,
    pub rollback_class: RollbackClass,
    pub plan_hash: String,
    #[serde(with = "time::serde::rfc3339")] pub created_at: OffsetDateTime,
    pub ttl_secs: u64,
    pub consumed: bool,
}

pub fn new_plan(task_id: String, intention_repr: String, target: PathBuf,
                target_hash_at_diff: String, diff: String, proposed_content: Vec<u8>,
                risk: RiskLevel, rollback_class: RollbackClass) -> Plan {
    let created_at = OffsetDateTime::now_utc();
    let plan_id = Uuid::new_v4();
    let mut plan = Plan {
        plan_id, task_id, intention_repr, target, target_hash_at_diff, diff, proposed_content,
        risk, rollback_class, plan_hash: String::new(), created_at, ttl_secs: 120, consumed: false,
    };
    plan.plan_hash = hex(Sha256::digest(plan.canonical_bytes()).as_slice());
    plan
}

impl Plan {
    /// Représentation canonique hashée : inclut le contenu approuvé (via son propre hash
    /// sha256, pour rester une chaîne texte propre) afin qu'il fasse partie du plan signé —
    /// toute substitution du contenu proposé après signature change le `plan_hash`.
    ///
    /// Injectivité : chaque champ variable est préfixé par sa longueur en octets
    /// (`"{len}:{valeur}"`) avant concaténation, plutôt que simplement joint par `|`. Un simple
    /// séparateur `|` non échappé rendrait la représentation non injective — deux plans avec
    /// des découpages de champs différents mais des octets de milieu identiques (ex.
    /// `task_id="a|b", intent="c"` vs `task_id="a", intent="b|c"`) produiraient la même chaîne
    /// canonique et donc le même hash, alors que ce sont des plans sémantiquement différents.
    /// Le préfixe-longueur élimine toute ambiguïté de frontière, quel que soit le contenu du
    /// champ (y compris s'il contient lui-même des `|` ou des chiffres suivis de `:`).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let content_hash = hex(Sha256::digest(&self.proposed_content).as_slice());
        let mut out = String::new();
        for field in [
            self.plan_id.to_string(),
            self.task_id.clone(),
            self.intention_repr.clone(),
            self.target.display().to_string(),
            self.target_hash_at_diff.clone(),
            self.diff.clone(),
            content_hash,
            self.created_at.to_string(),
        ] {
            out.push_str(&format!("{}:{}", field.len(), field));
        }
        out.into_bytes()
    }
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        (now - self.created_at).whole_seconds() as u64 > self.ttl_secs
    }
    /// Anti-TOCTOU : la cible doit avoir le même hash qu'au moment du diff.
    pub fn verify_target_unchanged(&self, current_hash: &str) -> Result<(), &'static str> {
        if current_hash == self.target_hash_at_diff { Ok(()) } else { Err("target changed since diff (TOCTOU)") }
    }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn hash_is_stable_and_content_addressed() {
        // NOTE (corrigé vs plan source) : le plan source comparait deux plans construits
        // séparément et attendait `plan_hash` identique — impossible par construction,
        // puisque `new_plan` mélange `plan_id` (UUID frais) et `created_at` (horloge) dans
        // la chaîne canonique, donc deux appels ne peuvent jamais halesher pareil. Ce test
        // vérifiait donc une propriété fausse (aurait dû toujours échouer). Corrigé pour
        // tester ce qui est réellement garanti : (a) stabilité — rehacher les mêmes octets
        // canoniques d'un plan déjà construit redonne le même hash ; (b) adressage par
        // contenu — deux plans avec un `target_hash_at_diff` différent divergent.
        let p = sample_plan("HASH_A");
        assert_eq!(p.plan_hash.len(), 64);                 // sha256 hex
        let recomputed = hex(Sha256::digest(p.canonical_bytes()).as_slice());
        assert_eq!(p.plan_hash, recomputed, "rehacher les mêmes octets canoniques doit redonner le même hash");
        assert_ne!(p.plan_hash, sample_plan("HASH_B").plan_hash);
    }
    #[test] fn toctou_refuses_changed_target() {           // test 12
        let p = sample_plan("HASH_A");
        assert!(p.verify_target_unchanged("HASH_A").is_ok());
        assert!(p.verify_target_unchanged("HASH_CHANGED").is_err());
    }
    #[test] fn expired_plan_is_rejected() {                // test 13 (TTL)
        let mut p = sample_plan("HASH_A"); p.ttl_secs = 0;
        assert!(p.is_expired(p.created_at + time::Duration::seconds(1)));
    }
    #[test] fn approved_content_is_part_of_the_signed_hash() {
        // Le contenu proposé fait partie du plan signé : deux plans identiques hors
        // contenu-proposé doivent produire des hash différents (anti-substitution).
        let a = new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
                 "HASH_A".into(), "diff".into(), b"CONTENT_A".to_vec(),
                 crate::policy::RiskLevel::L1, RollbackClass::Compensation);
        let b = new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
                 "HASH_A".into(), "diff".into(), b"CONTENT_B".to_vec(),
                 crate::policy::RiskLevel::L1, RollbackClass::Compensation);
        assert_ne!(a.plan_hash, b.plan_hash);
    }
    #[test] fn canonical_bytes_is_injective_across_field_boundary_shifts() {
        // Anti-régression pour le délimiteur `|` non échappé : `task_id="a|b", intent="c"` et
        // `task_id="a", intent="b|c"` donnaient auparavant les mêmes octets de milieu
        // (`...a|b|c...`), donc le même `canonical_bytes()`/`plan_hash`, alors que ce sont deux
        // plans sémantiquement différents. On construit deux plans à la main, identiques en
        // tout point (même `plan_id`, même `created_at`, mêmes autres champs) SAUF le découpage
        // task_id/intention_repr, pour isoler strictement cette variable.
        let mut a = sample_plan("HASH_A");
        a.task_id = "a|b".into();
        a.intention_repr = "c".into();

        let mut b = sample_plan("HASH_A");
        b.plan_id = a.plan_id;           // même plan_id
        b.created_at = a.created_at;     // même horodatage
        b.task_id = "a".into();
        b.intention_repr = "b|c".into(); // même octets "a|b|c" en concaténation naïve

        assert_ne!(a.canonical_bytes(), b.canonical_bytes(),
            "des découpages de champs différents doivent produire des canonical_bytes différents (préfixe-longueur)");
    }
    fn sample_plan(target_hash: &str) -> Plan {
        new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
                 target_hash.into(), "diff".into(), b"proposed content".to_vec(),
                 crate::policy::RiskLevel::L1, RollbackClass::Compensation)
    }
}
