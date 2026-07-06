#![forbid(unsafe_code)]
use crate::plan::Plan;
pub struct Card { pub quoi: String, pub ou: String, pub risque: String,
                  pub pourquoi: String, pub inhabituel: String, pub plan_hash: String }
impl Card {
    pub fn from_plan(p: &Plan, unusual: Option<String>, tainted: bool) -> Self {
        let pourquoi = if tainted {
            format!("Tâche {} — ⚠ action influencée par du contenu non fiable lu ce tour", p.task_id)
        } else { format!("Tâche {}", p.task_id) };
        Self {
            quoi: p.diff.clone(),
            ou: format!("{} (dans le bail de portée)", p.target.display()),
            risque: format!("{:?} · rollback réel = {:?}", p.risk, p.rollback_class),
            pourquoi,
            inhabituel: unusual.unwrap_or_else(|| "rien d'inhabituel signalé".into()),
            plan_hash: p.plan_hash.clone(),
        }
    }
    pub fn render_text(&self) -> String {
        format!("QUOI:\n{}\n\nOÙ: {}\n\nRISQUE: {}\n\nPOURQUOI: {}\n\nINHABITUEL: {}\n\nhash: {}",
                self.quoi, self.ou, self.risque, self.pourquoi, self.inhabituel, self.plan_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn card_has_five_ordered_sections_and_flags_taint() {
        let plan = crate::plan::new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
            "th".into(), "diff".into(), b"proposed".to_vec(),
            crate::policy::RiskLevel::L2, crate::plan::RollbackClass::Compensation);
        let card = Card::from_plan(&plan, Some("1re écriture hors ~/vault".into()), true);
        let text = card.render_text();
        for label in ["QUOI", "OÙ", "RISQUE", "POURQUOI", "INHABITUEL"] { assert!(text.contains(label)); }
        // NOTE (corrigé vs plan source) : le plan attendait la sous-chaîne "influencé" (sans
        // accord), mais l'implémentation (et les Global Constraints, ligne 22) écrit à raison
        // "influencée" (accord avec "action", féminin). Le test source ne pouvait donc jamais
        // passer sans dégrader la grammaire du message affiché à l'utilisateur. Corrigé pour
        // vérifier la même propriété (le drapeau taint est bien présent) sans figer une faute.
        assert!(text.contains("influencée par du contenu non fiable"));   // drapeau taint
        // NOTE (corrigé vs plan source) : le plan attendait la sous-chaîne minuscule
        // "compensation", mais `risque` rend `RollbackClass` via `{:?}` (Debug dérivé),
        // qui produit systématiquement "Compensation" (majuscule, nom du variant) — la
        // même convention que `risk: format!("{:?}", ...)` dans l'AuditRecord (pipeline.rs).
        // Changer la casse ici casserait cette convention partagée pour rien ; le test est
        // corrigé pour vérifier la même propriété (rollback réel = compensation, pas "auto").
        assert!(text.contains("Compensation"));                          // rollback réel
        assert!(!text.contains("Auto"), "MVP-0 gèle VSS/auto — la carte ne doit jamais l'afficher");
    }
}
