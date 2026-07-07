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

    /// C2 : rendu HTML minimal (sans framework) de la carte, pour `GET /op/:hash`. Chaque champ
    /// texte est un contenu potentiellement contrôlé par ce qui a été lu/proposé dans le plan
    /// (ex. `quoi` = diff = contenu du fichier proposé, `inhabituel` = signal dérivé d'un
    /// contenu lu) — jamais une constante du noyau — donc chaque valeur passe par
    /// [`escape_html`] avant interpolation, pour qu'un caractère `&<>"'` dans le contenu du plan
    /// ne puisse jamais être interprété comme balise/attribut par le navigateur qui affiche
    /// cette carte (XSS). Rendu volontairement minimal : pas de CSS/JS externe, pas de
    /// framework — cohérent avec l'exigence d'une page servie hors webui sur une origine isolée.
    pub fn render_html(&self) -> String {
        format!(
            "<!doctype html>\n\
             <html lang=\"fr\">\n\
             <head><meta charset=\"utf-8\"><title>HelixOS — Approbation</title></head>\n\
             <body>\n\
             <h1>Carte d'approbation</h1>\n\
             <section><h2>QUOI</h2><pre>{quoi}</pre></section>\n\
             <section><h2>OÙ</h2><p>{ou}</p></section>\n\
             <section><h2>RISQUE</h2><p>{risque}</p></section>\n\
             <section><h2>POURQUOI</h2><p>{pourquoi}</p></section>\n\
             <section><h2>INHABITUEL</h2><p>{inhabituel}</p></section>\n\
             <footer><p>hash: <code>{hash}</code></p></footer>\n\
             </body>\n\
             </html>\n",
            quoi = escape_html(&self.quoi),
            ou = escape_html(&self.ou),
            risque = escape_html(&self.risque),
            pourquoi = escape_html(&self.pourquoi),
            inhabituel = escape_html(&self.inhabituel),
            // Le hash est un hex sha256 (produit par le noyau, jamais du contenu utilisateur)
            // mais reste échappé par cohérence défensive — un hash n'est jamais un vecteur
            // d'attaque ici, l'échappement est un coût nul et évite toute exception à la règle.
            hash = escape_html(&self.plan_hash),
        )
    }
}

/// Échappe les 5 caractères significatifs pour l'injection HTML/attribut (`& < > " '`), dans
/// l'ordre qui évite une double-substitution : `&` doit être échappé EN PREMIER, sinon les
/// `&amp;`/`&lt;`/... produits pour les autres caractères seraient eux-mêmes ré-échappés
/// (`&` -> `&amp;amp;`). L'apostrophe `'` -> `&#x27;` (forme numérique canonique, pas `&apos;`
/// qui n'est pas une entité HTML4/HTML5 nommée universellement reconnue) complète la liste :
/// sans elle, un contexte attribut délimité par des apostrophes (ex. `onclick='...'`) resterait
/// injectable malgré l'échappement de `& < > "` — durcissement anti-régression (revue C2) sur la
/// surface où l'humain approuve.
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
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

    // --- C2 : rendu HTML de la carte (page d'approbation origine distincte) ---

    #[test] fn html_render_has_five_ordered_sections_and_hash() {
        let plan = crate::plan::new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
            "th".into(), "diff".into(), b"proposed".to_vec(),
            crate::policy::RiskLevel::L1, crate::plan::RollbackClass::Compensation);
        let card = Card::from_plan(&plan, None, false);
        let html = card.render_html();
        for label in ["QUOI", "OÙ", "RISQUE", "POURQUOI", "INHABITUEL"] {
            assert!(html.contains(label), "section {label} absente du rendu HTML");
        }
        assert!(html.contains(&plan.plan_hash), "le hash du plan doit être visible dans la carte");
    }

    #[test] fn html_render_escapes_dangerous_characters_from_plan_content() {
        // Le `diff` (section QUOI) peut contenir un contenu de fichier arbitraire, potentiellement
        // du HTML/JS si la note patchée en contenait — la carte ne doit jamais l'interpréter tel
        // quel (XSS). On injecte les 4 caractères dangereux dans le champ `diff` et on vérifie
        // qu'aucune balise/quote brute n'atteint le HTML final.
        let dangerous_diff = "<script>alert('xss')</script> & \"quoted\"";
        let plan = crate::plan::new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
            "th".into(), dangerous_diff.into(), b"proposed".to_vec(),
            crate::policy::RiskLevel::L1, crate::plan::RollbackClass::Compensation);
        let card = Card::from_plan(&plan, None, false);
        let html = card.render_html();
        assert!(!html.contains("<script>"), "un tag <script> brut ne doit jamais apparaître dans la carte");
        assert!(html.contains("&lt;script&gt;"), "< et > doivent être échappés en entités HTML");
        assert!(html.contains("&amp;"), "& doit être échappé");
        assert!(html.contains("&quot;"), "\" doit être échappée");
    }

    #[test] fn html_render_escapes_unusual_field_too() {
        // `inhabituel` vient aussi d'un champ potentiellement influencé par du contenu lu — même
        // exigence d'échappement que pour `quoi`.
        let plan = crate::plan::new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
            "th".into(), "diff".into(), b"proposed".to_vec(),
            crate::policy::RiskLevel::L1, crate::plan::RollbackClass::Compensation);
        let card = Card::from_plan(&plan, Some("<img src=x onerror=alert(1)>".into()), false);
        let html = card.render_html();
        assert!(!html.contains("<img"), "un tag brut dans INHABITUEL ne doit jamais apparaître");
        assert!(html.contains("&lt;img"));
    }

    #[test] fn html_render_escapes_apostrophe_from_plan_content() {
        // Durcissement (revue C2) : l'échappement doit couvrir les 5 caractères significatifs
        // HTML/attribut, y compris l'apostrophe `'` — un vecteur XSS classique dans un contexte
        // attribut délimité par des apostrophes (ex. `onclick='...'`) que les 4 caractères
        // `& < > "` seuls ne neutralisent pas. On injecte les 5 caractères dangereux ensemble
        // (`< > & " '`) dans un champ contrôlé par l'appelant (`inhabituel`) et vérifie que la
        // séquence dangereuse d'origine n'atteint jamais le HTML telle quelle, et que sa forme
        // échappée (dont l'apostrophe -> `&#x27;`) y est bien présente. NOTE : on n'asserte pas
        // "aucune apostrophe dans tout le document" — le chrome HTML statique du template
        // (constante du noyau, ex. `<h1>Carte d'approbation</h1>`) en contient légitimement une ;
        // seule l'absence de fuite du CONTENU CONTRÔLÉ PAR L'APPELANT importe ici.
        let plan = crate::plan::new_plan("t1".into(), "int".into(), "C:/vault/n.md".into(),
            "th".into(), "diff".into(), b"proposed".to_vec(),
            crate::policy::RiskLevel::L1, crate::plan::RollbackClass::Compensation);
        let dangerous = "<script>alert('xss')</script> & \"quoted\" 'single'";
        let card = Card::from_plan(&plan, Some(dangerous.into()), false);
        let html = card.render_html();
        assert!(!html.contains(dangerous), "la séquence dangereuse brute ne doit jamais atteindre le HTML rendu");
        assert!(html.contains("&#x27;"), "l'apostrophe doit être échappée en entité HTML &#x27;");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&quot;"));
        // La forme pleinement échappée de l'input dangereux doit apparaître intégralement.
        let expected_escaped = "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt; &amp; &quot;quoted&quot; &#x27;single&#x27;";
        assert!(html.contains(expected_escaped), "forme échappée attendue absente du HTML: {html}");
    }
}
