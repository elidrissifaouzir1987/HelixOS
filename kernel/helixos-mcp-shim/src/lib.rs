#![forbid(unsafe_code)]
//! `helixos-mcp-shim` — pont entre l'agent Hermes (qui parle MCP/JSON-RPC sur stdio) et le noyau
//! souverain HelixOS (qui parle mTLS). Un seul outil exposé : `helix_patch_note{path, patch}`.
//!
//! Flux : Hermes appelle `tools/call helix_patch_note` → le shim se connecte au noyau en mTLS
//! (cert client), envoie une intention `ProposeFilePatch` → reçoit un `plan_hash` → construit
//! l'`approval_url` → renvoie `{plan_hash, approval_url}`. **Le shim n'applique jamais** :
//! l'application réelle passe par la page d'approbation (humain), hors de la pile agent. Aucune
//! API freeform.
//!
//! Bibliothèque + binaire : les modules sont exposés ici pour que les tests d'intégration
//! (`tests/`, crate externe) exercent la couche protocole et le client mTLS. `main.rs` est un
//! mince point d'entrée.

pub mod config;
pub mod kernel_client;
pub mod mcp;

use config::ShimConfig;
use kernel_client::{ClientTls, KernelError};
use mcp::{ToolExecutor, ToolOutcome};
use std::io::Write;

/// Exécuteur réel de l'outil : effectue l'aller-retour mTLS vers le noyau, puis construit
/// l'`approval_url` à partir de l'origine d'approbation configurée. Détient le matériel TLS
/// (chargé une fois) et la config. Réutilise un runtime tokio courant pour le blocage synchrone :
/// la couche MCP `handle_request` est synchrone (elle traite une requête à la fois sur la boucle
/// stdio), donc l'exécuteur bloque sur le futur mTLS via un handle du runtime.
pub struct MtlsToolExecutor {
    tls: ClientTls,
    config: ShimConfig,
    runtime: tokio::runtime::Handle,
}

impl MtlsToolExecutor {
    pub fn new(tls: ClientTls, config: ShimConfig, runtime: tokio::runtime::Handle) -> Self {
        Self { tls, config, runtime }
    }
}

impl ToolExecutor for MtlsToolExecutor {
    fn patch_note(&self, path: &str, patch: &str) -> ToolOutcome {
        // Bloque sur le futur mTLS depuis ce contexte synchrone. `block_on` d'un `Handle` panique
        // s'il est appelé DEPUIS un thread de l'executor ; la boucle stdio tourne sur un thread
        // dédié (voir `run`), donc c'est sûr ici. `catch_unwind` n'est pas nécessaire : le chemin
        // mTLS ne panique pas (toutes les erreurs sont des `Result`).
        let result: Result<String, KernelError> = self.runtime.block_on(async {
            kernel_client::propose_file_patch(
                &self.tls,
                &self.config.kernel_addr,
                &self.config.server_name,
                path,
                patch,
            )
            .await
        });

        match result {
            Ok(plan_hash) => {
                let approval_url = self.config.approval_url(&plan_hash);
                ToolOutcome::Ok { plan_hash, approval_url }
            }
            Err(e) => ToolOutcome::Err(e.to_string()),
        }
    }
}

/// Boucle serveur MCP sur stdio, générique sur l'exécuteur d'outil (le vrai `MtlsToolExecutor` en
/// production ; un faux en test). Lit des lignes JSON-RPC sur `input` (une par ligne, cadre
/// « ligne = message », le plus simple et suffisant pour Hermes), traite chacune via
/// `mcp::handle_request`, et écrit la réponse (le cas échéant) sur `output`. Une notification
/// (sans réponse) n'écrit rien. Un JSON illisible produit une erreur JSON-RPC `PARSE_ERROR`
/// (id null). Se termine proprement à l'EOF de `input`.
///
/// Ne panique jamais sur une entrée malformée : robustesse exigée pour une frontière de confiance.
pub fn serve_stdio<R: std::io::BufRead, W: Write>(
    mut input: R,
    output: &mut W,
    executor: &dyn ToolExecutor,
) -> std::io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = input.read_line(&mut line)?;
        if n == 0 {
            break; // EOF : le conteneur a fermé stdin, arrêt propre.
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue; // lignes vides ignorées (keep-alive éventuel).
        }

        let response = match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(req) => mcp::handle_request(&req, executor),
            Err(e) => Some(mcp::error_response(
                serde_json::Value::Null,
                mcp::error_code::PARSE_ERROR,
                format!("JSON invalide: {e}"),
            )),
        };

        if let Some(resp) = response {
            let mut out = serde_json::to_string(&resp)
                .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"réponse non sérialisable"}}"#.to_string());
            out.push('\n');
            output.write_all(out.as_bytes())?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct StubExecutor;
    impl ToolExecutor for StubExecutor {
        fn patch_note(&self, _path: &str, _patch: &str) -> ToolOutcome {
            ToolOutcome::Ok {
                plan_hash: "f".repeat(64),
                approval_url: "https://a.example/op/".to_string() + &"f".repeat(64),
            }
        }
    }

    #[test]
    fn serve_stdio_answers_initialize_then_tools_list() {
        let input = format!(
            "{}\n{}\n",
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })
        );
        let mut output = Vec::new();
        serve_stdio(input.as_bytes(), &mut output, &StubExecutor).unwrap();
        let out = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "deux requêtes → deux réponses");
        let init: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "helixos-mcp-shim");
        let list: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(list["result"]["tools"][0]["name"], mcp::TOOL_NAME);
    }

    #[test]
    fn serve_stdio_notification_writes_nothing() {
        let input = format!(
            "{}\n",
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
        );
        let mut output = Vec::new();
        serve_stdio(input.as_bytes(), &mut output, &StubExecutor).unwrap();
        assert!(output.is_empty(), "une notification ne produit aucune sortie");
    }

    #[test]
    fn serve_stdio_bad_json_yields_parse_error() {
        let mut output = Vec::new();
        serve_stdio(b"{ this is not json\n".as_slice(), &mut output, &StubExecutor).unwrap();
        let out = String::from_utf8(output).unwrap();
        let resp: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(resp["error"]["code"], mcp::error_code::PARSE_ERROR);
    }
}
