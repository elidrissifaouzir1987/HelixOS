#![forbid(unsafe_code)]
//! Couche protocole MCP = JSON-RPC 2.0 sur stdio, faite main (décision spike : voir
//! `d1a-shim-report.md`). Pas de dépendance `rmcp` : MCP-sur-stdio est du JSON-RPC 2.0 avec un
//! petit jeu de méthodes stable (`initialize`, `notifications/initialized`, `tools/list`,
//! `tools/call`) et un seul outil à exposer (`helix_patch_note{path, patch}`).
//!
//! Ce module est PUR (aucune I/O réseau) : `handle_request` prend une requête JSON-RPC déjà
//! désérialisée et un exécuteur d'outil (`ToolExecutor`, trait), et renvoie soit une réponse
//! JSON-RPC, soit `None` pour une notification (pas de réponse attendue en JSON-RPC). Cela le
//! rend testable sans jamais monter de serveur mTLS ni brancher stdin/stdout.

use serde_json::{json, Value};

/// Version du protocole MCP annoncée au `initialize`. Le client (Hermes) négocie ; on renvoie
/// une version stable et largement supportée.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Nom de l'unique outil exposé au conteneur Hermes.
pub const TOOL_NAME: &str = "helix_patch_note";

/// Codes d'erreur JSON-RPC 2.0 standard (sous-ensemble utilisé ici).
pub mod error_code {
    /// JSON reçu mal formé / non parsable.
    pub const PARSE_ERROR: i64 = -32700;
    /// L'objet Request n'est pas conforme.
    pub const INVALID_REQUEST: i64 = -32600;
    /// Méthode inconnue.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Paramètres invalides (mauvais type, champ manquant).
    pub const INVALID_PARAMS: i64 = -32602;
    /// Erreur interne (ici : le noyau injoignable, hors bail, etc. — surfacé proprement,
    /// jamais un panic).
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// Résultat de l'exécution de l'outil : soit le couple `(plan_hash, approval_url)` renvoyé par le
/// noyau, soit un message d'erreur propre (noyau injoignable, intention hors bail, TLS refusé…).
pub enum ToolOutcome {
    Ok { plan_hash: String, approval_url: String },
    Err(String),
}

/// Contrat de l'exécuteur d'outil `helix_patch_note` : reçoit `path`+`patch`, effectue l'aller-
/// retour mTLS vers le noyau, renvoie le `plan_hash` (→ `approval_url`). Trait pour que les tests
/// de protocole injectent un faux exécuteur (aucun réseau) et que `main` injecte le vrai client
/// mTLS.
pub trait ToolExecutor {
    fn patch_note(&self, path: &str, patch: &str) -> ToolOutcome;
}

/// Construit l'objet `tools/list` de l'unique outil, avec son `inputSchema` JSON Schema : deux
/// paramètres string requis `path` et `patch`.
pub fn tool_descriptor() -> Value {
    json!({
        "name": TOOL_NAME,
        "description": "Propose un patch (remplacement intégral) d'une note du vault HelixOS. \
NE L'APPLIQUE PAS : renvoie un plan_hash et une URL d'approbation à ouvrir par l'humain. \
L'application réelle passe par cette page d'approbation, hors de la pile agent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Chemin absolu de la note du vault à patcher (doit être dans le bail de portée du noyau)."
                },
                "patch": {
                    "type": "string",
                    "description": "Nouveau contenu intégral de la note (MVP-0 : remplacement, pas un diff unifié)."
                }
            },
            "required": ["path", "patch"],
            "additionalProperties": false
        }
    })
}

/// Réponse JSON-RPC 2.0 de succès (`result`), avec l'`id` de la requête.
fn ok_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Réponse JSON-RPC 2.0 d'erreur (`error{code,message}`), avec l'`id` de la requête (ou `null`).
pub fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

/// Extrait un paramètre string requis de `params.arguments`. `Err` porte un message prêt pour un
/// `INVALID_PARAMS`.
fn required_str_arg<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, String> {
    match arguments.get(name) {
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err(format!("le paramètre '{name}' doit être une chaîne")),
        None => Err(format!("paramètre requis manquant: '{name}'")),
    }
}

/// Cœur du protocole : traite UNE requête JSON-RPC déjà désérialisée en `Value`, en déléguant
/// l'exécution effective de l'outil à `executor`. Renvoie `Some(reponse)` pour une requête (avec
/// `id`), `None` pour une notification (sans `id` — JSON-RPC n'attend pas de réponse). Ne panique
/// jamais : toute erreur devient une réponse JSON-RPC structurée.
pub fn handle_request(req: &Value, executor: &dyn ToolExecutor) -> Option<Value> {
    // `id` absent ⟺ notification. On le capture tôt : une méthode inconnue en notification ne
    // doit produire AUCUNE réponse (règle JSON-RPC), et `notifications/initialized` est la
    // notification standard post-handshake MCP.
    let id = req.get("id").cloned();
    let is_notification = id.is_none();
    let id_for_response = id.clone().unwrap_or(Value::Null);

    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => {
            if is_notification {
                return None;
            }
            return Some(error_response(
                id_for_response,
                error_code::INVALID_REQUEST,
                "champ 'method' manquant ou non-string",
            ));
        }
    };

    match method {
        "initialize" => {
            if is_notification {
                return None;
            }
            Some(ok_response(
                id_for_response,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "helixos-mcp-shim", "version": env!("CARGO_PKG_VERSION") }
                }),
            ))
        }
        // Notifications MCP standard post-handshake : pas de réponse.
        "notifications/initialized" | "initialized" => None,
        "ping" => {
            if is_notification {
                return None;
            }
            Some(ok_response(id_for_response, json!({})))
        }
        "tools/list" => {
            if is_notification {
                return None;
            }
            Some(ok_response(
                id_for_response,
                json!({ "tools": [ tool_descriptor() ] }),
            ))
        }
        "tools/call" => {
            if is_notification {
                return None;
            }
            Some(handle_tools_call(id_for_response, req, executor))
        }
        other => {
            if is_notification {
                return None;
            }
            Some(error_response(
                id_for_response,
                error_code::METHOD_NOT_FOUND,
                format!("méthode inconnue: {other}"),
            ))
        }
    }
}

/// Dispatch de `tools/call` : valide le nom d'outil + les paramètres, appelle `executor`, et
/// emballe le résultat en contenu MCP standard (`content: [{type:text,...}]`) ou en erreur
/// JSON-RPC structurée. Une erreur fonctionnelle du noyau (hors bail, injoignable) devient un
/// résultat MCP `isError: true` avec le message — c'est le canal d'erreur d'OUTIL prévu par MCP,
/// distinct d'une erreur de protocole JSON-RPC.
fn handle_tools_call(id: Value, req: &Value, executor: &dyn ToolExecutor) -> Value {
    let params = match req.get("params") {
        Some(p) => p,
        None => {
            return error_response(id, error_code::INVALID_PARAMS, "params manquants pour tools/call");
        }
    };
    let name = match params.get("name").and_then(Value::as_str) {
        Some(n) => n,
        None => {
            return error_response(id, error_code::INVALID_PARAMS, "params.name manquant ou non-string");
        }
    };
    if name != TOOL_NAME {
        return error_response(
            id,
            error_code::METHOD_NOT_FOUND,
            format!("outil inconnu: {name} (seul '{TOOL_NAME}' est exposé)"),
        );
    }

    // `arguments` peut être absent : on traite comme objet vide pour produire un INVALID_PARAMS
    // ciblé sur le champ manquant plutôt qu'une erreur générique.
    let empty = json!({});
    let arguments = params.get("arguments").unwrap_or(&empty);

    let path = match required_str_arg(arguments, "path") {
        Ok(p) => p,
        Err(e) => return error_response(id, error_code::INVALID_PARAMS, e),
    };
    let patch = match required_str_arg(arguments, "patch") {
        Ok(p) => p,
        Err(e) => return error_response(id, error_code::INVALID_PARAMS, e),
    };

    match executor.patch_note(path, patch) {
        ToolOutcome::Ok { plan_hash, approval_url } => {
            let human = format!(
                "Patch planifié (NON appliqué). Ouvrez la page d'approbation pour valider :\n\
                 plan_hash: {plan_hash}\napproval_url: {approval_url}"
            );
            // Contenu MCP standard : un bloc texte lisible + un bloc structuré (structuredContent)
            // pour les clients qui savant le consommer par machine.
            ok_response(
                id,
                json!({
                    "content": [ { "type": "text", "text": human } ],
                    "structuredContent": { "plan_hash": plan_hash, "approval_url": approval_url },
                    "isError": false
                }),
            )
        }
        ToolOutcome::Err(msg) => {
            // Erreur d'OUTIL (pas de protocole) : le modèle doit la voir. MCP → `isError: true`.
            ok_response(
                id,
                json!({
                    "content": [ { "type": "text", "text": format!("Échec de la planification du patch : {msg}") } ],
                    "isError": true
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exécuteur factice : renvoie toujours un plan_hash bidon, sans réseau. Sert à tester la
    /// couche protocole isolément.
    struct StubExecutor;
    impl ToolExecutor for StubExecutor {
        fn patch_note(&self, _path: &str, _patch: &str) -> ToolOutcome {
            ToolOutcome::Ok {
                plan_hash: "a".repeat(64),
                approval_url: "https://approval.example/op/".to_string() + &"a".repeat(64),
            }
        }
    }

    /// Exécuteur factice qui échoue toujours — pour vérifier le mapping erreur-outil.
    struct FailingExecutor;
    impl ToolExecutor for FailingExecutor {
        fn patch_note(&self, _path: &str, _patch: &str) -> ToolOutcome {
            ToolOutcome::Err("hors bail de portée (refus)".into())
        }
    }

    #[test]
    fn initialize_advertises_tools_capability_and_server_info() {
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} });
        let resp = handle_request(&req, &StubExecutor).expect("initialize doit répondre");
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["capabilities"]["tools"].is_object());
        assert_eq!(resp["result"]["serverInfo"]["name"], "helixos-mcp-shim");
    }

    #[test]
    fn tools_list_exposes_helix_patch_note_with_two_string_params() {
        let req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
        let resp = handle_request(&req, &StubExecutor).expect("tools/list doit répondre");
        let tools = resp["result"]["tools"].as_array().expect("tools est un tableau");
        assert_eq!(tools.len(), 1);
        let tool = &tools[0];
        assert_eq!(tool["name"], TOOL_NAME);
        let props = &tool["inputSchema"]["properties"];
        assert_eq!(props["path"]["type"], "string");
        assert_eq!(props["patch"]["type"], "string");
        let required = tool["inputSchema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "path"));
        assert!(required.iter().any(|v| v == "patch"));
    }

    #[test]
    fn tools_call_success_returns_plan_hash_and_approval_url() {
        let req = json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": TOOL_NAME, "arguments": { "path": "C:/vault/n.md", "patch": "NEW" } }
        });
        let resp = handle_request(&req, &StubExecutor).expect("tools/call doit répondre");
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["structuredContent"]["plan_hash"], "a".repeat(64));
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("plan_hash"));
        assert!(text.contains("approval_url"));
    }

    #[test]
    fn tools_call_with_missing_patch_is_invalid_params() {
        let req = json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": TOOL_NAME, "arguments": { "path": "C:/vault/n.md" } }
        });
        let resp = handle_request(&req, &StubExecutor).expect("doit répondre");
        assert_eq!(resp["error"]["code"], error_code::INVALID_PARAMS);
        assert!(resp["error"]["message"].as_str().unwrap().contains("patch"));
    }

    #[test]
    fn tools_call_with_wrong_type_param_is_invalid_params() {
        let req = json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": TOOL_NAME, "arguments": { "path": 123, "patch": "NEW" } }
        });
        let resp = handle_request(&req, &StubExecutor).expect("doit répondre");
        assert_eq!(resp["error"]["code"], error_code::INVALID_PARAMS);
    }

    #[test]
    fn tools_call_unknown_tool_is_method_not_found() {
        let req = json!({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": { "name": "run_bash", "arguments": {} }
        });
        let resp = handle_request(&req, &StubExecutor).expect("doit répondre");
        assert_eq!(resp["error"]["code"], error_code::METHOD_NOT_FOUND);
    }

    #[test]
    fn kernel_error_becomes_tool_error_not_protocol_error() {
        let req = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": TOOL_NAME, "arguments": { "path": "C:/etc/passwd", "patch": "X" } }
        });
        let resp = handle_request(&req, &FailingExecutor).expect("doit répondre");
        // Erreur d'OUTIL : réponse `result` avec isError=true, PAS un `error` JSON-RPC.
        assert!(resp.get("error").is_none());
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"].as_str().unwrap().contains("hors bail"));
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let req = json!({ "jsonrpc": "2.0", "id": 8, "method": "does/not/exist" });
        let resp = handle_request(&req, &StubExecutor).expect("doit répondre");
        assert_eq!(resp["error"]["code"], error_code::METHOD_NOT_FOUND);
    }

    #[test]
    fn initialized_notification_produces_no_response() {
        let req = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_request(&req, &StubExecutor).is_none(), "une notification ne renvoie rien");
    }

    #[test]
    fn notification_with_unknown_method_produces_no_response() {
        // Pas d'`id` ⟹ notification ⟹ silence même si la méthode est inconnue (règle JSON-RPC).
        let req = json!({ "jsonrpc": "2.0", "method": "some/random/notification" });
        assert!(handle_request(&req, &StubExecutor).is_none());
    }
}
