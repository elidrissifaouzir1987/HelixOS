#![forbid(unsafe_code)]
//! Orchestration partagée des tests d'intégration du shim. **Fix de revue D1a : plus AUCUNE
//! réplique du fil du noyau.**
//!
//! Historiquement ce module montait un serveur mTLS « ressemblant au noyau » dont la boucle
//! d'acceptation RÉPLIQUAIT le contrat de `handle_authenticated_connection` en écrivant une forme
//! de fil PLATE codée à la main (`serde_json::json!({"plan_hash": …})`). Cette réplique partageait
//! le bug du parseur du shim et le validait mutuellement : le VRAI `WireResponse` du noyau émettait
//! alors du NESTED `{"plan_hash":{"plan_hash":…}}`, donc contre le vrai noyau chaque patch réussi
//! remontait en erreur de protocole — invisible en test car serveur-de-test et parseur partageaient
//! la même forme fausse.
//!
//! Désormais l'e2e monte le **VRAI serveur du noyau** via
//! `helixos_kernel::mtls::spawn_test_server_returning_certs` (feature `test-harness`) : le VRAI
//! `handle_authenticated_connection` (handler de PRODUCTION, non copié) traite la connexion et écrit
//! le fil réel. Ce module ne fait plus qu'ORCHESTRER : il récupère la `TestCerts` renvoyée, en
//! dérive le matériel client (PEM sur disque → exerce `ClientTls::load`) et une `ShimConfig`
//! pointant sur l'adresse du serveur. Si le fil du noyau est incohérent avec ce que le shim parse,
//! l'e2e ÉCHOUE (auto-preuve du contrat de fil).

use helixos_kernel::mtls::{spawn_test_server_returning_certs, TestCerts};
use helixos_mcp_shim::config::ShimConfig;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Monte le **VRAI** serveur mTLS de test du noyau sur `127.0.0.1:0` (VRAI `Kernel`, VRAI
/// `build_server_config`, VRAI `handle_authenticated_connection`) avec `lease_root` comme unique
/// racine louée et `state_dir` comme état persistant, et renvoie son adresse + la `TestCerts` (CA +
/// serveur + client) que ce serveur accepte — de quoi construire un client mTLS externe.
pub async fn spawn_real_kernel_server(
    lease_root: PathBuf,
    state_dir: PathBuf,
) -> (SocketAddr, TestCerts) {
    spawn_test_server_returning_certs(lease_root, state_dir).await
}

/// Écrit les trois PEM (CA, cert client, clé client) de la `TestCerts` du noyau sur disque et
/// renvoie une `ShimConfig` pointant dessus — exerce le VRAI chemin `ClientTls::load` (fichiers
/// PEM). Le cert client est celui que le serveur du noyau accepte (même CA).
pub fn write_client_pems_and_config(
    certs: &TestCerts,
    dir: &Path,
    kernel_addr: SocketAddr,
) -> ShimConfig {
    let ca_path = dir.join("ca.pem");
    let cert_path = dir.join("client.pem");
    let key_path = dir.join("client.key");
    std::fs::write(&ca_path, &certs.ca_pem).expect("écriture CA PEM");
    std::fs::write(&cert_path, &certs.client.cert_pem).expect("écriture cert client PEM");
    std::fs::write(&key_path, &certs.client.key_pem).expect("écriture clé client PEM");

    ShimConfig {
        kernel_addr: kernel_addr.to_string(),
        approval_origin: "https://helix.test.ts.net".into(),
        ca_path,
        client_cert_path: cert_path,
        client_key_path: key_path,
        // Le cert serveur du noyau porte le SAN `localhost` (voir `generate_test_certs`).
        server_name: "localhost".into(),
    }
}

/// Un répertoire temporaire unique pour un test (auto-nettoyé best-effort par l'OS ; suffisant
/// pour un harness de test).
pub fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("création du répertoire temporaire de test");
    dir
}
