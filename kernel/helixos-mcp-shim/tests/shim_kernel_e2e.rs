#![forbid(unsafe_code)]
//! Tests d'intégration bout-en-bout du shim ↔ noyau : le VRAI client mTLS du shim se connecte à un
//! serveur qui exécute le VRAI `Kernel` du noyau via son format de fil exact, traite un
//! `helix_patch_note`, et rend `{plan_hash, approval_url}` — SANS appliquer (le shim planifie,
//! l'humain applique via la page d'approbation).

mod common;

use common::{generate_pki, spawn_kernel_like_server, temp_dir, TestPki};
use helixos_mcp_shim::config::ShimConfig;
use helixos_mcp_shim::kernel_client::{ClientTls, KernelError};
use helixos_mcp_shim::mcp::{ToolExecutor, ToolOutcome};
use helixos_mcp_shim::{serve_stdio, MtlsToolExecutor};
use std::path::PathBuf;

/// Écrit les trois PEM (CA, cert client, clé client) de la PKI de test sur disque et renvoie une
/// `ShimConfig` pointant dessus — exerce le vrai chemin `ClientTls::load` (fichiers PEM).
fn write_client_pems_and_config(
    pki: &TestPki,
    dir: &std::path::Path,
    kernel_addr: std::net::SocketAddr,
) -> ShimConfig {
    let ca_path = dir.join("ca.pem");
    let cert_path = dir.join("client.pem");
    let key_path = dir.join("client.key");
    std::fs::write(&ca_path, &pki.ca_pem).unwrap();
    std::fs::write(&cert_path, &pki.client.cert_pem).unwrap();
    std::fs::write(&key_path, &pki.client.key_pem).unwrap();

    ShimConfig {
        kernel_addr: kernel_addr.to_string(),
        approval_origin: "https://helix.test.ts.net".into(),
        ca_path,
        client_cert_path: cert_path,
        client_key_path: key_path,
        server_name: "localhost".into(),
    }
}

/// Cœur bout-en-bout : le client mTLS du shim envoie `ProposeFilePatch` au noyau et obtient un
/// plan_hash 64-hex ; le fichier cible N'EST PAS modifié (planification seule).
#[tokio::test]
async fn shim_client_gets_plan_hash_and_does_not_apply() {
    let pki = generate_pki();
    let vault = temp_dir("helix-shim-vault");
    let state = temp_dir("helix-shim-state");
    let note = vault.join("note.md");
    std::fs::write(&note, b"AVANT").unwrap();

    let addr = spawn_kernel_like_server(&pki, vault.clone(), state).await;
    let workdir = temp_dir("helix-shim-certs");
    let config = write_client_pems_and_config(&pki, &workdir, addr);
    let tls = ClientTls::load(&config.ca_path, &config.client_cert_path, &config.client_key_path)
        .expect("chargement des PEM client");

    let plan_hash = helixos_mcp_shim::kernel_client::propose_file_patch(
        &tls,
        &config.kernel_addr,
        &config.server_name,
        note.to_str().unwrap(),
        "NEW",
    )
    .await
    .expect("le noyau doit renvoyer un plan_hash");

    // plan_hash = sha256 hex : 64 caractères, tous hexadécimaux.
    assert_eq!(plan_hash.len(), 64, "un sha256 hex fait 64 caractères");
    assert!(plan_hash.chars().all(|c| c.is_ascii_hexdigit()), "plan_hash doit être hex");

    // Le shim PLANIFIE, il n'APPLIQUE pas : le fichier reste inchangé.
    assert_eq!(
        std::fs::read(&note).unwrap(),
        b"AVANT",
        "le shim ne doit jamais appliquer — le fichier doit rester inchangé"
    );
}

/// Chemin MCP complet : un `tools/call helix_patch_note` sur `serve_stdio`, avec le vrai
/// `MtlsToolExecutor` (client mTLS réel), produit un résultat MCP `{plan_hash, approval_url}` et
/// laisse le fichier intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_call_over_stdio_returns_plan_hash_and_approval_url() {
    let pki = generate_pki();
    let vault = temp_dir("helix-shim-vault2");
    let state = temp_dir("helix-shim-state2");
    let note = vault.join("doc.md");
    std::fs::write(&note, b"ORIGINAL").unwrap();

    let addr = spawn_kernel_like_server(&pki, vault.clone(), state).await;
    let workdir = temp_dir("helix-shim-certs2");
    let config = write_client_pems_and_config(&pki, &workdir, addr);
    let tls = ClientTls::load(&config.ca_path, &config.client_cert_path, &config.client_key_path)
        .expect("chargement des PEM client");

    // La boucle stdio est synchrone et l'exécuteur bloque sur le runtime courant ; on l'exécute
    // donc sur un thread bloquant dédié (jamais un worker de l'executor, sinon `block_on` panique).
    let handle = tokio::runtime::Handle::current();
    let note_str = note.to_str().unwrap().to_string();
    let approval_origin = config.approval_origin.clone();
    let output = tokio::task::spawn_blocking(move || {
        let executor = MtlsToolExecutor::new(tls, config, handle);
        let request = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "helix_patch_note", "arguments": { "path": note_str, "patch": "PATCHED" } }
        });
        let input = format!("{request}\n");
        let mut out = Vec::new();
        serve_stdio(input.as_bytes(), &mut out, &executor).unwrap();
        String::from_utf8(out).unwrap()
    })
    .await
    .expect("thread stdio");

    let resp: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
    assert_eq!(resp["result"]["isError"], false, "réponse: {output}");
    let plan_hash = resp["result"]["structuredContent"]["plan_hash"].as_str().unwrap();
    assert_eq!(plan_hash.len(), 64);
    let approval_url = resp["result"]["structuredContent"]["approval_url"].as_str().unwrap();
    assert_eq!(approval_url, format!("{approval_origin}/op/{plan_hash}"));

    // Toujours pas d'application.
    assert_eq!(std::fs::read(&note).unwrap(), b"ORIGINAL");
}

/// Un cert client signé par une CA ÉTRANGÈRE (inconnue du noyau) est refusé : le noyau exige un
/// cert dont l'émetteur est dans ses racines. On construit un `ClientTls` avec la bonne CA
/// (racines) mais une feuille cliente d'une autre PKI → le handshake mTLS échoue.
#[tokio::test]
async fn foreign_ca_client_cert_is_rejected() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    let pki = generate_pki();
    let vault = temp_dir("helix-shim-vault3");
    let state = temp_dir("helix-shim-state3");
    std::fs::write(vault.join("n.md"), b"X").unwrap();
    let addr = spawn_kernel_like_server(&pki, vault.clone(), state).await;

    // Une PKI totalement indépendante : sa feuille cliente n'est PAS signée par la CA du noyau.
    let foreign = generate_pki();
    let ca_roots = common::ca_roots(&pki); // le client fait bien confiance au serveur…
    let foreign_certs = vec![CertificateDer::from(foreign.client.cert_der.clone())];
    let foreign_key =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(foreign.client.key_pkcs8_der.clone()));
    // …mais présente une identité cliente d'une autre CA.
    let tls = ClientTls::from_der(ca_roots, foreign_certs, foreign_key);

    let result = helixos_mcp_shim::kernel_client::propose_file_patch(
        &tls,
        &addr.to_string(),
        "localhost",
        "C:/whatever/n.md",
        "NEW",
    )
    .await;

    match result {
        Err(KernelError::Transport(_)) | Err(KernelError::Protocol(_)) => {} // refusé au handshake/flux
        other => panic!("un cert client d'une autre CA doit être refusé, obtenu: {other:?}"),
    }
}

/// Une intention hors bail de portée → le noyau répond `{"error":…}` → le client la remonte en
/// `KernelRefused` → la couche MCP la présente en erreur d'OUTIL (`isError: true`), pas un panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn out_of_lease_path_surfaces_as_tool_error() {
    let pki = generate_pki();
    let vault = temp_dir("helix-shim-vault4");
    let state = temp_dir("helix-shim-state4");
    std::fs::write(vault.join("n.md"), b"X").unwrap();
    let addr = spawn_kernel_like_server(&pki, vault.clone(), state).await;
    let workdir = temp_dir("helix-shim-certs4");
    let config = write_client_pems_and_config(&pki, &workdir, addr);
    let tls = ClientTls::load(&config.ca_path, &config.client_cert_path, &config.client_key_path)
        .unwrap();

    // Un chemin hors du bail (`vault`) : le noyau refuse.
    let outside = PathBuf::from("C:/Windows/system32/drivers/etc/hosts");
    let handle = tokio::runtime::Handle::current();
    let outside_str = outside.to_str().unwrap().to_string();
    let outcome = tokio::task::spawn_blocking(move || {
        let executor = MtlsToolExecutor::new(tls, config, handle);
        executor.patch_note(&outside_str, "P")
    })
    .await
    .unwrap();

    match outcome {
        ToolOutcome::Err(msg) => assert!(
            msg.contains("hors bail") || msg.contains("refus"),
            "message de refus attendu, obtenu: {msg}"
        ),
        ToolOutcome::Ok { .. } => panic!("une intention hors bail ne doit jamais produire un plan_hash"),
    }
}
