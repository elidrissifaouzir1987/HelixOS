#![forbid(unsafe_code)]
//! Test d'ASSEMBLAGE du service noyau HelixOS (bootstrap MVP-0).
//!
//! Propriété NOUVELLE prouvée ici (au-delà de B8/C2 pris séparément) : quand le service monte les
//! DEUX serveurs (mTLS pour les appelants + micro-page HTTPS d'approbation) sur UN SEUL
//! `SharedKernel` commun — via le VRAI chemin de production `runtime::bind`/`Service::serve`, y
//! compris le chargement des certificats DEPUIS LE DISQUE (comme `helixos-provision` les écrit) —
//! alors un plan créé par un appelant sur la frontière mTLS est immédiatement visible ET
//! approuvable sur la page HTTPS, et son approbation applique réellement le patch au fichier vault.
//!
//! Chaîne bout-en-bout, sans shim ni Hermes :
//!   1. un client mTLS envoie `ProposeFilePatch{path: <note vault>, patch:"NEW"}` -> `plan_hash` réel ;
//!   2. `GET https://.../op/<plan_hash>` sur le serveur d'APPROBATION rend la CARTE de CE plan
//!      (preuve que les deux serveurs partagent le MÊME `Kernel` — le plan n'a jamais transité par
//!      la page, seulement par mTLS) ;
//!   3. `POST /op/<plan_hash>/approve` (plan L1) -> le noyau APPLIQUE -> le fichier vault vaut "NEW"
//!      et l'audit est écrit ;
//!   4. le fichier valait "AVANT" au départ (preuve d'un apply réel, pas d'un no-op).
//!
//! Gated `test-harness` : la génération des certificats de test s'appuie sur `generate_test_certs`
//! (qui tire `rcgen` UNIQUEMENT sous cette feature) ; le binaire de production ne compile jamais
//! `rcgen`. Les certs de test sont ÉCRITS SUR DISQUE puis rechargés par `runtime::bind`, de sorte
//! que le test exerce exactement le chemin de chargement PEM de production (`runtime::load_certs`).
#![cfg(feature = "test-harness")]

use helixos_kernel::intention::Intention;
use helixos_kernel::mtls::generate_test_certs;
use helixos_kernel::runtime::{self, Config};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Écrit une PKI de test sur disque dans `cert_dir`, dans la disposition EXACTE attendue par
/// `runtime::load_certs` (les mêmes noms de fichiers que `helixos-provision` produit). Le cert
/// serveur de test (SAN `localhost` + `127.0.0.1`) sert à la fois pour le serveur mTLS et pour le
/// serveur d'approbation : les deux sont atteints via `localhost` dans le test. La CA + le cert
/// client servent au client mTLS. Renvoie les PEM de la CA et du client pour le client mTLS.
struct TestPki {
    ca_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn write_test_pki(cert_dir: &Path) -> TestPki {
    let certs = generate_test_certs();
    // Serveur mTLS ET serveur d'approbation partagent le même cert de test (SAN localhost).
    std::fs::write(cert_dir.join("ca.pem"), &certs.ca_pem).unwrap();
    std::fs::write(cert_dir.join("mtls-server.pem"), &certs.server.cert_pem).unwrap();
    std::fs::write(cert_dir.join("mtls-server.key"), &certs.server.key_pem).unwrap();
    std::fs::write(cert_dir.join("approval-server.pem"), &certs.server.cert_pem).unwrap();
    std::fs::write(cert_dir.join("approval-server.key"), &certs.server.key_pem).unwrap();
    TestPki {
        ca_pem: certs.ca_pem,
        client_cert_pem: certs.client.cert_pem,
        client_key_pem: certs.client.key_pem,
    }
}

fn certs_from_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes()).collect::<Result<Vec<_>, _>>().unwrap()
}

fn key_from_pem(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut pem.as_bytes()).unwrap().expect("clé privée PEM")
}

fn client_roots(ca_pem: &str) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in certs_from_pem(ca_pem) {
        roots.add(cert).unwrap();
    }
    roots
}

/// Client mTLS minimal (cohérent avec le pattern déjà utilisé par `mtls::test_harness` et le
/// shim) : présente le certificat client de test signé par la CA, envoie `intention` en JSON (une
/// ligne) sur le canal authentifié, et renvoie la ligne de réponse brute du noyau.
async fn mtls_propose(
    mtls_addr: std::net::SocketAddr,
    pki: &TestPki,
    intention: &Intention,
) -> String {
    let client_config = ClientConfig::builder()
        .with_root_certificates(client_roots(&pki.ca_pem))
        .with_client_auth_cert(certs_from_pem(&pki.client_cert_pem), key_from_pem(&pki.client_key_pem))
        .expect("assemblage du ClientConfig mTLS de test");
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(mtls_addr).await.expect("connexion TCP au serveur mTLS");
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.expect("handshake mTLS");

    let (reader, mut writer) = tokio::io::split(tls);
    let mut line = serde_json::to_string(intention).unwrap();
    line.push('\n');
    writer.write_all(line.as_bytes()).await.expect("écriture de l'intention");
    writer.flush().await.expect("flush de l'intention");

    let mut lines = BufReader::new(reader).lines();
    lines
        .next_line()
        .await
        .expect("lecture de la réponse mTLS")
        .expect("le noyau doit renvoyer une ligne de réponse")
}

/// Client HTTPS minimal fait main (pas de dépendance HTTP-client) : fait confiance à la CA de test
/// et exécute une requête HTTP/1.1 `method path` sur le serveur d'approbation, renvoyant
/// (ligne de statut, corps). `Connection: close` pour que le serveur ferme après la réponse (le
/// corps est alors tout ce qui suit les en-têtes jusqu'à EOF).
async fn https_request(
    approval_addr: std::net::SocketAddr,
    ca_pem: &str,
    method: &str,
    path: &str,
) -> (String, String) {
    let client_config = ClientConfig::builder()
        .with_root_certificates(client_roots(ca_pem))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(approval_addr).await.expect("connexion TCP au serveur d'approbation");
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.expect("handshake HTTPS d'approbation");

    let req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.expect("écriture de la requête HTTP");
    tls.flush().await.expect("flush de la requête HTTP");

    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await.expect("lecture de la réponse HTTP jusqu'à EOF");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (headers, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status_line = headers.lines().next().unwrap_or("").to_string();
    (status_line, body.to_string())
}

/// Monte le service assemblé (les DEUX serveurs sur un `SharedKernel` commun) via le VRAI chemin
/// `runtime::bind` (certs chargés depuis le disque) et le sert en tâche de fond. Renvoie les
/// adresses effectives des deux ports (`:0` -> port choisi par l'OS).
async fn spawn_assembled_service(config: &Config) -> (std::net::SocketAddr, std::net::SocketAddr) {
    let service = runtime::bind(config).await.expect("assemblage du service (runtime::bind)");
    let mtls_addr = service.mtls_addr;
    let approval_addr = service.approval_addr;
    tokio::spawn(async move {
        // `pending()` : jamais de shutdown demandé — le service tourne tant que le test vit.
        let _ = service.serve(std::future::pending::<()>()).await;
    });
    (mtls_addr, approval_addr)
}

/// LE test d'assemblage bout-en-bout : mTLS -> plan partagé -> approbation -> apply, sur UN noyau.
#[tokio::test]
async fn mtls_created_plan_is_approvable_on_the_shared_https_page_and_applies() {
    // --- Vault + note "AVANT" (l'état de départ, pour prouver un apply réel en fin de test) ---
    let vault = temp_dir("helix-bootstrap-vault");
    let state_dir = temp_dir("helix-bootstrap-state");
    let cert_dir = temp_dir("helix-bootstrap-certs");
    let note = vault.join("note.md");
    std::fs::write(&note, b"AVANT").unwrap();

    let pki = write_test_pki(&cert_dir);

    // Config du service : ports `:0` (OS), bail sur le vault, PKI depuis le disque.
    let config = Config {
        state_dir,
        vault_roots: vec![vault.clone()],
        cert_dir,
        mtls_addr: "127.0.0.1:0".into(),
        approval_addr: "127.0.0.1:0".into(),
        approval_origin: "https://localhost".into(),
        task_id: "bootstrap-it".into(),
    };
    let (mtls_addr, approval_addr) = spawn_assembled_service(&config).await;

    // --- (1) mTLS : un appelant authentifié crée un plan -> plan_hash réel ---
    let intention = Intention::ProposeFilePatch { path: note.clone(), patch: "NEW".into() };
    let mtls_response = mtls_propose(mtls_addr, &pki, &intention).await;
    // Le fil mTLS est PLAT : {"plan_hash":"..."} (cf. mtls::WireResponse). On extrait le hash.
    let parsed: serde_json::Value =
        serde_json::from_str(&mtls_response).expect("réponse mTLS JSON valide");
    let plan_hash = parsed
        .get("plan_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("la réponse mTLS doit porter un plan_hash, reçu: {mtls_response}"))
        .to_string();
    assert_eq!(plan_hash.len(), 64, "plan_hash doit être un sha256 hex");
    assert!(plan_hash.chars().all(|c| c.is_ascii_hexdigit()));

    // Le fichier vault est ENCORE "AVANT" : créer un plan ne l'applique pas (l'approbation le fera).
    assert_eq!(
        std::fs::read(&note).unwrap(),
        b"AVANT",
        "créer un plan via mTLS ne doit PAS encore modifier le fichier"
    );

    // --- (2) Approbation (autre serveur, MÊME noyau) : GET /op/<hash> rend la carte de CE plan ---
    // C'est LA preuve de partage : le plan n'a été créé QUE via mTLS, jamais via la page ; s'il
    // apparaît ici, c'est que les deux serveurs partagent le même Kernel.
    let (status, body) = https_request(approval_addr, &pki.ca_pem, "GET", &format!("/op/{plan_hash}")).await;
    assert!(status.contains("200"), "GET /op/<hash> du plan mTLS doit répondre 200 sur la page: {status}");
    assert!(
        body.contains(&plan_hash),
        "la carte d'approbation doit référencer le plan_hash créé via mTLS (preuve de noyau partagé)"
    );
    for label in ["QUOI", "OÙ", "RISQUE", "POURQUOI", "INHABITUEL"] {
        assert!(body.contains(label), "section {label} absente de la carte rendue: {body}");
    }

    // --- (3) POST /op/<hash>/approve (plan L1) -> le noyau applique -> fichier == "NEW" ---
    let (approve_status, _approve_body) =
        https_request(approval_addr, &pki.ca_pem, "POST", &format!("/op/{plan_hash}/approve")).await;
    assert!(
        approve_status.contains("200"),
        "l'approbation d'un plan L1 doit appliquer (200): {approve_status}"
    );

    // --- (4) Preuve de l'apply RÉEL : le fichier vault, "AVANT" au départ, vaut maintenant "NEW" ---
    assert_eq!(
        std::fs::read(&note).unwrap(),
        b"NEW",
        "après approbation, le fichier vault doit être réellement patché en 'NEW' (apply réel)"
    );

    // L'audit du noyau PARTAGÉ référence le plan appliqué (écrit dans le state-dir du service).
    let audit = std::fs::read_to_string(config.state_dir.join("audit.jsonl"))
        .expect("audit.jsonl doit exister après une approbation appliquée");
    assert!(audit.contains(&plan_hash), "l'audit doit référencer le plan_hash appliqué");
    assert!(audit.contains("apply_file_patch"), "l'audit doit tracer l'opération d'apply");

    // Rejeu : ré-approuver le même plan doit être refusé (409) — preuve supplémentaire que le
    // premier POST a traversé le VRAI Kernel::apply (usage unique), pas un stub.
    let (replay_status, _) =
        https_request(approval_addr, &pki.ca_pem, "POST", &format!("/op/{plan_hash}/approve")).await;
    assert!(
        replay_status.contains("409"),
        "rejeu du même plan_hash doit être refusé (409), preuve du single-use réel: {replay_status}"
    );
}
