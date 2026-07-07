#![forbid(unsafe_code)]
//! Harness partagé des tests d'intégration du shim : génération de certs mTLS (CA + serveur +
//! client, via `rcgen` en pur Rust) et montage d'un **serveur mTLS de test qui parle le format de
//! fil EXACT du noyau**.
//!
//! Pourquoi ce serveur est monté ici plutôt qu'avec `helixos_kernel::mtls::spawn_test_server` :
//! `spawn_test_server` génère ses propres certs et ne les expose que via un registre process-
//! interne PRIVÉ — un client mTLS externe (le vrai client du shim, testé ici) ne peut donc pas
//! récupérer le certificat client que ce serveur accepterait. On réutilise à la place les briques
//! PUBLIQUES du noyau : `build_server_config` (assemblage `ServerConfig` mTLS, exige un cert
//! client valide) et `Kernel::new` (le vrai pipeline). La boucle d'acceptation réplique
//! fidèlement le contrat de `handle_authenticated_connection` (privé) : lit UNE ligne JSON
//! `Intention` → `Kernel::plan_intention` → écrit `{"plan_hash":…}` ou `{"error":…}`. Le noyau
//! reste la source de vérité du format de fil ; on n'en invente aucun octet.

use helixos_kernel::intention::Intention;
use helixos_kernel::mtls::build_server_config;
use helixos_kernel::pipeline::Kernel;
use helixos_kernel::scope::ScopeLease;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Une paire cert+clé au format PEM (chaînes) ET DER (octets), pour couvrir les deux besoins :
/// écrire des fichiers PEM que le shim charge (`ClientTls::load`), et construire des configs
/// rustls (DER).
pub struct PemLeaf {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
}

/// CA + serveur + client, tous signés par la même CA. `ca_pem`/`ca_der` = la racine de confiance.
pub struct TestPki {
    pub ca_pem: String,
    pub ca_der: Vec<u8>,
    pub server: PemLeaf,
    pub client: PemLeaf,
}

fn make_leaf(cn: &str, sans: Vec<String>, ca_params: &CertificateParams, ca_key: &KeyPair) -> PemLeaf {
    let key = KeyPair::generate().expect("génération de clé feuille");
    let mut params = CertificateParams::new(sans).expect("SANs valides");
    params.distinguished_name.push(DnType::CommonName, cn);
    let issuer = Issuer::from_params(ca_params, ca_key);
    let cert = params.signed_by(&key, &issuer).expect("signature de la feuille par la CA");
    PemLeaf {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().to_vec(),
        key_pkcs8_der: key.serialize_der(),
    }
}

/// Génère une PKI de test complète en pur Rust : CA auto-signée, cert serveur (SAN
/// `localhost`/`127.0.0.1`, pour que la vérification de nom TLS côté client réussisse avec
/// `server_name = "localhost"`) et cert client (CN `helix-shim-test`, l'identité d'appelant vue
/// par le noyau).
pub fn generate_pki() -> TestPki {
    let ca_key = KeyPair::generate().expect("génération de la clé CA");
    let mut ca_params = CertificateParams::new(vec!["Helix Shim Test CA".into()]).expect("params CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "Helix Shim Test CA");
    let ca_cert = ca_params.clone().self_signed(&ca_key).expect("auto-signature CA");

    let server = make_leaf(
        "helixos-kernel-test-server",
        vec!["localhost".into(), "127.0.0.1".into()],
        &ca_params,
        &ca_key,
    );
    let client = make_leaf("helix-shim-test", vec!["helix-shim-test".into()], &ca_params, &ca_key);

    TestPki { ca_pem: ca_cert.pem(), ca_der: ca_cert.der().to_vec(), server, client }
}

/// Racines de confiance (la CA) sous forme `RootCertStore` pour la config serveur.
pub fn ca_roots(pki: &TestPki) -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca_der.clone()))
        .expect("ajout de la CA de test aux racines");
    Arc::new(roots)
}

fn server_cert(pki: &TestPki) -> CertificateDer<'static> {
    CertificateDer::from(pki.server.cert_der.clone())
}
fn server_key(pki: &TestPki) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server.key_pkcs8_der.clone()))
}

/// Monte un serveur mTLS de test sur `127.0.0.1:0` avec le VRAI `Kernel` du noyau (bail =
/// `lease_root`, état = `state_dir`) et le VRAI `build_server_config` (exige un cert client
/// valide). Renvoie l'adresse d'écoute. La boucle réplique le contrat de fil du noyau
/// (`Intention` JSON une ligne → `plan_intention` → `{"plan_hash":…}`/`{"error":…}`).
pub async fn spawn_kernel_like_server(
    pki: &TestPki,
    lease_root: PathBuf,
    state_dir: PathBuf,
) -> SocketAddr {
    let server_config = build_server_config(ca_roots(pki), server_cert(pki), server_key(pki));
    let acceptor = TlsAcceptor::from(server_config);

    let lease = ScopeLease { task_id: "shim-caller".into(), roots: vec![lease_root] };
    let kernel = Kernel::new(state_dir, lease).expect("création du noyau de test");
    let kernel = Arc::new(tokio::sync::Mutex::new(kernel));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind serveur de test");
    let addr = listener.local_addr().expect("adresse locale");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let kernel = kernel.clone();
            tokio::spawn(async move {
                // Un handshake refusé (pas de cert client) termine ici sans bruit — comportement
                // attendu, pas une erreur serveur.
                if let Ok(tls) = acceptor.accept(stream).await {
                    let _ = handle_conn(tls, kernel).await;
                }
            });
        }
    });

    addr
}

/// Réplique fidèle du contrat de fil du noyau (`handle_authenticated_connection`, privé) : lit une
/// ligne JSON `Intention`, la passe à `Kernel::plan_intention`, renvoie `{"plan_hash":…}` en cas
/// de succès ou `{"error":…}` en cas de refus fonctionnel — le format EXACT que le client du shim
/// sait parser.
async fn handle_conn(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    kernel: Arc<tokio::sync::Mutex<Kernel>>,
) -> std::io::Result<()> {
    // Identité de l'appelant dérivée du certificat client (le noyau réel extrait le CN ; ici on
    // fixe une étiquette stable, l'objet du test est le format de fil et le plan_hash).
    let caller = "helix-shim-test";

    let (reader, mut writer) = tokio::io::split(tls);
    let mut lines = BufReader::new(reader).lines();
    let Some(line) = lines.next_line().await? else {
        return Ok(());
    };

    let response = match serde_json::from_str::<Intention>(&line) {
        Ok(intention) => {
            let mut k = kernel.lock().await;
            match k.plan_intention(caller, caller, intention, false) {
                Ok(plan) => serde_json::json!({ "plan_hash": plan.plan_hash }),
                Err(e) => serde_json::json!({ "error": e }),
            }
        }
        Err(e) => serde_json::json!({ "error": format!("intention JSON invalide: {e}") }),
    };

    let mut out = serde_json::to_string(&response)?;
    out.push('\n');
    writer.write_all(out.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Un répertoire temporaire unique pour un test (auto-nettoyé best-effort par l'OS ; suffisant
/// pour un harness de test).
pub fn temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("création du répertoire temporaire de test");
    dir
}
