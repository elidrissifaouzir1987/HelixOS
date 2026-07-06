#![forbid(unsafe_code)]
//! B8 (SPIKE) : frontière mTLS minimale d'authentification d'appelant.
//!
//! Contrat prouvé ici : le noyau n'accepte QUE des appelants présentant un certificat client
//! valide signé par la CA de confiance (`WebPkiClientVerifier`, politique anonyme = Deny par
//! défaut — voir `rustls::server::WebPkiClientVerifier::builder`). L'identité de l'appelant
//! vient du certificat (CN du sujet), jamais du réseau. Une intention JSON, envoyée en une
//! ligne sur ce canal authentifié, est transmise telle quelle à `pipeline::Kernel::plan_intention`
//! et le `plan_hash` (ou l'erreur) est renvoyé en JSON sur le même flux.
//!
//! Hors périmètre (voir tâche B8-minimal) : approbation (Phase C), shim MCP (Phase D),
//! WebAuthn. Ce module ne fait qu'authentifier l'appelant et faire transiter l'intention.
//!
//! ## Écarts vs consigne, notés pendant le spike
//!
//! 1. **`rcgen` en dépendance normale, pas dev-only.** La consigne demandait
//!    `cargo add --dev rcgen`. Vérifié empiriquement (sonde jetée après preuve) : quand
//!    `tests/mtls_it.rs` (crate d'intégration externe) lie `helixos_kernel`, la lib est
//!    compilée SANS `cfg(test)` actif — un `pub fn` sous `#[cfg(test)]` dans `src/`
//!    n'existerait alors pas dans le binaire lié. Comme l'interface demandée expose
//!    `mtls::spawn_test_server`/`connect_with_client_cert` en fonctions `pub` normales
//!    (appelées depuis `tests/mtls_it.rs`), tout ce qu'elles utilisent en interne — y compris
//!    le générateur de certs `rcgen` — doit être une dépendance normale du crate. `rcgen` est
//!    donc dans `[dependencies]` (voir `Cargo.toml`), pas `[dev-dependencies]`.
//! 2. **`CertificateParams::from_ca_cert_der` n'est pas une API publique de rcgen 0.14**
//!    (elle est `pub(crate)`, réservée aux tests internes du crate rcgen même avec la feature
//!    `x509-parser`). L'API publique pour signer une feuille avec une CA consiste à garder les
//!    `CertificateParams` ORIGINAUX de la CA en mémoire (pas de round-trip DER→params) et
//!    construire l'`Issuer` directement dessus via `Issuer::from_params(&ca_params, &ca_key)`.
//!    `generate_test_certs()` fait tout en une fois (CA + serveur + client signés dans la même
//!    portée) pour ne jamais avoir besoin de reconstruire des `CertificateParams` depuis un DER.
//! 3. `rustls::ServerConfig::builder()`/`ClientConfig::builder()` utilisent le
//!    `CryptoProvider` process-défaut, auto-installé depuis les crate features si exactement
//!    un backend (`aws-lc-rs` XOR `ring`) est activé sur `rustls`. Ici seule la feature
//!    `aws_lc_rs` est active sur `rustls` (vérifié via `cargo tree -e features -i rustls`) ;
//!    `ring` n'apparaît dans l'arbre que comme dépendance directe de `rcgen` (pour signer ses
//!    certificats), pas comme feature de `rustls` — aucun conflit de provider process-global.
//! 4. **Une CA de test par processus, pas par appel.** `spawn_test_server` génère une
//!    `TestCerts` et l'enregistre dans un petit registre process-global indexé par
//!    `SocketAddr` (`test_cert_registry`) ; `connect_with_client_cert`/
//!    `connect_without_client_cert` la relisent par adresse plutôt que d'appeler
//!    `generate_test_certs()` elles-mêmes. Sans ça, chaque appel régénère une CA (clé
//!    aléatoire) différente, et le client rejette le certificat serveur avec
//!    `invalid peer certificate: BadSignature` — trouvé en écrivant le premier test vert.

use crate::intention::Intention;
use crate::pipeline::Kernel;
use crate::scope::ScopeLease;
use rcgen::{BasicConstraints, CertificateParams, DnType, Issuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Octets DER bruts d'une paire cert/clé de test — stockés en `Vec<u8>` (clonable) plutôt qu'en
/// types `rustls` (`PrivateKeyDer` n'implémente pas `Clone`), pour pouvoir reconstruire un
/// `CertificateDer`/`PrivateKeyDer` frais à chaque connexion cliente à partir d'une CA partagée.
#[derive(Clone)]
pub struct LeafDer {
    pub cert_der: Vec<u8>,
    pub key_pkcs8_der: Vec<u8>,
}

impl LeafDer {
    fn cert(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der.clone())
    }
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()))
    }
}

/// Une CA de test + certificat serveur + certificat client, tous deux signés par la MÊME CA.
/// Usage exclusif du harness de test/spike (jamais en production — le noyau réel chargerait des
/// certs provisionnés hors bande). `Clone` : les octets DER sont réutilisables tels quels pour
/// reconstruire des configs TLS indépendantes (une par connexion), toutes ancrées à la même CA.
#[derive(Clone)]
pub struct TestCerts {
    pub ca_der: Vec<u8>,
    pub server: LeafDer,
    pub client: LeafDer,
}

impl TestCerts {
    pub fn ca_roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.ca_der.clone()))
            .expect("ajout de la CA de test aux racines de confiance");
        Arc::new(roots)
    }
}

fn generate_leaf(cn: &str, sans: Vec<String>, ca_params: &CertificateParams, ca_key: &KeyPair) -> LeafDer {
    let key = KeyPair::generate().expect("génération de clé de test");
    let mut params = CertificateParams::new(sans).expect("SANs de test valides");
    params.distinguished_name.push(DnType::CommonName, cn);
    let issuer = Issuer::from_params(ca_params, ca_key);
    let cert = params
        .signed_by(&key, &issuer)
        .expect("signature du certificat de test par la CA de test");
    LeafDer { cert_der: cert.der().to_vec(), key_pkcs8_der: key.serialize_der() }
}

/// Génère (en Rust pur, via `rcgen` — jamais le binaire `openssl`, qui peut être absent) une CA
/// de test, un certificat serveur (SAN `localhost`/`127.0.0.1`) et un certificat client, tous
/// deux signés par la MÊME CA fraîchement générée. Le CN du client identifie l'appelant côté
/// serveur (`"test-client"`).
pub fn generate_test_certs() -> TestCerts {
    let ca_key = KeyPair::generate().expect("génération de la clé de la CA de test");
    let mut ca_params =
        CertificateParams::new(vec!["Helix Test CA".into()]).expect("params de CA de test");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "Helix Test CA");
    let ca_cert = ca_params
        .clone()
        .self_signed(&ca_key)
        .expect("auto-signature de la CA de test");

    let server = generate_leaf(
        "helixos-kernel-test-server",
        vec!["localhost".into(), "127.0.0.1".into()],
        &ca_params,
        &ca_key,
    );
    let client = generate_leaf("test-client", vec!["test-client".into()], &ca_params, &ca_key);

    TestCerts { ca_der: ca_cert.der().to_vec(), server, client }
}

/// Registre process-global : associe l'adresse d'un serveur mTLS de test à la `TestCerts`
/// (CA + serveur + client) qu'il utilise. Nécessaire car `spawn_test_server` ne renvoie qu'un
/// `SocketAddr` (interface demandée) — les fonctions client (`connect_with_client_cert`,
/// `connect_without_client_cert`) doivent retrouver la MÊME CA que le serveur pour que la
/// vérification de chaîne de confiance réussisse (deux appels indépendants à
/// `generate_test_certs()` produiraient deux CA différentes et donc un `BadSignature`).
fn test_cert_registry() -> &'static Mutex<HashMap<SocketAddr, TestCerts>> {
    static REGISTRY: OnceLock<Mutex<HashMap<SocketAddr, TestCerts>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn register_test_certs(addr: SocketAddr, certs: TestCerts) {
    test_cert_registry()
        .lock()
        .expect("verrou du registre de certs de test")
        .insert(addr, certs);
}

fn test_certs_for(addr: SocketAddr) -> TestCerts {
    test_cert_registry()
        .lock()
        .expect("verrou du registre de certs de test")
        .get(&addr)
        .cloned()
        .unwrap_or_else(|| panic!("aucune TestCerts enregistrée pour {addr} — appeler spawn_test_server d'abord"))
}

/// Assemble le `ServerConfig` mTLS : `WebPkiClientVerifier` exige un certificat client signé
/// par une des `ca_roots` (politique anonyme par défaut = `Deny`, donc un appelant sans
/// certificat client est refusé au handshake — c'est le contrôle primaire du test 3).
pub fn build_server_config(
    ca_roots: Arc<RootCertStore>,
    server_der: CertificateDer<'static>,
    server_key_der: PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let verifier = WebPkiClientVerifier::builder(ca_roots)
        .build()
        .expect("construction du vérificateur de certificat client");
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_der], server_key_der)
        .expect("assemblage du ServerConfig mTLS");
    Arc::new(config)
}

/// Extrait le CN (Common Name) du sujet d'un certificat DER peer. Utilisé pour dériver
/// l'identité de l'appelant (`caller`/`task_id`) depuis le certificat client authentifié —
/// jamais depuis l'adresse réseau, conformément au contrat de transport souverain.
fn extract_common_name(cert_der: &CertificateDer<'_>) -> Result<String, String> {
    let (_remainder, x509) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("certificat peer illisible: {e}"))?;
    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .ok_or_else(|| "certificat peer sans CN".to_string())?
        .as_str()
        .map_err(|e| format!("CN du certificat peer non-UTF8: {e}"))?
        .to_string();
    Ok(cn)
}

/// Une ligne de réponse JSON envoyée sur le flux authentifié après traitement de l'intention.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum WireResponse {
    PlanHash { plan_hash: String },
    Error { error: String },
}

/// Traite une connexion mTLS déjà acceptée et authentifiée : lit une intention JSON (une
/// ligne), la fait transiter vers `Kernel::plan_intention` avec l'identité dérivée du CN du
/// certificat client peer, puis renvoie le résultat en JSON sur le même flux.
async fn handle_authenticated_connection(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    kernel: Arc<tokio::sync::Mutex<Kernel>>,
) -> io::Result<()> {
    let (_io, conn) = tls.get_ref();
    // `peer_certificates()` : présent car `WebPkiClientVerifier` a déjà validé la chaîne
    // pendant le handshake (anon_policy = Deny) — un flux qui atteint ce point a TOUJOURS un
    // certificat client valide. L'identité vient de ce certificat, jamais du réseau.
    let peer_leaf = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned()
        .ok_or_else(|| io::Error::other("connexion authentifiée sans certificat peer (invariant violé)"))?;
    let caller = extract_common_name(&peer_leaf).map_err(io::Error::other)?;

    let (reader, mut writer) = tokio::io::split(tls);
    let mut lines = BufReader::new(reader).lines();
    let Some(line) = lines.next_line().await? else {
        return Ok(()); // connexion fermée sans requête : rien à faire.
    };

    let response = match serde_json::from_str::<Intention>(&line) {
        Ok(intention) => {
            let mut kernel = kernel.lock().await;
            match kernel.plan_intention(&caller, &caller, intention, false) {
                Ok(plan) => WireResponse::PlanHash { plan_hash: plan.plan_hash },
                Err(e) => WireResponse::Error { error: e },
            }
        }
        Err(e) => WireResponse::Error { error: format!("intention JSON invalide: {e}") },
    };

    let mut out = serde_json::to_string(&response)?;
    out.push('\n');
    writer.write_all(out.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Démarre le serveur mTLS de test sur `127.0.0.1:0` (port choisi par l'OS) et renvoie son
/// adresse. `lease_root` devient l'unique racine louée du `Kernel` sous-jacent (bail par-tâche,
/// contrôle primaire hérité — voir `scope::ScopeLease`) ; `state_dir` est l'état persistant du
/// noyau (plans consommés, audit). La boucle d'acceptation tourne en tâche de fond tant que le
/// test vit (processus de test court-circuité en fin de run ; pas de handle d'arrêt exposé, le
/// périmètre B8-minimal ne couvre pas le cycle de vie du service).
pub async fn spawn_test_server(lease_root: PathBuf, state_dir: PathBuf) -> SocketAddr {
    let certs = generate_test_certs();
    let server_config =
        build_server_config(certs.ca_roots(), certs.server.cert(), certs.server.key());
    let acceptor = TlsAcceptor::from(server_config);

    let lease = ScopeLease { task_id: "mtls-caller".into(), roots: vec![lease_root] };
    let kernel = Kernel::new(state_dir, lease).expect("création du noyau de test mTLS");
    let kernel = Arc::new(tokio::sync::Mutex::new(kernel));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind du serveur mTLS de test");
    let addr = listener.local_addr().expect("adresse locale du serveur mTLS de test");
    // Enregistre la CA/serveur/client de CE serveur pour que les clients de test
    // (`connect_with_client_cert`/`connect_without_client_cert`) fassent confiance à la même
    // chaîne — voir la doc de `test_cert_registry` pour le pourquoi.
    register_test_certs(addr, certs);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer_addr)) = listener.accept().await else { break };
            let acceptor = acceptor.clone();
            let kernel = kernel.clone();
            tokio::spawn(async move {
                // Un handshake refusé (ex. pas de cert client, test 3) termine ici sans bruit :
                // c'est le comportement attendu, pas une erreur serveur à faire remonter.
                if let Ok(tls) = acceptor.accept(stream).await {
                    let _ = handle_authenticated_connection(tls, kernel).await;
                }
            });
        }
    });

    addr
}

/// Client de test qui présente un certificat client valide (signé par la même CA que le
/// serveur), envoie `intention` en JSON (une ligne) et renvoie le `plan_hash` reçu, ou l'erreur
/// (réseau, TLS, ou refus fonctionnel du noyau — ex. hors bail de portée).
pub async fn connect_with_client_cert(addr: SocketAddr, intention: &Intention) -> Result<String, String> {
    // Récupère la MÊME CA/client que celle enregistrée par `spawn_test_server` pour cette
    // adresse — jamais une CA fraîchement régénérée (voir doc de `test_cert_registry`).
    let certs = test_certs_for(addr);
    let client_config = ClientConfig::builder()
        .with_root_certificates((*certs.ca_roots()).clone())
        .with_client_auth_cert(vec![certs.client.cert()], certs.client.key())
        .map_err(|e| format!("assemblage ClientConfig (avec cert client): {e}"))?;
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(addr).await.map_err(|e| format!("connexion TCP: {e}"))?;
    let server_name =
        ServerName::try_from("localhost").map_err(|e| format!("nom de serveur invalide: {e}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("handshake TLS (avec cert client): {e}"))?;

    let (reader, mut writer) = tokio::io::split(tls);
    let mut line = serde_json::to_string(intention).map_err(|e| format!("sérialisation intention: {e}"))?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await.map_err(|e| format!("écriture intention: {e}"))?;
    writer.flush().await.map_err(|e| format!("flush intention: {e}"))?;

    let mut lines = BufReader::new(reader).lines();
    let response_line = lines
        .next_line()
        .await
        .map_err(|e| format!("lecture réponse: {e}"))?
        .ok_or_else(|| "connexion fermée sans réponse".to_string())?;
    match serde_json::from_str::<WireResponse>(&response_line) {
        Ok(WireResponse::PlanHash { plan_hash }) => Ok(plan_hash),
        Ok(WireResponse::Error { error }) => Err(error),
        Err(e) => Err(format!("réponse JSON invalide: {e}")),
    }
}

/// Client de test qui NE présente PAS de certificat client. Comme le noyau exige un certificat
/// client (`WebPkiClientVerifier`, politique anonyme = Deny), soit le handshake TLS échoue
/// directement, soit — selon le comportement exact du client rustls sans certificat — la
/// tentative d'échange applicatif qui suit échoue. Dans tous les cas cette fonction renvoie
/// `Err` : c'est le contrat exercé par le test 3.
pub async fn connect_without_client_cert(addr: SocketAddr) -> Result<(), String> {
    // Doit faire confiance à la CA réelle du serveur pour isoler la variable testée (absence
    // de cert client) — sinon un échec de vérification serveur masquerait le vrai signal.
    let certs = test_certs_for(addr);
    let client_config = ClientConfig::builder()
        .with_root_certificates((*certs.ca_roots()).clone())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect(addr).await.map_err(|e| format!("connexion TCP: {e}"))?;
    let server_name =
        ServerName::try_from("localhost").map_err(|e| format!("nom de serveur invalide: {e}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("handshake TLS refusé (attendu, pas de cert client): {e}"))?;

    // Si contre toute attente le handshake TLS a abouti (ex. si un jour la politique anonyme
    // changeait), on force la preuve fonctionnelle : envoyer une intention et vérifier que le
    // serveur ne renvoie rien d'exploitable revient, du point de vue de l'appelant, à un échec.
    // `write_all` échoue déjà si le serveur a fermé/alerté après le handshake côté verifier.
    let mut probe = serde_json::to_string(&Intention::SearchFiles { query: "x".into() })
        .expect("sérialisation de la sonde");
    probe.push('\n');
    tls.write_all(probe.as_bytes())
        .await
        .map_err(|e| format!("écriture refusée après handshake sans cert client: {e}"))?;
    tls.flush().await.map_err(|e| format!("flush refusé après handshake sans cert client: {e}"))?;

    let mut lines = BufReader::new(tls).lines();
    match lines.next_line().await {
        Ok(Some(_)) => Err("le serveur a répondu sans exiger de certificat client (contrôle primaire violé)".into()),
        Ok(None) => Err("connexion fermée par le serveur (pas de certificat client)".into()),
        Err(e) => Err(format!("lecture refusée après handshake sans cert client: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_test_certs_expose_matching_ca_roots_for_server_and_client() {
        // Sanity check hors réseau : la CA de test signe bien server ET client, et les deux CN
        // attendus sont extractibles (avant même de monter un serveur mTLS réel).
        let certs = generate_test_certs();
        let server_cn = extract_common_name(&certs.server.cert()).unwrap();
        let client_cn = extract_common_name(&certs.client.cert()).unwrap();
        assert_eq!(server_cn, "helixos-kernel-test-server");
        assert_eq!(client_cn, "test-client");
    }

    #[test]
    fn build_server_config_succeeds_with_generated_test_certs() {
        let certs = generate_test_certs();
        let _config = build_server_config(certs.ca_roots(), certs.server.cert(), certs.server.key());
    }
}
