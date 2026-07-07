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
//! ## Fix F4 (fix wave finale) : le harness de test hors du binaire de production
//!
//! `generate_test_certs`, `spawn_test_server`, les clients de test (`connect_with_client_cert`,
//! `connect_with_foreign_client_cert`, `connect_without_client_cert`), le registre process-global
//! de certs, `TestCerts`/`LeafDer` vivent maintenant dans le sous-module privé [`test_harness`],
//! gaté par `#[cfg(feature = "test-harness")]` et ré-exportés (`pub use`) à la racine de ce
//! module SEULEMENT sous la même feature. `rcgen` (`optional = true` dans `Cargo.toml`) n'est donc
//! tiré dans la compilation que si `test-harness` est active — jamais pour `cargo build`/`cargo
//! run` du binaire de production. `build_server_config` et `handle_authenticated_connection`
//! restent NON gatés : c'est la future API de production, elle ne dépend d'aucun symbole du
//! harness. Voir `[dev-dependencies]` dans `Cargo.toml` : la feature est auto-activée pour TOUTES
//! les cibles de test (unit ET intégration) du crate.
//!
//! ## Écarts vs consigne, notés pendant le spike
//!
//! 1. **`rcgen` en dépendance normale (optionnelle depuis le fix F4), pas dev-only.** La
//!    consigne demandait `cargo add --dev rcgen`. Vérifié empiriquement (sonde jetée après
//!    preuve) : quand `tests/mtls_it.rs` (crate d'intégration externe) lie `helixos_kernel`, la
//!    lib est compilée SANS `cfg(test)` actif — un `pub fn` sous `#[cfg(test)]` dans `src/`
//!    n'existerait alors pas dans le binaire lié. Comme l'interface demandée expose
//!    `mtls::spawn_test_server`/`connect_with_client_cert` en fonctions `pub` normales
//!    (appelées depuis `tests/mtls_it.rs`), elles ne pouvaient pas être gatées par
//!    `#[cfg(test)]` ; le fix F4 résout ça autrement, via `#[cfg(feature = "test-harness")]`
//!    activée par `[dev-dependencies]` plutôt que par `cfg(test)`.
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
use crate::pipeline::{Kernel, SharedKernel};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Assemble le `ServerConfig` mTLS : `WebPkiClientVerifier` exige un certificat client signé
/// par une des `ca_roots` (politique anonyme par défaut = `Deny`, donc un appelant sans
/// certificat client est refusé — c'est le contrôle primaire du test 3). API de PRODUCTION —
/// ne dépend d'aucun symbole du harness de test (fix F4), reste compilée inconditionnellement.
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
// MVP-0 (fix F4) : sans la feature `test-harness`, plus rien n'appelle
// `handle_authenticated_connection` (seul appelant : `spawn_test_server`, maintenant gaté) donc
// cette fonction devient orpheline du point de vue de `cargo build` seul — elle reste la future
// API de PRODUCTION (branchement réel du serveur mTLS reporté, `main.rs` est un stub), pas du
// code mort à supprimer.
#[cfg_attr(not(feature = "test-harness"), allow(dead_code))]
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
///
/// ## Format de fil PLAT (fix revue D1a) — `#[serde(untagged)]`, PAS externally-tagged
///
/// **Contrat de fil** : chaque variante sérialise DIRECTEMENT ses champs, sans enveloppe de tag :
/// `PlanHash{plan_hash}` → `{"plan_hash":"…"}` et `Error{error}` → `{"error":"…"}`. Les deux
/// variantes ont des jeux de champs DISJOINTS (`plan_hash` xor `error`), donc `untagged`
/// désérialise sans AUCUNE ambiguïté (essaie `PlanHash`, sinon `Error`).
///
/// **Pourquoi c'est critique (défaut mock-invisible corrigé ici) :** l'enum externally-tagged par
/// défaut (le `#[serde(rename_all = "snake_case")]` d'avant) sérialisait le NOM DE VARIANTE comme
/// clé externe → `{"plan_hash":{"plan_hash":"…"}}` (NIÉ, double niveau). Le shim (`kernel_client`),
/// lui, parse par forme un fil PLAT (`value["plan_hash"].as_str()`), donc contre le VRAI noyau
/// chaque patch réussi remontait comme une erreur de protocole → outil inutilisable. `untagged`
/// aligne le fil sur ce que le shim lit ET ce que le noyau relit (round-trip prouvé par le test
/// `wire_response_roundtrips_flat` ci-dessous). Voir `.superpowers/sdd/d1a-fix-report.md`.
///
/// Public sous `test-harness` (via le `pub use` en fin de module) pour que le test unitaire du shim
/// régénère son entrée codée en dur depuis un VRAI `to_string(&WireResponse::…)` (jamais un octet
/// réinventé).
// MVP-0 (fix F4) : même raison que sur `extract_common_name` ci-dessus — orpheline pour `cargo
// build` seul (sans `test-harness`), mais fait partie du protocole de PRODUCTION.
#[cfg_attr(not(feature = "test-harness"), allow(dead_code))]
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum WireResponse {
    PlanHash { plan_hash: String },
    Error { error: String },
}

/// Traite une connexion mTLS déjà acceptée et authentifiée : lit une intention JSON (une
/// ligne), la fait transiter vers `Kernel::plan_intention` avec l'identité dérivée du CN du
/// certificat client peer, puis renvoie le résultat en JSON sur le même flux. API de
/// PRODUCTION (fix F4) — ne dépend d'aucun symbole du harness de test.
// Sans la feature `test-harness`, `spawn_test_server` (seul appelant actuel) est absent : cette
// fonction reste la future API de production (branchement réel reporté, `main.rs` est un stub).
#[cfg_attr(not(feature = "test-harness"), allow(dead_code))]
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

/// Boucle de service mTLS de PRODUCTION (bootstrap MVP-0) : accepte en continu les connexions
/// entrantes sur `listener` (déjà lié — l'appelant connaît donc l'adresse effective, même pour
/// `127.0.0.1:0`), termine le handshake mTLS avec `server_config` (qui porte le
/// `WebPkiClientVerifier` : un appelant sans certificat client valide est refusé au handshake) et
/// délègue chaque connexion authentifiée à [`handle_authenticated_connection`] sur le `kernel`
/// PARTAGÉ. C'est LE point d'assemblage côté appelants : le `SharedKernel` passé ici est le même
/// `Arc<Mutex<Kernel>>` que celui du serveur d'approbation, donc un plan créé via cette frontière
/// mTLS est immédiatement approuvable sur la page HTTPS.
///
/// Ne dépend d'AUCUN symbole du harness de test (pas de `rcgen`) — `server_config` est assemblé en
/// amont par [`build_server_config`] à partir de certificats chargés sur disque
/// (`helixos-provision`). API de production, compilée inconditionnellement.
///
/// Cycle de vie : boucle tant que `listener.accept()` réussit. Chaque connexion est traitée dans
/// sa propre tâche `tokio::spawn` (une connexion lente ou un handshake refusé ne bloque pas les
/// autres). Un handshake refusé (ex. pas de certificat client — le contrôle primaire
/// d'authentification) se termine silencieusement dans sa tâche : c'est le comportement CORRECT, pas
/// une erreur de service à propager. `serve_mtls` ne rend la main (avec l'erreur d'`accept`) que si
/// le `listener` lui-même devient inutilisable — l'appelant (le bootstrap) traite alors cela comme
/// un arrêt du service.
pub async fn serve_mtls(
    listener: TcpListener,
    kernel: SharedKernel,
    server_config: Arc<ServerConfig>,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(server_config);
    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let kernel = kernel.clone();
        tokio::spawn(async move {
            // Un handshake refusé (ex. pas de cert client) termine ici sans bruit : comportement
            // attendu (contrôle primaire d'authentification), pas une erreur de service.
            if let Ok(tls) = acceptor.accept(stream).await {
                let _ = handle_authenticated_connection(tls, kernel).await;
            }
        });
    }
}

// Fix F4 : le harness de test mTLS (génération de certs via `rcgen`, serveur/clients de test,
// registre process-global de `TestCerts`) vit sous la feature `test-harness` — jamais compilé
// dans le binaire de PRODUCTION (`cargo build`/`cargo run` sans cette feature). `rcgen` lui-même
// (`optional = true` dans `Cargo.toml`) n'est donc tiré dans l'arbre de compilation que si cette
// feature est active (vérifié via `cargo tree`, voir le rapport de la fix wave finale).
#[cfg(feature = "test-harness")]
mod test_harness {
    use super::{build_server_config, serve_mtls, WireResponse};
    use crate::intention::Intention;
    use crate::pipeline::Kernel;
    use crate::scope::ScopeLease;
    use rcgen::{BasicConstraints, CertificateParams, DnType, Issuer, IsCa, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, OnceLock};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    /// Octets DER bruts d'une paire cert/clé de test — stockés en `Vec<u8>` (clonable) plutôt
    /// qu'en types `rustls` (`PrivateKeyDer` n'implémente pas `Clone`), pour pouvoir reconstruire
    /// un `CertificateDer`/`PrivateKeyDer` frais à chaque connexion cliente à partir d'une CA
    /// partagée.
    ///
    /// Les formes PEM (`cert_pem`/`key_pem`) sont AUSSI capturées à la génération (fix D1a) : un
    /// crate externe (le shim) les écrit sur disque pour exercer le VRAI chemin `ClientTls::load`
    /// (chargement PEM), sans avoir à ré-encoder du DER en PEM lui-même.
    #[derive(Clone)]
    pub struct LeafDer {
        pub cert_der: Vec<u8>,
        pub key_pkcs8_der: Vec<u8>,
        pub cert_pem: String,
        pub key_pem: String,
    }

    impl LeafDer {
        pub(crate) fn cert(&self) -> CertificateDer<'static> {
            CertificateDer::from(self.cert_der.clone())
        }
        pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8_der.clone()))
        }
    }

    /// Une CA de test + certificat serveur + certificat client, tous deux signés par la MÊME CA.
    /// Usage exclusif du harness de test/spike (jamais en production — le noyau réel chargerait
    /// des certs provisionnés hors bande). `Clone` : les octets DER sont réutilisables tels quels
    /// pour reconstruire des configs TLS indépendantes (une par connexion), toutes ancrées à la
    /// même CA.
    #[derive(Clone)]
    pub struct TestCerts {
        pub ca_der: Vec<u8>,
        /// PEM de la CA (racine de confiance) — écrit sur disque par les tests externes (shim) qui
        /// exercent `ClientTls::load`.
        pub ca_pem: String,
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
        LeafDer {
            cert_der: cert.der().to_vec(),
            key_pkcs8_der: key.serialize_der(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// Génère (en Rust pur, via `rcgen` — jamais le binaire `openssl`, qui peut être absent) une
    /// CA de test, un certificat serveur (SAN `localhost`/`127.0.0.1`) et un certificat client,
    /// tous deux signés par la MÊME CA fraîchement générée. Le CN du client identifie l'appelant
    /// côté serveur (`"test-client"`).
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

        TestCerts { ca_der: ca_cert.der().to_vec(), ca_pem: ca_cert.pem(), server, client }
    }

    /// Registre process-global : associe l'adresse d'un serveur mTLS de test à la `TestCerts`
    /// (CA + serveur + client) qu'il utilise. Nécessaire car `spawn_test_server` ne renvoie
    /// qu'un `SocketAddr` (interface demandée) — les fonctions client (`connect_with_client_cert`,
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

    /// Démarre le serveur mTLS de test sur `127.0.0.1:0` (port choisi par l'OS) et renvoie son
    /// adresse. `lease_root` devient l'unique racine louée du `Kernel` sous-jacent (bail
    /// par-tâche, contrôle primaire hérité — voir `scope::ScopeLease`) ; `state_dir` est l'état
    /// persistant du noyau (plans consommés, audit). La boucle d'acceptation tourne en tâche de
    /// fond tant que le test vit (processus de test court-circuité en fin de run ; pas de handle
    /// d'arrêt exposé, le périmètre B8-minimal ne couvre pas le cycle de vie du service).
    ///
    /// Réservé aux tests INTERNES du noyau (`tests/mtls_it.rs`), qui retrouvent les certs via le
    /// registre process-interne. Un crate EXTERNE (le shim) doit récupérer le cert client pour se
    /// connecter avec sa propre pile TLS : il utilise [`spawn_test_server_returning_certs`], qui
    /// exécute le MÊME `handle_authenticated_connection` réel et RENVOIE la `TestCerts`.
    pub async fn spawn_test_server(lease_root: PathBuf, state_dir: PathBuf) -> SocketAddr {
        let (addr, _certs) = spawn_test_server_returning_certs(lease_root, state_dir).await;
        addr
    }

    /// Variante de [`spawn_test_server`] pour les tests d'un AUTRE crate (le shim) : monte le VRAI
    /// serveur mTLS du noyau — même `build_server_config`, même boucle d'acceptation, même
    /// `handle_authenticated_connection` (le VRAI handler de production, PAS une réplique) — et
    /// RENVOIE la `TestCerts` (CA + cert/clé serveur + cert/clé client) pour que l'appelant externe
    /// construise un client mTLS présentant le cert client que ce serveur accepte.
    ///
    /// C'est le pivot du fix D1a (suppression de la réplique) : l'e2e du shim exerce désormais le
    /// vrai chemin noyau — s'il écrit une forme de fil incohérente avec ce que le shim parse, l'e2e
    /// ÉCHOUE (auto-preuve du contrat de fil). Les certs sont AUSSI enregistrés dans le registre
    /// interne pour que les helpers `connect_*` restent utilisables sur le même serveur.
    pub async fn spawn_test_server_returning_certs(
        lease_root: PathBuf,
        state_dir: PathBuf,
    ) -> (SocketAddr, TestCerts) {
        let certs = generate_test_certs();
        let server_config =
            build_server_config(certs.ca_roots(), certs.server.cert(), certs.server.key());

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
        register_test_certs(addr, certs.clone());

        // Fix bootstrap : le harness exerce désormais la VRAIE boucle de service de production
        // (`super::serve_mtls`) — même acceptation, même délégation à `handle_authenticated_connection`
        // sur le `SharedKernel` — plutôt qu'une réplique locale de la boucle. Toute divergence de la
        // boucle de prod ferait donc échouer les tests mTLS existants (auto-preuve du chemin réel).
        tokio::spawn(async move {
            let _ = serve_mtls(listener, kernel, server_config).await;
        });

        (addr, certs)
    }

    /// Client de test qui présente un certificat client valide (signé par la même CA que le
    /// serveur), envoie `intention` en JSON (une ligne) et renvoie le `plan_hash` reçu, ou
    /// l'erreur (réseau, TLS, ou refus fonctionnel du noyau — ex. hors bail de portée).
    pub async fn connect_with_client_cert(addr: SocketAddr, intention: &Intention) -> Result<String, String> {
        // Récupère la MÊME CA/client que celle enregistrée par `spawn_test_server` pour cette
        // adresse — jamais une CA fraîchement régénérée (voir doc de `test_cert_registry`).
        let certs = test_certs_for(addr);
        connect_with_leaf_cert(addr, &certs.ca_roots(), &certs.client, intention).await
    }

    /// Client de test qui présente un certificat client signé par une CA **ÉTRANGÈRE**,
    /// indépendante de celle du serveur (fix F9a) : preuve que la vérification de chaîne
    /// rejette bien un cert client structurellement valide (bonne forme, signature interne
    /// cohérente) mais dont l'ÉMETTEUR n'est pas dans les `ca_roots` du serveur — pas seulement
    /// l'absence totale de certificat (`connect_without_client_cert`, test 3). `foreign_client`
    /// doit être un `LeafDer` signé par une CA différente de celle enregistrée pour `addr` (voir
    /// `generate_test_certs()` appelé une 2e fois côté test). Le serveur continue de faire
    /// confiance à SA PROPRE CA (celle du registre) : seule la CA côté client change, pour
    /// isoler strictement la variable testée.
    pub async fn connect_with_foreign_client_cert(
        addr: SocketAddr,
        foreign_client: &LeafDer,
        intention: &Intention,
    ) -> Result<String, String> {
        let certs = test_certs_for(addr);
        connect_with_leaf_cert(addr, &certs.ca_roots(), foreign_client, intention).await
    }

    /// Cœur partagé de `connect_with_client_cert`/`connect_with_foreign_client_cert` : monte un
    /// `TlsConnector` qui fait confiance à `ca_roots` (toujours celle du SERVEUR réel — jamais
    /// celle de l'émetteur de `client_leaf`, sans quoi le scénario « cert d'une autre CA » serait
    /// vide de sens) et présente `client_leaf` comme certificat client.
    async fn connect_with_leaf_cert(
        addr: SocketAddr,
        ca_roots: &Arc<RootCertStore>,
        client_leaf: &LeafDer,
        intention: &Intention,
    ) -> Result<String, String> {
        let client_config = ClientConfig::builder()
            .with_root_certificates((**ca_roots).clone())
            .with_client_auth_cert(vec![client_leaf.cert()], client_leaf.key())
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

    /// Client de test qui NE présente PAS de certificat client. Le noyau exige un certificat
    /// client (`WebPkiClientVerifier`, politique anonyme = Deny), donc le comportement CORRECT
    /// est que la connexion soit refusée.
    ///
    /// **Pourquoi `connector.connect(...)` seul ne suffit PAS à discriminer (root cause creusée
    /// pendant le fix F1, vérifiée en lisant `rustls-0.23.41/src/server/tls13.rs:1037-1097`) :**
    /// en TLS 1.3, un client sans certificat configuré envoie quand même un message
    /// `Certificate` VIDE (légal côté client) suivi de `Finished` ; `TlsConnector::connect(...)`
    /// complète dès que CE CÔTÉ a fini d'émettre ses messages de handshake — il ne bloque PAS
    /// jusqu'à la réaction du serveur. Le serveur, lui, voit la chaîne vide, constate
    /// `client_auth_mandatory()==true` (politique `Deny`) et renvoie une alerte fatale
    /// `CertificateRequired` — mais cette alerte n'est consommée côté client qu'au PROCHAIN I/O
    /// applicatif (read/write), pas pendant `connect()`. Résultat mesuré empiriquement
    /// (déterministe sur 5 runs, pas une course) : `connector.connect(...)` réussit TOUJOURS ici,
    /// même sans cert client. Une version qui s'arrêterait à `connect().is_err()` conclurait donc
    /// systématiquement (et à tort) que la connexion anonyme a réussi.
    ///
    /// **Valeur de retour discriminante (fix F1 — le helper renvoyait `Err` sur TOUS les chemins
    /// avant ce correctif, y compris quand l'échange applicatif avait pleinement abouti, rendant
    /// `assert!(result.is_err())` tautologique côté appelant) :**
    /// - `Ok(())` ⟺ l'échange applicatif a PLEINEMENT ABOUTI : le serveur a renvoyé une ligne de
    ///   réponse exploitable après l'intention envoyée sur ce flux. C'est une VIOLATION du
    ///   contrôle primaire (le serveur a traité une requête sans avoir exigé de certificat
    ///   client) et doit faire échouer le test appelant.
    /// - `Err(_)` ⟺ la connexion anonyme a été REJETÉE — au handshake (rare mais géré) OU, cas
    ///   dominant en TLS 1.3, lors de l'I/O applicatif qui suit (l'alerte fatale du serveur
    ///   surgit à l'écriture ou à la lecture, ou le flux se ferme sans réponse). C'est le
    ///   comportement CORRECT (cert client bien exigé).
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

        // Le handshake TLS a abouti côté client (attendu en TLS 1.3, voir doc ci-dessus) : il
        // faut un I/O applicatif pour que l'éventuelle alerte fatale du serveur (chaîne vide +
        // mandatory) soit effectivement consommée. On envoie une intention neutre et on ne
        // considère la connexion anonyme comme un SUCCÈS (donc `Ok(())` = violation) QUE si le
        // serveur répond effectivement quelque chose d'exploitable — jamais sur la seule base du
        // handshake.
        let mut probe = serde_json::to_string(&Intention::SearchFiles { query: "x".into() })
            .expect("sérialisation de la sonde");
        probe.push('\n');
        if let Err(e) = tls.write_all(probe.as_bytes()).await {
            return Err(format!("écriture refusée après handshake sans cert client (alerte TLS attendue): {e}"));
        }
        if let Err(e) = tls.flush().await {
            return Err(format!("flush refusé après handshake sans cert client (alerte TLS attendue): {e}"));
        }

        let mut lines = BufReader::new(tls).lines();
        match lines.next_line().await {
            Ok(Some(_)) => Ok(()), // réponse exploitable reçue SANS cert client : violation du contrôle primaire.
            Ok(None) => Err("connexion fermée par le serveur sans réponse (attendu, pas de cert client)".into()),
            Err(e) => Err(format!("lecture refusée après handshake sans cert client (alerte TLS attendue): {e}")),
        }
    }
}

#[cfg(feature = "test-harness")]
pub use test_harness::{
    connect_with_client_cert, connect_with_foreign_client_cert, connect_without_client_cert,
    generate_test_certs, spawn_test_server, spawn_test_server_returning_certs, LeafDer, TestCerts,
};

// `WireResponse` est déclaré `pub` (ci-dessus) : c'est le type de fil de PRODUCTION, donc
// `helixos_kernel::mtls::WireResponse` est visible du crate shim, qui l'importe dans son test
// unitaire pour régénérer son entrée codée en dur depuis un VRAI
// `serde_json::to_string(&WireResponse::PlanHash{..})` — jamais un octet réinventé. (Pas de
// ré-export supplémentaire nécessaire : un `pub enum` au niveau module est déjà atteignable.)

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

    /// Fix D1a : le fil DOIT être PLAT et round-tripper à l'identique (ce que le noyau ÉCRIT, il le
    /// RELIT sans perte) — c'est l'invariant que l'ancien `#[serde(rename_all)]` externally-tagged
    /// violait côté shim (il émettait `{"plan_hash":{"plan_hash":…}}`). Ici on prouve les deux :
    /// (1) la forme sérialisée est PLATE (`{"plan_hash":"…"}` / `{"error":"…"}`, un seul niveau) ;
    /// (2) `from_str` after `to_string` redonne la même valeur, sans ambiguïté entre variantes.
    #[test]
    fn wire_response_roundtrips_flat() {
        let ok = WireResponse::PlanHash { plan_hash: "deadbeef".into() };
        let ok_json = serde_json::to_string(&ok).unwrap();
        assert_eq!(ok_json, r#"{"plan_hash":"deadbeef"}"#, "le fil de succès doit être PLAT");
        assert_eq!(serde_json::from_str::<WireResponse>(&ok_json).unwrap(), ok, "round-trip succès");

        let err = WireResponse::Error { error: "hors bail de portée".into() };
        let err_json = serde_json::to_string(&err).unwrap();
        assert_eq!(err_json, r#"{"error":"hors bail de portée"}"#, "le fil d'erreur doit être PLAT");
        assert_eq!(serde_json::from_str::<WireResponse>(&err_json).unwrap(), err, "round-trip erreur");

        // Désambiguïsation `untagged` : une forme `plan_hash` ne se lit JAMAIS comme `Error` et
        // réciproquement (jeux de champs disjoints).
        assert!(matches!(
            serde_json::from_str::<WireResponse>(r#"{"plan_hash":"h"}"#).unwrap(),
            WireResponse::PlanHash { .. }
        ));
        assert!(matches!(
            serde_json::from_str::<WireResponse>(r#"{"error":"e"}"#).unwrap(),
            WireResponse::Error { .. }
        ));
    }
}
